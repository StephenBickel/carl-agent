use std::error::Error;
use std::time::Duration;

use carl::providers::http::{
    ProviderEndpoint, ProviderHttpClient, ProviderHttpErrorCode, SecretCredential,
};
use futures_util::StreamExt;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[test]
fn credentials_are_bounded_and_debug_redacted() {
    let secret = SecretCredential::new(b"sk-fixture-super-secret".to_vec()).unwrap();
    assert_eq!(format!("{secret:?}"), "SecretCredential(<redacted>)");
    assert_eq!(secret.with_bytes(|bytes| bytes.len()), 23);
    assert!(SecretCredential::new(Vec::new()).is_err());
    assert!(SecretCredential::new(vec![b'x'; 513]).is_err());
    assert!(SecretCredential::new(b"key\nsecond-line".to_vec()).is_err());
}

#[test]
fn endpoints_are_closed_to_official_https_or_literal_loopback_http() {
    assert_eq!(
        ProviderEndpoint::openai().origin(),
        "https://api.openai.com"
    );
    assert_eq!(
        ProviderEndpoint::openrouter().origin(),
        "https://openrouter.ai"
    );
    assert!(ProviderEndpoint::loopback("http://127.0.0.1:41321").is_ok());
    for invalid in [
        "http://example.com",
        "https://127.0.0.1:443/path",
        "http://localhost:80",
        "http://127.0.0.1:80?key=secret",
    ] {
        assert!(
            ProviderEndpoint::loopback(invalid).is_err(),
            "accepted {invalid}"
        );
    }
}

#[tokio::test]
async fn json_requests_are_exact_bounded_and_secret_safe() -> TestResult {
    let (endpoint, request) =
        one_response("application/json", 200, br#"{"ok":true}"#, None).await?;
    let client = ProviderHttpClient::new(endpoint)?;
    let secret_literal = "sk-fixture-super-secret";
    let credential = SecretCredential::new(secret_literal.as_bytes().to_vec())?;
    let result = client
        .post_json(
            "/v1/test",
            &credential,
            &json!({"model":"fixture","stream":false}),
            CancellationToken::new(),
        )
        .await?;
    assert_eq!(result, json!({"ok": true}));
    let request = request.await??;
    assert!(
        request.starts_with("POST /v1/test HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer sk-fixture-super-secret\r\n")
    );
    assert!(request.contains("{\"model\":\"fixture\",\"stream\":false}"));
    assert!(!format!("{client:?}").contains(secret_literal));
    Ok(())
}

#[tokio::test]
async fn status_content_type_size_and_cancellation_fail_closed() -> TestResult {
    for (status, expected) in [
        (401, ProviderHttpErrorCode::Authentication),
        (403, ProviderHttpErrorCode::Authentication),
        (429, ProviderHttpErrorCode::RateLimit),
        (500, ProviderHttpErrorCode::Transport),
        (302, ProviderHttpErrorCode::InvalidResponse),
    ] {
        let (endpoint, request) = one_response(
            "application/json",
            status,
            br#"{"secret":"must-not-escape"}"#,
            None,
        )
        .await?;
        let client = ProviderHttpClient::new(endpoint)?;
        let credential = SecretCredential::new(b"fixture-key".to_vec())?;
        let error = client
            .post_json(
                "/v1/test",
                &credential,
                &json!({}),
                CancellationToken::new(),
            )
            .await
            .expect_err("status must fail");
        assert_eq!(error.code(), expected);
        assert!(!format!("{error:?}").contains("must-not-escape"));
        request.await??;
    }

    let (endpoint, request) = one_response("text/plain", 200, b"ok", None).await?;
    let client = ProviderHttpClient::new(endpoint)?;
    let credential = SecretCredential::new(b"fixture-key".to_vec())?;
    assert_eq!(
        client
            .post_json(
                "/v1/test",
                &credential,
                &json!({}),
                CancellationToken::new(),
            )
            .await
            .unwrap_err()
            .code(),
        ProviderHttpErrorCode::InvalidResponse
    );
    request.await??;

    let cancellation = CancellationToken::new();
    cancellation.cancel();
    assert_eq!(
        client
            .post_json("/v1/test", &credential, &json!({}), cancellation)
            .await
            .unwrap_err()
            .code(),
        ProviderHttpErrorCode::Cancelled
    );
    Ok(())
}

#[tokio::test]
async fn sse_frames_survive_split_writes_and_enforce_line_bounds() -> TestResult {
    let body = b"event: response.output_text.delta\r\ndata: {\"delta\":\"hi\"}\r\n\r\ndata: [DONE]\r\n\r\n";
    let (endpoint, request) = one_response("text/event-stream", 200, body, Some(7)).await?;
    let client = ProviderHttpClient::new(endpoint)?;
    let credential = SecretCredential::new(b"fixture-key".to_vec())?;
    let mut stream = client
        .post_sse(
            "/v1/responses",
            &credential,
            &json!({"stream":true}),
            CancellationToken::new(),
        )
        .await?;
    assert_eq!(
        stream.next().await.transpose()?,
        Some("{\"delta\":\"hi\"}".to_owned())
    );
    assert_eq!(stream.next().await.transpose()?, Some("[DONE]".to_owned()));
    assert!(stream.next().await.is_none());
    request.await??;

    let oversized = vec![b'x'; 256 * 1024 + 1];
    let (endpoint, request) = one_response("text/event-stream", 200, &oversized, None).await?;
    let client = ProviderHttpClient::new(endpoint)?;
    let mut stream = client
        .post_sse(
            "/v1/responses",
            &credential,
            &json!({"stream":true}),
            CancellationToken::new(),
        )
        .await?;
    assert_eq!(
        stream.next().await.unwrap().unwrap_err().code(),
        ProviderHttpErrorCode::InvalidResponse
    );
    request.await??;
    Ok(())
}

async fn one_response(
    content_type: &'static str,
    status: u16,
    body: &[u8],
    split: Option<usize>,
) -> TestResult<(
    ProviderEndpoint,
    tokio::task::JoinHandle<TestResult<String>>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let endpoint = ProviderEndpoint::loopback(&format!("http://{address}"))?;
    let body = body.to_vec();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Err("request ended before headers".into());
            }
            bytes.extend_from_slice(&buffer[..read]);
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec())?;
        let length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(str::to_owned)
            })
            .ok_or("request content length missing")?
            .parse::<usize>()?;
        while bytes.len() < header_end + length {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                return Err("request body ended early".into());
            }
            bytes.extend_from_slice(&buffer[..read]);
        }
        let reason = match status {
            200 => "OK",
            302 => "Found",
            401 => "Unauthorized",
            403 => "Forbidden",
            429 => "Too Many Requests",
            _ => "Internal Server Error",
        };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        if let Some(split) = split {
            for chunk in body.chunks(split) {
                stream.write_all(chunk).await?;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        } else {
            stream.write_all(&body).await?;
        }
        stream.shutdown().await?;
        Ok(String::from_utf8(bytes)?)
    });
    Ok((endpoint, task))
}
