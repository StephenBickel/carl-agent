use std::error::Error;

use carl::delegates::ReasoningEffort;
use carl::providers::http::{ProviderEndpoint, ProviderHttpClient, SecretCredential};
use carl::providers::openrouter::OpenRouterProvider;
use carl::providers::{
    FinishReason, Message, MessageContent, ModelRequest, ModelSettings, Provider, ProviderEvent,
    Role, ToolDefinition,
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn discovery_filters_vendor_neutrally_and_uses_exact_route() -> TestResult {
    let models = models_fixture();
    let (endpoint, captured) = spawn_response("application/json", &models.to_string()).await?;
    let provider = OpenRouterProvider::discover(
        ProviderHttpClient::new(endpoint)?,
        SecretCredential::new(b"sk-or-fixture".to_vec())?,
        CancellationToken::new(),
    )
    .await?;
    let ids = provider
        .catalog()
        .models()
        .iter()
        .map(|model| model.id().as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        vec![
            "anthropic/claude-sonnet-4.5",
            "deepseek/deepseek-v3.2",
            "google/gemini-3-pro",
            "moonshotai/kimi-k2",
            "qwen/qwen3-coder",
            "x-ai/grok-code-fast-1",
        ]
    );
    let request = captured.await??;
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.path,
        "/api/v1/models?supported_parameters=tools&output_modalities=text"
    );
    assert!(
        request
            .headers
            .contains("authorization: bearer sk-or-fixture")
    );
    assert!(
        request
            .headers
            .contains("http-referer: https://github.com/stephenbickel/carl-agent")
    );
    assert!(request.headers.contains("x-title: carl"));
    Ok(())
}

#[tokio::test]
async fn chat_stream_reassembles_indexed_calls_usage_and_finish() -> TestResult {
    let stream = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Checking \"},\"finish_reason\":null}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_or_1\",\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\"}}]},\"finish_reason\":null}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"README.md\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7}}\n\n",
        "data: [DONE]\n\n",
    );
    let (endpoint, captured) = spawn_response("text/event-stream", stream).await?;
    let provider = OpenRouterProvider::from_models_response(
        ProviderHttpClient::new(endpoint)?,
        SecretCredential::new(b"sk-or-fixture".to_vec())?,
        models_fixture(),
    )?;
    let events = provider
        .stream(request())
        .await?
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        events[0],
        ProviderEvent::TextDelta {
            text: "Checking ".to_owned()
        }
    );
    match events[1].clone() {
        ProviderEvent::ToolCall {
            provider_call_id,
            name,
            arguments,
            ..
        } => {
            assert_eq!(provider_call_id.as_deref(), Some("call_or_1"));
            assert_eq!(name, "read_file");
            assert_eq!(arguments, json!({"path":"README.md"}));
        }
        other => panic!("expected tool call, got {other:?}"),
    }
    assert_eq!(
        &events[2..],
        &[
            ProviderEvent::Usage {
                input_tokens: 11,
                output_tokens: 7
            },
            ProviderEvent::Finish {
                reason: FinishReason::ToolCalls
            }
        ]
    );
    let captured = captured.await??;
    assert_eq!(captured.method, "POST");
    assert_eq!(captured.path, "/api/v1/chat/completions");
    assert_eq!(captured.body["model"], json!("deepseek/deepseek-v3.2"));
    assert_eq!(captured.body["stream"], json!(true));
    assert_eq!(
        captured.body["stream_options"],
        json!({"include_usage":true})
    );
    assert_eq!(captured.body["reasoning"], json!({"effort":"high"}));
    assert_eq!(captured.body["tools"][0]["function"]["strict"], json!(true));
    Ok(())
}

#[tokio::test]
async fn malformed_indices_ids_arguments_and_finish_reasons_fail_closed() -> TestResult {
    for stream in [
        "data: {\"choices\":[{\"index\":1,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":2,\"id\":\"call\",\"function\":{\"name\":\"tool\",\"arguments\":\"{}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"secret_reason\"}]}\n\ndata: [DONE]\n\n",
        "data: {\"error\":{\"message\":\"sk-secret-must-not-escape\"}}\n\n",
    ] {
        let (endpoint, _) = spawn_response("text/event-stream", stream).await?;
        let provider = OpenRouterProvider::from_models_response(
            ProviderHttpClient::new(endpoint)?,
            SecretCredential::new(b"fixture".to_vec())?,
            models_fixture(),
        )?;
        let items = provider.stream(request()).await?.collect::<Vec<_>>().await;
        let error = items.into_iter().find_map(Result::err).unwrap();
        assert!(!format!("{error:?}").contains("sk-secret-must-not-escape"));
    }
    Ok(())
}

fn request() -> ModelRequest {
    ModelRequest {
        messages: vec![Message {
            role: Role::User,
            content: vec![MessageContent::Text {
                text: "Inspect README.md".to_owned(),
            }],
        }],
        tools: vec![ToolDefinition {
            name: "read_file".to_owned(),
            description: "Read a file".to_owned(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}),
        }],
        settings: ModelSettings {
            model: "deepseek/deepseek-v3.2".to_owned(),
            temperature: None,
            max_output_tokens: Some(1024),
            reasoning_effort: Some(ReasoningEffort::High),
        },
        cancellation: CancellationToken::new(),
    }
}

fn models_fixture() -> Value {
    let mut models = Vec::new();
    for (id, name) in [
        ("anthropic/claude-sonnet-4.5", "Claude Sonnet 4.5"),
        ("deepseek/deepseek-v3.2", "DeepSeek V3.2"),
        ("google/gemini-3-pro", "Gemini 3 Pro"),
        ("moonshotai/kimi-k2", "Kimi K2"),
        ("qwen/qwen3-coder", "Qwen 3 Coder"),
        ("x-ai/grok-code-fast-1", "Grok Code Fast"),
    ] {
        models.push(json!({
            "id":id,"name":name,"context_length":131072,
            "architecture":{"input_modalities":["text"],"output_modalities":["text"]},
            "supported_parameters":["tools","reasoning"]
        }));
    }
    models.push(json!({
        "id":"image/only","name":"Image Only","context_length":131072,
        "architecture":{"input_modalities":["image"],"output_modalities":["image"]},
        "supported_parameters":["tools"]
    }));
    models.push(json!({
        "id":"text/no-tools","name":"No Tools","context_length":131072,
        "architecture":{"input_modalities":["text"],"output_modalities":["text"]},
        "supported_parameters":[]
    }));
    json!({"data":models})
}

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    path: String,
    headers: String,
    body: Value,
}

async fn spawn_response(
    content_type: &'static str,
    response_body: &str,
) -> TestResult<(
    ProviderEndpoint,
    tokio::task::JoinHandle<TestResult<CapturedRequest>>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = ProviderEndpoint::loopback(&format!("http://{}", listener.local_addr()?))?;
    let response_body = response_body.as_bytes().to_vec();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err("request headers ended early".into());
            }
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec())?;
        let mut line = headers
            .lines()
            .next()
            .ok_or("request line missing")?
            .split(' ');
        let method = line.next().ok_or("method missing")?.to_owned();
        let path = line.next().ok_or("path missing")?.to_owned();
        let length = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(str::to_owned)
            })
            .map(|value| value.parse::<usize>())
            .transpose()?
            .unwrap_or(0);
        while bytes.len() < header_end + length {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err("request body ended early".into());
            }
            bytes.extend_from_slice(&chunk[..read]);
        }
        let body = if length == 0 {
            Value::Null
        } else {
            serde_json::from_slice(&bytes[header_end..header_end + length])?
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(&response_body).await?;
        stream.shutdown().await?;
        Ok(CapturedRequest {
            method,
            path,
            headers: headers.to_ascii_lowercase(),
            body,
        })
    });
    Ok((endpoint, task))
}
