use std::error::Error;

use carl::delegates::{ModelId, ReasoningEffort};
use carl::events::ToolCallId;
use carl::providers::catalog::{ProviderCatalog, ProviderKind, ProviderModel};
use carl::providers::http::{ProviderEndpoint, ProviderHttpClient, SecretCredential};
use carl::providers::openai::OpenAiProvider;
use carl::providers::{
    FinishReason, Message, MessageContent, ModelRequest, ModelSettings, Provider, ProviderError,
    ProviderEvent, Role, ToolDefinition,
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn responses_requests_and_streams_have_one_exact_normalized_contract() -> TestResult {
    let response = concat!(
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Working \"}\r\n\r\n",
        "data: {\"type\":\"response.output_item.added\",\"item\":{\"type\":\"function_call\",\"id\":\"fc_1\",\"call_id\":\"call_provider_1\",\"name\":\"read_file\",\"arguments\":\"\"}}\r\n\r\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc_1\",\"delta\":\"{\\\"path\\\":\"}\r\n\r\n",
        "data: {\"type\":\"response.function_call_arguments.delta\",\"item_id\":\"fc_1\",\"delta\":\"\\\"README.md\\\"}\"}\r\n\r\n",
        "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"id\":\"fc_1\",\"call_id\":\"call_provider_1\",\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"README.md\\\"}\"}}\r\n\r\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":41,\"output_tokens\":9}}}\r\n\r\n",
        "data: [DONE]\r\n\r\n",
    );
    let (endpoint, captured) = spawn_sse(response).await?;
    let adapter = provider(endpoint)?;
    assert_eq!(adapter.catalog(), &catalog());

    let events = adapter
        .stream(request())
        .await?
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(events.len(), 4);
    assert_eq!(
        events[0],
        ProviderEvent::TextDelta {
            text: "Working ".to_owned()
        }
    );
    let generated_id = match events[1].clone() {
        ProviderEvent::ToolCall {
            tool_call_id,
            provider_call_id,
            name,
            arguments,
        } => {
            assert_eq!(provider_call_id.as_deref(), Some("call_provider_1"));
            assert_eq!(name, "read_file");
            assert_eq!(arguments, json!({"path":"README.md"}));
            tool_call_id
        }
        other => panic!("expected tool call, got {other:?}"),
    };
    assert_eq!(
        events[2],
        ProviderEvent::Usage {
            input_tokens: 41,
            output_tokens: 9
        }
    );
    assert_eq!(
        events[3],
        ProviderEvent::Finish {
            reason: FinishReason::ToolCalls
        }
    );

    let captured_request = captured.await??;
    assert_eq!(captured_request.method, "POST");
    assert_eq!(captured_request.path, "/v1/responses");
    assert_eq!(
        captured_request.body,
        json!({
            "model": "gpt-5.2-codex",
            "store": false,
            "stream": true,
            "input": [
                {"role":"developer","content":[{"type":"input_text","text":"You are Carl."}]},
                {"role":"user","content":[{"type":"input_text","text":"Inspect the repo."}]},
                {"role":"assistant","content":[{"type":"output_text","text":"I will inspect it."}]},
                {"type":"function_call","call_id":"call_prior","name":"read_file","arguments":"{\"path\":\"Cargo.toml\"}"},
                {"type":"function_call_output","call_id":"call_prior","output":"{\"text\":\"[package]\"}"}
            ],
            "tools": [{
                "type":"function",
                "name":"read_file",
                "description":"Read one file",
                "parameters":{
                    "type":"object",
                    "properties":{"path":{"type":"string"}},
                    "required":["path"],
                    "additionalProperties":false
                },
                "strict":true
            }],
            "temperature": 0.2,
            "max_output_tokens": 1024,
            "reasoning":{"effort":"high"}
        })
    );

    let (second_endpoint, _) = spawn_sse(response).await?;
    let second = provider(second_endpoint)?
        .stream(request())
        .await?
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        second
            .iter()
            .find_map(|event| match event {
                ProviderEvent::ToolCall { tool_call_id, .. } => Some(tool_call_id.to_owned()),
                _ => None,
            })
            .unwrap(),
        generated_id,
        "provider call IDs must map deterministically across replay"
    );
    Ok(())
}

#[tokio::test]
async fn incomplete_reasons_are_typed_and_terminal() -> TestResult {
    for (reason, expected) in [
        ("max_output_tokens", FinishReason::Length),
        ("content_filter", FinishReason::ContentFilter),
    ] {
        let body = format!(
            "data: {{\"type\":\"response.incomplete\",\"response\":{{\"incomplete_details\":{{\"reason\":\"{reason}\"}},\"usage\":{{\"input_tokens\":2,\"output_tokens\":3}}}}}}\n\ndata: [DONE]\n\n"
        );
        let (endpoint, _) = spawn_sse(&body).await?;
        let events = provider(endpoint)?
            .stream(request())
            .await?
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            events,
            vec![
                ProviderEvent::Usage {
                    input_tokens: 2,
                    output_tokens: 3
                },
                ProviderEvent::Finish { reason: expected }
            ]
        );
    }
    Ok(())
}

#[tokio::test]
async fn malformed_or_ambiguous_streams_fail_closed_without_secret_output() -> TestResult {
    let cases = [
        "data: {\"type\":\"response.unknown\"}\n\n",
        "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"id\":\"fc\",\"call_id\":\"call\",\"name\":\"tool\",\"arguments\":\"not-json\"}}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
        "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
        "data: {\"type\":\"response.output_text.delta\",\"delta\":\"unterminated\"}\n\n",
        "data: {\"type\":\"error\",\"message\":\"sk-secret-must-not-escape\"}\n\n",
    ];
    for body in cases {
        let (endpoint, _) = spawn_sse(body).await?;
        let items = provider(endpoint)?
            .stream(request())
            .await?
            .collect::<Vec<_>>()
            .await;
        let error = items
            .into_iter()
            .find_map(Result::err)
            .expect("invalid stream must emit a typed error");
        assert!(matches!(error, ProviderError::InvalidResponse { .. }));
        assert!(!format!("{error:?}").contains("sk-secret-must-not-escape"));
    }
    Ok(())
}

fn provider(endpoint: ProviderEndpoint) -> Result<OpenAiProvider, ProviderError> {
    OpenAiProvider::new(
        ProviderHttpClient::new(endpoint).map_err(map_setup_error)?,
        SecretCredential::new(b"sk-openai-fixture".to_vec()).map_err(map_setup_error)?,
        catalog(),
    )
}

fn map_setup_error(error: impl std::fmt::Debug) -> ProviderError {
    ProviderError::InvalidRequest {
        detail: format!("fixture setup failed: {error:?}"),
    }
}

fn catalog() -> ProviderCatalog {
    let model = ProviderModel::new(
        ModelId::parse("gpt-5.2-codex").unwrap(),
        "GPT 5.2 Codex".to_owned(),
        400_000,
        vec![ReasoningEffort::Low, ReasoningEffort::High],
        ReasoningEffort::High,
        true,
        true,
        true,
    )
    .unwrap();
    ProviderCatalog::new(
        ProviderKind::OpenAiApi,
        vec![model.clone()],
        model.id().clone(),
    )
    .unwrap()
}

fn request() -> ModelRequest {
    let prior_id: ToolCallId = "11111111-1111-4111-8111-111111111111".parse().unwrap();
    ModelRequest {
        messages: vec![
            Message {
                role: Role::System,
                content: vec![MessageContent::Text {
                    text: "You are Carl.".to_owned(),
                }],
            },
            Message {
                role: Role::User,
                content: vec![MessageContent::Text {
                    text: "Inspect the repo.".to_owned(),
                }],
            },
            Message {
                role: Role::Assistant,
                content: vec![
                    MessageContent::Text {
                        text: "I will inspect it.".to_owned(),
                    },
                    MessageContent::ToolCall {
                        tool_call_id: prior_id,
                        provider_call_id: Some("call_prior".to_owned()),
                        name: "read_file".to_owned(),
                        arguments: json!({"path":"Cargo.toml"}),
                    },
                ],
            },
            Message {
                role: Role::Tool,
                content: vec![MessageContent::ToolResult {
                    tool_call_id: prior_id,
                    output: json!({"text":"[package]"}),
                }],
            },
        ],
        tools: vec![ToolDefinition {
            name: "read_file".to_owned(),
            description: "Read one file".to_owned(),
            input_schema: json!({
                "type":"object",
                "properties":{"path":{"type":"string"}},
                "required":["path"],
                "additionalProperties":false
            }),
        }],
        settings: ModelSettings {
            model: "gpt-5.2-codex".to_owned(),
            temperature: Some(0.2),
            max_output_tokens: Some(1024),
            reasoning_effort: Some(ReasoningEffort::High),
        },
        cancellation: CancellationToken::new(),
    }
}

#[derive(Debug)]
struct CapturedRequest {
    method: String,
    path: String,
    body: Value,
}

async fn spawn_sse(
    body: &str,
) -> TestResult<(
    ProviderEndpoint,
    tokio::task::JoinHandle<TestResult<CapturedRequest>>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let endpoint = ProviderEndpoint::loopback(&format!("http://{address}"))?;
    let response_body = body.as_bytes().to_vec();
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
        let mut first = headers
            .lines()
            .next()
            .ok_or("request line missing")?
            .split(' ');
        let method = first.next().ok_or("request method missing")?.to_owned();
        let path = first.next().ok_or("request path missing")?.to_owned();
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
        let request_body = serde_json::from_slice(&bytes[header_end..header_end + length])?;
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        );
        stream.write_all(headers.as_bytes()).await?;
        for chunk in response_body.chunks(11) {
            stream.write_all(chunk).await?;
        }
        stream.shutdown().await?;
        Ok(CapturedRequest {
            method,
            path,
            body: request_body,
        })
    });
    Ok((endpoint, task))
}
