use std::error::Error;

use carl::error::ErrorCode;
use carl::events::ToolCallId;
use carl::providers::scripted::ScriptedProvider;
use carl::providers::{
    FinishReason, Message, MessageContent, ModelRequest, ModelSettings, Provider,
    ProviderCapabilities, ProviderError, ProviderEvent, Role, ToolDefinition,
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

const TOOL_CALL_ID: &str = "11111111-1111-4111-8111-111111111111";
const SECOND_TOOL_CALL_ID: &str = "22222222-2222-4222-8222-222222222222";
const FIXTURE: &str = include_str!("fixtures/provider/tool_then_answer.json");

#[test]
fn scripted_fixture_uses_the_current_product_identity() {
    assert!(FIXTURE.contains("# Carl"));
    assert!(!FIXTURE.contains(&["Arc", "Wren"].concat()));
}

fn tool_call_id() -> ToolCallId {
    TOOL_CALL_ID.parse().expect("fixture tool-call ID is valid")
}

fn request(cancellation: CancellationToken) -> ModelRequest {
    ModelRequest {
        messages: vec![
            Message {
                role: Role::System,
                content: vec![MessageContent::Text {
                    text: "Be concise.".into(),
                }],
            },
            Message {
                role: Role::User,
                content: vec![MessageContent::Text {
                    text: "Read README.md".into(),
                }],
            },
        ],
        tools: vec![ToolDefinition {
            name: "fs.read".into(),
            description: "Read a bounded UTF-8 file".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
                "additionalProperties": false,
            }),
        }],
        settings: ModelSettings {
            model: "fixture-model".into(),
            temperature: Some(0.2),
            max_output_tokens: Some(512),
            reasoning_effort: None,
        },
        cancellation,
    }
}

#[test]
fn normalized_request_has_an_exact_provider_neutral_wire_contract() -> Result<(), Box<dyn Error>> {
    let encoded = serde_json::to_value(request(CancellationToken::new()))?;
    assert_eq!(
        encoded,
        json!({
            "messages": [
                {
                    "role": "system",
                    "content": [{"type": "text", "text": "Be concise."}],
                },
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "Read README.md"}],
                },
            ],
            "tools": [{
                "name": "fs.read",
                "description": "Read a bounded UTF-8 file",
                "input_schema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": false,
                },
            }],
            "settings": {
                "model": "fixture-model",
                "temperature": 0.2,
                "max_output_tokens": 512,
                "reasoning_effort": null,
            },
        })
    );
    assert!(encoded.get("cancellation").is_none());

    let decoded: ModelRequest = serde_json::from_value(encoded)?;
    assert_eq!(decoded.messages, request(CancellationToken::new()).messages);
    assert_eq!(decoded.tools, request(CancellationToken::new()).tools);
    assert_eq!(decoded.settings, request(CancellationToken::new()).settings);
    assert!(!decoded.cancellation.is_cancelled());
    Ok(())
}

#[test]
fn normalized_message_content_carries_tool_calls_and_results() -> Result<(), Box<dyn Error>> {
    let messages = vec![
        Message {
            role: Role::Assistant,
            content: vec![MessageContent::ToolCall {
                tool_call_id: tool_call_id(),
                provider_call_id: None,
                name: "fs.read".into(),
                arguments: json!({"path": "README.md"}),
            }],
        },
        Message {
            role: Role::Tool,
            content: vec![MessageContent::ToolResult {
                tool_call_id: tool_call_id(),
                output: json!({"text": "# Carl"}),
            }],
        },
    ];
    let expected = json!([
        {
            "role": "assistant",
            "content": [{
                "type": "tool_call",
                "tool_call_id": TOOL_CALL_ID,
                "name": "fs.read",
                "arguments": {"path": "README.md"},
            }],
        },
        {
            "role": "tool",
            "content": [{
                "type": "tool_result",
                "tool_call_id": TOOL_CALL_ID,
                "output": {"text": "# Carl"},
            }],
        },
    ]);

    assert_eq!(serde_json::to_value(&messages)?, expected);
    assert_eq!(serde_json::from_value::<Vec<Message>>(expected)?, messages);
    Ok(())
}

#[test]
fn capabilities_and_events_have_exact_serializable_contracts() -> Result<(), Box<dyn Error>> {
    let capabilities = ProviderCapabilities {
        streaming: true,
        structured_tool_calls: true,
        parallel_tool_calls: false,
        usage_reporting: true,
        context_window: Some(128_000),
    };
    let encoded_capabilities = json!({
        "streaming": true,
        "structured_tool_calls": true,
        "parallel_tool_calls": false,
        "usage_reporting": true,
        "context_window": 128000,
    });
    assert_eq!(serde_json::to_value(capabilities)?, encoded_capabilities);
    assert_eq!(
        serde_json::from_value::<ProviderCapabilities>(encoded_capabilities)?,
        capabilities
    );

    let cases = [
        (
            ProviderEvent::TextDelta {
                text: "The file says ".into(),
            },
            json!({"type": "text_delta", "text": "The file says "}),
        ),
        (
            ProviderEvent::ToolCall {
                tool_call_id: tool_call_id(),
                provider_call_id: None,
                name: "fs.read".into(),
                arguments: json!({"path": "README.md"}),
            },
            json!({
                "type": "tool_call",
                "tool_call_id": TOOL_CALL_ID,
                "name": "fs.read",
                "arguments": {"path": "README.md"},
            }),
        ),
        (
            ProviderEvent::Usage {
                input_tokens: 48,
                output_tokens: 9,
            },
            json!({"type": "usage", "input_tokens": 48, "output_tokens": 9}),
        ),
        (
            ProviderEvent::Finish {
                reason: FinishReason::ToolCalls,
            },
            json!({"type": "finish", "reason": "tool_calls"}),
        ),
    ];

    for (event, expected) in cases {
        assert_eq!(serde_json::to_value(&event)?, expected);
        assert_eq!(serde_json::from_value::<ProviderEvent>(expected)?, event);
    }
    Ok(())
}

#[test]
fn invalid_fixture_errors_expose_stable_sanitized_diagnostics() {
    let secret = "fixture contained sk-review-secret";
    let error = ProviderError::InvalidFixture {
        detail: secret.into(),
    };

    assert_eq!(error.code(), ErrorCode::Validation);
    assert_eq!(error.code().as_str(), "validation_error");
    assert_eq!(
        error.user_message(),
        "The scripted provider fixture is invalid."
    );
    assert_eq!(error.to_string(), "scripted provider fixture is invalid");
    assert!(!error.user_message().contains(secret));
    assert!(!error.to_string().contains(secret));
}

#[tokio::test]
async fn scripted_provider_replays_complete_responses_and_records_complete_requests()
-> Result<(), Box<dyn Error>> {
    let provider = ScriptedProvider::from_json(FIXTURE)?;
    assert_eq!(
        provider.capabilities(),
        ProviderCapabilities {
            streaming: true,
            structured_tool_calls: true,
            parallel_tool_calls: false,
            usage_reporting: true,
            context_window: Some(128_000),
        }
    );

    let first_cancellation = CancellationToken::new();
    let first_request = request(first_cancellation.clone());
    let first = provider
        .stream(first_request.clone())
        .await?
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        first,
        vec![
            ProviderEvent::ToolCall {
                tool_call_id: tool_call_id(),
                provider_call_id: None,
                name: "fs.read".into(),
                arguments: json!({"path": "README.md"}),
            },
            ProviderEvent::Usage {
                input_tokens: 48,
                output_tokens: 9,
            },
            ProviderEvent::Finish {
                reason: FinishReason::ToolCalls,
            },
        ]
    );

    let second_request = request(CancellationToken::new());
    let second = provider
        .stream(second_request.clone())
        .await?
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        second,
        vec![
            ProviderEvent::TextDelta {
                text: "The file says ".into(),
            },
            ProviderEvent::TextDelta {
                text: "# Carl".into(),
            },
            ProviderEvent::Usage {
                input_tokens: 71,
                output_tokens: 14,
            },
            ProviderEvent::Finish {
                reason: FinishReason::Stop,
            },
        ]
    );

    let recorded = provider.recorded_requests();
    assert_eq!(recorded.len(), 2);
    assert_eq!(recorded[0].messages, first_request.messages);
    assert_eq!(recorded[0].tools, first_request.tools);
    assert_eq!(recorded[0].settings, first_request.settings);
    first_cancellation.cancel();
    assert!(!recorded[0].cancellation.is_cancelled());
    assert_eq!(recorded[1].messages, second_request.messages);
    assert_eq!(recorded[1].tools, second_request.tools);
    assert_eq!(recorded[1].settings, second_request.settings);
    Ok(())
}

#[tokio::test]
async fn recorded_request_snapshots_cannot_cancel_the_stream_or_later_snapshots()
-> Result<(), Box<dyn Error>> {
    let provider = ScriptedProvider::from_json(FIXTURE)?;
    let live_cancellation = CancellationToken::new();
    let mut stream = provider.stream(request(live_cancellation.clone())).await?;

    let first_snapshot = provider.recorded_requests();
    assert_eq!(first_snapshot.len(), 1);
    first_snapshot[0].cancellation.cancel();
    assert!(!live_cancellation.is_cancelled());
    assert!(matches!(
        stream.next().await,
        Some(Ok(ProviderEvent::ToolCall { .. }))
    ));

    let later_snapshot = provider.recorded_requests();
    assert_eq!(later_snapshot.len(), 1);
    assert!(!later_snapshot[0].cancellation.is_cancelled());
    Ok(())
}

#[tokio::test]
async fn scripted_stream_observes_cancellation_between_events() -> Result<(), Box<dyn Error>> {
    let provider = ScriptedProvider::from_json(FIXTURE)?;
    let cancellation = CancellationToken::new();
    let mut stream = provider.stream(request(cancellation.clone())).await?;

    assert!(matches!(
        stream.next().await,
        Some(Ok(ProviderEvent::ToolCall { .. }))
    ));
    cancellation.cancel();
    assert_eq!(stream.next().await, Some(Err(ProviderError::Cancelled)));
    assert_eq!(stream.next().await, None);
    Ok(())
}

#[tokio::test]
async fn finish_event_terminates_the_stream_before_later_cancellation() -> Result<(), Box<dyn Error>>
{
    let provider = ScriptedProvider::from_json(FIXTURE)?;
    let cancellation = CancellationToken::new();
    let mut stream = provider.stream(request(cancellation.clone())).await?;

    assert!(matches!(
        stream.next().await,
        Some(Ok(ProviderEvent::ToolCall { .. }))
    ));
    assert!(matches!(
        stream.next().await,
        Some(Ok(ProviderEvent::Usage { .. }))
    ));
    assert_eq!(
        stream.next().await,
        Some(Ok(ProviderEvent::Finish {
            reason: FinishReason::ToolCalls,
        }))
    );

    cancellation.cancel();
    assert_eq!(stream.next().await, None);
    Ok(())
}

#[tokio::test]
async fn scripted_provider_reports_cancellation_before_stream_creation() {
    let provider = ScriptedProvider::from_json(FIXTURE).unwrap();
    let cancellation = CancellationToken::new();
    cancellation.cancel();

    assert!(matches!(
        provider.stream(request(cancellation)).await,
        Err(ProviderError::Cancelled)
    ));
    assert!(provider.recorded_requests().is_empty());
}

#[tokio::test]
async fn scripted_provider_reports_fixture_exhaustion_without_reusing_a_response()
-> Result<(), Box<dyn Error>> {
    let provider = ScriptedProvider::from_json(FIXTURE)?;
    for _ in 0..2 {
        provider
            .stream(request(CancellationToken::new()))
            .await?
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
    }

    assert!(matches!(
        provider.stream(request(CancellationToken::new())).await,
        Err(ProviderError::ScriptExhausted { response_count: 2 })
    ));
    assert_eq!(provider.recorded_requests().len(), 2);
    Ok(())
}

#[test]
fn inconsistent_scripted_capabilities_are_rejected() {
    assert_invalid_fixture(
        "parallel calls without structured calls",
        fixture(
            capabilities(true, false, true, false),
            vec![response(vec![finish("stop")])],
        ),
    );
    assert_invalid_fixture(
        "multiple calls without parallel-call capability",
        fixture(
            capabilities(true, true, false, false),
            vec![response(vec![
                tool_call(TOOL_CALL_ID, "fs.read", json!({"path": "README.md"})),
                tool_call(SECOND_TOOL_CALL_ID, "fs.read", json!({"path": "LICENSE"})),
                finish("tool_calls"),
            ])],
        ),
    );
}

#[test]
fn every_malformed_scripted_fixture_branch_returns_stable_sanitized_diagnostics() {
    assert_invalid_fixture_json("invalid JSON", "not JSON");

    let cases = vec![
        (
            "unsupported schema",
            json!({
                "schema_version": 2,
                "capabilities": capabilities(true, false, false, false),
                "responses": [],
            }),
        ),
        (
            "streaming disabled",
            fixture(
                capabilities(false, false, false, false),
                vec![response(vec![finish("stop")])],
            ),
        ),
        (
            "no responses",
            fixture(capabilities(true, false, false, false), vec![]),
        ),
        (
            "empty response",
            fixture(
                capabilities(true, false, false, false),
                vec![response(vec![])],
            ),
        ),
        (
            "missing finish",
            fixture(
                capabilities(true, false, false, false),
                vec![response(vec![json!({
                    "type": "text_delta",
                    "text": "unfinished",
                })])],
            ),
        ),
        (
            "event after finish",
            fixture(
                capabilities(true, false, false, false),
                vec![response(vec![
                    finish("stop"),
                    json!({"type": "text_delta", "text": "late"}),
                ])],
            ),
        ),
        (
            "empty text delta",
            fixture(
                capabilities(true, false, false, false),
                vec![response(vec![
                    json!({"type": "text_delta", "text": ""}),
                    finish("stop"),
                ])],
            ),
        ),
        (
            "tool call without structured-call capability",
            fixture(
                capabilities(true, false, false, false),
                vec![response(vec![
                    tool_call(TOOL_CALL_ID, "fs.read", json!({"path": "README.md"})),
                    finish("tool_calls"),
                ])],
            ),
        ),
        (
            "empty tool name",
            fixture(
                capabilities(true, true, false, false),
                vec![response(vec![
                    tool_call(TOOL_CALL_ID, " ", json!({"path": "README.md"})),
                    finish("tool_calls"),
                ])],
            ),
        ),
        (
            "non-object tool arguments",
            fixture(
                capabilities(true, true, false, false),
                vec![response(vec![
                    tool_call(TOOL_CALL_ID, "fs.read", json!("README.md")),
                    finish("tool_calls"),
                ])],
            ),
        ),
        (
            "usage without usage capability",
            fixture(
                capabilities(true, false, false, false),
                vec![response(vec![
                    json!({"type": "usage", "input_tokens": 1, "output_tokens": 2}),
                    finish("stop"),
                ])],
            ),
        ),
        (
            "duplicate finish",
            fixture(
                capabilities(true, false, false, false),
                vec![response(vec![finish("stop"), finish("stop")])],
            ),
        ),
        (
            "tool-calls finish without tool call",
            fixture(
                capabilities(true, true, false, false),
                vec![response(vec![finish("tool_calls")])],
            ),
        ),
    ];

    for (case, fixture) in cases {
        assert_invalid_fixture(case, fixture);
    }
}

fn capabilities(
    streaming: bool,
    structured_tool_calls: bool,
    parallel_tool_calls: bool,
    usage_reporting: bool,
) -> Value {
    json!({
        "streaming": streaming,
        "structured_tool_calls": structured_tool_calls,
        "parallel_tool_calls": parallel_tool_calls,
        "usage_reporting": usage_reporting,
        "context_window": null,
    })
}

fn fixture(capabilities: Value, responses: Vec<Value>) -> Value {
    json!({
        "schema_version": 1,
        "capabilities": capabilities,
        "responses": responses,
    })
}

fn response(events: Vec<Value>) -> Value {
    json!({"events": events})
}

fn tool_call(id: &str, name: &str, arguments: Value) -> Value {
    json!({
        "type": "tool_call",
        "tool_call_id": id,
        "name": name,
        "arguments": arguments,
    })
}

fn finish(reason: &str) -> Value {
    json!({"type": "finish", "reason": reason})
}

fn assert_invalid_fixture(case: &str, fixture: Value) {
    assert_invalid_fixture_json(case, &fixture.to_string());
}

fn assert_invalid_fixture_json(case: &str, fixture: &str) {
    let error = match ScriptedProvider::from_json(fixture) {
        Ok(_) => panic!("{case}: malformed fixture was accepted"),
        Err(error) => error,
    };
    assert!(
        matches!(&error, ProviderError::InvalidFixture { .. }),
        "{case}: wrong typed error: {error:?}"
    );
    assert_eq!(error.code(), ErrorCode::Validation, "{case}");
    assert_eq!(error.code().as_str(), "validation_error", "{case}");
    assert_eq!(
        error.user_message(),
        "The scripted provider fixture is invalid.",
        "{case}"
    );
    assert_eq!(
        error.to_string(),
        "scripted provider fixture is invalid",
        "{case}"
    );
}

#[tokio::test]
async fn provider_trait_is_usable_as_a_dynamic_async_boundary() -> Result<(), Box<dyn Error>> {
    async fn first_event(provider: &dyn Provider) -> Result<ProviderEvent, ProviderError> {
        provider
            .stream(request(CancellationToken::new()))
            .await?
            .next()
            .await
            .expect("fixture response is non-empty")
    }

    let provider = ScriptedProvider::from_json(FIXTURE)?;
    assert!(matches!(
        first_event(&provider).await?,
        ProviderEvent::ToolCall { .. }
    ));
    Ok(())
}

#[test]
fn fixture_is_complete_json_with_no_provider_specific_wire_fields() -> Result<(), Box<dyn Error>> {
    let fixture: Value = serde_json::from_str(FIXTURE)?;
    assert_eq!(fixture["schema_version"], 1);
    assert_eq!(fixture["responses"].as_array().map(Vec::len), Some(2));
    assert!(FIXTURE.contains("tool_call"));
    assert!(FIXTURE.contains("text_delta"));
    assert!(FIXTURE.contains("usage"));
    assert!(FIXTURE.contains("finish"));
    for provider_specific in ["choices", "response.output_item", "data:"] {
        assert!(!FIXTURE.contains(provider_specific));
    }
    Ok(())
}
