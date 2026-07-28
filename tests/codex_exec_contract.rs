use std::env;
use std::error::Error;

use carl::delegates::codex::{
    CodexEventNormalizer, CodexProtocolErrorCode, DelegateActivityKind, DelegateEvent,
    DelegateItemPhase, DelegateTerminal, DelegateUsage,
};
use libtest_mimic::{Arguments, Failed, Trial};
use serde_json::json;

type TestResult = Result<(), Box<dyn Error>>;

fn main() {
    let trials = vec![
        test(
            "normalization accepts the documented successful lifecycle",
            normalization_accepts_the_documented_successful_lifecycle,
        ),
        test(
            "normalization rejects lifecycle events out of order",
            normalization_rejects_lifecycle_events_out_of_order,
        ),
        test(
            "normalization rejects a second terminal event",
            normalization_rejects_a_second_terminal_event,
        ),
        test(
            "normalization validates required lifecycle fields",
            normalization_validates_required_lifecycle_fields,
        ),
        test(
            "normalization never retains reasoning text",
            normalization_never_retains_reasoning_text,
        ),
        test(
            "normalization preserves bounded activity status",
            normalization_preserves_bounded_activity_status,
        ),
        test(
            "normalization records unknown event types without raw payloads",
            normalization_records_unknown_event_types_without_raw_payloads,
        ),
        test(
            "normalization rejects oversized provider text",
            normalization_rejects_oversized_provider_text,
        ),
    ];
    libtest_mimic::run(&Arguments::from_iter(env::args_os().skip(1)), trials).exit();
}

fn test(name: &'static str, body: fn() -> TestResult) -> Trial {
    Trial::test(name, move || {
        body().map_err(|error| Failed::from(error.to_string()))
    })
}

fn normalization_accepts_the_documented_successful_lifecycle() -> TestResult {
    let input = [
        json!({
            "type": "thread.started",
            "thread_id": "0199a213-81c0-7800-8aa1-bbab2a035a53"
        }),
        json!({"type": "turn.started"}),
        json!({
            "type": "item.completed",
            "item": {
                "id": "item_1",
                "type": "agent_message",
                "text": "Fixed it."
            }
        }),
        json!({
            "type": "turn.completed",
            "usage": {
                "input_tokens": 120,
                "cached_input_tokens": 100,
                "output_tokens": 30
            }
        }),
    ];

    let mut normalizer = CodexEventNormalizer::new();
    let output = input
        .into_iter()
        .map(|value| normalizer.ingest(value))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    assert_eq!(
        output,
        vec![
            DelegateEvent::ThreadStarted {
                thread_id: "0199a213-81c0-7800-8aa1-bbab2a035a53".into(),
            },
            DelegateEvent::TurnStarted,
            DelegateEvent::AgentMessage {
                text: "Fixed it.".into(),
            },
            DelegateEvent::Terminal(DelegateTerminal::Completed {
                usage: DelegateUsage {
                    input_tokens: 120,
                    cached_input_tokens: 100,
                    output_tokens: 30,
                },
            }),
        ]
    );
    Ok(())
}

fn normalization_rejects_lifecycle_events_out_of_order() -> TestResult {
    let mut normalizer = CodexEventNormalizer::new();
    let error = normalizer
        .ingest(json!({"type": "turn.started"}))
        .expect_err("turn cannot start before its thread");

    assert_eq!(error.code(), CodexProtocolErrorCode::InvalidLifecycle);
    Ok(())
}

fn normalization_rejects_a_second_terminal_event() -> TestResult {
    let mut normalizer = started_normalizer()?;
    normalizer.ingest(completed_event())?;
    let error = normalizer
        .ingest(completed_event())
        .expect_err("a second terminal must fail");

    assert_eq!(error.code(), CodexProtocolErrorCode::InvalidLifecycle);
    Ok(())
}

fn normalization_validates_required_lifecycle_fields() -> TestResult {
    let mut normalizer = CodexEventNormalizer::new();
    let missing = normalizer
        .ingest(json!({"type": "thread.started"}))
        .expect_err("thread id is required");
    assert_eq!(missing.code(), CodexProtocolErrorCode::InvalidEvent);

    let mut normalizer = CodexEventNormalizer::new();
    let wrong_type = normalizer
        .ingest(json!({"type": "thread.started", "thread_id": 7}))
        .expect_err("thread id must be a string");
    assert_eq!(wrong_type.code(), CodexProtocolErrorCode::InvalidEvent);
    Ok(())
}

fn normalization_never_retains_reasoning_text() -> TestResult {
    let mut normalizer = started_normalizer()?;
    let event = normalizer
        .ingest(json!({
            "type": "item.completed",
            "item": {
                "id": "item_reasoning",
                "type": "reasoning",
                "text": "SECRET_REASONING_SENTINEL"
            }
        }))?
        .expect("reasoning produces metadata");

    assert_eq!(
        event,
        DelegateEvent::Activity {
            item_id: "item_reasoning".into(),
            kind: DelegateActivityKind::Reasoning,
            phase: DelegateItemPhase::Completed,
        }
    );
    assert!(!format!("{event:?}").contains("SECRET_REASONING_SENTINEL"));
    Ok(())
}

fn normalization_preserves_bounded_activity_status() -> TestResult {
    let mut normalizer = started_normalizer()?;
    let event = normalizer
        .ingest(json!({
            "type": "item.started",
            "item": {
                "id": "item_command",
                "type": "command_execution",
                "command": "cargo test",
                "status": "in_progress"
            }
        }))?
        .expect("command activity is visible");

    assert_eq!(
        event,
        DelegateEvent::Activity {
            item_id: "item_command".into(),
            kind: DelegateActivityKind::CommandExecution,
            phase: DelegateItemPhase::Started,
        }
    );
    Ok(())
}

fn normalization_records_unknown_event_types_without_raw_payloads() -> TestResult {
    let mut normalizer = CodexEventNormalizer::new();
    let event = normalizer
        .ingest(json!({
            "type": "future.event",
            "secret": "SECRET_PROVIDER_PAYLOAD"
        }))?
        .expect("unknown event becomes compatibility metadata");

    assert_eq!(
        event,
        DelegateEvent::Compatibility {
            event_type: "future.event".into(),
        }
    );
    assert!(!format!("{event:?}").contains("SECRET_PROVIDER_PAYLOAD"));
    Ok(())
}

fn normalization_rejects_oversized_provider_text() -> TestResult {
    let mut normalizer = started_normalizer()?;
    let error = normalizer
        .ingest(json!({
            "type": "item.completed",
            "item": {
                "id": "item_message",
                "type": "agent_message",
                "text": "x".repeat(32_769)
            }
        }))
        .expect_err("oversized text must fail");

    assert_eq!(error.code(), CodexProtocolErrorCode::LimitExceeded);
    Ok(())
}

fn started_normalizer() -> Result<CodexEventNormalizer, Box<dyn Error>> {
    let mut normalizer = CodexEventNormalizer::new();
    normalizer.ingest(json!({
        "type": "thread.started",
        "thread_id": "0199a213-81c0-7800-8aa1-bbab2a035a53"
    }))?;
    normalizer.ingest(json!({"type": "turn.started"}))?;
    Ok(normalizer)
}

fn completed_event() -> serde_json::Value {
    json!({
        "type": "turn.completed",
        "usage": {
            "input_tokens": 1,
            "cached_input_tokens": 0,
            "output_tokens": 1
        }
    })
}
