use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::error::{BudgetResource, CarlError, ErrorCode};
use carl::events::{
    ApprovalId, EVENT_SCHEMA_VERSION, Event, EventEnvelope, EventId, FrontendDeliveryStatus,
    SessionId, ToolCallId, TurnId,
};
use carl::policy::Frontend;
use carl::runtime::budget::{BudgetTracker, TurnBudget};
use carl::runtime::task::{CompletionContract, TaskBudget, TaskEvent, TaskId};
use chrono::{TimeZone, Utc};
use serde_json::{Value, json};
use std::path::PathBuf;

#[test]
fn every_event_has_a_stable_type_and_schema_version() -> Result<(), Box<dyn std::error::Error>> {
    let tool_call_id = ToolCallId::from_uuid(uuid::Uuid::parse_str(
        "11111111-1111-4111-8111-111111111111",
    )?);
    let approval_id = ApprovalId::from_uuid(uuid::Uuid::parse_str(
        "22222222-2222-4222-8222-222222222222",
    )?);
    let task_id = TaskId::from_uuid(uuid::Uuid::parse_str(
        "33333333-3333-4333-8333-333333333333",
    )?);
    let cases = [
        (
            Event::UserInput {
                text: "hello".into(),
            },
            json!({
                "schema_version": 4,
                "type": "user_input",
                "text": "hello",
            }),
        ),
        (
            Event::AssistantTextDelta {
                text: "world".into(),
            },
            json!({
                "schema_version": 4,
                "type": "assistant_text_delta",
                "text": "world",
            }),
        ),
        (
            Event::ToolProposed {
                tool_call_id,
                tool_name: "fs.read".into(),
                arguments: json!({"path": "notes.txt"}),
            },
            json!({
                "schema_version": 4,
                "type": "tool_proposed",
                "tool_call_id": "11111111-1111-4111-8111-111111111111",
                "tool_name": "fs.read",
                "arguments": {"path": "notes.txt"},
            }),
        ),
        (
            Event::ToolDispatchAuthorized {
                tool_call_id,
                request_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .into(),
                automatic: true,
            },
            json!({
                "schema_version": 4,
                "type": "tool_dispatch_authorized",
                "tool_call_id": "11111111-1111-4111-8111-111111111111",
                "request_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "automatic": true,
            }),
        ),
        (
            Event::ApprovalRequested {
                approval_id,
                tool_call_id,
                summary: "Read notes.txt".into(),
            },
            json!({
                "schema_version": 4,
                "type": "approval_requested",
                "approval_id": "22222222-2222-4222-8222-222222222222",
                "tool_call_id": "11111111-1111-4111-8111-111111111111",
                "summary": "Read notes.txt",
            }),
        ),
        (
            Event::ToolCompleted {
                tool_call_id,
                output: json!({"text": "contents"}),
            },
            json!({
                "schema_version": 4,
                "type": "tool_completed",
                "tool_call_id": "11111111-1111-4111-8111-111111111111",
                "output": {"text": "contents"},
            }),
        ),
        (
            Event::TurnCompleted,
            json!({
                "schema_version": 4,
                "type": "turn_completed",
            }),
        ),
        (
            Event::TurnInterrupted {
                reason: "cancelled".into(),
            },
            json!({
                "schema_version": 4,
                "type": "turn_interrupted",
                "reason": "cancelled",
            }),
        ),
        (
            Event::TaskLifecycle {
                task_id,
                event: TaskEvent::Created {
                    session_id: SessionId::from_uuid(uuid::Uuid::parse_str(
                        "44444444-4444-4444-8444-444444444444",
                    )?),
                    workspace: PathBuf::from("/workspace"),
                    contract: CompletionContract {
                        version: 1,
                        goal: "finish".into(),
                        constraints: vec![],
                        clauses: vec![],
                    },
                    budget: TaskBudget::default(),
                    model: ModelId::parse("gpt-5.6-sol")?,
                    effort: ReasoningEffort::High,
                    permission_mode: PermissionMode::BypassPermissions,
                },
            },
            json!({
                "schema_version": 4,
                "type": "task_lifecycle",
                "task_id": "33333333-3333-4333-8333-333333333333",
                "event": {
                    "task_event": "created",
                    "session_id": "44444444-4444-4444-8444-444444444444",
                    "workspace": "/workspace",
                    "contract": {
                        "version": 1,
                        "goal": "finish",
                        "constraints": [],
                        "clauses": [],
                    },
                    "budget": {
                        "max_wall_time_seconds": null,
                        "max_provider_requests": null,
                        "max_tool_calls": null,
                        "soft_epoch_seconds": 900,
                        "soft_epoch_tool_calls": 40,
                    },
                    "model": "gpt-5.6-sol",
                    "effort": "high",
                    "permission_mode": "bypassPermissions",
                },
            }),
        ),
    ];

    for (event, expected_json) in cases {
        let encoded = serde_json::to_value(&event)?;
        assert_eq!(encoded, expected_json);
        assert_eq!(serde_json::from_value::<Event>(encoded)?, event);
    }

    Ok(())
}

#[test]
fn schema_v1_literal_fixture_remains_readable_and_reencodes_as_current()
-> Result<(), Box<dyn std::error::Error>> {
    const V1_FIXTURE: &str = r#"{
        "schema_version": 1,
        "type": "tool_proposed",
        "tool_call_id": "11111111-1111-4111-8111-111111111111",
        "tool_name": "fs.read",
        "arguments": {"path": "notes.txt"}
    }"#;

    let decoded = serde_json::from_str::<Event>(V1_FIXTURE)?;
    assert_eq!(
        decoded,
        Event::ToolProposed {
            tool_call_id: ToolCallId::from_uuid(uuid::Uuid::parse_str(
                "11111111-1111-4111-8111-111111111111",
            )?),
            tool_name: "fs.read".into(),
            arguments: json!({"path": "notes.txt"}),
        }
    );
    assert_eq!(
        serde_json::to_value(decoded)?["schema_version"],
        EVENT_SCHEMA_VERSION
    );
    assert_eq!(EVENT_SCHEMA_VERSION, 4);

    Ok(())
}

#[test]
fn schema_v2_and_v3_literals_remain_readable_and_frontend_events_use_schema_v4()
-> Result<(), Box<dyn std::error::Error>> {
    let v2 = r#"{
        "schema_version": 2,
        "type": "turn_interrupted",
        "reason": "legacy"
    }"#;
    assert_eq!(
        serde_json::from_str::<Event>(v2)?,
        Event::TurnInterrupted {
            reason: "legacy".into(),
        }
    );
    let v3 = r#"{
        "schema_version": 3,
        "type": "frontend_session_bound",
        "frontend": "buzz",
        "external_session_id": "legacy-buzz-session",
        "protocol_version": 2
    }"#;
    assert_eq!(
        serde_json::from_str::<Event>(v3)?,
        Event::FrontendSessionBound {
            frontend: Frontend::Buzz,
            external_session_id: "legacy-buzz-session".into(),
            protocol_version: 2,
        }
    );

    let cases = [
        Event::FrontendSessionBound {
            frontend: Frontend::Buzz,
            external_session_id: "buzz-session-1".into(),
            protocol_version: 2,
        },
        Event::FrontendPermissionChanged {
            external_session_id: "buzz-session-1".into(),
            permission_mode: PermissionMode::Default,
        },
        Event::FrontendDeliveryTransitioned {
            action_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            status: FrontendDeliveryStatus::Delivered,
        },
    ];
    for event in cases {
        let encoded = serde_json::to_value(&event)?;
        assert_eq!(encoded["schema_version"], 4);
        assert_eq!(serde_json::from_value::<Event>(encoded)?, event);
    }
    Ok(())
}

#[test]
fn event_rejects_an_unknown_future_schema_version() {
    let error = serde_json::from_value::<Event>(json!({
        "schema_version": 5,
        "type": "user_input",
        "text": "hello",
    }))
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("unsupported event schema version 5")
    );
}

#[test]
fn event_envelope_serializes_metadata_and_a_flattened_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let id = EventId::new();
    let session_id = SessionId::new();
    let turn_id = TurnId::new();
    let timestamp = Utc.with_ymd_and_hms(2026, 7, 13, 12, 34, 56).unwrap();
    let envelope = EventEnvelope {
        id,
        session_id,
        turn_id: Some(turn_id),
        sequence: 7,
        timestamp,
        event: Event::UserInput {
            text: "hello".into(),
        },
    };

    let encoded = serde_json::to_value(&envelope)?;
    assert_eq!(encoded["id"], id.to_string());
    assert_eq!(encoded["session_id"], session_id.to_string());
    assert_eq!(encoded["turn_id"], turn_id.to_string());
    assert_eq!(encoded["sequence"], 7);
    assert_eq!(encoded["schema_version"], 4);
    assert_eq!(encoded["timestamp"], "2026-07-13T12:34:56Z");
    assert_eq!(encoded["type"], "user_input");
    assert_eq!(encoded["text"], "hello");
    assert!(encoded.get("event").is_none());
    assert_eq!(envelope.schema_version(), 4);
    assert_eq!(serde_json::from_value::<EventEnvelope>(encoded)?, envelope);

    Ok(())
}

#[test]
fn ids_are_uuid_newtypes_with_string_json_representations() -> Result<(), Box<dyn std::error::Error>>
{
    let ids: [Value; 5] = [
        serde_json::to_value(SessionId::new())?,
        serde_json::to_value(TurnId::new())?,
        serde_json::to_value(EventId::new())?,
        serde_json::to_value(ToolCallId::new())?,
        serde_json::to_value(ApprovalId::new())?,
    ];

    for encoded in ids {
        let text = encoded.as_str().expect("ID must serialize as a string");
        uuid::Uuid::parse_str(text)?;
    }

    Ok(())
}

#[test]
fn budget_tracker_rejects_counts_beyond_each_limit_without_incrementing() {
    let mut tracker = BudgetTracker::new(TurnBudget {
        max_iterations: 1,
        max_tool_calls: 1,
    });

    tracker.try_record_iteration().unwrap();
    assert_eq!(tracker.iterations(), 1);
    assert_eq!(
        tracker.try_record_iteration(),
        Err(CarlError::BudgetExceeded {
            resource: BudgetResource::Iterations,
            limit: 1,
        })
    );
    assert_eq!(tracker.iterations(), 1);

    tracker.try_record_tool_call().unwrap();
    assert_eq!(tracker.tool_calls(), 1);
    assert_eq!(
        tracker.try_record_tool_call(),
        Err(CarlError::BudgetExceeded {
            resource: BudgetResource::ToolCalls,
            limit: 1,
        })
    );
    assert_eq!(tracker.tool_calls(), 1);
}

#[test]
fn zero_budget_rejects_the_first_iteration_and_tool_call() {
    let mut tracker = BudgetTracker::new(TurnBudget::new(0, 0));

    assert_eq!(
        tracker.try_record_iteration(),
        Err(CarlError::BudgetExceeded {
            resource: BudgetResource::Iterations,
            limit: 0,
        })
    );
    assert_eq!(
        tracker.try_record_tool_call(),
        Err(CarlError::BudgetExceeded {
            resource: BudgetResource::ToolCalls,
            limit: 0,
        })
    );
    assert_eq!((tracker.iterations(), tracker.tool_calls()), (0, 0));
}

#[test]
fn errors_expose_stable_codes_and_sanitized_user_messages() -> Result<(), Box<dyn std::error::Error>>
{
    let secret = "provider response included sk-secret";
    let error = CarlError::Provider {
        detail: secret.into(),
    };

    assert_eq!(error.code(), ErrorCode::Provider);
    assert_eq!(error.code().as_str(), "provider_error");
    assert_eq!(serde_json::to_value(error.code())?, "provider_error");
    assert!(!error.user_message().contains(secret));
    assert_eq!(
        CarlError::BudgetExceeded {
            resource: BudgetResource::Iterations,
            limit: 3,
        }
        .code(),
        ErrorCode::BudgetExceeded
    );

    Ok(())
}

#[test]
fn every_error_code_has_a_stable_public_string() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (ErrorCode::Configuration, "configuration_error"),
        (ErrorCode::Authentication, "authentication_error"),
        (ErrorCode::Provider, "provider_error"),
        (ErrorCode::RateLimit, "rate_limit"),
        (ErrorCode::Policy, "policy_error"),
        (ErrorCode::Validation, "validation_error"),
        (ErrorCode::Tool, "tool_error"),
        (ErrorCode::Storage, "storage_error"),
        (ErrorCode::Channel, "channel_error"),
        (ErrorCode::Timeout, "timeout"),
        (ErrorCode::Cancelled, "cancelled"),
        (ErrorCode::BudgetExceeded, "budget_exceeded"),
    ];

    for (code, expected) in cases {
        assert_eq!(code.as_str(), expected);
        assert_eq!(code.to_string(), expected);
        assert_eq!(serde_json::to_value(code)?, expected);
    }

    Ok(())
}

#[test]
fn error_display_does_not_expose_internal_detail() {
    let secret = "provider response included sk-secret";
    let error = CarlError::Provider {
        detail: secret.into(),
    };

    let rendered = error.to_string();
    assert_eq!(rendered, error.user_message());
    assert!(!rendered.contains(secret));
    assert!(matches!(
        error,
        CarlError::Provider { ref detail } if detail == secret
    ));
}
