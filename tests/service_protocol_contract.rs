use std::{error::Error, path::PathBuf};

use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::runtime::task::TaskBudget;
use carl::runtime::task::TaskId;
use carl::service::protocol::{
    MAX_SERVICE_FRAME_BYTES, MAX_TASK_TEXT_BYTES, ProtocolErrorCode, RequestLedger,
    SERVICE_PROTOCOL_VERSION, ServiceCommand, ServiceRequest, StartTaskCommand, command_digest,
    decode_request_line, encode_request,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn Error>>;

fn status_request(request_id: &str, idempotency_key: &str) -> ServiceRequest {
    ServiceRequest {
        protocol_version: SERVICE_PROTOCOL_VERSION,
        request_id: request_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        command: ServiceCommand::Status {
            task_id: TaskId::new(),
        },
    }
}

fn start_command(budget: TaskBudget) -> StartTaskCommand {
    StartTaskCommand {
        external_session_id: "session-1".to_owned(),
        workspace: PathBuf::from("/workspace"),
        request: "Implement the bounded task".to_owned(),
        model: ModelId::parse("gpt-5.6-sol").unwrap(),
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::FullAccess,
        budget,
    }
}

#[test]
fn version_two_newline_json_round_trips_exactly() -> TestResult {
    let request = status_request("request-1", "key-1");
    let encoded = encode_request(&request)?;
    assert_eq!(encoded.last(), Some(&b'\n'));

    let mut ledger = RequestLedger::default();
    assert_eq!(decode_request_line(&encoded, &mut ledger)?, request);
    Ok(())
}

#[test]
fn unknown_fields_and_unsupported_versions_fail_closed() -> TestResult {
    let task_id = TaskId::new();
    let unknown = format!(
        "{}\n",
        json!({
            "protocol_version": SERVICE_PROTOCOL_VERSION,
            "request_id": "request-1",
            "idempotency_key": "key-1",
            "command": {"type":"status","params":{"task_id":task_id}},
            "ignored": true
        })
    );
    let mut ledger = RequestLedger::default();
    assert_eq!(
        decode_request_line(unknown.as_bytes(), &mut ledger)
            .expect_err("unknown field must be rejected")
            .code(),
        ProtocolErrorCode::InvalidFrame
    );

    for unsupported_version in [1, 3] {
        let unsupported = format!(
            "{}\n",
            json!({
                "protocol_version": unsupported_version,
                "request_id": format!("request-{unsupported_version}"),
                "idempotency_key": format!("key-{unsupported_version}"),
                "command": {"type":"status","params":{"task_id":task_id}}
            })
        );
        assert_eq!(
            decode_request_line(unsupported.as_bytes(), &mut ledger)
                .expect_err("unsupported protocol must be rejected")
                .code(),
            ProtocolErrorCode::UnsupportedVersion
        );
    }
    Ok(())
}

#[test]
fn oversized_frames_and_control_identifiers_are_rejected() {
    let mut ledger = RequestLedger::default();
    let oversized = vec![b'x'; MAX_SERVICE_FRAME_BYTES + 2];
    assert_eq!(
        decode_request_line(&oversized, &mut ledger)
            .expect_err("oversized frame must be rejected")
            .code(),
        ProtocolErrorCode::FrameTooLarge
    );

    let mut controlled = serde_json::to_vec(&json!({
        "protocol_version":SERVICE_PROTOCOL_VERSION,
        "request_id":"bad\u{1}",
        "idempotency_key":"key-1",
        "command":{"type":"list"}
    }))
    .expect("literal serializes");
    controlled.push(b'\n');
    assert_eq!(
        decode_request_line(&controlled, &mut ledger)
            .expect_err("control character must be rejected")
            .code(),
        ProtocolErrorCode::InvalidIdentifier
    );
}

#[test]
fn request_ids_are_unique_and_idempotency_keys_bind_one_command_digest() -> TestResult {
    let task_id = TaskId::new();
    let first = ServiceRequest {
        protocol_version: SERVICE_PROTOCOL_VERSION,
        request_id: "request-1".to_owned(),
        idempotency_key: "key-1".to_owned(),
        command: ServiceCommand::Cancel { task_id },
    };
    let same = ServiceRequest {
        request_id: "request-2".to_owned(),
        ..first.clone()
    };
    let different = ServiceRequest {
        request_id: "request-3".to_owned(),
        command: ServiceCommand::Resume { task_id },
        ..first.clone()
    };
    let mut ledger = RequestLedger::default();
    decode_request_line(&encode_request(&first)?, &mut ledger)?;

    assert_eq!(
        decode_request_line(&encode_request(&first)?, &mut ledger)
            .expect_err("duplicate request ID must be rejected")
            .code(),
        ProtocolErrorCode::DuplicateRequestId
    );
    assert_eq!(
        decode_request_line(&encode_request(&same)?, &mut ledger)?,
        same
    );
    assert_eq!(
        decode_request_line(&encode_request(&different)?, &mut ledger)
            .expect_err("key reuse with another command must be rejected")
            .code(),
        ProtocolErrorCode::IdempotencyConflict
    );
    Ok(())
}

#[test]
fn event_pages_enforce_the_durable_store_bounds() -> TestResult {
    for limit in [0, 513] {
        let request = ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: format!("request-{limit}"),
            idempotency_key: format!("key-{limit}"),
            command: ServiceCommand::Events {
                task_id: TaskId::new(),
                after_sequence: None,
                limit,
            },
        };
        assert_eq!(
            decode_request_line(&encode_request(&request)?, &mut RequestLedger::default())
                .expect_err("invalid event limit must be rejected")
                .code(),
            ProtocolErrorCode::InvalidEventLimit
        );
    }
    Ok(())
}

#[test]
fn task_text_is_bounded_to_the_engine_contract() -> TestResult {
    let request = ServiceRequest {
        protocol_version: SERVICE_PROTOCOL_VERSION,
        request_id: "steer-too-large".to_owned(),
        idempotency_key: "steer-too-large-key".to_owned(),
        command: ServiceCommand::Steer {
            task_id: TaskId::new(),
            text: "x".repeat(MAX_TASK_TEXT_BYTES + 1),
        },
    };
    assert_eq!(
        decode_request_line(&encode_request(&request)?, &mut RequestLedger::default())
            .expect_err("engine-sized task text bound must be enforced")
            .code(),
        ProtocolErrorCode::InvalidRequest
    );
    Ok(())
}

#[test]
fn service_info_is_a_versioned_bounded_negotiation_command() -> TestResult {
    let request = ServiceRequest {
        protocol_version: SERVICE_PROTOCOL_VERSION,
        request_id: "info-1".to_owned(),
        idempotency_key: "info-key-1".to_owned(),
        command: ServiceCommand::Info,
    };
    let encoded = encode_request(&request)?;
    assert_eq!(
        decode_request_line(&encoded, &mut RequestLedger::default())?,
        request
    );
    Ok(())
}

#[test]
fn live_poll_request_carries_the_generation_that_owns_its_cursor() -> TestResult {
    let task_id = TaskId::new();
    let mut frame = serde_json::to_vec(&json!({
        "protocol_version":SERVICE_PROTOCOL_VERSION,
        "request_id":"live-generation-request",
        "idempotency_key":"live-generation-key",
        "command":{
            "type":"live_updates",
            "params":{
                "task_id":task_id,
                "live_generation":"11111111-1111-4111-8111-111111111111",
                "after_cursor":7,
                "limit":128
            }
        }
    }))?;
    frame.push(b'\n');
    let decoded = decode_request_line(&frame, &mut RequestLedger::default())?;
    assert_eq!(decoded.request_id, "live-generation-request");
    Ok(())
}

#[test]
fn start_task_requires_a_closed_admission_validated_budget() -> TestResult {
    let base = json!({
        "protocol_version": SERVICE_PROTOCOL_VERSION,
        "request_id": "start-budget",
        "idempotency_key": "start-budget-key",
        "command": {
            "type": "start_task",
            "params": {
                "external_session_id": "session-1",
                "workspace": "/workspace",
                "request": "Implement the bounded task",
                "model": "gpt-5.6-sol",
                "effort": "high",
                "permission_mode": "fullAccess"
            }
        }
    });

    let mut missing = serde_json::to_vec(&base)?;
    missing.push(b'\n');
    assert_eq!(
        decode_request_line(&missing, &mut RequestLedger::default())
            .expect_err("a start without a budget must be rejected")
            .code(),
        ProtocolErrorCode::InvalidFrame
    );

    let mut unknown = base.clone();
    unknown["command"]["params"]["budget"] = serde_json::to_value(TaskBudget::default())?;
    unknown["command"]["params"]["budget"]["unrecognized_limit"] = json!(1);
    let mut unknown = serde_json::to_vec(&unknown)?;
    unknown.push(b'\n');
    assert_eq!(
        decode_request_line(&unknown, &mut RequestLedger::default())
            .expect_err("an unknown budget field must be rejected")
            .code(),
        ProtocolErrorCode::InvalidFrame
    );

    let invalid = [
        TaskBudget {
            max_wall_time_seconds: Some(0),
            ..TaskBudget::default()
        },
        TaskBudget {
            max_wall_time_seconds: Some(86_401),
            ..TaskBudget::default()
        },
        TaskBudget {
            max_provider_requests: Some(0),
            ..TaskBudget::default()
        },
        TaskBudget {
            max_provider_requests: Some(10_001),
            ..TaskBudget::default()
        },
        TaskBudget {
            max_tool_calls: Some(0),
            ..TaskBudget::default()
        },
        TaskBudget {
            max_tool_calls: Some(100_001),
            ..TaskBudget::default()
        },
        TaskBudget {
            soft_epoch_seconds: 29,
            ..TaskBudget::default()
        },
        TaskBudget {
            soft_epoch_seconds: 3_601,
            ..TaskBudget::default()
        },
        TaskBudget {
            soft_epoch_tool_calls: 0,
            ..TaskBudget::default()
        },
        TaskBudget {
            soft_epoch_tool_calls: 1_001,
            ..TaskBudget::default()
        },
    ];
    for (index, budget) in invalid.into_iter().enumerate() {
        let request = ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: format!("invalid-budget-{index}"),
            idempotency_key: format!("invalid-budget-key-{index}"),
            command: ServiceCommand::StartTask(start_command(budget)),
        };
        assert_eq!(
            decode_request_line(&encode_request(&request)?, &mut RequestLedger::default())
                .expect_err("out-of-policy budget must be rejected")
                .code(),
            ProtocolErrorCode::InvalidRequest,
            "accepted invalid budget {budget:?}"
        );
    }
    Ok(())
}

#[test]
fn start_task_accepts_exact_budget_boundaries() -> TestResult {
    for (index, budget) in [
        TaskBudget {
            max_wall_time_seconds: Some(1),
            max_provider_requests: Some(1),
            max_tool_calls: Some(1),
            soft_epoch_seconds: 30,
            soft_epoch_tool_calls: 1,
        },
        TaskBudget {
            max_wall_time_seconds: Some(86_400),
            max_provider_requests: Some(10_000),
            max_tool_calls: Some(100_000),
            soft_epoch_seconds: 3_600,
            soft_epoch_tool_calls: 1_000,
        },
    ]
    .into_iter()
    .enumerate()
    {
        let request = ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: format!("boundary-budget-{index}"),
            idempotency_key: format!("boundary-budget-key-{index}"),
            command: ServiceCommand::StartTask(start_command(budget)),
        };
        assert_eq!(
            decode_request_line(&encode_request(&request)?, &mut RequestLedger::default())?,
            request
        );
    }
    Ok(())
}

#[test]
fn start_command_digest_includes_the_task_budget() -> TestResult {
    let default = ServiceCommand::StartTask(start_command(TaskBudget::default()));
    let bounded = ServiceCommand::StartTask(start_command(TaskBudget {
        max_tool_calls: Some(99),
        ..TaskBudget::default()
    }));

    assert_ne!(command_digest(&default)?, command_digest(&bounded)?);
    Ok(())
}

#[test]
fn read_polling_outlives_the_bounded_request_id_replay_window() -> TestResult {
    let task_id = TaskId::new();
    let mut ledger = RequestLedger::default();
    for index in 0..8_200_u32 {
        let request = ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: format!("poll-{index}"),
            idempotency_key: format!("read-{index}"),
            command: if index % 2 == 0 {
                ServiceCommand::Status { task_id }
            } else {
                ServiceCommand::Events {
                    task_id,
                    after_sequence: Some(u64::from(index)),
                    limit: 128,
                }
            },
        };
        assert_eq!(
            decode_request_line(&encode_request(&request)?, &mut ledger)?,
            request,
            "read request {index} must not permanently fill the connection ledger"
        );
    }

    let recent = ServiceRequest {
        protocol_version: SERVICE_PROTOCOL_VERSION,
        request_id: "poll-8199".to_owned(),
        idempotency_key: "another-read-key".to_owned(),
        command: ServiceCommand::List,
    };
    assert_eq!(
        decode_request_line(&encode_request(&recent)?, &mut ledger)
            .expect_err("a recent request ID remains replay-protected")
            .code(),
        ProtocolErrorCode::DuplicateRequestId
    );

    let evicted = ServiceRequest {
        request_id: "poll-0".to_owned(),
        ..recent
    };
    assert_eq!(
        decode_request_line(&encode_request(&evicted)?, &mut ledger)?,
        evicted,
        "an evicted read request ID must not fail forever"
    );
    Ok(())
}
