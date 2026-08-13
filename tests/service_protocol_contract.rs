use std::{error::Error, path::PathBuf, str::FromStr as _};

use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::policy::Frontend;
use carl::runtime::task::{TaskBudget, TaskId};
use carl::service::protocol::{
    MAX_SERVICE_FRAME_BYTES, MAX_TASK_TEXT_BYTES, MaintenancePhase, ProtocolErrorCode,
    RequestLedger, SERVICE_PROTOCOL_VERSION, ServiceCapabilities, ServiceCommand, ServiceFrame,
    ServiceMaintenanceStatus, ServiceRequest, ServiceResult, StartTaskCommand, command_digest,
    decode_frame_line, decode_request_line, encode_frame, encode_request, is_mutation,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn Error>>;

fn start_command(budget: TaskBudget) -> StartTaskCommand {
    StartTaskCommand {
        frontend: Frontend::Tui,
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
fn version_seven_exposes_strict_durable_tui_sessions() -> TestResult {
    let command = ServiceCommand::Sessions {
        frontend: Frontend::Tui,
        limit: 64,
    };
    let request = ServiceRequest {
        protocol_version: SERVICE_PROTOCOL_VERSION,
        request_id: "sessions-request".to_owned(),
        idempotency_key: "sessions-read-key".to_owned(),
        command: command.clone(),
    };
    assert_eq!(
        decode_request_line(&encode_request(&request)?, &mut RequestLedger::default())?,
        request
    );
    assert_eq!(SERVICE_PROTOCOL_VERSION, 7);
    assert!(!is_mutation(&command));
    Ok(())
}

#[test]
fn version_seven_maintenance_and_capability_round_trip_strictly() -> TestResult {
    let task_id = TaskId::from_str("11111111-1111-4111-8111-111111111111")?;
    let checkpoint_id =
        carl::runtime::task::CheckpointId::from_str("22222222-2222-4222-8222-222222222222")?;
    let literal = format!(
        "{}\n",
        json!({
            "protocol_version": 7,
            "request_id": "maintenance-status-request",
            "idempotency_key": "maintenance-status-read-key",
            "command": {"type":"maintenance_status"}
        })
    );
    let decoded = decode_request_line(literal.as_bytes(), &mut RequestLedger::default())?;
    assert_eq!(decoded.protocol_version, SERVICE_PROTOCOL_VERSION);
    assert_eq!(decoded.command, ServiceCommand::MaintenanceStatus);
    assert!(!is_mutation(&decoded.command));
    assert!(is_mutation(&ServiceCommand::PrepareMaintenance));

    let capabilities: ServiceCapabilities = serde_json::from_value(json!({
        "durable_events": true,
        "reconnect": true,
        "trusted_buzz_admission": true,
        "configure_active_task": true,
        "explicit_task_budgets": true,
        "sanitized_task_metrics": true,
        "recoverable_maintenance": true,
        "explicit_task_compaction": true,
        "durable_frontend_sessions": true
    }))?;
    assert!(capabilities.recoverable_maintenance);

    let frame = ServiceFrame::Response {
        request_id: "maintenance-status-request".to_owned(),
        result: Box::new(ServiceResult::Maintenance(ServiceMaintenanceStatus {
            schema_version: 1,
            phase: MaintenancePhase::Ready,
            task_id: Some(task_id),
            checkpoint_id: Some(checkpoint_id),
        })),
    };
    let encoded = encode_frame(&frame)?;
    assert!(encoded.len() < 1024);
    assert_eq!(decode_frame_line(&encoded)?, frame);
    Ok(())
}

#[test]
fn version_seven_exposes_idempotent_explicit_task_compaction() -> TestResult {
    let task_id = TaskId::from_str("11111111-1111-4111-8111-111111111111")?;
    let request = ServiceRequest {
        protocol_version: SERVICE_PROTOCOL_VERSION,
        request_id: "compact-request".to_owned(),
        idempotency_key: "compact-key".to_owned(),
        command: ServiceCommand::Compact { task_id },
    };
    let encoded = encode_request(&request)?;
    assert_eq!(
        decode_request_line(&encoded, &mut RequestLedger::default())?,
        request
    );
    assert_eq!(SERVICE_PROTOCOL_VERSION, 7);
    assert!(is_mutation(&request.command));

    let capabilities: ServiceCapabilities = serde_json::from_value(json!({
        "durable_events": true,
        "reconnect": true,
        "trusted_buzz_admission": true,
        "configure_active_task": true,
        "explicit_task_budgets": true,
        "sanitized_task_metrics": true,
        "recoverable_maintenance": true,
        "explicit_task_compaction": true,
        "durable_frontend_sessions": true
    }))?;
    assert!(capabilities.explicit_task_compaction);
    Ok(())
}

#[test]
fn maintenance_status_invalid_combinations_and_unknown_fields_fail_closed() -> TestResult {
    let task_id = TaskId::from_str("11111111-1111-4111-8111-111111111111")?;
    let checkpoint_id =
        carl::runtime::task::CheckpointId::from_str("22222222-2222-4222-8222-222222222222")?;
    let invalid = [
        json!({"schema_version":2,"phase":"running","task_id":null,"checkpoint_id":null}),
        json!({"schema_version":1,"phase":"running","task_id":task_id,"checkpoint_id":checkpoint_id}),
        json!({"schema_version":1,"phase":"draining","task_id":null,"checkpoint_id":null}),
        json!({"schema_version":1,"phase":"draining","task_id":task_id,"checkpoint_id":checkpoint_id}),
        json!({"schema_version":1,"phase":"ready","task_id":task_id,"checkpoint_id":null}),
        json!({"schema_version":1,"phase":"ready","task_id":null,"checkpoint_id":checkpoint_id}),
        json!({"schema_version":1,"phase":"ready","task_id":null,"checkpoint_id":null,"detail":"secret/provider/path"}),
    ];
    for value in invalid {
        assert!(
            serde_json::from_value::<ServiceMaintenanceStatus>(value.clone()).is_err(),
            "accepted invalid maintenance status {value}"
        );
    }

    for valid in [
        json!({"schema_version":1,"phase":"running","task_id":null,"checkpoint_id":null}),
        json!({"schema_version":1,"phase":"running","task_id":task_id,"checkpoint_id":null}),
        json!({"schema_version":1,"phase":"draining","task_id":task_id,"checkpoint_id":null}),
        json!({"schema_version":1,"phase":"ready","task_id":null,"checkpoint_id":null}),
        json!({"schema_version":1,"phase":"ready","task_id":task_id,"checkpoint_id":checkpoint_id}),
    ] {
        serde_json::from_value::<ServiceMaintenanceStatus>(valid)?;
    }
    Ok(())
}

#[test]
fn prepare_maintenance_digest_replays_exactly_and_conflicts_with_other_mutations() -> TestResult {
    let first = ServiceRequest {
        protocol_version: SERVICE_PROTOCOL_VERSION,
        request_id: "prepare-1".to_owned(),
        idempotency_key: "maintenance-key".to_owned(),
        command: ServiceCommand::PrepareMaintenance,
    };
    let replay = ServiceRequest {
        request_id: "prepare-2".to_owned(),
        ..first.clone()
    };
    let conflict = ServiceRequest {
        request_id: "shutdown-1".to_owned(),
        command: ServiceCommand::Shutdown,
        ..first.clone()
    };
    let mut ledger = RequestLedger::default();
    assert_eq!(
        decode_request_line(&encode_request(&first)?, &mut ledger)?,
        first
    );
    assert_eq!(
        decode_request_line(&encode_request(&replay)?, &mut ledger)?,
        replay
    );
    assert_eq!(
        decode_request_line(&encode_request(&conflict)?, &mut ledger)
            .expect_err("prepare key reuse with shutdown must conflict")
            .code(),
        ProtocolErrorCode::IdempotencyConflict
    );
    assert_eq!(
        command_digest(&ServiceCommand::PrepareMaintenance)?,
        command_digest(&ServiceCommand::PrepareMaintenance)?
    );
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

    for unsupported_version in [6, 8] {
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
fn metrics_command_digest_is_stable_and_capabilities_fail_closed() -> TestResult {
    let task_id = TaskId::from_str("11111111-1111-4111-8111-111111111111")?;
    let command = ServiceCommand::Metrics { task_id };
    assert_eq!(
        digest_hex(command_digest(&command)?),
        "e276a1292e0d814a5f7414f8918a17845dd28b5c1b98d4321e238be6cb631a6d"
    );

    let exact = json!({
        "durable_events": true,
        "reconnect": true,
        "trusted_buzz_admission": true,
        "configure_active_task": true,
        "explicit_task_budgets": true,
        "sanitized_task_metrics": true,
        "recoverable_maintenance": true,
        "explicit_task_compaction": true,
        "durable_frontend_sessions": true
    });
    let mut missing = exact.clone();
    missing
        .as_object_mut()
        .unwrap()
        .remove("recoverable_maintenance");
    assert!(serde_json::from_value::<ServiceCapabilities>(missing).is_err());
    let mut unknown = exact;
    unknown
        .as_object_mut()
        .unwrap()
        .insert("raw_task_events".to_owned(), json!(true));
    assert!(serde_json::from_value::<ServiceCapabilities>(unknown).is_err());
    Ok(())
}

fn digest_hex(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
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
