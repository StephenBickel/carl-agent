use std::error::Error;

use carl::runtime::task::TaskId;
use carl::service::protocol::{
    MAX_SERVICE_FRAME_BYTES, MAX_TASK_TEXT_BYTES, ProtocolErrorCode, RequestLedger,
    SERVICE_PROTOCOL_VERSION, ServiceCommand, ServiceRequest, decode_request_line, encode_request,
};
use serde_json::json;

type TestResult = Result<(), Box<dyn Error>>;

fn status_request(request_id: &str, idempotency_key: &str) -> ServiceRequest {
    ServiceRequest {
        protocol_version: 1,
        request_id: request_id.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        command: ServiceCommand::Status {
            task_id: TaskId::new(),
        },
    }
}

#[test]
fn version_one_newline_json_round_trips_exactly() -> TestResult {
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
            "protocol_version": 1,
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

    let unsupported = format!(
        "{}\n",
        json!({
            "protocol_version": 2,
            "request_id": "request-2",
            "idempotency_key": "key-2",
            "command": {"type":"status","params":{"task_id":task_id}}
        })
    );
    assert_eq!(
        decode_request_line(unsupported.as_bytes(), &mut ledger)
            .expect_err("unsupported protocol must be rejected")
            .code(),
        ProtocolErrorCode::UnsupportedVersion
    );
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
        "protocol_version":1,
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
            protocol_version: 1,
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
