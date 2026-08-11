use std::path::PathBuf;

use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::events::{Event, EventEnvelope, EventId, SessionId};
use carl::policy::Sha256Digest;
use carl::runtime::agent_port::{
    AgentContextId, AgentEffectKind, AgentEffectRequest, AgentEpochId, AgentItem, AgentRequestId,
};
use carl::runtime::task::{
    CheckpointId, ClauseStatus, CompletionClause, CompletionContract, ContextPackageId,
    EffectClass, EpochId, EvidenceRef, OperationId, OperationStatus, TaskBudget, TaskEvent, TaskId,
    TaskReduceErrorCode, TaskSnapshot, TaskStatus, classify_effect, reduce_task,
};
use chrono::{TimeZone, Utc};
use serde_json::json;
use uuid::Uuid;

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).unwrap()
}

fn task_id() -> TaskId {
    TaskId::from_uuid(uuid("11111111-1111-4111-8111-111111111111"))
}

fn session_id() -> SessionId {
    SessionId::from_uuid(uuid("22222222-2222-4222-8222-222222222222"))
}

fn epoch_id() -> EpochId {
    EpochId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"))
}

fn operation_id() -> OperationId {
    OperationId::from_uuid(uuid("44444444-4444-4444-8444-444444444444"))
}

fn checkpoint_id() -> CheckpointId {
    CheckpointId::from_uuid(uuid("55555555-5555-4555-8555-555555555555"))
}

fn contract(version: u32, status: ClauseStatus) -> CompletionContract {
    CompletionContract {
        version,
        goal: "Ship the durable task reducer".into(),
        constraints: vec!["Preserve legacy event payloads".into()],
        clauses: vec![CompletionClause {
            id: "tests".into(),
            description: "All reducer tests pass".into(),
            required: true,
            status,
            evidence: if status == ClauseStatus::Satisfied {
                vec![EvidenceRef {
                    event_sequence: 9,
                    artifact_digest: Some("sha256:test-report".into()),
                    operation_id: None,
                }]
            } else {
                Vec::new()
            },
        }],
    }
}

fn created() -> TaskEvent {
    TaskEvent::Created {
        session_id: session_id(),
        workspace: PathBuf::from("/workspace"),
        contract: contract(1, ClauseStatus::Pending),
        budget: TaskBudget::default(),
        model: ModelId::parse("gpt-5.6-sol").unwrap(),
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::BypassPermissions,
    }
}

fn envelope(sequence: u64, event_task_id: TaskId, event: TaskEvent) -> EventEnvelope {
    EventEnvelope {
        id: EventId::from_uuid(Uuid::from_u128(0x9000 + u128::from(sequence))),
        session_id: session_id(),
        turn_id: None,
        sequence,
        timestamp: Utc.with_ymd_and_hms(2026, 8, 10, 12, 0, 0).unwrap(),
        event: Event::TaskLifecycle {
            task_id: event_task_id,
            event,
        },
    }
}

fn apply(state: Option<TaskSnapshot>, sequence: u64, event: TaskEvent) -> TaskSnapshot {
    reduce_task(state, &envelope(sequence, task_id(), event)).unwrap()
}

#[test]
fn task_ids_round_trip_as_uuids_without_debug_disclosure() {
    let cases = [
        (
            serde_json::to_value(task_id()).unwrap(),
            format!("{task:?}", task = task_id()),
        ),
        (
            serde_json::to_value(epoch_id()).unwrap(),
            format!("{epoch:?}", epoch = epoch_id()),
        ),
        (
            serde_json::to_value(operation_id()).unwrap(),
            format!("{operation:?}", operation = operation_id()),
        ),
        (
            serde_json::to_value(checkpoint_id()).unwrap(),
            format!("{checkpoint:?}", checkpoint = checkpoint_id()),
        ),
        (
            serde_json::to_value(ContextPackageId::from_uuid(uuid(
                "66666666-6666-4666-8666-666666666666",
            )))
            .unwrap(),
            format!(
                "{context:?}",
                context = ContextPackageId::from_uuid(uuid("66666666-6666-4666-8666-666666666666"))
            ),
        ),
    ];

    for (encoded, debug) in cases {
        let displayed = encoded.as_str().unwrap();
        Uuid::parse_str(displayed).unwrap();
        assert!(!debug.contains(displayed));
        assert!(debug.contains("<redacted>"));
    }

    let encoded = serde_json::to_string(&operation_id()).unwrap();
    assert_eq!(
        serde_json::from_str::<OperationId>(&encoded).unwrap(),
        operation_id()
    );
    assert_eq!(
        task_id().to_string(),
        "11111111-1111-4111-8111-111111111111"
    );
}

#[test]
fn completion_contract_accepts_the_bounded_shape() {
    let value = contract(1, ClauseStatus::Satisfied);
    value.validate().unwrap();
    let encoded = serde_json::to_value(&value).unwrap();
    assert_eq!(encoded["version"], 1);
    assert_eq!(encoded["clauses"][0]["status"], "satisfied");
    assert_eq!(
        serde_json::from_value::<CompletionContract>(encoded).unwrap(),
        value
    );
}

#[test]
fn completion_contract_rejects_each_required_bound() {
    let mut cases = Vec::new();

    let mut empty_goal = contract(1, ClauseStatus::Pending);
    empty_goal.goal = "  ".into();
    cases.push(empty_goal);

    let mut duplicate_ids = contract(1, ClauseStatus::Pending);
    duplicate_ids.clauses.push(duplicate_ids.clauses[0].clone());
    cases.push(duplicate_ids);

    let mut control = contract(1, ClauseStatus::Pending);
    control.constraints = vec!["line one\nline two".into()];
    cases.push(control);

    let mut clauses = contract(1, ClauseStatus::Pending);
    clauses.clauses = (0..65)
        .map(|index| CompletionClause {
            id: format!("clause-{index}"),
            description: "bounded".into(),
            required: false,
            status: ClauseStatus::Pending,
            evidence: Vec::new(),
        })
        .collect();
    cases.push(clauses);

    let mut constraints = contract(1, ClauseStatus::Pending);
    constraints.constraints = (0..129)
        .map(|index| format!("constraint-{index}"))
        .collect();
    cases.push(constraints);

    let mut long_text = contract(1, ClauseStatus::Pending);
    long_text.clauses[0].description = "x".repeat(16 * 1024 + 1);
    cases.push(long_text);

    for invalid in cases {
        assert!(
            invalid.validate().is_err(),
            "accepted invalid contract: {invalid:?}"
        );
    }
}

#[test]
fn task_budget_uses_fixed_soft_epoch_defaults() {
    assert_eq!(
        TaskBudget::default(),
        TaskBudget {
            max_wall_time_seconds: None,
            max_provider_requests: None,
            max_tool_calls: None,
            soft_epoch_seconds: 15 * 60,
            soft_epoch_tool_calls: 40,
        }
    );
}

#[test]
fn only_exact_file_change_effect_requests_are_idempotent_mutations() {
    let request = AgentEffectRequest {
        context_id: AgentContextId::parse("context").unwrap(),
        epoch_id: AgentEpochId::parse("provider-epoch").unwrap(),
        request_id: AgentRequestId::parse("request").unwrap(),
        item_id: "item-1".into(),
        kind: AgentEffectKind::FileChange,
        summary: "edit".into(),
        request_digest: Sha256Digest::parse("a".repeat(64)).unwrap(),
    };
    let item = AgentItem::FileChange {
        item_id: "item-1".into(),
        status: "pending".into(),
        changes: json!([]),
    };
    assert_eq!(
        classify_effect(&request, &item),
        EffectClass::IdempotentMutation
    );

    let mismatched = AgentItem::FileChange {
        item_id: "different-item".into(),
        status: "pending".into(),
        changes: json!([]),
    };
    assert_eq!(
        classify_effect(&request, &mismatched),
        EffectClass::AmbiguousConsequential
    );

    for kind in [
        AgentEffectKind::Command,
        AgentEffectKind::Network,
        AgentEffectKind::External,
    ] {
        let mut consequential = request.clone();
        consequential.kind = kind;
        assert_eq!(
            classify_effect(&consequential, &item),
            EffectClass::AmbiguousConsequential
        );
    }
}

#[test]
fn task_lifecycle_is_a_v4_only_round_trip_event() {
    let event = Event::TaskLifecycle {
        task_id: task_id(),
        event: TaskEvent::EpochStarted {
            epoch_id: epoch_id(),
            objective: "Implement reducer".into(),
        },
    };
    let encoded = serde_json::to_value(&event).unwrap();
    assert_eq!(encoded["schema_version"], 4);
    assert_eq!(encoded["type"], "task_lifecycle");
    assert_eq!(encoded["task_id"], task_id().to_string());
    assert_eq!(encoded["event"]["task_event"], "epoch_started");
    assert_eq!(serde_json::from_value::<Event>(encoded).unwrap(), event);

    let legacy_error = serde_json::from_value::<Event>(json!({
        "schema_version": 3,
        "type": "task_lifecycle",
        "task_id": task_id(),
        "event": {"task_event": "completed"}
    }))
    .unwrap_err();
    assert!(legacy_error.to_string().contains("unknown variant"));
}

#[test]
fn reducer_projects_a_complete_valid_lifecycle() {
    let mut state = apply(None, 1, created());
    assert_eq!(state.status, TaskStatus::Queued);
    assert_eq!(state.revision, 1);

    state = apply(
        Some(state),
        2,
        TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "worker acquired task".into(),
        },
    );
    state = apply(
        Some(state),
        3,
        TaskEvent::EpochStarted {
            epoch_id: epoch_id(),
            objective: "Implement reducer".into(),
        },
    );
    state = apply(
        Some(state),
        4,
        TaskEvent::OperationIntentRecorded {
            operation_id: operation_id(),
            epoch_id: epoch_id(),
            item_id: "edit-1".into(),
            effect_class: EffectClass::IdempotentMutation,
            request_digest: "sha256:edit".into(),
        },
    );
    state = apply(
        Some(state),
        5,
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::IntentRecorded,
            to: OperationStatus::Started,
            evidence_sequences: vec![4],
        },
    );
    state = apply(
        Some(state),
        6,
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::Started,
            to: OperationStatus::Succeeded,
            evidence_sequences: vec![5, 6],
        },
    );
    state = apply(
        Some(state),
        7,
        TaskEvent::EpochFinished {
            epoch_id: epoch_id(),
            report_digest: "sha256:epoch-report".into(),
        },
    );
    state = apply(
        Some(state),
        8,
        TaskEvent::CheckpointCommitted {
            checkpoint_id: checkpoint_id(),
            digest: "sha256:checkpoint".into(),
        },
    );
    state = apply(
        Some(state),
        9,
        TaskEvent::CompactionCompleted {
            generation: 1,
            checkpoint_id: checkpoint_id(),
            context_package_id: ContextPackageId::from_uuid(uuid(
                "66666666-6666-4666-8666-666666666666",
            )),
        },
    );
    state = apply(
        Some(state),
        10,
        TaskEvent::ContractRevised {
            contract: contract(2, ClauseStatus::Satisfied),
        },
    );
    state = apply(
        Some(state),
        11,
        TaskEvent::StateTransitioned {
            from: TaskStatus::Active,
            to: TaskStatus::Completing,
            reason: "required evidence verified".into(),
        },
    );
    state = apply(Some(state), 12, TaskEvent::Completed);

    assert_eq!(state.status, TaskStatus::Completed);
    assert_eq!(state.active_epoch, None);
    assert_eq!(state.latest_checkpoint, Some(checkpoint_id()));
    assert_eq!(
        state.operation_status(operation_id()),
        Some(OperationStatus::Succeeded)
    );
    assert_eq!(state.revision, 12);
}

#[test]
fn reducer_rejects_each_required_invalid_transition_with_stable_codes() {
    assert_eq!(
        TaskReduceErrorCode::IllegalStatusTransition.as_str(),
        "illegal_status_transition"
    );
    assert_eq!(
        serde_json::to_value(TaskReduceErrorCode::OperationIntentMissing).unwrap(),
        "operation_intent_missing"
    );

    let initial = apply(None, 1, created());
    let active = apply(
        Some(initial.clone()),
        2,
        TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "start".into(),
        },
    );
    let epoch = apply(
        Some(active.clone()),
        3,
        TaskEvent::EpochStarted {
            epoch_id: epoch_id(),
            objective: "first".into(),
        },
    );

    let cases = [
        (
            reduce_task(
                Some(initial.clone()),
                &envelope(
                    2,
                    task_id(),
                    TaskEvent::StateTransitioned {
                        from: TaskStatus::Queued,
                        to: TaskStatus::Completed,
                        reason: "skip verification".into(),
                    },
                ),
            ),
            TaskReduceErrorCode::IllegalStatusTransition,
        ),
        (
            reduce_task(
                Some(initial.clone()),
                &envelope(
                    2,
                    TaskId::new(),
                    TaskEvent::StateTransitioned {
                        from: TaskStatus::Queued,
                        to: TaskStatus::Active,
                        reason: "wrong task".into(),
                    },
                ),
            ),
            TaskReduceErrorCode::TaskIdMismatch,
        ),
        (
            reduce_task(
                Some(active.clone()),
                &envelope(
                    3,
                    task_id(),
                    TaskEvent::ContractRevised {
                        contract: contract(1, ClauseStatus::Pending),
                    },
                ),
            ),
            TaskReduceErrorCode::NonMonotonicContractVersion,
        ),
        (
            reduce_task(
                Some(epoch.clone()),
                &envelope(
                    4,
                    task_id(),
                    TaskEvent::EpochStarted {
                        epoch_id: EpochId::new(),
                        objective: "second".into(),
                    },
                ),
            ),
            TaskReduceErrorCode::EpochAlreadyActive,
        ),
        (
            reduce_task(
                Some(active.clone()),
                &envelope(
                    3,
                    task_id(),
                    TaskEvent::OperationTransitioned {
                        operation_id: operation_id(),
                        from: OperationStatus::IntentRecorded,
                        to: OperationStatus::Started,
                        evidence_sequences: vec![],
                    },
                ),
            ),
            TaskReduceErrorCode::OperationIntentMissing,
        ),
        (
            reduce_task(
                Some(active.clone()),
                &envelope(
                    3,
                    task_id(),
                    TaskEvent::CompactionCompleted {
                        generation: 1,
                        checkpoint_id: checkpoint_id(),
                        context_package_id: ContextPackageId::new(),
                    },
                ),
            ),
            TaskReduceErrorCode::CheckpointMissing,
        ),
        (
            reduce_task(
                Some(apply(
                    Some(active.clone()),
                    3,
                    TaskEvent::StateTransitioned {
                        from: TaskStatus::Active,
                        to: TaskStatus::Completing,
                        reason: "premature".into(),
                    },
                )),
                &envelope(4, task_id(), TaskEvent::Completed),
            ),
            TaskReduceErrorCode::RequiredClauseUnsatisfied,
        ),
    ];

    for (result, expected) in cases {
        assert_eq!(result.unwrap_err().code(), expected);
    }

    let satisfied = apply(
        Some(active),
        3,
        TaskEvent::ContractRevised {
            contract: contract(2, ClauseStatus::Satisfied),
        },
    );
    let completing = apply(
        Some(satisfied),
        4,
        TaskEvent::StateTransitioned {
            from: TaskStatus::Active,
            to: TaskStatus::Completing,
            reason: "verified".into(),
        },
    );
    let completed = apply(Some(completing), 5, TaskEvent::Completed);
    let error = reduce_task(
        Some(completed),
        &envelope(
            6,
            task_id(),
            TaskEvent::ProgressAssessed {
                fingerprint: "late".into(),
                stalled: false,
            },
        ),
    )
    .unwrap_err();
    assert_eq!(error.code(), TaskReduceErrorCode::TerminalState);
}

#[test]
fn generated_prefix_replay_matches_incremental_reduction_or_error_code() {
    let valid = vec![
        created(),
        TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "start".into(),
        },
        TaskEvent::EpochStarted {
            epoch_id: epoch_id(),
            objective: "bounded replay".into(),
        },
        TaskEvent::UsageObserved {
            epoch_id: epoch_id(),
            total_tokens: 100,
            context_window: Some(1_000),
        },
        TaskEvent::EpochFinished {
            epoch_id: epoch_id(),
            report_digest: "sha256:report".into(),
        },
        TaskEvent::ContractRevised {
            contract: contract(2, ClauseStatus::Satisfied),
        },
        TaskEvent::StateTransitioned {
            from: TaskStatus::Active,
            to: TaskStatus::Completing,
            reason: "verified".into(),
        },
        TaskEvent::Completed,
    ];

    let envelopes: Vec<_> = valid
        .into_iter()
        .enumerate()
        .map(|(index, event)| envelope(index as u64 + 1, task_id(), event))
        .collect();

    for prefix_len in 1..=envelopes.len() {
        let replayed = envelopes[..prefix_len]
            .iter()
            .try_fold(None, |state, event| reduce_task(state, event).map(Some))
            .map(Option::unwrap);

        let split = prefix_len / 2;
        let intermediate = envelopes[..split]
            .iter()
            .try_fold(None, |state, event| reduce_task(state, event).map(Some))
            .unwrap();
        let incremental = envelopes[split..prefix_len]
            .iter()
            .try_fold(intermediate.clone(), |state, event| {
                reduce_task(state, event).map(Some)
            })
            .map(Option::unwrap);

        assert_eq!(replayed, incremental);
    }

    for invalid_tail in [
        TaskEvent::EpochStarted {
            epoch_id: EpochId::new(),
            objective: "late epoch".into(),
        },
        TaskEvent::ContractRevised {
            contract: contract(1, ClauseStatus::Pending),
        },
        TaskEvent::OperationTransitioned {
            operation_id: OperationId::new(),
            from: OperationStatus::Started,
            to: OperationStatus::Succeeded,
            evidence_sequences: vec![],
        },
    ] {
        let base = &envelopes[..3];
        let invalid = envelope(4, task_id(), invalid_tail);
        let replay_error = base
            .iter()
            .chain(std::iter::once(&invalid))
            .try_fold(None, |state, event| reduce_task(state, event).map(Some))
            .unwrap_err();
        let intermediate = base
            .iter()
            .try_fold(None, |state, event| reduce_task(state, event).map(Some))
            .unwrap();
        let incremental_error = reduce_task(intermediate, &invalid).unwrap_err();
        assert_eq!(replay_error.code(), incremental_error.code());
    }
}
