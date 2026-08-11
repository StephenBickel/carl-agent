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
    EffectClass, EpochId, EvidenceRef, FilePostcondition, FilePostconditionEntry, OperationId,
    OperationStatus, TaskBudget, TaskEvent, TaskId, TaskReduceErrorCode, TaskSnapshot, TaskStatus,
    TaskValidationErrorCode, classify_effect, reduce_task,
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

fn reduce_events(events: &[TaskEvent]) -> Result<TaskSnapshot, TaskReduceErrorCode> {
    events
        .iter()
        .cloned()
        .enumerate()
        .try_fold(None, |state, (index, event)| {
            reduce_task(state, &envelope(index as u64 + 1, task_id(), event))
                .map(Some)
                .map_err(|error| error.code())
        })
        .map(Option::unwrap)
}

fn assert_every_replay_split_matches(events: &[TaskEvent]) {
    for prefix_len in 1..=events.len() {
        let expected = reduce_events(&events[..prefix_len]).unwrap();
        for split in 0..=prefix_len {
            let intermediate = if split == 0 {
                None
            } else {
                Some(reduce_events(&events[..split]).unwrap())
            };
            let actual = events[split..prefix_len]
                .iter()
                .cloned()
                .enumerate()
                .try_fold(intermediate, |state, (offset, event)| {
                    reduce_task(
                        state,
                        &envelope((split + offset + 1) as u64, task_id(), event),
                    )
                    .map(Some)
                })
                .map(Option::unwrap)
                .unwrap();
            assert_eq!(actual, expected, "prefix {prefix_len}, split {split}");
        }
    }
}

fn assert_invalid_replay_splits(events: &[TaskEvent], expected: TaskReduceErrorCode) {
    assert_eq!(reduce_events(events).unwrap_err(), expected);
    for split in 1..events.len() {
        let intermediate = Some(reduce_events(&events[..split]).unwrap());
        let error = events[split..]
            .iter()
            .cloned()
            .enumerate()
            .try_fold(intermediate, |state, (offset, event)| {
                reduce_task(
                    state,
                    &envelope((split + offset + 1) as u64, task_id(), event),
                )
                .map(Some)
            })
            .unwrap_err();
        assert_eq!(error.code(), expected, "split {split}");
    }
}

fn lifecycle_json(task_event: serde_json::Value) -> serde_json::Value {
    json!({
        "schema_version": 4,
        "type": "task_lifecycle",
        "task_id": task_id(),
        "event": task_event,
    })
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
fn file_postconditions_are_canonical_revalidated_and_debug_redacted() {
    let digest = Sha256Digest::parse("a".repeat(64)).unwrap();
    let postcondition = FilePostcondition::new(vec![
        FilePostconditionEntry::new("src/created.rs".to_owned(), None).unwrap(),
        FilePostconditionEntry::new("src/lib.rs".to_owned(), Some(digest)).unwrap(),
    ])
    .unwrap();
    let event = TaskEvent::OperationFilePostconditionBound {
        operation_id: operation_id(),
        postcondition,
    };
    let encoded = serde_json::to_value(&event).unwrap();
    assert_eq!(encoded["task_event"], "operation_file_postcondition_bound");
    assert_eq!(
        encoded["postcondition"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        serde_json::from_value::<TaskEvent>(encoded.clone()).unwrap(),
        event
    );
    let rendered = format!("{event:?}");
    assert!(!rendered.contains("src/lib.rs"));
    assert!(!rendered.contains(&digest.to_string()));

    let events = [
        created(),
        TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "activate".to_owned(),
        },
        TaskEvent::EpochStarted {
            epoch_id: epoch_id(),
            objective: "edit safely".to_owned(),
        },
        TaskEvent::OperationIntentRecorded {
            operation_id: operation_id(),
            epoch_id: epoch_id(),
            item_id: "edit-1".to_owned(),
            effect_class: EffectClass::IdempotentMutation,
            request_digest: "request-digest".to_owned(),
        },
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::IntentRecorded,
            to: OperationStatus::Started,
            evidence_sequences: Vec::new(),
        },
        event,
    ];
    assert_every_replay_split_matches(&events);

    for path in [
        "../outside",
        "/absolute",
        "src//lib.rs",
        "src\\lib.rs",
        "C:/lib.rs",
    ] {
        assert_eq!(
            FilePostconditionEntry::new(path.to_owned(), None)
                .unwrap_err()
                .code(),
            TaskValidationErrorCode::InvalidFilePostcondition
        );
    }
    let entry = FilePostconditionEntry::new("src/lib.rs".to_owned(), None).unwrap();
    assert_eq!(
        FilePostcondition::new(vec![entry.clone(), entry])
            .unwrap_err()
            .code(),
        TaskValidationErrorCode::InvalidFilePostcondition
    );
    let mut hostile = encoded;
    hostile["postcondition"]["entries"][0]["relative_path"] = json!("../outside");
    assert!(serde_json::from_value::<TaskEvent>(hostile).is_err());
}

#[test]
fn literal_v4_legacy_postcondition_event_deserializes_without_changing_its_payload() {
    const LEGACY_EVENT: &str = r#"{
        "schema_version":4,
        "type":"task_lifecycle",
        "task_id":"11111111-1111-4111-8111-111111111111",
        "event":{
            "task_event":"operation_postcondition_bound",
            "operation_id":"44444444-4444-4444-8444-444444444444",
            "postcondition_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    }"#;

    let event = serde_json::from_str::<Event>(LEGACY_EVENT)
        .expect("the bbe3edf-era v4 event remains readable");
    let encoded = serde_json::to_value(event).unwrap();
    assert_eq!(
        encoded["event"]["task_event"],
        "operation_postcondition_bound"
    );
    assert_eq!(
        encoded["event"]["postcondition_digest"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert!(encoded["event"].get("postcondition").is_none());
}

#[test]
fn legacy_projection_postcondition_digest_survives_decode_and_encode() {
    let snapshot = reduce_events(&[
        created(),
        TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "activate".to_owned(),
        },
        TaskEvent::EpochStarted {
            epoch_id: epoch_id(),
            objective: "legacy replay".to_owned(),
        },
        TaskEvent::OperationIntentRecorded {
            operation_id: operation_id(),
            epoch_id: epoch_id(),
            item_id: "legacy-edit".to_owned(),
            effect_class: EffectClass::IdempotentMutation,
            request_digest: "legacy-request".to_owned(),
        },
    ])
    .unwrap();
    let mut old_projection = serde_json::to_value(snapshot).unwrap();
    let operation = old_projection["operations"][operation_id().to_string()]
        .as_object_mut()
        .unwrap();
    operation.remove("file_postcondition");
    operation.insert(
        "postcondition_digest".to_owned(),
        json!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    );

    let decoded = serde_json::from_value::<TaskSnapshot>(old_projection)
        .expect("the bbe3edf-era projection remains readable");
    let reencoded = serde_json::to_value(decoded).unwrap();
    assert_eq!(
        reencoded["operations"][operation_id().to_string()]["postcondition_digest"],
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
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
fn task_event_metadata_is_bounded_on_decode_and_journal_encode() {
    let invalid_events = [
        lifecycle_json(json!({
            "task_event": "epoch_started",
            "epoch_id": epoch_id(),
            "objective": "x".repeat(16 * 1024 + 1),
        })),
        lifecycle_json(json!({
            "task_event": "state_transitioned",
            "from": "queued",
            "to": "active",
            "reason": "line one\nline two",
        })),
        lifecycle_json(json!({
            "task_event": "operation_intent_recorded",
            "operation_id": operation_id(),
            "epoch_id": epoch_id(),
            "item_id": "i".repeat(129),
            "effect_class": "idempotent_mutation",
            "request_digest": "sha256:request",
        })),
        lifecycle_json(json!({
            "task_event": "epoch_finished",
            "epoch_id": epoch_id(),
            "report_digest": "d".repeat(129),
        })),
        lifecycle_json(json!({
            "task_event": "created",
            "session_id": session_id(),
            "workspace": "relative/workspace",
            "contract": contract(1, ClauseStatus::Pending),
            "budget": TaskBudget::default(),
            "model": "gpt-5.6-sol",
            "effort": "high",
            "permission_mode": "bypassPermissions",
        })),
        lifecycle_json(json!({
            "task_event": "operation_transitioned",
            "operation_id": operation_id(),
            "from": "started",
            "to": "succeeded",
            "evidence_sequences": (1..=257).collect::<Vec<u64>>(),
        })),
    ];

    for invalid in invalid_events {
        assert!(
            serde_json::from_value::<Event>(invalid).is_err(),
            "accepted unbounded task event metadata"
        );
    }

    let invalid_programmatic_event = Event::TaskLifecycle {
        task_id: task_id(),
        event: TaskEvent::ProviderContextBound {
            context_id: "c".repeat(129),
        },
    };
    assert!(serde_json::to_value(invalid_programmatic_event).is_err());
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
        TaskEvent::OperationEvidenceRecorded {
            operation_id: operation_id(),
            result_digest: "sha256:operation-result".into(),
        },
    );
    state = apply(
        Some(state),
        7,
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::Started,
            to: OperationStatus::Succeeded,
            evidence_sequences: vec![6],
        },
    );
    state = apply(
        Some(state),
        8,
        TaskEvent::EpochFinished {
            epoch_id: epoch_id(),
            report_digest: "sha256:epoch-report".into(),
        },
    );
    state = apply(
        Some(state),
        9,
        TaskEvent::CheckpointCommitted {
            checkpoint_id: checkpoint_id(),
            digest: "sha256:checkpoint".into(),
        },
    );
    state = apply(
        Some(state),
        10,
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
        11,
        TaskEvent::ContractRevised {
            contract: contract(2, ClauseStatus::Satisfied),
        },
    );
    state = apply(
        Some(state),
        12,
        TaskEvent::StateTransitioned {
            from: TaskStatus::Active,
            to: TaskStatus::Completing,
            reason: "required evidence verified".into(),
        },
    );
    state = apply(Some(state), 13, TaskEvent::Completed);

    assert_eq!(state.status, TaskStatus::Completed);
    assert_eq!(state.active_epoch, None);
    assert_eq!(state.latest_checkpoint, Some(checkpoint_id()));
    assert_eq!(
        state.operation_status(operation_id()),
        Some(OperationStatus::Succeeded)
    );
    assert_eq!(state.revision, 13);
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
fn safe_boundaries_reject_active_epochs_and_unresolved_operations() {
    let active = apply(
        Some(apply(None, 1, created())),
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
            objective: "safe boundary".into(),
        },
    );
    let intent = apply(
        Some(epoch.clone()),
        4,
        TaskEvent::OperationIntentRecorded {
            operation_id: operation_id(),
            epoch_id: epoch_id(),
            item_id: "operation".into(),
            effect_class: EffectClass::IdempotentMutation,
            request_digest: "sha256:request".into(),
        },
    );
    let started = apply(
        Some(intent),
        5,
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::IntentRecorded,
            to: OperationStatus::Started,
            evidence_sequences: vec![4],
        },
    );

    for event in [
        TaskEvent::EpochFinished {
            epoch_id: epoch_id(),
            report_digest: "sha256:report".into(),
        },
        TaskEvent::CheckpointCommitted {
            checkpoint_id: checkpoint_id(),
            digest: "sha256:checkpoint".into(),
        },
    ] {
        let error = reduce_task(Some(started.clone()), &envelope(6, task_id(), event)).unwrap_err();
        assert_eq!(error.code(), TaskReduceErrorCode::UnsafeBoundary);
    }

    let cancelling = apply(Some(started.clone()), 6, TaskEvent::CancellationRequested);
    let cancellation_error = reduce_task(
        Some(cancelling),
        &envelope(
            7,
            task_id(),
            TaskEvent::StateTransitioned {
                from: TaskStatus::Cancelling,
                to: TaskStatus::Cancelled,
                reason: "provider interrupted with work still in flight".into(),
            },
        ),
    )
    .unwrap_err();
    assert_eq!(
        cancellation_error.code(),
        TaskReduceErrorCode::UnsafeBoundary
    );

    let checkpointed = apply(
        Some(active.clone()),
        3,
        TaskEvent::CheckpointCommitted {
            checkpoint_id: checkpoint_id(),
            digest: "sha256:checkpoint".into(),
        },
    );
    let compacting_epoch = apply(
        Some(checkpointed),
        4,
        TaskEvent::EpochStarted {
            epoch_id: epoch_id(),
            objective: "unsafe compaction".into(),
        },
    );
    let compaction_error = reduce_task(
        Some(compacting_epoch),
        &envelope(
            5,
            task_id(),
            TaskEvent::CompactionCompleted {
                generation: 1,
                checkpoint_id: checkpoint_id(),
                context_package_id: ContextPackageId::new(),
            },
        ),
    )
    .unwrap_err();
    assert_eq!(compaction_error.code(), TaskReduceErrorCode::UnsafeBoundary);

    let satisfied = apply(
        Some(epoch),
        4,
        TaskEvent::ContractRevised {
            contract: contract(2, ClauseStatus::Satisfied),
        },
    );
    let completing = apply(
        Some(satisfied),
        5,
        TaskEvent::StateTransitioned {
            from: TaskStatus::Active,
            to: TaskStatus::Completing,
            reason: "premature".into(),
        },
    );
    let completion_error = reduce_task(
        Some(completing),
        &envelope(6, task_id(), TaskEvent::Completed),
    )
    .unwrap_err();
    assert_eq!(completion_error.code(), TaskReduceErrorCode::UnsafeBoundary);
}

#[test]
fn operation_transitions_require_epoch_ownership_and_terminal_evidence() {
    let events = vec![
        created(),
        TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "start".into(),
        },
        TaskEvent::EpochStarted {
            epoch_id: epoch_id(),
            objective: "evidence binding".into(),
        },
        TaskEvent::OperationIntentRecorded {
            operation_id: operation_id(),
            epoch_id: epoch_id(),
            item_id: "operation".into(),
            effect_class: EffectClass::IdempotentMutation,
            request_digest: "sha256:request".into(),
        },
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::IntentRecorded,
            to: OperationStatus::Started,
            evidence_sequences: vec![4],
        },
    ];
    let started = reduce_events(&events).unwrap();

    let missing = reduce_task(
        Some(started.clone()),
        &envelope(
            6,
            task_id(),
            TaskEvent::OperationTransitioned {
                operation_id: operation_id(),
                from: OperationStatus::Started,
                to: OperationStatus::Succeeded,
                evidence_sequences: vec![],
            },
        ),
    )
    .unwrap_err();
    assert_eq!(
        missing.code(),
        TaskReduceErrorCode::OperationEvidenceMissing
    );

    let future = reduce_task(
        Some(started.clone()),
        &envelope(
            6,
            task_id(),
            TaskEvent::OperationTransitioned {
                operation_id: operation_id(),
                from: OperationStatus::Started,
                to: OperationStatus::Succeeded,
                evidence_sequences: vec![7],
            },
        ),
    )
    .unwrap_err();
    assert_eq!(future.code(), TaskReduceErrorCode::InvalidOperationEvidence);

    let self_evidence = reduce_task(
        Some(started.clone()),
        &envelope(
            6,
            task_id(),
            TaskEvent::OperationTransitioned {
                operation_id: operation_id(),
                from: OperationStatus::Started,
                to: OperationStatus::Succeeded,
                evidence_sequences: vec![6],
            },
        ),
    )
    .unwrap_err();
    assert_eq!(
        self_evidence.code(),
        TaskReduceErrorCode::InvalidOperationEvidence
    );

    let unrelated = reduce_task(
        Some(started.clone()),
        &envelope(
            6,
            task_id(),
            TaskEvent::OperationTransitioned {
                operation_id: operation_id(),
                from: OperationStatus::Started,
                to: OperationStatus::Succeeded,
                evidence_sequences: vec![1],
            },
        ),
    )
    .unwrap_err();
    assert_eq!(
        unrelated.code(),
        TaskReduceErrorCode::InvalidOperationEvidence
    );

    let mut mismatched_json = serde_json::to_value(&started).unwrap();
    mismatched_json["active_epoch"] = serde_json::to_value(EpochId::new()).unwrap();
    let mismatched = serde_json::from_value::<TaskSnapshot>(mismatched_json).unwrap();
    let ownership = reduce_task(
        Some(mismatched),
        &envelope(
            6,
            task_id(),
            TaskEvent::OperationTransitioned {
                operation_id: operation_id(),
                from: OperationStatus::Started,
                to: OperationStatus::Succeeded,
                evidence_sequences: vec![5, 6],
            },
        ),
    )
    .unwrap_err();
    assert_eq!(ownership.code(), TaskReduceErrorCode::EpochMismatch);

    let prior_result = apply(
        Some(started),
        6,
        TaskEvent::OperationEvidenceRecorded {
            operation_id: operation_id(),
            result_digest: "sha256:operation-result".into(),
        },
    );
    let succeeded = reduce_task(
        Some(prior_result),
        &envelope(
            7,
            task_id(),
            TaskEvent::OperationTransitioned {
                operation_id: operation_id(),
                from: OperationStatus::Started,
                to: OperationStatus::Succeeded,
                evidence_sequences: vec![6],
            },
        ),
    )
    .unwrap();
    assert_eq!(
        succeeded.operation_status(operation_id()),
        Some(OperationStatus::Succeeded)
    );
}

#[test]
fn uncertain_operations_accept_fresh_bound_evidence_and_reconcile() {
    let reconciled = reduce_events(&[
        created(),
        TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "start".into(),
        },
        TaskEvent::EpochStarted {
            epoch_id: epoch_id(),
            objective: "reconcile uncertain delivery".into(),
        },
        TaskEvent::OperationIntentRecorded {
            operation_id: operation_id(),
            epoch_id: epoch_id(),
            item_id: "operation".into(),
            effect_class: EffectClass::AmbiguousConsequential,
            request_digest: "sha256:request".into(),
        },
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::IntentRecorded,
            to: OperationStatus::Started,
            evidence_sequences: vec![4],
        },
        TaskEvent::OperationEvidenceRecorded {
            operation_id: operation_id(),
            result_digest: "sha256:uncertain".into(),
        },
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::Started,
            to: OperationStatus::Uncertain,
            evidence_sequences: vec![6],
        },
        TaskEvent::OperationEvidenceRecorded {
            operation_id: operation_id(),
            result_digest: "sha256:reconciled".into(),
        },
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::Uncertain,
            to: OperationStatus::Reconciled,
            evidence_sequences: vec![8],
        },
        TaskEvent::EpochFinished {
            epoch_id: epoch_id(),
            report_digest: "sha256:report".into(),
        },
    ])
    .unwrap();

    assert_eq!(
        reconciled.operation_status(operation_id()),
        Some(OperationStatus::Reconciled)
    );
    assert_eq!(reconciled.active_epoch, None);
}

#[test]
fn terminal_operation_evidence_rejects_unrelated_cross_operation_and_stale_sequences() {
    let started = reduce_events(&[
        created(),
        TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "start".into(),
        },
        TaskEvent::EpochStarted {
            epoch_id: epoch_id(),
            objective: "bind terminal evidence".into(),
        },
        TaskEvent::OperationIntentRecorded {
            operation_id: operation_id(),
            epoch_id: epoch_id(),
            item_id: "operation".into(),
            effect_class: EffectClass::IdempotentMutation,
            request_digest: "sha256:request".into(),
        },
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::IntentRecorded,
            to: OperationStatus::Started,
            evidence_sequences: vec![4],
        },
    ])
    .unwrap();
    let unrelated = apply(
        Some(started.clone()),
        6,
        TaskEvent::ProgressAssessed {
            fingerprint: "not-operation-evidence".into(),
            stalled: false,
        },
    );
    let error = reduce_task(
        Some(unrelated),
        &envelope(
            7,
            task_id(),
            TaskEvent::OperationTransitioned {
                operation_id: operation_id(),
                from: OperationStatus::Started,
                to: OperationStatus::Succeeded,
                evidence_sequences: vec![6],
            },
        ),
    )
    .unwrap_err();
    assert_eq!(error.code(), TaskReduceErrorCode::InvalidOperationEvidence);

    let bound = apply(
        Some(started.clone()),
        6,
        TaskEvent::OperationEvidenceRecorded {
            operation_id: operation_id(),
            result_digest: "sha256:bound".into(),
        },
    );
    let duplicate = reduce_task(
        Some(bound),
        &envelope(
            7,
            task_id(),
            TaskEvent::OperationTransitioned {
                operation_id: operation_id(),
                from: OperationStatus::Started,
                to: OperationStatus::Succeeded,
                evidence_sequences: vec![6, 6],
            },
        ),
    )
    .unwrap_err();
    assert_eq!(duplicate.code(), TaskReduceErrorCode::InvalidEventMetadata);

    let other_operation = OperationId::new();
    let other_intent = apply(
        Some(started.clone()),
        6,
        TaskEvent::OperationIntentRecorded {
            operation_id: other_operation,
            epoch_id: epoch_id(),
            item_id: "other-operation".into(),
            effect_class: EffectClass::Observation,
            request_digest: "sha256:other".into(),
        },
    );
    let other_started = apply(
        Some(other_intent),
        7,
        TaskEvent::OperationTransitioned {
            operation_id: other_operation,
            from: OperationStatus::IntentRecorded,
            to: OperationStatus::Started,
            evidence_sequences: vec![6],
        },
    );
    let other_evidence = apply(
        Some(other_started),
        8,
        TaskEvent::OperationEvidenceRecorded {
            operation_id: other_operation,
            result_digest: "sha256:other-result".into(),
        },
    );
    let error = reduce_task(
        Some(other_evidence),
        &envelope(
            9,
            task_id(),
            TaskEvent::OperationTransitioned {
                operation_id: operation_id(),
                from: OperationStatus::Started,
                to: OperationStatus::Succeeded,
                evidence_sequences: vec![8],
            },
        ),
    )
    .unwrap_err();
    assert_eq!(error.code(), TaskReduceErrorCode::InvalidOperationEvidence);

    let uncertain_evidence = apply(
        Some(started),
        6,
        TaskEvent::OperationEvidenceRecorded {
            operation_id: operation_id(),
            result_digest: "sha256:uncertain".into(),
        },
    );
    let uncertain = apply(
        Some(uncertain_evidence),
        7,
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::Started,
            to: OperationStatus::Uncertain,
            evidence_sequences: vec![6],
        },
    );
    let fresh_evidence = apply(
        Some(uncertain),
        8,
        TaskEvent::OperationEvidenceRecorded {
            operation_id: operation_id(),
            result_digest: "sha256:reconciled".into(),
        },
    );
    let error = reduce_task(
        Some(fresh_evidence),
        &envelope(
            9,
            task_id(),
            TaskEvent::OperationTransitioned {
                operation_id: operation_id(),
                from: OperationStatus::Uncertain,
                to: OperationStatus::Reconciled,
                evidence_sequences: vec![6, 8],
            },
        ),
    )
    .unwrap_err();
    assert_eq!(error.code(), TaskReduceErrorCode::InvalidOperationEvidence);
}

#[test]
fn generated_prefix_replay_matches_incremental_reduction_or_error_code() {
    for terminal in [
        OperationStatus::Succeeded,
        OperationStatus::Failed,
        OperationStatus::Cancelled,
    ] {
        let events = vec![
            created(),
            TaskEvent::StateTransitioned {
                from: TaskStatus::Queued,
                to: TaskStatus::Active,
                reason: "start".into(),
            },
            TaskEvent::ProviderContextBound {
                context_id: "provider-context".into(),
            },
            TaskEvent::EpochStarted {
                epoch_id: epoch_id(),
                objective: "bounded replay".into(),
            },
            TaskEvent::OperationIntentRecorded {
                operation_id: operation_id(),
                epoch_id: epoch_id(),
                item_id: "operation".into(),
                effect_class: EffectClass::IdempotentMutation,
                request_digest: "sha256:request".into(),
            },
            TaskEvent::OperationTransitioned {
                operation_id: operation_id(),
                from: OperationStatus::IntentRecorded,
                to: OperationStatus::Started,
                evidence_sequences: vec![5],
            },
            TaskEvent::OperationEvidenceRecorded {
                operation_id: operation_id(),
                result_digest: "sha256:operation-result".into(),
            },
            TaskEvent::OperationTransitioned {
                operation_id: operation_id(),
                from: OperationStatus::Started,
                to: terminal,
                evidence_sequences: vec![7],
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
            TaskEvent::CheckpointCommitted {
                checkpoint_id: checkpoint_id(),
                digest: "sha256:checkpoint".into(),
            },
            TaskEvent::CompactionRequested {
                generation: 1,
                reason: "context pressure".into(),
            },
            TaskEvent::CompactionCompleted {
                generation: 1,
                checkpoint_id: checkpoint_id(),
                context_package_id: ContextPackageId::from_uuid(uuid(
                    "66666666-6666-4666-8666-666666666666",
                )),
            },
            TaskEvent::ProviderContextLost {
                context_id: "provider-context".into(),
                reason: "replacement".into(),
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
        assert_every_replay_split_matches(&events);
    }

    let reconciled = vec![
        created(),
        TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "start".into(),
        },
        TaskEvent::EpochStarted {
            epoch_id: epoch_id(),
            objective: "reconcile".into(),
        },
        TaskEvent::OperationIntentRecorded {
            operation_id: operation_id(),
            epoch_id: epoch_id(),
            item_id: "operation".into(),
            effect_class: EffectClass::AmbiguousConsequential,
            request_digest: "sha256:request".into(),
        },
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::IntentRecorded,
            to: OperationStatus::Started,
            evidence_sequences: vec![4],
        },
        TaskEvent::OperationEvidenceRecorded {
            operation_id: operation_id(),
            result_digest: "sha256:uncertain-result".into(),
        },
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::Started,
            to: OperationStatus::Uncertain,
            evidence_sequences: vec![6],
        },
        TaskEvent::OperationEvidenceRecorded {
            operation_id: operation_id(),
            result_digest: "sha256:reconciliation-result".into(),
        },
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::Uncertain,
            to: OperationStatus::Reconciled,
            evidence_sequences: vec![8],
        },
        TaskEvent::EpochFinished {
            epoch_id: epoch_id(),
            report_digest: "sha256:report".into(),
        },
    ];
    assert_every_replay_split_matches(&reconciled);

    let cancellation_and_blocker = vec![
        created(),
        TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "start".into(),
        },
        TaskEvent::Blocked {
            reason: "external dependency".into(),
        },
        TaskEvent::StateTransitioned {
            from: TaskStatus::Blocked,
            to: TaskStatus::Active,
            reason: "dependency resolved".into(),
        },
        TaskEvent::CancellationRequested,
        TaskEvent::StateTransitioned {
            from: TaskStatus::Cancelling,
            to: TaskStatus::Cancelled,
            reason: "cancelled safely".into(),
        },
    ];
    assert_every_replay_split_matches(&cancellation_and_blocker);

    let invalid_missing_evidence = vec![
        created(),
        TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "start".into(),
        },
        TaskEvent::EpochStarted {
            epoch_id: epoch_id(),
            objective: "invalid evidence".into(),
        },
        TaskEvent::OperationIntentRecorded {
            operation_id: operation_id(),
            epoch_id: epoch_id(),
            item_id: "operation".into(),
            effect_class: EffectClass::IdempotentMutation,
            request_digest: "sha256:request".into(),
        },
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::IntentRecorded,
            to: OperationStatus::Started,
            evidence_sequences: vec![4],
        },
        TaskEvent::OperationTransitioned {
            operation_id: operation_id(),
            from: OperationStatus::Started,
            to: OperationStatus::Succeeded,
            evidence_sequences: vec![],
        },
    ];
    assert_invalid_replay_splits(
        &invalid_missing_evidence,
        TaskReduceErrorCode::OperationEvidenceMissing,
    );

    let mut invalid_boundary = invalid_missing_evidence[..5].to_vec();
    invalid_boundary.push(TaskEvent::EpochFinished {
        epoch_id: epoch_id(),
        report_digest: "sha256:report".into(),
    });
    assert_invalid_replay_splits(&invalid_boundary, TaskReduceErrorCode::UnsafeBoundary);
}

#[test]
fn background_process_termination_result_is_typed_bounded_and_replay_stable() {
    let termination = TaskEvent::BackgroundProcessTerminationRecorded {
        process_id: "process-123".to_owned(),
        item_id: "verification-item".to_owned(),
        terminated: true,
    };
    let encoded = serde_json::to_value(Event::TaskLifecycle {
        task_id: task_id(),
        event: termination.clone(),
    })
    .unwrap();
    assert_eq!(
        encoded["event"]["task_event"],
        "background_process_termination_recorded"
    );
    assert_eq!(encoded["event"]["process_id"], "process-123");
    assert_eq!(encoded["event"]["item_id"], "verification-item");
    assert_eq!(encoded["event"]["terminated"], true);
    assert_every_replay_split_matches(&[created(), termination]);

    for invalid in [
        TaskEvent::BackgroundProcessTerminationRecorded {
            process_id: String::new(),
            item_id: "verification-item".to_owned(),
            terminated: true,
        },
        TaskEvent::BackgroundProcessTerminationRecorded {
            process_id: "process-123".to_owned(),
            item_id: "x".repeat(129),
            terminated: false,
        },
    ] {
        assert!(invalid.validate().is_err());
    }
}
