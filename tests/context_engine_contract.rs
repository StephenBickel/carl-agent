use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::error::CarlError;
use carl::events::{Event, EventEnvelope, EventId, SessionId};
use carl::runtime::task::{
    CanonicalCheckpoint, CheckpointBuildInput, CheckpointError, CheckpointId, ClauseStatus,
    CompactionDecision, CompletionClause, CompletionContract, ContextBudget, ContextEngine,
    ContextError, ContextInput, ContextSourceKind, ContextUnit, DecisionRecord, EffectClass,
    EpochId, ExactIdentifier, OperationId, OperationStatus, ProviderCheckpoint,
    RepositoryCheckpoint, TaskBudget, TaskEvent, TaskId, TaskSnapshot, TaskStatus, WorkEvidence,
    reduce_task,
};
use carl::sidecar::DataRootLock;
use carl::storage::{NewCheckpoint, NewTask, RuntimeStore, Store};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Deserialize)]
struct LongHorizonFixture {
    required_identifier: String,
    narratives: Vec<String>,
    event_fingerprints: Vec<String>,
}

struct TemporaryTaskDatabase {
    root: PathBuf,
    database: PathBuf,
    workspace: PathBuf,
}

impl TemporaryTaskDatabase {
    fn new() -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!("carl-context-{}", Uuid::new_v4()));
        let database = root.join("carl.sqlite3");
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            root,
            database,
            workspace,
        })
    }
}

impl Drop for TemporaryTaskDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).unwrap()
}

fn timestamp(second: u32) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&format!("2026-08-10T12:00:{second:02}Z"))
        .unwrap()
        .with_timezone(&Utc)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn contract() -> CompletionContract {
    CompletionContract {
        version: 1,
        goal: "Continue a long-running task without semantic drift".to_owned(),
        constraints: vec!["Keep durable evidence authoritative".to_owned()],
        clauses: vec![CompletionClause {
            id: "durable".to_owned(),
            description: "Checkpoint state remains reproducible".to_owned(),
            required: false,
            status: ClauseStatus::Pending,
            evidence: Vec::new(),
        }],
    }
}

fn envelope(
    session_id: SessionId,
    task_id: TaskId,
    sequence: u64,
    event: TaskEvent,
) -> EventEnvelope {
    EventEnvelope {
        id: EventId::new(),
        session_id,
        turn_id: None,
        sequence,
        timestamp: timestamp(u32::try_from(sequence).unwrap()),
        event: Event::TaskLifecycle { task_id, event },
    }
}

fn replay(events: &[EventEnvelope]) -> TaskSnapshot {
    events
        .iter()
        .fold(None, |snapshot, event| {
            Some(reduce_task(snapshot, event).unwrap())
        })
        .unwrap()
}

fn canonical_history() -> (TaskSnapshot, Vec<EventEnvelope>, OperationId) {
    let session_id = SessionId::from_uuid(uuid("11111111-1111-4111-8111-111111111111"));
    let task_id = TaskId::from_uuid(uuid("22222222-2222-4222-8222-222222222222"));
    let epoch_id = EpochId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let operation_id = OperationId::from_uuid(uuid("44444444-4444-4444-8444-444444444444"));
    let events = vec![
        envelope(
            session_id,
            task_id,
            1,
            TaskEvent::Created {
                session_id,
                workspace: PathBuf::from("/tmp/carl-context-workspace"),
                contract: contract(),
                budget: TaskBudget::default(),
                model: ModelId::parse("gpt-5.6").unwrap(),
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::Default,
            },
        ),
        envelope(
            session_id,
            task_id,
            2,
            TaskEvent::StateTransitioned {
                from: TaskStatus::Queued,
                to: TaskStatus::Active,
                reason: "start".to_owned(),
            },
        ),
        envelope(
            session_id,
            task_id,
            3,
            TaskEvent::EpochStarted {
                epoch_id,
                objective: "produce durable evidence".to_owned(),
            },
        ),
        envelope(
            session_id,
            task_id,
            4,
            TaskEvent::OperationIntentRecorded {
                operation_id,
                epoch_id,
                item_id: "tool-item-1".to_owned(),
                effect_class: EffectClass::IdempotentMutation,
                request_digest: digest(b"request"),
            },
        ),
        envelope(
            session_id,
            task_id,
            5,
            TaskEvent::OperationTransitioned {
                operation_id,
                from: OperationStatus::IntentRecorded,
                to: OperationStatus::Started,
                evidence_sequences: Vec::new(),
            },
        ),
        envelope(
            session_id,
            task_id,
            6,
            TaskEvent::ProgressAssessed {
                fingerprint: digest(b"result"),
                stalled: false,
            },
        ),
        envelope(
            session_id,
            task_id,
            7,
            TaskEvent::OperationTransitioned {
                operation_id,
                from: OperationStatus::Started,
                to: OperationStatus::Succeeded,
                evidence_sequences: vec![6],
            },
        ),
        envelope(
            session_id,
            task_id,
            8,
            TaskEvent::EpochFinished {
                epoch_id,
                report_digest: digest(b"report"),
            },
        ),
    ];
    (replay(&events), events, operation_id)
}

fn build_input(snapshot: TaskSnapshot, events: Vec<EventEnvelope>) -> CheckpointBuildInput {
    let artifact = b"diff --git a/src/lib.rs b/src/lib.rs\n".to_vec();
    let artifact_digest = digest(&artifact);
    CheckpointBuildInput {
        checkpoint_id: CheckpointId::from_uuid(uuid("55555555-5555-4555-8555-555555555555")),
        snapshot,
        events,
        completed_work: vec![WorkEvidence {
            summary: "Recorded the operation result".to_owned(),
            event_sequences: vec![6],
            artifact_digests: vec![artifact_digest.clone()],
        }],
        decisions: vec![DecisionRecord {
            id: "decision-1".to_owned(),
            decision: "Keep the journal authoritative".to_owned(),
            rationale: "Provider contexts are replaceable".to_owned(),
        }],
        exact_identifiers: vec![ExactIdentifier {
            kind: "symbol".to_owned(),
            value: "needle_7f3a91c2".to_owned(),
        }],
        required_identifiers: vec![ExactIdentifier {
            kind: "symbol".to_owned(),
            value: "needle_7f3a91c2".to_owned(),
        }],
        repository: RepositoryCheckpoint {
            workspace_digest: digest(b"workspace"),
            git_head: Some("0123456789abcdef".to_owned()),
            git_status_digest: Some(digest(b"clean")),
            diff_artifact_digest: Some(artifact_digest.clone()),
            file_hashes: BTreeMap::from([("src/lib.rs".to_owned(), digest(b"lib"))]),
        },
        running_processes: Vec::new(),
        pending_approval_digests: Vec::new(),
        pending_steering_digests: Vec::new(),
        uncertain_delivery_digests: Vec::new(),
        next_objective: "continue from canonical evidence".to_owned(),
        blockers: Vec::new(),
        provider: ProviderCheckpoint {
            provider: "codex".to_owned(),
            model: "gpt-5.6".to_owned(),
            effort: "high".to_owned(),
            context_id: None,
            observed_total_tokens: None,
            observed_context_window: None,
        },
        compaction_generation: 0,
        previous_checkpoint: None,
        artifact_contents: BTreeMap::from([(artifact_digest, artifact)]),
        model_narrative: Some("non-authoritative provider prose".to_owned()),
    }
}

#[test]
fn checkpoint_bytes_are_canonical_across_event_insertion_orders() -> TestResult {
    let (snapshot, events, operation_id) = canonical_history();
    let forward = CanonicalCheckpoint::build(build_input(snapshot.clone(), events.clone()))?;
    let mut reverse_events = events;
    reverse_events.reverse();
    let reverse = CanonicalCheckpoint::build(build_input(snapshot, reverse_events))?;

    assert_eq!(forward.canonical_bytes()?, reverse.canonical_bytes()?);
    assert_eq!(forward.digest()?, reverse.digest()?);
    assert!(
        forward
            .digest()?
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(forward.operations[0].operation_id, operation_id);
    assert_eq!(forward.operations[0].status, OperationStatus::Succeeded);
    assert!(!String::from_utf8(forward.canonical_bytes()?)?.contains("provider prose"));

    let mut ordered = forward.clone();
    ordered.pending_approval_digests = vec!["approval-a".to_owned(), "approval-b".to_owned()];
    let mut reordered = forward;
    reordered.pending_approval_digests = vec!["approval-b".to_owned(), "approval-a".to_owned()];
    assert_eq!(ordered.canonical_bytes()?, reordered.canonical_bytes()?);
    Ok(())
}

#[test]
fn checkpoint_validation_rejects_lost_ids_bad_operations_evidence_and_artifacts() {
    let (snapshot, events, _) = canonical_history();

    let mut missing_identifier = build_input(snapshot.clone(), events.clone());
    missing_identifier.exact_identifiers.clear();
    assert_eq!(
        CanonicalCheckpoint::build(missing_identifier).unwrap_err(),
        CheckpointError::MissingRequiredIdentifier
    );

    let mut dangling = build_input(snapshot.clone(), events.clone());
    dangling.events.remove(3);
    assert_eq!(
        CanonicalCheckpoint::build(dangling).unwrap_err(),
        CheckpointError::DanglingOperation
    );

    let mut unpaired = build_input(snapshot.clone(), events.clone());
    unpaired.events.truncate(6);
    assert_eq!(
        CanonicalCheckpoint::build(unpaired).unwrap_err(),
        CheckpointError::UnpairedOperation
    );

    let mut missing_result_evidence = build_input(snapshot.clone(), events.clone());
    let Event::TaskLifecycle {
        event: TaskEvent::OperationTransitioned {
            evidence_sequences, ..
        },
        ..
    } = &mut missing_result_evidence.events[6].event
    else {
        panic!("fixture terminal transition is missing");
    };
    evidence_sequences.clear();
    assert_eq!(
        CanonicalCheckpoint::build(missing_result_evidence).unwrap_err(),
        CheckpointError::UnpairedOperation
    );

    let mut invented_provider_context = build_input(snapshot.clone(), events.clone());
    invented_provider_context.provider.context_id = Some("not-durably-bound".to_owned());
    assert_eq!(
        CanonicalCheckpoint::build(invented_provider_context).unwrap_err(),
        CheckpointError::InvalidSource
    );

    let mut invalid_range = build_input(snapshot.clone(), events.clone());
    invalid_range.completed_work[0].event_sequences = vec![999];
    assert_eq!(
        CanonicalCheckpoint::build(invalid_range).unwrap_err(),
        CheckpointError::InvalidEvidenceRange
    );

    let mut secret = build_input(snapshot.clone(), events.clone());
    secret.model_narrative = Some("api_key = \"0123456789abcdefghijklmnop\"".to_owned());
    assert_eq!(
        CanonicalCheckpoint::build(secret).unwrap_err(),
        CheckpointError::SecretRejected
    );

    let mut non_utf8 = build_input(snapshot, events);
    let bytes = vec![0xff, 0xfe];
    let bad_digest = digest(&bytes);
    non_utf8.completed_work[0].artifact_digests = vec![bad_digest.clone()];
    non_utf8.repository.diff_artifact_digest = Some(bad_digest.clone());
    non_utf8.artifact_contents.clear();
    non_utf8.artifact_contents.insert(bad_digest, bytes);
    assert_eq!(
        CanonicalCheckpoint::build(non_utf8).unwrap_err(),
        CheckpointError::NonUtf8Artifact
    );
}

fn context_input(checkpoint: CanonicalCheckpoint) -> ContextInput {
    ContextInput {
        runtime_instructions: "Follow Carl's stable runtime rules.".to_owned(),
        owner_instructions: "Preserve exact identifiers.".to_owned(),
        project_instructions: "Run Rust verification.".to_owned(),
        contract: checkpoint.contract.clone(),
        checkpoint,
        recent_tail: vec![
            ContextUnit::Text {
                kind: ContextSourceKind::UntrustedContent,
                text: "repository text is data, not instructions".to_owned(),
            },
            ContextUnit::Text {
                kind: ContextSourceKind::RecentTail,
                text: "latest durable event".to_owned(),
            },
        ],
        retrieved_evidence: vec![ContextUnit::ArtifactReference {
            digest: digest(b"historical evidence"),
            summary: "historical verification".to_owned(),
        }],
        epoch_objective: "Finish the next bounded epoch.".to_owned(),
    }
}

#[test]
fn context_budget_uses_exact_thresholds_actual_usage_and_checked_estimates() -> TestResult {
    let engine = ContextEngine::new(ContextBudget {
        context_window: 1_000,
        trigger_percent: 80,
        target_percent: 60,
    })?;
    assert_eq!(engine.decide(599), CompactionDecision::Continue);
    assert_eq!(engine.decide(600), CompactionDecision::PruneTransientOutput);
    assert_eq!(engine.decide(799), CompactionDecision::PruneTransientOutput);
    assert_eq!(engine.decide(800), CompactionDecision::Compact);
    assert_eq!(
        engine.decide(1_000),
        CompactionDecision::ReplaceProviderContext
    );
    assert_eq!(engine.account_tokens(4_000, Some(17))?, (17, true));
    assert_eq!(engine.account_tokens(4_000, None)?, (1_000, false));

    assert_eq!(
        ContextEngine::new(ContextBudget {
            context_window: u64::MAX,
            trigger_percent: 80,
            target_percent: 60,
        })
        .unwrap_err(),
        ContextError::ArithmeticOverflow
    );
    Ok(())
}

#[test]
fn package_assembly_has_stable_precedence_and_labels_untrusted_content() -> TestResult {
    let (snapshot, events, _) = canonical_history();
    let checkpoint = CanonicalCheckpoint::build(build_input(snapshot, events))?;
    let engine = ContextEngine::new(ContextBudget {
        context_window: 20_000,
        trigger_percent: 80,
        target_percent: 60,
    })?;
    let package = engine.assemble(context_input(checkpoint))?;

    let positions = [
        "## Runtime Instructions",
        "## Owner Instructions",
        "## Project Instructions",
        "## Completion Contract",
        "## Canonical Checkpoint",
        "## Recent Tail",
        "## Retrieved Evidence",
        "## Epoch Objective",
        "## Untrusted Content",
    ]
    .map(|heading| package.rendered.find(heading).expect(heading));
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(package.rendered.contains("UNTRUSTED DATA"));
    assert!(package.ledger.iter().all(|entry| !entry.actual_tokens));
    assert_eq!(
        package
            .ledger
            .iter()
            .filter(|entry| entry.included)
            .map(|entry| entry.token_count)
            .sum::<u64>(),
        package.total_tokens()?
    );
    assert!(package.total_tokens()? <= 12_000);
    Ok(())
}

#[test]
fn package_canonicalization_rejects_rendered_content_that_disagrees_with_its_ledger() -> TestResult
{
    let (snapshot, events, _) = canonical_history();
    let checkpoint = CanonicalCheckpoint::build(build_input(snapshot, events))?;
    let engine = ContextEngine::new(ContextBudget {
        context_window: 20_000,
        trigger_percent: 80,
        target_percent: 60,
    })?;
    let mut package = engine.assemble(context_input(checkpoint))?;
    package.rendered.replace_range(..1, "!");

    assert_eq!(package.digest().unwrap_err(), ContextError::InvalidSource);
    Ok(())
}

#[test]
fn tool_request_and_result_are_pruned_as_one_atomic_unit() -> TestResult {
    let (snapshot, events, operation_id) = canonical_history();
    let checkpoint = CanonicalCheckpoint::build(build_input(snapshot, events))?;
    let mut input = context_input(checkpoint);
    input.recent_tail = vec![ContextUnit::ToolExchange {
        operation_id,
        request: "request-marker".to_owned(),
        result: format!("result-marker {}", "x".repeat(40_000)),
    }];
    let engine = ContextEngine::new(ContextBudget {
        context_window: 8_000,
        trigger_percent: 80,
        target_percent: 60,
    })?;
    let package = engine.assemble(input)?;

    assert!(!package.rendered.contains("request-marker"));
    assert!(!package.rendered.contains("result-marker"));
    assert!(
        package
            .rendered
            .contains("tool_exchange_artifact_reference")
    );
    assert!(package.rendered.contains(&operation_id.to_string()));
    assert!(package.ledger.iter().any(|entry| {
        !entry.included
            && entry.omission_reason.as_deref() == Some("replaced_by_artifact_reference")
    }));
    Ok(())
}

#[test]
fn mandatory_sources_fail_closed_when_they_exceed_the_target_budget() -> TestResult {
    let (snapshot, events, _) = canonical_history();
    let checkpoint = CanonicalCheckpoint::build(build_input(snapshot, events))?;
    let engine = ContextEngine::new(ContextBudget {
        context_window: 100,
        trigger_percent: 80,
        target_percent: 60,
    })?;
    assert_eq!(
        engine.assemble(context_input(checkpoint)).unwrap_err(),
        ContextError::MandatorySourcesExceedBudget
    );
    Ok(())
}

#[test]
fn optional_sources_cannot_crowd_out_the_mandatory_epoch_objective() -> TestResult {
    let (snapshot, events, _) = canonical_history();
    let checkpoint = CanonicalCheckpoint::build(build_input(snapshot, events))?;
    let mut input = context_input(checkpoint);
    input.recent_tail = (0..4_000)
        .map(|_| ContextUnit::Text {
            kind: ContextSourceKind::RecentTail,
            text: "x".to_owned(),
        })
        .collect();
    let engine = ContextEngine::new(ContextBudget {
        context_window: 3_000,
        trigger_percent: 80,
        target_percent: 60,
    })?;
    let package = engine.assemble(input)?;

    assert!(package.rendered.contains("## Epoch Objective"));
    assert!(package.rendered.contains("Finish the next bounded epoch."));
    assert!(package.total_tokens()? <= 1_800);
    Ok(())
}

#[test]
fn twelve_compactions_preserve_canonical_truth_without_narrative_drift() -> TestResult {
    let fixture: LongHorizonFixture =
        serde_json::from_str(include_str!("fixtures/provider/long_horizon_context.json"))?;
    assert_eq!(fixture.narratives.len(), 12);
    assert_eq!(fixture.event_fingerprints.len(), 11);

    let (mut snapshot, events, _) = canonical_history();
    let mut input = build_input(snapshot.clone(), events);
    input.model_narrative = Some(fixture.narratives[0].clone());
    let mut checkpoint = CanonicalCheckpoint::build(input)?;

    for generation in 1..12_u32 {
        let sequence = 8 + u64::from(generation);
        let event = envelope(
            snapshot.session_id,
            snapshot.task_id,
            sequence,
            TaskEvent::ProgressAssessed {
                fingerprint: fixture.event_fingerprints[generation as usize - 1].clone(),
                stalled: false,
            },
        );
        snapshot = reduce_task(Some(snapshot), &event)?;
        let mut input = build_input(snapshot.clone(), vec![event]);
        input.checkpoint_id = CheckpointId::new();
        input.completed_work.clear();
        input.decisions.clear();
        input.exact_identifiers.clear();
        input.required_identifiers = vec![ExactIdentifier {
            kind: "symbol".to_owned(),
            value: fixture.required_identifier.clone(),
        }];
        input.previous_checkpoint = Some(checkpoint);
        input.compaction_generation = generation;
        input.model_narrative = Some(fixture.narratives[generation as usize].clone());
        checkpoint = CanonicalCheckpoint::build(input)?;

        let bytes = String::from_utf8(checkpoint.canonical_bytes()?)?;
        assert!(bytes.contains(&fixture.required_identifier));
        assert!(!fixture.narratives.iter().any(|prose| bytes.contains(prose)));
    }
    assert_eq!(checkpoint.compaction_generation, 11);
    assert_eq!(checkpoint.source_sequence_start, 1);
    assert_eq!(checkpoint.source_sequence_end, 19);
    Ok(())
}

fn storage_task(session_id: SessionId, workspace: &Path) -> NewTask {
    NewTask {
        session_id,
        workspace: workspace.to_owned(),
        contract: contract(),
        model: ModelId::parse("gpt-5.6").unwrap(),
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::Default,
        budget: TaskBudget::default(),
        created_at: timestamp(0),
    }
}

fn storage_checkpoint_input(
    task: &carl::storage::TaskRecord,
    events: Vec<EventEnvelope>,
) -> CheckpointBuildInput {
    let mut input = build_input(task.snapshot.clone(), events);
    input.checkpoint_id = CheckpointId::new();
    input.completed_work.clear();
    input.decisions.clear();
    input.exact_identifiers = vec![ExactIdentifier {
        kind: "task".to_owned(),
        value: task.snapshot.task_id.to_string(),
    }];
    input.required_identifiers = input.exact_identifiers.clone();
    input.repository.diff_artifact_digest = None;
    input.artifact_contents.clear();
    input
}

#[test]
fn checkpoint_and_context_payloads_commit_atomically_with_the_journal() -> TestResult {
    let fixture = TemporaryTaskDatabase::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let task = store.create_task(storage_task(session.id, &fixture.workspace))?;
    let events = store.read_task_events(task.snapshot.task_id)?;
    let checkpoint = CanonicalCheckpoint::build(storage_checkpoint_input(&task, events))?;
    let engine = ContextEngine::new(ContextBudget {
        context_window: 20_000,
        trigger_percent: 80,
        target_percent: 60,
    })?;
    let context_package = engine.assemble(context_input(checkpoint.clone()))?;
    let checkpoint_digest = checkpoint.digest()?;
    let context_package_digest = context_package.digest()?;
    let input = NewCheckpoint {
        task_id: task.snapshot.task_id,
        checkpoint,
        checkpoint_digest: checkpoint_digest.clone(),
        context_package,
        context_package_digest: context_package_digest.clone(),
        created_at: timestamp(1),
    };

    let record = store
        .commit_checkpoint(input, task.revision)?
        .expect("revision matches");
    assert_eq!(record.checkpoint_digest, checkpoint_digest);
    assert_eq!(record.context_package_digest, context_package_digest);
    assert_eq!(store.read_task_events(task.snapshot.task_id)?.len(), 2);
    assert_eq!(
        store
            .get_task(task.snapshot.task_id)?
            .unwrap()
            .snapshot
            .latest_checkpoint,
        Some(record.checkpoint.checkpoint_id)
    );

    let connection = rusqlite::Connection::open(&fixture.database)?;
    let payloads = connection.query_row(
        "SELECT checkpoint.checkpoint_json, package.package_json
         FROM task_checkpoints AS checkpoint
         JOIN task_context_packages AS package
           ON package.task_id = checkpoint.task_id
          AND package.checkpoint_id = checkpoint.id
         WHERE checkpoint.task_id = ?1",
        [task.snapshot.task_id.to_string()],
        |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<String>>(1)?,
            ))
        },
    )?;
    assert!(payloads.0.is_some());
    assert!(payloads.1.is_some());
    Ok(())
}

#[test]
fn checkpoint_commit_rejects_bad_digests_unknown_artifacts_and_revision_conflicts() -> TestResult {
    let fixture = TemporaryTaskDatabase::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let task = store.create_task(storage_task(session.id, &fixture.workspace))?;
    let events = store.read_task_events(task.snapshot.task_id)?;
    let mut checkpoint_input = storage_checkpoint_input(&task, events);
    let artifact = b"known to builder but not registered durably".to_vec();
    let artifact_digest = digest(&artifact);
    checkpoint_input.completed_work = vec![WorkEvidence {
        summary: "unregistered artifact".to_owned(),
        event_sequences: vec![1],
        artifact_digests: vec![artifact_digest.clone()],
    }];
    checkpoint_input
        .artifact_contents
        .insert(artifact_digest, artifact);
    let checkpoint = CanonicalCheckpoint::build(checkpoint_input)?;
    let engine = ContextEngine::new(ContextBudget {
        context_window: 20_000,
        trigger_percent: 80,
        target_percent: 60,
    })?;
    let package = engine.assemble(context_input(checkpoint.clone()))?;
    let input = NewCheckpoint {
        task_id: task.snapshot.task_id,
        checkpoint: checkpoint.clone(),
        checkpoint_digest: checkpoint.digest()?,
        context_package_digest: package.digest()?,
        context_package: package,
        created_at: timestamp(1),
    };
    assert!(matches!(
        store.commit_checkpoint(input, task.revision),
        Err(CarlError::Validation { .. })
    ));
    assert_eq!(store.read_task_events(task.snapshot.task_id)?.len(), 1);

    let events = store.read_task_events(task.snapshot.task_id)?;
    let checkpoint = CanonicalCheckpoint::build(storage_checkpoint_input(&task, events))?;
    let package = engine.assemble(context_input(checkpoint.clone()))?;
    let bad_digest = NewCheckpoint {
        task_id: task.snapshot.task_id,
        checkpoint,
        checkpoint_digest: "0".repeat(64),
        context_package_digest: package.digest()?,
        context_package: package,
        created_at: timestamp(2),
    };
    assert!(matches!(
        store.commit_checkpoint(bad_digest, task.revision),
        Err(CarlError::Validation { .. })
    ));
    assert_eq!(store.read_task_events(task.snapshot.task_id)?.len(), 1);
    Ok(())
}

#[test]
fn startup_rejects_a_context_payload_that_disagrees_with_its_ledger() -> TestResult {
    let fixture = TemporaryTaskDatabase::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let task = store.create_task(storage_task(session.id, &fixture.workspace))?;
    let events = store.read_task_events(task.snapshot.task_id)?;
    let checkpoint = CanonicalCheckpoint::build(storage_checkpoint_input(&task, events))?;
    let engine = ContextEngine::new(ContextBudget {
        context_window: 20_000,
        trigger_percent: 80,
        target_percent: 60,
    })?;
    let package = engine.assemble(context_input(checkpoint.clone()))?;
    let checkpoint_digest = checkpoint.digest()?;
    let package_digest = package.digest()?;
    store
        .commit_checkpoint(
            NewCheckpoint {
                task_id: task.snapshot.task_id,
                checkpoint,
                checkpoint_digest,
                context_package: package,
                context_package_digest: package_digest,
                created_at: timestamp(1),
            },
            task.revision,
        )?
        .expect("checkpoint commit succeeds");
    drop(store);

    let connection = rusqlite::Connection::open(&fixture.database)?;
    connection.execute(
        "UPDATE task_context_packages
         SET package_json = json_set(package_json, '$.rendered', '!tampered')",
        [],
    )?;
    drop(connection);

    let error = match Store::open(&fixture.database) {
        Ok(_) => panic!("invalid canonical context payload is rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, CarlError::Storage { .. }));
    Ok(())
}

#[cfg(unix)]
#[test]
fn runtime_reconciliation_retains_artifacts_referenced_by_checkpoints() -> TestResult {
    let fixture = TemporaryTaskDatabase::new()?;
    let mut runtime = RuntimeStore::open(DataRootLock::acquire(&fixture.root)?, timestamp(0))?;
    let artifact = b"durable checkpoint evidence";
    let stored = runtime.artifacts().put(artifact)?;
    let artifact_id = stored.id().clone();
    let connection = rusqlite::Connection::open(&fixture.database)?;
    connection.execute(
        "INSERT INTO artifact_objects (id, byte_length, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![
            artifact_id.as_str(),
            i64::try_from(artifact.len())?,
            timestamp(0).to_rfc3339(),
        ],
    )?;
    drop(connection);

    let session = runtime.create_session()?;
    let task = runtime.create_task(storage_task(session.id, &fixture.workspace))?;
    let events = runtime.read_task_events(task.snapshot.task_id)?;
    let mut checkpoint_input = storage_checkpoint_input(&task, events);
    checkpoint_input.completed_work = vec![WorkEvidence {
        summary: "retain content-addressed evidence".to_owned(),
        event_sequences: vec![1],
        artifact_digests: vec![artifact_id.to_string()],
    }];
    checkpoint_input
        .artifact_contents
        .insert(artifact_id.to_string(), artifact.to_vec());
    let checkpoint = CanonicalCheckpoint::build(checkpoint_input)?;
    let engine = ContextEngine::new(ContextBudget {
        context_window: 20_000,
        trigger_percent: 80,
        target_percent: 60,
    })?;
    let package = engine.assemble(context_input(checkpoint.clone()))?;
    let checkpoint_digest = checkpoint.digest()?;
    let package_digest = package.digest()?;
    runtime
        .commit_checkpoint(
            NewCheckpoint {
                task_id: task.snapshot.task_id,
                checkpoint,
                checkpoint_digest,
                context_package: package,
                context_package_digest: package_digest,
                created_at: timestamp(1),
            },
            task.revision,
        )?
        .expect("checkpoint commit succeeds");
    drop(runtime);

    let reopened = RuntimeStore::open(DataRootLock::acquire(&fixture.root)?, timestamp(2))?;
    assert_eq!(
        reopened.artifacts().read_verified(&artifact_id)?.bytes(),
        artifact
    );
    let connection = rusqlite::Connection::open(&fixture.database)?;
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM artifact_objects WHERE id = ?1",
            [artifact_id.as_str()],
            |row| row.get::<_, u64>(0),
        )?,
        1
    );
    Ok(())
}
