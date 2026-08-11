use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::error::CarlError;
use carl::runtime::task::{
    CheckpointId, ClauseStatus, CompletionClause, CompletionContract, ContextPackageId,
    EffectClass, EpochId, OperationId, OperationStatus, TaskBudget, TaskEvent, TaskSnapshot,
    TaskStatus, reduce_task,
};
use carl::storage::{NewTask, Store};
use chrono::{DateTime, Utc};
use rusqlite::Connection;
use uuid::Uuid;

struct TemporaryTaskDatabase {
    root: PathBuf,
    database: PathBuf,
    workspace: PathBuf,
}

impl TemporaryTaskDatabase {
    fn new() -> Result<Self, Box<dyn Error>> {
        let root = std::env::temp_dir().join(format!("carl-task-storage-{}", Uuid::new_v4()));
        let database = root.join("carl.sqlite3");
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace)?;
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

fn timestamp(second: u32) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&format!("2026-08-10T12:00:{second:02}Z"))
        .unwrap()
        .with_timezone(&Utc)
}

fn contract() -> CompletionContract {
    CompletionContract {
        version: 1,
        goal: "Persist the long-running task".to_owned(),
        constraints: vec!["Keep the journal authoritative".to_owned()],
        clauses: vec![CompletionClause {
            id: "durable".to_owned(),
            description: "The task survives restart".to_owned(),
            required: false,
            status: ClauseStatus::Pending,
            evidence: Vec::new(),
        }],
    }
}

fn new_task(session_id: carl::events::SessionId, workspace: &Path) -> NewTask {
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

fn replay(events: &[carl::events::EventEnvelope]) -> Result<TaskSnapshot, Box<dyn Error>> {
    let mut snapshot = None;
    for event in events {
        snapshot = Some(reduce_task(snapshot, event)?);
    }
    Ok(snapshot.expect("task has a creation event"))
}

#[test]
fn task_projection_reopens_and_matches_journal_replay_for_every_transition()
-> Result<(), Box<dyn Error>> {
    let fixture = TemporaryTaskDatabase::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let created = store.create_task(new_task(session.id, &fixture.workspace))?;
    let task_id = created.snapshot.task_id;
    assert_eq!(created.revision, 1);

    let epoch_id = EpochId::new();
    let operation_id = OperationId::new();
    let transitions = [
        TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "execution started".to_owned(),
        },
        TaskEvent::EpochStarted {
            epoch_id,
            objective: "exercise durable projections".to_owned(),
        },
        TaskEvent::OperationIntentRecorded {
            operation_id,
            epoch_id,
            item_id: "tool-item-1".to_owned(),
            effect_class: EffectClass::IdempotentMutation,
            request_digest: "request-digest".to_owned(),
        },
        TaskEvent::OperationTransitioned {
            operation_id,
            from: OperationStatus::IntentRecorded,
            to: OperationStatus::Started,
            evidence_sequences: Vec::new(),
        },
        TaskEvent::OperationEvidenceRecorded {
            operation_id,
            result_digest: "operation-result".to_owned(),
        },
        TaskEvent::OperationTransitioned {
            operation_id,
            from: OperationStatus::Started,
            to: OperationStatus::Succeeded,
            evidence_sequences: vec![6],
        },
        TaskEvent::EpochFinished {
            epoch_id,
            report_digest: "epoch-report".to_owned(),
        },
    ];

    let mut revision = created.revision;
    for (index, event) in transitions.into_iter().enumerate() {
        let updated = store
            .append_task_event(task_id, revision, event, timestamp(index as u32 + 1))?
            .expect("revision matches");
        revision = updated.revision;
        drop(store);

        store = Store::open(&fixture.database)?;
        let projected = store.get_task(task_id)?.expect("task projection exists");
        let replayed = replay(&store.read_task_events(task_id)?)?;
        assert_eq!(projected.snapshot, replayed);
        assert_eq!(projected.revision, replayed.revision);
    }

    let reopened = store.get_task(task_id)?.expect("task survives restart");
    assert_eq!(reopened.snapshot.active_epoch, None);
    assert_eq!(
        reopened.snapshot.operation_status(operation_id),
        Some(OperationStatus::Succeeded)
    );
    Ok(())
}

#[test]
fn task_event_pages_are_bounded_stable_and_isolated() -> Result<(), Box<dyn Error>> {
    let fixture = TemporaryTaskDatabase::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let first = store.create_task(new_task(session.id, &fixture.workspace))?;
    let second = store.create_task(new_task(session.id, &fixture.workspace))?;
    let other_session = store.create_session()?;
    let other_session_task = store.create_task(new_task(other_session.id, &fixture.workspace))?;

    let mut revision = first.revision;
    for index in 0..513_u32 {
        revision = store
            .append_task_event(
                first.snapshot.task_id,
                revision,
                TaskEvent::ProgressAssessed {
                    fingerprint: format!("progress-{index}"),
                    stalled: false,
                },
                timestamp(1),
            )?
            .expect("revision matches")
            .revision;
    }

    let first_page = store.read_task_event_page(first.snapshot.task_id, None, 512)?;
    assert_eq!(first_page.len(), 512);
    let single_event = store.read_task_event_page(first.snapshot.task_id, None, 1)?;
    assert_eq!(single_event, first_page[..1]);
    assert!(
        first_page
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence)
    );
    assert!(first_page.iter().all(|envelope| {
        matches!(
            envelope.event,
            carl::events::Event::TaskLifecycle { task_id, .. }
                if task_id == first.snapshot.task_id
        )
    }));

    let final_page = store.read_task_event_page(
        first.snapshot.task_id,
        Some(first_page.last().unwrap().sequence),
        512,
    )?;
    assert_eq!(final_page.len(), 2);
    assert!(
        store
            .read_task_event_page(
                first.snapshot.task_id,
                Some(final_page.last().unwrap().sequence),
                1,
            )?
            .is_empty()
    );
    assert_eq!(store.read_task_events(second.snapshot.task_id)?.len(), 1);
    assert_eq!(
        store
            .read_task_events(other_session_task.snapshot.task_id)?
            .len(),
        1
    );

    for invalid in [0, 513] {
        let error = store
            .read_task_event_page(first.snapshot.task_id, None, invalid)
            .expect_err("invalid limits are rejected");
        assert!(matches!(error, CarlError::Validation { .. }));
    }
    Ok(())
}

#[test]
fn checkpoint_context_and_steering_projections_commit_with_their_events()
-> Result<(), Box<dyn Error>> {
    let fixture = TemporaryTaskDatabase::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let created = store.create_task(new_task(session.id, &fixture.workspace))?;
    let task_id = created.snapshot.task_id;
    let epoch_id = EpochId::new();
    let checkpoint_id = CheckpointId::new();
    let context_package_id = ContextPackageId::new();
    let events = [
        TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "execution started".to_owned(),
        },
        TaskEvent::ProviderContextBound {
            context_id: "provider-context".to_owned(),
        },
        TaskEvent::SteeringQueued {
            steering_sequence: 0,
            text_digest: "steering-digest".to_owned(),
        },
        TaskEvent::EpochStarted {
            epoch_id,
            objective: "reach a safe checkpoint".to_owned(),
        },
        TaskEvent::EpochFinished {
            epoch_id,
            report_digest: "epoch-report".to_owned(),
        },
        TaskEvent::CheckpointCommitted {
            checkpoint_id,
            digest: "checkpoint-digest".to_owned(),
        },
        TaskEvent::CompactionCompleted {
            generation: 0,
            checkpoint_id,
            context_package_id,
        },
        TaskEvent::ProviderContextLost {
            context_id: "provider-context".to_owned(),
            reason: "provider thread ended".to_owned(),
        },
    ];
    let mut revision = created.revision;
    for (index, event) in events.into_iter().enumerate() {
        revision = store
            .append_task_event(task_id, revision, event, timestamp(index as u32 + 1))?
            .expect("revision matches")
            .revision;
    }
    drop(store);

    let store = Store::open(&fixture.database)?;
    let record = store.get_task(task_id)?.expect("task projection exists");
    assert_eq!(record.snapshot.latest_checkpoint, Some(checkpoint_id));
    assert_eq!(record.snapshot.provider_context, None);
    assert_eq!(record.snapshot, replay(&store.read_task_events(task_id)?)?);
    assert_eq!(store.list_resumable_tasks()?.len(), 1);

    let connection = Connection::open(&fixture.database)?;
    for table in [
        "task_epochs",
        "task_checkpoints",
        "task_context_packages",
        "task_steering",
    ] {
        assert_eq!(
            connection.query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE task_id = ?1"),
                [task_id.to_string()],
                |row| row.get::<_, u64>(0),
            )?,
            1,
            "missing {table} projection"
        );
    }
    Ok(())
}

#[test]
fn revision_conflict_and_projection_write_failure_append_nothing() -> Result<(), Box<dyn Error>> {
    let fixture = TemporaryTaskDatabase::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let created = store.create_task(new_task(session.id, &fixture.workspace))?;
    let task_id = created.snapshot.task_id;

    assert!(
        store
            .append_task_event(
                task_id,
                99,
                TaskEvent::ProgressAssessed {
                    fingerprint: "wrong-revision".to_owned(),
                    stalled: false,
                },
                timestamp(1),
            )?
            .is_none()
    );
    assert_eq!(store.read_task_events(task_id)?.len(), 1);

    let connection = Connection::open(&fixture.database)?;
    connection.execute_batch(
        "CREATE TRIGGER abort_task_projection_update
         BEFORE UPDATE OF revision ON agent_tasks
         BEGIN
             SELECT RAISE(ABORT, 'injected projection failure');
         END;",
    )?;
    drop(connection);

    let error = store
        .append_task_event(
            task_id,
            1,
            TaskEvent::ProgressAssessed {
                fingerprint: "must-roll-back".to_owned(),
                stalled: false,
            },
            timestamp(2),
        )
        .expect_err("projection failure aborts the transaction");
    assert!(matches!(error, CarlError::Storage { .. }));
    assert_eq!(store.read_task_events(task_id)?.len(), 1);
    assert_eq!(store.get_task(task_id)?.unwrap().revision, 1);
    Ok(())
}

#[test]
fn startup_rejects_a_resumable_projection_that_disagrees_with_replay() -> Result<(), Box<dyn Error>>
{
    let fixture = TemporaryTaskDatabase::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let task = store.create_task(new_task(session.id, &fixture.workspace))?;
    drop(store);

    let connection = Connection::open(&fixture.database)?;
    connection.execute(
        "UPDATE agent_tasks SET status = 'active' WHERE id = ?1",
        [task.snapshot.task_id.to_string()],
    )?;
    drop(connection);

    let error = match Store::open(&fixture.database) {
        Ok(_) => panic!("projection mismatch is rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        CarlError::Storage { ref detail } if detail.contains("task projection")
    ));
    Ok(())
}

#[test]
fn startup_rejects_a_journal_task_hidden_by_a_terminal_projection_status()
-> Result<(), Box<dyn Error>> {
    let fixture = TemporaryTaskDatabase::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let task = store.create_task(new_task(session.id, &fixture.workspace))?;

    let connection = Connection::open(&fixture.database)?;
    connection.execute(
        "UPDATE agent_tasks SET status = 'completed' WHERE id = ?1",
        [task.snapshot.task_id.to_string()],
    )?;
    drop(connection);

    let list_error = store
        .list_resumable_tasks()
        .expect_err("terminal status must not hide a resumable journal task from listing");
    assert!(matches!(list_error, CarlError::Storage { .. }));
    drop(store);

    let error = match Store::open(&fixture.database) {
        Ok(_) => panic!("terminal status must not hide a resumable journal task"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        CarlError::Storage { ref detail }
            if detail.contains("task projection") && !detail.contains(&task.snapshot.task_id.to_string())
    ));
    Ok(())
}

#[test]
fn startup_rejects_a_journal_task_with_a_missing_projection() -> Result<(), Box<dyn Error>> {
    let fixture = TemporaryTaskDatabase::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let task = store.create_task(new_task(session.id, &fixture.workspace))?;

    let connection = Connection::open(&fixture.database)?;
    connection.execute(
        "DELETE FROM agent_tasks WHERE id = ?1",
        [task.snapshot.task_id.to_string()],
    )?;
    drop(connection);

    let list_error = store
        .list_resumable_tasks()
        .expect_err("missing projection must not hide an authoritative journal task");
    assert!(matches!(list_error, CarlError::Storage { .. }));
    drop(store);

    let error = match Store::open(&fixture.database) {
        Ok(_) => panic!("authoritative journal task must have a projection"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        CarlError::Storage { ref detail }
            if detail.contains("task projection") && !detail.contains(&task.snapshot.task_id.to_string())
    ));
    Ok(())
}

#[test]
fn startup_discovery_checks_tasks_beyond_the_first_candidate_page() -> Result<(), Box<dyn Error>> {
    let fixture = TemporaryTaskDatabase::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut task_ids = Vec::with_capacity(513);
    for _ in 0..513 {
        task_ids.push(
            store
                .create_task(new_task(session.id, &fixture.workspace))?
                .snapshot
                .task_id,
        );
    }
    drop(store);

    let last_candidate = task_ids.into_iter().max().expect("tasks were created");
    let connection = Connection::open(&fixture.database)?;
    connection.execute(
        "UPDATE agent_tasks SET status = 'completed' WHERE id = ?1",
        [last_candidate.to_string()],
    )?;
    drop(connection);

    let error = match Store::open(&fixture.database) {
        Ok(_) => panic!("startup must validate journal task candidate pages after the first"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        CarlError::Storage { ref detail }
            if detail.contains("task projection") && !detail.contains(&last_candidate.to_string())
    ));
    Ok(())
}
