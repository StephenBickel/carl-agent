use carl::delegates::{DelegateSettings, DelegateSettingsLayers};
use carl::error::CarlError;
use carl::events::{ApprovalId, Event, EventId, SessionId, ToolCallId};
use carl::runtime::subscription::{RunConfigSnapshot, RunId};
use carl::storage::{ApprovalStatus, MemoryState, NewSubscriptionRun, Store};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, ErrorCode as SqliteErrorCode, params};
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

struct TemporaryDatabase {
    path: PathBuf,
}

impl TemporaryDatabase {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("carl-storage-{}.sqlite", Uuid::new_v4()));
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        for path in [
            self.path.clone(),
            PathBuf::from(format!("{}-wal", self.path.display())),
            PathBuf::from(format!("{}-shm", self.path.display())),
        ] {
            let _ = fs::remove_file(path);
        }
    }
}

#[test]
fn fresh_database_is_migrated_and_configured_for_durable_use() -> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    let store = Store::open(database.path())?;

    assert_eq!(store.journal_mode()?, "wal");
    assert!(store.foreign_keys_enabled()?);
    assert!(store.busy_timeout_millis()? >= 5_000);

    let connection = Connection::open(database.path())?;
    let tables = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    let required = BTreeSet::from([
        "approvals".to_owned(),
        "artifact_objects".to_owned(),
        "events".to_owned(),
        "frontend_deliveries".to_owned(),
        "frontend_sessions".to_owned(),
        "memories".to_owned(),
        "messages".to_owned(),
        "migrations".to_owned(),
        "processed_telegram_updates".to_owned(),
        "remote_codes".to_owned(),
        "sessions".to_owned(),
        "session_delegate_settings".to_owned(),
        "subscription_run_baseline_entries".to_owned(),
        "subscription_run_baseline_directories".to_owned(),
        "subscription_run_baselines".to_owned(),
        "subscription_run_events".to_owned(),
        "subscription_run_inspections".to_owned(),
        "subscription_run_proposals".to_owned(),
        "subscription_run_verification_argv".to_owned(),
        "subscription_run_verification_requests".to_owned(),
        "subscription_run_verification_results".to_owned(),
        "subscription_runs".to_owned(),
        "telegram_state".to_owned(),
        "usage_observations".to_owned(),
    ]);
    assert!(
        required.is_subset(&tables),
        "missing tables: {required:?} vs {tables:?}"
    );

    let migrations = connection.query_row("SELECT COUNT(*) FROM migrations", [], |row| {
        row.get::<_, u64>(0)
    })?;
    assert_eq!(migrations, 6);
    let checksums = connection
        .prepare("SELECT checksum FROM migrations ORDER BY version")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(checksums.len(), 6);
    assert_eq!(
        &checksums[..3],
        [
            "82b335d14e7368e3eef97384e97f74cfac926f21e24c78f495ef90134c41c582",
            "1dfd44f6bb2bc3f0f05f6263c6446eaa9e7974d96b86052d0d9bc74dc43c271d",
            "bb944b6783aae22313498e4ad388db36c48863182c3abae6e87ba4204bd8a691",
        ]
    );
    assert_eq!(
        checksums[3],
        "081dbc079c7cb22c3eb55771092ad6a924b0273f1c34f2328adaaec670f4014e"
    );
    assert_eq!(
        checksums[4],
        "b16563bec8020c47e4b8aa81fdf0ec28a1b6aa0841959c4a15455be1cca5f391"
    );
    assert_eq!(
        checksums[5],
        "67f18d5ed69b66f7fc0d40a578c59c0f61ea923ec172df919960ad4fe1f90158"
    );
    assert!(checksums.iter().all(|checksum| {
        checksum.len() == 64
            && checksum
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }));

    drop(connection);
    drop(store);
    let reopened = Store::open(database.path())?;
    assert_eq!(reopened.journal_mode()?, "wal");
    let connection = Connection::open(database.path())?;
    let migrations = connection.query_row("SELECT COUNT(*) FROM migrations", [], |row| {
        row.get::<_, u64>(0)
    })?;
    assert_eq!(migrations, 6);

    Ok(())
}

#[test]
fn verification_results_foreign_key_the_executable_attestation_to_the_request()
-> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    drop(Store::open(database.path())?);

    let connection = Connection::open(database.path())?;
    let attestation_bindings = connection.query_row(
        "SELECT COUNT(*)
         FROM pragma_foreign_key_list('subscription_run_verification_results')
         WHERE \"table\" = 'subscription_run_verification_requests'
           AND \"from\" = 'executable_attestation_digest'
           AND \"to\" = 'executable_attestation_digest'",
        [],
        |row| row.get::<_, u64>(0),
    )?;
    assert_eq!(
        attestation_bindings, 1,
        "a result must be unable to substitute an executable attestation \
         different from its request"
    );
    Ok(())
}

#[test]
fn store_open_rejects_a_database_that_cannot_enable_wal() {
    let error = open_error(":memory:");
    assert!(matches!(
        error,
        CarlError::Storage { ref detail }
            if detail.contains("journal mode") && detail.contains("memory")
    ));
}

#[test]
fn store_open_rejects_a_future_database_migration() -> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    drop(Store::open(database.path())?);

    let connection = Connection::open(database.path())?;
    ensure_checksum_column(&connection)?;
    connection.execute(
        "INSERT INTO migrations (version, name, applied_at, checksum)
         VALUES (7, 'future migration', '2026-07-13T12:00:00Z', ?1)",
        ["ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
    )?;
    drop(connection);

    let error = open_error(database.path());
    assert!(matches!(
        error,
        CarlError::Storage { ref detail }
            if detail.contains("unsupported database migration version 7")
    ));
    Ok(())
}

#[test]
fn store_open_rejects_a_tampered_migration_checksum() -> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    drop(Store::open(database.path())?);

    let connection = Connection::open(database.path())?;
    ensure_checksum_column(&connection)?;
    connection.execute(
        "UPDATE migrations SET checksum = ?1 WHERE version = 1",
        ["0000000000000000000000000000000000000000000000000000000000000000"],
    )?;
    drop(connection);

    let error = open_error(database.path());
    assert!(matches!(
        error,
        CarlError::Storage { ref detail }
            if detail.contains("migration 1 checksum mismatch")
    ));
    Ok(())
}

#[test]
fn pre_subscription_run_database_upgrades_without_rewriting_old_migrations()
-> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    let legacy_session_id = SessionId::new();
    let legacy_event_id = EventId::new();
    let connection = Connection::open(database.path())?;
    connection.execute_batch(include_str!("../migrations/0001_init.sql"))?;
    connection.execute_batch(include_str!("../migrations/0002_bound_approvals.sql"))?;
    connection.execute(
        "INSERT INTO migrations (version, name, applied_at, checksum)
         VALUES
            (1, 'initial schema', '2026-07-29T12:00:00Z', ?1),
            (2, 'bound approvals', '2026-07-29T12:00:01Z', ?2)",
        params![
            "e019c38bf699633416f7084691fa3686c3f3170725fe74afed751be50102201a",
            "157c7feae68f02ab41d598c777981560a123f6d95a26e9a6f13a5adae4e99c28",
        ],
    )?;
    connection.execute(
        "INSERT INTO sessions (id, created_at, updated_at)
         VALUES (?1, '2026-07-29T12:00:02Z', '2026-07-29T12:00:02Z')",
        [legacy_session_id.to_string()],
    )?;
    connection.execute(
        "INSERT INTO events (
            id, session_id, turn_id, sequence, timestamp, schema_version, event_json
         ) VALUES (?1, ?2, NULL, 1, '2026-07-29T12:00:03Z', 1, ?3)",
        params![
            legacy_event_id.to_string(),
            legacy_session_id.to_string(),
            r#"{"schema_version":1,"type":"user_input","text":"legacy event"}"#,
        ],
    )?;
    connection.execute(
        "UPDATE sessions SET next_sequence = 2 WHERE id = ?1",
        [legacy_session_id.to_string()],
    )?;
    drop(connection);

    let mut store = Store::open(database.path())?;
    let legacy_events = store.read_events(legacy_session_id)?;
    assert_eq!(legacy_events.len(), 1);
    assert_eq!(legacy_events[0].id, legacy_event_id);
    assert_eq!(
        legacy_events[0].event,
        Event::UserInput {
            text: "legacy event".to_owned()
        }
    );
    let resolved = DelegateSettingsLayers::default().resolve();
    let created_at = DateTime::parse_from_rfc3339("2026-07-29T12:00:04Z")?.with_timezone(&Utc);
    let run_id = RunId::new();
    store.create_subscription_run(NewSubscriptionRun::new(
        run_id,
        legacy_session_id,
        carl::events::TurnId::new(),
        DelegateSettings::default(),
        RunConfigSnapshot::from_resolved(&resolved),
        created_at,
    )?)?;
    assert_eq!(store.read_subscription_run_events(run_id)?.len(), 1);
    assert_eq!(store.read_events(legacy_session_id)?.len(), 2);
    drop(store);

    let connection = Connection::open(database.path())?;
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM migrations", [], |row| {
            row.get::<_, u64>(0)
        })?,
        6
    );
    let checksums = connection
        .prepare("SELECT checksum FROM migrations ORDER BY version")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(checksums.len(), 6);
    assert_eq!(
        &checksums[..3],
        [
            "e019c38bf699633416f7084691fa3686c3f3170725fe74afed751be50102201a",
            "157c7feae68f02ab41d598c777981560a123f6d95a26e9a6f13a5adae4e99c28",
            "bb944b6783aae22313498e4ad388db36c48863182c3abae6e87ba4204bd8a691",
        ],
        "legacy CRLF checksums remain accepted without rewriting the ledger"
    );
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM sessions WHERE id = ?1",
            [legacy_session_id.to_string()],
            |row| row.get::<_, u64>(0),
        )?,
        1
    );
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*)
             FROM sqlite_master
             WHERE type = 'table'
               AND name IN (
                    'artifact_objects',
                    'session_delegate_settings',
                    'subscription_run_baseline_directories',
                    'subscription_run_baseline_entries',
                    'subscription_run_baselines',
                    'subscription_runs',
                    'subscription_run_events',
                    'subscription_run_inspections',
                    'subscription_run_proposals',
                    'subscription_run_verification_argv',
                    'subscription_run_verification_requests',
                    'subscription_run_verification_results'
               )",
            [],
            |row| row.get::<_, u64>(0),
        )?,
        12
    );

    Ok(())
}

#[test]
fn pre_proposal_artifact_database_upgrades_through_migration_five_and_reopens()
-> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    let connection = Connection::open(database.path())?;
    connection.execute_batch(include_str!("../migrations/0001_init.sql"))?;
    connection.execute_batch(include_str!("../migrations/0002_bound_approvals.sql"))?;
    connection.execute_batch(include_str!("../migrations/0003_subscription_runs.sql"))?;
    connection.execute(
        "INSERT INTO migrations (version, name, applied_at, checksum)
         VALUES
            (1, 'initial schema', '2026-07-29T12:00:00Z', ?1),
            (2, 'bound approvals', '2026-07-29T12:00:01Z', ?2),
            (3, 'subscription runs', '2026-07-29T12:00:02Z', ?3)",
        params![
            "82b335d14e7368e3eef97384e97f74cfac926f21e24c78f495ef90134c41c582",
            "1dfd44f6bb2bc3f0f05f6263c6446eaa9e7974d96b86052d0d9bc74dc43c271d",
            "bb944b6783aae22313498e4ad388db36c48863182c3abae6e87ba4204bd8a691",
        ],
    )?;
    drop(connection);

    drop(Store::open(database.path())?);
    let connection = Connection::open(database.path())?;
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM migrations", [], |row| {
            row.get::<_, u64>(0)
        })?,
        6
    );
    let tables = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<BTreeSet<_>, _>>()?;
    let artifact_tables = BTreeSet::from([
        "artifact_objects".to_owned(),
        "subscription_run_baseline_entries".to_owned(),
        "subscription_run_baseline_directories".to_owned(),
        "subscription_run_baselines".to_owned(),
        "subscription_run_inspections".to_owned(),
        "subscription_run_proposals".to_owned(),
        "subscription_run_verification_argv".to_owned(),
        "subscription_run_verification_requests".to_owned(),
        "subscription_run_verification_results".to_owned(),
    ]);
    assert!(
        artifact_tables.is_subset(&tables),
        "missing migration-4/5 tables: {artifact_tables:?} vs {tables:?}"
    );
    drop(connection);

    drop(Store::open(database.path())?);
    let connection = Connection::open(database.path())?;
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM migrations", [], |row| {
            row.get::<_, u64>(0)
        })?,
        6
    );

    Ok(())
}

#[test]
fn pre_verification_database_applies_migration_five_and_reopens() -> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    let connection = Connection::open(database.path())?;
    connection.execute_batch(include_str!("../migrations/0001_init.sql"))?;
    connection.execute_batch(include_str!("../migrations/0002_bound_approvals.sql"))?;
    connection.execute_batch(include_str!("../migrations/0003_subscription_runs.sql"))?;
    connection.execute_batch(include_str!("../migrations/0004_proposal_artifacts.sql"))?;
    connection.execute(
        "INSERT INTO migrations (version, name, applied_at, checksum)
         VALUES
            (1, 'initial schema', '2026-07-29T12:00:00Z', ?1),
            (2, 'bound approvals', '2026-07-29T12:00:01Z', ?2),
            (3, 'subscription runs', '2026-07-29T12:00:02Z', ?3),
            (4, 'proposal artifacts', '2026-07-29T12:00:03Z', ?4)",
        params![
            "82b335d14e7368e3eef97384e97f74cfac926f21e24c78f495ef90134c41c582",
            "1dfd44f6bb2bc3f0f05f6263c6446eaa9e7974d96b86052d0d9bc74dc43c271d",
            "bb944b6783aae22313498e4ad388db36c48863182c3abae6e87ba4204bd8a691",
            "081dbc079c7cb22c3eb55771092ad6a924b0273f1c34f2328adaaec670f4014e",
        ],
    )?;
    drop(connection);

    drop(Store::open(database.path())?);
    let connection = Connection::open(database.path())?;
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM migrations", [], |row| {
            row.get::<_, u64>(0)
        })?,
        6
    );
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*)
             FROM sqlite_master
             WHERE type = 'table'
               AND name IN (
                    'subscription_run_baseline_directories',
                    'subscription_run_verification_argv',
                    'subscription_run_verification_requests',
                    'subscription_run_verification_results'
               )",
            [],
            |row| row.get::<_, u64>(0),
        )?,
        4
    );
    drop(connection);

    drop(Store::open(database.path())?);
    Ok(())
}

#[test]
fn subscription_run_schema_rejects_invalid_projection_values() -> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    let store = Store::open(database.path())?;
    let session = store.create_session()?;
    drop(store);

    let connection = Connection::open(database.path())?;
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    connection.execute(
        "INSERT INTO session_delegate_settings (
            session_id, provider, model, effort, updated_at
         ) VALUES (?1, 'codex', 'gpt-5.6', 'high', '2026-07-29T12:00:00Z')",
        [session.id.to_string()],
    )?;
    connection.execute(
        "INSERT INTO subscription_runs (
            id, session_id, turn_id, provider, state, revision,
            per_run_model, per_run_effort,
            resolved_model, resolved_effort, model_source, effort_source,
            provider_model_status, provider_model_value,
            provider_effort_status, provider_effort_value,
            failure_code, created_at, updated_at
         ) VALUES (
            'run-valid', ?1, 'turn-valid', 'codex', 'prepared', 1,
            'gpt-5.6', 'high',
            'gpt-5.6', 'high', 'per_run', 'per_run',
            'not_reported', NULL,
            'not_reported', NULL,
            NULL, '2026-07-29T12:00:01Z', '2026-07-29T12:00:01Z'
         )",
        [session.id.to_string()],
    )?;

    assert_constraint_violation(connection.execute(
        "UPDATE subscription_runs SET state = 'succeeded' WHERE id = 'run-valid'",
        [],
    ));
    assert_constraint_violation(connection.execute(
        "UPDATE subscription_runs
         SET provider_model_status = 'reported'
         WHERE id = 'run-valid'",
        [],
    ));
    assert_constraint_violation(connection.execute(
        "UPDATE subscription_runs
         SET state = 'failed'
         WHERE id = 'run-valid'",
        [],
    ));
    assert_constraint_violation(connection.execute(
        "UPDATE subscription_runs
         SET failure_code = 'delegate_start_failed'
         WHERE id = 'run-valid'",
        [],
    ));
    assert_constraint_violation(connection.execute(
        "UPDATE subscription_runs
         SET state = 'failed', failure_code = 'untyped_failure'
         WHERE id = 'run-valid'",
        [],
    ));
    assert_constraint_violation(connection.execute(
        "UPDATE subscription_runs
         SET model_source = 'provider_default'
         WHERE id = 'run-valid'",
        [],
    ));
    assert_constraint_violation(connection.execute(
        "UPDATE subscription_runs
         SET revision = 0
         WHERE id = 'run-valid'",
        [],
    ));
    assert_constraint_violation(connection.execute(
        "UPDATE session_delegate_settings
         SET effort = 'extreme'
         WHERE session_id = ?1 AND provider = 'codex'",
        [session.id.to_string()],
    ));

    Ok(())
}

#[test]
fn subscription_run_event_index_requires_ordered_unique_global_events() -> Result<(), Box<dyn Error>>
{
    let database = TemporaryDatabase::new();
    let store = Store::open(database.path())?;
    let session = store.create_session()?;
    drop(store);

    let connection = Connection::open(database.path())?;
    connection.execute_batch("PRAGMA foreign_keys = ON;")?;
    connection.execute(
        "INSERT INTO subscription_runs (
            id, session_id, turn_id, provider, state, revision,
            per_run_model, per_run_effort,
            resolved_model, resolved_effort, model_source, effort_source,
            provider_model_status, provider_model_value,
            provider_effort_status, provider_effort_value,
            failure_code, created_at, updated_at
         ) VALUES (
            'run-events', ?1, 'turn-events', 'codex', 'prepared', 1,
            NULL, NULL,
            NULL, NULL, 'provider_default', 'provider_default',
            'not_reported', NULL,
            'not_reported', NULL,
            NULL, '2026-07-29T12:00:00Z', '2026-07-29T12:00:00Z'
         )",
        [session.id.to_string()],
    )?;
    connection.execute(
        "INSERT INTO events (
            id, session_id, turn_id, sequence, timestamp, schema_version, event_json
         ) VALUES (
            'event-one', ?1, 'turn-events', 1, '2026-07-29T12:00:01Z', 1,
            '{\"schema_version\":1,\"type\":\"user_input\",\"text\":\"fixture\"}'
         )",
        [session.id.to_string()],
    )?;
    connection.execute(
        "INSERT INTO subscription_run_events (run_id, run_sequence, event_id)
         VALUES ('run-events', 1, 'event-one')",
        [],
    )?;

    assert_constraint_violation(connection.execute(
        "INSERT INTO subscription_run_events (run_id, run_sequence, event_id)
         VALUES ('run-events', 0, 'missing-event')",
        [],
    ));
    assert_constraint_violation(connection.execute(
        "INSERT INTO subscription_run_events (run_id, run_sequence, event_id)
         VALUES ('run-events', 2, 'event-one')",
        [],
    ));
    assert_constraint_violation(connection.execute(
        "INSERT INTO subscription_run_events (run_id, run_sequence, event_id)
         VALUES ('run-events', 2, 'missing-event')",
        [],
    ));

    Ok(())
}

#[test]
fn sessions_can_be_created_and_listed_newest_first() -> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    let store = Store::open(database.path())?;

    let first = store.create_session()?;
    let second = store.create_session()?;
    let sessions = store.list_sessions()?;

    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].id, second.id);
    assert_eq!(sessions[1].id, first.id);

    Ok(())
}

#[test]
fn appends_allocate_monotonic_per_session_sequences_and_read_in_order() -> Result<(), Box<dyn Error>>
{
    let database = TemporaryDatabase::new();
    let mut store = Store::open(database.path())?;
    let first_session = store.create_session()?;
    let second_session = store.create_session()?;

    let first = store.append(
        first_session.id,
        None,
        Event::UserInput { text: "one".into() },
    )?;
    let other = store.append(
        second_session.id,
        None,
        Event::UserInput {
            text: "other".into(),
        },
    )?;
    let second = store.append(
        first_session.id,
        None,
        Event::UserInput { text: "two".into() },
    )?;

    assert_eq!((first.sequence, second.sequence), (1, 2));
    assert_eq!(other.sequence, 1);
    assert_eq!(store.read_events(first_session.id)?, vec![first, second]);

    Ok(())
}

#[test]
fn sessions_and_events_survive_store_reopen() -> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let event = store.append(
        session.id,
        None,
        Event::UserInput {
            text: "persist me".into(),
        },
    )?;
    drop(store);

    let reopened = Store::open(database.path())?;
    assert_eq!(reopened.list_sessions()?[0].id, session.id);
    assert_eq!(reopened.read_events(session.id)?, vec![event]);
    Ok(())
}

#[test]
fn independent_store_connections_coordinate_event_sequences() -> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    let mut first_store = Store::open(database.path())?;
    let session = first_store.create_session()?;
    let mut second_store = Store::open(database.path())?;

    let first = first_store.append(session.id, None, Event::UserInput { text: "one".into() })?;
    let second = second_store.append(session.id, None, Event::UserInput { text: "two".into() })?;
    let third = first_store.append(
        session.id,
        None,
        Event::UserInput {
            text: "three".into(),
        },
    )?;

    assert_eq!([first.sequence, second.sequence, third.sequence], [1, 2, 3]);
    assert_eq!(
        second_store.read_events(session.id)?,
        vec![first, second, third]
    );
    Ok(())
}

#[test]
fn approvals_persist_pending_and_resolved_state() -> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    let store = Store::open(database.path())?;
    let session = store.create_session()?;
    let approval_id = ApprovalId::new();
    let tool_call_id = ToolCallId::new();

    let pending =
        store.create_approval(session.id, approval_id, tool_call_id, "Read project notes")?;
    assert_eq!(pending.status, ApprovalStatus::Pending);
    drop(store);

    let store = Store::open(database.path())?;
    assert_eq!(store.get_approval(approval_id)?, Some(pending));

    let allowed = store.resolve_approval(approval_id, ApprovalStatus::Allowed)?;
    assert_eq!(allowed.status, ApprovalStatus::Allowed);
    assert!(allowed.resolved_at.is_some());
    drop(store);

    let store = Store::open(database.path())?;
    assert_eq!(store.get_approval(approval_id)?, Some(allowed));

    Ok(())
}

#[test]
fn explicit_memories_are_retained_when_forgotten() -> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    let store = Store::open(database.path())?;

    let active = store.remember_explicit("The owner prefers terse output", "user request")?;
    assert_eq!(active.state, MemoryState::Active);
    drop(store);

    let store = Store::open(database.path())?;
    assert_eq!(store.list_active_memories()?, vec![active.clone()]);

    let forgotten = store.forget_memory(active.id)?;
    assert_eq!(forgotten.state, MemoryState::Forgotten);
    assert!(forgotten.forgotten_at.is_some());
    drop(store);

    let store = Store::open(database.path())?;
    assert!(store.list_active_memories()?.is_empty());
    assert_eq!(store.get_memory(active.id)?, Some(forgotten));

    Ok(())
}

#[test]
fn failed_event_insert_rolls_back_the_allocated_sequence() -> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let connection = Connection::open(database.path())?;
    connection.execute_batch(
        "CREATE TRIGGER reject_event_insert
         BEFORE INSERT ON events
         BEGIN
             SELECT RAISE(ABORT, 'injected append failure');
         END;",
    )?;

    let error = store
        .append(
            session.id,
            None,
            Event::UserInput {
                text: "rejected".into(),
            },
        )
        .unwrap_err();
    assert!(matches!(error, CarlError::Storage { .. }));
    connection.execute_batch("DROP TRIGGER reject_event_insert;")?;

    let accepted = store.append(
        session.id,
        None,
        Event::UserInput {
            text: "accepted".into(),
        },
    )?;
    assert_eq!(accepted.sequence, 1);
    assert_eq!(store.read_events(session.id)?, vec![accepted]);

    Ok(())
}

#[test]
fn reading_rejects_a_future_event_schema_as_a_typed_storage_error() -> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    let store = Store::open(database.path())?;
    let session = store.create_session()?;
    inject_future_event(database.path(), session.id)?;

    let error = store.read_events(session.id).unwrap_err();
    assert!(matches!(
        error,
        CarlError::Storage { ref detail }
            if detail.contains("unsupported event schema version 4")
    ));

    Ok(())
}

#[test]
fn reading_rejects_mismatched_outer_and_embedded_event_versions() -> Result<(), Box<dyn Error>> {
    let database = TemporaryDatabase::new();
    let store = Store::open(database.path())?;
    let session = store.create_session()?;
    let connection = Connection::open(database.path())?;
    connection.execute(
        "INSERT INTO events (
            id, session_id, turn_id, sequence, timestamp, schema_version, event_json
         ) VALUES (?1, ?2, NULL, 1, ?3, 2, ?4)",
        params![
            EventId::new().to_string(),
            session.id.to_string(),
            "2026-07-13T12:00:00Z",
            r#"{"schema_version":1,"type":"user_input","text":"legacy"}"#,
        ],
    )?;

    let error = store.read_events(session.id).unwrap_err();
    assert!(matches!(
        error,
        CarlError::Storage { ref detail }
            if detail.contains("schema versions do not match")
    ));
    Ok(())
}

fn inject_future_event(path: &Path, session_id: SessionId) -> Result<(), Box<dyn Error>> {
    let connection = Connection::open(path)?;
    connection.execute(
        "INSERT INTO events (
            id, session_id, turn_id, sequence, timestamp, schema_version, event_json
         ) VALUES (?1, ?2, NULL, 1, ?3, 4, ?4)",
        params![
            EventId::new().to_string(),
            session_id.to_string(),
            "2026-07-13T12:00:00Z",
            r#"{"schema_version":4,"type":"user_input","text":"future"}"#,
        ],
    )?;
    Ok(())
}

fn ensure_checksum_column(connection: &Connection) -> Result<(), Box<dyn Error>> {
    let columns = connection.query_row(
        "SELECT COUNT(*)
         FROM pragma_table_info('migrations')
         WHERE name = 'checksum'",
        [],
        |row| row.get::<_, u64>(0),
    )?;
    if columns == 0 {
        connection.execute_batch("ALTER TABLE migrations ADD COLUMN checksum TEXT;")?;
    }
    Ok(())
}

fn open_error(path: impl AsRef<Path>) -> CarlError {
    match Store::open(path) {
        Ok(_) => panic!("Store::open unexpectedly accepted an incompatible database"),
        Err(error) => error,
    }
}

fn assert_constraint_violation(result: rusqlite::Result<usize>) {
    let error = result.expect_err("invalid stored subscription-run value was accepted");
    assert!(
        matches!(
            error,
            rusqlite::Error::SqliteFailure(ref failure, _)
                if failure.code == SqliteErrorCode::ConstraintViolation
        ),
        "expected a SQLite constraint violation, got {error:?}"
    );
}
