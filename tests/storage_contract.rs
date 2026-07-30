use carl::error::CarlError;
use carl::events::{ApprovalId, Event, EventId, SessionId, ToolCallId};
use carl::storage::{ApprovalStatus, MemoryState, Store};
use rusqlite::{Connection, params};
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
        "events".to_owned(),
        "memories".to_owned(),
        "messages".to_owned(),
        "migrations".to_owned(),
        "processed_telegram_updates".to_owned(),
        "sessions".to_owned(),
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
    assert_eq!(migrations, 2);
    let checksums = connection
        .prepare("SELECT checksum FROM migrations ORDER BY version")?
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(checksums.len(), 2);
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
    assert_eq!(migrations, 2);

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
         VALUES (3, 'future migration', '2026-07-13T12:00:00Z', ?1)",
        ["ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"],
    )?;
    drop(connection);

    let error = open_error(database.path());
    assert!(matches!(
        error,
        CarlError::Storage { ref detail }
            if detail.contains("unsupported database migration version 3")
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
            if detail.contains("unsupported event schema version 2")
    ));

    Ok(())
}

fn inject_future_event(path: &Path, session_id: SessionId) -> Result<(), Box<dyn Error>> {
    let connection = Connection::open(path)?;
    connection.execute(
        "INSERT INTO events (
            id, session_id, turn_id, sequence, timestamp, schema_version, event_json
         ) VALUES (?1, ?2, NULL, 1, ?3, 2, ?4)",
        params![
            EventId::new().to_string(),
            session_id.to_string(),
            "2026-07-13T12:00:00Z",
            r#"{"schema_version":2,"type":"user_input","text":"future"}"#,
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
