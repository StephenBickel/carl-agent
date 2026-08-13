use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use carl::acp::PermissionMode;
use carl::events::{ApprovalId, SessionId, ToolCallId, TurnId};
use carl::policy::{ActorId, Frontend, Sha256Digest};
use carl::storage::{
    BoundApprovalBinding, ChannelId, ClientName, DeliveryKind, DeliveryStatus, ExternalSessionId,
    NewDelivery, NewFrontendSession, NewRemoteCode, ProviderRequestId, RemoteCodeClaim,
    RemoteCodeKind, Store, TrustedFrontendOwnerInput,
};
use chrono::{Duration, TimeZone, Utc};
use rusqlite::Connection;

static NEXT_LAYOUT: AtomicU64 = AtomicU64::new(0);

#[test]
fn list_frontend_sessions_is_bounded_ordered_and_isolated() -> Result<(), Box<dyn Error>> {
    let layout = TestLayout::new()?;
    let store = Store::open(&layout.database)?;
    for (external, frontend, offset) in [
        ("tui-old", Frontend::Tui, 0),
        ("acp-hidden", Frontend::Acp, 1),
        ("tui-new", Frontend::Tui, 2),
    ] {
        let session = store.create_session()?;
        store.bind_frontend_session(NewFrontendSession {
            frontend,
            external_session_id: ExternalSessionId::try_from(external)?,
            session_id: session.id,
            cwd: layout.workspace.clone(),
            protocol_version: 2,
            client_name: ClientName::try_from("carl-test")?,
            permission_mode: PermissionMode::FullAccess,
            channel_id: None,
            created_at: fixed_time() + Duration::seconds(offset),
        })?;
    }

    let sessions = store.list_frontend_sessions(Frontend::Tui, 2)?;
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|record| record.frontend == Frontend::Tui)
    );
    assert_eq!(sessions[0].external_session_id.as_str(), "tui-new");
    assert_eq!(sessions[1].external_session_id.as_str(), "tui-old");
    assert!(store.list_frontend_sessions(Frontend::Tui, 0).is_err());
    assert!(store.list_frontend_sessions(Frontend::Tui, 65).is_err());
    Ok(())
}

#[test]
fn migration_six_binds_and_recovers_frontend_sessions() -> Result<(), Box<dyn Error>> {
    let layout = TestLayout::new()?;
    let store = Store::open(&layout.database)?;
    let session = store.create_session()?;
    let created_at = fixed_time();
    let input = NewFrontendSession {
        frontend: Frontend::Buzz,
        external_session_id: ExternalSessionId::try_from("buzz-session-1")?,
        session_id: session.id,
        cwd: layout.workspace.clone(),
        protocol_version: 2,
        client_name: ClientName::try_from("buzz-acp")?,
        permission_mode: PermissionMode::Default,
        channel_id: Some(ChannelId::try_from("123e4567-e89b-12d3-a456-426614174000")?),
        created_at,
    };
    let bound = store.bind_frontend_session(input.clone())?;
    assert_eq!(bound.external_session_id.as_str(), "buzz-session-1");
    assert_eq!(bound.cwd, layout.workspace);
    assert_eq!(bound.permission_mode, PermissionMode::Default);
    assert_eq!(store.bind_frontend_session(input)?, bound);
    drop(store);

    let store = Store::open(&layout.database)?;
    assert_eq!(
        store.get_frontend_session("buzz-session-1")?,
        Some(bound.clone())
    );
    let connection = Connection::open(&layout.database)?;
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM migrations", [], |row| row
            .get::<_, u64>(0))?,
        13
    );
    for table in [
        "frontend_sessions",
        "remote_codes",
        "frontend_deliveries",
        "trusted_frontend_owners",
        "trusted_frontend_events",
        "task_control_receipts",
        "task_configuration_state",
        "task_control_markers",
        "service_task_receipts",
        "service_command_receipts",
        "service_configuration_controls",
    ] {
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get::<_, u64>(0),
            )?,
            1,
            "missing {table}"
        );
    }
    Ok(())
}

#[test]
fn migration_nine_preserves_legacy_wire_values_and_adds_canonical_profiles()
-> Result<(), Box<dyn Error>> {
    let layout = TestLayout::new()?;
    prepare_version_eight_database(&layout.database, &layout.workspace)?;

    let store = Store::open(&layout.database)?;
    let legacy = store
        .get_frontend_session("legacy-bypass")?
        .ok_or("legacy binding missing")?;
    assert_eq!(legacy.permission_mode, PermissionMode::FullAccess);
    let approval = store
        .get_frontend_session("legacy-default")?
        .ok_or("approval binding missing")?;
    assert_eq!(approval.permission_mode, PermissionMode::Default);

    let connection = Connection::open(&layout.database)?;
    assert_eq!(
        connection.query_row(
            "SELECT permission_mode FROM frontend_sessions WHERE external_session_id = 'legacy-bypass'",
            [],
            |row| row.get::<_, String>(0),
        )?,
        "bypassPermissions"
    );
    assert_eq!(
        connection.query_row(
            "SELECT permission_profile FROM frontend_sessions WHERE external_session_id = 'legacy-bypass'",
            [],
            |row| row.get::<_, String>(0),
        )?,
        "full_access"
    );
    assert_eq!(
        connection.query_row(
            "SELECT permission_profile FROM frontend_sessions WHERE external_session_id = 'legacy-default'",
            [],
            |row| row.get::<_, String>(0),
        )?,
        "approval"
    );
    Ok(())
}

#[test]
fn migration_ten_backfills_existing_epoch_interruptions_truthfully() -> Result<(), Box<dyn Error>> {
    let layout = TestLayout::new()?;
    prepare_version_eight_database(&layout.database, &layout.workspace)?;
    let connection = Connection::open(&layout.database)?;
    connection.execute_batch(include_str!(
        "../migrations/0009_trusted_frontend_owners.sql"
    ))?;
    let session_id =
        connection.query_row("SELECT id FROM sessions ORDER BY id LIMIT 1", [], |row| {
            row.get::<_, String>(0)
        })?;
    let task_id = "11111111-1111-4111-8111-111111111111";
    let epoch_id = "22222222-2222-4222-8222-222222222222";
    connection.execute(
        "INSERT INTO agent_tasks (
            id, session_id, status, contract_json, budget_json, snapshot_json,
            canonical_workspace, model, effort, permission_mode, revision,
            created_at, updated_at
         ) VALUES (?1, ?2, 'active', '{}', '{}', '{}', ?3,
                   'gpt-5.6-codex', 'ultra', 'default', 3, ?4, ?4)",
        rusqlite::params![
            task_id,
            session_id,
            layout.workspace.to_str(),
            fixed_time().to_rfc3339(),
        ],
    )?;
    connection.execute(
        "INSERT INTO task_epochs (
            id, task_id, objective, status, started_sequence,
            created_at, updated_at
         ) VALUES (?1, ?2, 'tighten permissions', 'active', 2, ?3, ?3)",
        rusqlite::params![epoch_id, task_id, fixed_time().to_rfc3339()],
    )?;
    connection.execute(
        "INSERT INTO task_epoch_interruptions (
            task_id, epoch_id, reason, event_sequence, interrupted_at
         ) VALUES (?1, ?2, 'permission_tightening', 3, ?3)",
        rusqlite::params![task_id, epoch_id, fixed_time().to_rfc3339()],
    )?;
    drop(connection);

    let connection = Connection::open(&layout.database)?;
    connection.execute_batch(include_str!("../migrations/0010_durable_task_controls.sql"))?;
    assert_eq!(
        connection.query_row(
            "SELECT status, finished_sequence, report_digest
             FROM task_epochs WHERE id = ?1",
            [epoch_id],
            |row| Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?
            )),
        )?,
        ("interrupted".to_owned(), 3, None),
    );
    Ok(())
}

#[test]
fn canonical_full_access_storage_and_trusted_owner_channel_fill_are_exact()
-> Result<(), Box<dyn Error>> {
    let layout = TestLayout::new()?;
    let store = Store::open(&layout.database)?;
    let session = store.create_session()?;
    let mut input = frontend_input(session.id, "canonical-full", &layout.workspace, None)?;
    input.permission_mode = PermissionMode::FullAccess;
    assert_eq!(
        store.bind_frontend_session(input)?.permission_mode,
        PermissionMode::FullAccess
    );
    let connection = Connection::open(&layout.database)?;
    assert_eq!(
        connection.query_row(
            "SELECT permission_mode || ':' || permission_profile FROM frontend_sessions WHERE external_session_id = 'canonical-full'",
            [],
            |row| row.get::<_, String>(0),
        )?,
        "bypassPermissions:full_access"
    );
    drop(connection);

    let actor = ActorId::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
    let trusted = store.trust_frontend_owner(TrustedFrontendOwnerInput {
        frontend: Frontend::Buzz,
        actor_id: actor.clone(),
        workspace: layout.workspace.clone(),
        permission_mode: PermissionMode::FullAccess,
        trusted_at: fixed_time(),
    })?;
    assert_eq!(trusted.channel_id, None);
    assert_eq!(trusted.permission_mode, PermissionMode::FullAccess);

    let channel = ChannelId::try_from("123e4567-e89b-12d3-a456-426614174000")?;
    let admitted = store.admit_trusted_frontend_owner(
        Frontend::Buzz,
        &actor,
        &channel,
        &layout.workspace,
        fixed_time() + Duration::seconds(1),
    )?;
    assert_eq!(admitted.channel_id.as_ref(), Some(&channel));
    store.admit_trusted_frontend_message(
        Frontend::Buzz,
        &actor,
        &channel,
        &layout.workspace,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        fixed_time() + Duration::seconds(1),
    )?;
    assert!(
        store
            .admit_trusted_frontend_message(
                Frontend::Buzz,
                &actor,
                &channel,
                &layout.workspace,
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                fixed_time() + Duration::seconds(2),
            )
            .is_err(),
        "signed event replay must be rejected"
    );
    assert!(
        store
            .admit_trusted_frontend_owner(
                Frontend::Buzz,
                &actor,
                &ChannelId::try_from("123e4567-e89b-12d3-a456-426614174001")?,
                &layout.workspace,
                fixed_time() + Duration::seconds(2),
            )
            .is_err()
    );
    assert!(
        store
            .admit_trusted_frontend_owner(
                Frontend::Buzz,
                &ActorId::parse(
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                )?,
                &channel,
                &layout.workspace,
                fixed_time() + Duration::seconds(2),
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn migration_six_database_upgrades_through_current_and_reopens() -> Result<(), Box<dyn Error>> {
    let layout = TestLayout::new()?;
    drop(Store::open(&layout.database)?);
    let connection = Connection::open(&layout.database)?;
    connection.execute_batch(
        "DROP TABLE task_control_markers;
         DROP TABLE task_configuration_state;
         DROP TABLE task_control_receipts;
         DROP TABLE service_configuration_controls;
         DROP TABLE service_command_receipts;
         DROP TABLE service_task_receipts;
         DROP TABLE trusted_frontend_events;
         DROP TABLE trusted_frontend_owners;
         DROP TABLE task_epoch_interruptions;
         ALTER TABLE frontend_sessions DROP COLUMN permission_profile;
         DROP TABLE task_steering;
         DROP TABLE task_context_packages;
         DROP TABLE task_checkpoints;
         DROP TABLE task_operations;
         DROP TABLE task_epochs;
         DROP TABLE agent_tasks;
         DROP TABLE frontend_deliveries;
         DROP TABLE remote_codes;
         DROP TABLE frontend_sessions;
         DELETE FROM migrations WHERE version >= 7;",
    )?;
    drop(connection);

    let store = Store::open(&layout.database)?;
    let session = store.create_session()?;
    let bound = store.bind_frontend_session(frontend_input(
        session.id,
        "upgraded-session",
        &layout.workspace,
        None,
    )?)?;
    drop(store);
    let store = Store::open(&layout.database)?;
    assert_eq!(store.get_frontend_session("upgraded-session")?, Some(bound));
    Ok(())
}

#[test]
fn frontend_bindings_reject_identity_and_workspace_rebinding() -> Result<(), Box<dyn Error>> {
    let layout = TestLayout::new()?;
    let store = Store::open(&layout.database)?;
    let first = store.create_session()?;
    let second = store.create_session()?;
    store.bind_frontend_session(frontend_input(
        first.id,
        "external-1",
        &layout.workspace,
        Some("123e4567-e89b-12d3-a456-426614174000"),
    )?)?;

    let changed_session = store.bind_frontend_session(frontend_input(
        second.id,
        "external-1",
        &layout.workspace,
        Some("123e4567-e89b-12d3-a456-426614174000"),
    )?);
    assert!(changed_session.is_err());
    let reused_channel = store.bind_frontend_session(frontend_input(
        second.id,
        "external-2",
        &layout.workspace,
        Some("123e4567-e89b-12d3-a456-426614174000"),
    )?);
    assert!(reused_channel.is_err());

    let relative = frontend_input(second.id, "external-3", Path::new("."), None)?;
    assert!(store.bind_frontend_session(relative).is_err());
    let noncanonical = frontend_input(
        second.id,
        "external-4",
        &noncanonical_workspace(&layout.workspace),
        None,
    )?;
    assert!(store.bind_frontend_session(noncanonical).is_err());
    Ok(())
}

#[cfg(not(windows))]
fn noncanonical_workspace(workspace: &Path) -> PathBuf {
    workspace.join("..").join("workspace")
}

#[cfg(windows)]
fn noncanonical_workspace(workspace: &Path) -> PathBuf {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let mut encoded = workspace
        .file_name()
        .expect("the canonical Windows workspace has a final component")
        .encode_wide()
        .collect::<Vec<_>>();
    let component = encoded
        .iter_mut()
        .find(|unit| (**unit as u8).is_ascii_alphabetic())
        .expect("the Windows workspace component contains an ASCII letter");
    *component = u16::from(if (*component as u8).is_ascii_uppercase() {
        (*component as u8).to_ascii_lowercase()
    } else {
        (*component as u8).to_ascii_uppercase()
    });
    let alias = workspace.with_file_name(OsString::from_wide(&encoded));
    assert_ne!(alias, workspace);
    assert_eq!(
        fs::canonicalize(&alias).expect("the noncanonical Windows alias still resolves"),
        workspace
    );
    alias
}

#[test]
fn remote_codes_are_digest_only_exact_single_use_and_expiring() -> Result<(), Box<dyn Error>> {
    let layout = TestLayout::new()?;
    let mut store = Store::open(&layout.database)?;
    let session = store.create_session()?;
    let other_session = store.create_session()?;
    store.bind_frontend_session(frontend_input(
        session.id,
        "external-1",
        &layout.workspace,
        None,
    )?)?;
    store.bind_frontend_session(frontend_input(
        other_session.id,
        "external-2",
        &layout.workspace,
        None,
    )?)?;

    let now = fixed_time();
    let approval_id = ApprovalId::new();
    let actor = ActorId::parse("buzz-owner")?;
    let request_digest = digest('a')?;
    store.create_bound_approval(
        approval_id,
        BoundApprovalBinding::new(
            session.id,
            TurnId::new(),
            ToolCallId::new(),
            actor.clone(),
            request_digest,
            now,
            now + Duration::minutes(10),
        )?,
        "Run cargo test",
    )?;

    let display_code = "7ac91f20bd";
    let provider_request_id = ProviderRequestId::try_from("provider-approval-7")?;
    let record = store.create_remote_code(NewRemoteCode {
        display_code,
        kind: RemoteCodeKind::Approval,
        external_session_id: ExternalSessionId::try_from("external-1")?,
        approval_id: Some(approval_id),
        provider_request_id: Some(provider_request_id.clone()),
        request_digest,
        actor_id: actor.clone(),
        created_at: now,
        expires_at: now + Duration::minutes(10),
    })?;
    assert_ne!(record.code_digest.to_string(), display_code);
    let connection = Connection::open(&layout.database)?;
    let stored = connection.query_row("SELECT code_digest FROM remote_codes", [], |row| {
        row.get::<_, String>(0)
    })?;
    assert_eq!(stored, record.code_digest.to_string());
    assert!(!stored.contains(display_code));
    drop(connection);

    let wrong_session = claim(
        display_code,
        "external-2",
        &actor,
        approval_id,
        &provider_request_id,
        request_digest,
        now + Duration::minutes(1),
    )?;
    assert!(store.consume_remote_code(wrong_session).is_err());
    assert!(
        store
            .get_remote_code(record.code_digest)?
            .unwrap()
            .consumed_at
            .is_none()
    );
    assert!(
        store
            .get_bound_approval(approval_id)?
            .unwrap()
            .consumed_at
            .is_none()
    );

    let consumed = store.consume_remote_code(claim(
        display_code,
        "external-1",
        &actor,
        approval_id,
        &provider_request_id,
        request_digest,
        now + Duration::minutes(1),
    )?)?;
    assert_eq!(consumed.code_digest, record.code_digest);
    assert!(consumed.consumed_at.is_some());
    assert!(
        store
            .get_bound_approval(approval_id)?
            .unwrap()
            .consumed_at
            .is_none()
    );
    assert!(
        store
            .consume_remote_code(claim(
                display_code,
                "external-1",
                &actor,
                approval_id,
                &provider_request_id,
                request_digest,
                now + Duration::minutes(2),
            )?)
            .is_err()
    );

    let expiring = store.create_remote_code(NewRemoteCode {
        display_code: "09ddecaf44",
        kind: RemoteCodeKind::BypassConfirmation,
        external_session_id: ExternalSessionId::try_from("external-1")?,
        approval_id: None,
        provider_request_id: None,
        request_digest: digest('b')?,
        actor_id: actor.clone(),
        created_at: now,
        expires_at: now + Duration::minutes(5),
    })?;
    assert!(
        store
            .consume_remote_code(RemoteCodeClaim {
                display_code: "09ddecaf44",
                kind: RemoteCodeKind::BypassConfirmation,
                external_session_id: ExternalSessionId::try_from("external-1")?,
                approval_id: None,
                provider_request_id: None,
                request_digest: digest('b')?,
                actor_id: actor,
                now: now + Duration::minutes(5),
            })
            .is_err()
    );
    assert!(
        store
            .get_remote_code(expiring.code_digest)?
            .unwrap()
            .consumed_at
            .is_none()
    );
    Ok(())
}

#[test]
fn delivery_state_is_closed_and_uncertain_is_terminal() -> Result<(), Box<dyn Error>> {
    let layout = TestLayout::new()?;
    let store = Store::open(&layout.database)?;
    let session = store.create_session()?;
    store.bind_frontend_session(frontend_input(
        session.id,
        "external-1",
        &layout.workspace,
        None,
    )?)?;
    let now = fixed_time();
    let action_digest = digest('d')?;
    let pending = store.create_delivery(NewDelivery {
        action_digest,
        external_session_id: ExternalSessionId::try_from("external-1")?,
        kind: DeliveryKind::Message,
        created_at: now,
    })?;
    assert_eq!(pending.status, DeliveryStatus::Pending);
    let uncertain = store.transition_delivery(
        action_digest,
        DeliveryStatus::Uncertain,
        now + Duration::seconds(1),
    )?;
    assert_eq!(uncertain.status, DeliveryStatus::Uncertain);
    assert!(
        store
            .transition_delivery(
                action_digest,
                DeliveryStatus::Delivered,
                now + Duration::seconds(2),
            )
            .is_err()
    );
    assert!(
        store
            .create_delivery(NewDelivery {
                action_digest,
                external_session_id: ExternalSessionId::try_from("external-1")?,
                kind: DeliveryKind::Message,
                created_at: now,
            })
            .is_err()
    );
    Ok(())
}

fn frontend_input(
    session_id: SessionId,
    external: &str,
    cwd: &Path,
    channel: Option<&str>,
) -> Result<NewFrontendSession, Box<dyn Error>> {
    Ok(NewFrontendSession {
        frontend: Frontend::Buzz,
        external_session_id: ExternalSessionId::try_from(external)?,
        session_id,
        cwd: cwd.to_path_buf(),
        protocol_version: 2,
        client_name: ClientName::try_from("buzz-acp")?,
        permission_mode: PermissionMode::Default,
        channel_id: channel.map(ChannelId::try_from).transpose()?,
        created_at: fixed_time(),
    })
}

fn claim(
    display_code: &'static str,
    external: &str,
    actor: &ActorId,
    approval_id: ApprovalId,
    provider_request_id: &ProviderRequestId,
    request_digest: Sha256Digest,
    now: chrono::DateTime<Utc>,
) -> Result<RemoteCodeClaim<'static>, Box<dyn Error>> {
    Ok(RemoteCodeClaim {
        display_code,
        kind: RemoteCodeKind::Approval,
        external_session_id: ExternalSessionId::try_from(external)?,
        approval_id: Some(approval_id),
        provider_request_id: Some(provider_request_id.clone()),
        request_digest,
        actor_id: actor.clone(),
        now,
    })
}

fn digest(character: char) -> Result<Sha256Digest, Box<dyn Error>> {
    Ok(Sha256Digest::parse(character.to_string().repeat(64))?)
}

fn fixed_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 10, 12, 0, 0).unwrap()
}

fn prepare_version_eight_database(database: &Path, workspace: &Path) -> Result<(), Box<dyn Error>> {
    use sha2::{Digest, Sha256};

    let mut connection = Connection::open(database)?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE migrations (
             version INTEGER PRIMARY KEY,
             name TEXT NOT NULL,
             applied_at TEXT NOT NULL,
             checksum TEXT NOT NULL
         );",
    )?;
    let migrations = [
        (
            1_i64,
            "initial schema",
            include_str!("../migrations/0001_init.sql"),
        ),
        (
            2,
            "bound approvals",
            include_str!("../migrations/0002_bound_approvals.sql"),
        ),
        (
            3,
            "subscription runs",
            include_str!("../migrations/0003_subscription_runs.sql"),
        ),
        (
            4,
            "proposal artifacts",
            include_str!("../migrations/0004_proposal_artifacts.sql"),
        ),
        (
            5,
            "verifications",
            include_str!("../migrations/0005_verifications.sql"),
        ),
        (
            6,
            "memory system",
            include_str!("../migrations/0006_memory_system.sql"),
        ),
        (
            7,
            "ACP frontends",
            include_str!("../migrations/0007_acp_frontends.sql"),
        ),
        (
            8,
            "long-horizon tasks",
            include_str!("../migrations/0008_long_horizon_tasks.sql"),
        ),
    ];
    let transaction = connection.transaction()?;
    for (version, name, sql) in migrations {
        transaction.execute_batch(sql)?;
        let normalized = sql.replace("\r\n", "\n");
        let checksum = format!("{:x}", Sha256::digest(normalized.as_bytes()));
        transaction.execute(
            "INSERT INTO migrations(version, name, applied_at, checksum) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![version, name, fixed_time().to_rfc3339(), checksum],
        )?;
    }
    for (session_id, external, mode) in [
        (SessionId::new(), "legacy-bypass", "bypassPermissions"),
        (SessionId::new(), "legacy-default", "default"),
    ] {
        transaction.execute(
            "INSERT INTO sessions(id, created_at, updated_at) VALUES (?1, ?2, ?2)",
            rusqlite::params![session_id.to_string(), fixed_time().to_rfc3339()],
        )?;
        transaction.execute(
            "INSERT INTO frontend_sessions(
                external_session_id, frontend, session_id, client_name, protocol_version,
                cwd, channel_id, provider_thread_id, permission_mode, created_at, updated_at
             ) VALUES (?1, 'buzz', ?2, 'fixture', 2, ?3, NULL, NULL, ?4, ?5, ?5)",
            rusqlite::params![
                external,
                session_id.to_string(),
                workspace.to_str(),
                mode,
                fixed_time().to_rfc3339(),
            ],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

struct TestLayout {
    root: PathBuf,
    database: PathBuf,
    workspace: PathBuf,
}

impl TestLayout {
    fn new() -> Result<Self, Box<dyn Error>> {
        let serial = NEXT_LAYOUT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::current_exe()?
            .parent()
            .ok_or("test executable has no parent")?
            .join(format!("carl-acp-storage-{}-{serial}", std::process::id()));
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace)?;
        let workspace = fs::canonicalize(workspace)?;
        Ok(Self {
            database: root.join("carl.sqlite3"),
            root,
            workspace,
        })
    }
}

impl Drop for TestLayout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
