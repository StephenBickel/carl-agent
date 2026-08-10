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
    RemoteCodeKind, Store,
};
use chrono::{Duration, TimeZone, Utc};
use rusqlite::Connection;

static NEXT_LAYOUT: AtomicU64 = AtomicU64::new(0);

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
        7
    );
    for table in ["frontend_sessions", "remote_codes", "frontend_deliveries"] {
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
fn migration_six_database_upgrades_to_seven_and_reopens() -> Result<(), Box<dyn Error>> {
    let layout = TestLayout::new()?;
    drop(Store::open(&layout.database)?);
    let connection = Connection::open(&layout.database)?;
    connection.execute_batch(
        "DROP TABLE frontend_deliveries;
         DROP TABLE remote_codes;
         DROP TABLE frontend_sessions;
         DELETE FROM migrations WHERE version = 7;",
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
        &layout.workspace.join("..").join("workspace"),
        None,
    )?;
    assert!(store.bind_frontend_session(noncanonical).is_err());
    Ok(())
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
