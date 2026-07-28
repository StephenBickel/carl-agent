use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use carl::error::CarlError;
use carl::events::{ApprovalId, ToolCallId, TurnId};
use carl::policy::{ActorId, Sha256Digest};
use carl::storage::{ApprovalStatus, BoundApprovalBinding, Store};
use chrono::{TimeDelta, TimeZone, Utc};
use uuid::Uuid;

type TestResult = Result<(), Box<dyn Error>>;

const REQUEST_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct TemporaryDatabase {
    path: PathBuf,
}

impl TemporaryDatabase {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir()
                .join(format!("carl-bound-approval-{}.sqlite", Uuid::new_v4())),
        }
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
fn bound_approvals_persist_and_consume_once() -> TestResult {
    let database = TemporaryDatabase::new();
    let store = Store::open(database.path())?;
    let session = store.create_session()?;
    let approval_id = ApprovalId::new();
    let binding = binding(session.id, REQUEST_DIGEST, "local-owner")?;

    let pending =
        store.create_bound_approval(approval_id, binding.clone(), "Run Codex in stage")?;
    assert_eq!(pending.status, ApprovalStatus::Pending);
    assert!(pending.consumed_at.is_none());
    drop(store);

    let mut store = Store::open(database.path())?;
    assert_eq!(store.get_bound_approval(approval_id)?, Some(pending));
    let allowed = store.resolve_bound_approval(
        approval_id,
        ApprovalStatus::Allowed,
        binding.created_at() + TimeDelta::minutes(1),
    )?;
    assert_eq!(allowed.status, ApprovalStatus::Allowed);
    let consumed = store.consume_bound_approval(
        approval_id,
        &binding,
        binding.created_at() + TimeDelta::minutes(2),
    )?;
    assert_eq!(consumed.id, approval_id);
    assert_eq!(consumed.request_digest, binding.request_digest());

    let replay = store
        .consume_bound_approval(
            approval_id,
            &binding,
            binding.created_at() + TimeDelta::minutes(3),
        )
        .expect_err("an approval must be single-use");
    assert!(matches!(replay, CarlError::Policy { .. }));
    assert_eq!(
        store
            .get_bound_approval(approval_id)?
            .ok_or("approval disappeared")?
            .consumed_at,
        Some(binding.created_at() + TimeDelta::minutes(2))
    );
    Ok(())
}

#[test]
fn every_binding_field_is_revalidated_before_consumption() -> TestResult {
    let database = TemporaryDatabase::new();
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let original = binding(session.id, REQUEST_DIGEST, "local-owner")?;

    let variants = [
        BoundApprovalBinding::new(
            session.id,
            original.turn_id(),
            original.tool_call_id(),
            ActorId::parse("other-owner")?,
            original.request_digest(),
            original.created_at(),
            original.expires_at(),
        )?,
        BoundApprovalBinding::new(
            session.id,
            original.turn_id(),
            original.tool_call_id(),
            original.actor_id().clone(),
            Sha256Digest::parse(OTHER_DIGEST)?,
            original.created_at(),
            original.expires_at(),
        )?,
        BoundApprovalBinding::new(
            store.create_session()?.id,
            original.turn_id(),
            original.tool_call_id(),
            original.actor_id().clone(),
            original.request_digest(),
            original.created_at(),
            original.expires_at(),
        )?,
        BoundApprovalBinding::new(
            session.id,
            TurnId::new(),
            original.tool_call_id(),
            original.actor_id().clone(),
            original.request_digest(),
            original.created_at(),
            original.expires_at(),
        )?,
        BoundApprovalBinding::new(
            session.id,
            original.turn_id(),
            ToolCallId::new(),
            original.actor_id().clone(),
            original.request_digest(),
            original.created_at(),
            original.expires_at(),
        )?,
    ];

    for variant in variants {
        let approval_id = ApprovalId::new();
        store.create_bound_approval(approval_id, original.clone(), "Run Codex")?;
        store.resolve_bound_approval(
            approval_id,
            ApprovalStatus::Allowed,
            original.created_at() + TimeDelta::seconds(30),
        )?;
        let error = store
            .consume_bound_approval(
                approval_id,
                &variant,
                original.created_at() + TimeDelta::minutes(1),
            )
            .expect_err("changed binding must invalidate approval");
        assert!(matches!(error, CarlError::Policy { .. }));
        assert!(
            store
                .get_bound_approval(approval_id)?
                .ok_or("approval disappeared")?
                .consumed_at
                .is_none()
        );
    }
    Ok(())
}

#[test]
fn denied_and_expired_approvals_never_consume() -> TestResult {
    let database = TemporaryDatabase::new();
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let binding = binding(session.id, REQUEST_DIGEST, "local-owner")?;

    let denied_id = ApprovalId::new();
    store.create_bound_approval(denied_id, binding.clone(), "Run Codex")?;
    store.resolve_bound_approval(
        denied_id,
        ApprovalStatus::Denied,
        binding.created_at() + TimeDelta::minutes(1),
    )?;
    assert!(
        store
            .consume_bound_approval(
                denied_id,
                &binding,
                binding.created_at() + TimeDelta::minutes(2),
            )
            .is_err()
    );

    let expired_id = ApprovalId::new();
    store.create_bound_approval(expired_id, binding.clone(), "Run Codex")?;
    store.resolve_bound_approval(
        expired_id,
        ApprovalStatus::Allowed,
        binding.created_at() + TimeDelta::minutes(1),
    )?;
    assert!(
        store
            .consume_bound_approval(
                expired_id,
                &binding,
                binding.expires_at() + TimeDelta::nanoseconds(1),
            )
            .is_err()
    );
    assert_eq!(
        store
            .get_bound_approval(expired_id)?
            .ok_or("approval disappeared")?
            .status,
        ApprovalStatus::Expired
    );
    Ok(())
}

#[test]
fn approval_lifetimes_are_positive_and_tightly_bounded() -> TestResult {
    let created = fixed_time();
    let session = carl::events::SessionId::new();
    let turn = TurnId::new();
    let tool = ToolCallId::new();
    let actor = ActorId::parse("local-owner")?;
    let digest = Sha256Digest::parse(REQUEST_DIGEST)?;

    assert!(
        BoundApprovalBinding::new(session, turn, tool, actor.clone(), digest, created, created,)
            .is_err()
    );
    assert!(
        BoundApprovalBinding::new(
            session,
            turn,
            tool,
            actor,
            digest,
            created,
            created + TimeDelta::minutes(15) + TimeDelta::nanoseconds(1),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn approval_debug_output_redacts_actor_and_digest() -> TestResult {
    let binding = binding(
        carl::events::SessionId::new(),
        REQUEST_DIGEST,
        "private-owner-id",
    )?;
    let debug = format!("{binding:?}");
    assert!(!debug.contains("private-owner-id"));
    assert!(!debug.contains(REQUEST_DIGEST));
    Ok(())
}

fn binding(
    session_id: carl::events::SessionId,
    digest: &str,
    actor: &str,
) -> Result<BoundApprovalBinding, CarlError> {
    let created_at = fixed_time();
    BoundApprovalBinding::new(
        session_id,
        TurnId::from_uuid(
            Uuid::parse_str("22222222-2222-4222-8222-222222222222").expect("fixture UUID is valid"),
        ),
        ToolCallId::from_uuid(
            Uuid::parse_str("33333333-3333-4333-8333-333333333333").expect("fixture UUID is valid"),
        ),
        ActorId::parse(actor)?,
        Sha256Digest::parse(digest)?,
        created_at,
        created_at + TimeDelta::minutes(5),
    )
}

fn fixed_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0)
        .single()
        .expect("fixture timestamp is valid")
}
