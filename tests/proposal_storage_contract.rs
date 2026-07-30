use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use carl::artifacts::ArtifactStore;
use carl::delegates::{DelegateSettings, DelegateSettingsLayers};
use carl::events::{SessionId, TurnId};
use carl::runtime::subscription::{
    RunConfigSnapshot, RunId, RunState, RunTransition, RunTrustLabel,
};
use carl::security::SecretFilter;
use carl::sidecar::DataRootLock;
use carl::staging::{
    ExactReplacementProposal, ProposalLimits, ProposalOutcome, SanitizedStage,
    SanitizedStageBuilder, StageLimits,
};
use carl::storage::{NewSubscriptionRun, RuntimeStore, Store, SubscriptionRunInspectionOutcome};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const BEFORE: &[u8] = b"pub fn answer() -> u32 { 41 }\n";
const AFTER: &[u8] = b"pub fn answer() -> u32 { 42 }\n";

struct StorageLayout {
    root: PathBuf,
    source: PathBuf,
    stages: PathBuf,
    artifacts: PathBuf,
    database: PathBuf,
}

impl StorageLayout {
    fn new() -> TestResult<Self> {
        #[cfg(unix)]
        let temporary_root = PathBuf::from("/tmp");
        #[cfg(not(unix))]
        let temporary_root = std::env::temp_dir();
        let root = temporary_root.join(format!("carl-proposal-storage-{}", Uuid::new_v4()));
        let source = root.join("source");
        let stages = root.join("stages");
        let artifacts = root.join("artifacts");
        let database = root.join("carl.sqlite3");
        fs::create_dir_all(&source)?;
        fs::create_dir_all(&stages)?;
        fs::create_dir_all(&artifacts)?;
        make_owner_only(&root)?;
        make_owner_only(&source)?;
        make_owner_only(&stages)?;
        make_owner_only(&artifacts)?;
        Ok(Self {
            root,
            source,
            stages,
            artifacts,
            database,
        })
    }

    fn write_source(&self, relative: &str, contents: &[u8]) -> TestResult {
        let path = self.source.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, contents)?;
        Ok(())
    }

    fn prepare(&self, artifacts: &ArtifactStore) -> TestResult<SanitizedStage> {
        Ok(SanitizedStageBuilder::open(
            &self.source,
            &self.stages,
            StageLimits::new(32, 4_096, 64 * 1_024)?,
            SecretFilter,
        )?
        .prepare(artifacts)?)
    }
}

impl Drop for StorageLayout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn sealed_baseline_is_cas_bound_single_assignment_and_durable() -> TestResult {
    let layout = StorageLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let mut store = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(0))?;
    let stage = layout.prepare(store.artifacts())?;
    let run_id = create_run(&mut store, instant(1))?;

    assert!(
        store
            .record_subscription_run_baseline(
                run_id,
                RunState::Prepared,
                2,
                stage.sealed_baseline(),
                instant(2),
            )?
            .is_none(),
        "a stale revision must lose without writing artifact references"
    );
    assert!(store.get_subscription_run_baseline(run_id)?.is_none());

    let persisted = store
        .record_subscription_run_baseline(
            run_id,
            RunState::Prepared,
            1,
            stage.sealed_baseline(),
            instant(3),
        )?
        .expect("the current state and revision must win");
    assert_eq!(
        &persisted.manifest_artifact_id,
        stage.sealed_baseline().manifest_artifact_id()
    );
    assert_eq!(
        persisted.manifest_digest,
        stage.baseline_manifest().digest()
    );
    assert_eq!(persisted.entry_count, 1);
    assert_eq!(persisted.total_bytes, BEFORE.len() as u64);
    assert_eq!(persisted.entries.len(), 1);
    assert_eq!(persisted.entries[0].ordinal, 0);
    assert_eq!(persisted.entries[0].path, "src/lib.rs");
    assert_eq!(persisted.entries[0].byte_length, BEFORE.len() as u64);
    assert_eq!(
        persisted.entries[0].content_artifact_id.as_str(),
        persisted.entries[0].content_digest.to_string()
    );

    assert!(
        store
            .record_subscription_run_baseline(
                run_id,
                RunState::Prepared,
                1,
                stage.sealed_baseline(),
                instant(4),
            )
            .is_err(),
        "a baseline is immutable once assigned"
    );
    let run = store
        .get_subscription_run(run_id)?
        .expect("run projection remains available");
    assert_eq!(run.state, RunState::Prepared);
    assert_eq!(run.revision, 1);
    assert_eq!(store.read_subscription_run_events(run_id)?.len(), 1);

    drop(stage);
    drop(store);
    let reopened = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(5))?;
    assert_eq!(
        reopened
            .get_subscription_run_baseline(run_id)?
            .expect("baseline metadata survives stage cleanup and restart"),
        persisted
    );
    Ok(())
}

#[test]
fn baseline_load_rejects_tampered_source_identity_evidence() -> TestResult {
    let layout = StorageLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let run_id = {
        let mut store = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(0))?;
        let stage = layout.prepare(store.artifacts())?;
        let run_id = create_run(&mut store, instant(1))?;
        store
            .record_subscription_run_baseline(
                run_id,
                RunState::Prepared,
                1,
                stage.sealed_baseline(),
                instant(2),
            )?
            .expect("baseline CAS succeeds");
        run_id
    };

    let connection = Connection::open(&layout.database)?;
    connection.execute(
        "UPDATE subscription_run_baseline_entries
         SET identity_a = identity_a || '9'
         WHERE run_id = ?1 AND ordinal = 0",
        [run_id.to_string()],
    )?;
    drop(connection);

    let reopened = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(3))?;
    assert!(
        reopened.get_subscription_run_baseline(run_id).is_err(),
        "source identity fields must be bound by sealed content-addressed evidence"
    );
    Ok(())
}

#[test]
fn exact_proposal_and_payload_references_survive_stage_cleanup_and_restart() -> TestResult {
    let layout = StorageLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let mut store = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(0))?;
    let stage = layout.prepare(store.artifacts())?;
    let run_id = create_run(&mut store, instant(1))?;
    store
        .record_subscription_run_baseline(
            run_id,
            RunState::Prepared,
            1,
            stage.sealed_baseline(),
            instant(2),
        )?
        .expect("baseline CAS succeeds");
    let revision = advance_to_inspecting(&mut store, run_id, 1)?;

    fs::write(stage.path().join("src/lib.rs"), AFTER)?;
    let proposal = exact_proposal(&stage, store.artifacts())?;
    assert!(
        store
            .record_subscription_run_exact_proposal(
                run_id,
                RunState::Inspecting,
                revision + 1,
                &proposal,
                instant(6),
            )?
            .is_none(),
        "a stale inspection revision must not persist a proposal"
    );

    let persisted = store
        .record_subscription_run_exact_proposal(
            run_id,
            RunState::Inspecting,
            revision,
            &proposal,
            instant(7),
        )?
        .expect("the current inspection CAS succeeds");
    assert_eq!(&persisted.proposal_artifact_id, proposal.artifact_id());
    assert_eq!(
        &persisted.payload_artifact_id,
        proposal.payload_artifact_id()
    );
    assert_eq!(
        persisted.baseline_manifest_artifact_id.as_str(),
        proposal.baseline_manifest_digest().to_string()
    );
    assert_eq!(
        persisted.candidate_manifest_digest,
        proposal.candidate_manifest_digest()
    );
    assert_eq!(persisted.path, proposal.path());
    assert_eq!(persisted.expected_live_hash, proposal.expected_live_hash());
    assert_eq!(persisted.before_hash, proposal.before_hash());
    assert_eq!(persisted.after_hash, proposal.after_hash());
    assert_eq!(persisted.payload_hash, proposal.payload_hash());
    assert_eq!(persisted.payload_bytes, AFTER.len() as u64);

    assert!(
        store
            .record_subscription_run_exact_proposal(
                run_id,
                RunState::Inspecting,
                revision,
                &proposal,
                instant(8),
            )
            .is_err(),
        "an inspection result is immutable once assigned"
    );
    let run = store
        .get_subscription_run(run_id)?
        .expect("run projection remains available");
    assert_eq!(run.state, RunState::Inspecting);
    assert_eq!(run.revision, revision);
    assert_eq!(
        store.read_subscription_run_events(run_id)?.len() as u64,
        revision
    );

    let stage_path = stage.path().to_path_buf();
    drop(stage);
    assert!(!stage_path.exists());
    drop(store);

    let reopened = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(9))?;
    assert_eq!(
        reopened
            .get_subscription_run_proposal(run_id)?
            .expect("proposal metadata survives restart"),
        persisted
    );
    let inspection = reopened
        .get_subscription_run_inspection(run_id)?
        .expect("inspection outcome survives restart");
    assert_eq!(
        inspection.outcome,
        SubscriptionRunInspectionOutcome::ExactReplacement
    );
    assert_eq!(
        inspection.stage_manifest_digest,
        proposal.candidate_manifest_digest()
    );
    assert!(
        !reopened
            .artifacts()
            .read_verified(&persisted.proposal_artifact_id)?
            .bytes()
            .is_empty(),
        "the persisted proposal reference resolves to a verified envelope"
    );
    assert_eq!(
        reopened
            .artifacts()
            .read_verified(&persisted.payload_artifact_id)?
            .bytes(),
        AFTER
    );
    Ok(())
}

#[test]
fn proposal_load_rejects_tampered_candidate_digest_and_orphaned_rows() -> TestResult {
    let layout = StorageLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let (run_id, candidate_manifest_digest, payload_artifact_id, payload_bytes) = {
        let mut store = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(0))?;
        let stage = layout.prepare(store.artifacts())?;
        let run_id = create_run(&mut store, instant(1))?;
        store
            .record_subscription_run_baseline(
                run_id,
                RunState::Prepared,
                1,
                stage.sealed_baseline(),
                instant(2),
            )?
            .expect("baseline CAS succeeds");
        let revision = advance_to_inspecting(&mut store, run_id, 1)?;
        fs::write(stage.path().join("src/lib.rs"), AFTER)?;
        let proposal = exact_proposal(&stage, store.artifacts())?;
        let persisted = store
            .record_subscription_run_exact_proposal(
                run_id,
                RunState::Inspecting,
                revision,
                &proposal,
                instant(7),
            )?
            .expect("proposal CAS succeeds");
        (
            run_id,
            persisted.candidate_manifest_digest.to_string(),
            persisted.payload_artifact_id.as_str().to_owned(),
            persisted.payload_bytes,
        )
    };

    let connection = Connection::open(&layout.database)?;
    connection.execute(
        "UPDATE subscription_run_inspections
         SET stage_manifest_digest = ?2
         WHERE run_id = ?1",
        params![run_id.to_string(), "f".repeat(64)],
    )?;
    drop(connection);
    let reopened = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(8))?;
    assert!(
        reopened.get_subscription_run_proposal(run_id).is_err(),
        "the candidate digest must be recomputed instead of trusted from SQLite"
    );
    drop(reopened);

    let connection = Connection::open(&layout.database)?;
    connection.execute(
        "UPDATE subscription_run_inspections
         SET stage_manifest_digest = ?2
         WHERE run_id = ?1",
        params![run_id.to_string(), candidate_manifest_digest],
    )?;
    connection.pragma_update(None, "foreign_keys", "OFF")?;
    assert_eq!(
        connection.execute(
            "DELETE FROM artifact_objects WHERE id = ?1",
            [&payload_artifact_id],
        )?,
        1
    );
    drop(connection);

    let reopened = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(9))?;
    assert!(
        reopened.get_subscription_run_proposal(run_id).is_err(),
        "a proposal whose registered payload object was deleted must be reported as corruption"
    );
    drop(reopened);

    let connection = Connection::open(&layout.database)?;
    connection.pragma_update(None, "foreign_keys", "OFF")?;
    connection.execute(
        "INSERT INTO artifact_objects (id, byte_length, created_at)
         VALUES (?1, ?2, ?3)",
        params![payload_artifact_id, payload_bytes, instant(7).to_rfc3339()],
    )?;
    assert_eq!(
        connection.execute(
            "DELETE FROM subscription_run_inspections WHERE run_id = ?1",
            [run_id.to_string()],
        )?,
        1
    );
    drop(connection);

    let reopened = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(10))?;
    assert!(
        reopened.get_subscription_run_inspection(run_id).is_err(),
        "an orphaned proposal row must be reported as corruption"
    );
    Ok(())
}

#[test]
fn no_changes_is_durable_and_excludes_a_later_proposal() -> TestResult {
    let layout = StorageLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let mut store = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(0))?;
    let stage = layout.prepare(store.artifacts())?;
    let run_id = create_run(&mut store, instant(1))?;
    store
        .record_subscription_run_baseline(
            run_id,
            RunState::Prepared,
            1,
            stage.sealed_baseline(),
            instant(2),
        )?
        .expect("baseline CAS succeeds");
    let revision = advance_to_inspecting(&mut store, run_id, 1)?;
    assert!(matches!(
        stage.inspect_proposal(store.artifacts(), ProposalLimits::new(4_096)?, SecretFilter)?,
        ProposalOutcome::NoChanges
    ));

    let persisted = store
        .record_subscription_run_no_changes(
            run_id,
            RunState::Inspecting,
            revision,
            &stage,
            ProposalLimits::new(4_096)?,
            SecretFilter,
            instant(6),
        )?
        .expect("no-change inspection CAS succeeds");
    assert_eq!(
        persisted.outcome,
        SubscriptionRunInspectionOutcome::NoChanges
    );
    assert_eq!(
        persisted.stage_manifest_digest,
        stage.baseline_manifest().digest()
    );
    assert!(
        store.get_subscription_run_proposal(run_id)?.is_none(),
        "no-change inspection cannot fabricate a proposal"
    );
    assert!(
        store
            .record_subscription_run_no_changes(
                run_id,
                RunState::Inspecting,
                revision,
                &stage,
                ProposalLimits::new(4_096)?,
                SecretFilter,
                instant(7),
            )
            .is_err(),
        "an inspection outcome is single-assignment"
    );
    Ok(())
}

#[test]
fn no_change_load_rejects_a_digest_that_disagrees_with_the_baseline() -> TestResult {
    let layout = StorageLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let run_id = {
        let mut store = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(0))?;
        let stage = layout.prepare(store.artifacts())?;
        let run_id = create_run(&mut store, instant(1))?;
        store
            .record_subscription_run_baseline(
                run_id,
                RunState::Prepared,
                1,
                stage.sealed_baseline(),
                instant(2),
            )?
            .expect("baseline CAS succeeds");
        let revision = advance_to_inspecting(&mut store, run_id, 1)?;
        store
            .record_subscription_run_no_changes(
                run_id,
                RunState::Inspecting,
                revision,
                &stage,
                ProposalLimits::new(4_096)?,
                SecretFilter,
                instant(6),
            )?
            .expect("no-change inspection CAS succeeds");
        run_id
    };

    let connection = Connection::open(&layout.database)?;
    connection.execute(
        "UPDATE subscription_run_inspections
         SET stage_manifest_digest = ?2
         WHERE run_id = ?1",
        params![run_id.to_string(), "f".repeat(64)],
    )?;
    drop(connection);

    let reopened = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(7))?;
    assert!(
        reopened.get_subscription_run_inspection(run_id).is_err(),
        "a no-change digest must be proven equal to the verified sealed baseline"
    );
    Ok(())
}

#[test]
fn injected_database_failures_roll_back_every_artifact_reference() -> TestResult {
    let layout = StorageLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let mut store = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(0))?;
    let stage = layout.prepare(store.artifacts())?;
    let run_id = create_run(&mut store, instant(1))?;
    let connection = Connection::open(&layout.database)?;
    connection.execute_batch(
        "CREATE TRIGGER reject_baseline_entry
         BEFORE INSERT ON subscription_run_baseline_entries
         BEGIN SELECT RAISE(ABORT, 'injected baseline failure'); END;",
    )?;
    assert!(
        store
            .record_subscription_run_baseline(
                run_id,
                RunState::Prepared,
                1,
                stage.sealed_baseline(),
                instant(2),
            )
            .is_err(),
        "injected baseline failure must surface"
    );
    assert_eq!(table_count(&connection, "artifact_objects")?, 0);
    assert_eq!(table_count(&connection, "subscription_run_baselines")?, 0);
    assert_eq!(
        table_count(&connection, "subscription_run_baseline_entries")?,
        0
    );
    connection.execute_batch("DROP TRIGGER reject_baseline_entry;")?;

    store
        .record_subscription_run_baseline(
            run_id,
            RunState::Prepared,
            1,
            stage.sealed_baseline(),
            instant(3),
        )?
        .expect("baseline succeeds after removing injected fault");
    let baseline_object_count = table_count(&connection, "artifact_objects")?;
    assert_eq!(baseline_object_count, 3);
    let revision = advance_to_inspecting(&mut store, run_id, 1)?;
    fs::write(stage.path().join("src/lib.rs"), AFTER)?;
    let proposal = exact_proposal(&stage, store.artifacts())?;

    connection.execute_batch(
        "CREATE TRIGGER reject_proposal
         BEFORE INSERT ON subscription_run_proposals
         BEGIN SELECT RAISE(ABORT, 'injected proposal failure'); END;",
    )?;
    assert!(
        store
            .record_subscription_run_exact_proposal(
                run_id,
                RunState::Inspecting,
                revision,
                &proposal,
                instant(7),
            )
            .is_err(),
        "injected proposal failure must surface"
    );
    assert_eq!(
        table_count(&connection, "artifact_objects")?,
        baseline_object_count,
        "proposal and payload object rows roll back with their references"
    );
    assert_eq!(table_count(&connection, "subscription_run_inspections")?, 0);
    assert_eq!(table_count(&connection, "subscription_run_proposals")?, 0);
    Ok(())
}

#[test]
fn runtime_store_owns_and_reopens_the_private_artifact_store() -> TestResult {
    let layout = StorageLayout::new()?;
    fs::remove_dir_all(&layout.artifacts)?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let artifact_id = {
        let mut runtime = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(1))?;
        let stage = layout.prepare(runtime.artifacts())?;
        let run_id = create_run(&mut runtime, instant(2))?;
        runtime
            .record_subscription_run_baseline(
                run_id,
                RunState::Prepared,
                1,
                stage.sealed_baseline(),
                instant(3),
            )?
            .expect("the baseline becomes the artifact's durable root");
        assert!(layout.root.join("artifacts").is_dir());
        stage.sealed_baseline().manifest_artifact_id().clone()
    };

    let reopened = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(4))?;
    assert!(
        !reopened
            .artifacts()
            .read_verified(&artifact_id)?
            .bytes()
            .is_empty()
    );
    Ok(())
}

#[test]
fn runtime_startup_removes_unreferenced_canonical_artifacts() -> TestResult {
    let layout = StorageLayout::new()?;
    fs::remove_dir_all(&layout.artifacts)?;
    let (orphan_id, orphan_bytes) = {
        let runtime = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(1))?;
        let artifact = runtime.artifacts().put(b"abandoned pending artifact")?;
        (artifact.id().clone(), artifact.bytes().len() as u64)
    };
    let connection = Connection::open(&layout.database)?;
    connection.execute(
        "INSERT INTO artifact_objects (id, byte_length, created_at)
         VALUES (?1, ?2, ?3)",
        params![orphan_id.as_str(), orphan_bytes, instant(1).to_rfc3339()],
    )?;
    drop(connection);
    let orphan_path = layout
        .root
        .join("artifacts")
        .join("objects")
        .join("sha256")
        .join(orphan_id.as_str());
    assert!(orphan_path.is_file());

    let reopened = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(2))?;
    assert!(
        reopened.artifacts().read_verified(&orphan_id).is_err(),
        "startup GC must not retain an artifact with no durable root"
    );
    assert!(!orphan_path.exists());
    assert_eq!(
        table_count(&Connection::open(&layout.database)?, "artifact_objects")?,
        0,
        "startup GC must also prune an orphaned object registry row"
    );
    Ok(())
}

#[test]
fn runtime_store_rejects_artifacts_sealed_by_a_different_store_without_writing_rows() -> TestResult
{
    let layout = StorageLayout::new()?;
    layout.write_source("src/lib.rs", BEFORE)?;
    let foreign_root = layout.root.join("foreign-artifacts");
    fs::create_dir(&foreign_root)?;
    make_owner_only(&foreign_root)?;
    let foreign_artifacts = ArtifactStore::open(&foreign_root)?;
    let stage = layout.prepare(&foreign_artifacts)?;
    let mut runtime = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(1))?;
    let run_id = create_run(&mut runtime, instant(2))?;

    assert!(
        runtime
            .record_subscription_run_baseline(
                run_id,
                RunState::Prepared,
                1,
                stage.sealed_baseline(),
                instant(3),
            )
            .is_err(),
        "artifact IDs from another store must not become durable references"
    );
    let connection = Connection::open(&layout.database)?;
    assert_eq!(table_count(&connection, "artifact_objects")?, 0);
    assert_eq!(table_count(&connection, "subscription_run_baselines")?, 0);
    assert_eq!(
        table_count(&connection, "subscription_run_baseline_entries")?,
        0
    );

    let trusted_stage = layout.prepare(runtime.artifacts())?;
    runtime
        .record_subscription_run_baseline(
            run_id,
            RunState::Prepared,
            1,
            trusted_stage.sealed_baseline(),
            instant(4),
        )?
        .expect("runtime-owned baseline succeeds");
    let baseline_object_count = table_count(&connection, "artifact_objects")?;
    let revision = advance_to_inspecting(&mut runtime, run_id, 1)?;
    fs::write(stage.path().join("src/lib.rs"), AFTER)?;
    let foreign_proposal = exact_proposal(&stage, &foreign_artifacts)?;
    assert!(
        runtime
            .record_subscription_run_exact_proposal(
                run_id,
                RunState::Inspecting,
                revision,
                &foreign_proposal,
                instant(8),
            )
            .is_err(),
        "proposal objects from another store must not become durable references"
    );
    assert_eq!(
        table_count(&connection, "artifact_objects")?,
        baseline_object_count,
        "a rejected foreign proposal must not register either object"
    );
    assert_eq!(table_count(&connection, "subscription_run_inspections")?, 0);
    assert_eq!(table_count(&connection, "subscription_run_proposals")?, 0);
    Ok(())
}

fn create_run(store: &mut Store, created_at: DateTime<Utc>) -> TestResult<RunId> {
    let session = store.create_session()?;
    create_run_for_session(store, session.id, created_at)
}

fn create_run_for_session(
    store: &mut Store,
    session_id: SessionId,
    created_at: DateTime<Utc>,
) -> TestResult<RunId> {
    let run_id = RunId::new();
    let resolved = DelegateSettingsLayers::default().resolve();
    store.create_subscription_run(NewSubscriptionRun::new(
        run_id,
        session_id,
        TurnId::new(),
        DelegateSettings::default(),
        RunConfigSnapshot::from_resolved(&resolved),
        created_at,
    )?)?;
    Ok(run_id)
}

fn advance_to_inspecting(store: &mut Store, run_id: RunId, revision: u64) -> TestResult<u64> {
    let awaiting = transition(
        store,
        run_id,
        RunState::Prepared,
        revision,
        RunState::AwaitingDelegateApproval,
        instant(3),
    )?;
    let running = transition(
        store,
        run_id,
        RunState::AwaitingDelegateApproval,
        awaiting,
        RunState::Running,
        instant(4),
    )?;
    transition(
        store,
        run_id,
        RunState::Running,
        running,
        RunState::Inspecting,
        instant(5),
    )
}

fn transition(
    store: &mut Store,
    run_id: RunId,
    from: RunState,
    revision: u64,
    to: RunState,
    at: DateTime<Utc>,
) -> TestResult<u64> {
    Ok(store
        .compare_and_transition_subscription_run(
            run_id,
            from,
            revision,
            RunTransition::new(from, to, None)?,
            RunTrustLabel::TrustedCarlState,
            at,
        )?
        .expect("transition CAS succeeds")
        .revision)
}

fn exact_proposal(
    stage: &SanitizedStage,
    artifacts: &ArtifactStore,
) -> TestResult<ExactReplacementProposal> {
    let outcome = stage.inspect_proposal(artifacts, ProposalLimits::new(4_096)?, SecretFilter)?;
    match outcome {
        ProposalOutcome::ExactReplacement(proposal) => Ok(*proposal),
        ProposalOutcome::NoChanges => Err("changed stage produced no proposal".into()),
    }
}

fn table_count(connection: &Connection, table: &str) -> Result<u64, rusqlite::Error> {
    connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
}

fn instant(second: u32) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&format!("2026-07-30T12:00:{second:02}Z"))
        .expect("valid test timestamp")
        .with_timezone(&Utc)
}

#[cfg(unix)]
fn make_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn make_owner_only(path: &Path) -> std::io::Result<()> {
    let identity = std::process::Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()?;
    if !identity.status.success() {
        return Err(std::io::Error::other(
            "the Windows fixture could not resolve the current identity",
        ));
    }
    let sid_start = identity
        .stdout
        .windows(4)
        .position(|window| window == b"S-1-")
        .ok_or_else(|| std::io::Error::other("whoami returned no current-user SID"))?;
    let sid_end = identity.stdout[sid_start..]
        .iter()
        .position(|byte| !byte.is_ascii_digit() && *byte != b'-' && *byte != b'S')
        .map_or(identity.stdout.len(), |offset| sid_start + offset);
    let sid = std::str::from_utf8(&identity.stdout[sid_start..sid_end])
        .map_err(|_| std::io::Error::other("whoami returned an invalid SID"))?;
    let numeric_identity = format!("*{sid}");
    let owner_status = std::process::Command::new("icacls")
        .arg(path)
        .arg("/setowner")
        .arg(&numeric_identity)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !owner_status.success() {
        return Err(std::io::Error::other(
            "the Windows fixture could not set the current user as owner",
        ));
    }
    let grant = format!("{numeric_identity}:(OI)(CI)F");
    let status = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(grant)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "the Windows fixture could not install a private DACL",
        ))
    }
}
