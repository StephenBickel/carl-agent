use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use carl::delegates::{
    DelegateSettings, DelegateSettingsLayers, ModelId, ReasoningEffort, SettingSource,
};
use carl::error::CarlError;
use carl::events::{Event, SessionId, TurnId};
use carl::runtime::subscription::{
    ProviderReported, RunConfigSnapshot, RunFailureCode, RunId, RunState, RunTransition,
    RunTrustLabel,
};
use carl::sidecar::{DataRootLock, DataRootLockErrorCode};
use carl::storage::{NewSubscriptionRun, RuntimeStore, Store};
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::Connection;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct TemporaryDatabase {
    path: PathBuf,
}

impl TemporaryDatabase {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir()
                .join(format!("carl-subscription-runs-{}.sqlite", Uuid::new_v4())),
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

struct RuntimeDatabase {
    root: PathBuf,
    path: PathBuf,
}

impl RuntimeDatabase {
    fn new() -> Result<Self, std::io::Error> {
        let root =
            std::env::temp_dir().join(format!("carl-subscription-runtime-{}", Uuid::new_v4()));
        fs::create_dir(&root)?;
        make_owner_only(&root)?;
        let path = root.join("carl.sqlite3");
        Ok(Self { root, path })
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for RuntimeDatabase {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn run_creation_persists_configuration_without_mutating_session_defaults() -> TestResult {
    let database = TemporaryDatabase::new();
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let session_settings = DelegateSettings::new(
        Some(ModelId::parse("gpt-5.4")?),
        Some(ReasoningEffort::High),
    );
    let per_run = DelegateSettings::new(Some(ModelId::parse("gpt-5.4-mini")?), None);
    let set_at = instant(0);
    let defaults =
        store.set_session_delegate_settings(session.id, session_settings.clone(), set_at)?;
    assert_eq!(defaults.settings, session_settings);

    let (request, expected_configuration) = new_run(
        session.id,
        session_settings.clone(),
        per_run.clone(),
        instant(1),
    )?;
    let run_id = request.id();
    let turn_id = request.turn_id();
    let created = store.create_subscription_run(request)?;

    assert_eq!(created.id, run_id);
    assert_eq!(created.session_id, session.id);
    assert_eq!(created.turn_id, turn_id);
    assert_eq!(created.state, RunState::Prepared);
    assert_eq!(created.revision, 1);
    assert_eq!(created.per_run_settings, per_run);
    assert_eq!(created.configuration, expected_configuration);
    assert_eq!(created.failure_code, None);
    drop(store);

    let reopened = Store::open(database.path())?;
    assert_eq!(
        reopened
            .get_session_delegate_settings(session.id)?
            .expect("session settings survive reopen")
            .settings,
        session_settings
    );
    assert_eq!(
        reopened
            .get_subscription_run(run_id)?
            .expect("run projection survives reopen"),
        created
    );

    let events = reopened.read_subscription_run_events(run_id)?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sequence, 1);
    match &events[0].event {
        Event::SubscriptionRunPrepared {
            run_id: event_run_id,
            run_sequence,
            configuration,
            state,
            trust_label,
        } => {
            assert_eq!(*event_run_id, run_id);
            assert_eq!(*run_sequence, 1);
            assert_eq!(configuration, &expected_configuration);
            assert_eq!(*state, RunState::Prepared);
            assert_eq!(*trust_label, RunTrustLabel::TrustedCarlState);
        }
        other => panic!("unexpected initial run event: {other:?}"),
    }
    Ok(())
}

#[test]
fn compare_and_transition_is_atomic_ordered_and_cas_safe() -> TestResult {
    let database = TemporaryDatabase::new();
    let mut first = Store::open(database.path())?;
    let session = first.create_session()?;
    let defaults = DelegateSettings::new(None, Some(ReasoningEffort::Medium));
    first.set_session_delegate_settings(session.id, defaults.clone(), instant(0))?;
    let (request, _) = new_run(
        session.id,
        defaults,
        DelegateSettings::default(),
        instant(1),
    )?;
    let run_id = request.id();
    first.create_subscription_run(request)?;
    let mut second = Store::open(database.path())?;

    let awaiting = first
        .compare_and_transition_subscription_run(
            run_id,
            RunState::Prepared,
            1,
            RunTransition::new(RunState::Prepared, RunState::AwaitingDelegateApproval, None)?,
            RunTrustLabel::TrustedCarlState,
            instant(2),
        )?
        .expect("the first compare-and-transition wins");
    assert_eq!(awaiting.state, RunState::AwaitingDelegateApproval);
    assert_eq!(awaiting.revision, 2);

    let lost = second.compare_and_transition_subscription_run(
        run_id,
        RunState::Prepared,
        1,
        RunTransition::new(RunState::Prepared, RunState::AwaitingDelegateApproval, None)?,
        RunTrustLabel::TrustedCarlState,
        instant(3),
    )?;
    assert_eq!(lost, None);
    assert_eq!(
        second.compare_and_transition_subscription_run(
            run_id,
            RunState::AwaitingDelegateApproval,
            1,
            RunTransition::new(RunState::AwaitingDelegateApproval, RunState::Running, None,)?,
            RunTrustLabel::TrustedCarlState,
            instant(4),
        )?,
        None,
        "a correct state with the wrong revision must lose"
    );
    assert_eq!(
        second.compare_and_transition_subscription_run(
            run_id,
            RunState::Prepared,
            2,
            RunTransition::new(RunState::Prepared, RunState::AwaitingDelegateApproval, None)?,
            RunTrustLabel::TrustedCarlState,
            instant(5),
        )?,
        None,
        "the correct revision with the wrong state must lose"
    );

    let projection = second
        .get_subscription_run(run_id)?
        .expect("projection remains available");
    assert_eq!(projection, awaiting);
    let events = second.read_subscription_run_events(run_id)?;
    assert_eq!(events.len(), 2);
    assert_eq!(
        events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    match &events[1].event {
        Event::SubscriptionRunTransitioned {
            run_id: event_run_id,
            run_sequence,
            transition,
            trust_label,
        } => {
            assert_eq!(*event_run_id, run_id);
            assert_eq!(*run_sequence, 2);
            assert_eq!(transition.from(), RunState::Prepared);
            assert_eq!(transition.to(), RunState::AwaitingDelegateApproval);
            assert_eq!(*trust_label, RunTrustLabel::TrustedCarlState);
        }
        other => panic!("unexpected transition event: {other:?}"),
    }
    Ok(())
}

#[test]
fn simultaneous_compare_and_transition_has_exactly_one_winner() -> TestResult {
    let database = TemporaryDatabase::new();
    let mut setup = Store::open(database.path())?;
    let session = setup.create_session()?;
    let run_id = create_default_run(&mut setup, session.id, instant(1))?;
    drop(setup);

    let stores = [Store::open(database.path())?, Store::open(database.path())?];
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for (second, mut store) in [2, 3].into_iter().zip(stores) {
        let barrier = std::sync::Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            store
                .compare_and_transition_subscription_run(
                    run_id,
                    RunState::Prepared,
                    1,
                    RunTransition::new(
                        RunState::Prepared,
                        RunState::AwaitingDelegateApproval,
                        None,
                    )
                    .expect("the fixture transition is valid"),
                    RunTrustLabel::TrustedCarlState,
                    instant(second),
                )
                .expect("the compare-and-transition completes")
                .is_some()
        }));
    }
    barrier.wait();
    let winners = workers
        .into_iter()
        .map(|worker| worker.join().expect("the competing worker does not panic"))
        .filter(|won| *won)
        .count();
    assert_eq!(winners, 1);

    let store = Store::open(database.path())?;
    assert_eq!(store.get_subscription_run(run_id)?.unwrap().revision, 2);
    assert_eq!(store.read_subscription_run_events(run_id)?.len(), 2);
    Ok(())
}

#[test]
fn invalid_and_terminal_transitions_never_write() -> TestResult {
    let database = TemporaryDatabase::new();
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let (request, _) = new_run(
        session.id,
        DelegateSettings::default(),
        DelegateSettings::default(),
        instant(1),
    )?;
    let run_id = request.id();
    store.create_subscription_run(request)?;

    assert!(
        RunTransition::new(RunState::Prepared, RunState::Promoted, None).is_err(),
        "the domain rejects a skipped transition"
    );
    assert_eq!(store.read_subscription_run_events(run_id)?.len(), 1);
    assert_eq!(store.get_subscription_run(run_id)?.unwrap().revision, 1);

    transition(
        &mut store,
        run_id,
        1,
        RunState::Prepared,
        RunState::Failed,
        Some(RunFailureCode::DelegateStartFailed),
        instant(2),
    )?;
    let terminal = store.get_subscription_run(run_id)?.unwrap();
    assert_eq!(terminal.state, RunState::Failed);
    assert_eq!(
        terminal.failure_code,
        Some(RunFailureCode::DelegateStartFailed)
    );
    assert!(
        RunTransition::new(RunState::Failed, RunState::Interrupted, None).is_err(),
        "terminal states reject outgoing transitions"
    );
    assert_eq!(store.read_subscription_run_events(run_id)?.len(), 2);
    Ok(())
}

#[test]
fn generic_transition_api_reserves_the_verification_lifecycle() -> TestResult {
    let database = TemporaryDatabase::new();
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let run_id = create_default_run(&mut store, session.id, instant(1))?;
    transition(
        &mut store,
        run_id,
        1,
        RunState::Prepared,
        RunState::AwaitingDelegateApproval,
        None,
        instant(2),
    )?;
    transition(
        &mut store,
        run_id,
        2,
        RunState::AwaitingDelegateApproval,
        RunState::Running,
        None,
        instant(3),
    )?;
    transition(
        &mut store,
        run_id,
        3,
        RunState::Running,
        RunState::Inspecting,
        None,
        instant(4),
    )?;

    let entering = store
        .compare_and_transition_subscription_run(
            run_id,
            RunState::Inspecting,
            4,
            RunTransition::new(RunState::Inspecting, RunState::Verifying, None)?,
            RunTrustLabel::TrustedCarlState,
            instant(5),
        )
        .expect_err("only the dedicated begin API may enter verification");
    assert!(matches!(
        entering,
        CarlError::Validation { ref detail }
            if detail.contains("dedicated verification")
    ));

    let exiting = store
        .compare_and_transition_subscription_run(
            run_id,
            RunState::Verifying,
            5,
            RunTransition::new(
                RunState::Verifying,
                RunState::AwaitingPromotionApproval,
                None,
            )?,
            RunTrustLabel::TrustedCarlVerification,
            instant(6),
        )
        .expect_err("only the dedicated completion API may exit verification");
    assert!(matches!(
        exiting,
        CarlError::Validation { ref detail }
            if detail.contains("dedicated verification")
    ));
    assert_eq!(
        store.get_subscription_run(run_id)?.unwrap().state,
        RunState::Inspecting
    );
    assert_eq!(store.read_subscription_run_events(run_id)?.len(), 4);
    Ok(())
}

#[test]
fn exclusive_runtime_startup_recovers_nonterminals_once_and_retains_the_lock() -> TestResult {
    let database = RuntimeDatabase::new()?;
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let active_id = create_default_run(&mut store, session.id, instant(1))?;
    let complete_id = create_default_run(&mut store, session.id, instant(2))?;

    transition(
        &mut store,
        active_id,
        1,
        RunState::Prepared,
        RunState::AwaitingDelegateApproval,
        None,
        instant(3),
    )?;
    transition(
        &mut store,
        complete_id,
        1,
        RunState::Prepared,
        RunState::AwaitingDelegateApproval,
        None,
        instant(4),
    )?;
    transition(
        &mut store,
        complete_id,
        2,
        RunState::AwaitingDelegateApproval,
        RunState::Running,
        None,
        instant(5),
    )?;
    transition(
        &mut store,
        complete_id,
        3,
        RunState::Running,
        RunState::Inspecting,
        None,
        instant(6),
    )?;
    transition(
        &mut store,
        complete_id,
        4,
        RunState::Inspecting,
        RunState::CompletedNoChanges,
        None,
        instant(7),
    )?;
    drop(store);

    let runtime_lock = DataRootLock::acquire(database.root())?;
    let reopened = RuntimeStore::open(runtime_lock, instant(8))?;
    assert_eq!(reopened.startup_recoveries(), &[active_id]);
    assert_eq!(
        reopened.get_subscription_run(active_id)?.unwrap().state,
        RunState::Interrupted
    );
    assert_eq!(
        reopened.get_subscription_run(complete_id)?.unwrap().state,
        RunState::CompletedNoChanges
    );
    assert_eq!(
        DataRootLock::acquire(database.root())
            .expect_err("the runtime store must retain exclusive ownership")
            .code(),
        DataRootLockErrorCode::Contended
    );
    assert_eq!(reopened.read_subscription_run_events(active_id)?.len(), 3);
    drop(reopened);

    let runtime_lock = DataRootLock::acquire(database.root())?;
    let reopened = RuntimeStore::open(runtime_lock, instant(9))?;
    assert!(reopened.startup_recoveries().is_empty());
    assert_eq!(
        reopened.read_subscription_run_events(active_id)?.len(),
        3,
        "a later startup must not append a second recovery event"
    );
    Ok(())
}

#[test]
fn runtime_store_derives_its_database_from_the_consumed_lock() -> TestResult {
    let first = RuntimeDatabase::new()?;
    let second = RuntimeDatabase::new()?;
    let mut setup = Store::open(first.path())?;
    let session = setup.create_session()?;
    let run_id = create_default_run(&mut setup, session.id, instant(1))?;
    drop(setup);

    let second_runtime = RuntimeStore::open(DataRootLock::acquire(second.root())?, instant(2))?;
    assert!(second_runtime.startup_recoveries().is_empty());
    assert_eq!(
        Store::open(first.path())?
            .get_subscription_run(run_id)?
            .expect("the first root remains untouched")
            .state,
        RunState::Prepared
    );
    drop(second_runtime);

    let first_runtime = RuntimeStore::open(DataRootLock::acquire(first.root())?, instant(3))?;
    assert_eq!(first_runtime.startup_recoveries(), &[run_id]);
    assert_eq!(
        first_runtime
            .get_subscription_run(run_id)?
            .expect("the guarded root is recovered")
            .state,
        RunState::Interrupted
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn runtime_store_rejects_a_replaced_data_root_after_lock_acquisition() -> TestResult {
    let database = RuntimeDatabase::new()?;
    let lock = DataRootLock::acquire(database.root())?;
    let moved = database.root().with_extension("moved");
    fs::rename(database.root(), &moved)?;
    fs::create_dir(database.root())?;
    make_owner_only(database.root())?;

    let result = RuntimeStore::open(lock, instant(1));
    assert!(
        result.is_err(),
        "a lock on the original directory cannot authorize its path replacement"
    );
    assert!(!database.root().join("carl.sqlite3").exists());
    drop(DataRootLock::acquire(database.root())?);

    fs::remove_dir_all(database.root())?;
    fs::rename(moved, database.root())?;
    Ok(())
}

#[test]
fn injected_create_failures_roll_back_projection_event_link_and_sequence() -> TestResult {
    for trigger in [
        "CREATE TRIGGER injected_failure
         BEFORE INSERT ON subscription_runs
         BEGIN SELECT RAISE(ABORT, 'projection insert failed'); END;",
        "CREATE TRIGGER injected_failure
         BEFORE INSERT ON events
         BEGIN SELECT RAISE(ABORT, 'global event insert failed'); END;",
        "CREATE TRIGGER injected_failure
         BEFORE INSERT ON subscription_run_events
         BEGIN SELECT RAISE(ABORT, 'run event link failed'); END;",
    ] {
        let database = TemporaryDatabase::new();
        let mut store = Store::open(database.path())?;
        let session = store.create_session()?;
        let connection = Connection::open(database.path())?;
        connection.execute_batch(trigger)?;
        let (request, _) = new_run(
            session.id,
            DelegateSettings::default(),
            DelegateSettings::default(),
            instant(1),
        )?;
        let run_id = request.id();

        assert!(store.create_subscription_run(request).is_err());
        assert_eq!(store.get_subscription_run(run_id)?, None);
        assert_storage_counts(&connection, session.id, 0, 0, 1)?;
    }
    Ok(())
}

#[test]
fn every_transition_write_boundary_rolls_back_atomically() -> TestResult {
    for boundary in ["projection", "global_event", "run_event_link"] {
        let database = TemporaryDatabase::new();
        let mut store = Store::open(database.path())?;
        let session = store.create_session()?;
        let run_id = create_default_run(&mut store, session.id, instant(1))?;
        let connection = Connection::open(database.path())?;
        let trigger = match boundary {
            "projection" => format!(
                "CREATE TRIGGER injected_failure
                 BEFORE UPDATE ON subscription_runs
                 WHEN OLD.id = '{run_id}'
                 BEGIN SELECT RAISE(ABORT, 'projection update failed'); END;"
            ),
            "global_event" => "CREATE TRIGGER injected_failure
                 BEFORE INSERT ON events
                 BEGIN SELECT RAISE(ABORT, 'global event insert failed'); END;"
                .to_owned(),
            "run_event_link" => "CREATE TRIGGER injected_failure
                 BEFORE INSERT ON subscription_run_events
                 BEGIN SELECT RAISE(ABORT, 'run event link failed'); END;"
                .to_owned(),
            _ => unreachable!("the boundary fixture is closed"),
        };
        connection.execute_batch(&trigger)?;

        assert!(
            transition(
                &mut store,
                run_id,
                1,
                RunState::Prepared,
                RunState::AwaitingDelegateApproval,
                None,
                instant(2),
            )
            .is_err(),
            "{boundary} failure must abort the transition"
        );
        let projection = store.get_subscription_run(run_id)?.unwrap();
        assert_eq!(projection.state, RunState::Prepared, "{boundary}");
        assert_eq!(projection.revision, 1, "{boundary}");
        assert_eq!(
            store.read_subscription_run_events(run_id)?.len(),
            1,
            "{boundary}"
        );
        assert_storage_counts(&connection, session.id, 1, 1, 2)?;
    }
    Ok(())
}

#[test]
fn injected_transition_and_recovery_failures_are_fully_atomic() -> TestResult {
    let database = RuntimeDatabase::new()?;
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let first_id = create_default_run(&mut store, session.id, instant(1))?;
    let second_id = create_default_run(&mut store, session.id, instant(2))?;
    let connection = Connection::open(database.path())?;

    connection.execute_batch(
        "CREATE TRIGGER reject_transition
         BEFORE INSERT ON subscription_run_events
         WHEN NEW.run_sequence = 2
         BEGIN SELECT RAISE(ABORT, 'transition link failed'); END;",
    )?;
    assert!(
        transition(
            &mut store,
            first_id,
            1,
            RunState::Prepared,
            RunState::AwaitingDelegateApproval,
            None,
            instant(3),
        )
        .is_err()
    );
    assert_eq!(store.get_subscription_run(first_id)?.unwrap().revision, 1);
    assert_eq!(store.read_subscription_run_events(first_id)?.len(), 1);
    assert_storage_counts(&connection, session.id, 2, 2, 3)?;
    connection.execute_batch("DROP TRIGGER reject_transition;")?;

    transition(
        &mut store,
        first_id,
        1,
        RunState::Prepared,
        RunState::AwaitingDelegateApproval,
        None,
        instant(4),
    )?;
    connection.execute_batch(&format!(
        "CREATE TRIGGER reject_recovery
         BEFORE UPDATE ON subscription_runs
         WHEN NEW.state = 'interrupted' AND OLD.id = '{}'
         BEGIN SELECT RAISE(ABORT, 'recovery failed'); END;",
        second_id
    ))?;
    drop(store);
    let runtime_lock = DataRootLock::acquire(database.root())?;
    assert!(
        RuntimeStore::open(runtime_lock, instant(5)).is_err(),
        "startup recovery must surface an injected failure"
    );
    let store = Store::open(database.path())?;
    assert_eq!(
        store.get_subscription_run(first_id)?.unwrap().state,
        RunState::AwaitingDelegateApproval
    );
    assert_eq!(
        store.get_subscription_run(second_id)?.unwrap().state,
        RunState::Prepared
    );
    assert_storage_counts(&connection, session.id, 2, 3, 4)?;
    drop(store);
    drop(DataRootLock::acquire(database.root())?);
    Ok(())
}

#[test]
fn replay_rejects_a_projection_that_disagrees_with_its_committed_events() -> TestResult {
    let database = TemporaryDatabase::new();
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let run_id = create_default_run(&mut store, session.id, instant(1))?;
    let connection = Connection::open(database.path())?;
    connection.execute(
        "UPDATE subscription_runs
         SET state = 'running'
         WHERE id = ?1",
        [run_id.to_string()],
    )?;

    let error = store.read_subscription_run_events(run_id).unwrap_err();
    assert!(
        matches!(error, CarlError::Storage { ref detail } if detail.contains("replay")),
        "projection/event disagreement must be a typed replay error: {error}"
    );
    Ok(())
}

#[test]
fn replay_rejects_missing_cross_bound_and_discontinuous_events() -> TestResult {
    {
        let database = TemporaryDatabase::new();
        let mut store = Store::open(database.path())?;
        let session = store.create_session()?;
        let run_id = create_default_run(&mut store, session.id, instant(1))?;
        transition(
            &mut store,
            run_id,
            1,
            RunState::Prepared,
            RunState::AwaitingDelegateApproval,
            None,
            instant(2),
        )?;
        Connection::open(database.path())?.execute(
            "DELETE FROM subscription_run_events
             WHERE run_id = ?1 AND run_sequence = 2",
            [run_id.to_string()],
        )?;
        assert!(store.read_subscription_run_events(run_id).is_err());
    }

    {
        let database = TemporaryDatabase::new();
        let mut store = Store::open(database.path())?;
        let session = store.create_session()?;
        let run_id = create_default_run(&mut store, session.id, instant(1))?;
        Connection::open(database.path())?.execute(
            "UPDATE events
             SET turn_id = ?2
             WHERE id = (
                SELECT event_id FROM subscription_run_events
                WHERE run_id = ?1 AND run_sequence = 1
             )",
            [run_id.to_string(), TurnId::new().to_string()],
        )?;
        assert!(store.read_subscription_run_events(run_id).is_err());
    }

    {
        let database = TemporaryDatabase::new();
        let mut store = Store::open(database.path())?;
        let session = store.create_session()?;
        let run_id = create_default_run(&mut store, session.id, instant(1))?;
        transition(
            &mut store,
            run_id,
            1,
            RunState::Prepared,
            RunState::AwaitingDelegateApproval,
            None,
            instant(2),
        )?;
        let discontinuous = Event::SubscriptionRunTransitioned {
            run_id,
            run_sequence: 2,
            transition: RunTransition::new(
                RunState::AwaitingDelegateApproval,
                RunState::Running,
                None,
            )?,
            trust_label: RunTrustLabel::TrustedCarlState,
        };
        Connection::open(database.path())?.execute(
            "UPDATE events
             SET event_json = ?2
             WHERE id = (
                SELECT event_id FROM subscription_run_events
                WHERE run_id = ?1 AND run_sequence = 2
             )",
            [run_id.to_string(), serde_json::to_string(&discontinuous)?],
        )?;
        assert!(store.read_subscription_run_events(run_id).is_err());
    }
    Ok(())
}

#[test]
fn replay_rejects_a_changed_terminal_failure_code() -> TestResult {
    let database = TemporaryDatabase::new();
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let run_id = create_default_run(&mut store, session.id, instant(1))?;
    transition(
        &mut store,
        run_id,
        1,
        RunState::Prepared,
        RunState::Failed,
        Some(RunFailureCode::DelegateStartFailed),
        instant(2),
    )?;
    Connection::open(database.path())?.execute(
        "UPDATE subscription_runs
         SET failure_code = 'authentication_required'
         WHERE id = ?1",
        [run_id.to_string()],
    )?;
    assert!(store.read_subscription_run_events(run_id).is_err());
    Ok(())
}

#[test]
fn startup_recovery_rejects_corrupt_history_without_writing() -> TestResult {
    let database = RuntimeDatabase::new()?;
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let run_id = create_default_run(&mut store, session.id, instant(1))?;
    transition(
        &mut store,
        run_id,
        1,
        RunState::Prepared,
        RunState::AwaitingDelegateApproval,
        None,
        instant(2),
    )?;
    let connection = Connection::open(database.path())?;
    connection.execute(
        "DELETE FROM subscription_run_events
         WHERE run_id = ?1 AND run_sequence = 2",
        [run_id.to_string()],
    )?;
    drop(store);

    let runtime_lock = DataRootLock::acquire(database.root())?;
    assert!(
        RuntimeStore::open(runtime_lock, instant(3)).is_err(),
        "startup recovery must fail closed when replay integrity is broken"
    );

    let projection = Store::open(database.path())?
        .get_subscription_run(run_id)?
        .expect("the projection remains present");
    assert_eq!(projection.state, RunState::AwaitingDelegateApproval);
    assert_eq!(projection.revision, 2);
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM events", [], |row| row
            .get::<_, u64>(0))?,
        2
    );
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM subscription_run_events", [], |row| {
            row.get::<_, u64>(0)
        },)?,
        1
    );
    assert_eq!(
        connection.query_row(
            "SELECT next_sequence FROM sessions WHERE id = ?1",
            [session.id.to_string()],
            |row| row.get::<_, u64>(0),
        )?,
        3
    );
    drop(DataRootLock::acquire(database.root())?);
    Ok(())
}

#[test]
fn provider_reported_configuration_is_untrusted_cas_safe_and_durable() -> TestResult {
    let database = TemporaryDatabase::new();
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let run_id = create_default_run(&mut store, session.id, instant(1))?;
    let provider_model = ModelId::parse("gpt-5.4-provider-resolved")?;
    assert!(
        store
            .record_subscription_run_provider_configuration(
                run_id,
                RunState::Prepared,
                1,
                ProviderReported::NotReported,
                ProviderReported::NotReported,
                instant(2),
            )
            .is_err(),
        "provider evidence cannot be attached before the delegate is running"
    );
    transition(
        &mut store,
        run_id,
        1,
        RunState::Prepared,
        RunState::AwaitingDelegateApproval,
        None,
        instant(2),
    )?;
    transition(
        &mut store,
        run_id,
        2,
        RunState::AwaitingDelegateApproval,
        RunState::Running,
        None,
        instant(3),
    )?;

    let observed = store
        .record_subscription_run_provider_configuration(
            run_id,
            RunState::Running,
            3,
            ProviderReported::Reported(provider_model.clone()),
            ProviderReported::Reported(ReasoningEffort::High),
            instant(4),
        )?
        .expect("the first provider observation wins");
    assert_eq!(observed.state, RunState::Running);
    assert_eq!(observed.revision, 4);
    assert!(observed.provider_configuration_observed);
    assert_eq!(
        observed.configuration.provider_model(),
        &ProviderReported::Reported(provider_model.clone())
    );
    assert_eq!(
        observed.configuration.provider_effort(),
        &ProviderReported::Reported(ReasoningEffort::High)
    );

    assert_eq!(
        store.record_subscription_run_provider_configuration(
            run_id,
            RunState::Running,
            3,
            ProviderReported::Reported(ModelId::parse("conflicting-model")?),
            ProviderReported::NotReported,
            instant(5),
        )?,
        None,
        "a stale observation must not overwrite the committed provider report"
    );
    assert!(
        store
            .record_subscription_run_provider_configuration(
                run_id,
                RunState::Running,
                4,
                ProviderReported::NotReported,
                ProviderReported::NotReported,
                instant(6),
            )
            .is_err(),
        "a committed provider report is single-assignment and cannot be erased"
    );
    drop(store);

    let reopened = Store::open(database.path())?;
    assert_eq!(reopened.get_subscription_run(run_id)?, Some(observed));
    let events = reopened.read_subscription_run_events(run_id)?;
    assert_eq!(events.len(), 4);
    match &events[3].event {
        Event::SubscriptionRunConfigurationObserved {
            run_id: event_run_id,
            run_sequence,
            configuration,
            trust_label,
        } => {
            assert_eq!(*event_run_id, run_id);
            assert_eq!(*run_sequence, 4);
            assert_eq!(
                configuration.provider_model(),
                &ProviderReported::Reported(provider_model)
            );
            assert_eq!(*trust_label, RunTrustLabel::UntrustedProviderEvidence);
        }
        other => panic!("unexpected provider observation event: {other:?}"),
    }
    Ok(())
}

#[test]
fn generic_event_append_cannot_forge_or_orphan_run_lifecycle_state() -> TestResult {
    let database = TemporaryDatabase::new();
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let configuration =
        RunConfigSnapshot::from_resolved(&DelegateSettingsLayers::default().resolve());
    let error = store
        .append(
            session.id,
            Some(TurnId::new()),
            Event::SubscriptionRunPrepared {
                run_id: RunId::new(),
                run_sequence: 1,
                configuration,
                state: RunState::Prepared,
                trust_label: RunTrustLabel::TrustedCarlState,
            },
        )
        .unwrap_err();
    assert!(matches!(error, CarlError::Validation { .. }));
    assert!(store.read_events(session.id)?.is_empty());
    let connection = Connection::open(database.path())?;
    assert_storage_counts(&connection, session.id, 0, 0, 1)?;
    Ok(())
}

#[test]
fn session_provenance_is_bound_to_persisted_defaults_at_run_creation() -> TestResult {
    let database = TemporaryDatabase::new();
    let mut store = Store::open(database.path())?;
    let session = store.create_session()?;
    let claimed = DelegateSettings::new(Some(ModelId::parse("claimed-session-model")?), None);
    let claimed_configuration = RunConfigSnapshot::from_resolved(
        &DelegateSettingsLayers {
            session: Some(&claimed),
            ..DelegateSettingsLayers::default()
        }
        .resolve(),
    );
    let missing_default = NewSubscriptionRun::new(
        RunId::new(),
        session.id,
        TurnId::new(),
        DelegateSettings::default(),
        claimed_configuration.clone(),
        instant(1),
    )?;
    assert!(store.create_subscription_run(missing_default).is_err());

    let persisted = DelegateSettings::new(Some(ModelId::parse("persisted-session-model")?), None);
    store.set_session_delegate_settings(session.id, persisted.clone(), instant(2))?;
    let mismatched = NewSubscriptionRun::new(
        RunId::new(),
        session.id,
        TurnId::new(),
        DelegateSettings::default(),
        claimed_configuration,
        instant(3),
    )?;
    assert!(store.create_subscription_run(mismatched).is_err());

    let personal = DelegateSettings::new(Some(ModelId::parse("personal-model")?), None);
    let lower_precedence = RunConfigSnapshot::from_resolved(
        &DelegateSettingsLayers {
            personal: Some(&personal),
            ..DelegateSettingsLayers::default()
        }
        .resolve(),
    );
    let forged_lower_precedence = NewSubscriptionRun::new(
        RunId::new(),
        session.id,
        TurnId::new(),
        DelegateSettings::default(),
        lower_precedence,
        instant(4),
    )?;
    assert!(
        store
            .create_subscription_run(forged_lower_precedence)
            .is_err(),
        "a caller cannot bypass a persisted session setting with a lower-precedence source"
    );

    let forged_provider_default = NewSubscriptionRun::new(
        RunId::new(),
        session.id,
        TurnId::new(),
        DelegateSettings::default(),
        RunConfigSnapshot::from_resolved(&DelegateSettingsLayers::default().resolve()),
        instant(5),
    )?;
    assert!(
        store
            .create_subscription_run(forged_provider_default)
            .is_err(),
        "a caller cannot bypass a persisted session setting with the provider default"
    );

    let (matching, _) = new_run(
        session.id,
        persisted,
        DelegateSettings::default(),
        instant(6),
    )?;
    let run_id = matching.id();
    let created = store.create_subscription_run(matching)?;
    store.set_session_delegate_settings(
        session.id,
        DelegateSettings::new(Some(ModelId::parse("later-session-model")?), None),
        instant(7),
    )?;
    assert_eq!(store.get_subscription_run(run_id)?, Some(created));
    Ok(())
}

fn new_run(
    session_id: SessionId,
    session_settings: DelegateSettings,
    per_run_settings: DelegateSettings,
    at: DateTime<Utc>,
) -> Result<(NewSubscriptionRun, RunConfigSnapshot), Box<dyn Error>> {
    let resolved = DelegateSettingsLayers {
        session: Some(&session_settings),
        per_run: Some(&per_run_settings),
        ..DelegateSettingsLayers::default()
    }
    .resolve();
    let configuration = RunConfigSnapshot::new(
        &resolved,
        ProviderReported::NotReported,
        ProviderReported::NotReported,
    );
    assert_eq!(
        configuration.model_source(),
        if per_run_settings.model().is_some() {
            SettingSource::PerRun
        } else if session_settings.model().is_some() {
            SettingSource::Session
        } else {
            SettingSource::ProviderDefault
        }
    );
    let request = NewSubscriptionRun::new(
        RunId::new(),
        session_id,
        TurnId::new(),
        per_run_settings,
        configuration.clone(),
        at,
    )?;
    Ok((request, configuration))
}

fn create_default_run(
    store: &mut Store,
    session_id: SessionId,
    at: DateTime<Utc>,
) -> Result<RunId, Box<dyn Error>> {
    let (request, _) = new_run(
        session_id,
        DelegateSettings::default(),
        DelegateSettings::default(),
        at,
    )?;
    let id = request.id();
    store.create_subscription_run(request)?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
fn transition(
    store: &mut Store,
    run_id: RunId,
    revision: u64,
    from: RunState,
    to: RunState,
    failure_code: Option<RunFailureCode>,
    at: DateTime<Utc>,
) -> TestResult {
    store
        .compare_and_transition_subscription_run(
            run_id,
            from,
            revision,
            RunTransition::new(from, to, failure_code)?,
            RunTrustLabel::TrustedCarlState,
            at,
        )?
        .expect("the transition precondition must match");
    Ok(())
}

fn assert_storage_counts(
    connection: &Connection,
    session_id: SessionId,
    expected_runs: u64,
    expected_events: u64,
    expected_next_sequence: u64,
) -> TestResult {
    let runs = connection.query_row("SELECT COUNT(*) FROM subscription_runs", [], |row| {
        row.get::<_, u64>(0)
    })?;
    let events = connection.query_row("SELECT COUNT(*) FROM events", [], |row| {
        row.get::<_, u64>(0)
    })?;
    let links =
        connection.query_row("SELECT COUNT(*) FROM subscription_run_events", [], |row| {
            row.get::<_, u64>(0)
        })?;
    let next_sequence = connection.query_row(
        "SELECT next_sequence FROM sessions WHERE id = ?1",
        [session_id.to_string()],
        |row| row.get::<_, u64>(0),
    )?;
    assert_eq!(runs, expected_runs);
    assert_eq!(events, expected_events);
    assert_eq!(links, expected_events);
    assert_eq!(next_sequence, expected_next_sequence);
    Ok(())
}

fn instant(second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 7, 30, 12, 0, second)
        .single()
        .expect("valid fixed test timestamp")
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
