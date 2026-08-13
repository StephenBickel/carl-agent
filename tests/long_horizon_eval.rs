use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use carl::evals::{
    EvaluationError, EvaluationMetrics, EvaluationScenario, NEEDLE_IDENTIFIER,
    evaluate_release_gate, run_long_horizon_evaluation, run_repository_release_gate_matrix,
    unresolved_started_cut_fails_closed,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

static FIXTURE_SERIAL: AtomicU64 = AtomicU64::new(0);

fn fixture_source() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/long_horizon/needle")
}

struct TestFixtureCopy {
    root: PathBuf,
}

impl TestFixtureCopy {
    fn new() -> TestResult<Self> {
        Self::new_with_timestamp(SystemTime::now())
    }

    fn new_with_timestamp(timestamp: SystemTime) -> TestResult<Self> {
        let unique = timestamp.duration_since(UNIX_EPOCH)?.as_nanos();
        let serial = FIXTURE_SERIAL.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "carl-long-horizon-fixture-{}-{unique}-{serial}",
            std::process::id(),
        ));
        fs::create_dir_all(root.join("src"))?;
        fs::create_dir_all(root.join("tests"))?;
        for relative in ["README.md", "Cargo.toml", "src/lib.rs", "tests/contract.rs"] {
            fs::copy(fixture_source().join(relative), root.join(relative))?;
        }
        Ok(Self { root })
    }
}

#[test]
fn fixture_copies_with_the_same_clock_read_are_isolated() -> TestResult {
    let timestamp = SystemTime::now();
    let first = TestFixtureCopy::new_with_timestamp(timestamp)?;
    let second = TestFixtureCopy::new_with_timestamp(timestamp)?;
    assert_ne!(first.root, second.root);
    assert!(first.root.is_dir());
    assert!(second.root.is_dir());
    Ok(())
}

impl Drop for TestFixtureCopy {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn passing_metrics() -> EvaluationMetrics {
    EvaluationMetrics {
        completed: true,
        work_epochs: 100,
        provider_requests: 101,
        tool_calls: 100,
        required_clauses_passed: 2,
        duplicate_effects: 0,
        lost_identifiers: 0,
        out_of_scope_changes: 0,
        restarts: 5,
        compactions: 33,
        strategy_changes: 5,
        orphan_processes: 0,
        secret_policy_violations: 0,
        replay_digest: "a".repeat(64),
    }
}

#[test]
fn public_contracts_are_bounded_sanitized_and_strict() -> TestResult {
    let scenario = EvaluationScenario::standard();
    assert_eq!(scenario.name, "needle-retention-100-epoch");
    assert_eq!(scenario.epochs, 100);
    assert_eq!(scenario.force_compaction_every, 3);
    assert_eq!(
        scenario
            .steering
            .iter()
            .map(|steering| steering.work_epoch)
            .collect::<Vec<_>>(),
        [11, 61]
    );
    assert_eq!(scenario.expected_identifiers, [NEEDLE_IDENTIFIER]);
    assert!(!scenario.restart_after_events.is_empty());

    let encoded = serde_json::to_string(&passing_metrics())?;
    for forbidden in ["assistant_text", "raw_tool_output", "credentials"] {
        assert!(!encoded.contains(forbidden));
    }
    let absolute_user_path = ["/", "Users", "/private/workspace"].concat();
    assert!(!encoded.contains(&absolute_user_path));
    let mut value = serde_json::to_value(passing_metrics())?;
    value
        .as_object_mut()
        .expect("metrics serialize as an object")
        .insert("assistant_text".to_owned(), serde_json::json!("untrusted"));
    assert!(serde_json::from_value::<EvaluationMetrics>(value).is_err());

    let mut failed = passing_metrics();
    failed.completed = false;
    failed.duplicate_effects = 1;
    failed.lost_identifiers = 1;
    failed.out_of_scope_changes = 1;
    failed.orphan_processes = 1;
    failed.secret_policy_violations = 1;
    assert_eq!(
        evaluate_release_gate("release-gate", 100, 2, failed).failure_codes,
        [
            "incomplete",
            "duplicate_effects",
            "lost_identifiers",
            "orphan_processes",
            "out_of_scope_changes",
            "secret_policy_violations",
        ]
    );
    Ok(())
}

#[test]
fn exhaustive_real_engine_lifecycle_cut_matrix_remains_a_release_dependency() {
    let lifecycle_contract = include_str!("epoch_engine_contract.rs");
    assert!(
        lifecycle_contract.contains(
            "async fn every_required_engine_restart_cut_restarts_from_real_engine_state()"
        )
    );
    for required_cut in [
        "TaskCreated",
        "EpochStarted",
        "OperationIntentRecorded",
        "EffectAuthorized",
        "ItemStarted",
        "WorkspaceMutated",
        "ItemCompleted",
        "CheckpointCandidateBuilt",
        "CheckpointCommitted",
        "CompactionRequested",
        "ProviderReplacementStarted",
        "ProviderBindingCommitted",
    ] {
        assert!(
            lifecycle_contract.contains(&format!("RequiredEngineRestartCut::{required_cut}")),
            "missing required real-engine lifecycle cut {required_cut}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn actual_engine_survives_one_hundred_epochs_and_normalizes_replay() -> TestResult {
    let result =
        run_long_horizon_evaluation(&EvaluationScenario::standard(), &fixture_source()).await?;

    assert!(
        result.passed,
        "release failures: {:?}",
        result.failure_codes
    );
    assert!(result.metrics.completed);
    assert_eq!(result.metrics.work_epochs, 100);
    assert_eq!(result.metrics.provider_requests, 101);
    assert_eq!(result.metrics.tool_calls, 100);
    assert_eq!(result.metrics.required_clauses_passed, 2);
    assert_eq!(result.metrics.compactions, 33);
    assert_eq!(result.metrics.restarts, 9);
    assert_eq!(result.metrics.strategy_changes, 5);
    assert_eq!(result.metrics.duplicate_effects, 0);
    assert_eq!(result.metrics.lost_identifiers, 0);
    assert_eq!(result.metrics.out_of_scope_changes, 0);
    assert_eq!(result.metrics.orphan_processes, 0);
    assert_eq!(result.metrics.secret_policy_violations, 0);
    assert_eq!(result.metrics.replay_digest.len(), 64);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn unresolved_started_operation_fails_closed_without_replay() -> TestResult {
    assert!(unresolved_started_cut_fails_closed(&fixture_source()).await?);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn repository_release_gate_matrix_is_bounded_and_isolated() -> TestResult {
    let results = run_repository_release_gate_matrix(&fixture_source()).await?;
    assert_eq!(
        results
            .iter()
            .map(|result| result.scenario.as_str())
            .collect::<Vec<_>>(),
        [
            "regression-first-bug-fix",
            "multi-file-refactor",
            "command-failure-recovery",
            "stalled-strategy-replacement",
            "provider-loss",
            "long-running-command-cancellation",
            "hostile-instructions",
            "secret-rejection",
            "out-of-scope-write",
            "ambiguous-external-effect",
        ]
    );
    assert!(
        results.iter().all(|result| result.passed),
        "matrix failures: {results:#?}"
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| !result.metrics.completed)
            .map(|result| result.failure_codes.as_slice())
            .collect::<Vec<_>>(),
        [
            ["cancelled_cleanly"].as_slice(),
            ["hostile_instruction_rejected"].as_slice(),
            ["secret_rejected"].as_slice(),
            ["out_of_scope_write_rejected"].as_slice(),
            ["ambiguous_effect_blocked"].as_slice(),
        ]
    );
    assert!(results.iter().all(|result| {
        result.metrics.duplicate_effects == 0
            && result.metrics.lost_identifiers == 0
            && result.metrics.out_of_scope_changes == 0
            && result.metrics.orphan_processes == 0
            && result.metrics.secret_policy_violations == 0
    }));
    let by_name = |name: &str| {
        results
            .iter()
            .find(|result| result.scenario == name)
            .expect("matrix case exists")
    };
    assert_eq!(by_name("command-failure-recovery").metrics.tool_calls, 2);
    assert_eq!(by_name("provider-loss").metrics.restarts, 1);
    assert_eq!(by_name("provider-loss").metrics.strategy_changes, 1);
    assert_eq!(by_name("out-of-scope-write").metrics.tool_calls, 1);
    assert_eq!(by_name("ambiguous-external-effect").metrics.restarts, 1);
    assert_eq!(by_name("ambiguous-external-effect").metrics.tool_calls, 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn repository_fixture_rejects_files_outside_the_exact_manifest() -> TestResult {
    let fixture = TestFixtureCopy::new()?;
    fs::write(fixture.root.join("unexpected.txt"), "must be rejected")?;

    let error = run_repository_release_gate_matrix(&fixture.root)
        .await
        .expect_err("an extra fixture file must fail closed");
    assert_eq!(error, EvaluationError::Fixture);
    Ok(())
}

#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn repository_fixture_rejects_symlinks() -> TestResult {
    use std::os::unix::fs::symlink;

    let fixture = TestFixtureCopy::new()?;
    symlink("README.md", fixture.root.join("linked-readme"))?;

    let error = run_repository_release_gate_matrix(&fixture.root)
        .await
        .expect_err("a symlink in the fixture must fail closed");
    assert_eq!(error, EvaluationError::Fixture);
    Ok(())
}
