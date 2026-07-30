use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use carl::artifacts::ArtifactStore;
use carl::delegates::{DelegateSettings, DelegateSettingsLayers};
use carl::events::{SessionId, TurnId};
use carl::runtime::subscription::{
    RunConfigSnapshot, RunFailureCode, RunId, RunState, RunTransition, RunTrustLabel,
};
use carl::security::SecretFilter;
use carl::sidecar::{DataRootLock, ExecutableTrustDecision, SidecarCommand, VersionOutputFormat};
use carl::staging::{
    ExactReplacementProposal, ProposalLimits, ProposalOutcome, SanitizedStage,
    SanitizedStageBuilder, StageLimits,
};
use carl::storage::{NewSubscriptionRun, RuntimeStore, Store, VerificationCompletionRecord};
use carl::verification::{
    VerificationEnvironmentProfile, VerificationLimits, VerificationOutcome, VerificationSpec,
    run_subscription_verification,
};
use chrono::{DateTime, Utc};
use libtest_mimic::{Arguments, Failed, Trial};
use semver::VersionReq;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const FIXTURE_ARGUMENT: &str = "--carl-private-verification-fixture";
const ENVIRONMENT_SENTINEL: &str = "sk-carl-verification-contract-secret";
const BEFORE: &[u8] = b"pub fn answer() -> u32 { 41 }\n";
const AFTER: &[u8] = b"pub fn answer() -> u32 { 42 }\n";

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if let Some(exit_code) = dispatch_fixture(&arguments) {
        process::exit(exit_code);
    }

    // SAFETY: this runs before libtest-mimic creates any test threads and proves
    // that the verifier establishes a closed child environment.
    unsafe {
        env::set_var("OPENAI_API_KEY", ENVIRONMENT_SENTINEL);
        env::set_var("CODEX_API_KEY", ENVIRONMENT_SENTINEL);
        env::set_var("CARL_VERIFICATION_POISON", ENVIRONMENT_SENTINEL);
    }

    let trials = vec![
        test(
            "verification specification preserves literal argv and binds every argument",
            verification_specification_preserves_literal_argv_and_binds_every_argument,
        ),
        test(
            "verification specification permits zero and empty arguments",
            verification_specification_permits_zero_and_empty_arguments,
        ),
        test(
            "verification specification rejects unsafe or unbounded arguments",
            verification_specification_rejects_unsafe_or_unbounded_arguments,
        ),
        test(
            "verification runs the exact approved command in a fresh closed candidate",
            verification_runs_the_exact_approved_command_in_a_fresh_closed_candidate,
        ),
        test(
            "verification persists a nonzero exit without a trusted capability",
            verification_persists_a_nonzero_exit_without_a_trusted_capability,
        ),
        test(
            "verification enforces one aggregate output cap",
            verification_enforces_one_aggregate_output_cap,
        ),
        test(
            "verification times out a hanging command",
            verification_times_out_a_hanging_command,
        ),
        test(
            "verification cancellation is durable and terminal",
            verification_cancellation_is_durable_and_terminal,
        ),
        test(
            "verification rejects mutation of the reconstructed candidate",
            verification_rejects_mutation_of_the_reconstructed_candidate,
        ),
        test(
            "verification never persists secret-bearing diagnostic output",
            verification_never_persists_secret_bearing_diagnostic_output,
        ),
        test(
            "verification can durably reject invalid output at the one-byte cap",
            verification_can_durably_reject_invalid_output_at_the_one_byte_cap,
        ),
        test(
            "verification rejects an executable changed after approval without spawning it",
            verification_rejects_an_executable_changed_after_approval_without_spawning_it,
        ),
        test(
            "verification timeout terminates the complete ordinary descendant tree",
            verification_timeout_terminates_the_complete_ordinary_descendant_tree,
        ),
    ];
    libtest_mimic::run(&Arguments::from_iter(env::args_os().skip(1)), trials).exit();
}

fn test(name: &'static str, body: fn() -> TestResult) -> Trial {
    Trial::test(name, move || {
        body().map_err(|error| Failed::from(error.to_string()))
    })
}

fn verification_specification_preserves_literal_argv_and_binds_every_argument() -> TestResult {
    let arguments = vec![
        "--check".to_owned(),
        String::new(),
        "space separated".to_owned(),
        "$(touch should-never-exist)".to_owned(),
        "\"quoted\"".to_owned(),
    ];
    let specification = VerificationSpec::new(
        trusted_fixture()?,
        arguments.clone(),
        VerificationEnvironmentProfile::CleanV1,
        verification_limits()?,
    )?;

    assert_eq!(specification.arguments(), arguments);
    assert!(
        !format!("{specification:?}").contains("should-never-exist"),
        "verification arguments are approval evidence and must stay redacted in Debug"
    );

    let merged = VerificationSpec::new(
        trusted_fixture()?,
        vec![arguments.join(" ")],
        VerificationEnvironmentProfile::CleanV1,
        verification_limits()?,
    )?;
    assert_ne!(
        specification.specification_digest(),
        merged.specification_digest(),
        "an argv vector must never collapse into shell text"
    );
    Ok(())
}

fn verification_specification_permits_zero_and_empty_arguments() -> TestResult {
    let none = VerificationSpec::new(
        trusted_fixture()?,
        Vec::new(),
        VerificationEnvironmentProfile::CleanV1,
        verification_limits()?,
    )?;
    assert!(none.arguments().is_empty());

    let empty_first = VerificationSpec::new(
        trusted_fixture()?,
        vec![String::new(), "second".to_owned()],
        VerificationEnvironmentProfile::CleanV1,
        verification_limits()?,
    )?;
    assert_eq!(empty_first.arguments(), ["", "second"]);
    assert_ne!(
        none.specification_digest(),
        empty_first.specification_digest()
    );
    Ok(())
}

fn verification_specification_rejects_unsafe_or_unbounded_arguments() -> TestResult {
    for arguments in [
        vec!["contains\0nul".to_owned()],
        vec!["token=\"sk-1234567890abcdefghijklmnop\"".to_owned()],
        vec!["x".repeat(4_097)],
        vec!["x".repeat(257); 129],
        vec!["x".repeat(4_096); 9],
    ] {
        assert!(
            VerificationSpec::new(
                trusted_fixture()?,
                arguments,
                VerificationEnvironmentProfile::CleanV1,
                verification_limits()?,
            )
            .is_err(),
            "unsafe or unbounded argv must be rejected"
        );
    }
    Ok(())
}

fn verification_runs_the_exact_approved_command_in_a_fresh_closed_candidate() -> TestResult {
    let mut prepared = PreparedRun::new()?;
    let literal_arguments = vec![
        String::new(),
        "space separated".to_owned(),
        "$(touch should-never-exist)".to_owned(),
        "\"quoted\"".to_owned(),
    ];
    let mut arguments = vec![FIXTURE_ARGUMENT.to_owned(), "report".to_owned()];
    arguments.extend(literal_arguments.clone());
    let specification = VerificationSpec::new(
        trusted_fixture()?,
        arguments,
        VerificationEnvironmentProfile::CleanV1,
        verification_limits()?,
    )?;

    let completion = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run_subscription_verification(
            &mut prepared.runtime,
            prepared.run_id,
            prepared.inspecting_revision,
            &specification,
            &prepared.layout.verifications,
            CancellationToken::new(),
        ))?
        .ok_or("the current inspection revision must start verification")?;

    assert_eq!(completion.result().outcome(), VerificationOutcome::Passed);
    assert_eq!(completion.result().exit_code(), Some(0));
    let verified = completion
        .verified_proposal()
        .ok_or("only a committed passing result may mint a verified proposal")?;
    assert_eq!(verified.run_id(), prepared.run_id);
    assert_eq!(
        verified.result_digest(),
        completion.result().result_digest()
    );
    assert_eq!(completion.run().state, RunState::AwaitingPromotionApproval);

    let report: Value = serde_json::from_str(completion.result().stdout().text())?;
    let reported_arguments = report["arguments"]
        .as_array()
        .ok_or("fixture report has no argument array")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "fixture argument is not text".into())
        })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(reported_arguments, literal_arguments);
    assert_eq!(report["openai_api_key_present"], false);
    assert_eq!(report["codex_api_key_present"], false);
    assert_eq!(report["poison_present"], false);

    let candidate = PathBuf::from(
        report["cwd"]
            .as_str()
            .ok_or("fixture report has no working directory")?,
    );
    assert!(candidate.starts_with(fs::canonicalize(&prepared.layout.verifications)?));
    assert_ne!(candidate, fs::canonicalize(prepared.stage.path())?);
    assert_ne!(candidate, fs::canonicalize(&prepared.layout.source)?);
    assert!(
        !candidate.exists(),
        "the disposable verification candidate must be removed after execution"
    );
    assert_eq!(
        fs::read(prepared.layout.source.join("src/lib.rs"))?,
        BEFORE,
        "verification must never execute in or mutate the live source"
    );

    let durable_request = prepared
        .runtime
        .get_subscription_run_verification_request(prepared.run_id)?
        .ok_or("the verification request was not persisted")?;
    let durable_result = prepared
        .runtime
        .get_subscription_run_verification_result(prepared.run_id)?
        .ok_or("the verification result was not persisted")?;
    assert_eq!(
        durable_request.request_digest(),
        completion.result().request_digest()
    );
    assert_eq!(durable_result, *completion.result());
    Ok(())
}

fn verification_persists_a_nonzero_exit_without_a_trusted_capability() -> TestResult {
    let mut prepared = PreparedRun::new()?;
    let completion = prepared.verify(
        "nonzero",
        verification_limits()?,
        CancellationToken::new(),
        None,
    )?;
    assert_failed_verification(&completion, VerificationOutcome::NonZeroExit);
    assert_eq!(completion.result().exit_code(), Some(23));
    assert!(completion.result().stdout().text().contains("nonzero"));
    assert_durable_result(&prepared, &completion)?;
    Ok(())
}

fn verification_enforces_one_aggregate_output_cap() -> TestResult {
    let mut prepared = PreparedRun::new()?;
    let completion = prepared.verify(
        "flood",
        verification_limits_with(Duration::from_secs(5), 1_024)?,
        CancellationToken::new(),
        None,
    )?;
    assert_failed_verification(&completion, VerificationOutcome::OutputLimitExceeded);
    assert_eq!(completion.result().stdout().byte_length(), 0);
    assert_eq!(completion.result().stderr().byte_length(), 0);
    assert_durable_result(&prepared, &completion)?;
    Ok(())
}

fn verification_times_out_a_hanging_command() -> TestResult {
    let mut prepared = PreparedRun::new()?;
    let completion = prepared.verify(
        "hang",
        verification_limits_with(Duration::from_millis(200), 64 * 1_024)?,
        CancellationToken::new(),
        None,
    )?;
    assert_failed_verification(&completion, VerificationOutcome::TimedOut);
    assert!(completion.result().stdout().text().contains("ready"));
    assert_durable_result(&prepared, &completion)?;
    Ok(())
}

fn verification_cancellation_is_durable_and_terminal() -> TestResult {
    let mut prepared = PreparedRun::new()?;
    let completion = prepared.verify(
        "hang",
        verification_limits()?,
        CancellationToken::new(),
        Some(Duration::from_millis(250)),
    )?;
    assert_eq!(
        completion.result().outcome(),
        VerificationOutcome::Cancelled
    );
    assert_eq!(completion.run().state, RunState::Cancelled);
    assert_eq!(completion.run().failure_code, None);
    assert!(completion.verified_proposal().is_none());
    assert!(completion.result().stdout().text().contains("ready"));
    assert_durable_result(&prepared, &completion)?;
    Ok(())
}

fn verification_rejects_mutation_of_the_reconstructed_candidate() -> TestResult {
    let mut prepared = PreparedRun::new()?;
    let completion = prepared.verify(
        "mutate",
        verification_limits()?,
        CancellationToken::new(),
        None,
    )?;
    assert_failed_verification(&completion, VerificationOutcome::CandidateMutated);
    assert_eq!(
        fs::read(prepared.layout.source.join("src/lib.rs"))?,
        BEFORE,
        "candidate mutation must not reach the live workspace"
    );
    assert_durable_result(&prepared, &completion)?;
    Ok(())
}

fn verification_never_persists_secret_bearing_diagnostic_output() -> TestResult {
    let mut prepared = PreparedRun::new()?;
    let completion = prepared.verify(
        "secret-output",
        verification_limits()?,
        CancellationToken::new(),
        None,
    )?;
    assert_failed_verification(&completion, VerificationOutcome::OutputRejected);
    assert!(
        !completion
            .result()
            .stdout()
            .text()
            .contains(ENVIRONMENT_SENTINEL)
    );
    assert!(
        !completion
            .result()
            .stderr()
            .text()
            .contains(ENVIRONMENT_SENTINEL)
    );

    let connection = rusqlite::Connection::open(prepared.layout.root.join("carl.sqlite3"))?;
    let persisted: (String, String) = connection.query_row(
        "SELECT stdout_text, stderr_text
         FROM subscription_run_verification_results
         WHERE run_id = ?1",
        [prepared.run_id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert!(!persisted.0.contains(ENVIRONMENT_SENTINEL));
    assert!(!persisted.1.contains(ENVIRONMENT_SENTINEL));
    assert_durable_result(&prepared, &completion)?;
    Ok(())
}

fn verification_can_durably_reject_invalid_output_at_the_one_byte_cap() -> TestResult {
    let mut prepared = PreparedRun::new()?;
    let completion = prepared.verify(
        "invalid-byte",
        verification_limits_with(Duration::from_secs(5), 1)?,
        CancellationToken::new(),
        None,
    )?;
    assert_failed_verification(&completion, VerificationOutcome::OutputRejected);
    assert_eq!(completion.result().stdout().byte_length(), 0);
    assert_eq!(completion.result().stderr().byte_length(), 0);
    assert_durable_result(&prepared, &completion)?;
    Ok(())
}

fn verification_rejects_an_executable_changed_after_approval_without_spawning_it() -> TestResult {
    let executable = MutableExecutable::new()?;
    let specification = VerificationSpec::new(
        trusted_fixture_at(&executable.path)?,
        vec![FIXTURE_ARGUMENT.to_owned(), "report".to_owned()],
        VerificationEnvironmentProfile::CleanV1,
        verification_limits()?,
    )?;
    executable.change_after_approval()?;

    let mut prepared = PreparedRun::new()?;
    let completion =
        prepared.verify_specification(&specification, CancellationToken::new(), None)?;
    assert_failed_verification(&completion, VerificationOutcome::ProcessFailed);
    assert_eq!(
        completion.result().stdout().byte_length(),
        0,
        "a changed executable must be rejected before it can run"
    );
    assert_eq!(completion.result().stderr().byte_length(), 0);
    assert_durable_result(&prepared, &completion)?;
    Ok(())
}

fn verification_timeout_terminates_the_complete_ordinary_descendant_tree() -> TestResult {
    let mut prepared = PreparedRun::new()?;
    let completion = prepared.verify(
        "descendants",
        verification_limits_with(Duration::from_millis(500), 64 * 1_024)?,
        CancellationToken::new(),
        None,
    )?;
    assert_failed_verification(&completion, VerificationOutcome::TimedOut);
    let pids: Value = serde_json::from_str(completion.result().stdout().text())?;
    let leader = u32::try_from(pids["leader"].as_u64().ok_or("no fixture leader PID")?)?;
    let descendant = u32::try_from(
        pids["descendant"]
            .as_u64()
            .ok_or("no fixture descendant PID")?,
    )?;
    wait_until_processes_exit(&[leader, descendant])?;
    assert_durable_result(&prepared, &completion)?;
    Ok(())
}

fn assert_failed_verification(
    completion: &VerificationCompletionRecord,
    expected: VerificationOutcome,
) {
    assert_eq!(completion.result().outcome(), expected);
    assert_eq!(completion.run().state, RunState::Failed);
    assert_eq!(
        completion.run().failure_code,
        Some(RunFailureCode::VerificationFailed)
    );
    assert!(completion.verified_proposal().is_none());
}

fn assert_durable_result(
    prepared: &PreparedRun,
    completion: &VerificationCompletionRecord,
) -> TestResult {
    let durable = prepared
        .runtime
        .get_subscription_run_verification_result(prepared.run_id)?
        .ok_or("the terminal verification result was not persisted")?;
    assert_eq!(durable, *completion.result());
    Ok(())
}

fn dispatch_fixture(arguments: &[OsString]) -> Option<i32> {
    if arguments.first().map(OsString::as_os_str) != Some(OsStr::new(FIXTURE_ARGUMENT)) {
        return None;
    }
    Some(match arguments.get(1).and_then(|value| value.to_str()) {
        Some("report") => {
            let report = serde_json::json!({
                "arguments": arguments[2..]
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect::<Vec<_>>(),
                "cwd": env::current_dir()
                    .map(|path| path.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                "openai_api_key_present": env::var_os("OPENAI_API_KEY").is_some(),
                "codex_api_key_present": env::var_os("CODEX_API_KEY").is_some(),
                "poison_present": env::var_os("CARL_VERIFICATION_POISON").is_some(),
            });
            match serde_json::to_writer(std::io::stdout(), &report) {
                Ok(()) => {
                    println!();
                    0
                }
                Err(_) => 74,
            }
        }
        Some("nonzero") => {
            println!("nonzero fixture exit");
            23
        }
        Some("flood") => {
            // Each stream stays below the 1 KiB test limit; only their combined
            // size crosses it, proving the supervisor uses one aggregate budget.
            let bytes = vec![b'x'; 768];
            let _ = io::stdout().write_all(&bytes);
            let _ = io::stdout().flush();
            let _ = io::stderr().write_all(&bytes);
            let _ = io::stderr().flush();
            thread::sleep(Duration::from_secs(30));
            0
        }
        Some("hang") => {
            println!("ready");
            let _ = io::stdout().flush();
            thread::sleep(Duration::from_secs(30));
            0
        }
        Some("mutate") => match fs::write("src/lib.rs", b"candidate was mutated\n") {
            Ok(()) => 0,
            Err(_) => 73,
        },
        Some("secret-output") => {
            println!("{ENVIRONMENT_SENTINEL}");
            0
        }
        Some("invalid-byte") => {
            let _ = io::stdout().write_all(&[0xff]);
            let _ = io::stdout().flush();
            0
        }
        Some("descendants") => {
            let executable = match env::current_exe() {
                Ok(executable) => executable,
                Err(_) => return Some(71),
            };
            let descendant = match Command::new(executable)
                .arg(FIXTURE_ARGUMENT)
                .arg("descendant-child")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(descendant) => descendant,
                Err(_) => return Some(71),
            };
            println!(
                "{}",
                serde_json::json!({
                    "leader": process::id(),
                    "descendant": descendant.id(),
                })
            );
            let _ = io::stdout().flush();
            thread::sleep(Duration::from_secs(30));
            0
        }
        Some("descendant-child") => {
            thread::sleep(Duration::from_secs(30));
            0
        }
        _ => 64,
    })
}

struct VerificationLayout {
    root: PathBuf,
    source: PathBuf,
    stages: PathBuf,
    verifications: PathBuf,
}

impl VerificationLayout {
    fn new() -> TestResult<Self> {
        let root = env::temp_dir().join(format!("carl-verification-contract-{}", Uuid::new_v4()));
        let source = root.join("source");
        let stages = root.join("stages");
        let verifications = root.join("verifications");
        fs::create_dir_all(source.join("src/empty/nested"))?;
        fs::create_dir_all(&stages)?;
        fs::create_dir_all(&verifications)?;
        make_owner_only(&root)?;
        make_owner_only(&source)?;
        make_owner_only(&source.join("src"))?;
        make_owner_only(&source.join("src/empty"))?;
        make_owner_only(&source.join("src/empty/nested"))?;
        make_owner_only(&stages)?;
        make_owner_only(&verifications)?;
        fs::write(source.join("src/lib.rs"), BEFORE)?;
        Ok(Self {
            root,
            source,
            stages,
            verifications,
        })
    }

    fn prepare(&self, artifacts: &ArtifactStore) -> TestResult<SanitizedStage> {
        Ok(SanitizedStageBuilder::open(
            &self.source,
            &self.stages,
            StageLimits::new(64, 64 * 1_024, 1024 * 1_024)?,
            SecretFilter,
        )?
        .prepare(artifacts)?)
    }
}

impl Drop for VerificationLayout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct PreparedRun {
    stage: SanitizedStage,
    runtime: RuntimeStore,
    layout: VerificationLayout,
    run_id: RunId,
    inspecting_revision: u64,
}

impl PreparedRun {
    fn new() -> TestResult<Self> {
        let layout = VerificationLayout::new()?;
        let mut runtime = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, instant(0))?;
        let stage = layout.prepare(runtime.artifacts())?;
        let run_id = create_run(&mut runtime, instant(1))?;
        runtime
            .record_subscription_run_baseline(
                run_id,
                RunState::Prepared,
                1,
                stage.sealed_baseline(),
                instant(2),
            )?
            .ok_or("the baseline write must win")?;
        let inspecting_revision = advance_to_inspecting(&mut runtime, run_id, 1)?;
        fs::write(stage.path().join("src/lib.rs"), AFTER)?;
        let proposal = exact_proposal(&stage, runtime.artifacts())?;
        runtime
            .record_subscription_run_exact_proposal(
                run_id,
                RunState::Inspecting,
                inspecting_revision,
                &proposal,
                instant(6),
            )?
            .ok_or("the exact proposal write must win")?;
        Ok(Self {
            stage,
            runtime,
            layout,
            run_id,
            inspecting_revision,
        })
    }

    fn verify(
        &mut self,
        scenario: &str,
        limits: VerificationLimits,
        cancellation: CancellationToken,
        cancel_after: Option<Duration>,
    ) -> TestResult<VerificationCompletionRecord> {
        let specification = VerificationSpec::new(
            trusted_fixture()?,
            vec![FIXTURE_ARGUMENT.to_owned(), scenario.to_owned()],
            VerificationEnvironmentProfile::CleanV1,
            limits,
        )?;
        self.verify_specification(&specification, cancellation, cancel_after)
    }

    fn verify_specification(
        &mut self,
        specification: &VerificationSpec,
        cancellation: CancellationToken,
        cancel_after: Option<Duration>,
    ) -> TestResult<VerificationCompletionRecord> {
        let cancel = cancellation.clone();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                if let Some(delay) = cancel_after {
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        cancel.cancel();
                    });
                }
                run_subscription_verification(
                    &mut self.runtime,
                    self.run_id,
                    self.inspecting_revision,
                    specification,
                    &self.layout.verifications,
                    cancellation,
                )
                .await
            })?
            .ok_or_else(|| "the current inspection revision must start verification".into())
    }
}

struct MutableExecutable {
    root: PathBuf,
    path: PathBuf,
}

impl MutableExecutable {
    fn new() -> TestResult<Self> {
        let current = env::current_exe()?;
        let parent = current
            .parent()
            .ok_or("the verification contract executable has no parent")?;
        let root = parent.join(format!(".carl-verifier-executable-{}", Uuid::new_v4()));
        fs::create_dir(&root)?;
        make_owner_only(&root)?;
        #[cfg(windows)]
        let path = root.join("verifier.exe");
        #[cfg(not(windows))]
        let path = root.join("verifier");
        fs::copy(current, &path)?;
        #[cfg(unix)]
        make_owner_only(&path)?;
        Ok(Self { root, path })
    }

    fn change_after_approval(&self) -> TestResult {
        let mut file = OpenOptions::new().append(true).open(&self.path)?;
        file.write_all(b"\0")?;
        file.sync_all()?;
        Ok(())
    }
}

impl Drop for MutableExecutable {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
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
        .ok_or("subscription-run transition lost its compare-and-swap")?
        .revision)
}

fn exact_proposal(
    stage: &SanitizedStage,
    artifacts: &ArtifactStore,
) -> TestResult<ExactReplacementProposal> {
    match stage.inspect_proposal(artifacts, ProposalLimits::new(64 * 1_024)?, SecretFilter)? {
        ProposalOutcome::ExactReplacement(proposal) => Ok(*proposal),
        ProposalOutcome::NoChanges => Err("changed verification stage produced no proposal".into()),
    }
}

fn trusted_fixture() -> TestResult<carl::sidecar::TrustedExecutable> {
    trusted_fixture_at(&env::current_exe()?)
}

fn trusted_fixture_at(path: &Path) -> TestResult<carl::sidecar::TrustedExecutable> {
    let command = SidecarCommand {
        executable: path.to_path_buf(),
        arguments: Vec::new(),
        version_arguments: vec![OsString::from("--version")],
        version_output: VersionOutputFormat::SingleSemverToken,
        isolated_home: PathBuf::from("verification-contract"),
        supported_versions: VersionReq::parse(">=0.0.0")?,
    };
    let resolved = command.resolve_executable()?;
    let decision = if resolved.metadata_risk().is_some() {
        ExecutableTrustDecision::TrustCanonicalPathWithMetadataRisk
    } else {
        ExecutableTrustDecision::TrustCanonicalPath
    };
    Ok(resolved.trust(decision)?)
}

fn verification_limits() -> TestResult<VerificationLimits> {
    verification_limits_with(Duration::from_secs(5), 64 * 1_024)
}

fn verification_limits_with(
    execution_timeout: Duration,
    max_output_bytes: usize,
) -> TestResult<VerificationLimits> {
    Ok(VerificationLimits::new(
        execution_timeout,
        max_output_bytes,
        Duration::from_millis(250),
        Duration::from_secs(2),
        Duration::from_millis(5),
    )?)
}

fn instant(second: u32) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&format!("2026-07-30T12:00:{second:02}Z"))
        .expect("valid test timestamp")
        .with_timezone(&Utc)
}

fn wait_until_processes_exit(pids: &[u32]) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(5);
    while pids.iter().any(|pid| process_is_alive(*pid)) {
        if Instant::now() >= deadline {
            return Err(format!("verification fixture processes are still alive: {pids:?}").into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: signal zero performs an existence check and never signals the process.
    let exists = unsafe { libc::kill(pid, 0) } == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    if !exists {
        return false;
    }
    let output = Command::new("ps")
        .args(["-o", "state=", "-p", &pid.to_string()])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            let state = String::from_utf8_lossy(&output.stdout);
            !state.trim_start().starts_with('Z') && !state.trim().is_empty()
        }
        _ => true,
    }
}

#[cfg(windows)]
fn process_is_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
    };

    // SAFETY: the handle is checked for null, waited without blocking, and closed once.
    unsafe {
        let process = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if process.is_null() {
            return std::io::Error::last_os_error().raw_os_error()
                != i32::try_from(ERROR_INVALID_PARAMETER).ok();
        }
        let alive = WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
        let _ = CloseHandle(process);
        alive
    }
}

#[cfg(unix)]
fn make_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn make_owner_only(path: &Path) -> std::io::Result<()> {
    let identity = process::Command::new("whoami")
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
    let owner_status = process::Command::new("icacls")
        .arg(path)
        .arg("/setowner")
        .arg(&numeric_identity)
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()?;
    if !owner_status.success() {
        return Err(std::io::Error::other(
            "the Windows fixture could not set the current user as owner",
        ));
    }
    let grant = format!("{numeric_identity}:(OI)(CI)F");
    let status = process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r"])
        .arg(grant)
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "the Windows fixture could not install a private DACL",
        ))
    }
}
