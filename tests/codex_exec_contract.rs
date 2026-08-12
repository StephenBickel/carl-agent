#[allow(dead_code)]
#[path = "support/sidecar.rs"]
mod support;

use std::collections::VecDeque;
use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Seek, Write};
use std::path::PathBuf;
use std::process::{self, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use carl::cli::{AcpEffort, BaselineCodexArgs, ExitClassification, run_baseline_codex_with_input};
use carl::delegates::codex::{
    CodexEventNormalizer, CodexExecAdapter, CodexExecRequest, CodexProtocolErrorCode,
    DelegateActivityKind, DelegateErrorCode, DelegateEvent, DelegateItemPhase, DelegateTerminal,
    DelegateUsage, DirectBaselineClock, DirectBaselineDeadline, DirectBaselineErrorCode,
    DirectBaselineProvider, DirectCodexBaseline, DirectCodexBaselineRequest,
    DirectCodexBaselineResult,
};
use carl::delegates::{
    BoundedDelegateTask, DelegateSettings, DelegateSettingsLayers, ModelId, ReasoningEffort,
};
use carl::sidecar::{
    ExecutableTrustDecision, ExecutionWorkspace, JsonlEventProcess, JsonlProcessOutcome,
    ProviderEnvironmentProfile, ProviderHome, SidecarCommand, SidecarErrorCode,
    VersionOutputFormat,
};
use libtest_mimic::{Arguments, Failed, Trial};
use semver::VersionReq;
use serde_json::json;
use support::{
    SECRET_SENTINEL, TestLayout, short_limits, wait_for_fixture_pids, wait_until_processes_exit,
    wait_until_processes_reaped,
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

const EXEC_FIXTURE_ARGUMENT: &str = "--carl-private-codex-exec-fixture";
const EXEC_FIXTURE_VERSION: &str = "1.2.3";
static CLI_ENVIRONMENT: Mutex<()> = Mutex::new(());

struct FixtureBaselineClock {
    instants: Mutex<VecDeque<Instant>>,
}

impl FixtureBaselineClock {
    fn new(instants: impl IntoIterator<Item = Instant>) -> Self {
        Self {
            instants: Mutex::new(instants.into_iter().collect()),
        }
    }
}

impl DirectBaselineClock for FixtureBaselineClock {
    fn now(&self) -> Instant {
        self.instants
            .lock()
            .expect("fixture clock lock is available")
            .pop_front()
            .expect("fixture clock has an instant")
    }
}

struct FixtureBaselineDeadline {
    permits: Arc<Semaphore>,
    observed: Mutex<Vec<Duration>>,
}

impl FixtureBaselineDeadline {
    fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(0)),
            observed: Mutex::new(Vec::new()),
        }
    }

    fn fire(&self) {
        self.permits.add_permits(1);
    }

    fn fire_twice(&self) {
        self.permits.add_permits(2);
    }
}

impl DirectBaselineDeadline for FixtureBaselineDeadline {
    fn wait(
        &self,
        timeout: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        self.observed
            .lock()
            .expect("deadline observation lock is available")
            .push(timeout);
        let permits = Arc::clone(&self.permits);
        Box::pin(async move {
            permits
                .acquire_owned()
                .await
                .expect("fixture deadline semaphore stays open")
                .forget();
        })
    }
}

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if let Some(exit_code) = dispatch_exec_fixture(&arguments) {
        process::exit(exit_code);
    }

    // SAFETY: this runs before libtest-mimic starts test threads and exists to prove
    // the worker's env_clear boundary.
    unsafe {
        env::set_var("OPENAI_API_KEY", SECRET_SENTINEL);
        env::set_var("CODEX_API_KEY", SECRET_SENTINEL);
        env::set_var("AZURE_OPENAI_API_KEY", SECRET_SENTINEL);
        env::set_var("BUZZ_SECRET_SENTINEL", SECRET_SENTINEL);
        env::set_var("XAI_SECRET_SENTINEL", SECRET_SENTINEL);
    }

    let trials = vec![
        test(
            "normalization accepts the documented successful lifecycle",
            normalization_accepts_the_documented_successful_lifecycle,
        ),
        test(
            "normalization rejects lifecycle events out of order",
            normalization_rejects_lifecycle_events_out_of_order,
        ),
        test(
            "normalization rejects a second terminal event",
            normalization_rejects_a_second_terminal_event,
        ),
        test(
            "normalization validates required lifecycle fields",
            normalization_validates_required_lifecycle_fields,
        ),
        test(
            "normalization never retains reasoning text",
            normalization_never_retains_reasoning_text,
        ),
        test(
            "normalization preserves bounded activity status",
            normalization_preserves_bounded_activity_status,
        ),
        test(
            "normalization records unknown event types without raw payloads",
            normalization_records_unknown_event_types_without_raw_payloads,
        ),
        test(
            "normalization rejects oversized provider text",
            normalization_rejects_oversized_provider_text,
        ),
        test(
            "process streams ordered JSON and closes stdin",
            process_streams_ordered_json_and_closes_stdin,
        ),
        test(
            "process reports nonzero exit without provider stderr",
            process_reports_nonzero_exit_without_provider_stderr,
        ),
        test(
            "process rejects malformed JSON",
            process_rejects_malformed_json,
        ),
        test(
            "process bounds and redacts stderr",
            process_bounds_and_redacts_stderr,
        ),
        test(
            "process cancellation is terminal",
            process_cancellation_is_terminal,
        ),
        test(
            "process rejects oversized JSONL",
            process_rejects_oversized_jsonl,
        ),
        test(
            "process rejects a mismatched workspace",
            process_rejects_a_mismatched_workspace,
        ),
        test(
            "process cancellation terminates descendants",
            process_cancellation_terminates_descendants,
        ),
        test(
            "adapter composes a private subscription-backed Codex run",
            adapter_composes_a_private_subscription_backed_codex_run,
        ),
        test(
            "adapter omits unset model overrides",
            adapter_omits_unset_model_overrides,
        ),
        test(
            "adapter rejects a non-Codex provider home",
            adapter_rejects_a_non_codex_provider_home,
        ),
        test(
            "adapter rejects an incompatible version before task input",
            adapter_rejects_an_incompatible_version_before_task_input,
        ),
        test(
            "adapter requires exactly one terminal event",
            adapter_requires_exactly_one_terminal_event,
        ),
        test(
            "adapter maps authentication failures",
            adapter_maps_authentication_failures,
        ),
        test(
            "adapter maps worker and protocol failures",
            adapter_maps_worker_and_protocol_failures,
        ),
        test(
            "adapter cancellation is stable and redacted",
            adapter_cancellation_is_stable_and_redacted,
        ),
        test(
            "direct baseline result is strict bounded and sanitized",
            direct_baseline_result_is_strict_bounded_and_sanitized,
        ),
        test(
            "direct baseline counts only completed bounded activity",
            direct_baseline_counts_only_completed_bounded_activity,
        ),
        test(
            "direct baseline validates timeout before provider spawn",
            direct_baseline_validates_timeout_before_provider_spawn,
        ),
        test(
            "direct baseline maps closed provider failures without partial success",
            direct_baseline_maps_closed_provider_failures_without_partial_success,
        ),
        test(
            "direct baseline rejects executable replacement after completion",
            direct_baseline_rejects_executable_replacement_after_completion,
        ),
        test(
            "direct baseline rejects same-inode mutation before task spawn",
            direct_baseline_rejects_same_inode_mutation_before_task_spawn,
        ),
        test(
            "direct baseline cancellation reaps descendants",
            direct_baseline_cancellation_reaps_descendants,
        ),
        test(
            "direct baseline timeout reaps descendants without partial success",
            direct_baseline_timeout_reaps_descendants_without_partial_success,
        ),
        test(
            "direct baseline timeout bounds start cleanup and reaps version descendants",
            direct_baseline_timeout_bounds_start_cleanup_and_reaps_version_descendants,
        ),
        test(
            "direct baseline CLI emits one sanitized JSON line",
            direct_baseline_cli_emits_one_sanitized_json_line,
        ),
        test(
            "direct baseline CLI rejects invalid task bytes before provider input",
            direct_baseline_cli_rejects_invalid_task_bytes_before_provider_input,
        ),
    ];
    libtest_mimic::run(&Arguments::from_iter(env::args_os().skip(1)), trials).exit();
}

fn test(name: &'static str, body: fn() -> TestResult) -> Trial {
    Trial::test(name, move || {
        body().map_err(|error| Failed::from(error.to_string()))
    })
}

fn normalization_accepts_the_documented_successful_lifecycle() -> TestResult {
    let input = [
        json!({
            "type": "thread.started",
            "thread_id": "0199a213-81c0-7800-8aa1-bbab2a035a53"
        }),
        json!({"type": "turn.started"}),
        json!({
            "type": "item.completed",
            "item": {
                "id": "item_1",
                "type": "agent_message",
                "text": "Fixed it."
            }
        }),
        json!({
            "type": "turn.completed",
            "usage": {
                "input_tokens": 120,
                "cached_input_tokens": 100,
                "output_tokens": 30
            }
        }),
    ];

    let mut normalizer = CodexEventNormalizer::new();
    let output = input
        .into_iter()
        .map(|value| normalizer.ingest(value))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();

    assert_eq!(
        output,
        vec![
            DelegateEvent::ThreadStarted {
                thread_id: "0199a213-81c0-7800-8aa1-bbab2a035a53".into(),
            },
            DelegateEvent::TurnStarted,
            DelegateEvent::AgentMessage {
                text: "Fixed it.".into(),
            },
            DelegateEvent::Terminal(DelegateTerminal::Completed {
                usage: DelegateUsage {
                    input_tokens: 120,
                    cached_input_tokens: 100,
                    output_tokens: 30,
                },
            }),
        ]
    );
    Ok(())
}

fn normalization_rejects_lifecycle_events_out_of_order() -> TestResult {
    let mut normalizer = CodexEventNormalizer::new();
    let error = normalizer
        .ingest(json!({"type": "turn.started"}))
        .expect_err("turn cannot start before its thread");

    assert_eq!(error.code(), CodexProtocolErrorCode::InvalidLifecycle);
    Ok(())
}

fn normalization_rejects_a_second_terminal_event() -> TestResult {
    let mut normalizer = started_normalizer()?;
    normalizer.ingest(completed_event())?;
    let error = normalizer
        .ingest(completed_event())
        .expect_err("a second terminal must fail");

    assert_eq!(error.code(), CodexProtocolErrorCode::InvalidLifecycle);
    Ok(())
}

fn normalization_validates_required_lifecycle_fields() -> TestResult {
    let mut normalizer = CodexEventNormalizer::new();
    let missing = normalizer
        .ingest(json!({"type": "thread.started"}))
        .expect_err("thread id is required");
    assert_eq!(missing.code(), CodexProtocolErrorCode::InvalidEvent);

    let mut normalizer = CodexEventNormalizer::new();
    let wrong_type = normalizer
        .ingest(json!({"type": "thread.started", "thread_id": 7}))
        .expect_err("thread id must be a string");
    assert_eq!(wrong_type.code(), CodexProtocolErrorCode::InvalidEvent);
    Ok(())
}

fn normalization_never_retains_reasoning_text() -> TestResult {
    let mut normalizer = started_normalizer()?;
    let event = normalizer
        .ingest(json!({
            "type": "item.completed",
            "item": {
                "id": "item_reasoning",
                "type": "reasoning",
                "text": "SECRET_REASONING_SENTINEL"
            }
        }))?
        .expect("reasoning produces metadata");

    assert_eq!(
        event,
        DelegateEvent::Activity {
            item_id: "item_reasoning".into(),
            kind: DelegateActivityKind::Reasoning,
            phase: DelegateItemPhase::Completed,
        }
    );
    assert!(!format!("{event:?}").contains("SECRET_REASONING_SENTINEL"));
    Ok(())
}

fn normalization_preserves_bounded_activity_status() -> TestResult {
    let mut normalizer = started_normalizer()?;
    let event = normalizer
        .ingest(json!({
            "type": "item.started",
            "item": {
                "id": "item_command",
                "type": "command_execution",
                "command": "cargo test",
                "status": "in_progress"
            }
        }))?
        .expect("command activity is visible");

    assert_eq!(
        event,
        DelegateEvent::Activity {
            item_id: "item_command".into(),
            kind: DelegateActivityKind::CommandExecution,
            phase: DelegateItemPhase::Started,
        }
    );
    Ok(())
}

fn normalization_records_unknown_event_types_without_raw_payloads() -> TestResult {
    let mut normalizer = CodexEventNormalizer::new();
    let event = normalizer
        .ingest(json!({
            "type": "future.event",
            "secret": "SECRET_PROVIDER_PAYLOAD"
        }))?
        .expect("unknown event becomes compatibility metadata");

    assert_eq!(
        event,
        DelegateEvent::Compatibility {
            event_type: "future.event".into(),
        }
    );
    assert!(!format!("{event:?}").contains("SECRET_PROVIDER_PAYLOAD"));
    Ok(())
}

fn normalization_rejects_oversized_provider_text() -> TestResult {
    let mut normalizer = started_normalizer()?;
    let error = normalizer
        .ingest(json!({
            "type": "item.completed",
            "item": {
                "id": "item_message",
                "type": "agent_message",
                "text": "x".repeat(32_769)
            }
        }))
        .expect_err("oversized text must fail");

    assert_eq!(error.code(), CodexProtocolErrorCode::LimitExceeded);
    Ok(())
}

fn started_normalizer() -> Result<CodexEventNormalizer, Box<dyn Error + Send + Sync>> {
    let mut normalizer = CodexEventNormalizer::new();
    normalizer.ingest(json!({
        "type": "thread.started",
        "thread_id": "0199a213-81c0-7800-8aa1-bbab2a035a53"
    }))?;
    normalizer.ingest(json!({"type": "turn.started"}))?;
    Ok(normalizer)
}

fn completed_event() -> serde_json::Value {
    json!({
        "type": "turn.completed",
        "usage": {
            "input_tokens": 1,
            "cached_input_tokens": 0,
            "output_tokens": 1
        }
    })
}

fn process_streams_ordered_json_and_closes_stdin() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let (specification, trusted, home, workspace) = execution_fixture(&layout, "success")?;
        let mut process = JsonlEventProcess::spawn_in_home(
            specification,
            &trusted,
            &home,
            &workspace,
            b"private task bytes",
            short_limits(),
        )
        .await?;

        let received = process
            .next_event()
            .await?
            .ok_or("fixture did not report received input")?;
        assert_eq!(received["type"], "fixture.received");
        assert_eq!(received["stdin"], "private task bytes");
        assert_eq!(received["openai_api_key"], serde_json::Value::Null);
        assert_eq!(received["codex_api_key"], serde_json::Value::Null);
        assert_eq!(
            PathBuf::from(received["cwd"].as_str().ok_or("cwd is not a string")?).canonicalize()?,
            layout.workspace.canonicalize()?
        );
        assert_eq!(
            process.next_event().await?,
            Some(json!({"type": "fixture.completed"}))
        );
        assert_eq!(process.next_event().await?, None);
        assert_eq!(process.wait().await?, JsonlProcessOutcome::Succeeded);
        Ok(())
    })
}

fn process_reports_nonzero_exit_without_provider_stderr() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let (specification, trusted, home, workspace) = execution_fixture(&layout, "nonzero")?;
        let mut process = JsonlEventProcess::spawn_in_home(
            specification,
            &trusted,
            &home,
            &workspace,
            b"task",
            short_limits(),
        )
        .await?;

        assert_eq!(process.next_event().await?, None);
        assert_eq!(process.wait().await?, JsonlProcessOutcome::Failed);
        assert_eq!(process.stderr_snapshot(), "");
        Ok(())
    })
}

fn process_rejects_malformed_json() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let (specification, trusted, home, workspace) = execution_fixture(&layout, "malformed")?;
        let mut process = JsonlEventProcess::spawn_in_home(
            specification,
            &trusted,
            &home,
            &workspace,
            b"task",
            short_limits(),
        )
        .await?;

        let error = process
            .next_event()
            .await
            .expect_err("malformed JSON must fail");
        assert_eq!(error.code(), SidecarErrorCode::ProtocolViolation);
        assert_eq!(process.wait().await?, JsonlProcessOutcome::ProtocolFailed);
        Ok(())
    })
}

fn process_bounds_and_redacts_stderr() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let (specification, trusted, home, workspace) = execution_fixture(&layout, "stderr")?;
        let mut process = JsonlEventProcess::spawn_in_home(
            specification,
            &trusted,
            &home,
            &workspace,
            b"task",
            short_limits(),
        )
        .await?;

        assert_eq!(
            process.next_event().await?,
            Some(json!({"type": "fixture.completed"}))
        );
        assert_eq!(process.next_event().await?, None);
        assert_eq!(process.wait().await?, JsonlProcessOutcome::Succeeded);
        assert_eq!(process.stderr_snapshot(), "<redacted sidecar stderr>");
        assert!(!process.stderr_snapshot().contains(SECRET_SENTINEL));
        Ok(())
    })
}

fn process_cancellation_is_terminal() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let (specification, trusted, home, workspace) = execution_fixture(&layout, "hanging")?;
        let mut process = JsonlEventProcess::spawn_in_home(
            specification,
            &trusted,
            &home,
            &workspace,
            b"task",
            short_limits(),
        )
        .await?;

        process.cancel().await?;
        assert_eq!(process.wait().await?, JsonlProcessOutcome::Cancelled);
        assert_eq!(process.next_event().await?, None);
        Ok(())
    })
}

fn process_rejects_oversized_jsonl() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let (specification, trusted, home, workspace) = execution_fixture(&layout, "oversized")?;
        let mut process = JsonlEventProcess::spawn_in_home(
            specification,
            &trusted,
            &home,
            &workspace,
            b"task",
            short_limits(),
        )
        .await?;

        let error = process
            .next_event()
            .await
            .expect_err("oversized JSONL must fail");
        assert_eq!(error.code(), SidecarErrorCode::ProtocolViolation);
        assert_eq!(process.wait().await?, JsonlProcessOutcome::ProtocolFailed);
        Ok(())
    })
}

fn process_rejects_a_mismatched_workspace() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let (specification, trusted, home, _) = execution_fixture(&layout, "success")?;
        let other_workspace = layout.workspace.join("other");
        fs::create_dir(&other_workspace)?;
        let workspace = ExecutionWorkspace::open(&other_workspace)?;

        let error = JsonlEventProcess::spawn_in_home(
            specification,
            &trusted,
            &home,
            &workspace,
            b"task",
            short_limits(),
        )
        .await
        .expect_err("the execution workspace must match the isolated provider home");
        assert_eq!(error.code(), SidecarErrorCode::InvalidConfiguration);
        Ok(())
    })
}

fn process_cancellation_terminates_descendants() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let (specification, trusted, home, workspace) =
            execution_fixture(&layout, "hanging-child")?;
        let mut process = JsonlEventProcess::spawn_in_home(
            specification,
            &trusted,
            &home,
            &workspace,
            b"task",
            short_limits(),
        )
        .await?;
        let (leader, grandchild) = wait_for_fixture_pids(&layout.home).await?;

        process.cancel().await?;
        assert_eq!(process.wait().await?, JsonlProcessOutcome::Cancelled);
        wait_until_processes_exit(&[leader, grandchild]).await?;
        wait_until_processes_reaped(&[leader]).await?;
        Ok(())
    })
}

fn adapter_composes_a_private_subscription_backed_codex_run() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
        let session = DelegateSettings::new(
            Some(ModelId::parse("gpt-5.6")?),
            Some(ReasoningEffort::High),
        );
        let per_run = DelegateSettings::new(
            Some(ModelId::parse("gpt-5.6-terra")?),
            Some(ReasoningEffort::Low),
        );
        let settings = DelegateSettingsLayers {
            personal: None,
            project: None,
            session: Some(&session),
            per_run: Some(&per_run),
        }
        .resolve();
        let workspace = ExecutionWorkspace::open(&layout.workspace)?;
        let task = "Fix the private sentinel regression";
        let request = CodexExecRequest {
            task: BoundedDelegateTask::parse(task)?,
            settings,
        };
        assert!(!format!("{request:?}").contains(task));
        let mut run = adapter.start(&workspace, request).await?;

        let mut events = Vec::new();
        while let Some(event) = run.next_event().await? {
            events.push(event);
        }
        let usage = run.finish().await?;
        assert_eq!(usage.output_tokens, 3);
        assert!(events.iter().any(|event| matches!(
            event,
            DelegateEvent::AgentMessage { text } if text == "Fixture completed."
        )));

        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(layout.home.join("exec-record.json"))?)?;
        let arguments = record["arguments"]
            .as_array()
            .ok_or("fixture arguments are not an array")?;
        assert_eq!(
            arguments,
            &[
                json!("--strict-config"),
                json!("--model"),
                json!("gpt-5.6-terra"),
                json!("-c"),
                json!("model_reasoning_effort=\"low\""),
                json!("--ask-for-approval"),
                json!("never"),
                json!("exec"),
                json!("--json"),
                json!("--ephemeral"),
                json!("--sandbox"),
                json!("workspace-write"),
                json!("--skip-git-repo-check"),
                json!("-"),
            ]
        );
        assert!(
            arguments
                .iter()
                .all(|argument| argument.as_str() != Some(task))
        );
        assert!(
            record["stdin"]
                .as_str()
                .is_some_and(|stdin| stdin.contains(task))
        );
        assert_eq!(record["openai_api_key"], serde_json::Value::Null);
        assert_eq!(record["codex_api_key"], serde_json::Value::Null);
        assert_eq!(
            fs::read_to_string(layout.home.join("config.toml"))?,
            concat!(
                "cli_auth_credentials_store = \"file\"\n",
                "approval_policy = \"never\"\n",
                "sandbox_mode = \"workspace-write\"\n",
                "\n",
                "[sandbox_workspace_write]\n",
                "network_access = false\n",
            )
        );
        assert!(!format!("{adapter:?}").contains(layout.home.to_string_lossy().as_ref()));
        Ok(())
    })
}

fn adapter_omits_unset_model_overrides() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
        let workspace = ExecutionWorkspace::open(&layout.workspace)?;
        let mut run = adapter
            .start(
                &workspace,
                CodexExecRequest {
                    task: BoundedDelegateTask::parse("Run with provider defaults")?,
                    settings: DelegateSettingsLayers::default().resolve(),
                },
            )
            .await?;
        while run.next_event().await?.is_some() {}
        run.finish().await?;

        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(layout.home.join("exec-record.json"))?)?;
        let arguments = record["arguments"]
            .as_array()
            .ok_or("fixture arguments are not an array")?;
        assert!(!arguments.iter().any(|argument| argument == "--model"));
        assert!(!arguments.iter().any(|argument| {
            argument
                .as_str()
                .is_some_and(|value| value.starts_with("model_reasoning_effort="))
        }));
        Ok(())
    })
}

fn adapter_rejects_a_non_codex_provider_home() -> TestResult {
    let layout = TestLayout::new()?;
    let specification = SidecarCommand {
        executable: env::current_exe()?,
        arguments: Vec::new(),
        version_arguments: Vec::new(),
        version_output: VersionOutputFormat::SingleSemverToken,
        isolated_home: layout.home.clone(),
        supported_versions: VersionReq::parse("=0.146.0")?,
    };
    let trusted = specification
        .resolve_executable()?
        .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
    let home = ProviderHome::prepare(
        ProviderEnvironmentProfile::Grok,
        &layout.data,
        &layout.workspace,
        &layout.home,
    )?;
    let error = CodexExecAdapter::new(trusted, home, short_limits())
        .expect_err("a Grok provider home must be rejected");
    assert_eq!(error.code(), DelegateErrorCode::Configuration);
    Ok(())
}

fn adapter_rejects_an_incompatible_version_before_task_input() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        fs::write(layout.data.join("fixture-version"), b"0.135.0")?;
        let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
        let workspace = ExecutionWorkspace::open(&layout.workspace)?;
        let error = adapter
            .start(
                &workspace,
                CodexExecRequest {
                    task: BoundedDelegateTask::parse("This must not be sent")?,
                    settings: DelegateSettingsLayers::default().resolve(),
                },
            )
            .await
            .expect_err("an incompatible Codex CLI must fail");
        assert_eq!(error.code(), DelegateErrorCode::Incompatible);
        assert!(!layout.home.join("exec-record.json").exists());
        Ok(())
    })
}

fn adapter_requires_exactly_one_terminal_event() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        fs::write(
            layout.workspace.join(".fixture-scenario"),
            b"missing-terminal",
        )?;
        let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
        let workspace = ExecutionWorkspace::open(&layout.workspace)?;
        let mut run = adapter
            .start(
                &workspace,
                CodexExecRequest {
                    task: BoundedDelegateTask::parse("Exercise the protocol")?,
                    settings: DelegateSettingsLayers::default().resolve(),
                },
            )
            .await?;
        while run.next_event().await?.is_some() {}
        let error = run
            .finish()
            .await
            .expect_err("a missing terminal event must fail");
        assert_eq!(error.code(), DelegateErrorCode::ProtocolFailed);
        Ok(())
    })
}

fn adapter_maps_authentication_failures() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        fs::write(layout.workspace.join(".fixture-scenario"), b"auth-failure")?;
        let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
        let workspace = ExecutionWorkspace::open(&layout.workspace)?;
        let mut run = adapter
            .start(
                &workspace,
                CodexExecRequest {
                    task: BoundedDelegateTask::parse("Exercise auth mapping")?,
                    settings: DelegateSettingsLayers::default().resolve(),
                },
            )
            .await?;
        while run.next_event().await?.is_some() {}
        let error = run
            .finish()
            .await
            .expect_err("the fixture reports missing authentication");
        assert_eq!(error.code(), DelegateErrorCode::AuthenticationRequired);
        Ok(())
    })
}

fn adapter_maps_worker_and_protocol_failures() -> TestResult {
    run_async(async {
        for (scenario, expected) in [
            ("nonzero", DelegateErrorCode::ProviderFailed),
            ("malformed", DelegateErrorCode::ProtocolFailed),
            ("oversized", DelegateErrorCode::ProtocolFailed),
        ] {
            let layout = TestLayout::new()?;
            fs::write(layout.workspace.join(".fixture-scenario"), scenario)?;
            let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
            let workspace = ExecutionWorkspace::open(&layout.workspace)?;
            let run = adapter
                .start(
                    &workspace,
                    CodexExecRequest {
                        task: BoundedDelegateTask::parse("Exercise failure mapping")?,
                        settings: DelegateSettingsLayers::default().resolve(),
                    },
                )
                .await?;
            let error = run.finish().await.expect_err("the fixture must fail");
            assert_eq!(error.code(), expected, "scenario: {scenario}");
        }
        Ok(())
    })
}

fn adapter_cancellation_is_stable_and_redacted() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        fs::write(layout.workspace.join(".fixture-scenario"), b"hanging")?;
        let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
        let workspace = ExecutionWorkspace::open(&layout.workspace)?;
        let task = "private cancellation task";
        let mut run = adapter
            .start(
                &workspace,
                CodexExecRequest {
                    task: BoundedDelegateTask::parse(task)?,
                    settings: DelegateSettingsLayers::default().resolve(),
                },
            )
            .await?;
        assert!(!format!("{run:?}").contains(task));
        assert!(!format!("{run:?}").contains(layout.workspace.to_string_lossy().as_ref()));

        run.cancel().await?;
        let error = run
            .finish()
            .await
            .expect_err("a cancelled run must stay cancelled");
        assert_eq!(error.code(), DelegateErrorCode::Cancelled);
        assert!(!format!("{error:?}").contains(task));
        Ok(())
    })
}

fn direct_baseline_result_is_strict_bounded_and_sanitized() -> TestResult {
    let value = json!({
        "schema_version": 1,
        "provider": "codex",
        "codex_version": "0.146.0",
        "model": "gpt-5.6-terra",
        "effort": "low",
        "completed": true,
        "elapsed_milliseconds": 25,
        "input_tokens": 10,
        "cached_input_tokens": 2,
        "output_tokens": 3,
        "command_executions": 1,
        "file_changes": 1,
        "mcp_tool_calls": 1,
        "web_searches": 1,
        "compatibility_events": 2
    });
    let result: DirectCodexBaselineResult = serde_json::from_value(value.clone())?;
    assert_eq!(result.schema_version, 1);
    assert_eq!(result.provider, DirectBaselineProvider::Codex);
    assert_eq!(result.codex_version, "0.146.0");
    let encoded = serde_json::to_vec(&result)?;
    assert!(encoded.len() < 4 * 1_024);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encoded)?,
        value
    );

    for (field, invalid) in [
        ("schema_version", json!(2)),
        ("provider", json!("other")),
        ("codex_version", json!("0.145.0")),
    ] {
        let mut invalid_value = value.clone();
        invalid_value[field] = invalid;
        assert!(serde_json::from_value::<DirectCodexBaselineResult>(invalid_value).is_err());
    }
    let mut unknown = value;
    unknown["agent_text"] = json!("SECRET_AGENT_TEXT_SENTINEL");
    assert!(serde_json::from_value::<DirectCodexBaselineResult>(unknown).is_err());
    let mut invalid_result = result.clone();
    invalid_result.schema_version = 2;
    assert!(serde_json::to_vec(&invalid_result).is_err());
    invalid_result.schema_version = 1;
    invalid_result.codex_version = "0.145.0".to_owned();
    assert!(serde_json::to_vec(&invalid_result).is_err());
    assert!(!format!("{result:?}").contains("SECRET_AGENT_TEXT_SENTINEL"));
    Ok(())
}

fn direct_baseline_counts_only_completed_bounded_activity() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        fs::write(
            layout.workspace.join(".fixture-scenario"),
            b"baseline-success",
        )?;
        let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
        let start = Instant::now();
        let baseline = DirectCodexBaseline::with_clock(
            adapter,
            Arc::new(FixtureBaselineClock::new([
                start,
                start + Duration::from_millis(1_234),
            ])),
        );
        let workspace = ExecutionWorkspace::open(&layout.workspace)?;
        let task = "SECRET_DIRECT_BASELINE_TASK_SENTINEL";
        let request = DirectCodexBaselineRequest {
            workspace,
            task: BoundedDelegateTask::parse(task)?,
            model: ModelId::parse("gpt-5.6-terra")?,
            effort: ReasoningEffort::Low,
            timeout: Duration::from_secs(60),
        };
        assert!(!format!("{request:?}").contains(task));

        let result = baseline.run(request, CancellationToken::new()).await?;
        assert_eq!(
            result,
            DirectCodexBaselineResult {
                schema_version: 1,
                provider: DirectBaselineProvider::Codex,
                codex_version: "0.146.0".to_owned(),
                model: ModelId::parse("gpt-5.6-terra")?,
                effort: ReasoningEffort::Low,
                completed: true,
                elapsed_milliseconds: 1_234,
                input_tokens: 120,
                cached_input_tokens: 100,
                output_tokens: 30,
                command_executions: 1,
                file_changes: 1,
                mcp_tool_calls: 1,
                web_searches: 1,
                compatibility_events: 2,
            }
        );
        assert_eq!(result.elapsed_milliseconds, 1_234);
        let rendered = serde_json::to_string(&result)?;
        for forbidden in [
            task,
            "SECRET_AGENT_TEXT_SENTINEL",
            layout.workspace.to_string_lossy().as_ref(),
            "cargo test --secret",
        ] {
            assert!(!rendered.contains(forbidden));
            assert!(!format!("{result:?}").contains(forbidden));
        }

        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(layout.home.join("exec-record.json"))?)?;
        assert_eq!(record["openai_api_key"], serde_json::Value::Null);
        assert_eq!(record["codex_api_key"], serde_json::Value::Null);
        assert_eq!(record["azure_openai_api_key"], serde_json::Value::Null);
        assert_eq!(record["buzz_secret"], serde_json::Value::Null);
        assert_eq!(record["xai_secret"], serde_json::Value::Null);
        let arguments = record["arguments"].as_array().ok_or("missing arguments")?;
        assert_eq!(
            arguments,
            &[
                json!("--strict-config"),
                json!("--model"),
                json!("gpt-5.6-terra"),
                json!("-c"),
                json!("model_reasoning_effort=\"low\""),
                json!("--ask-for-approval"),
                json!("never"),
                json!("exec"),
                json!("--json"),
                json!("--ephemeral"),
                json!("--sandbox"),
                json!("workspace-write"),
                json!("--skip-git-repo-check"),
                json!("-"),
            ]
        );
        assert!(arguments.iter().all(|argument| argument != task));
        assert!(
            record["stdin"]
                .as_str()
                .is_some_and(|stdin| stdin.contains(task))
        );
        Ok(())
    })
}

fn direct_baseline_validates_timeout_before_provider_spawn() -> TestResult {
    run_async(async {
        for timeout in [Duration::from_secs(59), Duration::from_secs(28_801)] {
            let layout = TestLayout::new()?;
            let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
            let baseline = DirectCodexBaseline::new(adapter);
            let error = baseline
                .run(
                    DirectCodexBaselineRequest {
                        workspace: ExecutionWorkspace::open(&layout.workspace)?,
                        task: BoundedDelegateTask::parse("bounded task")?,
                        model: ModelId::parse("gpt-5.6-terra")?,
                        effort: ReasoningEffort::Low,
                        timeout,
                    },
                    CancellationToken::new(),
                )
                .await
                .expect_err("out-of-range timeout must fail");
            assert_eq!(error.code(), DirectBaselineErrorCode::InvalidRequest);
            assert!(!layout.home.join("exec-record.json").exists());
        }
        let layout = TestLayout::new()?;
        let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
        let baseline = DirectCodexBaseline::new(adapter);
        let error = baseline
            .run(
                DirectCodexBaselineRequest {
                    workspace: ExecutionWorkspace::open(&layout.workspace)?,
                    task: BoundedDelegateTask::parse("x".repeat(16 * 1_024 + 1))?,
                    model: ModelId::parse("gpt-5.6-terra")?,
                    effort: ReasoningEffort::Low,
                    timeout: Duration::from_secs(60),
                },
                CancellationToken::new(),
            )
            .await
            .expect_err("oversized direct task must fail before spawn");
        assert_eq!(error.code(), DirectBaselineErrorCode::InvalidRequest);
        assert!(!layout.home.join("exec-record.json").exists());
        Ok(())
    })
}

fn direct_baseline_maps_closed_provider_failures_without_partial_success() -> TestResult {
    run_async(async {
        for (scenario, expected) in [
            ("missing-terminal", DirectBaselineErrorCode::ProtocolFailed),
            (
                "duplicate-terminal",
                DirectBaselineErrorCode::ProtocolFailed,
            ),
            ("malformed", DirectBaselineErrorCode::ProtocolFailed),
            ("oversized", DirectBaselineErrorCode::ProtocolFailed),
            (
                "auth-failure",
                DirectBaselineErrorCode::AuthenticationRequired,
            ),
            ("nonzero", DirectBaselineErrorCode::ProviderFailed),
        ] {
            let layout = TestLayout::new()?;
            fs::write(layout.workspace.join(".fixture-scenario"), scenario)?;
            let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
            let baseline = DirectCodexBaseline::new(adapter);
            let error = baseline
                .run(
                    DirectCodexBaselineRequest {
                        workspace: ExecutionWorkspace::open(&layout.workspace)?,
                        task: BoundedDelegateTask::parse("exercise closed failure mapping")?,
                        model: ModelId::parse("gpt-5.6-terra")?,
                        effort: ReasoningEffort::Low,
                        timeout: Duration::from_secs(60),
                    },
                    CancellationToken::new(),
                )
                .await
                .expect_err("provider failure must not produce partial success");
            assert_eq!(error.code(), expected, "scenario: {scenario}");
            assert!(!format!("{error:?}").contains("exercise closed failure mapping"));
        }
        Ok(())
    })
}

fn direct_baseline_rejects_executable_replacement_after_completion() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        fs::write(
            layout.workspace.join(".fixture-scenario"),
            b"replace-executable",
        )?;
        let copied_executable = layout.data.join("codex-fixture-copy");
        fs::copy(env::current_exe()?, &copied_executable)?;
        let specification = SidecarCommand {
            executable: copied_executable,
            arguments: Vec::new(),
            version_arguments: Vec::new(),
            version_output: VersionOutputFormat::SingleSemverToken,
            isolated_home: layout.home.clone(),
            supported_versions: VersionReq::parse("=0.146.0")?,
        };
        let trusted = specification
            .resolve_executable()?
            .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
        let home = ProviderHome::prepare(
            ProviderEnvironmentProfile::Codex,
            &layout.data,
            &layout.workspace,
            &layout.home,
        )?;
        home.write_static_file("auth.json", b"fixture subscription auth")?;
        let baseline =
            DirectCodexBaseline::new(CodexExecAdapter::new(trusted, home, short_limits())?);
        let error = baseline
            .run(
                DirectCodexBaselineRequest {
                    workspace: ExecutionWorkspace::open(&layout.workspace)?,
                    task: BoundedDelegateTask::parse("replace after terminal")?,
                    model: ModelId::parse("gpt-5.6-terra")?,
                    effort: ReasoningEffort::Low,
                    timeout: Duration::from_secs(60),
                },
                CancellationToken::new(),
            )
            .await
            .expect_err("post-completion executable replacement must fail closed");
        assert_eq!(error.code(), DirectBaselineErrorCode::Incompatible);
        Ok(())
    })
}

fn direct_baseline_rejects_same_inode_mutation_before_task_spawn() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        fs::write(layout.data.join("fixture-mutate-after-version"), b"mutate")?;
        let copied_executable = layout.data.join("codex-fixture-mutation-copy");
        fs::copy(env::current_exe()?, &copied_executable)?;
        let specification = SidecarCommand {
            executable: copied_executable,
            arguments: Vec::new(),
            version_arguments: Vec::new(),
            version_output: VersionOutputFormat::SingleSemverToken,
            isolated_home: layout.home.clone(),
            supported_versions: VersionReq::parse("=0.146.0")?,
        };
        let trusted = specification
            .resolve_executable()?
            .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
        let home = ProviderHome::prepare(
            ProviderEnvironmentProfile::Codex,
            &layout.data,
            &layout.workspace,
            &layout.home,
        )?;
        home.write_static_file("auth.json", b"fixture subscription auth")?;
        let baseline =
            DirectCodexBaseline::new(CodexExecAdapter::new(trusted, home, short_limits())?);
        let error = baseline
            .run(
                DirectCodexBaselineRequest {
                    workspace: ExecutionWorkspace::open(&layout.workspace)?,
                    task: BoundedDelegateTask::parse("must not reach mutated executable")?,
                    model: ModelId::parse("gpt-5.6-terra")?,
                    effort: ReasoningEffort::Low,
                    timeout: Duration::from_secs(60),
                },
                CancellationToken::new(),
            )
            .await
            .expect_err("same-inode mutation before exec spawn must fail closed");
        assert_eq!(error.code(), DirectBaselineErrorCode::Incompatible);
        assert!(!layout.home.join("exec-record.json").exists());
        Ok(())
    })
}

fn direct_baseline_cancellation_reaps_descendants() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        fs::write(layout.workspace.join(".fixture-scenario"), b"hanging-child")?;
        let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
        let baseline = DirectCodexBaseline::new(adapter);
        let cancellation = CancellationToken::new();
        let cancelled = cancellation.clone();
        let run = baseline.run(
            DirectCodexBaselineRequest {
                workspace: ExecutionWorkspace::open(&layout.workspace)?,
                task: BoundedDelegateTask::parse("cancel this direct baseline")?,
                model: ModelId::parse("gpt-5.6-terra")?,
                effort: ReasoningEffort::Low,
                timeout: Duration::from_secs(60),
            },
            cancellation,
        );
        tokio::pin!(run);
        let (leader, grandchild) = tokio::select! {
            pids = wait_for_fixture_pids(&layout.home) => pids?,
            result = &mut run => return Err(format!("baseline ended before cancellation: {result:?}").into()),
        };
        cancelled.cancel();
        let error = run.await.expect_err("cancelled baseline must not succeed");
        assert_eq!(error.code(), DirectBaselineErrorCode::Cancelled);
        wait_until_processes_exit(&[leader, grandchild]).await?;
        wait_until_processes_reaped(&[leader]).await?;
        Ok(())
    })
}

fn direct_baseline_timeout_reaps_descendants_without_partial_success() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        fs::write(layout.workspace.join(".fixture-scenario"), b"hanging-child")?;
        let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
        let start = Instant::now();
        let deadline = Arc::new(FixtureBaselineDeadline::new());
        let baseline = DirectCodexBaseline::with_clock_and_deadline(
            adapter,
            Arc::new(FixtureBaselineClock::new([start])),
            deadline.clone(),
        );
        let run = baseline.run(
            DirectCodexBaselineRequest {
                workspace: ExecutionWorkspace::open(&layout.workspace)?,
                task: BoundedDelegateTask::parse("time out this direct baseline")?,
                model: ModelId::parse("gpt-5.6-terra")?,
                effort: ReasoningEffort::Low,
                timeout: Duration::from_secs(60),
            },
            CancellationToken::new(),
        );
        tokio::pin!(run);
        let (leader, grandchild) = tokio::select! {
            pids = wait_for_fixture_pids(&layout.home) => pids?,
            result = &mut run => return Err(format!("baseline ended before timeout: {result:?}").into()),
        };
        deadline.fire();
        let error = run
            .await
            .expect_err("timed-out baseline must not return partial success");
        assert_eq!(error.code(), DirectBaselineErrorCode::TimedOut);
        assert_eq!(
            deadline
                .observed
                .lock()
                .expect("deadline observation lock is available")
                .as_slice(),
            &[Duration::from_secs(60)]
        );
        wait_until_processes_exit(&[leader, grandchild]).await?;
        wait_until_processes_reaped(&[leader]).await?;
        Ok(())
    })
}

fn direct_baseline_timeout_bounds_start_cleanup_and_reaps_version_descendants() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        fs::write(layout.data.join("fixture-version-hang"), b"hang")?;
        let adapter = codex_adapter_fixture(&layout, ProviderEnvironmentProfile::Codex)?;
        let start = Instant::now();
        let deadline = Arc::new(FixtureBaselineDeadline::new());
        let baseline = DirectCodexBaseline::with_clock_and_deadline(
            adapter,
            Arc::new(FixtureBaselineClock::new([start])),
            deadline.clone(),
        );
        let run = baseline.run(
            DirectCodexBaselineRequest {
                workspace: ExecutionWorkspace::open(&layout.workspace)?,
                task: BoundedDelegateTask::parse("time out during version probe")?,
                model: ModelId::parse("gpt-5.6-terra")?,
                effort: ReasoningEffort::Low,
                timeout: Duration::from_secs(60),
            },
            CancellationToken::new(),
        );
        tokio::pin!(run);
        let (leader, grandchild) = tokio::select! {
            pids = wait_for_fixture_pids(&layout.home) => pids?,
            result = &mut run => return Err(format!("baseline ended before start timeout: {result:?}").into()),
        };
        deadline.fire_twice();
        let error = run
            .await
            .expect_err("start-phase timeout must not return partial success");
        assert_eq!(error.code(), DirectBaselineErrorCode::TimedOut);
        assert_eq!(
            deadline
                .observed
                .lock()
                .expect("deadline observation lock is available")
                .as_slice(),
            &[Duration::from_secs(60), Duration::from_secs(2)]
        );
        wait_until_processes_exit(&[leader, grandchild]).await?;
        wait_until_processes_reaped(&[leader]).await?;
        assert!(!layout.home.join("exec-record.json").exists());
        Ok(())
    })
}

fn direct_baseline_cli_emits_one_sanitized_json_line() -> TestResult {
    let _environment = CLI_ENVIRONMENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_async(async {
        let layout = TestLayout::new()?;
        prepare_cli_baseline_fixture(&layout, true)?;
        fs::write(
            layout.workspace.join(".fixture-scenario"),
            b"baseline-success",
        )?;
        let task = " \nSECRET_CLI_TASK_SENTINEL\n ";
        let result = run_baseline_codex_with_input(
            BaselineCodexArgs {
                workspace: layout.workspace.clone(),
                model: "gpt-5.6-terra".to_owned(),
                effort: AcpEffort::Low,
                timeout_seconds: 60,
            },
            task.as_bytes(),
            CancellationToken::new(),
        )
        .await;
        assert_eq!(
            result.exit_classification(),
            ExitClassification::Success,
            "{}",
            result.stderr()
        );
        assert!(result.stderr().is_empty());
        assert_eq!(result.stdout().lines().count(), 1);
        assert!(result.stdout().ends_with('\n'));
        let output: DirectCodexBaselineResult = serde_json::from_str(result.stdout())?;
        assert!(output.completed);
        for forbidden in [
            task,
            SECRET_SENTINEL,
            "SECRET_AGENT_TEXT_SENTINEL",
            layout.workspace.to_string_lossy().as_ref(),
        ] {
            assert!(!result.stdout().contains(forbidden));
            assert!(!result.stderr().contains(forbidden));
        }
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(cli_codex_home(&layout).join("exec-record.json"))?)?;
        assert!(
            record["stdin"]
                .as_str()
                .is_some_and(|stdin| stdin.contains(task))
        );
        assert!(record["arguments"].as_array().is_some_and(|arguments| {
            arguments
                .iter()
                .all(|argument| argument.as_str() != Some(task))
        }));
        Ok(())
    })
}

fn direct_baseline_cli_rejects_invalid_task_bytes_before_provider_input() -> TestResult {
    let _environment = CLI_ENVIRONMENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    run_async(async {
        for input in [Vec::new(), vec![0xff], vec![b'x'; 16 * 1_024 + 1]] {
            let layout = TestLayout::new()?;
            prepare_cli_baseline_fixture(&layout, true)?;
            let result = run_baseline_codex_with_input(
                BaselineCodexArgs {
                    workspace: layout.workspace.clone(),
                    model: "gpt-5.6-terra".to_owned(),
                    effort: AcpEffort::Low,
                    timeout_seconds: 60,
                },
                &input,
                CancellationToken::new(),
            )
            .await;
            assert_eq!(result.exit_classification(), ExitClassification::Failure);
            assert!(result.stdout().is_empty());
            assert!(!cli_codex_home(&layout).join("exec-record.json").exists());
            assert!(!result.stderr().contains(SECRET_SENTINEL));
            assert!(
                !result
                    .stderr()
                    .contains(layout.workspace.to_string_lossy().as_ref())
            );
        }

        let layout = TestLayout::new()?;
        prepare_cli_baseline_fixture(&layout, true)?;
        let noncanonical_workspace = layout.workspace.join("..").join("workspace");
        let result = run_baseline_codex_with_input(
            BaselineCodexArgs {
                workspace: noncanonical_workspace,
                model: "gpt-5.6-terra".to_owned(),
                effort: AcpEffort::Low,
                timeout_seconds: 60,
            },
            b"valid task bytes",
            CancellationToken::new(),
        )
        .await;
        assert_eq!(result.exit_classification(), ExitClassification::Failure);
        assert!(result.stdout().is_empty());
        assert!(!cli_codex_home(&layout).join("exec-record.json").exists());

        let layout = TestLayout::new()?;
        prepare_cli_baseline_fixture(&layout, false)?;
        let task = b"SECRET_MISSING_AUTH_TASK_SENTINEL";
        let result = run_baseline_codex_with_input(
            BaselineCodexArgs {
                workspace: layout.workspace.clone(),
                model: "gpt-5.6-terra".to_owned(),
                effort: AcpEffort::Low,
                timeout_seconds: 60,
            },
            task,
            CancellationToken::new(),
        )
        .await;
        assert_eq!(result.exit_classification(), ExitClassification::Failure);
        assert!(result.stdout().is_empty());
        assert!(
            !result
                .stderr()
                .contains("SECRET_MISSING_AUTH_TASK_SENTINEL")
        );
        assert!(!cli_codex_home(&layout).join("exec-record.json").exists());
        Ok(())
    })
}

fn prepare_cli_baseline_fixture(layout: &TestLayout, authenticated: bool) -> TestResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(&layout.data, fs::Permissions::from_mode(0o700))?;
    }
    if authenticated {
        let home = ProviderHome::prepare(
            ProviderEnvironmentProfile::Codex,
            &layout.data,
            &layout.workspace,
            cli_codex_home(layout),
        )?;
        home.write_static_file("auth.json", b"fixture subscription auth")?;
    }
    // SAFETY: codex_exec_contract is a single-process, serial libtest-mimic harness.
    unsafe {
        env::set_var("CARL_DATA_DIR", &layout.data);
        env::set_var("CARL_CODEX_EXECUTABLE", env::current_exe()?);
        env::remove_var("OPENAI_API_KEY");
        env::remove_var("CODEX_API_KEY");
        env::remove_var("AZURE_OPENAI_API_KEY");
    }
    Ok(())
}

fn cli_codex_home(layout: &TestLayout) -> PathBuf {
    layout.data.join("providers").join("codex")
}

fn codex_adapter_fixture(
    layout: &TestLayout,
    profile: ProviderEnvironmentProfile,
) -> Result<CodexExecAdapter, Box<dyn Error + Send + Sync>> {
    let specification = SidecarCommand {
        executable: env::current_exe()?,
        arguments: Vec::new(),
        version_arguments: Vec::new(),
        version_output: VersionOutputFormat::SingleSemverToken,
        isolated_home: layout.home.clone(),
        supported_versions: VersionReq::parse("=0.146.0")?,
    };
    let trusted = specification
        .resolve_executable()?
        .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
    let home = ProviderHome::prepare(profile, &layout.data, &layout.workspace, &layout.home)?;
    if profile == ProviderEnvironmentProfile::Codex {
        home.write_static_file("auth.json", b"fixture subscription auth")?;
    }
    Ok(CodexExecAdapter::new(trusted, home, short_limits())?)
}

fn execution_fixture(
    layout: &TestLayout,
    scenario: &str,
) -> Result<
    (
        SidecarCommand,
        carl::sidecar::TrustedExecutable,
        ProviderHome,
        ExecutionWorkspace,
    ),
    Box<dyn Error + Send + Sync>,
> {
    let specification = SidecarCommand {
        executable: env::current_exe()?,
        arguments: vec![
            OsString::from(EXEC_FIXTURE_ARGUMENT),
            OsString::from(scenario),
        ],
        version_arguments: vec![
            OsString::from(EXEC_FIXTURE_ARGUMENT),
            OsString::from("version"),
        ],
        version_output: VersionOutputFormat::ExactPrefix("carl-codex-exec-fixture"),
        isolated_home: layout.home.clone(),
        supported_versions: VersionReq::parse("=1.2.3")?,
    };
    let trusted = specification
        .resolve_executable()?
        .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
    let home = ProviderHome::prepare(
        ProviderEnvironmentProfile::Codex,
        &layout.data,
        &layout.workspace,
        &layout.home,
    )?;
    let workspace = ExecutionWorkspace::open(&layout.workspace)?;
    Ok((specification, trusted, home, workspace))
}

fn run_async<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the test runtime builds")
        .block_on(future)
}

fn drain_fixture_stdin() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    Ok(())
}

fn dispatch_exec_fixture(arguments: &[OsString]) -> Option<i32> {
    if arguments == [OsString::from("--version")] {
        if let Some(home) = env::var_os("CODEX_HOME").map(PathBuf::from)
            && home
                .parent()
                .and_then(std::path::Path::parent)
                .is_some_and(|data| data.join("fixture-version-hang").is_file())
        {
            let child = match Command::new(env::current_exe().expect("fixture executable exists"))
                .args([EXEC_FIXTURE_ARGUMENT, "child-loop"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(child) => child,
                Err(_) => return Some(71),
            };
            if fs::write(
                home.join("fixture-pids.json"),
                serde_json::to_vec(&json!({
                    "leader": process::id(),
                    "grandchild": child.id(),
                }))
                .expect("fixture PID JSON serializes"),
            )
            .is_err()
            {
                return Some(73);
            }
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        let version = env::var_os("CODEX_HOME")
            .map(PathBuf::from)
            .and_then(|home| {
                home.parent()?
                    .parent()?
                    .join("fixture-version")
                    .is_file()
                    .then(|| {
                        fs::read_to_string(home.parent()?.parent()?.join("fixture-version")).ok()
                    })
                    .flatten()
            })
            .unwrap_or_else(|| "0.146.0".to_owned());
        println!("codex-cli {}", version.trim());
        if let Some(home) = env::var_os("CODEX_HOME").map(PathBuf::from)
            && home
                .parent()
                .and_then(std::path::Path::parent)
                .is_some_and(|data| data.join("fixture-mutate-after-version").is_file())
        {
            let executable = match env::current_exe() {
                Ok(executable) => executable,
                Err(_) => return Some(74),
            };
            let mut file = match fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(executable)
            {
                Ok(file) => file,
                Err(_) => return Some(73),
            };
            if file.seek(io::SeekFrom::End(-1)).is_err() {
                return Some(74);
            }
            let mut byte = [0_u8; 1];
            if file.read_exact(&mut byte).is_err()
                || file.seek(io::SeekFrom::End(-1)).is_err()
                || file.write_all(&[byte[0] ^ 1]).is_err()
                || file.sync_all().is_err()
            {
                return Some(74);
            }
        }
        return Some(0);
    }
    if arguments
        .iter()
        .any(|argument| argument == OsStr::new("exec"))
        && arguments.last().map(OsString::as_os_str) == Some(OsStr::new("-"))
    {
        return Some(adapter_exec_fixture(arguments));
    }
    if arguments.first().map(OsString::as_os_str) != Some(OsStr::new(EXEC_FIXTURE_ARGUMENT)) {
        return None;
    }
    let scenario = arguments.get(1)?.to_string_lossy();
    Some(match scenario.as_ref() {
        "version" if arguments.len() == 2 => {
            println!("carl-codex-exec-fixture {EXEC_FIXTURE_VERSION}");
            0
        }
        "success" => {
            let mut input = String::new();
            if io::stdin().read_to_string(&mut input).is_err() {
                return Some(74);
            }
            let received = json!({
                "type": "fixture.received",
                "stdin": input,
                "cwd": env::current_dir().ok(),
                "openai_api_key": env::var("OPENAI_API_KEY").ok(),
                "codex_api_key": env::var("CODEX_API_KEY").ok(),
            });
            println!("{received}");
            println!("{}", json!({"type": "fixture.completed"}));
            0
        }
        "nonzero" => {
            if drain_fixture_stdin().is_err() {
                return Some(74);
            }
            17
        }
        "malformed" => {
            if drain_fixture_stdin().is_err() {
                return Some(74);
            }
            println!("{{not-json");
            0
        }
        "oversized" => {
            if drain_fixture_stdin().is_err() {
                return Some(74);
            }
            println!(
                "{}",
                json!({"type": "fixture.oversized", "payload": "x".repeat(9 * 1_024)})
            );
            0
        }
        "stderr" => {
            if drain_fixture_stdin().is_err() {
                return Some(74);
            }
            let _ = writeln!(io::stderr(), "{SECRET_SENTINEL}");
            println!("{}", json!({"type": "fixture.completed"}));
            0
        }
        "hanging" => loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
        "hanging-child" => {
            let child = match Command::new(env::current_exe().expect("fixture executable exists"))
                .args([EXEC_FIXTURE_ARGUMENT, "child-loop"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(child) => child,
                Err(_) => return Some(71),
            };
            let home = PathBuf::from(env::var_os("CODEX_HOME").expect("CODEX_HOME is set"));
            fs::write(
                home.join("fixture-pids.json"),
                serde_json::to_vec(&json!({
                    "leader": process::id(),
                    "grandchild": child.id(),
                }))
                .expect("fixture PID JSON serializes"),
            )
            .expect("fixture PID file is written");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        "child-loop" => loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
        _ => 64,
    })
}

fn adapter_exec_fixture(arguments: &[OsString]) -> i32 {
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        return 74;
    }
    let Some(home) = env::var_os("CODEX_HOME").map(PathBuf::from) else {
        return 78;
    };
    let record = json!({
        "arguments": arguments
            .iter()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>(),
        "stdin": input,
        "openai_api_key": env::var("OPENAI_API_KEY").ok(),
        "codex_api_key": env::var("CODEX_API_KEY").ok(),
        "azure_openai_api_key": env::var("AZURE_OPENAI_API_KEY").ok(),
        "buzz_secret": env::var("BUZZ_SECRET_SENTINEL").ok(),
        "xai_secret": env::var("XAI_SECRET_SENTINEL").ok(),
    });
    if fs::write(
        home.join("exec-record.json"),
        serde_json::to_vec(&record).expect("fixture launch record serializes"),
    )
    .is_err()
    {
        return 73;
    }

    let scenario = env::current_dir()
        .ok()
        .and_then(|workspace| fs::read_to_string(workspace.join(".fixture-scenario")).ok())
        .unwrap_or_else(|| "success".to_owned());
    match scenario.trim() {
        "success" => {
            println!(
                "{}",
                json!({
                    "type": "thread.started",
                    "thread_id": "0199a213-81c0-7800-8aa1-bbab2a035a53"
                })
            );
            println!("{}", json!({"type": "turn.started"}));
            println!(
                "{}",
                json!({
                    "type": "item.completed",
                    "item": {
                        "id": "item_1",
                        "type": "agent_message",
                        "text": "Fixture completed."
                    }
                })
            );
            println!(
                "{}",
                json!({
                    "type": "turn.completed",
                    "usage": {
                        "input_tokens": 10,
                        "cached_input_tokens": 2,
                        "output_tokens": 3
                    }
                })
            );
            0
        }
        "missing-terminal" => {
            println!(
                "{}",
                json!({
                    "type": "thread.started",
                    "thread_id": "0199a213-81c0-7800-8aa1-bbab2a035a53"
                })
            );
            println!("{}", json!({"type": "turn.started"}));
            0
        }
        "duplicate-terminal" => {
            println!(
                "{}",
                json!({
                    "type": "thread.started",
                    "thread_id": "0199a213-81c0-7800-8aa1-bbab2a035a53"
                })
            );
            println!("{}", json!({"type": "turn.started"}));
            println!("{}", completed_event());
            println!("{}", completed_event());
            0
        }
        "baseline-success" => {
            println!(
                "{}",
                json!({
                    "type": "thread.started",
                    "thread_id": "0199a213-81c0-7800-8aa1-bbab2a035a53"
                })
            );
            println!("{}", json!({"type": "turn.started"}));
            for (phase, id, kind) in [
                ("started", "command_1", "command_execution"),
                ("updated", "command_1", "command_execution"),
                ("completed", "command_1", "command_execution"),
                ("completed", "file_1", "file_change"),
                ("completed", "mcp_1", "mcp_tool_call"),
                ("completed", "web_1", "web_search"),
                ("completed", "reasoning_1", "reasoning"),
            ] {
                println!(
                    "{}",
                    json!({
                        "type": format!("item.{phase}"),
                        "item": {
                            "id": id,
                            "type": kind,
                            "text": "SECRET_REASONING_SENTINEL",
                            "command": "cargo test --secret",
                            "output": "SECRET_COMMAND_OUTPUT_SENTINEL"
                        }
                    })
                );
            }
            println!(
                "{}",
                json!({
                    "type": "item.completed",
                    "item": {
                        "id": "message_1",
                        "type": "agent_message",
                        "text": "SECRET_AGENT_TEXT_SENTINEL"
                    }
                })
            );
            println!("{}", json!({"type": "future.event", "secret": "SECRET"}));
            println!(
                "{}",
                json!({
                    "type": "item.completed",
                    "item": {"id": "future_1", "type": "future_item", "secret": "SECRET"}
                })
            );
            println!(
                "{}",
                json!({
                    "type": "turn.completed",
                    "usage": {
                        "input_tokens": 120,
                        "cached_input_tokens": 100,
                        "output_tokens": 30
                    }
                })
            );
            0
        }
        "replace-executable" => {
            println!(
                "{}",
                json!({
                    "type": "thread.started",
                    "thread_id": "0199a213-81c0-7800-8aa1-bbab2a035a53"
                })
            );
            println!("{}", json!({"type": "turn.started"}));
            println!(
                "{}",
                json!({
                    "type": "turn.completed",
                    "usage": {
                        "input_tokens": 1,
                        "cached_input_tokens": 0,
                        "output_tokens": 1
                    }
                })
            );
            let executable = match env::current_exe() {
                Ok(executable) => executable,
                Err(_) => return 74,
            };
            let replacement = executable.with_extension("replacement");
            if fs::copy(&executable, &replacement).is_err()
                || fs::rename(&replacement, &executable).is_err()
            {
                return 73;
            }
            0
        }
        "auth-failure" => {
            println!(
                "{}",
                json!({
                    "type": "turn.failed",
                    "error": {"code": "authentication_required"}
                })
            );
            1
        }
        "nonzero" => 17,
        "malformed" => {
            println!("{{not-json");
            0
        }
        "oversized" => {
            println!(
                "{}",
                json!({"type": "fixture.oversized", "payload": "x".repeat(9 * 1_024)})
            );
            0
        }
        "hanging" => loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
        "hanging-child" => {
            let child = match Command::new(env::current_exe().expect("fixture executable exists"))
                .args([EXEC_FIXTURE_ARGUMENT, "child-loop"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(child) => child,
                Err(_) => return 71,
            };
            if fs::write(
                home.join("fixture-pids.json"),
                serde_json::to_vec(&json!({
                    "leader": process::id(),
                    "grandchild": child.id(),
                }))
                .expect("fixture PID JSON serializes"),
            )
            .is_err()
            {
                return 73;
            }
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        _ => 64,
    }
}
