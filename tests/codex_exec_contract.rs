#[allow(dead_code)]
#[path = "support/sidecar.rs"]
mod support;

use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{self, Command, Stdio};

use carl::delegates::codex::{
    CodexEventNormalizer, CodexExecAdapter, CodexExecRequest, CodexProtocolErrorCode,
    DelegateActivityKind, DelegateErrorCode, DelegateEvent, DelegateItemPhase, DelegateTerminal,
    DelegateUsage,
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

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

const EXEC_FIXTURE_ARGUMENT: &str = "--carl-private-codex-exec-fixture";
const EXEC_FIXTURE_VERSION: &str = "1.2.3";

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
                "cli_auth_credentials_store = \"keyring\"\n",
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
        supported_versions: VersionReq::parse("=0.136.0")?,
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
        supported_versions: VersionReq::parse("=0.136.0")?,
    };
    let trusted = specification
        .resolve_executable()?
        .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
    let home = ProviderHome::prepare(profile, &layout.data, &layout.workspace, &layout.home)?;
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
            .unwrap_or_else(|| "0.136.0".to_owned());
        println!("codex-cli {}", version.trim());
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
        _ => 64,
    }
}
