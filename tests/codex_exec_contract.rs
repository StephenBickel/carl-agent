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
    CodexEventNormalizer, CodexProtocolErrorCode, DelegateActivityKind, DelegateEvent,
    DelegateItemPhase, DelegateTerminal, DelegateUsage,
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
            PathBuf::from(received["cwd"].as_str().ok_or("cwd is not a string")?),
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

fn dispatch_exec_fixture(arguments: &[OsString]) -> Option<i32> {
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
        "stderr" => {
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
