use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use carl::acp::{PermissionMode, PermissionProfile};
use carl::delegates::codex::{
    CodexAppServer, CodexApprovalDecision, CodexEvent, CodexItem, CodexThreadId, CodexTurnId,
    DelegateErrorCode, StartThread, StartTurn,
};
use carl::delegates::{ModelId, ReasoningEffort};
use carl::runtime::agent_port::{
    AgentContextId, AgentEvent, AgentPort, AgentPortErrorCode, ResumeAgentContext, StartAgentEpoch,
};
use carl::sidecar::{
    ExecutableTrustDecision, ProviderEnvironmentProfile, ProviderHome, SidecarCommand,
    SidecarLimits, VersionOutputFormat,
};
use libtest_mimic::{Arguments, Failed, Trial};
use semver::VersionReq;
use serde_json::{Value, json};

static NEXT_LAYOUT: AtomicU64 = AtomicU64::new(0);

fn main() {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(code) = dispatch_fixture(&arguments) {
        process::exit(code);
    }
    let trials = vec![
        test(
            "Codex long-horizon protocol contract is pinned to 0.146.0",
            long_horizon_protocol_contract_is_pinned,
        ),
        test(
            "Codex app-server handshake catalog and thread start are exact",
            handshake_and_thread,
        ),
        test(
            "Codex app-server normalizes events approvals steering and interrupt",
            lifecycle_and_approval,
        ),
        test(
            "Codex app-server denies invalid bypass approvals before protocol failure",
            invalid_bypass_approval_is_denied_before_protocol_failure,
        ),
        test(
            "Codex app-server fails closed on malformed long-horizon evidence",
            malformed_long_horizon_evidence_fails_closed,
        ),
        test(
            "Codex normalized item diagnostics redact execution evidence",
            normalized_item_diagnostics_are_redacted,
        ),
        test(
            "Codex native lifecycle controls use exact requests and correlated barriers",
            native_lifecycle_controls_are_exact_and_correlated,
        ),
        test(
            "Codex lifecycle controls reject mismatched bindings and hostile process pages",
            lifecycle_controls_fail_closed,
        ),
    ];
    libtest_mimic::run(&Arguments::from_args(), trials).exit();
}

fn native_lifecycle_controls_are_exact_and_correlated() -> Result<(), Box<dyn Error + Send + Sync>>
{
    run_async(async {
        let layout = TestLayout::new()?;
        let mut server = connect(&layout).await?;
        server.models().await?;
        let capabilities = server.capabilities();
        assert!(capabilities.resume);
        assert!(capabilities.compact);
        assert!(capabilities.background_processes);
        assert!(capabilities.token_usage);
        assert!(capabilities.pre_dispatch_effects);

        let context_id = AgentContextId::parse("thr_123")?;
        assert_eq!(
            server
                .resume_context(ResumeAgentContext {
                    context_id: context_id.clone(),
                    cwd: layout.workspace.clone(),
                    model: ModelId::parse("gpt-5.6-codex")?,
                    permission_mode: PermissionMode::Default,
                })
                .await
                .map_err(|error| format!("resume failed: {error:?}"))?,
            context_id
        );
        server
            .compact_context(&context_id)
            .await
            .map_err(|error| format!("compact failed: {error:?}"))?;
        server.compact_context(&context_id).await?;
        let blocked = server
            .start_epoch(StartAgentEpoch {
                context_id: context_id.clone(),
                input: "must wait for compaction".into(),
                model: ModelId::parse("gpt-5.6-codex")?,
                effort: ReasoningEffort::High,
                permission_mode: PermissionMode::Default,
            })
            .await
            .expect_err("an epoch must not cross the compaction barrier");
        assert_eq!(blocked.code(), AgentPortErrorCode::InvalidRequest);
        assert!(matches!(
            AgentPort::next_event(&mut server).await?,
            AgentEvent::CompactionStarted { context_id: seen, item_id }
                if seen == context_id && item_id == "compact_native"
        ));
        assert!(matches!(
            AgentPort::next_event(&mut server).await?,
            AgentEvent::CompactionCompleted { context_id: seen, item_id }
                if seen == context_id && item_id == "compact_native"
        ));

        let processes = server
            .list_background_processes(&context_id)
            .await
            .map_err(|error| format!("background list failed: {error:?}"))?;
        assert_eq!(processes.len(), 2);
        assert_eq!(processes[0].process_id, "proc_123");
        assert_eq!(processes[1].process_id, "proc_456");
        assert!(
            server
                .terminate_background_process(&context_id, "proc_123")
                .await?
        );

        let requests = read_requests(&layout)?;
        let resume = requests
            .iter()
            .find(|request| request["method"] == "thread/resume")
            .expect("resume request is dispatched");
        assert_eq!(
            resume["params"],
            json!({
                "threadId":"thr_123",
                "cwd":layout.workspace,
                "model":"gpt-5.6-codex",
                "approvalPolicy":"on-request",
                "sandbox":"read-only",
                "excludeTurns":true
            })
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["method"] == "thread/compact/start")
                .count(),
            1
        );
        let compact = requests
            .iter()
            .find(|request| request["method"] == "thread/compact/start")
            .unwrap();
        assert_eq!(compact["params"], json!({"threadId":"thr_123"}));
        let background = requests
            .iter()
            .filter(|request| request["method"] == "thread/backgroundTerminals/list")
            .collect::<Vec<_>>();
        assert_eq!(background.len(), 2);
        assert_eq!(
            background[0]["params"],
            json!({"threadId":"thr_123","cursor":null,"limit":64})
        );
        assert_eq!(background[1]["params"]["cursor"], "background-page-2");
        let terminate = requests
            .iter()
            .find(|request| request["method"] == "thread/backgroundTerminals/terminate")
            .unwrap();
        assert_eq!(
            terminate["params"],
            json!({"threadId":"thr_123","processId":"proc_123"})
        );
        server.cancel().await?;
        Ok(())
    })
}

fn lifecycle_controls_fail_closed() -> Result<(), Box<dyn Error + Send + Sync>> {
    run_async(async {
        for context in [
            "thr_mismatch",
            "thr_permission",
            "thr_workspace",
            "thr_active",
            "thr_duplicate",
            "thr_outside",
            "thr_missing",
            "thr_cursor",
        ] {
            let layout = TestLayout::new()?;
            let mut server = connect(&layout).await?;
            server.models().await?;
            let context_id = AgentContextId::parse(context)?;
            let resumed = server
                .resume_context(ResumeAgentContext {
                    context_id: context_id.clone(),
                    cwd: layout.workspace.clone(),
                    model: ModelId::parse("gpt-5.6-codex")?,
                    permission_mode: PermissionMode::Default,
                })
                .await;
            if matches!(
                context,
                "thr_mismatch" | "thr_permission" | "thr_workspace" | "thr_active"
            ) {
                let error = resumed.expect_err("a mismatched resume binding must be rejected");
                assert_eq!(error.code(), AgentPortErrorCode::InvalidResponse);
            } else {
                assert_eq!(resumed?, context_id);
                let error = server
                    .list_background_processes(&context_id)
                    .await
                    .expect_err("hostile background terminal pages must fail closed");
                assert_eq!(error.code(), AgentPortErrorCode::InvalidResponse);
            }
            server.cancel().await?;
        }
        Ok(())
    })
}

fn normalized_item_diagnostics_are_redacted() -> Result<(), Box<dyn Error + Send + Sync>> {
    let item = CodexItem::Command {
        item_id: "item-secret".into(),
        command: "command-secret-7f39".into(),
        cwd: "/cwd-secret-7f39".into(),
        status: "failed".into(),
        exit_code: Some(17),
        aggregated_output: Some("output-secret-7f39".into()),
        process_id: Some("process-secret-7f39".into()),
    };
    let item_debug = format!("{item:?}");
    let event_debug = format!(
        "{:?}",
        CodexEvent::ItemCompleted {
            thread_id: CodexThreadId::parse("thread-debug")?,
            turn_id: CodexTurnId::parse("turn-debug")?,
            item,
        }
    );
    let file_debug = format!(
        "{:?}",
        CodexItem::FileChange {
            item_id: "file-secret".into(),
            status: "failed".into(),
            changes: json!([{"diff":"file-payload-secret-7f39"}]),
        }
    );
    for secret in [
        "command-secret-7f39",
        "/cwd-secret-7f39",
        "output-secret-7f39",
        "process-secret-7f39",
        "file-payload-secret-7f39",
    ] {
        assert!(!item_debug.contains(secret));
        assert!(!event_debug.contains(secret));
        assert!(!file_debug.contains(secret));
    }
    assert!(item_debug.contains("failed"));
    assert!(event_debug.contains("ItemCompleted"));
    Ok(())
}

fn long_horizon_protocol_contract_is_pinned() -> Result<(), Box<dyn Error + Send + Sync>> {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/codex/0.146.0/long_horizon_contract.json"
    ))?;
    assert_eq!(
        CodexAppServer::long_horizon_protocol_contract("0.146.0")?,
        fixture
    );
    let error = CodexAppServer::long_horizon_protocol_contract("0.145.0")
        .expect_err("a different Codex version must be rejected");
    assert_eq!(error.code(), DelegateErrorCode::Incompatible);
    Ok(())
}

fn test(name: &'static str, body: fn() -> Result<(), Box<dyn Error + Send + Sync>>) -> Trial {
    Trial::test(name, move || {
        body().map_err(|error| Failed::from(error.to_string()))
    })
}

fn handshake_and_thread() -> Result<(), Box<dyn Error + Send + Sync>> {
    run_async(async {
        assert_eq!(PermissionMode::Plan.profile(), PermissionProfile::ReadOnly);
        assert_eq!(
            PermissionMode::Default.profile(),
            PermissionProfile::Approval
        );
        assert_eq!(
            PermissionMode::BypassPermissions.profile(),
            PermissionProfile::FullAccess,
        );
        let layout = TestLayout::new()?;
        let mut server = connect(&layout).await?;
        let models = server.models().await?;
        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id().as_str(), "gpt-5.6-codex");
        assert_eq!(
            models[0].supported_efforts(),
            &[ReasoningEffort::Medium, ReasoningEffort::High]
        );
        let thread = server
            .start_thread(StartThread {
                cwd: layout.workspace.clone(),
                model: Some(ModelId::parse("gpt-5.6-codex")?),
                mode: PermissionMode::BypassPermissions,
            })
            .await?;
        assert_eq!(thread.as_str(), "thr_123");

        let requests = read_requests(&layout)?;
        assert_eq!(requests[0]["method"], "initialize");
        assert_eq!(requests[1]["method"], "initialized");
        assert_eq!(requests[2]["method"], "model/list");
        assert_eq!(requests[3]["params"]["cursor"], "page-2");
        assert_eq!(requests[4]["method"], "thread/start");
        assert_eq!(
            requests[4]["params"]["cwd"],
            layout.workspace.to_str().unwrap()
        );
        assert_eq!(requests[4]["params"]["model"], "gpt-5.6-codex");
        assert_eq!(requests[4]["params"]["approvalPolicy"], "on-request");
        assert_eq!(requests[4]["params"]["sandbox"], "read-only");
        assert_eq!(requests[4]["params"]["ephemeral"], false);
        assert!(requests[4]["params"].get("mcpServers").is_none());
        server.cancel().await?;
        Ok(())
    })
}

fn lifecycle_and_approval() -> Result<(), Box<dyn Error + Send + Sync>> {
    run_async(async {
        let layout = TestLayout::new()?;
        let mut server = connect(&layout).await?;
        server.models().await?;
        let thread = server
            .start_thread(StartThread {
                cwd: layout.workspace.clone(),
                model: Some(ModelId::parse("gpt-5.6-codex")?),
                mode: PermissionMode::Default,
            })
            .await?;
        let turn = server
            .start_turn(StartTurn {
                thread_id: thread.clone(),
                input: "Fix the tests".into(),
                model: Some(ModelId::parse("gpt-5.6-codex")?),
                effort: Some(ReasoningEffort::High),
                mode: PermissionMode::Default,
            })
            .await?;
        assert_eq!(turn.as_str(), "turn_123");

        assert!(matches!(
            server.next_event().await?,
            CodexEvent::ThreadStarted { .. }
        ));
        assert!(matches!(
            server.next_event().await?,
            CodexEvent::TurnStarted { .. }
        ));
        let CodexEvent::TokenUsageUpdated { usage, .. } = server.next_event().await? else {
            return Err("missing normalized token usage".into());
        };
        assert_eq!(usage.last_total_tokens, 3);
        assert_eq!(usage.total_tokens, 3);
        assert_eq!(usage.model_context_window, Some(258_400));
        let CodexEvent::ItemStarted { item, .. } = server.next_event().await? else {
            return Err("missing started item".into());
        };
        assert!(matches!(
            item,
            CodexItem::Other { item_id, item_type }
                if item_id == "item_123" && item_type == "agentMessage"
        ));
        let CodexEvent::AgentMessageDelta { text, .. } = server.next_event().await? else {
            return Err("missing agent delta".into());
        };
        assert_eq!(text, "Working");
        assert!(matches!(
            server.next_event().await?,
            CodexEvent::DiffUpdated { .. }
        ));
        let CodexEvent::ApprovalRequested(approval) = server.next_event().await? else {
            return Err("missing approval".into());
        };
        assert_eq!(approval.provider_request_id(), "approval-7");
        assert_eq!(approval.thread_id(), &thread);
        assert_eq!(approval.turn_id(), &turn);
        assert_eq!(approval.item_id(), "item_123");
        assert_eq!(approval.command(), Some("cargo test"));
        assert_eq!(approval.reason(), Some("Run the test suite"));
        assert_eq!(approval.request_digest().to_string().len(), 64);
        server
            .resolve_approval(&approval, CodexApprovalDecision::Allow)
            .await?;
        let CodexEvent::ItemCompleted { item, .. } = server.next_event().await? else {
            return Err("missing completed item".into());
        };
        assert!(matches!(
            item,
            CodexItem::Command {
                item_id,
                command,
                cwd,
                status,
                exit_code: Some(0),
                aggregated_output: Some(output),
                process_id: Some(process_id),
            } if item_id == "item_123"
                && command == "cargo test"
                && cwd == layout.workspace.to_string_lossy()
                && status == "completed"
                && output == "test result: ok"
                && process_id == "proc_123"
        ));

        let CodexEvent::ItemStarted { item, .. } = server.next_event().await? else {
            return Err("missing file-change start".into());
        };
        assert_eq!(
            item,
            CodexItem::FileChange {
                item_id: "file_123".into(),
                status: "inProgress".into(),
                changes: json!([{
                    "path":"src/lib.rs","kind":{"type":"update"},"diff":"@@ -1 +1 @@"
                }]),
            }
        );
        let CodexEvent::ItemCompleted { item, .. } = server.next_event().await? else {
            return Err("missing file-change completion".into());
        };
        assert!(matches!(
            item,
            CodexItem::FileChange { item_id, status, .. }
                if item_id == "file_123" && status == "completed"
        ));
        let CodexEvent::ItemStarted { item, .. } = server.next_event().await? else {
            return Err("missing compaction start".into());
        };
        assert_eq!(
            item,
            CodexItem::ContextCompaction {
                item_id: "compact_123".into()
            }
        );
        let CodexEvent::ItemCompleted { item, .. } = server.next_event().await? else {
            return Err("missing compaction completion".into());
        };
        assert_eq!(
            item,
            CodexItem::ContextCompaction {
                item_id: "compact_123".into()
            }
        );

        server.steer(&thread, &turn, "Focus on the parser").await?;
        server.interrupt(&thread, &turn).await?;
        let response: Value =
            serde_json::from_slice(&fs::read(layout.home.join("approval-response.json"))?)?;
        assert_eq!(
            response,
            json!({"id":"approval-7","result":{"decision":"accept"}})
        );
        let requests = read_requests(&layout)?;
        let steer = requests
            .iter()
            .find(|request| request["method"] == "turn/steer")
            .unwrap();
        assert_eq!(steer["params"]["expectedTurnId"], "turn_123");
        let interrupt = requests
            .iter()
            .find(|request| request["method"] == "turn/interrupt")
            .unwrap();
        assert_eq!(
            interrupt["params"],
            json!({"threadId":"thr_123","turnId":"turn_123"})
        );
        server.cancel().await?;
        Ok(())
    })
}

fn invalid_bypass_approval_is_denied_before_protocol_failure()
-> Result<(), Box<dyn Error + Send + Sync>> {
    run_async(async {
        for (scenario, approval_id) in [
            ("cross-turn", "approval-invalid-cross-turn"),
            ("cross-thread", "approval-invalid-cross-thread"),
        ] {
            let layout = TestLayout::new()?;
            let mut server = connect(&layout).await?;
            server.models().await?;
            let thread = server
                .start_thread(StartThread {
                    cwd: layout.workspace.clone(),
                    model: Some(ModelId::parse("gpt-5.6-codex")?),
                    mode: PermissionMode::BypassPermissions,
                })
                .await?;
            server
                .start_turn(StartTurn {
                    thread_id: thread,
                    input: format!("invalid bypass approval {scenario}"),
                    model: Some(ModelId::parse("gpt-5.6-codex")?),
                    effort: Some(ReasoningEffort::High),
                    mode: PermissionMode::BypassPermissions,
                })
                .await?;
            assert!(matches!(
                server.next_event().await?,
                CodexEvent::ThreadStarted { .. }
            ));
            assert!(matches!(
                server.next_event().await?,
                CodexEvent::TurnStarted { .. }
            ));
            assert!(matches!(
                server.next_event().await?,
                CodexEvent::ItemStarted { .. }
            ));

            let error = server
                .next_event()
                .await
                .expect_err("the invalid approval binding must fail the provider protocol");
            assert_eq!(error.code(), DelegateErrorCode::ProtocolFailed);
            let response =
                wait_for_json(&layout.home.join("invalid-approval-response.json")).await?;
            assert_eq!(
                response,
                json!({"id":approval_id,"result":{"decision":"decline"}})
            );
            server.cancel().await?;
        }
        Ok(())
    })
}

fn malformed_long_horizon_evidence_fails_closed() -> Result<(), Box<dyn Error + Send + Sync>> {
    run_async(async {
        for scenario in [
            "signed-token-count",
            "overflowing-token-count",
            "oversized-output",
            "malformed-command",
            "malformed-command-action",
            "unknown-command-field",
        ] {
            let layout = TestLayout::new()?;
            let mut server = connect(&layout).await?;
            server.models().await?;
            let thread = server
                .start_thread(StartThread {
                    cwd: layout.workspace.clone(),
                    model: Some(ModelId::parse("gpt-5.6-codex")?),
                    mode: PermissionMode::Default,
                })
                .await?;
            server
                .start_turn(StartTurn {
                    thread_id: thread,
                    input: format!("malformed evidence {scenario}"),
                    model: Some(ModelId::parse("gpt-5.6-codex")?),
                    effort: Some(ReasoningEffort::High),
                    mode: PermissionMode::Default,
                })
                .await?;
            assert!(matches!(
                server.next_event().await?,
                CodexEvent::ThreadStarted { .. }
            ));
            assert!(matches!(
                server.next_event().await?,
                CodexEvent::TurnStarted { .. }
            ));
            let error = server
                .next_event()
                .await
                .expect_err("malformed normalized evidence must fail the protocol");
            assert_eq!(error.code(), DelegateErrorCode::ProtocolFailed);
            server.cancel().await?;
        }
        Ok(())
    })
}

async fn connect(layout: &TestLayout) -> Result<CodexAppServer, Box<dyn Error + Send + Sync>> {
    let specification = SidecarCommand {
        executable: env::current_exe()?,
        arguments: Vec::new(),
        version_arguments: Vec::new(),
        version_output: VersionOutputFormat::ExactPrefixedVersion {
            prefix: "codex-cli",
            version: "0.146.0",
        },
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
    Ok(CodexAppServer::connect(&trusted, home, limits()).await?)
}

fn limits() -> SidecarLimits {
    SidecarLimits {
        max_stdout_line_bytes: 1024 * 1024,
        max_stderr_bytes: 128,
        graceful_shutdown_timeout: Duration::from_millis(150),
        forced_shutdown_timeout: Duration::from_secs(2),
        process_poll_interval: Duration::from_millis(10),
    }
}

fn dispatch_fixture(arguments: &[OsString]) -> Option<i32> {
    if arguments == [OsString::from("--version")] {
        println!("codex-cli 0.146.0");
        return Some(0);
    }
    let expected = [
        "app-server",
        "--strict-config",
        "-c",
        "cli_auth_credentials_store=\"file\"",
        "--listen",
        "stdio://",
    ];
    if arguments
        .iter()
        .map(OsString::as_os_str)
        .ne(expected.iter().map(OsStr::new))
    {
        return None;
    }
    Some(app_server_fixture())
}

fn app_server_fixture() -> i32 {
    let home = match env::var_os("CODEX_HOME").map(PathBuf::from) {
        Some(home) => home,
        None => return 73,
    };
    for line in std::io::stdin().lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => return 74,
        };
        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => return 65,
        };
        if append_request(&home, &request).is_err() {
            return 73;
        }
        let method = request.get("method").and_then(Value::as_str);
        let id = request.get("id").cloned();
        let result = match method {
            Some("initialized") => {
                if write_message(&json!({
                    "method":"remoteControl/status/changed",
                    "params":{
                        "status":"disabled", "serverName":"fixture",
                        "installationId":"00000000-0000-4000-8000-000000000000",
                        "environmentId":null
                    },
                    "emittedAtMs":1
                }))
                .is_err()
                {
                    return 74;
                }
                continue;
            }
            Some("initialize") => json!({
                "userAgent":"carl/0.146.0 (fixture; arm64) unknown (carl; 0.1.0)", "codexHome":home,
                "platformFamily":"unix", "platformOs":"fixture"
            }),
            Some("model/list") if request["params"]["cursor"].is_null() => json!({
                "data":[model("gpt-5.6-codex", "GPT-5.6 Codex", ["medium", "high"])],
                "nextCursor":"page-2"
            }),
            Some("model/list") => json!({
                "data":[model("gpt-5.6-mini", "GPT-5.6 Mini", ["low", "medium"])],
                "nextCursor":null
            }),
            Some("thread/start") => {
                let thread = thread(&home);
                let approval_policy = request["params"]["approvalPolicy"].clone();
                let sandbox = request["params"]["sandbox"].clone();
                let result = json!({
                    "thread":thread, "model":"gpt-5.6-codex", "modelProvider":"openai",
                    "cwd":workspace_for(&home),
                    "approvalPolicy":approval_policy, "approvalsReviewer":"user",
                    "sandbox":sandbox
                });
                if write_message(&json!({"id":id,"result":result})).is_err()
                    || write_message(&json!({
                        "method":"thread/started", "params":{"thread":thread},
                        "emittedAtMs":1
                    }))
                    .is_err()
                    || write_message(&json!({
                        "method":"mcpServer/startupStatus/updated",
                        "params":{
                            "threadId":"thr_123", "name":"fixture-mcp",
                            "status":"failed", "error":"fixture unavailable",
                            "failureReason":null
                        },
                        "emittedAtMs":1
                    }))
                    .is_err()
                {
                    return 74;
                }
                continue;
            }
            Some("thread/resume") => {
                let requested_thread = request["params"]["threadId"].as_str().unwrap_or_default();
                let returned_thread = if requested_thread == "thr_mismatch" {
                    "thr_other"
                } else {
                    requested_thread
                };
                let mut thread = thread(&home);
                thread["id"] = json!(returned_thread);
                if requested_thread == "thr_active" {
                    thread["status"] = json!({"type":"active","activeFlags":[]});
                }
                let network_access = requested_thread == "thr_permission";
                let returned_cwd = if requested_thread == "thr_workspace" {
                    home.clone()
                } else {
                    workspace_for(&home)
                };
                json!({
                    "thread":thread, "model":"gpt-5.6-codex", "modelProvider":"openai",
                    "cwd":returned_cwd,
                    "approvalPolicy":request["params"]["approvalPolicy"].clone(),
                    "approvalsReviewer":"user",
                    "sandbox":{"type":"readOnly","networkAccess":network_access}
                })
            }
            Some("thread/compact/start") => {
                if write_message(&json!({"id":id,"result":{}})).is_err()
                    || write_message(&json!({
                        "method":"item/started",
                        "params":{
                            "threadId":"thr_123","turnId":"turn_compact","startedAtMs":8,
                            "item":{"type":"contextCompaction","id":"compact_native"}
                        },
                        "emittedAtMs":8
                    }))
                    .is_err()
                    || write_message(&json!({
                        "method":"item/completed",
                        "params":{
                            "threadId":"thr_123","turnId":"turn_compact","completedAtMs":9,
                            "item":{"type":"contextCompaction","id":"compact_native"}
                        },
                        "emittedAtMs":9
                    }))
                    .is_err()
                {
                    return 74;
                }
                continue;
            }
            Some("thread/backgroundTerminals/list") if request["params"]["cursor"].is_null() => {
                match request["params"]["threadId"].as_str() {
                    Some("thr_duplicate") => json!({
                        "data":[
                            {"processId":"duplicate","itemId":"item_1","command":"one","cwd":workspace_for(&home)},
                            {"processId":"duplicate","itemId":"item_2","command":"two","cwd":workspace_for(&home)}
                        ],
                        "nextCursor":null
                    }),
                    Some("thr_outside") => json!({
                        "data":[{
                            "processId":"outside","itemId":"item_1","command":"pwd",
                            "cwd":home
                        }],
                        "nextCursor":null
                    }),
                    Some("thr_missing") => json!({
                        "data":[{
                            "processId":"missing","itemId":"item_1","command":"pwd",
                            "cwd":workspace_for(&home).join("missing")
                        }],
                        "nextCursor":null
                    }),
                    Some("thr_cursor") => {
                        json!({"data":[],"nextCursor":"repeated-background-cursor"})
                    }
                    _ => json!({
                        "data":[{
                            "processId":"proc_123","itemId":"item_123","command":"cargo test",
                            "cwd":workspace_for(&home),"osPid":42,"cpuPercent":12.5,"rssKb":4096
                        }],
                        "nextCursor":"background-page-2"
                    }),
                }
            }
            Some("thread/backgroundTerminals/list") => {
                if request["params"]["threadId"] == "thr_cursor" {
                    json!({"data":[],"nextCursor":"repeated-background-cursor"})
                } else {
                    json!({
                        "data":[{
                            "processId":"proc_456","itemId":"item_456","command":"cargo clippy",
                            "cwd":workspace_for(&home),"osPid":null
                        }]
                    })
                }
            }
            Some("thread/backgroundTerminals/terminate") => json!({"terminated":true}),
            Some("turn/start") => {
                let result = json!({"turn":{"id":"turn_123","items":[],"status":"inProgress"}});
                if write_message(&json!({"id":id,"result":result})).is_err() {
                    return 74;
                }
                let input = request["params"]["input"][0]["text"]
                    .as_str()
                    .unwrap_or_default();
                let notifications = match input.strip_prefix("invalid bypass approval ") {
                    Some(scenario) => invalid_approval_notifications(scenario),
                    None => match input.strip_prefix("malformed evidence ") {
                        Some(scenario) => malformed_evidence_notifications(scenario),
                        None => turn_notifications(),
                    },
                };
                for notification in notifications {
                    if write_message(&notification).is_err() {
                        return 74;
                    }
                }
                continue;
            }
            Some("turn/steer") => json!({"turnId":"turn_123"}),
            Some("turn/interrupt") => json!({}),
            None if request.get("id") == Some(&json!("approval-7")) => {
                if fs::write(home.join("approval-response.json"), line).is_err() {
                    return 73;
                }
                if write_message(&json!({
                    "method":"serverRequest/resolved",
                    "params":{"threadId":"thr_123","requestId":"approval-7"},
                    "emittedAtMs":3
                }))
                .is_err()
                    || write_message(&json!({
                        "method":"item/completed",
                        "params":{
                            "threadId":"thr_123","turnId":"turn_123",
                            "completedAtMs":3,
                            "item":{
                                "type":"commandExecution","id":"item_123",
                                "command":"cargo test","cwd":workspace_for(&home),
                                "status":"completed","exitCode":0,"durationMs":17,
                                "aggregatedOutput":"test result: ok","processId":"proc_123",
                                "commandActions":[]
                            }
                        },
                        "emittedAtMs":3
                    }))
                    .is_err()
                    || write_message(&json!({
                        "method":"item/started",
                        "params":{
                            "threadId":"thr_123","turnId":"turn_123","startedAtMs":4,
                            "item":{
                                "type":"fileChange","id":"file_123","status":"inProgress",
                                "changes":[{
                                    "path":"src/lib.rs","kind":{"type":"update"},
                                    "diff":"@@ -1 +1 @@"
                                }]
                            }
                        },
                        "emittedAtMs":4
                    }))
                    .is_err()
                    || write_message(&json!({
                        "method":"item/completed",
                        "params":{
                            "threadId":"thr_123","turnId":"turn_123","completedAtMs":5,
                            "item":{
                                "type":"fileChange","id":"file_123","status":"completed",
                                "changes":[{
                                    "path":"src/lib.rs","kind":{"type":"update"},
                                    "diff":"@@ -1 +1 @@"
                                }]
                            }
                        },
                        "emittedAtMs":5
                    }))
                    .is_err()
                    || write_message(&json!({
                        "method":"item/started",
                        "params":{
                            "threadId":"thr_123","turnId":"turn_123","startedAtMs":6,
                            "item":{"type":"contextCompaction","id":"compact_123"}
                        },
                        "emittedAtMs":6
                    }))
                    .is_err()
                    || write_message(&json!({
                        "method":"item/completed",
                        "params":{
                            "threadId":"thr_123","turnId":"turn_123","completedAtMs":7,
                            "item":{"type":"contextCompaction","id":"compact_123"}
                        },
                        "emittedAtMs":7
                    }))
                    .is_err()
                {
                    return 74;
                }
                continue;
            }
            None if request.get("id").and_then(Value::as_str).is_some_and(|id| {
                id == "approval-invalid-cross-turn" || id == "approval-invalid-cross-thread"
            }) =>
            {
                if fs::write(home.join("invalid-approval-response.json"), line).is_err() {
                    return 73;
                }
                continue;
            }
            _ => return 65,
        };
        if write_message(&json!({"id":id,"result":result})).is_err() {
            return 74;
        }
    }
    0
}

fn model<const N: usize>(id: &str, display: &str, efforts: [&str; N]) -> Value {
    json!({
        "id":id, "model":id, "displayName":display, "description":display,
        "isDefault":id == "gpt-5.6-codex", "hidden":false,
        "defaultReasoningEffort":efforts[0],
        "supportedReasoningEfforts":efforts.into_iter().map(|effort| json!({
            "reasoningEffort":effort,"description":effort
        })).collect::<Vec<_>>()
    })
}

fn thread(home: &Path) -> Value {
    json!({
        "id":"thr_123", "preview":"", "modelProvider":"openai",
        "createdAt":0, "updatedAt":0, "status":{"type":"idle"},
        "path":null, "cwd":workspace_for(home),
        "cliVersion":"0.146.0", "source":"cli", "agentNickname":null,
        "agentRole":null, "gitInfo":null, "name":null, "turns":[],
        "sessionId":null, "ephemeral":false
    })
}

fn workspace_for(home: &Path) -> PathBuf {
    home.parent()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .expect("fixture Codex home has a data-root parent")
        .join("workspace")
}

fn turn_notifications() -> Vec<Value> {
    let mut notifications = vec![
        json!({"method":"turn/started","params":{"threadId":"thr_123","turn":{"id":"turn_123","items":[],"status":"inProgress"}}}),
        json!({"method":"thread/status/changed","params":{"threadId":"thr_123","status":{"type":"active","activeFlags":[]}}}),
        json!({"method":"warning","params":{"threadId":"thr_123","message":"fixture warning"}}),
        json!({"method":"thread/tokenUsage/updated","params":{
            "threadId":"thr_123","turnId":"turn_123","tokenUsage":{
                "total":{"totalTokens":3,"inputTokens":2,"cachedInputTokens":0,"cacheWriteInputTokens":0,"outputTokens":1,"reasoningOutputTokens":0},
                "last":{"totalTokens":3,"inputTokens":2,"cachedInputTokens":0,"cacheWriteInputTokens":0,"outputTokens":1,"reasoningOutputTokens":0},
                "modelContextWindow":258400
            }
        }}),
        json!({"method":"account/rateLimits/updated","params":{"rateLimits":{
            "limitId":"codex","limitName":null,"primary":null,"secondary":null,
            "credits":{"hasCredits":false,"unlimited":false,"balance":"0"},
            "individualLimit":null,"spendControlReached":null,"planType":"pro",
            "rateLimitReachedType":null
        }}}),
        json!({"method":"item/started","params":{"threadId":"thr_123","turnId":"turn_123","startedAtMs":1,"item":{"type":"agentMessage","id":"item_123","text":""}}}),
        json!({"method":"item/agentMessage/delta","params":{"threadId":"thr_123","turnId":"turn_123","itemId":"item_123","delta":"Working"}}),
        json!({"method":"item/commandExecution/outputDelta","params":{"threadId":"thr_123","turnId":"turn_123","itemId":"item_123","delta":"fixture output"}}),
        json!({"method":"turn/diff/updated","params":{"threadId":"thr_123","turnId":"turn_123","diff":"diff --git a/a b/a"}}),
        json!({"id":"approval-7","method":"item/commandExecution/requestApproval","params":{
            "threadId":"thr_123","turnId":"turn_123","itemId":"item_123","startedAtMs":2,
            "command":"cargo test","reason":"Run the test suite","cwd":null
        }}),
    ];
    for notification in &mut notifications[..9] {
        notification["emittedAtMs"] = json!(2);
    }
    notifications
}

fn invalid_approval_notifications(scenario: &str) -> Vec<Value> {
    let (approval_id, thread_id, turn_id) = match scenario {
        "cross-turn" => ("approval-invalid-cross-turn", "thr_123", "turn_other"),
        "cross-thread" => ("approval-invalid-cross-thread", "thr_other", "turn_123"),
        _ => return Vec::new(),
    };
    vec![
        json!({"method":"turn/started","params":{"threadId":"thr_123","turn":{"id":"turn_123","items":[],"status":"inProgress"}},"emittedAtMs":2}),
        json!({"method":"item/started","params":{"threadId":"thr_123","turnId":"turn_123","startedAtMs":1,"item":{"type":"agentMessage","id":"item_123","text":""}},"emittedAtMs":2}),
        json!({"id":approval_id,"method":"item/commandExecution/requestApproval","params":{
            "threadId":thread_id,"turnId":turn_id,"itemId":"item_123","startedAtMs":2,
            "command":"cargo test","reason":"Run the test suite","cwd":null
        }}),
    ]
}

fn malformed_evidence_notifications(scenario: &str) -> Vec<Value> {
    let malformed = match scenario {
        "signed-token-count" | "overflowing-token-count" => {
            let total_tokens = if scenario == "signed-token-count" {
                json!(-1)
            } else {
                serde_json::from_str("18446744073709551616").unwrap()
            };
            let breakdown = json!({
                "totalTokens":total_tokens,"inputTokens":0,"cachedInputTokens":0,
                "cacheWriteInputTokens":0,"outputTokens":0,"reasoningOutputTokens":0
            });
            json!({"method":"thread/tokenUsage/updated","params":{
                "threadId":"thr_123","turnId":"turn_123",
                "tokenUsage":{"total":breakdown,"last":{
                    "totalTokens":0,"inputTokens":0,"cachedInputTokens":0,
                    "cacheWriteInputTokens":0,"outputTokens":0,"reasoningOutputTokens":0
                },"modelContextWindow":null}
            }})
        }
        "oversized-output" => command_notification(json!({
            "type":"commandExecution","id":"command_123","command":"cargo test",
            "cwd":"/workspace","status":"completed","exitCode":0,"durationMs":1,
            "aggregatedOutput":"x".repeat(512 * 1_024 + 1),"processId":null,"commandActions":[]
        })),
        "malformed-command" => command_notification(json!({
            "type":"commandExecution","id":"command_123","command":"cargo test",
            "status":"completed","exitCode":0,"durationMs":1,
            "aggregatedOutput":"ok","processId":null,"commandActions":[]
        })),
        "malformed-command-action" => command_notification(json!({
            "type":"commandExecution","id":"command_123","command":"cargo test",
            "cwd":"/workspace","status":"completed","exitCode":0,"durationMs":1,
            "aggregatedOutput":"ok","processId":null,"commandActions":[null]
        })),
        "unknown-command-field" => command_notification(json!({
            "type":"commandExecution","id":"command_123","command":"cargo test",
            "cwd":"/workspace","status":"completed","exitCode":0,"durationMs":1,
            "aggregatedOutput":"ok","processId":null,"commandActions":[],
            "providerPayload":"must not be accepted"
        })),
        _ => return Vec::new(),
    };
    vec![
        json!({"method":"turn/started","params":{"threadId":"thr_123","turn":{"id":"turn_123","items":[],"status":"inProgress"}},"emittedAtMs":2}),
        malformed,
    ]
}

fn command_notification(item: Value) -> Value {
    json!({
        "method":"item/completed",
        "params":{
            "threadId":"thr_123","turnId":"turn_123","completedAtMs":3,"item":item
        },
        "emittedAtMs":3
    })
}

fn append_request(home: &Path, request: &Value) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(home.join("requests.jsonl"))?;
    serde_json::to_writer(&mut file, request)?;
    writeln!(file)
}

fn write_message(value: &Value) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, value)?;
    writeln!(stdout)?;
    stdout.flush()
}

fn read_requests(layout: &TestLayout) -> Result<Vec<Value>, Box<dyn Error + Send + Sync>> {
    Ok(fs::read_to_string(layout.home.join("requests.jsonl"))?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?)
}

fn run_async<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

async fn wait_for_json(path: &Path) -> Result<Value, Box<dyn Error + Send + Sync>> {
    for _ in 0..100 {
        match fs::read(path) {
            Ok(bytes) => return Ok(serde_json::from_slice(&bytes)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err("invalid approval response was not received".into())
}

struct TestLayout {
    root: PathBuf,
    data: PathBuf,
    workspace: PathBuf,
    home: PathBuf,
}

impl TestLayout {
    fn new() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let serial = NEXT_LAYOUT.fetch_add(1, Ordering::Relaxed);
        let root = env::current_exe()?
            .parent()
            .ok_or("no parent")?
            .join(format!("carl-codex-app-server-{}-{serial}", process::id()));
        let data = root.join("data");
        let workspace = root.join("workspace");
        let home = data.join("providers/codex");
        fs::create_dir_all(&data)?;
        fs::create_dir_all(&workspace)?;
        Ok(Self {
            root,
            data,
            workspace,
            home,
        })
    }
}

impl Drop for TestLayout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
