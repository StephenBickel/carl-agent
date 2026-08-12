#[path = "support/private_dir.rs"]
mod private_dir;

use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use carl::acp::PermissionMode;
use carl::delegates::codex::{
    CodexAppServer, CodexApprovalDecision, CodexEvent, StartThread, StartTurn,
};
use carl::delegates::{ModelId, ReasoningEffort};
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
            "Codex app-server handshake catalog and thread start are exact",
            handshake_and_thread,
        ),
        test(
            "Codex app-server normalizes events approvals steering and interrupt",
            lifecycle_and_approval,
        ),
    ];
    libtest_mimic::run(&Arguments::from_args(), trials).exit();
}

fn test(name: &'static str, body: fn() -> Result<(), Box<dyn Error + Send + Sync>>) -> Trial {
    Trial::test(name, move || {
        body().map_err(|error| Failed::from(error.to_string()))
    })
}

fn handshake_and_thread() -> Result<(), Box<dyn Error + Send + Sync>> {
    run_async(async {
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
                mode: PermissionMode::Default,
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
        assert_eq!(requests[4]["params"]["sandbox"], "workspace-write");
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
        assert!(matches!(
            server.next_event().await?,
            CodexEvent::ItemStarted { .. }
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
        assert!(matches!(
            server.next_event().await?,
            CodexEvent::ItemCompleted { .. }
        ));

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
        max_stdout_line_bytes: 128 * 1024,
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
                let result = json!({
                    "thread":thread, "model":"gpt-5.6-codex", "modelProvider":"openai",
                    "cwd":workspace_for(&home),
                    "approvalPolicy":"on-request", "approvalsReviewer":"user",
                    "sandbox":"workspace-write"
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
            Some("turn/start") => {
                let result = json!({"turn":{"id":"turn_123","items":[],"status":"inProgress"}});
                if write_message(&json!({"id":id,"result":result})).is_err() {
                    return 74;
                }
                for notification in turn_notifications() {
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
                            "item":{"type":"commandExecution","id":"item_123"}
                        },
                        "emittedAtMs":3
                    }))
                    .is_err()
                {
                    return 74;
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
        fs::create_dir_all(&data)?;
        private_dir::make_owner_only_directory(&data)?;
        fs::create_dir_all(&workspace)?;
        let root = fs::canonicalize(root)?;
        let data = fs::canonicalize(data)?;
        let workspace = fs::canonicalize(workspace)?;
        let home = data.join("providers/codex");
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
