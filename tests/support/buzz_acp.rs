#![allow(dead_code)]

use std::collections::HashMap;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use carl::policy::{ActorId, Frontend};
use carl::storage::{ChannelId, Store};
use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;

pub type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

pub const PRIVATE_KEY: &str = "fixture-private-key";
pub const CHANNEL_ID: &str = "11111111-1111-4111-8111-111111111111";
pub const ACTOR_HEX: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub fn dispatch_fixture(arguments: &[OsString]) -> Option<i32> {
    if arguments == [OsString::from("--version")] {
        if std::env::var_os("CODEX_HOME").is_some() {
            println!("codex-cli 0.146.0");
        } else {
            println!("buzz 0.1.0");
        }
        return Some(0);
    }
    let app_server = [
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
        .eq(app_server.iter().map(OsStr::new))
    {
        return Some(app_server_fixture());
    }
    if arguments
        .iter()
        .take(2)
        .map(OsString::as_os_str)
        .eq(["messages", "send"].into_iter().map(OsStr::new))
    {
        return Some(buzz_publish_fixture(arguments));
    }
    None
}

pub struct Layout {
    pub root: PathBuf,
    pub data: PathBuf,
    pub workspace: PathBuf,
}

impl Layout {
    pub fn new(name: &str) -> TestResult<Self> {
        let serial = Uuid::new_v4().simple().to_string();
        let root = PathBuf::from("/tmp").join(format!(
            "carl-buzz-{}-{}",
            &name[..name.len().min(12)],
            &serial[..12]
        ));
        let data = root.join("data");
        let workspace = root.join("workspace");
        fs::create_dir_all(&data)?;
        fs::create_dir_all(&workspace)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
        }
        fs::write(workspace.join("target.txt"), "broken\n")?;
        Ok(Self {
            root: fs::canonicalize(root)?,
            data: fs::canonicalize(data)?,
            workspace: fs::canonicalize(workspace)?,
        })
    }

    pub fn publisher_records(&self) -> TestResult<Vec<Value>> {
        let path = self.workspace.join(".buzz-publications.jsonl");
        match fs::read_to_string(path) {
            Ok(contents) => Ok(contents
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<_, _>>()?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn action_count(&self, action: &str) -> TestResult<usize> {
        let path = self.workspace.join(".fixture-actions");
        match fs::read_to_string(path) {
            Ok(contents) => Ok(contents.lines().filter(|line| *line == action).count()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(error.into()),
        }
    }

    pub fn trust_owner(&self) -> TestResult {
        let output = Command::new(assert_cmd::cargo::cargo_bin!("carl"))
            .current_dir(&self.workspace)
            .env_clear()
            .env("CARL_DATA_DIR", fs::canonicalize(&self.data)?)
            .args(["trust", "buzz", "--actor", ACTOR_HEX, "--workspace"])
            .arg(fs::canonicalize(&self.workspace)?)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "owner trust failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    pub fn seed_admitted_event(&self, event_id: &str, channel_id: &str) -> TestResult {
        let store = Store::open(self.data.join("carl.sqlite3"))?;
        store.admit_trusted_frontend_message(
            Frontend::Buzz,
            &ActorId::parse(ACTOR_HEX)?,
            &ChannelId::try_from(channel_id)?,
            &fs::canonicalize(&self.workspace)?,
            event_id,
            Utc::now(),
        )?;
        Ok(())
    }

    pub fn provider_work_count(&self) -> TestResult<usize> {
        Ok(self
            .provider_requests()?
            .iter()
            .filter(|request| {
                matches!(
                    request["method"].as_str(),
                    Some("thread/start" | "turn/start")
                )
            })
            .count())
    }

    pub fn provider_requests(&self) -> TestResult<Vec<Value>> {
        let path = self.workspace.join(".provider-requests.jsonl");
        let requests = match fs::read_to_string(path) {
            Ok(contents) => contents
                .get(..=contents.rfind('\n').unwrap_or(0))
                .unwrap_or_default()
                .lines()
                .map(serde_json::from_str::<Value>)
                .collect::<Result<Vec<_>, _>>()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error.into()),
        };
        Ok(requests)
    }

    pub fn provider_method_count(&self, method: &str) -> TestResult<usize> {
        Ok(self
            .provider_requests()?
            .iter()
            .filter(|request| request["method"] == method)
            .count())
    }

    pub fn task_count(&self) -> TestResult<i64> {
        let connection = rusqlite::Connection::open(self.data.join("carl.sqlite3"))?;
        Ok(connection.query_row("SELECT COUNT(*) FROM agent_tasks", [], |row| row.get(0))?)
    }

    pub fn latest_task_id(&self) -> TestResult<String> {
        let connection = rusqlite::Connection::open(self.data.join("carl.sqlite3"))?;
        Ok(connection.query_row(
            "SELECT id FROM agent_tasks ORDER BY updated_at DESC, id ASC LIMIT 1",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn started_operation_count(&self) -> TestResult<i64> {
        self.operation_status_count("started")
    }

    pub fn operation_status_count(&self, status: &str) -> TestResult<i64> {
        let connection = rusqlite::Connection::open(self.data.join("carl.sqlite3"))?;
        Ok(connection.query_row(
            "SELECT COUNT(*) FROM task_operations WHERE status = ?1",
            [status],
            |row| row.get(0),
        )?)
    }

    pub fn task_lifecycle_event_count(&self, event: &str) -> TestResult<i64> {
        let connection = rusqlite::Connection::open(self.data.join("carl.sqlite3"))?;
        Ok(connection.query_row(
            "SELECT COUNT(*) FROM events
             WHERE json_extract(event_json, '$.type') = 'task_lifecycle'
               AND json_extract(event_json, '$.event.task_event') = ?1",
            [event],
            |row| row.get(0),
        )?)
    }

    pub fn permission_tightening_interrupt_count(&self) -> TestResult<i64> {
        let connection = rusqlite::Connection::open(self.data.join("carl.sqlite3"))?;
        Ok(connection.query_row(
            "SELECT COUNT(*) FROM events
             WHERE json_extract(event_json, '$.type') = 'task_lifecycle'
               AND json_extract(event_json, '$.event.task_event') = 'epoch_interrupted'
               AND json_extract(event_json, '$.event.reason') = 'permission_tightening'",
            [],
            |row| row.get(0),
        )?)
    }

    pub fn task_control_marker_count(&self, task_id: &str) -> TestResult<i64> {
        let connection = rusqlite::Connection::open(self.data.join("carl.sqlite3"))?;
        Ok(connection.query_row(
            "SELECT COUNT(*) FROM task_control_markers WHERE task_id = ?1",
            [task_id],
            |row| row.get(0),
        )?)
    }

    pub fn task_lifecycle_events(&self) -> TestResult<Vec<Value>> {
        let connection = rusqlite::Connection::open(self.data.join("carl.sqlite3"))?;
        let mut statement = connection.prepare(
            "SELECT event_json FROM events
             WHERE json_extract(event_json, '$.type') = 'task_lifecycle'
             ORDER BY sequence",
        )?;
        Ok(statement
            .query_map([], |row| row.get::<_, String>(0))?
            .map(|event| {
                event.and_then(|event| {
                    serde_json::from_str(&event).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })
                })
            })
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn wait_for_provider_method(&self, method: &str, minimum: usize) -> TestResult {
        let path = self.workspace.join(".provider-requests.jsonl");
        for _ in 0..400 {
            let observed = fs::read_to_string(&path)
                .ok()
                .map(|contents| {
                    contents
                        .lines()
                        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                        .filter(|request| request["method"] == method)
                        .count()
                })
                .unwrap_or(0);
            if observed >= minimum {
                std::thread::sleep(Duration::from_millis(20));
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let requests = fs::read_to_string(&path).unwrap_or_default();
        Err(format!(
            "provider method {method} was not observed {minimum} times; requests: {requests}"
        )
        .into())
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub struct Client {
    child: Child,
    service: Child,
    stdin: Option<ChildStdin>,
    frames: mpsc::Receiver<Result<Value, String>>,
    raw_stdout: Arc<Mutex<Vec<u8>>>,
    stdout_worker: Option<JoinHandle<()>>,
    raw_stderr: Arc<Mutex<Vec<u8>>>,
    stderr_worker: Option<JoinHandle<()>>,
}

impl Client {
    pub fn spawn(layout: &Layout, bypass: bool) -> TestResult<Self> {
        let binary = assert_cmd::cargo::cargo_bin!("carl");
        let fixture = fs::canonicalize(std::env::current_exe()?)?;
        let data_root = fs::canonicalize(&layout.data)?;
        let mut service = Command::new(binary)
            .current_dir(&layout.workspace)
            .env_clear()
            .env("CARL_DATA_DIR", &data_root)
            .env("CARL_CODEX_EXECUTABLE", &fixture)
            .env("CARL_BUZZ_EXECUTABLE", &fixture)
            .arg("serve")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let endpoint = data_root.join("carl.sock");
        for _ in 0..500 {
            if endpoint.exists() {
                break;
            }
            if let Some(status) = service.try_wait()? {
                let mut stderr = String::new();
                if let Some(mut output) = service.stderr.take() {
                    let _ = output.read_to_string(&mut stderr);
                }
                return Err(format!(
                    "Carl service exited before startup at {}: {status}: {stderr}",
                    data_root.display()
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !endpoint.exists() {
            let _ = service.kill();
            let _ = service.wait();
            return Err("Carl service endpoint was not created".into());
        }
        let mut command = Command::new(binary);
        command
            .current_dir(&layout.workspace)
            .env_clear()
            .env("CARL_DATA_DIR", data_root)
            .env("CARL_CODEX_EXECUTABLE", &fixture)
            .env("CARL_BUZZ_EXECUTABLE", &fixture)
            .env("BUZZ_ACP_AGENTS", "1")
            .arg("acp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if bypass {
            command.arg("--dangerously-bypass-permissions");
        }
        let mut child = command.spawn()?;
        let stdin = child.stdin.take().ok_or("Carl stdin missing")?;
        let stdout = child.stdout.take().ok_or("Carl stdout missing")?;
        let stderr = child.stderr.take().ok_or("Carl stderr missing")?;
        let raw_stdout = Arc::new(Mutex::new(Vec::new()));
        let stdout_capture = Arc::clone(&raw_stdout);
        let (sender, frames) = mpsc::sync_channel(256);
        let stdout_worker = std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                match reader.read_until(b'\n', &mut line) {
                    Ok(0) => break,
                    Ok(_) if line.len() <= 1_048_576 => {
                        stdout_capture.lock().unwrap().extend_from_slice(&line);
                        let parsed = serde_json::from_slice::<Value>(&line)
                            .map_err(|error| error.to_string());
                        if sender.send(parsed).is_err() {
                            break;
                        }
                    }
                    Ok(_) => {
                        let _ = sender.send(Err("oversized Carl stdout frame".to_owned()));
                        break;
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error.to_string()));
                        break;
                    }
                }
            }
        });
        let raw_stderr = Arc::new(Mutex::new(Vec::new()));
        let stderr_capture = Arc::clone(&raw_stderr);
        let stderr_worker = std::thread::spawn(move || {
            let mut stderr = stderr;
            let _ = stderr.read_to_end(&mut stderr_capture.lock().unwrap());
        });
        Ok(Self {
            child,
            service,
            stdin: Some(stdin),
            frames,
            raw_stdout,
            stdout_worker: Some(stdout_worker),
            raw_stderr,
            stderr_worker: Some(stderr_worker),
        })
    }

    pub fn send(&mut self, frame: &Value) -> TestResult {
        let stdin = self.stdin.as_mut().ok_or("Carl stdin closed")?;
        serde_json::to_writer(&mut *stdin, frame)?;
        writeln!(stdin)?;
        stdin.flush()?;
        Ok(())
    }

    pub fn send_partial(&mut self, frame: &Value) -> TestResult {
        let encoded = serde_json::to_vec(frame)?;
        let middle = encoded.len() / 2;
        let stdin = self.stdin.as_mut().ok_or("Carl stdin closed")?;
        stdin.write_all(&encoded[..middle])?;
        stdin.flush()?;
        std::thread::yield_now();
        stdin.write_all(&encoded[middle..])?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
        Ok(())
    }

    pub fn read(&self) -> TestResult<Value> {
        self.frames
            .recv_timeout(Duration::from_secs(8))
            .map_err(|error| -> Box<dyn Error + Send + Sync> {
                format!("timed out reading Carl frame: {error}").into()
            })?
            .map_err(|error| -> Box<dyn Error + Send + Sync> { error.into() })
    }

    pub fn read_id(&self, expected: i64) -> TestResult<Value> {
        self.read_id_with_updates(expected)
            .map(|(response, _)| response)
    }

    pub fn read_id_with_updates(&self, expected: i64) -> TestResult<(Value, Vec<Value>)> {
        let mut updates = Vec::new();
        for _ in 0..128 {
            let frame = self.read()?;
            if frame.get("id").and_then(Value::as_i64) == Some(expected) {
                return Ok((frame, updates));
            }
            updates.push(frame);
        }
        Err(format!("Carl response ID {expected} was not observed; frames={updates:?}").into())
    }

    pub fn finish(mut self) -> TestResult<CapturedProcess> {
        drop(self.stdin.take());
        let status = self.child.wait()?;
        if let Some(worker) = self.stdout_worker.take() {
            worker.join().map_err(|_| "stdout worker panicked")?;
        }
        if let Some(worker) = self.stderr_worker.take() {
            worker.join().map_err(|_| "stderr worker panicked")?;
        }
        let stdout = self.raw_stdout.lock().unwrap().clone();
        let stderr = self.raw_stderr.lock().unwrap().clone();
        if !status.success() {
            let _ = self.service.kill();
            let _ = self.service.wait();
            return Err(format!(
                "Carl exited {:?}: {}",
                status.code(),
                String::from_utf8_lossy(&stderr)
            )
            .into());
        }
        let _ = self.service.kill();
        let _ = self.service.wait();
        Ok(CapturedProcess { stdout, stderr })
    }
}

pub struct CapturedProcess {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub fn fixture(name: &str, workspace: &Path, session: Option<&str>) -> TestResult<Value> {
    let contents = match name {
        "initialize" => include_str!("../fixtures/buzz/44456e2/initialize.json"),
        "session_new" => include_str!("../fixtures/buzz/44456e2/session_new.json"),
        "prompt" => include_str!("../fixtures/buzz/44456e2/prompt.json"),
        "slash_prompt" => include_str!("../fixtures/buzz/44456e2/slash_prompt.json"),
        "cancel" => include_str!("../fixtures/buzz/44456e2/cancel.json"),
        "steer" => include_str!("../fixtures/buzz/44456e2/steer.json"),
        _ => return Err("unknown Buzz fixture".into()),
    };
    let mut value: Value = serde_json::from_str(contents)?;
    replace_string(&mut value, "$WORKSPACE", &workspace.to_string_lossy());
    if let Some(session) = session {
        replace_string(&mut value, "$SESSION", session);
    }
    Ok(value)
}

pub fn prompt_frame(id: i64, session: &str, text: &str, event: char) -> Value {
    prompt_frame_for_channel(id, session, text, event, CHANNEL_ID)
}

pub fn prompt_frame_for_channel(
    id: i64,
    session: &str,
    text: &str,
    event: char,
    channel_id: &str,
) -> Value {
    json!({
        "jsonrpc":"2.0", "id":id, "method":"session/prompt", "params":{
            "sessionId":session,
            "prompt":[
                {"type":"text","text":text},
                {"type":"text","text":format!(
                    "Event ID: {}\nChannel: Carl Test (#{channel_id})\nKind: 1\nFrom: Owner (hex: {ACTOR_HEX})\nTime: 2026-08-10T12:00:00Z\nContent: command",
                    event.to_string().repeat(64)
                )}
            ]
        }
    })
}

pub fn prompt_frame_for_identity(
    id: i64,
    session: &str,
    text: &str,
    event_id: &str,
    channel_id: &str,
    actor_hex: &str,
    kind: u32,
) -> Value {
    json!({
        "jsonrpc":"2.0", "id":id, "method":"session/prompt", "params":{
            "sessionId":session,
            "prompt":[
                {"type":"text","text":text},
                {"type":"text","text":format!(
                    "Event ID: {event_id}\nChannel: Carl Test (#{channel_id})\nKind: {kind}\nFrom: Owner (hex: {actor_hex})\nTime: 2026-08-10T12:00:00Z\nContent: command"
                )}
            ]
        }
    })
}

fn replace_string(value: &mut Value, needle: &str, replacement: &str) {
    match value {
        Value::String(text) if text == needle => *text = replacement.to_owned(),
        Value::Array(values) => values
            .iter_mut()
            .for_each(|value| replace_string(value, needle, replacement)),
        Value::Object(values) => values
            .values_mut()
            .for_each(|value| replace_string(value, needle, replacement)),
        _ => {}
    }
}

fn app_server_fixture() -> i32 {
    let Some(home) = std::env::var_os("CODEX_HOME").map(PathBuf::from) else {
        return 73;
    };
    if std::env::vars_os().any(|(name, _)| name.to_string_lossy().starts_with("BUZZ_")) {
        return 77;
    }
    let workspace = workspace_for(&home);
    let mut threads = HashMap::<String, PathBuf>::new();
    let mut thread_count = 0_u64;
    let mut turn_count = 0_u64;
    let mut pending: Option<PendingApproval> = None;
    let mut operation_ids = HashMap::<String, String>::new();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else {
            return 74;
        };
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            return 65;
        };
        if append_jsonl(&workspace.join(".provider-requests.jsonl"), &request).is_err() {
            return 73;
        }
        let method = request.get("method").and_then(Value::as_str);
        let id = request.get("id").cloned();
        match method {
            Some("initialized") => continue,
            Some("initialize") => {
                if respond(
                    id,
                    json!({
                        "userAgent":"codex_cli_rs/0.146.0", "codexHome":home,
                        "platformFamily":"unix", "platformOs":"fixture"
                    }),
                )
                .is_err()
                {
                    return 74;
                }
            }
            Some("model/list") => {
                if respond(
                    id,
                    json!({
                        "data":[{
                            "id":"gpt-5.6-codex", "model":"gpt-5.6-codex",
                            "displayName":"GPT-5.6 Codex", "description":"fixture",
                            "isDefault":true, "hidden":false,
                            "defaultReasoningEffort":"high",
                            "supportedReasoningEfforts":[
                                {"reasoningEffort":"medium","description":"Medium"},
                                {"reasoningEffort":"high","description":"High"}
                            ]
                        }], "nextCursor":null
                    }),
                )
                .is_err()
                {
                    return 74;
                }
            }
            Some("thread/start") => {
                thread_count += 1;
                let thread_id = format!("thr_{thread_count}");
                let Some(cwd) = request["params"]["cwd"].as_str().map(PathBuf::from) else {
                    return 65;
                };
                threads.insert(thread_id.clone(), cwd.clone());
                let model = request["params"]["model"].clone();
                let approval = request["params"]["approvalPolicy"].clone();
                let sandbox = request["params"]["sandbox"].clone();
                if respond(
                    id,
                    json!({
                        "thread":thread(&thread_id, &cwd), "model":model,
                        "modelProvider":"openai", "cwd":cwd,
                        "approvalPolicy":approval, "approvalsReviewer":"user", "sandbox":sandbox
                    }),
                )
                .and_then(|()| {
                    notify(json!({
                        "method":"thread/started", "params":{"thread":{"id":thread_id}}
                    }))
                })
                .is_err()
                {
                    return 74;
                }
            }
            Some("turn/start") => {
                turn_count += 1;
                let turn_id = format!("turn_{turn_count}");
                let Some(thread_id) = request["params"]["threadId"].as_str() else {
                    return 65;
                };
                let input = request["params"]["input"][0]["text"]
                    .as_str()
                    .unwrap_or_default();
                if respond(
                    id,
                    json!({"turn":{"id":turn_id,"items":[],"status":"inProgress"}}),
                )
                .and_then(|()| turn_started(thread_id, &turn_id))
                .is_err()
                {
                    return 74;
                }
                if input.contains("Read-only contract planning")
                    || input.contains("Repair the prior invalid contract")
                {
                    if agent_delta(
                        thread_id,
                        &turn_id,
                        "<carl-completion-contract>{\"version\":1,\"goal\":\"Report repository verification\",\"constraints\":[],\"clauses\":[{\"id\":\"report\",\"description\":\"Report the observed verification\",\"required\":false,\"status\":\"pending\",\"evidence\":[]}]}</carl-completion-contract>",
                    )
                    .and_then(|()| turn_completed(thread_id, &turn_id))
                    .is_err()
                    {
                        return 74;
                    }
                    continue;
                }
                if input.contains("wait for cancel") {
                    continue;
                }
                if input.contains("approval scenario") {
                    if item_started(thread_id, &turn_id, "file-item", "fileChange")
                        .and_then(|()| agent_delta(thread_id, &turn_id, "Preparing fix. "))
                        .and_then(|()| {
                            approval_request(
                                "approval-file",
                                "item/fileChange/requestApproval",
                                thread_id,
                                &turn_id,
                                "file-item",
                                json!({"reason":"Update target.txt"}),
                            )
                        })
                        .is_err()
                    {
                        return 74;
                    }
                    pending = Some(PendingApproval {
                        stage: ApprovalStage::File,
                        thread_id: thread_id.to_owned(),
                        turn_id,
                    });
                    continue;
                }
                if input.contains("bypass scenario") {
                    if item_started(thread_id, &turn_id, "bypass-item", "commandExecution")
                        .and_then(|()| {
                            approval_request(
                                "approval-bypass",
                                "item/commandExecution/requestApproval",
                                thread_id,
                                &turn_id,
                                "bypass-item",
                                json!({
                                    "command":"cargo test", "reason":"Verify the patch",
                                    "cwd":null
                                }),
                            )
                        })
                        .is_err()
                    {
                        return 74;
                    }
                    pending = Some(PendingApproval {
                        stage: ApprovalStage::Bypass,
                        thread_id: thread_id.to_owned(),
                        turn_id,
                    });
                    continue;
                }
                if agent_delta(
                    thread_id,
                    &turn_id,
                    "Repository verification complete. <carl-epoch-report>{\"schema_version\":1,\"disposition\":\"complete\",\"summary\":\"Repository verification complete.\",\"clause_evidence\":[],\"exact_identifiers\":[]}</carl-epoch-report>",
                )
                    .and_then(|()| turn_completed(thread_id, &turn_id))
                    .is_err()
                {
                    return 74;
                }
            }
            Some("turn/steer") => {
                let steering = request
                    .pointer("/params/input/0/text")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if let Some(operation_id) = steering.strip_prefix("carl-operation-id: ")
                    && let Some(turn_id) = request["params"]["expectedTurnId"].as_str()
                {
                    operation_ids.insert(turn_id.to_owned(), operation_id.to_owned());
                }
                let boundary_configuration = request
                    .pointer("/params/input/0/text")
                    .and_then(Value::as_str)
                    == Some("boundary configuration");
                if respond(id, json!({"turnId":request["params"]["expectedTurnId"]})).is_err() {
                    return 74;
                }
                if boundary_configuration {
                    std::thread::sleep(Duration::from_millis(50));
                }
                if boundary_configuration
                    && agent_delta(
                        request["params"]["threadId"].as_str().unwrap_or_default(),
                        request["params"]["expectedTurnId"].as_str().unwrap_or_default(),
                        "Reached a safe boundary. <carl-epoch-report>{\"schema_version\":1,\"disposition\":\"continue\",\"summary\":\"Apply queued configuration\",\"next_objective\":\"Verify queued configuration\",\"clause_evidence\":[],\"exact_identifiers\":[]}</carl-epoch-report>",
                    )
                    .and_then(|()| {
                        turn_completed(
                            request["params"]["threadId"].as_str().unwrap_or_default(),
                            request["params"]["expectedTurnId"].as_str().unwrap_or_default(),
                        )
                    })
                    .is_err()
                {
                    return 74;
                }
            }
            Some("turn/interrupt") => {
                if respond(id, json!({})).is_err() {
                    return 74;
                }
            }
            None if pending.is_some() => {
                let Some(mut approval) = pending.take() else {
                    return 65;
                };
                let accepted = request["result"]["decision"] == "accept";
                match approval.stage {
                    ApprovalStage::File => {
                        if accepted && fs::write(workspace.join("target.txt"), "fixed\n").is_err() {
                            return 73;
                        }
                        if item_completed(
                            &approval.thread_id,
                            &approval.turn_id,
                            "file-item",
                            "fileChange",
                            accepted,
                        )
                        .and_then(|()| diff_update(&approval.thread_id, &approval.turn_id))
                        .and_then(|()| {
                            item_started(
                                &approval.thread_id,
                                &approval.turn_id,
                                "command-item",
                                "commandExecution",
                            )
                        })
                        .and_then(|()| {
                            approval_request(
                                "approval-command",
                                "item/commandExecution/requestApproval",
                                &approval.thread_id,
                                &approval.turn_id,
                                "command-item",
                                json!({
                                    "command":"cargo test", "reason":"Verify the patch",
                                    "cwd":null
                                }),
                            )
                        })
                        .is_err()
                        {
                            return 74;
                        }
                        approval.stage = ApprovalStage::Command;
                        pending = Some(approval);
                    }
                    ApprovalStage::Command => {
                        if accepted
                            && append_line(&workspace.join(".fixture-actions"), "approved-command")
                                .is_err()
                        {
                            return 73;
                        }
                        let message = if accepted {
                            "Verification completed successfully."
                        } else {
                            "Verification denied safely."
                        };
                        if agent_delta(&approval.thread_id, &approval.turn_id, message)
                            .and_then(|()| turn_completed(&approval.thread_id, &approval.turn_id))
                            .is_err()
                        {
                            return 74;
                        }
                    }
                    ApprovalStage::Bypass => {
                        if !accepted {
                            return 65;
                        }
                        let Some(operation_id) = operation_ids.get(&approval.turn_id) else {
                            return 65;
                        };
                        let report =
                            completion_report("Bypass verification completed.", operation_id);
                        if fs::write(workspace.join("target.txt"), "fixed\n")
                            .and_then(|()| {
                                append_line(&workspace.join(".fixture-actions"), "approved-command")
                            })
                            .and_then(|()| {
                                item_completed(
                                    &approval.thread_id,
                                    &approval.turn_id,
                                    "bypass-item",
                                    "commandExecution",
                                    true,
                                )
                            })
                            .and_then(|()| diff_update(&approval.thread_id, &approval.turn_id))
                            .and_then(|()| {
                                agent_delta(&approval.thread_id, &approval.turn_id, &report)
                            })
                            .and_then(|()| turn_completed(&approval.thread_id, &approval.turn_id))
                            .is_err()
                        {
                            return 74;
                        }
                    }
                }
            }
            _ => return 65,
        }
    }
    0
}

fn completion_report(summary: &str, operation_id: &str) -> String {
    format!(
        "{summary} <carl-epoch-report>{}</carl-epoch-report>",
        json!({
            "schema_version":1,
            "disposition":"complete",
            "summary":summary,
            "clause_evidence":[
                {"clause_id":"requested-outcome","operation_ids":[operation_id],"event_sequences":[],"artifact_digests":[]},
                {"clause_id":"explicit-verification","operation_ids":[operation_id],"event_sequences":[],"artifact_digests":[]}
            ],
            "exact_identifiers":[]
        })
    )
}

#[derive(Clone, Copy)]
enum ApprovalStage {
    File,
    Command,
    Bypass,
}

struct PendingApproval {
    stage: ApprovalStage,
    thread_id: String,
    turn_id: String,
}

fn buzz_publish_fixture(arguments: &[OsString]) -> i32 {
    let required = ["BUZZ_RELAY_URL", "BUZZ_PRIVATE_KEY"];
    if required.iter().any(|name| std::env::var_os(name).is_none())
        || std::env::var_os("CODEX_HOME").is_some()
        || std::env::var_os("OPENAI_API_KEY").is_some()
    {
        return 77;
    }
    let channel_ok = argument_value(arguments, "--channel") == Some(CHANNEL_ID);
    let reply_ok = argument_value(arguments, "--reply-to").is_some_and(|reply| {
        reply.len() == 64 && reply.bytes().all(|byte| byte.is_ascii_hexdigit())
    });
    if !channel_ok || !reply_ok || !arguments.iter().any(|argument| argument == "--broadcast") {
        return 64;
    }
    let mut content = String::new();
    if std::io::stdin().read_to_string(&mut content).is_err() || content.is_empty() {
        return 74;
    }
    let record = json!({
        "channel":CHANNEL_ID,
        "reply_to":argument_value(arguments, "--reply-to"),
        "content":content,
        "environment_isolated":true
    });
    append_jsonl(
        &std::env::current_dir()
            .unwrap_or_default()
            .join(".buzz-publications.jsonl"),
        &record,
    )
    .map(|()| 0)
    .unwrap_or(73)
}

fn argument_value<'a>(arguments: &'a [OsString], flag: &str) -> Option<&'a str> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == flag)
        .and_then(|pair| pair[1].to_str())
}

fn thread(id: &str, cwd: &Path) -> Value {
    json!({
        "id":id, "preview":"", "modelProvider":"openai",
        "createdAt":0, "updatedAt":0, "status":{"type":"idle"},
        "path":null, "cwd":cwd, "cliVersion":"0.146.0", "source":"cli",
        "agentNickname":null, "agentRole":null, "gitInfo":null, "name":null,
        "turns":[], "sessionId":null, "ephemeral":false
    })
}

fn turn_started(thread_id: &str, turn_id: &str) -> std::io::Result<()> {
    notify(json!({
        "method":"turn/started", "params":{
            "threadId":thread_id,
            "turn":{"id":turn_id,"items":[],"status":"inProgress"}
        }
    }))
}

fn item_started(
    thread_id: &str,
    turn_id: &str,
    item_id: &str,
    item_type: &str,
) -> std::io::Result<()> {
    let item = match item_type {
        "commandExecution" => json!({
            "type":"commandExecution","id":item_id,"command":"cargo test",
            "cwd":"/workspace","status":"inProgress","commandActions":[]
        }),
        "fileChange" => file_change_fixture_item(item_id, "inProgress"),
        _ => return Err(std::io::Error::other("unsupported fixture item type")),
    };
    notify(json!({
        "method":"item/started", "params":{
            "threadId":thread_id,"turnId":turn_id,"startedAtMs":1,
            "item":item
        }
    }))
}

fn item_completed(
    thread_id: &str,
    turn_id: &str,
    item_id: &str,
    item_type: &str,
    succeeded: bool,
) -> std::io::Result<()> {
    let status = if succeeded { "completed" } else { "failed" };
    let item = match item_type {
        "commandExecution" => json!({
            "type":"commandExecution","id":item_id,"command":"cargo test",
            "cwd":"/workspace","status":status,"commandActions":[],
            "exitCode":succeeded.then_some(0),"aggregatedOutput":"ok"
        }),
        "fileChange" => file_change_fixture_item(item_id, status),
        _ => return Err(std::io::Error::other("unsupported fixture item type")),
    };
    notify(json!({
        "method":"item/completed", "params":{
            "threadId":thread_id,"turnId":turn_id,"completedAtMs":3,
            "item":item
        }
    }))
}

pub fn file_change_fixture_item(item_id: &str, status: &str) -> Value {
    json!({
        "type":"fileChange","id":item_id,"status":status,
        "changes":[{"path":"target.txt","kind":"update"}]
    })
}

fn agent_delta(thread_id: &str, turn_id: &str, text: &str) -> std::io::Result<()> {
    notify(json!({
        "method":"item/agentMessage/delta", "params":{
            "threadId":thread_id,"turnId":turn_id,"itemId":"agent-item","delta":text
        }
    }))
}

fn diff_update(thread_id: &str, turn_id: &str) -> std::io::Result<()> {
    notify(json!({
        "method":"turn/diff/updated", "params":{
            "threadId":thread_id,"turnId":turn_id,
            "diff":"diff --git a/target.txt b/target.txt\n-broken\n+fixed\n"
        }
    }))
}

fn turn_completed(thread_id: &str, turn_id: &str) -> std::io::Result<()> {
    notify(json!({
        "method":"turn/completed", "params":{
            "threadId":thread_id,"turn":{"id":turn_id,"items":[],"status":"completed"}
        }
    }))
}

fn approval_request(
    id: &str,
    method: &str,
    thread_id: &str,
    turn_id: &str,
    item_id: &str,
    extra: Value,
) -> std::io::Result<()> {
    let mut params = json!({
        "threadId":thread_id,"turnId":turn_id,"itemId":item_id,"startedAtMs":2
    });
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
    write_stdout(&json!({"id":id,"method":method,"params":params}))
}

fn respond(id: Option<Value>, result: Value) -> std::io::Result<()> {
    write_stdout(&json!({"id":id,"result":result}))
}

fn notify(value: Value) -> std::io::Result<()> {
    write_stdout(&value)
}

fn write_stdout(value: &Value) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, value)?;
    writeln!(stdout)?;
    stdout.flush()
}

fn workspace_for(home: &Path) -> PathBuf {
    home.parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .expect("fixture provider home has a data root")
        .join("workspace")
}

fn append_jsonl(path: &Path, value: &Value) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    serde_json::to_writer(&mut file, value)?;
    writeln!(file)
}

fn append_line(path: &Path, line: &str) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{line}")
}
