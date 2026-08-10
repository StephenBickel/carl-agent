use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use carl::acp::{AcpServer, CodexPort, IncomingFrame, JsonRpcId, Kernel, PortFuture, read_frame};
use carl::delegates::codex::{
    CodexApprovalDecision, CodexApprovalRequest, CodexEvent, CodexModel, CodexThreadId,
    CodexTurnId, StartThread, StartTurn,
};
use carl::delegates::{ModelId, ReasoningEffort};
use carl::policy::Frontend;
use carl::sidecar::DataRootLock;
use carl::storage::RuntimeStore;
use chrono::Utc;
use serde_json::{Value, json};
use tokio::io::{AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[tokio::test(flavor = "current_thread")]
async fn initialization_sessions_configuration_and_prompt_updates_are_exact() -> TestResult {
    for protocol_version in [1, 2] {
        let layout = Layout::new()?;
        let port = FakePort::lifecycle()?;
        let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
        let mut client = Client::start(AcpServer::new(kernel, Frontend::Acp)).await;

        client
            .send(json!({
                "jsonrpc":"2.0","id":1,"method":"initialize","params":{
                    "protocolVersion":protocol_version,
                    "clientInfo":{"name":"contract","version":"1.0.0"},
                    "clientCapabilities":{}
                }
            }))
            .await?;
        let initialized = client.read().await?;
        assert_eq!(initialized.value()["id"], 1);
        assert_eq!(
            initialized.value()["result"]["protocolVersion"],
            protocol_version
        );
        assert_eq!(initialized.value()["result"]["agentInfo"]["name"], "carl");
        assert_eq!(
            initialized.value()["result"]["agentCapabilities"]["loadSession"],
            false
        );
        assert_eq!(
            initialized.value()["result"]["_meta"]["steering"]["supported"],
            true
        );

        client
            .send(json!({
                "jsonrpc":"2.0","id":2,"method":"session/new","params":{
                    "cwd":layout.workspace,"mcpServers":[]
                }
            }))
            .await?;
        let created = client.read().await?;
        let session_id = created.value()["result"]["sessionId"]
            .as_str()
            .ok_or("session ID missing")?
            .to_owned();
        assert_eq!(
            created.value()["result"]["configOptions"][0]["configId"],
            "model"
        );

        client
            .send(json!({
                "jsonrpc":"2.0","id":3,"method":"session/set_config_option","params":{
                    "sessionId":session_id,"configId":"mode","value":"acceptEdits"
                }
            }))
            .await?;
        let configured = client.read().await?;
        assert_eq!(configured.value()["id"], 3);

        client
            .send(json!({
                "jsonrpc":"2.0","id":4,"method":"session/prompt","params":{
                    "sessionId":session_id,
                    "prompt":[{"type":"text","text":"inspect this repo"}]
                }
            }))
            .await?;
        let mut update_kinds = Vec::new();
        loop {
            let frame = client.read().await?;
            if frame.id() == Some(&JsonRpcId::Number(4)) {
                assert_eq!(frame.value()["result"]["stopReason"], "end_turn");
                break;
            }
            assert_eq!(frame.method(), Some("session/update"));
            update_kinds.push(
                frame.value()["params"]["update"]["sessionUpdate"]
                    .as_str()
                    .ok_or("update kind missing")?
                    .to_owned(),
            );
        }
        assert_eq!(update_kinds, ["agent_message_chunk", "agent_message_chunk"]);
        client.finish().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_methods_are_isolated_and_requests_before_initialize_fail_closed() -> TestResult {
    let layout = Layout::new()?;
    let kernel =
        Kernel::start_with_ports(layout.runtime()?, Box::new(FakePort::idle()?), None).await?;
    let mut client = Client::start(AcpServer::new(kernel, Frontend::Acp)).await;
    client
        .send(json!({"jsonrpc":"2.0","id":1,"method":"session/new","params":{"cwd":layout.workspace,"mcpServers":[]}}))
        .await?;
    let invalid = client.read().await?;
    assert_eq!(invalid.value()["error"]["code"], -32602);
    client
        .send(json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":2,"clientInfo":{"name":"contract","version":"1"}}}))
        .await?;
    assert_eq!(client.read().await?.value()["id"], 2);
    client
        .send(json!({"jsonrpc":"2.0","id":3,"method":"future/method","params":{}}))
        .await?;
    let unknown = client.read().await?;
    assert_eq!(unknown.value()["error"]["code"], -32601);
    client.finish().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn steering_and_idless_cancellation_remain_responsive_during_prompt() -> TestResult {
    let layout = Layout::new()?;
    let port = FakePort::idle()?;
    let state = Arc::clone(&port.state);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let mut client = Client::start(AcpServer::new(kernel, Frontend::Acp)).await;
    client
        .send(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":2,"clientInfo":{"name":"contract","version":"1"}}}))
        .await?;
    client.read().await?;
    client
        .send(json!({"jsonrpc":"2.0","id":2,"method":"session/new","params":{"cwd":layout.workspace,"mcpServers":[]}}))
        .await?;
    let session_id = client.read().await?.value()["result"]["sessionId"]
        .as_str()
        .ok_or("session missing")?
        .to_owned();
    client
        .send(json!({"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":session_id,"prompt":[{"type":"text","text":"keep working"}]}}))
        .await?;
    for _ in 0..100 {
        if state.lock().unwrap().starts == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    client
        .send(json!({"jsonrpc":"2.0","id":4,"method":"_session/steering","params":{"sessionId":session_id,"prompt":[{"type":"text","text":"focus on parsing"}]}}))
        .await?;
    let steered = client.read().await?;
    assert_eq!(steered.value()["result"]["outcome"], "injected");
    client
        .send(json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":session_id}}))
        .await?;
    let cancelled = client.read().await?;
    assert_eq!(cancelled.value()["id"], 3);
    assert_eq!(cancelled.value()["result"]["stopReason"], "cancelled");
    {
        let state = state.lock().unwrap();
        assert_eq!(state.steers, ["focus on parsing"]);
        assert_eq!(state.interrupts, 1);
    }
    client.finish().await?;
    Ok(())
}

struct Client {
    reader: BufReader<ReadHalf<DuplexStream>>,
    writer: Option<WriteHalf<DuplexStream>>,
    server: tokio::task::JoinHandle<Result<(), carl::acp::AcpServerError>>,
}

impl Client {
    async fn start(server: AcpServer) -> Self {
        let (client, server_io) = tokio::io::duplex(2 * 1_048_576);
        let (client_read, client_write) = tokio::io::split(client);
        let (server_read, server_write) = tokio::io::split(server_io);
        let server = tokio::spawn(server.serve(BufReader::new(server_read), server_write));
        Self {
            reader: BufReader::new(client_read),
            writer: Some(client_write),
            server,
        }
    }

    async fn send(&mut self, value: Value) -> TestResult {
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        self.writer
            .as_mut()
            .ok_or("client closed")?
            .write_all(&bytes)
            .await?;
        Ok(())
    }

    async fn read(&mut self) -> TestResult<IncomingFrame> {
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            read_frame(&mut self.reader, 1_048_576),
        )
        .await
        .map_err(|_| "server response timed out")??
        .ok_or_else(|| "server closed".into())
    }

    async fn finish(mut self) -> TestResult {
        if let Some(mut writer) = self.writer.take() {
            writer.shutdown().await?;
        }
        tokio::time::timeout(std::time::Duration::from_secs(3), self.server)
            .await
            .map_err(|_| "server shutdown timed out")???;
        Ok(())
    }
}

struct FakePort {
    state: Arc<Mutex<PortState>>,
}

struct PortState {
    events: VecDeque<CodexEvent>,
    starts: usize,
    steers: Vec<String>,
    interrupts: usize,
}

impl FakePort {
    fn lifecycle() -> TestResult<Self> {
        Ok(Self::with_events([
            CodexEvent::TurnStarted {
                thread_id: thread()?,
                turn_id: turn()?,
            },
            CodexEvent::AgentMessageDelta {
                thread_id: thread()?,
                turn_id: turn()?,
                item_id: "message".into(),
                text: "Working".into(),
            },
            CodexEvent::AgentMessageDelta {
                thread_id: thread()?,
                turn_id: turn()?,
                item_id: "message".into(),
                text: "Done".into(),
            },
            CodexEvent::TurnCompleted {
                thread_id: thread()?,
                turn_id: turn()?,
                status: "completed".into(),
            },
        ]))
    }

    fn idle() -> TestResult<Self> {
        Ok(Self::with_events([]))
    }

    fn with_events<const N: usize>(events: [CodexEvent; N]) -> Self {
        Self {
            state: Arc::new(Mutex::new(PortState {
                events: events.into(),
                starts: 0,
                steers: Vec::new(),
                interrupts: 0,
            })),
        }
    }
}

impl CodexPort for FakePort {
    fn models(&mut self) -> PortFuture<'_, Vec<CodexModel>> {
        Box::pin(async {
            Ok(vec![
                CodexModel::new(
                    ModelId::parse("gpt-5.6-codex").map_err(|_| invalid())?,
                    "GPT-5.6 Codex",
                    vec![ReasoningEffort::Medium, ReasoningEffort::High],
                    ReasoningEffort::Medium,
                )
                .map_err(|_| invalid())?,
            ])
        })
    }
    fn start_thread(&mut self, _request: StartThread) -> PortFuture<'_, CodexThreadId> {
        Box::pin(async { thread().map_err(|_| invalid()) })
    }
    fn start_turn(&mut self, _request: StartTurn) -> PortFuture<'_, CodexTurnId> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().unwrap().starts += 1;
            turn().map_err(|_| invalid())
        })
    }
    fn steer(
        &mut self,
        _thread_id: &CodexThreadId,
        _turn_id: &CodexTurnId,
        input: String,
    ) -> PortFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().unwrap().steers.push(input);
            Ok(())
        })
    }
    fn interrupt(
        &mut self,
        _thread_id: &CodexThreadId,
        _turn_id: &CodexTurnId,
    ) -> PortFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().unwrap().interrupts += 1;
            Ok(())
        })
    }
    fn next_event(&mut self) -> PortFuture<'_, CodexEvent> {
        let event = self.state.lock().unwrap().events.pop_front();
        Box::pin(async move {
            match event {
                Some(event) => Ok(event),
                None => std::future::pending().await,
            }
        })
    }
    fn resolve_approval(
        &mut self,
        _approval: &CodexApprovalRequest,
        _decision: CodexApprovalDecision,
    ) -> PortFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn cancel(&mut self) -> PortFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

fn thread() -> Result<CodexThreadId, carl::delegates::codex::DelegateError> {
    CodexThreadId::parse("thr_123")
}
fn turn() -> Result<CodexTurnId, carl::delegates::codex::DelegateError> {
    CodexTurnId::parse("turn_123")
}
fn invalid() -> carl::acp::KernelError {
    carl::acp::KernelError::from_code(carl::acp::KernelErrorCode::ProviderFailed)
}

struct Layout {
    root: PathBuf,
    workspace: PathBuf,
}
impl Layout {
    fn new() -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!("carl-acp-server-{}", Uuid::new_v4()));
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace)?;
        make_owner_only(&root)?;
        make_owner_only(&workspace)?;
        Ok(Self {
            root,
            workspace: fs::canonicalize(workspace)?,
        })
    }
    fn runtime(&self) -> TestResult<RuntimeStore> {
        Ok(RuntimeStore::open(
            DataRootLock::acquire(&self.root)?,
            Utc::now(),
        )?)
    }
}
impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
fn make_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}
#[cfg(windows)]
fn make_owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
