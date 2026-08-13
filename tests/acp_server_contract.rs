#[path = "support/private_dir.rs"]
mod private_dir;

use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use carl::acp::{AcpServer, IncomingFrame, JsonRpcId, Kernel, read_frame};
use carl::delegates::{ModelId, ReasoningEffort};
use carl::policy::Frontend;
use carl::runtime::agent_port::{
    AgentCapabilities, AgentContextId, AgentEpochId, AgentEvent, AgentFuture, AgentModel,
    AgentPort, AgentPortError, AgentPortErrorCode, AgentProcess, AgentRequestId, EffectDecision,
    ResumeAgentContext, StartAgentContext, StartAgentEpoch,
};
use carl::runtime::task::{ClauseStatus, CompletionClause, CompletionContract, TaskBudget};
use carl::sidecar::DataRootLock;
use carl::storage::{NewTask, RuntimeStore, Store};
use chrono::Utc;
use rusqlite::Connection;
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
                "jsonrpc":"2.0","id":20,"method":"_task/list","params":{
                    "sessionId":session_id
                }
            }))
            .await?;
        let listed = client.read().await?;
        assert_eq!(
            listed.value()["result"]["tasks"],
            json!([]),
            "{}",
            listed.value()
        );
        client
            .send(json!({
                "jsonrpc":"2.0","id":21,"method":"_task/cancel","params":{
                    "sessionId":session_id,
                    "taskId":Uuid::new_v4().to_string()
                }
            }))
            .await?;
        assert_eq!(client.read().await?.value()["error"]["code"], -32602);

        client
            .send(json!({
                "jsonrpc":"2.0","id":22,"method":"session/prompt","params":{
                    "sessionId":session_id,
                    "prompt":[{"type":"text","text":"/status"}]
                }
            }))
            .await?;
        let status_update = client.read().await?;
        assert_eq!(status_update.method(), Some("session/update"));
        assert_eq!(
            client.read().await?.value()["result"]["stopReason"],
            "end_turn"
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
async fn direct_metrics_extension_and_exact_slash_share_the_bound_sanitized_shape() -> TestResult {
    let layout = Layout::new()?;
    let kernel =
        Kernel::start_with_ports(layout.runtime()?, Box::new(FakePort::idle()?), None).await?;
    let mut client = Client::start(AcpServer::new(kernel, Frontend::Acp)).await;
    client
        .send(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":2,"clientInfo":{"name":"metrics","version":"1"}}}))
        .await?;
    client.read().await?;
    for id in [2, 3] {
        client
            .send(json!({"jsonrpc":"2.0","id":id,"method":"session/new","params":{"cwd":layout.workspace,"mcpServers":[]}}))
            .await?;
    }
    let first = client.read().await?;
    let second = client.read().await?;
    let first_session = first.value()["result"]["sessionId"]
        .as_str()
        .ok_or("first session missing")?
        .to_owned();
    let second_session = second.value()["result"]["sessionId"]
        .as_str()
        .ok_or("second session missing")?
        .to_owned();
    let mut store = Store::open(layout.root.join("carl.sqlite3"))?;
    let local_session = store
        .get_frontend_session(&first_session)?
        .ok_or("frontend binding missing")?
        .session_id;
    let task = store.create_task(NewTask {
        session_id: local_session,
        workspace: layout.workspace.clone(),
        contract: CompletionContract {
            version: 1,
            goal: "serve sanitized metrics".to_owned(),
            constraints: Vec::new(),
            clauses: Vec::new(),
        },
        model: ModelId::parse("gpt-5.6-codex")?,
        effort: ReasoningEffort::High,
        permission_mode: carl::acp::PermissionMode::Default,
        budget: TaskBudget::default(),
        created_at: Utc::now(),
    })?;
    drop(store);

    client
        .send(json!({"jsonrpc":"2.0","id":4,"method":"_task/metrics","params":{"sessionId":first_session,"taskId":task.snapshot.task_id}}))
        .await?;
    let extension = client.read().await?;
    let metrics = extension.value()["result"]["metrics"].clone();
    assert_eq!(metrics["schema_version"], 1);
    assert_eq!(metrics["task_id"], task.snapshot.task_id.to_string());
    assert_eq!(metrics["durable_event_count"], 1);

    client
        .send(json!({"jsonrpc":"2.0","id":5,"method":"session/prompt","params":{"sessionId":first_session,"prompt":[{"type":"text","text":"/metrics"}]}}))
        .await?;
    let update = client.read().await?;
    let slash_text = update.value()["params"]["update"]["content"]["text"]
        .as_str()
        .ok_or("metrics slash text missing")?;
    let slash: Value = serde_json::from_str(slash_text)?;
    assert_eq!(slash["metrics"], metrics);
    assert_eq!(
        client.read().await?.value()["result"]["stopReason"],
        "end_turn"
    );

    client
        .send(json!({"jsonrpc":"2.0","id":6,"method":"_task/metrics","params":{"sessionId":second_session,"taskId":task.snapshot.task_id}}))
        .await?;
    assert_eq!(client.read().await?.value()["error"]["code"], -32602);
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
    for (id, config_id, value) in [
        (39, "model", "gpt-5.6-codex"),
        (40, "thought_level", "high"),
        (41, "mode", "fullAccess"),
        (42, "mode", "plan"),
    ] {
        client
            .send(json!({
                "jsonrpc":"2.0","id":id,"method":"session/set_config_option","params":{
                    "sessionId":session_id,"configId":config_id,"value":value
                }
            }))
            .await?;
        assert!(client.read().await?.value()["result"]["configOptions"].is_array());
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
    client
        .send(json!({"jsonrpc":"2.0","id":5,"method":"session/prompt","params":{"sessionId":session_id,"prompt":[{"type":"text","text":"next epoch"}]}}))
        .await?;
    for _ in 0..100 {
        if state.lock().unwrap().starts == 2 {
            break;
        }
        tokio::task::yield_now().await;
    }
    client
        .send(json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":session_id}}))
        .await?;
    assert_eq!(client.read().await?.value()["id"], 5);
    {
        let state = state.lock().unwrap();
        assert_eq!(state.steers, ["focus on parsing"]);
        assert_eq!(state.interrupts, 3);
        assert_eq!(state.start_requests[1].model.as_str(), "gpt-5.6-codex");
        assert_eq!(state.start_requests[1].effort, ReasoningEffort::High);
        assert_eq!(
            state.start_requests[1].permission_mode,
            carl::acp::PermissionMode::Plan
        );
    }
    client.finish().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn task_resume_executes_a_bound_queued_task_and_returns_its_result() -> TestResult {
    let layout = Layout::new()?;
    let port = FakePort::autonomous_completion()?;
    let port_state = Arc::clone(&port.state);
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

    let mut store = Store::open(layout.root.join("carl.sqlite3"))?;
    let local_session = store
        .get_frontend_session(&session_id)?
        .ok_or("frontend binding missing")?
        .session_id;
    let persisted_budget = TaskBudget {
        max_wall_time_seconds: Some(7_200),
        max_provider_requests: Some(321),
        max_tool_calls: Some(654),
        soft_epoch_seconds: 600,
        soft_epoch_tool_calls: 77,
    };
    let task = store.create_task(NewTask {
        session_id: local_session,
        workspace: layout.workspace.clone(),
        contract: CompletionContract {
            version: 1,
            goal: "Finish the queued task".to_owned(),
            constraints: Vec::new(),
            clauses: vec![CompletionClause {
                id: "report".to_owned(),
                description: "Report completion".to_owned(),
                required: false,
                status: ClauseStatus::Pending,
                evidence: Vec::new(),
            }],
        },
        model: ModelId::parse("gpt-5.6-codex")?,
        effort: ReasoningEffort::Medium,
        permission_mode: carl::acp::PermissionMode::FullAccess,
        budget: persisted_budget,
        created_at: Utc::now(),
    })?;
    drop(store);

    Connection::open(layout.root.join("carl.sqlite3"))?.execute_batch(
        "CREATE TRIGGER fail_resume_receipt_completion
         BEFORE UPDATE OF state ON task_control_receipts
         WHEN NEW.state = 'completed' AND NEW.method = 'resume'
         BEGIN SELECT RAISE(ABORT, 'injected crash before resume receipt completion'); END;",
    )?;

    let mut request = json!({"jsonrpc":"2.0","id":3,"method":"_task/resume","params":{
        "sessionId":session_id,"taskId":task.snapshot.task_id.to_string(),
        "idempotencyKey":"resume-success"
    }});
    client.send(request.clone()).await?;
    let interrupted = client.read().await?;
    assert_eq!(interrupted.value()["error"]["code"], -32602);
    assert_eq!(port_state.lock().unwrap().starts, 1);
    Connection::open(layout.root.join("carl.sqlite3"))?
        .execute_batch("DROP TRIGGER fail_resume_receipt_completion;")?;

    request["id"] = json!(4);
    client.send(request).await?;
    let resumed = client.read().await?;
    assert_eq!(
        resumed.value()["result"]["outcome"],
        "accepted",
        "{}",
        resumed.value(),
    );
    assert_eq!(port_state.lock().unwrap().starts, 1);
    assert_eq!(
        Store::open(layout.root.join("carl.sqlite3"))?
            .get_task(task.snapshot.task_id)?
            .ok_or("resumed task missing")?
            .snapshot
            .budget,
        persisted_budget,
        "resuming through a default-config ACP server must retain persisted admission policy"
    );
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
    events: VecDeque<AgentEvent>,
    starts: usize,
    start_requests: Vec<StartAgentEpoch>,
    steers: Vec<String>,
    interrupts: usize,
}

impl FakePort {
    fn lifecycle() -> TestResult<Self> {
        Ok(Self::with_events([
            AgentEvent::EpochStarted {
                context_id: context()?,
                epoch_id: epoch()?,
            },
            AgentEvent::AssistantDelta {
                context_id: context()?,
                epoch_id: epoch()?,
                text: "Working".into(),
            },
            AgentEvent::AssistantDelta {
                context_id: context()?,
                epoch_id: epoch()?,
                text: "Done".into(),
            },
            AgentEvent::EpochCompleted {
                context_id: context()?,
                epoch_id: epoch()?,
                status: "completed".into(),
            },
        ]))
    }

    fn idle() -> TestResult<Self> {
        Ok(Self::with_events([]))
    }

    fn autonomous_completion() -> TestResult<Self> {
        Ok(Self::with_events([
            AgentEvent::EpochStarted {
                context_id: context()?,
                epoch_id: epoch()?,
            },
            AgentEvent::AssistantDelta {
                context_id: context()?,
                epoch_id: epoch()?,
                text: "Done. <carl-epoch-report>{\"schema_version\":1,\"disposition\":\"complete\",\"summary\":\"Done\",\"clause_evidence\":[],\"exact_identifiers\":[]}</carl-epoch-report>".into(),
            },
            AgentEvent::EpochCompleted {
                context_id: context()?,
                epoch_id: epoch()?,
                status: "completed".into(),
            },
        ]))
    }

    fn with_events<const N: usize>(events: [AgentEvent; N]) -> Self {
        Self {
            state: Arc::new(Mutex::new(PortState {
                events: events.into(),
                starts: 0,
                start_requests: Vec::new(),
                steers: Vec::new(),
                interrupts: 0,
            })),
        }
    }
}

impl AgentPort for FakePort {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            resume: true,
            compact: true,
            token_usage: true,
            pre_dispatch_effects: true,
            history_paging: false,
            background_processes: false,
        }
    }

    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>> {
        Box::pin(async {
            Ok(vec![AgentModel {
                id: ModelId::parse("gpt-5.6-codex").map_err(|_| invalid())?,
                display_name: "GPT-5.6 Codex".into(),
                supported_efforts: vec![ReasoningEffort::Medium, ReasoningEffort::High],
                default_effort: ReasoningEffort::Medium,
            }])
        })
    }
    fn start_context(&mut self, _request: StartAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async { context() })
    }
    fn resume_context(&mut self, request: ResumeAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async move { Ok(request.context_id) })
    }
    fn compact_context(&mut self, _context_id: &AgentContextId) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().unwrap().starts += 1;
            state.lock().unwrap().start_requests.push(request);
            epoch()
        })
    }
    fn steer(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
        input: String,
    ) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().unwrap().steers.push(input);
            Ok(())
        })
    }
    fn interrupt(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
    ) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().unwrap().interrupts += 1;
            Ok(())
        })
    }
    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent> {
        let event = self.state.lock().unwrap().events.pop_front();
        Box::pin(async move {
            match event {
                Some(event) => Ok(event),
                None => std::future::pending().await,
            }
        })
    }
    fn resolve_effect(
        &mut self,
        _request_id: &AgentRequestId,
        _decision: EffectDecision,
    ) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn list_background_processes(
        &mut self,
        _context_id: &AgentContextId,
    ) -> AgentFuture<'_, Vec<AgentProcess>> {
        Box::pin(async { Err(invalid()) })
    }
    fn terminate_background_process(
        &mut self,
        _context_id: &AgentContextId,
        _process_id: &str,
    ) -> AgentFuture<'_, bool> {
        Box::pin(async { Err(invalid()) })
    }
    fn shutdown(&mut self) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

fn context() -> Result<AgentContextId, AgentPortError> {
    AgentContextId::parse("thr_123")
}
fn epoch() -> Result<AgentEpochId, AgentPortError> {
    AgentEpochId::parse("turn_123")
}
fn invalid() -> AgentPortError {
    AgentPortError::from_code(AgentPortErrorCode::InvalidResponse)
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
        private_dir::make_owner_only_directory(&root)?;
        private_dir::make_owner_only_directory(&workspace)?;
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
