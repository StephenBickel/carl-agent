use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use serde_json::{Map, Value, json};
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    BuzzContext, BuzzPublisher, BuzzPublisherConfig, ConfigOutcome, ConfigSelection, IncomingFrame,
    JsonRpcId, KernelError, KernelHandle, KernelUpdate, OutgoingFrame, PermissionMode, Prompt,
    PromptStopReason, SessionConfiguration, ToolKind, ToolStatus, config_options, read_frame,
    write_frame,
};
use crate::delegates::{ModelId, ReasoningEffort};
use crate::events::SessionId;
use crate::policy::{ActorId, Frontend};
use crate::sidecar::{ExecutionWorkspace, TrustedExecutable};
use crate::storage::{ClientName, ExternalSessionId};

const MAX_FRAME_BYTES: usize = 1_048_576;
const WRITER_CAPACITY: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AcpServerErrorCode {
    #[error("ACP server input is invalid")]
    InvalidInput,
    #[error("ACP server transport failed")]
    Transport,
    #[error("ACP server kernel failed")]
    KernelFailed,
    #[error("ACP server output queue is unavailable")]
    OutputUnavailable,
    #[error("ACP server was cancelled")]
    Cancelled,
}

#[derive(Debug, Error)]
#[error("{code}")]
pub struct AcpServerError {
    code: AcpServerErrorCode,
}

impl AcpServerError {
    #[must_use]
    pub const fn code(&self) -> AcpServerErrorCode {
        self.code
    }

    const fn from_code(code: AcpServerErrorCode) -> Self {
        Self { code }
    }
}

#[derive(Clone)]
struct SessionBinding {
    local_id: SessionId,
    configuration: SessionConfiguration,
}

pub struct AcpServer {
    kernel: KernelHandle,
    config: AcpServerConfig,
    buzz_bootstrap: Option<BuzzPublisherBootstrap>,
    initialized: Option<InitializedClient>,
    sessions: HashMap<String, SessionBinding>,
}

pub struct BuzzPublisherBootstrap {
    executable: TrustedExecutable,
    workspace: ExecutionWorkspace,
}

impl BuzzPublisherBootstrap {
    #[must_use]
    pub const fn new(executable: TrustedExecutable, workspace: ExecutionWorkspace) -> Self {
        Self {
            executable,
            workspace,
        }
    }
}

impl fmt::Debug for BuzzPublisherBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BuzzPublisherBootstrap(<redacted>)")
    }
}

#[derive(Debug)]
pub struct AcpServerConfig {
    pub frontend: Frontend,
    pub model: Option<ModelId>,
    pub effort: Option<ReasoningEffort>,
    pub permission_mode: PermissionMode,
    pub buzz_publisher: Option<BuzzPublisherBootstrap>,
}

impl AcpServerConfig {
    #[must_use]
    pub const fn new(frontend: Frontend) -> Self {
        Self {
            frontend,
            model: None,
            effort: None,
            permission_mode: PermissionMode::Default,
            buzz_publisher: None,
        }
    }
}

impl fmt::Debug for AcpServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcpServer")
            .field("frontend", &self.config.frontend)
            .field("initialized", &self.initialized.is_some())
            .field("sessions", &self.sessions.len())
            .finish()
    }
}

#[derive(Clone)]
struct InitializedClient {
    protocol_version: u32,
    name: ClientName,
}

impl AcpServer {
    #[must_use]
    pub fn new(kernel: KernelHandle, frontend: Frontend) -> Self {
        Self::configured(kernel, AcpServerConfig::new(frontend))
    }

    #[must_use]
    pub fn configured(kernel: KernelHandle, mut config: AcpServerConfig) -> Self {
        let buzz_bootstrap = config.buzz_publisher.take();
        Self {
            kernel,
            config,
            buzz_bootstrap,
            initialized: None,
            sessions: HashMap::new(),
        }
    }

    pub async fn serve<R, W>(self, reader: R, writer: W) -> Result<(), AcpServerError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        self.serve_with_cancellation(reader, writer, CancellationToken::new())
            .await
    }

    pub async fn serve_with_cancellation<R, W>(
        mut self,
        mut reader: R,
        writer: W,
        cancellation: CancellationToken,
    ) -> Result<(), AcpServerError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (outbound, receiver) = mpsc::channel(WRITER_CAPACITY);
        let output_failed = CancellationToken::new();
        let writer_cancel = output_failed.clone();
        let writer_task =
            tokio::spawn(async move { writer_loop(writer, receiver, writer_cancel).await });
        let mut read_result = Ok(());
        loop {
            let frame = tokio::select! {
                () = output_failed.cancelled() => {
                    read_result = Err(server_error(AcpServerErrorCode::OutputUnavailable));
                    break;
                }
                () = cancellation.cancelled() => {
                    read_result = Err(server_error(AcpServerErrorCode::Cancelled));
                    break;
                }
                frame = read_frame(&mut reader, MAX_FRAME_BYTES) => frame,
            };
            let frame = match frame {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => {
                    read_result = Err(server_error(AcpServerErrorCode::InvalidInput));
                    break;
                }
            };
            if let Err(error) = self.dispatch(frame, &outbound, &output_failed).await {
                read_result = Err(error);
                break;
            }
        }
        let shutdown = self.kernel.shutdown().await;
        drop(outbound);
        let writer_result = writer_task
            .await
            .map_err(|_| server_error(AcpServerErrorCode::Transport))?;
        read_result?;
        shutdown.map_err(map_kernel)?;
        writer_result
    }

    async fn dispatch(
        &mut self,
        frame: IncomingFrame,
        outbound: &mpsc::Sender<OutgoingFrame>,
        cancelled: &CancellationToken,
    ) -> Result<(), AcpServerError> {
        let method = frame
            .method()
            .ok_or_else(|| server_error(AcpServerErrorCode::InvalidInput))?
            .to_owned();
        let id = frame.id().cloned();
        let value = frame.into_value();
        let params = value.get("params").cloned().unwrap_or_else(|| json!({}));

        match (method.as_str(), id) {
            ("initialize", Some(id)) => {
                let result = self.initialize(params);
                enqueue_result(outbound, id, result, cancelled)
            }
            ("session/new", Some(id)) => {
                let result = self.new_session(params).await;
                enqueue_result(outbound, id, result, cancelled)
            }
            ("session/set_config_option", Some(id)) => {
                let result = self.set_config(params).await;
                enqueue_result(outbound, id, result, cancelled)
            }
            ("session/prompt", Some(id)) => {
                let result = self
                    .start_prompt(params, id.clone(), outbound.clone(), cancelled.clone())
                    .await;
                if result.is_err() {
                    enqueue(
                        outbound,
                        OutgoingFrame::error(id, -32602, "invalid params"),
                        cancelled,
                    )?;
                }
                Ok(())
            }
            ("_session/steering", Some(id)) => {
                let result =
                    self.start_steering(params, id.clone(), outbound.clone(), cancelled.clone());
                if result.is_err() {
                    enqueue(
                        outbound,
                        OutgoingFrame::error(id, -32602, "invalid params"),
                        cancelled,
                    )?;
                }
                Ok(())
            }
            ("session/cancel", None) => {
                let _ = self.start_cancel(params);
                Ok(())
            }
            (_, Some(id)) => enqueue(
                outbound,
                OutgoingFrame::error(id, -32601, "method not found"),
                cancelled,
            ),
            (_, None) => Ok(()),
        }
    }

    fn initialize(&mut self, params: Value) -> Result<Value, AcpServerError> {
        if self.initialized.is_some() {
            return Err(server_error(AcpServerErrorCode::InvalidInput));
        }
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(
            params,
            &["protocolVersion", "clientInfo"],
            &["clientCapabilities"],
        )?;
        let protocol_version = params
            .get("protocolVersion")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| matches!(value, 1 | 2))
            .ok_or_else(invalid_input)?;
        let client = params
            .get("clientInfo")
            .and_then(Value::as_object)
            .ok_or_else(invalid_input)?;
        require_keys(client, &["name", "version"], &["title"])?;
        let name = bounded_string(client.get("name"), 128)?;
        let _version = bounded_string(client.get("version"), 128)?;
        let name = ClientName::try_from(name).map_err(|_| invalid_input())?;
        self.initialized = Some(InitializedClient {
            protocol_version,
            name,
        });
        Ok(json!({
            "protocolVersion":protocol_version,
            "agentCapabilities":{
                "loadSession":false,
                "promptCapabilities":{
                    "image":false,
                    "audio":false,
                    "embeddedContext":false,
                    "mcpCapabilities":{"http":false,"sse":false}
                },
                "sessionCapabilities":{}
            },
            "agentInfo":{"name":"carl","title":"Carl","version":env!("CARGO_PKG_VERSION")},
            "_meta":{"steering":{"supported":true}}
        }))
    }

    async fn new_session(&mut self, params: Value) -> Result<Value, AcpServerError> {
        let client = self.initialized.clone().ok_or_else(invalid_input)?;
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["cwd", "mcpServers"], &[])?;
        let cwd = PathBuf::from(bounded_string(params.get("cwd"), 32 * 1_024)?);
        let canonical = std::fs::canonicalize(&cwd).map_err(|_| invalid_input())?;
        if canonical != cwd || !canonical.is_dir() {
            return Err(invalid_input());
        }
        let mcp_servers = params.get("mcpServers").ok_or_else(invalid_input)?;
        let mcp_count = mcp_servers
            .as_array()
            .map(Vec::len)
            .ok_or_else(invalid_input)?;
        let publisher_config = match self.config.frontend {
            Frontend::Buzz => Some(
                BuzzPublisherConfig::from_mcp_servers(mcp_servers).map_err(|_| invalid_input())?,
            ),
            Frontend::Acp if mcp_count == 0 => None,
            _ => return Err(invalid_input()),
        };
        if let Some(bootstrap) = self.buzz_bootstrap.take() {
            let publisher = BuzzPublisher::connect(
                bootstrap.executable,
                bootstrap.workspace,
                publisher_config.ok_or_else(invalid_input)?,
            )
            .await
            .map_err(|_| invalid_input())?;
            self.kernel
                .install_publisher(Box::new(publisher))
                .await
                .map_err(map_kernel)?;
        }
        let external =
            ExternalSessionId::try_from(Uuid::new_v4().to_string()).map_err(|_| invalid_input())?;
        let session = self
            .kernel
            .new_session(super::NewSessionRequest {
                external_session_id: external.clone(),
                frontend: self.config.frontend,
                client_name: client.name,
                protocol_version: client.protocol_version,
                cwd,
                actor_id: ActorId::parse(if self.config.frontend == Frontend::Buzz {
                    "buzz-pending"
                } else {
                    "local-owner"
                })
                .map_err(|_| invalid_input())?,
                channel_id: None,
                buzz_context: None,
                model: self.config.model.clone(),
                effort: self.config.effort,
                mode: self.config.permission_mode,
            })
            .await
            .map_err(map_kernel)?;
        self.sessions.insert(
            external.as_str().to_owned(),
            SessionBinding {
                local_id: session.id(),
                configuration: session.configuration().clone(),
            },
        );
        Ok(json!({
            "sessionId":external.as_str(),
            "configOptions":session_config_options(self.kernel.catalog(), session.configuration())
        }))
    }

    async fn set_config(&mut self, params: Value) -> Result<Value, AcpServerError> {
        self.require_initialized()?;
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["sessionId", "configId", "value"], &[])?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let local_id = self
            .sessions
            .get(&external)
            .ok_or_else(invalid_input)?
            .local_id;
        let config_id = bounded_string(params.get("configId"), 64)?;
        let value = bounded_string(params.get("value"), 128)?;
        let selection = match config_id.as_str() {
            "model" => ConfigSelection::Model(ModelId::parse(value).map_err(|_| invalid_input())?),
            "thought_level" => ConfigSelection::Effort(parse_effort(&value)?),
            "mode" => ConfigSelection::Mode {
                mode: value.parse().map_err(|_| invalid_input())?,
                remote: self.config.frontend == Frontend::Buzz,
            },
            _ => return Err(invalid_input()),
        };
        let outcome = self
            .kernel
            .set_config(local_id, selection)
            .await
            .map_err(map_kernel)?;
        let binding = self.sessions.get_mut(&external).ok_or_else(invalid_input)?;
        let mut result;
        match outcome {
            ConfigOutcome::Applied(configuration) => {
                binding.configuration = configuration;
                result = json!({
                    "configOptions":session_config_options(
                        self.kernel.catalog(),
                        &binding.configuration
                    )
                });
            }
            ConfigOutcome::PendingBypass { display_code } => {
                result = json!({
                    "configOptions":session_config_options(
                        self.kernel.catalog(),
                        &binding.configuration
                    )
                });
                result["_meta"] = json!({"pendingBypassCode":display_code});
            }
        }
        Ok(result)
    }

    async fn start_prompt(
        &self,
        params: Value,
        id: JsonRpcId,
        outbound: mpsc::Sender<OutgoingFrame>,
        cancelled: CancellationToken,
    ) -> Result<(), AcpServerError> {
        self.require_initialized()?;
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["sessionId", "prompt"], &[])?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let local_id = self
            .sessions
            .get(&external)
            .ok_or_else(invalid_input)?
            .local_id;
        let blocks = parse_prompt_blocks(params.get("prompt"))?;
        let mut prompt = Prompt::new(blocks.clone()).map_err(map_kernel)?;
        if self.config.frontend == Frontend::Buzz {
            let refs = blocks.iter().map(String::as_str).collect::<Vec<_>>();
            let context = BuzzContext::parse(&refs).map_err(|_| invalid_input())?;
            self.kernel
                .attach_buzz_context(local_id, context.clone())
                .await
                .map_err(map_kernel)?;
            prompt = prompt
                .with_actor(ActorId::parse(context.actor_hex()).map_err(|_| invalid_input())?);
        }
        let kernel = self.kernel.clone();
        tokio::spawn(async move {
            match kernel.prompt(local_id, prompt).await {
                Ok(outcome) => {
                    let mut tools = HashMap::new();
                    for update in outcome.updates {
                        for params in render_update(&external, update, &mut tools) {
                            let Ok(frame) = OutgoingFrame::notification("session/update", params)
                            else {
                                cancelled.cancel();
                                return;
                            };
                            if enqueue(&outbound, frame, &cancelled).is_err() {
                                return;
                            }
                        }
                    }
                    let frame = OutgoingFrame::result(
                        id,
                        json!({"stopReason":stop_reason(outcome.stop_reason)}),
                    );
                    let _ = enqueue(&outbound, frame, &cancelled);
                }
                Err(_) => {
                    let _ = enqueue(
                        &outbound,
                        OutgoingFrame::error(id, -32000, "kernel request failed"),
                        &cancelled,
                    );
                }
            }
        });
        Ok(())
    }

    fn start_steering(
        &self,
        params: Value,
        id: JsonRpcId,
        outbound: mpsc::Sender<OutgoingFrame>,
        cancelled: CancellationToken,
    ) -> Result<(), AcpServerError> {
        self.require_initialized()?;
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["sessionId", "prompt"], &[])?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let session = self.sessions.get(&external).ok_or_else(invalid_input)?;
        let blocks = parse_prompt_blocks(params.get("prompt"))?;
        let input = blocks.join("\n\n");
        let kernel = self.kernel.clone();
        let local_id = session.local_id;
        tokio::spawn(async move {
            let frame = match kernel.steer(local_id, input).await {
                Ok(()) => OutgoingFrame::result(id, json!({"outcome":"injected"})),
                Err(_) => OutgoingFrame::error(id, -32000, "steering failed"),
            };
            let _ = enqueue(&outbound, frame, &cancelled);
        });
        Ok(())
    }

    fn start_cancel(&self, params: Value) -> Result<(), AcpServerError> {
        self.require_initialized()?;
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["sessionId"], &[])?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let session = self.sessions.get(&external).ok_or_else(invalid_input)?;
        let kernel = self.kernel.clone();
        let local_id = session.local_id;
        tokio::spawn(async move {
            let _ = kernel.cancel(local_id).await;
        });
        Ok(())
    }

    fn require_initialized(&self) -> Result<(), AcpServerError> {
        self.initialized
            .as_ref()
            .map(|_| ())
            .ok_or_else(invalid_input)
    }
}

fn enqueue_result(
    outbound: &mpsc::Sender<OutgoingFrame>,
    id: JsonRpcId,
    result: Result<Value, AcpServerError>,
    cancelled: &CancellationToken,
) -> Result<(), AcpServerError> {
    let frame = match result {
        Ok(result) => OutgoingFrame::result(id, result),
        Err(_) => OutgoingFrame::error(id, -32602, "invalid params"),
    };
    enqueue(outbound, frame, cancelled)
}

fn enqueue(
    outbound: &mpsc::Sender<OutgoingFrame>,
    frame: OutgoingFrame,
    cancelled: &CancellationToken,
) -> Result<(), AcpServerError> {
    outbound.try_send(frame).map_err(|_| {
        cancelled.cancel();
        server_error(AcpServerErrorCode::OutputUnavailable)
    })
}

async fn writer_loop<W>(
    mut writer: W,
    mut receiver: mpsc::Receiver<OutgoingFrame>,
    cancelled: CancellationToken,
) -> Result<(), AcpServerError>
where
    W: AsyncWrite + Unpin,
{
    while let Some(frame) = receiver.recv().await {
        if write_frame(&mut writer, &frame, MAX_FRAME_BYTES)
            .await
            .is_err()
        {
            cancelled.cancel();
            return Err(server_error(AcpServerErrorCode::Transport));
        }
    }
    Ok(())
}

fn render_update(
    session_id: &str,
    update: KernelUpdate,
    tools: &mut HashMap<String, String>,
) -> Vec<Value> {
    match update {
        KernelUpdate::AgentMessageChunk(text) => vec![json!({
            "sessionId":session_id,
            "update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":text}}
        })],
        KernelUpdate::ToolStarted { title, kind } => {
            let id = Uuid::new_v4().to_string();
            tools.insert(title.clone(), id.clone());
            vec![json!({
                "sessionId":session_id,
                "update":{
                    "sessionUpdate":"tool_call", "toolCallId":id, "title":title,
                    "kind":match kind { ToolKind::Execute => "execute", ToolKind::Edit => "edit" },
                    "status":"pending"
                }
            })]
        }
        KernelUpdate::ToolCompleted { title, status } => {
            let id = tools
                .remove(&title)
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            vec![json!({
                "sessionId":session_id,
                "update":{
                    "sessionUpdate":"tool_call_update", "toolCallId":id,
                    "status":match status {
                        ToolStatus::Pending => "pending",
                        ToolStatus::Completed => "completed",
                        ToolStatus::Failed => "failed"
                    }
                }
            })]
        }
        KernelUpdate::DiffUpdated(diff) => {
            let id = Uuid::new_v4().to_string();
            vec![
                json!({
                    "sessionId":session_id,
                    "update":{
                        "sessionUpdate":"tool_call", "toolCallId":id, "title":"Workspace diff",
                        "kind":"edit", "status":"in_progress", "content":[{"type":"diff","diff":diff}]
                    }
                }),
                json!({
                    "sessionId":session_id,
                    "update":{"sessionUpdate":"tool_call_update","toolCallId":id,"status":"completed"}
                }),
            ]
        }
        KernelUpdate::AvailableCommandsChanged => vec![json!({
            "sessionId":session_id,
            "update":{
                "sessionUpdate":"available_commands_update",
                "availableCommands":[
                    {"name":"approve","description":"Approve the exact pending request","input":{"hint":"<code>"}},
                    {"name":"deny","description":"Deny the exact pending request","input":{"hint":"<code>"}},
                    {"name":"permissions","description":"Change permission mode","input":{"hint":"<mode>"}}
                ]
            }
        })],
        KernelUpdate::SessionInfoChanged { configuration } => vec![json!({
            "sessionId":session_id,
            "update":{
                "sessionUpdate":"session_info_update",
                "_meta":{
                    "model":configuration.model().as_str(),
                    "thoughtLevel":configuration.effort().as_codex_value(),
                    "mode":configuration.mode().as_wire_str()
                }
            }
        })],
        KernelUpdate::TaskStatus { task_id, status } => vec![json!({
            "sessionUpdate":"task_status",
            "taskId":task_id.to_string(),
            "status":status,
        })],
        KernelUpdate::EpochObjective {
            task_id,
            epoch_id,
            objective,
        } => vec![json!({
            "sessionUpdate":"epoch_objective",
            "taskId":task_id.to_string(),
            "epochId":epoch_id.to_string(),
            "objective":objective,
        })],
        KernelUpdate::CheckpointCommitted {
            task_id,
            checkpoint_id,
            digest,
        } => vec![json!({
            "sessionUpdate":"checkpoint_committed",
            "taskId":task_id.to_string(),
            "checkpointId":checkpoint_id.to_string(),
            "digest":digest,
        })],
        KernelUpdate::ContextUsage {
            task_id,
            total_tokens,
            context_window,
        } => vec![json!({
            "sessionUpdate":"context_usage",
            "taskId":task_id.to_string(),
            "totalTokens":total_tokens,
            "contextWindow":context_window,
        })],
        KernelUpdate::Compaction {
            task_id,
            generation,
            replaced_provider,
        } => vec![json!({
            "sessionUpdate":"compaction",
            "taskId":task_id.to_string(),
            "generation":generation,
            "replacedProvider":replaced_provider,
        })],
        KernelUpdate::RecoveryStrategy { task_id, strategy } => vec![json!({
            "sessionUpdate":"recovery_strategy",
            "taskId":task_id.to_string(),
            "strategy":strategy,
        })],
        KernelUpdate::CompletionClauses { task_id, clauses } => vec![json!({
            "sessionUpdate":"completion_clauses",
            "taskId":task_id.to_string(),
            "clauses":clauses,
        })],
    }
}

fn session_config_options(
    catalog: &super::ModelCatalog,
    configuration: &SessionConfiguration,
) -> Vec<Value> {
    let mut options = config_options(catalog);
    options[0]["currentValue"] = json!(configuration.model().as_str());
    options[1]["currentValue"] = json!(configuration.effort().as_codex_value());
    if let Some(model) = catalog.find(configuration.model()) {
        options[1]["options"] = Value::Array(
            model
                .supported_efforts()
                .iter()
                .map(|effort| {
                    json!({
                        "value":effort.as_codex_value(),
                        "displayName":match effort {
                            ReasoningEffort::Low => "Low",
                            ReasoningEffort::Medium => "Medium",
                            ReasoningEffort::High => "High",
                            ReasoningEffort::XHigh => "Extra high",
                            ReasoningEffort::Max => "Max",
                            ReasoningEffort::Ultra => "Ultra",
                        }
                    })
                })
                .collect(),
        );
    }
    options[2]["currentValue"] = json!(configuration.mode().as_wire_str());
    options
}

fn parse_prompt_blocks(value: Option<&Value>) -> Result<Vec<String>, AcpServerError> {
    let blocks = value.and_then(Value::as_array).ok_or_else(invalid_input)?;
    if blocks.is_empty() || blocks.len() > 12 {
        return Err(invalid_input());
    }
    blocks
        .iter()
        .map(|block| {
            let block = block.as_object().ok_or_else(invalid_input)?;
            require_keys(block, &["type", "text"], &[])?;
            if block.get("type").and_then(Value::as_str) != Some("text") {
                return Err(invalid_input());
            }
            bounded_text(block.get("text"), 256 * 1_024)
        })
        .collect()
}

fn require_keys(
    object: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), AcpServerError> {
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(invalid_input());
    }
    Ok(())
}

fn bounded_string(value: Option<&Value>, maximum: usize) -> Result<String, AcpServerError> {
    let value = value.and_then(Value::as_str).ok_or_else(invalid_input)?;
    if value.is_empty()
        || value.len() > maximum
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(invalid_input());
    }
    Ok(value.to_owned())
}

fn bounded_text(value: Option<&Value>, maximum: usize) -> Result<String, AcpServerError> {
    let value = value.and_then(Value::as_str).ok_or_else(invalid_input)?;
    if value.is_empty() || value.len() > maximum || value.as_bytes().contains(&0) {
        return Err(invalid_input());
    }
    Ok(value.to_owned())
}

fn parse_effort(value: &str) -> Result<ReasoningEffort, AcpServerError> {
    match value {
        "low" => Ok(ReasoningEffort::Low),
        "medium" => Ok(ReasoningEffort::Medium),
        "high" => Ok(ReasoningEffort::High),
        "xhigh" => Ok(ReasoningEffort::XHigh),
        "max" => Ok(ReasoningEffort::Max),
        "ultra" => Ok(ReasoningEffort::Ultra),
        _ => Err(invalid_input()),
    }
}

const fn stop_reason(reason: PromptStopReason) -> &'static str {
    match reason {
        PromptStopReason::EndTurn => "end_turn",
        PromptStopReason::WaitingForApproval => "waiting_for_approval",
        PromptStopReason::Cancelled => "cancelled",
        PromptStopReason::Failed => "failed",
    }
}

fn map_kernel(_error: KernelError) -> AcpServerError {
    server_error(AcpServerErrorCode::KernelFailed)
}

const fn invalid_input() -> AcpServerError {
    server_error(AcpServerErrorCode::InvalidInput)
}

const fn server_error(code: AcpServerErrorCode) -> AcpServerError {
    AcpServerError::from_code(code)
}
