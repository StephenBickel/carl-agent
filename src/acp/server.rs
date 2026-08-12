use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use chrono::Utc;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    BuzzContext, BuzzPublisher, BuzzPublisherConfig, ConfigOutcome, ConfigSelection, IncomingFrame,
    JsonRpcId, KernelError, KernelErrorCode, KernelHandle, KernelUpdate, OutgoingFrame,
    PermissionMode, Prompt, PromptStopReason, SessionConfiguration, ToolKind, ToolStatus,
    config_options, read_frame, write_frame,
};
use crate::delegates::{ModelId, ReasoningEffort};
use crate::events::{Event, EventEnvelope, SessionId};
use crate::policy::{ActorId, Frontend, Sha256Digest};
use crate::runtime::task::{TaskBudget, TaskEvent, TaskId, TaskStatus};
use crate::service::client::TaskServiceClient;
use crate::service::protocol::{
    SERVICE_PROTOCOL_VERSION, ServiceApprovalDecision, ServiceCommand, ServiceRequest,
    ServiceResult, StartTaskCommand, TaskUpdate, TrustedStartTaskCommand,
};
use crate::sidecar::{ExecutionWorkspace, TrustedExecutable};
use crate::storage::{
    ClientName, ExternalSessionId, TaskControlMutationClaim, TaskControlMutationInput,
};

use super::session::exact_task_metrics_command;

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
    pub budget: TaskBudget,
    pub buzz_publisher: Option<BuzzPublisherBootstrap>,
}

impl AcpServerConfig {
    #[must_use]
    pub fn new(frontend: Frontend) -> Self {
        Self {
            frontend,
            model: None,
            effort: None,
            permission_mode: PermissionMode::Default,
            budget: TaskBudget::default(),
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
            ("_task/status", Some(id)) => {
                let result = self.task_status(params).await;
                enqueue_result(outbound, id, result, cancelled)
            }
            ("_task/metrics", Some(id)) => {
                let result = self.task_metrics(params).await;
                enqueue_result(outbound, id, result, cancelled)
            }
            ("_task/list", Some(id)) => {
                let result = self.task_list(params).await;
                enqueue_result(outbound, id, result, cancelled)
            }
            ("_task/context", Some(id)) => {
                let result = self.task_context(params).await;
                enqueue_result(outbound, id, result, cancelled)
            }
            ("_task/resume", Some(id)) => {
                let result = self.task_mutation("resume", params).await;
                enqueue_result(outbound, id, result, cancelled)
            }
            ("_task/cancel", Some(id)) => {
                let result = self.task_mutation("cancel", params).await;
                enqueue_result(outbound, id, result, cancelled)
            }
            ("_task/steer", Some(id)) => {
                let result = self.task_mutation("steer", params).await;
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
                budget: self.config.budget,
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

    async fn task_status(&self, params: Value) -> Result<Value, AcpServerError> {
        self.require_initialized()?;
        let (local_id, task_id) = self.parse_task_binding(&params, &[])?;
        let task = self
            .kernel
            .task_status(local_id, task_id)
            .await
            .map_err(map_kernel)?;
        Ok(json!({"task":task}))
    }

    async fn task_list(&self, params: Value) -> Result<Value, AcpServerError> {
        self.require_initialized()?;
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["sessionId"], &[])?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let local_id = self
            .sessions
            .get(&external)
            .ok_or_else(invalid_input)?
            .local_id;
        let tasks = self.kernel.task_list(local_id).await.map_err(map_kernel)?;
        Ok(json!({"tasks":tasks}))
    }

    async fn task_metrics(&self, params: Value) -> Result<Value, AcpServerError> {
        self.require_initialized()?;
        let (local_id, task_id) = self.parse_task_binding(&params, &[])?;
        let metrics = self
            .kernel
            .task_metrics(local_id, task_id)
            .await
            .map_err(map_kernel)?;
        Ok(json!({"metrics":metrics}))
    }

    async fn task_context(&self, params: Value) -> Result<Value, AcpServerError> {
        self.require_initialized()?;
        let (local_id, task_id) = self.parse_task_binding(&params, &[])?;
        let context = self
            .kernel
            .task_context(local_id, task_id)
            .await
            .map_err(map_kernel)?;
        Ok(json!({"context":context}))
    }

    async fn task_mutation(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<Value, AcpServerError> {
        self.require_initialized()?;
        let optional = if method == "steer" {
            &["text"][..]
        } else {
            &[][..]
        };
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["sessionId", "taskId", "idempotencyKey"], optional)?;
        if method == "steer" && !params.contains_key("text") {
            return Err(invalid_input());
        }
        let external = bounded_string(params.get("sessionId"), 128)?;
        let binding = self.sessions.get(&external).ok_or_else(invalid_input)?;
        let task_id = bounded_string(params.get("taskId"), 128)?
            .parse::<TaskId>()
            .map_err(|_| invalid_input())?;
        let idempotency_key = bounded_string(params.get("idempotencyKey"), 128)?;
        let control_id = task_control_identity(&external, &idempotency_key, task_id, method);
        let text = if method == "steer" {
            Some(bounded_text(params.get("text"), 256 * 1_024)?)
        } else {
            None
        };
        let current = self
            .kernel
            .task_status(binding.local_id, task_id)
            .await
            .map_err(map_kernel)?;
        let result = json!({"outcome":"accepted","taskId":task_id});
        let result_json = serde_json::to_string(&result).map_err(|_| invalid_input())?;
        let request_digest = task_control_digest(method, task_id, text.as_deref());
        let mutation = TaskControlMutationInput {
            external_session_id: ExternalSessionId::try_from(external)
                .map_err(|_| invalid_input())?,
            idempotency_key,
            task_id,
            method: method.to_owned(),
            request_digest,
            result_json: result_json.clone(),
            created_at: Utc::now(),
        };
        let claim = self
            .kernel
            .claim_task_mutation(mutation.clone())
            .await
            .map_err(map_kernel)?;
        match claim {
            TaskControlMutationClaim::Replay {
                result_json,
                failure_code,
            } => {
                if failure_code.is_some() {
                    Err(invalid_input())
                } else {
                    serde_json::from_str(&result_json).map_err(|_| invalid_input())
                }
            }
            claim @ (TaskControlMutationClaim::Fresh | TaskControlMutationClaim::Pending) => {
                if matches!(claim, TaskControlMutationClaim::Fresh) && current.status.is_terminal()
                {
                    let mut failure = mutation;
                    failure.result_json =
                        format!(r#"{{"outcome":"rejected","taskId":"{task_id}"}}"#);
                    failure.created_at = Utc::now();
                    self.kernel
                        .fail_task_mutation(failure)
                        .await
                        .map_err(map_kernel)?;
                    return Err(invalid_input());
                }
                let action = match method {
                    "resume" => self
                        .kernel
                        .task_resume(binding.local_id, task_id, control_id)
                        .await
                        .map(|_| ()),
                    "cancel" => {
                        self.kernel
                            .task_cancel(binding.local_id, task_id, control_id)
                            .await
                    }
                    "steer" => {
                        self.kernel
                            .task_steer(
                                binding.local_id,
                                task_id,
                                text.ok_or_else(invalid_input)?,
                                control_id,
                            )
                            .await
                    }
                    _ => return Err(invalid_input()),
                };
                if let Err(error) = action {
                    if error.code() == KernelErrorCode::InvalidInput {
                        let mut failure = mutation;
                        failure.result_json =
                            format!(r#"{{"outcome":"rejected","taskId":"{task_id}"}}"#);
                        failure.created_at = Utc::now();
                        self.kernel
                            .fail_task_mutation(failure)
                            .await
                            .map_err(map_kernel)?;
                    }
                    return Err(map_kernel(error));
                }
                let mut completion = mutation;
                completion.created_at = Utc::now();
                let completed = self
                    .kernel
                    .complete_task_mutation(completion)
                    .await
                    .map_err(map_kernel)?;
                serde_json::from_str(&completed).map_err(|_| invalid_input())
            }
        }
    }

    fn parse_task_binding(
        &self,
        params: &Value,
        optional: &[&str],
    ) -> Result<(SessionId, TaskId), AcpServerError> {
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["sessionId", "taskId"], optional)?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let local_id = self
            .sessions
            .get(&external)
            .ok_or_else(invalid_input)?
            .local_id;
        let task_id = bounded_string(params.get("taskId"), 128)?
            .parse::<TaskId>()
            .map_err(|_| invalid_input())?;
        Ok((local_id, task_id))
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

#[derive(Clone)]
struct ServiceSessionBinding {
    cwd: PathBuf,
    model: ModelId,
    effort: ReasoningEffort,
    permission_mode: PermissionMode,
    budget: TaskBudget,
    task_id: Option<TaskId>,
    last_event_cursor: Option<u64>,
    live_generation: String,
    last_live_cursor: Option<u64>,
    stream_generation: u64,
    prompt_active: bool,
    buzz_context: Option<BuzzContext>,
    pending_approval: Option<ServicePendingApproval>,
}

#[derive(Clone)]
struct ServicePendingApproval {
    task_id: TaskId,
    display_code: String,
    session_id: SessionId,
    turn_id: crate::events::TurnId,
}

/// ACP transport adapter backed by Carl's persistent owner service. Dropping
/// stdio drops only this client connection; it never sends service shutdown.
pub struct ServiceAcpServer {
    data_root: PathBuf,
    client: TaskServiceClient,
    config: AcpServerConfig,
    info: crate::service::protocol::ServiceInfo,
    initialized: bool,
    sessions: std::sync::Arc<tokio::sync::Mutex<HashMap<String, ServiceSessionBinding>>>,
    buzz_bootstrap: Option<BuzzPublisherBootstrap>,
    buzz_publisher: Option<std::sync::Arc<BuzzPublisher>>,
}

impl fmt::Debug for ServiceAcpServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceAcpServer")
            .field("initialized", &self.initialized)
            .field("frontend", &self.config.frontend)
            .finish_non_exhaustive()
    }
}

impl ServiceAcpServer {
    pub async fn new(
        data_root: impl AsRef<std::path::Path>,
        mut config: AcpServerConfig,
    ) -> Result<Self, AcpServerError> {
        if !matches!(config.frontend, Frontend::Acp | Frontend::Buzz)
            || (config.frontend == Frontend::Acp && config.buzz_publisher.is_some())
            || (config.frontend == Frontend::Buzz && config.buzz_publisher.is_none())
        {
            return Err(invalid_input());
        }
        config
            .budget
            .validate_for_admission()
            .map_err(|_| invalid_input())?;
        let data_root = data_root.as_ref().to_path_buf();
        let client = TaskServiceClient::connect(&data_root)
            .await
            .map_err(|_| server_error(AcpServerErrorCode::KernelFailed))?;
        let info = client.info().clone();
        let model = config
            .model
            .clone()
            .or_else(|| info.default_model.clone())
            .ok_or_else(invalid_input)?;
        let descriptor = info
            .models
            .iter()
            .find(|candidate| candidate.id == model)
            .ok_or_else(invalid_input)?;
        let effort = config.effort.unwrap_or(descriptor.default_effort);
        if !descriptor.supported_efforts.contains(&effort) {
            return Err(invalid_input());
        }
        config.model = Some(model);
        config.effort = Some(effort);
        let buzz_bootstrap = config.buzz_publisher.take();
        Ok(Self {
            data_root,
            client,
            config,
            info,
            initialized: false,
            sessions: std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            buzz_bootstrap,
            buzz_publisher: None,
        })
    }

    pub async fn serve<R, W>(mut self, mut reader: R, writer: W) -> Result<(), AcpServerError>
    where
        R: AsyncBufRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (outbound, receiver) = mpsc::channel(WRITER_CAPACITY);
        let cancelled = CancellationToken::new();
        let writer_cancel = cancelled.clone();
        let writer_task =
            tokio::spawn(async move { writer_loop(writer, receiver, writer_cancel).await });
        let mut frontend_eof = false;
        loop {
            let frame = tokio::select! {
                () = cancelled.cancelled() => break,
                frame = read_frame(&mut reader, MAX_FRAME_BYTES) => frame,
            }
            .map_err(|_| server_error(AcpServerErrorCode::InvalidInput))?;
            let Some(frame) = frame else {
                frontend_eof = true;
                break;
            };
            let id = frame.id().cloned();
            let method = frame.method().map(str::to_owned);
            let params = frame
                .value()
                .get("params")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let response = match (method.as_deref(), id) {
                (Some("initialize"), Some(id)) => {
                    let result = self.service_initialize(params);
                    service_outgoing(id, result)
                }
                (Some("session/new"), Some(id)) => {
                    let result = self.service_new_session(params).await;
                    service_outgoing(id, result)
                }
                (Some("session/load"), Some(id)) => {
                    let replay_params = params.clone();
                    let result = self.service_load_session(params).await;
                    if result.is_ok() {
                        self.start_service_replay(
                            &replay_params,
                            outbound.clone(),
                            cancelled.clone(),
                        )
                        .await?;
                    }
                    service_outgoing(id, result)
                }
                (Some("session/set_config_option"), Some(id)) => {
                    let result = self.service_set_config(params).await;
                    service_outgoing(id, result)
                }
                (Some("session/prompt"), Some(id)) => {
                    if self
                        .start_service_prompt(
                            params,
                            id.clone(),
                            outbound.clone(),
                            cancelled.clone(),
                        )
                        .await
                        .is_err()
                    {
                        service_outgoing(id, Err(invalid_input()))
                    } else {
                        continue;
                    }
                }
                (Some("_session/steering"), Some(id)) => {
                    let result = self.service_session_steer(params).await;
                    service_outgoing(id, result)
                }
                (Some("session/cancel"), None) => {
                    let _ = self.service_session_cancel(params).await;
                    continue;
                }
                (Some("_task/status"), Some(id)) => {
                    let result = self.service_task_status(params).await;
                    service_outgoing(id, result)
                }
                (Some("_task/metrics"), Some(id)) => {
                    let result = self.service_task_metrics(params).await;
                    service_outgoing(id, result)
                }
                (Some("_task/list"), Some(id)) => {
                    let result = self.service_task_list(params).await;
                    service_outgoing(id, result)
                }
                (Some("_task/context"), Some(id)) => {
                    let result = self.service_task_context(params).await;
                    service_outgoing(id, result)
                }
                (Some("_task/resume"), Some(id)) => {
                    let result = self.service_task_mutation(params, "resume").await;
                    service_outgoing(id, result)
                }
                (Some("_task/cancel"), Some(id)) => {
                    let result = self.service_task_mutation(params, "cancel").await;
                    service_outgoing(id, result)
                }
                (Some("_task/steer"), Some(id)) => {
                    let result = self.service_task_mutation(params, "steer").await;
                    service_outgoing(id, result)
                }
                (_, Some(id)) => OutgoingFrame::error(id, -32601, "method not found"),
                (_, None) => continue,
            };
            enqueue(&outbound, response, &cancelled)?;
        }
        cancelled.cancel();
        drop(outbound);
        let writer_result = writer_task
            .await
            .map_err(|_| server_error(AcpServerErrorCode::Transport))?;
        if frontend_eof { Ok(()) } else { writer_result }
    }

    fn service_initialize(&mut self, params: Value) -> Result<Value, AcpServerError> {
        if self.initialized {
            return Err(invalid_input());
        }
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(
            params,
            &["protocolVersion", "clientInfo"],
            &["clientCapabilities"],
        )?;
        let version = params
            .get("protocolVersion")
            .and_then(Value::as_u64)
            .filter(|version| matches!(version, 1 | 2))
            .ok_or_else(invalid_input)?;
        let client = params
            .get("clientInfo")
            .and_then(Value::as_object)
            .ok_or_else(invalid_input)?;
        require_keys(client, &["name", "version"], &["title"])?;
        bounded_string(client.get("name"), 128)?;
        bounded_string(client.get("version"), 128)?;
        self.initialized = true;
        Ok(json!({
            "protocolVersion":version,
            "agentCapabilities":{
                "loadSession":true,
                "promptCapabilities":{
                    "image":false,"audio":false,"embeddedContext":false,
                    "mcpCapabilities":{"http":false,"sse":false}
                },
                "sessionCapabilities":{}
            },
            "agentInfo":{"name":"carl","title":"Carl","version":env!("CARGO_PKG_VERSION")},
            "_meta":{"steering":{"supported":true},"persistentService":true}
        }))
    }

    async fn service_new_session(&mut self, params: Value) -> Result<Value, AcpServerError> {
        if !self.initialized {
            return Err(invalid_input());
        }
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["cwd", "mcpServers"], &[])?;
        self.prepare_service_publisher(params.get("mcpServers"))
            .await?;
        let cwd = PathBuf::from(bounded_string(params.get("cwd"), 32 * 1024)?);
        let canonical = std::fs::canonicalize(&cwd).map_err(|_| invalid_input())?;
        if canonical != cwd || !canonical.is_dir() {
            return Err(invalid_input());
        }
        let external = Uuid::new_v4().to_string();
        let model = self.config.model.clone().ok_or_else(invalid_input)?;
        let effort = self.config.effort.ok_or_else(invalid_input)?;
        self.sessions.lock().await.insert(
            external.clone(),
            ServiceSessionBinding {
                cwd,
                model: model.clone(),
                effort,
                permission_mode: self.config.permission_mode,
                budget: self.config.budget,
                task_id: None,
                last_event_cursor: None,
                live_generation: self.info.live_generation.clone(),
                last_live_cursor: None,
                stream_generation: 0,
                prompt_active: false,
                buzz_context: None,
                pending_approval: None,
            },
        );
        Ok(json!({
            "sessionId":external,
            "configOptions":service_config_options(&self.info, &model, effort, self.config.permission_mode),
            "_meta":{"liveGeneration":self.info.live_generation}
        }))
    }

    async fn service_load_session(&mut self, params: Value) -> Result<Value, AcpServerError> {
        if !self.initialized {
            return Err(invalid_input());
        }
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(
            params,
            &["sessionId", "cwd", "mcpServers"],
            &[
                "lastEventCursor",
                "lastLiveCursor",
                "lastLiveGeneration",
                "taskId",
            ],
        )?;
        self.prepare_service_publisher(params.get("mcpServers"))
            .await?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let cwd = PathBuf::from(bounded_string(params.get("cwd"), 32 * 1024)?);
        let canonical = std::fs::canonicalize(&cwd).map_err(|_| invalid_input())?;
        if canonical != cwd || !canonical.is_dir() {
            return Err(invalid_input());
        }
        let last_event_cursor = params.get("lastEventCursor").map_or(Ok(None), |value| {
            value.as_u64().map(Some).ok_or_else(invalid_input)
        })?;
        let requested_live_cursor = params.get("lastLiveCursor").map_or(Ok(None), |value| {
            value.as_u64().map(Some).ok_or_else(invalid_input)
        })?;
        let requested_live_generation = params
            .get("lastLiveGeneration")
            .map(|value| bounded_string(Some(value), 64))
            .transpose()?;
        if requested_live_generation
            .as_deref()
            .is_some_and(|generation| Uuid::parse_str(generation).is_err())
        {
            return Err(invalid_input());
        }
        let live_generation = self.info.live_generation.clone();
        let last_live_cursor =
            if requested_live_generation.as_deref() == Some(live_generation.as_str()) {
                requested_live_cursor
            } else {
                None
            };
        let requested_task = params
            .get("taskId")
            .map(|value| {
                bounded_string(Some(value), 128)?
                    .parse()
                    .map_err(|_| invalid_input())
            })
            .transpose()?;
        let service_session = match self
            .service_request(ServiceCommand::Session {
                external_session_id: external.clone(),
            })
            .await?
        {
            ServiceResult::Session(session) => session,
            _ => return Err(server_error(AcpServerErrorCode::KernelFailed)),
        };
        if service_session.frontend != self.config.frontend
            || service_session.workspace != cwd
            || requested_task.is_some_and(|task_id| !service_session.task_ids.contains(&task_id))
        {
            return Err(invalid_input());
        }
        let task_id = requested_task.or_else(|| service_session.task_ids.first().copied());
        let model = self.config.model.clone().ok_or_else(invalid_input)?;
        let effort = self.config.effort.ok_or_else(invalid_input)?;
        self.sessions.lock().await.insert(
            external.clone(),
            ServiceSessionBinding {
                cwd,
                model: model.clone(),
                effort,
                permission_mode: service_session.permission_mode,
                budget: self.config.budget,
                task_id,
                last_event_cursor,
                live_generation: live_generation.clone(),
                last_live_cursor,
                stream_generation: 0,
                prompt_active: false,
                buzz_context: None,
                pending_approval: None,
            },
        );
        Ok(json!({
            "sessionId":external,
            "configOptions":service_config_options(&self.info, &model, effort, service_session.permission_mode),
            "_meta":{"lastEventCursor":last_event_cursor,"lastLiveGeneration":live_generation,"lastLiveCursor":last_live_cursor,"taskId":task_id}
        }))
    }

    async fn start_service_replay(
        &mut self,
        params: &Value,
        outbound: mpsc::Sender<OutgoingFrame>,
        cancelled: CancellationToken,
    ) -> Result<(), AcpServerError> {
        let params = params.as_object().ok_or_else(invalid_input)?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let session = {
            let mut sessions = self.sessions.lock().await;
            let session = sessions.get_mut(&external).ok_or_else(invalid_input)?;
            session.stream_generation = session.stream_generation.saturating_add(1);
            session.clone()
        };
        let Some(task_id) = session.task_id else {
            return Ok(());
        };
        let data_root = self.data_root.clone();
        let sessions = std::sync::Arc::clone(&self.sessions);
        tokio::spawn(async move {
            replay_service_events(
                data_root,
                sessions,
                external,
                task_id,
                session.last_event_cursor,
                session.live_generation,
                session.last_live_cursor,
                session.stream_generation,
                outbound,
                cancelled,
            )
            .await;
        });
        Ok(())
    }

    async fn service_set_config(&mut self, params: Value) -> Result<Value, AcpServerError> {
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["sessionId", "configId", "value"], &[])?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let config_id = bounded_string(params.get("configId"), 64)?;
        let value = bounded_string(params.get("value"), 128)?;
        let mut session = self
            .sessions
            .lock()
            .await
            .get(&external)
            .cloned()
            .ok_or_else(invalid_input)?;
        match config_id.as_str() {
            "model" => session.model = ModelId::parse(value).map_err(|_| invalid_input())?,
            "thought_level" => session.effort = parse_effort(&value)?,
            "mode" => session.permission_mode = value.parse().map_err(|_| invalid_input())?,
            _ => return Err(invalid_input()),
        }
        validate_service_selection(&self.info, &session.model, session.effort)?;
        if let Some(task_id) = session.task_id {
            match self
                .service_request(ServiceCommand::Configure {
                    task_id,
                    model: session.model.clone(),
                    effort: session.effort,
                    permission_mode: session.permission_mode,
                })
                .await?
            {
                ServiceResult::Applied => {}
                _ => return Err(server_error(AcpServerErrorCode::KernelFailed)),
            }
        }
        self.sessions.lock().await.insert(external, session.clone());
        Ok(json!({
            "configOptions":service_config_options(
                &self.info,
                &session.model,
                session.effort,
                session.permission_mode
            )
        }))
    }

    async fn start_service_prompt(
        &mut self,
        params: Value,
        id: JsonRpcId,
        outbound: mpsc::Sender<OutgoingFrame>,
        cancelled: CancellationToken,
    ) -> Result<(), AcpServerError> {
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["sessionId", "prompt"], &[])?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let blocks = parse_service_prompt_blocks(params.get("prompt"))?;
        if self.config.frontend == Frontend::Buzz && service_maintenance_shaped(&blocks) {
            return Err(invalid_input());
        }
        let text = blocks.join("\n\n");
        let metrics_slash = exact_task_metrics_command(&blocks);
        let mut session = self
            .sessions
            .lock()
            .await
            .get(&external)
            .cloned()
            .ok_or_else(invalid_input)?;
        if session.prompt_active && !metrics_slash {
            return Err(invalid_input());
        }
        let buzz_context = if self.config.frontend == Frontend::Buzz {
            let refs = blocks.iter().map(String::as_str).collect::<Vec<_>>();
            Some(BuzzContext::parse(&refs).map_err(|_| invalid_input())?)
        } else {
            None
        };
        let resolved_approval = if let Some(pending) = session.pending_approval.clone() {
            let (decision, display_code) = service_approval_slash(&blocks)?;
            if display_code != pending.display_code {
                return Err(invalid_input());
            }
            let (actor_id, channel_id, event_id) = match buzz_context.as_ref() {
                Some(context) => (
                    ActorId::parse(context.actor_hex()).map_err(|_| invalid_input())?,
                    Some(context.channel_id().to_string()),
                    Some(context.reply_to().to_owned()),
                ),
                None if self.config.frontend == Frontend::Acp => (
                    ActorId::parse("local-owner").map_err(|_| invalid_input())?,
                    None,
                    None,
                ),
                None => return Err(invalid_input()),
            };
            let result = self
                .service_request(ServiceCommand::ResolveApproval {
                    task_id: pending.task_id,
                    external_session_id: external.clone(),
                    workspace: session.cwd.clone(),
                    frontend: self.config.frontend,
                    actor_id,
                    channel_id,
                    event_id,
                    display_code,
                    session_id: pending.session_id,
                    turn_id: pending.turn_id,
                    decision,
                })
                .await?;
            session.pending_approval = None;
            Some(result)
        } else {
            None
        };
        if session.pending_approval.is_none()
            && resolved_approval.is_none()
            && service_approval_shaped(&blocks)
        {
            return Err(invalid_input());
        }
        if resolved_approval.is_none() && metrics_slash {
            if !service_metrics_context_matches(
                &session,
                buzz_context.as_ref(),
                self.config.frontend,
            ) {
                return Err(invalid_input());
            }
            let task_id = session.task_id.ok_or_else(invalid_input)?;
            let ServiceResult::Metrics(metrics) = self
                .service_request(ServiceCommand::Metrics { task_id })
                .await?
            else {
                return Err(server_error(AcpServerErrorCode::KernelFailed));
            };
            enqueue(
                &outbound,
                OutgoingFrame::notification(
                    "session/update",
                    json!({
                        "sessionId":external,
                        "update":{
                            "sessionUpdate":"agent_message_chunk",
                            "content":{"type":"text","text":json!({"metrics":metrics}).to_string()}
                        }
                    }),
                )
                .map_err(|_| server_error(AcpServerErrorCode::OutputUnavailable))?,
                &cancelled,
            )?;
            enqueue(
                &outbound,
                OutgoingFrame::result(id, json!({"stopReason":"end_turn"})),
                &cancelled,
            )?;
            return Ok(());
        }
        if resolved_approval.is_none()
            && let Some(permission_mode) = service_permission_slash(&blocks)
        {
            if let Some(context) = buzz_context.as_ref() {
                match self
                    .service_request(ServiceCommand::ConfigureTrustedSession {
                        external_session_id: external.clone(),
                        workspace: session.cwd.clone(),
                        frontend: self.config.frontend,
                        actor_id: ActorId::parse(context.actor_hex())
                            .map_err(|_| invalid_input())?,
                        channel_id: context.channel_id().to_string(),
                        event_id: context.reply_to().to_owned(),
                        permission_mode,
                    })
                    .await?
                {
                    ServiceResult::Applied => {}
                    _ => return Err(server_error(AcpServerErrorCode::KernelFailed)),
                }
            }
            session.permission_mode = permission_mode;
            self.sessions
                .lock()
                .await
                .insert(external.clone(), session.clone());
            enqueue(
                &outbound,
                OutgoingFrame::notification(
                    "session/update",
                    json!({
                        "sessionId":external,
                        "update":{
                            "sessionUpdate":"session_info_update",
                            "_meta":{
                                "model":session.model.as_str(),
                                "thoughtLevel":session.effort.as_codex_value(),
                                "mode":permission_mode.as_wire_str()
                            }
                        }
                    }),
                )
                .map_err(|_| server_error(AcpServerErrorCode::OutputUnavailable))?,
                &cancelled,
            )?;
            enqueue(
                &outbound,
                OutgoingFrame::result(id, json!({"stopReason":"end_turn"})),
                &cancelled,
            )?;
            return Ok(());
        }
        let reusable_task = if resolved_approval.is_none()
            && let Some(task_id) = session.task_id
        {
            match self
                .service_request(ServiceCommand::Status { task_id })
                .await?
            {
                ServiceResult::Snapshot(snapshot) if !snapshot.status.is_terminal() => {
                    Some(task_id)
                }
                ServiceResult::Snapshot(_) => None,
                _ => return Err(server_error(AcpServerErrorCode::KernelFailed)),
            }
        } else {
            None
        };
        let request_id = Uuid::new_v4().to_string();
        let result = if let Some(result) = resolved_approval {
            Ok(result)
        } else if let Some(task_id) = reusable_task {
            self.client
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: request_id.clone(),
                    idempotency_key: request_id,
                    command: service_steer_command(
                        &session,
                        &external,
                        task_id,
                        text,
                        buzz_context.as_ref(),
                        self.config.frontend,
                    )?,
                })
                .await
        } else {
            self.client
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    request_id: request_id.clone(),
                    idempotency_key: request_id,
                    command: service_start_command(
                        &session,
                        &external,
                        text,
                        buzz_context.as_ref(),
                        self.config.frontend,
                    )?,
                })
                .await
        }
        .map_err(|_| server_error(AcpServerErrorCode::KernelFailed))?;
        let task_id = match result {
            ServiceResult::Accepted { task_id } => {
                session.task_id = Some(task_id);
                session.last_event_cursor = None;
                session.live_generation = self.client.info().live_generation.clone();
                session.last_live_cursor = None;
                task_id
            }
            ServiceResult::Applied => session.task_id.ok_or_else(invalid_input)?,
            _ => return Err(server_error(AcpServerErrorCode::KernelFailed)),
        };
        session.prompt_active = true;
        session.buzz_context = buzz_context;
        let buzz_publisher = self.buzz_publisher.clone();
        let buzz_context = session.buzz_context.clone();
        let (cursor, live_generation, live_cursor, stream_generation) = {
            let mut sessions = self.sessions.lock().await;
            let current = sessions.get(&external).ok_or_else(invalid_input)?;
            session.last_event_cursor = current.last_event_cursor;
            session.live_generation.clone_from(&current.live_generation);
            session.last_live_cursor = current.last_live_cursor;
            session.stream_generation = current.stream_generation.saturating_add(1);
            let state = (
                session.last_event_cursor,
                session.live_generation.clone(),
                session.last_live_cursor,
                session.stream_generation,
            );
            sessions.insert(external.clone(), session);
            state
        };
        let data_root = self.data_root.clone();
        let sessions = std::sync::Arc::clone(&self.sessions);
        tokio::spawn(async move {
            poll_service_prompt(
                data_root,
                sessions,
                external,
                task_id,
                cursor,
                live_generation,
                live_cursor,
                stream_generation,
                buzz_publisher,
                buzz_context,
                id,
                outbound,
                cancelled,
            )
            .await;
        });
        Ok(())
    }

    async fn service_session_steer(&mut self, params: Value) -> Result<Value, AcpServerError> {
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["sessionId", "prompt"], &[])?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let blocks = parse_service_prompt_blocks(params.get("prompt"))?;
        let text = blocks.join("\n\n");
        let session = self
            .sessions
            .lock()
            .await
            .get(&external)
            .cloned()
            .ok_or_else(invalid_input)?;
        let task_id = session.task_id.ok_or_else(invalid_input)?;
        let command = if self.config.frontend == Frontend::Buzz {
            let refs = blocks.iter().map(String::as_str).collect::<Vec<_>>();
            let context = BuzzContext::parse(&refs).map_err(|_| invalid_input())?;
            service_steer_command(
                &session,
                &external,
                task_id,
                text,
                Some(&context),
                self.config.frontend,
            )?
        } else {
            ServiceCommand::Steer { task_id, text }
        };
        match self.service_request(command).await? {
            ServiceResult::Applied => Ok(json!({"outcome":"injected","taskId":task_id})),
            _ => Err(server_error(AcpServerErrorCode::KernelFailed)),
        }
    }

    async fn service_session_cancel(&mut self, params: Value) -> Result<(), AcpServerError> {
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["sessionId"], &[])?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let task_id = self
            .sessions
            .lock()
            .await
            .get(&external)
            .and_then(|session| session.task_id)
            .ok_or_else(invalid_input)?;
        match self
            .service_request(ServiceCommand::Cancel { task_id })
            .await?
        {
            ServiceResult::Applied => Ok(()),
            _ => Err(server_error(AcpServerErrorCode::KernelFailed)),
        }
    }

    async fn service_task_status(&mut self, params: Value) -> Result<Value, AcpServerError> {
        let task_id = self.bound_service_task(&params).await?;
        let result = self
            .service_request(ServiceCommand::Status { task_id })
            .await?;
        match result {
            ServiceResult::Snapshot(task) => Ok(json!({"task":task})),
            _ => Err(server_error(AcpServerErrorCode::KernelFailed)),
        }
    }

    async fn service_task_list(&mut self, params: Value) -> Result<Value, AcpServerError> {
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["sessionId"], &[])?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let session = self
            .sessions
            .lock()
            .await
            .get(&external)
            .cloned()
            .ok_or_else(invalid_input)?;
        match self.service_request(ServiceCommand::List).await? {
            ServiceResult::TaskList(tasks) => Ok(
                json!({"tasks":tasks.into_iter().filter(|task| Some(task.task_id) == session.task_id).collect::<Vec<_>>() }),
            ),
            _ => Err(server_error(AcpServerErrorCode::KernelFailed)),
        }
    }

    async fn service_task_metrics(&mut self, params: Value) -> Result<Value, AcpServerError> {
        let task_id = self.bound_service_task(&params).await?;
        match self
            .service_request(ServiceCommand::Metrics { task_id })
            .await?
        {
            ServiceResult::Metrics(metrics) => Ok(json!({"metrics":metrics})),
            _ => Err(server_error(AcpServerErrorCode::KernelFailed)),
        }
    }

    async fn service_task_context(&mut self, params: Value) -> Result<Value, AcpServerError> {
        let task_id = self.bound_service_task(&params).await?;
        match self
            .service_request(ServiceCommand::Status { task_id })
            .await?
        {
            ServiceResult::Snapshot(task) => {
                Ok(json!({"context":super::TaskContextView::from(&task)}))
            }
            _ => Err(server_error(AcpServerErrorCode::KernelFailed)),
        }
    }

    async fn service_task_mutation(
        &mut self,
        params: Value,
        method: &'static str,
    ) -> Result<Value, AcpServerError> {
        if self.config.frontend == Frontend::Buzz && method == "steer" {
            return Err(invalid_input());
        }
        let (task_id, idempotency_key) = self
            .bound_service_mutation(&params, method == "steer")
            .await?;
        let params = params.as_object().ok_or_else(invalid_input)?;
        let command = match method {
            "resume" => ServiceCommand::Resume { task_id },
            "cancel" => ServiceCommand::Cancel { task_id },
            "steer" => ServiceCommand::Steer {
                task_id,
                text: bounded_text(
                    params.get("text"),
                    crate::service::protocol::MAX_TASK_TEXT_BYTES,
                )?,
            },
            _ => return Err(invalid_input()),
        };
        match self
            .service_request_with_key(command, idempotency_key)
            .await?
        {
            ServiceResult::Applied => Ok(json!({"outcome":"accepted","taskId":task_id})),
            _ => Err(server_error(AcpServerErrorCode::KernelFailed)),
        }
    }

    async fn bound_service_task(&mut self, params: &Value) -> Result<TaskId, AcpServerError> {
        let params = params.as_object().ok_or_else(invalid_input)?;
        require_keys(params, &["sessionId", "taskId"], &[])?;
        let external = bounded_string(params.get("sessionId"), 128)?;
        let task_id = bounded_string(params.get("taskId"), 128)?
            .parse::<TaskId>()
            .map_err(|_| invalid_input())?;
        let matches = self
            .sessions
            .lock()
            .await
            .get(&external)
            .is_some_and(|session| session.task_id == Some(task_id));
        if !matches {
            return Err(invalid_input());
        }
        Ok(task_id)
    }

    async fn bound_service_mutation(
        &mut self,
        params: &Value,
        steer: bool,
    ) -> Result<(TaskId, String), AcpServerError> {
        let params = params.as_object().ok_or_else(invalid_input)?;
        let optional = if steer { &["text"][..] } else { &[][..] };
        require_keys(params, &["sessionId", "taskId", "idempotencyKey"], optional)?;
        if steer && !params.contains_key("text") {
            return Err(invalid_input());
        }
        let external = bounded_string(params.get("sessionId"), 128)?;
        let task_id = bounded_string(params.get("taskId"), 128)?
            .parse::<TaskId>()
            .map_err(|_| invalid_input())?;
        let idempotency_key = bounded_string(params.get("idempotencyKey"), 128)?;
        let matches = self
            .sessions
            .lock()
            .await
            .get(&external)
            .is_some_and(|session| session.task_id == Some(task_id));
        if !matches {
            return Err(invalid_input());
        }
        Ok((task_id, idempotency_key))
    }

    async fn prepare_service_publisher(
        &mut self,
        servers: Option<&Value>,
    ) -> Result<(), AcpServerError> {
        let servers = servers
            .and_then(Value::as_array)
            .ok_or_else(invalid_input)?;
        match self.config.frontend {
            Frontend::Acp if servers.is_empty() => Ok(()),
            Frontend::Buzz => {
                let configuration =
                    BuzzPublisherConfig::from_mcp_servers(&Value::Array(servers.clone()))
                        .map_err(|_| invalid_input())?;
                if self.buzz_publisher.is_none() {
                    let bootstrap = self.buzz_bootstrap.take().ok_or_else(invalid_input)?;
                    let publisher = BuzzPublisher::connect(
                        bootstrap.executable,
                        bootstrap.workspace,
                        configuration,
                    )
                    .await
                    .map_err(|_| invalid_input())?;
                    self.buzz_publisher = Some(std::sync::Arc::new(publisher));
                }
                Ok(())
            }
            _ => Err(invalid_input()),
        }
    }

    async fn service_request(
        &mut self,
        command: ServiceCommand,
    ) -> Result<ServiceResult, AcpServerError> {
        self.service_request_with_key(command, Uuid::new_v4().to_string())
            .await
    }

    async fn service_request_with_key(
        &mut self,
        command: ServiceCommand,
        idempotency_key: String,
    ) -> Result<ServiceResult, AcpServerError> {
        self.client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: Uuid::new_v4().to_string(),
                idempotency_key,
                command,
            })
            .await
            .map_err(|_| server_error(AcpServerErrorCode::KernelFailed))
    }
}

fn service_start_command(
    session: &ServiceSessionBinding,
    external_session_id: &str,
    request: String,
    buzz_context: Option<&BuzzContext>,
    frontend: Frontend,
) -> Result<ServiceCommand, AcpServerError> {
    let start = StartTaskCommand {
        external_session_id: external_session_id.to_owned(),
        workspace: session.cwd.clone(),
        request,
        model: session.model.clone(),
        effort: session.effort,
        permission_mode: session.permission_mode,
        budget: session.budget,
    };
    match frontend {
        Frontend::Acp if buzz_context.is_none() => Ok(ServiceCommand::StartTask(start)),
        Frontend::Buzz => {
            let context = buzz_context.ok_or_else(invalid_input)?;
            Ok(ServiceCommand::StartTrustedTask(TrustedStartTaskCommand {
                start,
                frontend,
                actor_id: ActorId::parse(context.actor_hex()).map_err(|_| invalid_input())?,
                channel_id: context.channel_id().to_string(),
                event_id: context.reply_to().to_owned(),
            }))
        }
        _ => Err(invalid_input()),
    }
}

fn service_steer_command(
    session: &ServiceSessionBinding,
    external_session_id: &str,
    task_id: TaskId,
    text: String,
    buzz_context: Option<&BuzzContext>,
    frontend: Frontend,
) -> Result<ServiceCommand, AcpServerError> {
    match frontend {
        Frontend::Acp if buzz_context.is_none() => Ok(ServiceCommand::Steer { task_id, text }),
        Frontend::Buzz => {
            let context = buzz_context.ok_or_else(invalid_input)?;
            Ok(ServiceCommand::SteerTrusted {
                task_id,
                external_session_id: external_session_id.to_owned(),
                text,
                workspace: session.cwd.clone(),
                frontend,
                actor_id: ActorId::parse(context.actor_hex()).map_err(|_| invalid_input())?,
                channel_id: context.channel_id().to_string(),
                event_id: context.reply_to().to_owned(),
            })
        }
        _ => Err(invalid_input()),
    }
}

fn service_metrics_context_matches(
    session: &ServiceSessionBinding,
    context: Option<&BuzzContext>,
    frontend: Frontend,
) -> bool {
    match (frontend, context, session.buzz_context.as_ref()) {
        (Frontend::Acp, None, _) => true,
        (Frontend::Buzz, Some(context), Some(existing)) => {
            existing.channel_id() == context.channel_id()
                && existing.actor_hex() == context.actor_hex()
        }
        _ => false,
    }
}

fn validate_service_selection(
    info: &crate::service::protocol::ServiceInfo,
    model: &ModelId,
    effort: ReasoningEffort,
) -> Result<(), AcpServerError> {
    if info
        .models
        .iter()
        .any(|candidate| candidate.id == *model && candidate.supported_efforts.contains(&effort))
    {
        Ok(())
    } else {
        Err(invalid_input())
    }
}

fn parse_service_prompt_blocks(value: Option<&Value>) -> Result<Vec<String>, AcpServerError> {
    let blocks = parse_prompt_blocks(value)?;
    let aggregate = blocks
        .iter()
        .map(String::len)
        .sum::<usize>()
        .saturating_add(blocks.len().saturating_sub(1).saturating_mul(2));
    if aggregate > crate::service::protocol::MAX_TASK_TEXT_BYTES {
        return Err(invalid_input());
    }
    Ok(blocks)
}

#[allow(clippy::too_many_arguments)]
async fn poll_service_prompt(
    data_root: PathBuf,
    sessions: std::sync::Arc<tokio::sync::Mutex<HashMap<String, ServiceSessionBinding>>>,
    external_session_id: String,
    task_id: TaskId,
    mut cursor: Option<u64>,
    mut live_generation: String,
    mut live_cursor: Option<u64>,
    stream_generation: u64,
    buzz_publisher: Option<std::sync::Arc<BuzzPublisher>>,
    buzz_context: Option<BuzzContext>,
    response_id: JsonRpcId,
    outbound: mpsc::Sender<OutgoingFrame>,
    cancelled: CancellationToken,
) {
    let Ok(mut client) = TaskServiceClient::connect_with_cursor(&data_root, cursor).await else {
        let _ = enqueue(
            &outbound,
            OutgoingFrame::error(response_id, -32000, "service unavailable"),
            &cancelled,
        );
        return;
    };
    loop {
        if cancelled.is_cancelled()
            || !owns_service_stream(&sessions, &external_session_id, stream_generation).await
        {
            return;
        }
        let event_key = Uuid::new_v4().to_string();
        let events = client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: Uuid::new_v4().to_string(),
                idempotency_key: event_key,
                command: ServiceCommand::Events {
                    task_id,
                    after_sequence: cursor,
                    limit: 128,
                },
            })
            .await;
        let Ok(ServiceResult::Events(events)) = events else {
            let _ = enqueue(
                &outbound,
                OutgoingFrame::error(response_id, -32000, "service event stream failed"),
                &cancelled,
            );
            return;
        };
        for event in events {
            if cursor.is_some_and(|sequence| event.sequence <= sequence) {
                continue;
            }
            let mut bindings = sessions.lock().await;
            let Some(binding) = bindings
                .get_mut(&external_session_id)
                .filter(|binding| binding.stream_generation == stream_generation)
            else {
                return;
            };
            for params in render_service_event(&external_session_id, task_id, &event) {
                let Ok(frame) = OutgoingFrame::notification("session/update", params) else {
                    return;
                };
                if enqueue(&outbound, frame, &cancelled).is_err() {
                    return;
                }
            }
            cursor = Some(event.sequence);
            binding.last_event_cursor = cursor;
        }
        let Ok((next_live_generation, next_live_cursor, live_frames, pending_approval)) =
            poll_live_service_updates(
                &mut client,
                &external_session_id,
                task_id,
                &live_generation,
                live_cursor,
                buzz_publisher.as_deref(),
                buzz_context.as_ref(),
                &cancelled,
            )
            .await
        else {
            return;
        };
        let mut bindings = sessions.lock().await;
        let Some(binding) = bindings
            .get_mut(&external_session_id)
            .filter(|binding| binding.stream_generation == stream_generation)
        else {
            return;
        };
        for frame in live_frames {
            if enqueue(&outbound, frame, &cancelled).is_err() {
                return;
            }
        }
        live_generation = next_live_generation;
        live_cursor = next_live_cursor;
        binding.live_generation.clone_from(&live_generation);
        binding.last_live_cursor = live_cursor;
        if let Some(pending) = pending_approval {
            binding.pending_approval = Some(pending);
            binding.prompt_active = false;
            drop(bindings);
            let _ = enqueue(
                &outbound,
                OutgoingFrame::result(
                    response_id,
                    json!({
                        "stopReason":"waiting_for_approval",
                        "_meta":{"taskId":task_id,"lastEventCursor":cursor,"lastLiveGeneration":live_generation,"lastLiveCursor":live_cursor}
                    }),
                ),
                &cancelled,
            );
            return;
        }
        drop(bindings);
        let status_key = Uuid::new_v4().to_string();
        let status = client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: Uuid::new_v4().to_string(),
                idempotency_key: status_key,
                command: ServiceCommand::Status { task_id },
            })
            .await;
        let Ok(ServiceResult::Snapshot(snapshot)) = status else {
            let _ = enqueue(
                &outbound,
                OutgoingFrame::error(response_id, -32000, "service status failed"),
                &cancelled,
            );
            return;
        };
        if snapshot.status.is_terminal()
            || matches!(snapshot.status, TaskStatus::Blocked | TaskStatus::Paused)
        {
            if let Some(session) = sessions
                .lock()
                .await
                .get_mut(&external_session_id)
                .filter(|session| session.stream_generation == stream_generation)
            {
                session.last_event_cursor = cursor;
                session.live_generation.clone_from(&live_generation);
                session.last_live_cursor = live_cursor;
                session.prompt_active = false;
            }
            let stop_reason = match snapshot.status {
                TaskStatus::Completed => "end_turn",
                TaskStatus::Cancelled => "cancelled",
                TaskStatus::Blocked | TaskStatus::Paused => "waiting_for_approval",
                TaskStatus::Failed => "failed",
                _ => "failed",
            };
            let _ = enqueue(
                &outbound,
                OutgoingFrame::result(
                    response_id,
                    json!({
                        "stopReason":stop_reason,
                        "_meta":{"taskId":task_id,"lastEventCursor":cursor,"lastLiveGeneration":live_generation,"lastLiveCursor":live_cursor}
                    }),
                ),
                &cancelled,
            );
            return;
        }
        tokio::select! {
            () = cancelled.cancelled() => return,
            () = tokio::time::sleep(std::time::Duration::from_millis(25)) => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn replay_service_events(
    data_root: PathBuf,
    sessions: std::sync::Arc<tokio::sync::Mutex<HashMap<String, ServiceSessionBinding>>>,
    external_session_id: String,
    task_id: TaskId,
    mut cursor: Option<u64>,
    mut live_generation: String,
    mut live_cursor: Option<u64>,
    stream_generation: u64,
    outbound: mpsc::Sender<OutgoingFrame>,
    cancelled: CancellationToken,
) {
    let Ok(mut client) = TaskServiceClient::connect_with_cursor(&data_root, cursor).await else {
        return;
    };
    loop {
        if cancelled.is_cancelled()
            || !owns_service_stream(&sessions, &external_session_id, stream_generation).await
        {
            return;
        }
        let key = Uuid::new_v4().to_string();
        let Ok(ServiceResult::Events(events)) = client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: Uuid::new_v4().to_string(),
                idempotency_key: key,
                command: ServiceCommand::Events {
                    task_id,
                    after_sequence: cursor,
                    limit: 128,
                },
            })
            .await
        else {
            return;
        };
        let fetched = events.len();
        for event in events {
            if cancelled.is_cancelled() || cursor.is_some_and(|sequence| event.sequence <= sequence)
            {
                return;
            }
            let mut bindings = sessions.lock().await;
            let Some(binding) = bindings
                .get_mut(&external_session_id)
                .filter(|binding| binding.stream_generation == stream_generation)
            else {
                return;
            };
            for params in render_service_event(&external_session_id, task_id, &event) {
                let Ok(frame) = OutgoingFrame::notification("session/update", params) else {
                    return;
                };
                if enqueue(&outbound, frame, &cancelled).is_err() {
                    return;
                }
            }
            cursor = Some(event.sequence);
            binding.last_event_cursor = cursor;
        }
        let Ok((next_live_generation, next_live_cursor, live_frames, pending_approval)) =
            poll_live_service_updates(
                &mut client,
                &external_session_id,
                task_id,
                &live_generation,
                live_cursor,
                None,
                None,
                &cancelled,
            )
            .await
        else {
            return;
        };
        let mut bindings = sessions.lock().await;
        let Some(binding) = bindings
            .get_mut(&external_session_id)
            .filter(|binding| binding.stream_generation == stream_generation)
        else {
            return;
        };
        for frame in live_frames {
            if enqueue(&outbound, frame, &cancelled).is_err() {
                return;
            }
        }
        live_generation = next_live_generation;
        live_cursor = next_live_cursor;
        binding.last_event_cursor = cursor;
        binding.live_generation.clone_from(&live_generation);
        binding.last_live_cursor = live_cursor;
        let approval_pending = pending_approval.is_some();
        if let Some(pending) = pending_approval {
            binding.pending_approval = Some(pending);
        }
        drop(bindings);
        if approval_pending {
            return;
        }

        let status_key = Uuid::new_v4().to_string();
        let Ok(ServiceResult::Snapshot(snapshot)) = client
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: Uuid::new_v4().to_string(),
                idempotency_key: status_key,
                command: ServiceCommand::Status { task_id },
            })
            .await
        else {
            return;
        };
        if snapshot.status.is_terminal()
            || matches!(snapshot.status, TaskStatus::Blocked | TaskStatus::Paused)
        {
            return;
        }
        if fetched < 128 {
            tokio::select! {
                () = cancelled.cancelled() => return,
                () = tokio::time::sleep(std::time::Duration::from_millis(25)) => {}
            }
        }
    }
}

async fn owns_service_stream(
    sessions: &std::sync::Arc<tokio::sync::Mutex<HashMap<String, ServiceSessionBinding>>>,
    external_session_id: &str,
    generation: u64,
) -> bool {
    sessions
        .lock()
        .await
        .get(external_session_id)
        .is_some_and(|session| session.stream_generation == generation)
}

#[allow(clippy::too_many_arguments)]
async fn poll_live_service_updates(
    client: &mut TaskServiceClient,
    external_session_id: &str,
    task_id: TaskId,
    live_generation: &str,
    live_cursor: Option<u64>,
    buzz_publisher: Option<&BuzzPublisher>,
    buzz_context: Option<&BuzzContext>,
    cancelled: &CancellationToken,
) -> Result<
    (
        String,
        Option<u64>,
        Vec<OutgoingFrame>,
        Option<ServicePendingApproval>,
    ),
    AcpServerError,
> {
    let result = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            request_id: Uuid::new_v4().to_string(),
            idempotency_key: Uuid::new_v4().to_string(),
            command: ServiceCommand::LiveUpdates {
                task_id,
                live_generation: live_generation.to_owned(),
                after_cursor: live_cursor,
                limit: 128,
            },
        })
        .await
        .map_err(|_| server_error(AcpServerErrorCode::KernelFailed))?;
    let ServiceResult::LiveUpdates(page) = result else {
        return Err(server_error(AcpServerErrorCode::KernelFailed));
    };
    let page_generation = page.live_generation.clone();
    let mut frames = Vec::new();
    let mut pending_approval = None;
    if let Some(snapshot) = page.snapshot {
        frames.push(OutgoingFrame::notification(
            "session/update",
            json!({
                "sessionId":external_session_id,
                "update":{"sessionUpdate":"task_status","taskId":task_id,"status":snapshot.status},
                "_meta":{"liveGeneration":page_generation,"liveCursor":page.cursor,"snapshotFallback":true}
            }),
        )
        .map_err(|_| server_error(AcpServerErrorCode::KernelFailed))?);
    }
    for envelope in page.updates {
        let update = match envelope.update {
            TaskUpdate::AssistantDelta(text) => {
                if let (Some(publisher), Some(context)) = (buzz_publisher, buzz_context) {
                    publisher
                        .send_message(context, &text, cancelled.clone())
                        .await
                        .map_err(|_| server_error(AcpServerErrorCode::KernelFailed))?;
                }
                json!({
                    "sessionUpdate":"agent_message_chunk",
                    "content":{"type":"text","text":text}
                })
            }
            TaskUpdate::Diff(diff) => {
                if let (Some(publisher), Some(context)) = (buzz_publisher, buzz_context) {
                    publisher
                        .send_diff(context, &diff, cancelled.clone())
                        .await
                        .map_err(|_| server_error(AcpServerErrorCode::KernelFailed))?;
                }
                json!({
                    "sessionUpdate":"tool_call",
                    "toolCallId":format!("live-diff-{}", envelope.cursor),
                    "title":"Workspace diff","kind":"edit","status":"completed",
                    "content":[{"type":"diff","diff":diff}]
                })
            }
            TaskUpdate::ApprovalRequired {
                task_id: approval_task,
                operation_id,
                display_code,
                summary,
                request_id,
                session_id,
                turn_id,
                external_session_id: approval_session,
            } => {
                if approval_task != task_id || approval_session != external_session_id {
                    return Err(server_error(AcpServerErrorCode::KernelFailed));
                }
                let publication = format!(
                    "Approval required: {summary}\nApprove with /approve {display_code} or deny with /deny {display_code}"
                );
                if let (Some(publisher), Some(context)) = (buzz_publisher, buzz_context) {
                    publisher
                        .send_message(context, &publication, cancelled.clone())
                        .await
                        .map_err(|_| server_error(AcpServerErrorCode::KernelFailed))?;
                }
                frames.push(
                    OutgoingFrame::notification(
                        "session/update",
                        json!({
                            "sessionId":external_session_id,
                            "update":{
                                "sessionUpdate":"tool_call",
                                "toolCallId":operation_id,
                                "title":request_id,
                                "kind":"execute",
                                "status":"pending"
                            },
                            "_meta":{"liveGeneration":page_generation,"liveCursor":envelope.cursor}
                        }),
                    )
                    .map_err(|_| server_error(AcpServerErrorCode::KernelFailed))?,
                );
                pending_approval = Some(ServicePendingApproval {
                    task_id,
                    display_code,
                    session_id,
                    turn_id,
                });
                json!({
                    "sessionUpdate":"agent_message_chunk",
                    "content":{"type":"text","text":publication}
                })
            }
            _ => continue,
        };
        frames.push(
            OutgoingFrame::notification(
                "session/update",
                json!({
                    "sessionId":external_session_id,
                    "update":update,
                    "_meta":{"liveGeneration":page_generation,"liveCursor":envelope.cursor}
                }),
            )
            .map_err(|_| server_error(AcpServerErrorCode::KernelFailed))?,
        );
    }
    Ok((page_generation, page.cursor, frames, pending_approval))
}

fn render_service_event(session_id: &str, task_id: TaskId, envelope: &EventEnvelope) -> Vec<Value> {
    let Event::TaskLifecycle { event, .. } = &envelope.event else {
        return Vec::new();
    };
    let update = match event {
        TaskEvent::Created { .. } => json!({
            "sessionUpdate":"task_status","taskId":task_id,"status":"queued"
        }),
        TaskEvent::StateTransitioned { to, .. } => json!({
            "sessionUpdate":"task_status","taskId":task_id,"status":to
        }),
        TaskEvent::ContractRevised { contract } => json!({
            "sessionUpdate":"completion_clauses","taskId":task_id,
            "clauses":contract.clauses
        }),
        TaskEvent::EpochStarted {
            epoch_id,
            objective,
        } => json!({
            "sessionUpdate":"epoch_objective","taskId":task_id,
            "epochId":epoch_id,"objective":objective
        }),
        TaskEvent::CheckpointCommitted {
            checkpoint_id,
            digest,
        } => json!({
            "sessionUpdate":"checkpoint_committed","taskId":task_id,
            "checkpointId":checkpoint_id,"digest":digest
        }),
        TaskEvent::UsageObserved {
            total_tokens,
            context_window,
            ..
        } => json!({
            "sessionUpdate":"context_usage","taskId":task_id,
            "totalTokens":total_tokens,"contextWindow":context_window
        }),
        TaskEvent::CompactionCompleted { generation, .. } => json!({
            "sessionUpdate":"compaction","taskId":task_id,"generation":generation
        }),
        TaskEvent::OperationIntentRecorded {
            operation_id,
            effect_class,
            ..
        } => json!({
            "sessionUpdate":"tool_call","taskId":task_id,
            "toolCallId":operation_id,"title":format!("{effect_class:?}"),
            "kind":"execute","status":"pending"
        }),
        TaskEvent::OperationTransitioned {
            operation_id, to, ..
        } => json!({
            "sessionUpdate":"tool_call_update","taskId":task_id,
            "toolCallId":operation_id,"status":format!("{to:?}").to_lowercase()
        }),
        TaskEvent::ConfigurationQueued {
            model,
            effort,
            permission_mode,
            ..
        } => json!({
            "sessionUpdate":"session_info_update","taskId":task_id,
            "_meta":{"model":model.as_str(),"thoughtLevel":effort.as_codex_value(),
                "mode":permission_mode.as_wire_str(),"pending":true}
        }),
        TaskEvent::CancellationRequested => json!({
            "sessionUpdate":"task_status","taskId":task_id,"status":"cancelling"
        }),
        TaskEvent::Blocked { reason } => json!({
            "sessionUpdate":"task_status","taskId":task_id,"status":"blocked","reason":reason
        }),
        TaskEvent::Completed => json!({
            "sessionUpdate":"task_status","taskId":task_id,"status":"completed"
        }),
        _ => return Vec::new(),
    };
    vec![json!({
        "sessionId":session_id,
        "update":update,
        "_meta":{"eventSequence":envelope.sequence}
    })]
}

fn service_outgoing(id: JsonRpcId, result: Result<Value, AcpServerError>) -> OutgoingFrame {
    match result {
        Ok(value) => OutgoingFrame::result(id, value),
        Err(_) => OutgoingFrame::error(id, -32602, "invalid params"),
    }
}

fn service_config_options(
    info: &crate::service::protocol::ServiceInfo,
    model: &ModelId,
    effort: ReasoningEffort,
    mode: PermissionMode,
) -> Vec<Value> {
    let effort_options = info
        .models
        .iter()
        .find(|candidate| candidate.id == *model)
        .map(|candidate| candidate.supported_efforts.as_slice())
        .unwrap_or(&[]);
    vec![
        json!({"configId":"model","name":"Model","type":"select","currentValue":model.as_str(),"options":info.models.iter().map(|candidate| json!({"value":candidate.id.as_str(),"displayName":candidate.display_name})).collect::<Vec<_>>()}),
        json!({"configId":"thought_level","name":"Thought level","type":"select","currentValue":effort.as_codex_value(),"options":effort_options.iter().map(|candidate| json!({"value":candidate.as_codex_value(),"displayName":candidate.as_codex_value()})).collect::<Vec<_>>()}),
        json!({"configId":"mode","name":"Mode","type":"select","currentValue":mode.as_wire_str(),"options":PermissionMode::ALL.map(|candidate| json!({"value":candidate.as_wire_str(),"displayName":candidate.as_wire_str()}))}),
    ]
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
        tokio::select! {
            () = cancelled.cancelled() => {
                return Err(server_error(AcpServerErrorCode::OutputUnavailable));
            }
            result = write_frame(&mut writer, &frame, MAX_FRAME_BYTES) => {
                if result.is_err() {
                    cancelled.cancel();
                    return Err(server_error(AcpServerErrorCode::Transport));
                }
            }
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

fn service_permission_slash(blocks: &[String]) -> Option<PermissionMode> {
    match blocks.first()?.trim() {
        "/permissions fullAccess" => Some(PermissionMode::FullAccess),
        "/permissions approval" => Some(PermissionMode::Default),
        "/permissions readOnly" => Some(PermissionMode::Plan),
        _ => None,
    }
}

fn service_maintenance_shaped(blocks: &[String]) -> bool {
    let Some(command) = blocks.first().map(String::as_str) else {
        return false;
    };
    matches!(
        command,
        "/maintenance status"
            | "/maintenance prepare"
            | "maintenance status"
            | "maintenance prepare"
            | "carl maintenance prepare"
            | "prepare maintenance"
    )
}

fn service_approval_slash(
    blocks: &[String],
) -> Result<(ServiceApprovalDecision, String), AcpServerError> {
    let command = blocks
        .first()
        .map(|block| block.trim())
        .ok_or_else(invalid_input)?;
    let (decision, display_code) = if let Some(code) = command.strip_prefix("/approve ") {
        (ServiceApprovalDecision::Approve, code)
    } else if let Some(code) = command.strip_prefix("/deny ") {
        (ServiceApprovalDecision::Deny, code)
    } else {
        return Err(invalid_input());
    };
    if display_code.is_empty()
        || display_code.len() > 128
        || display_code.chars().any(char::is_whitespace)
    {
        return Err(invalid_input());
    }
    Ok((decision, display_code.to_owned()))
}

fn service_approval_shaped(blocks: &[String]) -> bool {
    blocks.first().is_some_and(|block| {
        let command = block.trim();
        command.starts_with("/approve ") || command.starts_with("/deny ")
    })
}

fn task_control_digest(method: &str, task_id: TaskId, text: Option<&str>) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"carl.task-control.v1\0");
    hasher.update((method.len() as u64).to_be_bytes());
    hasher.update(method.as_bytes());
    hasher.update(task_id.to_string().as_bytes());
    if let Some(text) = text {
        hasher.update((text.len() as u64).to_be_bytes());
        hasher.update(text.as_bytes());
    } else {
        hasher.update(0_u64.to_be_bytes());
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn task_control_identity(
    external_session_id: &str,
    idempotency_key: &str,
    task_id: TaskId,
    method: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"carl.task-control-identity.v1\0");
    for value in [external_session_id, idempotency_key, method] {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update(task_id.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
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

#[cfg(test)]
mod tests {
    use super::{PermissionMode, service_maintenance_shaped, service_permission_slash};

    #[test]
    fn maintenance_invocations_are_recognized_only_as_exact_owner_private_shapes() {
        for command in [
            "/maintenance status",
            "/maintenance prepare",
            "maintenance status",
            "maintenance prepare",
            "carl maintenance prepare",
            "prepare maintenance",
        ] {
            assert!(service_maintenance_shaped(&[
                command.to_owned(),
                "Buzz metadata".to_owned()
            ]));
        }
        for blocks in [
            vec!["please prepare maintenance later".to_owned()],
            vec!["\n/maintenance prepare".to_owned()],
            vec!["quoted:\n/maintenance prepare".to_owned()],
            vec!["/maintenance prepare now".to_owned()],
            vec!["/maintenance prepare ".to_owned()],
            vec![
                "ordinary input".to_owned(),
                "/maintenance prepare".to_owned(),
            ],
        ] {
            assert!(!service_maintenance_shaped(&blocks));
        }
    }

    #[test]
    fn persistent_permission_slashes_require_an_exact_leading_block() {
        for (command, expected) in [
            ("/permissions fullAccess", PermissionMode::FullAccess),
            ("/permissions approval", PermissionMode::Default),
            ("/permissions readOnly", PermissionMode::Plan),
        ] {
            assert_eq!(
                service_permission_slash(&[command.to_owned(), "Buzz metadata".to_owned()]),
                Some(expected)
            );
        }

        for blocks in [
            vec!["please use /permissions readOnly".to_owned()],
            vec!["quoted:\n/permissions readOnly".to_owned()],
            vec!["/permissions readOnly now".to_owned()],
            vec![
                "ordinary input".to_owned(),
                "/permissions readOnly".to_owned(),
            ],
        ] {
            assert_eq!(service_permission_slash(&blocks), None);
        }
    }
}
