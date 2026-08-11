use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use chrono::{TimeDelta, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::session::{
    ConfigOutcome, ConfigSelection, KernelError, KernelErrorCode, KernelSession, KernelUpdate,
    NewSessionRequest, Prompt, PromptOutcome, PromptStopReason, TaskContextView, TaskView,
    ToolKind, ToolStatus,
};
use super::{
    BuzzContext, BuzzErrorCode, BuzzPublisher, ConfigChange, ModeActivation, ModelCatalog,
    ModelDescriptor, PermissionMode, PermissionProfile, SessionConfiguration,
};
use crate::delegates::DelegateSettings;
use crate::events::{ApprovalId, Event, SessionId, ToolCallId, TurnId};
use crate::policy::{ActorId, Frontend, Sha256Digest};
use crate::runtime::agent_port::{
    AgentContextId, AgentEffectKind, AgentEffectRequest, AgentEpochId, AgentEvent, AgentItem,
    AgentModel, AgentPort, AgentPortError, EffectDecision, StartAgentContext, StartAgentEpoch,
};
use crate::runtime::task::{
    EngineToolKind, EngineToolStatus, StartTask, TaskBudget, TaskEngine, TaskEngineError,
    TaskEngineErrorCode, TaskEngineUpdate, TaskId,
};
use crate::runtime::task::{
    TaskEngineAcknowledgement, TaskEngineControl, TaskEngineFrontendContext,
    TaskEnginePermissionNotice,
};
use crate::security::SecretFilter;
use crate::storage::{
    ApprovalStatus, BoundApprovalBinding, DeliveryKind, DeliveryStatus, ExternalSessionId,
    NewDelivery, NewFrontendSession, NewRemoteCode, ProviderRequestId, ProviderThreadId,
    RemoteCodeClaim, RemoteCodeKind, RuntimeStore, Store, TaskControlMutationClaim,
    TaskControlMutationInput,
};

const COMMAND_CAPACITY: usize = 64;
const ROUTED_EVENT_CAPACITY: usize = 1_024;
const ROUTED_EVENTS_PER_SESSION: usize = 256;
const APPROVAL_LIFETIME: TimeDelta = TimeDelta::minutes(15);
const MAX_FINAL_MESSAGE_BYTES: usize = 256 * 1_024;

impl From<TaskEngineUpdate> for KernelUpdate {
    fn from(update: TaskEngineUpdate) -> Self {
        match update {
            TaskEngineUpdate::TaskStatus { task_id, status } => {
                Self::TaskStatus { task_id, status }
            }
            TaskEngineUpdate::EpochObjective {
                task_id,
                epoch_id,
                objective,
            } => Self::EpochObjective {
                task_id,
                epoch_id,
                objective,
            },
            TaskEngineUpdate::CheckpointCommitted {
                task_id,
                checkpoint_id,
                digest,
            } => Self::CheckpointCommitted {
                task_id,
                checkpoint_id,
                digest,
            },
            TaskEngineUpdate::ContextUsage {
                task_id,
                total_tokens,
                context_window,
            } => Self::ContextUsage {
                task_id,
                total_tokens,
                context_window,
            },
            TaskEngineUpdate::Compaction {
                task_id,
                generation,
                replaced_provider,
            } => Self::Compaction {
                task_id,
                generation,
                replaced_provider,
            },
            TaskEngineUpdate::RecoveryStrategy { task_id, strategy } => {
                Self::RecoveryStrategy { task_id, strategy }
            }
            TaskEngineUpdate::CompletionClauses { task_id, clauses } => {
                Self::CompletionClauses { task_id, clauses }
            }
            TaskEngineUpdate::AgentMessageChunk(text) => Self::AgentMessageChunk(text),
            TaskEngineUpdate::ToolStarted { title, kind } => Self::ToolStarted {
                title,
                kind: match kind {
                    EngineToolKind::Execute => ToolKind::Execute,
                    EngineToolKind::Edit => ToolKind::Edit,
                },
            },
            TaskEngineUpdate::ToolCompleted { title, status } => Self::ToolCompleted {
                title,
                status: match status {
                    EngineToolStatus::Completed => ToolStatus::Completed,
                    EngineToolStatus::Failed | EngineToolStatus::Cancelled => ToolStatus::Failed,
                },
            },
            TaskEngineUpdate::DiffUpdated(diff) => Self::DiffUpdated(diff),
            TaskEngineUpdate::PermissionRequired {
                request_id,
                summary,
            } => {
                Self::AgentMessageChunk(format!("Permission required for {request_id}: {summary}"))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationFailure {
    Failed,
    Uncertain,
}

pub trait KernelPublisher: Send {
    fn send_message<'a>(
        &'a mut self,
        context: &'a BuzzContext,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), PublicationFailure>> + Send + 'a>>;

    fn send_diff<'a>(
        &'a mut self,
        context: &'a BuzzContext,
        diff: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), PublicationFailure>> + Send + 'a>>;
}

impl KernelPublisher for BuzzPublisher {
    fn send_message<'a>(
        &'a mut self,
        context: &'a BuzzContext,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), PublicationFailure>> + Send + 'a>> {
        Box::pin(async move {
            BuzzPublisher::send_message(self, context, content, CancellationToken::new())
                .await
                .map_err(map_publication_error)
        })
    }

    fn send_diff<'a>(
        &'a mut self,
        context: &'a BuzzContext,
        diff: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), PublicationFailure>> + Send + 'a>> {
        Box::pin(async move {
            BuzzPublisher::send_diff(self, context, diff, CancellationToken::new())
                .await
                .map_err(map_publication_error)
        })
    }
}

pub enum KernelCommand {
    NewSession {
        request: NewSessionRequest,
        reply: oneshot::Sender<Result<KernelSession, KernelError>>,
    },
    Prompt {
        session_id: SessionId,
        prompt: Prompt,
        reply: oneshot::Sender<Result<PromptOutcome, KernelError>>,
    },
    SetConfig {
        session_id: SessionId,
        selection: ConfigSelection,
        reply: oneshot::Sender<Result<ConfigOutcome, KernelError>>,
    },
    AttachBuzzContext {
        session_id: SessionId,
        context: BuzzContext,
        reply: oneshot::Sender<Result<(), KernelError>>,
    },
    InstallPublisher {
        publisher: Box<dyn KernelPublisher>,
        reply: oneshot::Sender<Result<(), KernelError>>,
    },
    Cancel {
        session_id: SessionId,
        task_id: Option<TaskId>,
        control_id: Option<String>,
        reply: oneshot::Sender<Result<(), KernelError>>,
    },
    Steer {
        session_id: SessionId,
        input: String,
        task_id: Option<TaskId>,
        control_id: Option<String>,
        reply: oneshot::Sender<Result<(), KernelError>>,
    },
    TaskStatus {
        session_id: SessionId,
        task_id: TaskId,
        reply: oneshot::Sender<Result<TaskView, KernelError>>,
    },
    TaskList {
        session_id: SessionId,
        reply: oneshot::Sender<Result<Vec<TaskView>, KernelError>>,
    },
    TaskContext {
        session_id: SessionId,
        task_id: TaskId,
        reply: oneshot::Sender<Result<TaskContextView, KernelError>>,
    },
    TaskResume {
        session_id: SessionId,
        task_id: TaskId,
        control_id: String,
        reply: oneshot::Sender<Result<TaskView, KernelError>>,
    },
    ClaimTaskMutation {
        input: TaskControlMutationInput,
        reply: oneshot::Sender<Result<TaskControlMutationClaim, KernelError>>,
    },
    CompleteTaskMutation {
        input: TaskControlMutationInput,
        reply: oneshot::Sender<Result<String, KernelError>>,
    },
    FailTaskMutation {
        input: TaskControlMutationInput,
        reply: oneshot::Sender<Result<(), KernelError>>,
    },
    Shutdown {
        reply: oneshot::Sender<Result<(), KernelError>>,
    },
}

#[derive(Clone)]
pub struct KernelHandle {
    commands: mpsc::Sender<KernelCommand>,
    catalog: Arc<ModelCatalog>,
}

impl std::fmt::Debug for KernelHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KernelHandle(<bounded-channel>)")
    }
}

impl KernelHandle {
    #[must_use]
    pub fn catalog(&self) -> &ModelCatalog {
        &self.catalog
    }

    pub async fn new_session(
        &self,
        request: NewSessionRequest,
    ) -> Result<KernelSession, KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::NewSession { request, reply })
            .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn prompt(
        &self,
        session_id: SessionId,
        prompt: Prompt,
    ) -> Result<PromptOutcome, KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::Prompt {
            session_id,
            prompt,
            reply,
        })
        .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn set_config(
        &self,
        session_id: SessionId,
        selection: ConfigSelection,
    ) -> Result<ConfigOutcome, KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::SetConfig {
            session_id,
            selection,
            reply,
        })
        .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn attach_buzz_context(
        &self,
        session_id: SessionId,
        context: BuzzContext,
    ) -> Result<(), KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::AttachBuzzContext {
            session_id,
            context,
            reply,
        })
        .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn install_publisher(
        &self,
        publisher: Box<dyn KernelPublisher>,
    ) -> Result<(), KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::InstallPublisher { publisher, reply })
            .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn cancel(&self, session_id: SessionId) -> Result<(), KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::Cancel {
            session_id,
            task_id: None,
            control_id: None,
            reply,
        })
        .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn steer(&self, session_id: SessionId, input: String) -> Result<(), KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::Steer {
            session_id,
            input,
            task_id: None,
            control_id: None,
            reply,
        })
        .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn task_status(
        &self,
        session_id: SessionId,
        task_id: TaskId,
    ) -> Result<TaskView, KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::TaskStatus {
            session_id,
            task_id,
            reply,
        })
        .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn task_list(&self, session_id: SessionId) -> Result<Vec<TaskView>, KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::TaskList { session_id, reply })
            .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn task_context(
        &self,
        session_id: SessionId,
        task_id: TaskId,
    ) -> Result<TaskContextView, KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::TaskContext {
            session_id,
            task_id,
            reply,
        })
        .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn task_cancel(
        &self,
        session_id: SessionId,
        task_id: TaskId,
        control_id: String,
    ) -> Result<(), KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::Cancel {
            session_id,
            task_id: Some(task_id),
            control_id: Some(control_id),
            reply,
        })
        .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn task_steer(
        &self,
        session_id: SessionId,
        task_id: TaskId,
        input: String,
        control_id: String,
    ) -> Result<(), KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::Steer {
            session_id,
            input,
            task_id: Some(task_id),
            control_id: Some(control_id),
            reply,
        })
        .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn task_resume(
        &self,
        session_id: SessionId,
        task_id: TaskId,
        control_id: String,
    ) -> Result<TaskView, KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::TaskResume {
            session_id,
            task_id,
            control_id,
            reply,
        })
        .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn claim_task_mutation(
        &self,
        input: TaskControlMutationInput,
    ) -> Result<TaskControlMutationClaim, KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::ClaimTaskMutation { input, reply })
            .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn complete_task_mutation(
        &self,
        input: TaskControlMutationInput,
    ) -> Result<String, KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::CompleteTaskMutation { input, reply })
            .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn fail_task_mutation(
        &self,
        input: TaskControlMutationInput,
    ) -> Result<(), KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::FailTaskMutation { input, reply })
            .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn shutdown(&self) -> Result<(), KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::Shutdown { reply }).await?;
        result.await.map_err(|_| stopped_error())?
    }

    async fn send(&self, command: KernelCommand) -> Result<(), KernelError> {
        self.commands
            .send(command)
            .await
            .map_err(|_| stopped_error())
    }
}

pub struct Kernel;

impl Kernel {
    pub async fn start<A: AgentPort + 'static>(
        store: RuntimeStore,
        agent: A,
        publisher: Option<BuzzPublisher>,
    ) -> Result<KernelHandle, KernelError> {
        Self::start_with_ports(
            store,
            Box::new(agent),
            publisher.map(|publisher| Box::new(publisher) as Box<dyn KernelPublisher>),
        )
        .await
    }

    pub async fn start_with_ports(
        store: RuntimeStore,
        mut agent: Box<dyn AgentPort>,
        publisher: Option<Box<dyn KernelPublisher>>,
    ) -> Result<KernelHandle, KernelError> {
        let provider_models = agent.models().await.map_err(map_agent_port)?;
        let catalog = Arc::new(catalog_from_provider(&provider_models)?);
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let handle = KernelHandle {
            commands,
            catalog: Arc::clone(&catalog),
        };
        let durable_tasks = agent.supports_autonomous_tasks();
        let admission_store = Mutex::new(store.open_peer_store().map_err(map_storage)?);
        let mut engine = TaskEngine::new_runtime(store, agent);
        engine.reconcile_startup().await.map_err(map_task_engine)?;
        tokio::spawn(
            KernelActor {
                engine: Some(engine),
                admission_store,
                durable_tasks,
                publisher,
                catalog,
                sessions: HashMap::new(),
                routed_events: HashMap::new(),
                routed_event_count: 0,
                routed_failures: HashSet::new(),
                shutdown_requested: false,
                receiver,
            }
            .run(),
        );
        Ok(handle)
    }
}

struct SessionState {
    public: KernelSession,
    cwd: std::path::PathBuf,
    actor_id: ActorId,
    frontend: Frontend,
    buzz_context: Option<BuzzContext>,
    provider_context: Option<AgentContextId>,
    active: Option<ActiveTurn>,
    pending_bypass: Option<PendingBypass>,
    pending_configuration: Option<SessionConfiguration>,
    task_id: Option<crate::runtime::task::TaskId>,
}

struct ActiveTurn {
    local_turn_id: TurnId,
    provider_epoch_id: AgentEpochId,
    pending_approval: Option<PendingApproval>,
    assistant_text: String,
    item_ids: HashMap<String, (ToolCallId, AgentEffectKind)>,
}

struct PendingApproval {
    request: AgentEffectRequest,
    approval_id: ApprovalId,
    binding: BoundApprovalBinding,
}

struct PendingBypass {
    request_digest: Sha256Digest,
}

struct KernelActor {
    engine: Option<TaskEngine<Box<dyn AgentPort>, RuntimeStore>>,
    admission_store: Mutex<Store>,
    durable_tasks: bool,
    publisher: Option<Box<dyn KernelPublisher>>,
    catalog: Arc<ModelCatalog>,
    sessions: HashMap<SessionId, SessionState>,
    routed_events: HashMap<SessionId, VecDeque<AgentEvent>>,
    routed_event_count: usize,
    routed_failures: HashSet<SessionId>,
    shutdown_requested: bool,
    receiver: mpsc::Receiver<KernelCommand>,
}

enum PendingDurableReply {
    Prompt(oneshot::Sender<Result<PromptOutcome, KernelError>>),
    Steer(oneshot::Sender<Result<(), KernelError>>),
    Cancel(oneshot::Sender<Result<(), KernelError>>),
    Shutdown(oneshot::Sender<Result<(), KernelError>>),
    Approval,
    Config {
        reply: oneshot::Sender<Result<ConfigOutcome, KernelError>>,
        outcome: ConfigOutcome,
        task_id: TaskId,
    },
}

enum AgentEventOwner {
    Global,
    Session(SessionId),
    Unowned,
}

impl KernelActor {
    fn engine_ref(&self) -> &TaskEngine<Box<dyn AgentPort>, RuntimeStore> {
        self.engine.as_ref().expect("kernel engine is actor-owned")
    }

    fn engine_mut(&mut self) -> &mut TaskEngine<Box<dyn AgentPort>, RuntimeStore> {
        self.engine.as_mut().expect("kernel engine is actor-owned")
    }

    fn should_drive_durable_prompt(&self, session_id: SessionId, prompt: &Prompt) -> bool {
        self.durable_tasks
            && prompt.leading_slash_command().is_none()
            && self
                .sessions
                .get(&session_id)
                .is_some_and(|state| state.active.is_none())
    }

    async fn run(mut self) {
        while let Some(command) = self.receiver.recv().await {
            let should_stop = match command {
                KernelCommand::NewSession { request, reply } => {
                    let _ = reply.send(self.new_session(request).await);
                    false
                }
                KernelCommand::Prompt {
                    session_id,
                    prompt,
                    reply,
                } => {
                    if self.should_drive_durable_prompt(session_id, &prompt) {
                        let _ = self.begin_durable_prompt(session_id, prompt, reply).await;
                    } else {
                        let outcome = self.begin_prompt(session_id, prompt).await;
                        let _ = reply.send(outcome);
                    }
                    self.shutdown_requested
                }
                KernelCommand::SetConfig {
                    session_id,
                    selection,
                    reply,
                } => {
                    let result = self.set_config(session_id, selection);
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::AttachBuzzContext {
                    session_id,
                    context,
                    reply,
                } => {
                    let result = self.attach_buzz_context(session_id, context).await;
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::InstallPublisher { publisher, reply } => {
                    let result = if self.publisher.is_none() && self.sessions.is_empty() {
                        self.publisher = Some(publisher);
                        Ok(())
                    } else {
                        Err(KernelError::from_code(KernelErrorCode::InvalidInput))
                    };
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::Cancel {
                    session_id,
                    task_id,
                    control_id,
                    reply,
                } => {
                    let result = match (task_id, control_id) {
                        (None, None) => self.cancel_session(session_id).await,
                        (Some(task_id), Some(control_id)) => {
                            match task_view(
                                self.engine_ref().store(),
                                &self.sessions,
                                session_id,
                                task_id,
                            ) {
                                Ok(_) => self
                                    .engine_mut()
                                    .cancel_controlled(task_id, Some(&control_id))
                                    .await
                                    .map_err(map_task_engine),
                                Err(error) => Err(error),
                            }
                        }
                        _ => Err(invalid_input()),
                    };
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::Steer {
                    session_id,
                    input,
                    task_id,
                    control_id,
                    reply,
                } => {
                    let result = match (task_id, control_id) {
                        (None, None) => self.steer_session(session_id, input).await,
                        (Some(task_id), Some(control_id)) => {
                            let binding = task_view(
                                self.engine_ref().store(),
                                &self.sessions,
                                session_id,
                                task_id,
                            );
                            match binding {
                                Ok(_) => self
                                    .engine_mut()
                                    .steer_controlled(task_id, input, Some(&control_id))
                                    .await
                                    .map_err(map_task_engine),
                                Err(error) => Err(error),
                            }
                        }
                        _ => Err(invalid_input()),
                    };
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::TaskStatus {
                    session_id,
                    task_id,
                    reply,
                } => {
                    let result = task_view(
                        self.engine_ref().store(),
                        &self.sessions,
                        session_id,
                        task_id,
                    );
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::TaskList { session_id, reply } => {
                    let result = task_views(self.engine_ref().store(), &self.sessions, session_id);
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::TaskContext {
                    session_id,
                    task_id,
                    reply,
                } => {
                    let result = task_context_view(
                        self.engine_ref().store(),
                        &self.sessions,
                        session_id,
                        task_id,
                    );
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::TaskResume {
                    session_id,
                    task_id,
                    control_id,
                    reply,
                } => {
                    let result = self.resume_task(session_id, task_id, &control_id).await;
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::ClaimTaskMutation { input, reply } => {
                    let result = self
                        .engine_ref()
                        .store()
                        .claim_task_control_mutation(input)
                        .map_err(map_storage);
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::CompleteTaskMutation { input, reply } => {
                    let result = self
                        .engine_ref()
                        .store()
                        .complete_task_control_mutation(input)
                        .map_err(map_storage);
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::FailTaskMutation { input, reply } => {
                    let result = self
                        .engine_ref()
                        .store()
                        .fail_task_control_mutation(input, -32602)
                        .map_err(map_storage);
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::Shutdown { reply } => {
                    let result = self
                        .engine_mut()
                        .port_mut()
                        .shutdown()
                        .await
                        .map_err(map_agent_port);
                    let _ = reply.send(result);
                    true
                }
            };
            if should_stop {
                break;
            }
        }
        if let Some(engine) = self.engine.as_mut() {
            let _ = engine.port_mut().shutdown().await;
        }
    }

    async fn new_session(
        &mut self,
        request: NewSessionRequest,
    ) -> Result<KernelSession, KernelError> {
        let buzz_binding_valid = match (&request.buzz_context, &request.channel_id) {
            (Some(context), Some(channel)) if request.frontend == Frontend::Buzz => {
                channel.as_str() == context.channel_id().to_string()
            }
            (None, None) => true,
            _ => false,
        };
        if !matches!(request.protocol_version, 1 | 2) || !buzz_binding_valid {
            return Err(invalid_input());
        }
        let model = request
            .model
            .clone()
            .unwrap_or_else(|| self.catalog.models()[0].id().clone());
        let descriptor = self.catalog.find(&model).ok_or_else(invalid_input)?;
        let effort = request
            .effort
            .unwrap_or_else(|| descriptor.supported_efforts()[0]);
        let configuration =
            SessionConfiguration::new((*self.catalog).clone(), model.clone(), effort, request.mode)
                .map_err(|_| invalid_input())?;
        let created = self
            .engine_ref()
            .store()
            .create_session()
            .map_err(map_storage)?;
        let bound = self
            .engine_ref()
            .store()
            .bind_frontend_session(NewFrontendSession {
                frontend: request.frontend,
                external_session_id: request.external_session_id.clone(),
                session_id: created.id,
                cwd: request.cwd.clone(),
                protocol_version: request.protocol_version,
                client_name: request.client_name,
                permission_mode: request.mode,
                channel_id: request.channel_id,
                created_at: created.created_at,
            })
            .map_err(map_storage)?;
        self.engine_mut()
            .store_mut()
            .append(
                created.id,
                None,
                Event::FrontendSessionBound {
                    frontend: bound.frontend,
                    external_session_id: bound.external_session_id.as_str().to_owned(),
                    protocol_version: bound.protocol_version,
                },
            )
            .map_err(map_storage)?;
        let provider_context = if request.frontend == Frontend::Buzz {
            None
        } else {
            let context = self
                .engine_mut()
                .port_mut()
                .start_context(StartAgentContext {
                    cwd: request.cwd.clone(),
                    model,
                    permission_mode: request.mode,
                })
                .await
                .map_err(map_agent_port)?;
            let provider_thread_id =
                ProviderThreadId::try_from(context.as_str()).map_err(|_| provider_error())?;
            self.engine_ref()
                .store()
                .configure_frontend_session(
                    &bound.external_session_id,
                    Some(&provider_thread_id),
                    request.mode,
                    Utc::now(),
                )
                .map_err(map_storage)?;
            Some(context)
        };
        let public =
            KernelSession::new(created.id, bound.external_session_id.clone(), configuration);
        self.sessions.insert(
            created.id,
            SessionState {
                public: public.clone(),
                cwd: request.cwd,
                actor_id: request.actor_id,
                frontend: request.frontend,
                buzz_context: request.buzz_context,
                provider_context,
                active: None,
                pending_bypass: None,
                pending_configuration: None,
                task_id: None,
            },
        );
        Ok(public)
    }

    async fn begin_prompt(
        &mut self,
        session_id: SessionId,
        prompt: Prompt,
    ) -> Result<PromptOutcome, KernelError> {
        let actor_mismatch = self
            .sessions
            .get(&session_id)
            .ok_or_else(unknown_session)
            .map(|state| {
                prompt
                    .actor_id()
                    .is_some_and(|actor| actor != &state.actor_id)
            })?;
        if actor_mismatch {
            return Err(KernelError::from_code(KernelErrorCode::ApprovalUnavailable));
        }
        if self.routed_failures.remove(&session_id) {
            return Err(provider_error());
        }
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        if state.active.is_some() {
            if state
                .active
                .as_ref()
                .is_some_and(|active| active.pending_approval.is_some())
            {
                return self.resume_approval(session_id, prompt).await;
            }
            return Err(session_busy());
        }
        if prompt.leading_slash_command().is_some_and(|command| {
            command.starts_with("/approve ") || command.starts_with("/deny ")
        }) {
            return Err(KernelError::from_code(KernelErrorCode::ApprovalUnavailable));
        }
        if let Some(command) = prompt.leading_slash_command()
            && command.starts_with("/confirm-bypass ")
        {
            return self
                .confirm_bypass(session_id, command)
                .map(|configuration| PromptOutcome {
                    stop_reason: PromptStopReason::EndTurn,
                    updates: vec![KernelUpdate::SessionInfoChanged { configuration }],
                });
        }
        if let Some(command) = prompt.leading_slash_command()
            && command == "/permissions bypassPermissions"
        {
            let ConfigOutcome::PendingBypass { display_code } = self.set_config(
                session_id,
                ConfigSelection::Mode {
                    mode: PermissionMode::BypassPermissions,
                    remote: true,
                },
            )?
            else {
                return Err(invalid_input());
            };
            return Ok(PromptOutcome {
                stop_reason: PromptStopReason::EndTurn,
                updates: vec![KernelUpdate::AgentMessageChunk(format!(
                    "Confirm bypass with /confirm-bypass {display_code}"
                ))],
            });
        }
        if let Some(command) = prompt.task_slash_command() {
            return self.handle_task_slash(session_id, command).await;
        }

        let input = prompt.provider_text();
        SecretFilter
            .inspect(input.as_bytes())
            .map_err(|_| invalid_input())?;
        let local_turn_id = TurnId::new();
        self.engine_mut()
            .store_mut()
            .append(
                session_id,
                Some(local_turn_id),
                Event::UserInput {
                    text: input.clone(),
                },
            )
            .map_err(map_storage)?;
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        let context_id = state
            .provider_context
            .clone()
            .ok_or_else(|| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        let model = state.public.configuration().model().clone();
        let effort = state.public.configuration().effort();
        let permission_mode = state.public.configuration().mode();
        let provider_epoch_id = self
            .engine_mut()
            .port_mut()
            .start_epoch(StartAgentEpoch {
                context_id,
                input,
                model,
                effort,
                permission_mode,
            })
            .await
            .map_err(map_agent_port)?;
        self.sessions
            .get_mut(&session_id)
            .ok_or_else(unknown_session)?
            .active = Some(ActiveTurn {
            local_turn_id,
            provider_epoch_id,
            pending_approval: None,
            assistant_text: String::new(),
            item_ids: HashMap::new(),
        });
        self.drive_turn(session_id).await
    }

    async fn handle_task_slash(
        &mut self,
        session_id: SessionId,
        command: &str,
    ) -> Result<PromptOutcome, KernelError> {
        let message = match command {
            "/permissions fullAccess" => {
                let trusted = self
                    .sessions
                    .get(&session_id)
                    .ok_or_else(unknown_session)
                    .is_ok_and(|state| {
                        state.frontend == Frontend::Acp
                            || (state.frontend == Frontend::Buzz && state.buzz_context.is_some())
                    });
                if !trusted {
                    return Err(KernelError::from_code(KernelErrorCode::ApprovalUnavailable));
                }
                let ConfigOutcome::Applied(configuration) = self.set_config(
                    session_id,
                    ConfigSelection::Mode {
                        mode: PermissionMode::FullAccess,
                        remote: false,
                    },
                )?
                else {
                    return Err(invalid_input());
                };
                return Ok(PromptOutcome {
                    stop_reason: PromptStopReason::EndTurn,
                    updates: vec![KernelUpdate::SessionInfoChanged { configuration }],
                });
            }
            "/permissions approval" | "/permissions readOnly" => {
                let mode = if command.ends_with("approval") {
                    PermissionMode::Default
                } else {
                    PermissionMode::Plan
                };
                let ConfigOutcome::Applied(configuration) = self.set_config(
                    session_id,
                    ConfigSelection::Mode {
                        mode,
                        remote: false,
                    },
                )?
                else {
                    return Err(invalid_input());
                };
                return Ok(PromptOutcome {
                    stop_reason: PromptStopReason::EndTurn,
                    updates: vec![KernelUpdate::SessionInfoChanged { configuration }],
                });
            }
            "/status" => {
                let tasks = task_views(self.engine_ref().store(), &self.sessions, session_id)?;
                serde_json::to_string(&json!({"tasks":tasks})).map_err(|_| invalid_input())?
            }
            "/context" => {
                let task_id = self.latest_session_task(session_id)?;
                let context = task_context_view(
                    self.engine_ref().store(),
                    &self.sessions,
                    session_id,
                    task_id,
                )?;
                serde_json::to_string(&json!({"context":context})).map_err(|_| invalid_input())?
            }
            "/cancel" => {
                let task_id = self.latest_session_task(session_id)?;
                self.engine_mut()
                    .cancel(task_id)
                    .await
                    .map_err(map_task_engine)?;
                json!({"outcome":"accepted","taskId":task_id}).to_string()
            }
            "/resume" => {
                let task_id = self.latest_session_task(session_id)?;
                let snapshot = self
                    .engine_mut()
                    .run(task_id)
                    .await
                    .map_err(map_task_engine)?;
                self.sessions
                    .get_mut(&session_id)
                    .ok_or_else(unknown_session)?
                    .task_id = Some(task_id);
                serde_json::to_string(&json!({"task":TaskView::from(&snapshot)}))
                    .map_err(|_| invalid_input())?
            }
            _ => return Err(invalid_input()),
        };
        Ok(PromptOutcome {
            stop_reason: PromptStopReason::EndTurn,
            updates: vec![KernelUpdate::AgentMessageChunk(message)],
        })
    }

    fn latest_session_task(&self, session_id: SessionId) -> Result<TaskId, KernelError> {
        if let Some(task_id) = self
            .sessions
            .get(&session_id)
            .ok_or_else(unknown_session)?
            .task_id
        {
            return Ok(task_id);
        }
        self.engine_ref()
            .store()
            .list_tasks_for_session(session_id, 1)
            .map_err(map_storage)?
            .first()
            .map(|record| record.snapshot.task_id)
            .ok_or_else(invalid_input)
    }

    async fn begin_durable_prompt(
        &mut self,
        session_id: SessionId,
        prompt: Prompt,
        initial_reply: oneshot::Sender<Result<PromptOutcome, KernelError>>,
    ) -> Result<(), KernelError> {
        let actor_mismatch = self
            .sessions
            .get(&session_id)
            .ok_or_else(unknown_session)
            .map(|state| {
                prompt
                    .actor_id()
                    .is_some_and(|actor| actor != &state.actor_id)
            })?;
        if actor_mismatch {
            let _ = initial_reply.send(Err(KernelError::from_code(
                KernelErrorCode::ApprovalUnavailable,
            )));
            return Ok(());
        }
        let mut current_reply = Some(initial_reply);
        let input = prompt.provider_text();
        SecretFilter
            .inspect(input.as_bytes())
            .map_err(|_| invalid_input())?;
        let turn_id = TurnId::new();
        self.engine_mut()
            .store_mut()
            .append(
                session_id,
                Some(turn_id),
                Event::UserInput {
                    text: input.clone(),
                },
            )
            .map_err(map_storage)?;
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        let context_id = state
            .provider_context
            .clone()
            .ok_or_else(|| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        let workspace = state.cwd.clone();
        let model = state.public.configuration().model().clone();
        let effort = state.public.configuration().effort();
        let permission_mode = state.public.configuration().mode();
        let session_task = state.task_id;
        let actor_id = state.actor_id.clone();
        let external_session_id = state.public.external_session_id.clone();
        let existing_task = if let Some(task_id) = session_task {
            self.engine_ref()
                .store()
                .get_task(task_id)
                .map_err(map_storage)?
                .filter(|record| !record.snapshot.status.is_terminal())
                .map(|record| record.snapshot.task_id)
        } else {
            None
        };
        let (control_sender, control_receiver) = mpsc::channel(COMMAND_CAPACITY);
        let (acknowledgement_sender, mut acknowledgement_receiver) =
            mpsc::channel::<TaskEngineAcknowledgement>(COMMAND_CAPACITY);
        let (permission_sender, mut permission_receiver) =
            mpsc::channel::<TaskEnginePermissionNotice>(1);
        self.engine_mut().install_controls(
            control_receiver,
            acknowledgement_sender,
            permission_sender,
        );
        self.engine_mut()
            .install_frontend_context(TaskEngineFrontendContext {
                session_id,
                turn_id,
                external_session_id,
                actor_id: actor_id.clone(),
            });
        let mut pending = HashMap::<u64, PendingDurableReply>::new();
        let mut pending_permission = None::<TaskEnginePermissionNotice>;
        let mut deferred_permission_publications = Vec::<String>::new();
        let mut next_acknowledgement = 0_u64;
        let mut receiver_open = true;
        let mut durable_shutdown = false;
        let result = {
            let (engine, admission_store, receiver, sessions) = (
                &mut self.engine,
                &self.admission_store,
                &mut self.receiver,
                &mut self.sessions,
            );
            let engine = engine.as_mut().expect("kernel engine is actor-owned");
            let execution = async {
                if let Some(task_id) = existing_task {
                    engine.steer(task_id, input).await?;
                    engine.run(task_id).await
                } else {
                    engine
                        .start_in_context(
                            StartTask {
                                session_id,
                                workspace,
                                request: input,
                                model,
                                effort,
                                permission_mode,
                                budget: TaskBudget::default(),
                            },
                            context_id,
                        )
                        .await
                }
            };
            tokio::pin!(execution);
            loop {
                enum Next {
                    Finished(Result<crate::runtime::task::TaskSnapshot, TaskEngineError>),
                    Command(Option<KernelCommand>),
                    Acknowledged(Option<TaskEngineAcknowledgement>),
                    Permission(Option<TaskEnginePermissionNotice>),
                }
                let next = tokio::select! {
                    result = &mut execution => Next::Finished(result),
                    command = receiver.recv(), if receiver_open => Next::Command(command),
                    acknowledgement = acknowledgement_receiver.recv(), if !pending.is_empty() => {
                        Next::Acknowledged(acknowledgement)
                    }
                    permission = permission_receiver.recv() => Next::Permission(permission),
                };
                match next {
                    Next::Finished(result) => break result,
                    Next::Command(Some(command)) => {
                        let acknowledgement = next_acknowledgement;
                        next_acknowledgement = next_acknowledgement
                            .checked_add(1)
                            .ok_or_else(invalid_input)?;
                        match command {
                            KernelCommand::Prompt {
                                session_id: target,
                                prompt,
                                reply,
                            } if target == session_id => {
                                if prompt
                                    .actor_id()
                                    .is_some_and(|candidate| candidate != &actor_id)
                                {
                                    let _ = reply.send(Err(KernelError::from_code(
                                        KernelErrorCode::ApprovalUnavailable,
                                    )));
                                    continue;
                                }
                                if let Some(notice) = &pending_permission {
                                    let Some(command) = prompt.leading_slash_command() else {
                                        let _ = reply.send(Err(KernelError::from_code(
                                            KernelErrorCode::ApprovalUnavailable,
                                        )));
                                        continue;
                                    };
                                    let (decision, display_code) =
                                        if let Some(code) = command.strip_prefix("/approve ") {
                                            (EffectDecision::Allow, code)
                                        } else if let Some(code) = command.strip_prefix("/deny ") {
                                            (EffectDecision::Deny, code)
                                        } else {
                                            let _ = reply.send(Err(KernelError::from_code(
                                                KernelErrorCode::ApprovalUnavailable,
                                            )));
                                            continue;
                                        };
                                    if display_code != notice.display_code {
                                        let _ = reply.send(Err(KernelError::from_code(
                                            KernelErrorCode::ApprovalUnavailable,
                                        )));
                                        continue;
                                    }
                                    control_sender
                                        .send(TaskEngineControl::Approval {
                                            display_code: display_code.to_owned(),
                                            decision,
                                            session_id,
                                            turn_id,
                                            acknowledgement,
                                        })
                                        .await
                                        .map_err(|_| stopped_error())?;
                                    current_reply = Some(reply);
                                    pending.insert(acknowledgement, PendingDurableReply::Approval);
                                    continue;
                                }
                                let text = prompt.provider_text();
                                if validate_durable_steering(&text).is_err() {
                                    let _ = reply.send(Err(invalid_input()));
                                    continue;
                                }
                                let turn_id = TurnId::new();
                                let task_id =
                                    locked_active_durable_task_id(admission_store, session_id)?;
                                control_sender
                                    .send(TaskEngineControl::Steer {
                                        task_id,
                                        text,
                                        control_id: None,
                                        session_id,
                                        turn_id,
                                        acknowledgement,
                                    })
                                    .await
                                    .map_err(|_| stopped_error())?;
                                pending.insert(acknowledgement, PendingDurableReply::Prompt(reply));
                            }
                            KernelCommand::AttachBuzzContext {
                                session_id: target,
                                context,
                                reply,
                            } if target == session_id => {
                                let result = sessions
                                    .get(&session_id)
                                    .ok_or_else(unknown_session)
                                    .and_then(|state| {
                                        let matches_binding = state.frontend == Frontend::Buzz
                                            && state.buzz_context.as_ref().is_some_and(
                                                |existing| {
                                                    existing.channel_id() == context.channel_id()
                                                        && existing.actor_hex()
                                                            == context.actor_hex()
                                                },
                                            );
                                        if !matches_binding {
                                            return Err(KernelError::from_code(
                                                KernelErrorCode::ApprovalUnavailable,
                                            ));
                                        }
                                        let actor = ActorId::parse(context.actor_hex())
                                            .map_err(|_| invalid_input())?;
                                        let channel = crate::storage::ChannelId::try_from(
                                            context.channel_id().to_string(),
                                        )
                                        .map_err(map_storage)?;
                                        admission_store
                                            .lock()
                                            .map_err(|_| {
                                                KernelError::from_code(
                                                    KernelErrorCode::ProviderFailed,
                                                )
                                            })?
                                            .admit_trusted_frontend_message(
                                                Frontend::Buzz,
                                                &actor,
                                                &channel,
                                                &state.cwd,
                                                context.reply_to(),
                                                Utc::now(),
                                            )
                                            .map_err(|_| {
                                                KernelError::from_code(
                                                    KernelErrorCode::ApprovalUnavailable,
                                                )
                                            })?;
                                        Ok(())
                                    });
                                if result.is_ok()
                                    && let Some(state) = sessions.get_mut(&session_id)
                                {
                                    state.buzz_context = Some(context);
                                }
                                let _ = reply.send(result);
                            }
                            KernelCommand::SetConfig {
                                session_id: target,
                                selection,
                                reply,
                            } if target == session_id => {
                                let result = sessions
                                    .get_mut(&session_id)
                                    .ok_or_else(unknown_session)
                                    .and_then(|state| {
                                        queue_session_configuration(state, selection)
                                    });
                                let Ok(ConfigOutcome::Applied(configuration)) = &result else {
                                    let _ = reply.send(result);
                                    continue;
                                };
                                let task_id =
                                    locked_active_durable_task_id(admission_store, session_id)?;
                                if control_sender
                                    .send(TaskEngineControl::Configure {
                                        task_id,
                                        control_id: task_configuration_identity(
                                            task_id,
                                            acknowledgement,
                                            configuration,
                                        ),
                                        model: configuration.model().clone(),
                                        effort: configuration.effort(),
                                        permission_mode: configuration.mode(),
                                        acknowledgement,
                                    })
                                    .await
                                    .is_err()
                                {
                                    synchronize_session_configuration_from_projection(
                                        admission_store,
                                        sessions,
                                        session_id,
                                        task_id,
                                    )?;
                                    let _ = reply.send(Err(stopped_error()));
                                    continue;
                                }
                                pending.insert(
                                    acknowledgement,
                                    PendingDurableReply::Config {
                                        reply,
                                        outcome: ConfigOutcome::Applied(configuration.clone()),
                                        task_id,
                                    },
                                );
                            }
                            KernelCommand::Steer {
                                session_id: target,
                                input,
                                task_id,
                                control_id,
                                reply,
                            } if target == session_id => {
                                if validate_durable_steering(&input).is_err() {
                                    let _ = reply.send(Err(invalid_input()));
                                    continue;
                                }
                                if let Some(task_id) = task_id {
                                    let exact = admission_store
                                        .lock()
                                        .map_err(|_| provider_error())
                                        .and_then(|store| {
                                            task_view(&store, sessions, session_id, task_id)
                                        });
                                    if exact.is_err() || control_id.is_none() {
                                        let _ = reply.send(Err(invalid_input()));
                                        continue;
                                    }
                                    if locked_active_durable_task_id(admission_store, session_id)?
                                        != task_id
                                    {
                                        let _ = reply.send(Err(invalid_input()));
                                        continue;
                                    }
                                }
                                let task_id =
                                    locked_active_durable_task_id(admission_store, session_id)?;
                                control_sender
                                    .send(TaskEngineControl::Steer {
                                        task_id,
                                        text: input,
                                        control_id,
                                        session_id,
                                        turn_id: TurnId::new(),
                                        acknowledgement,
                                    })
                                    .await
                                    .map_err(|_| stopped_error())?;
                                pending.insert(acknowledgement, PendingDurableReply::Steer(reply));
                            }
                            KernelCommand::TaskStatus {
                                session_id: target,
                                task_id,
                                reply,
                            } if target == session_id => {
                                let result = admission_store
                                    .lock()
                                    .map_err(|_| provider_error())
                                    .and_then(|store| {
                                        task_view(&store, sessions, session_id, task_id)
                                    });
                                let _ = reply.send(result);
                            }
                            KernelCommand::TaskList {
                                session_id: target,
                                reply,
                            } if target == session_id => {
                                let result = admission_store
                                    .lock()
                                    .map_err(|_| provider_error())
                                    .and_then(|store| task_views(&store, sessions, session_id));
                                let _ = reply.send(result);
                            }
                            KernelCommand::TaskContext {
                                session_id: target,
                                task_id,
                                reply,
                            } if target == session_id => {
                                let result = admission_store
                                    .lock()
                                    .map_err(|_| provider_error())
                                    .and_then(|store| {
                                        task_context_view(&store, sessions, session_id, task_id)
                                    });
                                let _ = reply.send(result);
                            }
                            KernelCommand::TaskResume { reply, .. } => {
                                let _ = reply.send(Err(session_busy()));
                            }
                            KernelCommand::ClaimTaskMutation { input, reply } => {
                                let result = admission_store
                                    .lock()
                                    .map_err(|_| provider_error())
                                    .and_then(|store| {
                                        store
                                            .claim_task_control_mutation(input)
                                            .map_err(map_storage)
                                    });
                                let _ = reply.send(result);
                            }
                            KernelCommand::CompleteTaskMutation { input, reply } => {
                                let result = admission_store
                                    .lock()
                                    .map_err(|_| provider_error())
                                    .and_then(|store| {
                                        store
                                            .complete_task_control_mutation(input)
                                            .map_err(map_storage)
                                    });
                                let _ = reply.send(result);
                            }
                            KernelCommand::FailTaskMutation { input, reply } => {
                                let result = admission_store
                                    .lock()
                                    .map_err(|_| provider_error())
                                    .and_then(|store| {
                                        store
                                            .fail_task_control_mutation(input, -32602)
                                            .map_err(map_storage)
                                    });
                                let _ = reply.send(result);
                            }
                            KernelCommand::Cancel {
                                session_id: target,
                                task_id: requested_task_id,
                                control_id,
                                reply,
                            } if target == session_id => {
                                let task_id =
                                    locked_active_durable_task_id(admission_store, session_id)?;
                                if requested_task_id.is_some_and(|requested| requested != task_id)
                                    || requested_task_id.is_some() != control_id.is_some()
                                {
                                    let _ = reply.send(Err(invalid_input()));
                                    continue;
                                }
                                control_sender
                                    .send(TaskEngineControl::Cancel {
                                        task_id,
                                        control_id,
                                        session_id,
                                        turn_id,
                                        acknowledgement,
                                    })
                                    .await
                                    .map_err(|_| stopped_error())?;
                                pending.insert(acknowledgement, PendingDurableReply::Cancel(reply));
                            }
                            KernelCommand::Shutdown { reply } => {
                                durable_shutdown = true;
                                control_sender
                                    .send(TaskEngineControl::Cancel {
                                        task_id: locked_active_durable_task_id(
                                            admission_store,
                                            session_id,
                                        )?,
                                        control_id: None,
                                        session_id,
                                        turn_id,
                                        acknowledgement,
                                    })
                                    .await
                                    .map_err(|_| stopped_error())?;
                                pending
                                    .insert(acknowledgement, PendingDurableReply::Shutdown(reply));
                            }
                            other => reject_busy_command(other),
                        }
                    }
                    Next::Command(None) => receiver_open = false,
                    Next::Acknowledged(Some((acknowledgement, result))) => {
                        if let Some(reply) = pending.remove(&acknowledgement) {
                            if matches!(reply, PendingDurableReply::Approval) {
                                match result {
                                    Ok(()) => pending_permission = None,
                                    Err(error) => {
                                        if let Some(reply) = current_reply.take() {
                                            let _ = reply.send(Err(map_task_engine(error)));
                                        }
                                    }
                                }
                            } else {
                                if let PendingDurableReply::Config { task_id, .. } = &reply
                                    && let Err(error) =
                                        synchronize_session_configuration_from_projection(
                                            admission_store,
                                            sessions,
                                            session_id,
                                            *task_id,
                                        )
                                {
                                    fail_durable_reply(reply, error);
                                    continue;
                                }
                                complete_durable_reply(reply, result);
                            }
                        }
                    }
                    Next::Acknowledged(None) => {}
                    Next::Permission(Some(notice)) => {
                        let publication = format!(
                            "Approval required: {}\nApprove with /approve {} or deny with /deny {}",
                            notice.summary, notice.display_code, notice.display_code
                        );
                        deferred_permission_publications.push(publication.clone());
                        if let Some(reply) = current_reply.take() {
                            let _ = reply.send(Ok(PromptOutcome {
                                stop_reason: PromptStopReason::WaitingForApproval,
                                updates: vec![
                                    KernelUpdate::AgentMessageChunk(publication),
                                    KernelUpdate::ToolStarted {
                                        title: notice.request_id.clone(),
                                        kind: ToolKind::Execute,
                                    },
                                ],
                            }));
                        }
                        pending_permission = Some(notice);
                    }
                    Next::Permission(None) => {}
                }
            }
        };
        while let Ok((acknowledgement, result)) = acknowledgement_receiver.try_recv() {
            if let Some(reply) = pending.remove(&acknowledgement) {
                if matches!(reply, PendingDurableReply::Approval) {
                    match result {
                        Ok(()) => {}
                        Err(error) => {
                            if let Some(reply) = current_reply.take() {
                                let _ = reply.send(Err(map_task_engine(error)));
                            }
                        }
                    }
                } else {
                    if let PendingDurableReply::Config { task_id, .. } = &reply
                        && let Err(error) = synchronize_session_configuration_from_projection(
                            &self.admission_store,
                            &mut self.sessions,
                            session_id,
                            *task_id,
                        )
                    {
                        fail_durable_reply(reply, error);
                        continue;
                    }
                    complete_durable_reply(reply, result);
                }
            }
        }
        for (_, reply) in pending {
            if !matches!(reply, PendingDurableReply::Approval) {
                if let PendingDurableReply::Config { task_id, .. } = &reply
                    && let Err(error) = synchronize_session_configuration_from_projection(
                        &self.admission_store,
                        &mut self.sessions,
                        session_id,
                        *task_id,
                    )
                {
                    fail_durable_reply(reply, error);
                    continue;
                }
                fail_durable_reply(reply, session_busy());
            }
        }
        self.apply_pending_configuration(session_id)?;
        if durable_shutdown {
            self.engine_mut()
                .port_mut()
                .shutdown()
                .await
                .map_err(map_agent_port)?;
            self.shutdown_requested = true;
        }
        let task_updates = self.engine_mut().take_updates();
        for publication in deferred_permission_publications {
            self.publish(session_id, turn_id, DeliveryKind::Message, &publication)
                .await?;
        }
        for diff in task_updates.iter().filter_map(|update| match update {
            TaskEngineUpdate::DiffUpdated(diff) => Some(diff.as_str()),
            _ => None,
        }) {
            self.publish(session_id, turn_id, DeliveryKind::Diff, diff)
                .await?;
        }
        let final_text = task_updates
            .iter()
            .filter_map(|update| match update {
                TaskEngineUpdate::AgentMessageChunk(text) => Some(text.as_str()),
                _ => None,
            })
            .collect::<String>();
        if !final_text.is_empty() {
            self.publish(session_id, turn_id, DeliveryKind::Message, &final_text)
                .await?;
        }
        let updates = task_updates
            .into_iter()
            .map(KernelUpdate::from)
            .collect::<Vec<_>>();
        let outcome = match result {
            Ok(snapshot) => {
                self.sessions
                    .get_mut(&session_id)
                    .ok_or_else(unknown_session)?
                    .task_id = Some(snapshot.task_id);
                self.engine_mut()
                    .store_mut()
                    .append(session_id, Some(turn_id), Event::TurnCompleted)
                    .map_err(map_storage)?;
                Ok(PromptOutcome {
                    stop_reason: PromptStopReason::EndTurn,
                    updates,
                })
            }
            Err(error) => {
                if let Some(record) = self
                    .engine_ref()
                    .store()
                    .list_resumable_tasks()
                    .map_err(map_storage)?
                    .into_iter()
                    .find(|record| record.snapshot.session_id == session_id)
                {
                    self.sessions
                        .get_mut(&session_id)
                        .ok_or_else(unknown_session)?
                        .task_id = Some(record.snapshot.task_id);
                }
                if error.code() == TaskEngineErrorCode::Cancelled {
                    Ok(PromptOutcome {
                        stop_reason: PromptStopReason::Cancelled,
                        updates,
                    })
                } else if error.code() == TaskEngineErrorCode::Blocked {
                    Ok(PromptOutcome {
                        stop_reason: PromptStopReason::Failed,
                        updates,
                    })
                } else {
                    Err(map_task_engine(error))
                }
            }
        };
        if let Some(reply) = current_reply {
            let _ = reply.send(outcome);
        }
        Ok(())
    }

    async fn drive_turn(&mut self, session_id: SessionId) -> Result<PromptOutcome, KernelError> {
        let mut updates = Vec::new();
        loop {
            enum Next {
                Provider(Result<AgentEvent, AgentPortError>),
                Routed(AgentEvent),
                RoutedFailure,
                Command(Option<KernelCommand>),
            }
            let next = if self.routed_failures.remove(&session_id) {
                Next::RoutedFailure
            } else if let Some(event) = self.take_routed_event(session_id) {
                Next::Routed(event)
            } else {
                let (engine, receiver) = (&mut self.engine, &mut self.receiver);
                let port = engine
                    .as_mut()
                    .expect("kernel engine is actor-owned")
                    .port_mut();
                tokio::select! {
                    event = port.next_event() => Next::Provider(event),
                    command = receiver.recv() => Next::Command(command),
                }
            };
            match next {
                Next::Provider(event) => {
                    let event = match event {
                        Ok(event) => event,
                        Err(error) => {
                            self.fail_active_turn(session_id, "provider_failed");
                            return Err(map_agent_port(error));
                        }
                    };
                    match self.event_owner(&event) {
                        AgentEventOwner::Session(owner) if owner != session_id => {
                            self.route_event(owner, event).await;
                            continue;
                        }
                        AgentEventOwner::Session(_) | AgentEventOwner::Global => {}
                        AgentEventOwner::Unowned => continue,
                    }
                    match self
                        .process_provider_event(session_id, event, &mut updates)
                        .await
                    {
                        Ok(Some(outcome)) => return Ok(outcome),
                        Ok(None) => {}
                        Err(error) => {
                            self.fail_active_turn(session_id, "turn_failed");
                            return Err(error);
                        }
                    }
                }
                Next::Routed(event) => {
                    match self
                        .process_provider_event(session_id, event, &mut updates)
                        .await
                    {
                        Ok(Some(outcome)) => return Ok(outcome),
                        Ok(None) => {}
                        Err(error) => {
                            self.fail_active_turn(session_id, "turn_failed");
                            return Err(error);
                        }
                    }
                }
                Next::RoutedFailure => {
                    self.fail_active_turn(session_id, "provider_backlog_overflow");
                    return Err(provider_error());
                }
                Next::Command(Some(command)) => match command {
                    KernelCommand::Cancel {
                        session_id: target,
                        task_id,
                        control_id,
                        reply,
                    } if target == session_id => {
                        let result = if task_id.is_none() && control_id.is_none() {
                            self.cancel_session(session_id).await
                        } else {
                            Err(invalid_input())
                        };
                        let accepted = result.is_ok();
                        let _ = reply.send(result);
                        if accepted {
                            self.apply_pending_configuration(session_id)?;
                            return Ok(PromptOutcome {
                                stop_reason: PromptStopReason::Cancelled,
                                updates,
                            });
                        }
                    }
                    KernelCommand::Steer {
                        session_id: target,
                        input,
                        task_id,
                        reply,
                        ..
                    } if target == session_id => {
                        let result = if task_id.is_some() {
                            Err(invalid_input())
                        } else {
                            self.steer_session(session_id, input).await
                        };
                        let _ = reply.send(result);
                    }
                    KernelCommand::SetConfig {
                        session_id: target,
                        selection,
                        reply,
                    } if target == session_id => {
                        let prior = self
                            .sessions
                            .get(&session_id)
                            .ok_or_else(unknown_session)?
                            .public
                            .configuration()
                            .mode();
                        let result = self.set_config(session_id, selection);
                        let tightening = matches!(
                            &result,
                            Ok(ConfigOutcome::Applied(configuration))
                                if permission_strength(configuration.mode())
                                    < permission_strength(prior)
                        );
                        if tightening {
                            let (context_id, epoch_id) = {
                                let state =
                                    self.sessions.get(&session_id).ok_or_else(unknown_session)?;
                                let active = state.active.as_ref().ok_or_else(session_busy)?;
                                (
                                    state.provider_context.clone().ok_or_else(session_busy)?,
                                    active.provider_epoch_id.clone(),
                                )
                            };
                            let _ = self
                                .engine_mut()
                                .port_mut()
                                .interrupt(&context_id, &epoch_id)
                                .await;
                        }
                        let _ = reply.send(result);
                    }
                    KernelCommand::TaskStatus {
                        session_id: target,
                        task_id,
                        reply,
                    } => {
                        let result =
                            task_view(self.engine_ref().store(), &self.sessions, target, task_id);
                        let _ = reply.send(result);
                    }
                    KernelCommand::TaskList {
                        session_id: target,
                        reply,
                    } => {
                        let result = task_views(self.engine_ref().store(), &self.sessions, target);
                        let _ = reply.send(result);
                    }
                    KernelCommand::TaskContext {
                        session_id: target,
                        task_id,
                        reply,
                    } => {
                        let result = task_context_view(
                            self.engine_ref().store(),
                            &self.sessions,
                            target,
                            task_id,
                        );
                        let _ = reply.send(result);
                    }
                    KernelCommand::TaskResume { reply, .. } => {
                        let _ = reply.send(Err(session_busy()));
                    }
                    KernelCommand::ClaimTaskMutation { input, reply } => {
                        let result = self
                            .engine_ref()
                            .store()
                            .claim_task_control_mutation(input)
                            .map_err(map_storage);
                        let _ = reply.send(result);
                    }
                    KernelCommand::CompleteTaskMutation { input, reply } => {
                        let result = self
                            .engine_ref()
                            .store()
                            .complete_task_control_mutation(input)
                            .map_err(map_storage);
                        let _ = reply.send(result);
                    }
                    KernelCommand::FailTaskMutation { input, reply } => {
                        let result = self
                            .engine_ref()
                            .store()
                            .fail_task_control_mutation(input, -32602)
                            .map_err(map_storage);
                        let _ = reply.send(result);
                    }
                    KernelCommand::Shutdown { reply } => {
                        let result = self.cancel_session(session_id).await;
                        let _ = reply.send(result);
                        self.receiver.close();
                        return Ok(PromptOutcome {
                            stop_reason: PromptStopReason::Cancelled,
                            updates,
                        });
                    }
                    other => reject_busy_command(other),
                },
                Next::Command(None) => return Err(stopped_error()),
            }
        }
    }

    async fn process_provider_event(
        &mut self,
        session_id: SessionId,
        event: AgentEvent,
        updates: &mut Vec<KernelUpdate>,
    ) -> Result<Option<PromptOutcome>, KernelError> {
        if !self.active_event_matches(session_id, &event)? {
            return Ok(None);
        }
        event.validate().map_err(map_agent_port)?;
        let turn_id = self.active_turn(session_id)?.local_turn_id;
        match event {
            AgentEvent::ContextStarted { context_id } => {
                self.persist_lifecycle(session_id, None, "context_started", context_id.as_str())?;
            }
            AgentEvent::EpochStarted {
                epoch_id: provider, ..
            } => {
                self.persist_lifecycle(
                    session_id,
                    Some(turn_id),
                    "epoch_started",
                    provider.as_str(),
                )?;
            }
            AgentEvent::ItemStarted { item, .. } => {
                let item_id = item.item_id().to_owned();
                let kind = match item {
                    AgentItem::Command { .. } => Some(AgentEffectKind::Command),
                    AgentItem::FileChange { .. } => Some(AgentEffectKind::FileChange),
                    AgentItem::ContextCompaction { .. } | AgentItem::Other { .. } => None,
                };
                if let Some(kind) = kind {
                    let tool_call_id = ToolCallId::new();
                    if self
                        .active_turn_mut(session_id)?
                        .item_ids
                        .insert(item_id.clone(), (tool_call_id, kind))
                        .is_some()
                    {
                        return Err(provider_error());
                    }
                }
                self.persist_lifecycle(session_id, Some(turn_id), "item_started", &item_id)?;
            }
            AgentEvent::AssistantDelta { text, .. } => {
                SecretFilter
                    .inspect(text.as_bytes())
                    .map_err(|_| invalid_input())?;
                let active = self.active_turn_mut(session_id)?;
                if active.assistant_text.len().saturating_add(text.len()) > MAX_FINAL_MESSAGE_BYTES
                {
                    return Err(provider_error());
                }
                active.assistant_text.push_str(&text);
                self.engine_mut()
                    .store_mut()
                    .append(
                        session_id,
                        Some(turn_id),
                        Event::AssistantTextDelta { text: text.clone() },
                    )
                    .map_err(map_storage)?;
                updates.push(KernelUpdate::AgentMessageChunk(text));
            }
            AgentEvent::ItemCompleted { item, .. } => {
                let item_id = item.item_id().to_owned();
                let completion = match &item {
                    AgentItem::Command { status, .. } => Some((
                        AgentEffectKind::Command,
                        status.clone(),
                        terminal_tool_status(status)?,
                    )),
                    AgentItem::FileChange { status, .. } => Some((
                        AgentEffectKind::FileChange,
                        status.clone(),
                        terminal_tool_status(status)?,
                    )),
                    AgentItem::ContextCompaction { .. } | AgentItem::Other { .. } => None,
                };
                let Some((kind, provider_status, status)) = completion else {
                    self.persist_lifecycle(session_id, Some(turn_id), "item_completed", &item_id)?;
                    return Ok(None);
                };
                let (tool_call_id, started_kind) = self
                    .active_turn_mut(session_id)?
                    .item_ids
                    .remove(&item_id)
                    .ok_or_else(provider_error)?;
                if started_kind != kind {
                    return Err(provider_error());
                }
                self.engine_mut()
                    .store_mut()
                    .append(
                        session_id,
                        Some(turn_id),
                        Event::ToolCompleted {
                            tool_call_id,
                            output: json!({"status":provider_status}),
                        },
                    )
                    .map_err(map_storage)?;
                updates.push(KernelUpdate::ToolCompleted {
                    title: item_id,
                    status,
                });
            }
            AgentEvent::UsageUpdated { .. } => {}
            AgentEvent::DiffUpdated { diff, .. } => {
                SecretFilter
                    .inspect(diff.as_bytes())
                    .map_err(|_| invalid_input())?;
                self.engine_mut()
                    .store_mut()
                    .append(
                        session_id,
                        Some(turn_id),
                        Event::WorkspaceDiffUpdated { diff: diff.clone() },
                    )
                    .map_err(map_storage)?;
                self.publish(session_id, turn_id, DeliveryKind::Diff, &diff)
                    .await?;
                updates.push(KernelUpdate::DiffUpdated(diff));
            }
            AgentEvent::EffectRequested(approval) => {
                if self
                    .sessions
                    .get(&session_id)
                    .ok_or_else(unknown_session)?
                    .public
                    .configuration()
                    .mode()
                    .profile()
                    == PermissionProfile::FullAccess
                {
                    self.authorize_full_access_effect(session_id, turn_id, approval, updates)
                        .await?;
                    return Ok(None);
                }
                return self
                    .pause_for_approval(session_id, turn_id, approval, updates)
                    .await
                    .map(Some);
            }
            AgentEvent::CompactionStarted { item_id, .. } => {
                self.persist_lifecycle(session_id, Some(turn_id), "compaction_started", &item_id)?;
            }
            AgentEvent::CompactionCompleted { item_id, .. } => {
                self.persist_lifecycle(
                    session_id,
                    Some(turn_id),
                    "compaction_completed",
                    &item_id,
                )?;
            }
            AgentEvent::EpochCompleted { .. } => {
                let final_text = self.active_turn(session_id)?.assistant_text.clone();
                SecretFilter
                    .inspect(final_text.as_bytes())
                    .map_err(|_| provider_error())?;
                if !final_text.is_empty()
                    && let Err(error) = self
                        .publish(session_id, turn_id, DeliveryKind::Message, &final_text)
                        .await
                {
                    self.fail_active_turn(session_id, "publication_failed");
                    return Err(error);
                }
                self.engine_mut()
                    .store_mut()
                    .append(session_id, Some(turn_id), Event::TurnCompleted)
                    .map_err(map_storage)?;
                self.sessions
                    .get_mut(&session_id)
                    .ok_or_else(unknown_session)?
                    .active = None;
                self.apply_pending_configuration(session_id)?;
                return Ok(Some(PromptOutcome {
                    stop_reason: PromptStopReason::EndTurn,
                    updates: std::mem::take(updates),
                }));
            }
            AgentEvent::ProviderFailed { .. } => {
                self.engine_mut()
                    .store_mut()
                    .append(
                        session_id,
                        Some(turn_id),
                        Event::TurnInterrupted {
                            reason: "provider_failed".to_owned(),
                        },
                    )
                    .map_err(map_storage)?;
                self.sessions
                    .get_mut(&session_id)
                    .ok_or_else(unknown_session)?
                    .active = None;
                return Ok(Some(PromptOutcome {
                    stop_reason: PromptStopReason::Failed,
                    updates: std::mem::take(updates),
                }));
            }
        }
        Ok(None)
    }

    async fn authorize_full_access_effect(
        &mut self,
        session_id: SessionId,
        turn_id: TurnId,
        approval: AgentEffectRequest,
        updates: &mut Vec<KernelUpdate>,
    ) -> Result<(), KernelError> {
        self.deny_unsupported_effect(&approval).await?;
        let tool_call_id = {
            let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
            let active = state.active.as_ref().ok_or_else(session_busy)?;
            (turn_id == active.local_turn_id)
                .then(|| {
                    active
                        .item_ids
                        .get(&approval.item_id)
                        .copied()
                        .filter(|(_, kind)| *kind == approval.kind)
                        .map(|(tool_call_id, _)| tool_call_id)
                })
                .flatten()
        };
        let Some(tool_call_id) = tool_call_id else {
            self.engine_mut()
                .port_mut()
                .resolve_effect(&approval.request_id, EffectDecision::Deny)
                .await
                .map_err(map_agent_port)?;
            return Err(provider_error());
        };
        let (tool_name, tool_kind) = effect_metadata(approval.kind)?;
        let summary = approval.summary.clone();
        let title = effect_title(&approval);
        if SecretFilter.inspect(summary.as_bytes()).is_err() {
            self.engine_mut()
                .port_mut()
                .resolve_effect(&approval.request_id, EffectDecision::Deny)
                .await
                .map_err(map_agent_port)?;
            return Err(provider_error());
        }
        self.engine_mut()
            .store_mut()
            .append(
                session_id,
                Some(turn_id),
                Event::ToolProposed {
                    tool_call_id,
                    tool_name: tool_name.to_owned(),
                    arguments: json!({"summary":summary}),
                },
            )
            .map_err(map_storage)?;
        self.engine_mut()
            .store_mut()
            .append(
                session_id,
                Some(turn_id),
                Event::ToolDispatchAuthorized {
                    tool_call_id,
                    request_digest: approval.request_digest.to_string(),
                    automatic: true,
                },
            )
            .map_err(map_storage)?;
        self.engine_mut()
            .port_mut()
            .resolve_effect(&approval.request_id, EffectDecision::Allow)
            .await
            .map_err(map_agent_port)?;
        updates.push(KernelUpdate::ToolStarted {
            title,
            kind: tool_kind,
        });
        Ok(())
    }

    async fn pause_for_approval(
        &mut self,
        session_id: SessionId,
        turn_id: TurnId,
        approval: AgentEffectRequest,
        updates: &mut Vec<KernelUpdate>,
    ) -> Result<PromptOutcome, KernelError> {
        self.deny_unsupported_effect(&approval).await?;
        let (actor_id, external_session_id, frontend) = {
            let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
            (
                state.actor_id.clone(),
                state.public.external_session_id.clone(),
                state.frontend,
            )
        };
        let (tool_name, tool_kind) = effect_metadata(approval.kind)?;
        let title = effect_title(&approval);
        let summary = approval.summary.clone();
        if SecretFilter.inspect(summary.as_bytes()).is_err() {
            self.engine_mut()
                .port_mut()
                .resolve_effect(&approval.request_id, EffectDecision::Deny)
                .await
                .map_err(map_agent_port)?;
            self.engine_mut()
                .store_mut()
                .append(
                    session_id,
                    Some(turn_id),
                    Event::TurnInterrupted {
                        reason: "approval_secret_rejected".to_owned(),
                    },
                )
                .map_err(map_storage)?;
            self.sessions
                .get_mut(&session_id)
                .ok_or_else(unknown_session)?
                .active = None;
            return Ok(PromptOutcome {
                stop_reason: PromptStopReason::Failed,
                updates: std::mem::take(updates),
            });
        }
        let tool_call_id = self
            .active_turn_mut(session_id)?
            .item_ids
            .get(&approval.item_id)
            .copied()
            .filter(|(_, kind)| *kind == approval.kind)
            .map(|(tool_call_id, _)| tool_call_id);
        let Some(tool_call_id) = tool_call_id else {
            self.engine_mut()
                .port_mut()
                .resolve_effect(&approval.request_id, EffectDecision::Deny)
                .await
                .map_err(map_agent_port)?;
            return Err(provider_error());
        };
        let approval_id = ApprovalId::new();
        let now = Utc::now();
        let binding = BoundApprovalBinding::new(
            session_id,
            turn_id,
            tool_call_id,
            actor_id.clone(),
            approval.request_digest,
            now,
            now + APPROVAL_LIFETIME,
        )
        .map_err(map_storage)?;
        self.engine_mut()
            .store_mut()
            .append(
                session_id,
                Some(turn_id),
                Event::ToolProposed {
                    tool_call_id,
                    tool_name: tool_name.to_owned(),
                    arguments: json!({"summary":summary}),
                },
            )
            .map_err(map_storage)?;
        self.engine_ref()
            .store()
            .create_bound_approval(approval_id, binding.clone(), summary.clone())
            .map_err(map_storage)?;
        self.engine_mut()
            .store_mut()
            .append(
                session_id,
                Some(turn_id),
                Event::ApprovalRequested {
                    approval_id,
                    tool_call_id,
                    summary: summary.clone(),
                },
            )
            .map_err(map_storage)?;
        let display_code = self.create_approval_code(
            &external_session_id,
            approval_id,
            &approval,
            &actor_id,
            now,
        )?;
        let publication = format!(
            "Approval required: {summary}\nApprove with /approve {display_code} or deny with /deny {display_code}"
        );
        self.active_turn_mut(session_id)?.pending_approval = Some(PendingApproval {
            request: approval,
            approval_id,
            binding,
        });
        if let Err(error) = self
            .publish(session_id, turn_id, DeliveryKind::Message, &publication)
            .await
        {
            let request = self
                .active_turn(session_id)?
                .pending_approval
                .as_ref()
                .expect("approval was stored")
                .request
                .clone();
            let _ = self
                .engine_mut()
                .port_mut()
                .resolve_effect(&request.request_id, EffectDecision::Deny)
                .await;
            self.fail_active_turn(session_id, "approval_publication_failed");
            return Err(error);
        }
        if frontend != Frontend::Buzz {
            updates.push(KernelUpdate::AgentMessageChunk(publication));
        }
        updates.push(KernelUpdate::ToolStarted {
            title,
            kind: tool_kind,
        });
        Ok(PromptOutcome {
            stop_reason: PromptStopReason::WaitingForApproval,
            updates: std::mem::take(updates),
        })
    }

    async fn resume_approval(
        &mut self,
        session_id: SessionId,
        prompt: Prompt,
    ) -> Result<PromptOutcome, KernelError> {
        let command = prompt
            .leading_slash_command()
            .ok_or_else(|| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        let (decision, code) = if let Some(code) = command.strip_prefix("/approve ") {
            (EffectDecision::Allow, code)
        } else if let Some(code) = command.strip_prefix("/deny ") {
            (EffectDecision::Deny, code)
        } else {
            return Err(KernelError::from_code(KernelErrorCode::ApprovalUnavailable));
        };
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        let active = state.active.as_ref().ok_or_else(session_busy)?;
        let pending = active
            .pending_approval
            .as_ref()
            .ok_or_else(|| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        let external_session_id = state.public.external_session_id.clone();
        let actor_id = state.actor_id.clone();
        let approval_id = pending.approval_id;
        let binding = pending.binding.clone();
        let approval = pending.request.clone();
        let turn_id = active.local_turn_id;
        let provider_request_id = ProviderRequestId::try_from(pending.request.request_id.as_str())
            .map_err(|_| provider_error())?;
        let durable = self
            .engine_ref()
            .store()
            .get_frontend_session(external_session_id.as_str())
            .map_err(map_storage)?
            .ok_or_else(|| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        if durable.session_id != session_id
            || durable.cwd != state.cwd
            || durable
                .provider_thread_id
                .as_ref()
                .map(ProviderThreadId::as_str)
                != state.provider_context.as_ref().map(AgentContextId::as_str)
        {
            return Err(KernelError::from_code(KernelErrorCode::ApprovalUnavailable));
        }
        let status = match decision {
            EffectDecision::Allow => ApprovalStatus::Allowed,
            EffectDecision::Deny => ApprovalStatus::Denied,
        };
        let now = Utc::now();
        self.engine_mut()
            .store_mut()
            .consume_remote_bound_approval(
                RemoteCodeClaim {
                    display_code: code,
                    kind: RemoteCodeKind::Approval,
                    external_session_id,
                    approval_id: Some(approval_id),
                    provider_request_id: Some(provider_request_id),
                    request_digest: approval.request_digest,
                    actor_id,
                    now,
                },
                &binding,
                status,
            )
            .map_err(|_| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        let tool_title = effect_title(&approval);
        self.engine_mut()
            .port_mut()
            .resolve_effect(&approval.request_id, decision)
            .await
            .map_err(map_agent_port)?;
        self.engine_mut()
            .store_mut()
            .append(
                session_id,
                Some(turn_id),
                Event::UserInput {
                    text: match decision {
                        EffectDecision::Allow => "/approve <redacted>",
                        EffectDecision::Deny => "/deny <redacted>",
                    }
                    .to_owned(),
                },
            )
            .map_err(map_storage)?;
        self.active_turn_mut(session_id)?.pending_approval = None;
        let mut outcome = self.drive_turn(session_id).await?;
        outcome.updates.insert(
            0,
            KernelUpdate::ToolCompleted {
                title: tool_title,
                status: if decision == EffectDecision::Allow {
                    ToolStatus::Completed
                } else {
                    ToolStatus::Failed
                },
            },
        );
        Ok(outcome)
    }

    fn set_config(
        &mut self,
        session_id: SessionId,
        selection: ConfigSelection,
    ) -> Result<ConfigOutcome, KernelError> {
        let state = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(unknown_session)?;
        if let ConfigSelection::Mode {
            mode: PermissionMode::BypassPermissions,
            remote: true,
        } = selection
        {
            if state.active.is_some() {
                return Err(session_busy());
            }
            let external_session_id = state.public.external_session_id.clone();
            let actor_id = state.actor_id.clone();
            let cwd = state.cwd.clone();
            let digest = bypass_digest(&external_session_id, &actor_id, &cwd);
            let now = Utc::now();
            let _ = state;
            let display_code = create_remote_code(
                self.engine_ref().store(),
                RemoteCodeKind::BypassConfirmation,
                &external_session_id,
                None,
                None,
                digest,
                &actor_id,
                now,
            )?;
            self.sessions
                .get_mut(&session_id)
                .ok_or_else(unknown_session)?
                .pending_bypass = Some(PendingBypass {
                request_digest: digest,
            });
            return Ok(ConfigOutcome::PendingBypass { display_code });
        }
        if let ConfigSelection::Mode { mode, remote: true } = selection
            && mode.profile() == PermissionProfile::FullAccess
            && !(state.frontend == Frontend::Buzz && state.buzz_context.is_some())
        {
            return Err(KernelError::from_code(KernelErrorCode::ApprovalUnavailable));
        }
        let base = state
            .pending_configuration
            .clone()
            .unwrap_or_else(|| state.public.configuration.clone());
        let configuration = match selection {
            ConfigSelection::Model(model) => {
                apply_change(base, |configuration| configuration.set_model(model))?
            }
            ConfigSelection::Effort(effort) => {
                apply_change(base, |configuration| configuration.set_effort(effort))?
            }
            ConfigSelection::Mode { mode, remote } => apply_change(base, |configuration| {
                configuration.set_mode(
                    mode,
                    if remote {
                        ModeActivation::RemoteConfirmed
                    } else {
                        ModeActivation::LocalExplicit
                    },
                )
            })?,
        };
        if state.active.is_some() {
            state.pending_configuration = Some(configuration.clone());
            return Ok(ConfigOutcome::Applied(configuration));
        }
        state.public = KernelSession::new(
            state.public.id(),
            state.public.external_session_id.clone(),
            configuration.clone(),
        );
        self.persist_configuration(session_id)?;
        Ok(ConfigOutcome::Applied(configuration))
    }

    fn apply_pending_configuration(&mut self, session_id: SessionId) -> Result<(), KernelError> {
        let state = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(unknown_session)?;
        let Some(configuration) = state.pending_configuration.take() else {
            return Ok(());
        };
        state.public = KernelSession::new(
            state.public.id(),
            state.public.external_session_id.clone(),
            configuration,
        );
        self.persist_configuration(session_id)
    }

    async fn attach_buzz_context(
        &mut self,
        session_id: SessionId,
        context: BuzzContext,
    ) -> Result<(), KernelError> {
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        if state.frontend != Frontend::Buzz
            || state
                .active
                .as_ref()
                .is_some_and(|active| active.pending_approval.is_none())
        {
            return Err(session_busy());
        }
        let actor = ActorId::parse(context.actor_hex()).map_err(|_| invalid_input())?;
        let channel = crate::storage::ChannelId::try_from(context.channel_id().to_string())
            .map_err(map_storage)?;
        if let Some(existing) = state.buzz_context.as_ref()
            && (existing.channel_id() != context.channel_id()
                || existing.actor_hex() != context.actor_hex())
        {
            return Err(KernelError::from_code(KernelErrorCode::ApprovalUnavailable));
        }
        let cwd = state.cwd.clone();
        let external_session_id = state.public.external_session_id.clone();
        let model = state.public.configuration().model().clone();
        let needs_provider_context = state.provider_context.is_none();
        let first_admission = state.buzz_context.is_none();
        self.engine_ref()
            .store()
            .admit_trusted_frontend_message(
                Frontend::Buzz,
                &actor,
                &channel,
                &cwd,
                context.reply_to(),
                Utc::now(),
            )
            .map_err(|_| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        self.engine_ref()
            .store()
            .claim_frontend_channel(&external_session_id, &channel, Utc::now())
            .map_err(|_| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        let provider_context = if needs_provider_context {
            Some(
                self.engine_mut()
                    .port_mut()
                    .start_context(StartAgentContext {
                        cwd,
                        model,
                        permission_mode: PermissionMode::FullAccess,
                    })
                    .await
                    .map_err(map_agent_port)?,
            )
        } else {
            None
        };
        if let Some(provider_context) = provider_context.as_ref() {
            let provider_thread_id = ProviderThreadId::try_from(provider_context.as_str())
                .map_err(|_| provider_error())?;
            self.engine_ref()
                .store()
                .configure_frontend_session(
                    &external_session_id,
                    Some(&provider_thread_id),
                    PermissionMode::FullAccess,
                    Utc::now(),
                )
                .map_err(map_storage)?;
        }
        let state = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(unknown_session)?;
        let mut configuration = state.public.configuration().clone();
        if first_admission
            && !matches!(
                configuration.set_mode(PermissionMode::FullAccess, ModeActivation::LocalExplicit),
                ConfigChange::Applied
            )
        {
            return Err(invalid_input());
        }
        state.public = KernelSession::new(
            state.public.id(),
            state.public.external_session_id.clone(),
            configuration,
        );
        if let Some(provider_context) = provider_context {
            state.provider_context = Some(provider_context);
        }
        state.actor_id = actor;
        state.buzz_context = Some(context);
        Ok(())
    }

    fn confirm_bypass(
        &mut self,
        session_id: SessionId,
        command: &str,
    ) -> Result<SessionConfiguration, KernelError> {
        let code = command
            .strip_prefix("/confirm-bypass ")
            .ok_or_else(invalid_input)?;
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        let pending = state
            .pending_bypass
            .as_ref()
            .ok_or_else(|| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        let claim = RemoteCodeClaim {
            display_code: code,
            kind: RemoteCodeKind::BypassConfirmation,
            external_session_id: state.public.external_session_id.clone(),
            approval_id: None,
            provider_request_id: None,
            request_digest: pending.request_digest,
            actor_id: state.actor_id.clone(),
            now: Utc::now(),
        };
        self.engine_mut()
            .store_mut()
            .consume_remote_code(claim)
            .map_err(|_| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        let state = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(unknown_session)?;
        let mut configuration = state.public.configuration.clone();
        if configuration.set_mode(
            PermissionMode::BypassPermissions,
            ModeActivation::RemoteConfirmed,
        ) != ConfigChange::Applied
        {
            return Err(invalid_input());
        }
        state.public = KernelSession::new(
            state.public.id(),
            state.public.external_session_id.clone(),
            configuration.clone(),
        );
        state.pending_bypass = None;
        self.persist_configuration(session_id)?;
        Ok(configuration)
    }

    fn persist_configuration(&mut self, session_id: SessionId) -> Result<(), KernelError> {
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        let external_session_id = state.public.external_session_id.clone();
        let provider_thread_id = state
            .provider_context
            .as_ref()
            .map(|context| ProviderThreadId::try_from(context.as_str()))
            .transpose()
            .map_err(map_storage)?;
        let permission_mode = state.public.configuration.mode();
        let settings = DelegateSettings::new(
            Some(state.public.configuration().model().clone()),
            Some(state.public.configuration().effort()),
        );
        self.engine_ref()
            .store()
            .configure_frontend_session(
                &external_session_id,
                provider_thread_id.as_ref(),
                permission_mode,
                Utc::now(),
            )
            .map_err(map_storage)?;
        self.engine_ref()
            .store()
            .set_session_delegate_settings(session_id, settings, Utc::now())
            .map_err(map_storage)?;
        self.engine_mut()
            .store_mut()
            .append(
                session_id,
                None,
                Event::FrontendPermissionChanged {
                    external_session_id: external_session_id.as_str().to_owned(),
                    permission_mode,
                },
            )
            .map_err(map_storage)?;
        Ok(())
    }

    async fn cancel_session(&mut self, session_id: SessionId) -> Result<(), KernelError> {
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        let active = state.active.as_ref().ok_or_else(session_busy)?;
        let context_id = state.provider_context.clone().ok_or_else(session_busy)?;
        let epoch_id = active.provider_epoch_id.clone();
        let turn_id = active.local_turn_id;
        self.engine_mut()
            .port_mut()
            .interrupt(&context_id, &epoch_id)
            .await
            .map_err(map_agent_port)?;
        self.engine_mut()
            .store_mut()
            .append(
                session_id,
                Some(turn_id),
                Event::TurnInterrupted {
                    reason: "cancelled".to_owned(),
                },
            )
            .map_err(map_storage)?;
        self.sessions
            .get_mut(&session_id)
            .ok_or_else(unknown_session)?
            .active = None;
        Ok(())
    }

    async fn resume_task(
        &mut self,
        session_id: SessionId,
        task_id: TaskId,
        control_id: &str,
    ) -> Result<TaskView, KernelError> {
        let current = task_view(
            self.engine_ref().store(),
            &self.sessions,
            session_id,
            task_id,
        )?;
        let marker_exists = self
            .engine_ref()
            .store()
            .task_has_control_marker(
                task_id,
                control_id,
                crate::runtime::task::TaskControlKind::Resume,
            )
            .map_err(map_storage)?;
        if current.status == crate::runtime::task::TaskStatus::Completed && marker_exists {
            return Ok(current);
        }
        if current.status.is_terminal() {
            return Err(invalid_input());
        }
        if self
            .sessions
            .get(&session_id)
            .ok_or_else(unknown_session)?
            .active
            .is_some()
        {
            return Err(session_busy());
        }
        if !marker_exists {
            self.engine_mut()
                .mark_control_requested(
                    task_id,
                    control_id,
                    crate::runtime::task::TaskControlKind::Resume,
                )
                .map_err(map_task_engine)?;
        }
        let snapshot = self
            .engine_mut()
            .run(task_id)
            .await
            .map_err(map_task_engine)?;
        self.sessions
            .get_mut(&session_id)
            .ok_or_else(unknown_session)?
            .task_id = Some(task_id);
        Ok(TaskView::from(&snapshot))
    }

    async fn steer_session(
        &mut self,
        session_id: SessionId,
        input: String,
    ) -> Result<(), KernelError> {
        if input.trim().is_empty() || input.len() > MAX_FINAL_MESSAGE_BYTES {
            return Err(invalid_input());
        }
        SecretFilter
            .inspect(input.as_bytes())
            .map_err(|_| invalid_input())?;
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        let active = state.active.as_ref().ok_or_else(session_busy)?;
        if active.pending_approval.is_some() {
            return Err(session_busy());
        }
        let context_id = state.provider_context.clone().ok_or_else(session_busy)?;
        let epoch_id = active.provider_epoch_id.clone();
        let turn_id = active.local_turn_id;
        self.engine_mut()
            .store_mut()
            .append(
                session_id,
                Some(turn_id),
                Event::UserInput {
                    text: input.clone(),
                },
            )
            .map_err(map_storage)?;
        self.engine_mut()
            .port_mut()
            .steer(&context_id, &epoch_id, input)
            .await
            .map_err(map_agent_port)
    }

    async fn publish(
        &mut self,
        session_id: SessionId,
        turn_id: TurnId,
        kind: DeliveryKind,
        content: &str,
    ) -> Result<(), KernelError> {
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        let Some(context) = state.buzz_context.clone() else {
            return Ok(());
        };
        if self.publisher.is_none() {
            return Ok(());
        }
        let external_session_id = state.public.external_session_id.clone();
        SecretFilter
            .inspect(content.as_bytes())
            .map_err(|_| invalid_input())?;
        let digest = delivery_digest(session_id, turn_id, kind, content, &context);
        self.engine_ref()
            .store()
            .create_delivery(NewDelivery {
                action_digest: digest,
                external_session_id,
                kind,
                created_at: Utc::now(),
            })
            .map_err(map_storage)?;
        let publisher = self.publisher.as_mut().expect("publisher checked above");
        let result = match kind {
            DeliveryKind::Message => publisher.send_message(&context, content).await,
            DeliveryKind::Diff => publisher.send_diff(&context, content).await,
        };
        let status = match result {
            Ok(()) => DeliveryStatus::Delivered,
            Err(PublicationFailure::Failed) => DeliveryStatus::Failed,
            Err(PublicationFailure::Uncertain) => DeliveryStatus::Uncertain,
        };
        self.engine_ref()
            .store()
            .transition_delivery(digest, status, Utc::now())
            .map_err(map_storage)?;
        self.engine_mut()
            .store_mut()
            .append(
                session_id,
                Some(turn_id),
                Event::FrontendDeliveryTransitioned {
                    action_digest: digest.to_string(),
                    status: match status {
                        DeliveryStatus::Pending => unreachable!("terminal transition only"),
                        DeliveryStatus::Delivered => {
                            crate::events::FrontendDeliveryStatus::Delivered
                        }
                        DeliveryStatus::Failed => crate::events::FrontendDeliveryStatus::Failed,
                        DeliveryStatus::Uncertain => {
                            crate::events::FrontendDeliveryStatus::Uncertain
                        }
                    },
                },
            )
            .map_err(map_storage)?;
        match result {
            Ok(()) => Ok(()),
            Err(PublicationFailure::Failed) => {
                Err(KernelError::from_code(KernelErrorCode::PublicationFailed))
            }
            Err(PublicationFailure::Uncertain) => {
                Err(KernelError::from_code(KernelErrorCode::DeliveryUncertain))
            }
        }
    }

    fn create_approval_code(
        &self,
        external_session_id: &ExternalSessionId,
        approval_id: ApprovalId,
        approval: &AgentEffectRequest,
        actor_id: &ActorId,
        now: chrono::DateTime<Utc>,
    ) -> Result<String, KernelError> {
        let provider_request_id =
            ProviderRequestId::try_from(approval.request_id.as_str()).map_err(map_storage)?;
        create_remote_code(
            self.engine_ref().store(),
            RemoteCodeKind::Approval,
            external_session_id,
            Some(approval_id),
            Some(provider_request_id),
            approval.request_digest,
            actor_id,
            now,
        )
    }

    fn active_turn(&self, session_id: SessionId) -> Result<&ActiveTurn, KernelError> {
        self.sessions
            .get(&session_id)
            .and_then(|state| state.active.as_ref())
            .ok_or_else(session_busy)
    }

    fn active_turn_mut(&mut self, session_id: SessionId) -> Result<&mut ActiveTurn, KernelError> {
        self.sessions
            .get_mut(&session_id)
            .and_then(|state| state.active.as_mut())
            .ok_or_else(session_busy)
    }

    fn active_event_matches(
        &self,
        session_id: SessionId,
        event: &AgentEvent,
    ) -> Result<bool, KernelError> {
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        let active = state.active.as_ref().ok_or_else(session_busy)?;
        let context_matches =
            |context_id: &AgentContextId| state.provider_context.as_ref() == Some(context_id);
        let epoch_matches = |epoch_id: &AgentEpochId| epoch_id == &active.provider_epoch_id;
        let valid = match event {
            AgentEvent::ContextStarted { context_id } => context_matches(context_id),
            AgentEvent::EpochStarted {
                context_id,
                epoch_id,
            } => context_matches(context_id) && epoch_matches(epoch_id),
            AgentEvent::ItemStarted {
                context_id,
                epoch_id,
                ..
            }
            | AgentEvent::AssistantDelta {
                context_id,
                epoch_id,
                ..
            }
            | AgentEvent::DiffUpdated {
                context_id,
                epoch_id,
                ..
            }
            | AgentEvent::UsageUpdated {
                context_id,
                epoch_id,
                ..
            }
            | AgentEvent::ItemCompleted {
                context_id,
                epoch_id,
                ..
            }
            | AgentEvent::EpochCompleted {
                context_id,
                epoch_id,
                ..
            } => context_matches(context_id) && epoch_matches(epoch_id),
            AgentEvent::EffectRequested(request) => {
                context_matches(&request.context_id) && epoch_matches(&request.epoch_id)
            }
            AgentEvent::CompactionStarted { context_id, .. }
            | AgentEvent::CompactionCompleted { context_id, .. } => context_matches(context_id),
            AgentEvent::ProviderFailed {
                context_id,
                epoch_id,
            } => match (context_id, epoch_id) {
                (None, None) => true,
                (Some(context_id), Some(epoch_id)) => {
                    context_matches(context_id) && epoch_matches(epoch_id)
                }
                _ => false,
            },
        };
        Ok(valid)
    }

    fn event_owner(&self, event: &AgentEvent) -> AgentEventOwner {
        let context_id = match event {
            AgentEvent::ContextStarted { context_id }
            | AgentEvent::EpochStarted { context_id, .. }
            | AgentEvent::ItemStarted { context_id, .. }
            | AgentEvent::AssistantDelta { context_id, .. }
            | AgentEvent::DiffUpdated { context_id, .. }
            | AgentEvent::UsageUpdated { context_id, .. }
            | AgentEvent::ItemCompleted { context_id, .. }
            | AgentEvent::CompactionStarted { context_id, .. }
            | AgentEvent::CompactionCompleted { context_id, .. }
            | AgentEvent::EpochCompleted { context_id, .. } => Some(context_id),
            AgentEvent::EffectRequested(request) => Some(&request.context_id),
            AgentEvent::ProviderFailed {
                context_id: Some(context_id),
                ..
            } => Some(context_id),
            AgentEvent::ProviderFailed {
                context_id: None,
                epoch_id: None,
            } => return AgentEventOwner::Global,
            AgentEvent::ProviderFailed {
                context_id: None, ..
            } => return AgentEventOwner::Unowned,
        };
        context_id
            .and_then(|context_id| self.session_for_context(context_id))
            .map_or(AgentEventOwner::Unowned, AgentEventOwner::Session)
    }

    fn session_for_context(&self, context_id: &AgentContextId) -> Option<SessionId> {
        let mut matches = self
            .sessions
            .iter()
            .filter(|(_, state)| state.provider_context.as_ref() == Some(context_id))
            .map(|(session_id, _)| *session_id);
        let owner = matches.next()?;
        matches.next().is_none().then_some(owner)
    }

    async fn route_event(&mut self, session_id: SessionId, event: AgentEvent) {
        if self.routed_failures.contains(&session_id) {
            return;
        }
        let queue_len = self.routed_events.get(&session_id).map_or(0, VecDeque::len);
        if self.routed_event_count >= ROUTED_EVENT_CAPACITY
            || queue_len >= ROUTED_EVENTS_PER_SESSION
        {
            if let Some(discarded) = self.routed_events.remove(&session_id) {
                self.routed_event_count = self.routed_event_count.saturating_sub(discarded.len());
            }
            self.routed_failures.insert(session_id);
            let cleanup = self.sessions.get(&session_id).and_then(|state| {
                state.active.as_ref().map(|active| {
                    (
                        state.provider_context.clone(),
                        active.provider_epoch_id.clone(),
                        active
                            .pending_approval
                            .as_ref()
                            .map(|pending| pending.request.request_id.clone()),
                    )
                })
            });
            self.fail_active_turn(session_id, "provider_backlog_overflow");
            if let Some((context_id, epoch_id, pending_request_id)) = cleanup {
                if let Some(request_id) = pending_request_id {
                    let _ = self
                        .engine_mut()
                        .port_mut()
                        .resolve_effect(&request_id, EffectDecision::Deny)
                        .await;
                }
                if let Some(context_id) = context_id {
                    let _ = self
                        .engine_mut()
                        .port_mut()
                        .interrupt(&context_id, &epoch_id)
                        .await;
                }
            }
            return;
        }
        let queue = self.routed_events.entry(session_id).or_default();
        queue.push_back(event);
        self.routed_event_count += 1;
    }

    fn take_routed_event(&mut self, session_id: SessionId) -> Option<AgentEvent> {
        let queue = self.routed_events.get_mut(&session_id)?;
        let event = queue.pop_front()?;
        self.routed_event_count = self.routed_event_count.saturating_sub(1);
        if queue.is_empty() {
            self.routed_events.remove(&session_id);
        }
        Some(event)
    }

    async fn deny_unsupported_effect(
        &mut self,
        request: &AgentEffectRequest,
    ) -> Result<(), KernelError> {
        if matches!(
            request.kind,
            AgentEffectKind::Network | AgentEffectKind::External
        ) {
            self.engine_mut()
                .port_mut()
                .resolve_effect(&request.request_id, EffectDecision::Deny)
                .await
                .map_err(map_agent_port)?;
            return Err(provider_error());
        }
        Ok(())
    }

    fn persist_lifecycle(
        &mut self,
        session_id: SessionId,
        turn_id: Option<TurnId>,
        phase: &str,
        provider_id: &str,
    ) -> Result<(), KernelError> {
        self.engine_mut()
            .store_mut()
            .append(
                session_id,
                turn_id,
                Event::ProviderLifecycle {
                    phase: phase.to_owned(),
                    provider_id: Some(provider_id.to_owned()),
                },
            )
            .map_err(map_storage)?;
        Ok(())
    }

    fn fail_active_turn(&mut self, session_id: SessionId, reason: &str) {
        let turn_id = self
            .sessions
            .get(&session_id)
            .and_then(|state| state.active.as_ref())
            .map(|active| active.local_turn_id);
        if let Some(turn_id) = turn_id {
            let _ = self.engine_mut().store_mut().append(
                session_id,
                Some(turn_id),
                Event::TurnInterrupted {
                    reason: reason.to_owned(),
                },
            );
        }
        if let Some(state) = self.sessions.get_mut(&session_id) {
            state.active = None;
        }
    }
}

fn reject_busy_command(command: KernelCommand) {
    match command {
        KernelCommand::NewSession { reply, .. } => {
            let _ = reply.send(Err(session_busy()));
        }
        KernelCommand::Prompt { reply, .. } => {
            let _ = reply.send(Err(session_busy()));
        }
        KernelCommand::SetConfig { reply, .. } => {
            let _ = reply.send(Err(session_busy()));
        }
        KernelCommand::AttachBuzzContext { reply, .. } => {
            let _ = reply.send(Err(session_busy()));
        }
        KernelCommand::InstallPublisher { reply, .. } => {
            let _ = reply.send(Err(session_busy()));
        }
        KernelCommand::Cancel { reply, .. } | KernelCommand::Steer { reply, .. } => {
            let _ = reply.send(Err(session_busy()));
        }
        KernelCommand::TaskStatus { reply, .. } | KernelCommand::TaskResume { reply, .. } => {
            let _ = reply.send(Err(session_busy()));
        }
        KernelCommand::TaskList { reply, .. } => {
            let _ = reply.send(Err(session_busy()));
        }
        KernelCommand::TaskContext { reply, .. } => {
            let _ = reply.send(Err(session_busy()));
        }
        KernelCommand::ClaimTaskMutation { reply, .. } => {
            let _ = reply.send(Err(session_busy()));
        }
        KernelCommand::CompleteTaskMutation { reply, .. } => {
            let _ = reply.send(Err(session_busy()));
        }
        KernelCommand::FailTaskMutation { reply, .. } => {
            let _ = reply.send(Err(session_busy()));
        }
        KernelCommand::Shutdown { reply } => {
            let _ = reply.send(Err(session_busy()));
        }
    }
}

fn catalog_from_provider(models: &[AgentModel]) -> Result<ModelCatalog, KernelError> {
    let descriptors = models
        .iter()
        .map(|model| {
            ModelDescriptor::new(
                model.id.clone(),
                model.display_name.clone(),
                model.supported_efforts.clone(),
            )
            .map_err(|_| provider_error())
        })
        .collect::<Result<Vec<_>, _>>()?;
    ModelCatalog::new(descriptors).map_err(|_| provider_error())
}

fn apply_change(
    mut configuration: SessionConfiguration,
    change: impl FnOnce(&mut SessionConfiguration) -> ConfigChange,
) -> Result<SessionConfiguration, KernelError> {
    if change(&mut configuration) != ConfigChange::Applied {
        return Err(invalid_input());
    }
    Ok(configuration)
}

#[allow(clippy::too_many_arguments)]
fn create_remote_code(
    store: &crate::storage::Store,
    kind: RemoteCodeKind,
    external_session_id: &ExternalSessionId,
    approval_id: Option<ApprovalId>,
    provider_request_id: Option<ProviderRequestId>,
    request_digest: Sha256Digest,
    actor_id: &ActorId,
    now: chrono::DateTime<Utc>,
) -> Result<String, KernelError> {
    for _ in 0..16 {
        let display_code = Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(10)
            .collect::<String>();
        if store
            .create_remote_code(NewRemoteCode {
                display_code: &display_code,
                kind,
                external_session_id: external_session_id.clone(),
                approval_id,
                provider_request_id: provider_request_id.clone(),
                request_digest,
                actor_id: actor_id.clone(),
                created_at: now,
                expires_at: now + APPROVAL_LIFETIME,
            })
            .is_ok()
        {
            return Ok(display_code);
        }
    }
    Err(KernelError::from_code(KernelErrorCode::StorageFailed))
}

fn bypass_digest(
    session: &ExternalSessionId,
    actor: &ActorId,
    cwd: &std::path::Path,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"carl.bypass-confirmation.v1\0");
    hasher.update(session.as_str());
    hasher.update([0]);
    hasher.update(actor.as_str());
    hasher.update([0]);
    hasher.update(cwd.as_os_str().as_encoded_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn delivery_digest(
    session_id: SessionId,
    turn_id: TurnId,
    kind: DeliveryKind,
    content: &str,
    context: &BuzzContext,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"carl.frontend-delivery.v1\0");
    hasher.update(session_id.to_string());
    hasher.update(turn_id.to_string());
    hasher.update(match kind {
        DeliveryKind::Message => b"message".as_slice(),
        DeliveryKind::Diff => b"diff".as_slice(),
    });
    hasher.update(context.reply_to());
    hasher.update(content);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn map_publication_error(error: crate::acp::BuzzError) -> PublicationFailure {
    match error.code() {
        BuzzErrorCode::TimedOut => PublicationFailure::Uncertain,
        BuzzErrorCode::InvalidContext
        | BuzzErrorCode::InvalidConfiguration
        | BuzzErrorCode::UnsupportedVersion
        | BuzzErrorCode::PublicationFailed
        | BuzzErrorCode::Cancelled => PublicationFailure::Failed,
    }
}

fn task_view(
    store: &Store,
    sessions: &HashMap<SessionId, SessionState>,
    session_id: SessionId,
    task_id: TaskId,
) -> Result<TaskView, KernelError> {
    if !sessions.contains_key(&session_id) {
        return Err(unknown_session());
    }
    let record = store
        .get_task(task_id)
        .map_err(map_storage)?
        .filter(|record| record.snapshot.session_id == session_id)
        .ok_or_else(invalid_input)?;
    Ok(TaskView::from(&record.snapshot))
}

fn active_durable_task_id(store: &Store, session_id: SessionId) -> Result<TaskId, KernelError> {
    let active = store
        .list_tasks_for_session(session_id, 64)
        .map_err(map_storage)?
        .into_iter()
        .filter(|record| {
            matches!(
                record.snapshot.status,
                crate::runtime::task::TaskStatus::Active
                    | crate::runtime::task::TaskStatus::Checkpointing
                    | crate::runtime::task::TaskStatus::Cancelling
                    | crate::runtime::task::TaskStatus::Completing
            )
        })
        .map(|record| record.snapshot.task_id)
        .collect::<Vec<_>>();
    match active.as_slice() {
        [task_id] => Ok(*task_id),
        _ => Err(invalid_input()),
    }
}

fn locked_active_durable_task_id(
    store: &Mutex<Store>,
    session_id: SessionId,
) -> Result<TaskId, KernelError> {
    let store = store.lock().map_err(|_| provider_error())?;
    active_durable_task_id(&store, session_id)
}

fn synchronize_session_configuration_from_projection(
    store: &Mutex<Store>,
    sessions: &mut HashMap<SessionId, SessionState>,
    session_id: SessionId,
    task_id: TaskId,
) -> Result<(), KernelError> {
    let configuration = store
        .lock()
        .map_err(|_| provider_error())?
        .get_task_configuration(task_id)
        .map_err(map_storage)?
        .ok_or_else(invalid_input)?;
    let state = sessions.get_mut(&session_id).ok_or_else(unknown_session)?;
    let catalog = state.public.configuration().catalog().clone();
    let projected_active = SessionConfiguration::new(
        catalog.clone(),
        configuration.active_model,
        configuration.active_effort,
        configuration.active_permission_mode,
    )
    .map_err(|_| provider_error())?;
    let projected_pending = match (
        configuration.pending_model,
        configuration.pending_effort,
        configuration.pending_permission_mode,
    ) {
        (Some(model), Some(effort), Some(permission_mode)) => Some(
            SessionConfiguration::new(catalog, model, effort, permission_mode)
                .map_err(|_| provider_error())?,
        ),
        (None, None, None) => None,
        _ => return Err(provider_error()),
    };
    state.pending_configuration = projected_pending.or_else(|| {
        (state.public.configuration() != &projected_active).then_some(projected_active)
    });
    Ok(())
}

fn task_views(
    store: &Store,
    sessions: &HashMap<SessionId, SessionState>,
    session_id: SessionId,
) -> Result<Vec<TaskView>, KernelError> {
    if !sessions.contains_key(&session_id) {
        return Err(unknown_session());
    }
    store
        .list_tasks_for_session(session_id, 64)
        .map_err(map_storage)
        .map(|records| {
            records
                .iter()
                .map(|record| TaskView::from(&record.snapshot))
                .collect()
        })
}

fn task_context_view(
    store: &Store,
    sessions: &HashMap<SessionId, SessionState>,
    session_id: SessionId,
    task_id: TaskId,
) -> Result<TaskContextView, KernelError> {
    if !sessions.contains_key(&session_id) {
        return Err(unknown_session());
    }
    let record = store
        .get_task(task_id)
        .map_err(map_storage)?
        .filter(|record| record.snapshot.session_id == session_id)
        .ok_or_else(invalid_input)?;
    Ok(TaskContextView::from(&record.snapshot))
}

fn map_storage(_error: crate::error::CarlError) -> KernelError {
    KernelError::from_code(KernelErrorCode::StorageFailed)
}

fn map_agent_port(_error: AgentPortError) -> KernelError {
    provider_error()
}

fn validate_durable_steering(input: &str) -> Result<(), KernelError> {
    if input.trim().is_empty() || input.len() > MAX_FINAL_MESSAGE_BYTES {
        return Err(invalid_input());
    }
    SecretFilter
        .inspect(input.as_bytes())
        .map_err(|_| invalid_input())
}

fn complete_durable_reply(reply: PendingDurableReply, result: Result<(), TaskEngineError>) {
    match reply {
        PendingDurableReply::Prompt(reply) => {
            let result = result.map_or_else(
                |error| Err(map_task_engine(error)),
                |()| {
                    Ok(PromptOutcome {
                        stop_reason: PromptStopReason::EndTurn,
                        updates: Vec::new(),
                    })
                },
            );
            let _ = reply.send(result);
        }
        PendingDurableReply::Steer(reply) => {
            let _ = reply.send(result.map_err(map_task_engine));
        }
        PendingDurableReply::Cancel(reply) | PendingDurableReply::Shutdown(reply) => {
            let accepted = match result {
                Ok(()) => Ok(()),
                Err(error)
                    if matches!(
                        error.code(),
                        TaskEngineErrorCode::Cancelled | TaskEngineErrorCode::Blocked
                    ) =>
                {
                    Ok(())
                }
                Err(error) => Err(map_task_engine(error)),
            };
            let _ = reply.send(accepted);
        }
        PendingDurableReply::Approval => {}
        PendingDurableReply::Config { reply, outcome, .. } => {
            let _ = reply.send(result.map(|()| outcome).map_err(map_task_engine));
        }
    }
}

fn fail_durable_reply(reply: PendingDurableReply, error: KernelError) {
    match reply {
        PendingDurableReply::Prompt(reply) => {
            let _ = reply.send(Err(error));
        }
        PendingDurableReply::Steer(reply)
        | PendingDurableReply::Cancel(reply)
        | PendingDurableReply::Shutdown(reply) => {
            let _ = reply.send(Err(error));
        }
        PendingDurableReply::Approval => {}
        PendingDurableReply::Config { reply, .. } => {
            let _ = reply.send(Err(error));
        }
    }
}

const fn map_task_engine(error: TaskEngineError) -> KernelError {
    let code = match error.code() {
        TaskEngineErrorCode::InvalidTask => KernelErrorCode::InvalidInput,
        TaskEngineErrorCode::Storage => KernelErrorCode::StorageFailed,
        TaskEngineErrorCode::Provider
        | TaskEngineErrorCode::Context
        | TaskEngineErrorCode::Verification
        | TaskEngineErrorCode::Blocked => KernelErrorCode::ProviderFailed,
        TaskEngineErrorCode::Cancelled => KernelErrorCode::Cancelled,
    };
    KernelError::from_code(code)
}

fn effect_metadata(kind: AgentEffectKind) -> Result<(&'static str, ToolKind), KernelError> {
    match kind {
        AgentEffectKind::Command => Ok(("command", ToolKind::Execute)),
        AgentEffectKind::FileChange => Ok(("file_change", ToolKind::Edit)),
        AgentEffectKind::Network | AgentEffectKind::External => Err(provider_error()),
    }
}

fn effect_title(request: &AgentEffectRequest) -> String {
    request
        .summary
        .lines()
        .next()
        .filter(|line| !line.is_empty())
        .unwrap_or(match request.kind {
            AgentEffectKind::Command => "command",
            AgentEffectKind::FileChange => "file changes",
            AgentEffectKind::Network => "network access",
            AgentEffectKind::External => "external effect",
        })
        .to_owned()
}

const fn permission_strength(mode: PermissionMode) -> u8 {
    match mode.profile() {
        PermissionProfile::ReadOnly => 0,
        PermissionProfile::Approval => 1,
        PermissionProfile::FullAccess => 2,
    }
}

fn task_configuration_identity(
    task_id: TaskId,
    acknowledgement: u64,
    configuration: &SessionConfiguration,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"carl.task-configuration-control.v1\0");
    hasher.update(task_id.to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(acknowledgement.to_be_bytes());
    hasher.update(b"\0");
    hasher.update(configuration.model().as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(configuration.effort().as_codex_value().as_bytes());
    hasher.update(b"\0");
    hasher.update(configuration.mode().as_wire_str().as_bytes());
    format!("{:x}", hasher.finalize())
}

fn queue_session_configuration(
    state: &mut SessionState,
    selection: ConfigSelection,
) -> Result<ConfigOutcome, KernelError> {
    if matches!(
        selection,
        ConfigSelection::Mode {
            mode: PermissionMode::BypassPermissions,
            remote: true
        }
    ) {
        return Err(session_busy());
    }
    if let ConfigSelection::Mode { mode, remote: true } = selection
        && mode.profile() == PermissionProfile::FullAccess
        && !(state.frontend == Frontend::Buzz && state.buzz_context.is_some())
    {
        return Err(KernelError::from_code(KernelErrorCode::ApprovalUnavailable));
    }
    let base = state
        .pending_configuration
        .clone()
        .unwrap_or_else(|| state.public.configuration.clone());
    let configuration = match selection {
        ConfigSelection::Model(model) => {
            apply_change(base, |configuration| configuration.set_model(model))?
        }
        ConfigSelection::Effort(effort) => {
            apply_change(base, |configuration| configuration.set_effort(effort))?
        }
        ConfigSelection::Mode { mode, remote } => apply_change(base, |configuration| {
            configuration.set_mode(
                mode,
                if remote {
                    ModeActivation::RemoteConfirmed
                } else {
                    ModeActivation::LocalExplicit
                },
            )
        })?,
    };
    state.pending_configuration = Some(configuration.clone());
    Ok(ConfigOutcome::Applied(configuration))
}

const fn invalid_input() -> KernelError {
    KernelError::from_code(KernelErrorCode::InvalidInput)
}

const fn provider_error() -> KernelError {
    KernelError::from_code(KernelErrorCode::ProviderFailed)
}

fn terminal_tool_status(status: &str) -> Result<ToolStatus, KernelError> {
    match status {
        "completed" => Ok(ToolStatus::Completed),
        "failed" | "declined" => Ok(ToolStatus::Failed),
        _ => Err(provider_error()),
    }
}

const fn unknown_session() -> KernelError {
    KernelError::from_code(KernelErrorCode::UnknownSession)
}

const fn session_busy() -> KernelError {
    KernelError::from_code(KernelErrorCode::SessionBusy)
}

const fn stopped_error() -> KernelError {
    KernelError::from_code(KernelErrorCode::Stopped)
}
