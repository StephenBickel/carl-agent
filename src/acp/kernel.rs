use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use chrono::{TimeDelta, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::session::{
    ConfigOutcome, ConfigSelection, KernelError, KernelErrorCode, KernelSession, KernelUpdate,
    NewSessionRequest, Prompt, PromptOutcome, PromptStopReason, ToolKind, ToolStatus,
};
use super::{
    BuzzContext, BuzzErrorCode, BuzzPublisher, ConfigChange, ModeActivation, ModelCatalog,
    ModelDescriptor, PermissionMode, PermissionProfile, SessionConfiguration,
};
use crate::delegates::DelegateSettings;
use crate::delegates::codex::{
    CodexAppServer, CodexApprovalDecision, CodexApprovalKind, CodexApprovalRequest, CodexEvent,
    CodexItem, CodexModel, CodexThreadId, CodexTurnId, StartThread, StartTurn,
};
use crate::events::{ApprovalId, Event, SessionId, ToolCallId, TurnId};
use crate::policy::{ActorId, Frontend, Sha256Digest};
use crate::security::SecretFilter;
use crate::storage::{
    ApprovalStatus, BoundApprovalBinding, DeliveryKind, DeliveryStatus, ExternalSessionId,
    NewDelivery, NewFrontendSession, NewRemoteCode, ProviderRequestId, ProviderThreadId,
    RemoteCodeClaim, RemoteCodeKind, RuntimeStore,
};

const COMMAND_CAPACITY: usize = 64;
const APPROVAL_LIFETIME: TimeDelta = TimeDelta::minutes(15);
const MAX_FINAL_MESSAGE_BYTES: usize = 256 * 1_024;

pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, KernelError>> + Send + 'a>>;

pub trait CodexPort: Send {
    fn models(&mut self) -> PortFuture<'_, Vec<CodexModel>>;
    fn start_thread(&mut self, request: StartThread) -> PortFuture<'_, CodexThreadId>;
    fn start_turn(&mut self, request: StartTurn) -> PortFuture<'_, CodexTurnId>;
    fn steer(
        &mut self,
        thread_id: &CodexThreadId,
        turn_id: &CodexTurnId,
        input: String,
    ) -> PortFuture<'_, ()>;
    fn interrupt(&mut self, thread_id: &CodexThreadId, turn_id: &CodexTurnId)
    -> PortFuture<'_, ()>;
    fn next_event(&mut self) -> PortFuture<'_, CodexEvent>;
    fn resolve_approval(
        &mut self,
        approval: &CodexApprovalRequest,
        decision: CodexApprovalDecision,
    ) -> PortFuture<'_, ()>;
    fn cancel(&mut self) -> PortFuture<'_, ()>;
}

impl CodexPort for CodexAppServer {
    fn models(&mut self) -> PortFuture<'_, Vec<CodexModel>> {
        Box::pin(async move {
            CodexAppServer::models(self)
                .await
                .map_err(|_| provider_error())
        })
    }

    fn start_thread(&mut self, request: StartThread) -> PortFuture<'_, CodexThreadId> {
        Box::pin(async move {
            CodexAppServer::start_thread(self, request)
                .await
                .map_err(|_| provider_error())
        })
    }

    fn start_turn(&mut self, request: StartTurn) -> PortFuture<'_, CodexTurnId> {
        Box::pin(async move {
            CodexAppServer::start_turn(self, request)
                .await
                .map_err(|_| provider_error())
        })
    }

    fn steer(
        &mut self,
        thread_id: &CodexThreadId,
        turn_id: &CodexTurnId,
        input: String,
    ) -> PortFuture<'_, ()> {
        let thread_id = thread_id.clone();
        let turn_id = turn_id.clone();
        Box::pin(async move {
            CodexAppServer::steer(self, &thread_id, &turn_id, input)
                .await
                .map_err(|_| provider_error())
        })
    }

    fn interrupt(
        &mut self,
        thread_id: &CodexThreadId,
        turn_id: &CodexTurnId,
    ) -> PortFuture<'_, ()> {
        let thread_id = thread_id.clone();
        let turn_id = turn_id.clone();
        Box::pin(async move {
            CodexAppServer::interrupt(self, &thread_id, &turn_id)
                .await
                .map_err(|_| provider_error())
        })
    }

    fn next_event(&mut self) -> PortFuture<'_, CodexEvent> {
        Box::pin(async move {
            CodexAppServer::next_event(self)
                .await
                .map_err(|_| provider_error())
        })
    }

    fn resolve_approval(
        &mut self,
        approval: &CodexApprovalRequest,
        decision: CodexApprovalDecision,
    ) -> PortFuture<'_, ()> {
        let approval = approval.clone();
        Box::pin(async move {
            CodexAppServer::resolve_approval(self, &approval, decision)
                .await
                .map_err(|_| provider_error())
        })
    }

    fn cancel(&mut self) -> PortFuture<'_, ()> {
        Box::pin(async move {
            CodexAppServer::cancel(self)
                .await
                .map_err(|_| provider_error())
        })
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
        reply: oneshot::Sender<Result<(), KernelError>>,
    },
    Steer {
        session_id: SessionId,
        input: String,
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
        self.send(KernelCommand::Cancel { session_id, reply })
            .await?;
        result.await.map_err(|_| stopped_error())?
    }

    pub async fn steer(&self, session_id: SessionId, input: String) -> Result<(), KernelError> {
        let (reply, result) = oneshot::channel();
        self.send(KernelCommand::Steer {
            session_id,
            input,
            reply,
        })
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
    pub async fn start(
        store: RuntimeStore,
        codex: CodexAppServer,
        publisher: Option<BuzzPublisher>,
    ) -> Result<KernelHandle, KernelError> {
        Self::start_with_ports(
            store,
            Box::new(codex),
            publisher.map(|publisher| Box::new(publisher) as Box<dyn KernelPublisher>),
        )
        .await
    }

    pub async fn start_with_ports(
        store: RuntimeStore,
        mut codex: Box<dyn CodexPort>,
        publisher: Option<Box<dyn KernelPublisher>>,
    ) -> Result<KernelHandle, KernelError> {
        let provider_models = codex.models().await?;
        let catalog = Arc::new(catalog_from_provider(&provider_models)?);
        let (commands, receiver) = mpsc::channel(COMMAND_CAPACITY);
        let handle = KernelHandle {
            commands,
            catalog: Arc::clone(&catalog),
        };
        tokio::spawn(
            KernelActor {
                store,
                codex,
                publisher,
                catalog,
                sessions: HashMap::new(),
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
    provider_thread: CodexThreadId,
    active: Option<ActiveTurn>,
    pending_bypass: Option<PendingBypass>,
}

struct ActiveTurn {
    local_turn_id: TurnId,
    provider_turn_id: CodexTurnId,
    pending_approval: Option<PendingApproval>,
    assistant_text: String,
    item_ids: HashMap<String, ToolCallId>,
}

struct PendingApproval {
    request: CodexApprovalRequest,
    approval_id: ApprovalId,
    binding: BoundApprovalBinding,
}

struct PendingBypass {
    request_digest: Sha256Digest,
}

struct KernelActor {
    store: RuntimeStore,
    codex: Box<dyn CodexPort>,
    publisher: Option<Box<dyn KernelPublisher>>,
    catalog: Arc<ModelCatalog>,
    sessions: HashMap<SessionId, SessionState>,
    receiver: mpsc::Receiver<KernelCommand>,
}

impl KernelActor {
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
                    let outcome = self.begin_prompt(session_id, prompt).await;
                    let _ = reply.send(outcome);
                    false
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
                    let result = self.attach_buzz_context(session_id, context);
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
                KernelCommand::Cancel { session_id, reply } => {
                    let result = self.cancel_session(session_id).await;
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::Steer {
                    session_id,
                    input,
                    reply,
                } => {
                    let result = self.steer_session(session_id, input).await;
                    let _ = reply.send(result);
                    false
                }
                KernelCommand::Shutdown { reply } => {
                    let result = self.codex.cancel().await;
                    let _ = reply.send(result);
                    true
                }
            };
            if should_stop {
                break;
            }
        }
        let _ = self.codex.cancel().await;
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
        let created = self.store.store().create_session().map_err(map_storage)?;
        let bound = self
            .store
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
        self.store
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
        let provider_thread = self
            .codex
            .start_thread(StartThread {
                cwd: request.cwd.clone(),
                model: Some(model),
                mode: request.mode,
            })
            .await?;
        let provider_thread_id =
            ProviderThreadId::try_from(provider_thread.as_str()).map_err(|_| provider_error())?;
        self.store
            .store()
            .configure_frontend_session(
                &bound.external_session_id,
                Some(&provider_thread_id),
                request.mode,
                Utc::now(),
            )
            .map_err(map_storage)?;
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
                provider_thread,
                active: None,
                pending_bypass: None,
            },
        );
        Ok(public)
    }

    async fn begin_prompt(
        &mut self,
        session_id: SessionId,
        prompt: Prompt,
    ) -> Result<PromptOutcome, KernelError> {
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        if prompt
            .actor_id()
            .is_some_and(|actor| actor != &state.actor_id)
        {
            return Err(KernelError::from_code(KernelErrorCode::ApprovalUnavailable));
        }
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

        let input = prompt.provider_text();
        SecretFilter
            .inspect(input.as_bytes())
            .map_err(|_| invalid_input())?;
        let local_turn_id = TurnId::new();
        self.store
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
        let provider_turn_id = self
            .codex
            .start_turn(StartTurn {
                thread_id: state.provider_thread.clone(),
                input,
                model: Some(state.public.configuration().model().clone()),
                effort: Some(state.public.configuration().effort()),
                mode: state.public.configuration().mode(),
            })
            .await?;
        self.sessions
            .get_mut(&session_id)
            .ok_or_else(unknown_session)?
            .active = Some(ActiveTurn {
            local_turn_id,
            provider_turn_id,
            pending_approval: None,
            assistant_text: String::new(),
            item_ids: HashMap::new(),
        });
        self.drive_turn(session_id).await
    }

    async fn drive_turn(&mut self, session_id: SessionId) -> Result<PromptOutcome, KernelError> {
        let mut updates = Vec::new();
        loop {
            enum Next {
                Provider(Result<CodexEvent, KernelError>),
                Command(Option<KernelCommand>),
            }
            let next = tokio::select! {
                event = self.codex.next_event() => Next::Provider(event),
                command = self.receiver.recv() => Next::Command(command),
            };
            match next {
                Next::Provider(event) => {
                    let event = match event {
                        Ok(event) => event,
                        Err(error) => {
                            self.fail_active_turn(session_id, "provider_failed");
                            return Err(error);
                        }
                    };
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
                Next::Command(Some(command)) => match command {
                    KernelCommand::Cancel {
                        session_id: target,
                        reply,
                    } if target == session_id => {
                        let result = self.cancel_session(session_id).await;
                        let accepted = result.is_ok();
                        let _ = reply.send(result);
                        if accepted {
                            return Ok(PromptOutcome {
                                stop_reason: PromptStopReason::Cancelled,
                                updates,
                            });
                        }
                    }
                    KernelCommand::Steer {
                        session_id: target,
                        input,
                        reply,
                    } if target == session_id => {
                        let result = self.steer_session(session_id, input).await;
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
        event: CodexEvent,
        updates: &mut Vec<KernelUpdate>,
    ) -> Result<Option<PromptOutcome>, KernelError> {
        let turn_id = self.active_turn(session_id)?.local_turn_id;
        match event {
            CodexEvent::ThreadStarted { thread_id } => {
                self.persist_lifecycle(session_id, None, "thread_started", thread_id.as_str())?;
            }
            CodexEvent::TurnStarted {
                turn_id: provider, ..
            } => {
                self.persist_lifecycle(
                    session_id,
                    Some(turn_id),
                    "turn_started",
                    provider.as_str(),
                )?;
            }
            CodexEvent::ItemStarted { item, .. } => {
                let item_id = item.item_id().to_owned();
                if matches!(
                    item,
                    CodexItem::Command { .. } | CodexItem::FileChange { .. }
                ) {
                    let tool_call_id = ToolCallId::new();
                    self.active_turn_mut(session_id)?
                        .item_ids
                        .insert(item_id.clone(), tool_call_id);
                }
                self.persist_lifecycle(session_id, Some(turn_id), "item_started", &item_id)?;
            }
            CodexEvent::AgentMessageDelta { text, .. } => {
                SecretFilter
                    .inspect(text.as_bytes())
                    .map_err(|_| invalid_input())?;
                let active = self.active_turn_mut(session_id)?;
                if active.assistant_text.len().saturating_add(text.len()) > MAX_FINAL_MESSAGE_BYTES
                {
                    return Err(provider_error());
                }
                active.assistant_text.push_str(&text);
                self.store
                    .store_mut()
                    .append(
                        session_id,
                        Some(turn_id),
                        Event::AssistantTextDelta { text: text.clone() },
                    )
                    .map_err(map_storage)?;
                updates.push(KernelUpdate::AgentMessageChunk(text));
            }
            CodexEvent::ItemCompleted { item, .. } => {
                let item_id = item.item_id().to_owned();
                let status = match &item {
                    CodexItem::Command { status, .. } | CodexItem::FileChange { status, .. } => {
                        if status == "completed" {
                            Some(ToolStatus::Completed)
                        } else {
                            Some(ToolStatus::Failed)
                        }
                    }
                    CodexItem::ContextCompaction { .. } | CodexItem::Other { .. } => None,
                };
                let Some(status) = status else {
                    self.persist_lifecycle(session_id, Some(turn_id), "item_completed", &item_id)?;
                    return Ok(None);
                };
                let tool_call_id = self
                    .active_turn_mut(session_id)?
                    .item_ids
                    .remove(&item_id)
                    .unwrap_or_else(ToolCallId::new);
                self.store
                    .store_mut()
                    .append(
                        session_id,
                        Some(turn_id),
                        Event::ToolCompleted {
                            tool_call_id,
                            output: json!({"status":"completed"}),
                        },
                    )
                    .map_err(map_storage)?;
                updates.push(KernelUpdate::ToolCompleted {
                    title: item_id,
                    status,
                });
            }
            CodexEvent::TokenUsageUpdated { .. } => {}
            CodexEvent::DiffUpdated { diff, .. } => {
                SecretFilter
                    .inspect(diff.as_bytes())
                    .map_err(|_| invalid_input())?;
                self.store
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
            CodexEvent::ApprovalRequested(approval) => {
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
            CodexEvent::TurnCompleted { .. } => {
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
                self.store
                    .store_mut()
                    .append(session_id, Some(turn_id), Event::TurnCompleted)
                    .map_err(map_storage)?;
                self.sessions
                    .get_mut(&session_id)
                    .ok_or_else(unknown_session)?
                    .active = None;
                return Ok(Some(PromptOutcome {
                    stop_reason: PromptStopReason::EndTurn,
                    updates: std::mem::take(updates),
                }));
            }
            CodexEvent::ProviderError { .. } => {
                self.store
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
        approval: CodexApprovalRequest,
        updates: &mut Vec<KernelUpdate>,
    ) -> Result<(), KernelError> {
        let (thread_matches, turn_matches, tool_call_id) = {
            let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
            let active = state.active.as_ref().ok_or_else(session_busy)?;
            (
                approval.thread_id() == &state.provider_thread,
                approval.turn_id() == &active.provider_turn_id && turn_id == active.local_turn_id,
                active.item_ids.get(approval.item_id()).copied(),
            )
        };
        let Some(tool_call_id) = tool_call_id.filter(|_| thread_matches && turn_matches) else {
            self.codex
                .resolve_approval(&approval, CodexApprovalDecision::Deny)
                .await?;
            return Err(provider_error());
        };
        let title = approval
            .command()
            .unwrap_or_else(|| match approval.kind() {
                CodexApprovalKind::Command => "command",
                CodexApprovalKind::FileChange => "file changes",
            })
            .to_owned();
        let summary = match approval.reason() {
            Some(reason) => format!("{title}\nReason: {reason}"),
            None => title.clone(),
        };
        if SecretFilter.inspect(summary.as_bytes()).is_err() {
            self.codex
                .resolve_approval(&approval, CodexApprovalDecision::Deny)
                .await?;
            return Err(provider_error());
        }
        self.store
            .store_mut()
            .append(
                session_id,
                Some(turn_id),
                Event::ToolProposed {
                    tool_call_id,
                    tool_name: match approval.kind() {
                        CodexApprovalKind::Command => "command".to_owned(),
                        CodexApprovalKind::FileChange => "file_change".to_owned(),
                    },
                    arguments: json!({"summary":summary}),
                },
            )
            .map_err(map_storage)?;
        self.store
            .store_mut()
            .append(
                session_id,
                Some(turn_id),
                Event::ToolDispatchAuthorized {
                    tool_call_id,
                    request_digest: approval.request_digest().to_string(),
                    automatic: true,
                },
            )
            .map_err(map_storage)?;
        self.codex
            .resolve_approval(&approval, CodexApprovalDecision::Allow)
            .await?;
        updates.push(KernelUpdate::ToolStarted {
            title,
            kind: match approval.kind() {
                CodexApprovalKind::Command => ToolKind::Execute,
                CodexApprovalKind::FileChange => ToolKind::Edit,
            },
        });
        Ok(())
    }

    async fn pause_for_approval(
        &mut self,
        session_id: SessionId,
        turn_id: TurnId,
        approval: CodexApprovalRequest,
        updates: &mut Vec<KernelUpdate>,
    ) -> Result<PromptOutcome, KernelError> {
        let (actor_id, external_session_id, frontend) = {
            let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
            (
                state.actor_id.clone(),
                state.public.external_session_id.clone(),
                state.frontend,
            )
        };
        let title = approval
            .command()
            .unwrap_or_else(|| match approval.kind() {
                CodexApprovalKind::Command => "command",
                CodexApprovalKind::FileChange => "file changes",
            })
            .to_owned();
        let summary = match approval.reason() {
            Some(reason) => format!("{title}\nReason: {reason}"),
            None => title.clone(),
        };
        if SecretFilter.inspect(summary.as_bytes()).is_err() {
            self.codex
                .resolve_approval(&approval, CodexApprovalDecision::Deny)
                .await?;
            self.store
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
            .get(approval.item_id())
            .copied()
            .unwrap_or_else(ToolCallId::new);
        let approval_id = ApprovalId::new();
        let now = Utc::now();
        let binding = BoundApprovalBinding::new(
            session_id,
            turn_id,
            tool_call_id,
            actor_id.clone(),
            approval.request_digest(),
            now,
            now + APPROVAL_LIFETIME,
        )
        .map_err(map_storage)?;
        self.store
            .store_mut()
            .append(
                session_id,
                Some(turn_id),
                Event::ToolProposed {
                    tool_call_id,
                    tool_name: match approval.kind() {
                        CodexApprovalKind::Command => "command".to_owned(),
                        CodexApprovalKind::FileChange => "file_change".to_owned(),
                    },
                    arguments: json!({"summary":summary}),
                },
            )
            .map_err(map_storage)?;
        self.store
            .store()
            .create_bound_approval(approval_id, binding.clone(), summary.clone())
            .map_err(map_storage)?;
        self.store
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
                .codex
                .resolve_approval(&request, CodexApprovalDecision::Deny)
                .await;
            self.fail_active_turn(session_id, "approval_publication_failed");
            return Err(error);
        }
        if frontend != Frontend::Buzz {
            updates.push(KernelUpdate::AgentMessageChunk(publication));
        }
        updates.push(KernelUpdate::ToolStarted {
            title,
            kind: match self
                .active_turn(session_id)?
                .pending_approval
                .as_ref()
                .expect("approval was stored")
                .request
                .kind()
            {
                CodexApprovalKind::Command => ToolKind::Execute,
                CodexApprovalKind::FileChange => ToolKind::Edit,
            },
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
            (CodexApprovalDecision::Allow, code)
        } else if let Some(code) = command.strip_prefix("/deny ") {
            (CodexApprovalDecision::Deny, code)
        } else {
            return Err(KernelError::from_code(KernelErrorCode::ApprovalUnavailable));
        };
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        let active = state.active.as_ref().ok_or_else(session_busy)?;
        let pending = active
            .pending_approval
            .as_ref()
            .ok_or_else(|| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        let provider_request_id =
            ProviderRequestId::try_from(pending.request.provider_request_id())
                .map_err(|_| provider_error())?;
        let durable = self
            .store
            .store()
            .get_frontend_session(state.public.external_session_id.as_str())
            .map_err(map_storage)?
            .ok_or_else(|| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        if durable.session_id != session_id
            || durable.cwd != state.cwd
            || durable
                .provider_thread_id
                .as_ref()
                .map(ProviderThreadId::as_str)
                != Some(state.provider_thread.as_str())
        {
            return Err(KernelError::from_code(KernelErrorCode::ApprovalUnavailable));
        }
        let status = match decision {
            CodexApprovalDecision::Allow => ApprovalStatus::Allowed,
            CodexApprovalDecision::Deny => ApprovalStatus::Denied,
        };
        let now = Utc::now();
        self.store
            .store_mut()
            .consume_remote_bound_approval(
                RemoteCodeClaim {
                    display_code: code,
                    kind: RemoteCodeKind::Approval,
                    external_session_id: state.public.external_session_id.clone(),
                    approval_id: Some(pending.approval_id),
                    provider_request_id: Some(provider_request_id),
                    request_digest: pending.request.request_digest(),
                    actor_id: state.actor_id.clone(),
                    now,
                },
                &pending.binding,
                status,
            )
            .map_err(|_| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        let approval = pending.request.clone();
        let tool_title = approval.command().unwrap_or(approval.item_id()).to_owned();
        let turn_id = active.local_turn_id;
        self.codex.resolve_approval(&approval, decision).await?;
        self.store
            .store_mut()
            .append(
                session_id,
                Some(turn_id),
                Event::UserInput {
                    text: match decision {
                        CodexApprovalDecision::Allow => "/approve <redacted>",
                        CodexApprovalDecision::Deny => "/deny <redacted>",
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
                status: if decision == CodexApprovalDecision::Allow {
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
        if state.active.is_some() {
            return Err(session_busy());
        }
        if let ConfigSelection::Mode {
            mode: PermissionMode::BypassPermissions,
            remote: true,
        } = selection
        {
            let digest = bypass_digest(
                &state.public.external_session_id,
                &state.actor_id,
                &state.cwd,
            );
            let now = Utc::now();
            let display_code = create_remote_code(
                self.store.store(),
                RemoteCodeKind::BypassConfirmation,
                &state.public.external_session_id,
                None,
                None,
                digest,
                &state.actor_id,
                now,
            )?;
            state.pending_bypass = Some(PendingBypass {
                request_digest: digest,
            });
            return Ok(ConfigOutcome::PendingBypass { display_code });
        }
        let configuration = match selection {
            ConfigSelection::Model(model) => {
                apply_change(state.public.configuration.clone(), |configuration| {
                    configuration.set_model(model)
                })?
            }
            ConfigSelection::Effort(effort) => {
                apply_change(state.public.configuration.clone(), |configuration| {
                    configuration.set_effort(effort)
                })?
            }
            ConfigSelection::Mode { mode, remote } => {
                apply_change(state.public.configuration.clone(), |configuration| {
                    configuration.set_mode(
                        mode,
                        if remote {
                            ModeActivation::RemoteConfirmed
                        } else {
                            ModeActivation::LocalExplicit
                        },
                    )
                })?
            }
        };
        state.public = KernelSession::new(
            state.public.id(),
            state.public.external_session_id.clone(),
            configuration.clone(),
        );
        self.persist_configuration(session_id)?;
        Ok(ConfigOutcome::Applied(configuration))
    }

    fn attach_buzz_context(
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
        if self.sessions.iter().any(|(other_id, other)| {
            *other_id != session_id
                && other.cwd == state.cwd
                && other
                    .buzz_context
                    .as_ref()
                    .is_some_and(|existing| existing.channel_id() == context.channel_id())
        }) {
            return Err(KernelError::from_code(KernelErrorCode::ApprovalUnavailable));
        }
        if let Some(existing) = state.buzz_context.as_ref()
            && (existing.channel_id() != context.channel_id()
                || existing.actor_hex() != context.actor_hex())
        {
            return Err(KernelError::from_code(KernelErrorCode::ApprovalUnavailable));
        }
        self.store
            .store()
            .claim_frontend_channel(&state.public.external_session_id, &channel, Utc::now())
            .map_err(map_storage)?;
        let state = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(unknown_session)?;
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
        let state = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(unknown_session)?;
        let pending = state
            .pending_bypass
            .as_ref()
            .ok_or_else(|| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
        self.store
            .store_mut()
            .consume_remote_code(RemoteCodeClaim {
                display_code: code,
                kind: RemoteCodeKind::BypassConfirmation,
                external_session_id: state.public.external_session_id.clone(),
                approval_id: None,
                provider_request_id: None,
                request_digest: pending.request_digest,
                actor_id: state.actor_id.clone(),
                now: Utc::now(),
            })
            .map_err(|_| KernelError::from_code(KernelErrorCode::ApprovalUnavailable))?;
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
        self.store
            .store()
            .configure_frontend_session(
                &state.public.external_session_id,
                Some(
                    &ProviderThreadId::try_from(state.provider_thread.as_str())
                        .map_err(map_storage)?,
                ),
                state.public.configuration.mode(),
                Utc::now(),
            )
            .map_err(map_storage)?;
        self.store
            .store()
            .set_session_delegate_settings(
                session_id,
                DelegateSettings::new(
                    Some(state.public.configuration().model().clone()),
                    Some(state.public.configuration().effort()),
                ),
                Utc::now(),
            )
            .map_err(map_storage)?;
        self.store
            .store_mut()
            .append(
                session_id,
                None,
                Event::FrontendPermissionChanged {
                    external_session_id: state.public.external_session_id.as_str().to_owned(),
                    permission_mode: state.public.configuration.mode(),
                },
            )
            .map_err(map_storage)?;
        Ok(())
    }

    async fn cancel_session(&mut self, session_id: SessionId) -> Result<(), KernelError> {
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        let active = state.active.as_ref().ok_or_else(session_busy)?;
        self.codex
            .interrupt(&state.provider_thread, &active.provider_turn_id)
            .await?;
        self.store
            .store_mut()
            .append(
                session_id,
                Some(active.local_turn_id),
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
        self.store
            .store_mut()
            .append(
                session_id,
                Some(active.local_turn_id),
                Event::UserInput {
                    text: input.clone(),
                },
            )
            .map_err(map_storage)?;
        self.codex
            .steer(&state.provider_thread, &active.provider_turn_id, input)
            .await
    }

    async fn publish(
        &mut self,
        session_id: SessionId,
        turn_id: TurnId,
        kind: DeliveryKind,
        content: &str,
    ) -> Result<(), KernelError> {
        let state = self.sessions.get(&session_id).ok_or_else(unknown_session)?;
        let (Some(publisher), Some(context)) =
            (self.publisher.as_mut(), state.buzz_context.as_ref())
        else {
            return Ok(());
        };
        SecretFilter
            .inspect(content.as_bytes())
            .map_err(|_| invalid_input())?;
        let digest = delivery_digest(session_id, turn_id, kind, content, context);
        self.store
            .store()
            .create_delivery(NewDelivery {
                action_digest: digest,
                external_session_id: state.public.external_session_id.clone(),
                kind,
                created_at: Utc::now(),
            })
            .map_err(map_storage)?;
        let result = match kind {
            DeliveryKind::Message => publisher.send_message(context, content).await,
            DeliveryKind::Diff => publisher.send_diff(context, content).await,
        };
        let status = match result {
            Ok(()) => DeliveryStatus::Delivered,
            Err(PublicationFailure::Failed) => DeliveryStatus::Failed,
            Err(PublicationFailure::Uncertain) => DeliveryStatus::Uncertain,
        };
        self.store
            .store()
            .transition_delivery(digest, status, Utc::now())
            .map_err(map_storage)?;
        self.store
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
        approval: &CodexApprovalRequest,
        actor_id: &ActorId,
        now: chrono::DateTime<Utc>,
    ) -> Result<String, KernelError> {
        let provider_request_id =
            ProviderRequestId::try_from(approval.provider_request_id()).map_err(map_storage)?;
        create_remote_code(
            self.store.store(),
            RemoteCodeKind::Approval,
            external_session_id,
            Some(approval_id),
            Some(provider_request_id),
            approval.request_digest(),
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

    fn persist_lifecycle(
        &mut self,
        session_id: SessionId,
        turn_id: Option<TurnId>,
        phase: &str,
        provider_id: &str,
    ) -> Result<(), KernelError> {
        self.store
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
            let _ = self.store.store_mut().append(
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
        KernelCommand::Shutdown { reply } => {
            let _ = reply.send(Err(session_busy()));
        }
    }
}

fn catalog_from_provider(models: &[CodexModel]) -> Result<ModelCatalog, KernelError> {
    let descriptors = models
        .iter()
        .map(|model| {
            ModelDescriptor::new(
                model.id().clone(),
                model.display_name(),
                model.supported_efforts().to_vec(),
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

fn map_storage(_error: crate::error::CarlError) -> KernelError {
    KernelError::from_code(KernelErrorCode::StorageFailed)
}

const fn invalid_input() -> KernelError {
    KernelError::from_code(KernelErrorCode::InvalidInput)
}

const fn provider_error() -> KernelError {
    KernelError::from_code(KernelErrorCode::ProviderFailed)
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
