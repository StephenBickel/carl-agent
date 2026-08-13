use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use thiserror::Error;
use uuid::Uuid;

use crate::acp::PermissionMode;
use crate::delegates::{ModelId, ReasoningEffort};
use crate::events::{SessionId, TurnId};
use crate::policy::{ActorId, Frontend};
use crate::runtime::task::{TaskBudget, TaskId};
use crate::service::client::TaskServiceClient;
use crate::service::protocol::{
    SERVICE_PROTOCOL_VERSION, ServiceApprovalDecision, ServiceCommand, ServiceInfo, ServiceRequest,
    ServiceResult, ServiceSessionSummary, StartTaskCommand, TaskUpdate,
};

use super::command::{SlashCommand, SubmittedInput};
use super::state::TuiEvent;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TuiError {
    #[error("the Carl TUI service is unavailable")]
    ServiceUnavailable,
    #[error("the Carl TUI service returned an invalid response")]
    InvalidResponse,
    #[error("the Carl TUI command is invalid in the current state")]
    InvalidState,
    #[error("the selected model or effort is unsupported")]
    UnsupportedConfiguration,
}

pub trait TuiBackend {
    fn info(&self) -> &ServiceInfo;

    fn request<'a>(
        &'a mut self,
        command: ServiceCommand,
    ) -> Pin<Box<dyn Future<Output = Result<ServiceResult, TuiError>> + Send + 'a>>;
}

pub struct ServiceTuiBackend {
    client: TaskServiceClient,
}

impl ServiceTuiBackend {
    #[must_use]
    pub const fn new(client: TaskServiceClient) -> Self {
        Self { client }
    }
}

impl TuiBackend for ServiceTuiBackend {
    fn info(&self) -> &ServiceInfo {
        self.client.info()
    }

    fn request<'a>(
        &'a mut self,
        command: ServiceCommand,
    ) -> Pin<Box<dyn Future<Output = Result<ServiceResult, TuiError>> + Send + 'a>> {
        Box::pin(async move {
            let request_id = Uuid::new_v4().to_string();
            self.client
                .request(ServiceRequest {
                    protocol_version: SERVICE_PROTOCOL_VERSION,
                    idempotency_key: format!("tui-{request_id}"),
                    request_id,
                    command,
                })
                .await
                .map_err(|_| TuiError::ServiceUnavailable)
        })
    }
}

pub struct TuiController<B> {
    backend: B,
    workspace: PathBuf,
    sessions: Vec<ServiceSessionSummary>,
    external_session_id: Option<String>,
    task_id: Option<TaskId>,
    model: Option<ModelId>,
    effort: Option<ReasoningEffort>,
    permission_mode: PermissionMode,
    live_generation: String,
    live_cursor: Option<u64>,
    pending_approval: Option<PendingApproval>,
}

#[derive(Clone)]
struct PendingApproval {
    task_id: TaskId,
    external_session_id: String,
    display_code: String,
    session_id: SessionId,
    turn_id: TurnId,
}

impl<B: TuiBackend> TuiController<B> {
    pub fn new(backend: B, workspace: PathBuf) -> Self {
        let info = backend.info();
        Self {
            model: info.default_model.clone(),
            effort: info.default_effort,
            live_generation: info.live_generation.clone(),
            backend,
            workspace,
            sessions: Vec::new(),
            external_session_id: None,
            task_id: None,
            permission_mode: PermissionMode::FullAccess,
            live_cursor: None,
            pending_approval: None,
        }
    }

    pub async fn initialize(&mut self) -> Result<Vec<TuiEvent>, TuiError> {
        self.refresh_sessions().await
    }

    pub async fn submit(&mut self, input: SubmittedInput) -> Result<Vec<TuiEvent>, TuiError> {
        match input {
            SubmittedInput::Prompt(text) => self.submit_prompt(text).await,
            SubmittedInput::Command(command) => self.submit_command(command).await,
        }
    }

    async fn submit_prompt(&mut self, text: String) -> Result<Vec<TuiEvent>, TuiError> {
        if let Some(task_id) = self.task_id {
            self.expect_applied(ServiceCommand::Steer {
                task_id,
                text: text.clone(),
            })
            .await?;
            return Ok(vec![TuiEvent::UserSubmitted(text)]);
        }
        let model = self
            .model
            .clone()
            .ok_or(TuiError::UnsupportedConfiguration)?;
        let effort = self.effort.ok_or(TuiError::UnsupportedConfiguration)?;
        let external_session_id = self
            .external_session_id
            .clone()
            .unwrap_or_else(|| format!("tui-{}", Uuid::new_v4()));
        let result = self
            .backend
            .request(ServiceCommand::StartTask(StartTaskCommand {
                frontend: Frontend::Tui,
                external_session_id: external_session_id.clone(),
                workspace: self.workspace.clone(),
                request: text.clone(),
                model: model.clone(),
                effort,
                permission_mode: self.permission_mode,
                budget: TaskBudget::default(),
            }))
            .await?;
        let ServiceResult::Accepted { task_id } = result else {
            return Err(TuiError::InvalidResponse);
        };
        self.external_session_id = Some(external_session_id.clone());
        self.task_id = Some(task_id);
        Ok(vec![
            TuiEvent::UserSubmitted(text),
            TuiEvent::TaskBound {
                external_session_id,
                task_id,
                model,
                effort,
                permission_mode: self.permission_mode,
            },
        ])
    }

    async fn submit_command(&mut self, command: SlashCommand) -> Result<Vec<TuiEvent>, TuiError> {
        match command {
            SlashCommand::Model(None) => Ok(vec![TuiEvent::Notice(self.model_notice())]),
            SlashCommand::Model(Some(value)) => {
                let model = ModelId::parse(value).map_err(|_| TuiError::UnsupportedConfiguration)?;
                let service_model = self
                    .backend
                    .info()
                    .models
                    .iter()
                    .find(|candidate| candidate.id == model)
                    .ok_or(TuiError::UnsupportedConfiguration)?;
                let effort = self
                    .effort
                    .filter(|effort| service_model.supported_efforts.contains(effort))
                    .unwrap_or(service_model.default_effort);
                self.model = Some(model);
                self.effort = Some(effort);
                self.configure_active().await?;
                Ok(vec![TuiEvent::Notice("model updated".to_owned())])
            }
            SlashCommand::Provider(_) | SlashCommand::Login | SlashCommand::Logout => Ok(vec![
                TuiEvent::Notice(
                    "Slice 1 uses the configured OpenAI subscription; native provider onboarding follows"
                        .to_owned(),
                ),
            ]),
            SlashCommand::Effort(effort) => {
                let model = self.model.as_ref().ok_or(TuiError::UnsupportedConfiguration)?;
                let supported = self.backend.info().models.iter().any(|candidate| {
                    candidate.id == *model && candidate.supported_efforts.contains(&effort)
                });
                if !supported {
                    return Err(TuiError::UnsupportedConfiguration);
                }
                self.effort = Some(effort);
                self.configure_active().await?;
                Ok(vec![TuiEvent::Notice("effort updated".to_owned())])
            }
            SlashCommand::Permissions(permission_mode) => {
                self.permission_mode = permission_mode;
                self.configure_active().await?;
                Ok(vec![TuiEvent::Notice("permissions updated".to_owned())])
            }
            SlashCommand::Compact => {
                let task_id = self.task_id.ok_or(TuiError::InvalidState)?;
                self.expect_applied(ServiceCommand::Compact { task_id }).await?;
                Ok(vec![TuiEvent::Notice("compaction requested".to_owned())])
            }
            SlashCommand::New => {
                self.external_session_id = None;
                self.task_id = None;
                self.live_cursor = None;
                Ok(vec![TuiEvent::Notice("new session ready".to_owned())])
            }
            SlashCommand::Sessions => self.refresh_sessions().await,
            SlashCommand::Resume(target) => self.resume(target).await,
            SlashCommand::Status => {
                let task_id = self.task_id.ok_or(TuiError::InvalidState)?;
                match self.backend.request(ServiceCommand::Status { task_id }).await? {
                    ServiceResult::Snapshot(snapshot) => {
                        Ok(vec![TuiEvent::AuthoritativeSnapshot(snapshot)])
                    }
                    _ => Err(TuiError::InvalidResponse),
                }
            }
            SlashCommand::Cancel => {
                let task_id = self.task_id.ok_or(TuiError::InvalidState)?;
                self.expect_applied(ServiceCommand::Cancel { task_id }).await?;
                Ok(vec![TuiEvent::Notice("cancellation requested".to_owned())])
            }
            SlashCommand::Help => Ok(vec![TuiEvent::Notice(
                "/model /effort /permissions /compact /new /sessions /resume /status /cancel /help /exit"
                    .to_owned(),
            )]),
            SlashCommand::Exit => Ok(vec![TuiEvent::ExitRequested]),
        }
    }

    async fn configure_active(&mut self) -> Result<(), TuiError> {
        let Some(task_id) = self.task_id else {
            return Ok(());
        };
        self.expect_applied(ServiceCommand::Configure {
            task_id,
            model: self
                .model
                .clone()
                .ok_or(TuiError::UnsupportedConfiguration)?,
            effort: self.effort.ok_or(TuiError::UnsupportedConfiguration)?,
            permission_mode: self.permission_mode,
        })
        .await
    }

    async fn expect_applied(&mut self, command: ServiceCommand) -> Result<(), TuiError> {
        match self.backend.request(command).await? {
            ServiceResult::Applied => Ok(()),
            _ => Err(TuiError::InvalidResponse),
        }
    }

    async fn refresh_sessions(&mut self) -> Result<Vec<TuiEvent>, TuiError> {
        match self
            .backend
            .request(ServiceCommand::Sessions {
                frontend: Frontend::Tui,
                limit: 64,
            })
            .await?
        {
            ServiceResult::SessionList(sessions) => {
                self.sessions.clone_from(&sessions);
                Ok(vec![TuiEvent::SessionsLoaded(sessions)])
            }
            _ => Err(TuiError::InvalidResponse),
        }
    }

    async fn resume(&mut self, target: String) -> Result<Vec<TuiEvent>, TuiError> {
        let selected = target
            .parse::<usize>()
            .ok()
            .and_then(|index| index.checked_sub(1))
            .and_then(|index| self.sessions.get(index))
            .or_else(|| {
                self.sessions
                    .iter()
                    .find(|session| session.external_session_id == target)
            })
            .cloned()
            .ok_or(TuiError::InvalidState)?;
        let task_id = selected.latest_task_id.ok_or(TuiError::InvalidState)?;
        if selected
            .latest_task_status
            .is_some_and(|status| !status.is_terminal())
        {
            self.expect_applied(ServiceCommand::Resume { task_id })
                .await?;
        }
        self.external_session_id = Some(selected.external_session_id.clone());
        self.task_id = Some(task_id);
        self.model = selected.model.clone();
        self.effort = selected.effort;
        self.permission_mode = selected.permission_mode;
        self.live_cursor = None;
        Ok(vec![TuiEvent::TaskBound {
            external_session_id: selected.external_session_id,
            task_id,
            model: self.model.clone().ok_or(TuiError::InvalidResponse)?,
            effort: self.effort.ok_or(TuiError::InvalidResponse)?,
            permission_mode: self.permission_mode,
        }])
    }

    pub async fn poll_updates(&mut self) -> Result<Vec<TuiEvent>, TuiError> {
        let Some(task_id) = self.task_id else {
            return Ok(Vec::new());
        };
        let result = self
            .backend
            .request(ServiceCommand::LiveUpdates {
                task_id,
                live_generation: self.live_generation.clone(),
                after_cursor: self.live_cursor,
                limit: 128,
            })
            .await?;
        let ServiceResult::LiveUpdates(page) = result else {
            return Err(TuiError::InvalidResponse);
        };
        let mut events =
            Vec::with_capacity(page.updates.len() + usize::from(page.snapshot.is_some()));
        if let Some(snapshot) = page.snapshot {
            events.push(TuiEvent::AuthoritativeSnapshot(snapshot));
        }
        self.live_generation = page.live_generation.clone();
        for envelope in page.updates {
            if let TaskUpdate::ApprovalRequired {
                task_id,
                external_session_id,
                display_code,
                session_id,
                turn_id,
                ..
            } = &envelope.update
            {
                self.pending_approval = Some(PendingApproval {
                    task_id: *task_id,
                    external_session_id: external_session_id.clone(),
                    display_code: display_code.clone(),
                    session_id: *session_id,
                    turn_id: *turn_id,
                });
            }
            events.push(TuiEvent::DurableUpdate {
                live_generation: page.live_generation.clone(),
                cursor: envelope.cursor,
                update: envelope.update,
            });
        }
        self.live_cursor = page.cursor;
        Ok(events)
    }

    pub async fn resolve_approval(
        &mut self,
        decision: ServiceApprovalDecision,
    ) -> Result<Vec<TuiEvent>, TuiError> {
        let approval = self
            .pending_approval
            .clone()
            .ok_or(TuiError::InvalidState)?;
        if self.task_id != Some(approval.task_id)
            || self.external_session_id.as_deref() != Some(approval.external_session_id.as_str())
        {
            return Err(TuiError::InvalidState);
        }
        self.expect_applied(ServiceCommand::ResolveApproval {
            task_id: approval.task_id,
            external_session_id: approval.external_session_id,
            workspace: self.workspace.clone(),
            frontend: Frontend::Tui,
            actor_id: ActorId::parse("local-owner").map_err(|_| TuiError::InvalidState)?,
            channel_id: None,
            event_id: None,
            display_code: approval.display_code,
            session_id: approval.session_id,
            turn_id: approval.turn_id,
            decision,
        })
        .await?;
        self.pending_approval = None;
        Ok(vec![TuiEvent::Notice(match decision {
            ServiceApprovalDecision::Approve => "operation approved".to_owned(),
            ServiceApprovalDecision::Deny => "operation denied".to_owned(),
        })])
    }

    fn model_notice(&self) -> String {
        self.backend
            .info()
            .models
            .iter()
            .map(|model| model.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[must_use]
    pub fn into_backend(self) -> B {
        self.backend
    }
}
