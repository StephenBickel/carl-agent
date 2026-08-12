use std::fmt;
use std::path::PathBuf;

use serde::Serialize;
use thiserror::Error;

use super::{BuzzContext, PermissionMode, SessionConfiguration};
use crate::delegates::{ModelId, ReasoningEffort};
use crate::events::SessionId;
use crate::policy::{ActorId, Frontend};
use crate::runtime::task::TaskBudget;
use crate::runtime::task::{
    CheckpointId, CompletionClause, EpochId, RecoveryStrategy, TaskId, TaskSnapshot, TaskStatus,
};
use crate::storage::{ChannelId, ClientName, ExternalSessionId};

const MAX_PROMPT_BLOCKS: usize = 12;
const MAX_PROMPT_BYTES: usize = 256 * 1_024;
const MAX_TASK_CONTEXT_TEXT_BYTES: usize = 4 * 1_024;
const MAX_TASK_CONTEXT_CONSTRAINTS: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskView {
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub status: TaskStatus,
    pub revision: u64,
    pub active_epoch: Option<EpochId>,
    pub latest_checkpoint: Option<CheckpointId>,
}

impl From<&TaskSnapshot> for TaskView {
    fn from(snapshot: &TaskSnapshot) -> Self {
        Self {
            task_id: snapshot.task_id,
            session_id: snapshot.session_id,
            status: snapshot.status,
            revision: snapshot.revision,
            active_epoch: snapshot.active_epoch,
            latest_checkpoint: snapshot.latest_checkpoint,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaskContextView {
    pub task: TaskView,
    pub goal: String,
    pub constraints: Vec<String>,
}

impl From<&TaskSnapshot> for TaskContextView {
    fn from(snapshot: &TaskSnapshot) -> Self {
        Self {
            task: TaskView::from(snapshot),
            goal: bounded_task_context_text(&snapshot.contract.goal),
            constraints: snapshot
                .contract
                .constraints
                .iter()
                .take(MAX_TASK_CONTEXT_CONSTRAINTS)
                .map(|constraint| bounded_task_context_text(constraint))
                .collect(),
        }
    }
}

fn bounded_task_context_text(value: &str) -> String {
    if value.len() <= MAX_TASK_CONTEXT_TEXT_BYTES {
        return value.to_owned();
    }
    let mut end = MAX_TASK_CONTEXT_TEXT_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KernelErrorCode {
    #[error("kernel input is invalid")]
    InvalidInput,
    #[error("kernel session is unavailable")]
    UnknownSession,
    #[error("kernel session is busy")]
    SessionBusy,
    #[error("kernel approval is unavailable")]
    ApprovalUnavailable,
    #[error("kernel provider failed")]
    ProviderFailed,
    #[error("kernel publication failed")]
    PublicationFailed,
    #[error("kernel delivery is uncertain")]
    DeliveryUncertain,
    #[error("kernel durable state failed")]
    StorageFailed,
    #[error("kernel was cancelled")]
    Cancelled,
    #[error("kernel has stopped")]
    Stopped,
}

#[derive(Debug, Error)]
#[error("{code}")]
pub struct KernelError {
    code: KernelErrorCode,
}

impl KernelError {
    #[must_use]
    pub const fn from_code(code: KernelErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(&self) -> KernelErrorCode {
        self.code
    }
}

#[derive(Clone, Debug)]
pub struct NewSessionRequest {
    pub external_session_id: ExternalSessionId,
    pub frontend: Frontend,
    pub client_name: ClientName,
    pub protocol_version: u32,
    pub cwd: PathBuf,
    pub actor_id: ActorId,
    pub channel_id: Option<ChannelId>,
    pub buzz_context: Option<BuzzContext>,
    pub model: Option<ModelId>,
    pub effort: Option<ReasoningEffort>,
    pub mode: PermissionMode,
    pub budget: TaskBudget,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelSession {
    pub(crate) id: SessionId,
    pub(crate) external_session_id: ExternalSessionId,
    pub(crate) configuration: SessionConfiguration,
}

impl KernelSession {
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    #[must_use]
    pub const fn external_session_id(&self) -> &ExternalSessionId {
        &self.external_session_id
    }

    #[must_use]
    pub const fn configuration(&self) -> &SessionConfiguration {
        &self.configuration
    }

    pub(crate) fn new(
        id: SessionId,
        external_session_id: ExternalSessionId,
        configuration: SessionConfiguration,
    ) -> Self {
        Self {
            id,
            external_session_id,
            configuration,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Prompt {
    blocks: Vec<String>,
    actor_id: Option<ActorId>,
}

impl Prompt {
    pub fn new(blocks: Vec<String>) -> Result<Self, KernelError> {
        if blocks.is_empty() || blocks.len() > MAX_PROMPT_BLOCKS {
            return Err(KernelError::from_code(KernelErrorCode::InvalidInput));
        }
        let bytes = blocks.iter().try_fold(0_usize, |total, block| {
            total
                .checked_add(block.len())
                .ok_or_else(|| KernelError::from_code(KernelErrorCode::InvalidInput))
        })?;
        if bytes > MAX_PROMPT_BYTES || blocks.iter().any(|block| block.as_bytes().contains(&0)) {
            return Err(KernelError::from_code(KernelErrorCode::InvalidInput));
        }
        Ok(Self {
            blocks,
            actor_id: None,
        })
    }

    #[must_use]
    pub fn with_actor(mut self, actor_id: ActorId) -> Self {
        self.actor_id = Some(actor_id);
        self
    }

    #[must_use]
    pub fn blocks(&self) -> &[String] {
        &self.blocks
    }

    #[must_use]
    pub const fn actor_id(&self) -> Option<&ActorId> {
        self.actor_id.as_ref()
    }

    #[must_use]
    pub fn provider_text(&self) -> String {
        self.blocks.join("\n\n")
    }

    #[must_use]
    pub fn leading_slash_command(&self) -> Option<&str> {
        let command = self.blocks.first()?.trim();
        (command.starts_with('/') && command.len() <= 1_024 && !command.contains(['\n', '\r']))
            .then_some(command)
    }

    #[must_use]
    pub fn task_slash_command(&self) -> Option<&str> {
        self.leading_slash_command().filter(|command| {
            matches!(
                *command,
                "/status"
                    | "/metrics"
                    | "/resume"
                    | "/cancel"
                    | "/context"
                    | "/permissions fullAccess"
                    | "/permissions approval"
                    | "/permissions readOnly"
            )
        })
    }
}

impl fmt::Debug for Prompt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Prompt")
            .field("blocks", &self.blocks.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigSelection {
    Model(ModelId),
    Effort(ReasoningEffort),
    Mode { mode: PermissionMode, remote: bool },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigOutcome {
    Applied(SessionConfiguration),
    PendingBypass { display_code: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PromptStopReason {
    EndTurn,
    WaitingForApproval,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolKind {
    Execute,
    Edit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolStatus {
    Pending,
    Completed,
    Failed,
}

#[derive(Clone, Debug, PartialEq)]
pub enum KernelUpdate {
    AgentMessageChunk(String),
    ToolStarted {
        title: String,
        kind: ToolKind,
    },
    ToolCompleted {
        title: String,
        status: ToolStatus,
    },
    DiffUpdated(String),
    AvailableCommandsChanged,
    SessionInfoChanged {
        configuration: SessionConfiguration,
    },
    TaskStatus {
        task_id: TaskId,
        status: TaskStatus,
    },
    EpochObjective {
        task_id: TaskId,
        epoch_id: EpochId,
        objective: String,
    },
    CheckpointCommitted {
        task_id: TaskId,
        checkpoint_id: CheckpointId,
        digest: String,
    },
    ContextUsage {
        task_id: TaskId,
        total_tokens: u64,
        context_window: Option<u64>,
    },
    Compaction {
        task_id: TaskId,
        generation: u32,
        replaced_provider: bool,
    },
    RecoveryStrategy {
        task_id: TaskId,
        strategy: RecoveryStrategy,
    },
    CompletionClauses {
        task_id: TaskId,
        clauses: Vec<CompletionClause>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct PromptOutcome {
    pub stop_reason: PromptStopReason,
    pub updates: Vec<KernelUpdate>,
}
