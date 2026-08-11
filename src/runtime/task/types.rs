use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::acp::PermissionMode;
use crate::delegates::{ModelId, ReasoningEffort};
use crate::events::SessionId;
use crate::runtime::agent_port::{AgentEffectKind, AgentEffectRequest, AgentItem};

const MAX_CONTRACT_TEXT_BYTES: usize = 16 * 1024;
const MAX_CLAUSES: usize = 64;
const MAX_CONSTRAINTS: usize = 128;
const DEFAULT_SOFT_EPOCH_SECONDS: u64 = 15 * 60;
const DEFAULT_SOFT_EPOCH_TOOL_CALLS: u32 = 40;

macro_rules! define_task_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self::from_uuid(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.as_uuid()
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self::from_uuid)
            }
        }
    };
}

define_task_id!(TaskId);
define_task_id!(EpochId);
define_task_id!(OperationId);
define_task_id!(CheckpointId);
define_task_id!(ContextPackageId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClauseStatus {
    Pending,
    Satisfied,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompletionContract {
    pub version: u32,
    pub goal: String,
    pub constraints: Vec<String>,
    pub clauses: Vec<CompletionClause>,
}

#[derive(Deserialize)]
struct UnvalidatedCompletionContract {
    version: u32,
    goal: String,
    constraints: Vec<String>,
    clauses: Vec<CompletionClause>,
}

impl<'de> Deserialize<'de> for CompletionContract {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = UnvalidatedCompletionContract::deserialize(deserializer)?;
        let contract = Self {
            version: raw.version,
            goal: raw.goal,
            constraints: raw.constraints,
            clauses: raw.clauses,
        };
        contract
            .validate()
            .map_err(|_| D::Error::custom("invalid completion contract"))?;
        Ok(contract)
    }
}

impl CompletionContract {
    pub fn validate(&self) -> Result<(), TaskValidationError> {
        if self.goal.trim().is_empty() {
            return Err(TaskValidationError::from_code(
                TaskValidationErrorCode::EmptyGoal,
            ));
        }
        validate_text(&self.goal)?;
        if self.constraints.len() > MAX_CONSTRAINTS {
            return Err(TaskValidationError::from_code(
                TaskValidationErrorCode::TooManyConstraints,
            ));
        }
        if self.clauses.len() > MAX_CLAUSES {
            return Err(TaskValidationError::from_code(
                TaskValidationErrorCode::TooManyClauses,
            ));
        }

        let mut clause_ids = HashSet::with_capacity(self.clauses.len());
        for constraint in &self.constraints {
            validate_text(constraint)?;
        }
        for clause in &self.clauses {
            if clause.id.is_empty() {
                return Err(TaskValidationError::from_code(
                    TaskValidationErrorCode::EmptyClauseId,
                ));
            }
            validate_text(&clause.id)?;
            validate_text(&clause.description)?;
            if !clause_ids.insert(clause.id.as_str()) {
                return Err(TaskValidationError::from_code(
                    TaskValidationErrorCode::DuplicateClauseId,
                ));
            }
            for evidence in &clause.evidence {
                if let Some(digest) = &evidence.artifact_digest {
                    validate_text(digest)?;
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn required_clauses_satisfied(&self) -> bool {
        self.clauses
            .iter()
            .filter(|clause| clause.required)
            .all(|clause| clause.status == ClauseStatus::Satisfied && !clause.evidence.is_empty())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompletionClause {
    pub id: String,
    pub description: String,
    pub required: bool,
    pub status: ClauseStatus,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvidenceRef {
    pub event_sequence: u64,
    pub artifact_digest: Option<String>,
    pub operation_id: Option<OperationId>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TaskValidationErrorCode {
    #[error("completion goal is empty")]
    EmptyGoal,
    #[error("completion clause identifier is empty")]
    EmptyClauseId,
    #[error("completion clause identifier is duplicated")]
    DuplicateClauseId,
    #[error("completion contract contains too many clauses")]
    TooManyClauses,
    #[error("completion contract contains too many constraints")]
    TooManyConstraints,
    #[error("completion contract text is too long")]
    TextTooLong,
    #[error("completion contract text contains control characters")]
    ControlCharacter,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{code}")]
pub struct TaskValidationError {
    code: TaskValidationErrorCode,
}

impl TaskValidationError {
    const fn from_code(code: TaskValidationErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(&self) -> TaskValidationErrorCode {
        self.code
    }
}

fn validate_text(value: &str) -> Result<(), TaskValidationError> {
    if value.len() > MAX_CONTRACT_TEXT_BYTES {
        return Err(TaskValidationError::from_code(
            TaskValidationErrorCode::TextTooLong,
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(TaskValidationError::from_code(
            TaskValidationErrorCode::ControlCharacter,
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Queued,
    Active,
    Checkpointing,
    Paused,
    Blocked,
    Cancelling,
    Cancelled,
    Completing,
    Completed,
    Failed,
}

impl TaskStatus {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Cancelled | Self::Completed | Self::Failed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    IntentRecorded,
    Started,
    Succeeded,
    Failed,
    Cancelled,
    Uncertain,
    Reconciled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    Observation,
    IdempotentMutation,
    AmbiguousConsequential,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskBudget {
    pub max_wall_time_seconds: Option<u64>,
    pub max_provider_requests: Option<u64>,
    pub max_tool_calls: Option<u64>,
    pub soft_epoch_seconds: u64,
    pub soft_epoch_tool_calls: u32,
}

impl Default for TaskBudget {
    fn default() -> Self {
        Self {
            max_wall_time_seconds: None,
            max_provider_requests: None,
            max_tool_calls: None,
            soft_epoch_seconds: DEFAULT_SOFT_EPOCH_SECONDS,
            soft_epoch_tool_calls: DEFAULT_SOFT_EPOCH_TOOL_CALLS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct OperationSnapshot {
    epoch_id: EpochId,
    status: OperationStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskSnapshot {
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub status: TaskStatus,
    pub contract: CompletionContract,
    pub budget: TaskBudget,
    pub active_epoch: Option<EpochId>,
    pub latest_checkpoint: Option<CheckpointId>,
    pub provider_context: Option<String>,
    pub revision: u64,
    operations: BTreeMap<OperationId, OperationSnapshot>,
}

impl TaskSnapshot {
    pub(crate) fn created(
        task_id: TaskId,
        session_id: SessionId,
        contract: CompletionContract,
        budget: TaskBudget,
    ) -> Self {
        Self {
            task_id,
            session_id,
            status: TaskStatus::Queued,
            contract,
            budget,
            active_epoch: None,
            latest_checkpoint: None,
            provider_context: None,
            revision: 1,
            operations: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn operation_status(&self, operation_id: OperationId) -> Option<OperationStatus> {
        self.operations
            .get(&operation_id)
            .map(|operation| operation.status)
    }

    pub(crate) fn insert_operation(
        &mut self,
        operation_id: OperationId,
        epoch_id: EpochId,
    ) -> Option<OperationStatus> {
        self.operations
            .insert(
                operation_id,
                OperationSnapshot {
                    epoch_id,
                    status: OperationStatus::IntentRecorded,
                },
            )
            .map(|operation| operation.status)
    }

    pub(crate) fn operation_mut(
        &mut self,
        operation_id: OperationId,
    ) -> Option<&mut OperationStatus> {
        self.operations
            .get_mut(&operation_id)
            .map(|operation| &mut operation.status)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "task_event", rename_all = "snake_case")]
pub enum TaskEvent {
    Created {
        session_id: SessionId,
        workspace: PathBuf,
        contract: CompletionContract,
        budget: TaskBudget,
        model: ModelId,
        effort: ReasoningEffort,
        permission_mode: PermissionMode,
    },
    StateTransitioned {
        from: TaskStatus,
        to: TaskStatus,
        reason: String,
    },
    ContractRevised {
        contract: CompletionContract,
    },
    EpochStarted {
        epoch_id: EpochId,
        objective: String,
    },
    EpochFinished {
        epoch_id: EpochId,
        report_digest: String,
    },
    OperationIntentRecorded {
        operation_id: OperationId,
        epoch_id: EpochId,
        item_id: String,
        effect_class: EffectClass,
        request_digest: String,
    },
    OperationTransitioned {
        operation_id: OperationId,
        from: OperationStatus,
        to: OperationStatus,
        evidence_sequences: Vec<u64>,
    },
    UsageObserved {
        epoch_id: EpochId,
        total_tokens: u64,
        context_window: Option<u64>,
    },
    ProgressAssessed {
        fingerprint: String,
        stalled: bool,
    },
    CheckpointCommitted {
        checkpoint_id: CheckpointId,
        digest: String,
    },
    CompactionRequested {
        generation: u32,
        reason: String,
    },
    CompactionCompleted {
        generation: u32,
        checkpoint_id: CheckpointId,
        context_package_id: ContextPackageId,
    },
    ProviderContextBound {
        context_id: String,
    },
    ProviderContextLost {
        context_id: String,
        reason: String,
    },
    SteeringQueued {
        steering_sequence: u64,
        text_digest: String,
    },
    CancellationRequested,
    Blocked {
        reason: String,
    },
    Completed,
}

#[must_use]
pub fn classify_effect(request: &AgentEffectRequest, item: &AgentItem) -> EffectClass {
    match (request.kind, item) {
        (AgentEffectKind::FileChange, AgentItem::FileChange { item_id, .. })
            if request.item_id == *item_id =>
        {
            EffectClass::IdempotentMutation
        }
        _ => EffectClass::AmbiguousConsequential,
    }
}
