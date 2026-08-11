use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::acp::PermissionMode;
use crate::delegates::{ModelId, ReasoningEffort};
use crate::events::SessionId;
use crate::runtime::agent_port::{AgentEffectKind, AgentEffectRequest, AgentItem};

use super::progress::{RecoveryAttemptOutcome, RecoveryStrategy};

const MAX_CONTRACT_TEXT_BYTES: usize = 16 * 1024;
const MAX_CLAUSES: usize = 64;
const MAX_CONSTRAINTS: usize = 128;
const MAX_TASK_EVENT_TEXT_BYTES: usize = 16 * 1024;
const MAX_TASK_EVENT_IDENTIFIER_BYTES: usize = 128;
const MAX_TASK_EVENT_EVIDENCE_SEQUENCES: usize = 256;
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
    #[error("task event field is empty")]
    EmptyEventField,
    #[error("task workspace is invalid")]
    InvalidWorkspace,
    #[error("task event contains too many evidence sequences")]
    TooManyEvidenceSequences,
    #[error("task event evidence sequence is invalid")]
    InvalidEvidenceSequence,
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

impl OperationStatus {
    #[must_use]
    pub const fn is_resolved(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Reconciled
        )
    }

    #[must_use]
    pub const fn requires_terminal_evidence(self) -> bool {
        !matches!(self, Self::IntentRecorded | Self::Started)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationEvidenceError {
    IllegalTransition,
    Missing,
    Invalid,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct OperationEvidenceState {
    recorded_sequences: BTreeSet<u64>,
    consumed_sequences: Vec<u64>,
}

impl OperationEvidenceState {
    pub(crate) fn from_consumed(consumed_sequences: Vec<u64>) -> Self {
        Self {
            recorded_sequences: BTreeSet::new(),
            consumed_sequences,
        }
    }

    pub(crate) fn record(
        &mut self,
        status: OperationStatus,
        last_transition_sequence: u64,
        sequence: u64,
    ) -> Result<(), OperationEvidenceError> {
        if !matches!(
            status,
            OperationStatus::Started | OperationStatus::Uncertain
        ) || sequence <= last_transition_sequence
            || !self.recorded_sequences.insert(sequence)
        {
            return Err(OperationEvidenceError::Invalid);
        }
        Ok(())
    }

    pub(crate) fn transition(
        &mut self,
        status: OperationStatus,
        from: OperationStatus,
        to: OperationStatus,
        last_transition_sequence: u64,
        transition_sequence: u64,
        evidence_sequences: &[u64],
    ) -> Result<(), OperationEvidenceError> {
        if status != from || !legal_operation_edge(from, to) {
            return Err(OperationEvidenceError::IllegalTransition);
        }
        if evidence_sequences.first() == Some(&0)
            || evidence_sequences.windows(2).any(|pair| pair[0] >= pair[1])
            || evidence_sequences
                .iter()
                .any(|sequence| *sequence >= transition_sequence)
        {
            return Err(OperationEvidenceError::Invalid);
        }
        if !to.requires_terminal_evidence() {
            return Ok(());
        }
        if evidence_sequences.is_empty() {
            return Err(OperationEvidenceError::Missing);
        }
        if evidence_sequences.iter().any(|sequence| {
            *sequence <= last_transition_sequence
                || !self.recorded_sequences.contains(sequence)
                || self.consumed_sequences.contains(sequence)
        }) {
            return Err(OperationEvidenceError::Invalid);
        }
        self.consumed_sequences
            .extend_from_slice(evidence_sequences);
        Ok(())
    }

    pub(crate) fn consumed_sequences(&self) -> &[u64] {
        &self.consumed_sequences
    }
}

pub(crate) const fn legal_operation_edge(from: OperationStatus, to: OperationStatus) -> bool {
    matches!(
        (from, to),
        (OperationStatus::IntentRecorded, OperationStatus::Started)
            | (
                OperationStatus::Started,
                OperationStatus::Succeeded
                    | OperationStatus::Failed
                    | OperationStatus::Cancelled
                    | OperationStatus::Uncertain
            )
            | (OperationStatus::Uncertain, OperationStatus::Reconciled)
    )
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    Observation,
    IdempotentMutation,
    AmbiguousConsequential,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "evidence_kind", rename_all = "snake_case")]
pub enum NormalizedOperationEvidence {
    Command {
        completed: bool,
        exit_code: Option<i32>,
    },
    FileChange {
        completed: bool,
        artifact_digests: Vec<String>,
    },
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
    last_transition_sequence: u64,
    #[serde(default)]
    evidence: OperationEvidenceState,
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
    #[serde(default)]
    pending_recovery: Option<(EpochId, RecoveryStrategy, String)>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRequestPurpose {
    ContractPlanning,
    Work,
    Recovery,
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
            pending_recovery: None,
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
        sequence: u64,
    ) -> Option<OperationStatus> {
        self.operations
            .insert(
                operation_id,
                OperationSnapshot {
                    epoch_id,
                    status: OperationStatus::IntentRecorded,
                    last_transition_sequence: sequence,
                    evidence: OperationEvidenceState::default(),
                },
            )
            .map(|operation| operation.status)
    }

    pub(crate) fn operation(
        &self,
        operation_id: OperationId,
    ) -> Option<(EpochId, OperationStatus, u64)> {
        self.operations.get(&operation_id).map(|operation| {
            (
                operation.epoch_id,
                operation.status,
                operation.last_transition_sequence,
            )
        })
    }

    pub(crate) fn pending_recovery(&self) -> Option<&(EpochId, RecoveryStrategy, String)> {
        self.pending_recovery.as_ref()
    }

    pub(crate) fn start_recovery(
        &mut self,
        epoch_id: EpochId,
        strategy: RecoveryStrategy,
        strategy_fingerprint: String,
    ) -> bool {
        if self.pending_recovery.is_some() {
            return false;
        }
        self.pending_recovery = Some((epoch_id, strategy, strategy_fingerprint));
        true
    }

    pub(crate) fn finish_recovery(&mut self) {
        self.pending_recovery = None;
    }

    pub(crate) fn transition_operation(
        &mut self,
        operation_id: OperationId,
        from: OperationStatus,
        to: OperationStatus,
        sequence: u64,
        evidence_sequences: &[u64],
    ) -> Result<(), OperationEvidenceError> {
        let operation = self
            .operations
            .get_mut(&operation_id)
            .expect("operation existence checked before transition");
        operation.evidence.transition(
            operation.status,
            from,
            to,
            operation.last_transition_sequence,
            sequence,
            evidence_sequences,
        )?;
        operation.status = to;
        operation.last_transition_sequence = sequence;
        Ok(())
    }

    pub(crate) fn record_operation_evidence(
        &mut self,
        operation_id: OperationId,
        sequence: u64,
    ) -> Result<(), OperationEvidenceError> {
        let operation = self
            .operations
            .get_mut(&operation_id)
            .expect("operation existence checked before evidence");
        operation.evidence.record(
            operation.status,
            operation.last_transition_sequence,
            sequence,
        )
    }

    pub(crate) fn has_unresolved_operations(&self) -> bool {
        self.operations
            .values()
            .any(|operation| !operation.status.is_resolved())
    }

    pub(crate) fn started_operation_ids(&self) -> Vec<OperationId> {
        self.operations
            .iter()
            .filter_map(|(operation_id, operation)| {
                (operation.status == OperationStatus::Started).then_some(*operation_id)
            })
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "task_event", rename_all = "snake_case")]
pub enum TaskEvent {
    Created {
        session_id: SessionId,
        #[serde(deserialize_with = "deserialize_workspace")]
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
        #[serde(deserialize_with = "deserialize_event_text")]
        reason: String,
    },
    ContractRevised {
        contract: CompletionContract,
    },
    EpochStarted {
        epoch_id: EpochId,
        #[serde(deserialize_with = "deserialize_event_text")]
        objective: String,
    },
    EpochFinished {
        epoch_id: EpochId,
        #[serde(deserialize_with = "deserialize_event_identifier")]
        report_digest: String,
    },
    ProviderRequestRecorded {
        epoch_id: EpochId,
        purpose: ProviderRequestPurpose,
        request_sequence: u64,
        #[serde(deserialize_with = "deserialize_event_identifier")]
        request_digest: String,
    },
    ProviderEpochBound {
        epoch_id: EpochId,
        #[serde(deserialize_with = "deserialize_event_identifier")]
        provider_epoch_id: String,
    },
    OperationIntentRecorded {
        operation_id: OperationId,
        epoch_id: EpochId,
        #[serde(deserialize_with = "deserialize_event_identifier")]
        item_id: String,
        effect_class: EffectClass,
        #[serde(deserialize_with = "deserialize_event_identifier")]
        request_digest: String,
    },
    OperationTransitioned {
        operation_id: OperationId,
        from: OperationStatus,
        to: OperationStatus,
        #[serde(deserialize_with = "deserialize_evidence_sequences")]
        evidence_sequences: Vec<u64>,
    },
    OperationEvidenceRecorded {
        operation_id: OperationId,
        #[serde(deserialize_with = "deserialize_event_identifier")]
        result_digest: String,
    },
    NormalizedOperationEvidenceRecorded {
        operation_id: OperationId,
        evidence: NormalizedOperationEvidence,
    },
    UsageObserved {
        epoch_id: EpochId,
        total_tokens: u64,
        context_window: Option<u64>,
    },
    ProgressAssessed {
        #[serde(deserialize_with = "deserialize_event_identifier")]
        fingerprint: String,
        stalled: bool,
    },
    RecoveryAttemptStarted {
        epoch_id: EpochId,
        strategy: RecoveryStrategy,
        #[serde(deserialize_with = "deserialize_event_identifier")]
        strategy_fingerprint: String,
    },
    RecoveryAttemptRecorded {
        epoch_id: EpochId,
        strategy: RecoveryStrategy,
        #[serde(deserialize_with = "deserialize_event_identifier")]
        strategy_fingerprint: String,
        outcome: RecoveryAttemptOutcome,
    },
    CheckpointCommitted {
        checkpoint_id: CheckpointId,
        #[serde(deserialize_with = "deserialize_event_identifier")]
        digest: String,
    },
    CompactionRequested {
        generation: u32,
        #[serde(deserialize_with = "deserialize_event_text")]
        reason: String,
    },
    CompactionCompleted {
        generation: u32,
        checkpoint_id: CheckpointId,
        context_package_id: ContextPackageId,
    },
    ProviderContextBound {
        #[serde(deserialize_with = "deserialize_event_identifier")]
        context_id: String,
    },
    ProviderContextLost {
        #[serde(deserialize_with = "deserialize_event_identifier")]
        context_id: String,
        #[serde(deserialize_with = "deserialize_event_text")]
        reason: String,
    },
    SteeringQueued {
        steering_sequence: u64,
        #[serde(deserialize_with = "deserialize_event_identifier")]
        text_digest: String,
    },
    CancellationRequested,
    Blocked {
        #[serde(deserialize_with = "deserialize_event_text")]
        reason: String,
    },
    Completed,
}

impl TaskEvent {
    pub fn validate(&self) -> Result<(), TaskValidationError> {
        match self {
            Self::Created {
                workspace,
                contract,
                ..
            } => {
                validate_workspace(workspace)?;
                contract.validate()
            }
            Self::StateTransitioned { reason, .. }
            | Self::CompactionRequested { reason, .. }
            | Self::Blocked { reason } => validate_event_text(reason),
            Self::ContractRevised { contract } => contract.validate(),
            Self::EpochStarted { objective, .. } => validate_event_text(objective),
            Self::EpochFinished { report_digest, .. } => validate_event_identifier(report_digest),
            Self::ProviderRequestRecorded { request_digest, .. } => {
                validate_event_identifier(request_digest)
            }
            Self::ProviderEpochBound {
                provider_epoch_id, ..
            } => validate_event_identifier(provider_epoch_id),
            Self::OperationIntentRecorded {
                item_id,
                request_digest,
                ..
            } => {
                validate_event_identifier(item_id)?;
                validate_event_identifier(request_digest)
            }
            Self::OperationTransitioned {
                evidence_sequences, ..
            } => validate_evidence_sequences(evidence_sequences),
            Self::OperationEvidenceRecorded { result_digest, .. } => {
                validate_event_identifier(result_digest)
            }
            Self::NormalizedOperationEvidenceRecorded { evidence, .. } => match evidence {
                NormalizedOperationEvidence::Command { .. } => Ok(()),
                NormalizedOperationEvidence::FileChange {
                    artifact_digests, ..
                } => {
                    if artifact_digests.len() > MAX_TASK_EVENT_EVIDENCE_SEQUENCES
                        || artifact_digests
                            .iter()
                            .any(|digest| !is_lowercase_sha256(digest))
                    {
                        Err(TaskValidationError::from_code(
                            TaskValidationErrorCode::InvalidEvidenceSequence,
                        ))
                    } else {
                        Ok(())
                    }
                }
            },
            Self::ProgressAssessed { fingerprint, .. } => validate_event_identifier(fingerprint),
            Self::RecoveryAttemptStarted {
                strategy,
                strategy_fingerprint,
                ..
            }
            | Self::RecoveryAttemptRecorded {
                strategy,
                strategy_fingerprint,
                ..
            } => {
                if *strategy == RecoveryStrategy::DeclareBlocked
                    || !is_lowercase_sha256(strategy_fingerprint)
                {
                    return Err(TaskValidationError::from_code(
                        TaskValidationErrorCode::EmptyEventField,
                    ));
                }
                Ok(())
            }
            Self::CheckpointCommitted { digest, .. } => validate_event_identifier(digest),
            Self::ProviderContextBound { context_id } => validate_event_identifier(context_id),
            Self::ProviderContextLost { context_id, reason } => {
                validate_event_identifier(context_id)?;
                validate_event_text(reason)
            }
            Self::SteeringQueued { text_digest, .. } => validate_event_identifier(text_digest),
            Self::UsageObserved { .. }
            | Self::CompactionCompleted { .. }
            | Self::CancellationRequested
            | Self::Completed => Ok(()),
        }
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_event_text(value: &str) -> Result<(), TaskValidationError> {
    validate_event_string(value, MAX_TASK_EVENT_TEXT_BYTES)
}

fn validate_event_identifier(value: &str) -> Result<(), TaskValidationError> {
    validate_event_string(value, MAX_TASK_EVENT_IDENTIFIER_BYTES)
}

fn validate_event_string(value: &str, max_bytes: usize) -> Result<(), TaskValidationError> {
    if value.trim().is_empty() {
        return Err(TaskValidationError::from_code(
            TaskValidationErrorCode::EmptyEventField,
        ));
    }
    if value.len() > max_bytes {
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

fn validate_workspace(workspace: &Path) -> Result<(), TaskValidationError> {
    let Some(workspace_text) = workspace.to_str() else {
        return Err(TaskValidationError::from_code(
            TaskValidationErrorCode::InvalidWorkspace,
        ));
    };
    if !workspace.has_root()
        || workspace_text.len() > MAX_TASK_EVENT_TEXT_BYTES
        || workspace_text.chars().any(char::is_control)
    {
        return Err(TaskValidationError::from_code(
            TaskValidationErrorCode::InvalidWorkspace,
        ));
    }
    Ok(())
}

fn validate_evidence_sequences(sequences: &[u64]) -> Result<(), TaskValidationError> {
    if sequences.len() > MAX_TASK_EVENT_EVIDENCE_SEQUENCES {
        return Err(TaskValidationError::from_code(
            TaskValidationErrorCode::TooManyEvidenceSequences,
        ));
    }
    if sequences.first() == Some(&0) || sequences.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(TaskValidationError::from_code(
            TaskValidationErrorCode::InvalidEvidenceSequence,
        ));
    }
    Ok(())
}

fn deserialize_event_text<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_event_text(&value).map_err(|_| D::Error::custom("invalid task event text"))?;
    Ok(value)
}

fn deserialize_event_identifier<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_event_identifier(&value)
        .map_err(|_| D::Error::custom("invalid task event identifier"))?;
    Ok(value)
}

fn deserialize_workspace<'de, D>(deserializer: D) -> Result<PathBuf, D::Error>
where
    D: Deserializer<'de>,
{
    let value = PathBuf::deserialize(deserializer)?;
    validate_workspace(&value).map_err(|_| D::Error::custom("invalid task workspace"))?;
    Ok(value)
}

fn deserialize_evidence_sequences<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_seq(EvidenceSequencesVisitor)
}

struct EvidenceSequencesVisitor;

impl<'de> Visitor<'de> for EvidenceSequencesVisitor {
    type Value = Vec<u64>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded ordered list of task evidence sequences")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let capacity = sequence
            .size_hint()
            .unwrap_or(0)
            .min(MAX_TASK_EVENT_EVIDENCE_SEQUENCES);
        let mut values = Vec::with_capacity(capacity);
        while let Some(value) = sequence.next_element::<u64>()? {
            if values.len() == MAX_TASK_EVENT_EVIDENCE_SEQUENCES {
                return Err(A::Error::custom(
                    "task event contains too many evidence sequences",
                ));
            }
            if value == 0 || values.last().is_some_and(|previous| *previous >= value) {
                return Err(A::Error::custom(
                    "task event evidence sequences are not strictly ordered",
                ));
            }
            values.push(value);
        }
        Ok(values)
    }
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
