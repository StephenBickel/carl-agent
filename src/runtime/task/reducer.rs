use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::events::{Event, EventEnvelope};

use super::types::{OperationStatus, TaskEvent, TaskSnapshot, TaskStatus, TaskValidationErrorCode};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskReduceErrorCode {
    #[error("event is not a task lifecycle event")]
    NotTaskEvent,
    #[error("task must begin with a creation event")]
    TaskNotCreated,
    #[error("task was already created")]
    TaskAlreadyCreated,
    #[error("task identifier does not match")]
    TaskIdMismatch,
    #[error("task session does not match")]
    SessionMismatch,
    #[error("task is already terminal")]
    TerminalState,
    #[error("task status transition is illegal")]
    IllegalStatusTransition,
    #[error("completion contract is invalid")]
    InvalidContract,
    #[error("completion contract version is not monotonic")]
    NonMonotonicContractVersion,
    #[error("an epoch is already active")]
    EpochAlreadyActive,
    #[error("epoch identifier does not match")]
    EpochMismatch,
    #[error("operation intent is duplicated")]
    OperationAlreadyExists,
    #[error("operation intent is missing")]
    OperationIntentMissing,
    #[error("operation transition is illegal")]
    IllegalOperationTransition,
    #[error("operation terminal evidence is missing")]
    OperationEvidenceMissing,
    #[error("operation evidence is invalid")]
    InvalidOperationEvidence,
    #[error("task boundary is unsafe")]
    UnsafeBoundary,
    #[error("task event metadata is invalid")]
    InvalidEventMetadata,
    #[error("checkpoint is missing")]
    CheckpointMissing,
    #[error("provider context does not match")]
    ProviderContextMismatch,
    #[error("a required completion clause is unsatisfied")]
    RequiredClauseUnsatisfied,
    #[error("task revision overflowed")]
    RevisionOverflow,
}

impl TaskReduceErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotTaskEvent => "not_task_event",
            Self::TaskNotCreated => "task_not_created",
            Self::TaskAlreadyCreated => "task_already_created",
            Self::TaskIdMismatch => "task_id_mismatch",
            Self::SessionMismatch => "session_mismatch",
            Self::TerminalState => "terminal_state",
            Self::IllegalStatusTransition => "illegal_status_transition",
            Self::InvalidContract => "invalid_contract",
            Self::NonMonotonicContractVersion => "non_monotonic_contract_version",
            Self::EpochAlreadyActive => "epoch_already_active",
            Self::EpochMismatch => "epoch_mismatch",
            Self::OperationAlreadyExists => "operation_already_exists",
            Self::OperationIntentMissing => "operation_intent_missing",
            Self::IllegalOperationTransition => "illegal_operation_transition",
            Self::OperationEvidenceMissing => "operation_evidence_missing",
            Self::InvalidOperationEvidence => "invalid_operation_evidence",
            Self::UnsafeBoundary => "unsafe_boundary",
            Self::InvalidEventMetadata => "invalid_event_metadata",
            Self::CheckpointMissing => "checkpoint_missing",
            Self::ProviderContextMismatch => "provider_context_mismatch",
            Self::RequiredClauseUnsatisfied => "required_clause_unsatisfied",
            Self::RevisionOverflow => "revision_overflow",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{code}")]
pub struct TaskReduceError {
    code: TaskReduceErrorCode,
}

impl TaskReduceError {
    const fn from_code(code: TaskReduceErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(&self) -> TaskReduceErrorCode {
        self.code
    }
}

pub fn reduce_task(
    state: Option<TaskSnapshot>,
    envelope: &EventEnvelope,
) -> Result<TaskSnapshot, TaskReduceError> {
    let Event::TaskLifecycle { task_id, event } = &envelope.event else {
        return Err(error(TaskReduceErrorCode::NotTaskEvent));
    };

    let Some(mut state) = state else {
        let TaskEvent::Created {
            session_id,
            contract,
            budget,
            ..
        } = event
        else {
            return Err(error(TaskReduceErrorCode::TaskNotCreated));
        };
        event.validate().map_err(|validation| {
            if validation.code() == TaskValidationErrorCode::InvalidWorkspace {
                error(TaskReduceErrorCode::InvalidEventMetadata)
            } else {
                error(TaskReduceErrorCode::InvalidContract)
            }
        })?;
        if *session_id != envelope.session_id {
            return Err(error(TaskReduceErrorCode::SessionMismatch));
        }
        contract
            .validate()
            .map_err(|_| error(TaskReduceErrorCode::InvalidContract))?;
        return Ok(TaskSnapshot::created(
            *task_id,
            *session_id,
            contract.clone(),
            *budget,
        ));
    };

    if state.task_id != *task_id {
        return Err(error(TaskReduceErrorCode::TaskIdMismatch));
    }
    if state.session_id != envelope.session_id {
        return Err(error(TaskReduceErrorCode::SessionMismatch));
    }
    if state.status.is_terminal() {
        return Err(error(TaskReduceErrorCode::TerminalState));
    }
    if matches!(event, TaskEvent::Created { .. }) {
        return Err(error(TaskReduceErrorCode::TaskAlreadyCreated));
    }
    if !matches!(event, TaskEvent::ContractRevised { .. }) {
        event
            .validate()
            .map_err(|_| error(TaskReduceErrorCode::InvalidEventMetadata))?;
    }

    match event {
        TaskEvent::Created { .. } => unreachable!("creation handled before reduction"),
        TaskEvent::StateTransitioned { from, to, .. } => {
            transition_status(&mut state, *from, *to)?;
        }
        TaskEvent::ContractRevised { contract } => {
            contract
                .validate()
                .map_err(|_| error(TaskReduceErrorCode::InvalidContract))?;
            if contract.version <= state.contract.version {
                return Err(error(TaskReduceErrorCode::NonMonotonicContractVersion));
            }
            state.contract = contract.clone();
        }
        TaskEvent::EpochStarted { epoch_id, .. } => {
            if state.active_epoch.is_some() {
                return Err(error(TaskReduceErrorCode::EpochAlreadyActive));
            }
            if state.status != TaskStatus::Active {
                return Err(error(TaskReduceErrorCode::IllegalStatusTransition));
            }
            state.active_epoch = Some(*epoch_id);
        }
        TaskEvent::EpochFinished { epoch_id, .. } => {
            require_active_epoch(&state, *epoch_id)?;
            if state.has_unresolved_operations() {
                return Err(error(TaskReduceErrorCode::UnsafeBoundary));
            }
            state.active_epoch = None;
        }
        TaskEvent::OperationIntentRecorded {
            operation_id,
            epoch_id,
            ..
        } => {
            require_active_epoch(&state, *epoch_id)?;
            if state
                .insert_operation(*operation_id, *epoch_id, envelope.sequence)
                .is_some()
            {
                return Err(error(TaskReduceErrorCode::OperationAlreadyExists));
            }
        }
        TaskEvent::OperationTransitioned {
            operation_id,
            from,
            to,
            evidence_sequences,
        } => {
            let (operation_epoch, status, last_transition_sequence) = state
                .operation(*operation_id)
                .ok_or_else(|| error(TaskReduceErrorCode::OperationIntentMissing))?;
            if state.active_epoch != Some(operation_epoch) {
                return Err(error(TaskReduceErrorCode::EpochMismatch));
            }
            if status != *from || !legal_operation_edge(*from, *to) {
                return Err(error(TaskReduceErrorCode::IllegalOperationTransition));
            }
            if to.requires_terminal_evidence() && evidence_sequences.is_empty() {
                return Err(error(TaskReduceErrorCode::OperationEvidenceMissing));
            }
            if evidence_sequences
                .iter()
                .any(|sequence| *sequence > envelope.sequence)
                || (to.requires_terminal_evidence()
                    && (evidence_sequences.contains(&envelope.sequence)
                        || !evidence_sequences
                            .iter()
                            .any(|sequence| *sequence > last_transition_sequence)))
            {
                return Err(error(TaskReduceErrorCode::InvalidOperationEvidence));
            }
            state.set_operation_status(*operation_id, *to, envelope.sequence);
        }
        TaskEvent::OperationEvidenceRecorded { operation_id, .. } => {
            let (operation_epoch, status, last_transition_sequence) = state
                .operation(*operation_id)
                .ok_or_else(|| error(TaskReduceErrorCode::OperationIntentMissing))?;
            if state.active_epoch != Some(operation_epoch) {
                return Err(error(TaskReduceErrorCode::EpochMismatch));
            }
            if status != OperationStatus::Started || envelope.sequence <= last_transition_sequence {
                return Err(error(TaskReduceErrorCode::InvalidOperationEvidence));
            }
        }
        TaskEvent::UsageObserved { epoch_id, .. } => {
            require_active_epoch(&state, *epoch_id)?;
        }
        TaskEvent::ProgressAssessed { .. }
        | TaskEvent::CompactionRequested { .. }
        | TaskEvent::SteeringQueued { .. } => {}
        TaskEvent::CheckpointCommitted { checkpoint_id, .. } => {
            require_safe_boundary(&state)?;
            state.latest_checkpoint = Some(*checkpoint_id);
        }
        TaskEvent::CompactionCompleted { checkpoint_id, .. } => {
            require_safe_boundary(&state)?;
            if state.latest_checkpoint != Some(*checkpoint_id) {
                return Err(error(TaskReduceErrorCode::CheckpointMissing));
            }
        }
        TaskEvent::ProviderContextBound { context_id } => {
            state.provider_context = Some(context_id.clone());
        }
        TaskEvent::ProviderContextLost { context_id, .. } => {
            if state.provider_context.as_deref() != Some(context_id) {
                return Err(error(TaskReduceErrorCode::ProviderContextMismatch));
            }
            state.provider_context = None;
        }
        TaskEvent::CancellationRequested => {
            let from = state.status;
            transition_status(&mut state, from, TaskStatus::Cancelling)?;
        }
        TaskEvent::Blocked { .. } => {
            let from = state.status;
            transition_status(&mut state, from, TaskStatus::Blocked)?;
        }
        TaskEvent::Completed => {
            require_safe_boundary(&state)?;
            if !state.contract.required_clauses_satisfied() {
                return Err(error(TaskReduceErrorCode::RequiredClauseUnsatisfied));
            }
            let from = state.status;
            transition_status(&mut state, from, TaskStatus::Completed)?;
        }
    }

    state.revision = state
        .revision
        .checked_add(1)
        .ok_or_else(|| error(TaskReduceErrorCode::RevisionOverflow))?;
    Ok(state)
}

fn require_safe_boundary(state: &TaskSnapshot) -> Result<(), TaskReduceError> {
    if state.active_epoch.is_some() || state.has_unresolved_operations() {
        return Err(error(TaskReduceErrorCode::UnsafeBoundary));
    }
    Ok(())
}

fn require_active_epoch(
    state: &TaskSnapshot,
    epoch_id: super::types::EpochId,
) -> Result<(), TaskReduceError> {
    if state.active_epoch != Some(epoch_id) {
        return Err(error(TaskReduceErrorCode::EpochMismatch));
    }
    Ok(())
}

fn transition_status(
    state: &mut TaskSnapshot,
    from: TaskStatus,
    to: TaskStatus,
) -> Result<(), TaskReduceError> {
    if state.status != from || !legal_status_edge(from, to) {
        return Err(error(TaskReduceErrorCode::IllegalStatusTransition));
    }
    state.status = to;
    Ok(())
}

const fn legal_status_edge(from: TaskStatus, to: TaskStatus) -> bool {
    matches!(
        (from, to),
        (
            TaskStatus::Queued,
            TaskStatus::Active | TaskStatus::Cancelling | TaskStatus::Failed
        ) | (
            TaskStatus::Active,
            TaskStatus::Checkpointing
                | TaskStatus::Paused
                | TaskStatus::Blocked
                | TaskStatus::Cancelling
                | TaskStatus::Completing
                | TaskStatus::Failed
        ) | (
            TaskStatus::Checkpointing,
            TaskStatus::Active
                | TaskStatus::Paused
                | TaskStatus::Blocked
                | TaskStatus::Cancelling
                | TaskStatus::Failed
        ) | (
            TaskStatus::Paused,
            TaskStatus::Active | TaskStatus::Blocked | TaskStatus::Cancelling | TaskStatus::Failed
        ) | (
            TaskStatus::Blocked,
            TaskStatus::Active | TaskStatus::Cancelling | TaskStatus::Failed
        ) | (
            TaskStatus::Cancelling,
            TaskStatus::Cancelled | TaskStatus::Failed
        ) | (
            TaskStatus::Completing,
            TaskStatus::Completed | TaskStatus::Active | TaskStatus::Failed
        )
    )
}

const fn legal_operation_edge(from: OperationStatus, to: OperationStatus) -> bool {
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

const fn error(code: TaskReduceErrorCode) -> TaskReduceError {
    TaskReduceError::from_code(code)
}
