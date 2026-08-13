use std::collections::BTreeMap;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::events::{Event, EventEnvelope};

use super::{
    ClauseStatus, OperationId, OperationStatus, TaskBudget, TaskEvent, TaskId, TaskSnapshot,
    TaskStatus, reduce_task,
};

pub const TASK_METRICS_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskMetrics {
    #[serde(deserialize_with = "deserialize_schema_version")]
    pub schema_version: u16,
    pub task_id: TaskId,
    pub status: TaskStatus,
    pub revision: u64,
    pub durable_event_count: u64,
    pub durable_sequence_end: u64,
    pub provider_requests: u64,
    pub epochs_started: u64,
    pub epochs_completed: u64,
    pub operation_intents: u64,
    pub operations_succeeded: u64,
    pub operations_failed: u64,
    pub operations_cancelled: u64,
    pub operations_uncertain: u64,
    pub unresolved_operations: u64,
    pub compactions_completed: u64,
    pub provider_context_losses: u64,
    pub recovery_attempts: u64,
    pub latest_observed_tokens: Option<u64>,
    pub latest_context_window: Option<u64>,
    pub required_clauses_total: u32,
    pub required_clauses_satisfied: u32,
    pub budget: TaskBudget,
}

fn deserialize_schema_version<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u16::deserialize(deserializer)?;
    if version != TASK_METRICS_SCHEMA_VERSION {
        return Err(D::Error::custom("unsupported task metrics schema version"));
    }
    Ok(version)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskMetricsErrorCode {
    #[error("task metrics storage failed")]
    Storage,
    #[error("task metrics history is invalid")]
    InvalidHistory,
    #[error("task metrics arithmetic overflowed")]
    ArithmeticOverflow,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{code}")]
pub struct TaskMetricsError {
    code: TaskMetricsErrorCode,
}

impl TaskMetricsError {
    #[must_use]
    pub const fn code(&self) -> TaskMetricsErrorCode {
        self.code
    }

    const fn from_code(code: TaskMetricsErrorCode) -> Self {
        Self { code }
    }
}

#[derive(Clone, Copy)]
struct OperationMetricState {
    status: OperationStatus,
    terminal_classified: bool,
}

pub(crate) struct TaskMetricsReducer {
    task_id: TaskId,
    replayed: Option<TaskSnapshot>,
    last_sequence: Option<u64>,
    durable_event_count: u64,
    provider_requests: u64,
    epochs_started: u64,
    epochs_completed: u64,
    operation_intents: u64,
    terminal_classifications: u64,
    operations_succeeded: u64,
    operations_failed: u64,
    operations_cancelled: u64,
    operations_uncertain: u64,
    compactions_completed: u64,
    provider_context_losses: u64,
    recovery_attempts: u64,
    latest_observed_tokens: Option<u64>,
    latest_context_window: Option<u64>,
    operations: BTreeMap<OperationId, OperationMetricState>,
}

impl TaskMetricsReducer {
    pub(crate) fn new(task_id: TaskId) -> Self {
        Self {
            task_id,
            replayed: None,
            last_sequence: None,
            durable_event_count: 0,
            provider_requests: 0,
            epochs_started: 0,
            epochs_completed: 0,
            operation_intents: 0,
            terminal_classifications: 0,
            operations_succeeded: 0,
            operations_failed: 0,
            operations_cancelled: 0,
            operations_uncertain: 0,
            compactions_completed: 0,
            provider_context_losses: 0,
            recovery_attempts: 0,
            latest_observed_tokens: None,
            latest_context_window: None,
            operations: BTreeMap::new(),
        }
    }

    pub(crate) fn push(&mut self, envelope: &EventEnvelope) -> Result<(), TaskMetricsError> {
        if envelope.sequence == 0
            || self
                .last_sequence
                .is_some_and(|previous| envelope.sequence <= previous)
        {
            return Err(metrics_error(TaskMetricsErrorCode::InvalidHistory));
        }
        let Event::TaskLifecycle { task_id, event } = &envelope.event else {
            return Err(metrics_error(TaskMetricsErrorCode::InvalidHistory));
        };
        if *task_id != self.task_id {
            return Err(metrics_error(TaskMetricsErrorCode::InvalidHistory));
        }

        let replayed = reduce_task(self.replayed.take(), envelope)
            .map_err(|_| metrics_error(TaskMetricsErrorCode::InvalidHistory))?;
        self.count_event(event)?;
        self.replayed = Some(replayed);
        self.last_sequence = Some(envelope.sequence);
        self.durable_event_count = checked_add(self.durable_event_count, 1)?;
        Ok(())
    }

    pub(crate) fn finish(
        self,
        authoritative: &TaskSnapshot,
    ) -> Result<TaskMetrics, TaskMetricsError> {
        let replayed = self
            .replayed
            .ok_or_else(|| metrics_error(TaskMetricsErrorCode::InvalidHistory))?;
        if replayed != *authoritative || authoritative.task_id != self.task_id {
            return Err(metrics_error(TaskMetricsErrorCode::InvalidHistory));
        }
        let unresolved_operations = self
            .operation_intents
            .checked_sub(self.terminal_classifications)
            .ok_or_else(|| metrics_error(TaskMetricsErrorCode::InvalidHistory))?;
        let authoritative_unresolved = u64::try_from(authoritative.unresolved_operation_count())
            .map_err(|_| metrics_error(TaskMetricsErrorCode::ArithmeticOverflow))?;
        if unresolved_operations != authoritative_unresolved {
            return Err(metrics_error(TaskMetricsErrorCode::InvalidHistory));
        }
        let required_clauses_total = u32::try_from(
            authoritative
                .contract
                .clauses
                .iter()
                .filter(|clause| clause.required)
                .count(),
        )
        .map_err(|_| metrics_error(TaskMetricsErrorCode::ArithmeticOverflow))?;
        let required_clauses_satisfied = u32::try_from(
            authoritative
                .contract
                .clauses
                .iter()
                .filter(|clause| clause.required && clause.status == ClauseStatus::Satisfied)
                .count(),
        )
        .map_err(|_| metrics_error(TaskMetricsErrorCode::ArithmeticOverflow))?;
        Ok(TaskMetrics {
            schema_version: TASK_METRICS_SCHEMA_VERSION,
            task_id: self.task_id,
            status: authoritative.status,
            revision: authoritative.revision,
            durable_event_count: self.durable_event_count,
            durable_sequence_end: self
                .last_sequence
                .ok_or_else(|| metrics_error(TaskMetricsErrorCode::InvalidHistory))?,
            provider_requests: self.provider_requests,
            epochs_started: self.epochs_started,
            epochs_completed: self.epochs_completed,
            operation_intents: self.operation_intents,
            operations_succeeded: self.operations_succeeded,
            operations_failed: self.operations_failed,
            operations_cancelled: self.operations_cancelled,
            operations_uncertain: self.operations_uncertain,
            unresolved_operations,
            compactions_completed: self.compactions_completed,
            provider_context_losses: self.provider_context_losses,
            recovery_attempts: self.recovery_attempts,
            latest_observed_tokens: self.latest_observed_tokens,
            latest_context_window: self.latest_context_window,
            required_clauses_total,
            required_clauses_satisfied,
            budget: authoritative.budget,
        })
    }

    fn count_event(&mut self, event: &TaskEvent) -> Result<(), TaskMetricsError> {
        match event {
            TaskEvent::ProviderRequestRecorded { .. } => {
                self.provider_requests = checked_add(self.provider_requests, 1)?;
            }
            TaskEvent::EpochStarted { .. } => {
                self.epochs_started = checked_add(self.epochs_started, 1)?;
            }
            TaskEvent::EpochFinished { .. } => {
                self.epochs_completed = checked_add(self.epochs_completed, 1)?;
            }
            TaskEvent::OperationIntentRecorded { operation_id, .. } => {
                if self
                    .operations
                    .insert(
                        *operation_id,
                        OperationMetricState {
                            status: OperationStatus::IntentRecorded,
                            terminal_classified: false,
                        },
                    )
                    .is_some()
                {
                    return Err(metrics_error(TaskMetricsErrorCode::InvalidHistory));
                }
                self.operation_intents = checked_add(self.operation_intents, 1)?;
            }
            TaskEvent::OperationTransitioned {
                operation_id,
                from,
                to,
                ..
            } => self.count_operation_transition(*operation_id, *from, *to)?,
            TaskEvent::UsageObserved {
                total_tokens,
                context_window,
                ..
            } => {
                self.latest_observed_tokens = Some(*total_tokens);
                self.latest_context_window = *context_window;
            }
            TaskEvent::CompactionCompleted { .. } => {
                self.compactions_completed = checked_add(self.compactions_completed, 1)?;
            }
            TaskEvent::ProviderContextLost { .. } => {
                self.provider_context_losses = checked_add(self.provider_context_losses, 1)?;
            }
            TaskEvent::RecoveryAttemptStarted { .. } => {
                self.recovery_attempts = checked_add(self.recovery_attempts, 1)?;
            }
            TaskEvent::Created { .. }
            | TaskEvent::StateTransitioned { .. }
            | TaskEvent::ContractRevised { .. }
            | TaskEvent::EpochInterrupted { .. }
            | TaskEvent::ConfigurationQueued { .. }
            | TaskEvent::ConfigurationApplied { .. }
            | TaskEvent::ControlRequested { .. }
            | TaskEvent::ProviderEpochBound { .. }
            | TaskEvent::OperationPostconditionBound { .. }
            | TaskEvent::OperationFilePostconditionBound { .. }
            | TaskEvent::OperationEvidenceRecorded { .. }
            | TaskEvent::NormalizedOperationEvidenceRecorded { .. }
            | TaskEvent::ProgressAssessed { .. }
            | TaskEvent::RecoveryAttemptRecorded { .. }
            | TaskEvent::CheckpointCommitted { .. }
            | TaskEvent::CompactionRequested { .. }
            | TaskEvent::ProviderContextBound { .. }
            | TaskEvent::SteeringQueued { .. }
            | TaskEvent::BackgroundProcessTerminationRecorded { .. }
            | TaskEvent::CancellationRequested
            | TaskEvent::Blocked { .. }
            | TaskEvent::Completed => {}
        }
        Ok(())
    }

    fn count_operation_transition(
        &mut self,
        operation_id: OperationId,
        from: OperationStatus,
        to: OperationStatus,
    ) -> Result<(), TaskMetricsError> {
        let state = self
            .operations
            .get_mut(&operation_id)
            .ok_or_else(|| metrics_error(TaskMetricsErrorCode::InvalidHistory))?;
        if state.status != from {
            return Err(metrics_error(TaskMetricsErrorCode::InvalidHistory));
        }
        match to {
            OperationStatus::Succeeded => {
                classify_once(state)?;
                self.operations_succeeded = checked_add(self.operations_succeeded, 1)?;
                self.terminal_classifications = checked_add(self.terminal_classifications, 1)?;
            }
            OperationStatus::Failed => {
                classify_once(state)?;
                self.operations_failed = checked_add(self.operations_failed, 1)?;
                self.terminal_classifications = checked_add(self.terminal_classifications, 1)?;
            }
            OperationStatus::Cancelled => {
                classify_once(state)?;
                self.operations_cancelled = checked_add(self.operations_cancelled, 1)?;
                self.terminal_classifications = checked_add(self.terminal_classifications, 1)?;
            }
            OperationStatus::Uncertain => {
                if state.terminal_classified {
                    return Err(metrics_error(TaskMetricsErrorCode::InvalidHistory));
                }
                self.operations_uncertain = checked_add(self.operations_uncertain, 1)?;
            }
            OperationStatus::Reconciled => {
                classify_once(state)?;
                self.terminal_classifications = checked_add(self.terminal_classifications, 1)?;
            }
            OperationStatus::IntentRecorded | OperationStatus::Started => {}
        }
        state.status = to;
        Ok(())
    }
}

pub fn derive_task_metrics<'a>(
    task_id: TaskId,
    envelopes: impl IntoIterator<Item = &'a EventEnvelope>,
    authoritative: &TaskSnapshot,
) -> Result<TaskMetrics, TaskMetricsError> {
    let mut reducer = TaskMetricsReducer::new(task_id);
    for envelope in envelopes {
        reducer.push(envelope)?;
    }
    reducer.finish(authoritative)
}

fn classify_once(state: &mut OperationMetricState) -> Result<(), TaskMetricsError> {
    if state.terminal_classified {
        return Err(metrics_error(TaskMetricsErrorCode::InvalidHistory));
    }
    state.terminal_classified = true;
    Ok(())
}

fn checked_add(left: u64, right: u64) -> Result<u64, TaskMetricsError> {
    left.checked_add(right)
        .ok_or_else(|| metrics_error(TaskMetricsErrorCode::ArithmeticOverflow))
}

const fn metrics_error(code: TaskMetricsErrorCode) -> TaskMetricsError {
    TaskMetricsError::from_code(code)
}

#[cfg(test)]
mod tests {
    use super::{TaskMetricsErrorCode, checked_add};

    #[test]
    fn counter_overflow_has_a_typed_redacted_error() {
        let error = checked_add(u64::MAX, 1).expect_err("overflow must fail closed");
        assert_eq!(error.code(), TaskMetricsErrorCode::ArithmeticOverflow);
        assert_eq!(
            format!("{error:?}"),
            "TaskMetricsError { code: ArithmeticOverflow }"
        );
    }
}
