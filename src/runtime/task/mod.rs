mod checkpoint;
mod context;
mod engine;
mod metrics;
mod progress;
mod reducer;
mod report;
mod types;

pub use checkpoint::{
    CanonicalCheckpoint, CheckpointBuildInput, CheckpointError, ClauseEvidence, DecisionRecord,
    ExactIdentifier, OperationCheckpoint, ProcessCheckpoint, ProviderCheckpoint,
    RepositoryCheckpoint, WorkEvidence,
};
#[cfg(test)]
pub(crate) use checkpoint::{
    canonical_checkpoint_serializations, reset_canonical_checkpoint_serializations,
};
pub use context::{
    CompactionDecision, ContextBudget, ContextEngine, ContextError, ContextInput, ContextLedger,
    ContextLedgerEntry, ContextPackage, ContextSourceKind, ContextTrust, ContextUnit,
};
pub use engine::{
    EngineToolKind, EngineToolStatus, StartTask, TaskEngine, TaskEngineError, TaskEngineErrorCode,
    TaskEngineUpdate,
};
pub(crate) use engine::{
    OwnerConfigureSession, OwnerStartTask, OwnerTrustedAdmission, OwnerTrustedMessage,
    TaskEngineAcknowledgement, TaskEngineControl, TaskEngineFrontendContext,
    TaskEnginePermissionNotice,
};
pub(crate) use metrics::TaskMetricsReducer;
pub use metrics::{
    TASK_METRICS_SCHEMA_VERSION, TaskMetrics, TaskMetricsError, TaskMetricsErrorCode,
    derive_task_metrics,
};
pub use progress::{
    ProgressAssessment, RecoveryAttempt, RecoveryAttemptOutcome, RecoveryStrategy, assess_progress,
    assess_progress_with_recovery_attempts, recovery_attempt_fingerprint,
};
pub use reducer::{TaskReduceError, TaskReduceErrorCode, reduce_task};
pub use report::{
    CompletionDecision, EpochDisposition, EpochReport, OperationEvidence, ReportError,
    ReportErrorCode, ReportedClauseEvidence, decide_completion, parse_epoch_report,
};
pub(crate) use types::OperationEvidenceState;
pub use types::{
    CheckpointId, ClauseStatus, CompletionClause, CompletionContract, ContextPackageId,
    EffectClass, EpochId, EpochInterruptReason, EvidenceRef, FilePostcondition,
    FilePostconditionEntry, NormalizedOperationEvidence, OperationId, OperationStatus,
    ProviderRequestPurpose, TaskBudget, TaskControlKind, TaskEvent, TaskId, TaskSnapshot,
    TaskStatus, TaskValidationError, TaskValidationErrorCode, classify_effect,
};
