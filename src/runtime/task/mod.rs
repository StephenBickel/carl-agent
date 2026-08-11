mod checkpoint;
mod context;
mod engine;
mod progress;
mod reducer;
mod report;
mod types;

pub use checkpoint::{
    CanonicalCheckpoint, CheckpointBuildInput, CheckpointError, ClauseEvidence, DecisionRecord,
    ExactIdentifier, OperationCheckpoint, ProcessCheckpoint, ProviderCheckpoint,
    RepositoryCheckpoint, WorkEvidence,
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
    TaskEngineAcknowledgement, TaskEngineControl, TaskEngineFrontendContext,
    TaskEnginePermissionNotice,
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
    EffectClass, EpochId, EvidenceRef, NormalizedOperationEvidence, OperationId, OperationStatus,
    ProviderRequestPurpose, TaskBudget, TaskEvent, TaskId, TaskSnapshot, TaskStatus,
    TaskValidationError, TaskValidationErrorCode, classify_effect,
};
