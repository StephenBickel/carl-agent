mod checkpoint;
mod context;
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
pub use progress::{ProgressAssessment, RecoveryStrategy, assess_progress};
pub use reducer::{TaskReduceError, TaskReduceErrorCode, reduce_task};
pub use report::{
    CompletionDecision, EpochDisposition, EpochReport, OperationEvidence, ReportError,
    ReportErrorCode, ReportedClauseEvidence, decide_completion, parse_epoch_report,
};
pub(crate) use types::OperationEvidenceState;
pub use types::{
    CheckpointId, ClauseStatus, CompletionClause, CompletionContract, ContextPackageId,
    EffectClass, EpochId, EvidenceRef, OperationId, OperationStatus, TaskBudget, TaskEvent, TaskId,
    TaskSnapshot, TaskStatus, TaskValidationError, TaskValidationErrorCode, classify_effect,
};
