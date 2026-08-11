use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{CanonicalCheckpoint, OperationId, OperationStatus};

const REPORT_OPEN: &str = "<carl-epoch-report>";
const REPORT_CLOSE: &str = "</carl-epoch-report>";
const REPORT_LIKE: &str = "carl-epoch-report";
const MAX_REPORT_BYTES: usize = 64 * 1024;
const MAX_REPORT_TEXT_BYTES: usize = 16 * 1024;
const MAX_REPORT_CLAUSES: usize = 64;
const MAX_REPORT_IDENTIFIERS: usize = 128;
const MAX_REPORT_OPERATION_IDS: usize = 256;
const MAX_REPORT_EVIDENCE_VALUES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochDisposition {
    Continue,
    Complete,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedClauseEvidence {
    pub clause_id: String,
    pub operation_ids: Vec<OperationId>,
    pub event_sequences: Vec<u64>,
    pub artifact_digests: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EpochReport {
    pub schema_version: u16,
    pub disposition: EpochDisposition,
    pub summary: String,
    pub next_objective: Option<String>,
    pub clause_evidence: Vec<ReportedClauseEvidence>,
    pub exact_identifiers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompletionDecision {
    Continue { next_objective: String },
    Complete,
    Blocked { reason: String },
}

/// A normalized terminal operation result.  It is deliberately independent of provider prose.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationEvidence {
    Command {
        operation_id: OperationId,
        completed: bool,
        exit_code: Option<i32>,
    },
    FileChange {
        operation_id: OperationId,
        completed: bool,
        artifact_digests: Vec<String>,
    },
}

impl OperationEvidence {
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        match self {
            Self::Command { operation_id, .. } | Self::FileChange { operation_id, .. } => {
                *operation_id
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReportErrorCode {
    #[error("epoch report is invalid")]
    InvalidReport,
    #[error("epoch report references an unknown completion clause")]
    UnknownClause,
    #[error("epoch report references an unknown operation")]
    UnknownOperation,
    #[error("epoch report does not provide sufficient Carl-owned evidence")]
    InsufficientEvidence,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{code}")]
pub struct ReportError {
    code: ReportErrorCode,
}

impl ReportError {
    pub(super) const fn new(code: ReportErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(&self) -> ReportErrorCode {
        self.code
    }
}

/// Extracts the one terminal report block from an epoch transcript.
pub fn parse_epoch_report(output: &str) -> Result<EpochReport, ReportError> {
    if output.len() > MAX_REPORT_BYTES {
        return Err(invalid_report());
    }
    let Some(start) = output.find(REPORT_OPEN) else {
        return Err(invalid_report());
    };
    let body_start = start + REPORT_OPEN.len();
    let Some(relative_end) = output[body_start..].find(REPORT_CLOSE) else {
        return Err(invalid_report());
    };
    let end = body_start + relative_end;
    let suffix = &output[end + REPORT_CLOSE.len()..];
    let prefix = &output[..start];
    if prefix.contains(REPORT_LIKE)
        || suffix.contains(REPORT_LIKE)
        || !suffix.trim().is_empty()
        || output[body_start..end].contains(REPORT_OPEN)
        || output[body_start..end].contains(REPORT_CLOSE)
    {
        return Err(invalid_report());
    }

    let report = serde_json::from_str::<EpochReport>(&output[body_start..end])
        .map_err(|_| invalid_report())?;
    validate_report(&report)?;
    Ok(report)
}

/// Converts a claimed report disposition into a Carl-owned completion decision.
pub fn decide_completion(
    report: &EpochReport,
    checkpoint: &CanonicalCheckpoint,
    operation_evidence: &[OperationEvidence],
) -> Result<CompletionDecision, ReportError> {
    validate_report(report)?;
    let claims = validate_claims(report, checkpoint, operation_evidence)?;
    match report.disposition {
        EpochDisposition::Continue => Ok(CompletionDecision::Continue {
            next_objective: report.next_objective.clone().ok_or_else(invalid_report)?,
        }),
        EpochDisposition::Blocked => Ok(CompletionDecision::Blocked {
            reason: report.summary.clone(),
        }),
        EpochDisposition::Complete => {
            let required = checkpoint
                .contract
                .clauses
                .iter()
                .filter(|clause| clause.required)
                .map(|clause| clause.id.as_str())
                .collect::<BTreeSet<_>>();
            if required.iter().all(|clause_id| claims.contains(*clause_id)) {
                Ok(CompletionDecision::Complete)
            } else {
                Err(ReportError::new(ReportErrorCode::InsufficientEvidence))
            }
        }
    }
}

fn validate_claims(
    report: &EpochReport,
    checkpoint: &CanonicalCheckpoint,
    operation_evidence: &[OperationEvidence],
) -> Result<BTreeSet<String>, ReportError> {
    let clauses = checkpoint
        .contract
        .clauses
        .iter()
        .map(|clause| (clause.id.as_str(), clause))
        .collect::<HashMap<_, _>>();
    let operations = checkpoint
        .operations
        .iter()
        .map(|operation| (operation.operation_id, operation))
        .collect::<HashMap<_, _>>();
    let mut evidence = HashMap::new();
    for item in operation_evidence {
        if evidence.insert(item.operation_id(), item).is_some() {
            return Err(invalid_report());
        }
    }
    let artifacts = canonical_artifacts(checkpoint);
    let mut claimed = BTreeSet::new();

    for claim in &report.clause_evidence {
        if !clauses.contains_key(claim.clause_id.as_str()) {
            return Err(ReportError::new(ReportErrorCode::UnknownClause));
        }
        if !claimed.insert(claim.clause_id.clone()) || claim.operation_ids.is_empty() {
            return Err(invalid_report());
        }
        if claim
            .artifact_digests
            .iter()
            .any(|digest| !artifacts.contains(digest))
        {
            return Err(ReportError::new(ReportErrorCode::InsufficientEvidence));
        }
        let mut operation_ids = BTreeSet::new();
        for operation_id in &claim.operation_ids {
            if !operation_ids.insert(*operation_id) {
                return Err(invalid_report());
            }
            let operation = operations
                .get(operation_id)
                .ok_or_else(|| ReportError::new(ReportErrorCode::UnknownOperation))?;
            let normalized = evidence
                .get(operation_id)
                .ok_or_else(|| ReportError::new(ReportErrorCode::InsufficientEvidence))?;
            if operation.status != OperationStatus::Succeeded
                || !claim
                    .event_sequences
                    .iter()
                    .all(|sequence| operation.evidence_sequences.contains(sequence))
                || !valid_normalized_evidence(normalized, &claim.artifact_digests, &artifacts)
            {
                return Err(ReportError::new(ReportErrorCode::InsufficientEvidence));
            }
        }
    }
    Ok(claimed)
}

fn canonical_artifacts(checkpoint: &CanonicalCheckpoint) -> BTreeSet<String> {
    checkpoint
        .completed_work
        .iter()
        .flat_map(|work| work.artifact_digests.iter().cloned())
        .chain(checkpoint.repository.diff_artifact_digest.iter().cloned())
        .chain(checkpoint.repository.file_hashes.values().cloned())
        .collect()
}

fn valid_normalized_evidence(
    evidence: &OperationEvidence,
    claimed_artifacts: &[String],
    canonical_artifacts: &BTreeSet<String>,
) -> bool {
    match evidence {
        OperationEvidence::Command {
            completed,
            exit_code,
            ..
        } => *completed && *exit_code == Some(0),
        OperationEvidence::FileChange {
            completed,
            artifact_digests,
            ..
        } => {
            *completed
                && artifact_digests.iter().any(|digest| {
                    canonical_artifacts.contains(digest)
                        && (claimed_artifacts.is_empty() || claimed_artifacts.contains(digest))
                })
        }
    }
}

fn validate_report(report: &EpochReport) -> Result<(), ReportError> {
    if report.schema_version != 1
        || report.summary.trim().is_empty()
        || invalid_text(&report.summary)
        || report.clause_evidence.len() > MAX_REPORT_CLAUSES
        || report.exact_identifiers.len() > MAX_REPORT_IDENTIFIERS
        || report
            .exact_identifiers
            .iter()
            .any(|value| invalid_text(value))
    {
        return Err(invalid_report());
    }
    match (&report.disposition, &report.next_objective) {
        (EpochDisposition::Continue, Some(next))
            if !next.trim().is_empty() && !invalid_text(next) => {}
        (EpochDisposition::Continue, _) => return Err(invalid_report()),
        (_, Some(next)) if invalid_text(next) => return Err(invalid_report()),
        _ => {}
    }
    for evidence in &report.clause_evidence {
        if evidence.clause_id.trim().is_empty()
            || invalid_text(&evidence.clause_id)
            || evidence.operation_ids.len() > MAX_REPORT_OPERATION_IDS
            || evidence.event_sequences.len() > MAX_REPORT_EVIDENCE_VALUES
            || evidence.artifact_digests.len() > MAX_REPORT_EVIDENCE_VALUES
            || evidence.event_sequences.contains(&0)
            || evidence
                .artifact_digests
                .iter()
                .any(|digest| !is_digest(digest))
        {
            return Err(invalid_report());
        }
    }
    Ok(())
}

fn invalid_text(value: &str) -> bool {
    value.len() > MAX_REPORT_TEXT_BYTES || value.chars().any(char::is_control)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

const fn invalid_report() -> ReportError {
    ReportError::new(ReportErrorCode::InvalidReport)
}
