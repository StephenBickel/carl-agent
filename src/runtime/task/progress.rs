use std::collections::BTreeSet;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{CanonicalCheckpoint, ClauseStatus, EpochReport, ReportError, ReportErrorCode};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RecoveryStrategy {
    ReconstructFromEvidence,
    ReplaceApproach,
    FreshContextDiagnosis,
    MinimizeReproduction,
    DeclareBlocked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressAssessment {
    pub fingerprint: String,
    pub new_information: bool,
    pub resolved_clause_ids: Vec<String>,
    pub stall_count: u8,
    pub recovery: Option<RecoveryStrategy>,
}

/// Computes a deterministic assessment using only checkpoint-owned evidence and report control data.
pub fn assess_progress(
    checkpoint: &CanonicalCheckpoint,
    report: &EpochReport,
    history: &[ProgressAssessment],
) -> Result<ProgressAssessment, ReportError> {
    let next_objective = report
        .next_objective
        .as_deref()
        .unwrap_or(checkpoint.next_objective.as_str());
    if next_objective.trim().is_empty() {
        return Err(ReportError::new(ReportErrorCode::InvalidReport));
    }
    let resolved_clause_ids = checkpoint
        .contract
        .clauses
        .iter()
        .filter(|clause| clause.status == ClauseStatus::Satisfied && !clause.evidence.is_empty())
        .map(|clause| clause.id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let fingerprint = fingerprint(checkpoint, &resolved_clause_ids, next_objective)?;
    let new_information = !history
        .iter()
        .any(|assessment| assessment.fingerprint == fingerprint);
    let stall_count = if new_information {
        0
    } else {
        history
            .iter()
            .rev()
            .take_while(|assessment| assessment.fingerprint == fingerprint)
            .filter(|assessment| assessment.recovery.is_some())
            .count()
            .saturating_add(1)
            .min(u8::MAX as usize) as u8
    };
    let recovery = (!new_information).then(|| select_recovery(checkpoint, &fingerprint, history));
    Ok(ProgressAssessment {
        fingerprint,
        new_information,
        resolved_clause_ids,
        stall_count,
        recovery,
    })
}

fn select_recovery(
    checkpoint: &CanonicalCheckpoint,
    fingerprint: &str,
    history: &[ProgressAssessment],
) -> RecoveryStrategy {
    if checkpoint
        .blockers
        .iter()
        .any(|blocker| blocker == "missing_authority")
    {
        return RecoveryStrategy::DeclareBlocked;
    }
    let failed = history
        .iter()
        .filter(|assessment| assessment.fingerprint == fingerprint)
        .filter_map(|assessment| assessment.recovery)
        .collect::<BTreeSet<_>>();
    if failed.len() >= 3 {
        return RecoveryStrategy::DeclareBlocked;
    }
    if failed.len() == 2 {
        return if checkpoint.provider.context_id.is_some() {
            RecoveryStrategy::FreshContextDiagnosis
        } else {
            RecoveryStrategy::MinimizeReproduction
        };
    }
    [
        RecoveryStrategy::ReconstructFromEvidence,
        RecoveryStrategy::ReplaceApproach,
        RecoveryStrategy::FreshContextDiagnosis,
        RecoveryStrategy::MinimizeReproduction,
    ]
    .into_iter()
    .find(|strategy| !failed.contains(strategy))
    .unwrap_or(RecoveryStrategy::DeclareBlocked)
}

fn fingerprint(
    checkpoint: &CanonicalCheckpoint,
    resolved_clause_ids: &[String],
    next_objective: &str,
) -> Result<String, ReportError> {
    #[derive(Serialize)]
    struct Fingerprint<'a> {
        changed_file_digests: Vec<&'a String>,
        verification_outcomes: Vec<(&'a String, ClauseStatus, usize)>,
        failure_signatures: Vec<String>,
        resolved_clause_ids: &'a [String],
        decision_ids: Vec<&'a String>,
        next_objective: &'a str,
    }

    let changed_file_digests = checkpoint
        .repository
        .file_hashes
        .values()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut verification_outcomes = checkpoint
        .contract
        .clauses
        .iter()
        .map(|clause| (&clause.id, clause.status, clause.evidence.len()))
        .collect::<Vec<_>>();
    verification_outcomes.sort_by(|left, right| left.0.cmp(right.0));
    let failure_signatures = checkpoint
        .blockers
        .iter()
        .cloned()
        .chain(checkpoint.uncertain_delivery_digests.iter().cloned())
        .chain(
            checkpoint
                .operations
                .iter()
                .filter(|operation| {
                    matches!(
                        operation.status,
                        super::OperationStatus::Failed | super::OperationStatus::Uncertain
                    )
                })
                .map(|operation| {
                    format!(
                        "operation:{}:{:?}",
                        operation.request_digest, operation.status
                    )
                }),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let decision_ids = checkpoint
        .decisions
        .iter()
        .map(|decision| &decision.id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let encoded = serde_json::to_vec(&Fingerprint {
        changed_file_digests,
        verification_outcomes,
        failure_signatures,
        resolved_clause_ids,
        decision_ids,
        next_objective,
    })
    .map_err(|_| ReportError::new(ReportErrorCode::InvalidReport))?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}
