use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{CanonicalCheckpoint, ClauseStatus, EpochReport, ReportError, ReportErrorCode};

const MAX_RECOVERY_ATTEMPTS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStrategy {
    ReconstructFromEvidence,
    ReplaceApproach,
    FreshContextDiagnosis,
    MinimizeReproduction,
    DeclareBlocked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAttemptOutcome {
    Succeeded,
    Failed,
}

/// A durable, terminal result for one Carl-selected recovery strategy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecoveryAttempt {
    pub strategy: RecoveryStrategy,
    pub strategy_fingerprint: String,
    pub outcome: RecoveryAttemptOutcome,
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
    assess_progress_with_recovery_attempts(checkpoint, report, history, &[])
}

/// Computes progress with bounded durable outcomes for strategies Carl actually attempted.
pub fn assess_progress_with_recovery_attempts(
    checkpoint: &CanonicalCheckpoint,
    report: &EpochReport,
    history: &[ProgressAssessment],
    recovery_attempts: &[RecoveryAttempt],
) -> Result<ProgressAssessment, ReportError> {
    validate_recovery_attempts(recovery_attempts)?;
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
            .count()
            .min(u8::MAX as usize) as u8
    };
    let recovery = (has_missing_authority(checkpoint) || !new_information)
        .then(|| select_recovery(checkpoint, &fingerprint, recovery_attempts));
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
    recovery_attempts: &[RecoveryAttempt],
) -> RecoveryStrategy {
    if has_missing_authority(checkpoint) {
        return RecoveryStrategy::DeclareBlocked;
    }
    let failed = recovery_attempts
        .iter()
        .filter(|attempt| attempt.outcome == RecoveryAttemptOutcome::Failed)
        .filter(|attempt| {
            attempt.strategy != RecoveryStrategy::DeclareBlocked
                && attempt.strategy_fingerprint
                    == recovery_attempt_fingerprint(fingerprint, attempt.strategy)
        })
        .map(|attempt| attempt.strategy)
        .collect::<BTreeSet<_>>();
    if failed.len() >= 3 {
        return RecoveryStrategy::DeclareBlocked;
    }
    [
        RecoveryStrategy::ReconstructFromEvidence,
        RecoveryStrategy::ReplaceApproach,
        RecoveryStrategy::MinimizeReproduction,
        RecoveryStrategy::FreshContextDiagnosis,
    ]
    .into_iter()
    .find(|strategy| !failed.contains(strategy))
    .unwrap_or(RecoveryStrategy::DeclareBlocked)
}

/// Derives the strategy-specific identity that binds an attempted recovery to a stalled state.
#[must_use]
pub fn recovery_attempt_fingerprint(
    progress_fingerprint: &str,
    strategy: RecoveryStrategy,
) -> String {
    #[derive(Serialize)]
    struct RecoveryFingerprint<'a> {
        progress_fingerprint: &'a str,
        strategy: RecoveryStrategy,
    }
    let encoded = serde_json::to_vec(&RecoveryFingerprint {
        progress_fingerprint,
        strategy,
    })
    .expect("a fixed recovery fingerprint serialization cannot fail");
    format!("{:x}", Sha256::digest(encoded))
}

fn has_missing_authority(checkpoint: &CanonicalCheckpoint) -> bool {
    checkpoint
        .blockers
        .iter()
        .any(|blocker| blocker == "missing_authority")
}

fn validate_recovery_attempts(attempts: &[RecoveryAttempt]) -> Result<(), ReportError> {
    if attempts.len() > MAX_RECOVERY_ATTEMPTS
        || attempts.iter().any(|attempt| {
            attempt.strategy == RecoveryStrategy::DeclareBlocked
                || !is_fingerprint(&attempt.strategy_fingerprint)
        })
    {
        return Err(ReportError::new(ReportErrorCode::InvalidProgressInput));
    }
    Ok(())
}

fn fingerprint(
    checkpoint: &CanonicalCheckpoint,
    resolved_clause_ids: &[String],
    next_objective: &str,
) -> Result<String, ReportError> {
    #[derive(Serialize)]
    struct VerificationOutcome<'a> {
        clause_id: &'a str,
        status: Option<ClauseStatus>,
        evidence: Vec<(u64, Option<&'a String>, Option<super::OperationId>)>,
    }

    #[derive(Serialize)]
    struct Fingerprint<'a> {
        changed_files: Vec<(&'a String, &'a String)>,
        verification_outcomes: Vec<VerificationOutcome<'a>>,
        failure_signatures: Vec<String>,
        resolved_clause_ids: &'a [String],
        decision_ids: Vec<&'a String>,
        next_objective: &'a str,
    }

    let changed_files = checkpoint.repository.file_hashes.iter().collect();
    let statuses = checkpoint
        .contract
        .clauses
        .iter()
        .map(|clause| (clause.id.as_str(), clause.status))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut verification_outcomes = checkpoint
        .verification
        .iter()
        .map(|outcome| {
            let mut evidence = outcome
                .evidence
                .iter()
                .map(|item| {
                    (
                        item.event_sequence,
                        item.artifact_digest.as_ref(),
                        item.operation_id,
                    )
                })
                .collect::<Vec<_>>();
            evidence.sort();
            VerificationOutcome {
                clause_id: &outcome.clause_id,
                status: statuses.get(outcome.clause_id.as_str()).copied(),
                evidence,
            }
        })
        .collect::<Vec<_>>();
    verification_outcomes.sort_by(|left, right| {
        left.clause_id
            .cmp(right.clause_id)
            .then_with(|| left.evidence.cmp(&right.evidence))
    });
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
        changed_files,
        verification_outcomes,
        failure_signatures,
        resolved_clause_ids,
        decision_ids,
        next_objective,
    })
    .map_err(|_| ReportError::new(ReportErrorCode::InvalidReport))?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn is_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
