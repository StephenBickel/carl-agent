use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::events::{Event, EventEnvelope};
use crate::runtime::task::{
    CanonicalCheckpoint, EffectClass, EpochId, NormalizedOperationEvidence, OperationId,
    OperationStatus, ProviderRequestPurpose, TaskEvent, TaskStatus,
};

use super::{EvaluationError, EvaluationMetrics, EvaluationResult};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct EvaluationObservations {
    pub restarts: u32,
    pub duplicate_effects: u32,
    pub out_of_scope_changes: u32,
    pub orphan_processes: u32,
    pub secret_policy_violations: u32,
}

#[derive(Serialize)]
struct NormalizedReplay<'a> {
    status: TaskStatus,
    clauses: Vec<(&'a str, crate::runtime::task::ClauseStatus)>,
    operations: Vec<NormalizedOperation<'a>>,
    exact_identifiers: Vec<&'a str>,
    manifest: &'a BTreeMap<String, String>,
}

#[derive(Serialize)]
struct NormalizedOperation<'a> {
    request_digest: &'a str,
    effect_class: EffectClass,
    outcome: &'static str,
    evidence: &'a NormalizedOperationEvidence,
}

struct DurableOperation {
    epoch_id: EpochId,
    effect_class: EffectClass,
    request_digest: String,
    outcome: Option<OperationStatus>,
    evidence: Option<NormalizedOperationEvidence>,
}

pub(super) fn derive_metrics(
    expected_identifiers: &[String],
    events: &[EventEnvelope],
    checkpoint: &CanonicalCheckpoint,
    status: TaskStatus,
    manifest: &BTreeMap<String, String>,
    observations: EvaluationObservations,
) -> Result<EvaluationMetrics, EvaluationError> {
    let mut operations = BTreeMap::<OperationId, DurableOperation>::new();
    let mut operation_order = Vec::new();
    let mut provider_request_events = Vec::new();
    let mut compactions = 0_u32;
    let mut provider_losses = 0_u32;
    let mut recovery_changes = 0_u32;

    for envelope in events {
        let Event::TaskLifecycle { event, .. } = &envelope.event else {
            return Err(EvaluationError::Storage);
        };
        match event {
            TaskEvent::ProviderRequestRecorded {
                epoch_id, purpose, ..
            } => provider_request_events.push((*epoch_id, *purpose)),
            TaskEvent::OperationIntentRecorded {
                operation_id,
                epoch_id,
                effect_class,
                request_digest,
                ..
            } => {
                if operations
                    .insert(
                        *operation_id,
                        DurableOperation {
                            epoch_id: *epoch_id,
                            effect_class: *effect_class,
                            request_digest: request_digest.clone(),
                            outcome: None,
                            evidence: None,
                        },
                    )
                    .is_some()
                {
                    return Err(EvaluationError::Storage);
                }
                operation_order.push(*operation_id);
            }
            TaskEvent::OperationTransitioned {
                operation_id, to, ..
            } if to.is_resolved() || *to == OperationStatus::Uncertain => {
                operations
                    .get_mut(operation_id)
                    .ok_or(EvaluationError::Storage)?
                    .outcome = Some(*to);
            }
            TaskEvent::NormalizedOperationEvidenceRecorded {
                operation_id,
                evidence,
            } => {
                let operation = operations
                    .get_mut(operation_id)
                    .ok_or(EvaluationError::Storage)?;
                if operation.evidence.replace(evidence.clone()).is_some() {
                    return Err(EvaluationError::Storage);
                }
            }
            TaskEvent::CompactionCompleted { .. } => {
                compactions = compactions
                    .checked_add(1)
                    .ok_or(EvaluationError::Invariant)?;
            }
            TaskEvent::ProviderContextLost { .. } => {
                provider_losses = provider_losses
                    .checked_add(1)
                    .ok_or(EvaluationError::Invariant)?;
            }
            TaskEvent::RecoveryAttemptStarted { .. } => {
                recovery_changes = recovery_changes
                    .checked_add(1)
                    .ok_or(EvaluationError::Invariant)?;
            }
            _ => {}
        }
    }

    let normalized_operations = operation_order
        .iter()
        .filter_map(|operation_id| {
            let operation = operations.get(operation_id)?;
            Some(NormalizedOperation {
                request_digest: operation.request_digest.as_str(),
                effect_class: operation.effect_class,
                outcome: semantic_outcome(operation.outcome?),
                evidence: operation.evidence.as_ref()?,
            })
        })
        .collect::<Vec<_>>();
    let successful_request_digests = normalized_operations
        .iter()
        .filter(|operation| operation.outcome == "applied")
        .map(|operation| operation.request_digest)
        .collect::<Vec<_>>();
    let unique_request_digests = successful_request_digests
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let semantic_duplicates = successful_request_digests
        .len()
        .saturating_sub(unique_request_digests.len());
    let semantic_duplicates =
        u32::try_from(semantic_duplicates).map_err(|_| EvaluationError::Invariant)?;

    let mut exact_identifiers = checkpoint
        .exact_identifiers
        .iter()
        .map(|identifier| identifier.value.as_str())
        .collect::<Vec<_>>();
    exact_identifiers.sort_unstable();
    exact_identifiers.dedup();
    let lost_identifiers = expected_identifiers
        .iter()
        .filter(|expected| !exact_identifiers.contains(&expected.as_str()))
        .count();
    let lost_identifiers =
        u32::try_from(lost_identifiers).map_err(|_| EvaluationError::Invariant)?;

    let clauses = checkpoint
        .contract
        .clauses
        .iter()
        .map(|clause| (clause.id.as_str(), clause.status))
        .collect::<Vec<_>>();
    let required_clauses_passed = checkpoint
        .contract
        .clauses
        .iter()
        .filter(|clause| {
            clause.required
                && clause.status == crate::runtime::task::ClauseStatus::Satisfied
                && !clause.evidence.is_empty()
        })
        .count();
    let required_clauses_passed =
        u32::try_from(required_clauses_passed).map_err(|_| EvaluationError::Invariant)?;

    let normalized = NormalizedReplay {
        status,
        clauses,
        operations: normalized_operations,
        exact_identifiers,
        manifest,
    };
    let tool_bearing_epochs = operations
        .values()
        .filter(|operation| operation.evidence.is_some())
        .map(|operation| operation.epoch_id)
        .collect::<BTreeSet<_>>();
    let provider_requests =
        u32::try_from(provider_request_events.len()).map_err(|_| EvaluationError::Invariant)?;
    let work_epochs = provider_request_events
        .iter()
        .filter(|(epoch_id, purpose)| {
            matches!(
                purpose,
                ProviderRequestPurpose::Work | ProviderRequestPurpose::Recovery
            ) && tool_bearing_epochs.contains(epoch_id)
        })
        .count();
    let work_epochs = u32::try_from(work_epochs).map_err(|_| EvaluationError::Invariant)?;
    let replay_bytes = serde_json::to_vec(&normalized).map_err(|_| EvaluationError::Invariant)?;
    let replay_digest = format!("{:x}", Sha256::digest(replay_bytes));
    let tool_calls = u32::try_from(operations.len()).map_err(|_| EvaluationError::Invariant)?;

    Ok(EvaluationMetrics {
        completed: status == TaskStatus::Completed,
        work_epochs,
        provider_requests,
        tool_calls,
        required_clauses_passed,
        duplicate_effects: semantic_duplicates.saturating_add(observations.duplicate_effects),
        lost_identifiers,
        out_of_scope_changes: observations.out_of_scope_changes,
        restarts: observations.restarts,
        compactions,
        strategy_changes: provider_losses.max(recovery_changes),
        orphan_processes: u32::try_from(checkpoint.running_processes.len())
            .map_err(|_| EvaluationError::Invariant)?
            .saturating_add(observations.orphan_processes),
        secret_policy_violations: observations.secret_policy_violations,
        replay_digest,
    })
}

const fn semantic_outcome(status: OperationStatus) -> &'static str {
    match status {
        OperationStatus::Succeeded | OperationStatus::Reconciled => "applied",
        OperationStatus::Failed => "failed",
        OperationStatus::Cancelled => "cancelled",
        OperationStatus::Uncertain => "uncertain",
        OperationStatus::IntentRecorded | OperationStatus::Started => "unresolved",
    }
}

#[must_use]
pub fn evaluate_release_gate(
    scenario: &str,
    expected_work_epochs: u32,
    expected_required_clauses: u32,
    metrics: EvaluationMetrics,
) -> EvaluationResult {
    let mut failure_codes = Vec::new();
    if !metrics.completed {
        failure_codes.push("incomplete".to_owned());
    }
    if metrics.work_epochs != expected_work_epochs {
        failure_codes.push("work_epoch_mismatch".to_owned());
    }
    if metrics.required_clauses_passed != expected_required_clauses {
        failure_codes.push("required_clause_failure".to_owned());
    }
    if metrics.duplicate_effects != 0 {
        failure_codes.push("duplicate_effects".to_owned());
    }
    if metrics.lost_identifiers != 0 {
        failure_codes.push("lost_identifiers".to_owned());
    }
    if metrics.orphan_processes != 0 {
        failure_codes.push("orphan_processes".to_owned());
    }
    if metrics.out_of_scope_changes != 0 {
        failure_codes.push("out_of_scope_changes".to_owned());
    }
    if metrics.secret_policy_violations != 0 {
        failure_codes.push("secret_policy_violations".to_owned());
    }
    if metrics.replay_digest.len() != 64
        || !metrics
            .replay_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        failure_codes.push("invalid_replay_digest".to_owned());
    }
    EvaluationResult {
        scenario: scenario.to_owned(),
        passed: failure_codes.is_empty(),
        metrics,
        failure_codes,
    }
}
