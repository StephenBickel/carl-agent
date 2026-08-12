use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::events::{Event, EventEnvelope};
use crate::security::{SecretFilter, SecretRule};

use super::types::{
    CheckpointId, CompletionContract, EffectClass, EvidenceRef, OperationEvidenceError,
    OperationEvidenceState, OperationId, OperationStatus, TaskEvent, TaskId, TaskSnapshot,
};

const CHECKPOINT_SCHEMA_VERSION: u16 = 1;
const MAX_CHECKPOINT_BYTES: usize = 8 * 1024 * 1024;
const MAX_NARRATIVE_BYTES: usize = 64 * 1024;
const MAX_FIELD_BYTES: usize = 1024 * 1024;

#[cfg(test)]
std::thread_local! {
    static CANONICAL_CHECKPOINT_SERIALIZATIONS: std::cell::Cell<u64> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_canonical_checkpoint_serializations() {
    CANONICAL_CHECKPOINT_SERIALIZATIONS.set(0);
}

#[cfg(test)]
pub(crate) fn canonical_checkpoint_serializations() -> u64 {
    CANONICAL_CHECKPOINT_SERIALIZATIONS.get()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CanonicalCheckpoint {
    pub schema_version: u16,
    pub checkpoint_id: CheckpointId,
    pub task_id: TaskId,
    pub contract: CompletionContract,
    pub completed_work: Vec<WorkEvidence>,
    pub decisions: Vec<DecisionRecord>,
    pub exact_identifiers: Vec<ExactIdentifier>,
    pub operations: Vec<OperationCheckpoint>,
    pub repository: RepositoryCheckpoint,
    pub running_processes: Vec<ProcessCheckpoint>,
    pub pending_approval_digests: Vec<String>,
    pub pending_steering_digests: Vec<String>,
    pub uncertain_delivery_digests: Vec<String>,
    pub verification: Vec<ClauseEvidence>,
    pub next_objective: String,
    pub blockers: Vec<String>,
    pub provider: ProviderCheckpoint,
    pub compaction_generation: u32,
    pub source_sequence_start: u64,
    pub source_sequence_end: u64,
    pub previous_digest: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CheckpointBuildInput {
    pub checkpoint_id: CheckpointId,
    pub snapshot: TaskSnapshot,
    pub events: Vec<EventEnvelope>,
    pub completed_work: Vec<WorkEvidence>,
    pub decisions: Vec<DecisionRecord>,
    pub exact_identifiers: Vec<ExactIdentifier>,
    pub required_identifiers: Vec<ExactIdentifier>,
    pub repository: RepositoryCheckpoint,
    pub running_processes: Vec<ProcessCheckpoint>,
    pub pending_approval_digests: Vec<String>,
    pub pending_steering_digests: Vec<String>,
    pub uncertain_delivery_digests: Vec<String>,
    pub next_objective: String,
    pub blockers: Vec<String>,
    pub provider: ProviderCheckpoint,
    pub compaction_generation: u32,
    pub previous_checkpoint: Option<CanonicalCheckpoint>,
    pub artifact_contents: BTreeMap<String, Vec<u8>>,
    pub model_narrative: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WorkEvidence {
    pub summary: String,
    pub event_sequences: Vec<u64>,
    pub artifact_digests: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DecisionRecord {
    pub id: String,
    pub decision: String,
    pub rationale: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ExactIdentifier {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperationCheckpoint {
    pub operation_id: OperationId,
    pub status: OperationStatus,
    pub effect_class: EffectClass,
    pub request_digest: String,
    pub evidence_sequences: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RepositoryCheckpoint {
    pub workspace_digest: String,
    pub git_head: Option<String>,
    pub git_status_digest: Option<String>,
    pub diff_artifact_digest: Option<String>,
    pub file_hashes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ProcessCheckpoint {
    pub process_id: String,
    pub item_id: String,
    pub command_digest: String,
    pub cwd_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderCheckpoint {
    pub provider: String,
    pub model: String,
    pub effort: String,
    pub context_id: Option<String>,
    pub observed_total_tokens: Option<u64>,
    pub observed_context_window: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClauseEvidence {
    pub clause_id: String,
    pub evidence: Vec<EvidenceRef>,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CheckpointError {
    #[error("a required exact identifier is missing")]
    MissingRequiredIdentifier,
    #[error("an operation transition has no durable intent")]
    DanglingOperation,
    #[error("an operation request/result lifecycle is unpaired")]
    UnpairedOperation,
    #[error("an operation identifier is duplicated")]
    DuplicateOperation,
    #[error("evidence refers outside the checkpoint source range")]
    InvalidEvidenceRange,
    #[error("an artifact digest is invalid")]
    InvalidArtifactDigest,
    #[error("referenced artifact content is missing")]
    ArtifactMissing,
    #[error("artifact content does not match its digest")]
    ArtifactDigestMismatch,
    #[error("artifact content is not UTF-8")]
    NonUtf8Artifact,
    #[error("secret material is not allowed in a checkpoint")]
    SecretRejected,
    #[error("checkpoint source events are invalid")]
    InvalidSource,
    #[error("checkpoint source sequence metadata is invalid")]
    InvalidSourceSequence,
    #[error("checkpoint generation does not follow its predecessor")]
    InvalidGeneration,
    #[error("checkpoint content exceeds its bound")]
    LimitExceeded,
    #[error("checkpoint serialization failed")]
    Serialization,
}

impl CanonicalCheckpoint {
    pub fn build(mut input: CheckpointBuildInput) -> Result<Self, CheckpointError> {
        input
            .snapshot
            .contract
            .validate()
            .map_err(|_| CheckpointError::InvalidSource)?;
        validate_narrative(input.model_narrative.as_deref())?;
        input.events.sort_by_key(|event| event.sequence);
        validate_event_order(
            &input.events,
            &input.snapshot,
            input.previous_checkpoint.as_ref(),
        )?;

        let previous_digest = input
            .previous_checkpoint
            .as_ref()
            .map(Self::digest)
            .transpose()?;
        validate_generation(
            input.compaction_generation,
            input.previous_checkpoint.as_ref(),
        )?;
        let (source_sequence_start, source_sequence_end) =
            source_range(input.previous_checkpoint.as_ref(), &input.events)?;

        let mut completed_work = input
            .previous_checkpoint
            .as_ref()
            .map_or_else(Vec::new, |checkpoint| checkpoint.completed_work.clone());
        completed_work.append(&mut input.completed_work);
        normalize_work(&mut completed_work);

        let decisions = merge_decisions(input.previous_checkpoint.as_ref(), input.decisions)?;
        let exact_identifiers =
            merge_identifiers(input.previous_checkpoint.as_ref(), input.exact_identifiers);
        require_identifiers(&exact_identifiers, &input.required_identifiers)?;
        let operations = build_operations(
            input.previous_checkpoint.as_ref(),
            &input.events,
            source_sequence_start,
            source_sequence_end,
        )?;
        for operation in &operations {
            if input.snapshot.operation_status(operation.operation_id) != Some(operation.status) {
                return Err(CheckpointError::InvalidSource);
            }
        }
        validate_provider_metadata(
            &input.provider,
            &input.snapshot,
            input.previous_checkpoint.as_ref(),
            &input.events,
        )?;

        let mut running_processes = input.running_processes;
        running_processes.sort();
        running_processes.dedup();
        normalize_strings(&mut input.pending_approval_digests);
        normalize_strings(&mut input.pending_steering_digests);
        normalize_strings(&mut input.uncertain_delivery_digests);
        normalize_strings(&mut input.blockers);
        let verification = verification_from_contract(&input.snapshot.contract);

        let checkpoint = Self {
            schema_version: CHECKPOINT_SCHEMA_VERSION,
            checkpoint_id: input.checkpoint_id,
            task_id: input.snapshot.task_id,
            contract: input.snapshot.contract,
            completed_work,
            decisions,
            exact_identifiers,
            operations,
            repository: input.repository,
            running_processes,
            pending_approval_digests: input.pending_approval_digests,
            pending_steering_digests: input.pending_steering_digests,
            uncertain_delivery_digests: input.uncertain_delivery_digests,
            verification,
            next_objective: input.next_objective,
            blockers: input.blockers,
            provider: input.provider,
            compaction_generation: input.compaction_generation,
            source_sequence_start,
            source_sequence_end,
            previous_digest,
        };
        checkpoint.validate_structure()?;
        validate_artifact_contents(&checkpoint, &input.artifact_contents)?;
        Ok(checkpoint)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CheckpointError> {
        #[cfg(test)]
        CANONICAL_CHECKPOINT_SERIALIZATIONS
            .set(CANONICAL_CHECKPOINT_SERIALIZATIONS.get().saturating_add(1));
        let mut canonical = self.clone();
        canonical.normalize();
        canonical.validate_structure()?;
        let bytes = serde_json::to_vec(&canonical).map_err(|_| CheckpointError::Serialization)?;
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(CheckpointError::LimitExceeded);
        }
        SecretFilter
            .inspect(&bytes)
            .map_err(|_| CheckpointError::SecretRejected)?;
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<String, CheckpointError> {
        Ok(format!("{:x}", Sha256::digest(self.canonical_bytes()?)))
    }

    pub fn artifact_digests(&self) -> BTreeSet<String> {
        let mut digests = BTreeSet::new();
        for work in &self.completed_work {
            digests.extend(work.artifact_digests.iter().cloned());
        }
        if let Some(digest) = &self.repository.diff_artifact_digest {
            digests.insert(digest.clone());
        }
        for clause in &self.verification {
            for evidence in &clause.evidence {
                if let Some(digest) = &evidence.artifact_digest {
                    digests.insert(digest.clone());
                }
            }
        }
        digests
    }

    fn validate_structure(&self) -> Result<(), CheckpointError> {
        if self.schema_version != CHECKPOINT_SCHEMA_VERSION
            || self.source_sequence_start == 0
            || self.source_sequence_start > self.source_sequence_end
            || self.next_objective.trim().is_empty()
        {
            return Err(CheckpointError::InvalidSource);
        }
        self.contract
            .validate()
            .map_err(|_| CheckpointError::InvalidSource)?;
        for work in &self.completed_work {
            validate_text(&work.summary)?;
            validate_evidence_sequences(
                &work.event_sequences,
                self.source_sequence_start,
                self.source_sequence_end,
            )?;
        }
        for decision in &self.decisions {
            validate_nonempty(&decision.id)?;
            validate_nonempty(&decision.decision)?;
            validate_nonempty(&decision.rationale)?;
        }
        for identifier in &self.exact_identifiers {
            validate_nonempty(&identifier.kind)?;
            validate_nonempty(&identifier.value)?;
        }
        let mut operation_ids = BTreeSet::new();
        for operation in &self.operations {
            if !operation_ids.insert(operation.operation_id) {
                return Err(CheckpointError::DuplicateOperation);
            }
            validate_digest(&operation.request_digest)?;
            if !operation.status.is_resolved() {
                return Err(CheckpointError::UnpairedOperation);
            }
            if operation.evidence_sequences.is_empty()
                || operation.evidence_sequences.first() == Some(&0)
                || operation
                    .evidence_sequences
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(CheckpointError::InvalidEvidenceRange);
            }
            validate_evidence_sequences(
                &operation.evidence_sequences,
                self.source_sequence_start,
                self.source_sequence_end,
            )?;
        }
        validate_digest(&self.repository.workspace_digest)?;
        if let Some(digest) = &self.repository.git_status_digest {
            validate_digest(digest)?;
        }
        if let Some(digest) = &self.repository.diff_artifact_digest {
            validate_digest(digest)?;
        }
        for (path, digest) in &self.repository.file_hashes {
            validate_nonempty(path)?;
            validate_digest(digest)?;
        }
        for process in &self.running_processes {
            validate_nonempty(&process.process_id)?;
            validate_nonempty(&process.item_id)?;
            validate_digest(&process.command_digest)?;
            validate_digest(&process.cwd_digest)?;
        }
        for value in self
            .pending_approval_digests
            .iter()
            .chain(&self.pending_steering_digests)
            .chain(&self.uncertain_delivery_digests)
        {
            validate_digest(value)?;
        }
        for blocker in &self.blockers {
            validate_nonempty(blocker)?;
        }
        validate_nonempty(&self.next_objective)?;
        validate_nonempty(&self.provider.provider)?;
        validate_nonempty(&self.provider.model)?;
        validate_nonempty(&self.provider.effort)?;
        if let Some(context_id) = &self.provider.context_id {
            validate_nonempty(context_id)?;
        }
        if self
            .provider
            .observed_context_window
            .is_some_and(|window| window == 0)
        {
            return Err(CheckpointError::InvalidSource);
        }
        for clause in &self.verification {
            validate_nonempty(&clause.clause_id)?;
            for evidence in &clause.evidence {
                validate_evidence_sequences(
                    &[evidence.event_sequence],
                    self.source_sequence_start,
                    self.source_sequence_end,
                )?;
            }
        }
        if self.verification != verification_from_contract(&self.contract) {
            return Err(CheckpointError::InvalidSource);
        }
        if let Some(digest) = &self.previous_digest {
            validate_digest(digest)?;
        }
        for digest in self.artifact_digests() {
            validate_digest(&digest)?;
        }
        Ok(())
    }

    fn normalize(&mut self) {
        normalize_work(&mut self.completed_work);
        self.decisions.sort();
        self.decisions.dedup();
        self.exact_identifiers.sort();
        self.exact_identifiers.dedup();
        self.operations
            .sort_by_key(|operation| operation.operation_id);
        self.running_processes.sort();
        self.running_processes.dedup();
        normalize_strings(&mut self.pending_approval_digests);
        normalize_strings(&mut self.pending_steering_digests);
        normalize_strings(&mut self.uncertain_delivery_digests);
        normalize_strings(&mut self.blockers);
        for clause in &mut self.verification {
            clause.evidence.sort_by_key(|item| {
                (
                    item.event_sequence,
                    item.artifact_digest.clone(),
                    item.operation_id,
                )
            });
            clause.evidence.dedup();
        }
        self.verification
            .sort_by(|left, right| left.clause_id.cmp(&right.clause_id));
    }
}

fn validate_narrative(narrative: Option<&str>) -> Result<(), CheckpointError> {
    let Some(narrative) = narrative else {
        return Ok(());
    };
    if narrative.len() > MAX_NARRATIVE_BYTES {
        return Err(CheckpointError::LimitExceeded);
    }
    validate_text(narrative)?;
    SecretFilter
        .inspect(narrative.as_bytes())
        .map_err(|_| CheckpointError::SecretRejected)
}

fn validate_event_order(
    events: &[EventEnvelope],
    snapshot: &TaskSnapshot,
    previous: Option<&CanonicalCheckpoint>,
) -> Result<(), CheckpointError> {
    let mut prior = None;
    for envelope in events {
        if envelope.sequence == 0 || prior == Some(envelope.sequence) {
            return Err(CheckpointError::InvalidSourceSequence);
        }
        if previous.is_some_and(|checkpoint| envelope.sequence <= checkpoint.source_sequence_end) {
            return Err(CheckpointError::InvalidSourceSequence);
        }
        prior = Some(envelope.sequence);
        match &envelope.event {
            Event::TaskLifecycle { task_id, .. }
                if *task_id == snapshot.task_id && envelope.session_id == snapshot.session_id => {}
            _ => return Err(CheckpointError::InvalidSource),
        }
    }
    Ok(())
}

fn validate_generation(
    generation: u32,
    previous: Option<&CanonicalCheckpoint>,
) -> Result<(), CheckpointError> {
    match previous {
        None if generation == 0 => Ok(()),
        Some(previous)
            if previous
                .compaction_generation
                .checked_add(1)
                .is_some_and(|next| next == generation) =>
        {
            Ok(())
        }
        _ => Err(CheckpointError::InvalidGeneration),
    }
}

fn source_range(
    previous: Option<&CanonicalCheckpoint>,
    events: &[EventEnvelope],
) -> Result<(u64, u64), CheckpointError> {
    let start = previous
        .map(|checkpoint| checkpoint.source_sequence_start)
        .or_else(|| events.first().map(|event| event.sequence))
        .ok_or(CheckpointError::InvalidSourceSequence)?;
    let end = events
        .last()
        .map(|event| event.sequence)
        .or_else(|| previous.map(|checkpoint| checkpoint.source_sequence_end))
        .ok_or(CheckpointError::InvalidSourceSequence)?;
    (start <= end)
        .then_some((start, end))
        .ok_or(CheckpointError::InvalidSourceSequence)
}

fn merge_decisions(
    previous: Option<&CanonicalCheckpoint>,
    decisions: Vec<DecisionRecord>,
) -> Result<Vec<DecisionRecord>, CheckpointError> {
    let mut by_id = BTreeMap::new();
    if let Some(previous) = previous {
        for decision in &previous.decisions {
            by_id.insert(decision.id.clone(), decision.clone());
        }
    }
    for decision in decisions {
        if let Some(existing) = by_id.get(&decision.id)
            && existing != &decision
        {
            return Err(CheckpointError::InvalidSource);
        }
        by_id.insert(decision.id.clone(), decision);
    }
    Ok(by_id.into_values().collect())
}

fn merge_identifiers(
    previous: Option<&CanonicalCheckpoint>,
    identifiers: Vec<ExactIdentifier>,
) -> Vec<ExactIdentifier> {
    previous
        .into_iter()
        .flat_map(|checkpoint| checkpoint.exact_identifiers.iter().cloned())
        .chain(identifiers)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn require_identifiers(
    identifiers: &[ExactIdentifier],
    required: &[ExactIdentifier],
) -> Result<(), CheckpointError> {
    let identifiers = identifiers.iter().collect::<BTreeSet<_>>();
    if required
        .iter()
        .all(|identifier| identifiers.contains(identifier))
    {
        Ok(())
    } else {
        Err(CheckpointError::MissingRequiredIdentifier)
    }
}

fn build_operations(
    previous: Option<&CanonicalCheckpoint>,
    events: &[EventEnvelope],
    source_sequence_start: u64,
    source_sequence_end: u64,
) -> Result<Vec<OperationCheckpoint>, CheckpointError> {
    let mut operations = previous.map_or_else(BTreeMap::new, |checkpoint| {
        checkpoint
            .operations
            .iter()
            .cloned()
            .map(|operation| {
                (
                    operation.operation_id,
                    OperationBuildState {
                        last_transition_sequence: checkpoint.source_sequence_end,
                        evidence: OperationEvidenceState::from_consumed(
                            operation.evidence_sequences.clone(),
                        ),
                        checkpoint: operation,
                    },
                )
            })
            .collect()
    });
    for envelope in events {
        let Event::TaskLifecycle { event, .. } = &envelope.event else {
            return Err(CheckpointError::InvalidSource);
        };
        match event {
            TaskEvent::OperationIntentRecorded {
                operation_id,
                effect_class,
                request_digest,
                ..
            } => {
                if operations
                    .insert(
                        *operation_id,
                        OperationBuildState {
                            checkpoint: OperationCheckpoint {
                                operation_id: *operation_id,
                                status: OperationStatus::IntentRecorded,
                                effect_class: *effect_class,
                                request_digest: request_digest.clone(),
                                evidence_sequences: Vec::new(),
                            },
                            last_transition_sequence: envelope.sequence,
                            evidence: OperationEvidenceState::default(),
                        },
                    )
                    .is_some()
                {
                    return Err(CheckpointError::DuplicateOperation);
                }
            }
            TaskEvent::OperationTransitioned {
                operation_id,
                from,
                to,
                evidence_sequences,
            } => {
                let operation = operations
                    .get_mut(operation_id)
                    .ok_or(CheckpointError::DanglingOperation)?;
                if evidence_sequences.iter().any(|sequence| {
                    *sequence < source_sequence_start
                        || *sequence > source_sequence_end
                        || *sequence >= envelope.sequence
                }) {
                    return Err(CheckpointError::InvalidEvidenceRange);
                }
                operation
                    .evidence
                    .transition(
                        operation.checkpoint.status,
                        *from,
                        *to,
                        operation.last_transition_sequence,
                        envelope.sequence,
                        evidence_sequences,
                    )
                    .map_err(checkpoint_operation_evidence_error)?;
                operation.checkpoint.status = *to;
                operation.last_transition_sequence = envelope.sequence;
                operation.checkpoint.evidence_sequences =
                    operation.evidence.consumed_sequences().to_vec();
            }
            TaskEvent::OperationEvidenceRecorded {
                operation_id,
                result_digest,
            } => {
                validate_digest(result_digest)?;
                let operation = operations
                    .get_mut(operation_id)
                    .ok_or(CheckpointError::DanglingOperation)?;
                operation
                    .evidence
                    .record(
                        operation.checkpoint.status,
                        operation.last_transition_sequence,
                        envelope.sequence,
                    )
                    .map_err(checkpoint_operation_evidence_error)?;
            }
            _ => {}
        }
    }
    if operations
        .values()
        .any(|operation| !operation.checkpoint.status.is_resolved())
    {
        return Err(CheckpointError::UnpairedOperation);
    }
    Ok(operations
        .into_values()
        .map(|operation| operation.checkpoint)
        .collect())
}

struct OperationBuildState {
    checkpoint: OperationCheckpoint,
    last_transition_sequence: u64,
    evidence: OperationEvidenceState,
}

const fn checkpoint_operation_evidence_error(error: OperationEvidenceError) -> CheckpointError {
    match error {
        OperationEvidenceError::IllegalTransition | OperationEvidenceError::Missing => {
            CheckpointError::UnpairedOperation
        }
        OperationEvidenceError::Invalid => CheckpointError::InvalidEvidenceRange,
    }
}

fn verification_from_contract(contract: &CompletionContract) -> Vec<ClauseEvidence> {
    let mut verification = contract
        .clauses
        .iter()
        .map(|clause| {
            let mut evidence = clause.evidence.clone();
            evidence.sort_by_key(|item| {
                (
                    item.event_sequence,
                    item.artifact_digest.clone(),
                    item.operation_id,
                )
            });
            evidence.dedup();
            ClauseEvidence {
                clause_id: clause.id.clone(),
                evidence,
            }
        })
        .collect::<Vec<_>>();
    verification.sort_by(|left, right| left.clause_id.cmp(&right.clause_id));
    verification
}

fn validate_provider_metadata(
    provider: &ProviderCheckpoint,
    snapshot: &TaskSnapshot,
    previous: Option<&CanonicalCheckpoint>,
    events: &[EventEnvelope],
) -> Result<(), CheckpointError> {
    let mut expected_model = previous.map(|checkpoint| checkpoint.provider.model.clone());
    let mut expected_effort = previous.map(|checkpoint| checkpoint.provider.effort.clone());
    let mut expected_total_tokens =
        previous.and_then(|checkpoint| checkpoint.provider.observed_total_tokens);
    let mut expected_context_window =
        previous.and_then(|checkpoint| checkpoint.provider.observed_context_window);
    if previous.is_some_and(|checkpoint| checkpoint.provider.provider != provider.provider) {
        return Err(CheckpointError::InvalidSource);
    }
    for envelope in events {
        let Event::TaskLifecycle { event, .. } = &envelope.event else {
            return Err(CheckpointError::InvalidSource);
        };
        match event {
            TaskEvent::Created { model, effort, .. } => {
                expected_model = Some(model.as_str().to_owned());
                expected_effort = Some(effort.as_codex_value().to_owned());
            }
            TaskEvent::UsageObserved {
                total_tokens,
                context_window,
                ..
            } => {
                expected_total_tokens = Some(*total_tokens);
                if context_window.is_some() {
                    expected_context_window = *context_window;
                }
            }
            _ => {}
        }
    }
    if expected_model.as_deref() != Some(provider.model.as_str())
        || expected_effort.as_deref() != Some(provider.effort.as_str())
        || expected_total_tokens != provider.observed_total_tokens
        || expected_context_window != provider.observed_context_window
        || snapshot.provider_context != provider.context_id
    {
        return Err(CheckpointError::InvalidSource);
    }
    Ok(())
}

fn normalize_work(work: &mut Vec<WorkEvidence>) {
    for item in &mut *work {
        item.event_sequences.sort_unstable();
        item.event_sequences.dedup();
        normalize_strings(&mut item.artifact_digests);
    }
    work.sort();
    work.dedup();
}

fn normalize_strings(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn validate_artifact_contents(
    checkpoint: &CanonicalCheckpoint,
    contents: &BTreeMap<String, Vec<u8>>,
) -> Result<(), CheckpointError> {
    for digest in checkpoint.artifact_digests() {
        validate_digest(&digest)?;
        let bytes = contents
            .get(&digest)
            .ok_or(CheckpointError::ArtifactMissing)?;
        if format!("{:x}", Sha256::digest(bytes)) != digest {
            return Err(CheckpointError::ArtifactDigestMismatch);
        }
        match SecretFilter.inspect(bytes) {
            Ok(()) => {}
            Err(finding) if finding.rule() == SecretRule::NonUtf8 => {
                return Err(CheckpointError::NonUtf8Artifact);
            }
            Err(_) => return Err(CheckpointError::SecretRejected),
        }
    }
    Ok(())
}

fn validate_evidence_sequences(
    sequences: &[u64],
    start: u64,
    end: u64,
) -> Result<(), CheckpointError> {
    if sequences
        .iter()
        .any(|sequence| *sequence < start || *sequence > end)
    {
        Err(CheckpointError::InvalidEvidenceRange)
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str) -> Result<(), CheckpointError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(CheckpointError::InvalidArtifactDigest)
    }
}

fn validate_nonempty(value: &str) -> Result<(), CheckpointError> {
    if value.trim().is_empty() {
        Err(CheckpointError::InvalidSource)
    } else {
        validate_text(value)
    }
}

fn validate_text(value: &str) -> Result<(), CheckpointError> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(CheckpointError::LimitExceeded);
    }
    if value.chars().any(|character| {
        character == '\0' || (character.is_control() && !"\n\r\t".contains(character))
    }) {
        return Err(CheckpointError::InvalidSource);
    }
    Ok(())
}
