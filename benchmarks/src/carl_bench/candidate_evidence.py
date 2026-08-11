"""Paired benchmark and independent review evidence for sealed candidates."""

from __future__ import annotations

import hashlib
from typing import Any

from carl_bench.artifacts import PrivateArtifactStore
from carl_bench.candidate import (
    PairedEvidence,
    ReviewAttestation,
    ReviewPacket,
    SealedCandidate,
)
from carl_bench.canonical import canonical_json_bytes
from carl_bench.experiment import (
    ExperimentManifest,
    ExperimentProjection,
    ExperimentState,
    ReviewRole,
)
from carl_bench.models import (
    FailureClass,
    OutcomeStatus,
    RunManifest,
    Scorecard,
    TrackScorecard,
    TrialResult,
)
from carl_bench.report import compare_runs
from carl_bench.run_attestation import RunAttestationError, verify_attested_scorecard


class CandidateEvidenceError(ValueError):
    """A stable evidence failure that does not expose raw reports or benchmark content."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _exact_keys(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise CandidateEvidenceError("scorecard_keys_invalid")


def _trial_from_public(value: Any) -> TrialResult:
    if not isinstance(value, dict):
        raise CandidateEvidenceError("scorecard_trial_invalid")
    required = {
        "adapter_id",
        "adapter_version",
        "attempt",
        "elapsed_ms",
        "seed",
        "status",
        "task_digest",
        "task_id",
        "track",
        "trial_id",
    }
    optional = {"failure_class", "failure_code", "checks_passed", "checks_total", "tool_calls"}
    if not required <= set(value) or set(value) - required - optional:
        raise CandidateEvidenceError("scorecard_trial_keys_invalid")
    try:
        return TrialResult(
            trial_id=value["trial_id"],
            task_id=value["task_id"],
            task_digest=value["task_digest"],
            adapter_id=value["adapter_id"],
            adapter_version=value["adapter_version"],
            attempt=value["attempt"],
            seed=value["seed"],
            status=OutcomeStatus(value["status"]),
            elapsed_ms=value["elapsed_ms"],
            failure_class=(
                FailureClass(value["failure_class"]) if "failure_class" in value else None
            ),
            failure_code=value.get("failure_code"),
            checks_passed=value.get("checks_passed"),
            checks_total=value.get("checks_total"),
            tool_calls=value.get("tool_calls"),
            track=value["track"],
        )
    except (TypeError, ValueError) as error:
        raise CandidateEvidenceError("scorecard_trial_invalid") from error


def _track_from_public(value: Any) -> TrackScorecard:
    if not isinstance(value, dict):
        raise CandidateEvidenceError("scorecard_track_invalid")
    _exact_keys(
        value,
        {
            "failed_trials",
            "invalid_trials",
            "pass_rate",
            "passed_trials",
            "track",
            "valid_trials",
        },
    )
    try:
        return TrackScorecard(**value)
    except (TypeError, ValueError) as error:
        raise CandidateEvidenceError("scorecard_track_invalid") from error


def scorecard_from_public(value: Any) -> Scorecard:
    if not isinstance(value, dict):
        raise CandidateEvidenceError("scorecard_invalid")
    _exact_keys(
        value,
        {
            "effort",
            "failed_trials",
            "failure_counts",
            "invalid_trials",
            "league",
            "median_elapsed_ms",
            "median_tool_calls",
            "model",
            "pass_rate",
            "passed_trials",
            "run_digest",
            "run_id",
            "schema_version",
            "subject_commit",
            "tracks",
            "trials",
            "valid_trials",
        },
    )
    failures = value["failure_counts"]
    trials = value["trials"]
    tracks = value["tracks"]
    if (
        not isinstance(failures, list)
        or not isinstance(trials, list)
        or not isinstance(tracks, list)
    ):
        raise CandidateEvidenceError("scorecard_collections_invalid")
    failure_counts: list[tuple[str, int]] = []
    for failure in failures:
        if not isinstance(failure, dict):
            raise CandidateEvidenceError("scorecard_failure_count_invalid")
        _exact_keys(failure, {"code", "count"})
        failure_counts.append((failure["code"], failure["count"]))
    try:
        return Scorecard(
            schema_version=value["schema_version"],
            run_id=value["run_id"],
            run_digest=value["run_digest"],
            subject_commit=value["subject_commit"],
            valid_trials=value["valid_trials"],
            invalid_trials=value["invalid_trials"],
            passed_trials=value["passed_trials"],
            failed_trials=value["failed_trials"],
            pass_rate=value["pass_rate"],
            median_elapsed_ms=value["median_elapsed_ms"],
            median_tool_calls=value["median_tool_calls"],
            failure_counts=tuple(failure_counts),
            tracks=tuple(_track_from_public(track) for track in tracks),
            league=value["league"],
            model=value["model"],
            effort=value["effort"],
            trials=tuple(_trial_from_public(trial) for trial in trials),
        )
    except (TypeError, ValueError) as error:
        if isinstance(error, CandidateEvidenceError):
            raise
        raise CandidateEvidenceError("scorecard_invalid") from error


def run_manifest_from_public(value: Any) -> RunManifest:
    if not isinstance(value, dict):
        raise CandidateEvidenceError("run_manifest_invalid")
    _exact_keys(
        value,
        {
            "effort",
            "league",
            "model",
            "run_id",
            "schema_version",
            "seed",
            "started_at",
            "subject_commit",
            "trials",
        },
    )
    if not isinstance(value["trials"], list):
        raise CandidateEvidenceError("run_manifest_trials_invalid")
    try:
        return RunManifest(
            schema_version=value["schema_version"],
            run_id=value["run_id"],
            subject_commit=value["subject_commit"],
            league=value["league"],
            model=value["model"],
            effort=value["effort"],
            started_at=value["started_at"],
            seed=value["seed"],
            trials=tuple(_trial_from_public(trial) for trial in value["trials"]),
        )
    except (TypeError, ValueError) as error:
        if isinstance(error, CandidateEvidenceError):
            raise
        raise CandidateEvidenceError("run_manifest_invalid") from error


def _scorecard_digest(scorecard: Scorecard) -> str:
    return hashlib.sha256(canonical_json_bytes(scorecard.to_public_dict())).hexdigest()


def _basis_points(value: float) -> int:
    return max(-10_000, min(10_000, round(value * 10_000)))


def bind_paired_evidence(
    manifest: ExperimentManifest,
    candidate: SealedCandidate,
    baseline_attestation: Any,
    candidate_attestation: Any,
    *,
    attestation_key: bytes,
    comparison_seed: int,
    store: PrivateArtifactStore,
) -> PairedEvidence:
    raise CandidateEvidenceError("isolated_signer_required")


def _bind_paired_evidence_unreachable(
    manifest: ExperimentManifest,
    candidate: SealedCandidate,
    baseline_attestation: Any,
    candidate_attestation: Any,
    *,
    attestation_key: bytes,
    comparison_seed: int,
    store: PrivateArtifactStore,
) -> PairedEvidence:
    """Retain the draft implementation for the future isolated-signer phase."""
    if not isinstance(manifest, ExperimentManifest) or not isinstance(candidate, SealedCandidate):
        raise CandidateEvidenceError("invalid_paired_binding")
    if (
        candidate.experiment_id != manifest.experiment_id
        or candidate.manifest_digest != manifest.digest
        or candidate.parent_commit != manifest.parent_commit
    ):
        raise CandidateEvidenceError("candidate_manifest_mismatch")
    try:
        baseline = verify_attested_scorecard(
            baseline_attestation,
            key=attestation_key,
            expected_experiment_id=manifest.experiment_id,
            expected_role="baseline",
            expected_subject_commit=manifest.parent_commit,
        )
    except RunAttestationError as error:
        raise CandidateEvidenceError("baseline_attestation_invalid") from error
    try:
        candidate_scorecard = verify_attested_scorecard(
            candidate_attestation,
            key=attestation_key,
            expected_experiment_id=manifest.experiment_id,
            expected_role="candidate",
            expected_subject_commit=candidate.candidate_commit,
        )
    except RunAttestationError as error:
        raise CandidateEvidenceError("candidate_attestation_invalid") from error
    if not isinstance(store, PrivateArtifactStore):
        raise CandidateEvidenceError("invalid_artifact_store")
    try:
        comparison = compare_runs(baseline, candidate_scorecard, comparison_seed=comparison_seed)
    except (TypeError, ValueError) as error:
        raise CandidateEvidenceError("paired_comparison_invalid") from error
    comparison_content = canonical_json_bytes(comparison.to_public_dict())
    comparison_artifact = store.put(
        evidence_kind="paired_comparison",
        media_type="application/json",
        content=comparison_content,
    )
    if comparison.decision != "improvement":
        raise CandidateEvidenceError("paired_improvement_required")
    return PairedEvidence(
        schema_version=1,
        experiment_id=manifest.experiment_id,
        manifest_digest=manifest.digest,
        parent_commit=manifest.parent_commit,
        candidate_commit=candidate.candidate_commit,
        baseline_scorecard_digest=_scorecard_digest(baseline),
        candidate_scorecard_digest=_scorecard_digest(candidate_scorecard),
        comparison_artifact=comparison_artifact,
        decision=comparison.decision,
        paired_trials=comparison.paired_trials,
        pass_rate_delta_basis_points=_basis_points(comparison.pass_rate_delta),
        confidence_lower_basis_points=_basis_points(comparison.confidence_lower),
    )


def _phase3_projection(
    manifest: ExperimentManifest, projection: ExperimentProjection
) -> tuple[SealedCandidate, PairedEvidence]:
    if (
        not isinstance(manifest, ExperimentManifest)
        or not isinstance(projection, ExperimentProjection)
        or projection.experiment_id != manifest.experiment_id
        or projection.manifest_digest != manifest.digest
    ):
        raise CandidateEvidenceError("projection_manifest_mismatch")
    if projection.state is not ExperimentState.PAIRED_EVALUATION:
        raise CandidateEvidenceError("candidate_review_wrong_state")
    if projection.candidate is None or projection.paired_evidence is None:
        raise CandidateEvidenceError("paired_evidence_required")
    if projection.paired_evidence.decision != "improvement":
        raise CandidateEvidenceError("paired_improvement_required")
    return projection.candidate, projection.paired_evidence


def issue_review_packet(
    manifest: ExperimentManifest,
    projection: ExperimentProjection,
    role: ReviewRole,
) -> ReviewPacket:
    raise CandidateEvidenceError("isolated_signer_required")


def _issue_review_packet_unreachable(
    manifest: ExperimentManifest,
    projection: ExperimentProjection,
    role: ReviewRole,
) -> ReviewPacket:
    """Retain the draft implementation for the future isolated-signer phase."""
    candidate, paired = _phase3_projection(manifest, projection)
    if role not in {
        ReviewRole.CORRECTNESS,
        ReviewRole.SECURITY,
        ReviewRole.MAINTAINABILITY,
        ReviewRole.BENCHMARK_INTEGRITY,
    }:
        raise CandidateEvidenceError("invalid_candidate_review_role")
    return ReviewPacket(
        schema_version=1,
        experiment_id=manifest.experiment_id,
        manifest_digest=manifest.digest,
        candidate_commit=candidate.candidate_commit,
        role=role.value,
        diff_digest=candidate.diff_artifact.digest,
        deterministic_evidence_digest=candidate.digest,
        paired_evidence_digest=paired.digest,
        review_contract_version="candidate-review-v1",
    )


def record_review_attestation(
    manifest: ExperimentManifest,
    projection: ExperimentProjection,
    packet: ReviewPacket,
    *,
    reviewer_id: str,
    context_id: str,
    verdict: str,
    report: bytes,
    store: PrivateArtifactStore,
) -> ReviewAttestation:
    raise CandidateEvidenceError("isolated_signer_required")


def _record_review_attestation_unreachable(
    manifest: ExperimentManifest,
    projection: ExperimentProjection,
    packet: ReviewPacket,
    *,
    reviewer_id: str,
    context_id: str,
    verdict: str,
    report: bytes,
    store: PrivateArtifactStore,
) -> ReviewAttestation:
    """Retain the draft implementation for the future isolated-signer phase."""
    _phase3_projection(manifest, projection)
    if not isinstance(packet, ReviewPacket):
        raise CandidateEvidenceError("invalid_review_packet")
    try:
        role = ReviewRole(packet.role)
    except ValueError as error:
        raise CandidateEvidenceError("invalid_candidate_review_role") from error
    if _issue_review_packet_unreachable(manifest, projection, role) != packet:
        raise CandidateEvidenceError("review_packet_mismatch")
    if any(review.reviewer_id == reviewer_id for review in projection.candidate_attestations):
        raise CandidateEvidenceError("reviewer_identity_reused")
    if any(review.context_id == context_id for review in projection.candidate_attestations):
        raise CandidateEvidenceError("review_context_reused")
    if not isinstance(report, bytes) or not report:
        raise CandidateEvidenceError("invalid_review_report")
    if not isinstance(store, PrivateArtifactStore):
        raise CandidateEvidenceError("invalid_artifact_store")
    report_artifact = store.put(
        evidence_kind="review_report", media_type="text/plain", content=report
    )
    return ReviewAttestation(
        schema_version=1,
        experiment_id=manifest.experiment_id,
        manifest_digest=manifest.digest,
        candidate_commit=packet.candidate_commit,
        role=packet.role,
        reviewer_id=reviewer_id,
        context_id=context_id,
        packet_digest=packet.digest,
        verdict=verdict,
        report_artifact=report_artifact,
    )
