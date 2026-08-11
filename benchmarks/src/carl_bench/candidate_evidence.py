"""Paired benchmark and independent review evidence for sealed candidates."""

from __future__ import annotations

from typing import Any

from carl_bench.artifacts import PrivateArtifactStore
from carl_bench.candidate import (
    PairedEvidence,
    ReviewAttestation,
    ReviewPacket,
    SealedCandidate,
)
from carl_bench.experiment import (
    ExperimentManifest,
    ExperimentProjection,
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


def issue_review_packet(
    manifest: ExperimentManifest,
    projection: ExperimentProjection,
    role: ReviewRole,
) -> ReviewPacket:
    raise CandidateEvidenceError("isolated_signer_required")


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
