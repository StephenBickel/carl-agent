"""Deterministic benchmark scorecards and paired comparisons."""

from __future__ import annotations

import hashlib
import math
import random
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any

from carl_bench.canonical import canonical_json_bytes
from carl_bench.models import (
    OutcomeStatus,
    RunManifest,
    Scorecard,
    TrackScorecard,
    TrialResult,
)

BOOTSTRAP_RESAMPLES = 10_000


def _rate(passed: int, valid: int) -> float:
    return passed / valid if valid else 0.0


def _track_score(track: str, trials: tuple[TrialResult, ...]) -> TrackScorecard:
    valid = tuple(trial for trial in trials if trial.status is not OutcomeStatus.INVALID)
    passed = sum(trial.status is OutcomeStatus.PASSED for trial in valid)
    return TrackScorecard(
        track=track,
        valid_trials=len(valid),
        invalid_trials=len(trials) - len(valid),
        passed_trials=passed,
        failed_trials=len(valid) - passed,
        pass_rate=_rate(passed, len(valid)),
    )


def summarize_run(
    manifest: RunManifest, trials: tuple[TrialResult, ...] | list[TrialResult]
) -> Scorecard:
    """Aggregate one immutable run without counting infrastructure-invalid trials."""
    included = tuple(trials)
    if included != manifest.trials:
        raise ValueError("manifest trials do not match the supplied trial population")
    valid = tuple(trial for trial in included if trial.status is not OutcomeStatus.INVALID)
    passed = sum(trial.status is OutcomeStatus.PASSED for trial in valid)
    elapsed = [trial.elapsed_ms for trial in valid]
    tool_calls = [trial.tool_calls for trial in valid if trial.tool_calls is not None]
    failure_counts = Counter(
        trial.failure_code for trial in included if trial.failure_code is not None
    )
    grouped: dict[str, list[TrialResult]] = defaultdict(list)
    for trial in included:
        grouped[trial.track].append(trial)
    tracks = tuple(_track_score(track, tuple(grouped[track])) for track in sorted(grouped))
    digest = hashlib.sha256(canonical_json_bytes(manifest.to_public_dict())).hexdigest()
    return Scorecard(
        schema_version=1,
        run_id=manifest.run_id,
        run_digest=digest,
        valid_trials=len(valid),
        invalid_trials=len(included) - len(valid),
        passed_trials=passed,
        failed_trials=len(valid) - passed,
        pass_rate=_rate(passed, len(valid)),
        median_elapsed_ms=statistics.median(elapsed) if elapsed else None,
        median_tool_calls=statistics.median(tool_calls) if tool_calls else None,
        failure_counts=tuple(sorted(failure_counts.items())),
        tracks=tracks,
        league=manifest.league,
        model=manifest.model,
        effort=manifest.effort,
        trials=included,
    )


@dataclass(frozen=True, slots=True)
class Comparison:
    schema_version: int
    baseline_run_id: str
    candidate_run_id: str
    baseline_run_digest: str
    candidate_run_digest: str
    paired_trials: int
    baseline_pass_rate: float
    candidate_pass_rate: float
    pass_rate_delta: float
    confidence_lower: float
    confidence_upper: float
    track_deltas: tuple[tuple[str, float], ...]
    decision: str
    gate_reasons: tuple[str, ...]
    algorithm: str
    comparison_seed: int

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("schema_version must be 1")
        if self.decision not in {"improvement", "rejected", "insufficient_evidence"}:
            raise ValueError("comparison decision is unsupported")
        if any(
            not math.isfinite(value)
            for value in (
                self.baseline_pass_rate,
                self.candidate_pass_rate,
                self.pass_rate_delta,
                self.confidence_lower,
                self.confidence_upper,
            )
        ):
            raise ValueError("comparison metrics must be finite")
        if tuple(sorted(self.track_deltas)) != self.track_deltas:
            raise ValueError("track_deltas must be sorted")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "baseline_pass_rate": self.baseline_pass_rate,
            "baseline_run_digest": self.baseline_run_digest,
            "baseline_run_id": self.baseline_run_id,
            "candidate_pass_rate": self.candidate_pass_rate,
            "candidate_run_digest": self.candidate_run_digest,
            "candidate_run_id": self.candidate_run_id,
            "comparison_seed": self.comparison_seed,
            "confidence_lower": self.confidence_lower,
            "confidence_upper": self.confidence_upper,
            "decision": self.decision,
            "gate_reasons": list(self.gate_reasons),
            "paired_trials": self.paired_trials,
            "pass_rate_delta": self.pass_rate_delta,
            "schema_version": self.schema_version,
            "track_deltas": [
                {"delta": delta, "track": track} for track, delta in self.track_deltas
            ],
        }


def _trial_key(trial: TrialResult) -> tuple[str, str, int, int]:
    return (trial.task_id, trial.task_digest, trial.attempt, trial.seed)


def _valid_trial_map(scorecard: Scorecard) -> dict[tuple[str, str, int, int], TrialResult]:
    result: dict[tuple[str, str, int, int], TrialResult] = {}
    for trial in scorecard.trials:
        if trial.status is OutcomeStatus.INVALID:
            continue
        key = _trial_key(trial)
        if key in result:
            raise ValueError("scorecard contains duplicate paired trial keys")
        result[key] = trial
    return result


def _bootstrap_interval(clusters: tuple[tuple[int, ...], ...], seed: int) -> tuple[float, float]:
    if not clusters:
        return 0.0, 0.0
    generator = random.Random(seed)
    cluster_count = len(clusters)
    samples: list[float] = []
    for _ in range(BOOTSTRAP_RESAMPLES):
        selected = tuple(generator.choice(clusters) for _ in range(cluster_count))
        samples.append(
            sum(sum(cluster) for cluster in selected)
            / sum(len(cluster) for cluster in selected)
        )
    samples.sort()
    return samples[499], samples[9_499]


def compare_runs(baseline: Scorecard, candidate: Scorecard, *, comparison_seed: int) -> Comparison:
    """Compare exact paired valid trials with deterministic promotion evidence gates."""
    if (
        isinstance(comparison_seed, bool)
        or not isinstance(comparison_seed, int)
        or comparison_seed < 0
    ):
        raise ValueError("comparison_seed must be non-negative")
    if baseline.league != candidate.league:
        raise ValueError("comparison leagues must match")
    if baseline.league == "same-model" and (
        baseline.model != candidate.model or baseline.effort != candidate.effort
    ):
        raise ValueError("same-model comparisons require identical model and effort")

    baseline_map = _valid_trial_map(baseline)
    candidate_map = _valid_trial_map(candidate)
    common = sorted(set(baseline_map) & set(candidate_map))
    pairs = tuple((baseline_map[key], candidate_map[key]) for key in common)
    for baseline_trial, candidate_trial in pairs:
        if baseline_trial.track != candidate_trial.track:
            raise ValueError("paired trials must have the same track")

    baseline_passed = sum(
        baseline_trial.status is OutcomeStatus.PASSED for baseline_trial, _ in pairs
    )
    candidate_passed = sum(
        candidate_trial.status is OutcomeStatus.PASSED for _, candidate_trial in pairs
    )
    baseline_rate = _rate(baseline_passed, len(pairs))
    candidate_rate = _rate(candidate_passed, len(pairs))
    clustered_differences: dict[tuple[str, str], list[int]] = defaultdict(list)
    for baseline_trial, candidate_trial in pairs:
        clustered_differences[(baseline_trial.task_id, baseline_trial.task_digest)].append(
            int(candidate_trial.status is OutcomeStatus.PASSED)
            - int(baseline_trial.status is OutcomeStatus.PASSED)
        )
    confidence_lower, confidence_upper = _bootstrap_interval(
        tuple(tuple(clustered_differences[key]) for key in sorted(clustered_differences)),
        comparison_seed,
    )

    task_counts = Counter((trial.task_id, trial.task_digest) for trial, _ in pairs)
    tracks: dict[str, list[tuple[TrialResult, TrialResult]]] = defaultdict(list)
    for pair in pairs:
        tracks[pair[0].track].append(pair)
    track_deltas = tuple(
        (
            track,
            _rate(
                sum(
                    candidate_trial.status is OutcomeStatus.PASSED for _, candidate_trial in values
                ),
                len(values),
            )
            - _rate(
                sum(baseline_trial.status is OutcomeStatus.PASSED for baseline_trial, _ in values),
                len(values),
            ),
        )
        for track, values in sorted(tracks.items())
    )

    if not task_counts or min(task_counts.values()) < 3:
        decision = "insufficient_evidence"
        reasons = ("minimum_pairs_per_task",)
    else:
        collected: list[str] = []
        delta = candidate_rate - baseline_rate
        if delta < 0.03:
            collected.append("minimum_effect")
        if confidence_lower <= 0.0:
            collected.append("paired_confidence")
        if any(delta < -0.02 for _, delta in track_deltas):
            collected.append("track_noninferiority")
        reasons = tuple(collected)
        decision = "improvement" if not reasons else "rejected"

    return Comparison(
        schema_version=1,
        baseline_run_id=baseline.run_id,
        candidate_run_id=candidate.run_id,
        baseline_run_digest=baseline.run_digest,
        candidate_run_digest=candidate.run_digest,
        paired_trials=len(pairs),
        baseline_pass_rate=baseline_rate,
        candidate_pass_rate=candidate_rate,
        pass_rate_delta=candidate_rate - baseline_rate,
        confidence_lower=confidence_lower,
        confidence_upper=confidence_upper,
        track_deltas=track_deltas,
        decision=decision,
        gate_reasons=reasons,
        algorithm=f"task-clustered-paired-bootstrap-v1-{BOOTSTRAP_RESAMPLES}",
        comparison_seed=comparison_seed,
    )
