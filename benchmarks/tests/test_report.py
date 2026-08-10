from __future__ import annotations

import math
from dataclasses import replace
from pathlib import Path

import pytest

from carl_bench.models import RunManifest, TrialResult
from carl_bench.report import compare_runs, summarize_run
from carl_bench.sanitize import PublicSafetyError, write_public_json

DIGESTS = {
    "coding": "a" * 64,
    "workflow": "b" * 64,
    "safety": "c" * 64,
}


def trial(
    *,
    run: str,
    track: str,
    attempt: int,
    passed: bool | None,
    elapsed_ms: int = 100,
    tool_calls: int | None = 2,
) -> TrialResult:
    arguments = {
        "trial_id": f"{run}-{track}-{attempt}",
        "task_id": f"carl/{track}-task",
        "task_digest": DIGESTS[track],
        "track": track,
        "adapter_id": run,
        "adapter_version": "1.0.0",
        "attempt": attempt,
        "seed": 100 + attempt,
        "elapsed_ms": elapsed_ms,
    }
    if passed is True:
        return TrialResult.passed(
            **arguments,
            checks_passed=4,
            checks_total=4,
            tool_calls=tool_calls,
        )
    if passed is False:
        return TrialResult.agent_failure(
            **arguments,
            code="verifier_failed",
            checks_passed=3,
            checks_total=4,
            tool_calls=tool_calls,
        )
    return TrialResult.infrastructure_invalid(
        **arguments,
        code="verifier_unavailable",
    )


def manifest(run: str, trials: tuple[TrialResult, ...]) -> RunManifest:
    return RunManifest(
        schema_version=1,
        run_id=f"run-{run}",
        league="same-model",
        model="gpt-test",
        effort="low",
        started_at="2026-08-10T20:00:00Z",
        seed=77,
        trials=trials,
    )


def test_summary_excludes_invalid_trials_and_reports_tracks_failures_and_medians() -> None:
    trials = (
        trial(run="candidate", track="coding", attempt=1, passed=True, elapsed_ms=100),
        trial(
            run="candidate",
            track="coding",
            attempt=2,
            passed=False,
            elapsed_ms=300,
            tool_calls=4,
        ),
        trial(run="candidate", track="workflow", attempt=1, passed=None, elapsed_ms=1),
    )
    scorecard = summarize_run(manifest("candidate", trials), trials)

    assert scorecard.valid_trials == 2
    assert scorecard.invalid_trials == 1
    assert scorecard.passed_trials == 1
    assert scorecard.failed_trials == 1
    assert scorecard.pass_rate == 0.5
    assert scorecard.median_elapsed_ms == 200
    assert scorecard.median_tool_calls == 3
    assert scorecard.failure_counts == (
        ("verifier_failed", 1),
        ("verifier_unavailable", 1),
    )
    track_counts = [
        (track.track, track.valid_trials, track.invalid_trials) for track in scorecard.tracks
    ]
    assert track_counts == [
        ("coding", 2, 0),
        ("workflow", 0, 1),
    ]
    assert len(scorecard.run_digest) == 64


def test_summary_with_no_valid_trials_has_zero_rate_and_no_median() -> None:
    trials = (trial(run="candidate", track="safety", attempt=1, passed=None),)
    scorecard = summarize_run(manifest("candidate", trials), trials)
    assert scorecard.pass_rate == 0.0
    assert scorecard.median_elapsed_ms is None
    assert scorecard.median_tool_calls is None


def test_summary_rejects_trials_that_do_not_match_the_manifest() -> None:
    included = (trial(run="candidate", track="coding", attempt=1, passed=True),)
    different = (trial(run="candidate", track="coding", attempt=2, passed=True),)
    with pytest.raises(ValueError, match="manifest trials"):
        summarize_run(manifest("candidate", included), different)


def test_comparison_pairs_exact_task_digest_attempt_and_seed() -> None:
    baseline_trials = (
        trial(run="baseline", track="coding", attempt=1, passed=False),
        trial(run="baseline", track="coding", attempt=2, passed=False),
        trial(run="baseline", track="coding", attempt=3, passed=False),
        trial(run="baseline", track="workflow", attempt=1, passed=None),
    )
    candidate_trials = (
        trial(run="candidate", track="coding", attempt=1, passed=True),
        trial(run="candidate", track="coding", attempt=2, passed=True),
        trial(run="candidate", track="coding", attempt=3, passed=True),
        trial(run="candidate", track="workflow", attempt=1, passed=True),
    )
    comparison = compare_runs(
        summarize_run(manifest("baseline", baseline_trials), baseline_trials),
        summarize_run(manifest("candidate", candidate_trials), candidate_trials),
        comparison_seed=123,
    )

    assert comparison.paired_trials == 3
    assert comparison.baseline_pass_rate == 0.0
    assert comparison.candidate_pass_rate == 1.0
    assert comparison.pass_rate_delta == 1.0
    assert comparison.confidence_lower == 1.0
    assert comparison.confidence_upper == 1.0
    assert comparison.decision == "improvement"
    assert comparison.gate_reasons == ()
    assert comparison.algorithm == "task-clustered-paired-bootstrap-v1-10000"
    assert comparison.comparison_seed == 123


def test_comparison_is_deterministic_and_requires_three_pairs_per_task() -> None:
    baseline_trials = tuple(
        trial(run="baseline", track="coding", attempt=index, passed=False) for index in range(1, 3)
    )
    candidate_trials = tuple(
        trial(run="candidate", track="coding", attempt=index, passed=True) for index in range(1, 3)
    )
    baseline = summarize_run(manifest("baseline", baseline_trials), baseline_trials)
    candidate = summarize_run(manifest("candidate", candidate_trials), candidate_trials)
    first = compare_runs(baseline, candidate, comparison_seed=99)
    second = compare_runs(baseline, candidate, comparison_seed=99)
    assert first == second
    assert first.decision == "insufficient_evidence"
    assert first.gate_reasons == ("minimum_pairs_per_task",)


def test_comparison_rejects_a_regressing_track_even_with_positive_overall_delta() -> None:
    baseline_trials = tuple(
        [
            *(
                trial(run="baseline", track="coding", attempt=index, passed=False)
                for index in range(1, 7)
            ),
            *(
                trial(run="baseline", track="safety", attempt=index, passed=True)
                for index in range(1, 4)
            ),
        ]
    )
    candidate_trials = tuple(
        [
            *(
                trial(run="candidate", track="coding", attempt=index, passed=True)
                for index in range(1, 7)
            ),
            trial(run="candidate", track="safety", attempt=1, passed=True),
            trial(run="candidate", track="safety", attempt=2, passed=True),
            trial(run="candidate", track="safety", attempt=3, passed=False),
        ]
    )
    comparison = compare_runs(
        summarize_run(manifest("baseline", baseline_trials), baseline_trials),
        summarize_run(manifest("candidate", candidate_trials), candidate_trials),
        comparison_seed=3,
    )
    assert comparison.pass_rate_delta > 0.03
    assert dict(comparison.track_deltas)["safety"] < -0.02
    assert comparison.decision == "rejected"
    assert "track_noninferiority" in comparison.gate_reasons


def test_confidence_interval_resamples_tasks_as_clusters() -> None:
    baseline_trials = tuple(
        [
            *(
                trial(run="baseline", track="coding", attempt=index, passed=False)
                for index in range(1, 10)
            ),
            *(
                trial(run="baseline", track="safety", attempt=index, passed=True)
                for index in range(1, 4)
            ),
        ]
    )
    candidate_trials = tuple(
        [
            *(
                trial(run="candidate", track="coding", attempt=index, passed=True)
                for index in range(1, 10)
            ),
            *(
                trial(run="candidate", track="safety", attempt=index, passed=False)
                for index in range(1, 4)
            ),
        ]
    )
    comparison = compare_runs(
        summarize_run(manifest("baseline", baseline_trials), baseline_trials),
        summarize_run(manifest("candidate", candidate_trials), candidate_trials),
        comparison_seed=17,
    )
    assert comparison.pass_rate_delta == 0.5
    assert comparison.confidence_lower == -1.0
    assert comparison.confidence_upper == 1.0
    assert comparison.algorithm == "task-clustered-paired-bootstrap-v1-10000"


def test_comparison_rejects_model_or_effort_mismatch() -> None:
    trials = tuple(
        trial(run="baseline", track="coding", attempt=index, passed=False) for index in range(1, 4)
    )
    baseline = summarize_run(manifest("baseline", trials), trials)
    candidate_manifest = replace(manifest("candidate", trials), model="different-model")
    candidate = summarize_run(candidate_manifest, trials)
    with pytest.raises(ValueError, match="model and effort"):
        compare_runs(baseline, candidate, comparison_seed=1)


@pytest.mark.parametrize("unsafe", [math.nan, math.inf])
def test_public_comparison_write_rejects_non_finite_and_raw_output(
    tmp_path: Path, unsafe: float
) -> None:
    trials = tuple(
        trial(run="baseline", track="coding", attempt=index, passed=False) for index in range(1, 4)
    )
    baseline = summarize_run(manifest("baseline", trials), trials)
    candidate = summarize_run(manifest("candidate", trials), trials)
    comparison = compare_runs(baseline, candidate, comparison_seed=1).to_public_dict()
    comparison["confidence_lower"] = unsafe
    comparison["stdout"] = "private model output"
    destination = tmp_path / "comparison.json"
    with pytest.raises(PublicSafetyError):
        write_public_json(destination, comparison, tmp_path)
    assert not destination.exists()
