from __future__ import annotations

import math

import pytest

from carl_bench.models import (
    AgentOutcome,
    FailureClass,
    OutcomeStatus,
    RunManifest,
    Scorecard,
    TaskIdentity,
    TrialResult,
)

TASK_DIGEST = "a" * 64
RUN_DIGEST = "b" * 64


def passing_trial(trial_id: str = "trial-01") -> TrialResult:
    return TrialResult.passed(
        trial_id=trial_id,
        task_id="carl/coding-fix-config-lookup",
        task_digest=TASK_DIGEST,
        adapter_id="scripted",
        adapter_version="1.0.0",
        attempt=1,
        seed=7,
        elapsed_ms=125,
        checks_passed=4,
        checks_total=4,
        tool_calls=2,
    )


def test_trial_result_separates_agent_failure_from_invalid_run() -> None:
    failed = TrialResult.agent_failure(
        trial_id="trial-01",
        task_id="carl/coding-fix-config-lookup",
        task_digest=TASK_DIGEST,
        adapter_id="carl-acp",
        adapter_version="0.1.0",
        attempt=1,
        seed=7,
        code="agent_timeout",
        elapsed_ms=30_000,
    )
    invalid = TrialResult.infrastructure_invalid(
        trial_id="trial-02",
        task_id="carl/coding-fix-config-lookup",
        task_digest=TASK_DIGEST,
        adapter_id="carl-acp",
        adapter_version="0.1.0",
        attempt=1,
        seed=7,
        code="verifier_unavailable",
        elapsed_ms=0,
    )

    assert failed.status is OutcomeStatus.FAILED
    assert failed.failure_class is FailureClass.AGENT
    assert failed.failure_code == "agent_timeout"
    assert invalid.status is OutcomeStatus.INVALID
    assert invalid.failure_class is FailureClass.INFRASTRUCTURE
    assert invalid.failure_code == "verifier_unavailable"


def test_public_trial_dictionary_is_closed_and_omits_absent_metrics() -> None:
    public = TrialResult.agent_failure(
        trial_id="trial-01",
        task_id="carl/coding-fix-config-lookup",
        task_digest=TASK_DIGEST,
        adapter_id="carl-acp",
        adapter_version="0.1.0",
        attempt=2,
        seed=9,
        code="agent_exit_nonzero",
        elapsed_ms=87,
    ).to_public_dict()

    assert public == {
        "adapter_id": "carl-acp",
        "adapter_version": "0.1.0",
        "attempt": 2,
        "elapsed_ms": 87,
        "failure_class": "agent",
        "failure_code": "agent_exit_nonzero",
        "seed": 9,
        "status": "failed",
        "task_digest": TASK_DIGEST,
        "task_id": "carl/coding-fix-config-lookup",
        "trial_id": "trial-01",
    }
    assert "tool_calls" not in public
    assert "checks_passed" not in public


@pytest.mark.parametrize(
    ("factory", "match"),
    [
        (lambda: TaskIdentity(task_id="", digest=TASK_DIGEST, track="coding"), "task_id"),
        (
            lambda: TaskIdentity(task_id="x" * 129, digest=TASK_DIGEST, track="coding"),
            "task_id",
        ),
        (lambda: TaskIdentity(task_id="valid", digest="not-a-digest", track="coding"), "digest"),
        (lambda: TaskIdentity(task_id="valid", digest=TASK_DIGEST, track="unknown"), "track"),
        (
            lambda: AgentOutcome.succeeded(elapsed_ms=-1, tool_calls=0),
            "elapsed_ms",
        ),
        (
            lambda: AgentOutcome.succeeded(elapsed_ms=1, tool_calls=-1),
            "tool_calls",
        ),
        (
            lambda: TrialResult.agent_failure(
                trial_id="trial-01",
                task_id="task",
                task_digest=TASK_DIGEST,
                adapter_id="adapter",
                adapter_version="1",
                attempt=0,
                seed=1,
                code="agent_timeout",
                elapsed_ms=1,
            ),
            "attempt",
        ),
    ],
)
def test_models_reject_invalid_bounded_values(factory: object, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        factory()  # type: ignore[operator]


@pytest.mark.parametrize("value", [-1.0, 1.01, math.nan, math.inf])
def test_scorecard_rejects_invalid_pass_rates(value: float) -> None:
    with pytest.raises(ValueError, match="pass_rate"):
        Scorecard(
            schema_version=1,
            run_id="run-01",
            run_digest=RUN_DIGEST,
            valid_trials=1,
            invalid_trials=0,
            passed_trials=1,
            failed_trials=0,
            pass_rate=value,
            median_elapsed_ms=1,
            trials=(passing_trial(),),
        )


def test_run_manifest_rejects_duplicate_trial_ids() -> None:
    trial = passing_trial()
    with pytest.raises(ValueError, match="duplicate trial_id"):
        RunManifest(
            schema_version=1,
            run_id="run-01",
            league="plumbing",
            model=None,
            effort=None,
            started_at="2026-08-10T20:00:00Z",
            seed=7,
            trials=(trial, trial),
        )


def test_scorecard_counts_must_equal_the_included_population() -> None:
    with pytest.raises(ValueError, match="trial counts"):
        Scorecard(
            schema_version=1,
            run_id="run-01",
            run_digest=RUN_DIGEST,
            valid_trials=2,
            invalid_trials=0,
            passed_trials=2,
            failed_trials=0,
            pass_rate=1.0,
            median_elapsed_ms=125,
            trials=(passing_trial(),),
        )
