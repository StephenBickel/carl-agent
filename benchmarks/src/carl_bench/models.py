"""Closed, public-safe value contracts for benchmark evidence."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, ClassVar

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_CODE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_TRACKS = frozenset({"coding", "workflow", "safety"})


def _bounded_string(name: str, value: str, maximum: int) -> None:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{name} must be non-empty and at most {maximum} bytes")
    if not _ID_RE.fullmatch(value):
        raise ValueError(f"{name} contains unsupported characters")


def _digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _commit(name: str, value: str) -> None:
    if not isinstance(value, str) or not _COMMIT_RE.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase full commit ID")


def _non_negative(name: str, value: int, maximum: int = 86_400_000) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{name} must be an integer between 0 and {maximum}")


class OutcomeStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    INVALID = "invalid"


class FailureClass(str, Enum):
    AGENT = "agent"
    INFRASTRUCTURE = "infrastructure"


class MetricKind(str, Enum):
    BOOLEAN = "boolean"
    COUNT = "count"
    DURATION_MS = "duration_ms"
    RATE = "rate"


@dataclass(frozen=True, slots=True)
class TaskIdentity:
    task_id: str
    digest: str
    track: str

    def __post_init__(self) -> None:
        _bounded_string("task_id", self.task_id, 128)
        _digest("digest", self.digest)
        if self.track not in _TRACKS:
            raise ValueError("track must be coding, workflow, or safety")


@dataclass(frozen=True, slots=True)
class AgentRequest:
    trial_id: str
    task_id: str
    instruction: str
    workspace: str
    timeout_sec: int
    seed: int
    scripted_solution: str | None = None

    def __post_init__(self) -> None:
        _bounded_string("trial_id", self.trial_id, 128)
        _bounded_string("task_id", self.task_id, 128)
        if not self.instruction or len(self.instruction.encode("utf-8")) > 65_536:
            raise ValueError("instruction must be between 1 and 65536 bytes")
        if not self.workspace or len(self.workspace.encode("utf-8")) > 4_096:
            raise ValueError("workspace must be between 1 and 4096 bytes")
        if not 1 <= self.timeout_sec <= 3_600:
            raise ValueError("timeout_sec must be between 1 and 3600")
        _non_negative("seed", self.seed, (1 << 63) - 1)
        if self.scripted_solution is not None and (
            not self.scripted_solution or len(self.scripted_solution.encode("utf-8")) > 4_096
        ):
            raise ValueError("scripted_solution must be between 1 and 4096 bytes")


@dataclass(frozen=True, slots=True)
class AgentOutcome:
    status: OutcomeStatus
    elapsed_ms: int
    failure_code: str | None = None
    tool_calls: int | None = None

    AGENT_FAILURE_CODES: ClassVar[frozenset[str]] = frozenset(
        {
            "agent_cancelled",
            "agent_exit_nonzero",
            "agent_output_overflow",
            "agent_protocol_error",
            "agent_timeout",
            "verifier_failed",
        }
    )

    def __post_init__(self) -> None:
        _non_negative("elapsed_ms", self.elapsed_ms)
        if self.tool_calls is not None:
            _non_negative("tool_calls", self.tool_calls, 1_000_000)
        if self.status is OutcomeStatus.PASSED and self.failure_code is not None:
            raise ValueError("successful AgentOutcome cannot have failure_code")
        if self.status is OutcomeStatus.FAILED:
            if self.failure_code not in self.AGENT_FAILURE_CODES:
                raise ValueError("failed AgentOutcome requires a stable agent failure_code")
        elif self.status is OutcomeStatus.INVALID:
            raise ValueError("AgentOutcome cannot classify infrastructure failures")

    @classmethod
    def succeeded(cls, *, elapsed_ms: int, tool_calls: int | None = None) -> AgentOutcome:
        return cls(status=OutcomeStatus.PASSED, elapsed_ms=elapsed_ms, tool_calls=tool_calls)

    @classmethod
    def failed(cls, *, code: str, elapsed_ms: int, tool_calls: int | None = None) -> AgentOutcome:
        return cls(
            status=OutcomeStatus.FAILED,
            elapsed_ms=elapsed_ms,
            failure_code=code,
            tool_calls=tool_calls,
        )


@dataclass(frozen=True, slots=True)
class TrialResult:
    trial_id: str
    task_id: str
    task_digest: str
    adapter_id: str
    adapter_version: str
    attempt: int
    seed: int
    status: OutcomeStatus
    elapsed_ms: int
    failure_class: FailureClass | None = None
    failure_code: str | None = None
    checks_passed: int | None = None
    checks_total: int | None = None
    tool_calls: int | None = None
    track: str = "coding"

    INFRASTRUCTURE_FAILURE_CODES: ClassVar[frozenset[str]] = frozenset(
        {
            "runner_cancelled",
            "runner_internal_error",
            "runner_task_source_changed",
            "verifier_exit_nonzero",
            "verifier_invalid_output",
            "verifier_output_overflow",
            "verifier_private_dir_unsafe",
            "verifier_timeout",
            "verifier_unavailable",
            "verifier_workspace_unsafe",
        }
    )

    def __post_init__(self) -> None:
        _bounded_string("trial_id", self.trial_id, 128)
        _bounded_string("task_id", self.task_id, 128)
        _digest("task_digest", self.task_digest)
        _bounded_string("adapter_id", self.adapter_id, 64)
        _bounded_string("adapter_version", self.adapter_version, 64)
        if self.track not in _TRACKS:
            raise ValueError("track must be coding, workflow, or safety")
        if not 1 <= self.attempt <= 10:
            raise ValueError("attempt must be between 1 and 10")
        _non_negative("seed", self.seed, (1 << 63) - 1)
        _non_negative("elapsed_ms", self.elapsed_ms)
        if self.tool_calls is not None:
            _non_negative("tool_calls", self.tool_calls, 1_000_000)
        if (self.checks_passed is None) != (self.checks_total is None):
            raise ValueError("checks_passed and checks_total must appear together")
        if self.checks_total is not None and self.checks_passed is not None:
            _non_negative("checks_passed", self.checks_passed, 1_000_000)
            _non_negative("checks_total", self.checks_total, 1_000_000)
            if self.checks_passed > self.checks_total:
                raise ValueError("checks_passed cannot exceed checks_total")

        if self.status is OutcomeStatus.PASSED:
            if self.failure_class is not None or self.failure_code is not None:
                raise ValueError("passed trial cannot carry failure metadata")
            if self.checks_total is None or self.checks_passed != self.checks_total:
                raise ValueError("passed trial requires all verifier checks to pass")
        elif self.status is OutcomeStatus.FAILED:
            if self.failure_class is not FailureClass.AGENT:
                raise ValueError("failed trial must have agent failure_class")
            if self.failure_code not in AgentOutcome.AGENT_FAILURE_CODES:
                raise ValueError("failed trial requires a stable agent failure_code")
        else:
            if self.failure_class is not FailureClass.INFRASTRUCTURE:
                raise ValueError("invalid trial must have infrastructure failure_class")
            if self.failure_code not in self.INFRASTRUCTURE_FAILURE_CODES:
                raise ValueError("invalid trial requires a stable infrastructure failure_code")

    @classmethod
    def passed(
        cls,
        *,
        trial_id: str,
        task_id: str,
        task_digest: str,
        adapter_id: str,
        adapter_version: str,
        attempt: int,
        seed: int,
        elapsed_ms: int,
        checks_passed: int,
        checks_total: int,
        tool_calls: int | None = None,
        track: str = "coding",
    ) -> TrialResult:
        return cls(
            trial_id=trial_id,
            task_id=task_id,
            task_digest=task_digest,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            attempt=attempt,
            seed=seed,
            status=OutcomeStatus.PASSED,
            elapsed_ms=elapsed_ms,
            checks_passed=checks_passed,
            checks_total=checks_total,
            tool_calls=tool_calls,
            track=track,
        )

    @classmethod
    def agent_failure(
        cls,
        *,
        trial_id: str,
        task_id: str,
        task_digest: str,
        adapter_id: str,
        adapter_version: str,
        attempt: int,
        seed: int,
        code: str,
        elapsed_ms: int,
        tool_calls: int | None = None,
        checks_passed: int | None = None,
        checks_total: int | None = None,
        track: str = "coding",
    ) -> TrialResult:
        return cls(
            trial_id=trial_id,
            task_id=task_id,
            task_digest=task_digest,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            attempt=attempt,
            seed=seed,
            status=OutcomeStatus.FAILED,
            elapsed_ms=elapsed_ms,
            failure_class=FailureClass.AGENT,
            failure_code=code,
            tool_calls=tool_calls,
            checks_passed=checks_passed,
            checks_total=checks_total,
            track=track,
        )

    @classmethod
    def infrastructure_invalid(
        cls,
        *,
        trial_id: str,
        task_id: str,
        task_digest: str,
        adapter_id: str,
        adapter_version: str,
        attempt: int,
        seed: int,
        code: str,
        elapsed_ms: int,
        track: str = "coding",
    ) -> TrialResult:
        return cls(
            trial_id=trial_id,
            task_id=task_id,
            task_digest=task_digest,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            attempt=attempt,
            seed=seed,
            status=OutcomeStatus.INVALID,
            elapsed_ms=elapsed_ms,
            failure_class=FailureClass.INFRASTRUCTURE,
            failure_code=code,
            track=track,
        )

    def to_public_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "attempt": self.attempt,
            "elapsed_ms": self.elapsed_ms,
            "seed": self.seed,
            "status": self.status.value,
            "task_digest": self.task_digest,
            "task_id": self.task_id,
            "track": self.track,
            "trial_id": self.trial_id,
        }
        if self.failure_class is not None:
            result["failure_class"] = self.failure_class.value
        if self.failure_code is not None:
            result["failure_code"] = self.failure_code
        if self.checks_passed is not None:
            result["checks_passed"] = self.checks_passed
            result["checks_total"] = self.checks_total
        if self.tool_calls is not None:
            result["tool_calls"] = self.tool_calls
        return result


@dataclass(frozen=True, slots=True)
class RunManifest:
    schema_version: int
    run_id: str
    subject_commit: str
    league: str
    model: str | None
    effort: str | None
    started_at: str
    seed: int
    trials: tuple[TrialResult, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("schema_version must be 1")
        _bounded_string("run_id", self.run_id, 128)
        _commit("subject_commit", self.subject_commit)
        if self.league not in {"plumbing", "same-model", "native-product"}:
            raise ValueError("league is unsupported")
        if self.model is not None:
            _bounded_string("model", self.model, 128)
        if self.effort is not None:
            _bounded_string("effort", self.effort, 32)
        if not self.started_at or len(self.started_at) > 64:
            raise ValueError("started_at is invalid")
        _non_negative("seed", self.seed, (1 << 63) - 1)
        trial_ids = [trial.trial_id for trial in self.trials]
        if len(trial_ids) != len(set(trial_ids)):
            raise ValueError("duplicate trial_id")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "effort": self.effort,
            "league": self.league,
            "model": self.model,
            "run_id": self.run_id,
            "schema_version": self.schema_version,
            "seed": self.seed,
            "started_at": self.started_at,
            "subject_commit": self.subject_commit,
            "trials": [trial.to_public_dict() for trial in self.trials],
        }


@dataclass(frozen=True, slots=True)
class TrackScorecard:
    track: str
    valid_trials: int
    invalid_trials: int
    passed_trials: int
    failed_trials: int
    pass_rate: float

    def __post_init__(self) -> None:
        if self.track not in _TRACKS:
            raise ValueError("track must be coding, workflow, or safety")
        for name in ("valid_trials", "invalid_trials", "passed_trials", "failed_trials"):
            _non_negative(name, getattr(self, name), 1_000_000)
        if self.passed_trials + self.failed_trials != self.valid_trials:
            raise ValueError("track valid trial counts are inconsistent")
        expected_rate = self.passed_trials / self.valid_trials if self.valid_trials else 0.0
        if not math.isfinite(self.pass_rate) or not math.isclose(
            self.pass_rate, expected_rate, rel_tol=0.0, abs_tol=1e-12
        ):
            raise ValueError("track pass_rate does not match trial counts")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "failed_trials": self.failed_trials,
            "invalid_trials": self.invalid_trials,
            "pass_rate": self.pass_rate,
            "passed_trials": self.passed_trials,
            "track": self.track,
            "valid_trials": self.valid_trials,
        }


@dataclass(frozen=True, slots=True)
class Scorecard:
    schema_version: int
    run_id: str
    run_digest: str
    subject_commit: str
    valid_trials: int
    invalid_trials: int
    passed_trials: int
    failed_trials: int
    pass_rate: float
    median_elapsed_ms: int | float | None
    trials: tuple[TrialResult, ...]
    median_tool_calls: int | float | None = None
    failure_counts: tuple[tuple[str, int], ...] = ()
    tracks: tuple[TrackScorecard, ...] = ()
    league: str = "plumbing"
    model: str | None = None
    effort: str | None = None

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("schema_version must be 1")
        _bounded_string("run_id", self.run_id, 128)
        _digest("run_digest", self.run_digest)
        _commit("subject_commit", self.subject_commit)
        for name in ("valid_trials", "invalid_trials", "passed_trials", "failed_trials"):
            _non_negative(name, getattr(self, name), 1_000_000)
        if not math.isfinite(self.pass_rate) or not 0.0 <= self.pass_rate <= 1.0:
            raise ValueError("pass_rate must be finite and between 0 and 1")
        if self.median_elapsed_ms is not None and (
            not isinstance(self.median_elapsed_ms, int | float)
            or isinstance(self.median_elapsed_ms, bool)
            or not math.isfinite(self.median_elapsed_ms)
            or self.median_elapsed_ms < 0
        ):
            raise ValueError("median_elapsed_ms must be finite and non-negative")
        if self.median_tool_calls is not None and (
            not isinstance(self.median_tool_calls, int | float)
            or isinstance(self.median_tool_calls, bool)
            or not math.isfinite(self.median_tool_calls)
            or self.median_tool_calls < 0
        ):
            raise ValueError("median_tool_calls must be finite and non-negative")
        if self.valid_trials + self.invalid_trials != len(self.trials):
            raise ValueError("trial counts do not equal the included trial population")
        if self.passed_trials + self.failed_trials != self.valid_trials:
            raise ValueError("valid trial counts are inconsistent")
        expected_rate = self.passed_trials / self.valid_trials if self.valid_trials else 0.0
        if not math.isclose(self.pass_rate, expected_rate, rel_tol=0.0, abs_tol=1e-12):
            raise ValueError("pass_rate does not match trial counts")
        if tuple(sorted(self.failure_counts)) != self.failure_counts:
            raise ValueError("failure_counts must be sorted")
        for code, count in self.failure_counts:
            if not _CODE_RE.fullmatch(code):
                raise ValueError("failure_counts contains an invalid code")
            _non_negative("failure_count", count, 1_000_000)
        if tuple(sorted(track.track for track in self.tracks)) != tuple(
            track.track for track in self.tracks
        ):
            raise ValueError("tracks must be sorted")
        if self.league not in {"plumbing", "same-model", "native-product"}:
            raise ValueError("league is unsupported")
        if self.model is not None:
            _bounded_string("model", self.model, 128)
        if self.effort is not None:
            _bounded_string("effort", self.effort, 32)

    def to_public_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "effort": self.effort,
            "failed_trials": self.failed_trials,
            "failure_counts": [
                {"code": code, "count": count} for code, count in self.failure_counts
            ],
            "invalid_trials": self.invalid_trials,
            "league": self.league,
            "median_elapsed_ms": self.median_elapsed_ms,
            "median_tool_calls": self.median_tool_calls,
            "model": self.model,
            "pass_rate": self.pass_rate,
            "passed_trials": self.passed_trials,
            "run_digest": self.run_digest,
            "run_id": self.run_id,
            "schema_version": self.schema_version,
            "subject_commit": self.subject_commit,
            "tracks": [track.to_public_dict() for track in self.tracks],
            "trials": [trial.to_public_dict() for trial in self.trials],
            "valid_trials": self.valid_trials,
        }
        return value
