"""Deterministic reconciliation for credential-free GitHub-hosted execution."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from carl_bench.canonical import canonical_json_bytes

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_HEAVY_LOCAL_RE = re.compile(
    r"(?:^|[/\s])(?:cargo|pytest|docker|colima)(?:-[A-Za-z0-9_.-]+)?(?=$|[/\s])"
    r"|\bbenchmarks?\b|\bsoak\b",
    re.IGNORECASE,
)
_WORKFLOWS = frozenset({"autonomous-improvement.yml", "autonomous-soak.yml"})
_RUNNING_STATUSES = frozenset({"queued", "in_progress"})
_INFRASTRUCTURE_CONCLUSIONS = frozenset(
    {"action_required", "cancelled", "stale", "startup_failure", "timed_out"}
)
_CONCLUSIONS = _INFRASTRUCTURE_CONCLUSIONS | {
    "failure",
    "neutral",
    "skipped",
    "success",
}

CloudRunAction = Literal[
    "dispatch",
    "await_run",
    "download_artifacts",
    "record_success",
    "schedule_retry",
    "blocked",
]


class CloudExecutionError(ValueError):
    """A stable contract error that never includes commands or credentials."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise CloudExecutionError(f"invalid_{name}")


def _object(name: str, value: str) -> None:
    if not isinstance(value, str) or not _OBJECT_RE.fullmatch(value):
        raise CloudExecutionError(f"invalid_{name}")


def _utc(name: str, value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CloudExecutionError(f"invalid_{name}")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise CloudExecutionError(f"invalid_{name}") from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise CloudExecutionError(f"invalid_{name}")
    return parsed


def _request_payload(
    *,
    repository: str,
    workflow_file: str,
    experiment_digest: str,
    parent_commit: str,
    candidate_commit: str,
    task_set_digest: str,
    metric_pack_digest: str,
    policy_digest: str,
) -> dict[str, Any]:
    return {
        "candidate_commit": candidate_commit,
        "experiment_digest": experiment_digest,
        "metric_pack_digest": metric_pack_digest,
        "parent_commit": parent_commit,
        "policy_digest": policy_digest,
        "repository": repository,
        "schema_version": 1,
        "task_set_digest": task_set_digest,
        "workflow_file": workflow_file,
    }


def _request_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


@dataclass(frozen=True, slots=True)
class CloudRunRequest:
    schema_version: int
    repository: str
    workflow_file: str
    experiment_digest: str
    parent_commit: str
    candidate_commit: str
    task_set_digest: str
    metric_pack_digest: str
    policy_digest: str
    request_digest: str
    dispatch_key: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CloudExecutionError("cloud_request_schema_invalid")
        if not isinstance(self.repository, str) or not _REPOSITORY_RE.fullmatch(self.repository):
            raise CloudExecutionError("invalid_repository")
        if self.workflow_file not in _WORKFLOWS:
            raise CloudExecutionError("cloud_workflow_not_allowed")
        for name in (
            "experiment_digest",
            "task_set_digest",
            "metric_pack_digest",
            "policy_digest",
            "request_digest",
        ):
            _digest(name, getattr(self, name))
        _object("parent_commit", self.parent_commit)
        _object("candidate_commit", self.candidate_commit)
        expected_digest = _request_digest(
            _request_payload(
                repository=self.repository,
                workflow_file=self.workflow_file,
                experiment_digest=self.experiment_digest,
                parent_commit=self.parent_commit,
                candidate_commit=self.candidate_commit,
                task_set_digest=self.task_set_digest,
                metric_pack_digest=self.metric_pack_digest,
                policy_digest=self.policy_digest,
            )
        )
        if self.request_digest != expected_digest:
            raise CloudExecutionError("cloud_request_digest_mismatch")
        if self.dispatch_key != f"cloud-run-{expected_digest}":
            raise CloudExecutionError("cloud_dispatch_key_mismatch")

    @classmethod
    def create(
        cls,
        *,
        repository: str,
        workflow_file: str,
        experiment_digest: str,
        parent_commit: str,
        candidate_commit: str,
        task_set_digest: str,
        metric_pack_digest: str,
        policy_digest: str,
    ) -> CloudRunRequest:
        payload = _request_payload(
            repository=repository,
            workflow_file=workflow_file,
            experiment_digest=experiment_digest,
            parent_commit=parent_commit,
            candidate_commit=candidate_commit,
            task_set_digest=task_set_digest,
            metric_pack_digest=metric_pack_digest,
            policy_digest=policy_digest,
        )
        request_digest = _request_digest(payload)
        return cls(
            schema_version=1,
            repository=repository,
            workflow_file=workflow_file,
            experiment_digest=experiment_digest,
            parent_commit=parent_commit,
            candidate_commit=candidate_commit,
            task_set_digest=task_set_digest,
            metric_pack_digest=metric_pack_digest,
            policy_digest=policy_digest,
            request_digest=request_digest,
            dispatch_key=f"cloud-run-{request_digest}",
        )

    @property
    def expected_artifact_name(self) -> str:
        prefix = (
            "autonomous-improvement-evidence"
            if self.workflow_file == "autonomous-improvement.yml"
            else "autonomous-soak-observation"
        )
        return f"{prefix}-{self.request_digest}"

    def attempt_key(self, attempt: int) -> str:
        if isinstance(attempt, bool) or not isinstance(attempt, int) or not 1 <= attempt <= 3:
            raise CloudExecutionError("invalid_cloud_attempt")
        return f"{self.dispatch_key}-attempt-{attempt}"


@dataclass(frozen=True, slots=True)
class CloudArtifact:
    artifact_id: int
    name: str
    run_id: int
    digest: str
    downloaded_digest: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("artifact_id", "run_id"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise CloudExecutionError(f"invalid_cloud_{field_name}")
        if (
            not isinstance(self.name, str)
            or not self.name
            or len(self.name.encode("utf-8")) > 180
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", self.name)
        ):
            raise CloudExecutionError("invalid_cloud_artifact_name")
        _digest("cloud_artifact_digest", self.digest)
        if self.downloaded_digest is not None:
            _digest("cloud_downloaded_artifact_digest", self.downloaded_digest)


@dataclass(frozen=True, slots=True)
class CloudRunSnapshot:
    remote_available: bool
    observed_at: str
    repository: str | None = None
    workflow_file: str | None = None
    request_digest: str | None = None
    dispatch_key: str | None = None
    run_id: int | None = None
    head_sha: str | None = None
    status: str | None = None
    conclusion: str | None = None
    attempt: int = 1
    max_attempts: int = 3
    attempt_key: str | None = None
    prior_run_ids: tuple[int, ...] = ()
    artifacts: tuple[CloudArtifact, ...] = ()
    artifacts_expires_at: str | None = None
    commissioning_actionlint_passed: bool = False
    commissioning_dry_run_id: int | None = None
    local_fallback_command: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.remote_available, bool):
            raise CloudExecutionError("invalid_cloud_availability")
        _utc("cloud_observed_at", self.observed_at)
        if self.repository is not None and (
            not isinstance(self.repository, str) or not _REPOSITORY_RE.fullmatch(self.repository)
        ):
            raise CloudExecutionError("invalid_cloud_repository")
        if self.workflow_file is not None and self.workflow_file not in _WORKFLOWS:
            raise CloudExecutionError("invalid_cloud_workflow")
        if self.request_digest is not None:
            _digest("cloud_request_digest", self.request_digest)
        if self.dispatch_key is not None and (
            not isinstance(self.dispatch_key, str)
            or not re.fullmatch(r"cloud-run-[0-9a-f]{64}", self.dispatch_key)
        ):
            raise CloudExecutionError("invalid_cloud_dispatch_key")
        if self.run_id is not None and (
            isinstance(self.run_id, bool) or not isinstance(self.run_id, int) or self.run_id <= 0
        ):
            raise CloudExecutionError("invalid_cloud_run_id")
        if self.head_sha is not None:
            _object("cloud_head_sha", self.head_sha)
        if self.status not in {None, "queued", "in_progress", "completed"}:
            raise CloudExecutionError("invalid_cloud_run_status")
        if self.conclusion is not None and self.conclusion not in _CONCLUSIONS:
            raise CloudExecutionError("invalid_cloud_run_conclusion")
        if (
            isinstance(self.attempt, bool)
            or not isinstance(self.attempt, int)
            or not 1 <= self.attempt <= 3
            or isinstance(self.max_attempts, bool)
            or not isinstance(self.max_attempts, int)
            or self.max_attempts != 3
        ):
            raise CloudExecutionError("invalid_cloud_retry_state")
        if self.attempt_key is not None and (
            not isinstance(self.attempt_key, str)
            or not re.fullmatch(r"cloud-run-[0-9a-f]{64}-attempt-[1-3]", self.attempt_key)
        ):
            raise CloudExecutionError("invalid_cloud_attempt_key")
        if (
            not isinstance(self.prior_run_ids, tuple)
            or tuple(sorted(set(self.prior_run_ids))) != self.prior_run_ids
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in self.prior_run_ids
            )
            or len(self.prior_run_ids) > self.attempt - 1
        ):
            raise CloudExecutionError("invalid_cloud_prior_runs")
        if not isinstance(self.artifacts, tuple) or any(
            not isinstance(value, CloudArtifact) for value in self.artifacts
        ):
            raise CloudExecutionError("invalid_cloud_artifacts")
        if self.artifacts_expires_at is not None:
            _utc("cloud_artifacts_expires_at", self.artifacts_expires_at)
        if not isinstance(self.commissioning_actionlint_passed, bool):
            raise CloudExecutionError("invalid_cloud_actionlint_commissioning")
        if self.commissioning_dry_run_id is not None and (
            isinstance(self.commissioning_dry_run_id, bool)
            or not isinstance(self.commissioning_dry_run_id, int)
            or self.commissioning_dry_run_id <= 0
        ):
            raise CloudExecutionError("invalid_cloud_dry_run_id")
        if self.local_fallback_command is not None and (
            not isinstance(self.local_fallback_command, str)
            or not self.local_fallback_command.strip()
            or len(self.local_fallback_command.encode("utf-8")) > 4_096
        ):
            raise CloudExecutionError("invalid_local_fallback_command")


@dataclass(frozen=True, slots=True)
class CloudRunDecision:
    action: CloudRunAction
    reason: str
    repository: str
    workflow_file: str
    request_digest: str
    dispatch_key: str
    run_id: int | None = None
    head_sha: str | None = None
    conclusion: str | None = None
    artifact_id: int | None = None
    artifact_name: str | None = None
    artifact_digest: str | None = None
    next_attempt: int | None = None
    next_attempt_key: str | None = None
    retry_not_before: str | None = None


@dataclass(frozen=True, slots=True)
class CloudRetryState:
    """Minimal restart-safe state for one bounded cloud retry sequence."""

    schema_version: int
    request_digest: str
    revision: int
    attempt: int
    attempt_key: str
    prior_run_ids: tuple[int, ...]
    retry_not_before: str | None

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CloudExecutionError("cloud_retry_state_schema_invalid")
        _digest("cloud_retry_request_digest", self.request_digest)
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 0
        ):
            raise CloudExecutionError("invalid_cloud_retry_revision")
        if (
            isinstance(self.attempt, bool)
            or not isinstance(self.attempt, int)
            or not 1 <= self.attempt <= 3
        ):
            raise CloudExecutionError("invalid_cloud_retry_state")
        expected_key = f"cloud-run-{self.request_digest}-attempt-{self.attempt}"
        if self.attempt_key != expected_key:
            raise CloudExecutionError("invalid_cloud_attempt_key")
        if (
            not isinstance(self.prior_run_ids, tuple)
            or tuple(sorted(set(self.prior_run_ids))) != self.prior_run_ids
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in self.prior_run_ids
            )
            or len(self.prior_run_ids) > self.attempt - 1
        ):
            raise CloudExecutionError("invalid_cloud_prior_runs")
        if self.retry_not_before is not None:
            _utc("cloud_retry_not_before", self.retry_not_before)
        if self.attempt == 1 and self.retry_not_before is not None:
            raise CloudExecutionError("invalid_cloud_retry_state")

    @classmethod
    def initial(cls, request: CloudRunRequest) -> CloudRetryState:
        if not isinstance(request, CloudRunRequest):
            raise CloudExecutionError("invalid_cloud_retry_state")
        return cls(
            schema_version=1,
            request_digest=request.request_digest,
            revision=0,
            attempt=1,
            attempt_key=request.attempt_key(1),
            prior_run_ids=(),
            retry_not_before=None,
        )

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "attempt_key": self.attempt_key,
            "prior_run_ids": list(self.prior_run_ids),
            "request_digest": self.request_digest,
            "retry_not_before": self.retry_not_before,
            "revision": self.revision,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_canonical_dict(cls, value: object) -> CloudRetryState:
        if not isinstance(value, dict) or set(value) != {
            "attempt",
            "attempt_key",
            "prior_run_ids",
            "request_digest",
            "retry_not_before",
            "revision",
            "schema_version",
        }:
            raise CloudExecutionError("cloud_retry_state_invalid")
        prior_run_ids = value["prior_run_ids"]
        if not isinstance(prior_run_ids, list):
            raise CloudExecutionError("cloud_retry_state_invalid")
        try:
            return cls(
                schema_version=value["schema_version"],
                request_digest=value["request_digest"],
                revision=value["revision"],
                attempt=value["attempt"],
                attempt_key=value["attempt_key"],
                prior_run_ids=tuple(prior_run_ids),
                retry_not_before=value["retry_not_before"],
            )
        except TypeError as error:
            raise CloudExecutionError("cloud_retry_state_invalid") from error


def advance_retry_state(
    state: CloudRetryState,
    *,
    request: CloudRunRequest,
    decision: CloudRunDecision,
    prior_run_id: int | None = None,
) -> CloudRetryState:
    """Derive the sole valid successor for a schedule-retry decision."""
    if (
        not isinstance(state, CloudRetryState)
        or not isinstance(request, CloudRunRequest)
        or not isinstance(decision, CloudRunDecision)
        or state.request_digest != request.request_digest
        or decision.request_digest != request.request_digest
        or decision.action != "schedule_retry"
        or decision.next_attempt != state.attempt + 1
        or decision.next_attempt_key != request.attempt_key(state.attempt + 1)
        or decision.retry_not_before is None
    ):
        raise CloudExecutionError("cloud_retry_transition_invalid")
    _utc("cloud_retry_not_before", decision.retry_not_before)
    prior_runs = state.prior_run_ids
    if prior_run_id is not None:
        if isinstance(prior_run_id, bool) or not isinstance(prior_run_id, int) or prior_run_id <= 0:
            raise CloudExecutionError("invalid_cloud_run_id")
        if prior_run_id in prior_runs:
            raise CloudExecutionError("cloud_run_id_reused")
        prior_runs = tuple(sorted((*prior_runs, prior_run_id)))
    return CloudRetryState(
        schema_version=1,
        request_digest=state.request_digest,
        revision=state.revision + 1,
        attempt=decision.next_attempt,
        attempt_key=decision.next_attempt_key,
        prior_run_ids=prior_runs,
        retry_not_before=decision.retry_not_before,
    )


class CloudRetryStateStore:
    """Atomic JSON store with compare-and-swap and idempotent replay."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_name(f"{self.path.name}.lock")

    @contextmanager
    def _locked(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _load_unlocked(self) -> CloudRetryState | None:
        try:
            metadata = self.path.lstat()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise CloudExecutionError("cloud_retry_state_unreadable") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_size > 65_536
        ):
            raise CloudExecutionError("cloud_retry_state_invalid")
        try:
            value = json.loads(self.path.read_bytes())
        except (OSError, json.JSONDecodeError, UnicodeError) as error:
            raise CloudExecutionError("cloud_retry_state_invalid") from error
        return CloudRetryState.from_canonical_dict(value)

    def _write_unlocked(self, state: CloudRetryState) -> None:
        payload = canonical_json_bytes(state.to_canonical_dict()) + b"\n"
        temporary_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.path.parent, prefix=f".{self.path.name}.", delete=False
            ) as target:
                temporary_path = target.name
                os.chmod(target.name, 0o600)
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary_path, self.path)
            temporary_path = None
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as error:
            raise CloudExecutionError("cloud_retry_state_write_failed") from error
        finally:
            if temporary_path is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temporary_path)

    def load(self) -> CloudRetryState | None:
        with self._locked():
            return self._load_unlocked()

    def initialize(self, state: CloudRetryState) -> CloudRetryState:
        if not isinstance(state, CloudRetryState) or state.revision != 0:
            raise CloudExecutionError("cloud_retry_state_invalid")
        with self._locked():
            current = self._load_unlocked()
            if current is None:
                self._write_unlocked(state)
                return state
            if current == state:
                return current
            raise CloudExecutionError("cloud_retry_state_conflict")

    def compare_and_swap(
        self, *, expected: CloudRetryState, replacement: CloudRetryState
    ) -> CloudRetryState:
        if (
            not isinstance(expected, CloudRetryState)
            or not isinstance(replacement, CloudRetryState)
            or replacement.request_digest != expected.request_digest
            or replacement.revision != expected.revision + 1
        ):
            raise CloudExecutionError("cloud_retry_transition_invalid")
        with self._locked():
            current = self._load_unlocked()
            if current == replacement:
                return replacement
            if current != expected:
                raise CloudExecutionError("cloud_retry_state_conflict")
            self._write_unlocked(replacement)
            return replacement


def _decision(
    action: CloudRunAction,
    reason: str,
    request: CloudRunRequest,
    snapshot: CloudRunSnapshot,
    *,
    artifact: CloudArtifact | None = None,
    next_attempt: int | None = None,
    retry_not_before: str | None = None,
) -> CloudRunDecision:
    return CloudRunDecision(
        action=action,
        reason=reason,
        repository=request.repository,
        workflow_file=request.workflow_file,
        request_digest=request.request_digest,
        dispatch_key=request.dispatch_key,
        run_id=snapshot.run_id,
        head_sha=snapshot.head_sha,
        conclusion=snapshot.conclusion,
        artifact_id=artifact.artifact_id if artifact is not None else None,
        artifact_name=artifact.name if artifact is not None else None,
        artifact_digest=artifact.digest if artifact is not None else None,
        next_attempt=next_attempt,
        next_attempt_key=(request.attempt_key(next_attempt) if next_attempt is not None else None),
        retry_not_before=retry_not_before,
    )


def _retry_decision(
    reason: str, request: CloudRunRequest, snapshot: CloudRunSnapshot
) -> CloudRunDecision:
    if snapshot.attempt >= snapshot.max_attempts:
        return _decision("blocked", "cloud_retry_budget_exhausted", request, snapshot)
    observed = _utc("cloud_observed_at", snapshot.observed_at)
    delay_minutes = 5 * snapshot.attempt
    retry_at = (observed + timedelta(minutes=delay_minutes)).isoformat().replace(
        "+00:00", "Z"
    )
    return _decision(
        "schedule_retry",
        reason,
        request,
        snapshot,
        next_attempt=snapshot.attempt + 1,
        retry_not_before=retry_at,
    )


def _binding_failure(
    request: CloudRunRequest, snapshot: CloudRunSnapshot
) -> tuple[str | None, bool]:
    bindings = (
        (snapshot.repository, request.repository, "cloud_run_repository_mismatch"),
        (snapshot.workflow_file, request.workflow_file, "cloud_run_workflow_mismatch"),
        (snapshot.request_digest, request.request_digest, "cloud_run_request_mismatch"),
        (snapshot.dispatch_key, request.dispatch_key, "cloud_run_dispatch_key_mismatch"),
    )
    present = 0
    for actual, expected, reason in bindings:
        if actual is None:
            continue
        present += 1
        if actual != expected:
            return reason, False
    if snapshot.head_sha is not None and snapshot.head_sha != request.candidate_commit:
        return "cloud_run_head_mismatch", False
    complete = present == len(bindings)
    return None, complete


def reconcile_cloud_run(
    request: CloudRunRequest, snapshot: CloudRunSnapshot
) -> CloudRunDecision:
    """Choose one restart-safe control-plane action without executing local work."""
    if not isinstance(request, CloudRunRequest) or not isinstance(snapshot, CloudRunSnapshot):
        raise CloudExecutionError("invalid_cloud_reconciliation")
    if (
        snapshot.local_fallback_command is not None
        and _HEAVY_LOCAL_RE.search(snapshot.local_fallback_command)
    ):
        return _decision("blocked", "local_heavy_fallback_forbidden", request, snapshot)
    if snapshot.attempt_key is not None and snapshot.attempt_key != request.attempt_key(
        snapshot.attempt
    ):
        return _decision("blocked", "cloud_attempt_key_mismatch", request, snapshot)
    if snapshot.attempt_key is None and not snapshot.remote_available:
        return _decision("blocked", "cloud_attempt_key_missing", request, snapshot)
    if not snapshot.remote_available:
        return _retry_decision("cloud_execution_unavailable", request, snapshot)

    failure, bindings_complete = _binding_failure(request, snapshot)
    if failure is not None:
        return _decision("blocked", failure, request, snapshot)
    if bindings_complete and snapshot.attempt_key is None:
        return _decision("blocked", "cloud_attempt_key_missing", request, snapshot)
    if snapshot.run_id is None:
        if bindings_complete:
            return _decision("await_run", "cloud_dispatch_already_accepted", request, snapshot)
        if any(
            value is not None
            for value in (
                snapshot.repository,
                snapshot.workflow_file,
                snapshot.request_digest,
                snapshot.dispatch_key,
                snapshot.head_sha,
                snapshot.status,
                snapshot.conclusion,
            )
        ):
            return _decision("blocked", "cloud_run_binding_incomplete", request, snapshot)
        return _decision("dispatch", "cloud_dispatch_required", request, snapshot)
    if not bindings_complete:
        return _decision("blocked", "cloud_run_binding_incomplete", request, snapshot)
    if snapshot.attempt_key is None:
        return _decision("blocked", "cloud_attempt_key_missing", request, snapshot)
    if snapshot.run_id in snapshot.prior_run_ids:
        return _decision("blocked", "cloud_run_id_reused", request, snapshot)
    if snapshot.head_sha is None:
        return _decision("blocked", "cloud_run_head_missing", request, snapshot)
    if snapshot.status in _RUNNING_STATUSES:
        return _decision("await_run", "cloud_run_in_progress", request, snapshot)
    if snapshot.status != "completed" or snapshot.conclusion is None:
        return _decision("blocked", "cloud_run_state_incomplete", request, snapshot)
    if snapshot.conclusion in _INFRASTRUCTURE_CONCLUSIONS:
        return _retry_decision("cloud_run_infrastructure_failure", request, snapshot)
    if snapshot.conclusion != "success":
        return _decision("blocked", "cloud_run_failed", request, snapshot)
    if not snapshot.commissioning_actionlint_passed:
        return _decision("blocked", "cloud_actionlint_not_commissioned", request, snapshot)
    if snapshot.commissioning_dry_run_id is None:
        return _decision("blocked", "cloud_github_dry_run_not_commissioned", request, snapshot)
    if not snapshot.artifacts or snapshot.artifacts_expires_at is None:
        return _decision("blocked", "cloud_artifact_identity_missing", request, snapshot)
    if len(snapshot.artifacts) != 1:
        return _decision("blocked", "cloud_artifact_count_mismatch", request, snapshot)
    artifact = snapshot.artifacts[0]
    if artifact.name != request.expected_artifact_name:
        return _decision("blocked", "cloud_artifact_name_mismatch", request, snapshot)
    if artifact.run_id != snapshot.run_id:
        return _decision("blocked", "cloud_artifact_run_mismatch", request, snapshot)
    if _utc("cloud_artifacts_expires_at", snapshot.artifacts_expires_at) <= _utc(
        "cloud_observed_at", snapshot.observed_at
    ):
        return _decision("blocked", "cloud_artifact_expired", request, snapshot)
    if artifact.downloaded_digest is None:
        return _decision(
            "download_artifacts",
            "cloud_artifact_download_required",
            request,
            snapshot,
            artifact=artifact,
        )
    if artifact.downloaded_digest != artifact.digest:
        return _decision("blocked", "cloud_artifact_digest_mismatch", request, snapshot)
    return _decision(
        "record_success", "cloud_run_evidence_verified", request, snapshot, artifact=artifact
    )
