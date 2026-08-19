"""Deterministic reconciliation for credential-free GitHub-hosted execution."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
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
    artifact_digests: tuple[str, ...] = ()
    downloaded_artifact_digests: tuple[str, ...] = ()
    artifacts_expires_at: str | None = None
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
        if not isinstance(self.artifact_digests, tuple) or not isinstance(
            self.downloaded_artifact_digests, tuple
        ):
            raise CloudExecutionError("invalid_cloud_artifact_digests")
        for values in (self.artifact_digests, self.downloaded_artifact_digests):
            if tuple(sorted(set(values))) != values:
                raise CloudExecutionError("invalid_cloud_artifact_digests")
            for value in values:
                _digest("cloud_artifact_digest", value)
        if self.artifacts_expires_at is not None:
            _utc("cloud_artifacts_expires_at", self.artifacts_expires_at)
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
    artifact_digests: tuple[str, ...] = ()


def _decision(
    action: CloudRunAction,
    reason: str,
    request: CloudRunRequest,
    snapshot: CloudRunSnapshot,
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
        artifact_digests=snapshot.artifact_digests,
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
    if not snapshot.remote_available:
        return _decision("schedule_retry", "cloud_execution_unavailable", request, snapshot)

    failure, bindings_complete = _binding_failure(request, snapshot)
    if failure is not None:
        return _decision("blocked", failure, request, snapshot)
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
    if snapshot.head_sha is None:
        return _decision("blocked", "cloud_run_head_missing", request, snapshot)
    if snapshot.status in _RUNNING_STATUSES:
        return _decision("await_run", "cloud_run_in_progress", request, snapshot)
    if snapshot.status != "completed" or snapshot.conclusion is None:
        return _decision("blocked", "cloud_run_state_incomplete", request, snapshot)
    if snapshot.conclusion in _INFRASTRUCTURE_CONCLUSIONS:
        return _decision("schedule_retry", "cloud_run_infrastructure_failure", request, snapshot)
    if snapshot.conclusion != "success":
        return _decision("blocked", "cloud_run_failed", request, snapshot)
    if not snapshot.artifact_digests or snapshot.artifacts_expires_at is None:
        return _decision("blocked", "cloud_artifact_identity_missing", request, snapshot)
    if _utc("cloud_artifacts_expires_at", snapshot.artifacts_expires_at) <= _utc(
        "cloud_observed_at", snapshot.observed_at
    ):
        return _decision("blocked", "cloud_artifact_expired", request, snapshot)
    if not snapshot.downloaded_artifact_digests:
        return _decision(
            "download_artifacts", "cloud_artifact_download_required", request, snapshot
        )
    if snapshot.downloaded_artifact_digests != snapshot.artifact_digests:
        return _decision("blocked", "cloud_artifact_digest_mismatch", request, snapshot)
    return _decision("record_success", "cloud_run_evidence_verified", request, snapshot)
