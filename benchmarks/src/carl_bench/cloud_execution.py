"""Deterministic reconciliation for credential-free GitHub-hosted execution."""

from __future__ import annotations

import base64
import binascii
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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from carl_bench.canonical import canonical_json_bytes

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HEAVY_LOCAL_RE = re.compile(
    r"(?:^|[/\s])(?:cargo|pytest|docker|colima)(?:-[A-Za-z0-9_.-]+)?(?=$|[/\s])"
    r"|\bbenchmarks?\b|\bsoak\b",
    re.IGNORECASE,
)
_WORKFLOWS = frozenset({"autonomous-improvement.yml", "autonomous-soak.yml"})
_WORKFLOW_PATHS = {
    workflow_file: f".github/workflows/{workflow_file}" for workflow_file in _WORKFLOWS
}
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
    workflow_revision: str,
    workflow_blob_digest: str,
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
        "workflow_revision": workflow_revision,
        "workflow_blob_digest": workflow_blob_digest,
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
    workflow_revision: str
    workflow_blob_digest: str
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
            "workflow_blob_digest",
            "request_digest",
        ):
            _digest(name, getattr(self, name))
        _object("parent_commit", self.parent_commit)
        _object("candidate_commit", self.candidate_commit)
        _object("workflow_revision", self.workflow_revision)
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
                workflow_revision=self.workflow_revision,
                workflow_blob_digest=self.workflow_blob_digest,
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
        workflow_revision: str,
        workflow_blob_digest: str,
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
            workflow_revision=workflow_revision,
            workflow_blob_digest=workflow_blob_digest,
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
            workflow_revision=workflow_revision,
            workflow_blob_digest=workflow_blob_digest,
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

    @property
    def expected_workflow_path(self) -> str:
        return _WORKFLOW_PATHS[self.workflow_file]

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
class CommissioningReceipt:
    """Verified GitHub-hosted run identity required before cloud evidence is trusted."""

    schema_version: int
    repository: str
    workflow_file: str
    workflow_path: str
    workflow_revision: str
    workflow_blob_digest: str
    request_digest: str
    experiment_digest: str
    task_set_digest: str
    metric_pack_digest: str
    policy_digest: str
    run_id: int
    status: str
    conclusion: str
    observed_at: str
    artifact_id: int
    artifact_name: str
    artifact_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != 2:
            raise CloudExecutionError("cloud_commissioning_schema_invalid")
        if not isinstance(self.repository, str) or not _REPOSITORY_RE.fullmatch(self.repository):
            raise CloudExecutionError("invalid_cloud_commissioning_repository")
        if self.workflow_file not in _WORKFLOWS:
            raise CloudExecutionError("invalid_cloud_commissioning_workflow")
        if self.workflow_path != _WORKFLOW_PATHS[self.workflow_file]:
            raise CloudExecutionError("invalid_cloud_commissioning_workflow_path")
        _object("cloud_commissioning_workflow_revision", self.workflow_revision)
        for name in (
            "workflow_blob_digest",
            "request_digest",
            "experiment_digest",
            "task_set_digest",
            "metric_pack_digest",
            "policy_digest",
            "artifact_digest",
        ):
            _digest(f"cloud_commissioning_{name}", getattr(self, name))
        for name in ("run_id", "artifact_id"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise CloudExecutionError(f"invalid_cloud_commissioning_{name}")
        if self.status != "completed":
            raise CloudExecutionError("cloud_commissioning_run_not_completed")
        if self.conclusion != "success":
            raise CloudExecutionError("cloud_commissioning_run_not_successful")
        _utc("cloud_commissioning_observed_at", self.observed_at)
        if (
            not isinstance(self.artifact_name, str)
            or not self.artifact_name
            or len(self.artifact_name.encode("utf-8")) > 180
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", self.artifact_name)
        ):
            raise CloudExecutionError("invalid_cloud_commissioning_artifact_name")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class SignedCommissioningReceipt:
    receipt: CommissioningReceipt
    receipt_digest: str
    key_id: str
    signature_base64: str

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, CommissioningReceipt):
            raise CloudExecutionError("invalid_cloud_commissioning_receipt")
        _digest("cloud_commissioning_receipt_digest", self.receipt_digest)
        if not isinstance(self.key_id, str) or not _KEY_ID_RE.fullmatch(self.key_id):
            raise CloudExecutionError("invalid_cloud_commissioning_key_id")
        try:
            signature = base64.b64decode(self.signature_base64, validate=True)
        except (ValueError, binascii.Error) as error:
            raise CloudExecutionError("invalid_cloud_commissioning_signature") from error
        if len(signature) != 64:
            raise CloudExecutionError("invalid_cloud_commissioning_signature")

    @property
    def signature(self) -> bytes:
        return base64.b64decode(self.signature_base64, validate=True)


@dataclass(frozen=True, slots=True)
class CompletedRunObservation:
    """Canonical protected-observer fact for one completed infrastructure failure."""

    schema_version: int
    run_id: int
    repository: str
    workflow_revision: str
    workflow_path: str
    workflow_blob_digest: str
    request_digest: str
    status: str
    infrastructure_conclusion: str
    observed_at: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CloudExecutionError("cloud_completed_run_schema_invalid")
        if isinstance(self.run_id, bool) or not isinstance(self.run_id, int) or self.run_id <= 0:
            raise CloudExecutionError("invalid_cloud_run_id")
        if not isinstance(self.repository, str) or not _REPOSITORY_RE.fullmatch(self.repository):
            raise CloudExecutionError("invalid_cloud_completed_run_repository")
        _object("cloud_completed_run_workflow_revision", self.workflow_revision)
        if self.workflow_path not in _WORKFLOW_PATHS.values():
            raise CloudExecutionError("invalid_cloud_completed_run_workflow_path")
        _digest("cloud_completed_run_workflow_blob_digest", self.workflow_blob_digest)
        _digest("cloud_completed_run_request_digest", self.request_digest)
        if self.status != "completed":
            raise CloudExecutionError("cloud_completed_run_not_completed")
        if self.infrastructure_conclusion not in _INFRASTRUCTURE_CONCLUSIONS:
            raise CloudExecutionError("cloud_completed_run_not_infrastructure_failure")
        _utc("cloud_completed_run_observed_at", self.observed_at)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class SignedCompletedRunObservation:
    observation: CompletedRunObservation
    observation_digest: str
    key_id: str
    signature_base64: str

    def __post_init__(self) -> None:
        if not isinstance(self.observation, CompletedRunObservation):
            raise CloudExecutionError("invalid_cloud_completed_run_observation")
        _digest("cloud_completed_run_observation_digest", self.observation_digest)
        if not isinstance(self.key_id, str) or not _KEY_ID_RE.fullmatch(self.key_id):
            raise CloudExecutionError("invalid_cloud_completed_run_key_id")
        try:
            signature = base64.b64decode(self.signature_base64, validate=True)
        except (ValueError, binascii.Error) as error:
            raise CloudExecutionError("invalid_cloud_completed_run_signature") from error
        if len(signature) != 64:
            raise CloudExecutionError("invalid_cloud_completed_run_signature")

    @property
    def signature(self) -> bytes:
        return base64.b64decode(self.signature_base64, validate=True)


@dataclass(frozen=True, slots=True)
class TrustedCloudReceiptKey:
    """Configured verifier identity; private signing material never enters this object."""

    key_id: str
    public_key_pem: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or not _KEY_ID_RE.fullmatch(self.key_id):
            raise CloudExecutionError("invalid_cloud_trusted_key_id")
        if not isinstance(self.public_key_pem, bytes):
            raise CloudExecutionError("cloud_trusted_public_key_invalid")
        try:
            public_key = serialization.load_pem_public_key(self.public_key_pem)
        except (TypeError, ValueError) as error:
            raise CloudExecutionError("cloud_trusted_public_key_invalid") from error
        if not isinstance(public_key, Ed25519PublicKey):
            raise CloudExecutionError("cloud_trusted_public_key_invalid")

    @property
    def public_key(self) -> Ed25519PublicKey:
        public_key = serialization.load_pem_public_key(self.public_key_pem)
        if not isinstance(public_key, Ed25519PublicKey):  # pragma: no cover - constructor guards
            raise CloudExecutionError("cloud_trusted_public_key_invalid")
        return public_key


def _signed_payload_failure(
    *,
    payload: dict[str, Any],
    claimed_digest: str,
    key_id: str,
    signature: bytes,
    trusted_key: TrustedCloudReceiptKey | None,
    prefix: str,
) -> str | None:
    if trusted_key is None:
        return f"{prefix}_trusted_key_missing"
    if key_id != trusted_key.key_id:
        return f"{prefix}_key_mismatch"
    encoded = canonical_json_bytes(payload)
    if hashlib.sha256(encoded).hexdigest() != claimed_digest:
        return f"{prefix}_digest_mismatch"
    try:
        trusted_key.public_key.verify(signature, encoded)
    except InvalidSignature:
        return f"{prefix}_signature_invalid"
    return None


@dataclass(frozen=True, slots=True)
class CloudRunSnapshot:
    remote_available: bool
    observed_at: str
    repository: str | None = None
    workflow_file: str | None = None
    workflow_path: str | None = None
    workflow_blob_digest: str | None = None
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
    commissioning_receipt: CommissioningReceipt | SignedCommissioningReceipt | None = None
    completed_run_observation: (
        CompletedRunObservation | SignedCompletedRunObservation | None
    ) = None
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
        if self.workflow_path is not None and self.workflow_path not in _WORKFLOW_PATHS.values():
            raise CloudExecutionError("invalid_cloud_workflow_path")
        if self.workflow_blob_digest is not None:
            _digest("cloud_workflow_blob_digest", self.workflow_blob_digest)
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
        if self.commissioning_receipt is not None and not isinstance(
            self.commissioning_receipt,
            CommissioningReceipt | SignedCommissioningReceipt,
        ):
            raise CloudExecutionError("invalid_cloud_commissioning_receipt")
        if self.completed_run_observation is not None and not isinstance(
            self.completed_run_observation,
            CompletedRunObservation | SignedCompletedRunObservation,
        ):
            raise CloudExecutionError("invalid_cloud_completed_run_observation")
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
    workflow_revision: str
    workflow_path: str
    workflow_blob_digest: str
    candidate_commit: str
    run_id: int | None = None
    head_sha: str | None = None
    conclusion: str | None = None
    artifact_id: int | None = None
    artifact_name: str | None = None
    artifact_digest: str | None = None
    next_attempt: int | None = None
    next_attempt_key: str | None = None
    retry_not_before: str | None = None
    observed_at: str | None = None
    completed_run_observation_digest: str | None = None


@dataclass(frozen=True, slots=True)
class CloudRetryState:
    """Minimal restart-safe state for one bounded cloud retry sequence."""

    schema_version: int
    request_digest: str
    revision: int
    attempt: int
    attempt_key: str
    prior_run_ids: tuple[int, ...]
    prior_observation_digests: tuple[str, ...]
    retry_not_before: str | None

    def __post_init__(self) -> None:
        if self.schema_version != 2:
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
            or len(set(self.prior_run_ids)) != len(self.prior_run_ids)
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in self.prior_run_ids
            )
            or len(self.prior_run_ids) != self.attempt - 1
        ):
            raise CloudExecutionError("invalid_cloud_prior_runs")
        if (
            not isinstance(self.prior_observation_digests, tuple)
            or len(self.prior_observation_digests) != len(self.prior_run_ids)
        ):
            raise CloudExecutionError("invalid_cloud_prior_observations")
        for digest in self.prior_observation_digests:
            _digest("cloud_prior_observation_digest", digest)
        if len(set(self.prior_observation_digests)) != len(
            self.prior_observation_digests
        ):
            raise CloudExecutionError("invalid_cloud_prior_observations")
        if self.retry_not_before is not None:
            _utc("cloud_retry_not_before", self.retry_not_before)
        if (self.attempt == 1) != (self.retry_not_before is None):
            raise CloudExecutionError("invalid_cloud_retry_state")

    @classmethod
    def initial(cls, request: CloudRunRequest) -> CloudRetryState:
        if not isinstance(request, CloudRunRequest):
            raise CloudExecutionError("invalid_cloud_retry_state")
        return cls(
            schema_version=2,
            request_digest=request.request_digest,
            revision=0,
            attempt=1,
            attempt_key=request.attempt_key(1),
            prior_run_ids=(),
            prior_observation_digests=(),
            retry_not_before=None,
        )

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "attempt_key": self.attempt_key,
            "prior_observation_digests": list(self.prior_observation_digests),
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
            "prior_observation_digests",
            "prior_run_ids",
            "request_digest",
            "retry_not_before",
            "revision",
            "schema_version",
        }:
            raise CloudExecutionError("cloud_retry_state_invalid")
        prior_run_ids = value["prior_run_ids"]
        prior_observation_digests = value["prior_observation_digests"]
        if not isinstance(prior_run_ids, list) or not isinstance(
            prior_observation_digests, list
        ):
            raise CloudExecutionError("cloud_retry_state_invalid")
        try:
            return cls(
                schema_version=value["schema_version"],
                request_digest=value["request_digest"],
                revision=value["revision"],
                attempt=value["attempt"],
                attempt_key=value["attempt_key"],
                prior_run_ids=tuple(prior_run_ids),
                prior_observation_digests=tuple(prior_observation_digests),
                retry_not_before=value["retry_not_before"],
            )
        except TypeError as error:
            raise CloudExecutionError("cloud_retry_state_invalid") from error


def advance_retry_state(
    state: CloudRetryState,
    *,
    request: CloudRunRequest,
    decision: CloudRunDecision,
    prior_run_id: int,
    completed_run_observation: (
        CompletedRunObservation | SignedCompletedRunObservation | None
    ) = None,
    trusted_receipt_key: TrustedCloudReceiptKey | None = None,
) -> CloudRetryState:
    """Derive the sole valid successor for a schedule-retry decision."""
    if completed_run_observation is None:
        raise CloudExecutionError("cloud_completed_run_observation_missing")
    observation_failure = _completed_run_transition_failure(
        completed_run_observation,
        trusted_receipt_key,
        decision,
    )
    if observation_failure is not None:
        raise CloudExecutionError(observation_failure)
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
    if isinstance(prior_run_id, bool) or not isinstance(prior_run_id, int) or prior_run_id <= 0:
        raise CloudExecutionError("invalid_cloud_run_id")
    if decision.run_id != prior_run_id:
        raise CloudExecutionError("cloud_retry_prior_run_mismatch")
    if prior_run_id in state.prior_run_ids:
        raise CloudExecutionError("cloud_run_id_reused")
    assert isinstance(completed_run_observation, SignedCompletedRunObservation)
    observation_digest = completed_run_observation.observation_digest
    if observation_digest in state.prior_observation_digests:
        raise CloudExecutionError("cloud_completed_run_observation_reused")
    prior_runs = (*state.prior_run_ids, prior_run_id)
    prior_observations = (*state.prior_observation_digests, observation_digest)
    return CloudRetryState(
        schema_version=2,
        request_digest=state.request_digest,
        revision=state.revision + 1,
        attempt=decision.next_attempt,
        attempt_key=decision.next_attempt_key,
        prior_run_ids=prior_runs,
        prior_observation_digests=prior_observations,
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
        self,
        *,
        expected: CloudRetryState,
        replacement: CloudRetryState,
        retry_decision: CloudRunDecision,
        completed_run_observation: (
            CompletedRunObservation | SignedCompletedRunObservation | None
        ) = None,
        trusted_receipt_key: TrustedCloudReceiptKey | None = None,
    ) -> CloudRetryState:
        if (
            not isinstance(expected, CloudRetryState)
            or not isinstance(replacement, CloudRetryState)
            or not isinstance(retry_decision, CloudRunDecision)
            or replacement.request_digest != expected.request_digest
            or replacement.revision != expected.revision + 1
            or expected.attempt >= 3
            or replacement.attempt != expected.attempt + 1
            or replacement.attempt_key
            != f"cloud-run-{expected.request_digest}-attempt-{expected.attempt + 1}"
            or replacement.retry_not_before is None
            or retry_decision.action != "schedule_retry"
            or retry_decision.request_digest != expected.request_digest
            or retry_decision.next_attempt != replacement.attempt
            or retry_decision.next_attempt_key != replacement.attempt_key
            or retry_decision.retry_not_before != replacement.retry_not_before
            or retry_decision.run_id is None
            or retry_decision.conclusion not in _INFRASTRUCTURE_CONCLUSIONS
            or replacement.prior_run_ids[:-1] != expected.prior_run_ids
            or len(replacement.prior_run_ids) != len(expected.prior_run_ids) + 1
            or replacement.prior_run_ids[-1] != retry_decision.run_id
            or retry_decision.run_id in expected.prior_run_ids
            or replacement.prior_observation_digests[:-1]
            != expected.prior_observation_digests
            or len(replacement.prior_observation_digests)
            != len(expected.prior_observation_digests) + 1
            or retry_decision.completed_run_observation_digest is None
            or replacement.prior_observation_digests[-1]
            != retry_decision.completed_run_observation_digest
            or retry_decision.completed_run_observation_digest
            in expected.prior_observation_digests
        ):
            raise CloudExecutionError("cloud_retry_transition_invalid")
        with self._locked():
            observation_failure = _completed_run_transition_failure(
                completed_run_observation,
                trusted_receipt_key,
                retry_decision,
            )
            if observation_failure is not None:
                raise CloudExecutionError(observation_failure)
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
        workflow_revision=request.workflow_revision,
        workflow_path=request.expected_workflow_path,
        workflow_blob_digest=request.workflow_blob_digest,
        candidate_commit=request.candidate_commit,
        run_id=snapshot.run_id,
        head_sha=snapshot.head_sha,
        conclusion=snapshot.conclusion,
        artifact_id=artifact.artifact_id if artifact is not None else None,
        artifact_name=artifact.name if artifact is not None else None,
        artifact_digest=artifact.digest if artifact is not None else None,
        next_attempt=next_attempt,
        next_attempt_key=(request.attempt_key(next_attempt) if next_attempt is not None else None),
        retry_not_before=retry_not_before,
        observed_at=snapshot.observed_at,
        completed_run_observation_digest=(
            snapshot.completed_run_observation.observation_digest
            if isinstance(snapshot.completed_run_observation, SignedCompletedRunObservation)
            else None
        ),
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


def _verified_completed_run_observation(
    value: CompletedRunObservation | SignedCompletedRunObservation | None,
    trusted_receipt_key: TrustedCloudReceiptKey | None,
) -> tuple[CompletedRunObservation | None, str | None]:
    if value is None:
        return None, "cloud_completed_run_observation_missing"
    if isinstance(value, CompletedRunObservation):
        return None, "cloud_completed_run_signature_missing"
    try:
        signature = value.signature
    except (ValueError, binascii.Error):
        return None, "cloud_completed_run_signature_invalid"
    if len(signature) != 64:
        return None, "cloud_completed_run_signature_invalid"
    failure = _signed_payload_failure(
        payload=value.observation.to_canonical_dict(),
        claimed_digest=value.observation_digest,
        key_id=value.key_id,
        signature=signature,
        trusted_key=trusted_receipt_key,
        prefix="cloud_completed_run",
    )
    if failure is not None:
        return None, failure
    return value.observation, None


def _completed_run_snapshot_failure(
    request: CloudRunRequest,
    snapshot: CloudRunSnapshot,
    trusted_receipt_key: TrustedCloudReceiptKey | None,
) -> str | None:
    observation, failure = _verified_completed_run_observation(
        snapshot.completed_run_observation,
        trusted_receipt_key,
    )
    if failure is not None:
        return failure
    assert observation is not None
    bindings: tuple[tuple[object, object, str], ...] = (
        (observation.run_id, snapshot.run_id, "cloud_completed_run_id_mismatch"),
        (
            observation.repository,
            request.repository,
            "cloud_completed_run_repository_mismatch",
        ),
        (
            observation.workflow_revision,
            request.workflow_revision,
            "cloud_completed_run_revision_mismatch",
        ),
        (
            observation.workflow_path,
            request.expected_workflow_path,
            "cloud_completed_run_workflow_path_mismatch",
        ),
        (
            observation.workflow_blob_digest,
            request.workflow_blob_digest,
            "cloud_completed_run_workflow_blob_mismatch",
        ),
        (
            observation.request_digest,
            request.request_digest,
            "cloud_completed_run_request_mismatch",
        ),
        (observation.status, snapshot.status, "cloud_completed_run_status_mismatch"),
        (
            observation.infrastructure_conclusion,
            snapshot.conclusion,
            "cloud_completed_run_conclusion_mismatch",
        ),
        (
            observation.observed_at,
            snapshot.observed_at,
            "cloud_completed_run_observed_at_mismatch",
        ),
    )
    return next((reason for actual, expected, reason in bindings if actual != expected), None)


def _completed_run_transition_failure(
    value: CompletedRunObservation | SignedCompletedRunObservation | None,
    trusted_receipt_key: TrustedCloudReceiptKey | None,
    decision: CloudRunDecision,
) -> str | None:
    observation, failure = _verified_completed_run_observation(value, trusted_receipt_key)
    if failure is not None:
        return failure
    assert observation is not None
    envelope = value
    assert isinstance(envelope, SignedCompletedRunObservation)
    bindings: tuple[tuple[object, object, str], ...] = (
        (
            decision.completed_run_observation_digest,
            envelope.observation_digest,
            "cloud_retry_observation_digest_mismatch",
        ),
        (observation.run_id, decision.run_id, "cloud_retry_prior_run_mismatch"),
        (observation.repository, decision.repository, "cloud_retry_repository_mismatch"),
        (
            observation.workflow_revision,
            decision.workflow_revision,
            "cloud_retry_workflow_revision_mismatch",
        ),
        (
            observation.workflow_path,
            decision.workflow_path,
            "cloud_retry_workflow_path_mismatch",
        ),
        (
            observation.workflow_blob_digest,
            decision.workflow_blob_digest,
            "cloud_retry_workflow_blob_mismatch",
        ),
        (
            observation.request_digest,
            decision.request_digest,
            "cloud_retry_request_mismatch",
        ),
        (observation.status, "completed", "cloud_retry_run_not_completed"),
        (
            observation.infrastructure_conclusion,
            decision.conclusion,
            "cloud_retry_conclusion_mismatch",
        ),
        (
            observation.observed_at,
            decision.observed_at,
            "cloud_retry_observed_at_mismatch",
        ),
    )
    return next((reason for actual, expected, reason in bindings if actual != expected), None)


def _binding_failure(
    request: CloudRunRequest, snapshot: CloudRunSnapshot
) -> tuple[str | None, bool]:
    dispatch_bindings = (
        (snapshot.repository, request.repository, "cloud_run_repository_mismatch"),
        (snapshot.workflow_file, request.workflow_file, "cloud_run_workflow_mismatch"),
        (snapshot.request_digest, request.request_digest, "cloud_run_request_mismatch"),
        (snapshot.dispatch_key, request.dispatch_key, "cloud_run_dispatch_key_mismatch"),
    )
    run_bindings = (
        (
            snapshot.workflow_path,
            request.expected_workflow_path,
            "cloud_run_workflow_path_mismatch",
        ),
        (
            snapshot.workflow_blob_digest,
            request.workflow_blob_digest,
            "cloud_run_workflow_blob_mismatch",
        ),
    )
    bindings = dispatch_bindings + run_bindings
    for actual, expected, reason in bindings:
        if actual is None:
            continue
        if actual != expected:
            return reason, False
    if snapshot.head_sha is not None and snapshot.head_sha != request.workflow_revision:
        return "cloud_run_head_mismatch", False
    required = dispatch_bindings if snapshot.run_id is None else bindings
    complete = all(actual is not None for actual, _, _ in required)
    return None, complete


def _commissioning_failure(
    request: CloudRunRequest,
    snapshot: CloudRunSnapshot,
    artifact: CloudArtifact,
    trusted_receipt_key: TrustedCloudReceiptKey | None,
) -> str | None:
    envelope = snapshot.commissioning_receipt
    if envelope is None:
        return "cloud_commissioning_receipt_missing"
    if isinstance(envelope, CommissioningReceipt):
        return "cloud_commissioning_signature_missing"
    try:
        signature = envelope.signature
    except (ValueError, binascii.Error):
        return "cloud_commissioning_signature_invalid"
    if len(signature) != 64:
        return "cloud_commissioning_signature_invalid"
    signature_failure = _signed_payload_failure(
        payload=envelope.receipt.to_canonical_dict(),
        claimed_digest=envelope.receipt_digest,
        key_id=envelope.key_id,
        signature=signature,
        trusted_key=trusted_receipt_key,
        prefix="cloud_commissioning",
    )
    if signature_failure is not None:
        return signature_failure
    receipt = envelope.receipt
    bindings: tuple[tuple[object, object, str], ...] = (
        (receipt.repository, request.repository, "cloud_commissioning_repository_mismatch"),
        (receipt.workflow_file, request.workflow_file, "cloud_commissioning_workflow_mismatch"),
        (
            receipt.workflow_path,
            request.expected_workflow_path,
            "cloud_commissioning_workflow_path_mismatch",
        ),
        (
            receipt.workflow_revision,
            request.workflow_revision,
            "cloud_commissioning_revision_mismatch",
        ),
        (
            receipt.workflow_blob_digest,
            request.workflow_blob_digest,
            "cloud_commissioning_blob_mismatch",
        ),
        (receipt.request_digest, request.request_digest, "cloud_commissioning_request_mismatch"),
        (
            receipt.experiment_digest,
            request.experiment_digest,
            "cloud_commissioning_experiment_mismatch",
        ),
        (
            receipt.task_set_digest,
            request.task_set_digest,
            "cloud_commissioning_task_set_mismatch",
        ),
        (
            receipt.metric_pack_digest,
            request.metric_pack_digest,
            "cloud_commissioning_metric_pack_mismatch",
        ),
        (
            receipt.policy_digest,
            request.policy_digest,
            "cloud_commissioning_policy_mismatch",
        ),
        (receipt.run_id, snapshot.run_id, "cloud_commissioning_run_mismatch"),
        (receipt.status, snapshot.status, "cloud_commissioning_status_mismatch"),
        (receipt.conclusion, snapshot.conclusion, "cloud_commissioning_conclusion_mismatch"),
        (
            receipt.observed_at,
            snapshot.observed_at,
            "cloud_commissioning_observed_at_mismatch",
        ),
        (
            receipt.artifact_id,
            artifact.artifact_id,
            "cloud_commissioning_artifact_id_mismatch",
        ),
        (
            receipt.artifact_name,
            artifact.name,
            "cloud_commissioning_artifact_name_mismatch",
        ),
        (
            receipt.artifact_digest,
            artifact.digest,
            "cloud_commissioning_artifact_digest_mismatch",
        ),
    )
    return next((reason for actual, expected, reason in bindings if actual != expected), None)


def reconcile_cloud_run(
    request: CloudRunRequest,
    snapshot: CloudRunSnapshot,
    *,
    trusted_receipt_key: TrustedCloudReceiptKey | None = None,
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
    if snapshot.workflow_path is None:
        return _decision("blocked", "cloud_run_workflow_path_missing", request, snapshot)
    if snapshot.workflow_blob_digest is None:
        return _decision("blocked", "cloud_run_workflow_blob_missing", request, snapshot)
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
        observation_failure = _completed_run_snapshot_failure(
            request,
            snapshot,
            trusted_receipt_key,
        )
        if observation_failure is not None:
            return _decision("blocked", observation_failure, request, snapshot)
        return _retry_decision("cloud_run_infrastructure_failure", request, snapshot)
    if snapshot.conclusion != "success":
        return _decision("blocked", "cloud_run_failed", request, snapshot)
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
    commissioning_failure = _commissioning_failure(
        request,
        snapshot,
        artifact,
        trusted_receipt_key,
    )
    if commissioning_failure is not None:
        return _decision("blocked", commissioning_failure, request, snapshot)
    return _decision(
        "record_success", "cloud_run_evidence_verified", request, snapshot, artifact=artifact
    )
