"""Independent GitHub run observer for trusted cloud evidence."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from carl_bench.cloud_execution import (
    CloudExecutionError,
    CloudRunRequest,
    CommissioningReceipt,
    SignedCommissioningReceipt,
    decode_cloud_wire_json,
)
from carl_bench.cloud_signer import CloudReceiptSigner
from carl_bench.evidence_archive import ArchivedEvidence, ArchiveIdentity, EvidenceArchive

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OBJECT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,180}$")
_MAX_ARTIFACT_BYTES = 8_388_608
_DISPATCH_WINDOW = timedelta(minutes=10)


class CloudObserverError(ValueError):
    """Stable independent-observer failure without remote provider details."""


def _utc(value: str, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CloudObserverError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CloudObserverError(code) from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise CloudObserverError(code)
    return parsed


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo != UTC:
        raise CloudObserverError("cloud_observer_clock_invalid")
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class CloudRunMetadata:
    repository: str
    run_id: int
    workflow_file: str
    workflow_path: str
    workflow_revision: str
    workflow_blob_digest: str
    event: str
    request_digest: str
    dispatch_key: str
    attempt_key: str
    run_attempt: int
    head_sha: str
    head_ref: str
    parent_commit: str
    candidate_commit: str
    status: str
    conclusion: str
    created_at: str
    completed_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not _REPOSITORY.fullmatch(self.repository):
            raise CloudObserverError("cloud_run_repository_invalid")
        for name in ("run_id", "run_attempt"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise CloudObserverError(f"cloud_run_{name}_invalid")
        for name in ("workflow_blob_digest", "request_digest"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise CloudObserverError(f"cloud_run_{name}_invalid")
        for name in ("workflow_revision", "head_sha", "parent_commit", "candidate_commit"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _OBJECT.fullmatch(value):
                raise CloudObserverError(f"cloud_run_{name}_invalid")
        _utc(self.created_at, "cloud_run_created_at_invalid")
        _utc(self.completed_at, "cloud_run_completed_at_invalid")
        for name in (
            "workflow_file",
            "workflow_path",
            "event",
            "dispatch_key",
            "attempt_key",
            "head_ref",
            "status",
            "conclusion",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value.encode()) > 512:
                raise CloudObserverError(f"cloud_run_{name}_invalid")


@dataclass(frozen=True, slots=True)
class CloudArtifactMetadata:
    artifact_id: int
    run_id: int
    name: str
    digest: str
    size_in_bytes: int
    expired: bool
    expires_at: str

    def __post_init__(self) -> None:
        for name in ("artifact_id", "run_id", "size_in_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise CloudObserverError(f"cloud_artifact_{name}_invalid")
        if not isinstance(self.name, str) or not _NAME.fullmatch(self.name):
            raise CloudObserverError("cloud_artifact_name_invalid")
        if not isinstance(self.digest, str) or not _DIGEST.fullmatch(self.digest):
            raise CloudObserverError("cloud_artifact_digest_invalid")
        if type(self.expired) is not bool:
            raise CloudObserverError("cloud_artifact_expired_invalid")
        _utc(self.expires_at, "cloud_artifact_expires_at_invalid")


class ProtectedGitHubObserverGateway(Protocol):
    """Closed observer surface; workflow metadata and download URLs are not caller inputs."""

    def observe_run(self, request_digest: str, attempt_key: str) -> CloudRunMetadata: ...

    def list_run_artifacts(self, run_id: int) -> tuple[CloudArtifactMetadata, ...]: ...

    def download_run_artifact(self, run_id: int, artifact_id: int) -> bytes: ...


@dataclass(frozen=True, slots=True)
class TrustedCloudEvidence:
    run: CloudRunMetadata
    artifact: CloudArtifactMetadata
    archive: ArchivedEvidence
    signed_receipt: SignedCommissioningReceipt


class CloudObserver:
    __slots__ = ("__archive", "__clock", "__github", "__signer")

    def __init__(
        self,
        *,
        github: ProtectedGitHubObserverGateway,
        archive: EvidenceArchive,
        signer: CloudReceiptSigner,
        clock: object,
        _testing: bool,
    ) -> None:
        if (
            not _testing
            or not isinstance(archive, EvidenceArchive)
            or not isinstance(signer, CloudReceiptSigner)
            or not callable(clock)
        ):
            raise CloudObserverError("cloud_observer_construction_invalid")
        self.__github = github
        self.__archive = archive
        self.__signer = signer
        self.__clock = clock

    @classmethod
    def _for_testing(
        cls,
        *,
        github: ProtectedGitHubObserverGateway,
        archive: EvidenceArchive,
        signer: CloudReceiptSigner,
        clock: object,
    ) -> CloudObserver:
        return cls(
            github=github,
            archive=archive,
            signer=signer,
            clock=clock,
            _testing=True,
        )

    def observe_success(
        self, request: CloudRunRequest, *, attempt: int, dispatched_at: datetime
    ) -> TrustedCloudEvidence:
        if not isinstance(request, CloudRunRequest):
            raise CloudObserverError("cloud_observer_request_invalid")
        if isinstance(attempt, bool) or not isinstance(attempt, int) or not 1 <= attempt <= 3:
            raise CloudObserverError("cloud_observer_attempt_invalid")
        if not isinstance(dispatched_at, datetime) or dispatched_at.tzinfo != UTC:
            raise CloudObserverError("cloud_observer_dispatch_time_invalid")
        observed_at_value = self.__clock()
        _timestamp(observed_at_value)
        attempt_key = request.attempt_key(attempt)
        try:
            run = self.__github.observe_run(request.request_digest, attempt_key)
        except Exception:
            raise CloudObserverError("cloud_observer_run_unavailable") from None
        self._validate_run(request, run, attempt, attempt_key, dispatched_at, observed_at_value)
        try:
            artifacts = self.__github.list_run_artifacts(run.run_id)
        except Exception:
            raise CloudObserverError("cloud_observer_artifacts_unavailable") from None
        artifact = self._select_artifact(request, run, artifacts, observed_at_value)
        try:
            payload = self.__github.download_run_artifact(run.run_id, artifact.artifact_id)
        except Exception:
            raise CloudObserverError("cloud_observer_download_unavailable") from None
        if not isinstance(payload, bytes) or not 0 < len(payload) <= _MAX_ARTIFACT_BYTES:
            raise CloudObserverError("cloud_evidence_payload_invalid")
        if len(payload) != artifact.size_in_bytes:
            raise CloudObserverError("cloud_evidence_size_mismatch")
        payload_digest = hashlib.sha256(payload).hexdigest()
        if payload_digest != artifact.digest:
            raise CloudObserverError("cloud_evidence_digest_mismatch")
        self._validate_payload(request, run, attempt_key, attempt, payload)
        media_type = (
            "application/vnd.carl.improvement-evidence+json;version=1"
            if request.workflow_file == "autonomous-improvement.yml"
            else "application/vnd.carl.soak-observation+json;version=1"
        )
        archived = self.__archive.archive(
            ArchiveIdentity(
                repository=request.repository,
                request_digest=request.request_digest,
                run_id=run.run_id,
                artifact_id=artifact.artifact_id,
                artifact_name=artifact.name,
                media_type=media_type,
                schema_version=1,
            ),
            payload,
        )
        receipt = CommissioningReceipt(
            schema_version=2,
            repository=request.repository,
            workflow_file=request.workflow_file,
            workflow_path=request.expected_workflow_path,
            workflow_revision=request.workflow_revision,
            workflow_blob_digest=request.workflow_blob_digest,
            request_digest=request.request_digest,
            experiment_digest=request.experiment_digest,
            task_set_digest=request.task_set_digest,
            metric_pack_digest=request.metric_pack_digest,
            policy_digest=request.policy_digest,
            run_id=run.run_id,
            status="completed",
            conclusion="success",
            observed_at=run.completed_at,
            artifact_id=artifact.artifact_id,
            artifact_name=artifact.name,
            artifact_digest=payload_digest,
        )
        signed = self.__signer.sign_commissioning_receipt(receipt, archived)
        return TrustedCloudEvidence(run, artifact, archived, signed)

    @staticmethod
    def _validate_run(
        request: CloudRunRequest,
        run: object,
        attempt: int,
        attempt_key: str,
        dispatched_at: datetime,
        observed_at: datetime,
    ) -> None:
        if not isinstance(run, CloudRunMetadata):
            raise CloudObserverError("cloud_run_metadata_invalid")
        created = _utc(run.created_at, "cloud_run_created_at_invalid")
        completed = _utc(run.completed_at, "cloud_run_completed_at_invalid")
        if (
            run.repository != request.repository
            or run.workflow_file != request.workflow_file
            or run.workflow_path != request.expected_workflow_path
            or run.workflow_revision != request.workflow_revision
            or run.workflow_blob_digest != request.workflow_blob_digest
            or run.event != "workflow_dispatch"
            or run.request_digest != request.request_digest
            or run.dispatch_key != request.dispatch_key
            or run.attempt_key != attempt_key
            or run.run_attempt != attempt
            or run.head_sha != request.candidate_commit
            or run.head_ref != f"refs/heads/experimental/{request.experiment_digest}"
            or run.parent_commit != request.parent_commit
            or run.candidate_commit != request.candidate_commit
            or run.status != "completed"
            or run.conclusion != "success"
            or created < dispatched_at
            or created > dispatched_at + _DISPATCH_WINDOW
            or completed < created
            or completed > observed_at
        ):
            raise CloudObserverError("cloud_run_identity_mismatch")

    @staticmethod
    def _select_artifact(
        request: CloudRunRequest,
        run: CloudRunMetadata,
        artifacts: object,
        observed_at: datetime,
    ) -> CloudArtifactMetadata:
        if (
            type(artifacts) is not tuple
            or len(artifacts) != 1
            or any(not isinstance(item, CloudArtifactMetadata) for item in artifacts)
        ):
            raise CloudObserverError("cloud_artifact_collection_invalid")
        matches = [item for item in artifacts if item.name == request.expected_artifact_name]
        if len(matches) != 1:
            raise CloudObserverError("cloud_artifact_identity_mismatch")
        artifact = matches[0]
        if (
            artifact.run_id != run.run_id
            or artifact.expired
            or _utc(artifact.expires_at, "cloud_artifact_expires_at_invalid") <= observed_at
            or artifact.size_in_bytes > _MAX_ARTIFACT_BYTES
        ):
            raise CloudObserverError("cloud_artifact_identity_mismatch")
        return artifact

    @staticmethod
    def _validate_payload(
        request: CloudRunRequest,
        run: CloudRunMetadata,
        attempt_key: str,
        attempt: int,
        payload: bytes,
    ) -> None:
        try:
            decoded = decode_cloud_wire_json(payload)
        except CloudExecutionError as error:
            code = (
                "cloud_evidence_duplicate_json_key"
                if error.code == "cloud_codec_duplicate_json_key"
                else "cloud_evidence_schema_invalid"
            )
            raise CloudObserverError(code) from error
        expected = {
            "attempt_key": attempt_key,
            "candidate_commit": request.candidate_commit,
            "conclusion": "success",
            "experiment_digest": request.experiment_digest,
            "metric_pack_digest": request.metric_pack_digest,
            "parent_commit": request.parent_commit,
            "policy_digest": request.policy_digest,
            "repository": request.repository,
            "request_digest": request.request_digest,
            "run_attempt": attempt,
            "run_id": run.run_id,
            "schema_version": 1,
            "task_set_digest": request.task_set_digest,
        }
        if decoded != expected:
            raise CloudObserverError("cloud_evidence_schema_invalid")
