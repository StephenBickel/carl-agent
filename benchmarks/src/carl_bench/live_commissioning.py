"""Restart-safe commissioning runner for the complete protected cloud bridge."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_execution import (
    CloudArtifact,
    CloudRunRequest,
    CloudRunSnapshot,
    TrustedCloudReceiptKey,
    reconcile_cloud_run,
)
from carl_bench.cloud_observer import CloudObserver, TrustedCloudEvidence
from carl_bench.commissioning_controller import LiveCommissioningCommandStore
from carl_bench.github_promotion import APPROVED_REQUIRED_CHECKS

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OBJECT = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_REF = re.compile(r"^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,191}$")


class LiveCommissioningError(ValueError):
    """Stable live-commissioning failure without provider details."""


class DispatchResponseLost(RuntimeError):
    """The persisted workflow dispatch may have succeeded remotely."""


class DispatchNotFound(LiveCommissioningError):
    """No remote effect exists for the exact persisted dispatch identity."""


def _utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LiveCommissioningError(code)
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise LiveCommissioningError(code) from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise LiveCommissioningError(code)
    return parsed


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise LiveCommissioningError(code)
    return value


def _object(value: object, code: str) -> str:
    if not isinstance(value, str) or _OBJECT.fullmatch(value) is None:
        raise LiveCommissioningError(code)
    return value


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise LiveCommissioningError(code)
    return value


def _positive(value: object, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise LiveCommissioningError(code)
    return value


def _exact_dict(value: object, fields: object, code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(fields):
        raise LiveCommissioningError(code)
    return value


@dataclass(frozen=True, slots=True)
class RemoteRunIdentity:
    run_id: int
    attempt_key: str
    artifact_id: int
    artifact_name: str
    artifact_digest: str
    artifact_byte_length: int

    def __post_init__(self) -> None:
        _positive(self.run_id, "live_run_identity_invalid")
        _positive(self.artifact_id, "live_run_identity_invalid")
        _positive(self.artifact_byte_length, "live_run_identity_invalid")
        if self.artifact_byte_length > 8_388_608:
            raise LiveCommissioningError("live_artifact_too_large")
        if not isinstance(self.attempt_key, str) or not re.fullmatch(
            r"cloud-run-[0-9a-f]{64}-attempt-[1-3]", self.attempt_key
        ):
            raise LiveCommissioningError("live_run_identity_invalid")
        if not isinstance(self.artifact_name, str) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,180}", self.artifact_name
        ):
            raise LiveCommissioningError("live_run_identity_invalid")
        _digest(self.artifact_digest, "live_run_identity_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_canonical_dict(cls, value: object) -> RemoteRunIdentity:
        decoded = _exact_dict(value, cls.__dataclass_fields__, "live_run_identity_invalid")
        try:
            return cls(**decoded)
        except TypeError as error:
            raise LiveCommissioningError("live_run_identity_invalid") from error


@dataclass(frozen=True, slots=True)
class ImmutableExperimentalPublication:
    ref: str
    commit: str
    tree: str

    def __post_init__(self) -> None:
        if not isinstance(self.ref, str) or _REF.fullmatch(self.ref) is None:
            raise LiveCommissioningError("live_experimental_publication_invalid")
        if not self.ref.startswith("refs/heads/experimental/"):
            raise LiveCommissioningError("live_experimental_publication_invalid")
        _object(self.commit, "live_experimental_publication_invalid")
        _object(self.tree, "live_experimental_publication_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_canonical_dict(cls, value: object) -> ImmutableExperimentalPublication:
        decoded = _exact_dict(
            value, cls.__dataclass_fields__, "live_experimental_publication_invalid"
        )
        try:
            return cls(**decoded)
        except TypeError as error:
            raise LiveCommissioningError("live_experimental_publication_invalid") from error


@dataclass(frozen=True, slots=True)
class IndependentDisposition:
    disposition: str
    candidate_commit: str
    candidate_tree: str
    signed_receipt_digest: str
    disposition_digest: str

    def __post_init__(self) -> None:
        if self.disposition != "production_candidate":
            raise LiveCommissioningError("live_disposition_invalid")
        _object(self.candidate_commit, "live_disposition_invalid")
        _object(self.candidate_tree, "live_disposition_invalid")
        _digest(self.signed_receipt_digest, "live_disposition_invalid")
        _digest(self.disposition_digest, "live_disposition_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_canonical_dict(cls, value: object) -> IndependentDisposition:
        decoded = _exact_dict(value, cls.__dataclass_fields__, "live_disposition_invalid")
        try:
            return cls(**decoded)
        except TypeError as error:
            raise LiveCommissioningError("live_disposition_invalid") from error


@dataclass(frozen=True, slots=True)
class ProtectedPromotion:
    promotion_id: str
    pull_request_number: int
    head_commit: str
    head_tree: str
    required_checks: tuple[str, ...]
    auto_merge_enabled: bool
    merge_commit: str
    merge_tree: str
    merged_at: str

    def __post_init__(self) -> None:
        _identifier(self.promotion_id, "live_promotion_invalid")
        _positive(self.pull_request_number, "live_promotion_invalid")
        for value in (self.head_commit, self.head_tree, self.merge_commit, self.merge_tree):
            _object(value, "live_promotion_invalid")
        if (
            self.required_checks != APPROVED_REQUIRED_CHECKS
            or self.auto_merge_enabled is not True
            or self.merge_tree != self.head_tree
        ):
            raise LiveCommissioningError("live_promotion_invalid")
        _utc(self.merged_at, "live_promotion_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            **{
                name: getattr(self, name)
                for name in self.__dataclass_fields__
                if name != "required_checks"
            },
            "required_checks": list(self.required_checks),
        }

    @classmethod
    def from_canonical_dict(cls, value: object) -> ProtectedPromotion:
        decoded = dict(_exact_dict(value, cls.__dataclass_fields__, "live_promotion_invalid"))
        checks = decoded.get("required_checks")
        if not isinstance(checks, list):
            raise LiveCommissioningError("live_promotion_invalid")
        decoded["required_checks"] = tuple(checks)
        try:
            return cls(**decoded)
        except TypeError as error:
            raise LiveCommissioningError("live_promotion_invalid") from error


@dataclass(frozen=True, slots=True)
class AcceptedSoak:
    merge_commit: str
    merge_tree: str
    merged_at: str
    accepted_at: str
    observation_digest: str

    def __post_init__(self) -> None:
        _object(self.merge_commit, "live_soak_invalid")
        _object(self.merge_tree, "live_soak_invalid")
        merged = _utc(self.merged_at, "live_soak_invalid")
        accepted = _utc(self.accepted_at, "live_soak_invalid")
        if accepted - merged < timedelta(hours=24):
            raise LiveCommissioningError("live_soak_too_short")
        _digest(self.observation_digest, "live_soak_invalid")

    @classmethod
    def create(cls, *, promotion: ProtectedPromotion, accepted_at: str) -> AcceptedSoak:
        payload = {
            "accepted_at": accepted_at,
            "healthy": True,
            "merge_commit": promotion.merge_commit,
            "merge_tree": promotion.merge_tree,
            "merged_at": promotion.merged_at,
            "schema_version": 1,
        }
        return cls(
            merge_commit=promotion.merge_commit,
            merge_tree=promotion.merge_tree,
            merged_at=promotion.merged_at,
            accepted_at=accepted_at,
            observation_digest=hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
        )

    def to_canonical_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_canonical_dict(cls, value: object) -> AcceptedSoak:
        decoded = _exact_dict(value, cls.__dataclass_fields__, "live_soak_invalid")
        try:
            return cls(**decoded)
        except TypeError as error:
            raise LiveCommissioningError("live_soak_invalid") from error


@dataclass(frozen=True, slots=True)
class ExactRevert:
    hard_failure_merge_commit: str
    hard_failure_digest: str
    revert_pull_request_number: int
    revert_candidate_commit: str
    required_checks: tuple[str, ...]
    auto_merge_enabled: bool
    revert_started_at: str
    revert_merge_commit: str
    restored_tree: str
    reverted_at: str

    def __post_init__(self) -> None:
        for value in (
            self.hard_failure_merge_commit,
            self.revert_candidate_commit,
            self.revert_merge_commit,
            self.restored_tree,
        ):
            _object(value, "live_revert_invalid")
        _digest(self.hard_failure_digest, "live_revert_invalid")
        _positive(self.revert_pull_request_number, "live_revert_invalid")
        if self.required_checks != APPROVED_REQUIRED_CHECKS or self.auto_merge_enabled is not True:
            raise LiveCommissioningError("live_revert_invalid")
        started = _utc(self.revert_started_at, "live_revert_invalid")
        reverted = _utc(self.reverted_at, "live_revert_invalid")
        if reverted < started or reverted - started > timedelta(hours=2):
            raise LiveCommissioningError("live_revert_sla_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            **{
                name: getattr(self, name)
                for name in self.__dataclass_fields__
                if name != "required_checks"
            },
            "required_checks": list(self.required_checks),
        }

    @classmethod
    def from_canonical_dict(cls, value: object) -> ExactRevert:
        decoded = dict(_exact_dict(value, cls.__dataclass_fields__, "live_revert_invalid"))
        checks = decoded.get("required_checks")
        if not isinstance(checks, list):
            raise LiveCommissioningError("live_revert_invalid")
        decoded["required_checks"] = tuple(checks)
        try:
            return cls(**decoded)
        except TypeError as error:
            raise LiveCommissioningError("live_revert_invalid") from error


@dataclass(frozen=True, slots=True)
class LiveCommissioningPlan:
    schema_version: int
    experiment_id: str
    request: CloudRunRequest
    baseline_tree: str
    candidate_tree: str
    accepted_production_tree: str
    promotion_id: str
    hard_regression_promotion_id: str
    hard_regression_commit: str
    hard_regression_tree: str
    exact_revert_commit: str
    command_occurred_at: str
    merge_observed_at: str
    soak_accepted_at: str
    hard_failure_observed_at: str
    revert_observed_at: str

    def __post_init__(self) -> None:
        if self.schema_version != 1 or not isinstance(self.request, CloudRunRequest):
            raise LiveCommissioningError("live_commissioning_plan_invalid")
        _identifier(self.experiment_id, "live_commissioning_plan_invalid")
        for value in (
            self.candidate_tree,
            self.baseline_tree,
            self.accepted_production_tree,
            self.hard_regression_commit,
            self.hard_regression_tree,
            self.exact_revert_commit,
        ):
            _object(value, "live_commissioning_plan_invalid")
        if (
            self.accepted_production_tree != self.candidate_tree
            or self.baseline_tree == self.accepted_production_tree
            or self.hard_regression_commit == self.request.candidate_commit
            or self.hard_regression_tree == self.accepted_production_tree
            or self.exact_revert_commit
            in {
                self.request.candidate_commit,
                self.hard_regression_commit,
            }
        ):
            raise LiveCommissioningError("live_commissioning_plan_invalid")
        _identifier(self.promotion_id, "live_commissioning_plan_invalid")
        _identifier(self.hard_regression_promotion_id, "live_commissioning_plan_invalid")
        command = _utc(self.command_occurred_at, "live_commissioning_plan_invalid")
        merged = _utc(self.merge_observed_at, "live_commissioning_plan_invalid")
        accepted = _utc(self.soak_accepted_at, "live_commissioning_plan_invalid")
        failed = _utc(self.hard_failure_observed_at, "live_commissioning_plan_invalid")
        reverted = _utc(self.revert_observed_at, "live_commissioning_plan_invalid")
        if (
            not command <= merged
            or accepted - merged < timedelta(hours=24)
            or failed < accepted
            or reverted < failed
            or reverted - failed > timedelta(hours=2)
        ):
            raise LiveCommissioningError("live_commissioning_plan_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            name: (self.request.to_canonical_dict() if name == "request" else getattr(self, name))
            for name in self.__dataclass_fields__
        }

    @classmethod
    def from_canonical_dict(cls, value: object) -> LiveCommissioningPlan:
        decoded = dict(
            _exact_dict(value, cls.__dataclass_fields__, "live_commissioning_plan_invalid")
        )
        decoded["request"] = CloudRunRequest.from_canonical_dict(decoded["request"])
        try:
            return cls(**decoded)
        except (TypeError, ValueError) as error:
            raise LiveCommissioningError("live_commissioning_plan_invalid") from error

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class FakeCloudCommissioningReceipt:
    schema_version: int
    synthetic_test_only: bool
    remote_cloud_acceptance: str
    experiment_id: str
    experimental_ref: str
    candidate_commit: str
    candidate_tree: str
    provider_run_id: int
    artifact_digest: str
    artifact_object_key: str
    artifact_version_id: str
    artifact_byte_length: int
    signed_validation_receipt_digest: str
    disposition: str
    disposition_digest: str
    promotion_id: str
    promotion_pull_request_number: int
    required_checks_complete: bool
    required_checks: tuple[str, ...]
    auto_merge_enabled: bool
    promotion_merge_commit: str
    promotion_merge_tree: str
    promotion_merged_at: str
    soak_merge_commit: str
    soak_observation_digest: str
    soak_accepted_at: str
    hard_failure_merge_commit: str
    hard_failure_digest: str
    revert_pull_request_number: int
    revert_candidate_commit: str
    revert_required_checks_complete: bool
    revert_auto_merge_enabled: bool
    revert_started_at: str
    revert_merge_commit: str
    revert_restored_tree: str
    revert_merged_at: str
    restart_recoveries: int

    def __post_init__(self) -> None:
        if (
            self.schema_version != 1
            or self.synthetic_test_only is not True
            or self.remote_cloud_acceptance != "uncommissioned"
            or self.required_checks_complete is not True
            or self.required_checks != APPROVED_REQUIRED_CHECKS
            or self.auto_merge_enabled is not True
            or self.revert_required_checks_complete is not True
            or self.revert_auto_merge_enabled is not True
            or self.disposition != "production_candidate"
            or self.soak_merge_commit != self.promotion_merge_commit
            or self.promotion_merge_tree != self.candidate_tree
            or self.revert_restored_tree != self.candidate_tree
            or self.restart_recoveries != 2
        ):
            raise LiveCommissioningError("fake_cloud_commissioning_receipt_invalid")
        _identifier(self.experiment_id, "fake_cloud_commissioning_receipt_invalid")
        if self.experimental_ref != f"refs/heads/experimental/{self.experiment_id}":
            raise LiveCommissioningError("fake_cloud_commissioning_receipt_invalid")
        for value in (
            self.candidate_commit,
            self.candidate_tree,
            self.promotion_merge_commit,
            self.promotion_merge_tree,
            self.soak_merge_commit,
            self.hard_failure_merge_commit,
            self.revert_candidate_commit,
            self.revert_merge_commit,
            self.revert_restored_tree,
        ):
            _object(value, "fake_cloud_commissioning_receipt_invalid")
        for value in (
            self.artifact_digest,
            self.signed_validation_receipt_digest,
            self.disposition_digest,
            self.soak_observation_digest,
            self.hard_failure_digest,
        ):
            _digest(value, "fake_cloud_commissioning_receipt_invalid")
        for value in (
            self.provider_run_id,
            self.artifact_byte_length,
            self.promotion_pull_request_number,
            self.revert_pull_request_number,
        ):
            _positive(value, "fake_cloud_commissioning_receipt_invalid")
        if self.artifact_byte_length > 8_388_608:
            raise LiveCommissioningError("fake_cloud_commissioning_receipt_invalid")
        for value in (self.artifact_object_key, self.artifact_version_id, self.promotion_id):
            _identifier(value, "fake_cloud_commissioning_receipt_invalid")
        merged = _utc(self.promotion_merged_at, "fake_cloud_commissioning_receipt_invalid")
        accepted = _utc(self.soak_accepted_at, "fake_cloud_commissioning_receipt_invalid")
        failed = _utc(self.revert_started_at, "fake_cloud_commissioning_receipt_invalid")
        reverted = _utc(self.revert_merged_at, "fake_cloud_commissioning_receipt_invalid")
        if accepted - merged < timedelta(hours=24) or reverted - failed > timedelta(hours=2):
            raise LiveCommissioningError("fake_cloud_commissioning_receipt_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            name: (list(self.required_checks) if name == "required_checks" else getattr(self, name))
            for name in self.__dataclass_fields__
        }

    @classmethod
    def from_canonical_dict(cls, value: object) -> FakeCloudCommissioningReceipt:
        decoded = dict(
            _exact_dict(value, cls.__dataclass_fields__, "fake_cloud_commissioning_receipt_invalid")
        )
        checks = decoded.get("required_checks")
        if not isinstance(checks, list):
            raise LiveCommissioningError("fake_cloud_commissioning_receipt_invalid")
        decoded["required_checks"] = tuple(checks)
        try:
            return cls(**decoded)
        except TypeError as error:
            raise LiveCommissioningError("fake_cloud_commissioning_receipt_invalid") from error

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


class LiveCommissioningCloud(Protocol):
    def bind_plan(self, plan: LiveCommissioningPlan) -> None: ...

    def dispatch_validation(
        self, request: CloudRunRequest, *, attempt: int
    ) -> RemoteRunIdentity: ...

    def reconcile_validation_dispatch(
        self, request: CloudRunRequest, *, attempt: int
    ) -> RemoteRunIdentity: ...

    def ingest_trusted_evidence(self, evidence: TrustedCloudEvidence) -> str: ...

    def publish_experimental(
        self, *, experiment_id: str, candidate_commit: str, candidate_tree: str
    ) -> ImmutableExperimentalPublication: ...

    def record_disposition(
        self,
        *,
        publication: ImmutableExperimentalPublication,
        signed_receipt_digest: str,
    ) -> IndependentDisposition: ...

    def promote(
        self,
        *,
        promotion_id: str,
        publication: ImmutableExperimentalPublication,
        disposition: IndependentDisposition,
        merged_at: str,
    ) -> ProtectedPromotion: ...

    def accept_soak(self, *, promotion: ProtectedPromotion, accepted_at: str) -> AcceptedSoak: ...

    def hard_regression_and_exact_revert(
        self,
        *,
        plan: LiveCommissioningPlan,
        accepted: AcceptedSoak,
    ) -> ExactRevert: ...


class LiveCommissioningRunner:
    """Advance the complete commissioning graph and persist its terminal transcript."""

    def __init__(
        self,
        *,
        cloud: LiveCommissioningCloud,
        observer: CloudObserver,
        command_store: LiveCommissioningCommandStore,
        trusted_receipt_key: TrustedCloudReceiptKey,
        verified_at: datetime,
    ) -> None:
        if (
            not isinstance(observer, CloudObserver)
            or not isinstance(command_store, LiveCommissioningCommandStore)
            or not isinstance(trusted_receipt_key, TrustedCloudReceiptKey)
            or not isinstance(verified_at, datetime)
            or verified_at.tzinfo != UTC
        ):
            raise LiveCommissioningError("live_commissioning_runner_invalid")
        self._cloud = cloud
        self._observer = observer
        self._commands = command_store
        self._trusted_key = trusted_receipt_key
        self._verified_at = verified_at

    def run(self, plan: LiveCommissioningPlan) -> FakeCloudCommissioningReceipt:
        if not isinstance(plan, LiveCommissioningPlan):
            raise LiveCommissioningError("live_commissioning_plan_invalid")
        self._cloud.bind_plan(plan)
        command_key = f"commission-{plan.digest}"
        payload = plan.to_canonical_dict()
        command = self._commands.begin(
            command_key=command_key,
            request_payload=payload,
            occurred_at=plan.command_occurred_at,
        )
        if command.status == "completed":
            if command.result is None:
                raise LiveCommissioningError("live_commissioning_result_missing")
            return FakeCloudCommissioningReceipt.from_canonical_dict(command.result)

        try:
            remote_run = self._cloud.reconcile_validation_dispatch(plan.request, attempt=1)
        except DispatchNotFound:
            try:
                remote_run = self._cloud.dispatch_validation(plan.request, attempt=1)
            except DispatchResponseLost:
                remote_run = self._cloud.reconcile_validation_dispatch(plan.request, attempt=1)
        self._validate_remote_run(plan.request, remote_run)

        evidence = self._observer.observe_success(
            plan.request,
            attempt=1,
            dispatched_at=_utc(plan.command_occurred_at, "live_commissioning_plan_invalid"),
        )
        self._validate_evidence(remote_run, evidence)
        artifact = CloudArtifact(
            artifact_id=remote_run.artifact_id,
            name=remote_run.artifact_name,
            run_id=remote_run.run_id,
            digest=remote_run.artifact_digest,
            downloaded_digest=remote_run.artifact_digest,
        )
        decision = reconcile_cloud_run(
            plan.request,
            CloudRunSnapshot(
                remote_available=True,
                observed_at=evidence.run.completed_at,
                repository=plan.request.repository,
                workflow_file=plan.request.workflow_file,
                workflow_path=plan.request.expected_workflow_path,
                workflow_blob_digest=plan.request.workflow_blob_digest,
                request_digest=plan.request.request_digest,
                dispatch_key=plan.request.dispatch_key,
                run_id=remote_run.run_id,
                head_sha=plan.request.workflow_revision,
                status="completed",
                conclusion="success",
                attempt=1,
                attempt_key=plan.request.attempt_key(1),
                artifacts=(artifact,),
                artifacts_expires_at=evidence.artifact.expires_at,
                commissioning_receipt=evidence.signed_receipt,
            ),
            trusted_receipt_key=self._trusted_key,
            require_protected_archive=True,
            verified_at=self._verified_at.isoformat().replace("+00:00", "Z"),
        )
        if decision.action != "record_success" or decision.reason != "cloud_run_evidence_verified":
            raise LiveCommissioningError(f"live_evidence_rejected:{decision.reason}")
        signed_receipt_digest = self._cloud.ingest_trusted_evidence(evidence)
        if signed_receipt_digest != evidence.signed_receipt.receipt_digest:
            raise LiveCommissioningError("live_ingestion_identity_mismatch")

        publication = self._cloud.publish_experimental(
            experiment_id=plan.experiment_id,
            candidate_commit=plan.request.candidate_commit,
            candidate_tree=plan.candidate_tree,
        )
        if publication != ImmutableExperimentalPublication(
            f"refs/heads/experimental/{plan.experiment_id}",
            plan.request.candidate_commit,
            plan.candidate_tree,
        ):
            raise LiveCommissioningError("live_experimental_publication_mismatch")
        disposition = self._cloud.record_disposition(
            publication=publication,
            signed_receipt_digest=signed_receipt_digest,
        )
        if (
            disposition.candidate_commit != publication.commit
            or disposition.candidate_tree != publication.tree
            or disposition.signed_receipt_digest != signed_receipt_digest
        ):
            raise LiveCommissioningError("live_disposition_identity_mismatch")
        promotion = self._cloud.promote(
            promotion_id=plan.promotion_id,
            publication=publication,
            disposition=disposition,
            merged_at=plan.merge_observed_at,
        )
        if (
            promotion.promotion_id != plan.promotion_id
            or promotion.head_commit != publication.commit
            or promotion.head_tree != publication.tree
            or promotion.merge_tree != plan.accepted_production_tree
        ):
            raise LiveCommissioningError("live_promotion_identity_mismatch")
        accepted = self._cloud.accept_soak(
            promotion=promotion,
            accepted_at=plan.soak_accepted_at,
        )
        if (
            accepted.merge_commit != promotion.merge_commit
            or accepted.merge_tree != promotion.merge_tree
        ):
            raise LiveCommissioningError("live_soak_identity_mismatch")
        reverted = self._cloud.hard_regression_and_exact_revert(
            plan=plan,
            accepted=accepted,
        )
        if (
            reverted.restored_tree != accepted.merge_tree
            or reverted.revert_candidate_commit != plan.exact_revert_commit
            or reverted.revert_started_at != plan.hard_failure_observed_at
        ):
            raise LiveCommissioningError("live_revert_identity_mismatch")

        result = FakeCloudCommissioningReceipt(
            schema_version=1,
            synthetic_test_only=True,
            remote_cloud_acceptance="uncommissioned",
            experiment_id=plan.experiment_id,
            experimental_ref=publication.ref,
            candidate_commit=publication.commit,
            candidate_tree=publication.tree,
            provider_run_id=remote_run.run_id,
            artifact_digest=remote_run.artifact_digest,
            artifact_object_key=evidence.archive.object_key,
            artifact_version_id=evidence.archive.provider_version_id,
            artifact_byte_length=remote_run.artifact_byte_length,
            signed_validation_receipt_digest=signed_receipt_digest,
            disposition=disposition.disposition,
            disposition_digest=disposition.disposition_digest,
            promotion_id=promotion.promotion_id,
            promotion_pull_request_number=promotion.pull_request_number,
            required_checks_complete=promotion.required_checks == APPROVED_REQUIRED_CHECKS,
            required_checks=promotion.required_checks,
            auto_merge_enabled=promotion.auto_merge_enabled,
            promotion_merge_commit=promotion.merge_commit,
            promotion_merge_tree=promotion.merge_tree,
            promotion_merged_at=promotion.merged_at,
            soak_merge_commit=accepted.merge_commit,
            soak_observation_digest=accepted.observation_digest,
            soak_accepted_at=accepted.accepted_at,
            hard_failure_merge_commit=reverted.hard_failure_merge_commit,
            hard_failure_digest=reverted.hard_failure_digest,
            revert_pull_request_number=reverted.revert_pull_request_number,
            revert_candidate_commit=reverted.revert_candidate_commit,
            revert_required_checks_complete=(reverted.required_checks == APPROVED_REQUIRED_CHECKS),
            revert_auto_merge_enabled=reverted.auto_merge_enabled,
            revert_started_at=reverted.revert_started_at,
            revert_merge_commit=reverted.revert_merge_commit,
            revert_restored_tree=reverted.restored_tree,
            revert_merged_at=reverted.reverted_at,
            restart_recoveries=2,
        )
        completed = self._commands.complete(
            command_key=command_key,
            request_payload=payload,
            result=result.to_canonical_dict(),
        )
        if completed.result is None:
            raise LiveCommissioningError("live_commissioning_result_missing")
        return FakeCloudCommissioningReceipt.from_canonical_dict(completed.result)

    @staticmethod
    def _validate_remote_run(request: CloudRunRequest, run: object) -> None:
        if (
            not isinstance(run, RemoteRunIdentity)
            or run.attempt_key != request.attempt_key(1)
            or run.artifact_name != request.expected_artifact_name
        ):
            raise LiveCommissioningError("live_dispatch_identity_mismatch")

    @staticmethod
    def _validate_evidence(run: RemoteRunIdentity, evidence: object) -> None:
        if not isinstance(evidence, TrustedCloudEvidence):
            raise LiveCommissioningError("live_evidence_invalid")
        if (
            evidence.run.run_id != run.run_id
            or evidence.artifact.artifact_id != run.artifact_id
            or evidence.artifact.name != run.artifact_name
            or evidence.artifact.digest != run.artifact_digest
            or evidence.archive.payload_digest != run.artifact_digest
            or evidence.signed_receipt.receipt.artifact_digest != run.artifact_digest
        ):
            raise LiveCommissioningError("live_evidence_identity_mismatch")
