"""Concrete durable adapters for the protected autonomous product-builder command."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from carl_bench.candidate import SealedCandidate
from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_coordinator import ImmutableInputBinding
from carl_bench.experiment import ExperimentManifest
from carl_bench.product_builder import (
    BuildAttemptEvidence,
    BuilderError,
    BuilderLimits,
    BuilderPreregistration,
    BuilderSnapshot,
    ProductHypothesis,
    preregister_and_call_model,
    select_hypothesis,
    terminalize_unsuccessful_attempt,
    validate_attempts,
)
from carl_bench.product_builder_gateway import ProtectedOpenAIGateway

_PROTECTED_RUNTIME_ROOT = Path("/var/lib/carl/product-builder")
_DIGEST = frozenset("0123456789abcdef")


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _DIGEST


def _is_commit(value: object) -> bool:
    return isinstance(value, str) and len(value) in {40, 64} and set(value) <= _DIGEST


def _parse_object(payload: bytes, *, code: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise BuilderError(code) from error
    if type(value) is not dict or canonical_json_bytes(value) != payload:
        raise BuilderError(code)
    return value


@dataclass(frozen=True, slots=True)
class ValidationDispatchBinding:
    repository: str
    workflow_file: str
    workflow_revision: str
    workflow_blob_digest: str
    experiment_digest: str
    task_set_digest: str
    metric_pack_digest: str
    policy_digest: str

    def __post_init__(self) -> None:
        if self.repository != "StephenBickel/carl-agent":
            raise BuilderError("builder_dispatch_repository_invalid")
        if (
            not isinstance(self.workflow_file, str)
            or not self.workflow_file.endswith((".yml", ".yaml"))
            or "/" in self.workflow_file
            or not _is_commit(self.workflow_revision)
        ):
            raise BuilderError("builder_dispatch_workflow_invalid")
        for value in (
            self.workflow_blob_digest,
            self.experiment_digest,
            self.task_set_digest,
            self.metric_pack_digest,
            self.policy_digest,
        ):
            if not _is_digest(value):
                raise BuilderError("builder_dispatch_digest_invalid")

    def to_canonical_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_canonical_dict(cls, value: object) -> ValidationDispatchBinding:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise BuilderError("builder_dispatch_binding_invalid")
        try:
            return cls(**value)
        except TypeError as error:
            raise BuilderError("builder_dispatch_binding_invalid") from error


def _snapshot_dict(snapshot: BuilderSnapshot) -> dict[str, object]:
    return {
        "capability_family_cooldowns": [
            list(item) for item in snapshot.capability_family_cooldowns
        ],
        "coordinator_manifest_digest": snapshot.coordinator_manifest_digest,
        "cycle": snapshot.cycle,
        "exact_parent_commit": snapshot.exact_parent_commit,
        "immutable_inputs": [item.to_canonical_dict() for item in snapshot.immutable_inputs],
        "previous_hypothesis_digests": list(snapshot.previous_hypothesis_digests),
        "previous_work_digests": list(snapshot.previous_work_digests),
        "repository": snapshot.repository,
        "schema_version": snapshot.schema_version,
    }


def _snapshot_from(value: object) -> BuilderSnapshot:
    if type(value) is not dict:
        raise BuilderError("builder_request_snapshot_invalid")
    try:
        return BuilderSnapshot(
            schema_version=value["schema_version"],
            repository=value["repository"],
            exact_parent_commit=value["exact_parent_commit"],
            coordinator_manifest_digest=value["coordinator_manifest_digest"],
            cycle=value["cycle"],
            previous_hypothesis_digests=tuple(value["previous_hypothesis_digests"]),
            previous_work_digests=tuple(value["previous_work_digests"]),
            capability_family_cooldowns=tuple(
                tuple(item) for item in value["capability_family_cooldowns"]
            ),
            immutable_inputs=tuple(
                ImmutableInputBinding.from_canonical_dict(item)
                for item in value["immutable_inputs"]
            ),
        )
    except (KeyError, TypeError) as error:
        raise BuilderError("builder_request_snapshot_invalid") from error


@dataclass(frozen=True, slots=True)
class BuilderRunRequest:
    schema_version: int
    expected_revision: int
    snapshot: BuilderSnapshot
    hypotheses: tuple[ProductHypothesis, ...]
    manifest: ExperimentManifest
    limits: BuilderLimits
    prompt_digest: str
    validation_dispatch: ValidationDispatchBinding
    attempt: int = 1

    def __post_init__(self) -> None:
        if (
            self.schema_version != 1
            or isinstance(self.expected_revision, bool)
            or not isinstance(self.expected_revision, int)
            or self.expected_revision < 0
            or type(self.snapshot) is not BuilderSnapshot
            or not isinstance(self.hypotheses, tuple)
            or not self.hypotheses
            or any(type(item) is not ProductHypothesis for item in self.hypotheses)
            or type(self.manifest) is not ExperimentManifest
            or type(self.limits) is not BuilderLimits
            or not _is_digest(self.prompt_digest)
            or type(self.validation_dispatch) is not ValidationDispatchBinding
            or isinstance(self.attempt, bool)
            or not 1 <= self.attempt <= 3
        ):
            raise BuilderError("builder_run_request_invalid")
        if self.validation_dispatch.workflow_revision != self.snapshot.exact_parent_commit:
            raise BuilderError("builder_dispatch_parent_mismatch")

    @property
    def immutable_inputs_digest(self) -> str:
        value = [item.to_canonical_dict() for item in self.snapshot.immutable_inputs]
        return hashlib.sha256(canonical_json_bytes(value)).hexdigest()

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "attempt": self.attempt,
            "expected_revision": self.expected_revision,
            "hypotheses": [item.to_canonical_dict() for item in self.hypotheses],
            "limits": self.limits.to_canonical_dict(),
            "manifest": self.manifest.to_canonical_dict(),
            "prompt_digest": self.prompt_digest,
            "schema_version": self.schema_version,
            "snapshot": _snapshot_dict(self.snapshot),
            "validation_dispatch": self.validation_dispatch.to_canonical_dict(),
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()

    @classmethod
    def from_canonical_dict(cls, value: object) -> BuilderRunRequest:
        if type(value) is not dict or set(value) != {
            "attempt",
            "expected_revision",
            "hypotheses",
            "limits",
            "manifest",
            "prompt_digest",
            "schema_version",
            "snapshot",
            "validation_dispatch",
        }:
            raise BuilderError("builder_run_request_invalid")
        hypotheses = value["hypotheses"]
        limits = value["limits"]
        if not isinstance(hypotheses, list) or type(limits) is not dict:
            raise BuilderError("builder_run_request_invalid")
        try:
            return cls(
                schema_version=value["schema_version"],
                expected_revision=value["expected_revision"],
                snapshot=_snapshot_from(value["snapshot"]),
                hypotheses=tuple(ProductHypothesis(**item) for item in hypotheses),
                manifest=ExperimentManifest.from_canonical_dict(value["manifest"]),
                limits=BuilderLimits(
                    allowed_paths=tuple(limits["allowed_paths"]),
                    forbidden_paths=tuple(limits["forbidden_paths"]),
                    allowed_tools=tuple(limits["allowed_tools"]),
                    max_changed_paths=limits["max_changed_paths"],
                    max_patch_bytes=limits["max_patch_bytes"],
                    max_elapsed_seconds=limits["max_elapsed_seconds"],
                    max_cost_microdollars=limits["max_cost_microdollars"],
                ),
                prompt_digest=value["prompt_digest"],
                validation_dispatch=ValidationDispatchBinding.from_canonical_dict(
                    value["validation_dispatch"]
                ),
                attempt=value["attempt"],
            )
        except (KeyError, TypeError) as error:
            raise BuilderError("builder_run_request_invalid") from error


@dataclass(frozen=True, slots=True)
class ClaimedBuilderRequest:
    request: BuilderRunRequest
    claim_id: str
    revision: int
    expires_at: str


def _claim_timestamp(value: str, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise BuilderError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise BuilderError(code) from error
    if parsed.tzinfo != UTC or parsed.microsecond:
        raise BuilderError(code)
    return parsed


def _canonical_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class ProtectedBuilderStore:
    """Canonical, restart-safe builder state rooted in a protected service directory."""

    __slots__ = ("_root", "_testing")

    def __init__(self, root: Path, *, testing: bool) -> None:
        self._root = root
        self._testing = testing
        if testing:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
        else:
            try:
                metadata = root.stat()
            except OSError as error:
                raise BuilderError("builder_runtime_root_unavailable") from error
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise BuilderError("builder_runtime_root_identity_invalid")
        for name in (
            "requests",
            "claims",
            "registrations",
            "attempt-receipts",
            "packets",
            "terminals",
            "effects",
            "eligibility",
            "sandbox",
        ):
            (root / name).mkdir(exist_ok=True, mode=0o700)

    @classmethod
    def from_protected_environment(cls) -> ProtectedBuilderStore:
        return cls(_PROTECTED_RUNTIME_ROOT, testing=False)

    @classmethod
    def _for_testing(cls, root: Path) -> ProtectedBuilderStore:
        if not isinstance(root, Path) or not root.is_absolute():
            raise BuilderError("builder_runtime_root_invalid")
        return cls(root, testing=True)

    def _write_once(self, path: Path, value: object) -> None:
        payload = canonical_json_bytes(value)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except FileExistsError:
            if path.read_bytes() != payload:
                raise BuilderError("builder_durable_identity_conflict") from None

    def _replace(self, path: Path, value: object) -> None:
        payload = canonical_json_bytes(value)
        temporary: str | None = None
        try:
            descriptor, temporary = tempfile.mkstemp(prefix=".builder-", dir=path.parent)
            os.chmod(temporary, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, path)
            temporary = None
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)

    def enqueue(self, request: BuilderRunRequest) -> None:
        if type(request) is not BuilderRunRequest:
            raise BuilderError("builder_run_request_invalid")
        self._write_once(
            self._root / "requests" / f"{request.digest}.json", request.to_canonical_dict()
        )
        self._write_once(
            self._root / "requests" / f"{request.digest}.status.json",
            {
                "claim_expires_at": None,
                "claim_id": None,
                "request_digest": request.digest,
                "revision": 0,
                "schema_version": 1,
                "status": "pending",
            },
        )

    def load_request(self, request_digest: str) -> BuilderRunRequest:
        if not _is_digest(request_digest):
            raise BuilderError("builder_request_digest_invalid")
        path = self._root / "requests" / f"{request_digest}.json"
        try:
            request = BuilderRunRequest.from_canonical_dict(
                _parse_object(path.read_bytes(), code="builder_request_document_invalid")
            )
        except OSError as error:
            raise BuilderError("builder_request_missing") from error
        if request.digest != request_digest:
            raise BuilderError("builder_request_digest_mismatch")
        return request

    def request_status(self, request_digest: str) -> str:
        return self._request_state(request_digest)["status"]

    def _request_state(self, request_digest: str) -> dict[str, Any]:
        path = self._root / "requests" / f"{request_digest}.status.json"
        value = _parse_object(path.read_bytes(), code="builder_request_status_invalid")
        if (
            set(value)
            != {
                "claim_expires_at",
                "claim_id",
                "request_digest",
                "revision",
                "schema_version",
                "status",
            }
            or value["schema_version"] != 1
            or value["request_digest"] != request_digest
            or value["status"] not in {"pending", "claimed", "complete", "frozen"}
            or type(value["revision"]) is not int
            or value["revision"] < 0
            or (
                value["status"] == "claimed"
                and (
                    not isinstance(value["claim_id"], str)
                    or not value["claim_id"]
                    or not isinstance(value["claim_expires_at"], str)
                )
            )
            or (
                value["status"] != "claimed"
                and (value["claim_id"] is not None or value["claim_expires_at"] is not None)
            )
        ):
            raise BuilderError("builder_request_status_invalid")
        return value

    def _claim(
        self,
        request: BuilderRunRequest,
        *,
        claim_id: str | None,
        expected_revision: int | None,
        abandoned_claim_id: str | None,
        claimed_at: str | None,
        expires_at: str | None,
    ) -> ClaimedBuilderRequest:
        status_path = self._root / "requests" / f"{request.digest}.status.json"
        lock_path = self._root / "claims" / f"{request.digest}.lock"
        try:
            lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as error:
            raise BuilderError("builder_request_claim_busy") from error
        os.close(lock_fd)
        try:
            state = self._request_state(request.digest)
            now_text = _canonical_now() if claimed_at is None else claimed_at
            now = _claim_timestamp(now_text, "builder_claim_timestamp_invalid")
            expected = state["revision"] if expected_revision is None else expected_revision
            selected_claim = claim_id or f"builder-run-{request.digest[:32]}-{expected + 1}"
            selected_expiry = expires_at or (
                (now + timedelta(minutes=15)).isoformat().replace("+00:00", "Z")
            )
            expiry = _claim_timestamp(selected_expiry, "builder_claim_timestamp_invalid")
            if expiry <= now or type(expected) is not int or expected != state["revision"]:
                raise BuilderError("builder_request_claim_cas_mismatch")
            if not isinstance(selected_claim, str) or not selected_claim:
                raise BuilderError("builder_request_claim_invalid")
            if state["status"] == "claimed":
                prior_expiry = _claim_timestamp(
                    state["claim_expires_at"], "builder_request_status_invalid"
                )
                if now < prior_expiry:
                    if selected_claim == state["claim_id"]:
                        return ClaimedBuilderRequest(
                            request, selected_claim, state["revision"], state["claim_expires_at"]
                        )
                    raise BuilderError("builder_request_not_claimable")
                if abandoned_claim_id != state["claim_id"]:
                    raise BuilderError("builder_claim_recovery_identity_mismatch")
            elif state["status"] != "pending":
                raise BuilderError("builder_request_not_claimable")
            elif abandoned_claim_id is not None:
                raise BuilderError("builder_claim_recovery_identity_mismatch")
            next_revision = state["revision"] + 1
            self._replace(
                status_path,
                {
                    "claim_expires_at": selected_expiry,
                    "claim_id": selected_claim,
                    "request_digest": request.digest,
                    "revision": next_revision,
                    "schema_version": 1,
                    "status": "claimed",
                },
            )
            self._write_once(
                self._root / "claims" / f"{request.digest}-{next_revision}.json",
                {
                    "abandoned_claim_id": abandoned_claim_id,
                    "claim_expires_at": selected_expiry,
                    "claim_id": selected_claim,
                    "claimed_at": now_text,
                    "request_digest": request.digest,
                    "revision": next_revision,
                    "schema_version": 1,
                },
            )
            return ClaimedBuilderRequest(request, selected_claim, next_revision, selected_expiry)
        finally:
            lock_path.unlink(missing_ok=True)

    def claim_manual(
        self,
        request_digest: str,
        *,
        parent_commit: str,
        immutable_inputs_digest: str,
        claim_id: str | None = None,
        expected_revision: int | None = None,
        abandoned_claim_id: str | None = None,
        claimed_at: str | None = None,
        expires_at: str | None = None,
    ) -> ClaimedBuilderRequest:
        request = self.load_request(request_digest)
        if (
            request.snapshot.exact_parent_commit != parent_commit
            or request.manifest.parent_commit != parent_commit
            or request.immutable_inputs_digest != immutable_inputs_digest
        ):
            raise BuilderError("builder_manual_dispatch_mismatch")
        return self._claim(
            request,
            claim_id=claim_id,
            expected_revision=expected_revision,
            abandoned_claim_id=abandoned_claim_id,
            claimed_at=claimed_at,
            expires_at=expires_at,
        )

    def claim_scheduled(self, *, parent_commit: str) -> ClaimedBuilderRequest:
        if not _is_commit(parent_commit):
            raise BuilderError("builder_parent_commit_invalid")
        for path in sorted((self._root / "requests").glob("*.json"), key=lambda item: item.name):
            if path.name.endswith(".status.json"):
                continue
            request = self.load_request(path.stem)
            state = self._request_state(request.digest)
            if request.snapshot.exact_parent_commit == parent_commit and state["status"] in {
                "pending",
                "claimed",
            }:
                abandoned = None
                if state["status"] == "claimed":
                    now = datetime.now(UTC).replace(microsecond=0)
                    expiry = _claim_timestamp(
                        state["claim_expires_at"], "builder_request_status_invalid"
                    )
                    if now < expiry:
                        continue
                    abandoned = state["claim_id"]
                return self._claim(
                    request,
                    claim_id=None,
                    expected_revision=None,
                    abandoned_claim_id=abandoned,
                    claimed_at=None,
                    expires_at=None,
                )
        raise BuilderError("builder_scheduled_request_unavailable")

    def register(self, request_digest: str, registration: BuilderPreregistration) -> bool:
        document = {
            "registration": registration.to_canonical_dict(),
            "registration_digest": registration.digest,
            "request_digest": request_digest,
            "status": "complete",
        }
        path = self._root / "registrations" / f"{request_digest}-{registration.digest}.json"
        self._write_once(path, document)
        return True

    def registration_documents(self, request_digest: str) -> tuple[dict[str, Any], ...]:
        documents = []
        for path in sorted((self._root / "registrations").glob(f"{request_digest}-*.json")):
            documents.append(_parse_object(path.read_bytes(), code="builder_registration_invalid"))
        return tuple(documents)

    def has_registration(self, registration_digest: str) -> bool:
        return any((self._root / "registrations").glob(f"*-{registration_digest}.json"))

    @property
    def testing(self) -> bool:
        return self._testing

    @property
    def root(self) -> Path:
        return self._root

    @property
    def sandbox_executable(self) -> Path:
        return (
            self._root / "sandbox-executor"
            if self._testing
            else Path("/usr/local/libexec/carl-product-builder-sandbox")
        )

    def receipt_key(self) -> bytes:
        path = (
            self._root / "receipt.key"
            if self._testing
            else Path("/etc/carl/product-builder-receipt.key")
        )
        try:
            key = path.read_bytes()
        except OSError as error:
            raise BuilderError("builder_receipt_key_unavailable") from error
        if len(key) != 32:
            raise BuilderError("builder_receipt_key_invalid")
        return key

    def _terminalize_request(
        self,
        request_digest: str,
        *,
        claim_id: str,
        expected_revision: int,
        status: str,
    ) -> None:
        lock_path = self._root / "claims" / f"{request_digest}.lock"
        try:
            lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as error:
            raise BuilderError("builder_request_claim_busy") from error
        os.close(lock_fd)
        try:
            state = self._request_state(request_digest)
            if (
                state["status"] != "claimed"
                or state["claim_id"] != claim_id
                or state["revision"] != expected_revision
            ):
                raise BuilderError("builder_request_completion_cas_mismatch")
            self._replace(
                self._root / "requests" / f"{request_digest}.status.json",
                {
                    "claim_expires_at": None,
                    "claim_id": None,
                    "request_digest": request_digest,
                    "revision": expected_revision + 1,
                    "schema_version": 1,
                    "status": status,
                },
            )
        finally:
            lock_path.unlink(missing_ok=True)

    def complete_request(
        self, request_digest: str, *, claim_id: str, expected_revision: int
    ) -> None:
        self._terminalize_request(
            request_digest,
            claim_id=claim_id,
            expected_revision=expected_revision,
            status="complete",
        )

    def freeze_request(self, request_digest: str, *, claim_id: str, expected_revision: int) -> None:
        self._terminalize_request(
            request_digest,
            claim_id=claim_id,
            expected_revision=expected_revision,
            status="frozen",
        )

    def persist_gateway_cost_receipt(self, receipt: object) -> None:
        from carl_bench.product_builder_gateway import ProtectedGatewayCostReceipt

        if type(receipt) is not ProtectedGatewayCostReceipt:
            raise BuilderError("builder_gateway_cost_receipt_invalid")
        directory = self._root / "gateway-receipts"
        directory.mkdir(exist_ok=True, mode=0o700)
        self._write_once(
            directory / f"{receipt.model_request_digest}.json", receipt.to_canonical_dict()
        )

    def persist_attempt_receipt(
        self, experiment_id: str, receipt: object, *, verification_key: bytes
    ) -> None:
        from carl_bench.product_builder_evidence import SignedAttemptReceipt

        if type(receipt) is not SignedAttemptReceipt:
            raise BuilderError("builder_attempt_receipt_invalid")
        verified = receipt.verify(verification_key)
        self._write_once(
            self._root / "attempt-receipts" / f"{experiment_id}-attempt-{verified.attempt}.json",
            receipt.to_canonical_dict(),
        )

    def load_attempt_receipts(
        self, experiment_id: str, *, verification_key: bytes
    ) -> tuple[object, ...]:
        from carl_bench.product_builder_evidence import SignedAttemptReceipt

        receipts = []
        for path in sorted(
            (self._root / "attempt-receipts").glob(f"{experiment_id}-attempt-*.json"),
            key=lambda item: item.name,
        ):
            value = _parse_object(path.read_bytes(), code="builder_attempt_receipt_invalid")
            try:
                envelope = SignedAttemptReceipt.from_canonical_dict(value)
                envelope.verify(verification_key)
            except ValueError as error:
                raise BuilderError("builder_attempt_receipt_invalid") from error
            receipts.append(envelope)
        if tuple(item.receipt.attempt for item in receipts) != tuple(range(1, len(receipts) + 1)):
            raise BuilderError("builder_attempt_sequence_invalid")
        return tuple(receipts)

    def persist_packet(
        self, request_digest: str, packet: object, *, verification_key: bytes
    ) -> None:
        from carl_bench.product_builder_evidence import ProtectedCandidatePacket

        if type(packet) is not ProtectedCandidatePacket:
            raise BuilderError("builder_candidate_packet_invalid")
        packet.verify(verification_key)
        self._write_once(
            self._root / "packets" / f"{packet.digest}.json",
            {
                "packet": packet.to_canonical_dict(),
                "packet_digest": packet.digest,
                "request_digest": request_digest,
            },
        )

    def load_packet(self, packet_digest: str) -> dict[str, Any]:
        if not _is_digest(packet_digest):
            raise BuilderError("builder_candidate_packet_invalid")
        try:
            value = _parse_object(
                (self._root / "packets" / f"{packet_digest}.json").read_bytes(),
                code="builder_candidate_packet_invalid",
            )
        except OSError as error:
            raise BuilderError("builder_candidate_packet_missing") from error
        if (
            set(value) != {"packet", "packet_digest", "request_digest"}
            or value["packet_digest"] != packet_digest
            or hashlib.sha256(canonical_json_bytes(value["packet"])).hexdigest() != packet_digest
        ):
            raise BuilderError("builder_candidate_packet_invalid")
        return value

    def load_verified_packet(self, packet_digest: str, *, verification_key: bytes) -> object:
        from carl_bench.product_builder_evidence import ProtectedCandidatePacket

        value = self.load_packet(packet_digest)
        try:
            return ProtectedCandidatePacket.from_canonical_dict(value["packet"]).verify(
                verification_key
            )
        except ValueError as error:
            raise BuilderError("builder_candidate_packet_invalid") from error

    def persist_terminal(self, terminal: object) -> None:
        from carl_bench.product_builder_effects import BuilderTerminalDocument
        from carl_bench.product_builder_terminal import BuilderOutcomeTerminalDocument

        if type(terminal) not in {BuilderTerminalDocument, BuilderOutcomeTerminalDocument}:
            raise BuilderError("builder_terminal_document_invalid")
        self._write_once(
            self._root / "terminals" / f"{terminal.request_digest}.json",
            terminal.to_canonical_dict(),
        )

    def load_terminal(self, request_digest: str) -> object:
        from carl_bench.product_builder_effects import BuilderTerminalDocument
        from carl_bench.product_builder_terminal import BuilderOutcomeTerminalDocument

        try:
            value = _parse_object(
                (self._root / "terminals" / f"{request_digest}.json").read_bytes(),
                code="builder_terminal_document_invalid",
            )
        except OSError as error:
            raise BuilderError("builder_terminal_document_missing") from error
        terminal = (
            BuilderTerminalDocument.from_canonical_dict(value)
            if value.get("outcome") == "candidate_packet"
            else BuilderOutcomeTerminalDocument.from_canonical_dict(value)
        )
        if terminal.request_digest != request_digest:
            raise BuilderError("builder_terminal_document_invalid")
        return terminal

    def begin_effect(self, request: object) -> object | None:
        from carl_bench.product_builder_effects import (
            PurposeBoundEffectRequest,
            PurposeBoundEffectResponse,
        )

        if type(request) is not PurposeBoundEffectRequest:
            raise BuilderError("builder_effect_request_invalid")
        response_path = self._root / "effects" / f"{request.idempotency_key}.response.json"
        freeze_path = self._root / "effects" / f"{request.idempotency_key}.freeze.json"
        request_path = self._root / "effects" / f"{request.idempotency_key}.request.json"
        if request_path.exists():
            try:
                stored_request = _parse_object(
                    request_path.read_bytes(), code="builder_effect_request_invalid"
                )
            except (OSError, BuilderError):
                stored_request = None
            if stored_request != request.to_canonical_dict():
                frozen = PurposeBoundEffectResponse(
                    1,
                    request.node,
                    request.idempotency_key,
                    request.command_key,
                    request.effect_key,
                    request.github_request_digest,
                    "frozen",
                    None,
                    "builder_effect_persisted_identity_mismatch",
                )
                self.finish_effect(frozen, force_freeze=True)
                return frozen
        if freeze_path.exists():
            return self.load_effect_response(request.idempotency_key, expected_request=request)
        if response_path.exists():
            try:
                return self.load_effect_response(request.idempotency_key, expected_request=request)
            except BuilderError:
                frozen = PurposeBoundEffectResponse(
                    1,
                    request.node,
                    request.idempotency_key,
                    request.command_key,
                    request.effect_key,
                    request.github_request_digest,
                    "frozen",
                    None,
                    "builder_effect_persisted_identity_mismatch",
                )
                self.finish_effect(frozen, force_freeze=True)
                return frozen
        self._write_once(
            request_path,
            request.to_canonical_dict(),
        )
        self._write_once(
            self._root / "effects" / f"{request.idempotency_key}.status.json",
            {"idempotency_key": request.idempotency_key, "status": "pending"},
        )
        return None

    def finish_effect(self, response: object, *, force_freeze: bool = False) -> None:
        from carl_bench.product_builder_effects import PurposeBoundEffectResponse

        if type(response) is not PurposeBoundEffectResponse:
            raise BuilderError("builder_effect_response_invalid")
        target = (
            self._root / "effects" / f"{response.idempotency_key}.freeze.json"
            if force_freeze
            else self._root / "effects" / f"{response.idempotency_key}.response.json"
        )
        self._write_once(
            target,
            response.to_canonical_dict(),
        )
        self._replace(
            self._root / "effects" / f"{response.idempotency_key}.status.json",
            {"idempotency_key": response.idempotency_key, "status": response.status},
        )

    def load_effect_response(
        self, idempotency_key: str, *, expected_request: object | None = None
    ) -> object:
        from carl_bench.product_builder_effects import (
            PurposeBoundEffectRequest,
            PurposeBoundEffectResponse,
        )

        freeze_path = self._root / "effects" / f"{idempotency_key}.freeze.json"
        path = (
            freeze_path
            if freeze_path.exists()
            else self._root / "effects" / f"{idempotency_key}.response.json"
        )
        value = _parse_object(
            path.read_bytes(),
            code="builder_effect_response_invalid",
        )
        response = PurposeBoundEffectResponse.from_canonical_dict(value)
        if response.idempotency_key != idempotency_key:
            raise BuilderError("builder_effect_persisted_identity_mismatch")
        if expected_request is not None and (
            type(expected_request) is not PurposeBoundEffectRequest
            or (
                response.node,
                response.idempotency_key,
                response.command_key,
                response.effect_key,
                response.github_request_digest,
            )
            != (
                expected_request.node,
                expected_request.idempotency_key,
                expected_request.command_key,
                expected_request.effect_key,
                expected_request.github_request_digest,
            )
        ):
            raise BuilderError("builder_effect_persisted_identity_mismatch")
        return response

    def effect_status(self, idempotency_key: str) -> str:
        value = _parse_object(
            (self._root / "effects" / f"{idempotency_key}.status.json").read_bytes(),
            code="builder_effect_status_invalid",
        )
        if value.get("idempotency_key") != idempotency_key or value.get("status") not in {
            "pending",
            "completed",
            "frozen",
        }:
            raise BuilderError("builder_effect_status_invalid")
        return value["status"]

    def publication_completed(self, terminal: object) -> bool:
        from carl_bench.product_builder_effects import (
            BuilderTerminalDocument,
            PurposeBoundEffectRequest,
        )

        if type(terminal) is not BuilderTerminalDocument:
            return False
        request = PurposeBoundEffectRequest.for_publication(terminal)
        try:
            response = self.load_effect_response(request.idempotency_key, expected_request=request)
        except OSError:
            return False
        return response.status == "completed" and response.node == "publish_experimental"

    def load_publication_eligibility(self, publication_request_digest: str) -> dict[str, Any]:
        try:
            return _parse_object(
                (self._root / "eligibility" / f"{publication_request_digest}.json").read_bytes(),
                code="builder_publication_eligibility_invalid",
            )
        except OSError as error:
            raise BuilderError("builder_publication_eligibility_missing") from error


class DurableBuilderRegistrar:
    __slots__ = ("_request_digest", "_store")

    def __init__(self, store: ProtectedBuilderStore, request_digest: str) -> None:
        self._store = store
        self._request_digest = request_digest

    def register(self, registration: BuilderPreregistration) -> bool:
        return self._store.register(self._request_digest, registration)


@dataclass(frozen=True, slots=True)
class SandboxObservation:
    outcome: Literal["candidate", "repairable", "rejected", "inconclusive"]
    attempt: BuildAttemptEvidence
    candidate: SealedCandidate | None
    candidate_tree: str | None
    diff_artifact_digest: str
    evidence_digest: str | None
    next_hypothesis: ProductHypothesis | None
    prepatch_tree: str
    postpatch_tree: str
    test_command: tuple[str, ...]
    test_output_artifact_digest: str
    requested_at: str
    repository_id: str
    remote_url: str

    def __post_init__(self) -> None:
        candidate = (
            self.outcome == "candidate"
            and type(self.candidate) is SealedCandidate
            and _is_commit(self.candidate_tree)
            and self.candidate_tree == self.postpatch_tree
            and self.evidence_digest is None
            and self.next_hypothesis is None
        )
        unsuccessful = (
            self.outcome in {"repairable", "rejected", "inconclusive"}
            and self.candidate is None
            and self.candidate_tree is None
            and _is_digest(self.evidence_digest)
            and type(self.next_hypothesis) is ProductHypothesis
        )
        if (
            not (candidate or unsuccessful)
            or not _is_digest(self.diff_artifact_digest)
            or self.diff_artifact_digest != self.attempt.patch_digest
            or not _is_commit(self.prepatch_tree)
            or not _is_commit(self.postpatch_tree)
        ):
            raise BuilderError("builder_sandbox_observation_invalid")

    @classmethod
    def from_canonical_dict(cls, value: object) -> SandboxObservation:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise BuilderError("builder_sandbox_observation_invalid")
        attempt = value["attempt"]
        if type(attempt) is not dict:
            raise BuilderError("builder_sandbox_observation_invalid")
        normalized_attempt = dict(attempt)
        try:
            normalized_attempt["changed_paths"] = tuple(normalized_attempt["changed_paths"])
            normalized_attempt["tools"] = tuple(normalized_attempt["tools"])
            candidate = (
                None
                if value["candidate"] is None
                else SealedCandidate.from_canonical_dict(value["candidate"])
            )
            next_hypothesis = (
                None
                if value["next_hypothesis"] is None
                else ProductHypothesis(**value["next_hypothesis"])
            )
            return cls(
                outcome=value["outcome"],
                attempt=BuildAttemptEvidence(**normalized_attempt),
                candidate=candidate,
                candidate_tree=value["candidate_tree"],
                diff_artifact_digest=value["diff_artifact_digest"],
                evidence_digest=value["evidence_digest"],
                next_hypothesis=next_hypothesis,
                prepatch_tree=value["prepatch_tree"],
                postpatch_tree=value["postpatch_tree"],
                test_command=tuple(value["test_command"]),
                test_output_artifact_digest=value["test_output_artifact_digest"],
                requested_at=value["requested_at"],
                repository_id=value["repository_id"],
                remote_url=value["remote_url"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise BuilderError("builder_sandbox_observation_invalid") from error


class ProtectedCandidateSandboxExecutor:
    """Concrete fixed-executable candidate boundary; candidate environment is passed explicitly."""

    __slots__ = ("_executable", "_root", "environment")

    def __init__(self, store: ProtectedBuilderStore, environment: dict[str, str]) -> None:
        self.environment = dict(environment)
        self._executable = store.sandbox_executable
        self._root = store._root / "sandbox"
        try:
            metadata = self._executable.lstat()
        except OSError as error:
            raise BuilderError("builder_sandbox_executor_unavailable") from error
        expected_uid = os.getuid() if store.testing else 0
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not os.access(self._executable, os.X_OK)
        ):
            raise BuilderError("builder_sandbox_executor_identity_invalid")

    def execute(self, invocation: object, limits: BuilderLimits) -> SandboxObservation:
        from carl_bench.product_builder import BuilderModelInvocation

        if not isinstance(invocation, BuilderModelInvocation) or type(limits) is not BuilderLimits:
            raise BuilderError("builder_sandbox_invocation_invalid")
        if not self._executable.is_file() or not os.access(self._executable, os.X_OK):
            raise BuilderError("builder_sandbox_executor_unavailable")
        request = {
            "limits": limits.to_canonical_dict(),
            "model_output_digest": invocation.result.output_digest,
            "model_output_text": invocation.result.output_text,
            "model_request_digest": invocation.request.request_digest,
            "registration": invocation.registration.to_canonical_dict(),
            "registration_digest": invocation.registration.digest,
            "schema_version": 1,
        }
        with tempfile.TemporaryDirectory(prefix="attempt-", dir=self._root) as directory:
            request_path = Path(directory) / "request.json"
            result_path = Path(directory) / "result.json"
            request_path.write_bytes(canonical_json_bytes(request))
            try:
                completed = subprocess.run(
                    (
                        os.fspath(self._executable),
                        "--request",
                        os.fspath(request_path),
                        "--result",
                        os.fspath(result_path),
                    ),
                    cwd=directory,
                    env=self.environment,
                    capture_output=True,
                    timeout=limits.max_elapsed_seconds,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as error:
                raise BuilderError("builder_sandbox_execution_failed") from error
            if completed.returncode != 0:
                raise BuilderError("builder_sandbox_execution_failed")
            try:
                value = _parse_object(
                    result_path.read_bytes(), code="builder_sandbox_observation_invalid"
                )
            except OSError as error:
                raise BuilderError("builder_sandbox_observation_invalid") from error
        return SandboxObservation.from_canonical_dict(value)


class DurablePacketStore:
    __slots__ = ("_store",)

    def __init__(self, store: ProtectedBuilderStore) -> None:
        self._store = store

    def persist(
        self,
        request_digest: str,
        packet: object,
        *,
        verification_key: bytes,
    ) -> None:
        self._store.persist_packet(request_digest, packet, verification_key=verification_key)


class CanonicalTerminalWriter:
    __slots__ = ("_store",)

    def __init__(self, store: ProtectedBuilderStore) -> None:
        self._store = store

    def write(self, terminal: object, result_path: Path) -> None:
        from carl_bench.product_builder_effects import BuilderTerminalDocument
        from carl_bench.product_builder_terminal import BuilderOutcomeTerminalDocument

        if (
            type(terminal)
            not in {
                BuilderTerminalDocument,
                BuilderOutcomeTerminalDocument,
            }
            or not result_path.is_absolute()
        ):
            raise BuilderError("builder_terminal_output_invalid")
        self._store.persist_terminal(terminal)
        payload = canonical_json_bytes(terminal.to_canonical_dict())
        try:
            descriptor = os.open(result_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
        except FileExistsError:
            if result_path.read_bytes() != payload:
                raise BuilderError("builder_terminal_output_conflict") from None


def _read_environment(path: Path) -> dict[str, str]:
    value = _parse_object(path.read_bytes(), code="builder_candidate_environment_invalid")
    expected = {"CI", "HOME", "LANG", "LC_ALL", "PATH"}
    if set(value) != expected or any(
        not isinstance(item, str) or not item for item in value.values()
    ):
        raise BuilderError("builder_candidate_environment_invalid")
    return value


def run_protected(args: argparse.Namespace) -> int:
    if args.runtime_root_for_testing is not None and "PYTEST_CURRENT_TEST" not in os.environ:
        raise BuilderError("builder_testing_runtime_forbidden")
    store = (
        ProtectedBuilderStore._for_testing(args.runtime_root_for_testing)
        if args.runtime_root_for_testing is not None
        else ProtectedBuilderStore.from_protected_environment()
    )
    if args.scheduled:
        claimed = store.claim_scheduled(parent_commit=args.parent_commit)
    else:
        if args.request_digest is None or args.immutable_inputs_digest is None:
            raise BuilderError("builder_manual_dispatch_incomplete")
        claimed = store.claim_manual(
            args.request_digest,
            parent_commit=args.parent_commit,
            immutable_inputs_digest=args.immutable_inputs_digest,
        )
    request = claimed.request
    prompt = args.prompt.read_text(encoding="utf-8")
    if hashlib.sha256(prompt.encode()).hexdigest() != request.prompt_digest:
        raise BuilderError("builder_prompt_digest_mismatch")
    environment = _read_environment(args.candidate_environment)
    registrar = DurableBuilderRegistrar(store, request.digest)
    gateway = ProtectedOpenAIGateway(store)
    sandbox = ProtectedCandidateSandboxExecutor(store, environment)
    packet_store = DurablePacketStore(store)
    terminal_writer = CanonicalTerminalWriter(store)
    verification_key = store.receipt_key()
    prior_envelopes = store.load_attempt_receipts(
        request.manifest.experiment_id, verification_key=verification_key
    )
    prior_receipts = tuple(item.receipt for item in prior_envelopes)
    prior_attempts = tuple(item.to_attempt_evidence() for item in prior_receipts)
    if len(prior_attempts) != request.attempt - 1:
        raise BuilderError("builder_attempt_sequence_invalid")
    if prior_attempts:
        validate_attempts(request.limits, prior_attempts)
    selection = select_hypothesis(request.snapshot, request.hypotheses)
    invocation = preregister_and_call_model(
        selection=selection,
        manifest=request.manifest,
        snapshot=request.snapshot,
        limits=request.limits,
        registrar=registrar,
        gateway=gateway,
        prompt=prompt,
        attempt=request.attempt,
    )
    observation = sandbox.execute(invocation, request.limits)
    if prior_receipts and prior_receipts[-1].postpatch_tree != observation.prepatch_tree:
        raise BuilderError("builder_attempt_tree_sequence_invalid")
    from carl_bench.product_builder_effects import BuilderTerminalDocument
    from carl_bench.product_builder_evidence import (
        ProtectedAttemptReceipt,
        ProtectedCandidatePacket,
        SignedAttemptReceipt,
    )

    receipt = ProtectedAttemptReceipt.from_observation(
        registration=invocation.registration,
        builder_request_digest=request.digest,
        attempt=observation.attempt,
        exact_parent=request.snapshot.exact_parent_commit,
        prepatch_tree=observation.prepatch_tree,
        test_command=observation.test_command,
        test_output_artifact_digest=observation.test_output_artifact_digest,
        diff_artifact_digest=observation.diff_artifact_digest,
        postpatch_tree=observation.postpatch_tree,
        model_request=invocation.request,
        model_result=invocation.result,
        gateway_cost_receipt=gateway.cost_receipt(invocation.request.request_digest),
    )
    current_envelope = SignedAttemptReceipt.sign(receipt, verification_key)
    store.persist_attempt_receipt(
        request.manifest.experiment_id,
        current_envelope,
        verification_key=verification_key,
    )
    all_envelopes = (*prior_envelopes, current_envelope)
    all_attempts = (*prior_attempts, observation.attempt)
    if observation.outcome != "candidate":
        if observation.evidence_digest is None or observation.next_hypothesis is None:
            raise BuilderError("builder_sandbox_observation_invalid")
        result = terminalize_unsuccessful_attempt(
            registration=invocation.registration,
            current=selection.selected,
            limits=request.limits,
            attempts=all_attempts,
            finding_digest=observation.evidence_digest,
            disposition=observation.outcome,
            next_hypothesis=observation.next_hypothesis,
        )
        from carl_bench.product_builder_terminal import BuilderOutcomeTerminalDocument

        terminal = BuilderOutcomeTerminalDocument.create(
            request=request,
            registration_digest=invocation.registration.digest,
            result=result,
            attempt_receipt_digests=tuple(item.receipt.digest for item in all_envelopes),
        )
        terminal_writer.write(terminal, args.result)
        store.complete_request(
            request.digest,
            claim_id=claimed.claim_id,
            expected_revision=claimed.revision,
        )
        return 0
    validate_attempts(request.limits, all_attempts)
    if (
        observation.candidate is None
        or observation.candidate_tree is None
        or (
            observation.candidate.experiment_id != request.manifest.experiment_id
            or observation.candidate.manifest_digest != request.manifest.digest
            or observation.candidate.parent_commit != request.snapshot.exact_parent_commit
        )
    ):
        raise BuilderError("builder_candidate_packet_mismatch")
    packet = ProtectedCandidatePacket(
        schema_version=1,
        builder_request_digest=request.digest,
        registration_digest=invocation.registration.digest,
        parent_commit=request.snapshot.exact_parent_commit,
        candidate_tree=observation.candidate_tree,
        diff_artifact_digest=observation.diff_artifact_digest,
        candidate=observation.candidate,
        attempt_receipts=all_envelopes,
    ).verify(verification_key)
    packet_store.persist(request.digest, packet, verification_key=verification_key)
    terminal = BuilderTerminalDocument.create(
        request=request,
        registration_digest=invocation.registration.digest,
        packet=packet,
        candidate_tree=observation.candidate_tree,
        requested_at=observation.requested_at,
        repository_id=observation.repository_id,
        remote_url=observation.remote_url,
    )
    terminal_writer.write(terminal, args.result)
    store.complete_request(
        request.digest,
        claim_id=claimed.claim_id,
        expected_revision=claimed.revision,
    )
    return 0


def run_effect(args: argparse.Namespace) -> int:
    from carl_bench.product_builder_effects import (
        ProtectedBuilderEffectExecutor,
        PurposeBoundEffectRequest,
        PurposeBoundEffectResponse,
    )

    store = ProtectedBuilderStore.from_protected_environment()
    terminal = store.load_terminal(args.request_digest)
    expected = (
        PurposeBoundEffectRequest.for_publication(terminal)
        if args.command == "publish-protected"
        else PurposeBoundEffectRequest.for_validation(terminal)
    )
    supplied = (
        args.experiment_id,
        args.request_digest,
        args.publication_request_digest,
        args.candidate_packet_digest,
        args.parent_commit,
        args.expected_revision,
        args.idempotency_key,
    )
    actual = (
        expected.experiment_id,
        expected.request_digest,
        expected.publication_request_digest,
        expected.candidate_packet_digest,
        expected.parent_commit,
        expected.expected_revision,
        expected.idempotency_key,
    )
    if supplied != actual:
        existing = store.begin_effect(expected)
        if existing is not None:
            response = existing
        else:
            response = PurposeBoundEffectResponse(
                1,
                expected.node,
                expected.idempotency_key,
                expected.command_key,
                expected.effect_key,
                expected.github_request_digest,
                "frozen",
                None,
                "builder_effect_cli_identity_mismatch",
            )
            store.finish_effect(response)
    else:
        response = ProtectedBuilderEffectExecutor.from_protected_environment(store=store).execute(
            expected
        )
    payload = canonical_json_bytes(response.to_canonical_dict())
    args.result.write_bytes(payload)
    sys.stdout.write(payload.decode("utf-8") + "\n")
    return 0 if response.status == "completed" else 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m carl_bench.product_builder")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run-protected")
    run.add_argument("--request-digest")
    run.add_argument("--parent-commit", required=True)
    run.add_argument("--immutable-inputs-digest")
    run.add_argument("--candidate-environment", required=True, type=Path)
    run.add_argument("--prompt", required=True, type=Path)
    run.add_argument("--result", required=True, type=Path)
    run.add_argument("--scheduled", action="store_true")
    run.add_argument("--runtime-root-for-testing", type=Path, help=argparse.SUPPRESS)
    for name in ("publish-protected", "dispatch-validation-protected"):
        effect = commands.add_parser(name)
        effect.add_argument("--experiment-id", required=True)
        effect.add_argument("--request-digest", required=True)
        effect.add_argument("--publication-request-digest", required=True)
        effect.add_argument("--candidate-packet-digest", required=True)
        effect.add_argument("--parent-commit", required=True)
        effect.add_argument("--expected-revision", required=True, type=int)
        effect.add_argument("--idempotency-key", required=True)
        effect.add_argument("--result", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.command == "run-protected":
            return run_protected(args)
        if args.command in {"publish-protected", "dispatch-validation-protected"}:
            return run_effect(args)
    except (BuilderError, OSError, UnicodeError, ValueError):
        print("carl-product-builder: protected runtime or contract error", file=sys.stderr)
        return 2
    return 2
