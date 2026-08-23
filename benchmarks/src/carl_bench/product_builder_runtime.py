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
from pathlib import Path
from typing import Any

from carl_bench.candidate import SealedCandidate
from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_coordinator import ImmutableInputBinding
from carl_bench.experiment import ExperimentManifest
from carl_bench.openai_gateway import (
    OpenAIModelGateway,
    OpenAIModelRequest,
    OpenAIModelResult,
    OpenAIUsage,
)
from carl_bench.product_builder import (
    BuildAttemptEvidence,
    BuilderError,
    BuilderLimits,
    BuilderPreregistration,
    BuilderSnapshot,
    ProductHypothesis,
    preregister_and_call_model,
    select_hypothesis,
    validate_attempts,
)

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
            {"request_digest": request.digest, "status": "pending"},
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
        path = self._root / "requests" / f"{request_digest}.status.json"
        value = _parse_object(path.read_bytes(), code="builder_request_status_invalid")
        if value.get("request_digest") != request_digest or value.get("status") not in {
            "pending",
            "claimed",
            "complete",
            "frozen",
        }:
            raise BuilderError("builder_request_status_invalid")
        return value["status"]

    def _claim(self, request: BuilderRunRequest) -> BuilderRunRequest:
        claim = self._root / "claims" / request.digest
        self._write_once(claim, {"request_digest": request.digest})
        self._replace(
            self._root / "requests" / f"{request.digest}.status.json",
            {"request_digest": request.digest, "status": "claimed"},
        )
        return request

    def claim_manual(
        self,
        request_digest: str,
        *,
        parent_commit: str,
        immutable_inputs_digest: str,
    ) -> BuilderRunRequest:
        request = self.load_request(request_digest)
        if (
            request.snapshot.exact_parent_commit != parent_commit
            or request.manifest.parent_commit != parent_commit
            or request.immutable_inputs_digest != immutable_inputs_digest
        ):
            raise BuilderError("builder_manual_dispatch_mismatch")
        return self._claim(request)

    def claim_scheduled(self, *, parent_commit: str) -> BuilderRunRequest:
        if not _is_commit(parent_commit):
            raise BuilderError("builder_parent_commit_invalid")
        for path in sorted((self._root / "requests").glob("*.json"), key=lambda item: item.name):
            if path.name.endswith(".status.json"):
                continue
            request = self.load_request(path.stem)
            if (
                request.snapshot.exact_parent_commit == parent_commit
                and self.request_status(request.digest) == "pending"
            ):
                return self._claim(request)
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

    def complete_request(self, request_digest: str) -> None:
        self._replace(
            self._root / "requests" / f"{request_digest}.status.json",
            {"request_digest": request_digest, "status": "complete"},
        )

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

        if type(terminal) is not BuilderTerminalDocument:
            raise BuilderError("builder_terminal_document_invalid")
        self._write_once(
            self._root / "terminals" / f"{terminal.request_digest}.json",
            terminal.to_canonical_dict(),
        )

    def load_terminal(self, request_digest: str) -> object:
        from carl_bench.product_builder_effects import BuilderTerminalDocument

        try:
            value = _parse_object(
                (self._root / "terminals" / f"{request_digest}.json").read_bytes(),
                code="builder_terminal_document_invalid",
            )
        except OSError as error:
            raise BuilderError("builder_terminal_document_missing") from error
        terminal = BuilderTerminalDocument.from_canonical_dict(value)
        if terminal.request_digest != request_digest:
            raise BuilderError("builder_terminal_document_invalid")
        return terminal

    def begin_effect(self, request: object) -> object | None:
        from carl_bench.product_builder_effects import PurposeBoundEffectRequest

        if type(request) is not PurposeBoundEffectRequest:
            raise BuilderError("builder_effect_request_invalid")
        response_path = self._root / "effects" / f"{request.idempotency_key}.response.json"
        if response_path.exists():
            return self.load_effect_response(request.idempotency_key)
        self._write_once(
            self._root / "effects" / f"{request.idempotency_key}.request.json",
            request.to_canonical_dict(),
        )
        self._write_once(
            self._root / "effects" / f"{request.idempotency_key}.status.json",
            {"idempotency_key": request.idempotency_key, "status": "pending"},
        )
        return None

    def finish_effect(self, response: object) -> None:
        from carl_bench.product_builder_effects import PurposeBoundEffectResponse

        if type(response) is not PurposeBoundEffectResponse:
            raise BuilderError("builder_effect_response_invalid")
        self._write_once(
            self._root / "effects" / f"{response.idempotency_key}.response.json",
            response.to_canonical_dict(),
        )
        self._replace(
            self._root / "effects" / f"{response.idempotency_key}.status.json",
            {"idempotency_key": response.idempotency_key, "status": response.status},
        )

    def load_effect_response(self, idempotency_key: str) -> object:
        from carl_bench.product_builder_effects import PurposeBoundEffectResponse

        value = _parse_object(
            (self._root / "effects" / f"{idempotency_key}.response.json").read_bytes(),
            code="builder_effect_response_invalid",
        )
        return PurposeBoundEffectResponse.from_canonical_dict(value)

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
            response = self.load_effect_response(request.idempotency_key)
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


class ProtectedOpenAIGateway:
    """Lazy gateway that refuses evaluation unless durable preregistration is visible."""

    __slots__ = ("_costs", "_store")

    def __init__(self, store: ProtectedBuilderStore) -> None:
        self._store = store
        self._costs: dict[str, int] = {}

    def evaluate(self, request: OpenAIModelRequest) -> OpenAIModelResult:
        if not self._store.has_registration(request.execution_context_digest):
            raise BuilderError("builder_preregistration_not_durable")
        if self._store.testing:
            value = _parse_object(
                (self._store._root / "test-model-result.json").read_bytes(),
                code="builder_model_result_invalid",
            )
            usage_value = value.pop("usage", None)
            trusted_cost = value.pop("trusted_cost_microdollars", None)
            if type(usage_value) is not dict or not isinstance(trusted_cost, int):
                raise BuilderError("builder_model_result_invalid")
            try:
                result = OpenAIModelResult(
                    **value,
                    usage=OpenAIUsage(**usage_value),
                    request_digest=request.request_digest,
                )
            except TypeError as error:
                raise BuilderError("builder_model_result_invalid") from error
            self._costs[request.request_digest] = trusted_cost
            return result
        result = OpenAIModelGateway.from_protected_environment().evaluate(request)
        # Cost policy is controller-owned and intentionally independent of candidate output.
        self._costs[request.request_digest] = result.usage.total_tokens
        return result

    def trusted_cost_microdollars(self, request_digest: str) -> int:
        try:
            return self._costs[request_digest]
        except KeyError as error:
            raise BuilderError("builder_gateway_cost_missing") from error


@dataclass(frozen=True, slots=True)
class SandboxObservation:
    attempt: BuildAttemptEvidence
    candidate: SealedCandidate
    candidate_tree: str
    prepatch_tree: str
    postpatch_tree: str
    test_command: tuple[str, ...]
    test_output_artifact_digest: str
    requested_at: str
    repository_id: str
    remote_url: str

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
            return cls(
                attempt=BuildAttemptEvidence(**normalized_attempt),
                candidate=SealedCandidate.from_canonical_dict(value["candidate"]),
                candidate_tree=value["candidate_tree"],
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

        if type(terminal) is not BuilderTerminalDocument or not result_path.is_absolute():
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
        request = store.claim_scheduled(parent_commit=args.parent_commit)
    else:
        if args.request_digest is None or args.immutable_inputs_digest is None:
            raise BuilderError("builder_manual_dispatch_incomplete")
        request = store.claim_manual(
            args.request_digest,
            parent_commit=args.parent_commit,
            immutable_inputs_digest=args.immutable_inputs_digest,
        )
    prompt = args.prompt.read_text(encoding="utf-8")
    if hashlib.sha256(prompt.encode()).hexdigest() != request.prompt_digest:
        raise BuilderError("builder_prompt_digest_mismatch")
    environment = _read_environment(args.candidate_environment)
    registrar = DurableBuilderRegistrar(store, request.digest)
    gateway = ProtectedOpenAIGateway(store)
    sandbox = ProtectedCandidateSandboxExecutor(store, environment)
    packet_store = DurablePacketStore(store)
    terminal_writer = CanonicalTerminalWriter(store)
    invocation = preregister_and_call_model(
        selection=select_hypothesis(request.snapshot, request.hypotheses),
        manifest=request.manifest,
        snapshot=request.snapshot,
        limits=request.limits,
        registrar=registrar,
        gateway=gateway,
        prompt=prompt,
        attempt=request.attempt,
    )
    observation = sandbox.execute(invocation, request.limits)
    validate_attempts(request.limits, (observation.attempt,))
    if (
        observation.candidate.experiment_id != request.manifest.experiment_id
        or observation.candidate.manifest_digest != request.manifest.digest
        or observation.candidate.parent_commit != request.snapshot.exact_parent_commit
    ):
        raise BuilderError("builder_candidate_packet_mismatch")
    from carl_bench.product_builder_effects import BuilderTerminalDocument
    from carl_bench.product_builder_evidence import (
        ProtectedAttemptReceipt,
        ProtectedCandidatePacket,
        SignedAttemptReceipt,
    )

    receipt = ProtectedAttemptReceipt.from_observation(
        registration=invocation.registration,
        attempt=observation.attempt,
        exact_parent=request.snapshot.exact_parent_commit,
        prepatch_tree=observation.prepatch_tree,
        test_command=observation.test_command,
        test_output_artifact_digest=observation.test_output_artifact_digest,
        postpatch_tree=observation.postpatch_tree,
        model_request=invocation.request,
        model_result=invocation.result,
        trusted_cost_microdollars=gateway.trusted_cost_microdollars(
            invocation.request.request_digest
        ),
    )
    verification_key = store.receipt_key()
    packet = ProtectedCandidatePacket(
        schema_version=1,
        registration_digest=invocation.registration.digest,
        parent_commit=request.snapshot.exact_parent_commit,
        candidate=observation.candidate,
        attempt_receipts=(SignedAttemptReceipt.sign(receipt, verification_key),),
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
    store.complete_request(request.digest)
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
