"""Purpose-bound, idempotent publication and validation effects for product-builder terminals."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from carl_bench.canonical import canonical_json_bytes
from carl_bench.capability_validation import experimental_publication_request_digest
from carl_bench.cloud_execution import CloudRunRequest
from carl_bench.cloud_state import CloudCommand, CommandClaim, CommandState
from carl_bench.experimental_publication import (
    ExperimentalEligibilityVerifier,
    ExperimentalPublicationPolicy,
    ExperimentalPublicationRequest,
    SignedExperimentalPublicationEligibility,
    reconcile_experimental_publication,
)
from carl_bench.github_cloud import (
    ExperimentalBranchRequest,
    experimental_branch_binding,
    workflow_dispatch_binding,
)
from carl_bench.github_effect_client import GitHubEffectSocketClient
from carl_bench.github_effect_ipc import (
    REQUEST_DOMAIN,
    GitHubEffectOperation,
    GitHubEffectRequest,
    GitHubEffectResponse,
)
from carl_bench.product_builder import BuilderError
from carl_bench.product_builder_evidence import ProtectedCandidatePacket
from carl_bench.product_builder_runtime import BuilderRunRequest, ValidationDispatchBinding

_HEX = frozenset("0123456789abcdef")
_RECEIPT_KEY = Path("/etc/carl/product-builder-receipt.key")


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or not set(value) <= _HEX:
        raise BuilderError(code)
    return value


def _commit(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) not in {40, 64} or not set(value) <= _HEX:
        raise BuilderError(code)
    return value


@dataclass(frozen=True, slots=True)
class BuilderTerminalDocument:
    schema_version: int
    request_digest: str
    expected_revision: int
    registration_digest: str
    experiment_id: str
    parent_commit: str
    candidate_packet_digest: str
    candidate_commit: str
    candidate_tree: str
    diff_artifact_digest: str
    publication_request_id: str
    publication_request_digest: str
    requested_at: str
    repository_id: str
    remote_url: str
    validation_dispatch: ValidationDispatchBinding
    outcome: Literal["candidate_packet"] = "candidate_packet"
    next_safe_node: Literal["publish_experimental"] = "publish_experimental"

    def __post_init__(self) -> None:
        if (
            self.schema_version != 1
            or self.outcome != "candidate_packet"
            or self.next_safe_node != "publish_experimental"
            or isinstance(self.expected_revision, bool)
            or not isinstance(self.expected_revision, int)
            or self.expected_revision < 0
            or not isinstance(self.experiment_id, str)
            or not self.experiment_id
            or not isinstance(self.publication_request_id, str)
            or not self.publication_request_id
            or type(self.validation_dispatch) is not ValidationDispatchBinding
        ):
            raise BuilderError("builder_terminal_document_invalid")
        for value, code in (
            (self.request_digest, "builder_terminal_request_invalid"),
            (self.registration_digest, "builder_terminal_registration_invalid"),
            (self.candidate_packet_digest, "builder_terminal_packet_invalid"),
            (self.diff_artifact_digest, "builder_terminal_packet_invalid"),
            (self.publication_request_digest, "builder_terminal_publication_invalid"),
        ):
            _digest(value, code)
        for value in (self.parent_commit, self.candidate_commit, self.candidate_tree):
            _commit(value, "builder_terminal_commit_invalid")
        expected = experimental_publication_request_digest(
            request_id=self.publication_request_id,
            requested_at=self.requested_at,
            experiment_id=self.experiment_id,
            branch=f"experimental/{self.experiment_id}",
            candidate_packet_digest=self.candidate_packet_digest,
            candidate_commit=self.candidate_commit,
            candidate_tree=self.candidate_tree,
            repository_id=self.repository_id,
            remote_url=self.remote_url,
        )
        if expected != self.publication_request_digest:
            raise BuilderError("builder_terminal_publication_invalid")

    @classmethod
    def create(
        cls,
        *,
        request: BuilderRunRequest,
        registration_digest: str,
        packet: ProtectedCandidatePacket,
        candidate_tree: str,
        requested_at: str,
        repository_id: str,
        remote_url: str,
    ) -> BuilderTerminalDocument:
        if (
            type(request) is not BuilderRunRequest
            or type(packet) is not ProtectedCandidatePacket
            or packet.parent_commit != request.snapshot.exact_parent_commit
            or packet.candidate.experiment_id != request.manifest.experiment_id
            or packet.registration_digest != registration_digest
            or packet.builder_request_digest != request.digest
            or packet.candidate_tree != candidate_tree
        ):
            raise BuilderError("builder_terminal_identity_mismatch")
        request_id = f"builder-{request.digest[:32]}"
        publication_digest = experimental_publication_request_digest(
            request_id=request_id,
            requested_at=requested_at,
            experiment_id=request.manifest.experiment_id,
            branch=f"experimental/{request.manifest.experiment_id}",
            candidate_packet_digest=packet.digest,
            candidate_commit=packet.candidate.candidate_commit,
            candidate_tree=candidate_tree,
            repository_id=repository_id,
            remote_url=remote_url,
        )
        return cls(
            schema_version=1,
            request_digest=request.digest,
            expected_revision=request.expected_revision,
            registration_digest=registration_digest,
            experiment_id=request.manifest.experiment_id,
            parent_commit=request.snapshot.exact_parent_commit,
            candidate_packet_digest=packet.digest,
            candidate_commit=packet.candidate.candidate_commit,
            candidate_tree=candidate_tree,
            diff_artifact_digest=packet.diff_artifact_digest,
            publication_request_id=request_id,
            publication_request_digest=publication_digest,
            requested_at=requested_at,
            repository_id=repository_id,
            remote_url=remote_url,
            validation_dispatch=request.validation_dispatch,
        )

    def to_canonical_dict(self) -> dict[str, object]:
        value = {name: getattr(self, name) for name in self.__dataclass_fields__}
        value["validation_dispatch"] = self.validation_dispatch.to_canonical_dict()
        return value

    @classmethod
    def from_canonical_dict(cls, value: object) -> BuilderTerminalDocument:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise BuilderError("builder_terminal_document_invalid")
        normalized = dict(value)
        normalized["validation_dispatch"] = ValidationDispatchBinding.from_canonical_dict(
            value["validation_dispatch"]
        )
        try:
            return cls(**normalized)
        except TypeError as error:
            raise BuilderError("builder_terminal_document_invalid") from error


@dataclass(frozen=True, slots=True)
class PurposeBoundEffectRequest:
    schema_version: int
    node: Literal["publish_experimental", "dispatch_validation"]
    experiment_id: str
    request_digest: str
    publication_request_digest: str
    candidate_packet_digest: str
    parent_commit: str
    expected_revision: int
    command_key: str
    effect_key: str
    github_binding_request_digest: str
    github_request_digest: str
    idempotency_key: str

    def __post_init__(self) -> None:
        if (
            self.schema_version != 1
            or self.node not in {"publish_experimental", "dispatch_validation"}
            or not isinstance(self.experiment_id, str)
            or not self.experiment_id
            or isinstance(self.expected_revision, bool)
            or not isinstance(self.expected_revision, int)
            or self.expected_revision < 0
            or not isinstance(self.command_key, str)
            or not self.command_key
            or not isinstance(self.effect_key, str)
            or not self.effect_key.startswith("cloud-effect-")
        ):
            raise BuilderError("builder_effect_request_invalid")
        for value in (
            self.request_digest,
            self.publication_request_digest,
            self.candidate_packet_digest,
            self.github_binding_request_digest,
            self.github_request_digest,
            self.idempotency_key,
        ):
            _digest(value, "builder_effect_request_invalid")
        _commit(self.parent_commit, "builder_effect_request_invalid")
        identity = self.to_canonical_dict()
        identity.pop("idempotency_key")
        expected = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
        if self.idempotency_key != expected:
            raise BuilderError("builder_effect_idempotency_invalid")

    @classmethod
    def _create(
        cls,
        node: Literal["publish_experimental", "dispatch_validation"],
        terminal: BuilderTerminalDocument,
    ) -> PurposeBoundEffectRequest:
        if node == "publish_experimental":
            typed = ExperimentalBranchRequest.create(
                experiment_id=terminal.experiment_id,
                candidate_commit=terminal.candidate_commit,
            )
            binding = experimental_branch_binding(terminal.repository_id, typed)
            operation = GitHubEffectOperation.CREATE_EXPERIMENTAL_REF
            parameters = {
                "branch": typed.branch,
                "candidate_commit": typed.candidate_commit,
                "experiment_id": typed.experiment_id,
            }
        else:
            dispatch = terminal.validation_dispatch
            typed = CloudRunRequest.create(
                repository=dispatch.repository,
                workflow_file=dispatch.workflow_file,
                workflow_revision=dispatch.workflow_revision,
                workflow_blob_digest=dispatch.workflow_blob_digest,
                experiment_digest=dispatch.experiment_digest,
                candidate_commit=terminal.candidate_commit,
                parent_commit=terminal.parent_commit,
                task_set_digest=dispatch.task_set_digest,
                metric_pack_digest=dispatch.metric_pack_digest,
                policy_digest=dispatch.policy_digest,
            )
            binding = workflow_dispatch_binding(typed, attempt=1)
            operation = GitHubEffectOperation.DISPATCH_WORKFLOW
            parameters = {
                "candidate_commit": terminal.candidate_commit,
                "experiment_digest": dispatch.experiment_digest,
                "metric_pack_digest": dispatch.metric_pack_digest,
                "parent_commit": terminal.parent_commit,
                "policy_digest": dispatch.policy_digest,
                "repository": dispatch.repository,
                "task_set_digest": dispatch.task_set_digest,
                "workflow_blob_digest": dispatch.workflow_blob_digest,
                "workflow_file": dispatch.workflow_file,
                "workflow_revision": dispatch.workflow_revision,
            }
        command = CloudCommand.create(
            command_key=binding.command_key,
            authority=binding.authority,
            operation=binding.operation,
            request_digest=binding.request_digest,
            occurred_at=terminal.requested_at,
            expected_revision=terminal.expected_revision,
            attempt=1,
            max_attempts=3,
        )
        github_request = GitHubEffectRequest.from_canonical_dict(
            {
                "command_key": command.command_key,
                "domain": REQUEST_DOMAIN,
                "effect_key": command.effect_key,
                "occurred_at": command.occurred_at,
                "operation": operation.value,
                "parameters": parameters,
                "request_key": binding.request_key,
                "schema_version": 1,
            }
        )
        value = {
            "candidate_packet_digest": terminal.candidate_packet_digest,
            "command_key": command.command_key,
            "effect_key": command.effect_key,
            "expected_revision": terminal.expected_revision,
            "experiment_id": terminal.experiment_id,
            "github_binding_request_digest": binding.request_digest,
            "github_request_digest": github_request.digest,
            "node": node,
            "parent_commit": terminal.parent_commit,
            "publication_request_digest": terminal.publication_request_digest,
            "request_digest": terminal.request_digest,
            "schema_version": 1,
        }
        return cls(**value, idempotency_key=hashlib.sha256(canonical_json_bytes(value)).hexdigest())

    @classmethod
    def for_publication(cls, terminal: BuilderTerminalDocument) -> PurposeBoundEffectRequest:
        return cls._create("publish_experimental", terminal)

    @classmethod
    def for_validation(cls, terminal: BuilderTerminalDocument) -> PurposeBoundEffectRequest:
        return cls._create("dispatch_validation", terminal)

    def to_canonical_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    def github_request(self, terminal: BuilderTerminalDocument) -> GitHubEffectRequest:
        recreated = type(self)._create(self.node, terminal)
        if recreated != self:
            raise BuilderError("builder_effect_request_identity_mismatch")
        if self.node == "publish_experimental":
            parameters: dict[str, object] = {
                "branch": f"experimental/{terminal.experiment_id}",
                "candidate_commit": terminal.candidate_commit,
                "experiment_id": terminal.experiment_id,
            }
            operation = GitHubEffectOperation.CREATE_EXPERIMENTAL_REF
            request_key = experimental_branch_binding(
                terminal.repository_id,
                ExperimentalBranchRequest.create(
                    experiment_id=terminal.experiment_id,
                    candidate_commit=terminal.candidate_commit,
                ),
            ).request_key
        else:
            dispatch = terminal.validation_dispatch
            parameters = {
                "candidate_commit": terminal.candidate_commit,
                "experiment_digest": dispatch.experiment_digest,
                "metric_pack_digest": dispatch.metric_pack_digest,
                "parent_commit": terminal.parent_commit,
                "policy_digest": dispatch.policy_digest,
                "repository": dispatch.repository,
                "task_set_digest": dispatch.task_set_digest,
                "workflow_blob_digest": dispatch.workflow_blob_digest,
                "workflow_file": dispatch.workflow_file,
                "workflow_revision": dispatch.workflow_revision,
            }
            typed = CloudRunRequest.create(**parameters)
            request_key = workflow_dispatch_binding(typed, attempt=1).request_key
            operation = GitHubEffectOperation.DISPATCH_WORKFLOW
        request = GitHubEffectRequest.from_canonical_dict(
            {
                "command_key": self.command_key,
                "domain": REQUEST_DOMAIN,
                "effect_key": self.effect_key,
                "occurred_at": terminal.requested_at,
                "operation": operation.value,
                "parameters": parameters,
                "request_key": request_key,
                "schema_version": 1,
            }
        )
        if request.digest != self.github_request_digest:
            raise BuilderError("builder_effect_request_identity_mismatch")
        return request


@dataclass(frozen=True, slots=True)
class PurposeBoundEffectResponse:
    schema_version: int
    node: str
    idempotency_key: str
    command_key: str
    effect_key: str
    github_request_digest: str
    status: Literal["pending", "completed", "frozen"]
    result_digest: str | None
    reason: str

    def __post_init__(self) -> None:
        if (
            self.schema_version != 1
            or self.node not in {"publish_experimental", "dispatch_validation"}
            or self.status not in {"pending", "completed", "frozen"}
            or not isinstance(self.reason, str)
            or not self.reason
            or not isinstance(self.command_key, str)
            or not self.command_key
            or not isinstance(self.effect_key, str)
            or not self.effect_key.startswith("cloud-effect-")
        ):
            raise BuilderError("builder_effect_response_invalid")
        _digest(self.idempotency_key, "builder_effect_response_invalid")
        _digest(self.github_request_digest, "builder_effect_response_invalid")
        if self.status == "completed":
            _digest(self.result_digest, "builder_effect_response_invalid")
        elif self.result_digest is not None:
            raise BuilderError("builder_effect_response_invalid")

    def to_canonical_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_canonical_dict(cls, value: object) -> PurposeBoundEffectResponse:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise BuilderError("builder_effect_response_invalid")
        try:
            return cls(**value)
        except TypeError as error:
            raise BuilderError("builder_effect_response_invalid") from error


class ProtectedExperimentalPublicationAuthorizer:
    """Point-of-use adapter for the existing signed experimental publication gateway."""

    __slots__ = ("_store",)

    def __init__(self, store: object) -> None:
        self._store = store

    def authorize(
        self, terminal: BuilderTerminalDocument, packet: ProtectedCandidatePacket
    ) -> bool:
        try:
            policy_path = Path("/etc/carl/experimental-eligibility-policy.json")
            policy_raw = policy_path.read_bytes()
            policy_value = json.loads(policy_raw)
            if canonical_json_bytes(policy_value) != policy_raw:
                return False
            policy = ExperimentalPublicationPolicy.from_canonical_dict(policy_value)
            envelope = SignedExperimentalPublicationEligibility.from_canonical_dict(
                self._store.load_publication_eligibility(terminal.publication_request_digest)
            )
            publication = ExperimentalPublicationRequest(
                experiment_id=terminal.experiment_id,
                branch=f"experimental/{terminal.experiment_id}",
                candidate_packet=packet.candidate,
                candidate_tree=terminal.candidate_tree,
                request_id=terminal.publication_request_id,
                requested_at=terminal.requested_at,
                repository_id=terminal.repository_id,
                remote_url=terminal.remote_url,
            )
            decision = reconcile_experimental_publication(
                publication,
                None,
                verifier=ExperimentalEligibilityVerifier(policy=policy),
                eligibility=envelope,
            )
        except Exception:
            return False
        return decision.outcome == "push_branch"


class DurableCoordinatorCommandAuthority:
    """Testable durable authority using the same CloudCommand/CommandClaim contracts."""

    __slots__ = ("_root",)

    def __init__(self, root: Path) -> None:
        self._root = root
        root.mkdir(parents=True, exist_ok=True, mode=0o700)

    @classmethod
    def _for_testing(cls, root: Path) -> DurableCoordinatorCommandAuthority:
        return cls(root)

    def _path(self, command_key: str) -> Path:
        digest = hashlib.sha256(command_key.encode()).hexdigest()
        return self._root / f"{digest}.json"

    def _write(self, path: Path, value: object) -> None:
        payload = canonical_json_bytes(value)
        descriptor, temporary = tempfile.mkstemp(prefix=".command-", dir=self._root)
        try:
            os.chmod(temporary, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            temporary = ""
        finally:
            if temporary:
                Path(temporary).unlink(missing_ok=True)

    def register_and_claim(
        self, request: PurposeBoundEffectRequest, terminal: BuilderTerminalDocument
    ) -> CommandState:
        github_request = request.github_request(terminal)
        authority, operation = (
            ("builder", "publish_experimental")
            if request.node == "publish_experimental"
            else ("coordinator", "dispatch")
        )
        command = CloudCommand.create(
            command_key=request.command_key,
            authority=authority,
            operation=operation,
            request_digest=request.github_binding_request_digest,
            occurred_at=terminal.requested_at,
            expected_revision=request.expected_revision,
            attempt=1,
            max_attempts=3,
        )
        if (
            command.effect_key != request.effect_key
            or github_request.effect_key != command.effect_key
        ):
            raise BuilderError("builder_effect_command_identity_mismatch")
        path = self._path(command.command_key)
        if path.exists():
            try:
                state = CommandState.from_canonical_dict(json.loads(path.read_bytes()))
            except Exception as error:
                raise BuilderError("builder_effect_command_identity_mismatch") from error
            if state.command != command or state.status != "claimed":
                raise BuilderError("builder_effect_command_identity_mismatch")
            return state
        claimed_at = datetime.fromisoformat(terminal.requested_at[:-1] + "+00:00")
        expires_at = (claimed_at + timedelta(hours=24)).isoformat().replace("+00:00", "Z")
        claim = CommandClaim(
            command_key=command.command_key,
            claim_id=f"builder-effect-{request.idempotency_key[:48]}",
            authority=command.authority,
            expected_revision=command.expected_revision,
            claimed_at=terminal.requested_at,
            expires_at=expires_at,
        )
        state = CommandState(
            command=command,
            revision=command.expected_revision + 1,
            status="claimed",
            claim=claim,
            transition=None,
            result_digest=None,
            failure_code=None,
        )
        self._write(path, state.to_canonical_dict())
        return state

    def resolve_claimed_command(
        self, command_key: str, *, authority: str, observed_at: datetime
    ) -> CommandState:
        try:
            state = CommandState.from_canonical_dict(
                json.loads(self._path(command_key).read_bytes())
            )
        except Exception as error:
            raise BuilderError("builder_effect_command_missing") from error
        if (
            state.status != "claimed"
            or state.command.authority != authority
            or state.claim is None
            or datetime.fromisoformat(state.claim.expires_at[:-1] + "+00:00") <= observed_at
        ):
            raise BuilderError("builder_effect_command_not_claimed")
        return state


class ProtectedCoordinatorCommandAuthority:
    """Production adapter to the protected Postgres coordinator command authority."""

    __slots__ = ("_backend",)

    def __init__(self, backend: object) -> None:
        self._backend = backend

    @classmethod
    def from_protected_environment(cls) -> ProtectedCoordinatorCommandAuthority:
        from carl_bench.postgres_state import PostgresStateBackend

        return cls(PostgresStateBackend.from_protected_environment())

    def register_and_claim(
        self, request: PurposeBoundEffectRequest, terminal: BuilderTerminalDocument
    ) -> CommandState:
        github_request = request.github_request(terminal)
        state = self._backend.register_and_claim_builder_effect(
            node=request.node,
            experiment_id=request.experiment_id,
            expected_revision=request.expected_revision,
            idempotency_key=request.idempotency_key,
            builder_request_digest=request.request_digest,
            publication_request_digest=request.publication_request_digest,
            candidate_packet_digest=request.candidate_packet_digest,
            parent_commit=request.parent_commit,
            github_binding_request_digest=request.github_binding_request_digest,
            github_request=github_request,
        )
        if not isinstance(state, CommandState):
            raise BuilderError("builder_effect_command_identity_mismatch")
        return state


class ProtectedBuilderEffectExecutor:
    __slots__ = ("_authority", "_authorizer", "_github", "_store", "_verification_key")

    def __init__(
        self,
        *,
        store: object,
        authority: object,
        github: object,
        verification_key: bytes,
        authorizer: object,
    ) -> None:
        if (
            not callable(getattr(store, "begin_effect", None))
            or not callable(getattr(authority, "register_and_claim", None))
            or not callable(getattr(github, "execute", None))
            or not isinstance(verification_key, bytes)
            or len(verification_key) != 32
            or not callable(getattr(authorizer, "authorize", None))
        ):
            raise BuilderError("builder_effect_executor_invalid")
        self._store = store
        self._authority = authority
        self._github = github
        self._verification_key = verification_key
        self._authorizer = authorizer

    @classmethod
    def _for_testing(
        cls,
        *,
        store: object,
        github: object,
        authority: object | None = None,
        authorizer: object | None = None,
    ) -> ProtectedBuilderEffectExecutor:
        class AllowingAuthorizer:
            @staticmethod
            def authorize(terminal: object, packet: object) -> bool:
                return isinstance(terminal, BuilderTerminalDocument) and isinstance(
                    packet, ProtectedCandidatePacket
                )

        return cls(
            store=store,
            authority=(
                DurableCoordinatorCommandAuthority._for_testing(store.root / "commands")
                if authority is None
                else authority
            ),
            github=github,
            verification_key=b"k" * 32,
            authorizer=AllowingAuthorizer() if authorizer is None else authorizer,
        )

    @classmethod
    def from_protected_environment(cls, *, store: object) -> ProtectedBuilderEffectExecutor:
        try:
            key = _RECEIPT_KEY.read_bytes()
        except OSError as error:
            raise BuilderError("builder_receipt_key_unavailable") from error
        return cls(
            store=store,
            authority=ProtectedCoordinatorCommandAuthority.from_protected_environment(),
            github=GitHubEffectSocketClient.from_protected_environment(),
            verification_key=key,
            authorizer=ProtectedExperimentalPublicationAuthorizer(store),
        )

    def _response(
        self,
        request: PurposeBoundEffectRequest,
        status: Literal["pending", "completed", "frozen"],
        reason: str,
        result_digest: str | None = None,
    ) -> PurposeBoundEffectResponse:
        return PurposeBoundEffectResponse(
            1,
            request.node,
            request.idempotency_key,
            request.command_key,
            request.effect_key,
            request.github_request_digest,
            status,
            result_digest,
            reason,
        )

    def _freeze(
        self, request: PurposeBoundEffectRequest, reason: str
    ) -> PurposeBoundEffectResponse:
        response = self._response(request, "frozen", reason)
        self._store.finish_effect(response)
        return response

    def _github_request(
        self, request: PurposeBoundEffectRequest, terminal: BuilderTerminalDocument
    ) -> GitHubEffectRequest:
        return request.github_request(terminal)

    def _identity_matches(
        self,
        request: PurposeBoundEffectRequest,
        terminal: BuilderTerminalDocument,
        packet: ProtectedCandidatePacket,
    ) -> bool:
        return (
            terminal.request_digest == request.request_digest
            and terminal.experiment_id == request.experiment_id
            and terminal.publication_request_digest == request.publication_request_digest
            and terminal.candidate_packet_digest == request.candidate_packet_digest == packet.digest
            and terminal.parent_commit == request.parent_commit == packet.parent_commit
            and terminal.expected_revision == request.expected_revision
            and terminal.candidate_commit == packet.candidate.candidate_commit
            and terminal.candidate_tree == packet.candidate_tree
            and terminal.diff_artifact_digest == packet.diff_artifact_digest
            and packet.builder_request_digest == terminal.request_digest
        )

    def _response_matches(
        self,
        request: PurposeBoundEffectRequest,
        terminal: BuilderTerminalDocument,
        github_request: GitHubEffectRequest,
        response: GitHubEffectResponse,
    ) -> bool:
        if (
            not isinstance(response, GitHubEffectResponse)
            or response.status != "completed"
            or response.request_digest != github_request.digest
            or type(response.result) is not dict
        ):
            return False
        result = response.result
        if set(result) != {"result_type", "value"} or type(result["value"]) is not dict:
            return False
        value: dict[str, Any] = result["value"]
        common = (
            value.get("effect_key") == github_request.effect_key
            and value.get("request_key") == github_request.request_key
            and value.get("command_occurred_at") == github_request.occurred_at
            and value.get("repository") == "StephenBickel/carl-agent"
        )
        if request.node == "publish_experimental":
            return bool(
                common
                and result["result_type"] == "GitReferenceSnapshot"
                and value.get("commit_sha") == terminal.candidate_commit
                and value.get("ref") == f"refs/heads/experimental/{terminal.experiment_id}"
                and value.get("status") in {"created", "reconciled"}
            )
        return bool(
            common
            and result["result_type"] == "WorkflowDispatchSnapshot"
            and value.get("workflow_file") == terminal.validation_dispatch.workflow_file
            and value.get("workflow_revision") == terminal.validation_dispatch.workflow_revision
            and value.get("head_sha") == terminal.candidate_commit
            and value.get("status") in {"dispatched", "reconciled"}
        )

    def execute(self, request: PurposeBoundEffectRequest) -> PurposeBoundEffectResponse:
        if type(request) is not PurposeBoundEffectRequest:
            raise BuilderError("builder_effect_request_invalid")
        existing = self._store.begin_effect(request)
        if existing is not None:
            return existing
        try:
            terminal = self._store.load_terminal(request.request_digest)
            packet = self._store.load_verified_packet(
                request.candidate_packet_digest, verification_key=self._verification_key
            )
        except Exception:
            return self._freeze(request, "builder_effect_persisted_identity_mismatch")
        if not self._identity_matches(request, terminal, packet):
            return self._freeze(request, "builder_effect_request_identity_mismatch")
        if request.node == "dispatch_validation" and not self._store.publication_completed(
            terminal
        ):
            return self._freeze(request, "builder_publication_not_completed")
        if (
            request.node == "publish_experimental"
            and self._authorizer.authorize(terminal, packet) is not True
        ):
            return self._freeze(request, "builder_publication_not_eligible")
        github_request = self._github_request(request, terminal)
        try:
            state = self._authority.register_and_claim(request, terminal)
        except Exception:
            return self._freeze(request, "builder_effect_command_identity_mismatch")
        if (
            state.status != "claimed"
            or state.command.command_key != request.command_key
            or state.command.effect_key != request.effect_key
            or state.command.request_digest != request.github_binding_request_digest
        ):
            return self._freeze(request, "builder_effect_command_identity_mismatch")
        try:
            response = self._github.execute(github_request)
        except Exception:
            return self._response(request, "pending", "builder_effect_unavailable")
        if not self._response_matches(request, terminal, github_request, response):
            return self._freeze(request, "builder_effect_response_identity_mismatch")
        result_digest = hashlib.sha256(canonical_json_bytes(response.result)).hexdigest()
        completed = self._response(request, "completed", "builder_effect_completed", result_digest)
        self._store.finish_effect(completed)
        return completed
