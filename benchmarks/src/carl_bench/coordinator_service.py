"""Activated protected coordinator service boundary."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import struct
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from carl_bench.canonical import CanonicalizationError, canonical_json_bytes
from carl_bench.cloud_coordinator import (
    CloudCoordinatorDecision,
    CloudCoordinatorError,
    CoordinatorSnapshot,
    ProtectedCoordinatorExecutor,
    ProtectedEffectUnavailable,
    ProtectedProductionAuthorization,
    _selected_node,
    effect_family_for_node,
)
from carl_bench.coordinator_effects import (
    CoordinatorNodeEffectResponse,
    PreparedCoordinatorEffect,
)
from carl_bench.coordinator_ipc import (
    COORDINATOR_RESPONSE_DOMAIN,
    MAX_COORDINATOR_FRAME_BYTES,
    CoordinatorProtocolError,
    CoordinatorServiceRequest,
    CoordinatorServiceResponse,
    decode_request_bytes,
    encode_response_bytes,
)
from carl_bench.github_effect_client import GitHubEffectSocketClient
from carl_bench.github_effect_service import (
    _activation_descriptor_from_environment as _github_activation_descriptor,
)
from carl_bench.github_effect_service import (
    _peer_uid,
    _validated_activated_listener,
)
from carl_bench.github_promotion import APPROVED_REQUIRED_CHECKS
from carl_bench.live_archive_client import ProtectedArchiveSocketReader
from carl_bench.live_evaluation_authority import ProtectedArchiveVersion
from carl_bench.postgres_state import PostgresStateBackend, PostgresStateError

_SOCKET_PATH = Path("/run/carl/coordinator.sock")
_ALLOWED_CLIENT_UID = 0
_CONNECTION_TIMEOUT_SECONDS = 2.0
_PROMOTION_RECEIPT_BINDINGS = frozenset(
    {
        "branch_protection_object_key",
        "branch_protection_object_version",
        "branch_protection_recorded_at",
        "branch_protection_retain_until",
        "required_checks_object_key",
        "required_checks_object_version",
        "required_checks_recorded_at",
        "required_checks_retain_until",
    }
)


def _trusted_clock() -> datetime:
    return datetime.now(UTC)


def _activation_descriptor_from_environment() -> int:
    """Require the coordinator's exact supervisor descriptor name and FD contract."""
    if os.environ.get("LISTEN_FDNAMES") != "coordinator":
        raise RuntimeError("coordinator_service_activation_invalid")
    checked = dict(os.environ)
    checked["LISTEN_FDNAMES"] = "github-effect"
    try:
        return _github_activation_descriptor(
            environment=checked,
            process_id=os.getpid(),
        )
    except RuntimeError as error:
        raise RuntimeError("coordinator_service_activation_invalid") from error


def _authorization_from_durable_receipts(
    value: object, *, observed_at: datetime
) -> ProtectedProductionAuthorization:
    """Mint a service-local production value from one exact current controller row."""
    fields = frozenset(ProtectedProductionAuthorization.__dataclass_fields__)
    if type(value) is not dict or set(value) != fields:
        raise CloudCoordinatorError("protected_authorization_receipts_invalid")
    if not isinstance(observed_at, datetime) or observed_at.tzinfo != UTC:
        raise CloudCoordinatorError("coordinator_clock_invalid")
    verified_at = observed_at.isoformat().replace("+00:00", "Z")
    if value["verified_at"] != verified_at:
        raise CloudCoordinatorError("protected_authorization_time_mismatch")
    normalized = dict(value)
    authorization = object.__new__(ProtectedProductionAuthorization)
    for name in fields:
        object.__setattr__(authorization, name, normalized[name])
    authorization.__post_init__()
    return authorization


class _PostgresCoordinatorState:
    """Exact coordinator operations exposed only by the protected PostgreSQL controller."""

    __slots__ = ("__archive", "__backend")

    def __init__(self, backend: object, archive: object) -> None:
        self.__backend = backend
        self.__archive = archive

    def _verify_archive_receipt(
        self, receipt_row: dict[str, object], *, observed_at: datetime
    ) -> None:
        object_key = receipt_row.get("archive_object_key")
        version_id = receipt_row.get("archive_version_id")
        if not isinstance(object_key, str) or not isinstance(version_id, str):
            raise CloudCoordinatorError("protected_archive_receipt_mismatch")
        try:
            archive = self.__archive.read_exact(object_key, version_id)  # type: ignore[attr-defined]
        except Exception:
            raise CloudCoordinatorError("protected_archive_receipt_unavailable") from None
        payload = archive.payload if isinstance(archive, ProtectedArchiveVersion) else None
        if (
            not isinstance(archive, ProtectedArchiveVersion)
            or type(payload) is not bytes
            or archive.object_key != object_key
            or archive.version_id != version_id
            or archive.checksum_sha256 != receipt_row.get("archive_digest")
            or hashlib.sha256(payload).hexdigest() != receipt_row.get("archive_digest")
            or isinstance(archive.byte_length, bool)
            or archive.byte_length != len(payload)
            or archive.retention_mode != "COMPLIANCE"
            or archive.retain_until != receipt_row.get("archive_retain_until")
        ):
            raise CloudCoordinatorError("protected_archive_receipt_mismatch")
        try:
            created_at = datetime.fromisoformat(archive.created_at.removesuffix("Z") + "+00:00")
        except (AttributeError, ValueError) as error:
            raise CloudCoordinatorError("protected_archive_receipt_mismatch") from error
        if (
            not archive.created_at.endswith("Z")
            or created_at.tzinfo != UTC
            or created_at.isoformat().replace("+00:00", "Z") != archive.created_at
            or created_at > observed_at
        ):
            raise CloudCoordinatorError("protected_archive_receipt_mismatch")

    def _read_promotion_receipt(
        self,
        receipt_row: dict[str, object],
        *,
        prefix: str,
        digest_field: str,
        observed_at: datetime,
    ) -> bytes:
        object_key = receipt_row.get(f"{prefix}_object_key")
        object_version = receipt_row.get(f"{prefix}_object_version")
        recorded_at = receipt_row.get(f"{prefix}_recorded_at")
        retain_until = receipt_row.get(f"{prefix}_retain_until")
        digest = receipt_row.get(digest_field)
        if (
            not isinstance(object_key, str)
            or not isinstance(object_version, str)
            or not isinstance(recorded_at, str)
            or not isinstance(retain_until, str)
            or not isinstance(digest, str)
            or object_key != f"evidence/{digest}"
        ):
            raise CloudCoordinatorError("protected_promotion_receipt_mismatch")
        try:
            archive = self.__archive.read_exact(object_key, object_version)  # type: ignore[attr-defined]
            recorded = datetime.fromisoformat(recorded_at.removesuffix("Z") + "+00:00")
            retained = datetime.fromisoformat(retain_until.removesuffix("Z") + "+00:00")
            created = datetime.fromisoformat(archive.created_at.removesuffix("Z") + "+00:00")
        except Exception:
            raise CloudCoordinatorError("protected_promotion_receipt_mismatch") from None
        payload = archive.payload if isinstance(archive, ProtectedArchiveVersion) else None
        if (
            not isinstance(archive, ProtectedArchiveVersion)
            or type(payload) is not bytes
            or archive.object_key != object_key
            or archive.version_id != object_version
            or archive.checksum_sha256 != digest
            or hashlib.sha256(payload).hexdigest() != digest
            or isinstance(archive.byte_length, bool)
            or archive.byte_length != len(payload)
            or not 2 <= len(payload) <= 16_384
            or archive.retention_mode != "COMPLIANCE"
            or archive.retain_until != retain_until
            or recorded.tzinfo != UTC
            or retained.tzinfo != UTC
            or created.tzinfo != UTC
            or not recorded_at.endswith("Z")
            or not retain_until.endswith("Z")
            or not archive.created_at.endswith("Z")
            or recorded.isoformat().replace("+00:00", "Z") != recorded_at
            or recorded > observed_at
            or (observed_at - recorded).total_seconds() > 15 * 60
            or retained <= observed_at
            or created > observed_at
        ):
            raise CloudCoordinatorError("protected_promotion_receipt_mismatch")
        return payload

    @staticmethod
    def _strict_receipt_payload(payload: bytes) -> dict[str, object]:
        def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        try:
            decoded = json.loads(payload, object_pairs_hook=reject_duplicates)
            if type(decoded) is not dict or canonical_json_bytes(decoded) != payload:
                raise ValueError
        except (CanonicalizationError, UnicodeError, ValueError, json.JSONDecodeError) as error:
            raise CloudCoordinatorError("protected_promotion_receipt_mismatch") from error
        return decoded

    def _verify_promotion_receipts(
        self, receipt_row: dict[str, object], *, observed_at: datetime
    ) -> dict[str, object]:
        transient = set(receipt_row) & _PROMOTION_RECEIPT_BINDINGS
        requires_checks = receipt_row.get("required_checks_receipt_digest") is not None
        if not requires_checks:
            if transient:
                raise CloudCoordinatorError("protected_promotion_receipt_mismatch")
            return receipt_row
        if transient != _PROMOTION_RECEIPT_BINDINGS:
            raise CloudCoordinatorError("protected_promotion_receipt_mismatch")
        repository = receipt_row.get("repository")
        pull_request_number = receipt_row.get("pull_request_number")
        head_sha = receipt_row.get("pull_request_head")
        checks = self._strict_receipt_payload(
            self._read_promotion_receipt(
                receipt_row,
                prefix="required_checks",
                digest_field="required_checks_receipt_digest",
                observed_at=observed_at,
            )
        )
        expected_checks = {
            "checks": [
                {"app_id": 15368, "conclusion": "success", "name": name}
                for name in APPROVED_REQUIRED_CHECKS
            ],
            "head_sha": head_sha,
            "kind": "github_required_checks",
            "observed_at": receipt_row.get("required_checks_recorded_at"),
            "pull_request_number": pull_request_number,
            "repository": repository,
            "schema_version": 1,
        }
        protection = self._strict_receipt_payload(
            self._read_promotion_receipt(
                receipt_row,
                prefix="branch_protection",
                digest_field="branch_protection_receipt_digest",
                observed_at=observed_at,
            )
        )
        expected_protection = {
            "allow_auto_merge": True,
            "allow_deletions": False,
            "allow_force_pushes": False,
            "allow_merge_commit": False,
            "allow_rebase_merge": False,
            "allow_squash_merge": True,
            "branch": "main",
            "delete_branch_on_merge": True,
            "enforce_admins": True,
            "head_sha": head_sha,
            "kind": "github_branch_protection",
            "observed_at": receipt_row.get("branch_protection_recorded_at"),
            "pull_request_number": pull_request_number,
            "repository": repository,
            "required_checks": [
                {"app_id": 15368, "name": name} for name in APPROVED_REQUIRED_CHECKS
            ],
            "required_conversation_resolution": True,
            "required_linear_history": True,
            "required_status_checks_strict": True,
            "schema_version": 1,
        }
        if checks != expected_checks or protection != expected_protection:
            raise CloudCoordinatorError("protected_promotion_receipt_mismatch")
        return {key: value for key, value in receipt_row.items() if key not in transient}

    def reconstruct(self, command: str, *, observed_at: datetime) -> CoordinatorSnapshot | None:
        reconstructed = self.__backend.reconstruct_coordinator_snapshot(  # type: ignore[attr-defined]
            command, observed_at=observed_at
        )
        if reconstructed is None:
            return None
        if (
            not isinstance(reconstructed, tuple)
            or len(reconstructed) != 2
            or not isinstance(reconstructed[0], CoordinatorSnapshot)
            or (reconstructed[1] is not None and type(reconstructed[1]) is not dict)
        ):
            raise CloudCoordinatorError("coordinator_snapshot_invalid")
        snapshot, receipt_row = reconstructed
        selected = _selected_node(snapshot)
        if receipt_row is None:
            return snapshot
        if selected is None:
            raise CloudCoordinatorError("protected_authorization_receipts_invalid")
        self._verify_archive_receipt(receipt_row, observed_at=observed_at)
        verified_receipts = self._verify_promotion_receipts(receipt_row, observed_at=observed_at)
        authorization = _authorization_from_durable_receipts(
            verified_receipts, observed_at=observed_at
        )
        return replace(snapshot, production_authorization=authorization)

    def enqueue_pending_graph(self, *, observed_at: datetime) -> bool:
        return self.__backend.enqueue_pending_coordinator_graph(  # type: ignore[attr-defined,no-any-return]
            observed_at=observed_at
        )

    def apply(
        self, decision: CloudCoordinatorDecision, *, observed_at: datetime
    ) -> CloudCoordinatorDecision:
        return self.__backend.apply_coordinator_decision(  # type: ignore[attr-defined,no-any-return]
            decision, observed_at=observed_at
        )


class _ProtectedCoordinatorEffectRouter:
    """Fixed effect family router; requests are resolved from durable state, never IPC input."""

    __slots__ = (
        "__archive",
        "__backend",
        "__evaluator",
        "__github",
        "__input_publisher",
        "__observer",
    )

    def __init__(
        self,
        *,
        backend: object,
        github: object | None,
        input_publisher: object | None,
        observer: object | None,
        archive: object | None,
        evaluator: object | None,
        _testing: bool,
    ) -> None:
        if not _testing:
            raise CloudCoordinatorError("coordinator_effect_router_construction_invalid")
        self.__backend = backend
        self.__github = github
        self.__input_publisher = input_publisher
        self.__observer = observer
        self.__archive = archive
        self.__evaluator = evaluator

    @classmethod
    def _for_testing(
        cls,
        *,
        backend: object,
        github: object | None,
        input_publisher: object | None,
        observer: object | None,
        archive: object | None,
        evaluator: object | None,
    ) -> _ProtectedCoordinatorEffectRouter:
        return cls(
            backend=backend,
            github=github,
            input_publisher=input_publisher,
            observer=observer,
            archive=archive,
            evaluator=evaluator,
            _testing=True,
        )

    @classmethod
    def _for_protected_service(
        cls, *, backend: object, github: object
    ) -> _ProtectedCoordinatorEffectRouter:
        return cls(
            backend=backend,
            github=github,
            input_publisher=None,
            observer=None,
            archive=None,
            evaluator=None,
            _testing=True,
        )

    def execute(
        self, decision: CloudCoordinatorDecision, *, observed_at: datetime
    ) -> CloudCoordinatorDecision:
        if decision.node is None:
            raise CloudCoordinatorError("coordinator_effect_node_missing")
        family = effect_family_for_node(decision.node)
        if family in {"state", "supervisor"}:
            return self.__backend.execute_local_coordinator_effect(  # type: ignore[attr-defined,no-any-return]
                decision, family=family, observed_at=observed_at
            )
        if family == "github":
            if self.__github is None:
                raise ProtectedEffectUnavailable("github_service_uncommissioned")
            return self.__backend.execute_github_coordinator_effect(  # type: ignore[attr-defined,no-any-return]
                decision, github=self.__github, observed_at=observed_at
            )
        service, method_name = {
            "input": (self.__input_publisher, "publish"),
            "observer": (self.__observer, "observe"),
            "archive": (self.__archive, "archive"),
            "evaluator": (self.__evaluator, "evaluate"),
        }[family]
        if decision.action == "reconcile_effect":
            method_name = "reconcile"
        method = None if service is None else getattr(service, method_name, None)
        if not callable(method):
            raise ProtectedEffectUnavailable(f"{family}_service_uncommissioned")
        prepared = self.__backend.prepare_coordinator_effect(  # type: ignore[attr-defined]
            decision, expected_family=family, observed_at=observed_at
        )
        if not isinstance(prepared, PreparedCoordinatorEffect) or prepared.family != family:
            raise CloudCoordinatorError("coordinator_prepared_effect_invalid")
        response = method(prepared.request)
        if not isinstance(response, CoordinatorNodeEffectResponse):
            raise CloudCoordinatorError("coordinator_effect_response_invalid")
        return self.__backend.complete_coordinator_effect(  # type: ignore[attr-defined,no-any-return]
            decision, response, observed_at=observed_at
        )


def _build_protected_controller() -> ProtectedCoordinatorExecutor:
    """Construct the fixed service dependency graph from protected sources only."""
    backend = PostgresStateBackend.from_protected_environment()
    github = GitHubEffectSocketClient.from_protected_environment()
    archive = ProtectedArchiveSocketReader.from_protected_environment()
    return ProtectedCoordinatorExecutor._for_protected_service(
        state=_PostgresCoordinatorState(backend, archive),
        effects=_ProtectedCoordinatorEffectRouter._for_protected_service(
            backend=backend, github=github
        ),
        clock=_trusted_clock,
    )


def coordinator_response(
    request: CoordinatorServiceRequest, *, controller: ProtectedCoordinatorExecutor
) -> CoordinatorServiceResponse:
    if not isinstance(request, CoordinatorServiceRequest) or not isinstance(
        controller, ProtectedCoordinatorExecutor
    ):
        raise CloudCoordinatorError("coordinator_service_request_invalid")
    try:
        result = controller.advance(request.command)
    except (CloudCoordinatorError, PostgresStateError):
        return CoordinatorServiceResponse(
            schema_version=1,
            domain=COORDINATOR_RESPONSE_DOMAIN,
            status="rejected",
            request_digest=request.digest,
            result=None,
            error_code="coordinator_request_rejected",
        )
    return CoordinatorServiceResponse(
        schema_version=1,
        domain=COORDINATOR_RESPONSE_DOMAIN,
        status="completed",
        request_digest=request.digest,
        result=result.to_canonical_dict(),
        error_code=None,
    )


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise EOFError
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _serve_connection(
    connection: socket.socket, *, controller: ProtectedCoordinatorExecutor
) -> None:
    try:
        size = struct.unpack(">I", _recv_exact(connection, 4))[0]
        if not 0 < size <= MAX_COORDINATOR_FRAME_BYTES:
            return
        request = decode_request_bytes(_recv_exact(connection, size))
        payload = encode_response_bytes(coordinator_response(request, controller=controller))
        connection.sendall(struct.pack(">I", len(payload)) + payload)
    except (EOFError, OSError, TimeoutError, struct.error, CoordinatorProtocolError):
        return


def _serve_activated_listener(
    *,
    listener_fd: int,
    socket_path: Path,
    allowed_client_uid: int,
    service_uid: int,
    controller: ProtectedCoordinatorExecutor,
    connection_timeout_seconds: float,
    on_ready: object | None = None,
) -> None:
    """Serve only through a supervisor-owned, identity-checked activated socket."""
    if (
        not isinstance(socket_path, Path)
        or not socket_path.is_absolute()
        or socket_path.name in {"", ".", ".."}
        or not isinstance(controller, ProtectedCoordinatorExecutor)
        or isinstance(connection_timeout_seconds, bool)
        or not isinstance(connection_timeout_seconds, int | float)
        or not 0.05 <= connection_timeout_seconds <= 30.0
    ):
        raise RuntimeError("coordinator_service_configuration_invalid")
    with _validated_activated_listener(
        listener_fd=listener_fd,
        socket_path=socket_path,
        expected_uid=service_uid,
    ) as activated:
        listener, queued = activated
        if callable(on_ready):
            on_ready()
        while True:
            connection = queued.pop(0) if queued else listener.accept()[0]
            with connection:
                connection.settimeout(float(connection_timeout_seconds))
                if _peer_uid(connection) != allowed_client_uid:
                    continue
                _serve_connection(connection, controller=controller)


def main() -> int:
    """Run the fixed protected coordinator behind one supervisor-activated socket."""
    listener_fd = _activation_descriptor_from_environment()
    _serve_activated_listener(
        listener_fd=listener_fd,
        socket_path=_SOCKET_PATH,
        allowed_client_uid=_ALLOWED_CLIENT_UID,
        service_uid=0,
        controller=_build_protected_controller(),
        connection_timeout_seconds=_CONNECTION_TIMEOUT_SECONDS,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - service manager entrypoint
    raise SystemExit(main())
