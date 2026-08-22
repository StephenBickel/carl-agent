"""Activated protected coordinator service boundary."""

from __future__ import annotations

import hashlib
import os
import socket
import struct
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from carl_bench.cloud_coordinator import (
    CloudCoordinatorDecision,
    CloudCoordinatorError,
    CoordinatorSnapshot,
    ProtectedCoordinatorExecutor,
    ProtectedProductionAuthorization,
    _selected_node,
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
from carl_bench.live_archive_client import ProtectedArchiveSocketReader
from carl_bench.live_evaluation_authority import ProtectedArchiveVersion
from carl_bench.postgres_state import PostgresStateBackend, PostgresStateError

_SOCKET_PATH = Path("/run/carl/coordinator.sock")
_ALLOWED_CLIENT_UID = 0
_CONNECTION_TIMEOUT_SECONDS = 2.0


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
        authorization = _authorization_from_durable_receipts(receipt_row, observed_at=observed_at)
        return replace(snapshot, production_authorization=authorization)

    def apply(
        self, decision: CloudCoordinatorDecision, *, observed_at: datetime
    ) -> CloudCoordinatorDecision:
        return self.__backend.apply_coordinator_decision(  # type: ignore[attr-defined,no-any-return]
            decision, observed_at=observed_at
        )


class _ProtectedCoordinatorEffectRouter:
    """Fixed effect family router; requests are resolved from durable state, never IPC input."""

    __slots__ = ("__backend", "__github")

    def __init__(self, backend: object, github: object) -> None:
        self.__backend = backend
        self.__github = github

    def execute(
        self, decision: CloudCoordinatorDecision, *, observed_at: datetime
    ) -> CloudCoordinatorDecision:
        return self.__backend.execute_coordinator_effect(  # type: ignore[attr-defined,no-any-return]
            decision,
            github=self.__github,
            observed_at=observed_at,
        )


def _build_protected_controller() -> ProtectedCoordinatorExecutor:
    """Construct the fixed service dependency graph from protected sources only."""
    backend = PostgresStateBackend.from_protected_environment()
    github = GitHubEffectSocketClient.from_protected_environment()
    archive = ProtectedArchiveSocketReader.from_protected_environment()
    return ProtectedCoordinatorExecutor._for_protected_service(
        state=_PostgresCoordinatorState(backend, archive),
        effects=_ProtectedCoordinatorEffectRouter(backend, github),
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
