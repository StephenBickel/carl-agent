"""Activated credential-separated responder for one fixed coordinator effect family."""

from __future__ import annotations

import os
import socket
import struct
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

from carl_bench.cloud_coordinator import EffectFamily
from carl_bench.coordinator_effect_client import (
    MAX_EFFECT_FRAME_BYTES,
    PROTECTED_EFFECT_SOCKET_PATHS,
    decode_effect_request_bytes,
    encode_effect_response_bytes,
)
from carl_bench.coordinator_effects import (
    RESPONSE_DOMAIN,
    CoordinatorNodeEffectRequest,
    CoordinatorNodeEffectResponse,
)

_ALLOWED_CLIENT_UID = 0
_CONNECTION_TIMEOUT_SECONDS = 2.0
_FAMILIES = frozenset({"archive", "evaluator", "input", "observer"})


class CoordinatorEffectServiceError(RuntimeError):
    """Stable service error that exposes no credential or protected payload."""


class CoordinatorEffectAuthority(Protocol):
    def execute(self, request: CoordinatorNodeEffectRequest) -> CoordinatorNodeEffectResponse: ...


class StopSignal(Protocol):
    def is_set(self) -> bool: ...


def _timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class _ProtectedEffectAuthority:
    """Fail-closed production authority until a family-specific adapter is commissioned."""

    __slots__ = ("__family",)

    def __init__(self, family: EffectFamily) -> None:
        self.__family = family

    @classmethod
    def from_protected_environment(cls, family: EffectFamily) -> _ProtectedEffectAuthority:
        if family not in _FAMILIES:
            raise CoordinatorEffectServiceError("coordinator_effect_service_family_invalid")
        return cls(family)

    def execute(self, request: CoordinatorNodeEffectRequest) -> CoordinatorNodeEffectResponse:
        if not isinstance(request, CoordinatorNodeEffectRequest) or request.family != self.__family:
            raise CoordinatorEffectServiceError("coordinator_effect_service_request_invalid")
        return CoordinatorNodeEffectResponse(
            schema_version=1,
            domain=RESPONSE_DOMAIN,
            status="rejected",
            request_digest=request.digest,
            observed_at=_timestamp(),
            result_digest=None,
            retry_not_before=None,
            error_code=f"{self.__family}_service_uncommissioned",
        )


def _peer_uid(connection: socket.socket) -> int | None:
    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        return cast(tuple[int, int], getpeereid())[0]
    if hasattr(socket, "SO_PEERCRED"):
        return struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )[1]
    if hasattr(socket, "LOCAL_PEERCRED"):
        return struct.unpack("II", connection.getsockopt(0, socket.LOCAL_PEERCRED, 8))[1]
    return None


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    while count:
        chunk = connection.recv(count)
        if not chunk:
            raise CoordinatorEffectServiceError("coordinator_effect_service_protocol_invalid")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def _serve_connection(
    connection: socket.socket,
    *,
    family: EffectFamily,
    authority: CoordinatorEffectAuthority,
    allowed_client_uid: int,
) -> None:
    connection.settimeout(_CONNECTION_TIMEOUT_SECONDS)
    if _peer_uid(connection) != allowed_client_uid:
        raise CoordinatorEffectServiceError("coordinator_effect_service_client_denied")
    size = struct.unpack(">I", _recv_exact(connection, 4))[0]
    if not 0 < size <= MAX_EFFECT_FRAME_BYTES:
        raise CoordinatorEffectServiceError("coordinator_effect_service_protocol_invalid")
    request = decode_effect_request_bytes(_recv_exact(connection, size))
    if request.family != family:
        raise CoordinatorEffectServiceError("coordinator_effect_service_family_invalid")
    response = authority.execute(request)
    if (
        not isinstance(response, CoordinatorNodeEffectResponse)
        or response.request_digest != request.digest
    ):
        raise CoordinatorEffectServiceError("coordinator_effect_service_response_invalid")
    payload = encode_effect_response_bytes(response)
    connection.sendall(struct.pack(">I", len(payload)) + payload)


def _serve_activated_listener(
    listener: socket.socket,
    *,
    family: str,
    authority: CoordinatorEffectAuthority,
    allowed_client_uid: int,
    stop: StopSignal | None = None,
) -> None:
    if (
        not isinstance(listener, socket.socket)
        or listener.family != socket.AF_UNIX
        or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
        or family not in _FAMILIES
        or isinstance(allowed_client_uid, bool)
        or not isinstance(allowed_client_uid, int)
        or allowed_client_uid < 0
        or not callable(getattr(authority, "execute", None))
    ):
        raise CoordinatorEffectServiceError("coordinator_effect_service_activation_invalid")
    listener.listen(16)
    listener.settimeout(0.1)
    while stop is None or not stop.is_set():
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            continue
        with connection:
            try:
                _serve_connection(
                    connection,
                    family=cast(EffectFamily, family),
                    authority=authority,
                    allowed_client_uid=allowed_client_uid,
                )
            except (OSError, struct.error, ValueError, CoordinatorEffectServiceError):
                continue


def _activated_listener() -> tuple[socket.socket, EffectFamily]:
    descriptor_names = os.environ.get("LISTEN_FDNAMES")
    family = None if descriptor_names is None else descriptor_names.removesuffix("-effect")
    if (
        os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "1"
        or descriptor_names != f"{family}-effect"
        or family not in _FAMILIES
    ):
        raise CoordinatorEffectServiceError("coordinator_effect_service_activation_invalid")
    listener = socket.socket(fileno=os.dup(3))
    expected_path = PROTECTED_EFFECT_SOCKET_PATHS[family]
    if (
        listener.family != socket.AF_UNIX
        or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
        or Path(listener.getsockname()) != expected_path
    ):
        listener.close()
        raise CoordinatorEffectServiceError("coordinator_effect_service_activation_invalid")
    return listener, cast(EffectFamily, family)


def main() -> int:
    listener, family = _activated_listener()
    with listener:
        _serve_activated_listener(
            listener,
            family=family,
            authority=_ProtectedEffectAuthority.from_protected_environment(family),
            allowed_client_uid=_ALLOWED_CLIENT_UID,
        )
    return 0


if __name__ == "__main__":  # pragma: no cover - service manager entrypoint
    raise SystemExit(main())
