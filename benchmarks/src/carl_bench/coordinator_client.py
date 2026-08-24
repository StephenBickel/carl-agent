"""Credential-free Unix-socket client for the protected coordinator service."""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

from carl_bench.coordinator_ipc import (
    MAX_COORDINATOR_FRAME_BYTES,
    CoordinatorProtocolError,
    CoordinatorServiceRequest,
    CoordinatorServiceResponse,
    decode_response_bytes,
    encode_request_bytes,
)
from carl_bench.unix_socket_security import (
    ProtectedSocketPathError,
    open_pinned_parent,
    socket_identity_at,
)

_PROTECTED_SOCKET_PATH = Path("/run/carl/coordinator.sock")
_PROTECTED_SERVICE_UID = 0
_SOCKET_TIMEOUT_SECONDS = 15.0


class CoordinatorClientError(RuntimeError):
    pass


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise CoordinatorClientError("coordinator_service_unavailable")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _pin_socket_path(path: Path, expected_uid: int) -> tuple[int, tuple[int, ...]]:
    parent_fd: int | None = None
    try:
        parent_fd = open_pinned_parent(path, expected_uid=expected_uid)
        identity = socket_identity_at(parent_fd, path.name, expected_uid=expected_uid)
    except ProtectedSocketPathError as error:
        if parent_fd is not None:
            os.close(parent_fd)
        raise CoordinatorClientError("coordinator_service_identity_invalid") from error
    return parent_fd, identity


def _validate_peer(connection: socket.socket, expected_uid: int) -> None:
    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        peer_uid, _ = getpeereid()
        if peer_uid != expected_uid:
            raise CoordinatorClientError("coordinator_service_identity_invalid")
        return
    if hasattr(socket, "SO_PEERCRED"):
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _, peer_uid, _ = struct.unpack("3i", credentials)
        if peer_uid != expected_uid:
            raise CoordinatorClientError("coordinator_service_identity_invalid")
        return
    if hasattr(socket, "LOCAL_PEERCRED"):
        credentials = connection.getsockopt(0, socket.LOCAL_PEERCRED, 8)
        _, peer_uid = struct.unpack("II", credentials)
        if peer_uid != expected_uid:
            raise CoordinatorClientError("coordinator_service_identity_invalid")
        return
    raise CoordinatorClientError("coordinator_service_identity_invalid")


@dataclass(frozen=True, slots=True)
class CoordinatorSocketClient:
    _socket_path: Path
    _expected_peer_uid: int
    _timeout_seconds: float

    @classmethod
    def from_protected_environment(cls) -> CoordinatorSocketClient:
        return cls(_PROTECTED_SOCKET_PATH, _PROTECTED_SERVICE_UID, _SOCKET_TIMEOUT_SECONDS)

    @classmethod
    def _for_testing(
        cls, *, socket_path: Path, expected_peer_uid: int, timeout_seconds: float
    ) -> CoordinatorSocketClient:
        if (
            not isinstance(socket_path, Path)
            or not socket_path.is_absolute()
            or isinstance(expected_peer_uid, bool)
            or not isinstance(expected_peer_uid, int)
            or expected_peer_uid < 0
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int | float)
            or not 0.05 <= timeout_seconds <= 30.0
        ):
            raise CoordinatorClientError("coordinator_client_configuration_invalid")
        return cls(socket_path, expected_peer_uid, float(timeout_seconds))

    def execute(self, request: CoordinatorServiceRequest) -> CoordinatorServiceResponse:
        payload = encode_request_bytes(request)
        parent_fd, identity_before = _pin_socket_path(self._socket_path, self._expected_peer_uid)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout_seconds)
                connection.connect(os.fspath(self._socket_path))
                _validate_peer(connection, self._expected_peer_uid)
                identity_after = socket_identity_at(
                    parent_fd,
                    self._socket_path.name,
                    expected_uid=self._expected_peer_uid,
                )
                if identity_after != identity_before:
                    raise CoordinatorClientError("coordinator_service_identity_invalid")
                connection.sendall(struct.pack(">I", len(payload)) + payload)
                size = struct.unpack(">I", _recv_exact(connection, 4))[0]
                if not 0 < size <= MAX_COORDINATOR_FRAME_BYTES:
                    raise CoordinatorClientError("coordinator_service_response_invalid")
                response = decode_response_bytes(_recv_exact(connection, size))
        except CoordinatorClientError:
            raise
        except (OSError, struct.error, CoordinatorProtocolError, ProtectedSocketPathError) as error:
            raise CoordinatorClientError("coordinator_service_unavailable") from error
        finally:
            os.close(parent_fd)
        if response.request_digest != request.digest:
            raise CoordinatorClientError("coordinator_service_response_invalid")
        return response
