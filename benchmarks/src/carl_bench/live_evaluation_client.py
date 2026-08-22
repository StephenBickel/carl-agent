"""Credential-free Unix-socket client for the protected live evaluator."""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

from carl_bench.live_evaluation_ipc import (
    MAX_FRAME_BYTES,
    LiveEvaluationProtocolError,
    ProtectedJoinRequest,
    ProtectedJoinResponse,
    decode_response_bytes,
)
from carl_bench.unix_socket_security import (
    ProtectedSocketPathError,
    open_pinned_parent,
    socket_identity_at,
)

_SOCKET_PATH = Path("/run/carl-live-evaluator/live-evaluator.sock")


class LiveEvaluationClientError(RuntimeError):
    """Stable client error containing no evidence, path, or credential detail."""


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    while count:
        chunk = connection.recv(count)
        if not chunk:
            raise LiveEvaluationClientError("live_evaluation_service_unavailable")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def _peer_uid(connection: socket.socket) -> int | None:
    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        return getpeereid()[0]
    if hasattr(socket, "SO_PEERCRED"):
        return struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )[1]
    if hasattr(socket, "LOCAL_PEERCRED"):
        return struct.unpack("II", connection.getsockopt(0, socket.LOCAL_PEERCRED, 8))[1]
    return None


@dataclass(frozen=True, slots=True)
class LiveEvaluationSocketClient:
    _socket_path: Path
    _expected_peer_uid: int
    _timeout_seconds: float

    @classmethod
    def from_protected_environment(cls) -> LiveEvaluationSocketClient:
        return cls(_SOCKET_PATH, 0, 15.0)

    @classmethod
    def _for_testing(
        cls, *, socket_path: Path, expected_peer_uid: int, timeout_seconds: float
    ) -> LiveEvaluationSocketClient:
        if (
            not isinstance(socket_path, Path)
            or not socket_path.is_absolute()
            or isinstance(expected_peer_uid, bool)
            or not isinstance(expected_peer_uid, int)
            or expected_peer_uid < 0
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int | float)
            or not 0.05 <= timeout_seconds <= 30
        ):
            raise LiveEvaluationClientError("live_evaluation_client_configuration_invalid")
        return cls(socket_path, expected_peer_uid, float(timeout_seconds))

    def combine(self, request: ProtectedJoinRequest) -> ProtectedJoinResponse:
        if not isinstance(request, ProtectedJoinRequest):
            raise LiveEvaluationClientError("live_evaluation_request_invalid")
        payload = request.to_bytes()
        parent_fd: int | None = None
        try:
            parent_fd = open_pinned_parent(self._socket_path, expected_uid=self._expected_peer_uid)
            before = socket_identity_at(
                parent_fd,
                self._socket_path.name,
                expected_uid=self._expected_peer_uid,
            )
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout_seconds)
                connection.connect(os.fspath(self._socket_path))
                if _peer_uid(connection) != self._expected_peer_uid:
                    raise LiveEvaluationClientError("live_evaluation_service_identity_invalid")
                after = socket_identity_at(
                    parent_fd,
                    self._socket_path.name,
                    expected_uid=self._expected_peer_uid,
                )
                if after != before:
                    raise LiveEvaluationClientError("live_evaluation_service_identity_invalid")
                connection.sendall(struct.pack(">I", len(payload)) + payload)
                size = struct.unpack(">I", _recv_exact(connection, 4))[0]
                if not 0 < size <= MAX_FRAME_BYTES:
                    raise LiveEvaluationClientError("live_evaluation_response_invalid")
                response = decode_response_bytes(_recv_exact(connection, size))
        except LiveEvaluationClientError:
            raise
        except (
            OSError,
            struct.error,
            ProtectedSocketPathError,
            LiveEvaluationProtocolError,
        ) as error:
            raise LiveEvaluationClientError("live_evaluation_service_unavailable") from error
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
        if response.request_digest != request.digest:
            raise LiveEvaluationClientError("live_evaluation_response_invalid")
        if response.status == "rejected":
            raise LiveEvaluationClientError(
                response.error_code or "live_evaluation_service_rejected"
            )
        return response
