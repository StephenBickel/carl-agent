"""Credential-free production caller for the protected live runner service."""

from __future__ import annotations

import argparse
import os
import socket
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_execution_receipt import ProtectedLiveExecutionResult
from carl_bench.live_runner_ipc import (
    MAX_FRAME_BYTES,
    LiveRunnerProtocolError,
    ProtectedLiveRunnerRequest,
    decode_response,
)
from carl_bench.unix_socket_security import open_pinned_parent, socket_identity_at

_SOCKET_PATH = Path("/run/carl/live-runner.sock")


class LiveRunnerClientError(RuntimeError):
    pass


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


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    while count:
        chunk = connection.recv(count)
        if not chunk:
            raise LiveRunnerClientError("live_runner_service_unavailable")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


@dataclass(frozen=True, slots=True)
class ProtectedLiveRunnerSocketClient:
    _socket_path: Path
    _expected_peer_uid: int
    _timeout_seconds: float

    @classmethod
    def from_protected_environment(cls) -> ProtectedLiveRunnerSocketClient:
        return cls(_SOCKET_PATH, 0, 3_600.0)

    @classmethod
    def _for_testing(
        cls, *, socket_path: Path, expected_peer_uid: int, timeout_seconds: float
    ) -> ProtectedLiveRunnerSocketClient:
        return cls(socket_path, expected_peer_uid, timeout_seconds)

    def execute(self, request: ProtectedLiveRunnerRequest) -> ProtectedLiveExecutionResult:
        if not isinstance(request, ProtectedLiveRunnerRequest):
            raise LiveRunnerClientError("live_runner_request_invalid")
        payload = request.to_bytes()
        parent_fd = -1
        try:
            parent_fd = open_pinned_parent(self._socket_path, expected_uid=self._expected_peer_uid)
            before = socket_identity_at(
                parent_fd, self._socket_path.name, expected_uid=self._expected_peer_uid
            )
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout_seconds)
                connection.connect(os.fspath(self._socket_path))
                if (
                    _peer_uid(connection) != self._expected_peer_uid
                    or socket_identity_at(
                        parent_fd, self._socket_path.name, expected_uid=self._expected_peer_uid
                    )
                    != before
                ):
                    raise LiveRunnerClientError("live_runner_service_identity_invalid")
                connection.sendall(struct.pack(">I", len(payload)) + payload)
                size = struct.unpack(">I", _recv_exact(connection, 4))[0]
                if not 0 < size <= MAX_FRAME_BYTES:
                    raise LiveRunnerClientError("live_runner_response_invalid")
                response = decode_response(
                    _recv_exact(connection, size), request_digest=request.digest
                )
        except LiveRunnerClientError:
            raise
        except (OSError, ValueError, struct.error) as error:
            raise LiveRunnerClientError("live_runner_service_unavailable") from error
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)
        if response["status"] == "rejected":
            raise LiveRunnerClientError(response["error_code"])
        try:
            return ProtectedLiveExecutionResult.from_canonical_dict(response["result"])
        except ValueError as error:
            raise LiveRunnerClientError("live_runner_response_invalid") from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Execute one protected live worker request")
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        payload = args.request.read_bytes()
        request = ProtectedLiveRunnerRequest.from_bytes(payload)
        result = ProtectedLiveRunnerSocketClient.from_protected_environment().execute(request)
        args.output.write_bytes(canonical_json_bytes(result.to_canonical_dict()) + b"\n")
    except (OSError, LiveRunnerProtocolError, LiveRunnerClientError) as error:
        raise LiveRunnerClientError("live_runner_command_failed") from error
    return 0
