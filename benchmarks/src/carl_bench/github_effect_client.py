"""Credential-free Unix-socket client for protected GitHub effects."""

from __future__ import annotations

import os
import pwd
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

from carl_bench.github_effect_ipc import (
    MAX_FRAME_BYTES,
    GitHubEffectProtocolError,
    GitHubEffectRequest,
    GitHubEffectResponse,
    decode_response_bytes,
    encode_request_bytes,
)
from carl_bench.unix_socket_security import (
    ProtectedSocketPathError,
    open_pinned_parent,
    socket_identity_at,
)

_PROTECTED_SOCKET_PATH = Path("/run/carl/github-effect.sock")
_PROTECTED_PARENT_UID = 0
_PROTECTED_SERVICE_UID = 0
_PROTECTED_SOCKET_USER = "carl-autonomy-coordinator"
_SOCKET_TIMEOUT_SECONDS = 15.0


class GitHubEffectClientError(RuntimeError):
    """Stable client failure that discloses no local path or wire contents."""


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise GitHubEffectClientError("github_effect_service_unavailable")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _protected_socket_uid() -> int:
    try:
        uid = pwd.getpwnam(_PROTECTED_SOCKET_USER).pw_uid
    except (KeyError, AttributeError) as error:
        raise GitHubEffectClientError("github_effect_client_configuration_invalid") from error
    if isinstance(uid, bool) or not isinstance(uid, int) or uid <= 0:
        raise GitHubEffectClientError("github_effect_client_configuration_invalid")
    return uid


def _pin_socket_path(
    path: Path, expected_uid: int, socket_uid: int | None = None
) -> tuple[int, tuple[int, ...]]:
    expected_socket_uid = expected_uid if socket_uid is None else socket_uid
    parent_fd: int | None = None
    try:
        parent_fd = open_pinned_parent(path, expected_uid=expected_uid)
        identity = socket_identity_at(parent_fd, path.name, expected_uid=expected_socket_uid)
    except ProtectedSocketPathError as error:
        if parent_fd is not None:
            os.close(parent_fd)
        raise GitHubEffectClientError("github_effect_service_identity_invalid") from error
    return parent_fd, identity


def _validate_peer(connection: socket.socket, expected_uid: int) -> None:
    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        peer_uid, _ = getpeereid()
        if peer_uid != expected_uid:
            raise GitHubEffectClientError("github_effect_service_identity_invalid")
        return
    if hasattr(socket, "SO_PEERCRED"):
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _, peer_uid, _ = struct.unpack("3i", credentials)
        if peer_uid != expected_uid:
            raise GitHubEffectClientError("github_effect_service_identity_invalid")
        return
    if hasattr(socket, "LOCAL_PEERCRED"):
        credentials = connection.getsockopt(0, socket.LOCAL_PEERCRED, 8)
        _, peer_uid = struct.unpack("II", credentials)
        if peer_uid != expected_uid:
            raise GitHubEffectClientError("github_effect_service_identity_invalid")


@dataclass(frozen=True, slots=True)
class GitHubEffectSocketClient:
    """Immutable protocol client; it has no credential or executor dependency."""

    _socket_path: Path
    _expected_parent_uid: int
    _expected_socket_uid: int | None
    _expected_peer_uid: int
    _timeout_seconds: float

    @classmethod
    def from_protected_environment(cls) -> GitHubEffectSocketClient:
        return cls(
            _socket_path=_PROTECTED_SOCKET_PATH,
            _expected_parent_uid=_PROTECTED_PARENT_UID,
            _expected_socket_uid=None,
            _expected_peer_uid=_PROTECTED_SERVICE_UID,
            _timeout_seconds=_SOCKET_TIMEOUT_SECONDS,
        )

    @classmethod
    def _for_testing(
        cls,
        *,
        socket_path: Path,
        expected_peer_uid: int,
        timeout_seconds: float,
        expected_socket_uid: int | None = None,
        expected_parent_uid: int | None = None,
    ) -> GitHubEffectSocketClient:
        socket_uid = expected_peer_uid if expected_socket_uid is None else expected_socket_uid
        parent_uid = socket_uid if expected_parent_uid is None else expected_parent_uid
        if (
            not isinstance(socket_path, Path)
            or not socket_path.is_absolute()
            or isinstance(parent_uid, bool)
            or not isinstance(parent_uid, int)
            or parent_uid < 0
            or isinstance(socket_uid, bool)
            or not isinstance(socket_uid, int)
            or socket_uid < 0
            or isinstance(expected_peer_uid, bool)
            or not isinstance(expected_peer_uid, int)
            or expected_peer_uid < 0
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int | float)
            or not 0.05 <= timeout_seconds <= 30.0
        ):
            raise GitHubEffectClientError("github_effect_client_configuration_invalid")
        return cls(
            socket_path,
            parent_uid,
            socket_uid,
            expected_peer_uid,
            float(timeout_seconds),
        )

    def execute(self, request: GitHubEffectRequest) -> GitHubEffectResponse:
        payload = encode_request_bytes(request)
        socket_uid = (
            _protected_socket_uid()
            if self._expected_socket_uid is None
            else self._expected_socket_uid
        )
        parent_fd, identity_before = _pin_socket_path(
            self._socket_path, self._expected_parent_uid, socket_uid
        )
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout_seconds)
                connection.connect(os.fspath(self._socket_path))
                _validate_peer(connection, self._expected_peer_uid)
                try:
                    identity_after = socket_identity_at(
                        parent_fd,
                        self._socket_path.name,
                        expected_uid=socket_uid,
                    )
                except ProtectedSocketPathError as error:
                    raise GitHubEffectClientError(
                        "github_effect_service_identity_invalid"
                    ) from error
                if identity_after != identity_before:
                    raise GitHubEffectClientError("github_effect_service_identity_invalid")
                connection.sendall(struct.pack(">I", len(payload)) + payload)
                size = struct.unpack(">I", _recv_exact(connection, 4))[0]
                if not 0 < size <= MAX_FRAME_BYTES:
                    raise GitHubEffectClientError("github_effect_service_response_invalid")
                response = decode_response_bytes(_recv_exact(connection, size))
        except GitHubEffectClientError:
            raise
        except (OSError, struct.error, GitHubEffectProtocolError) as error:
            raise GitHubEffectClientError("github_effect_service_unavailable") from error
        finally:
            os.close(parent_fd)
        if response.request_digest != request.digest:
            raise GitHubEffectClientError("github_effect_service_response_invalid")
        return response
