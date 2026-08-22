"""Credential-free fixed Unix-socket clients for coordinator effect families."""

from __future__ import annotations

import json
import os
import socket
import stat
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import cast

from carl_bench.canonical import CanonicalizationError, canonical_json_bytes
from carl_bench.cloud_coordinator import EffectFamily
from carl_bench.coordinator_effects import (
    CoordinatorEffectContractError,
    CoordinatorNodeEffectRequest,
    CoordinatorNodeEffectResponse,
)
from carl_bench.unix_socket_security import (
    ProtectedSocketPathError,
    open_pinned_parent,
    socket_identity_at,
)

MAX_EFFECT_FRAME_BYTES = 32_768
_PROTECTED_POLICY_PATH = Path("/etc/carl/coordinator-effects-policy.json")
_PROTECTED_SERVICE_UID = 0
_SOCKET_TIMEOUT_SECONDS = 15.0
_EXTERNAL_FAMILIES = frozenset({"archive", "evaluator", "input", "observer"})
PROTECTED_EFFECT_SOCKET_PATHS: Mapping[str, Path] = MappingProxyType(
    {
        "archive": Path("/run/carl/archive-effect.sock"),
        "evaluator": Path("/run/carl/evaluator-effect.sock"),
        "input": Path("/run/carl/input-effect.sock"),
        "observer": Path("/run/carl/observer-effect.sock"),
    }
)


class CoordinatorEffectClientError(RuntimeError):
    """Stable client failure that exposes no socket path, policy bytes, or credentials."""


def _canonical(value: object) -> bytes:
    try:
        return canonical_json_bytes(value)
    except CanonicalizationError as error:
        raise CoordinatorEffectClientError("coordinator_effect_protocol_invalid") from error


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CoordinatorEffectClientError("coordinator_effect_protocol_invalid")
        result[key] = value
    return result


def _decode(payload: bytes) -> dict[str, object]:
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_EFFECT_FRAME_BYTES:
        raise CoordinatorEffectClientError("coordinator_effect_protocol_invalid")
    try:
        value = json.loads(payload, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CoordinatorEffectClientError("coordinator_effect_protocol_invalid") from error
    if type(value) is not dict or _canonical(value) != payload:
        raise CoordinatorEffectClientError("coordinator_effect_protocol_invalid")
    return value


def encode_effect_request_bytes(request: CoordinatorNodeEffectRequest) -> bytes:
    if not isinstance(request, CoordinatorNodeEffectRequest):
        raise CoordinatorEffectClientError("coordinator_effect_request_invalid")
    payload = _canonical(request.to_canonical_dict())
    if len(payload) > MAX_EFFECT_FRAME_BYTES:
        raise CoordinatorEffectClientError("coordinator_effect_request_invalid")
    return payload


def decode_effect_request_bytes(payload: bytes) -> CoordinatorNodeEffectRequest:
    try:
        return CoordinatorNodeEffectRequest.from_canonical_dict(_decode(payload))
    except (CoordinatorEffectContractError, CoordinatorEffectClientError) as error:
        raise CoordinatorEffectClientError("coordinator_effect_request_invalid") from error


def encode_effect_response_bytes(response: CoordinatorNodeEffectResponse) -> bytes:
    if not isinstance(response, CoordinatorNodeEffectResponse):
        raise CoordinatorEffectClientError("coordinator_effect_response_invalid")
    payload = _canonical(response.to_canonical_dict())
    if len(payload) > MAX_EFFECT_FRAME_BYTES:
        raise CoordinatorEffectClientError("coordinator_effect_response_invalid")
    return payload


def decode_effect_response_bytes(payload: bytes) -> CoordinatorNodeEffectResponse:
    try:
        return CoordinatorNodeEffectResponse.from_canonical_dict(_decode(payload))
    except (CoordinatorEffectContractError, CoordinatorEffectClientError) as error:
        raise CoordinatorEffectClientError("coordinator_effect_response_invalid") from error


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise CoordinatorEffectClientError("coordinator_effect_service_unavailable")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _validate_peer(connection: socket.socket, expected_uid: int) -> None:
    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        peer_uid, _ = getpeereid()
        if peer_uid != expected_uid:
            raise CoordinatorEffectClientError("coordinator_effect_service_identity_invalid")
        return
    if hasattr(socket, "SO_PEERCRED"):
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _, peer_uid, _ = struct.unpack("3i", credentials)
        if peer_uid != expected_uid:
            raise CoordinatorEffectClientError("coordinator_effect_service_identity_invalid")
        return
    if hasattr(socket, "LOCAL_PEERCRED"):
        credentials = connection.getsockopt(0, socket.LOCAL_PEERCRED, 8)
        _, peer_uid = struct.unpack("II", credentials)
        if peer_uid != expected_uid:
            raise CoordinatorEffectClientError("coordinator_effect_service_identity_invalid")
        return
    raise CoordinatorEffectClientError("coordinator_effect_service_identity_invalid")


@dataclass(frozen=True, slots=True)
class CoordinatorEffectSocketClient:
    family: EffectFamily
    _socket_path: Path
    _expected_peer_uid: int
    _timeout_seconds: float

    @classmethod
    def _for_testing(
        cls,
        *,
        family: str,
        socket_path: Path,
        expected_peer_uid: int,
        timeout_seconds: float,
    ) -> CoordinatorEffectSocketClient:
        if (
            family not in _EXTERNAL_FAMILIES
            or not isinstance(socket_path, Path)
            or not socket_path.is_absolute()
            or isinstance(expected_peer_uid, bool)
            or not isinstance(expected_peer_uid, int)
            or expected_peer_uid < 0
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int | float)
            or not 0.05 <= timeout_seconds <= 30.0
        ):
            raise CoordinatorEffectClientError("coordinator_effect_client_configuration_invalid")
        return cls(
            cast(EffectFamily, family), socket_path, expected_peer_uid, float(timeout_seconds)
        )

    def _execute(self, request: CoordinatorNodeEffectRequest) -> CoordinatorNodeEffectResponse:
        if not isinstance(request, CoordinatorNodeEffectRequest) or request.family != self.family:
            raise CoordinatorEffectClientError("coordinator_effect_request_invalid")
        payload = encode_effect_request_bytes(request)
        parent_fd: int | None = None
        try:
            parent_fd = open_pinned_parent(self._socket_path, expected_uid=self._expected_peer_uid)
            before = socket_identity_at(
                parent_fd, self._socket_path.name, expected_uid=self._expected_peer_uid
            )
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self._timeout_seconds)
                connection.connect(os.fspath(self._socket_path))
                _validate_peer(connection, self._expected_peer_uid)
                after = socket_identity_at(
                    parent_fd, self._socket_path.name, expected_uid=self._expected_peer_uid
                )
                if after != before:
                    raise CoordinatorEffectClientError(
                        "coordinator_effect_service_identity_invalid"
                    )
                connection.sendall(struct.pack(">I", len(payload)) + payload)
                size = struct.unpack(">I", _recv_exact(connection, 4))[0]
                if not 0 < size <= MAX_EFFECT_FRAME_BYTES:
                    raise CoordinatorEffectClientError("coordinator_effect_response_invalid")
                response = decode_effect_response_bytes(_recv_exact(connection, size))
        except CoordinatorEffectClientError:
            raise
        except (OSError, ProtectedSocketPathError, struct.error) as error:
            raise CoordinatorEffectClientError("coordinator_effect_service_unavailable") from error
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
        if response.request_digest != request.digest:
            raise CoordinatorEffectClientError("coordinator_effect_response_invalid")
        return response

    def publish(self, request: CoordinatorNodeEffectRequest) -> CoordinatorNodeEffectResponse:
        if self.family != "input":
            raise CoordinatorEffectClientError("coordinator_effect_family_invalid")
        return self._execute(request)

    def observe(self, request: CoordinatorNodeEffectRequest) -> CoordinatorNodeEffectResponse:
        if self.family != "observer":
            raise CoordinatorEffectClientError("coordinator_effect_family_invalid")
        return self._execute(request)

    def archive(self, request: CoordinatorNodeEffectRequest) -> CoordinatorNodeEffectResponse:
        if self.family != "archive":
            raise CoordinatorEffectClientError("coordinator_effect_family_invalid")
        return self._execute(request)

    def evaluate(self, request: CoordinatorNodeEffectRequest) -> CoordinatorNodeEffectResponse:
        if self.family != "evaluator":
            raise CoordinatorEffectClientError("coordinator_effect_family_invalid")
        return self._execute(request)

    def reconcile(self, request: CoordinatorNodeEffectRequest) -> CoordinatorNodeEffectResponse:
        return self._execute(request)


@dataclass(frozen=True, slots=True)
class ProtectedCoordinatorEffectClients:
    input_publisher: CoordinatorEffectSocketClient
    observer: CoordinatorEffectSocketClient
    archive: CoordinatorEffectSocketClient
    evaluator: CoordinatorEffectSocketClient


def _read_policy(path: Path, *, expected_owner_uid: int) -> dict[str, object]:
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_owner_uid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or not 2 <= metadata.st_size <= 4_096
        ):
            raise CoordinatorEffectClientError("coordinator_effect_policy_invalid")
        payload = os.read(descriptor, 4_097)
        if len(payload) != metadata.st_size:
            raise CoordinatorEffectClientError("coordinator_effect_policy_invalid")
        canonical_payload = payload[:-1] if payload.endswith(b"\n") else payload
        try:
            value = _decode(canonical_payload)
        except CoordinatorEffectClientError as error:
            raise CoordinatorEffectClientError("coordinator_effect_policy_invalid") from error
    except CoordinatorEffectClientError:
        raise
    except OSError as error:
        raise CoordinatorEffectClientError("coordinator_effect_policy_invalid") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return value


def load_protected_coordinator_effect_clients(
    *,
    _testing_policy_path: Path | None = None,
    _testing_expected_owner_uid: int | None = None,
    _testing_socket_paths: Mapping[str, Path] | None = None,
) -> ProtectedCoordinatorEffectClients:
    testing = _testing_policy_path is not None
    policy_path = _PROTECTED_POLICY_PATH if not testing else _testing_policy_path
    expected_owner_uid = _PROTECTED_SERVICE_UID if not testing else _testing_expected_owner_uid
    if (
        policy_path is None
        or expected_owner_uid is None
        or isinstance(expected_owner_uid, bool)
        or not isinstance(expected_owner_uid, int)
        or expected_owner_uid < 0
        or (_testing_socket_paths is not None and not testing)
    ):
        raise CoordinatorEffectClientError("coordinator_effect_policy_invalid")
    value = _read_policy(policy_path, expected_owner_uid=expected_owner_uid)
    expected = {
        "domain": "carl.coordinator-effect-policy.v1",
        "required_families": ["archive", "evaluator", "input", "observer"],
        "schema_version": 1,
        "service_uid": expected_owner_uid,
    }
    if value != expected:
        raise CoordinatorEffectClientError("coordinator_effect_policy_invalid")
    paths = (
        PROTECTED_EFFECT_SOCKET_PATHS if _testing_socket_paths is None else _testing_socket_paths
    )
    if set(paths) != _EXTERNAL_FAMILIES:
        raise CoordinatorEffectClientError("coordinator_effect_policy_invalid")

    def client(family: str) -> CoordinatorEffectSocketClient:
        return CoordinatorEffectSocketClient._for_testing(
            family=family,
            socket_path=paths[family],
            expected_peer_uid=expected_owner_uid,
            timeout_seconds=_SOCKET_TIMEOUT_SECONDS,
        )

    return ProtectedCoordinatorEffectClients(
        input_publisher=client("input"),
        observer=client("observer"),
        archive=client("archive"),
        evaluator=client("evaluator"),
    )
