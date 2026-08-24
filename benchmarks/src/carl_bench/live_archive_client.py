"""Credential-free exact-version reader for the protected evidence archive."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_evaluation_authority import ProtectedArchiveVersion
from carl_bench.unix_socket_security import (
    ProtectedSocketPathError,
    open_pinned_parent,
    socket_identity_at,
)

_REQUEST_DOMAIN = "carl.evidence-archive.read.request.v1"
_RESPONSE_DOMAIN = "carl.evidence-archive.read.response.v1"
_SOCKET_PATH = Path("/run/carl/evidence-archive.sock")
_MAX_PAYLOAD_BYTES = 8_388_608
_MAX_FRAME_BYTES = 11_300_000
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_KEY = re.compile(r"^carl-evidence/v1/sha256/[0-9a-f]{2}/[0-9a-f]{64}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+=-]{0,255}$")
_ERROR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")


class ProtectedArchiveClientError(RuntimeError):
    """Stable reader failure containing no provider or credential detail."""


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate")
        value[key] = item
    return value


def _decode(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= _MAX_FRAME_BYTES:
        raise ProtectedArchiveClientError("protected_archive_response_invalid")
    try:
        value = json.loads(payload, object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ProtectedArchiveClientError("protected_archive_response_invalid") from error
    if type(value) is not dict or canonical_json_bytes(value) != payload:
        raise ProtectedArchiveClientError("protected_archive_response_invalid")
    return value


def _request_bytes(object_key: object, version_id: object) -> bytes:
    if (
        not isinstance(object_key, str)
        or _OBJECT_KEY.fullmatch(object_key) is None
        or not isinstance(version_id, str)
        or _VERSION.fullmatch(version_id) is None
    ):
        raise ProtectedArchiveClientError("protected_archive_request_invalid")
    return canonical_json_bytes(
        {
            "domain": _REQUEST_DOMAIN,
            "object_key": object_key,
            "schema_version": 1,
            "version_id": version_id,
        }
    )


def _archive_document(archive: ProtectedArchiveVersion) -> dict[str, Any]:
    if not isinstance(archive, ProtectedArchiveVersion):
        raise ProtectedArchiveClientError("protected_archive_response_invalid")
    return {
        "byte_length": archive.byte_length,
        "checksum_sha256": archive.checksum_sha256,
        "created_at": archive.created_at,
        "object_key": archive.object_key,
        "payload_b64": base64.b64encode(archive.payload).decode("ascii"),
        "retain_until": archive.retain_until,
        "retention_mode": archive.retention_mode,
        "version_id": archive.version_id,
    }


def encode_archive_response_for_testing(
    *, request_digest: str, archive: ProtectedArchiveVersion
) -> bytes:
    """Encode a synthetic archive-service response for process contract tests."""
    if not isinstance(request_digest, str) or _DIGEST.fullmatch(request_digest) is None:
        raise ProtectedArchiveClientError("protected_archive_response_invalid")
    return canonical_json_bytes(
        {
            "archive": _archive_document(archive),
            "domain": _RESPONSE_DOMAIN,
            "error_code": None,
            "request_digest": request_digest,
            "schema_version": 1,
            "status": "completed",
        }
    )


def _archive_from_response(value: object) -> ProtectedArchiveVersion:
    if type(value) is not dict or set(value) != {
        "byte_length",
        "checksum_sha256",
        "created_at",
        "object_key",
        "payload_b64",
        "retain_until",
        "retention_mode",
        "version_id",
    }:
        raise ProtectedArchiveClientError("protected_archive_response_invalid")
    try:
        payload = base64.b64decode(value["payload_b64"], validate=True)
    except (TypeError, ValueError, binascii.Error) as error:
        raise ProtectedArchiveClientError("protected_archive_response_invalid") from error
    digest = hashlib.sha256(payload).hexdigest()
    byte_length = value["byte_length"]
    if (
        len(payload) > _MAX_PAYLOAD_BYTES
        or base64.b64encode(payload).decode("ascii") != value["payload_b64"]
        or not isinstance(value["object_key"], str)
        or _OBJECT_KEY.fullmatch(value["object_key"]) is None
        or value["object_key"] != f"carl-evidence/v1/sha256/{digest[:2]}/{digest}"
        or value["checksum_sha256"] != digest
        or isinstance(byte_length, bool)
        or not isinstance(byte_length, int)
        or byte_length != len(payload)
        or not isinstance(value["version_id"], str)
        or _VERSION.fullmatch(value["version_id"]) is None
        or value["retention_mode"] != "COMPLIANCE"
        or not isinstance(value["retain_until"], str)
        or not isinstance(value["created_at"], str)
    ):
        raise ProtectedArchiveClientError("protected_archive_response_invalid")
    return ProtectedArchiveVersion(
        object_key=value["object_key"],
        version_id=value["version_id"],
        payload=payload,
        checksum_sha256=digest,
        byte_length=byte_length,
        retention_mode="COMPLIANCE",
        retain_until=value["retain_until"],
        created_at=value["created_at"],
    )


def _response_archive(payload: bytes, *, request_digest: str) -> ProtectedArchiveVersion:
    value = _decode(payload)
    if (
        set(value)
        != {
            "archive",
            "domain",
            "error_code",
            "request_digest",
            "schema_version",
            "status",
        }
        or value["domain"] != _RESPONSE_DOMAIN
        or isinstance(value["schema_version"], bool)
        or value["schema_version"] != 1
        or value["request_digest"] != request_digest
        or value["status"] not in {"completed", "rejected"}
    ):
        raise ProtectedArchiveClientError("protected_archive_response_invalid")
    if value["status"] == "rejected":
        if (
            value["archive"] is not None
            or not isinstance(value["error_code"], str)
            or _ERROR.fullmatch(value["error_code"]) is None
        ):
            raise ProtectedArchiveClientError("protected_archive_response_invalid")
        raise ProtectedArchiveClientError(value["error_code"])
    if value["error_code"] is not None:
        raise ProtectedArchiveClientError("protected_archive_response_invalid")
    return _archive_from_response(value["archive"])


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    while count:
        chunk = connection.recv(count)
        if not chunk:
            raise ProtectedArchiveClientError("protected_archive_service_unavailable")
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
class ProtectedArchiveSocketReader:
    """Pinned exact-version reader with no cloud credential or endpoint input."""

    _socket_path: Path
    _expected_peer_uid: int
    _timeout_seconds: float

    @classmethod
    def from_protected_environment(cls) -> ProtectedArchiveSocketReader:
        return cls(_SOCKET_PATH, 0, 15.0)

    @classmethod
    def _for_testing(
        cls, *, socket_path: Path, expected_peer_uid: int, timeout_seconds: float
    ) -> ProtectedArchiveSocketReader:
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
            raise ProtectedArchiveClientError("protected_archive_client_configuration_invalid")
        return cls(socket_path, expected_peer_uid, float(timeout_seconds))

    def read_exact(self, object_key: str, version_id: str) -> ProtectedArchiveVersion:
        payload = _request_bytes(object_key, version_id)
        request_digest = hashlib.sha256(payload).hexdigest()
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
                    raise ProtectedArchiveClientError("protected_archive_service_identity_invalid")
                after = socket_identity_at(
                    parent_fd,
                    self._socket_path.name,
                    expected_uid=self._expected_peer_uid,
                )
                if after != before:
                    raise ProtectedArchiveClientError("protected_archive_service_identity_invalid")
                connection.sendall(struct.pack(">I", len(payload)) + payload)
                size = struct.unpack(">I", _recv_exact(connection, 4))[0]
                if not 0 < size <= _MAX_FRAME_BYTES:
                    raise ProtectedArchiveClientError("protected_archive_response_invalid")
                response = _recv_exact(connection, size)
        except ProtectedArchiveClientError:
            raise
        except (OSError, struct.error, ProtectedSocketPathError) as error:
            raise ProtectedArchiveClientError("protected_archive_service_unavailable") from error
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
        return _response_archive(response, request_digest=request_digest)
