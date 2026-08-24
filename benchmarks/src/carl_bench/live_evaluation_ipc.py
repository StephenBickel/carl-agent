"""Credential-free canonical protocol for protected live evidence joining."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_evaluation_authority import ProtectedEvidenceLocator

REQUEST_DOMAIN = "carl.live-evaluation.ipc.request.v1"
RESPONSE_DOMAIN = "carl.live-evaluation.ipc.response.v1"
MAX_FRAME_BYTES = 262_144
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ERROR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")


class LiveEvaluationProtocolError(ValueError):
    """Stable canonical protocol failure."""


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in items:
        if key in value:
            raise ValueError("duplicate")
        value[key] = item
    return value


def _decode(payload: bytes, code: str) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_FRAME_BYTES:
        raise LiveEvaluationProtocolError(code)
    try:
        value = json.loads(payload, object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise LiveEvaluationProtocolError(code) from error
    if type(value) is not dict or canonical_json_bytes(value) != payload:
        raise LiveEvaluationProtocolError(code)
    return value


def _locator(value: object, expected_kind: str) -> ProtectedEvidenceLocator:
    if type(value) is not dict or set(value) != {
        "kind",
        "object_key",
        "payload_digest",
        "version_id",
    }:
        raise LiveEvaluationProtocolError("live_evaluation_request_invalid")
    try:
        result = ProtectedEvidenceLocator(
            kind=value["kind"],
            object_key=value["object_key"],
            version_id=value["version_id"],
            payload_digest=value["payload_digest"],
        )
    except (TypeError, ValueError) as error:
        raise LiveEvaluationProtocolError("live_evaluation_request_invalid") from error
    if result.kind != expected_kind:
        raise LiveEvaluationProtocolError("live_evaluation_request_invalid")
    return result


@dataclass(frozen=True, slots=True)
class ProtectedJoinRequest:
    schema_version: int
    request_digest: str
    deterministic_locator: ProtectedEvidenceLocator
    live_locator: ProtectedEvidenceLocator

    def __post_init__(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or self.schema_version != 1
            or not isinstance(self.request_digest, str)
            or _DIGEST.fullmatch(self.request_digest) is None
            or not isinstance(self.deterministic_locator, ProtectedEvidenceLocator)
            or self.deterministic_locator.kind != "protected_deterministic_pair"
            or not isinstance(self.live_locator, ProtectedEvidenceLocator)
            or self.live_locator.kind != "protected_live_pair"
        ):
            raise LiveEvaluationProtocolError("live_evaluation_request_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "deterministic_locator": self.deterministic_locator.to_canonical_dict(),
            "domain": REQUEST_DOMAIN,
            "live_locator": self.live_locator.to_canonical_dict(),
            "request_digest": self.request_digest,
            "schema_version": self.schema_version,
        }

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_canonical_dict())

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()


def decode_request_bytes(payload: bytes) -> ProtectedJoinRequest:
    value = _decode(payload, "live_evaluation_request_invalid")
    if (
        set(value)
        != {
            "deterministic_locator",
            "domain",
            "live_locator",
            "request_digest",
            "schema_version",
        }
        or value.get("domain") != REQUEST_DOMAIN
    ):
        raise LiveEvaluationProtocolError("live_evaluation_request_invalid")
    try:
        return ProtectedJoinRequest(
            schema_version=value["schema_version"],
            request_digest=value["request_digest"],
            deterministic_locator=_locator(
                value["deterministic_locator"], "protected_deterministic_pair"
            ),
            live_locator=_locator(value["live_locator"], "protected_live_pair"),
        )
    except (TypeError, ValueError) as error:
        raise LiveEvaluationProtocolError("live_evaluation_request_invalid") from error


def _utc(value: object) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LiveEvaluationProtocolError("live_evaluation_response_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise LiveEvaluationProtocolError("live_evaluation_response_invalid") from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise LiveEvaluationProtocolError("live_evaluation_response_invalid")
    return value


@dataclass(frozen=True, slots=True)
class ProtectedJoinResponse:
    schema_version: int
    status: str
    request_digest: str
    observed_at: str
    receipt: dict[str, Any] | None
    error_code: str | None

    def __post_init__(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or self.schema_version != 1
            or self.status not in {"completed", "rejected"}
            or not isinstance(self.request_digest, str)
            or _DIGEST.fullmatch(self.request_digest) is None
        ):
            raise LiveEvaluationProtocolError("live_evaluation_response_invalid")
        _utc(self.observed_at)
        if self.status == "completed":
            if type(self.receipt) is not dict or self.error_code is not None:
                raise LiveEvaluationProtocolError("live_evaluation_response_invalid")
        elif (
            self.receipt is not None
            or not isinstance(self.error_code, str)
            or _ERROR.fullmatch(self.error_code) is None
        ):
            raise LiveEvaluationProtocolError("live_evaluation_response_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "domain": RESPONSE_DOMAIN,
            "error_code": self.error_code,
            "observed_at": self.observed_at,
            "receipt": self.receipt,
            "request_digest": self.request_digest,
            "schema_version": self.schema_version,
            "status": self.status,
        }


def encode_response_bytes(value: ProtectedJoinResponse) -> bytes:
    if not isinstance(value, ProtectedJoinResponse):
        raise LiveEvaluationProtocolError("live_evaluation_response_invalid")
    return canonical_json_bytes(value.to_canonical_dict())


def decode_response_bytes(payload: bytes) -> ProtectedJoinResponse:
    value = _decode(payload, "live_evaluation_response_invalid")
    if (
        set(value)
        != {
            "domain",
            "error_code",
            "observed_at",
            "receipt",
            "request_digest",
            "schema_version",
            "status",
        }
        or value.get("domain") != RESPONSE_DOMAIN
    ):
        raise LiveEvaluationProtocolError("live_evaluation_response_invalid")
    try:
        return ProtectedJoinResponse(
            schema_version=value["schema_version"],
            status=value["status"],
            request_digest=value["request_digest"],
            observed_at=value["observed_at"],
            receipt=value["receipt"],
            error_code=value["error_code"],
        )
    except (TypeError, ValueError) as error:
        raise LiveEvaluationProtocolError("live_evaluation_response_invalid") from error
