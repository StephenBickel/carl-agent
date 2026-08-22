"""Canonical credential-free protocol for the protected coordinator service."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from carl_bench.canonical import CanonicalizationError, canonical_json_bytes
from carl_bench.cloud_coordinator import CloudCoordinatorDecision

COORDINATOR_REQUEST_DOMAIN = "carl.coordinator.ipc.request.v1"
COORDINATOR_RESPONSE_DOMAIN = "carl.coordinator.ipc.response.v1"
MAX_COORDINATOR_FRAME_BYTES = 32_768
_COMMANDS = frozenset(
    {"request", "coordinate", "observe", "ingest", "publish-input", "health", "commission-live"}
)


class CoordinatorProtocolError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CoordinatorProtocolError("coordinator_ipc_duplicate_key")
        value[key] = item
    return value


def _decode(payload: bytes, code: str) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_COORDINATOR_FRAME_BYTES:
        raise CoordinatorProtocolError(code)
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_pairs)
    except (CoordinatorProtocolError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise CoordinatorProtocolError(code) from error
    try:
        canonical = canonical_json_bytes(value)
    except (CanonicalizationError, UnicodeError, RecursionError) as error:
        raise CoordinatorProtocolError(code) from error
    if type(value) is not dict or canonical != payload:
        raise CoordinatorProtocolError(code)
    return value


@dataclass(frozen=True, slots=True)
class CoordinatorServiceRequest:
    schema_version: int
    domain: str
    command: str

    @classmethod
    def create(cls, command: str) -> CoordinatorServiceRequest:
        return cls.from_canonical_dict(
            {"command": command, "domain": COORDINATOR_REQUEST_DOMAIN, "schema_version": 1}
        )

    @classmethod
    def from_canonical_dict(cls, value: object) -> CoordinatorServiceRequest:
        code = "coordinator_ipc_request_invalid"
        if (
            type(value) is not dict
            or set(value) != {"command", "domain", "schema_version"}
            or isinstance(value["schema_version"], bool)
            or value["schema_version"] != 1
            or value["domain"] != COORDINATOR_REQUEST_DOMAIN
            or value["command"] not in _COMMANDS
        ):
            raise CoordinatorProtocolError(code)
        return cls(1, COORDINATOR_REQUEST_DOMAIN, value["command"])

    def to_canonical_dict(self) -> dict[str, object]:
        return {"command": self.command, "domain": self.domain, "schema_version": 1}

    @property
    def digest(self) -> str:
        return hashlib.sha256(encode_request_bytes(self)).hexdigest()


@dataclass(frozen=True, slots=True)
class CoordinatorServiceResponse:
    schema_version: int
    domain: str
    status: Literal["completed", "rejected"]
    request_digest: str
    result: dict[str, object] | None
    error_code: str | None

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "error_code": self.error_code,
            "request_digest": self.request_digest,
            "result": self.result,
            "schema_version": self.schema_version,
            "status": self.status,
        }


def encode_request_bytes(request: CoordinatorServiceRequest) -> bytes:
    if not isinstance(request, CoordinatorServiceRequest):
        raise CoordinatorProtocolError("coordinator_ipc_request_invalid")
    validated = CoordinatorServiceRequest.from_canonical_dict(request.to_canonical_dict())
    return canonical_json_bytes(validated.to_canonical_dict())


def decode_request_bytes(payload: bytes) -> CoordinatorServiceRequest:
    try:
        return CoordinatorServiceRequest.from_canonical_dict(
            _decode(payload, "coordinator_ipc_request_invalid")
        )
    except CoordinatorProtocolError as error:
        raise CoordinatorProtocolError("coordinator_ipc_request_invalid") from error


def encode_response_bytes(response: CoordinatorServiceResponse) -> bytes:
    if not isinstance(response, CoordinatorServiceResponse):
        raise CoordinatorProtocolError("coordinator_ipc_response_invalid")
    return canonical_json_bytes(
        decode_response_bytes(
            canonical_json_bytes(response.to_canonical_dict())
        ).to_canonical_dict()
    )


def decode_response_bytes(payload: bytes) -> CoordinatorServiceResponse:
    code = "coordinator_ipc_response_invalid"
    try:
        value = _decode(payload, code)
        if set(value) != {
            "domain",
            "error_code",
            "request_digest",
            "result",
            "schema_version",
            "status",
        }:
            raise ValueError
        if (
            isinstance(value["schema_version"], bool)
            or value["schema_version"] != 1
            or value["domain"] != COORDINATOR_RESPONSE_DOMAIN
            or value["status"] not in {"completed", "rejected"}
            or not isinstance(value["request_digest"], str)
            or len(value["request_digest"]) != 64
        ):
            raise ValueError
        int(value["request_digest"], 16)
        result = value["result"]
        error = value["error_code"]
        if value["status"] == "completed":
            if type(result) is not dict or error is not None:
                raise ValueError
            result = CloudCoordinatorDecision.from_canonical_dict(result).to_canonical_dict()
        elif (
            result is not None or not isinstance(error, str) or not error.startswith("coordinator_")
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError, CoordinatorProtocolError) as exc:
        raise CoordinatorProtocolError(code) from exc
    return CoordinatorServiceResponse(
        1, COORDINATOR_RESPONSE_DOMAIN, value["status"], value["request_digest"], result, error
    )
