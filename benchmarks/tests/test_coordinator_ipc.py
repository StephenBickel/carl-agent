from __future__ import annotations

import hashlib
import json

import pytest

from carl_bench.coordinator_ipc import (
    COORDINATOR_REQUEST_DOMAIN,
    CoordinatorProtocolError,
    CoordinatorServiceRequest,
    decode_request_bytes,
    encode_request_bytes,
)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def request_document(command: str = "coordinate") -> dict[str, object]:
    return {
        "command": command,
        "domain": COORDINATOR_REQUEST_DOMAIN,
        "schema_version": 1,
    }


def test_request_contains_only_the_closed_command_identity() -> None:
    document = request_document()
    encoded = canonical(document)

    request = CoordinatorServiceRequest.from_canonical_dict(document)

    assert encode_request_bytes(request) == encoded
    assert decode_request_bytes(encoded) == request
    assert request.digest == hashlib.sha256(encoded).hexdigest()


@pytest.mark.parametrize(
    "forbidden",
    (
        "archive",
        "authority",
        "clock",
        "credentials",
        "dependencies",
        "dsn",
        "effect",
        "endpoint",
        "evidence",
        "model",
        "observed_at",
        "operation",
        "snapshot",
        "state",
        "tools",
    ),
)
def test_request_cannot_express_protected_state_or_dependencies(forbidden: str) -> None:
    document = request_document()
    document[forbidden] = {"attacker": "selected"}

    with pytest.raises(CoordinatorProtocolError, match="coordinator_ipc_request_invalid"):
        decode_request_bytes(canonical(document))


def test_request_rejects_boolean_schema_and_duplicate_json_keys() -> None:
    boolean_schema = request_document()
    boolean_schema["schema_version"] = True
    with pytest.raises(CoordinatorProtocolError, match="coordinator_ipc_request_invalid"):
        decode_request_bytes(canonical(boolean_schema))

    duplicate = canonical(request_document())[:-1] + b',"schema_version":1}'
    with pytest.raises(CoordinatorProtocolError, match="coordinator_ipc_request_invalid"):
        decode_request_bytes(duplicate)


@pytest.mark.parametrize(
    "command",
    (
        "request",
        "coordinate",
        "observe",
        "ingest",
        "publish-input",
        "health",
        "commission-live",
    ),
)
def test_request_command_vocabulary_is_exact(command: str) -> None:
    assert decode_request_bytes(canonical(request_document(command))).command == command


def test_request_rejects_unknown_command() -> None:
    with pytest.raises(CoordinatorProtocolError, match="coordinator_ipc_request_invalid"):
        decode_request_bytes(canonical(request_document("push-main")))
