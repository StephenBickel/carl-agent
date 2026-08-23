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


COMMAND_NODES = {
    "request": ["register_hypothesis", "request_builder"],
    "coordinate": [
        "create_revert",
        "observe_revert",
        "publish_input",
        "register_hypothesis",
        "request_builder",
        "dispatch_builder",
        "observe_builder",
        "archive_builder",
        "ingest_builder",
        "publish_experimental",
        "dispatch_validation",
        "observe_validation",
        "archive_validation",
        "ingest_validation",
        "record_disposition",
        "create_promotion_pr",
        "observe_required_checks",
        "enable_auto_merge",
        "schedule_soak",
        "observe_soak",
        "accept_soak",
        "trigger_supervisor",
    ],
    "observe": [
        "observe_revert",
        "observe_builder",
        "archive_builder",
        "observe_validation",
        "archive_validation",
        "observe_required_checks",
        "observe_soak",
    ],
    "ingest": ["ingest_builder", "ingest_validation", "record_disposition"],
    "publish-input": ["publish_input"],
    "health": ["trigger_supervisor"],
    "commission-live": [
        "create_revert",
        "observe_revert",
        "dispatch_validation",
        "observe_validation",
        "archive_validation",
        "ingest_validation",
        "record_disposition",
        "create_promotion_pr",
        "observe_required_checks",
        "enable_auto_merge",
        "schedule_soak",
        "observe_soak",
        "accept_soak",
    ],
}


def request_document(
    command: str = "coordinate", *, allowed_nodes: list[str] | None = None
) -> dict[str, object]:
    return {
        "allowed_nodes": COMMAND_NODES[command] if allowed_nodes is None else allowed_nodes,
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


def test_request_carries_only_a_canonical_subset_of_command_nodes() -> None:
    document = request_document(
        allowed_nodes=["create_revert", "observe_revert", "schedule_soak", "observe_soak"]
    )

    request = decode_request_bytes(canonical(document))

    assert request.allowed_nodes == (
        "create_revert",
        "observe_revert",
        "schedule_soak",
        "observe_soak",
    )


@pytest.mark.parametrize(
    "allowed_nodes",
    (
        [],
        ["observe_soak", "schedule_soak"],
        ["schedule_soak", "schedule_soak"],
        ["accept_soak", "push_main"],
    ),
)
def test_request_rejects_empty_reordered_duplicate_or_unknown_allowlists(
    allowed_nodes: list[str],
) -> None:
    with pytest.raises(CoordinatorProtocolError, match="coordinator_ipc_request_invalid"):
        decode_request_bytes(canonical(request_document(allowed_nodes=allowed_nodes)))
