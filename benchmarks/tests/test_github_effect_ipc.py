from __future__ import annotations

import hashlib
import importlib
import json
from types import ModuleType

import pytest

REQUEST_DOMAIN = "carl.github-effect.ipc.request.v1"
RESPONSE_DOMAIN = "carl.github-effect.ipc.response.v1"
NOW = "2026-08-21T12:00:00Z"
SHA = "2" * 40
DIGEST = "a" * 64
SHA_B = "3" * 40


def _operation_parameters() -> dict[str, dict[str, object]]:
    workflow = {
        "candidate_commit": SHA,
        "experiment_digest": DIGEST,
        "metric_pack_digest": "b" * 64,
        "parent_commit": SHA_B,
        "policy_digest": "c" * 64,
        "repository": "StephenBickel/carl-agent",
        "task_set_digest": "d" * 64,
        "workflow_blob_digest": "e" * 64,
        "workflow_file": "autonomous-improvement.yml",
        "workflow_revision": SHA_B,
    }
    pull_target = {
        "base_branch": "main",
        "head_branch": "experimental/promotion-001",
        "head_sha": SHA,
        "number": 17,
        "promotion_id": "promotion-001",
    }
    return {
        "create_experimental_ref": {
            "branch": "experimental/experiment-001",
            "candidate_commit": SHA,
            "experiment_id": "experiment-001",
        },
        "create_pull_request": {
            "base_branch": "main",
            "draft": True,
            "head_branch": "experimental/promotion-001",
            "head_sha": SHA,
            "promotion_id": "promotion-001",
            "pull_request_body": "Measured capability improvement.",
            "title": "Promote experiment 001",
        },
        "create_revert_pull_request": {
            "base_branch": "main",
            "draft": False,
            "expected_restored_tree": "4" * 40,
            "head_branch": "revert/promotion-001",
            "promotion_id": "promotion-001",
            "promotion_merge_commit": SHA_B,
            "pull_request_body": "Automated rollback after failed soak.",
            "revert_candidate_commit": SHA,
            "title": "Revert promotion 001",
        },
        "create_revert_ref": {
            "branch": "revert/promotion-001",
            "expected_restored_tree": "4" * 40,
            "promotion_id": "promotion-001",
            "promotion_merge_commit": SHA_B,
            "revert_candidate_commit": SHA,
        },
        "dispatch_workflow": dict(workflow),
        "enable_pull_request_auto_merge": {**pull_target, "merge_method": "squash"},
        "mark_pull_request_ready": dict(pull_target),
        "observe_required_checks": {
            "head_sha": SHA,
            "required_checks": [
                "Quality",
                "Benchmark contracts",
                "Test (ubuntu-latest)",
                "Test (macos-latest)",
                "Test (windows-latest)",
            ],
        },
        "update_pull_request": {
            **pull_target,
            "pull_request_body": "Updated independent review evidence.",
            "title": "Promote experiment 001 safely",
        },
    }


def _document_for(operation: str, parameters: dict[str, object]) -> dict[str, object]:
    return {
        "command_key": f"ipc-{operation}-001",
        "domain": REQUEST_DOMAIN,
        "effect_key": f"cloud-effect-{DIGEST}",
        "occurred_at": NOW,
        "operation": operation,
        "parameters": parameters,
        "request_key": f"ipc-{operation}-001",
        "schema_version": 1,
    }


def _ipc() -> ModuleType:
    try:
        return importlib.import_module("carl_bench.github_effect_ipc")
    except ModuleNotFoundError:
        pytest.fail("credential-free GitHub effect IPC codec module is required")


def _request_document() -> dict[str, object]:
    return {
        "command_key": f"github-checks-{SHA}",
        "domain": REQUEST_DOMAIN,
        "effect_key": f"cloud-effect-{DIGEST}",
        "occurred_at": NOW,
        "operation": "observe_required_checks",
        "parameters": {
            "head_sha": SHA,
            "required_checks": [
                "Quality",
                "Benchmark contracts",
                "Test (ubuntu-latest)",
                "Test (macos-latest)",
                "Test (windows-latest)",
            ],
        },
        "request_key": f"github-checks-{SHA}",
        "schema_version": 1,
    }


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def test_effect_operation_vocabulary_is_closed() -> None:
    ipc = _ipc()

    assert {operation.value for operation in ipc.GitHubEffectOperation} == {
        "create_experimental_ref",
        "create_pull_request",
        "create_revert_pull_request",
        "create_revert_ref",
        "dispatch_workflow",
        "enable_pull_request_auto_merge",
        "mark_pull_request_ready",
        "observe_required_checks",
        "update_pull_request",
    }


def test_request_codec_is_canonical_duplicate_aware_and_digest_bound() -> None:
    ipc = _ipc()
    expected = _canonical(_request_document())

    request = ipc.GitHubEffectRequest.from_canonical_dict(_request_document())

    assert ipc.encode_request_bytes(request) == expected
    assert ipc.decode_request_bytes(expected) == request
    assert request.digest == hashlib.sha256(expected).hexdigest()

    duplicate = expected[:-1] + b',"schema_version":1}'
    with pytest.raises(ipc.GitHubEffectProtocolError, match="github_effect_ipc_request_invalid"):
        ipc.decode_request_bytes(duplicate)


@pytest.mark.parametrize("operation", tuple(_operation_parameters()))
def test_every_closed_operation_has_a_canonical_typed_round_trip(operation: str) -> None:
    ipc = _ipc()
    document = _document_for(operation, _operation_parameters()[operation])
    encoded = _canonical(document)

    decoded = ipc.decode_request_bytes(encoded)

    assert decoded.operation.value == operation
    assert decoded.parameters == document["parameters"]
    assert ipc.encode_request_bytes(decoded) == encoded


@pytest.mark.parametrize("operation", tuple(_operation_parameters()))
def test_every_operation_rejects_extra_missing_and_wrong_type_fields(operation: str) -> None:
    ipc = _ipc()
    parameters = _operation_parameters()[operation]
    mutations = []
    extra = dict(parameters)
    extra["unexpected"] = "field"
    mutations.append(extra)
    missing = dict(parameters)
    missing.pop(next(iter(missing)))
    mutations.append(missing)
    wrong_type = dict(parameters)
    wrong_type[next(iter(wrong_type))] = []
    mutations.append(wrong_type)

    for mutation in mutations:
        with pytest.raises(
            ipc.GitHubEffectProtocolError, match="github_effect_ipc_request_invalid"
        ):
            ipc.decode_request_bytes(_canonical(_document_for(operation, mutation)))


@pytest.mark.parametrize("operation", tuple(_operation_parameters()))
@pytest.mark.parametrize(
    "forbidden",
    ("body", "graphql", "headers", "method", "path", "payload", "url", "variables"),
)
def test_every_operation_rejects_generic_raw_transport_fields(
    operation: str, forbidden: str
) -> None:
    ipc = _ipc()
    parameters = dict(_operation_parameters()[operation])
    parameters[forbidden] = "attacker-controlled"

    with pytest.raises(ipc.GitHubEffectProtocolError, match="github_effect_ipc_request_invalid"):
        ipc.decode_request_bytes(_canonical(_document_for(operation, parameters)))


@pytest.mark.parametrize(
    "forbidden",
    (
        "authorization",
        "graphql",
        "headers",
        "method",
        "path",
        "query",
        "token",
        "transport",
        "url",
        "variables",
    ),
)
def test_request_codec_cannot_express_raw_http_graphql_or_credentials(forbidden: str) -> None:
    ipc = _ipc()
    document = _request_document()
    document[forbidden] = "attacker-controlled"

    with pytest.raises(ipc.GitHubEffectProtocolError, match="github_effect_ipc_request_invalid"):
        ipc.decode_request_bytes(_canonical(document))

    nested = _request_document()
    parameters = dict(nested["parameters"])
    parameters[forbidden] = "attacker-controlled"
    nested["parameters"] = parameters
    with pytest.raises(ipc.GitHubEffectProtocolError, match="github_effect_ipc_request_invalid"):
        ipc.decode_request_bytes(_canonical(nested))


def test_request_codec_rejects_client_authority_and_claim_assertions() -> None:
    ipc = _ipc()

    for forbidden in ("authority", "claim_id", "claim_revision", "claim_expires_at"):
        document = _request_document()
        document[forbidden] = "forged"
        with pytest.raises(
            ipc.GitHubEffectProtocolError, match="github_effect_ipc_request_invalid"
        ):
            ipc.decode_request_bytes(_canonical(document))


def test_response_codec_is_bounded_to_typed_result_retry_or_redacted_error() -> None:
    ipc = _ipc()
    request = ipc.GitHubEffectRequest.from_canonical_dict(_request_document())
    response_document = {
        "domain": RESPONSE_DOMAIN,
        "error_code": "github_command_not_found",
        "observed_at": NOW,
        "request_digest": request.digest,
        "result": None,
        "retry_not_before": None,
        "schema_version": 1,
        "status": "rejected",
    }

    response = ipc.decode_response_bytes(_canonical(response_document))

    assert response.to_canonical_dict() == response_document
    assert ipc.encode_response_bytes(response) == _canonical(response_document)

    leaked = dict(response_document)
    leaked["error_detail"] = "Bearer github_pat_secret"
    with pytest.raises(ipc.GitHubEffectProtocolError, match="github_effect_ipc_response_invalid"):
        ipc.decode_response_bytes(_canonical(leaked))


def test_response_codec_rejects_raw_or_unknown_result_shapes() -> None:
    ipc = _ipc()
    request = ipc.GitHubEffectRequest.from_canonical_dict(_request_document())
    base = {
        "domain": RESPONSE_DOMAIN,
        "error_code": None,
        "observed_at": NOW,
        "request_digest": request.digest,
        "retry_not_before": None,
        "schema_version": 1,
        "status": "completed",
    }

    for result in (
        {"method": "POST", "path": "/graphql"},
        {"result_type": "ArbitraryHttpResponse", "value": {}},
        {"result_type": "RequiredChecksSnapshot", "value": {"token": "secret"}},
    ):
        with pytest.raises(
            ipc.GitHubEffectProtocolError, match="github_effect_ipc_response_invalid"
        ):
            ipc.decode_response_bytes(_canonical({**base, "result": result}))


def test_pull_request_result_round_trip_uses_typed_description_not_raw_body() -> None:
    ipc = _ipc()
    request = ipc.GitHubEffectRequest.from_canonical_dict(_request_document())
    document = {
        "domain": RESPONSE_DOMAIN,
        "error_code": None,
        "observed_at": NOW,
        "request_digest": request.digest,
        "result": {
            "result_type": "PullRequestEffectSnapshot",
            "value": {
                "auto_merge_enabled": False,
                "base_branch": "main",
                "command_occurred_at": NOW,
                "draft": True,
                "effect_key": f"cloud-effect-{DIGEST}",
                "head_branch": "experimental/promotion-001",
                "head_sha": SHA,
                "number": 17,
                "observed_at": NOW,
                "pull_request_body": "Measured capability improvement.",
                "repository": "StephenBickel/carl-agent",
                "request_key": "promotion-001",
                "state": "open",
                "status": "created",
                "title": "Promote experiment",
                "pull_request_url": "https://github.com/StephenBickel/carl-agent/pull/17",
            },
        },
        "retry_not_before": None,
        "schema_version": 1,
        "status": "completed",
    }

    response = ipc.decode_response_bytes(_canonical(document))

    assert ipc.encode_response_bytes(response) == _canonical(document)
    assert "body" not in response.result["value"]
