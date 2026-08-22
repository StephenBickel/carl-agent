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
        "discover_workflow_run",
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
