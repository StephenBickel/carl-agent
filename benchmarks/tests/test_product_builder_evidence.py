from __future__ import annotations

import importlib
from dataclasses import replace

import pytest
from test_product_builder import _attempt, _candidate, _register

from carl_bench.openai_gateway import OpenAIModelRequest, OpenAIModelResult, OpenAIUsage


def _evidence(name: str):
    return getattr(importlib.import_module("carl_bench.product_builder_evidence"), name)


def _model(registration) -> tuple[OpenAIModelRequest, OpenAIModelResult]:
    request = OpenAIModelRequest(
        schema_version=1,
        repository="openclaw/carl",
        experiment_id="exp-recovery-001",
        subject="candidate",
        task_id="product-builder-1",
        seed=7,
        attempt=1,
        input="Implement the preregistered behavior.",
        execution_context_digest=registration.digest,
    )
    result = OpenAIModelResult(
        response_id="resp_builder_001",
        model="gpt-5.2",
        status="completed",
        usage=OpenAIUsage(100, 0, 50, 10, 150),
        latency_ms=250,
        request_digest=request.request_digest,
        output_digest="b" * 64,
        output_text='{"patch":"bounded"}',
    )
    return request, result


def _receipt():
    registration = _register()
    request, result = _model(registration)
    return _evidence("ProtectedAttemptReceipt").from_observation(
        registration=registration,
        attempt=_attempt(),
        exact_parent=registration.parent_commit,
        prepatch_tree="1" * 40,
        test_command=("cargo", "test", "restart-preserves-progress"),
        test_output_artifact_digest="8" * 64,
        postpatch_tree="3" * 40,
        model_request=request,
        model_result=result,
        trusted_cost_microdollars=250_000,
    )


def test_signed_receipt_rejects_cost_tree_output_and_registration_tampering() -> None:
    key = b"k" * 32
    receipt = _receipt()
    envelope = _evidence("SignedAttemptReceipt").sign(receipt, key)
    assert envelope.verify(key) == receipt

    for mutation in (
        {"trusted_cost_microdollars": receipt.trusted_cost_microdollars + 1},
        {"postpatch_tree": "4" * 40},
        {"test_output_artifact_digest": "5" * 64},
        {"registration_digest": "6" * 64},
        {"action_digest": "7" * 64},
    ):
        forged = replace(envelope, receipt=replace(receipt, **mutation))
        with pytest.raises(ValueError, match="^builder_attempt_receipt_signature_invalid$"):
            forged.verify(key)


def test_candidate_packet_seals_and_reverifies_exact_receipt_digests() -> None:
    key = b"k" * 32
    registration = _register()
    receipt = _receipt()
    envelope = _evidence("SignedAttemptReceipt").sign(receipt, key)
    candidate = replace(_candidate(registration), changed_path_count=1)

    packet = _evidence("ProtectedCandidatePacket")(
        schema_version=1,
        registration_digest=registration.digest,
        parent_commit=registration.parent_commit,
        candidate=candidate,
        attempt_receipts=(envelope,),
    )

    assert packet.attempt_receipt_digests == (receipt.digest,)
    assert packet.verify(key).candidate == candidate
    with pytest.raises(ValueError, match="^builder_candidate_receipt_mismatch$"):
        replace(packet, registration_digest="f" * 64).verify(key)
