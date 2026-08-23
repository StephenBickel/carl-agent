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


def _cost_receipt(registration):
    request, result = _model(registration)
    gateway = importlib.import_module("carl_bench.product_builder_gateway")
    policy = gateway.BuilderPricingPolicy(
        schema_version=1,
        model="gpt-5.2",
        policy_revision="builder-pricing-test-v1",
        input_cost_microdollars_per_million_tokens=1_000_000_000,
        cached_input_cost_microdollars_per_million_tokens=1_000_000_000,
        output_cost_microdollars_per_million_tokens=1_000_000_000,
    )
    return gateway.ProtectedGatewayCostReceipt.sign(
        request=request, result=result, policy=policy, key=b"k" * 32
    )


def _receipt():
    registration = _register()
    request, result = _model(registration)
    return _evidence("ProtectedAttemptReceipt").from_observation(
        registration=registration,
        builder_request_digest="9" * 64,
        attempt=_attempt(cost_microdollars=150_000),
        exact_parent=registration.parent_commit,
        prepatch_tree="1" * 40,
        test_command=("cargo", "test", "restart-preserves-progress"),
        test_output_artifact_digest="8" * 64,
        diff_artifact_digest="7" * 64,
        postpatch_tree="3" * 40,
        model_request=request,
        model_result=result,
        gateway_cost_receipt=_cost_receipt(registration),
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
    base_candidate = _candidate(registration)
    candidate = replace(
        base_candidate,
        changed_path_count=1,
        diff_artifact=replace(base_candidate.diff_artifact, digest=receipt.diff_artifact_digest),
    )

    packet = _evidence("ProtectedCandidatePacket")(
        schema_version=1,
        builder_request_digest="9" * 64,
        registration_digest=registration.digest,
        parent_commit=registration.parent_commit,
        candidate_tree=receipt.postpatch_tree,
        diff_artifact_digest=receipt.patch_digest,
        candidate=candidate,
        attempt_receipts=(envelope,),
    )

    assert packet.attempt_receipt_digests == (receipt.digest,)
    assert packet.verify(key).candidate == candidate
    with pytest.raises(ValueError, match="^builder_candidate_receipt_mismatch$"):
        replace(packet, registration_digest="f" * 64).verify(key)

    for mutation in (
        {"candidate_tree": "4" * 40},
        {"diff_artifact_digest": "5" * 64},
        {"builder_request_digest": "6" * 64},
    ):
        with pytest.raises(ValueError, match="^builder_candidate_receipt_mismatch$"):
            replace(packet, **mutation).verify(key)


def test_candidate_packet_rejects_candidate_diff_artifact_identity_mismatch() -> None:
    key = b"k" * 32
    registration = _register()
    receipt = _receipt()
    envelope = _evidence("SignedAttemptReceipt").sign(receipt, key)
    candidate = replace(_candidate(registration), changed_path_count=1)
    packet = _evidence("ProtectedCandidatePacket")(
        schema_version=1,
        builder_request_digest=receipt.builder_request_digest,
        registration_digest=registration.digest,
        parent_commit=registration.parent_commit,
        candidate_tree=receipt.postpatch_tree,
        diff_artifact_digest=receipt.diff_artifact_digest,
        candidate=candidate,
        attempt_receipts=(envelope,),
    )

    with pytest.raises(ValueError, match="^builder_candidate_receipt_mismatch$"):
        packet.verify(key)


def test_packet_rejects_receipt_sequence_with_a_tree_gap() -> None:
    key = b"k" * 32
    registration = _register()
    first = _receipt()
    second = replace(
        first,
        attempt=2,
        action_digest="c" * 64,
        patch_digest="d" * 64,
        prepatch_tree="4" * 40,
        postpatch_tree="5" * 40,
        finding_digest="e" * 64,
    )
    candidate = replace(_candidate(registration), changed_path_count=1)
    packet = _evidence("ProtectedCandidatePacket")(
        schema_version=1,
        builder_request_digest="9" * 64,
        registration_digest=registration.digest,
        parent_commit=registration.parent_commit,
        candidate_tree=second.postpatch_tree,
        diff_artifact_digest=second.patch_digest,
        candidate=candidate,
        attempt_receipts=(
            _evidence("SignedAttemptReceipt").sign(first, key),
            _evidence("SignedAttemptReceipt").sign(second, key),
        ),
    )

    with pytest.raises(ValueError, match="^builder_candidate_receipt_mismatch$"):
        packet.verify(key)
