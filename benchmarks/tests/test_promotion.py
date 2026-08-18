from __future__ import annotations

import base64
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from carl_bench.canonical import canonical_json_bytes
from carl_bench.promotion import (
    PromotionContractError,
    PromotionExpectation,
    ProtectedValidationReceipt,
    SignedProtectedValidation,
    verify_protected_validation,
)


def receipt() -> ProtectedValidationReceipt:
    return ProtectedValidationReceipt(
        schema_version=1,
        validation_id="validation-exp-001-1",
        experiment_id="exp-001",
        manifest_digest="1" * 64,
        policy_digest="2" * 64,
        parent_commit="3" * 40,
        candidate_commit="4" * 40,
        candidate_tree="5" * 40,
        executable_digest="6" * 64,
        adapter_digest="7" * 64,
        task_set_digest="8" * 64,
        metric_pack_digest="9" * 64,
        environment_digest="a" * 64,
        model="gpt-5.6",
        effort="high",
        deterministic_checks_digest="b" * 64,
        repository_tests_digest="c" * 64,
        paired_score_delta_basis_points=420,
        paired_confidence_lower_basis_points=210,
        guard_delta_basis_points=-25,
        workflow_passed=True,
        safety_passed=True,
        flake_rate_basis_points=40,
        invalid_run_count=1,
        cost_microdollars=12_500_000,
        latency_ms=83_000,
        holdout_aggregate_basis_points=360,
        holdout_leakage_detected=False,
        proposal_review_digest="d" * 64,
        build_review_digest="e" * 64,
        security_review_digest="f" * 64,
        created_at="2026-08-18T12:00:00Z",
        expires_at="2026-08-18T18:00:00Z",
        decision="pass",
    )


def expectation() -> PromotionExpectation:
    value = receipt()
    return PromotionExpectation(
        experiment_id=value.experiment_id,
        manifest_digest=value.manifest_digest,
        policy_digest=value.policy_digest,
        parent_commit=value.parent_commit,
        candidate_commit=value.candidate_commit,
        candidate_tree=value.candidate_tree,
        executable_digest=value.executable_digest,
        adapter_digest=value.adapter_digest,
        task_set_digest=value.task_set_digest,
        metric_pack_digest=value.metric_pack_digest,
        model=value.model,
        effort=value.effort,
        environment_digest=value.environment_digest,
    )


def signed(value: ProtectedValidationReceipt) -> tuple[SignedProtectedValidation, bytes]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    signature = private_key.sign(canonical_json_bytes(value.to_canonical_dict()))
    return (
        SignedProtectedValidation(
            receipt=value,
            key_id="carl-protected-validator-2026-01",
            signature_base64=base64.b64encode(signature).decode("ascii"),
        ),
        public_key,
    )


def test_valid_signature_and_exact_identity_authorize_the_bound_candidate() -> None:
    envelope, public_key = signed(receipt())

    verified = verify_protected_validation(
        envelope,
        public_key_pem=public_key,
        expected=expectation(),
        now=datetime(2026, 8, 18, 13, tzinfo=UTC),
    )

    assert verified.receipt_digest == receipt().digest
    assert verified.validation_id == "validation-exp-001-1"
    assert verified.candidate_commit == "4" * 40


def test_forged_signature_is_rejected() -> None:
    envelope, _ = signed(receipt())
    other_key = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with pytest.raises(PromotionContractError, match="protected_signature_invalid"):
        verify_protected_validation(
            envelope,
            public_key_pem=other_key,
            expected=expectation(),
            now=datetime(2026, 8, 18, 13, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("parent_commit", "0" * 40, "protected_parent_mismatch"),
        ("candidate_commit", "0" * 40, "protected_candidate_mismatch"),
        ("policy_digest", "0" * 64, "protected_policy_mismatch"),
        ("model", "different-model", "protected_model_mismatch"),
        ("environment_digest", "0" * 64, "protected_environment_mismatch"),
    ],
)
def test_identity_drift_requires_fresh_protected_evidence(
    field: str, value: str, error: str
) -> None:
    envelope, public_key = signed(receipt())
    expected = replace(expectation(), **{field: value})

    with pytest.raises(PromotionContractError, match=error):
        verify_protected_validation(
            envelope,
            public_key_pem=public_key,
            expected=expected,
            now=datetime(2026, 8, 18, 13, tzinfo=UTC),
        )


def test_expired_receipt_fails_closed() -> None:
    envelope, public_key = signed(receipt())

    with pytest.raises(PromotionContractError, match="protected_receipt_expired"):
        verify_protected_validation(
            envelope,
            public_key_pem=public_key,
            expected=expectation(),
            now=datetime(2026, 8, 18, 18, 0, 1, tzinfo=UTC),
        )


def test_future_created_receipt_fails_closed() -> None:
    future = replace(
        receipt(),
        created_at="2026-08-18T14:00:00Z",
        expires_at="2026-08-18T20:00:00Z",
    )
    envelope, public_key = signed(future)

    with pytest.raises(PromotionContractError, match="protected_receipt_not_yet_valid"):
        verify_protected_validation(
            envelope,
            public_key_pem=public_key,
            expected=expectation(),
            now=datetime(2026, 8, 18, 13, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"decision": "fail"}, "protected_validation_not_passed"),
        ({"holdout_leakage_detected": True}, "protected_holdout_leakage"),
        ({"workflow_passed": False}, "protected_workflow_failed"),
        ({"safety_passed": False}, "protected_safety_failed"),
    ],
)
def test_failed_protected_gates_cannot_be_promoted(
    change: dict[str, object], error: str
) -> None:
    changed = replace(receipt(), **change)
    envelope, public_key = signed(changed)

    with pytest.raises(PromotionContractError, match=error):
        verify_protected_validation(
            envelope,
            public_key_pem=public_key,
            expected=expectation(),
            now=datetime(2026, 8, 18, 13, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/ci.yml",
        "benchmarks/pyproject.toml",
        "benchmarks/src/carl_bench/experiment.py",
        "benchmarks/uv.lock",
        "Cargo.lock",
        "Cargo.toml",
        "docs/benchmarks.md",
        "docs/superpowers/specs/2026-08-10-codex-carl-improvement-factory-design.md",
        "benchmarks/src/carl_bench/promotion.py",
        "SECURITY.md",
        "benchmarks/tasks/protected/task.toml",
        "scripts/benchmark-smoke.sh",
    ],
)
def test_ordinary_candidate_cannot_modify_constitutional_surfaces(path: str) -> None:
    envelope, public_key = signed(receipt())

    with pytest.raises(PromotionContractError, match="constitutional_change_requires_owner"):
        verify_protected_validation(
            envelope,
            public_key_pem=public_key,
            expected=expectation(),
            now=datetime(2026, 8, 18, 13, tzinfo=UTC),
            changed_paths=(path,),
        )


def test_ordinary_product_source_is_not_misclassified_as_constitutional() -> None:
    envelope, public_key = signed(receipt())

    verified = verify_protected_validation(
        envelope,
        public_key_pem=public_key,
        expected=expectation(),
        now=datetime(2026, 8, 18, 13, tzinfo=UTC),
        changed_paths=("src/runtime/task.rs",),
    )

    assert verified.candidate_commit == "4" * 40
