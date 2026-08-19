from __future__ import annotations

import base64
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from carl_bench.candidate_evidence import capability_report_from_public
from carl_bench.canonical import canonical_json_bytes
from carl_bench.capability_validation import (
    CapabilityClaim,
    CapabilityValidationReport,
    TaskOutcome,
    TransferCheck,
    evaluate_capability_validation,
)
from carl_bench.promotion import (
    PromotionContractError,
    PromotionExpectation,
    ProtectedValidationReceipt,
    SignedProtectedValidation,
    verify_protected_validation,
)


def transfer_check(
    check_id: str = "held-out-transfer",
    task_id: str = "held-out-task",
    *,
    check_type: str = "held_out",
    minimum_candidate_basis_points: int = 5_000,
) -> TransferCheck:
    return TransferCheck(
        check_id=check_id,
        task_id=task_id,
        check_type=check_type,
        evaluator_digest="a" * 64,
        minimum_candidate_basis_points=minimum_candidate_basis_points,
    )


def claim(*, claim_type: str = "capability") -> CapabilityClaim:
    return CapabilityClaim(
        claim_id="claim-001",
        claim_type=claim_type,
        behavior="Carl completes repository changes without narrowing supported inputs.",
        affected_task_ids=("primary-task",),
        guard_task_ids=("guard-task",),
        transfer_checks=(
            transfer_check(
                "fixture-probe",
                "fixture-probe-task",
                check_type="fixture_probe",
                minimum_candidate_basis_points=10_000,
            ),
            transfer_check(),
        ),
    )


def outcome(
    task_id: str,
    score_basis_points: int,
    *,
    evaluator_digest: str = "a" * 64,
    valid_trials: tuple[str, ...] = ("trial-1", "trial-2"),
    invalid_trials: tuple[str, ...] = ("trial-invalid",),
    passed_trials: tuple[str, ...] = ("trial-1",),
    failed_trials: tuple[str, ...] = ("trial-2",),
) -> TaskOutcome:
    return TaskOutcome(
        task_id=task_id,
        task_digest={
            "primary-task": "1" * 64,
            "guard-task": "2" * 64,
            "held-out-task": "3" * 64,
            "fixture-probe-task": "4" * 64,
        }[task_id],
        evaluator_digest=evaluator_digest,
        score_basis_points=score_basis_points,
        valid_trials=valid_trials,
        invalid_trials=invalid_trials,
        passed_trials=passed_trials,
        failed_trials=failed_trials,
    )


def baseline_outcomes() -> tuple[TaskOutcome, ...]:
    return (
        outcome("fixture-probe-task", 10_000),
        outcome("guard-task", 8_000),
        outcome("held-out-task", 6_000),
        outcome("primary-task", 6_000),
    )


def improved_outcomes() -> tuple[TaskOutcome, ...]:
    return (
        outcome("fixture-probe-task", 10_000),
        outcome("guard-task", 8_000),
        outcome("held-out-task", 6_500),
        outcome("primary-task", 7_000),
    )


def test_transferable_improvement_is_eligible_and_report_is_stable() -> None:
    report = evaluate_capability_validation(
        claim(), baseline_outcomes(), improved_outcomes(), ("src/runtime/task.rs",)
    )

    assert report.eligible
    assert report.reasons == ()
    assert report.transfer_gain_basis_points == 500
    assert report.affected_contract_cases_improved
    assert report.guards_non_inferior
    assert report.baseline_outcomes == baseline_outcomes()
    assert report.candidate_outcomes == improved_outcomes()
    assert report.transfer_checks == claim().transfer_checks
    assert report.to_canonical_dict()["baseline_outcomes"][0]["invalid_trials"] == [
        "trial-invalid"
    ]
    assert len(report.digest) == 64
    assert capability_report_from_public(report.to_canonical_dict()) == report


@pytest.mark.parametrize(
    "path",
    [
        "benchmarks/tasks/dev/foo/task.toml",
        "benchmarks/metric_packs/default.toml",
        "benchmarks/graders/repository.py",
        ".github/workflows/protected-validation.yml",
        "benchmarks/src/carl_bench/capability_validation.py",
        "benchmarks/src/carl_bench/promotion.py",
        "benchmarks/policies/promotion.toml",
        ".codex/automations/daily-builder/automation.toml",
    ],
)
def test_active_evaluator_changes_are_rejected(path: str) -> None:
    report = evaluate_capability_validation(
        claim(), baseline_outcomes(), improved_outcomes(), (path,)
    )

    assert "active_evaluator_modified" in report.reasons


def test_aggregate_gain_cannot_hide_one_task_regression() -> None:
    candidate = tuple(
        replace(item, score_basis_points=5_900)
        if item.task_id == "primary-task"
        else replace(item, score_basis_points=8_000)
        if item.task_id == "held-out-task"
        else item
        for item in improved_outcomes()
    )

    report = evaluate_capability_validation(claim(), baseline_outcomes(), candidate, ())

    assert "aggregate_hides_task_regression" in report.reasons


def test_public_score_only_gain_requires_held_out_transfer() -> None:
    candidate = tuple(
        replace(item, score_basis_points=6_000)
        if item.task_id == "held-out-task"
        else item
        for item in improved_outcomes()
    )

    report = evaluate_capability_validation(claim(), baseline_outcomes(), candidate, ())

    assert "transfer_gain_required" in report.reasons


def test_correctness_exception_cannot_hide_a_held_out_regression() -> None:
    candidate = tuple(
        replace(item, score_basis_points=5_999)
        if item.task_id == "held-out-task"
        else item
        for item in improved_outcomes()
    )

    report = evaluate_capability_validation(
        claim(claim_type="correctness"), baseline_outcomes(), candidate, ()
    )

    assert "aggregate_hides_task_regression" in report.reasons


def test_dropping_a_valid_failure_is_selective_retry() -> None:
    candidate = tuple(
        replace(
            item,
            valid_trials=("trial-1",),
            passed_trials=("trial-1",),
            failed_trials=(),
        )
        if item.task_id == "primary-task"
        else item
        for item in improved_outcomes()
    )

    report = evaluate_capability_validation(claim(), baseline_outcomes(), candidate, ())

    assert "selective_retry_detected" in report.reasons


def test_failed_fixture_probe_detects_hard_coding() -> None:
    candidate = tuple(
        replace(item, score_basis_points=0)
        if item.task_id == "fixture-probe-task"
        else item
        for item in improved_outcomes()
    )

    report = evaluate_capability_validation(claim(), baseline_outcomes(), candidate, ())

    assert "hard_coded_fixture_detected" in report.reasons


def test_missing_transfer_check_and_changed_identity_fail_closed() -> None:
    no_transfer = replace(claim(), transfer_checks=(claim().transfer_checks[0],))
    changed_identity = tuple(
        replace(item, evaluator_digest="b" * 64)
        if item.task_id == "held-out-task"
        else item
        for item in improved_outcomes()
    )

    no_transfer_report = evaluate_capability_validation(
        no_transfer, baseline_outcomes(), improved_outcomes(), ()
    )
    identity_report = evaluate_capability_validation(
        claim(), baseline_outcomes(), changed_identity, ()
    )

    assert "held_out_transfer_required" in no_transfer_report.reasons
    assert "evaluation_identity_changed" in identity_report.reasons


def test_incomplete_trial_accounting_and_guard_regression_fail_closed() -> None:
    candidate = tuple(
        replace(item, invalid_trials=())
        if item.task_id == "primary-task"
        else replace(item, score_basis_points=7_999)
        if item.task_id == "guard-task"
        else item
        for item in improved_outcomes()
    )

    report = evaluate_capability_validation(claim(), baseline_outcomes(), candidate, ())

    assert "incomplete_trial_accounting" in report.reasons
    assert "guard_task_regression" in report.reasons
    assert report.reasons == tuple(sorted(report.reasons))


def protected_receipt(**changes: object) -> ProtectedValidationReceipt:
    values: dict[str, object] = {
        "schema_version": 2,
        "validation_id": "validation-exp-001-1",
        "experiment_id": "exp-001",
        "manifest_digest": "1" * 64,
        "policy_digest": "2" * 64,
        "parent_commit": "3" * 40,
        "candidate_commit": "4" * 40,
        "candidate_tree": "5" * 40,
        "executable_digest": "6" * 64,
        "adapter_digest": "7" * 64,
        "task_set_digest": "8" * 64,
        "metric_pack_digest": "9" * 64,
        "environment_digest": "a" * 64,
        "model": "gpt-5.6",
        "effort": "high",
        "deterministic_checks_digest": "b" * 64,
        "repository_tests_digest": "c" * 64,
        "paired_score_delta_basis_points": 420,
        "paired_confidence_lower_basis_points": 210,
        "guard_delta_basis_points": 0,
        "workflow_passed": True,
        "safety_passed": True,
        "flake_rate_basis_points": 40,
        "invalid_run_count": 1,
        "cost_microdollars": 12_500_000,
        "latency_ms": 83_000,
        "holdout_aggregate_basis_points": 360,
        "holdout_leakage_detected": False,
        "proposal_review_digest": "d" * 64,
        "build_review_digest": "e" * 64,
        "security_review_digest": "f" * 64,
        "created_at": "2026-08-18T12:00:00Z",
        "expires_at": "2026-08-18T18:00:00Z",
        "decision": "pass",
        "capability_report_digest": "0" * 64,
        "transfer_gain_basis_points": 500,
    }
    values.update(changes)
    return ProtectedValidationReceipt(**values)  # type: ignore[arg-type]


def promotion_expectation(**changes: object) -> PromotionExpectation:
    value = protected_receipt()
    values: dict[str, object] = {
        "experiment_id": value.experiment_id,
        "manifest_digest": value.manifest_digest,
        "policy_digest": value.policy_digest,
        "parent_commit": value.parent_commit,
        "candidate_commit": value.candidate_commit,
        "candidate_tree": value.candidate_tree,
        "executable_digest": value.executable_digest,
        "adapter_digest": value.adapter_digest,
        "task_set_digest": value.task_set_digest,
        "metric_pack_digest": value.metric_pack_digest,
        "model": value.model,
        "effort": value.effort,
        "environment_digest": value.environment_digest,
        "capability_report_digest": value.capability_report_digest,
        "transfer_gain_basis_points": value.transfer_gain_basis_points,
        "capability_claim_type": "capability",
        "affected_contract_cases_improved": True,
        "capability_guards_non_inferior": True,
    }
    values.update(changes)
    return PromotionExpectation(**values)  # type: ignore[arg-type]


def signed(
    value: ProtectedValidationReceipt,
) -> tuple[SignedProtectedValidation, bytes]:
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


def verify_receipt(
    value: ProtectedValidationReceipt,
    expected: PromotionExpectation,
) -> None:
    envelope, public_key = signed(value)
    verify_protected_validation(
        envelope,
        public_key_pem=public_key,
        expected=expected,
        now=datetime(2026, 8, 18, 13, tzinfo=UTC),
    )


def test_schema_v2_binds_positive_transfer_evidence() -> None:
    verify_receipt(protected_receipt(), promotion_expectation())


@pytest.mark.parametrize(
    ("receipt_changes", "expectation_changes", "error"),
    [
        (
            {"capability_report_digest": "f" * 64},
            {},
            "protected_capability_report_mismatch",
        ),
        (
            {"transfer_gain_basis_points": 400},
            {},
            "protected_transfer_gain_mismatch",
        ),
        (
            {"transfer_gain_basis_points": 0},
            {"transfer_gain_basis_points": 0},
            "protected_transfer_gain_required",
        ),
    ],
)
def test_schema_v2_rejects_missing_mismatched_or_non_positive_transfer_evidence(
    receipt_changes: dict[str, object],
    expectation_changes: dict[str, object],
    error: str,
) -> None:
    with pytest.raises(PromotionContractError, match=error):
        verify_receipt(
            protected_receipt(**receipt_changes),
            promotion_expectation(**expectation_changes),
        )


@pytest.mark.parametrize("claim_type", ["correctness", "compatibility"])
def test_schema_v2_allows_preregistered_contract_exception(claim_type: str) -> None:
    verify_receipt(
        protected_receipt(transfer_gain_basis_points=0),
        promotion_expectation(
            transfer_gain_basis_points=0,
            capability_claim_type=claim_type,
            affected_contract_cases_improved=True,
            capability_guards_non_inferior=True,
        ),
    )


def test_schema_v2_contract_exception_requires_all_contract_and_guard_evidence() -> None:
    with pytest.raises(PromotionContractError, match="protected_transfer_gain_required"):
        verify_receipt(
            protected_receipt(transfer_gain_basis_points=0),
            promotion_expectation(
                transfer_gain_basis_points=0,
                capability_claim_type="correctness",
                affected_contract_cases_improved=False,
                capability_guards_non_inferior=True,
            ),
        )


def test_schema_v1_canonical_payload_and_verification_remain_legacy_compatible() -> None:
    legacy = protected_receipt(
        schema_version=1,
        capability_report_digest=None,
        transfer_gain_basis_points=None,
    )
    public = legacy.to_canonical_dict()

    assert "capability_report_digest" not in public
    assert "transfer_gain_basis_points" not in public
    verify_receipt(
        legacy,
        replace(
            promotion_expectation(),
            capability_report_digest=None,
            transfer_gain_basis_points=None,
            capability_claim_type=None,
            affected_contract_cases_improved=None,
            capability_guards_non_inferior=None,
        ),
    )


def test_new_expectation_rejects_legacy_receipt_without_capability_evidence() -> None:
    legacy = protected_receipt(
        schema_version=1,
        capability_report_digest=None,
        transfer_gain_basis_points=None,
    )

    with pytest.raises(PromotionContractError, match="protected_capability_report_missing"):
        verify_receipt(legacy, promotion_expectation())


def test_capability_records_are_frozen_and_require_sorted_exact_tuples() -> None:
    with pytest.raises(ValueError, match="capability_tuple_order_invalid"):
        replace(claim(), affected_task_ids=("z-task", "a-task"))
    with pytest.raises(ValueError, match="capability_tuple_order_invalid"):
        replace(outcome("primary-task", 6_000), valid_trials=("trial-2", "trial-1"))

    with pytest.raises(AttributeError):
        claim().claim_type = "correctness"  # type: ignore[misc]


def test_capability_report_public_parser_rejects_extra_fields() -> None:
    report = CapabilityValidationReport(
        schema_version=1,
        claim_id="claim-001",
        claim_type="capability",
        eligible=True,
        reasons=(),
        transfer_gain_basis_points=500,
        affected_contract_cases_improved=True,
        guards_non_inferior=True,
    )
    public = report.to_canonical_dict() | {"raw_holdout": "must-not-leak"}

    with pytest.raises(ValueError, match="capability_report_keys_invalid"):
        capability_report_from_public(public)
