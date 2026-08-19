from __future__ import annotations

import base64
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_experiment import manifest as base_manifest

from carl_bench.autonomy import (
    AutonomyProjection,
    ExperimentalPublication,
    PromotionRecord,
    ProtectedValidation,
    RetryRecord,
    RevertRecord,
    SoakObservation,
)
from carl_bench.autonomy_controller import (
    ControllerSnapshot,
    InfrastructureFailure,
    SoakResult,
    next_controller_action,
)
from carl_bench.canonical import canonical_json_bytes
from carl_bench.capability_validation import CapabilityValidationReport
from carl_bench.experiment import EventType, ExperimentEvent
from carl_bench.github_promotion import (
    CheckRun,
    PromotionRequest,
    PromotionSnapshot,
    PullRequestSnapshot,
    RevertSnapshot,
)
from carl_bench.ledger import ExperimentLedger
from carl_bench.promotion import (
    PromotionContractError,
    PromotionExpectation,
    ProtectedValidationReceipt,
    SignedProtectedValidation,
)
from carl_bench.promotion_monitor import PromotionHealthSnapshot

NOW = datetime(2026, 8, 19, 12, tzinfo=UTC)
PARENT = "1" * 40
CANDIDATE = "2" * 40
CANDIDATE_TREE = "3" * 40
MERGE = "4" * 40
RESTORED_TREE = "5" * 40
REVERT_CANDIDATE = "6" * 40
REVERT_MERGE = "7" * 40
MANIFEST = replace(
    base_manifest(),
    experiment_id="exp-001",
    parent_commit=PARENT,
)
MANIFEST_DIGEST = MANIFEST.digest
POLICY_DIGEST = "9" * 64
PACKET_DIGEST = "a" * 64
HEALTHY_DIGEST = "b" * 64
FAILURE_DIGEST = "c" * 64
REQUIRED_CHECKS = (
    "Benchmark contracts",
    "Quality",
    "Test (macos-latest)",
    "Test (ubuntu-latest)",
    "Test (windows-latest)",
)


def capability_report() -> CapabilityValidationReport:
    return CapabilityValidationReport(
        schema_version=1,
        claim_id="claim-001",
        claim_type="capability",
        eligible=True,
        reasons=(),
        transfer_gain_basis_points=500,
        affected_contract_cases_improved=True,
        guards_non_inferior=True,
    )


def receipt(report: CapabilityValidationReport) -> ProtectedValidationReceipt:
    return ProtectedValidationReceipt(
        schema_version=2,
        validation_id="validation-exp-001-1",
        experiment_id="exp-001",
        manifest_digest=MANIFEST_DIGEST,
        policy_digest=POLICY_DIGEST,
        parent_commit=PARENT,
        candidate_commit=CANDIDATE,
        candidate_tree=CANDIDATE_TREE,
        executable_digest="d" * 64,
        adapter_digest="e" * 64,
        task_set_digest="f" * 64,
        metric_pack_digest="0" * 64,
        environment_digest="1" * 64,
        model="gpt-5.6",
        effort="high",
        deterministic_checks_digest="2" * 64,
        repository_tests_digest="3" * 64,
        paired_score_delta_basis_points=500,
        paired_confidence_lower_basis_points=200,
        guard_delta_basis_points=0,
        workflow_passed=True,
        safety_passed=True,
        flake_rate_basis_points=0,
        invalid_run_count=0,
        cost_microdollars=1_000_000,
        latency_ms=60_000,
        holdout_aggregate_basis_points=500,
        holdout_leakage_detected=False,
        proposal_review_digest="4" * 64,
        build_review_digest="5" * 64,
        security_review_digest="6" * 64,
        created_at="2026-08-19T10:00:00Z",
        expires_at="2026-08-19T14:00:00Z",
        decision="pass",
        capability_report_digest=report.digest,
        transfer_gain_basis_points=report.transfer_gain_basis_points,
    )


def signed_receipt(
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
            key_id="protected-validator-2026-01",
            signature_base64=base64.b64encode(signature).decode("ascii"),
        ),
        public_key,
    )


def expectation() -> PromotionExpectation:
    value = receipt(capability_report())
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


def promotion_request(receipt_digest: str) -> PromotionRequest:
    return PromotionRequest(
        promotion_id="promotion-exp-001-1",
        experiment_id="exp-001",
        repository="StephenBickel/carl-agent",
        base_branch="main",
        head_branch="experimental/exp-001",
        parent_commit=PARENT,
        candidate_commit=CANDIDATE,
        candidate_tree=CANDIDATE_TREE,
        protected_receipt_digest=receipt_digest,
    )


def pull_request(**changes: object) -> PullRequestSnapshot:
    values: dict[str, object] = {
        "number": 81,
        "url": "https://github.com/StephenBickel/carl-agent/pull/81",
        "state": "OPEN",
        "is_draft": True,
        "base_branch": "main",
        "head_branch": "experimental/exp-001",
        "head_commit": CANDIDATE,
        "head_tree": CANDIDATE_TREE,
        "merge_state": "CLEAN",
        "checks": tuple(
            CheckRun(name=name, conclusion="SUCCESS", app_id=15368)
            for name in REQUIRED_CHECKS
        ),
        "merge_commit": None,
        "merge_tree": None,
    }
    values.update(changes)
    return PullRequestSnapshot(**values)  # type: ignore[arg-type]


def autonomy_projection(
    *,
    validation: ProtectedValidation | None = None,
    promotion: PromotionRecord | None = None,
    observations: tuple[SoakObservation, ...] = (),
    revert: RevertRecord | None = None,
) -> AutonomyProjection:
    return AutonomyProjection(
        experiment_id="exp-001",
        manifest_digest=MANIFEST_DIGEST,
        retry=None,
        experimental_publication=ExperimentalPublication(
            branch="experimental/exp-001",
            commit=CANDIDATE,
            tree=CANDIDATE_TREE,
            candidate_packet_digest=PACKET_DIGEST,
        ),
        protected_validation=validation,
        promotion=promotion,
        soak_observations=observations,
        revert=revert,
    )


def controller_snapshot() -> ControllerSnapshot:
    report = capability_report()
    protected_receipt = receipt(report)
    envelope, public_key = signed_receipt(protected_receipt)
    request = promotion_request(protected_receipt.digest)
    return ControllerSnapshot(
        autonomy=autonomy_projection(),
        capability_report=report,
        protected_validation=envelope,
        protected_public_key_pem=public_key,
        promotion_expectation=expectation(),
        promotion_request=request,
        promotion_snapshot=PromotionSnapshot(
            production_commit=PARENT,
            active_promotion_id=request.promotion_id,
            pull_request=None,
        ),
        required_checks=REQUIRED_CHECKS,
    )


def test_restart_safe_healthy_and_exact_revert_lifecycles() -> None:
    snapshot = controller_snapshot()

    validation = next_controller_action(snapshot, NOW)
    assert validation.action == "record_validation"
    assert validation.event is not None
    assert validation.capability_report_digest == snapshot.capability_report.digest
    assert validation.candidate_commit == CANDIDATE

    validated_projection = replace(
        snapshot.autonomy,
        protected_validation=ProtectedValidation(
            candidate_commit=CANDIDATE,
            candidate_tree=CANDIDATE_TREE,
            receipt_digest=snapshot.promotion_request.protected_receipt_digest,
        ),
    )
    snapshot = replace(snapshot, autonomy=validated_projection)
    create_pr = next_controller_action(snapshot, NOW)
    assert create_pr.action == "create_pr"
    assert create_pr.event is None

    snapshot = replace(
        snapshot,
        promotion_snapshot=replace(snapshot.promotion_snapshot, pull_request=pull_request()),
    )
    assert next_controller_action(snapshot, NOW).action == "mark_ready"

    ready = pull_request(is_draft=False)
    snapshot = replace(
        snapshot,
        promotion_snapshot=replace(snapshot.promotion_snapshot, pull_request=ready),
    )
    assert next_controller_action(snapshot, NOW).action == "enable_auto_merge"

    auto_merge = replace(ready, auto_merge_enabled=True)
    snapshot = replace(
        snapshot,
        promotion_snapshot=replace(snapshot.promotion_snapshot, pull_request=auto_merge),
    )
    assert next_controller_action(snapshot, NOW).action == "idle"

    merged_pr = replace(
        auto_merge,
        state="MERGED",
        merge_commit=MERGE,
        merge_tree=CANDIDATE_TREE,
    )
    snapshot = replace(
        snapshot,
        promotion_snapshot=replace(
            snapshot.promotion_snapshot,
            production_commit=MERGE,
            pull_request=merged_pr,
        ),
    )
    record_merge = next_controller_action(snapshot, NOW)
    assert record_merge.action == "record_merge"
    assert record_merge.merge_commit == MERGE
    assert record_merge.event is not None

    promotion = PromotionRecord(
        merge_commit=MERGE,
        merge_tree=CANDIDATE_TREE,
        merged_at="2026-08-19T12:00:00Z",
    )
    snapshot = replace(
        snapshot,
        autonomy=replace(snapshot.autonomy, promotion=promotion),
        soak_result=SoakResult(
            merge_commit=MERGE,
            observed_at="2026-08-20T13:00:00Z",
            healthy=True,
            evidence_digest=HEALTHY_DIGEST,
        ),
    )
    observe = next_controller_action(snapshot, datetime(2026, 8, 20, 13, tzinfo=UTC))
    assert observe.action == "observe_soak"
    assert observe.merge_commit == MERGE
    assert observe.event is not None

    healthy = SoakObservation(
        merge_commit=MERGE,
        observed_at="2026-08-20T13:00:00Z",
        healthy=True,
        evidence_digest=HEALTHY_DIGEST,
    )
    snapshot = replace(
        snapshot,
        autonomy=replace(snapshot.autonomy, soak_observations=(healthy,)),
        soak_result=None,
    )
    accepted = next_controller_action(snapshot, datetime(2026, 8, 20, 13, tzinfo=UTC))
    assert accepted.action == "accept"
    assert accepted.merge_commit == MERGE
    assert next_controller_action(replace(snapshot, accepted=True), NOW).action == "idle"

    failed_result = SoakResult(
        merge_commit=MERGE,
        observed_at="2026-08-19T13:00:00Z",
        healthy=False,
        evidence_digest=FAILURE_DIGEST,
    )
    failed = replace(snapshot, autonomy=replace(snapshot.autonomy, soak_observations=()))
    failed = replace(failed, soak_result=failed_result)
    failure_observation = next_controller_action(
        failed, datetime(2026, 8, 19, 13, tzinfo=UTC)
    )
    assert failure_observation.action == "observe_soak"

    hard_failure = SoakObservation(
        merge_commit=MERGE,
        observed_at=failed_result.observed_at,
        healthy=False,
        evidence_digest=FAILURE_DIGEST,
    )
    revert_snapshot = RevertSnapshot(
        promotion_id=failed.promotion_request.promotion_id,
        merge_commit=MERGE,
        hard_failure=True,
        revert_pull_request=None,
        revert_candidate_commit=None,
        expected_restored_tree=RESTORED_TREE,
        production_commit=MERGE,
        production_tree=CANDIDATE_TREE,
        reverted_commit=None,
    )
    failed = replace(
        failed,
        autonomy=replace(failed.autonomy, soak_observations=(hard_failure,)),
        soak_result=None,
        revert_snapshot=revert_snapshot,
    )
    create_revert = next_controller_action(failed, datetime(2026, 8, 19, 13, tzinfo=UTC))
    assert create_revert.action == "create_revert_pr"
    assert create_revert.restored_tree == RESTORED_TREE

    revert_pr = pull_request(
        number=82,
        url="https://github.com/StephenBickel/carl-agent/pull/82",
        is_draft=False,
        head_branch="revert/promotion-exp-001-1",
        head_commit=REVERT_CANDIDATE,
        head_tree=RESTORED_TREE,
    )
    failed = replace(
        failed,
        revert_snapshot=replace(
            revert_snapshot,
            revert_pull_request=revert_pr,
            revert_candidate_commit=REVERT_CANDIDATE,
        ),
    )
    assert next_controller_action(failed, NOW).action == "idle"

    reverted_pr = replace(
        revert_pr,
        state="MERGED",
        merge_commit=REVERT_MERGE,
        merge_tree=RESTORED_TREE,
    )
    failed = replace(
        failed,
        revert_snapshot=replace(
            failed.revert_snapshot,
            revert_pull_request=reverted_pr,
            production_commit=REVERT_MERGE,
            production_tree=RESTORED_TREE,
            reverted_commit=REVERT_MERGE,
        ),
    )
    reverted = next_controller_action(failed, NOW)
    assert reverted.action == "record_reverted"
    assert reverted.event is not None
    assert reverted.event.occurred_at == "2026-08-19T12:00:00Z"

    failed = replace(
        failed,
        autonomy=replace(
            failed.autonomy,
            revert=RevertRecord(
                merge_commit=MERGE,
                hard_failure_digest=FAILURE_DIGEST,
                restored_tree=RESTORED_TREE,
                reverted_at="2026-08-19T14:00:00Z",
            ),
        ),
    )
    assert next_controller_action(failed, NOW).action == "idle"


def test_validation_disposition_binds_the_exact_eligible_contract_exception() -> None:
    report = replace(
        capability_report(),
        claim_type="correctness",
        transfer_gain_basis_points=0,
    )
    protected_receipt = receipt(report)
    envelope, public_key = signed_receipt(protected_receipt)
    snapshot = replace(
        controller_snapshot(),
        capability_report=report,
        protected_validation=envelope,
        protected_public_key_pem=public_key,
        promotion_request=promotion_request(protected_receipt.digest),
    )

    action = next_controller_action(snapshot, NOW)

    assert action.action == "record_validation"
    assert action.capability_report_digest == report.digest
    assert action.capability_claim_type == "correctness"
    assert action.transfer_gain_basis_points == 0
    assert action.affected_contract_cases_improved is True
    assert action.capability_guards_non_inferior is True


def test_infrastructure_failure_allows_three_changed_retries_then_freezes() -> None:
    snapshot = controller_snapshot()
    changed_actions = (
        "refetch protected artifacts",
        "rerun on a fresh hosted runner",
        "rotate to the fallback runner pool",
    )

    for attempt, changed_action in enumerate(changed_actions, start=1):
        failure = InfrastructureFailure(
            failed_stage_attempt_id="protected-validation-run-1",
            failure_class="cloud_execution_unavailable",
            changed_action=changed_action,
        )
        action = next_controller_action(
            replace(snapshot, infrastructure_failure=failure), NOW
        )

        assert action.action == "schedule_retry"
        assert action.event is not None
        assert action.event.payload["attempt"] == attempt
        assert action.event.payload["changed_action"] == changed_action
        snapshot = replace(
            snapshot,
            autonomy=replace(
                snapshot.autonomy,
                retry=RetryRecord(**action.event.payload),
            ),
        )

    exhausted = next_controller_action(
        replace(
            snapshot,
            infrastructure_failure=InfrastructureFailure(
                failed_stage_attempt_id="protected-validation-run-1",
                failure_class="cloud_execution_unavailable",
                changed_action="dispatch to another clean runner",
            ),
        ),
        NOW,
    )

    assert exhausted.action == "idle"
    assert exhausted.reason == "infrastructure_retry_exhausted"


def test_expired_promotion_lease_resumes_only_after_stale_reconciliation() -> None:
    health = PromotionHealthSnapshot(
        automations=(),
        lease_expires_at="2026-08-19T11:00:00Z",
        lease_reconciled=False,
        promotion_in_progress=True,
        complete_receipts=True,
        soaking_since=None,
        last_soak_observation_at=None,
        hard_failure_at=None,
        revert_started_at=None,
    )
    snapshot = replace(controller_snapshot(), promotion_health=health)

    frozen = next_controller_action(snapshot, NOW)

    assert frozen.action == "idle"
    assert frozen.reason == "mutable_lease_expired_unreconciled"
    resumed = next_controller_action(
        replace(snapshot, promotion_health=replace(health, lease_reconciled=True)), NOW
    )
    assert resumed.action == "record_validation"


@pytest.mark.parametrize(
    ("promotion_changes", "reason"),
    [
        ({"production_commit": "0" * 40}, "production_parent_changed"),
        ({"active_promotion_id": None}, "promotion_lease_required"),
        ({"active_promotion_id": "promotion-other-1"}, "promotion_lease_conflict"),
    ],
)
def test_promotion_cancellation_preserves_reconciler_safety_identity(
    promotion_changes: dict[str, object], reason: str
) -> None:
    snapshot = controller_snapshot()
    snapshot = replace(
        snapshot,
        autonomy=replace(
            snapshot.autonomy,
            protected_validation=ProtectedValidation(
                candidate_commit=CANDIDATE,
                candidate_tree=CANDIDATE_TREE,
                receipt_digest=snapshot.promotion_request.protected_receipt_digest,
            ),
        ),
        promotion_snapshot=replace(snapshot.promotion_snapshot, **promotion_changes),
    )

    action = next_controller_action(snapshot, NOW)

    assert action.action == "idle"
    assert action.reason == reason


def test_stale_soak_observation_requests_recovery_with_26_hour_finding() -> None:
    snapshot = controller_snapshot()
    snapshot = replace(
        snapshot,
        autonomy=replace(
            snapshot.autonomy,
            protected_validation=ProtectedValidation(
                candidate_commit=CANDIDATE,
                candidate_tree=CANDIDATE_TREE,
                receipt_digest=snapshot.promotion_request.protected_receipt_digest,
            ),
            promotion=PromotionRecord(
                merge_commit=MERGE,
                merge_tree=CANDIDATE_TREE,
                merged_at="2026-08-18T09:00:00Z",
            ),
        ),
        promotion_snapshot=replace(snapshot.promotion_snapshot, production_commit=MERGE),
        promotion_health=PromotionHealthSnapshot(
            automations=(),
            lease_expires_at=None,
            lease_reconciled=True,
            promotion_in_progress=True,
            complete_receipts=True,
            soaking_since="2026-08-18T09:00:00Z",
            last_soak_observation_at="2026-08-18T09:30:00Z",
            hard_failure_at=None,
            revert_started_at=None,
        ),
    )

    action = next_controller_action(snapshot, NOW)

    assert action.action == "observe_soak"
    assert action.reason == "soak_observation_required"
    assert "soak_observation_stale" in action.health_findings


def test_overdue_hard_failure_keeps_exact_revert_identity_and_sla_finding() -> None:
    snapshot = controller_snapshot()
    failure = SoakObservation(
        merge_commit=MERGE,
        observed_at="2026-08-19T09:00:00Z",
        healthy=False,
        evidence_digest=FAILURE_DIGEST,
    )
    snapshot = replace(
        snapshot,
        autonomy=replace(
            snapshot.autonomy,
            protected_validation=ProtectedValidation(
                candidate_commit=CANDIDATE,
                candidate_tree=CANDIDATE_TREE,
                receipt_digest=snapshot.promotion_request.protected_receipt_digest,
            ),
            promotion=PromotionRecord(
                merge_commit=MERGE,
                merge_tree=CANDIDATE_TREE,
                merged_at="2026-08-19T08:00:00Z",
            ),
            soak_observations=(failure,),
        ),
        promotion_snapshot=replace(snapshot.promotion_snapshot, production_commit=MERGE),
        revert_snapshot=RevertSnapshot(
            promotion_id=snapshot.promotion_request.promotion_id,
            merge_commit=MERGE,
            hard_failure=True,
            revert_pull_request=None,
            revert_candidate_commit=None,
            expected_restored_tree=RESTORED_TREE,
            production_commit=MERGE,
            production_tree=CANDIDATE_TREE,
            reverted_commit=None,
        ),
        promotion_health=PromotionHealthSnapshot(
            automations=(),
            lease_expires_at=None,
            lease_reconciled=True,
            promotion_in_progress=True,
            complete_receipts=True,
            soaking_since="2026-08-19T08:00:00Z",
            last_soak_observation_at="2026-08-19T09:00:00Z",
            hard_failure_at="2026-08-19T09:00:00Z",
            revert_started_at=None,
        ),
    )

    action = next_controller_action(snapshot, NOW)

    assert action.action == "create_revert_pr"
    assert action.reason == "hard_soak_failure"
    assert action.merge_commit == MERGE
    assert action.restored_tree == RESTORED_TREE
    assert "rollback_start_sla_missed" in action.health_findings


def test_candidate_and_publication_without_protected_validation_never_promote() -> None:
    snapshot = replace(
        controller_snapshot(),
        protected_validation=None,
        protected_public_key_pem=None,
        promotion_expectation=None,
        promotion_request=None,
        promotion_snapshot=None,
    )

    action = next_controller_action(snapshot, NOW)

    assert action.action == "idle"
    assert action.reason == "protected_validation_required"


def test_ineligible_capability_report_is_rejected_before_signed_receipt_use() -> None:
    ineligible = replace(
        capability_report(),
        eligible=False,
        reasons=("transfer_gain_required",),
    )
    snapshot = replace(controller_snapshot(), capability_report=ineligible)

    with pytest.raises(PromotionContractError, match="capability_report_ineligible"):
        next_controller_action(snapshot, NOW)


def test_tampered_protected_receipt_signature_is_rejected() -> None:
    snapshot = controller_snapshot()
    tampered = replace(
        snapshot.protected_validation,
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )

    with pytest.raises(PromotionContractError, match="protected_signature_invalid"):
        next_controller_action(replace(snapshot, protected_validation=tampered), NOW)


def test_controller_event_uses_trusted_ledger_append_and_replays_idempotently(
    tmp_path: Path,
) -> None:
    ledger = ExperimentLedger(tmp_path / "controller.sqlite3")
    ledger.register_manifest(MANIFEST)
    publication = ExperimentEvent.create(
        experiment_id="exp-001",
        stage_attempt_id="experimental-publication-exp-001",
        event_type=EventType.EXPERIMENTAL_PUBLISHED,
        occurred_at="2026-08-19T11:00:00Z",
        payload={
            "branch": "experimental/exp-001",
            "candidate_packet_digest": PACKET_DIGEST,
            "commit": CANDIDATE,
            "tree": CANDIDATE_TREE,
        },
    )
    ledger.append(publication)
    snapshot = replace(controller_snapshot(), autonomy=ledger.autonomy_projection("exp-001"))
    action = next_controller_action(snapshot, NOW)

    first = action.append_event(ledger)
    duplicate = action.append_event(ledger)

    assert first is not None and first.appended is True
    assert duplicate is not None and duplicate.appended is False
    replayed = ledger.autonomy_projection("exp-001")
    assert replayed.protected_validation is not None
    assert replayed.protected_validation.receipt_digest == receipt(capability_report()).digest


def test_later_healthy_probe_cannot_mask_recorded_hard_failure() -> None:
    snapshot = controller_snapshot()
    failure = SoakObservation(
        merge_commit=MERGE,
        observed_at="2026-08-20T09:00:00Z",
        healthy=False,
        evidence_digest=FAILURE_DIGEST,
    )
    later_healthy = SoakObservation(
        merge_commit=MERGE,
        observed_at="2026-08-20T10:00:00Z",
        healthy=True,
        evidence_digest=HEALTHY_DIGEST,
    )
    snapshot = replace(
        snapshot,
        autonomy=replace(
            snapshot.autonomy,
            protected_validation=ProtectedValidation(
                candidate_commit=CANDIDATE,
                candidate_tree=CANDIDATE_TREE,
                receipt_digest=snapshot.promotion_request.protected_receipt_digest,
            ),
            promotion=PromotionRecord(
                merge_commit=MERGE,
                merge_tree=CANDIDATE_TREE,
                merged_at="2026-08-19T08:00:00Z",
            ),
            soak_observations=(failure, later_healthy),
        ),
        promotion_snapshot=replace(snapshot.promotion_snapshot, production_commit=MERGE),
        revert_snapshot=RevertSnapshot(
            promotion_id=snapshot.promotion_request.promotion_id,
            merge_commit=MERGE,
            hard_failure=True,
            revert_pull_request=None,
            revert_candidate_commit=None,
            expected_restored_tree=RESTORED_TREE,
            production_commit=MERGE,
            production_tree=CANDIDATE_TREE,
            reverted_commit=None,
        ),
    )

    action = next_controller_action(snapshot, datetime(2026, 8, 20, 10, tzinfo=UTC))

    assert action.action == "create_revert_pr"
    assert action.restored_tree == RESTORED_TREE


def test_protected_verification_receives_exact_changed_paths() -> None:
    snapshot = replace(
        controller_snapshot(),
        changed_paths=("benchmarks/src/carl_bench/promotion.py",),
    )

    with pytest.raises(
        PromotionContractError, match="constitutional_change_requires_owner"
    ):
        next_controller_action(snapshot, NOW)


def test_accepted_marker_without_bound_24_hour_soak_evidence_is_rejected() -> None:
    with pytest.raises(PromotionContractError, match="accepted_soak_evidence_required"):
        next_controller_action(replace(controller_snapshot(), accepted=True), NOW)


def test_different_eligible_report_cannot_reuse_an_exact_protected_receipt() -> None:
    snapshot = controller_snapshot()
    substituted_report = replace(snapshot.capability_report, claim_id="claim-substitute")

    with pytest.raises(
        PromotionContractError, match="protected_capability_report_mismatch"
    ):
        next_controller_action(
            replace(snapshot, capability_report=substituted_report), NOW
        )


def test_soak_rechecks_durable_validation_receipt_identity() -> None:
    snapshot = controller_snapshot()
    snapshot = replace(
        snapshot,
        autonomy=replace(
            snapshot.autonomy,
            protected_validation=ProtectedValidation(
                candidate_commit=CANDIDATE,
                candidate_tree=CANDIDATE_TREE,
                receipt_digest=snapshot.promotion_request.protected_receipt_digest,
            ),
            promotion=PromotionRecord(
                merge_commit=MERGE,
                merge_tree=CANDIDATE_TREE,
                merged_at="2026-08-19T08:00:00Z",
            ),
        ),
        promotion_request=replace(
            snapshot.promotion_request,
            protected_receipt_digest="f" * 64,
        ),
        promotion_snapshot=replace(snapshot.promotion_snapshot, production_commit=MERGE),
    )

    with pytest.raises(
        PromotionContractError, match="promotion_recorded_validation_mismatch"
    ):
        next_controller_action(snapshot, NOW)


def test_changed_main_during_soak_cancels_acceptance() -> None:
    snapshot = controller_snapshot()
    snapshot = replace(
        snapshot,
        autonomy=replace(
            snapshot.autonomy,
            protected_validation=ProtectedValidation(
                candidate_commit=CANDIDATE,
                candidate_tree=CANDIDATE_TREE,
                receipt_digest=snapshot.promotion_request.protected_receipt_digest,
            ),
            promotion=PromotionRecord(
                merge_commit=MERGE,
                merge_tree=CANDIDATE_TREE,
                merged_at="2026-08-19T08:00:00Z",
            ),
            soak_observations=(
                SoakObservation(
                    merge_commit=MERGE,
                    observed_at="2026-08-20T09:00:00Z",
                    healthy=True,
                    evidence_digest=HEALTHY_DIGEST,
                ),
            ),
        ),
        promotion_snapshot=replace(
            snapshot.promotion_snapshot,
            production_commit="0" * 40,
        ),
    )

    with pytest.raises(PromotionContractError, match="promotion_main_identity_mismatch"):
        next_controller_action(snapshot, datetime(2026, 8, 20, 9, tzinfo=UTC))
