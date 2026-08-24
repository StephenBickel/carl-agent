from __future__ import annotations

import base64
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fixtures.fake_cloud import StatefulFakeCloud

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_execution import CloudRunRequest, TrustedCloudReceiptKey
from carl_bench.commissioning import (
    CommissioningArtifactError,
    RemoteCloudAcceptanceReceipt,
    require_remote_cloud_acceptance,
)
from carl_bench.commissioning_controller import (
    CommissioningControllerError,
    LiveCommissioningCommandStore,
)
from carl_bench.github_promotion import APPROVED_REQUIRED_CHECKS
from carl_bench.live_commissioning import (
    LiveCommissioningPlan,
    LiveCommissioningRunner,
)


def _plan() -> LiveCommissioningPlan:
    request = CloudRunRequest.create(
        repository="StephenBickel/carl-agent",
        workflow_file="autonomous-improvement.yml",
        experiment_digest="a" * 64,
        parent_commit="1" * 40,
        candidate_commit="2" * 40,
        task_set_digest="b" * 64,
        metric_pack_digest="c" * 64,
        policy_digest="d" * 64,
        workflow_revision="3" * 40,
        workflow_blob_digest="e" * 64,
    )
    return LiveCommissioningPlan(
        schema_version=1,
        experiment_id="exp-live-commissioning-001",
        request=request,
        baseline_tree="8" * 40,
        candidate_tree="4" * 40,
        accepted_production_tree="4" * 40,
        promotion_id="promotion-exp-live-commissioning-001",
        hard_regression_promotion_id="promotion-hard-regression-001",
        hard_regression_commit="5" * 40,
        hard_regression_tree="6" * 40,
        exact_revert_commit="7" * 40,
        command_occurred_at="2026-08-21T12:00:00Z",
        merge_observed_at="2026-08-21T12:30:00Z",
        soak_accepted_at="2026-08-22T12:31:00Z",
        hard_failure_observed_at="2026-08-22T13:00:00Z",
        revert_observed_at="2026-08-22T13:30:00Z",
    )


def _runner(
    private_root: Path,
    cloud: StatefulFakeCloud,
) -> LiveCommissioningRunner:
    return LiveCommissioningRunner(
        cloud=cloud,
        observer=cloud.observer(),
        command_store=LiveCommissioningCommandStore(private_root / "commands.sqlite3"),
        trusted_receipt_key=cloud.trusted_receipt_key,
        verified_at=datetime(2026, 8, 21, 12, 10, tzinfo=UTC),
    )


def test_stateful_fake_cloud_commissions_the_complete_bridge_without_duplicate_effects(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    plan = _plan()
    cloud = StatefulFakeCloud(tmp_path / "fake-cloud.json")

    first = _runner(private_root, cloud).run(plan)
    before_restart = cloud.snapshot()
    restarted_cloud = StatefulFakeCloud(tmp_path / "fake-cloud.json")
    second = _runner(private_root, restarted_cloud).run(plan)
    after_restart = restarted_cloud.snapshot()

    assert second == first
    assert after_restart == before_restart
    assert first.synthetic_test_only is True
    assert first.remote_cloud_acceptance == "uncommissioned"
    assert first.experimental_ref == f"refs/heads/experimental/{plan.experiment_id}"
    assert first.candidate_commit == plan.request.candidate_commit
    assert first.candidate_tree == plan.candidate_tree
    assert first.disposition == "production_candidate"
    assert first.required_checks_complete is True
    assert first.required_checks == APPROVED_REQUIRED_CHECKS
    assert first.auto_merge_enabled is True
    assert first.soak_merge_commit == first.promotion_merge_commit
    assert first.soak_accepted_at == plan.soak_accepted_at
    assert first.hard_failure_merge_commit != first.promotion_merge_commit
    assert first.revert_restored_tree == plan.accepted_production_tree
    assert first.revert_required_checks_complete is True
    assert first.revert_auto_merge_enabled is True
    assert first.revert_started_at == plan.hard_failure_observed_at
    assert first.revert_merged_at == plan.revert_observed_at
    assert first.restart_recoveries == 2
    assert 0 < first.artifact_byte_length <= 8_388_608

    assert before_restart["dispatch_network_attempts"] == 1
    assert before_restart["lost_dispatch_responses"] == 1
    assert before_restart["effect_counts"] == {
        "accept_soak": 1,
        "archive_evidence": 1,
        "enable_promotion_auto_merge": 1,
        "enable_revert_auto_merge": 1,
        "hard_regression_merge": 1,
        "ingest_trusted_evidence": 1,
        "merge_promotion": 1,
        "merge_revert": 1,
        "observe_hard_regression": 1,
        "observe_soak": 1,
        "open_promotion_pr": 1,
        "open_revert_pr": 1,
        "publish_experimental": 1,
        "record_disposition": 1,
        "record_promotion_checks": 1,
        "record_revert_checks": 1,
        "sign_evidence": 1,
        "workflow_dispatch": 1,
    }
    assert before_restart["refs"][first.experimental_ref] == plan.request.candidate_commit
    assert before_restart["main"]["tree"] == plan.accepted_production_tree
    assert before_restart["main"]["commit"] == first.revert_merge_commit


def test_fake_cloud_receipt_is_structurally_ineligible_for_remote_acceptance(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    cloud = StatefulFakeCloud(tmp_path / "fake-cloud.json")
    result = _runner(private_root, cloud).run(_plan())

    with pytest.raises(
        CommissioningArtifactError,
        match="remote_cloud_acceptance_receipt_type_required",
    ):
        require_remote_cloud_acceptance(result, trusted_key=cloud.trusted_receipt_key)

    forged = {
        **result.to_canonical_dict(),
        "authority_kind": "remote_cloud_acceptance",
        "remote_cloud_acceptance": "commissioned",
        "synthetic_test_only": False,
    }
    with pytest.raises(
        CommissioningArtifactError,
        match="invalid_remote_cloud_acceptance_receipt",
    ):
        RemoteCloudAcceptanceReceipt.from_canonical_dict(forged)


def test_remote_cloud_acceptance_requires_the_exact_signed_production_schema() -> None:
    signer = Ed25519PrivateKey.generate()
    payload = {
        "accepted_at": "2026-08-22T12:31:00Z",
        "accepted_soak_digest": "8" * 64,
        "archive_digest": "9" * 64,
        "archive_object_key": "carl-evidence/v1/sha256/aa/" + "a" * 64,
        "archive_version_id": "version-aa",
        "authority_kind": "remote_cloud_acceptance",
        "candidate_commit": "2" * 40,
        "candidate_tree": "4" * 40,
        "disposition_digest": "7" * 64,
        "experiment_id": "exp-production-001",
        "experimental_ref": "refs/heads/experimental/exp-production-001",
        "merge_commit": "5" * 40,
        "merge_tree": "4" * 40,
        "merged_at": "2026-08-21T12:30:00Z",
        "promotion_id": "promotion-exp-production-001",
        "provider_account_id": "github-installation-991",
        "provider_kind": "github_actions",
        "provider_run_id": 901,
        "pull_request_number": 81,
        "remote_cloud_acceptance": "commissioned",
        "required_checks_digest": "a" * 64,
        "repository": "StephenBickel/carl-agent",
        "schema_version": 1,
        "signed_observation_digest": "6" * 64,
        "signer_key_id": "remote-cloud-acceptance-v1",
        "synthetic_test_only": False,
        "workflow_revision": "3" * 40,
    }
    receipt = RemoteCloudAcceptanceReceipt(
        **payload,
        signature_base64=base64.b64encode(signer.sign(canonical_json_bytes(payload))).decode(
            "ascii"
        ),
    )
    trusted_key = TrustedCloudReceiptKey(
        key_id="remote-cloud-acceptance-v1",
        public_key_pem=signer.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )

    assert require_remote_cloud_acceptance(receipt, trusted_key=trusted_key) == receipt

    with pytest.raises(
        CommissioningArtifactError,
        match="remote_cloud_acceptance_signature_invalid",
    ):
        require_remote_cloud_acceptance(
            replace(receipt, accepted_soak_digest="f" * 64),
            trusted_key=trusted_key,
        )


def test_live_command_store_replays_exact_result_and_rejects_conflicts(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    store = LiveCommissioningCommandStore(private_root / "commands.sqlite3")
    request = {"schema_version": 1, "request": "exact"}
    result = {"schema_version": 1, "outcome": "reverted"}

    pending = store.begin(
        command_key="commission-exact",
        request_payload=request,
        occurred_at="2026-08-21T12:00:00Z",
    )
    completed = store.complete(
        command_key="commission-exact",
        request_payload=request,
        result=result,
    )
    replayed = store.complete(
        command_key="commission-exact",
        request_payload=request,
        result=result,
    )

    assert pending.status == "pending"
    assert completed == replayed
    assert completed.status == "completed"
    assert completed.result == result
    assert completed.result_digest is not None

    with pytest.raises(
        CommissioningControllerError,
        match="live_commissioning_command_conflict",
    ):
        store.begin(
            command_key="commission-exact",
            request_payload={"schema_version": 1, "request": "changed"},
            occurred_at="2026-08-21T12:00:00Z",
        )
    with pytest.raises(
        CommissioningControllerError,
        match="live_commissioning_result_conflict",
    ):
        store.complete(
            command_key="commission-exact",
            request_payload=request,
            result={"schema_version": 1, "outcome": "changed"},
        )
