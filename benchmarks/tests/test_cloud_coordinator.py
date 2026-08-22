from __future__ import annotations

import base64
import hashlib
from dataclasses import replace

import pytest

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_coordinator import (
    CloudCoordinatorDecision,
    CloudCoordinatorError,
    CoordinatorFailure,
    CoordinatorNode,
    CoordinatorSnapshot,
    EffectObservation,
    ImmutableInputBinding,
    ProductionEvidence,
    choose_next_action,
    reconstruct_snapshot,
    run_protected_cloud_command,
)
from carl_bench.cloud_state import (
    CloudCommand,
    CloudLease,
    CommandClaim,
    CommandState,
    create_command_state,
)

NOW = "2026-08-22T12:00:00Z"
LATER = "2026-08-22T12:30:00Z"
DIGEST = "1" * 64


def node(
    kind: str = "dispatch_builder",
    *,
    status: str = "ready",
    attempt: int = 1,
    request_digest: str = DIGEST,
) -> CoordinatorNode:
    return CoordinatorNode(
        node_id=f"experiment-1:{kind}",
        kind=kind,
        status=status,
        authority="coordinator",
        operation="dispatch",
        request_digest=request_digest,
        occurred_at=NOW,
        attempt=attempt,
        max_attempts=3,
    )


def lease(
    *,
    holder_id: str = "coordinator-run-1",
    expires_at: str = LATER,
    reconciled_at: str | None = None,
    released_at: str | None = None,
) -> CloudLease:
    return CloudLease(
        lease_key="experiment-1:coordinator",
        holder_id=holder_id,
        authority="coordinator",
        revision=1,
        acquired_at="2026-08-22T11:30:00Z",
        expires_at=expires_at,
        reconciled_at=reconciled_at,
        reconciliation_observation_digest=(DIGEST if reconciled_at else None),
        released_at=released_at,
    )


def snapshot(
    *nodes: CoordinatorNode,
    current_lease: CloudLease | None = None,
    command: CommandState | None = None,
    effect: EffectObservation | None = None,
    failure: CoordinatorFailure | None = None,
    production_evidence: ProductionEvidence | None = None,
    dead_holder_observation_digest: str | None = None,
) -> CoordinatorSnapshot:
    return CoordinatorSnapshot(
        schema_version=1,
        experiment_id="experiment-1",
        revision=7,
        observed_at=NOW,
        coordinator_id="coordinator-run-1",
        nodes=nodes,
        lease=current_lease,
        command=command,
        effect=effect,
        failure=failure,
        production_evidence=production_evidence,
        immutable_inputs=(),
        dead_holder_observation_digest=dead_holder_observation_digest,
    )


def command_for(selected: CoordinatorNode, *, status: str = "pending") -> CommandState:
    command = CloudCommand.create(
        command_key=selected.command_key,
        authority=selected.authority,
        operation=selected.operation,
        request_digest=selected.request_digest,
        occurred_at=selected.occurred_at,
        expected_revision=7,
        attempt=selected.attempt,
        max_attempts=selected.max_attempts,
    )
    pending = create_command_state(command)
    if status == "pending":
        return pending
    raise AssertionError("test helper only builds pending commands")


def claimed_command_for(selected: CoordinatorNode) -> CommandState:
    pending = command_for(selected)
    claim = CommandClaim(
        command_key=selected.command_key,
        claim_id="claim-1",
        authority=selected.authority,
        expected_revision=7,
        claimed_at=NOW,
        expires_at=LATER,
    )
    return CommandState(
        command=pending.command,
        revision=8,
        status="claimed",
        claim=claim,
        transition=None,
        result_digest=None,
        failure_code=None,
    )


def test_reconstruct_snapshot_is_strict_canonical_and_rejects_oversize() -> None:
    original = snapshot(node(), current_lease=lease())
    rebuilt = reconstruct_snapshot(original.to_canonical_dict())
    assert rebuilt == original
    assert canonical_json_bytes(rebuilt.to_canonical_dict()) == canonical_json_bytes(
        original.to_canonical_dict()
    )

    with pytest.raises(CloudCoordinatorError, match="coordinator_snapshot_invalid"):
        reconstruct_snapshot({**original.to_canonical_dict(), "extra": True})
    with pytest.raises(CloudCoordinatorError, match="coordinator_snapshot_too_large"):
        reconstruct_snapshot(
            {
                **original.to_canonical_dict(),
                "coordinator_id": "x" * 1_100_000,
            }
        )


def test_input_bindings_fail_closed_on_wrong_resolution_or_duplicate_digest() -> None:
    binding = ImmutableInputBinding(
        digest=DIGEST,
        media_type="application/vnd.carl.improvement-task-set+json",
        media_version=1,
        size_bytes=128,
        visibility="private",
        resolved_digest=DIGEST,
    )
    valid = replace(snapshot(node(), current_lease=lease()), immutable_inputs=(binding,))
    assert reconstruct_snapshot(valid.to_canonical_dict()).immutable_inputs == (binding,)

    with pytest.raises(CloudCoordinatorError, match="immutable_input_resolution_mismatch"):
        replace(binding, resolved_digest="2" * 64)
    with pytest.raises(CloudCoordinatorError, match="immutable_input_duplicate"):
        replace(valid, immutable_inputs=(binding, binding))


def test_graph_order_selects_one_ready_node_independent_of_input_order() -> None:
    later = node("publish_experimental")
    earlier = node("register_hypothesis")
    decision = choose_next_action(snapshot(later, earlier, current_lease=lease()))
    assert decision.action == "persist_command"
    assert decision.node == "register_hypothesis"
    assert decision.consequential is True
    assert decision.command is not None


def test_command_is_persisted_before_effect_and_reuses_original_timestamp() -> None:
    selected = node()
    first = choose_next_action(snapshot(selected, current_lease=lease()))
    assert first.action == "persist_command"
    assert first.command is not None
    assert first.command.occurred_at == NOW

    restarted = replace(
        snapshot(selected, current_lease=lease()),
        observed_at="2026-08-22T12:10:00Z",
        command=create_command_state(first.command),
    )
    second = choose_next_action(restarted)
    assert second.action == "claim_command"
    assert second.command == first.command
    assert second.command.occurred_at == NOW


def test_pending_command_identity_conflict_freezes_before_effect() -> None:
    selected = node()
    conflicting = command_for(replace(selected, request_digest="2" * 64))
    decision = choose_next_action(snapshot(selected, current_lease=lease(), command=conflicting))
    assert decision.action == "frozen"
    assert decision.reason == "command_identity_conflict"
    assert decision.consequential is False


@pytest.mark.parametrize(
    ("kind", "expected_action"),
    [
        ("dispatch_builder", "execute_effect"),
        ("observe_builder", "execute_effect"),
        ("archive_builder", "execute_effect"),
        ("ingest_builder", "execute_effect"),
        ("publish_experimental", "execute_effect"),
        ("dispatch_validation", "execute_effect"),
        ("record_disposition", "execute_effect"),
        ("create_promotion_pr", "execute_effect"),
        ("schedule_soak", "execute_effect"),
        ("observe_soak", "execute_effect"),
        ("accept_soak", "execute_effect"),
        ("create_revert", "execute_effect"),
        ("trigger_supervisor", "execute_effect"),
    ],
)
def test_claimed_nodes_expose_exactly_one_effect(kind: str, expected_action: str) -> None:
    selected = node(kind)
    claimed = claimed_command_for(selected)
    evidence = (
        protected_evidence()
        if kind
        in {
            "create_promotion_pr",
            "schedule_soak",
            "observe_soak",
            "accept_soak",
            "create_revert",
        }
        else None
    )
    decision = choose_next_action(
        snapshot(
            selected,
            current_lease=lease(),
            command=claimed,
            production_evidence=evidence,
        )
    )
    assert decision.action == expected_action
    assert decision.effect_key == selected.effect_key
    assert decision.consequential is True


def test_lost_response_reconciles_effect_instead_of_reexecuting() -> None:
    selected = node()
    claimed = claimed_command_for(selected)
    effect = EffectObservation(
        effect_key=selected.effect_key,
        status="uncertain",
        result_digest=None,
        observed_at=NOW,
    )
    decision = choose_next_action(
        snapshot(selected, current_lease=lease(), command=claimed, effect=effect)
    )
    assert decision.action == "reconcile_effect"
    assert decision.reason == "effect_response_lost"


def test_applied_effect_is_completed_without_a_second_remote_effect() -> None:
    selected = node()
    claimed = claimed_command_for(selected)
    effect = EffectObservation(
        effect_key=selected.effect_key,
        status="applied",
        result_digest="3" * 64,
        observed_at=NOW,
    )
    decision = choose_next_action(
        snapshot(selected, current_lease=lease(), command=claimed, effect=effect)
    )
    assert decision.action == "complete_command"
    assert decision.result_digest == "3" * 64
    assert decision.remote_effect is False


def test_no_lease_acquires_only_a_lease_and_near_expiry_renews_only_the_lease() -> None:
    acquire = choose_next_action(snapshot(node()))
    assert acquire.action == "acquire_lease"
    assert acquire.node is None
    assert acquire.consequential is True

    renewal = choose_next_action(
        replace(snapshot(node(), current_lease=lease()), observed_at="2026-08-22T12:26:00Z")
    )
    assert renewal.action == "renew_lease"
    assert renewal.node is None


def test_expired_lease_requires_authenticated_reconciliation_then_release() -> None:
    expired = lease(expires_at="2026-08-22T11:59:59Z")
    without_receipt = choose_next_action(snapshot(node(), current_lease=expired))
    assert without_receipt.action == "trigger_supervisor"
    assert without_receipt.reason == "dead_holder_observation_required"

    with_receipt = choose_next_action(
        snapshot(
            node(),
            current_lease=expired,
            dead_holder_observation_digest="4" * 64,
        )
    )
    assert with_receipt.action == "reconcile_lease"

    reconciled = lease(
        expires_at="2026-08-22T11:59:59Z",
        reconciled_at="2026-08-22T12:00:00Z",
    )
    release = choose_next_action(snapshot(node(), current_lease=reconciled))
    assert release.action == "release_lease"


def test_foreign_active_lease_is_idle_and_writes_no_narrative_event() -> None:
    decision = choose_next_action(
        snapshot(node(), current_lease=lease(holder_id="coordinator-run-2"))
    )
    assert decision.action == "idle"
    assert decision.reason == "lease_held_by_active_coordinator"
    assert decision.consequential is False
    assert decision.event is None


def test_retry_requires_changed_rework_and_preserves_attempt_identity() -> None:
    selected = node(attempt=1)
    failure = CoordinatorFailure(
        failure_code="cloud_execution_unavailable",
        failed_command_key=selected.command_key,
        changed_action="use_fresh_runner",
        prior_changed_actions=(),
        next_request_digest="5" * 64,
    )
    decision = choose_next_action(snapshot(selected, current_lease=lease(), failure=failure))
    assert decision.action == "retry_rework"
    assert decision.command is not None
    assert decision.command.attempt == 2
    assert decision.command.command_key.endswith(":attempt:2")
    assert decision.command.request_digest == "5" * 64
    assert decision.command.occurred_at == NOW

    unchanged = replace(failure, prior_changed_actions=("use_fresh_runner",))
    escalated = choose_next_action(snapshot(selected, current_lease=lease(), failure=unchanged))
    assert escalated.action == "trigger_supervisor"
    assert escalated.reason == "unchanged_retry_forbidden"


def protected_evidence(**changes: object) -> ProductionEvidence:
    values: dict[str, object] = {
        "protected_archive_receipt": True,
        "verified_at": NOW,
        "archive_retain_until": "2026-09-22T12:00:00Z",
        "protected_live_model_provenance": True,
        "independent_disposition": True,
        "required_checks_passed": True,
        "branch_protection_current": True,
        "merge_bound_soak": True,
        "synthetic": False,
    }
    values.update(changes)
    return ProductionEvidence(**values)


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({"protected_archive_receipt": False}, "protected_archive_receipt_required"),
        ({"verified_at": "2026-08-22T11:30:00Z"}, "protected_verification_stale"),
        ({"protected_live_model_provenance": False}, "protected_live_model_required"),
        ({"independent_disposition": False}, "independent_disposition_required"),
        ({"required_checks_passed": False}, "required_checks_incomplete"),
        ({"branch_protection_current": False}, "branch_protection_drift"),
        ({"synthetic": True}, "synthetic_evidence_forbidden"),
    ],
)
def test_production_promotion_fails_closed_on_each_missing_gate(
    changes: dict[str, object], reason: str
) -> None:
    decision = choose_next_action(
        snapshot(
            node("create_promotion_pr"),
            current_lease=lease(),
            production_evidence=protected_evidence(**changes),
        )
    )
    assert decision.action == "frozen"
    assert decision.reason == reason
    assert decision.consequential is False


def test_soak_acceptance_requires_merge_bound_observation() -> None:
    decision = choose_next_action(
        snapshot(
            node("accept_soak"),
            current_lease=lease(),
            production_evidence=protected_evidence(merge_bound_soak=False),
        )
    )
    assert decision.action == "frozen"
    assert decision.reason == "merge_bound_soak_required"


def test_hard_regression_prioritizes_exact_revert_over_other_ready_work() -> None:
    decision = choose_next_action(
        snapshot(
            node("register_hypothesis"),
            node("create_revert"),
            current_lease=lease(),
            production_evidence=protected_evidence(),
        )
    )
    assert decision.node == "create_revert"
    assert decision.action == "persist_command"


def test_idle_has_stable_identity_and_no_event_or_effect() -> None:
    decision = choose_next_action(snapshot(current_lease=lease()))
    assert decision == CloudCoordinatorDecision(
        schema_version=1,
        action="idle",
        reason="no_ready_node",
        identity=hashlib.sha256(
            canonical_json_bytes(
                {
                    "action": "idle",
                    "experiment_id": "experiment-1",
                    "reason": "no_ready_node",
                    "revision": 7,
                }
            )
        ).hexdigest(),
        experiment_id="experiment-1",
        revision=7,
        node=None,
        command=None,
        effect_key=None,
        result_digest=None,
        consequential=False,
        remote_effect=False,
        event=None,
    )


def test_decision_codec_rejects_secret_shaped_or_private_payloads() -> None:
    decision = choose_next_action(snapshot(current_lease=lease()))
    assert CloudCoordinatorDecision.from_canonical_dict(decision.to_canonical_dict()) == decision
    with pytest.raises(CloudCoordinatorError, match="cloud_result_not_public_safe"):
        CloudCoordinatorDecision.from_canonical_dict(
            {**decision.to_canonical_dict(), "reason": "OPENAI_API_KEY"}
        )


def test_protected_command_reconstructs_canonical_environment_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = snapshot(node(), current_lease=lease())
    envelope = {
        "command": "coordinate",
        "schema_version": 1,
        "snapshot": state.to_canonical_dict(),
    }
    monkeypatch.setenv(
        "CARL_CLOUD_COMMAND_INPUT_B64",
        base64.b64encode(canonical_json_bytes(envelope)).decode("ascii"),
    )

    result = run_protected_cloud_command("coordinate")

    assert result["action"] == "persist_command"
    assert result["node"] == "dispatch_builder"
    assert result["command"]["occurred_at"] == NOW


def test_protected_command_rejects_cross_command_and_noncanonical_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = snapshot(node("observe_builder"), current_lease=lease())
    envelope = {
        "command": "ingest",
        "schema_version": 1,
        "snapshot": state.to_canonical_dict(),
    }
    monkeypatch.setenv(
        "CARL_CLOUD_COMMAND_INPUT_B64",
        base64.b64encode(canonical_json_bytes(envelope)).decode("ascii"),
    )
    mismatch = run_protected_cloud_command("observe")
    assert mismatch["action"] == "frozen"
    assert mismatch["reason"] == "cloud_command_input_mismatch"

    monkeypatch.setenv(
        "CARL_CLOUD_COMMAND_INPUT_B64",
        base64.b64encode(b'{"schema_version":1, "command":"observe"}').decode("ascii"),
    )
    malformed = run_protected_cloud_command("observe")
    assert malformed["action"] == "frozen"
    assert malformed["reason"] == "cloud_command_input_invalid"


def test_worker_command_cannot_advance_a_different_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = snapshot(node("dispatch_builder"), current_lease=lease())
    envelope = {
        "command": "observe",
        "schema_version": 1,
        "snapshot": state.to_canonical_dict(),
    }
    monkeypatch.setenv(
        "CARL_CLOUD_COMMAND_INPUT_B64",
        base64.b64encode(canonical_json_bytes(envelope)).decode("ascii"),
    )

    result = run_protected_cloud_command("observe")

    assert result["action"] == "frozen"
    assert result["reason"] == "cloud_command_node_mismatch"
