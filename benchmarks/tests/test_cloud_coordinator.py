from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from carl_bench import cloud_coordinator
from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_coordinator import (
    CloudCoordinatorDecision,
    CloudCoordinatorError,
    CoordinatorFailure,
    CoordinatorNode,
    CoordinatorSnapshot,
    EffectObservation,
    ImmutableInputBinding,
    ProtectedProductionAuthorization,
    choose_next_action,
    reconstruct_snapshot,
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

NODE_BINDINGS = {
    "create_revert": ("promoter", "github_effect"),
    "observe_revert": ("observer", "observe"),
    "publish_input": ("validator", "register_evidence"),
    "register_hypothesis": ("builder", "register_manifest"),
    "request_builder": ("coordinator", "schedule"),
    "dispatch_builder": ("coordinator", "dispatch"),
    "observe_builder": ("observer", "observe"),
    "archive_builder": ("observer", "register_evidence"),
    "ingest_builder": ("coordinator", "record_success"),
    "publish_experimental": ("builder", "publish_experimental"),
    "dispatch_validation": ("coordinator", "dispatch"),
    "observe_validation": ("observer", "observe"),
    "archive_validation": ("validator", "register_evidence"),
    "ingest_validation": ("coordinator", "record_success"),
    "record_disposition": ("validator", "append_disposition"),
    "create_promotion_pr": ("promoter", "github_effect"),
    "observe_required_checks": ("observer", "observe"),
    "enable_auto_merge": ("promoter", "github_effect"),
    "schedule_soak": ("coordinator", "schedule"),
    "observe_soak": ("soak", "production_observation"),
    "accept_soak": ("soak", "record_soak"),
    "trigger_supervisor": ("supervisor", "claim_trigger"),
}


def node(
    kind: str = "dispatch_builder",
    *,
    status: str = "ready",
    attempt: int = 1,
    request_digest: str = DIGEST,
    command_key: str | None = None,
) -> CoordinatorNode:
    authority, operation = NODE_BINDINGS[kind]
    return CoordinatorNode(
        node_id=f"experiment-1:{kind}",
        kind=kind,
        status=status,
        authority=authority,
        operation=operation,
        command_key=(
            f"experiment-1:{kind}:attempt:{attempt}" if command_key is None else command_key
        ),
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
    production_authorization: ProtectedProductionAuthorization | None = None,
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
        production_authorization=production_authorization,
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


def test_node_preserves_exact_effect_binding_command_key() -> None:
    exact = f"cloud-run-{'7' * 64}-attempt-1"
    selected = node(command_key=exact, request_digest="7" * 64)

    decision = choose_next_action(snapshot(selected, current_lease=lease()))

    assert decision.command is not None
    assert decision.command.command_key == exact


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
        ("trigger_supervisor", "execute_effect"),
    ],
)
def test_claimed_nodes_expose_exactly_one_effect(kind: str, expected_action: str) -> None:
    selected = node(kind)
    claimed = claimed_command_for(selected)
    decision = choose_next_action(
        snapshot(
            selected,
            current_lease=lease(),
            command=claimed,
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


def test_rate_limited_effect_waits_idly_then_reconciles_without_reexecution() -> None:
    selected = node()
    claimed = claimed_command_for(selected)
    waiting = EffectObservation(
        effect_key=selected.effect_key,
        status="retry_scheduled",
        result_digest=None,
        observed_at=NOW,
        retry_not_before="2026-08-22T12:10:00Z",
    )

    before = choose_next_action(
        replace(
            snapshot(selected, current_lease=lease(), command=claimed, effect=waiting),
            observed_at="2026-08-22T12:05:00Z",
        )
    )
    after = choose_next_action(
        replace(
            snapshot(selected, current_lease=lease(), command=claimed, effect=waiting),
            observed_at="2026-08-22T12:10:00Z",
        )
    )

    assert before.action == "idle"
    assert before.reason == "effect_retry_not_ready"
    assert before.consequential is False
    assert after.action == "reconcile_effect"
    assert after.reason == "effect_retry_ready"


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
        next_command_key="experiment-1:dispatch_builder:attempt:2",
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


def production_authorization_values(
    node_kind: str = "create_promotion_pr", **changes: object
) -> dict[str, object]:
    values = {
        "experiment_id": "experiment-1",
        "node_kind": node_kind,
        "request_digest": DIGEST,
        "repository": "StephenBickel/carl-agent",
        "candidate_commit": "2" * 40,
        "candidate_tree": "3" * 40,
        "experimental_ref": "refs/heads/experimental/experiment-1",
        "archive_object_key": f"carl-evidence/v1/sha256/{DIGEST[:2]}/{DIGEST}",
        "archive_version_id": "version-1",
        "archive_digest": DIGEST,
        "verified_at": NOW,
        "archive_retain_until": "2026-09-22T12:00:00Z",
        "source_receipt_digests": ("2" * 64, "3" * 64, "4" * 64, "5" * 64),
        "merge_commit": "4" * 40,
        "merge_tree": "5" * 40,
        "merged_at": "2026-08-21T12:00:00Z",
        "soak_observation_digest": "6" * 64,
        "soak_observed_at": NOW,
    }
    values.update(changes)
    return values


def test_production_authorization_cannot_be_constructed_by_ordinary_code() -> None:
    with pytest.raises(CloudCoordinatorError, match="protected_authorization_construction_invalid"):
        ProtectedProductionAuthorization(**production_authorization_values())


@pytest.mark.parametrize(
    "kind",
    sorted(
        {
            "create_promotion_pr",
            "observe_required_checks",
            "enable_auto_merge",
            "schedule_soak",
            "observe_soak",
            "accept_soak",
            "create_revert",
            "observe_revert",
        }
    ),
)
def test_production_nodes_fail_closed_without_service_minted_authorization(kind: str) -> None:
    decision = choose_next_action(
        snapshot(
            node(kind),
            current_lease=lease(),
        )
    )
    assert decision.action == "frozen"
    assert decision.reason == "protected_production_receipts_required"
    assert decision.consequential is False


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


def test_pure_coordinator_exposes_no_environment_snapshot_execution_path() -> None:
    assert not hasattr(cloud_coordinator, "run_protected_cloud_command")


def test_node_kind_rejects_caller_selected_authority_and_operation() -> None:
    with pytest.raises(CloudCoordinatorError, match="coordinator_node_binding_invalid"):
        CoordinatorNode(
            node_id="experiment-1:create_promotion_pr",
            kind="create_promotion_pr",
            status="ready",
            authority="builder",
            operation="publish_experimental",
            command_key="github-pr-experiment-1",
            request_digest=DIGEST,
            occurred_at=NOW,
            attempt=1,
            max_attempts=3,
        )


def test_retry_rework_rejects_an_unchanged_request_digest() -> None:
    selected = node(status="failed")
    unchanged = CoordinatorFailure(
        failure_code="infrastructure_failure",
        failed_command_key=selected.command_key,
        changed_action="retry_with_fresh_runner",
        prior_changed_actions=(),
        next_command_key=selected.command_key,
        next_request_digest=selected.request_digest,
    )

    decision = choose_next_action(snapshot(selected, current_lease=lease(), failure=unchanged))

    assert decision.action == "trigger_supervisor"
    assert decision.reason == "unchanged_retry_forbidden"


def test_snapshot_schema_version_rejects_boolean_true() -> None:
    value = snapshot(current_lease=lease()).to_canonical_dict()
    value["schema_version"] = True

    with pytest.raises(CloudCoordinatorError, match="coordinator_snapshot_schema_invalid"):
        reconstruct_snapshot(value)


def test_decision_schema_version_rejects_boolean_true() -> None:
    value = choose_next_action(snapshot(current_lease=lease())).to_canonical_dict()
    value["schema_version"] = True

    with pytest.raises(CloudCoordinatorError, match="cloud_decision_invalid"):
        CloudCoordinatorDecision.from_canonical_dict(value)
