from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from test_cloud_coordinator import claimed_command_for, lease, node, snapshot

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_coordinator import ProtectedCoordinatorExecutor, choose_next_action
from carl_bench.coordinator_effects import (
    CoordinatorNodeEffectRequest,
    CoordinatorNodeEffectResponse,
)
from carl_bench.coordinator_service import (
    PreparedCoordinatorEffect,
    _ProtectedCoordinatorEffectRouter,
)

NOW = datetime(2026, 8, 22, 12, tzinfo=UTC)
NOW_TEXT = "2026-08-22T12:00:00Z"
RESULT_DIGEST = "a" * 64


def test_cloud_request_enqueues_one_authenticated_manifest_before_reading_queue() -> None:
    calls: list[str] = []

    class State:
        def enqueue_pending_graph(self, *, observed_at: datetime):
            assert observed_at == NOW
            calls.append("enqueue")
            return True

        def reconstruct(self, command: str, *, observed_at: datetime):
            assert command == "request"
            assert observed_at == NOW
            calls.append("reconstruct")
            return None

        def apply(self, decision, *, observed_at):  # pragma: no cover
            raise AssertionError((decision, observed_at))

    class Effects:
        def execute(self, decision, *, observed_at):  # pragma: no cover
            raise AssertionError((decision, observed_at))

    decision = ProtectedCoordinatorExecutor._for_testing(
        state=State(), effects=Effects(), clock=lambda: NOW
    ).advance("request")

    assert calls == ["enqueue", "reconstruct"]
    assert decision.action == "idle"
    assert decision.reason == "no_applicable_node"


def test_non_github_lost_response_reconciles_without_a_second_consequence() -> None:
    selected = node("observe_builder")
    execute = choose_next_action(
        snapshot(
            selected,
            current_lease=lease(),
            command=claimed_command_for(selected),
        )
    )
    request = CoordinatorNodeEffectRequest.from_decision(execute)
    response = CoordinatorNodeEffectResponse.completed(
        request=request,
        result_digest=RESULT_DIGEST,
        observed_at=NOW_TEXT,
    )
    consequences: list[str] = []
    completed: list[object] = []

    class Backend:
        def prepare_coordinator_effect(self, decision, *, expected_family, observed_at):
            assert expected_family == "observer"
            assert observed_at == NOW
            return PreparedCoordinatorEffect("observer", request)

        def complete_coordinator_effect(self, decision, actual_response, *, observed_at):
            assert observed_at == NOW
            completed.append(actual_response)
            if len(completed) == 1:
                raise RuntimeError("lost response after provider consequence")
            return decision

    class Observer:
        def observe(self, actual_request):
            assert actual_request == request
            consequences.append("observed")
            return response

        def reconcile(self, actual_request):
            assert actual_request == request
            return response

    router = _ProtectedCoordinatorEffectRouter._for_testing(
        backend=Backend(),
        github=None,
        input_publisher=None,
        observer=Observer(),
        archive=None,
        evaluator=None,
    )

    with pytest.raises(RuntimeError, match="lost response"):
        router.execute(execute, observed_at=NOW)

    reconcile = replace(
        execute,
        action="reconcile_effect",
        reason="effect_response_lost",
        identity=hashlib.sha256(
            canonical_json_bytes(
                {
                    "action": "reconcile_effect",
                    "command_key": execute.command.command_key,
                    "effect_key": execute.command.effect_key,
                    "experiment_id": execute.experiment_id,
                    "node_id": selected.node_id,
                    "reason": "effect_response_lost",
                    "revision": execute.revision,
                }
            )
        ).hexdigest(),
    )
    assert router.execute(reconcile, observed_at=NOW) == reconcile
    assert consequences == ["observed"]
    assert completed == [response, response]


def test_recovery_request_has_no_caller_authority_and_binds_exact_node() -> None:
    from carl_bench.coordinator_recovery import CoordinatorRecoveryRequest

    request = CoordinatorRecoveryRequest(
        schema_version=1,
        domain="carl.coordinator.recovery.v1",
        experiment_id="experiment-1",
        node_id="experiment-1:archive_builder",
        node_kind="archive_builder",
        expected_revision=7,
        evidence_digest="b" * 64,
        repair_fingerprint="c" * 64,
        requested_at=NOW_TEXT,
    )

    assert "authority" not in request.to_canonical_dict()
    assert len(request.digest) == 64
    with pytest.raises(ValueError, match="coordinator_recovery_request_invalid"):
        CoordinatorRecoveryRequest.from_canonical_dict(
            {**request.to_canonical_dict(), "node_kind": "observe_builder"}
        )
