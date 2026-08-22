from __future__ import annotations

import importlib
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from test_cloud_coordinator import claimed_command_for, lease, node, snapshot
from test_coordinator_service import durable_production_receipts

from carl_bench import cloud_coordinator, coordinator_service
from carl_bench.cloud_coordinator import (
    CloudCoordinatorDecision,
    EffectObservation,
    ProtectedCoordinatorExecutor,
)
from carl_bench.cloud_state import create_command_state

NOW = datetime(2026, 8, 22, 12, tzinfo=UTC)
RESULT_DIGEST = "a" * 64

EXPECTED_EFFECT_FAMILIES = {
    "create_revert": "github",
    "observe_revert": "observer",
    "publish_input": "input",
    "register_hypothesis": "state",
    "request_builder": "state",
    "dispatch_builder": "github",
    "observe_builder": "observer",
    "archive_builder": "archive",
    "ingest_builder": "state",
    "publish_experimental": "github",
    "dispatch_validation": "github",
    "observe_validation": "observer",
    "archive_validation": "archive",
    "ingest_validation": "evaluator",
    "record_disposition": "state",
    "create_promotion_pr": "github",
    "observe_required_checks": "github",
    "enable_auto_merge": "github",
    "schedule_soak": "state",
    "observe_soak": "observer",
    "accept_soak": "state",
    "trigger_supervisor": "supervisor",
}


def _authorization(kind: str):
    if kind not in {
        "create_promotion_pr",
        "observe_required_checks",
        "enable_auto_merge",
        "schedule_soak",
        "observe_soak",
        "accept_soak",
        "create_revert",
        "observe_revert",
    }:
        return None
    return coordinator_service._authorization_from_durable_receipts(
        durable_production_receipts(kind), observed_at=NOW
    )


class RestartableState:
    def __init__(self, kind: str) -> None:
        selected = node(kind)
        self.current = snapshot(
            selected,
            current_lease=lease(),
            production_authorization=_authorization(kind),
        )
        self.consequences: list[str] = []
        self.frozen = False

    def reconstruct(self, command: str, *, observed_at: datetime):
        assert command == "coordinate"
        assert observed_at == NOW
        if self.frozen:
            return None
        return self.current

    def apply(self, decision: CloudCoordinatorDecision, *, observed_at: datetime):
        assert observed_at == NOW
        assert decision.node is not None
        selected = node(decision.node)
        self.consequences.append(decision.action)
        if decision.action == "persist_command":
            self.current = replace(self.current, command=create_command_state(decision.command))
        elif decision.action == "claim_command":
            self.current = replace(self.current, command=claimed_command_for(selected))
        elif decision.action == "complete_command":
            self.current = replace(
                self.current,
                revision=self.current.revision + 1,
                nodes=(replace(selected, status="complete"),),
                command=None,
                effect=None,
            )
        elif decision.action == "frozen":
            self.frozen = True
        else:  # pragma: no cover - names the production routing defect
            raise AssertionError(decision.action)
        return decision


class RestartableBackend:
    def __init__(self, state: RestartableState) -> None:
        self.state = state
        self.routes: list[tuple[str, str]] = []

    def _observe(self, decision: CloudCoordinatorDecision, route: str) -> None:
        assert decision.node is not None
        self.routes.append((route, decision.node))
        self.state.consequences.append(f"effect:{decision.node}")
        self.state.current = replace(
            self.state.current,
            effect=EffectObservation(
                effect_key=decision.effect_key,
                status="applied",
                result_digest=RESULT_DIGEST,
                observed_at="2026-08-22T12:00:00Z",
            ),
        )

    def execute_local_coordinator_effect(
        self, decision: CloudCoordinatorDecision, *, family: str, observed_at: datetime
    ):
        assert observed_at == NOW
        assert decision.node is not None
        assert family == EXPECTED_EFFECT_FAMILIES[decision.node]
        assert decision.remote_effect is False
        self._observe(decision, family)
        return decision

    def execute_github_coordinator_effect(
        self, decision: CloudCoordinatorDecision, *, github: object, observed_at: datetime
    ):
        assert github is not None
        assert observed_at == NOW
        assert decision.remote_effect is True
        self._observe(decision, "github")
        return decision

    def prepare_coordinator_effect(
        self,
        decision: CloudCoordinatorDecision,
        *,
        expected_family: str,
        observed_at: datetime,
    ):
        effects = importlib.import_module("carl_bench.coordinator_effects")
        assert observed_at == NOW
        assert decision.node is not None
        assert expected_family == EXPECTED_EFFECT_FAMILIES[decision.node]
        self.routes.append(("prepare", decision.node))
        request = effects.CoordinatorNodeEffectRequest.from_decision(decision)
        return effects.PreparedCoordinatorEffect(expected_family, request)

    def complete_coordinator_effect(
        self,
        decision: CloudCoordinatorDecision,
        response: object,
        *,
        observed_at: datetime,
    ):
        effects = importlib.import_module("carl_bench.coordinator_effects")
        assert observed_at == NOW
        request = effects.CoordinatorNodeEffectRequest.from_decision(decision)
        assert isinstance(response, effects.CoordinatorNodeEffectResponse)
        assert response.request_digest == request.digest
        self._observe(decision, "complete")
        return decision


class RestartableEffects:
    def __init__(self, state: RestartableState) -> None:
        self.backend = RestartableBackend(state)
        self.router = coordinator_service._ProtectedCoordinatorEffectRouter._for_testing(
            backend=self.backend,
            github=object(),
            input_publisher=self,
            observer=self,
            archive=self,
            evaluator=self,
        )

    def _external(self, request: object, route: str):
        effects = importlib.import_module("carl_bench.coordinator_effects")
        assert isinstance(request, effects.CoordinatorNodeEffectRequest)
        self.backend.routes.append((route, request.node_kind))
        return effects.CoordinatorNodeEffectResponse.completed(
            request=request,
            result_digest=RESULT_DIGEST,
            observed_at="2026-08-22T12:00:00Z",
        )

    def publish(self, request: object):
        return self._external(request, "input")

    def observe(self, request: object):
        return self._external(request, "observer")

    def archive(self, request: object):
        return self._external(request, "archive")

    def evaluate(self, request: object):
        return self._external(request, "evaluator")

    def execute(self, decision: CloudCoordinatorDecision, *, observed_at: datetime):
        return self.router.execute(decision, observed_at=observed_at)


def _restart(state: RestartableState, effects: object) -> ProtectedCoordinatorExecutor:
    return ProtectedCoordinatorExecutor._for_testing(
        state=state,
        effects=effects,
        clock=lambda: NOW,
    )


def test_effect_family_table_is_literal_complete_and_exhaustive() -> None:
    assert tuple(cloud_coordinator.NODE_ORDER) == tuple(EXPECTED_EFFECT_FAMILIES)
    assert dict(cloud_coordinator.EFFECT_FAMILY_BY_NODE) == EXPECTED_EFFECT_FAMILIES
    assert {
        cloud_coordinator.effect_family_for_node(kind) for kind in cloud_coordinator.NODE_ORDER
    } == {
        "archive",
        "evaluator",
        "github",
        "input",
        "observer",
        "state",
        "supervisor",
    }


@pytest.mark.parametrize("kind", tuple(EXPECTED_EFFECT_FAMILIES))
def test_every_node_survives_restart_and_reaches_exact_completion(kind: str) -> None:
    state = RestartableState(kind)
    effects = RestartableEffects(state)
    observed: list[str] = []

    for expected_action in (
        "persist_command",
        "claim_command",
        "execute_effect",
        "complete_command",
        "idle",
    ):
        before = len(state.consequences)
        decision = _restart(state, effects).advance("coordinate")
        observed.append(decision.action)
        expected_delta = 0 if expected_action == "idle" else 1
        assert len(state.consequences) - before == expected_delta

    assert observed == [
        "persist_command",
        "claim_command",
        "execute_effect",
        "complete_command",
        "idle",
    ]
    assert state.current.nodes[0].status == "complete"
    assert state.consequences == [
        "persist_command",
        "claim_command",
        f"effect:{kind}",
        "complete_command",
    ]
    family = EXPECTED_EFFECT_FAMILIES[kind]
    if family in {"github", "state", "supervisor"}:
        assert effects.backend.routes == [(family, kind)]
    else:
        assert effects.backend.routes == [
            ("prepare", kind),
            (family, kind),
            ("complete", kind),
        ]


def test_uncommissioned_family_persists_one_stable_selected_node_freeze() -> None:
    state = RestartableState("archive_builder")
    state.current = replace(
        state.current,
        command=claimed_command_for(node("archive_builder")),
    )

    class UncommissionedArchive:
        def execute(self, decision, *, observed_at):
            del decision, observed_at
            raise cloud_coordinator.ProtectedEffectUnavailable("archive_service_uncommissioned")

    decision = _restart(state, UncommissionedArchive()).advance("coordinate")
    restarted = _restart(state, UncommissionedArchive()).advance("coordinate")

    assert decision.action == "frozen"
    assert decision.node == "archive_builder"
    assert decision.reason == "archive_service_uncommissioned"
    assert decision.consequential is True
    assert restarted.action == "idle"
    assert state.consequences == ["frozen"]


def test_first_publish_input_socket_failure_freezes_once_then_is_durably_idle() -> None:
    state = RestartableState("publish_input")
    state.current = replace(
        state.current,
        command=claimed_command_for(node("publish_input")),
    )

    class MissingInput:
        def execute(self, decision, *, observed_at):
            assert decision.node == "publish_input"
            assert observed_at == NOW
            raise cloud_coordinator.ProtectedEffectUnavailable("input_service_uncommissioned")

    first = _restart(state, MissingInput()).advance("coordinate")
    repeated = _restart(state, MissingInput()).advance("coordinate")

    assert (first.action, first.reason, first.consequential) == (
        "frozen",
        "input_service_uncommissioned",
        True,
    )
    assert (repeated.action, repeated.reason, repeated.consequential) == (
        "idle",
        "no_applicable_node",
        False,
    )
    assert state.consequences == ["frozen"]


def test_typed_node_effect_codec_binds_exact_family_and_command_identity() -> None:
    effects = importlib.import_module("carl_bench.coordinator_effects")
    selected = node("observe_builder")
    decision = cloud_coordinator.choose_next_action(
        snapshot(
            selected,
            current_lease=lease(),
            command=claimed_command_for(selected),
        )
    )

    request = effects.CoordinatorNodeEffectRequest.from_decision(decision)
    response = effects.CoordinatorNodeEffectResponse.completed(
        request=request,
        result_digest=RESULT_DIGEST,
        observed_at="2026-08-22T12:00:00Z",
    )

    assert request.family == "observer"
    assert request.node_kind == "observe_builder"
    assert request.command_key == selected.command_key
    assert request.effect_key == selected.effect_key
    assert response.request_digest == request.digest
    assert response.result_digest == RESULT_DIGEST
    assert (
        effects.CoordinatorNodeEffectRequest.from_canonical_dict(request.to_canonical_dict())
        == request
    )
    assert (
        effects.CoordinatorNodeEffectResponse.from_canonical_dict(response.to_canonical_dict())
        == response
    )

    with pytest.raises(ValueError, match="coordinator_node_effect_request_invalid"):
        effects.CoordinatorNodeEffectRequest.from_canonical_dict(
            {**request.to_canonical_dict(), "schema_version": True}
        )
    with pytest.raises(ValueError, match="coordinator_node_effect_response_invalid"):
        effects.CoordinatorNodeEffectResponse.from_canonical_dict(
            {**response.to_canonical_dict(), "extra": False}
        )
    with pytest.raises(ValueError, match="coordinator_node_effect_response_invalid"):
        effects.CoordinatorNodeEffectResponse.from_canonical_dict(
            {
                **response.to_canonical_dict(),
                "status": "retry_scheduled",
                "result_digest": None,
                "retry_not_before": "2026-08-22T11:59:59Z",
            }
        )


@pytest.mark.parametrize(
    ("kind", "family", "method"),
    [
        ("publish_input", "input", "publish"),
        ("observe_builder", "observer", "observe"),
        ("archive_builder", "archive", "archive"),
        ("ingest_validation", "evaluator", "evaluate"),
    ],
)
def test_fixed_router_calls_only_the_typed_family_method(
    kind: str, family: str, method: str
) -> None:
    effects = importlib.import_module("carl_bench.coordinator_effects")
    selected = node(kind)
    decision = cloud_coordinator.choose_next_action(
        snapshot(
            selected,
            current_lease=lease(),
            command=claimed_command_for(selected),
        )
    )
    request = effects.CoordinatorNodeEffectRequest.from_decision(decision)
    response = effects.CoordinatorNodeEffectResponse.completed(
        request=request,
        result_digest=RESULT_DIGEST,
        observed_at="2026-08-22T12:00:00Z",
    )
    calls: list[tuple[str, object]] = []

    class Backend:
        def prepare_coordinator_effect(self, actual, *, expected_family, observed_at):
            assert actual == decision
            assert expected_family == family
            assert observed_at == NOW
            calls.append(("prepare", expected_family))
            return effects.PreparedCoordinatorEffect(expected_family, request)

        def complete_coordinator_effect(self, actual, actual_response, *, observed_at):
            assert actual == decision
            assert actual_response == response
            assert observed_at == NOW
            calls.append(("complete", actual_response))
            return actual

    class TypedService:
        def publish(self, actual):
            assert method == "publish" and actual == request
            calls.append(("publish", actual))
            return response

        def observe(self, actual):
            assert method == "observe" and actual == request
            calls.append(("observe", actual))
            return response

        def archive(self, actual):
            assert method == "archive" and actual == request
            calls.append(("archive", actual))
            return response

        def evaluate(self, actual):
            assert method == "evaluate" and actual == request
            calls.append(("evaluate", actual))
            return response

    service = TypedService()
    router = coordinator_service._ProtectedCoordinatorEffectRouter._for_testing(
        backend=Backend(),
        github=None,
        input_publisher=service if family == "input" else None,
        observer=service if family == "observer" else None,
        archive=service if family == "archive" else None,
        evaluator=service if family == "evaluator" else None,
    )

    assert router.execute(decision, observed_at=NOW) == decision
    assert [name for name, _ in calls] == ["prepare", method, "complete"]


@pytest.mark.parametrize("kind", ["register_hypothesis", "trigger_supervisor"])
def test_fixed_router_uses_only_atomic_postgres_for_local_families(kind: str) -> None:
    selected = node(kind)
    decision = cloud_coordinator.choose_next_action(
        snapshot(
            selected,
            current_lease=lease(),
            command=claimed_command_for(selected),
        )
    )
    calls: list[tuple[str, str]] = []

    class Backend:
        def execute_local_coordinator_effect(self, actual, *, family, observed_at):
            assert actual == decision
            assert observed_at == NOW
            calls.append((actual.node, family))
            return actual

    router = coordinator_service._ProtectedCoordinatorEffectRouter._for_testing(
        backend=Backend(),
        github=None,
        input_publisher=None,
        observer=None,
        archive=None,
        evaluator=None,
    )

    assert router.execute(decision, observed_at=NOW) == decision
    assert calls == [(kind, "supervisor" if kind == "trigger_supervisor" else "state")]


def test_fixed_router_uses_the_existing_github_effect_client() -> None:
    selected = node("dispatch_builder")
    decision = cloud_coordinator.choose_next_action(
        snapshot(
            selected,
            current_lease=lease(),
            command=claimed_command_for(selected),
        )
    )
    github = object()
    calls: list[tuple[object, object]] = []

    class Backend:
        def execute_github_coordinator_effect(self, actual, *, github, observed_at):
            assert actual == decision
            assert observed_at == NOW
            calls.append((actual, github))
            return actual

    router = coordinator_service._ProtectedCoordinatorEffectRouter._for_testing(
        backend=Backend(),
        github=github,
        input_publisher=None,
        observer=None,
        archive=None,
        evaluator=None,
    )

    assert router.execute(decision, observed_at=NOW) == decision
    assert calls == [(decision, github)]


def test_fixed_router_does_not_prepare_an_uncommissioned_external_family() -> None:
    selected = node("archive_validation")
    decision = cloud_coordinator.choose_next_action(
        snapshot(
            selected,
            current_lease=lease(),
            command=claimed_command_for(selected),
        )
    )

    class Backend:
        def prepare_coordinator_effect(self, *args, **kwargs):  # pragma: no cover
            del args, kwargs
            raise AssertionError("uncommissioned service must freeze before state mutation")

    router = coordinator_service._ProtectedCoordinatorEffectRouter._for_testing(
        backend=Backend(),
        github=None,
        input_publisher=None,
        observer=None,
        archive=None,
        evaluator=None,
    )

    with pytest.raises(
        cloud_coordinator.ProtectedEffectUnavailable,
        match="archive_service_uncommissioned",
    ):
        router.execute(decision, observed_at=NOW)


def test_fixed_router_maps_an_unavailable_typed_socket_to_a_durable_freeze() -> None:
    from carl_bench.coordinator_effect_client import CoordinatorEffectClientError

    selected = node("publish_input")
    decision = cloud_coordinator.choose_next_action(
        snapshot(
            selected,
            current_lease=lease(),
            command=claimed_command_for(selected),
        )
    )

    class Backend:
        def prepare_coordinator_effect(self, actual, *, expected_family, observed_at):
            from carl_bench.coordinator_effects import (
                CoordinatorNodeEffectRequest,
                PreparedCoordinatorEffect,
            )

            assert actual == decision
            request = CoordinatorNodeEffectRequest.from_decision(decision)
            return PreparedCoordinatorEffect(expected_family, request)

    class MissingInputService:
        def publish(self, request):
            del request
            raise CoordinatorEffectClientError("input_service_unavailable")

    router = coordinator_service._ProtectedCoordinatorEffectRouter._for_testing(
        backend=Backend(),
        github=None,
        input_publisher=MissingInputService(),
        observer=None,
        archive=None,
        evaluator=None,
    )

    with pytest.raises(
        cloud_coordinator.ProtectedEffectUnavailable,
        match="input_service_uncommissioned",
    ):
        router.execute(decision, observed_at=NOW)
