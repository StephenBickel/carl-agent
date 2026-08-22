from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import socket
from datetime import UTC, datetime, timedelta
from inspect import signature

import pytest

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_capability import (
    LiveEvaluationIdentity,
    LivePairPolicy,
    LiveTaskIdentity,
)
from carl_bench.live_gateway_authority import (
    ActualLiveExecution,
    LiveGatewayAuthorityError,
    ProtectedModelGatewayServer,
)
from carl_bench.live_gateway_http import _serve_loopback_listener
from carl_bench.openai_gateway import (
    OpenAIGatewayError,
    OpenAIModelRequest,
    OpenAIModelResult,
    OpenAIUsage,
    ProtectedOpenAIModelResult,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _policy_document() -> dict[str, str]:
    return {
        "model": "gpt-5.2",
        "policy_revision": "openai-responses-policy-2026-08-20.1",
        "reasoning_policy": "medium/no-summary",
    }


def _identity() -> LiveEvaluationIdentity:
    return LiveEvaluationIdentity.create(
        repository="StephenBickel/carl-agent",
        parent_commit="1" * 40,
        parent_tree="2" * 40,
        candidate_commit="3" * 40,
        candidate_tree="4" * 40,
        experiment_digest=_digest("experiment"),
        workflow_revision="5" * 40,
        workflow_digest=_digest("workflow"),
        task_set_digest=_digest("task-set"),
        metric_pack_digest=_digest("metric-pack"),
        policy_digest=_digest("policy"),
        model_policy_digest=hashlib.sha256(canonical_json_bytes(_policy_document())).hexdigest(),
        grader_digest=_digest("grader"),
        environment_digest=_digest("environment"),
        model="gpt-5.2",
        reasoning_policy="medium/no-summary",
        tool_protocol_revision="acp-v2/bounded-openai-v1",
        task_order=("held",),
        seeds=(41, 42),
        attempts=2,
    )


def _policy() -> LivePairPolicy:
    return LivePairPolicy(
        maximum_pair_retries=1,
        maximum_total_cost_microdollars=50_000,
        maximum_trial_latency_ms=30_000,
        input_cost_microdollars_per_million_tokens=5_000_000,
        cached_input_cost_microdollars_per_million_tokens=1_000_000,
        output_cost_microdollars_per_million_tokens=10_000_000,
        minimum_aggregate_gain_basis_points=500,
        minimum_held_out_gain_basis_points=1,
        require_affected_improvement=True,
        require_guard_non_regression=True,
    )


def _task() -> LiveTaskIdentity:
    prompt = "held-out prompt"
    return LiveTaskIdentity(
        task_id="held",
        task_digest=_digest("held-task"),
        input_digest=hashlib.sha256(prompt.encode()).hexdigest(),
        input_size=len(prompt.encode()),
        grader_digest=_digest("grader"),
        role="held_out",
    )


def _actual(
    identity: LiveEvaluationIdentity,
    policy: LivePairPolicy,
    task: LiveTaskIdentity,
    *,
    subject: str = "candidate",
    attempt: int = 1,
) -> ActualLiveExecution:
    seed = identity.seeds[attempt - 1]
    return ActualLiveExecution(
        repository=identity.repository,
        pair_request_digest=identity.request_digest,
        subject=subject,
        subject_commit=(
            identity.parent_commit if subject == "parent" else identity.candidate_commit
        ),
        subject_tree=identity.parent_tree if subject == "parent" else identity.candidate_tree,
        task_id=task.task_id,
        task_digest=task.task_digest,
        input_digest=task.input_digest,
        input_size=task.input_size,
        grader_digest=task.grader_digest,
        task_role=task.role,
        seed=seed,
        attempt=attempt,
        environment_digest=identity.environment_digest,
        model=identity.model,
        reasoning_policy=identity.reasoning_policy,
        live_policy_digest=hashlib.sha256(
            canonical_json_bytes(policy.to_canonical_dict())
        ).hexdigest(),
        execution_context_digest=identity.execution_context_digest(
            subject=subject,
            task=task,
            policy=policy,
            seed=seed,
            attempt=attempt,
        ),
    )


class _PinnedGateway:
    def __init__(self) -> None:
        self.requests: list[OpenAIModelRequest] = []

    def protected_execution_policy(self) -> dict[str, str]:
        return _policy_document()

    def evaluate(self, request: OpenAIModelRequest) -> ProtectedOpenAIModelResult:
        self.requests.append(request)
        return ProtectedOpenAIModelResult(
            response_id="resp-protected",
            model="gpt-5.2",
            status="completed",
            usage=OpenAIUsage(3, 0, 2, 1, 5),
            latency_ms=10,
            request_digest=request.request_digest,
            output_digest=_digest("output"),
            output_text="bounded result",
            provenance_tag=_digest("protected-service-owned-tag"),
        )

    def verify_protected_result(self, result: object) -> bool:
        return type(result) is ProtectedOpenAIModelResult


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("pair_request_digest", "f" * 64),
        ("subject", "parent"),
        ("subject_commit", "8" * 40),
        ("subject_tree", "9" * 40),
        ("task_id", "other"),
        ("task_digest", "a" * 64),
        ("input_digest", "b" * 64),
        ("input_size", 1),
        ("grader_digest", "c" * 64),
        ("task_role", "guard"),
        ("seed", 99),
        ("attempt", 2),
        ("environment_digest", "d" * 64),
        ("model", "gpt-5.1"),
        ("reasoning_policy", "high/no-summary"),
        ("live_policy_digest", "e" * 64),
        ("execution_context_digest", "0" * 64),
    ),
)
def test_server_rejects_any_actual_execution_binding_mutation(field: str, value: object) -> None:
    identity = _identity()
    policy = _policy()
    task = _task()
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_PinnedGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "pair-task-token-1234567890",
    )

    with pytest.raises(LiveGatewayAuthorityError, match="live_execution_binding_mismatch"):
        server.issue_observed_capability_for_testing(
            identity=identity,
            policy=policy,
            task=task,
            subject="candidate",
            attempt=1,
            observed_overrides={field: value},
        )


def test_gateway_capability_cannot_be_issued_from_caller_declared_execution() -> None:
    """The protected runner, not a caller-supplied dataclass, must own process observation."""
    assert "actual" not in signature(ProtectedModelGatewayServer.issue_capability).parameters
    with pytest.raises(LiveGatewayAuthorityError, match="live_execution_observation_protected"):
        _actual(_identity(), _policy(), _task())


def test_gateway_result_lifecycle_survives_server_restart(tmp_path) -> None:
    """Removing the durable store must lose the completed result after reconstruction."""
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    identity = _identity()
    policy = _policy()
    task = _task()
    store = SQLiteLiveGatewayStateStore._for_testing(tmp_path / "gateway.sqlite3")
    first = ProtectedModelGatewayServer._for_testing(
        gateway=_PinnedGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "pair-task-token-1234567890",
        state=store,
    )
    capability = first.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="candidate",
        attempt=1,
    )
    evaluated = first.evaluate(capability.token, "held-out prompt")

    restarted = ProtectedModelGatewayServer._for_testing(
        gateway=_PinnedGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "unused-restart-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(tmp_path / "gateway.sqlite3"),
    )

    assert restarted.take_completed_result(capability) == evaluated
    with pytest.raises(LiveGatewayAuthorityError, match="live_gateway_result_consumed"):
        restarted.take_completed_result(capability)


def test_protected_gateway_runner_has_supervised_entrypoint_and_owns_process_execution() -> None:
    from importlib.metadata import entry_points

    from carl_bench.live_gateway_runner import ProtectedLiveGatewayRunner

    assert "actual" not in signature(ProtectedModelGatewayServer.issue_capability).parameters
    assert (
        "process_launcher"
        not in signature(ProtectedLiveGatewayRunner.from_protected_process).parameters
    )
    entry = next(
        item
        for item in entry_points(group="console_scripts")
        if item.name == "carl-live-gateway-service"
    )
    assert entry.load().__module__ == "carl_bench.live_gateway_service"


def test_server_consumes_exact_capability_once_and_owns_model_request() -> None:
    identity = _identity()
    policy = _policy()
    task = _task()
    gateway = _PinnedGateway()
    tokens = iter(("pair-task-token-1234567890", "pair-task-token-1234567891"))
    server = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: next(tokens),
    )
    capability = server.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="candidate",
        attempt=1,
    )

    result = server.evaluate(capability.token, "held-out prompt")

    assert type(result) is ProtectedOpenAIModelResult
    assert len(gateway.requests) == 1
    request = gateway.requests[0]
    assert request.execution_context_digest == identity.execution_context_digest(
        subject="candidate", task=task, policy=policy, seed=41, attempt=1
    )
    assert request.request_digest == identity.model_request_digest(
        subject="candidate", task=task, policy=policy, seed=41, attempt=1
    )
    with pytest.raises(LiveGatewayAuthorityError, match="live_gateway_capability_consumed"):
        server.evaluate(capability.token, "held-out prompt")
    parent_capability = server.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="parent",
        attempt=1,
    )
    with pytest.raises(LiveGatewayAuthorityError, match="live_gateway_input_mismatch"):
        server.evaluate(parent_capability.token, "changed prompt")


def test_protected_evaluator_collects_authenticated_result_once_by_exact_capability() -> None:
    identity = _identity()
    policy = _policy()
    task = _task()
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_PinnedGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "pair-task-token-1234567890",
    )
    capability = server.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="candidate",
        attempt=1,
    )
    evaluated = server.evaluate(capability.token, "held-out prompt")

    collected = server.take_completed_result(capability)

    assert collected == evaluated
    with pytest.raises(LiveGatewayAuthorityError, match="live_gateway_result_consumed"):
        server.take_completed_result(capability)


def test_retry_capability_requires_exact_pair_scoped_infrastructure_failure() -> None:
    identity = _identity()
    policy = _policy()
    task = _task()
    tokens = iter(
        (
            "parent-task-token-1234567890",
            "candidate-task-token-1234567890",
            "retry-task-token-1234567890",
        )
    )
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_PinnedGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: next(tokens),
    )
    parent = server.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="parent",
        attempt=1,
    )
    candidate = server.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="candidate",
        attempt=1,
    )

    with pytest.raises(LiveGatewayAuthorityError, match="live_retry_not_authorized"):
        server.issue_observed_capability_for_testing(
            identity=identity,
            policy=policy,
            task=task,
            subject="candidate",
            attempt=2,
        )
    server.record_infrastructure_invalid(parent.token, "runner_internal_error")
    server.record_infrastructure_invalid(candidate.token, "runner_internal_error")
    retry = server.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="candidate",
        attempt=2,
    )
    assert retry.attempt == 2


def test_failed_model_call_after_dispatch_freezes_until_exact_reconciliation() -> None:
    class FailingGateway(_PinnedGateway):
        def evaluate(self, request: OpenAIModelRequest) -> ProtectedOpenAIModelResult:
            del request
            raise OpenAIGatewayError("openai_timeout")

    identity = _identity()
    policy = _policy()
    task = _task()
    server = ProtectedModelGatewayServer._for_testing(
        gateway=FailingGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "failed-model-token-1234567890",
    )
    capability = server.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="parent",
        attempt=1,
    )

    with pytest.raises(LiveGatewayAuthorityError, match="openai_timeout"):
        server.evaluate(capability.token, "held-out prompt")

    with pytest.raises(LiveGatewayAuthorityError, match="live_gateway_dispatch_ambiguous"):
        server.evaluate(capability.token, "held-out prompt")
    with pytest.raises(
        LiveGatewayAuthorityError,
        match="live_infrastructure_result_conflict",
    ):
        server.record_infrastructure_invalid(capability.token, "openai_timeout")
    assert server._state.retry_codes(identity.request_digest, task.task_id, 1) == {}


def test_crash_after_provider_claim_never_replays_provider_without_reconciliation(
    tmp_path,
) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    class SimulatedCrash(BaseException):
        pass

    class CrashingGateway(_PinnedGateway):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def evaluate(self, request: OpenAIModelRequest) -> ProtectedOpenAIModelResult:
            self.calls += 1
            raise SimulatedCrash

    state_path = tmp_path / "gateway.sqlite3"
    gateway = CrashingGateway()
    first = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "crash-window-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
    )
    capability = first.issue_observed_capability_for_testing(
        identity=_identity(),
        policy=_policy(),
        task=_task(),
        subject="candidate",
        attempt=1,
    )

    with pytest.raises(SimulatedCrash):
        first.evaluate(capability.token, "held-out prompt")

    restarted_gateway = _PinnedGateway()
    restarted = ProtectedModelGatewayServer._for_testing(
        gateway=restarted_gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "unused-restart-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
    )
    with pytest.raises(LiveGatewayAuthorityError, match="live_gateway_capability_in_progress"):
        restarted.evaluate(capability.token, "held-out prompt")
    assert gateway.calls == 1
    assert restarted_gateway.requests == []


def test_expired_post_dispatch_claim_freezes_pair_without_duplicate_provider_calls(
    tmp_path,
) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    class SimulatedCrash(BaseException):
        pass

    class CrashingGateway(_PinnedGateway):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def evaluate(self, request: OpenAIModelRequest) -> ProtectedOpenAIModelResult:
            del request
            self.calls += 1
            raise SimulatedCrash

    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    state_path = tmp_path / "gateway.sqlite3"
    tokens = iter(("parent-crash-token-1234567890", "candidate-crash-token-1234567890"))
    store = SQLiteLiveGatewayStateStore._for_testing(state_path)
    crashing_gateway = CrashingGateway()
    first = ProtectedModelGatewayServer._for_testing(
        gateway=crashing_gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: next(tokens),
        state=store,
        clock=lambda: now,
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_001, "100"),
        process_identity=lambda process_id: "100" if process_id == 61_001 else None,
    )
    identity = _identity()
    policy = _policy()
    task = _task()
    parent = first.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="parent",
        attempt=1,
    )
    candidate = first.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="candidate",
        attempt=1,
    )
    with pytest.raises(SimulatedCrash):
        first.evaluate(parent.token, "held-out prompt")
    with pytest.raises(SimulatedCrash):
        first.evaluate(candidate.token, "held-out prompt")

    replacement_gateway = _PinnedGateway()
    restarted = ProtectedModelGatewayServer._for_testing(
        gateway=replacement_gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "retry-after-crash-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now + timedelta(minutes=2),
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_002, "200"),
        process_identity=lambda process_id: "200" if process_id == 61_002 else None,
    )

    assert store.retry_codes(identity.request_digest, task.task_id, 1) == {}
    for capability in (parent, candidate):
        with pytest.raises(LiveGatewayAuthorityError, match="live_gateway_dispatch_ambiguous"):
            restarted.evaluate(capability.token, "held-out prompt")
        with pytest.raises(
            LiveGatewayAuthorityError,
            match="live_infrastructure_result_conflict",
        ):
            restarted.record_infrastructure_invalid(
                capability.token,
                "gateway_dispatch_ambiguous",
            )
        with pytest.raises(
            LiveGatewayAuthorityError,
            match="live_infrastructure_result_conflict",
        ):
            restarted.invalidate_execution(
                capability.token,
                "gateway_dispatch_ambiguous",
            )
    for subject in ("parent", "candidate"):
        with pytest.raises(LiveGatewayAuthorityError, match="live_retry_not_authorized"):
            restarted.issue_observed_capability_for_testing(
                identity=identity,
                policy=policy,
                task=task,
                subject=subject,
                attempt=2,
            )
    assert crashing_gateway.calls == 2
    assert replacement_gateway.requests == []


def test_dispatched_claim_cannot_be_reclassified_as_retryable_infrastructure_failure(
    tmp_path,
) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    identity = _identity()
    policy = _policy()
    task = _task()
    store = SQLiteLiveGatewayStateStore._for_testing(tmp_path / "gateway.sqlite3")
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_PinnedGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "dispatched-token-1234567890",
        state=store,
        clock=lambda: now,
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_001, "100"),
        process_identity=lambda process_id: "100" if process_id == 61_001 else None,
    )
    capability = server.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="candidate",
        attempt=1,
    )
    token_digest = hashlib.sha256(capability.token.encode()).hexdigest()
    claim_id = _digest("dispatched-claim")
    store.claim_grant(
        token_digest,
        claim_id=claim_id,
        boot_id="11111111-1111-4111-8111-111111111111",
        process_id=61_001,
        process_start="100",
        started_at=int(now.timestamp()),
        expires_at=int(now.timestamp()) + 60,
    )
    store.mark_provider_dispatched(
        token_digest,
        claim_id,
        request_digest=identity.model_request_digest(
            subject="candidate",
            task=task,
            policy=policy,
            seed=identity.seeds[0],
            attempt=1,
        ),
        dispatched_at=int(now.timestamp()),
    )

    for operation in (server.record_infrastructure_invalid, server.invalidate_execution):
        with pytest.raises(
            LiveGatewayAuthorityError,
            match="live_infrastructure_result_conflict",
        ):
            operation(capability.token, "runner_exit_nonzero")
    assert store.retry_codes(identity.request_digest, task.task_id, 1) == {}


def test_dead_pre_dispatch_pair_authorizes_exactly_one_retry(tmp_path) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    state_path = tmp_path / "gateway.sqlite3"
    identity = _identity()
    policy = _policy()
    task = _task()
    first_tokens = iter(
        ("parent-pre-dispatch-token-1234567890", "candidate-pre-dispatch-token-1234567890")
    )
    store = SQLiteLiveGatewayStateStore._for_testing(state_path)
    first = ProtectedModelGatewayServer._for_testing(
        gateway=_PinnedGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: next(first_tokens),
        state=store,
        clock=lambda: now,
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_001, "100"),
        process_identity=lambda process_id: "100" if process_id == 61_001 else None,
    )
    capabilities = tuple(
        first.issue_observed_capability_for_testing(
            identity=identity,
            policy=policy,
            task=task,
            subject=subject,
            attempt=1,
        )
        for subject in ("parent", "candidate")
    )
    for capability in capabilities:
        store.claim_grant(
            hashlib.sha256(capability.token.encode()).hexdigest(),
            claim_id=_digest(f"pre-dispatch-{capability.subject}"),
            boot_id="11111111-1111-4111-8111-111111111111",
            process_id=61_001,
            process_start="100",
            started_at=int(now.timestamp()),
            expires_at=int(now.timestamp()) + 60,
        )

    retry_tokens = iter(
        (
            "parent-retry-token-1234567890",
            "candidate-retry-token-1234567890",
            "parent-duplicate-retry-token-1234567890",
            "candidate-duplicate-retry-token-1234567890",
        )
    )
    restarted = ProtectedModelGatewayServer._for_testing(
        gateway=_PinnedGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: next(retry_tokens),
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now + timedelta(minutes=2),
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_002, "200"),
        process_identity=lambda process_id: None,
    )

    assert store.retry_codes(identity.request_digest, task.task_id, 1) == {
        "candidate": "gateway_pre_dispatch_abandoned",
        "parent": "gateway_pre_dispatch_abandoned",
    }
    retries = tuple(
        restarted.issue_observed_capability_for_testing(
            identity=identity,
            policy=policy,
            task=task,
            subject=subject,
            attempt=2,
        )
        for subject in ("parent", "candidate")
    )
    assert [capability.attempt for capability in retries] == [2, 2]
    for subject in ("parent", "candidate"):
        with pytest.raises(LiveGatewayAuthorityError, match="live_gateway_capability_duplicate"):
            restarted.issue_observed_capability_for_testing(
                identity=identity,
                policy=policy,
                task=task,
                subject=subject,
                attempt=2,
            )


def test_ambiguous_dispatch_requires_exact_authenticated_provider_result_reconciliation(
    tmp_path,
) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    class SimulatedCrash(BaseException):
        pass

    class CrashingGateway(_PinnedGateway):
        def evaluate(self, request: OpenAIModelRequest) -> ProtectedOpenAIModelResult:
            del request
            raise SimulatedCrash

    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    state_path = tmp_path / "gateway.sqlite3"
    identity = _identity()
    policy = _policy()
    task = _task()
    first = ProtectedModelGatewayServer._for_testing(
        gateway=CrashingGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "reconcile-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now,
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_001, "100"),
        process_identity=lambda process_id: "100" if process_id == 61_001 else None,
    )
    capability = first.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="candidate",
        attempt=1,
    )
    with pytest.raises(SimulatedCrash):
        first.evaluate(capability.token, "held-out prompt")

    restarted = ProtectedModelGatewayServer._for_testing(
        gateway=_PinnedGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "unused-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now + timedelta(minutes=2),
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_002, "200"),
        process_identity=lambda process_id: None,
    )
    expected_request = identity.model_request_digest(
        subject="candidate",
        task=task,
        policy=policy,
        seed=identity.seeds[0],
        attempt=1,
    )
    recovered = ProtectedOpenAIModelResult(
        response_id="resp-recovered-exact",
        model="gpt-5.2",
        status="completed",
        usage=OpenAIUsage(3, 0, 2, 1, 5),
        latency_ms=10,
        request_digest=expected_request,
        output_digest=_digest("recovered-output"),
        output_text="recovered exact output",
        provenance_tag=_digest("recovered-provenance"),
    )

    restarted.reconcile_provider_result(capability.token, recovered)

    assert restarted.take_completed_result(capability) == recovered


def test_expired_claim_with_same_live_process_identity_remains_in_progress(tmp_path) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    class SimulatedCrash(BaseException):
        pass

    class CrashingGateway(_PinnedGateway):
        def evaluate(self, request: OpenAIModelRequest) -> ProtectedOpenAIModelResult:
            del request
            raise SimulatedCrash

    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    state_path = tmp_path / "gateway.sqlite3"
    first = ProtectedModelGatewayServer._for_testing(
        gateway=CrashingGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "live-holder-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now,
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_001, "100"),
        process_identity=lambda process_id: "100" if process_id == 61_001 else None,
    )
    capability = first.issue_observed_capability_for_testing(
        identity=_identity(),
        policy=_policy(),
        task=_task(),
        subject="candidate",
        attempt=1,
    )
    with pytest.raises(SimulatedCrash):
        first.evaluate(capability.token, "held-out prompt")

    restarted = ProtectedModelGatewayServer._for_testing(
        gateway=_PinnedGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "unused-restart-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now + timedelta(minutes=2),
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_002, "200"),
        process_identity=lambda process_id: "100" if process_id == 61_001 else None,
    )
    with pytest.raises(LiveGatewayAuthorityError, match="live_gateway_capability_in_progress"):
        restarted.evaluate(capability.token, "held-out prompt")


def test_gateway_authority_rejects_synthetic_model_result() -> None:
    class _SyntheticGateway(_PinnedGateway):
        def evaluate(self, request: OpenAIModelRequest) -> OpenAIModelResult:
            protected = super().evaluate(request)
            return OpenAIModelResult(
                **{
                    name: getattr(protected, name)
                    for name in OpenAIModelResult.__dataclass_fields__
                }
            )

    identity = _identity()
    policy = _policy()
    task = _task()
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_SyntheticGateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "pair-task-token-1234567890",
    )
    capability = server.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="candidate",
        attempt=1,
    )

    with pytest.raises(LiveGatewayAuthorityError, match="live_model_provenance_invalid"):
        server.evaluate(capability.token, "held-out prompt")


def _http_request(port: int, token: str) -> tuple[int, bytes]:
    body = canonical_json_bytes({"input": "held-out prompt"})
    request = (
        b"POST /v1/evaluate HTTP/1.1\r\n"
        + f"Host: 127.0.0.1:{port}\r\n".encode()
        + f"Authorization: Bearer {token}\r\n".encode()
        + b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + body
    )
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.sendall(request)
        chunks: list[bytes] = []
        while chunk := connection.recv(65_536):
            chunks.append(chunk)
    response = b"".join(chunks)
    head, payload = response.split(b"\r\n\r\n", 1)
    status = int(head.split(b" ", 2)[1])
    return status, payload


def _serve_gateway_process(
    listener: socket.socket,
    server: ProtectedModelGatewayServer,
    ready: object,
) -> None:
    _serve_loopback_listener(
        listener_fd=listener.fileno(),
        server=server,
        maximum_connections=2,
        on_ready=ready.set,
    )


@pytest.mark.skipif(os.name == "nt", reason="requires inherited loopback listener")
def test_separate_http_process_consumes_opaque_capability_once_without_provenance_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    policy = _policy()
    task = _task()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    gateway = _PinnedGateway()
    server = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint=f"http://127.0.0.1:{port}/v1/evaluate",
        token_source=lambda: "pair-task-token-1234567890",
    )
    capability = server.issue_observed_capability_for_testing(
        identity=identity,
        policy=policy,
        task=task,
        subject="candidate",
        attempt=1,
    )
    context = multiprocessing.get_context("fork")
    ready = context.Event()
    process = context.Process(
        target=_serve_gateway_process,
        args=(listener, server, ready),
    )
    process.start()
    try:
        assert ready.wait(2)
        from carl_bench import live_gateway_authority

        monkeypatch.setattr(live_gateway_authority, "ProtectedModelGatewayServer", object())

        first_status, first_payload = _http_request(port, capability.token)
        second_status, second_payload = _http_request(port, capability.token)

        assert first_status == 200
        assert json.loads(first_payload) == {
            "output_text": "bounded result",
            "request_digest": identity.model_request_digest(
                subject="candidate", task=task, policy=policy, seed=41, attempt=1
            ),
            "status": "completed",
        }
        assert b"provenance" not in first_payload.lower()
        assert b"policy" not in first_payload.lower()
        assert second_status == 409
        assert json.loads(second_payload) == {"error": "live_gateway_capability_consumed"}
    finally:
        process.join(3)
        if process.is_alive():
            process.terminate()
            process.join(2)
        listener.close()
    assert process.exitcode == 0
