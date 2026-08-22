from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import socket
import sqlite3
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
    ProviderOperationIdentity,
    ProviderReconciliationCapability,
    ProviderReconciliationReceipt,
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
        self.operations: list[object] = []
        self.operation_results: dict[str, ProtectedOpenAIModelResult] = {}

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

    def provider_reconciliation_capability(self) -> ProviderReconciliationCapability:
        return ProviderReconciliationCapability(
            provider="openai-responses-webhook",
            project_digest=_digest("protected-provider-project"),
            protocol_revision="durable-webhook-receipt-v1",
            receipt_authority_digest=_digest("protected-webhook-authority"),
        )

    def dispatch_reconciled(
        self, request: OpenAIModelRequest, operation: object
    ) -> ProtectedOpenAIModelResult:
        self.operations.append(operation)
        result = self.evaluate(request)
        self.operation_results[operation.digest] = result
        return result

    def reconcile_provider_operation(
        self, request: OpenAIModelRequest, operation: object
    ) -> ProviderReconciliationReceipt:
        result = self.operation_results.get(operation.digest)
        return ProviderReconciliationReceipt(
            operation_digest=operation.digest,
            request_digest=request.request_digest,
            status="completed" if result is not None else "pending",
            receipt_digest=_digest(
                f"receipt:{operation.digest}:{'completed' if result is not None else 'pending'}"
            ),
            result=result,
        )

    def verify_provider_reconciliation(self, receipt: object, operation: object) -> bool:
        return (
            type(receipt) is ProviderReconciliationReceipt
            and receipt.operation_digest == operation.digest
        )


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


def test_ambiguous_dispatch_rejects_result_without_durable_provider_receipt(
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

    with pytest.raises(
        LiveGatewayAuthorityError,
        match="live_gateway_provider_receipt_required",
    ):
        restarted.reconcile_provider_result(capability.token, recovered)

    with pytest.raises(LiveGatewayAuthorityError, match="live_gateway_result_unavailable"):
        restarted.take_completed_result(capability)


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


def test_post_provider_precommit_crash_is_recovered_from_authenticated_receipt(
    tmp_path,
) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    class SimulatedCrash(BaseException):
        pass

    class CrashBeforeLocalCommit:
        def __init__(self, delegate: object) -> None:
            self.delegate = delegate

        def __getattr__(self, name: str) -> object:
            return getattr(self.delegate, name)

        def complete_result(self, *args: object, **kwargs: object) -> None:
            del args, kwargs
            raise SimulatedCrash

    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    state_path = tmp_path / "gateway.sqlite3"
    identity = _identity()
    policy = _policy()
    task = _task()
    gateway = _PinnedGateway()
    durable = SQLiteLiveGatewayStateStore._for_testing(state_path)
    first = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "precommit-crash-token-1234567890",
        state=CrashBeforeLocalCommit(durable),
        clock=lambda: now,
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_001, "100"),
        process_identity=lambda process_id: "100" if process_id == 61_001 else None,
    )
    capability = first._issue_observed_capability(
        identity=identity,
        policy=policy,
        task=task,
        actual=first._expected_actual(
            identity=identity,
            policy=policy,
            task=task,
            subject="candidate",
            attempt=1,
        ),
        runner_request_digest=_digest("exact-runner-request"),
        runner_context={},
    )

    with pytest.raises(SimulatedCrash):
        first.evaluate(capability.token, "held-out prompt")

    operation = gateway.operations[0]
    assert operation.runner_binding_kind == "runner_request"
    assert operation.runner_binding_digest == _digest("exact-runner-request")
    assert operation.project_digest == _digest("protected-provider-project")
    assert operation.model == "gpt-5.2"
    assert operation.attempt == 1
    assert operation.request_digest == identity.model_request_digest(
        subject="candidate",
        task=task,
        policy=policy,
        seed=identity.seeds[0],
        attempt=1,
    )
    assert (
        operation.immutable_inputs_digest
        == hashlib.sha256(gateway.requests[0].to_bytes()).hexdigest()
    )
    token_digest = hashlib.sha256(capability.token.encode()).hexdigest()
    assert (
        operation.grant_digest
        == hashlib.sha256(canonical_json_bytes(durable.load_grant(token_digest))).hexdigest()
    )

    restarted = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "unused-restart-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now + timedelta(minutes=2),
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_002, "200"),
        process_identity=lambda process_id: None,
    )

    recovered = restarted.take_completed_result(capability)
    assert recovered.output_text == "bounded result"
    assert len(gateway.requests) == 1


def test_lost_provider_response_is_recovered_without_a_second_create(tmp_path) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    class LostResponseGateway(_PinnedGateway):
        def dispatch_reconciled(
            self, request: OpenAIModelRequest, operation: object
        ) -> ProtectedOpenAIModelResult:
            super().dispatch_reconciled(request, operation)
            raise OpenAIGatewayError("openai_create_ambiguous")

    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    state_path = tmp_path / "gateway.sqlite3"
    gateway = LostResponseGateway()
    first = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "lost-response-token-1234567890",
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

    with pytest.raises(LiveGatewayAuthorityError, match="openai_create_ambiguous"):
        first.evaluate(capability.token, "held-out prompt")

    restarted = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "unused-restart-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now + timedelta(minutes=2),
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_002, "200"),
        process_identity=lambda process_id: None,
    )

    assert restarted.take_completed_result(capability).output_text == "bounded result"
    assert len(gateway.requests) == 1


def test_unverified_provider_receipt_freezes_without_accepting_result(tmp_path) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    class UnverifiedReceiptGateway(_PinnedGateway):
        def dispatch_reconciled(
            self, request: OpenAIModelRequest, operation: object
        ) -> ProtectedOpenAIModelResult:
            super().dispatch_reconciled(request, operation)
            raise OpenAIGatewayError("openai_create_ambiguous")

        def verify_provider_reconciliation(self, receipt: object, operation: object) -> bool:
            del receipt, operation
            return False

    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    state_path = tmp_path / "gateway.sqlite3"
    gateway = UnverifiedReceiptGateway()
    identity = _identity()
    task = _task()
    first = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "unverified-receipt-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now,
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_001, "100"),
        process_identity=lambda process_id: "100" if process_id == 61_001 else None,
    )
    capability = first.issue_observed_capability_for_testing(
        identity=identity,
        policy=_policy(),
        task=task,
        subject="candidate",
        attempt=1,
    )
    with pytest.raises(LiveGatewayAuthorityError, match="openai_create_ambiguous"):
        first.evaluate(capability.token, "held-out prompt")

    restarted = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "unused-unverified-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now + timedelta(minutes=2),
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_002, "200"),
        process_identity=lambda process_id: None,
    )

    with pytest.raises(LiveGatewayAuthorityError, match="live_gateway_result_unavailable"):
        restarted.take_completed_result(capability)
    store = SQLiteLiveGatewayStateStore._for_testing(state_path)
    assert store.retry_codes(identity.request_digest, task.task_id, 1) == {
        "candidate": "gateway_provider_reconciliation_invalid"
    }


def test_reconciliation_revalidates_operation_against_durable_runner_binding(tmp_path) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    class LostResponseGateway(_PinnedGateway):
        def dispatch_reconciled(
            self, request: OpenAIModelRequest, operation: object
        ) -> ProtectedOpenAIModelResult:
            super().dispatch_reconciled(request, operation)
            raise OpenAIGatewayError("openai_create_ambiguous")

    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    state_path = tmp_path / "gateway.sqlite3"
    gateway = LostResponseGateway()
    identity = _identity()
    policy = _policy()
    task = _task()
    first = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "operation-tamper-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now,
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_001, "100"),
        process_identity=lambda process_id: "100" if process_id == 61_001 else None,
    )
    capability = first._issue_observed_capability(
        identity=identity,
        policy=policy,
        task=task,
        actual=first._expected_actual(
            identity=identity,
            policy=policy,
            task=task,
            subject="candidate",
            attempt=1,
        ),
        runner_request_digest=_digest("durable-runner-request"),
        runner_context={},
    )
    with pytest.raises(LiveGatewayAuthorityError, match="openai_create_ambiguous"):
        first.evaluate(capability.token, "held-out prompt")

    original = gateway.operations[0]
    forged = ProviderOperationIdentity(
        **{
            **{
                key: value
                for key, value in original.binding_dict().items()
                if key != "schema_version"
            },
            "runner_binding_digest": _digest("forged-runner-request"),
        }
    )
    with sqlite3.connect(state_path) as connection:
        connection.execute(
            "UPDATE gateway_grants SET provider_operation_json = ?",
            (canonical_json_bytes(forged.to_canonical_dict()).decode(),),
        )

    ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "unused-operation-tamper-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now + timedelta(minutes=2),
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_002, "200"),
        process_identity=lambda process_id: None,
    )

    store = SQLiteLiveGatewayStateStore._for_testing(state_path)
    assert store.retry_codes(identity.request_digest, task.task_id, 1) == {
        "candidate": "gateway_provider_operation_binding_invalid"
    }


def test_provider_proven_not_executed_allows_one_bounded_dispatch(tmp_path) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    class ProvenNotExecutedGateway(_PinnedGateway):
        def __init__(self) -> None:
            super().__init__()
            self.dispatch_attempts = 0

        def dispatch_reconciled(
            self, request: OpenAIModelRequest, operation: object
        ) -> ProtectedOpenAIModelResult:
            self.dispatch_attempts += 1
            if self.dispatch_attempts == 1:
                raise OpenAIGatewayError("openai_provider_unavailable")
            return super().dispatch_reconciled(request, operation)

        def reconcile_provider_operation(
            self, request: OpenAIModelRequest, operation: object
        ) -> ProviderReconciliationReceipt:
            return ProviderReconciliationReceipt(
                operation_digest=operation.digest,
                request_digest=request.request_digest,
                status="not_executed",
                receipt_digest=_digest(f"not-executed:{operation.digest}"),
            )

    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    state_path = tmp_path / "gateway.sqlite3"
    gateway = ProvenNotExecutedGateway()
    first = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "not-executed-token-1234567890",
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
    with pytest.raises(LiveGatewayAuthorityError, match="openai_provider_unavailable"):
        first.evaluate(capability.token, "held-out prompt")

    restarted = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "unused-restart-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now + timedelta(minutes=2),
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_002, "200"),
        process_identity=lambda process_id: None,
    )

    assert restarted.take_completed_result(capability).output_text == "bounded result"
    assert gateway.dispatch_attempts == 2
    assert len(gateway.requests) == 1


def test_repeated_proven_not_executed_freezes_after_one_bounded_retry(tmp_path) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    class NeverExecutedGateway(_PinnedGateway):
        def __init__(self) -> None:
            super().__init__()
            self.dispatch_attempts = 0

        def dispatch_reconciled(
            self, request: OpenAIModelRequest, operation: object
        ) -> ProtectedOpenAIModelResult:
            del request, operation
            self.dispatch_attempts += 1
            raise OpenAIGatewayError("openai_provider_unavailable")

        def reconcile_provider_operation(
            self, request: OpenAIModelRequest, operation: object
        ) -> ProviderReconciliationReceipt:
            return ProviderReconciliationReceipt(
                operation_digest=operation.digest,
                request_digest=request.request_digest,
                status="not_executed",
                receipt_digest=_digest(f"never-executed:{operation.digest}"),
            )

    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    state_path = tmp_path / "gateway.sqlite3"
    gateway = NeverExecutedGateway()
    identity = _identity()
    task = _task()
    first = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "retry-exhaustion-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now,
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_001, "100"),
        process_identity=lambda process_id: "100" if process_id == 61_001 else None,
    )
    capability = first.issue_observed_capability_for_testing(
        identity=identity,
        policy=_policy(),
        task=task,
        subject="candidate",
        attempt=1,
    )
    with pytest.raises(LiveGatewayAuthorityError, match="openai_provider_unavailable"):
        first.evaluate(capability.token, "held-out prompt")

    ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "unused-restart-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now + timedelta(minutes=2),
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_002, "200"),
        process_identity=lambda process_id: None,
    )
    ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "unused-second-restart-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now + timedelta(minutes=4),
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_003, "300"),
        process_identity=lambda process_id: None,
    )

    store = SQLiteLiveGatewayStateStore._for_testing(state_path)
    assert gateway.dispatch_attempts == 2
    assert store.retry_codes(identity.request_digest, task.task_id, 1) == {
        "candidate": "gateway_provider_retry_exhausted"
    }


def test_pending_reconciliation_becomes_terminal_after_bounded_observations(tmp_path) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    class PendingGateway(_PinnedGateway):
        def __init__(self) -> None:
            super().__init__()
            self.dispatch_attempts = 0

        def dispatch_reconciled(
            self, request: OpenAIModelRequest, operation: object
        ) -> ProtectedOpenAIModelResult:
            del request, operation
            self.dispatch_attempts += 1
            raise OpenAIGatewayError("openai_create_ambiguous")

    now = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    state_path = tmp_path / "gateway.sqlite3"
    gateway = PendingGateway()
    identity = _identity()
    task = _task()
    first = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "pending-reconciliation-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        clock=lambda: now,
        claim_holder=("11111111-1111-4111-8111-111111111111", 61_001, "100"),
        process_identity=lambda process_id: "100" if process_id == 61_001 else None,
    )
    capability = first.issue_observed_capability_for_testing(
        identity=identity,
        policy=_policy(),
        task=task,
        subject="candidate",
        attempt=1,
    )
    with pytest.raises(LiveGatewayAuthorityError, match="openai_create_ambiguous"):
        first.evaluate(capability.token, "held-out prompt")

    for index, minutes in enumerate((2, 4, 6), start=2):
        ProtectedModelGatewayServer._for_testing(
            gateway=gateway,
            endpoint="http://127.0.0.1:43117/v1/evaluate",
            token_source=lambda: "unused-pending-token-1234567890",
            state=SQLiteLiveGatewayStateStore._for_testing(state_path),
            clock=lambda minutes=minutes: now + timedelta(minutes=minutes),
            claim_holder=(
                "11111111-1111-4111-8111-111111111111",
                61_000 + index,
                str(index * 100),
            ),
            process_identity=lambda process_id: None,
        )

    store = SQLiteLiveGatewayStateStore._for_testing(state_path)
    assert store.retry_codes(identity.request_digest, task.task_id, 1) == {
        "candidate": "gateway_provider_reconciliation_exhausted"
    }
    assert gateway.dispatch_attempts == 1


def test_unsupported_provider_freezes_before_any_create() -> None:
    class UnsupportedGateway(_PinnedGateway):
        def provider_reconciliation_capability(self) -> None:
            return None

    identity = _identity()
    task = _task()
    gateway = UnsupportedGateway()
    server = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "unsupported-provider-token-1234567890",
    )
    capability = server.issue_observed_capability_for_testing(
        identity=identity,
        policy=_policy(),
        task=task,
        subject="candidate",
        attempt=1,
    )

    with pytest.raises(
        LiveGatewayAuthorityError,
        match="live_gateway_provider_reconciliation_unsupported",
    ):
        server.evaluate(capability.token, "held-out prompt")

    assert gateway.requests == []
    assert server._state.retry_codes(identity.request_digest, task.task_id, 1) == {
        "candidate": "gateway_provider_reconciliation_unsupported"
    }


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
