from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import socket
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


def test_consumed_failed_model_call_can_be_durably_classified_for_pair_retry() -> None:
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

    server.record_infrastructure_invalid(capability.token, "openai_timeout")


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
