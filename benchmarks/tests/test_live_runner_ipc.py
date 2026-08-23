from __future__ import annotations

import hashlib
import os
import shutil
import socket
import tempfile
import threading
from importlib.metadata import entry_points
from pathlib import Path

import pytest

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_capability import LiveEvaluationIdentity, LivePairPolicy, LiveTaskIdentity
from carl_bench.live_execution_receipt import (
    ProtectedLiveExecutionResult,
    sign_execution_receipt,
)
from carl_bench.live_runner_client import ProtectedLiveRunnerSocketClient
from carl_bench.live_runner_ipc import (
    LiveRunnerProtocolError,
    ProtectedLiveRunnerRequest,
    decode_response,
)
from carl_bench.live_runner_service import _serve_runner_listener
from carl_bench.openai_gateway import OpenAIUsage, ProtectedOpenAIModelResult


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _request(checkout: Path) -> ProtectedLiveRunnerRequest:
    policy_document = {
        "model": "gpt-5.2",
        "policy_revision": "openai-responses-policy-2026-08-20.1",
        "reasoning_policy": "medium/no-summary",
    }
    identity = LiveEvaluationIdentity.create(
        repository="StephenBickel/carl-agent",
        parent_commit="1" * 40,
        parent_tree="2" * 40,
        candidate_commit="3" * 40,
        candidate_tree="4" * 40,
        experiment_digest=_digest("experiment"),
        workflow_revision="5" * 40,
        workflow_digest=_digest("workflow"),
        task_set_digest=_digest("tasks"),
        metric_pack_digest=_digest("metrics"),
        policy_digest=_digest("policy"),
        model_policy_digest=hashlib.sha256(canonical_json_bytes(policy_document)).hexdigest(),
        grader_digest=_digest("grader"),
        environment_digest=_digest("environment"),
        model="gpt-5.2",
        reasoning_policy="medium/no-summary",
        tool_protocol_revision="acp-v2/bounded-openai-v1",
        task_order=("held",),
        seeds=(41,),
        attempts=1,
    )
    policy = LivePairPolicy(0, 50_000, 30_000, 5_000_000, 1_000_000, 10_000_000, 0, 0, False, False)
    task = LiveTaskIdentity(
        task_id="held",
        task_digest=_digest("task"),
        input_digest=hashlib.sha256(b"held-out prompt").hexdigest(),
        input_size=15,
        grader_digest=_digest("grader"),
        role="held_out",
    )
    return ProtectedLiveRunnerRequest.create(
        identity=identity,
        policy=policy,
        task=task,
        subject="parent",
        attempt=1,
        checkout=checkout,
        executable=checkout / "carl",
        arguments=("--bounded-live",),
        timeout_seconds=30,
    )


def _bundle(request: ProtectedLiveRunnerRequest) -> ProtectedLiveExecutionResult:
    model_result = ProtectedOpenAIModelResult(
        response_id="resp-runner-ipc",
        model=request.identity.model,
        status="completed",
        usage=OpenAIUsage(3, 0, 2, 1, 5),
        latency_ms=7,
        request_digest=request.identity.model_request_digest(
            subject=request.subject,
            task=request.task,
            policy=request.policy,
            seed=request.identity.seeds[0],
            attempt=request.attempt,
        ),
        output_digest=_digest("output"),
        output_text="bounded output",
        provenance_tag=_digest("provenance"),
    )
    from carl_bench.live_execution_receipt import model_result_digest

    receipt = sign_execution_receipt(
        fields={
            "argv": (os.fspath(request.executable), *request.arguments),
            "timeout_seconds": request.timeout_seconds,
            "repository": request.identity.repository,
            "pair_request_digest": request.identity.request_digest,
            "subject": request.subject,
            "subject_commit": request.identity.parent_commit,
            "subject_tree": request.identity.parent_tree,
            "task_id": request.task.task_id,
            "task_digest": request.task.task_digest,
            "input_digest": request.task.input_digest,
            "input_size": request.task.input_size,
            "grader_digest": request.task.grader_digest,
            "task_role": request.task.role,
            "seed": request.identity.seeds[0],
            "attempt": request.attempt,
            "environment_digest": request.identity.environment_digest,
            "model": request.identity.model,
            "reasoning_policy": request.identity.reasoning_policy,
            "model_policy_digest": request.identity.model_policy_digest,
            "live_policy_digest": hashlib.sha256(
                canonical_json_bytes(request.policy.to_canonical_dict())
            ).hexdigest(),
            "execution_context_digest": request.identity.execution_context_digest(
                subject=request.subject,
                task=request.task,
                policy=request.policy,
                seed=request.identity.seeds[0],
                attempt=request.attempt,
            ),
            "process_id": 62001,
            "worker_uid": 62001,
            "worker_gid": 62001,
            "executable_device": 1,
            "executable_inode": 2,
            "executable_size": 3,
            "executable_mode": 0o100755,
            "executable_mtime_ns": 4,
            "executable_digest": _digest("executable"),
            "checkout_device": 5,
            "checkout_inode": 6,
            "checkout_digest": _digest("checkout"),
            "cgroup_unit": "carl-live-gateway.service",
            "cgroup_path": "/system.slice/carl-live-gateway.service/worker-test",
            "cgroup_observation_digest": _digest("cgroup"),
            "model_result_digest": model_result_digest(model_result),
            "model_request_digest": model_result.request_digest,
            "model_output_digest": model_result.output_digest,
            "response_id": model_result.response_id,
        },
        key=b"E" * 32,
    )
    return ProtectedLiveExecutionResult(model_result, receipt)


@pytest.mark.skipif(os.name == "nt", reason="requires Unix peer credentials")
def test_credential_free_runner_client_reaches_protected_execute_worker_and_restarts(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path / "checkout")

    class Runner:
        def __init__(self) -> None:
            self.requests: list[ProtectedLiveRunnerRequest] = []

        def execute_worker(self, **kwargs: object) -> ProtectedLiveExecutionResult:
            self.requests.append(ProtectedLiveRunnerRequest.create(**kwargs))
            return _bundle(self.requests[-1])

    runner = Runner()
    socket_root = Path(
        tempfile.mkdtemp(
            prefix="carl-runner-", dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp"
        )
    )
    socket_root.chmod(0o700)
    try:
        for generation in (1, 2):
            socket_path = socket_root / f"r{generation}.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o600)
            listener.listen(1)
            thread = threading.Thread(
                target=_serve_runner_listener,
                kwargs={
                    "listener": listener,
                    "allowed_client_uid": os.getuid(),
                    "runner": runner,
                    "maximum_connections": 1,
                },
                daemon=True,
            )
            thread.start()
            try:
                result = ProtectedLiveRunnerSocketClient._for_testing(
                    socket_path=socket_path,
                    expected_peer_uid=os.getuid(),
                    timeout_seconds=2,
                ).execute(request)
            finally:
                thread.join(3)
                listener.close()
            assert result == _bundle(request)
            assert thread.is_alive() is False
    finally:
        shutil.rmtree(socket_root)

    assert runner.requests == [request, request]
    scripts = {item.name: item.value for item in entry_points(group="console_scripts")}
    assert scripts["carl-live-runner"] == "carl_bench.live_runner_client:main"


def test_runner_protocol_rejects_completed_response_without_execution_bundle() -> None:
    payload = canonical_json_bytes(
        {
            "error_code": None,
            "request_digest": _digest("request"),
            "result": None,
            "schema_version": 1,
            "status": "completed",
        }
    )

    with pytest.raises(LiveRunnerProtocolError, match="live_runner_response_invalid"):
        decode_response(payload, request_digest=_digest("request"))


def test_runner_protocol_rejects_noncanonical_argument_shape(tmp_path: Path) -> None:
    document = _request(tmp_path / "checkout").to_canonical_dict()
    document["arguments"] = "--bounded-live"

    with pytest.raises(LiveRunnerProtocolError, match="live_runner_request_invalid"):
        ProtectedLiveRunnerRequest.from_bytes(canonical_json_bytes(document))
