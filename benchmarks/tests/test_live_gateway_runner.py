from __future__ import annotations

import hashlib
import os
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_capability import LiveEvaluationIdentity, LivePairPolicy, LiveTaskIdentity
from carl_bench.live_gateway_authority import ProtectedModelGatewayServer
from carl_bench.live_gateway_http import _serve_loopback_listener
from carl_bench.live_gateway_runner import ProtectedLiveGatewayRunner
from carl_bench.openai_gateway import (
    OpenAIModelRequest,
    OpenAIUsage,
    ProtectedOpenAIModelResult,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class _Gateway:
    def protected_execution_policy(self) -> dict[str, str]:
        return {
            "model": "gpt-5.2",
            "policy_revision": "openai-responses-policy-2026-08-20.1",
            "reasoning_policy": "medium/no-summary",
        }

    def evaluate(self, request: OpenAIModelRequest) -> ProtectedOpenAIModelResult:
        return ProtectedOpenAIModelResult(
            response_id="resp-runner",
            model="gpt-5.2",
            status="completed",
            usage=OpenAIUsage(3, 0, 2, 1, 5),
            latency_ms=7,
            request_digest=request.request_digest,
            output_digest=_digest("runner-output"),
            output_text="runner output",
            provenance_tag=_digest("runner-provenance"),
        )

    def verify_protected_result(self, result: object) -> bool:
        return type(result) is ProtectedOpenAIModelResult


def _checkout(root: Path, port: int, *, fork_background: bool = False) -> tuple[Path, str, str]:
    root.mkdir()
    executable = root / "subject"
    executable.write_text(
        "#!/usr/bin/python3\n"
        "import json, os, socket, sys, time, urllib.parse\n"
        + (
            "child = os.fork()\n"
            "if child == 0:\n"
            "    open(sys.argv[1], 'w', encoding='utf-8').write(str(os.getpid()))\n"
            "    time.sleep(60)\n"
            "    raise SystemExit(0)\n"
            if fork_background
            else ""
        )
        + "assert 'OPENAI_API_KEY' not in os.environ\n"
        "assert 'CARL_OPENAI_PROVENANCE_KEY_B64' not in os.environ\n"
        "target = urllib.parse.urlsplit(os.environ['CARL_MODEL_GATEWAY_ENDPOINT'])\n"
        "body = json.dumps({'input':'held-out prompt'}, separators=(',', ':')).encode()\n"
        "request = (\n"
        "    b'POST /v1/evaluate HTTP/1.1\\r\\n'\n"
        "    + f'Host: 127.0.0.1:{target.port}\\r\\n'.encode()\n"
        "    + f\"Authorization: Bearer {os.environ['CARL_MODEL_GATEWAY_TOKEN']}\\r\\n\".encode()\n"
        "    + b'Content-Type: application/json\\r\\n'\n"
        "    + f'Content-Length: {len(body)}\\r\\n'.encode()\n"
        "    + b'Connection: close\\r\\n\\r\\n' + body\n"
        ")\n"
        "with socket.create_connection(('127.0.0.1', target.port), timeout=2) as connection:\n"
        "    connection.sendall(request)\n"
        "    response = b''\n"
        "    while True:\n"
        "        chunk = connection.recv(65536)\n"
        "        if not chunk: break\n"
        "        response += chunk\n"
        "assert response.startswith(b'HTTP/1.1 200 OK')\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    subprocess.run(("git", "init", "-q"), cwd=root, check=True)
    subprocess.run(("git", "config", "user.email", "carl@example.invalid"), cwd=root, check=True)
    subprocess.run(("git", "config", "user.name", "Carl Test"), cwd=root, check=True)
    subprocess.run(("git", "add", "subject"), cwd=root, check=True)
    subprocess.run(("git", "commit", "-qm", "subject"), cwd=root, check=True)
    commit = subprocess.run(
        ("git", "rev-parse", "HEAD^{commit}"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ("git", "rev-parse", "HEAD^{tree}"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return executable, commit, tree


def _process_exists(process_id: int) -> bool:
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    return True


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX exec and descriptor semantics")
def test_runner_owns_launch_observation_capability_and_cross_process_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}/v1/evaluate"
    executable, parent_commit, parent_tree = _checkout(tmp_path / "parent", port)
    policy_document = _Gateway().protected_execution_policy()
    identity = LiveEvaluationIdentity.create(
        repository="StephenBickel/carl-agent",
        parent_commit=parent_commit,
        parent_tree=parent_tree,
        candidate_commit="2" * 40,
        candidate_tree="3" * 40,
        experiment_digest=_digest("experiment"),
        workflow_revision="4" * 40,
        workflow_digest=_digest("workflow"),
        task_set_digest=_digest("task-set"),
        metric_pack_digest=_digest("metric-pack"),
        policy_digest=_digest("policy"),
        model_policy_digest=hashlib.sha256(canonical_json_bytes(policy_document)).hexdigest(),
        grader_digest=_digest("grader"),
        environment_digest=ProtectedLiveGatewayRunner.environment_digest(endpoint),
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
        task_digest=_digest("held-task"),
        input_digest=hashlib.sha256(b"held-out prompt").hexdigest(),
        input_size=len(b"held-out prompt"),
        grader_digest=_digest("grader"),
        role="held_out",
    )
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_Gateway(),
        endpoint=endpoint,
        token_source=lambda: "runner-owned-token-1234567890",
    )
    runner = ProtectedLiveGatewayRunner._for_testing(
        server=server,
        workers=((os.geteuid(), os.getegid()), (os.geteuid() + 1, os.getegid() + 1)),
    )
    monkeypatch.setenv("OPENAI_API_KEY", "sk-protected-secret-visible-to-candidate")
    monkeypatch.setenv("CARL_OPENAI_PROVENANCE_KEY_B64", "protected-provenance-secret")
    thread = threading.Thread(
        target=_serve_loopback_listener,
        kwargs={"listener_fd": listener.fileno(), "server": server, "maximum_connections": 1},
        daemon=True,
    )
    thread.start()
    try:
        result = runner.execute_worker(
            identity=identity,
            policy=policy,
            task=task,
            subject="parent",
            attempt=1,
            checkout=tmp_path / "parent",
            executable=executable,
            timeout_seconds=5,
        )
    finally:
        thread.join(3)
        listener.close()

    assert type(result) is ProtectedOpenAIModelResult
    assert result.output_text == "runner output"
    assert thread.is_alive() is False


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX process-group semantics")
def test_runner_reaps_candidate_background_process_tree(
    tmp_path: Path,
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}/v1/evaluate"
    executable, parent_commit, parent_tree = _checkout(
        tmp_path / "parent", port, fork_background=True
    )
    policy_document = _Gateway().protected_execution_policy()
    identity = LiveEvaluationIdentity.create(
        repository="StephenBickel/carl-agent",
        parent_commit=parent_commit,
        parent_tree=parent_tree,
        candidate_commit="2" * 40,
        candidate_tree="3" * 40,
        experiment_digest=_digest("experiment"),
        workflow_revision="4" * 40,
        workflow_digest=_digest("workflow"),
        task_set_digest=_digest("task-set"),
        metric_pack_digest=_digest("metric-pack"),
        policy_digest=_digest("policy"),
        model_policy_digest=hashlib.sha256(canonical_json_bytes(policy_document)).hexdigest(),
        grader_digest=_digest("grader"),
        environment_digest=ProtectedLiveGatewayRunner.environment_digest(endpoint),
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
        task_digest=_digest("held-task"),
        input_digest=hashlib.sha256(b"held-out prompt").hexdigest(),
        input_size=len(b"held-out prompt"),
        grader_digest=_digest("grader"),
        role="held_out",
    )
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_Gateway(),
        endpoint=endpoint,
        token_source=lambda: "runner-owned-token-1234567890",
    )
    runner = ProtectedLiveGatewayRunner._for_testing(
        server=server,
        workers=((os.geteuid(), os.getegid()), (os.geteuid() + 1, os.getegid() + 1)),
    )
    pid_path = tmp_path / "background.pid"
    thread = threading.Thread(
        target=_serve_loopback_listener,
        kwargs={"listener_fd": listener.fileno(), "server": server, "maximum_connections": 1},
        daemon=True,
    )
    thread.start()
    child_pid = -1
    try:
        runner.execute_worker(
            identity=identity,
            policy=policy,
            task=task,
            subject="parent",
            attempt=1,
            checkout=tmp_path / "parent",
            executable=executable,
            arguments=(os.fspath(pid_path),),
            timeout_seconds=5,
        )
        child_pid = int(pid_path.read_text(encoding="utf-8"))
        deadline = time.monotonic() + 2
        while _process_exists(child_pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert _process_exists(child_pid) is False
    finally:
        if child_pid > 0 and _process_exists(child_pid):
            os.kill(child_pid, signal.SIGKILL)
        thread.join(3)
        listener.close()
