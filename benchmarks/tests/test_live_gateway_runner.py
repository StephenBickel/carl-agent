from __future__ import annotations

import hashlib
import os
import signal
import socket
import subprocess
import threading
import time
from configparser import ConfigParser
from contextlib import suppress
from pathlib import Path

import pytest

from carl_bench.adapters.carl_acp import BoundedModelGatewayCapability
from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_capability import LiveEvaluationIdentity, LivePairPolicy, LiveTaskIdentity
from carl_bench.live_execution_receipt import (
    ProtectedLiveExecutionResult,
    verify_execution_receipt,
)
from carl_bench.live_gateway_authority import (
    LiveGatewayAuthorityError,
    ProtectedModelGatewayServer,
)
from carl_bench.live_gateway_http import _serve_loopback_listener
from carl_bench.live_gateway_runner import ProtectedLiveGatewayRunner
from carl_bench.live_worker_isolation import (
    CgroupV2WorkerIsolation,
    CgroupV2WorkerScope,
    LiveWorkerIsolationError,
)
from carl_bench.openai_gateway import (
    OpenAIModelRequest,
    OpenAIUsage,
    ProtectedOpenAIModelResult,
    ProviderReconciliationCapability,
    ProviderReconciliationReceipt,
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class _Gateway:
    def __init__(self) -> None:
        self.operation_results: dict[str, ProtectedOpenAIModelResult] = {}

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

    def provider_reconciliation_capability(self) -> ProviderReconciliationCapability:
        return ProviderReconciliationCapability(
            provider="openai-responses-webhook",
            project_digest=_digest("runner-provider-project"),
            protocol_revision="durable-webhook-receipt-v1",
            receipt_authority_digest=_digest("runner-receipt-authority"),
        )

    def dispatch_reconciled(
        self, request: OpenAIModelRequest, operation: object
    ) -> ProtectedOpenAIModelResult:
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
            receipt_digest=_digest(f"runner-receipt:{operation.digest}"),
            result=result,
        )

    def verify_provider_reconciliation(self, receipt: object, operation: object) -> bool:
        return (
            type(receipt) is ProviderReconciliationReceipt
            and receipt.operation_digest == operation.digest
        )


def _checkout(
    root: Path,
    port: int,
    *,
    fork_background: bool = False,
    escape_session: bool = False,
    mutate_checkout: bool = False,
) -> tuple[Path, str, str]:
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
        + (
            "child = os.fork()\n"
            "if child == 0:\n"
            "    os.setsid()\n"
            "    os.close(1)\n"
            "    os.close(2)\n"
            "    open(sys.argv[1], 'w', encoding='utf-8').write(str(os.getpid()))\n"
            "    time.sleep(60)\n"
            "    raise SystemExit(0)\n"
            if escape_session
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
        "assert response.startswith(b'HTTP/1.1 200 OK')\n"
        + (
            "open('post-run-mutation', 'w', encoding='utf-8').write('dirty')\n"
            if mutate_checkout
            else ""
        ),
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
    status = subprocess.run(
        ("ps", "-o", "stat=", "-p", str(process_id)),
        check=False,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return bool(status) and not status.startswith("Z")


class _FakeIsolationScope:
    def __init__(
        self,
        *,
        observed_identity: tuple[int, int] | None = None,
        escaped_pid_path: Path | None = None,
        fail_cleanup: bool = False,
    ) -> None:
        self._observed_identity = observed_identity
        self._escaped_pid_path = escaped_pid_path
        self._fail_cleanup = fail_cleanup
        self.process_id = -1
        self.cleaned = False
        self.attestation_digest = _digest("fake-cgroup-v2-scope")

    def attach_and_observe(
        self, process_id: int, *, expected_uid: int, expected_gid: int
    ) -> tuple[int, int]:
        self.process_id = process_id
        return self._observed_identity or (expected_uid, expected_gid)

    def cleanup_and_verify_empty(self) -> None:
        if self.process_id > 0:
            with suppress(ProcessLookupError, PermissionError):
                os.killpg(self.process_id, signal.SIGKILL)
        if self._escaped_pid_path is not None:
            deadline = time.monotonic() + 2
            while not self._escaped_pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if self._escaped_pid_path.exists():
                escaped = int(self._escaped_pid_path.read_text(encoding="utf-8"))
                with suppress(ProcessLookupError):
                    os.kill(escaped, signal.SIGKILL)
                while _process_exists(escaped) and time.monotonic() < deadline:
                    time.sleep(0.01)
                if _process_exists(escaped):
                    raise LiveWorkerIsolationError("live_worker_isolation_not_empty")
        if self._fail_cleanup:
            raise LiveWorkerIsolationError("live_worker_isolation_not_empty")
        self.cleaned = True

    def receipt_observation(self) -> dict[str, str]:
        return {
            "cgroup_observation_digest": self.attestation_digest,
            "cgroup_path": "/system.slice/carl-live-gateway.service/worker-test",
            "cgroup_unit": "carl-live-gateway.service",
        }


class _FakeIsolation:
    def __init__(self, scope: _FakeIsolationScope | None = None) -> None:
        self.scope = scope or _FakeIsolationScope()

    def begin(self, execution_digest: str) -> _FakeIsolationScope:
        assert len(execution_digest) == 64
        return self.scope


def _case(
    *, endpoint: str, parent_commit: str, parent_tree: str
) -> tuple[LiveEvaluationIdentity, LivePairPolicy, LiveTaskIdentity]:
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
    return identity, policy, task


def test_runner_rejects_same_uid_with_different_gids() -> None:
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_Gateway(),
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token_source=lambda: "runner-owned-token-1234567890",
    )

    with pytest.raises(
        LiveGatewayAuthorityError,
        match="live_gateway_runner_configuration_invalid",
    ):
        ProtectedLiveGatewayRunner._for_testing(
            server=server,
            workers=((62_001, 62_001), (62_001, 62_002)),
            isolation=_FakeIsolation(),
        )


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX executable replacement")
def test_runner_rejects_checkout_replacement_after_observation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}/v1/evaluate"
    executable, parent_commit, parent_tree = _checkout(tmp_path / "parent", port)
    identity, policy, task = _case(
        endpoint=endpoint,
        parent_commit=parent_commit,
        parent_tree=parent_tree,
    )
    marker = tmp_path / "replacement-executed"
    replacement = tmp_path / "replacement"
    replacement.write_text(
        executable.read_text(encoding="utf-8").replace(
            "assert 'OPENAI_API_KEY' not in os.environ",
            f"open({os.fspath(marker)!r}, 'w', encoding='utf-8').write('executed')\n"
            "assert 'OPENAI_API_KEY' not in os.environ",
        ),
        encoding="utf-8",
    )
    replacement.chmod(0o755)
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_Gateway(),
        endpoint=endpoint,
        token_source=lambda: "runner-owned-token-1234567890",
    )
    scope = _FakeIsolationScope()
    runner = ProtectedLiveGatewayRunner._for_testing(
        server=server,
        workers=((os.geteuid(), os.getegid()), (os.geteuid() + 1, os.getegid() + 1)),
        isolation=_FakeIsolation(scope),
    )
    original = ProtectedLiveGatewayRunner._observe_checkout

    def replace_after_observation(cls: type[ProtectedLiveGatewayRunner], **kwargs: object):
        del cls
        observed = original(**kwargs)
        os.replace(replacement, executable)
        return observed

    monkeypatch.setattr(
        ProtectedLiveGatewayRunner,
        "_observe_checkout",
        classmethod(replace_after_observation),
    )
    thread = threading.Thread(
        target=_serve_loopback_listener,
        kwargs={"listener_fd": listener.fileno(), "server": server, "maximum_connections": 1},
        daemon=True,
    )
    thread.start()
    try:
        with pytest.raises(LiveGatewayAuthorityError, match="live_worker_checkout_changed"):
            runner.execute_worker(
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
    assert marker.exists() is False


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX checkout mutation")
def test_runner_invalidates_completed_result_when_checkout_changes_during_execution(
    tmp_path: Path,
) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}/v1/evaluate"
    executable, parent_commit, parent_tree = _checkout(
        tmp_path / "parent", port, mutate_checkout=True
    )
    identity, policy, task = _case(
        endpoint=endpoint,
        parent_commit=parent_commit,
        parent_tree=parent_tree,
    )
    token = "runner-owned-token-1234567890"
    store = SQLiteLiveGatewayStateStore._for_testing(tmp_path / "gateway.sqlite3")
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_Gateway(),
        endpoint=endpoint,
        token_source=lambda: token,
        state=store,
    )
    runner = ProtectedLiveGatewayRunner._for_testing(
        server=server,
        workers=((os.geteuid(), os.getegid()), (os.geteuid() + 1, os.getegid() + 1)),
        isolation=_FakeIsolation(),
    )
    thread = threading.Thread(
        target=_serve_loopback_listener,
        kwargs={"listener_fd": listener.fileno(), "server": server, "maximum_connections": 1},
        daemon=True,
    )
    thread.start()
    try:
        with pytest.raises(LiveGatewayAuthorityError, match="live_worker_checkout_changed"):
            runner.execute_worker(
                identity=identity,
                policy=policy,
                task=task,
                subject="parent",
                attempt=1,
                checkout=tmp_path / "parent",
                executable=executable,
                timeout_seconds=5,
            )
        capability = BoundedModelGatewayCapability(
            endpoint=endpoint,
            token=token,
            pair_request_digest=identity.request_digest,
            subject="parent",
            task_id=task.task_id,
            attempt=1,
        )
        with pytest.raises(LiveGatewayAuthorityError, match="live_gateway_result_unavailable"):
            server.take_completed_result(capability)
        assert store.retry_codes(identity.request_digest, task.task_id, 1) == {
            "parent": "runner_execution_changed"
        }
    finally:
        thread.join(3)
        listener.close()


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX worker execution")
def test_runner_invalidates_result_when_isolation_cannot_verify_empty(tmp_path: Path) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}/v1/evaluate"
    executable, parent_commit, parent_tree = _checkout(tmp_path / "parent", port)
    identity, policy, task = _case(
        endpoint=endpoint,
        parent_commit=parent_commit,
        parent_tree=parent_tree,
    )
    store = SQLiteLiveGatewayStateStore._for_testing(tmp_path / "gateway.sqlite3")
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_Gateway(),
        endpoint=endpoint,
        token_source=lambda: "runner-owned-token-1234567890",
        state=store,
    )
    runner = ProtectedLiveGatewayRunner._for_testing(
        server=server,
        workers=((os.geteuid(), os.getegid()), (os.geteuid() + 1, os.getegid() + 1)),
        isolation=_FakeIsolation(_FakeIsolationScope(fail_cleanup=True)),
    )
    thread = threading.Thread(
        target=_serve_loopback_listener,
        kwargs={"listener_fd": listener.fileno(), "server": server, "maximum_connections": 1},
        daemon=True,
    )
    thread.start()
    try:
        with pytest.raises(LiveGatewayAuthorityError, match="live_worker_isolation_not_empty"):
            runner.execute_worker(
                identity=identity,
                policy=policy,
                task=task,
                subject="parent",
                attempt=1,
                checkout=tmp_path / "parent",
                executable=executable,
                timeout_seconds=5,
            )
        assert store.retry_codes(identity.request_digest, task.task_id, 1) == {
            "parent": "runner_isolation_cleanup_failed"
        }
    finally:
        thread.join(3)
        listener.close()


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
    scope = _FakeIsolationScope()
    runner = ProtectedLiveGatewayRunner._for_testing(
        server=server,
        workers=((os.geteuid(), os.getegid()), (os.geteuid() + 1, os.getegid() + 1)),
        isolation=_FakeIsolation(scope),
        execution_key=b"E" * 32,
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

    assert type(result) is ProtectedLiveExecutionResult
    assert result.model_result.output_text == "runner output"
    receipt = result.execution_receipt
    assert verify_execution_receipt(receipt, key=b"E" * 32) is True
    assert receipt.argv == (os.fspath(executable),)
    assert receipt.timeout_seconds == 5
    assert receipt.executable_inode > 0
    assert receipt.executable_digest == hashlib.sha256(executable.read_bytes()).hexdigest()
    assert receipt.subject_tree == parent_tree
    assert receipt.input_size == task.input_size
    assert (receipt.worker_uid, receipt.worker_gid) == (os.geteuid(), os.getegid())
    assert receipt.cgroup_unit == "carl-live-gateway.service"
    assert receipt.cgroup_path.endswith("/worker-test")
    assert receipt.environment_digest == identity.environment_digest
    assert receipt.model_policy_digest == identity.model_policy_digest
    assert (
        receipt.model_result_digest
        == hashlib.sha256(
            canonical_json_bytes(
                {
                    "latency_ms": result.model_result.latency_ms,
                    "model": result.model_result.model,
                    "output_digest": result.model_result.output_digest,
                    "provenance_tag": result.model_result.provenance_tag,
                    "request_digest": result.model_result.request_digest,
                    "response_id": result.model_result.response_id,
                    "status": result.model_result.status,
                    "usage": {
                        name: getattr(result.model_result.usage, name)
                        for name in result.model_result.usage.__dataclass_fields__
                    },
                }
            )
        ).hexdigest()
    )
    assert server._grant("runner-owned-token-1234567890").actual.isolation_digest == (
        scope.attestation_digest
    )
    assert thread.is_alive() is False


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX worker execution")
def test_runner_exact_request_replays_same_durable_execution_bundle_after_restart(
    tmp_path: Path,
) -> None:
    from carl_bench.live_gateway_store import SQLiteLiveGatewayStateStore

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}/v1/evaluate"
    executable, parent_commit, parent_tree = _checkout(tmp_path / "parent", port)
    identity, policy, task = _case(
        endpoint=endpoint,
        parent_commit=parent_commit,
        parent_tree=parent_tree,
    )
    state_path = tmp_path / "gateway.sqlite3"
    first_server = ProtectedModelGatewayServer._for_testing(
        gateway=_Gateway(),
        endpoint=endpoint,
        token_source=lambda: "runner-owned-token-1234567890",
        state=SQLiteLiveGatewayStateStore._for_testing(state_path),
    )
    first_runner = ProtectedLiveGatewayRunner._for_testing(
        server=first_server,
        workers=((os.geteuid(), os.getegid()), (os.geteuid() + 1, os.getegid() + 1)),
        isolation=_FakeIsolation(),
        execution_key=b"E" * 32,
    )
    thread = threading.Thread(
        target=_serve_loopback_listener,
        kwargs={
            "listener_fd": listener.fileno(),
            "server": first_server,
            "maximum_connections": 1,
        },
        daemon=True,
    )
    thread.start()
    try:
        first = first_runner.execute_worker(
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

    # An exact IPC replay returns the sealed bundle before observing or executing
    # the now-dirty checkout, and it does not require another provider connection.
    (tmp_path / "parent" / "post-delivery-mutation").write_text("dirty", encoding="utf-8")
    replay_scope = _FakeIsolationScope()
    restarted = ProtectedLiveGatewayRunner._for_testing(
        server=ProtectedModelGatewayServer._for_testing(
            gateway=_Gateway(),
            endpoint=endpoint,
            token_source=lambda: "must-not-be-issued-1234567890",
            state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        ),
        workers=((os.geteuid(), os.getegid()), (os.geteuid() + 1, os.getegid() + 1)),
        isolation=_FakeIsolation(replay_scope),
        execution_key=b"E" * 32,
    )

    replayed = restarted.execute_worker(
        identity=identity,
        policy=policy,
        task=task,
        subject="parent",
        attempt=1,
        checkout=tmp_path / "parent",
        executable=executable,
        timeout_seconds=5,
    )

    assert replayed == first
    assert replay_scope.process_id == -1


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX worker execution")
def test_runner_resumes_completed_provider_result_after_preseal_crash_without_redispatch(
    tmp_path: Path,
) -> None:
    from carl_bench.live_gateway_store import (
        LiveGatewayStateError,
        SQLiteLiveGatewayCommissioningReader,
        SQLiteLiveGatewayStateStore,
    )
    from carl_bench.live_runner_ipc import ProtectedLiveRunnerRequest

    class CountingGateway(_Gateway):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        def evaluate(self, request: OpenAIModelRequest) -> ProtectedOpenAIModelResult:
            self.calls += 1
            return super().evaluate(request)

    class CrashBeforeSealState:
        def __init__(self, delegate: object) -> None:
            self._delegate = delegate
            self.bundle: dict[str, object] | None = None

        def __getattr__(self, name: str) -> object:
            return getattr(self._delegate, name)

        def seal_result_bundle(self, *args: object, **kwargs: object) -> object:
            del args
            bundle = kwargs["bundle"]
            assert type(bundle) is dict
            self.bundle = bundle
            raise RuntimeError("crash-before-seal")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}/v1/evaluate"
    executable, parent_commit, parent_tree = _checkout(tmp_path / "parent", port)
    identity, policy, task = _case(
        endpoint=endpoint,
        parent_commit=parent_commit,
        parent_tree=parent_tree,
    )
    state_path = tmp_path / "gateway.sqlite3"
    gateway = CountingGateway()
    durable_state = SQLiteLiveGatewayStateStore._for_testing(state_path)
    crash_state = CrashBeforeSealState(durable_state)
    first_server = ProtectedModelGatewayServer._for_testing(
        gateway=gateway,
        endpoint=endpoint,
        token_source=lambda: "runner-owned-token-1234567890",
        state=crash_state,
    )
    first_scope = _FakeIsolationScope()
    first_runner = ProtectedLiveGatewayRunner._for_testing(
        server=first_server,
        workers=((os.geteuid(), os.getegid()), (os.geteuid() + 1, os.getegid() + 1)),
        isolation=_FakeIsolation(first_scope),
        execution_key=b"E" * 32,
    )
    thread = threading.Thread(
        target=_serve_loopback_listener,
        kwargs={
            "listener_fd": listener.fileno(),
            "server": first_server,
            "maximum_connections": 1,
        },
        daemon=True,
    )
    thread.start()
    try:
        with pytest.raises(RuntimeError, match="crash-before-seal"):
            first_runner.execute_worker(
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

    assert crash_state.bundle is not None
    with pytest.raises(LiveGatewayStateError, match="live_gateway_bundle_conflict"):
        durable_state.seal_result_bundle(
            hashlib.sha256(b"runner-owned-token-1234567890").hexdigest(),
            runner_request_digest=_digest("different-runner-request"),
            bundle=crash_state.bundle,
        )

    commissioned = SQLiteLiveGatewayCommissioningReader._for_testing(state_path).expected_actuals(
        pair_request_digest=identity.request_digest,
        task_id=task.task_id,
        attempt=1,
        subject="parent",
    )
    assert commissioned == (first_scope.process_id, first_scope.attestation_digest)

    replay_scope = _FakeIsolationScope()
    restarted = ProtectedLiveGatewayRunner._for_testing(
        server=ProtectedModelGatewayServer._for_testing(
            gateway=gateway,
            endpoint=endpoint,
            token_source=lambda: "must-not-be-issued-1234567890",
            state=SQLiteLiveGatewayStateStore._for_testing(state_path),
        ),
        workers=((os.geteuid(), os.getegid()), (os.geteuid() + 1, os.getegid() + 1)),
        isolation=_FakeIsolation(replay_scope),
        execution_key=b"E" * 32,
    )

    resumed = restarted.execute_worker(
        identity=identity,
        policy=policy,
        task=task,
        subject="parent",
        attempt=1,
        checkout=tmp_path / "parent",
        executable=executable,
        timeout_seconds=5,
    )

    assert resumed.model_result.output_text == "runner output"
    assert verify_execution_receipt(resumed.execution_receipt, key=b"E" * 32) is True
    runner_request_digest = ProtectedLiveRunnerRequest.create(
        identity=identity,
        policy=policy,
        task=task,
        subject="parent",
        attempt=1,
        checkout=tmp_path / "parent",
        executable=executable,
        timeout_seconds=5,
    ).digest
    assert (
        restarted.gateway_server.seal_resumed_execution_bundle(
            runner_request_digest,
            bundle=resumed,
        )
        == resumed
    )
    assert gateway.calls == 1
    assert replay_scope.process_id == -1


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
        isolation=_FakeIsolation(),
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


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX setsid semantics")
def test_runner_cgroup_isolation_reaps_setsid_escape(tmp_path: Path) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}/v1/evaluate"
    escaped_pid_path = tmp_path / "escaped.pid"
    executable, parent_commit, parent_tree = _checkout(
        tmp_path / "parent", port, escape_session=True
    )
    identity, policy, task = _case(
        endpoint=endpoint,
        parent_commit=parent_commit,
        parent_tree=parent_tree,
    )
    scope = _FakeIsolationScope(escaped_pid_path=escaped_pid_path)
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_Gateway(),
        endpoint=endpoint,
        token_source=lambda: "runner-owned-token-1234567890",
    )
    runner = ProtectedLiveGatewayRunner._for_testing(
        server=server,
        workers=((os.geteuid(), os.getegid()), (os.geteuid() + 1, os.getegid() + 1)),
        isolation=_FakeIsolation(scope),
    )
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
            arguments=(os.fspath(escaped_pid_path),),
            timeout_seconds=5,
        )
        escaped_pid = int(escaped_pid_path.read_text(encoding="utf-8"))
        assert type(result) is ProtectedLiveExecutionResult
        assert scope.cleaned is True
        assert _process_exists(escaped_pid) is False
    finally:
        if escaped_pid_path.exists():
            escaped_pid = int(escaped_pid_path.read_text(encoding="utf-8"))
            if _process_exists(escaped_pid):
                os.kill(escaped_pid, signal.SIGKILL)
        thread.join(3)
        listener.close()


def test_runner_rejects_runtime_worker_identity_mismatch(tmp_path: Path) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    endpoint = f"http://127.0.0.1:{port}/v1/evaluate"
    executable, parent_commit, parent_tree = _checkout(tmp_path / "parent", port)
    identity, policy, task = _case(
        endpoint=endpoint,
        parent_commit=parent_commit,
        parent_tree=parent_tree,
    )
    expected = (os.geteuid(), os.getegid())
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_Gateway(),
        endpoint=endpoint,
        token_source=lambda: "runner-owned-token-1234567890",
    )
    runner = ProtectedLiveGatewayRunner._for_testing(
        server=server,
        workers=(expected, (os.geteuid() + 1, os.getegid() + 1)),
        isolation=_FakeIsolation(
            _FakeIsolationScope(observed_identity=(expected[0] + 10, expected[1]))
        ),
    )
    try:
        with pytest.raises(LiveGatewayAuthorityError, match="live_worker_identity_mismatch"):
            runner.execute_worker(
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
        listener.close()


def test_production_cgroup_isolation_fails_closed_outside_commissioned_service() -> None:
    with pytest.raises(LiveWorkerIsolationError, match="live_worker_isolation_not_commissioned"):
        CgroupV2WorkerIsolation.from_protected_process()


def test_cgroup_cleanup_kills_waits_for_verified_emptiness_and_removes_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scope_path = tmp_path / "worker-test"
    scope_path.mkdir()
    scope = CgroupV2WorkerScope(
        path=scope_path,
        relative="/system.slice/carl-live-gateway.service/worker-test",
        unit="carl-live-gateway.service",
        execution_digest=_digest("execution"),
    )
    writes: list[tuple[Path, str, str | None]] = []
    reads: list[Path] = []
    removed: list[Path] = []
    events = iter(("populated 1\n", "populated 0\n"))

    def write_text(path: Path, data: str, encoding: str | None = None) -> int:
        writes.append((path, data, encoding))
        return len(data)

    def read_bounded(path: Path, *, maximum_bytes: int = 16_384) -> str:
        del maximum_bytes
        reads.append(path)
        return next(events)

    def rmdir(path: Path) -> None:
        removed.append(path)

    monkeypatch.setattr(Path, "write_text", write_text)
    monkeypatch.setattr(Path, "rmdir", rmdir)
    monkeypatch.setattr("carl_bench.live_worker_isolation._read_bounded", read_bounded)
    monkeypatch.setattr("carl_bench.live_worker_isolation.time.sleep", lambda seconds: None)

    scope.cleanup_and_verify_empty()

    assert writes == [(scope_path / "cgroup.kill", "1\n", "ascii")]
    assert reads == [scope_path / "cgroup.events", scope_path / "cgroup.events"]
    assert removed == [scope_path]


def test_cgroup_cleanup_fails_closed_when_scope_remains_populated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scope_path = tmp_path / "worker-stuck"
    scope_path.mkdir()
    scope = CgroupV2WorkerScope(
        path=scope_path,
        relative="/system.slice/carl-live-gateway.service/worker-stuck",
        unit="carl-live-gateway.service",
        execution_digest=_digest("stuck-execution"),
    )
    removed: list[Path] = []
    observed_times = iter((0.0, 6.0))

    monkeypatch.setattr(Path, "write_text", lambda path, data, encoding=None: len(data))
    monkeypatch.setattr(Path, "rmdir", lambda path: removed.append(path))
    monkeypatch.setattr(
        "carl_bench.live_worker_isolation._read_bounded",
        lambda path, maximum_bytes=16_384: "populated 1\n",
    )
    monkeypatch.setattr(
        "carl_bench.live_worker_isolation.time.monotonic", lambda: next(observed_times)
    )

    with pytest.raises(LiveWorkerIsolationError, match="live_worker_isolation_not_empty"):
        scope.cleanup_and_verify_empty()

    assert removed == []


def test_live_gateway_systemd_contract_commissions_runner_ipc_and_delegated_cgroup_v2() -> None:
    systemd_root = Path(__file__).parents[2] / "infra/autonomy/systemd"
    service = ConfigParser(interpolation=None, strict=True)
    service.optionxform = str
    socket_unit = ConfigParser(interpolation=None, strict=True)
    socket_unit.optionxform = str
    runner_socket = ConfigParser(interpolation=None, strict=True)
    runner_socket.optionxform = str

    assert service.read(systemd_root / "carl-live-gateway.service")
    assert socket_unit.read(systemd_root / "carl-live-gateway.socket")
    assert runner_socket.read(systemd_root / "carl-live-runner.socket")
    assert service["Unit"]["Requires"] == ("carl-live-gateway.socket carl-live-runner.socket")
    assert service["Service"] == {
        "Type": "simple",
        "ExecStart": "/opt/carl/venv/bin/carl-live-gateway-service",
        "EnvironmentFile": "/etc/carl/live-gateway.env",
        "User": "root",
        "Group": "root",
        "Delegate": "pids",
        "TasksMax": "256",
        "NoNewPrivileges": "yes",
        "PrivateDevices": "yes",
        "PrivateTmp": "yes",
        "ProtectControlGroups": "no",
        "ProtectHome": "yes",
        "ProtectKernelModules": "yes",
        "ProtectKernelTunables": "yes",
        "ProtectSystem": "strict",
        "ReadOnlyPaths": "/srv/carl/checkouts",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        "RuntimeDirectory": "carl-live-gateway",
        "RuntimeDirectoryMode": "0700",
        "StateDirectory": "carl/live-gateway",
        "StateDirectoryMode": "0700",
        "UMask": "0077",
    }
    assert socket_unit["Socket"] == {
        "FileDescriptorName": "live-gateway",
        "ListenStream": "127.0.0.1:43117",
        "NoDelay": "true",
        "Service": "carl-live-gateway.service",
    }
    assert runner_socket["Socket"] == {
        "FileDescriptorName": "live-runner",
        "ListenStream": "/run/carl/live-runner.sock",
        "SocketGroup": "root",
        "SocketMode": "0600",
        "Service": "carl-live-gateway.service",
    }


def test_gateway_service_requires_exact_two_socket_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from carl_bench import live_gateway_service

    environment = {
        "LISTEN_PID": str(os.getpid()),
        "LISTEN_FDS": "2",
        "LISTEN_FDNAMES": "live-gateway:live-runner",
    }
    monkeypatch.setattr(live_gateway_service.os, "get_inheritable", lambda fd: fd in {3, 4})

    assert live_gateway_service._activation_descriptors(
        environment=environment,
        process_id=os.getpid(),
    ) == (3, 4)

    environment["LISTEN_FDNAMES"] = "live-runner:live-gateway"
    with pytest.raises(RuntimeError, match="live_gateway_service_activation_invalid"):
        live_gateway_service._activation_descriptors(
            environment=environment,
            process_id=os.getpid(),
        )


def test_gateway_listener_contains_connection_reset_and_keeps_accepting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from carl_bench import live_gateway_http

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    server = ProtectedModelGatewayServer._for_testing(
        gateway=_Gateway(),
        endpoint=f"http://127.0.0.1:{port}/v1/evaluate",
        token_source=lambda: "unused-listener-token-1234567890",
    )
    calls = 0

    def flaky_connection(connection: socket.socket, actual_server: object) -> None:
        nonlocal calls
        del connection
        assert actual_server is server
        calls += 1
        if calls == 1:
            raise ConnectionResetError("client reset")

    monkeypatch.setattr(live_gateway_http, "_serve_connection", flaky_connection)
    thread = threading.Thread(
        target=live_gateway_http._serve_loopback_listener,
        kwargs={
            "listener_fd": listener.fileno(),
            "server": server,
            "maximum_connections": 2,
        },
        daemon=True,
    )
    thread.start()
    try:
        for _ in range(2):
            with socket.create_connection(("127.0.0.1", port), timeout=2):
                pass
        thread.join(3)
    finally:
        listener.close()

    assert calls == 2
    assert thread.is_alive() is False


def test_gateway_listener_thread_failure_is_fatal_to_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from carl_bench import live_gateway_service

    def fail_listener(**kwargs: object) -> None:
        del kwargs
        raise RuntimeError("listener died")

    monkeypatch.setattr(live_gateway_service, "_serve_loopback_listener", fail_listener)
    monitor = live_gateway_service._start_gateway_listener(
        listener_fd=3,
        server=object(),
    )
    assert monitor.failed.wait(2)

    with pytest.raises(RuntimeError, match="live_gateway_listener_failed") as raised:
        monitor.check()

    assert isinstance(raised.value.__cause__, RuntimeError)


def test_provider_reconciler_advances_expired_claims_without_runner_request() -> None:
    from carl_bench import live_gateway_service

    called = threading.Event()

    class Server:
        def reconcile_expired_provider_operations(self) -> tuple[str, ...]:
            called.set()
            return (_digest("expired-provider-operation"),)

    monitor = live_gateway_service._start_provider_reconciler(
        server=Server(), interval_seconds=0.01
    )
    try:
        assert called.wait(1)
        monitor.check()
    finally:
        monitor.close()


def test_provider_reconciler_failure_is_service_fatal() -> None:
    from carl_bench import live_gateway_service

    failed = threading.Event()

    class Server:
        def reconcile_expired_provider_operations(self) -> tuple[str, ...]:
            failed.set()
            raise RuntimeError("reconciliation-state-unavailable")

    monitor = live_gateway_service._start_provider_reconciler(
        server=Server(), interval_seconds=0.01
    )
    try:
        assert failed.wait(1)
        monitor.thread.join(1)
        with pytest.raises(RuntimeError, match="live_gateway_reconciler_failed"):
            monitor.check()
    finally:
        monitor.close()


def test_runner_listener_failure_interrupts_an_inflight_worker_promptly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from carl_bench import live_runner_service

    server_connection, client_connection = socket.socketpair()
    entered = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []

    class OneConnectionListener:
        def settimeout(self, timeout: float) -> None:
            assert timeout <= 0.5

        def accept(self) -> tuple[socket.socket, object]:
            return server_connection, None

    def blocking_connection(connection: socket.socket, *, runner: object) -> None:
        del connection, runner
        entered.set()
        release.wait(5)

    def health_check() -> None:
        if entered.is_set():
            raise RuntimeError("gateway-listener-died-inflight")

    monkeypatch.setattr(live_runner_service, "_serve_connection", blocking_connection)

    def serve() -> None:
        try:
            live_runner_service._serve_runner_listener(
                listener=OneConnectionListener(),  # type: ignore[arg-type]
                allowed_client_uid=os.geteuid(),
                runner=object(),
                maximum_connections=1,
                health_check=health_check,
            )
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=serve, daemon=True)
    started_at = time.monotonic()
    thread.start()
    try:
        assert entered.wait(1)
        thread.join(1)
        assert thread.is_alive() is False
        assert time.monotonic() - started_at < 1.5
        assert len(errors) == 1
        assert str(errors[0]) == "gateway-listener-died-inflight"
    finally:
        release.set()
        thread.join(3)
        client_connection.close()
        with suppress(OSError):
            server_connection.close()
