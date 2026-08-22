from __future__ import annotations

import hashlib
import importlib
import json
import multiprocessing
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
from contextlib import suppress
from inspect import getmembers, isfunction, signature
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from carl_bench.cloud_state import CloudCommand, CommandClaim, CommandState
from carl_bench.github_promotion import APPROVED_REQUIRED_CHECKS

NOW = "2026-08-21T12:00:00Z"
SHA = "2" * 40
DIGEST = "a" * 64
SECRET = "github_pat_REAL_PROTECTED_TOKEN"
MAX_FRAME_BYTES = 262_144

_OPERATION_BINDINGS = {
    "create_experimental_ref": (
        "ExperimentalBranchRequest",
        "create_or_reconcile_experimental_branch",
    ),
    "create_pull_request": ("PullRequestCreateRequest", "create_or_reconcile_pull_request"),
    "create_revert_pull_request": (
        "RevertPullRequestRequest",
        "create_or_reconcile_revert_pull_request",
    ),
    "create_revert_ref": ("RevertBranchRequest", "create_or_reconcile_revert_branch"),
    "dispatch_workflow": ("CloudRunRequest", "dispatch_workflow"),
    "enable_pull_request_auto_merge": (
        "PullRequestAutoMergeRequest",
        "enable_pull_request_auto_merge",
    ),
    "mark_pull_request_ready": ("PullRequestReadyRequest", "mark_pull_request_ready"),
    "observe_required_checks": ("RequiredChecksRequest", "observe_required_checks"),
    "update_pull_request": ("PullRequestUpdateRequest", "update_pull_request"),
}

_PACKAGED_ENTRYPOINT_SCRIPT = r"""
from datetime import UTC, datetime
from importlib.metadata import entry_points
from pathlib import Path
from types import SimpleNamespace
import fcntl
import importlib
import os
import sys

if os.environ.get("CARL_TEST_ACTIVATED") != "1":
    source_listener = int(os.environ.pop("CARL_TEST_LISTENER_FD"))
    source_extra_text = os.environ.pop("CARL_TEST_EXTRA_FD", "")
    source_extra = int(source_extra_text) if source_extra_text else None
    listener_copy = fcntl.fcntl(source_listener, fcntl.F_DUPFD_CLOEXEC, 10)
    extra_copy = (
        fcntl.fcntl(source_extra, fcntl.F_DUPFD_CLOEXEC, 10)
        if source_extra is not None
        else None
    )
    os.close(source_listener)
    if source_extra is not None:
        os.close(source_extra)
    os.dup2(listener_copy, 3, inheritable=True)
    os.close(listener_copy)
    if extra_copy is not None:
        os.dup2(extra_copy, 4, inheritable=True)
        os.close(extra_copy)
    os.environ.update(
        CARL_TEST_ACTIVATED="1",
        LISTEN_PID=str(os.getpid()),
        LISTEN_FDS="1",
        LISTEN_FDNAMES="github-effect",
    )
    script = os.environ["CARL_TEST_ENTRYPOINT_SCRIPT"]
    os.execve(sys.executable, [sys.executable, "-c", script, sys.argv[1]], os.environ)

ordinary_runtime_fd = os.open(os.devnull, os.O_RDONLY)
assert not os.get_inheritable(ordinary_runtime_fd)
entrypoint = next(
    entry
    for entry in entry_points(group="console_scripts")
    if entry.name == "carl-github-effect-service"
)
main = entrypoint.load()
service = importlib.import_module("carl_bench.github_effect_service")
github = service._github_cloud()
now = datetime.fromisoformat("2026-08-21T12:00:00+00:00")

class RejectingState:
    def resolve_claimed_command(self, *args, **kwargs):
        del args, kwargs
        raise github.GitHubCloudError("github_command_not_found")

class GatewayFactory:
    @staticmethod
    def _construct_test_gateway(**kwargs):
        del kwargs
        return object()

github._load_protected_policy = lambda: SimpleNamespace(
    repository="StephenBickel/carl-agent",
    workflow_ref="main",
    dispatch_actor_login="carl-autonomy[bot]",
)
github._ProtectedStateControllerClient = RejectingState
github._InjectedGitHubCloudGateway = GatewayFactory
github._ProtectedGitHubTransport = object
github._system_clock = lambda: now
os.environ[github._PROTECTED_TOKEN_ENV] = "test-protected-token"
service._SOCKET_PATH = Path(sys.argv[1])
service._protected_graphql_documents = object
serve = service._serve_activated_listener

def serve_as_test_uid(**kwargs):
    kwargs["allowed_client_uid"] = os.getuid()
    kwargs["service_uid"] = os.getuid()
    return serve(**kwargs)

service._serve_activated_listener = serve_as_test_uid
raise SystemExit(main())
"""


class _DurableRejectingState:
    def __init__(self, calls: object) -> None:
        self.calls = calls

    def resolve_claimed_command(self, *args: object, **kwargs: object) -> object:
        del args, kwargs
        with self.calls.get_lock():
            self.calls.value += 1
        github = importlib.import_module("carl_bench.github_cloud")
        raise github.GitHubCloudError("github_command_not_found")


def _run_real_listener(
    listener: socket.socket, socket_path: str, ready: object, calls: object
) -> None:
    service = importlib.import_module("carl_bench.github_effect_service")
    now = __import__("datetime").datetime.fromisoformat("2026-08-21T12:00:00+00:00")
    service._serve_activated_listener(
        listener_fd=listener.fileno(),
        socket_path=Path(socket_path),
        allowed_client_uid=os.getuid(),
        service_uid=os.getuid(),
        gateway=object(),
        policy=SimpleNamespace(
            repository="StephenBickel/carl-agent",
            workflow_ref="main",
            dispatch_actor_login="carl-autonomy[bot]",
        ),
        state_controller=_DurableRejectingState(calls),
        clock=lambda: now,
        connection_timeout_seconds=0.2,
        on_ready=ready.set,
    )


def _supervisor_listener(socket_path: Path) -> socket.socket:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(socket_path))
    os.chmod(socket_path, 0o600)
    listener.listen(32)
    return listener


def _start_real_listener(
    listener: socket.socket, socket_path: Path, calls: object
) -> tuple[object, object]:
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    process = context.Process(
        target=_run_real_listener,
        args=(listener, str(socket_path), ready, calls),
    )
    process.start()
    if not ready.wait(5):
        _cleanup_service_process(process, socket_path, remove_runtime_directory=False)
        pytest.fail("real effect listener did not become ready")
    return process, ready


def _start_packaged_entrypoint(
    listener: socket.socket, socket_path: Path, *, extra_fd: int | None = None
) -> subprocess.Popen[str]:
    environment = dict(os.environ)
    environment["CARL_TEST_LISTENER_FD"] = str(listener.fileno())
    environment["CARL_TEST_ENTRYPOINT_SCRIPT"] = _PACKAGED_ENTRYPOINT_SCRIPT
    source_root = os.fspath(Path(__file__).parents[1] / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        item for item in (source_root, environment.get("PYTHONPATH", "")) if item
    )
    passed = [listener.fileno()]
    if extra_fd is not None:
        environment["CARL_TEST_EXTRA_FD"] = str(extra_fd)
        passed.append(extra_fd)
    return subprocess.Popen(
        [sys.executable, "-c", _PACKAGED_ENTRYPOINT_SCRIPT, os.fspath(socket_path)],
        env=environment,
        pass_fds=tuple(passed),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _entrypoint_response(process: subprocess.Popen[str], socket_path: Path) -> object:
    client = _client_module().GitHubEffectSocketClient._for_testing(
        socket_path=socket_path,
        expected_peer_uid=os.getuid(),
        timeout_seconds=0.5,
    )
    deadline = time.monotonic() + 5.0
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _stdout, stderr = process.communicate(timeout=1)
            pytest.fail(f"packaged effect service exited early: {stderr}")
        try:
            return client.execute(_request())
        except _client_module().GitHubEffectClientError as error:
            last_error = error
            time.sleep(0.02)
    pytest.fail(f"packaged effect service did not respond: {last_error}")


def _probe_activated_listener(
    listener: socket.socket,
    socket_path: str,
    expected_uid: int,
    declared_descriptors: int,
    observed: object,
) -> None:
    service = importlib.import_module("carl_bench.github_effect_service")
    os.set_inheritable(listener.fileno(), True)
    for descriptor in service._inheritable_descriptors():
        if descriptor != listener.fileno():
            os.set_inheritable(descriptor, False)
    environment = {
        "LISTEN_PID": str(os.getpid()),
        "LISTEN_FDS": str(declared_descriptors),
        "LISTEN_FDNAMES": "github-effect",
    }
    try:
        descriptor = service._activation_descriptor_from_environment(
            environment=environment,
            process_id=os.getpid(),
            descriptor_fd=listener.fileno(),
        )
        with service._validated_activated_listener(
            listener_fd=descriptor,
            socket_path=Path(socket_path),
            expected_uid=expected_uid,
        ):
            pass
    except RuntimeError as error:
        observed.put(str(error))
    else:
        observed.put("accepted")


def _activation_probe(
    listener: socket.socket,
    socket_path: Path,
    *,
    expected_uid: int | None = None,
    declared_descriptors: int = 1,
) -> str:
    context = multiprocessing.get_context("spawn")
    observed = context.Queue()
    process = context.Process(
        target=_probe_activated_listener,
        args=(
            listener,
            os.fspath(socket_path),
            os.getuid() if expected_uid is None else expected_uid,
            declared_descriptors,
            observed,
        ),
    )
    process.start()
    try:
        result = observed.get(timeout=5)
        _join(process)
        return result
    finally:
        process.join(0.05)
        if process.is_alive():
            process.kill()
            process.join(2)


def _module(name: str, failure: str) -> ModuleType:
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:
        pytest.fail(failure)


def _ipc() -> ModuleType:
    return _module(
        "carl_bench.github_effect_ipc",
        "credential-free GitHub effect IPC codec module is required",
    )


def _client_module() -> ModuleType:
    return _module(
        "carl_bench.github_effect_client",
        "credential-free Unix-socket GitHub effect client module is required",
    )


def _request() -> object:
    return _ipc().GitHubEffectRequest.from_canonical_dict(
        {
            "command_key": f"github-checks-{SHA}",
            "domain": "carl.github-effect.ipc.request.v1",
            "effect_key": f"cloud-effect-{DIGEST}",
            "occurred_at": NOW,
            "operation": "observe_required_checks",
            "parameters": {
                "head_sha": SHA,
                "required_checks": list(APPROVED_REQUIRED_CHECKS),
            },
            "request_key": f"github-checks-{SHA}",
            "schema_version": 1,
        }
    )


def _all_operation_documents() -> dict[str, dict[str, object]]:
    workflow = {
        "candidate_commit": SHA,
        "experiment_digest": DIGEST,
        "metric_pack_digest": "b" * 64,
        "parent_commit": "3" * 40,
        "policy_digest": "c" * 64,
        "repository": "StephenBickel/carl-agent",
        "task_set_digest": "d" * 64,
        "workflow_blob_digest": "e" * 64,
        "workflow_file": "autonomous-improvement.yml",
        "workflow_revision": "3" * 40,
    }
    target = {
        "base_branch": "main",
        "head_branch": "experimental/promotion-001",
        "head_sha": SHA,
        "number": 17,
        "promotion_id": "promotion-001",
    }
    checks = _request().to_canonical_dict()["parameters"]
    return {
        "create_experimental_ref": {
            "branch": "experimental/experiment-001",
            "candidate_commit": SHA,
            "experiment_id": "experiment-001",
        },
        "create_pull_request": {
            "base_branch": "main",
            "draft": True,
            "head_branch": "experimental/promotion-001",
            "head_sha": SHA,
            "promotion_id": "promotion-001",
            "pull_request_body": "Capability evidence.",
            "title": "Promote experiment",
        },
        "create_revert_pull_request": {
            "base_branch": "main",
            "draft": False,
            "expected_restored_tree": "4" * 40,
            "head_branch": "revert/promotion-001",
            "promotion_id": "promotion-001",
            "promotion_merge_commit": "3" * 40,
            "pull_request_body": "Failed soak rollback.",
            "revert_candidate_commit": SHA,
            "title": "Revert promotion",
        },
        "create_revert_ref": {
            "branch": "revert/promotion-001",
            "expected_restored_tree": "4" * 40,
            "promotion_id": "promotion-001",
            "promotion_merge_commit": "3" * 40,
            "revert_candidate_commit": SHA,
        },
        "dispatch_workflow": workflow,
        "enable_pull_request_auto_merge": {**target, "merge_method": "squash"},
        "mark_pull_request_ready": target,
        "observe_required_checks": checks,
        "update_pull_request": {
            **target,
            "pull_request_body": "Updated capability evidence.",
            "title": "Update promotion",
        },
    }


def _operation_request(operation: str, parameters: dict[str, object]) -> object:
    command_key = (
        "github-dispatch-autonomous-improvement.yml-" + DIGEST + "-attempt-1"
        if operation == "dispatch_workflow"
        else f"ipc-{operation}-001"
    )
    return _ipc().GitHubEffectRequest.from_canonical_dict(
        {
            "command_key": command_key,
            "domain": "carl.github-effect.ipc.request.v1",
            "effect_key": f"cloud-effect-{DIGEST}",
            "occurred_at": NOW,
            "operation": operation,
            "parameters": parameters,
            "request_key": command_key,
            "schema_version": 1,
        }
    )


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise RuntimeError("unexpected IPC EOF")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _one_shot_fake_service(
    socket_path: str, observed: object, ready: object, protected_secret: str
) -> None:
    os.environ["CARL_GITHUB_APP_INSTALLATION_TOKEN"] = protected_secret
    path = Path(socket_path)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(socket_path)
        os.chmod(socket_path, 0o600)
        listener.listen(1)
        ready.set()
        connection, _ = listener.accept()
        with connection:
            size = struct.unpack(">I", _recv_exact(connection, 4))[0]
            if not 0 < size <= MAX_FRAME_BYTES:
                raise RuntimeError("invalid IPC frame size")
            payload = _recv_exact(connection, size)
            observed.put(payload)
            response = json.dumps(
                {
                    "domain": "carl.github-effect.ipc.response.v1",
                    "error_code": "github_command_not_found",
                    "observed_at": NOW,
                    "request_digest": hashlib.sha256(payload).hexdigest(),
                    "result": None,
                    "retry_not_before": None,
                    "schema_version": 1,
                    "status": "rejected",
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            connection.sendall(struct.pack(">I", len(response)) + response)
    path.unlink(missing_ok=True)


def _start_service(socket_path: Path) -> tuple[object, object, object]:
    context = multiprocessing.get_context("spawn")
    observed = context.Queue()
    ready = context.Event()
    process = context.Process(
        target=_one_shot_fake_service,
        args=(str(socket_path), observed, ready, SECRET),
    )
    process.start()
    if not ready.wait(5):
        _cleanup_service_process(process, socket_path)
        pytest.fail("separate fake effect service did not bind its socket")
    return process, observed, ready


def _cleanup_service_process(
    process: object, socket_path: Path, *, remove_runtime_directory: bool = True
) -> None:
    process.join(0.05)
    if process.is_alive():
        process.terminate()
        process.join(2)
    if process.is_alive():
        process.kill()
        process.join(2)
    if process.is_alive():
        raise AssertionError("separate fake effect service cleanup timed out")
    socket_path.unlink(missing_ok=True)
    if remove_runtime_directory:
        with suppress(FileNotFoundError):
            socket_path.parent.rmdir()


def _join(process: object) -> None:
    process.join(5)
    if process.exitcode is None:
        pytest.fail("separate fake effect service did not exit")
    assert process.exitcode == 0


def _short_socket_path() -> Path:
    temporary_root = Path("/private/tmp") if Path("/tmp").is_symlink() else Path("/tmp")
    directory = Path(tempfile.mkdtemp(prefix="carl-ipc-", dir=temporary_root))
    directory.chmod(0o700)
    return directory / "effect.sock"


def _open_descriptor_count() -> int:
    descriptor_root = Path("/proc/self/fd")
    if not descriptor_root.is_dir():
        descriptor_root = Path("/dev/fd")
    return len(tuple(descriptor_root.iterdir()))


def _separate_process_decode_probe(payload: bytes, observed: object) -> None:
    os.environ["CARL_GITHUB_APP_INSTALLATION_TOKEN"] = SECRET
    ipc = importlib.import_module("carl_bench.github_effect_ipc")
    try:
        ipc.decode_request_bytes(payload)
    except ipc.GitHubEffectProtocolError as error:
        observed.put((str(error), SECRET in repr(ipc)))
    else:
        observed.put(("accepted", SECRET in repr(ipc)))


def test_test_service_cleanup_terminates_accept_waiter_and_removes_socket() -> None:
    socket_path = _short_socket_path()
    process, _, _ = _start_service(socket_path)

    try:
        _cleanup_service_process(process, socket_path)

        assert not process.is_alive()
        assert not socket_path.exists()
        assert not socket_path.parent.exists()
    finally:
        if process.is_alive():
            process.terminate()
            process.join(2)
        socket_path.unlink(missing_ok=True)
        if socket_path.parent.exists():
            socket_path.parent.rmdir()


def test_socket_client_surface_has_no_raw_http_graphql_or_dependency_injection() -> None:
    client_module = _client_module()
    client_type = client_module.GitHubEffectSocketClient
    public = {
        name: value
        for name, value in getmembers(client_type, predicate=isfunction)
        if not name.startswith("_")
    }

    assert set(public) == {"execute"}
    assert set(signature(public["execute"]).parameters) == {"self", "request"}
    assert set(signature(client_type.from_protected_environment).parameters) == set()
    assert not {
        "body",
        "graphql",
        "headers",
        "method",
        "path",
        "query",
        "state_controller",
        "token",
        "transport",
        "url",
        "variables",
    } & set(signature(client_type._for_testing).parameters)


def test_protected_service_has_a_dedicated_packaged_entrypoint() -> None:
    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())

    assert project["project"]["scripts"]["carl-github-effect-service"] == (
        "carl_bench.github_effect_service:main"
    )


def test_separate_process_round_trip_contains_no_secret_and_survives_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client_module = _client_module()
    socket_path = _short_socket_path()
    process = None
    restarted = None
    monkeypatch.delenv("CARL_GITHUB_APP_INSTALLATION_TOKEN", raising=False)
    try:
        process, observed, _ = _start_service(socket_path)
        client = client_module.GitHubEffectSocketClient._for_testing(
            socket_path=socket_path,
            expected_peer_uid=os.getuid(),
            timeout_seconds=2.0,
        )

        first = client.execute(_request())
        first_wire = observed.get(timeout=2)
        _join(process)

        assert first.status == "rejected"
        assert first.error_code == "github_command_not_found"
        assert SECRET.encode() not in first_wire
        assert b"authorization" not in first_wire
        assert b"graphql" not in first_wire
        assert b"method" not in first_wire
        assert b"path" not in first_wire
        assert "CARL_GITHUB_APP_INSTALLATION_TOKEN" not in os.environ

        restarted, restarted_observed, _ = _start_service(socket_path)
        second = client.execute(_request())
        second_wire = restarted_observed.get(timeout=2)
        _join(restarted)

        assert second == first
        assert second_wire == first_wire
    finally:
        if process is not None:
            _cleanup_service_process(process, socket_path, remove_runtime_directory=False)
        if restarted is not None:
            _cleanup_service_process(restarted, socket_path, remove_runtime_directory=False)
        socket_path.unlink(missing_ok=True)
        with suppress(FileNotFoundError):
            socket_path.parent.rmdir()


def test_client_module_monkeypatches_cannot_capture_credentials_or_replace_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client_module = _client_module()
    socket_path = _short_socket_path()
    process, observed, _ = _start_service(socket_path)
    try:
        client = client_module.GitHubEffectSocketClient._for_testing(
            socket_path=socket_path,
            expected_peer_uid=os.getuid(),
            timeout_seconds=2.0,
        )
        captured: list[object] = []
        monkeypatch.delenv("CARL_GITHUB_APP_INSTALLATION_TOKEN", raising=False)
        for name in (
            "_ProtectedGitHubTransport",
            "_ProtectedStateControllerClient",
            "_SERVICE_EXECUTOR",
            "_ENABLE_AUTO_MERGE_MUTATION",
            "_MARK_READY_MUTATION",
        ):
            monkeypatch.setattr(
                client_module,
                name,
                lambda *args, **kwargs: captured.append((args, kwargs)),
                raising=False,
            )

        response = client.execute(_request())
        wire = observed.get(timeout=2)
        _join(process)

        assert response.status == "rejected"
        assert captured == []
        assert SECRET not in repr(client)
        assert SECRET.encode() not in wire
        with pytest.raises(TypeError):
            vars(client)
    finally:
        _cleanup_service_process(process, socket_path)


def test_production_gateway_monkeypatches_cannot_change_separate_service_wire(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    github = _module("carl_bench.github_cloud", "GitHub gateway module is required")
    client_module = _client_module()
    socket_path = _short_socket_path()
    process, observed, _ = _start_service(socket_path)
    try:
        monkeypatch.delenv("CARL_GITHUB_APP_INSTALLATION_TOKEN", raising=False)
        monkeypatch.setattr(client_module, "_PROTECTED_SOCKET_PATH", socket_path)
        monkeypatch.setattr(client_module, "_PROTECTED_SERVICE_UID", os.getuid())
        captured: list[object] = []
        for name in (
            "_ProtectedGitHubTransport",
            "_ProtectedStateControllerClient",
            "_ENABLE_AUTO_MERGE_MUTATION",
            "_MARK_READY_MUTATION",
        ):
            monkeypatch.setattr(
                github,
                name,
                lambda *args, **kwargs: captured.append((args, kwargs, SECRET)),
                raising=False,
            )
        typed = github.RequiredChecksRequest.create(head_sha=SHA)
        binding = github.required_checks_binding("StephenBickel/carl-agent", typed)
        gateway = github.GitHubCloudGateway.from_protected_environment()

        with pytest.raises(github.GitHubCloudError, match="github_command_not_found"):
            gateway.observe_required_checks(binding.command_key, typed, occurred_at=NOW)
        wire = observed.get(timeout=2)
        _join(process)

        assert captured == []
        assert SECRET.encode() not in wire
        assert not any(field in wire for field in (b"graphql", b"method", b"path", b"token"))
    finally:
        _cleanup_service_process(process, socket_path)


def test_protected_service_graphql_documents_ignore_mutable_gateway_globals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _module("carl_bench.github_effect_service", "effect service is required")
    github = _module("carl_bench.github_cloud", "GitHub gateway module is required")
    malicious = "mutation A { __typename } mutation B { __typename }"
    monkeypatch.setattr(github, "_MARK_READY_MUTATION", malicious, raising=False)
    monkeypatch.setattr(github, "_ENABLE_AUTO_MERGE_MUTATION", malicious, raising=False)

    documents = service._protected_graphql_documents()

    assert documents.mark_ready_digest == (
        "49a7c81b57a1cdfb851fbaa6c3dfd374a892ed76c1f56afaf4282e147a62f973"
    )
    assert documents.enable_auto_merge_digest == (
        "6a96f13af464b95dcd16d58fe01b851362c59893e24b842a40592b04765336f4"
    )
    assert "expectedHeadOid: $expectedHeadOid" in documents.enable_auto_merge
    assert malicious not in (documents.mark_ready, documents.enable_auto_merge)


def test_separate_client_process_rejects_raw_fields_without_importing_secret() -> None:
    document = _request().to_canonical_dict()
    document["method"] = "POST"
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    context = multiprocessing.get_context("spawn")
    observed = context.Queue()
    process = context.Process(target=_separate_process_decode_probe, args=(payload, observed))

    process.start()
    try:
        result = observed.get(timeout=5)
        _join(process)
    finally:
        process.join(0.05)
        if process.is_alive():
            process.terminate()
            process.join(2)
        if process.is_alive():
            process.kill()
            process.join(2)

    assert result == ("github_effect_ipc_request_invalid", False)


def test_service_rejects_forged_high_level_request_before_executor() -> None:
    service = _module(
        "carl_bench.github_effect_service",
        "protected GitHub effect service module is required",
    )
    github = _module("carl_bench.github_cloud", "GitHub gateway module is required")

    typed = github.RequiredChecksRequest.create(head_sha=SHA)
    binding = github.required_checks_binding("StephenBickel/carl-agent", typed)
    command = CloudCommand.create(
        command_key=binding.command_key,
        authority=binding.authority,
        operation=binding.operation,
        request_digest=binding.request_digest,
        occurred_at=NOW,
        expected_revision=8,
        attempt=1,
        max_attempts=3,
    )
    state = CommandState(
        command=command,
        revision=9,
        status="claimed",
        claim=CommandClaim(
            command_key=command.command_key,
            claim_id="github-effect-service-claim",
            authority=command.authority,
            expected_revision=8,
            claimed_at=NOW,
            expires_at="2026-08-21T12:05:00Z",
        ),
        transition=None,
        result_digest=None,
        failure_code=None,
    )

    class ExistingState:
        def resolve_claimed_command(self, *args: object, **kwargs: object) -> object:
            return state

    class RecordingGateway:
        calls = 0

        def observe_required_checks(self, *args: object, **kwargs: object) -> object:
            self.calls += 1
            raise AssertionError("executor must not run without durable authority")

    gateway = RecordingGateway()
    response = service._response_for(
        _request(),
        gateway=gateway,
        policy=SimpleNamespace(
            repository="StephenBickel/carl-agent",
            workflow_ref="main",
            dispatch_actor_login="carl-autonomy[bot]",
        ),
        state_controller=ExistingState(),
        clock=lambda: __import__("datetime").datetime.fromisoformat("2026-08-21T12:00:00+00:00"),
    )

    assert response.status == "rejected"
    assert response.error_code == "github_command_binding_mismatch"
    assert gateway.calls == 0


def test_service_executes_only_exact_durably_bound_high_level_request() -> None:
    service = _module("carl_bench.github_effect_service", "effect service is required")
    github = _module("carl_bench.github_cloud", "GitHub gateway module is required")
    typed = github.RequiredChecksRequest.create(head_sha=SHA)
    binding = github.required_checks_binding("StephenBickel/carl-agent", typed)
    command = CloudCommand.create(
        command_key=binding.command_key,
        authority=binding.authority,
        operation=binding.operation,
        request_digest=binding.request_digest,
        occurred_at=NOW,
        expected_revision=8,
        attempt=1,
        max_attempts=3,
    )
    state = CommandState(
        command=command,
        revision=9,
        status="claimed",
        claim=CommandClaim(
            command_key=command.command_key,
            claim_id="github-effect-service-valid-claim",
            authority=command.authority,
            expected_revision=8,
            claimed_at=NOW,
            expires_at="2026-08-21T12:05:00Z",
        ),
        transition=None,
        result_digest=None,
        failure_code=None,
    )
    document = _request().to_canonical_dict()
    document["effect_key"] = command.effect_key
    request = _ipc().GitHubEffectRequest.from_canonical_dict(document)

    class ExistingState:
        def resolve_claimed_command(self, *args: object, **kwargs: object) -> object:
            return state

    class Gateway:
        calls = 0

        def observe_required_checks(self, command_key: str, candidate: object) -> object:
            self.calls += 1
            assert command_key == command.command_key
            assert candidate == typed
            return github.RequiredChecksSnapshot(
                repository="StephenBickel/carl-agent",
                head_sha=SHA,
                checks=(),
                complete=False,
                request_key=binding.request_key,
                effect_key=command.effect_key,
                command_occurred_at=NOW,
                observed_at=NOW,
            )

    gateway = Gateway()
    response = service._response_for(
        request,
        gateway=gateway,
        policy=SimpleNamespace(
            repository="StephenBickel/carl-agent",
            workflow_ref="main",
            dispatch_actor_login="carl-autonomy[bot]",
        ),
        state_controller=ExistingState(),
        clock=lambda: __import__("datetime").datetime.fromisoformat("2026-08-21T12:00:00+00:00"),
    )

    assert response.status == "completed"
    assert gateway.calls == 1
    assert _ipc().decode_response_bytes(_ipc().encode_response_bytes(response)) == response


@pytest.mark.parametrize(
    ("operation", "expected_request_type", "expected_method"),
    (
        (operation, request_type, method)
        for operation, (request_type, method) in _OPERATION_BINDINGS.items()
    ),
)
def test_service_maps_every_closed_operation_to_its_exact_typed_request_and_executor(
    operation: str, expected_request_type: str, expected_method: str
) -> None:
    service = _module("carl_bench.github_effect_service", "effect service is required")
    request = _operation_request(operation, _all_operation_documents()[operation])

    typed, _binding, method = service._typed_request(
        request,
        SimpleNamespace(
            repository="StephenBickel/carl-agent",
            workflow_ref="main",
            dispatch_actor_login="carl-autonomy[bot]",
        ),
    )

    assert type(typed).__name__ == expected_request_type
    assert method == expected_method
    if operation in {"create_pull_request", "create_revert_pull_request", "update_pull_request"}:
        assert typed.body == request.parameters["pull_request_body"]
        assert not hasattr(typed, "pull_request_body")


@pytest.mark.parametrize(
    ("operation", "expected_request_type", "expected_method"),
    (
        (operation, request_type, method)
        for operation, (request_type, method) in _OPERATION_BINDINGS.items()
    ),
)
def test_service_executes_every_advertised_operation_through_its_typed_gateway(
    operation: str, expected_request_type: str, expected_method: str
) -> None:
    service = _module("carl_bench.github_effect_service", "effect service is required")
    github = _module("carl_bench.github_cloud", "GitHub gateway module is required")
    policy = SimpleNamespace(
        repository="StephenBickel/carl-agent",
        workflow_ref="main",
        dispatch_actor_login="carl-autonomy[bot]",
    )
    seed = _operation_request(operation, _all_operation_documents()[operation])
    typed, binding, method = service._typed_request(seed, policy)
    assert type(typed).__name__ == expected_request_type
    assert method == expected_method
    command = CloudCommand.create(
        command_key=binding.command_key,
        authority=binding.authority,
        operation=binding.operation,
        request_digest=binding.request_digest,
        occurred_at=NOW,
        expected_revision=8,
        attempt=1,
        max_attempts=3,
    )
    request_document = seed.to_canonical_dict()
    request_document.update(
        command_key=binding.command_key,
        effect_key=command.effect_key,
        request_key=binding.request_key,
    )
    request = _ipc().GitHubEffectRequest.from_canonical_dict(request_document)
    state = CommandState(
        command=command,
        revision=9,
        status="claimed",
        claim=CommandClaim(
            command_key=command.command_key,
            claim_id=f"claim-{operation}",
            authority=command.authority,
            expected_revision=8,
            claimed_at=NOW,
            expires_at="2026-08-21T12:05:00Z",
        ),
        transition=None,
        result_digest=None,
        failure_code=None,
    )

    class ExistingState:
        def resolve_claimed_command(self, *args: object, **kwargs: object) -> object:
            del args, kwargs
            return state

    class ExactGateway:
        def __init__(self) -> None:
            self.calls: list[tuple[str, str, object]] = []

        def __getattr__(self, name: str) -> object:
            if name != expected_method:
                raise AssertionError(f"unexpected gateway method: {name}")

            def execute(command_key: str, candidate: object) -> object:
                self.calls.append((name, command_key, candidate))
                common = {
                    "repository": policy.repository,
                    "request_key": binding.request_key,
                    "effect_key": command.effect_key,
                    "command_occurred_at": NOW,
                    "observed_at": NOW,
                }
                if expected_method == "dispatch_workflow":
                    return github.WorkflowDispatchSnapshot(
                        status="dispatched",
                        workflow_file=typed.workflow_file,
                        workflow_revision=typed.workflow_revision,
                        attempt_key=binding.attempt_key,
                        run_id=41,
                        head_sha=typed.candidate_commit,
                        **common,
                    )
                if expected_method in {
                    "create_or_reconcile_experimental_branch",
                    "create_or_reconcile_revert_branch",
                }:
                    branch = typed.branch
                    commit_sha = (
                        getattr(typed, "candidate_commit", None) or typed.revert_candidate_commit
                    )
                    return github.GitReferenceSnapshot(
                        status="created",
                        ref=f"refs/heads/{branch}",
                        commit_sha=commit_sha,
                        **common,
                    )
                if expected_method == "observe_required_checks":
                    return github.RequiredChecksSnapshot(
                        head_sha=typed.head_sha,
                        checks=(),
                        complete=False,
                        **common,
                    )
                return github.PullRequestEffectSnapshot(
                    status=(
                        "updated"
                        if expected_method != "create_or_reconcile_pull_request"
                        else "created"
                    ),
                    number=getattr(typed, "number", 17),
                    url="https://github.com/StephenBickel/carl-agent/pull/17",
                    state="open",
                    draft=getattr(typed, "draft", False),
                    base_branch=typed.base_branch,
                    head_branch=typed.head_branch,
                    head_sha=getattr(typed, "head_sha", None) or typed.revert_candidate_commit,
                    title=getattr(typed, "title", "Promote experiment"),
                    body=getattr(typed, "body", "Capability evidence."),
                    auto_merge_enabled=expected_method == "enable_pull_request_auto_merge",
                    **common,
                )

            return execute

    gateway = ExactGateway()
    response = service._response_for(
        request,
        gateway=gateway,
        policy=policy,
        state_controller=ExistingState(),
        clock=lambda: __import__("datetime").datetime.fromisoformat("2026-08-21T12:00:00+00:00"),
    )

    assert response.status == "completed"
    assert response.error_code is None
    assert gateway.calls == [(expected_method, binding.command_key, typed)]
    assert _ipc().decode_response_bytes(_ipc().encode_response_bytes(response)) == response


def test_pull_request_service_result_crosses_ipc_without_raw_transport_fields() -> None:
    service = _module("carl_bench.github_effect_service", "effect service is required")
    github = _module("carl_bench.github_cloud", "GitHub gateway module is required")
    request = _operation_request(
        "create_pull_request", _all_operation_documents()["create_pull_request"]
    )
    snapshot = github.PullRequestEffectSnapshot(
        status="created",
        repository="StephenBickel/carl-agent",
        number=17,
        url="https://github.com/StephenBickel/carl-agent/pull/17",
        state="open",
        draft=True,
        base_branch="main",
        head_branch="experimental/promotion-001",
        head_sha=SHA,
        title="Promote experiment",
        body="Capability evidence.",
        auto_merge_enabled=False,
        request_key=request.request_key,
        effect_key=request.effect_key,
        command_occurred_at=NOW,
        observed_at=NOW,
    )
    response = _ipc().GitHubEffectResponse(
        schema_version=1,
        domain="carl.github-effect.ipc.response.v1",
        status="completed",
        request_digest=request.digest,
        observed_at=NOW,
        result={
            "result_type": "PullRequestEffectSnapshot",
            "value": service._canonical_result(snapshot),
        },
        retry_not_before=None,
        error_code=None,
    )

    decoded = _ipc().decode_response_bytes(_ipc().encode_response_bytes(response))
    restored = github._result_from_ipc(
        decoded, request=request, expected_type=github.PullRequestEffectSnapshot
    )

    assert restored == snapshot
    wire = _ipc().encode_response_bytes(response)
    assert b'"body"' not in wire
    assert b'"url"' not in wire


def test_partial_frames_time_out_and_next_client_remains_serviceable() -> None:
    context = multiprocessing.get_context("spawn")
    calls = context.Value("i", 0)
    socket_path = _short_socket_path()
    listener = _supervisor_listener(socket_path)
    process, _ = _start_real_listener(listener, socket_path, calls)
    partial = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        partial.connect(os.fspath(socket_path))
        partial.sendall(b"\x00\x00")
        client = _client_module().GitHubEffectSocketClient._for_testing(
            socket_path=socket_path,
            expected_peer_uid=os.getuid(),
            timeout_seconds=2.0,
        )

        started = time.monotonic()
        response = client.execute(_request())
        elapsed = time.monotonic() - started

        assert response.status == "rejected"
        assert response.error_code == "github_command_not_found"
        assert elapsed < 1.25
        assert calls.value == 1
    finally:
        partial.close()
        _cleanup_service_process(process, socket_path)
        listener.close()


def test_supervisor_listener_survives_sigkill_and_replacement_service_reuses_it() -> None:
    context = multiprocessing.get_context("spawn")
    calls = context.Value("i", 0)
    socket_path = _short_socket_path()
    listener = _supervisor_listener(socket_path)
    original_identity = socket_path.stat().st_ino
    first, _ = _start_real_listener(listener, socket_path, calls)
    client = _client_module().GitHubEffectSocketClient._for_testing(
        socket_path=socket_path,
        expected_peer_uid=os.getuid(),
        timeout_seconds=2.0,
    )
    restarted = None
    try:
        assert client.execute(_request()).error_code == "github_command_not_found"
        assert calls.value == 1
        first.kill()
        first.join(2)
        assert not first.is_alive()
        assert socket_path.is_socket()
        assert socket_path.stat().st_ino == original_identity

        restarted, _ = _start_real_listener(listener, socket_path, calls)

        assert client.execute(_request()).error_code == "github_command_not_found"
        assert calls.value == 2
        assert socket_path.stat().st_ino == original_identity
    finally:
        _cleanup_service_process(first, socket_path, remove_runtime_directory=False)
        if restarted is not None:
            _cleanup_service_process(restarted, socket_path, remove_runtime_directory=False)
        listener.close()
        socket_path.unlink(missing_ok=True)
        with suppress(FileNotFoundError):
            socket_path.parent.rmdir()


def test_packaged_entrypoint_reuses_inherited_fd3_after_sigkill_restart() -> None:
    socket_path = _short_socket_path()
    listener = _supervisor_listener(socket_path)
    identity = socket_path.stat().st_ino
    first = _start_packaged_entrypoint(listener, socket_path)
    restarted: subprocess.Popen[str] | None = None
    try:
        assert _entrypoint_response(first, socket_path).error_code == "github_command_not_found"
        first.kill()
        assert first.wait(timeout=2) != 0
        assert socket_path.stat().st_ino == identity

        restarted = _start_packaged_entrypoint(listener, socket_path)
        assert _entrypoint_response(restarted, socket_path).error_code == "github_command_not_found"
        assert socket_path.stat().st_ino == identity
    finally:
        for process in (first, restarted):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            if process is not None:
                process.communicate(timeout=1)
        listener.close()
        socket_path.unlink(missing_ok=True)
        socket_path.parent.rmdir()


def test_service_exit_never_unlinks_or_replaces_supervisor_socket() -> None:
    context = multiprocessing.get_context("spawn")
    calls = context.Value("i", 0)
    socket_path = _short_socket_path()
    listener = _supervisor_listener(socket_path)
    identity = socket_path.stat().st_ino
    process, _ = _start_real_listener(listener, socket_path, calls)
    try:
        process.terminate()
        process.join(2)
        assert not process.is_alive()
        assert socket_path.is_socket()
        assert socket_path.stat().st_ino == identity
    finally:
        _cleanup_service_process(process, socket_path, remove_runtime_directory=False)
        listener.close()
        socket_path.unlink(missing_ok=True)
        socket_path.parent.rmdir()


@pytest.mark.parametrize("defect", ("wrong_path", "wrong_mode", "wrong_owner"))
def test_activated_listener_process_rejects_wrong_path_mode_or_owner(defect: str) -> None:
    socket_path = _short_socket_path()
    listener = _supervisor_listener(socket_path)
    try:
        expected_path = socket_path
        expected_uid = os.getuid()
        if defect == "wrong_path":
            expected_path = socket_path.parent / "other.sock"
        elif defect == "wrong_mode":
            os.chmod(socket_path, 0o666)
        else:
            expected_uid += 1

        expected_error = (
            "github_effect_service_listener_invalid"
            if defect == "wrong_owner"
            else "github_effect_service_socket_identity_invalid"
        )
        assert (
            _activation_probe(listener, expected_path, expected_uid=expected_uid) == expected_error
        )
        assert socket_path.is_socket()
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)
        socket_path.parent.rmdir()


def test_activated_listener_rejects_unlinked_listener_after_path_is_rebound() -> None:
    socket_path = _short_socket_path()
    old_listener = _supervisor_listener(socket_path)
    socket_path.unlink()
    current_listener = _supervisor_listener(socket_path)
    try:
        assert (
            _activation_probe(old_listener, socket_path)
            == "github_effect_service_socket_identity_invalid"
        )
    finally:
        old_listener.close()
        current_listener.close()
        socket_path.unlink(missing_ok=True)
        socket_path.parent.rmdir()


@pytest.mark.parametrize("defect", ("datagram", "non_listening", "extra_descriptor"))
def test_activated_listener_process_rejects_wrong_type_state_or_extra_fd(defect: str) -> None:
    socket_path = _short_socket_path()
    socket_type = socket.SOCK_DGRAM if defect == "datagram" else socket.SOCK_STREAM
    listener = socket.socket(socket.AF_UNIX, socket_type)
    listener.bind(os.fspath(socket_path))
    os.chmod(socket_path, 0o600)
    if defect != "non_listening" and defect != "datagram":
        listener.listen(1)
    try:
        count = 2 if defect == "extra_descriptor" else 1
        expected = (
            "github_effect_service_activation_invalid"
            if defect == "extra_descriptor"
            else "github_effect_service_listener_invalid"
        )
        assert _activation_probe(listener, socket_path, declared_descriptors=count) == expected
        assert socket_path.is_socket()
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)
        socket_path.parent.rmdir()


def test_activation_contract_rejects_undeclared_inheritable_descriptor() -> None:
    service = _module("carl_bench.github_effect_service", "effect service is required")
    socket_path = _short_socket_path()
    listener = _supervisor_listener(socket_path)
    extra_read, extra_write = os.pipe()
    os.set_inheritable(listener.fileno(), True)
    os.set_inheritable(extra_read, True)
    try:
        with pytest.raises(RuntimeError, match="github_effect_service_activation_invalid"):
            service._activation_descriptor_from_environment(
                environment={
                    "LISTEN_PID": str(os.getpid()),
                    "LISTEN_FDS": "1",
                    "LISTEN_FDNAMES": "github-effect",
                },
                process_id=os.getpid(),
                descriptor_fd=listener.fileno(),
            )
    finally:
        os.close(extra_read)
        os.close(extra_write)
        listener.close()
        socket_path.unlink(missing_ok=True)
        socket_path.parent.rmdir()


def test_packaged_entrypoint_rejects_undeclared_inherited_fd4() -> None:
    socket_path = _short_socket_path()
    listener = _supervisor_listener(socket_path)
    identity = socket_path.stat().st_ino
    extra_read, extra_write = os.pipe()
    process = _start_packaged_entrypoint(listener, socket_path, extra_fd=extra_read)
    try:
        return_code = process.wait(timeout=5)
        _stdout, stderr = process.communicate(timeout=1)
        assert return_code != 0
        assert "github_effect_service_activation_invalid" in stderr
        assert socket_path.stat().st_ino == identity
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        os.close(extra_read)
        os.close(extra_write)
        listener.close()
        socket_path.unlink(missing_ok=True)
        socket_path.parent.rmdir()


def test_activated_listener_and_client_reject_symlinked_ancestor() -> None:
    temporary_root = Path("/private/tmp") if Path("/tmp").is_symlink() else Path("/tmp")
    root = Path(tempfile.mkdtemp(prefix="carl-ipc-", dir=temporary_root))
    real = root / "real"
    alias = root / "alias"
    real.mkdir(mode=0o700)
    alias.symlink_to(real, target_is_directory=True)
    socket_path = alias / "effect.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(socket_path))
    os.chmod(real / "effect.sock", 0o600)
    listener.listen(1)
    try:
        assert (
            _activation_probe(listener, socket_path)
            == "github_effect_service_socket_identity_invalid"
        )
        client = _client_module().GitHubEffectSocketClient._for_testing(
            socket_path=socket_path,
            expected_peer_uid=os.getuid(),
            timeout_seconds=0.2,
        )
        with pytest.raises(
            _client_module().GitHubEffectClientError,
            match="github_effect_service_identity_invalid",
        ):
            client.execute(_request())
    finally:
        listener.close()
        (real / "effect.sock").unlink(missing_ok=True)
        alias.unlink()
        real.rmdir()
        root.rmdir()


def test_client_rejects_socket_path_substitution_between_connect_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_path = _short_socket_path()
    original = _supervisor_listener(socket_path)
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connect = socket.socket.connect

    def substitute_then_connect(connection: socket.socket, address: str) -> None:
        socket_path.unlink()
        replacement.bind(os.fspath(socket_path))
        os.chmod(socket_path, 0o600)
        replacement.listen(1)
        connect(connection, address)

    client = _client_module().GitHubEffectSocketClient._for_testing(
        socket_path=socket_path,
        expected_peer_uid=os.getuid(),
        timeout_seconds=0.2,
    )
    monkeypatch.setattr(socket.socket, "connect", substitute_then_connect)
    try:
        with pytest.raises(
            _client_module().GitHubEffectClientError,
            match="github_effect_service_identity_invalid",
        ):
            client.execute(_request())
        assert socket_path.is_socket()
    finally:
        original.close()
        replacement.close()
        socket_path.unlink(missing_ok=True)
        socket_path.parent.rmdir()


def test_client_closes_pinned_parent_when_socket_identity_is_invalid() -> None:
    client_module = _client_module()
    socket_path = _short_socket_path()
    before = _open_descriptor_count()
    try:
        for _ in range(32):
            with pytest.raises(
                client_module.GitHubEffectClientError,
                match="github_effect_service_identity_invalid",
            ):
                client_module._pin_socket_path(socket_path, os.getuid())
        assert _open_descriptor_count() == before
    finally:
        socket_path.parent.rmdir()


@pytest.mark.parametrize(
    ("overrides", "descriptor"),
    (
        ({"LISTEN_PID": "999999"}, 3),
        ({"LISTEN_FDS": "0"}, 3),
        ({"LISTEN_FDS": "2"}, 3),
        ({"LISTEN_FDNAMES": "substituted"}, 3),
        ({}, -1),
    ),
)
def test_activation_contract_rejects_wrong_process_count_name_or_descriptor(
    overrides: dict[str, str], descriptor: int
) -> None:
    service = _module("carl_bench.github_effect_service", "effect service is required")
    environment = {
        "LISTEN_PID": str(os.getpid()),
        "LISTEN_FDS": "1",
        "LISTEN_FDNAMES": "github-effect",
        **overrides,
    }

    with pytest.raises(RuntimeError, match="github_effect_service_activation_invalid"):
        service._activation_descriptor_from_environment(
            environment=environment,
            process_id=os.getpid(),
            descriptor_fd=descriptor,
        )
