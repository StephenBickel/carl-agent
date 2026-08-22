from __future__ import annotations

import hashlib
import importlib
import json
import multiprocessing
import os
import socket
import struct
import tempfile
import tomllib
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
    assert ready.wait(5), "separate fake effect service did not bind its socket"
    return process, observed, ready


def _join(process: object) -> None:
    process.join(5)
    if process.is_alive():
        process.terminate()
        process.join(5)
        pytest.fail("separate fake effect service did not exit")
    assert process.exitcode == 0


def _short_socket_path() -> Path:
    directory = Path(tempfile.mkdtemp(prefix="carl-ipc-", dir="/tmp"))
    directory.chmod(0o700)
    return directory / "effect.sock"


def _separate_process_decode_probe(payload: bytes, observed: object) -> None:
    os.environ["CARL_GITHUB_APP_INSTALLATION_TOKEN"] = SECRET
    ipc = importlib.import_module("carl_bench.github_effect_ipc")
    try:
        ipc.decode_request_bytes(payload)
    except ipc.GitHubEffectProtocolError as error:
        observed.put((str(error), SECRET in repr(ipc)))
    else:
        observed.put(("accepted", SECRET in repr(ipc)))


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
    monkeypatch.delenv("CARL_GITHUB_APP_INSTALLATION_TOKEN", raising=False)
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


def test_client_module_monkeypatches_cannot_capture_credentials_or_replace_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client_module = _client_module()
    socket_path = _short_socket_path()
    process, observed, _ = _start_service(socket_path)
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


def test_production_gateway_monkeypatches_cannot_change_separate_service_wire(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    github = _module("carl_bench.github_cloud", "GitHub gateway module is required")
    client_module = _client_module()
    socket_path = _short_socket_path()
    process, observed, _ = _start_service(socket_path)
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


def test_separate_client_process_rejects_raw_fields_without_importing_secret() -> None:
    document = _request().to_canonical_dict()
    document["method"] = "POST"
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    context = multiprocessing.get_context("spawn")
    observed = context.Queue()
    process = context.Process(target=_separate_process_decode_probe, args=(payload, observed))

    process.start()
    result = observed.get(timeout=5)
    _join(process)

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
