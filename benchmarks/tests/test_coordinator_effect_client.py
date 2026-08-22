from __future__ import annotations

import json
import multiprocessing
import os
import socket
import struct
import tempfile
from pathlib import Path

import pytest

from carl_bench.coordinator_effects import (
    CoordinatorNodeEffectRequest,
    CoordinatorNodeEffectResponse,
)

NOW = "2026-08-22T12:00:00Z"
RESULT_DIGEST = "a" * 64


def _request(family: str) -> CoordinatorNodeEffectRequest:
    node = {
        "archive": "archive_builder",
        "evaluator": "ingest_validation",
        "input": "publish_input",
        "observer": "observe_builder",
    }[family]
    return CoordinatorNodeEffectRequest.from_canonical_dict(
        {
            "command_key": f"experiment-1:{node}:attempt:1",
            "domain": "carl.coordinator-node-effect.request.v1",
            "effect_key": f"cloud-effect-{'b' * 64}",
            "family": family,
            "node_kind": node,
            "occurred_at": NOW,
            "request_digest": "c" * 64,
            "schema_version": 1,
        }
    )


def _serve_one(listener: socket.socket, family: str, ready: object) -> None:
    from carl_bench.coordinator_effect_client import (
        decode_effect_request_bytes,
        encode_effect_response_bytes,
    )

    listener.listen(4)
    ready.set()
    connection, _ = listener.accept()
    with connection:
        size = struct.unpack(">I", connection.recv(4))[0]
        request = decode_effect_request_bytes(connection.recv(size))
        assert request.family == family
        response = CoordinatorNodeEffectResponse.completed(
            request=request,
            result_digest=RESULT_DIGEST,
            observed_at=NOW,
        )
        payload = encode_effect_response_bytes(response)
        connection.sendall(struct.pack(">I", len(payload)) + payload)


class _EffectAuthority:
    def __init__(self, family: str) -> None:
        self.family = family

    def execute(self, request: CoordinatorNodeEffectRequest) -> CoordinatorNodeEffectResponse:
        assert request.family == self.family
        return CoordinatorNodeEffectResponse.completed(
            request=request,
            result_digest=RESULT_DIGEST,
            observed_at=NOW,
        )


def _serve_activated_effect(
    listener: socket.socket, family: str, ready: object, stop: object
) -> None:
    from carl_bench.coordinator_effect_service import _serve_activated_listener

    ready.set()
    _serve_activated_listener(
        listener,
        family=family,
        authority=_EffectAuthority(family),
        allowed_client_uid=os.getuid(),
        stop=stop,
    )


class _ActivatedResponseSocket:
    """Exact Linux SCM_CREDENTIALS semantic without requiring root in unit tests."""

    def __init__(self, *, sender_uid: int, payload: bytes) -> None:
        self.sender_uid = sender_uid
        self.payload = payload
        self.offset = 0
        self.options: list[tuple[int, int, int]] = []
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        del args

    def settimeout(self, timeout: float) -> None:
        assert timeout == 1

    def setsockopt(self, level: int, option: int, value: int) -> None:
        self.options.append((level, option, value))

    def connect(self, path: str) -> None:
        assert path.endswith("input.sock")

    def sendall(self, payload: bytes) -> None:
        self.sent += payload

    def recvmsg(self, count: int, ancillary_size: int):
        del ancillary_size
        credentials = struct.pack("3i", 4321, self.sender_uid, self.sender_uid)
        payload = self.payload[self.offset : self.offset + count]
        self.offset += len(payload)
        return (
            payload,
            [(socket.SOL_SOCKET, getattr(socket, "SCM_CREDENTIALS", 2), credentials)],
            0,
            None,
        )

    def recv(self, count: int) -> bytes:
        payload = self.payload[self.offset : self.offset + count]
        self.offset += len(payload)
        return payload


@pytest.mark.parametrize(
    ("family", "method_name"),
    (
        ("archive", "archive"),
        ("evaluator", "evaluate"),
        ("input", "publish"),
        ("observer", "observe"),
    ),
)
def test_each_fixed_effect_family_round_trips_over_a_credential_free_socket(
    family: str, method_name: str
) -> None:
    from carl_bench.coordinator_effect_client import CoordinatorEffectSocketClient

    with tempfile.TemporaryDirectory(prefix="carl-cef-", dir="/private/tmp") as directory:
        socket_path = Path(directory) / f"{family}.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(socket_path))
        os.chmod(socket_path, 0o600)
        context = multiprocessing.get_context("spawn")
        ready = context.Event()
        process = context.Process(target=_serve_one, args=(listener, family, ready))
        process.start()
        try:
            assert ready.wait(5)
            client = CoordinatorEffectSocketClient._for_testing(
                family=family,
                socket_path=socket_path,
                expected_peer_uid=os.getuid(),
                timeout_seconds=1,
            )

            response = getattr(client, method_name)(_request(family))

            assert response.status == "completed"
            assert response.result_digest == RESULT_DIGEST
            process.join(5)
            assert process.exitcode == 0
        finally:
            listener.close()
            if process.is_alive():
                process.kill()
                process.join(2)


@pytest.mark.parametrize(
    ("family", "method_name"),
    (
        ("archive", "archive"),
        ("evaluator", "evaluate"),
        ("input", "publish"),
        ("observer", "observe"),
    ),
)
def test_each_packaged_protected_effect_service_responds_on_its_activated_socket(
    family: str, method_name: str
) -> None:
    from carl_bench.coordinator_effect_client import CoordinatorEffectSocketClient

    with tempfile.TemporaryDirectory(prefix="carl-ces-", dir="/private/tmp") as directory:
        socket_path = Path(directory) / f"{family}.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(socket_path))
        os.chmod(socket_path, 0o600)
        context = multiprocessing.get_context("spawn")
        ready = context.Event()
        stop = context.Event()
        process = context.Process(
            target=_serve_activated_effect,
            args=(listener, family, ready, stop),
        )
        process.start()
        try:
            assert ready.wait(5)
            client = CoordinatorEffectSocketClient._for_testing(
                family=family,
                socket_path=socket_path,
                expected_peer_uid=os.getuid(),
                timeout_seconds=1,
            )

            response = getattr(client, method_name)(_request(family))

            assert response.status == "completed"
            assert response.result_digest == RESULT_DIGEST
        finally:
            stop.set()
            process.join(5)
            listener.close()
            if process.is_alive():
                process.kill()
                process.join(2)
    assert process.exitcode == 0


def test_linux_socket_activation_authenticates_response_sender_not_root_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from carl_bench import coordinator_effect_client

    monkeypatch.setattr(coordinator_effect_client.socket, "SO_PASSCRED", 16, raising=False)
    monkeypatch.setattr(coordinator_effect_client.socket, "SCM_CREDENTIALS", 2, raising=False)
    expected_service_uid = 4104
    inherited_root_listener = _ActivatedResponseSocket(
        sender_uid=expected_service_uid,
        payload=struct.pack(">I", 17),
    )

    enabled = coordinator_effect_client._enable_authenticated_response(inherited_root_listener)
    prefix = coordinator_effect_client._recv_authenticated_prefix(
        inherited_root_listener,
        4,
        expected_sender_uid=expected_service_uid,
        response_credentials_enabled=enabled,
    )

    assert prefix == struct.pack(">I", 17)
    assert inherited_root_listener.options == [(socket.SOL_SOCKET, 16, 1)]

    spoofed_root_response = _ActivatedResponseSocket(
        sender_uid=0,
        payload=struct.pack(">I", 17),
    )
    with pytest.raises(
        coordinator_effect_client.CoordinatorEffectClientError,
        match="coordinator_effect_service_identity_invalid",
    ):
        spoofed_enabled = coordinator_effect_client._enable_authenticated_response(
            spoofed_root_response
        )
        coordinator_effect_client._recv_authenticated_prefix(
            spoofed_root_response,
            4,
            expected_sender_uid=expected_service_uid,
            response_credentials_enabled=spoofed_enabled,
        )


def test_root_activated_socket_accepts_first_publish_input_from_exact_responder(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from carl_bench import coordinator_effect_client

    request = _request("input")
    response = CoordinatorNodeEffectResponse.completed(
        request=request,
        result_digest=RESULT_DIGEST,
        observed_at=NOW,
    )
    response_payload = coordinator_effect_client.encode_effect_response_bytes(response)
    connection = _ActivatedResponseSocket(
        sender_uid=4101,
        payload=struct.pack(">I", len(response_payload)) + response_payload,
    )
    parent_fd = os.open(tmp_path, os.O_RDONLY)
    monkeypatch.setattr(coordinator_effect_client.socket, "SO_PASSCRED", 16, raising=False)
    monkeypatch.setattr(coordinator_effect_client.socket, "SCM_CREDENTIALS", 2, raising=False)
    monkeypatch.setattr(coordinator_effect_client.socket, "socket", lambda *args: connection)

    def pinned_parent(path: Path, *, expected_uid: int) -> int:
        assert path == tmp_path / "input.sock"
        assert expected_uid == 0
        return parent_fd

    def socket_identity(parent: int, name: str, *, expected_uid: int) -> tuple[int, ...]:
        assert parent == parent_fd
        assert name == "input.sock"
        assert expected_uid == 4100
        return (1, 2, 3, 4100, 4100, 4)

    monkeypatch.setattr(coordinator_effect_client, "open_pinned_parent", pinned_parent)
    monkeypatch.setattr(coordinator_effect_client, "socket_identity_at", socket_identity)
    client = coordinator_effect_client.CoordinatorEffectSocketClient._for_testing(
        family="input",
        socket_path=tmp_path / "input.sock",
        expected_parent_uid=0,
        expected_socket_uid=4100,
        expected_peer_uid=4101,
        timeout_seconds=1,
    )

    assert client.publish(request) == response
    sent_size = struct.unpack(">I", connection.sent[:4])[0]
    assert sent_size == len(connection.sent[4:])
    assert coordinator_effect_client.decode_effect_request_bytes(connection.sent[4:]) == request


def test_all_four_effect_services_are_distinct_long_lived_responders() -> None:
    from carl_bench.coordinator_effect_client import CoordinatorEffectSocketClient

    with tempfile.TemporaryDirectory(prefix="carl-ces-all-", dir="/private/tmp") as directory:
        root = Path(directory)
        context = multiprocessing.get_context("spawn")
        services: list[tuple[socket.socket, object, object, object, Path]] = []
        for family in ("archive", "evaluator", "input", "observer"):
            socket_path = root / f"{family}.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o600)
            ready = context.Event()
            stop = context.Event()
            process = context.Process(
                target=_serve_activated_effect,
                args=(listener, family, ready, stop),
            )
            process.start()
            services.append((listener, process, ready, stop, socket_path))
        try:
            assert all(ready.wait(5) for _, _, ready, _, _ in services)
            for family, method_name, service in zip(
                ("archive", "evaluator", "input", "observer"),
                ("archive", "evaluate", "publish", "observe"),
                services,
                strict=True,
            ):
                client = CoordinatorEffectSocketClient._for_testing(
                    family=family,
                    socket_path=service[4],
                    expected_peer_uid=os.getuid(),
                    timeout_seconds=1,
                )
                for _ in range(2):
                    assert getattr(client, method_name)(_request(family)).status == "completed"
                assert service[1].is_alive()
                assert service[1].pid is not None
            assert len({service[1].pid for service in services}) == 4
        finally:
            for listener, process, _, stop, _ in services:
                stop.set()
                process.join(5)
                listener.close()
                if process.is_alive():
                    process.kill()
                    process.join(2)
        assert all(process.exitcode == 0 for _, process, _, _, _ in services)


@pytest.mark.parametrize("family", ("archive", "evaluator", "input", "observer"))
def test_protected_responder_names_the_exact_uncommissioned_family(family: str) -> None:
    from carl_bench.coordinator_effect_service import _ProtectedEffectAuthority

    response = _ProtectedEffectAuthority.from_protected_environment(family).execute(
        _request(family)
    )

    assert response.status == "rejected"
    assert response.error_code == f"{family}_service_uncommissioned"


def test_protected_responder_authorizes_only_the_dedicated_coordinator_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from types import SimpleNamespace

    from carl_bench import coordinator_effect_service

    monkeypatch.setattr(
        coordinator_effect_service.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_uid=4201) if name == "carl-autonomy-coordinator" else None,
    )

    assert coordinator_effect_service._protected_coordinator_uid() == 4201
    assert coordinator_effect_service._protected_coordinator_uid() != 0


def test_protected_policy_loader_commissions_all_fixed_families_without_endpoints(
    tmp_path: Path,
) -> None:
    from carl_bench.coordinator_effect_client import (
        PROTECTED_EFFECT_SOCKET_PATHS,
        load_protected_coordinator_effect_clients,
    )

    policy = tmp_path / "coordinator-effects-policy.json"
    policy.write_text(
        json.dumps(
            {
                "domain": "carl.coordinator-effect-policy.v1",
                "required_families": ["archive", "evaluator", "input", "observer"],
                "schema_version": 1,
                "coordinator_user": "carl-autonomy-coordinator",
                "service_users": {
                    "archive": "carl-autonomy-archive",
                    "evaluator": "carl-autonomy-evaluator",
                    "input": "carl-autonomy-input",
                    "observer": "carl-autonomy-observer",
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    policy.chmod(0o600)

    clients = load_protected_coordinator_effect_clients(
        _testing_policy_path=policy,
        _testing_expected_owner_uid=os.getuid(),
        _testing_coordinator_uid=os.getuid() + 2,
        _testing_service_uids={family: os.getuid() + 1 for family in PROTECTED_EFFECT_SOCKET_PATHS},
        _testing_socket_paths={
            family: tmp_path / path.name for family, path in PROTECTED_EFFECT_SOCKET_PATHS.items()
        },
    )

    assert clients.input_publisher.family == "input"
    assert clients.observer.family == "observer"
    assert clients.archive.family == "archive"
    assert clients.evaluator.family == "evaluator"
    for client in (
        clients.input_publisher,
        clients.observer,
        clients.archive,
        clients.evaluator,
    ):
        assert client._expected_parent_uid == os.getuid()
        assert client._expected_socket_uid == os.getuid() + 2
        assert client._expected_peer_uid == os.getuid() + 1
    assert "socket" not in policy.read_text(encoding="utf-8")


def test_protected_policy_rejects_missing_family_or_caller_selected_endpoint(
    tmp_path: Path,
) -> None:
    from carl_bench.coordinator_effect_client import (
        CoordinatorEffectClientError,
        load_protected_coordinator_effect_clients,
    )

    policy = tmp_path / "coordinator-effects-policy.json"
    base = {
        "domain": "carl.coordinator-effect-policy.v1",
        "required_families": ["archive", "evaluator", "input"],
        "schema_version": 1,
        "coordinator_user": "carl-autonomy-coordinator",
        "service_users": {
            "archive": "carl-autonomy-archive",
            "evaluator": "carl-autonomy-evaluator",
            "input": "carl-autonomy-input",
        },
    }
    for document in (base, {**base, "socket_path": "/tmp/attacker.sock"}):
        policy.write_text(
            json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8"
        )
        policy.chmod(0o600)
        with pytest.raises(CoordinatorEffectClientError, match="coordinator_effect_policy_invalid"):
            load_protected_coordinator_effect_clients(
                _testing_policy_path=policy,
                _testing_expected_owner_uid=os.getuid(),
                _testing_coordinator_uid=os.getuid(),
                _testing_service_uids={
                    "archive": os.getuid(),
                    "evaluator": os.getuid(),
                    "input": os.getuid(),
                    "observer": os.getuid(),
                },
            )
