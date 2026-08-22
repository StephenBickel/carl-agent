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
        assert client._expected_socket_uid == os.getuid()
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
                _testing_service_uids={
                    "archive": os.getuid(),
                    "evaluator": os.getuid(),
                    "input": os.getuid(),
                    "observer": os.getuid(),
                },
            )
