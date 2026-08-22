from __future__ import annotations

import multiprocessing
import os
import socket
import tempfile
from contextlib import suppress
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from test_cloud_coordinator import claimed_command_for, lease, node, snapshot

from carl_bench.cloud_coordinator import ProtectedCoordinatorExecutor
from carl_bench.cloud_state import create_command_state
from carl_bench.coordinator_client import (
    CoordinatorClientError,
    CoordinatorSocketClient,
    _validate_peer,
)
from carl_bench.coordinator_ipc import CoordinatorServiceRequest


def test_client_fails_closed_without_a_peer_credential_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnverifiablePeer:
        pass

    monkeypatch.delattr(socket, "SO_PEERCRED", raising=False)
    monkeypatch.delattr(socket, "LOCAL_PEERCRED", raising=False)

    with pytest.raises(CoordinatorClientError, match="coordinator_service_identity_invalid"):
        _validate_peer(UnverifiablePeer(), os.getuid())  # type: ignore[arg-type]


class ProcessState:
    def __init__(self) -> None:
        self.current = snapshot(node(), current_lease=lease())

    def reconstruct(self, command: str, *, observed_at: datetime):
        assert command == "coordinate"
        assert observed_at == datetime(2026, 8, 22, 12, tzinfo=UTC)
        assert os.environ["CARL_AUTONOMY_POSTGRES_DSN"] == "service-only-dsn"
        return self.current

    def apply(self, decision, *, observed_at: datetime):
        del observed_at
        if decision.action == "persist_command":
            self.current = replace(self.current, command=create_command_state(decision.command))
        elif decision.action == "claim_command":
            self.current = replace(self.current, command=claimed_command_for(node()))
        else:  # pragma: no cover
            raise AssertionError(decision.action)
        return decision


class ProcessEffects:
    def execute(self, decision, *, observed_at: datetime):  # pragma: no cover
        del decision, observed_at
        raise AssertionError("unexpected remote effect")


def serve_coordinator(listener: socket.socket, path: str, ready: object) -> None:
    from carl_bench.coordinator_service import _serve_activated_listener

    os.environ["CARL_AUTONOMY_POSTGRES_DSN"] = "service-only-dsn"
    controller = ProtectedCoordinatorExecutor._for_testing(
        state=ProcessState(),
        effects=ProcessEffects(),
        clock=lambda: datetime(2026, 8, 22, 12, tzinfo=UTC),
    )
    _serve_activated_listener(
        listener_fd=listener.fileno(),
        socket_path=Path(path),
        allowed_client_uid=os.getuid(),
        service_uid=os.getuid(),
        controller=controller,
        connection_timeout_seconds=0.5,
        on_ready=ready.set,
    )


def test_separate_service_process_owns_state_secret_and_advances_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CARL_AUTONOMY_POSTGRES_DSN", raising=False)
    with tempfile.TemporaryDirectory(prefix="carl-coord-", dir="/private/tmp") as directory:
        socket_path = Path(directory) / "coordinator.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(8)
        context = multiprocessing.get_context("spawn")
        ready = context.Event()
        process = context.Process(
            target=serve_coordinator,
            args=(listener, os.fspath(socket_path), ready),
        )
        process.start()
        try:
            assert ready.wait(5), "protected coordinator did not become ready"
            client = CoordinatorSocketClient._for_testing(
                socket_path=socket_path,
                expected_peer_uid=os.getuid(),
                timeout_seconds=1,
            )
            request = CoordinatorServiceRequest.create("coordinate")

            first = client.execute(request)
            second = client.execute(request)

            assert first.result is not None and first.result["action"] == "persist_command"
            assert second.result is not None and second.result["action"] == "claim_command"
            assert b"service-only-dsn" not in str(first.to_canonical_dict()).encode()
            assert "CARL_AUTONOMY_POSTGRES_DSN" not in os.environ
        finally:
            process.terminate()
            process.join(5)
            listener.close()
            with suppress(FileNotFoundError):
                socket_path.unlink()
