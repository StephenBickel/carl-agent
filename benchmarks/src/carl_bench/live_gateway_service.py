"""Supervisor-activated durable live gateway service."""

from __future__ import annotations

import os
import socket
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field

from carl_bench.live_gateway_http import _serve_loopback_listener
from carl_bench.live_gateway_runner import ProtectedLiveGatewayRunner
from carl_bench.live_runner_service import _serve_runner_listener

_RUNNER_SOCKET_PATH = "/run/carl/live-runner.sock"


@dataclass(slots=True)
class _GatewayListenerMonitor:
    thread: threading.Thread
    failed: threading.Event
    _errors: list[BaseException] = field(repr=False)

    def check(self) -> None:
        if self.failed.is_set():
            error = self._errors[0] if self._errors else None
            raise RuntimeError("live_gateway_listener_failed") from error
        if not self.thread.is_alive():
            raise RuntimeError("live_gateway_listener_failed")


def _start_gateway_listener(*, listener_fd: int, server: object) -> _GatewayListenerMonitor:
    failed = threading.Event()
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            _serve_loopback_listener(listener_fd=listener_fd, server=server)
        except BaseException as error:
            errors.append(error)
            failed.set()

    thread = threading.Thread(
        target=serve,
        daemon=True,
        name="carl-live-model-gateway",
    )
    thread.start()
    return _GatewayListenerMonitor(thread=thread, failed=failed, _errors=errors)


def _activation_descriptors(*, environment: Mapping[str, str], process_id: int) -> tuple[int, int]:
    if (
        environment.get("LISTEN_PID") != str(process_id)
        or environment.get("LISTEN_FDS") != "2"
        or environment.get("LISTEN_FDNAMES") != "live-gateway:live-runner"
        or not os.get_inheritable(3)
        or not os.get_inheritable(4)
    ):
        raise RuntimeError("live_gateway_service_activation_invalid")
    return 3, 4


def _runner_listener(descriptor: int) -> socket.socket:
    try:
        listener = socket.socket(fileno=os.dup(descriptor))
        if (
            listener.family != socket.AF_UNIX
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or listener.getsockname() != _RUNNER_SOCKET_PATH
        ):
            raise RuntimeError("live_runner_service_listener_invalid")
        return listener
    except OSError as error:
        raise RuntimeError("live_runner_service_listener_invalid") from error


def main() -> int:
    runner = ProtectedLiveGatewayRunner.from_protected_process()
    gateway_descriptor, runner_descriptor = _activation_descriptors(
        environment=os.environ,
        process_id=os.getpid(),
    )
    gateway_monitor = _start_gateway_listener(
        listener_fd=gateway_descriptor,
        server=runner.gateway_server,
    )
    with _runner_listener(runner_descriptor) as listener:
        _serve_runner_listener(
            listener=listener,
            allowed_client_uid=0,
            runner=runner,
            health_check=gateway_monitor.check,
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
