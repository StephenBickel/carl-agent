"""Supervisor-activated durable live gateway service."""

from __future__ import annotations

import os
import socket
import threading
from collections.abc import Mapping

from carl_bench.live_gateway_http import _serve_loopback_listener
from carl_bench.live_gateway_runner import ProtectedLiveGatewayRunner
from carl_bench.live_runner_service import _serve_runner_listener

_RUNNER_SOCKET_PATH = "/run/carl/live-runner.sock"


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
    gateway_thread = threading.Thread(
        target=_serve_loopback_listener,
        kwargs={"listener_fd": gateway_descriptor, "server": runner.gateway_server},
        daemon=True,
        name="carl-live-model-gateway",
    )
    gateway_thread.start()
    with _runner_listener(runner_descriptor) as listener:
        _serve_runner_listener(
            listener=listener,
            allowed_client_uid=0,
            runner=runner,
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
