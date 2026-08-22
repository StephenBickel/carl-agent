"""Supervisor-activated durable live gateway service."""

from __future__ import annotations

import os

from carl_bench.live_gateway_http import _serve_loopback_listener
from carl_bench.live_gateway_runner import ProtectedLiveGatewayRunner


def _activation_descriptor() -> int:
    if (
        os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "1"
        or os.environ.get("LISTEN_FDNAMES") != "live-gateway"
        or not os.get_inheritable(3)
    ):
        raise RuntimeError("live_gateway_service_activation_invalid")
    return 3


def main() -> int:
    runner = ProtectedLiveGatewayRunner.from_protected_process()
    _serve_loopback_listener(
        listener_fd=_activation_descriptor(),
        server=runner.gateway_server,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
