"""Strict loopback HTTP listener for one-use protected model capabilities."""

from __future__ import annotations

import json
import os
import socket
from typing import Any

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_gateway_authority import (
    LiveGatewayAuthorityError,
    ProtectedModelGatewayServer,
)

_MAX_HEADER_BYTES = 16_384
_MAX_BODY_BYTES = 65_536
_MAX_TOKEN_BYTES = 512


class LiveGatewayHTTPError(ValueError):
    """Internal strict-protocol failure."""


def _recv_request(connection: socket.socket) -> tuple[str, bytes]:
    buffered = bytearray()
    while b"\r\n\r\n" not in buffered:
        chunk = connection.recv(4096)
        if not chunk:
            raise LiveGatewayHTTPError("live_gateway_http_invalid")
        buffered.extend(chunk)
        if len(buffered) > _MAX_HEADER_BYTES:
            raise LiveGatewayHTTPError("live_gateway_http_invalid")
    head, body = bytes(buffered).split(b"\r\n\r\n", 1)
    try:
        lines = head.decode("ascii").split("\r\n")
    except UnicodeError as error:
        raise LiveGatewayHTTPError("live_gateway_http_invalid") from error
    if lines[0] != "POST /v1/evaluate HTTP/1.1":
        raise LiveGatewayHTTPError("live_gateway_http_invalid")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            raise LiveGatewayHTTPError("live_gateway_http_invalid")
        name, value = line.split(":", 1)
        normalized = name.strip().lower()
        if normalized in headers:
            raise LiveGatewayHTTPError("live_gateway_http_invalid")
        headers[normalized] = value.strip()
    if (
        set(headers)
        != {
            "authorization",
            "connection",
            "content-length",
            "content-type",
            "host",
        }
        or headers["content-type"] != "application/json"
        or headers["connection"] != "close"
    ):
        raise LiveGatewayHTTPError("live_gateway_http_invalid")
    try:
        length = int(headers["content-length"])
    except ValueError as error:
        raise LiveGatewayHTTPError("live_gateway_http_invalid") from error
    if str(length) != headers["content-length"] or not 0 < length <= _MAX_BODY_BYTES:
        raise LiveGatewayHTTPError("live_gateway_http_invalid")
    while len(body) < length:
        chunk = connection.recv(min(4096, length - len(body)))
        if not chunk:
            raise LiveGatewayHTTPError("live_gateway_http_invalid")
        body += chunk
    if len(body) != length:
        raise LiveGatewayHTTPError("live_gateway_http_invalid")
    authorization = headers["authorization"]
    if not authorization.startswith("Bearer "):
        raise LiveGatewayHTTPError("live_gateway_http_invalid")
    token = authorization[7:]
    if not token or len(token.encode()) > _MAX_TOKEN_BYTES:
        raise LiveGatewayHTTPError("live_gateway_http_invalid")
    return token, body


def _body_input(payload: bytes) -> str:
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LiveGatewayHTTPError("live_gateway_http_invalid") from error
    if (
        type(value) is not dict
        or set(value) != {"input"}
        or not isinstance(value["input"], str)
        or canonical_json_bytes(value) != payload
    ):
        raise LiveGatewayHTTPError("live_gateway_http_invalid")
    return value["input"]


def _response(connection: socket.socket, status: int, payload: dict[str, Any]) -> None:
    body = canonical_json_bytes(payload)
    reason = {
        200: "OK",
        400: "Bad Request",
        403: "Forbidden",
        409: "Conflict",
        503: "Service Unavailable",
    }[status]
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    connection.sendall(head + body)


def _serve_connection(connection: socket.socket, server: ProtectedModelGatewayServer) -> None:
    try:
        token, payload = _recv_request(connection)
        result = server.evaluate(token, _body_input(payload))
        _response(
            connection,
            200,
            {
                "output_text": result.output_text,
                "request_digest": result.request_digest,
                "status": result.status,
            },
        )
    except LiveGatewayHTTPError:
        _response(connection, 400, {"error": "live_gateway_http_invalid"})
    except LiveGatewayAuthorityError as error:
        if error.code == "live_gateway_capability_consumed":
            status = 409
        elif error.code in {
            "live_gateway_capability_invalid",
            "live_gateway_input_mismatch",
        }:
            status = 403
        else:
            status = 503
        _response(connection, status, {"error": error.code})


def _serve_loopback_listener(
    *,
    listener_fd: int,
    server: ProtectedModelGatewayServer,
    maximum_connections: int | None = None,
    on_ready: object | None = None,
) -> None:
    """Serve a supervisor-created loopback socket without selecting model policy."""
    if not isinstance(server, ProtectedModelGatewayServer) or (
        maximum_connections is not None
        and (
            isinstance(maximum_connections, bool)
            or not isinstance(maximum_connections, int)
            or not 1 <= maximum_connections <= 10_000
        )
    ):
        raise RuntimeError("live_gateway_listener_configuration_invalid")
    try:
        duplicate = os.dup(listener_fd)
        listener = socket.socket(fileno=duplicate)
    except OSError as error:
        raise RuntimeError("live_gateway_listener_invalid") from error
    try:
        address = listener.getsockname()
        if (
            listener.family != socket.AF_INET
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
            or not isinstance(address, tuple)
            or address[0] != "127.0.0.1"
            or isinstance(address[1], bool)
            or not isinstance(address[1], int)
            or not 1 <= address[1] <= 65_535
        ):
            raise RuntimeError("live_gateway_listener_invalid")
        if on_ready is not None:
            on_ready()
        served = 0
        while maximum_connections is None or served < maximum_connections:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(30)
                _serve_connection(connection, server)
            served += 1
    finally:
        listener.close()
