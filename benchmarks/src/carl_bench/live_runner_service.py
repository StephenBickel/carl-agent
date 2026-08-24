"""Typed Unix-socket endpoint for protected live worker execution."""

from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Callable

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_execution_receipt import ProtectedLiveExecutionResult
from carl_bench.live_gateway_authority import LiveGatewayAuthorityError
from carl_bench.live_runner_ipc import MAX_FRAME_BYTES, ProtectedLiveRunnerRequest


def _peer_uid(connection: socket.socket) -> int | None:
    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        return getpeereid()[0]
    if hasattr(socket, "SO_PEERCRED"):
        return struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )[1]
    if hasattr(socket, "LOCAL_PEERCRED"):
        return struct.unpack("II", connection.getsockopt(0, socket.LOCAL_PEERCRED, 8))[1]
    return None


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    while count:
        chunk = connection.recv(count)
        if not chunk:
            raise EOFError
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def _serve_connection(connection: socket.socket, *, runner: object) -> None:
    try:
        size = struct.unpack(">I", _recv_exact(connection, 4))[0]
        if not 0 < size <= MAX_FRAME_BYTES:
            return
        request = ProtectedLiveRunnerRequest.from_bytes(_recv_exact(connection, size))
        try:
            result = runner.execute_worker(
                identity=request.identity,
                policy=request.policy,
                task=request.task,
                subject=request.subject,
                attempt=request.attempt,
                checkout=request.checkout,
                executable=request.executable,
                arguments=request.arguments,
                timeout_seconds=request.timeout_seconds,
            )
            if not isinstance(result, ProtectedLiveExecutionResult):
                raise LiveGatewayAuthorityError("live_execution_result_invalid")
            response = {
                "error_code": None,
                "request_digest": request.digest,
                "result": result.to_canonical_dict(),
                "schema_version": 1,
                "status": "completed",
            }
        except LiveGatewayAuthorityError as error:
            response = {
                "error_code": error.code,
                "request_digest": request.digest,
                "result": None,
                "schema_version": 1,
                "status": "rejected",
            }
        payload = canonical_json_bytes(response)
        connection.sendall(struct.pack(">I", len(payload)) + payload)
    except (EOFError, OSError, ValueError, struct.error):
        return


def _serve_runner_listener(
    *,
    listener: socket.socket,
    allowed_client_uid: int,
    runner: object,
    maximum_connections: int | None = None,
    health_check: Callable[[], None] | None = None,
) -> None:
    if health_check is not None:
        listener.settimeout(0.5)
    served = 0
    while maximum_connections is None or served < maximum_connections:
        if health_check is not None:
            health_check()
        try:
            connection, _ = listener.accept()
        except TimeoutError:
            continue
        with connection:
            if _peer_uid(connection) != allowed_client_uid:
                continue
            connection.settimeout(30)
            if health_check is None:
                _serve_connection(connection, runner=runner)
            else:
                completed = threading.Event()
                errors: list[BaseException] = []

                def serve(
                    active_connection: socket.socket = connection,
                    active_errors: list[BaseException] = errors,
                    active_completed: threading.Event = completed,
                ) -> None:
                    try:
                        _serve_connection(active_connection, runner=runner)
                    except BaseException as error:
                        active_errors.append(error)
                    finally:
                        active_completed.set()

                worker = threading.Thread(
                    target=serve,
                    daemon=True,
                    name="carl-live-runner-connection",
                )
                worker.start()
                while not completed.wait(0.05):
                    health_check()
                if errors:
                    raise errors[0]
            served += 1
