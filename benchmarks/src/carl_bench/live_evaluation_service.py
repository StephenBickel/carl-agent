"""Supervisor-activated protected live-evaluation service."""

from __future__ import annotations

import os
import select
import socket
import stat
import struct
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from carl_bench.live_evaluation_authority import (
    LiveEvaluationAuthorityError,
    ProtectedLiveEvaluationAuthority,
)
from carl_bench.live_evaluation_ipc import (
    MAX_FRAME_BYTES,
    LiveEvaluationProtocolError,
    ProtectedJoinRequest,
    ProtectedJoinResponse,
    decode_request_bytes,
    encode_response_bytes,
)
from carl_bench.unix_socket_security import (
    ProtectedSocketPathError,
    open_pinned_parent,
    socket_identity_at,
)

_SOCKET_PATH = Path("/run/carl/live-evaluator.sock")
_CONNECTION_TIMEOUT_SECONDS = 2.0
_ACTIVATION_PROBE_TIMEOUT_SECONDS = 1.0


def _now_text(clock: object) -> str:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo != UTC:
        raise RuntimeError("live_evaluation_service_clock_invalid")
    return value.isoformat().replace("+00:00", "Z")


def _response_for(
    request: ProtectedJoinRequest, *, authority: object, clock: object
) -> ProtectedJoinResponse:
    try:
        receipt = authority.combine(
            request_digest=request.request_digest,
            deterministic_locator=request.deterministic_locator,
            live_locator=request.live_locator,
        )
        return ProtectedJoinResponse(
            1,
            "completed",
            request.digest,
            _now_text(clock),
            receipt.to_canonical_dict(),
            None,
        )
    except LiveEvaluationAuthorityError as error:
        return ProtectedJoinResponse(
            1,
            "rejected",
            request.digest,
            _now_text(clock),
            None,
            error.code,
        )


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    while count:
        chunk = connection.recv(count)
        if not chunk:
            raise EOFError
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def _serve_connection(connection: socket.socket, *, authority: object, clock: object) -> None:
    try:
        size = struct.unpack(">I", _recv_exact(connection, 4))[0]
        if not 0 < size <= MAX_FRAME_BYTES:
            return
        request = decode_request_bytes(_recv_exact(connection, size))
        payload = encode_response_bytes(_response_for(request, authority=authority, clock=clock))
        connection.sendall(struct.pack(">I", len(payload)) + payload)
    except (EOFError, OSError, TimeoutError, struct.error, LiveEvaluationProtocolError):
        return


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


def _peer_pid(connection: socket.socket) -> int | None:
    if hasattr(socket, "SO_PEERCRED"):
        return struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        )[0]
    if hasattr(socket, "LOCAL_PEERCRED"):
        option = getattr(socket, "LOCAL_PEERPID", 2)
        return struct.unpack("i", connection.getsockopt(0, option, 4))[0]
    return None


def _descriptor_identity(descriptor: int, expected_uid: int) -> tuple[int, int, int, int]:
    try:
        details = os.fstat(descriptor)
    except OSError as error:
        raise RuntimeError("live_evaluation_service_listener_invalid") from error
    if not stat.S_ISSOCK(details.st_mode) or details.st_uid != expected_uid:
        raise RuntimeError("live_evaluation_service_listener_invalid")
    return details.st_dev, details.st_ino, details.st_mode, details.st_uid


def _prove_listener(listener: socket.socket, path: Path) -> list[socket.socket]:
    queued: list[socket.socket] = []
    deadline = time.monotonic() + _ACTIVATION_PROBE_TIMEOUT_SECONDS
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(_ACTIVATION_PROBE_TIMEOUT_SECONDS)
            probe.connect(os.fspath(path))
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([listener], [], [], remaining)[0]:
                    raise RuntimeError("live_evaluation_service_socket_identity_invalid")
                connection, _ = listener.accept()
                if _peer_pid(connection) == os.getpid():
                    connection.close()
                    return queued
                queued.append(connection)
    except Exception as error:
        for connection in queued:
            connection.close()
        if isinstance(error, RuntimeError):
            raise
        raise RuntimeError("live_evaluation_service_socket_identity_invalid") from error


@contextmanager
def _validated_activated_listener(
    *, listener_fd: int, socket_path: Path, expected_uid: int
) -> Iterator[tuple[socket.socket, list[socket.socket]]]:
    descriptor_before = _descriptor_identity(listener_fd, expected_uid)
    try:
        parent_fd = open_pinned_parent(socket_path, expected_uid=expected_uid)
        path_before = socket_identity_at(parent_fd, socket_path.name, expected_uid=expected_uid)
    except ProtectedSocketPathError as error:
        raise RuntimeError("live_evaluation_service_socket_identity_invalid") from error
    try:
        duplicate = os.dup(listener_fd)
        listener = socket.socket(fileno=duplicate)
        try:
            if (
                listener.family != socket.AF_UNIX
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or listener.getsockname() != os.fspath(socket_path)
            ):
                raise RuntimeError("live_evaluation_service_listener_invalid")
            queued = _prove_listener(listener, socket_path)
            descriptor_after = _descriptor_identity(listener_fd, expected_uid)
            path_after = socket_identity_at(parent_fd, socket_path.name, expected_uid=expected_uid)
            if descriptor_after != descriptor_before or path_after != path_before:
                raise RuntimeError("live_evaluation_service_socket_identity_invalid")
            try:
                yield listener, queued
            finally:
                for connection in queued:
                    connection.close()
        finally:
            listener.close()
    except ProtectedSocketPathError as error:
        raise RuntimeError("live_evaluation_service_socket_identity_invalid") from error
    finally:
        os.close(parent_fd)


def _serve_activated_listener(
    *,
    listener_fd: int,
    socket_path: Path,
    allowed_client_uid: int,
    service_uid: int,
    authority: object,
    clock: object,
    connection_timeout_seconds: float,
    on_ready: object | None = None,
) -> None:
    if (
        not socket_path.is_absolute()
        or socket_path.name in {"", ".", ".."}
        or isinstance(connection_timeout_seconds, bool)
        or not isinstance(connection_timeout_seconds, int | float)
        or not 0.05 <= connection_timeout_seconds <= 30
    ):
        raise RuntimeError("live_evaluation_service_configuration_invalid")
    with _validated_activated_listener(
        listener_fd=listener_fd,
        socket_path=socket_path,
        expected_uid=service_uid,
    ) as activated:
        listener, queued = activated
        if on_ready is not None:
            on_ready()
        while True:
            connection = queued.pop(0) if queued else listener.accept()[0]
            with connection:
                connection.settimeout(float(connection_timeout_seconds))
                if _peer_uid(connection) != allowed_client_uid:
                    continue
                _serve_connection(connection, authority=authority, clock=clock)


def _inheritable_descriptors() -> set[int]:
    names: list[str] | None = None
    for root in ("/proc/self/fd", "/dev/fd"):
        try:
            names = os.listdir(root)
        except OSError:
            continue
        break
    candidates = (
        (int(name) for name in names if name.isdecimal())
        if names is not None
        else range(3, int(os.sysconf("SC_OPEN_MAX")))
    )
    result: set[int] = set()
    for descriptor in candidates:
        if descriptor < 3:
            continue
        try:
            if os.get_inheritable(descriptor):
                result.add(descriptor)
        except OSError:
            continue
    return result


def _activation_descriptor_from_environment(
    *, environment: Mapping[str, str], process_id: int, descriptor_fd: int = 3
) -> int:
    if (
        isinstance(process_id, bool)
        or not isinstance(process_id, int)
        or process_id <= 0
        or environment.get("LISTEN_PID") != str(process_id)
        or environment.get("LISTEN_FDS") != "1"
        or environment.get("LISTEN_FDNAMES") != "live-evaluator"
        or not os.get_inheritable(descriptor_fd)
        or _inheritable_descriptors() != {descriptor_fd}
    ):
        raise RuntimeError("live_evaluation_service_activation_invalid")
    return descriptor_fd


def _load_protected_authority() -> ProtectedLiveEvaluationAuthority:
    """Load the fixed-policy authority inside the activated service."""
    return ProtectedLiveEvaluationAuthority.from_protected_process()


def main() -> int:
    descriptor = _activation_descriptor_from_environment(
        environment=os.environ, process_id=os.getpid()
    )
    authority = _load_protected_authority()
    _serve_activated_listener(
        listener_fd=descriptor,
        socket_path=_SOCKET_PATH,
        allowed_client_uid=0,
        service_uid=0,
        authority=authority,
        clock=lambda: datetime.now(UTC),
        connection_timeout_seconds=_CONNECTION_TIMEOUT_SECONDS,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
