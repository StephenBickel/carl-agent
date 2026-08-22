"""Protected GitHub effect service entrypoint.

This module is the only production path that constructs GitHub credentials, HTTP
transport, or durable state access.  Untrusted clients send closed high-level
requests over ``github_effect_ipc`` and never select an endpoint or payload.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import re
import socket
import stat
import struct
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from carl_bench.cloud_execution import CloudRunRequest
from carl_bench.github_effect_ipc import (
    MAX_FRAME_BYTES,
    RESPONSE_DOMAIN,
    GitHubEffectOperation,
    GitHubEffectProtocolError,
    GitHubEffectRequest,
    GitHubEffectResponse,
    decode_request_bytes,
    encode_response_bytes,
)
from carl_bench.unix_socket_security import (
    ProtectedSocketPathError,
    open_pinned_parent,
    socket_identity_at,
)

_SOCKET_PATH = Path("/run/carl/github-effect.sock")
_ALLOWED_CLIENT_UID = 0
_CONNECTION_TIMEOUT_SECONDS = 2.0


def _protected_graphql_documents() -> object:
    """Build fixed operations from service-local literals and independent pinned digests."""
    github = _github_cloud()
    mark_ready = """mutation MarkPullRequestReadyForReview($pullRequestId: ID!) {
  markPullRequestReadyForReview(input: {pullRequestId: $pullRequestId}) {
    pullRequest {
      id
      number
      isDraft
      baseRefName
      headRefName
      headRefOid
      repository { nameWithOwner }
    }
  }
}"""
    enable_auto_merge = (
        "mutation EnablePullRequestAutoMerge($pullRequestId: ID!, "
        "$expectedHeadOid: GitObjectID!) {\n"
        "  enablePullRequestAutoMerge(input: {pullRequestId: $pullRequestId, "
        "expectedHeadOid: $expectedHeadOid, mergeMethod: SQUASH}) {\n"
        """    pullRequest {
      id
      number
      isDraft
      baseRefName
      headRefName
      headRefOid
      repository { nameWithOwner }
      autoMergeRequest { mergeMethod }
    }
  }
}"""
    )
    return github._GitHubGraphQLDocuments.from_pinned_documents(
        mark_ready=mark_ready,
        enable_auto_merge=enable_auto_merge,
        expected_mark_ready_digest="49a7c81b57a1cdfb851fbaa6c3dfd374a892ed76c1f56afaf4282e147a62f973",
        expected_enable_auto_merge_digest=(
            "6a96f13af464b95dcd16d58fe01b851362c59893e24b842a40592b04765336f4"
        ),
    )


def _github_cloud():
    # Credential-bearing implementation is imported only by this service process.
    from carl_bench import github_cloud

    return github_cloud


def _typed_request(request: GitHubEffectRequest, policy: object) -> tuple[object, object, str]:
    github = _github_cloud()
    parameters = request.parameters
    operation = request.operation
    repository = policy.repository
    if operation is GitHubEffectOperation.DISPATCH_WORKFLOW:
        typed = CloudRunRequest.create(**parameters)
        match = re.search(r"-attempt-([1-3])$", request.command_key)
        if match is None:
            raise github.GitHubCloudError("github_command_binding_mismatch")
        binding = github.workflow_dispatch_binding(
            typed,
            attempt=int(match.group(1)),
            workflow_ref=policy.workflow_ref,
            dispatch_actor_login=policy.dispatch_actor_login,
        )
        method = "dispatch_workflow"
    elif operation is GitHubEffectOperation.CREATE_EXPERIMENTAL_REF:
        typed = github.ExperimentalBranchRequest(**parameters)
        binding = github.experimental_branch_binding(repository, typed)
        method = "create_or_reconcile_experimental_branch"
    elif operation is GitHubEffectOperation.CREATE_PULL_REQUEST:
        typed = github.PullRequestCreateRequest(
            **{key: value for key, value in parameters.items() if key != "pull_request_body"},
            body=parameters["pull_request_body"],
        )
        binding = github.pull_request_create_binding(repository, typed)
        method = "create_or_reconcile_pull_request"
    elif operation is GitHubEffectOperation.UPDATE_PULL_REQUEST:
        typed = github.PullRequestUpdateRequest(
            **{key: value for key, value in parameters.items() if key != "pull_request_body"},
            body=parameters["pull_request_body"],
        )
        binding = github.pull_request_update_binding(repository, typed)
        method = "update_pull_request"
    elif operation is GitHubEffectOperation.MARK_PULL_REQUEST_READY:
        typed = github.PullRequestReadyRequest(**parameters)
        binding = github.pull_request_ready_binding(repository, typed)
        method = "mark_pull_request_ready"
    elif operation is GitHubEffectOperation.ENABLE_PULL_REQUEST_AUTO_MERGE:
        typed = github.PullRequestAutoMergeRequest(**parameters)
        binding = github.pull_request_auto_merge_binding(repository, typed)
        method = "enable_pull_request_auto_merge"
    elif operation is GitHubEffectOperation.OBSERVE_REQUIRED_CHECKS:
        typed = github.RequiredChecksRequest(
            head_sha=parameters["head_sha"], required_checks=tuple(parameters["required_checks"])
        )
        binding = github.required_checks_binding(repository, typed)
        method = "observe_required_checks"
    elif operation is GitHubEffectOperation.CREATE_REVERT_REF:
        typed = github.RevertBranchRequest(**parameters)
        binding = github.revert_branch_binding(repository, typed)
        method = "create_or_reconcile_revert_branch"
    elif operation is GitHubEffectOperation.CREATE_REVERT_PULL_REQUEST:
        typed = github.RevertPullRequestRequest(
            **{key: value for key, value in parameters.items() if key != "pull_request_body"},
            body=parameters["pull_request_body"],
        )
        binding = github.revert_pull_request_binding(repository, typed)
        method = "create_or_reconcile_revert_pull_request"
    else:  # pragma: no cover - enum exhaustiveness guard
        raise github.GitHubCloudError("github_operation_not_allowed")
    return typed, binding, method


def _canonical_result(value: object) -> object:
    if dataclasses.is_dataclass(value):
        return {
            (
                "pull_request_body"
                if field.name == "body"
                else "pull_request_url"
                if field.name == "url"
                else field.name
            ): _canonical_result(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, tuple):
        return [_canonical_result(item) for item in value]
    if isinstance(value, list):
        return [_canonical_result(item) for item in value]
    if type(value) is dict:
        return {key: _canonical_result(item) for key, item in value.items()}
    if value is None or isinstance(value, bool | int | str):
        return value
    raise TypeError("unsupported protected result")


def _execute_validated(
    request: GitHubEffectRequest,
    *,
    gateway: object,
    policy: object,
    state_controller: object,
    clock: object,
) -> object:
    """Validate durable authority, then invoke one fixed high-level executor method."""
    github = _github_cloud()
    typed, binding, method = _typed_request(request, policy)
    observed_at = clock()
    if not isinstance(observed_at, datetime) or observed_at.tzinfo != UTC:
        raise github.GitHubCloudError("github_clock_invalid")
    state = state_controller.resolve_claimed_command(
        request.command_key,
        authority=binding.authority,
        observed_at=observed_at,
    )
    command = state.command
    effect_descriptor = {
        "authority": binding.authority,
        "command_key": binding.command_key,
        "operation": binding.operation,
        "request_digest": binding.request_digest,
    }
    expected_effect_key = (
        "cloud-effect-" + hashlib.sha256(github.canonical_json_bytes(effect_descriptor)).hexdigest()
    )
    if (
        request.command_key != binding.command_key
        or request.request_key != binding.request_key
        or request.effect_key != command.effect_key
        or request.effect_key != expected_effect_key
        or request.occurred_at != command.occurred_at
        or command.request_digest != binding.request_digest
        or command.operation != binding.operation
        or command.authority != binding.authority
    ):
        raise github.GitHubCloudError("github_command_binding_mismatch")
    return getattr(gateway, method)(request.command_key, typed)


def _response_for(
    request: GitHubEffectRequest,
    *,
    gateway: object,
    policy: object,
    state_controller: object,
    clock: object,
) -> GitHubEffectResponse:
    github = _github_cloud()
    try:
        result = _execute_validated(
            request,
            gateway=gateway,
            policy=policy,
            state_controller=state_controller,
            clock=clock,
        )
        observed_at = clock().isoformat().replace("+00:00", "Z")
        if isinstance(result, github.GitHubRetryDecision):
            return GitHubEffectResponse(
                1,
                RESPONSE_DOMAIN,
                "retry_scheduled",
                request.digest,
                observed_at,
                None,
                result.retry_not_before,
                None,
            )
        document = _canonical_result(result)
        assert isinstance(document, dict)
        return GitHubEffectResponse(
            1,
            RESPONSE_DOMAIN,
            "completed",
            request.digest,
            observed_at,
            {"result_type": type(result).__name__, "value": document},
            None,
            None,
        )
    except github.GitHubCloudError as error:
        observed_at = clock().isoformat().replace("+00:00", "Z")
        return GitHubEffectResponse(
            1,
            RESPONSE_DOMAIN,
            "rejected",
            request.digest,
            observed_at,
            None,
            None,
            error.code,
        )


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise EOFError
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _serve_connection(
    connection: socket.socket,
    *,
    gateway: object,
    policy: object,
    state_controller: object,
    clock: object,
) -> None:
    try:
        size = struct.unpack(">I", _recv_exact(connection, 4))[0]
        if not 0 < size <= MAX_FRAME_BYTES:
            return
        request = decode_request_bytes(_recv_exact(connection, size))
        response = _response_for(
            request,
            gateway=gateway,
            policy=policy,
            state_controller=state_controller,
            clock=clock,
        )
        payload = encode_response_bytes(response)
        connection.sendall(struct.pack(">I", len(payload)) + payload)
    except (
        EOFError,
        OSError,
        TimeoutError,
        struct.error,
        GitHubEffectProtocolError,
    ):
        return


def _activation_descriptor_from_environment(
    *, environment: Mapping[str, str], process_id: int, descriptor_fd: int = 3
) -> int:
    """Accept exactly one named supervisor descriptor for this process."""
    if (
        isinstance(process_id, bool)
        or not isinstance(process_id, int)
        or process_id <= 0
        or isinstance(descriptor_fd, bool)
        or not isinstance(descriptor_fd, int)
        or descriptor_fd < 0
        or environment.get("LISTEN_PID") != str(process_id)
        or environment.get("LISTEN_FDS") != "1"
        or environment.get("LISTEN_FDNAMES") != "github-effect"
    ):
        raise RuntimeError("github_effect_service_activation_invalid")
    return descriptor_fd


def _descriptor_identity(descriptor: int, *, expected_uid: int) -> tuple[int, int, int, int]:
    try:
        details = os.fstat(descriptor)
    except OSError as error:
        raise RuntimeError("github_effect_service_listener_invalid") from error
    if not stat.S_ISSOCK(details.st_mode) or details.st_uid != expected_uid:
        raise RuntimeError("github_effect_service_listener_invalid")
    return details.st_dev, details.st_ino, details.st_mode, details.st_uid


def _listener_is_accepting(listener: socket.socket) -> bool:
    """Check listening state, including AF_UNIX platforms without SO_ACCEPTCONN."""
    try:
        return listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1
    except OSError:
        previous_timeout = listener.gettimeout()
        listener.setblocking(False)
        try:
            connection, _ = listener.accept()
        except BlockingIOError:
            return True
        except OSError:
            return False
        else:
            connection.close()
            return False
        finally:
            listener.settimeout(previous_timeout)


@contextmanager
def _validated_activated_listener(
    *, listener_fd: int, socket_path: Path, expected_uid: int
) -> Iterator[socket.socket]:
    """Duplicate and validate a supervisor-owned listening Unix socket."""
    descriptor_before = _descriptor_identity(listener_fd, expected_uid=expected_uid)
    try:
        parent_fd = open_pinned_parent(socket_path, expected_uid=expected_uid)
        path_before = socket_identity_at(parent_fd, socket_path.name, expected_uid=expected_uid)
    except ProtectedSocketPathError as error:
        raise RuntimeError("github_effect_service_socket_identity_invalid") from error
    try:
        try:
            duplicate = os.dup(listener_fd)
            listener = socket.socket(fileno=duplicate)
        except OSError as error:
            raise RuntimeError("github_effect_service_listener_invalid") from error
        try:
            if (
                listener.family != socket.AF_UNIX
                or listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or not _listener_is_accepting(listener)
                or listener.getsockname() != os.fspath(socket_path)
            ):
                raise RuntimeError("github_effect_service_listener_invalid")
            descriptor_after = _descriptor_identity(listener_fd, expected_uid=expected_uid)
            path_after = socket_identity_at(parent_fd, socket_path.name, expected_uid=expected_uid)
            if descriptor_after != descriptor_before or path_after != path_before:
                raise RuntimeError("github_effect_service_socket_identity_invalid")
            yield listener
        finally:
            listener.close()
    except ProtectedSocketPathError as error:
        raise RuntimeError("github_effect_service_socket_identity_invalid") from error
    finally:
        os.close(parent_fd)


def _serve_activated_listener(
    *,
    listener_fd: int,
    socket_path: Path,
    allowed_client_uid: int,
    service_uid: int,
    gateway: object,
    policy: object,
    state_controller: object,
    clock: object,
    connection_timeout_seconds: float,
    on_ready: object | None = None,
) -> None:
    """Serve requests from a validated supervisor-owned listener without path mutation."""
    if (
        not socket_path.is_absolute()
        or socket_path.name in {"", ".", ".."}
        or isinstance(connection_timeout_seconds, bool)
        or not isinstance(connection_timeout_seconds, int | float)
        or not 0.05 <= connection_timeout_seconds <= 30.0
    ):
        raise RuntimeError("github_effect_service_configuration_invalid")
    with _validated_activated_listener(
        listener_fd=listener_fd,
        socket_path=socket_path,
        expected_uid=service_uid,
    ) as listener:
        if on_ready is not None:
            on_ready()
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(float(connection_timeout_seconds))
                peer_uid = _peer_uid(connection)
                if peer_uid is None or peer_uid != allowed_client_uid:
                    continue
                _serve_connection(
                    connection,
                    gateway=gateway,
                    policy=policy,
                    state_controller=state_controller,
                    clock=clock,
                )


def _peer_uid(connection: socket.socket) -> int | None:
    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        return getpeereid()[0]
    if hasattr(socket, "SO_PEERCRED"):
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        return struct.unpack("3i", credentials)[1]
    if hasattr(socket, "LOCAL_PEERCRED"):
        credentials = connection.getsockopt(0, socket.LOCAL_PEERCRED, 8)
        return struct.unpack("II", credentials)[1]
    return None


def main() -> int:
    """Run the fixed protected service. No caller-selected dependencies or paths."""
    listener_fd = _activation_descriptor_from_environment(
        environment=os.environ,
        process_id=os.getpid(),
    )
    github = _github_cloud()
    policy = github._load_protected_policy()
    token = os.environ.get(github._PROTECTED_TOKEN_ENV)
    if token is None or not token or len(token.encode()) > 4_096:
        raise RuntimeError("github_effect_service_credentials_invalid")
    state_controller = github._ProtectedStateControllerClient()
    gateway = github._InjectedGitHubCloudGateway._construct_test_gateway(
        repository=policy.repository,
        token=token,
        transport=github._ProtectedGitHubTransport(),
        clock=github._system_clock,
        state_controller=state_controller,
        workflow_ref=policy.workflow_ref,
        dispatch_actor_login=policy.dispatch_actor_login,
        graphql_documents=_protected_graphql_documents(),
    )
    _serve_activated_listener(
        listener_fd=listener_fd,
        socket_path=_SOCKET_PATH,
        allowed_client_uid=_ALLOWED_CLIENT_UID,
        service_uid=0,
        gateway=gateway,
        policy=policy,
        state_controller=state_controller,
        clock=github._system_clock,
        connection_timeout_seconds=_CONNECTION_TIMEOUT_SECONDS,
    )


if __name__ == "__main__":  # pragma: no cover - service manager entrypoint
    raise SystemExit(main())
