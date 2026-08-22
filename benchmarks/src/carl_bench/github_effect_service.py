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

_SOCKET_PATH = Path("/run/carl/github-effect.sock")
_ALLOWED_CLIENT_UID = 0


def _github_cloud():
    # Credential-bearing implementation is imported only by this service process.
    from carl_bench import github_cloud

    return github_cloud


def _typed_request(request: GitHubEffectRequest, policy: object) -> tuple[object, object, str]:
    github = _github_cloud()
    parameters = request.parameters
    operation = request.operation
    repository = policy.repository
    if operation in {
        GitHubEffectOperation.DISPATCH_WORKFLOW,
        GitHubEffectOperation.DISCOVER_WORKFLOW_RUN,
    }:
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
        typed = github.PullRequestCreateRequest(**parameters)
        binding = github.pull_request_create_binding(repository, typed)
        method = "create_or_reconcile_pull_request"
    elif operation is GitHubEffectOperation.UPDATE_PULL_REQUEST:
        typed = github.PullRequestUpdateRequest(**parameters)
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
        typed = github.RevertPullRequestRequest(**parameters)
        binding = github.revert_pull_request_binding(repository, typed)
        method = "create_or_reconcile_revert_pull_request"
    else:  # pragma: no cover - enum exhaustiveness guard
        raise github.GitHubCloudError("github_operation_not_allowed")
    return typed, binding, method


def _canonical_result(value: object) -> object:
    if dataclasses.is_dataclass(value):
        return {
            field.name: _canonical_result(getattr(value, field.name))
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
    if request.operation is GitHubEffectOperation.DISCOVER_WORKFLOW_RUN:
        # Discovery cannot silently escalate into dispatch. A dedicated observer is
        # added with the next effect family; fail closed until then.
        raise github.GitHubCloudError("github_operation_not_available")
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
    size = struct.unpack(">I", _recv_exact(connection, 4))[0]
    if not 0 < size <= MAX_FRAME_BYTES:
        return
    try:
        request = decode_request_bytes(_recv_exact(connection, size))
        response = _response_for(
            request,
            gateway=gateway,
            policy=policy,
            state_controller=state_controller,
            clock=clock,
        )
    except (EOFError, GitHubEffectProtocolError):
        return
    payload = encode_response_bytes(response)
    connection.sendall(struct.pack(">I", len(payload)) + payload)


def _validate_runtime_directory(path: Path) -> None:
    details = path.lstat()
    if (
        stat.S_ISLNK(details.st_mode)
        or not stat.S_ISDIR(details.st_mode)
        or details.st_uid != 0
        or stat.S_IMODE(details.st_mode) & 0o022
    ):
        raise RuntimeError("github_effect_service_configuration_invalid")


def _peer_uid(connection: socket.socket) -> int | None:
    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        return getpeereid()[0]
    if hasattr(socket, "SO_PEERCRED"):
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        return struct.unpack("3i", credentials)[1]
    return None


def main() -> int:
    """Run the fixed protected service. No caller-selected dependencies or paths."""
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
    )
    _validate_runtime_directory(_SOCKET_PATH.parent)
    if _SOCKET_PATH.exists() or _SOCKET_PATH.is_symlink():
        raise RuntimeError("github_effect_service_socket_exists")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(os.fspath(_SOCKET_PATH))
        os.chmod(_SOCKET_PATH, 0o600)
        listener.listen(32)
        while True:
            connection, _ = listener.accept()
            with connection:
                peer_uid = _peer_uid(connection)
                if peer_uid is None or peer_uid != _ALLOWED_CLIENT_UID:
                    continue
                _serve_connection(
                    connection,
                    gateway=gateway,
                    policy=policy,
                    state_controller=state_controller,
                    clock=github._system_clock,
                )


if __name__ == "__main__":  # pragma: no cover - service manager entrypoint
    raise SystemExit(main())
