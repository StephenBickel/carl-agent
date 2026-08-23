from __future__ import annotations

import importlib
import os
import socket
import tempfile
import threading
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from test_product_builder import _candidate, _register
from test_product_builder_evidence import _receipt
from test_product_builder_runtime import PARENT, _dispatch, _request

from carl_bench.github_effect_ipc import (
    RESPONSE_DOMAIN,
    GitHubEffectOperation,
    GitHubEffectResponse,
)


def _effects(name: str):
    return getattr(importlib.import_module("carl_bench.product_builder_effects"), name)


def _packet():
    registration = _register()
    receipt = replace(_receipt(), builder_request_digest=_request().digest)
    envelope = importlib.import_module(
        "carl_bench.product_builder_evidence"
    ).SignedAttemptReceipt.sign(receipt, b"k" * 32)
    candidate = replace(_candidate(registration), changed_path_count=1)
    packet = importlib.import_module(
        "carl_bench.product_builder_evidence"
    ).ProtectedCandidatePacket(
        schema_version=1,
        builder_request_digest=_request().digest,
        registration_digest=registration.digest,
        parent_commit=PARENT,
        candidate_tree=receipt.postpatch_tree,
        diff_artifact_digest=receipt.patch_digest,
        candidate=candidate,
        attempt_receipts=(envelope,),
    )
    return packet.verify(b"k" * 32)


def _terminal(packet):
    request = _request()
    return _effects("BuilderTerminalDocument").create(
        request=request,
        registration_digest=packet.registration_digest,
        packet=packet,
        candidate_tree=packet.candidate_tree,
        requested_at="2026-08-23T12:10:00Z",
        repository_id="StephenBickel/carl-agent",
        remote_url="https://github.com/StephenBickel/carl-agent.git",
    )


class RecordingGitHub:
    def __init__(self, *, mismatch: bool = False) -> None:
        self.requests = []
        self.mismatch = mismatch

    def execute(self, request):
        self.requests.append(request)
        common = {
            "command_occurred_at": request.occurred_at,
            "effect_key": request.effect_key,
            "observed_at": "2026-08-23T12:11:00Z",
            "repository": "StephenBickel/carl-agent",
            "request_key": request.request_key,
        }
        if request.operation is GitHubEffectOperation.CREATE_EXPERIMENTAL_REF:
            result = {
                "result_type": "GitReferenceSnapshot",
                "value": {
                    **common,
                    "commit_sha": "0" * 40
                    if self.mismatch
                    else request.parameters["candidate_commit"],
                    "ref": f"refs/heads/{request.parameters['branch']}",
                    "status": "created",
                },
            }
        else:
            result = {
                "result_type": "WorkflowDispatchSnapshot",
                "value": {
                    **common,
                    "attempt_key": f"builder-validation-{request.effect_key[-16:]}",
                    "head_sha": request.parameters["candidate_commit"],
                    "run_id": 42,
                    "status": "dispatched",
                    "workflow_file": request.parameters["workflow_file"],
                    "workflow_revision": request.parameters["workflow_revision"],
                },
            }
        return GitHubEffectResponse(
            schema_version=1,
            domain=RESPONSE_DOMAIN,
            status="completed",
            request_digest=request.digest,
            observed_at="2026-08-23T12:11:00Z",
            result=result,
            retry_not_before=None,
            error_code=None,
        )


def _prepared(tmp_path: Path):
    runtime = importlib.import_module("carl_bench.product_builder_runtime")
    store = runtime.ProtectedBuilderStore._for_testing(tmp_path / "state")
    request = _request()
    store.enqueue(request)
    packet = _packet()
    store.persist_packet(request.digest, packet, verification_key=b"k" * 32)
    terminal = _terminal(packet)
    store.persist_terminal(terminal)
    return store, terminal


class _ExactExperimentalGateway:
    def create_or_reconcile_experimental_branch(self, command_key, request):
        github = importlib.import_module("carl_bench.github_cloud")
        binding = github.experimental_branch_binding("StephenBickel/carl-agent", request)
        authority = _effects("DurableCoordinatorCommandAuthority")._for_testing(self.state_root)
        state = authority.resolve_claimed_command(
            command_key,
            authority="builder",
            observed_at=datetime(2026, 8, 23, 12, 11, tzinfo=UTC),
        )
        return github.GitReferenceSnapshot(
            status="created",
            repository="StephenBickel/carl-agent",
            ref=f"refs/heads/{request.branch}",
            commit_sha=request.candidate_commit,
            request_key=binding.request_key,
            effect_key=state.command.effect_key,
            command_occurred_at=state.command.occurred_at,
            observed_at="2026-08-23T12:11:00Z",
        )

    def dispatch_workflow(self, command_key, request):
        github = importlib.import_module("carl_bench.github_cloud")
        binding = github.workflow_dispatch_binding(
            request,
            attempt=int(command_key.rsplit("-attempt-", 1)[1]),
            workflow_ref="main",
            dispatch_actor_login="carl-autonomy[bot]",
        )
        authority = _effects("DurableCoordinatorCommandAuthority")._for_testing(self.state_root)
        state = authority.resolve_claimed_command(
            command_key,
            authority="coordinator",
            observed_at=datetime(2026, 8, 23, 12, 11, tzinfo=UTC),
        )
        return github.WorkflowDispatchSnapshot(
            status="dispatched",
            repository=request.repository,
            workflow_file=request.workflow_file,
            workflow_revision=request.workflow_revision,
            request_key=binding.request_key,
            attempt_key=binding.attempt_key,
            effect_key=state.command.effect_key,
            command_occurred_at=state.command.occurred_at,
            observed_at="2026-08-23T12:11:00Z",
            run_id=42,
            head_sha=request.candidate_commit,
        )


def _start_real_effect_service(socket_path: Path, state_root: Path):
    service = importlib.import_module("carl_bench.github_effect_service")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(socket_path))
    os.chmod(socket_path, 0o600)
    listener.listen(1)
    gateway = _ExactExperimentalGateway()
    gateway.state_root = state_root

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            service._serve_connection(
                connection,
                gateway=gateway,
                policy=SimpleNamespace(
                    repository="StephenBickel/carl-agent",
                    workflow_ref="main",
                    dispatch_actor_login="carl-autonomy[bot]",
                ),
                state_controller=_effects("DurableCoordinatorCommandAuthority")._for_testing(
                    state_root
                ),
                clock=lambda: datetime(2026, 8, 23, 12, 11, tzinfo=UTC),
            )
        listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def test_packet_and_terminal_are_canonical_restart_safe(tmp_path: Path) -> None:
    store, terminal = _prepared(tmp_path)
    runtime = importlib.import_module("carl_bench.product_builder_runtime")
    reopened = runtime.ProtectedBuilderStore._for_testing(tmp_path / "state")

    assert reopened.load_packet(terminal.candidate_packet_digest)["packet_digest"] == (
        terminal.candidate_packet_digest
    )
    assert reopened.load_terminal(terminal.request_digest) == terminal


def test_publication_is_purpose_bound_and_idempotent(tmp_path: Path) -> None:
    store, terminal = _prepared(tmp_path)
    github = RecordingGitHub()
    executor = _effects("ProtectedBuilderEffectExecutor")._for_testing(store=store, github=github)
    request = _effects("PurposeBoundEffectRequest").for_publication(terminal)

    first = executor.execute(request)
    second = executor.execute(request)

    assert first == second
    assert first.status == "completed"
    assert len(github.requests) == 1
    emitted = github.requests[0]
    assert emitted.operation is GitHubEffectOperation.CREATE_EXPERIMENTAL_REF
    assert emitted.parameters == {
        "branch": f"experimental/{terminal.experiment_id}",
        "candidate_commit": terminal.candidate_commit,
        "experiment_id": terminal.experiment_id,
    }


def test_real_effect_socket_executes_durable_publication_before_downstream_command(
    tmp_path: Path,
) -> None:
    store, terminal = _prepared(tmp_path)
    state_root = tmp_path / "coordinator-state"
    authority = _effects("DurableCoordinatorCommandAuthority")._for_testing(state_root)
    socket_root = Path("/private/tmp") if Path("/tmp").is_symlink() else Path("/tmp")
    socket_directory = Path(tempfile.mkdtemp(prefix="carl-builder-effect-", dir=socket_root))
    socket_path = socket_directory / "effect.sock"
    thread = _start_real_effect_service(socket_path, state_root)
    client = importlib.import_module(
        "carl_bench.github_effect_client"
    ).GitHubEffectSocketClient._for_testing(
        socket_path=socket_path,
        expected_peer_uid=os.getuid(),
        timeout_seconds=2.0,
    )
    executor = _effects("ProtectedBuilderEffectExecutor")._for_testing(
        store=store,
        authority=authority,
        github=client,
    )
    request = _effects("PurposeBoundEffectRequest").for_publication(terminal)

    result = executor.execute(request)
    thread.join(2)

    assert result.status == "completed"
    state = authority.resolve_claimed_command(
        request.command_key,
        authority="builder",
        observed_at=datetime(2026, 8, 23, 12, 12, tzinfo=UTC),
    )
    assert state.command.effect_key == request.effect_key
    assert state.command.request_digest == request.github_binding_request_digest
    assert not thread.is_alive()
    socket_path.unlink(missing_ok=True)

    downstream_socket = socket_directory / "downstream.sock"
    downstream_thread = _start_real_effect_service(downstream_socket, state_root)
    downstream_client = importlib.import_module(
        "carl_bench.github_effect_client"
    ).GitHubEffectSocketClient._for_testing(
        socket_path=downstream_socket,
        expected_peer_uid=os.getuid(),
        timeout_seconds=2.0,
    )
    downstream = _effects("PurposeBoundEffectRequest").for_validation(terminal)
    downstream_result = (
        _effects("ProtectedBuilderEffectExecutor")
        ._for_testing(
            store=store,
            authority=authority,
            github=downstream_client,
        )
        .execute(downstream)
    )
    downstream_thread.join(2)

    assert downstream_result.status == "completed"
    downstream_state = authority.resolve_claimed_command(
        downstream.command_key,
        authority="coordinator",
        observed_at=datetime(2026, 8, 23, 12, 12, tzinfo=UTC),
    )
    assert downstream_state.command.effect_key == downstream.effect_key
    assert downstream_state.command.request_digest == downstream.github_binding_request_digest
    assert not downstream_thread.is_alive()
    downstream_socket.unlink(missing_ok=True)
    socket_directory.rmdir()


def test_persisted_response_identity_drift_freezes_before_replay_or_downstream(
    tmp_path: Path,
) -> None:
    store, terminal = _prepared(tmp_path)
    github = RecordingGitHub()
    authority = _effects("DurableCoordinatorCommandAuthority")._for_testing(
        tmp_path / "coordinator-state"
    )
    executor = _effects("ProtectedBuilderEffectExecutor")._for_testing(
        store=store, authority=authority, github=github
    )
    request = _effects("PurposeBoundEffectRequest").for_publication(terminal)
    assert executor.execute(request).status == "completed"
    response_path = tmp_path / "state" / "effects" / f"{request.idempotency_key}.response.json"
    value = importlib.import_module("json").loads(response_path.read_bytes())
    value["effect_key"] = "cloud-effect-" + "0" * 64
    response_path.write_bytes(
        importlib.import_module("carl_bench.canonical").canonical_json_bytes(value)
    )

    replay = executor.execute(request)

    assert replay.status == "frozen"
    assert replay.reason == "builder_effect_persisted_identity_mismatch"
    assert len(github.requests) == 1


def test_pending_publication_recovers_with_same_claimed_command_after_restart(
    tmp_path: Path,
) -> None:
    store, terminal = _prepared(tmp_path)
    authority = _effects("DurableCoordinatorCommandAuthority")._for_testing(
        tmp_path / "coordinator-state"
    )

    class UnavailableGitHub:
        @staticmethod
        def execute(request):
            del request
            raise OSError("service unavailable")

    request = _effects("PurposeBoundEffectRequest").for_publication(terminal)
    first = (
        _effects("ProtectedBuilderEffectExecutor")
        ._for_testing(store=store, authority=authority, github=UnavailableGitHub())
        .execute(request)
    )
    assert first.status == "pending"
    assert store.effect_status(request.idempotency_key) == "pending"

    github = RecordingGitHub()
    recovered = (
        _effects("ProtectedBuilderEffectExecutor")
        ._for_testing(store=store, authority=authority, github=github)
        .execute(request)
    )

    assert recovered.status == "completed"
    assert len(github.requests) == 1
    assert github.requests[0].command_key == request.command_key
    assert github.requests[0].effect_key == request.effect_key


def test_publication_never_reaches_github_when_experimental_gateway_denies(
    tmp_path: Path,
) -> None:
    store, terminal = _prepared(tmp_path)
    github = RecordingGitHub()

    class DenyingAuthorizer:
        @staticmethod
        def authorize(terminal, packet) -> bool:
            return False

    executor = _effects("ProtectedBuilderEffectExecutor")._for_testing(
        store=store,
        github=github,
        authorizer=DenyingAuthorizer(),
    )

    result = executor.execute(_effects("PurposeBoundEffectRequest").for_publication(terminal))

    assert result.status == "frozen"
    assert result.reason == "builder_publication_not_eligible"
    assert github.requests == []


def test_publication_response_identity_mismatch_freezes_durably(tmp_path: Path) -> None:
    store, terminal = _prepared(tmp_path)
    github = RecordingGitHub(mismatch=True)
    executor = _effects("ProtectedBuilderEffectExecutor")._for_testing(store=store, github=github)
    request = _effects("PurposeBoundEffectRequest").for_publication(terminal)

    result = executor.execute(request)

    assert result.status == "frozen"
    assert result.reason == "builder_effect_response_identity_mismatch"
    reopened = importlib.import_module(
        "carl_bench.product_builder_runtime"
    ).ProtectedBuilderStore._for_testing(tmp_path / "state")
    assert reopened.effect_status(request.idempotency_key) == "frozen"


def test_persisted_packet_mismatch_freezes_instead_of_escaping(tmp_path: Path) -> None:
    store, terminal = _prepared(tmp_path)
    packet_path = tmp_path / "state" / "packets" / f"{terminal.candidate_packet_digest}.json"
    packet_path.write_bytes(b"{}")
    request = _effects("PurposeBoundEffectRequest").for_publication(terminal)
    executor = _effects("ProtectedBuilderEffectExecutor")._for_testing(
        store=store, github=RecordingGitHub()
    )

    result = executor.execute(request)

    assert result.status == "frozen"
    assert result.reason == "builder_effect_persisted_identity_mismatch"
    assert store.effect_status(request.idempotency_key) == "frozen"


def test_downstream_validation_requires_completed_publication_and_exact_identity(
    tmp_path: Path,
) -> None:
    store, terminal = _prepared(tmp_path)
    github = RecordingGitHub()
    executor = _effects("ProtectedBuilderEffectExecutor")._for_testing(store=store, github=github)
    dispatch = _effects("PurposeBoundEffectRequest").for_validation(terminal)

    blocked = executor.execute(dispatch)
    assert blocked.status == "frozen"
    assert blocked.reason == "builder_publication_not_completed"

    store, terminal = _prepared(tmp_path / "second")
    github = RecordingGitHub()
    executor = _effects("ProtectedBuilderEffectExecutor")._for_testing(store=store, github=github)
    publication = _effects("PurposeBoundEffectRequest").for_publication(terminal)
    assert executor.execute(publication).status == "completed"
    dispatched = executor.execute(_effects("PurposeBoundEffectRequest").for_validation(terminal))

    assert dispatched.status == "completed"
    assert github.requests[-1].operation is GitHubEffectOperation.DISPATCH_WORKFLOW
    assert github.requests[-1].parameters == {
        "candidate_commit": terminal.candidate_commit,
        "experiment_digest": _dispatch().experiment_digest,
        "metric_pack_digest": _dispatch().metric_pack_digest,
        "parent_commit": PARENT,
        "policy_digest": _dispatch().policy_digest,
        "repository": _dispatch().repository,
        "task_set_digest": _dispatch().task_set_digest,
        "workflow_blob_digest": _dispatch().workflow_blob_digest,
        "workflow_file": _dispatch().workflow_file,
        "workflow_revision": _dispatch().workflow_revision,
    }
