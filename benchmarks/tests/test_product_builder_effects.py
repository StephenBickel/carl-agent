from __future__ import annotations

import importlib
from dataclasses import replace
from pathlib import Path

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
    envelope = importlib.import_module(
        "carl_bench.product_builder_evidence"
    ).SignedAttemptReceipt.sign(_receipt(), b"k" * 32)
    candidate = replace(_candidate(registration), changed_path_count=1)
    packet = importlib.import_module(
        "carl_bench.product_builder_evidence"
    ).ProtectedCandidatePacket(
        schema_version=1,
        registration_digest=registration.digest,
        parent_commit=PARENT,
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
        candidate_tree="f" * 40,
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
                    "head_sha": request.parameters["workflow_revision"],
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
