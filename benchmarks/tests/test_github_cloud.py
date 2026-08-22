from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from inspect import getmembers, isfunction, signature

import pytest

from carl_bench import github_cloud
from carl_bench.cloud_execution import CloudRunRequest
from carl_bench.cloud_state import CloudCommand, CommandClaim, CommandState
from carl_bench.github_cloud import (
    ExperimentalBranchRequest,
    GitHubCloudError,
    GitHubCloudGateway,
    GitHubHttpRequest,
    GitHubHttpResponse,
    GitHubRetryDecision,
    GitHubTransportError,
    PullRequestAutoMergeRequest,
    PullRequestCreateRequest,
    PullRequestReadyRequest,
    PullRequestUpdateRequest,
    RequiredChecksRequest,
    RevertBranchRequest,
    RevertPullRequestRequest,
    experimental_branch_binding,
    pull_request_auto_merge_binding,
    pull_request_create_binding,
    pull_request_ready_binding,
    pull_request_update_binding,
    required_checks_binding,
    revert_branch_binding,
    revert_pull_request_binding,
    workflow_dispatch_binding,
)
from carl_bench.github_promotion import APPROVED_REQUIRED_CHECKS

_NOW = "2026-08-21T12:00:00Z"
_WORKFLOW_REVISION = "1" * 40
_CANDIDATE_COMMIT = "2" * 40


@dataclass
class FakeTransport:
    outcomes: deque[GitHubHttpResponse | GitHubTransportError]
    requests: list[GitHubHttpRequest] = field(default_factory=list)

    def send(self, request: GitHubHttpRequest) -> GitHubHttpResponse:
        self.requests.append(request)
        outcome = self.outcomes.popleft()
        if isinstance(outcome, GitHubTransportError):
            raise outcome
        return outcome


def _clock() -> datetime:
    return datetime(2026, 8, 21, 12, tzinfo=UTC)


def _request() -> CloudRunRequest:
    return CloudRunRequest.create(
        repository="StephenBickel/carl-agent",
        workflow_file="autonomous-improvement.yml",
        experiment_digest="a" * 64,
        parent_commit="0" * 40,
        candidate_commit=_CANDIDATE_COMMIT,
        task_set_digest="b" * 64,
        metric_pack_digest="c" * 64,
        policy_digest="d" * 64,
        workflow_revision=_WORKFLOW_REVISION,
        workflow_blob_digest="e" * 64,
    )


def _claimed_dispatch_command(request: CloudRunRequest) -> CommandState:
    binding = workflow_dispatch_binding(request, attempt=1)
    command = CloudCommand.create(
        command_key=binding.command_key,
        authority="coordinator",
        operation="dispatch",
        request_digest=binding.request_digest,
        occurred_at=_NOW,
        expected_revision=4,
        attempt=1,
        max_attempts=3,
    )
    claim = CommandClaim(
        command_key=command.command_key,
        claim_id="github-dispatch-claim-01",
        authority="coordinator",
        expected_revision=4,
        claimed_at=_NOW,
        expires_at="2026-08-21T12:05:00Z",
    )
    return CommandState(
        command=command,
        revision=5,
        status="claimed",
        claim=claim,
        transition=None,
        result_digest=None,
        failure_code=None,
    )


def _claimed_effect_command(
    binding: object,
    *,
    authority: str,
    operation: str,
    claim_id: str,
) -> CommandState:
    command = CloudCommand.create(
        command_key=binding.command_key,
        authority=authority,
        operation=operation,
        request_digest=binding.request_digest,
        occurred_at=_NOW,
        expected_revision=8,
        attempt=1,
        max_attempts=3,
    )
    claim = CommandClaim(
        command_key=command.command_key,
        claim_id=claim_id,
        authority=authority,
        expected_revision=8,
        claimed_at=_NOW,
        expires_at="2026-08-21T12:05:00Z",
    )
    return CommandState(
        command=command,
        revision=9,
        status="claimed",
        claim=claim,
        transition=None,
        result_digest=None,
        failure_code=None,
    )


def _json_response(status: int, body: bytes) -> GitHubHttpResponse:
    return GitHubHttpResponse(
        status=status,
        headers=(("content-type", "application/json; charset=utf-8"),),
        body=body,
    )


def _empty_runs() -> GitHubHttpResponse:
    return _json_response(200, b'{"total_count":0,"workflow_runs":[]}')


def _accepted_run(
    request: CloudRunRequest,
    *,
    head_sha: str = _WORKFLOW_REVISION,
    created_at: str = "2026-08-21T12:00:02Z",
) -> GitHubHttpResponse:
    attempt_key = request.attempt_key(1)
    body = (
        '{"total_count":1,"workflow_runs":[{'
        '"conclusion":null,'
        f'"created_at":"{created_at}",'
        f'"display_title":"{attempt_key}",'
        '"event":"workflow_dispatch",'
        f'"head_branch":"{_WORKFLOW_REVISION}",'
        f'"head_sha":"{head_sha}",'
        '"id":901,'
        '"path":".github/workflows/autonomous-improvement.yml",'
        '"status":"queued"'
        "}]}".encode()
    )
    return _json_response(200, body)


def test_gateway_has_no_caller_configurable_public_constructor() -> None:
    with pytest.raises(GitHubCloudError, match="github_protected_configuration_required"):
        GitHubCloudGateway(
            repository="attacker/repository",
            token="attacker-token",
            transport=FakeTransport(deque()),
            clock=_clock,
        )


def test_dispatch_requires_a_claimed_persisted_exact_command_before_network() -> None:
    request = _request()
    transport = FakeTransport(deque([_empty_runs()]))
    gateway = GitHubCloudGateway._for_testing(
        repository=request.repository,
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )
    command = _claimed_dispatch_command(request)
    pending = CommandState(
        command=command.command,
        revision=command.command.expected_revision,
        status="pending",
        claim=None,
        transition=None,
        result_digest=None,
        failure_code=None,
    )

    with pytest.raises(GitHubCloudError, match="github_command_not_claimed"):
        gateway.dispatch_workflow(pending, request)

    assert transport.requests == []


def test_exact_revision_dispatch_uses_bound_request_and_attempt_keys() -> None:
    request = _request()
    transport = FakeTransport(
        deque(
            [
                _empty_runs(),
                GitHubHttpResponse(status=204, headers=(), body=b""),
            ]
        )
    )
    gateway = GitHubCloudGateway._for_testing(
        repository=request.repository,
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.dispatch_workflow(_claimed_dispatch_command(request), request)

    assert result.status == "dispatched"
    assert result.request_key == request.dispatch_key
    assert result.attempt_key == request.attempt_key(1)
    assert result.command_occurred_at == _NOW
    assert [item.method for item in transport.requests] == ["GET", "POST"]
    dispatch = transport.requests[1]
    assert dispatch.origin == "https://api.github.com"
    assert dispatch.path == (
        "/repos/StephenBickel/carl-agent/actions/workflows/autonomous-improvement.yml/dispatches"
    )
    assert dispatch.query == ()
    assert dispatch.json_body == {
        "inputs": {
            "attempt_key": request.attempt_key(1),
            "candidate_commit": _CANDIDATE_COMMIT,
            "experiment_digest": "a" * 64,
            "metric_pack_digest": "c" * 64,
            "parent_commit": "0" * 40,
            "policy_digest": "d" * 64,
            "request_digest": request.request_digest,
            "task_set_digest": "b" * 64,
            "workflow_blob_digest": "e" * 64,
        },
        "ref": _WORKFLOW_REVISION,
    }
    assert dispatch.follow_redirects is False


def test_lost_dispatch_response_reconciles_the_exact_accepted_run_without_duplicate() -> None:
    request = _request()
    transport = FakeTransport(
        deque(
            [
                _empty_runs(),
                GitHubTransportError("github_response_ambiguous", ambiguous=True),
                _accepted_run(request),
            ]
        )
    )
    gateway = GitHubCloudGateway._for_testing(
        repository=request.repository,
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.dispatch_workflow(_claimed_dispatch_command(request), request)

    assert result.status == "reconciled"
    assert result.run_id == 901
    assert result.head_sha == _WORKFLOW_REVISION
    assert result.request_key == request.dispatch_key
    assert result.attempt_key == request.attempt_key(1)
    assert [item.method for item in transport.requests] == ["GET", "POST", "GET"]
    assert sum(item.method == "POST" for item in transport.requests) == 1


def test_run_discovery_follows_only_bounded_pinned_origin_pagination() -> None:
    request = _request()
    first_page = GitHubHttpResponse(
        status=200,
        headers=(
            ("content-type", "application/json"),
            (
                "link",
                "<https://api.github.com/repos/StephenBickel/carl-agent/actions/workflows/"
                "autonomous-improvement.yml/runs?branch=1111111111111111111111111111111111111111"
                '&event=workflow_dispatch&page=2&per_page=100>; rel="next", '
                "<https://api.github.com/repos/StephenBickel/carl-agent/actions/workflows/"
                'autonomous-improvement.yml/runs?page=2>; rel="last"',
            ),
        ),
        body=b'{"total_count":1,"workflow_runs":[]}',
    )
    transport = FakeTransport(deque([first_page, _accepted_run(request)]))
    gateway = GitHubCloudGateway._for_testing(
        repository=request.repository,
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.dispatch_workflow(_claimed_dispatch_command(request), request)

    assert result.status == "reconciled"
    assert result.run_id == 901
    assert [item.method for item in transport.requests] == ["GET", "GET"]
    assert transport.requests[1].query == (
        ("branch", _WORKFLOW_REVISION),
        ("event", "workflow_dispatch"),
        ("page", "2"),
        ("per_page", "100"),
    )


def test_run_discovery_rejects_cross_origin_pagination_without_following_it() -> None:
    request = _request()
    response = GitHubHttpResponse(
        status=200,
        headers=(
            ("content-type", "application/json"),
            ("link", '<https://attacker.invalid/runs?page=2>; rel="next"'),
        ),
        body=b'{"total_count":1,"workflow_runs":[]}',
    )
    transport = FakeTransport(deque([response]))
    gateway = GitHubCloudGateway._for_testing(
        repository=request.repository,
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    with pytest.raises(GitHubCloudError, match="github_pagination_link_invalid"):
        gateway.dispatch_workflow(_claimed_dispatch_command(request), request)

    assert len(transport.requests) == 1


def test_run_discovery_stops_at_the_page_budget_before_an_effect() -> None:
    request = _request()
    responses = deque()
    for page in range(1, 6):
        responses.append(
            GitHubHttpResponse(
                status=200,
                headers=(
                    ("content-type", "application/json"),
                    (
                        "link",
                        "<https://api.github.com/repos/StephenBickel/carl-agent/actions/"
                        f"workflows/autonomous-improvement.yml/runs?page={page + 1}>"
                        '; rel="next"',
                    ),
                ),
                body=b'{"total_count":6,"workflow_runs":[]}',
            )
        )
    transport = FakeTransport(responses)
    gateway = GitHubCloudGateway._for_testing(
        repository=request.repository,
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    with pytest.raises(GitHubCloudError, match="github_pagination_limit_exceeded"):
        gateway.dispatch_workflow(_claimed_dispatch_command(request), request)

    assert len(transport.requests) == 5
    assert all(item.method == "GET" for item in transport.requests)


def test_rate_limit_becomes_a_durable_retry_decision_without_sleeping() -> None:
    request = _request()
    response = GitHubHttpResponse(
        status=403,
        headers=(
            ("content-type", "application/json"),
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", "1787313720"),
        ),
        body=b'{"message":"API rate limit exceeded"}',
    )
    transport = FakeTransport(deque([response]))
    gateway = GitHubCloudGateway._for_testing(
        repository=request.repository,
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    decision = gateway.dispatch_workflow(_claimed_dispatch_command(request), request)

    assert isinstance(decision, GitHubRetryDecision)
    assert decision.status == "retry_scheduled"
    assert decision.reason == "github_rate_limited"
    assert decision.retry_not_before == "2026-08-21T12:02:00Z"
    assert decision.command_occurred_at == _NOW
    assert decision.attempt == 1
    assert decision.max_attempts == 3
    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(_accepted_run(_request(), head_sha="9" * 40), id="wrong-head"),
        pytest.param(
            _accepted_run(_request(), created_at="2026-08-21T11:59:59Z"),
            id="predates-command",
        ),
    ],
)
def test_attempt_key_collision_with_wrong_run_identity_blocks_duplicate_dispatch(
    response: GitHubHttpResponse,
) -> None:
    request = _request()
    transport = FakeTransport(deque([response]))
    gateway = GitHubCloudGateway._for_testing(
        repository=request.repository,
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    with pytest.raises(GitHubCloudError, match="github_dispatch_identity_conflict"):
        gateway.dispatch_workflow(_claimed_dispatch_command(request), request)

    assert [item.method for item in transport.requests] == ["GET"]


def _experimental_request() -> ExperimentalBranchRequest:
    return ExperimentalBranchRequest.create(
        experiment_id="exp-001",
        candidate_commit=_CANDIDATE_COMMIT,
    )


def _missing_ref() -> GitHubHttpResponse:
    return _json_response(404, b'{"message":"Not Found"}')


def _exact_ref() -> GitHubHttpResponse:
    return _json_response(
        200,
        (
            '{"object":{"sha":"'
            + _CANDIDATE_COMMIT
            + '","type":"commit"},"ref":"refs/heads/experimental/exp-001"}'
        ).encode(),
    )


def test_experimental_branch_create_is_immutable_and_command_bound() -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    created = GitHubHttpResponse(status=201, headers=_exact_ref().headers, body=_exact_ref().body)
    transport = FakeTransport(deque([_missing_ref(), created]))
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )
    command = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="github-experimental-claim-01",
    )

    result = gateway.create_or_reconcile_experimental_branch(command, request)

    assert result.status == "created"
    assert result.ref == "refs/heads/experimental/exp-001"
    assert result.commit_sha == _CANDIDATE_COMMIT
    assert result.effect_key == command.command.effect_key
    assert [item.method for item in transport.requests] == ["GET", "POST"]
    assert transport.requests[1].path == "/repos/StephenBickel/carl-agent/git/refs"
    assert transport.requests[1].json_body == {
        "ref": "refs/heads/experimental/exp-001",
        "sha": _CANDIDATE_COMMIT,
    }


def test_existing_exact_experimental_branch_reconciles_without_mutation() -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(deque([_exact_ref()]))
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.create_or_reconcile_experimental_branch(
        _claimed_effect_command(
            binding,
            authority="builder",
            operation="publish_experimental",
            claim_id="github-experimental-claim-01",
        ),
        request,
    )

    assert result.status == "reconciled"
    assert [item.method for item in transport.requests] == ["GET"]


def test_conflicting_experimental_branch_fails_closed_before_mutation() -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    conflict = _json_response(
        200,
        b'{"object":{"sha":"3333333333333333333333333333333333333333",'
        b'"type":"commit"},"ref":"refs/heads/experimental/exp-001"}',
    )
    transport = FakeTransport(deque([conflict]))
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    with pytest.raises(GitHubCloudError, match="github_immutable_ref_conflict"):
        gateway.create_or_reconcile_experimental_branch(
            _claimed_effect_command(
                binding,
                authority="builder",
                operation="publish_experimental",
                claim_id="github-experimental-claim-01",
            ),
            request,
        )

    assert [item.method for item in transport.requests] == ["GET"]


def test_lost_experimental_create_response_reconciles_without_duplicate() -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _missing_ref(),
                GitHubTransportError("github_response_ambiguous", ambiguous=True),
                _exact_ref(),
            ]
        )
    )
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.create_or_reconcile_experimental_branch(
        _claimed_effect_command(
            binding,
            authority="builder",
            operation="publish_experimental",
            claim_id="github-experimental-claim-01",
        ),
        request,
    )

    assert result.status == "reconciled"
    assert [item.method for item in transport.requests] == ["GET", "POST", "GET"]
    assert sum(item.method == "POST" for item in transport.requests) == 1


def _pull_request_create() -> PullRequestCreateRequest:
    return PullRequestCreateRequest.create(
        promotion_id="promotion-exp-001-1",
        head_branch="experimental/exp-001",
        head_sha=_CANDIDATE_COMMIT,
        title="Autonomous improvement exp-001",
        body="Promotion evidence: receipt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )


def _pull_request_body(
    *,
    draft: bool = True,
    auto_merge: bool = False,
    title: str = "Autonomous improvement exp-001",
    body: str = "Promotion evidence: receipt-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    head_branch: str = "experimental/exp-001",
    head_sha: str = _CANDIDATE_COMMIT,
) -> bytes:
    auto_merge_json = '{"merge_method":"squash"}' if auto_merge else "null"
    return (
        f'{{"auto_merge":{auto_merge_json},"base":{{"ref":"main"}},'
        f'"body":"{body}",'
        f'"draft":{str(draft).lower()},'
        f'"head":{{"ref":"{head_branch}","sha":"{head_sha}"}},'
        '"html_url":"https://github.com/StephenBickel/carl-agent/pull/81",'
        f'"number":81,"state":"open","title":"{title}"}}'
    ).encode()


def _pull_request_list(*, present: bool) -> GitHubHttpResponse:
    body = b"[" + _pull_request_body() + b"]" if present else b"[]"
    return _json_response(200, body)


def test_pull_request_create_uses_exact_main_and_experimental_identity() -> None:
    request = _pull_request_create()
    binding = pull_request_create_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _pull_request_list(present=False),
                _json_response(201, _pull_request_body()),
            ]
        )
    )
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )
    command = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-create-claim-01",
    )

    result = gateway.create_or_reconcile_pull_request(command, request)

    assert result.status == "created"
    assert result.number == 81
    assert result.base_branch == "main"
    assert result.head_branch == "experimental/exp-001"
    assert result.head_sha == _CANDIDATE_COMMIT
    assert [item.method for item in transport.requests] == ["GET", "POST"]
    assert transport.requests[1].path == "/repos/StephenBickel/carl-agent/pulls"
    assert transport.requests[1].json_body == {
        "base": "main",
        "body": request.body,
        "draft": True,
        "head": "experimental/exp-001",
        "title": request.title,
    }


def test_existing_exact_pull_request_reconciles_without_create() -> None:
    request = _pull_request_create()
    binding = pull_request_create_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(deque([_pull_request_list(present=True)]))
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.create_or_reconcile_pull_request(
        _claimed_effect_command(
            binding,
            authority="promoter",
            operation="github_effect",
            claim_id="github-pr-create-claim-01",
        ),
        request,
    )

    assert result.status == "reconciled"
    assert result.number == 81
    assert [item.method for item in transport.requests] == ["GET"]


def test_lost_pull_request_create_response_reconciles_without_duplicate() -> None:
    request = _pull_request_create()
    binding = pull_request_create_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _pull_request_list(present=False),
                GitHubTransportError("github_response_ambiguous", ambiguous=True),
                _pull_request_list(present=True),
            ]
        )
    )
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.create_or_reconcile_pull_request(
        _claimed_effect_command(
            binding,
            authority="promoter",
            operation="github_effect",
            claim_id="github-pr-create-claim-01",
        ),
        request,
    )

    assert result.status == "reconciled"
    assert result.number == 81
    assert [item.method for item in transport.requests] == ["GET", "POST", "GET"]
    assert sum(item.method == "POST" for item in transport.requests) == 1


def _pull_update() -> PullRequestUpdateRequest:
    return PullRequestUpdateRequest.create(
        promotion_id="promotion-exp-001-1",
        number=81,
        head_branch="experimental/exp-001",
        head_sha=_CANDIDATE_COMMIT,
        title="Autonomous improvement exp-001 (reviewed)",
        body="Promotion evidence: receipt-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )


def test_pull_request_update_can_change_only_title_and_body() -> None:
    request = _pull_update()
    binding = pull_request_update_binding("StephenBickel/carl-agent", request)
    updated_body = _pull_request_body(title=request.title, body=request.body)
    transport = FakeTransport(
        deque(
            [
                _json_response(200, _pull_request_body()),
                _json_response(200, updated_body),
            ]
        )
    )
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.update_pull_request(
        _claimed_effect_command(
            binding,
            authority="promoter",
            operation="github_effect",
            claim_id="github-pr-update-claim-01",
        ),
        request,
    )

    assert result.status == "updated"
    assert result.title == request.title
    assert result.body == request.body
    assert [item.method for item in transport.requests] == ["GET", "PATCH"]
    assert transport.requests[1].path == "/repos/StephenBickel/carl-agent/pulls/81"
    assert transport.requests[1].json_body == {"body": request.body, "title": request.title}


def test_lost_pull_request_update_reconciles_without_duplicate_patch() -> None:
    request = _pull_update()
    binding = pull_request_update_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _json_response(200, _pull_request_body()),
                GitHubTransportError("github_response_ambiguous", ambiguous=True),
                _json_response(200, _pull_request_body(title=request.title, body=request.body)),
            ]
        )
    )
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.update_pull_request(
        _claimed_effect_command(
            binding,
            authority="promoter",
            operation="github_effect",
            claim_id="github-pr-update-claim-01",
        ),
        request,
    )

    assert result.status == "reconciled"
    assert [item.method for item in transport.requests] == ["GET", "PATCH", "GET"]
    assert sum(item.method == "PATCH" for item in transport.requests) == 1


def _ready_request() -> PullRequestReadyRequest:
    return PullRequestReadyRequest.create(
        promotion_id="promotion-exp-001-1",
        number=81,
        head_branch="experimental/exp-001",
        head_sha=_CANDIDATE_COMMIT,
    )


def test_mark_ready_reconciles_before_and_after_one_transition() -> None:
    request = _ready_request()
    binding = pull_request_ready_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _json_response(200, _pull_request_body(draft=True)),
                GitHubTransportError("github_response_ambiguous", ambiguous=True),
                _json_response(200, _pull_request_body(draft=False)),
            ]
        )
    )
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.mark_pull_request_ready(
        _claimed_effect_command(
            binding,
            authority="promoter",
            operation="github_effect",
            claim_id="github-pr-ready-claim-01",
        ),
        request,
    )

    assert result.status == "reconciled"
    assert result.draft is False
    assert transport.requests[1].path == (
        "/repos/StephenBickel/carl-agent/pulls/81/ready_for_review"
    )
    assert [item.method for item in transport.requests] == ["GET", "POST", "GET"]
    assert sum(item.method == "POST" for item in transport.requests) == 1


def _auto_merge_request() -> PullRequestAutoMergeRequest:
    return PullRequestAutoMergeRequest.create(
        promotion_id="promotion-exp-001-1",
        number=81,
        head_branch="experimental/exp-001",
        head_sha=_CANDIDATE_COMMIT,
    )


def test_auto_merge_enablement_is_squash_only_and_reconciles_lost_response() -> None:
    request = _auto_merge_request()
    binding = pull_request_auto_merge_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _json_response(200, _pull_request_body(draft=False)),
                GitHubTransportError("github_response_ambiguous", ambiguous=True),
                _json_response(200, _pull_request_body(draft=False, auto_merge=True)),
            ]
        )
    )
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.enable_pull_request_auto_merge(
        _claimed_effect_command(
            binding,
            authority="promoter",
            operation="github_effect",
            claim_id="github-pr-auto-merge-claim-01",
        ),
        request,
    )

    assert result.status == "reconciled"
    assert result.auto_merge_enabled is True
    assert transport.requests[1].path == ("/repos/StephenBickel/carl-agent/pulls/81/auto-merge")
    assert transport.requests[1].json_body == {"merge_method": "squash"}
    assert [item.method for item in transport.requests] == ["GET", "PUT", "GET"]
    assert sum(item.method == "PUT" for item in transport.requests) == 1


def _checks_response(*, head_sha: str = _CANDIDATE_COMMIT) -> GitHubHttpResponse:
    runs = ",".join(
        (
            '{"app":{"id":15368},"conclusion":"success",'
            f'"head_sha":"{head_sha}","name":"{name}","status":"completed"}}'
        )
        for name in APPROVED_REQUIRED_CHECKS
    )
    return _json_response(
        200,
        f'{{"check_runs":[{runs}],"total_count":{len(APPROVED_REQUIRED_CHECKS)}}}'.encode(),
    )


def test_required_check_observation_is_bound_to_exact_head_sha() -> None:
    request = RequiredChecksRequest.create(head_sha=_CANDIDATE_COMMIT)
    binding = required_checks_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(deque([_checks_response()]))
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.observe_required_checks(
        _claimed_effect_command(
            binding,
            authority="observer",
            operation="observe",
            claim_id="github-check-observe-claim-01",
        ),
        request,
    )

    assert result.head_sha == _CANDIDATE_COMMIT
    assert tuple(check.name for check in result.checks) == APPROVED_REQUIRED_CHECKS
    assert all(check.status == "completed" for check in result.checks)
    assert all(check.conclusion == "success" for check in result.checks)
    assert result.complete is True
    assert transport.requests[0].path == (
        f"/repos/StephenBickel/carl-agent/commits/{_CANDIDATE_COMMIT}/check-runs"
    )


def test_required_check_response_with_a_different_head_fails_closed() -> None:
    request = RequiredChecksRequest.create(head_sha=_CANDIDATE_COMMIT)
    binding = required_checks_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(deque([_checks_response(head_sha="3" * 40)]))
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    with pytest.raises(GitHubCloudError, match="github_check_head_mismatch"):
        gateway.observe_required_checks(
            _claimed_effect_command(
                binding,
                authority="observer",
                operation="observe",
                claim_id="github-check-observe-claim-01",
            ),
            request,
        )


def test_required_check_command_mismatch_rejects_before_transport() -> None:
    request = RequiredChecksRequest.create(head_sha=_CANDIDATE_COMMIT)
    other = RequiredChecksRequest.create(head_sha="3" * 40)
    binding = required_checks_binding("StephenBickel/carl-agent", other)
    transport = FakeTransport(deque())
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    with pytest.raises(GitHubCloudError, match="github_command_binding_mismatch"):
        gateway.observe_required_checks(
            _claimed_effect_command(
                binding,
                authority="observer",
                operation="observe",
                claim_id="github-check-observe-claim-01",
            ),
            request,
        )

    assert transport.requests == []


def _revert_branch_request() -> RevertBranchRequest:
    return RevertBranchRequest.create(
        promotion_id="promotion-exp-001-1",
        promotion_merge_commit="4" * 40,
        revert_candidate_commit="5" * 40,
        expected_restored_tree="6" * 40,
    )


def _revert_ref() -> GitHubHttpResponse:
    return _json_response(
        200,
        b'{"object":{"sha":"5555555555555555555555555555555555555555",'
        b'"type":"commit"},"ref":"refs/heads/revert/promotion-exp-001-1"}',
    )


def test_exact_revert_branch_reconciles_a_lost_create_without_duplicate() -> None:
    request = _revert_branch_request()
    binding = revert_branch_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _missing_ref(),
                GitHubTransportError("github_response_ambiguous", ambiguous=True),
                _revert_ref(),
            ]
        )
    )
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.create_or_reconcile_revert_branch(
        _claimed_effect_command(
            binding,
            authority="promoter",
            operation="github_effect",
            claim_id="github-revert-branch-claim-01",
        ),
        request,
    )

    assert result.status == "reconciled"
    assert result.ref == "refs/heads/revert/promotion-exp-001-1"
    assert result.commit_sha == "5" * 40
    assert [item.method for item in transport.requests] == ["GET", "POST", "GET"]
    assert sum(item.method == "POST" for item in transport.requests) == 1


def _revert_pull_request() -> RevertPullRequestRequest:
    return RevertPullRequestRequest.create(
        promotion_id="promotion-exp-001-1",
        promotion_merge_commit="4" * 40,
        revert_candidate_commit="5" * 40,
        expected_restored_tree="6" * 40,
        title="Revert promotion promotion-exp-001-1",
        body="Hard-soak rollback receipt: receipt-cccccccccccccccccccccccccccccccc",
    )


def _revert_pull_body() -> bytes:
    request = _revert_pull_request()
    return _pull_request_body(
        draft=False,
        title=request.title,
        body=request.body,
        head_branch="revert/promotion-exp-001-1",
        head_sha="5" * 40,
    )


def test_exact_revert_pull_request_is_main_bound_and_reconciles_lost_create() -> None:
    request = _revert_pull_request()
    binding = revert_pull_request_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _pull_request_list(present=False),
                GitHubTransportError("github_response_ambiguous", ambiguous=True),
                _json_response(200, b"[" + _revert_pull_body() + b"]"),
            ]
        )
    )
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    result = gateway.create_or_reconcile_revert_pull_request(
        _claimed_effect_command(
            binding,
            authority="promoter",
            operation="github_effect",
            claim_id="github-revert-pr-claim-01",
        ),
        request,
    )

    assert result.status == "reconciled"
    assert result.base_branch == "main"
    assert result.head_branch == "revert/promotion-exp-001-1"
    assert result.head_sha == "5" * 40
    assert [item.method for item in transport.requests] == ["GET", "POST", "GET"]
    assert sum(item.method == "POST" for item in transport.requests) == 1


def test_public_gateway_surface_has_no_generic_or_prohibited_github_effects() -> None:
    public_methods = {
        name
        for name, value in getmembers(GitHubCloudGateway, predicate=isfunction)
        if not name.startswith("_")
    }
    prohibited = {
        "request",
        "graphql",
        "push_main",
        "update_main",
        "force_push",
        "delete_branch",
        "create_release",
        "create_deployment",
        "deploy",
    }

    assert public_methods.isdisjoint(prohibited)
    for method_name in public_methods:
        parameters = set(signature(getattr(GitHubCloudGateway, method_name)).parameters)
        assert parameters.isdisjoint({"url", "path", "graphql", "query"})


def test_authorization_header_is_not_exposed_by_request_repr() -> None:
    request = _request()
    transport = FakeTransport(
        deque([_empty_runs(), GitHubHttpResponse(status=204, headers=(), body=b"")])
    )
    gateway = GitHubCloudGateway._for_testing(
        repository=request.repository,
        token="github_pat_must_not_leak",
        transport=transport,
        clock=_clock,
    )

    gateway.dispatch_workflow(_claimed_dispatch_command(request), request)

    assert "github_pat_must_not_leak" not in repr(transport.requests[0])
    assert "authorization" not in repr(transport.requests[0]).lower()


@pytest.mark.parametrize(
    ("response", "code"),
    [
        pytest.param(
            GitHubHttpResponse(
                status=200,
                headers=(("content-type", "application/json"),),
                body=b'{"total_count":0,"total_count":1,"workflow_runs":[]}',
            ),
            "github_response_duplicate_key",
            id="duplicate-json-key",
        ),
        pytest.param(
            GitHubHttpResponse(
                status=200,
                headers=(("content-type", "text/html"),),
                body=b"credential-shaped-response-body",
            ),
            "github_response_content_type_invalid",
            id="wrong-content-type",
        ),
        pytest.param(
            GitHubHttpResponse(
                status=200,
                headers=(("content-type", "application/json"),),
                body=b"x" * 262_145,
            ),
            "github_response_too_large",
            id="oversized",
        ),
        pytest.param(
            GitHubHttpResponse(
                status=302,
                headers=(("location", "https://attacker.invalid/steal"),),
                body=b"",
            ),
            "github_redirect_rejected",
            id="redirect",
        ),
    ],
)
def test_invalid_responses_fail_closed_without_effect_or_sensitive_error_text(
    response: GitHubHttpResponse, code: str
) -> None:
    request = _request()
    transport = FakeTransport(deque([response]))
    gateway = GitHubCloudGateway._for_testing(
        repository=request.repository,
        token="github_pat_must_not_leak",
        transport=transport,
        clock=_clock,
    )

    with pytest.raises(GitHubCloudError, match=code) as raised:
        gateway.dispatch_workflow(_claimed_dispatch_command(request), request)

    assert str(raised.value) == code
    assert "github_pat_must_not_leak" not in str(raised.value)
    assert "credential-shaped-response-body" not in str(raised.value)
    assert [item.method for item in transport.requests] == ["GET"]


def test_future_command_timestamp_rejects_before_transport() -> None:
    request = _request()
    binding = workflow_dispatch_binding(request, attempt=1)
    command = CloudCommand.create(
        command_key=binding.command_key,
        authority="coordinator",
        operation="dispatch",
        request_digest=binding.request_digest,
        occurred_at="2026-08-21T12:00:01Z",
        expected_revision=4,
        attempt=1,
        max_attempts=3,
    )
    state = CommandState(
        command=command,
        revision=5,
        status="claimed",
        claim=CommandClaim(
            command_key=command.command_key,
            claim_id="github-dispatch-claim-01",
            authority="coordinator",
            expected_revision=4,
            claimed_at=_NOW,
            expires_at="2026-08-21T12:05:00Z",
        ),
        transition=None,
        result_digest=None,
        failure_code=None,
    )
    transport = FakeTransport(deque())
    gateway = GitHubCloudGateway._for_testing(
        repository=request.repository,
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    with pytest.raises(GitHubCloudError, match="github_command_timestamp_invalid"):
        gateway.dispatch_workflow(state, request)

    assert transport.requests == []


def test_production_gateway_loads_only_fixed_protected_policy_and_token_source(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_dir = tmp_path / "protected"
    policy_dir.mkdir(mode=0o700)
    policy_path = policy_dir / "github-cloud-policy.json"
    policy_path.write_bytes(
        b'{"api_origin":"https://api.github.com",'
        b'"repository":"StephenBickel/carl-agent","schema_version":1}'
    )
    policy_path.chmod(0o600)
    monkeypatch.setattr(github_cloud, "_PROTECTED_CONFIG_DIR", policy_dir)
    monkeypatch.setenv("CARL_GITHUB_APP_INSTALLATION_TOKEN", "github_pat_protected_test")
    request = _request()
    transport = FakeTransport(
        deque([_empty_runs(), GitHubHttpResponse(status=204, headers=(), body=b"")])
    )

    gateway = GitHubCloudGateway.from_protected_environment(
        transport=transport,
        clock=_clock,
    )
    result = gateway.dispatch_workflow(_claimed_dispatch_command(request), request)

    assert result.status == "dispatched"
    parameters = set(signature(GitHubCloudGateway.from_protected_environment).parameters)
    assert parameters.isdisjoint({"repository", "token", "path", "origin"})


def test_protected_policy_symlink_is_rejected(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_dir = tmp_path / "protected"
    policy_dir.mkdir(mode=0o700)
    target = tmp_path / "candidate-policy.json"
    target.write_bytes(
        b'{"api_origin":"https://api.github.com",'
        b'"repository":"attacker/repository","schema_version":1}'
    )
    (policy_dir / "github-cloud-policy.json").symlink_to(target)
    monkeypatch.setattr(github_cloud, "_PROTECTED_CONFIG_DIR", policy_dir)
    monkeypatch.setenv("CARL_GITHUB_APP_INSTALLATION_TOKEN", "github_pat_protected_test")

    with pytest.raises(GitHubCloudError, match="github_protected_configuration_invalid"):
        GitHubCloudGateway.from_protected_environment(
            transport=FakeTransport(deque()),
            clock=_clock,
        )


@pytest.mark.parametrize(
    ("method", "path", "query", "body"),
    [
        pytest.param(
            "POST",
            "/repos/StephenBickel/carl-agent/releases",
            (),
            {},
            id="release",
        ),
        pytest.param("POST", "/graphql", (), {}, id="graphql"),
        pytest.param(
            "POST",
            "/repos/StephenBickel/carl-agent/git/refs",
            (),
            {"ref": "refs/heads/main", "sha": _CANDIDATE_COMMIT},
            id="direct-main-ref",
        ),
        pytest.param(
            "GET",
            "/repos/StephenBickel/carl-agent/pulls/81",
            (("arbitrary", "value"),),
            None,
            id="arbitrary-query",
        ),
    ],
)
def test_internal_http_boundary_rejects_non_allowlisted_effects_before_transport(
    method: str,
    path: str,
    query: tuple[tuple[str, str], ...],
    body: dict[str, object] | None,
) -> None:
    transport = FakeTransport(deque())
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    with pytest.raises(GitHubCloudError, match="github_endpoint_not_allowed"):
        gateway._request(method, path, query=query, body=body)

    assert transport.requests == []
