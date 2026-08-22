from __future__ import annotations

import json
import subprocess
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from inspect import getmembers, isfunction, signature
from pathlib import Path

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
_WORKFLOW_REF = "main"
_DISPATCH_ACTOR = "carl-autonomy[bot]"
_REPOSITORY_ROOT = Path(__file__).parents[2]
_PULL_REQUEST_NODE_ID = "PR_kwDOAutonomy81"
_MARK_READY_MUTATION = """mutation MarkPullRequestReadyForReview($pullRequestId: ID!) {
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
_ENABLE_AUTO_MERGE_MUTATION = """mutation EnablePullRequestAutoMerge($pullRequestId: ID!) {
  enablePullRequestAutoMerge(input: {pullRequestId: $pullRequestId, mergeMethod: SQUASH}) {
    pullRequest {
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


@dataclass
class FakeDurableEffectController:
    """Shared fake for the protected state-controller boundary, not process memory."""

    commands: dict[str, CommandState]
    attempts: dict[str, dict[str, object]] = field(default_factory=dict)

    def resolve_claimed_command(
        self, command_key: str, *, authority: str, observed_at: datetime
    ) -> CommandState:
        del observed_at
        try:
            state = self.commands[command_key]
        except KeyError as error:
            raise GitHubCloudError("github_command_not_found") from error
        if state.command.authority != authority:
            raise GitHubCloudError("github_command_binding_mismatch")
        return state

    def prepare_effect_attempt(self, attempt: object) -> bool:
        document = attempt.to_canonical_dict()
        effect_key = document["effect_key"]
        existing = self.attempts.get(effect_key)
        if existing is None:
            self.attempts[effect_key] = dict(document)
            return True
        claim_fields = {
            "claim_expires_at",
            "claim_expected_revision",
            "claim_id",
            "command_revision",
        }
        mutable_fields = {
            "attempt_state",
            "not_before",
            "observed_at",
            "result_digest",
            *claim_fields,
        }
        if {key: existing[key] for key in document if key not in mutable_fields} != {
            key: document[key] for key in document if key not in mutable_fields
        }:
            raise GitHubCloudError("github_effect_fence_conflict")
        if (
            existing["attempt_state"] == "retry_scheduled"
            and document["observed_at"] >= existing["not_before"]
        ):
            self.attempts[effect_key] = dict(document)
            return True
        if existing["attempt_state"] == "uncertain":
            existing.update({key: document[key] for key in claim_fields})
            existing["observed_at"] = document["observed_at"]
            return False
        if any(existing[key] != document[key] for key in claim_fields):
            raise GitHubCloudError("github_effect_fence_conflict")
        return False

    def mark_effect_uncertain(
        self,
        effect_key: str,
        *,
        authority: str,
        not_before: str,
        observed_at: str,
    ) -> None:
        assert self.attempts[effect_key]["authority"] == authority
        self.attempts[effect_key].update(
            attempt_state="uncertain",
            not_before=not_before,
            observed_at=observed_at,
        )

    def mark_effect_completed(
        self,
        effect_key: str,
        *,
        authority: str,
        result_digest: str,
        observed_at: str,
    ) -> None:
        assert self.attempts[effect_key]["authority"] == authority
        self.attempts[effect_key].update(
            attempt_state="completed",
            result_digest=result_digest,
            observed_at=observed_at,
        )

    def mark_effect_retry_scheduled(
        self,
        effect_key: str,
        *,
        authority: str,
        retry_not_before: str,
        observed_at: str,
    ) -> None:
        assert self.attempts[effect_key]["authority"] == authority
        self.attempts[effect_key].update(
            attempt_state="retry_scheduled",
            not_before=retry_not_before,
            observed_at=observed_at,
        )


def _clock() -> datetime:
    return datetime(2026, 8, 21, 12, tzinfo=UTC)


def _request(workflow_file: str = "autonomous-improvement.yml") -> CloudRunRequest:
    return CloudRunRequest.create(
        repository="StephenBickel/carl-agent",
        workflow_file=workflow_file,
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


def _gateway_with_state(
    state: CommandState,
    transport: FakeTransport,
    *,
    repository: str = "StephenBickel/carl-agent",
    token: str = "github_pat_test_only",
    clock=_clock,
) -> GitHubCloudGateway:
    return GitHubCloudGateway._for_testing(
        repository=repository,
        token=token,
        transport=transport,
        clock=clock,
        state_controller=FakeDurableEffectController(commands={state.command.command_key: state}),
    )


def _gateway_with_controller(
    controller: FakeDurableEffectController,
    transport: FakeTransport,
    *,
    repository: str = "StephenBickel/carl-agent",
    clock=_clock,
) -> GitHubCloudGateway:
    return GitHubCloudGateway._for_testing(
        repository=repository,
        token="github_pat_test_only",
        transport=transport,
        clock=clock,
        state_controller=controller,
    )


def _json_response(status: int, body: bytes) -> GitHubHttpResponse:
    return GitHubHttpResponse(
        status=status,
        headers=(("content-type", "application/json; charset=utf-8"),),
        body=body,
    )


def _workflow_dispatch_inputs(workflow_file: str) -> set[str]:
    script = (
        'require "yaml"; require "json"; '
        "value = YAML.safe_load(File.read(ARGV.fetch(0)), permitted_classes: [], aliases: false); "
        'STDOUT.write(JSON.generate(value.fetch("on").fetch("workflow_dispatch").fetch("inputs").keys))'
    )
    result = subprocess.run(
        ["ruby", "-e", script, str(_REPOSITORY_ROOT / ".github/workflows" / workflow_file)],
        cwd=_REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    decoded = json.loads(result.stdout)
    assert isinstance(decoded, list)
    return set(decoded)


def _empty_runs() -> GitHubHttpResponse:
    return _json_response(200, b'{"total_count":0,"workflow_runs":[]}')


def _dispatch_response(*, run_id: int = 901) -> GitHubHttpResponse:
    return _json_response(
        200,
        (
            '{"html_url":"https://github.com/StephenBickel/carl-agent/actions/runs/'
            f'{run_id}","run_url":"https://api.github.com/repos/StephenBickel/'
            f'carl-agent/actions/runs/{run_id}","workflow_run_id":{run_id}}}'
        ).encode(),
    )


def _rate_limit_response(kind: str) -> tuple[GitHubHttpResponse, str]:
    if kind == "primary":
        return (
            GitHubHttpResponse(
                status=403,
                headers=(
                    ("content-type", "application/json; charset=utf-8"),
                    ("x-ratelimit-remaining", "0"),
                    ("x-ratelimit-reset", "1787313720"),
                ),
                body=b'{"message":"API rate limit exceeded"}',
            ),
            "2026-08-21T12:02:00Z",
        )
    assert kind == "secondary"
    return (
        GitHubHttpResponse(
            status=429,
            headers=(
                ("content-type", "application/json; charset=utf-8"),
                ("retry-after", "90"),
                ("x-ratelimit-remaining", "17"),
            ),
            body=b'{"message":"You have exceeded a secondary rate limit"}',
        ),
        "2026-08-21T12:01:30Z",
    )


def _accepted_run(
    request: CloudRunRequest,
    *,
    head_sha: str = _WORKFLOW_REVISION,
    created_at: str = "2026-08-21T12:00:02Z",
    path: str | None = None,
    actor: str = _DISPATCH_ACTOR,
    run_id: int = 901,
) -> GitHubHttpResponse:
    attempt_key = request.attempt_key(1)
    body = (
        '{"total_count":1,"workflow_runs":[{'
        f'"actor":{{"id":41898282,"login":"{actor}","type":"Bot"}},'
        '"conclusion":null,'
        f'"created_at":"{created_at}",'
        f'"display_title":"{attempt_key}",'
        '"event":"workflow_dispatch",'
        f'"head_branch":"{_WORKFLOW_REF}",'
        f'"head_sha":"{head_sha}",'
        f'"html_url":"https://github.com/StephenBickel/carl-agent/actions/runs/{run_id}",'
        f'"id":{run_id},'
        f'"path":"{path or request.expected_workflow_path + "@" + _WORKFLOW_REF}",'
        '"repository":{"full_name":"StephenBickel/carl-agent"},'
        '"status":"queued",'
        f'"url":"https://api.github.com/repos/StephenBickel/carl-agent/actions/runs/{run_id}"'
        "}]}".encode()
    )
    return _json_response(200, body)


def _multiple_accepted_runs(request: CloudRunRequest) -> GitHubHttpResponse:
    first = json.loads(_accepted_run(request).body)["workflow_runs"][0]
    second = json.loads(_accepted_run(request, run_id=902).body)["workflow_runs"][0]
    return _json_response(
        200,
        json.dumps(
            {"total_count": 2, "workflow_runs": [first, second]},
            separators=(",", ":"),
        ).encode(),
    )


def _documented_ref_response(
    *, object_url_origin: str = "https://api.github.com"
) -> GitHubHttpResponse:
    ref = "refs/heads/experimental/exp-001"
    return _json_response(
        200,
        json.dumps(
            {
                "ref": ref,
                "node_id": "REF_kwDODocumentedRef",
                "url": (
                    "https://api.github.com/repos/StephenBickel/carl-agent/git/refs/heads/"
                    "experimental/exp-001"
                ),
                "object": {
                    "type": "commit",
                    "sha": _CANDIDATE_COMMIT,
                    "url": (
                        f"{object_url_origin}/repos/StephenBickel/carl-agent/git/commits/"
                        f"{_CANDIDATE_COMMIT}"
                    ),
                },
            },
            separators=(",", ":"),
        ).encode(),
    )


def _documented_pull_response(
    *,
    title: str,
    body: str,
    head_repo_url: str = "https://api.github.com/repos/StephenBickel/carl-agent",
) -> GitHubHttpResponse:
    repository = {
        "id": 991,
        "node_id": "R_kgDODocumentedRepo",
        "name": "carl-agent",
        "full_name": "StephenBickel/carl-agent",
        "private": False,
        "url": head_repo_url,
        "html_url": "https://github.com/StephenBickel/carl-agent",
    }
    value = {
        "id": 1081,
        "node_id": "PR_kwDODocumentedPull",
        "number": 81,
        "state": "open",
        "locked": False,
        "title": title,
        "user": {
            "login": "carl-autonomy[bot]",
            "id": 41898282,
            "type": "Bot",
            "url": "https://api.github.com/users/carl-autonomy%5Bbot%5D",
            "html_url": "https://github.com/apps/carl-autonomy",
        },
        "body": body,
        "created_at": "2026-08-21T11:59:00Z",
        "updated_at": "2026-08-21T12:00:00Z",
        "closed_at": None,
        "merged_at": None,
        "merge_commit_sha": None,
        "assignee": None,
        "assignees": [],
        "requested_reviewers": [],
        "requested_teams": [],
        "labels": [],
        "milestone": None,
        "draft": True,
        "commits_url": "https://api.github.com/repos/StephenBickel/carl-agent/pulls/81/commits",
        "review_comments_url": (
            "https://api.github.com/repos/StephenBickel/carl-agent/pulls/81/comments"
        ),
        "comments_url": "https://api.github.com/repos/StephenBickel/carl-agent/issues/81/comments",
        "statuses_url": (
            f"https://api.github.com/repos/StephenBickel/carl-agent/statuses/{_CANDIDATE_COMMIT}"
        ),
        "url": "https://api.github.com/repos/StephenBickel/carl-agent/pulls/81",
        "html_url": "https://github.com/StephenBickel/carl-agent/pull/81",
        "issue_url": "https://api.github.com/repos/StephenBickel/carl-agent/issues/81",
        "diff_url": "https://github.com/StephenBickel/carl-agent/pull/81.diff",
        "patch_url": "https://github.com/StephenBickel/carl-agent/pull/81.patch",
        "head": {
            "label": "StephenBickel:experimental/exp-001",
            "ref": "experimental/exp-001",
            "sha": _CANDIDATE_COMMIT,
            "user": {"login": "StephenBickel"},
            "repo": repository,
        },
        "base": {
            "label": "StephenBickel:main",
            "ref": "main",
            "sha": "0" * 40,
            "user": {"login": "StephenBickel"},
            "repo": {**repository, "url": "https://api.github.com/repos/StephenBickel/carl-agent"},
        },
        "author_association": "OWNER",
        "auto_merge": None,
    }
    return _json_response(200, json.dumps(value, separators=(",", ":")).encode())


def _documented_workflow_run_response(
    request: CloudRunRequest,
    *,
    jobs_url_origin: str = "https://api.github.com",
) -> GitHubHttpResponse:
    run_id = 901
    actor = {
        "login": _DISPATCH_ACTOR,
        "id": 41898282,
        "node_id": "BOT_kgDODocumentedActor",
        "avatar_url": "https://avatars.githubusercontent.com/u/41898282?v=4",
        "gravatar_id": "",
        "url": "https://api.github.com/users/carl-autonomy%5Bbot%5D",
        "html_url": "https://github.com/apps/carl-autonomy",
        "followers_url": "https://api.github.com/users/carl-autonomy%5Bbot%5D/followers",
        "following_url": "https://api.github.com/users/carl-autonomy%5Bbot%5D/following{/other_user}",
        "gists_url": "https://api.github.com/users/carl-autonomy%5Bbot%5D/gists{/gist_id}",
        "starred_url": "https://api.github.com/users/carl-autonomy%5Bbot%5D/starred{/owner}{/repo}",
        "subscriptions_url": "https://api.github.com/users/carl-autonomy%5Bbot%5D/subscriptions",
        "organizations_url": "https://api.github.com/users/carl-autonomy%5Bbot%5D/orgs",
        "repos_url": "https://api.github.com/users/carl-autonomy%5Bbot%5D/repos",
        "events_url": "https://api.github.com/users/carl-autonomy%5Bbot%5D/events{/privacy}",
        "received_events_url": "https://api.github.com/users/carl-autonomy%5Bbot%5D/received_events",
        "type": "Bot",
        "site_admin": False,
    }
    run = {
        "id": run_id,
        "name": "Autonomous improvement",
        "node_id": "WFR_kwDODocumentedRun",
        "check_suite_id": 1901,
        "check_suite_node_id": "CS_kwDODocumentedSuite",
        "head_branch": _WORKFLOW_REF,
        "head_sha": _WORKFLOW_REVISION,
        "path": f"{request.expected_workflow_path}@{_WORKFLOW_REF}",
        "run_number": 42,
        "event": "workflow_dispatch",
        "display_title": request.attempt_key(1),
        "status": "queued",
        "conclusion": None,
        "workflow_id": 77,
        "url": f"https://api.github.com/repos/StephenBickel/carl-agent/actions/runs/{run_id}",
        "html_url": f"https://github.com/StephenBickel/carl-agent/actions/runs/{run_id}",
        "pull_requests": [],
        "created_at": "2026-08-21T12:00:02Z",
        "updated_at": "2026-08-21T12:00:03Z",
        "actor": actor,
        "run_attempt": 1,
        "run_started_at": "2026-08-21T12:00:02Z",
        "triggering_actor": actor,
        "jobs_url": (
            f"{jobs_url_origin}/repos/StephenBickel/carl-agent/actions/runs/{run_id}/jobs"
        ),
        "logs_url": f"https://api.github.com/repos/StephenBickel/carl-agent/actions/runs/{run_id}/logs",
        "check_suite_url": "https://api.github.com/repos/StephenBickel/carl-agent/check-suites/1901",
        "artifacts_url": f"https://api.github.com/repos/StephenBickel/carl-agent/actions/runs/{run_id}/artifacts",
        "cancel_url": f"https://api.github.com/repos/StephenBickel/carl-agent/actions/runs/{run_id}/cancel",
        "rerun_url": f"https://api.github.com/repos/StephenBickel/carl-agent/actions/runs/{run_id}/rerun",
        "workflow_url": "https://api.github.com/repos/StephenBickel/carl-agent/actions/workflows/77",
        "repository": {
            "id": 991,
            "node_id": "R_kgDODocumentedRepo",
            "name": "carl-agent",
            "full_name": "StephenBickel/carl-agent",
            "private": False,
            "url": "https://api.github.com/repos/StephenBickel/carl-agent",
            "html_url": "https://github.com/StephenBickel/carl-agent",
            "owner": {"login": "StephenBickel", "id": 42, "type": "User"},
        },
    }
    return _json_response(
        200,
        json.dumps({"total_count": 1, "workflow_runs": [run]}, separators=(",", ":")).encode(),
    )


def _documented_checks_response(
    *,
    check_url_origin: str = "https://api.github.com",
) -> GitHubHttpResponse:
    runs = []
    for index, name in enumerate(APPROVED_REQUIRED_CHECKS, start=1):
        runs.append(
            {
                "id": index,
                "head_sha": _CANDIDATE_COMMIT,
                "node_id": f"CR_kwDODocumented{index}",
                "external_id": f"autonomy-{index}",
                "url": (f"{check_url_origin}/repos/StephenBickel/carl-agent/check-runs/{index}"),
                "html_url": f"https://github.com/StephenBickel/carl-agent/runs/{index}",
                "details_url": f"https://github.com/StephenBickel/carl-agent/actions/runs/{index}",
                "status": "completed",
                "conclusion": "success",
                "started_at": "2026-08-21T11:58:00Z",
                "completed_at": "2026-08-21T11:59:00Z",
                "output": {
                    "title": name,
                    "summary": "All required checks passed.",
                    "text": "",
                    "annotations_count": 0,
                    "annotations_url": (
                        "https://api.github.com/repos/StephenBickel/carl-agent/check-runs/"
                        f"{index}/annotations"
                    ),
                },
                "name": name,
                "check_suite": {"id": 1901},
                "app": {
                    "id": 15368,
                    "slug": "github-actions",
                    "node_id": "A_kwDODocumentedApp",
                    "name": "GitHub Actions",
                    "description": "Automate your workflow from idea to production.",
                    "external_url": "https://docs.github.com/actions",
                    "html_url": "https://github.com/apps/github-actions",
                    "created_at": "2018-07-30T09:30:17Z",
                    "updated_at": "2026-08-01T09:30:17Z",
                },
                "pull_requests": [],
            }
        )
    return _json_response(
        200,
        json.dumps({"total_count": len(runs), "check_runs": runs}, separators=(",", ":")).encode(),
    )


def test_gateway_has_no_caller_configurable_public_constructor() -> None:
    with pytest.raises(GitHubCloudError, match="github_protected_configuration_required"):
        GitHubCloudGateway(
            repository="attacker/repository",
            token="attacker-token",
            transport=FakeTransport(deque()),
            clock=_clock,
            state_controller=FakeDurableEffectController(commands={}),
            workflow_ref=_WORKFLOW_REF,
            dispatch_actor_login=_DISPATCH_ACTOR,
        )


def test_dispatch_requires_a_claimed_persisted_exact_command_before_network() -> None:
    request = _request()
    transport = FakeTransport(deque([_empty_runs()]))
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
    gateway = _gateway_with_state(pending, transport, repository=request.repository)

    with pytest.raises(GitHubCloudError, match="github_command_not_claimed"):
        gateway.dispatch_workflow(pending.command.command_key, request)

    assert transport.requests == []


def test_exact_revision_dispatch_uses_bound_request_and_attempt_keys() -> None:
    request = _request()
    transport = FakeTransport(
        deque(
            [
                _empty_runs(),
                _dispatch_response(),
            ]
        )
    )
    state = _claimed_dispatch_command(request)
    gateway = _gateway_with_state(state, transport, repository=request.repository)

    result = gateway.dispatch_workflow(state.command.command_key, request)

    assert result.status == "dispatched"
    assert result.run_id == 901
    assert result.head_sha == _WORKFLOW_REVISION
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
            "workflow_revision": _WORKFLOW_REVISION,
            "workflow_blob_digest": "e" * 64,
        },
        "ref": _WORKFLOW_REF,
        "return_run_details": True,
    }
    assert dispatch.follow_redirects is False


@pytest.mark.parametrize(
    "workflow_file",
    ["autonomous-improvement.yml", "autonomous-soak.yml"],
)
def test_dispatch_input_keys_match_checked_in_workflow_contract(
    workflow_file: str,
) -> None:
    request = _request(workflow_file)
    state = _claimed_dispatch_command(request)
    transport = FakeTransport(deque([_empty_runs(), _dispatch_response()]))
    gateway = _gateway_with_state(state, transport, repository=request.repository)

    gateway.dispatch_workflow(state.command.command_key, request)

    payload = transport.requests[1].json_body
    assert payload is not None
    assert set(payload["inputs"]) == _workflow_dispatch_inputs(workflow_file)


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
    state = _claimed_dispatch_command(request)
    gateway = _gateway_with_state(state, transport, repository=request.repository)

    result = gateway.dispatch_workflow(state.command.command_key, request)

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
                "autonomous-improvement.yml/runs?actor=carl-autonomy%5Bbot%5D&branch=main"
                "&event=workflow_dispatch&head_sha=1111111111111111111111111111111111111111"
                '&page=2&per_page=100>; rel="next", '
                "<https://api.github.com/repos/StephenBickel/carl-agent/actions/workflows/"
                "autonomous-improvement.yml/runs?actor=carl-autonomy%5Bbot%5D&branch=main"
                "&event=workflow_dispatch&head_sha=1111111111111111111111111111111111111111"
                '&page=2&per_page=100>; rel="last"',
            ),
        ),
        body=b'{"total_count":1,"workflow_runs":[]}',
    )
    transport = FakeTransport(deque([first_page, _accepted_run(request)]))
    state = _claimed_dispatch_command(request)
    gateway = _gateway_with_state(state, transport, repository=request.repository)

    result = gateway.dispatch_workflow(state.command.command_key, request)

    assert result.status == "reconciled"
    assert result.run_id == 901
    assert [item.method for item in transport.requests] == ["GET", "GET"]
    assert transport.requests[1].query == (
        ("actor", _DISPATCH_ACTOR),
        ("branch", _WORKFLOW_REF),
        ("event", "workflow_dispatch"),
        ("head_sha", _WORKFLOW_REVISION),
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
    state = _claimed_dispatch_command(request)
    gateway = _gateway_with_state(state, transport, repository=request.repository)

    with pytest.raises(GitHubCloudError, match="github_pagination_link_invalid"):
        gateway.dispatch_workflow(state.command.command_key, request)

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
                        "workflows/autonomous-improvement.yml/runs?"
                        "actor=carl-autonomy%5Bbot%5D&branch=main&event=workflow_dispatch&"
                        "head_sha=1111111111111111111111111111111111111111&"
                        f"page={page + 1}&per_page=100>"
                        '; rel="next"',
                    ),
                ),
                body=b'{"total_count":6,"workflow_runs":[]}',
            )
        )
    transport = FakeTransport(responses)
    state = _claimed_dispatch_command(request)
    gateway = _gateway_with_state(state, transport, repository=request.repository)

    with pytest.raises(GitHubCloudError, match="github_pagination_limit_exceeded"):
        gateway.dispatch_workflow(state.command.command_key, request)

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
    state = _claimed_dispatch_command(request)
    gateway = _gateway_with_state(state, transport, repository=request.repository)

    decision = gateway.dispatch_workflow(state.command.command_key, request)

    assert isinstance(decision, GitHubRetryDecision)
    assert decision.status == "retry_scheduled"
    assert decision.reason == "github_rate_limited"
    assert decision.retry_not_before == "2026-08-21T12:02:00Z"
    assert decision.command_occurred_at == _NOW
    assert decision.attempt == 1
    assert decision.max_attempts == 3
    assert len(transport.requests) == 1


@pytest.mark.parametrize("kind", ["primary", "secondary"])
@pytest.mark.parametrize(
    ("effect", "expected_method"),
    [
        pytest.param("checks-get", "GET", id="get-required-checks"),
        pytest.param("dispatch-post", "POST", id="post-workflow-dispatch"),
        pytest.param("pull-patch", "PATCH", id="patch-pull-request"),
        pytest.param("auto-merge-post", "POST", id="post-auto-merge"),
    ],
)
def test_primary_and_secondary_limits_are_normalized_across_public_http_verbs(
    kind: str,
    effect: str,
    expected_method: str,
) -> None:
    limited, retry_not_before = _rate_limit_response(kind)
    if effect == "checks-get":
        request = RequiredChecksRequest.create(head_sha=_CANDIDATE_COMMIT)
        binding = required_checks_binding("StephenBickel/carl-agent", request)
        state = _claimed_effect_command(
            binding,
            authority="observer",
            operation="observe",
            claim_id=f"github-rate-{kind}-get-claim",
        )
        transport = FakeTransport(deque([limited]))
        gateway = _gateway_with_state(state, transport)
        decision = gateway.observe_required_checks(state.command.command_key, request)
    elif effect == "dispatch-post":
        request = _request()
        state = _claimed_dispatch_command(request)
        transport = FakeTransport(deque([_empty_runs(), limited]))
        gateway = _gateway_with_state(state, transport)
        decision = gateway.dispatch_workflow(state.command.command_key, request)
    elif effect == "pull-patch":
        request = _pull_update()
        binding = pull_request_update_binding("StephenBickel/carl-agent", request)
        state = _claimed_effect_command(
            binding,
            authority="promoter",
            operation="github_effect",
            claim_id=f"github-rate-{kind}-patch-claim",
        )
        transport = FakeTransport(deque([_json_response(200, _pull_request_body()), limited]))
        gateway = _gateway_with_state(state, transport)
        decision = gateway.update_pull_request(state.command.command_key, request)
    else:
        request = _auto_merge_request()
        binding = pull_request_auto_merge_binding("StephenBickel/carl-agent", request)
        state = _claimed_effect_command(
            binding,
            authority="promoter",
            operation="github_effect",
            claim_id=f"github-rate-{kind}-put-claim",
        )
        transport = FakeTransport(
            deque([_json_response(200, _pull_request_body(draft=False)), limited])
        )
        gateway = _gateway_with_state(state, transport)
        decision = gateway.enable_pull_request_auto_merge(state.command.command_key, request)

    assert isinstance(decision, GitHubRetryDecision)
    assert decision.reason == "github_rate_limited"
    assert decision.retry_not_before == retry_not_before
    assert decision.command_occurred_at == _NOW
    assert decision.attempt == 1
    assert decision.max_attempts == 3
    assert transport.requests[-1].method == expected_method


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param((("retry-after", "0"),), id="zero-retry-after"),
        pytest.param((("retry-after", "86401"),), id="excessive-retry-after"),
        pytest.param((("retry-after", "1.5"),), id="fractional-retry-after"),
        pytest.param(
            (("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "1787313600")),
            id="non-future-primary-reset",
        ),
        pytest.param(
            (("x-ratelimit-remaining", "0"), ("x-ratelimit-reset", "1787400001")),
            id="excessive-primary-reset",
        ),
    ],
)
def test_malformed_or_excessive_rate_limit_values_fail_closed(
    headers: tuple[tuple[str, str], ...],
) -> None:
    request = RequiredChecksRequest.create(head_sha=_CANDIDATE_COMMIT)
    binding = required_checks_binding("StephenBickel/carl-agent", request)
    state = _claimed_effect_command(
        binding,
        authority="observer",
        operation="observe",
        claim_id="github-rate-invalid-claim",
    )
    response = GitHubHttpResponse(
        status=429,
        headers=(("content-type", "application/json"), *headers),
        body=b'{"message":"rate limited"}',
    )
    transport = FakeTransport(deque([response]))
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_rate_limit_invalid"):
        gateway.observe_required_checks(state.command.command_key, request)


def test_mutation_rate_limit_fence_retries_after_durable_deadline_across_restart() -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    state = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="github-rate-restart-claim",
    )
    controller = FakeDurableEffectController(commands={state.command.command_key: state})
    limited, retry_not_before = _rate_limit_response("secondary")
    first_transport = FakeTransport(deque([_missing_ref(), limited]))

    first = _gateway_with_controller(
        controller, first_transport
    ).create_or_reconcile_experimental_branch(state.command.command_key, request)

    assert isinstance(first, GitHubRetryDecision)
    assert controller.attempts[state.command.effect_key]["attempt_state"] == "retry_scheduled"
    assert controller.attempts[state.command.effect_key]["not_before"] == retry_not_before

    created = GitHubHttpResponse(
        status=201,
        headers=_exact_ref().headers,
        body=_exact_ref().body,
    )
    retry_transport = FakeTransport(deque([_missing_ref(), created]))

    def retry_clock() -> datetime:
        return datetime(2026, 8, 21, 12, 1, 31, tzinfo=UTC)

    retried = _gateway_with_controller(
        controller,
        retry_transport,
        clock=retry_clock,
    ).create_or_reconcile_experimental_branch(state.command.command_key, request)

    assert retried.status == "created"
    assert [item.method for item in retry_transport.requests] == ["GET", "POST"]
    assert controller.attempts[state.command.effect_key]["attempt_state"] == "completed"


def test_rate_limit_fence_rearms_after_claim_expiry_under_exact_reclaimed_command() -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    state = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="github-rate-expiring-claim",
    )
    controller = FakeDurableEffectController(commands={state.command.command_key: state})
    limited = GitHubHttpResponse(
        status=429,
        headers=(
            ("content-type", "application/json; charset=utf-8"),
            ("retry-after", "360"),
        ),
        body=b'{"message":"You have exceeded a secondary rate limit"}',
    )
    first_transport = FakeTransport(deque([_missing_ref(), limited]))

    first = _gateway_with_controller(
        controller, first_transport
    ).create_or_reconcile_experimental_branch(state.command.command_key, request)

    assert isinstance(first, GitHubRetryDecision)
    assert first.retry_not_before == "2026-08-21T12:06:00Z"
    assert controller.attempts[state.command.effect_key]["attempt_state"] == "retry_scheduled"

    reclaimed_claim = CommandClaim(
        command_key=state.command.command_key,
        claim_id="github-rate-reclaimed-claim",
        authority="builder",
        expected_revision=10,
        claimed_at="2026-08-21T12:06:01Z",
        expires_at="2026-08-21T12:16:01Z",
    )
    reclaimed = replace(state, revision=11, claim=reclaimed_claim)
    controller.commands[state.command.command_key] = reclaimed
    created = GitHubHttpResponse(status=201, headers=_exact_ref().headers, body=_exact_ref().body)
    retry_transport = FakeTransport(deque([_missing_ref(), created]))

    def retry_clock() -> datetime:
        return datetime(2026, 8, 21, 12, 6, 2, tzinfo=UTC)

    retried = _gateway_with_controller(
        controller,
        retry_transport,
        clock=retry_clock,
    ).create_or_reconcile_experimental_branch(reclaimed.command.command_key, request)

    assert retried.status == "created"
    assert [item.method for item in retry_transport.requests] == ["GET", "POST"]
    persisted = controller.attempts[state.command.effect_key]
    assert persisted["claim_id"] == reclaimed_claim.claim_id
    assert persisted["command_revision"] == reclaimed.revision
    assert persisted["claim_expected_revision"] == reclaimed_claim.expected_revision


@pytest.mark.parametrize("kind", ["primary", "secondary"])
@pytest.mark.parametrize("at_mutation", [False, True], ids=["preflight-get", "mutation-post"])
@pytest.mark.parametrize(
    "effect",
    [
        "experimental-ref",
        "pull-create",
        "pull-ready",
        "revert-ref",
        "revert-pull",
    ],
)
def test_rate_limits_are_normalized_for_every_remaining_effect_family(
    kind: str,
    at_mutation: bool,
    effect: str,
) -> None:
    limited, retry_not_before = _rate_limit_response(kind)
    if effect == "experimental-ref":
        request = _experimental_request()
        binding = experimental_branch_binding("StephenBickel/carl-agent", request)
        outcomes = [_missing_ref(), limited] if at_mutation else [limited]
        invoke = "create_or_reconcile_experimental_branch"
        authority, operation = "builder", "publish_experimental"
    elif effect == "pull-create":
        request = _pull_request_create()
        binding = pull_request_create_binding("StephenBickel/carl-agent", request)
        outcomes = (
            [_exact_ref(), _pull_request_list(present=False), limited] if at_mutation else [limited]
        )
        invoke = "create_or_reconcile_pull_request"
        authority, operation = "promoter", "github_effect"
    elif effect == "pull-ready":
        request = _ready_request()
        binding = pull_request_ready_binding("StephenBickel/carl-agent", request)
        outcomes = (
            [_json_response(200, _pull_request_body(draft=True)), limited]
            if at_mutation
            else [limited]
        )
        invoke = "mark_pull_request_ready"
        authority, operation = "promoter", "github_effect"
    elif effect == "revert-ref":
        request = _revert_branch_request()
        binding = revert_branch_binding("StephenBickel/carl-agent", request)
        outcomes = (
            [*_valid_revert_topology(), _missing_ref(), limited] if at_mutation else [limited]
        )
        invoke = "create_or_reconcile_revert_branch"
        authority, operation = "promoter", "github_effect"
    else:
        request = _revert_pull_request()
        binding = revert_pull_request_binding("StephenBickel/carl-agent", request)
        outcomes = (
            [_revert_ref(), _pull_request_list(present=False), limited]
            if at_mutation
            else [limited]
        )
        invoke = "create_or_reconcile_revert_pull_request"
        authority, operation = "promoter", "github_effect"
    state = _claimed_effect_command(
        binding,
        authority=authority,
        operation=operation,
        claim_id=f"github-rate-{kind}-{effect}-claim",
    )
    transport = FakeTransport(deque(outcomes))
    gateway = _gateway_with_state(state, transport)

    decision = getattr(gateway, invoke)(state.command.command_key, request)

    assert isinstance(decision, GitHubRetryDecision)
    assert decision.retry_not_before == retry_not_before
    assert decision.command_occurred_at == _NOW
    assert transport.requests[-1].method == ("POST" if at_mutation else "GET")


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
    state = _claimed_dispatch_command(request)
    gateway = _gateway_with_state(state, transport, repository=request.repository)

    with pytest.raises(GitHubCloudError, match="github_dispatch_identity_conflict"):
        gateway.dispatch_workflow(state.command.command_key, request)

    assert [item.method for item in transport.requests] == ["GET"]


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(
            _accepted_run(_request(), actor="attacker"),
            id="wrong-actor",
        ),
        pytest.param(
            _accepted_run(
                _request(),
                path=".github/workflows/autonomous-soak.yml@main",
            ),
            id="wrong-path",
        ),
        pytest.param(
            _multiple_accepted_runs(_request()),
            id="multiple-matching-runs",
        ),
    ],
)
def test_same_title_run_without_exact_protected_identity_is_rejected(
    response: GitHubHttpResponse,
) -> None:
    request = _request()
    state = _claimed_dispatch_command(request)
    transport = FakeTransport(deque([response]))
    gateway = _gateway_with_state(state, transport, repository=request.repository)

    with pytest.raises(
        GitHubCloudError,
        match="github_dispatch_identity_(?:conflict|ambiguous)",
    ):
        gateway.dispatch_workflow(state.command.command_key, request)

    assert [item.method for item in transport.requests] == ["GET"]


def test_dispatch_200_rejects_run_urls_outside_exact_repository() -> None:
    request = _request()
    state = _claimed_dispatch_command(request)
    response = _json_response(
        200,
        b'{"html_url":"https://attacker.invalid/run/901",'
        b'"run_url":"https://api.github.com/repos/attacker/repository/actions/runs/901",'
        b'"workflow_run_id":901}',
    )
    transport = FakeTransport(deque([_empty_runs(), response]))
    gateway = _gateway_with_state(state, transport, repository=request.repository)

    with pytest.raises(GitHubCloudError, match="github_dispatch_response_invalid"):
        gateway.dispatch_workflow(state.command.command_key, request)

    assert [item.method for item in transport.requests] == ["GET", "POST"]


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
    command = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="github-experimental-claim-01",
    )
    gateway = _gateway_with_state(command, transport)

    result = gateway.create_or_reconcile_experimental_branch(command.command.command_key, request)

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
    state = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="github-experimental-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.create_or_reconcile_experimental_branch(
        state.command.command_key,
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
    state = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="github-experimental-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_immutable_ref_conflict"):
        gateway.create_or_reconcile_experimental_branch(
            state.command.command_key,
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
    state = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="github-experimental-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.create_or_reconcile_experimental_branch(
        state.command.command_key,
        request,
    )

    assert result.status == "reconciled"
    assert [item.method for item in transport.requests] == ["GET", "POST", "GET"]
    assert sum(item.method == "POST" for item in transport.requests) == 1


def test_experimental_branch_reconciles_a_422_ref_creation_race() -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _missing_ref(),
                _json_response(422, b'{"message":"Reference already exists"}'),
                _exact_ref(),
            ]
        )
    )
    state = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="github-experimental-race-claim",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.create_or_reconcile_experimental_branch(state.command.command_key, request)

    assert result.status == "reconciled"
    assert [item.method for item in transport.requests] == ["GET", "POST", "GET"]


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
        f'"node_id":"{_PULL_REQUEST_NODE_ID}",'
        f'"number":81,"state":"open","title":"{title}"}}'
    ).encode()


def _ready_graphql_response(*, head_sha: str = _CANDIDATE_COMMIT) -> GitHubHttpResponse:
    return _json_response(
        200,
        json.dumps(
            {
                "data": {
                    "markPullRequestReadyForReview": {
                        "pullRequest": {
                            "baseRefName": "main",
                            "headRefName": "experimental/exp-001",
                            "headRefOid": head_sha,
                            "id": _PULL_REQUEST_NODE_ID,
                            "isDraft": False,
                            "number": 81,
                            "repository": {"nameWithOwner": "StephenBickel/carl-agent"},
                        }
                    }
                }
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode(),
    )


def _auto_merge_graphql_response(*, head_sha: str = _CANDIDATE_COMMIT) -> GitHubHttpResponse:
    return _json_response(
        200,
        json.dumps(
            {
                "data": {
                    "enablePullRequestAutoMerge": {
                        "pullRequest": {
                            "autoMergeRequest": {"mergeMethod": "SQUASH"},
                            "baseRefName": "main",
                            "headRefName": "experimental/exp-001",
                            "headRefOid": head_sha,
                            "id": _PULL_REQUEST_NODE_ID,
                            "isDraft": False,
                            "number": 81,
                            "repository": {"nameWithOwner": "StephenBickel/carl-agent"},
                        }
                    }
                }
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode(),
    )


def _pull_request_list(
    *,
    present: bool,
    next_url: str | None = None,
) -> GitHubHttpResponse:
    body = b"[" + _pull_request_body() + b"]" if present else b"[]"
    response = _json_response(200, body)
    if next_url is None:
        return response
    return GitHubHttpResponse(
        status=200,
        headers=(*response.headers, ("link", f'<{next_url}>; rel="next"')),
        body=body,
    )


def _pull_page_url(page: int, *, origin: str = "https://api.github.com") -> str:
    return (
        f"{origin}/repos/StephenBickel/carl-agent/pulls?base=main&"
        "head=StephenBickel%3Aexperimental%2Fexp-001&"
        f"page={page}&per_page=100&state=all"
    )


def test_pull_request_create_uses_exact_main_and_experimental_identity() -> None:
    request = _pull_request_create()
    binding = pull_request_create_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _exact_ref(),
                _pull_request_list(present=False),
                _json_response(201, _pull_request_body()),
            ]
        )
    )
    command = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-create-claim-01",
    )
    gateway = _gateway_with_state(command, transport)

    result = gateway.create_or_reconcile_pull_request(command.command.command_key, request)

    assert result.status == "created"
    assert result.number == 81
    assert result.base_branch == "main"
    assert result.head_branch == "experimental/exp-001"
    assert result.head_sha == _CANDIDATE_COMMIT
    assert [item.method for item in transport.requests] == ["GET", "GET", "POST"]
    assert transport.requests[2].path == "/repos/StephenBickel/carl-agent/pulls"
    assert transport.requests[2].json_body == {
        "base": "main",
        "body": request.body,
        "draft": True,
        "head": "experimental/exp-001",
        "title": request.title,
    }


def test_existing_exact_pull_request_reconciles_without_create() -> None:
    request = _pull_request_create()
    binding = pull_request_create_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(deque([_exact_ref(), _pull_request_list(present=True)]))
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-create-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.create_or_reconcile_pull_request(
        state.command.command_key,
        request,
    )

    assert result.status == "reconciled"
    assert result.number == 81
    assert [item.method for item in transport.requests] == ["GET", "GET"]


def test_pull_request_reconciliation_finds_exact_existing_pr_on_later_page() -> None:
    request = _pull_request_create()
    binding = pull_request_create_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _exact_ref(),
                _pull_request_list(present=False, next_url=_pull_page_url(2)),
                _pull_request_list(present=True),
            ]
        )
    )
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-page-two-claim",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.create_or_reconcile_pull_request(state.command.command_key, request)

    assert result.status == "reconciled"
    assert [item.method for item in transport.requests] == ["GET", "GET", "GET"]
    assert transport.requests[2].query == (
        ("base", "main"),
        ("head", "StephenBickel:experimental/exp-001"),
        ("page", "2"),
        ("per_page", "100"),
        ("state", "all"),
    )


def test_pull_request_pagination_rejects_cross_origin_before_mutation() -> None:
    request = _pull_request_create()
    binding = pull_request_create_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _exact_ref(),
                _pull_request_list(
                    present=False,
                    next_url=_pull_page_url(2, origin="https://attacker.invalid"),
                ),
            ]
        )
    )
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-cross-origin-page-claim",
    )
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_pagination_link_invalid"):
        gateway.create_or_reconcile_pull_request(state.command.command_key, request)

    assert [item.method for item in transport.requests] == ["GET", "GET"]


def test_pull_request_pagination_rejects_repeated_page_cycle_before_mutation() -> None:
    request = _pull_request_create()
    binding = pull_request_create_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _exact_ref(),
                _pull_request_list(present=False, next_url=_pull_page_url(1)),
                _json_response(201, _pull_request_body()),
            ]
        )
    )
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-page-cycle-claim",
    )
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_pagination_link_invalid"):
        gateway.create_or_reconcile_pull_request(state.command.command_key, request)

    assert all(item.method == "GET" for item in transport.requests)


def test_pull_request_pagination_stops_at_page_budget_before_mutation() -> None:
    request = _pull_request_create()
    binding = pull_request_create_binding("StephenBickel/carl-agent", request)
    pages = [
        _pull_request_list(present=False, next_url=_pull_page_url(page + 1)) for page in range(1, 6)
    ]
    transport = FakeTransport(deque([_exact_ref(), *pages]))
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-page-budget-claim",
    )
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_pagination_limit_exceeded"):
        gateway.create_or_reconcile_pull_request(state.command.command_key, request)

    assert len(transport.requests) == 6
    assert all(item.method == "GET" for item in transport.requests)


def test_lost_pull_request_create_response_reconciles_without_duplicate() -> None:
    request = _pull_request_create()
    binding = pull_request_create_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _exact_ref(),
                _pull_request_list(present=False),
                GitHubTransportError("github_response_ambiguous", ambiguous=True),
                _exact_ref(),
                _pull_request_list(present=True),
            ]
        )
    )
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-create-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.create_or_reconcile_pull_request(
        state.command.command_key,
        request,
    )

    assert result.status == "reconciled"
    assert result.number == 81
    assert [item.method for item in transport.requests] == [
        "GET",
        "GET",
        "POST",
        "GET",
        "GET",
    ]
    assert sum(item.method == "POST" for item in transport.requests) == 1


def test_pull_request_create_rejects_a_head_ref_that_moved_before_effect() -> None:
    request = _pull_request_create()
    binding = pull_request_create_binding("StephenBickel/carl-agent", request)
    moved_ref = _json_response(
        200,
        b'{"object":{"sha":"3333333333333333333333333333333333333333",'
        b'"type":"commit"},"ref":"refs/heads/experimental/exp-001"}',
    )
    transport = FakeTransport(deque([moved_ref]))
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-create-moved-head-claim",
    )
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_pull_head_ref_mismatch"):
        gateway.create_or_reconcile_pull_request(state.command.command_key, request)

    assert [item.method for item in transport.requests] == ["GET"]


def test_pull_request_create_reconciles_a_422_creation_race() -> None:
    request = _pull_request_create()
    binding = pull_request_create_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _exact_ref(),
                _pull_request_list(present=False),
                _json_response(422, b'{"message":"Validation Failed"}'),
                _exact_ref(),
                _pull_request_list(present=True),
            ]
        )
    )
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-create-race-claim",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.create_or_reconcile_pull_request(state.command.command_key, request)

    assert result.status == "reconciled"
    assert [item.method for item in transport.requests] == [
        "GET",
        "GET",
        "POST",
        "GET",
        "GET",
    ]


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
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-update-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.update_pull_request(
        state.command.command_key,
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
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-update-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.update_pull_request(
        state.command.command_key,
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


def test_mark_ready_uses_the_closed_typed_github_graphql_mutation() -> None:
    request = _ready_request()
    binding = pull_request_ready_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _json_response(200, _pull_request_body(draft=True)),
                _ready_graphql_response(),
            ]
        )
    )
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-ready-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.mark_pull_request_ready(
        state.command.command_key,
        request,
    )

    assert result.status == "updated"
    assert result.draft is False
    assert transport.requests[1].path == "/graphql"
    assert transport.requests[1].json_body == {
        "operationName": "MarkPullRequestReadyForReview",
        "query": _MARK_READY_MUTATION,
        "variables": {"pullRequestId": _PULL_REQUEST_NODE_ID},
    }
    assert [item.method for item in transport.requests] == ["GET", "POST"]
    assert sum(item.method == "POST" for item in transport.requests) == 1


def _auto_merge_request() -> PullRequestAutoMergeRequest:
    return PullRequestAutoMergeRequest.create(
        promotion_id="promotion-exp-001-1",
        number=81,
        head_branch="experimental/exp-001",
        head_sha=_CANDIDATE_COMMIT,
    )


def test_auto_merge_uses_the_closed_typed_squash_github_graphql_mutation() -> None:
    request = _auto_merge_request()
    binding = pull_request_auto_merge_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                _json_response(200, _pull_request_body(draft=False)),
                _auto_merge_graphql_response(),
            ]
        )
    )
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-pr-auto-merge-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.enable_pull_request_auto_merge(
        state.command.command_key,
        request,
    )

    assert result.status == "updated"
    assert result.auto_merge_enabled is True
    assert transport.requests[1].path == "/graphql"
    assert transport.requests[1].json_body == {
        "operationName": "EnablePullRequestAutoMerge",
        "query": _ENABLE_AUTO_MERGE_MUTATION,
        "variables": {"pullRequestId": _PULL_REQUEST_NODE_ID},
    }
    assert [item.method for item in transport.requests] == ["GET", "POST"]
    assert sum(item.method == "POST" for item in transport.requests) == 1


def test_pinned_official_github_schema_supports_only_the_closed_pull_mutations() -> None:
    schema = (
        _REPOSITORY_ROOT / "benchmarks/tests/fixtures/github-graphql-pull-mutations.graphql"
    ).read_text(encoding="utf-8")

    assert "markPullRequestReadyForReview(input: MarkPullRequestReadyForReviewInput!)" in schema
    assert "enablePullRequestAutoMerge(input: EnablePullRequestAutoMergeInput!)" in schema
    assert "pullRequestId: ID!" in schema
    assert "mergeMethod: PullRequestMergeMethod = MERGE" in schema
    assert "SQUASH" in schema


@pytest.mark.parametrize("action", ["update", "ready", "auto-merge"])
def test_pull_effect_head_race_is_persisted_uncertain(action: str) -> None:
    if action == "update":
        request = _pull_update()
        binding = pull_request_update_binding("StephenBickel/carl-agent", request)
        before = _json_response(200, _pull_request_body())
        after = _json_response(
            200,
            _pull_request_body(
                title=request.title,
                body=request.body,
                head_sha="3" * 40,
            ),
        )
    elif action == "ready":
        request = _ready_request()
        binding = pull_request_ready_binding("StephenBickel/carl-agent", request)
        before = _json_response(200, _pull_request_body(draft=True))
        after = _ready_graphql_response(head_sha="3" * 40)
    else:
        request = _auto_merge_request()
        binding = pull_request_auto_merge_binding("StephenBickel/carl-agent", request)
        before = _json_response(200, _pull_request_body(draft=False))
        after = _auto_merge_graphql_response(head_sha="3" * 40)
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id=f"github-pr-{action}-race-claim",
    )
    controller = FakeDurableEffectController(commands={state.command.command_key: state})
    transport = FakeTransport(deque([before, after]))
    gateway = _gateway_with_controller(controller, transport)

    with pytest.raises(GitHubCloudError, match="github_pull_request_identity_conflict"):
        if action == "update":
            gateway.update_pull_request(state.command.command_key, request)
        elif action == "ready":
            gateway.mark_pull_request_ready(state.command.command_key, request)
        else:
            gateway.enable_pull_request_auto_merge(state.command.command_key, request)

    assert controller.attempts[state.command.effect_key]["attempt_state"] == "uncertain"


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
    state = _claimed_effect_command(
        binding,
        authority="observer",
        operation="observe",
        claim_id="github-check-observe-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.observe_required_checks(
        state.command.command_key,
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
    state = _claimed_effect_command(
        binding,
        authority="observer",
        operation="observe",
        claim_id="github-check-observe-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_check_head_mismatch"):
        gateway.observe_required_checks(
            state.command.command_key,
            request,
        )


def test_required_check_command_mismatch_rejects_before_transport() -> None:
    request = RequiredChecksRequest.create(head_sha=_CANDIDATE_COMMIT)
    other = RequiredChecksRequest.create(head_sha="3" * 40)
    binding = required_checks_binding("StephenBickel/carl-agent", other)
    transport = FakeTransport(deque())
    state = _claimed_effect_command(
        binding,
        authority="observer",
        operation="observe",
        claim_id="github-check-observe-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_command_binding_mismatch"):
        gateway.observe_required_checks(
            state.command.command_key,
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


def _git_commit_response(
    sha: str,
    *,
    tree: str,
    parents: tuple[str, ...],
) -> GitHubHttpResponse:
    return _json_response(
        200,
        json.dumps(
            {
                "parents": [{"sha": parent} for parent in parents],
                "sha": sha,
                "tree": {"sha": tree},
            },
            separators=(",", ":"),
        ).encode(),
    )


def _valid_revert_topology() -> list[GitHubHttpResponse]:
    return [
        _git_commit_response(
            "4" * 40,
            tree="a" * 40,
            parents=("7" * 40, "8" * 40),
        ),
        _git_commit_response("7" * 40, tree="6" * 40, parents=("9" * 40,)),
        _git_commit_response("5" * 40, tree="6" * 40, parents=("4" * 40,)),
    ]


def test_exact_revert_branch_reconciles_a_lost_create_without_duplicate() -> None:
    request = _revert_branch_request()
    binding = revert_branch_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                *_valid_revert_topology(),
                _missing_ref(),
                GitHubTransportError("github_response_ambiguous", ambiguous=True),
                _revert_ref(),
            ]
        )
    )
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-revert-branch-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.create_or_reconcile_revert_branch(
        state.command.command_key,
        request,
    )

    assert result.status == "reconciled"
    assert result.ref == "refs/heads/revert/promotion-exp-001-1"
    assert result.commit_sha == "5" * 40
    assert [item.method for item in transport.requests] == [
        "GET",
        "GET",
        "GET",
        "GET",
        "POST",
        "GET",
    ]
    assert sum(item.method == "POST" for item in transport.requests) == 1


@pytest.mark.parametrize(
    "topology",
    [
        pytest.param(
            [
                _git_commit_response(
                    "4" * 40,
                    tree="a" * 40,
                    parents=("7" * 40,),
                )
            ],
            id="promotion-not-two-parent-merge",
        ),
        pytest.param(
            [
                _valid_revert_topology()[0],
                _git_commit_response("7" * 40, tree="9" * 40, parents=("0" * 40,)),
            ],
            id="first-parent-tree-mismatch",
        ),
        pytest.param(
            [
                *_valid_revert_topology()[:2],
                _git_commit_response("5" * 40, tree="6" * 40, parents=("3" * 40,)),
            ],
            id="revert-parent-mismatch",
        ),
        pytest.param(
            [
                *_valid_revert_topology()[:2],
                _git_commit_response("5" * 40, tree="9" * 40, parents=("4" * 40,)),
            ],
            id="restored-tree-mismatch",
        ),
    ],
)
def test_revert_branch_rejects_unbound_commit_topology_before_mutation(
    topology: list[GitHubHttpResponse],
) -> None:
    request = _revert_branch_request()
    binding = revert_branch_binding("StephenBickel/carl-agent", request)
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-revert-topology-claim",
    )
    transport = FakeTransport(deque(topology))
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_revert_topology_invalid"):
        gateway.create_or_reconcile_revert_branch(state.command.command_key, request)

    assert all(item.method == "GET" for item in transport.requests)


def test_revert_branch_reconciles_a_422_ref_creation_race_after_topology_check() -> None:
    request = _revert_branch_request()
    binding = revert_branch_binding("StephenBickel/carl-agent", request)
    transport = FakeTransport(
        deque(
            [
                *_valid_revert_topology(),
                _missing_ref(),
                _json_response(422, b'{"message":"Reference already exists"}'),
                _revert_ref(),
            ]
        )
    )
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-revert-branch-race-claim",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.create_or_reconcile_revert_branch(state.command.command_key, request)

    assert result.status == "reconciled"
    assert [item.method for item in transport.requests] == [
        "GET",
        "GET",
        "GET",
        "GET",
        "POST",
        "GET",
    ]


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
                _revert_ref(),
                _pull_request_list(present=False),
                GitHubTransportError("github_response_ambiguous", ambiguous=True),
                _revert_ref(),
                _json_response(200, b"[" + _revert_pull_body() + b"]"),
            ]
        )
    )
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-revert-pr-claim-01",
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.create_or_reconcile_revert_pull_request(
        state.command.command_key,
        request,
    )

    assert result.status == "reconciled"
    assert result.base_branch == "main"
    assert result.head_branch == "revert/promotion-exp-001-1"
    assert result.head_sha == "5" * 40
    assert [item.method for item in transport.requests] == [
        "GET",
        "GET",
        "POST",
        "GET",
        "GET",
    ]
    assert sum(item.method == "POST" for item in transport.requests) == 1


def test_revert_pull_request_rejects_a_moved_revert_head_ref() -> None:
    request = _revert_pull_request()
    binding = revert_pull_request_binding("StephenBickel/carl-agent", request)
    moved = _json_response(
        200,
        b'{"object":{"sha":"3333333333333333333333333333333333333333",'
        b'"type":"commit"},"ref":"refs/heads/revert/promotion-exp-001-1"}',
    )
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-revert-pr-moved-head-claim",
    )
    transport = FakeTransport(deque([moved]))
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_pull_head_ref_mismatch"):
        gateway.create_or_reconcile_revert_pull_request(state.command.command_key, request)

    assert [item.method for item in transport.requests] == ["GET"]


def test_documented_additive_ref_shape_is_accepted() -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    state = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="github-documented-ref-claim",
    )
    transport = FakeTransport(deque([_documented_ref_response()]))
    gateway = _gateway_with_state(state, transport)

    result = gateway.create_or_reconcile_experimental_branch(state.command.command_key, request)

    assert result.status == "reconciled"
    assert result.commit_sha == _CANDIDATE_COMMIT


def test_documented_ref_shape_rejects_an_untrusted_object_url() -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    state = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="github-documented-ref-url-claim",
    )
    transport = FakeTransport(
        deque([_documented_ref_response(object_url_origin="https://attacker.invalid")])
    )
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_ref_response_schema_invalid"):
        gateway.create_or_reconcile_experimental_branch(state.command.command_key, request)


def test_documented_additive_pull_shape_is_accepted() -> None:
    request = _pull_update()
    binding = pull_request_update_binding("StephenBickel/carl-agent", request)
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-documented-pull-claim",
    )
    transport = FakeTransport(
        deque([_documented_pull_response(title=request.title, body=request.body)])
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.update_pull_request(state.command.command_key, request)

    assert result.status == "reconciled"
    assert result.head_sha == _CANDIDATE_COMMIT


def test_documented_pull_shape_rejects_an_untrusted_nested_repository_url() -> None:
    request = _pull_update()
    binding = pull_request_update_binding("StephenBickel/carl-agent", request)
    state = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="github-documented-pull-url-claim",
    )
    transport = FakeTransport(
        deque(
            [
                _documented_pull_response(
                    title=request.title,
                    body=request.body,
                    head_repo_url="https://attacker.invalid/repository",
                )
            ]
        )
    )
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_pull_response_schema_invalid"):
        gateway.update_pull_request(state.command.command_key, request)


def test_documented_additive_workflow_run_shape_is_accepted() -> None:
    request = _request()
    state = _claimed_dispatch_command(request)
    transport = FakeTransport(deque([_documented_workflow_run_response(request)]))
    gateway = _gateway_with_state(state, transport)

    result = gateway.dispatch_workflow(state.command.command_key, request)

    assert result.status == "reconciled"
    assert result.run_id == 901


def test_documented_workflow_run_shape_rejects_an_untrusted_jobs_url() -> None:
    request = _request()
    state = _claimed_dispatch_command(request)
    transport = FakeTransport(
        deque(
            [_documented_workflow_run_response(request, jobs_url_origin="https://attacker.invalid")]
        )
    )
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_run_response_schema_invalid"):
        gateway.dispatch_workflow(state.command.command_key, request)


def test_documented_dispatch_shape_tolerates_a_safe_additive_scalar() -> None:
    request = _request()
    state = _claimed_dispatch_command(request)
    body = {
        "workflow_run_id": 901,
        "run_url": "https://api.github.com/repos/StephenBickel/carl-agent/actions/runs/901",
        "html_url": "https://github.com/StephenBickel/carl-agent/actions/runs/901",
        "status": "queued",
    }
    transport = FakeTransport(
        deque([_empty_runs(), _json_response(200, json.dumps(body).encode())])
    )
    gateway = _gateway_with_state(state, transport)

    result = gateway.dispatch_workflow(state.command.command_key, request)

    assert result.status == "dispatched"
    assert result.run_id == 901


def test_documented_dispatch_shape_rejects_an_untrusted_additive_url() -> None:
    request = _request()
    state = _claimed_dispatch_command(request)
    body = {
        "workflow_run_id": 901,
        "run_url": "https://api.github.com/repos/StephenBickel/carl-agent/actions/runs/901",
        "html_url": "https://github.com/StephenBickel/carl-agent/actions/runs/901",
        "logs_url": "https://attacker.invalid/logs",
    }
    transport = FakeTransport(
        deque([_empty_runs(), _json_response(200, json.dumps(body).encode())])
    )
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_dispatch_response_invalid"):
        gateway.dispatch_workflow(state.command.command_key, request)


def test_documented_additive_check_run_shape_is_accepted() -> None:
    request = RequiredChecksRequest.create(head_sha=_CANDIDATE_COMMIT)
    binding = required_checks_binding("StephenBickel/carl-agent", request)
    state = _claimed_effect_command(
        binding,
        authority="observer",
        operation="observe",
        claim_id="github-documented-checks-claim",
    )
    transport = FakeTransport(deque([_documented_checks_response()]))
    gateway = _gateway_with_state(state, transport)

    result = gateway.observe_required_checks(state.command.command_key, request)

    assert result.complete is True
    assert tuple(check.name for check in result.checks) == APPROVED_REQUIRED_CHECKS


def test_documented_check_run_shape_rejects_an_untrusted_api_url() -> None:
    request = RequiredChecksRequest.create(head_sha=_CANDIDATE_COMMIT)
    binding = required_checks_binding("StephenBickel/carl-agent", request)
    state = _claimed_effect_command(
        binding,
        authority="observer",
        operation="observe",
        claim_id="github-documented-checks-url-claim",
    )
    transport = FakeTransport(
        deque([_documented_checks_response(check_url_origin="https://attacker.invalid")])
    )
    gateway = _gateway_with_state(state, transport)

    with pytest.raises(GitHubCloudError, match="github_check_response_schema_invalid"):
        gateway.observe_required_checks(state.command.command_key, request)


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
    state = _claimed_dispatch_command(request)
    gateway = _gateway_with_state(
        state,
        transport,
        repository=request.repository,
        token="github_pat_must_not_leak",
    )

    gateway.dispatch_workflow(state.command.command_key, request)

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
    state = _claimed_dispatch_command(request)
    gateway = _gateway_with_state(
        state,
        transport,
        repository=request.repository,
        token="github_pat_must_not_leak",
    )

    with pytest.raises(GitHubCloudError, match=code) as raised:
        gateway.dispatch_workflow(state.command.command_key, request)

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
    gateway = _gateway_with_state(state, transport, repository=request.repository)

    with pytest.raises(GitHubCloudError, match="github_command_timestamp_invalid"):
        gateway.dispatch_workflow(state.command.command_key, request)

    assert transport.requests == []


def test_production_gateway_factory_is_credential_and_policy_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CARL_GITHUB_APP_INSTALLATION_TOKEN", raising=False)
    monkeypatch.setattr(
        github_cloud,
        "_load_protected_policy",
        lambda: pytest.fail("client must not load protected policy"),
    )
    monkeypatch.setattr(
        github_cloud,
        "_ProtectedGitHubTransport",
        lambda: pytest.fail("client must not construct HTTP transport"),
    )
    monkeypatch.setattr(
        github_cloud,
        "_ProtectedStateControllerClient",
        lambda: pytest.fail("client must not construct protected state"),
    )

    gateway = GitHubCloudGateway.from_protected_environment()

    assert "token" not in repr(gateway).lower()
    assert signature(GitHubCloudGateway.from_protected_environment).parameters == {}


def test_protected_service_policy_symlink_is_rejected(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_dir = tmp_path / "protected"
    policy_dir.mkdir(mode=0o700)
    target = tmp_path / "candidate-policy.json"
    target.write_bytes(
        b'{"api_origin":"https://api.github.com",'
        b'"dispatch_actor_login":"attacker[bot]",'
        b'"repository":"attacker/repository","schema_version":1,'
        b'"workflow_ref":"main"}'
    )
    (policy_dir / "github-cloud-policy.json").symlink_to(target)
    monkeypatch.setattr(github_cloud, "_PROTECTED_CONFIG_DIR", policy_dir)
    with pytest.raises(GitHubCloudError, match="github_protected_configuration_invalid"):
        github_cloud._load_protected_policy()


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
            "/repos/StephenBickel/carl-agent/pulls/81/ready_for_review",
            (),
            {},
            id="fake-rest-ready",
        ),
        pytest.param(
            "PUT",
            "/repos/StephenBickel/carl-agent/pulls/81/auto-merge",
            (),
            {"merge_method": "squash"},
            id="fake-rest-auto-merge",
        ),
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
        gateway._validate_endpoint(method=method, path=path, query=query, body=body)

    assert transport.requests == []


def test_production_factory_exposes_no_transport_clock_or_credential_callback(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy_dir = tmp_path / "protected"
    policy_dir.mkdir(mode=0o700)
    policy_path = policy_dir / "github-cloud-policy.json"
    policy_path.write_bytes(
        b'{"api_origin":"https://api.github.com",'
        b'"dispatch_actor_login":"carl-autonomy[bot]",'
        b'"repository":"StephenBickel/carl-agent","schema_version":1,'
        b'"workflow_ref":"main"}'
    )
    policy_path.chmod(0o600)
    monkeypatch.setattr(github_cloud, "_PROTECTED_CONFIG_DIR", policy_dir)
    monkeypatch.setenv("CARL_GITHUB_APP_INSTALLATION_TOKEN", "github_pat_protected_test")
    recorder = FakeTransport(deque())

    assert signature(GitHubCloudGateway.from_protected_environment).parameters == {}
    with pytest.raises(TypeError):
        GitHubCloudGateway.from_protected_environment(transport=recorder, clock=_clock)

    assert recorder.requests == []


def test_production_gateway_post_construction_substitution_has_no_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CARL_GITHUB_APP_INSTALLATION_TOKEN", raising=False)
    gateway = GitHubCloudGateway.from_protected_environment()
    recorder = FakeTransport(deque())

    for attribute, replacement in (
        ("_transport", recorder),
        ("_state_controller", FakeDurableEffectController(commands={})),
        ("_token", "attacker-token"),
        ("_repository", "attacker/repository"),
    ):
        with pytest.raises((AttributeError, TypeError)):
            setattr(gateway, attribute, replacement)

    assert recorder.requests == []
    assert "github_pat" not in repr(gateway)


def test_reflected_effect_authority_cannot_forge_a_raw_mutation() -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    state = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="reflective-forgery-claim",
    )
    reflected = vars(github_cloud)
    authorization_type = reflected.get("_EffectAuthorization")
    authorization_key = reflected.get("_PRIVATE_EFFECT_AUTHORIZATION_KEY")
    transport = FakeTransport(deque([_exact_ref()]))
    gateway = _gateway_with_state(state, transport)
    raw_request = getattr(gateway, "_request", None)
    if authorization_type is None or authorization_key is None or raw_request is None:
        assert not callable(raw_request)
        assert transport.requests == []
        return
    attempt = github_cloud.GitHubEffectAttempt(
        schema_version=1,
        effect_key=state.command.effect_key,
        command_key=state.command.command_key,
        claim_id=state.claim.claim_id,
        command_revision=state.revision,
        claim_expected_revision=state.claim.expected_revision,
        action=binding.action,
        endpoint_id=binding.endpoint_id,
        method=binding.method,
        payload_digest=binding.payload_digest,
        command_request_digest=state.command.request_digest,
        repository=binding.repository,
        target_identity=binding.target_identity,
        request_key=binding.request_key,
        attempt_key=binding.attempt_key,
        authority=binding.authority,
        operation=binding.operation,
        command_occurred_at=state.command.occurred_at,
        claim_expires_at=state.claim.expires_at,
        attempt_state="prepared",
        not_before="2026-08-21T12:00:30Z",
        observed_at=_NOW,
    )
    forged = authorization_type(
        state=state,
        binding=binding,
        attempt=attempt,
        may_mutate=True,
        _construction_key=authorization_key,
    )

    with pytest.raises(GitHubCloudError, match="github_effect_authorization_required"):
        raw_request(
            "POST",
            "/repos/StephenBickel/carl-agent/git/refs",
            body={"ref": "refs/heads/experimental/exp-001", "sha": _CANDIDATE_COMMIT},
            authorization=forged,
        )

    assert transport.requests == []


def test_reflected_observation_authority_cannot_forge_a_raw_get() -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    state = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="reflective-observation-forgery-claim",
    )
    reflected = vars(github_cloud)
    authorization_type = reflected.get("_ObservationAuthorization")
    authorization_key = reflected.get("_PRIVATE_OBSERVATION_AUTHORIZATION_KEY")
    transport = FakeTransport(deque([_exact_ref()]))
    gateway = _gateway_with_state(state, transport)
    raw_request = getattr(gateway, "_request", None)
    if authorization_type is None or authorization_key is None or raw_request is None:
        assert not callable(raw_request)
        assert transport.requests == []
        return
    forged = authorization_type(
        state=state,
        binding=binding,
        _construction_key=authorization_key,
    )

    with pytest.raises(GitHubCloudError, match="github_observation_authorization_required"):
        raw_request(
            "GET",
            "/repos/StephenBickel/carl-agent/git/ref/heads/experimental/exp-01",
            authorization=forged,
        )

    assert transport.requests == []


def test_forged_command_state_and_raw_private_request_cannot_reach_mutation_transport() -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    forged = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="forged-caller-claim",
    )
    transport = FakeTransport(
        deque(
            [
                _missing_ref(),
                _json_response(
                    201,
                    (
                        '{"object":{"sha":"'
                        + _CANDIDATE_COMMIT
                        + '","type":"commit"},"ref":"refs/heads/experimental/exp-01"}'
                    ).encode(),
                ),
            ]
        )
    )
    gateway = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=transport,
        clock=_clock,
    )

    with pytest.raises(GitHubCloudError, match="github_command_reference_invalid"):
        gateway.create_or_reconcile_experimental_branch(forged, request)
    assert not callable(getattr(gateway, "_request", None))

    assert transport.requests == []


def test_ambiguous_effect_fence_survives_gateway_restart_and_prevents_duplicate_post() -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    claimed = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="durable-effect-claim",
    )
    controller = FakeDurableEffectController(commands={claimed.command.command_key: claimed})
    first_transport = FakeTransport(
        deque(
            [
                _missing_ref(),
                GitHubTransportError("connection_lost", ambiguous=True),
                _missing_ref(),
            ]
        )
    )
    first = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=first_transport,
        clock=_clock,
        state_controller=controller,
    )

    uncertain = first.create_or_reconcile_experimental_branch(claimed.command.command_key, request)

    assert uncertain.status == "uncertain"
    assert [item.method for item in first_transport.requests] == ["GET", "POST", "GET"]
    assert controller.attempts[claimed.command.effect_key]["attempt_state"] == "uncertain"

    replay_transport = FakeTransport(deque([_missing_ref()]))
    replay = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=replay_transport,
        clock=_clock,
        state_controller=controller,
    )

    still_uncertain = replay.create_or_reconcile_experimental_branch(
        claimed.command.command_key, request
    )

    assert still_uncertain.status == "uncertain"
    assert [item.method for item in replay_transport.requests] == ["GET"]

    visible_transport = FakeTransport(deque([_exact_ref()]))
    visible = GitHubCloudGateway._for_testing(
        repository="StephenBickel/carl-agent",
        token="github_pat_test_only",
        transport=visible_transport,
        clock=_clock,
        state_controller=controller,
    )

    reconciled = visible.create_or_reconcile_experimental_branch(
        claimed.command.command_key, request
    )

    assert reconciled.status == "reconciled"
    assert [item.method for item in visible_transport.requests] == ["GET"]


@pytest.mark.parametrize("remote_visible", [False, True], ids=["still-absent", "delayed-visible"])
def test_uncertain_effect_reclaim_after_claim_expiry_is_observation_only(
    remote_visible: bool,
) -> None:
    request = _experimental_request()
    binding = experimental_branch_binding("StephenBickel/carl-agent", request)
    original = _claimed_effect_command(
        binding,
        authority="builder",
        operation="publish_experimental",
        claim_id="uncertain-original-claim",
    )
    controller = FakeDurableEffectController(commands={original.command.command_key: original})
    first_transport = FakeTransport(
        deque(
            [
                _missing_ref(),
                GitHubTransportError("connection_lost", ambiguous=True),
                _missing_ref(),
            ]
        )
    )
    first = _gateway_with_controller(controller, first_transport)
    uncertain = first.create_or_reconcile_experimental_branch(original.command.command_key, request)
    assert uncertain.status == "uncertain"
    original_attempt = dict(controller.attempts[original.command.effect_key])

    replacement_claim = CommandClaim(
        command_key=original.command.command_key,
        claim_id="uncertain-replacement-claim",
        authority="builder",
        expected_revision=10,
        claimed_at="2026-08-21T12:06:01Z",
        expires_at="2026-08-21T12:16:01Z",
    )
    replacement = replace(original, revision=11, claim=replacement_claim)
    controller.commands[original.command.command_key] = replacement
    replay_transport = FakeTransport(deque([_exact_ref() if remote_visible else _missing_ref()]))

    def replay_clock() -> datetime:
        return datetime(2026, 8, 21, 12, 6, 2, tzinfo=UTC)

    replay = _gateway_with_controller(
        controller,
        replay_transport,
        clock=replay_clock,
    ).create_or_reconcile_experimental_branch(replacement.command.command_key, request)

    assert replay.status == ("reconciled" if remote_visible else "uncertain")
    assert [item.method for item in replay_transport.requests] == ["GET"]
    persisted = controller.attempts[original.command.effect_key]
    assert persisted["command_occurred_at"] == original_attempt["command_occurred_at"]
    assert persisted["claim_id"] == replacement_claim.claim_id
    assert persisted["command_revision"] == replacement.revision
    assert persisted["claim_expected_revision"] == replacement_claim.expected_revision
    if not remote_visible:
        assert persisted["attempt_state"] == "uncertain"


def test_dispatch_ambiguity_fence_survives_restart_and_delayed_run_visibility() -> None:
    request = _request()
    claimed = _claimed_dispatch_command(request)
    controller = FakeDurableEffectController(commands={claimed.command.command_key: claimed})
    first_transport = FakeTransport(
        deque(
            [
                _empty_runs(),
                GitHubTransportError("connection_lost", ambiguous=True),
                _empty_runs(),
            ]
        )
    )

    first = _gateway_with_controller(
        controller, first_transport, repository=request.repository
    ).dispatch_workflow(claimed.command.command_key, request)

    assert first.status == "uncertain"
    assert [item.method for item in first_transport.requests] == ["GET", "POST", "GET"]
    assert controller.attempts[claimed.command.effect_key]["attempt_state"] == "uncertain"

    replay_transport = FakeTransport(deque([_empty_runs()]))
    replay = _gateway_with_controller(
        controller, replay_transport, repository=request.repository
    ).dispatch_workflow(claimed.command.command_key, request)

    assert replay.status == "uncertain"
    assert [item.method for item in replay_transport.requests] == ["GET"]

    visible_transport = FakeTransport(deque([_accepted_run(request)]))
    visible = _gateway_with_controller(
        controller, visible_transport, repository=request.repository
    ).dispatch_workflow(claimed.command.command_key, request)

    assert visible.status == "reconciled"
    assert visible.run_id == 901
    assert [item.method for item in visible_transport.requests] == ["GET"]


def test_pull_create_ambiguity_fence_survives_restart_and_delayed_visibility() -> None:
    request = _pull_request_create()
    binding = pull_request_create_binding("StephenBickel/carl-agent", request)
    claimed = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="durable-pr-create-claim",
    )
    controller = FakeDurableEffectController(commands={claimed.command.command_key: claimed})
    first_transport = FakeTransport(
        deque(
            [
                _exact_ref(),
                _pull_request_list(present=False),
                GitHubTransportError("connection_lost", ambiguous=True),
                _exact_ref(),
                _pull_request_list(present=False),
            ]
        )
    )

    with pytest.raises(GitHubCloudError, match="github_pull_create_uncertain"):
        _gateway_with_controller(controller, first_transport).create_or_reconcile_pull_request(
            claimed.command.command_key, request
        )
    assert [item.method for item in first_transport.requests] == [
        "GET",
        "GET",
        "POST",
        "GET",
        "GET",
    ]

    replay_transport = FakeTransport(deque([_exact_ref(), _pull_request_list(present=False)]))
    with pytest.raises(GitHubCloudError, match="github_pull_create_uncertain"):
        _gateway_with_controller(controller, replay_transport).create_or_reconcile_pull_request(
            claimed.command.command_key, request
        )
    assert [item.method for item in replay_transport.requests] == ["GET", "GET"]

    visible_transport = FakeTransport(deque([_exact_ref(), _pull_request_list(present=True)]))
    visible = _gateway_with_controller(
        controller, visible_transport
    ).create_or_reconcile_pull_request(claimed.command.command_key, request)

    assert visible.status == "reconciled"
    assert [item.method for item in visible_transport.requests] == ["GET", "GET"]


def test_pull_update_ambiguity_fence_survives_restart_and_delayed_visibility() -> None:
    request = _pull_update()
    binding = pull_request_update_binding("StephenBickel/carl-agent", request)
    claimed = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="durable-pr-update-claim",
    )
    controller = FakeDurableEffectController(commands={claimed.command.command_key: claimed})
    old = _json_response(200, _pull_request_body())
    first_transport = FakeTransport(
        deque([old, GitHubTransportError("connection_lost", ambiguous=True), old])
    )

    first = _gateway_with_controller(controller, first_transport).update_pull_request(
        claimed.command.command_key, request
    )

    assert first.status == "uncertain"
    assert [item.method for item in first_transport.requests] == ["GET", "PATCH", "GET"]

    replay_transport = FakeTransport(deque([old]))
    replay = _gateway_with_controller(controller, replay_transport).update_pull_request(
        claimed.command.command_key, request
    )

    assert replay.status == "uncertain"
    assert [item.method for item in replay_transport.requests] == ["GET"]

    updated = _json_response(200, _pull_request_body(title=request.title, body=request.body))
    visible_transport = FakeTransport(deque([updated]))
    visible = _gateway_with_controller(controller, visible_transport).update_pull_request(
        claimed.command.command_key, request
    )

    assert visible.status == "reconciled"
    assert [item.method for item in visible_transport.requests] == ["GET"]


def test_ready_ambiguity_fence_survives_restart_and_delayed_visibility() -> None:
    request = _ready_request()
    binding = pull_request_ready_binding("StephenBickel/carl-agent", request)
    claimed = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="durable-pr-ready-claim",
    )
    controller = FakeDurableEffectController(commands={claimed.command.command_key: claimed})
    draft = _json_response(200, _pull_request_body(draft=True))
    first_transport = FakeTransport(
        deque([draft, GitHubTransportError("connection_lost", ambiguous=True), draft])
    )

    first = _gateway_with_controller(controller, first_transport).mark_pull_request_ready(
        claimed.command.command_key, request
    )

    assert first.status == "uncertain"
    assert [item.method for item in first_transport.requests] == ["GET", "POST", "GET"]

    replay_transport = FakeTransport(deque([draft]))
    replay = _gateway_with_controller(controller, replay_transport).mark_pull_request_ready(
        claimed.command.command_key, request
    )

    assert replay.status == "uncertain"
    assert [item.method for item in replay_transport.requests] == ["GET"]

    ready_transport = FakeTransport(deque([_json_response(200, _pull_request_body(draft=False))]))
    visible = _gateway_with_controller(controller, ready_transport).mark_pull_request_ready(
        claimed.command.command_key, request
    )

    assert visible.status == "reconciled"
    assert [item.method for item in ready_transport.requests] == ["GET"]


def test_auto_merge_ambiguity_fence_survives_restart_and_delayed_visibility() -> None:
    request = _auto_merge_request()
    binding = pull_request_auto_merge_binding("StephenBickel/carl-agent", request)
    claimed = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="durable-pr-auto-merge-claim",
    )
    controller = FakeDurableEffectController(commands={claimed.command.command_key: claimed})
    disabled = _json_response(200, _pull_request_body(draft=False))
    first_transport = FakeTransport(
        deque([disabled, GitHubTransportError("connection_lost", ambiguous=True), disabled])
    )

    first = _gateway_with_controller(controller, first_transport).enable_pull_request_auto_merge(
        claimed.command.command_key, request
    )

    assert first.status == "uncertain"
    assert [item.method for item in first_transport.requests] == ["GET", "POST", "GET"]

    replay_transport = FakeTransport(deque([disabled]))
    replay = _gateway_with_controller(controller, replay_transport).enable_pull_request_auto_merge(
        claimed.command.command_key, request
    )

    assert replay.status == "uncertain"
    assert [item.method for item in replay_transport.requests] == ["GET"]

    enabled_transport = FakeTransport(
        deque([_json_response(200, _pull_request_body(draft=False, auto_merge=True))])
    )
    visible = _gateway_with_controller(
        controller, enabled_transport
    ).enable_pull_request_auto_merge(claimed.command.command_key, request)

    assert visible.status == "reconciled"
    assert [item.method for item in enabled_transport.requests] == ["GET"]


def test_revert_branch_ambiguity_fence_survives_restart_and_delayed_visibility() -> None:
    request = _revert_branch_request()
    binding = revert_branch_binding("StephenBickel/carl-agent", request)
    claimed = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="durable-revert-branch-claim",
    )
    controller = FakeDurableEffectController(commands={claimed.command.command_key: claimed})
    first_transport = FakeTransport(
        deque(
            [
                *_valid_revert_topology(),
                _missing_ref(),
                GitHubTransportError("connection_lost", ambiguous=True),
                _missing_ref(),
            ]
        )
    )

    first = _gateway_with_controller(controller, first_transport).create_or_reconcile_revert_branch(
        claimed.command.command_key, request
    )

    assert first.status == "uncertain"
    assert [item.method for item in first_transport.requests] == [
        "GET",
        "GET",
        "GET",
        "GET",
        "POST",
        "GET",
    ]

    replay_transport = FakeTransport(deque([*_valid_revert_topology(), _missing_ref()]))
    replay = _gateway_with_controller(
        controller, replay_transport
    ).create_or_reconcile_revert_branch(claimed.command.command_key, request)

    assert replay.status == "uncertain"
    assert [item.method for item in replay_transport.requests] == [
        "GET",
        "GET",
        "GET",
        "GET",
    ]

    visible_transport = FakeTransport(deque([*_valid_revert_topology(), _revert_ref()]))
    visible = _gateway_with_controller(
        controller, visible_transport
    ).create_or_reconcile_revert_branch(claimed.command.command_key, request)

    assert visible.status == "reconciled"
    assert [item.method for item in visible_transport.requests] == [
        "GET",
        "GET",
        "GET",
        "GET",
    ]


def test_revert_pull_ambiguity_fence_survives_restart_and_delayed_visibility() -> None:
    request = _revert_pull_request()
    binding = revert_pull_request_binding("StephenBickel/carl-agent", request)
    claimed = _claimed_effect_command(
        binding,
        authority="promoter",
        operation="github_effect",
        claim_id="durable-revert-pr-claim",
    )
    controller = FakeDurableEffectController(commands={claimed.command.command_key: claimed})
    missing = _json_response(200, b"[]")
    first_transport = FakeTransport(
        deque(
            [
                _revert_ref(),
                missing,
                GitHubTransportError("connection_lost", ambiguous=True),
                _revert_ref(),
                missing,
            ]
        )
    )

    with pytest.raises(GitHubCloudError, match="github_revert_pull_create_uncertain"):
        _gateway_with_controller(
            controller, first_transport
        ).create_or_reconcile_revert_pull_request(claimed.command.command_key, request)
    assert [item.method for item in first_transport.requests] == [
        "GET",
        "GET",
        "POST",
        "GET",
        "GET",
    ]

    replay_transport = FakeTransport(deque([_revert_ref(), missing]))
    with pytest.raises(GitHubCloudError, match="github_revert_pull_create_uncertain"):
        _gateway_with_controller(
            controller, replay_transport
        ).create_or_reconcile_revert_pull_request(claimed.command.command_key, request)
    assert [item.method for item in replay_transport.requests] == ["GET", "GET"]

    visible_transport = FakeTransport(
        deque(
            [
                _revert_ref(),
                _json_response(200, b"[" + _revert_pull_body() + b"]"),
            ]
        )
    )
    visible = _gateway_with_controller(
        controller, visible_transport
    ).create_or_reconcile_revert_pull_request(claimed.command.command_key, request)

    assert visible.status == "reconciled"
    assert [item.method for item in visible_transport.requests] == ["GET", "GET"]
