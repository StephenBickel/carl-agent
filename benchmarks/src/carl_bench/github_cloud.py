"""Closed, replay-safe GitHub effects for the autonomous cloud controller."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_execution import CloudRunRequest
from carl_bench.cloud_state import CommandState
from carl_bench.github_effect_client import GitHubEffectSocketClient
from carl_bench.github_effect_ipc import (
    REQUEST_DOMAIN,
    GitHubEffectOperation,
    GitHubEffectRequest,
    GitHubEffectResponse,
)
from carl_bench.github_promotion import APPROVED_REQUIRED_CHECKS

_API_ORIGIN = "https://api.github.com"
_PROTECTED_CONFIG_DIR = Path("/etc/carl")
_PROTECTED_CONFIG_NAME = "github-cloud-policy.json"
_PROTECTED_TOKEN_ENV = "CARL_GITHUB_APP_INSTALLATION_TOKEN"
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_COMMAND_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
_WORKFLOW_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_ACTOR_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}[A-Za-z0-9])?(?:\[bot\])?$")
_DEFAULT_WORKFLOW_REF = "main"
_DEFAULT_DISPATCH_ACTOR_LOGIN = "carl-autonomy[bot]"
_MAX_RESPONSE_BYTES = 262_144
_MAX_PAGES = 5
_EFFECT_RECONCILIATION_DELAY = timedelta(seconds=30)
_GRAPHQL_NODE_ID_RE = re.compile(r"^[A-Za-z0-9_=-]{1,256}$")
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


class GitHubCloudError(ValueError):
    """A stable public failure that never includes credentials or response contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class GitHubTransportError(RuntimeError):
    """A redacted transport failure; ambiguous means the effect may have happened."""

    def __init__(self, code: str, *, ambiguous: bool = False) -> None:
        self.code = code
        self.ambiguous = ambiguous
        super().__init__(code)


class _GitHubRateLimited(RuntimeError):
    def __init__(self, retry_not_before: str) -> None:
        self.retry_not_before = retry_not_before
        super().__init__("github_rate_limited")


@dataclass(frozen=True, slots=True)
class GitHubHttpRequest:
    method: Literal["GET", "POST", "PATCH", "PUT"]
    origin: str
    path: str
    query: tuple[tuple[str, str], ...]
    body: bytes | None
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    follow_redirects: bool = False
    max_response_bytes: int = _MAX_RESPONSE_BYTES

    @property
    def json_body(self) -> dict[str, Any] | None:
        if self.body is None:
            return None
        value = json.loads(self.body)
        if type(value) is not dict:  # pragma: no cover - requests are built internally
            raise GitHubCloudError("github_request_invalid")
        return value


@dataclass(frozen=True, slots=True)
class GitHubHttpResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes


class GitHubHttpTransport(Protocol):
    def send(self, request: GitHubHttpRequest) -> GitHubHttpResponse: ...


class GitHubEffectStateController(Protocol):
    """Protected durable boundary used by the credential-bearing GitHub controller."""

    def resolve_claimed_command(
        self, command_key: str, *, authority: str, observed_at: datetime
    ) -> CommandState: ...

    def prepare_effect_attempt(self, attempt: GitHubEffectAttempt) -> bool: ...

    def mark_effect_uncertain(
        self, effect_key: str, *, authority: str, not_before: str, observed_at: str
    ) -> None: ...

    def mark_effect_retry_scheduled(
        self,
        effect_key: str,
        *,
        authority: str,
        retry_not_before: str,
        observed_at: str,
    ) -> None: ...

    def mark_effect_completed(
        self, effect_key: str, *, authority: str, result_digest: str, observed_at: str
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class _ProtectedGitHubPolicy:
    repository: str
    workflow_ref: str
    dispatch_actor_login: str


@dataclass(frozen=True, slots=True)
class GitHubCommandBinding:
    action: str
    repository: str
    endpoint_id: str
    method: str
    payload_digest: str
    target_identity: str
    request_key: str
    attempt_key: str
    command_key: str
    request_digest: str
    authority: str
    operation: str


@dataclass(frozen=True, slots=True)
class _BoundObservation:
    state: CommandState
    binding: GitHubCommandBinding


_OBSERVATION_ENDPOINTS_BY_ACTION = {
    "auto-merge": frozenset({"get_pull_request"}),
    "create_experimental_branch": frozenset({"get_git_ref"}),
    "create_pull_request": frozenset({"get_git_ref", "list_pull_requests"}),
    "create_revert_branch": frozenset({"get_git_commit", "get_git_ref"}),
    "create_revert_pull_request": frozenset({"get_git_ref", "list_pull_requests"}),
    "dispatch_workflow": frozenset({"list_workflow_runs"}),
    "observe_required_checks": frozenset({"list_check_runs_for_ref"}),
    "ready": frozenset({"get_pull_request"}),
    "update": frozenset({"get_pull_request"}),
}


@dataclass(frozen=True, slots=True)
class GitHubEffectAttempt:
    """Exact durable fence persisted before one consequential GitHub request."""

    schema_version: int
    effect_key: str
    command_key: str
    claim_id: str
    command_revision: int
    claim_expected_revision: int
    action: str
    endpoint_id: str
    method: str
    payload_digest: str
    command_request_digest: str
    repository: str
    target_identity: str
    request_key: str
    attempt_key: str
    authority: str
    operation: str
    command_occurred_at: str
    claim_expires_at: str
    attempt_state: Literal["prepared", "retry_scheduled", "uncertain", "completed"]
    not_before: str
    observed_at: str
    result_digest: str | None = None

    def __post_init__(self) -> None:
        if (
            self.schema_version != 1
            or not isinstance(self.effect_key, str)
            or not self.effect_key.startswith("cloud-effect-")
            or not isinstance(self.command_key, str)
            or not isinstance(self.claim_id, str)
            or isinstance(self.command_revision, bool)
            or not isinstance(self.command_revision, int)
            or self.command_revision < 0
            or isinstance(self.claim_expected_revision, bool)
            or not isinstance(self.claim_expected_revision, int)
            or self.claim_expected_revision < 0
            or self.attempt_state not in {"prepared", "retry_scheduled", "uncertain", "completed"}
            or self.method not in {"POST", "PATCH", "PUT"}
            or not isinstance(self.payload_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.payload_digest) is None
            or not isinstance(self.command_request_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", self.command_request_digest) is None
            or not isinstance(self.repository, str)
            or _REPOSITORY_RE.fullmatch(self.repository) is None
        ):
            raise GitHubCloudError("github_effect_fence_invalid")
        _utc(self.command_occurred_at, "github_effect_fence_invalid")
        _utc(self.claim_expires_at, "github_effect_fence_invalid")
        observed = _utc(self.observed_at, "github_effect_fence_invalid")
        not_before = _utc(self.not_before, "github_effect_fence_invalid")
        if not_before < observed:
            raise GitHubCloudError("github_effect_fence_invalid")
        if self.attempt_state == "completed":
            if (
                not isinstance(self.result_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", self.result_digest) is None
            ):
                raise GitHubCloudError("github_effect_fence_invalid")
        elif self.result_digest is not None:
            raise GitHubCloudError("github_effect_fence_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in sorted(self.__dataclass_fields__)}


@dataclass(frozen=True, slots=True)
class _BoundEffect:
    state: CommandState
    binding: GitHubCommandBinding
    attempt: GitHubEffectAttempt
    may_mutate: bool


@dataclass(frozen=True, slots=True)
class WorkflowDispatchSnapshot:
    status: Literal["dispatched", "reconciled", "uncertain"]
    repository: str
    workflow_file: str
    workflow_revision: str
    request_key: str
    attempt_key: str
    effect_key: str
    command_occurred_at: str
    observed_at: str
    run_id: int | None = None
    head_sha: str | None = None


@dataclass(frozen=True, slots=True)
class GitHubRetryDecision:
    status: Literal["retry_scheduled"]
    reason: Literal["github_rate_limited"]
    request_key: str
    attempt_key: str
    effect_key: str
    command_occurred_at: str
    retry_not_before: str
    attempt: int
    max_attempts: int


@dataclass(frozen=True, slots=True)
class ExperimentalBranchRequest:
    experiment_id: str
    branch: str
    candidate_commit: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.experiment_id, str)
            or _IDENTIFIER_RE.fullmatch(self.experiment_id) is None
            or self.branch != f"experimental/{self.experiment_id}"
            or not isinstance(self.candidate_commit, str)
            or _OBJECT_RE.fullmatch(self.candidate_commit) is None
        ):
            raise GitHubCloudError("github_experimental_request_invalid")

    @classmethod
    def create(cls, *, experiment_id: str, candidate_commit: str) -> ExperimentalBranchRequest:
        return cls(
            experiment_id=experiment_id,
            branch=f"experimental/{experiment_id}",
            candidate_commit=candidate_commit,
        )


@dataclass(frozen=True, slots=True)
class GitReferenceSnapshot:
    status: Literal["created", "reconciled", "uncertain"]
    repository: str
    ref: str
    commit_sha: str
    request_key: str
    effect_key: str
    command_occurred_at: str
    observed_at: str


@dataclass(frozen=True, slots=True)
class _GitCommitObservation:
    sha: str
    tree_sha: str
    parents: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PullRequestCreateRequest:
    promotion_id: str
    base_branch: str
    head_branch: str
    head_sha: str
    title: str
    body: str
    draft: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.promotion_id, str)
            or _IDENTIFIER_RE.fullmatch(self.promotion_id) is None
            or self.base_branch != "main"
            or not isinstance(self.head_branch, str)
            or re.fullmatch(r"experimental/[A-Za-z0-9][A-Za-z0-9._-]{0,95}", self.head_branch)
            is None
            or not isinstance(self.head_sha, str)
            or _OBJECT_RE.fullmatch(self.head_sha) is None
            or not isinstance(self.title, str)
            or not 1 <= len(self.title.encode()) <= 256
            or "\x00" in self.title
            or not isinstance(self.body, str)
            or not 1 <= len(self.body.encode()) <= 8_192
            or "\x00" in self.body
            or self.draft is not True
        ):
            raise GitHubCloudError("github_pull_request_invalid")

    @classmethod
    def create(
        cls,
        *,
        promotion_id: str,
        head_branch: str,
        head_sha: str,
        title: str,
        body: str,
    ) -> PullRequestCreateRequest:
        return cls(
            promotion_id=promotion_id,
            base_branch="main",
            head_branch=head_branch,
            head_sha=head_sha,
            title=title,
            body=body,
            draft=True,
        )


@dataclass(frozen=True, slots=True)
class PullRequestEffectSnapshot:
    status: Literal["created", "updated", "reconciled", "uncertain"]
    repository: str
    number: int
    url: str
    state: Literal["open", "closed"]
    draft: bool
    base_branch: str
    head_branch: str
    head_sha: str
    title: str
    body: str
    auto_merge_enabled: bool
    request_key: str
    effect_key: str
    command_occurred_at: str
    observed_at: str


@dataclass(frozen=True, slots=True)
class _PullRequestObservation:
    node_id: str
    number: int
    url: str
    state: Literal["open", "closed"]
    draft: bool
    base_branch: str
    head_branch: str
    head_sha: str
    title: str
    body: str
    auto_merge_enabled: bool


def _validate_pull_target(
    *, promotion_id: object, number: object, head_branch: object, head_sha: object
) -> None:
    if (
        not isinstance(promotion_id, str)
        or _IDENTIFIER_RE.fullmatch(promotion_id) is None
        or isinstance(number, bool)
        or not isinstance(number, int)
        or number <= 0
        or not isinstance(head_branch, str)
        or re.fullmatch(r"experimental/[A-Za-z0-9][A-Za-z0-9._-]{0,95}", head_branch) is None
        or not isinstance(head_sha, str)
        or _OBJECT_RE.fullmatch(head_sha) is None
    ):
        raise GitHubCloudError("github_pull_request_invalid")


@dataclass(frozen=True, slots=True)
class PullRequestUpdateRequest:
    promotion_id: str
    number: int
    base_branch: str
    head_branch: str
    head_sha: str
    title: str
    body: str

    def __post_init__(self) -> None:
        _validate_pull_target(
            promotion_id=self.promotion_id,
            number=self.number,
            head_branch=self.head_branch,
            head_sha=self.head_sha,
        )
        if (
            self.base_branch != "main"
            or not isinstance(self.title, str)
            or not 1 <= len(self.title.encode()) <= 256
            or "\x00" in self.title
            or not isinstance(self.body, str)
            or not 1 <= len(self.body.encode()) <= 8_192
            or "\x00" in self.body
        ):
            raise GitHubCloudError("github_pull_request_invalid")

    @classmethod
    def create(
        cls,
        *,
        promotion_id: str,
        number: int,
        head_branch: str,
        head_sha: str,
        title: str,
        body: str,
    ) -> PullRequestUpdateRequest:
        return cls(promotion_id, number, "main", head_branch, head_sha, title, body)


@dataclass(frozen=True, slots=True)
class PullRequestReadyRequest:
    promotion_id: str
    number: int
    base_branch: str
    head_branch: str
    head_sha: str

    def __post_init__(self) -> None:
        _validate_pull_target(
            promotion_id=self.promotion_id,
            number=self.number,
            head_branch=self.head_branch,
            head_sha=self.head_sha,
        )
        if self.base_branch != "main":
            raise GitHubCloudError("github_pull_request_invalid")

    @classmethod
    def create(
        cls,
        *,
        promotion_id: str,
        number: int,
        head_branch: str,
        head_sha: str,
    ) -> PullRequestReadyRequest:
        return cls(promotion_id, number, "main", head_branch, head_sha)


@dataclass(frozen=True, slots=True)
class PullRequestAutoMergeRequest:
    promotion_id: str
    number: int
    base_branch: str
    head_branch: str
    head_sha: str
    merge_method: Literal["squash"]

    def __post_init__(self) -> None:
        _validate_pull_target(
            promotion_id=self.promotion_id,
            number=self.number,
            head_branch=self.head_branch,
            head_sha=self.head_sha,
        )
        if self.base_branch != "main" or self.merge_method != "squash":
            raise GitHubCloudError("github_pull_request_invalid")

    @classmethod
    def create(
        cls,
        *,
        promotion_id: str,
        number: int,
        head_branch: str,
        head_sha: str,
    ) -> PullRequestAutoMergeRequest:
        return cls(promotion_id, number, "main", head_branch, head_sha, "squash")


@dataclass(frozen=True, slots=True)
class RequiredChecksRequest:
    head_sha: str
    required_checks: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.head_sha, str)
            or _OBJECT_RE.fullmatch(self.head_sha) is None
            or self.required_checks != APPROVED_REQUIRED_CHECKS
        ):
            raise GitHubCloudError("github_required_checks_request_invalid")

    @classmethod
    def create(cls, *, head_sha: str) -> RequiredChecksRequest:
        return cls(head_sha=head_sha, required_checks=APPROVED_REQUIRED_CHECKS)


@dataclass(frozen=True, slots=True)
class RequiredCheckObservation:
    name: str
    status: str
    conclusion: str | None
    app_id: int


@dataclass(frozen=True, slots=True)
class RequiredChecksSnapshot:
    repository: str
    head_sha: str
    checks: tuple[RequiredCheckObservation, ...]
    complete: bool
    request_key: str
    effect_key: str
    command_occurred_at: str
    observed_at: str


@dataclass(frozen=True, slots=True)
class RevertBranchRequest:
    promotion_id: str
    branch: str
    promotion_merge_commit: str
    revert_candidate_commit: str
    expected_restored_tree: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.promotion_id, str)
            or _IDENTIFIER_RE.fullmatch(self.promotion_id) is None
            or self.branch != f"revert/{self.promotion_id}"
            or any(
                not isinstance(value, str) or _OBJECT_RE.fullmatch(value) is None
                for value in (
                    self.promotion_merge_commit,
                    self.revert_candidate_commit,
                    self.expected_restored_tree,
                )
            )
        ):
            raise GitHubCloudError("github_revert_request_invalid")

    @classmethod
    def create(
        cls,
        *,
        promotion_id: str,
        promotion_merge_commit: str,
        revert_candidate_commit: str,
        expected_restored_tree: str,
    ) -> RevertBranchRequest:
        return cls(
            promotion_id=promotion_id,
            branch=f"revert/{promotion_id}",
            promotion_merge_commit=promotion_merge_commit,
            revert_candidate_commit=revert_candidate_commit,
            expected_restored_tree=expected_restored_tree,
        )


@dataclass(frozen=True, slots=True)
class RevertPullRequestRequest:
    promotion_id: str
    base_branch: str
    head_branch: str
    promotion_merge_commit: str
    revert_candidate_commit: str
    expected_restored_tree: str
    title: str
    body: str
    draft: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.promotion_id, str)
            or _IDENTIFIER_RE.fullmatch(self.promotion_id) is None
            or self.base_branch != "main"
            or self.head_branch != f"revert/{self.promotion_id}"
            or any(
                not isinstance(value, str) or _OBJECT_RE.fullmatch(value) is None
                for value in (
                    self.promotion_merge_commit,
                    self.revert_candidate_commit,
                    self.expected_restored_tree,
                )
            )
            or not isinstance(self.title, str)
            or not 1 <= len(self.title.encode()) <= 256
            or not isinstance(self.body, str)
            or not 1 <= len(self.body.encode()) <= 8_192
            or "\x00" in self.title
            or "\x00" in self.body
            or self.draft is not False
        ):
            raise GitHubCloudError("github_revert_request_invalid")

    @classmethod
    def create(
        cls,
        *,
        promotion_id: str,
        promotion_merge_commit: str,
        revert_candidate_commit: str,
        expected_restored_tree: str,
        title: str,
        body: str,
    ) -> RevertPullRequestRequest:
        return cls(
            promotion_id=promotion_id,
            base_branch="main",
            head_branch=f"revert/{promotion_id}",
            promotion_merge_commit=promotion_merge_commit,
            revert_candidate_commit=revert_candidate_commit,
            expected_restored_tree=expected_restored_tree,
            title=title,
            body=body,
            draft=False,
        )

    @property
    def head_sha(self) -> str:
        return self.revert_candidate_commit


def _dispatch_payload(
    request: CloudRunRequest,
    attempt: int,
    *,
    workflow_ref: str,
) -> dict[str, Any]:
    return {
        "inputs": {
            "attempt_key": request.attempt_key(attempt),
            "candidate_commit": request.candidate_commit,
            "experiment_digest": request.experiment_digest,
            "metric_pack_digest": request.metric_pack_digest,
            "parent_commit": request.parent_commit,
            "policy_digest": request.policy_digest,
            "request_digest": request.request_digest,
            "task_set_digest": request.task_set_digest,
            "workflow_revision": request.workflow_revision,
            "workflow_blob_digest": request.workflow_blob_digest,
        },
        "ref": workflow_ref,
        "return_run_details": True,
    }


def workflow_dispatch_binding(
    request: CloudRunRequest,
    *,
    attempt: int,
    workflow_ref: str = _DEFAULT_WORKFLOW_REF,
    dispatch_actor_login: str = _DEFAULT_DISPATCH_ACTOR_LOGIN,
) -> GitHubCommandBinding:
    """Build the exact descriptor a coordinator must persist before dispatch."""
    if not isinstance(request, CloudRunRequest):
        raise GitHubCloudError("github_dispatch_request_invalid")
    if (
        not _workflow_ref_is_valid(workflow_ref)
        or not isinstance(dispatch_actor_login, str)
        or _ACTOR_LOGIN_RE.fullmatch(dispatch_actor_login) is None
    ):
        raise GitHubCloudError("github_dispatch_policy_invalid")
    attempt_key = request.attempt_key(attempt)
    payload_digest = hashlib.sha256(
        canonical_json_bytes(_dispatch_payload(request, attempt, workflow_ref=workflow_ref))
    ).hexdigest()
    descriptor = {
        "action": "dispatch_workflow",
        "attempt_key": attempt_key,
        "endpoint_id": "workflow_dispatch",
        "method": "POST",
        "payload_digest": payload_digest,
        "dispatch_actor_login": dispatch_actor_login,
        "repository": request.repository,
        "request_key": request.dispatch_key,
        "schema_version": 1,
        "target_identity": (
            f"{request.workflow_file}@{request.workflow_revision}"
            f":ref-{workflow_ref}:actor-{dispatch_actor_login}"
        ),
    }
    request_digest = hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()
    return GitHubCommandBinding(
        action="dispatch_workflow",
        repository=request.repository,
        endpoint_id="workflow_dispatch",
        method="POST",
        payload_digest=payload_digest,
        target_identity=descriptor["target_identity"],
        request_key=request.dispatch_key,
        attempt_key=attempt_key,
        command_key=attempt_key,
        request_digest=request_digest,
        authority="coordinator",
        operation="dispatch",
    )


def experimental_branch_binding(
    repository: str, request: ExperimentalBranchRequest
) -> GitHubCommandBinding:
    """Build the exact descriptor persisted before immutable experimental creation."""
    if not isinstance(repository, str) or _REPOSITORY_RE.fullmatch(repository) is None:
        raise GitHubCloudError("github_repository_invalid")
    if not isinstance(request, ExperimentalBranchRequest):
        raise GitHubCloudError("github_experimental_request_invalid")
    payload = {"ref": f"refs/heads/{request.branch}", "sha": request.candidate_commit}
    payload_digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    request_key = f"github-experimental-{request.experiment_id}"
    descriptor = {
        "action": "create_experimental_branch",
        "endpoint_id": "create_git_ref",
        "method": "POST",
        "payload_digest": payload_digest,
        "repository": repository,
        "request_key": request_key,
        "schema_version": 1,
        "target_identity": f"refs/heads/{request.branch}@{request.candidate_commit}",
    }
    request_digest = hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()
    return GitHubCommandBinding(
        action="create_experimental_branch",
        repository=repository,
        endpoint_id="create_git_ref",
        method="POST",
        payload_digest=payload_digest,
        target_identity=descriptor["target_identity"],
        request_key=request_key,
        attempt_key=f"{request_key}-attempt-1",
        command_key=request_key,
        request_digest=request_digest,
        authority="builder",
        operation="publish_experimental",
    )


def pull_request_create_binding(
    repository: str, request: PullRequestCreateRequest
) -> GitHubCommandBinding:
    if not isinstance(repository, str) or _REPOSITORY_RE.fullmatch(repository) is None:
        raise GitHubCloudError("github_repository_invalid")
    if not isinstance(request, PullRequestCreateRequest):
        raise GitHubCloudError("github_pull_request_invalid")
    payload = {
        "base": request.base_branch,
        "body": request.body,
        "draft": request.draft,
        "head": request.head_branch,
        "title": request.title,
    }
    payload_digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    request_key = f"github-pr-{request.promotion_id}"
    descriptor = {
        "action": "create_pull_request",
        "endpoint_id": "create_pull_request",
        "method": "POST",
        "payload_digest": payload_digest,
        "repository": repository,
        "request_key": request_key,
        "schema_version": 1,
        "target_identity": (f"{request.base_branch}<-{request.head_branch}@{request.head_sha}"),
    }
    request_digest = hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()
    return GitHubCommandBinding(
        action="create_pull_request",
        repository=repository,
        endpoint_id="create_pull_request",
        method="POST",
        payload_digest=payload_digest,
        target_identity=descriptor["target_identity"],
        request_key=request_key,
        attempt_key=f"{request_key}-attempt-1",
        command_key=request_key,
        request_digest=request_digest,
        authority="promoter",
        operation="github_effect",
    )


def _pull_request_effect_binding(
    *,
    repository: str,
    promotion_id: str,
    number: int,
    head_branch: str,
    head_sha: str,
    action: str,
    endpoint_id: str,
    method: str,
    payload: dict[str, Any],
) -> GitHubCommandBinding:
    if not isinstance(repository, str) or _REPOSITORY_RE.fullmatch(repository) is None:
        raise GitHubCloudError("github_repository_invalid")
    payload_digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    request_key = f"github-pr-{action}-{promotion_id}-{number}"
    target = f"pull/{number}:main<-{head_branch}@{head_sha}"
    descriptor = {
        "action": action,
        "endpoint_id": endpoint_id,
        "method": method,
        "payload_digest": payload_digest,
        "repository": repository,
        "request_key": request_key,
        "schema_version": 1,
        "target_identity": target,
    }
    request_digest = hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()
    return GitHubCommandBinding(
        action=action,
        repository=repository,
        endpoint_id=endpoint_id,
        method=method,
        payload_digest=payload_digest,
        target_identity=target,
        request_key=request_key,
        attempt_key=f"{request_key}-attempt-1",
        command_key=request_key,
        request_digest=request_digest,
        authority="promoter",
        operation="github_effect",
    )


def pull_request_update_binding(
    repository: str, request: PullRequestUpdateRequest
) -> GitHubCommandBinding:
    if not isinstance(request, PullRequestUpdateRequest):
        raise GitHubCloudError("github_pull_request_invalid")
    return _pull_request_effect_binding(
        repository=repository,
        promotion_id=request.promotion_id,
        number=request.number,
        head_branch=request.head_branch,
        head_sha=request.head_sha,
        action="update",
        endpoint_id="update_pull_request",
        method="PATCH",
        payload={"body": request.body, "title": request.title},
    )


def pull_request_ready_binding(
    repository: str, request: PullRequestReadyRequest
) -> GitHubCommandBinding:
    if not isinstance(request, PullRequestReadyRequest):
        raise GitHubCloudError("github_pull_request_invalid")
    return _pull_request_effect_binding(
        repository=repository,
        promotion_id=request.promotion_id,
        number=request.number,
        head_branch=request.head_branch,
        head_sha=request.head_sha,
        action="ready",
        endpoint_id="mark_pull_request_ready",
        method="POST",
        payload={},
    )


def pull_request_auto_merge_binding(
    repository: str, request: PullRequestAutoMergeRequest
) -> GitHubCommandBinding:
    if not isinstance(request, PullRequestAutoMergeRequest):
        raise GitHubCloudError("github_pull_request_invalid")
    return _pull_request_effect_binding(
        repository=repository,
        promotion_id=request.promotion_id,
        number=request.number,
        head_branch=request.head_branch,
        head_sha=request.head_sha,
        action="auto-merge",
        endpoint_id="enable_pull_request_auto_merge",
        method="POST",
        payload={"merge_method": request.merge_method},
    )


def required_checks_binding(
    repository: str, request: RequiredChecksRequest
) -> GitHubCommandBinding:
    if not isinstance(repository, str) or _REPOSITORY_RE.fullmatch(repository) is None:
        raise GitHubCloudError("github_repository_invalid")
    if not isinstance(request, RequiredChecksRequest):
        raise GitHubCloudError("github_required_checks_request_invalid")
    payload: dict[str, Any] = {}
    payload_digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    request_key = f"github-checks-{request.head_sha}"
    descriptor = {
        "action": "observe_required_checks",
        "endpoint_id": "list_check_runs_for_ref",
        "method": "GET",
        "payload_digest": payload_digest,
        "repository": repository,
        "request_key": request_key,
        "schema_version": 1,
        "target_identity": f"commit/{request.head_sha}",
    }
    request_digest = hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()
    return GitHubCommandBinding(
        action="observe_required_checks",
        repository=repository,
        endpoint_id="list_check_runs_for_ref",
        method="GET",
        payload_digest=payload_digest,
        target_identity=descriptor["target_identity"],
        request_key=request_key,
        attempt_key=f"{request_key}-attempt-1",
        command_key=request_key,
        request_digest=request_digest,
        authority="observer",
        operation="observe",
    )


def revert_branch_binding(repository: str, request: RevertBranchRequest) -> GitHubCommandBinding:
    if not isinstance(repository, str) or _REPOSITORY_RE.fullmatch(repository) is None:
        raise GitHubCloudError("github_repository_invalid")
    if not isinstance(request, RevertBranchRequest):
        raise GitHubCloudError("github_revert_request_invalid")
    ref = f"refs/heads/{request.branch}"
    payload = {"ref": ref, "sha": request.revert_candidate_commit}
    payload_digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    request_key = f"github-revert-branch-{request.promotion_id}"
    descriptor = {
        "action": "create_revert_branch",
        "endpoint_id": "create_git_ref",
        "method": "POST",
        "payload_digest": payload_digest,
        "promotion_merge_commit": request.promotion_merge_commit,
        "repository": repository,
        "request_key": request_key,
        "restored_tree": request.expected_restored_tree,
        "schema_version": 1,
        "target_identity": f"{ref}@{request.revert_candidate_commit}",
    }
    digest = hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()
    return GitHubCommandBinding(
        action="create_revert_branch",
        repository=repository,
        endpoint_id="create_git_ref",
        method="POST",
        payload_digest=payload_digest,
        target_identity=descriptor["target_identity"],
        request_key=request_key,
        attempt_key=f"{request_key}-attempt-1",
        command_key=request_key,
        request_digest=digest,
        authority="promoter",
        operation="github_effect",
    )


def revert_pull_request_binding(
    repository: str, request: RevertPullRequestRequest
) -> GitHubCommandBinding:
    if not isinstance(repository, str) or _REPOSITORY_RE.fullmatch(repository) is None:
        raise GitHubCloudError("github_repository_invalid")
    if not isinstance(request, RevertPullRequestRequest):
        raise GitHubCloudError("github_revert_request_invalid")
    payload = {
        "base": request.base_branch,
        "body": request.body,
        "draft": request.draft,
        "head": request.head_branch,
        "title": request.title,
    }
    payload_digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    request_key = f"github-revert-pr-{request.promotion_id}"
    target = (
        f"main<-{request.head_branch}@{request.revert_candidate_commit}:"
        f"restore-{request.expected_restored_tree}:revert-{request.promotion_merge_commit}"
    )
    descriptor = {
        "action": "create_revert_pull_request",
        "endpoint_id": "create_pull_request",
        "method": "POST",
        "payload_digest": payload_digest,
        "repository": repository,
        "request_key": request_key,
        "schema_version": 1,
        "target_identity": target,
    }
    digest = hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()
    return GitHubCommandBinding(
        action="create_revert_pull_request",
        repository=repository,
        endpoint_id="create_pull_request",
        method="POST",
        payload_digest=payload_digest,
        target_identity=target,
        request_key=request_key,
        attempt_key=f"{request_key}-attempt-1",
        command_key=request_key,
        request_digest=digest,
        authority="promoter",
        operation="github_effect",
    )


def _utc(value: str, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise GitHubCloudError(code)
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise GitHubCloudError(code) from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise GitHubCloudError(code)
    return parsed


def _workflow_ref_is_valid(value: object) -> bool:
    return (
        isinstance(value, str)
        and _WORKFLOW_REF_RE.fullmatch(value) is not None
        and _OBJECT_RE.fullmatch(value) is None
        and not value.startswith((".", "/", "refs/"))
        and not value.endswith((".", "/", ".lock"))
        and ".." not in value
        and "//" not in value
        and "@{" not in value
        and "\\" not in value
    )


def _response_headers(response: GitHubHttpResponse) -> dict[str, str]:
    if not isinstance(response, GitHubHttpResponse):
        raise GitHubCloudError("github_response_invalid")
    headers: dict[str, str] = {}
    for name, value in response.headers:
        if not isinstance(name, str) or not isinstance(value, str):
            raise GitHubCloudError("github_response_headers_invalid")
        lowered = name.lower()
        if lowered in headers:
            raise GitHubCloudError("github_response_headers_invalid")
        headers[lowered] = value
    return headers


def _decode_json_value(response: GitHubHttpResponse) -> Any:
    if not isinstance(response, GitHubHttpResponse):
        raise GitHubCloudError("github_response_invalid")
    if len(response.body) > _MAX_RESPONSE_BYTES:
        raise GitHubCloudError("github_response_too_large")
    headers = _response_headers(response)
    if not headers.get("content-type", "").lower().startswith("application/json"):
        raise GitHubCloudError("github_response_content_type_invalid")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise GitHubCloudError("github_response_duplicate_key")
            value[key] = item
        return value

    try:
        decoded = json.loads(response.body, object_pairs_hook=reject_duplicates)
    except GitHubCloudError:
        raise
    except (json.JSONDecodeError, UnicodeError, TypeError) as error:
        raise GitHubCloudError("github_response_json_invalid") from error
    return decoded


def _decode_json(response: GitHubHttpResponse) -> dict[str, Any]:
    decoded = _decode_json_value(response)
    if type(decoded) is not dict:
        raise GitHubCloudError("github_response_schema_invalid")
    return decoded


def _rate_limit(response: GitHubHttpResponse, *, now: datetime) -> None:
    if response.status not in {403, 429}:
        return
    headers = _response_headers(response)
    raw_retry_after = headers.get("retry-after")
    if raw_retry_after is not None:
        if re.fullmatch(r"[1-9][0-9]{0,4}", raw_retry_after) is None:
            raise GitHubCloudError("github_rate_limit_invalid")
        retry_after = int(raw_retry_after)
        if retry_after > 86_400:
            raise GitHubCloudError("github_rate_limit_invalid")
        retry = now + timedelta(seconds=retry_after)
        raise _GitHubRateLimited(retry.isoformat().replace("+00:00", "Z"))
    if headers.get("x-ratelimit-remaining") != "0":
        if response.status == 429:
            retry = now + timedelta(minutes=1)
            raise _GitHubRateLimited(retry.isoformat().replace("+00:00", "Z"))
        return
    raw_reset = headers.get("x-ratelimit-reset")
    if raw_reset is None or re.fullmatch(r"[1-9][0-9]{0,11}", raw_reset) is None:
        raise GitHubCloudError("github_rate_limit_invalid")
    try:
        reset = datetime.fromtimestamp(int(raw_reset), tz=UTC)
    except (OverflowError, OSError, ValueError) as error:
        raise GitHubCloudError("github_rate_limit_invalid") from error
    if not now < reset <= now + timedelta(hours=24):
        raise GitHubCloudError("github_rate_limit_invalid")
    raise _GitHubRateLimited(reset.isoformat().replace("+00:00", "Z"))


def _load_protected_policy() -> _ProtectedGitHubPolicy:
    directory_fd = file_fd = -1
    try:
        directory_fd = os.open(
            _PROTECTED_CONFIG_DIR,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        directory_stat = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid not in {0, os.geteuid()}
            or directory_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise GitHubCloudError("github_protected_configuration_invalid")
        file_fd = os.open(
            _PROTECTED_CONFIG_NAME,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        file_stat = os.fstat(file_fd)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid not in {0, os.geteuid()}
            or file_stat.st_nlink != 1
            or file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 1 <= file_stat.st_size <= 4_096
        ):
            raise GitHubCloudError("github_protected_configuration_invalid")
        payload = os.read(file_fd, 4_097)
        if len(payload) != file_stat.st_size:
            raise GitHubCloudError("github_protected_configuration_invalid")
    except GitHubCloudError:
        raise
    except OSError as error:
        raise GitHubCloudError("github_protected_configuration_invalid") from error
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if directory_fd >= 0:
            os.close(directory_fd)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise GitHubCloudError("github_protected_configuration_invalid")
            value[key] = item
        return value

    try:
        decoded = json.loads(payload, object_pairs_hook=reject_duplicates)
    except GitHubCloudError:
        raise
    except (json.JSONDecodeError, UnicodeError, TypeError) as error:
        raise GitHubCloudError("github_protected_configuration_invalid") from error
    if (
        type(decoded) is not dict
        or set(decoded)
        != {
            "api_origin",
            "dispatch_actor_login",
            "repository",
            "schema_version",
            "workflow_ref",
        }
        or decoded["api_origin"] != _API_ORIGIN
        or isinstance(decoded["schema_version"], bool)
        or decoded["schema_version"] != 1
        or not isinstance(decoded["repository"], str)
        or _REPOSITORY_RE.fullmatch(decoded["repository"]) is None
        or not _workflow_ref_is_valid(decoded["workflow_ref"])
        or not isinstance(decoded["dispatch_actor_login"], str)
        or _ACTOR_LOGIN_RE.fullmatch(decoded["dispatch_actor_login"]) is None
        or canonical_json_bytes(decoded) != payload
    ):
        raise GitHubCloudError("github_protected_configuration_invalid")
    return _ProtectedGitHubPolicy(
        repository=decoded["repository"],
        workflow_ref=decoded["workflow_ref"],
        dispatch_actor_login=decoded["dispatch_actor_login"],
    )


def _system_clock() -> datetime:
    return datetime.now(UTC)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


class _ProtectedGitHubTransport:
    """Fixed production transport; it is never supplied by a gateway caller."""

    __slots__ = ("_opener",)

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirectHandler())

    def send(self, request: GitHubHttpRequest) -> GitHubHttpResponse:
        if not isinstance(request, GitHubHttpRequest) or request.origin != _API_ORIGIN:
            raise GitHubTransportError("github_transport_request_invalid")
        url = request.origin + request.path
        if request.query:
            url += "?" + urlencode(request.query)
        raw = urllib.request.Request(
            url,
            data=request.body,
            headers={name: value for name, value in request.headers},
            method=request.method,
        )
        try:
            response = self._opener.open(raw, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, TimeoutError, urllib.error.URLError) as error:
            raise GitHubTransportError(
                "github_transport_failed",
                ambiguous=request.method in {"POST", "PATCH", "PUT"},
            ) from error
        try:
            body = response.read(request.max_response_bytes + 1)
            headers = tuple((name, value) for name, value in response.headers.items())
            status = response.getcode()
        except Exception as error:
            raise GitHubTransportError(
                "github_transport_failed",
                ambiguous=request.method in {"POST", "PATCH", "PUT"},
            ) from error
        if len(body) > request.max_response_bytes:
            raise GitHubCloudError("github_response_too_large")
        if isinstance(status, bool) or not isinstance(status, int):
            raise GitHubCloudError("github_response_invalid")
        return GitHubHttpResponse(status=status, headers=headers, body=body)


class _RejectingTestStateController:
    __slots__ = ()

    def resolve_claimed_command(
        self, command_key: str, *, authority: str, observed_at: datetime
    ) -> CommandState:
        del command_key, authority, observed_at
        raise GitHubCloudError("github_command_not_found")

    def prepare_effect_attempt(self, attempt: GitHubEffectAttempt) -> bool:
        del attempt
        raise GitHubCloudError("github_effect_fence_invalid")

    def mark_effect_uncertain(
        self, effect_key: str, *, authority: str, not_before: str, observed_at: str
    ) -> None:
        del effect_key, authority, not_before, observed_at
        raise GitHubCloudError("github_effect_fence_invalid")

    def mark_effect_retry_scheduled(
        self,
        effect_key: str,
        *,
        authority: str,
        retry_not_before: str,
        observed_at: str,
    ) -> None:
        del effect_key, authority, retry_not_before, observed_at
        raise GitHubCloudError("github_effect_fence_invalid")

    def mark_effect_completed(
        self, effect_key: str, *, authority: str, result_digest: str, observed_at: str
    ) -> None:
        del effect_key, authority, result_digest, observed_at
        raise GitHubCloudError("github_effect_fence_invalid")


class _ProtectedStateControllerClient:
    """Fixed PostgreSQL-backed client for the isolated state-controller process."""

    __slots__ = ("_backend",)

    def __init__(self) -> None:
        from carl_bench.postgres_state import PostgresStateBackend

        self._backend = PostgresStateBackend.from_protected_environment()

    def resolve_claimed_command(
        self, command_key: str, *, authority: str, observed_at: datetime
    ) -> CommandState:
        return self._backend.resolve_claimed_command(
            command_key,
            authority=authority,
            observed_at=observed_at,
        )

    def prepare_effect_attempt(self, attempt: GitHubEffectAttempt) -> bool:
        return self._backend.prepare_effect_attempt(attempt)

    def mark_effect_uncertain(
        self, effect_key: str, *, authority: str, not_before: str, observed_at: str
    ) -> None:
        self._backend.mark_effect_uncertain(
            effect_key,
            authority=authority,
            not_before=not_before,
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
        self._backend.mark_effect_retry_scheduled(
            effect_key,
            authority=authority,
            retry_not_before=retry_not_before,
            observed_at=observed_at,
        )

    def mark_effect_completed(
        self, effect_key: str, *, authority: str, result_digest: str, observed_at: str
    ) -> None:
        self._backend.mark_effect_completed(
            effect_key,
            authority=authority,
            result_digest=result_digest,
            observed_at=observed_at,
        )


class _InjectedGitHubCloudGateway:
    """Credential-injected implementation confined to explicit test construction."""

    def __init__(
        self,
        *,
        repository: str,
        token: str,
        transport: GitHubHttpTransport,
        clock: Callable[[], datetime],
        state_controller: GitHubEffectStateController,
        workflow_ref: str,
        dispatch_actor_login: str,
    ) -> None:
        del (
            repository,
            token,
            transport,
            clock,
            state_controller,
            workflow_ref,
            dispatch_actor_login,
        )
        raise GitHubCloudError("github_protected_configuration_required")

    @classmethod
    def _construct_test_gateway(
        cls,
        *,
        repository: str,
        token: str,
        transport: GitHubHttpTransport,
        clock: Callable[[], datetime],
        state_controller: GitHubEffectStateController,
        workflow_ref: str,
        dispatch_actor_login: str,
    ) -> _InjectedGitHubCloudGateway:
        if not isinstance(repository, str) or _REPOSITORY_RE.fullmatch(repository) is None:
            raise GitHubCloudError("github_repository_invalid")
        if not isinstance(token, str) or not token or len(token.encode()) > 4_096:
            raise GitHubCloudError("github_credentials_invalid")
        if (
            not _workflow_ref_is_valid(workflow_ref)
            or not isinstance(dispatch_actor_login, str)
            or _ACTOR_LOGIN_RE.fullmatch(dispatch_actor_login) is None
        ):
            raise GitHubCloudError("github_protected_configuration_invalid")
        if (
            not callable(getattr(transport, "send", None))
            or not callable(clock)
            or not callable(getattr(state_controller, "resolve_claimed_command", None))
            or not callable(getattr(state_controller, "prepare_effect_attempt", None))
            or not callable(getattr(state_controller, "mark_effect_uncertain", None))
            or not callable(getattr(state_controller, "mark_effect_retry_scheduled", None))
            or not callable(getattr(state_controller, "mark_effect_completed", None))
        ):
            raise GitHubCloudError("github_protected_configuration_invalid")
        gateway = object.__new__(cls)
        gateway._repository = repository
        gateway._token = token
        gateway._transport = transport
        gateway._clock = clock
        gateway._state_controller = state_controller
        gateway._workflow_ref = workflow_ref
        gateway._dispatch_actor_login = dispatch_actor_login
        return gateway

    @classmethod
    def _for_testing(
        cls,
        *,
        repository: str,
        token: str,
        transport: GitHubHttpTransport,
        clock: Callable[[], datetime],
        state_controller: GitHubEffectStateController | None = None,
        workflow_ref: str = _DEFAULT_WORKFLOW_REF,
        dispatch_actor_login: str = _DEFAULT_DISPATCH_ACTOR_LOGIN,
    ) -> _InjectedGitHubCloudGateway:
        if state_controller is None:
            state_controller = _RejectingTestStateController()
        return cls._construct_test_gateway(
            repository=repository,
            token=token,
            transport=transport,
            clock=clock,
            state_controller=state_controller,
            workflow_ref=workflow_ref,
            dispatch_actor_login=dispatch_actor_login,
        )

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo != UTC:
            raise GitHubCloudError("github_clock_invalid")
        return now

    def _execute_bound_http(
        self,
        method: Literal["GET", "POST", "PATCH", "PUT"],
        path: str,
        *,
        query: tuple[tuple[str, str], ...] = (),
        body: dict[str, Any] | None = None,
        authorization: _BoundEffect | _BoundObservation | None = None,
    ) -> GitHubHttpResponse:
        endpoint_id = self._validate_endpoint(method=method, path=path, query=query, body=body)
        if method in {"POST", "PATCH", "PUT"}:
            if (
                not isinstance(authorization, _BoundEffect)
                or not authorization.may_mutate
                or authorization.binding.method != method
                or authorization.binding.endpoint_id != endpoint_id
                or hashlib.sha256(canonical_json_bytes(body)).hexdigest()
                != authorization.attempt.payload_digest
            ):
                raise GitHubCloudError("github_effect_authorization_required")
        elif (
            not isinstance(authorization, _BoundObservation)
            or endpoint_id
            not in _OBSERVATION_ENDPOINTS_BY_ACTION.get(authorization.binding.action, frozenset())
            or authorization.binding.repository != self._repository
        ):
            raise GitHubCloudError("github_observation_authorization_required")
        request = GitHubHttpRequest(
            method=method,
            origin=_API_ORIGIN,
            path=path,
            query=query,
            body=None if body is None else canonical_json_bytes(body),
            headers=(
                ("accept", "application/vnd.github+json"),
                ("authorization", f"Bearer {self._token}"),
                ("x-github-api-version", "2022-11-28"),
            ),
        )
        response = self._transport.send(request)
        if not isinstance(response, GitHubHttpResponse):
            raise GitHubCloudError("github_response_invalid")
        if len(response.body) > request.max_response_bytes:
            raise GitHubCloudError("github_response_too_large")
        if 300 <= response.status < 400:
            raise GitHubCloudError("github_redirect_rejected")
        try:
            _rate_limit(response, now=self._now())
        except _GitHubRateLimited as limited:
            if isinstance(authorization, _BoundEffect):
                self._mark_effect_retry_scheduled(
                    authorization, retry_not_before=limited.retry_not_before
                )
            raise
        return response

    def _validate_endpoint(
        self,
        *,
        method: object,
        path: object,
        query: object,
        body: object,
    ) -> str:
        if (
            method not in {"GET", "POST", "PATCH", "PUT"}
            or not isinstance(path, str)
            or not isinstance(query, tuple)
            or any(
                not isinstance(item, tuple)
                or len(item) != 2
                or not all(isinstance(value, str) for value in item)
                for item in query
            )
        ):
            raise GitHubCloudError("github_endpoint_not_allowed")
        if len({name for name, _ in query}) != len(query):
            raise GitHubCloudError("github_endpoint_not_allowed")
        query_values = dict(query)
        root = f"/repos/{self._repository}"
        if path == "/graphql":
            if (
                method != "POST"
                or query
                or type(body) is not dict
                or set(body) != {"operationName", "query", "variables"}
                or type(body["variables"]) is not dict
                or set(body["variables"]) != {"pullRequestId"}
                or not isinstance(body["variables"]["pullRequestId"], str)
                or _GRAPHQL_NODE_ID_RE.fullmatch(body["variables"]["pullRequestId"]) is None
            ):
                raise GitHubCloudError("github_endpoint_not_allowed")
            if (
                body["operationName"] == "MarkPullRequestReadyForReview"
                and body["query"] == _MARK_READY_MUTATION
            ):
                return "mark_pull_request_ready"
            if (
                body["operationName"] == "EnablePullRequestAutoMerge"
                and body["query"] == _ENABLE_AUTO_MERGE_MUTATION
            ):
                return "enable_pull_request_auto_merge"
            raise GitHubCloudError("github_endpoint_not_allowed")
        workflow_match = re.fullmatch(
            re.escape(root)
            + r"/actions/workflows/"
            + r"(autonomous-improvement\.yml|autonomous-soak\.yml)/(runs|dispatches)",
            path,
        )
        if workflow_match is not None:
            if workflow_match.group(2) == "runs":
                allowed_query = {
                    "actor",
                    "branch",
                    "event",
                    "head_sha",
                    "per_page",
                }
                if "page" in query_values:
                    allowed_query.add("page")
                if (
                    method != "GET"
                    or body is not None
                    or set(query_values) != allowed_query
                    or query_values["actor"] != self._dispatch_actor_login
                    or query_values["branch"] != self._workflow_ref
                    or query_values["event"] != "workflow_dispatch"
                    or _OBJECT_RE.fullmatch(query_values["head_sha"]) is None
                    or query_values["per_page"] != "100"
                    or (
                        "page" in query_values
                        and re.fullmatch(r"[2-9][0-9]{0,3}", query_values["page"]) is None
                    )
                ):
                    raise GitHubCloudError("github_endpoint_not_allowed")
                return "list_workflow_runs"
            if (
                method != "POST"
                or query
                or type(body) is not dict
                or set(body) != {"inputs", "ref", "return_run_details"}
                or body["ref"] != self._workflow_ref
                or body["return_run_details"] is not True
                or type(body["inputs"]) is not dict
                or set(body["inputs"])
                != {
                    "attempt_key",
                    "candidate_commit",
                    "experiment_digest",
                    "metric_pack_digest",
                    "parent_commit",
                    "policy_digest",
                    "request_digest",
                    "task_set_digest",
                    "workflow_revision",
                    "workflow_blob_digest",
                }
                or any(
                    not isinstance(value, str) or not value or len(value) > 192
                    for value in body["inputs"].values()
                )
            ):
                raise GitHubCloudError("github_endpoint_not_allowed")
            return "workflow_dispatch"

        ref_match = re.fullmatch(
            re.escape(root)
            + r"/git/ref/heads/(experimental|revert)/[A-Za-z0-9][A-Za-z0-9._-]{0,95}",
            path,
        )
        if ref_match is not None:
            if method != "GET" or query or body is not None:
                raise GitHubCloudError("github_endpoint_not_allowed")
            return "get_git_ref"
        if path == f"{root}/git/refs":
            if (
                method != "POST"
                or query
                or type(body) is not dict
                or set(body) != {"ref", "sha"}
                or not isinstance(body["ref"], str)
                or re.fullmatch(
                    r"refs/heads/(experimental|revert)/[A-Za-z0-9][A-Za-z0-9._-]{0,95}",
                    body["ref"],
                )
                is None
                or not isinstance(body["sha"], str)
                or _OBJECT_RE.fullmatch(body["sha"]) is None
            ):
                raise GitHubCloudError("github_endpoint_not_allowed")
            return "create_git_ref"

        commit_match = re.fullmatch(re.escape(root) + r"/git/commits/([0-9a-f]{40})", path)
        if commit_match is not None:
            if method != "GET" or query or body is not None:
                raise GitHubCloudError("github_endpoint_not_allowed")
            return "get_git_commit"

        if path == f"{root}/pulls":
            if method == "GET":
                owner = self._repository.split("/", 1)[0]
                allowed_query = {"base", "head", "per_page", "state"}
                if "page" in query_values:
                    allowed_query.add("page")
                if (
                    body is not None
                    or set(query_values) != allowed_query
                    or query_values["base"] != "main"
                    or re.fullmatch(
                        re.escape(owner)
                        + r":(experimental|revert)/[A-Za-z0-9][A-Za-z0-9._-]{0,95}",
                        query_values["head"],
                    )
                    is None
                    or query_values["per_page"] != "100"
                    or query_values["state"] != "all"
                    or (
                        "page" in query_values
                        and re.fullmatch(r"[2-9][0-9]{0,3}", query_values["page"]) is None
                    )
                ):
                    raise GitHubCloudError("github_endpoint_not_allowed")
                return "list_pull_requests"
            if (
                method != "POST"
                or query
                or type(body) is not dict
                or set(body) != {"base", "body", "draft", "head", "title"}
                or body["base"] != "main"
                or not isinstance(body["head"], str)
                or re.fullmatch(
                    r"(experimental|revert)/[A-Za-z0-9][A-Za-z0-9._-]{0,95}",
                    body["head"],
                )
                is None
                or not isinstance(body["draft"], bool)
                or not isinstance(body["title"], str)
                or not 1 <= len(body["title"].encode()) <= 256
                or not isinstance(body["body"], str)
                or not 1 <= len(body["body"].encode()) <= 8_192
            ):
                raise GitHubCloudError("github_endpoint_not_allowed")
            return "create_pull_request"

        pull_match = re.fullmatch(re.escape(root) + r"/pulls/([1-9][0-9]{0,9})(.*)", path)
        if pull_match is not None:
            suffix = pull_match.group(2)
            if not query and suffix == "" and method == "GET" and body is None:
                return "get_pull_request"
            if (
                not query
                and suffix == ""
                and method == "PATCH"
                and type(body) is dict
                and set(body) == {"body", "title"}
            ):
                return "update_pull_request"
            raise GitHubCloudError("github_endpoint_not_allowed")

        checks_match = re.fullmatch(re.escape(root) + r"/commits/[0-9a-f]{40}/check-runs", path)
        if checks_match is not None and (
            method == "GET"
            and body is None
            and query_values == {"filter": "latest", "per_page": "100"}
        ):
            return "list_check_runs_for_ref"
        raise GitHubCloudError("github_endpoint_not_allowed")

    def _require_dispatch_command(
        self, state: CommandState, request: CloudRunRequest
    ) -> GitHubCommandBinding:
        if not isinstance(state, CommandState) or state.status != "claimed" or state.claim is None:
            raise GitHubCloudError("github_command_not_claimed")
        if request.repository != self._repository:
            raise GitHubCloudError("github_repository_policy_mismatch")
        command = state.command
        binding = workflow_dispatch_binding(
            request,
            attempt=command.attempt,
            workflow_ref=self._workflow_ref,
            dispatch_actor_login=self._dispatch_actor_login,
        )
        if (
            command.command_key != binding.command_key
            or command.authority != binding.authority
            or command.operation != binding.operation
            or command.request_digest != binding.request_digest
            or command.max_attempts != 3
            or state.claim.authority != binding.authority
        ):
            raise GitHubCloudError("github_command_binding_mismatch")
        now = self._now()
        if _utc(command.occurred_at, "github_command_timestamp_invalid") > now:
            raise GitHubCloudError("github_command_timestamp_invalid")
        if _utc(state.claim.claimed_at, "github_claim_timestamp_invalid") > now:
            raise GitHubCloudError("github_claim_timestamp_invalid")
        if _utc(state.claim.expires_at, "github_claim_timestamp_invalid") <= now:
            raise GitHubCloudError("github_command_claim_expired")
        return binding

    def _require_effect_command(self, state: CommandState, binding: GitHubCommandBinding) -> None:
        if not isinstance(state, CommandState) or state.status != "claimed" or state.claim is None:
            raise GitHubCloudError("github_command_not_claimed")
        command = state.command
        if (
            binding.repository != self._repository
            or command.command_key != binding.command_key
            or command.authority != binding.authority
            or command.operation != binding.operation
            or command.request_digest != binding.request_digest
            or command.max_attempts != 3
            or state.claim.authority != binding.authority
        ):
            raise GitHubCloudError("github_command_binding_mismatch")
        now = self._now()
        if _utc(command.occurred_at, "github_command_timestamp_invalid") > now:
            raise GitHubCloudError("github_command_timestamp_invalid")
        if _utc(state.claim.claimed_at, "github_claim_timestamp_invalid") > now:
            raise GitHubCloudError("github_claim_timestamp_invalid")
        if _utc(state.claim.expires_at, "github_claim_timestamp_invalid") <= now:
            raise GitHubCloudError("github_command_claim_expired")

    def _resolve_claimed_command(self, command_key: object, *, authority: str) -> CommandState:
        if not isinstance(command_key, str) or _COMMAND_KEY_RE.fullmatch(command_key) is None:
            raise GitHubCloudError("github_command_reference_invalid")
        observed_at = self._now()
        state = self._state_controller.resolve_claimed_command(
            command_key,
            authority=authority,
            observed_at=observed_at,
        )
        if (
            not isinstance(state, CommandState)
            or state.status != "claimed"
            or state.claim is None
            or state.command.command_key != command_key
        ):
            raise GitHubCloudError("github_command_not_claimed")
        return state

    def _resolve_effect_state(
        self,
        command_key: object,
        binding: GitHubCommandBinding,
    ) -> CommandState:
        state = self._resolve_claimed_command(command_key, authority=binding.authority)
        self._require_effect_command(state, binding)
        return state

    def _prepare_effect_authorization(
        self,
        state: CommandState,
        binding: GitHubCommandBinding,
        *,
        payload: dict[str, Any] | None = None,
    ) -> _BoundEffect:
        self._require_effect_command(state, binding)
        assert state.claim is not None  # CommandState and the durable lookup established this.
        observed = self._now()
        observed_at = observed.isoformat().replace("+00:00", "Z")
        not_before = (observed + _EFFECT_RECONCILIATION_DELAY).isoformat().replace("+00:00", "Z")
        attempt = GitHubEffectAttempt(
            schema_version=1,
            effect_key=state.command.effect_key,
            command_key=state.command.command_key,
            claim_id=state.claim.claim_id,
            command_revision=state.revision,
            claim_expected_revision=state.claim.expected_revision,
            action=binding.action,
            endpoint_id=binding.endpoint_id,
            method=binding.method,
            payload_digest=(
                binding.payload_digest
                if payload is None
                else hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
            ),
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
            not_before=not_before,
            observed_at=observed_at,
        )
        may_mutate = self._state_controller.prepare_effect_attempt(attempt)
        if not isinstance(may_mutate, bool):
            raise GitHubCloudError("github_effect_fence_invalid")
        return _BoundEffect(
            state=state,
            binding=binding,
            attempt=attempt,
            may_mutate=may_mutate,
        )

    def _authorize_observations(
        self,
        state: CommandState,
        binding: GitHubCommandBinding,
    ) -> _BoundObservation:
        self._require_effect_command(state, binding)
        if binding.action not in _OBSERVATION_ENDPOINTS_BY_ACTION:
            raise GitHubCloudError("github_observation_authorization_invalid")
        return _BoundObservation(
            state=state,
            binding=binding,
        )

    def _mark_effect_uncertain(self, authorization: _BoundEffect) -> None:
        now = self._now().isoformat().replace("+00:00", "Z")
        self._state_controller.mark_effect_uncertain(
            authorization.attempt.effect_key,
            authority=authorization.binding.authority,
            not_before=authorization.attempt.not_before,
            observed_at=now,
        )

    def _mark_effect_retry_scheduled(
        self,
        authorization: _BoundEffect,
        *,
        retry_not_before: str,
    ) -> None:
        retry = _utc(retry_not_before, "github_rate_limit_invalid")
        now = self._now()
        if not now < retry <= now + timedelta(hours=24):
            raise GitHubCloudError("github_rate_limit_invalid")
        observed_at = now.isoformat().replace("+00:00", "Z")
        self._state_controller.mark_effect_retry_scheduled(
            authorization.attempt.effect_key,
            authority=authorization.binding.authority,
            retry_not_before=retry_not_before,
            observed_at=observed_at,
        )

    def _mark_effect_completed(
        self,
        authorization: _BoundEffect,
        *,
        result_identity: dict[str, Any],
    ) -> None:
        result_digest = hashlib.sha256(canonical_json_bytes(result_identity)).hexdigest()
        now = self._now().isoformat().replace("+00:00", "Z")
        self._state_controller.mark_effect_completed(
            authorization.attempt.effect_key,
            authority=authorization.binding.authority,
            result_digest=result_digest,
            observed_at=now,
        )

    @staticmethod
    def _retry_decision(
        state: CommandState,
        binding: GitHubCommandBinding,
        limited: _GitHubRateLimited,
    ) -> GitHubRetryDecision:
        return GitHubRetryDecision(
            status="retry_scheduled",
            reason="github_rate_limited",
            request_key=binding.request_key,
            attempt_key=binding.attempt_key,
            effect_key=state.command.effect_key,
            command_occurred_at=state.command.occurred_at,
            retry_not_before=limited.retry_not_before,
            attempt=state.command.attempt,
            max_attempts=state.command.max_attempts,
        )

    def _parse_git_ref(self, value: object, *, expected_ref: str) -> str:
        if type(value) is not dict or not {"object", "ref"} <= set(value) <= {
            "node_id",
            "object",
            "ref",
            "url",
        }:
            raise GitHubCloudError("github_ref_response_schema_invalid")
        if value["ref"] != expected_ref:
            raise GitHubCloudError("github_ref_response_schema_invalid")
        if "node_id" in value and (
            not isinstance(value["node_id"], str) or not 1 <= len(value["node_id"]) <= 256
        ):
            raise GitHubCloudError("github_ref_response_schema_invalid")
        expected_url = (
            f"{_API_ORIGIN}/repos/{self._repository}/git/{expected_ref.removeprefix('refs/')}"
        )
        if "url" in value and value["url"] != expected_url.replace(
            "/git/heads/", "/git/refs/heads/"
        ):
            raise GitHubCloudError("github_ref_response_schema_invalid")
        target = value["object"]
        if type(target) is not dict or not {"sha", "type"} <= set(target) <= {
            "sha",
            "type",
            "url",
        }:
            raise GitHubCloudError("github_ref_response_schema_invalid")
        sha = target["sha"]
        if (
            target["type"] != "commit"
            or not isinstance(sha, str)
            or _OBJECT_RE.fullmatch(sha) is None
            or (
                "url" in target
                and target["url"] != f"{_API_ORIGIN}/repos/{self._repository}/git/commits/{sha}"
            )
        ):
            raise GitHubCloudError("github_ref_response_schema_invalid")
        return sha

    def _read_ref(self, ref: str, *, authorization: _BoundObservation) -> str | None:
        path = f"/repos/{self._repository}/git/ref/{ref.removeprefix('refs/')}"
        response = self._execute_bound_http("GET", path, authorization=authorization)
        _rate_limit(response, now=self._now())
        if response.status == 404:
            decoded = _decode_json(response)
            if decoded != {"message": "Not Found"}:
                raise GitHubCloudError("github_ref_response_schema_invalid")
            return None
        if response.status != 200:
            raise GitHubCloudError("github_ref_observation_failed")
        return self._parse_git_ref(_decode_json(response), expected_ref=ref)

    def _read_git_commit(
        self, sha: str, *, authorization: _BoundObservation
    ) -> _GitCommitObservation:
        response = self._execute_bound_http(
            "GET",
            f"/repos/{self._repository}/git/commits/{sha}",
            authorization=authorization,
        )
        _rate_limit(response, now=self._now())
        if response.status != 200:
            raise GitHubCloudError("github_commit_observation_failed")
        decoded = _decode_json(response)
        if (
            set(decoded) != {"parents", "sha", "tree"}
            or decoded["sha"] != sha
            or type(decoded["tree"]) is not dict
            or set(decoded["tree"]) != {"sha"}
            or not isinstance(decoded["tree"]["sha"], str)
            or _OBJECT_RE.fullmatch(decoded["tree"]["sha"]) is None
            or not isinstance(decoded["parents"], list)
            or len(decoded["parents"]) > 2
        ):
            raise GitHubCloudError("github_commit_response_schema_invalid")
        parents: list[str] = []
        for parent in decoded["parents"]:
            if (
                type(parent) is not dict
                or set(parent) != {"sha"}
                or not isinstance(parent["sha"], str)
                or _OBJECT_RE.fullmatch(parent["sha"]) is None
            ):
                raise GitHubCloudError("github_commit_response_schema_invalid")
            parents.append(parent["sha"])
        if len(parents) != len(set(parents)) or sha in parents:
            raise GitHubCloudError("github_commit_response_schema_invalid")
        return _GitCommitObservation(
            sha=sha,
            tree_sha=decoded["tree"]["sha"],
            parents=tuple(parents),
        )

    def _require_head_ref(
        self,
        branch: str,
        expected_sha: str,
        *,
        authorization: _BoundObservation,
    ) -> None:
        observed = self._read_ref(f"refs/heads/{branch}", authorization=authorization)
        if observed != expected_sha:
            raise GitHubCloudError("github_pull_head_ref_mismatch")

    def _validate_revert_topology(
        self,
        request: RevertBranchRequest,
        *,
        authorization: _BoundObservation,
    ) -> None:
        merge = self._read_git_commit(request.promotion_merge_commit, authorization=authorization)
        if len(merge.parents) != 2:
            raise GitHubCloudError("github_revert_topology_invalid")
        first_parent = self._read_git_commit(merge.parents[0], authorization=authorization)
        if first_parent.tree_sha != request.expected_restored_tree:
            raise GitHubCloudError("github_revert_topology_invalid")
        revert = self._read_git_commit(request.revert_candidate_commit, authorization=authorization)
        if (
            revert.parents != (request.promotion_merge_commit,)
            or revert.tree_sha != request.expected_restored_tree
        ):
            raise GitHubCloudError("github_revert_topology_invalid")

    def _reference_snapshot(
        self,
        *,
        status: Literal["created", "reconciled", "uncertain"],
        state: CommandState,
        binding: GitHubCommandBinding,
        ref: str,
        commit_sha: str,
    ) -> GitReferenceSnapshot:
        return GitReferenceSnapshot(
            status=status,
            repository=self._repository,
            ref=ref,
            commit_sha=commit_sha,
            request_key=binding.request_key,
            effect_key=state.command.effect_key,
            command_occurred_at=state.command.occurred_at,
            observed_at=self._now().isoformat().replace("+00:00", "Z"),
        )

    def create_or_reconcile_experimental_branch(
        self, command_key: str, request: ExperimentalBranchRequest
    ) -> GitReferenceSnapshot | GitHubRetryDecision:
        """Create one immutable experimental ref, or reconcile its exact identity."""
        binding = experimental_branch_binding(self._repository, request)
        state = self._resolve_effect_state(command_key, binding)
        try:
            return self._create_or_reconcile_experimental_branch(state, binding, request)
        except _GitHubRateLimited as limited:
            return self._retry_decision(state, binding, limited)

    def _create_or_reconcile_experimental_branch(
        self,
        state: CommandState,
        binding: GitHubCommandBinding,
        request: ExperimentalBranchRequest,
    ) -> GitReferenceSnapshot:
        observations = self._authorize_observations(state, binding)
        ref = f"refs/heads/{request.branch}"
        existing = self._read_ref(ref, authorization=observations)
        if existing is not None:
            if existing != request.candidate_commit:
                raise GitHubCloudError("github_immutable_ref_conflict")
            authorization = self._prepare_effect_authorization(state, binding)
            self._mark_effect_completed(
                authorization,
                result_identity={"ref": ref, "sha": existing},
            )
            return self._reference_snapshot(
                status="reconciled",
                state=state,
                binding=binding,
                ref=ref,
                commit_sha=existing,
            )
        authorization = self._prepare_effect_authorization(state, binding)
        if not authorization.may_mutate:
            return self._reference_snapshot(
                status="uncertain",
                state=state,
                binding=binding,
                ref=ref,
                commit_sha=request.candidate_commit,
            )
        try:
            response = self._execute_bound_http(
                "POST",
                f"/repos/{self._repository}/git/refs",
                body={"ref": ref, "sha": request.candidate_commit},
                authorization=authorization,
            )
        except GitHubTransportError as error:
            if not error.ambiguous:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_transport_failed") from error
            reconciled = self._read_ref(ref, authorization=observations)
            if reconciled is not None and reconciled != request.candidate_commit:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_immutable_ref_conflict") from error
            if reconciled is None:
                self._mark_effect_uncertain(authorization)
            else:
                self._mark_effect_completed(
                    authorization,
                    result_identity={"ref": ref, "sha": reconciled},
                )
            return self._reference_snapshot(
                status="reconciled" if reconciled is not None else "uncertain",
                state=state,
                binding=binding,
                ref=ref,
                commit_sha=request.candidate_commit,
            )
        if response.status in {409, 422}:
            reconciled = self._read_ref(ref, authorization=observations)
            if reconciled is not None and reconciled != request.candidate_commit:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_immutable_ref_conflict")
            if reconciled is None:
                self._mark_effect_uncertain(authorization)
                return self._reference_snapshot(
                    status="uncertain",
                    state=state,
                    binding=binding,
                    ref=ref,
                    commit_sha=request.candidate_commit,
                )
            self._mark_effect_completed(
                authorization,
                result_identity={"ref": ref, "sha": reconciled},
            )
            return self._reference_snapshot(
                status="reconciled",
                state=state,
                binding=binding,
                ref=ref,
                commit_sha=reconciled,
            )
        if response.status != 201:
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_ref_create_failed")
        created_sha = self._parse_git_ref(_decode_json(response), expected_ref=ref)
        if created_sha != request.candidate_commit:
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_ref_response_schema_invalid")
        self._mark_effect_completed(
            authorization,
            result_identity={"ref": ref, "sha": request.candidate_commit},
        )
        return self._reference_snapshot(
            status="created",
            state=state,
            binding=binding,
            ref=ref,
            commit_sha=request.candidate_commit,
        )

    def _parse_pull_request(self, value: object) -> _PullRequestObservation:
        required = {
            "auto_merge",
            "base",
            "body",
            "draft",
            "head",
            "html_url",
            "node_id",
            "number",
            "state",
            "title",
        }
        documented = required | {
            "assignee",
            "assignees",
            "author_association",
            "closed_at",
            "comments_url",
            "commits_url",
            "created_at",
            "diff_url",
            "id",
            "issue_url",
            "labels",
            "locked",
            "merge_commit_sha",
            "merged_at",
            "milestone",
            "patch_url",
            "requested_reviewers",
            "requested_teams",
            "review_comments_url",
            "statuses_url",
            "updated_at",
            "url",
            "user",
        }
        if type(value) is not dict or not required <= set(value) <= documented:
            raise GitHubCloudError("github_pull_response_schema_invalid")
        base = value["base"]
        head = value["head"]
        if (
            type(base) is not dict
            or not {"ref"} <= set(base) <= {"label", "ref", "repo", "sha", "user"}
            or type(head) is not dict
            or not {"ref", "sha"} <= set(head) <= {"label", "ref", "repo", "sha", "user"}
        ):
            raise GitHubCloudError("github_pull_response_schema_invalid")
        number = value["number"]
        node_id = value["node_id"]
        url = value["html_url"]
        title = value["title"]
        body = value["body"]
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or number <= 0
            or not isinstance(url, str)
            or url != f"https://github.com/{self._repository}/pull/{number}"
            or not isinstance(node_id, str)
            or _GRAPHQL_NODE_ID_RE.fullmatch(node_id) is None
            or value["state"] not in {"open", "closed"}
            or not isinstance(value["draft"], bool)
            or not isinstance(base["ref"], str)
            or not isinstance(head["ref"], str)
            or not isinstance(head["sha"], str)
            or _OBJECT_RE.fullmatch(head["sha"]) is None
            or not isinstance(title, str)
            or not isinstance(body, str)
            or len(title.encode()) > 256
            or len(body.encode()) > 8_192
            or (
                value["auto_merge"] is not None
                and value["auto_merge"] != {"merge_method": "squash"}
            )
        ):
            raise GitHubCloudError("github_pull_response_schema_invalid")
        owner = self._repository.split("/", 1)[0]
        for branch in (base, head):
            if "sha" in branch and (
                not isinstance(branch["sha"], str) or _OBJECT_RE.fullmatch(branch["sha"]) is None
            ):
                raise GitHubCloudError("github_pull_response_schema_invalid")
            if "label" in branch and branch["label"] != f"{owner}:{branch['ref']}":
                raise GitHubCloudError("github_pull_response_schema_invalid")
            if "user" in branch and (
                type(branch["user"]) is not dict
                or set(branch["user"]) != {"login"}
                or branch["user"]["login"] != owner
            ):
                raise GitHubCloudError("github_pull_response_schema_invalid")
            if "repo" in branch:
                repository = branch["repo"]
                if (
                    type(repository) is not dict
                    or not {"full_name", "html_url", "id", "name", "node_id", "private", "url"}
                    <= set(repository)
                    or repository["full_name"] != self._repository
                    or repository["name"] != self._repository.split("/", 1)[1]
                    or repository["url"] != f"{_API_ORIGIN}/repos/{self._repository}"
                    or repository["html_url"] != f"https://github.com/{self._repository}"
                    or isinstance(repository["id"], bool)
                    or not isinstance(repository["id"], int)
                    or repository["id"] <= 0
                    or not isinstance(repository["node_id"], str)
                    or not isinstance(repository["private"], bool)
                ):
                    raise GitHubCloudError("github_pull_response_schema_invalid")
        expected_api = f"{_API_ORIGIN}/repos/{self._repository}"
        exact_urls = {
            "comments_url": f"{expected_api}/issues/{number}/comments",
            "commits_url": f"{expected_api}/pulls/{number}/commits",
            "diff_url": f"https://github.com/{self._repository}/pull/{number}.diff",
            "issue_url": f"{expected_api}/issues/{number}",
            "patch_url": f"https://github.com/{self._repository}/pull/{number}.patch",
            "review_comments_url": f"{expected_api}/pulls/{number}/comments",
            "statuses_url": f"{expected_api}/statuses/{head['sha']}",
            "url": f"{expected_api}/pulls/{number}",
        }
        if any(
            value.get(name) != expected for name, expected in exact_urls.items() if name in value
        ):
            raise GitHubCloudError("github_pull_response_schema_invalid")
        if any(
            name in value
            and value[name] is not None
            and not isinstance(value[name], str | int | bool | list | dict)
            for name in documented - required
        ):
            raise GitHubCloudError("github_pull_response_schema_invalid")
        return _PullRequestObservation(
            node_id=node_id,
            number=number,
            url=url,
            state=value["state"],
            draft=value["draft"],
            base_branch=base["ref"],
            head_branch=head["ref"],
            head_sha=head["sha"],
            title=title,
            body=body,
            auto_merge_enabled=value["auto_merge"] is not None,
        )

    def _find_pull_request(
        self,
        request: PullRequestCreateRequest | RevertPullRequestRequest,
        *,
        authorization: _BoundObservation,
    ) -> _PullRequestObservation | None:
        owner = self._repository.split("/", 1)[0]
        path = f"/repos/{self._repository}/pulls"
        base_query = (
            ("base", request.base_branch),
            ("head", f"{owner}:{request.head_branch}"),
            ("per_page", "100"),
            ("state", "all"),
        )
        observations: list[_PullRequestObservation] = []
        page = 1
        while True:
            query = (
                ("base", request.base_branch),
                ("head", f"{owner}:{request.head_branch}"),
                *(((("page", str(page)),)) if page > 1 else ()),
                ("per_page", "100"),
                ("state", "all"),
            )
            response = self._execute_bound_http(
                "GET", path, query=query, authorization=authorization
            )
            _rate_limit(response, now=self._now())
            if response.status != 200:
                raise GitHubCloudError("github_pull_observation_failed")
            decoded = _decode_json_value(response)
            if not isinstance(decoded, list) or len(decoded) > 100:
                raise GitHubCloudError("github_pull_response_schema_invalid")
            observations.extend(self._parse_pull_request(value) for value in decoded)
            if len(observations) > 1:
                raise GitHubCloudError("github_pull_request_identity_ambiguous")
            next_page = self._next_page(
                response,
                path=path,
                current_page=page,
                required_query=base_query,
            )
            if next_page is None:
                break
            if page >= _MAX_PAGES:
                raise GitHubCloudError("github_pagination_limit_exceeded")
            page = next_page
        if len(observations) > 1:
            raise GitHubCloudError("github_pull_request_identity_ambiguous")
        if not observations:
            return None
        observed = observations[0]
        if (
            observed.base_branch != request.base_branch
            or observed.head_branch != request.head_branch
            or observed.head_sha != request.head_sha
        ):
            raise GitHubCloudError("github_pull_request_identity_conflict")
        return observed

    def _pull_snapshot(
        self,
        *,
        status: Literal["created", "updated", "reconciled", "uncertain"],
        state: CommandState,
        binding: GitHubCommandBinding,
        observed: _PullRequestObservation,
    ) -> PullRequestEffectSnapshot:
        return PullRequestEffectSnapshot(
            status=status,
            repository=self._repository,
            number=observed.number,
            url=observed.url,
            state=observed.state,
            draft=observed.draft,
            base_branch=observed.base_branch,
            head_branch=observed.head_branch,
            head_sha=observed.head_sha,
            title=observed.title,
            body=observed.body,
            auto_merge_enabled=observed.auto_merge_enabled,
            request_key=binding.request_key,
            effect_key=state.command.effect_key,
            command_occurred_at=state.command.occurred_at,
            observed_at=self._now().isoformat().replace("+00:00", "Z"),
        )

    def _require_exact_pull_create(
        self,
        observed: _PullRequestObservation,
        request: PullRequestCreateRequest | RevertPullRequestRequest,
    ) -> None:
        if (
            observed.state != "open"
            or observed.title != request.title
            or observed.body != request.body
            or observed.draft != request.draft
        ):
            raise GitHubCloudError("github_pull_request_identity_conflict")

    def create_or_reconcile_pull_request(
        self, command_key: str, request: PullRequestCreateRequest
    ) -> PullRequestEffectSnapshot | GitHubRetryDecision:
        """Create the exact production PR, reconciling an existing identity first."""
        binding = pull_request_create_binding(self._repository, request)
        state = self._resolve_effect_state(command_key, binding)
        try:
            return self._create_or_reconcile_pull_request(state, binding, request)
        except _GitHubRateLimited as limited:
            return self._retry_decision(state, binding, limited)

    def _create_or_reconcile_pull_request(
        self,
        state: CommandState,
        binding: GitHubCommandBinding,
        request: PullRequestCreateRequest,
    ) -> PullRequestEffectSnapshot:
        observations = self._authorize_observations(state, binding)
        self._require_head_ref(request.head_branch, request.head_sha, authorization=observations)
        existing = self._find_pull_request(request, authorization=observations)
        if existing is not None:
            self._require_exact_pull_create(existing, request)
            authorization = self._prepare_effect_authorization(state, binding)
            self._mark_effect_completed(
                authorization,
                result_identity={
                    "head_sha": existing.head_sha,
                    "number": existing.number,
                },
            )
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=existing
            )
        payload = {
            "base": request.base_branch,
            "body": request.body,
            "draft": request.draft,
            "head": request.head_branch,
            "title": request.title,
        }
        authorization = self._prepare_effect_authorization(state, binding)
        if not authorization.may_mutate:
            raise GitHubCloudError("github_pull_create_uncertain")
        try:
            response = self._execute_bound_http(
                "POST",
                f"/repos/{self._repository}/pulls",
                body=payload,
                authorization=authorization,
            )
        except GitHubTransportError as error:
            if not error.ambiguous:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_transport_failed") from error
            self._require_head_ref(
                request.head_branch, request.head_sha, authorization=observations
            )
            reconciled = self._find_pull_request(request, authorization=observations)
            if reconciled is None:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_pull_create_uncertain") from error
            self._require_exact_pull_create(reconciled, request)
            self._mark_effect_completed(
                authorization,
                result_identity={
                    "head_sha": reconciled.head_sha,
                    "number": reconciled.number,
                },
            )
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=reconciled
            )
        if response.status == 422:
            self._require_head_ref(
                request.head_branch, request.head_sha, authorization=observations
            )
            reconciled = self._find_pull_request(request, authorization=observations)
            if reconciled is None:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_pull_create_uncertain")
            self._require_exact_pull_create(reconciled, request)
            self._mark_effect_completed(
                authorization,
                result_identity={
                    "head_sha": reconciled.head_sha,
                    "number": reconciled.number,
                },
            )
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=reconciled
            )
        if response.status != 201:
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_pull_create_failed")
        created = self._parse_pull_request(_decode_json(response))
        if (
            created.base_branch != request.base_branch
            or created.head_branch != request.head_branch
            or created.head_sha != request.head_sha
        ):
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_pull_request_identity_conflict")
        self._require_exact_pull_create(created, request)
        self._mark_effect_completed(
            authorization,
            result_identity={"head_sha": created.head_sha, "number": created.number},
        )
        return self._pull_snapshot(status="created", state=state, binding=binding, observed=created)

    def _get_pull_request(
        self, number: int, *, authorization: _BoundObservation
    ) -> _PullRequestObservation:
        response = self._execute_bound_http(
            "GET",
            f"/repos/{self._repository}/pulls/{number}",
            authorization=authorization,
        )
        _rate_limit(response, now=self._now())
        if response.status != 200:
            raise GitHubCloudError("github_pull_observation_failed")
        return self._parse_pull_request(_decode_json(response))

    def _require_pull_target(
        self,
        observed: _PullRequestObservation,
        *,
        number: int,
        base_branch: str,
        head_branch: str,
        head_sha: str,
    ) -> None:
        if (
            observed.number != number
            or observed.state != "open"
            or observed.base_branch != base_branch
            or observed.head_branch != head_branch
            or observed.head_sha != head_sha
        ):
            raise GitHubCloudError("github_pull_request_identity_conflict")

    def _parse_graphql_pull_effect(
        self,
        response: GitHubHttpResponse,
        *,
        operation: Literal["markPullRequestReadyForReview", "enablePullRequestAutoMerge"],
        observed: _PullRequestObservation,
    ) -> _PullRequestObservation:
        decoded = _decode_json(response)
        if set(decoded) != {"data"} or type(decoded["data"]) is not dict:
            raise GitHubCloudError("github_graphql_response_invalid")
        data = decoded["data"]
        if set(data) != {operation} or type(data[operation]) is not dict:
            raise GitHubCloudError("github_graphql_response_invalid")
        mutation = data[operation]
        if set(mutation) != {"pullRequest"} or type(mutation["pullRequest"]) is not dict:
            raise GitHubCloudError("github_graphql_response_invalid")
        pull = mutation["pullRequest"]
        expected_fields = {
            "baseRefName",
            "headRefName",
            "headRefOid",
            "id",
            "isDraft",
            "number",
            "repository",
        }
        if operation == "enablePullRequestAutoMerge":
            expected_fields.add("autoMergeRequest")
        if (
            set(pull) != expected_fields
            or pull["isDraft"] is not False
            or type(pull["repository"]) is not dict
        ):
            raise GitHubCloudError("github_graphql_response_invalid")
        if (
            pull["id"] != observed.node_id
            or pull["number"] != observed.number
            or pull["baseRefName"] != observed.base_branch
            or pull["headRefName"] != observed.head_branch
            or pull["headRefOid"] != observed.head_sha
            or pull["repository"] != {"nameWithOwner": self._repository}
        ):
            raise GitHubCloudError("github_pull_request_identity_conflict")
        if operation == "enablePullRequestAutoMerge" and pull["autoMergeRequest"] != {
            "mergeMethod": "SQUASH"
        }:
            raise GitHubCloudError("github_graphql_response_invalid")
        return replace(
            observed,
            draft=False,
            auto_merge_enabled=(
                observed.auto_merge_enabled or operation == "enablePullRequestAutoMerge"
            ),
        )

    def update_pull_request(
        self, command_key: str, request: PullRequestUpdateRequest
    ) -> PullRequestEffectSnapshot | GitHubRetryDecision:
        """Narrowly update title and body for one exact open pull request."""
        binding = pull_request_update_binding(self._repository, request)
        state = self._resolve_effect_state(command_key, binding)
        try:
            return self._update_pull_request(state, binding, request)
        except _GitHubRateLimited as limited:
            return self._retry_decision(state, binding, limited)

    def _update_pull_request(
        self,
        state: CommandState,
        binding: GitHubCommandBinding,
        request: PullRequestUpdateRequest,
    ) -> PullRequestEffectSnapshot:
        observations = self._authorize_observations(state, binding)
        observed = self._get_pull_request(request.number, authorization=observations)
        self._require_pull_target(
            observed,
            number=request.number,
            base_branch=request.base_branch,
            head_branch=request.head_branch,
            head_sha=request.head_sha,
        )
        if observed.title == request.title and observed.body == request.body:
            authorization = self._prepare_effect_authorization(state, binding)
            self._mark_effect_completed(
                authorization,
                result_identity={
                    "body": observed.body,
                    "head_sha": observed.head_sha,
                    "number": observed.number,
                    "title": observed.title,
                },
            )
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=observed
            )
        authorization = self._prepare_effect_authorization(state, binding)
        if not authorization.may_mutate:
            return self._pull_snapshot(
                status="uncertain", state=state, binding=binding, observed=observed
            )
        try:
            response = self._execute_bound_http(
                "PATCH",
                f"/repos/{self._repository}/pulls/{request.number}",
                body={"body": request.body, "title": request.title},
                authorization=authorization,
            )
        except GitHubTransportError as error:
            if not error.ambiguous:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_transport_failed") from error
            reconciled = self._get_pull_request(request.number, authorization=observations)
            try:
                self._require_pull_target(
                    reconciled,
                    number=request.number,
                    base_branch=request.base_branch,
                    head_branch=request.head_branch,
                    head_sha=request.head_sha,
                )
            except GitHubCloudError:
                self._mark_effect_uncertain(authorization)
                raise
            if reconciled.title != request.title or reconciled.body != request.body:
                self._mark_effect_uncertain(authorization)
                return self._pull_snapshot(
                    status="uncertain", state=state, binding=binding, observed=reconciled
                )
            self._mark_effect_completed(
                authorization,
                result_identity={
                    "body": reconciled.body,
                    "head_sha": reconciled.head_sha,
                    "number": reconciled.number,
                    "title": reconciled.title,
                },
            )
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=reconciled
            )
        if response.status != 200:
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_pull_update_failed")
        try:
            updated = self._parse_pull_request(_decode_json(response))
            self._require_pull_target(
                updated,
                number=request.number,
                base_branch=request.base_branch,
                head_branch=request.head_branch,
                head_sha=request.head_sha,
            )
        except GitHubCloudError:
            self._mark_effect_uncertain(authorization)
            raise
        if updated.title != request.title or updated.body != request.body:
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_pull_update_response_mismatch")
        self._mark_effect_completed(
            authorization,
            result_identity={
                "body": updated.body,
                "head_sha": updated.head_sha,
                "number": updated.number,
                "title": updated.title,
            },
        )
        return self._pull_snapshot(status="updated", state=state, binding=binding, observed=updated)

    def mark_pull_request_ready(
        self, command_key: str, request: PullRequestReadyRequest
    ) -> PullRequestEffectSnapshot | GitHubRetryDecision:
        """Mark one exact draft ready, reconciling before and after its sole effect."""
        binding = pull_request_ready_binding(self._repository, request)
        state = self._resolve_effect_state(command_key, binding)
        try:
            return self._mark_pull_request_ready(state, binding, request)
        except _GitHubRateLimited as limited:
            return self._retry_decision(state, binding, limited)

    def _mark_pull_request_ready(
        self,
        state: CommandState,
        binding: GitHubCommandBinding,
        request: PullRequestReadyRequest,
    ) -> PullRequestEffectSnapshot:
        observations = self._authorize_observations(state, binding)
        observed = self._get_pull_request(request.number, authorization=observations)
        self._require_pull_target(
            observed,
            number=request.number,
            base_branch=request.base_branch,
            head_branch=request.head_branch,
            head_sha=request.head_sha,
        )
        if not observed.draft:
            authorization = self._prepare_effect_authorization(
                state,
                binding,
                payload={
                    "operationName": "MarkPullRequestReadyForReview",
                    "query": _MARK_READY_MUTATION,
                    "variables": {"pullRequestId": observed.node_id},
                },
            )
            self._mark_effect_completed(
                authorization,
                result_identity={
                    "draft": observed.draft,
                    "head_sha": observed.head_sha,
                    "number": observed.number,
                },
            )
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=observed
            )
        payload = {
            "operationName": "MarkPullRequestReadyForReview",
            "query": _MARK_READY_MUTATION,
            "variables": {"pullRequestId": observed.node_id},
        }
        authorization = self._prepare_effect_authorization(
            state,
            binding,
            payload=payload,
        )
        if not authorization.may_mutate:
            return self._pull_snapshot(
                status="uncertain", state=state, binding=binding, observed=observed
            )
        try:
            response = self._execute_bound_http(
                "POST", "/graphql", body=payload, authorization=authorization
            )
        except GitHubTransportError as error:
            if not error.ambiguous:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_transport_failed") from error
            reconciled = self._get_pull_request(request.number, authorization=observations)
            try:
                self._require_pull_target(
                    reconciled,
                    number=request.number,
                    base_branch=request.base_branch,
                    head_branch=request.head_branch,
                    head_sha=request.head_sha,
                )
            except GitHubCloudError:
                self._mark_effect_uncertain(authorization)
                raise
            if reconciled.draft:
                self._mark_effect_uncertain(authorization)
                return self._pull_snapshot(
                    status="uncertain", state=state, binding=binding, observed=reconciled
                )
            self._mark_effect_completed(
                authorization,
                result_identity={
                    "draft": reconciled.draft,
                    "head_sha": reconciled.head_sha,
                    "number": reconciled.number,
                },
            )
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=reconciled
            )
        if response.status != 200:
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_ready_transition_failed")
        try:
            ready = self._parse_graphql_pull_effect(
                response,
                operation="markPullRequestReadyForReview",
                observed=observed,
            )
            self._require_pull_target(
                ready,
                number=request.number,
                base_branch=request.base_branch,
                head_branch=request.head_branch,
                head_sha=request.head_sha,
            )
        except GitHubCloudError:
            self._mark_effect_uncertain(authorization)
            raise
        if ready.draft:
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_ready_transition_response_mismatch")
        self._mark_effect_completed(
            authorization,
            result_identity={
                "draft": ready.draft,
                "head_sha": ready.head_sha,
                "number": ready.number,
            },
        )
        return self._pull_snapshot(status="updated", state=state, binding=binding, observed=ready)

    def enable_pull_request_auto_merge(
        self, command_key: str, request: PullRequestAutoMergeRequest
    ) -> PullRequestEffectSnapshot | GitHubRetryDecision:
        """Enable squash auto-merge for one exact, ready pull request."""
        binding = pull_request_auto_merge_binding(self._repository, request)
        state = self._resolve_effect_state(command_key, binding)
        try:
            return self._enable_pull_request_auto_merge(state, binding, request)
        except _GitHubRateLimited as limited:
            return self._retry_decision(state, binding, limited)

    def _enable_pull_request_auto_merge(
        self,
        state: CommandState,
        binding: GitHubCommandBinding,
        request: PullRequestAutoMergeRequest,
    ) -> PullRequestEffectSnapshot:
        observations = self._authorize_observations(state, binding)
        observed = self._get_pull_request(request.number, authorization=observations)
        self._require_pull_target(
            observed,
            number=request.number,
            base_branch=request.base_branch,
            head_branch=request.head_branch,
            head_sha=request.head_sha,
        )
        if observed.draft:
            raise GitHubCloudError("github_pull_request_not_ready")
        if observed.auto_merge_enabled:
            authorization = self._prepare_effect_authorization(
                state,
                binding,
                payload={
                    "operationName": "EnablePullRequestAutoMerge",
                    "query": _ENABLE_AUTO_MERGE_MUTATION,
                    "variables": {"pullRequestId": observed.node_id},
                },
            )
            self._mark_effect_completed(
                authorization,
                result_identity={
                    "auto_merge": True,
                    "head_sha": observed.head_sha,
                    "number": observed.number,
                },
            )
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=observed
            )
        payload = {
            "operationName": "EnablePullRequestAutoMerge",
            "query": _ENABLE_AUTO_MERGE_MUTATION,
            "variables": {"pullRequestId": observed.node_id},
        }
        authorization = self._prepare_effect_authorization(
            state,
            binding,
            payload=payload,
        )
        if not authorization.may_mutate:
            return self._pull_snapshot(
                status="uncertain", state=state, binding=binding, observed=observed
            )
        try:
            response = self._execute_bound_http(
                "POST", "/graphql", body=payload, authorization=authorization
            )
        except GitHubTransportError as error:
            if not error.ambiguous:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_transport_failed") from error
            reconciled = self._get_pull_request(request.number, authorization=observations)
            try:
                self._require_pull_target(
                    reconciled,
                    number=request.number,
                    base_branch=request.base_branch,
                    head_branch=request.head_branch,
                    head_sha=request.head_sha,
                )
            except GitHubCloudError:
                self._mark_effect_uncertain(authorization)
                raise
            if not reconciled.auto_merge_enabled:
                self._mark_effect_uncertain(authorization)
                return self._pull_snapshot(
                    status="uncertain", state=state, binding=binding, observed=reconciled
                )
            self._mark_effect_completed(
                authorization,
                result_identity={
                    "auto_merge": True,
                    "head_sha": reconciled.head_sha,
                    "number": reconciled.number,
                },
            )
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=reconciled
            )
        if response.status != 200:
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_auto_merge_failed")
        try:
            enabled = self._parse_graphql_pull_effect(
                response,
                operation="enablePullRequestAutoMerge",
                observed=observed,
            )
            self._require_pull_target(
                enabled,
                number=request.number,
                base_branch=request.base_branch,
                head_branch=request.head_branch,
                head_sha=request.head_sha,
            )
        except GitHubCloudError:
            self._mark_effect_uncertain(authorization)
            raise
        if not enabled.auto_merge_enabled:
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_auto_merge_response_mismatch")
        self._mark_effect_completed(
            authorization,
            result_identity={
                "auto_merge": True,
                "head_sha": enabled.head_sha,
                "number": enabled.number,
            },
        )
        return self._pull_snapshot(status="updated", state=state, binding=binding, observed=enabled)

    def observe_required_checks(
        self, command_key: str, request: RequiredChecksRequest
    ) -> RequiredChecksSnapshot | GitHubRetryDecision:
        """Observe approved checks only when every returned run binds the exact head."""
        binding = required_checks_binding(self._repository, request)
        state = self._resolve_effect_state(command_key, binding)
        try:
            return self._observe_required_checks(state, binding, request)
        except _GitHubRateLimited as limited:
            return self._retry_decision(state, binding, limited)

    def _observe_required_checks(
        self,
        state: CommandState,
        binding: GitHubCommandBinding,
        request: RequiredChecksRequest,
    ) -> RequiredChecksSnapshot:
        observations = self._authorize_observations(state, binding)
        response = self._execute_bound_http(
            "GET",
            f"/repos/{self._repository}/commits/{request.head_sha}/check-runs",
            query=(("filter", "latest"), ("per_page", "100")),
            authorization=observations,
        )
        _rate_limit(response, now=self._now())
        if response.status != 200:
            raise GitHubCloudError("github_check_observation_failed")
        decoded = _decode_json(response)
        if set(decoded) != {"check_runs", "total_count"}:
            raise GitHubCloudError("github_check_response_schema_invalid")
        values = decoded["check_runs"]
        total_count = decoded["total_count"]
        if (
            not isinstance(values, list)
            or len(values) > 100
            or isinstance(total_count, bool)
            or not isinstance(total_count, int)
            or total_count != len(values)
        ):
            raise GitHubCloudError("github_check_response_schema_invalid")
        checks: list[RequiredCheckObservation] = []
        for value in values:
            required = {
                "app",
                "conclusion",
                "head_sha",
                "name",
                "status",
            }
            documented = required | {
                "check_suite",
                "completed_at",
                "details_url",
                "external_id",
                "html_url",
                "id",
                "node_id",
                "output",
                "pull_requests",
                "started_at",
                "url",
            }
            if type(value) is not dict or not required <= set(value) <= documented:
                raise GitHubCloudError("github_check_response_schema_invalid")
            app = value["app"]
            app_fields = {
                "created_at",
                "description",
                "external_url",
                "html_url",
                "id",
                "name",
                "node_id",
                "slug",
                "updated_at",
            }
            if type(app) is not dict or not {"id"} <= set(app) <= app_fields:
                raise GitHubCloudError("github_check_response_schema_invalid")
            if value["head_sha"] != request.head_sha:
                raise GitHubCloudError("github_check_head_mismatch")
            if (
                not isinstance(value["name"], str)
                or value["name"] not in request.required_checks
                or value["status"] not in {"queued", "in_progress", "completed"}
                or (
                    value["conclusion"] is not None
                    and value["conclusion"]
                    not in {
                        "action_required",
                        "cancelled",
                        "failure",
                        "neutral",
                        "skipped",
                        "stale",
                        "success",
                        "timed_out",
                    }
                )
                or isinstance(app["id"], bool)
                or not isinstance(app["id"], int)
                or app["id"] <= 0
            ):
                raise GitHubCloudError("github_check_response_schema_invalid")
            if "id" in value:
                check_id = value["id"]
                if (
                    isinstance(check_id, bool)
                    or not isinstance(check_id, int)
                    or check_id <= 0
                    or (
                        "url" in value
                        and value["url"]
                        != f"{_API_ORIGIN}/repos/{self._repository}/check-runs/{check_id}"
                    )
                    or (
                        "html_url" in value
                        and value["html_url"]
                        != f"https://github.com/{self._repository}/runs/{check_id}"
                    )
                ):
                    raise GitHubCloudError("github_check_response_schema_invalid")
            if "details_url" in value and (
                not isinstance(value["details_url"], str)
                or not value["details_url"].startswith(
                    f"https://github.com/{self._repository}/actions/runs/"
                )
            ):
                raise GitHubCloudError("github_check_response_schema_invalid")
            for name in ("started_at", "completed_at"):
                if name in value:
                    _utc(value[name], "github_check_response_schema_invalid")
            if "check_suite" in value and (
                type(value["check_suite"]) is not dict
                or set(value["check_suite"]) != {"id"}
                or isinstance(value["check_suite"]["id"], bool)
                or not isinstance(value["check_suite"]["id"], int)
                or value["check_suite"]["id"] <= 0
            ):
                raise GitHubCloudError("github_check_response_schema_invalid")
            if "pull_requests" in value and value["pull_requests"] != []:
                raise GitHubCloudError("github_check_response_schema_invalid")
            if "output" in value:
                output = value["output"]
                if (
                    type(output) is not dict
                    or set(output)
                    != {
                        "annotations_count",
                        "annotations_url",
                        "summary",
                        "text",
                        "title",
                    }
                    or isinstance(output["annotations_count"], bool)
                    or not isinstance(output["annotations_count"], int)
                    or not 0 <= output["annotations_count"] <= 1_000
                    or output["annotations_url"]
                    != (
                        f"{_API_ORIGIN}/repos/{self._repository}/check-runs/"
                        f"{value.get('id')}/annotations"
                    )
                    or any(
                        not isinstance(output[name], str) for name in ("summary", "text", "title")
                    )
                ):
                    raise GitHubCloudError("github_check_response_schema_invalid")
            if (
                "html_url" in app and app["html_url"] != "https://github.com/apps/github-actions"
            ) or (
                "external_url" in app and app["external_url"] != "https://docs.github.com/actions"
            ):
                raise GitHubCloudError("github_check_response_schema_invalid")
            checks.append(
                RequiredCheckObservation(
                    name=value["name"],
                    status=value["status"],
                    conclusion=value["conclusion"],
                    app_id=app["id"],
                )
            )
        if len({check.name for check in checks}) != len(checks):
            raise GitHubCloudError("github_check_response_schema_invalid")
        by_name = {check.name: check for check in checks}
        ordered = tuple(by_name[name] for name in request.required_checks if name in by_name)
        complete = tuple(check.name for check in ordered) == request.required_checks and all(
            check.status == "completed" and check.conclusion == "success" and check.app_id == 15368
            for check in ordered
        )
        return RequiredChecksSnapshot(
            repository=self._repository,
            head_sha=request.head_sha,
            checks=ordered,
            complete=complete,
            request_key=binding.request_key,
            effect_key=state.command.effect_key,
            command_occurred_at=state.command.occurred_at,
            observed_at=self._now().isoformat().replace("+00:00", "Z"),
        )

    def create_or_reconcile_revert_branch(
        self, command_key: str, request: RevertBranchRequest
    ) -> GitReferenceSnapshot | GitHubRetryDecision:
        """Create the exact protected revert candidate ref without moving any existing ref."""
        binding = revert_branch_binding(self._repository, request)
        state = self._resolve_effect_state(command_key, binding)
        try:
            return self._create_or_reconcile_revert_branch(state, binding, request)
        except _GitHubRateLimited as limited:
            return self._retry_decision(state, binding, limited)

    def _create_or_reconcile_revert_branch(
        self,
        state: CommandState,
        binding: GitHubCommandBinding,
        request: RevertBranchRequest,
    ) -> GitReferenceSnapshot:
        observations = self._authorize_observations(state, binding)
        self._validate_revert_topology(request, authorization=observations)
        ref = f"refs/heads/{request.branch}"
        existing = self._read_ref(ref, authorization=observations)
        if existing is not None:
            if existing != request.revert_candidate_commit:
                raise GitHubCloudError("github_immutable_ref_conflict")
            authorization = self._prepare_effect_authorization(state, binding)
            self._mark_effect_completed(
                authorization,
                result_identity={"ref": ref, "sha": existing},
            )
            return self._reference_snapshot(
                status="reconciled",
                state=state,
                binding=binding,
                ref=ref,
                commit_sha=existing,
            )
        authorization = self._prepare_effect_authorization(state, binding)
        if not authorization.may_mutate:
            return self._reference_snapshot(
                status="uncertain",
                state=state,
                binding=binding,
                ref=ref,
                commit_sha=request.revert_candidate_commit,
            )
        try:
            response = self._execute_bound_http(
                "POST",
                f"/repos/{self._repository}/git/refs",
                body={"ref": ref, "sha": request.revert_candidate_commit},
                authorization=authorization,
            )
        except GitHubTransportError as error:
            if not error.ambiguous:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_transport_failed") from error
            reconciled = self._read_ref(ref, authorization=observations)
            if reconciled is not None and reconciled != request.revert_candidate_commit:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_immutable_ref_conflict") from error
            if reconciled is None:
                self._mark_effect_uncertain(authorization)
            else:
                self._mark_effect_completed(
                    authorization,
                    result_identity={"ref": ref, "sha": reconciled},
                )
            return self._reference_snapshot(
                status="reconciled" if reconciled is not None else "uncertain",
                state=state,
                binding=binding,
                ref=ref,
                commit_sha=request.revert_candidate_commit,
            )
        if response.status in {409, 422}:
            reconciled = self._read_ref(ref, authorization=observations)
            if reconciled is not None and reconciled != request.revert_candidate_commit:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_immutable_ref_conflict")
            if reconciled is None:
                self._mark_effect_uncertain(authorization)
                return self._reference_snapshot(
                    status="uncertain",
                    state=state,
                    binding=binding,
                    ref=ref,
                    commit_sha=request.revert_candidate_commit,
                )
            self._mark_effect_completed(
                authorization,
                result_identity={"ref": ref, "sha": reconciled},
            )
            return self._reference_snapshot(
                status="reconciled",
                state=state,
                binding=binding,
                ref=ref,
                commit_sha=reconciled,
            )
        if response.status != 201:
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_ref_create_failed")
        created_sha = self._parse_git_ref(_decode_json(response), expected_ref=ref)
        if created_sha != request.revert_candidate_commit:
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_ref_response_schema_invalid")
        self._mark_effect_completed(
            authorization,
            result_identity={"ref": ref, "sha": request.revert_candidate_commit},
        )
        return self._reference_snapshot(
            status="created",
            state=state,
            binding=binding,
            ref=ref,
            commit_sha=request.revert_candidate_commit,
        )

    def create_or_reconcile_revert_pull_request(
        self, command_key: str, request: RevertPullRequestRequest
    ) -> PullRequestEffectSnapshot | GitHubRetryDecision:
        """Create the exact main-bound revert PR, reconciling before any retry."""
        binding = revert_pull_request_binding(self._repository, request)
        state = self._resolve_effect_state(command_key, binding)
        try:
            return self._create_or_reconcile_revert_pull_request(state, binding, request)
        except _GitHubRateLimited as limited:
            return self._retry_decision(state, binding, limited)

    def _create_or_reconcile_revert_pull_request(
        self,
        state: CommandState,
        binding: GitHubCommandBinding,
        request: RevertPullRequestRequest,
    ) -> PullRequestEffectSnapshot:
        observations = self._authorize_observations(state, binding)
        self._require_head_ref(request.head_branch, request.head_sha, authorization=observations)
        existing = self._find_pull_request(request, authorization=observations)
        if existing is not None:
            self._require_exact_pull_create(existing, request)
            authorization = self._prepare_effect_authorization(state, binding)
            self._mark_effect_completed(
                authorization,
                result_identity={
                    "head_sha": existing.head_sha,
                    "number": existing.number,
                },
            )
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=existing
            )
        payload = {
            "base": request.base_branch,
            "body": request.body,
            "draft": request.draft,
            "head": request.head_branch,
            "title": request.title,
        }
        authorization = self._prepare_effect_authorization(state, binding)
        if not authorization.may_mutate:
            raise GitHubCloudError("github_revert_pull_create_uncertain")
        try:
            response = self._execute_bound_http(
                "POST",
                f"/repos/{self._repository}/pulls",
                body=payload,
                authorization=authorization,
            )
        except GitHubTransportError as error:
            if not error.ambiguous:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_transport_failed") from error
            self._require_head_ref(
                request.head_branch, request.head_sha, authorization=observations
            )
            reconciled = self._find_pull_request(request, authorization=observations)
            if reconciled is None:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_revert_pull_create_uncertain") from error
            self._require_exact_pull_create(reconciled, request)
            self._mark_effect_completed(
                authorization,
                result_identity={
                    "head_sha": reconciled.head_sha,
                    "number": reconciled.number,
                },
            )
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=reconciled
            )
        if response.status == 422:
            self._require_head_ref(
                request.head_branch, request.head_sha, authorization=observations
            )
            reconciled = self._find_pull_request(request, authorization=observations)
            if reconciled is None:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_revert_pull_create_uncertain")
            self._require_exact_pull_create(reconciled, request)
            self._mark_effect_completed(
                authorization,
                result_identity={
                    "head_sha": reconciled.head_sha,
                    "number": reconciled.number,
                },
            )
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=reconciled
            )
        if response.status != 201:
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_revert_pull_create_failed")
        created = self._parse_pull_request(_decode_json(response))
        if (
            created.base_branch != request.base_branch
            or created.head_branch != request.head_branch
            or created.head_sha != request.head_sha
        ):
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_pull_request_identity_conflict")
        self._require_exact_pull_create(created, request)
        self._mark_effect_completed(
            authorization,
            result_identity={"head_sha": created.head_sha, "number": created.number},
        )
        return self._pull_snapshot(status="created", state=state, binding=binding, observed=created)

    def _runs_path(self, request: CloudRunRequest) -> str:
        return f"/repos/{self._repository}/actions/workflows/{request.workflow_file}/runs"

    def _find_accepted_run(
        self,
        request: CloudRunRequest,
        binding: GitHubCommandBinding,
        *,
        authorization: _BoundObservation,
        dispatched_at: str,
    ) -> tuple[int, str] | None:
        dispatched = _utc(dispatched_at, "github_command_timestamp_invalid")
        latest = self._now() + timedelta(minutes=5)
        matches: list[tuple[int, str]] = []
        required_fields = {
            "actor",
            "conclusion",
            "created_at",
            "display_title",
            "event",
            "head_branch",
            "head_sha",
            "html_url",
            "id",
            "path",
            "repository",
            "status",
            "url",
        }
        documented_fields = required_fields | {
            "artifacts_url",
            "cancel_url",
            "check_suite_id",
            "check_suite_node_id",
            "check_suite_url",
            "jobs_url",
            "logs_url",
            "name",
            "node_id",
            "pull_requests",
            "rerun_url",
            "run_attempt",
            "run_number",
            "run_started_at",
            "triggering_actor",
            "updated_at",
            "workflow_id",
            "workflow_url",
        }
        path = self._runs_path(request)
        base_query = (
            ("actor", self._dispatch_actor_login),
            ("branch", self._workflow_ref),
            ("event", "workflow_dispatch"),
            ("head_sha", request.workflow_revision),
            ("per_page", "100"),
        )
        page = 1
        while True:
            query = (
                ("actor", self._dispatch_actor_login),
                ("branch", self._workflow_ref),
                ("event", "workflow_dispatch"),
                ("head_sha", request.workflow_revision),
                *((("page", str(page)),) if page > 1 else ()),
                ("per_page", "100"),
            )
            response = self._execute_bound_http(
                "GET", path, query=query, authorization=authorization
            )
            _rate_limit(response, now=self._now())
            if response.status != 200:
                raise GitHubCloudError("github_run_discovery_failed")
            decoded = _decode_json(response)
            if set(decoded) != {"total_count", "workflow_runs"}:
                raise GitHubCloudError("github_run_response_schema_invalid")
            total_count = decoded["total_count"]
            runs = decoded["workflow_runs"]
            if (
                isinstance(total_count, bool)
                or not isinstance(total_count, int)
                or total_count < 0
                or not isinstance(runs, list)
                or len(runs) > 100
                or total_count < len(runs)
            ):
                raise GitHubCloudError("github_run_response_schema_invalid")
            for run in runs:
                if type(run) is not dict or not required_fields <= set(run) <= documented_fields:
                    raise GitHubCloudError("github_run_response_schema_invalid")
                run_id = run["id"]
                if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
                    raise GitHubCloudError("github_run_response_schema_invalid")
                created_at = _utc(run["created_at"], "github_run_response_schema_invalid")
                if (
                    not isinstance(run["display_title"], str)
                    or not isinstance(run["head_branch"], str)
                    or not isinstance(run["head_sha"], str)
                    or _OBJECT_RE.fullmatch(run["head_sha"]) is None
                    or type(run["actor"]) is not dict
                    or not {"id", "login", "type"} <= set(run["actor"])
                    or isinstance(run["actor"]["id"], bool)
                    or not isinstance(run["actor"]["id"], int)
                    or run["actor"]["id"] <= 0
                    or not isinstance(run["actor"]["login"], str)
                    or run["actor"]["type"] not in {"Bot", "User"}
                    or type(run["repository"]) is not dict
                    or run["repository"].get("full_name") != self._repository
                    or not isinstance(run["path"], str)
                    or not isinstance(run["url"], str)
                    or not isinstance(run["html_url"], str)
                ):
                    raise GitHubCloudError("github_run_response_schema_invalid")
                expected_api = f"{_API_ORIGIN}/repos/{self._repository}"
                exact_urls = {
                    "artifacts_url": f"{expected_api}/actions/runs/{run_id}/artifacts",
                    "cancel_url": f"{expected_api}/actions/runs/{run_id}/cancel",
                    "check_suite_url": (f"{expected_api}/check-suites/{run.get('check_suite_id')}"),
                    "jobs_url": f"{expected_api}/actions/runs/{run_id}/jobs",
                    "logs_url": f"{expected_api}/actions/runs/{run_id}/logs",
                    "rerun_url": f"{expected_api}/actions/runs/{run_id}/rerun",
                    "workflow_url": f"{expected_api}/actions/workflows/{run.get('workflow_id')}",
                }
                if any(
                    run.get(name) != expected
                    for name, expected in exact_urls.items()
                    if name in run
                ):
                    raise GitHubCloudError("github_run_response_schema_invalid")
                for name in (
                    "check_suite_id",
                    "run_attempt",
                    "run_number",
                    "workflow_id",
                ):
                    if name in run and (
                        isinstance(run[name], bool)
                        or not isinstance(run[name], int)
                        or run[name] <= 0
                    ):
                        raise GitHubCloudError("github_run_response_schema_invalid")
                for name in ("run_started_at", "updated_at"):
                    if name in run:
                        _utc(run[name], "github_run_response_schema_invalid")
                if "pull_requests" in run and run["pull_requests"] != []:
                    raise GitHubCloudError("github_run_response_schema_invalid")
                if "triggering_actor" in run and (
                    type(run["triggering_actor"]) is not dict
                    or run["triggering_actor"].get("login") != self._dispatch_actor_login
                ):
                    raise GitHubCloudError("github_run_response_schema_invalid")
                if run["display_title"] != binding.attempt_key:
                    continue
                if (
                    run["event"] != "workflow_dispatch"
                    or run["head_branch"] != self._workflow_ref
                    or run["head_sha"] != request.workflow_revision
                    or run["path"] != f"{request.expected_workflow_path}@{self._workflow_ref}"
                    or run["actor"]["login"] != self._dispatch_actor_login
                    or run["url"] != f"{_API_ORIGIN}/repos/{self._repository}/actions/runs/{run_id}"
                    or run["html_url"]
                    != f"https://github.com/{self._repository}/actions/runs/{run_id}"
                    or not dispatched <= created_at <= latest
                ):
                    raise GitHubCloudError("github_dispatch_identity_conflict")
                if run["status"] not in {"queued", "in_progress", "completed"} or (
                    run["conclusion"] is not None
                    and run["conclusion"]
                    not in {
                        "action_required",
                        "cancelled",
                        "failure",
                        "neutral",
                        "skipped",
                        "stale",
                        "startup_failure",
                        "success",
                        "timed_out",
                    }
                ):
                    raise GitHubCloudError("github_run_response_schema_invalid")
                matches.append((run_id, run["head_sha"]))
            next_page = self._next_page(
                response,
                path=path,
                current_page=page,
                required_query=base_query,
            )
            if next_page is None:
                break
            if page >= _MAX_PAGES:
                raise GitHubCloudError("github_pagination_limit_exceeded")
            page = next_page
        if len(matches) > 1:
            raise GitHubCloudError("github_dispatch_identity_ambiguous")
        return matches[0] if matches else None

    def _next_page(
        self,
        response: GitHubHttpResponse,
        *,
        path: str,
        current_page: int,
        required_query: tuple[tuple[str, str], ...],
    ) -> int | None:
        raw_link = _response_headers(response).get("link")
        if raw_link is None:
            return None
        next_pages: list[int] = []
        for raw_item in raw_link.split(","):
            match = re.fullmatch(r'\s*<([^>]+)>;\s*rel="([a-z]+)"\s*', raw_item)
            if match is None:
                raise GitHubCloudError("github_pagination_link_invalid")
            parsed = urlsplit(match.group(1))
            if (
                parsed.scheme != "https"
                or parsed.netloc != "api.github.com"
                or parsed.path != path
                or parsed.fragment
            ):
                raise GitHubCloudError("github_pagination_link_invalid")
            try:
                pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
            except ValueError as error:
                raise GitHubCloudError("github_pagination_link_invalid") from error
            if len(pairs) != len({name for name, _ in pairs}):
                raise GitHubCloudError("github_pagination_link_invalid")
            query = dict(pairs)
            required = dict(required_query)
            if (
                len(required) != len(required_query)
                or set(query) != {*required, "page"}
                or any(query.get(name) != value for name, value in required.items())
                or match.group(2) not in {"first", "last", "next", "prev"}
            ):
                raise GitHubCloudError("github_pagination_link_invalid")
            if "page" not in query or re.fullmatch(r"[1-9][0-9]{0,3}", query["page"]) is None:
                raise GitHubCloudError("github_pagination_link_invalid")
            if match.group(2) == "next":
                next_pages.append(int(query["page"]))
        if not next_pages:
            return None
        if len(next_pages) != 1 or next_pages[0] != current_page + 1:
            raise GitHubCloudError("github_pagination_link_invalid")
        return next_pages[0]

    def _dispatch_snapshot(
        self,
        *,
        status: Literal["dispatched", "reconciled", "uncertain"],
        state: CommandState,
        request: CloudRunRequest,
        binding: GitHubCommandBinding,
        run: tuple[int, str] | None = None,
    ) -> WorkflowDispatchSnapshot:
        now = self._now().isoformat().replace("+00:00", "Z")
        return WorkflowDispatchSnapshot(
            status=status,
            repository=self._repository,
            workflow_file=request.workflow_file,
            workflow_revision=request.workflow_revision,
            request_key=binding.request_key,
            attempt_key=binding.attempt_key,
            effect_key=state.command.effect_key,
            command_occurred_at=state.command.occurred_at,
            observed_at=now,
            run_id=None if run is None else run[0],
            head_sha=None if run is None else run[1],
        )

    def dispatch_workflow(
        self, command_key: str, request: CloudRunRequest
    ) -> WorkflowDispatchSnapshot | GitHubRetryDecision:
        """Reconcile one exact workflow dispatch before and after its sole POST."""
        state = self._resolve_claimed_command(command_key, authority="coordinator")
        binding = self._require_dispatch_command(state, request)
        try:
            return self._dispatch_workflow(state, binding, request)
        except _GitHubRateLimited as limited:
            return self._retry_decision(state, binding, limited)

    def _dispatch_workflow(
        self,
        state: CommandState,
        binding: GitHubCommandBinding,
        request: CloudRunRequest,
    ) -> WorkflowDispatchSnapshot | GitHubRetryDecision:
        observations = self._authorize_observations(state, binding)
        try:
            existing = self._find_accepted_run(
                request,
                binding,
                authorization=observations,
                dispatched_at=state.command.occurred_at,
            )
        except _GitHubRateLimited as limited:
            return GitHubRetryDecision(
                status="retry_scheduled",
                reason="github_rate_limited",
                request_key=binding.request_key,
                attempt_key=binding.attempt_key,
                effect_key=state.command.effect_key,
                command_occurred_at=state.command.occurred_at,
                retry_not_before=limited.retry_not_before,
                attempt=state.command.attempt,
                max_attempts=state.command.max_attempts,
            )
        if existing is not None:
            authorization = self._prepare_effect_authorization(state, binding)
            self._mark_effect_completed(
                authorization,
                result_identity={"head_sha": existing[1], "run_id": existing[0]},
            )
            return self._dispatch_snapshot(
                status="reconciled",
                state=state,
                request=request,
                binding=binding,
                run=existing,
            )
        path = f"/repos/{self._repository}/actions/workflows/{request.workflow_file}/dispatches"
        authorization = self._prepare_effect_authorization(state, binding)
        if not authorization.may_mutate:
            return self._dispatch_snapshot(
                status="uncertain",
                state=state,
                request=request,
                binding=binding,
            )
        try:
            response = self._execute_bound_http(
                "POST",
                path,
                body=_dispatch_payload(
                    request,
                    state.command.attempt,
                    workflow_ref=self._workflow_ref,
                ),
                authorization=authorization,
            )
        except GitHubTransportError as error:
            if not error.ambiguous:
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_transport_failed") from error
            try:
                reconciled = self._find_accepted_run(
                    request,
                    binding,
                    authorization=observations,
                    dispatched_at=state.command.occurred_at,
                )
            except _GitHubRateLimited as limited:
                return GitHubRetryDecision(
                    status="retry_scheduled",
                    reason="github_rate_limited",
                    request_key=binding.request_key,
                    attempt_key=binding.attempt_key,
                    effect_key=state.command.effect_key,
                    command_occurred_at=state.command.occurred_at,
                    retry_not_before=limited.retry_not_before,
                    attempt=state.command.attempt,
                    max_attempts=state.command.max_attempts,
                )
            if reconciled is None:
                self._mark_effect_uncertain(authorization)
            else:
                self._mark_effect_completed(
                    authorization,
                    result_identity={"head_sha": reconciled[1], "run_id": reconciled[0]},
                )
            return self._dispatch_snapshot(
                status="reconciled" if reconciled is not None else "uncertain",
                state=state,
                request=request,
                binding=binding,
                run=reconciled,
            )
        if response.status == 204 and not response.body:
            self._mark_effect_completed(
                authorization,
                result_identity={"attempt_key": binding.attempt_key, "accepted": True},
            )
            return self._dispatch_snapshot(
                status="dispatched",
                state=state,
                request=request,
                binding=binding,
            )
        if response.status == 200:
            decoded = _decode_json(response)
            if not {"html_url", "run_url", "workflow_run_id"} <= set(decoded) <= {
                "html_url",
                "run_url",
                "status",
                "workflow_run_id",
            } or ("status" in decoded and decoded["status"] not in {"queued", "in_progress"}):
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_dispatch_response_invalid")
            run_id = decoded["workflow_run_id"]
            if (
                isinstance(run_id, bool)
                or not isinstance(run_id, int)
                or run_id <= 0
                or decoded["run_url"]
                != f"{_API_ORIGIN}/repos/{self._repository}/actions/runs/{run_id}"
                or decoded["html_url"]
                != f"https://github.com/{self._repository}/actions/runs/{run_id}"
            ):
                self._mark_effect_uncertain(authorization)
                raise GitHubCloudError("github_dispatch_response_invalid")
            run = (run_id, request.workflow_revision)
            self._mark_effect_completed(
                authorization,
                result_identity={
                    "attempt_key": binding.attempt_key,
                    "head_sha": request.workflow_revision,
                    "run_id": run_id,
                    "workflow_ref": self._workflow_ref,
                },
            )
            return self._dispatch_snapshot(
                status="dispatched",
                state=state,
                request=request,
                binding=binding,
                run=run,
            )
        else:
            self._mark_effect_uncertain(authorization)
            raise GitHubCloudError("github_dispatch_response_invalid")


_PRODUCTION_REPOSITORY = "StephenBickel/carl-agent"


def _ipc_effect_key(binding: GitHubCommandBinding) -> str:
    descriptor = {
        "authority": binding.authority,
        "command_key": binding.command_key,
        "operation": binding.operation,
        "request_digest": binding.request_digest,
    }
    return f"cloud-effect-{hashlib.sha256(canonical_json_bytes(descriptor)).hexdigest()}"


def _ipc_parameters(request: object) -> dict[str, object]:
    if isinstance(request, CloudRunRequest):
        excluded = {"dispatch_key", "request_digest", "schema_version"}
    else:
        excluded = set()
    try:
        fields = request.__dataclass_fields__
    except AttributeError as error:
        raise GitHubCloudError("github_operation_request_invalid") from error
    value: dict[str, object] = {}
    for name in fields:
        if name in excluded:
            continue
        item = getattr(request, name)
        value[name] = list(item) if isinstance(item, tuple) else item
    return value


def _result_from_ipc(
    response: GitHubEffectResponse,
    *,
    request: GitHubEffectRequest,
    expected_type: type,
) -> object:
    if response.status == "rejected":
        raise GitHubCloudError(response.error_code or "github_effect_service_rejected")
    if response.status == "retry_scheduled":
        attempt_match = re.search(r"-attempt-([1-3])$", request.command_key)
        attempt = int(attempt_match.group(1)) if attempt_match else 1
        return GitHubRetryDecision(
            status="retry_scheduled",
            reason="github_rate_limited",
            request_key=request.request_key,
            attempt_key=request.command_key,
            effect_key=request.effect_key,
            command_occurred_at=request.occurred_at,
            retry_not_before=response.retry_not_before or request.occurred_at,
            attempt=attempt,
            max_attempts=3,
        )
    if response.status != "completed" or type(response.result) is not dict:
        raise GitHubCloudError("github_effect_service_response_invalid")
    if set(response.result) != {"result_type", "value"}:
        raise GitHubCloudError("github_effect_service_response_invalid")
    if response.result["result_type"] != expected_type.__name__:
        raise GitHubCloudError("github_effect_service_response_invalid")
    value = response.result["value"]
    if type(value) is not dict:
        raise GitHubCloudError("github_effect_service_response_invalid")
    if expected_type is RequiredChecksSnapshot:
        decoded = dict(value)
        checks = decoded.get("checks")
        if type(checks) is not list:
            raise GitHubCloudError("github_effect_service_response_invalid")
        decoded["checks"] = tuple(RequiredCheckObservation(**item) for item in checks)
        value = decoded
    try:
        return expected_type(**value)
    except (TypeError, ValueError) as error:
        raise GitHubCloudError("github_effect_service_response_invalid") from error


class GitHubCloudGateway:
    """Credential-free typed facade over the protected Unix-socket service."""

    __slots__ = ("_client",)

    def __new__(cls, *args: object, **kwargs: object) -> GitHubCloudGateway:
        del cls, args, kwargs
        raise GitHubCloudError("github_protected_configuration_required")

    @classmethod
    def _for_testing(
        cls,
        *,
        repository: str,
        token: str,
        transport: GitHubHttpTransport,
        clock: Callable[[], datetime],
        state_controller: GitHubEffectStateController | None = None,
        workflow_ref: str = _DEFAULT_WORKFLOW_REF,
        dispatch_actor_login: str = _DEFAULT_DISPATCH_ACTOR_LOGIN,
    ) -> _InjectedGitHubCloudGateway:
        del cls
        return _InjectedGitHubCloudGateway._for_testing(
            repository=repository,
            token=token,
            transport=transport,
            clock=clock,
            state_controller=state_controller,
            workflow_ref=workflow_ref,
            dispatch_actor_login=dispatch_actor_login,
        )

    @classmethod
    def from_protected_environment(cls) -> GitHubCloudGateway:
        """Return a client that never reads credentials or protected state."""
        gateway = object.__new__(cls)
        gateway._client = GitHubEffectSocketClient.from_protected_environment()
        return gateway

    def _execute_ipc(
        self,
        *,
        operation: GitHubEffectOperation,
        command_key: str,
        occurred_at: str,
        typed_request: object,
        binding: GitHubCommandBinding,
        expected_type: type,
    ) -> object:
        request = GitHubEffectRequest.from_canonical_dict(
            {
                "command_key": command_key,
                "domain": REQUEST_DOMAIN,
                "effect_key": _ipc_effect_key(binding),
                "occurred_at": occurred_at,
                "operation": operation.value,
                "parameters": _ipc_parameters(typed_request),
                "request_key": binding.request_key,
                "schema_version": 1,
            }
        )
        if command_key != binding.command_key:
            raise GitHubCloudError("github_command_binding_mismatch")
        return _result_from_ipc(
            self._client.execute(request), request=request, expected_type=expected_type
        )

    def create_or_reconcile_experimental_branch(
        self, command_key: str, request: ExperimentalBranchRequest, *, occurred_at: str
    ) -> GitReferenceSnapshot | GitHubRetryDecision:
        return self._execute_ipc(
            operation=GitHubEffectOperation.CREATE_EXPERIMENTAL_REF,
            command_key=command_key,
            occurred_at=occurred_at,
            typed_request=request,
            binding=experimental_branch_binding(_PRODUCTION_REPOSITORY, request),
            expected_type=GitReferenceSnapshot,
        )

    def create_or_reconcile_pull_request(
        self, command_key: str, request: PullRequestCreateRequest, *, occurred_at: str
    ) -> PullRequestEffectSnapshot | GitHubRetryDecision:
        return self._execute_ipc(
            operation=GitHubEffectOperation.CREATE_PULL_REQUEST,
            command_key=command_key,
            occurred_at=occurred_at,
            typed_request=request,
            binding=pull_request_create_binding(_PRODUCTION_REPOSITORY, request),
            expected_type=PullRequestEffectSnapshot,
        )

    def create_or_reconcile_revert_branch(
        self, command_key: str, request: RevertBranchRequest, *, occurred_at: str
    ) -> GitReferenceSnapshot | GitHubRetryDecision:
        return self._execute_ipc(
            operation=GitHubEffectOperation.CREATE_REVERT_REF,
            command_key=command_key,
            occurred_at=occurred_at,
            typed_request=request,
            binding=revert_branch_binding(_PRODUCTION_REPOSITORY, request),
            expected_type=GitReferenceSnapshot,
        )

    def create_or_reconcile_revert_pull_request(
        self, command_key: str, request: RevertPullRequestRequest, *, occurred_at: str
    ) -> PullRequestEffectSnapshot | GitHubRetryDecision:
        return self._execute_ipc(
            operation=GitHubEffectOperation.CREATE_REVERT_PULL_REQUEST,
            command_key=command_key,
            occurred_at=occurred_at,
            typed_request=request,
            binding=revert_pull_request_binding(_PRODUCTION_REPOSITORY, request),
            expected_type=PullRequestEffectSnapshot,
        )

    def dispatch_workflow(
        self, command_key: str, request: CloudRunRequest, *, occurred_at: str
    ) -> WorkflowDispatchSnapshot | GitHubRetryDecision:
        attempt_match = re.search(r"-attempt-([1-3])$", command_key)
        if attempt_match is None:
            raise GitHubCloudError("github_command_binding_mismatch")
        return self._execute_ipc(
            operation=GitHubEffectOperation.DISPATCH_WORKFLOW,
            command_key=command_key,
            occurred_at=occurred_at,
            typed_request=request,
            binding=workflow_dispatch_binding(request, attempt=int(attempt_match.group(1))),
            expected_type=WorkflowDispatchSnapshot,
        )

    def enable_pull_request_auto_merge(
        self, command_key: str, request: PullRequestAutoMergeRequest, *, occurred_at: str
    ) -> PullRequestEffectSnapshot | GitHubRetryDecision:
        return self._execute_ipc(
            operation=GitHubEffectOperation.ENABLE_PULL_REQUEST_AUTO_MERGE,
            command_key=command_key,
            occurred_at=occurred_at,
            typed_request=request,
            binding=pull_request_auto_merge_binding(_PRODUCTION_REPOSITORY, request),
            expected_type=PullRequestEffectSnapshot,
        )

    def mark_pull_request_ready(
        self, command_key: str, request: PullRequestReadyRequest, *, occurred_at: str
    ) -> PullRequestEffectSnapshot | GitHubRetryDecision:
        return self._execute_ipc(
            operation=GitHubEffectOperation.MARK_PULL_REQUEST_READY,
            command_key=command_key,
            occurred_at=occurred_at,
            typed_request=request,
            binding=pull_request_ready_binding(_PRODUCTION_REPOSITORY, request),
            expected_type=PullRequestEffectSnapshot,
        )

    def observe_required_checks(
        self, command_key: str, request: RequiredChecksRequest, *, occurred_at: str
    ) -> RequiredChecksSnapshot | GitHubRetryDecision:
        return self._execute_ipc(
            operation=GitHubEffectOperation.OBSERVE_REQUIRED_CHECKS,
            command_key=command_key,
            occurred_at=occurred_at,
            typed_request=request,
            binding=required_checks_binding(_PRODUCTION_REPOSITORY, request),
            expected_type=RequiredChecksSnapshot,
        )

    def update_pull_request(
        self, command_key: str, request: PullRequestUpdateRequest, *, occurred_at: str
    ) -> PullRequestEffectSnapshot | GitHubRetryDecision:
        return self._execute_ipc(
            operation=GitHubEffectOperation.UPDATE_PULL_REQUEST,
            command_key=command_key,
            occurred_at=occurred_at,
            typed_request=request,
            binding=pull_request_update_binding(_PRODUCTION_REPOSITORY, request),
            expected_type=PullRequestEffectSnapshot,
        )
