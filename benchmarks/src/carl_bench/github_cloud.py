"""Closed, replay-safe GitHub effects for the autonomous cloud controller."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import parse_qsl, urlsplit

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_execution import CloudRunRequest
from carl_bench.cloud_state import CommandState
from carl_bench.github_promotion import APPROVED_REQUIRED_CHECKS

_API_ORIGIN = "https://api.github.com"
_PROTECTED_CONFIG_DIR = Path("/etc/carl")
_PROTECTED_CONFIG_NAME = "github-cloud-policy.json"
_PROTECTED_TOKEN_ENV = "CARL_GITHUB_APP_INSTALLATION_TOKEN"
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
_PRIVATE_CONSTRUCTION_KEY = object()
_MAX_RESPONSE_BYTES = 262_144
_MAX_PAGES = 5


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


def _dispatch_payload(request: CloudRunRequest, attempt: int) -> dict[str, Any]:
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
            "workflow_blob_digest": request.workflow_blob_digest,
        },
        "ref": request.workflow_revision,
    }


def workflow_dispatch_binding(request: CloudRunRequest, *, attempt: int) -> GitHubCommandBinding:
    """Build the exact descriptor a coordinator must persist before dispatch."""
    if not isinstance(request, CloudRunRequest):
        raise GitHubCloudError("github_dispatch_request_invalid")
    attempt_key = request.attempt_key(attempt)
    payload_digest = hashlib.sha256(
        canonical_json_bytes(_dispatch_payload(request, attempt))
    ).hexdigest()
    descriptor = {
        "action": "dispatch_workflow",
        "attempt_key": attempt_key,
        "endpoint_id": "workflow_dispatch",
        "method": "POST",
        "payload_digest": payload_digest,
        "repository": request.repository,
        "request_key": request.dispatch_key,
        "schema_version": 1,
        "target_identity": f"{request.workflow_file}@{request.workflow_revision}",
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
        method="PUT",
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
    if headers.get("x-ratelimit-remaining") != "0":
        return
    raw_reset = headers.get("x-ratelimit-reset")
    if raw_reset is None or re.fullmatch(r"[0-9]{10}", raw_reset) is None:
        raise GitHubCloudError("github_rate_limit_invalid")
    reset = datetime.fromtimestamp(int(raw_reset), tz=UTC)
    if not now < reset <= now + timedelta(hours=24):
        raise GitHubCloudError("github_rate_limit_invalid")
    raise _GitHubRateLimited(reset.isoformat().replace("+00:00", "Z"))


def _load_protected_policy() -> str:
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
        or set(decoded) != {"api_origin", "repository", "schema_version"}
        or decoded["api_origin"] != _API_ORIGIN
        or isinstance(decoded["schema_version"], bool)
        or decoded["schema_version"] != 1
        or not isinstance(decoded["repository"], str)
        or _REPOSITORY_RE.fullmatch(decoded["repository"]) is None
        or canonical_json_bytes(decoded) != payload
    ):
        raise GitHubCloudError("github_protected_configuration_invalid")
    return decoded["repository"]


class GitHubCloudGateway:
    """Narrow GitHub client; production construction is owned by protected provisioning."""

    def __init__(
        self,
        *,
        repository: str,
        token: str,
        transport: GitHubHttpTransport,
        clock: Callable[[], datetime],
        _construction_key: object | None = None,
    ) -> None:
        if _construction_key is not _PRIVATE_CONSTRUCTION_KEY:
            raise GitHubCloudError("github_protected_configuration_required")
        if not isinstance(repository, str) or _REPOSITORY_RE.fullmatch(repository) is None:
            raise GitHubCloudError("github_repository_invalid")
        if not isinstance(token, str) or not token or len(token.encode()) > 4_096:
            raise GitHubCloudError("github_credentials_invalid")
        if not callable(getattr(transport, "send", None)) or not callable(clock):
            raise GitHubCloudError("github_protected_configuration_invalid")
        self._repository = repository
        self._token = token
        self._transport = transport
        self._clock = clock

    @classmethod
    def _for_testing(
        cls,
        *,
        repository: str,
        token: str,
        transport: GitHubHttpTransport,
        clock: Callable[[], datetime],
    ) -> GitHubCloudGateway:
        return cls(
            repository=repository,
            token=token,
            transport=transport,
            clock=clock,
            _construction_key=_PRIVATE_CONSTRUCTION_KEY,
        )

    @classmethod
    def from_protected_environment(
        cls,
        *,
        transport: GitHubHttpTransport,
        clock: Callable[[], datetime],
    ) -> GitHubCloudGateway:
        """Load the fixed root-controlled policy and controller-only installation token."""
        repository = _load_protected_policy()
        token = os.environ.get(_PROTECTED_TOKEN_ENV)
        if token is None:
            raise GitHubCloudError("github_credentials_missing")
        return cls(
            repository=repository,
            token=token,
            transport=transport,
            clock=clock,
            _construction_key=_PRIVATE_CONSTRUCTION_KEY,
        )

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo != UTC:
            raise GitHubCloudError("github_clock_invalid")
        return now

    def _request(
        self,
        method: Literal["GET", "POST", "PATCH", "PUT"],
        path: str,
        *,
        query: tuple[tuple[str, str], ...] = (),
        body: dict[str, Any] | None = None,
    ) -> GitHubHttpResponse:
        self._validate_endpoint(method=method, path=path, query=query, body=body)
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
        return response

    def _validate_endpoint(
        self,
        *,
        method: object,
        path: object,
        query: object,
        body: object,
    ) -> None:
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
        workflow_match = re.fullmatch(
            re.escape(root)
            + r"/actions/workflows/"
            + r"(autonomous-improvement\.yml|autonomous-soak\.yml)/(runs|dispatches)",
            path,
        )
        if workflow_match is not None:
            if workflow_match.group(2) == "runs":
                allowed_query = {"branch", "event", "per_page"}
                if "page" in query_values:
                    allowed_query.add("page")
                if (
                    method != "GET"
                    or body is not None
                    or set(query_values) != allowed_query
                    or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", query_values["branch"]) is None
                    or query_values["event"] != "workflow_dispatch"
                    or query_values["per_page"] != "100"
                    or (
                        "page" in query_values
                        and re.fullmatch(r"[2-9][0-9]{0,3}", query_values["page"]) is None
                    )
                ):
                    raise GitHubCloudError("github_endpoint_not_allowed")
                return
            if (
                method != "POST"
                or query
                or type(body) is not dict
                or set(body) != {"inputs", "ref"}
                or not isinstance(body["ref"], str)
                or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", body["ref"]) is None
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
                    "workflow_blob_digest",
                }
                or any(
                    not isinstance(value, str) or not value or len(value) > 192
                    for value in body["inputs"].values()
                )
            ):
                raise GitHubCloudError("github_endpoint_not_allowed")
            return

        ref_match = re.fullmatch(
            re.escape(root)
            + r"/git/ref/heads/(experimental|revert)/[A-Za-z0-9][A-Za-z0-9._-]{0,95}",
            path,
        )
        if ref_match is not None:
            if method != "GET" or query or body is not None:
                raise GitHubCloudError("github_endpoint_not_allowed")
            return
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
            return

        if path == f"{root}/pulls":
            if method == "GET":
                owner = self._repository.split("/", 1)[0]
                if (
                    body is not None
                    or set(query_values) != {"base", "head", "per_page", "state"}
                    or query_values["base"] != "main"
                    or re.fullmatch(
                        re.escape(owner)
                        + r":(experimental|revert)/[A-Za-z0-9][A-Za-z0-9._-]{0,95}",
                        query_values["head"],
                    )
                    is None
                    or query_values["per_page"] != "100"
                    or query_values["state"] != "all"
                ):
                    raise GitHubCloudError("github_endpoint_not_allowed")
                return
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
            return

        pull_match = re.fullmatch(re.escape(root) + r"/pulls/([1-9][0-9]{0,9})(.*)", path)
        if pull_match is not None:
            suffix = pull_match.group(2)
            if not query and suffix == "" and method == "GET" and body is None:
                return
            if (
                not query
                and suffix == ""
                and method == "PATCH"
                and type(body) is dict
                and set(body) == {"body", "title"}
            ):
                return
            if not query and suffix == "/ready_for_review" and method == "POST" and body == {}:
                return
            if (
                not query
                and suffix == "/auto-merge"
                and method == "PUT"
                and body == {"merge_method": "squash"}
            ):
                return
            raise GitHubCloudError("github_endpoint_not_allowed")

        checks_match = re.fullmatch(re.escape(root) + r"/commits/[0-9a-f]{40}/check-runs", path)
        if checks_match is not None and (
            method == "GET"
            and body is None
            and query_values == {"filter": "latest", "per_page": "100"}
        ):
            return
        raise GitHubCloudError("github_endpoint_not_allowed")

    def _require_dispatch_command(
        self, state: CommandState, request: CloudRunRequest
    ) -> GitHubCommandBinding:
        if not isinstance(state, CommandState) or state.status != "claimed" or state.claim is None:
            raise GitHubCloudError("github_command_not_claimed")
        if request.repository != self._repository:
            raise GitHubCloudError("github_repository_policy_mismatch")
        command = state.command
        binding = workflow_dispatch_binding(request, attempt=command.attempt)
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

    def _read_ref(self, ref: str) -> str | None:
        path = f"/repos/{self._repository}/git/ref/{ref.removeprefix('refs/')}"
        response = self._request("GET", path)
        _rate_limit(response, now=self._now())
        if response.status == 404:
            decoded = _decode_json(response)
            if decoded != {"message": "Not Found"}:
                raise GitHubCloudError("github_ref_response_schema_invalid")
            return None
        if response.status != 200:
            raise GitHubCloudError("github_ref_observation_failed")
        decoded = _decode_json(response)
        if set(decoded) != {"object", "ref"} or decoded["ref"] != ref:
            raise GitHubCloudError("github_ref_response_schema_invalid")
        target = decoded["object"]
        if (
            type(target) is not dict
            or set(target) != {"sha", "type"}
            or target["type"] != "commit"
            or not isinstance(target["sha"], str)
            or _OBJECT_RE.fullmatch(target["sha"]) is None
        ):
            raise GitHubCloudError("github_ref_response_schema_invalid")
        return target["sha"]

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
        self, state: CommandState, request: ExperimentalBranchRequest
    ) -> GitReferenceSnapshot:
        """Create one immutable experimental ref, or reconcile its exact identity."""
        binding = experimental_branch_binding(self._repository, request)
        self._require_effect_command(state, binding)
        ref = f"refs/heads/{request.branch}"
        existing = self._read_ref(ref)
        if existing is not None:
            if existing != request.candidate_commit:
                raise GitHubCloudError("github_immutable_ref_conflict")
            return self._reference_snapshot(
                status="reconciled",
                state=state,
                binding=binding,
                ref=ref,
                commit_sha=existing,
            )
        try:
            response = self._request(
                "POST",
                f"/repos/{self._repository}/git/refs",
                body={"ref": ref, "sha": request.candidate_commit},
            )
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise GitHubCloudError("github_transport_failed") from error
            reconciled = self._read_ref(ref)
            if reconciled is not None and reconciled != request.candidate_commit:
                raise GitHubCloudError("github_immutable_ref_conflict") from error
            return self._reference_snapshot(
                status="reconciled" if reconciled is not None else "uncertain",
                state=state,
                binding=binding,
                ref=ref,
                commit_sha=request.candidate_commit,
            )
        if response.status != 201:
            raise GitHubCloudError("github_ref_create_failed")
        decoded = _decode_json(response)
        if (
            set(decoded) != {"object", "ref"}
            or decoded["ref"] != ref
            or type(decoded["object"]) is not dict
            or decoded["object"] != {"sha": request.candidate_commit, "type": "commit"}
        ):
            raise GitHubCloudError("github_ref_response_schema_invalid")
        return self._reference_snapshot(
            status="created",
            state=state,
            binding=binding,
            ref=ref,
            commit_sha=request.candidate_commit,
        )

    def _parse_pull_request(self, value: object) -> _PullRequestObservation:
        fields = {
            "auto_merge",
            "base",
            "body",
            "draft",
            "head",
            "html_url",
            "number",
            "state",
            "title",
        }
        if type(value) is not dict or set(value) != fields:
            raise GitHubCloudError("github_pull_response_schema_invalid")
        base = value["base"]
        head = value["head"]
        if (
            type(base) is not dict
            or set(base) != {"ref"}
            or type(head) is not dict
            or set(head) != {"ref", "sha"}
        ):
            raise GitHubCloudError("github_pull_response_schema_invalid")
        number = value["number"]
        url = value["html_url"]
        title = value["title"]
        body = value["body"]
        if (
            isinstance(number, bool)
            or not isinstance(number, int)
            or number <= 0
            or not isinstance(url, str)
            or url != f"https://github.com/{self._repository}/pull/{number}"
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
        return _PullRequestObservation(
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
        self, request: PullRequestCreateRequest | RevertPullRequestRequest
    ) -> _PullRequestObservation | None:
        owner = self._repository.split("/", 1)[0]
        response = self._request(
            "GET",
            f"/repos/{self._repository}/pulls",
            query=(
                ("base", request.base_branch),
                ("head", f"{owner}:{request.head_branch}"),
                ("per_page", "100"),
                ("state", "all"),
            ),
        )
        _rate_limit(response, now=self._now())
        if response.status != 200:
            raise GitHubCloudError("github_pull_observation_failed")
        decoded = _decode_json_value(response)
        if not isinstance(decoded, list) or len(decoded) > 100:
            raise GitHubCloudError("github_pull_response_schema_invalid")
        observations = [self._parse_pull_request(value) for value in decoded]
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
        self, state: CommandState, request: PullRequestCreateRequest
    ) -> PullRequestEffectSnapshot:
        """Create the exact production PR, reconciling an existing identity first."""
        binding = pull_request_create_binding(self._repository, request)
        self._require_effect_command(state, binding)
        existing = self._find_pull_request(request)
        if existing is not None:
            self._require_exact_pull_create(existing, request)
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
        try:
            response = self._request("POST", f"/repos/{self._repository}/pulls", body=payload)
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise GitHubCloudError("github_transport_failed") from error
            reconciled = self._find_pull_request(request)
            if reconciled is None:
                raise GitHubCloudError("github_pull_create_uncertain") from error
            self._require_exact_pull_create(reconciled, request)
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=reconciled
            )
        if response.status != 201:
            raise GitHubCloudError("github_pull_create_failed")
        created = self._parse_pull_request(_decode_json(response))
        if (
            created.base_branch != request.base_branch
            or created.head_branch != request.head_branch
            or created.head_sha != request.head_sha
        ):
            raise GitHubCloudError("github_pull_request_identity_conflict")
        self._require_exact_pull_create(created, request)
        return self._pull_snapshot(status="created", state=state, binding=binding, observed=created)

    def _get_pull_request(self, number: int) -> _PullRequestObservation:
        response = self._request("GET", f"/repos/{self._repository}/pulls/{number}")
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

    def update_pull_request(
        self, state: CommandState, request: PullRequestUpdateRequest
    ) -> PullRequestEffectSnapshot:
        """Narrowly update title and body for one exact open pull request."""
        binding = pull_request_update_binding(self._repository, request)
        self._require_effect_command(state, binding)
        observed = self._get_pull_request(request.number)
        self._require_pull_target(
            observed,
            number=request.number,
            base_branch=request.base_branch,
            head_branch=request.head_branch,
            head_sha=request.head_sha,
        )
        if observed.title == request.title and observed.body == request.body:
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=observed
            )
        try:
            response = self._request(
                "PATCH",
                f"/repos/{self._repository}/pulls/{request.number}",
                body={"body": request.body, "title": request.title},
            )
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise GitHubCloudError("github_transport_failed") from error
            reconciled = self._get_pull_request(request.number)
            self._require_pull_target(
                reconciled,
                number=request.number,
                base_branch=request.base_branch,
                head_branch=request.head_branch,
                head_sha=request.head_sha,
            )
            if reconciled.title != request.title or reconciled.body != request.body:
                raise GitHubCloudError("github_pull_update_uncertain") from error
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=reconciled
            )
        if response.status != 200:
            raise GitHubCloudError("github_pull_update_failed")
        updated = self._parse_pull_request(_decode_json(response))
        self._require_pull_target(
            updated,
            number=request.number,
            base_branch=request.base_branch,
            head_branch=request.head_branch,
            head_sha=request.head_sha,
        )
        if updated.title != request.title or updated.body != request.body:
            raise GitHubCloudError("github_pull_update_response_mismatch")
        return self._pull_snapshot(status="updated", state=state, binding=binding, observed=updated)

    def mark_pull_request_ready(
        self, state: CommandState, request: PullRequestReadyRequest
    ) -> PullRequestEffectSnapshot:
        """Mark one exact draft ready, reconciling before and after its sole effect."""
        binding = pull_request_ready_binding(self._repository, request)
        self._require_effect_command(state, binding)
        observed = self._get_pull_request(request.number)
        self._require_pull_target(
            observed,
            number=request.number,
            base_branch=request.base_branch,
            head_branch=request.head_branch,
            head_sha=request.head_sha,
        )
        if not observed.draft:
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=observed
            )
        path = f"/repos/{self._repository}/pulls/{request.number}/ready_for_review"
        try:
            response = self._request("POST", path, body={})
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise GitHubCloudError("github_transport_failed") from error
            reconciled = self._get_pull_request(request.number)
            self._require_pull_target(
                reconciled,
                number=request.number,
                base_branch=request.base_branch,
                head_branch=request.head_branch,
                head_sha=request.head_sha,
            )
            if reconciled.draft:
                raise GitHubCloudError("github_ready_transition_uncertain") from error
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=reconciled
            )
        if response.status != 200:
            raise GitHubCloudError("github_ready_transition_failed")
        ready = self._parse_pull_request(_decode_json(response))
        self._require_pull_target(
            ready,
            number=request.number,
            base_branch=request.base_branch,
            head_branch=request.head_branch,
            head_sha=request.head_sha,
        )
        if ready.draft:
            raise GitHubCloudError("github_ready_transition_response_mismatch")
        return self._pull_snapshot(status="updated", state=state, binding=binding, observed=ready)

    def enable_pull_request_auto_merge(
        self, state: CommandState, request: PullRequestAutoMergeRequest
    ) -> PullRequestEffectSnapshot:
        """Enable squash auto-merge for one exact, ready pull request."""
        binding = pull_request_auto_merge_binding(self._repository, request)
        self._require_effect_command(state, binding)
        observed = self._get_pull_request(request.number)
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
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=observed
            )
        path = f"/repos/{self._repository}/pulls/{request.number}/auto-merge"
        payload = {"merge_method": request.merge_method}
        try:
            response = self._request("PUT", path, body=payload)
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise GitHubCloudError("github_transport_failed") from error
            reconciled = self._get_pull_request(request.number)
            self._require_pull_target(
                reconciled,
                number=request.number,
                base_branch=request.base_branch,
                head_branch=request.head_branch,
                head_sha=request.head_sha,
            )
            if not reconciled.auto_merge_enabled:
                raise GitHubCloudError("github_auto_merge_uncertain") from error
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=reconciled
            )
        if response.status != 200:
            raise GitHubCloudError("github_auto_merge_failed")
        enabled = self._parse_pull_request(_decode_json(response))
        self._require_pull_target(
            enabled,
            number=request.number,
            base_branch=request.base_branch,
            head_branch=request.head_branch,
            head_sha=request.head_sha,
        )
        if not enabled.auto_merge_enabled:
            raise GitHubCloudError("github_auto_merge_response_mismatch")
        return self._pull_snapshot(status="updated", state=state, binding=binding, observed=enabled)

    def observe_required_checks(
        self, state: CommandState, request: RequiredChecksRequest
    ) -> RequiredChecksSnapshot:
        """Observe approved checks only when every returned run binds the exact head."""
        binding = required_checks_binding(self._repository, request)
        self._require_effect_command(state, binding)
        response = self._request(
            "GET",
            f"/repos/{self._repository}/commits/{request.head_sha}/check-runs",
            query=(("filter", "latest"), ("per_page", "100")),
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
            if type(value) is not dict or set(value) != {
                "app",
                "conclusion",
                "head_sha",
                "name",
                "status",
            }:
                raise GitHubCloudError("github_check_response_schema_invalid")
            app = value["app"]
            if type(app) is not dict or set(app) != {"id"}:
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
        self, state: CommandState, request: RevertBranchRequest
    ) -> GitReferenceSnapshot:
        """Create the exact protected revert candidate ref without moving any existing ref."""
        binding = revert_branch_binding(self._repository, request)
        self._require_effect_command(state, binding)
        ref = f"refs/heads/{request.branch}"
        existing = self._read_ref(ref)
        if existing is not None:
            if existing != request.revert_candidate_commit:
                raise GitHubCloudError("github_immutable_ref_conflict")
            return self._reference_snapshot(
                status="reconciled",
                state=state,
                binding=binding,
                ref=ref,
                commit_sha=existing,
            )
        try:
            response = self._request(
                "POST",
                f"/repos/{self._repository}/git/refs",
                body={"ref": ref, "sha": request.revert_candidate_commit},
            )
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise GitHubCloudError("github_transport_failed") from error
            reconciled = self._read_ref(ref)
            if reconciled is not None and reconciled != request.revert_candidate_commit:
                raise GitHubCloudError("github_immutable_ref_conflict") from error
            return self._reference_snapshot(
                status="reconciled" if reconciled is not None else "uncertain",
                state=state,
                binding=binding,
                ref=ref,
                commit_sha=request.revert_candidate_commit,
            )
        if response.status != 201:
            raise GitHubCloudError("github_ref_create_failed")
        decoded = _decode_json(response)
        if (
            set(decoded) != {"object", "ref"}
            or decoded["ref"] != ref
            or decoded["object"] != {"sha": request.revert_candidate_commit, "type": "commit"}
        ):
            raise GitHubCloudError("github_ref_response_schema_invalid")
        return self._reference_snapshot(
            status="created",
            state=state,
            binding=binding,
            ref=ref,
            commit_sha=request.revert_candidate_commit,
        )

    def create_or_reconcile_revert_pull_request(
        self, state: CommandState, request: RevertPullRequestRequest
    ) -> PullRequestEffectSnapshot:
        """Create the exact main-bound revert PR, reconciling before any retry."""
        binding = revert_pull_request_binding(self._repository, request)
        self._require_effect_command(state, binding)
        existing = self._find_pull_request(request)
        if existing is not None:
            self._require_exact_pull_create(existing, request)
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
        try:
            response = self._request("POST", f"/repos/{self._repository}/pulls", body=payload)
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise GitHubCloudError("github_transport_failed") from error
            reconciled = self._find_pull_request(request)
            if reconciled is None:
                raise GitHubCloudError("github_revert_pull_create_uncertain") from error
            self._require_exact_pull_create(reconciled, request)
            return self._pull_snapshot(
                status="reconciled", state=state, binding=binding, observed=reconciled
            )
        if response.status != 201:
            raise GitHubCloudError("github_revert_pull_create_failed")
        created = self._parse_pull_request(_decode_json(response))
        if (
            created.base_branch != request.base_branch
            or created.head_branch != request.head_branch
            or created.head_sha != request.head_sha
        ):
            raise GitHubCloudError("github_pull_request_identity_conflict")
        self._require_exact_pull_create(created, request)
        return self._pull_snapshot(status="created", state=state, binding=binding, observed=created)

    def _runs_path(self, request: CloudRunRequest) -> str:
        return f"/repos/{self._repository}/actions/workflows/{request.workflow_file}/runs"

    def _find_accepted_run(
        self,
        request: CloudRunRequest,
        binding: GitHubCommandBinding,
        *,
        dispatched_at: str,
    ) -> tuple[int, str] | None:
        dispatched = _utc(dispatched_at, "github_command_timestamp_invalid")
        latest = self._now() + timedelta(minutes=5)
        matches: list[tuple[int, str]] = []
        expected_fields = {
            "conclusion",
            "created_at",
            "display_title",
            "event",
            "head_branch",
            "head_sha",
            "id",
            "path",
            "status",
        }
        path = self._runs_path(request)
        page = 1
        while True:
            query = (
                ("branch", request.workflow_revision),
                ("event", "workflow_dispatch"),
                *((("page", str(page)),) if page > 1 else ()),
                ("per_page", "100"),
            )
            response = self._request("GET", path, query=query)
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
                if type(run) is not dict or set(run) != expected_fields:
                    raise GitHubCloudError("github_run_response_schema_invalid")
                run_id = run["id"]
                if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
                    raise GitHubCloudError("github_run_response_schema_invalid")
                created_at = _utc(run["created_at"], "github_run_response_schema_invalid")
                if not isinstance(run["display_title"], str):
                    raise GitHubCloudError("github_run_response_schema_invalid")
                if run["display_title"] != binding.attempt_key:
                    continue
                if (
                    run["event"] != "workflow_dispatch"
                    or run["head_branch"] != request.workflow_revision
                    or run["head_sha"] != request.workflow_revision
                    or run["path"] != request.expected_workflow_path
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
            next_page = self._next_page(response, path=path, current_page=page)
            if next_page is None:
                break
            if page >= _MAX_PAGES:
                raise GitHubCloudError("github_pagination_limit_exceeded")
            page = next_page
        if len(matches) > 1:
            raise GitHubCloudError("github_dispatch_identity_ambiguous")
        return matches[0] if matches else None

    def _next_page(
        self, response: GitHubHttpResponse, *, path: str, current_page: int
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
            if not set(query) <= {"branch", "event", "page", "per_page"}:
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
        self, state: CommandState, request: CloudRunRequest
    ) -> WorkflowDispatchSnapshot | GitHubRetryDecision:
        """Reconcile one exact workflow dispatch before and after its sole POST."""
        binding = self._require_dispatch_command(state, request)
        try:
            existing = self._find_accepted_run(
                request,
                binding,
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
            return self._dispatch_snapshot(
                status="reconciled",
                state=state,
                request=request,
                binding=binding,
                run=existing,
            )
        path = f"/repos/{self._repository}/actions/workflows/{request.workflow_file}/dispatches"
        try:
            response = self._request(
                "POST",
                path,
                body=_dispatch_payload(request, state.command.attempt),
            )
        except GitHubTransportError as error:
            if not error.ambiguous:
                raise GitHubCloudError("github_transport_failed") from error
            try:
                reconciled = self._find_accepted_run(
                    request,
                    binding,
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
            return self._dispatch_snapshot(
                status="reconciled" if reconciled is not None else "uncertain",
                state=state,
                request=request,
                binding=binding,
                run=reconciled,
            )
        if response.status != 204 or response.body:
            raise GitHubCloudError("github_dispatch_response_invalid")
        return self._dispatch_snapshot(
            status="dispatched",
            state=state,
            request=request,
            binding=binding,
        )
