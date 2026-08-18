"""Deterministic GitHub promotion and exact-revert reconciliation decisions."""

from __future__ import annotations

import re
from dataclasses import dataclass

from carl_bench.promotion import PromotionContractError

_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_SUCCESS = frozenset({"SUCCESS", "NEUTRAL", "SKIPPED"})
_PENDING = frozenset({"", "PENDING", "QUEUED", "IN_PROGRESS"})


def _id(name: str, value: str) -> None:
    if not isinstance(value, str) or not value or len(value.encode()) > 256:
        raise PromotionContractError(f"invalid_{name}")
    if not _ID_RE.fullmatch(value):
        raise PromotionContractError(f"invalid_{name}")


def _object(name: str, value: str) -> None:
    if not isinstance(value, str) or not _OBJECT_RE.fullmatch(value):
        raise PromotionContractError(f"invalid_{name}")


@dataclass(frozen=True, slots=True)
class CheckRun:
    name: str
    conclusion: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name or len(self.name.encode()) > 256:
            raise PromotionContractError("invalid_check_name")
        if not isinstance(self.conclusion, str) or len(self.conclusion) > 32:
            raise PromotionContractError("invalid_check_conclusion")


@dataclass(frozen=True, slots=True)
class PullRequestSnapshot:
    number: int
    url: str
    state: str
    is_draft: bool
    base_branch: str
    head_branch: str
    head_commit: str
    merge_state: str
    checks: tuple[CheckRun, ...]
    merge_commit: str | None
    merge_tree: str | None
    auto_merge_enabled: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.number, bool) or not isinstance(self.number, int) or self.number <= 0:
            raise PromotionContractError("invalid_pull_request_number")
        if not isinstance(self.url, str) or not self.url.startswith("https://github.com/"):
            raise PromotionContractError("invalid_pull_request_url")
        if self.state not in {"OPEN", "MERGED", "CLOSED"}:
            raise PromotionContractError("invalid_pull_request_state")
        if not isinstance(self.is_draft, bool) or not isinstance(self.auto_merge_enabled, bool):
            raise PromotionContractError("invalid_pull_request_flags")
        _id("base_branch", self.base_branch)
        _id("head_branch", self.head_branch)
        _object("head_commit", self.head_commit)
        if not isinstance(self.merge_state, str) or len(self.merge_state) > 32:
            raise PromotionContractError("invalid_merge_state")
        if not isinstance(self.checks, tuple) or any(
            not isinstance(check, CheckRun) for check in self.checks
        ):
            raise PromotionContractError("invalid_checks")
        if len({check.name for check in self.checks}) != len(self.checks):
            raise PromotionContractError("duplicate_check_name")
        for name, value in (("merge_commit", self.merge_commit), ("merge_tree", self.merge_tree)):
            if value is not None:
                _object(name, value)


@dataclass(frozen=True, slots=True)
class PromotionRequest:
    promotion_id: str
    experiment_id: str
    repository: str
    base_branch: str
    head_branch: str
    parent_commit: str
    candidate_commit: str
    candidate_tree: str
    protected_receipt_digest: str

    def __post_init__(self) -> None:
        _id("promotion_id", self.promotion_id)
        _id("experiment_id", self.experiment_id)
        if not isinstance(self.repository, str) or not _REPOSITORY_RE.fullmatch(self.repository):
            raise PromotionContractError("invalid_repository")
        _id("base_branch", self.base_branch)
        _id("head_branch", self.head_branch)
        for name in ("parent_commit", "candidate_commit", "candidate_tree"):
            _object(name, getattr(self, name))
        if not _DIGEST_RE.fullmatch(self.protected_receipt_digest):
            raise PromotionContractError("invalid_protected_receipt_digest")


@dataclass(frozen=True, slots=True)
class PromotionSnapshot:
    production_commit: str
    active_promotion_id: str | None
    pull_request: PullRequestSnapshot | None

    def __post_init__(self) -> None:
        _object("production_commit", self.production_commit)
        if self.active_promotion_id is not None:
            _id("active_promotion_id", self.active_promotion_id)
        if self.pull_request is not None and not isinstance(
            self.pull_request, PullRequestSnapshot
        ):
            raise PromotionContractError("invalid_pull_request")


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    action: str
    reason: str
    pull_request_number: int | None = None
    merge_commit: str | None = None
    revert_commit: str | None = None


@dataclass(frozen=True, slots=True)
class RevertSnapshot:
    promotion_id: str
    merge_commit: str
    hard_failure: bool
    revert_pull_request: PullRequestSnapshot | None
    reverted_commit: str | None

    def __post_init__(self) -> None:
        _id("promotion_id", self.promotion_id)
        _object("merge_commit", self.merge_commit)
        if not isinstance(self.hard_failure, bool):
            raise PromotionContractError("invalid_hard_failure")
        if self.revert_pull_request is not None and not isinstance(
            self.revert_pull_request, PullRequestSnapshot
        ):
            raise PromotionContractError("invalid_revert_pull_request")
        if self.reverted_commit is not None:
            _object("reverted_commit", self.reverted_commit)


def _check_decision(
    pull_request: PullRequestSnapshot, required_checks: tuple[str, ...]
) -> PromotionDecision | None:
    if not required_checks or len(set(required_checks)) != len(required_checks):
        raise PromotionContractError("invalid_required_checks")
    checks = {check.name: check.conclusion.upper() for check in pull_request.checks}
    missing = set(required_checks) - set(checks)
    if missing or any(checks[name] in _PENDING for name in required_checks if name in checks):
        return PromotionDecision("await_checks", "required_checks_incomplete", pull_request.number)
    if any(checks[name] not in _SUCCESS for name in required_checks):
        return PromotionDecision("blocked", "required_check_failed", pull_request.number)
    return None


def reconcile_promotion(
    request: PromotionRequest,
    snapshot: PromotionSnapshot,
    required_checks: tuple[str, ...],
) -> PromotionDecision:
    """Choose one idempotent action without performing GitHub mutations."""
    if snapshot.active_promotion_id not in {None, request.promotion_id}:
        return PromotionDecision("blocked", "promotion_lease_conflict")
    pull_request = snapshot.pull_request
    if pull_request is None:
        if snapshot.production_commit != request.parent_commit:
            return PromotionDecision("blocked", "production_parent_changed")
        return PromotionDecision("create_pull_request", "exact_candidate_ready")
    if pull_request.base_branch != request.base_branch:
        raise PromotionContractError("promotion_pr_base_mismatch")
    if pull_request.head_branch != request.head_branch:
        raise PromotionContractError("promotion_pr_head_mismatch")
    if pull_request.head_commit != request.candidate_commit:
        raise PromotionContractError("promotion_pr_commit_mismatch")
    if pull_request.state == "MERGED":
        if pull_request.merge_commit is None or pull_request.merge_tree is None:
            raise PromotionContractError("promotion_merge_identity_missing")
        if snapshot.production_commit != pull_request.merge_commit:
            raise PromotionContractError("promotion_main_identity_mismatch")
        if pull_request.merge_tree != request.candidate_tree:
            raise PromotionContractError("promotion_merge_tree_mismatch")
        return PromotionDecision(
            "record_merge_and_start_soak",
            "exact_merge_reconciled",
            pull_request.number,
            pull_request.merge_commit,
        )
    if pull_request.state != "OPEN":
        return PromotionDecision("blocked", "promotion_pull_request_closed", pull_request.number)
    if snapshot.production_commit != request.parent_commit:
        return PromotionDecision("blocked", "production_parent_changed", pull_request.number)
    if pull_request.is_draft:
        return PromotionDecision("mark_ready", "independent_review_complete", pull_request.number)
    check_decision = _check_decision(pull_request, required_checks)
    if check_decision is not None:
        return check_decision
    if pull_request.merge_state != "CLEAN":
        return PromotionDecision(
            "await_mergeability", "pull_request_not_clean", pull_request.number
        )
    if pull_request.auto_merge_enabled:
        return PromotionDecision("await_merge", "auto_merge_already_enabled", pull_request.number)
    return PromotionDecision(
        "enable_auto_merge",
        "all_production_gates_satisfied",
        pull_request.number,
    )


def reconcile_revert(snapshot: RevertSnapshot) -> PromotionDecision:
    """Choose one exact-revert action, reconciling existing work before creating it."""
    if snapshot.reverted_commit is not None:
        return PromotionDecision(
            "record_reverted", "exact_revert_reconciled", merge_commit=snapshot.reverted_commit
        )
    if not snapshot.hard_failure:
        return PromotionDecision("continue_soak", "no_hard_failure")
    if snapshot.revert_pull_request is not None:
        return PromotionDecision(
            "await_revert",
            "revert_pull_request_exists",
            snapshot.revert_pull_request.number,
            revert_commit=snapshot.merge_commit,
        )
    return PromotionDecision(
        "create_revert_pull_request",
        "hard_soak_failure",
        revert_commit=snapshot.merge_commit,
    )
