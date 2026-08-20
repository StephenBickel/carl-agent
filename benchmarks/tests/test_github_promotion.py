from __future__ import annotations

from dataclasses import replace

import pytest

from carl_bench.github_promotion import (
    CheckRun,
    PromotionRequest,
    PromotionSnapshot,
    PullRequestSnapshot,
    RevertSnapshot,
    reconcile_promotion,
    reconcile_revert,
)
from carl_bench.promotion import PromotionContractError

REQUIRED_CHECKS = (
    "Quality",
    "Benchmark contracts",
    "Test (ubuntu-latest)",
    "Test (macos-latest)",
    "Test (windows-latest)",
)


def request() -> PromotionRequest:
    return PromotionRequest(
        promotion_id="promotion-exp-001-1",
        experiment_id="exp-001",
        repository="StephenBickel/carl-agent",
        base_branch="main",
        head_branch="experimental/exp-001",
        parent_commit="1" * 40,
        candidate_commit="2" * 40,
        candidate_tree="3" * 40,
        protected_receipt_digest="4" * 64,
    )


def pull_request() -> PullRequestSnapshot:
    return PullRequestSnapshot(
        number=81,
        url="https://github.com/StephenBickel/carl-agent/pull/81",
        state="OPEN",
        is_draft=False,
        base_branch="main",
        head_branch="experimental/exp-001",
        head_commit="2" * 40,
        head_tree="3" * 40,
        merge_state="CLEAN",
        checks=tuple(
            CheckRun(name=name, conclusion="SUCCESS", app_id=15368) for name in REQUIRED_CHECKS
        ),
        merge_commit=None,
        merge_tree=None,
    )


def snapshot(**changes: object) -> PromotionSnapshot:
    base = PromotionSnapshot(
        production_commit="1" * 40,
        active_promotion_id="promotion-exp-001-1",
        pull_request=pull_request(),
    )
    return replace(base, **changes)


def test_missing_pull_request_creates_one_for_the_exact_head_and_base() -> None:
    decision = reconcile_promotion(request(), snapshot(pull_request=None), REQUIRED_CHECKS)

    assert decision.action == "create_pull_request"
    assert decision.pull_request_number is None
    assert decision.reason == "exact_candidate_ready"


def test_green_exact_pull_request_enables_squash_auto_merge() -> None:
    decision = reconcile_promotion(request(), snapshot(), REQUIRED_CHECKS)

    assert decision.action == "enable_auto_merge"
    assert decision.pull_request_number == 81
    assert decision.reason == "all_production_gates_satisfied"


def test_duplicate_tick_reconciles_already_enabled_auto_merge() -> None:
    current = replace(pull_request(), auto_merge_enabled=True)

    decision = reconcile_promotion(request(), snapshot(pull_request=current), REQUIRED_CHECKS)

    assert decision.action == "await_merge"
    assert decision.reason == "auto_merge_already_enabled"


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"production_commit": "0" * 40}, "production_parent_changed"),
        ({"active_promotion_id": "promotion-other-1"}, "promotion_lease_conflict"),
    ],
)
def test_stale_base_or_concurrent_promotion_fails_closed(
    change: dict[str, object], reason: str
) -> None:
    decision = reconcile_promotion(request(), snapshot(**change), REQUIRED_CHECKS)

    assert decision.action == "blocked"
    assert decision.reason == reason


def test_missing_promotion_lease_fails_closed() -> None:
    decision = reconcile_promotion(request(), snapshot(active_promotion_id=None), REQUIRED_CHECKS)

    assert decision.action == "blocked"
    assert decision.reason == "promotion_lease_required"


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("base_branch", "other", "promotion_pr_base_mismatch"),
        ("head_branch", "experimental/other", "promotion_pr_head_mismatch"),
        ("head_commit", "0" * 40, "promotion_pr_commit_mismatch"),
    ],
)
def test_pull_request_identity_mismatch_is_integrity_error(
    field: str, value: str, error: str
) -> None:
    current = replace(pull_request(), **{field: value})

    with pytest.raises(PromotionContractError, match=error):
        reconcile_promotion(request(), snapshot(pull_request=current), REQUIRED_CHECKS)


def test_pull_request_tree_mismatch_is_integrity_error() -> None:
    current = replace(pull_request(), head_tree="0" * 40)

    with pytest.raises(PromotionContractError, match="promotion_pr_tree_mismatch"):
        reconcile_promotion(request(), snapshot(pull_request=current), REQUIRED_CHECKS)


def test_missing_or_failed_check_never_enables_auto_merge() -> None:
    missing = replace(pull_request(), checks=pull_request().checks[:-1])
    failed = replace(
        pull_request(),
        checks=tuple(
            CheckRun(name=check.name, conclusion="FAILURE", app_id=check.app_id)
            if check.name == "Quality"
            else check
            for check in pull_request().checks
        ),
    )

    assert (
        reconcile_promotion(request(), snapshot(pull_request=missing), REQUIRED_CHECKS).action
        == "await_checks"
    )
    failed_decision = reconcile_promotion(request(), snapshot(pull_request=failed), REQUIRED_CHECKS)
    assert failed_decision.action == "blocked"
    assert failed_decision.reason == "required_check_failed"


@pytest.mark.parametrize("conclusion", ["SKIPPED", "NEUTRAL"])
def test_nonexecuted_required_check_never_enables_auto_merge(conclusion: str) -> None:
    current = replace(
        pull_request(),
        checks=tuple(
            CheckRun(name=check.name, conclusion=conclusion, app_id=check.app_id)
            if check.name == "Quality"
            else check
            for check in pull_request().checks
        ),
    )

    decision = reconcile_promotion(request(), snapshot(pull_request=current), REQUIRED_CHECKS)

    assert decision.action == "blocked"
    assert decision.reason == "required_check_failed"


def test_required_check_from_untrusted_app_never_enables_auto_merge() -> None:
    current = replace(
        pull_request(),
        checks=tuple(
            replace(check, app_id=999) if check.name == "Quality" else check
            for check in pull_request().checks
        ),
    )

    decision = reconcile_promotion(request(), snapshot(pull_request=current), REQUIRED_CHECKS)

    assert decision.action == "blocked"
    assert decision.reason == "required_check_app_mismatch"


def test_merged_pr_requires_exact_resulting_tree() -> None:
    merged = replace(
        pull_request(),
        state="MERGED",
        merge_commit="5" * 40,
        merge_tree="0" * 40,
        auto_merge_enabled=True,
    )

    with pytest.raises(PromotionContractError, match="promotion_merge_tree_mismatch"):
        reconcile_promotion(
            request(),
            snapshot(production_commit="5" * 40, pull_request=merged),
            REQUIRED_CHECKS,
        )


def test_exact_merged_tree_starts_the_soak() -> None:
    merged = replace(
        pull_request(),
        state="MERGED",
        merge_commit="5" * 40,
        merge_tree="3" * 40,
        auto_merge_enabled=True,
    )

    decision = reconcile_promotion(
        request(),
        snapshot(production_commit="5" * 40, pull_request=merged),
        REQUIRED_CHECKS,
    )

    assert decision.action == "record_merge_and_start_soak"
    assert decision.merge_commit == "5" * 40


def test_hard_soak_failure_opens_one_exact_revert() -> None:
    state = RevertSnapshot(
        promotion_id=request().promotion_id,
        merge_commit="5" * 40,
        hard_failure=True,
        revert_pull_request=None,
        revert_candidate_commit=None,
        expected_restored_tree="7" * 40,
        production_commit="5" * 40,
        production_tree="3" * 40,
        reverted_commit=None,
    )

    decision = reconcile_revert(state)

    assert decision.action == "create_revert_pull_request"
    assert decision.promotion_merge_commit == "5" * 40


def test_existing_revert_pr_is_reconciled_not_duplicated() -> None:
    revert_pr = replace(
        pull_request(),
        number=82,
        head_branch="revert/promotion-exp-001-1",
        head_commit="6" * 40,
        head_tree="7" * 40,
    )
    state = RevertSnapshot(
        promotion_id=request().promotion_id,
        merge_commit="5" * 40,
        hard_failure=True,
        revert_pull_request=revert_pr,
        revert_candidate_commit="6" * 40,
        expected_restored_tree="7" * 40,
        production_commit="5" * 40,
        production_tree="3" * 40,
        reverted_commit=None,
    )

    decision = reconcile_revert(state)

    assert decision.action == "await_revert"
    assert decision.pull_request_number == 82


def test_unrelated_pull_request_cannot_suppress_exact_revert() -> None:
    unrelated = replace(
        pull_request(),
        number=82,
        head_branch="experimental/unrelated",
        head_commit="6" * 40,
    )
    state = RevertSnapshot(
        promotion_id=request().promotion_id,
        merge_commit="5" * 40,
        hard_failure=True,
        revert_pull_request=unrelated,
        revert_candidate_commit="6" * 40,
        expected_restored_tree="7" * 40,
        production_commit="5" * 40,
        production_tree="3" * 40,
        reverted_commit=None,
    )

    with pytest.raises(PromotionContractError, match="revert_pr_head_mismatch"):
        reconcile_revert(state)


def test_arbitrary_reverted_commit_cannot_claim_restoration() -> None:
    state = RevertSnapshot(
        promotion_id=request().promotion_id,
        merge_commit="5" * 40,
        hard_failure=False,
        revert_pull_request=None,
        revert_candidate_commit=None,
        expected_restored_tree="7" * 40,
        production_commit="8" * 40,
        production_tree="0" * 40,
        reverted_commit="8" * 40,
    )

    with pytest.raises(PromotionContractError, match="revert_without_hard_failure"):
        reconcile_revert(state)


def test_exact_merged_revert_restores_the_preceding_tree() -> None:
    reverted_pr = replace(
        pull_request(),
        number=82,
        state="MERGED",
        head_branch="revert/promotion-exp-001-1",
        head_commit="6" * 40,
        head_tree="7" * 40,
        merge_commit="8" * 40,
        merge_tree="7" * 40,
    )
    state = RevertSnapshot(
        promotion_id=request().promotion_id,
        merge_commit="5" * 40,
        hard_failure=True,
        revert_pull_request=reverted_pr,
        revert_candidate_commit="6" * 40,
        expected_restored_tree="7" * 40,
        production_commit="8" * 40,
        production_tree="7" * 40,
        reverted_commit="8" * 40,
    )

    decision = reconcile_revert(state)

    assert decision.action == "record_reverted"
    assert decision.promotion_merge_commit == "5" * 40
    assert decision.revert_pull_request_number == 82
    assert decision.revert_candidate_commit == "6" * 40
    assert decision.revert_merge_commit == "8" * 40
