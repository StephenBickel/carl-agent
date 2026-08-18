from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from carl_bench.promotion_monitor import (
    AutomationObservation,
    PromotionHealthSnapshot,
    evaluate_promotion_health,
)

NOW = datetime(2026, 8, 18, 18, tzinfo=UTC)


def observation() -> AutomationObservation:
    return AutomationObservation(
        automation_id="daily-carl-production-review",
        cadence="daily",
        last_started_at="2026-08-18T10:00:00Z",
        last_completed_at="2026-08-18T10:30:00Z",
        last_outcome="success",
    )


def snapshot() -> PromotionHealthSnapshot:
    return PromotionHealthSnapshot(
        automations=(
            observation(),
            replace(
                observation(),
                automation_id="carl-promotion-watchdog",
                cadence="two_hour",
                last_started_at="2026-08-18T16:00:00Z",
                last_completed_at="2026-08-18T16:10:00Z",
            ),
        ),
        lease_expires_at=None,
        lease_reconciled=True,
        promotion_in_progress=False,
        complete_receipts=True,
        soaking_since=None,
        last_soak_observation_at=None,
        hard_failure_at=None,
        revert_started_at=None,
    )


def test_healthy_report_proves_outcomes_not_schedule_presence() -> None:
    report = evaluate_promotion_health(snapshot(), now=NOW)

    assert report.status == "healthy"
    assert report.findings == ()


def test_daily_run_older_than_36_hours_is_stale() -> None:
    stale = replace(
        observation(),
        last_completed_at="2026-08-16T23:00:00Z",
    )

    report = evaluate_promotion_health(
        replace(snapshot(), automations=(stale, snapshot().automations[1])), now=NOW
    )

    assert report.status == "critical"
    assert "daily_automation_stale:daily-carl-production-review" in report.findings


def test_two_hour_watchdog_older_than_four_hours_is_stale() -> None:
    stale = replace(
        snapshot().automations[1],
        last_completed_at="2026-08-18T13:59:59Z",
    )

    report = evaluate_promotion_health(
        replace(snapshot(), automations=(observation(), stale)), now=NOW
    )

    assert "watchdog_automation_stale:carl-promotion-watchdog" in report.findings


def test_expired_unreconciled_lease_freezes_promotion() -> None:
    report = evaluate_promotion_health(
        replace(
            snapshot(),
            lease_expires_at="2026-08-18T17:00:00Z",
            lease_reconciled=False,
        ),
        now=NOW,
    )

    assert report.status == "critical"
    assert "mutable_lease_expired_unreconciled" in report.findings


def test_incomplete_receipts_during_promotion_is_immediate_integrity_failure() -> None:
    report = evaluate_promotion_health(
        replace(snapshot(), promotion_in_progress=True, complete_receipts=False),
        now=NOW,
    )

    assert "promotion_receipts_incomplete" in report.findings


def test_soak_without_observation_for_26_hours_is_stale() -> None:
    report = evaluate_promotion_health(
        replace(
            snapshot(),
            soaking_since="2026-08-17T15:00:00Z",
            last_soak_observation_at="2026-08-17T15:30:00Z",
        ),
        now=NOW,
    )

    assert "soak_observation_stale" in report.findings


def test_hard_failure_without_revert_within_two_hours_is_critical() -> None:
    report = evaluate_promotion_health(
        replace(snapshot(), hard_failure_at="2026-08-18T15:59:59Z"),
        now=NOW,
    )

    assert "rollback_start_sla_missed" in report.findings


def test_started_revert_satisfies_rollback_start_sla() -> None:
    report = evaluate_promotion_health(
        replace(
            snapshot(),
            hard_failure_at="2026-08-18T15:00:00Z",
            revert_started_at="2026-08-18T15:30:00Z",
        ),
        now=NOW,
    )

    assert "rollback_start_sla_missed" not in report.findings


def test_future_automation_completion_is_critical() -> None:
    future = replace(
        observation(),
        last_started_at="2026-08-18T19:00:00Z",
        last_completed_at="2026-08-18T19:30:00Z",
    )

    report = evaluate_promotion_health(
        replace(snapshot(), automations=(future, snapshot().automations[1])), now=NOW
    )

    assert "automation_completion_in_future:daily-carl-production-review" in report.findings


def test_revert_start_before_hard_failure_is_critical() -> None:
    report = evaluate_promotion_health(
        replace(
            snapshot(),
            hard_failure_at="2026-08-18T16:00:00Z",
            revert_started_at="2026-08-18T15:59:59Z",
        ),
        now=NOW,
    )

    assert "revert_precedes_hard_failure" in report.findings


def test_running_watchdog_beyond_its_cadence_timeout_is_critical() -> None:
    stuck = replace(
        snapshot().automations[1],
        last_started_at="2026-08-18T13:59:59Z",
        last_completed_at="2026-08-18T17:00:00Z",
        last_outcome="running",
    )

    report = evaluate_promotion_health(
        replace(snapshot(), automations=(observation(), stuck)), now=NOW
    )

    assert "automation_running_overdue:carl-promotion-watchdog" in report.findings


def test_recently_started_watchdog_is_not_overdue() -> None:
    running = replace(
        snapshot().automations[1],
        last_started_at="2026-08-18T16:30:00Z",
        last_completed_at="2026-08-18T17:00:00Z",
        last_outcome="running",
    )

    report = evaluate_promotion_health(
        replace(snapshot(), automations=(observation(), running)), now=NOW
    )

    assert "automation_running_overdue:carl-promotion-watchdog" not in report.findings
