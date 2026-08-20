from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PORTFOLIO_PATH = (
    REPOSITORY_ROOT
    / "docs"
    / "automation-prompts"
    / "carl-autonomous-improvement.md"
)


@dataclass(frozen=True)
class PromptSnapshot:
    metadata: dict[str, object]
    prompt: str

    def contains(self, *phrases: str) -> bool:
        normalized = " ".join(self.prompt.lower().split())
        return all(phrase.lower() in normalized for phrase in phrases)

    @property
    def allows_experimental_push_without_protected_validation(self) -> bool:
        return self.contains(
            "push exactly one immutable `experimental/<experiment-id>` branch "
            "without human approval",
            "protected production validation is not required for experimental publication",
        )

    @property
    def requires_implementation_and_retest(self) -> bool:
        return self.contains(
            "write a failing test",
            "implement the smallest general product change",
            "retest the exact candidate",
        )

    @property
    def allows_pr_and_auto_merge_without_human_approval(self) -> bool:
        return self.contains(
            "open or reconcile the protected pull request to `main`",
            "enable auto-merge without human approval",
        )

    @property
    def forbids_idle_narrative(self) -> bool:
        return self.contains(
            "when no consequential state is active and health is green, emit only `idle: healthy`",
            "do not write an idle narrative",
        )

    @property
    def requires_changed_recovery_action(self) -> bool:
        return self.contains(
            "every recovery attempt must record a materially changed action",
            "a repeated diagnosis without a changed action is a failed supervisor run",
        )

    @property
    def critical_after_two_zero_candidate_cycles(self) -> bool:
        return self.contains(
            "critical after two consecutive completed builder cycles with zero "
            "experimental candidates",
        )


def _load_portfolio() -> dict[str, PromptSnapshot]:
    document = PORTFOLIO_PATH.read_text(encoding="utf-8")
    sections = re.split(r"(?m)^## Automation: ", document)[1:]
    snapshots: dict[str, PromptSnapshot] = {}

    for section in sections:
        heading, body = section.split("\n", 1)
        metadata_match = re.search(
            r"```toml automation\n(?P<value>.*?)\n```", body, re.DOTALL
        )
        prompt_match = re.search(
            r"```text prompt\n(?P<value>.*?)\n```", body, re.DOTALL
        )
        assert metadata_match is not None, f"missing automation metadata for {heading}"
        assert prompt_match is not None, f"missing canonical prompt for {heading}"

        metadata = tomllib.loads(metadata_match.group("value"))
        automation_id = str(metadata["id"])
        assert automation_id not in snapshots, f"duplicate automation id {automation_id}"
        snapshots[automation_id] = PromptSnapshot(
            metadata=metadata,
            prompt=prompt_match.group("value").strip(),
        )

    return snapshots


def test_portfolio_defines_the_six_nonoverlapping_automation_roles() -> None:
    portfolio = _load_portfolio()

    assert set(portfolio) == {
        "daily-carl-self-improvement-graph",
        "daily-carl-production-review",
        "carl-promotion-and-rollback-watchdog",
        "daily-carl-autonomy-outcome-monitor",
        "carl-autonomy-loop-supervisor",
        "weekly-carl-feature-and-autonomy-report",
    }

    for ownership_key, expected_owner in {
        "mutation_owner": "daily-carl-self-improvement-graph",
        "disposition_owner": "daily-carl-production-review",
        "promotion_owner": "daily-carl-production-review",
    }.items():
        owners = {
            automation_id
            for automation_id, snapshot in portfolio.items()
            if snapshot.metadata.get(ownership_key) is True
        }
        assert owners == {expected_owner}


def test_builder_implements_retests_and_can_publish_experimental_work() -> None:
    builder = _load_portfolio()["daily-carl-self-improvement-graph"]

    assert builder.allows_experimental_push_without_protected_validation
    assert builder.requires_implementation_and_retest
    assert builder.contains(
        "retry or rework a nonterminal failure instead of ending with a report-only failure",
        "held-out or adversarial transfer check",
        "benchmark-only score gains are not capability evidence",
    )


def test_promoter_owns_independent_disposition_and_protected_auto_merge() -> None:
    promoter = _load_portfolio()["daily-carl-production-review"]

    assert promoter.allows_pr_and_auto_merge_without_human_approval
    assert promoter.contains(
        "assign exactly one independent disposition",
        "retry or rework a repairable failure",
        "required checks and branch protection",
    )


def test_watchdog_is_compact_when_idle_and_recovers_active_work() -> None:
    watchdog = _load_portfolio()["carl-promotion-and-rollback-watchdog"]

    assert watchdog.forbids_idle_narrative
    assert watchdog.contains(
        "reconcile active experiments, reviews, promotions, soaks, reverts, leases, and retries",
        "three materially different recovery attempts",
    )


def test_supervisor_changes_recovery_action_and_noops_only_when_healthy() -> None:
    supervisor = _load_portfolio()["carl-autonomy-loop-supervisor"]

    assert supervisor.requires_changed_recovery_action
    assert supervisor.contains(
        "no-op only when commissioning is complete, no critical condition exists, "
        "and the loop is advancing",
        "redispatch the exact next safe node",
    )


def test_outcome_monitor_escalates_zero_candidate_throughput() -> None:
    outcome_monitor = _load_portfolio()["daily-carl-autonomy-outcome-monitor"]

    assert outcome_monitor.critical_after_two_zero_candidate_cycles
    assert outcome_monitor.contains(
        "watchdog run count is not throughput",
        "report-only runs",
        "retained learning",
    )


def test_schedules_models_and_reasoning_are_exact() -> None:
    portfolio = _load_portfolio()
    expected = {
        "daily-carl-self-improvement-graph": (
            "RRULE:FREQ=DAILY;BYHOUR=0;BYMINUTE=0",
            "gpt-5.6-sol",
            "high",
        ),
        "daily-carl-production-review": (
            "RRULE:FREQ=HOURLY;INTERVAL=6;BYMINUTE=15",
            "gpt-5.6-sol",
            "high",
        ),
        "carl-promotion-and-rollback-watchdog": (
            "RRULE:FREQ=HOURLY;INTERVAL=2;BYMINUTE=30",
            "gpt-5.6-luna",
            "medium",
        ),
        "daily-carl-autonomy-outcome-monitor": (
            "RRULE:FREQ=DAILY;BYHOUR=8;BYMINUTE=0",
            "gpt-5.6-luna",
            "medium",
        ),
        "carl-autonomy-loop-supervisor": (
            "RRULE:FREQ=HOURLY;INTERVAL=6;BYMINUTE=45",
            "gpt-5.6-sol",
            "ultra",
        ),
        "weekly-carl-feature-and-autonomy-report": (
            "RRULE:FREQ=WEEKLY;BYDAY=MO;BYHOUR=9;BYMINUTE=0",
            "gpt-5.6-terra",
            "medium",
        ),
    }

    assert {
        automation_id: (
            snapshot.metadata["rrule"],
            snapshot.metadata["model"],
            snapshot.metadata["reasoning_effort"],
        )
        for automation_id, snapshot in portfolio.items()
    } == expected


def test_every_automation_is_a_thin_fail_closed_local_controller() -> None:
    portfolio = _load_portfolio()

    for automation_id, snapshot in portfolio.items():
        assert snapshot.metadata["execution_environment"] == "local", automation_id
        assert snapshot.metadata["controller_mode"] == "thin_local", automation_id
        assert snapshot.metadata["heavy_execution"] == "github_hosted", automation_id
        assert snapshot.metadata["local_heavy_fallback"] is False, automation_id
        assert snapshot.contains(
            "dispatch heavy builds, tests, evaluations, and soak probes to github-hosted workflows",
            "never silently fall back to heavy local execution",
            "fail closed if either a trusted signed commissioning receipt or live acp "
            "capability evidence is missing",
        ), automation_id


def test_no_automation_has_forbidden_production_authority() -> None:
    portfolio = _load_portfolio()

    for automation_id, snapshot in portfolio.items():
        assert snapshot.metadata["direct_main_push"] is False, automation_id
        assert snapshot.metadata["force_push"] is False, automation_id
        assert snapshot.metadata["deploy"] is False, automation_id
        assert snapshot.metadata["release"] is False, automation_id
        assert snapshot.contains(
            "never directly push `main`, force-push, deploy, or release",
        ), automation_id
