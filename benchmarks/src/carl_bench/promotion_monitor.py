"""Outcome-based health checks for autonomous improvement and promotion."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from carl_bench.canonical import canonical_json_bytes
from carl_bench.promotion import PromotionContractError


def _time(name: str, value: str | None) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PromotionContractError(f"invalid_{name}")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise PromotionContractError(f"invalid_{name}") from error
    if parsed.tzinfo != UTC:
        raise PromotionContractError(f"invalid_{name}")
    return parsed


@dataclass(frozen=True, slots=True)
class AutomationObservation:
    automation_id: str
    cadence: str
    last_started_at: str | None
    last_completed_at: str | None
    last_outcome: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.automation_id, str)
            or not self.automation_id
            or len(self.automation_id.encode()) > 256
        ):
            raise PromotionContractError("invalid_automation_id")
        if self.cadence not in {"daily", "two_hour", "weekly"}:
            raise PromotionContractError("invalid_automation_cadence")
        _time("last_started_at", self.last_started_at)
        _time("last_completed_at", self.last_completed_at)
        if self.last_outcome not in {"success", "failed", "running", "never"}:
            raise PromotionContractError("invalid_automation_outcome")


@dataclass(frozen=True, slots=True)
class PromotionHealthSnapshot:
    automations: tuple[AutomationObservation, ...]
    lease_expires_at: str | None
    lease_reconciled: bool
    promotion_in_progress: bool
    complete_receipts: bool
    soaking_since: str | None
    last_soak_observation_at: str | None
    hard_failure_at: str | None
    revert_started_at: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.automations, tuple) or any(
            not isinstance(item, AutomationObservation) for item in self.automations
        ):
            raise PromotionContractError("invalid_automation_observations")
        if len({item.automation_id for item in self.automations}) != len(self.automations):
            raise PromotionContractError("duplicate_automation_observation")
        for name in (
            "lease_expires_at",
            "soaking_since",
            "last_soak_observation_at",
            "hard_failure_at",
            "revert_started_at",
        ):
            _time(name, getattr(self, name))
        for name in ("lease_reconciled", "promotion_in_progress", "complete_receipts"):
            if not isinstance(getattr(self, name), bool):
                raise PromotionContractError(f"invalid_{name}")


@dataclass(frozen=True, slots=True)
class PromotionHealthReport:
    schema_version: int
    evaluated_at: str
    status: str
    findings: tuple[str, ...]

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "evaluated_at": self.evaluated_at,
            "findings": list(self.findings),
            "schema_version": self.schema_version,
            "status": self.status,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


def evaluate_promotion_health(
    snapshot: PromotionHealthSnapshot, *, now: datetime
) -> PromotionHealthReport:
    """Evaluate fixed service objectives from durable outcome observations."""
    if now.tzinfo != UTC:
        raise PromotionContractError("invalid_monitor_time")
    findings: list[str] = []
    thresholds = {
        "daily": (timedelta(hours=36), "daily_automation_stale"),
        "two_hour": (timedelta(hours=4), "watchdog_automation_stale"),
        "weekly": (timedelta(days=8), "weekly_automation_stale"),
    }
    for automation in snapshot.automations:
        started = _time("last_started_at", automation.last_started_at)
        completed = _time("last_completed_at", automation.last_completed_at)
        threshold, code = thresholds[automation.cadence]
        if started is not None and started > now:
            findings.append(f"automation_start_in_future:{automation.automation_id}")
        if completed is not None and completed > now:
            findings.append(f"automation_completion_in_future:{automation.automation_id}")
        if started is not None and completed is not None and completed < started:
            findings.append(f"automation_completion_precedes_start:{automation.automation_id}")
        if completed is None or now - completed > threshold:
            findings.append(f"{code}:{automation.automation_id}")
        if automation.last_outcome == "failed":
            findings.append(f"automation_failed:{automation.automation_id}")
    lease_expires = _time("lease_expires_at", snapshot.lease_expires_at)
    if lease_expires is not None and now > lease_expires and not snapshot.lease_reconciled:
        findings.append("mutable_lease_expired_unreconciled")
    if snapshot.promotion_in_progress and not snapshot.complete_receipts:
        findings.append("promotion_receipts_incomplete")
    soaking_since = _time("soaking_since", snapshot.soaking_since)
    soak_observed = _time("last_soak_observation_at", snapshot.last_soak_observation_at)
    if soaking_since is not None and soaking_since > now:
        findings.append("soak_start_in_future")
    if soak_observed is not None and soak_observed > now:
        findings.append("soak_observation_in_future")
    if (
        soaking_since is not None
        and soak_observed is not None
        and soak_observed < soaking_since
    ):
        findings.append("soak_observation_precedes_start")
    if soaking_since is not None:
        latest = soak_observed or soaking_since
        if now - latest > timedelta(hours=26):
            findings.append("soak_observation_stale")
    hard_failure = _time("hard_failure_at", snapshot.hard_failure_at)
    revert_started = _time("revert_started_at", snapshot.revert_started_at)
    if hard_failure is not None and hard_failure > now:
        findings.append("hard_failure_in_future")
    if revert_started is not None and revert_started > now:
        findings.append("revert_start_in_future")
    if (
        hard_failure is not None
        and revert_started is not None
        and revert_started < hard_failure
    ):
        findings.append("revert_precedes_hard_failure")
    if (
        hard_failure is not None
        and revert_started is None
        and now - hard_failure > timedelta(hours=2)
    ):
        findings.append("rollback_start_sla_missed")
    unique_findings = tuple(sorted(set(findings)))
    evaluated_at = now.isoformat().replace("+00:00", "Z")
    return PromotionHealthReport(
        schema_version=1,
        evaluated_at=evaluated_at,
        status="critical" if unique_findings else "healthy",
        findings=unique_findings,
    )
