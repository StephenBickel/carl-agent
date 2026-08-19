"""Deterministic protected-promotion, soak, retry, and exact-revert controller."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Literal

from carl_bench.autonomy import AutonomyProjection
from carl_bench.canonical import canonical_json_bytes
from carl_bench.capability_validation import CapabilityValidationReport
from carl_bench.experiment import EventType, ExperimentEvent
from carl_bench.github_promotion import (
    PromotionRequest,
    PromotionSnapshot,
    RevertSnapshot,
    promotion_lease_reason,
    reconcile_promotion,
    reconcile_revert,
)
from carl_bench.promotion import (
    PromotionContractError,
    PromotionExpectation,
    SignedProtectedValidation,
    verify_protected_validation,
)
from carl_bench.promotion_monitor import (
    PromotionHealthSnapshot,
    evaluate_promotion_health,
    promotion_controller_blocker,
)

if TYPE_CHECKING:
    from carl_bench.ledger import AppendResult, ExperimentLedger

_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_TRUSTED_EVENTS = frozenset(
    {
        EventType.PROTECTED_VALIDATION_RECORDED,
        EventType.PROMOTION_RECORDED,
        EventType.SOAK_OBSERVED,
        EventType.REVERT_RECORDED,
    }
)

ControllerActionName = Literal[
    "record_validation",
    "create_pr",
    "mark_ready",
    "enable_auto_merge",
    "record_merge",
    "observe_soak",
    "accept",
    "create_revert_pr",
    "record_reverted",
    "schedule_retry",
    "idle",
]


def _utc(name: str, value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PromotionContractError(f"invalid_{name}")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise PromotionContractError(f"invalid_{name}") from error
    if parsed.tzinfo != UTC:
        raise PromotionContractError(f"invalid_{name}")
    return parsed


def _now(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo != UTC:
        raise PromotionContractError("invalid_controller_time")


def _attempt_id(action: str, bindings: dict[str, object]) -> str:
    digest = hashlib.sha256(canonical_json_bytes(bindings)).hexdigest()
    return f"controller-{action}-{digest[:32]}"


@dataclass(frozen=True, slots=True)
class SoakResult:
    merge_commit: str
    observed_at: str
    healthy: bool
    evidence_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.merge_commit, str) or not _OBJECT_RE.fullmatch(
            self.merge_commit
        ):
            raise PromotionContractError("invalid_soak_merge_commit")
        _utc("soak_observed_at", self.observed_at)
        if not isinstance(self.healthy, bool):
            raise PromotionContractError("invalid_soak_health")
        if not isinstance(self.evidence_digest, str) or not _DIGEST_RE.fullmatch(
            self.evidence_digest
        ):
            raise PromotionContractError("invalid_soak_evidence_digest")


@dataclass(frozen=True, slots=True)
class InfrastructureFailure:
    failed_stage_attempt_id: str
    failure_class: str
    changed_action: str

    def __post_init__(self) -> None:
        for name in ("failed_stage_attempt_id", "failure_class"):
            value = getattr(self, name)
            if (
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > 128
                or not _IDENTIFIER_RE.fullmatch(value)
            ):
                raise PromotionContractError(f"invalid_{name}")
        if (
            not isinstance(self.changed_action, str)
            or not self.changed_action.strip()
            or len(self.changed_action.encode("utf-8")) > 1_024
        ):
            raise PromotionContractError("invalid_changed_action")


@dataclass(frozen=True, slots=True)
class ControllerSnapshot:
    autonomy: AutonomyProjection
    capability_report: CapabilityValidationReport | None
    protected_validation: SignedProtectedValidation | None
    protected_public_key_pem: bytes | None
    promotion_expectation: PromotionExpectation | None
    promotion_request: PromotionRequest | None
    promotion_snapshot: PromotionSnapshot | None
    required_checks: tuple[str, ...]
    soak_result: SoakResult | None = None
    revert_snapshot: RevertSnapshot | None = None
    infrastructure_failure: InfrastructureFailure | None = None
    promotion_health: PromotionHealthSnapshot | None = None
    changed_paths: tuple[str, ...] = ()
    accepted: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.autonomy, AutonomyProjection):
            raise PromotionContractError("invalid_autonomy_projection")
        if self.capability_report is not None and not isinstance(
            self.capability_report, CapabilityValidationReport
        ):
            raise PromotionContractError("invalid_capability_report")
        if self.protected_validation is not None and not isinstance(
            self.protected_validation, SignedProtectedValidation
        ):
            raise PromotionContractError("invalid_protected_validation")
        if self.protected_public_key_pem is not None and not isinstance(
            self.protected_public_key_pem, bytes
        ):
            raise PromotionContractError("invalid_protected_public_key")
        if self.promotion_expectation is not None and not isinstance(
            self.promotion_expectation, PromotionExpectation
        ):
            raise PromotionContractError("invalid_promotion_expectation")
        if self.promotion_request is not None and not isinstance(
            self.promotion_request, PromotionRequest
        ):
            raise PromotionContractError("invalid_promotion_request")
        if self.promotion_snapshot is not None and not isinstance(
            self.promotion_snapshot, PromotionSnapshot
        ):
            raise PromotionContractError("invalid_promotion_snapshot")
        if not isinstance(self.required_checks, tuple) or any(
            not isinstance(item, str) for item in self.required_checks
        ):
            raise PromotionContractError("invalid_required_checks")
        if self.soak_result is not None and not isinstance(self.soak_result, SoakResult):
            raise PromotionContractError("invalid_soak_result")
        if self.revert_snapshot is not None and not isinstance(
            self.revert_snapshot, RevertSnapshot
        ):
            raise PromotionContractError("invalid_revert_snapshot")
        if self.infrastructure_failure is not None and not isinstance(
            self.infrastructure_failure, InfrastructureFailure
        ):
            raise PromotionContractError("invalid_infrastructure_failure")
        if self.promotion_health is not None and not isinstance(
            self.promotion_health, PromotionHealthSnapshot
        ):
            raise PromotionContractError("invalid_promotion_health_snapshot")
        if not isinstance(self.changed_paths, tuple) or any(
            not isinstance(item, str) for item in self.changed_paths
        ):
            raise PromotionContractError("invalid_changed_paths")
        if not isinstance(self.accepted, bool):
            raise PromotionContractError("invalid_controller_accepted")


@dataclass(frozen=True, slots=True)
class ControllerAction:
    action: ControllerActionName
    reason: str
    event: ExperimentEvent | None = None
    promotion_id: str | None = None
    parent_commit: str | None = None
    candidate_commit: str | None = None
    candidate_tree: str | None = None
    capability_report_digest: str | None = None
    capability_claim_type: str | None = None
    transfer_gain_basis_points: int | None = None
    affected_contract_cases_improved: bool | None = None
    capability_guards_non_inferior: bool | None = None
    protected_receipt_digest: str | None = None
    pull_request_number: int | None = None
    merge_commit: str | None = None
    restored_tree: str | None = None
    health_findings: tuple[str, ...] = ()

    def append_event(self, ledger: ExperimentLedger) -> AppendResult | None:
        """Persist only this action's graph fact through the appropriate ledger boundary."""
        if self.event is None:
            return None
        if self.event.event_type in _TRUSTED_EVENTS:
            return ledger.append_trusted_authority(self.event)
        return ledger.append(self.event)


def _idle(reason: str) -> ControllerAction:
    return ControllerAction("idle", reason)


def _accepted_evidence_is_bound(autonomy: AutonomyProjection) -> bool:
    promotion = autonomy.promotion
    if promotion is None or any(not item.healthy for item in autonomy.soak_observations):
        return False
    merged_at = _utc("promotion_merged_at", promotion.merged_at)
    return any(
        item.merge_commit == promotion.merge_commit
        and _utc("soak_observed_at", item.observed_at) - merged_at >= timedelta(hours=24)
        for item in autonomy.soak_observations
    )


def _retry_action(
    snapshot: ControllerSnapshot,
    failure: InfrastructureFailure,
    now: datetime,
) -> ControllerAction:
    prior = snapshot.autonomy.retry
    if prior is None or prior.failed_stage_attempt_id != failure.failed_stage_attempt_id:
        attempt = 1
    else:
        if prior.attempt >= 3:
            return _idle("infrastructure_retry_exhausted")
        if prior.changed_action == failure.changed_action:
            raise PromotionContractError("infrastructure_retry_action_unchanged")
        attempt = prior.attempt + 1
    scheduled_at = now.isoformat().replace("+00:00", "Z")
    event_payload = {
        "attempt": attempt,
        "changed_action": failure.changed_action,
        "failed_stage_attempt_id": failure.failed_stage_attempt_id,
        "failure_class": failure.failure_class,
        "scheduled_at": scheduled_at,
    }
    event = ExperimentEvent.create(
        experiment_id=snapshot.autonomy.experiment_id,
        stage_attempt_id=_attempt_id("retry", event_payload),
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at=scheduled_at,
        payload=event_payload,
    )
    return ControllerAction("schedule_retry", "changed_infrastructure_retry", event=event)


def _request(snapshot: ControllerSnapshot) -> tuple[PromotionRequest, PromotionSnapshot]:
    request = snapshot.promotion_request
    github = snapshot.promotion_snapshot
    if request is None or github is None:
        raise PromotionContractError("promotion_context_required")
    publication = snapshot.autonomy.experimental_publication
    if publication is None:
        raise PromotionContractError("experimental_publication_required")
    if (
        request.experiment_id != snapshot.autonomy.experiment_id
        or request.head_branch != publication.branch
        or request.candidate_commit != publication.commit
        or request.candidate_tree != publication.tree
    ):
        raise PromotionContractError("promotion_publication_identity_mismatch")
    return request, github


def _validation_action(snapshot: ControllerSnapshot, now: datetime) -> ControllerAction:
    report = snapshot.capability_report
    if report is None:
        return _idle("capability_report_required")
    if not report.eligible:
        raise PromotionContractError("capability_report_ineligible")
    envelope = snapshot.protected_validation
    public_key = snapshot.protected_public_key_pem
    expected = snapshot.promotion_expectation
    if envelope is None or public_key is None or expected is None:
        return _idle("protected_validation_required")
    request, github = _request(snapshot)
    lease_reason = promotion_lease_reason(github, request.promotion_id)
    if lease_reason is not None:
        return _idle(lease_reason)
    if expected.manifest_digest != snapshot.autonomy.manifest_digest:
        raise PromotionContractError("controller_manifest_mismatch")
    bound_expectation = replace(
        expected,
        capability_report_digest=report.digest,
        transfer_gain_basis_points=report.transfer_gain_basis_points,
        capability_claim_type=report.claim_type,
        affected_contract_cases_improved=report.affected_contract_cases_improved,
        capability_guards_non_inferior=report.guards_non_inferior,
    )
    verified = verify_protected_validation(
        envelope,
        public_key_pem=public_key,
        expected=bound_expectation,
        now=now,
        changed_paths=snapshot.changed_paths,
    )
    if request.protected_receipt_digest != verified.receipt_digest:
        raise PromotionContractError("promotion_receipt_digest_mismatch")
    if (
        request.parent_commit != expected.parent_commit
        or request.candidate_commit != verified.candidate_commit
        or request.candidate_tree != verified.candidate_tree
    ):
        raise PromotionContractError("promotion_validation_identity_mismatch")
    event_payload = {
        "candidate_commit": verified.candidate_commit,
        "candidate_tree": verified.candidate_tree,
        "receipt_digest": verified.receipt_digest,
    }
    event = ExperimentEvent.create(
        experiment_id=request.experiment_id,
        stage_attempt_id=_attempt_id("validation", event_payload),
        event_type=EventType.PROTECTED_VALIDATION_RECORDED,
        occurred_at=now.isoformat().replace("+00:00", "Z"),
        payload=event_payload,
    )
    return ControllerAction(
        "record_validation",
        "eligible_protected_validation_verified",
        event=event,
        promotion_id=request.promotion_id,
        parent_commit=request.parent_commit,
        candidate_commit=verified.candidate_commit,
        candidate_tree=verified.candidate_tree,
        capability_report_digest=report.digest,
        capability_claim_type=report.claim_type,
        transfer_gain_basis_points=report.transfer_gain_basis_points,
        affected_contract_cases_improved=report.affected_contract_cases_improved,
        capability_guards_non_inferior=report.guards_non_inferior,
        protected_receipt_digest=verified.receipt_digest,
    )


def _require_recorded_validation(
    snapshot: ControllerSnapshot, request: PromotionRequest
) -> None:
    validation = snapshot.autonomy.protected_validation
    if validation is None or (
        validation.candidate_commit != request.candidate_commit
        or validation.candidate_tree != request.candidate_tree
        or validation.receipt_digest != request.protected_receipt_digest
    ):
        raise PromotionContractError("promotion_recorded_validation_mismatch")


def _promotion_action(
    snapshot: ControllerSnapshot,
    request: PromotionRequest,
    github: PromotionSnapshot,
    now: datetime,
) -> ControllerAction:
    decision = reconcile_promotion(request, github, snapshot.required_checks)
    common = {
        "promotion_id": request.promotion_id,
        "parent_commit": request.parent_commit,
        "candidate_commit": request.candidate_commit,
        "candidate_tree": request.candidate_tree,
        "protected_receipt_digest": request.protected_receipt_digest,
        "pull_request_number": decision.pull_request_number,
    }
    if decision.action == "create_pull_request":
        return ControllerAction("create_pr", decision.reason, **common)
    if decision.action == "mark_ready":
        return ControllerAction("mark_ready", decision.reason, **common)
    if decision.action == "enable_auto_merge":
        return ControllerAction("enable_auto_merge", decision.reason, **common)
    if decision.action == "record_merge_and_start_soak":
        assert decision.merge_commit is not None
        event_payload = {
            "merge_commit": decision.merge_commit,
            "merge_tree": request.candidate_tree,
        }
        event = ExperimentEvent.create(
            experiment_id=request.experiment_id,
            stage_attempt_id=_attempt_id("merge", event_payload),
            event_type=EventType.PROMOTION_RECORDED,
            occurred_at=now.isoformat().replace("+00:00", "Z"),
            payload=event_payload,
        )
        return ControllerAction(
            "record_merge",
            decision.reason,
            event=event,
            merge_commit=decision.merge_commit,
            **common,
        )
    return _idle(decision.reason)


def _revert_action(
    snapshot: ControllerSnapshot,
    request: PromotionRequest,
    now: datetime,
) -> ControllerAction:
    revert_snapshot = snapshot.revert_snapshot
    if revert_snapshot is None:
        raise PromotionContractError("hard_failure_revert_snapshot_required")
    if (
        revert_snapshot.promotion_id != request.promotion_id
        or snapshot.autonomy.promotion is None
        or revert_snapshot.merge_commit != snapshot.autonomy.promotion.merge_commit
    ):
        raise PromotionContractError("revert_promotion_identity_mismatch")
    decision = reconcile_revert(revert_snapshot)
    if decision.action == "create_revert_pull_request":
        return ControllerAction(
            "create_revert_pr",
            decision.reason,
            promotion_id=request.promotion_id,
            merge_commit=revert_snapshot.merge_commit,
            restored_tree=revert_snapshot.expected_restored_tree,
        )
    if decision.action == "record_reverted":
        failure = next(
            item for item in reversed(snapshot.autonomy.soak_observations) if not item.healthy
        )
        assert decision.merge_commit is not None
        event_payload = {
            "hard_failure_digest": failure.evidence_digest,
            "merge_commit": revert_snapshot.merge_commit,
            "restored_tree": revert_snapshot.expected_restored_tree,
        }
        event = ExperimentEvent.create(
            experiment_id=request.experiment_id,
            stage_attempt_id=_attempt_id("reverted", event_payload),
            event_type=EventType.REVERT_RECORDED,
            occurred_at=now.isoformat().replace("+00:00", "Z"),
            payload=event_payload,
        )
        return ControllerAction(
            "record_reverted",
            decision.reason,
            event=event,
            promotion_id=request.promotion_id,
            merge_commit=decision.merge_commit,
            restored_tree=revert_snapshot.expected_restored_tree,
        )
    return _idle(decision.reason)


def _soak_action(
    snapshot: ControllerSnapshot,
    request: PromotionRequest,
    now: datetime,
) -> ControllerAction:
    promotion = snapshot.autonomy.promotion
    assert promotion is not None
    if snapshot.promotion_snapshot is None:
        raise PromotionContractError("promotion_context_required")
    lease_reason = promotion_lease_reason(
        snapshot.promotion_snapshot, request.promotion_id
    )
    if lease_reason is not None:
        return _idle(lease_reason)
    observations = snapshot.autonomy.soak_observations
    if any(not item.healthy for item in observations):
        return _revert_action(snapshot, request, now)
    if snapshot.promotion_snapshot.production_commit != promotion.merge_commit:
        raise PromotionContractError("promotion_main_identity_mismatch")
    result = snapshot.soak_result
    if result is not None:
        observed_at = _utc("soak_observed_at", result.observed_at)
        if result.merge_commit != promotion.merge_commit:
            raise PromotionContractError("soak_merge_identity_mismatch")
        if observed_at < _utc("promotion_merged_at", promotion.merged_at):
            raise PromotionContractError("soak_observation_precedes_merge")
        if observed_at > now:
            raise PromotionContractError("soak_observation_in_future")
        if any(
            item.observed_at == result.observed_at
            or item.evidence_digest == result.evidence_digest
            for item in observations
        ):
            raise PromotionContractError("duplicate_soak_observation")
        event_payload = {
            "evidence_digest": result.evidence_digest,
            "healthy": result.healthy,
            "merge_commit": result.merge_commit,
            "observed_at": result.observed_at,
        }
        event = ExperimentEvent.create(
            experiment_id=request.experiment_id,
            stage_attempt_id=_attempt_id("soak", event_payload),
            event_type=EventType.SOAK_OBSERVED,
            occurred_at=result.observed_at,
            payload=event_payload,
        )
        return ControllerAction(
            "observe_soak",
            "exact_soak_observation_ready",
            event=event,
            promotion_id=request.promotion_id,
            merge_commit=result.merge_commit,
        )
    if any(
        item.healthy
        and _utc("soak_observed_at", item.observed_at)
        - _utc("promotion_merged_at", promotion.merged_at)
        >= timedelta(hours=24)
        for item in observations
    ):
        return ControllerAction(
            "accept",
            "healthy_24_hour_soak_complete",
            promotion_id=request.promotion_id,
            merge_commit=promotion.merge_commit,
        )
    return ControllerAction(
        "observe_soak",
        "soak_observation_required",
        promotion_id=request.promotion_id,
        merge_commit=promotion.merge_commit,
    )


def next_controller_action(snapshot: ControllerSnapshot, now: datetime) -> ControllerAction:
    """Return one deterministic action while preserving every protected identity."""
    if not isinstance(snapshot, ControllerSnapshot):
        raise PromotionContractError("invalid_controller_snapshot")
    _now(now)
    if snapshot.accepted:
        if not _accepted_evidence_is_bound(snapshot.autonomy):
            raise PromotionContractError("accepted_soak_evidence_required")
        return _idle("experiment_accepted")
    if snapshot.autonomy.revert is not None:
        return _idle("experiment_reverted")
    if snapshot.infrastructure_failure is not None:
        return _retry_action(snapshot, snapshot.infrastructure_failure, now)
    health_findings: tuple[str, ...] = ()
    if snapshot.promotion_health is not None:
        health_report = evaluate_promotion_health(snapshot.promotion_health, now=now)
        health_findings = health_report.findings
        blocker = promotion_controller_blocker(health_report)
        if blocker is not None:
            return replace(_idle(blocker), health_findings=health_findings)
    if snapshot.autonomy.experimental_publication is None:
        action = _idle("experimental_publication_required")
    elif snapshot.autonomy.protected_validation is None:
        action = _validation_action(snapshot, now)
    else:
        request, github = _request(snapshot)
        _require_recorded_validation(snapshot, request)
        if snapshot.autonomy.promotion is None:
            action = _promotion_action(snapshot, request, github, now)
        else:
            action = _soak_action(snapshot, request, now)
    return replace(action, health_findings=health_findings)
