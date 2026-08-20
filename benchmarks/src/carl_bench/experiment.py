"""Deterministic contracts and reducer for the dry-run improvement graph."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import Enum
from pathlib import PurePosixPath
from typing import Any

from carl_bench.candidate import (
    CandidateContractError,
    DraftPullRequest,
    PairedEvidence,
    Phase3Decision,
    PreparedCandidate,
    ReviewAttestation,
    ReviewPacket,
    SealedCandidate,
)
from carl_bench.canonical import CanonicalizationError, canonical_json_bytes

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class GraphContractError(ValueError):
    """A stable graph-contract error that does not echo untrusted values."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _bounded_text(name: str, value: str, maximum: int) -> None:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise GraphContractError(f"invalid_{name}")


def _identifier(name: str, value: str, maximum: int = 128) -> None:
    _bounded_text(name, value, maximum)
    if not _ID_RE.fullmatch(value):
        raise GraphContractError(f"invalid_{name}")


def _unique_texts(name: str, values: tuple[str, ...], *, maximum_items: int = 128) -> None:
    if not isinstance(values, tuple) or not values or len(values) > maximum_items:
        raise GraphContractError(f"invalid_{name}")
    for value in values:
        _bounded_text(name, value, 512)
    if len(set(values)) != len(values):
        raise GraphContractError(f"duplicate_{name}")


def _surface(name: str, values: tuple[str, ...]) -> None:
    _unique_texts(name, values)
    for value in values:
        if "\\" in value:
            raise GraphContractError(f"invalid_{name}")
        raw_parts = value.split("/")
        if any(part in {"", ".", ".."} for part in raw_parts):
            raise GraphContractError(f"invalid_{name}")
        path = PurePosixPath(value)
        if path.is_absolute():
            raise GraphContractError(f"invalid_{name}")


def _iso_utc(name: str, value: str) -> None:
    _bounded_text(name, value, 64)
    if not value.endswith("Z"):
        raise GraphContractError(f"invalid_{name}")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise GraphContractError(f"invalid_{name}") from error
    if parsed.tzinfo != UTC:
        raise GraphContractError(f"invalid_{name}")


def _parse_utc(value: str) -> datetime:
    _iso_utc("timestamp", value)
    return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")


class ExperimentKind(str, Enum):
    CORRECTNESS = "correctness"
    RELIABILITY = "reliability"
    EFFICIENCY = "efficiency"
    SAFETY = "safety"
    FEATURE = "feature"
    EVALUATOR = "evaluator"
    CONSTITUTIONAL = "constitutional"


class ExperimentState(str, Enum):
    QUEUED = "queued"
    BASELINING = "baselining"
    DIAGNOSING = "diagnosing"
    PROPOSAL_REVIEW = "proposal_review"
    BUILDING = "building"
    DETERMINISTIC_VALIDATION = "deterministic_validation"
    PAIRED_EVALUATION = "paired_evaluation"
    HOLDOUT_VALIDATION = "holdout_validation"
    REVIEW_COMPLETE = "review_complete"
    PR_OPEN = "pr_open"
    MERGED = "merged"
    SOAKING = "soaking"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    BUDGET_EXHAUSTED = "budget_exhausted"
    REVERTED = "reverted"
    ABANDONED = "abandoned"


class EventType(str, Enum):
    STATE_TRANSITIONED = "state_transitioned"
    ROLE_RECORDED = "role_recorded"
    LEASE_ACQUIRED = "lease_acquired"
    LEASE_RECONCILED = "lease_reconciled"
    LEASE_RELEASED = "lease_released"
    LIVE_SPEND_RECORDED = "live_spend_recorded"
    WORKSPACE_PREPARED = "workspace_prepared"
    CANDIDATE_SEALED = "candidate_sealed"
    PAIRED_EVIDENCE_RECORDED = "paired_evidence_recorded"
    REVIEW_PACKET_RECORDED = "review_packet_recorded"
    REVIEW_ATTESTED = "review_attested"
    DRAFT_PR_REQUESTED = "draft_pr_requested"
    DRAFT_PR_RECORDED = "draft_pr_recorded"
    WORKSPACE_DISPOSED = "workspace_disposed"
    RETRY_SCHEDULED = "retry_scheduled"
    EXPERIMENTAL_PUBLISHED = "experimental_published"
    PROTECTED_VALIDATION_RECORDED = "protected_validation_recorded"
    PROMOTION_RECORDED = "promotion_recorded"
    SOAK_OBSERVED = "soak_observed"
    REVERT_RECORDED = "revert_recorded"


_AUTONOMY_EVENT_TYPES = frozenset(
    {
        EventType.RETRY_SCHEDULED,
        EventType.EXPERIMENTAL_PUBLISHED,
        EventType.PROTECTED_VALIDATION_RECORDED,
        EventType.PROMOTION_RECORDED,
        EventType.SOAK_OBSERVED,
        EventType.REVERT_RECORDED,
    }
)


_ISOLATED_AUTHORITY_REQUIRED_EVENTS = frozenset(
    {
        EventType.PAIRED_EVIDENCE_RECORDED,
        EventType.REVIEW_PACKET_RECORDED,
        EventType.REVIEW_ATTESTED,
        EventType.DRAFT_PR_REQUESTED,
        EventType.DRAFT_PR_RECORDED,
        EventType.WORKSPACE_DISPOSED,
        EventType.PROTECTED_VALIDATION_RECORDED,
        EventType.PROMOTION_RECORDED,
        EventType.SOAK_OBSERVED,
        EventType.REVERT_RECORDED,
    }
)


class ReviewRole(str, Enum):
    CAUSAL = "causal"
    PRODUCT = "product"
    EVALUATION = "evaluation"
    CORRECTNESS = "correctness"
    SECURITY = "security"
    MAINTAINABILITY = "maintainability"
    BENCHMARK_INTEGRITY = "benchmark_integrity"


class ReviewVerdict(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    HARD_OBJECTION = "hard_objection"
    HARD_FINDING = "hard_finding"


_PROPOSAL_ROLES = frozenset({ReviewRole.CAUSAL, ReviewRole.PRODUCT, ReviewRole.EVALUATION})
_CANDIDATE_ROLES = frozenset(
    {
        ReviewRole.CORRECTNESS,
        ReviewRole.SECURITY,
        ReviewRole.MAINTAINABILITY,
        ReviewRole.BENCHMARK_INTEGRITY,
    }
)


@dataclass(frozen=True, slots=True)
class ReviewOutput:
    role: ReviewRole
    verdict: ReviewVerdict
    artifact_digest: str
    stage_attempt_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, ReviewRole) or not isinstance(self.verdict, ReviewVerdict):
            raise GraphContractError("invalid_review_output")
        if self.role in _PROPOSAL_ROLES and self.verdict not in {
            ReviewVerdict.APPROVE,
            ReviewVerdict.REJECT,
            ReviewVerdict.HARD_OBJECTION,
        }:
            raise GraphContractError("invalid_proposal_verdict")
        if self.role in _CANDIDATE_ROLES and self.verdict not in {
            ReviewVerdict.APPROVE,
            ReviewVerdict.REJECT,
            ReviewVerdict.HARD_FINDING,
        }:
            raise GraphContractError("invalid_candidate_verdict")
        if not _DIGEST_RE.fullmatch(self.artifact_digest):
            raise GraphContractError("invalid_review_artifact_digest")
        _identifier("stage_attempt_id", self.stage_attempt_id)


@dataclass(frozen=True, slots=True)
class MutableStageLease:
    stage_attempt_id: str
    owner_id: str
    acquired_at: str
    expires_at: str
    stale_reconciled: bool = False


@dataclass(frozen=True, slots=True)
class DryRunDecision:
    schema_version: int
    experiment_id: str
    manifest_digest: str
    projection_digest: str
    state: ExperimentState
    outcome: str
    next_action: str
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise GraphContractError("invalid_decision_schema")
        if self.outcome not in {
            "advance",
            "blocked",
            "budget_exhausted",
            "simulated_build_eligible",
            "terminal",
        }:
            raise GraphContractError("invalid_dry_run_outcome")
        _identifier("next_action", self.next_action)
        if tuple(sorted(set(self.reasons))) != self.reasons:
            raise GraphContractError("decision_reasons_not_sorted_unique")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "decision_digest": self.digest,
            "experiment_id": self.experiment_id,
            "manifest_digest": self.manifest_digest,
            "next_action": self.next_action,
            "outcome": self.outcome,
            "projection_digest": self.projection_digest,
            "reasons": list(self.reasons),
            "schema_version": self.schema_version,
            "state": self.state.value,
        }

    @property
    def digest(self) -> str:
        value = {
            "experiment_id": self.experiment_id,
            "manifest_digest": self.manifest_digest,
            "next_action": self.next_action,
            "outcome": self.outcome,
            "projection_digest": self.projection_digest,
            "reasons": list(self.reasons),
            "schema_version": self.schema_version,
            "state": self.state.value,
        }
        return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class BudgetLimits:
    experiment_live_microdollars: int
    daily_live_microdollars: int
    weekly_live_microdollars: int
    elapsed_seconds: int
    live_concurrency: int

    def __post_init__(self) -> None:
        integer_fields = (
            "experiment_live_microdollars",
            "daily_live_microdollars",
            "weekly_live_microdollars",
            "elapsed_seconds",
            "live_concurrency",
        )
        for name in integer_fields:
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise GraphContractError(f"invalid_{name}")
        if self.experiment_live_microdollars > self.daily_live_microdollars:
            raise GraphContractError("experiment_budget_exceeds_daily_budget")
        if self.daily_live_microdollars > self.weekly_live_microdollars:
            raise GraphContractError("daily_budget_exceeds_weekly_budget")
        if self.elapsed_seconds > 86_400:
            raise GraphContractError("invalid_elapsed_seconds")
        if self.live_concurrency > 4:
            raise GraphContractError("invalid_live_concurrency")

    def to_canonical_dict(self) -> dict[str, int]:
        return {
            "daily_live_microdollars": self.daily_live_microdollars,
            "elapsed_seconds": self.elapsed_seconds,
            "experiment_live_microdollars": self.experiment_live_microdollars,
            "live_concurrency": self.live_concurrency,
            "weekly_live_microdollars": self.weekly_live_microdollars,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> BudgetLimits:
        if not isinstance(value, dict) or set(value) != {
            "daily_live_microdollars",
            "elapsed_seconds",
            "experiment_live_microdollars",
            "live_concurrency",
            "weekly_live_microdollars",
        }:
            raise GraphContractError("invalid_budget")
        try:
            return cls(**value)
        except TypeError as error:
            raise GraphContractError("invalid_budget") from error


@dataclass(frozen=True, slots=True)
class ExperimentManifest:
    schema_version: int
    experiment_id: str
    parent_experiment_id: str | None
    parent_commit: str
    parent_generation: int
    registered_at: str
    kind: ExperimentKind
    failure_cluster: str
    supporting_run_ids: tuple[str, ...]
    hypothesis: str
    target_surface: tuple[str, ...]
    forbidden_surface: tuple[str, ...]
    affected_tasks: tuple[str, ...]
    primary_metric: str
    guard_suites: tuple[str, ...]
    expected_direction: str
    minimum_effect_basis_points: int
    guard_noninferiority_basis_points: int
    deterministic_checks: tuple[str, ...]
    model: str
    provider: str
    harness_version: str
    tool_version: str
    task_version: str
    grader_version: str
    environment_digest: str
    policy_version: str
    minimum_paired_replicas: int
    maximum_paired_replicas: int
    budget: BudgetLimits
    known_risks: tuple[str, ...]
    rollback_trigger: str
    compatibility_impact: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise GraphContractError("invalid_manifest_schema")
        _identifier("experiment_id", self.experiment_id)
        if self.parent_experiment_id is not None:
            _identifier("parent_experiment_id", self.parent_experiment_id)
            if self.parent_experiment_id == self.experiment_id:
                raise GraphContractError("self_parent_experiment")
        if not _COMMIT_RE.fullmatch(self.parent_commit):
            raise GraphContractError("invalid_parent_commit")
        if (
            isinstance(self.parent_generation, bool)
            or not isinstance(self.parent_generation, int)
            or self.parent_generation < 0
        ):
            raise GraphContractError("invalid_parent_generation")
        _iso_utc("registered_at", self.registered_at)
        if not isinstance(self.kind, ExperimentKind):
            raise GraphContractError("invalid_experiment_kind")
        _identifier("failure_cluster", self.failure_cluster)
        _unique_texts("supporting_run_ids", self.supporting_run_ids)
        for run_id in self.supporting_run_ids:
            _identifier("supporting_run_id", run_id)
        _bounded_text("hypothesis", self.hypothesis, 4_096)
        _surface("target_surface", self.target_surface)
        _surface("forbidden_surface", self.forbidden_surface)
        for target in map(PurePosixPath, self.target_surface):
            for forbidden in map(PurePosixPath, self.forbidden_surface):
                if (
                    target == forbidden
                    or target in forbidden.parents
                    or forbidden in target.parents
                ):
                    raise GraphContractError("overlapping_source_surface")
        _unique_texts("affected_tasks", self.affected_tasks)
        for task in self.affected_tasks:
            _identifier("affected_task", task)
        _identifier("primary_metric", self.primary_metric)
        _unique_texts("guard_suites", self.guard_suites, maximum_items=32)
        for guard in self.guard_suites:
            _identifier("guard_suite", guard)
        if self.expected_direction not in {"increase", "decrease"}:
            raise GraphContractError("invalid_expected_direction")
        if (
            isinstance(self.minimum_effect_basis_points, bool)
            or not isinstance(self.minimum_effect_basis_points, int)
            or not 1 <= self.minimum_effect_basis_points <= 10_000
        ):
            raise GraphContractError("invalid_minimum_effect")
        if (
            isinstance(self.guard_noninferiority_basis_points, bool)
            or not isinstance(self.guard_noninferiority_basis_points, int)
            or not -10_000 <= self.guard_noninferiority_basis_points <= 0
        ):
            raise GraphContractError("invalid_guard_noninferiority")
        _unique_texts("deterministic_checks", self.deterministic_checks)
        for check in self.deterministic_checks:
            _identifier("deterministic_check", check)
        for name in (
            "model",
            "provider",
            "harness_version",
            "tool_version",
            "task_version",
            "grader_version",
            "policy_version",
        ):
            _identifier(name, getattr(self, name))
        if not _DIGEST_RE.fullmatch(self.environment_digest):
            raise GraphContractError("invalid_environment_digest")
        if (
            isinstance(self.minimum_paired_replicas, bool)
            or not isinstance(self.minimum_paired_replicas, int)
            or not 3 <= self.minimum_paired_replicas <= 10
        ):
            raise GraphContractError("invalid_minimum_paired_replicas")
        if (
            isinstance(self.maximum_paired_replicas, bool)
            or not isinstance(self.maximum_paired_replicas, int)
            or not self.minimum_paired_replicas <= self.maximum_paired_replicas <= 10
        ):
            raise GraphContractError("invalid_maximum_paired_replicas")
        if not isinstance(self.budget, BudgetLimits):
            raise GraphContractError("invalid_budget")
        _unique_texts("known_risks", self.known_risks, maximum_items=32)
        _bounded_text("rollback_trigger", self.rollback_trigger, 2_048)
        _bounded_text("compatibility_impact", self.compatibility_impact, 2_048)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "affected_tasks": list(self.affected_tasks),
            "budget": self.budget.to_canonical_dict(),
            "compatibility_impact": self.compatibility_impact,
            "deterministic_checks": list(self.deterministic_checks),
            "environment_digest": self.environment_digest,
            "expected_direction": self.expected_direction,
            "experiment_id": self.experiment_id,
            "failure_cluster": self.failure_cluster,
            "forbidden_surface": list(self.forbidden_surface),
            "grader_version": self.grader_version,
            "guard_noninferiority_basis_points": self.guard_noninferiority_basis_points,
            "guard_suites": list(self.guard_suites),
            "harness_version": self.harness_version,
            "hypothesis": self.hypothesis,
            "kind": self.kind.value,
            "known_risks": list(self.known_risks),
            "maximum_paired_replicas": self.maximum_paired_replicas,
            "minimum_effect_basis_points": self.minimum_effect_basis_points,
            "minimum_paired_replicas": self.minimum_paired_replicas,
            "model": self.model,
            "parent_commit": self.parent_commit,
            "parent_experiment_id": self.parent_experiment_id,
            "parent_generation": self.parent_generation,
            "policy_version": self.policy_version,
            "primary_metric": self.primary_metric,
            "provider": self.provider,
            "registered_at": self.registered_at,
            "rollback_trigger": self.rollback_trigger,
            "schema_version": self.schema_version,
            "supporting_run_ids": list(self.supporting_run_ids),
            "target_surface": list(self.target_surface),
            "task_version": self.task_version,
            "tool_version": self.tool_version,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()

    @classmethod
    def from_canonical_dict(cls, value: Any) -> ExperimentManifest:
        expected = {
            "affected_tasks",
            "budget",
            "compatibility_impact",
            "deterministic_checks",
            "environment_digest",
            "expected_direction",
            "experiment_id",
            "failure_cluster",
            "forbidden_surface",
            "grader_version",
            "guard_noninferiority_basis_points",
            "guard_suites",
            "harness_version",
            "hypothesis",
            "kind",
            "known_risks",
            "maximum_paired_replicas",
            "minimum_effect_basis_points",
            "minimum_paired_replicas",
            "model",
            "parent_commit",
            "parent_experiment_id",
            "parent_generation",
            "policy_version",
            "primary_metric",
            "provider",
            "registered_at",
            "rollback_trigger",
            "schema_version",
            "supporting_run_ids",
            "target_surface",
            "task_version",
            "tool_version",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise GraphContractError("invalid_manifest_keys")
        sequence_fields = (
            "affected_tasks",
            "deterministic_checks",
            "forbidden_surface",
            "guard_suites",
            "known_risks",
            "supporting_run_ids",
            "target_surface",
        )
        normalized = dict(value)
        for name in sequence_fields:
            item = value[name]
            if not isinstance(item, list) or any(not isinstance(entry, str) for entry in item):
                raise GraphContractError(f"invalid_{name}")
            normalized[name] = tuple(item)
        try:
            normalized["kind"] = ExperimentKind(value["kind"])
        except (TypeError, ValueError) as error:
            raise GraphContractError("invalid_experiment_kind") from error
        normalized["budget"] = BudgetLimits.from_canonical_dict(value["budget"])
        try:
            return cls(**normalized)
        except TypeError as error:
            raise GraphContractError("invalid_manifest") from error


@dataclass(frozen=True, slots=True)
class ExperimentEvent:
    schema_version: int
    experiment_id: str
    stage_attempt_id: str
    event_type: EventType
    occurred_at: str
    payload_json: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise GraphContractError("invalid_event_schema")
        _identifier("experiment_id", self.experiment_id)
        _identifier("stage_attempt_id", self.stage_attempt_id)
        if not isinstance(self.event_type, EventType):
            raise GraphContractError("invalid_event_type")
        _iso_utc("occurred_at", self.occurred_at)
        try:
            parsed = json.loads(self.payload_json)
            canonical = canonical_json_bytes(parsed).decode("utf-8")
        except (json.JSONDecodeError, UnicodeError, CanonicalizationError) as error:
            raise GraphContractError("invalid_event_payload") from error
        if not isinstance(parsed, dict) or canonical != self.payload_json:
            raise GraphContractError("noncanonical_event_payload")
        if len(self.payload_json.encode("utf-8")) > 16_384:
            raise GraphContractError("event_payload_too_large")

    @classmethod
    def create(
        cls,
        *,
        experiment_id: str,
        stage_attempt_id: str,
        event_type: EventType,
        occurred_at: str,
        payload: dict[str, Any],
    ) -> ExperimentEvent:
        try:
            payload_json = canonical_json_bytes(payload).decode("utf-8")
        except (UnicodeError, CanonicalizationError) as error:
            raise GraphContractError("invalid_event_payload") from error
        return cls(
            schema_version=1,
            experiment_id=experiment_id,
            stage_attempt_id=stage_attempt_id,
            event_type=event_type,
            occurred_at=occurred_at,
            payload_json=payload_json,
        )

    @property
    def payload(self) -> dict[str, Any]:
        value = json.loads(self.payload_json)
        if not isinstance(value, dict):
            raise AssertionError("validated event payload changed type")
        return value

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "experiment_id": self.experiment_id,
            "occurred_at": self.occurred_at,
            "payload": self.payload,
            "schema_version": self.schema_version,
            "stage_attempt_id": self.stage_attempt_id,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class ExperimentProjection:
    experiment_id: str
    manifest_digest: str
    state: ExperimentState
    last_sequence: int
    applied_attempt_ids: tuple[str, ...]
    event_digests: tuple[str, ...]
    proposal_reviews: tuple[ReviewOutput, ...]
    candidate_reviews: tuple[ReviewOutput, ...]
    lease: MutableStageLease | None
    live_spend_microdollars: int
    prepared_candidate: PreparedCandidate | None
    candidate: SealedCandidate | None
    paired_evidence: PairedEvidence | None
    review_packets: tuple[ReviewPacket, ...]
    candidate_attestations: tuple[ReviewAttestation, ...]
    draft_pull_request: DraftPullRequest | None
    draft_pull_request_request: dict[str, str] | None = None
    workspace_disposed: bool = False

    @property
    def digest(self) -> str:
        value = {
            "applied_attempt_ids": list(self.applied_attempt_ids),
            "candidate_reviews": [
                {
                    "artifact_digest": review.artifact_digest,
                    "role": review.role.value,
                    "stage_attempt_id": review.stage_attempt_id,
                    "verdict": review.verdict.value,
                }
                for review in self.candidate_reviews
            ],
            "event_digests": list(self.event_digests),
            "experiment_id": self.experiment_id,
            "last_sequence": self.last_sequence,
            "lease": (
                {
                    "acquired_at": self.lease.acquired_at,
                    "expires_at": self.lease.expires_at,
                    "owner_id": self.lease.owner_id,
                    "stage_attempt_id": self.lease.stage_attempt_id,
                    "stale_reconciled": self.lease.stale_reconciled,
                }
                if self.lease is not None
                else None
            ),
            "live_spend_microdollars": self.live_spend_microdollars,
            "manifest_digest": self.manifest_digest,
            "paired_evidence": (
                self.paired_evidence.to_canonical_dict()
                if self.paired_evidence is not None
                else None
            ),
            "prepared_candidate": (
                self.prepared_candidate.to_canonical_dict()
                if self.prepared_candidate is not None
                else None
            ),
            "proposal_reviews": [
                {
                    "artifact_digest": review.artifact_digest,
                    "role": review.role.value,
                    "stage_attempt_id": review.stage_attempt_id,
                    "verdict": review.verdict.value,
                }
                for review in self.proposal_reviews
            ],
            "candidate": (
                self.candidate.to_canonical_dict() if self.candidate is not None else None
            ),
            "candidate_attestations": [
                review.to_canonical_dict() for review in self.candidate_attestations
            ],
            "draft_pull_request": (
                self.draft_pull_request.to_canonical_dict()
                if self.draft_pull_request is not None
                else None
            ),
            "draft_pull_request_request": self.draft_pull_request_request,
            "review_packets": [packet.to_canonical_dict() for packet in self.review_packets],
            "state": self.state.value,
            "workspace_disposed": self.workspace_disposed,
        }
        return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


_FORWARD: dict[ExperimentState, ExperimentState] = {
    ExperimentState.QUEUED: ExperimentState.BASELINING,
    ExperimentState.BASELINING: ExperimentState.DIAGNOSING,
    ExperimentState.DIAGNOSING: ExperimentState.PROPOSAL_REVIEW,
    ExperimentState.PROPOSAL_REVIEW: ExperimentState.BUILDING,
    ExperimentState.BUILDING: ExperimentState.DETERMINISTIC_VALIDATION,
    ExperimentState.DETERMINISTIC_VALIDATION: ExperimentState.PAIRED_EVALUATION,
    ExperimentState.PAIRED_EVALUATION: ExperimentState.HOLDOUT_VALIDATION,
    ExperimentState.HOLDOUT_VALIDATION: ExperimentState.REVIEW_COMPLETE,
    ExperimentState.REVIEW_COMPLETE: ExperimentState.PR_OPEN,
    ExperimentState.PR_OPEN: ExperimentState.MERGED,
    ExperimentState.MERGED: ExperimentState.SOAKING,
    ExperimentState.SOAKING: ExperimentState.ACCEPTED,
}
_ALTERNATE_TERMINALS = frozenset(
    {
        ExperimentState.REJECTED,
        ExperimentState.INCONCLUSIVE,
        ExperimentState.BLOCKED,
        ExperimentState.BUDGET_EXHAUSTED,
        ExperimentState.REVERTED,
        ExperimentState.ABANDONED,
    }
)
_TERMINALS = _ALTERNATE_TERMINALS | {ExperimentState.ACCEPTED}
_MUTABLE_STATES = frozenset(
    {
        ExperimentState.BUILDING,
        ExperimentState.DETERMINISTIC_VALIDATION,
        ExperimentState.PAIRED_EVALUATION,
        ExperimentState.HOLDOUT_VALIDATION,
        ExperimentState.REVIEW_COMPLETE,
        ExperimentState.PR_OPEN,
        ExperimentState.MERGED,
        ExperimentState.SOAKING,
    }
)
_LEASE_REQUIRED_TARGETS = _MUTABLE_STATES | {ExperimentState.ACCEPTED}


def _state_payload(event: ExperimentEvent) -> tuple[ExperimentState, ExperimentState]:
    payload = _operation_payload(event)
    if set(payload) != {"from_state", "to_state"}:
        raise GraphContractError("invalid_transition_payload")
    try:
        return ExperimentState(payload["from_state"]), ExperimentState(payload["to_state"])
    except (TypeError, ValueError) as error:
        raise GraphContractError("invalid_transition_payload") from error


def _review_payload(event: ExperimentEvent) -> ReviewOutput:
    payload = _operation_payload(event)
    if set(payload) != {"artifact_digest", "role", "verdict"}:
        raise GraphContractError("invalid_review_payload")
    try:
        return ReviewOutput(
            role=ReviewRole(payload["role"]),
            verdict=ReviewVerdict(payload["verdict"]),
            artifact_digest=payload["artifact_digest"],
            stage_attempt_id=event.stage_attempt_id,
        )
    except (TypeError, ValueError) as error:
        raise GraphContractError("invalid_review_payload") from error


def _proposal_quorum(reviews: tuple[ReviewOutput, ...]) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if any(review.verdict is ReviewVerdict.HARD_OBJECTION for review in reviews):
        reasons.append("proposal_hard_objection")
    elif sum(review.verdict is ReviewVerdict.APPROVE for review in reviews) < 2:
        reasons.append("proposal_approvals_below_two")
    return not reasons, tuple(reasons)


def _candidate_quorum(reviews: tuple[ReviewOutput, ...]) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if any(review.verdict is ReviewVerdict.HARD_FINDING for review in reviews):
        reasons.append("candidate_hard_finding")
    elif sum(review.verdict is ReviewVerdict.APPROVE for review in reviews) < 3:
        reasons.append("candidate_approvals_below_three")
    return not reasons, tuple(reasons)


def _operation_payload(event: ExperimentEvent) -> dict[str, Any]:
    return {key: value for key, value in event.payload.items() if key != "_lease"}


def _require_live_lease(lease: MutableStageLease | None, event: ExperimentEvent) -> dict[str, Any]:
    if lease is None or _parse_utc(event.occurred_at) > _parse_utc(lease.expires_at):
        raise GraphContractError("mutable_lease_required")
    authorization = event.payload.get("_lease")
    if (
        not isinstance(authorization, dict)
        or set(authorization) != {"owner_id", "stage_attempt_id"}
        or authorization["owner_id"] != lease.owner_id
        or authorization["stage_attempt_id"] != lease.stage_attempt_id
    ):
        raise GraphContractError("lease_capability_invalid")
    return _operation_payload(event)


def _projection(
    *,
    manifest: ExperimentManifest,
    state: ExperimentState,
    attempts: list[str],
    digests: list[str],
    proposal_reviews: dict[ReviewRole, ReviewOutput],
    candidate_reviews: dict[ReviewRole, ReviewOutput],
    lease: MutableStageLease | None,
    live_spend_microdollars: int,
    prepared_candidate: PreparedCandidate | None,
    candidate: SealedCandidate | None,
    paired_evidence: PairedEvidence | None,
    review_packets: dict[str, ReviewPacket],
    candidate_attestations: dict[str, ReviewAttestation],
    draft_pull_request: DraftPullRequest | None,
    draft_pull_request_request: dict[str, str] | None,
    workspace_disposed: bool,
) -> ExperimentProjection:
    return ExperimentProjection(
        experiment_id=manifest.experiment_id,
        manifest_digest=manifest.digest,
        state=state,
        last_sequence=len(attempts),
        applied_attempt_ids=tuple(attempts),
        event_digests=tuple(digests),
        proposal_reviews=tuple(
            proposal_reviews[role] for role in sorted(proposal_reviews, key=str)
        ),
        candidate_reviews=tuple(
            candidate_reviews[role] for role in sorted(candidate_reviews, key=str)
        ),
        lease=lease,
        live_spend_microdollars=live_spend_microdollars,
        prepared_candidate=prepared_candidate,
        candidate=candidate,
        paired_evidence=paired_evidence,
        review_packets=tuple(review_packets[role] for role in sorted(review_packets)),
        candidate_attestations=tuple(
            candidate_attestations[role] for role in sorted(candidate_attestations)
        ),
        draft_pull_request=draft_pull_request,
        draft_pull_request_request=draft_pull_request_request,
        workspace_disposed=workspace_disposed,
    )


def reduce_events(
    manifest: ExperimentManifest,
    events: tuple[ExperimentEvent, ...],
    *,
    trusted_authority_event_digests: frozenset[str] = frozenset(),
) -> ExperimentProjection:
    """Replay events, recognizing only explicitly ledger-verified authority facts."""
    state = ExperimentState.QUEUED
    attempts: list[str] = []
    digests: list[str] = []
    seen_attempts: set[str] = set()
    proposal_reviews: dict[ReviewRole, ReviewOutput] = {}
    candidate_reviews: dict[ReviewRole, ReviewOutput] = {}
    lease: MutableStageLease | None = None
    live_spend_microdollars = 0
    prepared_candidate: PreparedCandidate | None = None
    candidate: SealedCandidate | None = None
    paired_evidence: PairedEvidence | None = None
    review_packets: dict[str, ReviewPacket] = {}
    candidate_attestations: dict[str, ReviewAttestation] = {}
    draft_pull_request: DraftPullRequest | None = None
    draft_pull_request_request: dict[str, str] | None = None
    workspace_disposed = False
    experimental_publication: dict[str, Any] | None = None
    protected_validation_candidate_commit: str | None = None
    for event in events:
        if event.experiment_id != manifest.experiment_id:
            raise GraphContractError("event_experiment_mismatch")
        trusted_authority = event.digest in trusted_authority_event_digests
        if event.event_type is EventType.EXPERIMENTAL_PUBLISHED:
            experimental_publication = event.payload
            continue
        if event.event_type in _AUTONOMY_EVENT_TYPES and not (
            event.event_type is EventType.PROTECTED_VALIDATION_RECORDED
            and trusted_authority
            and candidate is not None
            and paired_evidence is not None
        ):
            continue
        if event.event_type in _ISOLATED_AUTHORITY_REQUIRED_EVENTS and not trusted_authority:
            raise GraphContractError("isolated_signer_required")
        if _parse_utc(event.occurred_at) < _parse_utc(manifest.registered_at):
            raise GraphContractError("event_precedes_registration")
        if event.stage_attempt_id in seen_attempts:
            raise GraphContractError("duplicate_stage_attempt")
        if event.event_type is EventType.STATE_TRANSITIONED:
            source, target = _state_payload(event)
            if state in _TERMINALS:
                raise GraphContractError("terminal_state")
            if source is not state:
                raise GraphContractError("stale_source_state")
            if target is not _FORWARD.get(state) and target not in _ALTERNATE_TERMINALS:
                raise GraphContractError("invalid_transition")
            if target is ExperimentState.BUILDING:
                approved, _ = _proposal_quorum(tuple(proposal_reviews.values()))
                if not approved:
                    raise GraphContractError("proposal_quorum_unsatisfied")
            if target in _LEASE_REQUIRED_TARGETS:
                _require_live_lease(lease, event)
            if target is ExperimentState.REVIEW_COMPLETE:
                approved, _ = _candidate_quorum(tuple(candidate_reviews.values()))
                if not approved:
                    raise GraphContractError("candidate_quorum_unsatisfied")
            if target is ExperimentState.DETERMINISTIC_VALIDATION and (
                prepared_candidate is not None and candidate is None
            ):
                raise GraphContractError("sealed_candidate_required")
            if target is ExperimentState.PAIRED_EVALUATION and candidate is not None:
                check_ids = tuple(check.check_id for check in candidate.checks)
                if check_ids != tuple(sorted(manifest.deterministic_checks, key=str.encode)):
                    raise GraphContractError("deterministic_checks_mismatch")
            if (
                target is ExperimentState.HOLDOUT_VALIDATION
                and candidate is not None
                and (
                    paired_evidence is None
                    or protected_validation_candidate_commit != candidate.candidate_commit
                )
            ):
                raise GraphContractError("phase4_protected_validation_required")
            state = target
        elif event.event_type is EventType.ROLE_RECORDED:
            review = _review_payload(event)
            if review.role in _PROPOSAL_ROLES:
                if state is not ExperimentState.PROPOSAL_REVIEW:
                    raise GraphContractError("proposal_review_wrong_state")
                if review.role in proposal_reviews:
                    raise GraphContractError("duplicate_review_role")
                proposal_reviews[review.role] = review
            else:
                if state is not ExperimentState.HOLDOUT_VALIDATION:
                    raise GraphContractError("candidate_review_wrong_state")
                _require_live_lease(lease, event)
                if review.role in candidate_reviews:
                    raise GraphContractError("duplicate_review_role")
                candidate_reviews[review.role] = review
        elif event.event_type is EventType.LEASE_ACQUIRED:
            payload = event.payload
            if set(payload) != {"expires_at", "owner_id"}:
                raise GraphContractError("invalid_lease_payload")
            replacing_reconciled = lease is not None and lease.stale_reconciled
            if state is not ExperimentState.PROPOSAL_REVIEW and not (
                replacing_reconciled and state in _MUTABLE_STATES
            ):
                raise GraphContractError("lease_wrong_state")
            if lease is not None and not replacing_reconciled:
                raise GraphContractError("mutable_lease_conflict")
            try:
                _identifier("lease_owner", payload["owner_id"])
                acquired_at = _parse_utc(event.occurred_at)
                expires_at = _parse_utc(payload["expires_at"])
            except (TypeError, GraphContractError) as error:
                raise GraphContractError("invalid_lease_payload") from error
            duration = (expires_at - acquired_at).total_seconds()
            if not 0 < duration <= 21_600:
                raise GraphContractError("invalid_lease_duration")
            lease = MutableStageLease(
                stage_attempt_id=event.stage_attempt_id,
                owner_id=payload["owner_id"],
                acquired_at=event.occurred_at,
                expires_at=payload["expires_at"],
            )
        elif event.event_type is EventType.LEASE_RECONCILED:
            payload = event.payload
            if set(payload) != {"lease_stage_attempt_id", "worker_not_live"}:
                raise GraphContractError("invalid_lease_reconciliation")
            if lease is None or payload["lease_stage_attempt_id"] != lease.stage_attempt_id:
                raise GraphContractError("lease_identity_mismatch")
            if payload["worker_not_live"] is not True:
                raise GraphContractError("lease_worker_state_uncertain")
            if _parse_utc(event.occurred_at) < _parse_utc(lease.expires_at):
                raise GraphContractError("lease_not_expired")
            lease = replace(lease, stale_reconciled=True)
        elif event.event_type is EventType.LEASE_RELEASED:
            payload = event.payload
            if set(payload) != {"lease_stage_attempt_id"}:
                raise GraphContractError("invalid_lease_release")
            if lease is None or payload["lease_stage_attempt_id"] != lease.stage_attempt_id:
                raise GraphContractError("lease_identity_mismatch")
            if state in _MUTABLE_STATES:
                raise GraphContractError("mutable_stage_still_active")
            if (
                _parse_utc(event.occurred_at) > _parse_utc(lease.expires_at)
                and not lease.stale_reconciled
            ):
                raise GraphContractError("stale_lease_unreconciled")
            lease = None
        elif event.event_type is EventType.LIVE_SPEND_RECORDED:
            payload = event.payload
            if set(payload) != {"live_microdollars", "run_id"}:
                raise GraphContractError("invalid_spend_payload")
            amount = payload["live_microdollars"]
            if (
                isinstance(amount, bool)
                or not isinstance(amount, int)
                or not 0 < amount <= 1_000_000_000
            ):
                raise GraphContractError("invalid_spend_amount")
            try:
                _identifier("run_id", payload["run_id"])
            except (TypeError, GraphContractError) as error:
                raise GraphContractError("invalid_spend_payload") from error
            live_spend_microdollars += amount
        elif event.event_type is EventType.WORKSPACE_PREPARED:
            if state is not ExperimentState.BUILDING:
                raise GraphContractError("candidate_prepare_wrong_state")
            payload = _require_live_lease(lease, event)
            if prepared_candidate is not None:
                raise GraphContractError("candidate_already_prepared")
            try:
                prepared = PreparedCandidate.from_canonical_dict(payload)
            except CandidateContractError as error:
                raise GraphContractError("invalid_prepared_candidate_payload") from error
            if (
                prepared.experiment_id != manifest.experiment_id
                or prepared.manifest_digest != manifest.digest
                or prepared.parent_commit != manifest.parent_commit
            ):
                raise GraphContractError("prepared_candidate_manifest_mismatch")
            prepared_candidate = prepared
        elif event.event_type is EventType.CANDIDATE_SEALED:
            if state is not ExperimentState.BUILDING:
                raise GraphContractError("candidate_seal_wrong_state")
            payload = _require_live_lease(lease, event)
            if prepared_candidate is None:
                raise GraphContractError("prepared_candidate_required")
            if candidate is not None:
                raise GraphContractError("candidate_already_sealed")
            try:
                sealed = SealedCandidate.from_canonical_dict(payload)
            except CandidateContractError as error:
                raise GraphContractError("invalid_sealed_candidate_payload") from error
            if (
                sealed.experiment_id != manifest.experiment_id
                or sealed.manifest_digest != manifest.digest
                or sealed.parent_commit != manifest.parent_commit
                or sealed.branch != prepared_candidate.branch
            ):
                raise GraphContractError("sealed_candidate_manifest_mismatch")
            check_ids = tuple(check.check_id for check in sealed.checks)
            if check_ids != tuple(sorted(manifest.deterministic_checks, key=str.encode)):
                raise GraphContractError("deterministic_checks_mismatch")
            candidate = sealed
        elif event.event_type is EventType.PAIRED_EVIDENCE_RECORDED:
            if state is not ExperimentState.PAIRED_EVALUATION:
                raise GraphContractError("paired_evidence_wrong_state")
            payload = _require_live_lease(lease, event)
            if candidate is None:
                raise GraphContractError("sealed_candidate_required")
            if paired_evidence is not None:
                raise GraphContractError("paired_evidence_already_recorded")
            try:
                evidence = PairedEvidence.from_canonical_dict(payload)
            except CandidateContractError as error:
                raise GraphContractError("invalid_paired_evidence_payload") from error
            if (
                evidence.experiment_id != manifest.experiment_id
                or evidence.manifest_digest != manifest.digest
                or evidence.parent_commit != manifest.parent_commit
                or evidence.candidate_commit != candidate.candidate_commit
            ):
                raise GraphContractError("paired_evidence_candidate_mismatch")
            paired_evidence = evidence
        elif event.event_type is EventType.PROTECTED_VALIDATION_RECORDED:
            if state is not ExperimentState.PAIRED_EVALUATION:
                raise GraphContractError("protected_validation_wrong_state")
            if candidate is None or paired_evidence is None:
                raise GraphContractError("paired_evidence_required")
            if protected_validation_candidate_commit is not None:
                raise GraphContractError("protected_validation_already_recorded")
            payload = event.payload
            if set(payload) != {
                "candidate_commit",
                "candidate_tree",
                "receipt_digest",
            }:
                raise GraphContractError("invalid_protected_validation_payload")
            if (
                experimental_publication is None
                or set(experimental_publication)
                != {"branch", "candidate_packet_digest", "commit", "tree"}
                or experimental_publication["candidate_packet_digest"] != candidate.digest
                or experimental_publication["commit"] != candidate.candidate_commit
                or payload["candidate_commit"] != candidate.candidate_commit
                or payload["candidate_commit"] != experimental_publication["commit"]
                or payload["candidate_tree"] != experimental_publication["tree"]
                or not isinstance(payload["receipt_digest"], str)
                or not _DIGEST_RE.fullmatch(payload["receipt_digest"])
            ):
                raise GraphContractError("protected_validation_candidate_mismatch")
            protected_validation_candidate_commit = payload["candidate_commit"]
        elif event.event_type is EventType.REVIEW_PACKET_RECORDED:
            if state is not ExperimentState.PAIRED_EVALUATION:
                raise GraphContractError("review_packet_wrong_state")
            payload = _require_live_lease(lease, event)
            if candidate is None or paired_evidence is None:
                raise GraphContractError("paired_evidence_required")
            if paired_evidence.decision != "improvement":
                raise GraphContractError("paired_improvement_required")
            try:
                packet = ReviewPacket.from_canonical_dict(payload)
            except CandidateContractError as error:
                raise GraphContractError("invalid_review_packet_payload") from error
            if packet.role in review_packets:
                raise GraphContractError("duplicate_review_packet_role")
            if (
                packet.experiment_id != manifest.experiment_id
                or packet.manifest_digest != manifest.digest
                or packet.candidate_commit != candidate.candidate_commit
                or packet.diff_digest != candidate.diff_artifact.digest
                or packet.deterministic_evidence_digest != candidate.digest
                or packet.paired_evidence_digest != paired_evidence.digest
            ):
                raise GraphContractError("review_packet_candidate_mismatch")
            review_packets[packet.role] = packet
        elif event.event_type is EventType.REVIEW_ATTESTED:
            if state is not ExperimentState.PAIRED_EVALUATION:
                raise GraphContractError("review_attestation_wrong_state")
            payload = _require_live_lease(lease, event)
            try:
                raw_role = payload.get("role")
            except AttributeError as error:
                raise GraphContractError("invalid_review_attestation_payload") from error
            packet = review_packets.get(raw_role)
            if packet is None:
                raise GraphContractError("review_packet_required")
            if raw_role in candidate_attestations:
                raise GraphContractError("duplicate_review_attestation_role")
            try:
                attestation = ReviewAttestation.from_packet_dict(payload, packet)
            except CandidateContractError as error:
                raise GraphContractError("invalid_review_attestation_payload") from error
            if any(
                prior.reviewer_id == attestation.reviewer_id
                for prior in candidate_attestations.values()
            ):
                raise GraphContractError("reviewer_identity_reused")
            if any(
                prior.context_id == attestation.context_id
                for prior in candidate_attestations.values()
            ):
                raise GraphContractError("review_context_reused")
            candidate_attestations[attestation.role] = attestation
        elif event.event_type is EventType.DRAFT_PR_REQUESTED:
            if state is not ExperimentState.PAIRED_EVALUATION:
                raise GraphContractError("draft_pr_wrong_state")
            payload = _require_live_lease(lease, event)
            if candidate is None or paired_evidence is None:
                raise GraphContractError("paired_evidence_required")
            if draft_pull_request_request is not None:
                raise GraphContractError("draft_pr_authorization_already_recorded")
            attestations = tuple(candidate_attestations.values())
            if (
                len(attestations) != len(_CANDIDATE_ROLES)
                or set(candidate_attestations) != {role.value for role in _CANDIDATE_ROLES}
                or sum(review.verdict == "approve" for review in attestations) < 3
                or any(review.verdict == "hard_finding" for review in attestations)
            ):
                raise GraphContractError("candidate_attestation_quorum_unsatisfied")
            expected = {
                "base_branch",
                "candidate_commit",
                "expected_remote_url",
                "head_branch",
                "repository",
            }
            if (
                set(payload) != expected
                or not isinstance(payload["repository"], str)
                or not _REPOSITORY_RE.fullmatch(payload["repository"])
                or not isinstance(payload["base_branch"], str)
                or not _ID_RE.fullmatch(payload["base_branch"])
                or payload["head_branch"] != candidate.branch
                or payload["candidate_commit"] != candidate.candidate_commit
                or not isinstance(payload["expected_remote_url"], str)
                or not payload["expected_remote_url"]
                or "\x00" in payload["expected_remote_url"]
                or len(payload["expected_remote_url"].encode("utf-8")) > 4_096
            ):
                raise GraphContractError("invalid_draft_pr_authorization")
            draft_pull_request_request = dict(payload)
        elif event.event_type is EventType.DRAFT_PR_RECORDED:
            if state is not ExperimentState.PAIRED_EVALUATION:
                raise GraphContractError("draft_pr_wrong_state")
            payload = _operation_payload(event)
            if candidate is None or paired_evidence is None:
                raise GraphContractError("paired_evidence_required")
            if draft_pull_request_request is None:
                raise GraphContractError("draft_pr_authorization_required")
            if draft_pull_request is not None:
                raise GraphContractError("draft_pr_already_recorded")
            attestations = tuple(candidate_attestations.values())
            if (
                len(attestations) != len(_CANDIDATE_ROLES)
                or set(candidate_attestations) != {role.value for role in _CANDIDATE_ROLES}
                or sum(review.verdict == "approve" for review in attestations) < 3
                or any(review.verdict == "hard_finding" for review in attestations)
            ):
                raise GraphContractError("candidate_attestation_quorum_unsatisfied")
            try:
                draft = DraftPullRequest.from_candidate_dict(payload, candidate)
            except CandidateContractError as error:
                raise GraphContractError("invalid_draft_pr_payload") from error
            if (
                draft.repository != draft_pull_request_request["repository"]
                or draft.base_branch != draft_pull_request_request["base_branch"]
                or draft.head_branch != draft_pull_request_request["head_branch"]
                or draft.candidate_commit != draft_pull_request_request["candidate_commit"]
            ):
                raise GraphContractError("draft_pr_authorization_mismatch")
            draft_pull_request = draft
        elif event.event_type is EventType.WORKSPACE_DISPOSED:
            if state is not ExperimentState.PAIRED_EVALUATION:
                raise GraphContractError("workspace_dispose_wrong_state")
            payload = _require_live_lease(lease, event)
            if prepared_candidate is None or candidate is None or draft_pull_request is None:
                raise GraphContractError("draft_pr_required")
            if workspace_disposed:
                raise GraphContractError("workspace_already_disposed")
            if set(payload) != {
                "branch",
                "candidate_commit",
            }:
                raise GraphContractError("invalid_workspace_disposed_payload")
            if (
                payload["branch"] != prepared_candidate.branch
                or payload["branch"] != candidate.branch
                or payload["candidate_commit"] != candidate.candidate_commit
            ):
                raise GraphContractError("workspace_disposed_candidate_mismatch")
            workspace_disposed = True
        else:
            raise GraphContractError("unsupported_event_type")
        if event.event_type not in _AUTONOMY_EVENT_TYPES:
            seen_attempts.add(event.stage_attempt_id)
            attempts.append(event.stage_attempt_id)
            digests.append(event.digest)
    return _projection(
        manifest=manifest,
        state=state,
        attempts=attempts,
        digests=digests,
        proposal_reviews=proposal_reviews,
        candidate_reviews=candidate_reviews,
        lease=lease,
        live_spend_microdollars=live_spend_microdollars,
        prepared_candidate=prepared_candidate,
        candidate=candidate,
        paired_evidence=paired_evidence,
        review_packets=review_packets,
        candidate_attestations=candidate_attestations,
        draft_pull_request=draft_pull_request,
        draft_pull_request_request=draft_pull_request_request,
        workspace_disposed=workspace_disposed,
    )


def evaluate_dry_run(
    manifest: ExperimentManifest, projection: ExperimentProjection
) -> DryRunDecision:
    """Return the next deterministic dry-run action without dispatching it."""
    if (
        projection.experiment_id != manifest.experiment_id
        or projection.manifest_digest != manifest.digest
    ):
        raise GraphContractError("projection_manifest_mismatch")
    if projection.live_spend_microdollars >= manifest.budget.experiment_live_microdollars:
        outcome = "budget_exhausted"
        next_action = "record_budget_exhausted"
        reasons = ("experiment_live_budget_exhausted",)
    elif projection.state in _TERMINALS:
        outcome = "terminal"
        next_action = "none"
        reasons = ()
    elif projection.state is ExperimentState.PROPOSAL_REVIEW:
        approved, reasons = _proposal_quorum(projection.proposal_reviews)
        if approved:
            outcome = "advance"
            next_action = (
                "acquire_candidate_lease"
                if projection.lease is None
                else "record_building_transition"
            )
            reasons = ()
        else:
            outcome = "blocked"
            next_action = "collect_proposal_reviews"
    elif projection.state is ExperimentState.BUILDING:
        outcome = "advance"
        if projection.prepared_candidate is None:
            next_action = "prepare_candidate"
        elif projection.candidate is None:
            next_action = "seal_candidate"
        else:
            next_action = "record_deterministic_validation"
        reasons = ()
    elif projection.state is ExperimentState.DETERMINISTIC_VALIDATION:
        if projection.candidate is None:
            outcome = "blocked"
            next_action = "seal_candidate"
            reasons = ("sealed_candidate_required",)
        else:
            outcome = "advance"
            next_action = "record_paired_evaluation"
            reasons = ()
    elif projection.state is ExperimentState.PAIRED_EVALUATION:
        phase3 = evaluate_phase3(manifest, projection)
        next_action = phase3.next_action
        if phase3.outcome == "advance":
            outcome = "advance"
            reasons = ()
        else:
            outcome = "blocked"
            reasons = phase3.reasons or (phase3.next_action,)
    else:
        next_by_state = {
            ExperimentState.QUEUED: "start_baseline",
            ExperimentState.BASELINING: "record_baseline_diagnosis",
            ExperimentState.DIAGNOSING: "author_hypothesis",
            ExperimentState.HOLDOUT_VALIDATION: "phase4_holdout_not_enabled",
            ExperimentState.REVIEW_COMPLETE: "phase4_promotion_not_enabled",
            ExperimentState.PR_OPEN: "phase4_merge_not_enabled",
            ExperimentState.MERGED: "phase4_soak_not_enabled",
            ExperimentState.SOAKING: "phase4_acceptance_not_enabled",
        }
        next_action = next_by_state[projection.state]
        if projection.state in {
            ExperimentState.QUEUED,
            ExperimentState.BASELINING,
            ExperimentState.DIAGNOSING,
        }:
            outcome = "advance"
            reasons = ()
        else:
            outcome = "blocked"
            reasons = (next_action,)
    return DryRunDecision(
        schema_version=1,
        experiment_id=manifest.experiment_id,
        manifest_digest=manifest.digest,
        projection_digest=projection.digest,
        state=projection.state,
        outcome=outcome,
        next_action=next_action,
        reasons=tuple(sorted(reasons)),
    )


def evaluate_phase3(
    manifest: ExperimentManifest, projection: ExperimentProjection
) -> Phase3Decision:
    """Return the next local candidate action without claiming protected validation."""
    if (
        projection.experiment_id != manifest.experiment_id
        or projection.manifest_digest != manifest.digest
    ):
        raise GraphContractError("projection_manifest_mismatch")

    outcome = "advance"
    reasons: tuple[str, ...] = ()
    if projection.candidate is None:
        if projection.state is ExperimentState.BUILDING:
            next_action = (
                "prepare_candidate" if projection.prepared_candidate is None else "seal_candidate"
            )
        else:
            outcome = "blocked"
            next_action = "reach_building_state"
            reasons = ("phase3_candidate_not_building",)
    elif projection.state is ExperimentState.BUILDING:
        next_action = "record_deterministic_validation"
    elif projection.state is ExperimentState.DETERMINISTIC_VALIDATION:
        next_action = "record_paired_evaluation"
    elif projection.state is not ExperimentState.PAIRED_EVALUATION:
        outcome = "blocked"
        next_action = "none"
        reasons = ("phase3_state_not_supported",)
    else:
        outcome = "blocked"
        next_action = "await_isolated_signer"
        reasons = ("experimental_publication_disabled",)

    return Phase3Decision(
        schema_version=1,
        experiment_id=manifest.experiment_id,
        manifest_digest=manifest.digest,
        projection_digest=projection.digest,
        outcome=outcome,
        next_action=next_action,
        reasons=reasons,
    )
