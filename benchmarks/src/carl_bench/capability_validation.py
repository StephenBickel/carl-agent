"""Deterministic capability-validity and benchmark-gaming gates."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from carl_bench.canonical import canonical_json_bytes

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_CLAIM_TYPES = frozenset({"capability", "compatibility", "correctness"})
_TRANSFER_TYPES = frozenset({"adversarial", "fixture_probe", "held_out", "unit_contract"})
_BEHAVIORAL_TRANSFER_TYPES = frozenset({"adversarial", "held_out"})
_PROTECTED_EXACT_PATHS = frozenset(
    {
        ".github/CODEOWNERS",
        "benchmarks/src/carl_bench/capability_validation.py",
        "benchmarks/src/carl_bench/promotion.py",
        "benchmarks/src/carl_bench/verifier.py",
    }
)
_PROTECTED_PATH_PREFIXES = (
    ".codex/automations/",
    ".github/workflows/",
    "benchmarks/graders/",
    "benchmarks/metric_packs/",
    "benchmarks/metrics/",
    "benchmarks/policies/",
    "benchmarks/tasks/",
)


class CapabilityValidationError(ValueError):
    """A stable capability-contract failure that does not echo untrusted input."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _identifier(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 256
        or not _IDENTIFIER_RE.fullmatch(value)
    ):
        raise CapabilityValidationError("capability_identifier_invalid")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise CapabilityValidationError("capability_digest_invalid")
    return value


def _basis_points(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10_000:
        raise CapabilityValidationError("capability_basis_points_invalid")
    return value


def _sorted_identifiers(values: Any) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise CapabilityValidationError("capability_tuple_invalid")
    normalized = tuple(_identifier(value) for value in values)
    if len(set(normalized)) != len(normalized) or normalized != tuple(sorted(normalized)):
        raise CapabilityValidationError("capability_tuple_order_invalid")
    return normalized


@dataclass(frozen=True, slots=True)
class TransferCheck:
    check_id: str
    task_id: str
    check_type: str
    evaluator_digest: str
    minimum_candidate_basis_points: int

    def __post_init__(self) -> None:
        _identifier(self.check_id)
        _identifier(self.task_id)
        if self.check_type not in _TRANSFER_TYPES:
            raise CapabilityValidationError("capability_transfer_type_invalid")
        _digest(self.evaluator_digest)
        _basis_points(self.minimum_candidate_basis_points)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_type": self.check_type,
            "evaluator_digest": self.evaluator_digest,
            "minimum_candidate_basis_points": self.minimum_candidate_basis_points,
            "task_id": self.task_id,
        }


@dataclass(frozen=True, slots=True)
class CapabilityClaim:
    claim_id: str
    claim_type: str
    behavior: str
    affected_task_ids: tuple[str, ...]
    guard_task_ids: tuple[str, ...]
    transfer_checks: tuple[TransferCheck, ...]

    def __post_init__(self) -> None:
        _identifier(self.claim_id)
        if self.claim_type not in _CLAIM_TYPES:
            raise CapabilityValidationError("capability_claim_type_invalid")
        if (
            not isinstance(self.behavior, str)
            or not self.behavior.strip()
            or len(self.behavior.encode("utf-8")) > 2_048
        ):
            raise CapabilityValidationError("capability_behavior_invalid")
        affected = _sorted_identifiers(self.affected_task_ids)
        guards = _sorted_identifiers(self.guard_task_ids)
        if not affected or set(affected) & set(guards):
            raise CapabilityValidationError("capability_task_roles_invalid")
        if not isinstance(self.transfer_checks, tuple) or any(
            not isinstance(item, TransferCheck) for item in self.transfer_checks
        ):
            raise CapabilityValidationError("capability_transfer_checks_invalid")
        check_ids = tuple(item.check_id for item in self.transfer_checks)
        if len(set(check_ids)) != len(check_ids) or check_ids != tuple(sorted(check_ids)):
            raise CapabilityValidationError("capability_tuple_order_invalid")
        transfer_task_ids = tuple(item.task_id for item in self.transfer_checks)
        if len(set(transfer_task_ids)) != len(transfer_task_ids):
            raise CapabilityValidationError("capability_transfer_checks_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "affected_task_ids": list(self.affected_task_ids),
            "behavior": self.behavior,
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "guard_task_ids": list(self.guard_task_ids),
            "transfer_checks": [item.to_canonical_dict() for item in self.transfer_checks],
        }


@dataclass(frozen=True, slots=True)
class TaskOutcome:
    task_id: str
    task_digest: str
    evaluator_digest: str
    score_basis_points: int
    valid_trials: tuple[str, ...]
    invalid_trials: tuple[str, ...]
    passed_trials: tuple[str, ...]
    failed_trials: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.task_id)
        _digest(self.task_digest)
        _digest(self.evaluator_digest)
        _basis_points(self.score_basis_points)
        valid = _sorted_identifiers(self.valid_trials)
        invalid = _sorted_identifiers(self.invalid_trials)
        passed = _sorted_identifiers(self.passed_trials)
        failed = _sorted_identifiers(self.failed_trials)
        if set(valid) & set(invalid) or set(passed) & set(failed):
            raise CapabilityValidationError("capability_trial_accounting_invalid")
        if set(valid) != set(passed) | set(failed):
            raise CapabilityValidationError("capability_trial_accounting_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "evaluator_digest": self.evaluator_digest,
            "failed_trials": list(self.failed_trials),
            "invalid_trials": list(self.invalid_trials),
            "passed_trials": list(self.passed_trials),
            "score_basis_points": self.score_basis_points,
            "task_digest": self.task_digest,
            "task_id": self.task_id,
            "valid_trials": list(self.valid_trials),
        }


@dataclass(frozen=True, slots=True)
class CapabilityValidationReport:
    schema_version: int
    claim_id: str
    claim_type: str
    eligible: bool
    reasons: tuple[str, ...]
    transfer_gain_basis_points: int
    affected_contract_cases_improved: bool
    guards_non_inferior: bool
    baseline_outcomes: tuple[TaskOutcome, ...] = ()
    candidate_outcomes: tuple[TaskOutcome, ...] = ()
    transfer_checks: tuple[TransferCheck, ...] = ()

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CapabilityValidationError("capability_report_schema_invalid")
        _identifier(self.claim_id)
        if self.claim_type not in _CLAIM_TYPES:
            raise CapabilityValidationError("capability_claim_type_invalid")
        for value in (
            self.eligible,
            self.affected_contract_cases_improved,
            self.guards_non_inferior,
        ):
            if not isinstance(value, bool):
                raise CapabilityValidationError("capability_report_boolean_invalid")
        reasons = _sorted_identifiers(self.reasons)
        if self.eligible != (not reasons):
            raise CapabilityValidationError("capability_report_eligibility_invalid")
        if (
            isinstance(self.transfer_gain_basis_points, bool)
            or not isinstance(self.transfer_gain_basis_points, int)
            or not -10_000 <= self.transfer_gain_basis_points <= 10_000
        ):
            raise CapabilityValidationError("capability_transfer_gain_invalid")
        _outcomes_by_id(self.baseline_outcomes)
        _outcomes_by_id(self.candidate_outcomes)
        if not isinstance(self.transfer_checks, tuple) or any(
            not isinstance(item, TransferCheck) for item in self.transfer_checks
        ):
            raise CapabilityValidationError("capability_transfer_checks_invalid")
        check_ids = tuple(item.check_id for item in self.transfer_checks)
        if len(set(check_ids)) != len(check_ids) or check_ids != tuple(sorted(check_ids)):
            raise CapabilityValidationError("capability_tuple_order_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "affected_contract_cases_improved": self.affected_contract_cases_improved,
            "baseline_outcomes": [item.to_canonical_dict() for item in self.baseline_outcomes],
            "candidate_outcomes": [item.to_canonical_dict() for item in self.candidate_outcomes],
            "claim_id": self.claim_id,
            "claim_type": self.claim_type,
            "eligible": self.eligible,
            "guards_non_inferior": self.guards_non_inferior,
            "reasons": list(self.reasons),
            "schema_version": self.schema_version,
            "transfer_checks": [item.to_canonical_dict() for item in self.transfer_checks],
            "transfer_gain_basis_points": self.transfer_gain_basis_points,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


def _outcomes_by_id(values: tuple[TaskOutcome, ...]) -> dict[str, TaskOutcome]:
    if not isinstance(values, tuple) or any(not isinstance(item, TaskOutcome) for item in values):
        raise CapabilityValidationError("capability_outcomes_invalid")
    task_ids = tuple(item.task_id for item in values)
    if len(set(task_ids)) != len(task_ids) or task_ids != tuple(sorted(task_ids)):
        raise CapabilityValidationError("capability_tuple_order_invalid")
    return {item.task_id: item for item in values}


def _active_evaluator_path(path: Any) -> bool:
    if not isinstance(path, str) or not path or "\\" in path:
        raise CapabilityValidationError("capability_changed_path_invalid")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in path.split("/")):
        raise CapabilityValidationError("capability_changed_path_invalid")
    return path in _PROTECTED_EXACT_PATHS or path.startswith(_PROTECTED_PATH_PREFIXES)


def evaluate_capability_validation(
    claim: CapabilityClaim,
    baseline: tuple[TaskOutcome, ...],
    candidate: tuple[TaskOutcome, ...],
    changed_paths: tuple[str, ...],
) -> CapabilityValidationReport:
    """Evaluate task-level preservation, behavioral transfer, and anti-gaming evidence."""
    if not isinstance(claim, CapabilityClaim):
        raise CapabilityValidationError("capability_claim_invalid")
    baseline_by_id = _outcomes_by_id(baseline)
    candidate_by_id = _outcomes_by_id(candidate)
    if not isinstance(changed_paths, tuple):
        raise CapabilityValidationError("capability_changed_paths_invalid")

    reasons: set[str] = set()
    if any(_active_evaluator_path(path) for path in changed_paths):
        reasons.add("active_evaluator_modified")

    behavioral_checks = tuple(
        item for item in claim.transfer_checks if item.check_type in _BEHAVIORAL_TRANSFER_TYPES
    )
    if not behavioral_checks:
        reasons.add("held_out_transfer_required")

    required_ids = set(claim.affected_task_ids) | set(claim.guard_task_ids) | {
        item.task_id for item in claim.transfer_checks
    }
    if set(baseline_by_id) != set(candidate_by_id) or not required_ids <= set(baseline_by_id):
        reasons.add("evaluation_identity_changed")

    shared_ids = set(baseline_by_id) & set(candidate_by_id)
    for task_id in shared_ids:
        before = baseline_by_id[task_id]
        after = candidate_by_id[task_id]
        if (
            before.task_digest != after.task_digest
            or before.evaluator_digest != after.evaluator_digest
        ):
            reasons.add("evaluation_identity_changed")
        before_trials = set(before.valid_trials) | set(before.invalid_trials)
        after_trials = set(after.valid_trials) | set(after.invalid_trials)
        if before_trials != after_trials:
            reasons.add("incomplete_trial_accounting")
        if not set(before.failed_trials) <= set(after.valid_trials):
            reasons.add("selective_retry_detected")

    affected_pairs = tuple(
        (baseline_by_id[task_id], candidate_by_id[task_id])
        for task_id in claim.affected_task_ids
        if task_id in shared_ids
    )
    if len(affected_pairs) != len(claim.affected_task_ids):
        affected_improved = False
    else:
        affected_improved = all(
            after.score_basis_points > before.score_basis_points
            for before, after in affected_pairs
        )
        if any(
            after.score_basis_points < before.score_basis_points
            for before, after in affected_pairs
        ):
            reasons.add("aggregate_hides_task_regression")

    guard_pairs = tuple(
        (baseline_by_id[task_id], candidate_by_id[task_id])
        for task_id in claim.guard_task_ids
        if task_id in shared_ids
    )
    guards_non_inferior = len(guard_pairs) == len(claim.guard_task_ids) and all(
        after.score_basis_points >= before.score_basis_points for before, after in guard_pairs
    )
    if not guards_non_inferior:
        reasons.add("guard_task_regression")

    transfer_deltas: list[int] = []
    for check in claim.transfer_checks:
        if check.task_id not in shared_ids:
            continue
        before = baseline_by_id[check.task_id]
        after = candidate_by_id[check.task_id]
        if (
            before.evaluator_digest != check.evaluator_digest
            or after.evaluator_digest != check.evaluator_digest
        ):
            reasons.add("evaluation_identity_changed")
        if check.check_type in _BEHAVIORAL_TRANSFER_TYPES:
            transfer_deltas.append(after.score_basis_points - before.score_basis_points)
            if after.score_basis_points < before.score_basis_points:
                reasons.add("aggregate_hides_task_regression")
        if (
            check.check_type == "fixture_probe"
            and after.score_basis_points < check.minimum_candidate_basis_points
        ):
            reasons.add("hard_coded_fixture_detected")

    transfer_gain = sum(transfer_deltas) // len(transfer_deltas) if transfer_deltas else 0
    contract_exception = (
        claim.claim_type in {"compatibility", "correctness"}
        and affected_improved
        and guards_non_inferior
    )
    if transfer_gain <= 0 and not contract_exception:
        reasons.add("transfer_gain_required")

    stable_reasons = tuple(sorted(reasons))
    return CapabilityValidationReport(
        schema_version=1,
        claim_id=claim.claim_id,
        claim_type=claim.claim_type,
        eligible=not stable_reasons,
        reasons=stable_reasons,
        transfer_gain_basis_points=transfer_gain,
        affected_contract_cases_improved=affected_improved,
        guards_non_inferior=guards_non_inferior,
        baseline_outcomes=baseline,
        candidate_outcomes=candidate,
        transfer_checks=claim.transfer_checks,
    )
