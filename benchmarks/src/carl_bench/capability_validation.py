"""Deterministic capability-validity and benchmark-gaming gates."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from carl_bench.canonical import canonical_json_bytes

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_CLAIM_TYPES = frozenset({"capability", "compatibility", "correctness"})
_TRANSFER_TYPES = frozenset({"adversarial", "fixture_probe", "held_out", "unit_contract"})
_BEHAVIORAL_TRANSFER_TYPES = frozenset({"adversarial", "held_out"})
_EXPERIMENTAL_RECEIPT_TYPE = "experimental_publication_eligibility"
_EXPERIMENTAL_REVIEW_ROLES = (
    "benchmark_integrity",
    "correctness",
    "maintainability",
    "security",
)
_EXPERIMENTAL_LOCAL_GATES = (
    "deterministic_checks",
    "independent_reviews",
    "repository_tests",
    "security_review",
)
_EXPERIMENTAL_RESULTS = frozenset({"pass", "fail"})
_EXPERIMENTAL_VERDICTS = frozenset({"approve", "reject", "hard_finding"})
_UTC_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,6})?Z$"
)
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


class ExperimentalEligibilityError(ValueError):
    """A stable experimental-receipt failure that does not echo evidence."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _experimental_identifier(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 256
        or not _IDENTIFIER_RE.fullmatch(value)
    ):
        raise ExperimentalEligibilityError("experimental_eligibility_identifier_invalid")
    return value


def _experimental_digest(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ExperimentalEligibilityError("experimental_eligibility_digest_invalid")
    return value


def _experimental_object(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
        raise ExperimentalEligibilityError("experimental_eligibility_object_invalid")
    return value


def _experimental_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not _UTC_RE.fullmatch(value):
        raise ExperimentalEligibilityError("experimental_eligibility_timestamp_invalid")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ExperimentalEligibilityError("experimental_eligibility_timestamp_invalid") from error
    if parsed.tzinfo != UTC:
        raise ExperimentalEligibilityError("experimental_eligibility_timestamp_invalid")
    return parsed


def _experimental_exact(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ExperimentalEligibilityError(code)
    return value


@dataclass(frozen=True, slots=True)
class ExperimentalCheckResult:
    check_id: str
    status: str
    exit_code: int | None
    output_digest: str

    def __post_init__(self) -> None:
        _experimental_identifier(self.check_id)
        if self.status not in {"passed", "failed", "timed_out"}:
            raise ExperimentalEligibilityError("experimental_eligibility_check_invalid")
        if self.status == "timed_out":
            if self.exit_code is not None:
                raise ExperimentalEligibilityError("experimental_eligibility_check_invalid")
        elif (
            isinstance(self.exit_code, bool)
            or not isinstance(self.exit_code, int)
            or not 0 <= self.exit_code <= 255
            or (self.status == "passed" and self.exit_code != 0)
            or (self.status == "failed" and self.exit_code == 0)
        ):
            raise ExperimentalEligibilityError("experimental_eligibility_check_invalid")
        _experimental_digest(self.output_digest)

    @property
    def passed(self) -> bool:
        return self.status == "passed" and self.exit_code == 0

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "exit_code": self.exit_code,
            "output_digest": self.output_digest,
            "status": self.status,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> ExperimentalCheckResult:
        parsed = _experimental_exact(
            value,
            {"check_id", "exit_code", "output_digest", "status"},
            "experimental_eligibility_check_keys_invalid",
        )
        try:
            return cls(**parsed)
        except TypeError as error:
            raise ExperimentalEligibilityError("experimental_eligibility_check_invalid") from error


@dataclass(frozen=True, slots=True)
class ExperimentalReviewDisposition:
    role: str
    reviewer_id: str
    context_id: str
    experiment_id: str
    candidate_packet_digest: str
    candidate_commit: str
    candidate_tree: str
    packet_digest: str
    report_digest: str
    verdict: str

    def __post_init__(self) -> None:
        if self.role not in _EXPERIMENTAL_REVIEW_ROLES:
            raise ExperimentalEligibilityError("experimental_eligibility_review_invalid")
        _experimental_identifier(self.reviewer_id)
        _experimental_identifier(self.context_id)
        _experimental_identifier(self.experiment_id)
        _experimental_digest(self.candidate_packet_digest)
        _experimental_object(self.candidate_commit)
        _experimental_object(self.candidate_tree)
        _experimental_digest(self.packet_digest)
        _experimental_digest(self.report_digest)
        if self.verdict not in _EXPERIMENTAL_VERDICTS:
            raise ExperimentalEligibilityError("experimental_eligibility_review_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "candidate_commit": self.candidate_commit,
            "candidate_packet_digest": self.candidate_packet_digest,
            "candidate_tree": self.candidate_tree,
            "context_id": self.context_id,
            "experiment_id": self.experiment_id,
            "packet_digest": self.packet_digest,
            "report_digest": self.report_digest,
            "reviewer_id": self.reviewer_id,
            "role": self.role,
            "verdict": self.verdict,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> ExperimentalReviewDisposition:
        parsed = _experimental_exact(
            value,
            {
                "candidate_commit",
                "candidate_packet_digest",
                "candidate_tree",
                "context_id",
                "experiment_id",
                "packet_digest",
                "report_digest",
                "reviewer_id",
                "role",
                "verdict",
            },
            "experimental_eligibility_review_keys_invalid",
        )
        try:
            return cls(**parsed)
        except TypeError as error:
            raise ExperimentalEligibilityError("experimental_eligibility_review_invalid") from error


@dataclass(frozen=True, slots=True)
class ExperimentalLocalGateResult:
    gate_id: str
    result: str
    candidate_packet_digest: str
    candidate_commit: str
    candidate_tree: str
    evidence_digest: str

    def __post_init__(self) -> None:
        _experimental_identifier(self.gate_id)
        if self.result not in _EXPERIMENTAL_RESULTS:
            raise ExperimentalEligibilityError("experimental_eligibility_gate_invalid")
        _experimental_digest(self.candidate_packet_digest)
        _experimental_object(self.candidate_commit)
        _experimental_object(self.candidate_tree)
        _experimental_digest(self.evidence_digest)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "candidate_commit": self.candidate_commit,
            "candidate_packet_digest": self.candidate_packet_digest,
            "candidate_tree": self.candidate_tree,
            "evidence_digest": self.evidence_digest,
            "gate_id": self.gate_id,
            "result": self.result,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> ExperimentalLocalGateResult:
        parsed = _experimental_exact(
            value,
            {
                "candidate_commit",
                "candidate_packet_digest",
                "candidate_tree",
                "evidence_digest",
                "gate_id",
                "result",
            },
            "experimental_eligibility_gate_keys_invalid",
        )
        try:
            return cls(**parsed)
        except TypeError as error:
            raise ExperimentalEligibilityError("experimental_eligibility_gate_invalid") from error


def experimental_publication_request_digest(
    *,
    request_id: Any,
    requested_at: Any,
    experiment_id: Any,
    branch: Any,
    candidate_packet_digest: Any,
    candidate_commit: Any,
    candidate_tree: Any,
) -> str:
    """Bind one eligibility receipt to one exact publication request."""
    payload = {
        "branch": _experimental_identifier(branch),
        "candidate_commit": _experimental_object(candidate_commit),
        "candidate_packet_digest": _experimental_digest(candidate_packet_digest),
        "candidate_tree": _experimental_object(candidate_tree),
        "experiment_id": _experimental_identifier(experiment_id),
        "request_id": _experimental_identifier(request_id),
        "requested_at": requested_at,
        "schema_version": 1,
    }
    _experimental_timestamp(requested_at)
    if payload["branch"] != f"experimental/{payload['experiment_id']}":
        raise ExperimentalEligibilityError("experimental_eligibility_branch_invalid")
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def experimental_evidence_digest(
    *,
    required_checks: Any,
    builder_id: Any,
    review_dispositions: Any,
    security_result: Any,
    local_gates: Any,
) -> str:
    """Commit to the exact deterministic, review, security, and local gate evidence."""
    if not isinstance(required_checks, tuple) or any(
        not isinstance(item, ExperimentalCheckResult) for item in required_checks
    ):
        raise ExperimentalEligibilityError("experimental_eligibility_checks_invalid")
    if not isinstance(review_dispositions, tuple) or any(
        not isinstance(item, ExperimentalReviewDisposition) for item in review_dispositions
    ):
        raise ExperimentalEligibilityError("experimental_eligibility_reviews_invalid")
    if not isinstance(local_gates, tuple) or any(
        not isinstance(item, ExperimentalLocalGateResult) for item in local_gates
    ):
        raise ExperimentalEligibilityError("experimental_eligibility_gates_invalid")
    _experimental_identifier(builder_id)
    if security_result not in _EXPERIMENTAL_RESULTS:
        raise ExperimentalEligibilityError("experimental_eligibility_security_invalid")
    payload = {
        "builder_id": builder_id,
        "local_gates": [item.to_canonical_dict() for item in local_gates],
        "required_checks": [item.to_canonical_dict() for item in required_checks],
        "review_dispositions": [item.to_canonical_dict() for item in review_dispositions],
        "security_result": security_result,
        "schema_version": 1,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


@dataclass(frozen=True, slots=True)
class ExperimentalPublicationEligibility:
    schema_version: int
    receipt_type: str
    request_id: str
    requested_at: str
    request_digest: str
    experiment_id: str
    branch: str
    candidate_packet_digest: str
    candidate_commit: str
    candidate_tree: str
    required_checks: tuple[ExperimentalCheckResult, ...]
    builder_id: str
    review_dispositions: tuple[ExperimentalReviewDisposition, ...]
    security_result: str
    local_gates: tuple[ExperimentalLocalGateResult, ...]
    evidence_digest: str
    issued_at: str
    expires_at: str

    def __post_init__(self) -> None:
        if self.schema_version != 1 or self.receipt_type != _EXPERIMENTAL_RECEIPT_TYPE:
            raise ExperimentalEligibilityError("experimental_eligibility_schema_invalid")
        expected_request = experimental_publication_request_digest(
            request_id=self.request_id,
            requested_at=self.requested_at,
            experiment_id=self.experiment_id,
            branch=self.branch,
            candidate_packet_digest=self.candidate_packet_digest,
            candidate_commit=self.candidate_commit,
            candidate_tree=self.candidate_tree,
        )
        if self.request_digest != expected_request:
            raise ExperimentalEligibilityError("experimental_eligibility_request_digest_invalid")
        check_ids = tuple(item.check_id for item in self.required_checks)
        if check_ids != tuple(sorted(set(check_ids), key=str.encode)):
            raise ExperimentalEligibilityError("experimental_eligibility_checks_invalid")
        review_roles = tuple(item.role for item in self.review_dispositions)
        if review_roles != tuple(sorted(set(review_roles), key=str.encode)):
            raise ExperimentalEligibilityError("experimental_eligibility_reviews_invalid")
        gate_ids = tuple(item.gate_id for item in self.local_gates)
        if gate_ids != tuple(sorted(set(gate_ids), key=str.encode)):
            raise ExperimentalEligibilityError("experimental_eligibility_gates_invalid")
        expected_evidence = experimental_evidence_digest(
            required_checks=self.required_checks,
            builder_id=self.builder_id,
            review_dispositions=self.review_dispositions,
            security_result=self.security_result,
            local_gates=self.local_gates,
        )
        if self.evidence_digest != expected_evidence:
            raise ExperimentalEligibilityError("experimental_eligibility_evidence_digest_invalid")
        issued = _experimental_timestamp(self.issued_at)
        expires = _experimental_timestamp(self.expires_at)
        if expires <= issued:
            raise ExperimentalEligibilityError("experimental_eligibility_window_invalid")

    @property
    def eligible(self) -> bool:
        reviews = self.review_dispositions
        reviewers = tuple(item.reviewer_id for item in reviews)
        contexts = tuple(item.context_id for item in reviews)
        security_reviews = tuple(item for item in reviews if item.role == "security")
        exact_review_identities = all(
            item.experiment_id == self.experiment_id
            and item.candidate_packet_digest == self.candidate_packet_digest
            and item.candidate_commit == self.candidate_commit
            and item.candidate_tree == self.candidate_tree
            for item in reviews
        )
        exact_gate_identities = all(
            item.candidate_packet_digest == self.candidate_packet_digest
            and item.candidate_commit == self.candidate_commit
            and item.candidate_tree == self.candidate_tree
            for item in self.local_gates
        )
        return (
            bool(self.required_checks)
            and all(item.passed for item in self.required_checks)
            and tuple(item.role for item in reviews) == _EXPERIMENTAL_REVIEW_ROLES
            and exact_review_identities
            and len(set(reviewers)) == len(reviewers)
            and len(set(contexts)) == len(contexts)
            and self.builder_id not in reviewers
            and sum(item.verdict == "approve" for item in reviews) >= 3
            and not any(item.verdict == "hard_finding" for item in reviews)
            and len(security_reviews) == 1
            and security_reviews[0].verdict == "approve"
            and self.security_result == "pass"
            and tuple(item.gate_id for item in self.local_gates) == _EXPERIMENTAL_LOCAL_GATES
            and exact_gate_identities
            and all(item.result == "pass" for item in self.local_gates)
        )

    def valid_at(self, value: str) -> bool:
        observed = _experimental_timestamp(value)
        return (
            _experimental_timestamp(self.issued_at)
            <= observed
            < _experimental_timestamp(self.expires_at)
        )

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "branch": self.branch,
            "builder_id": self.builder_id,
            "candidate_commit": self.candidate_commit,
            "candidate_packet_digest": self.candidate_packet_digest,
            "candidate_tree": self.candidate_tree,
            "evidence_digest": self.evidence_digest,
            "experiment_id": self.experiment_id,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "local_gates": [item.to_canonical_dict() for item in self.local_gates],
            "receipt_type": self.receipt_type,
            "request_digest": self.request_digest,
            "request_id": self.request_id,
            "requested_at": self.requested_at,
            "required_checks": [item.to_canonical_dict() for item in self.required_checks],
            "review_dispositions": [item.to_canonical_dict() for item in self.review_dispositions],
            "schema_version": self.schema_version,
            "security_result": self.security_result,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()

    @classmethod
    def from_canonical_dict(cls, value: Any) -> ExperimentalPublicationEligibility:
        expected = {
            "branch",
            "builder_id",
            "candidate_commit",
            "candidate_packet_digest",
            "candidate_tree",
            "evidence_digest",
            "experiment_id",
            "expires_at",
            "issued_at",
            "local_gates",
            "receipt_type",
            "request_digest",
            "request_id",
            "requested_at",
            "required_checks",
            "review_dispositions",
            "schema_version",
            "security_result",
        }
        parsed = _experimental_exact(value, expected, "experimental_eligibility_keys_invalid")
        if any(
            not isinstance(parsed[name], list)
            for name in ("local_gates", "required_checks", "review_dispositions")
        ):
            raise ExperimentalEligibilityError("experimental_eligibility_collections_invalid")
        normalized = dict(parsed)
        normalized["required_checks"] = tuple(
            ExperimentalCheckResult.from_canonical_dict(item) for item in parsed["required_checks"]
        )
        normalized["review_dispositions"] = tuple(
            ExperimentalReviewDisposition.from_canonical_dict(item)
            for item in parsed["review_dispositions"]
        )
        normalized["local_gates"] = tuple(
            ExperimentalLocalGateResult.from_canonical_dict(item) for item in parsed["local_gates"]
        )
        try:
            receipt = cls(**normalized)
        except TypeError as error:
            raise ExperimentalEligibilityError("experimental_eligibility_invalid") from error
        if canonical_json_bytes(receipt.to_canonical_dict()) != canonical_json_bytes(value):
            raise ExperimentalEligibilityError("experimental_eligibility_noncanonical")
        return receipt


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

    if not any(item.check_type == "held_out" for item in claim.transfer_checks):
        reasons.add("held_out_transfer_required")

    required_ids = (
        set(claim.affected_task_ids)
        | set(claim.guard_task_ids)
        | {item.task_id for item in claim.transfer_checks}
    )
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
        if after.score_basis_points < before.score_basis_points:
            reasons.add("aggregate_hides_task_regression")

    affected_pairs = tuple(
        (baseline_by_id[task_id], candidate_by_id[task_id])
        for task_id in claim.affected_task_ids
        if task_id in shared_ids
    )
    if len(affected_pairs) != len(claim.affected_task_ids):
        affected_improved = False
    else:
        affected_improved = all(
            after.score_basis_points > before.score_basis_points for before, after in affected_pairs
        )

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
        if after.score_basis_points < check.minimum_candidate_basis_points:
            if check.check_type == "fixture_probe":
                reasons.add("hard_coded_fixture_detected")
            else:
                reasons.add("transfer_check_threshold_not_met")

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
