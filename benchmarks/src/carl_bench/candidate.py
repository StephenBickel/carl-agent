"""Immutable contracts for isolated candidate evidence."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, ClassVar

from carl_bench.artifacts import ArtifactIntegrityError, ArtifactRef
from carl_bench.canonical import canonical_json_bytes

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_BRANCH_RE = re.compile(r"^codex/experiment-[a-z0-9][a-z0-9-]*-[0-9a-f]{10}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_ROLES = frozenset({"correctness", "security", "maintainability", "benchmark_integrity"})


class CandidateContractError(ValueError):
    """A stable candidate failure that does not echo private evidence."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _identifier(name: str, value: str, maximum: int = 128) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or not _ID_RE.fullmatch(value)
    ):
        raise CandidateContractError(f"invalid_{name}")


def _digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise CandidateContractError(f"invalid_{name}")


def _commit(name: str, value: str) -> None:
    if not isinstance(value, str) or not _COMMIT_RE.fullmatch(value):
        raise CandidateContractError(f"invalid_{name}")


def _artifact(value: Any, name: str) -> ArtifactRef:
    try:
        return ArtifactRef.from_canonical_dict(value)
    except ArtifactIntegrityError as error:
        raise CandidateContractError(f"invalid_{name}_artifact") from error


def _exact(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise CandidateContractError(code)
    return value


class _Digestible:
    def to_canonical_dict(self) -> dict[str, Any]:
        raise NotImplementedError

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class PreparedCandidate(_Digestible):
    schema_version: int
    experiment_id: str
    manifest_digest: str
    parent_commit: str
    branch: str
    request_artifact: ArtifactRef

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CandidateContractError("invalid_prepared_candidate_schema")
        _identifier("experiment_id", self.experiment_id)
        _digest("manifest_digest", self.manifest_digest)
        _commit("parent_commit", self.parent_commit)
        if not isinstance(self.branch, str) or not _BRANCH_RE.fullmatch(self.branch):
            raise CandidateContractError("invalid_candidate_branch")
        if not isinstance(self.request_artifact, ArtifactRef):
            raise CandidateContractError("invalid_request_artifact")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "branch": self.branch,
            "experiment_id": self.experiment_id,
            "manifest_digest": self.manifest_digest,
            "parent_commit": self.parent_commit,
            "request_artifact": self.request_artifact.to_canonical_dict(),
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> PreparedCandidate:
        parsed = _exact(
            value,
            {
                "branch",
                "experiment_id",
                "manifest_digest",
                "parent_commit",
                "request_artifact",
                "schema_version",
            },
            "invalid_prepared_candidate_keys",
        )
        normalized = dict(parsed)
        normalized["request_artifact"] = _artifact(parsed["request_artifact"], "request")
        try:
            return cls(**normalized)
        except TypeError as error:
            raise CandidateContractError("invalid_prepared_candidate") from error


@dataclass(frozen=True, slots=True)
class DeterministicCheckResult:
    check_id: str
    status: str
    exit_code: int | None
    elapsed_ms: int
    output_artifact: ArtifactRef

    def __post_init__(self) -> None:
        _identifier("check_id", self.check_id)
        if self.status not in {"passed", "failed", "timed_out"}:
            raise CandidateContractError("invalid_check_status")
        if self.status == "timed_out":
            if self.exit_code is not None:
                raise CandidateContractError("invalid_check_exit_code")
        elif (
            isinstance(self.exit_code, bool)
            or not isinstance(self.exit_code, int)
            or not 0 <= self.exit_code <= 255
            or (self.status == "passed" and self.exit_code != 0)
            or (self.status == "failed" and self.exit_code == 0)
        ):
            raise CandidateContractError("invalid_check_exit_code")
        if (
            isinstance(self.elapsed_ms, bool)
            or not isinstance(self.elapsed_ms, int)
            or not 0 <= self.elapsed_ms <= 86_400_000
        ):
            raise CandidateContractError("invalid_check_elapsed")
        if not isinstance(self.output_artifact, ArtifactRef):
            raise CandidateContractError("invalid_check_output_artifact")

    @property
    def passed(self) -> bool:
        return self.status == "passed" and self.exit_code == 0

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "elapsed_ms": self.elapsed_ms,
            "exit_code": self.exit_code,
            "output_artifact": self.output_artifact.to_canonical_dict(),
            "status": self.status,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> DeterministicCheckResult:
        parsed = _exact(
            value,
            {"check_id", "elapsed_ms", "exit_code", "output_artifact", "status"},
            "invalid_check_result_keys",
        )
        normalized = dict(parsed)
        normalized["output_artifact"] = _artifact(parsed["output_artifact"], "check_output")
        try:
            return cls(**normalized)
        except TypeError as error:
            raise CandidateContractError("invalid_check_result") from error


@dataclass(frozen=True, slots=True)
class SealedCandidate(_Digestible):
    schema_version: int
    experiment_id: str
    manifest_digest: str
    parent_commit: str
    candidate_commit: str
    branch: str
    diff_artifact: ArtifactRef
    report_artifact: ArtifactRef
    changed_paths_artifact: ArtifactRef
    changed_path_count: int
    checks: tuple[DeterministicCheckResult, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CandidateContractError("invalid_sealed_candidate_schema")
        _identifier("experiment_id", self.experiment_id)
        _digest("manifest_digest", self.manifest_digest)
        _commit("parent_commit", self.parent_commit)
        _commit("candidate_commit", self.candidate_commit)
        if self.parent_commit == self.candidate_commit:
            raise CandidateContractError("candidate_equals_parent")
        if not isinstance(self.branch, str) or not _BRANCH_RE.fullmatch(self.branch):
            raise CandidateContractError("invalid_candidate_branch")
        for name in ("diff_artifact", "report_artifact", "changed_paths_artifact"):
            if not isinstance(getattr(self, name), ArtifactRef):
                raise CandidateContractError(f"invalid_{name}")
        if (
            isinstance(self.changed_path_count, bool)
            or not isinstance(self.changed_path_count, int)
            or not 1 <= self.changed_path_count <= 4_096
        ):
            raise CandidateContractError("invalid_changed_path_count")
        if not isinstance(self.checks, tuple) or not self.checks:
            raise CandidateContractError("invalid_candidate_checks")
        check_ids = tuple(check.check_id for check in self.checks)
        if check_ids != tuple(sorted(set(check_ids), key=str.encode)):
            raise CandidateContractError("candidate_checks_not_sorted_unique")
        if not all(check.passed for check in self.checks):
            raise CandidateContractError("candidate_checks_failed")

    @property
    def all_checks_passed(self) -> bool:
        return all(check.passed for check in self.checks)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "branch": self.branch,
            "candidate_commit": self.candidate_commit,
            "changed_path_count": self.changed_path_count,
            "changed_paths_artifact": self.changed_paths_artifact.to_canonical_dict(),
            "checks": [check.to_canonical_dict() for check in self.checks],
            "diff_artifact": self.diff_artifact.to_canonical_dict(),
            "experiment_id": self.experiment_id,
            "manifest_digest": self.manifest_digest,
            "parent_commit": self.parent_commit,
            "report_artifact": self.report_artifact.to_canonical_dict(),
            "schema_version": self.schema_version,
        }

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "all_checks_passed": self.all_checks_passed,
            "branch": self.branch,
            "candidate_commit": self.candidate_commit,
            "candidate_digest": self.digest,
            "changed_path_count": self.changed_path_count,
            "changed_paths_digest": self.changed_paths_artifact.digest,
            "check_count": len(self.checks),
            "diff_digest": self.diff_artifact.digest,
            "experiment_id": self.experiment_id,
            "manifest_digest": self.manifest_digest,
            "parent_commit": self.parent_commit,
            "report_digest": self.report_artifact.digest,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> SealedCandidate:
        parsed = _exact(
            value,
            {
                "branch",
                "candidate_commit",
                "changed_path_count",
                "changed_paths_artifact",
                "checks",
                "diff_artifact",
                "experiment_id",
                "manifest_digest",
                "parent_commit",
                "report_artifact",
                "schema_version",
            },
            "invalid_sealed_candidate_keys",
        )
        if not isinstance(parsed["checks"], list):
            raise CandidateContractError("invalid_candidate_checks")
        normalized = dict(parsed)
        normalized["diff_artifact"] = _artifact(parsed["diff_artifact"], "diff")
        normalized["report_artifact"] = _artifact(parsed["report_artifact"], "report")
        normalized["changed_paths_artifact"] = _artifact(
            parsed["changed_paths_artifact"], "changed_paths"
        )
        normalized["checks"] = tuple(
            DeterministicCheckResult.from_canonical_dict(item) for item in parsed["checks"]
        )
        try:
            return cls(**normalized)
        except TypeError as error:
            raise CandidateContractError("invalid_sealed_candidate") from error


@dataclass(frozen=True, slots=True)
class PairedEvidence(_Digestible):
    schema_version: int
    experiment_id: str
    manifest_digest: str
    parent_commit: str
    candidate_commit: str
    baseline_scorecard_digest: str
    candidate_scorecard_digest: str
    comparison_artifact: ArtifactRef
    decision: str
    paired_trials: int
    pass_rate_delta_basis_points: int
    confidence_lower_basis_points: int

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CandidateContractError("invalid_paired_evidence_schema")
        _identifier("experiment_id", self.experiment_id)
        _digest("manifest_digest", self.manifest_digest)
        _commit("parent_commit", self.parent_commit)
        _commit("candidate_commit", self.candidate_commit)
        _digest("baseline_scorecard_digest", self.baseline_scorecard_digest)
        _digest("candidate_scorecard_digest", self.candidate_scorecard_digest)
        if not isinstance(self.comparison_artifact, ArtifactRef):
            raise CandidateContractError("invalid_comparison_artifact")
        if self.decision not in {"improvement", "rejected", "insufficient_evidence"}:
            raise CandidateContractError("invalid_paired_decision")
        if (
            isinstance(self.paired_trials, bool)
            or not isinstance(self.paired_trials, int)
            or not 0 <= self.paired_trials <= 1_000_000
        ):
            raise CandidateContractError("invalid_paired_trials")
        for name in ("pass_rate_delta_basis_points", "confidence_lower_basis_points"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not -10_000 <= value <= 10_000
            ):
                raise CandidateContractError(f"invalid_{name}")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "baseline_scorecard_digest": self.baseline_scorecard_digest,
            "candidate_commit": self.candidate_commit,
            "candidate_scorecard_digest": self.candidate_scorecard_digest,
            "comparison_artifact": self.comparison_artifact.to_canonical_dict(),
            "confidence_lower_basis_points": self.confidence_lower_basis_points,
            "decision": self.decision,
            "experiment_id": self.experiment_id,
            "manifest_digest": self.manifest_digest,
            "paired_trials": self.paired_trials,
            "parent_commit": self.parent_commit,
            "pass_rate_delta_basis_points": self.pass_rate_delta_basis_points,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> PairedEvidence:
        parsed = _exact(
            value,
            {
                "baseline_scorecard_digest",
                "candidate_commit",
                "candidate_scorecard_digest",
                "comparison_artifact",
                "confidence_lower_basis_points",
                "decision",
                "experiment_id",
                "manifest_digest",
                "paired_trials",
                "parent_commit",
                "pass_rate_delta_basis_points",
                "schema_version",
            },
            "invalid_paired_evidence_keys",
        )
        normalized = dict(parsed)
        normalized["comparison_artifact"] = _artifact(parsed["comparison_artifact"], "comparison")
        try:
            return cls(**normalized)
        except TypeError as error:
            raise CandidateContractError("invalid_paired_evidence") from error


@dataclass(frozen=True, slots=True)
class ReviewPacket(_Digestible):
    schema_version: int
    experiment_id: str
    manifest_digest: str
    candidate_commit: str
    role: str
    diff_digest: str
    deterministic_evidence_digest: str
    paired_evidence_digest: str
    review_contract_version: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CandidateContractError("invalid_review_packet_schema")
        _identifier("experiment_id", self.experiment_id)
        _digest("manifest_digest", self.manifest_digest)
        _commit("candidate_commit", self.candidate_commit)
        if self.role not in _ROLES:
            raise CandidateContractError("invalid_review_role")
        _digest("diff_digest", self.diff_digest)
        _digest("deterministic_evidence_digest", self.deterministic_evidence_digest)
        _digest("paired_evidence_digest", self.paired_evidence_digest)
        if self.review_contract_version != "candidate-review-v1":
            raise CandidateContractError("invalid_review_contract_version")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "candidate_commit": self.candidate_commit,
            "deterministic_evidence_digest": self.deterministic_evidence_digest,
            "diff_digest": self.diff_digest,
            "experiment_id": self.experiment_id,
            "manifest_digest": self.manifest_digest,
            "paired_evidence_digest": self.paired_evidence_digest,
            "review_contract_version": self.review_contract_version,
            "role": self.role,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> ReviewPacket:
        parsed = _exact(
            value,
            {
                "candidate_commit",
                "deterministic_evidence_digest",
                "diff_digest",
                "experiment_id",
                "manifest_digest",
                "paired_evidence_digest",
                "review_contract_version",
                "role",
                "schema_version",
            },
            "invalid_review_packet_keys",
        )
        try:
            return cls(**parsed)
        except TypeError as error:
            raise CandidateContractError("invalid_review_packet") from error


@dataclass(frozen=True, slots=True)
class ReviewAttestation(_Digestible):
    schema_version: int
    experiment_id: str
    manifest_digest: str
    candidate_commit: str
    role: str
    reviewer_id: str
    context_id: str
    packet_digest: str
    verdict: str
    report_artifact: ArtifactRef

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CandidateContractError("invalid_review_attestation_schema")
        _identifier("experiment_id", self.experiment_id)
        _digest("manifest_digest", self.manifest_digest)
        _commit("candidate_commit", self.candidate_commit)
        if self.role not in _ROLES:
            raise CandidateContractError("invalid_review_role")
        _identifier("reviewer_id", self.reviewer_id)
        _identifier("context_id", self.context_id)
        if self.reviewer_id == self.context_id:
            raise CandidateContractError("review_identity_context_reused")
        _digest("packet_digest", self.packet_digest)
        if self.verdict not in {"approve", "reject", "hard_finding"}:
            raise CandidateContractError("invalid_review_verdict")
        if not isinstance(self.report_artifact, ArtifactRef):
            raise CandidateContractError("invalid_review_report_artifact")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "candidate_commit": self.candidate_commit,
            "context_id": self.context_id,
            "experiment_id": self.experiment_id,
            "manifest_digest": self.manifest_digest,
            "packet_digest": self.packet_digest,
            "report_artifact": self.report_artifact.to_canonical_dict(),
            "reviewer_id": self.reviewer_id,
            "role": self.role,
            "schema_version": self.schema_version,
            "verdict": self.verdict,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> ReviewAttestation:
        parsed = _exact(
            value,
            {
                "candidate_commit",
                "context_id",
                "experiment_id",
                "manifest_digest",
                "packet_digest",
                "report_artifact",
                "reviewer_id",
                "role",
                "schema_version",
                "verdict",
            },
            "invalid_review_attestation_keys",
        )
        normalized = dict(parsed)
        normalized["report_artifact"] = _artifact(parsed["report_artifact"], "review_report")
        try:
            return cls(**normalized)
        except TypeError as error:
            raise CandidateContractError("invalid_review_attestation") from error

    @classmethod
    def from_packet_dict(cls, value: Any, packet: ReviewPacket) -> ReviewAttestation:
        review = cls.from_canonical_dict(value)
        if review.candidate_commit != packet.candidate_commit:
            raise CandidateContractError("review_candidate_mismatch")
        if (
            review.experiment_id != packet.experiment_id
            or review.manifest_digest != packet.manifest_digest
            or review.role != packet.role
            or review.packet_digest != packet.digest
        ):
            raise CandidateContractError("review_packet_mismatch")
        return review


@dataclass(frozen=True, slots=True)
class DraftPullRequest(_Digestible):
    schema_version: int
    repository: str
    number: int
    url: str
    state: str
    is_draft: bool
    base_branch: str
    head_branch: str
    candidate_commit: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CandidateContractError("invalid_pull_request_schema")
        if not isinstance(self.repository, str) or not _REPOSITORY_RE.fullmatch(self.repository):
            raise CandidateContractError("invalid_pull_request_repository")
        if isinstance(self.number, bool) or not isinstance(self.number, int) or self.number <= 0:
            raise CandidateContractError("invalid_pull_request_number")
        expected_url = f"https://github.com/{self.repository}/pull/{self.number}"
        if self.url != expected_url:
            raise CandidateContractError("invalid_pull_request_url")
        if self.state != "OPEN":
            raise CandidateContractError("pull_request_not_open")
        if self.is_draft is not True:
            raise CandidateContractError("pull_request_not_draft")
        _identifier("base_branch", self.base_branch)
        if not isinstance(self.head_branch, str) or not _BRANCH_RE.fullmatch(self.head_branch):
            raise CandidateContractError("invalid_pull_request_head")
        _commit("candidate_commit", self.candidate_commit)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "base_branch": self.base_branch,
            "candidate_commit": self.candidate_commit,
            "head_branch": self.head_branch,
            "is_draft": self.is_draft,
            "number": self.number,
            "repository": self.repository,
            "schema_version": self.schema_version,
            "state": self.state,
            "url": self.url,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> DraftPullRequest:
        parsed = _exact(
            value,
            {
                "base_branch",
                "candidate_commit",
                "head_branch",
                "is_draft",
                "number",
                "repository",
                "schema_version",
                "state",
                "url",
            },
            "invalid_pull_request_keys",
        )
        try:
            return cls(**parsed)
        except TypeError as error:
            raise CandidateContractError("invalid_pull_request") from error

    @classmethod
    def from_candidate_dict(cls, value: Any, candidate: SealedCandidate) -> DraftPullRequest:
        draft = cls.from_canonical_dict(value)
        if draft.candidate_commit != candidate.candidate_commit:
            raise CandidateContractError("pull_request_candidate_mismatch")
        if draft.head_branch != candidate.branch:
            raise CandidateContractError("pull_request_head_mismatch")
        return draft


@dataclass(frozen=True, slots=True)
class Phase3Decision:
    schema_version: int
    experiment_id: str
    manifest_digest: str
    projection_digest: str
    outcome: str
    next_action: str
    reasons: tuple[str, ...]

    OUTCOMES: ClassVar[frozenset[str]] = frozenset({"advance", "blocked", "draft_open"})

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CandidateContractError("invalid_phase3_decision_schema")
        _identifier("experiment_id", self.experiment_id)
        _digest("manifest_digest", self.manifest_digest)
        _digest("projection_digest", self.projection_digest)
        if self.outcome not in self.OUTCOMES:
            raise CandidateContractError("invalid_phase3_outcome")
        _identifier("next_action", self.next_action)
        if self.reasons != tuple(sorted(set(self.reasons), key=str.encode)):
            raise CandidateContractError("invalid_phase3_reasons")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "manifest_digest": self.manifest_digest,
            "next_action": self.next_action,
            "outcome": self.outcome,
            "projection_digest": self.projection_digest,
            "reasons": list(self.reasons),
            "schema_version": self.schema_version,
        }
