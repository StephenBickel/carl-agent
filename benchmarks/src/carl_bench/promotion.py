"""Fail-closed contracts for externally protected production validation."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from carl_bench.canonical import canonical_json_bytes

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_CONSTITUTIONAL_EXACT = frozenset(
    {
        "AGENTS.md",
        "Cargo.lock",
        "Cargo.toml",
        "SECURITY.md",
        "docs/benchmarks.md",
    }
)
_CONSTITUTIONAL_PREFIXES = (
    ".codex/",
    ".github/",
    "benchmarks/",
    "docs/superpowers/plans/2026-08-18-carl-autonomous-main-promotion",
    "docs/superpowers/specs/2026-08-10-codex-carl-improvement-factory-design",
    "docs/superpowers/specs/2026-08-18-carl-autonomous-main-promotion",
    "scripts/benchmark",
    "scripts/live-codex",
)


class PromotionContractError(ValueError):
    """Stable promotion-contract error that does not echo untrusted input."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not value or len(value.encode()) > 256:
        raise PromotionContractError(f"invalid_{name}")
    if not _ID_RE.fullmatch(value):
        raise PromotionContractError(f"invalid_{name}")


def _digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise PromotionContractError(f"invalid_{name}")


def _object_id(name: str, value: str) -> None:
    if not isinstance(value, str) or not _OBJECT_RE.fullmatch(value):
        raise PromotionContractError(f"invalid_{name}")


def _parse_utc(name: str, value: str) -> datetime:
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
class ProtectedValidationReceipt:
    schema_version: int
    validation_id: str
    experiment_id: str
    manifest_digest: str
    policy_digest: str
    parent_commit: str
    candidate_commit: str
    candidate_tree: str
    executable_digest: str
    adapter_digest: str
    task_set_digest: str
    metric_pack_digest: str
    environment_digest: str
    model: str
    effort: str
    deterministic_checks_digest: str
    repository_tests_digest: str
    paired_score_delta_basis_points: int
    paired_confidence_lower_basis_points: int
    guard_delta_basis_points: int
    workflow_passed: bool
    safety_passed: bool
    flake_rate_basis_points: int
    invalid_run_count: int
    cost_microdollars: int
    latency_ms: int
    holdout_aggregate_basis_points: int
    holdout_leakage_detected: bool
    proposal_review_digest: str
    build_review_digest: str
    security_review_digest: str
    created_at: str
    expires_at: str
    decision: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise PromotionContractError("invalid_protected_receipt_schema")
        _identifier("validation_id", self.validation_id)
        _identifier("experiment_id", self.experiment_id)
        for name in (
            "manifest_digest",
            "policy_digest",
            "executable_digest",
            "adapter_digest",
            "task_set_digest",
            "metric_pack_digest",
            "environment_digest",
            "deterministic_checks_digest",
            "repository_tests_digest",
            "proposal_review_digest",
            "build_review_digest",
            "security_review_digest",
        ):
            _digest(name, getattr(self, name))
        for name in ("parent_commit", "candidate_commit", "candidate_tree"):
            _object_id(name, getattr(self, name))
        _identifier("model", self.model)
        _identifier("effort", self.effort)
        if self.decision not in {"pass", "fail"}:
            raise PromotionContractError("invalid_protected_decision")
        for name in ("workflow_passed", "safety_passed", "holdout_leakage_detected"):
            if not isinstance(getattr(self, name), bool):
                raise PromotionContractError(f"invalid_{name}")
        for name in (
            "paired_score_delta_basis_points",
            "paired_confidence_lower_basis_points",
            "guard_delta_basis_points",
            "holdout_aggregate_basis_points",
        ):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not -10_000 <= value <= 10_000
            ):
                raise PromotionContractError(f"invalid_{name}")
        for name in (
            "flake_rate_basis_points",
            "invalid_run_count",
            "cost_microdollars",
            "latency_ms",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise PromotionContractError(f"invalid_{name}")
        if self.flake_rate_basis_points > 10_000:
            raise PromotionContractError("invalid_flake_rate_basis_points")
        created = _parse_utc("created_at", self.created_at)
        expires = _parse_utc("expires_at", self.expires_at)
        if expires <= created:
            raise PromotionContractError("invalid_protected_receipt_window")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class SignedProtectedValidation:
    receipt: ProtectedValidationReceipt
    key_id: str
    signature_base64: str

    def __post_init__(self) -> None:
        if not isinstance(self.receipt, ProtectedValidationReceipt):
            raise PromotionContractError("invalid_protected_receipt")
        _identifier("protected_key_id", self.key_id)
        try:
            signature = base64.b64decode(self.signature_base64, validate=True)
        except (ValueError, binascii.Error) as error:
            raise PromotionContractError("invalid_protected_signature") from error
        if len(signature) != 64:
            raise PromotionContractError("invalid_protected_signature")

    @property
    def signature(self) -> bytes:
        return base64.b64decode(self.signature_base64, validate=True)


@dataclass(frozen=True, slots=True)
class PromotionExpectation:
    experiment_id: str
    manifest_digest: str
    policy_digest: str
    parent_commit: str
    candidate_commit: str
    candidate_tree: str
    executable_digest: str
    adapter_digest: str
    task_set_digest: str
    metric_pack_digest: str
    model: str
    effort: str
    environment_digest: str

    def __post_init__(self) -> None:
        _identifier("experiment_id", self.experiment_id)
        for name in (
            "manifest_digest",
            "policy_digest",
            "executable_digest",
            "adapter_digest",
            "task_set_digest",
            "metric_pack_digest",
            "environment_digest",
        ):
            _digest(name, getattr(self, name))
        for name in ("parent_commit", "candidate_commit", "candidate_tree"):
            _object_id(name, getattr(self, name))
        _identifier("model", self.model)
        _identifier("effort", self.effort)


@dataclass(frozen=True, slots=True)
class VerifiedProtectedValidation:
    validation_id: str
    receipt_digest: str
    candidate_commit: str
    candidate_tree: str
    expires_at: str


def _is_constitutional(path: str) -> bool:
    if not isinstance(path, str) or not path or "\\" in path:
        raise PromotionContractError("invalid_changed_path")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or any(part in {"", ".", ".."} for part in path.split("/")):
        raise PromotionContractError("invalid_changed_path")
    return path in _CONSTITUTIONAL_EXACT or path.startswith(_CONSTITUTIONAL_PREFIXES)


def verify_protected_validation(
    envelope: SignedProtectedValidation,
    *,
    public_key_pem: bytes,
    expected: PromotionExpectation,
    now: datetime,
    changed_paths: tuple[str, ...] = (),
) -> VerifiedProtectedValidation:
    """Verify external authority, immutable identities, and all hard protected gates."""
    if now.tzinfo != UTC:
        raise PromotionContractError("invalid_verification_time")
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as error:
        raise PromotionContractError("protected_public_key_invalid") from error
    if not isinstance(public_key, Ed25519PublicKey):
        raise PromotionContractError("protected_public_key_invalid")
    payload = canonical_json_bytes(envelope.receipt.to_canonical_dict())
    try:
        public_key.verify(envelope.signature, payload)
    except InvalidSignature as error:
        raise PromotionContractError("protected_signature_invalid") from error

    receipt = envelope.receipt
    identity_errors = (
        ("experiment_id", "protected_experiment_mismatch"),
        ("manifest_digest", "protected_manifest_mismatch"),
        ("policy_digest", "protected_policy_mismatch"),
        ("parent_commit", "protected_parent_mismatch"),
        ("candidate_commit", "protected_candidate_mismatch"),
        ("candidate_tree", "protected_candidate_tree_mismatch"),
        ("executable_digest", "protected_executable_mismatch"),
        ("adapter_digest", "protected_adapter_mismatch"),
        ("task_set_digest", "protected_task_set_mismatch"),
        ("metric_pack_digest", "protected_metric_pack_mismatch"),
        ("model", "protected_model_mismatch"),
        ("effort", "protected_effort_mismatch"),
        ("environment_digest", "protected_environment_mismatch"),
    )
    for name, error in identity_errors:
        if getattr(receipt, name) != getattr(expected, name):
            raise PromotionContractError(error)
    if now > _parse_utc("expires_at", receipt.expires_at):
        raise PromotionContractError("protected_receipt_expired")
    if receipt.decision != "pass":
        raise PromotionContractError("protected_validation_not_passed")
    if receipt.holdout_leakage_detected:
        raise PromotionContractError("protected_holdout_leakage")
    if not receipt.workflow_passed:
        raise PromotionContractError("protected_workflow_failed")
    if not receipt.safety_passed:
        raise PromotionContractError("protected_safety_failed")
    if any(_is_constitutional(path) for path in changed_paths):
        raise PromotionContractError("constitutional_change_requires_owner")
    return VerifiedProtectedValidation(
        validation_id=receipt.validation_id,
        receipt_digest=receipt.digest,
        candidate_commit=receipt.candidate_commit,
        candidate_tree=receipt.candidate_tree,
        expires_at=receipt.expires_at,
    )
