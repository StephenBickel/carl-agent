"""Protected archived-byte binding for one exact coordinator freeze recovery."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from carl_bench.canonical import CanonicalizationError, canonical_json_bytes
from carl_bench.cloud_coordinator import NODE_ORDER, effect_family_for_node
from carl_bench.live_evaluation_authority import ProtectedArchiveVersion

_DOMAIN = "carl.coordinator-recovery-artifact.v1"
_RECEIPT_DOMAIN = "carl.coordinator-recovery-archive-receipt.v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EFFECT_KEY = re.compile(r"^cloud-effect-[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+=-]{0,255}$")
_UNIVERSAL_REASONS = frozenset(
    {
        "authoritative_completion_receipt_invalid",
        "command_identity_conflict",
        "completed_command_node_not_advanced",
        "effect_identity_conflict",
        "claimed_command_identity_missing",
        "failure_command_mismatch",
    }
)
_PRODUCTION_NODES = frozenset(
    {
        "create_promotion_pr",
        "observe_required_checks",
        "enable_auto_merge",
        "schedule_soak",
        "observe_soak",
        "accept_soak",
        "create_revert",
        "observe_revert",
    }
)
_PRODUCTION_REASONS = frozenset(
    {
        "protected_production_receipts_required",
        "production_experiment_identity_mismatch",
        "production_node_identity_mismatch",
        "production_request_identity_mismatch",
        "protected_verification_stale",
        "protected_archive_retention_expired",
        "merge_bound_soak_required",
    }
)
_ARTIFACT_FIELDS = frozenset(
    {
        "attempt",
        "changed_action_digest",
        "command_key",
        "decision_identity",
        "domain",
        "effect_key",
        "experiment_id",
        "freeze_fingerprint",
        "node_id",
        "node_kind",
        "occurrence_key",
        "reason",
        "repair_fingerprint",
        "repaired_at",
        "request_digest",
        "runtime_revision",
        "schema_version",
    }
)


class CoordinatorRecoveryArchiveError(ValueError):
    def __init__(self, code: str = "coordinator_recovery_archive_invalid") -> None:
        self.code = code
        super().__init__(code)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoordinatorRecoveryArchiveError()
        result[key] = value
    return result


def _utc(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise CoordinatorRecoveryArchiveError()
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CoordinatorRecoveryArchiveError() from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise CoordinatorRecoveryArchiveError()
    return parsed


def _canonical_artifact(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not 2 <= len(payload) <= 32_768:
        raise CoordinatorRecoveryArchiveError()
    try:
        value = json.loads(payload, object_pairs_hook=_pairs)
        canonical = canonical_json_bytes(value)
    except (
        UnicodeError,
        json.JSONDecodeError,
        CanonicalizationError,
        CoordinatorRecoveryArchiveError,
    ) as error:
        raise CoordinatorRecoveryArchiveError() from error
    if type(value) is not dict or canonical != payload or set(value) != _ARTIFACT_FIELDS:
        raise CoordinatorRecoveryArchiveError()
    return value


def _freeze_reason_valid(node_kind: str, reason: object) -> bool:
    return isinstance(reason, str) and (
        reason == f"{effect_family_for_node(node_kind)}_service_uncommissioned"
        or reason in _UNIVERSAL_REASONS
        or (node_kind in _PRODUCTION_NODES and reason in _PRODUCTION_REASONS)
    )


@dataclass(frozen=True, slots=True)
class VerifiedCoordinatorRecoveryReceipt:
    artifact: dict[str, Any]
    evidence_digest: str
    archive_object_key: str
    archive_version_id: str
    archive_checksum_sha256: str
    archive_byte_length: int
    retention_mode: str
    retained_until: str
    archive_created_at: str
    verified_at: str

    @property
    def freeze_fingerprint(self) -> str:
        return self.artifact["freeze_fingerprint"]

    @property
    def occurrence_key(self) -> str:
        return self.artifact["occurrence_key"]

    @property
    def command_key(self) -> str:
        return self.artifact["command_key"]

    @property
    def effect_key(self) -> str:
        return self.artifact["effect_key"]

    @property
    def request_digest(self) -> str:
        return self.artifact["request_digest"]

    @property
    def reason(self) -> str:
        return self.artifact["reason"]

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "archive_byte_length": self.archive_byte_length,
            "archive_checksum_sha256": self.archive_checksum_sha256,
            "archive_created_at": self.archive_created_at,
            "archive_object_key": self.archive_object_key,
            "archive_version_id": self.archive_version_id,
            "artifact": self.artifact,
            "domain": _RECEIPT_DOMAIN,
            "evidence_digest": self.evidence_digest,
            "retained_until": self.retained_until,
            "retention_mode": self.retention_mode,
            "schema_version": 1,
            "verified_at": self.verified_at,
        }


def verify_archived_recovery_artifact(
    archive: ProtectedArchiveVersion, *, observed_at: datetime
) -> VerifiedCoordinatorRecoveryReceipt:
    if not isinstance(archive, ProtectedArchiveVersion) or observed_at.tzinfo != UTC:
        raise CoordinatorRecoveryArchiveError()
    artifact = _canonical_artifact(archive.payload)
    digest = hashlib.sha256(archive.payload).hexdigest()
    node_kind = artifact["node_kind"]
    experiment_id = artifact["experiment_id"]
    attempt = artifact["attempt"]
    freeze_fingerprint = artifact["freeze_fingerprint"]
    identity = {
        name: artifact[name]
        for name in (
            "attempt",
            "changed_action_digest",
            "command_key",
            "decision_identity",
            "effect_key",
            "experiment_id",
            "freeze_fingerprint",
            "node_id",
            "node_kind",
            "occurrence_key",
            "reason",
            "request_digest",
            "runtime_revision",
        )
    }
    try:
        repair_fingerprint = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    except CanonicalizationError as error:
        raise CoordinatorRecoveryArchiveError() from error
    created_at = _utc(archive.created_at)
    retained_until = _utc(archive.retain_until)
    repaired_at = _utc(artifact["repaired_at"])
    if (
        artifact["schema_version"] != 1
        or isinstance(artifact["schema_version"], bool)
        or artifact["domain"] != _DOMAIN
        or not isinstance(experiment_id, str)
        or _IDENTIFIER.fullmatch(experiment_id) is None
        or node_kind not in NODE_ORDER
        or artifact["node_id"] != f"{experiment_id}:{node_kind}"
        or isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or not 1 <= attempt <= 3
        or artifact["command_key"] != f"{experiment_id}:{node_kind}:attempt:{attempt}"
        or not isinstance(artifact["effect_key"], str)
        or _EFFECT_KEY.fullmatch(artifact["effect_key"]) is None
        or any(
            not isinstance(artifact[field], str)
            or _DIGEST.fullmatch(artifact[field]) is None
            or artifact[field] == "0" * 64
            for field in (
                "changed_action_digest",
                "decision_identity",
                "freeze_fingerprint",
                "repair_fingerprint",
                "request_digest",
            )
        )
        or artifact["occurrence_key"] != f"coordinator-freeze/{freeze_fingerprint}"
        or not _freeze_reason_valid(node_kind, artifact["reason"])
        or artifact["repair_fingerprint"] != repair_fingerprint
        or isinstance(artifact["runtime_revision"], bool)
        or not isinstance(artifact["runtime_revision"], int)
        or not 0 <= artifact["runtime_revision"] < 2_147_483_647
        or not isinstance(archive.object_key, str)
        or archive.object_key != f"carl-evidence/v1/sha256/{digest[:2]}/{digest}"
        or not isinstance(archive.version_id, str)
        or _VERSION.fullmatch(archive.version_id) is None
        or archive.checksum_sha256 != digest
        or isinstance(archive.byte_length, bool)
        or archive.byte_length != len(archive.payload)
        or archive.retention_mode != "COMPLIANCE"
        or created_at > observed_at
        or repaired_at > created_at
        or retained_until <= observed_at
    ):
        raise CoordinatorRecoveryArchiveError()
    return VerifiedCoordinatorRecoveryReceipt(
        artifact=artifact,
        evidence_digest=digest,
        archive_object_key=archive.object_key,
        archive_version_id=archive.version_id,
        archive_checksum_sha256=digest,
        archive_byte_length=len(archive.payload),
        retention_mode="COMPLIANCE",
        retained_until=archive.retain_until,
        archive_created_at=archive.created_at,
        verified_at=observed_at.isoformat().replace("+00:00", "Z"),
    )
