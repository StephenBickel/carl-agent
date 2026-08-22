from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_evaluation_authority import ProtectedArchiveVersion

NOW = datetime(2026, 8, 22, 12, tzinfo=UTC)


def _artifact(
    *,
    node_kind: str = "archive_builder",
    reason: str = "authoritative_completion_receipt_invalid",
) -> dict[str, object]:
    identity = {
        "attempt": 1,
        "changed_action_digest": "b" * 64,
        "command_key": f"experiment-1:{node_kind}:attempt:1",
        "decision_identity": "c" * 64,
        "effect_key": f"cloud-effect-{'d' * 64}",
        "experiment_id": "experiment-1",
        "freeze_fingerprint": "e" * 64,
        "node_id": f"experiment-1:{node_kind}",
        "node_kind": node_kind,
        "occurrence_key": f"coordinator-freeze/{'e' * 64}",
        "reason": reason,
        "request_digest": "f" * 64,
        "runtime_revision": 7,
    }
    repair_fingerprint = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
    return {
        **identity,
        "domain": "carl.coordinator-recovery-artifact.v1",
        "repair_fingerprint": repair_fingerprint,
        "repaired_at": "2026-08-22T11:59:00Z",
        "schema_version": 1,
    }


def _archive(payload: bytes) -> ProtectedArchiveVersion:
    digest = hashlib.sha256(payload).hexdigest()
    return ProtectedArchiveVersion(
        object_key=f"carl-evidence/v1/sha256/{digest[:2]}/{digest}",
        version_id="recovery-v1",
        payload=payload,
        checksum_sha256=digest,
        byte_length=len(payload),
        retention_mode="COMPLIANCE",
        retain_until="2027-08-22T12:00:00Z",
        created_at="2026-08-22T11:59:30Z",
    )


def test_recovery_receipt_hashes_actual_archived_bytes_and_exact_freeze_identity() -> None:
    from carl_bench.coordinator_recovery_archive import verify_archived_recovery_artifact

    payload = canonical_json_bytes(_artifact())

    receipt = verify_archived_recovery_artifact(_archive(payload), observed_at=NOW)

    assert receipt.evidence_digest == hashlib.sha256(payload).hexdigest()
    assert receipt.artifact == _artifact()
    assert receipt.archive_object_key == _archive(payload).object_key
    assert receipt.archive_version_id == "recovery-v1"
    assert receipt.freeze_fingerprint == "e" * 64
    assert receipt.occurrence_key == f"coordinator-freeze/{'e' * 64}"
    assert receipt.command_key == "experiment-1:archive_builder:attempt:1"
    assert receipt.effect_key == f"cloud-effect-{'d' * 64}"
    assert receipt.request_digest == "f" * 64
    assert receipt.reason == "authoritative_completion_receipt_invalid"


def test_recovery_receipt_accepts_exact_production_freeze_reason_for_production_node() -> None:
    from carl_bench.coordinator_recovery_archive import verify_archived_recovery_artifact

    artifact = _artifact(
        node_kind="create_promotion_pr",
        reason="protected_production_receipts_required",
    )
    payload = canonical_json_bytes(artifact)

    receipt = verify_archived_recovery_artifact(_archive(payload), observed_at=NOW)

    assert receipt.artifact == artifact
    assert receipt.reason == "protected_production_receipts_required"


def test_recovery_receipt_rejects_service_freeze_reason_for_a_different_family() -> None:
    from carl_bench.coordinator_recovery_archive import (
        CoordinatorRecoveryArchiveError,
        verify_archived_recovery_artifact,
    )

    payload = canonical_json_bytes(_artifact(reason="input_service_uncommissioned"))

    with pytest.raises(CoordinatorRecoveryArchiveError):
        verify_archived_recovery_artifact(_archive(payload), observed_at=NOW)


@pytest.mark.parametrize(
    "mutation",
    (
        {"reason": "different_reason"},
        {"request_digest": "0" * 64},
        {"command_key": "experiment-1:other:attempt:1"},
        {"freeze_fingerprint": "0" * 64},
        {"repair_fingerprint": "0" * 64},
    ),
)
def test_recovery_receipt_rejects_bytes_not_bound_to_the_exact_freeze(
    mutation: dict[str, object],
) -> None:
    from carl_bench.coordinator_recovery_archive import (
        CoordinatorRecoveryArchiveError,
        verify_archived_recovery_artifact,
    )

    artifact = {**_artifact(), **mutation}
    payload = canonical_json_bytes(artifact)

    with pytest.raises(CoordinatorRecoveryArchiveError):
        verify_archived_recovery_artifact(_archive(payload), observed_at=NOW)


def test_recovery_receipt_rejects_metadata_for_bytes_the_archive_did_not_return() -> None:
    from carl_bench.coordinator_recovery_archive import (
        CoordinatorRecoveryArchiveError,
        verify_archived_recovery_artifact,
    )

    payload = canonical_json_bytes(_artifact())
    archive = _archive(payload)
    forged = ProtectedArchiveVersion(
        object_key=archive.object_key,
        version_id=archive.version_id,
        payload=payload + b" ",
        checksum_sha256=archive.checksum_sha256,
        byte_length=archive.byte_length,
        retention_mode=archive.retention_mode,
        retain_until=archive.retain_until,
        created_at=archive.created_at,
    )

    with pytest.raises(CoordinatorRecoveryArchiveError):
        verify_archived_recovery_artifact(forged, observed_at=NOW)
