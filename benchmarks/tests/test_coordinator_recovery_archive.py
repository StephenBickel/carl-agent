from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from carl_bench.canonical import canonical_json_bytes
from carl_bench.coordinator_recovery import CoordinatorRecoveryRequest
from carl_bench.live_evaluation_authority import ProtectedArchiveVersion

NOW = datetime(2026, 8, 22, 12, tzinfo=UTC)
ARCHIVE_PRIVATE_KEY = Ed25519PrivateKey.generate()
ARCHIVE_KEY_ID = "protected-recovery-archive-v1"


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


def _trusted_keyring(
    private_key: Ed25519PrivateKey = ARCHIVE_PRIVATE_KEY,
    *,
    key_id: str = ARCHIVE_KEY_ID,
):
    from carl_bench.coordinator_recovery_archive import (
        CoordinatorRecoveryArchiveKeyring,
        TrustedCoordinatorRecoveryArchiveKey,
    )

    return CoordinatorRecoveryArchiveKeyring(
        keys=(
            TrustedCoordinatorRecoveryArchiveKey(
                key_id=key_id,
                algorithm="Ed25519",
                public_key_pem=private_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
            ),
        )
    )


def _signed_envelope(
    artifact: dict[str, object],
    *,
    private_key: Ed25519PrivateKey = ARCHIVE_PRIVATE_KEY,
    key_id: str = ARCHIVE_KEY_ID,
    algorithm: str = "Ed25519",
    issued_at: str = "2026-08-22T11:59:15Z",
    expires_at: str = "2026-08-22T13:00:00Z",
) -> dict[str, object]:
    binding = {
        field: artifact[field]
        for field in (
            "command_key",
            "effect_key",
            "freeze_fingerprint",
            "occurrence_key",
            "reason",
            "repair_fingerprint",
            "request_digest",
        )
    }
    unsigned = {
        "algorithm": algorithm,
        "artifact": artifact,
        "binding": binding,
        "domain": "carl.coordinator-recovery-signed-envelope.v1",
        "expires_at": expires_at,
        "issued_at": issued_at,
        "key_id": key_id,
        "purpose": "coordinator_node_recovery",
        "schema_version": 1,
    }
    return {
        **unsigned,
        "signature_base64": base64.b64encode(
            private_key.sign(canonical_json_bytes(unsigned))
        ).decode("ascii"),
    }


def _signed_archive(artifact: dict[str, object] | None = None) -> ProtectedArchiveVersion:
    return _archive(canonical_json_bytes(_signed_envelope(artifact or _artifact())))


def test_recovery_receipt_hashes_actual_archived_bytes_and_exact_freeze_identity() -> None:
    from carl_bench.coordinator_recovery_archive import (
        CoordinatorRecoveryArchiveError,
        VerifiedCoordinatorRecoveryReceipt,
        verify_archived_recovery_artifact,
    )

    with pytest.raises(CoordinatorRecoveryArchiveError):
        VerifiedCoordinatorRecoveryReceipt()

    payload = canonical_json_bytes(_signed_envelope(_artifact()))

    receipt = verify_archived_recovery_artifact(
        _archive(payload), observed_at=NOW, trusted_keyring=_trusted_keyring()
    )

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
    assert receipt.signature_algorithm == "Ed25519"
    assert receipt.signature_key_id == ARCHIVE_KEY_ID
    assert receipt.signature_expires_at == "2026-08-22T13:00:00Z"


def test_verified_recovery_receipt_cannot_be_mutated_after_signature_verification() -> None:
    from carl_bench.coordinator_recovery_archive import verify_archived_recovery_artifact

    receipt = verify_archived_recovery_artifact(
        _signed_archive(), observed_at=NOW, trusted_keyring=_trusted_keyring()
    )
    artifact = receipt.artifact
    envelope = receipt.signed_envelope

    artifact["reason"] = "different_reason"
    envelope["purpose"] = "different_purpose"
    envelope["artifact"] = artifact

    assert receipt.reason == "authoritative_completion_receipt_invalid"
    assert receipt.signed_envelope["purpose"] == "coordinator_node_recovery"
    assert receipt.to_canonical_dict()["artifact"] == _artifact()


def test_recovery_receipt_accepts_exact_production_freeze_reason_for_production_node() -> None:
    from carl_bench.coordinator_recovery_archive import verify_archived_recovery_artifact

    artifact = _artifact(
        node_kind="create_promotion_pr",
        reason="protected_production_receipts_required",
    )
    payload = canonical_json_bytes(_signed_envelope(artifact))

    receipt = verify_archived_recovery_artifact(
        _archive(payload), observed_at=NOW, trusted_keyring=_trusted_keyring()
    )

    assert receipt.artifact == artifact
    assert receipt.reason == "protected_production_receipts_required"


def test_recovery_receipt_rejects_service_freeze_reason_for_a_different_family() -> None:
    from carl_bench.coordinator_recovery_archive import (
        CoordinatorRecoveryArchiveError,
        verify_archived_recovery_artifact,
    )

    payload = canonical_json_bytes(
        _signed_envelope(_artifact(reason="input_service_uncommissioned"))
    )

    with pytest.raises(CoordinatorRecoveryArchiveError):
        verify_archived_recovery_artifact(
            _archive(payload), observed_at=NOW, trusted_keyring=_trusted_keyring()
        )


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
    payload = canonical_json_bytes(_signed_envelope(artifact))

    with pytest.raises(CoordinatorRecoveryArchiveError):
        verify_archived_recovery_artifact(
            _archive(payload), observed_at=NOW, trusted_keyring=_trusted_keyring()
        )


def test_recovery_receipt_rejects_wrong_key_and_forged_signature() -> None:
    from carl_bench.coordinator_recovery_archive import (
        CoordinatorRecoveryArchiveError,
        verify_archived_recovery_artifact,
    )

    archive = _signed_archive()
    with pytest.raises(
        CoordinatorRecoveryArchiveError, match="coordinator_recovery_signature_invalid"
    ):
        verify_archived_recovery_artifact(
            archive,
            observed_at=NOW,
            trusted_keyring=_trusted_keyring(Ed25519PrivateKey.generate()),
        )

    envelope = _signed_envelope(_artifact())
    envelope["signature_base64"] = base64.b64encode(bytes(64)).decode("ascii")
    with pytest.raises(
        CoordinatorRecoveryArchiveError, match="coordinator_recovery_signature_invalid"
    ):
        verify_archived_recovery_artifact(
            _archive(canonical_json_bytes(envelope)),
            observed_at=NOW,
            trusted_keyring=_trusted_keyring(),
        )


def test_recovery_receipt_rejects_changed_signed_artifact_bytes() -> None:
    from carl_bench.coordinator_recovery_archive import (
        CoordinatorRecoveryArchiveError,
        verify_archived_recovery_artifact,
    )

    envelope = _signed_envelope(_artifact())
    envelope["artifact"] = {**_artifact(), "request_digest": "a" * 64}

    with pytest.raises(CoordinatorRecoveryArchiveError):
        verify_archived_recovery_artifact(
            _archive(canonical_json_bytes(envelope)),
            observed_at=NOW,
            trusted_keyring=_trusted_keyring(),
        )


def test_recovery_receipt_rejects_expired_signed_envelope() -> None:
    from carl_bench.coordinator_recovery_archive import (
        CoordinatorRecoveryArchiveError,
        verify_archived_recovery_artifact,
    )

    archive = _archive(
        canonical_json_bytes(_signed_envelope(_artifact(), expires_at="2026-08-22T12:00:00Z"))
    )

    with pytest.raises(
        CoordinatorRecoveryArchiveError, match="coordinator_recovery_signature_expired"
    ):
        verify_archived_recovery_artifact(
            archive, observed_at=NOW, trusted_keyring=_trusted_keyring()
        )


def test_recovery_receipt_rejects_metadata_for_bytes_the_archive_did_not_return() -> None:
    from carl_bench.coordinator_recovery_archive import (
        CoordinatorRecoveryArchiveError,
        verify_archived_recovery_artifact,
    )

    payload = canonical_json_bytes(_signed_envelope(_artifact()))
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
        verify_archived_recovery_artifact(
            forged, observed_at=NOW, trusted_keyring=_trusted_keyring()
        )


def test_production_recovery_reads_verifies_registers_then_reactivates() -> None:
    from carl_bench.coordinator_recovery_archive import recover_coordinator_node_from_archive

    payload = canonical_json_bytes(_signed_envelope(_artifact()))
    archive = _archive(payload)
    order: list[str] = []

    class Reader:
        def read_exact(self, object_key: str, version_id: str) -> ProtectedArchiveVersion:
            assert (object_key, version_id) == (archive.object_key, archive.version_id)
            order.append("read")
            return archive

    class Registrar:
        def register_verified_coordinator_recovery_receipt(
            self, receipt: object, *, observed_at: datetime
        ) -> bool:
            assert receipt.evidence_digest == archive.checksum_sha256  # type: ignore[attr-defined]
            assert observed_at == NOW
            order.append("register")
            return True

    class State:
        def reactivate_verified_coordinator_node(
            self,
            recovery: CoordinatorRecoveryRequest,
            receipt: object,
            *,
            observed_at: datetime,
        ) -> dict[str, object]:
            assert recovery.evidence_digest == archive.checksum_sha256
            assert recovery.repair_fingerprint == _artifact()["repair_fingerprint"]
            assert receipt.evidence_digest == archive.checksum_sha256  # type: ignore[attr-defined]
            assert observed_at == NOW
            order.append("reactivate")
            return {
                "applied": True,
                "attempt": 2,
                "request_digest": "a" * 64,
                "revision": 8,
            }

    recovery = CoordinatorRecoveryRequest(
        schema_version=1,
        domain="carl.coordinator.recovery.v1",
        experiment_id="experiment-1",
        node_id="experiment-1:archive_builder",
        node_kind="archive_builder",
        expected_revision=7,
        evidence_digest=archive.checksum_sha256,
        repair_fingerprint=str(_artifact()["repair_fingerprint"]),
        requested_at="2026-08-22T12:00:00Z",
    )

    result = recover_coordinator_node_from_archive(
        recovery,
        object_key=archive.object_key,
        version_id=archive.version_id,
        archive_reader=Reader(),
        receipt_registrar=Registrar(),
        state=State(),
        observed_at=NOW,
        trusted_keyring=_trusted_keyring(),
    )

    assert result["applied"] is True
    assert order == ["read", "register", "reactivate"]


def test_production_recovery_never_registers_or_reactivates_unverified_bytes() -> None:
    from carl_bench.coordinator_recovery_archive import (
        CoordinatorRecoveryArchiveError,
        recover_coordinator_node_from_archive,
    )

    valid_payload = canonical_json_bytes(_signed_envelope(_artifact()))
    payload = valid_payload + b" "
    archive = _archive(valid_payload)
    forged = ProtectedArchiveVersion(
        object_key=archive.object_key,
        version_id=archive.version_id,
        payload=payload,
        checksum_sha256=archive.checksum_sha256,
        byte_length=archive.byte_length,
        retention_mode=archive.retention_mode,
        retain_until=archive.retain_until,
        created_at=archive.created_at,
    )
    called: list[str] = []

    class Reader:
        def read_exact(self, object_key: str, version_id: str) -> ProtectedArchiveVersion:
            del object_key, version_id
            return forged

    class Denied:
        def register_verified_coordinator_recovery_receipt(self, *args: object, **kwargs: object):
            del args, kwargs
            called.append("register")
            raise AssertionError("register")

        def reactivate_verified_coordinator_node(self, *args: object, **kwargs: object):
            del args, kwargs
            called.append("reactivate")
            raise AssertionError("reactivate")

    artifact = _artifact()
    recovery = CoordinatorRecoveryRequest(
        schema_version=1,
        domain="carl.coordinator.recovery.v1",
        experiment_id="experiment-1",
        node_id="experiment-1:archive_builder",
        node_kind="archive_builder",
        expected_revision=7,
        evidence_digest=archive.checksum_sha256,
        repair_fingerprint=str(artifact["repair_fingerprint"]),
        requested_at="2026-08-22T12:00:00Z",
    )

    with pytest.raises(CoordinatorRecoveryArchiveError):
        recover_coordinator_node_from_archive(
            recovery,
            object_key=archive.object_key,
            version_id=archive.version_id,
            archive_reader=Reader(),
            receipt_registrar=Denied(),
            state=Denied(),
            observed_at=NOW,
            trusted_keyring=_trusted_keyring(),
        )

    assert called == []


def test_archive_receipt_registrar_redacts_connection_failures() -> None:
    from carl_bench.coordinator_recovery_archive import verify_archived_recovery_artifact
    from carl_bench.postgres_state import (
        PostgresCoordinatorRecoveryReceiptRegistrar,
        PostgresStateError,
    )

    receipt = verify_archived_recovery_artifact(
        _signed_archive(), observed_at=NOW, trusted_keyring=_trusted_keyring()
    )

    def unavailable(dsn: str):
        assert dsn == "postgresql://protected-archive"
        raise RuntimeError("private connection detail")

    registrar = PostgresCoordinatorRecoveryReceiptRegistrar._for_testing(
        dsn="postgresql://protected-archive", connect=unavailable
    )

    with pytest.raises(PostgresStateError, match="postgres_archive_connection_failed") as error:
        registrar.register_verified_coordinator_recovery_receipt(receipt, observed_at=NOW)

    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    ("experiment_id", "expected_revision"),
    (("experiment-2", 7), ("experiment-1", 8)),
)
def test_signed_recovery_cannot_be_replayed_to_another_request_or_freeze(
    experiment_id: str, expected_revision: int
) -> None:
    from carl_bench.coordinator_recovery_archive import (
        CoordinatorRecoveryArchiveError,
        recover_coordinator_node_from_archive,
    )

    archive = _signed_archive()
    called: list[str] = []

    class Reader:
        def read_exact(self, object_key: str, version_id: str) -> ProtectedArchiveVersion:
            assert (object_key, version_id) == (archive.object_key, archive.version_id)
            return archive

    class Denied:
        def register_verified_coordinator_recovery_receipt(self, *args: object, **kwargs: object):
            del args, kwargs
            called.append("register")
            raise AssertionError("register")

        def reactivate_verified_coordinator_node(self, *args: object, **kwargs: object):
            del args, kwargs
            called.append("reactivate")
            raise AssertionError("reactivate")

    replay = CoordinatorRecoveryRequest(
        schema_version=1,
        domain="carl.coordinator.recovery.v1",
        experiment_id=experiment_id,
        node_id=f"{experiment_id}:archive_builder",
        node_kind="archive_builder",
        expected_revision=expected_revision,
        evidence_digest=archive.checksum_sha256,
        repair_fingerprint=str(_artifact()["repair_fingerprint"]),
        requested_at="2026-08-22T12:00:00Z",
    )

    with pytest.raises(CoordinatorRecoveryArchiveError):
        recover_coordinator_node_from_archive(
            replay,
            object_key=archive.object_key,
            version_id=archive.version_id,
            archive_reader=Reader(),
            receipt_registrar=Denied(),
            state=Denied(),
            observed_at=NOW,
            trusted_keyring=_trusted_keyring(),
        )

    assert called == []


def test_protected_recovery_keyring_loads_only_pinned_public_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from carl_bench import coordinator_recovery_archive
    from carl_bench.coordinator_recovery_archive import (
        load_protected_coordinator_recovery_keyring,
    )

    policy_dir = tmp_path / "etc-carl"
    policy_dir.mkdir(mode=0o700)
    public_key_pem = ARCHIVE_PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    policy = {
        "domain": "carl.coordinator-recovery-keyring.v1",
        "keys": [
            {
                "algorithm": "Ed25519",
                "key_id": ARCHIVE_KEY_ID,
                "public_key_pem_b64": base64.b64encode(public_key_pem).decode("ascii"),
            }
        ],
        "schema_version": 1,
    }
    policy_path = policy_dir / "coordinator-recovery-keyring.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    policy_path.chmod(0o600)
    monkeypatch.setattr(coordinator_recovery_archive, "_PROTECTED_KEYRING_CONFIG_DIR", policy_dir)

    keyring = load_protected_coordinator_recovery_keyring()

    assert keyring == _trusted_keyring()
    assert b"PRIVATE KEY" not in policy_path.read_bytes()


def test_protected_recovery_keyring_rejects_private_or_symmetric_signing_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from carl_bench import coordinator_recovery_archive
    from carl_bench.coordinator_recovery_archive import (
        CoordinatorRecoveryArchiveError,
        load_protected_coordinator_recovery_keyring,
    )

    policy_dir = tmp_path / "etc-carl"
    policy_dir.mkdir(mode=0o700)
    policy = {
        "domain": "carl.coordinator-recovery-keyring.v1",
        "keys": [
            {
                "algorithm": "HMAC-SHA256",
                "key_id": ARCHIVE_KEY_ID,
                "private_key_pem_b64": base64.b64encode(
                    ARCHIVE_PRIVATE_KEY.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    )
                ).decode("ascii"),
            }
        ],
        "schema_version": 1,
    }
    policy_path = policy_dir / "coordinator-recovery-keyring.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    policy_path.chmod(0o600)
    monkeypatch.setattr(coordinator_recovery_archive, "_PROTECTED_KEYRING_CONFIG_DIR", policy_dir)

    with pytest.raises(
        CoordinatorRecoveryArchiveError, match="coordinator_recovery_keyring_invalid"
    ):
        load_protected_coordinator_recovery_keyring()
