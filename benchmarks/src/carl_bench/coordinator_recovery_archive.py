"""Protected archived-byte binding for one exact coordinator freeze recovery."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from carl_bench.canonical import CanonicalizationError, canonical_json_bytes
from carl_bench.cloud_coordinator import NODE_ORDER, effect_family_for_node
from carl_bench.coordinator_recovery import CoordinatorRecoveryRequest
from carl_bench.live_evaluation_authority import ProtectedArchiveVersion

_DOMAIN = "carl.coordinator-recovery-artifact.v1"
_RECEIPT_DOMAIN = "carl.coordinator-recovery-archive-receipt.v1"
_ENVELOPE_DOMAIN = "carl.coordinator-recovery-signed-envelope.v1"
_ENVELOPE_PURPOSE = "coordinator_node_recovery"
_SIGNATURE_ALGORITHM = "Ed25519"
_PROTECTED_KEYRING_CONFIG_DIR = Path("/etc/carl")
_PROTECTED_KEYRING_CONFIG_NAME = "coordinator-recovery-keyring.json"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EFFECT_KEY = re.compile(r"^cloud-effect-[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
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
_BINDING_FIELDS = (
    "command_key",
    "effect_key",
    "freeze_fingerprint",
    "occurrence_key",
    "reason",
    "repair_fingerprint",
    "request_digest",
)
_ENVELOPE_FIELDS = frozenset(
    {
        "algorithm",
        "artifact",
        "binding",
        "domain",
        "expires_at",
        "issued_at",
        "key_id",
        "purpose",
        "schema_version",
        "signature_base64",
    }
)


class CoordinatorRecoveryArchiveError(ValueError):
    def __init__(self, code: str = "coordinator_recovery_archive_invalid") -> None:
        self.code = code
        super().__init__(code)


def _canonical_signature(value: object) -> bytes:
    if not isinstance(value, str):
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_signature_invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_signature_invalid") from error
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_signature_invalid")
    return decoded


@dataclass(frozen=True, slots=True)
class TrustedCoordinatorRecoveryArchiveKey:
    """Pinned archive-authority public key; no signing material enters the verifier."""

    key_id: str
    algorithm: str
    public_key_pem: bytes

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("TrustedCoordinatorRecoveryArchiveKey cannot be subclassed")

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or _KEY_ID.fullmatch(self.key_id) is None:
            raise CoordinatorRecoveryArchiveError("coordinator_recovery_key_invalid")
        if self.algorithm != _SIGNATURE_ALGORITHM or not isinstance(self.public_key_pem, bytes):
            raise CoordinatorRecoveryArchiveError("coordinator_recovery_key_invalid")
        try:
            key = serialization.load_pem_public_key(self.public_key_pem)
        except (TypeError, ValueError) as error:
            raise CoordinatorRecoveryArchiveError("coordinator_recovery_key_invalid") from error
        if not isinstance(key, Ed25519PublicKey):
            raise CoordinatorRecoveryArchiveError("coordinator_recovery_key_invalid")

    @property
    def public_key(self) -> Ed25519PublicKey:
        key = serialization.load_pem_public_key(self.public_key_pem)
        if not isinstance(key, Ed25519PublicKey):  # pragma: no cover - constructor guards
            raise CoordinatorRecoveryArchiveError("coordinator_recovery_key_invalid")
        return key


@dataclass(frozen=True, slots=True)
class CoordinatorRecoveryArchiveKeyring:
    """Immutable rotation keyring containing archive-authority public keys only."""

    keys: tuple[TrustedCoordinatorRecoveryArchiveKey, ...]

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("CoordinatorRecoveryArchiveKeyring cannot be subclassed")

    def __post_init__(self) -> None:
        if (
            type(self.keys) is not tuple
            or not 1 <= len(self.keys) <= 8
            or any(type(key) is not TrustedCoordinatorRecoveryArchiveKey for key in self.keys)
            or len({key.key_id for key in self.keys}) != len(self.keys)
        ):
            raise CoordinatorRecoveryArchiveError("coordinator_recovery_keyring_invalid")

    def trusted_key(
        self, key_id: object, algorithm: object
    ) -> TrustedCoordinatorRecoveryArchiveKey:
        if not isinstance(key_id, str) or not isinstance(algorithm, str):
            raise CoordinatorRecoveryArchiveError("coordinator_recovery_key_untrusted")
        for key in self.keys:
            if key.key_id == key_id and key.algorithm == algorithm:
                return key
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_key_untrusted")


def load_protected_coordinator_recovery_keyring() -> CoordinatorRecoveryArchiveKeyring:
    """Load the coordinator's root-owned public verifier set without any secret material."""

    directory_fd = file_fd = -1
    try:
        directory_fd = os.open(
            _PROTECTED_KEYRING_CONFIG_DIR,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        directory_stat = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid not in {0, os.geteuid()}
            or directory_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise CoordinatorRecoveryArchiveError("coordinator_recovery_keyring_invalid")
        file_fd = os.open(
            _PROTECTED_KEYRING_CONFIG_NAME,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        file_stat = os.fstat(file_fd)
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid not in {0, os.geteuid()}
            or file_stat.st_nlink != 1
            or file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not 2 <= file_stat.st_size <= 65_536
        ):
            raise CoordinatorRecoveryArchiveError("coordinator_recovery_keyring_invalid")
        payload = os.read(file_fd, 65_537)
        if len(payload) != file_stat.st_size:
            raise CoordinatorRecoveryArchiveError("coordinator_recovery_keyring_invalid")
    except CoordinatorRecoveryArchiveError:
        raise
    except OSError as error:
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_keyring_invalid") from error
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if directory_fd >= 0:
            os.close(directory_fd)
    try:
        value = json.loads(payload, object_pairs_hook=_pairs)
        if (
            type(value) is not dict
            or set(value) != {"domain", "keys", "schema_version"}
            or value["domain"] != "carl.coordinator-recovery-keyring.v1"
            or value["schema_version"] != 1
            or isinstance(value["schema_version"], bool)
            or type(value["keys"]) is not list
            or not 1 <= len(value["keys"]) <= 8
            or canonical_json_bytes(value) != payload
        ):
            raise CoordinatorRecoveryArchiveError("coordinator_recovery_keyring_invalid")
        keys: list[TrustedCoordinatorRecoveryArchiveKey] = []
        for item in value["keys"]:
            if type(item) is not dict or set(item) != {
                "algorithm",
                "key_id",
                "public_key_pem_b64",
            }:
                raise CoordinatorRecoveryArchiveError("coordinator_recovery_keyring_invalid")
            encoded = item["public_key_pem_b64"]
            if not isinstance(encoded, str) or not 1 <= len(encoded) <= 8_192:
                raise CoordinatorRecoveryArchiveError("coordinator_recovery_keyring_invalid")
            public_key_pem = base64.b64decode(encoded, validate=True)
            if (
                not 1 <= len(public_key_pem) <= 4_096
                or base64.b64encode(public_key_pem).decode("ascii") != encoded
            ):
                raise CoordinatorRecoveryArchiveError("coordinator_recovery_keyring_invalid")
            keys.append(
                TrustedCoordinatorRecoveryArchiveKey(
                    key_id=item["key_id"],
                    algorithm=item["algorithm"],
                    public_key_pem=public_key_pem,
                )
            )
        return CoordinatorRecoveryArchiveKeyring(keys=tuple(keys))
    except CoordinatorRecoveryArchiveError as error:
        if error.code == "coordinator_recovery_keyring_invalid":
            raise
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_keyring_invalid") from error
    except (UnicodeError, json.JSONDecodeError, CanonicalizationError, binascii.Error) as error:
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_keyring_invalid") from error


class CoordinatorRecoveryArchiveReader(Protocol):
    def read_exact(self, object_key: str, version_id: str) -> ProtectedArchiveVersion: ...


class CoordinatorRecoveryReceiptRegistrar(Protocol):
    def register_verified_coordinator_recovery_receipt(
        self, receipt: VerifiedCoordinatorRecoveryReceipt, *, observed_at: datetime
    ) -> bool: ...


class VerifiedCoordinatorRecoveryState(Protocol):
    def reactivate_verified_coordinator_node(
        self,
        recovery: CoordinatorRecoveryRequest,
        receipt: VerifiedCoordinatorRecoveryReceipt,
        *,
        observed_at: datetime,
    ) -> dict[str, object]: ...


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


def _canonical_envelope(payload: bytes) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    if not isinstance(payload, bytes) or not 2 <= len(payload) <= 32_768:
        raise CoordinatorRecoveryArchiveError()
    try:
        envelope = json.loads(payload, object_pairs_hook=_pairs)
        canonical = canonical_json_bytes(envelope)
    except (
        UnicodeError,
        json.JSONDecodeError,
        CanonicalizationError,
        CoordinatorRecoveryArchiveError,
    ) as error:
        raise CoordinatorRecoveryArchiveError() from error
    if type(envelope) is not dict or canonical != payload or set(envelope) != _ENVELOPE_FIELDS:
        raise CoordinatorRecoveryArchiveError()
    try:
        artifact_bytes = canonical_json_bytes(envelope["artifact"])
    except (KeyError, CanonicalizationError) as error:
        raise CoordinatorRecoveryArchiveError() from error
    artifact = _canonical_artifact(artifact_bytes)
    binding = envelope["binding"]
    expected_binding = {field: artifact[field] for field in _BINDING_FIELDS}
    if (
        envelope["schema_version"] != 1
        or isinstance(envelope["schema_version"], bool)
        or envelope["domain"] != _ENVELOPE_DOMAIN
        or envelope["purpose"] != _ENVELOPE_PURPOSE
        or envelope["algorithm"] != _SIGNATURE_ALGORITHM
        or not isinstance(envelope["key_id"], str)
        or _KEY_ID.fullmatch(envelope["key_id"]) is None
        or type(binding) is not dict
        or binding != expected_binding
    ):
        raise CoordinatorRecoveryArchiveError()
    return envelope, artifact, artifact_bytes


def _freeze_reason_valid(node_kind: str, reason: object) -> bool:
    return isinstance(reason, str) and (
        reason == f"{effect_family_for_node(node_kind)}_service_uncommissioned"
        or reason in _UNIVERSAL_REASONS
        or (node_kind in _PRODUCTION_NODES and reason in _PRODUCTION_REASONS)
    )


@dataclass(frozen=True, slots=True, init=False)
class VerifiedCoordinatorRecoveryReceipt:
    _artifact_bytes: bytes
    _signed_envelope_bytes: bytes
    evidence_digest: str
    archive_object_key: str
    archive_version_id: str
    archive_checksum_sha256: str
    archive_byte_length: int
    retention_mode: str
    retained_until: str
    archive_created_at: str
    verified_at: str
    signature_algorithm: str
    signature_key_id: str
    signature_base64: str
    signature_issued_at: str
    signature_expires_at: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise CoordinatorRecoveryArchiveError()

    @classmethod
    def _mint(cls, **fields: object) -> VerifiedCoordinatorRecoveryReceipt:
        if set(fields) != set(cls.__dataclass_fields__):
            raise CoordinatorRecoveryArchiveError()
        value = object.__new__(cls)
        for name in cls.__dataclass_fields__:
            object.__setattr__(value, name, fields[name])
        return value

    @property
    def artifact(self) -> dict[str, Any]:
        return json.loads(self._artifact_bytes)

    @property
    def signed_envelope(self) -> dict[str, Any]:
        return json.loads(self._signed_envelope_bytes)

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
            "signed_envelope": self.signed_envelope,
            "signature_algorithm": self.signature_algorithm,
            "signature_base64": self.signature_base64,
            "signature_expires_at": self.signature_expires_at,
            "signature_issued_at": self.signature_issued_at,
            "signature_key_id": self.signature_key_id,
            "verified_at": self.verified_at,
        }


def verify_archived_recovery_artifact(
    archive: ProtectedArchiveVersion,
    *,
    observed_at: datetime,
    trusted_keyring: CoordinatorRecoveryArchiveKeyring,
) -> VerifiedCoordinatorRecoveryReceipt:
    if (
        not isinstance(archive, ProtectedArchiveVersion)
        or observed_at.tzinfo != UTC
        or type(trusted_keyring) is not CoordinatorRecoveryArchiveKeyring
    ):
        raise CoordinatorRecoveryArchiveError()
    envelope, artifact, artifact_bytes = _canonical_envelope(archive.payload)
    unsigned_envelope = {
        name: value for name, value in envelope.items() if name != "signature_base64"
    }
    trusted_key = trusted_keyring.trusted_key(envelope["key_id"], envelope["algorithm"])
    try:
        trusted_key.public_key.verify(
            _canonical_signature(envelope["signature_base64"]),
            canonical_json_bytes(unsigned_envelope),
        )
    except (InvalidSignature, CanonicalizationError) as error:
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_signature_invalid") from error
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
    issued_at = _utc(envelope["issued_at"])
    expires_at = _utc(envelope["expires_at"])
    if observed_at >= expires_at:
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_signature_expired")
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
        or repaired_at > issued_at
        or issued_at > created_at
        or created_at > observed_at
        or retained_until <= observed_at
        or expires_at > retained_until
    ):
        raise CoordinatorRecoveryArchiveError()
    return VerifiedCoordinatorRecoveryReceipt._mint(
        _artifact_bytes=artifact_bytes,
        _signed_envelope_bytes=archive.payload,
        evidence_digest=digest,
        archive_object_key=archive.object_key,
        archive_version_id=archive.version_id,
        archive_checksum_sha256=digest,
        archive_byte_length=len(archive.payload),
        retention_mode="COMPLIANCE",
        retained_until=archive.retain_until,
        archive_created_at=archive.created_at,
        verified_at=observed_at.isoformat().replace("+00:00", "Z"),
        signature_algorithm=envelope["algorithm"],
        signature_key_id=envelope["key_id"],
        signature_base64=envelope["signature_base64"],
        signature_issued_at=envelope["issued_at"],
        signature_expires_at=envelope["expires_at"],
    )


def recover_coordinator_node_from_archive(
    recovery: CoordinatorRecoveryRequest,
    *,
    object_key: str,
    version_id: str,
    archive_reader: CoordinatorRecoveryArchiveReader,
    receipt_registrar: CoordinatorRecoveryReceiptRegistrar,
    state: VerifiedCoordinatorRecoveryState,
    observed_at: datetime,
    trusted_keyring: CoordinatorRecoveryArchiveKeyring,
) -> dict[str, object]:
    """Execute the only recovery path: protected bytes first, SQL effects second."""
    if (
        not isinstance(recovery, CoordinatorRecoveryRequest)
        or not isinstance(observed_at, datetime)
        or observed_at.tzinfo != UTC
        or not isinstance(object_key, str)
        or not isinstance(version_id, str)
        or not callable(getattr(archive_reader, "read_exact", None))
        or not callable(
            getattr(
                receipt_registrar,
                "register_verified_coordinator_recovery_receipt",
                None,
            )
        )
        or not callable(getattr(state, "reactivate_verified_coordinator_node", None))
        or type(trusted_keyring) is not CoordinatorRecoveryArchiveKeyring
    ):
        raise CoordinatorRecoveryArchiveError()
    try:
        archive = archive_reader.read_exact(object_key, version_id)
    except Exception as error:
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_archive_unavailable") from error
    receipt = verify_archived_recovery_artifact(
        archive, observed_at=observed_at, trusted_keyring=trusted_keyring
    )
    artifact = receipt.artifact
    if (
        archive.object_key != object_key
        or archive.version_id != version_id
        or recovery.experiment_id != artifact["experiment_id"]
        or recovery.node_id != artifact["node_id"]
        or recovery.node_kind != artifact["node_kind"]
        or recovery.expected_revision != artifact["runtime_revision"]
        or recovery.evidence_digest != receipt.evidence_digest
        or recovery.repair_fingerprint != artifact["repair_fingerprint"]
    ):
        raise CoordinatorRecoveryArchiveError()
    try:
        registered = receipt_registrar.register_verified_coordinator_recovery_receipt(
            receipt, observed_at=observed_at
        )
    except Exception as error:
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_registration_failed") from error
    if type(registered) is not bool:
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_registration_failed")
    try:
        result = state.reactivate_verified_coordinator_node(
            recovery, receipt, observed_at=observed_at
        )
    except Exception as error:
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_reactivation_failed") from error
    if type(result) is not dict:
        raise CoordinatorRecoveryArchiveError("coordinator_recovery_reactivation_failed")
    return result
