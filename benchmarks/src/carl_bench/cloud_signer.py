"""Protected non-exportable signing contract for archived cloud evidence."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_execution import (
    CommissioningReceipt,
    ProtectedReceiptBinding,
    SignedCommissioningReceipt,
)
from carl_bench.evidence_archive import ArchivedEvidence

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_PURPOSE = "commissioning-receipt"
_DOMAIN = "carl-autonomy/cloud-evidence/v1"
_ALGORITHM = "ED25519_SHA_512"


class CloudSignerError(ValueError):
    """Stable signer failure that exposes neither provider details nor key material."""


class SignResponseLost(RuntimeError):
    """The protected sign may have succeeded but its response was lost."""


@dataclass(frozen=True, slots=True)
class ProtectedSigningPolicy:
    repository: str
    key_id: str
    algorithm: str
    purpose: str
    domain: str
    public_key_pem: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not _REPOSITORY.fullmatch(self.repository):
            raise CloudSignerError("cloud_signer_repository_invalid")
        if not isinstance(self.key_id, str) or not _KEY_ID.fullmatch(self.key_id):
            raise CloudSignerError("cloud_signer_key_id_invalid")
        if self.algorithm != _ALGORITHM:
            raise CloudSignerError("cloud_signer_algorithm_invalid")
        if self.purpose != _PURPOSE:
            raise CloudSignerError("cloud_signer_purpose_invalid")
        if self.domain != _DOMAIN:
            raise CloudSignerError("cloud_signer_domain_invalid")
        if not isinstance(self.public_key_pem, bytes) or len(self.public_key_pem) > 16_384:
            raise CloudSignerError("cloud_signer_public_key_invalid")
        try:
            key = serialization.load_pem_public_key(self.public_key_pem)
        except (TypeError, ValueError) as error:
            raise CloudSignerError("cloud_signer_public_key_invalid") from error
        if not isinstance(key, Ed25519PublicKey):
            raise CloudSignerError("cloud_signer_public_key_invalid")

    @property
    def public_key(self) -> Ed25519PublicKey:
        key = serialization.load_pem_public_key(self.public_key_pem)
        if not isinstance(key, Ed25519PublicKey):  # pragma: no cover
            raise CloudSignerError("cloud_signer_public_key_invalid")
        return key


@dataclass(frozen=True, slots=True)
class KmsSignRequest:
    repository: str
    key_id: str
    algorithm: str
    purpose: str
    domain: str
    payload: bytes
    payload_digest: str
    archive_object_key: str
    archive_version_id: str
    archive_digest: str
    occurred_at: str
    request_digest: str

    @classmethod
    def create(
        cls,
        *,
        policy: ProtectedSigningPolicy,
        payload: bytes,
        archive: ArchivedEvidence,
        occurred_at: str,
        request_digest: str,
    ) -> KmsSignRequest:
        payload_digest = hashlib.sha256(payload).hexdigest()
        if not isinstance(request_digest, str) or not _DIGEST.fullmatch(request_digest):
            raise CloudSignerError("cloud_signer_request_digest_invalid")
        return cls(
            repository=policy.repository,
            key_id=policy.key_id,
            algorithm=policy.algorithm,
            purpose=policy.purpose,
            domain=policy.domain,
            payload=payload,
            payload_digest=payload_digest,
            archive_object_key=archive.object_key,
            archive_version_id=archive.provider_version_id,
            archive_digest=archive.payload_digest,
            occurred_at=occurred_at,
            request_digest=request_digest,
        )


@dataclass(frozen=True, slots=True)
class KmsSignResult:
    request_digest: str
    key_id: str
    algorithm: str
    payload_digest: str
    signature: bytes


class ProtectedKms(Protocol):
    """One-purpose signing surface; generic KMS operations and key export are absent."""

    def sign_cloud_evidence(self, request: KmsSignRequest) -> KmsSignResult: ...

    def reconcile_cloud_signature(self, request_digest: str) -> KmsSignResult | None: ...


class CloudReceiptSigner:
    __slots__ = ("__kms", "__policy")

    def __init__(
        self, *, kms: ProtectedKms, policy: ProtectedSigningPolicy, _testing: bool
    ) -> None:
        if not _testing or not isinstance(policy, ProtectedSigningPolicy):
            raise CloudSignerError("cloud_signer_construction_invalid")
        self.__kms = kms
        self.__policy = policy

    @classmethod
    def _for_testing(
        cls, *, kms: ProtectedKms, policy: ProtectedSigningPolicy
    ) -> CloudReceiptSigner:
        return cls(kms=kms, policy=policy, _testing=True)

    def sign_commissioning_receipt(
        self, receipt: CommissioningReceipt, archive: ArchivedEvidence
    ) -> SignedCommissioningReceipt:
        self._validate_binding(receipt, archive)
        identity_payload: dict[str, Any] = {
            "algorithm": self.__policy.algorithm,
            "archive_checksum_sha256": archive.provider_checksum_sha256,
            "archive_digest": archive.payload_digest,
            "archive_object_key": archive.object_key,
            "archive_record_digest": archive.digest,
            "archive_version_id": archive.provider_version_id,
            "domain": self.__policy.domain,
            "key_id": self.__policy.key_id,
            "occurred_at": receipt.observed_at,
            "purpose": self.__policy.purpose,
            "receipt_digest": receipt.digest,
            "repository": self.__policy.repository,
            "retention_mode": archive.retention_mode,
            "retain_until": archive.retain_until,
            "schema_version": 1,
        }
        signer_request_digest = hashlib.sha256(canonical_json_bytes(identity_payload)).hexdigest()
        binding = ProtectedReceiptBinding(
            schema_version=1,
            algorithm=self.__policy.algorithm,
            purpose=self.__policy.purpose,
            domain=self.__policy.domain,
            repository=self.__policy.repository,
            signer_request_digest=signer_request_digest,
            archive_object_key=archive.object_key,
            archive_version_id=archive.provider_version_id,
            archive_digest=archive.payload_digest,
            archive_checksum_sha256=archive.provider_checksum_sha256,
            archive_record_digest=archive.digest,
            retention_mode=archive.retention_mode,
            retain_until=archive.retain_until,
            occurred_at=receipt.observed_at,
        )
        payload = canonical_json_bytes(
            {
                "protected_binding": binding.to_canonical_dict(),
                "receipt": receipt.to_canonical_dict(),
            }
        )
        request = KmsSignRequest.create(
            policy=self.__policy,
            payload=payload,
            archive=archive,
            occurred_at=receipt.observed_at,
            request_digest=signer_request_digest,
        )
        try:
            result = self.__kms.sign_cloud_evidence(request)
        except SignResponseLost:
            try:
                result = self.__kms.reconcile_cloud_signature(request.request_digest)
            except Exception:
                raise CloudSignerError("cloud_signer_unavailable") from None
            if result is None:
                raise CloudSignerError("cloud_signer_response_ambiguous") from None
        except CloudSignerError:
            raise
        except Exception:
            raise CloudSignerError("cloud_signer_unavailable") from None
        self._validate_result(request, result)
        return SignedCommissioningReceipt(
            receipt=receipt,
            receipt_digest=receipt.digest,
            key_id=result.key_id,
            signature_base64=base64.b64encode(result.signature).decode("ascii"),
            protected_binding=binding,
        )

    def _validate_binding(self, receipt: CommissioningReceipt, archive: ArchivedEvidence) -> None:
        if not isinstance(receipt, CommissioningReceipt) or not isinstance(
            archive, ArchivedEvidence
        ):
            raise CloudSignerError("cloud_signer_input_invalid")
        identity = archive.identity
        if (
            receipt.repository != self.__policy.repository
            or identity.repository != receipt.repository
            or identity.request_digest != receipt.request_digest
            or identity.run_id != receipt.run_id
            or identity.artifact_id != receipt.artifact_id
            or identity.artifact_name != receipt.artifact_name
            or archive.payload_digest != receipt.artifact_digest
            or archive.provider_checksum_sha256 != receipt.artifact_digest
            or archive.retention_mode != "COMPLIANCE"
        ):
            raise CloudSignerError("cloud_signer_archive_binding_invalid")

    def _validate_result(self, request: KmsSignRequest, result: object) -> None:
        if not isinstance(result, KmsSignResult):
            raise CloudSignerError("cloud_signer_result_invalid")
        if (
            result.request_digest != request.request_digest
            or result.key_id != self.__policy.key_id
            or result.algorithm != self.__policy.algorithm
            or result.payload_digest != request.payload_digest
            or not isinstance(result.signature, bytes)
            or len(result.signature) != 64
        ):
            raise CloudSignerError("cloud_signer_result_invalid")
        try:
            self.__policy.public_key.verify(result.signature, request.payload)
        except InvalidSignature as error:
            raise CloudSignerError("cloud_signer_signature_invalid") from error


def verify_protected_receipt(
    signed: SignedCommissioningReceipt,
    policy: ProtectedSigningPolicy,
    archive: ArchivedEvidence,
) -> str | None:
    """Verify a protected receipt and its immutable archive binding."""
    if not isinstance(signed, SignedCommissioningReceipt):
        return "cloud_signer_receipt_invalid"
    if not isinstance(policy, ProtectedSigningPolicy) or not isinstance(archive, ArchivedEvidence):
        return "cloud_signer_verifier_invalid"
    receipt = signed.receipt
    identity = archive.identity
    binding = signed.protected_binding
    if (
        binding is None
        or signed.key_id != policy.key_id
        or receipt.repository != policy.repository
        or identity.repository != receipt.repository
        or identity.request_digest != receipt.request_digest
        or identity.run_id != receipt.run_id
        or identity.artifact_id != receipt.artifact_id
        or identity.artifact_name != receipt.artifact_name
        or archive.payload_digest != receipt.artifact_digest
        or archive.provider_checksum_sha256 != receipt.artifact_digest
        or signed.receipt_digest != receipt.digest
        or binding.repository != policy.repository
        or binding.algorithm != policy.algorithm
        or binding.purpose != policy.purpose
        or binding.domain != policy.domain
        or binding.archive_object_key != archive.object_key
        or binding.archive_version_id != archive.provider_version_id
        or binding.archive_digest != archive.payload_digest
        or binding.archive_checksum_sha256 != archive.provider_checksum_sha256
        or binding.archive_record_digest != archive.digest
        or binding.retention_mode != archive.retention_mode
        or binding.retain_until != archive.retain_until
        or binding.occurred_at != receipt.observed_at
    ):
        return "cloud_signer_binding_invalid"
    identity_payload: dict[str, Any] = {
        "algorithm": policy.algorithm,
        "archive_checksum_sha256": archive.provider_checksum_sha256,
        "archive_digest": archive.payload_digest,
        "archive_object_key": archive.object_key,
        "archive_record_digest": archive.digest,
        "archive_version_id": archive.provider_version_id,
        "domain": policy.domain,
        "key_id": policy.key_id,
        "occurred_at": receipt.observed_at,
        "purpose": policy.purpose,
        "receipt_digest": receipt.digest,
        "repository": policy.repository,
        "retention_mode": archive.retention_mode,
        "retain_until": archive.retain_until,
        "schema_version": 1,
    }
    expected_request_digest = hashlib.sha256(canonical_json_bytes(identity_payload)).hexdigest()
    if binding.signer_request_digest != expected_request_digest:
        return "cloud_signer_binding_invalid"
    payload = canonical_json_bytes(
        {
            "protected_binding": binding.to_canonical_dict(),
            "receipt": receipt.to_canonical_dict(),
        }
    )
    try:
        signature = base64.b64decode(signed.signature_base64, validate=True)
    except (ValueError, binascii.Error):
        return "cloud_signer_signature_invalid"
    if len(signature) != 64:
        return "cloud_signer_signature_invalid"
    try:
        policy.public_key.verify(signature, payload)
    except InvalidSignature:
        return "cloud_signer_signature_invalid"
    return None
