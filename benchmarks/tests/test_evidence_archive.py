from __future__ import annotations

import base64
import hashlib
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_execution import CommissioningReceipt
from carl_bench.cloud_signer import (
    CloudReceiptSigner,
    KmsSignResult,
    ProtectedSigningPolicy,
    SignResponseLost,
    verify_protected_receipt,
)
from carl_bench.evidence_archive import (
    ArchiveIdentity,
    ArchiveResponseLost,
    EvidenceArchive,
    EvidenceArchiveError,
    ImmutableObject,
)

NOW = datetime(2026, 8, 22, 12, tzinfo=UTC)
DIGEST = "a" * 64
REPOSITORY = "StephenBickel/carl-agent"
ARCHIVE_PAYLOAD = b'{"schema_version":1}'
ARCHIVE_DIGEST = hashlib.sha256(ARCHIVE_PAYLOAD).hexdigest()


class FakeStore:
    def __init__(self) -> None:
        self.objects: dict[str, tuple[bytes, dict[str, str], ImmutableObject]] = {}
        self.create_calls = 0
        self.head_calls = 0
        self.lose_response = False

    def create_immutable(
        self, key: str, payload: bytes, metadata: dict[str, str]
    ) -> ImmutableObject:
        self.create_calls += 1
        digest = hashlib.sha256(payload).hexdigest()
        record = ImmutableObject(
            object_key=key,
            version_id="v-0001",
            etag='"immutable-etag"',
            checksum_sha256=digest,
            byte_length=len(payload),
            retention_mode="COMPLIANCE",
            retain_until="2027-08-22T12:00:00Z",
            metadata_digest=hashlib.sha256(canonical_json_bytes(metadata)).hexdigest(),
            created_at="2026-08-22T12:00:00Z",
        )
        previous = self.objects.get(key)
        if previous is not None and previous[:2] != (payload, metadata):
            raise EvidenceArchiveError("evidence_archive_conflict")
        if previous is not None:
            return previous[2]
        self.objects[key] = (payload, dict(metadata), record)
        if self.lose_response:
            self.lose_response = False
            raise ArchiveResponseLost
        return record

    def head_immutable(self, key: str) -> ImmutableObject | None:
        self.head_calls += 1
        current = self.objects.get(key)
        return None if current is None else current[2]


def identity() -> ArchiveIdentity:
    return ArchiveIdentity(
        repository=REPOSITORY,
        request_digest=DIGEST,
        run_id=42,
        artifact_id=99,
        artifact_name=f"autonomous-improvement-evidence-{DIGEST}",
        media_type="application/vnd.carl.improvement-evidence+json;version=1",
        schema_version=1,
    )


def test_archive_is_content_addressed_immutable_and_reconciles_lost_response() -> None:
    store = FakeStore()
    store.lose_response = True
    archive = EvidenceArchive._for_testing(store=store, clock=lambda: NOW)
    payload = ARCHIVE_PAYLOAD

    record = archive.archive(identity(), payload)

    digest = hashlib.sha256(payload).hexdigest()
    assert record.object_key == f"carl-evidence/v1/sha256/{digest[:2]}/{digest}"
    assert record.payload_digest == digest
    assert record.provider_version_id == "v-0001"
    assert record.provider_checksum_sha256 == digest
    assert record.retention_mode == "COMPLIANCE"
    assert record.byte_length == len(payload)
    assert store.create_calls == 1
    assert store.head_calls == 1
    assert store.objects[record.object_key][0] is payload
    assert store.objects[record.object_key][1]["request_digest"] == DIGEST


def test_archive_replay_preserves_original_provider_occurrence_time() -> None:
    current = [NOW]
    store = FakeStore()
    archive = EvidenceArchive._for_testing(store=store, clock=lambda: current[0])
    first = archive.archive(identity(), ARCHIVE_PAYLOAD)
    current[0] = datetime(2026, 8, 23, 12, tzinfo=UTC)
    replay = archive.archive(identity(), ARCHIVE_PAYLOAD)
    assert replay == first
    assert replay.archived_at == "2026-08-22T12:00:00Z"


def test_archive_rejects_conflicting_provider_identity_and_never_overwrites() -> None:
    store = FakeStore()
    archive = EvidenceArchive._for_testing(store=store, clock=lambda: NOW)
    payload = ARCHIVE_PAYLOAD
    first = archive.archive(identity(), payload)
    key = first.object_key
    stored_payload, metadata, provider = store.objects[key]

    mutations = (
        replace(provider, version_id=""),
        replace(provider, checksum_sha256="b" * 64),
        replace(provider, byte_length=provider.byte_length + 1),
        replace(provider, retention_mode="GOVERNANCE"),
        replace(provider, retain_until="2026-08-22T11:59:59Z"),
        replace(provider, object_key=key + "-wrong"),
        replace(provider, metadata_digest="b" * 64),
        replace(provider, created_at="2026-08-22T12:00:01Z"),
    )
    for poisoned in mutations:
        store.objects[key] = (stored_payload, metadata, poisoned)
        with pytest.raises(EvidenceArchiveError):
            archive.archive(identity(), payload)
        store.objects[key] = (stored_payload, metadata, provider)
    assert store.objects[key][0] == payload


def test_archive_rejects_unbounded_or_invalid_caller_selected_identity() -> None:
    archive = EvidenceArchive._for_testing(store=FakeStore(), clock=lambda: NOW)
    with pytest.raises(EvidenceArchiveError):
        archive.archive(replace(identity(), repository="other/repo"), b"x" * 8_388_609)
    with pytest.raises(EvidenceArchiveError):
        replace(identity(), media_type="application/octet-stream")


class FakeKms:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self.private_key = private_key
        self.requests = []
        self.results = {}
        self.lose_response = False

    def sign_cloud_evidence(self, request):
        self.requests.append(request)
        result = KmsSignResult(
            request_digest=request.request_digest,
            key_id=request.key_id,
            algorithm=request.algorithm,
            payload_digest=request.payload_digest,
            signature=self.private_key.sign(request.payload),
        )
        self.results[request.request_digest] = result
        if self.lose_response:
            self.lose_response = False
            raise SignResponseLost
        return result

    def reconcile_cloud_signature(self, request_digest: str):
        return self.results.get(request_digest)


def receipt() -> CommissioningReceipt:
    return CommissioningReceipt(
        schema_version=2,
        repository=REPOSITORY,
        workflow_file="autonomous-improvement.yml",
        workflow_path=".github/workflows/autonomous-improvement.yml",
        workflow_revision="1" * 40,
        workflow_blob_digest="2" * 64,
        request_digest=DIGEST,
        experiment_digest="3" * 64,
        task_set_digest="4" * 64,
        metric_pack_digest="5" * 64,
        policy_digest="6" * 64,
        run_id=42,
        status="completed",
        conclusion="success",
        observed_at="2026-08-22T12:00:00Z",
        artifact_id=99,
        artifact_name=f"autonomous-improvement-evidence-{DIGEST}",
        artifact_digest=ARCHIVE_DIGEST,
    )


def signing_policy(private_key: Ed25519PrivateKey) -> ProtectedSigningPolicy:
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return ProtectedSigningPolicy(
        repository=REPOSITORY,
        key_id="carl-observer-kms-v1",
        algorithm="ED25519_SHA_512",
        purpose="commissioning-receipt",
        domain="carl-autonomy/cloud-evidence/v1",
        public_key_pem=public_pem,
    )


def test_signer_binds_archive_and_exact_receipt_and_reconciles_lost_response() -> None:
    private = Ed25519PrivateKey.generate()
    kms = FakeKms(private)
    kms.lose_response = True
    policy = signing_policy(private)
    archive = EvidenceArchive._for_testing(store=FakeStore(), clock=lambda: NOW).archive(
        identity(), ARCHIVE_PAYLOAD
    )
    signer = CloudReceiptSigner._for_testing(kms=kms, policy=policy)

    signed = signer.sign_commissioning_receipt(receipt(), archive)

    request = kms.requests[0]
    assert request.repository == REPOSITORY
    assert request.purpose == policy.purpose
    assert request.domain == policy.domain
    assert request.archive_object_key == archive.object_key
    assert request.archive_version_id == archive.provider_version_id
    assert request.archive_digest == archive.payload_digest
    assert request.occurred_at == receipt().observed_at
    assert request.payload_digest == hashlib.sha256(request.payload).hexdigest()
    assert receipt().digest.encode() not in request.payload
    assert b'"receipt"' in request.payload
    assert verify_protected_receipt(signed, policy, archive) is None
    assert signer.sign_commissioning_receipt(receipt(), archive) == signed


@pytest.mark.parametrize(
    "field,value",
    (("algorithm", "RSA_PSS_SHA_256"), ("purpose", "other"), ("domain", "other/domain")),
)
def test_signer_rejects_invalid_protected_policy(field: str, value: str) -> None:
    private = Ed25519PrivateKey.generate()
    good = signing_policy(private)
    with pytest.raises(ValueError):
        replace(good, **{field: value})


def test_signer_rejects_cross_repository_and_verifier_rejects_wrong_key_id() -> None:
    private = Ed25519PrivateKey.generate()
    policy = signing_policy(private)
    archive = EvidenceArchive._for_testing(store=FakeStore(), clock=lambda: NOW).archive(
        identity(), ARCHIVE_PAYLOAD
    )
    signer = CloudReceiptSigner._for_testing(kms=FakeKms(private), policy=policy)
    with pytest.raises(ValueError):
        CloudReceiptSigner._for_testing(
            kms=FakeKms(private), policy=replace(policy, repository="other/repo")
        ).sign_commissioning_receipt(receipt(), archive)
    signed = signer.sign_commissioning_receipt(receipt(), archive)
    assert verify_protected_receipt(signed, replace(policy, key_id="wrong"), archive) is not None


def test_verifier_rejects_mutation_wrong_archive_and_malformed_signature() -> None:
    private = Ed25519PrivateKey.generate()
    policy = signing_policy(private)
    archive = EvidenceArchive._for_testing(store=FakeStore(), clock=lambda: NOW).archive(
        identity(), ARCHIVE_PAYLOAD
    )
    signer = CloudReceiptSigner._for_testing(kms=FakeKms(private), policy=policy)
    signed = signer.sign_commissioning_receipt(receipt(), archive)
    other_archive = replace(archive, provider_version_id="v-0002")
    assert verify_protected_receipt(signed, policy, other_archive) is not None
    changed_media = replace(
        archive,
        identity=replace(
            archive.identity,
            media_type="application/vnd.carl.soak-observation+json;version=1",
        ),
    )
    assert verify_protected_receipt(signed, policy, changed_media) is not None
    malformed = replace(signed, signature_base64=base64.b64encode(b"x" * 64).decode())
    assert verify_protected_receipt(malformed, policy, archive) is not None
