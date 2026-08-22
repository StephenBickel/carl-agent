from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_execution import CloudRunRequest, SignedCommissioningReceipt
from carl_bench.cloud_observer import (
    CloudArtifactMetadata,
    CloudObserver,
    CloudObserverError,
    CloudRunMetadata,
)
from carl_bench.cloud_signer import CloudReceiptSigner, KmsSignResult, ProtectedSigningPolicy
from carl_bench.evidence_archive import EvidenceArchive, ImmutableObject

NOW = datetime(2026, 8, 22, 12, 5, tzinfo=UTC)
DISPATCHED = datetime(2026, 8, 22, 12, tzinfo=UTC)
REPOSITORY = "StephenBickel/carl-agent"


def request() -> CloudRunRequest:
    return CloudRunRequest.create(
        repository=REPOSITORY,
        workflow_file="autonomous-improvement.yml",
        experiment_digest="1" * 64,
        parent_commit="2" * 40,
        candidate_commit="3" * 40,
        task_set_digest="4" * 64,
        metric_pack_digest="5" * 64,
        policy_digest="6" * 64,
        workflow_revision="7" * 40,
        workflow_blob_digest="8" * 64,
    )


def evidence_payload(cloud_request: CloudRunRequest) -> bytes:
    return canonical_json_bytes(
        {
            "attempt_key": cloud_request.attempt_key(1),
            "candidate_commit": cloud_request.candidate_commit,
            "conclusion": "success",
            "experiment_digest": cloud_request.experiment_digest,
            "metric_pack_digest": cloud_request.metric_pack_digest,
            "parent_commit": cloud_request.parent_commit,
            "policy_digest": cloud_request.policy_digest,
            "repository": cloud_request.repository,
            "request_digest": cloud_request.request_digest,
            "run_attempt": 1,
            "run_id": 42,
            "schema_version": 1,
            "task_set_digest": cloud_request.task_set_digest,
        }
    )


def run_metadata(cloud_request: CloudRunRequest) -> CloudRunMetadata:
    return CloudRunMetadata(
        repository=cloud_request.repository,
        run_id=42,
        workflow_file=cloud_request.workflow_file,
        workflow_path=cloud_request.expected_workflow_path,
        workflow_revision=cloud_request.workflow_revision,
        workflow_blob_digest=cloud_request.workflow_blob_digest,
        event="workflow_dispatch",
        request_digest=cloud_request.request_digest,
        dispatch_key=cloud_request.dispatch_key,
        attempt_key=cloud_request.attempt_key(1),
        run_attempt=1,
        head_sha=cloud_request.candidate_commit,
        head_ref=f"refs/heads/experimental/{cloud_request.experiment_digest}",
        parent_commit=cloud_request.parent_commit,
        candidate_commit=cloud_request.candidate_commit,
        status="completed",
        conclusion="success",
        created_at="2026-08-22T12:00:05Z",
        completed_at="2026-08-22T12:04:00Z",
    )


class FakeGitHub:
    def __init__(self, cloud_request: CloudRunRequest) -> None:
        self.run = run_metadata(cloud_request)
        self.payload = evidence_payload(cloud_request)
        self.artifacts = (
            CloudArtifactMetadata(
                artifact_id=99,
                run_id=42,
                name=cloud_request.expected_artifact_name,
                digest=hashlib.sha256(self.payload).hexdigest(),
                size_in_bytes=len(self.payload),
                expired=False,
                expires_at="2026-08-23T12:00:00Z",
            ),
        )
        self.downloads = 0

    def observe_run(self, request_digest: str, attempt_key: str) -> CloudRunMetadata:
        return self.run

    def list_run_artifacts(self, run_id: int) -> tuple[CloudArtifactMetadata, ...]:
        return self.artifacts

    def download_run_artifact(self, run_id: int, artifact_id: int) -> bytes:
        self.downloads += 1
        return self.payload


class Store:
    def __init__(self) -> None:
        self.objects = {}
        self.archived = False

    def create_immutable(self, key, payload, metadata):
        digest = hashlib.sha256(payload).hexdigest()
        result = ImmutableObject(
            key,
            "v1",
            '"etag"',
            digest,
            len(payload),
            "COMPLIANCE",
            "2027-08-22T12:00:00Z",
            hashlib.sha256(canonical_json_bytes(metadata)).hexdigest(),
            "2026-08-22T12:05:00Z",
        )
        self.objects[key] = (payload, metadata, result)
        self.archived = True
        return result

    def head_immutable(self, key):
        return self.objects.get(key, (None, None, None))[2]


class Kms:
    def __init__(self, key, store: Store) -> None:
        self.key = key
        self.store = store
        self.calls = 0

    def sign_cloud_evidence(self, request):
        assert self.store.archived
        self.calls += 1
        return KmsSignResult(
            request.request_digest,
            request.key_id,
            request.algorithm,
            request.payload_digest,
            self.key.sign(request.payload),
        )

    def reconcile_cloud_signature(self, request_digest):
        return None


def observer(cloud_request: CloudRunRequest):
    github = FakeGitHub(cloud_request)
    store = Store()
    key = Ed25519PrivateKey.generate()
    policy = ProtectedSigningPolicy(
        repository=REPOSITORY,
        key_id="observer-kms-v1",
        algorithm="ED25519_SHA_512",
        purpose="commissioning-receipt",
        domain="carl-autonomy/cloud-evidence/v1",
        public_key_pem=key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
    )
    value = CloudObserver._for_testing(
        github=github,
        archive=EvidenceArchive._for_testing(store=store, clock=lambda: NOW),
        signer=CloudReceiptSigner._for_testing(kms=Kms(key, store), policy=policy),
        clock=lambda: NOW,
    )
    return value, github, store


def test_observer_independently_downloads_archives_then_signs_exact_evidence() -> None:
    cloud_request = request()
    value, github, store = observer(cloud_request)

    result = value.observe_success(cloud_request, attempt=1, dispatched_at=DISPATCHED)

    assert isinstance(result.signed_receipt, SignedCommissioningReceipt)
    assert result.signed_receipt.receipt.request_digest == cloud_request.request_digest
    assert (
        result.signed_receipt.receipt.artifact_digest == hashlib.sha256(github.payload).hexdigest()
    )
    assert result.archive.payload_digest == result.signed_receipt.receipt.artifact_digest
    assert store.archived
    assert github.downloads == 1


@pytest.mark.parametrize(
    "field,value",
    (
        ("repository", "other/repo"),
        ("workflow_path", ".github/workflows/other.yml"),
        ("workflow_revision", "9" * 40),
        ("workflow_blob_digest", "9" * 64),
        ("event", "push"),
        ("request_digest", "9" * 64),
        ("dispatch_key", "wrong"),
        ("attempt_key", "wrong"),
        ("run_attempt", 2),
        ("head_sha", "9" * 40),
        ("parent_commit", "9" * 40),
        ("status", "in_progress"),
        ("conclusion", "failure"),
        ("created_at", "2026-08-22T11:59:59Z"),
    ),
)
def test_observer_rejects_every_mismatched_run_identity(field: str, value: object) -> None:
    cloud_request = request()
    value_observer, github, _ = observer(cloud_request)
    github.run = replace(github.run, **{field: value})
    with pytest.raises(CloudObserverError):
        value_observer.observe_success(cloud_request, attempt=1, dispatched_at=DISPATCHED)
    assert github.downloads == 0


@pytest.mark.parametrize(
    "defect", ("expired", "wrong_name", "wrong_run", "wrong_digest", "oversized", "duplicate")
)
def test_observer_rejects_artifact_identity_expiry_bounds_and_duplicates(defect: str) -> None:
    cloud_request = request()
    value, github, _ = observer(cloud_request)
    item = github.artifacts[0]
    if defect == "expired":
        github.artifacts = (replace(item, expired=True),)
    elif defect == "wrong_name":
        github.artifacts = (replace(item, name="other"),)
    elif defect == "wrong_run":
        github.artifacts = (replace(item, run_id=43),)
    elif defect == "wrong_digest":
        github.artifacts = (replace(item, digest="9" * 64),)
    elif defect == "oversized":
        github.artifacts = (replace(item, size_in_bytes=8_388_609),)
    else:
        github.artifacts = (item, replace(item, artifact_id=100))
    with pytest.raises(CloudObserverError):
        value.observe_success(cloud_request, attempt=1, dispatched_at=DISPATCHED)


def test_observer_hashes_and_parses_the_same_single_downloaded_bytes() -> None:
    cloud_request = request()
    value, github, _ = observer(cloud_request)
    github.payload = b'{"schema_version":1,"schema_version":1}'
    github.artifacts = (
        replace(
            github.artifacts[0],
            digest=hashlib.sha256(github.payload).hexdigest(),
            size_in_bytes=len(github.payload),
        ),
    )
    with pytest.raises(CloudObserverError, match="cloud_evidence_duplicate_json_key"):
        value.observe_success(cloud_request, attempt=1, dispatched_at=DISPATCHED)
    assert github.downloads == 1


def test_observer_rejects_workflow_claimed_signature_and_synthetic_receipt_fields() -> None:
    cloud_request = request()
    value, github, _ = observer(cloud_request)
    decoded = __import__("json").loads(github.payload)
    decoded["signature"] = "workflow-self-signed"
    github.payload = canonical_json_bytes(decoded)
    github.artifacts = (
        replace(
            github.artifacts[0],
            digest=hashlib.sha256(github.payload).hexdigest(),
            size_in_bytes=len(github.payload),
        ),
    )
    with pytest.raises(CloudObserverError):
        value.observe_success(cloud_request, attempt=1, dispatched_at=DISPATCHED)
