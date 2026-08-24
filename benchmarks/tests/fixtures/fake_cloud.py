from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_execution import (
    CloudRunRequest,
    SignedCommissioningReceipt,
    TrustedCloudReceiptKey,
)
from carl_bench.cloud_observer import (
    CloudArtifactMetadata,
    CloudObserver,
    CloudRunMetadata,
    TrustedCloudEvidence,
)
from carl_bench.cloud_signer import (
    CloudReceiptSigner,
    KmsSignRequest,
    KmsSignResult,
    ProtectedSigningPolicy,
)
from carl_bench.evidence_archive import (
    EvidenceArchive,
    ImmutableObject,
)
from carl_bench.github_promotion import APPROVED_REQUIRED_CHECKS
from carl_bench.live_commissioning import (
    AcceptedSoak,
    DispatchNotFound,
    DispatchResponseLost,
    ExactRevert,
    ImmutableExperimentalPublication,
    IndependentDisposition,
    LiveCommissioningError,
    LiveCommissioningPlan,
    ProtectedPromotion,
    RemoteRunIdentity,
)

_NOW = datetime(2026, 8, 21, 12, 10, tzinfo=UTC)
_PRIVATE_KEY_BYTES = bytes.fromhex(
    "7d28a77ad84679b8a43f68c016a52ad74bd03b98d9282f87cdd45a2ff0913a64"
)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _effect_digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class StatefulFakeCloud:
    """Persistent fake provider implementing the protected commissioning surfaces."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write(
                {
                    "dispatch_network_attempts": 0,
                    "effect_counts": {},
                    "effects": {},
                    "lost_dispatch_responses": 0,
                    "main": None,
                    "objects": {},
                    "operations": [],
                    "plan": None,
                    "pull_requests": {},
                    "refs": {},
                    "runs": {},
                    "schema_version": 1,
                    "signatures": {},
                }
            )

    @property
    def _private_key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(_PRIVATE_KEY_BYTES)

    @property
    def trusted_receipt_key(self) -> TrustedCloudReceiptKey:
        return TrustedCloudReceiptKey(
            key_id="fake-cloud-kms-v1",
            public_key_pem=self._private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )

    def observer(self) -> CloudObserver:
        policy = ProtectedSigningPolicy(
            repository="StephenBickel/carl-agent",
            key_id="fake-cloud-kms-v1",
            algorithm="ED25519_SHA_512",
            purpose="commissioning-receipt",
            domain="carl-autonomy/cloud-evidence/v1",
            public_key_pem=self.trusted_receipt_key.public_key_pem,
        )
        return CloudObserver._for_testing(
            github=self,
            archive=EvidenceArchive._for_testing(store=self, clock=lambda: _NOW),
            signer=CloudReceiptSigner._for_testing(kms=self, policy=policy),
            clock=lambda: _NOW,
        )

    def _load(self) -> dict[str, Any]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, value: dict[str, Any]) -> None:
        payload = canonical_json_bytes(value) + b"\n"
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.path.parent, prefix=".fake-cloud-", delete=False
            ) as target:
                temporary = target.name
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.path)
            temporary = None
        finally:
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)

    def snapshot(self) -> dict[str, Any]:
        return self._load()

    def bind_plan(self, plan: LiveCommissioningPlan) -> None:
        state = self._load()
        encoded = plan.to_canonical_dict()
        if state["plan"] is not None and state["plan"] != encoded:
            raise LiveCommissioningError("fake_cloud_plan_conflict")
        if state["plan"] is None:
            state["plan"] = encoded
            state["main"] = {
                "commit": plan.request.parent_commit,
                "tree": plan.baseline_tree,
            }
            self._write(state)

    def _record_effect(
        self,
        *,
        key: str,
        operation: str,
        request: dict[str, Any],
        result: dict[str, Any],
    ) -> tuple[dict[str, Any], bool]:
        state = self._load()
        request_digest = _effect_digest(request)
        existing = state["effects"].get(key)
        if existing is not None:
            if existing["request_digest"] != request_digest:
                raise LiveCommissioningError("fake_cloud_effect_conflict")
            return existing["result"], False
        state["effects"][key] = {
            "request_digest": request_digest,
            "result": result,
        }
        state["effect_counts"][operation] = state["effect_counts"].get(operation, 0) + 1
        state["operations"].append(operation)
        self._write(state)
        return result, True

    def dispatch_validation(self, request: CloudRunRequest, *, attempt: int) -> RemoteRunIdentity:
        state = self._load()
        state["dispatch_network_attempts"] += 1
        self._write(state)
        run_id = 901
        payload = canonical_json_bytes(
            {
                "attempt_key": request.attempt_key(attempt),
                "candidate_commit": request.candidate_commit,
                "conclusion": "success",
                "experiment_digest": request.experiment_digest,
                "metric_pack_digest": request.metric_pack_digest,
                "parent_commit": request.parent_commit,
                "policy_digest": request.policy_digest,
                "repository": request.repository,
                "request_digest": request.request_digest,
                "run_attempt": attempt,
                "run_id": run_id,
                "schema_version": 1,
                "task_set_digest": request.task_set_digest,
            }
        )
        artifact_digest = hashlib.sha256(payload).hexdigest()
        result = RemoteRunIdentity(
            run_id=run_id,
            attempt_key=request.attempt_key(attempt),
            artifact_id=801,
            artifact_name=request.expected_artifact_name,
            artifact_digest=artifact_digest,
            artifact_byte_length=len(payload),
        )
        _, created = self._record_effect(
            key=request.attempt_key(attempt),
            operation="workflow_dispatch",
            request=request.to_canonical_dict(),
            result=result.to_canonical_dict(),
        )
        state = self._load()
        state["runs"][str(run_id)] = {
            "artifact_base64": base64.b64encode(payload).decode("ascii"),
            "request": request.to_canonical_dict(),
            "result": result.to_canonical_dict(),
        }
        if created:
            state["lost_dispatch_responses"] += 1
            self._write(state)
            raise DispatchResponseLost("fake_cloud_dispatch_response_lost")
        self._write(state)
        return result

    def reconcile_validation_dispatch(
        self, request: CloudRunRequest, *, attempt: int
    ) -> RemoteRunIdentity:
        state = self._load()
        effect = state["effects"].get(request.attempt_key(attempt))
        if effect is None:
            raise DispatchNotFound("fake_cloud_dispatch_not_found")
        return RemoteRunIdentity.from_canonical_dict(effect["result"])

    def observe_run(self, request_digest: str, attempt_key: str) -> CloudRunMetadata:
        state = self._load()
        matching = [
            value
            for value in state["runs"].values()
            if value["request"]["request_digest"] == request_digest
            and value["result"]["attempt_key"] == attempt_key
        ]
        if len(matching) != 1:
            raise LiveCommissioningError("fake_cloud_run_not_found")
        value = matching[0]
        request = CloudRunRequest.from_canonical_dict(value["request"])
        run = RemoteRunIdentity.from_canonical_dict(value["result"])
        return CloudRunMetadata(
            repository=request.repository,
            run_id=run.run_id,
            workflow_file=request.workflow_file,
            workflow_path=request.expected_workflow_path,
            workflow_revision=request.workflow_revision,
            workflow_blob_digest=request.workflow_blob_digest,
            event="workflow_dispatch",
            request_digest=request.request_digest,
            dispatch_key=request.dispatch_key,
            attempt_key=run.attempt_key,
            run_attempt=1,
            head_sha=request.candidate_commit,
            head_ref=f"refs/heads/experimental/{request.experiment_digest}",
            parent_commit=request.parent_commit,
            candidate_commit=request.candidate_commit,
            status="completed",
            conclusion="success",
            created_at="2026-08-21T12:00:02Z",
            completed_at="2026-08-21T12:05:00Z",
        )

    def list_run_artifacts(self, run_id: int) -> tuple[CloudArtifactMetadata, ...]:
        value = self._load()["runs"].get(str(run_id))
        if value is None:
            raise LiveCommissioningError("fake_cloud_run_not_found")
        run = RemoteRunIdentity.from_canonical_dict(value["result"])
        return (
            CloudArtifactMetadata(
                artifact_id=run.artifact_id,
                run_id=run_id,
                name=run.artifact_name,
                size_in_bytes=run.artifact_byte_length,
                digest=run.artifact_digest,
                expired=False,
                expires_at="2026-08-22T12:10:00Z",
            ),
        )

    def download_run_artifact(self, run_id: int, artifact_id: int) -> bytes:
        value = self._load()["runs"].get(str(run_id))
        if value is None or value["result"]["artifact_id"] != artifact_id:
            raise LiveCommissioningError("fake_cloud_artifact_not_found")
        return base64.b64decode(value["artifact_base64"], validate=True)

    def create_immutable(
        self, key: str, payload: bytes, metadata: dict[str, str]
    ) -> ImmutableObject:
        digest = hashlib.sha256(payload).hexdigest()
        result = {
            "byte_length": len(payload),
            "checksum_sha256": digest,
            "created_at": "2026-08-21T12:05:01Z",
            "etag": f'"{digest}"',
            "metadata_digest": hashlib.sha256(canonical_json_bytes(metadata)).hexdigest(),
            "object_key": key,
            "retain_until": "2027-08-21T12:05:01Z",
            "retention_mode": "COMPLIANCE",
            "version_id": f"version-{digest[:24]}",
        }
        stored, _ = self._record_effect(
            key=f"archive:{key}",
            operation="archive_evidence",
            request={"key": key, "metadata": metadata, "payload_digest": digest},
            result=result,
        )
        state = self._load()
        state["objects"][key] = stored
        self._write(state)
        return ImmutableObject(**stored)

    def head_immutable(self, key: str) -> ImmutableObject | None:
        value = self._load()["objects"].get(key)
        return None if value is None else ImmutableObject(**value)

    def sign_cloud_evidence(self, request: KmsSignRequest) -> KmsSignResult:
        signature = self._private_key.sign(request.payload)
        result = {
            "algorithm": request.algorithm,
            "key_id": request.key_id,
            "payload_digest": request.payload_digest,
            "request_digest": request.request_digest,
            "signature_base64": base64.b64encode(signature).decode("ascii"),
        }
        stored, _ = self._record_effect(
            key=f"signature:{request.request_digest}",
            operation="sign_evidence",
            request={
                "archive_digest": request.archive_digest,
                "payload_digest": request.payload_digest,
                "request_digest": request.request_digest,
            },
            result=result,
        )
        state = self._load()
        state["signatures"][request.request_digest] = stored
        self._write(state)
        return KmsSignResult(
            request_digest=stored["request_digest"],
            key_id=stored["key_id"],
            algorithm=stored["algorithm"],
            payload_digest=stored["payload_digest"],
            signature=base64.b64decode(stored["signature_base64"], validate=True),
        )

    def reconcile_cloud_signature(self, request_digest: str) -> KmsSignResult | None:
        value = self._load()["signatures"].get(request_digest)
        if value is None:
            return None
        return KmsSignResult(
            request_digest=value["request_digest"],
            key_id=value["key_id"],
            algorithm=value["algorithm"],
            payload_digest=value["payload_digest"],
            signature=base64.b64decode(value["signature_base64"], validate=True),
        )

    def ingest_trusted_evidence(self, evidence: TrustedCloudEvidence) -> str:
        if not isinstance(evidence.signed_receipt, SignedCommissioningReceipt):
            raise LiveCommissioningError("fake_cloud_signed_evidence_required")
        result = {"receipt_digest": evidence.signed_receipt.receipt_digest}
        stored, _ = self._record_effect(
            key=f"ingest:{evidence.signed_receipt.receipt_digest}",
            operation="ingest_trusted_evidence",
            request=evidence.signed_receipt.to_canonical_dict(),
            result=result,
        )
        return str(stored["receipt_digest"])

    def publish_experimental(
        self, *, experiment_id: str, candidate_commit: str, candidate_tree: str
    ) -> ImmutableExperimentalPublication:
        ref = f"refs/heads/experimental/{experiment_id}"
        result = ImmutableExperimentalPublication(ref, candidate_commit, candidate_tree)
        stored, _ = self._record_effect(
            key=f"publish:{experiment_id}",
            operation="publish_experimental",
            request={
                "candidate_commit": candidate_commit,
                "candidate_tree": candidate_tree,
                "experiment_id": experiment_id,
            },
            result=result.to_canonical_dict(),
        )
        state = self._load()
        existing = state["refs"].get(ref)
        if existing not in {None, candidate_commit}:
            raise LiveCommissioningError("fake_cloud_experimental_ref_conflict")
        state["refs"][ref] = candidate_commit
        self._write(state)
        return ImmutableExperimentalPublication.from_canonical_dict(stored)

    def record_disposition(
        self,
        *,
        publication: ImmutableExperimentalPublication,
        signed_receipt_digest: str,
    ) -> IndependentDisposition:
        digest = _effect_digest(
            {
                "candidate_commit": publication.commit,
                "candidate_tree": publication.tree,
                "signed_receipt_digest": signed_receipt_digest,
            }
        )
        result = IndependentDisposition(
            disposition="production_candidate",
            candidate_commit=publication.commit,
            candidate_tree=publication.tree,
            signed_receipt_digest=signed_receipt_digest,
            disposition_digest=digest,
        )
        stored, _ = self._record_effect(
            key=f"disposition:{publication.ref}",
            operation="record_disposition",
            request={
                "publication": publication.to_canonical_dict(),
                "signed_receipt_digest": signed_receipt_digest,
            },
            result=result.to_canonical_dict(),
        )
        return IndependentDisposition.from_canonical_dict(stored)

    def promote(
        self,
        *,
        promotion_id: str,
        publication: ImmutableExperimentalPublication,
        disposition: IndependentDisposition,
        merged_at: str,
    ) -> ProtectedPromotion:
        if disposition.candidate_commit != publication.commit:
            raise LiveCommissioningError("fake_cloud_disposition_identity_mismatch")
        pr_number = 81
        self._record_effect(
            key=f"promotion-pr:{promotion_id}",
            operation="open_promotion_pr",
            request={"promotion_id": promotion_id, "publication": publication.to_canonical_dict()},
            result={"number": pr_number},
        )
        self._record_effect(
            key=f"promotion-checks:{promotion_id}",
            operation="record_promotion_checks",
            request={"number": pr_number, "required_checks": list(APPROVED_REQUIRED_CHECKS)},
            result={"complete": True},
        )
        self._record_effect(
            key=f"promotion-auto-merge:{promotion_id}",
            operation="enable_promotion_auto_merge",
            request={"number": pr_number, "head_commit": publication.commit},
            result={"enabled": True},
        )
        merge_commit = hashlib.sha1(f"merge:{promotion_id}".encode()).hexdigest()
        result = ProtectedPromotion(
            promotion_id=promotion_id,
            pull_request_number=pr_number,
            head_commit=publication.commit,
            head_tree=publication.tree,
            required_checks=APPROVED_REQUIRED_CHECKS,
            auto_merge_enabled=True,
            merge_commit=merge_commit,
            merge_tree=publication.tree,
            merged_at=merged_at,
        )
        stored, _ = self._record_effect(
            key=f"promotion-merge:{promotion_id}",
            operation="merge_promotion",
            request={
                "disposition_digest": disposition.disposition_digest,
                "head_commit": publication.commit,
                "number": pr_number,
            },
            result=result.to_canonical_dict(),
        )
        state = self._load()
        state["main"] = {"commit": merge_commit, "tree": publication.tree}
        self._write(state)
        return ProtectedPromotion.from_canonical_dict(stored)

    def accept_soak(self, *, promotion: ProtectedPromotion, accepted_at: str) -> AcceptedSoak:
        observed = AcceptedSoak.create(promotion=promotion, accepted_at=accepted_at)
        stored, _ = self._record_effect(
            key=f"soak-observe:{promotion.promotion_id}",
            operation="observe_soak",
            request={
                "merge_commit": promotion.merge_commit,
                "observed_at": accepted_at,
            },
            result=observed.to_canonical_dict(),
        )
        self._record_effect(
            key=f"soak-accept:{promotion.promotion_id}",
            operation="accept_soak",
            request=stored,
            result={"accepted": True},
        )
        return AcceptedSoak.from_canonical_dict(stored)

    def hard_regression_and_exact_revert(
        self,
        *,
        plan: LiveCommissioningPlan,
        accepted: AcceptedSoak,
    ) -> ExactRevert:
        hard_merge_commit = hashlib.sha1(
            f"hard-merge:{plan.hard_regression_promotion_id}".encode()
        ).hexdigest()
        self._record_effect(
            key=f"hard-merge:{plan.hard_regression_promotion_id}",
            operation="hard_regression_merge",
            request={
                "candidate_commit": plan.hard_regression_commit,
                "candidate_tree": plan.hard_regression_tree,
                "prior_accepted_merge": accepted.merge_commit,
            },
            result={"merge_commit": hard_merge_commit, "merge_tree": plan.hard_regression_tree},
        )
        state = self._load()
        state["main"] = {"commit": hard_merge_commit, "tree": plan.hard_regression_tree}
        self._write(state)
        hard_failure_digest = _effect_digest(
            {
                "healthy": False,
                "merge_commit": hard_merge_commit,
                "observed_at": plan.hard_failure_observed_at,
            }
        )
        self._record_effect(
            key=f"hard-observation:{hard_merge_commit}",
            operation="observe_hard_regression",
            request={
                "merge_commit": hard_merge_commit,
                "observed_at": plan.hard_failure_observed_at,
            },
            result={"evidence_digest": hard_failure_digest, "healthy": False},
        )
        revert_pr = 82
        self._record_effect(
            key=f"revert-pr:{hard_merge_commit}",
            operation="open_revert_pr",
            request={
                "expected_restored_tree": plan.accepted_production_tree,
                "hard_failure_digest": hard_failure_digest,
                "promotion_merge_commit": hard_merge_commit,
                "revert_candidate_commit": plan.exact_revert_commit,
            },
            result={"number": revert_pr},
        )
        self._record_effect(
            key=f"revert-checks:{hard_merge_commit}",
            operation="record_revert_checks",
            request={"number": revert_pr, "required_checks": list(APPROVED_REQUIRED_CHECKS)},
            result={"complete": True},
        )
        self._record_effect(
            key=f"revert-auto-merge:{hard_merge_commit}",
            operation="enable_revert_auto_merge",
            request={"head_commit": plan.exact_revert_commit, "number": revert_pr},
            result={"enabled": True},
        )
        revert_merge_commit = hashlib.sha1(f"revert:{hard_merge_commit}".encode()).hexdigest()
        result = ExactRevert(
            hard_failure_merge_commit=hard_merge_commit,
            hard_failure_digest=hard_failure_digest,
            revert_pull_request_number=revert_pr,
            revert_candidate_commit=plan.exact_revert_commit,
            required_checks=APPROVED_REQUIRED_CHECKS,
            auto_merge_enabled=True,
            revert_started_at=plan.hard_failure_observed_at,
            revert_merge_commit=revert_merge_commit,
            restored_tree=plan.accepted_production_tree,
            reverted_at=plan.revert_observed_at,
        )
        stored, _ = self._record_effect(
            key=f"revert-merge:{hard_merge_commit}",
            operation="merge_revert",
            request={
                "expected_restored_tree": plan.accepted_production_tree,
                "head_commit": plan.exact_revert_commit,
                "number": revert_pr,
            },
            result=result.to_canonical_dict(),
        )
        state = self._load()
        state["main"] = {"commit": revert_merge_commit, "tree": plan.accepted_production_tree}
        self._write(state)
        return ExactRevert.from_canonical_dict(stored)
