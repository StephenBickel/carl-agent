"""Typed, content-addressed evidence for one protected promotion run."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from carl_bench.artifacts import ArtifactIntegrityError, ArtifactRef, PrivateArtifactStore
from carl_bench.canonical import canonical_json_bytes
from carl_bench.capability_validation import CapabilityValidationReport
from carl_bench.commissioning import CommissioningArtifactError
from carl_bench.promotion import (
    PromotionContractError,
    PromotionExpectation,
    ProtectedValidationReceipt,
    SignedProtectedValidation,
    verify_protected_validation,
)

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_REVIEW_ROLES = ("build", "proposal", "security")


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise CommissioningArtifactError(code)
    return value


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise CommissioningArtifactError(code)
    return value


def _object(value: object, code: str) -> str:
    if not isinstance(value, str) or _OBJECT_RE.fullmatch(value) is None:
        raise CommissioningArtifactError(code)
    return value


def _sandbox_kind() -> str:
    if sys.platform == "darwin":
        return "macos_sandbox_exec"
    if sys.platform.startswith("linux"):
        return "linux_network_namespace"
    return "unsupported"


@dataclass(frozen=True, slots=True)
class ProtectedVerifierConfig:
    """Owner-pinned verifier policy; it is never supplied by a run bundle."""

    schema_version: int
    key_id: str
    public_key_pem: bytes
    policy_digest: str
    model: str
    effort: str
    repository_tests_command: tuple[str, ...]
    cost_per_millisecond_microdollars: int
    reviewer_ids: tuple[tuple[str, str], ...]
    network_sandbox_kind: str = ""

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CommissioningArtifactError("invalid_protected_verifier_config")
        _identifier(self.key_id, "invalid_protected_verifier_key_id")
        _digest(self.policy_digest, "invalid_protected_verifier_policy")
        _identifier(self.model, "invalid_protected_verifier_model")
        _identifier(self.effort, "invalid_protected_verifier_effort")
        if (
            not isinstance(self.public_key_pem, bytes)
            or not self.public_key_pem
            or len(self.public_key_pem) > 16_384
        ):
            raise CommissioningArtifactError("invalid_protected_verifier_public_key")
        try:
            key = serialization.load_pem_public_key(self.public_key_pem)
        except (TypeError, ValueError) as error:
            raise CommissioningArtifactError("invalid_protected_verifier_public_key") from error
        if not isinstance(key, Ed25519PublicKey):
            raise CommissioningArtifactError("invalid_protected_verifier_public_key")
        if (
            not isinstance(self.repository_tests_command, tuple)
            or not self.repository_tests_command
            or any(
                not isinstance(item, str) or not item or "\0" in item
                for item in self.repository_tests_command
            )
        ):
            raise CommissioningArtifactError("invalid_protected_repository_test_command")
        if (
            isinstance(self.cost_per_millisecond_microdollars, bool)
            or not isinstance(self.cost_per_millisecond_microdollars, int)
            or self.cost_per_millisecond_microdollars < 0
        ):
            raise CommissioningArtifactError("invalid_protected_cost_rate")
        if (
            not isinstance(self.reviewer_ids, tuple)
            or tuple(role for role, _ in self.reviewer_ids) != _REVIEW_ROLES
            or any(
                _identifier(reviewer, "invalid_protected_reviewer") != reviewer
                for _, reviewer in self.reviewer_ids
            )
            or len({reviewer for _, reviewer in self.reviewer_ids}) != len(self.reviewer_ids)
        ):
            raise CommissioningArtifactError("invalid_protected_reviewers")
        expected_sandbox = _sandbox_kind()
        if not self.network_sandbox_kind:
            object.__setattr__(self, "network_sandbox_kind", expected_sandbox)
        if self.network_sandbox_kind != expected_sandbox or expected_sandbox == "unsupported":
            raise CommissioningArtifactError("invalid_protected_network_sandbox")


@dataclass(frozen=True, slots=True)
class ProtectedCommandResult:
    schema_version: int
    run_kind: str
    baseline_commit: str
    candidate_commit: str
    candidate_tree: str
    command: tuple[str, ...]
    exit_code: int
    elapsed_ms: int
    stdout_ref: ArtifactRef
    stderr_ref: ArtifactRef

    def __post_init__(self) -> None:
        if self.schema_version != 1 or self.run_kind not in {
            "deterministic_checks",
            "full_repository_tests",
        }:
            raise CommissioningArtifactError("invalid_protected_command_result")
        _object(self.baseline_commit, "invalid_protected_command_identity")
        _object(self.candidate_commit, "invalid_protected_command_identity")
        _object(self.candidate_tree, "invalid_protected_command_identity")
        if (
            not isinstance(self.command, tuple)
            or not self.command
            or any(not isinstance(item, str) or not item or "\0" in item for item in self.command)
            or isinstance(self.exit_code, bool)
            or not isinstance(self.exit_code, int)
            or not 0 <= self.exit_code <= 255
            or isinstance(self.elapsed_ms, bool)
            or not isinstance(self.elapsed_ms, int)
            or not 0 <= self.elapsed_ms <= 86_400_000
            or not isinstance(self.stdout_ref, ArtifactRef)
            or not isinstance(self.stderr_ref, ArtifactRef)
        ):
            raise CommissioningArtifactError("invalid_protected_command_result")
        if (
            self.stdout_ref.evidence_kind != "protected_command_stdout"
            or self.stdout_ref.media_type != "application/octet-stream"
            or self.stderr_ref.evidence_kind != "protected_command_stderr"
            or self.stderr_ref.media_type != "application/octet-stream"
        ):
            raise CommissioningArtifactError("invalid_protected_command_result")

    @property
    def passed(self) -> bool:
        return self.exit_code == 0

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "baseline_commit": self.baseline_commit,
            "candidate_commit": self.candidate_commit,
            "candidate_tree": self.candidate_tree,
            "command": list(self.command),
            "elapsed_ms": self.elapsed_ms,
            "exit_code": self.exit_code,
            "run_kind": self.run_kind,
            "schema_version": self.schema_version,
            "stderr_ref": self.stderr_ref.to_canonical_dict(),
            "stdout_ref": self.stdout_ref.to_canonical_dict(),
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> ProtectedCommandResult:
        expected = {
            "baseline_commit",
            "candidate_commit",
            "candidate_tree",
            "command",
            "elapsed_ms",
            "exit_code",
            "run_kind",
            "schema_version",
            "stderr_ref",
            "stdout_ref",
        }
        if (
            not isinstance(value, dict)
            or set(value) != expected
            or not isinstance(value.get("command"), list)
        ):
            raise CommissioningArtifactError("invalid_protected_command_result")
        normalized = dict(value)
        normalized["command"] = tuple(value["command"])
        try:
            normalized["stdout_ref"] = ArtifactRef.from_canonical_dict(value["stdout_ref"])
            normalized["stderr_ref"] = ArtifactRef.from_canonical_dict(value["stderr_ref"])
            return cls(**normalized)
        except (ArtifactIntegrityError, TypeError) as error:
            raise CommissioningArtifactError("invalid_protected_command_result") from error


@dataclass(frozen=True, slots=True)
class ProtectedRunEvidence:
    receipt: ProtectedValidationReceipt
    manifest_ref: ArtifactRef
    artifact_refs: tuple[tuple[str, ArtifactRef], ...]


@dataclass(frozen=True, slots=True)
class VerifiedProtectedRun:
    receipt: ProtectedValidationReceipt
    artifact_refs: tuple[tuple[str, ArtifactRef], ...]


def _put_json(
    artifacts: PrivateArtifactStore,
    *,
    evidence_kind: str,
    value: dict[str, Any],
) -> ArtifactRef:
    return artifacts.put(
        evidence_kind=evidence_kind,
        media_type="application/json",
        content=canonical_json_bytes(value),
    )


def _read_json(
    artifacts: PrivateArtifactStore,
    ref: ArtifactRef,
    *,
    evidence_kind: str,
    expected: set[str],
    code: str,
) -> dict[str, Any]:
    if (
        not isinstance(ref, ArtifactRef)
        or ref.evidence_kind != evidence_kind
        or ref.media_type != "application/json"
    ):
        raise CommissioningArtifactError(code)
    try:
        value = json.loads(artifacts.read(ref))
    except (ArtifactIntegrityError, UnicodeError, json.JSONDecodeError) as error:
        raise CommissioningArtifactError(code) from error
    if not isinstance(value, dict) or set(value) != expected:
        raise CommissioningArtifactError(code)
    return value


def _artifact_ref(value: Any, kind: str, media_type: str, code: str) -> ArtifactRef:
    try:
        ref = ArtifactRef.from_canonical_dict(value)
    except (ArtifactIntegrityError, TypeError) as error:
        raise CommissioningArtifactError(code) from error
    if ref.evidence_kind != kind or ref.media_type != media_type:
        raise CommissioningArtifactError(code)
    return ref


def _score_values(
    report: CapabilityValidationReport,
    task_roles: tuple[tuple[str, str], ...],
) -> dict[str, int | bool]:
    before = {item.task_id: item for item in report.baseline_outcomes}
    after = {item.task_id: item for item in report.candidate_outcomes}
    if set(before) != set(after) or set(before) != {task for task, _ in task_roles}:
        raise CommissioningArtifactError("protected_holdout_identity_mismatch")
    deltas = {
        task: after[task].score_basis_points - before[task].score_basis_points for task in before
    }
    non_guard = [deltas[task] for task, role in task_roles if role != "guard"]
    guards = [deltas[task] for task, role in task_roles if role == "guard"]
    held_out = [after[task].score_basis_points for task, role in task_roles if role == "held_out"]
    if not non_guard or not guards or not held_out:
        raise CommissioningArtifactError("protected_holdout_identity_mismatch")
    invalid = sum(len(item.invalid_trials) for item in report.candidate_outcomes)
    return {
        "guard_delta_basis_points": min(guards),
        "holdout_aggregate_basis_points": sum(held_out) // len(held_out),
        "holdout_leakage_detected": "active_evaluator_modified" in report.reasons,
        "invalid_run_count": invalid,
        "paired_confidence_lower_basis_points": min(non_guard),
        "paired_score_delta_basis_points": sum(deltas.values()) // len(deltas),
    }


def persist_protected_run(
    *,
    artifacts: PrivateArtifactStore,
    verifier_config: ProtectedVerifierConfig,
    experiment_id: str,
    manifest_digest: str,
    validation_id: str,
    baseline_commit: str,
    candidate_commit: str,
    candidate_tree: str,
    evidence_bundle_ref: ArtifactRef,
    evaluator_ref: ArtifactRef,
    capability_report: CapabilityValidationReport,
    task_roles: tuple[tuple[str, str], ...],
    changed_paths: tuple[str, ...],
    executable_bytes: bytes,
    subject_path: str,
    deterministic_result: ProtectedCommandResult,
    repository_result: ProtectedCommandResult,
    created_at: str,
    expires_at: str,
) -> ProtectedRunEvidence:
    """Build typed artifacts first, then derive the only signable receipt from them."""
    _identifier(experiment_id, "invalid_protected_run_experiment")
    _digest(manifest_digest, "invalid_protected_run_manifest")
    _identifier(validation_id, "invalid_protected_run_validation")
    _object(baseline_commit, "invalid_protected_run_identity")
    _object(candidate_commit, "invalid_protected_run_identity")
    _object(candidate_tree, "invalid_protected_run_identity")
    if not capability_report.eligible:
        raise CommissioningArtifactError("protected_run_capability_ineligible")
    if deterministic_result.run_kind != "deterministic_checks" or (
        repository_result.run_kind != "full_repository_tests"
    ):
        raise CommissioningArtifactError("invalid_protected_command_result")

    executable_ref = artifacts.put(
        evidence_kind="protected_executable",
        media_type="application/octet-stream",
        content=executable_bytes,
    )
    adapter_ref = _put_json(
        artifacts,
        evidence_kind="protected_adapter",
        value={
            "executable_ref": executable_ref.to_canonical_dict(),
            "invocation": ["python", subject_path],
            "stdin_format": "canonical_json_line",
            "schema_version": 1,
        },
    )
    metric_pack_ref = _put_json(
        artifacts,
        evidence_kind="protected_metric_pack",
        value={
            "algorithm": "capability_validation_v1",
            "score_scale": "basis_points",
            "schema_version": 1,
        },
    )
    environment_ref = _put_json(
        artifacts,
        evidence_kind="protected_environment",
        value={
            "network": "deny_all",
            "python_implementation": sys.implementation.name,
            "sandbox": verifier_config.network_sandbox_kind,
            "schema_version": 1,
        },
    )
    deterministic_ref = _put_json(
        artifacts,
        evidence_kind="protected_deterministic_checks",
        value=deterministic_result.to_canonical_dict(),
    )
    repository_ref = _put_json(
        artifacts,
        evidence_kind="protected_repository_tests",
        value=repository_result.to_canonical_dict(),
    )

    try:
        evidence_bundle = json.loads(artifacts.read(evidence_bundle_ref))
    except (ArtifactIntegrityError, UnicodeError, json.JSONDecodeError) as error:
        raise CommissioningArtifactError("invalid_protected_evidence_bundle") from error
    if not isinstance(evidence_bundle, dict):
        raise CommissioningArtifactError("invalid_protected_evidence_bundle")
    changed_paths_ref = _artifact_ref(
        evidence_bundle.get("changed_paths_ref"),
        "git_changed_paths",
        "application/json",
        "invalid_protected_changed_paths_ref",
    )
    workflow_value = {
        "candidate_commit": candidate_commit,
        "changed_paths_ref": changed_paths_ref.to_canonical_dict(),
        "deterministic_checks_ref": deterministic_ref.to_canonical_dict(),
        "passed": deterministic_result.passed
        and not any(path.startswith(".github/workflows/") for path in changed_paths),
        "schema_version": 1,
    }
    workflow_ref = _put_json(
        artifacts,
        evidence_kind="protected_workflow_gate",
        value=workflow_value,
    )
    score_values = _score_values(capability_report, task_roles)
    safety_value = {
        "candidate_commit": candidate_commit,
        "guards_non_inferior": capability_report.guards_non_inferior,
        "invalid_run_count": score_values["invalid_run_count"],
        "passed": capability_report.guards_non_inferior and score_values["invalid_run_count"] == 0,
        "schema_version": 1,
    }
    safety_ref = _put_json(
        artifacts,
        evidence_kind="protected_safety_gate",
        value=safety_value,
    )
    holdout_value = {
        "candidate_commit": candidate_commit,
        "capability_report_digest": capability_report.digest,
        **score_values,
        "schema_version": 1,
        "transfer_gain_basis_points": capability_report.transfer_gain_basis_points,
    }
    holdout_ref = _put_json(
        artifacts,
        evidence_kind="protected_holdout_stats",
        value=holdout_value,
    )
    latency_ms = deterministic_result.elapsed_ms + repository_result.elapsed_ms
    cost_value = {
        "cost_microdollars": latency_ms * verifier_config.cost_per_millisecond_microdollars,
        "latency_ms": latency_ms,
        "rate_microdollars_per_ms": verifier_config.cost_per_millisecond_microdollars,
        "run_refs": [
            deterministic_ref.to_canonical_dict(),
            repository_ref.to_canonical_dict(),
        ],
        "schema_version": 1,
    }
    cost_ref = _put_json(
        artifacts,
        evidence_kind="protected_cost_latency",
        value=cost_value,
    )

    reviewer_ids = dict(verifier_config.reviewer_ids)
    review_inputs = {
        "proposal": (evidence_bundle_ref, holdout_ref),
        "build": (deterministic_ref, repository_ref),
        "security": (workflow_ref, safety_ref),
    }
    review_refs: dict[str, ArtifactRef] = {}
    for role in ("proposal", "build", "security"):
        evidence_refs = review_inputs[role]
        if role == "proposal":
            approved = capability_report.eligible
        elif role == "build":
            approved = deterministic_result.passed and repository_result.passed
        else:
            approved = workflow_value["passed"] and safety_value["passed"]
        review_refs[role] = _put_json(
            artifacts,
            evidence_kind=f"protected_{role}_review",
            value={
                "candidate_commit": candidate_commit,
                "evidence_refs": [ref.to_canonical_dict() for ref in evidence_refs],
                "reviewer_id": reviewer_ids[role],
                "role": role,
                "schema_version": 1,
                "verdict": "approve" if approved else "reject",
            },
        )

    decision = (
        "pass"
        if all(
            (
                deterministic_result.passed,
                repository_result.passed,
                workflow_value["passed"],
                safety_value["passed"],
                not score_values["holdout_leakage_detected"],
            )
        )
        else "fail"
    )
    manifest_value = {
        "adapter_ref": adapter_ref.to_canonical_dict(),
        "candidate_commit": candidate_commit,
        "candidate_tree": candidate_tree,
        "capability_evidence_bundle_ref": evidence_bundle_ref.to_canonical_dict(),
        "cost_latency_ref": cost_ref.to_canonical_dict(),
        "created_at": created_at,
        "deterministic_checks_ref": deterministic_ref.to_canonical_dict(),
        "effort": verifier_config.effort,
        "environment_ref": environment_ref.to_canonical_dict(),
        "executable_ref": executable_ref.to_canonical_dict(),
        "experiment_id": experiment_id,
        "expires_at": expires_at,
        "full_repository_tests_ref": repository_ref.to_canonical_dict(),
        "holdout_stats_ref": holdout_ref.to_canonical_dict(),
        "manifest_digest": manifest_digest,
        "metric_pack_ref": metric_pack_ref.to_canonical_dict(),
        "model": verifier_config.model,
        "parent_commit": baseline_commit,
        "policy_digest": verifier_config.policy_digest,
        "proposal_review_ref": review_refs["proposal"].to_canonical_dict(),
        "build_review_ref": review_refs["build"].to_canonical_dict(),
        "safety_gate_ref": safety_ref.to_canonical_dict(),
        "schema_version": 1,
        "security_review_ref": review_refs["security"].to_canonical_dict(),
        "task_set_ref": evaluator_ref.to_canonical_dict(),
        "validation_id": validation_id,
        "workflow_gate_ref": workflow_ref.to_canonical_dict(),
    }
    manifest_ref = _put_json(
        artifacts,
        evidence_kind="protected_run_manifest",
        value=manifest_value,
    )
    receipt = ProtectedValidationReceipt(
        schema_version=3,
        validation_id=validation_id,
        experiment_id=experiment_id,
        manifest_digest=manifest_digest,
        policy_digest=verifier_config.policy_digest,
        parent_commit=baseline_commit,
        candidate_commit=candidate_commit,
        candidate_tree=candidate_tree,
        executable_digest=executable_ref.digest,
        adapter_digest=adapter_ref.digest,
        task_set_digest=evaluator_ref.digest,
        metric_pack_digest=metric_pack_ref.digest,
        environment_digest=environment_ref.digest,
        model=verifier_config.model,
        effort=verifier_config.effort,
        deterministic_checks_digest=deterministic_ref.digest,
        repository_tests_digest=repository_ref.digest,
        paired_score_delta_basis_points=int(score_values["paired_score_delta_basis_points"]),
        paired_confidence_lower_basis_points=int(
            score_values["paired_confidence_lower_basis_points"]
        ),
        guard_delta_basis_points=int(score_values["guard_delta_basis_points"]),
        workflow_passed=bool(workflow_value["passed"]),
        safety_passed=bool(safety_value["passed"]),
        flake_rate_basis_points=0,
        invalid_run_count=int(score_values["invalid_run_count"]),
        cost_microdollars=cost_value["cost_microdollars"],
        latency_ms=cost_value["latency_ms"],
        holdout_aggregate_basis_points=int(score_values["holdout_aggregate_basis_points"]),
        holdout_leakage_detected=bool(score_values["holdout_leakage_detected"]),
        proposal_review_digest=review_refs["proposal"].digest,
        build_review_digest=review_refs["build"].digest,
        security_review_digest=review_refs["security"].digest,
        created_at=created_at,
        expires_at=expires_at,
        decision=decision,
        capability_report_digest=capability_report.digest,
        transfer_gain_basis_points=capability_report.transfer_gain_basis_points,
        protected_run_manifest_digest=manifest_ref.digest,
    )
    named = {
        "adapter": adapter_ref,
        "build_review": review_refs["build"],
        "cost_latency": cost_ref,
        "deterministic_checks": deterministic_ref,
        "environment": environment_ref,
        "executable": executable_ref,
        "full_repository_tests": repository_ref,
        "holdout_stats": holdout_ref,
        "metric_pack": metric_pack_ref,
        "proposal_review": review_refs["proposal"],
        "protected_run_manifest": manifest_ref,
        "safety_gate": safety_ref,
        "security_review": review_refs["security"],
        "workflow_gate": workflow_ref,
    }
    return ProtectedRunEvidence(receipt, manifest_ref, tuple(sorted(named.items())))


def _git_blob(repository: Path, commit: str, path: str) -> bytes:
    try:
        return subprocess.run(
            ("git", "-C", os.fspath(repository), "show", f"{commit}:{path}"),
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise CommissioningArtifactError("protected_run_git_identity_invalid") from error


def verify_protected_run(
    *,
    artifacts: PrivateArtifactStore,
    source_repository: Path,
    evidence_bundle_ref: ArtifactRef,
    manifest_ref: ArtifactRef,
    envelope: SignedProtectedValidation,
    verifier_config: ProtectedVerifierConfig,
) -> VerifiedProtectedRun:
    """Resolve the complete graph, recompute receipt fields, then verify its signer."""
    from carl_bench.commissioning_runner import (
        ProtectedEvaluator,
        verify_protected_pair_evaluation,
    )

    if envelope.key_id != verifier_config.key_id:
        raise CommissioningArtifactError("protected_run_signer_mismatch")
    verified_pair = verify_protected_pair_evaluation(
        artifacts=artifacts,
        evidence_bundle_ref=evidence_bundle_ref,
        source_repository=source_repository,
    )
    pair_refs = dict(verified_pair.artifact_refs)
    evaluator_ref = pair_refs["protected_evaluator"]
    evaluator = ProtectedEvaluator.from_bytes(artifacts.read(evaluator_ref))
    manifest_keys = {
        "adapter_ref",
        "build_review_ref",
        "candidate_commit",
        "candidate_tree",
        "capability_evidence_bundle_ref",
        "cost_latency_ref",
        "created_at",
        "deterministic_checks_ref",
        "effort",
        "environment_ref",
        "executable_ref",
        "experiment_id",
        "expires_at",
        "full_repository_tests_ref",
        "holdout_stats_ref",
        "manifest_digest",
        "metric_pack_ref",
        "model",
        "parent_commit",
        "policy_digest",
        "proposal_review_ref",
        "safety_gate_ref",
        "schema_version",
        "security_review_ref",
        "task_set_ref",
        "validation_id",
        "workflow_gate_ref",
    }
    manifest = _read_json(
        artifacts,
        manifest_ref,
        evidence_kind="protected_run_manifest",
        expected=manifest_keys,
        code="protected_run_manifest_invalid",
    )
    if manifest["schema_version"] != 1:
        raise CommissioningArtifactError("protected_run_manifest_invalid")
    if (
        manifest["candidate_commit"] != verified_pair.candidate_commit
        or manifest["candidate_tree"] != verified_pair.candidate_tree
        or manifest["parent_commit"] != verified_pair.baseline_commit
        or manifest["capability_evidence_bundle_ref"] != evidence_bundle_ref.to_canonical_dict()
        or manifest["policy_digest"] != verifier_config.policy_digest
        or manifest["model"] != verifier_config.model
        or manifest["effort"] != verifier_config.effort
    ):
        raise CommissioningArtifactError("protected_run_manifest_identity_mismatch")

    specs = {
        "adapter": ("adapter_ref", "protected_adapter", "application/json"),
        "build_review": ("build_review_ref", "protected_build_review", "application/json"),
        "cost_latency": ("cost_latency_ref", "protected_cost_latency", "application/json"),
        "deterministic_checks": (
            "deterministic_checks_ref",
            "protected_deterministic_checks",
            "application/json",
        ),
        "environment": ("environment_ref", "protected_environment", "application/json"),
        "executable": (
            "executable_ref",
            "protected_executable",
            "application/octet-stream",
        ),
        "full_repository_tests": (
            "full_repository_tests_ref",
            "protected_repository_tests",
            "application/json",
        ),
        "holdout_stats": (
            "holdout_stats_ref",
            "protected_holdout_stats",
            "application/json",
        ),
        "metric_pack": ("metric_pack_ref", "protected_metric_pack", "application/json"),
        "proposal_review": (
            "proposal_review_ref",
            "protected_proposal_review",
            "application/json",
        ),
        "safety_gate": ("safety_gate_ref", "protected_safety_gate", "application/json"),
        "security_review": (
            "security_review_ref",
            "protected_security_review",
            "application/json",
        ),
        "workflow_gate": (
            "workflow_gate_ref",
            "protected_workflow_gate",
            "application/json",
        ),
    }
    refs = {
        name: _artifact_ref(manifest[field], kind, media, "protected_run_artifact_invalid")
        for name, (field, kind, media) in specs.items()
    }
    refs["protected_run_manifest"] = manifest_ref
    task_set_ref = _artifact_ref(
        manifest["task_set_ref"],
        "protected_evaluator",
        "application/json",
        "protected_run_task_set_invalid",
    )
    if task_set_ref != evaluator_ref:
        raise CommissioningArtifactError("protected_run_task_set_invalid")

    subject_bytes = _git_blob(
        source_repository,
        verified_pair.candidate_commit,
        evaluator.subject_path,
    )
    if artifacts.read(refs["executable"]) != subject_bytes:
        raise CommissioningArtifactError("protected_run_executable_mismatch")
    expected_adapter = {
        "executable_ref": refs["executable"].to_canonical_dict(),
        "invocation": ["python", evaluator.subject_path],
        "stdin_format": "canonical_json_line",
        "schema_version": 1,
    }
    expected_metric = {
        "algorithm": "capability_validation_v1",
        "score_scale": "basis_points",
        "schema_version": 1,
    }
    expected_environment = {
        "network": "deny_all",
        "python_implementation": sys.implementation.name,
        "sandbox": verifier_config.network_sandbox_kind,
        "schema_version": 1,
    }
    for name, expected in (
        ("adapter", expected_adapter),
        ("metric_pack", expected_metric),
        ("environment", expected_environment),
    ):
        if json.loads(artifacts.read(refs[name])) != expected:
            raise CommissioningArtifactError("protected_run_identity_artifact_mismatch")

    deterministic = ProtectedCommandResult.from_canonical_dict(
        json.loads(artifacts.read(refs["deterministic_checks"]))
    )
    repository_tests = ProtectedCommandResult.from_canonical_dict(
        json.loads(artifacts.read(refs["full_repository_tests"]))
    )
    expected_deterministic_command = (
        "git",
        "diff",
        "--check",
        verified_pair.baseline_commit,
        verified_pair.candidate_commit,
        "--",
    )
    for result, expected_kind, expected_command in (
        (deterministic, "deterministic_checks", expected_deterministic_command),
        (
            repository_tests,
            "full_repository_tests",
            verifier_config.repository_tests_command,
        ),
    ):
        if (
            result.run_kind != expected_kind
            or result.command != expected_command
            or result.baseline_commit != verified_pair.baseline_commit
            or result.candidate_commit != verified_pair.candidate_commit
            or result.candidate_tree != verified_pair.candidate_tree
        ):
            raise CommissioningArtifactError("protected_run_command_identity_mismatch")
        artifacts.read(result.stdout_ref)
        artifacts.read(result.stderr_ref)
    try:
        deterministic_replay = subprocess.run(
            (
                "git",
                "-C",
                os.fspath(source_repository),
                "diff",
                "--check",
                verified_pair.baseline_commit,
                verified_pair.candidate_commit,
                "--",
            ),
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CommissioningArtifactError("protected_run_deterministic_replay_failed") from error
    if (
        deterministic_replay.returncode != deterministic.exit_code
        or artifacts.read(deterministic.stdout_ref) != deterministic_replay.stdout
        or artifacts.read(deterministic.stderr_ref) != deterministic_replay.stderr
    ):
        raise CommissioningArtifactError("protected_run_deterministic_replay_mismatch")

    changed_paths_ref = pair_refs["git_changed_paths"]
    workflow = {
        "candidate_commit": verified_pair.candidate_commit,
        "changed_paths_ref": changed_paths_ref.to_canonical_dict(),
        "deterministic_checks_ref": refs["deterministic_checks"].to_canonical_dict(),
        "passed": deterministic.passed
        and not any(path.startswith(".github/workflows/") for path in verified_pair.changed_paths),
        "schema_version": 1,
    }
    score_values = _score_values(
        verified_pair.report,
        tuple((task.task_id, task.role) for task in evaluator.tasks),
    )
    safety = {
        "candidate_commit": verified_pair.candidate_commit,
        "guards_non_inferior": verified_pair.report.guards_non_inferior,
        "invalid_run_count": score_values["invalid_run_count"],
        "passed": verified_pair.report.guards_non_inferior
        and score_values["invalid_run_count"] == 0,
        "schema_version": 1,
    }
    holdout = {
        "candidate_commit": verified_pair.candidate_commit,
        "capability_report_digest": verified_pair.report.digest,
        **score_values,
        "schema_version": 1,
        "transfer_gain_basis_points": verified_pair.report.transfer_gain_basis_points,
    }
    latency_ms = deterministic.elapsed_ms + repository_tests.elapsed_ms
    cost = {
        "cost_microdollars": latency_ms * verifier_config.cost_per_millisecond_microdollars,
        "latency_ms": latency_ms,
        "rate_microdollars_per_ms": verifier_config.cost_per_millisecond_microdollars,
        "run_refs": [
            refs["deterministic_checks"].to_canonical_dict(),
            refs["full_repository_tests"].to_canonical_dict(),
        ],
        "schema_version": 1,
    }
    expected_json = {
        "workflow_gate": workflow,
        "safety_gate": safety,
        "holdout_stats": holdout,
        "cost_latency": cost,
    }
    for name, expected in expected_json.items():
        if json.loads(artifacts.read(refs[name])) != expected:
            raise CommissioningArtifactError("protected_run_derived_artifact_mismatch")

    reviewer_ids = dict(verifier_config.reviewer_ids)
    review_inputs = {
        "proposal": (evidence_bundle_ref, refs["holdout_stats"]),
        "build": (refs["deterministic_checks"], refs["full_repository_tests"]),
        "security": (refs["workflow_gate"], refs["safety_gate"]),
    }
    for role in ("proposal", "build", "security"):
        approved = {
            "proposal": verified_pair.report.eligible,
            "build": deterministic.passed and repository_tests.passed,
            "security": workflow["passed"] and safety["passed"],
        }[role]
        expected_review = {
            "candidate_commit": verified_pair.candidate_commit,
            "evidence_refs": [ref.to_canonical_dict() for ref in review_inputs[role]],
            "reviewer_id": reviewer_ids[role],
            "role": role,
            "schema_version": 1,
            "verdict": "approve" if approved else "reject",
        }
        if json.loads(artifacts.read(refs[f"{role}_review"])) != expected_review:
            raise CommissioningArtifactError("protected_run_review_mismatch")

    expected_receipt = ProtectedValidationReceipt(
        schema_version=3,
        validation_id=manifest["validation_id"],
        experiment_id=manifest["experiment_id"],
        manifest_digest=manifest["manifest_digest"],
        policy_digest=verifier_config.policy_digest,
        parent_commit=verified_pair.baseline_commit,
        candidate_commit=verified_pair.candidate_commit,
        candidate_tree=verified_pair.candidate_tree,
        executable_digest=refs["executable"].digest,
        adapter_digest=refs["adapter"].digest,
        task_set_digest=evaluator_ref.digest,
        metric_pack_digest=refs["metric_pack"].digest,
        environment_digest=refs["environment"].digest,
        model=verifier_config.model,
        effort=verifier_config.effort,
        deterministic_checks_digest=refs["deterministic_checks"].digest,
        repository_tests_digest=refs["full_repository_tests"].digest,
        paired_score_delta_basis_points=int(score_values["paired_score_delta_basis_points"]),
        paired_confidence_lower_basis_points=int(
            score_values["paired_confidence_lower_basis_points"]
        ),
        guard_delta_basis_points=int(score_values["guard_delta_basis_points"]),
        workflow_passed=bool(workflow["passed"]),
        safety_passed=bool(safety["passed"]),
        flake_rate_basis_points=0,
        invalid_run_count=int(score_values["invalid_run_count"]),
        cost_microdollars=cost["cost_microdollars"],
        latency_ms=cost["latency_ms"],
        holdout_aggregate_basis_points=int(score_values["holdout_aggregate_basis_points"]),
        holdout_leakage_detected=bool(score_values["holdout_leakage_detected"]),
        proposal_review_digest=refs["proposal_review"].digest,
        build_review_digest=refs["build_review"].digest,
        security_review_digest=refs["security_review"].digest,
        created_at=manifest["created_at"],
        expires_at=manifest["expires_at"],
        decision=(
            "pass"
            if all(
                (
                    deterministic.passed,
                    repository_tests.passed,
                    workflow["passed"],
                    safety["passed"],
                    not score_values["holdout_leakage_detected"],
                )
            )
            else "fail"
        ),
        capability_report_digest=verified_pair.report.digest,
        transfer_gain_basis_points=verified_pair.report.transfer_gain_basis_points,
        protected_run_manifest_digest=manifest_ref.digest,
    )
    if envelope.receipt != expected_receipt:
        raise CommissioningArtifactError("protected_run_receipt_mismatch")
    expectation = PromotionExpectation(
        experiment_id=manifest["experiment_id"],
        manifest_digest=manifest["manifest_digest"],
        policy_digest=verifier_config.policy_digest,
        parent_commit=verified_pair.baseline_commit,
        candidate_commit=verified_pair.candidate_commit,
        candidate_tree=verified_pair.candidate_tree,
        executable_digest=refs["executable"].digest,
        adapter_digest=refs["adapter"].digest,
        task_set_digest=evaluator_ref.digest,
        metric_pack_digest=refs["metric_pack"].digest,
        model=verifier_config.model,
        effort=verifier_config.effort,
        environment_digest=refs["environment"].digest,
        capability_report_digest=verified_pair.report.digest,
        transfer_gain_basis_points=verified_pair.report.transfer_gain_basis_points,
        capability_claim_type=verified_pair.report.claim_type,
        affected_contract_cases_improved=(verified_pair.report.affected_contract_cases_improved),
        capability_guards_non_inferior=verified_pair.report.guards_non_inferior,
        protected_run_manifest_digest=manifest_ref.digest,
    )
    try:
        verify_protected_validation(
            envelope,
            public_key_pem=verifier_config.public_key_pem,
            expected=expectation,
            now=__import__("datetime").datetime.fromisoformat(
                manifest["created_at"].replace("Z", "+00:00")
            ),
            changed_paths=verified_pair.changed_paths,
        )
    except PromotionContractError as error:
        code = (
            "protected_run_signature_invalid"
            if error.code == "protected_signature_invalid"
            else "protected_run_receipt_invalid"
        )
        raise CommissioningArtifactError(code) from error
    return VerifiedProtectedRun(expected_receipt, tuple(sorted(refs.items())))
