from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_experiment import manifest as base_manifest

from carl_bench.artifacts import PrivateArtifactStore
from carl_bench.autonomy import (
    AutonomyProjection,
    ExperimentalPublication,
    PromotionRecord,
    ProtectedValidation,
    SoakObservation,
)
from carl_bench.autonomy_controller import (
    ControllerSnapshot,
    SoakResult,
    next_controller_action,
)
from carl_bench.candidate import (
    DeterministicCheckResult,
    PairedEvidence,
    PreparedCandidate,
    SealedCandidate,
)
from carl_bench.canonical import canonical_json_bytes
from carl_bench.capability_validation import (
    CapabilityClaim,
    CapabilityValidationReport,
    TaskOutcome,
    TransferCheck,
    evaluate_capability_validation,
)
from carl_bench.cloud_execution import (
    CloudArtifact,
    CloudRunRequest,
    CloudRunSnapshot,
    reconcile_cloud_run,
)
from carl_bench.commissioning import (
    CommissioningArtifactError,
    CommissioningArtifactStore,
    SyntheticCommissioningReceipt,
)
from carl_bench.experiment import (
    EventType,
    ExperimentEvent,
    ExperimentState,
    ReviewRole,
    ReviewVerdict,
)
from carl_bench.experimental_publication import (
    ExperimentalPublicationRequest,
    publish_experimental_branch,
)
from carl_bench.github_promotion import (
    APPROVED_REQUIRED_CHECKS,
    CheckRun,
    PromotionRequest,
    PromotionSnapshot,
    PullRequestSnapshot,
    RevertSnapshot,
)
from carl_bench.ledger import ExperimentLedger
from carl_bench.promotion import (
    PromotionContractError,
    PromotionExpectation,
    ProtectedValidationReceipt,
    SignedProtectedValidation,
    verify_protected_validation,
)
from carl_bench.supervisor_triggers import (
    RecoveryAttempt,
    SupervisorTrigger,
    SupervisorTriggerStore,
    TriggerResolution,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROMPT_PATH = REPOSITORY_ROOT / "docs" / "automation-prompts" / "carl-autonomous-improvement.md"
PROMPT_MANIFEST_PATH = PROMPT_PATH.with_name("carl-autonomous-improvement-live-manifest.json")
NOW = datetime(2026, 8, 19, 12, tzinfo=UTC)
EXPERIMENT_ID = "exp-commissioning-001"
POLICY_DIGEST = "9" * 64


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _git(cwd: Path, *arguments: str) -> str:
    executable = shutil.which("git")
    if executable is None:  # pragma: no cover - repository tests require Git
        pytest.skip("git executable is unavailable")
    completed = subprocess.run(
        (executable, *arguments),
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return completed.stdout.strip()


def _write_commit(repository: Path, path: str, content: str, message: str) -> str:
    destination = repository / path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding="utf-8")
    _git(repository, "add", "--", path)
    _git(repository, "commit", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


@dataclass(frozen=True, slots=True)
class DisposableGitFixture:
    root: Path
    origin: Path
    builder: Path
    baseline: str
    baseline_tree: str
    valid_candidate: str
    valid_tree: str
    benchmark_gamed_candidate: str
    evaluator_altered_candidate: str
    network_candidate: str
    hard_regression_candidate: str
    hard_regression_tree: str


@pytest.fixture
def disposable_git(tmp_path: Path) -> DisposableGitFixture:
    root = tmp_path / "disposable-git"
    root.mkdir(mode=0o700)
    origin = root / "origin.git"
    origin.mkdir()
    _git(origin, "init", "--bare")
    builder = root / "builder"
    _git(root, "clone", os.fspath(origin), os.fspath(builder))
    _git(builder, "config", "user.email", "commissioning@example.invalid")
    _git(builder, "config", "user.name", "Synthetic Commissioning")

    baseline = _write_commit(
        builder,
        "src/runtime/capability.txt",
        "baseline behavior\n",
        "baseline",
    )
    _write_commit(
        builder,
        "benchmarks/tasks/public/task.toml",
        "score = 6000\n",
        "add public evaluator fixture",
    )
    _write_commit(
        builder,
        "src/runtime/subject.py",
        """import json
import sys

request = json.load(sys.stdin)
answer = "deny" if request.get("event") == "safe_default" else "unsupported"
print(json.dumps({"answer": answer}, sort_keys=True, separators=(",", ":")))
""",
        "add baseline synthetic subject",
    )
    baseline = _git(builder, "rev-parse", "HEAD")
    baseline_tree = _git(builder, "rev-parse", "HEAD^{tree}")
    _git(builder, "branch", "-M", "main")
    _git(builder, "push", "origin", "main")
    _git(origin, "symbolic-ref", "HEAD", "refs/heads/main")

    _git(builder, "switch", "-c", "candidate-valid", baseline)
    valid_candidate = _write_commit(
        builder,
        "src/runtime/capability.txt",
        "generalized behavior with restart recovery\n",
        "improve generalized restart recovery",
    )
    valid_candidate = _write_commit(
        builder,
        "src/runtime/subject.py",
        """import json
import sys

request = json.load(sys.stdin)
answers = {
    "effect_without_receipt": "reconcile_once",
    "receipt_without_effect": "inspect_then_resume",
    "safe_default": "deny",
}
answer = answers.get(request.get("event"), "inspect_then_resume")
print(json.dumps({"answer": answer}, sort_keys=True, separators=(",", ":")))
""",
        "implement generalized recovery behavior",
    )
    valid_tree = _git(builder, "rev-parse", "HEAD^{tree}")

    _git(builder, "switch", "-c", "candidate-benchmark-gamed", baseline)
    benchmark_gamed_candidate = _write_commit(
        builder,
        "benchmarks/tasks/public/task.toml",
        "score = 10000\nfixture = 'hard-coded'\n",
        "game public benchmark",
    )

    _git(builder, "switch", "-c", "candidate-evaluator-altered", baseline)
    evaluator_altered_candidate = _write_commit(
        builder,
        "benchmarks/tasks/public/evaluator.json",
        '{"expected":"always-pass"}\n',
        "alter candidate-owned evaluator",
    )

    _git(builder, "switch", "-c", "candidate-network", baseline)
    network_candidate = _write_commit(
        builder,
        "src/runtime/subject.py",
        """import json
import socket
import sys

socket.create_connection(("127.0.0.1", 9), timeout=0.1)
print(json.dumps({"answer": json.load(sys.stdin).get("event")}))
""",
        "attempt network access during evaluation",
    )

    _git(builder, "switch", "-c", "candidate-hard-regression", baseline)
    hard_regression_candidate = _write_commit(
        builder,
        "src/runtime/capability.txt",
        "hard regression\n",
        "inject hard production regression",
    )
    hard_regression_tree = _git(builder, "rev-parse", "HEAD^{tree}")
    _git(builder, "switch", "candidate-valid")

    return DisposableGitFixture(
        root=root,
        origin=origin,
        builder=builder,
        baseline=baseline,
        baseline_tree=baseline_tree,
        valid_candidate=valid_candidate,
        valid_tree=valid_tree,
        benchmark_gamed_candidate=benchmark_gamed_candidate,
        evaluator_altered_candidate=evaluator_altered_candidate,
        network_candidate=network_candidate,
        hard_regression_candidate=hard_regression_candidate,
        hard_regression_tree=hard_regression_tree,
    )


class ProtectedRunner:
    def __init__(self, fixture: DisposableGitFixture, private_root: Path) -> None:
        self.fixture = fixture
        self.private_root = private_root
        self.private_root.mkdir(mode=0o700, parents=True)
        self.private_root.chmod(0o700)
        self.key_path = self.private_root / "protected-validator.pem"
        private_key = Ed25519PrivateKey.generate()
        self.key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.key_path.chmod(0o600)
        self.public_key_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.pull_request: PullRequestSnapshot | None = None
        self.pull_request_creations = 0
        self.merge_count = 0

    def sign(self, receipt: ProtectedValidationReceipt) -> SignedProtectedValidation:
        private_key = serialization.load_pem_private_key(
            self.key_path.read_bytes(),
            password=None,
        )
        assert isinstance(private_key, Ed25519PrivateKey)
        signature = private_key.sign(canonical_json_bytes(receipt.to_canonical_dict()))
        return SignedProtectedValidation(
            receipt=receipt,
            key_id="synthetic-protected-validator",
            signature_base64=base64.b64encode(signature).decode("ascii"),
        )

    def snapshot(self, request: PromotionRequest) -> PromotionSnapshot:
        production = _git(
            self.fixture.builder,
            "ls-remote",
            "origin",
            "refs/heads/main",
        ).split()[0]
        return PromotionSnapshot(
            production_commit=production,
            active_promotion_id=request.promotion_id,
            pull_request=self.pull_request,
        )

    def create_pull_request(self, request: PromotionRequest) -> PullRequestSnapshot:
        if self.pull_request is None:
            self.pull_request_creations += 1
            self.pull_request = PullRequestSnapshot(
                number=41,
                url="https://github.com/fixture/carl-agent/pull/41",
                state="OPEN",
                is_draft=True,
                base_branch=request.base_branch,
                head_branch=request.head_branch,
                head_commit=request.candidate_commit,
                head_tree=request.candidate_tree,
                merge_state="CLEAN",
                checks=tuple(
                    CheckRun(name=name, conclusion="SUCCESS", app_id=15368)
                    for name in APPROVED_REQUIRED_CHECKS
                ),
                merge_commit=None,
                merge_tree=None,
            )
        assert self.pull_request.head_commit == request.candidate_commit
        return self.pull_request

    def mark_ready(self) -> PullRequestSnapshot:
        assert self.pull_request is not None
        self.pull_request = replace(self.pull_request, is_draft=False)
        return self.pull_request

    def enable_auto_merge(self) -> PullRequestSnapshot:
        assert self.pull_request is not None
        self.pull_request = replace(self.pull_request, auto_merge_enabled=True)
        return self.pull_request

    def merge(self, request: PromotionRequest) -> PullRequestSnapshot:
        assert self.pull_request is not None
        if self.pull_request.state == "MERGED":
            return self.pull_request
        checkout = self.private_root / "protected-checkout"
        _git(self.private_root, "clone", os.fspath(self.fixture.origin), os.fspath(checkout))
        _git(checkout, "config", "user.email", "protected@example.invalid")
        _git(checkout, "config", "user.name", "Protected Runner")
        _git(checkout, "switch", "main")
        _git(
            checkout,
            "fetch",
            "origin",
            f"refs/heads/{request.head_branch}",
        )
        _git(checkout, "merge", "--no-ff", "--no-edit", request.candidate_commit)
        merge_commit = _git(checkout, "rev-parse", "HEAD")
        merge_tree = _git(checkout, "rev-parse", "HEAD^{tree}")
        assert merge_tree == request.candidate_tree
        _git(checkout, "push", "origin", "HEAD:refs/heads/main")
        self.merge_count += 1
        self.pull_request = replace(
            self.pull_request,
            state="MERGED",
            is_draft=False,
            auto_merge_enabled=True,
            merge_commit=merge_commit,
            merge_tree=merge_tree,
        )
        return self.pull_request


def _task_outcome(
    task_id: str,
    score_basis_points: int,
    *,
    evaluator_digest: str = "a" * 64,
) -> TaskOutcome:
    task_digests = {
        "fixture-probe-task": "1" * 64,
        "guard-task": "2" * 64,
        "held-out-task": "3" * 64,
        "primary-task": "4" * 64,
    }
    return TaskOutcome(
        task_id=task_id,
        task_digest=task_digests[task_id],
        evaluator_digest=evaluator_digest,
        score_basis_points=score_basis_points,
        valid_trials=("trial-1", "trial-2"),
        invalid_trials=("trial-invalid",),
        passed_trials=("trial-1",),
        failed_trials=("trial-2",),
    )


def _capability_claim() -> CapabilityClaim:
    return CapabilityClaim(
        claim_id="claim-commissioning-001",
        claim_type="capability",
        behavior="Carl recovers interrupted consequential effects without duplicate work.",
        affected_task_ids=("primary-task",),
        guard_task_ids=("guard-task",),
        transfer_checks=(
            TransferCheck(
                check_id="fixture-probe",
                task_id="fixture-probe-task",
                check_type="fixture_probe",
                evaluator_digest="a" * 64,
                minimum_candidate_basis_points=10_000,
            ),
            TransferCheck(
                check_id="held-out-transfer",
                task_id="held-out-task",
                check_type="held_out",
                evaluator_digest="a" * 64,
                minimum_candidate_basis_points=6_500,
            ),
        ),
    )


def _baseline_outcomes() -> tuple[TaskOutcome, ...]:
    return (
        _task_outcome("fixture-probe-task", 10_000),
        _task_outcome("guard-task", 8_000),
        _task_outcome("held-out-task", 6_000),
        _task_outcome("primary-task", 6_000),
    )


def _improved_outcomes() -> tuple[TaskOutcome, ...]:
    return (
        _task_outcome("fixture-probe-task", 10_000),
        _task_outcome("guard-task", 8_000),
        _task_outcome("held-out-task", 6_500),
        _task_outcome("primary-task", 7_000),
    )


def _candidate_packet(
    fixture: DisposableGitFixture,
    manifest_digest: str,
    artifact_store: PrivateArtifactStore,
) -> SealedCandidate:
    diff = _git(
        fixture.builder,
        "diff",
        "--binary",
        fixture.baseline,
        fixture.valid_candidate,
    ).encode()
    return SealedCandidate(
        schema_version=1,
        experiment_id=EXPERIMENT_ID,
        manifest_digest=manifest_digest,
        parent_commit=fixture.baseline,
        candidate_commit=fixture.valid_candidate,
        branch=f"codex/experiment-{EXPERIMENT_ID}-{fixture.baseline[:10]}",
        diff_artifact=artifact_store.put(
            evidence_kind="candidate_diff",
            media_type="text/plain",
            content=diff,
        ),
        report_artifact=artifact_store.put(
            evidence_kind="implementation_report",
            media_type="application/json",
            content=canonical_json_bytes(
                {
                    "behavior": "restart recovery",
                    "candidate": fixture.valid_candidate,
                }
            ),
        ),
        changed_paths_artifact=artifact_store.put(
            evidence_kind="changed_paths",
            media_type="application/json",
            content=canonical_json_bytes({"paths": ["src/runtime/capability.txt"]}),
        ),
        changed_path_count=1,
        checks=(
            DeterministicCheckResult(
                check_id="synthetic-contracts",
                status="passed",
                exit_code=0,
                elapsed_ms=125,
                output_artifact=artifact_store.put(
                    evidence_kind="check_output",
                    media_type="application/json",
                    content=canonical_json_bytes({"passed": True}),
                ),
            ),
        ),
    )


def _protected_receipt(
    *,
    manifest_digest: str,
    fixture: DisposableGitFixture,
    capability_report: CapabilityValidationReport,
) -> ProtectedValidationReceipt:
    return ProtectedValidationReceipt(
        schema_version=2,
        validation_id="validation-commissioning-001",
        experiment_id=EXPERIMENT_ID,
        manifest_digest=manifest_digest,
        policy_digest=POLICY_DIGEST,
        parent_commit=fixture.baseline,
        candidate_commit=fixture.valid_candidate,
        candidate_tree=fixture.valid_tree,
        executable_digest="a" * 64,
        adapter_digest="b" * 64,
        task_set_digest="c" * 64,
        metric_pack_digest="d" * 64,
        environment_digest="e" * 64,
        model="gpt-5.6",
        effort="high",
        deterministic_checks_digest="f" * 64,
        repository_tests_digest="0" * 64,
        paired_score_delta_basis_points=1_000,
        paired_confidence_lower_basis_points=500,
        guard_delta_basis_points=0,
        workflow_passed=True,
        safety_passed=True,
        flake_rate_basis_points=0,
        invalid_run_count=0,
        cost_microdollars=100_000,
        latency_ms=1_000,
        holdout_aggregate_basis_points=500,
        holdout_leakage_detected=False,
        proposal_review_digest="1" * 64,
        build_review_digest="2" * 64,
        security_review_digest="3" * 64,
        created_at="2026-08-19T10:00:00Z",
        expires_at="2026-08-19T18:00:00Z",
        decision="pass",
        capability_report_digest=capability_report.digest,
        transfer_gain_basis_points=capability_report.transfer_gain_basis_points,
    )


def _promotion_expectation(receipt: ProtectedValidationReceipt) -> PromotionExpectation:
    return PromotionExpectation(
        experiment_id=receipt.experiment_id,
        manifest_digest=receipt.manifest_digest,
        policy_digest=receipt.policy_digest,
        parent_commit=receipt.parent_commit,
        candidate_commit=receipt.candidate_commit,
        candidate_tree=receipt.candidate_tree,
        executable_digest=receipt.executable_digest,
        adapter_digest=receipt.adapter_digest,
        task_set_digest=receipt.task_set_digest,
        metric_pack_digest=receipt.metric_pack_digest,
        model=receipt.model,
        effort=receipt.effort,
        environment_digest=receipt.environment_digest,
    )


def _promotion_request(receipt: ProtectedValidationReceipt) -> PromotionRequest:
    return PromotionRequest(
        promotion_id="promotion-exp-commissioning-001-1",
        experiment_id=EXPERIMENT_ID,
        repository="fixture/carl-agent",
        base_branch="main",
        head_branch=f"experimental/{EXPERIMENT_ID}",
        parent_commit=receipt.parent_commit,
        candidate_commit=receipt.candidate_commit,
        candidate_tree=receipt.candidate_tree,
        protected_receipt_digest=receipt.digest,
    )


def _controller_snapshot(
    *,
    ledger_path: Path,
    report: CapabilityValidationReport,
    envelope: SignedProtectedValidation,
    public_key: bytes,
    expectation: PromotionExpectation,
    request: PromotionRequest,
    promotion_snapshot: PromotionSnapshot,
    soak_result: SoakResult | None = None,
    accepted: bool = False,
) -> ControllerSnapshot:
    return ControllerSnapshot(
        autonomy=ExperimentLedger(ledger_path).autonomy_projection(EXPERIMENT_ID),
        capability_report=report,
        protected_validation=envelope,
        protected_public_key_pem=public_key,
        promotion_expectation=expectation,
        promotion_request=request,
        promotion_snapshot=promotion_snapshot,
        required_checks=APPROVED_REQUIRED_CHECKS,
        soak_result=soak_result,
        changed_paths=("src/runtime/capability.txt",),
        accepted=accepted,
    )


def _append_publication(
    ledger_path: Path,
    packet: SealedCandidate,
    candidate_tree: str,
) -> bool:
    event = ExperimentEvent.create(
        experiment_id=EXPERIMENT_ID,
        stage_attempt_id="publish-experimental-commissioning-001",
        event_type=EventType.EXPERIMENTAL_PUBLISHED,
        occurred_at="2026-08-19T11:00:00Z",
        payload={
            "branch": f"experimental/{EXPERIMENT_ID}",
            "candidate_packet_digest": packet.digest,
            "commit": packet.candidate_commit,
            "tree": candidate_tree,
        },
    )
    return ExperimentLedger(ledger_path).append(event).appended


def _lifecycle_transition(
    *,
    source: ExperimentState,
    target: ExperimentState,
    attempt: str,
    occurred_at: str,
    lease_owner: str = "commissioning-controller",
    lease_attempt: str = "commissioning-lifecycle-lease",
) -> ExperimentEvent:
    payload: dict[str, object] = {
        "from_state": source.value,
        "to_state": target.value,
    }
    if target in {
        ExperimentState.BUILDING,
        ExperimentState.DETERMINISTIC_VALIDATION,
        ExperimentState.PAIRED_EVALUATION,
        ExperimentState.HOLDOUT_VALIDATION,
        ExperimentState.REVIEW_COMPLETE,
        ExperimentState.PR_OPEN,
        ExperimentState.MERGED,
        ExperimentState.SOAKING,
        ExperimentState.ACCEPTED,
    }:
        payload["_lease"] = {
            "owner_id": lease_owner,
            "stage_attempt_id": lease_attempt,
        }
    return ExperimentEvent.create(
        experiment_id=EXPERIMENT_ID,
        stage_attempt_id=attempt,
        event_type=EventType.STATE_TRANSITIONED,
        occurred_at=occurred_at,
        payload=payload,
    )


def _append_accepted_lifecycle(
    *,
    ledger_path: Path,
    manifest_digest: str,
    parent_commit: str,
    packet: SealedCandidate,
    candidate_tree: str,
    protected_receipt_digest: str,
    promotion_commit: str,
    artifact_store: PrivateArtifactStore,
) -> None:
    ledger = ExperimentLedger(ledger_path)
    for source, target, attempt, occurred_at in (
        (
            ExperimentState.QUEUED,
            ExperimentState.BASELINING,
            "commissioning-baseline",
            "2026-08-19T09:01:00Z",
        ),
        (
            ExperimentState.BASELINING,
            ExperimentState.DIAGNOSING,
            "commissioning-diagnosis",
            "2026-08-19T09:02:00Z",
        ),
        (
            ExperimentState.DIAGNOSING,
            ExperimentState.PROPOSAL_REVIEW,
            "commissioning-proposal",
            "2026-08-19T09:03:00Z",
        ),
    ):
        ledger.append(
            _lifecycle_transition(
                source=source,
                target=target,
                attempt=attempt,
                occurred_at=occurred_at,
            )
        )
    for index, role in enumerate((ReviewRole.CAUSAL, ReviewRole.PRODUCT), start=4):
        review_ref = artifact_store.put(
            evidence_kind="proposal_review",
            media_type="application/json",
            content=canonical_json_bytes({"role": role.value, "verdict": "approve"}),
        )
        ledger.append(
            ExperimentEvent.create(
                experiment_id=EXPERIMENT_ID,
                stage_attempt_id=f"commissioning-proposal-review-{role.value}",
                event_type=EventType.ROLE_RECORDED,
                occurred_at=f"2026-08-19T09:0{index}:00Z",
                payload={
                    "artifact_digest": review_ref.digest,
                    "role": role.value,
                    "verdict": ReviewVerdict.APPROVE.value,
                },
            )
        )
    ledger.append(
        ExperimentEvent.create(
            experiment_id=EXPERIMENT_ID,
            stage_attempt_id="commissioning-lifecycle-lease",
            event_type=EventType.LEASE_ACQUIRED,
            occurred_at="2026-08-19T09:06:00Z",
            payload={
                "expires_at": "2026-08-19T15:06:00Z",
                "owner_id": "commissioning-controller",
            },
        )
    )
    ledger.append(
        _lifecycle_transition(
            source=ExperimentState.PROPOSAL_REVIEW,
            target=ExperimentState.BUILDING,
            attempt="commissioning-build",
            occurred_at="2026-08-19T09:07:00Z",
        )
    )
    request_ref = artifact_store.put(
        evidence_kind="builder_request",
        media_type="application/json",
        content=canonical_json_bytes({"candidate": packet.candidate_commit}),
    )
    prepared = PreparedCandidate(
        schema_version=1,
        experiment_id=EXPERIMENT_ID,
        manifest_digest=manifest_digest,
        parent_commit=parent_commit,
        branch=packet.branch,
        request_artifact=request_ref,
    )
    lease = {
        "owner_id": "commissioning-controller",
        "stage_attempt_id": "commissioning-lifecycle-lease",
    }
    ledger.append(
        ExperimentEvent.create(
            experiment_id=EXPERIMENT_ID,
            stage_attempt_id="commissioning-workspace-prepared",
            event_type=EventType.WORKSPACE_PREPARED,
            occurred_at="2026-08-19T09:08:00Z",
            payload={**prepared.to_canonical_dict(), "_lease": lease},
        )
    )
    ledger.append(
        ExperimentEvent.create(
            experiment_id=EXPERIMENT_ID,
            stage_attempt_id="commissioning-candidate-sealed",
            event_type=EventType.CANDIDATE_SEALED,
            occurred_at="2026-08-19T09:09:00Z",
            payload={**packet.to_canonical_dict(), "_lease": lease},
        )
    )
    ledger.append(
        _lifecycle_transition(
            source=ExperimentState.BUILDING,
            target=ExperimentState.DETERMINISTIC_VALIDATION,
            attempt="commissioning-deterministic-validation",
            occurred_at="2026-08-19T09:10:00Z",
        )
    )
    ledger.append(
        _lifecycle_transition(
            source=ExperimentState.DETERMINISTIC_VALIDATION,
            target=ExperimentState.PAIRED_EVALUATION,
            attempt="commissioning-paired-evaluation",
            occurred_at="2026-08-19T09:11:00Z",
        )
    )
    baseline_ref = artifact_store.put(
        evidence_kind="baseline_scorecard",
        media_type="application/json",
        content=canonical_json_bytes({"pass_rate_basis_points": 5_000}),
    )
    candidate_ref = artifact_store.put(
        evidence_kind="candidate_scorecard",
        media_type="application/json",
        content=canonical_json_bytes({"pass_rate_basis_points": 7_500}),
    )
    comparison_ref = artifact_store.put(
        evidence_kind="paired_comparison",
        media_type="application/json",
        content=canonical_json_bytes(
            {
                "baseline": baseline_ref.to_canonical_dict(),
                "candidate": candidate_ref.to_canonical_dict(),
            }
        ),
    )
    paired = PairedEvidence(
        schema_version=1,
        experiment_id=EXPERIMENT_ID,
        manifest_digest=manifest_digest,
        parent_commit=parent_commit,
        candidate_commit=packet.candidate_commit,
        baseline_scorecard_digest=baseline_ref.digest,
        candidate_scorecard_digest=candidate_ref.digest,
        comparison_artifact=comparison_ref,
        decision="improvement",
        paired_trials=3,
        pass_rate_delta_basis_points=2_500,
        confidence_lower_basis_points=500,
    )
    ledger.append_trusted_authority(
        ExperimentEvent.create(
            experiment_id=EXPERIMENT_ID,
            stage_attempt_id="commissioning-paired-evidence",
            event_type=EventType.PAIRED_EVIDENCE_RECORDED,
            occurred_at="2026-08-19T09:12:00Z",
            payload={**paired.to_canonical_dict(), "_lease": lease},
        )
    )
    ledger.append(
        ExperimentEvent.create(
            experiment_id=EXPERIMENT_ID,
            stage_attempt_id="commissioning-experimental-publication",
            event_type=EventType.EXPERIMENTAL_PUBLISHED,
            occurred_at="2026-08-19T09:13:00Z",
            payload={
                "branch": f"experimental/{EXPERIMENT_ID}",
                "candidate_packet_digest": packet.digest,
                "commit": packet.candidate_commit,
                "tree": candidate_tree,
            },
        )
    )
    ledger.append_trusted_authority(
        ExperimentEvent.create(
            experiment_id=EXPERIMENT_ID,
            stage_attempt_id="commissioning-protected-validation",
            event_type=EventType.PROTECTED_VALIDATION_RECORDED,
            occurred_at="2026-08-19T09:14:00Z",
            payload={
                "candidate_commit": packet.candidate_commit,
                "candidate_tree": candidate_tree,
                "receipt_digest": protected_receipt_digest,
            },
        )
    )
    ledger.append(
        _lifecycle_transition(
            source=ExperimentState.PAIRED_EVALUATION,
            target=ExperimentState.HOLDOUT_VALIDATION,
            attempt="commissioning-holdout",
            occurred_at="2026-08-19T09:15:00Z",
        )
    )
    for minute, role in enumerate(
        (ReviewRole.CORRECTNESS, ReviewRole.SECURITY, ReviewRole.MAINTAINABILITY),
        start=16,
    ):
        review_ref = artifact_store.put(
            evidence_kind="candidate_review",
            media_type="application/json",
            content=canonical_json_bytes({"role": role.value, "verdict": "approve"}),
        )
        ledger.append(
            ExperimentEvent.create(
                experiment_id=EXPERIMENT_ID,
                stage_attempt_id=f"commissioning-candidate-review-{role.value}",
                event_type=EventType.ROLE_RECORDED,
                occurred_at=f"2026-08-19T09:{minute}:00Z",
                payload={
                    "_lease": lease,
                    "artifact_digest": review_ref.digest,
                    "role": role.value,
                    "verdict": ReviewVerdict.APPROVE.value,
                },
            )
        )
    for source, target, attempt, occurred_at in (
        (
            ExperimentState.HOLDOUT_VALIDATION,
            ExperimentState.REVIEW_COMPLETE,
            "commissioning-review-complete",
            "2026-08-19T09:19:00Z",
        ),
        (
            ExperimentState.REVIEW_COMPLETE,
            ExperimentState.PR_OPEN,
            "commissioning-pr-open",
            "2026-08-19T09:20:00Z",
        ),
    ):
        ledger.append(
            _lifecycle_transition(
                source=source,
                target=target,
                attempt=attempt,
                occurred_at=occurred_at,
            )
        )
    ledger.append_trusted_authority(
        ExperimentEvent.create(
            experiment_id=EXPERIMENT_ID,
            stage_attempt_id="commissioning-promotion",
            event_type=EventType.PROMOTION_RECORDED,
            occurred_at="2026-08-19T10:00:00Z",
            payload={"merge_commit": promotion_commit, "merge_tree": candidate_tree},
        )
    )
    ledger.append(
        _lifecycle_transition(
            source=ExperimentState.PR_OPEN,
            target=ExperimentState.MERGED,
            attempt="commissioning-merged",
            occurred_at="2026-08-19T10:01:00Z",
        )
    )
    ledger.append(
        _lifecycle_transition(
            source=ExperimentState.MERGED,
            target=ExperimentState.SOAKING,
            attempt="commissioning-soaking",
            occurred_at="2026-08-19T10:02:00Z",
        )
    )
    soak_ref = artifact_store.put(
        evidence_kind="soak_observation",
        media_type="application/json",
        content=canonical_json_bytes({"healthy": True, "merge_commit": promotion_commit}),
    )
    ledger.append_trusted_authority(
        ExperimentEvent.create(
            experiment_id=EXPERIMENT_ID,
            stage_attempt_id="commissioning-24h-soak",
            event_type=EventType.SOAK_OBSERVED,
            occurred_at="2026-08-20T10:02:00Z",
            payload={
                "evidence_digest": soak_ref.digest,
                "healthy": True,
                "merge_commit": promotion_commit,
                "observed_at": "2026-08-20T10:02:00Z",
            },
        )
    )
    ledger.append(
        ExperimentEvent.create(
            experiment_id=EXPERIMENT_ID,
            stage_attempt_id="commissioning-reconcile-expired-lease",
            event_type=EventType.LEASE_RECONCILED,
            occurred_at="2026-08-20T10:03:00Z",
            payload={
                "lease_stage_attempt_id": "commissioning-lifecycle-lease",
                "worker_not_live": True,
            },
        )
    )
    ledger.append(
        ExperimentEvent.create(
            experiment_id=EXPERIMENT_ID,
            stage_attempt_id="commissioning-acceptance-lease",
            event_type=EventType.LEASE_ACQUIRED,
            occurred_at="2026-08-20T10:04:00Z",
            payload={
                "expires_at": "2026-08-20T16:04:00Z",
                "owner_id": "commissioning-acceptance-controller",
            },
        )
    )
    ledger.append(
        _lifecycle_transition(
            source=ExperimentState.SOAKING,
            target=ExperimentState.ACCEPTED,
            attempt="commissioning-accepted",
            occurred_at="2026-08-20T10:05:00Z",
            lease_owner="commissioning-acceptance-controller",
            lease_attempt="commissioning-acceptance-lease",
        )
    )
    ledger.append(
        ExperimentEvent.create(
            experiment_id=EXPERIMENT_ID,
            stage_attempt_id="commissioning-release-acceptance-lease",
            event_type=EventType.LEASE_RELEASED,
            occurred_at="2026-08-20T10:06:00Z",
            payload={"lease_stage_attempt_id": "commissioning-acceptance-lease"},
        )
    )


def _canonical_lifecycle_export(ledger_path: Path) -> bytes:
    ledger = ExperimentLedger(ledger_path)
    projection = ledger.projection(EXPERIMENT_ID)
    autonomy = ledger.autonomy_projection(EXPERIMENT_ID)
    return canonical_json_bytes(
        {
            "autonomy": autonomy.to_canonical_dict(),
            "events": [event.to_canonical_dict() for event in ledger.events(EXPERIMENT_ID)],
            "experiment_id": EXPERIMENT_ID,
            "projection_digest": projection.digest,
            "schema_version": 1,
            "terminal_state": projection.state.value,
        }
    )


def test_accepted_lifecycle_is_derived_from_fresh_ledger_and_bare_refs(
    tmp_path: Path,
    disposable_git: DisposableGitFixture,
) -> None:
    automation_root = tmp_path / "automation-data"
    store = CommissioningArtifactStore(
        automation_data_root=automation_root,
        repository_root=disposable_git.builder,
    )
    evidence = PrivateArtifactStore(store.objects_root, disposable_git.builder)
    manifest = replace(
        base_manifest(),
        experiment_id=EXPERIMENT_ID,
        parent_commit=disposable_git.baseline,
        registered_at="2026-08-19T09:00:00Z",
        deterministic_checks=("synthetic-contracts",),
    )
    ledger_path = automation_root / "lifecycle.sqlite3"
    ledger = ExperimentLedger(ledger_path)
    assert ledger.register_manifest(manifest) is True
    packet = _candidate_packet(disposable_git, manifest.digest, evidence)

    _git(disposable_git.builder, "switch", "-C", "commissioning-accepted", manifest.parent_commit)
    _git(
        disposable_git.builder,
        "merge",
        "--no-ff",
        "--no-edit",
        disposable_git.valid_candidate,
    )
    promotion_commit = _git(disposable_git.builder, "rev-parse", "HEAD")
    assert _git(disposable_git.builder, "rev-parse", "HEAD^{tree}") == disposable_git.valid_tree
    _git(disposable_git.builder, "push", "origin", "HEAD:refs/heads/main")
    _git(
        disposable_git.builder,
        "push",
        "origin",
        f"{disposable_git.valid_candidate}:refs/heads/experimental/{EXPERIMENT_ID}",
    )

    protected_receipt_ref = evidence.put(
        evidence_kind="protected_receipt",
        media_type="application/json",
        content=canonical_json_bytes({"candidate_commit": disposable_git.valid_candidate}),
    )
    _append_accepted_lifecycle(
        ledger_path=ledger_path,
        manifest_digest=manifest.digest,
        parent_commit=manifest.parent_commit,
        packet=packet,
        candidate_tree=disposable_git.valid_tree,
        protected_receipt_digest=protected_receipt_ref.digest,
        promotion_commit=promotion_commit,
        artifact_store=evidence,
    )
    assert ExperimentLedger(ledger_path).projection(EXPERIMENT_ID).state is ExperimentState.ACCEPTED
    lifecycle_ref = evidence.put(
        evidence_kind="lifecycle_ledger",
        media_type="application/json",
        content=_canonical_lifecycle_export(ledger_path),
    )

    verified = store.verify_accepted_lifecycle(
        experiment_id=EXPERIMENT_ID,
        ledger_path=ledger_path,
        bare_repository=disposable_git.origin,
        lifecycle_artifact_ref=lifecycle_ref,
    )

    assert verified.terminal_state == "accepted"
    assert verified.candidate_commit == disposable_git.valid_candidate
    assert verified.candidate_tree == disposable_git.valid_tree
    assert verified.experimental_ref == f"refs/heads/experimental/{EXPERIMENT_ID}"
    assert verified.promotion_commit == promotion_commit
    assert verified.production_commit == promotion_commit
    assert verified.soak_elapsed_seconds >= 24 * 60 * 60
    assert verified.lifecycle_artifact_ref == lifecycle_ref

    object_path = store.objects_root / lifecycle_ref.digest
    object_path.write_bytes(b"x" * lifecycle_ref.byte_size)
    object_path.chmod(0o600)
    with pytest.raises(CommissioningArtifactError, match="commissioning_artifact_invalid"):
        store.verify_accepted_lifecycle(
            experiment_id=EXPERIMENT_ID,
            ledger_path=ledger_path,
            bare_repository=disposable_git.origin,
            lifecycle_artifact_ref=lifecycle_ref,
        )


def _controller_command(
    *,
    effect_store: Path,
    artifact_store: Path,
    repository_root: Path,
    bare_repository: Path,
    request_path: Path,
    signing_key: Path,
    pause_marker: Path | None = None,
) -> tuple[str, ...]:
    command = (
        sys.executable,
        "-m",
        "carl_bench.commissioning_controller",
        "run",
        "--effect-store",
        os.fspath(effect_store),
        "--artifact-store",
        os.fspath(artifact_store),
        "--repository-root",
        os.fspath(repository_root),
        "--bare-repository",
        os.fspath(bare_repository),
        "--request",
        os.fspath(request_path),
        "--signing-key",
        os.fspath(signing_key),
        "--key-id",
        "synthetic-protected-controller",
    )
    if pause_marker is not None:
        command = (*command, "--pause-after-effect", os.fspath(pause_marker))
    return command


def _controller_environment() -> dict[str, str]:
    return {
        **os.environ,
        "PYTHONPATH": os.fspath(REPOSITORY_ROOT / "benchmarks" / "src"),
    }


def _kill_after_effect(command: tuple[str, ...], marker: Path) -> None:
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_controller_environment(),
    )
    deadline = time.monotonic() + 10
    while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    if not marker.exists():
        stdout, stderr = process.communicate(timeout=5)
        pytest.fail(
            f"controller did not reach effect boundary: return={process.returncode}; "
            f"stdout={stdout!r}; stderr={stderr!r}"
        )
    process.kill()
    process.wait(timeout=5)
    assert process.returncode is not None and process.returncode != 0


def _complete_controller(command: tuple[str, ...]) -> dict[str, object]:
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=_controller_environment(),
    )
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


def _inspect_effect(effect_store: Path, effect_key: str) -> dict[str, object]:
    completed = subprocess.run(
        (
            sys.executable,
            "-m",
            "carl_bench.commissioning_controller",
            "inspect",
            "--effect-store",
            os.fspath(effect_store),
            "--effect-key",
            effect_key,
        ),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=_controller_environment(),
    )
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


def _verify_effect_receipt(
    *,
    artifact_store: Path,
    repository_root: Path,
    receipt_ref_path: Path,
    public_key_path: Path,
    request_path: Path,
) -> dict[str, object]:
    completed = subprocess.run(
        (
            sys.executable,
            "-m",
            "carl_bench.commissioning_controller",
            "verify-receipt",
            "--artifact-store",
            os.fspath(artifact_store),
            "--repository-root",
            os.fspath(repository_root),
            "--receipt-ref",
            os.fspath(receipt_ref_path),
            "--public-key",
            os.fspath(public_key_path),
            "--request",
            os.fspath(request_path),
        ),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=_controller_environment(),
    )
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


def test_controller_subprocess_recovers_two_effect_receipt_boundaries(
    tmp_path: Path,
    disposable_git: DisposableGitFixture,
) -> None:
    automation_root = tmp_path / "automation-data"
    commissioning_store = CommissioningArtifactStore(
        automation_data_root=automation_root,
        repository_root=disposable_git.builder,
    )
    protected_runner = ProtectedRunner(
        disposable_git,
        automation_root / ".protected-runner",
    )
    effect_store = automation_root / ".shared-private" / "commissioning-effects.sqlite3"
    request_root = automation_root / ".shared-private" / "controller-requests"
    request_root.mkdir(mode=0o700)
    request_root.chmod(0o700)

    publication_request = {
        "effect_key": f"publish:{EXPERIMENT_ID}",
        "expected_old_commit": "0" * 40,
        "kind": "experimental_publish",
        "occurred_at": "2026-08-19T09:13:00Z",
        "pr": None,
        "ref": f"refs/heads/experimental/{EXPERIMENT_ID}",
        "repository_id": "fixture/carl-agent",
        "schema_version": 1,
        "source_repository": os.fspath(disposable_git.builder),
        "target_commit": disposable_git.valid_candidate,
        "target_tree": disposable_git.valid_tree,
    }
    publication_path = request_root / "publication.json"
    publication_path.write_bytes(canonical_json_bytes(publication_request))
    publication_path.chmod(0o600)
    publication_marker = request_root / "publication.effect-applied"
    publication_command = _controller_command(
        effect_store=effect_store,
        artifact_store=commissioning_store.objects_root,
        repository_root=disposable_git.builder,
        bare_repository=disposable_git.origin,
        request_path=publication_path,
        signing_key=protected_runner.key_path,
        pause_marker=publication_marker,
    )
    _kill_after_effect(publication_command, publication_marker)
    assert (
        _git(
            disposable_git.origin,
            "rev-parse",
            f"refs/heads/experimental/{EXPERIMENT_ID}",
        )
        == disposable_git.valid_candidate
    )

    recovered_publication = _complete_controller(
        _controller_command(
            effect_store=effect_store,
            artifact_store=commissioning_store.objects_root,
            repository_root=disposable_git.builder,
            bare_repository=disposable_git.origin,
            request_path=publication_path,
            signing_key=protected_runner.key_path,
        )
    )
    assert recovered_publication["action"] == "recovered_effect_receipt"
    publication_replay = _complete_controller(
        _controller_command(
            effect_store=effect_store,
            artifact_store=commissioning_store.objects_root,
            repository_root=disposable_git.builder,
            bare_repository=disposable_git.origin,
            request_path=publication_path,
            signing_key=protected_runner.key_path,
        )
    )
    assert publication_replay["action"] == "already_receipted"
    assert publication_replay["receipt_ref"] == recovered_publication["receipt_ref"]

    _git(disposable_git.builder, "switch", "-C", "controller-promotion", disposable_git.baseline)
    _git(
        disposable_git.builder,
        "merge",
        "--no-ff",
        "--no-edit",
        disposable_git.valid_candidate,
    )
    promotion_commit = _git(disposable_git.builder, "rev-parse", "HEAD")
    promotion_tree = _git(disposable_git.builder, "rev-parse", "HEAD^{tree}")
    assert promotion_tree == disposable_git.valid_tree
    promotion_request = {
        "effect_key": f"promotion:{EXPERIMENT_ID}",
        "expected_old_commit": disposable_git.baseline,
        "kind": "promotion_merge",
        "occurred_at": "2026-08-19T10:00:00Z",
        "pr": {
            "base_branch": "main",
            "head_branch": f"experimental/{EXPERIMENT_ID}",
            "head_commit": disposable_git.valid_candidate,
            "head_tree": disposable_git.valid_tree,
            "number": 41,
            "promotion_id": f"promotion-{EXPERIMENT_ID}-1",
            "role": "promotion",
        },
        "ref": "refs/heads/main",
        "repository_id": "fixture/carl-agent",
        "schema_version": 1,
        "source_repository": os.fspath(disposable_git.builder),
        "target_commit": promotion_commit,
        "target_tree": promotion_tree,
    }
    promotion_path = request_root / "promotion.json"
    promotion_path.write_bytes(canonical_json_bytes(promotion_request))
    promotion_path.chmod(0o600)
    promotion_marker = request_root / "promotion.effect-applied"
    promotion_command = _controller_command(
        effect_store=effect_store,
        artifact_store=commissioning_store.objects_root,
        repository_root=disposable_git.builder,
        bare_repository=disposable_git.origin,
        request_path=promotion_path,
        signing_key=protected_runner.key_path,
        pause_marker=promotion_marker,
    )
    _kill_after_effect(promotion_command, promotion_marker)
    assert _git(disposable_git.origin, "rev-parse", "refs/heads/main") == promotion_commit

    recovered_promotion = _complete_controller(
        _controller_command(
            effect_store=effect_store,
            artifact_store=commissioning_store.objects_root,
            repository_root=disposable_git.builder,
            bare_repository=disposable_git.origin,
            request_path=promotion_path,
            signing_key=protected_runner.key_path,
        )
    )
    assert recovered_promotion["action"] == "recovered_effect_receipt"
    promotion_replay = _complete_controller(
        _controller_command(
            effect_store=effect_store,
            artifact_store=commissioning_store.objects_root,
            repository_root=disposable_git.builder,
            bare_repository=disposable_git.origin,
            request_path=promotion_path,
            signing_key=protected_runner.key_path,
        )
    )
    assert promotion_replay["action"] == "already_receipted"
    assert promotion_replay["receipt_ref"] == recovered_promotion["receipt_ref"]

    publication_record = _inspect_effect(effect_store, publication_request["effect_key"])
    promotion_record = _inspect_effect(effect_store, promotion_request["effect_key"])
    assert publication_record["status"] == "receipted"
    assert promotion_record["status"] == "receipted"
    assert len(publication_record["recoveries"]) == 1
    assert len(promotion_record["recoveries"]) == 1
    assert [item["action"] for item in publication_record["invocations"]] == [
        "effect_applied",
        "recovered_effect_receipt",
        "already_receipted",
    ]
    assert [item["action"] for item in promotion_record["invocations"]] == [
        "effect_applied",
        "recovered_effect_receipt",
        "already_receipted",
    ]
    assert promotion_record["pull_request"] == {
        **promotion_request["pr"],
        "effect_key": promotion_request["effect_key"],
        "merge_commit": promotion_commit,
        "merge_tree": promotion_tree,
        "state": "MERGED",
    }
    receipt_refs = {
        publication_record["receipt_ref"]["digest"],
        promotion_record["receipt_ref"]["digest"],
    }
    assert len(receipt_refs) == 2
    assert all((commissioning_store.objects_root / digest).is_file() for digest in receipt_refs)
    public_key_path = request_root / "protected-controller-public.pem"
    public_key_path.write_bytes(protected_runner.public_key_pem)
    public_key_path.chmod(0o600)
    for request_path, record in (
        (publication_path, publication_record),
        (promotion_path, promotion_record),
    ):
        receipt_ref_path = request_root / f"{record['effect_key'].replace(':', '-')}.ref.json"
        receipt_ref_path.write_bytes(canonical_json_bytes(record["receipt_ref"]))
        receipt_ref_path.chmod(0o600)
        verified_receipt = _verify_effect_receipt(
            artifact_store=commissioning_store.objects_root,
            repository_root=disposable_git.builder,
            receipt_ref_path=receipt_ref_path,
            public_key_path=public_key_path,
            request_path=request_path,
        )
        assert verified_receipt == {
            "action": "verified_effect_receipt",
            "effect_key": record["effect_key"],
            "receipt_digest": record["receipt_ref"]["digest"],
            "recovered": True,
        }


def _protected_evaluator_bytes() -> bytes:
    return canonical_json_bytes(
        {
            "behavior": "Recover interrupted consequential effects exactly once.",
            "claim_id": "claim-commissioning-command-evaluation",
            "claim_type": "capability",
            "schema_version": 1,
            "subject_path": "src/runtime/subject.py",
            "tasks": [
                {
                    "expected": {"answer": "reconcile_once"},
                    "input": {"event": "effect_without_receipt"},
                    "minimum_candidate_basis_points": 10_000,
                    "role": "affected",
                    "task_id": "primary-recovery",
                },
                {
                    "expected": {"answer": "inspect_then_resume"},
                    "input": {"event": "receipt_without_effect"},
                    "minimum_candidate_basis_points": 10_000,
                    "role": "held_out",
                    "task_id": "transfer-recovery",
                },
                {
                    "expected": {"answer": "deny"},
                    "input": {"event": "safe_default"},
                    "minimum_candidate_basis_points": 10_000,
                    "role": "guard",
                    "task_id": "unchanged-safety",
                },
            ],
        }
    )


def _changed_paths(
    fixture: DisposableGitFixture,
    candidate_commit: str,
) -> tuple[str, ...]:
    return tuple(
        _git(
            fixture.builder,
            "diff",
            "--name-only",
            fixture.baseline,
            candidate_commit,
        ).splitlines()
    )


def test_protected_runner_derives_scores_from_commands_and_denies_sockets(
    tmp_path: Path,
    disposable_git: DisposableGitFixture,
) -> None:
    from carl_bench.commissioning_runner import ProtectedSyntheticRunner

    automation_root = tmp_path / "automation-data"
    commissioning_store = CommissioningArtifactStore(
        automation_data_root=automation_root,
        repository_root=disposable_git.builder,
    )
    evidence = PrivateArtifactStore(
        commissioning_store.objects_root,
        disposable_git.builder,
    )
    evaluator_ref = evidence.put(
        evidence_kind="protected_evaluator",
        media_type="application/json",
        content=_protected_evaluator_bytes(),
    )
    runner = ProtectedSyntheticRunner(
        artifacts=evidence,
        protected_root=automation_root / ".protected-runner" / "command-evaluation",
        source_repository=disposable_git.builder,
    )

    valid = runner.evaluate_pair(
        baseline_commit=disposable_git.baseline,
        candidate_commit=disposable_git.valid_candidate,
        evaluator_ref=evaluator_ref,
        changed_paths=_changed_paths(disposable_git, disposable_git.valid_candidate),
    )

    assert valid.report.eligible is True
    assert valid.report.reasons == ()
    assert valid.report.transfer_gain_basis_points == 10_000
    assert {
        outcome.task_id: outcome.score_basis_points
        for outcome in valid.report.baseline_outcomes
    } == {
        "primary-recovery": 0,
        "transfer-recovery": 0,
        "unchanged-safety": 10_000,
    }
    assert {
        outcome.task_id: outcome.score_basis_points
        for outcome in valid.report.candidate_outcomes
    } == {
        "primary-recovery": 10_000,
        "transfer-recovery": 10_000,
        "unchanged-safety": 10_000,
    }
    assert json.loads(evidence.read(valid.capability_report_ref)) == (
        valid.report.to_canonical_dict()
    )
    execution = json.loads(evidence.read(valid.execution_bundle_ref))
    assert execution["baseline"]["subject_commit"] == disposable_git.baseline
    assert execution["candidate"]["subject_commit"] == disposable_git.valid_candidate
    assert all(item["command_exit_code"] == 0 for item in execution["baseline"]["trials"])
    assert all(item["command_exit_code"] == 0 for item in execution["candidate"]["trials"])

    benchmark_gamed = runner.evaluate_pair(
        baseline_commit=disposable_git.baseline,
        candidate_commit=disposable_git.benchmark_gamed_candidate,
        evaluator_ref=evaluator_ref,
        changed_paths=_changed_paths(
            disposable_git,
            disposable_git.benchmark_gamed_candidate,
        ),
    )
    assert benchmark_gamed.report.eligible is False
    assert "active_evaluator_modified" in benchmark_gamed.report.reasons
    assert "transfer_gain_required" in benchmark_gamed.report.reasons

    evaluator_altered = runner.evaluate_pair(
        baseline_commit=disposable_git.baseline,
        candidate_commit=disposable_git.evaluator_altered_candidate,
        evaluator_ref=evaluator_ref,
        changed_paths=_changed_paths(
            disposable_git,
            disposable_git.evaluator_altered_candidate,
        ),
    )
    assert evaluator_altered.report.eligible is False
    assert "active_evaluator_modified" in evaluator_altered.report.reasons
    assert evaluator_altered.evaluator_ref == evaluator_ref

    with pytest.raises(
        CommissioningArtifactError,
        match="synthetic_subject_network_denied",
    ):
        runner.evaluate_pair(
            baseline_commit=disposable_git.baseline,
            candidate_commit=disposable_git.network_candidate,
            evaluator_ref=evaluator_ref,
            changed_paths=_changed_paths(disposable_git, disposable_git.network_candidate),
        )


def _write_controller_request(root: Path, name: str, value: dict[str, object]) -> Path:
    path = root / f"{name}.json"
    path.write_bytes(canonical_json_bytes(value))
    path.chmod(0o600)
    return path


def test_changed_main_receipt_replay_and_exact_revert_are_durable_real_effects(
    tmp_path: Path,
    disposable_git: DisposableGitFixture,
) -> None:
    from carl_bench.commissioning_controller import (
        CommissioningControllerError,
        CommissioningEffectStore,
    )

    automation_root = tmp_path / "automation-data"
    commissioning_store = CommissioningArtifactStore(
        automation_data_root=automation_root,
        repository_root=disposable_git.builder,
    )
    evidence = PrivateArtifactStore(
        commissioning_store.objects_root,
        disposable_git.builder,
    )
    protected_runner = ProtectedRunner(
        disposable_git,
        automation_root / ".protected-runner",
    )
    request_root = automation_root / ".shared-private" / "attack-requests"
    request_root.mkdir(mode=0o700)
    request_root.chmod(0o700)
    effect_store_path = (
        automation_root / ".shared-private" / "commissioning-effects.sqlite3"
    )

    changed_origin = disposable_git.root / "changed-main-origin.git"
    _git(
        disposable_git.root,
        "clone",
        "--bare",
        os.fspath(disposable_git.origin),
        os.fspath(changed_origin),
    )
    changed_builder = disposable_git.root / "changed-main-builder"
    _git(
        disposable_git.root,
        "clone",
        os.fspath(changed_origin),
        os.fspath(changed_builder),
    )
    _git(changed_builder, "config", "user.email", "drift@example.invalid")
    _git(changed_builder, "config", "user.name", "Changed Main Attack")
    _git(changed_builder, "switch", "main")
    drift_commit = _write_commit(
        changed_builder,
        "unexpected-main.txt",
        "unexpected production advance\n",
        "advance main before promotion reconciliation",
    )
    _git(changed_builder, "push", "origin", "HEAD:refs/heads/main")
    drift_tree = _git(changed_builder, "rev-parse", "HEAD^{tree}")
    changed_main_request = {
        "effect_key": f"changed-main:{EXPERIMENT_ID}",
        "expected_old_commit": disposable_git.baseline,
        "kind": "main_precondition",
        "occurred_at": "2026-08-19T09:30:00Z",
        "pr": None,
        "ref": "refs/heads/main",
        "repository_id": "fixture/carl-agent-changed-main",
        "schema_version": 1,
        "source_repository": os.fspath(disposable_git.builder),
        "target_commit": disposable_git.valid_candidate,
        "target_tree": disposable_git.valid_tree,
    }
    changed_main_path = _write_controller_request(
        request_root,
        "changed-main",
        changed_main_request,
    )
    changed_main = _complete_controller(
        _controller_command(
            effect_store=effect_store_path,
            artifact_store=commissioning_store.objects_root,
            repository_root=disposable_git.builder,
            bare_repository=changed_origin,
            request_path=changed_main_path,
            signing_key=protected_runner.key_path,
        )
    )
    assert changed_main == {
        "action": "blocked",
        "effect_key": changed_main_request["effect_key"],
        "observed_commit": drift_commit,
        "reason": "production_parent_changed",
    }
    assert _git(changed_origin, "rev-parse", "refs/heads/main") == drift_commit
    assert _git(changed_origin, "rev-parse", "refs/heads/main^{tree}") == drift_tree
    changed_record = _inspect_effect(
        effect_store_path,
        str(changed_main_request["effect_key"]),
    )
    assert changed_record["status"] == "rejected"
    assert changed_record["pull_request"] is None

    _git(disposable_git.builder, "switch", "-C", "healthy-production", disposable_git.baseline)
    _git(
        disposable_git.builder,
        "merge",
        "--no-ff",
        "--no-edit",
        disposable_git.valid_candidate,
    )
    healthy_merge = _git(disposable_git.builder, "rev-parse", "HEAD")
    healthy_tree = _git(disposable_git.builder, "rev-parse", "HEAD^{tree}")
    healthy_request = {
        "effect_key": f"healthy-promotion:{EXPERIMENT_ID}",
        "expected_old_commit": disposable_git.baseline,
        "kind": "promotion_merge",
        "occurred_at": "2026-08-19T10:00:00Z",
        "pr": {
            "base_branch": "main",
            "head_branch": f"experimental/{EXPERIMENT_ID}",
            "head_commit": disposable_git.valid_candidate,
            "head_tree": disposable_git.valid_tree,
            "number": 41,
            "promotion_id": f"promotion-{EXPERIMENT_ID}-1",
            "role": "promotion",
        },
        "ref": "refs/heads/main",
        "repository_id": "fixture/carl-agent",
        "schema_version": 1,
        "source_repository": os.fspath(disposable_git.builder),
        "target_commit": healthy_merge,
        "target_tree": healthy_tree,
    }
    healthy_path = _write_controller_request(request_root, "healthy", healthy_request)
    assert _complete_controller(
        _controller_command(
            effect_store=effect_store_path,
            artifact_store=commissioning_store.objects_root,
            repository_root=disposable_git.builder,
            bare_repository=disposable_git.origin,
            request_path=healthy_path,
            signing_key=protected_runner.key_path,
        )
    )["action"] == "effect_receipted"

    _git(disposable_git.builder, "switch", "-C", "hard-candidate", healthy_merge)
    hard_candidate = _write_commit(
        disposable_git.builder,
        "src/runtime/subject.py",
        "raise RuntimeError('hard production regression')\n",
        "inject hard production regression after accepted candidate",
    )
    hard_candidate_tree = _git(disposable_git.builder, "rev-parse", "HEAD^{tree}")
    _git(disposable_git.builder, "switch", "-C", "hard-merge", healthy_merge)
    _git(disposable_git.builder, "merge", "--no-ff", "--no-edit", hard_candidate)
    hard_merge = _git(disposable_git.builder, "rev-parse", "HEAD")
    hard_tree = _git(disposable_git.builder, "rev-parse", "HEAD^{tree}")
    assert hard_tree == hard_candidate_tree
    hard_request = {
        "effect_key": f"hard-regression:{EXPERIMENT_ID}",
        "expected_old_commit": healthy_merge,
        "kind": "hard_regression_merge",
        "occurred_at": "2026-08-19T12:00:00Z",
        "pr": {
            "base_branch": "main",
            "head_branch": f"hard-regression/{EXPERIMENT_ID}",
            "head_commit": hard_candidate,
            "head_tree": hard_tree,
            "number": 42,
            "promotion_id": f"hard-regression-{EXPERIMENT_ID}-1",
            "role": "hard_regression",
        },
        "ref": "refs/heads/main",
        "repository_id": "fixture/carl-agent",
        "schema_version": 1,
        "source_repository": os.fspath(disposable_git.builder),
        "target_commit": hard_merge,
        "target_tree": hard_tree,
    }
    hard_path = _write_controller_request(request_root, "hard-regression", hard_request)
    assert _complete_controller(
        _controller_command(
            effect_store=effect_store_path,
            artifact_store=commissioning_store.objects_root,
            repository_root=disposable_git.builder,
            bare_repository=disposable_git.origin,
            request_path=hard_path,
            signing_key=protected_runner.key_path,
        )
    )["action"] == "effect_receipted"
    assert _git(disposable_git.origin, "rev-parse", "refs/heads/main") == hard_merge

    _git(disposable_git.builder, "switch", "-C", "exact-revert-candidate", hard_merge)
    _git(disposable_git.builder, "revert", "-m", "1", "--no-edit", hard_merge)
    revert_candidate = _git(disposable_git.builder, "rev-parse", "HEAD")
    revert_candidate_tree = _git(disposable_git.builder, "rev-parse", "HEAD^{tree}")
    assert revert_candidate_tree == healthy_tree
    _git(disposable_git.builder, "switch", "-C", "exact-revert-merge", hard_merge)
    _git(disposable_git.builder, "merge", "--no-ff", "--no-edit", revert_candidate)
    revert_merge = _git(disposable_git.builder, "rev-parse", "HEAD")
    revert_tree = _git(disposable_git.builder, "rev-parse", "HEAD^{tree}")
    assert revert_tree == healthy_tree
    revert_request = {
        "effect_key": f"exact-revert:{EXPERIMENT_ID}",
        "expected_old_commit": hard_merge,
        "kind": "revert_merge",
        "occurred_at": "2026-08-19T13:00:00Z",
        "pr": {
            "base_branch": "main",
            "head_branch": f"revert/hard-regression-{EXPERIMENT_ID}-1",
            "head_commit": revert_candidate,
            "head_tree": revert_tree,
            "number": 43,
            "promotion_id": f"revert-{EXPERIMENT_ID}-1",
            "role": "revert",
        },
        "ref": "refs/heads/main",
        "repository_id": "fixture/carl-agent",
        "schema_version": 1,
        "source_repository": os.fspath(disposable_git.builder),
        "target_commit": revert_merge,
        "target_tree": revert_tree,
    }
    revert_path = _write_controller_request(request_root, "exact-revert", revert_request)
    assert _complete_controller(
        _controller_command(
            effect_store=effect_store_path,
            artifact_store=commissioning_store.objects_root,
            repository_root=disposable_git.builder,
            bare_repository=disposable_git.origin,
            request_path=revert_path,
            signing_key=protected_runner.key_path,
        )
    )["action"] == "effect_receipted"
    assert _git(disposable_git.origin, "rev-parse", "refs/heads/main") == revert_merge
    assert _git(disposable_git.origin, "rev-parse", "refs/heads/main^{tree}") == healthy_tree
    hard_record = _inspect_effect(effect_store_path, str(hard_request["effect_key"]))
    revert_record = _inspect_effect(effect_store_path, str(revert_request["effect_key"]))
    assert hard_record["pull_request"]["state"] == "MERGED"
    assert revert_record["pull_request"]["state"] == "MERGED"
    assert hard_record["pull_request"]["number"] == 42
    assert revert_record["pull_request"]["number"] == 43

    capability_report = evaluate_capability_validation(
        _capability_claim(),
        _baseline_outcomes(),
        _improved_outcomes(),
        ("src/runtime/capability.txt",),
    )
    protected_receipt = _protected_receipt(
        manifest_digest="a" * 64,
        fixture=disposable_git,
        capability_report=capability_report,
    )
    envelope = protected_runner.sign(protected_receipt)
    expectation = replace(
        _promotion_expectation(protected_receipt),
        capability_report_digest=capability_report.digest,
        transfer_gain_basis_points=capability_report.transfer_gain_basis_points,
        capability_claim_type=capability_report.claim_type,
        affected_contract_cases_improved=capability_report.affected_contract_cases_improved,
        capability_guards_non_inferior=capability_report.guards_non_inferior,
    )
    verify_protected_validation(
        envelope,
        public_key_pem=protected_runner.public_key_pem,
        expected=expectation,
        now=NOW,
        changed_paths=("src/runtime/capability.txt",),
    )
    envelope_ref = evidence.put(
        evidence_kind="signed_protected_receipt",
        media_type="application/json",
        content=canonical_json_bytes(
            {
                "key_id": envelope.key_id,
                "receipt": envelope.receipt.to_canonical_dict(),
                "signature_base64": envelope.signature_base64,
            }
        ),
    )
    durable_effects = CommissioningEffectStore(effect_store_path)
    first_use = durable_effects.consume_protected_receipt(
        receipt_digest=protected_receipt.digest,
        envelope_ref=envelope_ref,
        occurred_at="2026-08-19T10:00:00Z",
    )
    assert first_use == "consumed"
    with pytest.raises(CommissioningControllerError, match="protected_receipt_replay"):
        durable_effects.consume_protected_receipt(
            receipt_digest=protected_receipt.digest,
            envelope_ref=envelope_ref,
            occurred_at="2026-08-19T10:01:00Z",
        )
    assert [
        attempt["outcome"] for attempt in durable_effects.protected_receipt_attempts()
    ] == ["consumed", "replay_rejected"]


def test_component_scenarios_cannot_self_issue_commissioning_pass(
    tmp_path: Path,
    disposable_git: DisposableGitFixture,
) -> None:
    automation_data_root = tmp_path / "owner-private-automation-data"
    commissioning_store = CommissioningArtifactStore(
        automation_data_root=automation_data_root,
        repository_root=disposable_git.builder,
    )
    artifact_store = PrivateArtifactStore(
        automation_data_root / "daily-carl-self-improvement-graph" / "objects",
        disposable_git.builder,
    )
    manifest = replace(
        base_manifest(),
        experiment_id=EXPERIMENT_ID,
        parent_commit=disposable_git.baseline,
        registered_at="2026-08-19T09:00:00Z",
    )
    ledger_path = (
        automation_data_root
        / "daily-carl-autonomy-outcome-monitor"
        / "commissioning"
        / "lifecycle.sqlite3"
    )
    ledger = ExperimentLedger(ledger_path)
    assert ledger.register_manifest(manifest) is True

    claim = _capability_claim()
    capability_report = evaluate_capability_validation(
        claim,
        _baseline_outcomes(),
        _improved_outcomes(),
        ("src/runtime/capability.txt",),
    )
    assert capability_report.eligible is True
    assert capability_report.transfer_gain_basis_points == 500

    public_only = tuple(
        replace(item, score_basis_points=6_000) if item.task_id == "held-out-task" else item
        for item in _improved_outcomes()
    )
    gaming_paths = tuple(
        _git(
            disposable_git.builder,
            "diff",
            "--name-only",
            disposable_git.baseline,
            disposable_git.benchmark_gamed_candidate,
        ).splitlines()
    )
    benchmark_gaming = evaluate_capability_validation(
        claim,
        _baseline_outcomes(),
        public_only,
        gaming_paths,
    )
    assert "transfer_gain_required" in benchmark_gaming.reasons
    assert "active_evaluator_modified" in benchmark_gaming.reasons

    evaluator_altered = tuple(
        replace(item, evaluator_digest="f" * 64) if item.task_id == "held-out-task" else item
        for item in _improved_outcomes()
    )
    evaluator_report = evaluate_capability_validation(
        claim,
        _baseline_outcomes(),
        evaluator_altered,
        ("src/runtime/capability.txt",),
    )
    assert "evaluation_identity_changed" in evaluator_report.reasons

    packet = _candidate_packet(disposable_git, manifest.digest, artifact_store)
    publication_request = ExperimentalPublicationRequest(
        experiment_id=EXPERIMENT_ID,
        branch=f"experimental/{EXPERIMENT_ID}",
        candidate_packet=packet,
        candidate_tree=disposable_git.valid_tree,
        capability_report=capability_report,
    )
    git_executable = Path(shutil.which("git") or "/missing-git")

    # The branch effect succeeds and the controller is killed before its ledger receipt.
    first_publication = publish_experimental_branch(
        publication_request,
        repository=disposable_git.builder,
        remote="origin",
        git_executable=git_executable,
    )
    assert first_publication.outcome == "record_existing_exact_branch"
    assert (
        ExperimentLedger(ledger_path).autonomy_projection(EXPERIMENT_ID).experimental_publication
        is None
    )

    # A fresh process reconciles the exact ref instead of pushing or duplicating it.
    recovered_publication = publish_experimental_branch(
        publication_request,
        repository=disposable_git.builder,
        remote="origin",
        git_executable=git_executable,
    )
    assert recovered_publication == first_publication
    assert _append_publication(ledger_path, packet, disposable_git.valid_tree) is True
    assert _append_publication(ledger_path, packet, disposable_git.valid_tree) is False
    experimental_refs = _git(
        disposable_git.origin,
        "for-each-ref",
        "--format=%(refname)",
        "refs/heads/experimental",
    ).splitlines()
    assert experimental_refs == [f"refs/heads/experimental/{EXPERIMENT_ID}"]
    assert (
        _git(
            disposable_git.builder,
            "ls-remote",
            "origin",
            "refs/heads/main",
        ).split()[0]
        == disposable_git.baseline
    )

    runner = ProtectedRunner(
        disposable_git,
        automation_data_root / ".protected-runner",
    )
    assert not runner.key_path.is_relative_to(disposable_git.builder)
    assert stat.S_IMODE(runner.key_path.stat().st_mode) == 0o600
    assert tuple(disposable_git.builder.rglob("*.pem")) == ()

    protected_receipt = _protected_receipt(
        manifest_digest=manifest.digest,
        fixture=disposable_git,
        capability_report=capability_report,
    )
    envelope = runner.sign(protected_receipt)
    expectation = _promotion_expectation(protected_receipt)
    request = _promotion_request(protected_receipt)
    bound_expectation = replace(
        expectation,
        capability_report_digest=capability_report.digest,
        transfer_gain_basis_points=capability_report.transfer_gain_basis_points,
        capability_claim_type=capability_report.claim_type,
        affected_contract_cases_improved=(capability_report.affected_contract_cases_improved),
        capability_guards_non_inferior=capability_report.guards_non_inferior,
    )
    assert (
        verify_protected_validation(
            envelope,
            public_key_pem=runner.public_key_pem,
            expected=bound_expectation,
            now=NOW,
            changed_paths=("src/runtime/capability.txt",),
        ).receipt_digest
        == protected_receipt.digest
    )

    tampered_receipt = replace(protected_receipt, repository_tests_digest="f" * 64)
    tampered_envelope = SignedProtectedValidation(
        receipt=tampered_receipt,
        key_id=envelope.key_id,
        signature_base64=envelope.signature_base64,
    )
    with pytest.raises(PromotionContractError, match="protected_signature_invalid"):
        verify_protected_validation(
            tampered_envelope,
            public_key_pem=runner.public_key_pem,
            expected=bound_expectation,
            now=NOW,
        )
    with pytest.raises(PromotionContractError, match="protected_candidate_mismatch"):
        verify_protected_validation(
            envelope,
            public_key_pem=runner.public_key_pem,
            expected=replace(
                bound_expectation,
                candidate_commit=disposable_git.hard_regression_candidate,
                candidate_tree=disposable_git.hard_regression_tree,
            ),
            now=NOW,
        )

    restart_recoveries = 1
    before_validation = _controller_snapshot(
        ledger_path=ledger_path,
        report=capability_report,
        envelope=envelope,
        public_key=runner.public_key_pem,
        expectation=expectation,
        request=request,
        promotion_snapshot=runner.snapshot(request),
    )
    validation = next_controller_action(before_validation, NOW)
    validation_after_restart = next_controller_action(
        _controller_snapshot(
            ledger_path=ledger_path,
            report=capability_report,
            envelope=envelope,
            public_key=runner.public_key_pem,
            expectation=expectation,
            request=request,
            promotion_snapshot=runner.snapshot(request),
        ),
        NOW,
    )
    assert validation.action == "record_validation"
    assert validation_after_restart.event == validation.event
    first_validation_append = validation_after_restart.append_event(ExperimentLedger(ledger_path))
    duplicate_validation_append = validation_after_restart.append_event(
        ExperimentLedger(ledger_path)
    )
    assert first_validation_append is not None and first_validation_append.appended
    assert duplicate_validation_append is not None
    assert duplicate_validation_append.appended is False
    restart_recoveries += 1

    create_pr = next_controller_action(
        _controller_snapshot(
            ledger_path=ledger_path,
            report=capability_report,
            envelope=envelope,
            public_key=runner.public_key_pem,
            expectation=expectation,
            request=request,
            promotion_snapshot=runner.snapshot(request),
        ),
        NOW,
    )
    assert create_pr.action == "create_pr"
    runner.create_pull_request(request)

    # Process death after PR creation is recovered from observed PR identity.
    after_pr_restart = next_controller_action(
        _controller_snapshot(
            ledger_path=ledger_path,
            report=capability_report,
            envelope=envelope,
            public_key=runner.public_key_pem,
            expectation=expectation,
            request=request,
            promotion_snapshot=runner.snapshot(request),
        ),
        NOW,
    )
    assert after_pr_restart.action == "mark_ready"
    assert runner.create_pull_request(request).number == 41
    assert runner.pull_request_creations == 1
    restart_recoveries += 1

    runner.mark_ready()
    enable_merge = next_controller_action(
        _controller_snapshot(
            ledger_path=ledger_path,
            report=capability_report,
            envelope=envelope,
            public_key=runner.public_key_pem,
            expectation=expectation,
            request=request,
            promotion_snapshot=runner.snapshot(request),
        ),
        NOW,
    )
    assert enable_merge.action == "enable_auto_merge"
    runner.enable_auto_merge()
    waiting = next_controller_action(
        _controller_snapshot(
            ledger_path=ledger_path,
            report=capability_report,
            envelope=envelope,
            public_key=runner.public_key_pem,
            expectation=expectation,
            request=request,
            promotion_snapshot=runner.snapshot(request),
        ),
        NOW,
    )
    assert waiting.action == "idle"
    assert waiting.reason == "auto_merge_already_enabled"

    merged_pr = runner.merge(request)
    assert runner.merge(request) == merged_pr
    assert runner.merge_count == 1
    assert merged_pr.merge_commit is not None
    assert merged_pr.merge_tree == disposable_git.valid_tree

    # Process death after the merge effect is reconciled into one graph event.
    record_merge = next_controller_action(
        _controller_snapshot(
            ledger_path=ledger_path,
            report=capability_report,
            envelope=envelope,
            public_key=runner.public_key_pem,
            expectation=expectation,
            request=request,
            promotion_snapshot=runner.snapshot(request),
        ),
        NOW,
    )
    assert record_merge.action == "record_merge"
    first_merge_append = record_merge.append_event(ExperimentLedger(ledger_path))
    duplicate_merge_append = record_merge.append_event(ExperimentLedger(ledger_path))
    assert first_merge_append is not None and first_merge_append.appended
    assert duplicate_merge_append is not None and not duplicate_merge_append.appended
    restart_recoveries += 1

    for elapsed_hours in (1, 12, 24):
        observed_at = NOW + timedelta(hours=elapsed_hours)
        observed_at_text = observed_at.isoformat().replace("+00:00", "Z")
        evidence_digest = _sha256(f"healthy-soak-{elapsed_hours}".encode())
        snapshot = _controller_snapshot(
            ledger_path=ledger_path,
            report=capability_report,
            envelope=envelope,
            public_key=runner.public_key_pem,
            expectation=expectation,
            request=request,
            promotion_snapshot=runner.snapshot(request),
            soak_result=SoakResult(
                merge_commit=merged_pr.merge_commit,
                observed_at=observed_at_text,
                healthy=True,
                evidence_digest=evidence_digest,
            ),
        )
        observation = next_controller_action(snapshot, observed_at)
        duplicate_tick = next_controller_action(
            _controller_snapshot(
                ledger_path=ledger_path,
                report=capability_report,
                envelope=envelope,
                public_key=runner.public_key_pem,
                expectation=expectation,
                request=request,
                promotion_snapshot=runner.snapshot(request),
                soak_result=snapshot.soak_result,
            ),
            observed_at,
        )
        assert observation.action == "observe_soak"
        assert duplicate_tick.event == observation.event
        appended = observation.append_event(ExperimentLedger(ledger_path))
        replayed = observation.append_event(ExperimentLedger(ledger_path))
        assert appended is not None and appended.appended
        assert replayed is not None and not replayed.appended

    accepted_at = NOW + timedelta(hours=24)
    accepted_snapshot = _controller_snapshot(
        ledger_path=ledger_path,
        report=capability_report,
        envelope=envelope,
        public_key=runner.public_key_pem,
        expectation=expectation,
        request=request,
        promotion_snapshot=runner.snapshot(request),
    )
    accepted = next_controller_action(accepted_snapshot, accepted_at)
    assert accepted.action == "accept"
    assert accepted.merge_commit == merged_pr.merge_commit
    terminal = next_controller_action(
        replace(accepted_snapshot, accepted=True),
        accepted_at,
    )
    assert terminal.action == "idle"
    assert terminal.reason == "experiment_accepted"

    final_projection = ExperimentLedger(ledger_path).autonomy_projection(EXPERIMENT_ID)
    assert final_projection.experimental_publication is not None
    assert final_projection.protected_validation is not None
    assert final_projection.promotion is not None
    assert final_projection.promotion.merge_commit == merged_pr.merge_commit
    assert len(final_projection.soak_observations) == 3
    assert all(
        observation.merge_commit == merged_pr.merge_commit
        for observation in final_projection.soak_observations
    )
    assert datetime.fromisoformat(
        final_projection.soak_observations[-1].observed_at.replace("Z", "+00:00")
    ) - datetime.fromisoformat(
        final_projection.promotion.merged_at.replace("Z", "+00:00")
    ) == timedelta(hours=24)
    with pytest.raises(PromotionContractError, match="promotion_main_identity_mismatch"):
        next_controller_action(
            replace(
                accepted_snapshot,
                promotion_snapshot=replace(
                    accepted_snapshot.promotion_snapshot,
                    production_commit=disposable_git.benchmark_gamed_candidate,
                ),
            ),
            accepted_at,
        )

    prompt_manifest = json.loads(PROMPT_MANIFEST_PATH.read_text(encoding="utf-8"))
    entries = prompt_manifest["automations"]
    assert len(entries) == 6
    assert all(entry["status"] == "ACTIVE" for entry in entries)
    assert sum(entry["configuration"]["mutation_owner"] is True for entry in entries) == 1
    assert sum(entry["configuration"]["promotion_owner"] is True for entry in entries) == 1
    prompt_portfolio_digest = _sha256(
        canonical_json_bytes(
            {
                "canonical_prompt_sha256": _sha256(PROMPT_PATH.read_bytes()),
                "live_manifest": prompt_manifest,
            }
        )
    )

    trigger_store = SupervisorTriggerStore(
        automation_data_root / ".shared-private" / "carl-autonomy-supervisor-triggers.sqlite3"
    )
    initial_attempt = RecoveryAttempt(
        attempt_id="watchdog-observed-interruption",
        action_digest=_sha256(b"observe effect without durable receipt"),
        occurred_at="2026-08-19T11:01:00Z",
        outcome="still_blocked",
    )
    trigger = SupervisorTrigger(
        schema_version=1,
        trigger_id="commissioning-controller-interruption",
        evidence_digest=protected_receipt.digest,
        unsafe_boundary="promotion:effect_receipt_gap",
        attempt_history=(initial_attempt,),
        next_safe_node_key="commissioning:reconcile-existing-effect",
        created_at="2026-08-19T11:02:00Z",
    )
    assert trigger_store.append(trigger).applied is True
    pending = SupervisorTriggerStore(trigger_store.path).list_pending()
    assert tuple(item.trigger.trigger_id for item in pending) == (trigger.trigger_id,)
    recovery_attempt = RecoveryAttempt(
        attempt_id="supervisor-reconcile-exact-effect",
        action_digest=_sha256(b"reconcile exact remote identity then append receipt"),
        occurred_at="2026-08-19T11:03:00Z",
        outcome="state_reconciled",
    )
    claimed = SupervisorTriggerStore(trigger_store.path).claim_and_record_action(
        trigger_id=trigger.trigger_id,
        claim_id="supervisor-commissioning-run",
        expected_revision=0,
        attempt=recovery_attempt,
    )
    supervisor_result_digest = _sha256(b"exact effect reconciled without duplication")
    resolution = TriggerResolution(
        status="resolved",
        recovery_action=recovery_attempt,
        evidence_digest=trigger.evidence_digest,
        result_digest=supervisor_result_digest,
        resolved_at="2026-08-19T11:04:00Z",
    )
    resolved = SupervisorTriggerStore(trigger_store.path).resolve(
        trigger_id=trigger.trigger_id,
        claim_id="supervisor-commissioning-run",
        expected_revision=claimed.revision,
        resolution=resolution,
    )
    assert resolved.record.resolution == resolution
    assert SupervisorTriggerStore(trigger_store.path).list_pending() == ()

    workflow_blob_digest = _sha256(
        (REPOSITORY_ROOT / ".github/workflows/autonomous-improvement.yml").read_bytes()
    )
    cloud_request = CloudRunRequest.create(
        repository="fixture/carl-agent",
        workflow_file="autonomous-improvement.yml",
        experiment_digest=manifest.digest,
        parent_commit=disposable_git.baseline,
        candidate_commit=disposable_git.valid_candidate,
        task_set_digest=protected_receipt.task_set_digest,
        metric_pack_digest=protected_receipt.metric_pack_digest,
        policy_digest=protected_receipt.policy_digest,
        workflow_revision=disposable_git.baseline,
        workflow_blob_digest=workflow_blob_digest,
    )
    cloud_artifact_digest = _sha256(b"synthetic runner output")
    cloud_decision = reconcile_cloud_run(
        cloud_request,
        CloudRunSnapshot(
            remote_available=True,
            observed_at="2026-08-19T12:00:00Z",
            repository=cloud_request.repository,
            workflow_file=cloud_request.workflow_file,
            workflow_path=cloud_request.expected_workflow_path,
            workflow_blob_digest=cloud_request.workflow_blob_digest,
            request_digest=cloud_request.request_digest,
            dispatch_key=cloud_request.dispatch_key,
            run_id=77,
            head_sha=cloud_request.workflow_revision,
            status="completed",
            conclusion="success",
            attempt=1,
            max_attempts=3,
            attempt_key=cloud_request.attempt_key(1),
            artifacts=(
                CloudArtifact(
                    artifact_id=88,
                    name=cloud_request.expected_artifact_name,
                    run_id=77,
                    digest=cloud_artifact_digest,
                    downloaded_digest=cloud_artifact_digest,
                ),
            ),
            artifacts_expires_at="2026-08-20T12:00:00Z",
            commissioning_receipt=None,
        ),
    )
    assert cloud_decision.action == "blocked"
    assert cloud_decision.reason == "cloud_commissioning_receipt_missing"

    regression_branch = "synthetic-regression-production"
    _git(
        disposable_git.builder,
        "switch",
        "-C",
        regression_branch,
        disposable_git.baseline,
    )
    _git(
        disposable_git.builder,
        "merge",
        "--no-ff",
        "--no-edit",
        disposable_git.hard_regression_candidate,
    )
    regression_merge = _git(disposable_git.builder, "rev-parse", "HEAD")
    regression_tree = _git(disposable_git.builder, "rev-parse", "HEAD^{tree}")
    assert regression_tree == disposable_git.hard_regression_tree

    hard_receipt_digest = "8" * 64
    hard_request = replace(
        request,
        promotion_id="promotion-exp-commissioning-hard-1",
        candidate_commit=disposable_git.hard_regression_candidate,
        candidate_tree=disposable_git.hard_regression_tree,
        protected_receipt_digest=hard_receipt_digest,
    )
    hard_failure_digest = _sha256(b"hard production regression")
    hard_autonomy = AutonomyProjection(
        experiment_id=EXPERIMENT_ID,
        manifest_digest=manifest.digest,
        retry=None,
        experimental_publication=ExperimentalPublication(
            branch=f"experimental/{EXPERIMENT_ID}",
            commit=disposable_git.hard_regression_candidate,
            tree=disposable_git.hard_regression_tree,
            candidate_packet_digest="7" * 64,
        ),
        protected_validation=ProtectedValidation(
            candidate_commit=disposable_git.hard_regression_candidate,
            candidate_tree=disposable_git.hard_regression_tree,
            receipt_digest=hard_receipt_digest,
        ),
        promotion=PromotionRecord(
            merge_commit=regression_merge,
            merge_tree=regression_tree,
            merged_at="2026-08-19T12:00:00Z",
        ),
        soak_observations=(
            SoakObservation(
                merge_commit=regression_merge,
                observed_at="2026-08-19T13:00:00Z",
                healthy=False,
                evidence_digest=hard_failure_digest,
            ),
        ),
        revert=None,
    )
    initial_revert = RevertSnapshot(
        promotion_id=hard_request.promotion_id,
        merge_commit=regression_merge,
        hard_failure=True,
        revert_pull_request=None,
        revert_candidate_commit=None,
        expected_restored_tree=disposable_git.baseline_tree,
        production_commit=regression_merge,
        production_tree=regression_tree,
        reverted_commit=None,
    )
    hard_snapshot = ControllerSnapshot(
        autonomy=hard_autonomy,
        capability_report=None,
        protected_validation=None,
        protected_public_key_pem=None,
        promotion_expectation=None,
        promotion_request=hard_request,
        promotion_snapshot=PromotionSnapshot(
            production_commit=regression_merge,
            active_promotion_id=hard_request.promotion_id,
            pull_request=None,
        ),
        required_checks=APPROVED_REQUIRED_CHECKS,
        revert_snapshot=initial_revert,
    )
    create_revert = next_controller_action(
        hard_snapshot,
        datetime(2026, 8, 19, 13, tzinfo=UTC),
    )
    duplicate_revert_tick = next_controller_action(
        hard_snapshot,
        datetime(2026, 8, 19, 13, tzinfo=UTC),
    )
    assert create_revert.action == "create_revert_pr"
    assert duplicate_revert_tick == create_revert
    assert create_revert.restored_tree == disposable_git.baseline_tree

    _git(disposable_git.builder, "revert", "-m", "1", "--no-edit", regression_merge)
    revert_commit = _git(disposable_git.builder, "rev-parse", "HEAD")
    restored_tree = _git(disposable_git.builder, "rev-parse", "HEAD^{tree}")
    assert restored_tree == disposable_git.baseline_tree
    assert (
        _git(
            disposable_git.builder,
            "rev-list",
            "--count",
            f"{regression_merge}..{revert_commit}",
        )
        == "1"
    )
    revert_pr = PullRequestSnapshot(
        number=42,
        url="https://github.com/fixture/carl-agent/pull/42",
        state="MERGED",
        is_draft=False,
        base_branch="main",
        head_branch=f"revert/{hard_request.promotion_id}",
        head_commit=revert_commit,
        head_tree=restored_tree,
        merge_state="CLEAN",
        checks=tuple(
            CheckRun(name=name, conclusion="SUCCESS", app_id=15368)
            for name in APPROVED_REQUIRED_CHECKS
        ),
        merge_commit=revert_commit,
        merge_tree=restored_tree,
        auto_merge_enabled=True,
    )
    reconciled_revert = replace(
        initial_revert,
        revert_pull_request=revert_pr,
        revert_candidate_commit=revert_commit,
        production_commit=revert_commit,
        production_tree=restored_tree,
        reverted_commit=revert_commit,
    )
    recorded_revert = next_controller_action(
        replace(hard_snapshot, revert_snapshot=reconciled_revert),
        datetime(2026, 8, 19, 14, tzinfo=UTC),
    )
    assert recorded_revert.action == "record_reverted"
    assert recorded_revert.revert_pull_request_number == 42
    assert recorded_revert.revert_merge_commit == revert_commit
    assert recorded_revert.restored_tree == disposable_git.baseline_tree

    ledger_digest = _sha256(ledger_path.read_bytes())
    synthetic_receipt = SyntheticCommissioningReceipt(
        schema_version=1,
        synthetic_test_only=True,
        experiment_id=EXPERIMENT_ID,
        terminal_state="accepted",
        experimental_ref=f"refs/heads/experimental/{EXPERIMENT_ID}",
        candidate_commit=disposable_git.valid_candidate,
        candidate_tree=disposable_git.valid_tree,
        promotion_id=request.promotion_id,
        pull_request_number=41,
        merge_commit=merged_pr.merge_commit,
        restart_recoveries=restart_recoveries,
        lifecycle_ledger_digest=ledger_digest,
        protected_receipt_digest=protected_receipt.digest,
        capability_report_digest=capability_report.digest,
        prompt_portfolio_digest=prompt_portfolio_digest,
        supervisor_result_digest=supervisor_result_digest,
        remote_cloud_acceptance="uncommissioned",
        adversarial_outcomes=(
            "benchmark_gaming_rejected",
            "changed_main_rejected",
            "controller_effect_recovered",
            "duplicate_tick_idempotent",
            "evaluator_alteration_rejected",
            "exact_revert_restored_tree",
            "receipt_replay_rejected",
            "tampered_evidence_rejected",
        ),
    )
    with pytest.raises(
        CommissioningArtifactError,
        match="caller_authored_commissioning_receipt_forbidden",
    ):
        commissioning_store.persist_synthetic(synthetic_receipt)
    assert not commissioning_store.index_path.exists()


def _synthetic_receipt() -> SyntheticCommissioningReceipt:
    return SyntheticCommissioningReceipt(
        schema_version=1,
        synthetic_test_only=True,
        experiment_id="exp-commissioning-001",
        terminal_state="accepted",
        experimental_ref="refs/heads/experimental/exp-commissioning-001",
        candidate_commit="1" * 40,
        candidate_tree="2" * 40,
        promotion_id="promotion-exp-commissioning-001-1",
        pull_request_number=41,
        merge_commit="3" * 40,
        restart_recoveries=3,
        lifecycle_ledger_digest="4" * 64,
        protected_receipt_digest="5" * 64,
        capability_report_digest="6" * 64,
        prompt_portfolio_digest="7" * 64,
        supervisor_result_digest="8" * 64,
        remote_cloud_acceptance="uncommissioned",
        adversarial_outcomes=(
            "benchmark_gaming_rejected",
            "changed_main_rejected",
            "controller_effect_recovered",
            "duplicate_tick_idempotent",
            "evaluator_alteration_rejected",
            "exact_revert_restored_tree",
            "receipt_replay_rejected",
            "tampered_evidence_rejected",
        ),
    )


def test_caller_authored_commissioning_receipt_cannot_create_passing_report(
    tmp_path: Path,
) -> None:
    automation_data_root = tmp_path / ".codex" / "automations"
    automation_data_root.mkdir(mode=0o755, parents=True)
    automation_data_root.chmod(0o755)
    store = CommissioningArtifactStore(
        automation_data_root=automation_data_root,
        repository_root=REPOSITORY_ROOT,
    )

    with pytest.raises(
        CommissioningArtifactError,
        match="caller_authored_commissioning_receipt_forbidden",
    ):
        store.persist_synthetic(_synthetic_receipt())

    assert stat.S_IMODE(automation_data_root.stat().st_mode) == 0o755
    for directory in (store.private_root, store.root, store.objects_root):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert tuple(store.objects_root.iterdir()) == ()
    assert not store.index_path.exists()


def test_legacy_unverified_commissioning_index_is_rejected(tmp_path: Path) -> None:
    automation_data_root = tmp_path / ".codex" / "automations"
    store = CommissioningArtifactStore(
        automation_data_root=automation_data_root,
        repository_root=REPOSITORY_ROOT,
    )
    store._persist_verified_receipt(_synthetic_receipt())

    with pytest.raises(
        CommissioningArtifactError,
        match="commissioning_verified_sources_required",
    ):
        CommissioningArtifactStore(
            automation_data_root=automation_data_root,
            repository_root=REPOSITORY_ROOT,
        ).load_latest_synthetic()


def test_synthetic_commissioning_artifacts_cannot_claim_remote_acceptance_or_live_status(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        CommissioningArtifactError,
        match="synthetic_cloud_acceptance_must_be_uncommissioned",
    ):
        SyntheticCommissioningReceipt(
            **{
                **_synthetic_receipt().to_canonical_dict(),
                "remote_cloud_acceptance": "commissioned",
                "adversarial_outcomes": _synthetic_receipt().adversarial_outcomes,
            }
        )

    with pytest.raises(
        CommissioningArtifactError,
        match="commissioning_store_inside_repository",
    ):
        CommissioningArtifactStore(
            automation_data_root=REPOSITORY_ROOT / ".private-commissioning",
            repository_root=REPOSITORY_ROOT,
        )
