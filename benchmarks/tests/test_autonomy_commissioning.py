from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
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
from carl_bench.candidate import DeterministicCheckResult, SealedCandidate
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
from carl_bench.experiment import EventType, ExperimentEvent
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
    valid_tree = _git(builder, "rev-parse", "HEAD^{tree}")

    _git(builder, "switch", "-c", "candidate-benchmark-gamed", baseline)
    benchmark_gamed_candidate = _write_commit(
        builder,
        "benchmarks/tasks/public/task.toml",
        "score = 10000\nfixture = 'hard-coded'\n",
        "game public benchmark",
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


def test_autonomy_loop_commissions_healthy_and_adversarial_paths_without_network(
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
    artifacts = commissioning_store.persist_synthetic(synthetic_receipt)
    assert artifacts.report.status == "synthetic_passed"
    assert artifacts.report.terminal_state == "accepted"
    assert artifacts.report.remote_cloud_acceptance == "uncommissioned"
    assert artifacts.report.restart_recoveries >= 2
    assert (
        CommissioningArtifactStore(
            automation_data_root=automation_data_root,
            repository_root=disposable_git.builder,
        ).load_latest_synthetic()
        == artifacts
    )


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


def test_synthetic_commissioning_artifacts_are_private_sanitized_and_restart_safe(
    tmp_path: Path,
) -> None:
    automation_data_root = tmp_path / ".codex" / "automations"
    automation_data_root.mkdir(mode=0o755, parents=True)
    automation_data_root.chmod(0o755)
    store = CommissioningArtifactStore(
        automation_data_root=automation_data_root,
        repository_root=REPOSITORY_ROOT,
    )

    first = store.persist_synthetic(_synthetic_receipt())
    replay = CommissioningArtifactStore(
        automation_data_root=automation_data_root,
        repository_root=REPOSITORY_ROOT,
    ).persist_synthetic(_synthetic_receipt())
    reopened = CommissioningArtifactStore(
        automation_data_root=automation_data_root,
        repository_root=REPOSITORY_ROOT,
    ).load_latest_synthetic()

    assert replay == first
    assert reopened == first
    assert first.report.synthetic_test_only is True
    assert first.report.remote_cloud_acceptance == "uncommissioned"
    assert first.report.artifact_digests == (
        ("capability_report", "6" * 64),
        ("lifecycle_ledger", "4" * 64),
        ("prompt_portfolio", "7" * 64),
        ("protected_receipt", "5" * 64),
        ("supervisor_result", "8" * 64),
        ("synthetic_receipt", first.receipt_ref.digest),
    )
    assert first.report_ref.digest == first.report.digest

    report_content = store.read(first.report_ref)
    assert json.loads(report_content) == first.report.to_canonical_dict()
    serialized = report_content.decode("utf-8")
    assert "private_key" not in serialized
    assert "signature_base64" not in serialized
    assert os.fspath(REPOSITORY_ROOT) not in serialized

    assert stat.S_IMODE(automation_data_root.stat().st_mode) == 0o755
    for directory in (store.private_root, store.root, store.objects_root):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for file_path in (store.index_path, *store.objects_root.iterdir()):
        assert stat.S_IMODE(file_path.stat().st_mode) == 0o600


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
