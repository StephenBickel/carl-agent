"""Protected command-based evaluator for local synthetic commissioning."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from carl_bench.artifacts import ArtifactRef, PrivateArtifactStore
from carl_bench.canonical import canonical_json_bytes
from carl_bench.capability_validation import (
    CapabilityClaim,
    CapabilityValidationReport,
    TaskOutcome,
    TransferCheck,
    evaluate_capability_validation,
)
from carl_bench.commissioning import CommissioningArtifactError

_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_SOCKET_GUARD = b"""import socket as _socket

def _deny(*_args, **_kwargs):
    raise PermissionError("commissioning_socket_denied")

class _DeniedSocket(_socket.socket):
    def connect(self, *_args, **_kwargs):
        return _deny()

    def connect_ex(self, *_args, **_kwargs):
        return _deny()

_socket.socket = _DeniedSocket
_socket.create_connection = _deny
_socket.getaddrinfo = _deny
"""


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
        raise CommissioningArtifactError(code)
    return value


def _object(value: object, code: str) -> str:
    if not isinstance(value, str) or _OBJECT_RE.fullmatch(value) is None:
        raise CommissioningArtifactError(code)
    return value


def _owner_private_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return False
    return os.name == "nt" or not (
        stat.S_IMODE(metadata.st_mode) & 0o077
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    )


def _prepare_private_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        if not _owner_private_directory(path):
            raise CommissioningArtifactError("synthetic_runner_root_unsafe")
        return
    try:
        path.mkdir(mode=0o700, parents=True)
        if os.name != "nt":
            path.chmod(0o700)
    except OSError as error:
        raise CommissioningArtifactError("synthetic_runner_root_unavailable") from error
    if not _owner_private_directory(path):
        raise CommissioningArtifactError("synthetic_runner_root_unsafe")


def _safe_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise CommissioningArtifactError("invalid_synthetic_subject_path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise CommissioningArtifactError("invalid_synthetic_subject_path")
    return value


@dataclass(frozen=True, slots=True)
class EvaluatorTask:
    task_id: str
    role: str
    input: dict[str, Any]
    expected: dict[str, Any]
    minimum_candidate_basis_points: int

    @classmethod
    def from_canonical_dict(cls, value: Any) -> EvaluatorTask:
        expected_keys = {
            "expected",
            "input",
            "minimum_candidate_basis_points",
            "role",
            "task_id",
        }
        if not isinstance(value, dict) or set(value) != expected_keys:
            raise CommissioningArtifactError("invalid_protected_evaluator_task")
        try:
            task = cls(**value)
        except TypeError as error:
            raise CommissioningArtifactError("invalid_protected_evaluator_task") from error
        _identifier(task.task_id, "invalid_protected_evaluator_task")
        if task.role not in {"affected", "guard", "held_out"}:
            raise CommissioningArtifactError("invalid_protected_evaluator_role")
        if not isinstance(task.input, dict) or not isinstance(task.expected, dict):
            raise CommissioningArtifactError("invalid_protected_evaluator_task")
        if (
            isinstance(task.minimum_candidate_basis_points, bool)
            or not isinstance(task.minimum_candidate_basis_points, int)
            or not 0 <= task.minimum_candidate_basis_points <= 10_000
        ):
            raise CommissioningArtifactError("invalid_protected_evaluator_threshold")
        canonical_json_bytes(task.input)
        canonical_json_bytes(task.expected)
        return task

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "expected": self.expected,
            "input": self.input,
            "minimum_candidate_basis_points": self.minimum_candidate_basis_points,
            "role": self.role,
            "task_id": self.task_id,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class ProtectedEvaluator:
    schema_version: int
    claim_id: str
    claim_type: str
    behavior: str
    subject_path: str
    tasks: tuple[EvaluatorTask, ...]

    @classmethod
    def from_bytes(cls, content: bytes) -> ProtectedEvaluator:
        try:
            value = json.loads(content)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise CommissioningArtifactError("invalid_protected_evaluator") from error
        expected = {
            "behavior",
            "claim_id",
            "claim_type",
            "schema_version",
            "subject_path",
            "tasks",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise CommissioningArtifactError("invalid_protected_evaluator")
        if not isinstance(value["tasks"], list):
            raise CommissioningArtifactError("invalid_protected_evaluator")
        normalized = dict(value)
        normalized["tasks"] = tuple(
            EvaluatorTask.from_canonical_dict(item) for item in value["tasks"]
        )
        try:
            evaluator = cls(**normalized)
        except TypeError as error:
            raise CommissioningArtifactError("invalid_protected_evaluator") from error
        if evaluator.schema_version != 1:
            raise CommissioningArtifactError("invalid_protected_evaluator_schema")
        _identifier(evaluator.claim_id, "invalid_protected_evaluator_claim")
        if evaluator.claim_type not in {"capability", "compatibility", "correctness"}:
            raise CommissioningArtifactError("invalid_protected_evaluator_claim")
        if (
            not isinstance(evaluator.behavior, str)
            or not evaluator.behavior.strip()
            or len(evaluator.behavior.encode("utf-8")) > 2_048
        ):
            raise CommissioningArtifactError("invalid_protected_evaluator_behavior")
        _safe_relative_path(evaluator.subject_path)
        task_ids = tuple(task.task_id for task in evaluator.tasks)
        if not task_ids or task_ids != tuple(sorted(set(task_ids))):
            raise CommissioningArtifactError("invalid_protected_evaluator_tasks")
        roles = {task.role for task in evaluator.tasks}
        if roles != {"affected", "guard", "held_out"}:
            raise CommissioningArtifactError("invalid_protected_evaluator_roles")
        return evaluator

    def capability_claim(self, evaluator_digest: str) -> CapabilityClaim:
        affected = tuple(task.task_id for task in self.tasks if task.role == "affected")
        guards = tuple(task.task_id for task in self.tasks if task.role == "guard")
        transfers = tuple(
            TransferCheck(
                check_id=f"transfer-{task.task_id}",
                task_id=task.task_id,
                check_type="held_out",
                evaluator_digest=evaluator_digest,
                minimum_candidate_basis_points=task.minimum_candidate_basis_points,
            )
            for task in self.tasks
            if task.role == "held_out"
        )
        return CapabilityClaim(
            claim_id=self.claim_id,
            claim_type=self.claim_type,
            behavior=self.behavior,
            affected_task_ids=affected,
            guard_task_ids=guards,
            transfer_checks=transfers,
        )


@dataclass(frozen=True, slots=True)
class ProtectedPairEvaluation:
    report: CapabilityValidationReport
    evaluator_ref: ArtifactRef
    execution_bundle_ref: ArtifactRef
    capability_report_ref: ArtifactRef
    evidence_bundle_ref: ArtifactRef


@dataclass(frozen=True, slots=True)
class VerifiedProtectedPairEvaluation:
    """A protected evaluation rebuilt from evaluator and command-output bytes."""

    report: CapabilityValidationReport
    baseline_commit: str
    baseline_tree: str
    candidate_commit: str
    candidate_tree: str
    changed_paths: tuple[str, ...]
    artifact_refs: tuple[tuple[str, ArtifactRef], ...]


def _typed_artifact_ref(
    value: Any,
    *,
    evidence_kind: str,
    media_type: str,
    code: str,
) -> ArtifactRef:
    try:
        ref = ArtifactRef.from_canonical_dict(value)
    except (TypeError, ValueError) as error:
        raise CommissioningArtifactError(code) from error
    if ref.evidence_kind != evidence_kind or ref.media_type != media_type:
        raise CommissioningArtifactError(code)
    return ref


def _json_object(content: bytes, expected: set[str], code: str) -> dict[str, Any]:
    try:
        value = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CommissioningArtifactError(code) from error
    if not isinstance(value, dict) or set(value) != expected:
        raise CommissioningArtifactError(code)
    return value


def _rebuild_execution_side(
    *,
    artifacts: PrivateArtifactStore,
    side_name: str,
    value: Any,
    evaluator: ProtectedEvaluator,
    evaluator_ref: ArtifactRef,
) -> tuple[tuple[TaskOutcome, ...], str, str, tuple[tuple[str, ArtifactRef], ...]]:
    if not isinstance(value, dict) or set(value) != {
        "outcomes",
        "subject_commit",
        "subject_tree",
        "trials",
    }:
        raise CommissioningArtifactError("invalid_protected_execution_bundle")
    commit = _object(value["subject_commit"], "invalid_synthetic_subject_commit")
    tree = _object(value["subject_tree"], "invalid_synthetic_subject_tree")
    trials = value["trials"]
    if not isinstance(trials, list) or len(trials) != len(evaluator.tasks):
        raise CommissioningArtifactError("invalid_protected_execution_trials")

    outcomes: list[TaskOutcome] = []
    refs: list[tuple[str, ArtifactRef]] = []
    for task, trial in zip(evaluator.tasks, trials, strict=True):
        if not isinstance(trial, dict) or set(trial) != {
            "command_exit_code",
            "evaluator_digest",
            "expected",
            "stderr_ref",
            "stdout_ref",
            "subject_commit",
            "task_digest",
            "task_id",
            "valid",
        }:
            raise CommissioningArtifactError("invalid_protected_execution_trial")
        exit_code = trial["command_exit_code"]
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise CommissioningArtifactError("invalid_protected_execution_trial")
        if (
            trial["evaluator_digest"] != evaluator_ref.digest
            or trial["expected"] != task.expected
            or trial["subject_commit"] != commit
            or trial["task_digest"] != task.digest
            or trial["task_id"] != task.task_id
            or not isinstance(trial["valid"], bool)
        ):
            raise CommissioningArtifactError("protected_execution_identity_mismatch")
        stdout_ref = _typed_artifact_ref(
            trial["stdout_ref"],
            evidence_kind="command_stdout",
            media_type="application/json",
            code="invalid_protected_stdout_ref",
        )
        stderr_ref = _typed_artifact_ref(
            trial["stderr_ref"],
            evidence_kind="command_stderr",
            media_type="text/plain",
            code="invalid_protected_stderr_ref",
        )
        stdout = artifacts.read(stdout_ref)
        stderr = artifacts.read(stderr_ref)
        if b"commissioning_socket_denied" in stderr:
            raise CommissioningArtifactError("synthetic_subject_network_denied")
        parsed: Any = None
        valid = exit_code == 0
        if valid:
            try:
                parsed = json.loads(stdout)
            except (UnicodeError, json.JSONDecodeError):
                valid = False
        if trial["valid"] is not valid:
            raise CommissioningArtifactError("protected_execution_validity_mismatch")
        passed = valid and parsed == task.expected
        trial_id = f"trial-{task.task_id}"
        outcomes.append(
            TaskOutcome(
                task_id=task.task_id,
                task_digest=task.digest,
                evaluator_digest=evaluator_ref.digest,
                score_basis_points=10_000 if passed else 0,
                valid_trials=(trial_id,) if valid else (),
                invalid_trials=() if valid else (trial_id,),
                passed_trials=(trial_id,) if passed else (),
                failed_trials=(trial_id,) if valid and not passed else (),
            )
        )
        refs.extend(
            (
                (f"{side_name}_{task.task_id}_stderr", stderr_ref),
                (f"{side_name}_{task.task_id}_stdout", stdout_ref),
            )
        )
    derived = tuple(outcomes)
    if value["outcomes"] != [item.to_canonical_dict() for item in derived]:
        raise CommissioningArtifactError("protected_execution_outcome_mismatch")
    return derived, commit, tree, tuple(refs)


def verify_protected_pair_evaluation(
    *,
    artifacts: PrivateArtifactStore,
    evidence_bundle_ref: ArtifactRef,
) -> VerifiedProtectedPairEvaluation:
    """Recompute a paired report without trusting persisted scores or validity flags."""
    if not isinstance(artifacts, PrivateArtifactStore):
        raise CommissioningArtifactError("invalid_synthetic_artifact_store")
    if (
        not isinstance(evidence_bundle_ref, ArtifactRef)
        or evidence_bundle_ref.evidence_kind != "capability_evidence_bundle"
        or evidence_bundle_ref.media_type != "application/json"
    ):
        raise CommissioningArtifactError("invalid_capability_evidence_bundle_ref")
    bundle = _json_object(
        artifacts.read(evidence_bundle_ref),
        {
            "capability_report_ref",
            "changed_paths",
            "claim",
            "evaluator_ref",
            "execution_bundle_ref",
            "schema_version",
        },
        "invalid_capability_evidence_bundle",
    )
    if bundle["schema_version"] != 1:
        raise CommissioningArtifactError("invalid_capability_evidence_bundle")
    evaluator_ref = _typed_artifact_ref(
        bundle["evaluator_ref"],
        evidence_kind="protected_evaluator",
        media_type="application/json",
        code="invalid_protected_evaluator_ref",
    )
    execution_ref = _typed_artifact_ref(
        bundle["execution_bundle_ref"],
        evidence_kind="protected_execution_bundle",
        media_type="application/json",
        code="invalid_protected_execution_bundle_ref",
    )
    report_ref = _typed_artifact_ref(
        bundle["capability_report_ref"],
        evidence_kind="capability_report",
        media_type="application/json",
        code="invalid_capability_report_ref",
    )
    evaluator = ProtectedEvaluator.from_bytes(artifacts.read(evaluator_ref))
    claim = evaluator.capability_claim(evaluator_ref.digest)
    if bundle["claim"] != claim.to_canonical_dict():
        raise CommissioningArtifactError("protected_capability_claim_mismatch")
    changed_paths_value = bundle["changed_paths"]
    if not isinstance(changed_paths_value, list) or any(
        not isinstance(path, str) for path in changed_paths_value
    ):
        raise CommissioningArtifactError("invalid_synthetic_changed_paths")
    changed_paths = tuple(changed_paths_value)
    execution = _json_object(
        artifacts.read(execution_ref),
        {"baseline", "candidate", "evaluator_ref", "schema_version"},
        "invalid_protected_execution_bundle",
    )
    if execution["schema_version"] != 1 or execution["evaluator_ref"] != (
        evaluator_ref.to_canonical_dict()
    ):
        raise CommissioningArtifactError("protected_execution_identity_mismatch")
    baseline, baseline_commit, baseline_tree, baseline_refs = _rebuild_execution_side(
        artifacts=artifacts,
        side_name="baseline",
        value=execution["baseline"],
        evaluator=evaluator,
        evaluator_ref=evaluator_ref,
    )
    candidate, candidate_commit, candidate_tree, candidate_refs = _rebuild_execution_side(
        artifacts=artifacts,
        side_name="candidate",
        value=execution["candidate"],
        evaluator=evaluator,
        evaluator_ref=evaluator_ref,
    )
    report = evaluate_capability_validation(
        claim,
        baseline,
        candidate,
        changed_paths,
    )
    if artifacts.read(report_ref) != canonical_json_bytes(report.to_canonical_dict()):
        raise CommissioningArtifactError("protected_capability_report_mismatch")
    refs = tuple(
        sorted(
            (
                ("capability_evidence_bundle", evidence_bundle_ref),
                ("capability_report", report_ref),
                ("protected_evaluator", evaluator_ref),
                ("protected_execution_bundle", execution_ref),
                *baseline_refs,
                *candidate_refs,
            )
        )
    )
    return VerifiedProtectedPairEvaluation(
        report=report,
        baseline_commit=baseline_commit,
        baseline_tree=baseline_tree,
        candidate_commit=candidate_commit,
        candidate_tree=candidate_tree,
        changed_paths=changed_paths,
        artifact_refs=refs,
    )


class ProtectedSyntheticRunner:
    """Run exact commits against protected tasks with Python socket access denied."""

    def __init__(
        self,
        *,
        artifacts: PrivateArtifactStore,
        protected_root: Path,
        source_repository: Path,
    ) -> None:
        if not isinstance(artifacts, PrivateArtifactStore):
            raise CommissioningArtifactError("invalid_synthetic_artifact_store")
        self.artifacts = artifacts
        self.protected_root = protected_root.expanduser().absolute()
        _prepare_private_directory(self.protected_root)
        source = source_repository.expanduser().absolute()
        if not source.is_dir() or "://" in os.fspath(source):
            raise CommissioningArtifactError("invalid_synthetic_source_repository")
        self.source_repository = source
        self.guard_root = self.protected_root / "socket-guard"
        _prepare_private_directory(self.guard_root)
        guard = self.guard_root / "sitecustomize.py"
        if guard.exists():
            if guard.read_bytes() != _SOCKET_GUARD:
                raise CommissioningArtifactError("synthetic_socket_guard_mismatch")
        else:
            guard.write_bytes(_SOCKET_GUARD)
            if os.name != "nt":
                guard.chmod(0o600)

    @staticmethod
    def _git(*arguments: str, cwd: Path | None = None) -> str:
        try:
            completed = subprocess.run(
                ("git", *arguments),
                cwd=cwd,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise CommissioningArtifactError("synthetic_git_failed") from error
        return completed.stdout.strip()

    def _checkout(self, commit: str, destination: Path) -> None:
        _object(commit, "invalid_synthetic_subject_commit")
        self._git(
            "clone",
            "--quiet",
            "--no-checkout",
            os.fspath(self.source_repository),
            os.fspath(destination),
        )
        self._git("checkout", "--quiet", "--detach", commit, cwd=destination)
        if self._git("rev-parse", "HEAD", cwd=destination) != commit:
            raise CommissioningArtifactError("synthetic_checkout_identity_mismatch")

    def _trial(
        self,
        *,
        checkout: Path,
        subject_commit: str,
        evaluator: ProtectedEvaluator,
        evaluator_ref: ArtifactRef,
        task: EvaluatorTask,
    ) -> tuple[TaskOutcome, dict[str, Any]]:
        subject = checkout / evaluator.subject_path
        if not subject.is_file() or subject.is_symlink():
            raise CommissioningArtifactError("synthetic_subject_missing")
        environment = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.fspath(self.guard_root),
            "PYTHONSAFEPATH": "1",
        }
        try:
            completed = subprocess.run(
                (sys.executable, os.fspath(subject)),
                cwd=checkout,
                input=canonical_json_bytes(task.input).decode("utf-8") + "\n",
                capture_output=True,
                text=True,
                timeout=10,
                env=environment,
            )
            exit_code = completed.returncode
            stdout = completed.stdout.encode("utf-8")
            stderr = completed.stderr.encode("utf-8")
        except subprocess.TimeoutExpired as error:
            exit_code = 124
            stdout = (error.stdout or b"") if isinstance(error.stdout, bytes) else b""
            stderr = (error.stderr or b"") if isinstance(error.stderr, bytes) else b""
        if b"commissioning_socket_denied" in stderr:
            raise CommissioningArtifactError("synthetic_subject_network_denied")
        stdout_ref = self.artifacts.put(
            evidence_kind="command_stdout",
            media_type="application/json",
            content=stdout,
        )
        stderr_ref = self.artifacts.put(
            evidence_kind="command_stderr",
            media_type="text/plain",
            content=stderr,
        )
        trial_id = f"trial-{task.task_id}"
        parsed: Any = None
        valid = exit_code == 0
        if valid:
            try:
                parsed = json.loads(stdout)
            except (UnicodeError, json.JSONDecodeError):
                valid = False
        passed = valid and parsed == task.expected
        outcome = TaskOutcome(
            task_id=task.task_id,
            task_digest=task.digest,
            evaluator_digest=evaluator_ref.digest,
            score_basis_points=10_000 if passed else 0,
            valid_trials=(trial_id,) if valid else (),
            invalid_trials=() if valid else (trial_id,),
            passed_trials=(trial_id,) if passed else (),
            failed_trials=(trial_id,) if valid and not passed else (),
        )
        trial = {
            "command_exit_code": exit_code,
            "evaluator_digest": evaluator_ref.digest,
            "expected": task.expected,
            "stderr_ref": stderr_ref.to_canonical_dict(),
            "stdout_ref": stdout_ref.to_canonical_dict(),
            "subject_commit": subject_commit,
            "task_digest": task.digest,
            "task_id": task.task_id,
            "valid": valid,
        }
        return outcome, trial

    def _evaluate_commit(
        self,
        *,
        checkout: Path,
        commit: str,
        evaluator: ProtectedEvaluator,
        evaluator_ref: ArtifactRef,
    ) -> tuple[tuple[TaskOutcome, ...], dict[str, Any]]:
        outcomes: list[TaskOutcome] = []
        trials: list[dict[str, Any]] = []
        for task in evaluator.tasks:
            outcome, trial = self._trial(
                checkout=checkout,
                subject_commit=commit,
                evaluator=evaluator,
                evaluator_ref=evaluator_ref,
                task=task,
            )
            outcomes.append(outcome)
            trials.append(trial)
        return tuple(outcomes), {
            "outcomes": [item.to_canonical_dict() for item in outcomes],
            "subject_commit": commit,
            "subject_tree": self._git("rev-parse", "HEAD^{tree}", cwd=checkout),
            "trials": trials,
        }

    def evaluate_pair(
        self,
        *,
        baseline_commit: str,
        candidate_commit: str,
        evaluator_ref: ArtifactRef,
        changed_paths: tuple[str, ...],
    ) -> ProtectedPairEvaluation:
        _object(baseline_commit, "invalid_synthetic_baseline_commit")
        _object(candidate_commit, "invalid_synthetic_candidate_commit")
        if baseline_commit == candidate_commit:
            raise CommissioningArtifactError("synthetic_candidate_equals_baseline")
        if (
            not isinstance(evaluator_ref, ArtifactRef)
            or evaluator_ref.evidence_kind != "protected_evaluator"
            or evaluator_ref.media_type != "application/json"
        ):
            raise CommissioningArtifactError("invalid_protected_evaluator_ref")
        if not isinstance(changed_paths, tuple) or any(
            not isinstance(path, str) for path in changed_paths
        ):
            raise CommissioningArtifactError("invalid_synthetic_changed_paths")
        evaluator_bytes = self.artifacts.read(evaluator_ref)
        if hashlib.sha256(evaluator_bytes).hexdigest() != evaluator_ref.digest:
            raise CommissioningArtifactError("protected_evaluator_digest_mismatch")
        evaluator = ProtectedEvaluator.from_bytes(evaluator_bytes)
        run_root = Path(tempfile.mkdtemp(prefix="paired-", dir=self.protected_root))
        if os.name != "nt":
            run_root.chmod(0o700)
        try:
            baseline_checkout = run_root / "baseline"
            candidate_checkout = run_root / "candidate"
            self._checkout(baseline_commit, baseline_checkout)
            self._checkout(candidate_commit, candidate_checkout)
            baseline, baseline_execution = self._evaluate_commit(
                checkout=baseline_checkout,
                commit=baseline_commit,
                evaluator=evaluator,
                evaluator_ref=evaluator_ref,
            )
            candidate, candidate_execution = self._evaluate_commit(
                checkout=candidate_checkout,
                commit=candidate_commit,
                evaluator=evaluator,
                evaluator_ref=evaluator_ref,
            )
        finally:
            shutil.rmtree(run_root, ignore_errors=True)
        execution_ref = self.artifacts.put(
            evidence_kind="protected_execution_bundle",
            media_type="application/json",
            content=canonical_json_bytes(
                {
                    "baseline": baseline_execution,
                    "candidate": candidate_execution,
                    "evaluator_ref": evaluator_ref.to_canonical_dict(),
                    "schema_version": 1,
                }
            ),
        )
        claim = evaluator.capability_claim(evaluator_ref.digest)
        report = evaluate_capability_validation(
            claim,
            baseline,
            candidate,
            changed_paths,
        )
        report_ref = self.artifacts.put(
            evidence_kind="capability_report",
            media_type="application/json",
            content=canonical_json_bytes(report.to_canonical_dict()),
        )
        bundle_ref = self.artifacts.put(
            evidence_kind="capability_evidence_bundle",
            media_type="application/json",
            content=canonical_json_bytes(
                {
                    "capability_report_ref": report_ref.to_canonical_dict(),
                    "changed_paths": list(changed_paths),
                    "claim": claim.to_canonical_dict(),
                    "evaluator_ref": evaluator_ref.to_canonical_dict(),
                    "execution_bundle_ref": execution_ref.to_canonical_dict(),
                    "schema_version": 1,
                }
            ),
        )
        return ProtectedPairEvaluation(
            report=report,
            evaluator_ref=evaluator_ref,
            execution_bundle_ref=execution_ref,
            capability_report_ref=report_ref,
            evidence_bundle_ref=bundle_ref,
        )
