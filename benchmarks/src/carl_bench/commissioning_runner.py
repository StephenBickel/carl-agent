"""Protected command-based evaluator for local synthetic commissioning."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from carl_bench.artifacts import ArtifactRef, PrivateArtifactStore
from carl_bench.candidate import DeterministicCheckResult, PairedEvidence, SealedCandidate
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
_MAX_COMMAND_OUTPUT_BYTES = 65_536
_SANDBOX_DIAGNOSTIC_PREFIX = b"carl-protected-run:"


def _sandbox_environment(writable_root: Path) -> dict[str, str]:
    root = writable_root.expanduser().absolute()
    return {
        "HOME": os.fspath(root),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.pathsep.join(("/usr/bin", "/bin")),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONSAFEPATH": "1",
        "TMPDIR": os.fspath(root),
        "XDG_CACHE_HOME": os.fspath(root),
    }


def _sandbox_path(path: Path) -> Path:
    return Path(os.path.realpath(path.expanduser().absolute()))


def _sandbox_path_variants(path: Path) -> tuple[Path, ...]:
    lexical = path.expanduser().absolute()
    resolved = _sandbox_path(path)
    return tuple(dict.fromkeys((lexical, resolved)))


def _sbpl_literal(path: Path) -> str:
    value = os.fspath(path.expanduser().absolute())
    if "\0" in value or "\n" in value or "\r" in value:
        raise CommissioningArtifactError("invalid_synthetic_sandbox_path")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _macos_sandbox_profile(
    readonly_paths: tuple[Path, ...],
    writable_paths: tuple[Path, ...],
) -> str:
    reads = " ".join(f'(subpath "{_sbpl_literal(path)}")' for path in readonly_paths)
    writes = " ".join(f'(subpath "{_sbpl_literal(path)}")' for path in writable_paths)
    return " ".join(
        (
            "(version 1)",
            "(deny default)",
            '(import "system.sb")',
            "(allow process*)",
            "(allow signal (target self))",
            f'(allow file-read* {reads} (literal "/dev/null") (literal "/dev/urandom"))',
            f"(allow file-map-executable {reads})",
            f'(allow file-write* {writes} (literal "/dev/null"))',
            "(deny network*)",
        )
    )


def _linux_parent_directories(paths: tuple[Path, ...]) -> tuple[str, ...]:
    parents: set[str] = {"/dev", "/proc", "/tmp"}
    for path in paths:
        resolved = _sandbox_path(path)
        current = resolved if resolved.is_dir() else resolved.parent
        while current != current.parent:
            parents.add(os.fspath(current))
            current = current.parent
    return tuple(sorted(parents, key=lambda item: (item.count("/"), item)))


def _sandbox_command(
    command: tuple[str, ...],
    *,
    readonly_paths: tuple[Path, ...],
    writable_paths: tuple[Path, ...],
    platform: str = sys.platform,
    executable_lookup=shutil.which,
) -> tuple[str, ...]:
    if not command:
        raise CommissioningArtifactError("invalid_synthetic_sandbox_command")
    reads = tuple(
        dict.fromkeys(
            variant for path in readonly_paths for variant in _sandbox_path_variants(path)
        )
    )
    writes = tuple(
        dict.fromkeys(
            variant for path in writable_paths for variant in _sandbox_path_variants(path)
        )
    )
    if platform == "darwin":
        executable = Path("/usr/bin/sandbox-exec")
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise CommissioningArtifactError("synthetic_execution_sandbox_unavailable")
        return (
            os.fspath(executable),
            "-p",
            _macos_sandbox_profile(reads, writes),
            *command,
        )
    if platform.startswith("linux"):
        bubblewrap = executable_lookup("bwrap")
        sudo = executable_lookup("sudo")
        setpriv = executable_lookup("setpriv")
        if bubblewrap is None or sudo is None or setpriv is None:
            raise CommissioningArtifactError("synthetic_execution_sandbox_unavailable")
        prefix: list[str] = [
            sudo,
            "--non-interactive",
            bubblewrap,
            "--die-with-parent",
            "--new-session",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-ipc",
            "--unshare-cgroup-try",
            "--unshare-net",
            "--tmpfs",
            "/",
        ]
        for directory in _linux_parent_directories((*reads, *writes)):
            prefix.extend(("--dir", directory))
        prefix.extend(("--dev", "/dev", "--proc", "/proc"))
        for path in reads:
            value = os.fspath(path)
            prefix.extend(("--ro-bind", value, value))
        for path in writes:
            value = os.fspath(path)
            prefix.extend(("--bind", value, value))
        prefix.extend(
            (
                "--",
                setpriv,
                f"--reuid={os.getuid()}",
                f"--regid={os.getgid()}",
                "--clear-groups",
                "--bounding-set=-all",
                "--no-new-privs",
                "--",
            )
        )
        return (*prefix, *command)
    raise CommissioningArtifactError("synthetic_execution_sandbox_unavailable")


def _bounded_output(content: bytes, marker: bytes = b"truncated") -> bytes:
    if len(content) <= _MAX_COMMAND_OUTPUT_BYTES:
        return content
    suffix = b"\n" + _SANDBOX_DIAGNOSTIC_PREFIX + b" " + marker + b"\n"
    return content[: _MAX_COMMAND_OUTPUT_BYTES - len(suffix)] + suffix


def _launch_failure(code: bytes) -> tuple[int, bytes, bytes]:
    exit_codes = {
        b"executable_not_found": 127,
        b"permission_denied": 126,
        b"os_launch_error": 125,
    }
    return (
        exit_codes[code],
        b"",
        _SANDBOX_DIAGNOSTIC_PREFIX + b" " + code + b"\n",
    )


def _sandbox_failure_reason(stderr: bytes) -> str:
    lowered = stderr.lower()
    diagnostic = stderr.decode("ascii", errors="backslashreplace")[:240]
    diagnostic = re.sub(r"[^A-Za-z0-9 ._:/=+-]", "?", diagnostic).strip()
    reasons = (
        (b"operation not permitted", "operation_not_permitted"),
        (b"permission denied", "permission_denied"),
        (b"no such file or directory", "missing_path"),
        (b"not found", "missing_path"),
        (b"read-only file system", "readonly_filesystem"),
        (b"invalid argument", "invalid_argument"),
    )
    for marker, reason in reasons:
        if marker in lowered:
            return f"{reason}:{diagnostic}"
    return f"unknown:{diagnostic or 'empty_stderr'}"


def _toolchain_paths(command: tuple[str, ...]) -> tuple[Path, ...]:
    paths: list[Path] = []
    executable = command[0]
    resolved = executable if os.path.isabs(executable) else shutil.which(executable)
    if resolved is not None:
        paths.append(Path(resolved).parent)
    for prefix in {sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix}:
        paths.append(Path(prefix))
    xcode_selectors = {
        Path("/private/var/db/xcode_select_link"),
        Path("/var/db/xcode_select_link"),
    }
    for path in (
        Path("/bin"),
        Path("/usr/bin"),
        Path("/usr/lib"),
        Path("/usr/libexec"),
        Path("/System/Library"),
        Path("/Library/Apple"),
        Path("/Library/Developer/CommandLineTools"),
        Path("/Applications/Xcode.app/Contents/Developer"),
        Path("/private/var/db/xcode_select_link"),
        Path("/var/db/xcode_select_link"),
        Path("/private/var/select"),
        Path("/var/select"),
        Path("/lib"),
        Path("/lib64"),
        Path("/etc/ld.so.cache"),
    ):
        if path.exists() or (sys.platform == "darwin" and path in xcode_selectors):
            paths.append(path)
    return tuple(dict.fromkeys(path.expanduser().absolute() for path in paths))


def _run_sandboxed_command(
    command: tuple[str, ...],
    *,
    checkout: Path,
    writable_root: Path,
    input_bytes: bytes | None,
    timeout_seconds: int,
) -> tuple[int, bytes, bytes]:
    executable = command[0]
    resolved = executable if os.path.isabs(executable) else shutil.which(executable)
    if resolved is None or not Path(resolved).exists():
        return _launch_failure(b"executable_not_found")
    if not os.access(resolved, os.X_OK):
        return _launch_failure(b"permission_denied")
    executable_path = os.path.realpath(resolved)
    executable_command = (executable_path, *command[1:])
    sandboxed = _sandbox_command(
        executable_command,
        readonly_paths=(checkout, *_toolchain_paths(command)),
        writable_paths=(writable_root,),
    )
    try:
        completed = subprocess.run(
            sandboxed,
            cwd=checkout,
            input=input_bytes,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
            env=_sandbox_environment(writable_root),
        )
        exit_code = completed.returncode
        stdout = completed.stdout
        stderr = completed.stderr
    except subprocess.TimeoutExpired as error:
        exit_code = 124
        stdout = error.stdout or b""
        stderr = (error.stderr or b"") + _SANDBOX_DIAGNOSTIC_PREFIX + b" timeout\n"
    except FileNotFoundError:
        return _launch_failure(b"executable_not_found")
    except PermissionError:
        return _launch_failure(b"permission_denied")
    except (OSError, subprocess.SubprocessError):
        return _launch_failure(b"os_launch_error")
    if exit_code < 0:
        signal_number = min(abs(exit_code), 127)
        exit_code = 128 + signal_number
        stderr += (
            _SANDBOX_DIAGNOSTIC_PREFIX
            + b" terminated_by_signal:"
            + str(signal_number).encode("ascii")
            + b"\n"
        )
    elif 128 < exit_code <= 255 and (exit_code - 128) in signal.valid_signals():
        signal_number = exit_code - 128
        stderr += (
            _SANDBOX_DIAGNOSTIC_PREFIX
            + b" terminated_by_signal:"
            + str(signal_number).encode("ascii")
            + b"\n"
        )
    return exit_code, _bounded_output(stdout), _bounded_output(stderr)


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


def _canonical_git_diff(
    source_repository: Path,
    baseline_commit: str,
    candidate_commit: str,
) -> tuple[bytes, tuple[str, ...]]:
    """Return protected diff bytes and canonical paths for two exact commits."""
    _object(baseline_commit, "invalid_synthetic_baseline_commit")
    _object(candidate_commit, "invalid_synthetic_candidate_commit")
    source = source_repository.expanduser().absolute()
    if not source.is_dir() or "://" in os.fspath(source):
        raise CommissioningArtifactError("invalid_synthetic_source_repository")

    base = (
        "git",
        "-c",
        "core.quotepath=false",
        "-c",
        "diff.external=",
        "-C",
        os.fspath(source),
        "diff",
        "--no-ext-diff",
        "--no-renames",
    )
    try:
        diff = subprocess.run(
            (*base, "--binary", "--full-index", baseline_commit, candidate_commit, "--"),
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout
        raw_paths = subprocess.run(
            (*base, "--name-only", "-z", baseline_commit, candidate_commit, "--"),
            check=True,
            capture_output=True,
            timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise CommissioningArtifactError("synthetic_git_failed") from error
    try:
        decoded = tuple(
            item.decode("utf-8", errors="strict") for item in raw_paths.split(b"\0") if item
        )
    except UnicodeError as error:
        raise CommissioningArtifactError("invalid_synthetic_changed_paths") from error
    paths = tuple(sorted((_safe_relative_path(path) for path in decoded), key=str.encode))
    if not paths or len(paths) != len(set(paths)):
        raise CommissioningArtifactError("invalid_synthetic_changed_paths")
    return diff, paths


def _git_tree(source_repository: Path, commit: str) -> str:
    """Resolve an exact commit tree from the protected source repository."""
    _object(commit, "invalid_synthetic_subject_commit")
    source = source_repository.expanduser().absolute()
    if not source.is_dir() or "://" in os.fspath(source):
        raise CommissioningArtifactError("invalid_synthetic_source_repository")
    try:
        tree = subprocess.run(
            ("git", "-C", os.fspath(source), "rev-parse", f"{commit}^{{tree}}"),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise CommissioningArtifactError("synthetic_git_failed") from error
    return _object(tree, "protected_git_tree_mismatch")


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
        artifacts.read(stderr_ref)
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
    source_repository: Path,
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
            "changed_paths_ref",
            "claim",
            "diff_ref",
            "evaluator_ref",
            "execution_bundle_ref",
            "schema_version",
        },
        "invalid_capability_evidence_bundle",
    )
    if bundle["schema_version"] != 2:
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
    changed_paths_ref = _typed_artifact_ref(
        bundle["changed_paths_ref"],
        evidence_kind="git_changed_paths",
        media_type="application/json",
        code="invalid_synthetic_changed_paths_ref",
    )
    diff_ref = _typed_artifact_ref(
        bundle["diff_ref"],
        evidence_kind="git_binary_diff",
        media_type="application/octet-stream",
        code="invalid_synthetic_diff_ref",
    )
    evaluator = ProtectedEvaluator.from_bytes(artifacts.read(evaluator_ref))
    claim = evaluator.capability_claim(evaluator_ref.digest)
    if bundle["claim"] != claim.to_canonical_dict():
        raise CommissioningArtifactError("protected_capability_claim_mismatch")
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
    derived_baseline_tree = _git_tree(source_repository, baseline_commit)
    derived_candidate_tree = _git_tree(source_repository, candidate_commit)
    if baseline_tree != derived_baseline_tree or candidate_tree != derived_candidate_tree:
        raise CommissioningArtifactError("protected_git_tree_mismatch")
    baseline_tree = derived_baseline_tree
    candidate_tree = derived_candidate_tree
    exact_diff, changed_paths = _canonical_git_diff(
        source_repository,
        baseline_commit,
        candidate_commit,
    )
    expected_paths = {
        "baseline_commit": baseline_commit,
        "candidate_commit": candidate_commit,
        "paths": list(changed_paths),
        "schema_version": 1,
    }
    if (
        artifacts.read(diff_ref) != exact_diff
        or _json_object(
            artifacts.read(changed_paths_ref),
            {"baseline_commit", "candidate_commit", "paths", "schema_version"},
            "invalid_synthetic_changed_paths",
        )
        != expected_paths
    ):
        raise CommissioningArtifactError("protected_git_diff_mismatch")
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
                ("git_binary_diff", diff_ref),
                ("git_changed_paths", changed_paths_ref),
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


def derive_protected_paired_evidence(
    *,
    artifacts: PrivateArtifactStore,
    source_repository: Path,
    evidence_bundle_ref: ArtifactRef,
    experiment_id: str,
    manifest_digest: str,
) -> PairedEvidence:
    """Derive canonical lifecycle evidence from protected command scorecards."""
    verified = verify_protected_pair_evaluation(
        artifacts=artifacts,
        evidence_bundle_ref=evidence_bundle_ref,
        source_repository=source_repository,
    )
    _identifier(experiment_id, "invalid_paired_experiment")
    if (
        not isinstance(manifest_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", manifest_digest) is None
    ):
        raise CommissioningArtifactError("invalid_paired_manifest")
    refs = dict(verified.artifact_refs)
    evaluator = ProtectedEvaluator.from_bytes(artifacts.read(refs["protected_evaluator"]))
    baseline_ref = artifacts.put(
        evidence_kind="baseline_scorecard",
        media_type="application/json",
        content=canonical_json_bytes(
            {
                "commit": verified.baseline_commit,
                "outcomes": [
                    item.to_canonical_dict() for item in verified.report.baseline_outcomes
                ],
                "schema_version": 1,
            }
        ),
    )
    candidate_ref = artifacts.put(
        evidence_kind="candidate_scorecard",
        media_type="application/json",
        content=canonical_json_bytes(
            {
                "commit": verified.candidate_commit,
                "outcomes": [
                    item.to_canonical_dict() for item in verified.report.candidate_outcomes
                ],
                "schema_version": 1,
            }
        ),
    )
    before = {item.task_id: item.score_basis_points for item in verified.report.baseline_outcomes}
    after = {item.task_id: item.score_basis_points for item in verified.report.candidate_outcomes}
    if set(before) != set(after) or not before:
        raise CommissioningArtifactError("protected_paired_identity_mismatch")
    deltas = tuple(after[task] - before[task] for task in sorted(before))
    non_guard_deltas = tuple(
        after[task.task_id] - before[task.task_id]
        for task in evaluator.tasks
        if task.role != "guard"
    )
    if not non_guard_deltas:
        raise CommissioningArtifactError("protected_paired_identity_mismatch")
    paired_trials = sum(
        len(item.valid_trials) + len(item.invalid_trials)
        for item in verified.report.candidate_outcomes
    )
    pass_rate_delta = sum(deltas) // len(deltas)
    confidence_lower = min(non_guard_deltas)
    comparison_ref = artifacts.put(
        evidence_kind="paired_comparison",
        media_type="application/json",
        content=canonical_json_bytes(
            {
                "baseline_scorecard_ref": baseline_ref.to_canonical_dict(),
                "candidate_scorecard_ref": candidate_ref.to_canonical_dict(),
                "capability_report_ref": refs["capability_report"].to_canonical_dict(),
                "confidence_lower_basis_points": confidence_lower,
                "paired_trials": paired_trials,
                "parent_commit": verified.baseline_commit,
                "candidate_commit": verified.candidate_commit,
                "pass_rate_delta_basis_points": pass_rate_delta,
                "schema_version": 1,
            }
        ),
    )
    return PairedEvidence(
        schema_version=1,
        experiment_id=experiment_id,
        manifest_digest=manifest_digest,
        parent_commit=verified.baseline_commit,
        candidate_commit=verified.candidate_commit,
        baseline_scorecard_digest=baseline_ref.digest,
        candidate_scorecard_digest=candidate_ref.digest,
        comparison_artifact=comparison_ref,
        decision="improvement" if verified.report.eligible else "rejected",
        paired_trials=paired_trials,
        pass_rate_delta_basis_points=pass_rate_delta,
        confidence_lower_basis_points=confidence_lower,
    )


class ProtectedSyntheticRunner:
    """Run exact commits against protected tasks inside an OS network sandbox."""

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
        probe_root = Path(tempfile.mkdtemp(prefix="sandbox-probe-", dir=self.protected_root))
        try:
            exit_code, _, stderr = _run_sandboxed_command(
                (sys.executable, "-c", "raise SystemExit(0)"),
                checkout=self.protected_root,
                writable_root=probe_root,
                input_bytes=None,
                timeout_seconds=10,
            )
        finally:
            shutil.rmtree(probe_root, ignore_errors=True)
        if exit_code != 0:
            reason = _sandbox_failure_reason(stderr)
            raise CommissioningArtifactError(
                f"synthetic_execution_sandbox_unavailable:{reason}:exit_{exit_code}"
            )

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
        writable_root = Path(tempfile.mkdtemp(prefix="trial-output-", dir=self.protected_root))
        try:
            exit_code, stdout, stderr = _run_sandboxed_command(
                (sys.executable, os.fspath(subject)),
                checkout=checkout,
                writable_root=writable_root,
                input_bytes=canonical_json_bytes(task.input) + b"\n",
                timeout_seconds=10,
            )
        finally:
            shutil.rmtree(writable_root, ignore_errors=True)
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

    def _protected_command_result(
        self,
        *,
        checkout: Path,
        run_kind: str,
        baseline_commit: str,
        candidate_commit: str,
        candidate_tree: str,
        logical_command: tuple[str, ...],
        actual_command: tuple[str, ...],
        timeout_seconds: int = 120,
    ):
        from carl_bench.protected_run import ProtectedCommandResult

        started = time.monotonic_ns()
        writable_root = Path(
            tempfile.mkdtemp(prefix="protected-command-output-", dir=self.protected_root)
        )
        try:
            exit_code, stdout, stderr = _run_sandboxed_command(
                actual_command,
                checkout=checkout,
                writable_root=writable_root,
                input_bytes=None,
                timeout_seconds=timeout_seconds,
            )
        finally:
            shutil.rmtree(writable_root, ignore_errors=True)
        elapsed_ms = max(1, (time.monotonic_ns() - started) // 1_000_000)
        stdout_ref = self.artifacts.put(
            evidence_kind="protected_command_stdout",
            media_type="application/octet-stream",
            content=stdout,
        )
        stderr_ref = self.artifacts.put(
            evidence_kind="protected_command_stderr",
            media_type="application/octet-stream",
            content=stderr,
        )
        return ProtectedCommandResult(
            schema_version=1,
            run_kind=run_kind,
            baseline_commit=baseline_commit,
            candidate_commit=candidate_commit,
            candidate_tree=candidate_tree,
            command=logical_command,
            exit_code=exit_code,
            elapsed_ms=elapsed_ms,
            stdout_ref=stdout_ref,
            stderr_ref=stderr_ref,
        )

    def build_protected_run(
        self,
        *,
        evaluation: ProtectedPairEvaluation,
        experiment_id: str,
        manifest_digest: str,
        validation_id: str,
        created_at: str,
        expires_at: str,
        verifier_config,
    ):
        """Execute protected checks and derive one fully artifact-backed receipt."""
        from carl_bench.protected_run import (
            ProtectedCommandResult,
            ProtectedFlakeObservationSet,
            ProtectedFlakeSample,
            ProtectedVerifierConfig,
            persist_protected_run,
        )

        if not isinstance(evaluation, ProtectedPairEvaluation) or not isinstance(
            verifier_config, ProtectedVerifierConfig
        ):
            raise CommissioningArtifactError("invalid_protected_run_input")
        verified = verify_protected_pair_evaluation(
            artifacts=self.artifacts,
            evidence_bundle_ref=evaluation.evidence_bundle_ref,
            source_repository=self.source_repository,
        )
        if verified.report != evaluation.report:
            raise CommissioningArtifactError("protected_run_evaluation_mismatch")
        evaluator = ProtectedEvaluator.from_bytes(self.artifacts.read(evaluation.evaluator_ref))
        run_root = Path(tempfile.mkdtemp(prefix="protected-run-", dir=self.protected_root))
        if os.name != "nt":
            run_root.chmod(0o700)
        try:
            checkout = run_root / "candidate"
            self._checkout(verified.candidate_commit, checkout)
            subject = checkout / evaluator.subject_path
            if not subject.is_file() or subject.is_symlink():
                raise CommissioningArtifactError("synthetic_subject_missing")
            executable_bytes = subject.read_bytes()
            logical_deterministic = (
                "git",
                "diff",
                "--check",
                verified.baseline_commit,
                verified.candidate_commit,
                "--",
            )
            git_executable = shutil.which("git")
            command_line_tools_git = Path("/Library/Developer/CommandLineTools/usr/bin/git")
            if (
                sys.platform == "darwin"
                and command_line_tools_git.is_file()
                and os.access(command_line_tools_git, os.X_OK)
            ):
                git_executable = os.fspath(command_line_tools_git)
            if git_executable is None:
                raise CommissioningArtifactError("synthetic_git_failed")
            samples = []
            for sample_number in range(1, 4):
                deterministic = self._protected_command_result(
                    checkout=checkout,
                    run_kind="deterministic_checks",
                    baseline_commit=verified.baseline_commit,
                    candidate_commit=verified.candidate_commit,
                    candidate_tree=verified.candidate_tree,
                    logical_command=logical_deterministic,
                    actual_command=(git_executable, *logical_deterministic[1:]),
                )
                repository_tests = self._protected_command_result(
                    checkout=checkout,
                    run_kind="full_repository_tests",
                    baseline_commit=verified.baseline_commit,
                    candidate_commit=verified.candidate_commit,
                    candidate_tree=verified.candidate_tree,
                    logical_command=verifier_config.repository_tests_command,
                    actual_command=verifier_config.repository_tests_command,
                )
                deterministic_ref = self.artifacts.put(
                    evidence_kind="protected_deterministic_checks",
                    media_type="application/json",
                    content=canonical_json_bytes(deterministic.to_canonical_dict()),
                )
                repository_ref = self.artifacts.put(
                    evidence_kind="protected_repository_tests",
                    media_type="application/json",
                    content=canonical_json_bytes(repository_tests.to_canonical_dict()),
                )
                samples.append(
                    ProtectedFlakeSample(
                        schema_version=1,
                        sample_id=f"sample-{sample_number:03d}",
                        deterministic_checks_ref=deterministic_ref,
                        repository_tests_ref=repository_ref,
                    )
                )
        finally:
            shutil.rmtree(run_root, ignore_errors=True)
        observations = ProtectedFlakeObservationSet(
            schema_version=1,
            baseline_commit=verified.baseline_commit,
            candidate_commit=verified.candidate_commit,
            candidate_tree=verified.candidate_tree,
            samples=tuple(samples),
        )
        flake_observations_ref = self.artifacts.put(
            evidence_kind="protected_flake_observations",
            media_type="application/json",
            content=canonical_json_bytes(observations.to_canonical_dict()),
        )
        first_deterministic = ProtectedCommandResult.from_canonical_dict(
            json.loads(self.artifacts.read(samples[0].deterministic_checks_ref))
        )
        first_repository = ProtectedCommandResult.from_canonical_dict(
            json.loads(self.artifacts.read(samples[0].repository_tests_ref))
        )
        return persist_protected_run(
            artifacts=self.artifacts,
            source_repository=self.source_repository,
            verifier_config=verifier_config,
            experiment_id=experiment_id,
            manifest_digest=manifest_digest,
            validation_id=validation_id,
            baseline_commit=verified.baseline_commit,
            candidate_commit=verified.candidate_commit,
            candidate_tree=verified.candidate_tree,
            evidence_bundle_ref=evaluation.evidence_bundle_ref,
            evaluator_ref=evaluation.evaluator_ref,
            capability_report=verified.report,
            task_roles=tuple((task.task_id, task.role) for task in evaluator.tasks),
            changed_paths=verified.changed_paths,
            executable_bytes=executable_bytes,
            subject_path=evaluator.subject_path,
            deterministic_result=first_deterministic,
            repository_result=first_repository,
            flake_observations_ref=flake_observations_ref,
            created_at=created_at,
            expires_at=expires_at,
        )

    def seal_candidate_from_protected_run(
        self,
        *,
        evaluation: ProtectedPairEvaluation,
        protected_run,
        experiment_id: str,
        manifest_digest: str,
    ) -> SealedCandidate:
        """Seal the exact pair diff and protected deterministic command output."""
        from carl_bench.protected_run import (
            ProtectedCommandResult,
            ProtectedRunEvidence,
        )

        if not isinstance(evaluation, ProtectedPairEvaluation) or not isinstance(
            protected_run, ProtectedRunEvidence
        ):
            raise CommissioningArtifactError("invalid_protected_candidate_input")
        verified = verify_protected_pair_evaluation(
            artifacts=self.artifacts,
            evidence_bundle_ref=evaluation.evidence_bundle_ref,
            source_repository=self.source_repository,
        )
        pair_refs = dict(verified.artifact_refs)
        run_refs = dict(protected_run.artifact_refs)
        deterministic_ref = run_refs["deterministic_checks"]
        deterministic = ProtectedCommandResult.from_canonical_dict(
            json.loads(self.artifacts.read(deterministic_ref))
        )
        report_ref = self.artifacts.put(
            evidence_kind="implementation_report",
            media_type="application/json",
            content=canonical_json_bytes(
                {
                    "candidate_commit": verified.candidate_commit,
                    "capability_report_ref": pair_refs["capability_report"].to_canonical_dict(),
                    "protected_run_manifest_ref": protected_run.manifest_ref.to_canonical_dict(),
                    "schema_version": 1,
                }
            ),
        )
        return SealedCandidate(
            schema_version=1,
            experiment_id=experiment_id,
            manifest_digest=manifest_digest,
            parent_commit=verified.baseline_commit,
            candidate_commit=verified.candidate_commit,
            branch=f"codex/experiment-{experiment_id}-{verified.baseline_commit[:10]}",
            diff_artifact=pair_refs["git_binary_diff"],
            report_artifact=report_ref,
            changed_paths_artifact=pair_refs["git_changed_paths"],
            changed_path_count=len(verified.changed_paths),
            checks=(
                DeterministicCheckResult(
                    check_id="synthetic-git-diff-check",
                    status="passed" if deterministic.passed else "failed",
                    exit_code=deterministic.exit_code,
                    elapsed_ms=deterministic.elapsed_ms,
                    output_artifact=deterministic_ref,
                ),
            ),
        )

    def evaluate_pair(
        self,
        *,
        baseline_commit: str,
        candidate_commit: str,
        evaluator_ref: ArtifactRef,
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
        exact_diff, changed_paths = _canonical_git_diff(
            self.source_repository,
            baseline_commit,
            candidate_commit,
        )
        baseline_tree = _git_tree(self.source_repository, baseline_commit)
        candidate_tree = _git_tree(self.source_repository, candidate_commit)
        diff_ref = self.artifacts.put(
            evidence_kind="git_binary_diff",
            media_type="application/octet-stream",
            content=exact_diff,
        )
        changed_paths_ref = self.artifacts.put(
            evidence_kind="git_changed_paths",
            media_type="application/json",
            content=canonical_json_bytes(
                {
                    "baseline_commit": baseline_commit,
                    "candidate_commit": candidate_commit,
                    "paths": list(changed_paths),
                    "schema_version": 1,
                }
            ),
        )
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
            if (
                baseline_execution["subject_tree"] != baseline_tree
                or candidate_execution["subject_tree"] != candidate_tree
            ):
                raise CommissioningArtifactError("protected_git_tree_mismatch")
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
                    "changed_paths_ref": changed_paths_ref.to_canonical_dict(),
                    "claim": claim.to_canonical_dict(),
                    "diff_ref": diff_ref.to_canonical_dict(),
                    "evaluator_ref": evaluator_ref.to_canonical_dict(),
                    "execution_bundle_ref": execution_ref.to_canonical_dict(),
                    "schema_version": 2,
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
