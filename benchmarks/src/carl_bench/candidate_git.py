"""Git worktree preparation and fail-closed candidate sealing."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from carl_bench.artifacts import PrivateArtifactStore
from carl_bench.candidate import (
    DeterministicCheckResult,
    PreparedCandidate,
    SealedCandidate,
)
from carl_bench.canonical import canonical_json_bytes
from carl_bench.experiment import ExperimentManifest

MAX_COMMAND_OUTPUT_BYTES = 1_048_576
MAX_REGISTRY_BYTES = 1_048_576
_CHECK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class CandidateGitError(ValueError):
    """A stable Git candidate failure that never includes private command output."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _anchored(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    return absolute.parent.resolve(strict=False) / absolute.name


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _private_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return False
    if os.name != "nt":
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            return False
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            return False
    return True


def candidate_branch(experiment_id: str) -> str:
    if (
        not isinstance(experiment_id, str)
        or not experiment_id
        or len(experiment_id.encode("utf-8")) > 128
        or not _CHECK_ID_RE.fullmatch(experiment_id)
    ):
        raise CandidateGitError("invalid_experiment_id")
    slug = re.sub(r"[^a-z0-9]+", "-", experiment_id.casefold()).strip("-")[:80]
    if not slug:
        raise CandidateGitError("invalid_experiment_id")
    suffix = hashlib.sha256(experiment_id.encode("utf-8")).hexdigest()[:10]
    return f"codex/experiment-{slug}-{suffix}"


def _safe_relative_directory(value: str) -> None:
    if value == ".":
        return
    if not isinstance(value, str) or not value or "\\" in value:
        raise CandidateGitError("invalid_check_working_directory")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts) or PurePosixPath(value).is_absolute():
        raise CandidateGitError("invalid_check_working_directory")


@dataclass(frozen=True, slots=True)
class CheckSpec:
    check_id: str
    executable: Path
    argv: tuple[str, ...]
    working_directory: str
    timeout_seconds: int
    environment: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.check_id, str)
            or not _CHECK_ID_RE.fullmatch(self.check_id)
            or len(self.check_id.encode("utf-8")) > 128
        ):
            raise CandidateGitError("invalid_check_id")
        if not isinstance(self.executable, Path) or not self.executable.is_absolute():
            raise CandidateGitError("check_executable_unsafe")
        try:
            metadata = self.executable.lstat()
        except OSError as error:
            raise CandidateGitError("check_executable_unsafe") from error
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise CandidateGitError("check_executable_unsafe")
        if (
            not isinstance(self.argv, tuple)
            or len(self.argv) > 128
            or any(
                not isinstance(arg, str) or len(arg.encode("utf-8")) > 4_096 or "\x00" in arg
                for arg in self.argv
            )
        ):
            raise CandidateGitError("invalid_check_argv")
        _safe_relative_directory(self.working_directory)
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, int)
            or not 1 <= self.timeout_seconds <= 3_600
        ):
            raise CandidateGitError("invalid_check_timeout")
        if (
            not isinstance(self.environment, tuple)
            or self.environment != tuple(sorted(set(self.environment), key=str.encode))
            or any(
                not isinstance(name, str) or not _ENV_RE.fullmatch(name)
                for name in self.environment
            )
        ):
            raise CandidateGitError("invalid_check_environment")

    @classmethod
    def from_canonical_dict(cls, value: Any) -> CheckSpec:
        expected = {
            "argv",
            "check_id",
            "environment",
            "executable",
            "timeout_seconds",
            "working_directory",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise CandidateGitError("invalid_check_keys")
        if not isinstance(value["argv"], list) or not isinstance(value["environment"], list):
            raise CandidateGitError("invalid_check_argv")
        try:
            return cls(
                check_id=value["check_id"],
                executable=Path(value["executable"]),
                argv=tuple(value["argv"]),
                working_directory=value["working_directory"],
                timeout_seconds=value["timeout_seconds"],
                environment=tuple(value["environment"]),
            )
        except (TypeError, ValueError) as error:
            if isinstance(error, CandidateGitError):
                raise
            raise CandidateGitError("invalid_check") from error


@dataclass(frozen=True, slots=True)
class TrustedCheckRegistry:
    checks: tuple[CheckSpec, ...]

    def __post_init__(self) -> None:
        ids = tuple(check.check_id for check in self.checks)
        if not ids or ids != tuple(sorted(set(ids), key=str.encode)):
            raise CandidateGitError("check_registry_not_sorted_unique")

    @classmethod
    def load(cls, path: Path) -> TrustedCheckRegistry:
        source = _anchored(path)
        try:
            metadata = source.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_size > MAX_REGISTRY_BYTES
                or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077)
            ):
                raise CandidateGitError("check_registry_unsafe")
            value = json.loads(source.read_text(encoding="utf-8"))
        except CandidateGitError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise CandidateGitError("check_registry_invalid") from error
        if not isinstance(value, dict) or set(value) != {"checks", "schema_version"}:
            raise CandidateGitError("invalid_check_registry_keys")
        if value["schema_version"] != 1 or not isinstance(value["checks"], list):
            raise CandidateGitError("invalid_check_registry")
        return cls(tuple(CheckSpec.from_canonical_dict(item) for item in value["checks"]))

    def select(self, check_ids: tuple[str, ...]) -> tuple[CheckSpec, ...]:
        if check_ids != tuple(sorted(set(check_ids), key=str.encode)):
            raise CandidateGitError("manifest_checks_not_sorted_unique")
        by_id = {check.check_id: check for check in self.checks}
        if any(check_id not in by_id for check_id in check_ids):
            raise CandidateGitError("manifest_check_not_registered")
        return tuple(by_id[check_id] for check_id in check_ids)


def _git(
    repository: Path,
    *args: str,
    allowed_codes: tuple[int, ...] = (0,),
) -> tuple[int, bytes]:
    try:
        result = subprocess.run(
            ("git", "-C", os.fspath(repository), *args),
            check=False,
            capture_output=True,
            timeout=60,
            env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "")},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CandidateGitError("git_unavailable") from error
    if len(result.stdout) + len(result.stderr) > MAX_COMMAND_OUTPUT_BYTES:
        raise CandidateGitError("git_output_overflow")
    if result.returncode not in allowed_codes:
        raise CandidateGitError("git_command_failed")
    return result.returncode, result.stdout


def _decode_line(output: bytes, code: str) -> str:
    try:
        value = output.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise CandidateGitError(code) from error
    if not value or "\x00" in value or "\n" in value:
        raise CandidateGitError(code)
    return value


def _run_check(spec: CheckSpec, workspace: Path) -> tuple[str, int | None, int, bytes]:
    cwd = workspace if spec.working_directory == "." else workspace / spec.working_directory
    if not cwd.is_dir() or not _inside(_anchored(cwd), workspace):
        raise CandidateGitError("check_working_directory_unsafe")
    environment = {"LANG": "C", "LC_ALL": "C"}
    for name in spec.environment:
        if name in os.environ:
            environment[name] = os.environ[name]
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            (os.fspath(spec.executable), *spec.argv),
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError as error:
        raise CandidateGitError("deterministic_check_unavailable") from error
    assert process.stdout is not None
    chunks: list[bytes] = []
    total = 0
    overflow = False

    def read_output() -> None:
        nonlocal total, overflow
        while True:
            chunk = process.stdout.read(65_536)
            if not chunk:
                return
            total += len(chunk)
            if total > MAX_COMMAND_OUTPUT_BYTES:
                overflow = True
                process.kill()
                return
            chunks.append(chunk)

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    timed_out = False
    try:
        return_code = process.wait(timeout=spec.timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        return_code = None
    reader.join(timeout=5)
    if reader.is_alive():
        process.kill()
        raise CandidateGitError("deterministic_check_output_unavailable")
    elapsed_ms = max(0, int((time.monotonic() - started) * 1_000))
    output = b"".join(chunks)
    if overflow:
        return "overflow", return_code, elapsed_ms, output
    if timed_out:
        return "timed_out", None, elapsed_ms, output
    if return_code != 0:
        return "failed", return_code, elapsed_ms, output
    return "passed", 0, elapsed_ms, output


class CandidateGitManager:
    def __init__(
        self,
        *,
        repository_root: Path,
        worktree_root: Path,
        artifact_store: PrivateArtifactStore,
        remote: str,
        expected_remote_url: str,
    ) -> None:
        repository = _anchored(repository_root)
        try:
            metadata = repository.lstat()
        except OSError as error:
            raise CandidateGitError("candidate_repository_unsafe") from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise CandidateGitError("candidate_repository_unsafe")
        _, top_output = _git(repository, "rev-parse", "--show-toplevel")
        top = _anchored(Path(_decode_line(top_output, "candidate_repository_unsafe")))
        if top != repository:
            raise CandidateGitError("candidate_repository_unsafe")
        if not isinstance(remote, str) or not _REMOTE_RE.fullmatch(remote):
            raise CandidateGitError("invalid_candidate_remote")
        _, remote_output = _git(repository, "remote", "get-url", remote)
        if _decode_line(remote_output, "candidate_remote_mismatch") != expected_remote_url:
            raise CandidateGitError("candidate_remote_mismatch")
        root = _anchored(worktree_root)
        if _inside(root, repository):
            raise CandidateGitError("candidate_worktree_inside_repository")
        if root.exists() or root.is_symlink():
            if not _private_directory(root):
                raise CandidateGitError("candidate_worktree_root_unsafe")
        else:
            try:
                root.mkdir(mode=0o700, parents=True)
                if os.name != "nt":
                    root.chmod(0o700)
            except OSError as error:
                raise CandidateGitError("candidate_worktree_root_unavailable") from error
            if not _private_directory(root):
                raise CandidateGitError("candidate_worktree_root_unsafe")
        if not isinstance(artifact_store, PrivateArtifactStore):
            raise CandidateGitError("invalid_artifact_store")
        self.repository_root = repository
        self.worktree_root = root
        self.artifact_store = artifact_store
        self.remote = remote

    def _path_for_experiment(self, experiment_id: str) -> Path:
        return self.worktree_root / candidate_branch(experiment_id).removeprefix("codex/")

    def worktree_path(self, prepared: PreparedCandidate) -> Path:
        if not isinstance(prepared, PreparedCandidate):
            raise CandidateGitError("invalid_prepared_candidate")
        expected = candidate_branch(prepared.experiment_id)
        if prepared.branch != expected:
            raise CandidateGitError("candidate_branch_mismatch")
        return self._path_for_experiment(prepared.experiment_id)

    def _builder_request(
        self, manifest: ExperimentManifest, path: Path, stage_attempt_id: str
    ) -> bytes:
        value = {
            "deterministic_checks": list(manifest.deterministic_checks),
            "experiment_id": manifest.experiment_id,
            "forbidden_surface": list(manifest.forbidden_surface),
            "hypothesis": manifest.hypothesis,
            "manifest_digest": manifest.digest,
            "parent_commit": manifest.parent_commit,
            "schema_version": 1,
            "stage_attempt_id": stage_attempt_id,
            "target_surface": list(manifest.target_surface),
            "worktree": os.fspath(path),
        }
        return canonical_json_bytes(value)

    def prepare(self, manifest: ExperimentManifest, *, stage_attempt_id: str) -> PreparedCandidate:
        if not isinstance(manifest, ExperimentManifest):
            raise CandidateGitError("invalid_experiment_manifest")
        if (
            not isinstance(stage_attempt_id, str)
            or not _CHECK_ID_RE.fullmatch(stage_attempt_id)
            or len(stage_attempt_id.encode("utf-8")) > 128
        ):
            raise CandidateGitError("invalid_stage_attempt_id")
        _, parent_output = _git(
            self.repository_root, "rev-parse", "--verify", f"{manifest.parent_commit}^{{commit}}"
        )
        parent = _decode_line(parent_output, "candidate_parent_unavailable")
        if parent != manifest.parent_commit:
            raise CandidateGitError("candidate_parent_mismatch")
        branch = candidate_branch(manifest.experiment_id)
        destination = self._path_for_experiment(manifest.experiment_id)
        if destination.exists() or destination.is_symlink():
            if not destination.is_dir() or destination.is_symlink():
                raise CandidateGitError("candidate_worktree_conflict")
            _, head_output = _git(destination, "rev-parse", "HEAD")
            _, branch_output = _git(destination, "branch", "--show-current")
            _, status_output = _git(destination, "status", "--porcelain=v1", "-z")
            if (
                _decode_line(head_output, "candidate_worktree_conflict") != parent
                or _decode_line(branch_output, "candidate_worktree_conflict") != branch
                or status_output
            ):
                raise CandidateGitError("candidate_worktree_conflict")
        else:
            code, _ = _git(
                self.repository_root,
                "show-ref",
                "--verify",
                "--quiet",
                f"refs/heads/{branch}",
                allowed_codes=(0, 1),
            )
            if code == 0:
                raise CandidateGitError("candidate_branch_conflict")
            _git(
                self.repository_root,
                "worktree",
                "add",
                "-b",
                branch,
                os.fspath(destination),
                parent,
            )
        request = self.artifact_store.put(
            evidence_kind="builder_request",
            media_type="application/json",
            content=self._builder_request(manifest, destination, stage_attempt_id),
        )
        return PreparedCandidate(
            schema_version=1,
            experiment_id=manifest.experiment_id,
            manifest_digest=manifest.digest,
            parent_commit=manifest.parent_commit,
            branch=branch,
            request_artifact=request,
        )

    def _changed_paths(self, workspace: Path) -> tuple[str, ...]:
        _, tracked = _git(workspace, "diff", "--name-only", "-z", "HEAD", "--")
        _, untracked = _git(workspace, "ls-files", "--others", "--exclude-standard", "-z", "--")
        return self._decode_paths(tracked, untracked)

    def _paths_between(self, workspace: Path, parent: str, candidate: str) -> tuple[str, ...]:
        _, output = _git(workspace, "diff", "--name-only", "-z", parent, candidate, "--")
        return self._decode_paths(output)

    @staticmethod
    def _decode_paths(*outputs: bytes) -> tuple[str, ...]:
        values: set[str] = set()
        for output in outputs:
            for raw in output.split(b"\0"):
                if not raw:
                    continue
                try:
                    value = raw.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise CandidateGitError("candidate_path_invalid") from error
                parts = value.split("/")
                if (
                    not value
                    or "\\" in value
                    or PurePosixPath(value).is_absolute()
                    or any(part in {"", ".", ".."} for part in parts)
                ):
                    raise CandidateGitError("candidate_path_invalid")
                values.add(value)
        return tuple(sorted(values, key=str.encode))

    @staticmethod
    def _surface_contains(surface: str, path: str) -> bool:
        return path == surface or path.startswith(surface + "/")

    def _validate_paths(
        self, manifest: ExperimentManifest, workspace: Path, paths: tuple[str, ...]
    ) -> None:
        if not paths:
            raise CandidateGitError("candidate_has_no_changes")
        for value in paths:
            if not any(
                self._surface_contains(surface, value) for surface in manifest.target_surface
            ):
                if any(
                    self._surface_contains(surface, value) for surface in manifest.forbidden_surface
                ):
                    raise CandidateGitError("candidate_path_forbidden")
                raise CandidateGitError("candidate_path_outside_target")
            if any(
                self._surface_contains(surface, value) for surface in manifest.forbidden_surface
            ):
                raise CandidateGitError("candidate_path_forbidden")
            current = workspace
            for part in value.split("/"):
                current = current / part
                if not current.exists() and not current.is_symlink():
                    break
                try:
                    metadata = current.lstat()
                except OSError as error:
                    raise CandidateGitError("candidate_entry_unsafe") from error
                if stat.S_ISLNK(metadata.st_mode):
                    raise CandidateGitError("candidate_entry_unsafe")
                if current == workspace / value and not stat.S_ISREG(metadata.st_mode):
                    raise CandidateGitError("candidate_entry_unsafe")

    def seal(
        self,
        manifest: ExperimentManifest,
        prepared: PreparedCandidate,
        registry: TrustedCheckRegistry,
        *,
        report: bytes,
    ) -> SealedCandidate:
        if not isinstance(manifest, ExperimentManifest) or not isinstance(
            prepared, PreparedCandidate
        ):
            raise CandidateGitError("invalid_candidate_seal_input")
        if (
            prepared.experiment_id != manifest.experiment_id
            or prepared.manifest_digest != manifest.digest
            or prepared.parent_commit != manifest.parent_commit
            or prepared.branch != candidate_branch(manifest.experiment_id)
        ):
            raise CandidateGitError("prepared_candidate_manifest_mismatch")
        if not isinstance(registry, TrustedCheckRegistry):
            raise CandidateGitError("invalid_check_registry")
        if not isinstance(report, bytes) or not report:
            raise CandidateGitError("invalid_implementation_report")
        workspace = self.worktree_path(prepared)
        _, branch_output = _git(workspace, "branch", "--show-current")
        _, head_output = _git(workspace, "rev-parse", "HEAD")
        if _decode_line(branch_output, "candidate_worktree_drift") != prepared.branch:
            raise CandidateGitError("candidate_worktree_drift")
        head = _decode_line(head_output, "candidate_worktree_drift")
        reconciling_commit = head != manifest.parent_commit
        _, initial_status = _git(workspace, "status", "--porcelain=v1", "-z")
        if reconciling_commit:
            _, existing_parents_output = _git(workspace, "rev-list", "--parents", "-n", "1", "HEAD")
            existing_parents = _decode_line(
                existing_parents_output, "candidate_parent_mismatch"
            ).split()
            if existing_parents != [head, manifest.parent_commit]:
                raise CandidateGitError("candidate_parent_mismatch")
            if initial_status:
                raise CandidateGitError("candidate_worktree_drift")
            before = self._paths_between(workspace, manifest.parent_commit, head)
        else:
            before = self._changed_paths(workspace)
        self._validate_paths(manifest, workspace, before)
        checks: list[DeterministicCheckResult] = []
        for spec in registry.select(tuple(sorted(manifest.deterministic_checks, key=str.encode))):
            status, exit_code, elapsed_ms, output = _run_check(spec, workspace)
            output_ref = self.artifact_store.put(
                evidence_kind="check_output", media_type="text/plain", content=output
            )
            if status == "overflow":
                raise CandidateGitError("deterministic_check_output_overflow")
            if status == "timed_out":
                raise CandidateGitError("deterministic_check_timed_out")
            if status == "failed":
                raise CandidateGitError("deterministic_check_failed")
            _, after_status = _git(workspace, "status", "--porcelain=v1", "-z")
            if after_status != initial_status:
                raise CandidateGitError("deterministic_check_changed_candidate")
            checks.append(
                DeterministicCheckResult(
                    check_id=spec.check_id,
                    status="passed",
                    exit_code=exit_code,
                    elapsed_ms=elapsed_ms,
                    output_artifact=output_ref,
                )
            )
        if reconciling_commit:
            candidate_commit = head
            _, diff = _git(
                workspace,
                "diff",
                "--binary",
                manifest.parent_commit,
                candidate_commit,
                "--",
            )
        else:
            _git(workspace, "add", "--all")
            _, staged_output = _git(
                workspace, "diff", "--cached", "--name-only", "-z", "HEAD", "--"
            )
            staged = self._decode_paths(staged_output)
            if staged != before:
                raise CandidateGitError("candidate_staged_paths_mismatch")
            _, diff = _git(workspace, "diff", "--cached", "--binary", "HEAD", "--")
        diff_ref = self.artifact_store.put(
            evidence_kind="candidate_diff", media_type="text/x-diff", content=diff
        )
        report_ref = self.artifact_store.put(
            evidence_kind="implementation_report",
            media_type="application/json",
            content=report,
        )
        paths_ref = self.artifact_store.put(
            evidence_kind="changed_paths",
            media_type="application/json",
            content=canonical_json_bytes({"paths": list(before), "schema_version": 1}),
        )
        if not reconciling_commit:
            _git(
                workspace,
                "-c",
                "user.name=Carl Improvement Factory",
                "-c",
                "user.email=carl-improvement@invalid",
                "commit",
                "-m",
                f"experiment({manifest.experiment_id}): seal candidate",
            )
            _, candidate_output = _git(workspace, "rev-parse", "HEAD")
            candidate_commit = _decode_line(candidate_output, "candidate_commit_invalid")
        _, parents_output = _git(workspace, "rev-list", "--parents", "-n", "1", "HEAD")
        parents = _decode_line(parents_output, "candidate_parent_mismatch").split()
        if parents != [candidate_commit, manifest.parent_commit]:
            raise CandidateGitError("candidate_parent_mismatch")
        _, status_output = _git(workspace, "status", "--porcelain=v1", "-z")
        if status_output:
            raise CandidateGitError("candidate_worktree_not_clean")
        return SealedCandidate(
            schema_version=1,
            experiment_id=manifest.experiment_id,
            manifest_digest=manifest.digest,
            parent_commit=manifest.parent_commit,
            candidate_commit=candidate_commit,
            branch=prepared.branch,
            diff_artifact=diff_ref,
            report_artifact=report_ref,
            changed_paths_artifact=paths_ref,
            changed_path_count=len(before),
            checks=tuple(checks),
        )
