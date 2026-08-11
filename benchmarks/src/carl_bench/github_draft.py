"""Narrow GitHub gateway for exact-ref pushes and draft pull requests only."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

from carl_bench.candidate import CandidateContractError, DraftPullRequest
from carl_bench.experiment import ExperimentManifest, ExperimentProjection, ExperimentState

MAX_GATEWAY_OUTPUT_BYTES = 1_048_576
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_GH_FIELDS = "number,url,isDraft,state,headRefName,headRefOid,baseRefName"


class DraftPrGatewayError(ValueError):
    """A stable draft-publication error that omits command output and credentials."""

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


def _run_bounded(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
    failure_code: str,
) -> bytes:
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError as error:
        raise DraftPrGatewayError(failure_code) from error
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
            if total > MAX_GATEWAY_OUTPUT_BYTES:
                overflow = True
                process.kill()
                return
            chunks.append(chunk)

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    try:
        return_code = process.wait(timeout=60)
    except subprocess.TimeoutExpired as error:
        process.kill()
        reader.join(timeout=5)
        raise DraftPrGatewayError(failure_code) from error
    reader.join(timeout=5)
    if reader.is_alive() or overflow or return_code != 0:
        process.kill()
        raise DraftPrGatewayError(failure_code)
    return b"".join(chunks)


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DraftPrGatewayError("github_response_invalid")
        value[key] = item
    return value


class DraftPrGateway:
    def __init__(
        self,
        *,
        repository_root: Path,
        repository_slug: str,
        remote: str,
        expected_remote_url: str,
        base_branch: str,
        gh_executable: Path,
        private_root: Path,
        command_env: dict[str, str],
    ) -> None:
        repository = _anchored(repository_root)
        try:
            metadata = repository.lstat()
        except OSError as error:
            raise DraftPrGatewayError("candidate_repository_unsafe") from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise DraftPrGatewayError("candidate_repository_unsafe")
        if not isinstance(repository_slug, str) or not _REPOSITORY_RE.fullmatch(repository_slug):
            raise DraftPrGatewayError("invalid_repository_slug")
        if not isinstance(remote, str) or not _REMOTE_RE.fullmatch(remote):
            raise DraftPrGatewayError("invalid_remote")
        if not isinstance(base_branch, str) or not _NAME_RE.fullmatch(base_branch):
            raise DraftPrGatewayError("invalid_base_branch")
        executable = _anchored(gh_executable)
        try:
            executable_metadata = executable.lstat()
        except OSError as error:
            raise DraftPrGatewayError("github_cli_unsafe") from error
        if (
            not stat.S_ISREG(executable_metadata.st_mode)
            or stat.S_ISLNK(executable_metadata.st_mode)
            or (os.name != "nt" and not executable_metadata.st_mode & stat.S_IXUSR)
        ):
            raise DraftPrGatewayError("github_cli_unsafe")
        root = _anchored(private_root)
        if _inside(root, repository):
            raise DraftPrGatewayError("gateway_private_root_inside_repository")
        if root.exists() or root.is_symlink():
            if not _private_directory(root):
                raise DraftPrGatewayError("gateway_private_root_unsafe")
        else:
            try:
                root.mkdir(mode=0o700, parents=True)
                if os.name != "nt":
                    root.chmod(0o700)
            except OSError as error:
                raise DraftPrGatewayError("gateway_private_root_unavailable") from error
            if not _private_directory(root):
                raise DraftPrGatewayError("gateway_private_root_unsafe")
        if not isinstance(command_env, dict):
            raise DraftPrGatewayError("invalid_gateway_environment")
        base_environment = {"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "")}
        git_environment = dict(base_environment)
        github_environment = dict(base_environment)
        allowed_names = {
            "GH_ENTERPRISE_TOKEN",
            "GH_HOST",
            "GH_TOKEN",
            "HOME",
            "SSH_AUTH_SOCK",
            "XDG_CONFIG_HOME",
        }
        for name, value in command_env.items():
            if (
                not isinstance(name, str)
                or not _ENV_RE.fullmatch(name)
                or (name not in allowed_names and not name.startswith("FAKE_GH_"))
                or not isinstance(value, str)
                or "\x00" in value
                or len(value.encode("utf-8")) > 65_536
            ):
                raise DraftPrGatewayError("invalid_gateway_environment")
            if name in {"HOME", "SSH_AUTH_SOCK"}:
                git_environment[name] = value
            if name in {
                "GH_ENTERPRISE_TOKEN",
                "GH_HOST",
                "GH_TOKEN",
                "HOME",
                "XDG_CONFIG_HOME",
            } or name.startswith("FAKE_GH_"):
                github_environment[name] = value
        hooks_root = root / "empty-hooks"
        try:
            hooks_root.mkdir(mode=0o700, exist_ok=True)
            if os.name != "nt":
                hooks_root.chmod(0o700)
        except OSError as error:
            raise DraftPrGatewayError("gateway_hooks_root_unavailable") from error
        if not _private_directory(hooks_root):
            raise DraftPrGatewayError("gateway_hooks_root_unsafe")
        self.repository_root = repository
        self.repository_slug = repository_slug
        self.remote = remote
        self.base_branch = base_branch
        self.gh_executable = executable
        self.private_root = root
        self._hooks_root = hooks_root
        self._git_environment = git_environment
        self._github_environment = github_environment
        remote_url = self._git("remote", "get-url", remote).decode("utf-8").strip()
        if remote_url != expected_remote_url:
            raise DraftPrGatewayError("candidate_remote_mismatch")

    def _git(self, *args: str) -> bytes:
        return _run_bounded(
            (
                "git",
                "-C",
                os.fspath(self.repository_root),
                "-c",
                f"core.hooksPath={self._hooks_root}",
                "-c",
                "credential.helper=",
                *args,
            ),
            cwd=self.repository_root,
            environment=self._git_environment,
            failure_code="git_gateway_failed",
        )

    def _gh(self, *args: str) -> bytes:
        return _run_bounded(
            (os.fspath(self.gh_executable), *args),
            cwd=self.repository_root,
            environment=self._github_environment,
            failure_code="github_cli_failed",
        )

    def _inspect(self, head_branch: str) -> list[dict[str, Any]]:
        output = self._gh(
            "pr",
            "list",
            "--repo",
            self.repository_slug,
            "--head",
            head_branch,
            "--state",
            "all",
            "--limit",
            "2",
            "--json",
            _GH_FIELDS,
        )
        try:
            value = json.loads(output.decode("utf-8"), object_pairs_hook=_object_without_duplicates)
        except DraftPrGatewayError:
            raise
        except (UnicodeError, json.JSONDecodeError) as error:
            raise DraftPrGatewayError("github_response_invalid") from error
        if (
            not isinstance(value, list)
            or len(value) > 1
            or any(not isinstance(item, dict) for item in value)
        ):
            raise DraftPrGatewayError("github_response_conflict")
        expected = {
            "baseRefName",
            "headRefName",
            "headRefOid",
            "isDraft",
            "number",
            "state",
            "url",
        }
        if value and set(value[0]) != expected:
            raise DraftPrGatewayError("github_response_invalid")
        return value

    def _reconciled_draft(
        self, value: dict[str, Any], candidate_commit: str, head_branch: str
    ) -> DraftPullRequest:
        if value["baseRefName"] != self.base_branch:
            raise DraftPrGatewayError("pull_request_base_mismatch")
        if value["headRefName"] != head_branch:
            raise DraftPrGatewayError("pull_request_head_mismatch")
        if value["headRefOid"] != candidate_commit:
            raise DraftPrGatewayError("pull_request_candidate_mismatch")
        try:
            return DraftPullRequest.from_canonical_dict(
                {
                    "base_branch": value["baseRefName"],
                    "candidate_commit": value["headRefOid"],
                    "head_branch": value["headRefName"],
                    "is_draft": value["isDraft"],
                    "number": value["number"],
                    "repository": self.repository_slug,
                    "schema_version": 1,
                    "state": value["state"],
                    "url": value["url"],
                }
            )
        except CandidateContractError as error:
            raise DraftPrGatewayError(error.code) from error

    @staticmethod
    def _verify_projection(manifest: ExperimentManifest, projection: ExperimentProjection) -> None:
        if (
            not isinstance(manifest, ExperimentManifest)
            or not isinstance(projection, ExperimentProjection)
            or projection.experiment_id != manifest.experiment_id
            or projection.manifest_digest != manifest.digest
        ):
            raise DraftPrGatewayError("projection_manifest_mismatch")
        if projection.state is not ExperimentState.PAIRED_EVALUATION:
            raise DraftPrGatewayError("draft_pr_wrong_state")
        if projection.candidate is None or projection.paired_evidence is None:
            raise DraftPrGatewayError("paired_evidence_required")
        if projection.paired_evidence.decision != "improvement":
            raise DraftPrGatewayError("paired_improvement_required")
        roles = {review.role for review in projection.candidate_attestations}
        if (
            len(projection.review_packets) != 4
            or len(projection.candidate_attestations) != 4
            or roles != {"correctness", "security", "maintainability", "benchmark_integrity"}
            or len({review.reviewer_id for review in projection.candidate_attestations}) != 4
            or len({review.context_id for review in projection.candidate_attestations}) != 4
            or sum(review.verdict == "approve" for review in projection.candidate_attestations) < 3
            or any(review.verdict == "hard_finding" for review in projection.candidate_attestations)
        ):
            raise DraftPrGatewayError("candidate_attestation_quorum_unsatisfied")

    def _body(self, manifest: ExperimentManifest, projection: ExperimentProjection) -> bytes:
        assert projection.candidate is not None
        assert projection.paired_evidence is not None
        lines = (
            "Automated local candidate (draft only)",
            "",
            f"Experiment: `{manifest.experiment_id}`",
            f"Manifest: `{manifest.digest}`",
            f"Candidate: `{projection.candidate.candidate_commit}`",
            f"Deterministic evidence: `{projection.candidate.digest}`",
            f"Paired evidence: `{projection.paired_evidence.digest}`",
            "",
            "This draft has not run protected validation and is not eligible for merge.",
        )
        return ("\n".join(lines) + "\n").encode("utf-8")

    def open_or_reconcile(
        self, manifest: ExperimentManifest, projection: ExperimentProjection
    ) -> DraftPullRequest:
        self._verify_projection(manifest, projection)
        assert projection.candidate is not None
        candidate = projection.candidate
        if projection.draft_pull_request is not None:
            if (
                projection.draft_pull_request.candidate_commit != candidate.candidate_commit
                or projection.draft_pull_request.head_branch != candidate.branch
            ):
                raise DraftPrGatewayError("recorded_pull_request_mismatch")
            return projection.draft_pull_request
        local = (
            self._git("rev-parse", "--verify", f"refs/heads/{candidate.branch}^{{commit}}")
            .decode("utf-8")
            .strip()
        )
        if local != candidate.candidate_commit:
            raise DraftPrGatewayError("candidate_local_ref_mismatch")
        existing = self._inspect(candidate.branch)
        if existing:
            return self._reconciled_draft(existing[0], candidate.candidate_commit, candidate.branch)
        self._git(
            "push",
            "--no-verify",
            "--porcelain",
            self.remote,
            f"{candidate.candidate_commit}:refs/heads/{candidate.branch}",
        )
        descriptor, body_name = tempfile.mkstemp(prefix="draft-body-", dir=self.private_root)
        body_path = Path(body_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(self._body(manifest, projection))
                stream.flush()
                os.fsync(stream.fileno())
            if os.name != "nt":
                body_path.chmod(0o600)
            self._gh(
                "pr",
                "create",
                "--repo",
                self.repository_slug,
                "--draft",
                "--base",
                self.base_branch,
                "--head",
                candidate.branch,
                "--title",
                f"experiment({manifest.experiment_id}): candidate",
                "--body-file",
                os.fspath(body_path),
            )
        finally:
            body_path.unlink(missing_ok=True)
        created = self._inspect(candidate.branch)
        if not created:
            raise DraftPrGatewayError("pull_request_reconciliation_missing")
        return self._reconciled_draft(created[0], candidate.candidate_commit, candidate.branch)
