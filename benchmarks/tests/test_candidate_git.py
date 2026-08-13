from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from test_experiment import manifest

from carl_bench.artifacts import PrivateArtifactStore
from carl_bench.candidate_git import (
    CandidateGitError,
    CandidateGitManager,
    TrustedCheckRegistry,
    candidate_branch,
)


def _run(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True)
    if os.name != "nt":
        path.chmod(0o700)
    return path


def _repository(tmp_path: Path) -> tuple[Path, Path, str]:
    repository = tmp_path / "repository"
    origin = tmp_path / "origin.git"
    repository.mkdir()
    _run("git", "init", "-b", "main", cwd=repository)
    _run("git", "config", "user.name", "Fixture", cwd=repository)
    _run("git", "config", "user.email", "fixture@example.invalid", cwd=repository)
    source = repository / "src" / "runtime" / "task"
    source.mkdir(parents=True)
    (source / "value.txt").write_text("before\n", encoding="utf-8")
    (repository / "README.md").write_text("fixture\n", encoding="utf-8")
    _run("git", "add", "--all", cwd=repository)
    _run("git", "commit", "-m", "fixture", cwd=repository)
    _run("git", "init", "--bare", os.fspath(origin), cwd=tmp_path)
    _run("git", "remote", "add", "origin", os.fspath(origin), cwd=repository)
    _run("git", "push", "-u", "origin", "main", cwd=repository)
    return repository, origin, _run("git", "rev-parse", "HEAD", cwd=repository)


def _manager(tmp_path: Path) -> tuple[CandidateGitManager, Path, str]:
    repository, origin, parent = _repository(tmp_path)
    private = _private(tmp_path / "private")
    store = PrivateArtifactStore(private / "artifacts", repository)
    manager = CandidateGitManager(
        repository_root=repository,
        worktree_root=private / "worktrees",
        artifact_store=store,
        remote="origin",
        expected_remote_url=os.fspath(origin),
    )
    return manager, repository, parent


def _registry(path: Path, checks: list[dict[str, object]]) -> TrustedCheckRegistry:
    path.write_text(json.dumps({"checks": checks, "schema_version": 1}), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)
    return TrustedCheckRegistry.load(path)


def _check(
    check_id: str,
    program: str,
    *,
    timeout_seconds: int = 5,
    environment: list[str] | None = None,
) -> dict[str, object]:
    return {
        "argv": ["-c", program],
        "check_id": check_id,
        "environment": environment or [],
        "executable": os.fspath(Path(sys.executable).resolve()),
        "timeout_seconds": timeout_seconds,
        "working_directory": ".",
    }


def test_candidate_branch_and_prepare_are_exact_parent_idempotent_and_private(
    tmp_path: Path,
) -> None:
    manager, repository, parent = _manager(tmp_path)
    selected = replace(manifest(), parent_commit=parent)

    assert (
        candidate_branch(selected.experiment_id)
        == "codex/experiment-exp-context-recovery-001-c2c5d3e327"
    )
    prepared = manager.prepare(selected, stage_attempt_id="prepare-candidate-1")
    repeated = manager.prepare(selected, stage_attempt_id="prepare-candidate-1")

    assert repeated == prepared
    worktree = manager.worktree_path(prepared)
    assert worktree.is_dir()
    assert not worktree.is_relative_to(repository)
    assert _run("git", "rev-parse", "HEAD", cwd=worktree) == parent
    assert _run("git", "branch", "--show-current", cwd=worktree) == prepared.branch
    request = json.loads(manager.artifact_store.read(prepared.request_artifact))
    assert request["worktree"] == os.fspath(worktree)
    assert request["stage_attempt_id"] == "prepare-candidate-1"
    assert request["manifest_digest"] == selected.digest
    if os.name != "nt":
        assert stat.S_IMODE(worktree.parent.stat().st_mode) == 0o700


def test_seal_runs_registered_checks_in_closed_environment_and_commits_allowed_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, _, parent = _manager(tmp_path)
    selected = replace(
        manifest(),
        parent_commit=parent,
        deterministic_checks=("closed-env", "content-check"),
    )
    prepared = manager.prepare(selected, stage_attempt_id="prepare-candidate-1")
    worktree = manager.worktree_path(prepared)
    (worktree / "src" / "runtime" / "task" / "value.txt").write_text("after\n", encoding="utf-8")
    monkeypatch.setenv("CARL_TEST_SECRET", "must-not-reach-check")
    registry = _registry(
        tmp_path / "private" / "checks.json",
        [
            _check(
                "closed-env",
                "import os; raise SystemExit('CARL_TEST_SECRET' in os.environ)",
            ),
            _check(
                "content-check",
                "from pathlib import Path; "
                "raise SystemExit(Path('src/runtime/task/value.txt').read_text() != 'after\\n')",
            ),
        ],
    )

    candidate = manager.seal(
        selected,
        prepared,
        registry,
        report=b'{"summary":"changed fixture"}',
    )

    assert candidate.parent_commit == parent
    assert candidate.candidate_commit != parent
    assert candidate.changed_path_count == 1
    assert tuple(check.check_id for check in candidate.checks) == (
        "closed-env",
        "content-check",
    )
    assert candidate.all_checks_passed
    assert _run("git", "status", "--porcelain", cwd=worktree) == ""
    assert _run("git", "rev-parse", "HEAD^", cwd=worktree) == parent
    assert b"value.txt" in manager.artifact_store.read(candidate.diff_artifact)


def test_seal_reconciles_an_exact_parent_commit_created_before_ledger_append(
    tmp_path: Path,
) -> None:
    manager, _, parent = _manager(tmp_path)
    selected = replace(manifest(), parent_commit=parent, deterministic_checks=("pass",))
    prepared = manager.prepare(selected, stage_attempt_id="prepare-reconcile")
    worktree = manager.worktree_path(prepared)
    (worktree / "src" / "runtime" / "task" / "value.txt").write_text(
        "candidate committed before append\n", encoding="utf-8"
    )
    _run("git", "add", "--all", cwd=worktree)
    _run("git", "commit", "-m", "candidate before controller receipt", cwd=worktree)
    existing_commit = _run("git", "rev-parse", "HEAD", cwd=worktree)
    registry = _registry(
        tmp_path / "private" / "checks-reconcile.json",
        [_check("pass", "raise SystemExit(0)")],
    )

    candidate = manager.seal(
        selected,
        prepared,
        registry,
        report=b'{"summary":"reconciled after commit"}',
    )

    assert candidate.candidate_commit == existing_commit
    assert candidate.parent_commit == parent
    assert candidate.changed_path_count == 1
    assert b"candidate committed before append" in manager.artifact_store.read(
        candidate.diff_artifact
    )


def test_seal_never_executes_repository_git_hooks(tmp_path: Path) -> None:
    manager, repository, parent = _manager(tmp_path)
    selected = replace(manifest(), parent_commit=parent, deterministic_checks=("pass",))
    prepared = manager.prepare(selected, stage_attempt_id="prepare-hook-test")
    worktree = manager.worktree_path(prepared)
    (worktree / "src" / "runtime" / "task" / "value.txt").write_text(
        "candidate\n", encoding="utf-8"
    )
    marker = tmp_path / "hook-ran"
    hooks = repository / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    hook = hooks / "pre-commit"
    hook.write_text(f"#!/bin/sh\nprintf ran > '{marker}'\n", encoding="utf-8")
    hook.chmod(0o700)
    registry = _registry(
        tmp_path / "private" / "checks-hook.json",
        [_check("pass", "raise SystemExit(0)")],
    )

    manager.seal(selected, prepared, registry, report=b'{"summary":"hook test"}')

    assert not marker.exists()


def test_dispose_removes_only_clean_matching_worktree_and_is_idempotent(tmp_path: Path) -> None:
    manager, repository, parent = _manager(tmp_path)
    selected = replace(manifest(), parent_commit=parent, deterministic_checks=("pass",))
    prepared = manager.prepare(selected, stage_attempt_id="prepare-dispose")
    worktree = manager.worktree_path(prepared)
    (worktree / "src" / "runtime" / "task" / "value.txt").write_text(
        "candidate\n", encoding="utf-8"
    )
    registry = _registry(
        tmp_path / "private" / "checks-dispose.json",
        [_check("pass", "raise SystemExit(0)")],
    )
    candidate = manager.seal(selected, prepared, registry, report=b'{"summary":"dispose test"}')

    assert manager.dispose(prepared, candidate) is True
    assert not worktree.exists()
    assert manager.dispose(prepared, candidate) is False
    assert (
        _run("git", "rev-parse", f"refs/heads/{candidate.branch}", cwd=repository)
        == candidate.candidate_commit
    )


def test_dispose_rejects_dirty_or_mismatched_candidate_worktree(tmp_path: Path) -> None:
    manager, _, parent = _manager(tmp_path)
    selected = replace(manifest(), parent_commit=parent, deterministic_checks=("pass",))
    prepared = manager.prepare(selected, stage_attempt_id="prepare-dirty-dispose")
    worktree = manager.worktree_path(prepared)
    (worktree / "src" / "runtime" / "task" / "value.txt").write_text(
        "candidate\n", encoding="utf-8"
    )
    registry = _registry(
        tmp_path / "private" / "checks-dirty-dispose.json",
        [_check("pass", "raise SystemExit(0)")],
    )
    candidate = manager.seal(
        selected, prepared, registry, report=b'{"summary":"dirty dispose test"}'
    )
    (worktree / "src" / "runtime" / "task" / "extra.txt").write_text(
        "uncommitted\n", encoding="utf-8"
    )
    with pytest.raises(CandidateGitError, match="candidate_dispose_conflict"):
        manager.dispose(prepared, candidate)

    mismatched = replace(candidate, candidate_commit="f" * 40)
    with pytest.raises(CandidateGitError, match="candidate_dispose_conflict"):
        manager.dispose(prepared, mismatched)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("outside", "candidate_path_outside_target"),
        ("forbidden", "candidate_path_forbidden"),
        ("symlink", "candidate_entry_unsafe"),
    ],
)
def test_seal_rejects_out_of_scope_forbidden_and_special_entries(
    tmp_path: Path, mutation: str, code: str
) -> None:
    manager, _, parent = _manager(tmp_path)
    selected = replace(manifest(), parent_commit=parent, deterministic_checks=("pass",))
    prepared = manager.prepare(selected, stage_attempt_id=f"prepare-{mutation}")
    worktree = manager.worktree_path(prepared)
    if mutation == "outside":
        (worktree / "README.md").write_text("changed\n", encoding="utf-8")
    elif mutation == "forbidden":
        target = worktree / "benchmarks" / "leak.txt"
        target.parent.mkdir()
        target.write_text("changed\n", encoding="utf-8")
    else:
        target = worktree / "src" / "runtime" / "task" / "link"
        target.symlink_to(worktree / "README.md")
    registry = _registry(
        tmp_path / "private" / f"checks-{mutation}.json",
        [_check("pass", "raise SystemExit(0)")],
    )

    with pytest.raises(CandidateGitError, match=code):
        manager.seal(selected, prepared, registry, report=b"report")


@pytest.mark.parametrize(
    ("program", "timeout_seconds", "code"),
    [
        ("raise SystemExit(7)", 5, "deterministic_check_failed"),
        ("import time; time.sleep(2)", 1, "deterministic_check_timed_out"),
        ("print('x' * 1100000)", 5, "deterministic_check_output_overflow"),
        (
            "from pathlib import Path; Path('src/runtime/task/generated.txt').write_text('dirty')",
            5,
            "deterministic_check_changed_candidate",
        ),
    ],
)
def test_seal_fails_closed_when_checks_fail_timeout_overflow_or_mutate_candidate(
    tmp_path: Path, program: str, timeout_seconds: int, code: str
) -> None:
    manager, _, parent = _manager(tmp_path)
    selected = replace(manifest(), parent_commit=parent, deterministic_checks=("gate",))
    prepared = manager.prepare(selected, stage_attempt_id=f"prepare-{code}")
    worktree = manager.worktree_path(prepared)
    (worktree / "src" / "runtime" / "task" / "value.txt").write_text("after\n", encoding="utf-8")
    registry = _registry(
        tmp_path / "private" / f"checks-{code}.json",
        [_check("gate", program, timeout_seconds=timeout_seconds)],
    )

    with pytest.raises(CandidateGitError, match=code):
        manager.seal(selected, prepared, registry, report=b"report")


def test_check_registry_rejects_shell_strings_relative_executables_and_unknown_keys(
    tmp_path: Path,
) -> None:
    private = _private(tmp_path / "private")
    base = _check("pass", "raise SystemExit(0)")
    cases = (
        ({**base, "executable": "python"}, "check_executable_unsafe"),
        ({**base, "argv": "-c echo bad"}, "invalid_check_argv"),
        ({**base, "shell": True}, "invalid_check_keys"),
        ({**base, "environment": ["GH_TOKEN"]}, "invalid_check_environment"),
    )
    for index, (value, code) in enumerate(cases):
        source = private / f"invalid-{index}.json"
        source.write_text(json.dumps({"checks": [value], "schema_version": 1}), encoding="utf-8")
        if os.name != "nt":
            source.chmod(0o600)
        with pytest.raises(CandidateGitError, match=code):
            TrustedCheckRegistry.load(source)
