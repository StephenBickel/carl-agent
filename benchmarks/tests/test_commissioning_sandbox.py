from __future__ import annotations

import os
import signal
import stat
import sys
from pathlib import Path

import pytest

import carl_bench.commissioning_runner as commissioning_runner
from carl_bench.artifacts import PrivateArtifactStore
from carl_bench.commissioning import CommissioningArtifactError
from carl_bench.commissioning_runner import (
    ProtectedSyntheticRunner,
    _sandbox_command,
    _sandbox_environment,
)


def test_sandbox_environment_scrubs_host_values_and_uses_private_writable_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CARL_HOST_SECRET", "must-not-cross-boundary")
    writable = tmp_path / "writable"
    writable.mkdir()

    environment = _sandbox_environment(writable)

    assert "CARL_HOST_SECRET" not in environment
    assert "PYTHONPATH" not in environment
    assert set(environment) == {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONSAFEPATH",
        "TMPDIR",
        "XDG_CACHE_HOME",
    }
    assert environment["HOME"] == os.fspath(writable)
    assert environment["TMPDIR"] == os.fspath(writable)
    assert environment["XDG_CACHE_HOME"] == os.fspath(writable)


def test_linux_sandbox_command_has_explicit_mounts_and_no_host_root_bind(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "subject"
    checkout.mkdir()
    writable = tmp_path / "output"
    writable.mkdir()
    toolchain = tmp_path / "toolchain"
    toolchain.mkdir()
    bwrap = tmp_path / "bwrap"
    bwrap.write_text("fixture", encoding="utf-8")

    command = _sandbox_command(
        ("/toolchain/python", "subject.py"),
        readonly_paths=(checkout, toolchain),
        writable_paths=(writable,),
        platform="linux",
        executable_lookup=lambda name: os.fspath(bwrap) if name == "bwrap" else None,
    )

    assert command[0] == os.fspath(bwrap)
    assert command[-2:] == ("/toolchain/python", "subject.py")
    assert "--unshare-net" in command
    assert "--die-with-parent" in command
    assert ("--ro-bind", "/", "/") not in tuple(
        tuple(command[index : index + 3]) for index in range(len(command) - 2)
    )
    assert ("--ro-bind", os.fspath(checkout), os.fspath(checkout)) in tuple(
        tuple(command[index : index + 3]) for index in range(len(command) - 2)
    )
    assert ("--bind", os.fspath(writable), os.fspath(writable)) in tuple(
        tuple(command[index : index + 3]) for index in range(len(command) - 2)
    )


def test_linux_sandbox_fails_closed_when_bubblewrap_is_unavailable(tmp_path: Path) -> None:
    with pytest.raises(
        CommissioningArtifactError,
        match="synthetic_execution_sandbox_unavailable",
    ):
        _sandbox_command(
            ("/usr/bin/true",),
            readonly_paths=(tmp_path,),
            writable_paths=(tmp_path,),
            platform="linux",
            executable_lookup=lambda _name: None,
        )


def test_protected_commands_normalize_launch_timeout_and_signal_failures(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    protected_root = tmp_path / "protected"
    artifacts = PrivateArtifactStore(tmp_path / "objects", repository)
    runner = ProtectedSyntheticRunner(
        artifacts=artifacts,
        protected_root=protected_root,
        source_repository=repository,
    )
    executable = tmp_path / "not-executable"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(stat.S_IRUSR | stat.S_IWUSR)
    commands = (
        ((os.fspath(tmp_path / "missing"),), 127, b"executable_not_found"),
        ((os.fspath(executable),), 126, b"permission_denied"),
        ((sys.executable, "-c", "import time; time.sleep(10)"), 124, b"timeout"),
        (
            (
                sys.executable,
                "-c",
                f"import os, signal; os.kill(os.getpid(), {signal.SIGTERM})",
            ),
            128 + signal.SIGTERM,
            b"terminated_by_signal",
        ),
    )

    for index, (command, expected_exit, marker) in enumerate(commands):
        result = runner._protected_command_result(
            checkout=repository,
            run_kind="full_repository_tests",
            baseline_commit="1" * 40,
            candidate_commit="2" * 40,
            candidate_tree="3" * 40,
            logical_command=command,
            actual_command=command,
            timeout_seconds=1,
        )
        assert result.exit_code == expected_exit, index
        stderr = artifacts.read(result.stderr_ref)
        assert marker in stderr
        assert len(stderr) <= 65_536
        assert len(artifacts.read(result.stdout_ref)) <= 65_536


def test_protected_command_normalizes_generic_os_launch_error_into_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    artifacts = PrivateArtifactStore(tmp_path / "objects", repository)
    runner = ProtectedSyntheticRunner(
        artifacts=artifacts,
        protected_root=tmp_path / "protected",
        source_repository=repository,
    )

    def fail_launch(*_args: object, **_kwargs: object) -> None:
        raise OSError("synthetic kernel launch failure")

    monkeypatch.setattr(commissioning_runner.subprocess, "run", fail_launch)
    result = runner._protected_command_result(
        checkout=repository,
        run_kind="full_repository_tests",
        baseline_commit="1" * 40,
        candidate_commit="2" * 40,
        candidate_tree="3" * 40,
        logical_command=(sys.executable, "-c", "raise SystemExit(0)"),
        actual_command=(sys.executable, "-c", "raise SystemExit(0)"),
        timeout_seconds=1,
    )

    assert result.exit_code == 125
    assert artifacts.read(result.stderr_ref) == b"carl-protected-run: os_launch_error\n"
