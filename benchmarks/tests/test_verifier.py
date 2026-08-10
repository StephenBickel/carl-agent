from __future__ import annotations

import asyncio
import os
import shutil
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from carl_bench.tasks import BenchmarkTask, load_task
from carl_bench.verifier import Verifier

TASK_FIXTURE = Path(__file__).parent / "fixtures" / "valid-task"
FAKE_VERIFIER = Path(__file__).parent / "fakes" / "fake-verifier.py"


def fake_task(tmp_path: Path, *, timeout_sec: int = 2) -> BenchmarkTask:
    source = tmp_path / "task"
    shutil.copytree(TASK_FIXTURE, source)
    return replace(
        load_task(source),
        verifier_source=FAKE_VERIFIER,
        verifier_timeout_sec=timeout_sec,
    )


def workspace_and_private(tmp_path: Path, mode: str) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    private = tmp_path / "private"
    workspace.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    (workspace / "mode.txt").write_text(mode, encoding="utf-8")
    return workspace, private


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "passed", "code"),
    [
        ("pass", True, None),
        ("fail", False, None),
        ("malformed", None, "verifier_invalid_output"),
        ("unknown-field", None, "verifier_invalid_output"),
        ("inconsistent", None, "verifier_invalid_output"),
        ("oversized-result", None, "verifier_invalid_output"),
        ("oversized-output", None, "verifier_output_overflow"),
        ("nonzero", None, "verifier_exit_nonzero"),
        ("environment", True, None),
    ],
)
async def test_verifier_classifies_semantic_and_infrastructure_outcomes(
    tmp_path: Path,
    mode: str,
    passed: bool | None,
    code: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SHOULD_NOT_LEAK", "provider-secret")
    task = fake_task(tmp_path)
    workspace, private = workspace_and_private(tmp_path, mode)

    outcome = await Verifier(output_limit_bytes=65_536).run(task, workspace, private)

    assert outcome.passed is passed
    assert outcome.infrastructure_code == code
    if passed is not None:
        assert outcome.checks_total > 0
        assert outcome.checks_passed <= outcome.checks_total


@pytest.mark.asyncio
async def test_missing_verifier_is_infrastructure_invalid(tmp_path: Path) -> None:
    task = replace(fake_task(tmp_path), verifier_source=tmp_path / "missing.py")
    workspace, private = workspace_and_private(tmp_path, "pass")
    outcome = await Verifier().run(task, workspace, private)
    assert outcome.passed is None
    assert outcome.infrastructure_code == "verifier_unavailable"


@pytest.mark.asyncio
async def test_timeout_terminates_leader_and_descendant(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("process-group descendant assertion is Unix-only")
    task = fake_task(tmp_path, timeout_sec=1)
    workspace, private = workspace_and_private(tmp_path, "timeout")
    outcome = await Verifier().run(task, workspace, private)
    assert outcome.infrastructure_code == "verifier_timeout"
    leader = int((workspace / "leader.pid").read_text(encoding="utf-8"))
    child = int((workspace / "child.pid").read_text(encoding="utf-8"))
    await assert_process_gone(leader)
    await assert_process_gone(child)


@pytest.mark.asyncio
async def test_cancellation_terminates_leader_and_descendant(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("process-group descendant assertion is Unix-only")
    task = fake_task(tmp_path, timeout_sec=30)
    workspace, private = workspace_and_private(tmp_path, "cancel")
    running = asyncio.create_task(Verifier().run(task, workspace, private))
    for _ in range(100):
        if (workspace / "child.pid").exists():
            break
        await asyncio.sleep(0.02)
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    leader = int((workspace / "leader.pid").read_text(encoding="utf-8"))
    child = int((workspace / "child.pid").read_text(encoding="utf-8"))
    await assert_process_gone(leader)
    await assert_process_gone(child)


@pytest.mark.asyncio
async def test_private_directory_must_be_absolute_private_and_not_symlinked(tmp_path: Path) -> None:
    task = fake_task(tmp_path)
    workspace, private = workspace_and_private(tmp_path, "pass")
    os.chmod(private, 0o755)
    unsafe = await Verifier().run(task, workspace, private)
    assert unsafe.infrastructure_code == "verifier_private_dir_unsafe"

    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    linked = await Verifier().run(task, workspace, link)
    assert linked.infrastructure_code == "verifier_private_dir_unsafe"

    relative = await Verifier().run(task, workspace, Path("relative"))
    assert relative.infrastructure_code == "verifier_private_dir_unsafe"


@pytest.mark.asyncio
async def test_result_file_is_owner_private(tmp_path: Path) -> None:
    task = fake_task(tmp_path)
    workspace, private = workspace_and_private(tmp_path, "pass")
    outcome = await Verifier().run(task, workspace, private)
    assert outcome.passed is True
    assert stat.S_IMODE((private / "verifier-result.json").stat().st_mode) == 0o600


async def assert_process_gone(process_id: int) -> None:
    for _ in range(100):
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            return
        await asyncio.sleep(0.02)
    pytest.fail(f"process {process_id} survived verifier cleanup")
