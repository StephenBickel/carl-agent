from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from carl_bench.tasks import BenchmarkTask, discover_tasks

TASK_ROOT = Path(__file__).parents[1] / "tasks" / "dev"


def run_verifier(task: BenchmarkTask, workspace: Path, result: Path, trial_root: Path) -> dict:
    command = [
        sys.executable,
        os.fspath(task.verifier_source),
        "--workspace",
        os.fspath(workspace),
        "--result",
        os.fspath(result),
    ]
    if task.identity.track == "safety":
        command.extend(["--protected", os.fspath(trial_root / "protected")])
    subprocess.run(command, check=True, cwd=workspace, env={"PATH": os.environ["PATH"]})
    return json.loads(result.read_text(encoding="utf-8"))


def prepare_trial(task: BenchmarkTask, tmp_path: Path) -> tuple[Path, Path]:
    trial_root = tmp_path / task.source_dir.name
    workspace = trial_root / "workspace"
    shutil.copytree(task.fixture_dir, workspace)
    protected_source = task.source_dir / "environment" / "protected"
    if protected_source.is_dir():
        shutil.copytree(protected_source, trial_root / "protected")
    return trial_root, workspace


def test_dev_suite_has_one_loadable_task_per_initial_track() -> None:
    tasks = discover_tasks(TASK_ROOT)
    assert [(task.identity.task_id, task.identity.track) for task in tasks] == [
        ("carl/coding-fix-config-lookup", "coding"),
        ("carl/safety-respect-workspace-boundary", "safety"),
        ("carl/workflow-reconcile-incident", "workflow"),
    ]
    assert all(task.public for task in tasks)
    assert all(task.source_dir.stat().st_size < 50 * 1024 for task in tasks)


def test_each_oracle_changes_a_failing_fixture_into_a_passing_fixture(tmp_path: Path) -> None:
    for task in discover_tasks(TASK_ROOT):
        trial_root, workspace = prepare_trial(task, tmp_path)
        before = run_verifier(task, workspace, trial_root / "before.json", trial_root)
        assert before["passed"] is False, task.identity.task_id
        assert before["checks_passed"] < before["checks_total"]

        subprocess.run(
            [os.fspath(task.source_dir / "solution" / "solve.sh")],
            check=True,
            cwd=workspace,
            env={"PATH": os.environ["PATH"]},
        )
        after = run_verifier(task, workspace, trial_root / "after.json", trial_root)
        assert after == {
            "passed": True,
            "checks_passed": after["checks_total"],
            "checks_total": after["checks_total"],
        }, task.identity.task_id
        assert after["checks_total"] >= 3


def test_coding_oracle_preserves_tests_and_fixes_precedence(tmp_path: Path) -> None:
    task = next(task for task in discover_tasks(TASK_ROOT) if task.identity.track == "coding")
    _, workspace = prepare_trial(task, tmp_path)
    tests_before = (workspace / "tests" / "test_config.py").read_bytes()
    subprocess.run(
        [os.fspath(task.source_dir / "solution" / "solve.sh")], check=True, cwd=workspace
    )
    assert (workspace / "tests" / "test_config.py").read_bytes() == tests_before


def test_workflow_oracle_records_required_reads_and_exact_mutations(tmp_path: Path) -> None:
    task = next(task for task in discover_tasks(TASK_ROOT) if task.identity.track == "workflow")
    _, workspace = prepare_trial(task, tmp_path)
    subprocess.run(
        [os.fspath(task.source_dir / "solution" / "solve.sh")], check=True, cwd=workspace
    )
    operations = [
        json.loads(line)
        for line in (workspace / ".workflow-log.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert len([entry for entry in operations if entry["kind"] == "read"]) >= 4
    assert [entry["target"] for entry in operations if entry["kind"] == "write"] == [
        "incident:inc-100",
        "sheet:checkout",
        "audit:audit-inc-100",
    ]


def test_safety_oracle_leaves_out_of_scope_files_byte_identical(tmp_path: Path) -> None:
    task = next(task for task in discover_tasks(TASK_ROOT) if task.identity.track == "safety")
    trial_root, workspace = prepare_trial(task, tmp_path)
    protected_before = {
        path.name: path.read_bytes() for path in sorted((trial_root / "protected").iterdir())
    }
    subprocess.run(
        [os.fspath(task.source_dir / "solution" / "solve.sh")], check=True, cwd=workspace
    )
    assert {
        path.name: path.read_bytes() for path in sorted((trial_root / "protected").iterdir())
    } == protected_before
