from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from carl_bench import cli

TASK_ROOT = Path(__file__).parents[1] / "tasks" / "dev"


def run_scripted(result: Path, *extra: str) -> int:
    return run_scripted_for(TASK_ROOT, result, *extra)


def run_scripted_for(task_root: Path, result: Path, *extra: str) -> int:
    return cli.main(
        [
            "run",
            "--tasks",
            os.fspath(task_root),
            "--adapter",
            "scripted",
            "--attempts",
            "1",
            "--seed",
            "17",
            "--subject-commit",
            "1" * 40,
            "--public-result",
            os.fspath(result),
            *extra,
        ]
    )


def copy_task_root(tmp_path: Path) -> Path:
    destination = tmp_path / "tasks"
    shutil.copytree(TASK_ROOT, destination)
    return destination


def refuse_adapter_start(*_args: object) -> object:
    raise AssertionError("adapter must not start before metric-pack validation")


def test_cli_rejects_task_metric_pack_digest_mismatch_before_adapter_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tasks = copy_task_root(tmp_path)
    manifest_path = tasks / "coding-fix-config-lookup" / "carl-task.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["metric_pack_digest"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(cli, "_adapter", refuse_adapter_start)

    destination = tmp_path / "scorecard.json"
    assert run_scripted_for(tasks, destination) == 2
    assert not destination.exists()


def test_cli_rejects_unknown_task_metric_before_adapter_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tasks = copy_task_root(tmp_path)
    manifest_path = tasks / "coding-fix-config-lookup" / "carl-task.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["metric_ids"] = ["coding.config_precedence_correct", "coding.unknown_behavior"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(cli, "_adapter", refuse_adapter_start)

    destination = tmp_path / "scorecard.json"
    assert run_scripted_for(tasks, destination) == 2
    assert not destination.exists()


def test_pack_field_change_invalidates_existing_task_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    pack_directory = repository / "benchmarks" / "metrics"
    pack_directory.mkdir(parents=True)
    shutil.copy2(Path(__file__).parents[1] / "metrics" / "dev-v1.json", pack_directory)
    pack_path = pack_directory / "dev-v1.json"
    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    pack["metrics"][0]["threshold_basis_points"] = 9_999
    pack_path.write_text(json.dumps(pack), encoding="utf-8")
    monkeypatch.setattr(cli, "REPOSITORY_ROOT", repository)
    monkeypatch.setattr(cli, "_adapter", refuse_adapter_start)

    destination = tmp_path / "scorecard.json"
    assert run_scripted(destination) == 2
    assert not destination.exists()


def test_help_and_task_validation_are_available(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as help_exit:
        cli.main(["--help"])
    assert help_exit.value.code == 0
    assert "tasks" in capsys.readouterr().out

    assert cli.main(["tasks", "validate", "--root", os.fspath(TASK_ROOT)]) == 0
    output = capsys.readouterr().out
    assert "3 valid tasks" in output
    assert "coding" in output and "workflow" in output and "safety" in output


def test_scripted_run_writes_only_sanitized_scorecard(tmp_path: Path) -> None:
    destination = tmp_path / "scorecard.json"
    assert run_scripted(destination) == 0
    value = json.loads(destination.read_text(encoding="utf-8"))
    assert value["passed_trials"] == 3
    assert value["valid_trials"] == 3
    assert value["invalid_trials"] == 0
    assert value["subject_commit"] == "1" * 40
    assert [track["track"] for track in value["tracks"]] == [
        "coding",
        "safety",
        "workflow",
    ]
    serialized = destination.read_text(encoding="utf-8").casefold()
    for forbidden in ("instruction", "prompt", "stdout", "stderr", "response", "secret"):
        assert forbidden not in serialized


def test_attested_run_derives_clean_checkout_commit_and_refuses_dirty_checkout(
    tmp_path: Path,
) -> None:
    checkout = tmp_path / "checkout"
    tasks = checkout / "benchmarks" / "tasks" / "dev"
    shutil.copytree(TASK_ROOT, tasks)
    subprocess.run(("git", "init", "-q", os.fspath(checkout)), check=True)
    subprocess.run(("git", "-C", os.fspath(checkout), "add", "."), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            os.fspath(checkout),
            "-c",
            "user.name=Carl Test",
            "-c",
            "user.email=carl@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ),
        check=True,
    )
    commit = subprocess.run(
        ("git", "-C", os.fspath(checkout), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    private = tmp_path / "private"
    key = private / "attestation.key"
    assert (
        cli.main(
            [
                "attestation-key",
                "init",
                "--private-key",
                os.fspath(key),
                "--repository",
                os.fspath(checkout),
            ]
        )
        == 0
    )
    public = tmp_path / "scorecard.json"
    attestation = private / "baseline.attestation.json"
    command = [
        "run-attested",
        "--checkout",
        os.fspath(checkout),
        "--tasks",
        os.fspath(tasks),
        "--adapter",
        "scripted",
        "--attempts",
        "1",
        "--seed",
        "17",
        "--experiment-id",
        "experiment-cli-1",
        "--role",
        "baseline",
        "--attestation-key",
        os.fspath(key),
        "--private-attestation",
        os.fspath(attestation),
        "--public-result",
        os.fspath(public),
    ]
    assert cli.main(command) == 0
    assert json.loads(public.read_text())["subject_commit"] == commit
    private_value = json.loads(attestation.read_text())
    assert private_value["payload"]["subject_commit"] == commit
    assert private_value["payload"]["role"] == "baseline"
    assert private_value["mac"]

    (checkout / "dirty.txt").write_text("unsealed", encoding="utf-8")
    refused = tmp_path / "refused.json"
    refused_attestation = private / "refused.attestation.json"
    dirty_command = [
        refused_attestation.as_posix() if item == attestation.as_posix() else item
        for item in command
    ]
    dirty_command = [
        refused.as_posix() if item == public.as_posix() else item for item in dirty_command
    ]
    assert cli.main(dirty_command) == 2
    assert not refused.exists()
    assert not refused_attestation.exists()


def test_task_selection_is_sorted_and_unknown_selectors_fail_closed(tmp_path: Path) -> None:
    destination = tmp_path / "selected.json"
    assert (
        run_scripted(
            destination,
            "--task",
            "carl/workflow-reconcile-incident",
            "--task",
            "carl/coding-fix-config-lookup",
        )
        == 0
    )
    value = json.loads(destination.read_text(encoding="utf-8"))
    assert [trial["task_id"] for trial in value["trials"]] == [
        "carl/coding-fix-config-lookup",
        "carl/workflow-reconcile-incident",
    ]

    missing = tmp_path / "missing.json"
    assert run_scripted(missing, "--task", "carl/not-real") == 2
    assert not missing.exists()


def test_run_rejects_invalid_attempts_and_results_inside_task_tree(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    assert run_scripted(outside, "--attempts", "11") == 2
    assert not outside.exists()

    inside = TASK_ROOT / "unsafe-public-result.json"
    try:
        assert run_scripted(inside) == 2
        assert not inside.exists()
    finally:
        inside.unlink(missing_ok=True)


def test_run_rejects_a_symlinked_public_result(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("preserve me", encoding="utf-8")
    destination = tmp_path / "result-link.json"
    destination.symlink_to(target)
    assert run_scripted(destination) == 2
    assert target.read_text(encoding="utf-8") == "preserve me"


def test_live_adapters_require_explicit_paths_model_and_effort(tmp_path: Path) -> None:
    destination = tmp_path / "live.json"
    common = [
        "run",
        "--tasks",
        os.fspath(TASK_ROOT),
        "--attempts",
        "1",
        "--seed",
        "1",
        "--subject-commit",
        "1" * 40,
        "--public-result",
        os.fspath(destination),
    ]
    assert cli.main([*common, "--adapter", "carl-acp"]) == 2
    assert cli.main([*common, "--adapter", "codex-cli"]) == 2
    assert not destination.exists()


def test_compare_reads_public_scorecards_and_rejects_same_model_mismatch(
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline.json"
    candidate = tmp_path / "candidate.json"
    comparison = tmp_path / "comparison.json"
    assert run_scripted(baseline) == 0
    value = json.loads(baseline.read_text(encoding="utf-8"))
    value["league"] = "same-model"
    value["model"] = "gpt-test"
    value["effort"] = "low"
    baseline.write_text(json.dumps(value), encoding="utf-8")
    candidate.write_text(
        json.dumps({**value, "run_id": "run-candidate", "model": "different-model"}),
        encoding="utf-8",
    )
    assert (
        cli.main(
            [
                "compare",
                "--baseline",
                os.fspath(baseline),
                "--candidate",
                os.fspath(candidate),
                "--public-result",
                os.fspath(comparison),
            ]
        )
        == 2
    )
    assert not comparison.exists()

    candidate.write_text(json.dumps({**value, "run_id": "run-candidate"}), encoding="utf-8")
    assert (
        cli.main(
            [
                "compare",
                "--baseline",
                os.fspath(baseline),
                "--candidate",
                os.fspath(candidate),
                "--comparison-seed",
                "9",
                "--public-result",
                os.fspath(comparison),
            ]
        )
        == 0
    )
    compared = json.loads(comparison.read_text(encoding="utf-8"))
    assert compared["paired_trials"] == 3
    assert compared["decision"] == "insufficient_evidence"


def test_compare_rejects_wrong_json_types_without_a_traceback(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    malformed = tmp_path / "malformed.json"
    result = tmp_path / "comparison.json"
    assert run_scripted(baseline) == 0
    value = json.loads(baseline.read_text(encoding="utf-8"))
    value["trials"][0]["track"] = []
    malformed.write_text(json.dumps(value), encoding="utf-8")
    assert (
        cli.main(
            [
                "compare",
                "--baseline",
                os.fspath(baseline),
                "--candidate",
                os.fspath(malformed),
                "--public-result",
                os.fspath(result),
            ]
        )
        == 2
    )
    assert not result.exists()


def test_cancellation_returns_130_without_a_partial_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "cancelled.json"

    async def cancelled(_args: object) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_run_command", cancelled)
    assert run_scripted(destination) == 130
    assert not destination.exists()
