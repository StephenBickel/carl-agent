from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from carl_bench import cli

TASK_ROOT = Path(__file__).parents[1] / "tasks" / "dev"


def run_scripted(result: Path, *extra: str) -> int:
    return cli.main(
        [
            "run",
            "--tasks",
            os.fspath(TASK_ROOT),
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
