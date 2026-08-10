"""Command-line orchestration for public-safe Carl benchmark runs."""

from __future__ import annotations

import argparse
import asyncio
import json
import stat
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from carl_bench.adapters.base import AgentAdapter
from carl_bench.adapters.carl_acp import CarlAcpAdapter
from carl_bench.adapters.codex_cli import CodexCliAdapter
from carl_bench.adapters.scripted import ScriptedAdapter
from carl_bench.models import (
    FailureClass,
    OutcomeStatus,
    RunManifest,
    Scorecard,
    TrackScorecard,
    TrialResult,
)
from carl_bench.report import compare_runs, summarize_run
from carl_bench.runner import BenchmarkRunner
from carl_bench.sanitize import PublicSafetyError, assert_public_safe, write_public_json
from carl_bench.tasks import BenchmarkTask, TaskContractError, discover_tasks

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
MAX_SCORECARD_BYTES = 4 * 1_048_576


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="carl-bench",
        description="Run reproducible coding, workflow, and safety agent benchmarks.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    tasks = commands.add_parser("tasks", help="inspect portable benchmark tasks")
    task_commands = tasks.add_subparsers(dest="task_command", required=True)
    validate = task_commands.add_parser("validate", help="validate all tasks beneath a root")
    validate.add_argument("--root", required=True, type=Path)

    run = commands.add_parser("run", help="run isolated benchmark trials")
    run.add_argument("--tasks", required=True, type=Path)
    run.add_argument("--adapter", required=True, choices=("scripted", "carl-acp", "codex-cli"))
    run.add_argument("--task", action="append", default=[], help="exact task ID to include")
    run.add_argument("--attempts", required=True, type=int)
    run.add_argument("--seed", required=True, type=int)
    run.add_argument("--public-result", required=True, type=Path)
    run.add_argument("--league", choices=("plumbing", "same-model", "native-product"))
    run.add_argument("--model")
    run.add_argument("--effort", choices=("minimal", "low", "medium", "high", "xhigh"))
    run.add_argument("--carl-bin", type=Path)
    run.add_argument("--carl-data-dir", type=Path)
    run.add_argument("--codex-bin", type=Path)
    run.add_argument("--codex-home", type=Path)
    run.add_argument(
        "--permission-mode",
        default="default",
        choices=("plan", "default", "acceptEdits", "dontAsk"),
    )

    compare = commands.add_parser("compare", help="compare exact paired public scorecards")
    compare.add_argument("--baseline", required=True, type=Path)
    compare.add_argument("--candidate", required=True, type=Path)
    compare.add_argument("--comparison-seed", type=int, default=0)
    compare.add_argument("--public-result", required=True, type=Path)
    return parser


def _resolved(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _safe_result_path(destination: Path, forbidden_roots: Sequence[Path]) -> Path:
    result = _resolved(destination)
    for root in forbidden_roots:
        if _inside(result, _resolved(root)):
            raise ValueError("public result cannot be written inside benchmark task sources")
    return result


def _select_tasks(root: Path, selectors: Sequence[str]) -> tuple[BenchmarkTask, ...]:
    tasks = discover_tasks(_resolved(root))
    if not selectors:
        return tasks
    if len(selectors) != len(set(selectors)):
        raise ValueError("duplicate task selector")
    by_id = {task.identity.task_id: task for task in tasks}
    if any(selector not in by_id for selector in selectors):
        raise ValueError("unknown task selector")
    return tuple(by_id[selector] for selector in sorted(selectors, key=str.encode))


def _adapter(args: argparse.Namespace) -> tuple[AgentAdapter, str, str | None, str | None]:
    league = args.league
    if args.adapter == "scripted":
        selected_league = league or "plumbing"
        if selected_league == "same-model" and (args.model is None or args.effort is None):
            raise ValueError("same-model runs require model and effort")
        return ScriptedAdapter(), selected_league, args.model, args.effort

    if args.model is None or args.effort is None:
        raise ValueError("live adapters require explicit model and effort")
    selected_league = league or "same-model"
    if args.adapter == "carl-acp":
        if args.carl_bin is None or args.codex_bin is None or args.carl_data_dir is None:
            raise ValueError("Carl ACP requires explicit executable and data paths")
        adapter = CarlAcpAdapter(
            executable=args.carl_bin,
            codex_executable=args.codex_bin,
            data_dir=args.carl_data_dir,
            model=args.model,
            effort=args.effort,
            permission_mode=args.permission_mode,
        )
    else:
        if args.codex_bin is None or args.codex_home is None:
            raise ValueError("Codex CLI requires explicit executable and home paths")
        adapter = CodexCliAdapter(
            executable=args.codex_bin,
            codex_home=args.codex_home,
            model=args.model,
            effort=args.effort,
        )
    return adapter, selected_league, args.model, args.effort


async def _run_command(args: argparse.Namespace) -> int:
    if not 1 <= args.attempts <= 10:
        raise ValueError("attempts must be between 1 and 10")
    if isinstance(args.seed, bool) or not 0 <= args.seed < (1 << 63):
        raise ValueError("seed must be a non-negative 63-bit integer")
    if args.seed + args.attempts - 1 >= (1 << 63):
        raise ValueError("attempt seeds exceed the supported range")
    task_root = _resolved(args.tasks)
    destination = _safe_result_path(args.public_result, (task_root,))
    tasks = _select_tasks(task_root, args.task)
    if not tasks:
        raise ValueError("no benchmark tasks selected")
    adapter, league, model, effort = _adapter(args)
    runner = BenchmarkRunner()
    trials: list[TrialResult] = []
    for task in tasks:
        for attempt in range(1, args.attempts + 1):
            trials.append(
                await runner.run(
                    task,
                    adapter,
                    attempt=attempt,
                    seed=args.seed + attempt - 1,
                )
            )
    manifest = RunManifest(
        schema_version=1,
        run_id=f"run-{args.adapter}-{uuid.uuid4().hex}",
        league=league,
        model=model,
        effort=effort,
        started_at=datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        seed=args.seed,
        trials=tuple(trials),
    )
    scorecard = summarize_run(manifest, trials)
    write_public_json(destination, scorecard.to_public_dict(), REPOSITORY_ROOT)
    print(
        f"run {scorecard.run_id}: {scorecard.passed_trials}/{scorecard.valid_trials} "
        f"passed; {scorecard.invalid_trials} invalid"
    )
    if scorecard.invalid_trials:
        return 4
    if scorecard.failed_trials:
        return 3
    return 0


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _read_public_object(path: Path) -> dict[str, Any]:
    source = _resolved(path)
    try:
        metadata = source.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_size > MAX_SCORECARD_BYTES
        ):
            raise ValueError("scorecard source is unsafe")
        value = json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=_object_without_duplicates
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("scorecard source is invalid") from error
    if not isinstance(value, dict):
        raise ValueError("scorecard must be a JSON object")
    assert_public_safe(value, REPOSITORY_ROOT)
    return value


def _exact_keys(value: dict[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise ValueError("scorecard keys are invalid")


def _trial_from_public(value: Any) -> TrialResult:
    if not isinstance(value, dict):
        raise ValueError("trial must be an object")
    required = {
        "adapter_id",
        "adapter_version",
        "attempt",
        "elapsed_ms",
        "seed",
        "status",
        "task_digest",
        "task_id",
        "track",
        "trial_id",
    }
    optional = {"failure_class", "failure_code", "checks_passed", "checks_total", "tool_calls"}
    if not required <= set(value) or set(value) - required - optional:
        raise ValueError("trial keys are invalid")
    return TrialResult(
        trial_id=value["trial_id"],
        task_id=value["task_id"],
        task_digest=value["task_digest"],
        adapter_id=value["adapter_id"],
        adapter_version=value["adapter_version"],
        attempt=value["attempt"],
        seed=value["seed"],
        status=OutcomeStatus(value["status"]),
        elapsed_ms=value["elapsed_ms"],
        failure_class=(FailureClass(value["failure_class"]) if "failure_class" in value else None),
        failure_code=value.get("failure_code"),
        checks_passed=value.get("checks_passed"),
        checks_total=value.get("checks_total"),
        tool_calls=value.get("tool_calls"),
        track=value["track"],
    )


def _track_from_public(value: Any) -> TrackScorecard:
    if not isinstance(value, dict):
        raise ValueError("track score must be an object")
    _exact_keys(
        value,
        {
            "failed_trials",
            "invalid_trials",
            "pass_rate",
            "passed_trials",
            "track",
            "valid_trials",
        },
    )
    return TrackScorecard(**value)


def _scorecard_from_public(value: dict[str, Any]) -> Scorecard:
    _exact_keys(
        value,
        {
            "effort",
            "failed_trials",
            "failure_counts",
            "invalid_trials",
            "league",
            "median_elapsed_ms",
            "median_tool_calls",
            "model",
            "pass_rate",
            "passed_trials",
            "run_digest",
            "run_id",
            "schema_version",
            "tracks",
            "trials",
            "valid_trials",
        },
    )
    failures = value["failure_counts"]
    if not isinstance(failures, list):
        raise ValueError("failure_counts must be a list")
    failure_counts: list[tuple[str, int]] = []
    for failure in failures:
        if not isinstance(failure, dict):
            raise ValueError("failure count must be an object")
        _exact_keys(failure, {"code", "count"})
        failure_counts.append((failure["code"], failure["count"]))
    trials = value["trials"]
    tracks = value["tracks"]
    if not isinstance(trials, list) or not isinstance(tracks, list):
        raise ValueError("scorecard trials and tracks must be lists")
    return Scorecard(
        schema_version=value["schema_version"],
        run_id=value["run_id"],
        run_digest=value["run_digest"],
        valid_trials=value["valid_trials"],
        invalid_trials=value["invalid_trials"],
        passed_trials=value["passed_trials"],
        failed_trials=value["failed_trials"],
        pass_rate=value["pass_rate"],
        median_elapsed_ms=value["median_elapsed_ms"],
        median_tool_calls=value["median_tool_calls"],
        failure_counts=tuple(failure_counts),
        tracks=tuple(_track_from_public(track) for track in tracks),
        league=value["league"],
        model=value["model"],
        effort=value["effort"],
        trials=tuple(_trial_from_public(trial) for trial in trials),
    )


def _compare_command(args: argparse.Namespace) -> int:
    destination = _safe_result_path(args.public_result, ())
    baseline_path = _resolved(args.baseline)
    candidate_path = _resolved(args.candidate)
    if destination in {baseline_path, candidate_path}:
        raise ValueError("comparison output cannot overwrite an input scorecard")
    baseline = _scorecard_from_public(_read_public_object(baseline_path))
    candidate = _scorecard_from_public(_read_public_object(candidate_path))
    comparison = compare_runs(baseline, candidate, comparison_seed=args.comparison_seed)
    write_public_json(destination, comparison.to_public_dict(), REPOSITORY_ROOT)
    print(
        f"comparison {comparison.decision}: {comparison.paired_trials} pairs; "
        f"delta {comparison.pass_rate_delta:+.3f}"
    )
    return 0


def _validate_command(args: argparse.Namespace) -> int:
    tasks = discover_tasks(_resolved(args.root))
    tracks = ", ".join(sorted({task.identity.track for task in tasks}))
    print(f"{len(tasks)} valid tasks ({tracks})")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "tasks":
            return _validate_command(args)
        if args.command == "compare":
            return _compare_command(args)
        return asyncio.run(_run_command(args))
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 130
    except (TaskContractError, PublicSafetyError, ValueError, OSError):
        print("carl-bench: configuration or contract error", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
