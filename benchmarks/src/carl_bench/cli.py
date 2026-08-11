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
from carl_bench.candidate_evidence import scorecard_from_public
from carl_bench.canonical import canonical_json_bytes
from carl_bench.experiment import (
    EventType,
    ExperimentEvent,
    ExperimentManifest,
    ReviewVerdict,
    evaluate_dry_run,
)
from carl_bench.ledger import ExperimentLedger
from carl_bench.models import RunManifest, TrialResult
from carl_bench.report import compare_runs, summarize_run
from carl_bench.runner import BenchmarkRunner
from carl_bench.sanitize import PublicSafetyError, assert_public_safe, write_public_json
from carl_bench.tasks import BenchmarkTask, TaskContractError, discover_tasks

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
MAX_SCORECARD_BYTES = 4 * 1_048_576
MAX_CONTROL_INPUT_BYTES = 1_048_576


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

    experiment = commands.add_parser(
        "experiment", help="operate the owner-private dry-run experiment graph"
    )
    experiment_commands = experiment.add_subparsers(dest="experiment_command", required=True)

    initialize = experiment_commands.add_parser("init", help="register an immutable manifest")
    initialize.add_argument("--ledger", required=True, type=Path)
    initialize.add_argument("--manifest", required=True, type=Path)

    record = experiment_commands.add_parser("record", help="append one normalized graph event")
    record.add_argument("--ledger", required=True, type=Path)
    record.add_argument("--event", required=True, type=Path)

    for name, help_text in (
        ("status", "emit a sanitized replay projection"),
        ("decide", "emit a deterministic dry-run decision"),
    ):
        command = experiment_commands.add_parser(name, help=help_text)
        command.add_argument("--ledger", required=True, type=Path)
        command.add_argument("--experiment-id", required=True)
        command.add_argument("--public-result", required=True, type=Path)

    budget = experiment_commands.add_parser(
        "budget-check", help="check live-run budget without reserving or spending"
    )
    budget.add_argument("--ledger", required=True, type=Path)
    budget.add_argument("--experiment-id", required=True)
    budget.add_argument("--requested-microdollars", required=True, type=int)
    budget.add_argument("--at", required=True)
    budget.add_argument("--active-live-workers", required=True, type=int)
    budget.add_argument("--public-result", required=True, type=Path)
    return parser


def _anchored(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    return absolute.parent.resolve(strict=False) / absolute.name


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _safe_result_path(destination: Path, forbidden_roots: Sequence[Path]) -> Path:
    result = _anchored(destination)
    for root in forbidden_roots:
        if _inside(result, _anchored(root)):
            raise ValueError("public result cannot be written inside benchmark task sources")
    return result


def _select_tasks(root: Path, selectors: Sequence[str]) -> tuple[BenchmarkTask, ...]:
    tasks = discover_tasks(_anchored(root))
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
    task_root = _anchored(args.tasks)
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
    source = _anchored(path)
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


def _read_control_object(path: Path) -> dict[str, Any]:
    source = _anchored(path)
    try:
        metadata = source.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_size > MAX_CONTROL_INPUT_BYTES
        ):
            raise ValueError("control input is unsafe")
        value = json.loads(
            source.read_text(encoding="utf-8"), object_pairs_hook=_object_without_duplicates
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("control input is invalid") from error
    if not isinstance(value, dict):
        raise ValueError("control input must be a JSON object")
    return value


def _private_ledger(path: Path) -> ExperimentLedger:
    ledger_path = _anchored(path)
    if _inside(ledger_path, REPOSITORY_ROOT.resolve()):
        raise ValueError("experiment ledger must remain outside the public repository")
    return ExperimentLedger(ledger_path)


def _event_from_control(value: dict[str, Any]) -> ExperimentEvent:
    if set(value) != {
        "event_type",
        "experiment_id",
        "occurred_at",
        "payload",
        "schema_version",
        "stage_attempt_id",
    }:
        raise ValueError("event keys are invalid")
    if value["schema_version"] != 1 or not isinstance(value["payload"], dict):
        raise ValueError("event contract is invalid")
    try:
        event_type = EventType(value["event_type"])
    except (TypeError, ValueError) as error:
        raise ValueError("event type is invalid") from error
    event = ExperimentEvent.create(
        experiment_id=value["experiment_id"],
        stage_attempt_id=value["stage_attempt_id"],
        event_type=event_type,
        occurred_at=value["occurred_at"],
        payload=value["payload"],
    )
    if canonical_json_bytes(event.to_canonical_dict()) != canonical_json_bytes(value):
        raise ValueError("event contract is noncanonical")
    return event


def _experiment_output(destination: Path, ledger: Path) -> Path:
    result = _safe_result_path(destination, ())
    if result == _anchored(ledger):
        raise ValueError("public result cannot overwrite the private ledger")
    return result


def _status_dict(ledger: ExperimentLedger, experiment_id: str) -> dict[str, Any]:
    projection = ledger.projection(experiment_id)
    return {
        "active_lease": projection.lease is not None,
        "candidate_review_approvals": sum(
            review.verdict is ReviewVerdict.APPROVE for review in projection.candidate_reviews
        ),
        "event_count": projection.last_sequence,
        "experiment_id": projection.experiment_id,
        "live_spend_microdollars": projection.live_spend_microdollars,
        "manifest_digest": projection.manifest_digest,
        "projection_digest": projection.digest,
        "proposal_review_approvals": sum(
            review.verdict is ReviewVerdict.APPROVE for review in projection.proposal_reviews
        ),
        "schema_version": 1,
        "state": projection.state.value,
    }


def _experiment_command(args: argparse.Namespace) -> int:
    ledger = _private_ledger(args.ledger)
    if args.experiment_command == "init":
        manifest = ExperimentManifest.from_canonical_dict(_read_control_object(args.manifest))
        registered = ledger.register_manifest(manifest)
        status = "registered" if registered else "already_registered"
        print(f"experiment {manifest.experiment_id}: {status} {manifest.digest}")
        return 0
    if args.experiment_command == "record":
        event = _event_from_control(_read_control_object(args.event))
        appended = ledger.append(event)
        status = "appended" if appended.appended else "already_recorded"
        print(f"event {event.stage_attempt_id}: {status} ordinal {appended.ordinal}")
        return 0

    destination = _experiment_output(args.public_result, args.ledger)
    if args.experiment_command == "status":
        value = _status_dict(ledger, args.experiment_id)
    elif args.experiment_command == "decide":
        manifest = ledger.load_manifest(args.experiment_id)
        value = evaluate_dry_run(manifest, ledger.projection(args.experiment_id)).to_public_dict()
    else:
        budget = ledger.can_dispatch_live_run(
            args.experiment_id,
            requested_microdollars=args.requested_microdollars,
            at=args.at,
            active_live_workers=args.active_live_workers,
        )
        value = {
            "active_live_workers": budget.active_live_workers,
            "allowed": budget.allowed,
            "daily_after_microdollars": budget.daily_after_microdollars,
            "experiment_after_microdollars": budget.experiment_after_microdollars,
            "experiment_elapsed_seconds": budget.experiment_elapsed_seconds,
            "experiment_id": args.experiment_id,
            "reasons": list(budget.reasons),
            "schema_version": 1,
            "weekly_after_microdollars": budget.weekly_after_microdollars,
        }
    write_public_json(destination, value, REPOSITORY_ROOT)
    print(f"experiment {args.experiment_id}: wrote {args.experiment_command} result")
    return 0


def _compare_command(args: argparse.Namespace) -> int:
    destination = _safe_result_path(args.public_result, ())
    baseline_path = _anchored(args.baseline)
    candidate_path = _anchored(args.candidate)
    if destination in {baseline_path, candidate_path}:
        raise ValueError("comparison output cannot overwrite an input scorecard")
    baseline = scorecard_from_public(_read_public_object(baseline_path))
    candidate = scorecard_from_public(_read_public_object(candidate_path))
    comparison = compare_runs(baseline, candidate, comparison_seed=args.comparison_seed)
    write_public_json(destination, comparison.to_public_dict(), REPOSITORY_ROOT)
    print(
        f"comparison {comparison.decision}: {comparison.paired_trials} pairs; "
        f"delta {comparison.pass_rate_delta:+.3f}"
    )
    return 0


def _validate_command(args: argparse.Namespace) -> int:
    tasks = discover_tasks(_anchored(args.root))
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
        if args.command == "experiment":
            return _experiment_command(args)
        return asyncio.run(_run_command(args))
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 130
    except (TaskContractError, PublicSafetyError, TypeError, ValueError, OSError):
        print("carl-bench: configuration or contract error", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
