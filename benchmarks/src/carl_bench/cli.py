"""Command-line orchestration for public-safe Carl benchmark runs."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from carl_bench.adapters.base import AgentAdapter
from carl_bench.adapters.carl_acp import CarlAcpAdapter
from carl_bench.adapters.codex_cli import CodexCliAdapter
from carl_bench.adapters.scripted import ScriptedAdapter
from carl_bench.artifacts import MAX_ARTIFACT_BYTES, PrivateArtifactStore
from carl_bench.candidate import (
    DraftPullRequest,
    PairedEvidence,
    PreparedCandidate,
    ReviewAttestation,
    ReviewPacket,
    SealedCandidate,
)
from carl_bench.candidate_evidence import (
    bind_paired_evidence,
    issue_review_packet,
    record_review_attestation,
    scorecard_from_public,
)
from carl_bench.candidate_git import CandidateGitManager, TrustedCheckRegistry
from carl_bench.canonical import canonical_json_bytes
from carl_bench.experiment import (
    EventType,
    ExperimentEvent,
    ExperimentManifest,
    ExperimentState,
    ReviewRole,
    ReviewVerdict,
    evaluate_dry_run,
    evaluate_phase3,
    reduce_events,
)
from carl_bench.github_draft import DraftPrGateway
from carl_bench.ledger import ExperimentLedger
from carl_bench.models import RunManifest, Scorecard, TrialResult
from carl_bench.report import compare_runs, summarize_run
from carl_bench.run_attestation import attest_run
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
    run.add_argument("--subject-commit", required=True)
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

    run_attested = commands.add_parser(
        "run-attested", help="run and attest promotion evidence from a clean checkout"
    )
    run_attested.add_argument("--checkout", required=True, type=Path)
    run_attested.add_argument("--tasks", required=True, type=Path)
    run_attested.add_argument(
        "--adapter", required=True, choices=("scripted", "carl-acp", "codex-cli")
    )
    run_attested.add_argument(
        "--task", action="append", default=[], help="exact task ID to include"
    )
    run_attested.add_argument("--attempts", required=True, type=int)
    run_attested.add_argument("--seed", required=True, type=int)
    run_attested.add_argument("--experiment-id", required=True)
    run_attested.add_argument("--role", required=True, choices=("baseline", "candidate"))
    run_attested.add_argument("--attestation-key", required=True, type=Path)
    run_attested.add_argument("--private-attestation", required=True, type=Path)
    run_attested.add_argument("--public-result", required=True, type=Path)
    run_attested.add_argument("--league", choices=("plumbing", "same-model", "native-product"))
    run_attested.add_argument("--model")
    run_attested.add_argument("--effort", choices=("minimal", "low", "medium", "high", "xhigh"))
    run_attested.add_argument("--carl-bin", type=Path)
    run_attested.add_argument("--carl-data-dir", type=Path)
    run_attested.add_argument("--codex-bin", type=Path)
    run_attested.add_argument("--codex-home", type=Path)
    run_attested.add_argument(
        "--permission-mode",
        default="default",
        choices=("plan", "default", "acceptEdits", "dontAsk"),
    )

    attestation_key = commands.add_parser(
        "attestation-key", help="manage the controller-only benchmark attestation key"
    )
    key_commands = attestation_key.add_subparsers(dest="key_command", required=True)
    key_init = key_commands.add_parser("init", help="create a new owner-private signing key")
    key_init.add_argument("--private-key", required=True, type=Path)
    key_init.add_argument("--repository", required=True, type=Path)

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

    candidate = commands.add_parser(
        "candidate", help="operate the isolated phase-three candidate workflow"
    )
    candidate_commands = candidate.add_subparsers(dest="candidate_command", required=True)

    def add_candidate_context(command: argparse.ArgumentParser) -> None:
        command.add_argument("--ledger", required=True, type=Path)
        command.add_argument("--experiment-id", required=True)
        command.add_argument("--repository", required=True, type=Path)
        command.add_argument("--worktree-root", required=True, type=Path)
        command.add_argument("--artifacts", required=True, type=Path)
        command.add_argument("--remote", required=True)
        command.add_argument("--expected-remote-url", required=True)

    def add_mutation(command: argparse.ArgumentParser) -> None:
        add_candidate_context(command)
        command.add_argument("--stage-attempt-id", required=True)
        command.add_argument("--occurred-at", required=True)
        command.add_argument("--lease-owner-id", required=True)
        command.add_argument("--lease-stage-attempt-id", required=True)

    prepare = candidate_commands.add_parser("prepare", help="prepare an isolated worktree")
    add_mutation(prepare)
    prepare.add_argument("--private-result", required=True, type=Path)

    seal = candidate_commands.add_parser("seal", help="validate and seal one candidate commit")
    add_mutation(seal)
    seal.add_argument("--check-registry", required=True, type=Path)
    seal.add_argument("--report", required=True, type=Path)
    seal.add_argument("--public-result", required=True, type=Path)

    bind = candidate_commands.add_parser(
        "bind-comparison", help="bind an exact paired benchmark improvement"
    )
    add_mutation(bind)
    bind.add_argument("--baseline-attestation", required=True, type=Path)
    bind.add_argument("--candidate-attestation", required=True, type=Path)
    bind.add_argument("--attestation-key", required=True, type=Path)
    bind.add_argument("--comparison-seed", required=True, type=int)
    bind.add_argument("--public-result", required=True, type=Path)

    packet = candidate_commands.add_parser(
        "review-packet", help="issue one role-specific private review packet"
    )
    add_mutation(packet)
    packet.add_argument(
        "--role",
        required=True,
        choices=("correctness", "security", "maintainability", "benchmark_integrity"),
    )
    packet.add_argument("--private-result", required=True, type=Path)

    review = candidate_commands.add_parser(
        "record-review", help="record one independent review attestation"
    )
    add_mutation(review)
    review.add_argument("--packet", required=True, type=Path)
    review.add_argument("--reviewer-id", required=True)
    review.add_argument("--context-id", required=True)
    review.add_argument("--verdict", required=True, choices=("approve", "reject", "hard_finding"))
    review.add_argument("--report", required=True, type=Path)
    review.add_argument("--public-result", required=True, type=Path)

    candidate_status = candidate_commands.add_parser(
        "status", help="emit sanitized phase-three status"
    )
    candidate_status.add_argument("--ledger", required=True, type=Path)
    candidate_status.add_argument("--experiment-id", required=True)
    candidate_status.add_argument("--public-result", required=True, type=Path)

    draft = candidate_commands.add_parser(
        "open-draft-pr", help="push the sealed commit and open or reconcile a draft PR"
    )
    add_mutation(draft)
    draft.add_argument("--repository-slug", required=True)
    draft.add_argument("--base-branch", required=True)
    draft.add_argument("--gh-executable", required=True, type=Path)
    draft.add_argument("--gateway-private-root", required=True, type=Path)
    draft.add_argument("--gateway-env-name", action="append", default=[])
    draft.add_argument("--enable-github-draft", action="store_true")
    draft.add_argument("--public-result", required=True, type=Path)

    dispose = candidate_commands.add_parser(
        "dispose", help="remove the exact clean candidate worktree after draft creation"
    )
    add_mutation(dispose)
    dispose.add_argument("--public-result", required=True, type=Path)
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


async def _execute_run(
    args: argparse.Namespace, *, subject_commit: str
) -> tuple[RunManifest, Scorecard, tuple[BenchmarkTask, ...], int]:
    if not 1 <= args.attempts <= 10:
        raise ValueError("attempts must be between 1 and 10")
    if isinstance(args.seed, bool) or not 0 <= args.seed < (1 << 63):
        raise ValueError("seed must be a non-negative 63-bit integer")
    if args.seed + args.attempts - 1 >= (1 << 63):
        raise ValueError("attempt seeds exceed the supported range")
    task_root = _anchored(args.tasks)
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
        subject_commit=subject_commit,
        league=league,
        model=model,
        effort=effort,
        started_at=datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
        seed=args.seed,
        trials=tuple(trials),
    )
    scorecard = summarize_run(manifest, trials)
    if scorecard.invalid_trials:
        status = 4
    elif scorecard.failed_trials:
        status = 3
    else:
        status = 0
    return manifest, scorecard, tasks, status


def _print_run_result(scorecard: Scorecard) -> None:
    print(
        f"run {scorecard.run_id}: {scorecard.passed_trials}/{scorecard.valid_trials} "
        f"passed; {scorecard.invalid_trials} invalid"
    )


async def _run_command(args: argparse.Namespace) -> int:
    task_root = _anchored(args.tasks)
    destination = _safe_result_path(args.public_result, (task_root,))
    _, scorecard, _, status = await _execute_run(args, subject_commit=args.subject_commit)
    write_public_json(destination, scorecard.to_public_dict(), REPOSITORY_ROOT)
    _print_run_result(scorecard)
    return status


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


def _read_private_bytes(path: Path, *, maximum: int = MAX_ARTIFACT_BYTES) -> bytes:
    source = _anchored(path)
    try:
        metadata = source.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_size > maximum
            or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077)
            or (os.name != "nt" and hasattr(os, "getuid") and metadata.st_uid != os.getuid())
        ):
            raise ValueError("private input is unsafe")
        return source.read_bytes()
    except OSError as error:
        raise ValueError("private input is invalid") from error


def _read_private_object(path: Path, *, maximum: int = MAX_CONTROL_INPUT_BYTES) -> dict[str, Any]:
    try:
        value = json.loads(
            _read_private_bytes(path, maximum=maximum).decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("private JSON input is invalid") from error
    if not isinstance(value, dict):
        raise ValueError("private JSON input must be an object")
    return value


def _write_private_json(destination: Path, value: Any, *forbidden_roots: Path) -> None:
    target = _anchored(destination)
    if any(_inside(target, _anchored(root)) for root in forbidden_roots):
        raise ValueError("private result path is unsafe")
    try:
        existing = target.lstat()
    except FileNotFoundError:
        existing = None
    except OSError as error:
        raise ValueError("private result path is unsafe") from error
    if existing is not None and (
        not stat.S_ISREG(existing.st_mode) or stat.S_ISLNK(existing.st_mode)
    ):
        raise ValueError("private result path is unsafe")
    payload = canonical_json_bytes(value) + b"\n"
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.parent.is_symlink() or not target.parent.is_dir():
        raise ValueError("private result path is unsafe")
    if os.name != "nt":
        target.parent.chmod(0o700)
    descriptor, name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    temporary = Path(name)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _init_attestation_key(args: argparse.Namespace) -> int:
    destination = _anchored(args.private_key)
    repository = _anchored(args.repository)
    if _inside(destination, repository):
        raise ValueError("attestation key must remain outside the repository")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if destination.parent.is_symlink() or not destination.parent.is_dir():
        raise ValueError("attestation key parent is unsafe")
    if os.name != "nt":
        destination.parent.chmod(0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(destination, flags, 0o600)
    except OSError as error:
        raise ValueError("attestation key cannot be created") from error
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(os.urandom(32))
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    print("created controller-only benchmark attestation key")
    return 0


def _load_attestation_key(path: Path, checkout: Path) -> bytes:
    source = _anchored(path)
    if _inside(source, _anchored(checkout)):
        raise ValueError("attestation key must remain outside the benchmark checkout")
    key = _read_private_bytes(source, maximum=64)
    if not 32 <= len(key) <= 64:
        raise ValueError("attestation key is invalid")
    return key


def _git_checkout_output(checkout: Path, *arguments: str) -> bytes:
    environment = {
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
    }
    try:
        result = subprocess.run(
            ("git", "-C", os.fspath(checkout), *arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("benchmark checkout is unavailable") from error
    if result.returncode != 0 or len(result.stdout) > MAX_CONTROL_INPUT_BYTES:
        raise ValueError("benchmark checkout is invalid")
    return result.stdout


def _clean_checkout_snapshot(checkout: Path) -> tuple[str, str]:
    root = _anchored(checkout)
    top = Path(
        os.fsdecode(_git_checkout_output(root, "rev-parse", "--show-toplevel")).strip()
    ).resolve(strict=True)
    if top != root.resolve(strict=True):
        raise ValueError("benchmark checkout must be the exact Git worktree root")
    status = _git_checkout_output(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    if status:
        raise ValueError("benchmark checkout must be clean and sealed")
    commit = os.fsdecode(
        _git_checkout_output(root, "rev-parse", "--verify", "HEAD^{commit}")
    ).strip()
    tree = os.fsdecode(_git_checkout_output(root, "rev-parse", "--verify", "HEAD^{tree}")).strip()
    return commit, tree


async def _run_attested_command(args: argparse.Namespace) -> int:
    checkout = _anchored(args.checkout)
    task_root = _anchored(args.tasks)
    if not _inside(task_root, checkout):
        raise ValueError("attested benchmark tasks must come from the exact checkout")
    public_result = _safe_result_path(args.public_result, (task_root, checkout))
    private_attestation = _anchored(args.private_attestation)
    if _inside(private_attestation, checkout):
        raise ValueError("run attestation must remain outside the benchmark checkout")
    before = _clean_checkout_snapshot(checkout)
    manifest, scorecard, tasks, status = await _execute_run(args, subject_commit=before[0])
    after = _clean_checkout_snapshot(checkout)
    if after != before:
        raise ValueError("benchmark checkout changed during the attested run")
    key = _load_attestation_key(args.attestation_key, checkout)
    task_identities = tuple(
        {
            "digest": task.identity.digest,
            "task_id": task.identity.task_id,
            "track": task.identity.track,
        }
        for task in tasks
    )
    attestation = attest_run(
        experiment_id=args.experiment_id,
        role=args.role,
        checkout_tree_digest=before[1],
        manifest=manifest,
        scorecard=scorecard,
        task_identities=task_identities,
        attempts=args.attempts,
        key=key,
    )
    _write_private_json(private_attestation, attestation.to_canonical_dict(), checkout)
    write_public_json(public_result, scorecard.to_public_dict(), REPOSITORY_ROOT)
    _print_run_result(scorecard)
    return status


def _candidate_manager(args: argparse.Namespace) -> CandidateGitManager:
    store = PrivateArtifactStore(_anchored(args.artifacts), _anchored(args.repository))
    return CandidateGitManager(
        repository_root=_anchored(args.repository),
        worktree_root=_anchored(args.worktree_root),
        artifact_store=store,
        remote=args.remote,
        expected_remote_url=args.expected_remote_url,
    )


def _existing_candidate_event(
    ledger: ExperimentLedger,
    experiment_id: str,
    stage_attempt_id: str,
    expected_type: EventType,
) -> ExperimentEvent | None:
    for event in ledger.events(experiment_id):
        if event.stage_attempt_id != stage_attempt_id:
            continue
        if event.event_type is not expected_type:
            raise ValueError("stage attempt conflicts with an existing event")
        return event
    return None


def _append_candidate_event(
    ledger: ExperimentLedger,
    *,
    experiment_id: str,
    stage_attempt_id: str,
    occurred_at: str,
    event_type: EventType,
    payload: dict[str, Any],
    lease_owner_id: str,
    lease_stage_attempt_id: str,
) -> None:
    authorized_payload = {
        **payload,
        "_lease": {
            "owner_id": lease_owner_id,
            "stage_attempt_id": lease_stage_attempt_id,
        },
    }
    ledger.append(
        ExperimentEvent.create(
            experiment_id=experiment_id,
            stage_attempt_id=stage_attempt_id,
            event_type=event_type,
            occurred_at=occurred_at,
            payload=authorized_payload,
        )
    )


def _candidate_event_payload(event: ExperimentEvent) -> dict[str, Any]:
    return {key: value for key, value in event.payload.items() if key != "_lease"}


def _candidate_status_dict(
    manifest: ExperimentManifest, ledger: ExperimentLedger
) -> dict[str, Any]:
    projection = ledger.projection(manifest.experiment_id)
    decision = evaluate_phase3(manifest, projection)
    candidate = projection.candidate
    paired = projection.paired_evidence
    draft = projection.draft_pull_request
    return {
        "candidate_commit": candidate.candidate_commit if candidate is not None else None,
        "candidate_digest": candidate.digest if candidate is not None else None,
        "candidate_review_approvals": sum(
            review.verdict == "approve" for review in projection.candidate_attestations
        ),
        "candidate_review_hard_findings": sum(
            review.verdict == "hard_finding" for review in projection.candidate_attestations
        ),
        "candidate_review_packets": len(projection.review_packets),
        "candidate_reviews": len(projection.candidate_attestations),
        "deterministic_check_count": len(candidate.checks) if candidate is not None else 0,
        "draft_pull_request_number": draft.number if draft is not None else None,
        "draft_pull_request_url": draft.url if draft is not None else None,
        "experiment_id": manifest.experiment_id,
        "manifest_digest": manifest.digest,
        "next_action": decision.next_action,
        "outcome": decision.outcome,
        "paired_decision": paired.decision if paired is not None else None,
        "paired_evidence_digest": paired.digest if paired is not None else None,
        "projection_digest": projection.digest,
        "reasons": list(decision.reasons),
        "schema_version": 1,
        "state": projection.state.value,
        "workspace_disposed": projection.workspace_disposed,
    }


def _candidate_command(args: argparse.Namespace) -> int:
    ledger = _private_ledger(args.ledger)
    manifest = ledger.load_manifest(args.experiment_id)
    if args.candidate_command == "status":
        destination = _experiment_output(args.public_result, args.ledger)
        write_public_json(destination, _candidate_status_dict(manifest, ledger), REPOSITORY_ROOT)
        print(f"candidate {args.experiment_id}: wrote status")
        return 0

    manager = _candidate_manager(args)
    projection = ledger.projection(args.experiment_id)
    if args.candidate_command == "prepare":
        existing = _existing_candidate_event(
            ledger, args.experiment_id, args.stage_attempt_id, EventType.WORKSPACE_PREPARED
        )
        if existing is None:
            if projection.state is not ExperimentState.BUILDING or projection.lease is None:
                raise ValueError("candidate preparation is not eligible")
            prepared = manager.prepare(manifest, stage_attempt_id=args.stage_attempt_id)
            _append_candidate_event(
                ledger,
                experiment_id=args.experiment_id,
                stage_attempt_id=args.stage_attempt_id,
                occurred_at=args.occurred_at,
                event_type=EventType.WORKSPACE_PREPARED,
                payload=prepared.to_canonical_dict(),
                lease_owner_id=args.lease_owner_id,
                lease_stage_attempt_id=args.lease_stage_attempt_id,
            )
        else:
            prepared = PreparedCandidate.from_canonical_dict(_candidate_event_payload(existing))
        _write_private_json(
            args.private_result,
            {
                **prepared.to_canonical_dict(),
                "worktree": os.fspath(manager.worktree_path(prepared)),
            },
            REPOSITORY_ROOT,
            args.repository,
        )
        print(f"candidate {args.experiment_id}: prepared {prepared.branch}")
        return 0

    if args.candidate_command == "seal":
        existing = _existing_candidate_event(
            ledger, args.experiment_id, args.stage_attempt_id, EventType.CANDIDATE_SEALED
        )
        report = _read_private_bytes(args.report)
        if existing is None:
            if projection.prepared_candidate is None:
                raise ValueError("candidate has not been prepared")
            registry = TrustedCheckRegistry.load(args.check_registry)
            sealed = manager.seal(manifest, projection.prepared_candidate, registry, report=report)
            _append_candidate_event(
                ledger,
                experiment_id=args.experiment_id,
                stage_attempt_id=args.stage_attempt_id,
                occurred_at=args.occurred_at,
                event_type=EventType.CANDIDATE_SEALED,
                payload=sealed.to_canonical_dict(),
                lease_owner_id=args.lease_owner_id,
                lease_stage_attempt_id=args.lease_stage_attempt_id,
            )
        else:
            sealed = SealedCandidate.from_canonical_dict(_candidate_event_payload(existing))
            if manager.artifact_store.read(sealed.report_artifact) != report:
                raise ValueError("candidate report conflicts with sealed evidence")
        write_public_json(
            _experiment_output(args.public_result, args.ledger),
            sealed.to_public_dict(),
            REPOSITORY_ROOT,
        )
        print(f"candidate {args.experiment_id}: sealed {sealed.candidate_commit}")
        return 0

    if args.candidate_command == "bind-comparison":
        existing = _existing_candidate_event(
            ledger,
            args.experiment_id,
            args.stage_attempt_id,
            EventType.PAIRED_EVIDENCE_RECORDED,
        )
        if existing is None:
            if projection.candidate is None:
                raise ValueError("candidate has not been sealed")
            baseline_attestation = _read_private_object(
                args.baseline_attestation, maximum=MAX_SCORECARD_BYTES
            )
            candidate_attestation = _read_private_object(
                args.candidate_attestation, maximum=MAX_SCORECARD_BYTES
            )
            attestation_key = _load_attestation_key(args.attestation_key, args.repository)
            paired = bind_paired_evidence(
                manifest,
                projection.candidate,
                baseline_attestation,
                candidate_attestation,
                attestation_key=attestation_key,
                comparison_seed=args.comparison_seed,
                store=manager.artifact_store,
            )
            _append_candidate_event(
                ledger,
                experiment_id=args.experiment_id,
                stage_attempt_id=args.stage_attempt_id,
                occurred_at=args.occurred_at,
                event_type=EventType.PAIRED_EVIDENCE_RECORDED,
                payload=paired.to_canonical_dict(),
                lease_owner_id=args.lease_owner_id,
                lease_stage_attempt_id=args.lease_stage_attempt_id,
            )
        else:
            paired = PairedEvidence.from_canonical_dict(_candidate_event_payload(existing))
        value = {
            "candidate_commit": paired.candidate_commit,
            "confidence_lower_basis_points": paired.confidence_lower_basis_points,
            "decision": paired.decision,
            "experiment_id": paired.experiment_id,
            "paired_evidence_digest": paired.digest,
            "paired_trials": paired.paired_trials,
            "pass_rate_delta_basis_points": paired.pass_rate_delta_basis_points,
            "schema_version": 1,
        }
        write_public_json(
            _experiment_output(args.public_result, args.ledger), value, REPOSITORY_ROOT
        )
        print(f"candidate {args.experiment_id}: bound paired evidence")
        return 0

    if args.candidate_command == "review-packet":
        existing = _existing_candidate_event(
            ledger,
            args.experiment_id,
            args.stage_attempt_id,
            EventType.REVIEW_PACKET_RECORDED,
        )
        if existing is None:
            packet = issue_review_packet(manifest, projection, ReviewRole(args.role))
            _append_candidate_event(
                ledger,
                experiment_id=args.experiment_id,
                stage_attempt_id=args.stage_attempt_id,
                occurred_at=args.occurred_at,
                event_type=EventType.REVIEW_PACKET_RECORDED,
                payload=packet.to_canonical_dict(),
                lease_owner_id=args.lease_owner_id,
                lease_stage_attempt_id=args.lease_stage_attempt_id,
            )
        else:
            packet = ReviewPacket.from_canonical_dict(_candidate_event_payload(existing))
            if packet.role != args.role:
                raise ValueError("review role conflicts with existing packet")
        _write_private_json(
            args.private_result,
            packet.to_canonical_dict(),
            REPOSITORY_ROOT,
            args.repository,
        )
        print(f"candidate {args.experiment_id}: issued {packet.role} packet")
        return 0

    if args.candidate_command == "record-review":
        existing = _existing_candidate_event(
            ledger, args.experiment_id, args.stage_attempt_id, EventType.REVIEW_ATTESTED
        )
        report = _read_private_bytes(args.report)
        if existing is None:
            packet = ReviewPacket.from_canonical_dict(_read_control_object(args.packet))
            attestation = record_review_attestation(
                manifest,
                projection,
                packet,
                reviewer_id=args.reviewer_id,
                context_id=args.context_id,
                verdict=args.verdict,
                report=report,
                store=manager.artifact_store,
            )
            _append_candidate_event(
                ledger,
                experiment_id=args.experiment_id,
                stage_attempt_id=args.stage_attempt_id,
                occurred_at=args.occurred_at,
                event_type=EventType.REVIEW_ATTESTED,
                payload=attestation.to_canonical_dict(),
                lease_owner_id=args.lease_owner_id,
                lease_stage_attempt_id=args.lease_stage_attempt_id,
            )
        else:
            attestation = ReviewAttestation.from_canonical_dict(_candidate_event_payload(existing))
            if manager.artifact_store.read(attestation.report_artifact) != report:
                raise ValueError("review report conflicts with existing attestation")
        value = {
            "attestation_digest": attestation.digest,
            "candidate_commit": attestation.candidate_commit,
            "experiment_id": attestation.experiment_id,
            "report_digest": attestation.report_artifact.digest,
            "role": attestation.role,
            "schema_version": 1,
            "verdict": attestation.verdict,
        }
        write_public_json(
            _experiment_output(args.public_result, args.ledger), value, REPOSITORY_ROOT
        )
        print(f"candidate {args.experiment_id}: recorded {attestation.role} review")
        return 0

    if args.candidate_command == "dispose":
        existing = _existing_candidate_event(
            ledger, args.experiment_id, args.stage_attempt_id, EventType.WORKSPACE_DISPOSED
        )
        if existing is None:
            if projection.prepared_candidate is None or projection.candidate is None:
                raise ValueError("candidate has not been sealed")
            payload = {
                "branch": projection.candidate.branch,
                "candidate_commit": projection.candidate.candidate_commit,
            }
            event = ExperimentEvent.create(
                experiment_id=args.experiment_id,
                stage_attempt_id=args.stage_attempt_id,
                event_type=EventType.WORKSPACE_DISPOSED,
                occurred_at=args.occurred_at,
                payload={
                    **payload,
                    "_lease": {
                        "owner_id": args.lease_owner_id,
                        "stage_attempt_id": args.lease_stage_attempt_id,
                    },
                },
            )
            reduce_events(manifest, (*ledger.events(args.experiment_id), event))
            manager.dispose(projection.prepared_candidate, projection.candidate)
            ledger.append(event)
        else:
            payload = _candidate_event_payload(existing)
        value = {
            "branch": payload["branch"],
            "candidate_commit": payload["candidate_commit"],
            "disposed": True,
            "experiment_id": args.experiment_id,
            "schema_version": 1,
        }
        write_public_json(
            _experiment_output(args.public_result, args.ledger), value, REPOSITORY_ROOT
        )
        print(f"candidate {args.experiment_id}: disposed candidate worktree")
        return 0

    if not args.enable_github_draft:
        raise ValueError("GitHub draft mutation is disabled")
    existing = _existing_candidate_event(
        ledger, args.experiment_id, args.stage_attempt_id, EventType.DRAFT_PR_RECORDED
    )
    if len(args.gateway_env_name) != len(set(args.gateway_env_name)):
        raise ValueError("duplicate gateway environment name")
    if any(name not in os.environ for name in args.gateway_env_name):
        raise ValueError("gateway environment is unavailable")
    if projection.candidate is None:
        raise ValueError("candidate has not been sealed")
    request_payload = {
        "base_branch": args.base_branch,
        "candidate_commit": projection.candidate.candidate_commit,
        "expected_remote_url": args.expected_remote_url,
        "head_branch": projection.candidate.branch,
        "repository": args.repository_slug,
    }
    request_attempt_id = (
        "draft-request-" + hashlib.sha256(args.stage_attempt_id.encode("utf-8")).hexdigest()[:32]
    )
    request = _existing_candidate_event(
        ledger,
        args.experiment_id,
        request_attempt_id,
        EventType.DRAFT_PR_REQUESTED,
    )
    if request is None:
        _append_candidate_event(
            ledger,
            experiment_id=args.experiment_id,
            stage_attempt_id=request_attempt_id,
            occurred_at=args.occurred_at,
            event_type=EventType.DRAFT_PR_REQUESTED,
            payload=request_payload,
            lease_owner_id=args.lease_owner_id,
            lease_stage_attempt_id=args.lease_stage_attempt_id,
        )
    elif (
        request.occurred_at != args.occurred_at
        or _candidate_event_payload(request) != request_payload
        or request.payload.get("_lease")
        != {
            "owner_id": args.lease_owner_id,
            "stage_attempt_id": args.lease_stage_attempt_id,
        }
    ):
        raise ValueError("draft request conflicts with existing authorization")
    projection = ledger.projection(args.experiment_id)
    gateway = DraftPrGateway(
        repository_root=args.repository,
        repository_slug=args.repository_slug,
        remote=args.remote,
        expected_remote_url=args.expected_remote_url,
        base_branch=args.base_branch,
        gh_executable=args.gh_executable,
        private_root=args.gateway_private_root,
        command_env={name: os.environ[name] for name in args.gateway_env_name},
    )
    draft = gateway.open_or_reconcile(manifest, projection)
    if existing is None:
        _append_candidate_event(
            ledger,
            experiment_id=args.experiment_id,
            stage_attempt_id=args.stage_attempt_id,
            occurred_at=args.occurred_at,
            event_type=EventType.DRAFT_PR_RECORDED,
            payload=draft.to_canonical_dict(),
            lease_owner_id=args.lease_owner_id,
            lease_stage_attempt_id=args.lease_stage_attempt_id,
        )
    else:
        recorded = DraftPullRequest.from_canonical_dict(_candidate_event_payload(existing))
        if draft != recorded:
            raise ValueError("live draft conflicts with recorded draft")
    write_public_json(
        _experiment_output(args.public_result, args.ledger),
        draft.to_canonical_dict(),
        REPOSITORY_ROOT,
    )
    print(f"candidate {args.experiment_id}: draft PR {draft.number}")
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
        if args.command == "candidate":
            return _candidate_command(args)
        if args.command == "attestation-key":
            return _init_attestation_key(args)
        if args.command == "run-attested":
            return asyncio.run(_run_attested_command(args))
        return asyncio.run(_run_command(args))
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 130
    except (TaskContractError, PublicSafetyError, TypeError, ValueError, OSError):
        print("carl-bench: configuration or contract error", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
