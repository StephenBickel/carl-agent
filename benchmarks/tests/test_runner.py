from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from functools import lru_cache
from pathlib import Path

import pytest

from carl_bench.adapters.scripted import ScriptedAdapter
from carl_bench.canonical import sha256_tree
from carl_bench.models import AgentOutcome, AgentRequest, FailureClass, OutcomeStatus
from carl_bench.runner import BenchmarkRunner
from carl_bench.tasks import BenchmarkTask, discover_tasks

TASK_ROOT = Path(__file__).parents[1] / "tasks" / "dev"


@lru_cache(maxsize=3)
def task(track: str) -> BenchmarkTask:
    return next(task for task in discover_tasks(TASK_ROOT) if task.identity.track == track)


class NoopAdapter:
    adapter_id = "noop"

    def version(self) -> str:
        return "1.0.0"

    async def run(self, request: AgentRequest) -> AgentOutcome:
        return AgentOutcome.succeeded(elapsed_ms=1, tool_calls=0)


class FailedAdapter(NoopAdapter):
    adapter_id = "failed"

    async def run(self, request: AgentRequest) -> AgentOutcome:
        return AgentOutcome.failed(code="agent_timeout", elapsed_ms=10)


class CrashingAdapter(NoopAdapter):
    adapter_id = "crashing"

    async def run(self, request: AgentRequest) -> AgentOutcome:
        raise RuntimeError("private adapter detail")


class RecordingAdapter(NoopAdapter):
    adapter_id = "recording"

    def __init__(self) -> None:
        self.workspaces: list[Path] = []

    async def run(self, request: AgentRequest) -> AgentOutcome:
        self.workspaces.append(Path(request.workspace))
        return await super().run(request)


class HangingAdapter(NoopAdapter):
    adapter_id = "hanging"

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.workspace: Path | None = None

    async def run(self, request: AgentRequest) -> AgentOutcome:
        self.workspace = Path(request.workspace)
        self.started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


@pytest.mark.asyncio
@pytest.mark.parametrize("track", ["coding", "workflow", "safety"])
async def test_scripted_oracle_passes_every_track_in_a_fresh_copy(
    tmp_path: Path, track: str
) -> None:
    selected = task(track)
    source_digest = sha256_tree(selected.source_dir)
    result = await BenchmarkRunner(temp_root=tmp_path).run(
        selected, ScriptedAdapter(), attempt=1, seed=7
    )
    assert result.status is OutcomeStatus.PASSED
    assert result.checks_passed == result.checks_total
    assert result.failure_class is None
    assert sha256_tree(selected.source_dir) == source_digest


@pytest.mark.asyncio
async def test_each_attempt_has_a_unique_id_and_disposable_workspace(tmp_path: Path) -> None:
    adapter = RecordingAdapter()
    runner = BenchmarkRunner(temp_root=tmp_path)
    first = await runner.run(task("coding"), adapter, attempt=1, seed=7)
    second = await runner.run(task("coding"), adapter, attempt=1, seed=7)
    assert first.trial_id != second.trial_id
    assert len(set(adapter.workspaces)) == 2
    assert all(not workspace.exists() for workspace in adapter.workspaces)


@pytest.mark.asyncio
async def test_agent_and_verifier_failures_are_classified_separately(tmp_path: Path) -> None:
    runner = BenchmarkRunner(temp_root=tmp_path)
    agent_failure = await runner.run(task("coding"), FailedAdapter(), attempt=1, seed=1)
    semantic_failure = await runner.run(task("coding"), NoopAdapter(), attempt=1, seed=1)
    invalid_task = replace(task("coding"), verifier_source=tmp_path / "missing.py")
    infrastructure = await runner.run(invalid_task, NoopAdapter(), attempt=1, seed=1)

    assert (agent_failure.status, agent_failure.failure_class, agent_failure.failure_code) == (
        OutcomeStatus.FAILED,
        FailureClass.AGENT,
        "agent_timeout",
    )
    semantic_classification = (
        semantic_failure.status,
        semantic_failure.failure_class,
        semantic_failure.failure_code,
    )
    assert semantic_classification == (
        OutcomeStatus.FAILED,
        FailureClass.AGENT,
        "verifier_failed",
    )
    assert (infrastructure.status, infrastructure.failure_class, infrastructure.failure_code) == (
        OutcomeStatus.INVALID,
        FailureClass.INFRASTRUCTURE,
        "verifier_unavailable",
    )


@pytest.mark.asyncio
async def test_unexpected_adapter_exception_is_infrastructure_invalid(tmp_path: Path) -> None:
    result = await BenchmarkRunner(temp_root=tmp_path).run(
        task("coding"), CrashingAdapter(), attempt=1, seed=1
    )
    assert result.status is OutcomeStatus.INVALID
    assert result.failure_code == "runner_internal_error"


@pytest.mark.asyncio
async def test_cancellation_cleans_the_disposable_workspace(tmp_path: Path) -> None:
    adapter = HangingAdapter()
    running = asyncio.create_task(
        BenchmarkRunner(temp_root=tmp_path).run(task("coding"), adapter, attempt=1, seed=1)
    )
    await adapter.started.wait()
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    assert adapter.workspace is not None
    assert not adapter.workspace.exists()


@pytest.mark.asyncio
async def test_runner_rejects_invalid_attempt_and_seed_before_copying(tmp_path: Path) -> None:
    runner = BenchmarkRunner(temp_root=tmp_path)
    with pytest.raises(ValueError, match="attempt"):
        await runner.run(task("coding"), NoopAdapter(), attempt=0, seed=1)
    with pytest.raises(ValueError, match="seed"):
        await runner.run(task("coding"), NoopAdapter(), attempt=1, seed=-1)
    assert list(tmp_path.iterdir()) == []


def test_runner_requires_an_absolute_private_temp_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="temp_root"):
        BenchmarkRunner(temp_root=Path("relative"))
    os.chmod(tmp_path, 0o755)
    with pytest.raises(ValueError, match="temp_root"):
        BenchmarkRunner(temp_root=tmp_path)
