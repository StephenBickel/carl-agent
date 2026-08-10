"""Isolated local execution for one benchmark task attempt."""

from __future__ import annotations

import asyncio
import os
import shutil
import stat
import tempfile
import time
import uuid
from pathlib import Path

from carl_bench.adapters.base import AgentAdapter
from carl_bench.canonical import CanonicalizationError, sha256_tree
from carl_bench.models import AgentRequest, OutcomeStatus, TrialResult
from carl_bench.tasks import BenchmarkTask
from carl_bench.verifier import Verifier


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1_000))


def _private_directory(path: Path) -> bool:
    if not path.is_absolute():
        return False
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and not stat.S_IMODE(metadata.st_mode) & 0o077
        and (not hasattr(os, "getuid") or metadata.st_uid == os.getuid())
    )


class BenchmarkRunner:
    def __init__(self, *, temp_root: Path | None = None, verifier: Verifier | None = None) -> None:
        if temp_root is not None and not _private_directory(temp_root):
            raise ValueError("temp_root must be an absolute owner-private directory")
        self._temp_root = temp_root
        self._verifier = verifier or Verifier()

    async def run(
        self,
        task: BenchmarkTask,
        adapter: AgentAdapter,
        *,
        attempt: int,
        seed: int,
    ) -> TrialResult:
        if not 1 <= attempt <= 10:
            raise ValueError("attempt must be between 1 and 10")
        if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < (1 << 63):
            raise ValueError("seed must be a non-negative 63-bit integer")
        adapter_id = adapter.adapter_id
        adapter_version = adapter.version()
        trial_id = f"trial-{uuid.uuid4().hex}"
        started = time.monotonic()

        with tempfile.TemporaryDirectory(prefix="carl-bench-", dir=self._temp_root) as temporary:
            trial_root = Path(temporary)
            os.chmod(trial_root, 0o700)
            workspace = trial_root / "workspace"
            private_dir = trial_root / "private"
            shutil.copytree(task.fixture_dir, workspace, symlinks=False)
            private_dir.mkdir(mode=0o700)
            protected_dir: Path | None = None
            if task.protected_dir is not None:
                protected_dir = trial_root / "protected"
                shutil.copytree(task.protected_dir, protected_dir, symlinks=False)

            request = AgentRequest(
                trial_id=trial_id,
                task_id=task.identity.task_id,
                instruction=task.instruction,
                workspace=os.fspath(workspace),
                timeout_sec=task.agent_timeout_sec,
                seed=seed,
                scripted_solution=os.fspath(task.source_dir / "solution" / "solve.sh"),
            )
            try:
                outcome = await adapter.run(request)
            except asyncio.CancelledError:
                raise
            except Exception:
                return TrialResult.infrastructure_invalid(
                    trial_id=trial_id,
                    task_id=task.identity.task_id,
                    task_digest=task.identity.digest,
                    adapter_id=adapter_id,
                    adapter_version=adapter_version,
                    attempt=attempt,
                    seed=seed,
                    code="runner_internal_error",
                    elapsed_ms=_elapsed_ms(started),
                )

            try:
                source_unchanged = sha256_tree(task.source_dir) == task.identity.digest
            except CanonicalizationError:
                source_unchanged = False
            if not source_unchanged:
                return TrialResult.infrastructure_invalid(
                    trial_id=trial_id,
                    task_id=task.identity.task_id,
                    task_digest=task.identity.digest,
                    adapter_id=adapter_id,
                    adapter_version=adapter_version,
                    attempt=attempt,
                    seed=seed,
                    code="runner_task_source_changed",
                    elapsed_ms=_elapsed_ms(started),
                )
            if outcome.status is OutcomeStatus.FAILED:
                assert outcome.failure_code is not None
                return TrialResult.agent_failure(
                    trial_id=trial_id,
                    task_id=task.identity.task_id,
                    task_digest=task.identity.digest,
                    adapter_id=adapter_id,
                    adapter_version=adapter_version,
                    attempt=attempt,
                    seed=seed,
                    code=outcome.failure_code,
                    elapsed_ms=_elapsed_ms(started),
                    tool_calls=outcome.tool_calls,
                )

            verification = await self._verifier.run(
                task, workspace, private_dir, protected_dir=protected_dir
            )
            if verification.infrastructure_code is not None:
                return TrialResult.infrastructure_invalid(
                    trial_id=trial_id,
                    task_id=task.identity.task_id,
                    task_digest=task.identity.digest,
                    adapter_id=adapter_id,
                    adapter_version=adapter_version,
                    attempt=attempt,
                    seed=seed,
                    code=verification.infrastructure_code,
                    elapsed_ms=_elapsed_ms(started),
                )
            if not verification.passed:
                return TrialResult.agent_failure(
                    trial_id=trial_id,
                    task_id=task.identity.task_id,
                    task_digest=task.identity.digest,
                    adapter_id=adapter_id,
                    adapter_version=adapter_version,
                    attempt=attempt,
                    seed=seed,
                    code="verifier_failed",
                    elapsed_ms=_elapsed_ms(started),
                    tool_calls=outcome.tool_calls,
                    checks_passed=verification.checks_passed,
                    checks_total=verification.checks_total,
                )
            return TrialResult.passed(
                trial_id=trial_id,
                task_id=task.identity.task_id,
                task_digest=task.identity.digest,
                adapter_id=adapter_id,
                adapter_version=adapter_version,
                attempt=attempt,
                seed=seed,
                elapsed_ms=_elapsed_ms(started),
                checks_passed=verification.checks_passed,
                checks_total=verification.checks_total,
                tool_calls=outcome.tool_calls,
            )
