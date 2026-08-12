"""Offline oracle adapter used to verify benchmark plumbing."""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import stat
import time
from contextlib import suppress
from pathlib import Path

from carl_bench.models import AgentOutcome, AgentRequest


class _OutputOverflow(Exception):
    pass


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1_000))


async def _read_bounded(stream: asyncio.StreamReader, maximum: int) -> None:
    total = 0
    while True:
        chunk = await stream.read(min(16_384, maximum + 1 - total))
        if not chunk:
            return
        total += len(chunk)
        if total > maximum:
            raise _OutputOverflow


async def _terminate(process: asyncio.subprocess.Process) -> None:
    if os.name != "nt":
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        if process.returncode is None:
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except TimeoutError:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
        await process.wait()
        return
    if process.returncode is None:
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=2)
        except TimeoutError:
            process.kill()
    await process.wait()


def _solution_is_safe(path: Path) -> bool:
    if not path.is_absolute():
        return False
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and bool(metadata.st_mode & stat.S_IXUSR)
        and metadata.st_size <= 1_048_576
    )


class ScriptedAdapter:
    adapter_id = "scripted"

    def version(self) -> str:
        return "1.0.0"

    async def run(self, request: AgentRequest) -> AgentOutcome:
        started = time.monotonic()
        if request.scripted_solution is None:
            return AgentOutcome.failed(code="agent_protocol_error", elapsed_ms=0)
        source = Path(request.scripted_solution)
        workspace = Path(request.workspace)
        if not _solution_is_safe(source) or not workspace.is_absolute() or not workspace.is_dir():
            return AgentOutcome.failed(code="agent_protocol_error", elapsed_ms=0)
        copied = workspace.parent / ".carl-bench-solution.sh"
        try:
            shutil.copyfile(source, copied, follow_symlinks=False)
            os.chmod(copied, 0o700)
            process = await asyncio.create_subprocess_exec(
                os.fspath(copied),
                cwd=workspace,
                env={
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                },
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=os.name != "nt",
            )
        except OSError:
            with suppress(FileNotFoundError):
                copied.unlink()
            return AgentOutcome.failed(code="agent_protocol_error", elapsed_ms=_elapsed_ms(started))

        assert process.stdout is not None
        assert process.stderr is not None
        readers = [
            asyncio.create_task(_read_bounded(process.stdout, 65_536)),
            asyncio.create_task(_read_bounded(process.stderr, 65_536)),
        ]
        try:
            async with asyncio.timeout(request.timeout_sec):
                await asyncio.gather(process.wait(), *readers)
        except _OutputOverflow:
            await asyncio.shield(_terminate(process))
            return AgentOutcome.failed(
                code="agent_output_overflow", elapsed_ms=_elapsed_ms(started)
            )
        except TimeoutError:
            await asyncio.shield(_terminate(process))
            return AgentOutcome.failed(code="agent_timeout", elapsed_ms=_elapsed_ms(started))
        except asyncio.CancelledError:
            await asyncio.shield(_terminate(process))
            raise
        finally:
            for reader in readers:
                if not reader.done():
                    reader.cancel()
            await asyncio.gather(*readers, return_exceptions=True)
            with suppress(FileNotFoundError):
                copied.unlink()

        await _terminate(process)
        if process.returncode != 0:
            return AgentOutcome.failed(code="agent_exit_nonzero", elapsed_ms=_elapsed_ms(started))
        return AgentOutcome.succeeded(elapsed_ms=_elapsed_ms(started), tool_calls=0)
