"""Pinned same-model baseline adapter for the local Codex CLI."""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import stat
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

from carl_bench.models import AgentOutcome, AgentRequest

PINNED_CODEX_VERSION = "0.146.0"
MAX_EVENT_BYTES = 1_048_576
MAX_STDOUT_BYTES = 4 * 1_048_576
MAX_STDERR_BYTES = 256 * 1_024


class _ProtocolError(Exception):
    pass


class _OutputOverflow(Exception):
    pass


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1_000))


def _regular_executable(path: Path) -> bool:
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
    )


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


async def _read_stderr(stream: asyncio.StreamReader) -> None:
    total = 0
    while chunk := await stream.read(16_384):
        total += len(chunk)
        if total > MAX_STDERR_BYTES:
            raise _OutputOverflow


async def _read_events(stream: asyncio.StreamReader) -> tuple[int, int]:
    total = 0
    tool_calls = 0
    terminal_events = 0
    while True:
        try:
            line = await stream.readuntil(b"\n")
        except asyncio.IncompleteReadError as error:
            if error.partial:
                raise _ProtocolError from error
            break
        except asyncio.LimitOverrunError as error:
            raise _OutputOverflow from error
        total += len(line)
        if len(line) > MAX_EVENT_BYTES or total > MAX_STDOUT_BYTES:
            raise _OutputOverflow
        try:
            event: Any = json.loads(line)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise _ProtocolError from error
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise _ProtocolError
        event_type = event["type"]
        if event_type == "turn.completed":
            terminal_events += 1
        if event_type == "item.completed":
            item = event.get("item")
            if isinstance(item, dict) and item.get("type") in {
                "command_execution",
                "file_change",
                "mcp_tool_call",
            }:
                tool_calls += 1
    return tool_calls, terminal_events


class CodexCliAdapter:
    adapter_id = "codex-cli"

    def __init__(self, *, executable: Path, codex_home: Path, model: str, effort: str) -> None:
        if not _regular_executable(executable):
            raise ValueError("executable must be an absolute regular executable")
        if not _private_directory(codex_home):
            raise ValueError("codex_home must be an absolute owner-private directory")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", model):
            raise ValueError("model is invalid")
        if effort not in {"minimal", "low", "medium", "high", "xhigh"}:
            raise ValueError("effort is invalid")
        self._executable = executable
        self._codex_home = codex_home
        self._model = model
        self._effort = effort

    def version(self) -> str:
        return PINNED_CODEX_VERSION

    def _environment(self) -> dict[str, str]:
        return {
            "CODEX_HOME": os.fspath(self._codex_home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }

    async def _version_matches(self, workspace: Path) -> bool:
        try:
            process = await asyncio.create_subprocess_exec(
                os.fspath(self._executable),
                "--version",
                cwd=workspace,
                env=self._environment(),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=os.name != "nt",
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5)
        except TimeoutError:
            await asyncio.shield(_terminate(process))
            return False
        except OSError:
            return False
        await _terminate(process)
        if len(stdout) > 1_024 or len(stderr) > 1_024 or process.returncode != 0:
            return False
        try:
            return stdout.decode("utf-8").strip() == f"codex-cli {PINNED_CODEX_VERSION}"
        except UnicodeError:
            return False

    async def run(self, request: AgentRequest) -> AgentOutcome:
        started = time.monotonic()
        workspace = Path(request.workspace)
        if not workspace.is_absolute() or not workspace.is_dir() or workspace.is_symlink():
            return AgentOutcome.failed(code="agent_protocol_error", elapsed_ms=0)
        if not await self._version_matches(workspace):
            return AgentOutcome.failed(code="agent_protocol_error", elapsed_ms=_elapsed_ms(started))
        command = (
            os.fspath(self._executable),
            "exec",
            "--model",
            self._model,
            "-c",
            f'model_reasoning_effort="{self._effort}"',
            "--sandbox",
            "workspace-write",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--color",
            "never",
            "--json",
            "--skip-git-repo-check",
            "-C",
            os.fspath(workspace),
            "-",
        )
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=workspace,
                env=self._environment(),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=os.name != "nt",
                limit=MAX_EVENT_BYTES,
            )
        except OSError:
            return AgentOutcome.failed(code="agent_protocol_error", elapsed_ms=_elapsed_ms(started))
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_task = asyncio.create_task(_read_events(process.stdout))
        stderr_task = asyncio.create_task(_read_stderr(process.stderr))
        try:
            process.stdin.write(request.instruction.encode("utf-8"))
            await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()
            async with asyncio.timeout(request.timeout_sec):
                _, event_summary, _ = await asyncio.gather(process.wait(), stdout_task, stderr_task)
        except _OutputOverflow:
            await asyncio.shield(_terminate(process))
            return AgentOutcome.failed(
                code="agent_output_overflow", elapsed_ms=_elapsed_ms(started)
            )
        except (_ProtocolError, UnicodeError):
            await asyncio.shield(_terminate(process))
            return AgentOutcome.failed(code="agent_protocol_error", elapsed_ms=_elapsed_ms(started))
        except TimeoutError:
            await asyncio.shield(_terminate(process))
            return AgentOutcome.failed(code="agent_timeout", elapsed_ms=_elapsed_ms(started))
        except asyncio.CancelledError:
            await asyncio.shield(_terminate(process))
            raise
        finally:
            for background in (stdout_task, stderr_task):
                if not background.done():
                    background.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        await _terminate(process)
        if process.returncode != 0:
            return AgentOutcome.failed(code="agent_exit_nonzero", elapsed_ms=_elapsed_ms(started))
        tool_calls, terminal_events = event_summary
        if terminal_events != 1:
            return AgentOutcome.failed(code="agent_protocol_error", elapsed_ms=_elapsed_ms(started))
        return AgentOutcome.succeeded(elapsed_ms=_elapsed_ms(started), tool_calls=tool_calls)
