"""Trusted-host adapter for benchmarking Carl through ACP v2."""

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

MAX_FRAME_BYTES = 1_048_576
MAX_STDERR_BYTES = 256 * 1_024
MAX_NOTIFICATIONS = 10_000


class _ProtocolError(Exception):
    pass


class _OutputOverflow(Exception):
    pass


class _AgentExited(Exception):
    def __init__(self, returncode: int | None) -> None:
        self.returncode = returncode


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


async def _drain_stderr(stream: asyncio.StreamReader) -> None:
    total = 0
    while chunk := await stream.read(16_384):
        total += len(chunk)
        if total > MAX_STDERR_BYTES:
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


async def _read_frame(stream: asyncio.StreamReader) -> dict[str, Any]:
    try:
        encoded = await stream.readuntil(b"\n")
    except asyncio.LimitOverrunError as error:
        raise _OutputOverflow from error
    except asyncio.IncompleteReadError as error:
        raise _AgentExited(None) from error
    if len(encoded) > MAX_FRAME_BYTES or not encoded.endswith(b"\n"):
        raise _OutputOverflow
    try:
        value = json.loads(encoded)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise _ProtocolError from error
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
        raise _ProtocolError
    return value


class _AcpConnection:
    def __init__(
        self,
        process: asyncio.subprocess.Process,
        stderr_task: asyncio.Task[None],
        exit_task: asyncio.Task[int],
    ) -> None:
        assert process.stdin is not None
        assert process.stdout is not None
        self.process = process
        self.stdin = process.stdin
        self.stdout = process.stdout
        self.stderr_task = stderr_task
        self.exit_task = exit_task
        self.next_id = 1
        self.notifications = 0
        self.tool_calls = 0

    async def _message(self) -> dict[str, Any]:
        message_task = asyncio.create_task(_read_frame(self.stdout))
        done, _ = await asyncio.wait(
            {message_task, self.stderr_task, self.exit_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if self.stderr_task in done:
            exception = self.stderr_task.exception()
            if exception is not None:
                message_task.cancel()
                await asyncio.gather(message_task, return_exceptions=True)
                raise exception
        if message_task in done:
            return message_task.result()
        if self.exit_task in done:
            try:
                return await message_task
            except _AgentExited as error:
                raise _AgentExited(self.process.returncode) from error
        return await message_task

    async def request(self, method: str, params: dict[str, Any]) -> Any:
        request_id = self.next_id
        self.next_id += 1
        encoded = (
            json.dumps(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if len(encoded) > MAX_FRAME_BYTES:
            raise _ProtocolError
        self.stdin.write(encoded)
        await self.stdin.drain()
        while True:
            message = await self._message()
            if "method" in message:
                if "id" in message:
                    raise _ProtocolError
                self.notifications += 1
                if self.notifications > MAX_NOTIFICATIONS:
                    raise _OutputOverflow
                if message.get("method") == "session/update":
                    update = message.get("params", {}).get("update", {})
                    if isinstance(update, dict) and update.get("sessionUpdate") == "tool_call":
                        self.tool_calls += 1
                continue
            if message.get("id") != request_id:
                raise _ProtocolError
            if ("result" in message) == ("error" in message):
                raise _ProtocolError
            if "error" in message:
                raise _ProtocolError
            return message["result"]


class CarlAcpAdapter:
    adapter_id = "carl-acp"

    def __init__(
        self,
        *,
        executable: Path,
        codex_executable: Path,
        data_dir: Path,
        model: str,
        effort: str,
        permission_mode: str = "default",
    ) -> None:
        if not _regular_executable(executable):
            raise ValueError("executable must be an absolute regular executable")
        if not _regular_executable(codex_executable):
            raise ValueError("codex_executable must be an absolute regular executable")
        if not _private_directory(data_dir):
            raise ValueError("data_dir must be an absolute owner-private directory")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", model):
            raise ValueError("model is invalid")
        if effort not in {"minimal", "low", "medium", "high", "xhigh"}:
            raise ValueError("effort is invalid")
        if permission_mode not in {"plan", "default", "acceptEdits", "dontAsk"}:
            raise ValueError("permission_mode is invalid")
        self._executable = executable
        self._codex_executable = codex_executable
        self._data_dir = data_dir
        self._model = model
        self._effort = effort
        self._permission_mode = permission_mode

    def version(self) -> str:
        return "0.1.0"

    async def run(self, request: AgentRequest) -> AgentOutcome:
        started = time.monotonic()
        workspace = Path(request.workspace)
        if not workspace.is_absolute() or not workspace.is_dir() or workspace.is_symlink():
            return AgentOutcome.failed(code="agent_protocol_error", elapsed_ms=0)
        environment = {
            "CARL_CODEX_EXECUTABLE": os.fspath(self._codex_executable),
            "CARL_DATA_DIR": os.fspath(self._data_dir),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        try:
            process = await asyncio.create_subprocess_exec(
                os.fspath(self._executable),
                "acp",
                "--model",
                self._model,
                "--effort",
                self._effort,
                "--permission-mode",
                self._permission_mode,
                cwd=workspace,
                env=environment,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=os.name != "nt",
                limit=MAX_FRAME_BYTES,
            )
        except OSError:
            return AgentOutcome.failed(code="agent_protocol_error", elapsed_ms=0)
        assert process.stderr is not None
        stderr_task = asyncio.create_task(_drain_stderr(process.stderr))
        exit_task = asyncio.create_task(process.wait())
        connection = _AcpConnection(process, stderr_task, exit_task)
        try:
            async with asyncio.timeout(request.timeout_sec):
                initialized = await connection.request(
                    "initialize",
                    {
                        "protocolVersion": 2,
                        "clientCapabilities": {},
                        "clientInfo": {"name": "carl-bench", "version": "1"},
                    },
                )
                if not isinstance(initialized, dict) or initialized.get("protocolVersion") != 2:
                    raise _ProtocolError
                session = await connection.request(
                    "session/new", {"cwd": os.fspath(workspace), "mcpServers": []}
                )
                if not isinstance(session, dict) or not isinstance(session.get("sessionId"), str):
                    raise _ProtocolError
                session_id = session["sessionId"]
                if not session_id or len(session_id.encode("utf-8")) > 256:
                    raise _ProtocolError
                result = await connection.request(
                    "session/prompt",
                    {
                        "sessionId": session_id,
                        "prompt": [{"type": "text", "text": request.instruction}],
                    },
                )
                if not isinstance(result, dict) or not isinstance(result.get("stopReason"), str):
                    raise _ProtocolError
                stop_reason = result["stopReason"]
                assert process.stdin is not None
                process.stdin.close()
                await process.stdin.wait_closed()
                await asyncio.wait_for(exit_task, timeout=3)
                if process.returncode != 0:
                    raise _AgentExited(process.returncode)
                await _terminate(process)
        except _OutputOverflow:
            await asyncio.shield(_terminate(process))
            return AgentOutcome.failed(
                code="agent_output_overflow", elapsed_ms=_elapsed_ms(started)
            )
        except _AgentExited as error:
            await asyncio.shield(_terminate(process))
            returncode = error.returncode if error.returncode is not None else process.returncode
            code = "agent_exit_nonzero" if returncode not in {None, 0} else "agent_protocol_error"
            return AgentOutcome.failed(code=code, elapsed_ms=_elapsed_ms(started))
        except (_ProtocolError, ValueError):
            await asyncio.shield(_terminate(process))
            return AgentOutcome.failed(code="agent_protocol_error", elapsed_ms=_elapsed_ms(started))
        except TimeoutError:
            await asyncio.shield(_terminate(process))
            return AgentOutcome.failed(code="agent_timeout", elapsed_ms=_elapsed_ms(started))
        except asyncio.CancelledError:
            await asyncio.shield(_terminate(process))
            raise
        finally:
            for background in (stderr_task, exit_task):
                if not background.done():
                    background.cancel()
            await asyncio.gather(stderr_task, exit_task, return_exceptions=True)

        if stop_reason == "end_turn":
            return AgentOutcome.succeeded(
                elapsed_ms=_elapsed_ms(started), tool_calls=connection.tool_calls
            )
        if stop_reason == "cancelled":
            return AgentOutcome.failed(
                code="agent_cancelled",
                elapsed_ms=_elapsed_ms(started),
                tool_calls=connection.tool_calls,
            )
        return AgentOutcome.failed(
            code="agent_protocol_error",
            elapsed_ms=_elapsed_ms(started),
            tool_calls=connection.tool_calls,
        )
