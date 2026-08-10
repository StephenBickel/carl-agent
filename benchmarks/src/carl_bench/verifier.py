"""Bounded verifier process supervision and result validation."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from carl_bench.tasks import BenchmarkTask

MAX_RESULT_BYTES = 4_096


@dataclass(frozen=True, slots=True)
class VerificationOutcome:
    passed: bool | None
    checks_passed: int
    checks_total: int
    elapsed_ms: int
    infrastructure_code: str | None = None

    @classmethod
    def invalid(cls, code: str, elapsed_ms: int) -> VerificationOutcome:
        return cls(
            passed=None,
            checks_passed=0,
            checks_total=0,
            elapsed_ms=elapsed_ms,
            infrastructure_code=code,
        )


class _OutputOverflow(Exception):
    pass


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1_000))


def _private_directory_safe(path: Path) -> bool:
    if not path.is_absolute():
        return False
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return False
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        return False
    return not hasattr(os, "getuid") or metadata.st_uid == os.getuid()


def _regular_file(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)


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
    if process.returncode is not None:
        await process.wait()
        return
    try:
        if os.name == "nt":
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(process.wait(), timeout=2)
        return
    except TimeoutError:
        pass
    try:
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    await process.wait()


def _closed_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _parse_result(path: Path, expected_identity: tuple[int, int]) -> tuple[bool, int, int]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ValueError("not regular")
        if (metadata.st_dev, metadata.st_ino) != expected_identity or metadata.st_nlink != 1:
            raise ValueError("identity changed")
        if metadata.st_size > MAX_RESULT_BYTES:
            raise ValueError("too large")
        os.chmod(path, 0o600)
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_closed_json_object)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("invalid verifier result") from error
    if not isinstance(value, dict) or set(value) != {"passed", "checks_passed", "checks_total"}:
        raise ValueError("invalid verifier result")
    passed = value["passed"]
    checks_passed = value["checks_passed"]
    checks_total = value["checks_total"]
    if not isinstance(passed, bool):
        raise ValueError("invalid verifier result")
    if (
        isinstance(checks_passed, bool)
        or not isinstance(checks_passed, int)
        or isinstance(checks_total, bool)
        or not isinstance(checks_total, int)
        or not 0 <= checks_passed <= checks_total <= 1_000_000
        or checks_total == 0
        or passed != (checks_passed == checks_total)
    ):
        raise ValueError("invalid verifier result")
    return passed, checks_passed, checks_total


class Verifier:
    def __init__(self, *, output_limit_bytes: int = 65_536) -> None:
        if not 1_024 <= output_limit_bytes <= 1_048_576:
            raise ValueError("output_limit_bytes must be between 1024 and 1048576")
        self._output_limit_bytes = output_limit_bytes

    async def run(
        self,
        task: BenchmarkTask,
        workspace: Path,
        private_dir: Path,
        protected_dir: Path | None = None,
    ) -> VerificationOutcome:
        started = time.monotonic()
        if not _private_directory_safe(private_dir):
            return VerificationOutcome.invalid("verifier_private_dir_unsafe", _elapsed_ms(started))
        if not workspace.is_absolute() or not workspace.is_dir() or workspace.is_symlink():
            return VerificationOutcome.invalid("verifier_workspace_unsafe", _elapsed_ms(started))
        if not _regular_file(task.verifier_source):
            return VerificationOutcome.invalid("verifier_unavailable", _elapsed_ms(started))

        result_path = private_dir / "verifier-result.json"
        try:
            descriptor = os.open(result_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            result_metadata = os.fstat(descriptor)
            os.close(descriptor)
        except OSError:
            return VerificationOutcome.invalid("verifier_private_dir_unsafe", _elapsed_ms(started))

        environment = {
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "PYTHONIOENCODING": "utf-8",
        }
        command = [
            sys.executable,
            os.fspath(task.verifier_source),
            "--workspace",
            os.fspath(workspace),
            "--result",
            os.fspath(result_path),
        ]
        if task.protected_dir is not None:
            if (
                protected_dir is None
                or not protected_dir.is_absolute()
                or not protected_dir.is_dir()
                or protected_dir.is_symlink()
            ):
                return VerificationOutcome.invalid(
                    "verifier_workspace_unsafe", _elapsed_ms(started)
                )
            command.extend(["--protected", os.fspath(protected_dir)])
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=workspace,
                env=environment,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=os.name != "nt",
            )
        except OSError:
            return VerificationOutcome.invalid("verifier_unavailable", _elapsed_ms(started))

        assert process.stdout is not None
        assert process.stderr is not None
        readers = [
            asyncio.create_task(_read_bounded(process.stdout, self._output_limit_bytes)),
            asyncio.create_task(_read_bounded(process.stderr, self._output_limit_bytes)),
        ]
        try:
            async with asyncio.timeout(task.verifier_timeout_sec):
                await asyncio.gather(process.wait(), *readers)
        except _OutputOverflow:
            await asyncio.shield(_terminate(process))
            return VerificationOutcome.invalid("verifier_output_overflow", _elapsed_ms(started))
        except TimeoutError:
            await asyncio.shield(_terminate(process))
            return VerificationOutcome.invalid("verifier_timeout", _elapsed_ms(started))
        except asyncio.CancelledError:
            await asyncio.shield(_terminate(process))
            raise
        finally:
            for reader in readers:
                if not reader.done():
                    reader.cancel()
            await asyncio.gather(*readers, return_exceptions=True)

        if process.returncode != 0:
            return VerificationOutcome.invalid("verifier_exit_nonzero", _elapsed_ms(started))
        try:
            passed, checks_passed, checks_total = _parse_result(
                result_path, (result_metadata.st_dev, result_metadata.st_ino)
            )
        except ValueError:
            return VerificationOutcome.invalid("verifier_invalid_output", _elapsed_ms(started))
        return VerificationOutcome(
            passed=passed,
            checks_passed=checks_passed,
            checks_total=checks_total,
            elapsed_ms=_elapsed_ms(started),
        )
