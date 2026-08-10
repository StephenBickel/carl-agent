"""Fail-closed serialization for public benchmark evidence."""

from __future__ import annotations

import math
import os
import re
import stat
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any

from carl_bench.canonical import canonical_json_bytes

MAX_PUBLIC_DEPTH = 12
MAX_PUBLIC_WIDTH = 256
MAX_PUBLIC_STRING_BYTES = 512
_FORBIDDEN_KEYS = frozenset(
    {
        "environment",
        "instruction",
        "output",
        "prompt",
        "response",
        "secret",
        "stderr",
        "stdout",
        "token",
    }
)
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{12,}"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token)\s*[:=]\s*\S{12,}"),
)


class PublicSafetyError(ValueError):
    """A content-free error for rejected public evidence."""

    def __init__(self, code: str, pointer: str) -> None:
        self.code = code
        self.pointer = pointer
        super().__init__(f"{code} at {pointer}")


def _pointer(parent: str, segment: str | int) -> str:
    escaped = str(segment).replace("~", "~0").replace("/", "~1")
    return f"{parent}/{escaped}" if parent else f"/{escaped}"


def _reject_unsafe_string(value: str, pointer: str, protected_paths: tuple[str, ...]) -> None:
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as error:
        raise PublicSafetyError("public_string_invalid", pointer) from error
    if len(encoded) > MAX_PUBLIC_STRING_BYTES:
        raise PublicSafetyError("public_string_too_long", pointer)
    if any(path and path in value for path in protected_paths):
        raise PublicSafetyError("public_absolute_path", pointer)
    if any(pattern.search(value) for pattern in _SECRET_PATTERNS):
        raise PublicSafetyError("public_secret_pattern", pointer)


def assert_public_safe(value: Any, repository_root: Path) -> None:
    """Validate that a complete JSON value is safe for public persistence."""
    try:
        repository = str(repository_root.resolve(strict=True))
    except OSError as error:
        raise PublicSafetyError("public_repository_invalid", "") from error
    home = str(Path.home().resolve())
    protected_paths = tuple(dict.fromkeys((repository, home)))

    def visit(current: Any, pointer: str, depth: int) -> None:
        if depth > MAX_PUBLIC_DEPTH:
            raise PublicSafetyError("public_too_deep", pointer)
        if current is None or isinstance(current, bool | int):
            return
        if isinstance(current, float):
            if not math.isfinite(current):
                raise PublicSafetyError("public_number_invalid", pointer)
            return
        if isinstance(current, str):
            _reject_unsafe_string(current, pointer, protected_paths)
            return
        if isinstance(current, list | tuple):
            if len(current) > MAX_PUBLIC_WIDTH:
                raise PublicSafetyError("public_too_wide", pointer)
            for index, item in enumerate(current):
                visit(item, _pointer(pointer, index), depth + 1)
            return
        if isinstance(current, dict):
            if len(current) > MAX_PUBLIC_WIDTH:
                raise PublicSafetyError("public_too_wide", pointer)
            for key, item in current.items():
                if not isinstance(key, str):
                    raise PublicSafetyError("public_key_invalid", pointer)
                child_pointer = _pointer(pointer, key)
                if key.casefold() in _FORBIDDEN_KEYS:
                    raise PublicSafetyError("public_forbidden_key", child_pointer)
                _reject_unsafe_string(key, child_pointer, protected_paths)
                visit(item, child_pointer, depth + 1)
            return
        raise PublicSafetyError("public_type_invalid", pointer)

    visit(value, "", 0)


def _destination_is_safe(destination: Path) -> bool:
    try:
        metadata = destination.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)


def write_public_json(destination: Path, value: Any, repository_root: Path) -> None:
    """Atomically write canonical public JSON after full safety validation."""
    assert_public_safe(value, repository_root)
    if not _destination_is_safe(destination):
        raise PublicSafetyError("public_destination_unsafe", "")
    try:
        payload = canonical_json_bytes(value) + b"\n"
    except ValueError as error:
        raise PublicSafetyError("public_json_invalid", "") from error

    parent = destination.parent
    temporary_path: Path | None = None
    try:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir():
            raise PublicSafetyError("public_destination_unsafe", "")
        descriptor, raw_path = tempfile.mkstemp(prefix=f".{destination.name}.", dir=parent)
        temporary_path = Path(raw_path)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except PublicSafetyError:
        raise
    except OSError as error:
        raise PublicSafetyError("public_write_failed", "") from error
    finally:
        if temporary_path is not None:
            with suppress(FileNotFoundError):
                temporary_path.unlink()
