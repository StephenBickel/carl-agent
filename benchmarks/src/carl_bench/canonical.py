"""Deterministic, bounded hashing for benchmark inputs."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 1_048_576
MAX_TREE_BYTES = 16 * 1_048_576
MAX_TREE_ENTRIES = 10_000


class CanonicalizationError(ValueError):
    """A stable error that never includes input content or ambient paths."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize a JSON value using one deterministic UTF-8 representation."""
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise CanonicalizationError("canonical_json_invalid") from error
    return encoded


def sha256_file(path: Path) -> str:
    """Hash one regular file without following symbolic links."""
    try:
        before = path.lstat()
    except OSError as error:
        raise CanonicalizationError("file_unavailable") from error
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise CanonicalizationError("file_not_regular")

    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as source:
            while chunk := source.read(64 * 1024):
                total += len(chunk)
                if total > MAX_FILE_BYTES:
                    raise CanonicalizationError("file_too_large")
                digest.update(chunk)
        after = path.lstat()
    except CanonicalizationError:
        raise
    except OSError as error:
        raise CanonicalizationError("file_unavailable") from error
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_mode,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_mode,
    ):
        raise CanonicalizationError("file_changed_during_hash")
    return digest.hexdigest()


def _update_field(digest: Any, value: bytes) -> None:
    digest.update(len(value).to_bytes(8, byteorder="big", signed=False))
    digest.update(value)


def sha256_tree(root: Path, *, excluded_names: frozenset[str] = frozenset()) -> str:
    """Hash a bounded directory tree including paths, kinds, modes, and bytes."""
    try:
        root_stat = root.lstat()
    except OSError as error:
        raise CanonicalizationError("tree_root_invalid") from error
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise CanonicalizationError("tree_root_invalid")
    if any(not name or "/" in name or "\\" in name for name in excluded_names):
        raise CanonicalizationError("tree_exclusion_invalid")

    records: list[tuple[bytes, bytes, bytes, bytes]] = []
    total_bytes = 0
    seen_casefolded: dict[str, str] = {}
    pending = [root]

    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name.encode("utf-8"))
        except (OSError, UnicodeError) as error:
            raise CanonicalizationError("tree_unavailable") from error
        for entry in entries:
            if entry.name in excluded_names:
                continue
            path = Path(entry.path)
            try:
                relative = path.relative_to(root).as_posix()
                relative_bytes = relative.encode("utf-8")
                entry_stat = entry.stat(follow_symlinks=False)
            except (OSError, UnicodeError, ValueError) as error:
                raise CanonicalizationError("tree_unavailable") from error
            if not relative or relative.startswith("../") or relative.startswith("/"):
                raise CanonicalizationError("tree_path_invalid")
            folded = relative.casefold()
            if (previous := seen_casefolded.get(folded)) and previous != relative:
                raise CanonicalizationError("tree_path_collision")
            seen_casefolded[folded] = relative
            if len(seen_casefolded) > MAX_TREE_ENTRIES:
                raise CanonicalizationError("tree_too_many_entries")

            mode = f"{stat.S_IMODE(entry_stat.st_mode):04o}".encode("ascii")
            if stat.S_ISDIR(entry_stat.st_mode):
                records.append((relative_bytes, b"directory", mode, b""))
                pending.append(path)
                continue
            if not stat.S_ISREG(entry_stat.st_mode) or entry.is_symlink():
                raise CanonicalizationError("tree_unsupported_entry")
            if entry_stat.st_size > MAX_FILE_BYTES:
                raise CanonicalizationError("tree_file_too_large")
            total_bytes += entry_stat.st_size
            if total_bytes > MAX_TREE_BYTES:
                raise CanonicalizationError("tree_too_large")
            try:
                content_digest = bytes.fromhex(sha256_file(path))
            except CanonicalizationError as error:
                mapped = {
                    "file_too_large": "tree_file_too_large",
                    "file_not_regular": "tree_unsupported_entry",
                }.get(error.code, error.code)
                raise CanonicalizationError(mapped) from error
            records.append((relative_bytes, b"file", mode, content_digest))

    digest = hashlib.sha256()
    for record in sorted(records, key=lambda value: value[0]):
        for field in record:
            _update_field(digest, field)
    return digest.hexdigest()
