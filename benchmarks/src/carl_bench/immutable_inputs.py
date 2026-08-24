"""Versioned immutable input publication, resolution, and soak health contracts."""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import tempfile
import unicodedata
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from carl_bench.canonical import CanonicalizationError, canonical_json_bytes

REGISTRY_MEDIA_TYPE = "application/vnd.carl.immutable-input-registry+json"
REGISTRY_VERSION = 1
EXPERIMENT_MEDIA_TYPE = "application/vnd.carl.experiment+json"
IMPROVEMENT_TASK_SET_MEDIA_TYPE = "application/vnd.carl.improvement-task-set+json"
IMPROVEMENT_TASK_SET_VERSION = 1
SOAK_TASK_SET_MEDIA_TYPE = "application/vnd.carl.soak-task-set+tar"
SOAK_TASK_SET_VERSION = 1
METRIC_PACK_MEDIA_TYPE = "application/vnd.carl.metric-pack+json"
POLICY_MEDIA_TYPE = "application/vnd.carl.policy+json"

MAX_REGISTRY_BYTES = 1_048_576
MAX_REGISTRY_ENTRIES = 4096
MAX_OBJECT_BYTES = 32 * 1_048_576
MAX_SOAK_ARCHIVE_BYTES = 20 * 1_048_576
MAX_SOAK_ARCHIVE_ENTRIES = 1024
MAX_SOAK_MEMBER_BYTES = 1_048_576
MAX_SOAK_CONTENT_BYTES = 16 * 1_048_576
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 10_000
_MAX_JSON_STRING_BYTES = 65_536

_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_OBJECT_KEY_RE = re.compile(r"[a-z0-9][a-z0-9._/-]{0,511}\Z")
_KNOWN_MEDIA = {
    EXPERIMENT_MEDIA_TYPE: frozenset({1}),
    IMPROVEMENT_TASK_SET_MEDIA_TYPE: frozenset({IMPROVEMENT_TASK_SET_VERSION}),
    SOAK_TASK_SET_MEDIA_TYPE: frozenset({SOAK_TASK_SET_VERSION}),
    METRIC_PACK_MEDIA_TYPE: frozenset({1}),
    POLICY_MEDIA_TYPE: frozenset({1}),
}

_publication_after_registry_load_for_test: Callable[[], None] | None = None


class ImmutableInputError(ValueError):
    """Stable fail-closed error that never contains object bytes, locators, or paths."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class BoundedObjectStore(Protocol):
    """Injected private object-store boundary with a caller-owned byte limit."""

    def fetch(self, object_key: str, *, max_bytes: int) -> bytes:
        """Return at most ``max_bytes`` for the committed logical object key."""


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    digest: str
    size_bytes: int
    media_type: str
    media_version: int
    object_key: str
    visibility: str

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "digest": self.digest,
            "media_type": self.media_type,
            "media_version": self.media_version,
            "object_key": self.object_key,
            "size_bytes": self.size_bytes,
            "visibility": self.visibility,
        }


@dataclass(frozen=True, slots=True)
class Registry:
    entries: tuple[RegistryEntry, ...]

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "entries": [entry.to_canonical_dict() for entry in self.entries],
            "media_type": REGISTRY_MEDIA_TYPE,
            "media_version": REGISTRY_VERSION,
        }


@dataclass(frozen=True, slots=True)
class SoakHealthDecision:
    healthy: bool
    score_basis_points: int
    reasons: tuple[str, ...]
    input_digests: dict[str, str]

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "healthy": self.healthy,
            "input_digests": dict(sorted(self.input_digests.items())),
            "kind": "immutable_soak_health_decision",
            "reasons": list(self.reasons),
            "schema_version": 1,
            "score_basis_points": self.score_basis_points,
        }


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _bounded_json_shape(value: object, *, code: str) -> None:
    nodes = 0

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_JSON_NODES or depth > _MAX_JSON_DEPTH:
            raise ImmutableInputError(code)
        if item is None or isinstance(item, bool) or _is_int(item):
            return
        if isinstance(item, float):
            raise ImmutableInputError(code)
        if isinstance(item, str):
            if len(item.encode("utf-8")) > _MAX_JSON_STRING_BYTES:
                raise ImmutableInputError(code)
            return
        if isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
            return
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > 256:
                    raise ImmutableInputError(code)
                visit(child, depth + 1)
            return
        raise ImmutableInputError(code)

    visit(value, 0)


def _parse_canonical_json(payload: bytes, *, code: str) -> object:
    if len(payload) > MAX_OBJECT_BYTES:
        raise ImmutableInputError(code)
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_object_without_duplicates)
        _bounded_json_shape(value, code=code)
        if canonical_json_bytes(value) != payload:
            raise ImmutableInputError(code)
    except ImmutableInputError:
        raise
    except (
        CanonicalizationError,
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as error:
        raise ImmutableInputError(code) from error
    return value


def _read_regular(path: Path, *, maximum_bytes: int, code: str) -> bytes:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_size > maximum_bytes
        ):
            raise ImmutableInputError(code)
        with path.open("rb") as source:
            payload = source.read(maximum_bytes + 1)
        after = path.lstat()
    except ImmutableInputError:
        raise
    except OSError as error:
        raise ImmutableInputError(code) from error
    if len(payload) > maximum_bytes:
        raise ImmutableInputError(code)
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mode)
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mode):
        raise ImmutableInputError(code)
    return payload


def _atomic_write(path: Path, payload: bytes, *, mode: int = 0o644) -> None:
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=".immutable-", suffix=".tmp", dir=path.parent
        )
        with os.fdopen(descriptor, "wb") as target:
            os.fchmod(target.fileno(), mode)
            target.write(payload)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
        temporary = None
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        raise ImmutableInputError("publication_atomic_write_failed") from error
    finally:
        if temporary is not None:
            with contextlib.suppress(OSError):
                os.unlink(temporary)


def _validate_media(media_type: object, media_version: object) -> tuple[str, int]:
    if (
        not isinstance(media_type, str)
        or not _is_int(media_version)
        or media_type not in _KNOWN_MEDIA
        or media_version not in _KNOWN_MEDIA[media_type]
    ):
        raise ImmutableInputError("registry_media_invalid")
    return media_type, media_version


def _validate_object_key(object_key: object, *, visibility: str, digest: str) -> str:
    if not isinstance(object_key, str) or not _OBJECT_KEY_RE.fullmatch(object_key):
        raise ImmutableInputError("registry_object_key_invalid")
    parts = object_key.split("/")
    if any(part in {"", ".", ".."} for part in parts) or "\\" in object_key:
        raise ImmutableInputError("registry_object_key_invalid")
    if visibility == "public":
        if object_key != f"public/{digest}":
            raise ImmutableInputError("registry_object_key_invalid")
    elif not object_key.startswith("private/"):
        raise ImmutableInputError("registry_object_key_invalid")
    return object_key


def _parse_registry_entry(value: object) -> RegistryEntry:
    expected = {
        "digest",
        "media_type",
        "media_version",
        "object_key",
        "size_bytes",
        "visibility",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ImmutableInputError("registry_schema_invalid")
    digest = value["digest"]
    size_bytes = value["size_bytes"]
    visibility = value["visibility"]
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise ImmutableInputError("registry_schema_invalid")
    if not _is_int(size_bytes) or not 1 <= size_bytes <= MAX_OBJECT_BYTES:
        raise ImmutableInputError("registry_schema_invalid")
    if visibility not in {"public", "private"}:
        raise ImmutableInputError("registry_schema_invalid")
    media_type, media_version = _validate_media(value["media_type"], value["media_version"])
    object_key = _validate_object_key(value["object_key"], visibility=visibility, digest=digest)
    return RegistryEntry(
        digest=digest,
        size_bytes=size_bytes,
        media_type=media_type,
        media_version=media_version,
        object_key=object_key,
        visibility=visibility,
    )


def _parse_registry(payload: bytes) -> Registry:
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_object_without_duplicates)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ImmutableInputError("registry_json_invalid") from error
    if not isinstance(value, dict) or set(value) != {"entries", "media_type", "media_version"}:
        raise ImmutableInputError("registry_schema_invalid")
    if value["media_type"] != REGISTRY_MEDIA_TYPE or value["media_version"] != REGISTRY_VERSION:
        raise ImmutableInputError("registry_schema_invalid")
    raw_entries = value["entries"]
    if not isinstance(raw_entries, list) or len(raw_entries) > MAX_REGISTRY_ENTRIES:
        raise ImmutableInputError("registry_schema_invalid")
    entries = tuple(_parse_registry_entry(item) for item in raw_entries)
    if tuple(sorted(entries, key=lambda item: item.digest)) != entries:
        raise ImmutableInputError("registry_schema_invalid")
    if len({entry.digest for entry in entries}) != len(entries):
        raise ImmutableInputError("registry_schema_invalid")
    if len({entry.object_key for entry in entries}) != len(entries):
        raise ImmutableInputError("registry_schema_invalid")
    _bounded_json_shape(value, code="registry_schema_invalid")
    try:
        canonical = canonical_json_bytes(value) + b"\n"
    except CanonicalizationError as error:
        raise ImmutableInputError("registry_schema_invalid") from error
    if canonical != payload:
        raise ImmutableInputError("registry_not_canonical")
    return Registry(entries=entries)


def load_registry(path: Path) -> Registry:
    """Load one bounded, duplicate-aware, exact-schema canonical registry."""
    payload = _read_regular(
        Path(path), maximum_bytes=MAX_REGISTRY_BYTES, code="registry_file_invalid"
    )
    return _parse_registry(payload)


def _safe_directory(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and not metadata.st_mode & 0o022
    )


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _read_regular_at(
    directory_fd: int,
    name: str,
    *,
    maximum_bytes: int,
    code: str,
) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        before = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o022
            or before.st_size > maximum_bytes
            or not _same_inode(before, named)
        ):
            raise ImmutableInputError(code)
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            len(payload) > maximum_bytes
            or (before.st_dev, before.st_ino, before.st_size, before.st_mode)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mode)
            or not _same_inode(after, current)
        ):
            raise ImmutableInputError(code)
        return payload
    except ImmutableInputError:
        raise
    except OSError as error:
        raise ImmutableInputError(code) from error
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)


@dataclass(slots=True)
class _PublicationTransaction:
    root_parent_fd: int
    root_fd: int
    root_name: str
    root_metadata: os.stat_result
    lock_fd: int
    lock_name: str
    lock_metadata: os.stat_result
    public_fd: int | None
    public_metadata: os.stat_result | None

    def verify(self) -> None:
        try:
            root_open = os.fstat(self.root_fd)
            root_named = os.stat(
                self.root_name,
                dir_fd=self.root_parent_fd,
                follow_symlinks=False,
            )
            lock_open = os.fstat(self.lock_fd)
            lock_named = os.stat(
                self.lock_name,
                dir_fd=self.root_fd,
                follow_symlinks=False,
            )
            if (
                not _safe_directory(root_open)
                or not _same_inode(root_open, self.root_metadata)
                or not _same_inode(root_open, root_named)
            ):
                raise ImmutableInputError("registry_root_invalid")
            if (
                not stat.S_ISREG(lock_open.st_mode)
                or lock_open.st_nlink != 1
                or lock_open.st_uid != os.geteuid()
                or lock_open.st_mode & 0o077
                or not _same_inode(lock_open, self.lock_metadata)
                or not _same_inode(lock_open, lock_named)
            ):
                raise ImmutableInputError("registry_lock_invalid")
            if self.public_fd is not None and self.public_metadata is not None:
                public_open = os.fstat(self.public_fd)
                public_named = os.stat("public", dir_fd=self.root_fd, follow_symlinks=False)
                if (
                    not _safe_directory(public_open)
                    or not _same_inode(public_open, self.public_metadata)
                    or not _same_inode(public_open, public_named)
                ):
                    raise ImmutableInputError("registry_root_invalid")
        except ImmutableInputError:
            raise
        except OSError as error:
            raise ImmutableInputError("registry_root_invalid") from error


def _open_public_directory(root_fd: int) -> tuple[int, os.stat_result]:
    descriptor = -1
    try:
        descriptor = os.open(
            "public",
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        metadata = os.fstat(descriptor)
        named = os.stat("public", dir_fd=root_fd, follow_symlinks=False)
        if not _safe_directory(metadata) or not _same_inode(metadata, named):
            raise ImmutableInputError("registry_root_invalid")
        return descriptor, metadata
    except ImmutableInputError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise ImmutableInputError("registry_root_invalid") from error


@contextlib.contextmanager
def _publication_lock(
    registry_path: Path,
    *,
    require_public: bool = False,
) -> Iterator[_PublicationTransaction]:
    registry_path = Path(registry_path)
    root_path = registry_path.parent
    if registry_path.name != "registry.json" or not root_path.name:
        raise ImmutableInputError("registry_root_invalid")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    if not no_follow or not directory:
        raise ImmutableInputError("registry_lock_unsupported")
    root_parent_fd = root_fd = lock_fd = public_fd = -1
    locked = False
    try:
        root_parent_fd = os.open(
            root_path.parent,
            os.O_RDONLY | directory | os.O_CLOEXEC | no_follow,
        )
        root_fd = os.open(
            root_path.name,
            os.O_RDONLY | directory | os.O_CLOEXEC | no_follow,
            dir_fd=root_parent_fd,
        )
        root_metadata = os.fstat(root_fd)
        root_named = os.stat(
            root_path.name,
            dir_fd=root_parent_fd,
            follow_symlinks=False,
        )
        if not _safe_directory(root_metadata) or not _same_inode(root_metadata, root_named):
            raise ImmutableInputError("registry_root_invalid")
        lock_name = f".{registry_path.name}.lock"
        for _ in range(128):
            try:
                lock_fd = os.open(
                    lock_name,
                    os.O_RDWR | os.O_CLOEXEC | no_follow,
                    dir_fd=root_fd,
                )
                break
            except FileNotFoundError:
                try:
                    lock_fd = os.open(
                        lock_name,
                        os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                        0o600,
                        dir_fd=root_fd,
                    )
                    break
                except FileExistsError:
                    continue
        else:
            raise ImmutableInputError("registry_lock_invalid")
        lock_metadata = os.fstat(lock_fd)
        lock_named = os.stat(lock_name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_nlink != 1
            or lock_metadata.st_uid != os.geteuid()
            or lock_metadata.st_mode & 0o077
            or not _same_inode(lock_metadata, lock_named)
        ):
            raise ImmutableInputError("registry_lock_invalid")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        locked = True
        public_metadata: os.stat_result | None = None
        if require_public:
            public_fd, public_metadata = _open_public_directory(root_fd)
        transaction = _PublicationTransaction(
            root_parent_fd=root_parent_fd,
            root_fd=root_fd,
            root_name=root_path.name,
            root_metadata=root_metadata,
            lock_fd=lock_fd,
            lock_name=lock_name,
            lock_metadata=lock_metadata,
            public_fd=public_fd if public_fd >= 0 else None,
            public_metadata=public_metadata,
        )
        transaction.verify()
        yield transaction
        transaction.verify()
    except ImmutableInputError:
        raise
    except OSError as error:
        raise ImmutableInputError("registry_lock_invalid") from error
    finally:
        if locked:
            with contextlib.suppress(OSError):
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        for descriptor in (public_fd, lock_fd, root_fd, root_parent_fd):
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)


def _temporary_name() -> str:
    return f".immutable-{os.urandom(16).hex()}.tmp"


def _atomic_write_at(
    directory_fd: int,
    name: str,
    payload: bytes,
    *,
    mode: int,
    transaction: _PublicationTransaction,
) -> None:
    temporary: str | None = None
    descriptor = -1
    try:
        for _ in range(128):
            temporary = _temporary_name()
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    mode,
                    dir_fd=directory_fd,
                )
                break
            except FileExistsError:
                continue
        else:
            raise ImmutableInputError("publication_atomic_write_failed")
        os.fchmod(descriptor, mode)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short publication write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        transaction.verify()
        os.replace(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary = None
        os.fsync(directory_fd)
        transaction.verify()
    except ImmutableInputError:
        raise
    except OSError as error:
        raise ImmutableInputError("publication_atomic_write_failed") from error
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if temporary is not None:
            with contextlib.suppress(OSError):
                os.unlink(temporary, dir_fd=directory_fd)


def _reconcile_crash_temps_at(directory_fd: int) -> None:
    removed = False
    try:
        candidates = tuple(
            name
            for name in os.listdir(directory_fd)
            if name.startswith(".immutable-") and name.endswith(".tmp")
        )
        if len(candidates) > 128:
            raise ImmutableInputError("publication_recovery_invalid")
        for candidate in candidates:
            metadata = os.stat(candidate, dir_fd=directory_fd, follow_symlinks=False)
            if (
                stat.S_ISREG(metadata.st_mode)
                and metadata.st_nlink == 1
                and metadata.st_uid == os.geteuid()
            ):
                os.unlink(candidate, dir_fd=directory_fd)
                removed = True
        if removed:
            os.fsync(directory_fd)
    except ImmutableInputError:
        raise
    except OSError as error:
        raise ImmutableInputError("publication_recovery_invalid") from error


def _load_registry_at(transaction: _PublicationTransaction) -> Registry:
    transaction.verify()
    payload = _read_regular_at(
        transaction.root_fd,
        "registry.json",
        maximum_bytes=MAX_REGISTRY_BYTES,
        code="registry_file_invalid",
    )
    transaction.verify()
    return _parse_registry(payload)


def _write_registry_at(
    transaction: _PublicationTransaction,
    entries: Sequence[RegistryEntry],
) -> None:
    registry = Registry(entries=tuple(sorted(entries, key=lambda item: item.digest)))
    payload = canonical_json_bytes(registry.to_canonical_dict()) + b"\n"
    if len(payload) > MAX_REGISTRY_BYTES:
        raise ImmutableInputError("registry_too_large")
    _atomic_write_at(
        transaction.root_fd,
        "registry.json",
        payload,
        mode=0o644,
        transaction=transaction,
    )


def _validate_improvement_task_set(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "adapter",
        "attempts",
        "probes",
        "schema_version",
    }:
        raise ImmutableInputError("improvement_task_set_invalid")
    if value["schema_version"] != IMPROVEMENT_TASK_SET_VERSION:
        raise ImmutableInputError("improvement_task_set_invalid")
    if value["adapter"] != "trusted-carl-cli-v1":
        raise ImmutableInputError("improvement_task_set_invalid")
    if not _is_int(value["attempts"]) or not 1 <= value["attempts"] <= 5:
        raise ImmutableInputError("improvement_task_set_invalid")
    probes = value["probes"]
    if not isinstance(probes, list) or not 1 <= len(probes) <= 64:
        raise ImmutableInputError("improvement_task_set_invalid")
    identifiers: list[str] = []
    required = {"argv", "expected_exit", "id", "timeout_seconds"}
    optional = {"stdout_contains", "stdout_regex"}
    for probe in probes:
        if not isinstance(probe, dict) or not required <= set(probe) <= required | optional:
            raise ImmutableInputError("improvement_task_set_invalid")
        identifier = probe["id"]
        argv = probe["argv"]
        timeout = probe["timeout_seconds"]
        expected_exit = probe["expected_exit"]
        if not isinstance(identifier, str) or not _IDENTIFIER_RE.fullmatch(identifier):
            raise ImmutableInputError("improvement_task_set_invalid")
        if (
            not isinstance(argv, list)
            or not 1 <= len(argv) <= 16
            or any(not isinstance(item, str) or len(item.encode("utf-8")) > 256 for item in argv)
        ):
            raise ImmutableInputError("improvement_task_set_invalid")
        if not _is_int(timeout) or not 1 <= timeout <= 30:
            raise ImmutableInputError("improvement_task_set_invalid")
        if not _is_int(expected_exit) or not 0 <= expected_exit <= 255:
            raise ImmutableInputError("improvement_task_set_invalid")
        contains = probe.get("stdout_contains", [])
        if not isinstance(contains, list) or any(
            not isinstance(item, str) or len(item.encode("utf-8")) > 512 for item in contains
        ):
            raise ImmutableInputError("improvement_task_set_invalid")
        pattern = probe.get("stdout_regex")
        if pattern is not None:
            if not isinstance(pattern, str) or len(pattern.encode("utf-8")) > 512:
                raise ImmutableInputError("improvement_task_set_invalid")
            try:
                re.compile(pattern)
            except re.error as error:
                raise ImmutableInputError("improvement_task_set_invalid") from error
        identifiers.append(identifier)
    if len(set(identifiers)) != len(identifiers):
        raise ImmutableInputError("improvement_task_set_invalid")


def pack_improvement_task_set(value: Mapping[str, object]) -> bytes:
    """Produce the sole accepted canonical encoding for an improvement task set."""
    _validate_improvement_task_set(value)
    try:
        payload = canonical_json_bytes(value)
    except CanonicalizationError as error:
        raise ImmutableInputError("improvement_task_set_invalid") from error
    _bounded_json_shape(value, code="improvement_task_set_invalid")
    return payload


def _normalized_archive_path(value: object, seen: set[str]) -> str:
    if not isinstance(value, str):
        raise ImmutableInputError("soak_archive_path_invalid")
    try:
        normalized = unicodedata.normalize("NFC", value)
        encoded = normalized.encode("utf-8")
    except UnicodeError as error:
        raise ImmutableInputError("soak_archive_path_invalid") from error
    if normalized in seen:
        raise ImmutableInputError("soak_archive_path_duplicate")
    if (
        value != normalized
        or not value
        or value.startswith("/")
        or "\\" in value
        or len(encoded) > 512
        or any(
            part in {"", ".", ".."} or len(part.encode("utf-8")) > 255 for part in value.split("/")
        )
    ):
        raise ImmutableInputError("soak_archive_path_invalid")
    seen.add(normalized)
    return normalized


def pack_soak_archive(files: Mapping[str, bytes]) -> bytes:
    """Pack regular files into one cross-platform deterministic USTAR archive."""
    if not isinstance(files, Mapping) or not files:
        raise ImmutableInputError("soak_archive_invalid")
    if len(files) > MAX_SOAK_ARCHIVE_ENTRIES:
        raise ImmutableInputError("soak_archive_too_many_entries")
    normalized_files: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0
    for name, content in files.items():
        normalized = _normalized_archive_path(name, seen)
        if not isinstance(content, bytes):
            raise ImmutableInputError("soak_archive_entry_invalid")
        if len(content) > MAX_SOAK_MEMBER_BYTES:
            raise ImmutableInputError("soak_archive_member_too_large")
        total += len(content)
        if total > MAX_SOAK_CONTENT_BYTES:
            raise ImmutableInputError("soak_archive_content_too_large")
        normalized_files[normalized] = content
    target = io.BytesIO()
    try:
        with tarfile.open(fileobj=target, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name in sorted(normalized_files, key=lambda item: item.encode("utf-8")):
                content = normalized_files[name]
                member = tarfile.TarInfo(name)
                member.size = len(content)
                member.mode = 0o644
                member.mtime = 0
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                member.type = tarfile.REGTYPE
                archive.addfile(member, io.BytesIO(content))
    except (OSError, tarfile.TarError, UnicodeError, ValueError) as error:
        raise ImmutableInputError("soak_archive_invalid") from error
    payload = target.getvalue()
    if len(payload) > MAX_SOAK_ARCHIVE_BYTES:
        raise ImmutableInputError("soak_archive_too_large")
    return payload


def verify_soak_archive(payload: bytes) -> dict[str, bytes]:
    """Validate a canonical archive without extracting paths to the filesystem."""
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_SOAK_ARCHIVE_BYTES:
        raise ImmutableInputError("soak_archive_too_large")
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > MAX_SOAK_ARCHIVE_ENTRIES:
                raise ImmutableInputError("soak_archive_too_many_entries")
            for member in members:
                name = _normalized_archive_path(member.name, seen)
                if (
                    not member.isreg()
                    or member.type != tarfile.REGTYPE
                    or member.mode != 0o644
                    or member.mtime != 0
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.linkname
                    or member.devmajor != 0
                    or member.devminor != 0
                    or member.pax_headers
                ):
                    raise ImmutableInputError("soak_archive_entry_invalid")
                if member.size > MAX_SOAK_MEMBER_BYTES:
                    raise ImmutableInputError("soak_archive_member_too_large")
                total += member.size
                if total > MAX_SOAK_CONTENT_BYTES:
                    raise ImmutableInputError("soak_archive_content_too_large")
                source = archive.extractfile(member)
                if source is None:
                    raise ImmutableInputError("soak_archive_entry_invalid")
                content = source.read(member.size + 1)
                if len(content) != member.size:
                    raise ImmutableInputError("soak_archive_entry_invalid")
                files[name] = content
    except ImmutableInputError:
        raise
    except (OSError, tarfile.TarError, EOFError, UnicodeError, ValueError) as error:
        raise ImmutableInputError("soak_archive_invalid") from error
    if not files:
        raise ImmutableInputError("soak_archive_invalid")
    if pack_soak_archive(files) != payload:
        raise ImmutableInputError("soak_archive_not_canonical")
    return files


def _verify_payload(payload: bytes, *, media_type: str, media_version: int) -> None:
    _validate_media(media_type, media_version)
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_OBJECT_BYTES:
        raise ImmutableInputError("object_size_invalid")
    if media_type == SOAK_TASK_SET_MEDIA_TYPE:
        verify_soak_archive(payload)
        return
    value = _parse_canonical_json(payload, code="object_json_invalid")
    if not isinstance(value, dict) or value.get("schema_version") != media_version:
        raise ImmutableInputError("object_schema_invalid")
    if media_type == IMPROVEMENT_TASK_SET_MEDIA_TYPE:
        _validate_improvement_task_set(value)


def _registry_root(registry_path: Path, root: Path) -> tuple[Path, Path]:
    registry_path = Path(registry_path)
    root = Path(root)
    try:
        root_stat = root.lstat()
        public_stat = (root / "public").lstat()
    except OSError as error:
        raise ImmutableInputError("registry_root_invalid") from error
    if (
        registry_path.parent != root
        or registry_path.name != "registry.json"
        or not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_ISLNK(root_stat.st_mode)
        or not stat.S_ISDIR(public_stat.st_mode)
        or stat.S_ISLNK(public_stat.st_mode)
    ):
        raise ImmutableInputError("registry_root_invalid")
    return registry_path, root


def _publish_entry(
    registry_path: Path,
    entry: RegistryEntry,
    *,
    public_payload: bytes | None = None,
    public_root: Path | None = None,
) -> RegistryEntry:
    if public_root is not None and Path(public_root) != Path(registry_path).parent:
        raise ImmutableInputError("registry_root_invalid")
    with _publication_lock(
        registry_path,
        require_public=public_payload is not None,
    ) as transaction:
        transaction.verify()
        _reconcile_crash_temps_at(transaction.root_fd)
        if transaction.public_fd is not None:
            transaction.verify()
            _reconcile_crash_temps_at(transaction.public_fd)
        transaction.verify()
        registry = _load_registry_at(transaction)
        if _publication_after_registry_load_for_test is not None:
            _publication_after_registry_load_for_test()
        by_digest = {item.digest: item for item in registry.entries}
        existing = by_digest.get(entry.digest)
        if existing is not None and existing != entry:
            raise ImmutableInputError("registry_entry_conflict")
        if any(
            item.object_key == entry.object_key and item.digest != entry.digest
            for item in registry.entries
        ):
            raise ImmutableInputError("registry_object_key_conflict")
        if existing is None and len(registry.entries) >= MAX_REGISTRY_ENTRIES:
            raise ImmutableInputError("registry_too_large")
        if public_payload is not None:
            if public_root is None or transaction.public_fd is None:
                raise ImmutableInputError("registry_root_invalid")
            try:
                target = os.stat(
                    entry.digest,
                    dir_fd=transaction.public_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                target = None
            except OSError as error:
                raise ImmutableInputError("public_object_conflict") from error
            if target is not None:
                current = _read_regular_at(
                    transaction.public_fd,
                    entry.digest,
                    maximum_bytes=MAX_OBJECT_BYTES,
                    code="public_object_conflict",
                )
                if current != public_payload:
                    raise ImmutableInputError("public_object_conflict")
            else:
                _atomic_write_at(
                    transaction.public_fd,
                    entry.digest,
                    public_payload,
                    mode=0o444,
                    transaction=transaction,
                )
        if existing is None:
            _write_registry_at(transaction, (*registry.entries, entry))
        transaction.verify()
        return existing or entry


def publish_public(
    registry_path: Path,
    *,
    root: Path,
    payload: bytes,
    media_type: str,
    media_version: int,
) -> RegistryEntry:
    """Atomically create or reconcile one digest-addressed committed public object."""
    registry_path, root = _registry_root(registry_path, root)
    _verify_payload(payload, media_type=media_type, media_version=media_version)
    digest = hashlib.sha256(payload).hexdigest()
    entry = RegistryEntry(
        digest=digest,
        size_bytes=len(payload),
        media_type=media_type,
        media_version=media_version,
        object_key=f"public/{digest}",
        visibility="public",
    )
    return _publish_entry(
        registry_path,
        entry,
        public_payload=payload,
        public_root=root,
    )


def publish_private_commitment(
    registry_path: Path,
    *,
    digest: str,
    size_bytes: int,
    media_type: str,
    media_version: int,
    object_key: str,
) -> RegistryEntry:
    """Publish only private commitment metadata; private bytes never cross this API."""
    registry_path = Path(registry_path)
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise ImmutableInputError("registry_digest_invalid")
    if not _is_int(size_bytes) or not 1 <= size_bytes <= MAX_OBJECT_BYTES:
        raise ImmutableInputError("registry_size_invalid")
    media_type, media_version = _validate_media(media_type, media_version)
    object_key = _validate_object_key(object_key, visibility="private", digest=digest)
    entry = RegistryEntry(
        digest=digest,
        size_bytes=size_bytes,
        media_type=media_type,
        media_version=media_version,
        object_key=object_key,
        visibility="private",
    )
    return _publish_entry(registry_path, entry)


def _entry_for_digest(registry: Registry, digest: str) -> RegistryEntry:
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise ImmutableInputError("object_digest_invalid")
    entry = next((item for item in registry.entries if item.digest == digest), None)
    if entry is None:
        raise ImmutableInputError("object_not_committed")
    return entry


def resolve_entry(
    registry_path: Path,
    *,
    root: Path,
    digest: str,
    expected_media_type: str,
    expected_media_version: int,
    object_store: BoundedObjectStore | None = None,
) -> bytes:
    """Resolve one committed object and verify size and digest before parsing."""
    registry_path, root = _registry_root(registry_path, root)
    registry = load_registry(registry_path)
    entry = _entry_for_digest(registry, digest)
    if entry.media_type != expected_media_type or entry.media_version != expected_media_version:
        raise ImmutableInputError("object_media_mismatch")
    if entry.visibility == "public":
        expected_key = f"public/{entry.digest}"
        if entry.object_key != expected_key:
            raise ImmutableInputError("registry_object_key_invalid")
        payload = _read_regular(
            root / "public" / entry.digest,
            maximum_bytes=entry.size_bytes,
            code="public_object_invalid",
        )
    else:
        if object_store is None:
            raise ImmutableInputError("private_object_store_required")
        try:
            payload = object_store.fetch(entry.object_key, max_bytes=entry.size_bytes)
        except Exception as error:
            raise ImmutableInputError("private_object_unavailable") from error
        if not isinstance(payload, bytes):
            raise ImmutableInputError("private_object_unavailable")
    if len(payload) != entry.size_bytes:
        raise ImmutableInputError("object_size_mismatch")
    if hashlib.sha256(payload).hexdigest() != entry.digest:
        raise ImmutableInputError("object_digest_mismatch")
    _verify_payload(payload, media_type=entry.media_type, media_version=entry.media_version)
    return payload


def _strict_contract(payload: bytes, *, fields: set[str], code: str) -> dict[str, Any]:
    value = _parse_canonical_json(payload, code=code)
    if not isinstance(value, dict) or set(value) != fields or value.get("schema_version") != 1:
        raise ImmutableInputError(code)
    return value


def _check_ids(value: object, *, code: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 64
        or any(not isinstance(item, str) or not _IDENTIFIER_RE.fullmatch(item) for item in value)
        or len(set(value)) != len(value)
    ):
        raise ImmutableInputError(code)
    return tuple(value)


def evaluate_soak_health(
    experiment_payload: bytes,
    task_set_payload: bytes,
    metric_pack_payload: bytes,
    policy_payload: bytes,
    observations: Mapping[str, bool],
) -> SoakHealthDecision:
    """Make all four immutable soak contracts govern one fail-closed health decision."""
    experiment = _strict_contract(
        experiment_payload,
        fields={"schema_version", "soak_check_ids"},
        code="soak_experiment_contract_invalid",
    )
    experiment_ids = _check_ids(
        experiment["soak_check_ids"], code="soak_experiment_contract_invalid"
    )
    archive = verify_soak_archive(task_set_payload)
    manifest_payload = archive.get("soak-contract.json")
    if manifest_payload is None:
        raise ImmutableInputError("soak_task_set_contract_invalid")
    manifest = _strict_contract(
        manifest_payload,
        fields={"check_ids", "schema_version"},
        code="soak_task_set_contract_invalid",
    )
    task_ids = _check_ids(manifest["check_ids"], code="soak_task_set_contract_invalid")
    metric_pack = _strict_contract(
        metric_pack_payload,
        fields={"algorithm", "check_weights", "schema_version"},
        code="soak_metric_pack_contract_invalid",
    )
    weights = metric_pack["check_weights"]
    if metric_pack["algorithm"] != "weighted-binary-soak-v1" or not isinstance(weights, dict):
        raise ImmutableInputError("soak_metric_pack_contract_invalid")
    policy = _strict_contract(
        policy_payload,
        fields={"minimum_score_basis_points", "require_all_checks", "schema_version"},
        code="soak_policy_contract_invalid",
    )
    minimum = policy["minimum_score_basis_points"]
    require_all = policy["require_all_checks"]
    expected = set(experiment_ids)
    if set(task_ids) != expected or set(weights) != expected:
        raise ImmutableInputError("soak_contract_identity_mismatch")
    if not isinstance(observations, Mapping) or set(observations) != expected:
        raise ImmutableInputError("soak_observations_invalid")
    if any(not isinstance(value, bool) for value in observations.values()):
        raise ImmutableInputError("soak_observations_invalid")
    if any(not _is_int(weight) or not 1 <= weight <= 10_000 for weight in weights.values()):
        raise ImmutableInputError("soak_metric_pack_contract_invalid")
    if not _is_int(minimum) or not 0 <= minimum <= 10_000 or not isinstance(require_all, bool):
        raise ImmutableInputError("soak_policy_contract_invalid")
    total = sum(weights.values())
    passed = sum(weights[identifier] for identifier in experiment_ids if observations[identifier])
    score = (passed * 10_000 + total // 2) // total
    reasons: list[str] = []
    if require_all and not all(observations.values()):
        reasons.append("soak_required_check_failed")
    if score < minimum:
        reasons.append("soak_minimum_score_not_met")
    return SoakHealthDecision(
        healthy=not reasons,
        score_basis_points=score,
        reasons=tuple(reasons),
        input_digests={
            "experiment": hashlib.sha256(experiment_payload).hexdigest(),
            "metric_pack": hashlib.sha256(metric_pack_payload).hexdigest(),
            "policy": hashlib.sha256(policy_payload).hexdigest(),
            "task_set": hashlib.sha256(task_set_payload).hexdigest(),
        },
    )


def _resolve_set(args: argparse.Namespace) -> str:
    expected_task_media = (
        IMPROVEMENT_TASK_SET_MEDIA_TYPE if args.mode == "improvement" else SOAK_TASK_SET_MEDIA_TYPE
    )
    if args.task_media_type != expected_task_media:
        raise ImmutableInputError("object_media_mismatch")
    requests = {
        "experiment": (args.experiment_digest, EXPERIMENT_MEDIA_TYPE, 1),
        "metric-pack": (args.metric_pack_digest, METRIC_PACK_MEDIA_TYPE, 1),
        "policy": (args.policy_digest, POLICY_MEDIA_TYPE, 1),
        "task-set": (args.task_set_digest, expected_task_media, 1),
    }
    output_dir = Path(args.output_dir)
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        metadata = output_dir.lstat()
    except OSError as error:
        raise ImmutableInputError("resolved_output_invalid") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ImmutableInputError("resolved_output_invalid")
    registry = load_registry(Path(args.registry))
    bindings: dict[str, dict[str, object]] = {}
    for name, (digest, media_type, media_version) in requests.items():
        payload = resolve_entry(
            Path(args.registry),
            root=Path(args.root),
            digest=digest,
            expected_media_type=media_type,
            expected_media_version=media_version,
        )
        _atomic_write(output_dir / name, payload, mode=0o600)
        bindings[name] = _entry_for_digest(registry, digest).to_canonical_dict()
    return hashlib.sha256(canonical_json_bytes(bindings)).hexdigest()


def _soak_health_command(args: argparse.Namespace) -> None:
    observations_value = _parse_canonical_json(
        _read_regular(
            Path(args.observations),
            maximum_bytes=MAX_REGISTRY_BYTES,
            code="soak_observations_invalid",
        ),
        code="soak_observations_invalid",
    )
    if not isinstance(observations_value, dict):
        raise ImmutableInputError("soak_observations_invalid")
    decision = evaluate_soak_health(
        _read_regular(Path(args.experiment), maximum_bytes=MAX_OBJECT_BYTES, code="object_invalid"),
        _read_regular(Path(args.task_set), maximum_bytes=MAX_OBJECT_BYTES, code="object_invalid"),
        _read_regular(
            Path(args.metric_pack), maximum_bytes=MAX_OBJECT_BYTES, code="object_invalid"
        ),
        _read_regular(Path(args.policy), maximum_bytes=MAX_OBJECT_BYTES, code="object_invalid"),
        observations_value,
    )
    _atomic_write(Path(args.output), canonical_json_bytes(decision.to_canonical_dict()), mode=0o600)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Resolve and evaluate immutable Carl inputs")
    commands = parser.add_subparsers(dest="command", required=True)
    resolve = commands.add_parser("resolve-set")
    resolve.add_argument("--registry", type=Path, required=True)
    resolve.add_argument("--root", type=Path, required=True)
    resolve.add_argument("--mode", choices=("improvement", "soak"), required=True)
    resolve.add_argument("--task-media-type", required=True)
    resolve.add_argument("--experiment-digest", required=True)
    resolve.add_argument("--task-set-digest", required=True)
    resolve.add_argument("--metric-pack-digest", required=True)
    resolve.add_argument("--policy-digest", required=True)
    resolve.add_argument("--output-dir", type=Path, required=True)
    health = commands.add_parser("soak-health")
    health.add_argument("--experiment", type=Path, required=True)
    health.add_argument("--task-set", type=Path, required=True)
    health.add_argument("--metric-pack", type=Path, required=True)
    health.add_argument("--policy", type=Path, required=True)
    health.add_argument("--observations", type=Path, required=True)
    health.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "resolve-set":
            print(_resolve_set(args))
        else:
            _soak_health_command(args)
    except ImmutableInputError as error:
        print(error.code, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
