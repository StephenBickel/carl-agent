"""Descriptor-pinned filesystem checks for protected Unix sockets."""

from __future__ import annotations

import os
import stat
from contextlib import suppress
from pathlib import Path


class ProtectedSocketPathError(ValueError):
    """The protected socket path does not have the required identity."""


def _canonical_absolute(path: Path) -> bool:
    return (
        isinstance(path, Path)
        and path.is_absolute()
        and path.name not in {"", ".", ".."}
        and ".." not in path.parts
        and os.path.normpath(os.fspath(path)) == os.fspath(path)
    )


def open_pinned_parent(path: Path, *, expected_uid: int) -> int:
    """Open every ancestor from root without following symbolic links."""
    if (
        not _canonical_absolute(path)
        or isinstance(expected_uid, bool)
        or not isinstance(expected_uid, int)
        or expected_uid < 0
    ):
        raise ProtectedSocketPathError
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        current = os.open("/", flags)
        for component in path.parent.parts[1:]:
            try:
                following = os.open(component, flags, dir_fd=current)
            finally:
                os.close(current)
            current = following
            details = os.fstat(current)
            if not stat.S_ISDIR(details.st_mode) or details.st_uid not in {0, expected_uid}:
                raise ProtectedSocketPathError
        parent = os.fstat(current)
        if (
            parent.st_uid != expected_uid
            or stat.S_IMODE(parent.st_mode) & 0o022
            or not stat.S_ISDIR(parent.st_mode)
        ):
            raise ProtectedSocketPathError
        return current
    except (OSError, ProtectedSocketPathError) as error:
        with suppress(OSError, UnboundLocalError):
            os.close(current)
        raise ProtectedSocketPathError from error


def socket_identity_at(parent_fd: int, name: str, *, expected_uid: int) -> tuple[int, ...]:
    """Return the exact no-follow identity of a protected 0600 socket."""
    try:
        details = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise ProtectedSocketPathError from error
    if (
        stat.S_ISLNK(details.st_mode)
        or not stat.S_ISSOCK(details.st_mode)
        or details.st_uid != expected_uid
        or stat.S_IMODE(details.st_mode) != 0o600
    ):
        raise ProtectedSocketPathError
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_uid,
        details.st_gid,
        details.st_ctime_ns,
    )
