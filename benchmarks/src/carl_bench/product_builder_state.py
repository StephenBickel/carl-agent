"""Crash-safe kernel locking for product-builder durable state transitions."""

from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from carl_bench.product_builder import BuilderError


@contextmanager
def kernel_request_lock(path: Path) -> Iterator[None]:
    """Hold an advisory kernel lock; stale lock pathnames carry no ownership."""
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise BuilderError("builder_request_claim_busy") from error
    try:
        mode = os.fstat(descriptor).st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode) & 0o077:
            raise BuilderError("builder_request_claim_lock_invalid")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise BuilderError("builder_request_claim_busy") from error
        yield
    finally:
        os.close(descriptor)
