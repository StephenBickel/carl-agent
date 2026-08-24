"""Credential-free exec barrier for one deterministic harness subject."""

from __future__ import annotations

import os
import stat
import sys
from contextlib import suppress


def main() -> int:
    if len(sys.argv) < 2:
        return 64
    raw_barrier = os.environ.get("CARL_WORKER_BARRIER_FD")
    raw_executable = os.environ.get("CARL_PINNED_EXECUTABLE_FD")
    if (
        not isinstance(raw_barrier, str)
        or not raw_barrier.isdecimal()
        or not isinstance(raw_executable, str)
        or not raw_executable.isdecimal()
    ):
        return 64
    barrier = int(raw_barrier)
    executable = int(raw_executable)
    if barrier < 3 or executable < 3:
        return 64
    try:
        released = os.read(barrier, 1)
        details = os.fstat(executable)
    except OSError:
        return 70
    finally:
        with suppress(OSError):
            os.close(barrier)
    if released != b"1" or not stat.S_ISREG(details.st_mode):
        return 70
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.defpath,
    }
    execution_path = (
        f"/proc/self/fd/{executable}" if sys.platform.startswith("linux") else sys.argv[1]
    )
    try:
        os.execve(execution_path, sys.argv[1:], environment)
    except OSError:
        return 70


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
