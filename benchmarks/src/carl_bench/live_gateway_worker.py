"""Credential-free exec barrier for a protected live-evaluation subject."""

from __future__ import annotations

import os
import stat
import sys
from contextlib import suppress


def main() -> int:
    if len(sys.argv) < 2:
        return 64
    raw_descriptor = os.environ.get("CARL_WORKER_BARRIER_FD")
    if not isinstance(raw_descriptor, str) or not raw_descriptor.isdecimal():
        return 64
    descriptor = int(raw_descriptor)
    if descriptor < 3:
        return 64
    try:
        released = os.read(descriptor, 1)
    except OSError:
        return 70
    finally:
        with suppress(OSError):
            os.close(descriptor)
    if released != b"1":
        return 70
    endpoint = os.environ.get("CARL_MODEL_GATEWAY_ENDPOINT")
    token = os.environ.get("CARL_MODEL_GATEWAY_TOKEN")
    raw_executable_descriptor = os.environ.get("CARL_PINNED_EXECUTABLE_FD")
    if (
        not endpoint
        or not token
        or not isinstance(raw_executable_descriptor, str)
        or not raw_executable_descriptor.isdecimal()
    ):
        return 70
    executable_descriptor = int(raw_executable_descriptor)
    try:
        executable_details = os.fstat(executable_descriptor)
    except OSError:
        return 70
    if executable_descriptor < 3 or not stat.S_ISREG(executable_details.st_mode):
        return 70
    environment = {
        "CARL_MODEL_GATEWAY_ENDPOINT": endpoint,
        "CARL_MODEL_GATEWAY_TOKEN": token,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.defpath,
    }
    try:
        execution_path = (
            f"/proc/self/fd/{executable_descriptor}"
            if sys.platform.startswith("linux")
            else sys.argv[1]
        )
        os.execve(execution_path, sys.argv[1:], environment)
    except OSError:
        return 70


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
