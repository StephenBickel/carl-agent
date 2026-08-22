"""Protected Linux cgroup v2 containment for untrusted live-evaluation workers."""

from __future__ import annotations

import hashlib
import re
import stat
import sys
import time
from contextlib import suppress
from pathlib import Path

from carl_bench.canonical import canonical_json_bytes

_SERVICE_CGROUP = "/system.slice/carl-live-gateway.service"
_CGROUP_MOUNT = Path("/sys/fs/cgroup")
_PROCESS_CGROUP = Path("/proc/self/cgroup")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class LiveWorkerIsolationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _read_bounded(path: Path, *, maximum_bytes: int = 16_384) -> str:
    try:
        details = path.lstat()
        if not stat.S_ISREG(details.st_mode) or stat.S_ISLNK(details.st_mode):
            raise LiveWorkerIsolationError("live_worker_isolation_not_commissioned")
        payload = path.read_bytes()
    except OSError as error:
        raise LiveWorkerIsolationError("live_worker_isolation_not_commissioned") from error
    if not 0 < len(payload) <= maximum_bytes:
        raise LiveWorkerIsolationError("live_worker_isolation_not_commissioned")
    try:
        return payload.decode("ascii")
    except UnicodeError:
        raise LiveWorkerIsolationError("live_worker_isolation_not_commissioned") from None


class CgroupV2WorkerScope:
    """One delegated cgroup whose descendants cannot escape through setsid()."""

    __slots__ = ("_path", "_relative", "attestation_digest")

    def __init__(self, *, path: Path, relative: str, execution_digest: str) -> None:
        self._path = path
        self._relative = relative
        details = path.stat()
        self.attestation_digest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "cgroup_device": details.st_dev,
                    "cgroup_inode": details.st_ino,
                    "cgroup_path": relative,
                    "execution_digest": execution_digest,
                    "profile": "systemd-delegated-cgroup-v2-v1",
                    "schema_version": 1,
                }
            )
        ).hexdigest()

    @staticmethod
    def _runtime_identity(process_id: int) -> tuple[int, int]:
        status = _read_bounded(Path(f"/proc/{process_id}/status"))
        fields: dict[str, list[str]] = {}
        for line in status.splitlines():
            name, separator, value = line.partition(":")
            if separator:
                fields[name] = value.split()
        uids = fields.get("Uid")
        gids = fields.get("Gid")
        if (
            uids is None
            or gids is None
            or len(uids) != 4
            or len(gids) != 4
            or any(not value.isdecimal() for value in (*uids, *gids))
            or len(set(uids)) != 1
            or len(set(gids)) != 1
        ):
            raise LiveWorkerIsolationError("live_worker_identity_mismatch")
        return int(uids[0]), int(gids[0])

    def attach_and_observe(
        self, process_id: int, *, expected_uid: int, expected_gid: int
    ) -> tuple[int, int]:
        if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
            raise LiveWorkerIsolationError("live_worker_isolation_attach_failed")
        try:
            (self._path / "cgroup.procs").write_text(f"{process_id}\n", encoding="ascii")
        except OSError as error:
            raise LiveWorkerIsolationError("live_worker_isolation_attach_failed") from error
        identity = self._runtime_identity(process_id)
        process_cgroup = _read_bounded(Path(f"/proc/{process_id}/cgroup")).strip()
        members = _read_bounded(self._path / "cgroup.procs").split()
        if (
            identity != (expected_uid, expected_gid)
            or process_cgroup != f"0::{self._relative}"
            or str(process_id) not in members
        ):
            raise LiveWorkerIsolationError("live_worker_identity_mismatch")
        return identity

    @staticmethod
    def _populated(events: str) -> bool:
        values = dict(line.split() for line in events.splitlines() if len(line.split()) == 2)
        if values.get("populated") not in {"0", "1"}:
            raise LiveWorkerIsolationError("live_worker_isolation_state_invalid")
        return values["populated"] == "1"

    def cleanup_and_verify_empty(self) -> None:
        try:
            (self._path / "cgroup.kill").write_text("1\n", encoding="ascii")
        except OSError as error:
            raise LiveWorkerIsolationError("live_worker_isolation_cleanup_failed") from error
        deadline = time.monotonic() + 5
        while self._populated(_read_bounded(self._path / "cgroup.events")):
            if time.monotonic() >= deadline:
                raise LiveWorkerIsolationError("live_worker_isolation_not_empty")
            time.sleep(0.01)
        try:
            self._path.rmdir()
        except OSError as error:
            raise LiveWorkerIsolationError("live_worker_isolation_cleanup_failed") from error


class CgroupV2WorkerIsolation:
    """Factory for exact root-owned delegated worker cgroups."""

    __slots__ = ("_root",)

    def __new__(cls, *args: object, **kwargs: object) -> CgroupV2WorkerIsolation:
        del cls, args, kwargs
        raise LiveWorkerIsolationError("live_worker_isolation_protected_construction_required")

    @classmethod
    def from_protected_process(cls) -> CgroupV2WorkerIsolation:
        if not sys.platform.startswith("linux"):
            raise LiveWorkerIsolationError("live_worker_isolation_not_commissioned")
        if _read_bounded(_PROCESS_CGROUP).strip() != f"0::{_SERVICE_CGROUP}":
            raise LiveWorkerIsolationError("live_worker_isolation_not_commissioned")
        root = _CGROUP_MOUNT / _SERVICE_CGROUP.removeprefix("/")
        try:
            details = root.lstat()
            entries = {item.name for item in root.iterdir()}
        except OSError as error:
            raise LiveWorkerIsolationError("live_worker_isolation_not_commissioned") from error
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != 0
            or stat.S_IMODE(details.st_mode) & 0o022
            or not {"cgroup.events", "cgroup.kill", "cgroup.procs", "cgroup.type"}.issubset(entries)
            or _read_bounded(root / "cgroup.type").strip() != "domain"
        ):
            raise LiveWorkerIsolationError("live_worker_isolation_not_commissioned")
        value = object.__new__(cls)
        value._root = root
        return value

    def begin(self, execution_digest: str) -> CgroupV2WorkerScope:
        if not isinstance(execution_digest, str) or _DIGEST_RE.fullmatch(execution_digest) is None:
            raise LiveWorkerIsolationError("live_worker_isolation_request_invalid")
        path = self._root / f"worker-{execution_digest[:32]}"
        try:
            path.mkdir(mode=0o700)
            required = {"cgroup.events", "cgroup.kill", "cgroup.procs", "cgroup.type"}
            if not required.issubset({item.name for item in path.iterdir()}):
                raise LiveWorkerIsolationError("live_worker_isolation_not_commissioned")
            if _read_bounded(path / "cgroup.type").strip() != "domain":
                raise LiveWorkerIsolationError("live_worker_isolation_not_commissioned")
        except LiveWorkerIsolationError:
            with suppress(OSError):
                path.rmdir()
            raise
        except OSError as error:
            raise LiveWorkerIsolationError("live_worker_isolation_unavailable") from error
        relative = f"{_SERVICE_CGROUP}/{path.name}"
        return CgroupV2WorkerScope(
            path=path,
            relative=relative,
            execution_digest=execution_digest,
        )
