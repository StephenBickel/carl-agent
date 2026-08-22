"""Independent protected commissioning policy for live execution receipts."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_execution_receipt import ProtectedExecutionReceipt

_PROTECTED_CHECKOUT_ROOT = Path("/srv/carl/checkouts")
_EXECUTABLE_RELATIVE_PATH = "carl"
_ARGUMENTS = ("--bounded-live",)
_TIMEOUT_SECONDS = 30
_CGROUP_UNIT = "carl-live-gateway.service"


class LiveExecutionCommissioningError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class LiveExecutionCommissioningPolicy:
    """Pinned policy that independently observes the executable named by a receipt."""

    __slots__ = (
        "_arguments",
        "_cgroup_unit",
        "_checkout_root",
        "_executable_relative_path",
        "_timeout_seconds",
        "_workers",
    )

    def __new__(cls, *args: object, **kwargs: object) -> LiveExecutionCommissioningPolicy:
        del cls, args, kwargs
        raise LiveExecutionCommissioningError(
            "live_execution_commissioning_protected_construction_required"
        )

    @classmethod
    def from_protected_process(
        cls, *, workers: tuple[tuple[int, int], tuple[int, int]]
    ) -> LiveExecutionCommissioningPolicy:
        try:
            details = _PROTECTED_CHECKOUT_ROOT.lstat()
        except OSError as error:
            raise LiveExecutionCommissioningError(
                "live_execution_commissioning_not_available"
            ) from error
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != 0
            or stat.S_IMODE(details.st_mode) & 0o022
        ):
            raise LiveExecutionCommissioningError("live_execution_commissioning_not_available")
        return cls._construct(
            checkout_root=_PROTECTED_CHECKOUT_ROOT,
            executable_relative_path=_EXECUTABLE_RELATIVE_PATH,
            arguments=_ARGUMENTS,
            timeout_seconds=_TIMEOUT_SECONDS,
            workers=workers,
            cgroup_unit=_CGROUP_UNIT,
        )

    @classmethod
    def _for_testing(
        cls,
        *,
        checkout_root: Path,
        executable_relative_path: str,
        arguments: tuple[str, ...],
        timeout_seconds: int,
        workers: tuple[tuple[int, int], tuple[int, int]],
        cgroup_unit: str,
    ) -> LiveExecutionCommissioningPolicy:
        return cls._construct(
            checkout_root=checkout_root,
            executable_relative_path=executable_relative_path,
            arguments=arguments,
            timeout_seconds=timeout_seconds,
            workers=workers,
            cgroup_unit=cgroup_unit,
        )

    @classmethod
    def _construct(
        cls,
        *,
        checkout_root: Path,
        executable_relative_path: str,
        arguments: tuple[str, ...],
        timeout_seconds: int,
        workers: tuple[tuple[int, int], tuple[int, int]],
        cgroup_unit: str,
    ) -> LiveExecutionCommissioningPolicy:
        relative = Path(executable_relative_path)
        if (
            not isinstance(checkout_root, Path)
            or not checkout_root.is_absolute()
            or checkout_root.is_symlink()
            or relative.is_absolute()
            or str(relative) in {"", ".", ".."}
            or ".." in relative.parts
            or type(arguments) is not tuple
            or any(not isinstance(item, str) or "\x00" in item for item in arguments)
            or type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 3_600
            or not isinstance(workers, tuple)
            or len(workers) != 2
            or workers[0][0] == workers[1][0]
            or any(
                type(value) is not int or not 1 <= value <= 2_147_483_647
                for worker in workers
                for value in worker
            )
            or cgroup_unit != "carl-live-gateway.service"
        ):
            raise LiveExecutionCommissioningError(
                "live_execution_commissioning_configuration_invalid"
            )
        value = object.__new__(cls)
        value._checkout_root = checkout_root
        value._executable_relative_path = relative
        value._arguments = arguments
        value._timeout_seconds = timeout_seconds
        value._workers = workers
        value._cgroup_unit = cgroup_unit
        return value

    @property
    def workers(self) -> tuple[tuple[int, int], tuple[int, int]]:
        return self._workers

    def verifies(self, receipt: object) -> bool:
        if type(receipt) is not ProtectedExecutionReceipt:
            return False
        worker = self._workers[0 if receipt.subject == "parent" else 1]
        checkout = self._checkout_root / receipt.subject_commit
        executable = checkout / self._executable_relative_path
        expected_argv = (os.fspath(executable), *self._arguments)
        if (
            receipt.argv != expected_argv
            or receipt.timeout_seconds != self._timeout_seconds
            or (receipt.worker_uid, receipt.worker_gid) != worker
            or receipt.cgroup_unit != self._cgroup_unit
        ):
            return False
        try:
            checkout_details = checkout.lstat()
            executable_before = executable.lstat()
            if (
                not stat.S_ISDIR(checkout_details.st_mode)
                or stat.S_ISLNK(checkout_details.st_mode)
                or not stat.S_ISREG(executable_before.st_mode)
                or stat.S_ISLNK(executable_before.st_mode)
                or executable_before.st_nlink != 1
                or not executable_before.st_mode & stat.S_IXUSR
            ):
                return False
            digest = hashlib.sha256()
            with executable.open("rb") as source:
                while chunk := source.read(65_536):
                    digest.update(chunk)
            executable_after = executable.lstat()
        except OSError:
            return False
        executable_identity = (
            executable_before.st_dev,
            executable_before.st_ino,
            executable_before.st_size,
            executable_before.st_mode,
            executable_before.st_mtime_ns,
        )
        if executable_identity != (
            executable_after.st_dev,
            executable_after.st_ino,
            executable_after.st_size,
            executable_after.st_mode,
            executable_after.st_mtime_ns,
        ):
            return False
        executable_digest = digest.hexdigest()
        checkout_digest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "commit": receipt.subject_commit,
                    "executable_digest": executable_digest,
                    "executable_identity": list(executable_identity),
                    "root_device": checkout_details.st_dev,
                    "root_inode": checkout_details.st_ino,
                    "tree": receipt.subject_tree,
                }
            )
        ).hexdigest()
        execution_digest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "attempt": receipt.attempt,
                    "checkout_digest": checkout_digest,
                    "pair_request_digest": receipt.pair_request_digest,
                    "subject": receipt.subject,
                    "task_id": receipt.task_id,
                }
            )
        ).hexdigest()
        expected_cgroup_path = f"/system.slice/{self._cgroup_unit}/worker-{execution_digest[:32]}"
        return (
            receipt.executable_device,
            receipt.executable_inode,
            receipt.executable_size,
            receipt.executable_mode,
            receipt.executable_mtime_ns,
            receipt.executable_digest,
            receipt.checkout_device,
            receipt.checkout_inode,
            receipt.checkout_digest,
            receipt.cgroup_path,
        ) == (
            *executable_identity,
            executable_digest,
            checkout_details.st_dev,
            checkout_details.st_ino,
            checkout_digest,
            expected_cgroup_path,
        )
