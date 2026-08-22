"""Protected owner of live subject process launch and gateway capability issuance."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import signal
import stat
import subprocess
import sys
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_capability import LiveEvaluationIdentity, LivePairPolicy, LiveTaskIdentity
from carl_bench.live_execution_receipt import (
    ProtectedLiveExecutionResult,
    model_result_digest,
    sign_execution_receipt,
)
from carl_bench.live_gateway_authority import (
    LiveGatewayAuthorityError,
    ProtectedExecutionObservation,
    ProtectedModelGatewayServer,
)
from carl_bench.live_worker_isolation import CgroupV2WorkerIsolation, LiveWorkerIsolationError

_MAX_WORKER_SECONDS = 3_600


@dataclass(frozen=True, slots=True)
class _PinnedCheckout:
    checkout: Path
    executable: Path
    descriptor: int
    expected_commit: str
    expected_tree: str
    root_identity: tuple[int, int]
    executable_identity: tuple[int, int, int, int, int]
    executable_digest: str
    checkout_digest: str


class ProtectedLiveGatewayRunner:
    """Launch exact unprivileged workers and bind their observed process to one capability."""

    __slots__ = ("_execution_key", "_isolation", "_server", "_workers")

    def __new__(cls, *args: object, **kwargs: object) -> ProtectedLiveGatewayRunner:
        del cls, args, kwargs
        raise LiveGatewayAuthorityError("live_gateway_runner_protected_construction_required")

    @staticmethod
    def _worker(prefix: str) -> tuple[int, int]:
        uid = os.environ.get(f"CARL_{prefix}_WORKER_UID")
        gid = os.environ.get(f"CARL_{prefix}_WORKER_GID")
        if (
            not isinstance(uid, str)
            or not isinstance(gid, str)
            or not uid.isdecimal()
            or not gid.isdecimal()
            or str(int(uid)) != uid
            or str(int(gid)) != gid
        ):
            raise LiveGatewayAuthorityError("live_worker_identity_missing")
        identity = int(uid), int(gid)
        if not 1 <= identity[0] <= 2_147_483_647 or not 1 <= identity[1] <= 2_147_483_647:
            raise LiveGatewayAuthorityError("live_worker_identity_invalid")
        return identity

    @classmethod
    def from_protected_process(cls) -> ProtectedLiveGatewayRunner:
        workers = cls._worker("PARENT"), cls._worker("CANDIDATE")
        if workers[0][0] == workers[1][0] or os.geteuid() in {
            workers[0][0],
            workers[1][0],
        }:
            raise LiveGatewayAuthorityError("live_worker_identity_invalid")
        isolation = CgroupV2WorkerIsolation.from_live_gateway_process()
        return cls._construct(
            server=ProtectedModelGatewayServer.from_protected_process(),
            workers=workers,
            isolation=isolation,
            execution_key=cls._protected_execution_key(),
        )

    @staticmethod
    def _protected_execution_key() -> bytes:
        encoded = os.environ.get("CARL_LIVE_EXECUTION_KEY_B64")
        if not isinstance(encoded, str):
            raise LiveGatewayAuthorityError("live_acp_credential_missing")
        try:
            key = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise LiveGatewayAuthorityError("live_execution_receipt_key_invalid") from None
        if len(key) != 32 or base64.b64encode(key).decode("ascii") != encoded:
            raise LiveGatewayAuthorityError("live_execution_receipt_key_invalid")
        return key

    @classmethod
    def _for_testing(
        cls,
        *,
        server: ProtectedModelGatewayServer,
        workers: tuple[tuple[int, int], tuple[int, int]],
        isolation: object,
        execution_key: bytes = b"E" * 32,
    ) -> ProtectedLiveGatewayRunner:
        return cls._construct(
            server=server,
            workers=workers,
            isolation=isolation,
            execution_key=execution_key,
        )

    @classmethod
    def _construct(
        cls,
        *,
        server: ProtectedModelGatewayServer,
        workers: tuple[tuple[int, int], tuple[int, int]],
        isolation: object,
        execution_key: bytes,
    ) -> ProtectedLiveGatewayRunner:
        if (
            not isinstance(server, ProtectedModelGatewayServer)
            or not isinstance(workers, tuple)
            or len(workers) != 2
            or workers[0][0] == workers[1][0]
            or not callable(getattr(isolation, "begin", None))
            or not isinstance(execution_key, bytes)
            or len(execution_key) != 32
        ):
            raise LiveGatewayAuthorityError("live_gateway_runner_configuration_invalid")
        value = object.__new__(cls)
        value._server = server
        value._workers = workers
        value._isolation = isolation
        value._execution_key = execution_key
        return value

    @property
    def gateway_server(self) -> ProtectedModelGatewayServer:
        return self._server

    @staticmethod
    def environment_digest(endpoint: str) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "gateway_endpoint": endpoint,
                    "language": "C.UTF-8",
                    "path": os.defpath,
                    "profile": "credential-free-live-worker-v1",
                    "worker_isolation": "systemd-delegated-cgroup-v2-v1",
                    "schema_version": 1,
                }
            )
        ).hexdigest()

    @staticmethod
    def _git(checkout: Path, *arguments: str) -> str:
        try:
            result = subprocess.run(
                ("git", "-C", os.fspath(checkout), *arguments),
                check=False,
                capture_output=True,
                env={"LANG": "C", "LC_ALL": "C", "PATH": os.defpath},
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise LiveGatewayAuthorityError("live_worker_checkout_invalid") from error
        if result.returncode != 0 or result.stderr:
            raise LiveGatewayAuthorityError("live_worker_checkout_invalid")
        return result.stdout.strip()

    @staticmethod
    def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
        if os.name == "posix":
            with suppress(ProcessLookupError, PermissionError):
                os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:  # pragma: no cover - protected service is POSIX
            process.kill()
        if process.poll() is None:
            with suppress(subprocess.TimeoutExpired):
                process.wait(timeout=2)

    @classmethod
    def _observe_checkout(
        cls,
        *,
        checkout: Path,
        executable: Path,
        expected_commit: str,
        expected_tree: str,
    ) -> _PinnedCheckout:
        if (
            not isinstance(checkout, Path)
            or not checkout.is_absolute()
            or checkout.is_symlink()
            or not checkout.is_dir()
            or not isinstance(executable, Path)
            or not executable.is_absolute()
        ):
            raise LiveGatewayAuthorityError("live_worker_checkout_invalid")
        descriptor = -1
        try:
            executable.relative_to(checkout)
            root = checkout.stat()
            path_before = executable.lstat()
            descriptor = os.open(
                executable,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            before = os.fstat(descriptor)
        except (OSError, ValueError) as error:
            raise LiveGatewayAuthorityError("live_worker_checkout_invalid") from error
        try:
            invalid = (
                not stat.S_ISREG(before.st_mode)
                or stat.S_ISLNK(path_before.st_mode)
                or before.st_nlink != 1
                or (path_before.st_dev, path_before.st_ino) != (before.st_dev, before.st_ino)
                or not before.st_mode & stat.S_IXUSR
                or cls._git(checkout, "rev-parse", "--show-toplevel") != os.fspath(checkout)
                or cls._git(checkout, "rev-parse", "--verify", "HEAD^{commit}") != expected_commit
                or cls._git(checkout, "rev-parse", "--verify", "HEAD^{tree}") != expected_tree
                or cls._git(checkout, "status", "--porcelain=v1", "--untracked-files=all")
            )
        except Exception:
            os.close(descriptor)
            raise
        if invalid:
            os.close(descriptor)
            raise LiveGatewayAuthorityError("live_worker_checkout_invalid")
        try:
            digest = hashlib.sha256()
            while payload := os.read(descriptor, 65_536):
                digest.update(payload)
            os.lseek(descriptor, 0, os.SEEK_SET)
            after = os.fstat(descriptor)
            path_after = executable.lstat()
        except OSError as error:
            with suppress(OSError):
                os.close(descriptor)
            raise LiveGatewayAuthorityError("live_worker_checkout_invalid") from error
        executable_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mode,
            before.st_mtime_ns,
        )
        if executable_identity != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mode,
            after.st_mtime_ns,
        ) or (path_after.st_dev, path_after.st_ino) != (before.st_dev, before.st_ino):
            os.close(descriptor)
            raise LiveGatewayAuthorityError("live_worker_checkout_invalid")
        executable_digest = digest.hexdigest()
        checkout_digest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "commit": expected_commit,
                    "executable_digest": executable_digest,
                    "executable_identity": list(executable_identity),
                    "root_device": root.st_dev,
                    "root_inode": root.st_ino,
                    "tree": expected_tree,
                }
            )
        ).hexdigest()
        return _PinnedCheckout(
            checkout=checkout,
            executable=executable,
            descriptor=descriptor,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
            root_identity=(root.st_dev, root.st_ino),
            executable_identity=executable_identity,
            executable_digest=executable_digest,
            checkout_digest=checkout_digest,
        )

    @classmethod
    def _revalidate_checkout(cls, pinned: _PinnedCheckout) -> None:
        try:
            root = pinned.checkout.stat()
            descriptor = os.fstat(pinned.descriptor)
            path = pinned.executable.lstat()
        except OSError as error:
            raise LiveGatewayAuthorityError("live_worker_checkout_changed") from error
        if (
            (root.st_dev, root.st_ino) != pinned.root_identity
            or (
                descriptor.st_dev,
                descriptor.st_ino,
                descriptor.st_size,
                descriptor.st_mode,
                descriptor.st_mtime_ns,
            )
            != pinned.executable_identity
            or (path.st_dev, path.st_ino) != pinned.executable_identity[:2]
            or cls._git(pinned.checkout, "rev-parse", "--verify", "HEAD^{commit}")
            != pinned.expected_commit
            or cls._git(pinned.checkout, "rev-parse", "--verify", "HEAD^{tree}")
            != pinned.expected_tree
            or cls._git(pinned.checkout, "status", "--porcelain=v1", "--untracked-files=all")
        ):
            raise LiveGatewayAuthorityError("live_worker_checkout_changed")

    def execute_worker(
        self,
        *,
        identity: LiveEvaluationIdentity,
        policy: LivePairPolicy,
        task: LiveTaskIdentity,
        subject: str,
        attempt: int,
        checkout: Path,
        executable: Path,
        arguments: Sequence[str] = (),
        timeout_seconds: int,
    ) -> ProtectedLiveExecutionResult:
        if (
            subject not in {"parent", "candidate"}
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or not 1 <= timeout_seconds <= _MAX_WORKER_SECONDS
            or any(not isinstance(item, str) or "\x00" in item for item in arguments)
        ):
            raise LiveGatewayAuthorityError("live_worker_request_invalid")
        expected_commit = (
            identity.parent_commit if subject == "parent" else identity.candidate_commit
        )
        expected_tree = identity.parent_tree if subject == "parent" else identity.candidate_tree
        pinned = self._observe_checkout(
            checkout=checkout,
            executable=executable,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
        )
        worker = self._workers[0 if subject == "parent" else 1]
        execution_digest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "attempt": attempt,
                    "checkout_digest": pinned.checkout_digest,
                    "pair_request_digest": identity.request_digest,
                    "subject": subject,
                    "task_id": task.task_id,
                }
            )
        ).hexdigest()
        try:
            prepared = self._server._prepare_capability(
                identity=identity,
                task=task,
                subject=subject,
                attempt=attempt,
            )
            if identity.environment_digest != self.environment_digest(prepared.endpoint):
                raise LiveGatewayAuthorityError("live_execution_binding_mismatch")
            isolation_scope = self._isolation.begin(execution_digest)
        except LiveWorkerIsolationError as error:
            os.close(pinned.descriptor)
            raise LiveGatewayAuthorityError(error.code) from error
        except Exception:
            os.close(pinned.descriptor)
            raise

        def demote() -> None:
            os.umask(0o077)
            if os.geteuid() == 0:
                os.setgroups([])
                os.setgid(worker[1])
                os.setuid(worker[0])
            elif worker != (os.geteuid(), os.getegid()):
                os._exit(126)

        read_descriptor = -1
        write_descriptor = -1
        process: subprocess.Popen[bytes] | None = None
        capability_issued = False
        execution_invalidated = False
        cleanup_attempted = False

        def invalidate_execution(code: str) -> None:
            nonlocal execution_invalidated
            if capability_issued and not execution_invalidated:
                self._server.invalidate_execution(prepared.token, code)
                execution_invalidated = True

        try:
            read_descriptor, write_descriptor = os.pipe()
            os.set_inheritable(read_descriptor, True)
            environment = {
                **prepared.subject_environment(),
                "CARL_PINNED_EXECUTABLE_FD": str(pinned.descriptor),
                "CARL_WORKER_BARRIER_FD": str(read_descriptor),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": os.defpath,
            }
            os.set_inheritable(pinned.descriptor, True)
            process = subprocess.Popen(
                (
                    sys.executable,
                    os.fspath(Path(__file__).with_name("live_gateway_worker.py")),
                    os.fspath(executable),
                    *arguments,
                ),
                cwd=checkout,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=(read_descriptor, pinned.descriptor),
                start_new_session=True,
                preexec_fn=demote,
            )
            os.close(read_descriptor)
            read_descriptor = -1
            try:
                observed_identity = isolation_scope.attach_and_observe(
                    process.pid,
                    expected_uid=worker[0],
                    expected_gid=worker[1],
                )
            except LiveWorkerIsolationError as error:
                raise LiveGatewayAuthorityError(error.code) from error
            if observed_identity != worker:
                raise LiveGatewayAuthorityError("live_worker_identity_mismatch")
            self._revalidate_checkout(pinned)
            actual = self._server._expected_actual(
                identity=identity,
                policy=policy,
                task=task,
                subject=subject,
                attempt=attempt,
                process_id=process.pid,
                worker_uid=worker[0],
                worker_gid=worker[1],
                executable_digest=pinned.executable_digest,
                checkout_digest=pinned.checkout_digest,
                isolation_digest=isolation_scope.attestation_digest,
            )
            observation = ProtectedExecutionObservation._mint(
                identity=identity,
                policy=policy,
                task=task,
                actual=actual,
            )
            self._server._issue_observed_capability(
                identity=observation.identity,
                policy=observation.policy,
                task=observation.task,
                actual=observation.actual,
                prepared=prepared,
            )
            capability_issued = True
            os.write(write_descriptor, b"1")
            os.close(write_descriptor)
            write_descriptor = -1
            try:
                return_code = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired as error:
                self._terminate_process_tree(process)
                self._server.record_infrastructure_invalid(prepared.token, "runner_timeout")
                execution_invalidated = True
                raise LiveGatewayAuthorityError("live_worker_timeout") from error
            if return_code != 0:
                self._server.record_infrastructure_invalid(prepared.token, "runner_exit_nonzero")
                execution_invalidated = True
                raise LiveGatewayAuthorityError("live_worker_exit_nonzero")
            try:
                self._revalidate_checkout(pinned)
            except LiveGatewayAuthorityError:
                invalidate_execution("runner_execution_changed")
                raise
            cleanup_attempted = True
            try:
                isolation_scope.cleanup_and_verify_empty()
            except LiveWorkerIsolationError as error:
                invalidate_execution("runner_isolation_cleanup_failed")
                raise LiveGatewayAuthorityError(error.code) from error
            model_result = self._server.take_completed_result(prepared)
            try:
                isolation_observation = isolation_scope.receipt_observation()
            except Exception as error:
                invalidate_execution("runner_isolation_observation_invalid")
                raise LiveGatewayAuthorityError("live_worker_isolation_state_invalid") from error
            fields = {
                "argv": (os.fspath(executable), *arguments),
                "timeout_seconds": timeout_seconds,
                "repository": identity.repository,
                "pair_request_digest": identity.request_digest,
                "subject": subject,
                "subject_commit": actual.subject_commit,
                "subject_tree": actual.subject_tree,
                "task_id": task.task_id,
                "task_digest": task.task_digest,
                "input_digest": task.input_digest,
                "input_size": task.input_size,
                "grader_digest": task.grader_digest,
                "task_role": task.role,
                "seed": actual.seed,
                "attempt": attempt,
                "environment_digest": identity.environment_digest,
                "model": identity.model,
                "reasoning_policy": identity.reasoning_policy,
                "model_policy_digest": identity.model_policy_digest,
                "live_policy_digest": actual.live_policy_digest,
                "execution_context_digest": actual.execution_context_digest,
                "process_id": actual.process_id,
                "worker_uid": actual.worker_uid,
                "worker_gid": actual.worker_gid,
                "executable_device": pinned.executable_identity[0],
                "executable_inode": pinned.executable_identity[1],
                "executable_size": pinned.executable_identity[2],
                "executable_mode": pinned.executable_identity[3],
                "executable_mtime_ns": pinned.executable_identity[4],
                "executable_digest": pinned.executable_digest,
                "checkout_device": pinned.root_identity[0],
                "checkout_inode": pinned.root_identity[1],
                "checkout_digest": pinned.checkout_digest,
                **isolation_observation,
                "model_result_digest": model_result_digest(model_result),
                "model_request_digest": model_result.request_digest,
                "model_output_digest": model_result.output_digest,
                "response_id": model_result.response_id,
            }
            return ProtectedLiveExecutionResult(
                model_result=model_result,
                execution_receipt=sign_execution_receipt(
                    fields=fields,
                    key=self._execution_key,
                ),
            )
        except OSError as error:
            if process is not None:
                self._terminate_process_tree(process)
            invalidate_execution("runner_execution_failed")
            raise LiveGatewayAuthorityError("live_worker_execution_failed") from error
        finally:
            if process is not None:
                self._terminate_process_tree(process)
            if not cleanup_attempted:
                try:
                    isolation_scope.cleanup_and_verify_empty()
                except LiveWorkerIsolationError as error:
                    invalidate_execution("runner_isolation_cleanup_failed")
                    raise LiveGatewayAuthorityError(error.code) from error
            for descriptor in (read_descriptor, write_descriptor):
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)
            with suppress(OSError):
                os.close(pinned.descriptor)
