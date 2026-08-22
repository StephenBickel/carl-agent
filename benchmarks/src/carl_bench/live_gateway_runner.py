"""Protected owner of live subject process launch and gateway capability issuance."""

from __future__ import annotations

import hashlib
import os
import signal
import stat
import subprocess
import sys
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_capability import LiveEvaluationIdentity, LivePairPolicy, LiveTaskIdentity
from carl_bench.live_gateway_authority import (
    LiveGatewayAuthorityError,
    ProtectedExecutionObservation,
    ProtectedModelGatewayServer,
)
from carl_bench.openai_gateway import ProtectedOpenAIModelResult

_MAX_WORKER_SECONDS = 3_600


class ProtectedLiveGatewayRunner:
    """Launch exact unprivileged workers and bind their observed process to one capability."""

    __slots__ = ("_server", "_workers")

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
        if workers[0] == workers[1] or os.geteuid() in {workers[0][0], workers[1][0]}:
            raise LiveGatewayAuthorityError("live_worker_identity_invalid")
        return cls._construct(
            server=ProtectedModelGatewayServer.from_protected_process(), workers=workers
        )

    @classmethod
    def _for_testing(
        cls,
        *,
        server: ProtectedModelGatewayServer,
        workers: tuple[tuple[int, int], tuple[int, int]],
    ) -> ProtectedLiveGatewayRunner:
        return cls._construct(server=server, workers=workers)

    @classmethod
    def _construct(
        cls,
        *,
        server: ProtectedModelGatewayServer,
        workers: tuple[tuple[int, int], tuple[int, int]],
    ) -> ProtectedLiveGatewayRunner:
        if (
            not isinstance(server, ProtectedModelGatewayServer)
            or not isinstance(workers, tuple)
            or len(workers) != 2
            or workers[0] == workers[1]
        ):
            raise LiveGatewayAuthorityError("live_gateway_runner_configuration_invalid")
        value = object.__new__(cls)
        value._server = server
        value._workers = workers
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
            with suppress(ProcessLookupError):
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
    ) -> tuple[str, str]:
        if (
            not isinstance(checkout, Path)
            or not checkout.is_absolute()
            or checkout.is_symlink()
            or not checkout.is_dir()
            or not isinstance(executable, Path)
            or not executable.is_absolute()
        ):
            raise LiveGatewayAuthorityError("live_worker_checkout_invalid")
        try:
            executable.relative_to(checkout)
            before = executable.lstat()
        except (OSError, ValueError) as error:
            raise LiveGatewayAuthorityError("live_worker_checkout_invalid") from error
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or not before.st_mode & stat.S_IXUSR
            or cls._git(checkout, "rev-parse", "--show-toplevel") != os.fspath(checkout)
            or cls._git(checkout, "rev-parse", "--verify", "HEAD^{commit}") != expected_commit
            or cls._git(checkout, "rev-parse", "--verify", "HEAD^{tree}") != expected_tree
            or cls._git(checkout, "status", "--porcelain=v1", "--untracked-files=all")
        ):
            raise LiveGatewayAuthorityError("live_worker_checkout_invalid")
        try:
            payload = executable.read_bytes()
            after = executable.lstat()
        except OSError as error:
            raise LiveGatewayAuthorityError("live_worker_checkout_invalid") from error
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise LiveGatewayAuthorityError("live_worker_checkout_invalid")
        executable_digest = hashlib.sha256(payload).hexdigest()
        checkout_digest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "commit": expected_commit,
                    "executable_digest": executable_digest,
                    "root_device": checkout.stat().st_dev,
                    "root_inode": checkout.stat().st_ino,
                    "tree": expected_tree,
                }
            )
        ).hexdigest()
        return executable_digest, checkout_digest

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
    ) -> ProtectedOpenAIModelResult:
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
        executable_digest, checkout_digest = self._observe_checkout(
            checkout=checkout,
            executable=executable,
            expected_commit=expected_commit,
            expected_tree=expected_tree,
        )
        worker = self._workers[0 if subject == "parent" else 1]
        prepared = self._server._prepare_capability(
            identity=identity,
            task=task,
            subject=subject,
            attempt=attempt,
        )
        if identity.environment_digest != self.environment_digest(prepared.endpoint):
            raise LiveGatewayAuthorityError("live_execution_binding_mismatch")
        read_descriptor, write_descriptor = os.pipe()
        os.set_inheritable(read_descriptor, True)

        def demote() -> None:
            os.umask(0o077)
            if os.geteuid() == 0:
                os.setgroups([])
                os.setgid(worker[1])
                os.setuid(worker[0])
            elif worker != (os.geteuid(), os.getegid()):
                os._exit(126)

        environment = {
            **prepared.subject_environment(),
            "CARL_WORKER_BARRIER_FD": str(read_descriptor),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": os.defpath,
        }
        process: subprocess.Popen[bytes] | None = None
        try:
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
                pass_fds=(read_descriptor,),
                start_new_session=True,
                preexec_fn=demote,
            )
            os.close(read_descriptor)
            read_descriptor = -1
            actual = self._server._expected_actual(
                identity=identity,
                policy=policy,
                task=task,
                subject=subject,
                attempt=attempt,
                process_id=process.pid,
                worker_uid=worker[0],
                worker_gid=worker[1],
                executable_digest=executable_digest,
                checkout_digest=checkout_digest,
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
            os.write(write_descriptor, b"1")
            os.close(write_descriptor)
            write_descriptor = -1
            try:
                return_code = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired as error:
                self._terminate_process_tree(process)
                self._server.record_infrastructure_invalid(prepared.token, "runner_timeout")
                raise LiveGatewayAuthorityError("live_worker_timeout") from error
            if return_code != 0:
                self._server.record_infrastructure_invalid(prepared.token, "runner_exit_nonzero")
                raise LiveGatewayAuthorityError("live_worker_exit_nonzero")
            return self._server.take_completed_result(prepared)
        except OSError as error:
            if process is not None:
                self._terminate_process_tree(process)
            raise LiveGatewayAuthorityError("live_worker_execution_failed") from error
        finally:
            if process is not None:
                self._terminate_process_tree(process)
            for descriptor in (read_descriptor, write_descriptor):
                if descriptor >= 0:
                    with suppress(OSError):
                        os.close(descriptor)
