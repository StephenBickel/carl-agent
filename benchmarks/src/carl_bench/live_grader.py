"""Protected digest-addressed live grader configuration."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_capability import LiveEvaluationIdentity, LiveTaskIdentity
from carl_bench.openai_gateway import ProtectedOpenAIModelResult

_GRADER_ROOT = Path("/var/lib/carl/live-graders")
_MAX_GRADER_BYTES = 1_048_576


class ProtectedLiveGraderError(ValueError):
    """Stable failure for unavailable or invalid protected grader material."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ProtectedGraderBundle:
    """Reads one protected grader bundle by its preregistered content digest."""

    __slots__ = ("_expected_uid", "_root")

    def __new__(cls, *args: object, **kwargs: object) -> ProtectedGraderBundle:
        del cls, args, kwargs
        raise ProtectedLiveGraderError("live_grader_protected_construction_required")

    @classmethod
    def from_protected_process(cls) -> ProtectedGraderBundle:
        return cls._construct(root=_GRADER_ROOT, expected_uid=os.geteuid())

    @classmethod
    def _for_testing(cls, *, root: Path, expected_uid: int) -> ProtectedGraderBundle:
        return cls._construct(root=root, expected_uid=expected_uid)

    @classmethod
    def _construct(cls, *, root: Path, expected_uid: int) -> ProtectedGraderBundle:
        if (
            not isinstance(root, Path)
            or not root.is_absolute()
            or root.is_symlink()
            or not root.is_dir()
            or isinstance(expected_uid, bool)
            or not isinstance(expected_uid, int)
            or expected_uid < 0
        ):
            raise ProtectedLiveGraderError("live_grader_configuration_invalid")
        details = root.stat()
        if details.st_uid != expected_uid or stat.S_IMODE(details.st_mode) & 0o022:
            raise ProtectedLiveGraderError("live_grader_configuration_invalid")
        value = object.__new__(cls)
        value._root = root
        value._expected_uid = expected_uid
        return value

    @staticmethod
    def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate")
            value[key] = item
        return value

    def _document(self, digest: str) -> dict[str, Any]:
        path = self._root / f"{digest}.json"
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise ProtectedLiveGraderError("live_grader_unavailable") from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != self._expected_uid
                or stat.S_IMODE(before.st_mode) & 0o022
                or not 0 < before.st_size <= _MAX_GRADER_BYTES
            ):
                raise ProtectedLiveGraderError("live_grader_invalid")
            payload = b""
            while len(payload) <= _MAX_GRADER_BYTES:
                chunk = os.read(descriptor, min(65_536, _MAX_GRADER_BYTES + 1 - len(payload)))
                if not chunk:
                    break
                payload += chunk
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (
            len(payload) != before.st_size
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or hashlib.sha256(payload).hexdigest() != digest
        ):
            raise ProtectedLiveGraderError("live_grader_invalid")
        try:
            value = json.loads(payload, object_pairs_hook=self._pairs)
        except (UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise ProtectedLiveGraderError("live_grader_invalid") from error
        if type(value) is not dict or canonical_json_bytes(value) != payload:
            raise ProtectedLiveGraderError("live_grader_invalid")
        return value

    def grade(
        self,
        *,
        identity: LiveEvaluationIdentity,
        task: LiveTaskIdentity,
        result: ProtectedOpenAIModelResult,
    ) -> int:
        if (
            not isinstance(identity, LiveEvaluationIdentity)
            or not isinstance(task, LiveTaskIdentity)
            or type(result) is not ProtectedOpenAIModelResult
            or task.grader_digest != identity.grader_digest
        ):
            raise ProtectedLiveGraderError("live_grader_binding_invalid")
        document = self._document(identity.grader_digest)
        if (
            set(document) != {"algorithm", "schema_version", "tasks"}
            or document.get("algorithm") != "exact-output-digest-score-v1"
            or document.get("schema_version") != 1
        ):
            raise ProtectedLiveGraderError("live_grader_invalid")
        raw_tasks = document["tasks"]
        if type(raw_tasks) is not dict or type(raw_tasks.get(task.task_id)) is not dict:
            raise ProtectedLiveGraderError("live_grader_binding_invalid")
        task_policy = raw_tasks[task.task_id]
        if set(task_policy) != {"input_digest", "outputs", "task_digest"} or (
            task_policy["task_digest"] != task.task_digest
            or task_policy["input_digest"] != task.input_digest
            or type(task_policy["outputs"]) is not dict
        ):
            raise ProtectedLiveGraderError("live_grader_binding_invalid")
        score = task_policy["outputs"].get(result.output_digest)
        if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 10_000:
            raise ProtectedLiveGraderError("live_grader_output_unrecognized")
        return score
