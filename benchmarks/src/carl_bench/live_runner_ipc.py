"""Canonical one-command protocol for the protected live worker runner."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_capability import LiveEvaluationIdentity, LivePairPolicy, LiveTaskIdentity

MAX_FRAME_BYTES = 1_048_576
_ERROR_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")


class LiveRunnerProtocolError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _strict_document(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_FRAME_BYTES:
        raise LiveRunnerProtocolError("live_runner_frame_invalid")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    try:
        value = json.loads(payload, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise LiveRunnerProtocolError("live_runner_frame_invalid") from error
    if type(value) is not dict or canonical_json_bytes(value) != payload:
        raise LiveRunnerProtocolError("live_runner_frame_invalid")
    return value


@dataclass(frozen=True, slots=True)
class ProtectedLiveRunnerRequest:
    schema_version: int
    identity: LiveEvaluationIdentity
    policy: LivePairPolicy
    task: LiveTaskIdentity
    subject: str
    attempt: int
    checkout: Path
    executable: Path
    arguments: tuple[str, ...]
    timeout_seconds: int

    @classmethod
    def create(
        cls,
        *,
        identity: LiveEvaluationIdentity,
        policy: LivePairPolicy,
        task: LiveTaskIdentity,
        subject: str,
        attempt: int,
        checkout: Path,
        executable: Path,
        arguments: tuple[str, ...] = (),
        timeout_seconds: int,
    ) -> ProtectedLiveRunnerRequest:
        if (
            not isinstance(identity, LiveEvaluationIdentity)
            or not isinstance(policy, LivePairPolicy)
            or not isinstance(task, LiveTaskIdentity)
            or subject not in {"parent", "candidate"}
            or type(attempt) is not int
            or not 1 <= attempt <= identity.attempts
            or not isinstance(checkout, Path)
            or not checkout.is_absolute()
            or not isinstance(executable, Path)
            or not executable.is_absolute()
            or type(arguments) is not tuple
            or any(not isinstance(item, str) or "\x00" in item for item in arguments)
            or type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 3_600
        ):
            raise LiveRunnerProtocolError("live_runner_request_invalid")
        try:
            executable.relative_to(checkout)
        except ValueError as error:
            raise LiveRunnerProtocolError("live_runner_request_invalid") from error
        return cls(
            1,
            identity,
            policy,
            task,
            subject,
            attempt,
            checkout,
            executable,
            arguments,
            timeout_seconds,
        )

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "arguments": list(self.arguments),
            "attempt": self.attempt,
            "checkout": os.fspath(self.checkout),
            "executable": os.fspath(self.executable),
            "identity": self.identity.to_canonical_dict(),
            "policy": self.policy.to_canonical_dict(),
            "schema_version": 1,
            "subject": self.subject,
            "task": self.task.to_canonical_dict(),
            "timeout_seconds": self.timeout_seconds,
        }

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_canonical_dict())

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_bytes(cls, payload: bytes) -> ProtectedLiveRunnerRequest:
        value = _strict_document(payload)
        if set(value) != {
            "arguments",
            "attempt",
            "checkout",
            "executable",
            "identity",
            "policy",
            "schema_version",
            "subject",
            "task",
            "timeout_seconds",
        } or (
            value["schema_version"] != 1
            or type(value["schema_version"]) is not int
            or type(value["arguments"]) is not list
            or type(value["identity"]) is not dict
            or type(value["policy"]) is not dict
            or type(value["task"]) is not dict
            or not isinstance(value["checkout"], str)
            or not isinstance(value["executable"], str)
        ):
            raise LiveRunnerProtocolError("live_runner_request_invalid")
        try:
            identity_fields = dict(value["identity"])
            identity_fields["task_order"] = tuple(identity_fields["task_order"])
            identity_fields["seeds"] = tuple(identity_fields["seeds"])
            result = cls.create(
                identity=LiveEvaluationIdentity.create(**identity_fields),
                policy=LivePairPolicy(**value["policy"]),
                task=LiveTaskIdentity(**value["task"]),
                subject=value["subject"],
                attempt=value["attempt"],
                checkout=Path(value["checkout"]),
                executable=Path(value["executable"]),
                arguments=tuple(value["arguments"]),
                timeout_seconds=value["timeout_seconds"],
            )
            if result.to_bytes() != payload:
                raise LiveRunnerProtocolError("live_runner_request_invalid")
            return result
        except LiveRunnerProtocolError:
            raise
        except (KeyError, TypeError, ValueError) as error:
            raise LiveRunnerProtocolError("live_runner_request_invalid") from error


def decode_response(payload: bytes, *, request_digest: str) -> dict[str, Any]:
    value = _strict_document(payload)
    if set(value) != {"error_code", "request_digest", "result", "schema_version", "status"} or (
        value["schema_version"] != 1
        or type(value["schema_version"]) is not int
        or value["request_digest"] != request_digest
        or value["status"] not in {"completed", "rejected"}
    ):
        raise LiveRunnerProtocolError("live_runner_response_invalid")
    if value["status"] == "completed":
        if value["error_code"] is not None or type(value["result"]) is not dict:
            raise LiveRunnerProtocolError("live_runner_response_invalid")
    elif (
        not isinstance(value["error_code"], str)
        or _ERROR_CODE.fullmatch(value["error_code"]) is None
        or value["result"] is not None
    ):
        raise LiveRunnerProtocolError("live_runner_response_invalid")
    return value
