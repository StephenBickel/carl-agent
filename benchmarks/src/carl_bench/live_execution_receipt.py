"""Signed binding between a protected worker execution and its model result."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from carl_bench.canonical import canonical_json_bytes
from carl_bench.openai_gateway import ProtectedOpenAIModelResult
from carl_bench.run_attestation import attest_bound_payload, verify_bound_payload_attestation

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OBJECT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:-]{0,255}$")
_PURPOSE = "protected-live-execution-receipt"


class LiveExecutionReceiptError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def model_result_digest(result: ProtectedOpenAIModelResult) -> str:
    if type(result) is not ProtectedOpenAIModelResult:
        raise LiveExecutionReceiptError("live_execution_result_invalid")
    usage = result.usage
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "latency_ms": result.latency_ms,
                "model": result.model,
                "output_digest": result.output_digest,
                "provenance_tag": result.provenance_tag,
                "request_digest": result.request_digest,
                "response_id": result.response_id,
                "status": result.status,
                "usage": {name: getattr(usage, name) for name in usage.__dataclass_fields__},
            }
        )
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ProtectedExecutionReceipt:
    schema_version: int
    argv: tuple[str, ...]
    timeout_seconds: int
    repository: str
    pair_request_digest: str
    subject: str
    subject_commit: str
    subject_tree: str
    task_id: str
    task_digest: str
    input_digest: str
    input_size: int
    grader_digest: str
    task_role: str
    seed: int
    attempt: int
    environment_digest: str
    model: str
    reasoning_policy: str
    model_policy_digest: str
    live_policy_digest: str
    execution_context_digest: str
    process_id: int
    worker_uid: int
    worker_gid: int
    executable_device: int
    executable_inode: int
    executable_size: int
    executable_mode: int
    executable_mtime_ns: int
    executable_digest: str
    checkout_device: int
    checkout_inode: int
    checkout_digest: str
    cgroup_unit: str
    cgroup_path: str
    cgroup_observation_digest: str
    model_result_digest: str
    model_request_digest: str
    model_output_digest: str
    response_id: str
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        integer_fields = (
            self.timeout_seconds,
            self.input_size,
            self.seed,
            self.attempt,
            self.process_id,
            self.worker_uid,
            self.worker_gid,
            self.executable_device,
            self.executable_inode,
            self.executable_size,
            self.executable_mode,
            self.executable_mtime_ns,
            self.checkout_device,
            self.checkout_inode,
        )
        digest_fields = (
            self.pair_request_digest,
            self.task_digest,
            self.input_digest,
            self.grader_digest,
            self.environment_digest,
            self.model_policy_digest,
            self.live_policy_digest,
            self.execution_context_digest,
            self.executable_digest,
            self.checkout_digest,
            self.cgroup_observation_digest,
            self.model_result_digest,
            self.model_request_digest,
            self.model_output_digest,
        )
        if (
            self.schema_version != 1
            or type(self.schema_version) is not int
            or not self.argv
            or any(not isinstance(item, str) or "\x00" in item for item in self.argv)
            or any(type(item) is not int or item < 0 for item in integer_fields)
            or not 1 <= self.timeout_seconds <= 3_600
            or not 1 <= self.input_size <= 65_536
            or not 1 <= self.attempt <= 3
            or self.process_id <= 0
            or self.worker_uid <= 0
            or self.worker_gid <= 0
            or self.executable_inode <= 0
            or self.executable_size <= 0
            or self.checkout_inode <= 0
            or self.subject not in {"parent", "candidate"}
            or self.task_role not in {"affected", "guard", "held_out"}
            or _OBJECT.fullmatch(self.subject_commit) is None
            or _OBJECT.fullmatch(self.subject_tree) is None
            or any(_DIGEST.fullmatch(item) is None for item in digest_fields)
            or any(
                not isinstance(item, str) or _ID.fullmatch(item) is None
                for item in (
                    self.repository,
                    self.task_id,
                    self.model,
                    self.reasoning_policy,
                    self.cgroup_unit,
                    self.response_id,
                    self.key_id,
                    self.signature,
                )
            )
            or not isinstance(self.cgroup_path, str)
            or not self.cgroup_path.startswith("/system.slice/")
            or ".." in self.cgroup_path.split("/")
        ):
            raise LiveExecutionReceiptError("live_execution_receipt_invalid")

    def unsigned_canonical_dict(self) -> dict[str, Any]:
        return {
            name: (list(value) if name == "argv" else value)
            for name, value in (
                (field, getattr(self, field)) for field in self.__dataclass_fields__
            )
            if name not in {"key_id", "signature"}
        }

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            **self.unsigned_canonical_dict(),
            "key_id": self.key_id,
            "signature": self.signature,
        }

    @classmethod
    def from_canonical_dict(cls, value: object) -> ProtectedExecutionReceipt:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise LiveExecutionReceiptError("live_execution_receipt_invalid")
        fields = dict(value)
        if type(fields.get("argv")) is not list:
            raise LiveExecutionReceiptError("live_execution_receipt_invalid")
        fields["argv"] = tuple(fields["argv"])
        try:
            return cls(**fields)
        except (TypeError, ValueError) as error:
            raise LiveExecutionReceiptError("live_execution_receipt_invalid") from error


@dataclass(frozen=True, slots=True)
class ProtectedLiveExecutionResult:
    model_result: ProtectedOpenAIModelResult
    execution_receipt: ProtectedExecutionReceipt

    def __post_init__(self) -> None:
        if type(self.model_result) is not ProtectedOpenAIModelResult or not isinstance(
            self.execution_receipt, ProtectedExecutionReceipt
        ):
            raise LiveExecutionReceiptError("live_execution_result_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        result = self.model_result
        return {
            "execution_receipt": self.execution_receipt.to_canonical_dict(),
            "model_result": {
                "latency_ms": result.latency_ms,
                "model": result.model,
                "output_digest": result.output_digest,
                "output_text": result.output_text,
                "provenance_tag": result.provenance_tag,
                "request_digest": result.request_digest,
                "response_id": result.response_id,
                "schema_version": 1,
                "status": result.status,
                "usage": {
                    name: getattr(result.usage, name) for name in result.usage.__dataclass_fields__
                },
            },
            "schema_version": 1,
        }

    @classmethod
    def from_canonical_dict(cls, value: object) -> ProtectedLiveExecutionResult:
        if (
            type(value) is not dict
            or set(value)
            != {
                "execution_receipt",
                "model_result",
                "schema_version",
            }
            or value["schema_version"] != 1
        ):
            raise LiveExecutionReceiptError("live_execution_result_invalid")
        result = value["model_result"]
        if (
            type(result) is not dict
            or set(result)
            != {
                "latency_ms",
                "model",
                "output_digest",
                "output_text",
                "provenance_tag",
                "request_digest",
                "response_id",
                "schema_version",
                "status",
                "usage",
            }
            or result["schema_version"] != 1
            or type(result["usage"]) is not dict
        ):
            raise LiveExecutionReceiptError("live_execution_result_invalid")
        try:
            from carl_bench.openai_gateway import OpenAIUsage

            model_result = ProtectedOpenAIModelResult(
                **{
                    name: item
                    for name, item in result.items()
                    if name != "schema_version" and name != "usage"
                },
                usage=OpenAIUsage(**result["usage"]),
            )
            receipt = ProtectedExecutionReceipt.from_canonical_dict(value["execution_receipt"])
            return cls(model_result, receipt)
        except (TypeError, ValueError) as error:
            raise LiveExecutionReceiptError("live_execution_result_invalid") from error


def sign_execution_receipt(*, fields: dict[str, Any], key: bytes) -> ProtectedExecutionReceipt:
    unsigned = dict(fields)
    unsigned["schema_version"] = 1
    try:
        candidate = ProtectedExecutionReceipt(
            **unsigned,
            key_id="pending",
            signature="pending",
        )
        key_id, signature = attest_bound_payload(
            canonical_json_bytes(candidate.unsigned_canonical_dict()),
            purpose=_PURPOSE,
            key=key,
        )
        return ProtectedExecutionReceipt(**unsigned, key_id=key_id, signature=signature)
    except (TypeError, ValueError) as error:
        if isinstance(error, LiveExecutionReceiptError):
            raise
        raise LiveExecutionReceiptError("live_execution_receipt_invalid") from error


def verify_execution_receipt(receipt: object, *, key: bytes) -> bool:
    return isinstance(receipt, ProtectedExecutionReceipt) and verify_bound_payload_attestation(
        canonical_json_bytes(receipt.unsigned_canonical_dict()),
        purpose=_PURPOSE,
        key=key,
        expected_key_id=receipt.key_id,
        signature=receipt.signature,
    )
