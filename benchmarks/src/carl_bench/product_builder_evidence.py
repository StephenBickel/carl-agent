"""Protected canonical attempt receipts and receipt-sealed candidate packets."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from itertools import pairwise

from carl_bench.candidate import SealedCandidate
from carl_bench.canonical import canonical_json_bytes
from carl_bench.openai_gateway import OpenAIModelRequest, OpenAIModelResult
from carl_bench.product_builder import BuildAttemptEvidence, BuilderPreregistration

_HEX = frozenset("0123456789abcdef")


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or not set(value) <= _HEX:
        raise ValueError(code)
    return value


def _commit(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) not in {40, 64} or not set(value) <= _HEX:
        raise ValueError(code)
    return value


@dataclass(frozen=True, slots=True)
class ProtectedAttemptReceipt:
    schema_version: int
    builder_request_digest: str
    registration_digest: str
    action_digest: str
    parent_commit: str
    prepatch_tree: str
    test_command: tuple[str, ...]
    test_command_digest: str
    test_output_artifact_digest: str
    diff_artifact_digest: str
    failing_test_id: str
    red_exit_code: int
    red_observed_at: str
    patch_applied_at: str
    patch_digest: str
    postpatch_tree: str
    model_request_digest: str
    model_output_digest: str
    gateway_usage: dict[str, int]
    gateway_usage_digest: str
    gateway_cost_receipt_digest: str
    trusted_cost_microdollars: int
    changed_paths: tuple[str, ...]
    tools: tuple[str, ...]
    attempt: int
    patch_bytes: int
    elapsed_seconds: int
    finding_digest: str | None

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("builder_attempt_receipt_invalid")
        for value, code in (
            (self.builder_request_digest, "builder_attempt_request_invalid"),
            (self.registration_digest, "builder_attempt_registration_invalid"),
            (self.action_digest, "builder_attempt_action_invalid"),
            (self.test_command_digest, "builder_attempt_test_command_invalid"),
            (self.test_output_artifact_digest, "builder_attempt_test_output_invalid"),
            (self.diff_artifact_digest, "builder_attempt_diff_artifact_invalid"),
            (self.patch_digest, "builder_attempt_patch_invalid"),
            (self.model_request_digest, "builder_attempt_model_request_invalid"),
            (self.model_output_digest, "builder_attempt_model_output_invalid"),
            (self.gateway_usage_digest, "builder_attempt_gateway_usage_invalid"),
            (self.gateway_cost_receipt_digest, "builder_attempt_gateway_cost_invalid"),
        ):
            _digest(value, code)
        _commit(self.parent_commit, "builder_attempt_parent_invalid")
        _commit(self.prepatch_tree, "builder_attempt_prepatch_tree_invalid")
        _commit(self.postpatch_tree, "builder_attempt_postpatch_tree_invalid")
        if self.prepatch_tree == self.postpatch_tree:
            raise ValueError("builder_attempt_patch_unchanged")
        if (
            not isinstance(self.test_command, tuple)
            or not self.test_command
            or any(
                not isinstance(item, str) or not item or "\x00" in item
                for item in self.test_command
            )
            or hashlib.sha256(canonical_json_bytes(list(self.test_command))).hexdigest()
            != self.test_command_digest
        ):
            raise ValueError("builder_attempt_test_command_invalid")
        if (
            isinstance(self.red_exit_code, bool)
            or not isinstance(self.red_exit_code, int)
            or not 1 <= self.red_exit_code <= 255
            or not isinstance(self.gateway_usage, dict)
            or set(self.gateway_usage)
            != {
                "cached_input_tokens",
                "input_tokens",
                "output_tokens",
                "reasoning_output_tokens",
                "total_tokens",
            }
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in self.gateway_usage.values()
            )
            or hashlib.sha256(canonical_json_bytes(self.gateway_usage)).hexdigest()
            != self.gateway_usage_digest
            or isinstance(self.trusted_cost_microdollars, bool)
            or not isinstance(self.trusted_cost_microdollars, int)
            or self.trusted_cost_microdollars < 0
            or not isinstance(self.changed_paths, tuple)
            or not self.changed_paths
            or self.changed_paths != tuple(sorted(set(self.changed_paths), key=str.encode))
            or not isinstance(self.tools, tuple)
            or not self.tools
            or self.tools != tuple(sorted(set(self.tools), key=str.encode))
            or not isinstance(self.failing_test_id, str)
            or not self.failing_test_id
            or not isinstance(self.red_observed_at, str)
            or not isinstance(self.patch_applied_at, str)
            or isinstance(self.attempt, bool)
            or not 1 <= self.attempt <= 3
            or isinstance(self.patch_bytes, bool)
            or self.patch_bytes <= 0
            or isinstance(self.elapsed_seconds, bool)
            or self.elapsed_seconds < 0
        ):
            raise ValueError("builder_attempt_receipt_invalid")
        if self.finding_digest is not None:
            _digest(self.finding_digest, "builder_attempt_finding_invalid")

    @classmethod
    def from_observation(
        cls,
        *,
        registration: BuilderPreregistration,
        builder_request_digest: str,
        attempt: BuildAttemptEvidence,
        exact_parent: str,
        prepatch_tree: str,
        test_command: tuple[str, ...],
        test_output_artifact_digest: str,
        diff_artifact_digest: str,
        postpatch_tree: str,
        model_request: OpenAIModelRequest,
        model_result: OpenAIModelResult,
        gateway_cost_receipt: object,
    ) -> ProtectedAttemptReceipt:
        if (
            type(registration) is not BuilderPreregistration
            or type(attempt) is not BuildAttemptEvidence
            or type(model_request) is not OpenAIModelRequest
            or not isinstance(model_result, OpenAIModelResult)
            or exact_parent != registration.parent_commit
            or model_request.execution_context_digest != registration.digest
            or model_request.request_digest != model_result.request_digest
            or model_request.attempt != attempt.attempt
            or test_output_artifact_digest != attempt.red_output_digest
            or diff_artifact_digest != attempt.patch_digest
        ):
            raise ValueError("builder_attempt_observation_mismatch")
        _digest(builder_request_digest, "builder_attempt_request_invalid")
        from carl_bench.product_builder_gateway import ProtectedGatewayCostReceipt

        if (
            type(gateway_cost_receipt) is not ProtectedGatewayCostReceipt
            or gateway_cost_receipt.model_request_digest != model_request.request_digest
            or gateway_cost_receipt.model_output_digest != model_result.output_digest
            or gateway_cost_receipt.cost_microdollars != attempt.cost_microdollars
        ):
            raise ValueError("builder_attempt_observation_mismatch")
        usage = {
            "cached_input_tokens": model_result.usage.cached_input_tokens,
            "input_tokens": model_result.usage.input_tokens,
            "output_tokens": model_result.usage.output_tokens,
            "reasoning_output_tokens": model_result.usage.reasoning_output_tokens,
            "total_tokens": model_result.usage.total_tokens,
        }
        return cls(
            schema_version=1,
            builder_request_digest=builder_request_digest,
            registration_digest=registration.digest,
            action_digest=attempt.action_digest,
            parent_commit=exact_parent,
            prepatch_tree=prepatch_tree,
            test_command=test_command,
            test_command_digest=hashlib.sha256(
                canonical_json_bytes(list(test_command))
            ).hexdigest(),
            test_output_artifact_digest=test_output_artifact_digest,
            diff_artifact_digest=diff_artifact_digest,
            failing_test_id=attempt.failing_test_id,
            red_exit_code=attempt.red_exit_code,
            red_observed_at=attempt.red_observed_at,
            patch_applied_at=attempt.patch_applied_at,
            patch_digest=attempt.patch_digest,
            postpatch_tree=postpatch_tree,
            model_request_digest=model_request.request_digest,
            model_output_digest=model_result.output_digest,
            gateway_usage=usage,
            gateway_usage_digest=hashlib.sha256(canonical_json_bytes(usage)).hexdigest(),
            gateway_cost_receipt_digest=gateway_cost_receipt.digest,
            trusted_cost_microdollars=gateway_cost_receipt.cost_microdollars,
            changed_paths=attempt.changed_paths,
            tools=attempt.tools,
            attempt=attempt.attempt,
            patch_bytes=attempt.patch_bytes,
            elapsed_seconds=attempt.elapsed_seconds,
            finding_digest=attempt.finding_digest,
        )

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "action_digest": self.action_digest,
            "attempt": self.attempt,
            "builder_request_digest": self.builder_request_digest,
            "changed_paths": list(self.changed_paths),
            "elapsed_seconds": self.elapsed_seconds,
            "diff_artifact_digest": self.diff_artifact_digest,
            "finding_digest": self.finding_digest,
            "failing_test_id": self.failing_test_id,
            "gateway_usage": self.gateway_usage,
            "gateway_usage_digest": self.gateway_usage_digest,
            "gateway_cost_receipt_digest": self.gateway_cost_receipt_digest,
            "model_output_digest": self.model_output_digest,
            "model_request_digest": self.model_request_digest,
            "parent_commit": self.parent_commit,
            "patch_bytes": self.patch_bytes,
            "patch_applied_at": self.patch_applied_at,
            "patch_digest": self.patch_digest,
            "postpatch_tree": self.postpatch_tree,
            "prepatch_tree": self.prepatch_tree,
            "red_exit_code": self.red_exit_code,
            "red_observed_at": self.red_observed_at,
            "registration_digest": self.registration_digest,
            "schema_version": self.schema_version,
            "test_command": list(self.test_command),
            "test_command_digest": self.test_command_digest,
            "test_output_artifact_digest": self.test_output_artifact_digest,
            "tools": list(self.tools),
            "trusted_cost_microdollars": self.trusted_cost_microdollars,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()

    @classmethod
    def from_canonical_dict(cls, value: object) -> ProtectedAttemptReceipt:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("builder_attempt_receipt_invalid")
        normalized = dict(value)
        normalized["test_command"] = tuple(normalized["test_command"])
        normalized["changed_paths"] = tuple(normalized["changed_paths"])
        normalized["tools"] = tuple(normalized["tools"])
        try:
            return cls(**normalized)
        except (TypeError, ValueError) as error:
            raise ValueError("builder_attempt_receipt_invalid") from error

    def to_attempt_evidence(self) -> BuildAttemptEvidence:
        return BuildAttemptEvidence(
            schema_version=1,
            attempt=self.attempt,
            action_digest=self.action_digest,
            patch_digest=self.patch_digest,
            failing_test_id=self.failing_test_id,
            red_exit_code=self.red_exit_code,
            red_output_digest=self.test_output_artifact_digest,
            red_observed_at=self.red_observed_at,
            patch_applied_at=self.patch_applied_at,
            changed_paths=self.changed_paths,
            tools=self.tools,
            patch_bytes=self.patch_bytes,
            elapsed_seconds=self.elapsed_seconds,
            cost_microdollars=self.trusted_cost_microdollars,
            finding_digest=self.finding_digest,
        )


@dataclass(frozen=True, slots=True)
class SignedAttemptReceipt:
    schema_version: int
    receipt: ProtectedAttemptReceipt
    authentication_tag: str

    @classmethod
    def sign(cls, receipt: ProtectedAttemptReceipt, key: bytes) -> SignedAttemptReceipt:
        if (
            type(receipt) is not ProtectedAttemptReceipt
            or not isinstance(key, bytes)
            or len(key) != 32
        ):
            raise ValueError("builder_attempt_receipt_signing_invalid")
        tag = hmac.new(
            key, canonical_json_bytes(receipt.to_canonical_dict()), hashlib.sha256
        ).hexdigest()
        return cls(1, receipt, tag)

    def verify(self, key: bytes) -> ProtectedAttemptReceipt:
        if (
            self.schema_version != 1
            or type(self.receipt) is not ProtectedAttemptReceipt
            or not isinstance(key, bytes)
            or len(key) != 32
        ):
            raise ValueError("builder_attempt_receipt_signature_invalid")
        expected = hmac.new(
            key,
            canonical_json_bytes(self.receipt.to_canonical_dict()),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(self.authentication_tag, expected):
            raise ValueError("builder_attempt_receipt_signature_invalid")
        return self.receipt

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "authentication_tag": self.authentication_tag,
            "receipt": self.receipt.to_canonical_dict(),
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_canonical_dict(cls, value: object) -> SignedAttemptReceipt:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("builder_attempt_receipt_invalid")
        try:
            return cls(
                schema_version=value["schema_version"],
                receipt=ProtectedAttemptReceipt.from_canonical_dict(value["receipt"]),
                authentication_tag=value["authentication_tag"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("builder_attempt_receipt_invalid") from error


@dataclass(frozen=True, slots=True)
class ProtectedCandidatePacket:
    schema_version: int
    builder_request_digest: str
    registration_digest: str
    parent_commit: str
    candidate_tree: str
    diff_artifact_digest: str
    candidate: SealedCandidate
    attempt_receipts: tuple[SignedAttemptReceipt, ...]

    def __post_init__(self) -> None:
        if (
            self.schema_version != 1
            or not _digest(self.builder_request_digest, "builder_candidate_receipt_mismatch")
            or not _digest(self.registration_digest, "builder_candidate_receipt_mismatch")
            or not _commit(self.parent_commit, "builder_candidate_receipt_mismatch")
            or not _commit(self.candidate_tree, "builder_candidate_receipt_mismatch")
            or not _digest(self.diff_artifact_digest, "builder_candidate_receipt_mismatch")
            or type(self.candidate) is not SealedCandidate
            or not isinstance(self.attempt_receipts, tuple)
            or not self.attempt_receipts
            or any(type(item) is not SignedAttemptReceipt for item in self.attempt_receipts)
        ):
            raise ValueError("builder_candidate_receipt_mismatch")

    @property
    def attempt_receipt_digests(self) -> tuple[str, ...]:
        return tuple(item.receipt.digest for item in self.attempt_receipts)

    def verify(self, key: bytes) -> ProtectedCandidatePacket:
        receipts = tuple(item.verify(key) for item in self.attempt_receipts)
        paths = {path for receipt in receipts for path in receipt.changed_paths}
        if (
            self.candidate.parent_commit != self.parent_commit
            or any(receipt.registration_digest != self.registration_digest for receipt in receipts)
            or receipts[-1].builder_request_digest != self.builder_request_digest
            or len({receipt.builder_request_digest for receipt in receipts}) != len(receipts)
            or any(receipt.parent_commit != self.parent_commit for receipt in receipts)
            or tuple(receipt.attempt for receipt in receipts) != tuple(range(1, len(receipts) + 1))
            or any(
                earlier.postpatch_tree != later.prepatch_tree
                for earlier, later in pairwise(receipts)
            )
            or receipts[-1].postpatch_tree != self.candidate_tree
            or receipts[-1].diff_artifact_digest != self.diff_artifact_digest
            or self.candidate.changed_path_count != len(paths)
        ):
            raise ValueError("builder_candidate_receipt_mismatch")
        return self

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "attempt_receipt_digests": list(self.attempt_receipt_digests),
            "attempt_receipts": [item.to_canonical_dict() for item in self.attempt_receipts],
            "builder_request_digest": self.builder_request_digest,
            "candidate": self.candidate.to_canonical_dict(),
            "candidate_tree": self.candidate_tree,
            "diff_artifact_digest": self.diff_artifact_digest,
            "parent_commit": self.parent_commit,
            "registration_digest": self.registration_digest,
            "schema_version": self.schema_version,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()

    @classmethod
    def from_canonical_dict(cls, value: object) -> ProtectedCandidatePacket:
        if type(value) is not dict or set(value) != {
            "attempt_receipt_digests",
            "attempt_receipts",
            "builder_request_digest",
            "candidate",
            "candidate_tree",
            "diff_artifact_digest",
            "parent_commit",
            "registration_digest",
            "schema_version",
        }:
            raise ValueError("builder_candidate_receipt_mismatch")
        receipts = value["attempt_receipts"]
        if not isinstance(receipts, list) or not isinstance(value["attempt_receipt_digests"], list):
            raise ValueError("builder_candidate_receipt_mismatch")
        try:
            packet = cls(
                schema_version=value["schema_version"],
                builder_request_digest=value["builder_request_digest"],
                registration_digest=value["registration_digest"],
                parent_commit=value["parent_commit"],
                candidate_tree=value["candidate_tree"],
                diff_artifact_digest=value["diff_artifact_digest"],
                candidate=SealedCandidate.from_canonical_dict(value["candidate"]),
                attempt_receipts=tuple(
                    SignedAttemptReceipt.from_canonical_dict(item) for item in receipts
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("builder_candidate_receipt_mismatch") from error
        if list(packet.attempt_receipt_digests) != value["attempt_receipt_digests"]:
            raise ValueError("builder_candidate_receipt_mismatch")
        return packet
