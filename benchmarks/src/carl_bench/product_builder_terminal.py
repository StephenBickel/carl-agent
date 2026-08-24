"""Canonical non-candidate terminal assembly for repair and retained-learning outcomes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from carl_bench.product_builder import (
    BuilderError,
    BuilderTerminalResult,
    RepairRequest,
    RetainedLearning,
)

_HEX = frozenset("0123456789abcdef")


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


@dataclass(frozen=True, slots=True)
class BuilderOutcomeTerminalDocument:
    schema_version: int
    request_digest: str
    expected_revision: int
    registration_digest: str
    experiment_id: str
    parent_commit: str
    outcome: Literal["repair_request", "retained_learning"]
    attempt_receipt_digests: tuple[str, ...]
    repair_request: RepairRequest | None
    retained_learning: RetainedLearning | None
    next_safe_node: str

    def __post_init__(self) -> None:
        repair = (
            self.outcome == "repair_request"
            and type(self.repair_request) is RepairRequest
            and self.retained_learning is None
        )
        learning = (
            self.outcome == "retained_learning"
            and self.repair_request is None
            and type(self.retained_learning) is RetainedLearning
        )
        if (
            self.schema_version != 1
            or type(self.expected_revision) is not int
            or self.expected_revision < 0
            or not _digest(self.request_digest)
            or not _digest(self.registration_digest)
            or not isinstance(self.experiment_id, str)
            or not self.experiment_id
            or not isinstance(self.parent_commit, str)
            or len(self.parent_commit) not in {40, 64}
            or not set(self.parent_commit) <= _HEX
            or not self.attempt_receipt_digests
            or any(not _digest(value) for value in self.attempt_receipt_digests)
            or not isinstance(self.next_safe_node, str)
            or not self.next_safe_node
            or not (repair or learning)
        ):
            raise BuilderError("builder_terminal_document_invalid")

    @classmethod
    def create(
        cls,
        *,
        request: object,
        registration_digest: str,
        result: BuilderTerminalResult,
        attempt_receipt_digests: tuple[str, ...],
    ) -> BuilderOutcomeTerminalDocument:
        from carl_bench.product_builder_runtime import BuilderRunRequest

        if (
            type(request) is not BuilderRunRequest
            or type(result) is not BuilderTerminalResult
            or result.outcome not in {"repair_request", "retained_learning"}
            or result.experiment_id != request.manifest.experiment_id
        ):
            raise BuilderError("builder_terminal_document_invalid")
        return cls(
            schema_version=1,
            request_digest=request.digest,
            expected_revision=request.expected_revision,
            registration_digest=registration_digest,
            experiment_id=result.experiment_id,
            parent_commit=request.snapshot.exact_parent_commit,
            outcome=result.outcome,
            attempt_receipt_digests=attempt_receipt_digests,
            repair_request=result.repair_request,
            retained_learning=result.retained_learning,
            next_safe_node=result.next_safe_node,
        )

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "attempt_receipt_digests": list(self.attempt_receipt_digests),
            "expected_revision": self.expected_revision,
            "experiment_id": self.experiment_id,
            "next_safe_node": self.next_safe_node,
            "outcome": self.outcome,
            "parent_commit": self.parent_commit,
            "registration_digest": self.registration_digest,
            "repair_request": (
                None
                if self.repair_request is None
                else {
                    name: getattr(self.repair_request, name)
                    for name in self.repair_request.__dataclass_fields__
                }
            ),
            "request_digest": self.request_digest,
            "retained_learning": (
                None
                if self.retained_learning is None
                else {
                    name: getattr(self.retained_learning, name)
                    for name in self.retained_learning.__dataclass_fields__
                }
            ),
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_canonical_dict(cls, value: object) -> BuilderOutcomeTerminalDocument:
        if type(value) is not dict or set(value) != {
            "attempt_receipt_digests",
            "expected_revision",
            "experiment_id",
            "next_safe_node",
            "outcome",
            "parent_commit",
            "registration_digest",
            "repair_request",
            "request_digest",
            "retained_learning",
            "schema_version",
        }:
            raise BuilderError("builder_terminal_document_invalid")
        try:
            return cls(
                **{
                    **value,
                    "attempt_receipt_digests": tuple(value["attempt_receipt_digests"]),
                    "repair_request": (
                        None
                        if value["repair_request"] is None
                        else RepairRequest(**value["repair_request"])
                    ),
                    "retained_learning": (
                        None
                        if value["retained_learning"] is None
                        else RetainedLearning(**value["retained_learning"])
                    ),
                }
            )
        except (TypeError, ValueError) as error:
            raise BuilderError("builder_terminal_document_invalid") from error
