"""Durable autonomous lifecycle facts layered over legacy experiment replay."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from carl_bench.canonical import canonical_json_bytes
from carl_bench.experiment import (
    EventType,
    ExperimentEvent,
    ExperimentManifest,
    ExperimentState,
    GraphContractError,
)

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_AUTONOMY_EVENT_TYPES = frozenset(
    {
        EventType.RETRY_SCHEDULED,
        EventType.EXPERIMENTAL_PUBLISHED,
        EventType.PROTECTED_VALIDATION_RECORDED,
        EventType.PROMOTION_RECORDED,
        EventType.SOAK_OBSERVED,
        EventType.REVERT_RECORDED,
    }
)


def _text(value: Any, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise GraphContractError("invalid_autonomy_text")
    return value


def _identifier(value: Any, maximum: int = 128) -> str:
    value = _text(value, maximum)
    if not _IDENTIFIER_RE.fullmatch(value):
        raise GraphContractError("invalid_autonomy_identifier")
    return value


def _digest(value: Any) -> str:
    value = _text(value, 64)
    if not _DIGEST_RE.fullmatch(value):
        raise GraphContractError("invalid_autonomy_digest")
    return value


def _object_id(value: Any) -> str:
    value = _text(value, 64)
    if not _OBJECT_RE.fullmatch(value):
        raise GraphContractError("invalid_autonomy_object")
    return value


def _utc(value: Any) -> datetime:
    value = _text(value, 64)
    if not value.endswith("Z"):
        raise GraphContractError("invalid_autonomy_timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise GraphContractError("invalid_autonomy_timestamp") from error
    if parsed.tzinfo != UTC:
        raise GraphContractError("invalid_autonomy_timestamp")
    return parsed


@dataclass(frozen=True, slots=True)
class RetryRecord:
    failed_stage_attempt_id: str
    attempt: int
    failure_class: str
    changed_action: str
    scheduled_at: str

    def __post_init__(self) -> None:
        _identifier(self.failed_stage_attempt_id)
        if isinstance(self.attempt, bool) or not isinstance(self.attempt, int) or self.attempt < 1:
            raise GraphContractError("invalid_retry_attempt")
        _identifier(self.failure_class)
        _text(self.changed_action, 1_024)
        _utc(self.scheduled_at)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "changed_action": self.changed_action,
            "failed_stage_attempt_id": self.failed_stage_attempt_id,
            "failure_class": self.failure_class,
            "scheduled_at": self.scheduled_at,
        }


@dataclass(frozen=True, slots=True)
class ExperimentalPublication:
    branch: str
    commit: str
    tree: str
    candidate_packet_digest: str

    def __post_init__(self) -> None:
        _text(self.branch, 256)
        if not self.branch.startswith("experimental/"):
            raise GraphContractError("invalid_experimental_branch")
        _object_id(self.commit)
        _object_id(self.tree)
        _digest(self.candidate_packet_digest)

    def to_canonical_dict(self) -> dict[str, str]:
        return {
            "branch": self.branch,
            "candidate_packet_digest": self.candidate_packet_digest,
            "commit": self.commit,
            "tree": self.tree,
        }


@dataclass(frozen=True, slots=True)
class ProtectedValidation:
    candidate_commit: str
    candidate_tree: str
    receipt_digest: str

    def __post_init__(self) -> None:
        _object_id(self.candidate_commit)
        _object_id(self.candidate_tree)
        _digest(self.receipt_digest)

    def to_canonical_dict(self) -> dict[str, str]:
        return {
            "candidate_commit": self.candidate_commit,
            "candidate_tree": self.candidate_tree,
            "receipt_digest": self.receipt_digest,
        }


@dataclass(frozen=True, slots=True)
class PromotionRecord:
    merge_commit: str
    merge_tree: str
    merged_at: str

    def __post_init__(self) -> None:
        _object_id(self.merge_commit)
        _object_id(self.merge_tree)
        _utc(self.merged_at)

    def to_canonical_dict(self) -> dict[str, str]:
        return {
            "merge_commit": self.merge_commit,
            "merge_tree": self.merge_tree,
            "merged_at": self.merged_at,
        }


@dataclass(frozen=True, slots=True)
class SoakObservation:
    merge_commit: str
    observed_at: str
    healthy: bool
    evidence_digest: str

    def __post_init__(self) -> None:
        _object_id(self.merge_commit)
        _utc(self.observed_at)
        if not isinstance(self.healthy, bool):
            raise GraphContractError("invalid_soak_health")
        _digest(self.evidence_digest)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "evidence_digest": self.evidence_digest,
            "healthy": self.healthy,
            "merge_commit": self.merge_commit,
            "observed_at": self.observed_at,
        }


@dataclass(frozen=True, slots=True)
class RevertRecord:
    merge_commit: str
    hard_failure_digest: str
    restored_tree: str
    revert_pull_request_number: int
    revert_candidate_commit: str
    revert_merge_commit: str
    reverted_at: str

    def __post_init__(self) -> None:
        _object_id(self.merge_commit)
        _digest(self.hard_failure_digest)
        _object_id(self.restored_tree)
        if (
            not isinstance(self.revert_pull_request_number, int)
            or isinstance(self.revert_pull_request_number, bool)
            or self.revert_pull_request_number <= 0
        ):
            raise GraphContractError("invalid_revert_pull_request_number")
        _object_id(self.revert_candidate_commit)
        _object_id(self.revert_merge_commit)
        _utc(self.reverted_at)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "hard_failure_digest": self.hard_failure_digest,
            "merge_commit": self.merge_commit,
            "restored_tree": self.restored_tree,
            "revert_candidate_commit": self.revert_candidate_commit,
            "revert_merge_commit": self.revert_merge_commit,
            "revert_pull_request_number": self.revert_pull_request_number,
            "reverted_at": self.reverted_at,
        }


@dataclass(frozen=True, slots=True)
class AutonomyProjection:
    experiment_id: str
    manifest_digest: str
    retry: RetryRecord | None
    experimental_publication: ExperimentalPublication | None
    protected_validation: ProtectedValidation | None
    promotion: PromotionRecord | None
    soak_observations: tuple[SoakObservation, ...]
    revert: RevertRecord | None

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "experimental_publication": (
                self.experimental_publication.to_canonical_dict()
                if self.experimental_publication is not None
                else None
            ),
            "manifest_digest": self.manifest_digest,
            "promotion": self.promotion.to_canonical_dict() if self.promotion is not None else None,
            "protected_validation": (
                self.protected_validation.to_canonical_dict()
                if self.protected_validation is not None
                else None
            ),
            "retry": self.retry.to_canonical_dict() if self.retry is not None else None,
            "revert": self.revert.to_canonical_dict() if self.revert is not None else None,
            "soak_observations": [item.to_canonical_dict() for item in self.soak_observations],
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


def _payload(event: ExperimentEvent, expected: set[str], code: str) -> dict[str, Any]:
    value = event.payload
    if set(value) != expected:
        raise GraphContractError(code)
    return value


def _record(cls: type[Any], payload: dict[str, Any], code: str) -> Any:
    try:
        return cls(**payload)
    except (GraphContractError, TypeError) as error:
        raise GraphContractError(code) from error


def _accepted(event: ExperimentEvent) -> bool:
    if event.event_type is not EventType.STATE_TRANSITIONED:
        return False
    payload = event.payload
    return (
        set(payload) in ({"from_state", "to_state"}, {"_lease", "from_state", "to_state"})
        and payload.get("to_state") == ExperimentState.ACCEPTED.value
    )


def reduce_autonomy_events(
    manifest: ExperimentManifest, events: tuple[ExperimentEvent, ...]
) -> AutonomyProjection:
    """Replay lifecycle facts without changing the legacy experiment projection."""
    retries: dict[str, RetryRecord] = {}
    publication: ExperimentalPublication | None = None
    protected_validation: ProtectedValidation | None = None
    promotion: PromotionRecord | None = None
    soak_observations: list[SoakObservation] = []
    revert: RevertRecord | None = None
    seen_attempts: set[str] = set()
    registered_at = _utc(manifest.registered_at)

    for event in events:
        if event.experiment_id != manifest.experiment_id:
            raise GraphContractError("event_experiment_mismatch")
        occurred_at = _utc(event.occurred_at)
        if occurred_at < registered_at:
            raise GraphContractError("event_precedes_registration")
        if event.stage_attempt_id in seen_attempts:
            raise GraphContractError("duplicate_stage_attempt")
        seen_attempts.add(event.stage_attempt_id)

        if event.event_type is EventType.RETRY_SCHEDULED:
            payload = _payload(
                event,
                {
                    "attempt",
                    "changed_action",
                    "failed_stage_attempt_id",
                    "failure_class",
                    "scheduled_at",
                },
                "invalid_retry_payload",
            )
            retry = _record(RetryRecord, payload, "invalid_retry_payload")
            if retry.scheduled_at != event.occurred_at:
                raise GraphContractError("retry_timestamp_mismatch")
            prior = retries.get(retry.failed_stage_attempt_id)
            if retry.attempt > 3:
                raise GraphContractError("retry_attempt_exhausted")
            if prior is None and retry.attempt != 1:
                raise GraphContractError("retry_attempt_not_monotonic")
            if prior is not None and retry.attempt != prior.attempt + 1:
                raise GraphContractError("retry_attempt_not_monotonic")
            if prior is not None and retry.changed_action == prior.changed_action:
                raise GraphContractError("retry_action_unchanged")
            retries[retry.failed_stage_attempt_id] = retry
        elif event.event_type is EventType.EXPERIMENTAL_PUBLISHED:
            if publication is not None:
                raise GraphContractError("experimental_publication_already_recorded")
            publication = _record(
                ExperimentalPublication,
                _payload(
                    event,
                    {"branch", "candidate_packet_digest", "commit", "tree"},
                    "invalid_experimental_publication_payload",
                ),
                "invalid_experimental_publication_payload",
            )
        elif event.event_type is EventType.PROTECTED_VALIDATION_RECORDED:
            if publication is None:
                raise GraphContractError("protected_validation_publication_required")
            if protected_validation is not None:
                raise GraphContractError("protected_validation_already_recorded")
            validation = _record(
                ProtectedValidation,
                _payload(
                    event,
                    {"candidate_commit", "candidate_tree", "receipt_digest"},
                    "invalid_protected_validation_payload",
                ),
                "invalid_protected_validation_payload",
            )
            if (
                validation.candidate_commit != publication.commit
                or validation.candidate_tree != publication.tree
            ):
                raise GraphContractError("protected_validation_candidate_mismatch")
            protected_validation = validation
        elif event.event_type is EventType.PROMOTION_RECORDED:
            if protected_validation is None:
                raise GraphContractError("promotion_protected_validation_required")
            if promotion is not None:
                raise GraphContractError("promotion_already_recorded")
            payload = _payload(
                event,
                {"merge_commit", "merge_tree"},
                "invalid_promotion_payload",
            )
            promotion = _record(
                PromotionRecord,
                {**payload, "merged_at": event.occurred_at},
                "invalid_promotion_payload",
            )
        elif event.event_type is EventType.SOAK_OBSERVED:
            if promotion is None:
                raise GraphContractError("soak_promotion_required")
            soak = _record(
                SoakObservation,
                _payload(
                    event,
                    {"evidence_digest", "healthy", "merge_commit", "observed_at"},
                    "invalid_soak_payload",
                ),
                "invalid_soak_payload",
            )
            if soak.observed_at != event.occurred_at:
                raise GraphContractError("soak_timestamp_mismatch")
            if soak.merge_commit != promotion.merge_commit:
                raise GraphContractError("soak_merge_mismatch")
            soak_observations.append(soak)
        elif event.event_type is EventType.REVERT_RECORDED:
            if promotion is None:
                raise GraphContractError("revert_promotion_required")
            if revert is not None:
                raise GraphContractError("revert_already_recorded")
            payload = _payload(
                event,
                {
                    "hard_failure_digest",
                    "merge_commit",
                    "restored_tree",
                    "revert_candidate_commit",
                    "revert_merge_commit",
                    "revert_pull_request_number",
                },
                "invalid_revert_payload",
            )
            recorded_revert = _record(
                RevertRecord,
                {**payload, "reverted_at": event.occurred_at},
                "invalid_revert_payload",
            )
            if recorded_revert.merge_commit != promotion.merge_commit:
                raise GraphContractError("revert_merge_mismatch")
            if not any(
                not observation.healthy
                and observation.merge_commit == recorded_revert.merge_commit
                and observation.evidence_digest == recorded_revert.hard_failure_digest
                for observation in soak_observations
            ):
                raise GraphContractError("hard_failure_required")
            revert = recorded_revert
        elif _accepted(event):
            if promotion is None:
                raise GraphContractError("soak_healthy_observation_required")
            accepted_at = occurred_at
            if not any(
                observation.healthy
                and _utc(observation.observed_at) <= accepted_at
                and _utc(observation.observed_at) - _utc(promotion.merged_at) >= timedelta(hours=24)
                for observation in soak_observations
            ):
                raise GraphContractError("soak_healthy_observation_required")
        elif event.event_type not in _AUTONOMY_EVENT_TYPES:
            continue

    latest_retry = (
        max(
            retries.values(),
            key=lambda item: (item.scheduled_at, item.failed_stage_attempt_id),
        )
        if retries
        else None
    )
    return AutonomyProjection(
        experiment_id=manifest.experiment_id,
        manifest_digest=manifest.digest,
        retry=latest_retry,
        experimental_publication=publication,
        protected_validation=protected_validation,
        promotion=promotion,
        soak_observations=tuple(soak_observations),
        revert=revert,
    )
