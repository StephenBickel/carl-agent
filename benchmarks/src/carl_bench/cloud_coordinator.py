"""Pure restart-safe orchestration decisions for Carl's cloud improvement graph.

The coordinator reconstructs only canonical durable facts and returns one bounded decision.  It
does not own provider clients, credentials, model policy, or local execution fallbacks.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any, Literal, Protocol

from carl_bench.canonical import CanonicalizationError, canonical_json_bytes
from carl_bench.cloud_state import CloudCommand, CloudLease, CloudStateError, CommandState

MAX_COORDINATOR_SNAPSHOT_BYTES = 1_048_576
MAX_CLOUD_RESULT_BYTES = 16_384
_MAX_NODES = 64
_LEASE_RENEWAL_WINDOW = timedelta(minutes=5)
_MAX_PROTECTED_VERIFICATION_AGE = timedelta(minutes=15)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_MEDIA_TYPE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$")
_FAILURE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PUBLIC_FORBIDDEN = re.compile(
    r"(?:api[_-]?key|authorization|bearer|credential|hidden.reasoning|password|private[_-]?key|secret)",
    re.IGNORECASE,
)

NodeStatus = Literal["waiting", "ready", "complete", "failed"]
EffectStatus = Literal["none", "retry_scheduled", "uncertain", "applied"]
CoordinatorAction = Literal[
    "idle",
    "acquire_lease",
    "renew_lease",
    "reconcile_lease",
    "release_lease",
    "persist_command",
    "claim_command",
    "execute_effect",
    "reconcile_effect",
    "complete_command",
    "retry_rework",
    "trigger_supervisor",
    "frozen",
]

NODE_ORDER = (
    "create_revert",
    "observe_revert",
    "publish_input",
    "register_hypothesis",
    "request_builder",
    "dispatch_builder",
    "observe_builder",
    "archive_builder",
    "ingest_builder",
    "publish_experimental",
    "dispatch_validation",
    "observe_validation",
    "archive_validation",
    "ingest_validation",
    "record_disposition",
    "create_promotion_pr",
    "observe_required_checks",
    "enable_auto_merge",
    "schedule_soak",
    "observe_soak",
    "accept_soak",
    "trigger_supervisor",
)
_NODE_ORDER = NODE_ORDER
_NODE_PRIORITY = {name: index for index, name in enumerate(_NODE_ORDER)}
EffectFamily = Literal["archive", "evaluator", "github", "input", "observer", "state", "supervisor"]
EFFECT_FAMILY_BY_NODE = MappingProxyType(
    {
        "create_revert": "github",
        "observe_revert": "observer",
        "publish_input": "input",
        "register_hypothesis": "state",
        "request_builder": "state",
        "dispatch_builder": "github",
        "observe_builder": "observer",
        "archive_builder": "archive",
        "ingest_builder": "state",
        "publish_experimental": "github",
        "dispatch_validation": "github",
        "observe_validation": "observer",
        "archive_validation": "archive",
        "ingest_validation": "evaluator",
        "record_disposition": "state",
        "create_promotion_pr": "github",
        "observe_required_checks": "github",
        "enable_auto_merge": "github",
        "schedule_soak": "state",
        "observe_soak": "observer",
        "accept_soak": "state",
        "trigger_supervisor": "supervisor",
    }
)
if tuple(EFFECT_FAMILY_BY_NODE) != NODE_ORDER:  # pragma: no cover - import-time invariant
    raise RuntimeError("coordinator_effect_family_table_invalid")
_PRODUCTION_NODES = frozenset(
    {
        "create_promotion_pr",
        "observe_required_checks",
        "enable_auto_merge",
        "schedule_soak",
        "observe_soak",
        "accept_soak",
        "create_revert",
        "observe_revert",
    }
)
_PULL_REQUEST_RECEIPT_NODES = _PRODUCTION_NODES - {
    "create_promotion_pr",
    "create_revert",
}
_CHECK_RECEIPT_NODES = _PRODUCTION_NODES - {
    "create_promotion_pr",
    "observe_required_checks",
    "create_revert",
}
_MERGE_RECEIPT_NODES = frozenset(
    {"schedule_soak", "observe_soak", "accept_soak", "create_revert", "observe_revert"}
)
_SOAK_RECEIPT_NODES = frozenset({"accept_soak", "create_revert", "observe_revert"})
_REVERT_RECEIPT_NODES = frozenset({"create_revert", "observe_revert"})
_CLOUD_COMMANDS = frozenset(
    {"request", "coordinate", "observe", "ingest", "publish-input", "health", "commission-live"}
)
_COMMAND_NODES: dict[str, frozenset[str]] = {
    "request": frozenset({"register_hypothesis", "request_builder"}),
    "coordinate": frozenset(_NODE_ORDER),
    "observe": frozenset(
        {
            "observe_builder",
            "archive_builder",
            "observe_validation",
            "archive_validation",
            "observe_required_checks",
            "observe_soak",
            "observe_revert",
        }
    ),
    "ingest": frozenset({"ingest_builder", "ingest_validation", "record_disposition"}),
    "publish-input": frozenset({"publish_input"}),
    "health": frozenset({"trigger_supervisor"}),
    "commission-live": frozenset(
        {
            "dispatch_validation",
            "observe_validation",
            "archive_validation",
            "ingest_validation",
            "record_disposition",
            *_PRODUCTION_NODES,
        }
    ),
}
_NODE_BINDINGS: dict[str, tuple[str, str]] = {
    "create_revert": ("promoter", "github_effect"),
    "observe_revert": ("observer", "observe"),
    "publish_input": ("validator", "register_evidence"),
    "register_hypothesis": ("builder", "register_manifest"),
    "request_builder": ("coordinator", "schedule"),
    "dispatch_builder": ("coordinator", "dispatch"),
    "observe_builder": ("observer", "observe"),
    "archive_builder": ("observer", "register_evidence"),
    "ingest_builder": ("coordinator", "record_success"),
    "publish_experimental": ("builder", "publish_experimental"),
    "dispatch_validation": ("coordinator", "dispatch"),
    "observe_validation": ("observer", "observe"),
    "archive_validation": ("validator", "register_evidence"),
    "ingest_validation": ("coordinator", "record_success"),
    "record_disposition": ("validator", "append_disposition"),
    "create_promotion_pr": ("promoter", "github_effect"),
    "observe_required_checks": ("observer", "observe"),
    "enable_auto_merge": ("promoter", "github_effect"),
    "schedule_soak": ("coordinator", "schedule"),
    "observe_soak": ("soak", "production_observation"),
    "accept_soak": ("soak", "record_soak"),
    "trigger_supervisor": ("supervisor", "claim_trigger"),
}


class CloudCoordinatorError(ValueError):
    """Stable orchestration failure that never includes private payloads."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ProtectedEffectUnavailable(CloudCoordinatorError):
    """One fixed protected service is not commissioned for the selected node."""

    def __init__(self, code: str) -> None:
        if (
            not isinstance(code, str)
            or not code.endswith("_service_uncommissioned")
            or _FAILURE.fullmatch(code) is None
        ):
            raise CloudCoordinatorError("protected_effect_unavailable_invalid")
        super().__init__(code)


def effect_family_for_node(kind: str) -> EffectFamily:
    """Return the fixed protected effect family for one exact graph node."""
    try:
        return EFFECT_FAMILY_BY_NODE[kind]  # type: ignore[return-value]
    except (KeyError, TypeError) as error:
        raise CloudCoordinatorError("coordinator_effect_family_invalid") from error


def _timestamp(value: object, code: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64 or not value.endswith("Z"):
        raise CloudCoordinatorError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CloudCoordinatorError(code) from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise CloudCoordinatorError(code)
    return parsed


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise CloudCoordinatorError(code)
    return value


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise CloudCoordinatorError(code)
    return value


def _strict_fields(value: object, fields: frozenset[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise CloudCoordinatorError(code)
    return value


def _canonical_size(value: object, *, maximum: int, code: str) -> bytes:
    try:
        payload = canonical_json_bytes(value)
    except (CanonicalizationError, UnicodeError, RecursionError) as error:
        raise CloudCoordinatorError(code) from error
    if len(payload) > maximum:
        raise CloudCoordinatorError(code)
    return payload


@dataclass(frozen=True, slots=True)
class ImmutableInputBinding:
    digest: str
    media_type: str
    media_version: int
    size_bytes: int
    visibility: Literal["public", "private"]
    resolved_digest: str

    def __post_init__(self) -> None:
        _digest(self.digest, "immutable_input_digest_invalid")
        _digest(self.resolved_digest, "immutable_input_resolved_digest_invalid")
        if self.digest != self.resolved_digest:
            raise CloudCoordinatorError("immutable_input_resolution_mismatch")
        if not isinstance(self.media_type, str) or _MEDIA_TYPE.fullmatch(self.media_type) is None:
            raise CloudCoordinatorError("immutable_input_media_type_invalid")
        if (
            isinstance(self.media_version, bool)
            or not isinstance(self.media_version, int)
            or not 1 <= self.media_version <= 255
        ):
            raise CloudCoordinatorError("immutable_input_media_version_invalid")
        if (
            isinstance(self.size_bytes, bool)
            or not isinstance(self.size_bytes, int)
            or not 0 <= self.size_bytes <= 32 * 1_048_576
        ):
            raise CloudCoordinatorError("immutable_input_size_invalid")
        if self.visibility not in {"public", "private"}:
            raise CloudCoordinatorError("immutable_input_visibility_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_canonical_dict(cls, value: object) -> ImmutableInputBinding:
        decoded = _strict_fields(
            value, frozenset(cls.__dataclass_fields__), "immutable_input_binding_invalid"
        )
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudCoordinatorError("immutable_input_binding_invalid") from error


@dataclass(frozen=True, slots=True)
class CoordinatorNode:
    node_id: str
    kind: str
    status: NodeStatus
    authority: str
    operation: str
    command_key: str
    request_digest: str
    occurred_at: str
    attempt: int
    max_attempts: int

    def __post_init__(self) -> None:
        _identifier(self.node_id, "coordinator_node_id_invalid")
        if self.kind not in _NODE_PRIORITY:
            raise CloudCoordinatorError("coordinator_node_kind_invalid")
        if self.status not in {"waiting", "ready", "complete", "failed"}:
            raise CloudCoordinatorError("coordinator_node_status_invalid")
        if (self.authority, self.operation) != _NODE_BINDINGS[self.kind]:
            raise CloudCoordinatorError("coordinator_node_binding_invalid")
        _identifier(self.command_key, "coordinator_node_command_key_invalid")
        _digest(self.request_digest, "coordinator_node_request_digest_invalid")
        _timestamp(self.occurred_at, "coordinator_node_occurred_at_invalid")
        try:
            self.command(expected_revision=0)
        except CloudStateError as error:
            raise CloudCoordinatorError("coordinator_node_command_invalid") from error

    @property
    def effect_key(self) -> str:
        return self.command(expected_revision=0).effect_key

    def command(
        self,
        *,
        expected_revision: int,
        request_digest: str | None = None,
        attempt: int | None = None,
        command_key: str | None = None,
    ) -> CloudCommand:
        selected_attempt = self.attempt if attempt is None else attempt
        selected_digest = self.request_digest if request_digest is None else request_digest
        selected_key = self.command_key if command_key is None else command_key
        if command_key is None and selected_attempt != self.attempt:
            raise CloudStateError("retry_command_key_required")
        return CloudCommand.create(
            command_key=selected_key,
            authority=self.authority,
            operation=self.operation,
            request_digest=selected_digest,
            occurred_at=self.occurred_at,
            expected_revision=expected_revision,
            attempt=selected_attempt,
            max_attempts=self.max_attempts,
        )

    def to_canonical_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_canonical_dict(cls, value: object) -> CoordinatorNode:
        decoded = _strict_fields(
            value,
            frozenset(cls.__dataclass_fields__),
            "coordinator_node_invalid",
        )
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudCoordinatorError("coordinator_node_invalid") from error


@dataclass(frozen=True, slots=True)
class EffectObservation:
    effect_key: str
    status: EffectStatus
    result_digest: str | None
    observed_at: str
    retry_not_before: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.effect_key, "effect_observation_key_invalid")
        if self.status not in {"none", "retry_scheduled", "uncertain", "applied"}:
            raise CloudCoordinatorError("effect_observation_status_invalid")
        _timestamp(self.observed_at, "effect_observation_time_invalid")
        if self.status == "applied":
            _digest(self.result_digest, "effect_observation_result_invalid")
        elif self.result_digest is not None:
            raise CloudCoordinatorError("effect_observation_result_unexpected")
        if self.status == "retry_scheduled":
            retry_at = _timestamp(self.retry_not_before, "effect_observation_retry_time_invalid")
            if retry_at < _timestamp(self.observed_at, "effect_observation_time_invalid"):
                raise CloudCoordinatorError("effect_observation_retry_time_invalid")
        elif self.retry_not_before is not None:
            raise CloudCoordinatorError("effect_observation_retry_time_unexpected")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_canonical_dict(cls, value: object) -> EffectObservation:
        decoded = _strict_fields(
            value, frozenset(cls.__dataclass_fields__), "effect_observation_invalid"
        )
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudCoordinatorError("effect_observation_invalid") from error


@dataclass(frozen=True, slots=True)
class CoordinatorFailure:
    failure_code: str
    failed_command_key: str
    changed_action: str
    prior_changed_actions: tuple[str, ...]
    next_command_key: str
    next_request_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.failure_code, str) or _FAILURE.fullmatch(self.failure_code) is None:
            raise CloudCoordinatorError("coordinator_failure_code_invalid")
        _identifier(self.failed_command_key, "coordinator_failure_command_invalid")
        _identifier(self.changed_action, "coordinator_failure_action_invalid")
        if (
            not isinstance(self.prior_changed_actions, tuple)
            or len(self.prior_changed_actions) > 3
            or any(
                not isinstance(item, str) or _IDENTIFIER.fullmatch(item) is None
                for item in self.prior_changed_actions
            )
            or len(set(self.prior_changed_actions)) != len(self.prior_changed_actions)
        ):
            raise CloudCoordinatorError("coordinator_failure_history_invalid")
        _identifier(self.next_command_key, "coordinator_failure_command_key_invalid")
        _digest(self.next_request_digest, "coordinator_failure_request_digest_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "changed_action": self.changed_action,
            "failed_command_key": self.failed_command_key,
            "failure_code": self.failure_code,
            "next_command_key": self.next_command_key,
            "next_request_digest": self.next_request_digest,
            "prior_changed_actions": list(self.prior_changed_actions),
        }

    @classmethod
    def from_canonical_dict(cls, value: object) -> CoordinatorFailure:
        decoded = _strict_fields(
            value, frozenset(cls.__dataclass_fields__), "coordinator_failure_invalid"
        )
        history = decoded["prior_changed_actions"]
        if not isinstance(history, list):
            raise CloudCoordinatorError("coordinator_failure_invalid")
        try:
            return cls(
                failure_code=decoded["failure_code"],
                failed_command_key=decoded["failed_command_key"],
                changed_action=decoded["changed_action"],
                prior_changed_actions=tuple(history),
                next_command_key=decoded["next_command_key"],
                next_request_digest=decoded["next_request_digest"],
            )
        except (KeyError, TypeError) as error:
            raise CloudCoordinatorError("coordinator_failure_invalid") from error


@dataclass(frozen=True, slots=True, init=False)
class ProtectedProductionAuthorization:
    """Exact protected-service result for one production node and request.

    This value is never accepted by a wire codec.  It can only enter a coordinator snapshot through
    the isolated service's independently verified durable reconstruction.
    """

    experiment_id: str
    node_kind: str
    request_digest: str
    repository: str
    candidate_commit: str
    candidate_tree: str
    experimental_ref: str
    archive_object_key: str
    archive_version_id: str
    archive_digest: str
    archive_receipt_digest: str
    experimental_receipt_digest: str
    live_provenance_receipt_digest: str
    independent_disposition_receipt_digest: str
    archive_retain_until: str
    verified_at: str
    pull_request_number: int | None = None
    pull_request_head: str | None = None
    pull_request_base: str | None = None
    required_checks_receipt_digest: str | None = None
    branch_protection_receipt_digest: str | None = None
    merge_commit: str | None = None
    merge_tree: str | None = None
    merged_at: str | None = None
    soak_observation_digest: str | None = None
    soak_observed_at: str | None = None
    hard_failure_digest: str | None = None
    revert_candidate_commit: str | None = None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise CloudCoordinatorError("protected_authorization_construction_invalid")

    def __post_init__(self) -> None:
        _identifier(self.experiment_id, "protected_authorization_identity_invalid")
        if self.node_kind not in _PRODUCTION_NODES:
            raise CloudCoordinatorError("protected_authorization_node_invalid")
        _digest(self.request_digest, "protected_authorization_identity_invalid")
        if (
            not isinstance(self.repository, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository) is None
            or not isinstance(self.candidate_commit, str)
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", self.candidate_commit) is None
            or not isinstance(self.candidate_tree, str)
            or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", self.candidate_tree) is None
            or not isinstance(self.experimental_ref, str)
            or self.experimental_ref != f"refs/heads/experimental/{self.experiment_id}"
            or not isinstance(self.archive_object_key, str)
            or self.archive_object_key
            != f"carl-evidence/v1/sha256/{self.archive_digest[:2]}/{self.archive_digest}"
            or not isinstance(self.archive_version_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+=-]{0,255}", self.archive_version_id)
            is None
        ):
            raise CloudCoordinatorError("protected_authorization_identity_invalid")
        _digest(self.archive_digest, "protected_authorization_archive_invalid")
        verified = _timestamp(self.verified_at, "protected_authorization_time_invalid")
        retained = _timestamp(
            self.archive_retain_until, "protected_authorization_retention_invalid"
        )
        if retained <= verified:
            raise CloudCoordinatorError("protected_authorization_retention_invalid")
        common_receipts = (
            self.archive_receipt_digest,
            self.experimental_receipt_digest,
            self.live_provenance_receipt_digest,
            self.independent_disposition_receipt_digest,
        )
        for digest in common_receipts:
            _digest(digest, "protected_authorization_receipts_invalid")
        if len(set(common_receipts)) != len(common_receipts):
            raise CloudCoordinatorError("protected_authorization_receipts_invalid")
        pull_request_values = (
            self.pull_request_number,
            self.pull_request_head,
            self.pull_request_base,
        )
        requires_pull_request = self.node_kind in _PULL_REQUEST_RECEIPT_NODES
        has_any_pull_request = any(value is not None for value in pull_request_values)
        has_all_pull_request = all(value is not None for value in pull_request_values)
        if (
            has_any_pull_request != has_all_pull_request
            or requires_pull_request != has_all_pull_request
        ):
            raise CloudCoordinatorError("protected_authorization_pull_request_invalid")
        if requires_pull_request:
            if (
                isinstance(self.pull_request_number, bool)
                or not isinstance(self.pull_request_number, int)
                or self.pull_request_number <= 0
                or not isinstance(self.pull_request_head, str)
                or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", self.pull_request_head) is None
                or self.pull_request_base != "main"
            ):
                raise CloudCoordinatorError("protected_authorization_pull_request_invalid")
            if (
                self.node_kind not in _REVERT_RECEIPT_NODES
                and self.pull_request_head != self.candidate_commit
            ):
                raise CloudCoordinatorError("protected_authorization_pull_request_invalid")
        check_values = (
            self.required_checks_receipt_digest,
            self.branch_protection_receipt_digest,
        )
        requires_checks = self.node_kind in _CHECK_RECEIPT_NODES
        has_any_checks = any(value is not None for value in check_values)
        has_all_checks = all(value is not None for value in check_values)
        if has_any_checks != has_all_checks or requires_checks != has_all_checks:
            raise CloudCoordinatorError("protected_authorization_checks_invalid")
        if requires_checks:
            for digest in check_values:
                _digest(digest, "protected_authorization_checks_invalid")
            if len(set((*common_receipts, *check_values))) != 6:
                raise CloudCoordinatorError("protected_authorization_checks_invalid")
        merge_values = (self.merge_commit, self.merge_tree, self.merged_at)
        requires_merge = self.node_kind in _MERGE_RECEIPT_NODES
        has_any_merge = any(value is not None for value in merge_values)
        has_all_merge = all(value is not None for value in merge_values)
        if has_any_merge != has_all_merge or requires_merge != has_all_merge:
            raise CloudCoordinatorError("protected_authorization_merge_invalid")
        if self.merge_commit is not None:
            for value in (self.merge_commit, self.merge_tree):
                if (
                    not isinstance(value, str)
                    or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) is None
                ):
                    raise CloudCoordinatorError("protected_authorization_merge_invalid")
            _timestamp(self.merged_at, "protected_authorization_merge_invalid")
        soak_values = (self.soak_observation_digest, self.soak_observed_at)
        requires_soak = self.node_kind in _SOAK_RECEIPT_NODES
        has_any_soak = any(value is not None for value in soak_values)
        has_all_soak = all(value is not None for value in soak_values)
        if has_any_soak != has_all_soak or requires_soak != has_all_soak:
            raise CloudCoordinatorError("protected_authorization_soak_invalid")
        if self.soak_observation_digest is not None:
            _digest(self.soak_observation_digest, "protected_authorization_soak_invalid")
            _timestamp(self.soak_observed_at, "protected_authorization_soak_invalid")
            if self.merge_commit is None:
                raise CloudCoordinatorError("protected_authorization_soak_invalid")
        revert_values = (self.hard_failure_digest, self.revert_candidate_commit)
        requires_revert = self.node_kind in _REVERT_RECEIPT_NODES
        has_any_revert = any(value is not None for value in revert_values)
        has_all_revert = all(value is not None for value in revert_values)
        if has_any_revert != has_all_revert or requires_revert != has_all_revert:
            raise CloudCoordinatorError("protected_authorization_revert_invalid")
        if requires_revert:
            _digest(self.hard_failure_digest, "protected_authorization_revert_invalid")
            if (
                not isinstance(self.revert_candidate_commit, str)
                or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", self.revert_candidate_commit) is None
                or (
                    self.node_kind == "observe_revert"
                    and self.pull_request_head != self.revert_candidate_commit
                )
            ):
                raise CloudCoordinatorError("protected_authorization_revert_invalid")

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    name: list(value) if isinstance(value, tuple) else value
                    for name, value in (
                        (field, getattr(self, field)) for field in self.__dataclass_fields__
                    )
                }
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class CoordinatorSnapshot:
    schema_version: int
    experiment_id: str
    revision: int
    observed_at: str
    coordinator_id: str
    nodes: tuple[CoordinatorNode, ...]
    lease: CloudLease | None
    command: CommandState | None
    effect: EffectObservation | None
    failure: CoordinatorFailure | None
    production_authorization: ProtectedProductionAuthorization | None
    immutable_inputs: tuple[ImmutableInputBinding, ...]
    dead_holder_observation_digest: str | None

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or self.schema_version != 1:
            raise CloudCoordinatorError("coordinator_snapshot_schema_invalid")
        _identifier(self.experiment_id, "coordinator_experiment_id_invalid")
        _identifier(self.coordinator_id, "coordinator_id_invalid")
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 0
        ):
            raise CloudCoordinatorError("coordinator_revision_invalid")
        _timestamp(self.observed_at, "coordinator_observed_at_invalid")
        if (
            not isinstance(self.nodes, tuple)
            or len(self.nodes) > _MAX_NODES
            or any(not isinstance(item, CoordinatorNode) for item in self.nodes)
        ):
            raise CloudCoordinatorError("coordinator_nodes_invalid")
        node_ids = tuple(item.node_id for item in self.nodes)
        if len(set(node_ids)) != len(node_ids):
            raise CloudCoordinatorError("coordinator_node_duplicate")
        if self.lease is not None and not isinstance(self.lease, CloudLease):
            raise CloudCoordinatorError("coordinator_lease_invalid")
        if self.command is not None and not isinstance(self.command, CommandState):
            raise CloudCoordinatorError("coordinator_command_invalid")
        if self.effect is not None and not isinstance(self.effect, EffectObservation):
            raise CloudCoordinatorError("coordinator_effect_invalid")
        if self.failure is not None and not isinstance(self.failure, CoordinatorFailure):
            raise CloudCoordinatorError("coordinator_failure_invalid")
        if self.production_authorization is not None and not isinstance(
            self.production_authorization, ProtectedProductionAuthorization
        ):
            raise CloudCoordinatorError("protected_authorization_invalid")
        if not isinstance(self.immutable_inputs, tuple) or any(
            not isinstance(item, ImmutableInputBinding) for item in self.immutable_inputs
        ):
            raise CloudCoordinatorError("immutable_inputs_invalid")
        input_digests = tuple(item.digest for item in self.immutable_inputs)
        if len(set(input_digests)) != len(input_digests):
            raise CloudCoordinatorError("immutable_input_duplicate")
        if self.dead_holder_observation_digest is not None:
            _digest(
                self.dead_holder_observation_digest,
                "dead_holder_observation_digest_invalid",
            )
        _canonical_size(
            self.to_canonical_dict(),
            maximum=MAX_COORDINATOR_SNAPSHOT_BYTES,
            code="coordinator_snapshot_too_large",
        )

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "command": None if self.command is None else self.command.to_canonical_dict(),
            "coordinator_id": self.coordinator_id,
            "dead_holder_observation_digest": self.dead_holder_observation_digest,
            "effect": None if self.effect is None else self.effect.to_canonical_dict(),
            "experiment_id": self.experiment_id,
            "failure": None if self.failure is None else self.failure.to_canonical_dict(),
            "immutable_inputs": [item.to_canonical_dict() for item in self.immutable_inputs],
            "lease": None if self.lease is None else self.lease.to_canonical_dict(),
            "nodes": [item.to_canonical_dict() for item in self.nodes],
            "observed_at": self.observed_at,
            "production_authorization": (
                None
                if self.production_authorization is None
                else {"authorization_digest": self.production_authorization.digest}
            ),
            "revision": self.revision,
            "schema_version": self.schema_version,
        }


def _raise_caller_authorization_forbidden() -> None:
    raise CloudCoordinatorError("protected_authorization_caller_forbidden")


def reconstruct_snapshot(value: object) -> CoordinatorSnapshot:
    """Strictly decode one canonical durable snapshot without accepting coercion."""
    _canonical_size(
        value,
        maximum=MAX_COORDINATOR_SNAPSHOT_BYTES,
        code="coordinator_snapshot_too_large",
    )
    decoded = _strict_fields(
        value, frozenset(CoordinatorSnapshot.__dataclass_fields__), "coordinator_snapshot_invalid"
    )
    nodes = decoded["nodes"]
    inputs = decoded["immutable_inputs"]
    if not isinstance(nodes, list) or not isinstance(inputs, list):
        raise CloudCoordinatorError("coordinator_snapshot_invalid")
    try:
        return CoordinatorSnapshot(
            schema_version=decoded["schema_version"],
            experiment_id=decoded["experiment_id"],
            revision=decoded["revision"],
            observed_at=decoded["observed_at"],
            coordinator_id=decoded["coordinator_id"],
            nodes=tuple(CoordinatorNode.from_canonical_dict(item) for item in nodes),
            lease=(
                None
                if decoded["lease"] is None
                else CloudLease.from_canonical_dict(decoded["lease"])
            ),
            command=(
                None
                if decoded["command"] is None
                else CommandState.from_canonical_dict(decoded["command"])
            ),
            effect=(
                None
                if decoded["effect"] is None
                else EffectObservation.from_canonical_dict(decoded["effect"])
            ),
            failure=(
                None
                if decoded["failure"] is None
                else CoordinatorFailure.from_canonical_dict(decoded["failure"])
            ),
            production_authorization=(
                None
                if decoded["production_authorization"] is None
                else (_raise_caller_authorization_forbidden())
            ),
            immutable_inputs=tuple(
                ImmutableInputBinding.from_canonical_dict(item) for item in inputs
            ),
            dead_holder_observation_digest=decoded["dead_holder_observation_digest"],
        )
    except CloudCoordinatorError:
        raise
    except (CloudStateError, KeyError, TypeError, ValueError) as error:
        raise CloudCoordinatorError("coordinator_snapshot_invalid") from error


@dataclass(frozen=True, slots=True)
class CloudCoordinatorDecision:
    schema_version: int
    action: CoordinatorAction
    reason: str
    identity: str
    experiment_id: str
    revision: int
    node: str | None
    command: CloudCommand | None
    effect_key: str | None
    result_digest: str | None
    consequential: bool
    remote_effect: bool
    event: None

    def __post_init__(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or self.schema_version != 1
            or self.action
            not in {
                "idle",
                "acquire_lease",
                "renew_lease",
                "reconcile_lease",
                "release_lease",
                "persist_command",
                "claim_command",
                "execute_effect",
                "reconcile_effect",
                "complete_command",
                "retry_rework",
                "trigger_supervisor",
                "frozen",
            }
        ):
            raise CloudCoordinatorError("cloud_decision_invalid")
        if (
            not isinstance(self.reason, str)
            or not self.reason
            or len(self.reason) > 128
            or _PUBLIC_FORBIDDEN.search(self.reason)
        ):
            raise CloudCoordinatorError("cloud_result_not_public_safe")
        _digest(self.identity, "cloud_decision_identity_invalid")
        _identifier(self.experiment_id, "cloud_decision_experiment_invalid")
        if (
            isinstance(self.revision, bool)
            or not isinstance(self.revision, int)
            or self.revision < 0
        ):
            raise CloudCoordinatorError("cloud_decision_revision_invalid")
        if self.node is not None and self.node not in _NODE_PRIORITY:
            raise CloudCoordinatorError("cloud_decision_node_invalid")
        if self.command is not None and not isinstance(self.command, CloudCommand):
            raise CloudCoordinatorError("cloud_decision_command_invalid")
        if self.effect_key is not None:
            _identifier(self.effect_key, "cloud_decision_effect_invalid")
        if self.result_digest is not None:
            _digest(self.result_digest, "cloud_decision_result_invalid")
        if type(self.consequential) is not bool or type(self.remote_effect) is not bool:
            raise CloudCoordinatorError("cloud_decision_invalid")
        if self.remote_effect and not self.consequential:
            raise CloudCoordinatorError("cloud_decision_invalid")
        if self.event is not None:
            raise CloudCoordinatorError("cloud_decision_event_forbidden")
        _canonical_size(
            self.to_canonical_dict(),
            maximum=MAX_CLOUD_RESULT_BYTES,
            code="cloud_result_too_large",
        )

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "command": None if self.command is None else self.command.to_canonical_dict(),
            "consequential": self.consequential,
            "effect_key": self.effect_key,
            "event": None,
            "experiment_id": self.experiment_id,
            "identity": self.identity,
            "node": self.node,
            "reason": self.reason,
            "remote_effect": self.remote_effect,
            "result_digest": self.result_digest,
            "revision": self.revision,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_canonical_dict(cls, value: object) -> CloudCoordinatorDecision:
        decoded = _strict_fields(
            value, frozenset(cls.__dataclass_fields__), "cloud_decision_invalid"
        )
        try:
            return cls(
                schema_version=decoded["schema_version"],
                action=decoded["action"],
                reason=decoded["reason"],
                identity=decoded["identity"],
                experiment_id=decoded["experiment_id"],
                revision=decoded["revision"],
                node=decoded["node"],
                command=(
                    None
                    if decoded["command"] is None
                    else CloudCommand.from_canonical_dict(decoded["command"])
                ),
                effect_key=decoded["effect_key"],
                result_digest=decoded["result_digest"],
                consequential=decoded["consequential"],
                remote_effect=decoded["remote_effect"],
                event=decoded["event"],
            )
        except CloudCoordinatorError:
            raise
        except (CloudStateError, KeyError, TypeError) as error:
            raise CloudCoordinatorError("cloud_decision_invalid") from error


def _decision(
    snapshot: CoordinatorSnapshot,
    action: CoordinatorAction,
    reason: str,
    *,
    node: CoordinatorNode | None = None,
    command: CloudCommand | None = None,
    effect_key: str | None = None,
    result_digest: str | None = None,
    consequential: bool = False,
    remote_effect: bool = False,
) -> CloudCoordinatorDecision:
    if action == "frozen":
        consequential = True
    identity_payload = {
        "action": action,
        "experiment_id": snapshot.experiment_id,
        "reason": reason,
        "revision": snapshot.revision,
    }
    if node is not None:
        identity_payload["node_id"] = node.node_id
    if command is not None:
        identity_payload["command_key"] = command.command_key
        identity_payload["effect_key"] = command.effect_key
    identity = hashlib.sha256(canonical_json_bytes(identity_payload)).hexdigest()
    return CloudCoordinatorDecision(
        schema_version=1,
        action=action,
        reason=reason,
        identity=identity,
        experiment_id=snapshot.experiment_id,
        revision=snapshot.revision,
        node=None if node is None else node.kind,
        command=command,
        effect_key=effect_key,
        result_digest=result_digest,
        consequential=consequential,
        remote_effect=remote_effect,
        event=None,
    )


def _empty_queue_decision(
    command: str, *, reason: Literal["no_applicable_node", "already_frozen"] = "no_applicable_node"
) -> CloudCoordinatorDecision:
    """Return a stable public idle result without inventing durable experiment state."""
    identity = hashlib.sha256(
        canonical_json_bytes(
            {
                "action": "idle",
                "command": command,
                "reason": reason,
                "schema_version": 1,
            }
        )
    ).hexdigest()
    return CloudCoordinatorDecision(
        schema_version=1,
        action="idle",
        reason=reason,
        identity=identity,
        experiment_id=f"coordinator-queue:{command}",
        revision=0,
        node=None,
        command=None,
        effect_key=None,
        result_digest=None,
        consequential=False,
        remote_effect=False,
        event=None,
    )


def _is_atomic_receipt_freeze(applied: object, *, expected: CloudCoordinatorDecision) -> bool:
    if not isinstance(applied, CloudCoordinatorDecision) or expected.node is None:
        return False
    identity = hashlib.sha256(
        canonical_json_bytes(
            {
                "action": "frozen",
                "experiment_id": expected.experiment_id,
                "node_id": f"{expected.experiment_id}:{expected.node}",
                "reason": "authoritative_completion_receipt_invalid",
                "revision": expected.revision,
            }
        )
    ).hexdigest()
    return applied == CloudCoordinatorDecision(
        schema_version=1,
        action="frozen",
        reason="authoritative_completion_receipt_invalid",
        identity=identity,
        experiment_id=expected.experiment_id,
        revision=expected.revision,
        node=expected.node,
        command=None,
        effect_key=None,
        result_digest=None,
        consequential=True,
        remote_effect=False,
        event=None,
    )


def _lease_decision(snapshot: CoordinatorSnapshot) -> CloudCoordinatorDecision | None:
    current = snapshot.lease
    now = _timestamp(snapshot.observed_at, "coordinator_observed_at_invalid")
    if current is None or current.status == "released":
        return _decision(
            snapshot,
            "acquire_lease",
            "coordinator_lease_required",
            consequential=True,
        )
    if current.status == "reconciled":
        return _decision(
            snapshot,
            "release_lease",
            "reconciled_lease_release_required",
            consequential=True,
        )
    expires = _timestamp(current.expires_at, "coordinator_lease_invalid")
    if now >= expires:
        if snapshot.dead_holder_observation_digest is None:
            return _decision(
                snapshot,
                "trigger_supervisor",
                "dead_holder_observation_required",
                consequential=True,
            )
        return _decision(
            snapshot,
            "reconcile_lease",
            "expired_lease_reconciliation_required",
            consequential=True,
        )
    if current.holder_id != snapshot.coordinator_id:
        return _decision(snapshot, "idle", "lease_held_by_active_coordinator")
    if expires - now <= _LEASE_RENEWAL_WINDOW:
        return _decision(
            snapshot,
            "renew_lease",
            "coordinator_lease_renewal_required",
            consequential=True,
        )
    return None


def _production_blocker(snapshot: CoordinatorSnapshot, selected: CoordinatorNode) -> str | None:
    if selected.kind not in _PRODUCTION_NODES:
        return None
    authorization = snapshot.production_authorization
    if authorization is None:
        return "protected_production_receipts_required"
    now = _timestamp(snapshot.observed_at, "coordinator_observed_at_invalid")
    verified = _timestamp(authorization.verified_at, "protected_authorization_time_invalid")
    retained = _timestamp(
        authorization.archive_retain_until, "protected_authorization_retention_invalid"
    )
    if authorization.experiment_id != snapshot.experiment_id:
        return "production_experiment_identity_mismatch"
    if authorization.node_kind != selected.kind:
        return "production_node_identity_mismatch"
    if authorization.request_digest != selected.request_digest:
        return "production_request_identity_mismatch"
    if verified > now or now - verified > _MAX_PROTECTED_VERIFICATION_AGE:
        return "protected_verification_stale"
    if retained <= now:
        return "protected_archive_retention_expired"
    if selected.kind == "accept_soak":
        if (
            authorization.merge_commit is None
            or authorization.merge_tree is None
            or authorization.merged_at is None
            or authorization.soak_observation_digest is None
            or authorization.soak_observed_at is None
        ):
            return "merge_bound_soak_required"
        merged = _timestamp(authorization.merged_at, "protected_authorization_merge_invalid")
        observed = _timestamp(
            authorization.soak_observed_at, "protected_authorization_soak_invalid"
        )
        if observed - merged < timedelta(hours=24) or observed != verified:
            return "merge_bound_soak_required"
    return None


def _selected_node(snapshot: CoordinatorSnapshot) -> CoordinatorNode | None:
    active = tuple(item for item in snapshot.nodes if item.status in {"ready", "failed"})
    if snapshot.command is not None:
        matches = tuple(
            item for item in active if item.command_key == snapshot.command.command.command_key
        )
        if len(matches) == 1:
            return matches[0]
        return None
    if not active:
        return None
    return min(active, key=lambda item: (_NODE_PRIORITY[item.kind], item.node_id.encode("utf-8")))


def choose_next_action(snapshot: CoordinatorSnapshot) -> CloudCoordinatorDecision:
    """Select at most one mutation or effect from an independently reconstructed snapshot."""
    if not isinstance(snapshot, CoordinatorSnapshot):
        raise CloudCoordinatorError("coordinator_snapshot_invalid")

    lease_decision = _lease_decision(snapshot)
    if lease_decision is not None:
        return lease_decision

    selected = _selected_node(snapshot)
    if selected is None:
        if snapshot.command is not None:
            return _decision(
                snapshot,
                "trigger_supervisor",
                "command_node_missing",
                consequential=True,
            )
        return _decision(snapshot, "idle", "no_ready_node")

    blocker = _production_blocker(snapshot, selected)
    if blocker is not None:
        return _decision(snapshot, "frozen", blocker, node=selected)

    if snapshot.failure is not None:
        failure = snapshot.failure
        if failure.failed_command_key != selected.command_key:
            return _decision(snapshot, "frozen", "failure_command_mismatch", node=selected)
        if selected.attempt >= selected.max_attempts:
            return _decision(
                snapshot,
                "trigger_supervisor",
                "retry_budget_exhausted",
                node=selected,
                consequential=True,
            )
        if failure.changed_action in failure.prior_changed_actions:
            return _decision(
                snapshot,
                "trigger_supervisor",
                "unchanged_retry_forbidden",
                node=selected,
                consequential=True,
            )
        if failure.next_request_digest == selected.request_digest:
            return _decision(
                snapshot,
                "trigger_supervisor",
                "unchanged_retry_forbidden",
                node=selected,
                consequential=True,
            )
        if failure.next_command_key == selected.command_key:
            return _decision(
                snapshot,
                "trigger_supervisor",
                "unchanged_retry_forbidden",
                node=selected,
                consequential=True,
            )
        retry = selected.command(
            expected_revision=snapshot.revision,
            request_digest=failure.next_request_digest,
            attempt=selected.attempt + 1,
            command_key=failure.next_command_key,
        )
        return _decision(
            snapshot,
            "retry_rework",
            "changed_rework_required",
            node=selected,
            command=retry,
            consequential=True,
        )

    if snapshot.command is None:
        command = selected.command(expected_revision=snapshot.revision)
        return _decision(
            snapshot,
            "persist_command",
            "command_persistence_required",
            node=selected,
            command=command,
            consequential=True,
        )

    state = snapshot.command
    expected = selected.command(expected_revision=state.command.expected_revision)
    if state.command != expected:
        return _decision(snapshot, "frozen", "command_identity_conflict", node=selected)
    if state.status == "pending":
        return _decision(
            snapshot,
            "claim_command",
            "command_claim_required",
            node=selected,
            command=state.command,
            consequential=True,
        )
    if state.status == "failed":
        return _decision(
            snapshot,
            "trigger_supervisor",
            "failed_command_requires_rework",
            node=selected,
            consequential=True,
        )
    if state.status == "completed":
        return _decision(snapshot, "frozen", "completed_command_node_not_advanced", node=selected)

    if state.claim is None:
        return _decision(snapshot, "frozen", "claimed_command_identity_missing", node=selected)
    if _timestamp(state.claim.expires_at, "command_claim_expiry_invalid") <= _timestamp(
        snapshot.observed_at, "coordinator_observed_at_invalid"
    ):
        return _decision(
            snapshot,
            "trigger_supervisor",
            "expired_command_claim_reconciliation_required",
            node=selected,
            consequential=True,
        )
    effect = snapshot.effect
    if effect is not None and effect.effect_key != state.command.effect_key:
        return _decision(snapshot, "frozen", "effect_identity_conflict", node=selected)
    if effect is not None and effect.status == "retry_scheduled":
        retry_at = _timestamp(effect.retry_not_before, "effect_observation_retry_time_invalid")
        observed_at = _timestamp(snapshot.observed_at, "coordinator_observed_at_invalid")
        if observed_at < retry_at:
            return _decision(snapshot, "idle", "effect_retry_not_ready", node=selected)
        return _decision(
            snapshot,
            "reconcile_effect",
            "effect_retry_ready",
            node=selected,
            command=state.command,
            effect_key=state.command.effect_key,
            consequential=True,
            remote_effect=effect_family_for_node(selected.kind) not in {"state", "supervisor"},
        )
    if effect is not None and effect.status == "uncertain":
        return _decision(
            snapshot,
            "reconcile_effect",
            "effect_response_lost",
            node=selected,
            command=state.command,
            effect_key=state.command.effect_key,
            consequential=True,
            remote_effect=effect_family_for_node(selected.kind) not in {"state", "supervisor"},
        )
    if effect is not None and effect.status == "applied":
        return _decision(
            snapshot,
            "complete_command",
            "observed_effect_completion_required",
            node=selected,
            command=state.command,
            effect_key=state.command.effect_key,
            result_digest=effect.result_digest,
            consequential=True,
        )
    return _decision(
        snapshot,
        "execute_effect",
        "persisted_command_ready",
        node=selected,
        command=state.command,
        effect_key=state.command.effect_key,
        consequential=True,
        remote_effect=effect_family_for_node(selected.kind) not in {"state", "supervisor"},
    )


class ProtectedCoordinatorState(Protocol):
    """Service-only durable state surface; ordinary CLI code cannot construct it."""

    def enqueue_pending_graph(self, *, observed_at: datetime) -> bool: ...

    def reconstruct(self, command: str, *, observed_at: datetime) -> CoordinatorSnapshot | None: ...

    def apply(
        self, decision: CloudCoordinatorDecision, *, observed_at: datetime
    ) -> CloudCoordinatorDecision: ...


class ProtectedCoordinatorEffects(Protocol):
    """Fixed typed effect router owned by the activated coordinator service."""

    def execute(
        self, decision: CloudCoordinatorDecision, *, observed_at: datetime
    ) -> CloudCoordinatorDecision: ...


class ProtectedCoordinatorExecutor:
    """Reconstruct and apply exactly one durable transition or protected remote effect."""

    __slots__ = ("__clock", "__effects", "__state")

    def __init__(
        self,
        *,
        state: ProtectedCoordinatorState,
        effects: ProtectedCoordinatorEffects,
        clock: object,
        _testing: bool,
    ) -> None:
        if not _testing or not callable(clock):
            raise CloudCoordinatorError("coordinator_executor_construction_invalid")
        self.__state = state
        self.__effects = effects
        self.__clock = clock

    @classmethod
    def _for_testing(
        cls,
        *,
        state: ProtectedCoordinatorState,
        effects: ProtectedCoordinatorEffects,
        clock: object,
    ) -> ProtectedCoordinatorExecutor:
        return cls(state=state, effects=effects, clock=clock, _testing=True)

    @classmethod
    def _for_protected_service(
        cls,
        *,
        state: ProtectedCoordinatorState,
        effects: ProtectedCoordinatorEffects,
        clock: object,
    ) -> ProtectedCoordinatorExecutor:
        return cls(state=state, effects=effects, clock=clock, _testing=True)

    def advance(self, command: str) -> CloudCoordinatorDecision:
        if command not in _CLOUD_COMMANDS:
            raise CloudCoordinatorError("cloud_command_invalid")
        observed_at = self.__clock()
        if not isinstance(observed_at, datetime) or observed_at.tzinfo != UTC:
            raise CloudCoordinatorError("coordinator_clock_invalid")
        if command == "request":
            enqueue = getattr(self.__state, "enqueue_pending_graph", None)
            if not callable(enqueue):
                raise CloudCoordinatorError("coordinator_enqueue_unavailable")
            enqueued = enqueue(observed_at=observed_at)
            if type(enqueued) is not bool:
                raise CloudCoordinatorError("coordinator_enqueue_invalid")
        snapshot = self.__state.reconstruct(command, observed_at=observed_at)
        if snapshot is None:
            frozen_status = getattr(self.__state, "frozen_status", None)
            if callable(frozen_status) and frozen_status(command, observed_at=observed_at) is True:
                return _empty_queue_decision(command, reason="already_frozen")
            return _empty_queue_decision(command)
        if not isinstance(snapshot, CoordinatorSnapshot):
            raise CloudCoordinatorError("coordinator_snapshot_invalid")
        trusted_time = observed_at.isoformat().replace("+00:00", "Z")
        if snapshot.observed_at != trusted_time:
            raise CloudCoordinatorError("coordinator_snapshot_clock_mismatch")
        decision = choose_next_action(snapshot)
        allowed = _COMMAND_NODES[command]
        if decision.node is not None and decision.node not in allowed:
            return _decision(snapshot, "idle", "no_applicable_node")
        if decision.node is None and command not in {"coordinate", "health"}:
            return _decision(snapshot, "idle", "no_applicable_node")
        if not decision.consequential:
            return decision
        if decision.action in {"execute_effect", "reconcile_effect"}:
            try:
                applied = self.__effects.execute(decision, observed_at=observed_at)
            except Exception as error:
                if not isinstance(error, ProtectedEffectUnavailable):
                    raise
                frozen = _decision(
                    snapshot,
                    "frozen",
                    error.code,
                    node=_selected_node(snapshot),
                    consequential=True,
                )
                applied = self.__state.apply(frozen, observed_at=observed_at)
                if applied != frozen:
                    raise CloudCoordinatorError("coordinator_applied_identity_mismatch") from error
                return frozen
        else:
            applied = self.__state.apply(decision, observed_at=observed_at)
        if _is_atomic_receipt_freeze(applied, expected=decision):
            return applied
        if applied != decision:
            raise CloudCoordinatorError("coordinator_applied_identity_mismatch")
        return decision


def protected_cloud_failure(command: str, reason: str) -> dict[str, object]:
    """Return one public-safe frozen node result without configuration details."""
    if (
        command not in _CLOUD_COMMANDS
        or not isinstance(reason, str)
        or _PUBLIC_FORBIDDEN.search(reason)
    ):
        raise CloudCoordinatorError("cloud_command_invalid")
    identity = hashlib.sha256(
        canonical_json_bytes(
            {
                "action": "frozen",
                "node": command,
                "reason": reason,
                "schema_version": 1,
            }
        )
    ).hexdigest()
    value: dict[str, object] = {
        "action": "frozen",
        "identity": identity,
        "node": command,
        "reason": reason,
        "schema_version": 1,
    }
    _canonical_size(value, maximum=MAX_CLOUD_RESULT_BYTES, code="cloud_result_too_large")
    return value
