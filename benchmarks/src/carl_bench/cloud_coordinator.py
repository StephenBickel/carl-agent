"""Pure restart-safe orchestration decisions for Carl's cloud improvement graph.

The coordinator reconstructs only canonical durable facts and returns one bounded decision.  It
does not own provider clients, credentials, model policy, or local execution fallbacks.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

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
EffectStatus = Literal["none", "uncertain", "applied"]
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

_NODE_ORDER = (
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
_NODE_PRIORITY = {name: index for index, name in enumerate(_NODE_ORDER)}
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
_CLOUD_INPUT_ENV = "CARL_CLOUD_COMMAND_INPUT_B64"


class CloudCoordinatorError(ValueError):
    """Stable orchestration failure that never includes private payloads."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


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
        _digest(self.request_digest, "coordinator_node_request_digest_invalid")
        _timestamp(self.occurred_at, "coordinator_node_occurred_at_invalid")
        try:
            self.command(expected_revision=0)
        except CloudStateError as error:
            raise CloudCoordinatorError("coordinator_node_command_invalid") from error

    @property
    def command_key(self) -> str:
        return f"{self.node_id}:attempt:{self.attempt}"

    @property
    def effect_key(self) -> str:
        return self.command(expected_revision=0).effect_key

    def command(
        self,
        *,
        expected_revision: int,
        request_digest: str | None = None,
        attempt: int | None = None,
    ) -> CloudCommand:
        selected_attempt = self.attempt if attempt is None else attempt
        selected_digest = self.request_digest if request_digest is None else request_digest
        return CloudCommand.create(
            command_key=f"{self.node_id}:attempt:{selected_attempt}",
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

    def __post_init__(self) -> None:
        _identifier(self.effect_key, "effect_observation_key_invalid")
        if self.status not in {"none", "uncertain", "applied"}:
            raise CloudCoordinatorError("effect_observation_status_invalid")
        _timestamp(self.observed_at, "effect_observation_time_invalid")
        if self.status == "applied":
            _digest(self.result_digest, "effect_observation_result_invalid")
        elif self.result_digest is not None:
            raise CloudCoordinatorError("effect_observation_result_unexpected")

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
        _digest(self.next_request_digest, "coordinator_failure_request_digest_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "changed_action": self.changed_action,
            "failed_command_key": self.failed_command_key,
            "failure_code": self.failure_code,
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
                next_request_digest=decoded["next_request_digest"],
            )
        except (KeyError, TypeError) as error:
            raise CloudCoordinatorError("coordinator_failure_invalid") from error


@dataclass(frozen=True, slots=True)
class ProductionEvidence:
    protected_archive_receipt: bool
    verified_at: str
    archive_retain_until: str
    protected_live_model_provenance: bool
    independent_disposition: bool
    required_checks_passed: bool
    branch_protection_current: bool
    merge_bound_soak: bool
    synthetic: bool

    def __post_init__(self) -> None:
        for name in (
            "protected_archive_receipt",
            "protected_live_model_provenance",
            "independent_disposition",
            "required_checks_passed",
            "branch_protection_current",
            "merge_bound_soak",
            "synthetic",
        ):
            if type(getattr(self, name)) is not bool:
                raise CloudCoordinatorError("production_evidence_invalid")
        _timestamp(self.verified_at, "production_evidence_verified_at_invalid")
        if _timestamp(
            self.archive_retain_until, "production_evidence_retention_invalid"
        ) <= _timestamp(self.verified_at, "production_evidence_verified_at_invalid"):
            raise CloudCoordinatorError("production_evidence_retention_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_canonical_dict(cls, value: object) -> ProductionEvidence:
        decoded = _strict_fields(
            value, frozenset(cls.__dataclass_fields__), "production_evidence_invalid"
        )
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudCoordinatorError("production_evidence_invalid") from error


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
    production_evidence: ProductionEvidence | None
    immutable_inputs: tuple[ImmutableInputBinding, ...]
    dead_holder_observation_digest: str | None

    def __post_init__(self) -> None:
        if self.schema_version != 1:
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
        if self.production_evidence is not None and not isinstance(
            self.production_evidence, ProductionEvidence
        ):
            raise CloudCoordinatorError("production_evidence_invalid")
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
            "production_evidence": (
                None
                if self.production_evidence is None
                else self.production_evidence.to_canonical_dict()
            ),
            "revision": self.revision,
            "schema_version": self.schema_version,
        }


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
            production_evidence=(
                None
                if decoded["production_evidence"] is None
                else ProductionEvidence.from_canonical_dict(decoded["production_evidence"])
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
        if self.schema_version != 1 or self.action not in {
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
        }:
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
    evidence = snapshot.production_evidence
    if evidence is None:
        return "protected_evidence_required"
    now = _timestamp(snapshot.observed_at, "coordinator_observed_at_invalid")
    verified = _timestamp(evidence.verified_at, "production_evidence_verified_at_invalid")
    retained = _timestamp(evidence.archive_retain_until, "production_evidence_retention_invalid")
    if evidence.synthetic:
        return "synthetic_evidence_forbidden"
    if not evidence.protected_archive_receipt:
        return "protected_archive_receipt_required"
    if verified > now or now - verified > _MAX_PROTECTED_VERIFICATION_AGE:
        return "protected_verification_stale"
    if retained <= now:
        return "protected_archive_retention_expired"
    if not evidence.protected_live_model_provenance:
        return "protected_live_model_required"
    if not evidence.independent_disposition:
        return "independent_disposition_required"
    if not evidence.required_checks_passed:
        return "required_checks_incomplete"
    if not evidence.branch_protection_current:
        return "branch_protection_drift"
    if selected.kind == "accept_soak" and not evidence.merge_bound_soak:
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
            return _decision(snapshot, "frozen", "command_node_missing")
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
        retry = selected.command(
            expected_revision=snapshot.revision,
            request_digest=failure.next_request_digest,
            attempt=selected.attempt + 1,
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
    if effect is not None and effect.status == "uncertain":
        return _decision(
            snapshot,
            "reconcile_effect",
            "effect_response_lost",
            node=selected,
            command=state.command,
            effect_key=state.command.effect_key,
            consequential=True,
            remote_effect=True,
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
        remote_effect=True,
    )


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


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CloudCoordinatorError("cloud_command_input_invalid")
        value[key] = item
    return value


def _protected_command_snapshot(command: str) -> CoordinatorSnapshot | None:
    encoded = os.environ.get(_CLOUD_INPUT_ENV)
    if encoded is None:
        return None
    if not isinstance(encoded, str) or not 1 <= len(encoded) <= 1_500_000:
        raise CloudCoordinatorError("cloud_command_input_invalid")
    try:
        payload = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as error:
        raise CloudCoordinatorError("cloud_command_input_invalid") from error
    if base64.b64encode(payload).decode("ascii") != encoded or not payload:
        raise CloudCoordinatorError("cloud_command_input_invalid")
    if len(payload) > MAX_COORDINATOR_SNAPSHOT_BYTES:
        raise CloudCoordinatorError("cloud_command_input_invalid")
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (
        CloudCoordinatorError,
        UnicodeError,
        json.JSONDecodeError,
        RecursionError,
    ) as error:
        raise CloudCoordinatorError("cloud_command_input_invalid") from error
    if type(value) is not dict or canonical_json_bytes(value) != payload:
        raise CloudCoordinatorError("cloud_command_input_invalid")
    decoded = _strict_fields(
        value,
        frozenset({"command", "schema_version", "snapshot"}),
        "cloud_command_input_invalid",
    )
    if decoded["schema_version"] != 1:
        raise CloudCoordinatorError("cloud_command_input_invalid")
    if decoded["command"] != command:
        raise CloudCoordinatorError("cloud_command_input_mismatch")
    return reconstruct_snapshot(decoded["snapshot"])


def run_protected_cloud_command(command: str) -> dict[str, object]:
    """Reconstruct one protected snapshot and emit exactly one safe-node decision.

    No caller-selected endpoint, model, tool, command, credential, or evidence path is accepted.
    The cloud workflow supplies one bounded canonical environment envelope reconstructed from the
    durable state service.  Missing or invalid input freezes only this node and never falls back to
    local heavy execution.
    """
    if command not in _CLOUD_COMMANDS:
        raise CloudCoordinatorError("cloud_command_invalid")
    try:
        snapshot = _protected_command_snapshot(command)
        if snapshot is None:
            return protected_cloud_failure(command, "cloud_configuration_unavailable")
        decision = choose_next_action(snapshot)
        if decision.node is not None and decision.node not in _COMMAND_NODES[command]:
            return protected_cloud_failure(command, "cloud_command_node_mismatch")
        if decision.node is None and command not in {"coordinate", "health"}:
            return protected_cloud_failure(command, "cloud_command_node_mismatch")
        return decision.to_canonical_dict()
    except CloudCoordinatorError as error:
        reason = (
            error.code
            if error.code
            in {
                "cloud_command_input_invalid",
                "cloud_command_input_mismatch",
            }
            else "cloud_command_input_invalid"
        )
        return protected_cloud_failure(command, reason)
