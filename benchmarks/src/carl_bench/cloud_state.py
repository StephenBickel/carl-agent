"""Pure, durable cloud-state contracts for adapters and coordinators.

This module deliberately owns no database connection or network client.  It defines the immutable
records and compare-and-swap successor rules a transactional state backend must preserve.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from carl_bench.canonical import CanonicalizationError, canonical_json_bytes

if TYPE_CHECKING:
    from carl_bench.autonomy import AutonomyProjection
    from carl_bench.experiment import ExperimentEvent, ExperimentManifest, ExperimentProjection
    from carl_bench.ledger import AppendResult
    from carl_bench.supervisor_triggers import (
        TriggerMutation,
        TriggerResolution,
    )

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_MEDIA_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$")
_FAILURE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_RETRY_ATTEMPTS = 3
_MAX_SIGNED_CAPABILITY_BYTES = 16_384
_COMMAND_STATUSES = frozenset({"pending", "claimed", "completed", "failed"})
_TRANSITION_STATUSES = frozenset({"completed", "failed"})
_LEASE_AUTHORITIES = frozenset({"coordinator", "supervisor"})
_EVIDENCE_PRODUCERS = frozenset({"validator", "observer"})
_CAPABILITY_SCOPE_KINDS = frozenset({"command", "evidence", "lease", "supervisor_trigger"})
_OPERATIONS_BY_AUTHORITY: dict[str, frozenset[str]] = {
    "builder": frozenset({"register_manifest", "candidate_fact", "publish_experimental"}),
    "validator": frozenset({"append_disposition", "protected_evidence", "register_evidence"}),
    "promoter": frozenset({"record_promotion", "github_effect"}),
    "soak": frozenset({"record_soak", "record_revert", "production_observation"}),
    "supervisor": frozenset({"claim_trigger", "dispatch", "resolve_trigger", "recovery"}),
    "coordinator": frozenset(
        {
            "await_run",
            "blocked",
            "dispatch",
            "download_artifacts",
            "reconcile",
            "record_success",
            "release_lease",
            "schedule",
            "schedule_retry",
        }
    ),
    "observer": frozenset({"observe", "register_evidence"}),
}

CommandStatus = Literal["pending", "claimed", "completed", "failed"]
TransitionStatus = Literal["completed", "failed"]


class CloudStateError(ValueError):
    """A stable domain error that does not expose state or effect contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _key(name: str, value: object) -> str:
    if not isinstance(value, str) or _KEY_RE.fullmatch(value) is None:
        raise CloudStateError(f"invalid_{name}")
    return value


def _digest(name: str, value: object) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise CloudStateError(f"invalid_{name}")
    return value


def _revision(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CloudStateError(f"invalid_{name}")
    return value


def _timestamp(name: str, value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64 or not value.endswith("Z"):
        raise CloudStateError(f"invalid_{name}")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise CloudStateError(f"invalid_{name}") from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise CloudStateError(f"invalid_{name}")
    return parsed


def _canonical_output(value: dict[str, Any]) -> dict[str, Any]:
    try:
        canonical_json_bytes(value)
    except CanonicalizationError as error:
        raise CloudStateError("cloud_state_codec_invalid") from error
    return value


def _canonical_fields(value: object, fields: frozenset[str], code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise CloudStateError(code)
    return _canonical_output(value)


def _bounded_canonical(value: dict[str, Any], code: str) -> bytes:
    try:
        encoded = canonical_json_bytes(value)
    except CanonicalizationError as error:
        raise CloudStateError(code) from error
    if len(encoded) > _MAX_SIGNED_CAPABILITY_BYTES:
        raise CloudStateError("signed_capability_too_large")
    return encoded


def _signature(name: str, value: object) -> bytes:
    if not isinstance(value, str):
        raise CloudStateError(f"invalid_{name}")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise CloudStateError(f"invalid_{name}") from error
    if len(decoded) != 64:
        raise CloudStateError(f"invalid_{name}")
    return decoded


@dataclass(frozen=True, slots=True)
class TrustedAuthorityKey:
    """Pinned public verifier; private signing material never enters production state code."""

    key_id: str
    public_key_pem: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or _KEY_ID_RE.fullmatch(self.key_id) is None:
            raise CloudStateError("invalid_trusted_authority_key_id")
        if not isinstance(self.public_key_pem, bytes):
            raise CloudStateError("trusted_authority_public_key_invalid")
        try:
            key = serialization.load_pem_public_key(self.public_key_pem)
        except (TypeError, ValueError) as error:
            raise CloudStateError("trusted_authority_public_key_invalid") from error
        if not isinstance(key, Ed25519PublicKey):
            raise CloudStateError("trusted_authority_public_key_invalid")

    @property
    def public_key(self) -> Ed25519PublicKey:
        key = serialization.load_pem_public_key(self.public_key_pem)
        if not isinstance(key, Ed25519PublicKey):  # pragma: no cover - constructor guards
            raise CloudStateError("trusted_authority_public_key_invalid")
        return key


def _signed_scope(
    *,
    authority: object,
    subject_id: object,
    scope_kind: object,
    scope_key: object,
    revision: object,
    issued_at: object,
    expires_at: object,
    key_id: object,
    code: str,
) -> None:
    if not isinstance(authority, str) or authority not in _OPERATIONS_BY_AUTHORITY:
        raise CloudStateError(code)
    _key("capability_subject_id", subject_id)
    if not isinstance(scope_kind, str) or scope_kind not in _CAPABILITY_SCOPE_KINDS:
        raise CloudStateError(code)
    _key("capability_scope_key", scope_key)
    _revision("capability_revision", revision)
    issued = _timestamp("capability_issued_at", issued_at)
    if _timestamp("capability_expires_at", expires_at) <= issued:
        raise CloudStateError("invalid_capability_expiry")
    if not isinstance(key_id, str) or _KEY_ID_RE.fullmatch(key_id) is None:
        raise CloudStateError("invalid_capability_key_id")


@dataclass(frozen=True, slots=True)
class AuthorityCapability:
    schema_version: int
    authority: str
    subject_id: str
    scope_kind: str
    scope_key: str
    revision: int
    issued_at: str
    expires_at: str
    key_id: str
    signature_base64: str

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or self.schema_version != 1:
            raise CloudStateError("invalid_authority_capability_schema")
        _signed_scope(
            authority=self.authority,
            subject_id=self.subject_id,
            scope_kind=self.scope_kind,
            scope_key=self.scope_key,
            revision=self.revision,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            key_id=self.key_id,
            code="invalid_authority_capability",
        )
        _signature("authority_capability_signature", self.signature_base64)

    def _payload(self) -> dict[str, Any]:
        return {
            "authority": self.authority,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "key_id": self.key_id,
            "revision": self.revision,
            "schema_version": self.schema_version,
            "scope_key": self.scope_key,
            "scope_kind": self.scope_kind,
            "subject_id": self.subject_id,
        }

    def signing_payload(self) -> bytes:
        return _bounded_canonical(self._payload(), "invalid_authority_capability")

    def to_canonical_dict(self) -> dict[str, Any]:
        value = {name: getattr(self, name) for name in self.__dataclass_fields__}
        _bounded_canonical(value, "invalid_authority_capability")
        return value

    @classmethod
    def from_canonical_dict(cls, value: object) -> AuthorityCapability:
        decoded = _canonical_fields(
            value, frozenset(cls.__dataclass_fields__), "invalid_authority_capability"
        )
        _bounded_canonical(decoded, "invalid_authority_capability")
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudStateError("invalid_authority_capability") from error


@dataclass(frozen=True, slots=True)
class DeadHolderObservation:
    schema_version: int
    authority: str
    subject_id: str
    scope_kind: str
    scope_key: str
    revision: int
    issued_at: str
    observed_at: str
    expires_at: str
    live: bool
    key_id: str
    signature_base64: str

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or self.schema_version != 1:
            raise CloudStateError("invalid_dead_holder_observation_schema")
        _signed_scope(
            authority=self.authority,
            subject_id=self.subject_id,
            scope_kind=self.scope_kind,
            scope_key=self.scope_key,
            revision=self.revision,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            key_id=self.key_id,
            code="invalid_dead_holder_observation",
        )
        observed = _timestamp("dead_holder_observed_at", self.observed_at)
        if observed < _timestamp("capability_issued_at", self.issued_at):
            raise CloudStateError("dead_holder_observation_precedes_issue")
        if not isinstance(self.live, bool):
            raise CloudStateError("invalid_dead_holder_liveness")
        _signature("dead_holder_observation_signature", self.signature_base64)

    def _payload(self) -> dict[str, Any]:
        return {
            "authority": self.authority,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "key_id": self.key_id,
            "live": self.live,
            "observed_at": self.observed_at,
            "revision": self.revision,
            "schema_version": self.schema_version,
            "scope_key": self.scope_key,
            "scope_kind": self.scope_kind,
            "subject_id": self.subject_id,
        }

    def signing_payload(self) -> bytes:
        return _bounded_canonical(self._payload(), "invalid_dead_holder_observation")

    @property
    def digest(self) -> str:
        return hashlib.sha256(
            _bounded_canonical(self.to_canonical_dict(), "invalid_dead_holder_observation")
        ).hexdigest()

    def to_canonical_dict(self) -> dict[str, Any]:
        value = {name: getattr(self, name) for name in self.__dataclass_fields__}
        _bounded_canonical(value, "invalid_dead_holder_observation")
        return value

    @classmethod
    def from_canonical_dict(cls, value: object) -> DeadHolderObservation:
        decoded = _canonical_fields(
            value, frozenset(cls.__dataclass_fields__), "invalid_dead_holder_observation"
        )
        _bounded_canonical(decoded, "invalid_dead_holder_observation")
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudStateError("invalid_dead_holder_observation") from error


_VERIFIED_AUTHORITY_TOKEN = object()
_VERIFIED_DEAD_HOLDER_TOKEN = object()


class VerifiedAuthority:
    """Opaque post-verification capability; only the local verifier can construct it."""

    __slots__ = ("capability",)

    def __init__(self, capability: AuthorityCapability, *, _token: object) -> None:
        if _token is not _VERIFIED_AUTHORITY_TOKEN:
            raise CloudStateError("verified_authority_factory_required")
        self.capability = capability


class VerifiedDeadHolderObservation:
    """Opaque post-verification dead-holder observation."""

    __slots__ = ("observation",)

    def __init__(self, observation: DeadHolderObservation, *, _token: object) -> None:
        if _token is not _VERIFIED_DEAD_HOLDER_TOKEN:
            raise CloudStateError("verified_dead_holder_factory_required")
        self.observation = observation

    @property
    def digest(self) -> str:
        return self.observation.digest


def _verify_signed(
    *, payload: bytes, key_id: str, signature_base64: str, trusted_key: TrustedAuthorityKey
) -> None:
    if not isinstance(trusted_key, TrustedAuthorityKey):
        raise CloudStateError("trusted_authority_key_missing")
    if key_id != trusted_key.key_id:
        raise CloudStateError("trusted_authority_key_mismatch")
    try:
        trusted_key.public_key.verify(base64.b64decode(signature_base64, validate=True), payload)
    except (InvalidSignature, ValueError, binascii.Error) as error:
        raise CloudStateError("trusted_authority_signature_invalid") from error


def verify_authority_capability(
    capability: AuthorityCapability, *, trusted_key: TrustedAuthorityKey, observed_at: str
) -> VerifiedAuthority:
    if not isinstance(capability, AuthorityCapability):
        raise CloudStateError("invalid_authority_capability")
    observed = _timestamp("capability_verification_time", observed_at)
    if (
        not _timestamp("capability_issued_at", capability.issued_at)
        <= observed
        < _timestamp("capability_expires_at", capability.expires_at)
    ):
        raise CloudStateError("authority_capability_expired")
    _verify_signed(
        payload=capability.signing_payload(),
        key_id=capability.key_id,
        signature_base64=capability.signature_base64,
        trusted_key=trusted_key,
    )
    return VerifiedAuthority(capability, _token=_VERIFIED_AUTHORITY_TOKEN)


def verify_dead_holder_observation(
    observation: DeadHolderObservation, *, trusted_key: TrustedAuthorityKey, observed_at: str
) -> VerifiedDeadHolderObservation:
    if not isinstance(observation, DeadHolderObservation):
        raise CloudStateError("invalid_dead_holder_observation")
    observed = _timestamp("dead_holder_verification_time", observed_at)
    if (
        not _timestamp("capability_issued_at", observation.issued_at)
        <= observed
        < _timestamp("capability_expires_at", observation.expires_at)
    ):
        raise CloudStateError("dead_holder_observation_expired")
    if observation.live:
        raise CloudStateError("dead_holder_observation_live")
    _verify_signed(
        payload=observation.signing_payload(),
        key_id=observation.key_id,
        signature_base64=observation.signature_base64,
        trusted_key=trusted_key,
    )
    return VerifiedDeadHolderObservation(observation, _token=_VERIFIED_DEAD_HOLDER_TOKEN)


def _require_capability(
    capability: VerifiedAuthority,
    *,
    authority: str,
    subject_id: str,
    scope_kind: str,
    scope_key: str,
    revision: int,
    observed_at: str,
) -> None:
    if not isinstance(capability, VerifiedAuthority):
        raise CloudStateError("verified_authority_required")
    item = capability.capability
    if (
        item.authority != authority
        or item.subject_id != subject_id
        or item.scope_kind != scope_kind
        or item.scope_key != scope_key
        or item.revision != revision
    ):
        raise CloudStateError("authority_capability_mismatch")
    observed = _timestamp("capability_use_time", observed_at)
    if (
        not _timestamp("capability_issued_at", item.issued_at)
        <= observed
        < _timestamp("capability_expires_at", item.expires_at)
    ):
        raise CloudStateError("authority_capability_expired")


def _require_dead_holder(
    dead_holder: VerifiedDeadHolderObservation,
    *,
    authority: str,
    subject_id: str,
    scope_kind: str,
    scope_key: str,
    revision: int,
    observed_at: str,
) -> DeadHolderObservation:
    if not isinstance(dead_holder, VerifiedDeadHolderObservation):
        raise CloudStateError("verified_dead_holder_required")
    item = dead_holder.observation
    if (
        item.authority != authority
        or item.subject_id != subject_id
        or item.scope_kind != scope_kind
        or item.scope_key != scope_key
        or item.revision != revision
        or item.live
        or item.observed_at != observed_at
    ):
        raise CloudStateError("dead_holder_observation_mismatch")
    return item


def _effect_key(*, command_key: str, authority: str, operation: str, request_digest: str) -> str:
    payload = {
        "authority": authority,
        "command_key": command_key,
        "operation": operation,
        "request_digest": request_digest,
    }
    return f"cloud-effect-{hashlib.sha256(canonical_json_bytes(payload)).hexdigest()}"


def _authorized_operation(authority: object, operation: object) -> tuple[str, str]:
    if not isinstance(authority, str) or authority not in _OPERATIONS_BY_AUTHORITY:
        raise CloudStateError("invalid_command_authority")
    if not isinstance(operation, str) or operation not in _OPERATIONS_BY_AUTHORITY[authority]:
        raise CloudStateError("command_authority_denied")
    return authority, operation


@dataclass(frozen=True, slots=True)
class CloudCommand:
    """One exact effect request that must be persisted before the external effect."""

    schema_version: int
    command_key: str
    effect_key: str
    authority: str
    operation: str
    request_digest: str
    occurred_at: str
    expected_revision: int
    attempt: int
    max_attempts: int

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or self.schema_version != 1:
            raise CloudStateError("invalid_command_schema")
        _key("command_key", self.command_key)
        authority, operation = _authorized_operation(self.authority, self.operation)
        _digest("command_request_digest", self.request_digest)
        _timestamp("command_occurred_at", self.occurred_at)
        _revision("command_expected_revision", self.expected_revision)
        for name in ("attempt", "max_attempts"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= _MAX_RETRY_ATTEMPTS
            ):
                raise CloudStateError(f"invalid_command_{name}")
        if self.attempt > self.max_attempts:
            raise CloudStateError("command_attempt_exceeds_max")
        if self.effect_key != _effect_key(
            command_key=self.command_key,
            authority=authority,
            operation=operation,
            request_digest=self.request_digest,
        ):
            raise CloudStateError("command_effect_key_mismatch")

    @classmethod
    def create(
        cls,
        *,
        command_key: str,
        authority: str,
        operation: str,
        request_digest: str,
        occurred_at: str,
        expected_revision: int,
        attempt: int,
        max_attempts: int,
    ) -> CloudCommand:
        return cls(
            schema_version=1,
            command_key=command_key,
            effect_key=_effect_key(
                command_key=command_key,
                authority=authority,
                operation=operation,
                request_digest=request_digest,
            ),
            authority=authority,
            operation=operation,
            request_digest=request_digest,
            occurred_at=occurred_at,
            expected_revision=expected_revision,
            attempt=attempt,
            max_attempts=max_attempts,
        )

    def to_canonical_dict(self) -> dict[str, Any]:
        return _canonical_output({name: getattr(self, name) for name in self.__dataclass_fields__})

    @classmethod
    def from_canonical_dict(cls, value: object) -> CloudCommand:
        decoded = _canonical_fields(value, frozenset(cls.__dataclass_fields__), "invalid_command")
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudStateError("invalid_command") from error


@dataclass(frozen=True, slots=True)
class CommandClaim:
    command_key: str
    claim_id: str
    authority: str
    expected_revision: int
    claimed_at: str
    expires_at: str

    def __post_init__(self) -> None:
        _key("claim_command_key", self.command_key)
        _key("claim_id", self.claim_id)
        if not isinstance(self.authority, str) or self.authority not in _OPERATIONS_BY_AUTHORITY:
            raise CloudStateError("invalid_claim_authority")
        _revision("claim_expected_revision", self.expected_revision)
        if _timestamp("claim_expires_at", self.expires_at) <= _timestamp(
            "claim_claimed_at", self.claimed_at
        ):
            raise CloudStateError("invalid_claim_expiry")

    def to_canonical_dict(self) -> dict[str, Any]:
        return _canonical_output({name: getattr(self, name) for name in self.__dataclass_fields__})

    @classmethod
    def from_canonical_dict(cls, value: object) -> CommandClaim:
        decoded = _canonical_fields(
            value, frozenset(cls.__dataclass_fields__), "invalid_command_claim"
        )
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudStateError("invalid_command_claim") from error


@dataclass(frozen=True, slots=True)
class ClaimReconciliation:
    command_key: str
    claim_id: str
    authority: str
    expected_revision: int
    next_revision: int
    observed_at: str

    def __post_init__(self) -> None:
        _key("reconciliation_command_key", self.command_key)
        _key("reconciliation_claim_id", self.claim_id)
        if not isinstance(self.authority, str) or self.authority not in _OPERATIONS_BY_AUTHORITY:
            raise CloudStateError("invalid_reconciliation_authority")
        expected_revision = _revision("reconciliation_expected_revision", self.expected_revision)
        if _revision("reconciliation_next_revision", self.next_revision) != expected_revision + 1:
            raise CloudStateError("reconciliation_revision_invalid")
        _timestamp("reconciliation_observed_at", self.observed_at)

    def to_canonical_dict(self) -> dict[str, Any]:
        return _canonical_output({name: getattr(self, name) for name in self.__dataclass_fields__})

    @classmethod
    def from_canonical_dict(cls, value: object) -> ClaimReconciliation:
        decoded = _canonical_fields(
            value, frozenset(cls.__dataclass_fields__), "invalid_claim_reconciliation"
        )
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudStateError("invalid_claim_reconciliation") from error


@dataclass(frozen=True, slots=True)
class StateTransition:
    command_key: str
    authority: str
    claim_id: str
    expected_revision: int
    next_revision: int
    status: TransitionStatus
    occurred_at: str
    result_digest: str | None
    failure_code: str | None

    def __post_init__(self) -> None:
        _key("transition_command_key", self.command_key)
        _key("transition_claim_id", self.claim_id)
        if not isinstance(self.authority, str) or self.authority not in _OPERATIONS_BY_AUTHORITY:
            raise CloudStateError("invalid_transition_authority")
        expected_revision = _revision("transition_expected_revision", self.expected_revision)
        if _revision("transition_next_revision", self.next_revision) != expected_revision + 1:
            raise CloudStateError("transition_revision_invalid")
        if not isinstance(self.status, str) or self.status not in _TRANSITION_STATUSES:
            raise CloudStateError("invalid_transition_status")
        _timestamp("transition_occurred_at", self.occurred_at)
        if self.status == "completed":
            _digest("transition_result_digest", self.result_digest)
            if self.failure_code is not None:
                raise CloudStateError("completed_transition_has_failure")
        else:
            if self.result_digest is not None:
                raise CloudStateError("failed_transition_has_result")
            if (
                not isinstance(self.failure_code, str)
                or _FAILURE_RE.fullmatch(self.failure_code) is None
            ):
                raise CloudStateError("invalid_transition_failure")

    def to_canonical_dict(self) -> dict[str, Any]:
        return _canonical_output({name: getattr(self, name) for name in self.__dataclass_fields__})

    @classmethod
    def from_canonical_dict(cls, value: object) -> StateTransition:
        decoded = _canonical_fields(
            value, frozenset(cls.__dataclass_fields__), "invalid_transition"
        )
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudStateError("invalid_transition") from error


@dataclass(frozen=True, slots=True)
class CommandState:
    """The command record as atomically read or written by a backend."""

    command: CloudCommand
    revision: int
    status: CommandStatus
    claim: CommandClaim | None
    transition: StateTransition | None
    result_digest: str | None
    failure_code: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.command, CloudCommand):
            raise CloudStateError("invalid_state_command")
        revision = _revision("state_revision", self.revision)
        if not isinstance(self.status, str) or self.status not in _COMMAND_STATUSES:
            raise CloudStateError("invalid_state_status")
        if self.status == "pending":
            if (
                revision < self.command.expected_revision
                or self.claim is not None
                or self.transition is not None
                or self.result_digest is not None
                or self.failure_code is not None
            ):
                raise CloudStateError("invalid_pending_command_state")
            return
        if not isinstance(self.claim, CommandClaim):
            raise CloudStateError("invalid_state_claim")
        if self.claim.command_key != self.command.command_key:
            raise CloudStateError("state_claim_command_mismatch")
        if self.claim.authority != self.command.authority:
            raise CloudStateError("command_authority_denied")
        if self.status == "claimed":
            if (
                revision != self.claim.expected_revision + 1
                or self.transition is not None
                or self.result_digest is not None
                or self.failure_code is not None
            ):
                raise CloudStateError("invalid_claimed_command_state")
            return
        if not isinstance(self.transition, StateTransition):
            raise CloudStateError("invalid_state_transition")
        if (
            self.transition.command_key != self.command.command_key
            or self.transition.claim_id != self.claim.claim_id
            or self.transition.authority != self.command.authority
            or self.transition.next_revision != revision
            or self.transition.status != self.status
            or self.transition.expected_revision != self.claim.expected_revision + 1
        ):
            raise CloudStateError("state_transition_mismatch")
        if (
            self.result_digest != self.transition.result_digest
            or self.failure_code != self.transition.failure_code
        ):
            raise CloudStateError("state_result_mismatch")

    def to_canonical_dict(self) -> dict[str, Any]:
        return _canonical_output(
            {
                "claim": None if self.claim is None else self.claim.to_canonical_dict(),
                "command": self.command.to_canonical_dict(),
                "failure_code": self.failure_code,
                "result_digest": self.result_digest,
                "revision": self.revision,
                "status": self.status,
                "transition": (
                    None if self.transition is None else self.transition.to_canonical_dict()
                ),
            }
        )

    @classmethod
    def from_canonical_dict(cls, value: object) -> CommandState:
        decoded = _canonical_fields(
            value, frozenset(cls.__dataclass_fields__), "invalid_command_state"
        )
        try:
            claim = decoded["claim"]
            transition = decoded["transition"]
            return cls(
                command=CloudCommand.from_canonical_dict(decoded["command"]),
                revision=decoded["revision"],
                status=decoded["status"],
                claim=None if claim is None else CommandClaim.from_canonical_dict(claim),
                transition=None
                if transition is None
                else StateTransition.from_canonical_dict(transition),
                result_digest=decoded["result_digest"],
                failure_code=decoded["failure_code"],
            )
        except (KeyError, TypeError) as error:
            raise CloudStateError("invalid_command_state") from error


@dataclass(frozen=True, slots=True)
class CloudLease:
    lease_key: str
    holder_id: str
    authority: str
    revision: int
    acquired_at: str
    expires_at: str
    reconciled_at: str | None = None
    reconciliation_observation_digest: str | None = None
    released_at: str | None = None

    def __post_init__(self) -> None:
        _key("lease_key", self.lease_key)
        _key("lease_holder_id", self.holder_id)
        if not isinstance(self.authority, str) or self.authority not in _LEASE_AUTHORITIES:
            raise CloudStateError("lease_authority_denied")
        _revision("lease_revision", self.revision)
        if _timestamp("lease_expires_at", self.expires_at) <= _timestamp(
            "lease_acquired_at", self.acquired_at
        ):
            raise CloudStateError("invalid_lease_expiry")
        reconciliation = (self.reconciled_at, self.reconciliation_observation_digest)
        if any(item is None for item in reconciliation) and any(
            item is not None for item in reconciliation
        ):
            raise CloudStateError("invalid_lease_reconciliation")
        if self.reconciled_at is not None:
            if _timestamp("lease_reconciled_at", self.reconciled_at) < _timestamp(
                "lease_expires_at", self.expires_at
            ):
                raise CloudStateError("lease_reconciliation_precedes_expiry")
            _digest(
                "lease_reconciliation_observation_digest",
                self.reconciliation_observation_digest,
            )
        if self.released_at is not None:
            _timestamp("lease_released_at", self.released_at)

    @property
    def status(self) -> Literal["active", "reconciled", "released"]:
        if self.released_at is not None:
            return "released"
        if self.reconciled_at is not None:
            return "reconciled"
        return "active"

    def to_canonical_dict(self) -> dict[str, Any]:
        return _canonical_output({name: getattr(self, name) for name in self.__dataclass_fields__})

    @classmethod
    def from_canonical_dict(cls, value: object) -> CloudLease:
        decoded = _canonical_fields(
            value, frozenset(cls.__dataclass_fields__), "invalid_cloud_lease"
        )
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudStateError("invalid_cloud_lease") from error


@dataclass(frozen=True, slots=True)
class LeaseReconciliation:
    lease_key: str
    holder_id: str
    authority: str
    expected_revision: int
    next_revision: int
    observed_at: str

    def __post_init__(self) -> None:
        _key("lease_reconciliation_key", self.lease_key)
        _key("lease_reconciliation_holder_id", self.holder_id)
        if not isinstance(self.authority, str) or self.authority not in _LEASE_AUTHORITIES:
            raise CloudStateError("lease_authority_denied")
        expected_revision = _revision(
            "lease_reconciliation_expected_revision", self.expected_revision
        )
        if (
            _revision("lease_reconciliation_next_revision", self.next_revision)
            != expected_revision + 1
        ):
            raise CloudStateError("lease_reconciliation_revision_invalid")
        _timestamp("lease_reconciliation_observed_at", self.observed_at)

    def to_canonical_dict(self) -> dict[str, Any]:
        return _canonical_output({name: getattr(self, name) for name in self.__dataclass_fields__})

    @classmethod
    def from_canonical_dict(cls, value: object) -> LeaseReconciliation:
        decoded = _canonical_fields(
            value, frozenset(cls.__dataclass_fields__), "invalid_lease_reconciliation"
        )
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudStateError("invalid_lease_reconciliation") from error


@dataclass(frozen=True, slots=True)
class LeaseRelease:
    lease_key: str
    holder_id: str
    authority: str
    expected_revision: int
    next_revision: int
    released_at: str
    observation_digest: str | None

    def __post_init__(self) -> None:
        _key("lease_release_key", self.lease_key)
        _key("lease_release_holder_id", self.holder_id)
        if not isinstance(self.authority, str) or self.authority not in _LEASE_AUTHORITIES:
            raise CloudStateError("lease_authority_denied")
        expected_revision = _revision("lease_release_expected_revision", self.expected_revision)
        if _revision("lease_release_next_revision", self.next_revision) != expected_revision + 1:
            raise CloudStateError("lease_release_revision_invalid")
        _timestamp("lease_released_at", self.released_at)
        if self.observation_digest is not None:
            _digest("lease_release_observation_digest", self.observation_digest)

    def to_canonical_dict(self) -> dict[str, Any]:
        return _canonical_output({name: getattr(self, name) for name in self.__dataclass_fields__})

    @classmethod
    def from_canonical_dict(cls, value: object) -> LeaseRelease:
        decoded = _canonical_fields(
            value, frozenset(cls.__dataclass_fields__), "invalid_lease_release"
        )
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudStateError("invalid_lease_release") from error


@dataclass(frozen=True, slots=True)
class EvidenceObject:
    digest: str
    object_key: str
    object_version: str
    producer: str
    request_digest: str
    media_type: str
    retained_until: str

    def __post_init__(self) -> None:
        digest = _digest("evidence_digest", self.digest)
        if self.object_key != f"evidence/{digest}":
            raise CloudStateError("evidence_object_key_mismatch")
        if (
            not isinstance(self.object_version, str)
            or _VERSION_RE.fullmatch(self.object_version) is None
        ):
            raise CloudStateError("invalid_evidence_object_version")
        if not isinstance(self.producer, str) or self.producer not in _EVIDENCE_PRODUCERS:
            raise CloudStateError("evidence_authority_denied")
        _digest("evidence_request_digest", self.request_digest)
        if (
            not isinstance(self.media_type, str)
            or _MEDIA_TYPE_RE.fullmatch(self.media_type) is None
        ):
            raise CloudStateError("invalid_evidence_media_type")
        _timestamp("evidence_retained_until", self.retained_until)

    def to_canonical_dict(self) -> dict[str, Any]:
        return _canonical_output({name: getattr(self, name) for name in self.__dataclass_fields__})

    @classmethod
    def from_canonical_dict(cls, value: object) -> EvidenceObject:
        decoded = _canonical_fields(
            value, frozenset(cls.__dataclass_fields__), "invalid_evidence_object"
        )
        try:
            return cls(**decoded)
        except TypeError as error:
            raise CloudStateError("invalid_evidence_object") from error


def authorize_evidence(
    evidence: EvidenceObject, *, capability: VerifiedAuthority, observed_at: str
) -> EvidenceObject:
    """Require a signed, scope-bound authority capability before evidence is persisted."""
    if not isinstance(evidence, EvidenceObject):
        raise CloudStateError("invalid_evidence_object")
    _require_capability(
        capability,
        authority=evidence.producer,
        subject_id=evidence.object_version,
        scope_kind="evidence",
        scope_key=evidence.object_key,
        revision=0,
        observed_at=observed_at,
    )
    return evidence


@dataclass(frozen=True, slots=True)
class HealthSnapshot:
    observed_at: str
    healthy: bool
    detail_digest: str

    def __post_init__(self) -> None:
        _timestamp("health_observed_at", self.observed_at)
        if not isinstance(self.healthy, bool):
            raise CloudStateError("invalid_health_status")
        _digest("health_detail_digest", self.detail_digest)


@dataclass(frozen=True, slots=True)
class CommandMutation:
    applied: bool
    state: CommandState

    def __post_init__(self) -> None:
        if not isinstance(self.applied, bool) or not isinstance(self.state, CommandState):
            raise CloudStateError("invalid_command_mutation")


@dataclass(frozen=True, slots=True)
class LeaseMutation:
    applied: bool
    lease: CloudLease | None
    revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.applied, bool) or (
            self.lease is not None and not isinstance(self.lease, CloudLease)
        ):
            raise CloudStateError("invalid_lease_mutation")
        _revision("lease_mutation_revision", self.revision)


def create_command_state(command: CloudCommand) -> CommandState:
    if not isinstance(command, CloudCommand):
        raise CloudStateError("invalid_command")
    return CommandState(
        command=command,
        revision=command.expected_revision,
        status="pending",
        claim=None,
        transition=None,
        result_digest=None,
        failure_code=None,
    )


def replay_command(persisted: CloudCommand, replay: CloudCommand) -> CloudCommand:
    """Return the first persisted command, preserving its occurrence timestamp on replay."""
    if not isinstance(persisted, CloudCommand) or not isinstance(replay, CloudCommand):
        raise CloudStateError("invalid_command")
    if persisted.command_key != replay.command_key:
        raise CloudStateError("command_replay_key_mismatch")
    identity = (
        "schema_version",
        "effect_key",
        "authority",
        "operation",
        "request_digest",
        "expected_revision",
        "attempt",
        "max_attempts",
    )
    if any(getattr(persisted, name) != getattr(replay, name) for name in identity):
        raise CloudStateError("command_replay_conflict")
    return persisted


def claim_command(
    state: CommandState,
    claim: CommandClaim,
    *,
    capability: VerifiedAuthority,
    observed_at: str,
) -> CommandState:
    if not isinstance(state, CommandState) or not isinstance(claim, CommandClaim):
        raise CloudStateError("invalid_command_claim")
    if state.command.command_key != claim.command_key:
        raise CloudStateError("claim_command_mismatch")
    if state.command.authority != claim.authority:
        raise CloudStateError("command_authority_denied")
    _require_capability(
        capability,
        authority=state.command.authority,
        subject_id=claim.claim_id,
        scope_kind="command",
        scope_key=state.command.command_key,
        revision=state.revision,
        observed_at=observed_at,
    )
    if _timestamp("claim_observed_at", observed_at) >= _timestamp(
        "claim_expires_at", claim.expires_at
    ):
        raise CloudStateError("command_claim_expired")
    if state.status == "claimed" and state.claim == claim:
        return state
    if state.status != "pending":
        raise CloudStateError("command_not_claimable")
    if state.revision != claim.expected_revision:
        raise CloudStateError("command_cas_mismatch")
    return CommandState(
        command=state.command,
        revision=state.revision + 1,
        status="claimed",
        claim=claim,
        transition=None,
        result_digest=None,
        failure_code=None,
    )


def _terminal_successor(
    state: CommandState,
    transition: StateTransition,
    expected_status: TransitionStatus,
    *,
    capability: VerifiedAuthority,
    observed_at: str,
) -> CommandState:
    if not isinstance(state, CommandState) or not isinstance(transition, StateTransition):
        raise CloudStateError("invalid_state_transition")
    if transition.status != expected_status:
        raise CloudStateError("transition_status_mismatch")
    if state.status == expected_status:
        _require_capability(
            capability,
            authority=state.command.authority,
            subject_id=state.claim.claim_id if state.claim is not None else transition.claim_id,
            scope_kind="command",
            scope_key=state.command.command_key,
            revision=transition.expected_revision,
            observed_at=observed_at,
        )
        if state.claim is not None and _timestamp(
            "terminal_observed_at", observed_at
        ) >= _timestamp("claim_expires_at", state.claim.expires_at):
            raise CloudStateError("command_claim_expired")
        if state.transition == transition:
            return state
        if expected_status == "completed":
            raise CloudStateError("command_result_conflict")
        raise CloudStateError("command_failure_conflict")
    if state.status != "claimed" or state.claim is None:
        raise CloudStateError("command_not_completable")
    if (
        transition.command_key != state.command.command_key
        or transition.claim_id != state.claim.claim_id
        or transition.authority != state.command.authority
    ):
        raise CloudStateError("transition_claim_mismatch")
    if transition.expected_revision != state.claim.expected_revision + 1:
        raise CloudStateError("transition_claim_revision_mismatch")
    if transition.expected_revision != state.revision:
        raise CloudStateError("command_cas_mismatch")
    _require_capability(
        capability,
        authority=state.command.authority,
        subject_id=state.claim.claim_id if state.claim is not None else transition.claim_id,
        scope_kind="command",
        scope_key=state.command.command_key,
        revision=transition.expected_revision,
        observed_at=observed_at,
    )
    if state.claim is not None and _timestamp("terminal_observed_at", observed_at) >= _timestamp(
        "claim_expires_at", state.claim.expires_at
    ):
        raise CloudStateError("command_claim_expired")
    return CommandState(
        command=state.command,
        revision=transition.next_revision,
        status=transition.status,
        claim=state.claim,
        transition=transition,
        result_digest=transition.result_digest,
        failure_code=transition.failure_code,
    )


def complete_command(
    state: CommandState,
    transition: StateTransition,
    *,
    capability: VerifiedAuthority,
    observed_at: str,
) -> CommandState:
    return _terminal_successor(
        state, transition, "completed", capability=capability, observed_at=observed_at
    )


def fail_command(
    state: CommandState,
    transition: StateTransition,
    *,
    capability: VerifiedAuthority,
    observed_at: str,
) -> CommandState:
    return _terminal_successor(
        state, transition, "failed", capability=capability, observed_at=observed_at
    )


def reconcile_expired_claim(
    state: CommandState,
    reconciliation: ClaimReconciliation,
    *,
    capability: VerifiedAuthority,
    dead_holder: VerifiedDeadHolderObservation,
) -> CommandState:
    """Fence an expired claim with independently authenticated dead-worker evidence."""
    if not isinstance(state, CommandState) or not isinstance(reconciliation, ClaimReconciliation):
        raise CloudStateError("invalid_claim_reconciliation")
    if state.status != "claimed" or state.claim is None:
        raise CloudStateError("command_not_reconcilable")
    if (
        reconciliation.command_key != state.command.command_key
        or reconciliation.claim_id != state.claim.claim_id
        or reconciliation.authority != state.command.authority
    ):
        raise CloudStateError("claim_reconciliation_mismatch")
    if reconciliation.expected_revision != state.revision:
        raise CloudStateError("command_cas_mismatch")
    _require_capability(
        capability,
        authority=state.command.authority,
        subject_id=state.claim.claim_id,
        scope_kind="command",
        scope_key=state.command.command_key,
        revision=reconciliation.expected_revision,
        observed_at=reconciliation.observed_at,
    )
    if _timestamp("reconciliation_observed_at", reconciliation.observed_at) < _timestamp(
        "claim_expires_at", state.claim.expires_at
    ):
        raise CloudStateError("command_claim_active")
    _require_dead_holder(
        dead_holder,
        authority=state.command.authority,
        subject_id=state.claim.claim_id,
        scope_kind="command",
        scope_key=state.command.command_key,
        revision=reconciliation.expected_revision,
        observed_at=reconciliation.observed_at,
    )
    return CommandState(
        command=state.command,
        revision=reconciliation.next_revision,
        status="pending",
        claim=None,
        transition=None,
        result_digest=None,
        failure_code=None,
    )


def lease_expired(lease: CloudLease, *, observed_at: str) -> bool:
    if not isinstance(lease, CloudLease):
        raise CloudStateError("invalid_cloud_lease")
    return _timestamp("lease_observed_at", observed_at) >= _timestamp(
        "lease_expires_at", lease.expires_at
    )


def acquire_lease(
    current: CloudLease | None,
    desired: CloudLease,
    *,
    capability: VerifiedAuthority,
    observed_at: str,
) -> CloudLease:
    if (current is not None and not isinstance(current, CloudLease)) or not isinstance(
        desired, CloudLease
    ):
        raise CloudStateError("invalid_cloud_lease")
    observed = _timestamp("lease_observed_at", observed_at)
    _require_capability(
        capability,
        authority=desired.authority,
        subject_id=desired.holder_id,
        scope_kind="lease",
        scope_key=desired.lease_key,
        revision=desired.revision,
        observed_at=observed_at,
    )
    if _timestamp("lease_desired_acquired_at", desired.acquired_at) < observed:
        raise CloudStateError("lease_acquisition_precedes_observation")
    if current is not None:
        if current.lease_key != desired.lease_key or current.authority != desired.authority:
            raise CloudStateError("lease_identity_mismatch")
        if desired.revision != current.revision:
            raise CloudStateError("lease_cas_mismatch")
        if current.status == "active" and not lease_expired(current, observed_at=observed_at):
            raise CloudStateError("lease_active")
        if current.status == "active":
            raise CloudStateError("lease_reconciliation_required")
        if current.status == "reconciled":
            raise CloudStateError("lease_release_required")
    elif desired.revision != 0:
        raise CloudStateError("lease_cas_mismatch")
    return CloudLease(
        lease_key=desired.lease_key,
        holder_id=desired.holder_id,
        authority=desired.authority,
        revision=desired.revision + 1,
        acquired_at=desired.acquired_at,
        expires_at=desired.expires_at,
    )


def reconcile_lease(
    lease: CloudLease,
    reconciliation: LeaseReconciliation,
    *,
    capability: VerifiedAuthority,
    dead_holder: VerifiedDeadHolderObservation,
) -> CloudLease:
    """Mark an expired lease reconciled only after trusted dead-worker observation."""
    if not isinstance(lease, CloudLease) or not isinstance(reconciliation, LeaseReconciliation):
        raise CloudStateError("invalid_lease_reconciliation")
    if (
        lease.status != "active"
        or reconciliation.lease_key != lease.lease_key
        or reconciliation.holder_id != lease.holder_id
        or reconciliation.authority != lease.authority
    ):
        raise CloudStateError("lease_reconciliation_mismatch")
    if reconciliation.expected_revision != lease.revision:
        raise CloudStateError("lease_cas_mismatch")
    _require_capability(
        capability,
        authority=lease.authority,
        subject_id=lease.holder_id,
        scope_kind="lease",
        scope_key=lease.lease_key,
        revision=reconciliation.expected_revision,
        observed_at=reconciliation.observed_at,
    )
    if _timestamp("lease_reconciliation_observed_at", reconciliation.observed_at) < _timestamp(
        "lease_expires_at", lease.expires_at
    ):
        raise CloudStateError("lease_active")
    observation = _require_dead_holder(
        dead_holder,
        authority=lease.authority,
        subject_id=lease.holder_id,
        scope_kind="lease",
        scope_key=lease.lease_key,
        revision=reconciliation.expected_revision,
        observed_at=reconciliation.observed_at,
    )
    return CloudLease(
        lease_key=lease.lease_key,
        holder_id=lease.holder_id,
        authority=lease.authority,
        revision=reconciliation.next_revision,
        acquired_at=lease.acquired_at,
        expires_at=lease.expires_at,
        reconciled_at=reconciliation.observed_at,
        reconciliation_observation_digest=observation.digest,
    )


def release_lease(
    lease: CloudLease, release: LeaseRelease, *, capability: VerifiedAuthority
) -> CloudLease:
    if not isinstance(lease, CloudLease) or not isinstance(release, LeaseRelease):
        raise CloudStateError("invalid_cloud_lease")
    if (
        lease.status == "released"
        or release.lease_key != lease.lease_key
        or release.holder_id != lease.holder_id
        or release.authority != lease.authority
    ):
        raise CloudStateError("lease_release_mismatch")
    if release.expected_revision != lease.revision:
        raise CloudStateError("lease_cas_mismatch")
    _require_capability(
        capability,
        authority=lease.authority,
        subject_id=lease.holder_id,
        scope_kind="lease",
        scope_key=lease.lease_key,
        revision=release.expected_revision,
        observed_at=release.released_at,
    )
    if lease.status == "reconciled":
        if release.observation_digest != lease.reconciliation_observation_digest:
            raise CloudStateError("lease_release_evidence_mismatch")
    elif release.observation_digest is not None:
        raise CloudStateError("lease_release_evidence_unexpected")
    return CloudLease(
        lease_key=lease.lease_key,
        holder_id=lease.holder_id,
        authority=lease.authority,
        revision=release.next_revision,
        acquired_at=lease.acquired_at,
        expires_at=lease.expires_at,
        reconciled_at=lease.reconciled_at,
        reconciliation_observation_digest=lease.reconciliation_observation_digest,
        released_at=release.released_at,
    )


class StateBackend(Protocol):
    """Transactional persistence boundary implemented by the cloud state adapter."""

    def register_manifest(
        self, manifest: ExperimentManifest, *, capability: VerifiedAuthority
    ) -> bool: ...

    def append_event(
        self, event: ExperimentEvent, *, capability: VerifiedAuthority
    ) -> AppendResult: ...

    def create_command(
        self, command: CloudCommand, *, capability: VerifiedAuthority
    ) -> CommandMutation: ...

    def claim_command(
        self, claim: CommandClaim, *, capability: VerifiedAuthority, observed_at: str
    ) -> CommandMutation: ...

    def complete_command(
        self, transition: StateTransition, *, capability: VerifiedAuthority, observed_at: str
    ) -> CommandMutation: ...

    def fail_command(
        self, transition: StateTransition, *, capability: VerifiedAuthority, observed_at: str
    ) -> CommandMutation: ...

    def reconcile_expired_claim(
        self,
        reconciliation: ClaimReconciliation,
        *,
        capability: VerifiedAuthority,
        dead_holder: VerifiedDeadHolderObservation,
    ) -> CommandMutation: ...

    def acquire_lease(
        self, desired: CloudLease, *, capability: VerifiedAuthority, observed_at: str
    ) -> LeaseMutation: ...

    def reconcile_lease(
        self,
        reconciliation: LeaseReconciliation,
        *,
        capability: VerifiedAuthority,
        dead_holder: VerifiedDeadHolderObservation,
    ) -> LeaseMutation: ...

    def release_lease(
        self, release: LeaseRelease, *, capability: VerifiedAuthority
    ) -> LeaseMutation: ...

    def claim_supervisor_trigger(
        self,
        *,
        trigger_id: str,
        claim_id: str,
        expected_revision: int,
        capability: VerifiedAuthority,
    ) -> TriggerMutation: ...

    def resolve_supervisor_trigger(
        self,
        *,
        trigger_id: str,
        claim_id: str,
        expected_revision: int,
        resolution: TriggerResolution,
        capability: VerifiedAuthority,
    ) -> TriggerMutation: ...

    def load_projection(
        self, experiment_id: str
    ) -> tuple[ExperimentProjection, AutonomyProjection]: ...

    def register_evidence(
        self, evidence: EvidenceObject, *, capability: VerifiedAuthority
    ) -> bool: ...

    def health_snapshot(self) -> HealthSnapshot: ...
