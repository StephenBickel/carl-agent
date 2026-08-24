"""Pure, durable cloud-state contracts for adapters and coordinators.

This module deliberately owns no database connection or network client.  It defines the immutable
records and compare-and-swap successor rules a transactional state backend must preserve.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, final

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
_CAPABILITY_SCOPE_KINDS = frozenset(
    {
        "command",
        "dead_holder_observation",
        "evidence",
        "event",
        "health",
        "lease",
        "manifest",
        "supervisor_trigger",
    }
)
_CAPABILITY_ACTIONS = frozenset(
    {
        "append_event",
        "acquire_lease",
        "claim_command",
        "claim_supervisor_trigger",
        "complete_command",
        "complete_command_with_event",
        "create_command",
        "fail_command",
        "reconcile_expired_claim",
        "reconcile_lease",
        "record_health",
        "register_evidence",
        "register_dead_holder_observation",
        "register_manifest",
        "release_lease",
        "resolve_supervisor_trigger",
    }
)
_AUTHORITY_CAPABILITY_DOMAIN = "carl.cloud-state.authority-capability.v1"
_DEAD_HOLDER_OBSERVATION_DOMAIN = "carl.cloud-state.dead-holder-observation.v1"
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
    if base64.b64encode(decoded).decode("ascii") != value:
        raise CloudStateError(f"invalid_{name}")
    return decoded


@dataclass(frozen=True, slots=True)
class TrustedAuthorityKey:
    """Pinned public verifier; private signing material never enters production state code."""

    key_id: str
    purpose: Literal["authority_capability", "dead_holder_observation"]
    public_key_pem: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.key_id, str) or _KEY_ID_RE.fullmatch(self.key_id) is None:
            raise CloudStateError("invalid_trusted_authority_key_id")
        if self.purpose not in {"authority_capability", "dead_holder_observation"}:
            raise CloudStateError("invalid_trusted_authority_key_purpose")
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
    action: str
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
        if not isinstance(self.action, str) or self.action not in _CAPABILITY_ACTIONS:
            raise CloudStateError("invalid_authority_capability_action")
        _signature("authority_capability_signature", self.signature_base64)

    def _payload(self) -> dict[str, Any]:
        return {
            "domain": _AUTHORITY_CAPABILITY_DOMAIN,
            "action": self.action,
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
            "domain": _DEAD_HOLDER_OBSERVATION_DOMAIN,
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


def _verify_signed(
    *,
    payload: bytes,
    key_id: str,
    signature_base64: str,
    trusted_key: TrustedAuthorityKey,
    purpose: Literal["authority_capability", "dead_holder_observation"],
) -> None:
    if not isinstance(trusted_key, TrustedAuthorityKey):
        raise CloudStateError("trusted_authority_key_missing")
    if key_id != trusted_key.key_id or trusted_key.purpose != purpose:
        raise CloudStateError("trusted_authority_key_mismatch")
    try:
        trusted_key.public_key.verify(
            _signature("signed_envelope_signature", signature_base64), payload
        )
    except (InvalidSignature, ValueError, binascii.Error) as error:
        raise CloudStateError("trusted_authority_signature_invalid") from error


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AuthorityVerifier:
    """Immutable controller-owned verifier for raw signed envelopes and trusted time.

    Hostile arbitrary code already executing in the trusted controller process is outside this
    boundary; Python reflection can bypass ordinary object access controls in that environment.
    """

    __slots__ = ("_authority_key", "_clock", "_dead_holder_key")

    def __init__(
        self,
        *,
        authority_key: TrustedAuthorityKey,
        dead_holder_key: TrustedAuthorityKey,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not callable(clock):
            raise CloudStateError("trusted_clock_required")
        if not isinstance(authority_key, TrustedAuthorityKey) or not isinstance(
            dead_holder_key, TrustedAuthorityKey
        ):
            raise CloudStateError("trusted_authority_key_missing")
        if authority_key.purpose != "authority_capability":
            raise CloudStateError("trusted_authority_key_mismatch")
        if dead_holder_key.purpose != "dead_holder_observation":
            raise CloudStateError("trusted_authority_key_mismatch")
        authority_key_bytes = authority_key.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        dead_holder_key_bytes = dead_holder_key.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if (
            authority_key.key_id == dead_holder_key.key_id
            or authority_key_bytes == dead_holder_key_bytes
        ):
            raise CloudStateError("trusted_authority_keys_not_separated")
        object.__setattr__(self, "_authority_key", authority_key)
        object.__setattr__(self, "_dead_holder_key", dead_holder_key)
        object.__setattr__(self, "_clock", clock)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("AuthorityVerifier is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("AuthorityVerifier is immutable")

    def __copy__(self) -> AuthorityVerifier:
        raise TypeError("AuthorityVerifier cannot be copied or serialized")

    def __deepcopy__(self, memo: object) -> AuthorityVerifier:
        raise TypeError("AuthorityVerifier cannot be copied or serialized")

    def __reduce__(self) -> object:
        raise TypeError("AuthorityVerifier cannot be copied or serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("AuthorityVerifier cannot be copied or serialized")

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo != UTC:
            raise CloudStateError("trusted_clock_invalid")
        return now

    def now(self) -> datetime:
        """Return the verifier's controller-owned UTC clock for state-time checks."""
        return self._now()

    def require_authority(
        self,
        capability: AuthorityCapability,
        *,
        action: str,
        authority: str,
        subject_id: str,
        scope_kind: str,
        scope_key: str,
        revision: int,
    ) -> None:
        self._require_authority_at(
            capability,
            now=self._now(),
            action=action,
            authority=authority,
            subject_id=subject_id,
            scope_kind=scope_kind,
            scope_key=scope_key,
            revision=revision,
        )

    def _require_authority_at(
        self,
        capability: AuthorityCapability,
        *,
        now: datetime,
        action: str,
        authority: str,
        subject_id: str,
        scope_kind: str,
        scope_key: str,
        revision: int,
    ) -> None:
        if not isinstance(capability, AuthorityCapability):
            raise CloudStateError("invalid_authority_capability")
        issued = _timestamp("capability_issued_at", capability.issued_at)
        expires = _timestamp("capability_expires_at", capability.expires_at)
        if now < issued:
            raise CloudStateError("authority_capability_not_yet_valid")
        if now >= expires:
            raise CloudStateError("authority_capability_expired")
        _verify_signed(
            payload=capability.signing_payload(),
            key_id=capability.key_id,
            signature_base64=capability.signature_base64,
            trusted_key=self._authority_key,
            purpose="authority_capability",
        )
        if (
            capability.action != action
            or capability.authority != authority
            or capability.subject_id != subject_id
            or capability.scope_kind != scope_kind
            or capability.scope_key != scope_key
            or capability.revision != revision
        ):
            raise CloudStateError("authority_capability_mismatch")

    def require_dead_holder(
        self,
        observation: DeadHolderObservation,
        *,
        authority: str,
        subject_id: str,
        scope_kind: str,
        scope_key: str,
        revision: int,
    ) -> DeadHolderObservation:
        return self._require_dead_holder_at(
            observation,
            now=self._now(),
            authority=authority,
            subject_id=subject_id,
            scope_kind=scope_kind,
            scope_key=scope_key,
            revision=revision,
        )

    def _require_dead_holder_at(
        self,
        observation: DeadHolderObservation,
        *,
        now: datetime,
        authority: str,
        subject_id: str,
        scope_kind: str,
        scope_key: str,
        revision: int,
    ) -> DeadHolderObservation:
        if not isinstance(observation, DeadHolderObservation):
            raise CloudStateError("invalid_dead_holder_observation")
        issued = _timestamp("capability_issued_at", observation.issued_at)
        observed = _timestamp("dead_holder_observed_at", observation.observed_at)
        expires = _timestamp("capability_expires_at", observation.expires_at)
        if now < issued or now < observed:
            raise CloudStateError("dead_holder_observation_future")
        if now >= expires:
            raise CloudStateError("dead_holder_observation_expired")
        if observation.live:
            raise CloudStateError("dead_holder_observation_live")
        _verify_signed(
            payload=observation.signing_payload(),
            key_id=observation.key_id,
            signature_base64=observation.signature_base64,
            trusted_key=self._dead_holder_key,
            purpose="dead_holder_observation",
        )
        if (
            observation.authority != authority
            or observation.subject_id != subject_id
            or observation.scope_kind != scope_kind
            or observation.scope_key != scope_key
            or observation.revision != revision
        ):
            raise CloudStateError("dead_holder_observation_mismatch")
        return observation


def _require_capability(
    verifier: AuthorityVerifier,
    capability: AuthorityCapability,
    *,
    action: str,
    authority: str,
    subject_id: str,
    scope_kind: str,
    scope_key: str,
    revision: int,
    now: datetime,
) -> None:
    if type(verifier) is not AuthorityVerifier:
        raise CloudStateError("authority_verifier_required")
    verifier._require_authority_at(
        capability,
        now=now,
        action=action,
        authority=authority,
        subject_id=subject_id,
        scope_kind=scope_kind,
        scope_key=scope_key,
        revision=revision,
    )


def _require_dead_holder(
    verifier: AuthorityVerifier,
    dead_holder: DeadHolderObservation,
    *,
    authority: str,
    subject_id: str,
    scope_kind: str,
    scope_key: str,
    revision: int,
    now: datetime,
) -> DeadHolderObservation:
    if type(verifier) is not AuthorityVerifier:
        raise CloudStateError("authority_verifier_required")
    return verifier._require_dead_holder_at(
        dead_holder,
        now=now,
        authority=authority,
        subject_id=subject_id,
        scope_kind=scope_kind,
        scope_key=scope_key,
        revision=revision,
    )


def _mutation_time(verifier: AuthorityVerifier) -> datetime:
    if type(verifier) is not AuthorityVerifier:
        raise CloudStateError("authority_verifier_required")
    return verifier._now()


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
    evidence: EvidenceObject, *, verifier: AuthorityVerifier, capability: AuthorityCapability
) -> EvidenceObject:
    """Require a signed, scope-bound authority capability before evidence is persisted."""
    if not isinstance(evidence, EvidenceObject):
        raise CloudStateError("invalid_evidence_object")
    observed = _mutation_time(verifier)
    _require_capability(
        verifier,
        capability,
        action="register_evidence",
        authority=evidence.producer,
        subject_id=evidence.object_version,
        scope_kind="evidence",
        scope_key=evidence.object_key,
        revision=0,
        now=observed,
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
    verifier: AuthorityVerifier,
    capability: AuthorityCapability,
) -> CommandState:
    if not isinstance(state, CommandState) or not isinstance(claim, CommandClaim):
        raise CloudStateError("invalid_command_claim")
    if state.command.command_key != claim.command_key:
        raise CloudStateError("claim_command_mismatch")
    if state.command.authority != claim.authority:
        raise CloudStateError("command_authority_denied")
    observed = _mutation_time(verifier)
    _require_capability(
        verifier,
        capability,
        action="claim_command",
        authority=state.command.authority,
        subject_id=claim.claim_id,
        scope_kind="command",
        scope_key=state.command.command_key,
        revision=state.revision,
        now=observed,
    )
    if observed >= _timestamp("claim_expires_at", claim.expires_at):
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
    verifier: AuthorityVerifier,
    capability: AuthorityCapability,
    action: Literal["complete_command", "fail_command"],
) -> CommandState:
    if not isinstance(state, CommandState) or not isinstance(transition, StateTransition):
        raise CloudStateError("invalid_state_transition")
    if transition.status != expected_status:
        raise CloudStateError("transition_status_mismatch")
    observed = _mutation_time(verifier)
    if state.status == expected_status:
        _require_capability(
            verifier,
            capability,
            action=action,
            authority=state.command.authority,
            subject_id=state.claim.claim_id if state.claim is not None else transition.claim_id,
            scope_kind="command",
            scope_key=state.command.command_key,
            revision=transition.expected_revision,
            now=observed,
        )
        if state.claim is not None and observed >= _timestamp(
            "claim_expires_at", state.claim.expires_at
        ):
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
        verifier,
        capability,
        action=action,
        authority=state.command.authority,
        subject_id=state.claim.claim_id if state.claim is not None else transition.claim_id,
        scope_kind="command",
        scope_key=state.command.command_key,
        revision=transition.expected_revision,
        now=observed,
    )
    if state.claim is not None and observed >= _timestamp(
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
    verifier: AuthorityVerifier,
    capability: AuthorityCapability,
) -> CommandState:
    return _terminal_successor(
        state,
        transition,
        "completed",
        verifier=verifier,
        capability=capability,
        action="complete_command",
    )


def fail_command(
    state: CommandState,
    transition: StateTransition,
    *,
    verifier: AuthorityVerifier,
    capability: AuthorityCapability,
) -> CommandState:
    return _terminal_successor(
        state, transition, "failed", verifier=verifier, capability=capability, action="fail_command"
    )


def reconcile_expired_claim(
    state: CommandState,
    reconciliation: ClaimReconciliation,
    *,
    verifier: AuthorityVerifier,
    capability: AuthorityCapability,
    dead_holder: DeadHolderObservation,
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
    observed = _mutation_time(verifier)
    _require_capability(
        verifier,
        capability,
        action="reconcile_expired_claim",
        authority=state.command.authority,
        subject_id=state.claim.claim_id,
        scope_kind="command",
        scope_key=state.command.command_key,
        revision=reconciliation.expected_revision,
        now=observed,
    )
    if observed < _timestamp("claim_expires_at", state.claim.expires_at):
        raise CloudStateError("command_claim_active")
    _require_dead_holder(
        verifier,
        dead_holder,
        authority=state.command.authority,
        subject_id=state.claim.claim_id,
        scope_kind="command",
        scope_key=state.command.command_key,
        revision=reconciliation.expected_revision,
        now=observed,
    )
    if reconciliation.observed_at != dead_holder.observed_at:
        raise CloudStateError("dead_holder_observation_mismatch")
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
    verifier: AuthorityVerifier,
    capability: AuthorityCapability,
) -> CloudLease:
    if (current is not None and not isinstance(current, CloudLease)) or not isinstance(
        desired, CloudLease
    ):
        raise CloudStateError("invalid_cloud_lease")
    observed = _mutation_time(verifier)
    _require_capability(
        verifier,
        capability,
        action="acquire_lease",
        authority=desired.authority,
        subject_id=desired.holder_id,
        scope_kind="lease",
        scope_key=desired.lease_key,
        revision=desired.revision,
        now=observed,
    )
    if _timestamp("lease_desired_acquired_at", desired.acquired_at) < observed:
        raise CloudStateError("lease_acquisition_precedes_observation")
    if current is not None:
        if current.lease_key != desired.lease_key or current.authority != desired.authority:
            raise CloudStateError("lease_identity_mismatch")
        if desired.revision != current.revision:
            raise CloudStateError("lease_cas_mismatch")
        if current.status == "active" and not lease_expired(
            current, observed_at=observed.isoformat().replace("+00:00", "Z")
        ):
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
    verifier: AuthorityVerifier,
    capability: AuthorityCapability,
    dead_holder: DeadHolderObservation,
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
    observed = _mutation_time(verifier)
    _require_capability(
        verifier,
        capability,
        action="reconcile_lease",
        authority=lease.authority,
        subject_id=lease.holder_id,
        scope_kind="lease",
        scope_key=lease.lease_key,
        revision=reconciliation.expected_revision,
        now=observed,
    )
    if observed < _timestamp("lease_expires_at", lease.expires_at):
        raise CloudStateError("lease_active")
    observation = _require_dead_holder(
        verifier,
        dead_holder,
        authority=lease.authority,
        subject_id=lease.holder_id,
        scope_kind="lease",
        scope_key=lease.lease_key,
        revision=reconciliation.expected_revision,
        now=observed,
    )
    if reconciliation.observed_at != observation.observed_at:
        raise CloudStateError("dead_holder_observation_mismatch")
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
    lease: CloudLease,
    release: LeaseRelease,
    *,
    verifier: AuthorityVerifier,
    capability: AuthorityCapability,
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
    observed = _mutation_time(verifier)
    _require_capability(
        verifier,
        capability,
        action="release_lease",
        authority=lease.authority,
        subject_id=lease.holder_id,
        scope_kind="lease",
        scope_key=lease.lease_key,
        revision=release.expected_revision,
        now=observed,
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


_BACKEND_MUTATIONS = frozenset(
    {
        "register_manifest",
        "append_event",
        "register_dead_holder_observation",
        "create_command",
        "claim_command",
        "complete_command",
        "complete_command_with_event",
        "fail_command",
        "reconcile_expired_claim",
        "acquire_lease",
        "reconcile_lease",
        "release_lease",
        "claim_supervisor_trigger",
        "resolve_supervisor_trigger",
        "register_evidence",
        "record_health",
    }
)
_BACKEND_ENFORCEMENT_MEMBERS = frozenset(
    {
        "_StateBackend__verifier",
        "_authorize",
        "_verifier",
        "__delattr__",
        "__getattribute__",
        "__init__",
        "__init_subclass__",
        "__setattr__",
        "verifier",
    }
)


def _backend_verifier(backend: StateBackend) -> AuthorityVerifier:
    verifier = object.__getattribute__(backend, "_StateBackend__verifier")
    if type(verifier) is not AuthorityVerifier:
        raise CloudStateError("authority_verifier_required")
    return verifier


_EVENTS_BY_AUTHORITY = {
    "builder": frozenset(
        {"role_recorded", "workspace_prepared", "candidate_sealed", "experimental_published"}
    ),
    "validator": frozenset(
        {
            "paired_evidence_recorded",
            "review_packet_recorded",
            "review_attested",
            "protected_validation_recorded",
        }
    ),
    "promoter": frozenset(
        {"draft_pr_requested", "draft_pr_recorded", "workspace_disposed", "promotion_recorded"}
    ),
    "soak": frozenset({"soak_observed", "revert_recorded", "state_transitioned"}),
    "coordinator": frozenset(
        {
            "state_transitioned",
            "lease_acquired",
            "lease_reconciled",
            "lease_released",
            "live_spend_recorded",
            "retry_scheduled",
        }
    ),
}


def _event_authority_allowed(authority: str, event: ExperimentEvent) -> bool:
    event_type = getattr(getattr(event, "event_type", None), "value", None)
    if event_type not in _EVENTS_BY_AUTHORITY.get(authority, frozenset()):
        return False
    if authority == "soak" and event_type == "state_transitioned":
        payload = getattr(event, "payload", None)
        return (
            isinstance(payload, dict)
            and payload.get("from_state") == "soaking"
            and payload.get("to_state") == "accepted"
        )
    return True


class StateBackend(ABC):
    """Authorized template-method boundary for transactional state adapters.

    Public mutation wrappers are final and cannot be replaced by adapters. They capture trusted
    time once, verify the exact signed action and object scope, then delegate storage only to the
    corresponding protected hook. Hostile code already executing inside the controller process is
    outside this ordinary Python object boundary.
    """

    __slots__ = ("__verifier",)

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        boundary_index = cls.__mro__.index(StateBackend)
        adapter_layers = cls.__mro__[:boundary_index]
        mutation_overrides = frozenset().union(
            *(_BACKEND_MUTATIONS.intersection(layer.__dict__) for layer in adapter_layers)
        )
        if mutation_overrides:
            names = ", ".join(sorted(mutation_overrides))
            raise TypeError(f"cannot override authorized mutation: {names}")
        enforcement_overrides = frozenset().union(
            *(_BACKEND_ENFORCEMENT_MEMBERS.intersection(layer.__dict__) for layer in adapter_layers)
        )
        if enforcement_overrides:
            names = ", ".join(sorted(enforcement_overrides))
            raise TypeError(f"cannot override backend enforcement: {names}")

    def __init__(self, *, verifier: AuthorityVerifier) -> None:
        if type(verifier) is not AuthorityVerifier:
            raise CloudStateError("authority_verifier_required")
        object.__setattr__(self, "_StateBackend__verifier", verifier)

    def __setattr__(self, name: str, value: object) -> None:
        if name in {"_StateBackend__verifier", "_verifier", "verifier"}:
            raise AttributeError("StateBackend verifier is immutable")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if name in {"_StateBackend__verifier", "_verifier", "verifier"}:
            raise AttributeError("StateBackend verifier is immutable")
        object.__delattr__(self, name)

    @property
    def verifier(self) -> AuthorityVerifier:
        return _backend_verifier(self)

    def _authorize(
        self,
        capability: AuthorityCapability,
        *,
        action: str,
        authority: str,
        subject_id: str,
        scope_kind: str,
        scope_key: str,
        revision: int,
        now: datetime,
    ) -> None:
        _require_capability(
            _backend_verifier(self),
            capability,
            action=action,
            authority=authority,
            subject_id=subject_id,
            scope_kind=scope_kind,
            scope_key=scope_key,
            revision=revision,
            now=now,
        )

    @final
    def register_manifest(
        self, manifest: ExperimentManifest, *, capability: AuthorityCapability
    ) -> bool:
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="register_manifest",
            authority="builder",
            subject_id=manifest.experiment_id,
            scope_kind="manifest",
            scope_key=manifest.experiment_id,
            revision=0,
            now=now,
        )
        return self._register_manifest(manifest, observed_at=now)

    @final
    def append_event(
        self, event: ExperimentEvent, *, capability: AuthorityCapability
    ) -> AppendResult:
        if not isinstance(capability, AuthorityCapability):
            raise CloudStateError("invalid_authority_capability")
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="append_event",
            authority=capability.authority,
            subject_id=event.stage_attempt_id,
            scope_kind="event",
            scope_key=event.experiment_id,
            revision=0,
            now=now,
        )
        if not _event_authority_allowed(capability.authority, event):
            raise CloudStateError("event_authority_denied")
        return self._append_event(event, observed_at=now)

    @final
    def register_dead_holder_observation(
        self,
        observation: DeadHolderObservation,
        *,
        capability: AuthorityCapability,
    ) -> bool:
        """Persist an observer-signed non-live fact before any reconciliation can consume it."""
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="register_dead_holder_observation",
            authority="observer",
            subject_id=observation.digest,
            scope_kind="dead_holder_observation",
            scope_key=observation.digest,
            revision=observation.revision,
            now=now,
        )
        verified = _require_dead_holder(
            _backend_verifier(self),
            observation,
            authority=observation.authority,
            subject_id=observation.subject_id,
            scope_kind=observation.scope_kind,
            scope_key=observation.scope_key,
            revision=observation.revision,
            now=now,
        )
        return self._register_dead_holder_observation(verified, observed_at=now)

    @final
    def create_command(
        self, command: CloudCommand, *, capability: AuthorityCapability
    ) -> CommandMutation:
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="create_command",
            authority=command.authority,
            subject_id=command.effect_key,
            scope_kind="command",
            scope_key=command.command_key,
            revision=command.expected_revision,
            now=now,
        )
        return self._create_command(command, observed_at=now)

    @final
    def claim_command(
        self, claim: CommandClaim, *, capability: AuthorityCapability
    ) -> CommandMutation:
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="claim_command",
            authority=claim.authority,
            subject_id=claim.claim_id,
            scope_kind="command",
            scope_key=claim.command_key,
            revision=claim.expected_revision,
            now=now,
        )
        return self._claim_command(claim, observed_at=now)

    @final
    def complete_command(
        self, transition: StateTransition, *, capability: AuthorityCapability
    ) -> CommandMutation:
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="complete_command",
            authority=transition.authority,
            subject_id=transition.claim_id,
            scope_kind="command",
            scope_key=transition.command_key,
            revision=transition.expected_revision,
            now=now,
        )
        return self._complete_command(transition, observed_at=now)

    @final
    def complete_command_with_event(
        self,
        transition: StateTransition,
        event: ExperimentEvent,
        *,
        command_capability: AuthorityCapability,
        event_capability: AuthorityCapability,
    ) -> tuple[CommandMutation, AppendResult]:
        """Complete a command and append its authorized outcome at one storage boundary."""
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            command_capability,
            action="complete_command_with_event",
            authority=transition.authority,
            subject_id=transition.claim_id,
            scope_kind="command",
            scope_key=transition.command_key,
            revision=transition.expected_revision,
            now=now,
        )
        StateBackend._authorize(
            self,
            event_capability,
            action="append_event",
            authority=transition.authority,
            subject_id=event.stage_attempt_id,
            scope_kind="event",
            scope_key=event.experiment_id,
            revision=0,
            now=now,
        )
        if not _event_authority_allowed(transition.authority, event):
            raise CloudStateError("event_authority_denied")
        return self._complete_command_with_event(transition, event, observed_at=now)

    @final
    def fail_command(
        self, transition: StateTransition, *, capability: AuthorityCapability
    ) -> CommandMutation:
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="fail_command",
            authority=transition.authority,
            subject_id=transition.claim_id,
            scope_kind="command",
            scope_key=transition.command_key,
            revision=transition.expected_revision,
            now=now,
        )
        return self._fail_command(transition, observed_at=now)

    @final
    def reconcile_expired_claim(
        self,
        reconciliation: ClaimReconciliation,
        *,
        capability: AuthorityCapability,
        dead_holder: DeadHolderObservation,
    ) -> CommandMutation:
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="reconcile_expired_claim",
            authority=reconciliation.authority,
            subject_id=reconciliation.claim_id,
            scope_kind="command",
            scope_key=reconciliation.command_key,
            revision=reconciliation.expected_revision,
            now=now,
        )
        observation = _require_dead_holder(
            _backend_verifier(self),
            dead_holder,
            authority=reconciliation.authority,
            subject_id=reconciliation.claim_id,
            scope_kind="command",
            scope_key=reconciliation.command_key,
            revision=reconciliation.expected_revision,
            now=now,
        )
        if reconciliation.observed_at != observation.observed_at:
            raise CloudStateError("dead_holder_observation_mismatch")
        return self._reconcile_expired_claim(
            reconciliation, observation_digest=observation.digest, observed_at=now
        )

    @final
    def acquire_lease(
        self, desired: CloudLease, *, capability: AuthorityCapability
    ) -> LeaseMutation:
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="acquire_lease",
            authority=desired.authority,
            subject_id=desired.holder_id,
            scope_kind="lease",
            scope_key=desired.lease_key,
            revision=desired.revision,
            now=now,
        )
        return self._acquire_lease(desired, observed_at=now)

    @final
    def reconcile_lease(
        self,
        reconciliation: LeaseReconciliation,
        *,
        capability: AuthorityCapability,
        dead_holder: DeadHolderObservation,
    ) -> LeaseMutation:
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="reconcile_lease",
            authority=reconciliation.authority,
            subject_id=reconciliation.holder_id,
            scope_kind="lease",
            scope_key=reconciliation.lease_key,
            revision=reconciliation.expected_revision,
            now=now,
        )
        observation = _require_dead_holder(
            _backend_verifier(self),
            dead_holder,
            authority=reconciliation.authority,
            subject_id=reconciliation.holder_id,
            scope_kind="lease",
            scope_key=reconciliation.lease_key,
            revision=reconciliation.expected_revision,
            now=now,
        )
        if reconciliation.observed_at != observation.observed_at:
            raise CloudStateError("dead_holder_observation_mismatch")
        return self._reconcile_lease(
            reconciliation, observation_digest=observation.digest, observed_at=now
        )

    @final
    def release_lease(
        self, release: LeaseRelease, *, capability: AuthorityCapability
    ) -> LeaseMutation:
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="release_lease",
            authority=release.authority,
            subject_id=release.holder_id,
            scope_kind="lease",
            scope_key=release.lease_key,
            revision=release.expected_revision,
            now=now,
        )
        return self._release_lease(release, observed_at=now)

    @final
    def claim_supervisor_trigger(
        self,
        *,
        trigger_id: str,
        claim_id: str,
        expected_revision: int,
        capability: AuthorityCapability,
    ) -> TriggerMutation:
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="claim_supervisor_trigger",
            authority="supervisor",
            subject_id=claim_id,
            scope_kind="supervisor_trigger",
            scope_key=trigger_id,
            revision=expected_revision,
            now=now,
        )
        return self._claim_supervisor_trigger(
            trigger_id=trigger_id,
            claim_id=claim_id,
            expected_revision=expected_revision,
            observed_at=now,
        )

    @final
    def resolve_supervisor_trigger(
        self,
        *,
        trigger_id: str,
        claim_id: str,
        expected_revision: int,
        resolution: TriggerResolution,
        capability: AuthorityCapability,
    ) -> TriggerMutation:
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="resolve_supervisor_trigger",
            authority="supervisor",
            subject_id=claim_id,
            scope_kind="supervisor_trigger",
            scope_key=trigger_id,
            revision=expected_revision,
            now=now,
        )
        return self._resolve_supervisor_trigger(
            trigger_id=trigger_id,
            claim_id=claim_id,
            expected_revision=expected_revision,
            resolution=resolution,
            observed_at=now,
        )

    @final
    def register_evidence(
        self, evidence: EvidenceObject, *, capability: AuthorityCapability
    ) -> bool:
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="register_evidence",
            authority=evidence.producer,
            subject_id=evidence.object_version,
            scope_kind="evidence",
            scope_key=evidence.object_key,
            revision=0,
            now=now,
        )
        return self._register_evidence(evidence, observed_at=now)

    @final
    def record_health(self, snapshot: HealthSnapshot, *, capability: AuthorityCapability) -> bool:
        now = _mutation_time(_backend_verifier(self))
        StateBackend._authorize(
            self,
            capability,
            action="record_health",
            authority="observer",
            subject_id=snapshot.detail_digest,
            scope_kind="health",
            scope_key=snapshot.detail_digest,
            revision=0,
            now=now,
        )
        return self._record_health(snapshot, observed_at=now)

    @abstractmethod
    def _register_manifest(
        self, manifest: ExperimentManifest, *, observed_at: datetime
    ) -> bool: ...

    @abstractmethod
    def _append_event(self, event: ExperimentEvent, *, observed_at: datetime) -> AppendResult: ...

    @abstractmethod
    def _register_dead_holder_observation(
        self, observation: DeadHolderObservation, *, observed_at: datetime
    ) -> bool: ...

    @abstractmethod
    def _create_command(
        self, command: CloudCommand, *, observed_at: datetime
    ) -> CommandMutation: ...

    @abstractmethod
    def _claim_command(self, claim: CommandClaim, *, observed_at: datetime) -> CommandMutation: ...

    @abstractmethod
    def _complete_command(
        self, transition: StateTransition, *, observed_at: datetime
    ) -> CommandMutation: ...

    @abstractmethod
    def _complete_command_with_event(
        self,
        transition: StateTransition,
        event: ExperimentEvent,
        *,
        observed_at: datetime,
    ) -> tuple[CommandMutation, AppendResult]: ...

    @abstractmethod
    def _fail_command(
        self, transition: StateTransition, *, observed_at: datetime
    ) -> CommandMutation: ...

    @abstractmethod
    def _reconcile_expired_claim(
        self,
        reconciliation: ClaimReconciliation,
        *,
        observation_digest: str,
        observed_at: datetime,
    ) -> CommandMutation: ...

    @abstractmethod
    def _acquire_lease(self, desired: CloudLease, *, observed_at: datetime) -> LeaseMutation: ...

    @abstractmethod
    def _reconcile_lease(
        self,
        reconciliation: LeaseReconciliation,
        *,
        observation_digest: str,
        observed_at: datetime,
    ) -> LeaseMutation: ...

    @abstractmethod
    def _release_lease(self, release: LeaseRelease, *, observed_at: datetime) -> LeaseMutation: ...

    @abstractmethod
    def _claim_supervisor_trigger(
        self,
        *,
        trigger_id: str,
        claim_id: str,
        expected_revision: int,
        observed_at: datetime,
    ) -> TriggerMutation: ...

    @abstractmethod
    def _resolve_supervisor_trigger(
        self,
        *,
        trigger_id: str,
        claim_id: str,
        expected_revision: int,
        resolution: TriggerResolution,
        observed_at: datetime,
    ) -> TriggerMutation: ...

    @abstractmethod
    def _register_evidence(self, evidence: EvidenceObject, *, observed_at: datetime) -> bool: ...

    @abstractmethod
    def _record_health(self, snapshot: HealthSnapshot, *, observed_at: datetime) -> bool: ...

    @abstractmethod
    def load_projection(
        self, experiment_id: str
    ) -> tuple[ExperimentProjection, AutonomyProjection]: ...

    @abstractmethod
    def health_snapshot(self) -> HealthSnapshot: ...
