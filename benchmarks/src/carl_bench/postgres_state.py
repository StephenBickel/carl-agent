"""Transactional PostgreSQL implementation of the sealed cloud-state boundary."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, cast

from carl_bench.autonomy import AutonomyProjection, reduce_autonomy_events
from carl_bench.canonical import CanonicalizationError, canonical_json_bytes
from carl_bench.cloud_state import (
    AuthorityVerifier,
    ClaimReconciliation,
    CloudCommand,
    CloudLease,
    CloudStateError,
    CommandClaim,
    CommandMutation,
    CommandState,
    DeadHolderObservation,
    EvidenceObject,
    HealthSnapshot,
    LeaseMutation,
    LeaseReconciliation,
    LeaseRelease,
    StateBackend,
    StateTransition,
    TrustedAuthorityKey,
)
from carl_bench.experiment import (
    _ISOLATED_AUTHORITY_REQUIRED_EVENTS,
    EventType,
    ExperimentEvent,
    ExperimentManifest,
    ExperimentProjection,
    GraphContractError,
    reduce_events,
)
from carl_bench.github_cloud import GitHubEffectAttempt
from carl_bench.ledger import AppendResult
from carl_bench.supervisor_triggers import (
    StoredSupervisorTrigger,
    SupervisorTrigger,
    SupervisorTriggerError,
    TriggerMutation,
    TriggerResolution,
)

MAX_STATE_REVISION = 2_147_483_647
_ZERO_DIGEST = "0" * 64
_DATABASE_ROLE = "carl_state_backend"
_PROTECTED_STATE_CONFIG_DIR = Path("/etc/carl")
_PROTECTED_STATE_CONFIG_NAME = "postgres-state-policy.json"
_PROTECTED_STATE_DSN_ENV = "CARL_AUTONOMY_POSTGRES_DSN"
_WORKFLOW_AUTHORITIES = frozenset(
    {"builder", "coordinator", "observer", "promoter", "soak", "supervisor", "validator"}
)
_EVENT_AUTHORITIES = {
    EventType.ROLE_RECORDED: "builder",
    EventType.WORKSPACE_PREPARED: "builder",
    EventType.CANDIDATE_SEALED: "builder",
    EventType.EXPERIMENTAL_PUBLISHED: "builder",
    EventType.PAIRED_EVIDENCE_RECORDED: "validator",
    EventType.REVIEW_PACKET_RECORDED: "validator",
    EventType.REVIEW_ATTESTED: "validator",
    EventType.PROTECTED_VALIDATION_RECORDED: "validator",
    EventType.DRAFT_PR_REQUESTED: "promoter",
    EventType.DRAFT_PR_RECORDED: "promoter",
    EventType.WORKSPACE_DISPOSED: "promoter",
    EventType.PROMOTION_RECORDED: "promoter",
    EventType.SOAK_OBSERVED: "soak",
    EventType.REVERT_RECORDED: "soak",
    EventType.LEASE_ACQUIRED: "coordinator",
    EventType.LEASE_RECONCILED: "coordinator",
    EventType.LEASE_RELEASED: "coordinator",
    EventType.LIVE_SPEND_RECORDED: "coordinator",
    EventType.RETRY_SCHEDULED: "coordinator",
}
_TRUSTED_EVENT_AUTHORITIES = {
    EventType.PAIRED_EVIDENCE_RECORDED: "validator",
    EventType.REVIEW_PACKET_RECORDED: "validator",
    EventType.REVIEW_ATTESTED: "validator",
    EventType.DRAFT_PR_REQUESTED: "promoter",
    EventType.DRAFT_PR_RECORDED: "promoter",
    EventType.WORKSPACE_DISPOSED: "promoter",
    EventType.PROTECTED_VALIDATION_RECORDED: "validator",
    EventType.PROMOTION_RECORDED: "promoter",
    EventType.SOAK_OBSERVED: "soak",
    EventType.REVERT_RECORDED: "soak",
}


class PostgresStateError(ValueError):
    """Stable PostgreSQL adapter failure without query, credential, or payload contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _default_connect(dsn: str) -> Any:
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.connect(dsn, row_factory=dict_row)


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class PostgresStateConfig:
    """Protected connection and trust roots for the isolated state-controller service."""

    dsn: str
    database_role: str
    authority_key: TrustedAuthorityKey
    dead_holder_key: TrustedAuthorityKey
    clock: Callable[[], datetime] = _utc_now
    connect: Callable[[str], Any] = _default_connect

    def __post_init__(self) -> None:
        if not isinstance(self.dsn, str) or not self.dsn or len(self.dsn) > 8_192:
            raise PostgresStateError("postgres_dsn_invalid")
        if self.database_role != _DATABASE_ROLE:
            raise PostgresStateError("database_role_invalid")
        if not isinstance(self.authority_key, TrustedAuthorityKey) or not isinstance(
            self.dead_holder_key, TrustedAuthorityKey
        ):
            raise PostgresStateError("postgres_trust_root_invalid")
        if not callable(self.clock) or not callable(self.connect):
            raise PostgresStateError("postgres_config_invalid")


@dataclass(frozen=True, slots=True)
class _PostgresRuntime:
    dsn: str
    database_role: str
    connect: Callable[[str], Any]


def _canonical_text(value: Mapping[str, Any]) -> str:
    try:
        return canonical_json_bytes(dict(value)).decode("utf-8")
    except (CanonicalizationError, UnicodeError) as error:
        raise PostgresStateError("postgres_payload_invalid") from error


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PostgresStateError("postgres_json_duplicate_key")
        result[key] = value
    return result


def _strict_json_object(value: object, *, code: str) -> dict[str, Any]:
    if not isinstance(value, str):
        raise PostgresStateError(code)
    try:
        decoded = json.loads(value, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise PostgresStateError(code) from error
    if type(decoded) is not dict:
        raise PostgresStateError(code)
    try:
        canonical = canonical_json_bytes(decoded).decode("utf-8")
    except (CanonicalizationError, UnicodeError) as error:
        raise PostgresStateError(code) from error
    if canonical != value:
        raise PostgresStateError(code)
    return decoded


def _strict_row(row: object, fields: frozenset[str]) -> dict[str, Any]:
    if not isinstance(row, Mapping) or set(row) != fields:
        raise PostgresStateError("postgres_result_shape_invalid")
    return dict(row)


def _strict_bool(value: object) -> bool:
    if type(value) is not bool:
        raise PostgresStateError("postgres_result_type_invalid")
    return value


def _strict_revision(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_STATE_REVISION:
        raise PostgresStateError("postgres_revision_invalid")
    return value


def _chain_digest(
    *,
    experiment_id: str,
    manifest_digest: str,
    ordinal: int,
    event_digest: str,
    previous_chain_digest: str,
) -> str:
    payload = {
        "event_digest": event_digest,
        "experiment_id": experiment_id,
        "manifest_digest": manifest_digest,
        "ordinal": ordinal,
        "previous_chain_digest": previous_chain_digest,
    }
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


class PostgresStateBackend(StateBackend):
    """PostgreSQL adapter whose public mutations remain sealed by ``StateBackend``."""

    __slots__ = ("_runtime",)

    _COMMAND_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "applied",
            "claim_json",
            "command_json",
            "failure_code",
            "result_digest",
            "revision",
            "status",
            "transition_json",
        }
    )
    _LEASE_FIELDS: ClassVar[frozenset[str]] = frozenset({"applied", "lease_json", "revision"})
    _TRIGGER_FIELDS: ClassVar[frozenset[str]] = frozenset(
        {"applied", "claim_id", "resolution_json", "revision", "trigger_json"}
    )

    @classmethod
    def from_config(cls, config: PostgresStateConfig) -> PostgresStateBackend:
        if not isinstance(config, PostgresStateConfig):
            raise PostgresStateError("postgres_config_invalid")
        verifier = AuthorityVerifier(
            authority_key=config.authority_key,
            dead_holder_key=config.dead_holder_key,
            clock=config.clock,
        )
        backend = cls(verifier=verifier)
        backend._runtime = _PostgresRuntime(
            dsn=config.dsn,
            database_role=config.database_role,
            connect=config.connect,
        )
        return backend

    @classmethod
    def from_protected_environment(cls) -> PostgresStateBackend:
        """Construct the isolated controller backend without caller-supplied seams."""
        directory_fd = file_fd = -1
        try:
            directory_fd = os.open(
                _PROTECTED_STATE_CONFIG_DIR,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            directory_stat = os.fstat(directory_fd)
            if (
                not stat.S_ISDIR(directory_stat.st_mode)
                or directory_stat.st_uid not in {0, os.geteuid()}
                or directory_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise PostgresStateError("postgres_protected_configuration_invalid")
            file_fd = os.open(
                _PROTECTED_STATE_CONFIG_NAME,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            file_stat = os.fstat(file_fd)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_uid not in {0, os.geteuid()}
                or file_stat.st_nlink != 1
                or file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or not 1 <= file_stat.st_size <= 16_384
            ):
                raise PostgresStateError("postgres_protected_configuration_invalid")
            payload = os.read(file_fd, 16_385)
            if len(payload) != file_stat.st_size:
                raise PostgresStateError("postgres_protected_configuration_invalid")
        except PostgresStateError:
            raise
        except OSError as error:
            raise PostgresStateError("postgres_protected_configuration_invalid") from error
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            if directory_fd >= 0:
                os.close(directory_fd)
        try:
            decoded = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, UnicodeError, PostgresStateError) as error:
            raise PostgresStateError("postgres_protected_configuration_invalid") from error
        if (
            type(decoded) is not dict
            or set(decoded)
            != {"authority_key", "database_role", "dead_holder_key", "schema_version"}
            or decoded["schema_version"] != 1
            or decoded["database_role"] != _DATABASE_ROLE
            or canonical_json_bytes(decoded) != payload
        ):
            raise PostgresStateError("postgres_protected_configuration_invalid")

        def trusted_key(name: str) -> TrustedAuthorityKey:
            value = decoded[name]
            if type(value) is not dict or set(value) != {
                "key_id",
                "public_key_pem_b64",
                "purpose",
            }:
                raise PostgresStateError("postgres_protected_configuration_invalid")
            encoded = value["public_key_pem_b64"]
            if type(encoded) is not str or not 1 <= len(encoded) <= 8_192:
                raise PostgresStateError("postgres_protected_configuration_invalid")
            try:
                public_key_pem = base64.b64decode(encoded, validate=True)
                if (
                    not 1 <= len(public_key_pem) <= 4_096
                    or base64.b64encode(public_key_pem).decode("ascii") != encoded
                ):
                    raise PostgresStateError("postgres_protected_configuration_invalid")
                return TrustedAuthorityKey(
                    key_id=value["key_id"],
                    purpose=value["purpose"],
                    public_key_pem=public_key_pem,
                )
            except (binascii.Error, CloudStateError, TypeError) as error:
                raise PostgresStateError("postgres_protected_configuration_invalid") from error

        dsn = os.environ.get(_PROTECTED_STATE_DSN_ENV)
        if dsn is None:
            raise PostgresStateError("postgres_dsn_missing")
        return cls.from_config(
            PostgresStateConfig(
                dsn=dsn,
                database_role=_DATABASE_ROLE,
                authority_key=trusted_key("authority_key"),
                dead_holder_key=trusted_key("dead_holder_key"),
            )
        )

    def _runtime_config(self) -> _PostgresRuntime:
        try:
            runtime = self._runtime
        except AttributeError as error:
            raise PostgresStateError("postgres_backend_not_configured") from error
        if not isinstance(runtime, _PostgresRuntime):
            raise PostgresStateError("postgres_backend_not_configured")
        return runtime

    def _connection(self) -> Any:
        runtime = self._runtime_config()
        try:
            return runtime.connect(runtime.dsn)
        except Exception as error:
            raise PostgresStateError("postgres_connection_failed") from error

    def _verify_role(self, cursor: Any) -> None:
        cursor.execute("SELECT current_user AS database_role")
        row = _strict_row(cursor.fetchone(), frozenset({"database_role"}))
        if cursor.fetchone() is not None:
            raise PostgresStateError("postgres_result_shape_invalid")
        if row["database_role"] != self._runtime_config().database_role:
            raise PostgresStateError("database_role_mismatch")

    @staticmethod
    def _set_authority(cursor: Any, authority: str) -> None:
        if authority not in _WORKFLOW_AUTHORITIES:
            raise PostgresStateError("database_authority_invalid")
        cursor.execute("SELECT set_config('carl_autonomy.authority', %s, true)", (authority,))

    @staticmethod
    def _one(cursor: Any, query: str, parameters: tuple[object, ...]) -> dict[str, Any]:
        cursor.execute(query, parameters)
        row = cursor.fetchone()
        if row is None or cursor.fetchone() is not None:
            raise PostgresStateError("postgres_result_shape_invalid")
        if not isinstance(row, Mapping):
            raise PostgresStateError("postgres_result_shape_invalid")
        return dict(row)

    def _mutation(
        self,
        authority: str,
        query: str,
        parameters: tuple[object, ...],
        decode: Callable[[dict[str, Any]], Any],
    ) -> Any:
        connection = self._connection()
        try:
            with connection.transaction(), connection.cursor() as cursor:
                self._verify_role(cursor)
                self._set_authority(cursor, authority)
                return decode(self._one(cursor, query, parameters))
        except Exception as error:
            if isinstance(error, PostgresStateError | CloudStateError | GraphContractError):
                if isinstance(error, PostgresStateError):
                    raise
                raise PostgresStateError("postgres_domain_result_invalid") from error
            raise PostgresStateError("postgres_mutation_failed") from error
        finally:
            connection.close()

    @staticmethod
    def _decode_applied(row: dict[str, Any]) -> bool:
        decoded = _strict_row(row, frozenset({"applied"}))
        return _strict_bool(decoded["applied"])

    @classmethod
    def _decode_command(cls, row: dict[str, Any]) -> CommandMutation:
        decoded = _strict_row(row, cls._COMMAND_FIELDS)
        applied = _strict_bool(decoded["applied"])
        revision = _strict_revision(decoded["revision"])
        command_value = _strict_json_object(decoded["command_json"], code="command_json_invalid")
        claim_value = decoded["claim_json"]
        transition_value = decoded["transition_json"]
        try:
            command = CloudCommand.from_canonical_dict(command_value)
            claim = (
                None
                if claim_value is None
                else CommandClaim.from_canonical_dict(
                    _strict_json_object(claim_value, code="claim_json_invalid")
                )
            )
            transition = (
                None
                if transition_value is None
                else StateTransition.from_canonical_dict(
                    _strict_json_object(transition_value, code="transition_json_invalid")
                )
            )
            state = CommandState(
                command=command,
                revision=revision,
                status=decoded["status"],
                claim=claim,
                transition=transition,
                result_digest=decoded["result_digest"],
                failure_code=decoded["failure_code"],
            )
        except CloudStateError as error:
            raise PostgresStateError("command_state_invalid") from error
        return CommandMutation(applied=applied, state=state)

    @classmethod
    def _decode_lease(cls, row: dict[str, Any]) -> LeaseMutation:
        decoded = _strict_row(row, cls._LEASE_FIELDS)
        applied = _strict_bool(decoded["applied"])
        revision = _strict_revision(decoded["revision"])
        lease_value = decoded["lease_json"]
        try:
            lease = (
                None
                if lease_value is None
                else CloudLease.from_canonical_dict(
                    _strict_json_object(lease_value, code="lease_json_invalid")
                )
            )
            return LeaseMutation(applied=applied, lease=lease, revision=revision)
        except CloudStateError as error:
            raise PostgresStateError("lease_state_invalid") from error

    @classmethod
    def _decode_trigger(cls, row: dict[str, Any]) -> TriggerMutation:
        decoded = _strict_row(row, cls._TRIGGER_FIELDS)
        applied = _strict_bool(decoded["applied"])
        revision = _strict_revision(decoded["revision"])
        claim_id = decoded["claim_id"]
        if claim_id is not None and not isinstance(claim_id, str):
            raise PostgresStateError("trigger_state_invalid")
        resolution_json = decoded["resolution_json"]
        try:
            trigger = SupervisorTrigger.from_canonical_dict(
                _strict_json_object(decoded["trigger_json"], code="trigger_json_invalid")
            )
            resolution = (
                None
                if resolution_json is None
                else TriggerResolution.from_canonical_dict(
                    _strict_json_object(resolution_json, code="resolution_json_invalid")
                )
            )
        except SupervisorTriggerError as error:
            raise PostgresStateError("trigger_state_invalid") from error
        return TriggerMutation(
            applied=applied,
            revision=revision,
            record=StoredSupervisorTrigger(
                trigger=trigger,
                revision=revision,
                claim_id=claim_id,
                resolution=resolution,
            ),
        )

    def _register_manifest(self, manifest: ExperimentManifest, *, observed_at: datetime) -> bool:
        return cast(
            bool,
            self._mutation(
                "builder",
                "SELECT * FROM carl_autonomy.register_manifest(%s, %s, %s)",
                (_canonical_text(manifest.to_canonical_dict()), manifest.digest, observed_at),
                self._decode_applied,
            ),
        )

    def _append_event(self, event: ExperimentEvent, *, observed_at: datetime) -> AppendResult:
        def decode(row: dict[str, Any]) -> AppendResult:
            value = _strict_row(
                row,
                frozenset({"appended", "chain_digest", "event_digest", "ordinal"}),
            )
            if type(value["ordinal"]) is not int or not 1 <= value["ordinal"] <= MAX_STATE_REVISION:
                raise PostgresStateError("event_ordinal_invalid")
            if value["event_digest"] != event.digest:
                raise PostgresStateError("event_digest_mismatch")
            for name in ("event_digest", "chain_digest"):
                if not isinstance(value[name], str) or len(value[name]) != 64:
                    raise PostgresStateError("event_digest_invalid")
            return AppendResult(
                ordinal=value["ordinal"],
                event_digest=value["event_digest"],
                chain_digest=value["chain_digest"],
                appended=_strict_bool(value["appended"]),
            )

        return cast(
            AppendResult,
            self._mutation(
                self._event_authority(event),
                "SELECT * FROM carl_autonomy.append_event(%s, %s, %s, %s)",
                (
                    _canonical_text(event.to_canonical_dict()),
                    event.digest,
                    event.payload_json,
                    observed_at,
                ),
                decode,
            ),
        )

    @staticmethod
    def _event_authority(event: ExperimentEvent) -> str:
        if event.event_type is EventType.STATE_TRANSITIONED:
            if (
                event.payload.get("from_state") == "soaking"
                and event.payload.get("to_state") == "accepted"
            ):
                return "soak"
            return "coordinator"
        try:
            return _EVENT_AUTHORITIES[event.event_type]
        except KeyError as error:
            raise PostgresStateError("event_authority_invalid") from error

    def _register_dead_holder_observation(
        self, observation: DeadHolderObservation, *, observed_at: datetime
    ) -> bool:
        return cast(
            bool,
            self._mutation(
                "observer",
                "SELECT * FROM carl_autonomy.register_dead_holder_observation(%s, %s, %s)",
                (
                    _canonical_text(observation.to_canonical_dict()),
                    observation.digest,
                    observed_at,
                ),
                self._decode_applied,
            ),
        )

    def _create_command(self, command: CloudCommand, *, observed_at: datetime) -> CommandMutation:
        return cast(
            CommandMutation,
            self._mutation(
                command.authority,
                "SELECT * FROM carl_autonomy.create_command(%s, %s)",
                (_canonical_text(command.to_canonical_dict()), observed_at),
                self._decode_command,
            ),
        )

    def _claim_command(self, claim: CommandClaim, *, observed_at: datetime) -> CommandMutation:
        return cast(
            CommandMutation,
            self._mutation(
                claim.authority,
                "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
                (_canonical_text(claim.to_canonical_dict()), observed_at),
                self._decode_command,
            ),
        )

    @staticmethod
    def _effect_timestamp(value: str) -> datetime:
        if not isinstance(value, str) or not value.endswith("Z"):
            raise PostgresStateError("effect_attempt_timestamp_invalid")
        try:
            parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
        except ValueError as error:
            raise PostgresStateError("effect_attempt_timestamp_invalid") from error
        if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
            raise PostgresStateError("effect_attempt_timestamp_invalid")
        return parsed

    def resolve_claimed_command(
        self,
        command_key: str,
        *,
        authority: str,
        observed_at: datetime,
    ) -> CommandState:
        if authority not in _WORKFLOW_AUTHORITIES or not isinstance(observed_at, datetime):
            raise PostgresStateError("effect_command_lookup_invalid")
        mutation = cast(
            CommandMutation,
            self._mutation(
                authority,
                "SELECT * FROM carl_autonomy.resolve_claimed_command(%s, %s)",
                (command_key, observed_at),
                self._decode_command,
            ),
        )
        if mutation.applied:
            raise PostgresStateError("effect_command_lookup_invalid")
        return mutation.state

    def prepare_effect_attempt(self, attempt: GitHubEffectAttempt) -> bool:
        if not isinstance(attempt, GitHubEffectAttempt):
            raise PostgresStateError("effect_attempt_invalid")
        observed_at = self._effect_timestamp(attempt.observed_at)
        return cast(
            bool,
            self._mutation(
                attempt.authority,
                "SELECT * FROM carl_autonomy.prepare_effect_attempt(%s, %s)",
                (_canonical_text(attempt.to_canonical_dict()), observed_at),
                self._decode_applied,
            ),
        )

    def mark_effect_uncertain(
        self,
        effect_key: str,
        *,
        authority: str,
        not_before: str,
        observed_at: str,
    ) -> None:
        observed = self._effect_timestamp(observed_at)
        self._mutation(
            authority,
            "SELECT * FROM carl_autonomy.mark_effect_uncertain(%s, %s, %s, %s)",
            (effect_key, not_before, observed_at, observed),
            self._decode_applied,
        )

    def mark_effect_retry_scheduled(
        self,
        effect_key: str,
        *,
        authority: str,
        retry_not_before: str,
        observed_at: str,
    ) -> None:
        observed = self._effect_timestamp(observed_at)
        self._effect_timestamp(retry_not_before)
        self._mutation(
            authority,
            "SELECT * FROM carl_autonomy.mark_effect_retry_scheduled(%s, %s, %s, %s)",
            (effect_key, retry_not_before, observed_at, observed),
            self._decode_applied,
        )

    def mark_effect_completed(
        self,
        effect_key: str,
        *,
        command_key: str,
        claim_id: str,
        command_revision: int,
        claim_expected_revision: int,
        claim_expires_at: str,
        authority: str,
        result_digest: str,
        observed_at: str,
    ) -> None:
        observed = self._effect_timestamp(observed_at)
        self._effect_timestamp(claim_expires_at)
        self._mutation(
            authority,
            "SELECT * FROM carl_autonomy.mark_effect_completed(%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                effect_key,
                command_key,
                claim_id,
                command_revision,
                claim_expected_revision,
                claim_expires_at,
                result_digest,
                observed_at,
                observed,
            ),
            self._decode_applied,
        )

    def _complete_command(
        self, transition: StateTransition, *, observed_at: datetime
    ) -> CommandMutation:
        raise PostgresStateError("atomic_completion_event_required")

    def _complete_command_with_event(
        self,
        transition: StateTransition,
        event: ExperimentEvent,
        *,
        observed_at: datetime,
    ) -> tuple[CommandMutation, AppendResult]:
        atomic_fields = self._COMMAND_FIELDS | {
            "appended",
            "chain_digest",
            "event_digest",
            "ordinal",
        }

        def decode(row: dict[str, Any]) -> tuple[CommandMutation, AppendResult]:
            value = _strict_row(row, atomic_fields)
            command = self._decode_command({name: value[name] for name in self._COMMAND_FIELDS})
            ordinal = value["ordinal"]
            if type(ordinal) is not int or not 1 <= ordinal <= MAX_STATE_REVISION:
                raise PostgresStateError("event_ordinal_invalid")
            if value["event_digest"] != event.digest:
                raise PostgresStateError("event_digest_mismatch")
            if not isinstance(value["chain_digest"], str) or len(value["chain_digest"]) != 64:
                raise PostgresStateError("event_digest_invalid")
            append = AppendResult(
                ordinal=ordinal,
                event_digest=value["event_digest"],
                chain_digest=value["chain_digest"],
                appended=_strict_bool(value["appended"]),
            )
            return command, append

        return cast(
            tuple[CommandMutation, AppendResult],
            self._mutation(
                transition.authority,
                "SELECT * FROM carl_autonomy.complete_command_and_append_event(%s, %s, %s, %s, %s)",
                (
                    _canonical_text(transition.to_canonical_dict()),
                    _canonical_text(event.to_canonical_dict()),
                    event.digest,
                    event.payload_json,
                    observed_at,
                ),
                decode,
            ),
        )

    def _fail_command(
        self, transition: StateTransition, *, observed_at: datetime
    ) -> CommandMutation:
        return cast(
            CommandMutation,
            self._mutation(
                transition.authority,
                "SELECT * FROM carl_autonomy.fail_command(%s, %s)",
                (_canonical_text(transition.to_canonical_dict()), observed_at),
                self._decode_command,
            ),
        )

    def _reconcile_expired_claim(
        self,
        reconciliation: ClaimReconciliation,
        *,
        observation_digest: str,
        observed_at: datetime,
    ) -> CommandMutation:
        return cast(
            CommandMutation,
            self._mutation(
                reconciliation.authority,
                "SELECT * FROM carl_autonomy.reconcile_expired_claim(%s, %s, %s)",
                (
                    _canonical_text(reconciliation.to_canonical_dict()),
                    observation_digest,
                    observed_at,
                ),
                self._decode_command,
            ),
        )

    def _acquire_lease(self, desired: CloudLease, *, observed_at: datetime) -> LeaseMutation:
        return cast(
            LeaseMutation,
            self._mutation(
                desired.authority,
                "SELECT * FROM carl_autonomy.acquire_lease(%s, %s)",
                (_canonical_text(desired.to_canonical_dict()), observed_at),
                self._decode_lease,
            ),
        )

    def _reconcile_lease(
        self,
        reconciliation: LeaseReconciliation,
        *,
        observation_digest: str,
        observed_at: datetime,
    ) -> LeaseMutation:
        return cast(
            LeaseMutation,
            self._mutation(
                reconciliation.authority,
                "SELECT * FROM carl_autonomy.reconcile_lease(%s, %s, %s)",
                (
                    _canonical_text(reconciliation.to_canonical_dict()),
                    observation_digest,
                    observed_at,
                ),
                self._decode_lease,
            ),
        )

    def _release_lease(self, release: LeaseRelease, *, observed_at: datetime) -> LeaseMutation:
        return cast(
            LeaseMutation,
            self._mutation(
                release.authority,
                "SELECT * FROM carl_autonomy.release_lease(%s, %s)",
                (_canonical_text(release.to_canonical_dict()), observed_at),
                self._decode_lease,
            ),
        )

    def _claim_supervisor_trigger(
        self,
        *,
        trigger_id: str,
        claim_id: str,
        expected_revision: int,
        observed_at: datetime,
    ) -> TriggerMutation:
        return cast(
            TriggerMutation,
            self._mutation(
                "supervisor",
                "SELECT * FROM carl_autonomy.claim_supervisor_trigger(%s, %s, %s, %s)",
                (trigger_id, claim_id, expected_revision, observed_at),
                self._decode_trigger,
            ),
        )

    def _resolve_supervisor_trigger(
        self,
        *,
        trigger_id: str,
        claim_id: str,
        expected_revision: int,
        resolution: TriggerResolution,
        observed_at: datetime,
    ) -> TriggerMutation:
        return cast(
            TriggerMutation,
            self._mutation(
                "supervisor",
                "SELECT * FROM carl_autonomy.resolve_supervisor_trigger(%s, %s, %s, %s, %s)",
                (
                    trigger_id,
                    claim_id,
                    expected_revision,
                    _canonical_text(resolution.to_canonical_dict()),
                    observed_at,
                ),
                self._decode_trigger,
            ),
        )

    def _register_evidence(self, evidence: EvidenceObject, *, observed_at: datetime) -> bool:
        return cast(
            bool,
            self._mutation(
                evidence.producer,
                "SELECT * FROM carl_autonomy.register_evidence(%s, %s)",
                (_canonical_text(evidence.to_canonical_dict()), observed_at),
                self._decode_applied,
            ),
        )

    def _record_health(self, snapshot: HealthSnapshot, *, observed_at: datetime) -> bool:
        snapshot_value = {
            "detail_digest": snapshot.detail_digest,
            "healthy": snapshot.healthy,
            "observed_at": snapshot.observed_at,
        }
        return cast(
            bool,
            self._mutation(
                "observer",
                "SELECT * FROM carl_autonomy.record_health(%s, %s)",
                (_canonical_text(snapshot_value), observed_at),
                self._decode_applied,
            ),
        )

    @staticmethod
    def _event_from_canonical(value: dict[str, Any]) -> ExperimentEvent:
        expected = {
            "event_type",
            "experiment_id",
            "occurred_at",
            "payload",
            "schema_version",
            "stage_attempt_id",
        }
        if set(value) != expected or type(value["payload"]) is not dict:
            raise PostgresStateError("event_json_invalid")
        try:
            return ExperimentEvent.create(
                experiment_id=value["experiment_id"],
                stage_attempt_id=value["stage_attempt_id"],
                event_type=EventType(value["event_type"]),
                occurred_at=value["occurred_at"],
                payload=value["payload"],
            )
        except (GraphContractError, TypeError, ValueError) as error:
            raise PostgresStateError("event_json_invalid") from error

    def load_projection(
        self, experiment_id: str
    ) -> tuple[ExperimentProjection, AutonomyProjection]:
        connection = self._connection()
        try:
            with connection.transaction():  # noqa: SIM117
                with connection.cursor() as cursor:
                    cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                    self._verify_role(cursor)
                    self._set_authority(cursor, "coordinator")
                    manifest_row = self._one(
                        cursor,
                        "SELECT * FROM carl_autonomy.load_experiment_manifest(%s)",
                        (experiment_id,),
                    )
                    manifest_data = _strict_row(
                        manifest_row, frozenset({"manifest_digest", "manifest_json"})
                    )
                    manifest_value = _strict_json_object(
                        manifest_data["manifest_json"], code="manifest_json_invalid"
                    )
                    try:
                        manifest = ExperimentManifest.from_canonical_dict(manifest_value)
                    except GraphContractError as error:
                        raise PostgresStateError("manifest_json_invalid") from error
                    if manifest.digest != manifest_data["manifest_digest"]:
                        raise PostgresStateError("manifest_digest_mismatch")
                    cursor.execute(
                        "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
                        (experiment_id,),
                    )
                    rows = cursor.fetchall()

                    events: list[ExperimentEvent] = []
                    trusted: set[str] = set()
                    previous = _ZERO_DIGEST
                    event_fields = frozenset(
                        {
                            "authority",
                            "trusted_authority",
                            "chain_digest",
                            "event_digest",
                            "event_json",
                            "ordinal",
                            "previous_chain_digest",
                        }
                    )
                    for expected_ordinal, raw_row in enumerate(rows, start=1):
                        row = _strict_row(raw_row, event_fields)
                        if row["ordinal"] != expected_ordinal:
                            raise PostgresStateError("event_ordinal_gap")
                        if row["previous_chain_digest"] != previous:
                            raise PostgresStateError("event_chain_link_mismatch")
                        event = self._event_from_canonical(
                            _strict_json_object(row["event_json"], code="event_json_invalid")
                        )
                        if (
                            event.experiment_id != experiment_id
                            or event.digest != row["event_digest"]
                        ):
                            raise PostgresStateError("event_digest_mismatch")
                        expected_chain = _chain_digest(
                            experiment_id=experiment_id,
                            manifest_digest=manifest.digest,
                            ordinal=expected_ordinal,
                            event_digest=event.digest,
                            previous_chain_digest=previous,
                        )
                        if row["chain_digest"] != expected_chain:
                            raise PostgresStateError("event_chain_digest_mismatch")
                        trusted_authority = row["trusted_authority"]
                        if type(trusted_authority) is not bool:
                            raise PostgresStateError("event_authority_invalid")
                        required_authority = _TRUSTED_EVENT_AUTHORITIES.get(event.event_type)
                        if event.event_type in _ISOLATED_AUTHORITY_REQUIRED_EVENTS:
                            if not trusted_authority or row["authority"] != required_authority:
                                raise PostgresStateError("event_authority_invalid")
                            trusted.add(event.digest)
                        elif trusted_authority:
                            is_acceptance = (
                                event.event_type is EventType.STATE_TRANSITIONED
                                and row["authority"] == "soak"
                                and event.payload.get("from_state") == "soaking"
                                and event.payload.get("to_state") == "accepted"
                            )
                            if not is_acceptance:
                                raise PostgresStateError("event_authority_invalid")
                            trusted.add(event.digest)
                        events.append(event)
                        previous = expected_chain
                    try:
                        return (
                            reduce_events(
                                manifest,
                                tuple(events),
                                trusted_authority_event_digests=frozenset(trusted),
                            ),
                            reduce_autonomy_events(manifest, tuple(events)),
                        )
                    except GraphContractError as error:
                        raise PostgresStateError(error.code) from error
        except Exception as error:
            if isinstance(error, PostgresStateError):
                raise
            raise PostgresStateError("postgres_read_failed") from error
        finally:
            connection.close()

    def health_snapshot(self) -> HealthSnapshot:
        connection = self._connection()
        try:
            with connection.transaction():  # noqa: SIM117
                with connection.cursor() as cursor:
                    self._verify_role(cursor)
                    self._set_authority(cursor, "observer")
                    row = self._one(
                        cursor,
                        "SELECT * FROM carl_autonomy.latest_health_snapshot()",
                        (),
                    )
                    decoded = _strict_row(
                        row, frozenset({"detail_digest", "healthy", "observed_at"})
                    )
                    if type(decoded["healthy"]) is not bool:
                        raise PostgresStateError("health_snapshot_invalid")
                    try:
                        return HealthSnapshot(
                            observed_at=decoded["observed_at"],
                            healthy=decoded["healthy"],
                            detail_digest=decoded["detail_digest"],
                        )
                    except CloudStateError as error:
                        raise PostgresStateError("health_snapshot_invalid") from error
        finally:
            connection.close()

    def reconstruct_coordinator_snapshot(
        self, command: str, *, observed_at: datetime
    ) -> tuple[object, dict[str, Any] | None] | None:
        """Load one service-selected snapshot and its separately protected receipt row."""
        from carl_bench.cloud_coordinator import reconstruct_snapshot

        if (
            command
            not in {
                "request",
                "coordinate",
                "observe",
                "ingest",
                "publish-input",
                "health",
                "commission-live",
            }
            or not isinstance(observed_at, datetime)
            or observed_at.tzinfo != UTC
        ):
            raise PostgresStateError("coordinator_reconstruction_invalid")

        def decode(row: dict[str, Any]) -> tuple[object, dict[str, Any] | None] | None:
            value = _strict_row(
                row,
                frozenset({"production_receipts_json", "snapshot_json"}),
            )
            if value["snapshot_json"] is None:
                if value["production_receipts_json"] is not None:
                    raise PostgresStateError("coordinator_empty_queue_receipts_invalid")
                return None
            snapshot_value = _strict_json_object(
                value["snapshot_json"], code="coordinator_snapshot_json_invalid"
            )
            receipts_text = value["production_receipts_json"]
            receipts = (
                None
                if receipts_text is None
                else _strict_json_object(
                    receipts_text,
                    code="coordinator_production_receipts_json_invalid",
                )
            )
            try:
                return reconstruct_snapshot(snapshot_value), receipts
            except Exception as error:
                raise PostgresStateError("coordinator_snapshot_invalid") from error

        return cast(
            tuple[object, dict[str, Any] | None] | None,
            self._mutation(
                "coordinator",
                "SELECT * FROM carl_autonomy.load_coordinator_snapshot(%s, %s)",
                (command, observed_at),
                decode,
            ),
        )

    @staticmethod
    def _decode_coordinator_decision(row: dict[str, Any], *, expected: object) -> object:
        from carl_bench.cloud_coordinator import CloudCoordinatorDecision

        value = _strict_row(row, frozenset({"applied", "decision_json"}))
        _strict_bool(value["applied"])
        try:
            decision = CloudCoordinatorDecision.from_canonical_dict(
                _strict_json_object(
                    value["decision_json"], code="coordinator_decision_json_invalid"
                )
            )
        except Exception as error:
            raise PostgresStateError("coordinator_decision_invalid") from error
        if decision != expected:
            raise PostgresStateError("coordinator_decision_identity_mismatch")
        return decision

    def apply_coordinator_decision(self, decision: object, *, observed_at: datetime) -> object:
        """Apply or replay exactly one non-remote coordinator decision transactionally."""
        from carl_bench.cloud_coordinator import CloudCoordinatorDecision

        if (
            not isinstance(decision, CloudCoordinatorDecision)
            or not decision.consequential
            or decision.remote_effect
            or not isinstance(observed_at, datetime)
            or observed_at.tzinfo != UTC
        ):
            raise PostgresStateError("coordinator_decision_invalid")
        return self._mutation(
            "coordinator",
            "SELECT * FROM carl_autonomy.apply_coordinator_decision(%s, %s)",
            (_canonical_text(decision.to_canonical_dict()), observed_at),
            lambda row: self._decode_coordinator_decision(row, expected=decision),
        )

    def execute_coordinator_effect(
        self,
        decision: object,
        *,
        github: object,
        observed_at: datetime,
    ) -> object:
        """Resolve, execute, and durably fence one exact protected GitHub effect."""
        from carl_bench.cloud_coordinator import CloudCoordinatorDecision
        from carl_bench.github_effect_ipc import GitHubEffectRequest, GitHubEffectResponse

        if (
            not isinstance(decision, CloudCoordinatorDecision)
            or not decision.consequential
            or not decision.remote_effect
            or decision.command is None
            or not isinstance(observed_at, datetime)
            or observed_at.tzinfo != UTC
            or not callable(getattr(github, "execute", None))
        ):
            raise PostgresStateError("coordinator_effect_invalid")

        def prepare(row: dict[str, Any]) -> GitHubEffectRequest:
            value = _strict_row(row, frozenset({"effect_family", "request_json"}))
            if value["effect_family"] != "github":
                raise PostgresStateError("coordinator_effect_family_invalid")
            try:
                request = GitHubEffectRequest.from_canonical_dict(
                    _strict_json_object(
                        value["request_json"], code="coordinator_effect_request_json_invalid"
                    )
                )
            except Exception as error:
                raise PostgresStateError("coordinator_effect_request_invalid") from error
            if (
                request.command_key != decision.command.command_key
                or request.effect_key != decision.command.effect_key
                or request.occurred_at != decision.command.occurred_at
            ):
                raise PostgresStateError("coordinator_effect_identity_mismatch")
            return request

        request = self._mutation(
            "coordinator",
            "SELECT * FROM carl_autonomy.prepare_coordinator_effect(%s, %s)",
            (_canonical_text(decision.to_canonical_dict()), observed_at),
            prepare,
        )
        try:
            response = github.execute(request)
        except Exception as error:
            raise PostgresStateError("coordinator_effect_unavailable") from error
        if (
            not isinstance(response, GitHubEffectResponse)
            or response.request_digest != request.digest
        ):
            raise PostgresStateError("coordinator_effect_response_invalid")
        return self._mutation(
            "coordinator",
            "SELECT * FROM carl_autonomy.complete_coordinator_effect(%s, %s, %s)",
            (
                _canonical_text(decision.to_canonical_dict()),
                _canonical_text(response.to_canonical_dict()),
                observed_at,
            ),
            lambda row: self._decode_coordinator_decision(row, expected=decision),
        )
