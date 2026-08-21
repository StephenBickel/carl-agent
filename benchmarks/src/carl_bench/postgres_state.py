"""Transactional PostgreSQL implementation of the sealed cloud-state boundary."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
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
    EventType,
    ExperimentEvent,
    ExperimentManifest,
    ExperimentProjection,
    GraphContractError,
    reduce_events,
)
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
_DATABASE_ROLES = frozenset(
    {
        "carl_builder",
        "carl_coordinator",
        "carl_observer",
        "carl_promoter",
        "carl_soak",
        "carl_supervisor",
        "carl_validator",
    }
)
_TRUSTED_CANONICAL_EVENTS = frozenset(
    {EventType.PAIRED_EVIDENCE_RECORDED, EventType.PROTECTED_VALIDATION_RECORDED}
)


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
    """Protected connection and trust-root configuration for one workflow role."""

    dsn: str
    database_role: str
    authority_key: TrustedAuthorityKey
    dead_holder_key: TrustedAuthorityKey
    clock: Callable[[], datetime] = _utc_now
    connect: Callable[[str], Any] = _default_connect

    def __post_init__(self) -> None:
        if not isinstance(self.dsn, str) or not self.dsn or len(self.dsn) > 8_192:
            raise PostgresStateError("postgres_dsn_invalid")
        if self.database_role not in _DATABASE_ROLES:
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
        query: str,
        parameters: tuple[object, ...],
        decode: Callable[[dict[str, Any]], Any],
    ) -> Any:
        connection = self._connection()
        try:
            with connection.transaction(), connection.cursor() as cursor:
                self._verify_role(cursor)
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

    def _create_command(self, command: CloudCommand, *, observed_at: datetime) -> CommandMutation:
        return cast(
            CommandMutation,
            self._mutation(
                "SELECT * FROM carl_autonomy.create_command(%s, %s)",
                (_canonical_text(command.to_canonical_dict()), observed_at),
                self._decode_command,
            ),
        )

    def _claim_command(self, claim: CommandClaim, *, observed_at: datetime) -> CommandMutation:
        return cast(
            CommandMutation,
            self._mutation(
                "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
                (_canonical_text(claim.to_canonical_dict()), observed_at),
                self._decode_command,
            ),
        )

    def _complete_command(
        self, transition: StateTransition, *, observed_at: datetime
    ) -> CommandMutation:
        return cast(
            CommandMutation,
            self._mutation(
                "SELECT * FROM carl_autonomy.complete_command(%s, %s)",
                (_canonical_text(transition.to_canonical_dict()), observed_at),
                self._decode_command,
            ),
        )

    def _fail_command(
        self, transition: StateTransition, *, observed_at: datetime
    ) -> CommandMutation:
        return cast(
            CommandMutation,
            self._mutation(
                "SELECT * FROM carl_autonomy.fail_command(%s, %s)",
                (_canonical_text(transition.to_canonical_dict()), observed_at),
                self._decode_command,
            ),
        )

    def _reconcile_expired_claim(
        self,
        reconciliation: ClaimReconciliation,
        *,
        dead_holder: DeadHolderObservation,
        observed_at: datetime,
    ) -> CommandMutation:
        return cast(
            CommandMutation,
            self._mutation(
                "SELECT * FROM carl_autonomy.reconcile_expired_claim(%s, %s, %s)",
                (
                    _canonical_text(reconciliation.to_canonical_dict()),
                    _canonical_text(dead_holder.to_canonical_dict()),
                    observed_at,
                ),
                self._decode_command,
            ),
        )

    def _acquire_lease(self, desired: CloudLease, *, observed_at: datetime) -> LeaseMutation:
        return cast(
            LeaseMutation,
            self._mutation(
                "SELECT * FROM carl_autonomy.acquire_lease(%s, %s)",
                (_canonical_text(desired.to_canonical_dict()), observed_at),
                self._decode_lease,
            ),
        )

    def _reconcile_lease(
        self,
        reconciliation: LeaseReconciliation,
        *,
        dead_holder: DeadHolderObservation,
        observed_at: datetime,
    ) -> LeaseMutation:
        return cast(
            LeaseMutation,
            self._mutation(
                "SELECT * FROM carl_autonomy.reconcile_lease(%s, %s, %s)",
                (
                    _canonical_text(reconciliation.to_canonical_dict()),
                    _canonical_text(dead_holder.to_canonical_dict()),
                    observed_at,
                ),
                self._decode_lease,
            ),
        )

    def _release_lease(self, release: LeaseRelease, *, observed_at: datetime) -> LeaseMutation:
        return cast(
            LeaseMutation,
            self._mutation(
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
                        if event.event_type in _TRUSTED_CANONICAL_EVENTS:
                            if row["authority"] != "validator":
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
