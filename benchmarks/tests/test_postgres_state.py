from __future__ import annotations

import base64
from contextlib import AbstractContextManager
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_experiment import manifest as sample_manifest

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_state import (
    AuthorityCapability,
    ClaimReconciliation,
    CloudCommand,
    CloudLease,
    CommandClaim,
    DeadHolderObservation,
    EvidenceObject,
    HealthSnapshot,
    LeaseReconciliation,
    LeaseRelease,
    StateTransition,
    TrustedAuthorityKey,
)
from carl_bench.experiment import EventType, ExperimentEvent
from carl_bench.postgres_state import (
    MAX_STATE_REVISION,
    PostgresStateBackend,
    PostgresStateConfig,
    PostgresStateError,
)
from carl_bench.supervisor_triggers import RecoveryAttempt, TriggerResolution

NOW = datetime(2026, 8, 20, 12, tzinfo=UTC)
NOW_TEXT = "2026-08-20T12:00:00Z"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64

AUTHORITY_PRIVATE = Ed25519PrivateKey.generate()
LIVENESS_PRIVATE = Ed25519PrivateKey.generate()
AUTHORITY_KEY = TrustedAuthorityKey(
    key_id="postgres-authority-v1",
    purpose="authority_capability",
    public_key_pem=AUTHORITY_PRIVATE.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ),
)
LIVENESS_KEY = TrustedAuthorityKey(
    key_id="postgres-liveness-v1",
    purpose="dead_holder_observation",
    public_key_pem=LIVENESS_PRIVATE.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ),
)


class FakeTransaction(AbstractContextManager[None]):
    def __init__(self, database: FakeDatabase) -> None:
        self.database = database

    def __enter__(self) -> None:
        self.database.transactions_started += 1
        self.database.transaction_depth += 1
        return None

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> bool:
        if exception_type is None:
            self.database.transactions_committed += 1
        else:
            self.database.transactions_rolled_back += 1
        self.database.transaction_depth -= 1
        return False


class FakeCursor(AbstractContextManager["FakeCursor"]):
    def __init__(self, database: FakeDatabase) -> None:
        self.database = database
        self.rows: list[dict[str, Any]] = []

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *args: object) -> bool:
        return False

    def execute(self, query: str, parameters: tuple[object, ...] | None = None) -> None:
        bound = () if parameters is None else parameters
        self.database.calls.append((query, bound))
        self.database.call_depths.append(self.database.transaction_depth)
        if self.database.failure is not None and "carl_autonomy." in query:
            raise self.database.failure
        if "current_user AS database_role" in query:
            self.rows = [{"database_role": self.database.database_role}]
            return
        self.rows = [
            dict(row) for row in self.database.responses.get(self.database.operation(query), [])
        ]

    def fetchone(self) -> dict[str, Any] | None:
        return self.rows.pop(0) if self.rows else None

    def fetchall(self) -> list[dict[str, Any]]:
        rows, self.rows = self.rows, []
        return rows


class FakeConnection:
    def __init__(self, database: FakeDatabase) -> None:
        self.database = database

    def cursor(self) -> FakeCursor:
        return FakeCursor(self.database)

    def transaction(self) -> FakeTransaction:
        return FakeTransaction(self.database)

    def close(self) -> None:
        self.database.connections_closed += 1


class FakeDatabase:
    def __init__(self, *, database_role: str = "carl_coordinator") -> None:
        self.database_role = database_role
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.call_depths: list[int] = []
        self.responses: dict[str, list[dict[str, Any]]] = {}
        self.failure: Exception | None = None
        self.transactions_started = 0
        self.transaction_depth = 0
        self.transactions_committed = 0
        self.transactions_rolled_back = 0
        self.connections_closed = 0

    @staticmethod
    def operation(query: str) -> str:
        for operation in (
            "register_manifest",
            "append_event",
            "create_command",
            "claim_command",
            "complete_command",
            "fail_command",
            "reconcile_expired_claim",
            "acquire_lease",
            "reconcile_lease",
            "release_lease",
            "claim_supervisor_trigger",
            "resolve_supervisor_trigger",
            "register_evidence",
            "record_health",
            "load_experiment_manifest",
            "load_experiment_events",
            "latest_health_snapshot",
        ):
            if f"carl_autonomy.{operation}" in query:
                return operation
        return "unknown"

    def connect(self, dsn: str) -> FakeConnection:
        assert dsn == "postgresql://protected.invalid/carl"
        return FakeConnection(self)


def _config(database: FakeDatabase, *, role: str = "carl_coordinator") -> PostgresStateConfig:
    return PostgresStateConfig(
        dsn="postgresql://protected.invalid/carl",
        database_role=role,
        authority_key=AUTHORITY_KEY,
        dead_holder_key=LIVENESS_KEY,
        clock=lambda: NOW,
        connect=database.connect,
    )


def _backend(database: FakeDatabase, *, role: str = "carl_coordinator") -> PostgresStateBackend:
    return PostgresStateBackend.from_config(_config(database, role=role))


def _canonical(value: dict[str, Any]) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def _command(*, revision: int = 7) -> CloudCommand:
    return CloudCommand.create(
        command_key="dispatch-exp-001",
        authority="coordinator",
        operation="dispatch",
        request_digest=DIGEST_A,
        occurred_at=NOW_TEXT,
        expected_revision=revision,
        attempt=1,
        max_attempts=3,
    )


def _claim(*, revision: int = 7) -> CommandClaim:
    return CommandClaim(
        command_key="dispatch-exp-001",
        claim_id="claim-exp-001",
        authority="coordinator",
        expected_revision=revision,
        claimed_at=NOW_TEXT,
        expires_at="2026-08-20T12:05:00Z",
    )


def _transition(*, status: str = "completed", revision: int = 8) -> StateTransition:
    return StateTransition(
        command_key="dispatch-exp-001",
        authority="coordinator",
        claim_id="claim-exp-001",
        expected_revision=revision,
        next_revision=revision + 1,
        status=status,  # type: ignore[arg-type]
        occurred_at="2026-08-20T12:02:00Z",
        result_digest=DIGEST_B if status == "completed" else None,
        failure_code=None if status == "completed" else "runner_failed",
    )


def _command_row(
    *,
    applied: bool = True,
    status: str = "pending",
    revision: int = 7,
) -> dict[str, Any]:
    claim = _claim()
    transition = (
        _transition(status=status, revision=8) if status in {"completed", "failed"} else None
    )
    return {
        "applied": applied,
        "claim_json": _canonical(claim.to_canonical_dict()) if status != "pending" else None,
        "command_json": _canonical(_command().to_canonical_dict()),
        "failure_code": None if transition is None else transition.failure_code,
        "result_digest": None if transition is None else transition.result_digest,
        "revision": revision,
        "status": status,
        "transition_json": None
        if transition is None
        else _canonical(transition.to_canonical_dict()),
    }


def _lease(*, revision: int = 0) -> CloudLease:
    return CloudLease(
        lease_key="coordinator",
        holder_id="worker-001",
        authority="coordinator",
        revision=revision,
        acquired_at=NOW_TEXT,
        expires_at="2026-08-20T12:05:00Z",
    )


def _lease_row(lease: CloudLease, *, applied: bool = True) -> dict[str, Any]:
    return {
        "applied": applied,
        "lease_json": _canonical(lease.to_canonical_dict()),
        "revision": lease.revision,
    }


def _capability(
    *,
    action: str,
    authority: str,
    subject_id: str,
    scope_kind: str,
    scope_key: str,
    revision: int,
) -> AuthorityCapability:
    unsigned = AuthorityCapability(
        schema_version=1,
        authority=authority,
        action=action,
        subject_id=subject_id,
        scope_kind=scope_kind,
        scope_key=scope_key,
        revision=revision,
        issued_at="2026-08-20T11:55:00Z",
        expires_at="2026-08-20T12:05:00Z",
        key_id=AUTHORITY_KEY.key_id,
        signature_base64=base64.b64encode(bytes(64)).decode("ascii"),
    )
    return replace(
        unsigned,
        signature_base64=base64.b64encode(
            AUTHORITY_PRIVATE.sign(unsigned.signing_payload())
        ).decode("ascii"),
    )


def test_backend_constructs_and_owns_verifier_from_protected_config() -> None:
    database = FakeDatabase()
    backend = _backend(database)

    assert backend.verifier is not None
    with pytest.raises(AttributeError, match="immutable"):
        backend.verifier = None  # type: ignore[misc]
    with pytest.raises(PostgresStateError, match="postgres_config_invalid"):
        PostgresStateBackend.from_config(replace(_config(database), clock=None))  # type: ignore[arg-type]


def test_public_authorization_fails_before_opening_database_connection() -> None:
    database = FakeDatabase(database_role="carl_builder")
    backend = _backend(database, role="carl_builder")
    item = sample_manifest()
    wrong = _capability(
        action="register_manifest",
        authority="builder",
        subject_id="wrong-experiment",
        scope_kind="manifest",
        scope_key=item.experiment_id,
        revision=0,
    )

    with pytest.raises(ValueError, match="authority_capability_mismatch"):
        backend.register_manifest(item, capability=wrong)

    assert database.calls == []


def test_register_manifest_binds_values_and_commits_one_transaction() -> None:
    database = FakeDatabase(database_role="carl_builder")
    database.responses["register_manifest"] = [{"applied": True}]
    backend = _backend(database, role="carl_builder")
    item = sample_manifest()

    assert backend._register_manifest(item, observed_at=NOW) is True

    query, parameters = next(call for call in database.calls if "register_manifest" in call[0])
    assert "%s" in query
    assert item.experiment_id not in query
    assert parameters == (_canonical(item.to_canonical_dict()), item.digest, NOW)
    assert database.transactions_started == database.transactions_committed == 1
    assert database.transactions_rolled_back == 0
    assert database.connections_closed == 1


def test_database_role_probe_is_inside_the_committing_transaction() -> None:
    database = FakeDatabase(database_role="carl_builder")
    database.responses["register_manifest"] = [{"applied": True}]

    _backend(database, role="carl_builder")._register_manifest(sample_manifest(), observed_at=NOW)

    role_call = next(
        index
        for index, (query, _parameters) in enumerate(database.calls)
        if "current_user AS database_role" in query
    )
    assert database.call_depths[role_call] == 1


def test_every_state_backend_hook_maps_to_its_transactional_procedure() -> None:
    database = FakeDatabase()
    backend = _backend(database)
    event = ExperimentEvent.create(
        experiment_id=sample_manifest().experiment_id,
        stage_attempt_id="attempt-001",
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at=NOW_TEXT,
        payload={"attempt": 1},
    )
    command = _command()
    claim = _claim()
    completed = _transition()
    failed = _transition(status="failed")
    desired_lease = _lease()
    acquired_lease = replace(desired_lease, revision=1)
    release = LeaseRelease(
        lease_key="coordinator",
        holder_id="worker-001",
        authority="coordinator",
        expected_revision=1,
        next_revision=2,
        released_at="2026-08-20T12:01:00Z",
        observation_digest=None,
    )
    reconciliation = ClaimReconciliation(
        command_key=command.command_key,
        claim_id=claim.claim_id,
        authority="coordinator",
        expected_revision=8,
        next_revision=9,
        observed_at=NOW_TEXT,
    )
    lease_reconciliation = LeaseReconciliation(
        lease_key="coordinator",
        holder_id="worker-001",
        authority="coordinator",
        expected_revision=1,
        next_revision=2,
        observed_at="2026-08-20T12:05:00Z",
    )
    dead_holder = DeadHolderObservation(
        schema_version=1,
        authority="coordinator",
        subject_id="claim-exp-001",
        scope_kind="command",
        scope_key=command.command_key,
        revision=8,
        issued_at="2026-08-20T11:55:00Z",
        observed_at=NOW_TEXT,
        expires_at="2026-08-20T12:05:00Z",
        live=False,
        key_id=LIVENESS_KEY.key_id,
        signature_base64=base64.b64encode(bytes(64)).decode("ascii"),
    )
    evidence = EvidenceObject(
        digest=DIGEST_A,
        object_key=f"evidence/{DIGEST_A}",
        object_version="version-001",
        producer="observer",
        request_digest=DIGEST_B,
        media_type="application/json",
        retained_until="2027-08-20T12:00:00Z",
    )
    health = HealthSnapshot(observed_at=NOW_TEXT, healthy=True, detail_digest=DIGEST_A)
    resolution = TriggerResolution(
        status="resolved",
        recovery_action=RecoveryAttempt(
            attempt_id="recovery-001",
            action_digest=DIGEST_A,
            occurred_at=NOW_TEXT,
            outcome="reconciled",
        ),
        evidence_digest=DIGEST_A,
        result_digest=DIGEST_B,
        resolved_at=NOW_TEXT,
    )

    database.responses.update(
        {
            "append_event": [
                {
                    "appended": True,
                    "chain_digest": DIGEST_B,
                    "event_digest": event.digest,
                    "ordinal": 1,
                }
            ],
            "create_command": [_command_row()],
            "claim_command": [_command_row(status="claimed", revision=8)],
            "complete_command": [_command_row(status="completed", revision=9)],
            "fail_command": [_command_row(status="failed", revision=9)],
            "reconcile_expired_claim": [_command_row(status="pending", revision=9)],
            "acquire_lease": [_lease_row(acquired_lease)],
            "reconcile_lease": [
                _lease_row(
                    replace(
                        acquired_lease,
                        revision=2,
                        reconciled_at="2026-08-20T12:05:00Z",
                        reconciliation_observation_digest=DIGEST_A,
                    )
                )
            ],
            "release_lease": [
                _lease_row(replace(acquired_lease, revision=2, released_at="2026-08-20T12:01:00Z"))
            ],
            "claim_supervisor_trigger": [
                {
                    "applied": True,
                    "claim_id": "trigger-claim-001",
                    "resolution_json": None,
                    "revision": 1,
                    "trigger_json": _canonical(
                        {
                            "attempt_history": [],
                            "created_at": NOW_TEXT,
                            "evidence_digest": DIGEST_A,
                            "next_safe_node_key": "retry-builder",
                            "schema_version": 1,
                            "trigger_id": "trigger-001",
                            "unsafe_boundary": "builder",
                        }
                    ),
                }
            ],
            "resolve_supervisor_trigger": [
                {
                    "applied": True,
                    "claim_id": "trigger-claim-001",
                    "resolution_json": _canonical(resolution.to_canonical_dict()),
                    "revision": 2,
                    "trigger_json": _canonical(
                        {
                            "attempt_history": [],
                            "created_at": NOW_TEXT,
                            "evidence_digest": DIGEST_A,
                            "next_safe_node_key": "retry-builder",
                            "schema_version": 1,
                            "trigger_id": "trigger-001",
                            "unsafe_boundary": "builder",
                        }
                    ),
                }
            ],
            "register_evidence": [{"applied": True}],
            "record_health": [{"applied": True}],
        }
    )

    operations = (
        ("append_event", lambda: backend._append_event(event, observed_at=NOW)),
        ("create_command", lambda: backend._create_command(command, observed_at=NOW)),
        ("claim_command", lambda: backend._claim_command(claim, observed_at=NOW)),
        ("complete_command", lambda: backend._complete_command(completed, observed_at=NOW)),
        ("fail_command", lambda: backend._fail_command(failed, observed_at=NOW)),
        (
            "reconcile_expired_claim",
            lambda: backend._reconcile_expired_claim(
                reconciliation, dead_holder=dead_holder, observed_at=NOW
            ),
        ),
        ("acquire_lease", lambda: backend._acquire_lease(desired_lease, observed_at=NOW)),
        (
            "reconcile_lease",
            lambda: backend._reconcile_lease(
                lease_reconciliation, dead_holder=dead_holder, observed_at=NOW
            ),
        ),
        ("release_lease", lambda: backend._release_lease(release, observed_at=NOW)),
        (
            "claim_supervisor_trigger",
            lambda: backend._claim_supervisor_trigger(
                trigger_id="trigger-001",
                claim_id="trigger-claim-001",
                expected_revision=0,
                observed_at=NOW,
            ),
        ),
        (
            "resolve_supervisor_trigger",
            lambda: backend._resolve_supervisor_trigger(
                trigger_id="trigger-001",
                claim_id="trigger-claim-001",
                expected_revision=1,
                resolution=resolution,
                observed_at=NOW,
            ),
        ),
        ("register_evidence", lambda: backend._register_evidence(evidence, observed_at=NOW)),
        ("record_health", lambda: backend._record_health(health, observed_at=NOW)),
    )

    for operation, invoke in operations:
        invoke()
        query, parameters = next(
            call for call in reversed(database.calls) if f"carl_autonomy.{operation}" in call[0]
        )
        assert "%s" in query
        assert parameters

    assert database.transactions_started == len(operations)
    assert database.transactions_committed == len(operations)


def test_adapter_rejects_wrong_database_role_before_mutation() -> None:
    database = FakeDatabase(database_role="carl_builder")
    database.responses["record_health"] = [{"applied": True}]
    backend = _backend(database, role="carl_observer")

    with pytest.raises(PostgresStateError, match="database_role_mismatch"):
        backend._record_health(
            HealthSnapshot(observed_at=NOW_TEXT, healthy=True, detail_digest=DIGEST_A),
            observed_at=NOW,
        )

    assert not any("record_health" in query for query, _ in database.calls)
    assert database.connections_closed == 1


@pytest.mark.parametrize(
    "bad_row",
    [
        {**_command_row(), "unexpected": "column"},
        {**_command_row(), "applied": 1},
        {**_command_row(), "revision": MAX_STATE_REVISION + 1},
        {**_command_row(), "command_json": '{"schema_version":1,"schema_version":1}'},
        {**_command_row(), "command_json": '{ "schema_version": 1 }'},
    ],
)
def test_command_rows_fail_closed_on_shape_type_bound_and_json_corruption(
    bad_row: dict[str, Any],
) -> None:
    database = FakeDatabase()
    database.responses["create_command"] = [bad_row]
    backend = _backend(database)

    with pytest.raises(PostgresStateError):
        backend._create_command(_command(), observed_at=NOW)


def test_procedure_requires_exactly_one_result_row_and_rolls_back() -> None:
    database = FakeDatabase()
    database.responses["register_evidence"] = [{"applied": True}, {"applied": True}]
    backend = _backend(database)
    evidence = EvidenceObject(
        digest=DIGEST_A,
        object_key=f"evidence/{DIGEST_A}",
        object_version="version-001",
        producer="observer",
        request_digest=DIGEST_B,
        media_type="application/json",
        retained_until="2027-08-20T12:00:00Z",
    )

    with pytest.raises(PostgresStateError, match="postgres_result_shape_invalid"):
        backend._register_evidence(evidence, observed_at=NOW)

    assert database.transactions_rolled_back == 1
    assert database.transactions_committed == 0
    assert database.connections_closed == 1


def test_load_projection_uses_one_read_only_snapshot_and_revalidates_chain() -> None:
    database = FakeDatabase()
    item = sample_manifest()
    event = ExperimentEvent.create(
        experiment_id=item.experiment_id,
        stage_attempt_id="queue-to-baseline",
        event_type=EventType.STATE_TRANSITIONED,
        occurred_at="2026-08-20T12:00:00Z",
        payload={"from_state": "queued", "to_state": "baselining"},
    )
    database.responses["load_experiment_manifest"] = [
        {"manifest_digest": item.digest, "manifest_json": _canonical(item.to_canonical_dict())}
    ]
    database.responses["load_experiment_events"] = [
        {
            "authority": "coordinator",
            "chain_digest": DIGEST_B,
            "event_digest": event.digest,
            "event_json": _canonical(event.to_canonical_dict()),
            "ordinal": 1,
            "previous_chain_digest": "0" * 64,
        }
    ]
    backend = _backend(database)

    with pytest.raises(PostgresStateError, match="event_chain_digest_mismatch"):
        backend.load_projection(item.experiment_id)

    set_transaction = next(
        index
        for index, (query, _parameters) in enumerate(database.calls)
        if query.startswith("SET TRANSACTION")
    )
    role_probe = next(
        index
        for index, (query, _parameters) in enumerate(database.calls)
        if "current_user AS database_role" in query
    )
    assert set_transaction < role_probe
    assert database.transactions_started == 1
    assert database.transactions_rolled_back == 1


def test_latest_health_snapshot_rejects_extra_columns() -> None:
    database = FakeDatabase()
    database.responses["latest_health_snapshot"] = [
        {
            "detail_digest": DIGEST_A,
            "healthy": True,
            "observed_at": NOW_TEXT,
            "unexpected": "column",
        }
    ]

    with pytest.raises(PostgresStateError, match="postgres_result_shape_invalid"):
        _backend(database).health_snapshot()
