from __future__ import annotations

import base64
import json
import os
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
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
from carl_bench.postgres_state import PostgresStateBackend, PostgresStateConfig, PostgresStateError
from carl_bench.supervisor_triggers import (
    RecoveryAttempt,
    SupervisorTrigger,
    TriggerResolution,
)

POSTGRES_DSN = os.environ.get("CARL_POSTGRES_TEST_DSN") or None
pytestmark = pytest.mark.skipif(
    POSTGRES_DSN is None,
    reason="CARL_POSTGRES_TEST_DSN is unset; PostgreSQL 16 integration is mandatory in CI",
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = (
    REPOSITORY_ROOT / "infra/autonomy/postgres/001_initial.sql",
    REPOSITORY_ROOT / "infra/autonomy/postgres/002_role_procedures.sql",
)
NOW = "2026-08-20T12:00:00Z"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
AUTHORITY_PRIVATE = Ed25519PrivateKey.generate()
LIVENESS_PRIVATE = Ed25519PrivateKey.generate()
AUTHORITY_KEY = TrustedAuthorityKey(
    key_id="integration-authority-v1",
    purpose="authority_capability",
    public_key_pem=AUTHORITY_PRIVATE.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ),
)
LIVENESS_KEY = TrustedAuthorityKey(
    key_id="integration-liveness-v1",
    purpose="dead_holder_observation",
    public_key_pem=LIVENESS_PRIVATE.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ),
)


def _canonical(value: dict[str, Any]) -> str:
    return canonical_json_bytes(value).decode("utf-8")


@pytest.fixture(scope="module")
def postgres() -> object:
    import psycopg

    assert POSTGRES_DSN is not None
    with psycopg.connect(POSTGRES_DSN, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS carl_autonomy CASCADE")
        for migration in MIGRATIONS:
            connection.execute(migration.read_text(encoding="utf-8"), prepare=False)
    return psycopg


@pytest.fixture(autouse=True)
def clean_state(postgres: object) -> None:
    assert POSTGRES_DSN is not None
    with postgres.connect(POSTGRES_DSN, autocommit=True) as connection:  # type: ignore[attr-defined]
        connection.execute(
            "TRUNCATE carl_autonomy.experiment_events, "
            "carl_autonomy.experiment_manifests, carl_autonomy.commands, "
            "carl_autonomy.leases, carl_autonomy.supervisor_triggers, "
            "carl_autonomy.evidence_objects, carl_autonomy.monitor_snapshots, "
            "carl_autonomy.dead_holder_observations "
            "RESTART IDENTITY CASCADE"
        )


@contextmanager
def _as_role(postgres: object, role: str):
    from psycopg import sql
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None
    with postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    ) as connection:
        connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
        yield connection


def _register_manifest(connection: object, manifest: object) -> bool:
    row = connection.execute(  # type: ignore[attr-defined]
        "SELECT * FROM carl_autonomy.register_manifest(%s, %s, %s)",
        (_canonical(manifest.to_canonical_dict()), manifest.digest, NOW),  # type: ignore[attr-defined]
    ).fetchone()
    return row["applied"]


def _append_event(connection: object, event: ExperimentEvent) -> dict[str, Any]:
    return connection.execute(  # type: ignore[attr-defined]
        "SELECT * FROM carl_autonomy.append_event(%s, %s, %s, %s)",
        (_canonical(event.to_canonical_dict()), event.digest, event.payload_json, NOW),
    ).fetchone()


def _retry_payload(*, attempt: int, scheduled_at: str, changed_action: str) -> dict[str, Any]:
    return {
        "attempt": attempt,
        "changed_action": changed_action,
        "failed_stage_attempt_id": "failed-stage-001",
        "failure_class": "infrastructure",
        "scheduled_at": scheduled_at,
    }


def _dead_holder(
    *,
    scope_kind: str,
    scope_key: str,
    subject_id: str,
    revision: int,
    authority: str = "coordinator",
) -> DeadHolderObservation:
    unsigned = DeadHolderObservation(
        schema_version=1,
        authority=authority,
        subject_id=subject_id,
        scope_kind=scope_kind,
        scope_key=scope_key,
        revision=revision,
        issued_at="2026-08-20T11:55:00Z",
        observed_at="2026-08-20T12:02:00Z",
        expires_at="2026-08-20T12:05:00Z",
        live=False,
        key_id=LIVENESS_KEY.key_id,
        signature_base64=base64.b64encode(bytes(64)).decode("ascii"),
    )
    return replace(
        unsigned,
        signature_base64=base64.b64encode(LIVENESS_PRIVATE.sign(unsigned.signing_payload())).decode(
            "ascii"
        ),
    )


def _capability(
    *, action: str, authority: str, subject_id: str, scope_kind: str, scope_key: str, revision: int
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


def _register_observation(postgres: object, observation: DeadHolderObservation) -> None:
    with _as_role(postgres, "carl_observer") as observer:
        row = observer.execute(
            "SELECT * FROM carl_autonomy.register_dead_holder_observation(%s, %s, %s)",
            (
                _canonical(observation.to_canonical_dict()),
                observation.digest,
                observation.observed_at,
            ),
        ).fetchone()
        assert row["applied"] is True


def _command(*, occurred_at: str = NOW, request_digest: str = DIGEST_A) -> CloudCommand:
    return CloudCommand.create(
        command_key="dispatch-exp-001",
        authority="coordinator",
        operation="dispatch",
        request_digest=request_digest,
        occurred_at=occurred_at,
        expected_revision=7,
        attempt=1,
        max_attempts=3,
    )


def _claim(*, claim_id: str = "claim-001", revision: int = 7) -> CommandClaim:
    return CommandClaim(
        command_key="dispatch-exp-001",
        claim_id=claim_id,
        authority="coordinator",
        expected_revision=revision,
        claimed_at=NOW,
        expires_at="2026-08-20T12:01:00Z",
    )


def _transition(*, revision: int, result_digest: str = DIGEST_B) -> StateTransition:
    return StateTransition(
        command_key="dispatch-exp-001",
        authority="coordinator",
        claim_id="claim-002" if revision == 10 else "claim-001",
        expected_revision=revision,
        next_revision=revision + 1,
        status="completed",
        occurred_at="2026-08-20T12:03:00Z",
        result_digest=result_digest,
        failure_code=None,
    )


def _required_tables(connection: object) -> set[str]:
    rows = connection.execute(  # type: ignore[attr-defined]
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = %s ORDER BY table_name",
        ("carl_autonomy",),
    ).fetchall()
    return {row["table_name"] for row in rows}


def test_schema_has_all_strict_transactional_state_tables(postgres: object) -> None:
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None
    with postgres.connect(POSTGRES_DSN, row_factory=dict_row) as connection:  # type: ignore[attr-defined]
        assert _required_tables(connection) == {
            "commands",
            "dead_holder_observations",
            "evidence_objects",
            "experiment_events",
            "experiment_manifests",
            "experiment_projection_guards",
            "leases",
            "monitor_snapshots",
            "supervisor_triggers",
        }


def test_workflow_roles_have_no_direct_table_dml_and_public_has_no_execute(
    postgres: object,
) -> None:
    with _as_role(postgres, "carl_coordinator") as connection:
        row = connection.execute(
            "SELECT has_table_privilege(%s, %s, %s) AS direct_dml, "
            "has_function_privilege(%s, %s, %s) AS role_execute, "
            "EXISTS ("
            "SELECT 1 FROM pg_proc AS p "
            "JOIN pg_namespace AS n ON n.oid = p.pronamespace "
            "CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) AS a "
            "WHERE n.nspname = %s AND p.proname = %s "
            "AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'"
            ") AS public_execute",
            (
                "carl_builder",
                "carl_autonomy.experiment_events",
                "INSERT,UPDATE,DELETE",
                "carl_builder",
                "carl_autonomy.append_event(text,text,text,timestamptz)",
                "EXECUTE",
                "carl_autonomy",
                "append_event",
            ),
        ).fetchone()
    assert row == {"direct_dml": False, "public_execute": False, "role_execute": True}


def test_registered_dead_holder_identity_and_observer_reconciler_role_separation(
    postgres: object,
) -> None:
    from datetime import UTC, datetime

    from psycopg import sql
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None

    def observer_connect(dsn: str):
        connection = postgres.connect(dsn, row_factory=dict_row)  # type: ignore[attr-defined]
        connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier("carl_observer")))
        return connection

    observation = _dead_holder(
        scope_kind="command",
        scope_key="dispatch-exp-001",
        subject_id="claim-001",
        revision=8,
    )
    observer_backend = PostgresStateBackend.from_config(
        PostgresStateConfig(
            dsn=POSTGRES_DSN,
            database_role="carl_observer",
            authority_key=AUTHORITY_KEY,
            dead_holder_key=LIVENESS_KEY,
            clock=lambda: datetime(2026, 8, 20, 12, 2, tzinfo=UTC),
            connect=observer_connect,
        )
    )
    capability = _capability(
        action="register_dead_holder_observation",
        authority="observer",
        subject_id=observation.digest,
        scope_kind="dead_holder_observation",
        scope_key=observation.digest,
        revision=observation.revision,
    )
    assert (
        observer_backend.register_dead_holder_observation(observation, capability=capability)
        is True
    )

    command = _command()
    reconciliation = ClaimReconciliation(
        command_key=command.command_key,
        claim_id="claim-001",
        authority="coordinator",
        expected_revision=8,
        next_revision=9,
        observed_at="2026-08-20T12:02:00Z",
    )
    with _as_role(postgres, "carl_coordinator") as coordinator:
        coordinator.execute(
            "SELECT * FROM carl_autonomy.create_command(%s, %s)",
            (_canonical(command.to_canonical_dict()), NOW),
        )
        coordinator.execute(
            "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
            (_canonical(_claim().to_canonical_dict()), NOW),
        )
        with pytest.raises(Exception, match="dead_holder_observation_unregistered"):
            coordinator.execute(
                "SELECT * FROM carl_autonomy.reconcile_expired_claim(%s, %s, %s)",
                (_canonical(reconciliation.to_canonical_dict()), "f" * 64, "2026-08-20T12:02:00Z"),
            )
        wrong = _dead_holder(
            scope_kind="command",
            scope_key=command.command_key,
            subject_id="claim-001",
            revision=8,
            authority="supervisor",
        )
    _register_observation(postgres, wrong)
    with _as_role(postgres, "carl_coordinator") as coordinator:
        with pytest.raises(Exception, match="dead_holder_observation_mismatch"):
            coordinator.execute(
                "SELECT * FROM carl_autonomy.reconcile_expired_claim(%s, %s, %s)",
                (
                    _canonical(reconciliation.to_canonical_dict()),
                    wrong.digest,
                    "2026-08-20T12:02:00Z",
                ),
            )
        reconciled = coordinator.execute(
            "SELECT * FROM carl_autonomy.reconcile_expired_claim(%s, %s, %s)",
            (
                _canonical(reconciliation.to_canonical_dict()),
                observation.digest,
                "2026-08-20T12:02:00Z",
            ),
        ).fetchone()
        assert reconciled["revision"] == 9
        with pytest.raises(Exception, match="permission denied"):
            coordinator.execute(
                "SELECT * FROM carl_autonomy.register_dead_holder_observation(%s, %s, %s)",
                (_canonical(observation.to_canonical_dict()), observation.digest, NOW),
            )
    with (
        _as_role(postgres, "carl_observer") as observer,
        pytest.raises(Exception, match="permission denied"),
    ):
        observer.execute(
            "SELECT * FROM carl_autonomy.reconcile_expired_claim(%s, %s, %s)",
            (
                _canonical(reconciliation.to_canonical_dict()),
                observation.digest,
                "2026-08-20T12:02:00Z",
            ),
        )


def test_manifest_event_chain_global_attempt_replay_and_role_denial(postgres: object) -> None:
    parent = sample_manifest()
    child = replace(
        parent,
        experiment_id="exp-child-001",
        parent_experiment_id=parent.experiment_id,
        parent_generation=parent.parent_generation + 1,
        registered_at="2026-08-10T00:01:00Z",
    )
    orphan = replace(child, experiment_id="exp-orphan-001", parent_experiment_id="missing-parent")

    with _as_role(postgres, "carl_builder") as builder:
        with pytest.raises(Exception, match="parent_experiment_not_found"):
            _register_manifest(builder, orphan)
        assert _register_manifest(builder, parent) is True
        assert _register_manifest(builder, parent) is False
        assert _register_manifest(builder, child) is True

    first = ExperimentEvent.create(
        experiment_id=parent.experiment_id,
        stage_attempt_id="retry-attempt-global-001",
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at=NOW,
        payload=_retry_payload(attempt=1, scheduled_at=NOW, changed_action="retry with telemetry"),
    )
    second = ExperimentEvent.create(
        experiment_id=parent.experiment_id,
        stage_attempt_id="retry-attempt-002",
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at="2026-08-20T12:00:01Z",
        payload=_retry_payload(
            attempt=2,
            scheduled_at="2026-08-20T12:00:01Z",
            changed_action="retry with isolated cache",
        ),
    )
    conflict = ExperimentEvent.create(
        experiment_id=child.experiment_id,
        stage_attempt_id=first.stage_attempt_id,
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at=NOW,
        payload=_retry_payload(attempt=1, scheduled_at=NOW, changed_action="conflicting replay"),
    )
    protected = ExperimentEvent.create(
        experiment_id=parent.experiment_id,
        stage_attempt_id="promotion-001",
        event_type=EventType.PROMOTION_RECORDED,
        occurred_at=NOW,
        payload={"promotion_digest": DIGEST_A},
    )

    with _as_role(postgres, "carl_coordinator") as coordinator:
        inserted = _append_event(coordinator, first)
        replay = _append_event(coordinator, first)
        following = _append_event(coordinator, second)
        assert inserted["appended"] is True
        assert replay == {**inserted, "appended": False}
        assert following["ordinal"] == 2
        rows = coordinator.execute(
            "SELECT ordinal, previous_chain_digest, chain_digest "
            "FROM carl_autonomy.load_experiment_events(%s)",
            (parent.experiment_id,),
        ).fetchall()
        assert rows[0]["previous_chain_digest"] == "0" * 64
        assert rows[1]["previous_chain_digest"] == rows[0]["chain_digest"]
        with pytest.raises(Exception, match="stage_attempt_conflict"):
            _append_event(coordinator, conflict)

    with (
        _as_role(postgres, "carl_builder") as builder,
        pytest.raises(Exception, match="event_authority_denied"),
    ):
        _append_event(builder, protected)


def test_database_rejects_impossible_transitions_and_missing_prerequisites_atomically(
    postgres: object,
) -> None:
    manifest = sample_manifest()
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)

    impossible = ExperimentEvent.create(
        experiment_id=manifest.experiment_id,
        stage_attempt_id="impossible-queued-building",
        event_type=EventType.STATE_TRANSITIONED,
        occurred_at=NOW,
        payload={"from_state": "queued", "to_state": "building"},
    )
    with _as_role(postgres, "carl_coordinator") as coordinator:
        with pytest.raises(Exception, match="invalid_transition"):
            _append_event(coordinator, impossible)
        assert coordinator.execute(
            "SELECT lifecycle_state, lifecycle_revision "
            "FROM carl_autonomy.experiment_projection_guards "
            "WHERE experiment_id = %s",
            (manifest.experiment_id,),
        ).fetchone() == {"lifecycle_revision": 0, "lifecycle_state": "queued"}
        assert (
            coordinator.execute(
                "SELECT count(*) AS count FROM carl_autonomy.load_experiment_events(%s)",
                (manifest.experiment_id,),
            ).fetchone()["count"]
            == 0
        )

    transitions = (
        ("queued", "baselining"),
        ("baselining", "diagnosing"),
        ("diagnosing", "proposal_review"),
    )
    with _as_role(postgres, "carl_coordinator") as coordinator:
        for index, (source, target) in enumerate(transitions, start=1):
            _append_event(
                coordinator,
                ExperimentEvent.create(
                    experiment_id=manifest.experiment_id,
                    stage_attempt_id=f"prerequisite-transition-{index}",
                    event_type=EventType.STATE_TRANSITIONED,
                    occurred_at=f"2026-08-20T12:00:0{index}Z",
                    payload={"from_state": source, "to_state": target},
                ),
            )
    with _as_role(postgres, "carl_builder") as builder:
        _append_event(
            builder,
            ExperimentEvent.create(
                experiment_id=manifest.experiment_id,
                stage_attempt_id="only-one-proposal-approval",
                event_type=EventType.ROLE_RECORDED,
                occurred_at="2026-08-20T12:00:04Z",
                payload={"artifact_digest": DIGEST_A, "role": "causal", "verdict": "approve"},
            ),
        )
    with _as_role(postgres, "carl_coordinator") as coordinator:
        _append_event(
            coordinator,
            ExperimentEvent.create(
                experiment_id=manifest.experiment_id,
                stage_attempt_id="proposal-lease",
                event_type=EventType.LEASE_ACQUIRED,
                occurred_at="2026-08-20T12:00:05Z",
                payload={"expires_at": "2026-08-20T18:00:05Z", "owner_id": "director-1"},
            ),
        )
        missing_quorum = ExperimentEvent.create(
            experiment_id=manifest.experiment_id,
            stage_attempt_id="building-missing-quorum",
            event_type=EventType.STATE_TRANSITIONED,
            occurred_at="2026-08-20T12:00:06Z",
            payload={
                "_lease": {"owner_id": "director-1", "stage_attempt_id": "proposal-lease"},
                "from_state": "proposal_review",
                "to_state": "building",
            },
        )
        with pytest.raises(Exception, match="proposal_quorum_unsatisfied"):
            _append_event(coordinator, missing_quorum)
        guard = coordinator.execute(
            "SELECT lifecycle_state, lifecycle_revision "
            "FROM carl_autonomy.experiment_projection_guards "
            "WHERE experiment_id = %s",
            (manifest.experiment_id,),
        ).fetchone()
        assert guard == {"lifecycle_revision": 3, "lifecycle_state": "proposal_review"}
        assert (
            coordinator.execute(
                "SELECT count(*) AS count FROM carl_autonomy.load_experiment_events(%s)",
                (manifest.experiment_id,),
            ).fetchone()["count"]
            == 5
        )


def test_trusted_autonomy_event_vocabulary_replays_with_persisted_authority(
    postgres: object,
) -> None:
    from datetime import UTC, datetime

    from psycopg import sql
    from psycopg.rows import dict_row

    manifest = sample_manifest()
    publication = ExperimentEvent.create(
        experiment_id=manifest.experiment_id,
        stage_attempt_id="trusted-publication",
        event_type=EventType.EXPERIMENTAL_PUBLISHED,
        occurred_at="2026-08-20T12:01:00Z",
        payload={
            "branch": "experimental/trusted",
            "candidate_packet_digest": DIGEST_A,
            "commit": "c" * 40,
            "tree": "d" * 40,
        },
    )
    protected = ExperimentEvent.create(
        experiment_id=manifest.experiment_id,
        stage_attempt_id="trusted-protected-validation",
        event_type=EventType.PROTECTED_VALIDATION_RECORDED,
        occurred_at="2026-08-20T12:02:00Z",
        payload={
            "candidate_commit": "c" * 40,
            "candidate_tree": "d" * 40,
            "receipt_digest": "e" * 64,
        },
    )
    promotion = ExperimentEvent.create(
        experiment_id=manifest.experiment_id,
        stage_attempt_id="trusted-promotion",
        event_type=EventType.PROMOTION_RECORDED,
        occurred_at="2026-08-20T12:03:00Z",
        payload={"merge_commit": "f" * 40, "merge_tree": "1" * 40},
    )
    healthy = ExperimentEvent.create(
        experiment_id=manifest.experiment_id,
        stage_attempt_id="trusted-soak-healthy",
        event_type=EventType.SOAK_OBSERVED,
        occurred_at="2026-08-20T12:04:00Z",
        payload={
            "evidence_digest": "2" * 64,
            "healthy": True,
            "merge_commit": "f" * 40,
            "observed_at": "2026-08-20T12:04:00Z",
        },
    )
    failed = ExperimentEvent.create(
        experiment_id=manifest.experiment_id,
        stage_attempt_id="trusted-soak-failed",
        event_type=EventType.SOAK_OBSERVED,
        occurred_at="2026-08-20T12:05:00Z",
        payload={
            "evidence_digest": "3" * 64,
            "healthy": False,
            "merge_commit": "f" * 40,
            "observed_at": "2026-08-20T12:05:00Z",
        },
    )
    revert = ExperimentEvent.create(
        experiment_id=manifest.experiment_id,
        stage_attempt_id="trusted-revert",
        event_type=EventType.REVERT_RECORDED,
        occurred_at="2026-08-20T12:06:00Z",
        payload={
            "hard_failure_digest": "3" * 64,
            "merge_commit": "f" * 40,
            "restored_tree": "4" * 40,
            "revert_candidate_commit": "5" * 40,
            "revert_merge_commit": "6" * 40,
            "revert_pull_request_number": 82,
        },
    )

    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
        _append_event(builder, publication)
    assert POSTGRES_DSN is not None
    with postgres.connect(POSTGRES_DSN, autocommit=True) as owner:  # type: ignore[attr-defined]
        owner.execute(
            "UPDATE carl_autonomy.experiment_projection_guards "
            "SET lifecycle_state = 'paired_evaluation', candidate_sealed = true, "
            "paired_evidence_recorded = true WHERE experiment_id = %s",
            (manifest.experiment_id,),
        )
    with _as_role(postgres, "carl_validator") as validator:
        _append_event(validator, protected)
    with _as_role(postgres, "carl_promoter") as promoter:
        _append_event(promoter, promotion)
    with _as_role(postgres, "carl_soak") as soak:
        _append_event(soak, healthy)
        _append_event(soak, failed)
        _append_event(soak, revert)

    def coordinator_connect(dsn: str):
        connection = postgres.connect(dsn, row_factory=dict_row)  # type: ignore[attr-defined]
        connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier("carl_coordinator")))
        return connection

    backend = PostgresStateBackend.from_config(
        PostgresStateConfig(
            dsn=POSTGRES_DSN,
            database_role="carl_coordinator",
            authority_key=AUTHORITY_KEY,
            dead_holder_key=LIVENESS_KEY,
            clock=lambda: datetime(2026, 8, 20, 12, 6, tzinfo=UTC),
            connect=coordinator_connect,
        )
    )
    _experiment, autonomy = backend.load_projection(manifest.experiment_id)
    assert autonomy.promotion is not None
    assert autonomy.revert is not None


def test_command_persist_replay_skip_locked_retry_and_terminal_revision_chain(
    postgres: object,
) -> None:
    command = _command()
    replay = _command(occurred_at="2026-08-20T12:00:30Z")
    conflict = _command(request_digest="c" * 64)
    dead_holder = _dead_holder(
        scope_kind="command",
        scope_key=command.command_key,
        subject_id="claim-001",
        revision=8,
    )
    _register_observation(postgres, dead_holder)

    with _as_role(postgres, "carl_coordinator") as coordinator:
        created = coordinator.execute(
            "SELECT * FROM carl_autonomy.create_command(%s, %s)",
            (_canonical(command.to_canonical_dict()), NOW),
        ).fetchone()
        replayed = coordinator.execute(
            "SELECT * FROM carl_autonomy.create_command(%s, %s)",
            (_canonical(replay.to_canonical_dict()), NOW),
        ).fetchone()
        assert created["applied"] is True
        assert replayed["applied"] is False
        assert replayed["command_json"] == _canonical(command.to_canonical_dict())
        with pytest.raises(Exception, match="command_replay_conflict"):
            coordinator.execute(
                "SELECT * FROM carl_autonomy.create_command(%s, %s)",
                (_canonical(conflict.to_canonical_dict()), NOW),
            ).fetchone()

    assert POSTGRES_DSN is not None
    from psycopg.rows import dict_row

    with postgres.connect(POSTGRES_DSN, row_factory=dict_row) as locker:  # type: ignore[attr-defined]
        locker.execute(
            "SELECT 1 FROM carl_autonomy.commands WHERE command_key = %s FOR UPDATE",
            (command.command_key,),
        )
        with _as_role(postgres, "carl_coordinator") as contender:
            contender.execute("SET statement_timeout = '500ms'")
            started = time.monotonic()
            with pytest.raises(Exception, match="command_busy"):
                contender.execute(
                    "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
                    (_canonical(_claim().to_canonical_dict()), NOW),
                ).fetchone()
            assert time.monotonic() - started < 0.5
        locker.rollback()

    with _as_role(postgres, "carl_coordinator") as coordinator:
        claimed = coordinator.execute(
            "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
            (_canonical(_claim().to_canonical_dict()), NOW),
        ).fetchone()
        assert (claimed["status"], claimed["revision"]) == ("claimed", 8)
        reconciliation = ClaimReconciliation(
            command_key=command.command_key,
            claim_id="claim-001",
            authority="coordinator",
            expected_revision=8,
            next_revision=9,
            observed_at="2026-08-20T12:02:00Z",
        )
        pending = coordinator.execute(
            "SELECT * FROM carl_autonomy.reconcile_expired_claim(%s, %s, %s)",
            (
                _canonical(reconciliation.to_canonical_dict()),
                dead_holder.digest,
                "2026-08-20T12:02:00Z",
            ),
        ).fetchone()
        assert (pending["status"], pending["revision"]) == ("pending", 9)
        retry_claim = replace(
            _claim(claim_id="claim-002", revision=9),
            claimed_at="2026-08-20T12:02:00Z",
            expires_at="2026-08-20T12:05:00Z",
        )
        retried = coordinator.execute(
            "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
            (_canonical(retry_claim.to_canonical_dict()), "2026-08-20T12:02:00Z"),
        ).fetchone()
        assert retried["revision"] == 10
        transition = replace(
            _transition(revision=10),
            status="failed",
            result_digest=None,
            failure_code="runner_failed",
        )
        terminal = coordinator.execute(
            "SELECT * FROM carl_autonomy.fail_command(%s, %s)",
            (_canonical(transition.to_canonical_dict()), "2026-08-20T12:03:00Z"),
        ).fetchone()
        duplicate = coordinator.execute(
            "SELECT * FROM carl_autonomy.fail_command(%s, %s)",
            (_canonical(transition.to_canonical_dict()), "2026-08-20T12:03:00Z"),
        ).fetchone()
        assert (terminal["status"], terminal["revision"], terminal["applied"]) == (
            "failed",
            11,
            True,
        )
        assert duplicate["applied"] is False
        with pytest.raises(Exception, match="command_result_conflict"):
            changed = replace(transition, failure_code="different_failure")
            coordinator.execute(
                "SELECT * FROM carl_autonomy.fail_command(%s, %s)",
                (_canonical(changed.to_canonical_dict()), "2026-08-20T12:03:00Z"),
            ).fetchone()


def test_lease_trigger_evidence_and_health_contracts(postgres: object) -> None:
    desired = CloudLease(
        lease_key="coordinator",
        holder_id="worker-001",
        authority="coordinator",
        revision=0,
        acquired_at=NOW,
        expires_at="2026-08-20T12:01:00Z",
    )
    dead_holder = _dead_holder(
        scope_kind="lease",
        scope_key="coordinator",
        subject_id="worker-001",
        revision=1,
    )
    _register_observation(postgres, dead_holder)
    with _as_role(postgres, "carl_coordinator") as coordinator:
        lease = coordinator.execute(
            "SELECT * FROM carl_autonomy.acquire_lease(%s, %s)",
            (_canonical(desired.to_canonical_dict()), NOW),
        ).fetchone()
        assert lease["revision"] == 1
        with pytest.raises(Exception, match="lease_cas_mismatch"):
            coordinator.execute(
                "SELECT * FROM carl_autonomy.acquire_lease(%s, %s)",
                (_canonical(desired.to_canonical_dict()), NOW),
            ).fetchone()
        reconciliation = LeaseReconciliation(
            lease_key="coordinator",
            holder_id="worker-001",
            authority="coordinator",
            expected_revision=1,
            next_revision=2,
            observed_at="2026-08-20T12:02:00Z",
        )
        reconciled = coordinator.execute(
            "SELECT * FROM carl_autonomy.reconcile_lease(%s, %s, %s)",
            (
                _canonical(reconciliation.to_canonical_dict()),
                dead_holder.digest,
                "2026-08-20T12:02:00Z",
            ),
        ).fetchone()
        reconciled_lease = json.loads(reconciled["lease_json"])
        release = LeaseRelease(
            lease_key="coordinator",
            holder_id="worker-001",
            authority="coordinator",
            expected_revision=2,
            next_revision=3,
            released_at="2026-08-20T12:02:01Z",
            observation_digest=reconciled_lease["reconciliation_observation_digest"],
        )
        released = coordinator.execute(
            "SELECT * FROM carl_autonomy.release_lease(%s, %s)",
            (_canonical(release.to_canonical_dict()), "2026-08-20T12:02:01Z"),
        ).fetchone()
        assert (released["status"], released["revision"]) == ("released", 3)

        trigger = SupervisorTrigger(
            schema_version=1,
            trigger_id="trigger-001",
            evidence_digest=DIGEST_A,
            unsafe_boundary="builder",
            attempt_history=(),
            next_safe_node_key="retry-builder",
            created_at=NOW,
        )
        coordinator.execute(
            "SELECT * FROM carl_autonomy.create_supervisor_trigger(%s, %s)",
            (_canonical(trigger.to_canonical_dict()), NOW),
        ).fetchone()

    resolution = TriggerResolution(
        status="resolved",
        recovery_action=RecoveryAttempt(
            attempt_id="recovery-001",
            action_digest=DIGEST_A,
            occurred_at=NOW,
            outcome="reconciled",
        ),
        evidence_digest=DIGEST_A,
        result_digest=DIGEST_B,
        resolved_at=NOW,
    )
    with _as_role(postgres, "carl_supervisor") as supervisor:
        claimed = supervisor.execute(
            "SELECT * FROM carl_autonomy.claim_supervisor_trigger(%s, %s, %s, %s)",
            ("trigger-001", "trigger-claim-001", 0, NOW),
        ).fetchone()
        resolved = supervisor.execute(
            "SELECT * FROM carl_autonomy.resolve_supervisor_trigger(%s, %s, %s, %s, %s)",
            (
                "trigger-001",
                "trigger-claim-001",
                1,
                _canonical(resolution.to_canonical_dict()),
                NOW,
            ),
        ).fetchone()
        assert (claimed["revision"], resolved["revision"]) == (1, 2)

    evidence = EvidenceObject(
        digest=DIGEST_A,
        object_key=f"evidence/{DIGEST_A}",
        object_version="version-001",
        producer="observer",
        request_digest=DIGEST_B,
        media_type="application/json",
        retained_until="2027-08-20T12:00:00Z",
    )
    health = HealthSnapshot(observed_at=NOW, healthy=True, detail_digest=DIGEST_B)
    with _as_role(postgres, "carl_observer") as observer:
        first = observer.execute(
            "SELECT * FROM carl_autonomy.register_evidence(%s, %s)",
            (_canonical(evidence.to_canonical_dict()), NOW),
        ).fetchone()
        duplicate = observer.execute(
            "SELECT * FROM carl_autonomy.register_evidence(%s, %s)",
            (_canonical(evidence.to_canonical_dict()), NOW),
        ).fetchone()
        recorded = observer.execute(
            "SELECT * FROM carl_autonomy.record_health(%s, %s)",
            (
                _canonical(
                    {"detail_digest": health.detail_digest, "healthy": True, "observed_at": NOW}
                ),
                NOW,
            ),
        ).fetchone()
        latest = observer.execute("SELECT * FROM carl_autonomy.latest_health_snapshot()").fetchone()
        assert (first["applied"], duplicate["applied"], recorded["applied"]) == (
            True,
            False,
            True,
        )
        assert latest == {
            "detail_digest": DIGEST_B,
            "healthy": True,
            "observed_at": NOW,
        }


def test_command_completion_and_event_append_are_atomic(postgres: object) -> None:
    manifest = sample_manifest()
    command = _command()
    claim = _claim()
    transition = _transition(revision=8)
    invalid_event = ExperimentEvent.create(
        experiment_id=manifest.experiment_id,
        stage_attempt_id="atomic-retry-invalid",
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at=NOW,
        payload={"attempt": 1},
    )
    valid_event = ExperimentEvent.create(
        experiment_id=manifest.experiment_id,
        stage_attempt_id="atomic-retry-valid",
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at=NOW,
        payload=_retry_payload(attempt=1, scheduled_at=NOW, changed_action="atomic retry"),
    )

    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    with _as_role(postgres, "carl_coordinator") as coordinator:
        coordinator.execute(
            "SELECT * FROM carl_autonomy.create_command(%s, %s)",
            (_canonical(command.to_canonical_dict()), NOW),
        ).fetchone()
        coordinator.execute(
            "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
            (_canonical(claim.to_canonical_dict()), NOW),
        ).fetchone()
    from datetime import UTC, datetime

    from psycopg import sql
    from psycopg.rows import dict_row

    def coordinator_connect(dsn: str):
        connection = postgres.connect(dsn, row_factory=dict_row)  # type: ignore[attr-defined]
        connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier("carl_coordinator")))
        return connection

    assert POSTGRES_DSN is not None
    backend = PostgresStateBackend.from_config(
        PostgresStateConfig(
            dsn=POSTGRES_DSN,
            database_role="carl_coordinator",
            authority_key=AUTHORITY_KEY,
            dead_holder_key=LIVENESS_KEY,
            clock=lambda: datetime(2026, 8, 20, 12, tzinfo=UTC),
            connect=coordinator_connect,
        )
    )
    command_capability = _capability(
        action="complete_command_with_event",
        authority="coordinator",
        subject_id=transition.claim_id,
        scope_kind="command",
        scope_key=transition.command_key,
        revision=transition.expected_revision,
    )
    invalid_event_capability = _capability(
        action="append_event",
        authority="coordinator",
        subject_id=invalid_event.stage_attempt_id,
        scope_kind="event",
        scope_key=invalid_event.experiment_id,
        revision=0,
    )
    with pytest.raises(PostgresStateError, match="postgres_mutation_failed"):
        backend.complete_command_with_event(
            transition,
            invalid_event,
            command_capability=command_capability,
            event_capability=invalid_event_capability,
        )
    with _as_role(postgres, "carl_coordinator") as coordinator:
        state = coordinator.execute(
            "SELECT * FROM carl_autonomy.create_command(%s, %s)",
            (_canonical(command.to_canonical_dict()), NOW),
        ).fetchone()
        events = coordinator.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()
        assert (state["status"], state["revision"], state["applied"]) == (
            "claimed",
            8,
            False,
        )
        assert events == []

    valid_event_capability = _capability(
        action="append_event",
        authority="coordinator",
        subject_id=valid_event.stage_attempt_id,
        scope_kind="event",
        scope_key=valid_event.experiment_id,
        revision=0,
    )
    completed, appended = backend.complete_command_with_event(
        transition,
        valid_event,
        command_capability=command_capability,
        event_capability=valid_event_capability,
    )
    assert (completed.state.status, completed.state.revision, appended.ordinal) == (
        "completed",
        9,
        1,
    )
