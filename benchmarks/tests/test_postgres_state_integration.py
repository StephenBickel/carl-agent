from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import tempfile
import threading
import time
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from postgres_event_policy import EVENT_PAYLOAD_KEY_SETS, INVALID_EVENT_PAYLOAD_TYPES
from psycopg.rows import dict_row
from test_cloud_coordinator import node as coordinator_node
from test_cloud_coordinator import snapshot as coordinator_snapshot
from test_experiment import (
    candidate_artifact,
    paired_evidence,
    phase3_build_events,
    prepared_candidate,
    sealed_candidate,
)
from test_experiment import (
    manifest as sample_manifest,
)

from carl_bench.candidate import DraftPullRequest, ReviewAttestation, ReviewPacket
from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_coordinator import (
    CloudCoordinatorDecision,
    CoordinatorSnapshot,
    choose_next_action,
    reconstruct_snapshot,
)
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
from carl_bench.coordinator_recovery import CoordinatorRecoveryRequest
from carl_bench.experiment import EventType, ExperimentEvent, ExperimentState
from carl_bench.github_cloud import GitHubEffectAttempt
from carl_bench.live_evaluation_authority import ProtectedArchiveVersion
from carl_bench.postgres_state import (
    PostgresCoordinatorRecoveryReceiptRegistrar,
    PostgresStateBackend,
    PostgresStateConfig,
    PostgresStateError,
)
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
BASE_MIGRATIONS = (
    REPOSITORY_ROOT / "infra/autonomy/postgres/001_initial.sql",
    REPOSITORY_ROOT / "infra/autonomy/postgres/002_role_procedures.sql",
)
GITHUB_EFFECT_FENCES_MIGRATION = (
    REPOSITORY_ROOT / "infra/autonomy/postgres/003_github_effect_fences.sql"
)
COORDINATOR_RUNTIME_MIGRATION = (
    REPOSITORY_ROOT / "infra/autonomy/postgres/004_coordinator_runtime.sql"
)
SUPERVISOR_AUTHORITY_MIGRATION = (
    REPOSITORY_ROOT / "infra/autonomy/postgres/005_supervisor_authority.sql"
)
HISTORICAL_EFFECT_FENCE_FIXTURE = (
    REPOSITORY_ROOT / "benchmarks/tests/fixtures/postgres-4aa2ab5-github-effect-fences.sql"
)
MIGRATIONS = (
    *BASE_MIGRATIONS,
    GITHUB_EFFECT_FENCES_MIGRATION,
    COORDINATOR_RUNTIME_MIGRATION,
    SUPERVISOR_AUTHORITY_MIGRATION,
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


@pytest.mark.parametrize(
    ("value", "expected"),
    (
        ("{}", 0),
        ('{"alpha":1,"beta":{"nested":true}}', 2),
        ('{"duplicate":1,"duplicate":2}', 1),
        ("[]", None),
        ("[1,2]", None),
        ('"scalar"', None),
        ("1", None),
        ("null", None),
    ),
)
def test_jsonb_object_cardinality_is_exact_and_fails_closed(
    postgres: object, value: str, expected: int | None
) -> None:
    assert POSTGRES_DSN is not None
    with postgres.connect(POSTGRES_DSN, autocommit=True) as connection:  # type: ignore[attr-defined]
        actual = connection.execute(
            "SELECT carl_autonomy.jsonb_object_cardinality(%s::jsonb)", (value,)
        ).fetchone()[0]
    assert actual == expected


def test_coordinator_timestamp_preserves_six_digit_python_canonical_fraction(
    postgres: object,
) -> None:
    assert POSTGRES_DSN is not None
    with postgres.connect(POSTGRES_DSN, autocommit=True) as connection:  # type: ignore[attr-defined]
        actual = connection.execute(
            "SELECT carl_autonomy.coordinator_timestamp(%s::timestamptz)",
            ("2026-08-23T22:12:22.258780Z",),
        ).fetchone()[0]
    assert actual == "2026-08-23T22:12:22.258780Z"


@pytest.mark.parametrize(
    ("url", "expected"),
    (
        ("https://github.com/StephenBickel/carl-agent/pull/17", True),
        ("https://github.com/StephenBickel/carl-agent/pull/18", False),
        ("https://github.com/other-owner/carl-agent/pull/17", False),
        ({"value": "https://github.com/StephenBickel/carl-agent/pull/17"}, False),
    ),
)
def test_draft_pr_url_identity_uses_exact_text_concatenation(
    postgres: object, url: object, expected: bool
) -> None:
    payload = {
        "_lease": {"owner_id": "promoter-1", "stage_attempt_id": "draft-pr-1"},
        "base_branch": "main",
        "candidate_commit": "a" * 40,
        "head_branch": "codex/experiment-url-precedence-0123456789",
        "is_draft": True,
        "number": 17,
        "repository": "StephenBickel/carl-agent",
        "schema_version": 1,
        "state": "OPEN",
        "url": url,
    }
    assert POSTGRES_DSN is not None
    with postgres.connect(POSTGRES_DSN, autocommit=True) as connection:  # type: ignore[attr-defined]
        actual = connection.execute(
            "SELECT carl_autonomy.event_payload_keys_exact('draft_pr_recorded', %s::jsonb) "
            "AND carl_autonomy.event_payload_shape_valid('draft_pr_recorded', %s::jsonb)",
            (json.dumps(payload), json.dumps(payload)),
        ).fetchone()[0]
    assert actual is expected


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
            "TRUNCATE carl_autonomy.supervisor_recovery_receipts, "
            "carl_autonomy.supervisor_recovery_attempts, "
            "carl_autonomy.coordinator_recovery_receipts, "
            "carl_autonomy.coordinator_runtime, "
            "carl_autonomy.experiment_events, "
            "carl_autonomy.experiment_manifests, carl_autonomy.commands, "
            "carl_autonomy.leases, carl_autonomy.supervisor_triggers, "
            "carl_autonomy.evidence_objects, carl_autonomy.monitor_snapshots, "
            "carl_autonomy.dead_holder_observations "
            "RESTART IDENTITY CASCADE"
        )


def _supervisor_claim_document(
    trigger_id: str,
    *,
    expected_revision: int,
    action_digest: str,
    attempt_id: str,
) -> dict[str, object]:
    return {
        "action_digest": action_digest,
        "action_kind": "freeze_stable_boundary",
        "attempt_id": attempt_id,
        "claim_id": f"supervisor:{trigger_id}",
        "expected_revision": expected_revision,
        "schema_version": 1,
        "trigger_id": trigger_id,
    }


def _create_supervisor_trigger(
    connection: object,
    *,
    trigger_id: str,
    unsafe_boundary: str,
    created_at: str,
) -> None:
    trigger = SupervisorTrigger(
        schema_version=1,
        trigger_id=trigger_id,
        evidence_digest=DIGEST_A,
        unsafe_boundary=unsafe_boundary,
        attempt_history=(),
        next_safe_node_key="experiment-1:schedule_soak",
        created_at=created_at,
    )
    connection.execute(  # type: ignore[attr-defined]
        "SELECT * FROM carl_autonomy.create_supervisor_trigger(%s, %s)",
        (_canonical(trigger.to_canonical_dict()), created_at),
    ).fetchone()


def test_supervisor_authority_prioritizes_rollback_and_denies_lower_priority_claim(
    postgres: object,
) -> None:
    with _as_role(postgres, "carl_coordinator") as coordinator:
        _create_supervisor_trigger(
            coordinator,
            trigger_id="commissioning-outage",
            unsafe_boundary="commissioning:provider",
            created_at="2026-08-20T10:00:00Z",
        )
        _create_supervisor_trigger(
            coordinator,
            trigger_id="rollback-required",
            unsafe_boundary="rollback:hard_failure",
            created_at="2026-08-20T11:00:00Z",
        )

    with _as_role(postgres, "carl_supervisor") as supervisor:
        selected = supervisor.execute(
            "SELECT * FROM carl_autonomy.select_supervisor_trigger()"
        ).fetchone()
        assert selected["trigger_id"] == "rollback-required"
        with pytest.raises(psycopg.Error, match="rollback_priority_required"):
            supervisor.execute(
                "SELECT * FROM carl_autonomy.claim_supervisor_recovery(%s, %s)",
                (
                    _canonical(
                        _supervisor_claim_document(
                            "commissioning-outage",
                            expected_revision=0,
                            action_digest="1" * 64,
                            attempt_id="attempt-1",
                        )
                    ),
                    NOW,
                ),
            ).fetchone()


def test_supervisor_authority_enforces_changed_action_and_three_infrastructure_attempts(
    postgres: object,
) -> None:
    with _as_role(postgres, "carl_coordinator") as coordinator:
        _create_supervisor_trigger(
            coordinator,
            trigger_id="provider-outage",
            unsafe_boundary="commissioning:provider",
            created_at=NOW,
        )

    revision = 0
    with _as_role(postgres, "carl_supervisor") as supervisor:
        for index in range(1, 4):
            action_digest = str(index) * 64
            attempt_id = f"infrastructure-attempt-{index}"
            claim = supervisor.execute(
                "SELECT * FROM carl_autonomy.claim_supervisor_recovery(%s, %s)",
                (
                    _canonical(
                        _supervisor_claim_document(
                            "provider-outage",
                            expected_revision=revision,
                            action_digest=action_digest,
                            attempt_id=attempt_id,
                        )
                    ),
                    NOW,
                ),
            ).fetchone()
            revision = claim["revision"]
            failure = {
                "action_digest": action_digest,
                "attempt_id": attempt_id,
                "claim_id": "supervisor:provider-outage",
                "expected_revision": revision,
                "failure_code": "coordinator_service_unavailable",
                "result_digest": str(index + 3) * 64,
                "schema_version": 1,
                "trigger_id": "provider-outage",
            }
            failed = supervisor.execute(
                "SELECT * FROM carl_autonomy.fail_supervisor_recovery(%s, %s)",
                (_canonical(failure), NOW),
            ).fetchone()
            assert failed["outcome"] == "infrastructure_attempted"
            revision = failed["revision"]

        with pytest.raises(psycopg.Error, match="infrastructure_attempt_budget_exhausted"):
            supervisor.execute(
                "SELECT * FROM carl_autonomy.claim_supervisor_recovery(%s, %s)",
                (
                    _canonical(
                        _supervisor_claim_document(
                            "provider-outage",
                            expected_revision=revision,
                            action_digest="9" * 64,
                            attempt_id="infrastructure-attempt-4",
                        )
                    ),
                    NOW,
                ),
            ).fetchone()

        with pytest.raises(psycopg.Error, match="recovery_action_unchanged"):
            supervisor.execute(
                "SELECT * FROM carl_autonomy.claim_supervisor_recovery(%s, %s)",
                (
                    _canonical(
                        _supervisor_claim_document(
                            "provider-outage",
                            expected_revision=revision,
                            action_digest="1" * 64,
                            attempt_id="changed-id-same-action",
                        )
                    ),
                    NOW,
                ),
            ).fetchone()


def test_supervisor_completion_is_material_and_rereads_exact_durable_receipt(
    postgres: object,
) -> None:
    with _as_role(postgres, "carl_coordinator") as coordinator:
        _create_supervisor_trigger(
            coordinator,
            trigger_id="stable-boundary",
            unsafe_boundary="commissioning:provider",
            created_at=NOW,
        )
    claim_document = _supervisor_claim_document(
        "stable-boundary",
        expected_revision=0,
        action_digest="7" * 64,
        attempt_id="freeze-attempt-1",
    )
    with _as_role(postgres, "carl_supervisor") as supervisor:
        claimed = supervisor.execute(
            "SELECT * FROM carl_autonomy.claim_supervisor_recovery(%s, %s)",
            (_canonical(claim_document), NOW),
        ).fetchone()
        completion = {
            "action_digest": "7" * 64,
            "attempt_id": "freeze-attempt-1",
            "boundary": "commissioning:provider",
            "claim_id": "supervisor:stable-boundary",
            "evidence_digest": DIGEST_A,
            "expected_revision": claimed["revision"],
            "outcome": "stable_boundary_frozen",
            "result_digest": DIGEST_B,
            "schema_version": 1,
            "trigger_id": "stable-boundary",
        }
        completed = supervisor.execute(
            "SELECT * FROM carl_autonomy.complete_supervisor_recovery(%s, %s)",
            (_canonical(completion), NOW),
        ).fetchone()
        reread = supervisor.execute(
            "SELECT * FROM carl_autonomy.read_supervisor_recovery_receipt(%s, %s)",
            ("stable-boundary", "7" * 64),
        ).fetchone()

    assert completed == reread
    assert completed["outcome"] == "stable_boundary_frozen"
    assert completed["revision"] == 2
    receipt = json.loads(completed["receipt_json"])
    assert receipt["action_digest"] == "7" * 64
    assert receipt["authoritative_revision"] == 2
    assert receipt["outcome"] == "stable_boundary_frozen"


@contextmanager
def _as_role(postgres: object, role: str):
    from psycopg import sql
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None
    with postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    ) as connection:
        database_role = "carl_archive_backend" if role == "carl_archive" else "carl_state_backend"
        connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(database_role)))
        if role == "carl_archive":
            yield connection
            return
        connection.execute(
            "SELECT set_config('carl_autonomy.authority', %s, false)",
            (role.removeprefix("carl_"),),
        )
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


def test_completion_receipt_builder_rejects_unknown_nodes_and_arbitrary_authority(
    postgres: object,
) -> None:
    with (
        postgres.connect(  # type: ignore[attr-defined]
            POSTGRES_DSN, autocommit=True, row_factory=dict_row
        ) as admin,
        pytest.raises(psycopg.Error, match="coordinator_completion_identity_invalid"),
    ):
        admin.execute(
            "SELECT * FROM carl_autonomy.build_coordinator_completion_event("
            "%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                "experiment-1",
                "attacker_selected_node",
                1,
                "experiment-1:attacker:attempt:1",
                f"cloud-effect-{'a' * 64}",
                "b" * 64,
                "c" * 64,
                NOW,
            ),
        ).fetchone()


def _retry_payload(*, attempt: int, scheduled_at: str, changed_action: str) -> dict[str, Any]:
    return {
        "attempt": attempt,
        "changed_action": changed_action,
        "failed_stage_attempt_id": "failed-stage-001",
        "failure_class": "infrastructure",
        "scheduled_at": scheduled_at,
    }


def _insert_coordinator_receipt_fixture(
    connection: object, *, node_kind: str, include_soak: bool = False
) -> tuple[str, str]:
    experiment_id = "experiment-1"
    request_digest = "9" * 64
    archive_receipt_digest = "a" * 64
    experimental_receipt_digest = "b" * 64
    live_receipt_digest = "c" * 64
    disposition_receipt_digest = "d" * 64
    checks_receipt_digest = "e" * 64
    protection_receipt_digest = "f" * 64
    archive_digest = "1" * 64
    candidate_commit = "2" * 40
    candidate_tree = "3" * 40
    merge_commit = "4" * 40
    merge_tree = "5" * 40
    retained_until = "2027-08-22T12:00:00Z"
    manifest_digest = "6" * 64
    connection.execute(  # type: ignore[attr-defined]
        "INSERT INTO carl_autonomy.experiment_manifests("
        "experiment_id, manifest_json, manifest_digest, registered_at, registered_at_text, "
        "recorded_at) VALUES (%s, %s, %s, %s, %s, %s)",
        (experiment_id, "{}", manifest_digest, NOW, NOW, NOW),
    )
    connection.execute(  # type: ignore[attr-defined]
        "INSERT INTO carl_autonomy.experiment_projection_guards("
        "experiment_id, manifest_digest, manifest_parent_commit, manifest_registered_at, "
        "manifest_deterministic_checks, experimental_branch, "
        "experimental_candidate_packet_digest, experimental_commit, experimental_tree, "
        "protected_validation_receipt_digest, paired_evidence_digest, paired_decision, "
        "promotion_merge_commit, promotion_merge_tree, promotion_merged_at, updated_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            experiment_id,
            manifest_digest,
            "7" * 40,
            NOW,
            ["benchmark-contracts"],
            f"experimental/{experiment_id}",
            experimental_receipt_digest,
            candidate_commit,
            candidate_tree,
            live_receipt_digest,
            disposition_receipt_digest,
            "improvement",
            merge_commit if include_soak else None,
            merge_tree if include_soak else None,
            "2026-08-21T12:00:00Z" if include_soak else None,
            NOW,
        ),
    )
    for digest, version in (
        (archive_receipt_digest, "archive-v1"),
        (checks_receipt_digest, "checks-v1"),
        (protection_receipt_digest, "protection-v1"),
    ):
        evidence = {
            "digest": digest,
            "media_type": "application/json",
            "object_key": f"evidence/{digest}",
            "object_version": version,
            "producer": "observer",
            "request_digest": request_digest,
            "retained_until": retained_until,
        }
        connection.execute(  # type: ignore[attr-defined]
            "INSERT INTO carl_autonomy.evidence_objects("
            "digest, object_key, object_version, producer, request_digest, media_type, "
            "retained_until, retained_until_text, evidence_json, recorded_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                digest,
                evidence["object_key"],
                version,
                "observer",
                request_digest,
                "application/json",
                retained_until,
                retained_until,
                _canonical(evidence),
                "2026-08-22T12:00:00Z",
            ),
        )
    selected = coordinator_node(node_kind, request_digest=request_digest)
    snapshot_json = _canonical(coordinator_snapshot(selected).to_canonical_dict())
    receipts: dict[str, object] = {
        "archive_digest": archive_digest,
        "archive_object_key": f"carl-evidence/v1/sha256/{archive_digest[:2]}/{archive_digest}",
        "archive_receipt_digest": archive_receipt_digest,
        "archive_retain_until": retained_until,
        "archive_version_id": "archive-v1",
        "branch_protection_receipt_digest": protection_receipt_digest,
        "candidate_commit": candidate_commit,
        "candidate_tree": candidate_tree,
        "experiment_id": experiment_id,
        "experimental_receipt_digest": experimental_receipt_digest,
        "experimental_ref": f"refs/heads/experimental/{experiment_id}",
        "hard_failure_digest": None,
        "independent_disposition_receipt_digest": disposition_receipt_digest,
        "live_provenance_receipt_digest": live_receipt_digest,
        "merge_commit": merge_commit if include_soak else None,
        "merge_tree": merge_tree if include_soak else None,
        "merged_at": "2026-08-21T12:00:00Z" if include_soak else None,
        "node_kind": node_kind,
        "pull_request_base": "main",
        "pull_request_head": candidate_commit,
        "pull_request_number": 42,
        "repository": "StephenBickel/carl-agent",
        "request_digest": request_digest,
        "required_checks_receipt_digest": checks_receipt_digest,
        "revert_candidate_commit": None,
        "soak_observation_digest": "8" * 64 if include_soak else None,
        "soak_observed_at": "2026-08-22T12:00:00Z" if include_soak else None,
        "verified_at": None,
    }
    receipts_json = _canonical(receipts)
    connection.execute(  # type: ignore[attr-defined]
        "INSERT INTO carl_autonomy.coordinator_runtime("
        "experiment_id, command_name, snapshot_json, snapshot_digest, "
        "production_receipts_json, production_receipts_digest, status, revision, updated_at) "
        "VALUES (%s, 'commission-live', %s, %s, %s, %s, 'ready', 7, %s)",
        (
            experiment_id,
            snapshot_json,
            hashlib.sha256(snapshot_json.encode()).hexdigest(),
            receipts_json,
            hashlib.sha256(receipts_json.encode()).hexdigest(),
            NOW,
        ),
    )
    if include_soak:
        payload = {
            "evidence_digest": "8" * 64,
            "healthy": True,
            "merge_commit": merge_commit,
            "observed_at": "2026-08-22T12:00:00Z",
        }
        connection.execute(  # type: ignore[attr-defined]
            "INSERT INTO carl_autonomy.experiment_events("
            "experiment_id, ordinal, schema_version, stage_attempt_id, event_type, occurred_at, "
            "occurred_at_text, payload_json, event_json, event_digest, previous_chain_digest, "
            "chain_digest, authority, trusted_authority, provenance_json, appended_at) "
            "VALUES (%s, 1, 1, 'soak-healthy', 'soak_observed', %s, %s, %s, '{}', %s, %s, "
            "%s, 'soak', true, '{}', %s)",
            (
                experiment_id,
                "2026-08-22T12:00:00Z",
                "2026-08-22T12:00:00Z",
                _canonical(payload),
                "8" * 64,
                "0" * 64,
                "8" * 64,
                "2026-08-22T12:00:00Z",
            ),
        )
    return checks_receipt_digest, protection_receipt_digest


def test_coordinator_runtime_returns_exact_protected_check_object_bindings(
    postgres: object,
) -> None:
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None
    with postgres.connect(POSTGRES_DSN, autocommit=True, row_factory=dict_row) as admin:  # type: ignore[attr-defined]
        checks_digest, protection_digest = _insert_coordinator_receipt_fixture(
            admin, node_kind="enable_auto_merge"
        )
    with _as_role(postgres, "carl_coordinator") as coordinator:
        row = coordinator.execute(
            "SELECT * FROM carl_autonomy.load_coordinator_snapshot(%s, %s)",
            ("commission-live", "2026-08-22T12:00:00Z"),
        ).fetchone()

    receipts = json.loads(row["production_receipts_json"])
    assert receipts["required_checks_object_key"] == f"evidence/{checks_digest}"
    assert receipts["required_checks_object_version"] == "checks-v1"
    assert receipts["branch_protection_object_key"] == f"evidence/{protection_digest}"
    assert receipts["branch_protection_object_version"] == "protection-v1"


def test_coordinator_runtime_rejects_a_later_unhealthy_soak_atomically(
    postgres: object,
) -> None:
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None
    with postgres.connect(POSTGRES_DSN, autocommit=True, row_factory=dict_row) as admin:  # type: ignore[attr-defined]
        _insert_coordinator_receipt_fixture(admin, node_kind="accept_soak", include_soak=True)
    with _as_role(postgres, "carl_coordinator") as coordinator:
        healthy = coordinator.execute(
            "SELECT * FROM carl_autonomy.load_coordinator_snapshot(%s, %s)",
            ("commission-live", "2026-08-22T12:00:00Z"),
        ).fetchone()
    assert healthy["production_receipts_json"] is not None

    failure_payload = {
        "evidence_digest": "9" * 64,
        "healthy": False,
        "merge_commit": "4" * 40,
        "observed_at": "2026-08-22T12:30:00Z",
    }
    with postgres.connect(POSTGRES_DSN, autocommit=True, row_factory=dict_row) as admin:  # type: ignore[attr-defined]
        admin.execute(
            "INSERT INTO carl_autonomy.experiment_events("
            "experiment_id, ordinal, schema_version, stage_attempt_id, event_type, occurred_at, "
            "occurred_at_text, payload_json, event_json, event_digest, previous_chain_digest, "
            "chain_digest, authority, trusted_authority, provenance_json, appended_at) "
            "VALUES ('experiment-1', 2, 1, 'soak-hard-failure', 'soak_observed', %s, %s, %s, "
            "'{}', %s, %s, %s, 'soak', true, '{}', %s)",
            (
                "2026-08-22T12:30:00Z",
                "2026-08-22T12:30:00Z",
                _canonical(failure_payload),
                "9" * 64,
                "8" * 64,
                "9" * 64,
                "2026-08-22T12:30:00Z",
            ),
        )
    with (
        _as_role(postgres, "carl_coordinator") as coordinator,
        pytest.raises(psycopg.Error, match="coordinator_production_receipt_mismatch"),
    ):
        coordinator.execute(
            "SELECT * FROM carl_autonomy.load_coordinator_snapshot(%s, %s)",
            ("commission-live", "2026-08-22T13:00:00Z"),
        ).fetchone()


def test_acceptance_append_rechecks_a_concurrent_production_worse_commit(
    postgres: object,
) -> None:
    manifest = sample_manifest()
    history = _full_event_history()
    accepted_index = next(
        index for index, event in enumerate(history) if event.stage_attempt_id == "parity-accepted"
    )
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    for event in history[:accepted_index]:
        with _as_role(postgres, f"carl_{_event_authority(event)}") as connection:
            _append_event(connection, event)

    production_worse = ExperimentEvent.create(
        experiment_id=manifest.experiment_id,
        stage_attempt_id="acceptance-race-production-worse",
        event_type=EventType.SOAK_OBSERVED,
        occurred_at="2026-08-11T12:02:30Z",
        payload={
            "evidence_digest": "9" * 64,
            "healthy": False,
            "merge_commit": "d" * 40,
            "observed_at": "2026-08-11T12:02:30Z",
        },
    )
    accepted = history[accepted_index]

    with (
        _as_role(postgres, "carl_soak") as acceptance_connection,
        _as_role(postgres, "carl_soak") as failure_connection,
    ):
        acceptance_connection.execute("BEGIN")
        observed = acceptance_connection.execute(
            "SELECT count(*) AS count FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchone()
        assert observed == {"count": accepted_index}
        failure_connection.execute("BEGIN")
        _append_event(failure_connection, production_worse)
        failure_connection.execute("COMMIT")
        with pytest.raises(psycopg.Error, match="soak_healthy_observation_required"):
            _append_event(acceptance_connection, accepted)
        acceptance_connection.execute("ROLLBACK")


def test_postgres_effect_family_routing_is_exhaustive_and_matches_python(
    postgres: object,
) -> None:
    from psycopg.rows import dict_row

    from carl_bench.cloud_coordinator import EFFECT_FAMILY_BY_NODE

    assert POSTGRES_DSN is not None
    with postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    ) as admin:
        rows = admin.execute(
            "SELECT node_kind, carl_autonomy.coordinator_effect_family(node_kind) AS family "
            "FROM unnest(%s::text[]) WITH ORDINALITY AS nodes(node_kind, ordinal) "
            "ORDER BY ordinal",
            (list(EFFECT_FAMILY_BY_NODE),),
        ).fetchall()

    assert {row["node_kind"]: row["family"] for row in rows} == dict(EFFECT_FAMILY_BY_NODE)


def test_protected_enqueue_turns_an_authenticated_manifest_into_all_22_nodes(
    postgres: object,
) -> None:
    from carl_bench.cloud_coordinator import NODE_ORDER

    manifest = sample_manifest()
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    with _as_role(postgres, "carl_coordinator") as coordinator:
        enqueued = coordinator.execute(
            "SELECT * FROM carl_autonomy.enqueue_pending_coordinator_graph(%s)",
            (NOW,),
        ).fetchone()
        replay = coordinator.execute(
            "SELECT * FROM carl_autonomy.enqueue_pending_coordinator_graph(%s)",
            (NOW,),
        ).fetchone()
    with postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    ) as admin:
        row = admin.execute(
            "SELECT snapshot_json, graph_request_digest, graph_occurrence_key "
            "FROM carl_autonomy.coordinator_runtime WHERE experiment_id = %s",
            (manifest.experiment_id,),
        ).fetchone()

    graph = json.loads(row["snapshot_json"])
    assert enqueued["applied"] is True
    assert replay["applied"] is False
    assert enqueued["request_digest"] == row["graph_request_digest"]
    assert enqueued["occurrence_key"] == row["graph_occurrence_key"]
    assert [item["kind"] for item in graph["nodes"]] == list(NODE_ORDER)
    assert len({item["node_id"] for item in graph["nodes"]}) == 22
    assert graph["immutable_inputs"][0]["digest"] == manifest.digest


def test_invalid_completion_freeze_is_atomic_across_crash_and_replay(
    postgres: object,
) -> None:
    manifest = sample_manifest()
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    with _as_role(postgres, "carl_coordinator") as coordinator:
        coordinator.execute(
            "SELECT * FROM carl_autonomy.enqueue_pending_coordinator_graph(%s)", (NOW,)
        ).fetchone()

        def load() -> CoordinatorSnapshot:
            row = coordinator.execute(
                "SELECT * FROM carl_autonomy.load_coordinator_snapshot(%s,%s)",
                ("coordinate", NOW),
            ).fetchone()
            assert row["snapshot_json"] is not None
            return reconstruct_snapshot(json.loads(row["snapshot_json"]))

        for expected_action in ("acquire_lease", "persist_command", "claim_command"):
            decision = choose_next_action(load())
            assert decision.action == expected_action
            applied = coordinator.execute(
                "SELECT * FROM carl_autonomy.apply_coordinator_decision(%s,%s)",
                (_canonical(decision.to_canonical_dict()), NOW),
            ).fetchone()
            assert applied["decision_json"] == _canonical(decision.to_canonical_dict())

        claimed = load()
        selected = next(item for item in claimed.nodes if item.kind == "publish_input")
        assert claimed.command is not None
        command = claimed.command.command
        identity_payload = {
            "action": "complete_command",
            "command_key": command.command_key,
            "effect_key": command.effect_key,
            "experiment_id": claimed.experiment_id,
            "node_id": selected.node_id,
            "reason": "observed_effect_completion_required",
            "revision": claimed.revision,
        }
        invalid_completion = CloudCoordinatorDecision(
            schema_version=1,
            action="complete_command",
            reason="observed_effect_completion_required",
            identity=hashlib.sha256(canonical_json_bytes(identity_payload)).hexdigest(),
            experiment_id=claimed.experiment_id,
            revision=claimed.revision,
            node=selected.kind,
            command=command,
            effect_key=command.effect_key,
            result_digest="a" * 64,
            consequential=True,
            remote_effect=False,
            event=None,
        )
        invalid_json = _canonical(invalid_completion.to_canonical_dict())

        coordinator.execute("BEGIN")
        crashed = coordinator.execute(
            "SELECT * FROM carl_autonomy.apply_coordinator_decision(%s,%s)",
            (invalid_json, NOW),
        ).fetchone()
        assert json.loads(crashed["decision_json"])["action"] == "frozen"
        assert (
            coordinator.execute(
                "SELECT * FROM carl_autonomy.coordinator_frozen_status(%s)", ("coordinate",)
            ).fetchone()["already_frozen"]
            is True
        )
        coordinator.execute("ROLLBACK")

        assert (
            coordinator.execute(
                "SELECT * FROM carl_autonomy.coordinator_frozen_status(%s)", ("coordinate",)
            ).fetchone()["already_frozen"]
            is False
        )
        committed = coordinator.execute(
            "SELECT * FROM carl_autonomy.apply_coordinator_decision(%s,%s)",
            (invalid_json, NOW),
        ).fetchone()
        frozen = json.loads(committed["decision_json"])
        assert (frozen["action"], frozen["reason"]) == (
            "frozen",
            "authoritative_completion_receipt_invalid",
        )
        assert (
            coordinator.execute(
                "SELECT * FROM carl_autonomy.coordinator_frozen_status(%s)", ("coordinate",)
            ).fetchone()["already_frozen"]
            is True
        )

    with postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    ) as reader:
        occurrence_count = reader.execute(
            "SELECT count(*) AS count FROM carl_autonomy.coordinator_freeze_occurrences "
            "WHERE experiment_id=%s",
            (manifest.experiment_id,),
        ).fetchone()["count"]
    assert occurrence_count == 1


def test_non_github_effect_is_fenced_then_constructs_receipt_after_verified_result(
    postgres: object,
) -> None:
    from carl_bench.cloud_coordinator import (
        CoordinatorNode,
        CoordinatorSnapshot,
        choose_next_action,
    )
    from carl_bench.cloud_state import CommandState

    manifest = sample_manifest()
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    with _as_role(postgres, "carl_coordinator") as coordinator:
        coordinator.execute(
            "SELECT * FROM carl_autonomy.enqueue_pending_coordinator_graph(%s)", (NOW,)
        ).fetchone()
    with postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    ) as admin:
        row = admin.execute(
            "SELECT snapshot_json FROM carl_autonomy.coordinator_runtime WHERE experiment_id=%s",
            (manifest.experiment_id,),
        ).fetchone()
    graph = json.loads(row["snapshot_json"])
    selected_value = next(item for item in graph["nodes"] if item["kind"] == "publish_input")
    selected = CoordinatorNode.from_canonical_dict(selected_value)
    command = selected.command(expected_revision=0)
    claim = CommandClaim(
        command_key=command.command_key,
        claim_id="claim:publish_input",
        authority=command.authority,
        expected_revision=0,
        claimed_at=NOW,
        expires_at="2026-08-20T12:15:00Z",
    )
    with _as_role(postgres, "carl_validator") as validator:
        validator.execute(
            "SELECT * FROM carl_autonomy.create_command(%s, %s)",
            (_canonical(command.to_canonical_dict()), NOW),
        ).fetchone()
        validator.execute(
            "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
            (_canonical(claim.to_canonical_dict()), NOW),
        ).fetchone()
    current = CoordinatorSnapshot(
        schema_version=1,
        experiment_id=manifest.experiment_id,
        revision=0,
        observed_at=NOW,
        coordinator_id="carl-cloud-coordinator-v1",
        nodes=tuple(CoordinatorNode.from_canonical_dict(item) for item in graph["nodes"]),
        lease=CloudLease(
            lease_key=f"{manifest.experiment_id}:coordinator",
            holder_id="carl-cloud-coordinator-v1",
            authority="coordinator",
            revision=1,
            acquired_at="2026-08-20T11:30:00Z",
            expires_at="2026-08-20T12:30:00Z",
        ),
        command=CommandState(
            command=command,
            revision=1,
            status="claimed",
            claim=claim,
            transition=None,
            result_digest=None,
            failure_code=None,
        ),
        effect=None,
        failure=None,
        production_authorization=None,
        immutable_inputs=(),
        dead_holder_observation_digest=None,
    )
    decision = choose_next_action(current)
    assert decision.action == "execute_effect"
    decision_json = _canonical(decision.to_canonical_dict())
    with _as_role(postgres, "carl_coordinator") as coordinator:
        first = coordinator.execute(
            "SELECT * FROM carl_autonomy.prepare_coordinator_effect(%s, %s)",
            (decision_json, NOW),
        ).fetchone()
        second = coordinator.execute(
            "SELECT * FROM carl_autonomy.prepare_coordinator_effect(%s, %s)",
            (decision_json, NOW),
        ).fetchone()
    with postgres.connect(POSTGRES_DSN, autocommit=True) as admin:  # type: ignore[attr-defined]
        occurrence = admin.execute(
            "SELECT status, request_digest FROM carl_autonomy.coordinator_effect_occurrences "
            "WHERE effect_key=%s",
            (command.effect_key,),
        ).fetchone()

    assert first == second
    assert occurrence == (
        "in_progress",
        hashlib.sha256(first["request_json"].encode("utf-8")).hexdigest(),
    )

    from carl_bench.coordinator_effects import (
        CoordinatorNodeEffectRequest,
        CoordinatorNodeEffectResponse,
    )

    request = CoordinatorNodeEffectRequest.from_canonical_dict(json.loads(first["request_json"]))
    response = CoordinatorNodeEffectResponse.completed(
        request=request,
        result_digest="e" * 64,
        observed_at=NOW,
    )
    with _as_role(postgres, "carl_coordinator") as coordinator:
        completed = coordinator.execute(
            "SELECT * FROM carl_autonomy.complete_coordinator_effect(%s,%s,%s)",
            (decision_json, _canonical(response.to_canonical_dict()), NOW),
        ).fetchone()
    with postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    ) as admin:
        receipt = admin.execute(
            "SELECT completion_event_json, completion_event_digest, effect_response_json, "
            "status, carl_autonomy.coordinator_node_authority('publish_input') "
            "AS completion_event_authority "
            "FROM carl_autonomy.coordinator_runtime AS runtime WHERE experiment_id=%s",
            (manifest.experiment_id,),
        ).fetchone()

    event = json.loads(receipt["completion_event_json"])
    assert completed["applied"] is True
    assert receipt["status"] == "effect_observed"
    assert json.loads(receipt["effect_response_json"]) == response.to_canonical_dict()
    assert (
        receipt["completion_event_digest"]
        == hashlib.sha256(receipt["completion_event_json"].encode()).hexdigest()
    )
    assert "authority" not in event
    assert receipt["completion_event_authority"] == "validator"
    assert event["payload"] == {
        "command_key": command.command_key,
        "effect_key": command.effect_key,
        "node_kind": "publish_input",
        "request_digest": command.request_digest,
        "result_digest": "e" * 64,
    }


def test_concurrent_valid_effect_completion_replays_without_freeze_or_duplicate_effect(
    postgres: object,
) -> None:
    from carl_bench.cloud_coordinator import CoordinatorNode, CoordinatorSnapshot
    from carl_bench.cloud_state import CommandState
    from carl_bench.coordinator_effects import (
        CoordinatorNodeEffectRequest,
        CoordinatorNodeEffectResponse,
    )

    manifest = sample_manifest()
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    with _as_role(postgres, "carl_coordinator") as coordinator:
        coordinator.execute(
            "SELECT * FROM carl_autonomy.enqueue_pending_coordinator_graph(%s)", (NOW,)
        ).fetchone()
    assert POSTGRES_DSN is not None
    with postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    ) as admin:
        row = admin.execute(
            "SELECT snapshot_json FROM carl_autonomy.coordinator_runtime WHERE experiment_id=%s",
            (manifest.experiment_id,),
        ).fetchone()
    graph = json.loads(row["snapshot_json"])
    selected = CoordinatorNode.from_canonical_dict(
        next(item for item in graph["nodes"] if item["kind"] == "publish_input")
    )
    command = selected.command(expected_revision=0)
    claim = CommandClaim(
        command_key=command.command_key,
        claim_id="claim:concurrent-publish-input",
        authority=command.authority,
        expected_revision=0,
        claimed_at=NOW,
        expires_at="2026-08-20T12:15:00Z",
    )
    with _as_role(postgres, "carl_validator") as validator:
        validator.execute(
            "SELECT * FROM carl_autonomy.create_command(%s, %s)",
            (_canonical(command.to_canonical_dict()), NOW),
        ).fetchone()
        validator.execute(
            "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
            (_canonical(claim.to_canonical_dict()), NOW),
        ).fetchone()
    current = CoordinatorSnapshot(
        schema_version=1,
        experiment_id=manifest.experiment_id,
        revision=0,
        observed_at=NOW,
        coordinator_id="carl-cloud-coordinator-v1",
        nodes=tuple(CoordinatorNode.from_canonical_dict(item) for item in graph["nodes"]),
        lease=CloudLease(
            lease_key=f"{manifest.experiment_id}:coordinator",
            holder_id="carl-cloud-coordinator-v1",
            authority="coordinator",
            revision=1,
            acquired_at="2026-08-20T11:30:00Z",
            expires_at="2026-08-20T12:30:00Z",
        ),
        command=CommandState(
            command=command,
            revision=1,
            status="claimed",
            claim=claim,
            transition=None,
            result_digest=None,
            failure_code=None,
        ),
        effect=None,
        failure=None,
        production_authorization=None,
        immutable_inputs=(),
        dead_holder_observation_digest=None,
    )
    decision = choose_next_action(current)
    decision_json = _canonical(decision.to_canonical_dict())
    with _as_role(postgres, "carl_coordinator") as coordinator:
        prepared = coordinator.execute(
            "SELECT * FROM carl_autonomy.prepare_coordinator_effect(%s, %s)",
            (decision_json, NOW),
        ).fetchone()
    request = CoordinatorNodeEffectRequest.from_canonical_dict(json.loads(prepared["request_json"]))
    response_json = _canonical(
        CoordinatorNodeEffectResponse.completed(
            request=request,
            result_digest="e" * 64,
            observed_at=NOW,
        ).to_canonical_dict()
    )

    winner = postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN,
        row_factory=dict_row,
        application_name="carl-coordinator-completion-winner",
    )
    loser_started = threading.Event()
    loser_finished = threading.Event()
    loser_rows: list[dict[str, Any]] = []
    loser_errors: list[BaseException] = []

    def complete_as_loser() -> None:
        try:
            with postgres.connect(  # type: ignore[attr-defined]
                POSTGRES_DSN,
                autocommit=True,
                row_factory=dict_row,
                application_name="carl-coordinator-completion-loser",
            ) as connection:
                connection.execute("SET ROLE carl_state_backend")
                connection.execute(
                    "SELECT set_config('carl_autonomy.authority', 'coordinator', false)"
                )
                loser_started.set()
                loser_rows.append(
                    connection.execute(
                        "SELECT * FROM carl_autonomy.complete_coordinator_effect(%s,%s,%s)",
                        (decision_json, response_json, NOW),
                    ).fetchone()
                )
        except BaseException as error:
            loser_errors.append(error)
        finally:
            loser_finished.set()

    thread = threading.Thread(target=complete_as_loser, daemon=True)
    try:
        winner.execute("SET ROLE carl_state_backend")
        winner.execute("SELECT set_config('carl_autonomy.authority', 'coordinator', false)")
        winner_row = winner.execute(
            "SELECT * FROM carl_autonomy.complete_coordinator_effect(%s,%s,%s)",
            (decision_json, response_json, NOW),
        ).fetchone()
        thread.start()
        assert loser_started.wait(timeout=5)
        deadline = time.monotonic() + 5
        waiting_on_runtime_lock = False
        while time.monotonic() < deadline:
            with postgres.connect(  # type: ignore[attr-defined]
                POSTGRES_DSN, autocommit=True, row_factory=dict_row
            ) as observer:
                waiting = observer.execute(
                    "SELECT wait_event_type FROM pg_stat_activity "
                    "WHERE application_name='carl-coordinator-completion-loser' "
                    "AND state='active'"
                ).fetchone()
            if waiting is not None and waiting["wait_event_type"] == "Lock":
                waiting_on_runtime_lock = True
                break
            if loser_finished.is_set():
                break
            time.sleep(0.01)
        assert waiting_on_runtime_lock, "overlapping completion did not wait on the runtime lock"
        assert not loser_finished.is_set(), "overlapping completion did not serialize"
        winner.commit()
        assert loser_finished.wait(timeout=5)
    finally:
        if winner.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
            winner.rollback()
        winner.close()
        thread.join(timeout=5)

    assert loser_errors == []
    assert winner_row == {"applied": True, "decision_json": decision_json}
    assert loser_rows == [{"applied": False, "decision_json": decision_json}]
    with postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    ) as admin:
        durable = admin.execute(
            "SELECT status, effect_response_json, freeze_reason FROM "
            "carl_autonomy.coordinator_runtime WHERE experiment_id=%s",
            (manifest.experiment_id,),
        ).fetchone()
        effect_count = admin.execute(
            "SELECT count(*) AS count FROM carl_autonomy.coordinator_effect_occurrences "
            "WHERE effect_key=%s",
            (command.effect_key,),
        ).fetchone()["count"]
        freeze_count = admin.execute(
            "SELECT count(*) AS count FROM carl_autonomy.coordinator_freeze_occurrences "
            "WHERE experiment_id=%s",
            (manifest.experiment_id,),
        ).fetchone()["count"]

    assert durable == {
        "status": "effect_observed",
        "effect_response_json": response_json,
        "freeze_reason": None,
    }
    assert effect_count == 1
    assert freeze_count == 0


def test_frozen_node_reactivates_only_with_changed_retained_repair_evidence(
    postgres: object,
) -> None:
    from test_coordinator_recovery_archive import _signed_envelope, _trusted_keyring

    manifest = sample_manifest()
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    with _as_role(postgres, "carl_coordinator") as coordinator:
        coordinator.execute(
            "SELECT * FROM carl_autonomy.enqueue_pending_coordinator_graph(%s)", (NOW,)
        ).fetchone()
    with postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    ) as admin:
        row = admin.execute(
            "SELECT snapshot_json FROM carl_autonomy.coordinator_runtime WHERE experiment_id=%s",
            (manifest.experiment_id,),
        ).fetchone()
    graph = json.loads(row["snapshot_json"])
    selected = next(item for item in graph["nodes"] if item["kind"] == "publish_input")
    frozen_identity = hashlib.sha256(
        canonical_json_bytes(
            {
                "action": "frozen",
                "experiment_id": manifest.experiment_id,
                "node_id": selected["node_id"],
                "reason": "input_service_uncommissioned",
                "revision": 0,
            }
        )
    ).hexdigest()
    frozen = CloudCoordinatorDecision(
        schema_version=1,
        action="frozen",
        reason="input_service_uncommissioned",
        identity=frozen_identity,
        experiment_id=manifest.experiment_id,
        revision=0,
        node="publish_input",
        command=None,
        effect_key=None,
        result_digest=None,
        consequential=True,
        remote_effect=False,
        event=None,
    )
    freeze_fingerprint = hashlib.sha256(
        canonical_json_bytes(
            {
                "attempt": selected["attempt"],
                "experiment_id": manifest.experiment_id,
                "node_id": selected["node_id"],
                "node_kind": selected["kind"],
                "reason": frozen.reason,
                "request_digest": selected["request_digest"],
                "revision": 0,
            }
        )
    ).hexdigest()
    with _as_role(postgres, "carl_coordinator") as coordinator:
        applied = coordinator.execute(
            "SELECT * FROM carl_autonomy.apply_coordinator_decision(%s,%s)",
            (_canonical(frozen.to_canonical_dict()), NOW),
        ).fetchone()
    assert applied["applied"] is True
    with postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    ) as admin:
        freeze = admin.execute(
            "SELECT effect_key FROM carl_autonomy.coordinator_freeze_occurrences "
            "WHERE freeze_fingerprint=%s",
            (freeze_fingerprint,),
        ).fetchone()
    assert freeze is not None
    evidence = EvidenceObject(
        digest="c" * 64,
        object_key=f"evidence/{'c' * 64}",
        object_version="repair-v1",
        producer="observer",
        request_digest=selected["request_digest"],
        media_type="application/vnd.carl.repair-receipt+json",
        retained_until="2027-08-22T12:00:00Z",
    )
    recovery = {
        "domain": "carl.coordinator.recovery.v1",
        "evidence_digest": evidence.digest,
        "expected_revision": 0,
        "experiment_id": manifest.experiment_id,
        "node_id": selected["node_id"],
        "node_kind": selected["kind"],
        "repair_fingerprint": evidence.digest,
        "requested_at": NOW,
        "schema_version": 1,
    }
    with (
        _as_role(postgres, "carl_supervisor") as supervisor,
        pytest.raises(psycopg.Error, match="coordinator_recovery_evidence_invalid"),
    ):
        supervisor.execute(
            "SELECT * FROM carl_autonomy.reactivate_coordinator_node(%s, %s)",
            (_canonical(recovery), NOW),
        ).fetchone()
    with _as_role(postgres, "carl_observer") as observer:
        observer.execute(
            "SELECT * FROM carl_autonomy.register_evidence(%s, %s)",
            (_canonical(evidence.to_canonical_dict()), NOW),
        ).fetchone()
    with (
        _as_role(postgres, "carl_supervisor") as supervisor,
        pytest.raises(psycopg.Error, match="coordinator_recovery_evidence_invalid"),
    ):
        supervisor.execute(
            "SELECT * FROM carl_autonomy.reactivate_coordinator_node(%s, %s)",
            (_canonical(recovery), NOW),
        ).fetchone()

    artifact_identity = {
        "attempt": selected["attempt"],
        "changed_action_digest": "d" * 64,
        "command_key": selected["command_key"],
        "decision_identity": frozen.identity,
        "effect_key": freeze["effect_key"],
        "experiment_id": manifest.experiment_id,
        "freeze_fingerprint": freeze_fingerprint,
        "node_id": selected["node_id"],
        "node_kind": selected["kind"],
        "occurrence_key": f"coordinator-freeze/{freeze_fingerprint}",
        "reason": frozen.reason,
        "request_digest": selected["request_digest"],
        "runtime_revision": 0,
    }
    repair_fingerprint = hashlib.sha256(canonical_json_bytes(artifact_identity)).hexdigest()
    artifact = {
        **artifact_identity,
        "domain": "carl.coordinator-recovery-artifact.v1",
        "repair_fingerprint": repair_fingerprint,
        "repaired_at": NOW,
        "schema_version": 1,
    }
    envelope_json = _canonical(
        _signed_envelope(
            artifact,
            issued_at=NOW,
            expires_at="2026-08-20T13:00:00Z",
        )
    )
    evidence_digest = hashlib.sha256(envelope_json.encode()).hexdigest()
    recovery.update(
        evidence_digest=evidence_digest,
        repair_fingerprint=repair_fingerprint,
    )
    archived = ProtectedArchiveVersion(
        object_key=f"carl-evidence/v1/sha256/{evidence_digest[:2]}/{evidence_digest}",
        version_id="recovery-v1",
        payload=envelope_json.encode(),
        checksum_sha256=evidence_digest,
        byte_length=len(envelope_json.encode()),
        retention_mode="COMPLIANCE",
        retain_until="2027-08-22T12:00:00Z",
        created_at=NOW,
    )

    class Reader:
        def read_exact(self, object_key: str, version_id: str) -> ProtectedArchiveVersion:
            assert (object_key, version_id) == (archived.object_key, archived.version_id)
            return archived

    request = CoordinatorRecoveryRequest.from_canonical_dict(recovery)
    backend = _backend(postgres)
    registrar = _archive_registrar(postgres)
    repaired = backend.reactivate_coordinator_node(
        request,
        object_key=archived.object_key,
        version_id=archived.version_id,
        archive_reader=Reader(),
        receipt_registrar=registrar,
        observed_at=datetime.fromisoformat(NOW.replace("Z", "+00:00")),
        trusted_keyring=_trusted_keyring(),
    )
    replay = backend.reactivate_coordinator_node(
        request,
        object_key=archived.object_key,
        version_id=archived.version_id,
        archive_reader=Reader(),
        receipt_registrar=registrar,
        observed_at=datetime.fromisoformat(NOW.replace("Z", "+00:00")),
        trusted_keyring=_trusted_keyring(),
    )

    assert repaired["applied"] is True
    assert replay["applied"] is False
    assert repaired["attempt"] == 2
    assert repaired["revision"] == 1


@pytest.mark.parametrize(
    ("node_kind", "event_type"),
    (
        ("observe_revert", "revert_recorded"),
        ("observe_builder", "candidate_sealed"),
        ("archive_builder", "state_transitioned"),
        ("observe_validation", "protected_validation_recorded"),
        ("observe_required_checks", "state_transitioned"),
        ("trigger_supervisor", "retry_scheduled"),
    ),
)
def test_exact_observer_and_supervisor_node_completion_authority_is_node_bound(
    postgres: object, node_kind: str, event_type: str
) -> None:
    with _as_role(postgres, "carl_coordinator") as coordinator:
        allowed = coordinator.execute(
            "SELECT carl_autonomy.coordinator_node_event_authority(%s, %s) AS authority",
            (node_kind, event_type),
        ).fetchone()
        denied = coordinator.execute(
            "SELECT carl_autonomy.coordinator_node_event_authority(%s, %s) AS authority",
            (node_kind, "live_spend_recorded"),
        ).fetchone()

    assert allowed["authority"] in {"builder", "coordinator", "validator", "soak"}
    assert denied["authority"] is None


def test_coordinator_and_archive_backends_have_separated_procedure_only_access(
    postgres: object,
) -> None:
    with postgres.connect(POSTGRES_DSN, autocommit=True) as admin:  # type: ignore[attr-defined]
        privileges = admin.execute(
            "SELECT "
            "has_table_privilege('carl_state_backend', "
            "'carl_autonomy.coordinator_runtime', 'SELECT,INSERT,UPDATE,DELETE') "
            "AS runtime_raw, "
            "has_table_privilege('carl_state_backend', "
            "'carl_autonomy.coordinator_effect_occurrences', "
            "'SELECT,INSERT,UPDATE,DELETE') AS occurrence_raw, "
            "has_table_privilege('carl_state_backend', "
            "'carl_autonomy.coordinator_completion_receipts', "
            "'SELECT,INSERT,UPDATE,DELETE') AS completion_raw, "
            "has_table_privilege('carl_state_backend', "
            "'carl_autonomy.coordinator_freeze_occurrences', "
            "'SELECT,INSERT,UPDATE,DELETE') AS freeze_raw, "
            "has_function_privilege('carl_state_backend', "
            "'carl_autonomy.enqueue_pending_coordinator_graph(timestamptz)', "
            "'EXECUTE') AS protected_enqueue, "
            "has_function_privilege('carl_state_backend', "
            "'carl_autonomy.reactivate_coordinator_node(text,timestamptz)', "
            "'EXECUTE') AS protected_recovery, "
            "has_function_privilege('carl_state_backend', "
            "'carl_autonomy.build_coordinator_completion_event(text,text,integer,text,text,"
            "text,text,timestamptz)', 'EXECUTE') AS raw_completion_builder, "
            "has_function_privilege('carl_autonomy_workflow', "
            "'carl_autonomy.enqueue_coordinator_graph(text,timestamptz)', "
            "'EXECUTE') AS workflow_raw_enqueue, "
            "has_table_privilege('carl_archive_backend', "
            "'carl_autonomy.coordinator_recovery_receipts', "
            "'SELECT,INSERT,UPDATE,DELETE') AS archive_recovery_raw, "
            "has_function_privilege('carl_archive_backend', "
            "'carl_autonomy.register_coordinator_recovery_receipt(text,timestamptz)', "
            "'EXECUTE') AS archive_registration, "
            "has_function_privilege('carl_state_backend', "
            "'carl_autonomy.register_coordinator_recovery_receipt(text,timestamptz)', "
            "'EXECUTE') AS state_registration, "
            "has_function_privilege('carl_archive_backend', "
            "'carl_autonomy.reactivate_coordinator_node(text,timestamptz)', "
            "'EXECUTE') AS archive_reactivation"
        ).fetchone()

    assert privileges == (
        False,
        False,
        False,
        False,
        True,
        True,
        False,
        False,
        False,
        True,
        False,
        False,
    )


def _state_event(
    *,
    attempt: str,
    source: ExperimentState,
    target: ExperimentState,
    occurred_at: str,
    lease_attempt: str = "lease-phase3",
    lease_owner: str = "director-phase3",
) -> ExperimentEvent:
    payload: dict[str, Any] = {"from_state": source.value, "to_state": target.value}
    if target in {
        ExperimentState.BUILDING,
        ExperimentState.DETERMINISTIC_VALIDATION,
        ExperimentState.PAIRED_EVALUATION,
        ExperimentState.HOLDOUT_VALIDATION,
        ExperimentState.REVIEW_COMPLETE,
        ExperimentState.PR_OPEN,
        ExperimentState.MERGED,
        ExperimentState.SOAKING,
        ExperimentState.ACCEPTED,
    }:
        payload["_lease"] = {"owner_id": lease_owner, "stage_attempt_id": lease_attempt}
    return ExperimentEvent.create(
        experiment_id=sample_manifest().experiment_id,
        stage_attempt_id=attempt,
        event_type=EventType.STATE_TRANSITIONED,
        occurred_at=occurred_at,
        payload=payload,
    )


def _leased_event(
    *, attempt: str, event_type: EventType, occurred_at: str, payload: dict[str, Any]
) -> ExperimentEvent:
    return ExperimentEvent.create(
        experiment_id=sample_manifest().experiment_id,
        stage_attempt_id=attempt,
        event_type=event_type,
        occurred_at=occurred_at,
        payload={
            **payload,
            "_lease": {"owner_id": "director-phase3", "stage_attempt_id": "lease-phase3"},
        },
    )


def _full_event_history() -> tuple[ExperimentEvent, ...]:
    manifest = sample_manifest()
    candidate = sealed_candidate()
    evidence = paired_evidence()
    roles = ("correctness", "security", "maintainability", "benchmark_integrity")
    packets = {
        role: ReviewPacket(
            schema_version=1,
            experiment_id=manifest.experiment_id,
            manifest_digest=manifest.digest,
            candidate_commit=candidate.candidate_commit,
            role=role,
            diff_digest=candidate.diff_artifact.digest,
            deterministic_evidence_digest=candidate.digest,
            paired_evidence_digest=evidence.digest,
            review_contract_version="candidate-review-v1",
        )
        for role in roles
    }
    attestations = {
        role: ReviewAttestation(
            schema_version=1,
            experiment_id=manifest.experiment_id,
            manifest_digest=manifest.digest,
            candidate_commit=candidate.candidate_commit,
            role=role,
            reviewer_id=f"reviewer-{role}",
            context_id=f"context-{role}",
            packet_digest=packets[role].digest,
            verdict="approve" if index < 3 else "reject",
            report_artifact=candidate_artifact("review_report", marker),
        )
        for index, (role, marker) in enumerate(zip(roles, "789a", strict=True))
    }
    draft = DraftPullRequest(
        schema_version=1,
        repository="StephenBickel/carl-agent",
        number=17,
        url="https://github.com/StephenBickel/carl-agent/pull/17",
        state="OPEN",
        is_draft=True,
        base_branch="main",
        head_branch=candidate.branch,
        candidate_commit=candidate.candidate_commit,
    )
    events: list[ExperimentEvent] = list(phase3_build_events())
    events.extend(
        (
            ExperimentEvent.create(
                experiment_id=manifest.experiment_id,
                stage_attempt_id="parity-retry",
                event_type=EventType.RETRY_SCHEDULED,
                occurred_at="2026-08-10T12:00:08Z",
                payload=_retry_payload(
                    attempt=1,
                    scheduled_at="2026-08-10T12:00:08Z",
                    changed_action="retry with isolated state",
                ),
            ),
            ExperimentEvent.create(
                experiment_id=manifest.experiment_id,
                stage_attempt_id="parity-live-spend",
                event_type=EventType.LIVE_SPEND_RECORDED,
                occurred_at="2026-08-10T12:00:09Z",
                payload={"live_microdollars": 500, "run_id": "run-parity-001"},
            ),
            _leased_event(
                attempt="parity-workspace",
                event_type=EventType.WORKSPACE_PREPARED,
                occurred_at="2026-08-10T12:01:01Z",
                payload=prepared_candidate().to_canonical_dict(),
            ),
            _leased_event(
                attempt="parity-sealed",
                event_type=EventType.CANDIDATE_SEALED,
                occurred_at="2026-08-10T12:01:02Z",
                payload=candidate.to_canonical_dict(),
            ),
            _state_event(
                attempt="parity-deterministic",
                source=ExperimentState.BUILDING,
                target=ExperimentState.DETERMINISTIC_VALIDATION,
                occurred_at="2026-08-10T12:01:03Z",
            ),
            _state_event(
                attempt="parity-paired",
                source=ExperimentState.DETERMINISTIC_VALIDATION,
                target=ExperimentState.PAIRED_EVALUATION,
                occurred_at="2026-08-10T12:01:04Z",
            ),
            _leased_event(
                attempt="parity-evidence",
                event_type=EventType.PAIRED_EVIDENCE_RECORDED,
                occurred_at="2026-08-10T12:01:05Z",
                payload=evidence.to_canonical_dict(),
            ),
            ExperimentEvent.create(
                experiment_id=manifest.experiment_id,
                stage_attempt_id="parity-publication",
                event_type=EventType.EXPERIMENTAL_PUBLISHED,
                occurred_at="2026-08-10T12:01:06Z",
                payload={
                    "branch": f"experimental/{manifest.experiment_id}",
                    "candidate_packet_digest": candidate.digest,
                    "commit": candidate.candidate_commit,
                    "tree": "b" * 40,
                },
            ),
            ExperimentEvent.create(
                experiment_id=manifest.experiment_id,
                stage_attempt_id="parity-protected",
                event_type=EventType.PROTECTED_VALIDATION_RECORDED,
                occurred_at="2026-08-10T12:01:07Z",
                payload={
                    "candidate_commit": candidate.candidate_commit,
                    "candidate_tree": "b" * 40,
                    "receipt_digest": "c" * 64,
                },
            ),
        )
    )
    for index, role in enumerate(roles, start=8):
        events.append(
            _leased_event(
                attempt=f"parity-packet-{role}",
                event_type=EventType.REVIEW_PACKET_RECORDED,
                occurred_at=f"2026-08-10T12:01:{index:02d}Z",
                payload=packets[role].to_canonical_dict(),
            )
        )
    for index, role in enumerate(roles, start=12):
        events.append(
            _leased_event(
                attempt=f"parity-attestation-{role}",
                event_type=EventType.REVIEW_ATTESTED,
                occurred_at=f"2026-08-10T12:01:{index:02d}Z",
                payload=attestations[role].to_canonical_dict(),
            )
        )
    events.extend(
        (
            _leased_event(
                attempt="parity-draft-request",
                event_type=EventType.DRAFT_PR_REQUESTED,
                occurred_at="2026-08-10T12:01:16Z",
                payload={
                    "base_branch": "main",
                    "candidate_commit": candidate.candidate_commit,
                    "expected_remote_url": "https://github.com/StephenBickel/carl-agent.git",
                    "head_branch": candidate.branch,
                    "repository": "StephenBickel/carl-agent",
                },
            ),
            _leased_event(
                attempt="parity-draft-recorded",
                event_type=EventType.DRAFT_PR_RECORDED,
                occurred_at="2026-08-10T12:01:17Z",
                payload=draft.to_canonical_dict(),
            ),
            _leased_event(
                attempt="parity-workspace-disposed",
                event_type=EventType.WORKSPACE_DISPOSED,
                occurred_at="2026-08-10T12:01:18Z",
                payload={
                    "branch": candidate.branch,
                    "candidate_commit": candidate.candidate_commit,
                },
            ),
            _state_event(
                attempt="parity-holdout",
                source=ExperimentState.PAIRED_EVALUATION,
                target=ExperimentState.HOLDOUT_VALIDATION,
                occurred_at="2026-08-10T12:01:19Z",
            ),
        )
    )
    for index, (role, marker) in enumerate(zip(roles, "bcde", strict=True), start=20):
        events.append(
            _leased_event(
                attempt=f"parity-role-{role}",
                event_type=EventType.ROLE_RECORDED,
                occurred_at=f"2026-08-10T12:01:{index:02d}Z",
                payload={
                    "artifact_digest": marker * 64,
                    "role": role,
                    "verdict": "approve" if index < 23 else "reject",
                },
            )
        )
    events.extend(
        (
            _state_event(
                attempt="parity-review-complete",
                source=ExperimentState.HOLDOUT_VALIDATION,
                target=ExperimentState.REVIEW_COMPLETE,
                occurred_at="2026-08-10T12:01:24Z",
            ),
            _state_event(
                attempt="parity-pr-open",
                source=ExperimentState.REVIEW_COMPLETE,
                target=ExperimentState.PR_OPEN,
                occurred_at="2026-08-10T12:01:25Z",
            ),
            _state_event(
                attempt="parity-merged",
                source=ExperimentState.PR_OPEN,
                target=ExperimentState.MERGED,
                occurred_at="2026-08-10T12:01:26Z",
            ),
            _state_event(
                attempt="parity-soaking",
                source=ExperimentState.MERGED,
                target=ExperimentState.SOAKING,
                occurred_at="2026-08-10T12:01:27Z",
            ),
            ExperimentEvent.create(
                experiment_id=manifest.experiment_id,
                stage_attempt_id="parity-promotion",
                event_type=EventType.PROMOTION_RECORDED,
                occurred_at="2026-08-10T12:01:28Z",
                payload={"merge_commit": "d" * 40, "merge_tree": "e" * 40},
            ),
            ExperimentEvent.create(
                experiment_id=manifest.experiment_id,
                stage_attempt_id="parity-lease-reconciled",
                event_type=EventType.LEASE_RECONCILED,
                occurred_at="2026-08-11T11:59:00Z",
                payload={"lease_stage_attempt_id": "lease-phase3", "worker_not_live": True},
            ),
            ExperimentEvent.create(
                experiment_id=manifest.experiment_id,
                stage_attempt_id="parity-soak-lease",
                event_type=EventType.LEASE_ACQUIRED,
                occurred_at="2026-08-11T12:00:00Z",
                payload={"expires_at": "2026-08-11T18:00:00Z", "owner_id": "soak-worker"},
            ),
            ExperimentEvent.create(
                experiment_id=manifest.experiment_id,
                stage_attempt_id="parity-soak-healthy",
                event_type=EventType.SOAK_OBSERVED,
                occurred_at="2026-08-11T12:02:00Z",
                payload={
                    "evidence_digest": "4" * 64,
                    "healthy": True,
                    "merge_commit": "d" * 40,
                    "observed_at": "2026-08-11T12:02:00Z",
                },
            ),
            _state_event(
                attempt="parity-accepted",
                source=ExperimentState.SOAKING,
                target=ExperimentState.ACCEPTED,
                occurred_at="2026-08-11T12:03:00Z",
                lease_attempt="parity-soak-lease",
                lease_owner="soak-worker",
            ),
            ExperimentEvent.create(
                experiment_id=manifest.experiment_id,
                stage_attempt_id="parity-soak-failed",
                event_type=EventType.SOAK_OBSERVED,
                occurred_at="2026-08-11T12:04:00Z",
                payload={
                    "evidence_digest": "f" * 64,
                    "healthy": False,
                    "merge_commit": "d" * 40,
                    "observed_at": "2026-08-11T12:04:00Z",
                },
            ),
            ExperimentEvent.create(
                experiment_id=manifest.experiment_id,
                stage_attempt_id="parity-revert",
                event_type=EventType.REVERT_RECORDED,
                occurred_at="2026-08-11T12:04:30Z",
                payload={
                    "hard_failure_digest": "f" * 64,
                    "merge_commit": "d" * 40,
                    "restored_tree": "1" * 40,
                    "revert_candidate_commit": "2" * 40,
                    "revert_merge_commit": "3" * 40,
                    "revert_pull_request_number": 18,
                },
            ),
            ExperimentEvent.create(
                experiment_id=manifest.experiment_id,
                stage_attempt_id="parity-lease-release",
                event_type=EventType.LEASE_RELEASED,
                occurred_at="2026-08-11T12:05:00Z",
                payload={"lease_stage_attempt_id": "parity-soak-lease"},
            ),
        )
    )
    return tuple(events)


def _event_authority(event: ExperimentEvent) -> str:
    return PostgresStateBackend._event_authority(event)


def _backend(postgres: object) -> PostgresStateBackend:
    from psycopg import sql
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None

    def connect(dsn: str):
        connection = postgres.connect(  # type: ignore[attr-defined]
            dsn, autocommit=True, row_factory=dict_row
        )
        connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier("carl_state_backend")))
        return connection

    return PostgresStateBackend.from_config(
        PostgresStateConfig(
            dsn=POSTGRES_DSN,
            database_role="carl_state_backend",
            authority_key=AUTHORITY_KEY,
            dead_holder_key=LIVENESS_KEY,
            clock=lambda: datetime(2026, 8, 11, 12, 4, tzinfo=UTC),
            connect=connect,
        )
    )


def test_builder_publication_uses_postgres_authority_and_one_real_socket_effect(
    postgres: object, tmp_path: Path
) -> None:
    from test_product_builder_effects import _prepared
    from test_product_builder_runtime import _request

    from carl_bench.cloud_coordinator import CoordinatorNode
    from carl_bench.github_cloud import (
        GitReferenceSnapshot,
        experimental_branch_binding,
    )
    from carl_bench.github_effect_client import GitHubEffectSocketClient
    from carl_bench.product_builder_effects import (
        ProtectedBuilderEffectExecutor,
        ProtectedCoordinatorCommandAuthority,
        PurposeBoundEffectRequest,
    )

    store, terminal = _prepared(tmp_path)
    manifest = _request().manifest
    with _as_role(postgres, "carl_builder") as builder:
        assert _register_manifest(builder, manifest) is True

    def graph_node(kind: str, status: str, marker: str) -> CoordinatorNode:
        bindings = {
            "publish_experimental": ("builder", "publish_experimental"),
            "dispatch_validation": ("coordinator", "dispatch"),
            "observe_validation": ("observer", "observe"),
        }
        authority, operation = bindings[kind]
        return CoordinatorNode(
            node_id=f"{terminal.experiment_id}:{kind}",
            kind=kind,
            status=status,
            authority=authority,
            operation=operation,
            command_key=f"{terminal.experiment_id}:{kind}:attempt:1",
            request_digest=marker * 64,
            occurred_at=terminal.requested_at,
            attempt=1,
            max_attempts=3,
        )

    snapshot = CoordinatorSnapshot(
        schema_version=1,
        experiment_id=terminal.experiment_id,
        revision=terminal.expected_revision,
        observed_at=terminal.requested_at,
        coordinator_id="carl-cloud-coordinator-v1",
        nodes=(
            graph_node("publish_experimental", "ready", "6"),
            graph_node("dispatch_validation", "waiting", "7"),
            graph_node("observe_validation", "waiting", "8"),
        ),
        lease=None,
        command=None,
        effect=None,
        failure=None,
        production_authorization=None,
        immutable_inputs=(),
        dead_holder_observation_digest=None,
    )
    snapshot_json = _canonical(snapshot.to_canonical_dict())
    assert POSTGRES_DSN is not None
    with postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    ) as admin:
        admin.execute(
            "INSERT INTO carl_autonomy.coordinator_runtime("
            "experiment_id, command_name, snapshot_json, snapshot_digest, status, revision, "
            "updated_at) VALUES (%s, 'coordinate', %s, %s, 'ready', %s, %s)",
            (
                terminal.experiment_id,
                snapshot_json,
                hashlib.sha256(snapshot_json.encode()).hexdigest(),
                terminal.expected_revision,
                terminal.requested_at,
            ),
        )

    backend = _backend(postgres)
    authority = ProtectedCoordinatorCommandAuthority(backend)
    publication = PurposeBoundEffectRequest.for_publication(terminal)
    store.begin_effect(publication)
    authority.register_and_claim(publication, terminal)
    github_request = publication.github_request(terminal)
    service_clock = datetime.now(UTC)

    class OneEffectGateway:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def create_or_reconcile_experimental_branch(
            self, command_key: str, request: object
        ) -> GitReferenceSnapshot:
            self.calls.append(command_key)
            binding = experimental_branch_binding("StephenBickel/carl-agent", request)
            return GitReferenceSnapshot(
                status="created",
                repository="StephenBickel/carl-agent",
                ref=f"refs/heads/{request.branch}",
                commit_sha=request.candidate_commit,
                request_key=binding.request_key,
                effect_key=publication.effect_key,
                command_occurred_at=github_request.occurred_at,
                observed_at=service_clock.isoformat().replace("+00:00", "Z"),
            )

    gateway = OneEffectGateway()
    socket_root = Path("/private/tmp") if Path("/tmp").is_symlink() else Path("/tmp")
    socket_directory = Path(tempfile.mkdtemp(prefix="carl-postgres-builder-", dir=socket_root))
    socket_path = socket_directory / "github-effect.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(os.fspath(socket_path))
    os.chmod(socket_path, 0o600)
    listener.listen(1)

    def serve() -> None:
        from carl_bench.github_effect_service import _serve_connection

        connection, _ = listener.accept()
        with connection:
            _serve_connection(
                connection,
                gateway=gateway,
                policy=type(
                    "Policy",
                    (),
                    {
                        "repository": "StephenBickel/carl-agent",
                        "workflow_ref": "main",
                        "dispatch_actor_login": "carl-autonomy[bot]",
                    },
                )(),
                state_controller=backend,
                clock=lambda: service_clock,
            )
        listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = GitHubEffectSocketClient._for_testing(
        socket_path=socket_path,
        expected_peer_uid=os.getuid(),
        timeout_seconds=2.0,
    )
    github_response = client.execute(github_request)
    thread.join(2)
    assert not thread.is_alive()
    result_digest = hashlib.sha256(canonical_json_bytes(github_response.result)).hexdigest()
    receipt = authority.complete_effect(
        publication,
        terminal,
        github_response=github_response,
        result_digest=result_digest,
        observed_at=github_response.observed_at,
    )

    class GitHubMustNotReplay:
        @staticmethod
        def execute(request: object) -> object:  # pragma: no cover - exploit assertion
            del request
            raise AssertionError("authoritative publication must not replay")

    replayed = ProtectedBuilderEffectExecutor._for_testing(
        store=store,
        authority=authority,
        github=GitHubMustNotReplay(),
    ).execute(publication)
    backend.load_projection(terminal.experiment_id)
    downstream = PurposeBoundEffectRequest.for_validation(
        terminal, expected_revision=receipt.authoritative_revision
    )
    downstream_state = authority.register_and_claim(downstream, terminal)

    with postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    ) as admin:
        runtime = admin.execute(
            "SELECT revision, snapshot_json FROM carl_autonomy.coordinator_runtime "
            "WHERE experiment_id = %s",
            (terminal.experiment_id,),
        ).fetchone()
        durable_receipt = admin.execute(
            "SELECT idempotency_key, request_digest, publication_request_digest, "
            "candidate_packet_digest, command_key, effect_key, "
            "github_binding_request_digest, github_request_digest, result_digest, "
            "expected_revision, authoritative_revision "
            "FROM carl_autonomy.builder_effect_completion_receipts "
            "WHERE idempotency_key = %s",
            (publication.idempotency_key,),
        ).fetchone()
        completion_events = admin.execute(
            "SELECT authority, event_digest, event_json "
            "FROM carl_autonomy.experiment_events "
            "WHERE experiment_id = %s "
            "AND (event_json::jsonb)->>'event_type' = 'coordinator_node_completed'",
            (terminal.experiment_id,),
        ).fetchall()
    nodes = {
        node["kind"]: node["status"] for node in json.loads(runtime["snapshot_json"])["nodes"]
    }
    assert replayed.result_digest == result_digest
    assert replayed.authoritative_revision == terminal.expected_revision + 1
    assert runtime["revision"] == terminal.expected_revision + 1
    assert nodes == {
        "publish_experimental": "complete",
        "dispatch_validation": "ready",
        "observe_validation": "waiting",
    }
    assert [kind for kind, status in nodes.items() if status == "ready"] == [
        "dispatch_validation"
    ]
    assert durable_receipt == {
        "idempotency_key": publication.idempotency_key,
        "request_digest": publication.request_digest,
        "publication_request_digest": publication.publication_request_digest,
        "candidate_packet_digest": publication.candidate_packet_digest,
        "command_key": publication.command_key,
        "effect_key": publication.effect_key,
        "github_binding_request_digest": publication.github_binding_request_digest,
        "github_request_digest": publication.github_request_digest,
        "result_digest": result_digest,
        "expected_revision": terminal.expected_revision,
        "authoritative_revision": terminal.expected_revision + 1,
    }
    assert len(completion_events) == 1
    completion_event = json.loads(completion_events[0]["event_json"])
    assert completion_events[0]["authority"] == "builder"
    assert completion_events[0]["event_digest"] == hashlib.sha256(
        completion_events[0]["event_json"].encode()
    ).hexdigest()
    assert completion_event["event_type"] == "coordinator_node_completed"
    assert completion_event["experiment_id"] == terminal.experiment_id
    assert completion_event["payload"] == {
        "command_key": publication.command_key,
        "effect_key": publication.effect_key,
        "node_kind": "publish_experimental",
        "request_digest": publication.github_binding_request_digest,
        "result_digest": result_digest,
    }
    assert downstream_state.status == "claimed"
    assert downstream_state.command.expected_revision == terminal.expected_revision + 1
    assert gateway.calls == [publication.command_key]
    socket_path.unlink(missing_ok=True)
    socket_directory.rmdir()


def _archive_registrar(postgres: object) -> PostgresCoordinatorRecoveryReceiptRegistrar:
    from psycopg import sql
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None

    def connect(dsn: str):
        connection = postgres.connect(  # type: ignore[attr-defined]
            dsn, autocommit=True, row_factory=dict_row
        )
        connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier("carl_archive_backend")))
        return connection

    return PostgresCoordinatorRecoveryReceiptRegistrar._for_testing(
        dsn=POSTGRES_DSN, connect=connect
    )


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


def test_additive_effect_fence_migration_upgrades_a_populated_001_002_schema(
    postgres: object,
) -> None:
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None
    assert GITHUB_EFFECT_FENCES_MIGRATION.is_file()
    with postgres.connect(POSTGRES_DSN, autocommit=True, row_factory=dict_row) as admin:  # type: ignore[attr-defined]
        admin.execute("DROP SCHEMA IF EXISTS carl_autonomy CASCADE")
        for migration in BASE_MIGRATIONS:
            admin.execute(migration.read_text(encoding="utf-8"), prepare=False)
    try:
        manifest = sample_manifest()
        event = _full_event_history()[0]
        command = _command()
        lease = CloudLease(
            lease_key="upgrade-coordinator",
            holder_id="upgrade-worker-001",
            authority="coordinator",
            revision=0,
            acquired_at=NOW,
            expires_at="2026-08-20T12:10:00Z",
        )
        evidence = EvidenceObject(
            digest=DIGEST_A,
            object_key=f"evidence/{DIGEST_A}",
            object_version="upgrade-version-001",
            producer="observer",
            request_digest=DIGEST_B,
            media_type="application/json",
            retained_until="2027-08-20T12:00:00Z",
        )
        with _as_role(postgres, "carl_builder") as builder:
            assert _register_manifest(builder, manifest) is True
        with _as_role(postgres, "carl_coordinator") as coordinator:
            assert _append_event(coordinator, event)["appended"] is True
            assert (
                coordinator.execute(
                    "SELECT * FROM carl_autonomy.create_command(%s, %s)",
                    (_canonical(command.to_canonical_dict()), NOW),
                ).fetchone()["applied"]
                is True
            )
            assert (
                coordinator.execute(
                    "SELECT * FROM carl_autonomy.acquire_lease(%s, %s)",
                    (_canonical(lease.to_canonical_dict()), NOW),
                ).fetchone()["applied"]
                is True
            )
        with _as_role(postgres, "carl_observer") as observer:
            assert (
                observer.execute(
                    "SELECT * FROM carl_autonomy.register_evidence(%s, %s)",
                    (_canonical(evidence.to_canonical_dict()), NOW),
                ).fetchone()["applied"]
                is True
            )

        with postgres.connect(POSTGRES_DSN, autocommit=True, row_factory=dict_row) as admin:  # type: ignore[attr-defined]
            before = admin.execute(
                "SELECT "
                "(SELECT count(*) FROM carl_autonomy.experiment_manifests) AS manifests, "
                "(SELECT count(*) FROM carl_autonomy.experiment_events) AS events, "
                "(SELECT count(*) FROM carl_autonomy.commands) AS commands, "
                "(SELECT count(*) FROM carl_autonomy.leases) AS leases, "
                "(SELECT count(*) FROM carl_autonomy.evidence_objects) AS evidence"
            ).fetchone()
            admin.execute(
                GITHUB_EFFECT_FENCES_MIGRATION.read_text(encoding="utf-8"),
                prepare=False,
            )
            after = admin.execute(
                "SELECT "
                "(SELECT count(*) FROM carl_autonomy.experiment_manifests) AS manifests, "
                "(SELECT count(*) FROM carl_autonomy.experiment_events) AS events, "
                "(SELECT count(*) FROM carl_autonomy.commands) AS commands, "
                "(SELECT count(*) FROM carl_autonomy.leases) AS leases, "
                "(SELECT count(*) FROM carl_autonomy.evidence_objects) AS evidence"
            ).fetchone()
            privileges = admin.execute(
                "SELECT "
                "has_table_privilege('carl_state_backend', "
                "'carl_autonomy.effect_attempts', 'INSERT') AS direct_insert, "
                "has_function_privilege('carl_state_backend', "
                "'carl_autonomy.prepare_effect_attempt(text,timestamptz)', "
                "'EXECUTE') AS execute_prepare"
            ).fetchone()
        assert (
            before
            == after
            == {
                "commands": 1,
                "events": 1,
                "evidence": 1,
                "leases": 1,
                "manifests": 1,
            }
        )
        assert privileges == {"direct_insert": False, "execute_prepare": True}

        claim = _claim()
        attempt = GitHubEffectAttempt(
            schema_version=1,
            effect_key=command.effect_key,
            command_key=command.command_key,
            claim_id=claim.claim_id,
            command_revision=8,
            claim_expected_revision=claim.expected_revision,
            action="dispatch_workflow",
            endpoint_id="workflow_dispatch",
            method="POST",
            payload_digest="c" * 64,
            command_request_digest=command.request_digest,
            repository="StephenBickel/carl-agent",
            target_identity="autonomous-improvement.yml@" + "1" * 40,
            request_key="cloud-run-request-upgrade-001",
            attempt_key="cloud-run-request-upgrade-001-attempt-1",
            authority=command.authority,
            operation=command.operation,
            command_occurred_at=command.occurred_at,
            claim_expires_at=claim.expires_at,
            attempt_state="prepared",
            not_before="2026-08-20T12:00:30Z",
            observed_at=NOW,
        )
        with _as_role(postgres, "carl_coordinator") as coordinator:
            coordinator.execute(
                "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
                (_canonical(claim.to_canonical_dict()), NOW),
            ).fetchone()
            prepared = coordinator.execute(
                "SELECT * FROM carl_autonomy.prepare_effect_attempt(%s, %s)",
                (_canonical(attempt.to_canonical_dict()), NOW),
            ).fetchone()
            uncertain = coordinator.execute(
                "SELECT * FROM carl_autonomy.mark_effect_uncertain(%s, %s, %s, %s)",
                (
                    attempt.effect_key,
                    attempt.not_before,
                    "2026-08-20T12:00:01Z",
                    "2026-08-20T12:00:01Z",
                ),
            ).fetchone()
            completed = coordinator.execute(
                "SELECT * FROM carl_autonomy.mark_effect_completed("
                "%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    attempt.effect_key,
                    attempt.command_key,
                    attempt.claim_id,
                    attempt.command_revision,
                    attempt.claim_expected_revision,
                    attempt.claim_expires_at,
                    DIGEST_B,
                    "2026-08-20T12:00:02Z",
                    "2026-08-20T12:00:02Z",
                ),
            ).fetchone()
        assert (prepared["applied"], uncertain["applied"], completed["applied"]) == (
            True,
            True,
            True,
        )
    finally:
        with postgres.connect(POSTGRES_DSN, autocommit=True) as admin:  # type: ignore[attr-defined]
            admin.execute("DROP SCHEMA IF EXISTS carl_autonomy CASCADE")
            for migration in MIGRATIONS:
                if migration.is_file():
                    admin.execute(migration.read_text(encoding="utf-8"), prepare=False)


def test_effect_fence_migration_upgrades_populated_pinned_4aa2ab5_state(
    postgres: object,
) -> None:
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None
    assert HISTORICAL_EFFECT_FENCE_FIXTURE.is_file()
    with postgres.connect(POSTGRES_DSN, autocommit=True, row_factory=dict_row) as admin:  # type: ignore[attr-defined]
        admin.execute("DROP SCHEMA IF EXISTS carl_autonomy CASCADE")
        for migration in BASE_MIGRATIONS:
            admin.execute(migration.read_text(encoding="utf-8"), prepare=False)
        admin.execute(
            HISTORICAL_EFFECT_FENCE_FIXTURE.read_text(encoding="utf-8"),
            prepare=False,
        )
    try:
        command = _command()
        claim = _claim()
        attempt = GitHubEffectAttempt(
            schema_version=1,
            effect_key=command.effect_key,
            command_key=command.command_key,
            claim_id=claim.claim_id,
            command_revision=8,
            claim_expected_revision=claim.expected_revision,
            action="dispatch_workflow",
            endpoint_id="workflow_dispatch",
            method="POST",
            payload_digest="c" * 64,
            command_request_digest=command.request_digest,
            repository="StephenBickel/carl-agent",
            target_identity="autonomous-improvement.yml@" + "1" * 40,
            request_key="cloud-run-request-historical-001",
            attempt_key="cloud-run-request-historical-001-attempt-1",
            authority=command.authority,
            operation=command.operation,
            command_occurred_at=command.occurred_at,
            claim_expires_at=claim.expires_at,
            attempt_state="prepared",
            not_before="2026-08-20T12:00:30Z",
            observed_at=NOW,
        )
        with _as_role(postgres, "carl_coordinator") as coordinator:
            coordinator.execute(
                "SELECT * FROM carl_autonomy.create_command(%s, %s)",
                (_canonical(command.to_canonical_dict()), NOW),
            ).fetchone()
            coordinator.execute(
                "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
                (_canonical(claim.to_canonical_dict()), NOW),
            ).fetchone()
        with postgres.connect(POSTGRES_DSN, autocommit=True, row_factory=dict_row) as admin:  # type: ignore[attr-defined]
            admin.execute(
                "INSERT INTO carl_autonomy.effect_attempts("
                "effect_key,command_key,claim_id,command_revision,claim_expected_revision,"
                "authority,operation,action,endpoint_id,method,payload_digest,"
                "command_request_digest,repository,target_identity,request_key,attempt_key,"
                "command_occurred_at,command_occurred_at_text,claim_expires_at,"
                "claim_expires_at_text,attempt_state,not_before,not_before_text,attempt_json,"
                "result_digest,observed_at,observed_at_text,created_at,updated_at) VALUES ("
                "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                "%s,%s,%s,%s,%s,%s,%s)",
                (
                    attempt.effect_key,
                    attempt.command_key,
                    attempt.claim_id,
                    attempt.command_revision,
                    attempt.claim_expected_revision,
                    attempt.authority,
                    attempt.operation,
                    attempt.action,
                    attempt.endpoint_id,
                    attempt.method,
                    attempt.payload_digest,
                    attempt.command_request_digest,
                    attempt.repository,
                    attempt.target_identity,
                    attempt.request_key,
                    attempt.attempt_key,
                    attempt.command_occurred_at,
                    attempt.command_occurred_at,
                    attempt.claim_expires_at,
                    attempt.claim_expires_at,
                    attempt.attempt_state,
                    attempt.not_before,
                    attempt.not_before,
                    _canonical(attempt.to_canonical_dict()),
                    None,
                    attempt.observed_at,
                    attempt.observed_at,
                    attempt.observed_at,
                    attempt.observed_at,
                ),
            )
            admin.execute(
                GITHUB_EFFECT_FENCES_MIGRATION.read_text(encoding="utf-8"),
                prepare=False,
            )
            preserved = admin.execute(
                "SELECT effect_key, command_key, claim_id, attempt_state, attempt_json "
                "FROM carl_autonomy.effect_attempts"
            ).fetchone()
            contracts = admin.execute(
                "SELECT pg_catalog.pg_get_userbyid(c.relowner) = current_user AS owner_ok, "
                "NOT has_table_privilege('carl_state_backend', c.oid, 'SELECT') AS table_denied, "
                "to_regprocedure('carl_autonomy.mark_effect_completed("
                "text,text,text,integer,integer,text,text,text,timestamptz)') "
                "IS NOT NULL AS new_completion, "
                "to_regprocedure('carl_autonomy.mark_effect_completed("
                "text,text,text,timestamptz)') IS NULL AS old_removed, "
                "has_function_privilege('carl_state_backend', "
                "'carl_autonomy.mark_effect_completed("
                "text,text,text,integer,integer,text,text,text,timestamptz)', "
                "'EXECUTE') AS backend_execute "
                "FROM pg_catalog.pg_class AS c JOIN pg_catalog.pg_namespace AS n "
                "ON n.oid = c.relnamespace WHERE n.nspname = 'carl_autonomy' "
                "AND c.relname = 'effect_attempts'"
            ).fetchone()
        assert preserved == {
            "attempt_json": _canonical(attempt.to_canonical_dict()),
            "attempt_state": "prepared",
            "claim_id": claim.claim_id,
            "command_key": command.command_key,
            "effect_key": command.effect_key,
        }
        assert contracts == {
            "backend_execute": True,
            "new_completion": True,
            "old_removed": True,
            "owner_ok": True,
            "table_denied": True,
        }
    finally:
        with postgres.connect(POSTGRES_DSN, autocommit=True) as admin:  # type: ignore[attr-defined]
            admin.execute("DROP SCHEMA IF EXISTS carl_autonomy CASCADE")
            for migration in MIGRATIONS:
                admin.execute(migration.read_text(encoding="utf-8"), prepare=False)


def test_effect_fence_migration_rejects_incompatible_existing_table(postgres: object) -> None:
    assert POSTGRES_DSN is not None
    try:
        with postgres.connect(  # type: ignore[attr-defined]
            POSTGRES_DSN, autocommit=True
        ) as admin:
            admin.execute("DROP SCHEMA IF EXISTS carl_autonomy CASCADE")
            admin.execute("DROP SCHEMA IF EXISTS carl_poison CASCADE")
            for migration in BASE_MIGRATIONS:
                admin.execute(migration.read_text(encoding="utf-8"), prepare=False)
            admin.execute(
                "CREATE TABLE carl_autonomy.effect_attempts(effect_key text PRIMARY KEY)"
            )
            with pytest.raises(Exception, match="effect_fence_schema_invalid"):
                admin.execute(
                    GITHUB_EFFECT_FENCES_MIGRATION.read_text(encoding="utf-8"),
                    prepare=False,
                )
            admin.rollback()
    finally:
        with postgres.connect(  # type: ignore[attr-defined]
            POSTGRES_DSN, autocommit=True
        ) as restore:
            restore.execute("DROP SCHEMA IF EXISTS carl_autonomy CASCADE")
            for migration in MIGRATIONS:
                restore.execute(migration.read_text(encoding="utf-8"), prepare=False)


def test_effect_fence_migration_rejects_scratch_poison_and_drops_its_own_scratch(
    postgres: object,
) -> None:
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None
    scratch = "carl_autonomy._migration_expected_effect_attempts"
    failed_connection = postgres.connect(  # type: ignore[attr-defined]
        POSTGRES_DSN, autocommit=True, row_factory=dict_row
    )
    try:
        failed_connection.execute("DROP SCHEMA IF EXISTS carl_autonomy CASCADE")
        for migration in BASE_MIGRATIONS:
            failed_connection.execute(migration.read_text(encoding="utf-8"), prepare=False)
        failed_connection.execute(f"CREATE TABLE {scratch}(poison integer)")
        with pytest.raises(Exception, match="effect_fence_scratch_exists"):
            failed_connection.execute(
                GITHUB_EFFECT_FENCES_MIGRATION.read_text(encoding="utf-8"),
                prepare=False,
            )
        failed_connection.rollback()
        failed_connection.close()

        with postgres.connect(  # type: ignore[attr-defined]
            POSTGRES_DSN, autocommit=True, row_factory=dict_row
        ) as recovered:
            assert recovered.execute(
                "SELECT to_regclass(%s) IS NOT NULL AS poison_preserved",
                (scratch,),
            ).fetchone() == {"poison_preserved": True}
            recovered.execute(f"DROP TABLE {scratch}")

            recovered.execute(
                GITHUB_EFFECT_FENCES_MIGRATION.read_text(encoding="utf-8"),
                prepare=False,
            )
            assert recovered.execute(
                "SELECT to_regclass(%s) IS NULL AS scratch_dropped",
                (scratch,),
            ).fetchone() == {"scratch_dropped": True}
    finally:
        if not failed_connection.closed:
            failed_connection.rollback()
            failed_connection.close()
        with postgres.connect(  # type: ignore[attr-defined]
            POSTGRES_DSN, autocommit=True
        ) as restore:
            restore.execute("DROP SCHEMA IF EXISTS carl_autonomy CASCADE")
            for migration in MIGRATIONS:
                restore.execute(migration.read_text(encoding="utf-8"), prepare=False)


@pytest.mark.parametrize(
    "poison_sql",
    (
        "ALTER TABLE carl_autonomy.effect_attempts ALTER COLUMN claim_id TYPE varchar(191)",
        "ALTER TABLE carl_autonomy.effect_attempts ALTER COLUMN claim_id SET DEFAULT 'forged'",
        "DO $$ DECLARE n text; BEGIN SELECT conname INTO n FROM pg_constraint "
        "WHERE conrelid='carl_autonomy.effect_attempts'::regclass AND contype='c' "
        "AND pg_get_constraintdef(oid) LIKE '%command_revision%'; "
        "EXECUTE format('ALTER TABLE carl_autonomy.effect_attempts DROP CONSTRAINT %I', n); "
        "ALTER TABLE carl_autonomy.effect_attempts ADD CHECK (command_revision >= 0); END $$",
        "DO $$ DECLARE n text; BEGIN SELECT conname INTO n FROM pg_constraint "
        "WHERE conrelid='carl_autonomy.effect_attempts'::regclass AND contype='f' "
        "AND conkey=ARRAY[1]::smallint[]; "
        "EXECUTE format('ALTER TABLE carl_autonomy.effect_attempts DROP CONSTRAINT %I', n); "
        "ALTER TABLE carl_autonomy.effect_attempts ADD FOREIGN KEY (effect_key) "
        "REFERENCES carl_autonomy.commands(command_key); END $$",
        "DROP INDEX carl_autonomy.effect_attempts_reconciliation; "
        "CREATE INDEX effect_attempts_reconciliation ON carl_autonomy.effect_attempts"
        "(attempt_state,not_before,effect_key) WHERE attempt_state='uncertain'",
        "CREATE SCHEMA carl_poison; "
        "CREATE COLLATION carl_poison.poison (provider = libc, locale = 'C'); "
        "ALTER TABLE carl_autonomy.effect_attempts ALTER COLUMN command_key "
        "TYPE varchar(192) COLLATE carl_poison.poison",
        "ALTER TABLE carl_autonomy.effect_attempts "
        "DROP CONSTRAINT effect_attempts_command_key_key; "
        "CREATE INDEX effect_attempts_command_key_key "
        "ON carl_autonomy.effect_attempts(command_key)",
        "CREATE SCHEMA carl_poison; "
        "CREATE OPERATOR CLASS carl_poison.text_ops FOR TYPE text USING btree AS "
        "OPERATOR 1 < (text,text), OPERATOR 2 <= (text,text), "
        "OPERATOR 3 = (text,text), OPERATOR 4 >= (text,text), "
        "OPERATOR 5 > (text,text), "
        "FUNCTION 1 pg_catalog.bttextcmp(text,text), "
        "FUNCTION 2 pg_catalog.bttextsortsupport(internal), "
        "FUNCTION 4 pg_catalog.btvarstrequalimage(oid); "
        "DROP INDEX carl_autonomy.effect_attempts_reconciliation; "
        "CREATE INDEX effect_attempts_reconciliation ON carl_autonomy.effect_attempts"
        "(attempt_state carl_poison.text_ops,not_before,effect_key) "
        "WHERE attempt_state IN ('retry_scheduled','uncertain')",
        "ALTER TABLE carl_autonomy.effect_attempts "
        "DROP CONSTRAINT effect_attempts_command_key_key; "
        "ALTER TABLE carl_autonomy.effect_attempts "
        "ADD CONSTRAINT effect_attempts_command_key_key UNIQUE (command_key) DEFERRABLE",
        "ALTER TABLE carl_autonomy.effect_attempts "
        "DROP CONSTRAINT effect_attempts_command_key_key; "
        "ALTER TABLE carl_autonomy.effect_attempts "
        "ADD CONSTRAINT effect_attempts_command_key_key "
        "UNIQUE NULLS NOT DISTINCT (command_key)",
        "DROP INDEX carl_autonomy.effect_attempts_reconciliation; "
        "CREATE INDEX effect_attempts_reconciliation ON carl_autonomy.effect_attempts"
        "(attempt_state DESC,not_before,effect_key) INCLUDE (claim_id) "
        "WHERE attempt_state IN ('retry_scheduled','uncertain')",
        "DROP INDEX carl_autonomy.effect_attempts_reconciliation; "
        "CREATE INDEX effect_attempts_reconciliation ON carl_autonomy.effect_attempts"
        "(attempt_state,not_before,lower(effect_key)) "
        "WHERE attempt_state IN ('retry_scheduled','uncertain')",
    ),
)
def test_effect_fence_migration_rejects_exact_catalog_poison(
    postgres: object, poison_sql: str
) -> None:
    assert POSTGRES_DSN is not None
    failed_connection = postgres.connect(POSTGRES_DSN, autocommit=True)  # type: ignore[attr-defined]
    try:
        failed_connection.execute("DROP SCHEMA IF EXISTS carl_autonomy CASCADE")
        failed_connection.execute("DROP SCHEMA IF EXISTS carl_poison CASCADE")
        for migration in BASE_MIGRATIONS:
            failed_connection.execute(migration.read_text(encoding="utf-8"), prepare=False)
        failed_connection.execute(
            HISTORICAL_EFFECT_FENCE_FIXTURE.read_text(encoding="utf-8"), prepare=False
        )
        failed_connection.execute(
            GITHUB_EFFECT_FENCES_MIGRATION.read_text(encoding="utf-8"), prepare=False
        )
        failed_connection.execute(poison_sql, prepare=False)
        with pytest.raises(Exception, match="effect_fence_schema_invalid"):
            failed_connection.execute(
                GITHUB_EFFECT_FENCES_MIGRATION.read_text(encoding="utf-8"), prepare=False
            )
        failed_connection.rollback()
    finally:
        failed_connection.close()
        with postgres.connect(POSTGRES_DSN, autocommit=True) as restore:  # type: ignore[attr-defined]
            restore.execute("DROP SCHEMA IF EXISTS carl_autonomy CASCADE")
            restore.execute("DROP SCHEMA IF EXISTS carl_poison CASCADE")
            for migration in MIGRATIONS:
                restore.execute(migration.read_text(encoding="utf-8"), prepare=False)


def test_effect_fence_migration_revokes_every_arbitrary_catalog_grantee(
    postgres: object,
) -> None:
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None
    with postgres.connect(POSTGRES_DSN, autocommit=True, row_factory=dict_row) as admin:  # type: ignore[attr-defined]
        admin.execute("DROP SCHEMA IF EXISTS carl_autonomy CASCADE")
        admin.execute("DROP ROLE IF EXISTS carl_effect_intruder")
        admin.execute("CREATE ROLE carl_effect_intruder NOLOGIN")
        for migration in BASE_MIGRATIONS:
            admin.execute(migration.read_text(encoding="utf-8"), prepare=False)
        admin.execute(HISTORICAL_EFFECT_FENCE_FIXTURE.read_text(encoding="utf-8"), prepare=False)
        admin.execute("CREATE SEQUENCE carl_autonomy.effect_poison_sequence")
        admin.execute(
            "GRANT SELECT, INSERT ON carl_autonomy.effect_attempts TO carl_effect_intruder"
        )
        admin.execute(
            "GRANT SELECT(effect_key), UPDATE(claim_id), INSERT(operation), "
            "REFERENCES(command_key) ON carl_autonomy.effect_attempts TO carl_effect_intruder"
        )
        admin.execute(
            "GRANT SELECT(effect_key), UPDATE(claim_id) ON carl_autonomy.effect_attempts TO PUBLIC"
        )
        admin.execute(
            "GRANT EXECUTE ON FUNCTION "
            "carl_autonomy.prepare_effect_attempt(text,timestamptz) TO carl_effect_intruder"
        )
        admin.execute(
            "GRANT USAGE, SELECT ON SEQUENCE carl_autonomy.effect_poison_sequence "
            "TO carl_effect_intruder"
        )

        admin.execute(GITHUB_EFFECT_FENCES_MIGRATION.read_text(encoding="utf-8"), prepare=False)

        table_acl = admin.execute(
            "SELECT count(*) AS total, count(*) FILTER (WHERE acl.grantee=c.relowner) AS owner "
            "FROM pg_class c CROSS JOIN LATERAL aclexplode("
            "coalesce(c.relacl,acldefault('r',c.relowner))) acl "
            "WHERE c.oid='carl_autonomy.effect_attempts'::regclass"
        ).fetchone()
        function_acl = admin.execute(
            "SELECT count(*) AS total, "
            "count(*) FILTER (WHERE acl.grantee=p.proowner) AS owner, "
            "count(*) FILTER (WHERE acl.grantee='carl_state_backend'::regrole) AS backend "
            "FROM pg_proc p CROSS JOIN LATERAL aclexplode("
            "coalesce(p.proacl,acldefault('f',p.proowner))) acl "
            "WHERE p.oid = ANY(ARRAY["
            "'carl_autonomy.resolve_claimed_command(text,timestamptz)'::regprocedure::oid,"
            "'carl_autonomy.prepare_effect_attempt(text,timestamptz)'::regprocedure::oid,"
            "'carl_autonomy.mark_effect_retry_scheduled(text,text,text,timestamptz)'::regprocedure::oid,"
            "'carl_autonomy.mark_effect_uncertain(text,text,text,timestamptz)'::regprocedure::oid,"
            "'carl_autonomy.mark_effect_completed(text,text,text,integer,integer,text,text,text,timestamptz)'::regprocedure::oid])"
        ).fetchone()
        leaked = admin.execute(
            "SELECT (has_table_privilege('carl_effect_intruder',"
            "'carl_autonomy.effect_attempts','SELECT') OR "
            "has_function_privilege('carl_effect_intruder',"
            "'carl_autonomy.prepare_effect_attempt(text,timestamptz)','EXECUTE') OR "
            "has_sequence_privilege('carl_effect_intruder',"
            "'carl_autonomy.effect_poison_sequence','USAGE')) AS leaked"
        ).fetchone()
        sequence_acl = admin.execute(
            "SELECT count(*) AS total, count(*) FILTER (WHERE acl.grantee=c.relowner) AS owner "
            "FROM pg_class c CROSS JOIN LATERAL aclexplode("
            "coalesce(c.relacl,acldefault('s',c.relowner))) acl "
            "WHERE c.oid='carl_autonomy.effect_poison_sequence'::regclass"
        ).fetchone()
        column_acl = admin.execute(
            "SELECT count(*) AS total FROM pg_attribute "
            "WHERE attrelid='carl_autonomy.effect_attempts'::regclass "
            "AND attnum > 0 AND NOT attisdropped AND attacl IS NOT NULL"
        ).fetchone()
        assert table_acl == {"owner": 7, "total": 7}
        assert function_acl == {"backend": 5, "owner": 5, "total": 10}
        assert sequence_acl == {"owner": 3, "total": 3}
        assert column_acl == {"total": 0}
        assert leaked == {"leaked": False}

        admin.execute("DROP SCHEMA IF EXISTS carl_autonomy CASCADE")
        admin.execute("DROP ROLE carl_effect_intruder")
        for migration in MIGRATIONS:
            admin.execute(migration.read_text(encoding="utf-8"), prepare=False)


def test_schema_has_all_strict_transactional_state_tables(postgres: object) -> None:
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None
    with postgres.connect(POSTGRES_DSN, row_factory=dict_row) as connection:  # type: ignore[attr-defined]
        assert _required_tables(connection) == {
            "commands",
            "dead_holder_observations",
            "effect_attempts",
            "evidence_objects",
            "experiment_events",
            "experiment_manifests",
            "experiment_projection_guards",
            "leases",
            "monitor_snapshots",
            "supervisor_triggers",
        }


def test_every_authorized_event_appends_through_real_history_and_replays(
    postgres: object,
) -> None:
    manifest = sample_manifest()
    with _as_role(postgres, "carl_builder") as builder:
        assert _register_manifest(builder, manifest) is True

    backend = _backend(postgres)
    observed_types: set[EventType] = set()
    for event in _full_event_history():
        with _as_role(postgres, f"carl_{_event_authority(event)}") as connection:
            assert _append_event(connection, event)["appended"] is True
        backend.load_projection(manifest.experiment_id)
        observed_types.add(event.event_type)

    assert observed_types == set(EventType)


@pytest.mark.parametrize("mutation", ("extra", "missing_payload"))
def test_noncanonical_event_envelope_does_not_mutate_chain(postgres: object, mutation: str) -> None:
    manifest = sample_manifest()
    event = ExperimentEvent.create(
        experiment_id=manifest.experiment_id,
        stage_attempt_id=f"invalid-envelope-{mutation}",
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at=NOW,
        payload=_retry_payload(attempt=1, scheduled_at=NOW, changed_action="canonical envelope"),
    )
    envelope = event.to_canonical_dict()
    if mutation == "extra":
        envelope["unexpected"] = True
    else:
        envelope.pop("payload")
    event_json = _canonical(envelope)
    event_digest = hashlib.sha256(event_json.encode("utf-8")).hexdigest()

    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    with _as_role(postgres, "carl_coordinator") as coordinator:
        before = coordinator.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()
        with pytest.raises(psycopg.Error):
            coordinator.execute(
                "SELECT * FROM carl_autonomy.append_event(%s, %s, %s, %s)",
                (event_json, event_digest, event.payload_json, NOW),
            ).fetchone()
        after = coordinator.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()

    assert after == before == []


def test_equivalent_but_nonidentical_soak_timestamp_text_does_not_mutate_chain(
    postgres: object,
) -> None:
    manifest = sample_manifest()
    history = _full_event_history()
    target_index = next(
        index
        for index, event in enumerate(history)
        if event.stage_attempt_id == "parity-soak-failed"
    )
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    for event in history[:target_index]:
        with _as_role(postgres, f"carl_{_event_authority(event)}") as connection:
            _append_event(connection, event)

    target = history[target_index]
    mismatch = ExperimentEvent.create(
        experiment_id=target.experiment_id,
        stage_attempt_id="invalid-soak-timestamp-text",
        event_type=target.event_type,
        occurred_at="2026-08-11T12:01:00.1Z",
        payload={**target.payload, "observed_at": "2026-08-11T12:01:00.10Z"},
    )
    with _as_role(postgres, "carl_coordinator") as reader:
        before = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()
    with _as_role(postgres, "carl_soak") as soak, pytest.raises(psycopg.Error):
        _append_event(soak, mismatch)
    with _as_role(postgres, "carl_coordinator") as reader:
        after = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()

    assert after == before
    _backend(postgres).load_projection(manifest.experiment_id)


@pytest.mark.parametrize("event_type", tuple(EventType))
def test_invalid_payload_for_each_authorized_event_does_not_mutate_chain(
    postgres: object, event_type: EventType
) -> None:
    manifest = sample_manifest()
    history = _full_event_history()
    target_index = next(
        index for index, event in enumerate(history) if event.event_type is event_type
    )
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    for event in history[:target_index]:
        with _as_role(postgres, f"carl_{_event_authority(event)}") as connection:
            _append_event(connection, event)

    target = history[target_index]
    assert frozenset(target.payload) in EVENT_PAYLOAD_KEY_SETS[event_type]
    invalid = ExperimentEvent.create(
        experiment_id=target.experiment_id,
        stage_attempt_id=f"invalid-{event_type.value}",
        event_type=event_type,
        occurred_at=target.occurred_at,
        payload={**target.payload, "unexpected": True},
    )
    with _as_role(postgres, "carl_coordinator") as reader:
        before = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()
    with (
        _as_role(postgres, f"carl_{_event_authority(target)}") as connection,
        pytest.raises(psycopg.Error),
    ):
        _append_event(connection, invalid)
    with _as_role(postgres, "carl_coordinator") as reader:
        after = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()

    assert after == before
    _backend(postgres).load_projection(manifest.experiment_id)


@pytest.mark.parametrize(("event_type", "path", "invalid_value"), INVALID_EVENT_PAYLOAD_TYPES)
def test_reducer_invalid_payload_types_do_not_mutate_live_chain(
    postgres: object,
    event_type: EventType,
    path: tuple[str | int, ...],
    invalid_value: Any,
) -> None:
    manifest = sample_manifest()
    history = _full_event_history()
    target_index = next(
        index for index, event in enumerate(history) if event.event_type is event_type
    )
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    for event in history[:target_index]:
        with _as_role(postgres, f"carl_{_event_authority(event)}") as connection:
            _append_event(connection, event)

    target = history[target_index]
    invalid_payload = deepcopy(target.payload)
    destination: Any = invalid_payload
    for key in path[:-1]:
        destination = destination[key]
        assert isinstance(destination, dict | list)
    destination[path[-1]] = invalid_value
    invalid = ExperimentEvent.create(
        experiment_id=target.experiment_id,
        stage_attempt_id=f"invalid-type-{event_type.value}",
        event_type=event_type,
        occurred_at=target.occurred_at,
        payload=invalid_payload,
    )
    with _as_role(postgres, "carl_coordinator") as reader:
        before = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()
    with (
        _as_role(postgres, f"carl_{_event_authority(target)}") as connection,
        pytest.raises(psycopg.Error),
    ):
        _append_event(connection, invalid)
    with _as_role(postgres, "carl_coordinator") as reader:
        after = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()

    assert after == before
    _backend(postgres).load_projection(manifest.experiment_id)


@pytest.mark.parametrize(
    ("event_type", "field", "invalid_value"),
    (
        (EventType.WORKSPACE_PREPARED, "manifest_digest", "0" * 64),
        (EventType.LEASE_ACQUIRED, "expires_at", "2026-08-10 18:00:00+00"),
        (EventType.DRAFT_PR_REQUESTED, "base_branch", "a" * 129),
    ),
)
def test_reducer_identity_and_text_contract_mismatch_does_not_mutate_chain(
    postgres: object,
    event_type: EventType,
    field: str,
    invalid_value: str,
) -> None:
    manifest = sample_manifest()
    history = _full_event_history()
    target_index = next(
        index for index, event in enumerate(history) if event.event_type is event_type
    )
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    for event in history[:target_index]:
        with _as_role(postgres, f"carl_{_event_authority(event)}") as connection:
            _append_event(connection, event)

    target = history[target_index]
    invalid = ExperimentEvent.create(
        experiment_id=target.experiment_id,
        stage_attempt_id=f"invalid-contract-{event_type.value}-{field}",
        event_type=event_type,
        occurred_at=target.occurred_at,
        payload={**target.payload, field: invalid_value},
    )
    with _as_role(postgres, "carl_coordinator") as reader:
        before = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()
    with (
        _as_role(postgres, f"carl_{_event_authority(target)}") as connection,
        pytest.raises(psycopg.Error),
    ):
        _append_event(connection, invalid)
    with _as_role(postgres, "carl_coordinator") as reader:
        after = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()

    assert after == before
    _backend(postgres).load_projection(manifest.experiment_id)


def test_all_hard_finding_attestations_cannot_authorize_draft_pr(postgres: object) -> None:
    manifest = sample_manifest()
    history = _full_event_history()
    draft_index = next(
        index
        for index, event in enumerate(history)
        if event.event_type is EventType.DRAFT_PR_REQUESTED
    )
    hard_history = tuple(
        ExperimentEvent.create(
            experiment_id=event.experiment_id,
            stage_attempt_id=event.stage_attempt_id,
            event_type=event.event_type,
            occurred_at=event.occurred_at,
            payload={**event.payload, "verdict": "hard_finding"},
        )
        if event.event_type is EventType.REVIEW_ATTESTED
        else event
        for event in history[:draft_index]
    )
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    for event in hard_history:
        with _as_role(postgres, f"carl_{_event_authority(event)}") as connection:
            _append_event(connection, event)

    draft = history[draft_index]
    with _as_role(postgres, "carl_coordinator") as reader:
        before = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()
    with _as_role(postgres, "carl_promoter") as promoter, pytest.raises(psycopg.Error):
        _append_event(promoter, draft)
    with _as_role(postgres, "carl_coordinator") as reader:
        after = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()

    assert after == before
    _backend(postgres).load_projection(manifest.experiment_id)


@pytest.mark.parametrize(
    ("event_type", "field", "value"),
    (
        (EventType.EXPERIMENTAL_PUBLISHED, "branch", "experimental/wrong-experiment"),
        (EventType.EXPERIMENTAL_PUBLISHED, "candidate_packet_digest", "0" * 64),
        (EventType.EXPERIMENTAL_PUBLISHED, "commit", "9" * 40),
        (EventType.PROTECTED_VALIDATION_RECORDED, "candidate_tree", "9" * 40),
    ),
)
def test_candidate_publication_identity_mismatch_does_not_mutate_chain(
    postgres: object, event_type: EventType, field: str, value: str
) -> None:
    manifest = sample_manifest()
    history = _full_event_history()
    target_index = next(
        index for index, event in enumerate(history) if event.event_type is event_type
    )
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    for event in history[:target_index]:
        with _as_role(postgres, f"carl_{_event_authority(event)}") as connection:
            _append_event(connection, event)

    target = history[target_index]
    invalid = ExperimentEvent.create(
        experiment_id=target.experiment_id,
        stage_attempt_id=f"invalid-identity-{field}",
        event_type=event_type,
        occurred_at=target.occurred_at,
        payload={**target.payload, field: value},
    )
    with _as_role(postgres, "carl_coordinator") as reader:
        before = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()
    with (
        _as_role(postgres, f"carl_{_event_authority(target)}") as connection,
        pytest.raises(psycopg.Error),
    ):
        _append_event(connection, invalid)
    with _as_role(postgres, "carl_coordinator") as reader:
        after = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()

    assert after == before
    _backend(postgres).load_projection(manifest.experiment_id)


def test_canonical_candidate_digest_seals_publishes_and_replays(postgres: object) -> None:
    manifest = sample_manifest()
    candidate = sealed_candidate()
    history = _full_event_history()
    publication_index = next(
        index
        for index, event in enumerate(history)
        if event.event_type is EventType.EXPERIMENTAL_PUBLISHED
    )
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    for event in history[:publication_index]:
        with _as_role(postgres, f"carl_{_event_authority(event)}") as connection:
            _append_event(connection, event)

    with _as_role(postgres, "carl_coordinator") as reader:
        guard = reader.execute(
            "SELECT candidate_packet_digest FROM "
            "carl_autonomy.experiment_projection_guards WHERE experiment_id = %s",
            (manifest.experiment_id,),
        ).fetchone()
        before = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()
    assert candidate.digest == "278d2d94d70cd9d1e54baed3fdbe617e4a88aaee0ac93dbb5e4895cbd9bd3b54"
    assert guard["candidate_packet_digest"] == candidate.digest

    publication = history[publication_index]
    mismatch = ExperimentEvent.create(
        experiment_id=publication.experiment_id,
        stage_attempt_id="candidate-envelope-digest-mismatch",
        event_type=EventType.EXPERIMENTAL_PUBLISHED,
        occurred_at=publication.occurred_at,
        payload={
            **publication.payload,
            "candidate_packet_digest": (
                "63451549980c44835ba0879b978e928bf7e5225887b5856e2fcc28a13839ed31"
            ),
        },
    )
    with _as_role(postgres, "carl_builder") as builder, pytest.raises(psycopg.Error):
        _append_event(builder, mismatch)
    with _as_role(postgres, "carl_coordinator") as reader:
        after_rejection = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()
    assert after_rejection == before

    with _as_role(postgres, "carl_builder") as builder:
        assert _append_event(builder, publication)["appended"] is True
    projection, autonomy = _backend(postgres).load_projection(manifest.experiment_id)
    assert projection.candidate is not None
    assert projection.candidate.digest == candidate.digest
    assert autonomy.experimental_publication is not None
    assert autonomy.experimental_publication.candidate_packet_digest == candidate.digest


def test_retry_sequence_rejects_nonfirst_skipped_and_repeated_attempts(postgres: object) -> None:
    manifest = sample_manifest()
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)

    def retry(stage_attempt_id: str, attempt: int, changed_action: str) -> ExperimentEvent:
        occurred_at = f"2026-08-20T12:00:0{attempt}Z"
        return ExperimentEvent.create(
            experiment_id=manifest.experiment_id,
            stage_attempt_id=stage_attempt_id,
            event_type=EventType.RETRY_SCHEDULED,
            occurred_at=occurred_at,
            payload=_retry_payload(
                attempt=attempt,
                scheduled_at=occurred_at,
                changed_action=changed_action,
            ),
        )

    with _as_role(postgres, "carl_coordinator") as coordinator:
        with pytest.raises(psycopg.Error, match="retry_attempt_not_monotonic"):
            _append_event(coordinator, retry("retry-first-two", 2, "first action"))
        assert _append_event(coordinator, retry("retry-one", 1, "first action"))["appended"]
        with pytest.raises(psycopg.Error, match="retry_attempt_not_monotonic"):
            _append_event(coordinator, retry("retry-skipped-three", 3, "third action"))
        with pytest.raises(psycopg.Error, match="retry_attempt_not_monotonic"):
            _append_event(coordinator, retry("retry-repeated-one", 1, "repeated action"))
        assert _append_event(coordinator, retry("retry-two", 2, "second action"))["appended"]
        with pytest.raises(psycopg.Error, match="retry_attempt_not_monotonic"):
            _append_event(coordinator, retry("retry-repeated-two", 2, "another action"))

    _backend(postgres).load_projection(manifest.experiment_id)


def test_duplicate_revert_is_rejected_without_chain_mutation(postgres: object) -> None:
    manifest = sample_manifest()
    history = _full_event_history()
    target_index = next(
        index
        for index, event in enumerate(history)
        if event.event_type is EventType.REVERT_RECORDED
    )
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    for event in history[: target_index + 1]:
        with _as_role(postgres, f"carl_{_event_authority(event)}") as connection:
            _append_event(connection, event)

    first = history[target_index]
    duplicate = ExperimentEvent.create(
        experiment_id=first.experiment_id,
        stage_attempt_id="duplicate-revert",
        event_type=EventType.REVERT_RECORDED,
        occurred_at="2026-08-11T12:01:31Z",
        payload=first.payload,
    )
    with _as_role(postgres, "carl_coordinator") as reader:
        before = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()
    with _as_role(postgres, "carl_soak") as soak, pytest.raises(psycopg.Error):
        _append_event(soak, duplicate)
    with _as_role(postgres, "carl_coordinator") as reader:
        after = reader.execute(
            "SELECT * FROM carl_autonomy.load_experiment_events(%s)",
            (manifest.experiment_id,),
        ).fetchall()

    assert after == before
    _backend(postgres).load_projection(manifest.experiment_id)


@pytest.mark.parametrize("width", (40, 64))
def test_projection_guard_preserves_sha1_and_sha256_git_ids(postgres: object, width: int) -> None:
    manifest = sample_manifest()
    candidate_commit = "9" * width
    candidate = replace(sealed_candidate(), candidate_commit=candidate_commit)
    evidence = replace(paired_evidence(), candidate_commit=candidate_commit)
    candidate_tree = "8" * width
    merge_commit = "7" * width
    merge_tree = "6" * width
    events = (
        *phase3_build_events(),
        _leased_event(
            attempt=f"width-{width}-workspace",
            event_type=EventType.WORKSPACE_PREPARED,
            occurred_at="2026-08-10T12:01:01Z",
            payload=prepared_candidate().to_canonical_dict(),
        ),
        _leased_event(
            attempt=f"width-{width}-sealed",
            event_type=EventType.CANDIDATE_SEALED,
            occurred_at="2026-08-10T12:01:02Z",
            payload=candidate.to_canonical_dict(),
        ),
        _state_event(
            attempt=f"width-{width}-deterministic",
            source=ExperimentState.BUILDING,
            target=ExperimentState.DETERMINISTIC_VALIDATION,
            occurred_at="2026-08-10T12:01:03Z",
        ),
        _state_event(
            attempt=f"width-{width}-paired",
            source=ExperimentState.DETERMINISTIC_VALIDATION,
            target=ExperimentState.PAIRED_EVALUATION,
            occurred_at="2026-08-10T12:01:04Z",
        ),
        _leased_event(
            attempt=f"width-{width}-evidence",
            event_type=EventType.PAIRED_EVIDENCE_RECORDED,
            occurred_at="2026-08-10T12:01:05Z",
            payload=evidence.to_canonical_dict(),
        ),
        ExperimentEvent.create(
            experiment_id=manifest.experiment_id,
            stage_attempt_id=f"width-{width}-publication",
            event_type=EventType.EXPERIMENTAL_PUBLISHED,
            occurred_at="2026-08-10T12:01:06Z",
            payload={
                "branch": f"experimental/{manifest.experiment_id}",
                "candidate_packet_digest": candidate.digest,
                "commit": candidate_commit,
                "tree": candidate_tree,
            },
        ),
        ExperimentEvent.create(
            experiment_id=manifest.experiment_id,
            stage_attempt_id=f"width-{width}-protected",
            event_type=EventType.PROTECTED_VALIDATION_RECORDED,
            occurred_at="2026-08-10T12:01:07Z",
            payload={
                "candidate_commit": candidate_commit,
                "candidate_tree": candidate_tree,
                "receipt_digest": "5" * 64,
            },
        ),
        ExperimentEvent.create(
            experiment_id=manifest.experiment_id,
            stage_attempt_id=f"width-{width}-promotion",
            event_type=EventType.PROMOTION_RECORDED,
            occurred_at="2026-08-10T12:01:08Z",
            payload={"merge_commit": merge_commit, "merge_tree": merge_tree},
        ),
    )
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    for event in events:
        with _as_role(postgres, f"carl_{_event_authority(event)}") as connection:
            _append_event(connection, event)

    with _as_role(postgres, "carl_coordinator") as reader:
        guard = reader.execute(
            "SELECT candidate_commit, experimental_commit, experimental_tree, "
            "promotion_merge_commit, promotion_merge_tree "
            "FROM carl_autonomy.experiment_projection_guards WHERE experiment_id = %s",
            (manifest.experiment_id,),
        ).fetchone()
    assert guard == {
        "candidate_commit": candidate_commit,
        "experimental_commit": candidate_commit,
        "experimental_tree": candidate_tree,
        "promotion_merge_commit": merge_commit,
        "promotion_merge_tree": merge_tree,
    }
    _backend(postgres).load_projection(manifest.experiment_id)


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
    assert row == {"direct_dml": False, "public_execute": False, "role_execute": False}


def test_registered_dead_holder_identity_and_observer_reconciler_role_separation(
    postgres: object,
) -> None:
    from datetime import UTC, datetime

    from psycopg import sql
    from psycopg.rows import dict_row

    assert POSTGRES_DSN is not None

    def observer_connect(dsn: str):
        connection = postgres.connect(dsn, row_factory=dict_row)  # type: ignore[attr-defined]
        connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier("carl_state_backend")))
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
            database_role="carl_state_backend",
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
    manifest = sample_manifest()
    with _as_role(postgres, "carl_builder") as builder:
        _register_manifest(builder, manifest)
    for event in _full_event_history():
        with _as_role(postgres, f"carl_{_event_authority(event)}") as connection:
            _append_event(connection, event)

    _experiment, autonomy = _backend(postgres).load_projection(manifest.experiment_id)
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


def test_effect_rate_limit_retry_rearms_once_after_persisted_deadline(
    postgres: object,
) -> None:
    command = _command()
    claim = _claim()
    dead_holder = _dead_holder(
        scope_kind="command",
        scope_key=command.command_key,
        subject_id=claim.claim_id,
        revision=8,
    )
    _register_observation(postgres, dead_holder)
    attempt = GitHubEffectAttempt(
        schema_version=1,
        effect_key=command.effect_key,
        command_key=command.command_key,
        claim_id=claim.claim_id,
        command_revision=8,
        claim_expected_revision=claim.expected_revision,
        action="dispatch_workflow",
        endpoint_id="workflow_dispatch",
        method="POST",
        payload_digest="c" * 64,
        command_request_digest=command.request_digest,
        repository="StephenBickel/carl-agent",
        target_identity="autonomous-improvement.yml@" + "1" * 40,
        request_key="cloud-run-request-001",
        attempt_key="cloud-run-request-001-attempt-1",
        authority=command.authority,
        operation=command.operation,
        command_occurred_at=command.occurred_at,
        claim_expires_at=claim.expires_at,
        attempt_state="prepared",
        not_before="2026-08-20T12:00:30Z",
        observed_at=NOW,
    )
    with _as_role(postgres, "carl_coordinator") as coordinator:
        coordinator.execute(
            "SELECT * FROM carl_autonomy.create_command(%s, %s)",
            (_canonical(command.to_canonical_dict()), NOW),
        ).fetchone()
        coordinator.execute(
            "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
            (_canonical(claim.to_canonical_dict()), NOW),
        ).fetchone()
        prepared = coordinator.execute(
            "SELECT * FROM carl_autonomy.prepare_effect_attempt(%s, %s)",
            (_canonical(attempt.to_canonical_dict()), NOW),
        ).fetchone()
        scheduled = coordinator.execute(
            "SELECT * FROM carl_autonomy.mark_effect_retry_scheduled(%s, %s, %s, %s)",
            (
                attempt.effect_key,
                "2026-08-20T12:01:30Z",
                "2026-08-20T12:00:01Z",
                "2026-08-20T12:00:01Z",
            ),
        ).fetchone()
        reconciliation = ClaimReconciliation(
            command_key=command.command_key,
            claim_id=claim.claim_id,
            authority=command.authority,
            expected_revision=8,
            next_revision=9,
            observed_at="2026-08-20T12:02:00Z",
        )
        coordinator.execute(
            "SELECT * FROM carl_autonomy.reconcile_expired_claim(%s, %s, %s)",
            (
                _canonical(reconciliation.to_canonical_dict()),
                dead_holder.digest,
                reconciliation.observed_at,
            ),
        ).fetchone()
        retry_claim = replace(
            _claim(claim_id="claim-002", revision=9),
            claimed_at="2026-08-20T12:02:00Z",
            expires_at="2026-08-20T12:05:00Z",
        )
        reclaimed = coordinator.execute(
            "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
            (
                _canonical(retry_claim.to_canonical_dict()),
                retry_claim.claimed_at,
            ),
        ).fetchone()
        due_attempt = replace(
            attempt,
            claim_id=retry_claim.claim_id,
            command_revision=10,
            claim_expected_revision=retry_claim.expected_revision,
            claim_expires_at=retry_claim.expires_at,
            observed_at="2026-08-20T12:02:01Z",
            not_before="2026-08-20T12:02:31Z",
        )
        rearmed = coordinator.execute(
            "SELECT * FROM carl_autonomy.prepare_effect_attempt(%s, %s)",
            (
                _canonical(due_attempt.to_canonical_dict()),
                due_attempt.observed_at,
            ),
        ).fetchone()
        duplicate = coordinator.execute(
            "SELECT * FROM carl_autonomy.prepare_effect_attempt(%s, %s)",
            (
                _canonical(due_attempt.to_canonical_dict()),
                due_attempt.observed_at,
            ),
        ).fetchone()

    assert prepared["applied"] is True
    assert scheduled["applied"] is True
    assert reclaimed["revision"] == 10
    assert rearmed["applied"] is True
    assert duplicate["applied"] is False


def test_uncertain_effect_completion_requires_replacement_claim_adoption(
    postgres: object,
) -> None:
    command = _command()
    claim = _claim()
    dead_holder = _dead_holder(
        scope_kind="command",
        scope_key=command.command_key,
        subject_id=claim.claim_id,
        revision=8,
    )
    _register_observation(postgres, dead_holder)
    attempt = GitHubEffectAttempt(
        schema_version=1,
        effect_key=command.effect_key,
        command_key=command.command_key,
        claim_id=claim.claim_id,
        command_revision=8,
        claim_expected_revision=claim.expected_revision,
        action="dispatch_workflow",
        endpoint_id="workflow_dispatch",
        method="POST",
        payload_digest="c" * 64,
        command_request_digest=command.request_digest,
        repository="StephenBickel/carl-agent",
        target_identity="autonomous-improvement.yml@" + "1" * 40,
        request_key="cloud-run-request-uncertain-001",
        attempt_key="cloud-run-request-uncertain-001-attempt-1",
        authority=command.authority,
        operation=command.operation,
        command_occurred_at=command.occurred_at,
        claim_expires_at=claim.expires_at,
        attempt_state="prepared",
        not_before="2026-08-20T12:00:30Z",
        observed_at=NOW,
    )
    with _as_role(postgres, "carl_coordinator") as coordinator:
        coordinator.execute(
            "SELECT * FROM carl_autonomy.create_command(%s, %s)",
            (_canonical(command.to_canonical_dict()), NOW),
        ).fetchone()
        coordinator.execute(
            "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
            (_canonical(claim.to_canonical_dict()), NOW),
        ).fetchone()
        coordinator.execute(
            "SELECT * FROM carl_autonomy.prepare_effect_attempt(%s, %s)",
            (_canonical(attempt.to_canonical_dict()), NOW),
        ).fetchone()
        coordinator.execute(
            "SELECT * FROM carl_autonomy.mark_effect_uncertain(%s, %s, %s, %s)",
            (
                attempt.effect_key,
                attempt.not_before,
                "2026-08-20T12:00:01Z",
                "2026-08-20T12:00:01Z",
            ),
        ).fetchone()
        reconciliation = ClaimReconciliation(
            command_key=command.command_key,
            claim_id=claim.claim_id,
            authority=command.authority,
            expected_revision=8,
            next_revision=9,
            observed_at="2026-08-20T12:02:00Z",
        )
        coordinator.execute(
            "SELECT * FROM carl_autonomy.reconcile_expired_claim(%s, %s, %s)",
            (
                _canonical(reconciliation.to_canonical_dict()),
                dead_holder.digest,
                reconciliation.observed_at,
            ),
        ).fetchone()
        with pytest.raises(Exception, match="effect_attempt_transition_denied"):
            coordinator.execute(
                "SELECT * FROM carl_autonomy.mark_effect_completed(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (
                    attempt.effect_key,
                    attempt.command_key,
                    attempt.claim_id,
                    attempt.command_revision,
                    attempt.claim_expected_revision,
                    attempt.claim_expires_at,
                    DIGEST_B,
                    "2026-08-20T12:02:00Z",
                    "2026-08-20T12:02:00Z",
                ),
            ).fetchone()
        replacement_claim = replace(
            _claim(claim_id="claim-uncertain-replacement", revision=9),
            claimed_at="2026-08-20T12:02:00Z",
            expires_at="2026-08-20T12:05:00Z",
        )
        reclaimed = coordinator.execute(
            "SELECT * FROM carl_autonomy.claim_command(%s, %s)",
            (
                _canonical(replacement_claim.to_canonical_dict()),
                replacement_claim.claimed_at,
            ),
        ).fetchone()
        replacement_attempt = replace(
            attempt,
            claim_id=replacement_claim.claim_id,
            command_revision=10,
            claim_expected_revision=replacement_claim.expected_revision,
            claim_expires_at=replacement_claim.expires_at,
            observed_at="2026-08-20T12:02:01Z",
            not_before="2026-08-20T12:02:31Z",
        )
        observation_only = coordinator.execute(
            "SELECT * FROM carl_autonomy.prepare_effect_attempt(%s, %s)",
            (
                _canonical(replacement_attempt.to_canonical_dict()),
                replacement_attempt.observed_at,
            ),
        ).fetchone()
        completed = coordinator.execute(
            "SELECT * FROM carl_autonomy.mark_effect_completed(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (
                replacement_attempt.effect_key,
                replacement_attempt.command_key,
                replacement_attempt.claim_id,
                replacement_attempt.command_revision,
                replacement_attempt.claim_expected_revision,
                replacement_attempt.claim_expires_at,
                DIGEST_B,
                "2026-08-20T12:02:02Z",
                "2026-08-20T12:02:02Z",
            ),
        ).fetchone()
        persisted = coordinator.execute(
            "SELECT attempt_state, claim_id, result_digest "
            "FROM carl_autonomy.effect_attempts WHERE effect_key = %s",
            (attempt.effect_key,),
        ).fetchone()

    assert reclaimed["revision"] == 10
    assert observation_only["applied"] is False
    assert completed["applied"] is True
    assert persisted == {
        "attempt_state": "completed",
        "claim_id": replacement_claim.claim_id,
        "result_digest": DIGEST_B,
    }


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
        connection.execute(sql.SQL("SET ROLE {}").format(sql.Identifier("carl_state_backend")))
        return connection

    assert POSTGRES_DSN is not None
    backend = PostgresStateBackend.from_config(
        PostgresStateConfig(
            dsn=POSTGRES_DSN,
            database_role="carl_state_backend",
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

    malformed_envelope = valid_event.to_canonical_dict()
    malformed_envelope["unexpected"] = True
    malformed_event_json = _canonical(malformed_envelope)
    malformed_event_digest = hashlib.sha256(malformed_event_json.encode("utf-8")).hexdigest()
    with _as_role(postgres, "carl_coordinator") as coordinator:
        with pytest.raises(psycopg.Error):
            coordinator.execute(
                "SELECT * FROM carl_autonomy.complete_command_and_append_event(%s, %s, %s, %s, %s)",
                (
                    _canonical(transition.to_canonical_dict()),
                    malformed_event_json,
                    malformed_event_digest,
                    valid_event.payload_json,
                    NOW,
                ),
            ).fetchone()
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
