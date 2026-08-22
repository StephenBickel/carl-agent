from __future__ import annotations

import base64
import hashlib
import json
import re
from contextlib import AbstractContextManager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from postgres_event_policy import (
    EVENT_BOOLEAN_FIELDS,
    EVENT_INTEGER_FIELDS,
    EVENT_PAYLOAD_KEY_SETS,
    EVENT_REDUCER_BINDINGS,
    EVENT_STRING_FIELDS,
    INVALID_EVENT_PAYLOAD_TYPES,
)
from test_cloud_coordinator import claimed_command_for as coordinator_claimed_command
from test_cloud_coordinator import lease as coordinator_lease
from test_cloud_coordinator import node as coordinator_node
from test_cloud_coordinator import snapshot as coordinator_snapshot
from test_experiment import manifest as sample_manifest
from test_experiment import sealed_candidate

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_coordinator import EFFECT_FAMILY_BY_NODE, choose_next_action
from carl_bench.cloud_execution import CloudRunRequest
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
from carl_bench.coordinator_effects import (
    CoordinatorNodeEffectRequest,
    CoordinatorNodeEffectResponse,
    PreparedCoordinatorEffect,
)
from carl_bench.experiment import EventType, ExperimentEvent
from carl_bench.github_cloud import GitHubEffectAttempt, workflow_dispatch_binding
from carl_bench.github_effect_ipc import (
    REQUEST_DOMAIN,
    RESPONSE_DOMAIN,
    GitHubEffectRequest,
    GitHubEffectResponse,
)
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
WORKFLOW_DATABASE_ROLES = (
    "carl_builder",
    "carl_coordinator",
    "carl_observer",
    "carl_promoter",
    "carl_soak",
    "carl_supervisor",
    "carl_validator",
)
ROLE_PROCEDURES_SQL = (
    Path(__file__).parents[2] / "infra/autonomy/postgres/002_role_procedures.sql"
).read_text(encoding="utf-8")
INITIAL_SQL = (Path(__file__).parents[2] / "infra/autonomy/postgres/001_initial.sql").read_text(
    encoding="utf-8"
)
GITHUB_EFFECT_FENCES_PATH = (
    Path(__file__).parents[2] / "infra/autonomy/postgres/003_github_effect_fences.sql"
)
GITHUB_EFFECT_FENCES_SQL = (
    GITHUB_EFFECT_FENCES_PATH.read_text(encoding="utf-8")
    if GITHUB_EFFECT_FENCES_PATH.exists()
    else ""
)
COORDINATOR_RUNTIME_PATH = (
    Path(__file__).parents[2] / "infra/autonomy/postgres/004_coordinator_runtime.sql"
)
COORDINATOR_RUNTIME_SQL = (
    COORDINATOR_RUNTIME_PATH.read_text(encoding="utf-8")
    if COORDINATOR_RUNTIME_PATH.exists()
    else ""
)
POSTGRES_INTEGRATION_SOURCE = (
    Path(__file__).with_name("test_postgres_state_integration.py").read_text(encoding="utf-8")
)
BENCHMARK_WORKFLOW = (
    Path(__file__).parents[2] / ".github/workflows/benchmark-contracts.yml"
).read_text(encoding="utf-8")
HISTORICAL_EFFECT_FENCE_FIXTURE = (
    Path(__file__).parents[2]
    / "benchmarks/tests/fixtures/postgres-4aa2ab5-github-effect-fences.sql"
)
EVENT_POLICY_CASES = (
    (EventType.STATE_TRANSITIONED, frozenset({"coordinator", "soak"}), "if"),
    (EventType.ROLE_RECORDED, frozenset({"builder"}), "if"),
    (EventType.LEASE_ACQUIRED, frozenset({"coordinator"}), "if"),
    (EventType.LEASE_RECONCILED, frozenset({"coordinator"}), "case"),
    (EventType.LEASE_RELEASED, frozenset({"coordinator"}), "case"),
    (EventType.LIVE_SPEND_RECORDED, frozenset({"coordinator"}), "case"),
    (EventType.WORKSPACE_PREPARED, frozenset({"builder"}), "case"),
    (EventType.CANDIDATE_SEALED, frozenset({"builder"}), "case"),
    (EventType.PAIRED_EVIDENCE_RECORDED, frozenset({"validator"}), "case"),
    (EventType.REVIEW_PACKET_RECORDED, frozenset({"validator"}), "case"),
    (EventType.REVIEW_ATTESTED, frozenset({"validator"}), "case"),
    (EventType.DRAFT_PR_REQUESTED, frozenset({"promoter"}), "case"),
    (EventType.DRAFT_PR_RECORDED, frozenset({"promoter"}), "case"),
    (EventType.WORKSPACE_DISPOSED, frozenset({"promoter"}), "case"),
    (EventType.RETRY_SCHEDULED, frozenset({"coordinator"}), "case"),
    (EventType.EXPERIMENTAL_PUBLISHED, frozenset({"builder"}), "case"),
    (EventType.PROTECTED_VALIDATION_RECORDED, frozenset({"validator"}), "case"),
    (EventType.PROMOTION_RECORDED, frozenset({"promoter"}), "case"),
    (EventType.SOAK_OBSERVED, frozenset({"soak"}), "case"),
    (EventType.REVERT_RECORDED, frozenset({"soak"}), "case"),
)


def test_sql_persists_exact_effect_fence_before_network_and_reuses_it_on_restart() -> None:
    assert GITHUB_EFFECT_FENCES_PATH.is_file()
    assert not re.search(
        r"CREATE\s+TABLE\s+carl_autonomy\.effect_attempts",
        INITIAL_SQL,
        re.IGNORECASE,
    )
    assert not re.search(
        r"FUNCTION\s+carl_autonomy\.(?:prepare_effect_attempt|mark_effect_uncertain)",
        ROLE_PROCEDURES_SQL,
        re.IGNORECASE,
    )
    assert re.search(
        r"CREATE\s+TABLE\s+carl_autonomy\.effect_attempts",
        GITHUB_EFFECT_FENCES_SQL,
        re.IGNORECASE,
    )
    for column in (
        "effect_key",
        "command_key",
        "claim_id",
        "command_revision",
        "payload_digest",
        "attempt_state",
        "not_before",
        "attempt_json",
    ):
        assert re.search(rf"\b{column}\b", GITHUB_EFFECT_FENCES_SQL, re.IGNORECASE)
    for function_name in (
        "resolve_claimed_command",
        "prepare_effect_attempt",
        "mark_effect_uncertain",
        "mark_effect_retry_scheduled",
        "mark_effect_completed",
    ):
        assert re.search(
            rf"FUNCTION\s+carl_autonomy\.{function_name}\b",
            GITHUB_EFFECT_FENCES_SQL,
            re.IGNORECASE,
        )
    prepare = re.search(
        r"FUNCTION\s+carl_autonomy\.prepare_effect_attempt\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        GITHUB_EFFECT_FENCES_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert prepare is not None
    body = prepare.group("body")
    assert "FOR UPDATE" in body
    assert "command_json" in body
    assert "claim_json" in body
    assert "INSERT INTO carl_autonomy.effect_attempts" in body
    assert "effect_attempt_conflict" in body


def test_sql_exposes_exact_coordinator_reconstruction_and_effect_fences() -> None:
    assert COORDINATOR_RUNTIME_PATH.is_file()
    for function_name in (
        "load_coordinator_snapshot",
        "apply_coordinator_decision",
        "prepare_coordinator_effect",
        "complete_coordinator_effect",
    ):
        assert re.search(
            rf"FUNCTION\s+carl_autonomy\.{function_name}\b",
            COORDINATOR_RUNTIME_SQL,
            re.IGNORECASE,
        )
    assert "FOR UPDATE SKIP LOCKED" in COORDINATOR_RUNTIME_SQL
    assert "decision_identity" in COORDINATOR_RUNTIME_SQL
    assert "request_digest" in COORDINATOR_RUNTIME_SQL
    assert "carl_state_backend" in COORDINATOR_RUNTIME_SQL


def test_coordinator_sql_strictly_validates_typed_effect_documents() -> None:
    prepare = re.search(
        r"FUNCTION\s+carl_autonomy\.prepare_coordinator_effect\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        COORDINATOR_RUNTIME_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    complete = re.search(
        r"FUNCTION\s+carl_autonomy\.complete_coordinator_effect\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        COORDINATOR_RUNTIME_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    local = re.search(
        r"FUNCTION\s+carl_autonomy\.execute_coordinator_local_effect\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        COORDINATOR_RUNTIME_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert prepare is not None
    assert complete is not None
    assert local is not None
    prepare_body = prepare.group("body")
    complete_body = complete.group("body")
    local_body = local.group("body")
    for field in (
        "family",
        "node_kind",
        "command_key",
        "effect_key",
        "request_digest",
        "occurred_at",
    ):
        assert re.search(rf"request_value->>'{field}'\s+IS\s+DISTINCT\s+FROM", prepare_body)
        assert re.search(rf"request_value->>'{field}'\s+IS\s+DISTINCT\s+FROM", local_body)
    for field in ("request_digest",):
        assert re.search(rf"response_value->>'{field}'\s+IS\s+DISTINCT\s+FROM", complete_body)
    assert re.search(
        r"canonical_utc_text_valid\(\s*response_value->>'observed_at'\s*\)",
        complete_body,
    )
    assert "command_state.occurred_at" in complete_body
    assert "p_observed_at + interval '30 seconds'" in complete_body
    assert "jsonb_typeof(response_value->'result_digest') <> 'string'" in complete_body
    assert "jsonb_typeof(response_value->'retry_not_before') <> 'string'" in complete_body
    assert re.search(
        r"canonical_utc_text_valid\(\s*response_value->>'retry_not_before'\s*\)",
        complete_body,
    )


def test_coordinator_sql_effect_family_table_matches_every_python_node() -> None:
    routing = re.search(
        r"FUNCTION\s+carl_autonomy\.coordinator_effect_family\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        COORDINATOR_RUNTIME_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert routing is not None
    sql_routes = dict(re.findall(r"WHEN\s+'([^']+)'\s+THEN\s+'([^']+)'", routing.group("body")))
    assert sql_routes == dict(EFFECT_FAMILY_BY_NODE)


def test_coordinator_migration_is_mandatory_in_integration_and_ci() -> None:
    assert "004_coordinator_runtime.sql" in POSTGRES_INTEGRATION_SOURCE
    assert "--file infra/autonomy/postgres/004_coordinator_runtime.sql" in BENCHMARK_WORKFLOW


def test_protected_policy_decodes_canonical_bounded_base64_public_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from carl_bench import postgres_state

    policy_dir = tmp_path / "etc-carl"
    policy_dir.mkdir(mode=0o700)
    policy = {
        "authority_key": {
            "key_id": AUTHORITY_KEY.key_id,
            "public_key_pem_b64": base64.b64encode(AUTHORITY_KEY.public_key_pem).decode("ascii"),
            "purpose": AUTHORITY_KEY.purpose,
        },
        "database_role": "carl_state_backend",
        "dead_holder_key": {
            "key_id": LIVENESS_KEY.key_id,
            "public_key_pem_b64": base64.b64encode(LIVENESS_KEY.public_key_pem).decode("ascii"),
            "purpose": LIVENESS_KEY.purpose,
        },
        "schema_version": 1,
    }
    policy_path = policy_dir / "postgres-state-policy.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    policy_path.chmod(0o600)
    monkeypatch.setattr(postgres_state, "_PROTECTED_STATE_CONFIG_DIR", policy_dir)
    monkeypatch.setenv("CARL_AUTONOMY_POSTGRES_DSN", "postgresql://protected.invalid/carl")

    backend = PostgresStateBackend.from_protected_environment()

    assert backend.verifier._authority_key == AUTHORITY_KEY
    assert backend.verifier._dead_holder_key == LIVENESS_KEY


@pytest.mark.parametrize(
    "encoded_key",
    (
        "QUJD\n",
        "A" * 8_193,
        "not+canonical=base64===",
    ),
)
def test_protected_policy_rejects_noncanonical_or_oversized_base64_keys(
    encoded_key: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from carl_bench import postgres_state

    policy_dir = tmp_path / "etc-carl"
    policy_dir.mkdir(mode=0o700)
    policy = {
        "authority_key": {
            "key_id": AUTHORITY_KEY.key_id,
            "public_key_pem_b64": encoded_key,
            "purpose": AUTHORITY_KEY.purpose,
        },
        "database_role": "carl_state_backend",
        "dead_holder_key": {
            "key_id": LIVENESS_KEY.key_id,
            "public_key_pem_b64": base64.b64encode(LIVENESS_KEY.public_key_pem).decode("ascii"),
            "purpose": LIVENESS_KEY.purpose,
        },
        "schema_version": 1,
    }
    policy_path = policy_dir / "postgres-state-policy.json"
    policy_path.write_bytes(canonical_json_bytes(policy))
    policy_path.chmod(0o600)
    monkeypatch.setattr(postgres_state, "_PROTECTED_STATE_CONFIG_DIR", policy_dir)
    monkeypatch.setenv("CARL_AUTONOMY_POSTGRES_DSN", "postgresql://protected.invalid/carl")

    with pytest.raises(PostgresStateError, match="postgres_protected_configuration_invalid"):
        PostgresStateBackend.from_protected_environment()


def test_coordinator_sql_requires_semantic_check_and_protection_objects() -> None:
    load = re.search(
        r"FUNCTION\s+carl_autonomy\.load_coordinator_snapshot\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        COORDINATOR_RUNTIME_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert load is not None
    body = load.group("body")
    for binding in (
        "required_checks_object_key",
        "required_checks_object_version",
        "required_checks_recorded_at",
        "required_checks_retain_until",
        "branch_protection_object_key",
        "branch_protection_object_version",
        "branch_protection_recorded_at",
        "branch_protection_retain_until",
    ):
        assert binding in body
    assert "checks_state.evidence_json" in body
    assert "protection_state.evidence_json" in body
    assert "archive_state.digest IS NULL" in body
    assert re.search(
        r"checks_state\.recorded_at\s*<\s*p_observed_at\s*-\s*interval\s*'15 minutes'",
        body,
        re.IGNORECASE,
    )
    assert re.search(
        r"protection_state\.recorded_at\s*<\s*p_observed_at\s*-\s*interval\s*'15 minutes'",
        body,
        re.IGNORECASE,
    )


def test_coordinator_sql_accepts_only_healthy_soak_without_later_hard_failure() -> None:
    load = re.search(
        r"FUNCTION\s+carl_autonomy\.load_coordinator_snapshot\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        COORDINATOR_RUNTIME_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert load is not None
    body = load.group("body")
    assert re.search(
        r"soak\.payload_json::jsonb->'healthy'\s*=\s*'true'::jsonb", body, re.IGNORECASE
    )
    assert re.search(
        r"NOT\s+EXISTS\s*\(.*?hard_failure.*?occurred_at\s*>=\s*soak\.occurred_at",
        body,
        re.IGNORECASE | re.DOTALL,
    )
    assert re.search(
        r"p_observed_at\s*>=\s*guard_state\.promotion_merged_at\s*\+\s*interval\s*'24 hours'",
        body,
        re.IGNORECASE,
    )


def test_acceptance_append_transaction_rechecks_failure_absence() -> None:
    validation = re.search(
        r"FUNCTION\s+carl_autonomy\.validate_and_advance_event\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert validation is not None
    accepted_guard = re.search(
        r"IF\s+target_state\s*=\s*'accepted'\s+AND\s*\((?P<predicate>.*?)\)\s*THEN",
        validation.group("body"),
        re.IGNORECASE | re.DOTALL,
    )

    assert accepted_guard is not None
    predicate = accepted_guard.group("predicate")
    assert "guard.promotion_recorded" in predicate
    assert "guard.qualifying_healthy_soak_at IS NULL" in predicate
    assert "guard.soak_failure_recorded" in predicate
    assert "guard.soak_failure_digest IS NOT NULL" in predicate


def test_sql_reconstructs_mutable_coordinator_truth_from_protected_tables() -> None:
    load = re.search(
        r"FUNCTION\s+carl_autonomy\.load_coordinator_snapshot\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        COORDINATOR_RUNTIME_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert load is not None
    body = load.group("body")
    for durable_source in (
        "carl_autonomy.commands",
        "carl_autonomy.leases",
        "carl_autonomy.effect_attempts",
        "carl_autonomy.experiment_projection_guards",
        "carl_autonomy.evidence_objects",
    ):
        assert durable_source in body
    for caller_selected_field in (
        "'{command}'",
        "'{effect}'",
        "'{lease}'",
        "'{observed_at}'",
        "'{production_authorization}'",
    ):
        assert caller_selected_field in body
    assert "coordinator_snapshot_mutable_input_forbidden" in body
    assert "coordinator_node_priority" in body


def test_sql_applies_every_consequential_coordinator_action_or_fails_closed() -> None:
    apply = re.search(
        r"FUNCTION\s+carl_autonomy\.apply_coordinator_decision\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        COORDINATOR_RUNTIME_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert apply is not None
    body = apply.group("body")
    for action in (
        "acquire_lease",
        "renew_lease",
        "reconcile_lease",
        "release_lease",
        "persist_command",
        "claim_command",
        "complete_command",
        "retry_rework",
        "trigger_supervisor",
        "frozen",
    ):
        assert re.search(rf"WHEN[^\n]*'{action}'", body)
    for durable_operation in (
        "acquire_lease",
        "renew_coordinator_lease",
        "reconcile_lease",
        "release_lease",
        "create_command",
        "claim_command",
        "complete_command_and_append_event",
        "create_supervisor_trigger",
    ):
        assert f"carl_autonomy.{durable_operation}" in body
    assert "coordinator_action_not_supported" in body
    assert "_service_uncommissioned" in body


def test_sql_derives_named_production_receipts_from_exact_durable_identities() -> None:
    load = re.search(
        r"FUNCTION\s+carl_autonomy\.load_coordinator_snapshot\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        COORDINATOR_RUNTIME_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert load is not None
    body = load.group("body")
    for identity in (
        "archive_receipt_digest",
        "experimental_receipt_digest",
        "live_provenance_receipt_digest",
        "independent_disposition_receipt_digest",
        "required_checks_receipt_digest",
        "branch_protection_receipt_digest",
        "pull_request_number",
        "pull_request_head",
        "pull_request_base",
        "hard_failure_digest",
        "revert_candidate_commit",
    ):
        assert identity in body
    assert "coordinator_production_receipt_mismatch" in body
    assert "coordinator_production_receipt_digest_mismatch" in body
    assert "production_receipts_digest" in COORDINATOR_RUNTIME_SQL
    assert re.search(
        r"jsonb_set\s*\(\s*receipt_value\s*,\s*'\{verified_at\}'",
        body,
        re.IGNORECASE | re.DOTALL,
    )
    assert "p_observed_at" in body


def test_sql_effect_fence_can_rearm_only_after_a_durable_rate_limit_deadline() -> None:
    assert re.search(
        r"attempt_state\s+IN\s*\([^)]*'retry_scheduled'",
        GITHUB_EFFECT_FENCES_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    retry = re.search(
        r"FUNCTION\s+carl_autonomy\.mark_effect_retry_scheduled\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        GITHUB_EFFECT_FENCES_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert retry is not None
    assert "FOR UPDATE" in retry.group("body")
    assert "retry_scheduled" in retry.group("body")
    prepare = re.search(
        r"FUNCTION\s+carl_autonomy\.prepare_effect_attempt\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        GITHUB_EFFECT_FENCES_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert prepare is not None
    assert re.search(
        r"attempt_state\s*=\s*'retry_scheduled'.*?p_observed_at\s*>=\s*existing\.not_before",
        prepare.group("body"),
        re.IGNORECASE | re.DOTALL,
    )
    rearm = re.search(
        r"IF\s+existing\.attempt_state\s*=\s*'retry_scheduled'.*?THEN\s+"
        r"UPDATE\s+carl_autonomy\.effect_attempts.*?SET(?P<assignments>.*?)WHERE",
        prepare.group("body"),
        re.IGNORECASE | re.DOTALL,
    )
    assert rearm is not None
    assignments = rearm.group("assignments")
    for assignment in (
        "claim_id = claim_key",
        "command_revision = command_revision_value",
        "claim_expected_revision = claim_revision_value",
        "claim_expires_at = claim_expires_time",
        "claim_expires_at_text = claim_expires_text",
    ):
        assert assignment in assignments


def test_sql_uncertain_fence_reclaim_changes_claim_lineage_without_restoring_mutation() -> None:
    prepare = re.search(
        r"FUNCTION\s+carl_autonomy\.prepare_effect_attempt\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        GITHUB_EFFECT_FENCES_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert prepare is not None
    uncertain = re.search(
        r"IF\s+existing\.attempt_state\s*=\s*'uncertain'.*?THEN(?P<body>.*?)END\s+IF",
        prepare.group("body"),
        re.IGNORECASE | re.DOTALL,
    )
    assert uncertain is not None
    body = uncertain.group("body")
    for assignment in (
        "claim_id = claim_key",
        "command_revision = command_revision_value",
        "claim_expected_revision = claim_revision_value",
        "claim_expires_at = claim_expires_time",
        "claim_expires_at_text = claim_expires_text",
    ):
        assert assignment in body
    assert "attempt_state = 'prepared'" not in body
    assert "RETURN QUERY SELECT false" in body


def test_sql_completion_requires_exact_current_live_claim_and_adopted_fence_lineage() -> None:
    completed = re.search(
        r"FUNCTION\s+carl_autonomy\.mark_effect_completed\b.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        GITHUB_EFFECT_FENCES_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert completed is not None
    body = completed.group("body")
    for identity in (
        "p_command_key",
        "p_claim_id",
        "p_command_revision",
        "p_claim_expected_revision",
        "p_claim_expires_at_text",
    ):
        assert identity in body
    assert "carl_autonomy.commands" in body
    assert body.count("FOR UPDATE") >= 2
    assert "current_state.claim_expires_at <= p_observed_at" in body
    assert "current_attempt.claim_id <> p_claim_id" in body
    assert "current_attempt.command_revision <> p_command_revision" in body


def test_effect_fence_migration_pins_and_validates_both_historical_starting_states() -> None:
    assert HISTORICAL_EFFECT_FENCE_FIXTURE.is_file()
    fixture_bytes = HISTORICAL_EFFECT_FENCE_FIXTURE.read_bytes()
    assert hashlib.sha256(fixture_bytes).hexdigest() == (
        "31666751b9c7e337b49d4a4316e1e0d67572aed2af879340e0498b99cbdf718a"
    )
    fixture = fixture_bytes.decode("utf-8")
    assert "Source commit: 4aa2ab57779beecf61137bc6f994a82a5fb797c3" in fixture
    assert (
        "001 SHA-256: af8ee07b184fd0183b6810ce9e7f8946ce7e23736c02e7a39e2cada3dbcbf202" in fixture
    )
    assert (
        "002 SHA-256: dffbd010b6d4d1c5bd6dbcdbcc5d35e4b33cf99557c3af35a246573192e668d1" in fixture
    )
    assert "CREATE TABLE carl_autonomy.effect_attempts" in fixture
    assert "CREATE OR REPLACE FUNCTION carl_autonomy.mark_effect_completed" in fixture
    for contract in (
        "to_regclass('carl_autonomy.effect_attempts')",
        "effect_fence_schema_invalid",
        "pg_catalog.pg_attribute",
        "pg_catalog.pg_get_userbyid",
        "effect_attempts_reconciliation",
    ):
        assert contract in GITHUB_EFFECT_FENCES_SQL


def test_effect_fence_migration_compares_exact_catalog_contract_before_replacement() -> None:
    for catalog_contract in (
        "pg_catalog.pg_attribute",
        "pg_catalog.format_type",
        "pg_catalog.pg_attrdef",
        "pg_catalog.pg_constraint",
        "pg_catalog.pg_get_constraintdef",
        "pg_catalog.pg_index",
        "pg_catalog.pg_opclass",
        "pg_catalog.pg_collation",
        "pg_catalog.pg_proc",
        "prosecdef",
        "proconfig",
        "aclexplode",
        "attcollation",
        "indnkeyatts",
        "indnullsnotdistinct",
        "indisprimary",
        "indisunique",
        "indkey",
        "indoption",
        "indexprs",
        "pg_catalog.pg_opfamily",
        "pg_catalog.pg_tablespace",
        "attacl",
    ):
        assert catalog_contract in GITHUB_EFFECT_FENCES_SQL
    assert not re.search(
        r"CREATE\s+TEMP(?:ORARY)?\s+TABLE\b.*?"
        r"REFERENCES\s+carl_autonomy\.commands",
        GITHUB_EFFECT_FENCES_SQL,
        re.IGNORECASE | re.DOTALL,
    )
    assert re.search(
        r"CREATE\s+TABLE\s+carl_autonomy\._migration_expected_effect_attempts\b",
        GITHUB_EFFECT_FENCES_SQL,
        re.IGNORECASE,
    )
    assert re.search(
        r"DROP\s+TABLE\s+carl_autonomy\._migration_expected_effect_attempts\b",
        GITHUB_EFFECT_FENCES_SQL,
        re.IGNORECASE,
    )
    assert "unexpected_grantee" in GITHUB_EFFECT_FENCES_SQL
    assert "effect_fence_function_invalid" in GITHUB_EFFECT_FENCES_SQL


def test_shared_event_policy_keys_equal_production_event_type() -> None:
    production = set(EventType)

    assert {event_type for event_type, _authorities, _handler in EVENT_POLICY_CASES} == production
    assert set(EVENT_PAYLOAD_KEY_SETS) == production
    assert set(EVENT_STRING_FIELDS) == production
    assert set(EVENT_INTEGER_FIELDS) == production
    assert set(EVENT_BOOLEAN_FIELDS) == production
    assert set(EVENT_REDUCER_BINDINGS) == production
    assert {event_type for event_type, _path, _value in INVALID_EVENT_PAYLOAD_TYPES} == production


def test_sql_guard_binds_workspace_to_registered_manifest_identity() -> None:
    assert re.search(r"manifest_digest\s+character\(64\)\s+NOT\s+NULL", INITIAL_SQL, re.I)
    assert re.search(r"manifest_parent_commit\s+varchar\(64\)\s+NOT\s+NULL", INITIAL_SQL, re.I)
    assert re.search(r"workspace_manifest_digest\s+character\(64\)", INITIAL_SQL, re.I)
    assert re.search(r"workspace_parent_commit\s+varchar\(64\)", INITIAL_SQL, re.I)
    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.validate_and_advance_event.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    workspace = re.search(
        r"WHEN\s+'workspace_prepared'\s+THEN(?P<body>.*?)"
        r"WHEN\s+'candidate_sealed'",
        validator.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert workspace is not None
    assert "guard.manifest_digest" in workspace.group("body")
    assert "guard.manifest_parent_commit" in workspace.group("body")


def test_sql_attestation_quorum_rejects_all_hard_findings() -> None:
    assert re.search(r"review_attestation_approvals\s+smallint\s+NOT\s+NULL", INITIAL_SQL, re.I)
    assert re.search(r"review_attestation_hard_findings\s+smallint\s+NOT\s+NULL", INITIAL_SQL, re.I)
    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.validate_and_advance_event.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    draft = re.search(
        r"WHEN\s+'draft_pr_requested'\s+THEN(?P<body>.*?)"
        r"WHEN\s+'draft_pr_recorded'",
        validator.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert draft is not None
    assert re.search(r"review_attestation_approvals\s*<\s*3", draft.group("body"), re.I)
    assert re.search(r"review_attestation_hard_findings\s*<>\s*0", draft.group("body"), re.I)


def test_sql_requires_canonical_utc_z_event_timestamps() -> None:
    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.canonical_utc_text_valid\(.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    body = validator.group("body")
    assert "octet_length" in body
    assert re.search(r"T.*Z", body, re.DOTALL)
    assert re.search(
        r"canonical_utc_text_valid\(p_payload->>'expires_at'\)",
        ROLE_PROCEDURES_SQL,
        re.I,
    )
    assert re.search(
        r"canonical_utc_text_valid\(p_payload->>'scheduled_at'\)",
        ROLE_PROCEDURES_SQL,
        re.I,
    )
    assert re.search(
        r"canonical_utc_text_valid\(p_payload->>'observed_at'\)",
        ROLE_PROCEDURES_SQL,
        re.I,
    )


def test_append_and_atomic_event_ingress_require_exact_top_level_keys() -> None:
    append = re.search(
        r"FUNCTION\s+carl_autonomy\.append_event\(.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert append is not None
    body = append.group("body")
    assert re.search(r"jsonb_object_length\(value\)\s*<>\s*6", body, re.I)
    assert re.search(
        r"value\s+\?&\s+ARRAY\[\s*'schema_version',\s*'experiment_id',\s*"
        r"'stage_attempt_id',\s*'event_type',\s*'occurred_at',\s*'payload'\s*\]",
        body,
        re.I | re.S,
    )
    atomic = re.search(
        r"FUNCTION\s+carl_autonomy\.complete_command_and_append_event\(.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert atomic is not None
    assert "carl_autonomy.append_event" in atomic.group("body")


def test_reducer_timestamp_identity_uses_canonical_text_equality() -> None:
    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.validate_and_advance_event.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    body = validator.group("body")
    soak = re.search(
        r"WHEN\s+'soak_observed'\s+THEN(?P<body>.*?)WHEN\s+'revert_recorded'",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    )
    retry = re.search(
        r"WHEN\s+'retry_scheduled'\s+THEN(?P<body>.*?)ELSE",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert soak is not None
    assert retry is not None
    assert re.search(
        r"p_payload->>'observed_at'\s+IS\s+DISTINCT\s+FROM\s+p_occurred_at_text",
        soak.group("body"),
        re.I,
    )
    assert re.search(
        r"p_payload->>'scheduled_at'\s+IS\s+DISTINCT\s+FROM\s+p_occurred_at_text",
        retry.group("body"),
        re.I,
    )


def test_sql_draft_base_branch_matches_python_128_byte_bound() -> None:
    draft_shape = re.search(
        r"WHEN\s+'draft_pr_requested'\s+THEN(?P<body>.*?)"
        r"WHEN\s+'draft_pr_recorded'",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert draft_shape is not None
    assert re.search(
        r"octet_length\(p_payload->>'base_branch'\)\s+BETWEEN\s+1\s+AND\s+128",
        draft_shape.group("body"),
        re.I,
    )


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
    def __init__(self, *, database_role: str = "carl_state_backend") -> None:
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
            "register_dead_holder_observation",
            "complete_command_and_append_event",
            "register_manifest",
            "append_event",
            "create_command",
            "claim_command",
            "resolve_claimed_command",
            "prepare_effect_attempt",
            "mark_effect_uncertain",
            "mark_effect_retry_scheduled",
            "mark_effect_completed",
            "load_coordinator_snapshot",
            "apply_coordinator_decision",
            "prepare_coordinator_effect",
            "complete_coordinator_effect",
            "execute_coordinator_local_effect",
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


def _config(database: FakeDatabase, *, role: str = "carl_state_backend") -> PostgresStateConfig:
    return PostgresStateConfig(
        dsn="postgresql://protected.invalid/carl",
        database_role=role,
        authority_key=AUTHORITY_KEY,
        dead_holder_key=LIVENESS_KEY,
        clock=lambda: NOW,
        connect=database.connect,
    )


def _backend(database: FakeDatabase, *, role: str = "carl_state_backend") -> PostgresStateBackend:
    return PostgresStateBackend.from_config(_config(database, role=role))


def _canonical(value: dict[str, Any]) -> str:
    return canonical_json_bytes(value).decode("utf-8")


@pytest.mark.parametrize("workflow_role", WORKFLOW_DATABASE_ROLES)
def test_config_rejects_workflow_database_credentials(workflow_role: str) -> None:
    database = FakeDatabase(database_role=workflow_role)

    with pytest.raises(PostgresStateError, match="database_role_invalid"):
        _config(database, role=workflow_role)


def test_sql_grants_no_state_procedure_execution_to_workflow_roles() -> None:
    execute_grants = re.findall(
        r"GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+.*?\s+TO\s+([^;]+);",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    granted_roles = {
        role.strip()
        for recipients in execute_grants
        for role in recipients.replace("\n", " ").split(",")
    }

    assert granted_roles.isdisjoint(WORKFLOW_DATABASE_ROLES)


def test_sql_binds_experimental_publication_branch_to_experiment() -> None:
    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.validate_and_advance_event.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    branch = re.search(
        r"WHEN\s+'experimental_published'\s+THEN(?P<body>.*?)WHEN\s+'promotion_recorded'",
        validator.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )

    assert branch is not None
    assert re.search(
        r"p_payload->>'branch'\s+IS\s+DISTINCT\s+FROM\s+"
        r"'experimental/'\s*\|\|\s*p_experiment_id",
        branch.group("body"),
        flags=re.IGNORECASE,
    )


@pytest.mark.parametrize(("event_type", "authorities", "handler"), EVENT_POLICY_CASES)
def test_sql_event_vocabulary_authority_and_handler_parity(
    event_type: EventType, authorities: frozenset[str], handler: str
) -> None:
    schema_match = re.search(
        r"event_type\s+IN\s*\((?P<body>.*?)\)\s*\)",
        INITIAL_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    policy_match = re.search(
        r"FUNCTION\s+carl_autonomy\.event_role_allowed.*?AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    validator_match = re.search(
        r"FUNCTION\s+carl_autonomy\.validate_and_advance_event.*?AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert schema_match is not None
    assert policy_match is not None
    assert validator_match is not None

    schema_events = frozenset(re.findall(r"'([a-z_]+)'", schema_match.group("body")))
    assert schema_events == frozenset(item.value for item in EventType)

    actual_authorities = {
        authority
        for authority in ("builder", "validator", "promoter", "soak", "coordinator")
        if re.search(
            rf"WHEN\s+'carl_{authority}'\s+THEN(?:(?!WHEN\s+'carl_|ELSE).)*"
            rf"'{event_type.value}'",
            policy_match.group("body"),
            flags=re.IGNORECASE | re.DOTALL,
        )
    }
    assert actual_authorities == authorities

    handler_pattern = (
        rf"IF\s+p_event_type\s*=\s*'{event_type.value}'"
        if handler == "if"
        else rf"WHEN\s+'{event_type.value}'\s+THEN"
    )
    assert re.search(handler_pattern, validator_match.group("body"), flags=re.IGNORECASE)


def test_sql_exact_payload_key_policy_matches_canonical_event_schemas() -> None:
    policy = re.search(
        r"FUNCTION\s+carl_autonomy\.event_payload_key_policy\(\).*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert policy is not None

    actual: dict[EventType, set[frozenset[str]]] = {}
    for event_name, raw_keys in re.findall(
        r"\('([a-z_]+)'\s*,\s*ARRAY\[(.*?)\]::text\[\]\)",
        policy.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    ):
        actual.setdefault(EventType(event_name), set()).add(
            frozenset(re.findall(r"'([a-z_]+)'", raw_keys))
        )

    assert actual == {
        event_type: set(key_sets) for event_type, key_sets in EVENT_PAYLOAD_KEY_SETS.items()
    }

    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.validate_and_advance_event.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    assert re.search(
        r"IF\s+NOT\s+carl_autonomy\.event_payload_keys_exact"
        r"\(p_event_type,\s*p_payload\)\s+THEN",
        validator.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )


def test_sql_binds_experimental_publication_to_sealed_candidate_guard() -> None:
    assert re.search(r"candidate_packet_digest\s+character\(64\)", INITIAL_SQL, flags=re.IGNORECASE)
    assert re.search(r"candidate_commit\s+varchar\(64\)", INITIAL_SQL, flags=re.IGNORECASE)

    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.validate_and_advance_event.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    sealed = re.search(
        r"WHEN\s+'candidate_sealed'\s+THEN(?P<body>.*?)"
        r"WHEN\s+'paired_evidence_recorded'",
        validator.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )
    publication = re.search(
        r"WHEN\s+'experimental_published'\s+THEN(?P<body>.*?)"
        r"WHEN\s+'promotion_recorded'",
        validator.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )
    protected = re.search(
        r"WHEN\s+'protected_validation_recorded'\s+THEN(?P<body>.*?)"
        r"WHEN\s+'review_packet_recorded'",
        validator.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert sealed is not None and publication is not None and protected is not None
    assert re.search(
        r"candidate_packet_digest\s*=\s*"
        r"carl_autonomy\.candidate_payload_digest\(p_payload\)",
        sealed.group("body"),
        re.I,
    )
    assert re.search(
        r"candidate_commit\s*=\s*p_payload->>'candidate_commit'", sealed.group("body"), re.I
    )
    assert re.search(
        r"p_payload->>'candidate_packet_digest'\s+IS\s+DISTINCT\s+FROM\s+"
        r"guard\.candidate_packet_digest",
        publication.group("body"),
        re.I,
    )
    assert re.search(
        r"p_payload->>'commit'\s+IS\s+DISTINCT\s+FROM\s+guard\.candidate_commit",
        publication.group("body"),
        re.I,
    )
    assert re.search(
        r"p_payload->>'branch'\s+IS\s+DISTINCT\s+FROM\s+"
        r"'experimental/'\s*\|\|\s*p_experiment_id",
        publication.group("body"),
        re.I,
    )
    assert re.search(
        r"p_payload->>'candidate_tree'\s+IS\s+DISTINCT\s+FROM\s+"
        r"guard\.experimental_tree",
        protected.group("body"),
        re.I,
    )


def test_sql_candidate_digest_matches_hand_derived_python_known_vector() -> None:
    candidate = sealed_candidate()
    leased_payload = {
        **candidate.to_canonical_dict(),
        "_lease": {"owner_id": "director-phase3", "stage_attempt_id": "lease-phase3"},
    }

    assert candidate.digest == "278d2d94d70cd9d1e54baed3fdbe617e4a88aaee0ac93dbb5e4895cbd9bd3b54"
    assert hashlib.sha256(canonical_json_bytes(leased_payload)).hexdigest() == (
        "63451549980c44835ba0879b978e928bf7e5225887b5856e2fcc28a13839ed31"
    )
    assert candidate.digest != hashlib.sha256(canonical_json_bytes(leased_payload)).hexdigest()
    assert re.search(
        r"candidate_packet_digest\s*=\s*"
        r"carl_autonomy\.candidate_payload_digest\(p_payload\)",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE,
    )


def test_shared_sql_payload_boundary_distinguishes_worker_liveness_boolean_type() -> None:
    string_payload = json.loads(
        '{"lease_stage_attempt_id":"lease-phase3","worker_not_live":"true"}'
    )
    boolean_payload = json.loads('{"lease_stage_attempt_id":"lease-phase3","worker_not_live":true}')

    assert string_payload["worker_not_live"] == "true"
    assert boolean_payload["worker_not_live"] is True
    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.event_payload_shape_valid\(.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    assert re.search(
        r"jsonb_typeof\(p_payload->'worker_not_live'\)\s*=\s*'boolean'",
        validator.group("body"),
        flags=re.IGNORECASE,
    )
    assert re.search(
        r"p_payload->'worker_not_live'\s*=\s*'true'::jsonb",
        validator.group("body"),
        flags=re.IGNORECASE,
    )


@pytest.mark.parametrize(
    ("event_type", "required_checks"),
    (
        ("workspace_prepared", ("lease_payload_valid", "artifact_payload_valid")),
        (
            "candidate_sealed",
            ("lease_payload_valid", "artifact_payload_valid", "check_array_payload_valid"),
        ),
        ("paired_evidence_recorded", ("lease_payload_valid", "artifact_payload_valid")),
        ("review_packet_recorded", ("lease_payload_valid",)),
        ("review_attested", ("lease_payload_valid", "artifact_payload_valid")),
        ("draft_pr_requested", ("lease_payload_valid",)),
        ("draft_pr_recorded", ("lease_payload_valid",)),
        ("workspace_disposed", ("lease_payload_valid",)),
    ),
)
def test_sql_nested_payload_family_uses_exact_typed_helpers(
    event_type: str, required_checks: tuple[str, ...]
) -> None:
    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.event_payload_shape_valid\(.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    branch = re.search(
        rf"WHEN\s+'{event_type}'\s+THEN(?P<body>.*?)(?=WHEN\s+'|ELSE)",
        validator.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert branch is not None
    for helper in required_checks:
        assert f"carl_autonomy.{helper}" in branch.group("body")

    assert re.search(
        r"FUNCTION\s+carl_autonomy\.lease_payload_valid\(.*?"
        r"jsonb_typeof\(value\)\s*=\s*'object'.*?"
        r"jsonb_object_length\(value\)\s*=\s*2.*?"
        r"value\s+\?&\s+ARRAY\['owner_id',\s*'stage_attempt_id'\]",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert re.search(
        r"FUNCTION\s+carl_autonomy\.artifact_payload_valid\(.*?"
        r"jsonb_object_length\(value\)\s*=\s*5.*?"
        r"jsonb_typeof\(value->'byte_size'\)\s*=\s*'number'",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert re.search(
        r"FUNCTION\s+carl_autonomy\.check_array_payload_valid\(.*?"
        r"jsonb_typeof\(value\)\s*=\s*'array'.*?"
        r"jsonb_array_length\(value\)\s*>\s*0",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )


@pytest.mark.parametrize(("event_type", "fields"), tuple(EVENT_STRING_FIELDS.items()))
def test_sql_string_fields_check_json_type_before_text_use(
    event_type: EventType, fields: frozenset[str]
) -> None:
    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.event_payload_shape_valid\(.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    branch = re.search(
        rf"WHEN\s+'{event_type.value}'\s+THEN(?P<body>.*?)(?=WHEN\s+'|ELSE)",
        validator.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert branch is not None
    for field in fields:
        assert re.search(
            rf"jsonb_typeof\(p_payload->'{field}'\)\s*=\s*'string'",
            branch.group("body"),
            flags=re.IGNORECASE,
        ), field


@pytest.mark.parametrize(("event_type", "fields"), tuple(EVENT_INTEGER_FIELDS.items()))
def test_sql_integer_fields_reject_non_integral_json_numbers(
    event_type: EventType, fields: dict[str, tuple[int, int] | None]
) -> None:
    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.event_payload_shape_valid\(.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    branch = re.search(
        rf"WHEN\s+'{event_type.value}'\s+THEN(?P<body>.*?)(?=WHEN\s+'|ELSE)",
        validator.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert branch is not None
    for field, bounds in fields.items():
        if bounds is None:
            pattern = rf"carl_autonomy\.jsonb_positive_integer\(p_payload->'{field}'\)"
        else:
            minimum, maximum = bounds
            pattern = (
                rf"carl_autonomy\.jsonb_integer_between\("
                rf"p_payload->'{field}',\s*{minimum},\s*{maximum}\)"
            )
        assert re.search(pattern, branch.group("body"), flags=re.IGNORECASE), field


@pytest.mark.parametrize(("event_type", "fields"), tuple(EVENT_BOOLEAN_FIELDS.items()))
def test_sql_boolean_fields_require_json_booleans(
    event_type: EventType, fields: dict[str, bool | None]
) -> None:
    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.event_payload_shape_valid\(.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    branch = re.search(
        rf"WHEN\s+'{event_type.value}'\s+THEN(?P<body>.*?)(?=WHEN\s+'|ELSE)",
        validator.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert branch is not None
    for field, required in fields.items():
        assert re.search(
            rf"jsonb_typeof\(p_payload->'{field}'\)\s*=\s*'boolean'",
            branch.group("body"),
            flags=re.IGNORECASE,
        ), field
        if required is not None:
            literal = str(required).lower()
            assert re.search(
                rf"p_payload->'{field}'\s*=\s*'{literal}'::jsonb",
                branch.group("body"),
                flags=re.IGNORECASE,
            ), field


def test_valid_draft_url_validation_does_not_construct_postgres_nul_text() -> None:
    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.event_payload_shape_valid\(.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    draft = re.search(
        r"WHEN\s+'draft_pr_requested'\s+THEN(?P<body>.*?)(?=WHEN\s+')",
        validator.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert draft is not None
    assert "chr(0)" not in draft.group("body").lower()


def test_sql_role_handler_preserves_candidate_hard_finding_verdict() -> None:
    validator = re.search(
        r"FUNCTION\s+carl_autonomy\.validate_and_advance_event.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert validator is not None
    role = re.search(
        r"IF\s+p_event_type\s*=\s*'role_recorded'\s+THEN(?P<body>.*?)RETURN;",
        validator.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert role is not None
    assert not re.search(
        r"verdict_name\s+NOT\s+IN\s*\('approve',\s*'reject',\s*'hard_objection'\)",
        role.group("body"),
        flags=re.IGNORECASE,
    )


def test_soak_transition_authorization_checks_json_string_types() -> None:
    policy = re.search(
        r"FUNCTION\s+carl_autonomy\.event_role_allowed.*?"
        r"AS\s+\$\$(?P<body>.*?)\$\$;",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert policy is not None
    soak = re.search(
        r"WHEN\s+'carl_soak'\s+THEN(?P<body>.*?)(?=WHEN\s+'carl_|ELSE)",
        policy.group("body"),
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert soak is not None
    for field in ("from_state", "to_state"):
        assert re.search(
            rf"jsonb_typeof\(payload->'{field}'\)\s*=\s*'string'",
            soak.group("body"),
            flags=re.IGNORECASE,
        )


def test_sql_enforces_retry_first_attempt_and_monotonic_sequence() -> None:
    assert re.search(
        r"retry_state\s+jsonb\s+NOT\s+NULL\s+DEFAULT\s+'\{\}'::jsonb",
        INITIAL_SQL,
        flags=re.IGNORECASE,
    )
    retry = re.search(
        r"WHEN\s+'retry_scheduled'\s+THEN(?P<body>.*?)ELSE\s+RAISE",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert retry is not None
    body = retry.group("body")
    assert re.search(r"prior_retry\s*:=\s*guard\.retry_state\s*->", body, re.I)
    assert re.search(r"prior_retry\s+IS\s+NULL.*?attempt.*?<>\s*1", body, re.I | re.S)
    assert re.search(
        r"prior_retry\s+IS\s+NOT\s+NULL.*?attempt.*?<>.*?prior_retry.*?attempt.*?\+\s*1",
        body,
        re.I | re.S,
    )
    assert re.search(
        r"changed_action.*?IS\s+NOT\s+DISTINCT\s+FROM.*?prior_retry", body, re.I | re.S
    )
    assert re.search(r"scheduled_at.*?IS\s+DISTINCT\s+FROM\s+p_occurred_at_text", body, re.I | re.S)


def test_sql_rejects_duplicate_revert_and_records_terminal_identity() -> None:
    assert re.search(
        r"revert_recorded\s+boolean\s+NOT\s+NULL\s+DEFAULT\s+false",
        INITIAL_SQL,
        flags=re.IGNORECASE,
    )
    revert = re.search(
        r"WHEN\s+'revert_recorded'\s+THEN(?P<body>.*?)"
        r"WHEN\s+'lease_reconciled'",
        ROLE_PROCEDURES_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )
    assert revert is not None
    body = revert.group("body")
    assert re.search(r"guard\.revert_recorded", body, re.I)
    assert re.search(
        r"guard\.soak_failures\s*->>\s*\(p_payload->>'hard_failure_digest'\)"
        r".*?guard\.promotion_merge_commit",
        body,
        re.I | re.S,
    )
    assert re.search(r"merge_commit.*?guard\.promotion_merge_commit", body, re.I | re.S)
    assert re.search(r"SET\s+revert_recorded\s*=\s*true", body, re.I | re.S)


@pytest.mark.parametrize(
    "column",
    (
        "candidate_commit",
        "experimental_commit",
        "experimental_tree",
        "promotion_merge_commit",
        "promotion_merge_tree",
    ),
)
def test_projection_guard_git_object_columns_accept_sha1_and_sha256(column: str) -> None:
    assert re.search(rf"{column}\s+varchar\(64\)", INITIAL_SQL, flags=re.IGNORECASE)
    assert re.search(
        rf"{column}\s+IS\s+NULL\s+OR\s+{column}\s+~\s+"
        r"'\^\(\[0-9a-f\]\{40\}\|\[0-9a-f\]\{64\}\)\$'",
        INITIAL_SQL,
        flags=re.IGNORECASE | re.DOTALL,
    )


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


def _effect_attempt() -> GitHubEffectAttempt:
    command = _command()
    claim = _claim()
    return GitHubEffectAttempt(
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
        observed_at=NOW_TEXT,
    )


def test_postgres_adapter_resolves_durable_claim_and_atomically_prepares_effect_fence() -> None:
    database = FakeDatabase()
    database.responses["resolve_claimed_command"] = [
        _command_row(applied=False, status="claimed", revision=8)
    ]
    database.responses["prepare_effect_attempt"] = [{"applied": True}]
    backend = _backend(database)
    attempt = _effect_attempt()

    state = backend.resolve_claimed_command(
        attempt.command_key,
        authority=attempt.authority,
        observed_at=NOW,
    )
    prepared = backend.prepare_effect_attempt(attempt)

    assert state.status == "claimed"
    assert state.command.effect_key == attempt.effect_key
    assert prepared is True
    assert any("carl_autonomy.resolve_claimed_command" in query for query, _ in database.calls)
    assert any("carl_autonomy.prepare_effect_attempt" in query for query, _ in database.calls)


def test_postgres_adapter_persists_effect_rate_limit_retry_deadline() -> None:
    database = FakeDatabase()
    database.responses["mark_effect_retry_scheduled"] = [{"applied": True}]
    backend = _backend(database)
    attempt = _effect_attempt()

    backend.mark_effect_retry_scheduled(
        attempt.effect_key,
        authority=attempt.authority,
        retry_not_before="2026-08-20T12:02:00Z",
        observed_at="2026-08-20T12:00:01Z",
    )

    query, parameters = next(
        (query, parameters)
        for query, parameters in database.calls
        if "carl_autonomy.mark_effect_retry_scheduled" in query
    )
    assert query.startswith("SELECT * FROM")
    assert parameters[:3] == (
        attempt.effect_key,
        "2026-08-20T12:02:00Z",
        "2026-08-20T12:00:01Z",
    )


def test_postgres_adapter_completion_binds_exact_live_claim_identity() -> None:
    database = FakeDatabase()
    database.responses["mark_effect_completed"] = [{"applied": True}]
    backend = _backend(database)
    attempt = _effect_attempt()

    backend.mark_effect_completed(
        attempt.effect_key,
        command_key=attempt.command_key,
        claim_id=attempt.claim_id,
        command_revision=attempt.command_revision,
        claim_expected_revision=attempt.claim_expected_revision,
        claim_expires_at=attempt.claim_expires_at,
        authority=attempt.authority,
        result_digest="d" * 64,
        observed_at="2026-08-20T12:00:02Z",
    )

    query, parameters = next(
        (query, parameters)
        for query, parameters in database.calls
        if "carl_autonomy.mark_effect_completed" in query
    )
    assert query.startswith("SELECT * FROM")
    assert parameters[:-1] == (
        attempt.effect_key,
        attempt.command_key,
        attempt.claim_id,
        attempt.command_revision,
        attempt.claim_expected_revision,
        attempt.claim_expires_at,
        "d" * 64,
        "2026-08-20T12:00:02Z",
    )


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


def _dead_holder(
    *,
    scope_kind: str = "command",
    scope_key: str = "dispatch-exp-001",
    subject_id: str = "claim-exp-001",
    revision: int = 8,
) -> DeadHolderObservation:
    unsigned = DeadHolderObservation(
        schema_version=1,
        authority="coordinator",
        subject_id=subject_id,
        scope_kind=scope_kind,
        scope_key=scope_key,
        revision=revision,
        issued_at="2026-08-20T11:55:00Z",
        observed_at=NOW_TEXT,
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


def test_adapter_rejects_forged_observation_before_registration_sql() -> None:
    database = FakeDatabase()
    backend = _backend(database)
    observation = _dead_holder()
    forged = replace(observation, signature_base64=base64.b64encode(bytes(64)).decode("ascii"))
    capability = _capability(
        action="register_dead_holder_observation",
        authority="observer",
        subject_id=observation.digest,
        scope_kind="dead_holder_observation",
        scope_key=observation.digest,
        revision=observation.revision,
    )
    capability = replace(
        capability,
        subject_id=forged.digest,
        scope_key=forged.digest,
        signature_base64=base64.b64encode(bytes(64)).decode("ascii"),
    )
    capability = replace(
        capability,
        signature_base64=base64.b64encode(
            AUTHORITY_PRIVATE.sign(capability.signing_payload())
        ).decode("ascii"),
    )

    with pytest.raises(ValueError, match="trusted_authority_signature_invalid"):
        backend.register_dead_holder_observation(forged, capability=capability)

    assert database.calls == []


def test_observation_registration_and_reconciliation_bind_digest_only() -> None:
    database = FakeDatabase()
    database.responses["register_dead_holder_observation"] = [{"applied": True}]
    backend = _backend(database)
    observation = _dead_holder()

    assert backend._register_dead_holder_observation(observation, observed_at=NOW) is True
    query, parameters = next(
        call for call in database.calls if "register_dead_holder_observation" in call[0]
    )
    assert "%s" in query
    assert parameters == (
        _canonical(observation.to_canonical_dict()),
        observation.digest,
        NOW,
    )

    coordinator_db = FakeDatabase()
    coordinator_db.responses["reconcile_expired_claim"] = [
        _command_row(status="pending", revision=9)
    ]
    reconciliation = ClaimReconciliation(
        command_key="dispatch-exp-001",
        claim_id="claim-exp-001",
        authority="coordinator",
        expected_revision=8,
        next_revision=9,
        observed_at=NOW_TEXT,
    )
    _backend(coordinator_db)._reconcile_expired_claim(
        reconciliation,
        observation_digest=observation.digest,
        observed_at=NOW,
    )
    _query, reconcile_parameters = next(
        call for call in coordinator_db.calls if "reconcile_expired_claim" in call[0]
    )
    assert reconcile_parameters == (
        _canonical(reconciliation.to_canonical_dict()),
        observation.digest,
        NOW,
    )


def test_atomic_completion_uses_one_combined_procedure_transaction() -> None:
    database = FakeDatabase()
    event = ExperimentEvent.create(
        experiment_id=sample_manifest().experiment_id,
        stage_attempt_id="atomic-retry-001",
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at=NOW_TEXT,
        payload={"attempt": 1},
    )
    database.responses["complete_command_and_append_event"] = [
        {
            **_command_row(status="completed", revision=9),
            "appended": True,
            "chain_digest": DIGEST_A,
            "event_digest": event.digest,
            "ordinal": 1,
        }
    ]

    command_result, append_result = _backend(database)._complete_command_with_event(
        _transition(), event, observed_at=NOW
    )

    assert command_result.state.status == "completed"
    assert append_result.event_digest == event.digest
    mutation_calls = [call for call in database.calls if "FROM carl_autonomy." in call[0]]
    assert len(mutation_calls) == 1
    assert "complete_command_and_append_event" in mutation_calls[0][0]
    assert database.transactions_started == database.transactions_committed == 1


def test_backend_constructs_and_owns_verifier_from_protected_config() -> None:
    database = FakeDatabase()
    backend = _backend(database)

    assert backend.verifier is not None
    with pytest.raises(AttributeError, match="immutable"):
        backend.verifier = None  # type: ignore[misc]
    with pytest.raises(PostgresStateError, match="postgres_config_invalid"):
        PostgresStateBackend.from_config(replace(_config(database), clock=None))  # type: ignore[arg-type]


def test_public_authorization_fails_before_opening_database_connection() -> None:
    database = FakeDatabase()
    backend = _backend(database)
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


def test_public_append_rejects_capability_from_wrong_event_authority_before_sql() -> None:
    database = FakeDatabase()
    backend = _backend(database)
    event = ExperimentEvent.create(
        experiment_id=sample_manifest().experiment_id,
        stage_attempt_id="wrong-authority-retry",
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at=NOW_TEXT,
        payload={
            "attempt": 1,
            "changed_action": "retry with state isolation",
            "failed_stage_attempt_id": "failed-stage-001",
            "failure_class": "infrastructure",
            "scheduled_at": NOW_TEXT,
        },
    )
    capability = _capability(
        action="append_event",
        authority="builder",
        subject_id=event.stage_attempt_id,
        scope_kind="event",
        scope_key=event.experiment_id,
        revision=0,
    )

    with pytest.raises(ValueError, match="event_authority_denied"):
        backend.append_event(event, capability=capability)

    assert database.calls == []


def test_register_manifest_binds_values_and_commits_one_transaction() -> None:
    database = FakeDatabase()
    database.responses["register_manifest"] = [{"applied": True}]
    backend = _backend(database)
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
    database = FakeDatabase()
    database.responses["register_manifest"] = [{"applied": True}]

    _backend(database)._register_manifest(sample_manifest(), observed_at=NOW)

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
    dead_holder = _dead_holder()
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
            "register_dead_holder_observation": [{"applied": True}],
            "create_command": [_command_row()],
            "claim_command": [_command_row(status="claimed", revision=8)],
            "complete_command_and_append_event": [
                {
                    **_command_row(status="completed", revision=9),
                    "appended": True,
                    "chain_digest": DIGEST_B,
                    "event_digest": event.digest,
                    "ordinal": 1,
                }
            ],
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
        (
            "register_dead_holder_observation",
            lambda: backend._register_dead_holder_observation(dead_holder, observed_at=NOW),
        ),
        ("create_command", lambda: backend._create_command(command, observed_at=NOW)),
        ("claim_command", lambda: backend._claim_command(claim, observed_at=NOW)),
        (
            "complete_command_and_append_event",
            lambda: backend._complete_command_with_event(completed, event, observed_at=NOW),
        ),
        ("fail_command", lambda: backend._fail_command(failed, observed_at=NOW)),
        (
            "reconcile_expired_claim",
            lambda: backend._reconcile_expired_claim(
                reconciliation, observation_digest=dead_holder.digest, observed_at=NOW
            ),
        ),
        ("acquire_lease", lambda: backend._acquire_lease(desired_lease, observed_at=NOW)),
        (
            "reconcile_lease",
            lambda: backend._reconcile_lease(
                lease_reconciliation, observation_digest=dead_holder.digest, observed_at=NOW
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
    backend = _backend(database)

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
            "trusted_authority": False,
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


def _coordinator_state():
    return replace(
        coordinator_snapshot(
            coordinator_node(),
            current_lease=coordinator_lease(),
        ),
        observed_at=NOW_TEXT,
    )


def _github_effect_request() -> tuple[object, GitHubEffectRequest]:
    run = CloudRunRequest.create(
        repository="StephenBickel/carl-agent",
        workflow_file="autonomous-improvement.yml",
        workflow_revision="3" * 40,
        workflow_blob_digest="e" * 64,
        parent_commit="4" * 40,
        candidate_commit="2" * 40,
        experiment_digest="a" * 64,
        task_set_digest="b" * 64,
        metric_pack_digest="c" * 64,
        policy_digest="d" * 64,
    )
    binding = workflow_dispatch_binding(run, attempt=1)
    selected = coordinator_node(
        command_key=binding.command_key,
        request_digest=binding.request_digest,
    )
    remote_state = replace(
        _coordinator_state(),
        nodes=(selected,),
        command=coordinator_claimed_command(selected),
    )
    decision = choose_next_action(remote_state)
    assert decision.command is not None
    request = GitHubEffectRequest.from_canonical_dict(
        {
            "command_key": binding.command_key,
            "domain": REQUEST_DOMAIN,
            "effect_key": decision.command.effect_key,
            "occurred_at": decision.command.occurred_at,
            "operation": "dispatch_workflow",
            "parameters": {
                name: getattr(run, name)
                for name in (
                    "candidate_commit",
                    "experiment_digest",
                    "metric_pack_digest",
                    "parent_commit",
                    "policy_digest",
                    "repository",
                    "task_set_digest",
                    "workflow_blob_digest",
                    "workflow_file",
                    "workflow_revision",
                )
            },
            "request_key": binding.request_key,
            "schema_version": 1,
        }
    )
    return decision, request


def test_postgres_coordinator_operations_decode_exact_durable_results() -> None:
    database = FakeDatabase()
    state = _coordinator_state()
    decision = choose_next_action(state)
    remote_decision, request = _github_effect_request()
    response = GitHubEffectResponse(
        schema_version=1,
        domain=RESPONSE_DOMAIN,
        status="rejected",
        request_digest=request.digest,
        observed_at=NOW_TEXT,
        result=None,
        retry_not_before=None,
        error_code="github_command_not_found",
    )
    database.responses.update(
        {
            "load_coordinator_snapshot": [
                {
                    "production_receipts_json": None,
                    "snapshot_json": _canonical(state.to_canonical_dict()),
                }
            ],
            "apply_coordinator_decision": [
                {
                    "applied": True,
                    "decision_json": _canonical(decision.to_canonical_dict()),
                }
            ],
            "prepare_coordinator_effect": [
                {
                    "effect_family": "github",
                    "request_json": _canonical(request.to_canonical_dict()),
                }
            ],
            "complete_coordinator_effect": [
                {
                    "applied": True,
                    "decision_json": _canonical(remote_decision.to_canonical_dict()),
                }
            ],
        }
    )
    backend = _backend(database)

    rebuilt, receipts = backend.reconstruct_coordinator_snapshot("coordinate", observed_at=NOW)
    applied = backend.apply_coordinator_decision(decision, observed_at=NOW)

    class Client:
        def execute(self, actual):
            assert actual == request
            return response

    completed = backend.execute_github_coordinator_effect(
        remote_decision, github=Client(), observed_at=NOW
    )

    assert rebuilt == state
    assert receipts is None
    assert applied == decision
    assert completed == remote_decision
    assert database.transactions_started == 4
    assert database.transactions_committed == 4


def test_postgres_coordinator_prepares_and_completes_exact_typed_family() -> None:
    observed_at = datetime(2026, 8, 22, 12, tzinfo=UTC)
    selected = coordinator_node("observe_builder")
    decision = choose_next_action(
        coordinator_snapshot(
            selected,
            current_lease=coordinator_lease(),
            command=coordinator_claimed_command(selected),
        )
    )
    request = CoordinatorNodeEffectRequest.from_decision(decision)
    response = CoordinatorNodeEffectResponse.completed(
        request=request,
        result_digest=DIGEST_B,
        observed_at="2026-08-22T12:00:00Z",
    )
    database = FakeDatabase()
    database.responses.update(
        {
            "prepare_coordinator_effect": [
                {
                    "effect_family": "observer",
                    "request_json": _canonical(request.to_canonical_dict()),
                }
            ],
            "complete_coordinator_effect": [
                {
                    "applied": True,
                    "decision_json": _canonical(decision.to_canonical_dict()),
                }
            ],
        }
    )
    backend = _backend(database)

    prepared = backend.prepare_coordinator_effect(
        decision, expected_family="observer", observed_at=observed_at
    )
    completed = backend.complete_coordinator_effect(decision, response, observed_at=observed_at)

    assert prepared == PreparedCoordinatorEffect("observer", request)
    assert completed == decision
    assert database.transactions_started == 2
    assert database.transactions_committed == 2


@pytest.mark.parametrize(
    ("kind", "family"),
    [("register_hypothesis", "state"), ("trigger_supervisor", "supervisor")],
)
def test_postgres_coordinator_executes_local_family_atomically(kind: str, family: str) -> None:
    observed_at = datetime(2026, 8, 22, 12, tzinfo=UTC)
    selected = coordinator_node(kind)
    decision = choose_next_action(
        coordinator_snapshot(
            selected,
            current_lease=coordinator_lease(),
            command=coordinator_claimed_command(selected),
        )
    )
    database = FakeDatabase()
    database.responses["execute_coordinator_local_effect"] = [
        {
            "applied": True,
            "decision_json": _canonical(decision.to_canonical_dict()),
        }
    ]

    completed = _backend(database).execute_local_coordinator_effect(
        decision, family=family, observed_at=observed_at
    )

    assert completed == decision
    assert database.transactions_started == 1
    assert database.transactions_committed == 1


def test_postgres_coordinator_empty_queue_is_not_a_failure_or_mutation() -> None:
    database = FakeDatabase()
    database.responses["load_coordinator_snapshot"] = [
        {"production_receipts_json": None, "snapshot_json": None}
    ]

    result = _backend(database).reconstruct_coordinator_snapshot("observe", observed_at=NOW)

    assert result is None
    assert database.transactions_started == 1
    assert database.transactions_committed == 1
