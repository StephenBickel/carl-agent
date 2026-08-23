from __future__ import annotations

from typing import Any

from carl_bench.experiment import EventType

EVENT_PAYLOAD_KEY_SETS: dict[EventType, tuple[frozenset[str], ...]] = {
    EventType.STATE_TRANSITIONED: (
        frozenset({"from_state", "to_state"}),
        frozenset({"_lease", "from_state", "to_state"}),
    ),
    EventType.ROLE_RECORDED: (
        frozenset({"artifact_digest", "role", "verdict"}),
        frozenset({"_lease", "artifact_digest", "role", "verdict"}),
    ),
    EventType.LEASE_ACQUIRED: (frozenset({"expires_at", "owner_id"}),),
    EventType.LEASE_RECONCILED: (frozenset({"lease_stage_attempt_id", "worker_not_live"}),),
    EventType.LEASE_RELEASED: (frozenset({"lease_stage_attempt_id"}),),
    EventType.LIVE_SPEND_RECORDED: (frozenset({"live_microdollars", "run_id"}),),
    EventType.WORKSPACE_PREPARED: (
        frozenset(
            {
                "_lease",
                "branch",
                "experiment_id",
                "manifest_digest",
                "parent_commit",
                "request_artifact",
                "schema_version",
            }
        ),
    ),
    EventType.CANDIDATE_SEALED: (
        frozenset(
            {
                "_lease",
                "branch",
                "candidate_commit",
                "changed_path_count",
                "changed_paths_artifact",
                "checks",
                "diff_artifact",
                "experiment_id",
                "manifest_digest",
                "parent_commit",
                "report_artifact",
                "schema_version",
            }
        ),
    ),
    EventType.PAIRED_EVIDENCE_RECORDED: (
        frozenset(
            {
                "_lease",
                "baseline_scorecard_digest",
                "candidate_commit",
                "candidate_scorecard_digest",
                "comparison_artifact",
                "confidence_lower_basis_points",
                "decision",
                "experiment_id",
                "manifest_digest",
                "paired_trials",
                "parent_commit",
                "pass_rate_delta_basis_points",
                "schema_version",
            }
        ),
    ),
    EventType.REVIEW_PACKET_RECORDED: (
        frozenset(
            {
                "_lease",
                "candidate_commit",
                "deterministic_evidence_digest",
                "diff_digest",
                "experiment_id",
                "manifest_digest",
                "paired_evidence_digest",
                "review_contract_version",
                "role",
                "schema_version",
            }
        ),
    ),
    EventType.REVIEW_ATTESTED: (
        frozenset(
            {
                "_lease",
                "candidate_commit",
                "context_id",
                "experiment_id",
                "manifest_digest",
                "packet_digest",
                "report_artifact",
                "reviewer_id",
                "role",
                "schema_version",
                "verdict",
            }
        ),
    ),
    EventType.DRAFT_PR_REQUESTED: (
        frozenset(
            {
                "_lease",
                "base_branch",
                "candidate_commit",
                "expected_remote_url",
                "head_branch",
                "repository",
            }
        ),
    ),
    EventType.DRAFT_PR_RECORDED: (
        frozenset(
            {
                "_lease",
                "base_branch",
                "candidate_commit",
                "head_branch",
                "is_draft",
                "number",
                "repository",
                "schema_version",
                "state",
                "url",
            }
        ),
    ),
    EventType.WORKSPACE_DISPOSED: (frozenset({"_lease", "branch", "candidate_commit"}),),
    EventType.RETRY_SCHEDULED: (
        frozenset(
            {
                "attempt",
                "changed_action",
                "failed_stage_attempt_id",
                "failure_class",
                "scheduled_at",
            }
        ),
    ),
    EventType.COORDINATOR_NODE_COMPLETED: (
        frozenset(
            {"command_key", "effect_key", "node_kind", "request_digest", "result_digest"}
        ),
    ),
    EventType.EXPERIMENTAL_PUBLISHED: (
        frozenset({"branch", "candidate_packet_digest", "commit", "tree"}),
    ),
    EventType.PROTECTED_VALIDATION_RECORDED: (
        frozenset({"candidate_commit", "candidate_tree", "receipt_digest"}),
    ),
    EventType.PROMOTION_RECORDED: (frozenset({"merge_commit", "merge_tree"}),),
    EventType.SOAK_OBSERVED: (
        frozenset({"evidence_digest", "healthy", "merge_commit", "observed_at"}),
    ),
    EventType.REVERT_RECORDED: (
        frozenset(
            {
                "hard_failure_digest",
                "merge_commit",
                "restored_tree",
                "revert_candidate_commit",
                "revert_merge_commit",
                "revert_pull_request_number",
            }
        ),
    ),
}

EVENT_STRING_FIELDS: dict[EventType, frozenset[str]] = {
    EventType.STATE_TRANSITIONED: frozenset({"from_state", "to_state"}),
    EventType.ROLE_RECORDED: frozenset({"artifact_digest", "role", "verdict"}),
    EventType.LEASE_ACQUIRED: frozenset({"expires_at", "owner_id"}),
    EventType.LEASE_RECONCILED: frozenset({"lease_stage_attempt_id"}),
    EventType.LEASE_RELEASED: frozenset({"lease_stage_attempt_id"}),
    EventType.LIVE_SPEND_RECORDED: frozenset({"run_id"}),
    EventType.WORKSPACE_PREPARED: frozenset(
        {"branch", "experiment_id", "manifest_digest", "parent_commit"}
    ),
    EventType.CANDIDATE_SEALED: frozenset(
        {"branch", "candidate_commit", "experiment_id", "manifest_digest", "parent_commit"}
    ),
    EventType.PAIRED_EVIDENCE_RECORDED: frozenset(
        {
            "baseline_scorecard_digest",
            "candidate_commit",
            "candidate_scorecard_digest",
            "decision",
            "experiment_id",
            "manifest_digest",
            "parent_commit",
        }
    ),
    EventType.REVIEW_PACKET_RECORDED: frozenset(
        {
            "candidate_commit",
            "deterministic_evidence_digest",
            "diff_digest",
            "experiment_id",
            "manifest_digest",
            "paired_evidence_digest",
            "review_contract_version",
            "role",
        }
    ),
    EventType.REVIEW_ATTESTED: frozenset(
        {
            "candidate_commit",
            "context_id",
            "experiment_id",
            "manifest_digest",
            "packet_digest",
            "reviewer_id",
            "role",
            "verdict",
        }
    ),
    EventType.DRAFT_PR_REQUESTED: frozenset(
        {"base_branch", "candidate_commit", "expected_remote_url", "head_branch", "repository"}
    ),
    EventType.DRAFT_PR_RECORDED: frozenset(
        {"base_branch", "candidate_commit", "head_branch", "repository", "state", "url"}
    ),
    EventType.WORKSPACE_DISPOSED: frozenset({"branch", "candidate_commit"}),
    EventType.RETRY_SCHEDULED: frozenset(
        {"changed_action", "failed_stage_attempt_id", "failure_class", "scheduled_at"}
    ),
    EventType.COORDINATOR_NODE_COMPLETED: frozenset(
        {"command_key", "effect_key", "node_kind", "request_digest", "result_digest"}
    ),
    EventType.EXPERIMENTAL_PUBLISHED: frozenset(
        {"branch", "candidate_packet_digest", "commit", "tree"}
    ),
    EventType.PROTECTED_VALIDATION_RECORDED: frozenset(
        {"candidate_commit", "candidate_tree", "receipt_digest"}
    ),
    EventType.PROMOTION_RECORDED: frozenset({"merge_commit", "merge_tree"}),
    EventType.SOAK_OBSERVED: frozenset({"evidence_digest", "merge_commit", "observed_at"}),
    EventType.REVERT_RECORDED: frozenset(
        {
            "hard_failure_digest",
            "merge_commit",
            "restored_tree",
            "revert_candidate_commit",
            "revert_merge_commit",
        }
    ),
}

EVENT_INTEGER_FIELDS: dict[EventType, dict[str, tuple[int, int] | None]] = {
    EventType.STATE_TRANSITIONED: {},
    EventType.ROLE_RECORDED: {},
    EventType.LEASE_ACQUIRED: {},
    EventType.LEASE_RECONCILED: {},
    EventType.LEASE_RELEASED: {},
    EventType.LIVE_SPEND_RECORDED: {"live_microdollars": (1, 1_000_000_000)},
    EventType.WORKSPACE_PREPARED: {"schema_version": (1, 1)},
    EventType.CANDIDATE_SEALED: {
        "changed_path_count": (1, 4_096),
        "schema_version": (1, 1),
    },
    EventType.PAIRED_EVIDENCE_RECORDED: {
        "confidence_lower_basis_points": (-10_000, 10_000),
        "paired_trials": (0, 1_000_000),
        "pass_rate_delta_basis_points": (-10_000, 10_000),
        "schema_version": (1, 1),
    },
    EventType.REVIEW_PACKET_RECORDED: {"schema_version": (1, 1)},
    EventType.REVIEW_ATTESTED: {"schema_version": (1, 1)},
    EventType.DRAFT_PR_REQUESTED: {},
    EventType.DRAFT_PR_RECORDED: {"number": None, "schema_version": (1, 1)},
    EventType.WORKSPACE_DISPOSED: {},
    EventType.RETRY_SCHEDULED: {"attempt": (1, 3)},
    EventType.COORDINATOR_NODE_COMPLETED: {},
    EventType.EXPERIMENTAL_PUBLISHED: {},
    EventType.PROTECTED_VALIDATION_RECORDED: {},
    EventType.PROMOTION_RECORDED: {},
    EventType.SOAK_OBSERVED: {},
    EventType.REVERT_RECORDED: {"revert_pull_request_number": None},
}

EVENT_BOOLEAN_FIELDS: dict[EventType, dict[str, bool | None]] = {
    EventType.STATE_TRANSITIONED: {},
    EventType.ROLE_RECORDED: {},
    EventType.LEASE_ACQUIRED: {},
    EventType.LEASE_RECONCILED: {"worker_not_live": True},
    EventType.LEASE_RELEASED: {},
    EventType.LIVE_SPEND_RECORDED: {},
    EventType.WORKSPACE_PREPARED: {},
    EventType.CANDIDATE_SEALED: {},
    EventType.PAIRED_EVIDENCE_RECORDED: {},
    EventType.REVIEW_PACKET_RECORDED: {},
    EventType.REVIEW_ATTESTED: {},
    EventType.DRAFT_PR_REQUESTED: {},
    EventType.DRAFT_PR_RECORDED: {"is_draft": True},
    EventType.WORKSPACE_DISPOSED: {},
    EventType.RETRY_SCHEDULED: {},
    EventType.COORDINATOR_NODE_COMPLETED: {},
    EventType.EXPERIMENTAL_PUBLISHED: {},
    EventType.PROTECTED_VALIDATION_RECORDED: {},
    EventType.PROMOTION_RECORDED: {},
    EventType.SOAK_OBSERVED: {"healthy": None},
    EventType.REVERT_RECORDED: {},
}

EVENT_REDUCER_BINDINGS: dict[EventType, frozenset[str]] = {
    EventType.STATE_TRANSITIONED: frozenset({"from_state", "to_state", "_lease"}),
    EventType.ROLE_RECORDED: frozenset({"role", "_lease"}),
    EventType.LEASE_ACQUIRED: frozenset(),
    EventType.LEASE_RECONCILED: frozenset({"lease_stage_attempt_id"}),
    EventType.LEASE_RELEASED: frozenset({"lease_stage_attempt_id"}),
    EventType.LIVE_SPEND_RECORDED: frozenset(),
    EventType.WORKSPACE_PREPARED: frozenset({"experiment_id", "manifest_digest", "parent_commit"}),
    EventType.CANDIDATE_SEALED: frozenset(
        {"branch", "checks", "experiment_id", "manifest_digest", "parent_commit"}
    ),
    EventType.PAIRED_EVIDENCE_RECORDED: frozenset(
        {"candidate_commit", "experiment_id", "manifest_digest", "parent_commit"}
    ),
    EventType.REVIEW_PACKET_RECORDED: frozenset(
        {
            "candidate_commit",
            "deterministic_evidence_digest",
            "diff_digest",
            "experiment_id",
            "manifest_digest",
            "paired_evidence_digest",
            "role",
        }
    ),
    EventType.REVIEW_ATTESTED: frozenset(
        {
            "candidate_commit",
            "context_id",
            "experiment_id",
            "manifest_digest",
            "packet_digest",
            "reviewer_id",
            "role",
            "verdict",
        }
    ),
    EventType.DRAFT_PR_REQUESTED: frozenset(
        {"base_branch", "candidate_commit", "head_branch", "review_attestation_quorum"}
    ),
    EventType.DRAFT_PR_RECORDED: frozenset(
        {"base_branch", "candidate_commit", "head_branch", "repository"}
    ),
    EventType.WORKSPACE_DISPOSED: frozenset({"branch", "candidate_commit"}),
    EventType.RETRY_SCHEDULED: frozenset(
        {"attempt", "changed_action", "failed_stage_attempt_id", "scheduled_at"}
    ),
    EventType.COORDINATOR_NODE_COMPLETED: frozenset(),
    EventType.EXPERIMENTAL_PUBLISHED: frozenset({"branch", "candidate_packet_digest", "commit"}),
    EventType.PROTECTED_VALIDATION_RECORDED: frozenset({"candidate_commit", "candidate_tree"}),
    EventType.PROMOTION_RECORDED: frozenset({"protected_validation"}),
    EventType.SOAK_OBSERVED: frozenset({"merge_commit", "observed_at"}),
    EventType.REVERT_RECORDED: frozenset({"hard_failure_digest", "merge_commit"}),
}

INVALID_EVENT_PAYLOAD_TYPES: tuple[tuple[EventType, tuple[str | int, ...], Any], ...] = (
    (EventType.STATE_TRANSITIONED, ("from_state",), True),
    (EventType.STATE_TRANSITIONED, ("_lease",), None),
    (EventType.ROLE_RECORDED, ("artifact_digest",), 1),
    (EventType.LEASE_ACQUIRED, ("owner_id",), []),
    (EventType.LEASE_RECONCILED, ("worker_not_live",), "true"),
    (EventType.LEASE_RELEASED, ("lease_stage_attempt_id",), 1),
    (EventType.LIVE_SPEND_RECORDED, ("live_microdollars",), 1.5),
    (EventType.WORKSPACE_PREPARED, ("_lease", "unexpected"), True),
    (EventType.CANDIDATE_SEALED, ("checks",), {}),
    (EventType.CANDIDATE_SEALED, ("checks", 0, "exit_code"), None),
    (EventType.CANDIDATE_SEALED, ("checks", 0), "not-an-object"),
    (EventType.CANDIDATE_SEALED, ("diff_artifact", "byte_size"), True),
    (EventType.PAIRED_EVIDENCE_RECORDED, ("comparison_artifact",), None),
    (EventType.REVIEW_PACKET_RECORDED, ("role",), []),
    (EventType.REVIEW_ATTESTED, ("report_artifact", "unexpected"), True),
    (EventType.DRAFT_PR_REQUESTED, ("expected_remote_url",), False),
    (EventType.DRAFT_PR_RECORDED, ("is_draft",), "true"),
    (EventType.WORKSPACE_DISPOSED, ("candidate_commit",), {}),
    (EventType.RETRY_SCHEDULED, ("attempt",), 1.5),
    (EventType.COORDINATOR_NODE_COMPLETED, ("effect_key",), False),
    (EventType.EXPERIMENTAL_PUBLISHED, ("candidate_packet_digest",), 1),
    (EventType.PROTECTED_VALIDATION_RECORDED, ("candidate_tree",), False),
    (EventType.PROMOTION_RECORDED, ("merge_tree",), []),
    (EventType.SOAK_OBSERVED, ("healthy",), "true"),
    (EventType.REVERT_RECORDED, ("revert_pull_request_number",), 1.5),
)
