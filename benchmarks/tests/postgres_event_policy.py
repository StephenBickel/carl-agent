from __future__ import annotations

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
