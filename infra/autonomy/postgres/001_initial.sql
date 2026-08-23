BEGIN;

CREATE SCHEMA IF NOT EXISTS carl_autonomy;
REVOKE ALL ON SCHEMA carl_autonomy FROM PUBLIC;

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA carl_autonomy;

CREATE TABLE carl_autonomy.experiment_manifests (
    experiment_id varchar(128) PRIMARY KEY,
    parent_experiment_id varchar(128) REFERENCES carl_autonomy.experiment_manifests(experiment_id),
    manifest_json text NOT NULL CHECK (octet_length(manifest_json) BETWEEN 2 AND 131072),
    manifest_digest character(64) NOT NULL UNIQUE CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    registered_at timestamptz NOT NULL,
    registered_at_text varchar(64) NOT NULL,
    recorded_at timestamptz NOT NULL,
    CHECK (experiment_id ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'),
    CHECK (parent_experiment_id IS NULL OR parent_experiment_id <> experiment_id)
);

CREATE TABLE carl_autonomy.experiment_events (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    experiment_id varchar(128) NOT NULL REFERENCES carl_autonomy.experiment_manifests(experiment_id),
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 1 AND 2147483647),
    schema_version smallint NOT NULL CHECK (schema_version = 1),
    stage_attempt_id varchar(128) NOT NULL UNIQUE,
    event_type varchar(64) NOT NULL CHECK (
        event_type IN (
            'state_transitioned', 'role_recorded', 'lease_acquired', 'lease_reconciled',
            'lease_released', 'live_spend_recorded', 'workspace_prepared', 'candidate_sealed',
            'paired_evidence_recorded', 'review_packet_recorded', 'review_attested',
            'draft_pr_requested', 'draft_pr_recorded', 'workspace_disposed', 'retry_scheduled',
            'coordinator_node_completed', 'experimental_published',
            'protected_validation_recorded', 'promotion_recorded', 'soak_observed',
            'revert_recorded'
        )
    ),
    occurred_at timestamptz NOT NULL,
    occurred_at_text varchar(64) NOT NULL,
    payload_json text NOT NULL CHECK (octet_length(payload_json) BETWEEN 2 AND 16384),
    event_json text NOT NULL CHECK (octet_length(event_json) BETWEEN 2 AND 32768),
    event_digest character(64) NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
    previous_chain_digest character(64) NOT NULL CHECK (previous_chain_digest ~ '^[0-9a-f]{64}$'),
    chain_digest character(64) NOT NULL UNIQUE CHECK (chain_digest ~ '^[0-9a-f]{64}$'),
    authority varchar(32) NOT NULL CHECK (
        authority IN ('builder', 'validator', 'promoter', 'soak', 'supervisor', 'coordinator', 'observer')
    ),
    trusted_authority boolean NOT NULL,
    provenance_json text NOT NULL CHECK (octet_length(provenance_json) BETWEEN 2 AND 2048),
    appended_at timestamptz NOT NULL,
    UNIQUE (experiment_id, ordinal),
    CHECK (stage_attempt_id ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$')
);

CREATE INDEX experiment_events_experiment_order
    ON carl_autonomy.experiment_events(experiment_id, ordinal);

CREATE TABLE carl_autonomy.experiment_projection_guards (
    experiment_id varchar(128) PRIMARY KEY
        REFERENCES carl_autonomy.experiment_manifests(experiment_id),
    manifest_digest character(64) NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    manifest_parent_commit varchar(64) NOT NULL CHECK (
        manifest_parent_commit ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
    ),
    manifest_registered_at timestamptz NOT NULL,
    manifest_deterministic_checks text[] NOT NULL,
    lifecycle_state varchar(32) NOT NULL DEFAULT 'queued' CHECK (
        lifecycle_state IN (
            'queued', 'baselining', 'diagnosing', 'proposal_review', 'building',
            'deterministic_validation', 'paired_evaluation', 'holdout_validation',
            'review_complete', 'pr_open', 'merged', 'soaking', 'accepted', 'rejected',
            'inconclusive', 'blocked', 'budget_exhausted', 'reverted', 'abandoned'
        )
    ),
    lifecycle_revision integer NOT NULL DEFAULT 0
        CHECK (lifecycle_revision BETWEEN 0 AND 2147483647),
    proposal_approvals smallint NOT NULL DEFAULT 0 CHECK (proposal_approvals BETWEEN 0 AND 3),
    proposal_hard_objections smallint NOT NULL DEFAULT 0
        CHECK (proposal_hard_objections BETWEEN 0 AND 3),
    candidate_approvals smallint NOT NULL DEFAULT 0 CHECK (candidate_approvals BETWEEN 0 AND 4),
    candidate_hard_findings smallint NOT NULL DEFAULT 0
        CHECK (candidate_hard_findings BETWEEN 0 AND 4),
    proposal_roles text[] NOT NULL DEFAULT '{}',
    candidate_roles text[] NOT NULL DEFAULT '{}',
    review_packet_roles text[] NOT NULL DEFAULT '{}',
    review_attestation_roles text[] NOT NULL DEFAULT '{}',
    lease_active boolean NOT NULL DEFAULT false,
    lease_reconciled boolean NOT NULL DEFAULT false,
    lease_attempt_id varchar(128),
    lease_owner_id varchar(192),
    lease_expires_at timestamptz,
    workspace_prepared boolean NOT NULL DEFAULT false,
    workspace_manifest_digest character(64),
    workspace_parent_commit varchar(64),
    workspace_branch text,
    candidate_sealed boolean NOT NULL DEFAULT false,
    candidate_packet_digest character(64),
    candidate_commit varchar(64),
    candidate_branch text,
    candidate_diff_digest character(64),
    paired_evidence_recorded boolean NOT NULL DEFAULT false,
    paired_evidence_digest character(64),
    paired_evidence_candidate_commit varchar(64),
    paired_baseline_scorecard_digest character(64),
    paired_candidate_scorecard_digest character(64),
    paired_decision varchar(32),
    protected_validation_recorded boolean NOT NULL DEFAULT false,
    protected_validation_candidate_commit varchar(64),
    protected_validation_candidate_tree varchar(64),
    protected_validation_receipt_digest character(64),
    review_packet_count smallint NOT NULL DEFAULT 0 CHECK (review_packet_count BETWEEN 0 AND 4),
    review_attestation_count smallint NOT NULL DEFAULT 0
        CHECK (review_attestation_count BETWEEN 0 AND 4),
    review_packet_identities jsonb NOT NULL DEFAULT '{}'::jsonb,
    review_attestation_identities jsonb NOT NULL DEFAULT '{}'::jsonb,
    review_attestation_reviewers text[] NOT NULL DEFAULT '{}',
    review_attestation_contexts text[] NOT NULL DEFAULT '{}',
    review_attestation_approvals smallint NOT NULL DEFAULT 0
        CHECK (review_attestation_approvals BETWEEN 0 AND 4),
    review_attestation_hard_findings smallint NOT NULL DEFAULT 0
        CHECK (review_attestation_hard_findings BETWEEN 0 AND 4),
    draft_pr_requested boolean NOT NULL DEFAULT false,
    draft_request_repository text,
    draft_request_base_branch text,
    draft_request_head_branch text,
    draft_request_candidate_commit varchar(64),
    draft_pr_recorded boolean NOT NULL DEFAULT false,
    draft_pr_repository text,
    draft_pr_base_branch text,
    draft_pr_head_branch text,
    draft_pr_candidate_commit varchar(64),
    workspace_disposed boolean NOT NULL DEFAULT false,
    workspace_disposed_branch text,
    workspace_disposed_candidate_commit varchar(64),
    retry_state jsonb NOT NULL DEFAULT '{}'::jsonb,
    experimental_published boolean NOT NULL DEFAULT false,
    experimental_branch text,
    experimental_candidate_packet_digest character(64),
    experimental_commit varchar(64),
    experimental_tree varchar(64),
    promotion_recorded boolean NOT NULL DEFAULT false,
    promotion_merge_commit varchar(64),
    promotion_merge_tree varchar(64),
    promotion_merged_at timestamptz,
    soak_failure_recorded boolean NOT NULL DEFAULT false,
    soak_failure_digest character(64),
    soak_failures jsonb NOT NULL DEFAULT '{}'::jsonb,
    qualifying_healthy_soak_at timestamptz,
    revert_recorded boolean NOT NULL DEFAULT false,
    revert_merge_commit varchar(64),
    revert_hard_failure_digest character(64),
    revert_restored_tree varchar(64),
    revert_candidate_commit varchar(64),
    revert_result_merge_commit varchar(64),
    revert_pull_request_number numeric,
    updated_at timestamptz NOT NULL,
    CHECK (candidate_packet_digest IS NULL OR candidate_packet_digest ~ '^[0-9a-f]{64}$'),
    CHECK (
        workspace_manifest_digest IS NULL OR workspace_manifest_digest ~ '^[0-9a-f]{64}$'
    ),
    CHECK (
        workspace_parent_commit IS NULL
        OR workspace_parent_commit ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
    ),
    CHECK (candidate_commit IS NULL OR candidate_commit ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
    CHECK (candidate_diff_digest IS NULL OR candidate_diff_digest ~ '^[0-9a-f]{64}$'),
    CHECK (paired_evidence_digest IS NULL OR paired_evidence_digest ~ '^[0-9a-f]{64}$'),
    CHECK (
        paired_evidence_candidate_commit IS NULL
        OR paired_evidence_candidate_commit ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
    ),
    CHECK (
        paired_baseline_scorecard_digest IS NULL
        OR paired_baseline_scorecard_digest ~ '^[0-9a-f]{64}$'
    ),
    CHECK (
        paired_candidate_scorecard_digest IS NULL
        OR paired_candidate_scorecard_digest ~ '^[0-9a-f]{64}$'
    ),
    CHECK (
        paired_decision IS NULL
        OR paired_decision IN ('improvement', 'rejected', 'insufficient_evidence')
    ),
    CHECK (
        experimental_commit IS NULL
        OR experimental_commit ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
    ),
    CHECK (
        experimental_tree IS NULL
        OR experimental_tree ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
    ),
    CHECK (
        promotion_merge_commit IS NULL
        OR promotion_merge_commit ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
    ),
    CHECK (
        promotion_merge_tree IS NULL
        OR promotion_merge_tree ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
    ),
    CHECK (
        (lease_active AND lease_attempt_id IS NOT NULL AND lease_owner_id IS NOT NULL
            AND lease_expires_at IS NOT NULL)
        OR
        (NOT lease_active AND NOT lease_reconciled
            AND lease_attempt_id IS NULL AND lease_owner_id IS NULL
            AND lease_expires_at IS NULL)
    )
);

CREATE TABLE carl_autonomy.dead_holder_observations (
    observation_digest character(64) PRIMARY KEY
        CHECK (observation_digest ~ '^[0-9a-f]{64}$'),
    observation_json text NOT NULL CHECK (octet_length(observation_json) BETWEEN 2 AND 16384),
    authority varchar(32) NOT NULL CHECK (
        authority IN ('builder', 'validator', 'promoter', 'soak', 'supervisor', 'coordinator', 'observer')
    ),
    subject_id varchar(192) NOT NULL,
    scope_kind varchar(32) NOT NULL CHECK (scope_kind IN ('command', 'lease')),
    scope_key varchar(192) NOT NULL,
    revision integer NOT NULL CHECK (revision BETWEEN 0 AND 2147483647),
    issued_at timestamptz NOT NULL,
    issued_at_text varchar(64) NOT NULL,
    observed_at timestamptz NOT NULL,
    observed_at_text varchar(64) NOT NULL,
    expires_at timestamptz NOT NULL,
    expires_at_text varchar(64) NOT NULL,
    live boolean NOT NULL,
    key_id varchar(128) NOT NULL,
    signature_base64 varchar(128) NOT NULL,
    registered_at timestamptz NOT NULL,
    CHECK (observed_at >= issued_at AND expires_at > observed_at),
    CHECK (subject_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'),
    CHECK (scope_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'),
    CHECK (key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
);

CREATE TABLE carl_autonomy.commands (
    command_key varchar(192) PRIMARY KEY,
    effect_key varchar(192) NOT NULL UNIQUE,
    command_json text NOT NULL CHECK (octet_length(command_json) BETWEEN 2 AND 32768),
    authority varchar(32) NOT NULL CHECK (
        authority IN ('builder', 'validator', 'promoter', 'soak', 'supervisor', 'coordinator', 'observer')
    ),
    operation varchar(64) NOT NULL,
    request_digest character(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    occurred_at timestamptz NOT NULL,
    occurred_at_text varchar(64) NOT NULL,
    expected_revision integer NOT NULL CHECK (expected_revision BETWEEN 0 AND 2147483646),
    attempt smallint NOT NULL CHECK (attempt BETWEEN 1 AND 3),
    max_attempts smallint NOT NULL CHECK (max_attempts BETWEEN 1 AND 3 AND attempt <= max_attempts),
    revision integer NOT NULL CHECK (revision BETWEEN 0 AND 2147483647),
    status varchar(16) NOT NULL CHECK (status IN ('pending', 'claimed', 'completed', 'failed')),
    claim_json text,
    claim_id varchar(192),
    claimed_at timestamptz,
    claimed_at_text varchar(64),
    claim_expires_at timestamptz,
    claim_expires_at_text varchar(64),
    transition_json text,
    result_digest character(64),
    failure_code varchar(64),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (command_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'),
    CHECK (effect_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'),
    CHECK (claim_id IS NULL OR claim_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'),
    CHECK (result_digest IS NULL OR result_digest ~ '^[0-9a-f]{64}$'),
    CHECK (failure_code IS NULL OR failure_code ~ '^[a-z][a-z0-9_]{0,63}$'),
    CHECK (
        (status = 'pending' AND claim_json IS NULL AND claim_id IS NULL
            AND transition_json IS NULL AND result_digest IS NULL AND failure_code IS NULL)
        OR
        (status = 'claimed' AND claim_json IS NOT NULL AND claim_id IS NOT NULL
            AND claimed_at IS NOT NULL AND claim_expires_at IS NOT NULL
            AND transition_json IS NULL AND result_digest IS NULL AND failure_code IS NULL)
        OR
        (status = 'completed' AND claim_json IS NOT NULL AND claim_id IS NOT NULL
            AND transition_json IS NOT NULL AND result_digest IS NOT NULL AND failure_code IS NULL)
        OR
        (status = 'failed' AND claim_json IS NOT NULL AND claim_id IS NOT NULL
            AND transition_json IS NOT NULL AND result_digest IS NULL AND failure_code IS NOT NULL)
    )
);

CREATE INDEX commands_claimable
    ON carl_autonomy.commands(authority, status, revision, command_key)
    WHERE status = 'pending';

CREATE TABLE carl_autonomy.leases (
    lease_key varchar(192) PRIMARY KEY,
    lease_json text NOT NULL CHECK (octet_length(lease_json) BETWEEN 2 AND 16384),
    holder_id varchar(192) NOT NULL,
    authority varchar(32) NOT NULL CHECK (authority IN ('coordinator', 'supervisor')),
    revision integer NOT NULL CHECK (revision BETWEEN 0 AND 2147483647),
    acquired_at timestamptz NOT NULL,
    acquired_at_text varchar(64) NOT NULL,
    expires_at timestamptz NOT NULL,
    expires_at_text varchar(64) NOT NULL,
    reconciled_at timestamptz,
    reconciled_at_text varchar(64),
    reconciliation_observation_digest character(64),
    released_at timestamptz,
    released_at_text varchar(64),
    status varchar(16) NOT NULL CHECK (status IN ('active', 'reconciled', 'released')),
    updated_at timestamptz NOT NULL,
    CHECK (lease_key ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'),
    CHECK (holder_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'),
    CHECK (expires_at > acquired_at),
    CHECK (
        (status = 'active' AND reconciled_at IS NULL
            AND reconciliation_observation_digest IS NULL AND released_at IS NULL)
        OR
        (status = 'reconciled' AND reconciled_at IS NOT NULL
            AND reconciliation_observation_digest IS NOT NULL AND released_at IS NULL)
        OR
        (status = 'released' AND released_at IS NOT NULL)
    ),
    CHECK (
        reconciliation_observation_digest IS NULL
        OR reconciliation_observation_digest ~ '^[0-9a-f]{64}$'
    )
);

CREATE TABLE carl_autonomy.supervisor_triggers (
    trigger_id varchar(192) PRIMARY KEY,
    trigger_json text NOT NULL CHECK (octet_length(trigger_json) BETWEEN 2 AND 32768),
    revision integer NOT NULL CHECK (revision BETWEEN 0 AND 2147483647),
    claim_id varchar(192),
    resolution_json text,
    status varchar(16) NOT NULL CHECK (status IN ('pending', 'claimed', 'resolved', 'rejected')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (trigger_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'),
    CHECK (claim_id IS NULL OR claim_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'),
    CHECK (
        (status = 'pending' AND claim_id IS NULL AND resolution_json IS NULL)
        OR (status = 'claimed' AND claim_id IS NOT NULL AND resolution_json IS NULL)
        OR (status IN ('resolved', 'rejected') AND claim_id IS NOT NULL AND resolution_json IS NOT NULL)
    )
);

CREATE INDEX supervisor_triggers_pending
    ON carl_autonomy.supervisor_triggers(created_at, trigger_id)
    WHERE resolution_json IS NULL;

CREATE TABLE carl_autonomy.evidence_objects (
    digest character(64) PRIMARY KEY CHECK (digest ~ '^[0-9a-f]{64}$'),
    object_key varchar(256) NOT NULL UNIQUE,
    object_version varchar(192) NOT NULL,
    producer varchar(32) NOT NULL CHECK (producer IN ('validator', 'observer')),
    request_digest character(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    media_type varchar(128) NOT NULL,
    retained_until timestamptz NOT NULL,
    retained_until_text varchar(64) NOT NULL,
    evidence_json text NOT NULL CHECK (octet_length(evidence_json) BETWEEN 2 AND 16384),
    recorded_at timestamptz NOT NULL,
    CHECK (object_key = 'evidence/' || digest),
    CHECK (object_version ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$')
);

CREATE TABLE carl_autonomy.monitor_snapshots (
    snapshot_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    observed_at timestamptz NOT NULL,
    observed_at_text varchar(64) NOT NULL,
    healthy boolean NOT NULL,
    detail_digest character(64) NOT NULL CHECK (detail_digest ~ '^[0-9a-f]{64}$'),
    snapshot_json text NOT NULL CHECK (octet_length(snapshot_json) BETWEEN 2 AND 8192),
    recorded_at timestamptz NOT NULL,
    UNIQUE (observed_at, detail_digest)
);

CREATE INDEX monitor_snapshots_latest
    ON carl_autonomy.monitor_snapshots(observed_at DESC, snapshot_id DESC);

CREATE OR REPLACE FUNCTION carl_autonomy.reject_immutable_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, carl_autonomy
AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'immutable_state_mutation_denied';
END;
$$;

CREATE TRIGGER experiment_manifests_immutable
BEFORE UPDATE OR DELETE ON carl_autonomy.experiment_manifests
FOR EACH ROW EXECUTE FUNCTION carl_autonomy.reject_immutable_mutation();

CREATE TRIGGER experiment_events_append_only
BEFORE UPDATE OR DELETE ON carl_autonomy.experiment_events
FOR EACH ROW EXECUTE FUNCTION carl_autonomy.reject_immutable_mutation();

CREATE TRIGGER dead_holder_observations_immutable
BEFORE UPDATE OR DELETE ON carl_autonomy.dead_holder_observations
FOR EACH ROW EXECUTE FUNCTION carl_autonomy.reject_immutable_mutation();

CREATE TRIGGER evidence_objects_immutable
BEFORE UPDATE OR DELETE ON carl_autonomy.evidence_objects
FOR EACH ROW EXECUTE FUNCTION carl_autonomy.reject_immutable_mutation();

CREATE TRIGGER monitor_snapshots_append_only
BEFORE UPDATE OR DELETE ON carl_autonomy.monitor_snapshots
FOR EACH ROW EXECUTE FUNCTION carl_autonomy.reject_immutable_mutation();

REVOKE ALL ON ALL TABLES IN SCHEMA carl_autonomy FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA carl_autonomy FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA carl_autonomy FROM PUBLIC;

COMMIT;
