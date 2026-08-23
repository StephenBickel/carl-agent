BEGIN;

CREATE TABLE carl_autonomy.coordinator_runtime (
    experiment_id varchar(128) PRIMARY KEY
        REFERENCES carl_autonomy.experiment_manifests(experiment_id),
    command_name varchar(32) NOT NULL CHECK (
        command_name IN (
            'request', 'coordinate', 'observe', 'ingest', 'publish-input', 'health',
            'commission-live'
        )
    ),
    snapshot_json text NOT NULL CHECK (octet_length(snapshot_json) BETWEEN 2 AND 1048576),
    snapshot_digest character(64) NOT NULL CHECK (snapshot_digest ~ '^[0-9a-f]{64}$'),
    production_receipts_json text,
    production_receipts_digest character(64),
    completion_event_json text,
    completion_event_digest character(64),
    effect_family varchar(24) CHECK (
        effect_family IN (
            'archive', 'evaluator', 'github', 'input', 'observer', 'state', 'supervisor'
        )
    ),
    effect_request_json text,
    effect_request_digest character(64),
    decision_identity character(64),
    decision_json text,
    effect_response_json text,
    graph_request_json text,
    graph_request_digest character(64),
    graph_occurrence_key varchar(192),
    repair_fingerprint character(64),
    freeze_reason varchar(128),
    freeze_fingerprint character(64),
    freeze_occurrence_key varchar(96),
    freeze_attempt smallint,
    status varchar(24) NOT NULL DEFAULT 'ready' CHECK (
        status IN ('ready', 'effect_prepared', 'effect_observed', 'complete', 'frozen')
    ),
    revision integer NOT NULL CHECK (revision BETWEEN 0 AND 2147483647),
    updated_at timestamptz NOT NULL,
    CHECK (
        (effect_family IS NULL AND effect_request_json IS NULL AND effect_request_digest IS NULL)
        OR (
            effect_family IS NOT NULL
            AND effect_request_json IS NOT NULL
            AND effect_request_digest IS NOT NULL
        )
    ),
    CHECK (
        (completion_event_json IS NULL AND completion_event_digest IS NULL)
        OR (completion_event_json IS NOT NULL AND completion_event_digest IS NOT NULL)
    ),
    CHECK (
        (production_receipts_json IS NULL AND production_receipts_digest IS NULL)
        OR (production_receipts_json IS NOT NULL AND production_receipts_digest IS NOT NULL)
    ),
    CHECK (
        production_receipts_digest IS NULL
        OR production_receipts_digest ~ '^[0-9a-f]{64}$'
    ),
    CHECK (completion_event_digest IS NULL OR completion_event_digest ~ '^[0-9a-f]{64}$'),
    CHECK (effect_request_digest IS NULL OR effect_request_digest ~ '^[0-9a-f]{64}$'),
    CHECK (decision_identity IS NULL OR decision_identity ~ '^[0-9a-f]{64}$'),
    CHECK (
        (graph_request_json IS NULL AND graph_request_digest IS NULL
            AND graph_occurrence_key IS NULL)
        OR (graph_request_json IS NOT NULL AND graph_request_digest IS NOT NULL
            AND graph_occurrence_key IS NOT NULL)
    ),
    CHECK (graph_request_digest IS NULL OR graph_request_digest ~ '^[0-9a-f]{64}$'),
    CHECK (repair_fingerprint IS NULL OR repair_fingerprint ~ '^[0-9a-f]{64}$'),
    CHECK (
        (freeze_reason IS NULL AND freeze_fingerprint IS NULL
            AND freeze_occurrence_key IS NULL AND freeze_attempt IS NULL)
        OR (
            freeze_reason IS NOT NULL
            AND freeze_fingerprint ~ '^[0-9a-f]{64}$'
            AND freeze_occurrence_key = 'coordinator-freeze/' || freeze_fingerprint
            AND freeze_attempt BETWEEN 1 AND 3
        )
    ),
    UNIQUE (graph_occurrence_key)
);

REVOKE ALL ON carl_autonomy.coordinator_runtime FROM PUBLIC, carl_autonomy_workflow;

CREATE TABLE carl_autonomy.coordinator_effect_occurrences (
    effect_key varchar(192) PRIMARY KEY,
    occurrence_key varchar(192) NOT NULL UNIQUE,
    experiment_id varchar(128) NOT NULL
        REFERENCES carl_autonomy.coordinator_runtime(experiment_id),
    node_kind varchar(32) NOT NULL,
    effect_family varchar(24) NOT NULL CHECK (
        effect_family IN ('archive', 'evaluator', 'input', 'observer', 'state', 'supervisor')
    ),
    command_key varchar(192) NOT NULL,
    request_json text NOT NULL CHECK (octet_length(request_json) BETWEEN 2 AND 32768),
    request_digest character(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    response_json text,
    response_digest character(64),
    status varchar(24) NOT NULL CHECK (
        status IN ('effect_prepared', 'in_progress', 'effect_observed')
    ),
    prepared_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (
        (response_json IS NULL AND response_digest IS NULL)
        OR (response_json IS NOT NULL AND response_digest IS NOT NULL)
    ),
    CHECK (response_digest IS NULL OR response_digest ~ '^[0-9a-f]{64}$')
);

REVOKE ALL ON carl_autonomy.coordinator_effect_occurrences
FROM PUBLIC, carl_autonomy_workflow;

CREATE TABLE carl_autonomy.coordinator_completion_receipts (
    event_digest character(64) PRIMARY KEY CHECK (event_digest ~ '^[0-9a-f]{64}$'),
    experiment_id varchar(128) NOT NULL
        REFERENCES carl_autonomy.coordinator_runtime(experiment_id),
    node_kind varchar(32) NOT NULL,
    authority varchar(32) NOT NULL CHECK (
        authority IN (
            'builder', 'validator', 'promoter', 'soak', 'supervisor',
            'coordinator', 'observer'
        )
    ),
    command_key varchar(192) NOT NULL,
    effect_key varchar(192) NOT NULL UNIQUE,
    request_digest character(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    result_digest character(64) NOT NULL CHECK (result_digest ~ '^[0-9a-f]{64}$'),
    event_json text NOT NULL CHECK (octet_length(event_json) BETWEEN 2 AND 32768),
    occurred_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL
);

REVOKE ALL ON carl_autonomy.coordinator_completion_receipts
FROM PUBLIC, carl_autonomy_workflow;

CREATE TABLE carl_autonomy.coordinator_freeze_occurrences (
    occurrence_key varchar(96) PRIMARY KEY,
    freeze_fingerprint character(64) NOT NULL UNIQUE
        CHECK (freeze_fingerprint ~ '^[0-9a-f]{64}$'),
    experiment_id varchar(128) NOT NULL
        REFERENCES carl_autonomy.coordinator_runtime(experiment_id),
    node_id varchar(192) NOT NULL,
    node_kind varchar(32) NOT NULL,
    attempt smallint NOT NULL CHECK (attempt BETWEEN 1 AND 3),
    reason varchar(128) NOT NULL,
    command_key varchar(192) NOT NULL,
    effect_key varchar(192) NOT NULL,
    request_digest character(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    runtime_revision integer NOT NULL CHECK (runtime_revision BETWEEN 0 AND 2147483647),
    decision_identity character(64) NOT NULL CHECK (decision_identity ~ '^[0-9a-f]{64}$'),
    decision_json text NOT NULL CHECK (octet_length(decision_json) BETWEEN 2 AND 32768),
    frozen_at timestamptz NOT NULL,
    recovery_evidence_digest character(64),
    recovery_fingerprint character(64),
    recovered_at timestamptz,
    CHECK (occurrence_key = 'coordinator-freeze/' || freeze_fingerprint),
    CHECK (node_id = experiment_id || ':' || node_kind),
    CHECK (command_key = experiment_id || ':' || node_kind || ':attempt:' || attempt::text),
    CHECK (effect_key ~ '^cloud-effect-[0-9a-f]{64}$'),
    CHECK (
        (recovery_evidence_digest IS NULL AND recovery_fingerprint IS NULL
            AND recovered_at IS NULL)
        OR (
            recovery_evidence_digest ~ '^[0-9a-f]{64}$'
            AND recovery_fingerprint ~ '^[0-9a-f]{64}$'
            AND recovered_at IS NOT NULL
        )
    )
);

REVOKE ALL ON carl_autonomy.coordinator_freeze_occurrences
FROM PUBLIC, carl_autonomy_workflow;

CREATE TABLE carl_autonomy.coordinator_recovery_receipts (
    evidence_digest character(64) PRIMARY KEY CHECK (evidence_digest ~ '^[0-9a-f]{64}$'),
    occurrence_key varchar(96) NOT NULL UNIQUE,
    freeze_fingerprint character(64) NOT NULL CHECK (freeze_fingerprint ~ '^[0-9a-f]{64}$'),
    experiment_id varchar(128) NOT NULL
        REFERENCES carl_autonomy.coordinator_runtime(experiment_id),
    node_id varchar(192) NOT NULL,
    node_kind varchar(32) NOT NULL,
    attempt smallint NOT NULL CHECK (attempt BETWEEN 1 AND 3),
    reason varchar(128) NOT NULL,
    command_key varchar(192) NOT NULL,
    effect_key varchar(192) NOT NULL,
    request_digest character(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    runtime_revision integer NOT NULL CHECK (runtime_revision BETWEEN 0 AND 2147483646),
    decision_identity character(64) NOT NULL CHECK (decision_identity ~ '^[0-9a-f]{64}$'),
    changed_action_digest character(64) NOT NULL
        CHECK (changed_action_digest ~ '^[0-9a-f]{64}$'),
    repair_fingerprint character(64) NOT NULL CHECK (repair_fingerprint ~ '^[0-9a-f]{64}$'),
    signature_key_id varchar(128) NOT NULL
        CHECK (signature_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
    signature_algorithm varchar(16) NOT NULL CHECK (signature_algorithm = 'Ed25519'),
    signature_base64 character(88) NOT NULL
        CHECK (signature_base64 ~ '^[A-Za-z0-9+/]{86}==$'),
    signature_issued_at timestamptz NOT NULL,
    signature_expires_at timestamptz NOT NULL,
    archive_object_key varchar(256) NOT NULL,
    archive_version_id varchar(256) NOT NULL,
    archive_checksum_sha256 character(64) NOT NULL
        CHECK (archive_checksum_sha256 ~ '^[0-9a-f]{64}$'),
    archive_byte_length integer NOT NULL CHECK (archive_byte_length BETWEEN 2 AND 32768),
    retention_mode varchar(16) NOT NULL CHECK (retention_mode = 'COMPLIANCE'),
    retained_until timestamptz NOT NULL,
    archive_created_at timestamptz NOT NULL,
    verified_at timestamptz NOT NULL,
    receipt_json text NOT NULL CHECK (octet_length(receipt_json) BETWEEN 2 AND 65536),
    registered_at timestamptz NOT NULL,
    CHECK (occurrence_key = 'coordinator-freeze/' || freeze_fingerprint),
    CHECK (node_id = experiment_id || ':' || node_kind),
    CHECK (command_key = experiment_id || ':' || node_kind || ':attempt:' || attempt::text),
    CHECK (effect_key ~ '^cloud-effect-[0-9a-f]{64}$'),
    CHECK (
        archive_object_key = 'carl-evidence/v1/sha256/'
            || substr(evidence_digest, 1, 2) || '/' || evidence_digest
    ),
    CHECK (archive_checksum_sha256 = evidence_digest),
    CHECK (
        signature_issued_at <= archive_created_at
        AND archive_created_at <= verified_at
        AND verified_at < signature_expires_at
        AND signature_expires_at <= retained_until
    )
);

REVOKE ALL ON carl_autonomy.coordinator_recovery_receipts
FROM PUBLIC, carl_autonomy_workflow;

CREATE TRIGGER coordinator_recovery_receipts_immutable
BEFORE UPDATE OR DELETE ON carl_autonomy.coordinator_recovery_receipts
FOR EACH ROW EXECUTE FUNCTION carl_autonomy.reject_immutable_mutation();

CREATE OR REPLACE FUNCTION carl_autonomy.coordinator_timestamp(p_value timestamptz)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT to_char(p_value AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS')
        || CASE
            WHEN (extract(microseconds FROM p_value)::bigint % 1000000) = 0 THEN ''
            ELSE '.' || regexp_replace(
                to_char(p_value AT TIME ZONE 'UTC', 'US'), '0+$', ''
            )
        END
        || 'Z'
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.coordinator_node_priority(p_kind text)
RETURNS integer
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT CASE p_kind
        WHEN 'create_revert' THEN 0
        WHEN 'observe_revert' THEN 1
        WHEN 'publish_input' THEN 2
        WHEN 'register_hypothesis' THEN 3
        WHEN 'request_builder' THEN 4
        WHEN 'dispatch_builder' THEN 5
        WHEN 'observe_builder' THEN 6
        WHEN 'archive_builder' THEN 7
        WHEN 'ingest_builder' THEN 8
        WHEN 'publish_experimental' THEN 9
        WHEN 'dispatch_validation' THEN 10
        WHEN 'observe_validation' THEN 11
        WHEN 'archive_validation' THEN 12
        WHEN 'ingest_validation' THEN 13
        WHEN 'record_disposition' THEN 14
        WHEN 'create_promotion_pr' THEN 15
        WHEN 'observe_required_checks' THEN 16
        WHEN 'enable_auto_merge' THEN 17
        WHEN 'schedule_soak' THEN 18
        WHEN 'observe_soak' THEN 19
        WHEN 'accept_soak' THEN 20
        WHEN 'trigger_supervisor' THEN 21
        ELSE NULL
    END
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.coordinator_command_state(p_command_key text)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT jsonb_build_object(
        'claim', CASE WHEN c.claim_json IS NULL THEN NULL ELSE c.claim_json::jsonb END,
        'command', c.command_json::jsonb,
        'failure_code', c.failure_code,
        'result_digest', c.result_digest,
        'revision', c.revision,
        'status', c.status,
        'transition', CASE WHEN c.transition_json IS NULL THEN NULL ELSE c.transition_json::jsonb END
    )
    FROM carl_autonomy.commands AS c
    WHERE c.command_key = p_command_key
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.coordinator_effect_family(p_kind text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT CASE p_kind
        WHEN 'create_revert' THEN 'github'
        WHEN 'observe_revert' THEN 'observer'
        WHEN 'publish_input' THEN 'input'
        WHEN 'register_hypothesis' THEN 'state'
        WHEN 'request_builder' THEN 'state'
        WHEN 'dispatch_builder' THEN 'github'
        WHEN 'observe_builder' THEN 'observer'
        WHEN 'archive_builder' THEN 'archive'
        WHEN 'ingest_builder' THEN 'state'
        WHEN 'publish_experimental' THEN 'github'
        WHEN 'dispatch_validation' THEN 'github'
        WHEN 'observe_validation' THEN 'observer'
        WHEN 'archive_validation' THEN 'archive'
        WHEN 'ingest_validation' THEN 'evaluator'
        WHEN 'record_disposition' THEN 'state'
        WHEN 'create_promotion_pr' THEN 'github'
        WHEN 'observe_required_checks' THEN 'github'
        WHEN 'enable_auto_merge' THEN 'github'
        WHEN 'schedule_soak' THEN 'state'
        WHEN 'observe_soak' THEN 'observer'
        WHEN 'accept_soak' THEN 'state'
        WHEN 'trigger_supervisor' THEN 'supervisor'
        ELSE NULL
    END
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.coordinator_node_authority(p_kind text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT CASE p_kind
        WHEN 'create_revert' THEN 'promoter'
        WHEN 'observe_revert' THEN 'observer'
        WHEN 'publish_input' THEN 'validator'
        WHEN 'register_hypothesis' THEN 'builder'
        WHEN 'request_builder' THEN 'coordinator'
        WHEN 'dispatch_builder' THEN 'coordinator'
        WHEN 'observe_builder' THEN 'observer'
        WHEN 'archive_builder' THEN 'observer'
        WHEN 'ingest_builder' THEN 'coordinator'
        WHEN 'publish_experimental' THEN 'builder'
        WHEN 'dispatch_validation' THEN 'coordinator'
        WHEN 'observe_validation' THEN 'observer'
        WHEN 'archive_validation' THEN 'validator'
        WHEN 'ingest_validation' THEN 'coordinator'
        WHEN 'record_disposition' THEN 'validator'
        WHEN 'create_promotion_pr' THEN 'promoter'
        WHEN 'observe_required_checks' THEN 'observer'
        WHEN 'enable_auto_merge' THEN 'promoter'
        WHEN 'schedule_soak' THEN 'coordinator'
        WHEN 'observe_soak' THEN 'soak'
        WHEN 'accept_soak' THEN 'soak'
        WHEN 'trigger_supervisor' THEN 'supervisor'
        ELSE NULL
    END
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.coordinator_node_operation(p_kind text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT CASE p_kind
        WHEN 'create_revert' THEN 'github_effect'
        WHEN 'observe_revert' THEN 'observe'
        WHEN 'publish_input' THEN 'register_evidence'
        WHEN 'register_hypothesis' THEN 'register_manifest'
        WHEN 'request_builder' THEN 'schedule'
        WHEN 'dispatch_builder' THEN 'dispatch'
        WHEN 'observe_builder' THEN 'observe'
        WHEN 'archive_builder' THEN 'register_evidence'
        WHEN 'ingest_builder' THEN 'record_success'
        WHEN 'publish_experimental' THEN 'publish_experimental'
        WHEN 'dispatch_validation' THEN 'dispatch'
        WHEN 'observe_validation' THEN 'observe'
        WHEN 'archive_validation' THEN 'register_evidence'
        WHEN 'ingest_validation' THEN 'record_success'
        WHEN 'record_disposition' THEN 'append_disposition'
        WHEN 'create_promotion_pr' THEN 'github_effect'
        WHEN 'observe_required_checks' THEN 'observe'
        WHEN 'enable_auto_merge' THEN 'github_effect'
        WHEN 'schedule_soak' THEN 'schedule'
        WHEN 'observe_soak' THEN 'production_observation'
        WHEN 'accept_soak' THEN 'record_soak'
        WHEN 'trigger_supervisor' THEN 'claim_trigger'
        ELSE NULL
    END
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.coordinator_freeze_reason_valid(
    p_kind text,
    p_reason text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT CASE
        WHEN carl_autonomy.coordinator_node_priority(p_kind) IS NULL THEN false
        WHEN p_reason = carl_autonomy.coordinator_effect_family(p_kind)
                || '_service_uncommissioned' THEN true
        WHEN p_kind IN (
            'create_promotion_pr', 'observe_required_checks', 'enable_auto_merge',
            'schedule_soak', 'observe_soak', 'accept_soak', 'create_revert',
            'observe_revert'
        ) AND p_reason IN (
            'protected_production_receipts_required',
            'production_experiment_identity_mismatch',
            'production_node_identity_mismatch',
            'production_request_identity_mismatch',
            'protected_verification_stale',
            'protected_archive_retention_expired',
            'merge_bound_soak_required'
        ) THEN true
        WHEN p_reason IN (
            'failure_command_mismatch', 'command_identity_conflict',
            'completed_command_node_not_advanced', 'claimed_command_identity_missing',
            'effect_identity_conflict', 'authoritative_completion_receipt_invalid'
        ) THEN true
        ELSE false
    END
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.build_coordinator_completion_event(
    p_experiment_id text,
    p_node_kind text,
    p_attempt integer,
    p_command_key text,
    p_effect_key text,
    p_request_digest text,
    p_result_digest text,
    p_occurred_at timestamptz
)
RETURNS TABLE(event_authority text, event_json text, event_digest text)
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    authority_value text;
    stage_attempt_value text;
    event_value text;
BEGIN
    authority_value := carl_autonomy.coordinator_node_authority(p_node_kind);
    IF authority_value IS NULL
        OR p_experiment_id !~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
        OR p_attempt NOT BETWEEN 1 AND 3
        OR p_command_key <> p_experiment_id || ':' || p_node_kind
            || ':attempt:' || p_attempt::text
        OR p_effect_key !~ '^cloud-effect-[0-9a-f]{64}$'
        OR p_request_digest !~ '^[0-9a-f]{64}$'
        OR p_result_digest !~ '^[0-9a-f]{64}$'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'coordinator_completion_identity_invalid';
    END IF;
    stage_attempt_value := 'coordinator-completion-' || substr(
        carl_autonomy.sha256_text(carl_autonomy.canonical_jsonb(jsonb_build_object(
            'attempt', p_attempt,
            'command_key', p_command_key,
            'effect_key', p_effect_key,
            'experiment_id', p_experiment_id,
            'node_kind', p_node_kind,
            'request_digest', p_request_digest,
            'result_digest', p_result_digest
        ))),
        1,
        64
    );
    event_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
        'authority', authority_value,
        'domain', 'carl.coordinator-node-completion.v1',
        'event_type', 'coordinator_node_completed',
        'experiment_id', p_experiment_id,
        'occurred_at', carl_autonomy.coordinator_timestamp(p_occurred_at),
        'payload', jsonb_build_object(
            'command_key', p_command_key,
            'effect_key', p_effect_key,
            'node_kind', p_node_kind,
            'request_digest', p_request_digest,
            'result_digest', p_result_digest
        ),
        'schema_version', 1,
        'stage_attempt_id', stage_attempt_value
    ));
    RETURN QUERY SELECT authority_value, event_value,
        carl_autonomy.sha256_text(event_value);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.coordinator_node_event_authority(
    p_kind text,
    p_event_type text
)
RETURNS text
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT CASE
        WHEN p_kind = 'observe_revert' AND p_event_type = 'revert_recorded' THEN 'soak'
        WHEN p_kind = 'observe_builder' AND p_event_type = 'candidate_sealed' THEN 'builder'
        WHEN p_kind = 'archive_builder' AND p_event_type = 'state_transitioned'
            THEN 'coordinator'
        WHEN p_kind = 'observe_validation'
            AND p_event_type = 'protected_validation_recorded' THEN 'validator'
        WHEN p_kind = 'observe_required_checks' AND p_event_type = 'state_transitioned'
            THEN 'coordinator'
        WHEN p_kind = 'trigger_supervisor' AND p_event_type = 'retry_scheduled'
            THEN 'coordinator'
        ELSE NULL
    END
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.coordinator_command_allows_node(
    p_command text,
    p_kind text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT CASE p_command
        WHEN 'request' THEN p_kind IN ('register_hypothesis', 'request_builder')
        WHEN 'coordinate' THEN carl_autonomy.coordinator_node_priority(p_kind) IS NOT NULL
        WHEN 'observe' THEN p_kind IN (
            'observe_builder', 'archive_builder', 'observe_validation', 'archive_validation',
            'observe_required_checks', 'observe_soak', 'observe_revert'
        )
        WHEN 'ingest' THEN p_kind IN (
            'ingest_builder', 'ingest_validation', 'record_disposition'
        )
        WHEN 'publish-input' THEN p_kind = 'publish_input'
        WHEN 'health' THEN p_kind = 'trigger_supervisor'
        WHEN 'commission-live' THEN p_kind IN (
            'dispatch_validation', 'observe_validation', 'archive_validation',
            'ingest_validation', 'record_disposition', 'create_promotion_pr',
            'observe_required_checks', 'enable_auto_merge', 'schedule_soak',
            'observe_soak', 'accept_soak', 'create_revert', 'observe_revert'
        )
        ELSE false
    END
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.enqueue_coordinator_graph(
    p_request_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean, experiment_id text, occurrence_key text, request_digest text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    request_value jsonb;
    request_hash text;
    manifest_state carl_autonomy.experiment_manifests%ROWTYPE;
    manifest_value jsonb;
    existing carl_autonomy.coordinator_runtime%ROWTYPE;
    nodes_value jsonb;
    snapshot_value text;
    input_request jsonb;
    input_request_text text;
    input_request_digest text;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    request_value := carl_autonomy.parse_object(
        p_request_json, 'coordinator_graph_request_invalid'
    );
    IF carl_autonomy.canonical_jsonb(request_value) <> p_request_json
        OR carl_autonomy.jsonb_object_cardinality(request_value) IS DISTINCT FROM 9
        OR NOT request_value ?& ARRAY[
            'schema_version', 'domain', 'occurrence_key', 'experiment_id',
            'manifest_digest', 'parent_experiment_id', 'parent_commit',
            'input_digest', 'requested_at'
        ]
        OR request_value->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR request_value->>'domain' <> 'carl.coordinator.graph-request.v1'
        OR request_value->>'occurrence_key'
            !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'
        OR request_value->>'experiment_id'
            !~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
        OR request_value->>'manifest_digest' !~ '^[0-9a-f]{64}$'
        OR request_value->>'input_digest' !~ '^[0-9a-f]{64}$'
        OR request_value->>'parent_commit' !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
        OR NOT carl_autonomy.canonical_utc_text_valid(request_value->>'requested_at')
        OR (request_value->>'requested_at')::timestamptz > p_observed_at
        OR NOT (
            request_value->'parent_experiment_id' = 'null'::jsonb
            OR (
                jsonb_typeof(request_value->'parent_experiment_id') = 'string'
                AND request_value->>'parent_experiment_id'
                    ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
            )
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'coordinator_graph_request_invalid';
    END IF;
    request_hash := carl_autonomy.sha256_text(p_request_json);
    PERFORM pg_advisory_xact_lock(hashtextextended(request_value->>'occurrence_key', 11));
    SELECT runtime.* INTO existing
    FROM carl_autonomy.coordinator_runtime AS runtime
    WHERE runtime.experiment_id = request_value->>'experiment_id'
        OR runtime.graph_occurrence_key = request_value->>'occurrence_key'
    FOR UPDATE;
    IF FOUND THEN
        IF existing.experiment_id = request_value->>'experiment_id'
            AND existing.graph_occurrence_key = request_value->>'occurrence_key'
            AND existing.graph_request_json = p_request_json
            AND existing.graph_request_digest = request_hash
        THEN
            RETURN QUERY SELECT false, existing.experiment_id::text,
                existing.graph_occurrence_key::text, existing.graph_request_digest::text;
            RETURN;
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '23505', MESSAGE = 'coordinator_graph_occurrence_conflict';
    END IF;
    SELECT manifest.* INTO manifest_state
    FROM carl_autonomy.experiment_manifests AS manifest
    WHERE manifest.experiment_id = request_value->>'experiment_id'
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'coordinator_manifest_not_found';
    END IF;
    manifest_value := carl_autonomy.parse_object(
        manifest_state.manifest_json, 'coordinator_manifest_invalid'
    );
    IF manifest_state.manifest_digest <> request_value->>'manifest_digest'
        OR request_value->>'input_digest' <> manifest_state.manifest_digest
        OR manifest_state.parent_experiment_id IS DISTINCT FROM
            NULLIF(request_value->>'parent_experiment_id', '')
        OR manifest_value->>'parent_commit' <> request_value->>'parent_commit'
        OR manifest_state.registered_at_text <> request_value->>'requested_at'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'coordinator_graph_manifest_identity_mismatch';
    END IF;
    SELECT jsonb_agg(
        jsonb_build_object(
            'attempt', 1,
            'authority', carl_autonomy.coordinator_node_authority(kind),
            'command_key', (request_value->>'experiment_id') || ':' || kind || ':attempt:1',
            'kind', kind,
            'max_attempts', 3,
            'node_id', (request_value->>'experiment_id') || ':' || kind,
            'occurred_at', request_value->>'requested_at',
            'operation', carl_autonomy.coordinator_node_operation(kind),
            'request_digest', carl_autonomy.sha256_text(carl_autonomy.canonical_jsonb(
                jsonb_build_object(
                    'attempt', 1,
                    'graph_request_digest', request_hash,
                    'input_digest', request_value->>'input_digest',
                    'node_kind', kind,
                    'parent_commit', request_value->>'parent_commit'
                )
            )),
            'status', CASE
                WHEN kind IN ('create_revert', 'observe_revert', 'trigger_supervisor')
                    THEN 'waiting'
                ELSE 'ready'
            END
        ) ORDER BY ordinal
    ) INTO nodes_value
    FROM unnest(ARRAY[
        'create_revert', 'observe_revert', 'publish_input', 'register_hypothesis',
        'request_builder', 'dispatch_builder', 'observe_builder', 'archive_builder',
        'ingest_builder', 'publish_experimental', 'dispatch_validation',
        'observe_validation', 'archive_validation', 'ingest_validation',
        'record_disposition', 'create_promotion_pr', 'observe_required_checks',
        'enable_auto_merge', 'schedule_soak', 'observe_soak', 'accept_soak',
        'trigger_supervisor'
    ]::text[]) WITH ORDINALITY AS fixed(kind, ordinal);
    snapshot_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
        'command', NULL,
        'coordinator_id', 'carl-cloud-coordinator-v1',
        'dead_holder_observation_digest', NULL,
        'effect', NULL,
        'experiment_id', request_value->>'experiment_id',
        'failure', NULL,
        'immutable_inputs', jsonb_build_array(jsonb_build_object(
            'digest', request_value->>'input_digest',
            'media_type', 'application/vnd.carl.improvement-request+json',
            'media_version', 1,
            'resolved_digest', request_value->>'input_digest',
            'size_bytes', octet_length(manifest_state.manifest_json),
            'visibility', 'private'
        )),
        'lease', NULL,
        'nodes', nodes_value,
        'observed_at', request_value->>'requested_at',
        'production_authorization', NULL,
        'revision', 0,
        'schema_version', 1
    ));
    SELECT node INTO input_request
    FROM jsonb_array_elements(nodes_value) AS node
    WHERE node->>'kind' = 'publish_input';
    input_request_text := carl_autonomy.canonical_jsonb(jsonb_build_object(
        'command_key', input_request->>'command_key',
        'domain', 'carl.coordinator-node-effect.request.v1',
        'effect_key', 'cloud-effect-' || carl_autonomy.sha256_text(
            carl_autonomy.canonical_jsonb(jsonb_build_object(
                'authority', input_request->>'authority',
                'command_key', input_request->>'command_key',
                'operation', input_request->>'operation',
                'request_digest', input_request->>'request_digest'
            ))
        ),
        'family', 'input',
        'node_kind', 'publish_input',
        'occurred_at', input_request->>'occurred_at',
        'request_digest', input_request->>'request_digest',
        'schema_version', 1
    ));
    input_request_digest := carl_autonomy.sha256_text(input_request_text);
    INSERT INTO carl_autonomy.coordinator_runtime(
        experiment_id, command_name, snapshot_json, snapshot_digest,
        effect_family, effect_request_json, effect_request_digest,
        graph_request_json, graph_request_digest, graph_occurrence_key,
        status, revision, updated_at
    ) VALUES (
        request_value->>'experiment_id', 'request', snapshot_value,
        carl_autonomy.sha256_text(snapshot_value), 'input', input_request_text,
        input_request_digest, p_request_json, request_hash,
        request_value->>'occurrence_key', 'ready', 0, p_observed_at
    );
    RETURN QUERY SELECT true, request_value->>'experiment_id',
        request_value->>'occurrence_key', request_hash;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.enqueue_pending_coordinator_graph(
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean, experiment_id text, occurrence_key text, request_digest text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    selected carl_autonomy.experiment_manifests%ROWTYPE;
    request_value text;
    manifest_value jsonb;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    SELECT manifest.* INTO selected
    FROM carl_autonomy.experiment_manifests AS manifest
    LEFT JOIN carl_autonomy.coordinator_runtime AS runtime
        ON runtime.experiment_id = manifest.experiment_id
    ORDER BY (runtime.experiment_id IS NULL) DESC,
        manifest.registered_at, manifest.experiment_id
    FOR UPDATE OF manifest SKIP LOCKED
    LIMIT 1;
    IF NOT FOUND THEN
        RETURN QUERY SELECT false, NULL::text, NULL::text, NULL::text;
        RETURN;
    END IF;
    manifest_value := carl_autonomy.parse_object(
        selected.manifest_json, 'coordinator_manifest_invalid'
    );
    request_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
        'domain', 'carl.coordinator.graph-request.v1',
        'experiment_id', selected.experiment_id,
        'input_digest', selected.manifest_digest,
        'manifest_digest', selected.manifest_digest,
        'occurrence_key', 'manifest/' || selected.manifest_digest,
        'parent_commit', manifest_value->>'parent_commit',
        'parent_experiment_id', selected.parent_experiment_id,
        'requested_at', selected.registered_at_text,
        'schema_version', 1
    ));
    RETURN QUERY SELECT *
    FROM carl_autonomy.enqueue_coordinator_graph(request_value, p_observed_at);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.register_coordinator_recovery_receipt(
    p_receipt_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    receipt_value jsonb;
    artifact_value jsonb;
    signed_envelope_value jsonb;
    binding_value jsonb;
    artifact_json text;
    envelope_json text;
    identity_value text;
    evidence_digest_value text;
    existing carl_autonomy.coordinator_recovery_receipts%ROWTYPE;
    occurrence carl_autonomy.coordinator_freeze_occurrences%ROWTYPE;
BEGIN
    IF CASE
        WHEN current_setting('role', true) IS NULL
            OR current_setting('role', true) = 'none' THEN session_user::text
        ELSE current_setting('role', true)
    END <> 'carl_archive_backend'
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'database_role_denied';
    END IF;
    receipt_value := carl_autonomy.parse_object(
        p_receipt_json, 'coordinator_recovery_archive_invalid'
    );
    artifact_value := receipt_value->'artifact';
    signed_envelope_value := receipt_value->'signed_envelope';
    binding_value := signed_envelope_value->'binding';
    IF carl_autonomy.canonical_jsonb(receipt_value) <> p_receipt_json
        OR carl_autonomy.jsonb_object_cardinality(receipt_value) IS DISTINCT FROM 18
        OR NOT receipt_value ?& ARRAY[
            'archive_byte_length', 'archive_checksum_sha256', 'archive_created_at',
            'archive_object_key', 'archive_version_id', 'artifact', 'domain',
            'evidence_digest', 'retained_until', 'retention_mode', 'schema_version',
            'signed_envelope', 'signature_algorithm', 'signature_base64',
            'signature_expires_at', 'signature_issued_at', 'signature_key_id', 'verified_at'
        ]
        OR receipt_value->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR receipt_value->>'domain'
            <> 'carl.coordinator-recovery-archive-receipt.v1'
        OR jsonb_typeof(signed_envelope_value) <> 'object'
        OR carl_autonomy.jsonb_object_cardinality(signed_envelope_value) IS DISTINCT FROM 10
        OR NOT signed_envelope_value ?& ARRAY[
            'algorithm', 'artifact', 'binding', 'domain', 'expires_at', 'issued_at',
            'key_id', 'purpose', 'schema_version', 'signature_base64'
        ]
        OR signed_envelope_value->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR signed_envelope_value->>'domain'
            <> 'carl.coordinator-recovery-signed-envelope.v1'
        OR signed_envelope_value->>'purpose' <> 'coordinator_node_recovery'
        OR signed_envelope_value->>'algorithm' <> 'Ed25519'
        OR signed_envelope_value->>'key_id'
            !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
        OR signed_envelope_value->>'signature_base64'
            !~ '^[A-Za-z0-9+/]{86}==$'
        OR signed_envelope_value->'artifact' IS DISTINCT FROM artifact_value
        OR jsonb_typeof(binding_value) <> 'object'
        OR carl_autonomy.jsonb_object_cardinality(binding_value) IS DISTINCT FROM 7
        OR NOT binding_value ?& ARRAY[
            'command_key', 'effect_key', 'freeze_fingerprint', 'occurrence_key',
            'reason', 'repair_fingerprint', 'request_digest'
        ]
        OR jsonb_typeof(artifact_value) <> 'object'
        OR carl_autonomy.jsonb_object_cardinality(artifact_value) IS DISTINCT FROM 17
        OR NOT artifact_value ?& ARRAY[
            'attempt', 'changed_action_digest', 'command_key', 'decision_identity',
            'domain', 'effect_key', 'experiment_id', 'freeze_fingerprint', 'node_id',
            'node_kind', 'occurrence_key', 'reason', 'repair_fingerprint', 'repaired_at',
            'request_digest', 'runtime_revision', 'schema_version'
        ]
        OR artifact_value->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR artifact_value->>'domain' <> 'carl.coordinator-recovery-artifact.v1'
        OR artifact_value->>'experiment_id'
            !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
        OR carl_autonomy.coordinator_node_priority(artifact_value->>'node_kind') IS NULL
        OR artifact_value->>'node_id' <> (
            (artifact_value->>'experiment_id') || ':' || (artifact_value->>'node_kind')
        )
        OR jsonb_typeof(artifact_value->'attempt') <> 'number'
        OR (artifact_value->>'attempt')::integer NOT BETWEEN 1 AND 3
        OR artifact_value->>'command_key' <> (
            (artifact_value->>'experiment_id') || ':' || (artifact_value->>'node_kind')
                || ':attempt:' || (artifact_value->>'attempt')
        )
        OR artifact_value->>'effect_key' !~ '^cloud-effect-[0-9a-f]{64}$'
        OR artifact_value->>'occurrence_key'
            <> ('coordinator-freeze/' || (artifact_value->>'freeze_fingerprint'))
        OR NOT carl_autonomy.coordinator_freeze_reason_valid(
            artifact_value->>'node_kind', artifact_value->>'reason'
        )
        OR jsonb_typeof(artifact_value->'runtime_revision') <> 'number'
        OR (artifact_value->>'runtime_revision')::integer NOT BETWEEN 0 AND 2147483646
        OR NOT carl_autonomy.canonical_utc_text_valid(artifact_value->>'repaired_at')
        OR NOT carl_autonomy.canonical_utc_text_valid(receipt_value->>'archive_created_at')
        OR NOT carl_autonomy.canonical_utc_text_valid(receipt_value->>'retained_until')
        OR NOT carl_autonomy.canonical_utc_text_valid(
            signed_envelope_value->>'issued_at'
        )
        OR NOT carl_autonomy.canonical_utc_text_valid(
            signed_envelope_value->>'expires_at'
        )
        OR NOT carl_autonomy.canonical_utc_text_valid(
            receipt_value->>'signature_issued_at'
        )
        OR NOT carl_autonomy.canonical_utc_text_valid(
            receipt_value->>'signature_expires_at'
        )
        OR NOT carl_autonomy.canonical_utc_text_valid(receipt_value->>'verified_at')
        OR (receipt_value->>'verified_at')::timestamptz <> p_observed_at
        OR receipt_value->>'signature_algorithm'
            IS DISTINCT FROM signed_envelope_value->>'algorithm'
        OR receipt_value->>'signature_key_id'
            IS DISTINCT FROM signed_envelope_value->>'key_id'
        OR receipt_value->>'signature_base64'
            IS DISTINCT FROM signed_envelope_value->>'signature_base64'
        OR receipt_value->>'signature_issued_at'
            IS DISTINCT FROM signed_envelope_value->>'issued_at'
        OR receipt_value->>'signature_expires_at'
            IS DISTINCT FROM signed_envelope_value->>'expires_at'
        OR (signed_envelope_value->>'issued_at')::timestamptz
            > (receipt_value->>'archive_created_at')::timestamptz
        OR (artifact_value->>'repaired_at')::timestamptz
            > (signed_envelope_value->>'issued_at')::timestamptz
        OR (receipt_value->>'archive_created_at')::timestamptz > p_observed_at
        OR (signed_envelope_value->>'expires_at')::timestamptz <= p_observed_at
        OR (signed_envelope_value->>'expires_at')::timestamptz
            > (receipt_value->>'retained_until')::timestamptz
        OR (receipt_value->>'retained_until')::timestamptz <= p_observed_at
        OR receipt_value->>'retention_mode' <> 'COMPLIANCE'
        OR receipt_value->>'archive_version_id'
            !~ '^[A-Za-z0-9][A-Za-z0-9._:/+=-]{0,255}$'
        OR jsonb_typeof(receipt_value->'archive_byte_length') <> 'number'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'coordinator_recovery_archive_invalid';
    END IF;
    FOREACH evidence_digest_value IN ARRAY ARRAY[
        artifact_value->>'changed_action_digest',
        artifact_value->>'decision_identity',
        artifact_value->>'freeze_fingerprint',
        artifact_value->>'repair_fingerprint',
        artifact_value->>'request_digest',
        receipt_value->>'archive_checksum_sha256',
        receipt_value->>'evidence_digest'
    ]
    LOOP
        IF evidence_digest_value !~ '^[0-9a-f]{64}$'
            OR evidence_digest_value = repeat('0', 64)
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023', MESSAGE = 'coordinator_recovery_archive_invalid';
        END IF;
    END LOOP;
    artifact_json := carl_autonomy.canonical_jsonb(artifact_value);
    envelope_json := carl_autonomy.canonical_jsonb(signed_envelope_value);
    evidence_digest_value := carl_autonomy.sha256_text(envelope_json);
    identity_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
        'attempt', (artifact_value->>'attempt')::integer,
        'changed_action_digest', artifact_value->>'changed_action_digest',
        'command_key', artifact_value->>'command_key',
        'decision_identity', artifact_value->>'decision_identity',
        'effect_key', artifact_value->>'effect_key',
        'experiment_id', artifact_value->>'experiment_id',
        'freeze_fingerprint', artifact_value->>'freeze_fingerprint',
        'node_id', artifact_value->>'node_id',
        'node_kind', artifact_value->>'node_kind',
        'occurrence_key', artifact_value->>'occurrence_key',
        'reason', artifact_value->>'reason',
        'request_digest', artifact_value->>'request_digest',
        'runtime_revision', (artifact_value->>'runtime_revision')::integer
    ));
    IF receipt_value->>'evidence_digest' <> evidence_digest_value
        OR receipt_value->>'archive_checksum_sha256' <> evidence_digest_value
        OR receipt_value->>'archive_object_key' <> (
            'carl-evidence/v1/sha256/' || substr(evidence_digest_value, 1, 2)
                || '/' || evidence_digest_value
        )
        OR (receipt_value->>'archive_byte_length')::integer <> octet_length(envelope_json)
        OR artifact_value->>'repair_fingerprint'
            <> carl_autonomy.sha256_text(identity_value)
        OR binding_value->>'command_key' <> artifact_value->>'command_key'
        OR binding_value->>'effect_key' <> artifact_value->>'effect_key'
        OR binding_value->>'freeze_fingerprint' <> artifact_value->>'freeze_fingerprint'
        OR binding_value->>'occurrence_key' <> artifact_value->>'occurrence_key'
        OR binding_value->>'reason' <> artifact_value->>'reason'
        OR binding_value->>'repair_fingerprint' <> artifact_value->>'repair_fingerprint'
        OR binding_value->>'request_digest' <> artifact_value->>'request_digest'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'coordinator_recovery_archive_invalid';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(evidence_digest_value, 41));
    SELECT item.* INTO existing
    FROM carl_autonomy.coordinator_recovery_receipts AS item
    WHERE item.evidence_digest = evidence_digest_value;
    IF FOUND THEN
        IF existing.receipt_json = p_receipt_json THEN
            RETURN QUERY SELECT false;
            RETURN;
        END IF;
        RAISE EXCEPTION USING
            ERRCODE = '23505', MESSAGE = 'coordinator_recovery_receipt_conflict';
    END IF;
    SELECT item.* INTO occurrence
    FROM carl_autonomy.coordinator_freeze_occurrences AS item
    WHERE item.occurrence_key = artifact_value->>'occurrence_key'
    FOR SHARE;
    IF NOT FOUND
        OR occurrence.freeze_fingerprint <> artifact_value->>'freeze_fingerprint'
        OR occurrence.experiment_id <> artifact_value->>'experiment_id'
        OR occurrence.node_id <> artifact_value->>'node_id'
        OR occurrence.node_kind <> artifact_value->>'node_kind'
        OR occurrence.attempt <> (artifact_value->>'attempt')::integer
        OR occurrence.reason <> artifact_value->>'reason'
        OR occurrence.command_key <> artifact_value->>'command_key'
        OR occurrence.effect_key <> artifact_value->>'effect_key'
        OR occurrence.request_digest <> artifact_value->>'request_digest'
        OR occurrence.runtime_revision <> (artifact_value->>'runtime_revision')::integer
        OR occurrence.decision_identity <> artifact_value->>'decision_identity'
        OR occurrence.recovered_at IS NOT NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'coordinator_recovery_freeze_mismatch';
    END IF;
    INSERT INTO carl_autonomy.coordinator_recovery_receipts(
        evidence_digest, occurrence_key, freeze_fingerprint, experiment_id, node_id,
        node_kind, attempt, reason, command_key, effect_key, request_digest,
        runtime_revision, decision_identity, changed_action_digest, repair_fingerprint,
        signature_key_id, signature_algorithm, signature_base64,
        signature_issued_at, signature_expires_at,
        archive_object_key, archive_version_id, archive_checksum_sha256,
        archive_byte_length, retention_mode, retained_until, archive_created_at,
        verified_at, receipt_json, registered_at
    ) VALUES (
        evidence_digest_value, artifact_value->>'occurrence_key',
        artifact_value->>'freeze_fingerprint', artifact_value->>'experiment_id',
        artifact_value->>'node_id', artifact_value->>'node_kind',
        (artifact_value->>'attempt')::integer, artifact_value->>'reason',
        artifact_value->>'command_key', artifact_value->>'effect_key',
        artifact_value->>'request_digest',
        (artifact_value->>'runtime_revision')::integer,
        artifact_value->>'decision_identity', artifact_value->>'changed_action_digest',
        artifact_value->>'repair_fingerprint', receipt_value->>'signature_key_id',
        receipt_value->>'signature_algorithm', receipt_value->>'signature_base64',
        (receipt_value->>'signature_issued_at')::timestamptz,
        (receipt_value->>'signature_expires_at')::timestamptz,
        receipt_value->>'archive_object_key',
        receipt_value->>'archive_version_id', receipt_value->>'archive_checksum_sha256',
        (receipt_value->>'archive_byte_length')::integer, receipt_value->>'retention_mode',
        (receipt_value->>'retained_until')::timestamptz,
        (receipt_value->>'archive_created_at')::timestamptz,
        (receipt_value->>'verified_at')::timestamptz, p_receipt_json, p_observed_at
    );
    RETURN QUERY SELECT true;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.reactivate_coordinator_node(
    p_recovery_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean, attempt integer, request_digest text, revision integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    recovery_value jsonb;
    runtime carl_autonomy.coordinator_runtime%ROWTYPE;
    snapshot_value jsonb;
    decision_value jsonb;
    selected_node jsonb;
    repaired_node jsonb;
    repaired_nodes jsonb;
    recovery_receipt carl_autonomy.coordinator_recovery_receipts%ROWTYPE;
    next_attempt integer;
    next_revision integer;
    next_request_digest text;
    next_effect_key text;
    next_effect_family text;
    next_effect_request text;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_supervisor']);
    recovery_value := carl_autonomy.parse_object(
        p_recovery_json, 'coordinator_recovery_request_invalid'
    );
    IF carl_autonomy.canonical_jsonb(recovery_value) <> p_recovery_json
        OR carl_autonomy.jsonb_object_cardinality(recovery_value) IS DISTINCT FROM 9
        OR NOT recovery_value ?& ARRAY[
            'schema_version', 'domain', 'experiment_id', 'node_id', 'node_kind',
            'expected_revision', 'evidence_digest', 'repair_fingerprint', 'requested_at'
        ]
        OR recovery_value->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR recovery_value->>'domain' <> 'carl.coordinator.recovery.v1'
        OR recovery_value->>'experiment_id'
            !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
        OR recovery_value->>'node_id' <> (
            (recovery_value->>'experiment_id') || ':' || (recovery_value->>'node_kind')
        )
        OR carl_autonomy.coordinator_node_priority(recovery_value->>'node_kind') IS NULL
        OR jsonb_typeof(recovery_value->'expected_revision') <> 'number'
        OR (recovery_value->>'expected_revision')::integer NOT BETWEEN 0 AND 2147483646
        OR recovery_value->>'evidence_digest' !~ '^[0-9a-f]{64}$'
        OR recovery_value->>'repair_fingerprint' !~ '^[0-9a-f]{64}$'
        OR NOT carl_autonomy.canonical_utc_text_valid(recovery_value->>'requested_at')
        OR (recovery_value->>'requested_at')::timestamptz > p_observed_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'coordinator_recovery_request_invalid';
    END IF;
    SELECT item.* INTO runtime
    FROM carl_autonomy.coordinator_runtime AS item
    WHERE item.experiment_id = recovery_value->>'experiment_id'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'coordinator_runtime_not_found';
    END IF;
    snapshot_value := carl_autonomy.parse_object(
        runtime.snapshot_json, 'coordinator_snapshot_json_invalid'
    );
    SELECT node INTO selected_node
    FROM jsonb_array_elements(snapshot_value->'nodes') AS node
    WHERE node->>'node_id' = recovery_value->>'node_id';
    IF runtime.repair_fingerprint = recovery_value->>'repair_fingerprint'
        AND runtime.revision = (recovery_value->>'expected_revision')::integer + 1
        AND selected_node->>'kind' = recovery_value->>'node_kind'
    THEN
        RETURN QUERY SELECT false, (selected_node->>'attempt')::integer,
            selected_node->>'request_digest', runtime.revision;
        RETURN;
    END IF;
    IF runtime.status <> 'frozen'
        OR runtime.revision <> (recovery_value->>'expected_revision')::integer
        OR runtime.repair_fingerprint = recovery_value->>'repair_fingerprint'
        OR selected_node IS NULL
        OR selected_node->>'kind' <> recovery_value->>'node_kind'
        OR selected_node->>'status' NOT IN ('ready', 'failed')
        OR (selected_node->>'attempt')::integer >= (selected_node->>'max_attempts')::integer
        OR runtime.decision_json IS NULL
        OR runtime.decision_identity IS NULL
        OR runtime.freeze_reason IS NULL
        OR runtime.freeze_fingerprint IS NULL
        OR runtime.freeze_occurrence_key
            IS DISTINCT FROM 'coordinator-freeze/' || runtime.freeze_fingerprint
        OR runtime.freeze_attempt IS DISTINCT FROM (selected_node->>'attempt')::integer
        OR recovery_value->>'repair_fingerprint' = runtime.freeze_fingerprint
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001', MESSAGE = 'coordinator_recovery_cas_mismatch';
    END IF;
    decision_value := carl_autonomy.parse_object(
        runtime.decision_json, 'coordinator_decision_json_invalid'
    );
    next_effect_family := carl_autonomy.coordinator_effect_family(selected_node->>'kind');
    IF decision_value->>'action' <> 'frozen'
        OR decision_value->>'node' <> selected_node->>'kind'
        OR decision_value->>'reason' IS DISTINCT FROM runtime.freeze_reason
        OR NOT carl_autonomy.coordinator_freeze_reason_valid(
            selected_node->>'kind', runtime.freeze_reason
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'coordinator_recovery_freeze_mismatch';
    END IF;
    SELECT receipt.* INTO recovery_receipt
    FROM carl_autonomy.coordinator_recovery_receipts AS receipt
    WHERE receipt.evidence_digest = recovery_value->>'evidence_digest'
    FOR SHARE;
    IF NOT FOUND
        OR recovery_receipt.repair_fingerprint <> recovery_value->>'repair_fingerprint'
        OR recovery_receipt.occurrence_key <> runtime.freeze_occurrence_key
        OR recovery_receipt.freeze_fingerprint <> runtime.freeze_fingerprint
        OR recovery_receipt.experiment_id <> runtime.experiment_id
        OR recovery_receipt.node_id <> selected_node->>'node_id'
        OR recovery_receipt.node_kind <> selected_node->>'kind'
        OR recovery_receipt.attempt <> (selected_node->>'attempt')::integer
        OR recovery_receipt.reason <> runtime.freeze_reason
        OR recovery_receipt.command_key <> selected_node->>'command_key'
        OR recovery_receipt.effect_key <> selected_node->>'effect_key'
        OR recovery_receipt.request_digest <> selected_node->>'request_digest'
        OR recovery_receipt.runtime_revision <> runtime.revision
        OR recovery_receipt.decision_identity <> runtime.decision_identity
        OR recovery_receipt.archive_checksum_sha256
            <> recovery_receipt.evidence_digest
        OR recovery_receipt.archive_object_key
            <> 'carl-evidence/v1/sha256/'
                || substr(recovery_receipt.evidence_digest, 1, 2)
                || '/' || recovery_receipt.evidence_digest
        OR recovery_receipt.signature_algorithm <> 'Ed25519'
        OR recovery_receipt.signature_issued_at > recovery_receipt.archive_created_at
        OR recovery_receipt.signature_expires_at <= p_observed_at
        OR recovery_receipt.signature_expires_at > recovery_receipt.retained_until
        OR recovery_receipt.retention_mode <> 'COMPLIANCE'
        OR recovery_receipt.registered_at > p_observed_at
        OR recovery_receipt.archive_created_at > recovery_receipt.verified_at
        OR recovery_receipt.verified_at > p_observed_at
        OR recovery_receipt.retained_until <= p_observed_at
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'coordinator_recovery_evidence_invalid';
    END IF;
    next_attempt := (selected_node->>'attempt')::integer + 1;
    next_revision := runtime.revision + 1;
    next_request_digest := carl_autonomy.sha256_text(carl_autonomy.canonical_jsonb(
        jsonb_build_object(
            'attempt', next_attempt,
            'node_id', selected_node->>'node_id',
            'prior_request_digest', selected_node->>'request_digest',
            'repair_fingerprint', recovery_value->>'repair_fingerprint'
        )
    ));
    repaired_node := jsonb_set(
        jsonb_set(
            jsonb_set(
                jsonb_set(
                    selected_node,
                    '{attempt}',
                    to_jsonb(next_attempt),
                    false
                ),
                '{command_key}',
                to_jsonb(
                    (recovery_value->>'experiment_id') || ':' || (selected_node->>'kind')
                        || ':attempt:' || next_attempt::text
                ),
                false
            ),
            '{request_digest}',
            to_jsonb(next_request_digest),
            false
        ),
        '{occurred_at}',
        to_jsonb(recovery_value->>'requested_at'),
        false
    );
    repaired_node := jsonb_set(repaired_node, '{status}', '"ready"'::jsonb, false);
    SELECT jsonb_agg(
        CASE WHEN node->>'node_id' = recovery_value->>'node_id' THEN repaired_node ELSE node END
        ORDER BY ordinal
    ) INTO repaired_nodes
    FROM jsonb_array_elements(snapshot_value->'nodes')
        WITH ORDINALITY AS value(node, ordinal);
    snapshot_value := jsonb_set(snapshot_value, '{nodes}', repaired_nodes, false);
    snapshot_value := jsonb_set(snapshot_value, '{failure}', 'null'::jsonb, false);
    snapshot_value := jsonb_set(
        snapshot_value, '{revision}', to_jsonb(next_revision), false
    );
    snapshot_value := jsonb_set(
        snapshot_value, '{observed_at}', to_jsonb(recovery_value->>'requested_at'), false
    );
    next_effect_key := 'cloud-effect-' || carl_autonomy.sha256_text(
        carl_autonomy.canonical_jsonb(jsonb_build_object(
            'authority', repaired_node->>'authority',
            'command_key', repaired_node->>'command_key',
            'operation', repaired_node->>'operation',
            'request_digest', repaired_node->>'request_digest'
        ))
    );
    next_effect_request := CASE WHEN next_effect_family <> 'github' THEN
        carl_autonomy.canonical_jsonb(jsonb_build_object(
            'command_key', repaired_node->>'command_key',
            'domain', 'carl.coordinator-node-effect.request.v1',
            'effect_key', next_effect_key,
            'family', next_effect_family,
            'node_kind', repaired_node->>'kind',
            'occurred_at', repaired_node->>'occurred_at',
            'request_digest', repaired_node->>'request_digest',
            'schema_version', 1
        ))
        ELSE NULL
    END;
    UPDATE carl_autonomy.coordinator_freeze_occurrences AS occurrence
    SET recovery_evidence_digest = recovery_value->>'evidence_digest',
        recovery_fingerprint = recovery_value->>'repair_fingerprint',
        recovered_at = p_observed_at
    WHERE occurrence.occurrence_key = runtime.freeze_occurrence_key
        AND occurrence.freeze_fingerprint = runtime.freeze_fingerprint
        AND occurrence.experiment_id = runtime.experiment_id
        AND occurrence.node_id = selected_node->>'node_id'
        AND occurrence.node_kind = selected_node->>'kind'
        AND occurrence.attempt = (selected_node->>'attempt')::integer
        AND occurrence.reason = runtime.freeze_reason
        AND occurrence.command_key = selected_node->>'command_key'
        AND occurrence.effect_key = selected_node->>'effect_key'
        AND occurrence.request_digest = selected_node->>'request_digest'
        AND occurrence.runtime_revision = runtime.revision
        AND occurrence.decision_identity = runtime.decision_identity
        AND occurrence.decision_json = runtime.decision_json
        AND occurrence.recovery_evidence_digest IS NULL
        AND occurrence.recovery_fingerprint IS NULL
        AND occurrence.recovered_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'coordinator_freeze_occurrence_missing';
    END IF;
    UPDATE carl_autonomy.coordinator_runtime AS item
    SET snapshot_json = carl_autonomy.canonical_jsonb(snapshot_value),
        snapshot_digest = carl_autonomy.sha256_text(
            carl_autonomy.canonical_jsonb(snapshot_value)
        ),
        completion_event_json = NULL,
        completion_event_digest = NULL,
        effect_family = CASE WHEN next_effect_request IS NULL THEN NULL ELSE next_effect_family END,
        effect_request_json = next_effect_request,
        effect_request_digest = CASE
            WHEN next_effect_request IS NULL THEN NULL
            ELSE carl_autonomy.sha256_text(next_effect_request)
        END,
        effect_response_json = NULL,
        decision_identity = NULL,
        decision_json = NULL,
        repair_fingerprint = recovery_value->>'repair_fingerprint',
        freeze_reason = NULL,
        freeze_fingerprint = NULL,
        freeze_occurrence_key = NULL,
        freeze_attempt = NULL,
        revision = next_revision,
        status = 'ready',
        updated_at = p_observed_at
    WHERE item.experiment_id = runtime.experiment_id;
    RETURN QUERY SELECT true, next_attempt, next_request_digest, next_revision;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.coordinator_frozen_status(p_command_name text)
RETURNS TABLE(already_frozen boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    RETURN QUERY SELECT EXISTS (
        SELECT 1
        FROM carl_autonomy.coordinator_runtime AS runtime
        CROSS JOIN LATERAL (
            SELECT node
            FROM jsonb_array_elements(
                carl_autonomy.parse_object(
                    runtime.snapshot_json, 'coordinator_snapshot_json_invalid'
                )->'nodes'
            ) AS active(node)
            WHERE node->>'status' IN ('ready', 'failed')
            ORDER BY carl_autonomy.coordinator_node_priority(node->>'kind'), node->>'node_id'
            LIMIT 1
        ) AS selected_node
        WHERE runtime.status = 'frozen'
            AND runtime.freeze_occurrence_key IS NOT NULL
            AND runtime.freeze_fingerprint IS NOT NULL
            AND runtime.freeze_reason IS NOT NULL
            AND carl_autonomy.coordinator_command_allows_node(
                p_command_name, selected_node.node->>'kind'
            )
    );
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.load_coordinator_snapshot(
    p_command_name text,
    p_observed_at timestamptz
)
RETURNS TABLE(snapshot_json text, production_receipts_json text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    selected carl_autonomy.coordinator_runtime%ROWTYPE;
    snapshot_value jsonb;
    ready_node jsonb;
    command_value jsonb;
    effect_value jsonb;
    receipt_value jsonb;
    command_state carl_autonomy.commands%ROWTYPE;
    lease_state carl_autonomy.leases%ROWTYPE;
    effect_state carl_autonomy.effect_attempts%ROWTYPE;
    coordinator_effect_state carl_autonomy.coordinator_effect_occurrences%ROWTYPE;
    response_value jsonb;
    guard_state carl_autonomy.experiment_projection_guards%ROWTYPE;
    archive_state carl_autonomy.evidence_objects%ROWTYPE;
    checks_state carl_autonomy.evidence_objects%ROWTYPE;
    protection_state carl_autonomy.evidence_objects%ROWTYPE;
    dead_holder_digest text;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    SELECT runtime.* INTO selected
    FROM carl_autonomy.coordinator_runtime AS runtime
    CROSS JOIN LATERAL (
        SELECT node
        FROM jsonb_array_elements(
            carl_autonomy.parse_object(
                runtime.snapshot_json, 'coordinator_snapshot_json_invalid'
            )->'nodes'
        ) AS active(node)
        WHERE node->>'status' IN ('ready', 'failed')
        ORDER BY carl_autonomy.coordinator_node_priority(node->>'kind'), node->>'node_id'
        LIMIT 1
    ) AS selected_node
    WHERE runtime.status NOT IN ('complete', 'frozen')
        AND carl_autonomy.coordinator_command_allows_node(
            p_command_name, selected_node.node->>'kind'
        )
    ORDER BY runtime.updated_at, runtime.experiment_id
    FOR UPDATE SKIP LOCKED
    LIMIT 1;
    IF NOT FOUND THEN
        RETURN QUERY SELECT NULL::text, NULL::text;
        RETURN;
    END IF;
    IF carl_autonomy.sha256_text(selected.snapshot_json) <> selected.snapshot_digest THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_snapshot_digest_mismatch';
    END IF;
    snapshot_value := carl_autonomy.parse_object(
        selected.snapshot_json, 'coordinator_snapshot_json_invalid'
    );
    IF snapshot_value->>'experiment_id' <> selected.experiment_id
        OR (snapshot_value->>'revision')::integer <> selected.revision
        OR snapshot_value->'command' IS DISTINCT FROM 'null'::jsonb
        OR snapshot_value->'effect' IS DISTINCT FROM 'null'::jsonb
        OR snapshot_value->'lease' IS DISTINCT FROM 'null'::jsonb
        OR snapshot_value->'dead_holder_observation_digest' IS DISTINCT FROM 'null'::jsonb
        OR snapshot_value->'production_authorization' IS DISTINCT FROM 'null'::jsonb
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'coordinator_snapshot_mutable_input_forbidden';
    END IF;
    SELECT node INTO ready_node
    FROM jsonb_array_elements(snapshot_value->'nodes') AS node
    WHERE node->>'status' IN ('ready', 'failed')
    ORDER BY carl_autonomy.coordinator_node_priority(node->>'kind'), node->>'node_id'
    LIMIT 1;
    IF ready_node IS NOT NULL THEN
        SELECT command.* INTO command_state
        FROM carl_autonomy.commands AS command
        WHERE command.command_key = ready_node->>'command_key';
        IF FOUND THEN
            command_value := jsonb_build_object(
                'claim', CASE
                    WHEN command_state.claim_json IS NULL THEN NULL
                    ELSE carl_autonomy.parse_object(
                        command_state.claim_json, 'coordinator_claim_json_invalid'
                    )
                END,
                'command', carl_autonomy.parse_object(
                    command_state.command_json, 'coordinator_command_json_invalid'
                ),
                'failure_code', command_state.failure_code,
                'result_digest', command_state.result_digest,
                'revision', command_state.revision,
                'status', command_state.status,
                'transition', CASE
                    WHEN command_state.transition_json IS NULL THEN NULL
                    ELSE carl_autonomy.parse_object(
                        command_state.transition_json, 'coordinator_transition_json_invalid'
                    )
                END
            );
        END IF;
    END IF;
    SELECT lease.* INTO lease_state
    FROM carl_autonomy.leases AS lease
    WHERE lease.lease_key = selected.experiment_id || ':coordinator';
    IF FOUND THEN
        snapshot_value := jsonb_set(
            snapshot_value,
            '{lease}',
            carl_autonomy.parse_object(lease_state.lease_json, 'coordinator_lease_json_invalid'),
            false
        );
        SELECT observation.observation_digest::text INTO dead_holder_digest
        FROM carl_autonomy.dead_holder_observations AS observation
        WHERE observation.authority = lease_state.authority
            AND observation.subject_id = lease_state.holder_id
            AND observation.scope_kind = 'lease'
            AND observation.scope_key = lease_state.lease_key
            AND observation.revision = lease_state.revision
            AND NOT observation.live
            AND observation.expires_at > p_observed_at
        ORDER BY observation.registered_at DESC, observation.observation_digest
        LIMIT 1;
    END IF;
    IF command_state.command_key IS NOT NULL THEN
        SELECT attempt.* INTO effect_state
        FROM carl_autonomy.effect_attempts AS attempt
        WHERE attempt.effect_key = command_state.effect_key;
        IF FOUND THEN
            effect_value := CASE effect_state.attempt_state
                WHEN 'retry_scheduled' THEN jsonb_build_object(
                    'effect_key', effect_state.effect_key,
                    'observed_at', effect_state.observed_at_text,
                    'result_digest', NULL,
                    'retry_not_before', effect_state.not_before_text,
                    'status', 'retry_scheduled'
                )
                WHEN 'uncertain' THEN jsonb_build_object(
                    'effect_key', effect_state.effect_key,
                    'observed_at', effect_state.observed_at_text,
                    'result_digest', NULL,
                    'retry_not_before', NULL,
                    'status', 'uncertain'
                )
                WHEN 'completed' THEN jsonb_build_object(
                    'effect_key', effect_state.effect_key,
                    'observed_at', effect_state.observed_at_text,
                    'result_digest', effect_state.result_digest,
                    'retry_not_before', NULL,
                    'status', 'applied'
                )
                ELSE NULL
            END;
        END IF;
    END IF;
    IF effect_value IS NULL
        AND selected.effect_family IS NOT NULL
        AND selected.effect_family <> 'github'
    THEN
        SELECT occurrence.* INTO coordinator_effect_state
        FROM carl_autonomy.coordinator_effect_occurrences AS occurrence
        WHERE occurrence.experiment_id = selected.experiment_id
            AND occurrence.effect_key = command_state.effect_key;
        IF FOUND AND coordinator_effect_state.status IN ('effect_prepared', 'in_progress') THEN
            effect_value := jsonb_build_object(
                'effect_key', coordinator_effect_state.effect_key,
                'observed_at', carl_autonomy.coordinator_timestamp(
                    coordinator_effect_state.updated_at
                ),
                'result_digest', NULL,
                'retry_not_before', NULL,
                'status', 'uncertain'
            );
        END IF;
    END IF;
    IF effect_value IS NULL
        AND selected.effect_family IS NOT NULL
        AND selected.effect_family <> 'github'
        AND selected.effect_response_json IS NOT NULL
    THEN
        response_value := carl_autonomy.parse_object(
            selected.effect_response_json, 'coordinator_effect_response_json_invalid'
        );
        effect_value := CASE response_value->>'status'
            WHEN 'retry_scheduled' THEN jsonb_build_object(
                'effect_key', command_state.effect_key,
                'observed_at', response_value->>'observed_at',
                'result_digest', NULL,
                'retry_not_before', response_value->>'retry_not_before',
                'status', 'retry_scheduled'
            )
            WHEN 'uncertain' THEN jsonb_build_object(
                'effect_key', command_state.effect_key,
                'observed_at', response_value->>'observed_at',
                'result_digest', NULL,
                'retry_not_before', NULL,
                'status', 'uncertain'
            )
            WHEN 'completed' THEN jsonb_build_object(
                'effect_key', command_state.effect_key,
                'observed_at', response_value->>'observed_at',
                'result_digest', response_value->>'result_digest',
                'retry_not_before', NULL,
                'status', 'applied'
            )
            ELSE NULL
        END;
    END IF;
    snapshot_value := jsonb_set(
        snapshot_value, '{command}', COALESCE(command_value, 'null'::jsonb), false
    );
    snapshot_value := jsonb_set(
        snapshot_value, '{effect}', COALESCE(effect_value, 'null'::jsonb), false
    );
    snapshot_value := jsonb_set(
        snapshot_value,
        '{dead_holder_observation_digest}',
        COALESCE(to_jsonb(dead_holder_digest), 'null'::jsonb),
        false
    );
    snapshot_value := jsonb_set(
        snapshot_value,
        '{observed_at}',
        to_jsonb(carl_autonomy.coordinator_timestamp(p_observed_at)),
        false
    );
    snapshot_value := jsonb_set(
        snapshot_value, '{production_authorization}', 'null'::jsonb, false
    );
    IF selected.production_receipts_json IS NOT NULL AND ready_node IS NOT NULL THEN
        IF carl_autonomy.sha256_text(selected.production_receipts_json)
            <> selected.production_receipts_digest
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'coordinator_production_receipt_digest_mismatch';
        END IF;
        receipt_value := carl_autonomy.parse_object(
            selected.production_receipts_json,
            'coordinator_production_receipts_json_invalid'
        );
        IF receipt_value->'verified_at' IS DISTINCT FROM 'null'::jsonb THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'coordinator_production_receipt_clock_forbidden';
        END IF;
        receipt_value := jsonb_set(
            receipt_value,
            '{verified_at}',
            to_jsonb(carl_autonomy.coordinator_timestamp(p_observed_at)),
            false
        );
        SELECT guard.* INTO guard_state
        FROM carl_autonomy.experiment_projection_guards AS guard
        WHERE guard.experiment_id = selected.experiment_id;
        SELECT evidence.* INTO archive_state
        FROM carl_autonomy.evidence_objects AS evidence
        WHERE evidence.digest = receipt_value->>'archive_receipt_digest';
        IF receipt_value->>'required_checks_receipt_digest' IS NOT NULL THEN
            SELECT evidence.* INTO checks_state
            FROM carl_autonomy.evidence_objects AS evidence
            WHERE evidence.digest = receipt_value->>'required_checks_receipt_digest';
        END IF;
        IF receipt_value->>'branch_protection_receipt_digest' IS NOT NULL THEN
            SELECT evidence.* INTO protection_state
            FROM carl_autonomy.evidence_objects AS evidence
            WHERE evidence.digest = receipt_value->>'branch_protection_receipt_digest';
        END IF;
        IF archive_state.digest IS NULL
            OR receipt_value->>'experiment_id' <> selected.experiment_id
            OR receipt_value->>'node_kind' <> ready_node->>'kind'
            OR receipt_value->>'request_digest' <> ready_node->>'request_digest'
            OR receipt_value->>'repository' <> 'StephenBickel/carl-agent'
            OR receipt_value->>'candidate_commit' IS DISTINCT FROM guard_state.experimental_commit
            OR receipt_value->>'candidate_tree' IS DISTINCT FROM guard_state.experimental_tree
            OR receipt_value->>'experimental_ref'
                IS DISTINCT FROM ('refs/heads/' || guard_state.experimental_branch)
            OR receipt_value->>'experimental_receipt_digest'
                IS DISTINCT FROM guard_state.experimental_candidate_packet_digest
            OR receipt_value->>'live_provenance_receipt_digest'
                IS DISTINCT FROM guard_state.protected_validation_receipt_digest
            OR receipt_value->>'independent_disposition_receipt_digest'
                IS DISTINCT FROM guard_state.paired_evidence_digest
            OR guard_state.paired_decision <> 'improvement'
            OR archive_state.request_digest <> ready_node->>'request_digest'
            OR archive_state.retained_until_text <> receipt_value->>'archive_retain_until'
            OR archive_state.retained_until <= p_observed_at
            OR receipt_value->>'verified_at'
                <> carl_autonomy.coordinator_timestamp(p_observed_at)
            OR (
                ready_node->>'kind' IN ('create_promotion_pr', 'create_revert')
                AND (
                    receipt_value->>'pull_request_number' IS NOT NULL
                    OR receipt_value->>'pull_request_head' IS NOT NULL
                    OR receipt_value->>'pull_request_base' IS NOT NULL
                )
            )
            OR (
                ready_node->>'kind' NOT IN ('create_promotion_pr', 'create_revert')
                AND (
                    jsonb_typeof(receipt_value->'pull_request_number') <> 'number'
                    OR (receipt_value->>'pull_request_number')::integer <= 0
                    OR receipt_value->>'pull_request_head'
                        !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
                    OR receipt_value->>'pull_request_base' <> 'main'
                )
            )
            OR (
                receipt_value->>'required_checks_receipt_digest' IS NOT NULL
                AND (
                    checks_state.digest IS NULL
                    OR checks_state.request_digest <> ready_node->>'request_digest'
                    OR checks_state.retained_until <= p_observed_at
                    OR checks_state.recorded_at > p_observed_at
                    OR checks_state.recorded_at < p_observed_at - interval '15 minutes'
                    OR carl_autonomy.parse_object(
                        checks_state.evidence_json,
                        'coordinator_required_checks_evidence_invalid'
                    )->>'digest' <> receipt_value->>'required_checks_receipt_digest'
                    OR carl_autonomy.parse_object(
                        checks_state.evidence_json,
                        'coordinator_required_checks_evidence_invalid'
                    )->>'object_key' <> checks_state.object_key
                    OR carl_autonomy.parse_object(
                        checks_state.evidence_json,
                        'coordinator_required_checks_evidence_invalid'
                    )->>'object_version' <> checks_state.object_version
                    OR carl_autonomy.parse_object(
                        checks_state.evidence_json,
                        'coordinator_required_checks_evidence_invalid'
                    )->>'request_digest' <> checks_state.request_digest
                    OR carl_autonomy.parse_object(
                        checks_state.evidence_json,
                        'coordinator_required_checks_evidence_invalid'
                    )->>'retained_until' <> checks_state.retained_until_text
                )
            )
            OR (
                receipt_value->>'branch_protection_receipt_digest' IS NOT NULL
                AND (
                    protection_state.digest IS NULL
                    OR protection_state.request_digest <> ready_node->>'request_digest'
                    OR protection_state.retained_until <= p_observed_at
                    OR protection_state.recorded_at > p_observed_at
                    OR protection_state.recorded_at < p_observed_at - interval '15 minutes'
                    OR carl_autonomy.parse_object(
                        protection_state.evidence_json,
                        'coordinator_branch_protection_evidence_invalid'
                    )->>'digest' <> receipt_value->>'branch_protection_receipt_digest'
                    OR carl_autonomy.parse_object(
                        protection_state.evidence_json,
                        'coordinator_branch_protection_evidence_invalid'
                    )->>'object_key' <> protection_state.object_key
                    OR carl_autonomy.parse_object(
                        protection_state.evidence_json,
                        'coordinator_branch_protection_evidence_invalid'
                    )->>'object_version' <> protection_state.object_version
                    OR carl_autonomy.parse_object(
                        protection_state.evidence_json,
                        'coordinator_branch_protection_evidence_invalid'
                    )->>'request_digest' <> protection_state.request_digest
                    OR carl_autonomy.parse_object(
                        protection_state.evidence_json,
                        'coordinator_branch_protection_evidence_invalid'
                    )->>'retained_until' <> protection_state.retained_until_text
                )
            )
            OR (
                receipt_value->>'merge_commit' IS NOT NULL
                AND (
                    receipt_value->>'merge_commit'
                        IS DISTINCT FROM guard_state.promotion_merge_commit
                    OR receipt_value->>'merge_tree'
                        IS DISTINCT FROM guard_state.promotion_merge_tree
                    OR (receipt_value->>'merged_at')::timestamptz
                        IS DISTINCT FROM guard_state.promotion_merged_at
                )
            )
            OR (
                receipt_value->>'soak_observation_digest' IS NOT NULL
                AND NOT EXISTS (
                    SELECT 1 FROM carl_autonomy.experiment_events AS soak
                    WHERE soak.experiment_id = selected.experiment_id
                        AND soak.event_type = 'soak_observed'
                        AND soak.payload_json::jsonb->>'evidence_digest'
                            = receipt_value->>'soak_observation_digest'
                        AND soak.payload_json::jsonb->>'merge_commit'
                            = receipt_value->>'merge_commit'
                        AND soak.occurred_at_text = receipt_value->>'soak_observed_at'
                        AND soak.payload_json::jsonb->'healthy' = 'true'::jsonb
                        AND soak.occurred_at >= guard_state.promotion_merged_at
                            + interval '24 hours'
                        AND p_observed_at >= guard_state.promotion_merged_at
                            + interval '24 hours'
                        AND guard_state.soak_failure_digest IS NULL
                        AND NOT EXISTS (
                            SELECT 1
                            FROM carl_autonomy.experiment_events AS hard_failure
                            WHERE hard_failure.experiment_id = selected.experiment_id
                                AND hard_failure.event_type = 'soak_observed'
                                AND hard_failure.payload_json::jsonb->>'merge_commit'
                                    = receipt_value->>'merge_commit'
                                AND hard_failure.payload_json::jsonb->'healthy'
                                    = 'false'::jsonb
                                AND hard_failure.occurred_at >= soak.occurred_at
                                AND hard_failure.occurred_at <= p_observed_at
                        )
                )
            )
            OR (
                ready_node->>'kind' IN ('create_revert', 'observe_revert')
                AND (
                    receipt_value->>'hard_failure_digest'
                        IS DISTINCT FROM guard_state.soak_failure_digest
                    OR receipt_value->>'revert_candidate_commit'
                        !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
                )
            )
            OR (
                ready_node->>'kind' NOT IN ('create_revert', 'observe_revert')
                AND (
                    receipt_value->>'hard_failure_digest' IS NOT NULL
                    OR receipt_value->>'revert_candidate_commit' IS NOT NULL
                )
            )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'coordinator_production_receipt_mismatch';
        END IF;
        IF receipt_value->>'required_checks_receipt_digest' IS NOT NULL THEN
            receipt_value := receipt_value || jsonb_build_object(
                'required_checks_object_key', checks_state.object_key,
                'required_checks_object_version', checks_state.object_version,
                'required_checks_recorded_at',
                    carl_autonomy.coordinator_timestamp(checks_state.recorded_at),
                'required_checks_retain_until', checks_state.retained_until_text,
                'branch_protection_object_key', protection_state.object_key,
                'branch_protection_object_version', protection_state.object_version,
                'branch_protection_recorded_at',
                    carl_autonomy.coordinator_timestamp(protection_state.recorded_at),
                'branch_protection_retain_until', protection_state.retained_until_text
            );
        END IF;
    END IF;
    RETURN QUERY SELECT
        carl_autonomy.canonical_jsonb(snapshot_value),
        CASE
            WHEN receipt_value IS NULL THEN NULL
            ELSE carl_autonomy.canonical_jsonb(receipt_value)
        END;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.renew_coordinator_lease(
    p_lease_key text,
    p_holder_id text,
    p_expected_revision integer,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean, lease_json text, revision integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    current_state carl_autonomy.leases%ROWTYPE;
    expires_time timestamptz;
    expires_text text;
    document text;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    SELECT lease.* INTO current_state
    FROM carl_autonomy.leases AS lease
    WHERE lease.lease_key = p_lease_key
    FOR UPDATE;
    IF NOT FOUND OR current_state.status <> 'active'
        OR current_state.authority <> 'coordinator'
        OR current_state.holder_id <> p_holder_id
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_lease_renewal_mismatch';
    END IF;
    IF current_state.revision <> p_expected_revision
        OR p_expected_revision = 2147483647
    THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'coordinator_lease_renewal_cas_mismatch';
    END IF;
    IF p_observed_at >= current_state.expires_at
        OR current_state.expires_at - p_observed_at > interval '5 minutes'
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_lease_renewal_not_due';
    END IF;
    expires_time := p_observed_at + interval '30 minutes';
    expires_text := carl_autonomy.coordinator_timestamp(expires_time);
    document := carl_autonomy.lease_document(
        current_state.lease_key,
        current_state.holder_id,
        current_state.authority,
        current_state.revision + 1,
        current_state.acquired_at_text,
        expires_text,
        NULL,
        NULL,
        NULL
    );
    UPDATE carl_autonomy.leases AS lease
    SET lease_json = document,
        revision = current_state.revision + 1,
        expires_at = expires_time,
        expires_at_text = expires_text,
        updated_at = p_observed_at
    WHERE lease.lease_key = current_state.lease_key;
    RETURN QUERY SELECT *
    FROM carl_autonomy.lease_result(current_state.lease_key, true);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.complete_coordinator_node_event(
    p_transition_json text,
    p_event_json text,
    p_event_digest text,
    p_payload_json text,
    p_node_kind text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    transition_value jsonb;
    event_value jsonb;
    runtime carl_autonomy.coordinator_runtime%ROWTYPE;
    snapshot_value jsonb;
    selected_node jsonb;
    command_state carl_autonomy.commands%ROWTYPE;
    event_authority text;
    command_result record;
    event_result record;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    transition_value := carl_autonomy.parse_object(
        p_transition_json, 'coordinator_transition_invalid'
    );
    event_value := carl_autonomy.parse_object(p_event_json, 'coordinator_event_invalid');
    event_authority := carl_autonomy.coordinator_node_event_authority(
        p_node_kind, event_value->>'event_type'
    );
    SELECT item.* INTO runtime
    FROM carl_autonomy.coordinator_runtime AS item
    WHERE item.experiment_id = event_value->>'experiment_id'
    FOR UPDATE;
    IF NOT FOUND OR event_authority IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501', MESSAGE = 'coordinator_node_event_authority_denied';
    END IF;
    snapshot_value := carl_autonomy.parse_object(
        runtime.snapshot_json, 'coordinator_snapshot_json_invalid'
    );
    SELECT node INTO selected_node
    FROM jsonb_array_elements(snapshot_value->'nodes') AS node
    WHERE node->>'status' IN ('ready', 'failed')
    ORDER BY carl_autonomy.coordinator_node_priority(node->>'kind'), node->>'node_id'
    LIMIT 1;
    SELECT command.* INTO command_state
    FROM carl_autonomy.commands AS command
    WHERE command.command_key = transition_value->>'command_key'
    FOR UPDATE;
    IF NOT FOUND
        OR selected_node->>'kind' <> p_node_kind
        OR selected_node->>'node_id'
            <> (runtime.experiment_id || ':' || p_node_kind)
        OR selected_node->>'command_key' <> command_state.command_key
        OR command_state.authority
            <> carl_autonomy.coordinator_node_authority(p_node_kind)
        OR command_state.authority NOT IN ('observer', 'supervisor')
        OR event_value->>'stage_attempt_id' <> (
            'coordinator-event-' || substr(carl_autonomy.sha256_text(
                carl_autonomy.canonical_jsonb(jsonb_build_object(
                    'attempt', (selected_node->>'attempt')::integer,
                    'experiment_id', runtime.experiment_id,
                    'node_kind', p_node_kind
                ))
            ), 1, 64)
        )
        OR carl_autonomy.sha256_text(p_event_json) <> p_event_digest
        OR event_value->'payload' <> carl_autonomy.parse_object(
            p_payload_json, 'coordinator_event_payload_invalid'
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501', MESSAGE = 'coordinator_node_event_authority_denied';
    END IF;
    PERFORM set_config('carl_autonomy.authority', command_state.authority, true);
    SELECT * INTO STRICT command_result
    FROM carl_autonomy.terminal_command(p_transition_json, 'completed', p_observed_at);
    PERFORM set_config('carl_autonomy.authority', event_authority, true);
    SELECT * INTO STRICT event_result
    FROM carl_autonomy.append_event(
        p_event_json, p_event_digest, p_payload_json, p_observed_at
    );
    PERFORM set_config('carl_autonomy.authority', 'coordinator', true);
    RETURN QUERY SELECT command_result.applied;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.apply_coordinator_decision_unchecked(
    p_decision_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean, decision_json text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    decision_value jsonb;
    runtime carl_autonomy.coordinator_runtime%ROWTYPE;
    snapshot_value jsonb;
    ready_node jsonb;
    command_value jsonb;
    identity_value jsonb;
    lease_value text;
    reconciliation_value text;
    release_value text;
    claim_value text;
    transition_value text;
    trigger_value text;
    next_effect_family text;
    next_effect_request text;
    existing_effect_request jsonb;
    event_value jsonb;
    nodes_value jsonb;
    next_revision integer;
    next_status text;
    dead_holder_digest text;
    command_state carl_autonomy.commands%ROWTYPE;
    lease_state carl_autonomy.leases%ROWTYPE;
    claim_result record;
    create_result record;
    lease_result record;
    completion_result record;
    trigger_result record;
    freeze_fingerprint_value text;
    expected_completion record;
    existing_completion carl_autonomy.coordinator_completion_receipts%ROWTYPE;
    existing_freeze carl_autonomy.coordinator_freeze_occurrences%ROWTYPE;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    decision_value := carl_autonomy.parse_object(
        p_decision_json, 'coordinator_decision_json_invalid'
    );
    IF decision_value->>'schema_version' <> '1'
        OR decision_value->>'consequential' <> 'true'
        OR decision_value->>'remote_effect' <> 'false'
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'coordinator_decision_invalid';
    END IF;
    SELECT item.* INTO runtime
    FROM carl_autonomy.coordinator_runtime AS item
    WHERE item.experiment_id = decision_value->>'experiment_id'
        AND item.revision = (decision_value->>'revision')::integer
    FOR UPDATE SKIP LOCKED;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'coordinator_decision_cas_mismatch';
    END IF;
    IF runtime.decision_identity = decision_value->>'identity'
        AND runtime.decision_json = p_decision_json
    THEN
        RETURN QUERY SELECT false, runtime.decision_json;
        RETURN;
    END IF;
    IF carl_autonomy.sha256_text(runtime.snapshot_json) <> runtime.snapshot_digest THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_snapshot_digest_mismatch';
    END IF;
    snapshot_value := carl_autonomy.parse_object(
        runtime.snapshot_json, 'coordinator_snapshot_json_invalid'
    );
    SELECT node INTO ready_node
    FROM jsonb_array_elements(snapshot_value->'nodes') AS node
    WHERE node->>'status' IN ('ready', 'failed')
    ORDER BY carl_autonomy.coordinator_node_priority(node->>'kind'), node->>'node_id'
    LIMIT 1;
    IF decision_value->>'node' IS NOT NULL AND (
        ready_node IS NULL OR decision_value->>'node' <> ready_node->>'kind'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_decision_node_mismatch';
    END IF;
    command_value := decision_value->'command';
    identity_value := jsonb_build_object(
        'action', decision_value->>'action',
        'experiment_id', runtime.experiment_id,
        'reason', decision_value->>'reason',
        'revision', runtime.revision
    );
    IF ready_node IS NOT NULL AND decision_value->>'node' IS NOT NULL THEN
        identity_value := identity_value || jsonb_build_object('node_id', ready_node->>'node_id');
    END IF;
    IF command_value IS NOT NULL AND command_value <> 'null'::jsonb THEN
        identity_value := identity_value || jsonb_build_object(
            'command_key', command_value->>'command_key',
            'effect_key', command_value->>'effect_key'
        );
    END IF;
    IF carl_autonomy.sha256_text(carl_autonomy.canonical_jsonb(identity_value))
        <> decision_value->>'identity'
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_decision_identity_mismatch';
    END IF;
    next_revision := runtime.revision;
    next_status := runtime.status;
    CASE decision_value->>'action'
        WHEN 'acquire_lease' THEN
            SELECT lease.* INTO lease_state
            FROM carl_autonomy.leases AS lease
            WHERE lease.lease_key = runtime.experiment_id || ':coordinator';
            lease_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
                'acquired_at', carl_autonomy.coordinator_timestamp(p_observed_at),
                'authority', 'coordinator',
                'expires_at', carl_autonomy.coordinator_timestamp(
                    p_observed_at + interval '30 minutes'
                ),
                'holder_id', snapshot_value->>'coordinator_id',
                'lease_key', runtime.experiment_id || ':coordinator',
                'reconciled_at', NULL,
                'reconciliation_observation_digest', NULL,
                'released_at', NULL,
                'revision', CASE WHEN FOUND THEN lease_state.revision ELSE 0 END
            ));
            PERFORM set_config('carl_autonomy.authority', 'coordinator', true);
            SELECT * INTO lease_result
            FROM carl_autonomy.acquire_lease(lease_value, p_observed_at);
        WHEN 'renew_lease' THEN
            SELECT lease.* INTO lease_state
            FROM carl_autonomy.leases AS lease
            WHERE lease.lease_key = runtime.experiment_id || ':coordinator';
            SELECT * INTO lease_result
            FROM carl_autonomy.renew_coordinator_lease(
                runtime.experiment_id || ':coordinator',
                snapshot_value->>'coordinator_id',
                lease_state.revision,
                p_observed_at
            );
        WHEN 'reconcile_lease' THEN
            SELECT lease.* INTO lease_state
            FROM carl_autonomy.leases AS lease
            WHERE lease.lease_key = runtime.experiment_id || ':coordinator'
            FOR UPDATE;
            SELECT observation.observation_digest::text INTO dead_holder_digest
            FROM carl_autonomy.dead_holder_observations AS observation
            WHERE observation.authority = lease_state.authority
                AND observation.subject_id = lease_state.holder_id
                AND observation.scope_kind = 'lease'
                AND observation.scope_key = lease_state.lease_key
                AND observation.revision = lease_state.revision
                AND NOT observation.live
                AND observation.expires_at > p_observed_at
            ORDER BY observation.registered_at DESC, observation.observation_digest
            LIMIT 1;
            IF dead_holder_digest IS NULL THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'coordinator_dead_holder_receipt_required';
            END IF;
            SELECT observation.observed_at_text INTO lease_value
            FROM carl_autonomy.dead_holder_observations AS observation
            WHERE observation.observation_digest = dead_holder_digest;
            reconciliation_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
                'authority', 'coordinator',
                'expected_revision', lease_state.revision,
                'holder_id', lease_state.holder_id,
                'lease_key', lease_state.lease_key,
                'next_revision', lease_state.revision + 1,
                'observed_at', lease_value
            ));
            PERFORM set_config('carl_autonomy.authority', 'coordinator', true);
            SELECT * INTO lease_result
            FROM carl_autonomy.reconcile_lease(
                reconciliation_value, dead_holder_digest, p_observed_at
            );
        WHEN 'release_lease' THEN
            SELECT lease.* INTO lease_state
            FROM carl_autonomy.leases AS lease
            WHERE lease.lease_key = runtime.experiment_id || ':coordinator'
            FOR UPDATE;
            release_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
                'authority', 'coordinator',
                'expected_revision', lease_state.revision,
                'holder_id', lease_state.holder_id,
                'lease_key', lease_state.lease_key,
                'next_revision', lease_state.revision + 1,
                'observation_digest', lease_state.reconciliation_observation_digest,
                'released_at', carl_autonomy.coordinator_timestamp(p_observed_at)
            ));
            PERFORM set_config('carl_autonomy.authority', 'coordinator', true);
            SELECT * INTO lease_result
            FROM carl_autonomy.release_lease(release_value, p_observed_at);
        WHEN 'persist_command', 'retry_rework' THEN
            IF command_value IS NULL OR command_value = 'null'::jsonb THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'coordinator_command_required';
            END IF;
            IF command_value->>'authority' <> ready_node->>'authority'
                OR command_value->>'operation' <> ready_node->>'operation'
                OR (command_value->>'max_attempts')::integer
                    <> (ready_node->>'max_attempts')::integer
                OR (command_value->>'expected_revision')::integer <> runtime.revision
                OR CASE decision_value->>'action'
                    WHEN 'persist_command' THEN
                        command_value->>'command_key' <> ready_node->>'command_key'
                        OR command_value->>'request_digest' <> ready_node->>'request_digest'
                        OR (command_value->>'attempt')::integer
                            <> (ready_node->>'attempt')::integer
                    WHEN 'retry_rework' THEN
                        snapshot_value->'failure' IS NULL
                        OR command_value->>'command_key'
                            <> snapshot_value->'failure'->>'next_command_key'
                        OR command_value->>'request_digest'
                            <> snapshot_value->'failure'->>'next_request_digest'
                        OR (command_value->>'attempt')::integer
                            <> (ready_node->>'attempt')::integer + 1
                    ELSE true
                END
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '42501', MESSAGE = 'coordinator_command_node_authority_denied';
            END IF;
            PERFORM set_config('carl_autonomy.authority', command_value->>'authority', true);
            SELECT * INTO create_result
            FROM carl_autonomy.create_command(
                carl_autonomy.canonical_jsonb(command_value), p_observed_at
            );
            IF decision_value->>'action' = 'retry_rework' THEN
                nodes_value := (
                    SELECT jsonb_agg(
                        CASE WHEN node->>'node_id' = ready_node->>'node_id' THEN
                            jsonb_set(
                                jsonb_set(
                                    jsonb_set(
                                        node,
                                        '{attempt}',
                                        to_jsonb((command_value->>'attempt')::integer),
                                        false
                                    ),
                                    '{command_key}',
                                    to_jsonb(command_value->>'command_key'),
                                    false
                                ),
                                '{request_digest}',
                                to_jsonb(command_value->>'request_digest'),
                                false
                            )
                        ELSE node END
                        ORDER BY ordinal
                    )
                    FROM jsonb_array_elements(snapshot_value->'nodes')
                        WITH ORDINALITY AS value(node, ordinal)
                );
                snapshot_value := jsonb_set(snapshot_value, '{nodes}', nodes_value, false);
                snapshot_value := jsonb_set(
                    snapshot_value, '{failure}', 'null'::jsonb, false
                );
            END IF;
            next_effect_family := carl_autonomy.coordinator_effect_family(
                ready_node->>'kind'
            );
            IF next_effect_family <> 'github' THEN
                next_effect_request := carl_autonomy.canonical_jsonb(jsonb_build_object(
                    'command_key', command_value->>'command_key',
                    'domain', 'carl.coordinator-node-effect.request.v1',
                    'effect_key', command_value->>'effect_key',
                    'family', next_effect_family,
                    'node_kind', ready_node->>'kind',
                    'occurred_at', command_value->>'occurred_at',
                    'request_digest', command_value->>'request_digest',
                    'schema_version', 1
                ));
            ELSIF runtime.effect_family = 'github'
                AND runtime.effect_request_json IS NOT NULL
                AND runtime.effect_request_digest IS NOT NULL
                AND carl_autonomy.sha256_text(runtime.effect_request_json)
                    = runtime.effect_request_digest
            THEN
                existing_effect_request := carl_autonomy.parse_object(
                    runtime.effect_request_json, 'coordinator_effect_request_json_invalid'
                );
                IF existing_effect_request->>'command_key' = command_value->>'command_key'
                    AND existing_effect_request->>'effect_key' = command_value->>'effect_key'
                    AND existing_effect_request->>'occurred_at' = command_value->>'occurred_at'
                THEN
                    next_effect_request := runtime.effect_request_json;
                END IF;
            END IF;
        WHEN 'claim_command' THEN
            SELECT command.* INTO command_state
            FROM carl_autonomy.commands AS command
            WHERE command.command_key = command_value->>'command_key';
            IF NOT FOUND OR command_state.status <> 'pending' THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'coordinator_command_not_claimable';
            END IF;
            claim_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
                'authority', command_value->>'authority',
                'claimed_at', carl_autonomy.coordinator_timestamp(p_observed_at),
                'command_key', command_value->>'command_key',
                'claim_id', 'coordinator-claim-' || substr(decision_value->>'identity', 1, 48),
                'expected_revision', command_state.revision,
                'expires_at', carl_autonomy.coordinator_timestamp(
                    p_observed_at + interval '15 minutes'
                )
            ));
            PERFORM set_config('carl_autonomy.authority', command_value->>'authority', true);
            SELECT * INTO claim_result
            FROM carl_autonomy.claim_command(claim_value, p_observed_at);
        WHEN 'complete_command' THEN
            SELECT command.* INTO command_state
            FROM carl_autonomy.commands AS command
            WHERE command.command_key = command_value->>'command_key'
            FOR UPDATE;
            IF NOT FOUND OR command_state.status <> 'claimed'
                OR runtime.completion_event_json IS NULL
                OR carl_autonomy.sha256_text(runtime.completion_event_json)
                    <> runtime.completion_event_digest
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'coordinator_completion_receipt_required';
            END IF;
            event_value := carl_autonomy.parse_object(
                runtime.completion_event_json, 'coordinator_completion_event_invalid'
            );
            SELECT * INTO expected_completion
            FROM carl_autonomy.build_coordinator_completion_event(
                runtime.experiment_id,
                ready_node->>'kind',
                (ready_node->>'attempt')::integer,
                command_state.command_key,
                command_state.effect_key,
                command_state.request_digest,
                decision_value->>'result_digest',
                (event_value->>'occurred_at')::timestamptz
            );
            IF event_value->>'experiment_id' <> runtime.experiment_id
                OR (event_value->>'occurred_at')::timestamptz > p_observed_at
                OR (event_value->>'occurred_at')::timestamptz < command_state.occurred_at
                OR runtime.completion_event_json <> expected_completion.event_json
                OR runtime.completion_event_digest <> expected_completion.event_digest
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'coordinator_completion_event_mismatch';
            END IF;
            transition_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
                'authority', command_state.authority,
                'claim_id', command_state.claim_id,
                'command_key', command_state.command_key,
                'expected_revision', command_state.revision,
                'failure_code', NULL,
                'next_revision', command_state.revision + 1,
                'result_digest', decision_value->>'result_digest',
                'status', 'completed'
            ));
            INSERT INTO carl_autonomy.coordinator_completion_receipts(
                event_digest, experiment_id, node_kind, authority, command_key,
                effect_key, request_digest, result_digest, event_json, occurred_at,
                recorded_at
            ) VALUES (
                expected_completion.event_digest,
                runtime.experiment_id,
                ready_node->>'kind',
                expected_completion.event_authority,
                command_state.command_key,
                command_state.effect_key,
                command_state.request_digest,
                decision_value->>'result_digest',
                expected_completion.event_json,
                (event_value->>'occurred_at')::timestamptz,
                p_observed_at
            ) ON CONFLICT (event_digest) DO NOTHING;
            SELECT receipt.* INTO existing_completion
            FROM carl_autonomy.coordinator_completion_receipts AS receipt
            WHERE receipt.effect_key = command_state.effect_key
            FOR UPDATE;
            IF NOT FOUND
                OR existing_completion.event_digest
                    <> expected_completion.event_digest::character(64)
                OR existing_completion.experiment_id <> runtime.experiment_id
                OR existing_completion.node_kind <> ready_node->>'kind'
                OR existing_completion.authority <> expected_completion.event_authority
                OR existing_completion.command_key <> command_state.command_key
                OR existing_completion.request_digest <> command_state.request_digest
                OR existing_completion.result_digest <> decision_value->>'result_digest'
                OR existing_completion.event_json <> expected_completion.event_json
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23505', MESSAGE = 'coordinator_completion_receipt_conflict';
            END IF;
            PERFORM set_config('carl_autonomy.authority', command_state.authority, true);
            SELECT * INTO completion_result
            FROM carl_autonomy.terminal_command(
                transition_value, 'completed', p_observed_at
            );
            nodes_value := (
                SELECT jsonb_agg(
                    CASE WHEN node->>'node_id' = ready_node->>'node_id'
                        THEN jsonb_set(node, '{status}', '"complete"'::jsonb, false)
                        ELSE node
                    END
                    ORDER BY ordinal
                )
                FROM jsonb_array_elements(snapshot_value->'nodes')
                    WITH ORDINALITY AS value(node, ordinal)
            );
            next_revision := runtime.revision + 1;
            snapshot_value := jsonb_set(snapshot_value, '{nodes}', nodes_value, false);
            snapshot_value := jsonb_set(
                snapshot_value, '{revision}', to_jsonb(next_revision), false
            );
            next_status := CASE WHEN EXISTS (
                SELECT 1
                FROM jsonb_array_elements(nodes_value) AS remaining(node)
                WHERE remaining.node->>'status' IN ('ready', 'failed')
            ) THEN 'ready' ELSE 'complete' END;
        WHEN 'trigger_supervisor' THEN
            trigger_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
                'attempt_history', jsonb_build_array(),
                'created_at', carl_autonomy.coordinator_timestamp(p_observed_at),
                'evidence_digest', COALESCE(
                    snapshot_value->'failure'->>'next_request_digest',
                    snapshot_value->>'dead_holder_observation_digest',
                    decision_value->>'identity'
                ),
                'next_safe_node_key', COALESCE(
                    ready_node->>'node_id', runtime.experiment_id || ':coordinator'
                ),
                'schema_version', 1,
                'trigger_id', 'coordinator-trigger-' || substr(
                    decision_value->>'identity', 1, 48
                ),
                'unsafe_boundary', decision_value->>'reason'
            ));
            PERFORM set_config('carl_autonomy.authority', 'coordinator', true);
            SELECT * INTO trigger_result
            FROM carl_autonomy.create_supervisor_trigger(trigger_value, p_observed_at);
            next_status := 'frozen';
        WHEN 'frozen' THEN
            IF ready_node IS NULL
                OR NOT carl_autonomy.coordinator_freeze_reason_valid(
                    ready_node->>'kind', decision_value->>'reason'
                )
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '55000', MESSAGE = 'coordinator_freeze_reason_invalid';
            END IF;
            freeze_fingerprint_value := carl_autonomy.sha256_text(
                carl_autonomy.canonical_jsonb(jsonb_build_object(
                    'attempt', (ready_node->>'attempt')::integer,
                    'experiment_id', runtime.experiment_id,
                    'node_id', ready_node->>'node_id',
                    'node_kind', ready_node->>'kind',
                    'reason', decision_value->>'reason',
                    'request_digest', ready_node->>'request_digest',
                    'revision', runtime.revision
                ))
            );
            INSERT INTO carl_autonomy.coordinator_freeze_occurrences(
                occurrence_key, freeze_fingerprint, experiment_id, node_id, node_kind,
                attempt, reason, command_key, effect_key, request_digest, runtime_revision,
                decision_identity, decision_json, frozen_at
            ) VALUES (
                'coordinator-freeze/' || freeze_fingerprint_value,
                freeze_fingerprint_value,
                runtime.experiment_id,
                ready_node->>'node_id',
                ready_node->>'kind',
                (ready_node->>'attempt')::integer,
                decision_value->>'reason',
                ready_node->>'command_key',
                ready_node->>'effect_key',
                ready_node->>'request_digest',
                runtime.revision,
                decision_value->>'identity',
                p_decision_json,
                p_observed_at
            ) ON CONFLICT (occurrence_key) DO NOTHING;
            SELECT occurrence.* INTO existing_freeze
            FROM carl_autonomy.coordinator_freeze_occurrences AS occurrence
            WHERE occurrence.occurrence_key
                = 'coordinator-freeze/' || freeze_fingerprint_value
            FOR UPDATE;
            IF NOT FOUND
                OR existing_freeze.freeze_fingerprint
                    <> freeze_fingerprint_value::character(64)
                OR existing_freeze.experiment_id <> runtime.experiment_id
                OR existing_freeze.node_id <> ready_node->>'node_id'
                OR existing_freeze.node_kind <> ready_node->>'kind'
                OR existing_freeze.attempt <> (ready_node->>'attempt')::integer
                OR existing_freeze.reason <> decision_value->>'reason'
                OR existing_freeze.command_key <> ready_node->>'command_key'
                OR existing_freeze.effect_key <> ready_node->>'effect_key'
                OR existing_freeze.request_digest <> ready_node->>'request_digest'
                OR existing_freeze.runtime_revision <> runtime.revision
                OR existing_freeze.decision_identity <> decision_value->>'identity'
                OR existing_freeze.decision_json <> p_decision_json
                OR existing_freeze.recovered_at IS NOT NULL
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23505', MESSAGE = 'coordinator_freeze_occurrence_conflict';
            END IF;
            next_status := 'frozen';
        ELSE
            RAISE EXCEPTION USING ERRCODE = '0A000', MESSAGE = 'coordinator_action_not_supported';
    END CASE;
    PERFORM set_config('carl_autonomy.authority', 'coordinator', true);
    UPDATE carl_autonomy.coordinator_runtime AS item
    SET decision_identity = decision_value->>'identity',
        decision_json = p_decision_json,
        snapshot_json = carl_autonomy.canonical_jsonb(snapshot_value),
        snapshot_digest = carl_autonomy.sha256_text(
            carl_autonomy.canonical_jsonb(snapshot_value)
        ),
        revision = next_revision,
        status = next_status,
        completion_event_json = CASE
            WHEN decision_value->>'action' IN ('retry_rework', 'complete_command')
                THEN NULL
            ELSE item.completion_event_json
        END,
        completion_event_digest = CASE
            WHEN decision_value->>'action' IN ('retry_rework', 'complete_command')
                THEN NULL
            ELSE item.completion_event_digest
        END,
        effect_family = CASE
            WHEN decision_value->>'action' IN ('persist_command', 'retry_rework')
                THEN CASE
                    WHEN next_effect_request IS NULL THEN NULL
                    ELSE next_effect_family
                END
            ELSE item.effect_family
        END,
        effect_request_json = CASE
            WHEN decision_value->>'action' IN ('persist_command', 'retry_rework')
                THEN next_effect_request
            ELSE item.effect_request_json
        END,
        effect_request_digest = CASE
            WHEN decision_value->>'action' IN ('persist_command', 'retry_rework')
                THEN CASE
                    WHEN next_effect_request IS NULL THEN NULL
                    ELSE carl_autonomy.sha256_text(next_effect_request)
                END
            ELSE item.effect_request_digest
        END,
        effect_response_json = CASE
            WHEN decision_value->>'action' IN ('persist_command', 'retry_rework') THEN NULL
            ELSE item.effect_response_json
        END,
        freeze_reason = CASE
            WHEN decision_value->>'action' = 'frozen' THEN decision_value->>'reason'
            ELSE item.freeze_reason
        END,
        freeze_fingerprint = CASE
            WHEN decision_value->>'action' = 'frozen' THEN freeze_fingerprint_value
            ELSE item.freeze_fingerprint
        END,
        freeze_occurrence_key = CASE
            WHEN decision_value->>'action' = 'frozen'
                THEN 'coordinator-freeze/' || freeze_fingerprint_value
            ELSE item.freeze_occurrence_key
        END,
        freeze_attempt = CASE
            WHEN decision_value->>'action' = 'frozen'
                THEN (ready_node->>'attempt')::integer
            ELSE item.freeze_attempt
        END,
        updated_at = p_observed_at
    WHERE item.experiment_id = runtime.experiment_id;
    RETURN QUERY SELECT true, p_decision_json;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.prepare_coordinator_effect_unchecked(
    p_decision_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(effect_family text, request_json text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    decision_value jsonb;
    runtime carl_autonomy.coordinator_runtime%ROWTYPE;
    request_value jsonb;
    snapshot_value jsonb;
    ready_node jsonb;
    command_state carl_autonomy.commands%ROWTYPE;
    occurrence_state carl_autonomy.coordinator_effect_occurrences%ROWTYPE;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    decision_value := carl_autonomy.parse_object(
        p_decision_json, 'coordinator_decision_json_invalid'
    );
    IF decision_value->>'remote_effect' IS DISTINCT FROM 'true'
        OR decision_value->>'action' NOT IN ('execute_effect', 'reconcile_effect')
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'coordinator_effect_invalid';
    END IF;
    SELECT item.* INTO runtime
    FROM carl_autonomy.coordinator_runtime AS item
    WHERE item.experiment_id = decision_value->>'experiment_id'
        AND item.revision = (decision_value->>'revision')::integer
    FOR UPDATE SKIP LOCKED;
    IF NOT FOUND OR runtime.effect_family IS NULL OR runtime.effect_request_json IS NULL
    THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'coordinator_effect_not_found';
    END IF;
    IF carl_autonomy.sha256_text(runtime.effect_request_json)
        IS DISTINCT FROM runtime.effect_request_digest
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_effect_digest_mismatch';
    END IF;
    request_value := carl_autonomy.parse_object(
        runtime.effect_request_json, 'coordinator_effect_request_json_invalid'
    );
    snapshot_value := carl_autonomy.parse_object(
        runtime.snapshot_json, 'coordinator_snapshot_json_invalid'
    );
    SELECT node INTO ready_node
    FROM jsonb_array_elements(snapshot_value->'nodes') AS node
    WHERE node->>'status' IN ('ready', 'failed')
    ORDER BY carl_autonomy.coordinator_node_priority(node->>'kind'), node->>'node_id'
    LIMIT 1;
    SELECT command.* INTO command_state
    FROM carl_autonomy.commands AS command
    WHERE command.command_key = request_value->>'command_key';
    IF NOT FOUND OR command_state.status <> 'claimed'
        OR command_state.claim_expires_at <= p_observed_at
        OR decision_value->>'node' IS DISTINCT FROM ready_node->>'kind'
        OR runtime.effect_family
            IS DISTINCT FROM carl_autonomy.coordinator_effect_family(ready_node->>'kind')
        OR runtime.effect_family IN ('state', 'supervisor')
        OR request_value->>'command_key'
            IS DISTINCT FROM decision_value->'command'->>'command_key'
        OR request_value->>'effect_key' IS DISTINCT FROM decision_value->>'effect_key'
        OR request_value->>'occurred_at'
            IS DISTINCT FROM decision_value->'command'->>'occurred_at'
        OR request_value->>'effect_key' IS DISTINCT FROM command_state.effect_key
        OR carl_autonomy.canonical_jsonb(decision_value->'command')
            <> command_state.command_json
        OR CASE
            WHEN runtime.effect_family = 'github' THEN CASE ready_node->>'kind'
                WHEN 'dispatch_builder' THEN
                    request_value->>'operation' IS DISTINCT FROM 'dispatch_workflow'
                WHEN 'dispatch_validation' THEN
                    request_value->>'operation' IS DISTINCT FROM 'dispatch_workflow'
                WHEN 'publish_experimental' THEN
                    request_value->>'operation' IS DISTINCT FROM 'create_experimental_ref'
                WHEN 'create_promotion_pr' THEN
                    request_value->>'operation' IS DISTINCT FROM 'create_pull_request'
                WHEN 'observe_required_checks' THEN
                    request_value->>'operation' IS DISTINCT FROM 'observe_required_checks'
                WHEN 'enable_auto_merge' THEN
                    request_value->>'operation'
                        IS DISTINCT FROM 'enable_pull_request_auto_merge'
                WHEN 'create_revert' THEN
                    request_value->>'operation' IS DISTINCT FROM 'create_revert_ref'
                ELSE true
            END
            ELSE carl_autonomy.jsonb_object_cardinality(request_value) IS DISTINCT FROM 8
                OR NOT request_value ?& ARRAY[
                    'schema_version', 'domain', 'family', 'node_kind', 'command_key',
                    'effect_key', 'request_digest', 'occurred_at'
                ]
                OR request_value->'schema_version' IS DISTINCT FROM '1'::jsonb
                OR jsonb_typeof(request_value->'domain') <> 'string'
                OR request_value->>'domain'
                    IS DISTINCT FROM 'carl.coordinator-node-effect.request.v1'
                OR jsonb_typeof(request_value->'family') <> 'string'
                OR request_value->>'family' IS DISTINCT FROM runtime.effect_family
                OR jsonb_typeof(request_value->'node_kind') <> 'string'
                OR request_value->>'node_kind' IS DISTINCT FROM ready_node->>'kind'
                OR jsonb_typeof(request_value->'command_key') <> 'string'
                OR request_value->>'command_key'
                    IS DISTINCT FROM command_state.command_key
                OR jsonb_typeof(request_value->'effect_key') <> 'string'
                OR request_value->>'effect_key' IS DISTINCT FROM command_state.effect_key
                OR jsonb_typeof(request_value->'request_digest') <> 'string'
                OR request_value->>'request_digest'
                    IS DISTINCT FROM command_state.request_digest
                OR request_value->>'request_digest' !~ '^[0-9a-f]{64}$'
                OR jsonb_typeof(request_value->'occurred_at') <> 'string'
                OR request_value->>'occurred_at'
                    IS DISTINCT FROM command_state.occurred_at_text
                OR NOT carl_autonomy.canonical_utc_text_valid(
                    request_value->>'occurred_at'
                )
        END
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_effect_identity_mismatch';
    END IF;
    IF runtime.effect_family <> 'github' THEN
        SELECT occurrence.* INTO occurrence_state
        FROM carl_autonomy.coordinator_effect_occurrences AS occurrence
        WHERE occurrence.effect_key = command_state.effect_key
        FOR UPDATE;
        IF FOUND THEN
            IF occurrence_state.experiment_id <> runtime.experiment_id
                OR occurrence_state.node_kind <> ready_node->>'kind'
                OR occurrence_state.effect_family <> runtime.effect_family
                OR occurrence_state.command_key <> command_state.command_key
                OR occurrence_state.request_json <> runtime.effect_request_json
                OR occurrence_state.request_digest <> runtime.effect_request_digest
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23505', MESSAGE = 'coordinator_effect_occurrence_conflict';
            END IF;
        ELSE
            INSERT INTO carl_autonomy.coordinator_effect_occurrences(
                effect_key, occurrence_key, experiment_id, node_kind, effect_family,
                command_key, request_json, request_digest, status, prepared_at, updated_at
            ) VALUES (
                command_state.effect_key,
                'coordinator/' || runtime.effect_request_digest,
                runtime.experiment_id,
                ready_node->>'kind',
                runtime.effect_family,
                command_state.command_key,
                runtime.effect_request_json,
                runtime.effect_request_digest,
                'in_progress',
                p_observed_at,
                p_observed_at
            );
        END IF;
    END IF;
    UPDATE carl_autonomy.coordinator_runtime AS item
    SET decision_identity = decision_value->>'identity', decision_json = p_decision_json,
        status = 'effect_prepared', updated_at = p_observed_at
    WHERE item.experiment_id = runtime.experiment_id;
    RETURN QUERY SELECT runtime.effect_family::text, runtime.effect_request_json;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.complete_coordinator_effect_unchecked(
    p_decision_json text,
    p_response_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean, decision_json text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    decision_value jsonb;
    response_value jsonb;
    prior_response_value jsonb;
    runtime carl_autonomy.coordinator_runtime%ROWTYPE;
    command_state carl_autonomy.commands%ROWTYPE;
    effect_state carl_autonomy.effect_attempts%ROWTYPE;
    occurrence_state carl_autonomy.coordinator_effect_occurrences%ROWTYPE;
    transition_value text;
    failure_result record;
    completion_event record;
    completion_result_digest text;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    decision_value := carl_autonomy.parse_object(
        p_decision_json, 'coordinator_decision_json_invalid'
    );
    response_value := carl_autonomy.parse_object(
        p_response_json, 'coordinator_effect_response_json_invalid'
    );
    SELECT item.* INTO runtime
    FROM carl_autonomy.coordinator_runtime AS item
    WHERE item.experiment_id = decision_value->>'experiment_id'
        AND item.decision_identity = decision_value->>'identity'
        AND item.decision_json = p_decision_json
    FOR UPDATE;
    IF NOT FOUND OR runtime.status NOT IN ('effect_prepared', 'effect_observed')
        OR response_value->>'request_digest' IS DISTINCT FROM runtime.effect_request_digest
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_effect_response_mismatch';
    END IF;
    IF runtime.effect_response_json = p_response_json THEN
        RETURN QUERY SELECT false, runtime.decision_json;
        RETURN;
    END IF;
    SELECT command.* INTO command_state
    FROM carl_autonomy.commands AS command
    WHERE command.command_key = decision_value->'command'->>'command_key'
    FOR UPDATE;
    IF NOT FOUND OR command_state.status <> 'claimed'
        OR command_state.effect_key <> decision_value->>'effect_key'
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_effect_command_mismatch';
    END IF;
    SELECT attempt.* INTO effect_state
    FROM carl_autonomy.effect_attempts AS attempt
    WHERE attempt.effect_key = command_state.effect_key;
    IF runtime.effect_family = 'github' THEN
        IF response_value->>'status' = 'completed' AND (
            NOT FOUND OR effect_state.attempt_state <> 'completed'
            OR effect_state.result_digest IS NULL
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'coordinator_effect_receipt_missing';
        ELSIF response_value->>'status' = 'uncertain' AND (
            NOT FOUND OR effect_state.attempt_state <> 'uncertain'
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'coordinator_effect_receipt_missing';
        ELSIF response_value->>'status' = 'retry_scheduled' AND (
            NOT FOUND OR effect_state.attempt_state <> 'retry_scheduled'
            OR effect_state.not_before_text <> response_value->>'retry_not_before'
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'coordinator_effect_receipt_missing';
        END IF;
    ELSIF runtime.effect_family NOT IN ('archive', 'evaluator', 'input', 'observer')
        OR carl_autonomy.jsonb_object_cardinality(response_value) IS DISTINCT FROM 8
        OR NOT response_value ?& ARRAY[
            'schema_version', 'domain', 'status', 'request_digest', 'observed_at',
            'result_digest', 'retry_not_before', 'error_code'
        ]
        OR response_value->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR jsonb_typeof(response_value->'domain') <> 'string'
        OR response_value->>'domain'
            IS DISTINCT FROM 'carl.coordinator-node-effect.response.v1'
        OR jsonb_typeof(response_value->'status') <> 'string'
        OR jsonb_typeof(response_value->'request_digest') <> 'string'
        OR response_value->>'request_digest'
            IS DISTINCT FROM runtime.effect_request_digest
        OR response_value->>'request_digest' !~ '^[0-9a-f]{64}$'
        OR CASE
            WHEN jsonb_typeof(response_value->'observed_at') <> 'string' THEN true
            WHEN NOT carl_autonomy.canonical_utc_text_valid(
                response_value->>'observed_at'
            ) THEN true
            ELSE (response_value->>'observed_at')::timestamptz
                    < command_state.occurred_at
                OR (response_value->>'observed_at')::timestamptz
                    > p_observed_at + interval '30 seconds'
        END
        OR CASE response_value->>'status'
            WHEN 'completed' THEN
                jsonb_typeof(response_value->'result_digest') <> 'string'
                OR response_value->>'result_digest' !~ '^[0-9a-f]{64}$'
                OR response_value->'retry_not_before' IS DISTINCT FROM 'null'::jsonb
                OR response_value->'error_code' IS DISTINCT FROM 'null'::jsonb
            WHEN 'rejected' THEN response_value->'result_digest' IS DISTINCT FROM 'null'::jsonb
                OR response_value->'retry_not_before' IS DISTINCT FROM 'null'::jsonb
                OR jsonb_typeof(response_value->'error_code') <> 'string'
                OR response_value->>'error_code' !~ '^[a-z][a-z0-9_]{0,63}$'
            WHEN 'retry_scheduled' THEN
                response_value->'result_digest' IS DISTINCT FROM 'null'::jsonb
                OR response_value->'error_code' IS DISTINCT FROM 'null'::jsonb
                OR CASE
                    WHEN jsonb_typeof(response_value->'retry_not_before') <> 'string'
                        THEN true
                    WHEN NOT carl_autonomy.canonical_utc_text_valid(
                        response_value->>'retry_not_before'
                    ) THEN true
                    ELSE (response_value->>'retry_not_before')::timestamptz < p_observed_at
                END
            WHEN 'uncertain' THEN
                response_value->'result_digest' IS DISTINCT FROM 'null'::jsonb
                OR response_value->'retry_not_before' IS DISTINCT FROM 'null'::jsonb
                OR response_value->'error_code' IS DISTINCT FROM 'null'::jsonb
            ELSE true
        END
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'coordinator_effect_response_mismatch';
    END IF;
    IF runtime.effect_response_json IS NOT NULL THEN
        prior_response_value := carl_autonomy.parse_object(
            runtime.effect_response_json, 'coordinator_effect_response_json_invalid'
        );
        IF runtime.effect_family = 'github'
            OR decision_value->>'action' <> 'reconcile_effect'
            OR prior_response_value->>'request_digest'
                IS DISTINCT FROM runtime.effect_request_digest
            OR prior_response_value->>'status' IN ('completed', 'rejected')
            OR prior_response_value->>'status' NOT IN ('uncertain', 'retry_scheduled')
            OR CASE
                WHEN NOT carl_autonomy.canonical_utc_text_valid(
                    prior_response_value->>'observed_at'
                ) THEN true
                ELSE (prior_response_value->>'observed_at')::timestamptz
                    > (response_value->>'observed_at')::timestamptz
            END
            OR (
                prior_response_value->>'status' = 'retry_scheduled'
                AND CASE
                    WHEN NOT carl_autonomy.canonical_utc_text_valid(
                        prior_response_value->>'retry_not_before'
                    ) THEN true
                    ELSE (prior_response_value->>'retry_not_before')::timestamptz
                        > p_observed_at
                END
            )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505', MESSAGE = 'coordinator_effect_response_conflict';
        END IF;
    END IF;
    IF runtime.effect_family <> 'github' THEN
        SELECT occurrence.* INTO occurrence_state
        FROM carl_autonomy.coordinator_effect_occurrences AS occurrence
        WHERE occurrence.effect_key = command_state.effect_key
        FOR UPDATE;
        IF NOT FOUND
            OR occurrence_state.experiment_id <> runtime.experiment_id
            OR occurrence_state.node_kind <> decision_value->>'node'
            OR occurrence_state.effect_family <> runtime.effect_family
            OR occurrence_state.command_key <> command_state.command_key
            OR occurrence_state.request_json <> runtime.effect_request_json
            OR occurrence_state.request_digest <> runtime.effect_request_digest
            OR occurrence_state.response_json IS DISTINCT FROM runtime.effect_response_json
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000', MESSAGE = 'coordinator_effect_occurrence_missing';
        END IF;
        UPDATE carl_autonomy.coordinator_effect_occurrences AS occurrence
        SET response_json = p_response_json,
            response_digest = carl_autonomy.sha256_text(p_response_json),
            status = 'effect_observed',
            updated_at = p_observed_at
        WHERE occurrence.effect_key = command_state.effect_key;
    END IF;
    IF response_value->>'status' = 'rejected' THEN
        transition_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
            'authority', command_state.authority,
            'claim_id', command_state.claim_id,
            'command_key', command_state.command_key,
            'expected_revision', command_state.revision,
            'failure_code', response_value->>'error_code',
            'next_revision', command_state.revision + 1,
            'result_digest', NULL,
            'status', 'failed'
        ));
        PERFORM set_config('carl_autonomy.authority', command_state.authority, true);
        SELECT * INTO failure_result
        FROM carl_autonomy.fail_command(transition_value, p_observed_at);
        PERFORM set_config('carl_autonomy.authority', 'coordinator', true);
    ELSIF response_value->>'status' NOT IN (
        'completed', 'uncertain', 'retry_scheduled', 'rejected'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_effect_response_mismatch';
    END IF;
    IF response_value->>'status' = 'completed' THEN
        completion_result_digest := CASE
            WHEN runtime.effect_family = 'github' THEN effect_state.result_digest::text
            ELSE response_value->>'result_digest'
        END;
        SELECT * INTO completion_event
        FROM carl_autonomy.build_coordinator_completion_event(
            runtime.experiment_id,
            decision_value->>'node',
            (decision_value->'command'->>'attempt')::integer,
            command_state.command_key,
            command_state.effect_key,
            command_state.request_digest,
            completion_result_digest,
            p_observed_at
        );
    END IF;
    UPDATE carl_autonomy.coordinator_runtime AS item
    SET effect_response_json = p_response_json,
        completion_event_json = CASE
            WHEN response_value->>'status' = 'completed' THEN completion_event.event_json
            ELSE NULL
        END,
        completion_event_digest = CASE
            WHEN response_value->>'status' = 'completed' THEN completion_event.event_digest
            ELSE NULL
        END,
        status = 'effect_observed',
        updated_at = p_observed_at
    WHERE item.experiment_id = runtime.experiment_id;
    RETURN QUERY SELECT true, p_decision_json;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.execute_coordinator_local_effect_unchecked(
    p_decision_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean, decision_json text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    decision_value jsonb;
    runtime carl_autonomy.coordinator_runtime%ROWTYPE;
    snapshot_value jsonb;
    ready_node jsonb;
    request_value jsonb;
    response_value jsonb;
    command_state carl_autonomy.commands%ROWTYPE;
    occurrence_state carl_autonomy.coordinator_effect_occurrences%ROWTYPE;
    trigger_value text;
    trigger_result record;
    completion_event record;
    local_result_digest text;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    decision_value := carl_autonomy.parse_object(
        p_decision_json, 'coordinator_decision_json_invalid'
    );
    IF decision_value->>'action' <> 'execute_effect'
        OR decision_value->>'remote_effect' <> 'false'
        OR decision_value->'command' IS NULL
        OR decision_value->'command' = 'null'::jsonb
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'coordinator_effect_invalid';
    END IF;
    SELECT item.* INTO runtime
    FROM carl_autonomy.coordinator_runtime AS item
    WHERE item.experiment_id = decision_value->>'experiment_id'
        AND item.revision = (decision_value->>'revision')::integer
    FOR UPDATE SKIP LOCKED;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'coordinator_decision_cas_mismatch';
    END IF;
    IF runtime.decision_identity = decision_value->>'identity'
        AND runtime.decision_json = p_decision_json
        AND runtime.effect_response_json IS NOT NULL
    THEN
        RETURN QUERY SELECT false, runtime.decision_json;
        RETURN;
    END IF;
    IF runtime.effect_family NOT IN ('state', 'supervisor')
        OR runtime.effect_request_json IS NULL
        OR runtime.effect_request_digest IS NULL
        OR carl_autonomy.sha256_text(runtime.effect_request_json)
            IS DISTINCT FROM runtime.effect_request_digest
        OR runtime.effect_response_json IS NOT NULL
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_local_effect_invalid';
    END IF;
    snapshot_value := carl_autonomy.parse_object(
        runtime.snapshot_json, 'coordinator_snapshot_json_invalid'
    );
    SELECT node INTO ready_node
    FROM jsonb_array_elements(snapshot_value->'nodes') AS node
    WHERE node->>'status' IN ('ready', 'failed')
    ORDER BY carl_autonomy.coordinator_node_priority(node->>'kind'), node->>'node_id'
    LIMIT 1;
    request_value := carl_autonomy.parse_object(
        runtime.effect_request_json, 'coordinator_effect_request_json_invalid'
    );
    SELECT command.* INTO command_state
    FROM carl_autonomy.commands AS command
    WHERE command.command_key = decision_value->'command'->>'command_key'
    FOR UPDATE;
    IF NOT FOUND OR command_state.status <> 'claimed'
        OR command_state.claim_expires_at <= p_observed_at
        OR runtime.effect_family
            IS DISTINCT FROM carl_autonomy.coordinator_effect_family(ready_node->>'kind')
        OR decision_value->>'node' IS DISTINCT FROM ready_node->>'kind'
        OR decision_value->>'effect_key' IS DISTINCT FROM command_state.effect_key
        OR carl_autonomy.canonical_jsonb(decision_value->'command')
            <> command_state.command_json
        OR carl_autonomy.jsonb_object_cardinality(request_value) IS DISTINCT FROM 8
        OR NOT request_value ?& ARRAY[
            'schema_version', 'domain', 'family', 'node_kind', 'command_key',
            'effect_key', 'request_digest', 'occurred_at'
        ]
        OR request_value->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR jsonb_typeof(request_value->'domain') <> 'string'
        OR request_value->>'domain'
            IS DISTINCT FROM 'carl.coordinator-node-effect.request.v1'
        OR jsonb_typeof(request_value->'family') <> 'string'
        OR request_value->>'family' IS DISTINCT FROM runtime.effect_family
        OR jsonb_typeof(request_value->'node_kind') <> 'string'
        OR request_value->>'node_kind' IS DISTINCT FROM ready_node->>'kind'
        OR jsonb_typeof(request_value->'command_key') <> 'string'
        OR request_value->>'command_key' IS DISTINCT FROM command_state.command_key
        OR jsonb_typeof(request_value->'effect_key') <> 'string'
        OR request_value->>'effect_key' IS DISTINCT FROM command_state.effect_key
        OR jsonb_typeof(request_value->'request_digest') <> 'string'
        OR request_value->>'request_digest' IS DISTINCT FROM command_state.request_digest
        OR request_value->>'request_digest' !~ '^[0-9a-f]{64}$'
        OR jsonb_typeof(request_value->'occurred_at') <> 'string'
        OR request_value->>'occurred_at' IS DISTINCT FROM command_state.occurred_at_text
        OR NOT carl_autonomy.canonical_utc_text_valid(request_value->>'occurred_at')
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_effect_identity_mismatch';
    END IF;
    SELECT occurrence.* INTO occurrence_state
    FROM carl_autonomy.coordinator_effect_occurrences AS occurrence
    WHERE occurrence.effect_key = command_state.effect_key
    FOR UPDATE;
    IF FOUND THEN
        IF occurrence_state.experiment_id <> runtime.experiment_id
            OR occurrence_state.node_kind <> ready_node->>'kind'
            OR occurrence_state.effect_family <> runtime.effect_family
            OR occurrence_state.command_key <> command_state.command_key
            OR occurrence_state.request_json <> runtime.effect_request_json
            OR occurrence_state.request_digest <> runtime.effect_request_digest
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505', MESSAGE = 'coordinator_effect_occurrence_conflict';
        END IF;
    ELSE
        INSERT INTO carl_autonomy.coordinator_effect_occurrences(
            effect_key, occurrence_key, experiment_id, node_kind, effect_family,
            command_key, request_json, request_digest, status, prepared_at, updated_at
        ) VALUES (
            command_state.effect_key,
            'coordinator/' || runtime.effect_request_digest,
            runtime.experiment_id,
            ready_node->>'kind',
            runtime.effect_family,
            command_state.command_key,
            runtime.effect_request_json,
            runtime.effect_request_digest,
            'in_progress',
            p_observed_at,
            p_observed_at
        );
    END IF;
    IF runtime.effect_family = 'supervisor' THEN
        trigger_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
            'attempt_history', jsonb_build_array(),
            'created_at', carl_autonomy.coordinator_timestamp(p_observed_at),
            'evidence_digest', command_state.request_digest,
            'next_safe_node_key', ready_node->>'node_id',
            'schema_version', 1,
            'trigger_id', 'coordinator-trigger-' || substr(
                decision_value->>'identity', 1, 48
            ),
            'unsafe_boundary', 'node_recovery_required'
        ));
        PERFORM set_config('carl_autonomy.authority', 'coordinator', true);
        SELECT * INTO trigger_result
        FROM carl_autonomy.create_supervisor_trigger(trigger_value, p_observed_at);
    END IF;
    local_result_digest := carl_autonomy.sha256_text(
        carl_autonomy.canonical_jsonb(jsonb_build_object(
            'command_key', command_state.command_key,
            'effect_key', command_state.effect_key,
            'family', runtime.effect_family,
            'node_kind', ready_node->>'kind',
            'request_digest', command_state.request_digest,
            'status', 'completed'
        ))
    );
    SELECT * INTO completion_event
    FROM carl_autonomy.build_coordinator_completion_event(
        runtime.experiment_id,
        ready_node->>'kind',
        (ready_node->>'attempt')::integer,
        command_state.command_key,
        command_state.effect_key,
        command_state.request_digest,
        local_result_digest,
        p_observed_at
    );
    response_value := jsonb_build_object(
        'domain', 'carl.coordinator-node-effect.response.v1',
        'error_code', NULL,
        'observed_at', carl_autonomy.coordinator_timestamp(p_observed_at),
        'request_digest', runtime.effect_request_digest,
        'result_digest', local_result_digest,
        'retry_not_before', NULL,
        'schema_version', 1,
        'status', 'completed'
    );
    UPDATE carl_autonomy.coordinator_effect_occurrences AS occurrence
    SET response_json = carl_autonomy.canonical_jsonb(response_value),
        response_digest = carl_autonomy.sha256_text(
            carl_autonomy.canonical_jsonb(response_value)
        ),
        status = 'effect_observed',
        updated_at = p_observed_at
    WHERE occurrence.effect_key = command_state.effect_key;
    UPDATE carl_autonomy.coordinator_runtime AS item
    SET decision_identity = decision_value->>'identity',
        decision_json = p_decision_json,
        effect_response_json = carl_autonomy.canonical_jsonb(response_value),
        completion_event_json = completion_event.event_json,
        completion_event_digest = completion_event.event_digest,
        status = 'effect_observed',
        updated_at = p_observed_at
    WHERE item.experiment_id = runtime.experiment_id;
    RETURN QUERY SELECT true, p_decision_json;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.coordinator_authoritative_receipt_failure(
    failure_code text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT failure_code = ANY(ARRAY[
        'coordinator_completion_event_invalid',
        'coordinator_completion_event_mismatch',
        'coordinator_completion_identity_invalid',
        'coordinator_completion_receipt_conflict',
        'coordinator_completion_receipt_required',
        'coordinator_effect_command_mismatch',
        'coordinator_effect_digest_mismatch',
        'coordinator_effect_identity_mismatch',
        'coordinator_effect_occurrence_conflict',
        'coordinator_effect_occurrence_missing',
        'coordinator_effect_receipt_missing',
        'coordinator_effect_request_json_invalid',
        'coordinator_effect_response_conflict',
        'coordinator_effect_response_json_invalid',
        'coordinator_effect_response_mismatch'
    ]::text[])
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.freeze_coordinator_receipt_failure(
    p_decision_json text,
    p_observed_at timestamptz,
    p_failure_code text
)
RETURNS TABLE(applied boolean, decision_json text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    source_decision jsonb;
    runtime carl_autonomy.coordinator_runtime%ROWTYPE;
    snapshot_value jsonb;
    ready_node jsonb;
    identity_value jsonb;
    frozen_identity text;
    frozen_decision text;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    IF NOT carl_autonomy.coordinator_authoritative_receipt_failure(p_failure_code) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'coordinator_receipt_failure_invalid';
    END IF;
    source_decision := carl_autonomy.parse_object(
        p_decision_json, 'coordinator_decision_json_invalid'
    );
    SELECT item.* INTO runtime
    FROM carl_autonomy.coordinator_runtime AS item
    WHERE item.experiment_id = source_decision->>'experiment_id'
        AND item.revision = (source_decision->>'revision')::integer
    FOR UPDATE;
    IF NOT FOUND OR runtime.status = 'frozen' THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001', MESSAGE = 'coordinator_decision_cas_mismatch';
    END IF;
    snapshot_value := carl_autonomy.parse_object(
        runtime.snapshot_json, 'coordinator_snapshot_json_invalid'
    );
    SELECT node INTO ready_node
    FROM jsonb_array_elements(snapshot_value->'nodes') AS node
    WHERE node->>'status' IN ('ready', 'failed')
    ORDER BY carl_autonomy.coordinator_node_priority(node->>'kind'), node->>'node_id'
    LIMIT 1;
    IF ready_node IS NULL
        OR source_decision->>'node' IS DISTINCT FROM ready_node->>'kind'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'coordinator_decision_node_mismatch';
    END IF;
    identity_value := jsonb_build_object(
        'action', 'frozen',
        'experiment_id', runtime.experiment_id,
        'node_id', ready_node->>'node_id',
        'reason', 'authoritative_completion_receipt_invalid',
        'revision', runtime.revision
    );
    frozen_identity := carl_autonomy.sha256_text(
        carl_autonomy.canonical_jsonb(identity_value)
    );
    frozen_decision := carl_autonomy.canonical_jsonb(jsonb_build_object(
        'action', 'frozen',
        'command', NULL,
        'consequential', true,
        'effect_key', NULL,
        'event', NULL,
        'experiment_id', runtime.experiment_id,
        'identity', frozen_identity,
        'node', ready_node->>'kind',
        'reason', 'authoritative_completion_receipt_invalid',
        'remote_effect', false,
        'result_digest', NULL,
        'revision', runtime.revision,
        'schema_version', 1
    ));
    RETURN QUERY
    SELECT result.applied, result.decision_json
    FROM carl_autonomy.apply_coordinator_decision_unchecked(
        frozen_decision, p_observed_at
    ) AS result;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.apply_coordinator_decision(
    p_decision_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean, decision_json text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    failure_code text;
BEGIN
    BEGIN
        RETURN QUERY
        SELECT result.applied, result.decision_json
        FROM carl_autonomy.apply_coordinator_decision_unchecked(
            p_decision_json, p_observed_at
        ) AS result;
        RETURN;
    EXCEPTION WHEN OTHERS THEN
        failure_code := SQLERRM;
        IF NOT carl_autonomy.coordinator_authoritative_receipt_failure(failure_code) THEN
            RAISE;
        END IF;
    END;
    RETURN QUERY SELECT * FROM carl_autonomy.freeze_coordinator_receipt_failure(
        p_decision_json, p_observed_at, failure_code
    );
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.prepare_coordinator_effect(
    p_decision_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(effect_family text, request_json text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    failure_code text;
    frozen_result record;
BEGIN
    BEGIN
        RETURN QUERY
        SELECT result.effect_family, result.request_json
        FROM carl_autonomy.prepare_coordinator_effect_unchecked(
            p_decision_json, p_observed_at
        ) AS result;
        RETURN;
    EXCEPTION WHEN OTHERS THEN
        failure_code := SQLERRM;
        IF NOT carl_autonomy.coordinator_authoritative_receipt_failure(failure_code) THEN
            RAISE;
        END IF;
    END;
    SELECT result.* INTO STRICT frozen_result
    FROM carl_autonomy.freeze_coordinator_receipt_failure(
        p_decision_json, p_observed_at, failure_code
    ) AS result;
    RETURN QUERY SELECT NULL::text, frozen_result.decision_json::text;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.complete_coordinator_effect(
    p_decision_json text,
    p_response_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean, decision_json text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    failure_code text;
BEGIN
    BEGIN
        RETURN QUERY
        SELECT result.applied, result.decision_json
        FROM carl_autonomy.complete_coordinator_effect_unchecked(
            p_decision_json, p_response_json, p_observed_at
        ) AS result;
        RETURN;
    EXCEPTION WHEN OTHERS THEN
        failure_code := SQLERRM;
        IF NOT carl_autonomy.coordinator_authoritative_receipt_failure(failure_code) THEN
            RAISE;
        END IF;
    END;
    RETURN QUERY SELECT * FROM carl_autonomy.freeze_coordinator_receipt_failure(
        p_decision_json, p_observed_at, failure_code
    );
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.execute_coordinator_local_effect(
    p_decision_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean, decision_json text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    failure_code text;
BEGIN
    BEGIN
        RETURN QUERY
        SELECT result.applied, result.decision_json
        FROM carl_autonomy.execute_coordinator_local_effect_unchecked(
            p_decision_json, p_observed_at
        ) AS result;
        RETURN;
    EXCEPTION WHEN OTHERS THEN
        failure_code := SQLERRM;
        IF NOT carl_autonomy.coordinator_authoritative_receipt_failure(failure_code) THEN
            RAISE;
        END IF;
    END;
    RETURN QUERY SELECT * FROM carl_autonomy.freeze_coordinator_receipt_failure(
        p_decision_json, p_observed_at, failure_code
    );
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.register_and_claim_builder_effect(
    p_registration_json text
)
RETURNS TABLE(
    applied boolean,
    claim_json text,
    command_json text,
    failure_code text,
    result_digest text,
    revision integer,
    status text,
    transition_json text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    registration jsonb;
    github_request jsonb;
    runtime carl_autonomy.coordinator_runtime%ROWTYPE;
    snapshot_value jsonb;
    selected_node jsonb;
    repaired_nodes jsonb;
    command_value text;
    claim_value text;
    command_effect_key text;
    expected_idempotency text;
    observed_at timestamptz := statement_timestamp();
    create_result record;
    claim_result record;
    existing_command carl_autonomy.commands%ROWTYPE;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_state_backend']);
    registration := carl_autonomy.parse_object(
        p_registration_json, 'builder_effect_registration_invalid'
    );
    IF carl_autonomy.canonical_jsonb(registration) <> p_registration_json
        OR carl_autonomy.jsonb_object_cardinality(registration) IS DISTINCT FROM 12
        OR NOT registration ?& ARRAY[
            'schema_version', 'domain', 'node', 'experiment_id', 'expected_revision',
            'idempotency_key', 'builder_request_digest', 'publication_request_digest',
            'candidate_packet_digest', 'parent_commit',
            'github_binding_request_digest', 'github_request'
        ]
        OR registration->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR registration->>'domain' <> 'carl.product-builder.coordinator-effect.v1'
        OR registration->>'node' NOT IN ('publish_experimental', 'dispatch_validation')
        OR registration->>'experiment_id' !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
        OR jsonb_typeof(registration->'expected_revision') <> 'number'
        OR (registration->>'expected_revision')::integer NOT BETWEEN 0 AND 2147483646
        OR registration->>'idempotency_key' !~ '^[0-9a-f]{64}$'
        OR registration->>'builder_request_digest' !~ '^[0-9a-f]{64}$'
        OR registration->>'publication_request_digest' !~ '^[0-9a-f]{64}$'
        OR registration->>'candidate_packet_digest' !~ '^[0-9a-f]{64}$'
        OR registration->>'github_binding_request_digest' !~ '^[0-9a-f]{64}$'
        OR registration->>'parent_commit' !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
        OR jsonb_typeof(registration->'github_request') <> 'object'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'builder_effect_registration_invalid';
    END IF;
    github_request := registration->'github_request';
    IF carl_autonomy.jsonb_object_cardinality(github_request) IS DISTINCT FROM 8
        OR NOT github_request ?& ARRAY[
            'schema_version', 'domain', 'operation', 'command_key', 'effect_key',
            'request_key', 'occurred_at', 'parameters'
        ]
        OR github_request->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR github_request->>'domain' <> 'carl.github-effect.ipc.request.v1'
        OR NOT carl_autonomy.canonical_utc_text_valid(github_request->>'occurred_at')
        OR CASE registration->>'node'
            WHEN 'publish_experimental' THEN
                github_request->>'operation' <> 'create_experimental_ref'
            WHEN 'dispatch_validation' THEN
                github_request->>'operation' <> 'dispatch_workflow'
            ELSE true
        END
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'builder_effect_github_request_invalid';
    END IF;
    command_effect_key := 'cloud-effect-' || carl_autonomy.sha256_text(
        carl_autonomy.canonical_jsonb(jsonb_build_object(
            'authority', CASE registration->>'node'
                WHEN 'publish_experimental' THEN 'builder' ELSE 'coordinator' END,
            'command_key', github_request->>'command_key',
            'operation', CASE registration->>'node'
                WHEN 'publish_experimental' THEN 'publish_experimental' ELSE 'dispatch' END,
            'request_digest', registration->>'github_binding_request_digest'
        ))
    );
    expected_idempotency := carl_autonomy.sha256_text(
        carl_autonomy.canonical_jsonb(jsonb_build_object(
            'candidate_packet_digest', registration->>'candidate_packet_digest',
            'command_key', github_request->>'command_key',
            'effect_key', command_effect_key,
            'expected_revision', (registration->>'expected_revision')::integer,
            'experiment_id', registration->>'experiment_id',
            'github_binding_request_digest', registration->>'github_binding_request_digest',
            'github_request_digest', carl_autonomy.sha256_text(
                carl_autonomy.canonical_jsonb(github_request)
            ),
            'node', registration->>'node',
            'parent_commit', registration->>'parent_commit',
            'publication_request_digest', registration->>'publication_request_digest',
            'request_digest', registration->>'builder_request_digest',
            'schema_version', 1
        ))
    );
    IF github_request->>'effect_key' <> command_effect_key
        OR registration->>'idempotency_key' <> expected_idempotency
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'builder_effect_identity_mismatch';
    END IF;
    SELECT item.* INTO runtime
    FROM carl_autonomy.coordinator_runtime AS item
    WHERE item.experiment_id = registration->>'experiment_id'
    FOR UPDATE;
    IF NOT FOUND
        OR runtime.status IN ('complete', 'frozen')
        OR runtime.revision <> (registration->>'expected_revision')::integer
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001', MESSAGE = 'builder_effect_revision_cas_mismatch';
    END IF;
    snapshot_value := carl_autonomy.parse_object(
        runtime.snapshot_json, 'coordinator_snapshot_json_invalid'
    );
    SELECT node INTO selected_node
    FROM jsonb_array_elements(snapshot_value->'nodes') AS node
    WHERE node->>'status' = 'ready'
    ORDER BY carl_autonomy.coordinator_node_priority(node->>'kind'), node->>'node_id'
    LIMIT 1;
    IF selected_node IS NULL
        OR selected_node->>'kind' <> registration->>'node'
        OR selected_node->>'node_id'
            <> ((registration->>'experiment_id') || ':' || (registration->>'node'))
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'builder_effect_node_mismatch';
    END IF;
    SELECT command.* INTO existing_command
    FROM carl_autonomy.commands AS command
    WHERE command.command_key = github_request->>'command_key';
    IF FOUND THEN
        IF existing_command.effect_key <> command_effect_key
            OR existing_command.request_digest
                <> (registration->>'github_binding_request_digest')::character(64)
            OR existing_command.status <> 'claimed'
            OR runtime.effect_request_json <> carl_autonomy.canonical_jsonb(github_request)
            OR runtime.effect_request_digest
                <> carl_autonomy.sha256_text(carl_autonomy.canonical_jsonb(github_request))
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505', MESSAGE = 'builder_effect_replay_conflict';
        END IF;
        RETURN QUERY SELECT false, existing_command.claim_json,
            existing_command.command_json, existing_command.failure_code,
            existing_command.result_digest, existing_command.revision,
            existing_command.status, existing_command.transition_json;
        RETURN;
    END IF;
    command_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
        'attempt', 1,
        'authority', CASE registration->>'node'
            WHEN 'publish_experimental' THEN 'builder' ELSE 'coordinator' END,
        'command_key', github_request->>'command_key',
        'effect_key', command_effect_key,
        'expected_revision', runtime.revision,
        'max_attempts', 3,
        'occurred_at', github_request->>'occurred_at',
        'operation', CASE registration->>'node'
            WHEN 'publish_experimental' THEN 'publish_experimental' ELSE 'dispatch' END,
        'request_digest', registration->>'github_binding_request_digest',
        'schema_version', 1
    ));
    PERFORM set_config(
        'carl_autonomy.authority',
        CASE registration->>'node'
            WHEN 'publish_experimental' THEN 'builder' ELSE 'coordinator' END,
        true
    );
    SELECT * INTO STRICT create_result
    FROM carl_autonomy.create_command(command_value, observed_at);
    claim_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
        'authority', (command_value::jsonb)->>'authority',
        'claimed_at', carl_autonomy.coordinator_timestamp(observed_at),
        'command_key', github_request->>'command_key',
        'claim_id', 'builder-effect-' || substr(registration->>'idempotency_key', 1, 48),
        'expected_revision', runtime.revision,
        'expires_at', carl_autonomy.coordinator_timestamp(
            observed_at + interval '15 minutes'
        )
    ));
    SELECT * INTO STRICT claim_result
    FROM carl_autonomy.claim_command(claim_value, observed_at);
    SELECT jsonb_agg(
        CASE WHEN node->>'node_id' = selected_node->>'node_id' THEN
            jsonb_set(
                jsonb_set(
                    jsonb_set(node, '{command_key}', to_jsonb(github_request->>'command_key'), false),
                    '{request_digest}',
                    to_jsonb(registration->>'github_binding_request_digest'),
                    false
                ),
                '{occurred_at}', to_jsonb(github_request->>'occurred_at'), false
            )
        ELSE node END
        ORDER BY ordinal
    ) INTO repaired_nodes
    FROM jsonb_array_elements(snapshot_value->'nodes')
        WITH ORDINALITY AS value(node, ordinal);
    snapshot_value := jsonb_set(snapshot_value, '{nodes}', repaired_nodes, false);
    PERFORM set_config('carl_autonomy.authority', 'coordinator', true);
    UPDATE carl_autonomy.coordinator_runtime AS item
    SET snapshot_json = carl_autonomy.canonical_jsonb(snapshot_value),
        snapshot_digest = carl_autonomy.sha256_text(
            carl_autonomy.canonical_jsonb(snapshot_value)
        ),
        effect_family = 'github',
        effect_request_json = carl_autonomy.canonical_jsonb(github_request),
        effect_request_digest = carl_autonomy.sha256_text(
            carl_autonomy.canonical_jsonb(github_request)
        ),
        updated_at = observed_at
    WHERE item.experiment_id = runtime.experiment_id
        AND item.revision = runtime.revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001', MESSAGE = 'builder_effect_revision_cas_mismatch';
    END IF;
    RETURN QUERY SELECT claim_result.applied, claim_result.claim_json,
        claim_result.command_json, claim_result.failure_code,
        claim_result.result_digest, claim_result.revision,
        claim_result.status, claim_result.transition_json;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.complete_builder_effect(
    p_completion_json text
)
RETURNS TABLE(applied boolean, revision integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    completion jsonb;
    github_response jsonb;
    runtime carl_autonomy.coordinator_runtime%ROWTYPE;
    snapshot_value jsonb;
    selected_node jsonb;
    nodes_value jsonb;
    command_state carl_autonomy.commands%ROWTYPE;
    transition_value text;
    completion_event record;
    completion_result record;
    next_revision integer;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_state_backend']);
    completion := carl_autonomy.parse_object(
        p_completion_json, 'builder_effect_completion_invalid'
    );
    IF carl_autonomy.canonical_jsonb(completion) <> p_completion_json
        OR carl_autonomy.jsonb_object_cardinality(completion) IS DISTINCT FROM 12
        OR NOT completion ?& ARRAY[
            'schema_version', 'node', 'experiment_id', 'expected_revision',
            'idempotency_key', 'command_key', 'effect_key',
            'github_binding_request_digest', 'github_request_digest',
            'github_response', 'result_digest', 'observed_at'
        ]
        OR completion->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR completion->>'node' NOT IN ('publish_experimental', 'dispatch_validation')
        OR completion->>'experiment_id' !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$'
        OR jsonb_typeof(completion->'expected_revision') <> 'number'
        OR (completion->>'expected_revision')::integer NOT BETWEEN 0 AND 2147483646
        OR completion->>'idempotency_key' !~ '^[0-9a-f]{64}$'
        OR completion->>'effect_key' !~ '^cloud-effect-[0-9a-f]{64}$'
        OR completion->>'github_binding_request_digest' !~ '^[0-9a-f]{64}$'
        OR completion->>'github_request_digest' !~ '^[0-9a-f]{64}$'
        OR completion->>'result_digest' !~ '^[0-9a-f]{64}$'
        OR NOT carl_autonomy.canonical_utc_text_valid(completion->>'observed_at')
        OR jsonb_typeof(completion->'github_response') <> 'object'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'builder_effect_completion_invalid';
    END IF;
    github_response := completion->'github_response';
    IF github_response->>'status' <> 'completed'
        OR github_response->>'request_digest' <> completion->>'github_request_digest'
        OR carl_autonomy.sha256_text(
            carl_autonomy.canonical_jsonb(github_response->'result')
        ) <> completion->>'result_digest'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'builder_effect_response_mismatch';
    END IF;
    SELECT item.* INTO runtime
    FROM carl_autonomy.coordinator_runtime AS item
    WHERE item.experiment_id = completion->>'experiment_id'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001', MESSAGE = 'builder_effect_revision_cas_mismatch';
    END IF;
    IF runtime.revision = (completion->>'expected_revision')::integer + 1 THEN
        IF EXISTS (
            SELECT 1 FROM carl_autonomy.coordinator_completion_receipts AS receipt
            WHERE receipt.experiment_id = runtime.experiment_id
                AND receipt.node_kind = completion->>'node'
                AND receipt.command_key = completion->>'command_key'
                AND receipt.effect_key = completion->>'effect_key'
                AND receipt.request_digest = completion->>'github_binding_request_digest'
                AND receipt.result_digest = completion->>'result_digest'
        ) THEN
            RETURN QUERY SELECT false, runtime.revision;
            RETURN;
        END IF;
    END IF;
    IF runtime.status IN ('complete', 'frozen')
        OR runtime.revision <> (completion->>'expected_revision')::integer
        OR runtime.effect_request_digest <> completion->>'github_request_digest'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001', MESSAGE = 'builder_effect_revision_cas_mismatch';
    END IF;
    snapshot_value := carl_autonomy.parse_object(
        runtime.snapshot_json, 'coordinator_snapshot_json_invalid'
    );
    SELECT node INTO selected_node
    FROM jsonb_array_elements(snapshot_value->'nodes') AS node
    WHERE node->>'status' = 'ready'
    ORDER BY carl_autonomy.coordinator_node_priority(node->>'kind'), node->>'node_id'
    LIMIT 1;
    SELECT command.* INTO command_state
    FROM carl_autonomy.commands AS command
    WHERE command.command_key = completion->>'command_key'
    FOR UPDATE;
    IF selected_node IS NULL
        OR selected_node->>'kind' <> completion->>'node'
        OR selected_node->>'node_id'
            <> runtime.experiment_id || ':' || (completion->>'node')
        OR NOT FOUND
        OR command_state.status <> 'claimed'
        OR command_state.effect_key <> completion->>'effect_key'
        OR command_state.request_digest <> completion->>'github_binding_request_digest'
        OR command_state.expected_revision <> runtime.revision
        OR command_state.claim_expires_at <= (completion->>'observed_at')::timestamptz
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'builder_effect_completion_identity_mismatch';
    END IF;
    SELECT * INTO completion_event
    FROM carl_autonomy.build_coordinator_completion_event(
        runtime.experiment_id,
        selected_node->>'kind',
        (selected_node->>'attempt')::integer,
        command_state.command_key,
        command_state.effect_key,
        command_state.request_digest,
        completion->>'result_digest',
        (completion->>'observed_at')::timestamptz
    );
    transition_value := carl_autonomy.canonical_jsonb(jsonb_build_object(
        'authority', command_state.authority,
        'claim_id', command_state.claim_id,
        'command_key', command_state.command_key,
        'expected_revision', command_state.revision,
        'failure_code', NULL,
        'next_revision', command_state.revision + 1,
        'result_digest', completion->>'result_digest',
        'status', 'completed'
    ));
    PERFORM set_config('carl_autonomy.authority', command_state.authority, true);
    SELECT * INTO completion_result
    FROM carl_autonomy.complete_command_and_append_event(
        transition_value,
        completion_event.event_json,
        completion_event.event_digest,
        carl_autonomy.canonical_jsonb(
            carl_autonomy.parse_object(
                completion_event.event_json, 'coordinator_completion_event_invalid'
            )->'payload'
        ),
        (completion->>'observed_at')::timestamptz
    );
    INSERT INTO carl_autonomy.coordinator_completion_receipts(
        event_digest, experiment_id, node_kind, authority, command_key,
        effect_key, request_digest, result_digest, event_json, occurred_at, recorded_at
    ) VALUES (
        completion_event.event_digest,
        runtime.experiment_id,
        selected_node->>'kind',
        completion_event.event_authority,
        command_state.command_key,
        command_state.effect_key,
        command_state.request_digest,
        completion->>'result_digest',
        completion_event.event_json,
        (completion->>'observed_at')::timestamptz,
        statement_timestamp()
    );
    SELECT jsonb_agg(
        CASE WHEN node->>'node_id' = selected_node->>'node_id'
            THEN jsonb_set(node, '{status}', '"complete"'::jsonb, false)
            ELSE node END
        ORDER BY ordinal
    ) INTO nodes_value
    FROM jsonb_array_elements(snapshot_value->'nodes')
        WITH ORDINALITY AS value(node, ordinal);
    next_revision := runtime.revision + 1;
    snapshot_value := jsonb_set(snapshot_value, '{nodes}', nodes_value, false);
    snapshot_value := jsonb_set(
        snapshot_value, '{revision}', to_jsonb(next_revision), false
    );
    PERFORM set_config('carl_autonomy.authority', 'coordinator', true);
    UPDATE carl_autonomy.coordinator_runtime AS item
    SET snapshot_json = carl_autonomy.canonical_jsonb(snapshot_value),
        snapshot_digest = carl_autonomy.sha256_text(
            carl_autonomy.canonical_jsonb(snapshot_value)
        ),
        revision = next_revision,
        status = 'ready',
        completion_event_json = NULL,
        completion_event_digest = NULL,
        effect_family = NULL,
        effect_request_json = NULL,
        effect_request_digest = NULL,
        effect_response_json = carl_autonomy.canonical_jsonb(github_response),
        updated_at = statement_timestamp()
    WHERE item.experiment_id = runtime.experiment_id
        AND item.revision = runtime.revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '40001', MESSAGE = 'builder_effect_revision_cas_mismatch';
    END IF;
    RETURN QUERY SELECT true, next_revision;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.recover_builder_effect_completion(
    p_identity_json text
)
RETURNS TABLE(found boolean, result_digest text, revision integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    identity_value jsonb;
    runtime carl_autonomy.coordinator_runtime%ROWTYPE;
    receipt carl_autonomy.coordinator_completion_receipts%ROWTYPE;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_state_backend']);
    identity_value := carl_autonomy.parse_object(
        p_identity_json, 'builder_effect_completion_identity_invalid'
    );
    IF carl_autonomy.canonical_jsonb(identity_value) <> p_identity_json
        OR carl_autonomy.jsonb_object_cardinality(identity_value) IS DISTINCT FROM 8
        OR NOT identity_value ?& ARRAY[
            'schema_version', 'node', 'experiment_id', 'expected_revision',
            'idempotency_key', 'command_key', 'effect_key',
            'github_binding_request_digest'
        ]
        OR identity_value->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR identity_value->>'node' NOT IN ('publish_experimental', 'dispatch_validation')
        OR identity_value->>'idempotency_key' !~ '^[0-9a-f]{64}$'
        OR identity_value->>'effect_key' !~ '^cloud-effect-[0-9a-f]{64}$'
        OR identity_value->>'github_binding_request_digest' !~ '^[0-9a-f]{64}$'
        OR jsonb_typeof(identity_value->'expected_revision') <> 'number'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'builder_effect_completion_identity_invalid';
    END IF;
    SELECT item.* INTO runtime
    FROM carl_autonomy.coordinator_runtime AS item
    WHERE item.experiment_id = identity_value->>'experiment_id';
    SELECT item.* INTO receipt
    FROM carl_autonomy.coordinator_completion_receipts AS item
    WHERE item.experiment_id = identity_value->>'experiment_id'
        AND item.node_kind = identity_value->>'node'
        AND item.command_key = identity_value->>'command_key'
        AND item.effect_key = identity_value->>'effect_key'
        AND item.request_digest = identity_value->>'github_binding_request_digest';
    IF receipt.event_digest IS NULL THEN
        RETURN QUERY SELECT false, NULL::text, NULL::integer;
        RETURN;
    END IF;
    IF runtime.revision <> (identity_value->>'expected_revision')::integer + 1
        OR receipt.result_digest !~ '^[0-9a-f]{64}$'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'builder_effect_completion_identity_mismatch';
    END IF;
    RETURN QUERY SELECT true, receipt.result_digest::text, runtime.revision;
END;
$$;

REVOKE ALL ON FUNCTION
    carl_autonomy.coordinator_timestamp(timestamptz),
    carl_autonomy.coordinator_node_priority(text),
    carl_autonomy.coordinator_command_state(text),
    carl_autonomy.coordinator_node_authority(text),
    carl_autonomy.coordinator_node_operation(text),
    carl_autonomy.coordinator_freeze_reason_valid(text, text),
    carl_autonomy.coordinator_authoritative_receipt_failure(text),
    carl_autonomy.freeze_coordinator_receipt_failure(text, timestamptz, text),
    carl_autonomy.build_coordinator_completion_event(
        text, text, integer, text, text, text, text, timestamptz
    ),
    carl_autonomy.coordinator_node_event_authority(text, text),
    carl_autonomy.coordinator_command_allows_node(text, text),
    carl_autonomy.enqueue_coordinator_graph(text, timestamptz),
    carl_autonomy.enqueue_pending_coordinator_graph(timestamptz),
    carl_autonomy.register_coordinator_recovery_receipt(text, timestamptz),
    carl_autonomy.reactivate_coordinator_node(text, timestamptz),
    carl_autonomy.complete_coordinator_node_event(
        text, text, text, text, text, timestamptz
    ),
    carl_autonomy.renew_coordinator_lease(text, text, integer, timestamptz),
    carl_autonomy.coordinator_frozen_status(text),
    carl_autonomy.load_coordinator_snapshot(text, timestamptz),
    carl_autonomy.apply_coordinator_decision_unchecked(text, timestamptz),
    carl_autonomy.apply_coordinator_decision(text, timestamptz),
    carl_autonomy.prepare_coordinator_effect_unchecked(text, timestamptz),
    carl_autonomy.prepare_coordinator_effect(text, timestamptz),
    carl_autonomy.complete_coordinator_effect_unchecked(text, text, timestamptz),
    carl_autonomy.complete_coordinator_effect(text, text, timestamptz),
    carl_autonomy.execute_coordinator_local_effect_unchecked(text, timestamptz),
    carl_autonomy.execute_coordinator_local_effect(text, timestamptz),
    carl_autonomy.register_and_claim_builder_effect(text),
    carl_autonomy.complete_builder_effect(text),
    carl_autonomy.recover_builder_effect_completion(text),
    carl_autonomy.coordinator_effect_family(text)
FROM PUBLIC, carl_autonomy_workflow;

GRANT EXECUTE ON FUNCTION
    carl_autonomy.register_coordinator_recovery_receipt(text, timestamptz)
TO carl_archive_backend;

GRANT EXECUTE ON FUNCTION
    carl_autonomy.coordinator_node_event_authority(text, text),
    carl_autonomy.enqueue_pending_coordinator_graph(timestamptz),
    carl_autonomy.reactivate_coordinator_node(text, timestamptz),
    carl_autonomy.complete_coordinator_node_event(
        text, text, text, text, text, timestamptz
    ),
    carl_autonomy.coordinator_frozen_status(text),
    carl_autonomy.load_coordinator_snapshot(text, timestamptz),
    carl_autonomy.apply_coordinator_decision(text, timestamptz),
    carl_autonomy.prepare_coordinator_effect(text, timestamptz),
    carl_autonomy.complete_coordinator_effect(text, text, timestamptz),
    carl_autonomy.execute_coordinator_local_effect(text, timestamptz),
    carl_autonomy.register_and_claim_builder_effect(text),
    carl_autonomy.complete_builder_effect(text),
    carl_autonomy.recover_builder_effect_completion(text)
TO carl_state_backend;

COMMIT;
