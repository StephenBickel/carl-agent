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
    effect_family varchar(24) CHECK (effect_family IN ('github')),
    effect_request_json text,
    effect_request_digest character(64),
    decision_identity character(64),
    decision_json text,
    effect_response_json text,
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
    CHECK (decision_identity IS NULL OR decision_identity ~ '^[0-9a-f]{64}$')
);

REVOKE ALL ON carl_autonomy.coordinator_runtime FROM PUBLIC, carl_autonomy_workflow;

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
    guard_state carl_autonomy.experiment_projection_guards%ROWTYPE;
    archive_state carl_autonomy.evidence_objects%ROWTYPE;
    checks_state carl_autonomy.evidence_objects%ROWTYPE;
    protection_state carl_autonomy.evidence_objects%ROWTYPE;
    dead_holder_digest text;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    SELECT runtime.* INTO selected
    FROM carl_autonomy.coordinator_runtime AS runtime
    WHERE runtime.command_name = p_command_name
        AND runtime.status NOT IN ('complete', 'frozen')
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
                IS DISTINCT FROM 'refs/heads/' || guard_state.experimental_branch
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
            IF event_value->>'experiment_id' <> runtime.experiment_id
                OR (event_value->>'occurred_at')::timestamptz > p_observed_at
                OR (event_value->>'occurred_at')::timestamptz < command_state.occurred_at
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
            PERFORM set_config('carl_autonomy.authority', command_state.authority, true);
            SELECT * INTO completion_result
            FROM carl_autonomy.complete_command_and_append_event(
                transition_value,
                runtime.completion_event_json,
                runtime.completion_event_digest,
                carl_autonomy.canonical_jsonb(event_value->'payload'),
                p_observed_at
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
        updated_at = p_observed_at
    WHERE item.experiment_id = runtime.experiment_id;
    RETURN QUERY SELECT true, p_decision_json;
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
    decision_value jsonb;
    runtime carl_autonomy.coordinator_runtime%ROWTYPE;
    request_value jsonb;
    snapshot_value jsonb;
    ready_node jsonb;
    command_state carl_autonomy.commands%ROWTYPE;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    decision_value := carl_autonomy.parse_object(
        p_decision_json, 'coordinator_decision_json_invalid'
    );
    IF decision_value->>'remote_effect' <> 'true'
        OR decision_value->>'action' NOT IN ('execute_effect', 'reconcile_effect')
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'coordinator_effect_invalid';
    END IF;
    SELECT item.* INTO runtime
    FROM carl_autonomy.coordinator_runtime AS item
    WHERE item.experiment_id = decision_value->>'experiment_id'
        AND item.revision = (decision_value->>'revision')::integer
    FOR UPDATE SKIP LOCKED;
    IF NOT FOUND OR runtime.effect_family <> 'github'
        OR runtime.effect_request_json IS NULL
    THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'coordinator_effect_not_found';
    END IF;
    IF carl_autonomy.sha256_text(runtime.effect_request_json)
        <> runtime.effect_request_digest
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
        OR decision_value->>'node' <> ready_node->>'kind'
        OR request_value->>'command_key' <> decision_value->'command'->>'command_key'
        OR request_value->>'effect_key' <> decision_value->>'effect_key'
        OR request_value->>'occurred_at' <> decision_value->'command'->>'occurred_at'
        OR request_value->>'effect_key' <> command_state.effect_key
        OR carl_autonomy.canonical_jsonb(decision_value->'command')
            <> command_state.command_json
        OR CASE ready_node->>'kind'
            WHEN 'dispatch_builder' THEN request_value->>'operation' <> 'dispatch_workflow'
            WHEN 'dispatch_validation' THEN request_value->>'operation' <> 'dispatch_workflow'
            WHEN 'publish_experimental' THEN
                request_value->>'operation' <> 'create_experimental_ref'
            WHEN 'create_promotion_pr' THEN
                request_value->>'operation' <> 'create_pull_request'
            WHEN 'observe_required_checks' THEN
                request_value->>'operation' <> 'observe_required_checks'
            WHEN 'enable_auto_merge' THEN
                request_value->>'operation' <> 'enable_pull_request_auto_merge'
            WHEN 'create_revert' THEN request_value->>'operation' <> 'create_revert_ref'
            ELSE true
        END
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_effect_identity_mismatch';
    END IF;
    UPDATE carl_autonomy.coordinator_runtime AS item
    SET decision_identity = decision_value->>'identity', decision_json = p_decision_json,
        status = 'effect_prepared', updated_at = p_observed_at
    WHERE item.experiment_id = runtime.experiment_id;
    RETURN QUERY SELECT runtime.effect_family::text, runtime.effect_request_json;
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
    decision_value jsonb;
    response_value jsonb;
    runtime carl_autonomy.coordinator_runtime%ROWTYPE;
    command_state carl_autonomy.commands%ROWTYPE;
    effect_state carl_autonomy.effect_attempts%ROWTYPE;
    transition_value text;
    failure_result record;
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
    FOR UPDATE SKIP LOCKED;
    IF NOT FOUND OR runtime.status NOT IN ('effect_prepared', 'effect_observed')
        OR response_value->>'request_digest' <> runtime.effect_request_digest
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_effect_response_mismatch';
    END IF;
    IF runtime.effect_response_json = p_response_json THEN
        RETURN QUERY SELECT false, runtime.decision_json;
        RETURN;
    END IF;
    IF runtime.effect_response_json IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'coordinator_effect_response_conflict';
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
    IF response_value->>'status' = 'completed' AND (
        NOT FOUND OR effect_state.attempt_state <> 'completed'
        OR effect_state.result_digest IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_effect_receipt_missing';
    ELSIF response_value->>'status' = 'uncertain' AND (
        NOT FOUND OR effect_state.attempt_state <> 'uncertain'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_effect_receipt_missing';
    ELSIF response_value->>'status' = 'retry_scheduled' AND (
        NOT FOUND OR effect_state.attempt_state <> 'retry_scheduled'
        OR effect_state.not_before_text <> response_value->>'retry_not_before'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'coordinator_effect_receipt_missing';
    ELSIF response_value->>'status' = 'rejected' THEN
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
    UPDATE carl_autonomy.coordinator_runtime AS item
    SET effect_response_json = p_response_json, status = 'effect_observed',
        updated_at = p_observed_at
    WHERE item.experiment_id = runtime.experiment_id;
    RETURN QUERY SELECT true, p_decision_json;
END;
$$;

REVOKE ALL ON FUNCTION
    carl_autonomy.coordinator_timestamp(timestamptz),
    carl_autonomy.coordinator_node_priority(text),
    carl_autonomy.coordinator_command_state(text),
    carl_autonomy.renew_coordinator_lease(text, text, integer, timestamptz),
    carl_autonomy.load_coordinator_snapshot(text, timestamptz),
    carl_autonomy.apply_coordinator_decision(text, timestamptz),
    carl_autonomy.prepare_coordinator_effect(text, timestamptz),
    carl_autonomy.complete_coordinator_effect(text, text, timestamptz)
FROM PUBLIC, carl_autonomy_workflow;

GRANT EXECUTE ON FUNCTION
    carl_autonomy.load_coordinator_snapshot(text, timestamptz),
    carl_autonomy.apply_coordinator_decision(text, timestamptz),
    carl_autonomy.prepare_coordinator_effect(text, timestamptz),
    carl_autonomy.complete_coordinator_effect(text, text, timestamptz)
TO carl_state_backend;

COMMIT;
