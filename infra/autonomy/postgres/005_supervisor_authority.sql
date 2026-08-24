BEGIN;

CREATE TABLE carl_autonomy.supervisor_recovery_attempts (
    trigger_id varchar(192) NOT NULL REFERENCES carl_autonomy.supervisor_triggers(trigger_id),
    attempt_id varchar(192) PRIMARY KEY,
    claim_id varchar(192) NOT NULL,
    action_kind varchar(32) NOT NULL CHECK (action_kind IN (
        'freeze_stable_boundary', 'redispatch_safe_node'
    )),
    action_digest character(64) NOT NULL CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    expected_revision integer NOT NULL CHECK (expected_revision BETWEEN 0 AND 2147483646),
    claimed_revision integer NOT NULL CHECK (claimed_revision = expected_revision + 1),
    status varchar(32) NOT NULL CHECK (status IN (
        'started', 'infrastructure_failed', 'completed'
    )),
    result_digest character(64),
    receipt_digest character(64),
    attempted_at timestamptz NOT NULL,
    completed_at timestamptz,
    UNIQUE (trigger_id, action_digest),
    CHECK (attempt_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'),
    CHECK (claim_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'),
    CHECK (result_digest IS NULL OR result_digest ~ '^[0-9a-f]{64}$'),
    CHECK (receipt_digest IS NULL OR receipt_digest ~ '^[0-9a-f]{64}$'),
    CHECK (
        (status = 'started' AND result_digest IS NULL AND receipt_digest IS NULL
            AND completed_at IS NULL)
        OR
        (status IN ('infrastructure_failed', 'completed') AND result_digest IS NOT NULL
            AND receipt_digest IS NOT NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX supervisor_recovery_attempts_trigger
    ON carl_autonomy.supervisor_recovery_attempts(trigger_id, attempted_at, attempt_id);

CREATE TABLE carl_autonomy.supervisor_recovery_receipts (
    receipt_digest character(64) PRIMARY KEY CHECK (receipt_digest ~ '^[0-9a-f]{64}$'),
    trigger_id varchar(192) NOT NULL REFERENCES carl_autonomy.supervisor_triggers(trigger_id),
    attempt_id varchar(192) NOT NULL UNIQUE
        REFERENCES carl_autonomy.supervisor_recovery_attempts(attempt_id),
    action_digest character(64) NOT NULL CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    outcome varchar(32) NOT NULL CHECK (outcome IN (
        'infrastructure_attempted', 'safe_node_redispatched', 'stable_boundary_frozen'
    )),
    authoritative_revision integer NOT NULL CHECK (
        authoritative_revision BETWEEN 1 AND 2147483647
    ),
    receipt_json text NOT NULL CHECK (octet_length(receipt_json) BETWEEN 2 AND 32768),
    recorded_at timestamptz NOT NULL,
    UNIQUE (trigger_id, action_digest)
);

CREATE OR REPLACE FUNCTION carl_autonomy.select_supervisor_trigger()
RETURNS TABLE(trigger_id text, trigger_json text, revision integer, claim_id text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_supervisor']);
    RETURN QUERY
    SELECT item.trigger_id::text, item.trigger_json, item.revision, item.claim_id::text
    FROM carl_autonomy.supervisor_triggers AS item
    WHERE item.resolution_json IS NULL
    ORDER BY
        CASE WHEN carl_autonomy.parse_object(
            item.trigger_json, 'trigger_json_invalid'
        )->>'unsafe_boundary' LIKE 'rollback:%' THEN 0 ELSE 1 END,
        item.created_at,
        item.trigger_id
    LIMIT 1;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.supervisor_recovery_result(
    p_trigger_id text,
    p_action_digest text
)
RETURNS TABLE(
    action_digest text,
    outcome text,
    receipt_json text,
    revision integer,
    trigger_id text
)
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT receipt.action_digest::text, receipt.outcome::text, receipt.receipt_json,
        receipt.authoritative_revision, receipt.trigger_id::text
    FROM carl_autonomy.supervisor_recovery_receipts AS receipt
    WHERE receipt.trigger_id = p_trigger_id
        AND receipt.action_digest = p_action_digest
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.claim_supervisor_recovery(
    p_request_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(
    action_digest text,
    applied boolean,
    attempt_id text,
    claim_id text,
    revision integer,
    trigger_id text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    request_value jsonb;
    trigger_value jsonb;
    current_state carl_autonomy.supervisor_triggers%ROWTYPE;
    expected_value integer;
    infrastructure_attempts integer;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_supervisor']);
    request_value := carl_autonomy.parse_object(
        p_request_json, 'supervisor_recovery_claim_invalid'
    );
    IF carl_autonomy.canonical_jsonb(request_value) <> p_request_json
        OR carl_autonomy.jsonb_object_cardinality(request_value) IS DISTINCT FROM 7
        OR NOT request_value ?& ARRAY[
            'schema_version', 'trigger_id', 'claim_id', 'expected_revision',
            'attempt_id', 'action_kind', 'action_digest'
        ]
        OR request_value->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR request_value->>'trigger_id' !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'
        OR request_value->>'claim_id' !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'
        OR request_value->>'attempt_id' !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'
        OR request_value->>'action_digest' !~ '^[0-9a-f]{64}$'
        OR request_value->>'action_kind' NOT IN (
            'freeze_stable_boundary', 'redispatch_safe_node'
        )
        OR jsonb_typeof(request_value->'expected_revision') <> 'number'
        OR (request_value->>'expected_revision')::integer NOT BETWEEN 0 AND 2147483646
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'supervisor_recovery_claim_invalid';
    END IF;
    expected_value := (request_value->>'expected_revision')::integer;
    SELECT item.* INTO current_state
    FROM carl_autonomy.supervisor_triggers AS item
    WHERE item.trigger_id = request_value->>'trigger_id'
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'trigger_not_found';
    END IF;
    trigger_value := carl_autonomy.parse_object(
        current_state.trigger_json, 'trigger_json_invalid'
    );
    IF trigger_value->>'unsafe_boundary' NOT LIKE 'rollback:%'
        AND EXISTS (
            SELECT 1
            FROM carl_autonomy.supervisor_triggers AS higher
            WHERE higher.resolution_json IS NULL
                AND carl_autonomy.parse_object(
                    higher.trigger_json, 'trigger_json_invalid'
                )->>'unsafe_boundary' LIKE 'rollback:%'
        )
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'rollback_priority_required';
    END IF;
    IF current_state.resolution_json IS NOT NULL
        OR current_state.status NOT IN ('pending', 'claimed')
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'trigger_not_claimable';
    END IF;
    IF current_state.claim_id IS NOT NULL
        AND current_state.claim_id <> request_value->>'claim_id'
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'trigger_claim_mismatch';
    END IF;
    IF current_state.revision <> expected_value THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'trigger_cas_mismatch';
    END IF;
    IF EXISTS (
        SELECT 1 FROM carl_autonomy.supervisor_recovery_attempts AS attempt
        WHERE attempt.trigger_id = current_state.trigger_id
            AND attempt.action_digest = request_value->>'action_digest'
    ) OR EXISTS (
        SELECT 1
        FROM jsonb_array_elements(trigger_value->'attempt_history') AS prior(item)
        WHERE prior.item->>'action_digest' = request_value->>'action_digest'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'recovery_action_unchanged';
    END IF;
    IF EXISTS (
        SELECT 1 FROM carl_autonomy.supervisor_recovery_attempts AS attempt
        WHERE attempt.trigger_id = current_state.trigger_id AND attempt.status = 'started'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'recovery_attempt_in_progress';
    END IF;
    SELECT count(*)::integer INTO infrastructure_attempts
    FROM jsonb_array_elements(trigger_value->'attempt_history') AS prior(item)
    WHERE prior.item->>'outcome' = 'infrastructure_attempted';
    IF infrastructure_attempts >= 3 THEN
        RAISE EXCEPTION USING
            ERRCODE = '54000', MESSAGE = 'infrastructure_attempt_budget_exhausted';
    END IF;
    INSERT INTO carl_autonomy.supervisor_recovery_attempts(
        trigger_id, attempt_id, claim_id, action_kind, action_digest,
        expected_revision, claimed_revision, status, attempted_at
    ) VALUES (
        current_state.trigger_id, request_value->>'attempt_id', request_value->>'claim_id',
        request_value->>'action_kind', request_value->>'action_digest', expected_value,
        expected_value + 1, 'started', p_observed_at
    );
    UPDATE carl_autonomy.supervisor_triggers AS item
    SET claim_id = request_value->>'claim_id', revision = expected_value + 1,
        status = 'claimed', updated_at = p_observed_at
    WHERE item.trigger_id = current_state.trigger_id AND item.revision = expected_value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'trigger_cas_mismatch';
    END IF;
    RETURN QUERY SELECT request_value->>'action_digest', true,
        request_value->>'attempt_id', request_value->>'claim_id',
        expected_value + 1, current_state.trigger_id::text;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.fail_supervisor_recovery(
    p_failure_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(
    action_digest text,
    outcome text,
    receipt_json text,
    revision integer,
    trigger_id text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    failure_value jsonb;
    trigger_value jsonb;
    attempt_value jsonb;
    receipt_value jsonb;
    receipt_digest_value text;
    current_state carl_autonomy.supervisor_triggers%ROWTYPE;
    current_attempt carl_autonomy.supervisor_recovery_attempts%ROWTYPE;
    expected_value integer;
    next_value integer;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_supervisor']);
    failure_value := carl_autonomy.parse_object(
        p_failure_json, 'supervisor_recovery_failure_invalid'
    );
    IF carl_autonomy.canonical_jsonb(failure_value) <> p_failure_json
        OR carl_autonomy.jsonb_object_cardinality(failure_value) IS DISTINCT FROM 8
        OR NOT failure_value ?& ARRAY[
            'schema_version', 'trigger_id', 'claim_id', 'expected_revision',
            'attempt_id', 'action_digest', 'result_digest', 'failure_code'
        ]
        OR failure_value->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR failure_value->>'trigger_id' !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'
        OR failure_value->>'claim_id' !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'
        OR failure_value->>'attempt_id' !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'
        OR failure_value->>'action_digest' !~ '^[0-9a-f]{64}$'
        OR failure_value->>'result_digest' !~ '^[0-9a-f]{64}$'
        OR failure_value->>'failure_code' !~ '^[a-z][a-z0-9_]{0,95}$'
        OR jsonb_typeof(failure_value->'expected_revision') <> 'number'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'supervisor_recovery_failure_invalid';
    END IF;
    expected_value := (failure_value->>'expected_revision')::integer;
    SELECT item.* INTO current_state
    FROM carl_autonomy.supervisor_triggers AS item
    WHERE item.trigger_id = failure_value->>'trigger_id'
    FOR UPDATE;
    SELECT item.* INTO current_attempt
    FROM carl_autonomy.supervisor_recovery_attempts AS item
    WHERE item.attempt_id = failure_value->>'attempt_id';
    IF current_state.trigger_id IS NULL OR current_attempt.attempt_id IS NULL
        OR current_state.revision <> expected_value
        OR current_state.claim_id <> failure_value->>'claim_id'
        OR current_state.resolution_json IS NOT NULL
        OR current_attempt.trigger_id <> current_state.trigger_id
        OR current_attempt.claim_id <> current_state.claim_id
        OR current_attempt.action_digest <> failure_value->>'action_digest'
        OR current_attempt.status <> 'started'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'supervisor_recovery_identity_mismatch';
    END IF;
    next_value := expected_value + 1;
    attempt_value := jsonb_build_object(
        'action_digest', failure_value->>'action_digest',
        'attempt_id', failure_value->>'attempt_id',
        'occurred_at', carl_autonomy.coordinator_timestamp(p_observed_at),
        'outcome', 'infrastructure_attempted'
    );
    trigger_value := carl_autonomy.parse_object(
        current_state.trigger_json, 'trigger_json_invalid'
    );
    trigger_value := jsonb_set(
        trigger_value, '{attempt_history}',
        (trigger_value->'attempt_history') || jsonb_build_array(attempt_value), false
    );
    receipt_value := jsonb_build_object(
        'action_digest', failure_value->>'action_digest',
        'attempt_id', failure_value->>'attempt_id',
        'authoritative_revision', next_value,
        'failure_code', failure_value->>'failure_code',
        'outcome', 'infrastructure_attempted',
        'result_digest', failure_value->>'result_digest',
        'schema_version', 1,
        'trigger_id', current_state.trigger_id
    );
    receipt_digest_value := carl_autonomy.sha256_text(
        carl_autonomy.canonical_jsonb(receipt_value)
    );
    UPDATE carl_autonomy.supervisor_triggers AS item
    SET trigger_json = carl_autonomy.canonical_jsonb(trigger_value), revision = next_value,
        updated_at = p_observed_at
    WHERE item.trigger_id = current_state.trigger_id AND item.revision = expected_value;
    UPDATE carl_autonomy.supervisor_recovery_attempts AS item
    SET status = 'infrastructure_failed', result_digest = failure_value->>'result_digest',
        receipt_digest = receipt_digest_value, completed_at = p_observed_at
    WHERE item.attempt_id = current_attempt.attempt_id AND item.status = 'started';
    INSERT INTO carl_autonomy.supervisor_recovery_receipts(
        receipt_digest, trigger_id, attempt_id, action_digest, outcome,
        authoritative_revision, receipt_json, recorded_at
    ) VALUES (
        receipt_digest_value, current_state.trigger_id, current_attempt.attempt_id,
        current_attempt.action_digest, 'infrastructure_attempted', next_value,
        carl_autonomy.canonical_jsonb(receipt_value), p_observed_at
    );
    RETURN QUERY SELECT * FROM carl_autonomy.supervisor_recovery_result(
        current_state.trigger_id, current_attempt.action_digest::text
    );
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.complete_supervisor_recovery(
    p_completion_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(
    action_digest text,
    outcome text,
    receipt_json text,
    revision integer,
    trigger_id text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    completion_value jsonb;
    trigger_value jsonb;
    attempt_value jsonb;
    resolution_value jsonb;
    receipt_value jsonb;
    receipt_digest_value text;
    current_state carl_autonomy.supervisor_triggers%ROWTYPE;
    current_attempt carl_autonomy.supervisor_recovery_attempts%ROWTYPE;
    expected_value integer;
    next_value integer;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_supervisor']);
    completion_value := carl_autonomy.parse_object(
        p_completion_json, 'supervisor_recovery_completion_invalid'
    );
    IF carl_autonomy.canonical_jsonb(completion_value) <> p_completion_json
        OR carl_autonomy.jsonb_object_cardinality(completion_value) IS DISTINCT FROM 10
        OR NOT completion_value ?& ARRAY[
            'schema_version', 'trigger_id', 'claim_id', 'expected_revision', 'attempt_id',
            'action_digest', 'evidence_digest', 'result_digest', 'outcome', 'boundary'
        ]
        OR completion_value->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR completion_value->>'outcome' <> 'stable_boundary_frozen'
        OR completion_value->>'trigger_id' !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'
        OR completion_value->>'claim_id' !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'
        OR completion_value->>'attempt_id' !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'
        OR completion_value->>'action_digest' !~ '^[0-9a-f]{64}$'
        OR completion_value->>'evidence_digest' !~ '^[0-9a-f]{64}$'
        OR completion_value->>'result_digest' !~ '^[0-9a-f]{64}$'
        OR completion_value->>'boundary' !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'
        OR jsonb_typeof(completion_value->'expected_revision') <> 'number'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'supervisor_recovery_completion_invalid';
    END IF;
    expected_value := (completion_value->>'expected_revision')::integer;
    SELECT item.* INTO current_state
    FROM carl_autonomy.supervisor_triggers AS item
    WHERE item.trigger_id = completion_value->>'trigger_id'
    FOR UPDATE;
    SELECT item.* INTO current_attempt
    FROM carl_autonomy.supervisor_recovery_attempts AS item
    WHERE item.attempt_id = completion_value->>'attempt_id';
    trigger_value := carl_autonomy.parse_object(
        current_state.trigger_json, 'trigger_json_invalid'
    );
    IF current_state.trigger_id IS NULL OR current_attempt.attempt_id IS NULL
        OR current_state.revision <> expected_value
        OR current_state.claim_id <> completion_value->>'claim_id'
        OR current_state.resolution_json IS NOT NULL
        OR current_attempt.trigger_id <> current_state.trigger_id
        OR current_attempt.claim_id <> current_state.claim_id
        OR current_attempt.action_digest <> completion_value->>'action_digest'
        OR current_attempt.action_kind <> 'freeze_stable_boundary'
        OR current_attempt.status <> 'started'
        OR trigger_value->>'evidence_digest' <> completion_value->>'evidence_digest'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'supervisor_recovery_identity_mismatch';
    END IF;
    next_value := expected_value + 1;
    attempt_value := jsonb_build_object(
        'action_digest', completion_value->>'action_digest',
        'attempt_id', completion_value->>'attempt_id',
        'occurred_at', carl_autonomy.coordinator_timestamp(p_observed_at),
        'outcome', 'stable_boundary_frozen'
    );
    trigger_value := jsonb_set(
        trigger_value, '{attempt_history}',
        (trigger_value->'attempt_history') || jsonb_build_array(attempt_value), false
    );
    resolution_value := jsonb_build_object(
        'evidence_digest', completion_value->>'evidence_digest',
        'recovery_action', attempt_value,
        'resolved_at', carl_autonomy.coordinator_timestamp(p_observed_at),
        'result_digest', completion_value->>'result_digest',
        'status', 'resolved'
    );
    receipt_value := jsonb_build_object(
        'action_digest', completion_value->>'action_digest',
        'attempt_id', completion_value->>'attempt_id',
        'authoritative_revision', next_value,
        'boundary', completion_value->>'boundary',
        'evidence_digest', completion_value->>'evidence_digest',
        'outcome', 'stable_boundary_frozen',
        'result_digest', completion_value->>'result_digest',
        'schema_version', 1,
        'trigger_id', current_state.trigger_id
    );
    receipt_digest_value := carl_autonomy.sha256_text(
        carl_autonomy.canonical_jsonb(receipt_value)
    );
    UPDATE carl_autonomy.supervisor_triggers AS item
    SET trigger_json = carl_autonomy.canonical_jsonb(trigger_value),
        resolution_json = carl_autonomy.canonical_jsonb(resolution_value),
        revision = next_value, status = 'resolved', updated_at = p_observed_at
    WHERE item.trigger_id = current_state.trigger_id AND item.revision = expected_value;
    UPDATE carl_autonomy.supervisor_recovery_attempts AS item
    SET status = 'completed', result_digest = completion_value->>'result_digest',
        receipt_digest = receipt_digest_value, completed_at = p_observed_at
    WHERE item.attempt_id = current_attempt.attempt_id AND item.status = 'started';
    INSERT INTO carl_autonomy.supervisor_recovery_receipts(
        receipt_digest, trigger_id, attempt_id, action_digest, outcome,
        authoritative_revision, receipt_json, recorded_at
    ) VALUES (
        receipt_digest_value, current_state.trigger_id, current_attempt.attempt_id,
        current_attempt.action_digest, 'stable_boundary_frozen', next_value,
        carl_autonomy.canonical_jsonb(receipt_value), p_observed_at
    );
    RETURN QUERY SELECT * FROM carl_autonomy.supervisor_recovery_result(
        current_state.trigger_id, current_attempt.action_digest::text
    );
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.complete_supervisor_redispatch(
    p_completion_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(
    action_digest text,
    outcome text,
    receipt_json text,
    revision integer,
    trigger_id text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    completion_value jsonb;
    result_value jsonb;
    trigger_value jsonb;
    attempt_value jsonb;
    resolution_value jsonb;
    receipt_value jsonb;
    receipt_digest_value text;
    current_state carl_autonomy.supervisor_triggers%ROWTYPE;
    current_attempt carl_autonomy.supervisor_recovery_attempts%ROWTYPE;
    runtime_state carl_autonomy.coordinator_runtime%ROWTYPE;
    expected_value integer;
    next_value integer;
    expected_node text;
    expected_experiment text;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_supervisor']);
    completion_value := carl_autonomy.parse_object(
        p_completion_json, 'supervisor_redispatch_completion_invalid'
    );
    IF carl_autonomy.canonical_jsonb(completion_value) <> p_completion_json
        OR carl_autonomy.jsonb_object_cardinality(completion_value) IS DISTINCT FROM 11
        OR NOT completion_value ?& ARRAY[
            'schema_version', 'trigger_id', 'claim_id', 'expected_revision', 'attempt_id',
            'action_digest', 'evidence_digest', 'result_digest', 'outcome',
            'coordinator_request_digest', 'coordinator_result'
        ]
        OR completion_value->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR completion_value->>'outcome' <> 'safe_node_redispatched'
        OR completion_value->>'coordinator_request_digest' !~ '^[0-9a-f]{64}$'
        OR completion_value->>'action_digest' !~ '^[0-9a-f]{64}$'
        OR completion_value->>'evidence_digest' !~ '^[0-9a-f]{64}$'
        OR completion_value->>'result_digest' !~ '^[0-9a-f]{64}$'
        OR jsonb_typeof(completion_value->'expected_revision') <> 'number'
        OR jsonb_typeof(completion_value->'coordinator_result') <> 'object'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'supervisor_redispatch_completion_invalid';
    END IF;
    result_value := completion_value->'coordinator_result';
    IF carl_autonomy.jsonb_object_cardinality(result_value) IS DISTINCT FROM 13
        OR result_value->'schema_version' IS DISTINCT FROM '1'::jsonb
        OR result_value->'consequential' IS DISTINCT FROM 'true'::jsonb
        OR result_value->>'action' NOT IN (
            'persist_command', 'claim_command', 'execute_effect', 'reconcile_effect',
            'complete_command', 'retry_rework'
        )
        OR result_value->>'identity' !~ '^[0-9a-f]{64}$'
        OR jsonb_typeof(result_value->'revision') <> 'number'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'supervisor_redispatch_completion_invalid';
    END IF;
    expected_value := (completion_value->>'expected_revision')::integer;
    SELECT item.* INTO current_state
    FROM carl_autonomy.supervisor_triggers AS item
    WHERE item.trigger_id = completion_value->>'trigger_id'
    FOR UPDATE;
    SELECT item.* INTO current_attempt
    FROM carl_autonomy.supervisor_recovery_attempts AS item
    WHERE item.attempt_id = completion_value->>'attempt_id';
    trigger_value := carl_autonomy.parse_object(
        current_state.trigger_json, 'trigger_json_invalid'
    );
    expected_node := regexp_replace(trigger_value->>'next_safe_node_key', '^.*:', '');
    expected_experiment := left(
        trigger_value->>'next_safe_node_key',
        length(trigger_value->>'next_safe_node_key') - length(expected_node) - 1
    );
    SELECT item.* INTO runtime_state
    FROM carl_autonomy.coordinator_runtime AS item
    WHERE item.experiment_id = expected_experiment;
    IF current_state.trigger_id IS NULL OR current_attempt.attempt_id IS NULL
        OR current_state.revision <> expected_value
        OR current_state.claim_id <> completion_value->>'claim_id'
        OR current_state.resolution_json IS NOT NULL
        OR current_attempt.trigger_id <> current_state.trigger_id
        OR current_attempt.claim_id <> current_state.claim_id
        OR current_attempt.action_digest <> completion_value->>'action_digest'
        OR current_attempt.action_kind <> 'redispatch_safe_node'
        OR current_attempt.status <> 'started'
        OR trigger_value->>'evidence_digest' <> completion_value->>'evidence_digest'
        OR result_value->>'experiment_id' <> expected_experiment
        OR result_value->>'node' <> expected_node
        OR runtime_state.experiment_id IS NULL
        OR runtime_state.revision <= (result_value->>'revision')::integer
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000', MESSAGE = 'supervisor_redispatch_identity_mismatch';
    END IF;
    next_value := expected_value + 1;
    attempt_value := jsonb_build_object(
        'action_digest', completion_value->>'action_digest',
        'attempt_id', completion_value->>'attempt_id',
        'occurred_at', carl_autonomy.coordinator_timestamp(p_observed_at),
        'outcome', 'safe_node_redispatched'
    );
    trigger_value := jsonb_set(
        trigger_value, '{attempt_history}',
        (trigger_value->'attempt_history') || jsonb_build_array(attempt_value), false
    );
    resolution_value := jsonb_build_object(
        'evidence_digest', completion_value->>'evidence_digest',
        'recovery_action', attempt_value,
        'resolved_at', carl_autonomy.coordinator_timestamp(p_observed_at),
        'result_digest', completion_value->>'result_digest',
        'status', 'resolved'
    );
    receipt_value := jsonb_build_object(
        'action_digest', completion_value->>'action_digest',
        'attempt_id', completion_value->>'attempt_id',
        'authoritative_revision', next_value,
        'coordinator_request_digest', completion_value->>'coordinator_request_digest',
        'coordinator_result_digest', completion_value->>'result_digest',
        'coordinator_runtime_revision', runtime_state.revision,
        'evidence_digest', completion_value->>'evidence_digest',
        'outcome', 'safe_node_redispatched',
        'schema_version', 1,
        'trigger_id', current_state.trigger_id
    );
    receipt_digest_value := carl_autonomy.sha256_text(
        carl_autonomy.canonical_jsonb(receipt_value)
    );
    UPDATE carl_autonomy.supervisor_triggers AS item
    SET trigger_json = carl_autonomy.canonical_jsonb(trigger_value),
        resolution_json = carl_autonomy.canonical_jsonb(resolution_value),
        revision = next_value, status = 'resolved', updated_at = p_observed_at
    WHERE item.trigger_id = current_state.trigger_id AND item.revision = expected_value;
    UPDATE carl_autonomy.supervisor_recovery_attempts AS item
    SET status = 'completed', result_digest = completion_value->>'result_digest',
        receipt_digest = receipt_digest_value, completed_at = p_observed_at
    WHERE item.attempt_id = current_attempt.attempt_id AND item.status = 'started';
    INSERT INTO carl_autonomy.supervisor_recovery_receipts(
        receipt_digest, trigger_id, attempt_id, action_digest, outcome,
        authoritative_revision, receipt_json, recorded_at
    ) VALUES (
        receipt_digest_value, current_state.trigger_id, current_attempt.attempt_id,
        current_attempt.action_digest, 'safe_node_redispatched', next_value,
        carl_autonomy.canonical_jsonb(receipt_value), p_observed_at
    );
    RETURN QUERY SELECT * FROM carl_autonomy.supervisor_recovery_result(
        current_state.trigger_id, current_attempt.action_digest::text
    );
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.read_supervisor_recovery_receipt(
    p_trigger_id text,
    p_action_digest text
)
RETURNS TABLE(
    action_digest text,
    outcome text,
    receipt_json text,
    revision integer,
    trigger_id text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_supervisor']);
    IF p_trigger_id !~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'
        OR p_action_digest !~ '^[0-9a-f]{64}$'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023', MESSAGE = 'supervisor_recovery_receipt_identity_invalid';
    END IF;
    RETURN QUERY SELECT * FROM carl_autonomy.supervisor_recovery_result(
        p_trigger_id, p_action_digest
    );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0002', MESSAGE = 'supervisor_recovery_receipt_not_found';
    END IF;
END;
$$;

REVOKE ALL ON TABLE carl_autonomy.supervisor_recovery_attempts,
    carl_autonomy.supervisor_recovery_receipts
FROM PUBLIC, carl_autonomy_workflow;

REVOKE ALL ON FUNCTION
    carl_autonomy.select_supervisor_trigger(),
    carl_autonomy.supervisor_recovery_result(text, text),
    carl_autonomy.claim_supervisor_recovery(text, timestamptz),
    carl_autonomy.fail_supervisor_recovery(text, timestamptz),
    carl_autonomy.complete_supervisor_recovery(text, timestamptz),
    carl_autonomy.complete_supervisor_redispatch(text, timestamptz),
    carl_autonomy.read_supervisor_recovery_receipt(text, text),
    carl_autonomy.claim_supervisor_trigger(text, text, integer, timestamptz),
    carl_autonomy.resolve_supervisor_trigger(text, text, integer, text, timestamptz)
FROM PUBLIC, carl_autonomy_workflow, carl_state_backend;

GRANT EXECUTE ON FUNCTION
    carl_autonomy.select_supervisor_trigger(),
    carl_autonomy.claim_supervisor_recovery(text, timestamptz),
    carl_autonomy.fail_supervisor_recovery(text, timestamptz),
    carl_autonomy.complete_supervisor_recovery(text, timestamptz),
    carl_autonomy.complete_supervisor_redispatch(text, timestamptz),
    carl_autonomy.read_supervisor_recovery_receipt(text, text)
TO carl_state_backend;

COMMIT;
