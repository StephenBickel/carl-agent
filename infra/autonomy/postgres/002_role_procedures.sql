BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'carl_autonomy_workflow') THEN
        CREATE ROLE carl_autonomy_workflow NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END;
$$;

DO $$
DECLARE
    role_name text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format(
                'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT',
                role_name
            );
        END IF;
        EXECUTE format('GRANT carl_autonomy_workflow TO %I', role_name);
    END LOOP;
END;
$$;

GRANT USAGE ON SCHEMA carl_autonomy TO carl_autonomy_workflow;
REVOKE ALL ON ALL TABLES IN SCHEMA carl_autonomy FROM carl_autonomy_workflow;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA carl_autonomy FROM carl_autonomy_workflow;

CREATE OR REPLACE FUNCTION carl_autonomy.caller_role()
RETURNS text
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT CASE
        WHEN current_setting('role', true) IS NULL OR current_setting('role', true) = 'none'
            THEN session_user::text
        ELSE current_setting('role', true)
    END
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.require_role(allowed_roles text[])
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    role_name text := carl_autonomy.caller_role();
BEGIN
    IF role_name <> ALL(allowed_roles) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'database_role_denied';
    END IF;
    RETURN role_name;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.role_authority(role_name text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT CASE role_name
        WHEN 'carl_builder' THEN 'builder'
        WHEN 'carl_validator' THEN 'validator'
        WHEN 'carl_promoter' THEN 'promoter'
        WHEN 'carl_soak' THEN 'soak'
        WHEN 'carl_supervisor' THEN 'supervisor'
        WHEN 'carl_coordinator' THEN 'coordinator'
        WHEN 'carl_observer' THEN 'observer'
        ELSE NULL
    END
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.parse_object(value text, error_code text)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    decoded jsonb;
BEGIN
    IF octet_length(value) > 131072 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = error_code;
    END IF;
    BEGIN
        decoded := value::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = error_code;
    END;
    IF jsonb_typeof(decoded) <> 'object' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = error_code;
    END IF;
    RETURN decoded;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.sha256_text(value text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT encode(carl_autonomy.digest(convert_to(value, 'UTF8'), 'sha256'), 'hex')
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.event_role_allowed(
    role_name text,
    event_type text,
    payload jsonb
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT CASE role_name
        WHEN 'carl_builder' THEN event_type IN (
            'role_recorded', 'workspace_prepared', 'candidate_sealed', 'experimental_published'
        )
        WHEN 'carl_validator' THEN event_type IN (
            'paired_evidence_recorded', 'review_packet_recorded', 'review_attested',
            'protected_validation_recorded'
        )
        WHEN 'carl_promoter' THEN event_type IN (
            'draft_pr_requested', 'draft_pr_recorded', 'workspace_disposed', 'promotion_recorded'
        )
        WHEN 'carl_soak' THEN event_type IN ('soak_observed', 'revert_recorded') OR (
            event_type = 'state_transitioned'
            AND payload->>'from_state' = 'soaking'
            AND payload->>'to_state' = 'accepted'
        )
        WHEN 'carl_coordinator' THEN event_type IN (
            'state_transitioned', 'lease_acquired', 'lease_reconciled', 'lease_released',
            'live_spend_recorded', 'retry_scheduled'
        )
        ELSE false
    END
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.register_manifest(
    p_manifest_json text,
    p_manifest_digest text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    caller text;
    value jsonb;
    experiment_key text;
    parent_key text;
    registered_text text;
    registered_time timestamptz;
    parent_registered timestamptz;
    existing carl_autonomy.experiment_manifests%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY['carl_builder']);
    value := carl_autonomy.parse_object(p_manifest_json, 'manifest_json_invalid');
    IF carl_autonomy.sha256_text(p_manifest_json) <> p_manifest_digest THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'manifest_digest_mismatch';
    END IF;
    experiment_key := value->>'experiment_id';
    parent_key := value->>'parent_experiment_id';
    registered_text := value->>'registered_at';
    BEGIN
        registered_time := registered_text::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'manifest_json_invalid';
    END;
    IF experiment_key IS NULL OR registered_text IS NULL OR value->>'schema_version' <> '1' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'manifest_json_invalid';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(experiment_key, 0));
    SELECT m.* INTO existing
    FROM carl_autonomy.experiment_manifests AS m
    WHERE m.experiment_id = experiment_key;
    IF FOUND THEN
        IF existing.parent_experiment_id IS NOT DISTINCT FROM parent_key
            AND existing.manifest_json = p_manifest_json
            AND existing.manifest_digest = p_manifest_digest
        THEN
            RETURN QUERY SELECT false;
            RETURN;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'manifest_conflict';
    END IF;
    IF parent_key IS NOT NULL THEN
        SELECT m.registered_at INTO parent_registered
        FROM carl_autonomy.experiment_manifests AS m
        WHERE m.experiment_id = parent_key
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'parent_experiment_not_found';
        END IF;
        IF registered_time < parent_registered THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'child_precedes_parent';
        END IF;
    END IF;
    INSERT INTO carl_autonomy.experiment_manifests(
        experiment_id, parent_experiment_id, manifest_json, manifest_digest,
        registered_at, registered_at_text, recorded_at
    ) VALUES (
        experiment_key, parent_key, p_manifest_json, p_manifest_digest,
        registered_time, registered_text, p_observed_at
    );
    RETURN QUERY SELECT true;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.append_event(
    p_event_json text,
    p_event_digest text,
    p_payload_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(ordinal integer, event_digest text, chain_digest text, appended boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    caller text;
    authority_name text;
    value jsonb;
    payload jsonb;
    experiment_key text;
    attempt_key text;
    type_name text;
    occurred_text text;
    occurred_time timestamptz;
    manifest_hash text;
    existing carl_autonomy.experiment_events%ROWTYPE;
    next_ordinal integer;
    previous_hash text;
    next_chain text;
    chain_payload text;
BEGIN
    caller := carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak', 'carl_coordinator'
    ]);
    authority_name := carl_autonomy.role_authority(caller);
    value := carl_autonomy.parse_object(p_event_json, 'event_json_invalid');
    payload := carl_autonomy.parse_object(p_payload_json, 'event_payload_invalid');
    IF carl_autonomy.sha256_text(p_event_json) <> p_event_digest
        OR value->'payload' <> payload
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'event_digest_mismatch';
    END IF;
    experiment_key := value->>'experiment_id';
    attempt_key := value->>'stage_attempt_id';
    type_name := value->>'event_type';
    occurred_text := value->>'occurred_at';
    BEGIN
        occurred_time := occurred_text::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'event_json_invalid';
    END;
    IF experiment_key IS NULL OR attempt_key IS NULL OR type_name IS NULL
        OR occurred_text IS NULL OR value->>'schema_version' <> '1'
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'event_json_invalid';
    END IF;
    IF NOT carl_autonomy.event_role_allowed(caller, type_name, payload) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'event_authority_denied';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(attempt_key, 1));
    SELECT e.* INTO existing
    FROM carl_autonomy.experiment_events AS e
    WHERE e.stage_attempt_id = attempt_key;
    IF FOUND THEN
        IF existing.experiment_id = experiment_key AND existing.event_digest = p_event_digest THEN
            RETURN QUERY SELECT existing.ordinal, existing.event_digest::text,
                existing.chain_digest::text, false;
            RETURN;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'stage_attempt_conflict';
    END IF;
    SELECT m.manifest_digest::text INTO manifest_hash
    FROM carl_autonomy.experiment_manifests AS m
    WHERE m.experiment_id = experiment_key
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'experiment_not_found';
    END IF;
    SELECT e.ordinal, e.chain_digest::text
    INTO next_ordinal, previous_hash
    FROM carl_autonomy.experiment_events AS e
    WHERE e.experiment_id = experiment_key
    ORDER BY e.ordinal DESC
    LIMIT 1;
    IF FOUND THEN
        IF next_ordinal = 2147483647 THEN
            RAISE EXCEPTION USING ERRCODE = '22003', MESSAGE = 'event_ordinal_exhausted';
        END IF;
        next_ordinal := next_ordinal + 1;
    ELSE
        next_ordinal := 1;
        previous_hash := repeat('0', 64);
    END IF;
    chain_payload := '{"event_digest":' || to_json(p_event_digest)::text
        || ',"experiment_id":' || to_json(experiment_key)::text
        || ',"manifest_digest":' || to_json(manifest_hash)::text
        || ',"ordinal":' || next_ordinal::text
        || ',"previous_chain_digest":' || to_json(previous_hash)::text || '}';
    next_chain := carl_autonomy.sha256_text(chain_payload);
    INSERT INTO carl_autonomy.experiment_events(
        experiment_id, ordinal, schema_version, stage_attempt_id, event_type,
        occurred_at, occurred_at_text, payload_json, event_json, event_digest,
        previous_chain_digest, chain_digest, authority, provenance_json, appended_at
    ) VALUES (
        experiment_key, next_ordinal, 1, attempt_key, type_name,
        occurred_time, occurred_text, p_payload_json, p_event_json, p_event_digest,
        previous_hash, next_chain, authority_name,
        json_build_object('database_role', caller, 'observed_at', p_observed_at)::text,
        p_observed_at
    );
    RETURN QUERY SELECT next_ordinal, p_event_digest, next_chain, true;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.load_experiment_manifest(p_experiment_id text)
RETURNS TABLE(manifest_json text, manifest_digest text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]);
    RETURN QUERY
    SELECT m.manifest_json, m.manifest_digest::text
    FROM carl_autonomy.experiment_manifests AS m
    WHERE m.experiment_id = p_experiment_id;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.load_experiment_events(p_experiment_id text)
RETURNS TABLE(
    authority text,
    chain_digest text,
    event_digest text,
    event_json text,
    ordinal integer,
    previous_chain_digest text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]);
    RETURN QUERY
    SELECT e.authority::text, e.chain_digest::text, e.event_digest::text,
        e.event_json, e.ordinal, e.previous_chain_digest::text
    FROM carl_autonomy.experiment_events AS e
    WHERE e.experiment_id = p_experiment_id
    ORDER BY e.ordinal;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.command_operation_allowed(
    authority_name text,
    operation_name text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT CASE authority_name
        WHEN 'builder' THEN operation_name IN ('register_manifest', 'candidate_fact', 'publish_experimental')
        WHEN 'validator' THEN operation_name IN ('append_disposition', 'protected_evidence', 'register_evidence')
        WHEN 'promoter' THEN operation_name IN ('record_promotion', 'github_effect')
        WHEN 'soak' THEN operation_name IN ('record_soak', 'record_revert', 'production_observation')
        WHEN 'supervisor' THEN operation_name IN ('claim_trigger', 'dispatch', 'resolve_trigger', 'recovery')
        WHEN 'coordinator' THEN operation_name IN (
            'await_run', 'blocked', 'dispatch', 'download_artifacts', 'reconcile',
            'record_success', 'release_lease', 'schedule', 'schedule_retry'
        )
        WHEN 'observer' THEN operation_name IN ('observe', 'register_evidence')
        ELSE false
    END
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.command_result(p_command_key text, p_applied boolean)
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
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT p_applied, c.claim_json, c.command_json, c.failure_code::text,
        c.result_digest::text, c.revision, c.status::text, c.transition_json
    FROM carl_autonomy.commands AS c
    WHERE c.command_key = p_command_key
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.create_command(
    p_command_json text,
    p_observed_at timestamptz
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
    caller text;
    caller_authority text;
    value jsonb;
    command_key_value text;
    effect_key_value text;
    authority_value text;
    operation_value text;
    request_hash text;
    occurred_text text;
    occurred_time timestamptz;
    expected_value integer;
    attempt_value smallint;
    maximum_value smallint;
    expected_effect text;
    effect_payload text;
    existing carl_autonomy.commands%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]);
    caller_authority := carl_autonomy.role_authority(caller);
    value := carl_autonomy.parse_object(p_command_json, 'command_json_invalid');
    command_key_value := value->>'command_key';
    effect_key_value := value->>'effect_key';
    authority_value := value->>'authority';
    operation_value := value->>'operation';
    request_hash := value->>'request_digest';
    occurred_text := value->>'occurred_at';
    BEGIN
        occurred_time := occurred_text::timestamptz;
        expected_value := (value->>'expected_revision')::integer;
        attempt_value := (value->>'attempt')::smallint;
        maximum_value := (value->>'max_attempts')::smallint;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'command_json_invalid';
    END;
    IF value->>'schema_version' <> '1' OR authority_value <> caller_authority
        OR NOT carl_autonomy.command_operation_allowed(authority_value, operation_value)
        OR expected_value < 0 OR expected_value > 2147483646
        OR attempt_value < 1 OR maximum_value > 3 OR attempt_value > maximum_value
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'command_authority_denied';
    END IF;
    effect_payload := '{"authority":' || to_json(authority_value)::text
        || ',"command_key":' || to_json(command_key_value)::text
        || ',"operation":' || to_json(operation_value)::text
        || ',"request_digest":' || to_json(request_hash)::text || '}';
    expected_effect := 'cloud-effect-' || carl_autonomy.sha256_text(effect_payload);
    IF effect_key_value <> expected_effect THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'command_effect_key_mismatch';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(command_key_value, 2));
    SELECT c.* INTO existing
    FROM carl_autonomy.commands AS c
    WHERE c.command_key = command_key_value;
    IF FOUND THEN
        IF existing.effect_key = effect_key_value
            AND existing.authority = authority_value
            AND existing.operation = operation_value
            AND existing.request_digest = request_hash
            AND existing.expected_revision = expected_value
            AND existing.attempt = attempt_value
            AND existing.max_attempts = maximum_value
        THEN
            RETURN QUERY SELECT * FROM carl_autonomy.command_result(command_key_value, false);
            RETURN;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'command_replay_conflict';
    END IF;
    INSERT INTO carl_autonomy.commands(
        command_key, effect_key, command_json, authority, operation, request_digest,
        occurred_at, occurred_at_text, expected_revision, attempt, max_attempts,
        revision, status, created_at, updated_at
    ) VALUES (
        command_key_value, effect_key_value, p_command_json, authority_value, operation_value,
        request_hash, occurred_time, occurred_text, expected_value, attempt_value, maximum_value,
        expected_value, 'pending', p_observed_at, p_observed_at
    );
    RETURN QUERY SELECT * FROM carl_autonomy.command_result(command_key_value, true);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.claim_command(
    p_claim_json text,
    p_observed_at timestamptz
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
    caller text;
    caller_authority text;
    value jsonb;
    command_key_value text;
    claim_key text;
    authority_value text;
    expected_value integer;
    claimed_text text;
    expires_text text;
    claimed_time timestamptz;
    expires_time timestamptz;
    current_state carl_autonomy.commands%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]);
    caller_authority := carl_autonomy.role_authority(caller);
    value := carl_autonomy.parse_object(p_claim_json, 'claim_json_invalid');
    command_key_value := value->>'command_key';
    claim_key := value->>'claim_id';
    authority_value := value->>'authority';
    claimed_text := value->>'claimed_at';
    expires_text := value->>'expires_at';
    BEGIN
        expected_value := (value->>'expected_revision')::integer;
        claimed_time := claimed_text::timestamptz;
        expires_time := expires_text::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'claim_json_invalid';
    END;
    IF authority_value <> caller_authority OR expires_time <= claimed_time
        OR expires_time <= p_observed_at
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'command_authority_denied';
    END IF;
    SELECT c.* INTO current_state
    FROM carl_autonomy.commands AS c
    WHERE c.command_key = command_key_value
    FOR UPDATE SKIP LOCKED;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM carl_autonomy.commands AS c WHERE c.command_key = command_key_value
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '55P03', MESSAGE = 'command_busy';
        END IF;
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'command_not_found';
    END IF;
    IF current_state.authority <> authority_value THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'command_authority_denied';
    END IF;
    IF current_state.status = 'claimed' AND current_state.claim_json = p_claim_json THEN
        RETURN QUERY SELECT * FROM carl_autonomy.command_result(command_key_value, false);
        RETURN;
    END IF;
    IF current_state.status <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'command_not_claimable';
    END IF;
    IF current_state.revision <> expected_value OR current_state.revision = 2147483647 THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'command_cas_mismatch';
    END IF;
    UPDATE carl_autonomy.commands AS c
    SET status = 'claimed', revision = current_state.revision + 1,
        claim_json = p_claim_json, claim_id = claim_key,
        claimed_at = claimed_time, claimed_at_text = claimed_text,
        claim_expires_at = expires_time, claim_expires_at_text = expires_text,
        updated_at = p_observed_at
    WHERE c.command_key = command_key_value;
    RETURN QUERY SELECT * FROM carl_autonomy.command_result(command_key_value, true);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.reconcile_expired_claim(
    p_reconciliation_json text,
    p_dead_holder_json text,
    p_observed_at timestamptz
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
    caller text;
    caller_authority text;
    value jsonb;
    dead_value jsonb;
    command_key_value text;
    claim_key text;
    authority_value text;
    expected_value integer;
    next_value integer;
    observed_text text;
    current_state carl_autonomy.commands%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]);
    caller_authority := carl_autonomy.role_authority(caller);
    value := carl_autonomy.parse_object(p_reconciliation_json, 'claim_reconciliation_invalid');
    dead_value := carl_autonomy.parse_object(p_dead_holder_json, 'dead_holder_observation_invalid');
    command_key_value := value->>'command_key';
    claim_key := value->>'claim_id';
    authority_value := value->>'authority';
    observed_text := value->>'observed_at';
    BEGIN
        expected_value := (value->>'expected_revision')::integer;
        next_value := (value->>'next_revision')::integer;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'claim_reconciliation_invalid';
    END;
    IF authority_value <> caller_authority OR next_value <> expected_value + 1
        OR dead_value->>'authority' <> authority_value
        OR dead_value->>'subject_id' <> claim_key
        OR dead_value->>'scope_kind' <> 'command'
        OR dead_value->>'scope_key' <> command_key_value
        OR (dead_value->>'revision')::integer <> expected_value
        OR (dead_value->>'live')::boolean IS DISTINCT FROM false
        OR dead_value->>'observed_at' <> observed_text
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'dead_holder_observation_mismatch';
    END IF;
    SELECT c.* INTO current_state
    FROM carl_autonomy.commands AS c
    WHERE c.command_key = command_key_value
    FOR UPDATE;
    IF NOT FOUND OR current_state.status <> 'claimed' OR current_state.claim_id <> claim_key THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'command_not_reconcilable';
    END IF;
    IF current_state.revision <> expected_value THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'command_cas_mismatch';
    END IF;
    IF p_observed_at < current_state.claim_expires_at THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'command_claim_active';
    END IF;
    UPDATE carl_autonomy.commands AS c
    SET status = 'pending', revision = next_value,
        claim_json = NULL, claim_id = NULL, claimed_at = NULL, claimed_at_text = NULL,
        claim_expires_at = NULL, claim_expires_at_text = NULL,
        transition_json = NULL, result_digest = NULL, failure_code = NULL,
        updated_at = p_observed_at
    WHERE c.command_key = command_key_value;
    RETURN QUERY SELECT * FROM carl_autonomy.command_result(command_key_value, true);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.terminal_command(
    p_transition_json text,
    p_status text,
    p_observed_at timestamptz
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
    caller text;
    caller_authority text;
    value jsonb;
    command_key_value text;
    claim_key text;
    authority_value text;
    expected_value integer;
    next_value integer;
    result_value text;
    failure_value text;
    current_state carl_autonomy.commands%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]);
    caller_authority := carl_autonomy.role_authority(caller);
    IF p_status NOT IN ('completed', 'failed') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'transition_status_invalid';
    END IF;
    value := carl_autonomy.parse_object(p_transition_json, 'transition_json_invalid');
    command_key_value := value->>'command_key';
    claim_key := value->>'claim_id';
    authority_value := value->>'authority';
    result_value := value->>'result_digest';
    failure_value := value->>'failure_code';
    BEGIN
        expected_value := (value->>'expected_revision')::integer;
        next_value := (value->>'next_revision')::integer;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'transition_json_invalid';
    END;
    IF authority_value <> caller_authority OR value->>'status' <> p_status
        OR next_value <> expected_value + 1
        OR (p_status = 'completed' AND (result_value IS NULL OR failure_value IS NOT NULL))
        OR (p_status = 'failed' AND (result_value IS NOT NULL OR failure_value IS NULL))
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transition_authority_denied';
    END IF;
    SELECT c.* INTO current_state
    FROM carl_autonomy.commands AS c
    WHERE c.command_key = command_key_value
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'command_not_found';
    END IF;
    IF current_state.status = p_status THEN
        IF current_state.transition_json = p_transition_json THEN
            RETURN QUERY SELECT * FROM carl_autonomy.command_result(command_key_value, false);
            RETURN;
        END IF;
        IF p_status = 'completed' THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'command_result_conflict';
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'command_failure_conflict';
    END IF;
    IF current_state.status <> 'claimed' OR current_state.claim_id <> claim_key THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'command_not_completable';
    END IF;
    IF current_state.revision <> expected_value OR next_value > 2147483647 THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'command_cas_mismatch';
    END IF;
    IF p_observed_at >= current_state.claim_expires_at THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'command_claim_expired';
    END IF;
    UPDATE carl_autonomy.commands AS c
    SET status = p_status, revision = next_value, transition_json = p_transition_json,
        result_digest = result_value, failure_code = failure_value, updated_at = p_observed_at
    WHERE c.command_key = command_key_value;
    RETURN QUERY SELECT * FROM carl_autonomy.command_result(command_key_value, true);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.complete_command(
    p_transition_json text,
    p_observed_at timestamptz
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
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT * FROM carl_autonomy.terminal_command(p_transition_json, 'completed', p_observed_at)
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.fail_command(
    p_transition_json text,
    p_observed_at timestamptz
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
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT * FROM carl_autonomy.terminal_command(p_transition_json, 'failed', p_observed_at)
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.lease_document(
    p_lease_key text,
    p_holder_id text,
    p_authority text,
    p_revision integer,
    p_acquired_at text,
    p_expires_at text,
    p_reconciled_at text,
    p_observation_digest text,
    p_released_at text
)
RETURNS text
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT '{"acquired_at":' || to_json(p_acquired_at)::text
        || ',"authority":' || to_json(p_authority)::text
        || ',"expires_at":' || to_json(p_expires_at)::text
        || ',"holder_id":' || to_json(p_holder_id)::text
        || ',"lease_key":' || to_json(p_lease_key)::text
        || ',"reconciled_at":' || COALESCE(to_json(p_reconciled_at)::text, 'null')
        || ',"reconciliation_observation_digest":'
        || COALESCE(to_json(p_observation_digest)::text, 'null')
        || ',"released_at":' || COALESCE(to_json(p_released_at)::text, 'null')
        || ',"revision":' || p_revision::text || '}'
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.lease_result(p_lease_key text, p_applied boolean)
RETURNS TABLE(applied boolean, lease_json text, revision integer)
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT p_applied, l.lease_json, l.revision
    FROM carl_autonomy.leases AS l
    WHERE l.lease_key = p_lease_key
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.acquire_lease(
    p_lease_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean, lease_json text, revision integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    caller text;
    caller_authority text;
    value jsonb;
    lease_key_value text;
    holder_value text;
    authority_value text;
    expected_value integer;
    acquired_text text;
    expires_text text;
    acquired_time timestamptz;
    expires_time timestamptz;
    next_value integer;
    document text;
    current_state carl_autonomy.leases%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY['carl_coordinator', 'carl_supervisor']);
    caller_authority := carl_autonomy.role_authority(caller);
    value := carl_autonomy.parse_object(p_lease_json, 'lease_json_invalid');
    lease_key_value := value->>'lease_key';
    holder_value := value->>'holder_id';
    authority_value := value->>'authority';
    acquired_text := value->>'acquired_at';
    expires_text := value->>'expires_at';
    BEGIN
        expected_value := (value->>'revision')::integer;
        acquired_time := acquired_text::timestamptz;
        expires_time := expires_text::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'lease_json_invalid';
    END;
    IF authority_value <> caller_authority OR expires_time <= acquired_time
        OR acquired_time < p_observed_at OR value->>'reconciled_at' IS NOT NULL
        OR value->>'reconciliation_observation_digest' IS NOT NULL
        OR value->>'released_at' IS NOT NULL
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'lease_authority_denied';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(lease_key_value, 3));
    SELECT l.* INTO current_state
    FROM carl_autonomy.leases AS l
    WHERE l.lease_key = lease_key_value
    FOR UPDATE;
    IF FOUND THEN
        IF current_state.authority <> authority_value THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'lease_authority_denied';
        END IF;
        IF current_state.revision <> expected_value OR expected_value = 2147483647 THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'lease_cas_mismatch';
        END IF;
        IF current_state.status = 'active' AND p_observed_at < current_state.expires_at THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'lease_active';
        END IF;
        IF current_state.status = 'active' THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'lease_reconciliation_required';
        END IF;
        IF current_state.status = 'reconciled' THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'lease_release_required';
        END IF;
        next_value := expected_value + 1;
        document := carl_autonomy.lease_document(
            lease_key_value, holder_value, authority_value, next_value,
            acquired_text, expires_text, NULL, NULL, NULL
        );
        UPDATE carl_autonomy.leases AS l
        SET lease_json = document, holder_id = holder_value, revision = next_value,
            acquired_at = acquired_time, acquired_at_text = acquired_text,
            expires_at = expires_time, expires_at_text = expires_text,
            reconciled_at = NULL, reconciled_at_text = NULL,
            reconciliation_observation_digest = NULL,
            released_at = NULL, released_at_text = NULL,
            status = 'active', updated_at = p_observed_at
        WHERE l.lease_key = lease_key_value;
    ELSE
        IF expected_value <> 0 THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'lease_cas_mismatch';
        END IF;
        next_value := 1;
        document := carl_autonomy.lease_document(
            lease_key_value, holder_value, authority_value, next_value,
            acquired_text, expires_text, NULL, NULL, NULL
        );
        INSERT INTO carl_autonomy.leases(
            lease_key, lease_json, holder_id, authority, revision,
            acquired_at, acquired_at_text, expires_at, expires_at_text,
            status, updated_at
        ) VALUES (
            lease_key_value, document, holder_value, authority_value, next_value,
            acquired_time, acquired_text, expires_time, expires_text,
            'active', p_observed_at
        );
    END IF;
    RETURN QUERY SELECT * FROM carl_autonomy.lease_result(lease_key_value, true);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.reconcile_lease(
    p_reconciliation_json text,
    p_dead_holder_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean, lease_json text, revision integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    caller text;
    caller_authority text;
    value jsonb;
    dead_value jsonb;
    lease_key_value text;
    holder_value text;
    authority_value text;
    expected_value integer;
    next_value integer;
    observed_text text;
    observation_digest text;
    document text;
    current_state carl_autonomy.leases%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY['carl_coordinator', 'carl_supervisor']);
    caller_authority := carl_autonomy.role_authority(caller);
    value := carl_autonomy.parse_object(p_reconciliation_json, 'lease_reconciliation_invalid');
    dead_value := carl_autonomy.parse_object(p_dead_holder_json, 'dead_holder_observation_invalid');
    lease_key_value := value->>'lease_key';
    holder_value := value->>'holder_id';
    authority_value := value->>'authority';
    observed_text := value->>'observed_at';
    BEGIN
        expected_value := (value->>'expected_revision')::integer;
        next_value := (value->>'next_revision')::integer;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'lease_reconciliation_invalid';
    END;
    IF authority_value <> caller_authority OR next_value <> expected_value + 1
        OR dead_value->>'authority' <> authority_value
        OR dead_value->>'subject_id' <> holder_value
        OR dead_value->>'scope_kind' <> 'lease'
        OR dead_value->>'scope_key' <> lease_key_value
        OR (dead_value->>'revision')::integer <> expected_value
        OR (dead_value->>'live')::boolean IS DISTINCT FROM false
        OR dead_value->>'observed_at' <> observed_text
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'dead_holder_observation_mismatch';
    END IF;
    SELECT l.* INTO current_state
    FROM carl_autonomy.leases AS l
    WHERE l.lease_key = lease_key_value
    FOR UPDATE;
    IF NOT FOUND OR current_state.status <> 'active'
        OR current_state.holder_id <> holder_value OR current_state.authority <> authority_value
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'lease_reconciliation_mismatch';
    END IF;
    IF current_state.revision <> expected_value THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'lease_cas_mismatch';
    END IF;
    IF p_observed_at < current_state.expires_at THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'lease_active';
    END IF;
    observation_digest := carl_autonomy.sha256_text(p_dead_holder_json);
    document := carl_autonomy.lease_document(
        lease_key_value, holder_value, authority_value, next_value,
        current_state.acquired_at_text, current_state.expires_at_text,
        observed_text, observation_digest, NULL
    );
    UPDATE carl_autonomy.leases AS l
    SET lease_json = document, revision = next_value,
        reconciled_at = p_observed_at, reconciled_at_text = observed_text,
        reconciliation_observation_digest = observation_digest,
        status = 'reconciled', updated_at = p_observed_at
    WHERE l.lease_key = lease_key_value;
    RETURN QUERY SELECT * FROM carl_autonomy.lease_result(lease_key_value, true);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.release_lease(
    p_release_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean, lease_json text, revision integer)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    caller text;
    caller_authority text;
    value jsonb;
    lease_key_value text;
    holder_value text;
    authority_value text;
    expected_value integer;
    next_value integer;
    released_text text;
    released_time timestamptz;
    evidence_value text;
    document text;
    current_state carl_autonomy.leases%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY['carl_coordinator', 'carl_supervisor']);
    caller_authority := carl_autonomy.role_authority(caller);
    value := carl_autonomy.parse_object(p_release_json, 'lease_release_invalid');
    lease_key_value := value->>'lease_key';
    holder_value := value->>'holder_id';
    authority_value := value->>'authority';
    released_text := value->>'released_at';
    evidence_value := value->>'observation_digest';
    BEGIN
        expected_value := (value->>'expected_revision')::integer;
        next_value := (value->>'next_revision')::integer;
        released_time := released_text::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'lease_release_invalid';
    END;
    IF authority_value <> caller_authority OR next_value <> expected_value + 1 THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'lease_authority_denied';
    END IF;
    SELECT l.* INTO current_state
    FROM carl_autonomy.leases AS l
    WHERE l.lease_key = lease_key_value
    FOR UPDATE;
    IF NOT FOUND OR current_state.status = 'released'
        OR current_state.holder_id <> holder_value OR current_state.authority <> authority_value
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'lease_release_mismatch';
    END IF;
    IF current_state.revision <> expected_value THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'lease_cas_mismatch';
    END IF;
    IF current_state.status = 'reconciled'
        AND evidence_value IS DISTINCT FROM current_state.reconciliation_observation_digest::text
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'lease_release_evidence_mismatch';
    END IF;
    IF current_state.status = 'active' AND evidence_value IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'lease_release_evidence_unexpected';
    END IF;
    document := carl_autonomy.lease_document(
        lease_key_value, holder_value, authority_value, next_value,
        current_state.acquired_at_text, current_state.expires_at_text,
        current_state.reconciled_at_text,
        current_state.reconciliation_observation_digest::text, released_text
    );
    UPDATE carl_autonomy.leases AS l
    SET lease_json = document, revision = next_value,
        released_at = released_time, released_at_text = released_text,
        status = 'released', updated_at = p_observed_at
    WHERE l.lease_key = lease_key_value;
    RETURN QUERY SELECT * FROM carl_autonomy.lease_result(lease_key_value, true);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.trigger_result(p_trigger_id text, p_applied boolean)
RETURNS TABLE(
    applied boolean,
    claim_id text,
    resolution_json text,
    revision integer,
    trigger_json text
)
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT p_applied, t.claim_id::text, t.resolution_json, t.revision, t.trigger_json
    FROM carl_autonomy.supervisor_triggers AS t
    WHERE t.trigger_id = p_trigger_id
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.create_supervisor_trigger(
    p_trigger_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(
    applied boolean,
    claim_id text,
    resolution_json text,
    revision integer,
    trigger_json text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    value jsonb;
    trigger_key text;
    created_time timestamptz;
    existing carl_autonomy.supervisor_triggers%ROWTYPE;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_coordinator']);
    value := carl_autonomy.parse_object(p_trigger_json, 'trigger_json_invalid');
    trigger_key := value->>'trigger_id';
    BEGIN
        created_time := (value->>'created_at')::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'trigger_json_invalid';
    END;
    IF value->>'schema_version' <> '1' OR trigger_key IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'trigger_json_invalid';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(trigger_key, 4));
    SELECT t.* INTO existing
    FROM carl_autonomy.supervisor_triggers AS t
    WHERE t.trigger_id = trigger_key;
    IF FOUND THEN
        IF existing.trigger_json = p_trigger_json THEN
            RETURN QUERY SELECT * FROM carl_autonomy.trigger_result(trigger_key, false);
            RETURN;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'trigger_conflict';
    END IF;
    INSERT INTO carl_autonomy.supervisor_triggers(
        trigger_id, trigger_json, revision, status, created_at, updated_at
    ) VALUES (trigger_key, p_trigger_json, 0, 'pending', created_time, p_observed_at);
    RETURN QUERY SELECT * FROM carl_autonomy.trigger_result(trigger_key, true);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.claim_supervisor_trigger(
    p_trigger_id text,
    p_claim_id text,
    p_expected_revision integer,
    p_observed_at timestamptz
)
RETURNS TABLE(
    applied boolean,
    claim_id text,
    resolution_json text,
    revision integer,
    trigger_json text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    current_state carl_autonomy.supervisor_triggers%ROWTYPE;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_supervisor']);
    SELECT t.* INTO current_state
    FROM carl_autonomy.supervisor_triggers AS t
    WHERE t.trigger_id = p_trigger_id
    FOR UPDATE SKIP LOCKED;
    IF NOT FOUND THEN
        IF EXISTS (
            SELECT 1 FROM carl_autonomy.supervisor_triggers AS t
            WHERE t.trigger_id = p_trigger_id
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '55P03', MESSAGE = 'trigger_busy';
        END IF;
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'trigger_not_found';
    END IF;
    IF current_state.status = 'claimed' AND current_state.claim_id = p_claim_id THEN
        RETURN QUERY SELECT * FROM carl_autonomy.trigger_result(p_trigger_id, false);
        RETURN;
    END IF;
    IF current_state.status <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'trigger_not_claimable';
    END IF;
    IF current_state.revision <> p_expected_revision OR p_expected_revision = 2147483647 THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'trigger_cas_mismatch';
    END IF;
    UPDATE carl_autonomy.supervisor_triggers AS t
    SET claim_id = p_claim_id, revision = p_expected_revision + 1,
        status = 'claimed', updated_at = p_observed_at
    WHERE t.trigger_id = p_trigger_id;
    RETURN QUERY SELECT * FROM carl_autonomy.trigger_result(p_trigger_id, true);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.resolve_supervisor_trigger(
    p_trigger_id text,
    p_claim_id text,
    p_expected_revision integer,
    p_resolution_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(
    applied boolean,
    claim_id text,
    resolution_json text,
    revision integer,
    trigger_json text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    value jsonb;
    status_value text;
    current_state carl_autonomy.supervisor_triggers%ROWTYPE;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_supervisor']);
    value := carl_autonomy.parse_object(p_resolution_json, 'resolution_json_invalid');
    status_value := value->>'status';
    IF status_value NOT IN ('resolved', 'rejected') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'resolution_json_invalid';
    END IF;
    SELECT t.* INTO current_state
    FROM carl_autonomy.supervisor_triggers AS t
    WHERE t.trigger_id = p_trigger_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'trigger_not_found';
    END IF;
    IF current_state.status = status_value
        AND current_state.claim_id = p_claim_id
        AND current_state.resolution_json = p_resolution_json
    THEN
        RETURN QUERY SELECT * FROM carl_autonomy.trigger_result(p_trigger_id, false);
        RETURN;
    END IF;
    IF current_state.status <> 'claimed' OR current_state.claim_id <> p_claim_id THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'trigger_claim_mismatch';
    END IF;
    IF current_state.revision <> p_expected_revision OR p_expected_revision = 2147483647 THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'trigger_cas_mismatch';
    END IF;
    UPDATE carl_autonomy.supervisor_triggers AS t
    SET resolution_json = p_resolution_json, revision = p_expected_revision + 1,
        status = status_value, updated_at = p_observed_at
    WHERE t.trigger_id = p_trigger_id;
    RETURN QUERY SELECT * FROM carl_autonomy.trigger_result(p_trigger_id, true);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.register_evidence(
    p_evidence_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    caller text;
    authority_name text;
    value jsonb;
    digest_value text;
    object_key_value text;
    version_value text;
    producer_value text;
    request_value text;
    media_value text;
    retained_text text;
    retained_time timestamptz;
    existing carl_autonomy.evidence_objects%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY['carl_validator', 'carl_observer']);
    authority_name := carl_autonomy.role_authority(caller);
    value := carl_autonomy.parse_object(p_evidence_json, 'evidence_json_invalid');
    digest_value := value->>'digest';
    object_key_value := value->>'object_key';
    version_value := value->>'object_version';
    producer_value := value->>'producer';
    request_value := value->>'request_digest';
    media_value := value->>'media_type';
    retained_text := value->>'retained_until';
    BEGIN
        retained_time := retained_text::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'evidence_json_invalid';
    END;
    IF producer_value <> authority_name OR object_key_value <> 'evidence/' || digest_value THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'evidence_authority_denied';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(digest_value, 5));
    SELECT e.* INTO existing
    FROM carl_autonomy.evidence_objects AS e
    WHERE e.digest = digest_value;
    IF FOUND THEN
        IF existing.evidence_json = p_evidence_json THEN
            RETURN QUERY SELECT false;
            RETURN;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'evidence_conflict';
    END IF;
    INSERT INTO carl_autonomy.evidence_objects(
        digest, object_key, object_version, producer, request_digest,
        media_type, retained_until, retained_until_text, evidence_json, recorded_at
    ) VALUES (
        digest_value, object_key_value, version_value, producer_value, request_value,
        media_value, retained_time, retained_text, p_evidence_json, p_observed_at
    );
    RETURN QUERY SELECT true;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.record_health(
    p_snapshot_json text,
    p_recorded_at timestamptz
)
RETURNS TABLE(applied boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    value jsonb;
    observed_text text;
    observed_time timestamptz;
    healthy_value boolean;
    digest_value text;
    existing carl_autonomy.monitor_snapshots%ROWTYPE;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_observer']);
    value := carl_autonomy.parse_object(p_snapshot_json, 'health_snapshot_invalid');
    observed_text := value->>'observed_at';
    digest_value := value->>'detail_digest';
    BEGIN
        observed_time := observed_text::timestamptz;
        healthy_value := (value->>'healthy')::boolean;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'health_snapshot_invalid';
    END;
    PERFORM pg_advisory_xact_lock(hashtextextended(observed_text || digest_value, 6));
    SELECT s.* INTO existing
    FROM carl_autonomy.monitor_snapshots AS s
    WHERE s.observed_at = observed_time AND s.detail_digest = digest_value;
    IF FOUND THEN
        IF existing.snapshot_json = p_snapshot_json THEN
            RETURN QUERY SELECT false;
            RETURN;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'health_snapshot_conflict';
    END IF;
    INSERT INTO carl_autonomy.monitor_snapshots(
        observed_at, observed_at_text, healthy, detail_digest, snapshot_json, recorded_at
    ) VALUES (
        observed_time, observed_text, healthy_value, digest_value, p_snapshot_json, p_recorded_at
    );
    RETURN QUERY SELECT true;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.latest_health_snapshot()
RETURNS TABLE(observed_at text, healthy boolean, detail_digest text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]);
    RETURN QUERY
    SELECT s.observed_at_text, s.healthy, s.detail_digest::text
    FROM carl_autonomy.monitor_snapshots AS s
    ORDER BY s.observed_at DESC, s.snapshot_id DESC
    LIMIT 1;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.complete_command_and_append_event(
    p_transition_json text,
    p_event_json text,
    p_event_digest text,
    p_payload_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(
    applied boolean,
    claim_json text,
    command_json text,
    failure_code text,
    result_digest text,
    revision integer,
    status text,
    transition_json text,
    ordinal integer,
    event_digest text,
    chain_digest text,
    appended boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    command_row record;
    event_row record;
BEGIN
    SELECT * INTO STRICT command_row
    FROM carl_autonomy.terminal_command(p_transition_json, 'completed', p_observed_at);
    SELECT * INTO STRICT event_row
    FROM carl_autonomy.append_event(
        p_event_json, p_event_digest, p_payload_json, p_observed_at
    );
    RETURN QUERY SELECT
        command_row.applied, command_row.claim_json, command_row.command_json,
        command_row.failure_code, command_row.result_digest, command_row.revision,
        command_row.status, command_row.transition_json,
        event_row.ordinal, event_row.event_digest, event_row.chain_digest, event_row.appended;
END;
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA carl_autonomy FROM PUBLIC, carl_autonomy_workflow;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA carl_autonomy FROM PUBLIC, carl_autonomy_workflow;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA carl_autonomy FROM PUBLIC, carl_autonomy_workflow;

GRANT EXECUTE ON FUNCTION carl_autonomy.register_manifest(text, text, timestamptz)
    TO carl_builder;
GRANT EXECUTE ON FUNCTION carl_autonomy.append_event(text, text, text, timestamptz)
    TO carl_builder, carl_validator, carl_promoter, carl_soak, carl_coordinator;
GRANT EXECUTE ON FUNCTION carl_autonomy.load_experiment_manifest(text),
    carl_autonomy.load_experiment_events(text),
    carl_autonomy.latest_health_snapshot()
    TO carl_builder, carl_validator, carl_promoter, carl_soak,
       carl_supervisor, carl_coordinator, carl_observer;

GRANT EXECUTE ON FUNCTION carl_autonomy.create_command(text, timestamptz),
    carl_autonomy.claim_command(text, timestamptz),
    carl_autonomy.reconcile_expired_claim(text, text, timestamptz),
    carl_autonomy.complete_command(text, timestamptz),
    carl_autonomy.fail_command(text, timestamptz)
    TO carl_builder, carl_validator, carl_promoter, carl_soak,
       carl_supervisor, carl_coordinator, carl_observer;

GRANT EXECUTE ON FUNCTION carl_autonomy.acquire_lease(text, timestamptz),
    carl_autonomy.reconcile_lease(text, text, timestamptz),
    carl_autonomy.release_lease(text, timestamptz)
    TO carl_coordinator, carl_supervisor;

GRANT EXECUTE ON FUNCTION carl_autonomy.create_supervisor_trigger(text, timestamptz)
    TO carl_coordinator;
GRANT EXECUTE ON FUNCTION carl_autonomy.claim_supervisor_trigger(text, text, integer, timestamptz),
    carl_autonomy.resolve_supervisor_trigger(text, text, integer, text, timestamptz)
    TO carl_supervisor;

GRANT EXECUTE ON FUNCTION carl_autonomy.register_evidence(text, timestamptz)
    TO carl_validator, carl_observer;
GRANT EXECUTE ON FUNCTION carl_autonomy.record_health(text, timestamptz)
    TO carl_observer;
GRANT EXECUTE ON FUNCTION carl_autonomy.complete_command_and_append_event(
    text, text, text, text, timestamptz
) TO carl_coordinator;

COMMIT;
