-- Exact GitHub effect-object fixture extracted from the production state at 4aa2ab5.
-- Source commit: 4aa2ab57779beecf61137bc6f994a82a5fb797c3
-- 001 SHA-256: af8ee07b184fd0183b6810ce9e7f8946ce7e23736c02e7a39e2cada3dbcbf202
-- 002 SHA-256: dffbd010b6d4d1c5bd6dbcdbcc5d35e4b33cf99557c3af35a246573192e668d1

CREATE TABLE carl_autonomy.effect_attempts (
    effect_key varchar(192) PRIMARY KEY REFERENCES carl_autonomy.commands(effect_key),
    command_key varchar(192) NOT NULL UNIQUE REFERENCES carl_autonomy.commands(command_key),
    claim_id varchar(192) NOT NULL,
    command_revision integer NOT NULL CHECK (command_revision BETWEEN 0 AND 2147483647),
    claim_expected_revision integer NOT NULL CHECK (
        claim_expected_revision BETWEEN 0 AND 2147483646
    ),
    authority varchar(32) NOT NULL CHECK (
        authority IN ('builder', 'validator', 'promoter', 'soak', 'supervisor', 'coordinator', 'observer')
    ),
    operation varchar(64) NOT NULL,
    action varchar(64) NOT NULL,
    endpoint_id varchar(64) NOT NULL,
    method varchar(8) NOT NULL CHECK (method IN ('POST', 'PATCH', 'PUT')),
    payload_digest character(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    command_request_digest character(64) NOT NULL CHECK (
        command_request_digest ~ '^[0-9a-f]{64}$'
    ),
    repository varchar(192) NOT NULL,
    target_identity varchar(1024) NOT NULL,
    request_key varchar(192) NOT NULL,
    attempt_key varchar(192) NOT NULL,
    command_occurred_at timestamptz NOT NULL,
    command_occurred_at_text varchar(64) NOT NULL,
    claim_expires_at timestamptz NOT NULL,
    claim_expires_at_text varchar(64) NOT NULL,
    attempt_state varchar(16) NOT NULL CHECK (
        attempt_state IN ('prepared', 'retry_scheduled', 'uncertain', 'completed')
    ),
    not_before timestamptz NOT NULL,
    not_before_text varchar(64) NOT NULL,
    attempt_json text NOT NULL CHECK (octet_length(attempt_json) BETWEEN 2 AND 32768),
    result_digest character(64),
    observed_at timestamptz NOT NULL,
    observed_at_text varchar(64) NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (claim_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$'),
    CHECK (action ~ '^[a-z][a-z0-9_-]{0,63}$'),
    CHECK (endpoint_id ~ '^[a-z][a-z0-9_]{0,63}$'),
    CHECK (octet_length(target_identity) BETWEEN 1 AND 1024),
    CHECK (result_digest IS NULL OR result_digest ~ '^[0-9a-f]{64}$'),
    CHECK (not_before >= observed_at),
    CHECK (
        (attempt_state IN ('prepared', 'retry_scheduled', 'uncertain') AND result_digest IS NULL)
        OR (attempt_state = 'completed' AND result_digest IS NOT NULL)
    )
);

CREATE OR REPLACE FUNCTION carl_autonomy.resolve_claimed_command(
    p_command_key text,
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
    current_state carl_autonomy.commands%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]);
    caller_authority := carl_autonomy.role_authority(caller);
    SELECT c.* INTO current_state
    FROM carl_autonomy.commands AS c
    WHERE c.command_key = p_command_key
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'command_not_found';
    END IF;
    IF current_state.authority <> caller_authority
        OR current_state.status <> 'claimed'
        OR current_state.claim_expires_at <= p_observed_at
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'command_not_claimed';
    END IF;
    RETURN QUERY SELECT * FROM carl_autonomy.command_result(p_command_key, false);
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.prepare_effect_attempt(
    p_attempt_json text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    caller text;
    caller_authority text;
    value jsonb;
    claim_value jsonb;
    effect_key_value text;
    command_key_value text;
    claim_key text;
    authority_value text;
    operation_value text;
    command_revision_value integer;
    claim_revision_value integer;
    command_occurred_text text;
    command_occurred_time timestamptz;
    claim_expires_text text;
    claim_expires_time timestamptz;
    observed_text text;
    observed_time timestamptz;
    not_before_text_value text;
    not_before_time timestamptz;
    current_state carl_autonomy.commands%ROWTYPE;
    existing carl_autonomy.effect_attempts%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]);
    caller_authority := carl_autonomy.role_authority(caller);
    value := carl_autonomy.parse_object(p_attempt_json, 'effect_attempt_invalid');
    IF (SELECT count(*) FROM jsonb_object_keys(value)) <> 23
        OR NOT value ?& ARRAY[
            'action', 'attempt_key', 'attempt_state', 'authority', 'claim_expires_at',
            'claim_expected_revision', 'claim_id', 'command_key', 'command_occurred_at',
            'command_request_digest', 'command_revision', 'effect_key', 'endpoint_id',
            'method', 'not_before', 'observed_at', 'operation', 'payload_digest',
            'repository', 'request_key', 'result_digest', 'schema_version',
            'target_identity'
        ]
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'effect_attempt_invalid';
    END IF;
    effect_key_value := value->>'effect_key';
    command_key_value := value->>'command_key';
    claim_key := value->>'claim_id';
    authority_value := value->>'authority';
    operation_value := value->>'operation';
    command_occurred_text := value->>'command_occurred_at';
    claim_expires_text := value->>'claim_expires_at';
    observed_text := value->>'observed_at';
    not_before_text_value := value->>'not_before';
    BEGIN
        command_revision_value := (value->>'command_revision')::integer;
        claim_revision_value := (value->>'claim_expected_revision')::integer;
        command_occurred_time := command_occurred_text::timestamptz;
        claim_expires_time := claim_expires_text::timestamptz;
        observed_time := observed_text::timestamptz;
        not_before_time := not_before_text_value::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'effect_attempt_invalid';
    END;
    IF value->>'schema_version' <> '1'
        OR value->>'attempt_state' <> 'prepared'
        OR value->'result_digest' <> 'null'::jsonb
        OR authority_value <> caller_authority
        OR value->>'method' NOT IN ('POST', 'PATCH', 'PUT')
        OR NOT carl_autonomy.canonical_utc_text_valid(command_occurred_text)
        OR NOT carl_autonomy.canonical_utc_text_valid(claim_expires_text)
        OR NOT carl_autonomy.canonical_utc_text_valid(observed_text)
        OR NOT carl_autonomy.canonical_utc_text_valid(not_before_text_value)
        OR observed_time <> p_observed_at
        OR not_before_time < observed_time
        OR claim_expires_time <= observed_time
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'effect_attempt_invalid';
    END IF;
    SELECT c.* INTO current_state
    FROM carl_autonomy.commands AS c
    WHERE c.command_key = command_key_value
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'command_not_found';
    END IF;
    claim_value := carl_autonomy.parse_object(current_state.claim_json, 'claim_json_invalid');
    IF current_state.command_json IS NULL
        OR current_state.claim_json IS NULL
        OR current_state.status <> 'claimed'
        OR current_state.effect_key <> effect_key_value
        OR current_state.authority <> authority_value
        OR current_state.operation <> operation_value
        OR current_state.request_digest <> value->>'command_request_digest'
        OR current_state.occurred_at_text <> command_occurred_text
        OR current_state.revision <> command_revision_value
        OR current_state.claim_id <> claim_key
        OR current_state.claim_expires_at_text <> claim_expires_text
        OR current_state.claim_expires_at <= p_observed_at
        OR (claim_value->>'expected_revision')::integer <> claim_revision_value
        OR claim_value->>'claim_id' <> claim_key
        OR claim_value->>'authority' <> authority_value
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'effect_attempt_command_mismatch';
    END IF;
    SELECT e.* INTO existing
    FROM carl_autonomy.effect_attempts AS e
    WHERE e.effect_key = effect_key_value
    FOR UPDATE;
    IF FOUND THEN
        IF existing.command_key = command_key_value
            AND existing.authority = authority_value
            AND existing.operation = operation_value
            AND existing.action = value->>'action'
            AND existing.endpoint_id = value->>'endpoint_id'
            AND existing.method = value->>'method'
            AND existing.payload_digest = value->>'payload_digest'
            AND existing.command_request_digest = value->>'command_request_digest'
            AND existing.repository = value->>'repository'
            AND existing.target_identity = value->>'target_identity'
            AND existing.request_key = value->>'request_key'
            AND existing.attempt_key = value->>'attempt_key'
            AND existing.command_occurred_at_text = command_occurred_text
        THEN
            IF existing.attempt_state = 'retry_scheduled'
                AND p_observed_at >= existing.not_before
            THEN
                UPDATE carl_autonomy.effect_attempts AS e
                SET claim_id = claim_key, command_revision = command_revision_value,
                    claim_expected_revision = claim_revision_value,
                    claim_expires_at = claim_expires_time,
                    claim_expires_at_text = claim_expires_text,
                    attempt_state = 'prepared', not_before = not_before_time,
                    not_before_text = not_before_text_value, attempt_json = p_attempt_json,
                    observed_at = p_observed_at, observed_at_text = observed_text,
                    updated_at = p_observed_at
                WHERE e.effect_key = effect_key_value;
                RETURN QUERY SELECT true;
                RETURN;
            END IF;
            IF existing.claim_id = claim_key
                AND existing.command_revision = command_revision_value
                AND existing.claim_expected_revision = claim_revision_value
                AND existing.claim_expires_at_text = claim_expires_text
            THEN
                RETURN QUERY SELECT false;
                RETURN;
            END IF;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'effect_attempt_conflict';
    END IF;
    INSERT INTO carl_autonomy.effect_attempts(
        effect_key, command_key, claim_id, command_revision, claim_expected_revision,
        authority, operation, action, endpoint_id, method, payload_digest,
        command_request_digest, repository, target_identity, request_key, attempt_key,
        command_occurred_at, command_occurred_at_text, claim_expires_at,
        claim_expires_at_text, attempt_state, not_before, not_before_text, attempt_json,
        result_digest, observed_at, observed_at_text, created_at, updated_at
    ) VALUES (
        effect_key_value, command_key_value, claim_key, command_revision_value,
        claim_revision_value, authority_value, operation_value, value->>'action',
        value->>'endpoint_id', value->>'method', value->>'payload_digest',
        value->>'command_request_digest', value->>'repository', value->>'target_identity',
        value->>'request_key', value->>'attempt_key', command_occurred_time,
        command_occurred_text, claim_expires_time, claim_expires_text, 'prepared',
        not_before_time, not_before_text_value, p_attempt_json, NULL, observed_time,
        observed_text, p_observed_at, p_observed_at
    );
    RETURN QUERY SELECT true;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.mark_effect_retry_scheduled(
    p_effect_key text,
    p_retry_not_before_text text,
    p_observed_at_text text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    caller text;
    caller_authority text;
    retry_not_before timestamptz;
    current_attempt carl_autonomy.effect_attempts%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]);
    caller_authority := carl_autonomy.role_authority(caller);
    IF NOT carl_autonomy.canonical_utc_text_valid(p_retry_not_before_text)
        OR NOT carl_autonomy.canonical_utc_text_valid(p_observed_at_text)
        OR p_observed_at_text::timestamptz <> p_observed_at
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'effect_retry_invalid';
    END IF;
    retry_not_before := p_retry_not_before_text::timestamptz;
    IF retry_not_before <= p_observed_at
        OR retry_not_before > p_observed_at + interval '24 hours'
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'effect_retry_invalid';
    END IF;
    SELECT e.* INTO current_attempt
    FROM carl_autonomy.effect_attempts AS e
    WHERE e.effect_key = p_effect_key
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'effect_attempt_not_found';
    END IF;
    IF current_attempt.authority <> caller_authority
        OR p_observed_at < current_attempt.observed_at
        OR current_attempt.attempt_state IN ('uncertain', 'completed')
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'effect_attempt_transition_denied';
    END IF;
    IF current_attempt.attempt_state = 'retry_scheduled' THEN
        IF current_attempt.not_before_text = p_retry_not_before_text THEN
            RETURN QUERY SELECT false;
            RETURN;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'effect_retry_conflict';
    END IF;
    UPDATE carl_autonomy.effect_attempts AS e
    SET attempt_state = 'retry_scheduled', not_before = retry_not_before,
        not_before_text = p_retry_not_before_text, observed_at = p_observed_at,
        observed_at_text = p_observed_at_text, updated_at = p_observed_at
    WHERE e.effect_key = p_effect_key;
    RETURN QUERY SELECT true;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.mark_effect_uncertain(
    p_effect_key text,
    p_not_before_text text,
    p_observed_at_text text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    caller text;
    caller_authority text;
    current_attempt carl_autonomy.effect_attempts%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]);
    caller_authority := carl_autonomy.role_authority(caller);
    SELECT e.* INTO current_attempt
    FROM carl_autonomy.effect_attempts AS e
    WHERE e.effect_key = p_effect_key
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'effect_attempt_not_found';
    END IF;
    IF current_attempt.authority <> caller_authority
        OR current_attempt.not_before_text <> p_not_before_text
        OR NOT carl_autonomy.canonical_utc_text_valid(p_observed_at_text)
        OR p_observed_at_text::timestamptz <> p_observed_at
        OR p_observed_at < current_attempt.observed_at
        OR current_attempt.attempt_state = 'completed'
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'effect_attempt_transition_denied';
    END IF;
    IF current_attempt.attempt_state = 'uncertain' THEN
        RETURN QUERY SELECT false;
        RETURN;
    END IF;
    UPDATE carl_autonomy.effect_attempts AS e
    SET attempt_state = 'uncertain', observed_at = p_observed_at,
        observed_at_text = p_observed_at_text, updated_at = p_observed_at
    WHERE e.effect_key = p_effect_key;
    RETURN QUERY SELECT true;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.mark_effect_completed(
    p_effect_key text,
    p_result_digest text,
    p_observed_at_text text,
    p_observed_at timestamptz
)
RETURNS TABLE(applied boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    caller text;
    caller_authority text;
    current_attempt carl_autonomy.effect_attempts%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]);
    caller_authority := carl_autonomy.role_authority(caller);
    IF p_result_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'effect_result_invalid';
    END IF;
    SELECT e.* INTO current_attempt
    FROM carl_autonomy.effect_attempts AS e
    WHERE e.effect_key = p_effect_key
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'effect_attempt_not_found';
    END IF;
    IF current_attempt.authority <> caller_authority
        OR NOT carl_autonomy.canonical_utc_text_valid(p_observed_at_text)
        OR p_observed_at_text::timestamptz <> p_observed_at
        OR p_observed_at < current_attempt.observed_at
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'effect_attempt_transition_denied';
    END IF;
    IF current_attempt.attempt_state = 'completed' THEN
        IF current_attempt.result_digest = p_result_digest THEN
            RETURN QUERY SELECT false;
            RETURN;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'effect_result_conflict';
    END IF;
    UPDATE carl_autonomy.effect_attempts AS e
    SET attempt_state = 'completed', result_digest = p_result_digest,
        observed_at = p_observed_at,
        observed_at_text = p_observed_at_text, updated_at = p_observed_at
    WHERE e.effect_key = p_effect_key;
    RETURN QUERY SELECT true;
END;
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA carl_autonomy FROM PUBLIC, carl_autonomy_workflow;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA carl_autonomy FROM PUBLIC, carl_autonomy_workflow;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA carl_autonomy FROM PUBLIC, carl_autonomy_workflow;

GRANT EXECUTE ON FUNCTION carl_autonomy.resolve_claimed_command(text, timestamptz),
    carl_autonomy.prepare_effect_attempt(text, timestamptz),
    carl_autonomy.mark_effect_retry_scheduled(text, text, text, timestamptz),
    carl_autonomy.mark_effect_uncertain(text, text, text, timestamptz),
    carl_autonomy.mark_effect_completed(text, text, text, timestamptz)
    TO carl_state_backend;
