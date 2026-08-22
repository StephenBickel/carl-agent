BEGIN;

DO $migration$
DECLARE
    actual_column_signature text;
    expected_column_signature text;
    actual_constraint_signature text;
    expected_constraint_signature text;
    table_owner text;
    table_namespace text;
    table_kind "char";
BEGIN
IF to_regclass('carl_autonomy._migration_expected_effect_attempts') IS NOT NULL THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'effect_fence_scratch_exists';
END IF;

IF to_regclass('carl_autonomy.effect_attempts') IS NULL THEN
EXECUTE $ddl$CREATE TABLE carl_autonomy.effect_attempts (
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
)$ddl$;
END IF;

CREATE TABLE carl_autonomy._migration_expected_effect_attempts (
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

SELECT pg_catalog.pg_get_userbyid(c.relowner), n.nspname, c.relkind
INTO table_owner, table_namespace, table_kind
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
WHERE c.oid = 'carl_autonomy.effect_attempts'::regclass;

SELECT string_agg(
    a.attnum::text || ':' || a.attname || ':'
    || pg_catalog.format_type(a.atttypid, a.atttypmod) || ':'
    || a.attcollation::text || ':' || coalesce(cn.nspname, '<none>') || ':'
    || coalesce(coll.collname, '<none>') || ':'
    || a.attnotnull::text || ':' || a.attidentity || ':' || a.attgenerated || ':'
    || a.attstorage || ':' || a.attcompression || ':'
    || coalesce(pg_catalog.pg_get_expr(d.adbin, d.adrelid), '<none>'),
    '|' ORDER BY a.attnum
)
INTO actual_column_signature
FROM pg_catalog.pg_attribute AS a
LEFT JOIN pg_catalog.pg_attrdef AS d
    ON d.adrelid = a.attrelid AND d.adnum = a.attnum
LEFT JOIN pg_catalog.pg_collation AS coll ON coll.oid = a.attcollation
LEFT JOIN pg_catalog.pg_namespace AS cn ON cn.oid = coll.collnamespace
WHERE a.attrelid = 'carl_autonomy.effect_attempts'::regclass
    AND a.attnum > 0 AND NOT a.attisdropped;

SELECT string_agg(
    a.attnum::text || ':' || a.attname || ':'
    || pg_catalog.format_type(a.atttypid, a.atttypmod) || ':'
    || a.attcollation::text || ':' || coalesce(cn.nspname, '<none>') || ':'
    || coalesce(coll.collname, '<none>') || ':'
    || a.attnotnull::text || ':' || a.attidentity || ':' || a.attgenerated || ':'
    || a.attstorage || ':' || a.attcompression || ':'
    || coalesce(pg_catalog.pg_get_expr(d.adbin, d.adrelid), '<none>'),
    '|' ORDER BY a.attnum
)
INTO expected_column_signature
FROM pg_catalog.pg_attribute AS a
LEFT JOIN pg_catalog.pg_attrdef AS d
    ON d.adrelid = a.attrelid AND d.adnum = a.attnum
LEFT JOIN pg_catalog.pg_collation AS coll ON coll.oid = a.attcollation
LEFT JOIN pg_catalog.pg_namespace AS cn ON cn.oid = coll.collnamespace
WHERE a.attrelid = 'carl_autonomy._migration_expected_effect_attempts'::regclass
    AND a.attnum > 0 AND NOT a.attisdropped;

SELECT string_agg(
    c.contype || ':' || c.conkey::text || ':' || coalesce(c.confkey::text, '') || ':'
    || c.confupdtype || ':' || c.confdeltype || ':' || c.confmatchtype || ':'
    || c.condeferrable::text || ':' || c.condeferred::text || ':'
    || c.convalidated::text || ':' || c.connoinherit::text || ':'
    || pg_catalog.pg_get_constraintdef(c.oid, true),
    '|' ORDER BY c.contype, c.conkey::text, pg_catalog.pg_get_constraintdef(c.oid, true)
)
INTO actual_constraint_signature
FROM pg_catalog.pg_constraint AS c
WHERE c.conrelid = 'carl_autonomy.effect_attempts'::regclass;

SELECT string_agg(
    c.contype || ':' || c.conkey::text || ':' || coalesce(c.confkey::text, '') || ':'
    || c.confupdtype || ':' || c.confdeltype || ':' || c.confmatchtype || ':'
    || c.condeferrable::text || ':' || c.condeferred::text || ':'
    || c.convalidated::text || ':' || c.connoinherit::text || ':'
    || pg_catalog.pg_get_constraintdef(c.oid, true),
    '|' ORDER BY c.contype, c.conkey::text, pg_catalog.pg_get_constraintdef(c.oid, true)
)
INTO expected_constraint_signature
FROM pg_catalog.pg_constraint AS c
WHERE c.conrelid = 'carl_autonomy._migration_expected_effect_attempts'::regclass;

IF table_owner <> CURRENT_USER OR table_namespace <> 'carl_autonomy' OR table_kind <> 'r'
    OR actual_column_signature IS DISTINCT FROM expected_column_signature
    OR actual_constraint_signature IS DISTINCT FROM expected_constraint_signature
THEN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'effect_fence_schema_invalid';
END IF;

END;
$migration$;

CREATE INDEX IF NOT EXISTS effect_attempts_reconciliation
    ON carl_autonomy.effect_attempts(attempt_state, not_before, effect_key)
    WHERE attempt_state IN ('retry_scheduled', 'uncertain');

CREATE INDEX _migration_expected_effect_attempts_reconciliation
    ON carl_autonomy._migration_expected_effect_attempts(
        attempt_state, not_before, effect_key
    )
    WHERE attempt_state IN ('retry_scheduled', 'uncertain');

DO $migration$
DECLARE
    actual_index_signature jsonb;
    expected_index_signature jsonb;
BEGIN
    WITH target(catalog_side, relid) AS (
        VALUES
            ('actual', 'carl_autonomy.effect_attempts'::regclass),
            (
                'expected',
                'carl_autonomy._migration_expected_effect_attempts'::regclass
            )
    ), index_contract AS (
        SELECT target.catalog_side, pg_catalog.jsonb_build_object(
            'indnatts', i.indnatts,
            'indnkeyatts', i.indnkeyatts,
            'indisunique', i.indisunique,
            'indnullsnotdistinct', i.indnullsnotdistinct,
            'indisprimary', i.indisprimary,
            'indisexclusion', i.indisexclusion,
            'indimmediate', i.indimmediate,
            'indisclustered', i.indisclustered,
            'indisvalid', i.indisvalid,
            'indcheckxmin', i.indcheckxmin,
            'indisready', i.indisready,
            'indislive', i.indislive,
            'indisreplident', i.indisreplident,
            'indkey', i.indkey::text,
            'indcollation', i.indcollation::text,
            'indclass', i.indclass::text,
            'indoption', i.indoption::text,
            'indexprs', pg_catalog.pg_get_expr(i.indexprs, i.indrelid, true),
            'indpred', pg_catalog.pg_get_expr(i.indpred, i.indrelid, true),
            'access_method_oid', am.oid,
            'access_method_name', am.amname,
            'access_method_type', am.amtype,
            'index_owner', pg_catalog.pg_get_userbyid(idx.relowner),
            'index_namespace', ni.nspname,
            'index_relkind', idx.relkind,
            'index_relpersistence', idx.relpersistence,
            'index_relam', idx.relam,
            'index_reltablespace', idx.reltablespace,
            'index_tablespace_name', ts.spcname,
            'index_reloptions', idx.reloptions,
            'key_columns', (
                SELECT coalesce(pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'position', key.position,
                        'attnum', key.attnum,
                        'attname', attribute.attname,
                        'expression', key.attnum = 0
                    ) ORDER BY key.position
                ), '[]'::jsonb)
                FROM unnest(i.indkey) WITH ORDINALITY AS key(attnum, position)
                LEFT JOIN pg_catalog.pg_attribute AS attribute
                    ON attribute.attrelid = i.indrelid
                    AND attribute.attnum = key.attnum
            ),
            'include_columns', (
                SELECT coalesce(pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'position', included.position,
                        'attnum', included.attnum,
                        'attname', attribute.attname
                    ) ORDER BY included.position
                ), '[]'::jsonb)
                FROM unnest(i.indkey) WITH ORDINALITY AS included(attnum, position)
                LEFT JOIN pg_catalog.pg_attribute AS attribute
                    ON attribute.attrelid = i.indrelid
                    AND attribute.attnum = included.attnum
                WHERE included.position > i.indnkeyatts
            ),
            'opclasses', (
                SELECT coalesce(pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'position', opclass.position,
                        'oid', opc.oid,
                        'namespace_oid', opn.oid,
                        'namespace_name', opn.nspname,
                        'name', opc.opcname,
                        'input_type_oid', opc.opcintype,
                        'key_type_oid', opc.opckeytype,
                        'family_oid', opf.oid,
                        'family_namespace_oid', opfn.oid,
                        'family_namespace_name', opfn.nspname,
                        'family_name', opf.opfname
                    ) ORDER BY opclass.position
                ), '[]'::jsonb)
                FROM unnest(i.indclass) WITH ORDINALITY AS opclass(oid, position)
                JOIN pg_catalog.pg_opclass AS opc ON opc.oid = opclass.oid
                JOIN pg_catalog.pg_namespace AS opn ON opn.oid = opc.opcnamespace
                JOIN pg_catalog.pg_opfamily AS opf ON opf.oid = opc.opcfamily
                JOIN pg_catalog.pg_namespace AS opfn ON opfn.oid = opf.opfnamespace
            ),
            'collations', (
                SELECT coalesce(pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'position', index_collation.position,
                        'oid', index_collation.oid,
                        'namespace_oid', coln.oid,
                        'namespace_name', coln.nspname,
                        'name', coll.collname
                    ) ORDER BY index_collation.position
                ), '[]'::jsonb)
                FROM unnest(i.indcollation)
                    WITH ORDINALITY AS index_collation(oid, position)
                LEFT JOIN pg_catalog.pg_collation AS coll
                    ON coll.oid = index_collation.oid
                LEFT JOIN pg_catalog.pg_namespace AS coln
                    ON coln.oid = coll.collnamespace
            )
        ) AS signature
        FROM target
        JOIN pg_catalog.pg_index AS i ON i.indrelid = target.relid
        JOIN pg_catalog.pg_class AS idx ON idx.oid = i.indexrelid
        JOIN pg_catalog.pg_namespace AS ni ON ni.oid = idx.relnamespace
        JOIN pg_catalog.pg_am AS am ON am.oid = idx.relam
        LEFT JOIN pg_catalog.pg_tablespace AS ts ON ts.oid = idx.reltablespace
    )
    SELECT
        coalesce(pg_catalog.jsonb_agg(signature ORDER BY signature::text)
            FILTER (WHERE catalog_side = 'actual'), '[]'::jsonb),
        coalesce(pg_catalog.jsonb_agg(signature ORDER BY signature::text)
            FILTER (WHERE catalog_side = 'expected'), '[]'::jsonb)
    INTO actual_index_signature, expected_index_signature
    FROM index_contract;

    IF actual_index_signature IS DISTINCT FROM expected_index_signature THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'effect_fence_schema_invalid';
    END IF;
END;
$migration$;

DROP TABLE carl_autonomy._migration_expected_effect_attempts;

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
            IF existing.attempt_state = 'uncertain' THEN
                UPDATE carl_autonomy.effect_attempts AS e
                SET claim_id = claim_key,
                    command_revision = command_revision_value,
                    claim_expected_revision = claim_revision_value,
                    claim_expires_at = claim_expires_time,
                    claim_expires_at_text = claim_expires_text,
                    observed_at = p_observed_at,
                    observed_at_text = observed_text,
                    updated_at = p_observed_at
                WHERE e.effect_key = effect_key_value;
                RETURN QUERY SELECT false;
                RETURN;
            END IF;
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

DROP FUNCTION IF EXISTS carl_autonomy.mark_effect_completed(text, text, text, timestamptz);

CREATE OR REPLACE FUNCTION carl_autonomy.mark_effect_completed(
    p_effect_key text,
    p_command_key text,
    p_claim_id text,
    p_command_revision integer,
    p_claim_expected_revision integer,
    p_claim_expires_at_text text,
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
    claim_value jsonb;
    current_state carl_autonomy.commands%ROWTYPE;
    current_attempt carl_autonomy.effect_attempts%ROWTYPE;
BEGIN
    caller := carl_autonomy.require_role(ARRAY[
        'carl_builder', 'carl_validator', 'carl_promoter', 'carl_soak',
        'carl_supervisor', 'carl_coordinator', 'carl_observer'
    ]);
    caller_authority := carl_autonomy.role_authority(caller);
    IF p_result_digest !~ '^[0-9a-f]{64}$'
        OR NOT carl_autonomy.canonical_utc_text_valid(p_claim_expires_at_text)
        OR NOT carl_autonomy.canonical_utc_text_valid(p_observed_at_text)
        OR p_observed_at_text::timestamptz <> p_observed_at
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'effect_result_invalid';
    END IF;
    SELECT c.* INTO current_state
    FROM carl_autonomy.commands AS c
    WHERE c.command_key = p_command_key
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'command_not_found';
    END IF;
    IF current_state.command_json IS NULL OR current_state.claim_json IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'effect_attempt_transition_denied';
    END IF;
    claim_value := carl_autonomy.parse_object(current_state.claim_json, 'claim_json_invalid');
    SELECT e.* INTO current_attempt
    FROM carl_autonomy.effect_attempts AS e
    WHERE e.effect_key = p_effect_key
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'effect_attempt_not_found';
    END IF;
    IF current_state.status <> 'claimed'
        OR current_state.command_key <> p_command_key
        OR current_state.effect_key <> p_effect_key
        OR current_state.authority <> caller_authority
        OR current_state.revision <> p_command_revision
        OR current_state.claim_id <> p_claim_id
        OR current_state.claim_expires_at_text <> p_claim_expires_at_text
        OR current_state.claim_expires_at <= p_observed_at
        OR (claim_value->>'expected_revision')::integer <> p_claim_expected_revision
        OR claim_value->>'claim_id' <> p_claim_id
        OR claim_value->>'authority' <> caller_authority
        OR current_attempt.authority <> caller_authority
        OR current_attempt.command_key <> p_command_key
        OR current_attempt.claim_id <> p_claim_id
        OR current_attempt.command_revision <> p_command_revision
        OR current_attempt.claim_expected_revision <> p_claim_expected_revision
        OR current_attempt.claim_expires_at_text <> p_claim_expires_at_text
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

ALTER TABLE carl_autonomy.effect_attempts OWNER TO CURRENT_USER;
ALTER FUNCTION carl_autonomy.resolve_claimed_command(text, timestamptz) OWNER TO CURRENT_USER;
ALTER FUNCTION carl_autonomy.prepare_effect_attempt(text, timestamptz) OWNER TO CURRENT_USER;
ALTER FUNCTION carl_autonomy.mark_effect_retry_scheduled(text, text, text, timestamptz)
    OWNER TO CURRENT_USER;
ALTER FUNCTION carl_autonomy.mark_effect_uncertain(text, text, text, timestamptz)
    OWNER TO CURRENT_USER;
ALTER FUNCTION carl_autonomy.mark_effect_completed(
    text, text, text, integer, integer, text, text, text, timestamptz
)
    OWNER TO CURRENT_USER;

DO $acl_normalization$
DECLARE
    unexpected_grantee oid;
    column_record record;
    sequence_record record;
    function_record record;
BEGIN
    FOR column_record IN
        SELECT DISTINCT a.attname, acl.grantee
        FROM pg_catalog.pg_attribute AS a
        CROSS JOIN LATERAL pg_catalog.aclexplode(a.attacl) AS acl
        WHERE a.attrelid = 'carl_autonomy.effect_attempts'::regclass
            AND a.attnum > 0 AND NOT a.attisdropped
    LOOP
        IF column_record.grantee = 0 THEN
            EXECUTE format(
                'REVOKE ALL PRIVILEGES (%I) ON TABLE '
                'carl_autonomy.effect_attempts FROM PUBLIC',
                column_record.attname
            );
        ELSE
            EXECUTE format(
                'REVOKE ALL PRIVILEGES (%I) ON TABLE '
                'carl_autonomy.effect_attempts FROM %I',
                column_record.attname,
                pg_catalog.pg_get_userbyid(column_record.grantee)
            );
        END IF;
    END LOOP;

    FOR unexpected_grantee IN
        SELECT DISTINCT acl.grantee
        FROM pg_catalog.pg_class AS c
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            coalesce(c.relacl, pg_catalog.acldefault('r', c.relowner))
        ) AS acl
        WHERE c.oid = 'carl_autonomy.effect_attempts'::regclass
            AND acl.grantee <> c.relowner
    LOOP
        IF unexpected_grantee = 0 THEN
            EXECUTE 'REVOKE ALL ON TABLE carl_autonomy.effect_attempts FROM PUBLIC';
        ELSE
            EXECUTE format(
                'REVOKE ALL ON TABLE carl_autonomy.effect_attempts FROM %I',
                pg_catalog.pg_get_userbyid(unexpected_grantee)
            );
        END IF;
    END LOOP;

    FOR sequence_record IN
        SELECT c.oid, c.relowner, n.nspname, c.relname
        FROM pg_catalog.pg_class AS c
        JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
        WHERE n.nspname = 'carl_autonomy' AND c.relkind = 'S'
    LOOP
        FOR unexpected_grantee IN
            SELECT DISTINCT acl.grantee
            FROM pg_catalog.pg_class AS sequence_class
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                coalesce(
                    sequence_class.relacl,
                    pg_catalog.acldefault('s', sequence_class.relowner)
                )
            ) AS acl
            WHERE sequence_class.oid = sequence_record.oid
                AND acl.grantee <> sequence_class.relowner
        LOOP
            IF unexpected_grantee = 0 THEN
                EXECUTE format(
                    'REVOKE ALL ON SEQUENCE %I.%I FROM PUBLIC',
                    sequence_record.nspname, sequence_record.relname
                );
            ELSE
                EXECUTE format(
                    'REVOKE ALL ON SEQUENCE %I.%I FROM %I',
                    sequence_record.nspname, sequence_record.relname,
                    pg_catalog.pg_get_userbyid(unexpected_grantee)
                );
            END IF;
        END LOOP;
    END LOOP;

    FOR function_record IN
        SELECT p.oid, p.proowner
        FROM pg_catalog.pg_proc AS p
        WHERE p.oid = ANY(ARRAY[
            'carl_autonomy.resolve_claimed_command(text,timestamptz)'::regprocedure::oid,
            'carl_autonomy.prepare_effect_attempt(text,timestamptz)'::regprocedure::oid,
            'carl_autonomy.mark_effect_retry_scheduled(text,text,text,timestamptz)'::regprocedure::oid,
            'carl_autonomy.mark_effect_uncertain(text,text,text,timestamptz)'::regprocedure::oid,
            'carl_autonomy.mark_effect_completed(text,text,text,integer,integer,text,text,text,timestamptz)'::regprocedure::oid
        ])
    LOOP
        FOR unexpected_grantee IN
            SELECT DISTINCT acl.grantee
            FROM pg_catalog.pg_proc AS function_class
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                coalesce(
                    function_class.proacl,
                    pg_catalog.acldefault('f', function_class.proowner)
                )
            ) AS acl
            WHERE function_class.oid = function_record.oid
                AND acl.grantee <> function_class.proowner
        LOOP
            IF unexpected_grantee = 0 THEN
                EXECUTE format(
                    'REVOKE ALL ON FUNCTION %s FROM PUBLIC',
                    function_record.oid::regprocedure
                );
            ELSE
                EXECUTE format(
                    'REVOKE ALL ON FUNCTION %s FROM %I',
                    function_record.oid::regprocedure,
                    pg_catalog.pg_get_userbyid(unexpected_grantee)
                );
            END IF;
        END LOOP;
    END LOOP;
END;
$acl_normalization$;

REVOKE ALL ON TABLE carl_autonomy.effect_attempts
    FROM PUBLIC, carl_autonomy_workflow, carl_state_backend;
REVOKE ALL ON FUNCTION carl_autonomy.resolve_claimed_command(text, timestamptz),
    carl_autonomy.prepare_effect_attempt(text, timestamptz),
    carl_autonomy.mark_effect_retry_scheduled(text, text, text, timestamptz),
    carl_autonomy.mark_effect_uncertain(text, text, text, timestamptz),
    carl_autonomy.mark_effect_completed(
        text, text, text, integer, integer, text, text, text, timestamptz
    )
    FROM PUBLIC, carl_autonomy_workflow;
GRANT EXECUTE ON FUNCTION carl_autonomy.resolve_claimed_command(text, timestamptz),
    carl_autonomy.prepare_effect_attempt(text, timestamptz),
    carl_autonomy.mark_effect_retry_scheduled(text, text, text, timestamptz),
    carl_autonomy.mark_effect_uncertain(text, text, text, timestamptz),
    carl_autonomy.mark_effect_completed(
        text, text, text, integer, integer, text, text, text, timestamptz
    )
    TO carl_state_backend;

DO $contract_verification$
DECLARE
    invalid_functions integer;
    unexpected_grantee oid;
    function_count integer;
    function_acl_count integer;
    owner_function_grants integer;
    backend_function_grants integer;
    table_acl_count integer;
    owner_table_grants integer;
    column_acl_count integer;
BEGIN
    SELECT count(*), count(*) FILTER (WHERE
            n.nspname <> 'carl_autonomy'
            OR pg_catalog.pg_get_userbyid(p.proowner) <> CURRENT_USER
            OR l.lanname <> 'plpgsql' OR NOT p.prosecdef OR p.proleakproof
            OR p.provolatile <> 'v' OR p.proparallel <> 'u' OR p.prokind <> 'f'
            OR p.proconfig IS DISTINCT FROM ARRAY['search_path=pg_catalog, carl_autonomy']::text[]
        )
    INTO function_count, invalid_functions
    FROM pg_catalog.pg_proc AS p
    JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
    JOIN pg_catalog.pg_language AS l ON l.oid = p.prolang
    WHERE p.oid = ANY(ARRAY[
        'carl_autonomy.resolve_claimed_command(text,timestamptz)'::regprocedure::oid,
        'carl_autonomy.prepare_effect_attempt(text,timestamptz)'::regprocedure::oid,
        'carl_autonomy.mark_effect_retry_scheduled(text,text,text,timestamptz)'::regprocedure::oid,
        'carl_autonomy.mark_effect_uncertain(text,text,text,timestamptz)'::regprocedure::oid,
        'carl_autonomy.mark_effect_completed(text,text,text,integer,integer,text,text,text,timestamptz)'::regprocedure::oid
    ])
        ;
    IF function_count <> 5 OR invalid_functions <> 0 THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'effect_fence_function_invalid';
    END IF;

    SELECT count(*), count(*) FILTER (WHERE
        acl.grantee = c.relowner
        AND acl.privilege_type = ANY(ARRAY[
            'DELETE', 'INSERT', 'REFERENCES', 'SELECT', 'TRIGGER', 'TRUNCATE', 'UPDATE'
        ])
    )
    INTO table_acl_count, owner_table_grants
    FROM pg_catalog.pg_class AS c
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        coalesce(c.relacl, pg_catalog.acldefault('r', c.relowner))
    ) AS acl
    WHERE c.oid = 'carl_autonomy.effect_attempts'::regclass;
    IF table_acl_count <> 7 OR owner_table_grants <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'effect_fence_acl_invalid';
    END IF;

    SELECT count(*) INTO column_acl_count
    FROM pg_catalog.pg_attribute AS a
    WHERE a.attrelid = 'carl_autonomy.effect_attempts'::regclass
        AND a.attnum > 0 AND NOT a.attisdropped AND a.attacl IS NOT NULL;
    IF column_acl_count <> 0 THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'effect_fence_acl_invalid';
    END IF;

    SELECT count(*), count(*) FILTER (WHERE
            acl.grantee = p.proowner AND acl.privilege_type = 'EXECUTE'
        ), count(*) FILTER (WHERE
            acl.grantee = 'carl_state_backend'::regrole::oid
            AND acl.privilege_type = 'EXECUTE' AND NOT acl.is_grantable
        )
    INTO function_acl_count, owner_function_grants, backend_function_grants
    FROM pg_catalog.pg_proc AS p
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))
    ) AS acl
    WHERE p.oid = ANY(ARRAY[
        'carl_autonomy.resolve_claimed_command(text,timestamptz)'::regprocedure::oid,
        'carl_autonomy.prepare_effect_attempt(text,timestamptz)'::regprocedure::oid,
        'carl_autonomy.mark_effect_retry_scheduled(text,text,text,timestamptz)'::regprocedure::oid,
        'carl_autonomy.mark_effect_uncertain(text,text,text,timestamptz)'::regprocedure::oid,
        'carl_autonomy.mark_effect_completed(text,text,text,integer,integer,text,text,text,timestamptz)'::regprocedure::oid
    ])
        ;
    IF function_acl_count <> 10 OR owner_function_grants <> 5
        OR backend_function_grants <> 5
    THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'effect_fence_acl_invalid';
    END IF;

    SELECT acl.grantee INTO unexpected_grantee
    FROM pg_catalog.pg_class AS c
    JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        coalesce(c.relacl, pg_catalog.acldefault('s', c.relowner))
    ) AS acl
    WHERE n.nspname = 'carl_autonomy' AND c.relkind = 'S'
        AND (
            pg_catalog.pg_get_userbyid(c.relowner) <> CURRENT_USER
            OR acl.grantee <> c.relowner
        )
    LIMIT 1;
    IF FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'effect_fence_acl_invalid';
    END IF;

    IF to_regclass('carl_autonomy._migration_expected_effect_attempts') IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'effect_fence_scratch_not_dropped';
    END IF;
END;
$contract_verification$;

COMMIT;
