BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'carl_state_backend') THEN
        CREATE ROLE carl_state_backend NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
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
                'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT',
                role_name
            );
        END IF;
        EXECUTE format('ALTER ROLE %I NOLOGIN NOINHERIT', role_name);
        EXECUTE format('REVOKE carl_autonomy_workflow FROM %I', role_name);
        EXECUTE format('REVOKE %I FROM carl_autonomy_workflow', role_name);
    END LOOP;
END;
$$;

GRANT USAGE ON SCHEMA carl_autonomy TO carl_state_backend;
REVOKE ALL ON SCHEMA carl_autonomy FROM carl_autonomy_workflow;
REVOKE ALL ON ALL TABLES IN SCHEMA carl_autonomy FROM carl_autonomy_workflow;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA carl_autonomy FROM carl_autonomy_workflow;

CREATE OR REPLACE FUNCTION carl_autonomy.caller_role()
RETURNS text
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT CASE current_setting('carl_autonomy.authority', true)
        WHEN 'builder' THEN 'carl_builder'
        WHEN 'validator' THEN 'carl_validator'
        WHEN 'promoter' THEN 'carl_promoter'
        WHEN 'soak' THEN 'carl_soak'
        WHEN 'supervisor' THEN 'carl_supervisor'
        WHEN 'coordinator' THEN 'carl_coordinator'
        WHEN 'observer' THEN 'carl_observer'
        ELSE NULL
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
    database_role text := CASE
        WHEN current_setting('role', true) IS NULL OR current_setting('role', true) = 'none'
            THEN session_user::text
        ELSE current_setting('role', true)
    END;
BEGIN
    IF database_role <> 'carl_state_backend' OR role_name IS NULL
        OR role_name <> ALL(allowed_roles)
    THEN
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

CREATE OR REPLACE FUNCTION carl_autonomy.canonical_jsonb(value jsonb)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    result text := '';
    separator text := '';
    item record;
BEGIN
    IF jsonb_typeof(value) = 'object' THEN
        FOR item IN
            SELECT field.key, field.value
            FROM jsonb_each(value) AS field
            ORDER BY convert_to(field.key, 'UTF8')
        LOOP
            result := result || separator || to_json(item.key)::text || ':'
                || carl_autonomy.canonical_jsonb(item.value);
            separator := ',';
        END LOOP;
        RETURN '{' || result || '}';
    END IF;
    IF jsonb_typeof(value) = 'array' THEN
        FOR item IN
            SELECT element.value
            FROM jsonb_array_elements(value) WITH ORDINALITY AS element(value, ordinal)
            ORDER BY element.ordinal
        LOOP
            result := result || separator || carl_autonomy.canonical_jsonb(item.value);
            separator := ',';
        END LOOP;
        RETURN '[' || result || ']';
    END IF;
    RETURN value::text;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.candidate_payload_digest(p_payload jsonb)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT carl_autonomy.sha256_text(
        carl_autonomy.canonical_jsonb(p_payload - '_lease')
    )
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.event_payload_key_policy()
RETURNS TABLE(event_type text, required_keys text[])
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    VALUES
        ('state_transitioned', ARRAY['from_state', 'to_state']::text[]),
        ('state_transitioned', ARRAY['_lease', 'from_state', 'to_state']::text[]),
        ('role_recorded', ARRAY['artifact_digest', 'role', 'verdict']::text[]),
        ('role_recorded', ARRAY['_lease', 'artifact_digest', 'role', 'verdict']::text[]),
        ('lease_acquired', ARRAY['expires_at', 'owner_id']::text[]),
        ('lease_reconciled', ARRAY['lease_stage_attempt_id', 'worker_not_live']::text[]),
        ('lease_released', ARRAY['lease_stage_attempt_id']::text[]),
        ('live_spend_recorded', ARRAY['live_microdollars', 'run_id']::text[]),
        ('workspace_prepared', ARRAY[
            '_lease', 'branch', 'experiment_id', 'manifest_digest', 'parent_commit',
            'request_artifact', 'schema_version'
        ]::text[]),
        ('candidate_sealed', ARRAY[
            '_lease', 'branch', 'candidate_commit', 'changed_path_count',
            'changed_paths_artifact', 'checks', 'diff_artifact', 'experiment_id',
            'manifest_digest', 'parent_commit', 'report_artifact', 'schema_version'
        ]::text[]),
        ('paired_evidence_recorded', ARRAY[
            '_lease', 'baseline_scorecard_digest', 'candidate_commit',
            'candidate_scorecard_digest', 'comparison_artifact',
            'confidence_lower_basis_points', 'decision', 'experiment_id',
            'manifest_digest', 'paired_trials', 'parent_commit',
            'pass_rate_delta_basis_points', 'schema_version'
        ]::text[]),
        ('review_packet_recorded', ARRAY[
            '_lease', 'candidate_commit', 'deterministic_evidence_digest', 'diff_digest',
            'experiment_id', 'manifest_digest', 'paired_evidence_digest',
            'review_contract_version', 'role', 'schema_version'
        ]::text[]),
        ('review_attested', ARRAY[
            '_lease', 'candidate_commit', 'context_id', 'experiment_id', 'manifest_digest',
            'packet_digest', 'report_artifact', 'reviewer_id', 'role', 'schema_version', 'verdict'
        ]::text[]),
        ('draft_pr_requested', ARRAY[
            '_lease', 'base_branch', 'candidate_commit', 'expected_remote_url',
            'head_branch', 'repository'
        ]::text[]),
        ('draft_pr_recorded', ARRAY[
            '_lease', 'base_branch', 'candidate_commit', 'head_branch', 'is_draft',
            'number', 'repository', 'schema_version', 'state', 'url'
        ]::text[]),
        ('workspace_disposed', ARRAY['_lease', 'branch', 'candidate_commit']::text[]),
        ('retry_scheduled', ARRAY[
            'attempt', 'changed_action', 'failed_stage_attempt_id', 'failure_class', 'scheduled_at'
        ]::text[]),
        ('experimental_published', ARRAY[
            'branch', 'candidate_packet_digest', 'commit', 'tree'
        ]::text[]),
        ('protected_validation_recorded', ARRAY[
            'candidate_commit', 'candidate_tree', 'receipt_digest'
        ]::text[]),
        ('promotion_recorded', ARRAY['merge_commit', 'merge_tree']::text[]),
        ('soak_observed', ARRAY[
            'evidence_digest', 'healthy', 'merge_commit', 'observed_at'
        ]::text[]),
        ('revert_recorded', ARRAY[
            'hard_failure_digest', 'merge_commit', 'restored_tree',
            'revert_candidate_commit', 'revert_merge_commit', 'revert_pull_request_number'
        ]::text[])
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.event_payload_keys_exact(
    p_event_type text,
    p_payload jsonb
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM carl_autonomy.event_payload_key_policy() AS policy
        WHERE policy.event_type = p_event_type
          AND cardinality(policy.required_keys) = jsonb_object_length(p_payload)
          AND p_payload ?& policy.required_keys
    )
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.jsonb_integer_between(
    value jsonb,
    minimum numeric,
    maximum numeric
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
BEGIN
    IF jsonb_typeof(value) <> 'number' OR value::text !~ '^-?(0|[1-9][0-9]*)$' THEN
        RETURN false;
    END IF;
    RETURN value::text::numeric BETWEEN minimum AND maximum;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.jsonb_positive_integer(value jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
BEGIN
    IF jsonb_typeof(value) <> 'number' OR value::text !~ '^(0|[1-9][0-9]*)$' THEN
        RETURN false;
    END IF;
    RETURN value::text::numeric > 0;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.canonical_utc_text_valid(value text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    parsed timestamptz;
BEGIN
    IF octet_length(value) NOT BETWEEN 20 AND 27
        OR value !~ '^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,6})?Z$'
    THEN
        RETURN false;
    END IF;
    BEGIN
        parsed := value::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RETURN false;
    END;
    RETURN parsed IS NOT NULL;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.lease_payload_valid(value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT jsonb_typeof(value) = 'object'
        AND jsonb_object_length(value) = 2
        AND value ?& ARRAY['owner_id', 'stage_attempt_id']
        AND jsonb_typeof(value->'owner_id') = 'string'
        AND jsonb_typeof(value->'stage_attempt_id') = 'string'
        AND value->>'owner_id' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
        AND value->>'stage_attempt_id' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.artifact_payload_valid(value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT jsonb_typeof(value) = 'object'
        AND jsonb_object_length(value) = 5
        AND value ?& ARRAY['byte_size', 'digest', 'evidence_kind', 'media_type', 'schema_version']
        AND carl_autonomy.jsonb_integer_between(value->'schema_version', 1, 1)
        AND jsonb_typeof(value->'digest') = 'string'
        AND value->>'digest' ~ '^[0-9a-f]{64}$'
        AND jsonb_typeof(value->'byte_size') = 'number'
        AND carl_autonomy.jsonb_integer_between(value->'byte_size', 0, 16777216)
        AND jsonb_typeof(value->'evidence_kind') = 'string'
        AND value->>'evidence_kind' ~ '^[a-z][a-z0-9_]{0,63}$'
        AND jsonb_typeof(value->'media_type') = 'string'
        AND value->>'media_type'
            ~ '^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}$'
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.check_payload_valid(value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT jsonb_typeof(value) = 'object'
        AND jsonb_object_length(value) = 5
        AND value ?& ARRAY['check_id', 'elapsed_ms', 'exit_code', 'output_artifact', 'status']
        AND jsonb_typeof(value->'check_id') = 'string'
        AND value->>'check_id' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
        AND jsonb_typeof(value->'status') = 'string'
        AND value->>'status' = 'passed'
        AND carl_autonomy.jsonb_integer_between(value->'exit_code', 0, 0)
        AND carl_autonomy.jsonb_integer_between(value->'elapsed_ms', 0, 86400000)
        AND carl_autonomy.artifact_payload_valid(value->'output_artifact')
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.check_array_payload_valid(value jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT jsonb_typeof(value) = 'array'
        AND jsonb_array_length(value) > 0
        AND NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements(value) AS checks(item)
            WHERE NOT carl_autonomy.check_payload_valid(item)
        )
        AND NOT EXISTS (
            SELECT 1
            FROM (
                SELECT convert_to(item->>'check_id', 'UTF8') AS check_id,
                    lag(convert_to(item->>'check_id', 'UTF8')) OVER (ORDER BY ordinal) AS prior_id
                FROM jsonb_array_elements(value) WITH ORDINALITY AS checks(item, ordinal)
            ) AS ordered
            WHERE prior_id >= check_id
        )
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.event_payload_shape_valid(
    p_event_type text,
    p_payload jsonb
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY INVOKER
SET search_path = pg_catalog, carl_autonomy
AS $$
    SELECT CASE p_event_type
        WHEN 'state_transitioned' THEN
            jsonb_typeof(p_payload->'from_state') = 'string'
            AND jsonb_typeof(p_payload->'to_state') = 'string'
            AND p_payload->>'from_state' IN (
                'queued', 'baselining', 'diagnosing', 'proposal_review', 'building',
                'deterministic_validation', 'paired_evaluation', 'holdout_validation',
                'review_complete', 'pr_open', 'merged', 'soaking', 'accepted', 'rejected',
                'inconclusive', 'blocked', 'budget_exhausted', 'reverted', 'abandoned'
            )
            AND p_payload->>'to_state' IN (
                'queued', 'baselining', 'diagnosing', 'proposal_review', 'building',
                'deterministic_validation', 'paired_evaluation', 'holdout_validation',
                'review_complete', 'pr_open', 'merged', 'soaking', 'accepted', 'rejected',
                'inconclusive', 'blocked', 'budget_exhausted', 'reverted', 'abandoned'
            )
            AND (
                NOT (p_payload ? '_lease')
                OR carl_autonomy.lease_payload_valid(p_payload->'_lease')
            )
        WHEN 'role_recorded' THEN
            jsonb_typeof(p_payload->'artifact_digest') = 'string'
            AND p_payload->>'artifact_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'role') = 'string'
            AND jsonb_typeof(p_payload->'verdict') = 'string'
            AND (
                (
                    p_payload->>'role' IN ('causal', 'product', 'evaluation')
                    AND p_payload->>'verdict' IN ('approve', 'reject', 'hard_objection')
                )
                OR (
                    p_payload->>'role' IN (
                        'correctness', 'security', 'maintainability', 'benchmark_integrity'
                    )
                    AND p_payload->>'verdict' IN ('approve', 'reject', 'hard_finding')
                )
            )
            AND (
                NOT (p_payload ? '_lease')
                OR carl_autonomy.lease_payload_valid(p_payload->'_lease')
            )
        WHEN 'lease_acquired' THEN
            jsonb_typeof(p_payload->'expires_at') = 'string'
            AND carl_autonomy.canonical_utc_text_valid(p_payload->>'expires_at')
            AND jsonb_typeof(p_payload->'owner_id') = 'string'
            AND p_payload->>'owner_id' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
        WHEN 'lease_reconciled' THEN
            jsonb_typeof(p_payload->'lease_stage_attempt_id') = 'string'
            AND p_payload->>'lease_stage_attempt_id'
                ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
            AND jsonb_typeof(p_payload->'worker_not_live') = 'boolean'
            AND p_payload->'worker_not_live' = 'true'::jsonb
        WHEN 'lease_released' THEN
            jsonb_typeof(p_payload->'lease_stage_attempt_id') = 'string'
            AND p_payload->>'lease_stage_attempt_id'
                ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
        WHEN 'live_spend_recorded' THEN
            jsonb_typeof(p_payload->'run_id') = 'string'
            AND p_payload->>'run_id' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
            AND carl_autonomy.jsonb_integer_between(p_payload->'live_microdollars', 1, 1000000000)
        WHEN 'workspace_prepared' THEN
            carl_autonomy.lease_payload_valid(p_payload->'_lease')
            AND carl_autonomy.jsonb_integer_between(p_payload->'schema_version', 1, 1)
            AND jsonb_typeof(p_payload->'branch') = 'string'
            AND p_payload->>'branch'
                ~ '^codex/experiment-[a-z0-9][a-z0-9-]*-[0-9a-f]{10}$'
            AND jsonb_typeof(p_payload->'experiment_id') = 'string'
            AND p_payload->>'experiment_id' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
            AND jsonb_typeof(p_payload->'manifest_digest') = 'string'
            AND p_payload->>'manifest_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'parent_commit') = 'string'
            AND p_payload->>'parent_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND carl_autonomy.artifact_payload_valid(p_payload->'request_artifact')
        WHEN 'candidate_sealed' THEN
            carl_autonomy.lease_payload_valid(p_payload->'_lease')
            AND carl_autonomy.jsonb_integer_between(p_payload->'schema_version', 1, 1)
            AND carl_autonomy.jsonb_integer_between(p_payload->'changed_path_count', 1, 4096)
            AND jsonb_typeof(p_payload->'branch') = 'string'
            AND p_payload->>'branch'
                ~ '^codex/experiment-[a-z0-9][a-z0-9-]*-[0-9a-f]{10}$'
            AND jsonb_typeof(p_payload->'candidate_commit') = 'string'
            AND p_payload->>'candidate_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'experiment_id') = 'string'
            AND p_payload->>'experiment_id' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
            AND jsonb_typeof(p_payload->'manifest_digest') = 'string'
            AND p_payload->>'manifest_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'parent_commit') = 'string'
            AND p_payload->>'parent_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND p_payload->>'candidate_commit' <> p_payload->>'parent_commit'
            AND carl_autonomy.artifact_payload_valid(p_payload->'diff_artifact')
            AND carl_autonomy.artifact_payload_valid(p_payload->'report_artifact')
            AND carl_autonomy.artifact_payload_valid(p_payload->'changed_paths_artifact')
            AND carl_autonomy.check_array_payload_valid(p_payload->'checks')
        WHEN 'paired_evidence_recorded' THEN
            carl_autonomy.lease_payload_valid(p_payload->'_lease')
            AND carl_autonomy.jsonb_integer_between(p_payload->'schema_version', 1, 1)
            AND carl_autonomy.jsonb_integer_between(p_payload->'paired_trials', 0, 1000000)
            AND carl_autonomy.jsonb_integer_between(p_payload->'pass_rate_delta_basis_points', -10000, 10000)
            AND carl_autonomy.jsonb_integer_between(p_payload->'confidence_lower_basis_points', -10000, 10000)
            AND jsonb_typeof(p_payload->'baseline_scorecard_digest') = 'string'
            AND p_payload->>'baseline_scorecard_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'candidate_commit') = 'string'
            AND p_payload->>'candidate_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'candidate_scorecard_digest') = 'string'
            AND p_payload->>'candidate_scorecard_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'decision') = 'string'
            AND p_payload->>'decision' IN ('improvement', 'rejected', 'insufficient_evidence')
            AND jsonb_typeof(p_payload->'experiment_id') = 'string'
            AND p_payload->>'experiment_id' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
            AND jsonb_typeof(p_payload->'manifest_digest') = 'string'
            AND p_payload->>'manifest_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'parent_commit') = 'string'
            AND p_payload->>'parent_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND carl_autonomy.artifact_payload_valid(p_payload->'comparison_artifact')
        WHEN 'review_packet_recorded' THEN
            carl_autonomy.lease_payload_valid(p_payload->'_lease')
            AND carl_autonomy.jsonb_integer_between(p_payload->'schema_version', 1, 1)
            AND jsonb_typeof(p_payload->'candidate_commit') = 'string'
            AND p_payload->>'candidate_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'deterministic_evidence_digest') = 'string'
            AND p_payload->>'deterministic_evidence_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'diff_digest') = 'string'
            AND p_payload->>'diff_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'experiment_id') = 'string'
            AND p_payload->>'experiment_id' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
            AND jsonb_typeof(p_payload->'manifest_digest') = 'string'
            AND p_payload->>'manifest_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'paired_evidence_digest') = 'string'
            AND p_payload->>'paired_evidence_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'review_contract_version') = 'string'
            AND p_payload->>'review_contract_version' = 'candidate-review-v1'
            AND jsonb_typeof(p_payload->'role') = 'string'
            AND p_payload->>'role' IN (
                'correctness', 'security', 'maintainability', 'benchmark_integrity'
            )
        WHEN 'review_attested' THEN
            carl_autonomy.lease_payload_valid(p_payload->'_lease')
            AND carl_autonomy.jsonb_integer_between(p_payload->'schema_version', 1, 1)
            AND jsonb_typeof(p_payload->'candidate_commit') = 'string'
            AND p_payload->>'candidate_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'context_id') = 'string'
            AND p_payload->>'context_id' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
            AND jsonb_typeof(p_payload->'experiment_id') = 'string'
            AND p_payload->>'experiment_id' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
            AND jsonb_typeof(p_payload->'manifest_digest') = 'string'
            AND p_payload->>'manifest_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'packet_digest') = 'string'
            AND p_payload->>'packet_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'reviewer_id') = 'string'
            AND p_payload->>'reviewer_id' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
            AND p_payload->>'reviewer_id' <> p_payload->>'context_id'
            AND jsonb_typeof(p_payload->'role') = 'string'
            AND p_payload->>'role' IN (
                'correctness', 'security', 'maintainability', 'benchmark_integrity'
            )
            AND jsonb_typeof(p_payload->'verdict') = 'string'
            AND p_payload->>'verdict' IN ('approve', 'reject', 'hard_finding')
            AND carl_autonomy.artifact_payload_valid(p_payload->'report_artifact')
        WHEN 'draft_pr_requested' THEN
            carl_autonomy.lease_payload_valid(p_payload->'_lease')
            AND jsonb_typeof(p_payload->'base_branch') = 'string'
            AND p_payload->>'base_branch' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]*$'
            AND octet_length(p_payload->>'base_branch') BETWEEN 1 AND 128
            AND jsonb_typeof(p_payload->'candidate_commit') = 'string'
            AND p_payload->>'candidate_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'expected_remote_url') = 'string'
            AND octet_length(p_payload->>'expected_remote_url') BETWEEN 1 AND 4096
            AND jsonb_typeof(p_payload->'head_branch') = 'string'
            AND p_payload->>'head_branch'
                ~ '^codex/experiment-[a-z0-9][a-z0-9-]*-[0-9a-f]{10}$'
            AND jsonb_typeof(p_payload->'repository') = 'string'
            AND p_payload->>'repository'
                ~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'
        WHEN 'draft_pr_recorded' THEN
            carl_autonomy.lease_payload_valid(p_payload->'_lease')
            AND carl_autonomy.jsonb_integer_between(p_payload->'schema_version', 1, 1)
            AND carl_autonomy.jsonb_positive_integer(p_payload->'number')
            AND jsonb_typeof(p_payload->'is_draft') = 'boolean'
            AND p_payload->'is_draft' = 'true'::jsonb
            AND jsonb_typeof(p_payload->'base_branch') = 'string'
            AND p_payload->>'base_branch' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
            AND jsonb_typeof(p_payload->'candidate_commit') = 'string'
            AND p_payload->>'candidate_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'head_branch') = 'string'
            AND p_payload->>'head_branch'
                ~ '^codex/experiment-[a-z0-9][a-z0-9-]*-[0-9a-f]{10}$'
            AND jsonb_typeof(p_payload->'repository') = 'string'
            AND p_payload->>'repository' ~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'
            AND jsonb_typeof(p_payload->'state') = 'string'
            AND p_payload->>'state' = 'OPEN'
            AND jsonb_typeof(p_payload->'url') = 'string'
            AND p_payload->>'url' = 'https://github.com/' || p_payload->>'repository'
                || '/pull/' || (p_payload->'number')::text
        WHEN 'workspace_disposed' THEN
            carl_autonomy.lease_payload_valid(p_payload->'_lease')
            AND jsonb_typeof(p_payload->'branch') = 'string'
            AND p_payload->>'branch'
                ~ '^codex/experiment-[a-z0-9][a-z0-9-]*-[0-9a-f]{10}$'
            AND jsonb_typeof(p_payload->'candidate_commit') = 'string'
            AND p_payload->>'candidate_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
        WHEN 'retry_scheduled' THEN
            carl_autonomy.jsonb_integer_between(p_payload->'attempt', 1, 3)
            AND
            jsonb_typeof(p_payload->'changed_action') = 'string'
            AND octet_length(p_payload->>'changed_action') BETWEEN 1 AND 1024
            AND jsonb_typeof(p_payload->'failed_stage_attempt_id') = 'string'
            AND p_payload->>'failed_stage_attempt_id'
                ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
            AND jsonb_typeof(p_payload->'failure_class') = 'string'
            AND p_payload->>'failure_class' ~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
            AND jsonb_typeof(p_payload->'scheduled_at') = 'string'
            AND carl_autonomy.canonical_utc_text_valid(p_payload->>'scheduled_at')
        WHEN 'experimental_published' THEN
            jsonb_typeof(p_payload->'branch') = 'string'
            AND octet_length(p_payload->>'branch') BETWEEN 1 AND 256
            AND p_payload->>'branch' LIKE 'experimental/%'
            AND jsonb_typeof(p_payload->'candidate_packet_digest') = 'string'
            AND p_payload->>'candidate_packet_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'commit') = 'string'
            AND p_payload->>'commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'tree') = 'string'
            AND p_payload->>'tree' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
        WHEN 'protected_validation_recorded' THEN
            jsonb_typeof(p_payload->'candidate_commit') = 'string'
            AND p_payload->>'candidate_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'candidate_tree') = 'string'
            AND p_payload->>'candidate_tree' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'receipt_digest') = 'string'
            AND p_payload->>'receipt_digest' ~ '^[0-9a-f]{64}$'
        WHEN 'promotion_recorded' THEN
            jsonb_typeof(p_payload->'merge_commit') = 'string'
            AND p_payload->>'merge_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'merge_tree') = 'string'
            AND p_payload->>'merge_tree' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
        WHEN 'soak_observed' THEN
            jsonb_typeof(p_payload->'evidence_digest') = 'string'
            AND p_payload->>'evidence_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'merge_commit') = 'string'
            AND p_payload->>'merge_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'observed_at') = 'string'
            AND carl_autonomy.canonical_utc_text_valid(p_payload->>'observed_at')
            AND jsonb_typeof(p_payload->'healthy') = 'boolean'
        WHEN 'revert_recorded' THEN
            carl_autonomy.jsonb_positive_integer(p_payload->'revert_pull_request_number')
            AND
            jsonb_typeof(p_payload->'hard_failure_digest') = 'string'
            AND p_payload->>'hard_failure_digest' ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(p_payload->'merge_commit') = 'string'
            AND p_payload->>'merge_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'restored_tree') = 'string'
            AND p_payload->>'restored_tree' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'revert_candidate_commit') = 'string'
            AND p_payload->>'revert_candidate_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            AND jsonb_typeof(p_payload->'revert_merge_commit') = 'string'
            AND p_payload->>'revert_merge_commit' ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
        ELSE true
    END
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
            AND jsonb_typeof(payload->'from_state') = 'string'
            AND jsonb_typeof(payload->'to_state') = 'string'
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
    parent_commit_value text;
    registered_text text;
    registered_time timestamptz;
    deterministic_checks_value text[];
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
    parent_commit_value := value->>'parent_commit';
    registered_text := value->>'registered_at';
    IF experiment_key IS NULL OR registered_text IS NULL OR value->>'schema_version' <> '1'
        OR NOT carl_autonomy.canonical_utc_text_valid(registered_text)
        OR parent_commit_value !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
        OR jsonb_typeof(value->'deterministic_checks') <> 'array'
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'manifest_json_invalid';
    END IF;
    BEGIN
        registered_time := registered_text::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'manifest_json_invalid';
    END;
    SELECT array_agg(check_id ORDER BY convert_to(check_id, 'UTF8'))
    INTO deterministic_checks_value
    FROM jsonb_array_elements_text(value->'deterministic_checks') AS checks(check_id);
    IF deterministic_checks_value IS NULL THEN
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
    INSERT INTO carl_autonomy.experiment_projection_guards(
        experiment_id, manifest_digest, manifest_parent_commit, manifest_registered_at,
        manifest_deterministic_checks, updated_at
    ) VALUES (
        experiment_key, p_manifest_digest, parent_commit_value, registered_time,
        deterministic_checks_value, p_observed_at
    );
    RETURN QUERY SELECT true;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.validate_and_advance_event(
    p_experiment_id text,
    p_event_type text,
    p_payload jsonb,
    p_payload_digest text,
    p_stage_attempt_id text,
    p_occurred_at_text text,
    p_occurred_at timestamptz,
    p_observed_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    guard carl_autonomy.experiment_projection_guards%ROWTYPE;
    source_state text;
    target_state text;
    role_name text;
    verdict_name text;
    expected_target text;
    lease_required boolean := false;
    prior_retry jsonb;
    packet_identity jsonb;
    retry_attempt integer;
    retry_key text;
BEGIN
    SELECT g.* INTO guard
    FROM carl_autonomy.experiment_projection_guards AS g
    WHERE g.experiment_id = p_experiment_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'experiment_projection_missing';
    END IF;
    IF NOT carl_autonomy.event_payload_keys_exact(p_event_type, p_payload) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid_event_payload_keys';
    END IF;
    IF NOT carl_autonomy.event_payload_shape_valid(p_event_type, p_payload) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid_event_payload_shape';
    END IF;
    IF p_occurred_at < guard.manifest_registered_at THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'event_precedes_registration';
    END IF;

    IF p_event_type = 'state_transitioned' THEN
        source_state := p_payload->>'from_state';
        target_state := p_payload->>'to_state';
        IF source_state IS NULL OR target_state IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid_transition_payload';
        END IF;
        IF guard.lifecycle_state IN (
            'accepted', 'rejected', 'inconclusive', 'blocked', 'budget_exhausted',
            'reverted', 'abandoned'
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'terminal_state';
        END IF;
        IF source_state <> guard.lifecycle_state THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'stale_source_state';
        END IF;
        expected_target := CASE source_state
            WHEN 'queued' THEN 'baselining'
            WHEN 'baselining' THEN 'diagnosing'
            WHEN 'diagnosing' THEN 'proposal_review'
            WHEN 'proposal_review' THEN 'building'
            WHEN 'building' THEN 'deterministic_validation'
            WHEN 'deterministic_validation' THEN 'paired_evaluation'
            WHEN 'paired_evaluation' THEN 'holdout_validation'
            WHEN 'holdout_validation' THEN 'review_complete'
            WHEN 'review_complete' THEN 'pr_open'
            WHEN 'pr_open' THEN 'merged'
            WHEN 'merged' THEN 'soaking'
            WHEN 'soaking' THEN 'accepted'
            ELSE NULL
        END;
        IF target_state <> expected_target AND target_state NOT IN (
            'rejected', 'inconclusive', 'blocked', 'budget_exhausted', 'reverted', 'abandoned'
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid_transition';
        END IF;
        lease_required := target_state IN (
            'building', 'deterministic_validation', 'paired_evaluation', 'holdout_validation',
            'review_complete', 'pr_open', 'merged', 'soaking', 'accepted'
        );
        IF lease_required AND (
            NOT guard.lease_active
            OR guard.lease_reconciled
            OR p_payload->'_lease'->>'owner_id' IS DISTINCT FROM guard.lease_owner_id
            OR p_payload->'_lease'->>'stage_attempt_id' IS DISTINCT FROM guard.lease_attempt_id
            OR p_occurred_at > guard.lease_expires_at
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'lease_capability_invalid';
        END IF;
        IF target_state = 'building' AND (
            guard.proposal_approvals < 2 OR guard.proposal_hard_objections <> 0
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'proposal_quorum_unsatisfied';
        END IF;
        IF target_state = 'deterministic_validation'
            AND guard.workspace_prepared AND NOT guard.candidate_sealed
        THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'sealed_candidate_required';
        END IF;
        IF target_state = 'holdout_validation'
            AND (NOT guard.paired_evidence_recorded OR NOT guard.protected_validation_recorded)
        THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'phase4_protected_validation_required';
        END IF;
        IF target_state = 'review_complete' AND (
            guard.candidate_approvals < 3 OR cardinality(guard.candidate_roles) <> 4
            OR guard.candidate_hard_findings <> 0
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'candidate_quorum_unsatisfied';
        END IF;
        IF target_state = 'accepted' AND (
            NOT guard.promotion_recorded
            OR guard.qualifying_healthy_soak_at IS NULL
            OR guard.qualifying_healthy_soak_at > p_occurred_at
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'soak_healthy_observation_required';
        END IF;
        UPDATE carl_autonomy.experiment_projection_guards
        SET lifecycle_state = target_state,
            lifecycle_revision = lifecycle_revision + 1,
            updated_at = p_observed_at
        WHERE experiment_id = p_experiment_id;
        RETURN;
    END IF;

    IF p_event_type = 'role_recorded' THEN
        role_name := p_payload->>'role';
        verdict_name := p_payload->>'verdict';
        IF role_name IN ('causal', 'product', 'evaluation') THEN
            IF guard.lifecycle_state <> 'proposal_review' OR role_name = ANY(guard.proposal_roles) THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'proposal_review_invalid';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET proposal_roles = array_append(proposal_roles, role_name),
                proposal_approvals = proposal_approvals + (verdict_name = 'approve')::integer,
                proposal_hard_objections = proposal_hard_objections
                    + (verdict_name = 'hard_objection')::integer,
                updated_at = p_observed_at
            WHERE experiment_id = p_experiment_id;
        ELSE
            IF guard.lifecycle_state <> 'holdout_validation'
                OR role_name NOT IN ('correctness', 'security', 'maintainability', 'benchmark_integrity')
                OR role_name = ANY(guard.candidate_roles)
                OR NOT guard.lease_active OR guard.lease_reconciled
                OR p_payload->'_lease'->>'owner_id' IS DISTINCT FROM guard.lease_owner_id
                OR p_payload->'_lease'->>'stage_attempt_id' IS DISTINCT FROM guard.lease_attempt_id
                OR p_occurred_at > guard.lease_expires_at
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'candidate_review_invalid';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET candidate_roles = array_append(candidate_roles, role_name),
                candidate_approvals = candidate_approvals + (verdict_name = 'approve')::integer,
                candidate_hard_findings = candidate_hard_findings
                    + (verdict_name = 'hard_finding')::integer,
                updated_at = p_observed_at
            WHERE experiment_id = p_experiment_id;
        END IF;
        RETURN;
    END IF;

    IF p_event_type = 'lease_acquired' THEN
        IF NOT (
                (guard.lifecycle_state = 'proposal_review' AND NOT guard.lease_active)
                OR (guard.lease_active AND guard.lease_reconciled AND guard.lifecycle_state IN (
                    'building', 'deterministic_validation', 'paired_evaluation',
                    'holdout_validation', 'review_complete', 'pr_open', 'merged', 'soaking'
                ))
            )
            OR p_payload->>'owner_id' IS NULL OR p_payload->>'expires_at' IS NULL
            OR (p_payload->>'expires_at')::timestamptz <= p_occurred_at
            OR (p_payload->>'expires_at')::timestamptz > p_occurred_at + interval '6 hours'
        THEN
            RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'lease_wrong_state';
        END IF;
        UPDATE carl_autonomy.experiment_projection_guards
        SET lease_active = true, lease_reconciled = false, lease_attempt_id = p_stage_attempt_id,
            lease_owner_id = p_payload->>'owner_id',
            lease_expires_at = (p_payload->>'expires_at')::timestamptz,
            updated_at = p_observed_at
        WHERE experiment_id = p_experiment_id;
        RETURN;
    END IF;

    IF p_event_type IN (
        'workspace_prepared', 'candidate_sealed', 'paired_evidence_recorded',
        'review_packet_recorded', 'review_attested', 'draft_pr_requested',
        'draft_pr_recorded', 'workspace_disposed'
    ) AND (
        NOT guard.lease_active
        OR guard.lease_reconciled
        OR p_payload->'_lease'->>'owner_id' IS DISTINCT FROM guard.lease_owner_id
        OR p_payload->'_lease'->>'stage_attempt_id' IS DISTINCT FROM guard.lease_attempt_id
        OR p_occurred_at > guard.lease_expires_at
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'lease_capability_invalid';
    END IF;

    CASE p_event_type
        WHEN 'workspace_prepared' THEN
            IF guard.lifecycle_state <> 'building' OR guard.workspace_prepared
                OR p_payload->>'experiment_id' IS DISTINCT FROM p_experiment_id
                OR p_payload->>'manifest_digest' IS DISTINCT FROM guard.manifest_digest::text
                OR p_payload->>'parent_commit' IS DISTINCT FROM guard.manifest_parent_commit
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'candidate_prepare_wrong_state';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET workspace_prepared = true,
                workspace_manifest_digest = p_payload->>'manifest_digest',
                workspace_parent_commit = p_payload->>'parent_commit',
                workspace_branch = p_payload->>'branch',
                updated_at = p_observed_at
            WHERE experiment_id = p_experiment_id;
        WHEN 'candidate_sealed' THEN
            IF guard.lifecycle_state <> 'building' OR NOT guard.workspace_prepared
                OR guard.candidate_sealed
                OR p_payload->>'candidate_commit' !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
                OR p_payload->>'experiment_id' IS DISTINCT FROM p_experiment_id
                OR p_payload->>'manifest_digest' IS DISTINCT FROM guard.manifest_digest::text
                OR p_payload->>'parent_commit' IS DISTINCT FROM guard.manifest_parent_commit
                OR p_payload->>'branch' IS DISTINCT FROM guard.workspace_branch
                OR ARRAY(
                    SELECT check_item->>'check_id'
                    FROM jsonb_array_elements(p_payload->'checks')
                        WITH ORDINALITY AS checks(check_item, ordinal)
                    ORDER BY ordinal
                ) IS DISTINCT FROM guard.manifest_deterministic_checks
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'prepared_candidate_required';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET candidate_sealed = true,
                candidate_packet_digest = carl_autonomy.candidate_payload_digest(p_payload),
                candidate_commit = p_payload->>'candidate_commit',
                candidate_branch = p_payload->>'branch',
                candidate_diff_digest = p_payload->'diff_artifact'->>'digest',
                updated_at = p_observed_at WHERE experiment_id = p_experiment_id;
        WHEN 'paired_evidence_recorded' THEN
            IF guard.lifecycle_state <> 'paired_evaluation' OR NOT guard.candidate_sealed
                OR guard.paired_evidence_recorded
                OR p_payload->>'experiment_id' IS DISTINCT FROM p_experiment_id
                OR p_payload->>'manifest_digest' IS DISTINCT FROM guard.manifest_digest::text
                OR p_payload->>'parent_commit' IS DISTINCT FROM guard.manifest_parent_commit
                OR p_payload->>'candidate_commit' IS DISTINCT FROM guard.candidate_commit
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'paired_evidence_prerequisite_missing';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET paired_evidence_recorded = true,
                paired_evidence_digest = carl_autonomy.candidate_payload_digest(p_payload),
                paired_evidence_candidate_commit = p_payload->>'candidate_commit',
                paired_baseline_scorecard_digest = p_payload->>'baseline_scorecard_digest',
                paired_candidate_scorecard_digest = p_payload->>'candidate_scorecard_digest',
                paired_decision = p_payload->>'decision',
                updated_at = p_observed_at
            WHERE experiment_id = p_experiment_id;
        WHEN 'protected_validation_recorded' THEN
            IF guard.lifecycle_state <> 'paired_evaluation' OR NOT guard.candidate_sealed
                OR NOT guard.paired_evidence_recorded OR NOT guard.experimental_published
                OR guard.protected_validation_recorded
                OR jsonb_object_length(p_payload) <> 3
                OR NOT p_payload ?& ARRAY['candidate_commit', 'candidate_tree', 'receipt_digest']
                OR p_payload->>'candidate_commit' IS DISTINCT FROM guard.candidate_commit
                OR p_payload->>'candidate_commit' IS DISTINCT FROM guard.experimental_commit
                OR p_payload->>'candidate_tree' IS DISTINCT FROM guard.experimental_tree
                OR p_payload->>'receipt_digest' !~ '^[0-9a-f]{64}$'
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'protected_validation_prerequisite_missing';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET protected_validation_recorded = true,
                protected_validation_candidate_commit = p_payload->>'candidate_commit',
                protected_validation_candidate_tree = p_payload->>'candidate_tree',
                protected_validation_receipt_digest = p_payload->>'receipt_digest',
                updated_at = p_observed_at
            WHERE experiment_id = p_experiment_id;
        WHEN 'review_packet_recorded' THEN
            role_name := p_payload->>'role';
            IF guard.lifecycle_state <> 'paired_evaluation' OR NOT guard.paired_evidence_recorded
                OR role_name IS NULL OR role_name = ANY(guard.review_packet_roles)
                OR guard.paired_decision IS DISTINCT FROM 'improvement'
                OR p_payload->>'experiment_id' IS DISTINCT FROM p_experiment_id
                OR p_payload->>'manifest_digest' IS DISTINCT FROM guard.manifest_digest::text
                OR p_payload->>'candidate_commit' IS DISTINCT FROM guard.candidate_commit
                OR p_payload->>'diff_digest' IS DISTINCT FROM guard.candidate_diff_digest::text
                OR p_payload->>'deterministic_evidence_digest'
                    IS DISTINCT FROM guard.candidate_packet_digest::text
                OR p_payload->>'paired_evidence_digest'
                    IS DISTINCT FROM guard.paired_evidence_digest::text
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'review_packet_prerequisite_missing';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET review_packet_roles = array_append(review_packet_roles, role_name),
                review_packet_count = review_packet_count + 1,
                review_packet_identities = jsonb_set(
                    review_packet_identities,
                    ARRAY[role_name],
                    jsonb_build_object(
                        'candidate_commit', p_payload->>'candidate_commit',
                        'deterministic_evidence_digest',
                            p_payload->>'deterministic_evidence_digest',
                        'diff_digest', p_payload->>'diff_digest',
                        'manifest_digest', p_payload->>'manifest_digest',
                        'packet_digest', carl_autonomy.candidate_payload_digest(p_payload),
                        'paired_evidence_digest', p_payload->>'paired_evidence_digest',
                        'role', role_name
                    ),
                    true
                ),
                updated_at = p_observed_at
            WHERE experiment_id = p_experiment_id;
        WHEN 'review_attested' THEN
            role_name := p_payload->>'role';
            packet_identity := guard.review_packet_identities -> role_name;
            IF guard.lifecycle_state <> 'paired_evaluation'
                OR NOT role_name = ANY(guard.review_packet_roles)
                OR role_name = ANY(guard.review_attestation_roles)
                OR packet_identity IS NULL
                OR p_payload->>'experiment_id' IS DISTINCT FROM p_experiment_id
                OR p_payload->>'manifest_digest' IS DISTINCT FROM guard.manifest_digest::text
                OR p_payload->>'candidate_commit' IS DISTINCT FROM guard.candidate_commit
                OR p_payload->>'role' IS DISTINCT FROM packet_identity->>'role'
                OR p_payload->>'packet_digest' IS DISTINCT FROM packet_identity->>'packet_digest'
                OR p_payload->>'reviewer_id' = ANY(guard.review_attestation_reviewers)
                OR p_payload->>'context_id' = ANY(guard.review_attestation_contexts)
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'review_packet_required';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET review_attestation_roles = array_append(review_attestation_roles, role_name),
                review_attestation_count = review_attestation_count + 1,
                review_attestation_reviewers = array_append(
                    review_attestation_reviewers, p_payload->>'reviewer_id'
                ),
                review_attestation_contexts = array_append(
                    review_attestation_contexts, p_payload->>'context_id'
                ),
                review_attestation_approvals = review_attestation_approvals
                    + (p_payload->>'verdict' = 'approve')::integer,
                review_attestation_hard_findings = review_attestation_hard_findings
                    + (p_payload->>'verdict' = 'hard_finding')::integer,
                review_attestation_identities = jsonb_set(
                    review_attestation_identities,
                    ARRAY[role_name],
                    jsonb_build_object(
                        'context_id', p_payload->>'context_id',
                        'packet_digest', p_payload->>'packet_digest',
                        'reviewer_id', p_payload->>'reviewer_id',
                        'role', role_name,
                        'verdict', p_payload->>'verdict'
                    ),
                    true
                ),
                updated_at = p_observed_at WHERE experiment_id = p_experiment_id;
        WHEN 'draft_pr_requested' THEN
            IF guard.lifecycle_state <> 'paired_evaluation'
                OR NOT guard.paired_evidence_recorded
                OR guard.review_attestation_count <> 4
                OR cardinality(guard.review_attestation_roles) <> 4
                OR NOT guard.review_attestation_roles @> ARRAY[
                    'correctness', 'security', 'maintainability', 'benchmark_integrity'
                ]::text[]
                OR guard.review_attestation_approvals < 3
                OR guard.review_attestation_hard_findings <> 0
                OR guard.draft_pr_requested
                OR p_payload->>'candidate_commit' IS DISTINCT FROM guard.candidate_commit
                OR p_payload->>'head_branch' IS DISTINCT FROM guard.candidate_branch
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'candidate_attestation_quorum_unsatisfied';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET draft_pr_requested = true,
                draft_request_repository = p_payload->>'repository',
                draft_request_base_branch = p_payload->>'base_branch',
                draft_request_head_branch = p_payload->>'head_branch',
                draft_request_candidate_commit = p_payload->>'candidate_commit',
                updated_at = p_observed_at
            WHERE experiment_id = p_experiment_id;
        WHEN 'draft_pr_recorded' THEN
            IF guard.lifecycle_state <> 'paired_evaluation'
                OR NOT guard.paired_evidence_recorded
                OR NOT guard.draft_pr_requested OR guard.draft_pr_recorded
                OR guard.review_attestation_count <> 4
                OR guard.review_attestation_approvals < 3
                OR guard.review_attestation_hard_findings <> 0
                OR p_payload->>'repository' IS DISTINCT FROM guard.draft_request_repository
                OR p_payload->>'base_branch' IS DISTINCT FROM guard.draft_request_base_branch
                OR p_payload->>'head_branch' IS DISTINCT FROM guard.draft_request_head_branch
                OR p_payload->>'candidate_commit'
                    IS DISTINCT FROM guard.draft_request_candidate_commit
                OR p_payload->>'candidate_commit' IS DISTINCT FROM guard.candidate_commit
                OR p_payload->>'head_branch' IS DISTINCT FROM guard.candidate_branch
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'draft_pr_authorization_required';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET draft_pr_recorded = true,
                draft_pr_repository = p_payload->>'repository',
                draft_pr_base_branch = p_payload->>'base_branch',
                draft_pr_head_branch = p_payload->>'head_branch',
                draft_pr_candidate_commit = p_payload->>'candidate_commit',
                updated_at = p_observed_at
            WHERE experiment_id = p_experiment_id;
        WHEN 'workspace_disposed' THEN
            IF guard.lifecycle_state <> 'paired_evaluation'
                OR NOT guard.workspace_prepared OR NOT guard.candidate_sealed
                OR NOT guard.draft_pr_recorded OR guard.workspace_disposed
                OR p_payload->>'branch' IS DISTINCT FROM guard.workspace_branch
                OR p_payload->>'branch' IS DISTINCT FROM guard.candidate_branch
                OR p_payload->>'candidate_commit' IS DISTINCT FROM guard.candidate_commit
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'draft_pr_required';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET workspace_disposed = true,
                workspace_disposed_branch = p_payload->>'branch',
                workspace_disposed_candidate_commit = p_payload->>'candidate_commit',
                updated_at = p_observed_at
            WHERE experiment_id = p_experiment_id;
        WHEN 'experimental_published' THEN
            IF guard.experimental_published OR NOT guard.candidate_sealed
                OR jsonb_typeof(p_payload->'branch') <> 'string'
                OR p_payload->>'branch' IS DISTINCT FROM 'experimental/' || p_experiment_id
                OR octet_length(p_payload->>'branch') > 256
                OR p_payload->>'candidate_packet_digest' !~ '^[0-9a-f]{64}$'
                OR p_payload->>'candidate_packet_digest'
                    IS DISTINCT FROM guard.candidate_packet_digest
                OR p_payload->>'commit' !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
                OR p_payload->>'commit' IS DISTINCT FROM guard.candidate_commit
                OR p_payload->>'tree' !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'experimental_already_published';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET experimental_published = true,
                experimental_branch = p_payload->>'branch',
                experimental_candidate_packet_digest = p_payload->>'candidate_packet_digest',
                experimental_commit = p_payload->>'commit',
                experimental_tree = p_payload->>'tree',
                updated_at = p_observed_at
            WHERE experiment_id = p_experiment_id;
        WHEN 'promotion_recorded' THEN
            IF NOT guard.protected_validation_recorded OR guard.promotion_recorded
                OR p_payload->>'merge_commit' !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
                OR p_payload->>'merge_tree' !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'promotion_prerequisite_missing';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET promotion_recorded = true,
                promotion_merge_commit = p_payload->>'merge_commit',
                promotion_merge_tree = p_payload->>'merge_tree',
                promotion_merged_at = p_occurred_at,
                updated_at = p_observed_at WHERE experiment_id = p_experiment_id;
        WHEN 'soak_observed' THEN
            IF NOT guard.promotion_recorded OR jsonb_object_length(p_payload) <> 4
                OR NOT p_payload ?& ARRAY[
                    'evidence_digest', 'healthy', 'merge_commit', 'observed_at'
                ]
                OR p_payload->>'evidence_digest' !~ '^[0-9a-f]{64}$'
                OR p_payload->>'merge_commit' IS DISTINCT FROM guard.promotion_merge_commit
                OR p_payload->>'observed_at' IS DISTINCT FROM p_occurred_at_text
                OR jsonb_typeof(p_payload->'healthy') <> 'boolean'
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'soak_prerequisite_missing';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET soak_failure_recorded = soak_failure_recorded OR (p_payload->>'healthy')::boolean = false,
                soak_failure_digest = CASE WHEN (p_payload->>'healthy')::boolean = false
                    THEN p_payload->>'evidence_digest' ELSE soak_failure_digest END,
                soak_failures = CASE WHEN (p_payload->>'healthy')::boolean = false
                    THEN jsonb_set(
                        soak_failures,
                        ARRAY[p_payload->>'evidence_digest'],
                        to_jsonb(p_payload->>'merge_commit'),
                        true
                    )
                    ELSE soak_failures
                END,
                qualifying_healthy_soak_at = CASE
                    WHEN (p_payload->>'healthy')::boolean = true
                        AND p_occurred_at - promotion_merged_at >= interval '24 hours'
                        AND (
                            qualifying_healthy_soak_at IS NULL
                            OR p_occurred_at < qualifying_healthy_soak_at
                        )
                    THEN p_occurred_at
                    ELSE qualifying_healthy_soak_at
                END,
                updated_at = p_observed_at WHERE experiment_id = p_experiment_id;
        WHEN 'revert_recorded' THEN
            IF NOT guard.soak_failure_recorded OR guard.revert_recorded
                OR p_payload->>'merge_commit' IS DISTINCT FROM guard.promotion_merge_commit
                OR guard.soak_failures ->> (p_payload->>'hard_failure_digest')
                    IS DISTINCT FROM guard.promotion_merge_commit
                OR p_payload->>'restored_tree' !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
                OR p_payload->>'revert_candidate_commit' !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
                OR p_payload->>'revert_merge_commit' !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
                OR jsonb_typeof(p_payload->'revert_pull_request_number') <> 'number'
                OR p_payload->>'revert_pull_request_number' !~ '^[1-9][0-9]*$'
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'hard_failure_required';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET revert_recorded = true,
                revert_merge_commit = p_payload->>'merge_commit',
                revert_hard_failure_digest = p_payload->>'hard_failure_digest',
                revert_restored_tree = p_payload->>'restored_tree',
                revert_candidate_commit = p_payload->>'revert_candidate_commit',
                revert_result_merge_commit = p_payload->>'revert_merge_commit',
                revert_pull_request_number = (p_payload->>'revert_pull_request_number')::numeric,
                updated_at = p_observed_at
            WHERE experiment_id = p_experiment_id;
        WHEN 'lease_reconciled' THEN
            IF NOT guard.lease_active OR guard.lease_reconciled
                OR p_payload->>'lease_stage_attempt_id' IS DISTINCT FROM guard.lease_attempt_id
                OR p_payload->>'worker_not_live' <> 'true'
                OR p_occurred_at < guard.lease_expires_at
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'invalid_lease_reconciliation';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards SET lease_reconciled = true,
                updated_at = p_observed_at WHERE experiment_id = p_experiment_id;
        WHEN 'lease_released' THEN
            IF NOT guard.lease_active
                OR p_payload->>'lease_stage_attempt_id' IS DISTINCT FROM guard.lease_attempt_id
                OR guard.lifecycle_state IN (
                    'building', 'deterministic_validation', 'paired_evaluation',
                    'holdout_validation', 'review_complete', 'pr_open', 'merged', 'soaking'
                )
                OR (p_occurred_at > guard.lease_expires_at AND NOT guard.lease_reconciled)
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'invalid_lease_release';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET lease_active = false, lease_reconciled = false, lease_attempt_id = NULL,
                lease_owner_id = NULL, lease_expires_at = NULL, updated_at = p_observed_at
            WHERE experiment_id = p_experiment_id;
        WHEN 'live_spend_recorded' THEN
            IF jsonb_object_length(p_payload) <> 2
                OR NOT p_payload ?& ARRAY['live_microdollars', 'run_id']
                OR jsonb_typeof(p_payload->'live_microdollars') <> 'number'
                OR (p_payload->>'live_microdollars')::bigint NOT BETWEEN 1 AND 1000000000
            THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid_spend_payload';
            END IF;
        WHEN 'retry_scheduled' THEN
            retry_key := p_payload->>'failed_stage_attempt_id';
            IF jsonb_typeof(p_payload->'attempt') <> 'number'
                OR p_payload->>'attempt' !~ '^[1-3]$'
                OR retry_key !~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
                OR p_payload->>'failure_class' !~ '^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$'
                OR octet_length(p_payload->>'changed_action') NOT BETWEEN 1 AND 1024
                OR p_payload->>'scheduled_at' IS DISTINCT FROM p_occurred_at_text
            THEN
                RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid_retry_payload';
            END IF;
            retry_attempt := (p_payload->>'attempt')::integer;
            prior_retry := guard.retry_state -> retry_key;
            IF (prior_retry IS NULL AND retry_attempt <> 1)
                OR (
                    prior_retry IS NOT NULL
                    AND retry_attempt <> (prior_retry->>'attempt')::integer + 1
                )
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'retry_attempt_not_monotonic';
            END IF;
            IF prior_retry IS NOT NULL
                AND p_payload->>'changed_action'
                    IS NOT DISTINCT FROM prior_retry->>'changed_action'
            THEN
                RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'retry_action_unchanged';
            END IF;
            UPDATE carl_autonomy.experiment_projection_guards
            SET retry_state = jsonb_set(retry_state, ARRAY[retry_key], p_payload, true),
                updated_at = p_observed_at
            WHERE experiment_id = p_experiment_id;
        ELSE
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'unsupported_event_type';
    END CASE;
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
    IF jsonb_object_length(value) <> 6
        OR NOT value ?& ARRAY[
            'schema_version', 'experiment_id', 'stage_attempt_id',
            'event_type', 'occurred_at', 'payload'
        ]
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'event_json_invalid';
    END IF;
    IF carl_autonomy.sha256_text(p_event_json) <> p_event_digest
        OR value->'payload' <> payload
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'event_digest_mismatch';
    END IF;
    experiment_key := value->>'experiment_id';
    attempt_key := value->>'stage_attempt_id';
    type_name := value->>'event_type';
    occurred_text := value->>'occurred_at';
    IF experiment_key IS NULL OR attempt_key IS NULL OR type_name IS NULL
        OR occurred_text IS NULL OR value->>'schema_version' <> '1'
        OR NOT carl_autonomy.canonical_utc_text_valid(occurred_text)
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'event_json_invalid';
    END IF;
    BEGIN
        occurred_time := occurred_text::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'event_json_invalid';
    END;
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
    PERFORM carl_autonomy.validate_and_advance_event(
        experiment_key, type_name, payload, carl_autonomy.sha256_text(p_payload_json),
        attempt_key, occurred_text, occurred_time, p_observed_at
    );
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
        previous_chain_digest, chain_digest, authority, trusted_authority,
        provenance_json, appended_at
    ) VALUES (
        experiment_key, next_ordinal, 1, attempt_key, type_name,
        occurred_time, occurred_text, p_payload_json, p_event_json, p_event_digest,
        previous_hash, next_chain, authority_name,
        type_name IN (
            'paired_evidence_recorded', 'review_packet_recorded', 'review_attested',
            'draft_pr_requested', 'draft_pr_recorded', 'workspace_disposed',
            'protected_validation_recorded', 'promotion_recorded', 'soak_observed',
            'revert_recorded'
        ) OR (authority_name = 'soak' AND type_name = 'state_transitioned'),
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
    trusted_authority boolean,
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
    SELECT e.authority::text, e.trusted_authority, e.chain_digest::text, e.event_digest::text,
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

CREATE OR REPLACE FUNCTION carl_autonomy.register_dead_holder_observation(
    p_observation_json text,
    p_observation_digest text,
    p_registered_at timestamptz
)
RETURNS TABLE(applied boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, carl_autonomy
AS $$
DECLARE
    value jsonb;
    issued_time timestamptz;
    observed_time timestamptz;
    expires_time timestamptz;
    revision_value integer;
    existing carl_autonomy.dead_holder_observations%ROWTYPE;
BEGIN
    PERFORM carl_autonomy.require_role(ARRAY['carl_observer']);
    value := carl_autonomy.parse_object(p_observation_json, 'dead_holder_observation_invalid');
    IF carl_autonomy.sha256_text(p_observation_json) <> p_observation_digest
        OR value->>'schema_version' <> '1'
        OR value->>'authority' IS NULL
        OR value->>'subject_id' IS NULL
        OR value->>'scope_kind' NOT IN ('command', 'lease')
        OR value->>'scope_key' IS NULL
        OR value->>'key_id' IS NULL
        OR value->>'signature_base64' IS NULL
        OR length(value->>'signature_base64') <> 88
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'dead_holder_observation_invalid';
    END IF;
    BEGIN
        revision_value := (value->>'revision')::integer;
        issued_time := (value->>'issued_at')::timestamptz;
        observed_time := (value->>'observed_at')::timestamptz;
        expires_time := (value->>'expires_at')::timestamptz;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'dead_holder_observation_invalid';
    END;
    IF revision_value < 0 OR value->>'live' <> 'false'
        OR observed_time < issued_time OR observed_time > p_registered_at
        OR expires_time <= observed_time
        OR expires_time <= p_registered_at
    THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'dead_holder_observation_invalid';
    END IF;
    SELECT d.* INTO existing
    FROM carl_autonomy.dead_holder_observations AS d
    WHERE d.observation_digest = p_observation_digest;
    IF FOUND THEN
        IF existing.observation_json = p_observation_json THEN
            RETURN QUERY SELECT false;
            RETURN;
        END IF;
        RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'dead_holder_observation_conflict';
    END IF;
    INSERT INTO carl_autonomy.dead_holder_observations(
        observation_digest, observation_json, authority, subject_id, scope_kind,
        scope_key, revision, issued_at, issued_at_text, observed_at, observed_at_text,
        expires_at, expires_at_text, live, key_id, signature_base64, registered_at
    ) VALUES (
        p_observation_digest, p_observation_json, value->>'authority', value->>'subject_id',
        value->>'scope_kind', value->>'scope_key', revision_value,
        issued_time, value->>'issued_at', observed_time, value->>'observed_at',
        expires_time, value->>'expires_at', false, value->>'key_id',
        value->>'signature_base64', p_registered_at
    );
    RETURN QUERY SELECT true;
END;
$$;

CREATE OR REPLACE FUNCTION carl_autonomy.reconcile_expired_claim(
    p_reconciliation_json text,
    p_observation_digest text,
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
    observation carl_autonomy.dead_holder_observations%ROWTYPE;
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
    SELECT d.* INTO observation
    FROM carl_autonomy.dead_holder_observations AS d
    WHERE d.observation_digest = p_observation_digest
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'dead_holder_observation_unregistered';
    END IF;
    IF authority_value <> caller_authority OR next_value <> expected_value + 1
        OR observation.authority <> authority_value
        OR observation.subject_id <> claim_key
        OR observation.scope_kind <> 'command'
        OR observation.scope_key <> command_key_value
        OR observation.revision <> expected_value
        OR observation.live
        OR observation.observed_at_text <> observed_text
        OR observation.expires_at <= p_observed_at
    THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'dead_holder_observation_mismatch';
    END IF;
    SELECT c.* INTO current_state
    FROM carl_autonomy.commands AS c
    WHERE c.command_key = command_key_value
    FOR UPDATE;
    IF NOT FOUND OR current_state.status <> 'claimed' OR current_state.claim_id <> claim_key
        OR current_state.authority <> authority_value
    THEN
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
    p_observation_digest text,
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
    observation carl_autonomy.dead_holder_observations%ROWTYPE;
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
    SELECT d.* INTO observation
    FROM carl_autonomy.dead_holder_observations AS d
    WHERE d.observation_digest = p_observation_digest
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'dead_holder_observation_unregistered';
    END IF;
    IF authority_value <> caller_authority OR next_value <> expected_value + 1
        OR observation.authority <> authority_value
        OR observation.subject_id <> holder_value
        OR observation.scope_kind <> 'lease'
        OR observation.scope_key <> lease_key_value
        OR observation.revision <> expected_value
        OR observation.live
        OR observation.observed_at_text <> observed_text
        OR observation.expires_at <= p_observed_at
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
    observation_digest := p_observation_digest;
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
    TO carl_state_backend;
GRANT EXECUTE ON FUNCTION carl_autonomy.append_event(text, text, text, timestamptz)
    TO carl_state_backend;
GRANT EXECUTE ON FUNCTION carl_autonomy.load_experiment_manifest(text),
    carl_autonomy.load_experiment_events(text),
    carl_autonomy.latest_health_snapshot()
    TO carl_state_backend;

GRANT EXECUTE ON FUNCTION carl_autonomy.create_command(text, timestamptz),
    carl_autonomy.claim_command(text, timestamptz),
    carl_autonomy.fail_command(text, timestamptz)
    TO carl_state_backend;
GRANT EXECUTE ON FUNCTION carl_autonomy.resolve_claimed_command(text, timestamptz),
    carl_autonomy.prepare_effect_attempt(text, timestamptz),
    carl_autonomy.mark_effect_retry_scheduled(text, text, text, timestamptz),
    carl_autonomy.mark_effect_uncertain(text, text, text, timestamptz),
    carl_autonomy.mark_effect_completed(text, text, text, timestamptz)
    TO carl_state_backend;
GRANT EXECUTE ON FUNCTION carl_autonomy.reconcile_expired_claim(text, text, timestamptz)
    TO carl_state_backend;

GRANT EXECUTE ON FUNCTION carl_autonomy.register_dead_holder_observation(
    text, text, timestamptz
) TO carl_state_backend;

GRANT EXECUTE ON FUNCTION carl_autonomy.acquire_lease(text, timestamptz),
    carl_autonomy.reconcile_lease(text, text, timestamptz),
    carl_autonomy.release_lease(text, timestamptz)
    TO carl_state_backend;

GRANT EXECUTE ON FUNCTION carl_autonomy.create_supervisor_trigger(text, timestamptz)
    TO carl_state_backend;
GRANT EXECUTE ON FUNCTION carl_autonomy.claim_supervisor_trigger(text, text, integer, timestamptz),
    carl_autonomy.resolve_supervisor_trigger(text, text, integer, text, timestamptz)
    TO carl_state_backend;

GRANT EXECUTE ON FUNCTION carl_autonomy.register_evidence(text, timestamptz)
    TO carl_state_backend;
GRANT EXECUTE ON FUNCTION carl_autonomy.record_health(text, timestamptz)
    TO carl_state_backend;
GRANT EXECUTE ON FUNCTION carl_autonomy.complete_command_and_append_event(
    text, text, text, text, timestamptz
) TO carl_state_backend;

COMMIT;
