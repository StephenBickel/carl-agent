CREATE TABLE session_delegate_settings (
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider = 'codex'),
    model TEXT,
    effort TEXT,
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0),
    PRIMARY KEY (session_id, provider),
    CHECK (model IS NOT NULL OR effort IS NOT NULL),
    CHECK (
        model IS NULL
        OR (
            length(CAST(model AS BLOB)) BETWEEN 1 AND 128
            AND model NOT GLOB '*[^A-Za-z0-9_.:-]*'
            AND instr(model, char(0)) = 0
        )
    ),
    CHECK (
        effort IS NULL
        OR effort IN ('low', 'medium', 'high', 'xhigh', 'max', 'ultra')
    )
);

CREATE TABLE subscription_runs (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) > 0),
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    turn_id TEXT NOT NULL CHECK (length(turn_id) > 0),
    provider TEXT NOT NULL CHECK (provider = 'codex'),
    state TEXT NOT NULL CHECK (
        state IN (
            'prepared',
            'awaiting_delegate_approval',
            'running',
            'inspecting',
            'verifying',
            'awaiting_promotion_approval',
            'promoted',
            'completed_no_changes',
            'failed',
            'cancelled',
            'interrupted'
        )
    ),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    per_run_model TEXT,
    per_run_effort TEXT,
    resolved_model TEXT,
    resolved_effort TEXT,
    model_source TEXT NOT NULL CHECK (
        model_source IN (
            'provider_default',
            'personal',
            'project',
            'session',
            'per_run'
        )
    ),
    effort_source TEXT NOT NULL CHECK (
        effort_source IN (
            'provider_default',
            'personal',
            'project',
            'session',
            'per_run'
        )
    ),
    provider_model_status TEXT NOT NULL CHECK (
        provider_model_status IN ('not_reported', 'reported')
    ),
    provider_model_value TEXT,
    provider_effort_status TEXT NOT NULL CHECK (
        provider_effort_status IN ('not_reported', 'reported')
    ),
    provider_effort_value TEXT,
    provider_configuration_observed INTEGER NOT NULL DEFAULT 0 CHECK (
        provider_configuration_observed IN (0, 1)
    ),
    failure_code TEXT CHECK (
        failure_code IN (
            'authentication_required',
            'subscription_unavailable',
            'delegate_incompatible',
            'delegate_configuration_failed',
            'delegate_start_failed',
            'delegate_protocol_failed',
            'delegate_budget_exhausted',
            'stage_rejected',
            'proposal_rejected',
            'verification_failed',
            'stale_workspace',
            'promotion_failed'
        )
    ),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0),
    CHECK (
        per_run_model IS NULL
        OR (
            length(CAST(per_run_model AS BLOB)) BETWEEN 1 AND 128
            AND per_run_model NOT GLOB '*[^A-Za-z0-9_.:-]*'
            AND instr(per_run_model, char(0)) = 0
        )
    ),
    CHECK (
        per_run_effort IS NULL
        OR per_run_effort IN ('low', 'medium', 'high', 'xhigh', 'max', 'ultra')
    ),
    CHECK (
        resolved_model IS NULL
        OR (
            length(CAST(resolved_model AS BLOB)) BETWEEN 1 AND 128
            AND resolved_model NOT GLOB '*[^A-Za-z0-9_.:-]*'
            AND instr(resolved_model, char(0)) = 0
        )
    ),
    CHECK (
        resolved_effort IS NULL
        OR resolved_effort IN ('low', 'medium', 'high', 'xhigh', 'max', 'ultra')
    ),
    CHECK (
        provider_model_value IS NULL
        OR (
            length(CAST(provider_model_value AS BLOB)) BETWEEN 1 AND 128
            AND provider_model_value NOT GLOB '*[^A-Za-z0-9_.:-]*'
            AND instr(provider_model_value, char(0)) = 0
        )
    ),
    CHECK (
        provider_effort_value IS NULL
        OR provider_effort_value IN ('low', 'medium', 'high', 'xhigh', 'max', 'ultra')
    ),
    CHECK (
        (model_source = 'provider_default' AND resolved_model IS NULL)
        OR (model_source <> 'provider_default' AND resolved_model IS NOT NULL)
    ),
    CHECK (
        (effort_source = 'provider_default' AND resolved_effort IS NULL)
        OR (effort_source <> 'provider_default' AND resolved_effort IS NOT NULL)
    ),
    CHECK (
        (
            model_source = 'per_run'
            AND per_run_model IS NOT NULL
            AND resolved_model = per_run_model
        )
        OR (model_source <> 'per_run' AND per_run_model IS NULL)
    ),
    CHECK (
        (
            effort_source = 'per_run'
            AND per_run_effort IS NOT NULL
            AND resolved_effort = per_run_effort
        )
        OR (effort_source <> 'per_run' AND per_run_effort IS NULL)
    ),
    CHECK (
        (
            provider_model_status = 'not_reported'
            AND provider_model_value IS NULL
        )
        OR (
            provider_model_status = 'reported'
            AND provider_model_value IS NOT NULL
        )
    ),
    CHECK (
        (
            provider_effort_status = 'not_reported'
            AND provider_effort_value IS NULL
        )
        OR (
            provider_effort_status = 'reported'
            AND provider_effort_value IS NOT NULL
        )
    ),
    CHECK (
        provider_configuration_observed = 1
        OR (
            provider_model_status = 'not_reported'
            AND provider_model_value IS NULL
            AND provider_effort_status = 'not_reported'
            AND provider_effort_value IS NULL
        )
    ),
    CHECK (
        (state = 'failed' AND failure_code IS NOT NULL)
        OR (state <> 'failed' AND failure_code IS NULL)
    )
);

CREATE INDEX subscription_runs_by_session_state
    ON subscription_runs(session_id, state, created_at);

CREATE TABLE subscription_run_events (
    run_id TEXT NOT NULL REFERENCES subscription_runs(id) ON DELETE CASCADE,
    run_sequence INTEGER NOT NULL CHECK (run_sequence >= 1),
    event_id TEXT NOT NULL UNIQUE REFERENCES events(id) ON DELETE CASCADE,
    PRIMARY KEY (run_id, run_sequence)
);
