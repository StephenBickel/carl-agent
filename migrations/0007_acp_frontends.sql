CREATE TABLE frontend_sessions (
    external_session_id TEXT PRIMARY KEY NOT NULL
        CHECK (length(external_session_id) BETWEEN 1 AND 128),
    frontend TEXT NOT NULL CHECK (frontend IN ('acp', 'buzz')),
    session_id TEXT NOT NULL UNIQUE REFERENCES sessions(id) ON DELETE CASCADE,
    client_name TEXT NOT NULL CHECK (length(client_name) BETWEEN 1 AND 128),
    protocol_version INTEGER NOT NULL CHECK (protocol_version IN (1, 2)),
    cwd TEXT NOT NULL CHECK (length(cwd) BETWEEN 1 AND 32768),
    channel_id TEXT CHECK (channel_id IS NULL OR length(channel_id) BETWEEN 1 AND 128),
    provider_thread_id TEXT
        CHECK (provider_thread_id IS NULL OR length(provider_thread_id) BETWEEN 1 AND 128),
    permission_mode TEXT NOT NULL
        CHECK (permission_mode IN ('plan','default','acceptEdits','dontAsk','bypassPermissions')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX frontend_sessions_stable_channel
    ON frontend_sessions(frontend, channel_id, cwd)
    WHERE channel_id IS NOT NULL;

CREATE TABLE remote_codes (
    code_digest TEXT PRIMARY KEY NOT NULL CHECK (length(code_digest) = 64),
    kind TEXT NOT NULL CHECK (kind IN ('approval','bypass_confirmation')),
    external_session_id TEXT NOT NULL
        REFERENCES frontend_sessions(external_session_id) ON DELETE CASCADE,
    approval_id TEXT REFERENCES bound_approvals(id) ON DELETE CASCADE,
    provider_request_id TEXT
        CHECK (provider_request_id IS NULL OR length(provider_request_id) BETWEEN 1 AND 128),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    CHECK (
        (kind = 'approval' AND approval_id IS NOT NULL AND provider_request_id IS NOT NULL)
        OR
        (kind = 'bypass_confirmation' AND approval_id IS NULL AND provider_request_id IS NULL)
    )
);

CREATE INDEX remote_codes_external_session
    ON remote_codes(external_session_id, kind, expires_at);

CREATE TABLE frontend_deliveries (
    action_digest TEXT PRIMARY KEY NOT NULL CHECK (length(action_digest) = 64),
    external_session_id TEXT NOT NULL
        REFERENCES frontend_sessions(external_session_id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('message', 'diff')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'delivered', 'failed', 'uncertain')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX frontend_deliveries_session_status
    ON frontend_deliveries(external_session_id, status, created_at);
