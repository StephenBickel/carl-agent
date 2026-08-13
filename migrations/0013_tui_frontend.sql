ALTER TABLE remote_codes RENAME TO remote_codes_v12;
ALTER TABLE frontend_deliveries RENAME TO frontend_deliveries_v12;
ALTER TABLE task_control_receipts RENAME TO task_control_receipts_v12;
ALTER TABLE frontend_sessions RENAME TO frontend_sessions_v12;

CREATE TABLE frontend_sessions (
    external_session_id TEXT PRIMARY KEY NOT NULL
        CHECK (length(external_session_id) BETWEEN 1 AND 128),
    frontend TEXT NOT NULL CHECK (frontend IN ('acp', 'buzz', 'tui')),
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
    updated_at TEXT NOT NULL,
    permission_profile TEXT NOT NULL DEFAULT 'approval'
        CHECK (permission_profile IN ('read_only', 'approval', 'full_access'))
);

INSERT INTO frontend_sessions (
    external_session_id, frontend, session_id, client_name, protocol_version,
    cwd, channel_id, provider_thread_id, permission_mode, created_at, updated_at,
    permission_profile
)
SELECT external_session_id, frontend, session_id, client_name, protocol_version,
       cwd, channel_id, provider_thread_id, permission_mode, created_at, updated_at,
       permission_profile
FROM frontend_sessions_v12;

DROP TABLE frontend_sessions_v12;

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

INSERT INTO remote_codes
SELECT * FROM remote_codes_v12;
DROP TABLE remote_codes_v12;
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

INSERT INTO frontend_deliveries
SELECT * FROM frontend_deliveries_v12;
DROP TABLE frontend_deliveries_v12;
CREATE INDEX frontend_deliveries_session_status
    ON frontend_deliveries(external_session_id, status, created_at);

CREATE TABLE task_control_receipts (
    external_session_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    task_id TEXT NOT NULL,
    method TEXT NOT NULL CHECK (method IN ('resume', 'cancel', 'steer')),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 64),
    state TEXT NOT NULL CHECK (state IN ('pending', 'completed')),
    starting_revision INTEGER NOT NULL CHECK (starting_revision >= 1),
    applied_revision INTEGER CHECK (applied_revision IS NULL OR applied_revision >= starting_revision),
    result_json TEXT CHECK (result_json IS NULL OR length(result_json) BETWEEN 2 AND 65536),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    failure_code INTEGER CHECK (failure_code IS NULL OR failure_code = -32602),
    CHECK (
        (state = 'pending' AND applied_revision IS NULL AND result_json IS NULL AND completed_at IS NULL)
        OR (state = 'completed' AND applied_revision IS NOT NULL AND result_json IS NOT NULL AND completed_at IS NOT NULL)
    ),
    PRIMARY KEY (external_session_id, idempotency_key),
    FOREIGN KEY (external_session_id)
        REFERENCES frontend_sessions(external_session_id) ON DELETE CASCADE,
    FOREIGN KEY (task_id) REFERENCES agent_tasks(id) ON DELETE CASCADE
);

INSERT INTO task_control_receipts
SELECT * FROM task_control_receipts_v12;
DROP TABLE task_control_receipts_v12;
