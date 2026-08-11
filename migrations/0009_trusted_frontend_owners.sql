ALTER TABLE frontend_sessions
    ADD COLUMN permission_profile TEXT NOT NULL DEFAULT 'approval'
        CHECK (permission_profile IN ('read_only', 'approval', 'full_access'));

UPDATE frontend_sessions
SET permission_profile = CASE permission_mode
    WHEN 'plan' THEN 'read_only'
    WHEN 'dontAsk' THEN 'read_only'
    WHEN 'bypassPermissions' THEN 'full_access'
    ELSE 'approval'
END;

ALTER TABLE task_steering ADD COLUMN control_id TEXT
    CHECK (control_id IS NULL OR length(control_id) = 64);

CREATE UNIQUE INDEX task_steering_control_id
    ON task_steering(task_id, control_id)
    WHERE control_id IS NOT NULL;

CREATE TABLE task_epoch_interruptions (
    task_id TEXT NOT NULL,
    epoch_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason = 'permission_tightening'),
    event_sequence INTEGER NOT NULL CHECK (event_sequence > 0),
    interrupted_at TEXT NOT NULL,
    PRIMARY KEY (task_id, epoch_id),
    FOREIGN KEY (task_id, epoch_id)
        REFERENCES task_epochs(task_id, id) ON DELETE CASCADE
);

CREATE TABLE trusted_frontend_owners (
    frontend TEXT NOT NULL CHECK (frontend IN ('acp', 'buzz')),
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
    channel_id TEXT CHECK (channel_id IS NULL OR length(channel_id) BETWEEN 1 AND 128),
    workspace_digest TEXT NOT NULL CHECK (length(workspace_digest) = 64),
    permission_mode TEXT NOT NULL CHECK (
        permission_mode IN ('plan','default','acceptEdits','dontAsk','bypassPermissions')
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (frontend, workspace_digest)
);

CREATE TABLE trusted_frontend_events (
    event_id TEXT PRIMARY KEY NOT NULL CHECK (length(event_id) = 64),
    frontend TEXT NOT NULL,
    workspace_digest TEXT NOT NULL CHECK (length(workspace_digest) = 64),
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
    channel_id TEXT NOT NULL CHECK (length(channel_id) BETWEEN 1 AND 128),
    admitted_at TEXT NOT NULL,
    FOREIGN KEY (frontend, workspace_digest)
        REFERENCES trusted_frontend_owners(frontend, workspace_digest) ON DELETE CASCADE
);

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
    CHECK (
        (state = 'pending' AND applied_revision IS NULL AND result_json IS NULL AND completed_at IS NULL)
        OR (state = 'completed' AND applied_revision IS NOT NULL AND result_json IS NOT NULL AND completed_at IS NOT NULL)
    ),
    PRIMARY KEY (external_session_id, idempotency_key),
    FOREIGN KEY (external_session_id)
        REFERENCES frontend_sessions(external_session_id) ON DELETE CASCADE,
    FOREIGN KEY (task_id) REFERENCES agent_tasks(id) ON DELETE CASCADE
);
