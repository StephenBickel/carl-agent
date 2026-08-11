CREATE TABLE service_command_receipts (
    idempotency_key TEXT PRIMARY KEY
        CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    command_digest TEXT NOT NULL
        CHECK (length(command_digest) = 64),
    command_kind TEXT NOT NULL
        CHECK (length(command_kind) BETWEEN 1 AND 32),
    state TEXT NOT NULL CHECK (state IN ('pending', 'completed')),
    result_json TEXT CHECK (
        result_json IS NULL OR length(CAST(result_json AS BLOB)) BETWEEN 1 AND 262144
    ),
    created_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK (
        (state = 'pending' AND result_json IS NULL AND completed_at IS NULL)
        OR (state = 'completed' AND result_json IS NOT NULL AND completed_at IS NOT NULL)
    )
) STRICT;

INSERT INTO service_command_receipts (
    idempotency_key, command_digest, command_kind, state,
    result_json, created_at, completed_at
)
SELECT idempotency_key, command_digest, 'legacy_start', 'completed',
       '{"type":"accepted","value":{"task_id":"' || task_id || '"}}',
       created_at, created_at
FROM service_task_receipts;

CREATE TABLE service_configuration_controls (
    task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL CHECK (length(control_id) = 64),
    event_sequence INTEGER NOT NULL CHECK (event_sequence > 0),
    PRIMARY KEY (task_id, control_id),
    UNIQUE (task_id, event_sequence)
) STRICT;

INSERT INTO service_configuration_controls (task_id, control_id, event_sequence)
SELECT task_id, pending_control_id, queued_sequence
FROM task_configuration_state
WHERE pending_control_id IS NOT NULL;
