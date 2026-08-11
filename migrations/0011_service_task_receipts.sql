CREATE TABLE service_task_receipts (
    idempotency_key TEXT PRIMARY KEY
        CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    command_digest TEXT NOT NULL
        CHECK (length(command_digest) = 64),
    task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX service_task_receipts_task
    ON service_task_receipts(task_id);
