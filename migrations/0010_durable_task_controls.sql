CREATE TABLE task_configuration_state (
    task_id TEXT PRIMARY KEY NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    active_model TEXT NOT NULL CHECK (
        length(active_model) BETWEEN 1 AND 128
        AND active_model NOT GLOB '*[^A-Za-z0-9_.:-]*'
    ),
    active_effort TEXT NOT NULL CHECK (
        active_effort IN ('low', 'medium', 'high', 'xhigh', 'max', 'ultra')
    ),
    active_permission_mode TEXT NOT NULL CHECK (
        active_permission_mode IN (
            'plan', 'default', 'acceptEdits', 'dontAsk', 'fullAccess', 'bypassPermissions'
        )
    ),
    effective_permission_mode TEXT NOT NULL CHECK (
        effective_permission_mode IN (
            'plan', 'default', 'acceptEdits', 'dontAsk', 'fullAccess', 'bypassPermissions'
        )
    ),
    pending_control_id TEXT CHECK (
        pending_control_id IS NULL OR length(pending_control_id) = 64
    ),
    pending_model TEXT CHECK (
        pending_model IS NULL OR (
            length(pending_model) BETWEEN 1 AND 128
            AND pending_model NOT GLOB '*[^A-Za-z0-9_.:-]*'
        )
    ),
    pending_effort TEXT CHECK (
        pending_effort IS NULL
        OR pending_effort IN ('low', 'medium', 'high', 'xhigh', 'max', 'ultra')
    ),
    pending_permission_mode TEXT CHECK (
        pending_permission_mode IS NULL
        OR pending_permission_mode IN (
            'plan', 'default', 'acceptEdits', 'dontAsk', 'fullAccess', 'bypassPermissions'
        )
    ),
    queued_sequence INTEGER CHECK (queued_sequence IS NULL OR queued_sequence > 0),
    applied_sequence INTEGER CHECK (applied_sequence IS NULL OR applied_sequence > 0),
    CHECK (
        (pending_control_id IS NULL AND pending_model IS NULL AND pending_effort IS NULL
            AND pending_permission_mode IS NULL AND queued_sequence IS NULL)
        OR
        (pending_control_id IS NOT NULL AND pending_model IS NOT NULL
            AND pending_effort IS NOT NULL AND pending_permission_mode IS NOT NULL
            AND queued_sequence IS NOT NULL)
    )
);

INSERT INTO task_configuration_state (
    task_id, active_model, active_effort, active_permission_mode,
    effective_permission_mode
)
SELECT id, model, effort, permission_mode, permission_mode
FROM agent_tasks;

CREATE TABLE task_control_markers (
    task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL CHECK (length(control_id) = 64),
    kind TEXT NOT NULL CHECK (kind IN ('resume', 'cancel')),
    event_sequence INTEGER NOT NULL CHECK (event_sequence > 0),
    created_at TEXT NOT NULL,
    PRIMARY KEY (task_id, control_id),
    UNIQUE (task_id, event_sequence)
);

ALTER TABLE task_control_receipts ADD COLUMN failure_code INTEGER
    CHECK (failure_code IS NULL OR failure_code = -32602);

CREATE TABLE task_epochs_v10 (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    objective TEXT NOT NULL CHECK (
        length(CAST(objective AS BLOB)) BETWEEN 1 AND 16384
        AND instr(objective, char(0)) = 0
    ),
    status TEXT NOT NULL CHECK (status IN ('active', 'finished', 'interrupted')),
    started_sequence INTEGER NOT NULL CHECK (started_sequence > 0),
    finished_sequence INTEGER CHECK (
        finished_sequence IS NULL OR finished_sequence > started_sequence
    ),
    report_digest TEXT CHECK (
        report_digest IS NULL
        OR length(CAST(report_digest AS BLOB)) BETWEEN 1 AND 128
    ),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0),
    UNIQUE(task_id, id),
    UNIQUE(task_id, started_sequence),
    CHECK (
        (status = 'active' AND finished_sequence IS NULL AND report_digest IS NULL)
        OR
        (status = 'finished' AND finished_sequence IS NOT NULL AND report_digest IS NOT NULL)
        OR
        (status = 'interrupted' AND finished_sequence IS NOT NULL AND report_digest IS NULL)
    )
);

INSERT INTO task_epochs_v10
SELECT epochs.id, epochs.task_id, epochs.objective,
       CASE
           WHEN interruptions.epoch_id IS NOT NULL THEN 'interrupted'
           ELSE epochs.status
       END,
       epochs.started_sequence,
       COALESCE(interruptions.event_sequence, epochs.finished_sequence),
       CASE
           WHEN interruptions.epoch_id IS NOT NULL THEN NULL
           ELSE epochs.report_digest
       END,
       epochs.created_at,
       COALESCE(interruptions.interrupted_at, epochs.updated_at)
FROM task_epochs AS epochs
LEFT JOIN task_epoch_interruptions AS interruptions
    ON interruptions.task_id = epochs.task_id
   AND interruptions.epoch_id = epochs.id;

DROP TABLE task_epochs;
ALTER TABLE task_epochs_v10 RENAME TO task_epochs;
