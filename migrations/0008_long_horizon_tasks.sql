CREATE TABLE agent_tasks (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (
        status IN (
            'queued', 'active', 'checkpointing', 'paused', 'blocked',
            'cancelling', 'cancelled', 'completing', 'completed', 'failed'
        )
    ),
    contract_json TEXT NOT NULL CHECK (
        length(CAST(contract_json AS BLOB)) BETWEEN 2 AND 4194304
        AND json_valid(contract_json)
        AND json_type(contract_json) = 'object'
    ),
    budget_json TEXT NOT NULL CHECK (
        length(CAST(budget_json AS BLOB)) BETWEEN 2 AND 4096
        AND json_valid(budget_json)
        AND json_type(budget_json) = 'object'
    ),
    snapshot_json TEXT NOT NULL CHECK (
        length(CAST(snapshot_json AS BLOB)) BETWEEN 2 AND 8388608
        AND json_valid(snapshot_json)
        AND json_type(snapshot_json) = 'object'
    ),
    canonical_workspace TEXT NOT NULL CHECK (
        length(CAST(canonical_workspace AS BLOB)) BETWEEN 1 AND 16384
        AND instr(canonical_workspace, char(0)) = 0
    ),
    provider TEXT NOT NULL DEFAULT 'codex' CHECK (provider = 'codex'),
    model TEXT NOT NULL CHECK (
        length(CAST(model AS BLOB)) BETWEEN 1 AND 128
        AND model NOT GLOB '*[^A-Za-z0-9_.:-]*'
        AND instr(model, char(0)) = 0
    ),
    effort TEXT NOT NULL CHECK (effort IN ('low', 'medium', 'high', 'xhigh', 'max', 'ultra')),
    permission_mode TEXT NOT NULL CHECK (
        permission_mode IN ('plan', 'default', 'acceptEdits', 'dontAsk', 'bypassPermissions')
    ),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    current_epoch_id TEXT REFERENCES task_epochs(id) ON DELETE SET NULL,
    latest_checkpoint_id TEXT REFERENCES task_checkpoints(id) ON DELETE SET NULL,
    provider_context TEXT CHECK (
        provider_context IS NULL
        OR length(CAST(provider_context AS BLOB)) BETWEEN 1 AND 128
    ),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0)
);

CREATE INDEX agent_tasks_resumable
    ON agent_tasks(status, updated_at, id);

CREATE TABLE task_epochs (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    objective TEXT NOT NULL CHECK (
        length(CAST(objective AS BLOB)) BETWEEN 1 AND 16384
        AND instr(objective, char(0)) = 0
    ),
    status TEXT NOT NULL CHECK (status IN ('active', 'finished')),
    started_sequence INTEGER NOT NULL CHECK (started_sequence > 0),
    finished_sequence INTEGER CHECK (finished_sequence IS NULL OR finished_sequence > started_sequence),
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
    )
);

CREATE TABLE task_operations (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    epoch_id TEXT NOT NULL,
    item_id TEXT NOT NULL CHECK (length(CAST(item_id AS BLOB)) BETWEEN 1 AND 128),
    effect_class TEXT NOT NULL CHECK (
        effect_class IN ('observation', 'idempotent_mutation', 'ambiguous_consequential')
    ),
    request_digest TEXT NOT NULL CHECK (
        length(CAST(request_digest AS BLOB)) BETWEEN 1 AND 128
    ),
    status TEXT NOT NULL CHECK (
        status IN (
            'intent_recorded', 'started', 'succeeded', 'failed',
            'cancelled', 'uncertain', 'reconciled'
        )
    ),
    intent_sequence INTEGER NOT NULL CHECK (intent_sequence > 0),
    last_transition_sequence INTEGER NOT NULL CHECK (last_transition_sequence >= intent_sequence),
    evidence_sequences_json TEXT NOT NULL DEFAULT '[]' CHECK (
        length(CAST(evidence_sequences_json AS BLOB)) BETWEEN 2 AND 8192
        AND json_valid(evidence_sequences_json)
        AND json_type(evidence_sequences_json) = 'array'
    ),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0),
    FOREIGN KEY (task_id, epoch_id) REFERENCES task_epochs(task_id, id) ON DELETE CASCADE,
    UNIQUE(task_id, intent_sequence)
);

CREATE INDEX task_operations_by_task_status
    ON task_operations(task_id, status, intent_sequence);

CREATE TABLE task_checkpoints (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    digest TEXT NOT NULL CHECK (length(CAST(digest AS BLOB)) BETWEEN 1 AND 128),
    event_sequence INTEGER NOT NULL CHECK (event_sequence > 0),
    checkpoint_json TEXT CHECK (
        checkpoint_json IS NULL
        OR (
            length(CAST(checkpoint_json AS BLOB)) BETWEEN 2 AND 8388608
            AND json_valid(checkpoint_json)
            AND json_type(checkpoint_json) = 'object'
        )
    ),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    UNIQUE(task_id, id),
    UNIQUE(task_id, event_sequence)
);

CREATE TABLE task_context_packages (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    checkpoint_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    event_sequence INTEGER NOT NULL CHECK (event_sequence > 0),
    package_json TEXT CHECK (
        package_json IS NULL
        OR (
            length(CAST(package_json AS BLOB)) BETWEEN 2 AND 8388608
            AND json_valid(package_json)
            AND json_type(package_json) = 'object'
        )
    ),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    FOREIGN KEY (task_id, checkpoint_id)
        REFERENCES task_checkpoints(task_id, id) ON DELETE CASCADE,
    UNIQUE(task_id, generation),
    UNIQUE(task_id, event_sequence)
);

CREATE TABLE task_steering (
    task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    steering_sequence INTEGER NOT NULL CHECK (steering_sequence >= 0),
    text_digest TEXT NOT NULL CHECK (length(CAST(text_digest AS BLOB)) BETWEEN 1 AND 128),
    event_sequence INTEGER NOT NULL CHECK (event_sequence > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    PRIMARY KEY (task_id, steering_sequence),
    UNIQUE(task_id, event_sequence)
);
