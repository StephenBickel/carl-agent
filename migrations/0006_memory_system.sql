ALTER TABLE memories RENAME TO legacy_memories;

CREATE TABLE memories (
    id TEXT PRIMARY KEY NOT NULL,
    owner_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('global', 'workspace', 'session')),
    scope_key TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('profile', 'preference', 'fact', 'goal', 'episode')),
    memory_key TEXT NOT NULL,
    content TEXT NOT NULL,
    provenance TEXT NOT NULL,
    importance INTEGER NOT NULL CHECK (importance BETWEEN 0 AND 100),
    revision INTEGER NOT NULL CHECK (revision >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT,
    CHECK (
        (scope_kind = 'global' AND scope_key = '*') OR
        (scope_kind IN ('workspace', 'session') AND length(scope_key) > 0)
    ),
    UNIQUE (owner_id, agent_id, scope_kind, scope_key, kind, memory_key)
);

INSERT INTO memories (
    id, owner_id, agent_id, scope_kind, scope_key, kind, memory_key,
    content, provenance, importance, revision, created_at, updated_at, expires_at
)
SELECT
    id, 'local-owner', 'carl', 'global', '*', 'fact', 'legacy-' || id,
    content, provenance, 50, 1, created_at, created_at, NULL
FROM legacy_memories
WHERE kind = 'explicit' AND state = 'active';

DROP TABLE legacy_memories;

CREATE INDEX memories_by_partition_scope
    ON memories(owner_id, agent_id, scope_kind, scope_key, updated_at DESC);

CREATE INDEX memories_by_partition_expiration
    ON memories(owner_id, agent_id, expires_at)
    WHERE expires_at IS NOT NULL;

CREATE TABLE memory_settings (
    owner_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    max_context_items INTEGER NOT NULL CHECK (max_context_items BETWEEN 1 AND 32),
    context_bytes INTEGER NOT NULL CHECK (context_bytes BETWEEN 256 AND 65536),
    max_memories INTEGER NOT NULL CHECK (max_memories BETWEEN 1 AND 5000),
    max_storage_bytes INTEGER NOT NULL CHECK (max_storage_bytes BETWEEN 64 AND 67108864),
    episode_ttl_days INTEGER NOT NULL CHECK (episode_ttl_days BETWEEN 1 AND 3650),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (owner_id, agent_id)
);

CREATE TABLE memory_proposals (
    id TEXT PRIMARY KEY NOT NULL,
    owner_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('global', 'workspace', 'session')),
    scope_key TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('profile', 'preference', 'fact', 'goal', 'episode')),
    memory_key TEXT NOT NULL,
    content TEXT NOT NULL,
    provenance TEXT NOT NULL,
    importance INTEGER NOT NULL CHECK (importance BETWEEN 0 AND 100),
    memory_expires_at TEXT,
    origin TEXT NOT NULL CHECK (origin IN ('owner_input', 'verified_episode')),
    source_session_id TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    CHECK (
        (scope_kind = 'global' AND scope_key = '*') OR
        (scope_kind IN ('workspace', 'session') AND length(scope_key) > 0)
    )
);

CREATE INDEX memory_proposals_by_partition_expiration
    ON memory_proposals(owner_id, agent_id, expires_at);
