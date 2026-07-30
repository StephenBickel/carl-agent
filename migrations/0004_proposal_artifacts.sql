CREATE TABLE artifact_objects (
    id TEXT PRIMARY KEY NOT NULL CHECK (
        length(id) = 64
        AND id NOT GLOB '*[^0-9a-f]*'
        AND instr(id, char(0)) = 0
    ),
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    UNIQUE (id, byte_length)
);

CREATE INDEX artifact_objects_by_created_at
    ON artifact_objects(created_at, id);

CREATE TABLE subscription_run_baselines (
    run_id TEXT PRIMARY KEY NOT NULL
        REFERENCES subscription_runs(id) ON DELETE CASCADE,
    manifest_artifact_id TEXT NOT NULL
        REFERENCES artifact_objects(id) ON DELETE RESTRICT,
    manifest_digest TEXT NOT NULL CHECK (
        length(manifest_digest) = 64
        AND manifest_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(manifest_digest, char(0)) = 0
    ),
    source_preconditions_artifact_id TEXT NOT NULL
        REFERENCES artifact_objects(id) ON DELETE RESTRICT,
    source_preconditions_digest TEXT NOT NULL CHECK (
        length(source_preconditions_digest) = 64
        AND source_preconditions_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(source_preconditions_digest, char(0)) = 0
    ),
    entry_count INTEGER NOT NULL CHECK (
        entry_count BETWEEN 0 AND 100000
    ),
    total_bytes INTEGER NOT NULL CHECK (
        total_bytes BETWEEN 0 AND 104857600
    ),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    UNIQUE (run_id, manifest_artifact_id),
    UNIQUE (run_id, source_preconditions_artifact_id),
    CHECK (manifest_artifact_id = manifest_digest),
    CHECK (source_preconditions_artifact_id = source_preconditions_digest)
);

CREATE INDEX subscription_run_baselines_by_preconditions
    ON subscription_run_baselines(source_preconditions_artifact_id, run_id);

CREATE TABLE subscription_run_baseline_entries (
    run_id TEXT NOT NULL
        REFERENCES subscription_run_baselines(run_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (
        ordinal BETWEEN 0 AND 99999
    ),
    path TEXT NOT NULL CHECK (
        length(CAST(path AS BLOB)) BETWEEN 1 AND 4096
        AND instr(path, char(0)) = 0
        AND substr(path, 1, 1) <> '/'
        AND substr(path, 1, 1) <> char(92)
        AND substr(path, -1, 1) <> '/'
        AND instr(path, char(92)) = 0
        AND instr(path, '//') = 0
        AND instr('/' || path || '/', '/../') = 0
        AND instr('/' || path || '/', '/./') = 0
    ),
    byte_length INTEGER NOT NULL CHECK (
        byte_length BETWEEN 0 AND 1048576
    ),
    content_sha256 TEXT NOT NULL CHECK (
        length(content_sha256) = 64
        AND content_sha256 NOT GLOB '*[^0-9a-f]*'
        AND instr(content_sha256, char(0)) = 0
    ),
    content_artifact_id TEXT NOT NULL,
    identity_platform TEXT NOT NULL CHECK (
        identity_platform IN ('unix', 'windows')
    ),
    identity_a TEXT NOT NULL CHECK (
        length(CAST(identity_a AS BLOB)) BETWEEN 1 AND 128
        AND instr(identity_a, char(0)) = 0
    ),
    identity_b TEXT NOT NULL CHECK (
        length(CAST(identity_b AS BLOB)) BETWEEN 1 AND 128
        AND instr(identity_b, char(0)) = 0
    ),
    owner_id TEXT NOT NULL CHECK (
        length(CAST(owner_id AS BLOB)) BETWEEN 1 AND 256
        AND instr(owner_id, char(0)) = 0
    ),
    owner_mode INTEGER,
    PRIMARY KEY (run_id, ordinal),
    UNIQUE (run_id, path),
    UNIQUE (run_id, path, content_sha256),
    FOREIGN KEY (content_artifact_id, byte_length)
        REFERENCES artifact_objects(id, byte_length) ON DELETE RESTRICT,
    CHECK (content_artifact_id = content_sha256),
    CHECK (
        (
            identity_platform = 'unix'
            AND owner_mode IS NOT NULL
            AND owner_mode BETWEEN 0 AND 4095
        )
        OR (
            identity_platform = 'windows'
            AND owner_mode IS NULL
        )
    )
);

CREATE INDEX subscription_run_baseline_entries_by_object
    ON subscription_run_baseline_entries(content_artifact_id, run_id);

CREATE TABLE subscription_run_inspections (
    run_id TEXT PRIMARY KEY NOT NULL
        REFERENCES subscription_runs(id) ON DELETE CASCADE,
    outcome TEXT NOT NULL CHECK (
        outcome IN ('no_changes', 'exact_replacement')
    ),
    stage_manifest_digest TEXT NOT NULL CHECK (
        length(stage_manifest_digest) = 64
        AND stage_manifest_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(stage_manifest_digest, char(0)) = 0
    ),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    UNIQUE (run_id, outcome)
);

CREATE INDEX subscription_run_inspections_by_outcome
    ON subscription_run_inspections(outcome, created_at, run_id);

CREATE TABLE subscription_run_proposals (
    run_id TEXT PRIMARY KEY NOT NULL,
    outcome TEXT NOT NULL DEFAULT 'exact_replacement' CHECK (
        outcome = 'exact_replacement'
    ),
    proposal_artifact_id TEXT NOT NULL
        REFERENCES artifact_objects(id) ON DELETE RESTRICT,
    baseline_manifest_artifact_id TEXT NOT NULL,
    path TEXT NOT NULL CHECK (
        length(CAST(path AS BLOB)) BETWEEN 1 AND 4096
        AND instr(path, char(0)) = 0
        AND substr(path, 1, 1) <> '/'
        AND substr(path, 1, 1) <> char(92)
        AND substr(path, -1, 1) <> '/'
        AND instr(path, char(92)) = 0
        AND instr(path, '//') = 0
        AND instr('/' || path || '/', '/../') = 0
        AND instr('/' || path || '/', '/./') = 0
    ),
    expected_live_sha256 TEXT NOT NULL CHECK (
        length(expected_live_sha256) = 64
        AND expected_live_sha256 NOT GLOB '*[^0-9a-f]*'
        AND instr(expected_live_sha256, char(0)) = 0
    ),
    before_sha256 TEXT NOT NULL CHECK (
        length(before_sha256) = 64
        AND before_sha256 NOT GLOB '*[^0-9a-f]*'
        AND instr(before_sha256, char(0)) = 0
    ),
    after_sha256 TEXT NOT NULL CHECK (
        length(after_sha256) = 64
        AND after_sha256 NOT GLOB '*[^0-9a-f]*'
        AND instr(after_sha256, char(0)) = 0
    ),
    payload_sha256 TEXT NOT NULL CHECK (
        length(payload_sha256) = 64
        AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        AND instr(payload_sha256, char(0)) = 0
    ),
    payload_bytes INTEGER NOT NULL CHECK (
        payload_bytes BETWEEN 0 AND 1048576
    ),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    FOREIGN KEY (run_id, outcome)
        REFERENCES subscription_run_inspections(run_id, outcome)
        ON DELETE CASCADE,
    FOREIGN KEY (run_id, baseline_manifest_artifact_id)
        REFERENCES subscription_run_baselines(run_id, manifest_artifact_id)
        ON DELETE CASCADE,
    FOREIGN KEY (run_id, path, before_sha256)
        REFERENCES subscription_run_baseline_entries(run_id, path, content_sha256)
        ON DELETE CASCADE,
    FOREIGN KEY (payload_sha256, payload_bytes)
        REFERENCES artifact_objects(id, byte_length)
        ON DELETE RESTRICT,
    CHECK (expected_live_sha256 = before_sha256),
    CHECK (after_sha256 = payload_sha256)
);

CREATE INDEX subscription_run_proposals_by_artifact
    ON subscription_run_proposals(proposal_artifact_id, run_id);
