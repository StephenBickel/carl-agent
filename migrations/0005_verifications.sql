ALTER TABLE subscription_run_baselines
    ADD COLUMN directory_count INTEGER CHECK (
        directory_count IS NULL
        OR directory_count BETWEEN 0 AND 100000
    );

ALTER TABLE subscription_run_baselines
    ADD COLUMN directory_manifest_digest TEXT CHECK (
        directory_manifest_digest IS NULL
        OR (
            length(directory_manifest_digest) = 64
            AND directory_manifest_digest NOT GLOB '*[^0-9a-f]*'
            AND instr(directory_manifest_digest, char(0)) = 0
        )
    );

CREATE TABLE subscription_run_baseline_directories (
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
    PRIMARY KEY (run_id, ordinal),
    UNIQUE (run_id, path)
);

CREATE UNIQUE INDEX subscription_run_proposals_by_run_artifact
    ON subscription_run_proposals(run_id, proposal_artifact_id);

CREATE UNIQUE INDEX subscription_run_proposals_by_run_artifact_payload
    ON subscription_run_proposals(
        run_id, proposal_artifact_id, payload_sha256
    );

CREATE UNIQUE INDEX subscription_run_inspections_by_run_candidate
    ON subscription_run_inspections(run_id, outcome, stage_manifest_digest);

CREATE UNIQUE INDEX subscription_run_baselines_by_run_directory_manifest
    ON subscription_run_baselines(
        run_id, manifest_artifact_id, directory_manifest_digest
    );

CREATE TABLE subscription_run_verification_requests (
    id TEXT PRIMARY KEY NOT NULL CHECK (
        length(id) = 36
        AND substr(id, 9, 1) = '-'
        AND substr(id, 14, 1) = '-'
        AND substr(id, 19, 1) = '-'
        AND substr(id, 24, 1) = '-'
        AND replace(id, '-', '') NOT GLOB '*[^0-9a-f]*'
        AND instr(id, char(0)) = 0
    ),
    run_id TEXT NOT NULL UNIQUE,
    started_run_sequence INTEGER NOT NULL CHECK (
        started_run_sequence >= 1
    ),
    inspection_outcome TEXT NOT NULL DEFAULT 'exact_replacement' CHECK (
        inspection_outcome = 'exact_replacement'
    ),
    baseline_manifest_artifact_id TEXT NOT NULL CHECK (
        length(baseline_manifest_artifact_id) = 64
        AND baseline_manifest_artifact_id NOT GLOB '*[^0-9a-f]*'
        AND instr(baseline_manifest_artifact_id, char(0)) = 0
    ),
    source_preconditions_artifact_id TEXT NOT NULL CHECK (
        length(source_preconditions_artifact_id) = 64
        AND source_preconditions_artifact_id NOT GLOB '*[^0-9a-f]*'
        AND instr(source_preconditions_artifact_id, char(0)) = 0
    ),
    source_preconditions_digest TEXT NOT NULL CHECK (
        length(source_preconditions_digest) = 64
        AND source_preconditions_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(source_preconditions_digest, char(0)) = 0
    ),
    baseline_directory_manifest_digest TEXT NOT NULL CHECK (
        length(baseline_directory_manifest_digest) = 64
        AND baseline_directory_manifest_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(baseline_directory_manifest_digest, char(0)) = 0
    ),
    proposal_artifact_id TEXT NOT NULL CHECK (
        length(proposal_artifact_id) = 64
        AND proposal_artifact_id NOT GLOB '*[^0-9a-f]*'
        AND instr(proposal_artifact_id, char(0)) = 0
    ),
    payload_artifact_id TEXT NOT NULL CHECK (
        length(payload_artifact_id) = 64
        AND payload_artifact_id NOT GLOB '*[^0-9a-f]*'
        AND instr(payload_artifact_id, char(0)) = 0
    ),
    candidate_manifest_digest TEXT NOT NULL CHECK (
        length(candidate_manifest_digest) = 64
        AND candidate_manifest_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(candidate_manifest_digest, char(0)) = 0
    ),
    executable_path TEXT NOT NULL CHECK (
        length(CAST(executable_path AS BLOB)) BETWEEN 1 AND 4096
        AND instr(executable_path, char(0)) = 0
    ),
    executable_metadata_risk TEXT NOT NULL CHECK (
        executable_metadata_risk IN (
            'none',
            'group_writable_install_directory'
        )
    ),
    executable_platform_identity BLOB NOT NULL CHECK (
        typeof(executable_platform_identity) = 'blob'
        AND length(executable_platform_identity) BETWEEN 1 AND 128
    ),
    executable_byte_length INTEGER NOT NULL CHECK (
        executable_byte_length BETWEEN 1 AND 536870912
    ),
    executable_content_sha256 TEXT NOT NULL CHECK (
        length(executable_content_sha256) = 64
        AND executable_content_sha256 NOT GLOB '*[^0-9a-f]*'
        AND instr(executable_content_sha256, char(0)) = 0
    ),
    executable_attestation_digest TEXT NOT NULL CHECK (
        length(executable_attestation_digest) = 64
        AND executable_attestation_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(executable_attestation_digest, char(0)) = 0
    ),
    verification_spec_digest TEXT NOT NULL CHECK (
        length(verification_spec_digest) = 64
        AND verification_spec_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(verification_spec_digest, char(0)) = 0
    ),
    request_digest TEXT NOT NULL UNIQUE CHECK (
        length(request_digest) = 64
        AND request_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(request_digest, char(0)) = 0
    ),
    argv_digest TEXT NOT NULL CHECK (
        length(argv_digest) = 64
        AND argv_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(argv_digest, char(0)) = 0
    ),
    environment_profile TEXT NOT NULL CHECK (
        environment_profile = 'credential_free_v1'
    ),
    execution_timeout_nanos INTEGER NOT NULL CHECK (
        execution_timeout_nanos BETWEEN 1 AND 3600000000000
    ),
    max_output_bytes INTEGER NOT NULL CHECK (
        max_output_bytes BETWEEN 1 AND 1048576
    ),
    graceful_shutdown_timeout_nanos INTEGER NOT NULL CHECK (
        graceful_shutdown_timeout_nanos BETWEEN 1 AND 30000000000
    ),
    forced_shutdown_timeout_nanos INTEGER NOT NULL CHECK (
        forced_shutdown_timeout_nanos BETWEEN 1 AND 30000000000
    ),
    poll_interval_nanos INTEGER NOT NULL CHECK (
        poll_interval_nanos BETWEEN 1 AND 1000000000
    ),
    argv_count INTEGER NOT NULL CHECK (
        argv_count BETWEEN 0 AND 128
    ),
    argv_bytes INTEGER NOT NULL CHECK (
        argv_bytes BETWEEN 0 AND 32768
    ),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    UNIQUE (
        id, run_id, request_digest, candidate_manifest_digest,
        baseline_directory_manifest_digest, executable_attestation_digest,
        max_output_bytes
    ),
    UNIQUE (run_id, started_run_sequence),
    FOREIGN KEY (run_id, baseline_manifest_artifact_id)
        REFERENCES subscription_run_baselines(run_id, manifest_artifact_id)
        ON DELETE CASCADE,
    FOREIGN KEY (run_id, source_preconditions_artifact_id)
        REFERENCES subscription_run_baselines(
            run_id, source_preconditions_artifact_id
        )
        ON DELETE CASCADE,
    FOREIGN KEY (
        run_id, baseline_manifest_artifact_id,
        baseline_directory_manifest_digest
    )
        REFERENCES subscription_run_baselines(
            run_id, manifest_artifact_id, directory_manifest_digest
        )
        ON DELETE CASCADE,
    FOREIGN KEY (run_id, proposal_artifact_id, payload_artifact_id)
        REFERENCES subscription_run_proposals(
            run_id, proposal_artifact_id, payload_sha256
        )
        ON DELETE CASCADE,
    FOREIGN KEY (run_id, inspection_outcome, candidate_manifest_digest)
        REFERENCES subscription_run_inspections(
            run_id, outcome, stage_manifest_digest
        )
        ON DELETE CASCADE,
    CHECK (source_preconditions_artifact_id = source_preconditions_digest),
    CHECK (poll_interval_nanos <= graceful_shutdown_timeout_nanos),
    CHECK (poll_interval_nanos <= forced_shutdown_timeout_nanos)
);

CREATE INDEX subscription_run_verification_requests_by_proposal
    ON subscription_run_verification_requests(proposal_artifact_id, run_id);

CREATE TABLE subscription_run_verification_argv (
    verification_id TEXT NOT NULL
        REFERENCES subscription_run_verification_requests(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (
        ordinal BETWEEN 0 AND 127
    ),
    value TEXT NOT NULL CHECK (
        length(CAST(value AS BLOB)) BETWEEN 0 AND 4096
        AND instr(value, char(0)) = 0
    ),
    PRIMARY KEY (verification_id, ordinal)
);

CREATE TABLE subscription_run_verification_results (
    verification_id TEXT PRIMARY KEY NOT NULL,
    run_id TEXT NOT NULL UNIQUE,
    completed_run_sequence INTEGER NOT NULL CHECK (
        completed_run_sequence >= 1
    ),
    request_digest TEXT NOT NULL CHECK (
        length(request_digest) = 64
        AND request_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(request_digest, char(0)) = 0
    ),
    expected_candidate_manifest_digest TEXT NOT NULL CHECK (
        length(expected_candidate_manifest_digest) = 64
        AND expected_candidate_manifest_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(expected_candidate_manifest_digest, char(0)) = 0
    ),
    expected_directory_manifest_digest TEXT NOT NULL CHECK (
        length(expected_directory_manifest_digest) = 64
        AND expected_directory_manifest_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(expected_directory_manifest_digest, char(0)) = 0
    ),
    outcome TEXT NOT NULL CHECK (
        outcome IN (
            'passed',
            'cancelled',
            'timed_out',
            'output_limit_exceeded',
            'nonzero_exit',
            'candidate_modified',
            'diagnostic_rejected',
            'supervisor_failed'
        )
    ),
    exit_code INTEGER CHECK (
        exit_code BETWEEN -2147483648 AND 2147483647
    ),
    observed_candidate_manifest_digest TEXT CHECK (
        observed_candidate_manifest_digest IS NULL
        OR (
            length(observed_candidate_manifest_digest) = 64
            AND observed_candidate_manifest_digest NOT GLOB '*[^0-9a-f]*'
            AND instr(observed_candidate_manifest_digest, char(0)) = 0
        )
    ),
    observed_directory_manifest_digest TEXT CHECK (
        observed_directory_manifest_digest IS NULL
        OR (
            length(observed_directory_manifest_digest) = 64
            AND observed_directory_manifest_digest NOT GLOB '*[^0-9a-f]*'
            AND instr(observed_directory_manifest_digest, char(0)) = 0
        )
    ),
    executable_attestation_evidence TEXT NOT NULL CHECK (
        length(CAST(executable_attestation_evidence AS BLOB))
            BETWEEN 1 AND 16384
        AND executable_attestation_evidence NOT GLOB '*[^0-9a-f]*'
        AND instr(executable_attestation_evidence, char(0)) = 0
    ),
    executable_attestation_digest TEXT NOT NULL CHECK (
        length(executable_attestation_digest) = 64
        AND executable_attestation_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(executable_attestation_digest, char(0)) = 0
    ),
    stdout_text TEXT NOT NULL CHECK (
        instr(stdout_text, char(0)) = 0
    ),
    stdout_bytes INTEGER NOT NULL CHECK (
        stdout_bytes BETWEEN 0 AND 1048576
        AND stdout_bytes = length(CAST(stdout_text AS BLOB))
    ),
    stdout_digest TEXT NOT NULL CHECK (
        length(stdout_digest) = 64
        AND stdout_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(stdout_digest, char(0)) = 0
    ),
    stderr_text TEXT NOT NULL CHECK (
        instr(stderr_text, char(0)) = 0
    ),
    stderr_bytes INTEGER NOT NULL CHECK (
        stderr_bytes BETWEEN 0 AND 1048576
        AND stderr_bytes = length(CAST(stderr_text AS BLOB))
    ),
    stderr_digest TEXT NOT NULL CHECK (
        length(stderr_digest) = 64
        AND stderr_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(stderr_digest, char(0)) = 0
    ),
    max_output_bytes INTEGER NOT NULL CHECK (
        max_output_bytes BETWEEN 1 AND 1048576
    ),
    duration_nanos INTEGER NOT NULL CHECK (
        duration_nanos BETWEEN 0 AND 3691000000000
    ),
    result_digest TEXT NOT NULL UNIQUE CHECK (
        length(result_digest) = 64
        AND result_digest NOT GLOB '*[^0-9a-f]*'
        AND instr(result_digest, char(0)) = 0
    ),
    completed_at TEXT NOT NULL CHECK (length(completed_at) > 0),
    UNIQUE (run_id, completed_run_sequence),
    FOREIGN KEY (
        verification_id, run_id, request_digest,
        expected_candidate_manifest_digest,
        expected_directory_manifest_digest, executable_attestation_digest,
        max_output_bytes
    )
        REFERENCES subscription_run_verification_requests(
            id, run_id, request_digest,
            candidate_manifest_digest,
            baseline_directory_manifest_digest, executable_attestation_digest,
            max_output_bytes
        )
        ON DELETE CASCADE,
    CHECK (stdout_bytes + stderr_bytes <= max_output_bytes),
    CHECK (
        outcome <> 'passed'
        OR (
            exit_code = 0
            AND observed_candidate_manifest_digest =
                expected_candidate_manifest_digest
            AND observed_directory_manifest_digest =
                expected_directory_manifest_digest
        )
    ),
    CHECK (
        outcome <> 'nonzero_exit'
        OR (exit_code IS NOT NULL AND exit_code <> 0)
    )
);

CREATE TRIGGER subscription_run_verification_requests_immutable
BEFORE UPDATE ON subscription_run_verification_requests
BEGIN
    SELECT RAISE(ABORT, 'verification requests are immutable');
END;

CREATE TRIGGER subscription_run_baseline_requires_directory_manifest
BEFORE INSERT ON subscription_run_baselines
WHEN NEW.directory_count IS NULL OR NEW.directory_manifest_digest IS NULL
BEGIN
    SELECT RAISE(ABORT, 'baseline directory topology is required');
END;

CREATE TRIGGER subscription_run_verification_argv_immutable
BEFORE UPDATE ON subscription_run_verification_argv
BEGIN
    SELECT RAISE(ABORT, 'verification argv is immutable');
END;

CREATE TRIGGER subscription_run_verification_results_immutable
BEFORE UPDATE ON subscription_run_verification_results
BEGIN
    SELECT RAISE(ABORT, 'verification results are immutable');
END;

CREATE TRIGGER subscription_run_verification_request_requires_inspecting
BEFORE INSERT ON subscription_run_verification_requests
WHEN NOT EXISTS (
    SELECT 1
    FROM subscription_runs
    WHERE id = NEW.run_id AND state = 'inspecting'
)
BEGIN
    SELECT RAISE(ABORT, 'verification request requires an inspecting run');
END;

CREATE TRIGGER subscription_run_verification_result_requires_verifying
BEFORE INSERT ON subscription_run_verification_results
WHEN NOT EXISTS (
    SELECT 1
    FROM subscription_runs
    WHERE id = NEW.run_id AND state = 'verifying'
)
BEGIN
    SELECT RAISE(ABORT, 'verification result requires a verifying run');
END;

CREATE TRIGGER subscription_run_entering_verifying_requires_request
BEFORE UPDATE OF state ON subscription_runs
WHEN NEW.state = 'verifying'
    AND OLD.state <> 'verifying'
    AND NOT EXISTS (
        SELECT 1
        FROM subscription_run_verification_requests
        WHERE run_id = NEW.id
          AND started_run_sequence = NEW.revision
    )
BEGIN
    SELECT RAISE(ABORT, 'verifying state requires a verification request');
END;

CREATE TRIGGER subscription_run_awaiting_promotion_requires_passed_verification
BEFORE UPDATE OF state ON subscription_runs
WHEN NEW.state = 'awaiting_promotion_approval'
    AND OLD.state <> 'awaiting_promotion_approval'
    AND NOT EXISTS (
        SELECT 1
        FROM subscription_run_verification_results
        WHERE run_id = NEW.id
          AND completed_run_sequence = NEW.revision
          AND outcome = 'passed'
    )
BEGIN
    SELECT RAISE(
        ABORT,
        'promotion approval state requires a passed verification'
    );
END;

CREATE TRIGGER subscription_run_verification_terminal_requires_result
BEFORE UPDATE OF state ON subscription_runs
WHEN OLD.state = 'verifying'
    AND NEW.state IN ('failed', 'cancelled')
    AND NOT EXISTS (
        SELECT 1
        FROM subscription_run_verification_results
        WHERE run_id = NEW.id
          AND completed_run_sequence = NEW.revision
          AND (
              (NEW.state = 'cancelled' AND outcome = 'cancelled')
              OR (
                  NEW.state = 'failed'
                  AND outcome NOT IN ('passed', 'cancelled')
              )
          )
    )
BEGIN
    SELECT RAISE(
        ABORT,
        'terminal verification state requires its committed result'
    );
END;
