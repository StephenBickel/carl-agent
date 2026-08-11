use std::collections::BTreeMap;
use std::error::Error;

use carl::runtime::task::{
    CanonicalCheckpoint, CheckpointId, ClauseEvidence, ClauseStatus, CompletionClause,
    CompletionContract, DecisionRecord, EffectClass, EpochDisposition, EvidenceRef,
    ExactIdentifier, OperationCheckpoint, OperationEvidence, OperationId, OperationStatus,
    ProcessCheckpoint, ProgressAssessment, ProviderCheckpoint, RecoveryAttempt,
    RecoveryAttemptOutcome, RecoveryStrategy, ReportErrorCode, RepositoryCheckpoint, TaskId,
    WorkEvidence, assess_progress, assess_progress_with_recovery_attempts, decide_completion,
    parse_epoch_report, recovery_attempt_fingerprint,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).unwrap()
}

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn report(disposition: &str, clauses: &str) -> String {
    format!(
        "<carl-epoch-report>{{\"schema_version\":1,\"disposition\":\"{disposition}\",\"summary\":\"Regression reproduced\",\"next_objective\":\"Implement the fix\",\"clause_evidence\":[{clauses}],\"exact_identifiers\":[\"parser::decode\"]}}</carl-epoch-report>"
    )
}

fn checkpoint(operation_id: OperationId, artifact_digest: String) -> CanonicalCheckpoint {
    CanonicalCheckpoint {
        schema_version: 1,
        checkpoint_id: CheckpointId::from_uuid(uuid("11111111-1111-4111-8111-111111111111")),
        task_id: TaskId::from_uuid(uuid("22222222-2222-4222-8222-222222222222")),
        contract: CompletionContract {
            version: 1,
            goal: "Fix the parser".to_owned(),
            constraints: Vec::new(),
            clauses: vec![CompletionClause {
                id: "parser-fixed".to_owned(),
                description: "The parser decodes the input".to_owned(),
                required: true,
                status: ClauseStatus::Pending,
                evidence: Vec::new(),
            }],
        },
        completed_work: vec![WorkEvidence {
            summary: "Canonical artifact".to_owned(),
            event_sequences: vec![7],
            artifact_digests: vec![artifact_digest.clone()],
        }],
        decisions: vec![DecisionRecord {
            id: "decision-1".to_owned(),
            decision: "repair".to_owned(),
            rationale: "evidence".to_owned(),
        }],
        exact_identifiers: vec![ExactIdentifier {
            kind: "symbol".to_owned(),
            value: "parser::decode".to_owned(),
        }],
        operations: vec![OperationCheckpoint {
            operation_id,
            status: OperationStatus::Succeeded,
            effect_class: EffectClass::AmbiguousConsequential,
            request_digest: digest(b"request"),
            evidence_sequences: vec![7],
        }],
        repository: RepositoryCheckpoint {
            workspace_digest: digest(b"workspace"),
            git_head: None,
            git_status_digest: None,
            diff_artifact_digest: Some(artifact_digest),
            file_hashes: BTreeMap::from([("src/parser.rs".to_owned(), digest(b"parser"))]),
        },
        running_processes: Vec::<ProcessCheckpoint>::new(),
        pending_approval_digests: Vec::new(),
        pending_steering_digests: Vec::new(),
        uncertain_delivery_digests: Vec::new(),
        verification: vec![ClauseEvidence {
            clause_id: "parser-fixed".to_owned(),
            evidence: Vec::new(),
        }],
        next_objective: "Implement the fix".to_owned(),
        blockers: Vec::new(),
        provider: ProviderCheckpoint {
            provider: "provider-a".to_owned(),
            model: "model-a".to_owned(),
            effort: "high".to_owned(),
            context_id: Some("ctx-a".to_owned()),
            observed_total_tokens: Some(42),
            observed_context_window: Some(128),
        },
        compaction_generation: 0,
        source_sequence_start: 1,
        source_sequence_end: 8,
        previous_digest: None,
    }
}

#[test]
fn parses_one_final_epoch_report_block() -> TestResult {
    let parsed = parse_epoch_report(&format!(
        "provider transcript\n{}\n",
        report("continue", "")
    ))?;
    assert_eq!(parsed.schema_version, 1);
    assert_eq!(parsed.disposition, EpochDisposition::Continue);
    assert_eq!(parsed.next_objective.as_deref(), Some("Implement the fix"));
    Ok(())
}

#[test]
fn rejects_ambiguous_or_unbounded_epoch_reports() {
    let valid = report("continue", "");
    for output in [
        format!("{valid}{valid}"),
        format!("{valid}\n<carl-epoch-report>later"),
        format!("{valid}\nprovider appended report-like text"),
        "<carl-epoch-report>{\"schema_version\":1,\"disposition\":\"continue\",\"summary\":\"x\",\"next_objective\":\"next\",\"clause_evidence\":[],\"exact_identifiers\":[],\"unknown\":true}</carl-epoch-report>".to_owned(),
        "x".repeat(64 * 1024 + 1),
    ] {
        assert_eq!(
            parse_epoch_report(&output).unwrap_err().code(),
            ReportErrorCode::InvalidReport
        );
    }
}

#[test]
fn completion_requires_normalized_successful_command_evidence() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let artifact = digest(b"diff");
    let checkpoint = checkpoint(operation_id, artifact);
    let parsed = parse_epoch_report(&report(
        "complete",
        &format!(
            "{{\"clause_id\":\"parser-fixed\",\"operation_ids\":[\"{operation_id}\"],\"event_sequences\":[7],\"artifact_digests\":[]}}"
        ),
    ))?;

    let completion = decide_completion(
        &parsed,
        &checkpoint,
        &[OperationEvidence::Command {
            operation_id,
            completed: true,
            exit_code: Some(0),
        }],
    )?;
    assert!(matches!(
        completion,
        carl::runtime::task::CompletionDecision::Complete
    ));

    assert_eq!(
        decide_completion(
            &parsed,
            &checkpoint,
            &[OperationEvidence::Command {
                operation_id,
                completed: true,
                exit_code: Some(1),
            }],
        )
        .unwrap_err()
        .code(),
        ReportErrorCode::InsufficientEvidence
    );
    Ok(())
}

#[test]
fn rejects_duplicate_operation_evidence_claims() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let checkpoint = checkpoint(operation_id, digest(b"diff"));
    let parsed = parse_epoch_report(&report(
        "complete",
        &format!(
            "{{\"clause_id\":\"parser-fixed\",\"operation_ids\":[\"{operation_id}\",\"{operation_id}\"],\"event_sequences\":[7],\"artifact_digests\":[]}}"
        ),
    ))?;
    assert_eq!(
        decide_completion(
            &parsed,
            &checkpoint,
            &[OperationEvidence::Command {
                operation_id,
                completed: true,
                exit_code: Some(0),
            }],
        )
        .unwrap_err()
        .code(),
        ReportErrorCode::InvalidReport
    );
    Ok(())
}

#[test]
fn rejects_unknown_clause_or_operation_claims() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let checkpoint = checkpoint(operation_id, digest(b"diff"));
    let parsed = parse_epoch_report(&report(
        "continue",
        &format!(
            "{{\"clause_id\":\"unknown\",\"operation_ids\":[\"{operation_id}\"],\"event_sequences\":[7],\"artifact_digests\":[]}}"
        ),
    ))?;
    assert_eq!(
        decide_completion(&parsed, &checkpoint, &[])
            .unwrap_err()
            .code(),
        ReportErrorCode::UnknownClause
    );
    let unknown_operation = OperationId::from_uuid(uuid("44444444-4444-4444-8444-444444444444"));
    let parsed = parse_epoch_report(&report(
        "continue",
        &format!(
            "{{\"clause_id\":\"parser-fixed\",\"operation_ids\":[\"{unknown_operation}\"],\"event_sequences\":[7],\"artifact_digests\":[]}}"
        ),
    ))?;
    assert_eq!(
        decide_completion(&parsed, &checkpoint, &[])
            .unwrap_err()
            .code(),
        ReportErrorCode::UnknownOperation
    );
    Ok(())
}

#[test]
fn completion_requires_a_matching_canonical_file_artifact() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let artifact = digest(b"diff");
    let mut checkpoint = checkpoint(operation_id, artifact.clone());
    checkpoint.operations[0].effect_class = EffectClass::IdempotentMutation;
    let parsed = parse_epoch_report(&report(
        "complete",
        &format!(
            "{{\"clause_id\":\"parser-fixed\",\"operation_ids\":[\"{operation_id}\"],\"event_sequences\":[7],\"artifact_digests\":[\"{artifact}\"]}}"
        ),
    ))?;
    assert!(matches!(
        decide_completion(
            &parsed,
            &checkpoint,
            &[OperationEvidence::FileChange {
                operation_id,
                completed: true,
                artifact_digests: vec![artifact.clone()],
            }],
        )?,
        carl::runtime::task::CompletionDecision::Complete
    ));
    assert_eq!(
        decide_completion(
            &parsed,
            &checkpoint,
            &[OperationEvidence::FileChange {
                operation_id,
                completed: true,
                artifact_digests: Vec::new(),
            }],
        )
        .unwrap_err()
        .code(),
        ReportErrorCode::InsufficientEvidence
    );
    Ok(())
}

#[test]
fn fingerprints_carl_owned_state_not_provider_metadata_or_prose() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let artifact = digest(b"diff");
    let checkpoint = checkpoint(operation_id, artifact);
    let first_report = parse_epoch_report(&report("continue", ""))?;
    let mut second_report = first_report.clone();
    second_report.summary = "Provider chose different prose".to_owned();
    let first = assess_progress(&checkpoint, &first_report, &[])?;
    let second = assess_progress(&checkpoint, &second_report, &[])?;
    assert_eq!(first.fingerprint, second.fingerprint);
    Ok(())
}

#[test]
fn fingerprints_verification_outcomes_in_canonical_order() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let artifact = digest(b"diff");
    let mut first = checkpoint(operation_id, artifact.clone());
    let mut second = checkpoint(operation_id, artifact);
    let second_clause = CompletionClause {
        id: "repository-clean".to_owned(),
        description: "The repository is clean".to_owned(),
        required: false,
        status: ClauseStatus::Failed,
        evidence: Vec::new(),
    };
    first.contract.clauses.push(second_clause.clone());
    second.contract.clauses.insert(0, second_clause);
    let report = parse_epoch_report(&report("continue", ""))?;
    assert_eq!(
        assess_progress(&first, &report, &[])?.fingerprint,
        assess_progress(&second, &report, &[])?.fingerprint
    );
    Ok(())
}

#[test]
fn fingerprints_exact_canonical_verification_evidence() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let mut first = checkpoint(operation_id, digest(b"diff"));
    let mut second = first.clone();
    first.verification[0].evidence = vec![EvidenceRef {
        event_sequence: 7,
        artifact_digest: Some(digest(b"artifact-one")),
        operation_id: Some(operation_id),
    }];
    second.verification[0].evidence = vec![EvidenceRef {
        event_sequence: 7,
        artifact_digest: Some(digest(b"artifact-two")),
        operation_id: Some(operation_id),
    }];
    let report = parse_epoch_report(&report("continue", ""))?;
    assert_ne!(
        assess_progress(&first, &report, &[])?.fingerprint,
        assess_progress(&second, &report, &[])?.fingerprint
    );
    Ok(())
}

#[test]
fn fingerprints_changed_files_with_identity_and_multiplicity() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let mut first = checkpoint(operation_id, digest(b"diff"));
    let mut second = first.clone();
    let file_digest = digest(b"same file contents");
    first
        .repository
        .file_hashes
        .insert("src/first.rs".to_owned(), file_digest.clone());
    first
        .repository
        .file_hashes
        .insert("src/second.rs".to_owned(), file_digest.clone());
    second
        .repository
        .file_hashes
        .insert("src/renamed.rs".to_owned(), file_digest);
    let report = parse_epoch_report(&report("continue", ""))?;
    assert_ne!(
        assess_progress(&first, &report, &[])?.fingerprint,
        assess_progress(&second, &report, &[])?.fingerprint
    );
    Ok(())
}

#[test]
fn stalls_only_block_after_three_distinct_recovery_strategies_failed() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let checkpoint = checkpoint(operation_id, digest(b"diff"));
    let report = parse_epoch_report(&report("continue", ""))?;
    let baseline = assess_progress(&checkpoint, &report, &[])?;
    let mut history: Vec<ProgressAssessment> = vec![baseline.clone()];
    let mut attempts = Vec::new();
    for expected in [
        RecoveryStrategy::ReconstructFromEvidence,
        RecoveryStrategy::ReplaceApproach,
        RecoveryStrategy::MinimizeReproduction,
    ] {
        let assessment =
            assess_progress_with_recovery_attempts(&checkpoint, &report, &history, &attempts)?;
        assert_eq!(assessment.recovery, Some(expected));
        attempts.push(RecoveryAttempt {
            strategy: expected,
            strategy_fingerprint: recovery_attempt_fingerprint(&assessment.fingerprint, expected),
            outcome: RecoveryAttemptOutcome::Failed,
        });
        history.push(assessment);
    }
    let blocked =
        assess_progress_with_recovery_attempts(&checkpoint, &report, &history, &attempts)?;
    assert_eq!(blocked.recovery, Some(RecoveryStrategy::DeclareBlocked));
    assert_eq!(blocked.stall_count, 4);
    Ok(())
}

#[test]
fn recovery_recommendations_are_not_failed_recovery_attempts() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let checkpoint = checkpoint(operation_id, digest(b"diff"));
    let report = parse_epoch_report(&report("continue", ""))?;
    let baseline = assess_progress(&checkpoint, &report, &[])?;
    let history = [
        ProgressAssessment {
            recovery: Some(RecoveryStrategy::ReconstructFromEvidence),
            ..baseline.clone()
        },
        ProgressAssessment {
            recovery: Some(RecoveryStrategy::ReplaceApproach),
            ..baseline.clone()
        },
        ProgressAssessment {
            recovery: Some(RecoveryStrategy::FreshContextDiagnosis),
            ..baseline
        },
    ];
    assert_eq!(
        assess_progress(&checkpoint, &report, &history)?.recovery,
        Some(RecoveryStrategy::ReconstructFromEvidence)
    );
    Ok(())
}

#[test]
fn only_three_distinct_terminal_failed_recovery_attempts_can_block() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let checkpoint = checkpoint(operation_id, digest(b"diff"));
    let report = parse_epoch_report(&report("continue", ""))?;
    let baseline = assess_progress(&checkpoint, &report, &[])?;
    let attempts = [
        RecoveryAttempt {
            strategy: RecoveryStrategy::ReconstructFromEvidence,
            strategy_fingerprint: recovery_attempt_fingerprint(
                &baseline.fingerprint,
                RecoveryStrategy::ReconstructFromEvidence,
            ),
            outcome: RecoveryAttemptOutcome::Failed,
        },
        RecoveryAttempt {
            strategy: RecoveryStrategy::ReplaceApproach,
            strategy_fingerprint: recovery_attempt_fingerprint(
                &baseline.fingerprint,
                RecoveryStrategy::ReplaceApproach,
            ),
            outcome: RecoveryAttemptOutcome::Failed,
        },
        RecoveryAttempt {
            strategy: RecoveryStrategy::MinimizeReproduction,
            strategy_fingerprint: recovery_attempt_fingerprint(
                &baseline.fingerprint,
                RecoveryStrategy::MinimizeReproduction,
            ),
            outcome: RecoveryAttemptOutcome::Failed,
        },
    ];
    assert_eq!(
        assess_progress_with_recovery_attempts(&checkpoint, &report, &[baseline], &attempts)?
            .recovery,
        Some(RecoveryStrategy::DeclareBlocked)
    );
    Ok(())
}

#[test]
fn missing_authority_blocks_without_a_prior_stall() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let mut checkpoint = checkpoint(operation_id, digest(b"diff"));
    checkpoint.blockers.push("missing_authority".to_owned());
    let report = parse_epoch_report(&report("continue", ""))?;
    assert_eq!(
        assess_progress(&checkpoint, &report, &[])?.recovery,
        Some(RecoveryStrategy::DeclareBlocked)
    );
    Ok(())
}

#[test]
fn recovery_selection_is_independent_of_provider_metadata() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let mut first = checkpoint(operation_id, digest(b"diff"));
    let mut second = first.clone();
    first.provider.context_id = None;
    second.provider.provider = "different-provider".to_owned();
    second.provider.model = "different-model".to_owned();
    second.provider.context_id = Some("different-context".to_owned());
    let report = parse_epoch_report(&report("continue", ""))?;
    let first_baseline = assess_progress(&first, &report, &[])?;
    let second_baseline = assess_progress(&second, &report, &[])?;
    assert_eq!(first_baseline.fingerprint, second_baseline.fingerprint);
    assert_eq!(
        assess_progress(&first, &report, std::slice::from_ref(&first_baseline))?.recovery,
        assess_progress(&second, &report, std::slice::from_ref(&second_baseline))?.recovery
    );
    Ok(())
}
