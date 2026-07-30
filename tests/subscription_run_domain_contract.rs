use carl::delegates::{
    DelegateSettings, DelegateSettingsLayers, ModelId, ReasoningEffort, SettingSource,
};
use carl::error::ErrorCode;
use carl::events::Event;
use carl::runtime::subscription::{
    ArtifactId, ProviderReported, RunConfigSnapshot, RunFailureCode, RunId, RunState,
    RunTransition, RunTrustLabel, VerificationId,
};

#[test]
fn subscription_run_ids_are_validated_stable_identifiers() -> Result<(), Box<dyn std::error::Error>>
{
    let run_id = RunId::from_uuid(uuid::Uuid::parse_str(
        "11111111-1111-4111-8111-111111111111",
    )?);
    let verification_id = VerificationId::from_uuid(uuid::Uuid::parse_str(
        "22222222-2222-4222-8222-222222222222",
    )?);
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let artifact_id = ArtifactId::parse(digest)?;

    assert_eq!(run_id.to_string(), "11111111-1111-4111-8111-111111111111");
    assert_eq!(
        verification_id.to_string(),
        "22222222-2222-4222-8222-222222222222"
    );
    assert_eq!(artifact_id.as_str(), digest);
    assert_eq!(serde_json::to_value(run_id)?, json_string(run_id));
    assert_eq!(
        serde_json::to_value(verification_id)?,
        json_string(verification_id)
    );
    assert_eq!(serde_json::to_value(&artifact_id)?, digest);
    assert_eq!(
        serde_json::from_str::<ArtifactId>(&format!(r#""{digest}""#))?,
        artifact_id
    );

    for invalid in [
        "",
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "0123456789abcdef",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
    ] {
        assert_eq!(
            ArtifactId::parse(invalid)
                .expect_err("non-lowercase-SHA-256 IDs must be rejected")
                .code(),
            ErrorCode::Validation
        );
        assert!(
            serde_json::from_str::<ArtifactId>(&format!(r#""{invalid}""#)).is_err(),
            "deserialization must preserve ArtifactId validation"
        );
    }

    Ok(())
}

fn json_string(value: impl ToString) -> serde_json::Value {
    serde_json::Value::String(value.to_string())
}

#[test]
fn run_states_have_a_closed_stable_wire_vocabulary() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (RunState::Prepared, "prepared", false),
        (
            RunState::AwaitingDelegateApproval,
            "awaiting_delegate_approval",
            false,
        ),
        (RunState::Running, "running", false),
        (RunState::Inspecting, "inspecting", false),
        (RunState::Verifying, "verifying", false),
        (
            RunState::AwaitingPromotionApproval,
            "awaiting_promotion_approval",
            false,
        ),
        (RunState::Promoted, "promoted", true),
        (RunState::CompletedNoChanges, "completed_no_changes", true),
        (RunState::Failed, "failed", true),
        (RunState::Cancelled, "cancelled", true),
        (RunState::Interrupted, "interrupted", true),
    ];

    for (state, wire_name, terminal) in cases {
        assert_eq!(state.as_str(), wire_name);
        assert_eq!(state.is_terminal(), terminal);
        assert_eq!(RunState::parse(wire_name)?, state);
        assert_eq!(serde_json::to_value(state)?, wire_name);
        assert_eq!(
            serde_json::from_str::<RunState>(&format!(r#""{wire_name}""#))?,
            state
        );
    }

    assert!(RunState::parse("complete").is_err());
    Ok(())
}

#[test]
fn run_state_machine_accepts_only_forward_or_terminal_transitions() {
    let forward = [
        (RunState::Prepared, RunState::AwaitingDelegateApproval),
        (RunState::AwaitingDelegateApproval, RunState::Running),
        (RunState::Running, RunState::Inspecting),
        (RunState::Inspecting, RunState::Verifying),
        (RunState::Inspecting, RunState::CompletedNoChanges),
        (RunState::Verifying, RunState::AwaitingPromotionApproval),
        (RunState::AwaitingPromotionApproval, RunState::Promoted),
    ];

    for (from, to) in forward {
        assert!(from.can_transition_to(to), "{from:?} -> {to:?}");
        RunTransition::new(from, to, None).expect("forward transition must be valid");
        assert!(
            !to.can_transition_to(from),
            "{to:?} must not reverse to {from:?}"
        );
    }

    for state in [
        RunState::Prepared,
        RunState::AwaitingDelegateApproval,
        RunState::Running,
        RunState::Inspecting,
        RunState::Verifying,
        RunState::AwaitingPromotionApproval,
    ] {
        assert!(state.can_transition_to(RunState::Failed));
        assert!(state.can_transition_to(RunState::Cancelled));
        assert!(state.can_transition_to(RunState::Interrupted));
    }

    for terminal in [
        RunState::Promoted,
        RunState::CompletedNoChanges,
        RunState::Failed,
        RunState::Cancelled,
        RunState::Interrupted,
    ] {
        assert!(!terminal.can_transition_to(RunState::Prepared));
        assert!(!terminal.can_transition_to(terminal));
    }

    assert!(RunTransition::new(RunState::Prepared, RunState::Running, None).is_err());
}

#[test]
fn failed_is_the_only_state_that_carries_a_failure_code() -> Result<(), Box<dyn std::error::Error>>
{
    let failed = RunTransition::new(
        RunState::Running,
        RunState::Failed,
        Some(RunFailureCode::DelegateProtocolFailed),
    )?;
    assert_eq!(failed.from(), RunState::Running);
    assert_eq!(failed.to(), RunState::Failed);
    assert_eq!(
        failed.failure_code(),
        Some(RunFailureCode::DelegateProtocolFailed)
    );

    assert!(RunTransition::new(RunState::Running, RunState::Failed, None).is_err());
    assert!(
        RunTransition::new(
            RunState::Running,
            RunState::Inspecting,
            Some(RunFailureCode::DelegateProtocolFailed),
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<RunTransition>(serde_json::json!({
            "from": "running",
            "to": "failed",
            "failure_code": null,
        }))
        .is_err()
    );

    Ok(())
}

#[test]
fn configuration_sources_and_failure_codes_have_stable_wire_names()
-> Result<(), Box<dyn std::error::Error>> {
    let sources = [
        (SettingSource::ProviderDefault, "provider_default"),
        (SettingSource::Personal, "personal"),
        (SettingSource::Project, "project"),
        (SettingSource::Session, "session"),
        (SettingSource::PerRun, "per_run"),
    ];
    for (source, wire_name) in sources {
        assert_eq!(source.as_str(), wire_name);
        assert_eq!(SettingSource::parse(wire_name)?, source);
        assert_eq!(serde_json::to_value(source)?, wire_name);
        assert_eq!(
            serde_json::from_str::<SettingSource>(&format!(r#""{wire_name}""#))?,
            source
        );
    }

    let failures = [
        (
            RunFailureCode::AuthenticationRequired,
            "authentication_required",
        ),
        (
            RunFailureCode::SubscriptionUnavailable,
            "subscription_unavailable",
        ),
        (
            RunFailureCode::DelegateIncompatible,
            "delegate_incompatible",
        ),
        (
            RunFailureCode::DelegateConfigurationFailed,
            "delegate_configuration_failed",
        ),
        (RunFailureCode::DelegateStartFailed, "delegate_start_failed"),
        (
            RunFailureCode::DelegateProtocolFailed,
            "delegate_protocol_failed",
        ),
        (
            RunFailureCode::DelegateBudgetExhausted,
            "delegate_budget_exhausted",
        ),
        (RunFailureCode::StageRejected, "stage_rejected"),
        (RunFailureCode::ProposalRejected, "proposal_rejected"),
        (RunFailureCode::VerificationFailed, "verification_failed"),
        (RunFailureCode::StaleWorkspace, "stale_workspace"),
        (RunFailureCode::PromotionFailed, "promotion_failed"),
    ];
    for (failure, wire_name) in failures {
        assert_eq!(failure.as_str(), wire_name);
        assert_eq!(RunFailureCode::parse(wire_name)?, failure);
        assert_eq!(serde_json::to_value(failure)?, wire_name);
    }

    assert!(SettingSource::parse("default").is_err());
    assert!(RunFailureCode::parse("provider_error").is_err());
    Ok(())
}

#[test]
fn trust_labels_keep_provider_claims_distinct_from_carl_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (RunTrustLabel::TrustedCarlState, "trusted_carl_state"),
        (
            RunTrustLabel::UntrustedProviderEvidence,
            "untrusted_provider_evidence",
        ),
        (
            RunTrustLabel::TrustedCarlVerification,
            "trusted_carl_verification",
        ),
        (RunTrustLabel::OwnerApproval, "owner_approval"),
        (
            RunTrustLabel::LiveWorkspaceMutationResult,
            "live_workspace_mutation_result",
        ),
    ];

    for (label, wire_name) in cases {
        assert_eq!(label.as_str(), wire_name);
        assert_eq!(RunTrustLabel::parse(wire_name)?, label);
        assert_eq!(serde_json::to_value(label)?, wire_name);
    }

    assert!(RunTrustLabel::parse("trusted_provider_evidence").is_err());
    Ok(())
}

#[test]
fn run_configuration_snapshots_preserve_sources_and_provider_reporting()
-> Result<(), Box<dyn std::error::Error>> {
    let session = DelegateSettings::new(
        Some(ModelId::parse("gpt-5.6")?),
        Some(ReasoningEffort::High),
    );
    let per_run = DelegateSettings::new(Some(ModelId::parse("gpt-5.6-terra")?), None);
    let resolved = DelegateSettingsLayers {
        personal: None,
        project: None,
        session: Some(&session),
        per_run: Some(&per_run),
    }
    .resolve();
    let snapshot = RunConfigSnapshot::new(
        &resolved,
        ProviderReported::Reported(ModelId::parse("gpt-5.6-terra-2026-07-15")?),
        ProviderReported::NotReported,
    );

    assert_eq!(snapshot.model().map(ModelId::as_str), Some("gpt-5.6-terra"));
    assert_eq!(snapshot.model_source(), SettingSource::PerRun);
    assert_eq!(snapshot.effort(), Some(ReasoningEffort::High));
    assert_eq!(snapshot.effort_source(), SettingSource::Session);
    assert_eq!(
        snapshot.provider_reported_model(),
        &ProviderReported::Reported(ModelId::parse("gpt-5.6-terra-2026-07-15")?)
    );
    assert_eq!(
        snapshot.provider_model(),
        snapshot.provider_reported_model()
    );
    assert_eq!(
        snapshot.provider_reported_effort(),
        &ProviderReported::NotReported
    );
    assert_eq!(
        snapshot.provider_effort(),
        snapshot.provider_reported_effort()
    );
    assert_eq!(
        serde_json::to_value(&snapshot)?,
        serde_json::json!({
            "model": "gpt-5.6-terra",
            "model_source": "per_run",
            "effort": "high",
            "effort_source": "session",
            "provider_reported_model": {
                "reported": "gpt-5.6-terra-2026-07-15"
            },
            "provider_reported_effort": "not_reported",
        })
    );
    assert_eq!(
        serde_json::from_value::<RunConfigSnapshot>(serde_json::to_value(&snapshot)?)?,
        snapshot
    );

    assert_eq!(
        serde_json::to_value(&session)?,
        serde_json::json!({"model": "gpt-5.6", "effort": "high"})
    );
    assert_eq!(
        serde_json::from_value::<DelegateSettings>(serde_json::to_value(&session)?)?,
        session
    );

    Ok(())
}

#[test]
fn configuration_reconstruction_rejects_impossible_value_source_pairs() {
    let model = ModelId::parse("gpt-5.6").expect("fixture model is valid");

    assert!(
        RunConfigSnapshot::reconstruct(
            Some(model.clone()),
            SettingSource::ProviderDefault,
            None,
            SettingSource::ProviderDefault,
            ProviderReported::NotReported,
            ProviderReported::NotReported,
        )
        .is_err()
    );
    assert!(
        RunConfigSnapshot::reconstruct(
            None,
            SettingSource::Session,
            None,
            SettingSource::ProviderDefault,
            ProviderReported::NotReported,
            ProviderReported::NotReported,
        )
        .is_err()
    );
    assert!(
        serde_json::from_value::<RunConfigSnapshot>(serde_json::json!({
            "model": model,
            "model_source": "provider_default",
            "effort": null,
            "effort_source": "provider_default",
            "provider_reported_model": "not_reported",
            "provider_reported_effort": "not_reported",
        }))
        .is_err()
    );
}

#[test]
fn unresolved_provider_values_are_explicitly_not_reported() -> Result<(), Box<dyn std::error::Error>>
{
    let resolved = DelegateSettingsLayers::default().resolve();
    let snapshot = RunConfigSnapshot::from_resolved(&resolved);

    assert_eq!(snapshot.model(), None);
    assert_eq!(snapshot.model_source(), SettingSource::ProviderDefault);
    assert_eq!(snapshot.effort(), None);
    assert_eq!(snapshot.effort_source(), SettingSource::ProviderDefault);
    assert_eq!(
        snapshot.provider_reported_model(),
        &ProviderReported::NotReported
    );
    assert_eq!(
        snapshot.provider_reported_effort(),
        &ProviderReported::NotReported
    );

    Ok(())
}

#[test]
fn schema_v2_prepared_event_carries_replay_sequence_and_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    let run_id = RunId::from_uuid(uuid::Uuid::parse_str(
        "11111111-1111-4111-8111-111111111111",
    )?);
    let configuration =
        RunConfigSnapshot::from_resolved(&DelegateSettingsLayers::default().resolve());
    let event = Event::SubscriptionRunPrepared {
        run_id,
        run_sequence: 1,
        configuration: configuration.clone(),
        state: RunState::Prepared,
        trust_label: RunTrustLabel::TrustedCarlState,
    };
    let encoded = serde_json::to_value(&event)?;

    assert_eq!(
        encoded,
        serde_json::json!({
            "schema_version": 2,
            "type": "subscription_run_prepared",
            "run_id": "11111111-1111-4111-8111-111111111111",
            "run_sequence": 1,
            "configuration": {
                "model": null,
                "model_source": "provider_default",
                "effort": null,
                "effort_source": "provider_default",
                "provider_reported_model": "not_reported",
                "provider_reported_effort": "not_reported",
            },
            "state": "prepared",
            "trust_label": "trusted_carl_state",
        })
    );
    assert_eq!(serde_json::from_value::<Event>(encoded)?, event);

    Ok(())
}

#[test]
fn schema_v2_provider_observation_is_explicitly_untrusted() -> Result<(), Box<dyn std::error::Error>>
{
    let run_id = RunId::from_uuid(uuid::Uuid::parse_str(
        "11111111-1111-4111-8111-111111111111",
    )?);
    let base = RunConfigSnapshot::from_resolved(&DelegateSettingsLayers::default().resolve());
    let configuration = base.with_provider_reported(
        ProviderReported::Reported(ModelId::parse("gpt-5.6-provider-resolved")?),
        ProviderReported::NotReported,
    );
    let event = Event::SubscriptionRunConfigurationObserved {
        run_id,
        run_sequence: 4,
        configuration: configuration.clone(),
        trust_label: RunTrustLabel::UntrustedProviderEvidence,
    };
    let encoded = serde_json::to_value(&event)?;

    assert_eq!(
        encoded,
        serde_json::json!({
            "schema_version": 2,
            "type": "subscription_run_configuration_observed",
            "run_id": "11111111-1111-4111-8111-111111111111",
            "run_sequence": 4,
            "configuration": {
                "model": null,
                "model_source": "provider_default",
                "effort": null,
                "effort_source": "provider_default",
                "provider_reported_model": {
                    "reported": "gpt-5.6-provider-resolved"
                },
                "provider_reported_effort": "not_reported",
            },
            "trust_label": "untrusted_provider_evidence",
        })
    );
    assert_eq!(serde_json::from_value::<Event>(encoded)?, event);

    Ok(())
}

#[test]
fn schema_v2_transition_event_carries_validated_transition_and_replay_sequence()
-> Result<(), Box<dyn std::error::Error>> {
    let run_id = RunId::from_uuid(uuid::Uuid::parse_str(
        "11111111-1111-4111-8111-111111111111",
    )?);
    let transition =
        RunTransition::new(RunState::Prepared, RunState::AwaitingDelegateApproval, None)?;
    let event = Event::SubscriptionRunTransitioned {
        run_id,
        run_sequence: 2,
        transition: transition.clone(),
        trust_label: RunTrustLabel::TrustedCarlState,
    };
    let encoded = serde_json::to_value(&event)?;

    assert_eq!(
        encoded,
        serde_json::json!({
            "schema_version": 2,
            "type": "subscription_run_transitioned",
            "run_id": "11111111-1111-4111-8111-111111111111",
            "run_sequence": 2,
            "transition": {
                "from": "prepared",
                "to": "awaiting_delegate_approval",
                "failure_code": null,
            },
            "trust_label": "trusted_carl_state",
        })
    );
    assert_eq!(serde_json::from_value::<Event>(encoded)?, event);

    Ok(())
}
