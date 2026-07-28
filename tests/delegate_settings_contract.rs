use carl::delegates::{
    BoundedDelegateTask, DelegateSettings, DelegateSettingsLayers, ModelId, ReasoningEffort,
    SettingSource,
};
use carl::error::ErrorCode;

#[test]
fn per_run_values_override_session_without_mutating_it() {
    let session = DelegateSettings::new(
        Some(ModelId::parse("gpt-5.6").expect("session model is valid")),
        Some(ReasoningEffort::High),
    );
    let per_run = DelegateSettings::new(
        Some(ModelId::parse("gpt-5.6-terra").expect("per-run model is valid")),
        Some(ReasoningEffort::Low),
    );

    let resolved = DelegateSettingsLayers {
        personal: None,
        project: None,
        session: Some(&session),
        per_run: Some(&per_run),
    }
    .resolve();

    assert_eq!(resolved.model().map(ModelId::as_str), Some("gpt-5.6-terra"));
    assert_eq!(resolved.model_source(), SettingSource::PerRun);
    assert_eq!(resolved.effort(), Some(ReasoningEffort::Low));
    assert_eq!(resolved.effort_source(), SettingSource::PerRun);
    assert_eq!(session.model().map(ModelId::as_str), Some("gpt-5.6"));
    assert_eq!(session.effort(), Some(ReasoningEffort::High));
}

#[test]
fn settings_resolve_each_field_independently() {
    let personal = DelegateSettings::new(
        Some(ModelId::parse("gpt-5.6").expect("personal model is valid")),
        None,
    );
    let project = DelegateSettings::new(
        Some(ModelId::parse("gpt-5.6-terra").expect("project model is valid")),
        None,
    );
    let session = DelegateSettings::new(None, Some(ReasoningEffort::XHigh));

    let resolved = DelegateSettingsLayers {
        personal: Some(&personal),
        project: Some(&project),
        session: Some(&session),
        per_run: None,
    }
    .resolve();

    assert_eq!(resolved.model().map(ModelId::as_str), Some("gpt-5.6-terra"));
    assert_eq!(resolved.model_source(), SettingSource::Project);
    assert_eq!(resolved.effort(), Some(ReasoningEffort::XHigh));
    assert_eq!(resolved.effort_source(), SettingSource::Session);
}

#[test]
fn unset_settings_preserve_the_provider_default_instead_of_guessing() {
    let resolved = DelegateSettingsLayers::default().resolve();

    assert_eq!(resolved.model(), None);
    assert_eq!(resolved.model_source(), SettingSource::ProviderDefault);
    assert_eq!(resolved.effort(), None);
    assert_eq!(resolved.effort_source(), SettingSource::ProviderDefault);
}

#[test]
fn model_ids_are_bounded_provider_owned_strings() {
    for invalid in ["", "gpt 5.6", "gpt/5.6", "gpt-5.6\n", &"x".repeat(129)] {
        let error = ModelId::parse(invalid).expect_err("invalid model must be rejected");
        assert_eq!(error.code(), ErrorCode::Validation);
    }

    assert_eq!(
        ModelId::parse("openai:gpt-5.6")
            .expect("provider model is valid")
            .as_str(),
        "openai:gpt-5.6"
    );
}

#[test]
fn model_deserialization_cannot_bypass_validation() {
    assert!(serde_json::from_str::<ModelId>(r#""gpt 5.6""#).is_err());
    assert_eq!(
        serde_json::from_str::<ModelId>(r#""gpt-5.6""#)
            .expect("valid model deserializes")
            .as_str(),
        "gpt-5.6"
    );
}

#[test]
fn reasoning_effort_uses_the_exact_codex_values() {
    let cases = [
        (ReasoningEffort::Low, "low"),
        (ReasoningEffort::Medium, "medium"),
        (ReasoningEffort::High, "high"),
        (ReasoningEffort::XHigh, "xhigh"),
        (ReasoningEffort::Max, "max"),
        (ReasoningEffort::Ultra, "ultra"),
    ];

    for (effort, expected) in cases {
        assert_eq!(effort.as_codex_value(), expected);
        assert_eq!(
            serde_json::to_string(&effort).expect("effort serializes"),
            format!(r#""{expected}""#)
        );
        assert_eq!(
            serde_json::from_str::<ReasoningEffort>(&format!(r#""{expected}""#))
                .expect("effort deserializes"),
            effort
        );
    }
}

#[test]
fn delegate_tasks_are_nonempty_bounded_and_redacted() {
    for invalid in ["", " \n\t ", "contains\0nul", &"x".repeat(32_769)] {
        let error = BoundedDelegateTask::parse(invalid).expect_err("invalid task must be rejected");
        assert_eq!(error.code(), ErrorCode::Validation);
    }

    let task = BoundedDelegateTask::parse("Fix the failing test").expect("ordinary task is valid");
    assert_eq!(task.as_str(), "Fix the failing test");
    assert!(!format!("{task:?}").contains("Fix the failing test"));
}
