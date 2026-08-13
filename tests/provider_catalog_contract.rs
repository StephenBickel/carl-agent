use std::collections::BTreeSet;

use carl::delegates::{ModelId, ReasoningEffort};
use carl::providers::catalog::{ProviderCatalog, ProviderKind, ProviderModel, ProviderSelection};
use serde_json::json;

#[test]
fn provider_kinds_have_one_strict_stable_wire_vocabulary() {
    for (kind, literal) in [
        (ProviderKind::OpenAiSubscription, "openai_subscription"),
        (ProviderKind::OpenAiApi, "openai_api"),
        (ProviderKind::OpenRouter, "openrouter"),
    ] {
        assert_eq!(serde_json::to_value(kind).unwrap(), json!(literal));
        assert_eq!(
            serde_json::from_value::<ProviderKind>(json!(literal)).unwrap(),
            kind
        );
    }
    assert!(serde_json::from_value::<ProviderKind>(json!("open_ai")).is_err());
}

#[test]
fn openrouter_model_ids_are_validated_as_segments_not_workspace_paths() {
    assert_eq!(
        ModelId::parse("deepseek/deepseek-v3.2").unwrap().as_str(),
        "deepseek/deepseek-v3.2"
    );
    assert_eq!(
        ModelId::parse("qwen/qwen3-coder:free").unwrap().as_str(),
        "qwen/qwen3-coder:free"
    );
    for invalid in [
        "/openai/gpt-5",
        "openai/gpt-5/",
        "openai//gpt-5",
        "openai/../gpt-5",
        "./gpt-5",
    ] {
        assert!(ModelId::parse(invalid).is_err(), "accepted {invalid}");
    }
}

#[test]
fn provider_models_enforce_coding_capabilities_and_bounds() {
    let model = valid_model("openai/gpt-5.2", "GPT 5.2");
    assert_eq!(model.id().as_str(), "openai/gpt-5.2");
    assert_eq!(model.display_name(), "GPT 5.2");
    assert_eq!(model.context_window(), 128_000);
    assert_eq!(
        model.supported_efforts(),
        &[ReasoningEffort::Medium, ReasoningEffort::High]
    );
    assert_eq!(model.default_effort(), ReasoningEffort::Medium);
    assert!(model.structured_tools());
    assert!(model.text_input());
    assert!(model.text_output());

    for context in [0, 32_767, 4_000_001] {
        assert!(
            ProviderModel::new(
                ModelId::parse("openai/gpt-5.2").unwrap(),
                "GPT 5.2".to_owned(),
                context,
                vec![ReasoningEffort::Medium],
                ReasoningEffort::Medium,
                true,
                true,
                true,
            )
            .is_err()
        );
    }
    for (tools, input, output) in [
        (false, true, true),
        (true, false, true),
        (true, true, false),
    ] {
        assert!(
            ProviderModel::new(
                ModelId::parse("openai/gpt-5.2").unwrap(),
                "GPT 5.2".to_owned(),
                128_000,
                vec![ReasoningEffort::Medium],
                ReasoningEffort::Medium,
                tools,
                input,
                output,
            )
            .is_err()
        );
    }
    assert!(
        ProviderModel::new(
            ModelId::parse("openai/gpt-5.2").unwrap(),
            "GPT 5.2".to_owned(),
            128_000,
            vec![ReasoningEffort::Medium],
            ReasoningEffort::High,
            true,
            true,
            true,
        )
        .is_err()
    );
    assert!(
        ProviderModel::new(
            ModelId::parse("openai/gpt-5.2").unwrap(),
            " GPT 5.2".to_owned(),
            128_000,
            vec![ReasoningEffort::Medium],
            ReasoningEffort::Medium,
            true,
            true,
            true,
        )
        .is_err()
    );
    assert!(
        ProviderModel::new(
            ModelId::parse("openai/gpt-5.2").unwrap(),
            "GPT 5.2".to_owned(),
            128_000,
            vec![ReasoningEffort::Medium, ReasoningEffort::Medium],
            ReasoningEffort::Medium,
            true,
            true,
            true,
        )
        .is_err()
    );
}

#[test]
fn catalogs_are_unique_bounded_and_selections_never_guess() {
    let first = valid_model("openai/gpt-5.2", "GPT 5.2");
    let second = valid_model("anthropic/claude-sonnet-4.5", "Claude Sonnet 4.5");
    let catalog = ProviderCatalog::new(
        ProviderKind::OpenRouter,
        vec![first.clone(), second.clone()],
        first.id().clone(),
    )
    .unwrap();
    assert_eq!(catalog.provider(), ProviderKind::OpenRouter);
    assert_eq!(catalog.models().len(), 2);
    assert_eq!(catalog.default_model(), first.id());
    assert_eq!(
        catalog
            .models()
            .iter()
            .map(|model| model.id().as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["anthropic/claude-sonnet-4.5", "openai/gpt-5.2"])
    );

    ProviderSelection::new(first.id().clone(), ReasoningEffort::High)
        .validate_against(&catalog)
        .unwrap();
    assert!(
        ProviderSelection::new(first.id().clone(), ReasoningEffort::Ultra)
            .validate_against(&catalog)
            .is_err()
    );
    assert!(
        ProviderSelection::new(
            ModelId::parse("qwen/qwen3-coder").unwrap(),
            ReasoningEffort::High,
        )
        .validate_against(&catalog)
        .is_err()
    );

    assert!(
        ProviderCatalog::new(
            ProviderKind::OpenRouter,
            vec![first.clone(), first.clone()],
            first.id().clone(),
        )
        .is_err()
    );
    let too_many = (0..257)
        .map(|index| valid_model(&format!("provider/model-{index}"), "Model"))
        .collect();
    assert!(
        ProviderCatalog::new(
            ProviderKind::OpenRouter,
            too_many,
            ModelId::parse("provider/model-0").unwrap(),
        )
        .is_err()
    );
    assert!(
        ProviderCatalog::new(ProviderKind::OpenRouter, vec![first], second.id().clone(),).is_err()
    );
    assert!(
        serde_json::from_value::<ProviderCatalog>(json!({
            "provider": "openrouter",
            "models": [],
            "default_model": "openai/gpt-5.2",
            "api_key": "must-not-be-accepted"
        }))
        .is_err()
    );
}

fn valid_model(id: &str, display_name: &str) -> ProviderModel {
    ProviderModel::new(
        ModelId::parse(id).unwrap(),
        display_name.to_owned(),
        128_000,
        vec![ReasoningEffort::Medium, ReasoningEffort::High],
        ReasoningEffort::Medium,
        true,
        true,
        true,
    )
    .unwrap()
}
