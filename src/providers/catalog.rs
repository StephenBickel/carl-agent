use std::collections::{BTreeSet, HashSet};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::delegates::{ModelId, ReasoningEffort};

const MIN_CONTEXT_WINDOW: u64 = 32_768;
const MAX_CONTEXT_WINDOW: u64 = 4_000_000;
const MAX_MODELS: usize = 256;
const MAX_DISPLAY_NAME_BYTES: usize = 256;
const MAX_EFFORTS: usize = 6;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ProviderKind {
    #[serde(rename = "openai_subscription")]
    OpenAiSubscription,
    #[serde(rename = "openai_api")]
    OpenAiApi,
    #[serde(rename = "openrouter")]
    OpenRouter,
}

impl ProviderKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiSubscription => "openai_subscription",
            Self::OpenAiApi => "openai_api",
            Self::OpenRouter => "openrouter",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("native provider catalog is invalid")]
pub struct ProviderCatalogError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderModel {
    id: ModelId,
    display_name: String,
    context_window: u64,
    supported_efforts: Vec<ReasoningEffort>,
    default_effort: ReasoningEffort,
    structured_tools: bool,
    text_input: bool,
    text_output: bool,
}

impl ProviderModel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ModelId,
        display_name: String,
        context_window: u64,
        supported_efforts: Vec<ReasoningEffort>,
        default_effort: ReasoningEffort,
        structured_tools: bool,
        text_input: bool,
        text_output: bool,
    ) -> Result<Self, ProviderCatalogError> {
        let display_valid = !display_name.is_empty()
            && display_name.len() <= MAX_DISPLAY_NAME_BYTES
            && display_name.trim() == display_name
            && !display_name.chars().any(char::is_control);
        let efforts = supported_efforts.iter().copied().collect::<HashSet<_>>();
        if !display_valid
            || !(MIN_CONTEXT_WINDOW..=MAX_CONTEXT_WINDOW).contains(&context_window)
            || supported_efforts.is_empty()
            || supported_efforts.len() > MAX_EFFORTS
            || efforts.len() != supported_efforts.len()
            || !efforts.contains(&default_effort)
            || !structured_tools
            || !text_input
            || !text_output
        {
            return Err(ProviderCatalogError);
        }
        Ok(Self {
            id,
            display_name,
            context_window,
            supported_efforts,
            default_effort,
            structured_tools,
            text_input,
            text_output,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &ModelId {
        &self.id
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub const fn context_window(&self) -> u64 {
        self.context_window
    }

    #[must_use]
    pub fn supported_efforts(&self) -> &[ReasoningEffort] {
        &self.supported_efforts
    }

    #[must_use]
    pub const fn default_effort(&self) -> ReasoningEffort {
        self.default_effort
    }

    #[must_use]
    pub const fn structured_tools(&self) -> bool {
        self.structured_tools
    }

    #[must_use]
    pub const fn text_input(&self) -> bool {
        self.text_input
    }

    #[must_use]
    pub const fn text_output(&self) -> bool {
        self.text_output
    }
}

impl<'de> Deserialize<'de> for ProviderModel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawModel {
            id: ModelId,
            display_name: String,
            context_window: u64,
            supported_efforts: Vec<ReasoningEffort>,
            default_effort: ReasoningEffort,
            structured_tools: bool,
            text_input: bool,
            text_output: bool,
        }
        let raw = RawModel::deserialize(deserializer)?;
        Self::new(
            raw.id,
            raw.display_name,
            raw.context_window,
            raw.supported_efforts,
            raw.default_effort,
            raw.structured_tools,
            raw.text_input,
            raw.text_output,
        )
        .map_err(|_| D::Error::custom("invalid native provider model"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCatalog {
    provider: ProviderKind,
    models: Vec<ProviderModel>,
    default_model: ModelId,
}

impl ProviderCatalog {
    pub fn new(
        provider: ProviderKind,
        models: Vec<ProviderModel>,
        default_model: ModelId,
    ) -> Result<Self, ProviderCatalogError> {
        let unique = models
            .iter()
            .map(|model| model.id().as_str())
            .collect::<BTreeSet<_>>();
        if models.is_empty()
            || models.len() > MAX_MODELS
            || unique.len() != models.len()
            || !models.iter().any(|model| model.id() == &default_model)
        {
            return Err(ProviderCatalogError);
        }
        Ok(Self {
            provider,
            models,
            default_model,
        })
    }

    #[must_use]
    pub const fn provider(&self) -> ProviderKind {
        self.provider
    }

    #[must_use]
    pub fn models(&self) -> &[ProviderModel] {
        &self.models
    }

    #[must_use]
    pub const fn default_model(&self) -> &ModelId {
        &self.default_model
    }
}

impl<'de> Deserialize<'de> for ProviderCatalog {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawCatalog {
            provider: ProviderKind,
            models: Vec<ProviderModel>,
            default_model: ModelId,
        }
        let raw = RawCatalog::deserialize(deserializer)?;
        Self::new(raw.provider, raw.models, raw.default_model)
            .map_err(|_| D::Error::custom("invalid native provider catalog"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSelection {
    model: ModelId,
    effort: ReasoningEffort,
}

impl ProviderSelection {
    #[must_use]
    pub const fn new(model: ModelId, effort: ReasoningEffort) -> Self {
        Self { model, effort }
    }

    pub fn validate_against<'a>(
        &self,
        catalog: &'a ProviderCatalog,
    ) -> Result<&'a ProviderModel, ProviderCatalogError> {
        catalog
            .models()
            .iter()
            .find(|model| {
                model.id() == &self.model && model.supported_efforts().contains(&self.effort)
            })
            .ok_or(ProviderCatalogError)
    }
}
