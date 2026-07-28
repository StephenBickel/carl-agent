use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::CarlError;

const MAX_DELEGATE_TASK_BYTES: usize = 32 * 1_024;
const MAX_MODEL_ID_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ModelId(String);

impl ModelId {
    pub fn parse(value: impl Into<String>) -> Result<Self, CarlError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_MODEL_ID_BYTES
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            });
        if !valid {
            return Err(validation_error("delegate model identifier is invalid"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ModelId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(|_| D::Error::custom("invalid delegate model identifier"))
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BoundedDelegateTask(String);

impl BoundedDelegateTask {
    pub fn parse(value: impl Into<String>) -> Result<Self, CarlError> {
        let value = value.into();
        if value.trim().is_empty()
            || value.len() > MAX_DELEGATE_TASK_BYTES
            || value.as_bytes().contains(&0)
        {
            return Err(validation_error("delegate task is invalid"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BoundedDelegateTask {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundedDelegateTask(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    Low,
    Medium,
    High,
    #[serde(rename = "xhigh")]
    XHigh,
    Max,
    Ultra,
}

impl ReasoningEffort {
    #[must_use]
    pub const fn as_codex_value(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::XHigh => "xhigh",
            Self::Max => "max",
            Self::Ultra => "ultra",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DelegateSettings {
    model: Option<ModelId>,
    effort: Option<ReasoningEffort>,
}

impl DelegateSettings {
    #[must_use]
    pub const fn new(model: Option<ModelId>, effort: Option<ReasoningEffort>) -> Self {
        Self { model, effort }
    }

    #[must_use]
    pub fn model(&self) -> Option<&ModelId> {
        self.model.as_ref()
    }

    #[must_use]
    pub const fn effort(&self) -> Option<ReasoningEffort> {
        self.effort
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettingSource {
    ProviderDefault,
    Personal,
    Project,
    Session,
    PerRun,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DelegateSettingsLayers<'a> {
    pub personal: Option<&'a DelegateSettings>,
    pub project: Option<&'a DelegateSettings>,
    pub session: Option<&'a DelegateSettings>,
    pub per_run: Option<&'a DelegateSettings>,
}

impl DelegateSettingsLayers<'_> {
    #[must_use]
    pub fn resolve(self) -> ResolvedDelegateSettings {
        let ordered = [
            (self.per_run, SettingSource::PerRun),
            (self.session, SettingSource::Session),
            (self.project, SettingSource::Project),
            (self.personal, SettingSource::Personal),
        ];

        let (model, model_source) = ordered
            .iter()
            .find_map(|(settings, source)| {
                settings
                    .and_then(DelegateSettings::model)
                    .map(|model| (model.clone(), *source))
            })
            .map_or((None, SettingSource::ProviderDefault), |(value, source)| {
                (Some(value), source)
            });
        let (effort, effort_source) = ordered
            .iter()
            .find_map(|(settings, source)| {
                settings
                    .and_then(DelegateSettings::effort)
                    .map(|effort| (effort, *source))
            })
            .map_or((None, SettingSource::ProviderDefault), |(value, source)| {
                (Some(value), source)
            });

        ResolvedDelegateSettings {
            model,
            model_source,
            effort,
            effort_source,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedDelegateSettings {
    model: Option<ModelId>,
    model_source: SettingSource,
    effort: Option<ReasoningEffort>,
    effort_source: SettingSource,
}

impl ResolvedDelegateSettings {
    #[must_use]
    pub fn model(&self) -> Option<&ModelId> {
        self.model.as_ref()
    }

    #[must_use]
    pub const fn model_source(&self) -> SettingSource {
        self.model_source
    }

    #[must_use]
    pub const fn effort(&self) -> Option<ReasoningEffort> {
        self.effort
    }

    #[must_use]
    pub const fn effort_source(&self) -> SettingSource {
        self.effort_source
    }
}

fn validation_error(detail: &str) -> CarlError {
    CarlError::Validation {
        detail: detail.to_owned(),
    }
}
