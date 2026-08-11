use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

use crate::delegates::{ModelId, ReasoningEffort};

const MAX_MODELS: usize = 64;
const MAX_DISPLAY_NAME_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConfigErrorCode {
    #[error("ACP configuration value is invalid")]
    InvalidValue,
    #[error("ACP model is not available")]
    UnknownModel,
    #[error("ACP reasoning effort is not available for this model")]
    UnsupportedEffort,
    #[error("ACP model catalog is invalid")]
    InvalidCatalog,
}

#[derive(Debug, Error)]
#[error("{code}")]
pub struct ConfigError {
    code: ConfigErrorCode,
}

impl ConfigError {
    #[must_use]
    pub const fn code(&self) -> ConfigErrorCode {
        self.code
    }

    const fn from_code(code: ConfigErrorCode) -> Self {
        Self { code }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionMode {
    Plan,
    Default,
    AcceptEdits,
    DontAsk,
    FullAccess,
    BypassPermissions,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionProfile {
    ReadOnly,
    Approval,
    FullAccess,
}

impl PermissionMode {
    pub const ALL: [Self; 5] = [
        Self::Plan,
        Self::Default,
        Self::AcceptEdits,
        Self::DontAsk,
        Self::FullAccess,
    ];

    #[must_use]
    pub const fn as_wire_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Default => "default",
            Self::AcceptEdits => "acceptEdits",
            Self::DontAsk => "dontAsk",
            Self::FullAccess => "fullAccess",
            Self::BypassPermissions => "bypassPermissions",
        }
    }

    #[must_use]
    pub const fn profile(self) -> PermissionProfile {
        match self {
            Self::Plan => PermissionProfile::ReadOnly,
            Self::Default | Self::AcceptEdits => PermissionProfile::Approval,
            Self::DontAsk => PermissionProfile::ReadOnly,
            Self::FullAccess | Self::BypassPermissions => PermissionProfile::FullAccess,
        }
    }
}

impl FromStr for PermissionMode {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "plan" => Ok(Self::Plan),
            "default" => Ok(Self::Default),
            "acceptEdits" => Ok(Self::AcceptEdits),
            "dontAsk" => Ok(Self::DontAsk),
            "fullAccess" => Ok(Self::FullAccess),
            "bypassPermissions" => Ok(Self::BypassPermissions),
            _ => Err(ConfigError::from_code(ConfigErrorCode::InvalidValue)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModeActivation {
    LocalExplicit,
    RemoteUnconfirmed,
    RemoteConfirmed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigChange {
    Applied,
    PendingBypass { display_code: String },
    Rejected(ConfigErrorCode),
}

#[derive(Clone, Eq, PartialEq)]
pub struct ModelDescriptor {
    id: ModelId,
    display_name: String,
    supported_efforts: Vec<ReasoningEffort>,
}

impl fmt::Debug for ModelDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModelDescriptor")
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("supported_efforts", &self.supported_efforts)
            .finish()
    }
}

impl ModelDescriptor {
    pub fn new(
        id: ModelId,
        display_name: impl Into<String>,
        supported_efforts: Vec<ReasoningEffort>,
    ) -> Result<Self, ConfigError> {
        let display_name = display_name.into();
        let unique = supported_efforts.iter().copied().collect::<HashSet<_>>();
        if display_name.is_empty()
            || display_name.len() > MAX_DISPLAY_NAME_BYTES
            || display_name.as_bytes().contains(&0)
            || supported_efforts.is_empty()
            || unique.len() != supported_efforts.len()
        {
            return Err(ConfigError::from_code(ConfigErrorCode::InvalidCatalog));
        }
        Ok(Self {
            id,
            display_name,
            supported_efforts,
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
    pub fn supported_efforts(&self) -> &[ReasoningEffort] {
        &self.supported_efforts
    }

    #[must_use]
    pub fn supports_effort(&self, effort: ReasoningEffort) -> bool {
        self.supported_efforts.contains(&effort)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCatalog {
    models: Vec<ModelDescriptor>,
}

impl ModelCatalog {
    pub fn new(models: Vec<ModelDescriptor>) -> Result<Self, ConfigError> {
        let unique = models
            .iter()
            .map(|model| model.id().as_str())
            .collect::<HashSet<_>>();
        if models.is_empty() || models.len() > MAX_MODELS || unique.len() != models.len() {
            return Err(ConfigError::from_code(ConfigErrorCode::InvalidCatalog));
        }
        Ok(Self { models })
    }

    #[must_use]
    pub fn models(&self) -> &[ModelDescriptor] {
        &self.models
    }

    #[must_use]
    pub fn find(&self, id: &ModelId) -> Option<&ModelDescriptor> {
        self.models.iter().find(|model| model.id() == id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionConfiguration {
    catalog: ModelCatalog,
    model: ModelId,
    effort: ReasoningEffort,
    mode: PermissionMode,
}

impl SessionConfiguration {
    pub fn new(
        catalog: ModelCatalog,
        model: ModelId,
        effort: ReasoningEffort,
        mode: PermissionMode,
    ) -> Result<Self, ConfigError> {
        let descriptor = catalog
            .find(&model)
            .ok_or_else(|| ConfigError::from_code(ConfigErrorCode::UnknownModel))?;
        if !descriptor.supports_effort(effort) {
            return Err(ConfigError::from_code(ConfigErrorCode::UnsupportedEffort));
        }
        Ok(Self {
            catalog,
            model,
            effort,
            mode,
        })
    }

    #[must_use]
    pub const fn model(&self) -> &ModelId {
        &self.model
    }

    #[must_use]
    pub const fn effort(&self) -> ReasoningEffort {
        self.effort
    }

    #[must_use]
    pub const fn mode(&self) -> PermissionMode {
        self.mode
    }

    #[must_use]
    pub const fn catalog(&self) -> &ModelCatalog {
        &self.catalog
    }

    pub fn set_model(&mut self, model: ModelId) -> ConfigChange {
        let Some(descriptor) = self.catalog.find(&model) else {
            return ConfigChange::Rejected(ConfigErrorCode::UnknownModel);
        };
        if !descriptor.supports_effort(self.effort) {
            return ConfigChange::Rejected(ConfigErrorCode::UnsupportedEffort);
        }
        self.model = model;
        ConfigChange::Applied
    }

    pub fn set_effort(&mut self, effort: ReasoningEffort) -> ConfigChange {
        let Some(descriptor) = self.catalog.find(&self.model) else {
            return ConfigChange::Rejected(ConfigErrorCode::UnknownModel);
        };
        if !descriptor.supports_effort(effort) {
            return ConfigChange::Rejected(ConfigErrorCode::UnsupportedEffort);
        }
        self.effort = effort;
        ConfigChange::Applied
    }

    pub fn set_mode(&mut self, mode: PermissionMode, activation: ModeActivation) -> ConfigChange {
        if mode.profile() == PermissionProfile::FullAccess
            && activation == ModeActivation::RemoteUnconfirmed
        {
            let display_code = Uuid::new_v4()
                .simple()
                .to_string()
                .chars()
                .take(10)
                .collect();
            return ConfigChange::PendingBypass { display_code };
        }
        self.mode = mode;
        ConfigChange::Applied
    }
}

#[must_use]
pub fn config_options(catalog: &ModelCatalog) -> Vec<Value> {
    let first_model = &catalog.models()[0];
    vec![
        json!({
            "configId": "model",
            "category": "model",
            "displayName": "Model",
            "currentValue": first_model.id().as_str(),
            "options": catalog.models().iter().map(|model| json!({
                "value": model.id().as_str(),
                "displayName": model.display_name(),
            })).collect::<Vec<_>>(),
        }),
        json!({
            "configId": "thought_level",
            "category": "thought_level",
            "displayName": "Reasoning effort",
            "currentValue": effort_wire(first_model.supported_efforts()[0]),
            "options": first_model.supported_efforts().iter().map(|effort| json!({
                "value": effort_wire(*effort),
                "displayName": effort_display(*effort),
            })).collect::<Vec<_>>(),
        }),
        json!({
            "configId": "mode",
            "category": "mode",
            "displayName": "Permission mode",
            "currentValue": PermissionMode::Default.as_wire_str(),
            "options": PermissionMode::ALL.iter().map(|mode| json!({
                "value": mode.as_wire_str(),
                "displayName": mode_display(*mode),
            })).collect::<Vec<_>>(),
        }),
    ]
}

const fn effort_wire(effort: ReasoningEffort) -> &'static str {
    effort.as_codex_value()
}

const fn effort_display(effort: ReasoningEffort) -> &'static str {
    match effort {
        ReasoningEffort::Low => "Low",
        ReasoningEffort::Medium => "Medium",
        ReasoningEffort::High => "High",
        ReasoningEffort::XHigh => "Extra high",
        ReasoningEffort::Max => "Max",
        ReasoningEffort::Ultra => "Ultra",
    }
}

const fn mode_display(mode: PermissionMode) -> &'static str {
    match mode {
        PermissionMode::Plan => "Plan",
        PermissionMode::Default => "Default",
        PermissionMode::AcceptEdits => "Accept edits",
        PermissionMode::DontAsk => "Don't ask",
        PermissionMode::FullAccess => "Full access",
        PermissionMode::BypassPermissions => "Bypass permissions",
    }
}
