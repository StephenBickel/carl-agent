use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::delegates::{ModelId, ReasoningEffort, ResolvedDelegateSettings, SettingSource};
use crate::error::CarlError;

macro_rules! define_uuid_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self::from_uuid(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.as_uuid()
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self::from_uuid)
            }
        }
    };
}

define_uuid_id!(RunId);
define_uuid_id!(VerificationId);

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ArtifactId(String);

impl ArtifactId {
    pub fn parse(value: impl Into<String>) -> Result<Self, CarlError> {
        let value = value.into();
        let valid = value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !valid {
            return Err(validation_error(
                "artifact identifier is not a lowercase SHA-256 digest",
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ArtifactId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ArtifactId {
    type Err = CarlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for ArtifactId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(|_| D::Error::custom("invalid artifact identifier"))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Prepared,
    AwaitingDelegateApproval,
    Running,
    Inspecting,
    Verifying,
    AwaitingPromotionApproval,
    Promoted,
    CompletedNoChanges,
    Failed,
    Cancelled,
    Interrupted,
}

impl RunState {
    pub fn parse(value: &str) -> Result<Self, CarlError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "awaiting_delegate_approval" => Ok(Self::AwaitingDelegateApproval),
            "running" => Ok(Self::Running),
            "inspecting" => Ok(Self::Inspecting),
            "verifying" => Ok(Self::Verifying),
            "awaiting_promotion_approval" => Ok(Self::AwaitingPromotionApproval),
            "promoted" => Ok(Self::Promoted),
            "completed_no_changes" => Ok(Self::CompletedNoChanges),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "interrupted" => Ok(Self::Interrupted),
            _ => Err(validation_error("subscription run state is invalid")),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::AwaitingDelegateApproval => "awaiting_delegate_approval",
            Self::Running => "running",
            Self::Inspecting => "inspecting",
            Self::Verifying => "verifying",
            Self::AwaitingPromotionApproval => "awaiting_promotion_approval",
            Self::Promoted => "promoted",
            Self::CompletedNoChanges => "completed_no_changes",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Interrupted => "interrupted",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Promoted
                | Self::CompletedNoChanges
                | Self::Failed
                | Self::Cancelled
                | Self::Interrupted
        )
    }

    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        let forward = matches!(
            (self, next),
            (Self::Prepared, Self::AwaitingDelegateApproval)
                | (Self::AwaitingDelegateApproval, Self::Running)
                | (Self::Running, Self::Inspecting)
                | (Self::Inspecting, Self::Verifying | Self::CompletedNoChanges)
                | (Self::Verifying, Self::AwaitingPromotionApproval)
                | (Self::AwaitingPromotionApproval, Self::Promoted)
        );
        let terminal_exit = !self.is_terminal()
            && matches!(next, Self::Failed | Self::Cancelled | Self::Interrupted);
        forward || terminal_exit
    }
}

impl fmt::Display for RunState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RunState {
    type Err = CarlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunFailureCode {
    AuthenticationRequired,
    SubscriptionUnavailable,
    DelegateIncompatible,
    DelegateConfigurationFailed,
    DelegateStartFailed,
    DelegateProtocolFailed,
    DelegateBudgetExhausted,
    StageRejected,
    ProposalRejected,
    VerificationFailed,
    StaleWorkspace,
    PromotionFailed,
}

impl RunFailureCode {
    pub fn parse(value: &str) -> Result<Self, CarlError> {
        match value {
            "authentication_required" => Ok(Self::AuthenticationRequired),
            "subscription_unavailable" => Ok(Self::SubscriptionUnavailable),
            "delegate_incompatible" => Ok(Self::DelegateIncompatible),
            "delegate_configuration_failed" => Ok(Self::DelegateConfigurationFailed),
            "delegate_start_failed" => Ok(Self::DelegateStartFailed),
            "delegate_protocol_failed" => Ok(Self::DelegateProtocolFailed),
            "delegate_budget_exhausted" => Ok(Self::DelegateBudgetExhausted),
            "stage_rejected" => Ok(Self::StageRejected),
            "proposal_rejected" => Ok(Self::ProposalRejected),
            "verification_failed" => Ok(Self::VerificationFailed),
            "stale_workspace" => Ok(Self::StaleWorkspace),
            "promotion_failed" => Ok(Self::PromotionFailed),
            _ => Err(validation_error("subscription run failure code is invalid")),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "authentication_required",
            Self::SubscriptionUnavailable => "subscription_unavailable",
            Self::DelegateIncompatible => "delegate_incompatible",
            Self::DelegateConfigurationFailed => "delegate_configuration_failed",
            Self::DelegateStartFailed => "delegate_start_failed",
            Self::DelegateProtocolFailed => "delegate_protocol_failed",
            Self::DelegateBudgetExhausted => "delegate_budget_exhausted",
            Self::StageRejected => "stage_rejected",
            Self::ProposalRejected => "proposal_rejected",
            Self::VerificationFailed => "verification_failed",
            Self::StaleWorkspace => "stale_workspace",
            Self::PromotionFailed => "promotion_failed",
        }
    }
}

impl fmt::Display for RunFailureCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RunFailureCode {
    type Err = CarlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTrustLabel {
    TrustedCarlState,
    UntrustedProviderEvidence,
    TrustedCarlVerification,
    OwnerApproval,
    LiveWorkspaceMutationResult,
}

impl RunTrustLabel {
    pub fn parse(value: &str) -> Result<Self, CarlError> {
        match value {
            "trusted_carl_state" => Ok(Self::TrustedCarlState),
            "untrusted_provider_evidence" => Ok(Self::UntrustedProviderEvidence),
            "trusted_carl_verification" => Ok(Self::TrustedCarlVerification),
            "owner_approval" => Ok(Self::OwnerApproval),
            "live_workspace_mutation_result" => Ok(Self::LiveWorkspaceMutationResult),
            _ => Err(validation_error("subscription run trust label is invalid")),
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrustedCarlState => "trusted_carl_state",
            Self::UntrustedProviderEvidence => "untrusted_provider_evidence",
            Self::TrustedCarlVerification => "trusted_carl_verification",
            Self::OwnerApproval => "owner_approval",
            Self::LiveWorkspaceMutationResult => "live_workspace_mutation_result",
        }
    }
}

impl fmt::Display for RunTrustLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RunTrustLabel {
    type Err = CarlError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderReported<T> {
    Reported(T),
    NotReported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunConfigSnapshot {
    model: Option<ModelId>,
    model_source: SettingSource,
    effort: Option<ReasoningEffort>,
    effort_source: SettingSource,
    provider_reported_model: ProviderReported<ModelId>,
    provider_reported_effort: ProviderReported<ReasoningEffort>,
}

impl RunConfigSnapshot {
    #[must_use]
    pub fn from_resolved(settings: &ResolvedDelegateSettings) -> Self {
        Self::new(
            settings,
            ProviderReported::NotReported,
            ProviderReported::NotReported,
        )
    }

    #[must_use]
    pub fn new(
        settings: &ResolvedDelegateSettings,
        provider_reported_model: ProviderReported<ModelId>,
        provider_reported_effort: ProviderReported<ReasoningEffort>,
    ) -> Self {
        Self {
            model: settings.model().cloned(),
            model_source: settings.model_source(),
            effort: settings.effort(),
            effort_source: settings.effort_source(),
            provider_reported_model,
            provider_reported_effort,
        }
    }

    pub fn reconstruct(
        model: Option<ModelId>,
        model_source: SettingSource,
        effort: Option<ReasoningEffort>,
        effort_source: SettingSource,
        provider_reported_model: ProviderReported<ModelId>,
        provider_reported_effort: ProviderReported<ReasoningEffort>,
    ) -> Result<Self, CarlError> {
        if !valid_value_source_pair(model.is_some(), model_source)
            || !valid_value_source_pair(effort.is_some(), effort_source)
        {
            return Err(validation_error(
                "subscription run configuration provenance is invalid",
            ));
        }
        Ok(Self {
            model,
            model_source,
            effort,
            effort_source,
            provider_reported_model,
            provider_reported_effort,
        })
    }

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

    #[must_use]
    pub const fn provider_reported_model(&self) -> &ProviderReported<ModelId> {
        &self.provider_reported_model
    }

    #[must_use]
    pub const fn provider_model(&self) -> &ProviderReported<ModelId> {
        self.provider_reported_model()
    }

    #[must_use]
    pub const fn provider_reported_effort(&self) -> &ProviderReported<ReasoningEffort> {
        &self.provider_reported_effort
    }

    #[must_use]
    pub const fn provider_effort(&self) -> &ProviderReported<ReasoningEffort> {
        self.provider_reported_effort()
    }

    #[must_use]
    pub fn with_provider_reported(
        &self,
        provider_reported_model: ProviderReported<ModelId>,
        provider_reported_effort: ProviderReported<ReasoningEffort>,
    ) -> Self {
        Self {
            model: self.model.clone(),
            model_source: self.model_source,
            effort: self.effort,
            effort_source: self.effort_source,
            provider_reported_model,
            provider_reported_effort,
        }
    }
}

#[derive(Deserialize)]
struct RunConfigSnapshotWire {
    model: Option<ModelId>,
    model_source: SettingSource,
    effort: Option<ReasoningEffort>,
    effort_source: SettingSource,
    provider_reported_model: ProviderReported<ModelId>,
    provider_reported_effort: ProviderReported<ReasoningEffort>,
}

impl<'de> Deserialize<'de> for RunConfigSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RunConfigSnapshotWire::deserialize(deserializer)?;
        Self::reconstruct(
            wire.model,
            wire.model_source,
            wire.effort,
            wire.effort_source,
            wire.provider_reported_model,
            wire.provider_reported_effort,
        )
        .map_err(|_| D::Error::custom("invalid subscription run configuration"))
    }
}

const fn valid_value_source_pair(has_value: bool, source: SettingSource) -> bool {
    has_value != matches!(source, SettingSource::ProviderDefault)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RunTransition {
    from: RunState,
    to: RunState,
    failure_code: Option<RunFailureCode>,
}

impl RunTransition {
    pub fn new(
        from: RunState,
        to: RunState,
        failure_code: Option<RunFailureCode>,
    ) -> Result<Self, CarlError> {
        if !from.can_transition_to(to) {
            return Err(validation_error("subscription run transition is invalid"));
        }
        if (to == RunState::Failed) != failure_code.is_some() {
            return Err(validation_error(
                "subscription run failure code does not match its state",
            ));
        }
        Ok(Self {
            from,
            to,
            failure_code,
        })
    }

    #[must_use]
    pub const fn from(&self) -> RunState {
        self.from
    }

    #[must_use]
    pub const fn to(&self) -> RunState {
        self.to
    }

    #[must_use]
    pub const fn failure_code(&self) -> Option<RunFailureCode> {
        self.failure_code
    }
}

#[derive(Deserialize)]
struct RunTransitionWire {
    from: RunState,
    to: RunState,
    failure_code: Option<RunFailureCode>,
}

impl<'de> Deserialize<'de> for RunTransition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RunTransitionWire::deserialize(deserializer)?;
        Self::new(wire.from, wire.to, wire.failure_code)
            .map_err(|_| D::Error::custom("invalid subscription run transition"))
    }
}

fn validation_error(detail: &str) -> CarlError {
    CarlError::Validation {
        detail: detail.to_owned(),
    }
}
