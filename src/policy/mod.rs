mod capability;

pub use capability::{
    ActorId, ActorIdentity, CapabilityRequest, EnvironmentGrant, Frontend, ProviderNetwork,
    Sha256Digest,
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDisposition {
    Allow,
    Ask,
    Deny,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyReasonCode {
    ExternalAgentRequiresApproval,
    LiveWorkspaceExposure,
    EnvironmentGrantForbidden,
    ProviderNetworkMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    disposition: PolicyDisposition,
    reason: PolicyReasonCode,
}

impl PolicyDecision {
    const fn ask(reason: PolicyReasonCode) -> Self {
        Self {
            disposition: PolicyDisposition::Ask,
            reason,
        }
    }

    const fn deny(reason: PolicyReasonCode) -> Self {
        Self {
            disposition: PolicyDisposition::Deny,
            reason,
        }
    }

    #[must_use]
    pub const fn disposition(self) -> PolicyDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn reason(self) -> PolicyReasonCode {
        self.reason
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultPolicy;

impl DefaultPolicy {
    #[must_use]
    pub fn evaluate(self, request: &CapabilityRequest) -> PolicyDecision {
        if request.live_workspace_writable() {
            return PolicyDecision::deny(PolicyReasonCode::LiveWorkspaceExposure);
        }
        if !request.environment_grants().is_empty() {
            return PolicyDecision::deny(PolicyReasonCode::EnvironmentGrantForbidden);
        }
        if !request.provider_matches_tool() {
            return PolicyDecision::deny(PolicyReasonCode::ProviderNetworkMismatch);
        }
        PolicyDecision::ask(PolicyReasonCode::ExternalAgentRequiresApproval)
    }
}
