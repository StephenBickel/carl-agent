use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

use crate::auth::{AuthError, AuthErrorCode};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ErrorCode {
    #[serde(rename = "configuration_error")]
    Configuration,
    #[serde(rename = "authentication_error")]
    Authentication,
    #[serde(rename = "provider_error")]
    Provider,
    #[serde(rename = "rate_limit")]
    RateLimit,
    #[serde(rename = "policy_error")]
    Policy,
    #[serde(rename = "validation_error")]
    Validation,
    #[serde(rename = "tool_error")]
    Tool,
    #[serde(rename = "storage_error")]
    Storage,
    #[serde(rename = "channel_error")]
    Channel,
    #[serde(rename = "timeout")]
    Timeout,
    #[serde(rename = "cancelled")]
    Cancelled,
    #[serde(rename = "budget_exceeded")]
    BudgetExceeded,
}

impl ErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Configuration => "configuration_error",
            Self::Authentication => "authentication_error",
            Self::Provider => "provider_error",
            Self::RateLimit => "rate_limit",
            Self::Policy => "policy_error",
            Self::Validation => "validation_error",
            Self::Tool => "tool_error",
            Self::Storage => "storage_error",
            Self::Channel => "channel_error",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
            Self::BudgetExceeded => "budget_exceeded",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetResource {
    Iterations,
    ToolCalls,
}

impl fmt::Display for BudgetResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Iterations => formatter.write_str("iterations"),
            Self::ToolCalls => formatter.write_str("tool calls"),
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CarlError {
    #[error("Carl's configuration is invalid.")]
    Configuration { detail: String },
    #[error("Authentication failed.")]
    Authentication { detail: String },
    #[error("The model provider request failed.")]
    Provider { detail: String },
    #[error("The model provider is temporarily rate limited.")]
    RateLimit { detail: String },
    #[error("The requested action is not allowed.")]
    Policy { detail: String },
    #[error("The request is invalid.")]
    Validation { detail: String },
    #[error("The tool failed.")]
    Tool { detail: String },
    #[error("Carl could not access its local data.")]
    Storage { detail: String },
    #[error("The frontend connection failed.")]
    Channel { detail: String },
    #[error("The operation timed out.")]
    Timeout { detail: String },
    #[error("The operation was cancelled.")]
    Cancelled { detail: String },
    #[error("The turn reached its configured budget.")]
    BudgetExceeded {
        resource: BudgetResource,
        limit: u32,
    },
}

impl CarlError {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Configuration { .. } => ErrorCode::Configuration,
            Self::Authentication { .. } => ErrorCode::Authentication,
            Self::Provider { .. } => ErrorCode::Provider,
            Self::RateLimit { .. } => ErrorCode::RateLimit,
            Self::Policy { .. } => ErrorCode::Policy,
            Self::Validation { .. } => ErrorCode::Validation,
            Self::Tool { .. } => ErrorCode::Tool,
            Self::Storage { .. } => ErrorCode::Storage,
            Self::Channel { .. } => ErrorCode::Channel,
            Self::Timeout { .. } => ErrorCode::Timeout,
            Self::Cancelled { .. } => ErrorCode::Cancelled,
            Self::BudgetExceeded { .. } => ErrorCode::BudgetExceeded,
        }
    }

    #[must_use]
    pub const fn user_message(&self) -> &'static str {
        match self {
            Self::Configuration { .. } => "Carl's configuration is invalid.",
            Self::Authentication { .. } => "Authentication failed.",
            Self::Provider { .. } => "The model provider request failed.",
            Self::RateLimit { .. } => "The model provider is temporarily rate limited.",
            Self::Policy { .. } => "The requested action is not allowed.",
            Self::Validation { .. } => "The request is invalid.",
            Self::Tool { .. } => "The tool failed.",
            Self::Storage { .. } => "Carl could not access its local data.",
            Self::Channel { .. } => "The frontend connection failed.",
            Self::Timeout { .. } => "The operation timed out.",
            Self::Cancelled { .. } => "The operation was cancelled.",
            Self::BudgetExceeded { .. } => "The turn reached its configured budget.",
        }
    }
}

impl From<AuthError> for CarlError {
    fn from(error: AuthError) -> Self {
        match error.code() {
            AuthErrorCode::InvalidAuthorizationUrl | AuthErrorCode::InvalidUserCode => {
                Self::Validation {
                    detail: "The subscription login challenge is invalid.".into(),
                }
            }
            AuthErrorCode::ExecutableMissing | AuthErrorCode::UnsupportedVersion => {
                Self::Configuration {
                    detail: "The subscription authentication sidecar is unavailable.".into(),
                }
            }
            AuthErrorCode::TimedOut => Self::Timeout {
                detail: "Subscription authentication timed out.".into(),
            },
            AuthErrorCode::Cancelled => Self::Cancelled {
                detail: "Subscription authentication was cancelled.".into(),
            },
            AuthErrorCode::ForegroundRequired => Self::Channel {
                detail: "Subscription login requires a local foreground terminal.".into(),
            },
            AuthErrorCode::KeyringUnavailable
            | AuthErrorCode::ProtocolMismatch
            | AuthErrorCode::ProviderRejected
            | AuthErrorCode::UnsafeCredentialStore
            | AuthErrorCode::SidecarExited => Self::Authentication {
                detail: "The subscription authentication sidecar failed.".into(),
            },
        }
    }
}
