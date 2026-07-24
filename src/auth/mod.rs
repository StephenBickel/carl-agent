use std::collections::HashSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use url::Url;

pub mod codex;
pub mod grok;

const MAX_AUTHORIZATION_URL_BYTES: usize = 8_192;
const MAX_USER_CODE_BYTES: usize = 128;
const INVALID_AUTH_DATA: &str = "invalid subscription authentication data";

// Positive allowlist for non-secret OAuth authorization/navigation parameters.
//
// The first group is the standard authorization request surface Carl needs. The final
// four are emitted by the current Codex login server, including its conditional
// `allowed_workspace_id` parameter:
// https://github.com/openai/codex/blob/main/codex-rs/login/src/server.rs
//
// Keep this list exact. Token, API-key, secret, credential, login-hint, and arbitrary
// navigation aliases must continue to fail closed.
const ALLOWED_AUTHORIZATION_QUERY_KEYS: &[&str] = &[
    "client_id",
    "state",
    "response_type",
    "redirect_uri",
    "scope",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "prompt",
    "audience",
    "resource",
    "id_token_add_organizations",
    "codex_cli_simplified_flow",
    "originator",
    "allowed_workspace_id",
];

pub type AuthFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AuthError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum SubscriptionService {
    #[serde(rename = "openai_codex")]
    OpenAiCodex,
    #[serde(rename = "xai_grok")]
    XaiGrok,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum AuthMethod {
    #[serde(rename = "browser_oauth")]
    BrowserOAuth,
    #[serde(rename = "device_code")]
    DeviceCode,
    #[serde(rename = "provider_managed")]
    ProviderManaged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum SubscriptionPlan {
    #[serde(rename = "free")]
    Free,
    #[serde(rename = "go")]
    Go,
    #[serde(rename = "plus")]
    Plus,
    #[serde(rename = "pro")]
    Pro,
    #[serde(rename = "pro_lite")]
    ProLite,
    #[serde(rename = "team")]
    Team,
    #[serde(rename = "business")]
    Business,
    #[serde(rename = "enterprise")]
    Enterprise,
    #[serde(rename = "education")]
    Education,
    #[serde(rename = "super_grok")]
    SuperGrok,
    #[serde(rename = "x_premium")]
    XPremium,
    #[serde(rename = "x_premium_plus")]
    XPremiumPlus,
    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum AuthUnavailableCode {
    #[serde(rename = "executable_missing")]
    ExecutableMissing,
    #[serde(rename = "unsupported_version")]
    UnsupportedVersion,
    #[serde(rename = "keyring_unavailable")]
    KeyringUnavailable,
    #[serde(rename = "protocol_mismatch")]
    ProtocolMismatch,
    #[serde(rename = "provider_rejected")]
    ProviderRejected,
    #[serde(rename = "foreground_required")]
    ForegroundRequired,
    #[serde(rename = "unsafe_credential_store")]
    UnsafeCredentialStore,
    #[serde(rename = "timed_out")]
    TimedOut,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthState {
    SignedOut,
    Pending,
    SignedIn {
        method: AuthMethod,
        plan: Option<SubscriptionPlan>,
    },
    Unavailable {
        code: AuthUnavailableCode,
    },
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum AuthStateWire {
    SignedOut {},
    Pending {},
    SignedIn {
        method: AuthMethod,
        plan: Option<SubscriptionPlan>,
    },
    Unavailable {
        code: AuthUnavailableCode,
    },
}

impl<'de> Deserialize<'de> for AuthState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = AuthStateWire::deserialize(deserializer)
            .map_err(|_| D::Error::custom(INVALID_AUTH_DATA))?;
        match wire {
            AuthStateWire::SignedOut {} => Ok(Self::SignedOut),
            AuthStateWire::Pending {} => Ok(Self::Pending),
            AuthStateWire::SignedIn { method, plan } => Ok(Self::SignedIn { method, plan }),
            AuthStateWire::Unavailable { code } => Ok(Self::Unavailable { code }),
        }
    }
}

#[derive(Eq, PartialEq)]
pub struct AuthorizationUrl(Url);

impl AuthorizationUrl {
    pub fn parse(value: &str) -> Result<Self, AuthError> {
        if value.is_empty()
            || value.len() > MAX_AUTHORIZATION_URL_BYTES
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(AuthError::from_code(AuthErrorCode::InvalidAuthorizationUrl));
        }

        let url = Url::parse(value)
            .map_err(|_| AuthError::from_code(AuthErrorCode::InvalidAuthorizationUrl))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || contains_disallowed_authorization_query(&url)
        {
            return Err(AuthError::from_code(AuthErrorCode::InvalidAuthorizationUrl));
        }

        Ok(Self(url))
    }

    #[must_use]
    pub fn into_foreground_string(self) -> String {
        self.0.to_string()
    }
}

fn contains_disallowed_authorization_query(url: &Url) -> bool {
    let mut seen_keys = HashSet::new();
    url.query_pairs().any(|(key, value)| {
        !seen_keys.insert(key.as_ref().to_owned())
            || !ALLOWED_AUTHORIZATION_QUERY_KEYS.contains(&key.as_ref())
            || starts_with_bearer_credential(&value)
    })
}

fn starts_with_bearer_credential(value: &str) -> bool {
    let value = value.trim_start_matches(|character: char| character.is_ascii_whitespace());
    value
        .as_bytes()
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"bearer "))
}

impl fmt::Debug for AuthorizationUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationUrl(<redacted>)")
    }
}

#[derive(Eq, PartialEq)]
pub struct UserCode(String);

impl UserCode {
    pub fn parse(value: &str) -> Result<Self, AuthError> {
        if value.is_empty()
            || value.len() > MAX_USER_CODE_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(AuthError::from_code(AuthErrorCode::InvalidUserCode));
        }

        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn into_foreground_string(self) -> String {
        self.0
    }
}

impl fmt::Debug for UserCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UserCode(<redacted>)")
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum LoginChallenge {
    Browser {
        authorization_url: AuthorizationUrl,
    },
    Device {
        verification_url: AuthorizationUrl,
        user_code: UserCode,
    },
    /// The provider owns the foreground terminal ceremony and exposes no credential
    /// material or navigation target to Carl.
    ProviderManaged,
}

pub trait SubscriptionAuthBroker: Send {
    fn service(&self) -> SubscriptionService;

    fn auth_state(&mut self) -> AuthFuture<'_, AuthState>;

    fn start_login(&mut self, method: AuthMethod) -> AuthFuture<'_, LoginChallenge>;

    fn logout(&mut self) -> AuthFuture<'_, ()>;

    fn cancel_login(&mut self) -> AuthFuture<'_, ()>;

    /// Boundedly stop and reap every provider process owned by this broker.
    fn shutdown(&mut self) -> AuthFuture<'_, ()>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum AuthErrorCode {
    #[serde(rename = "invalid_authorization_url")]
    InvalidAuthorizationUrl,
    #[serde(rename = "invalid_user_code")]
    InvalidUserCode,
    #[serde(rename = "executable_missing")]
    ExecutableMissing,
    #[serde(rename = "unsupported_version")]
    UnsupportedVersion,
    #[serde(rename = "keyring_unavailable")]
    KeyringUnavailable,
    #[serde(rename = "protocol_mismatch")]
    ProtocolMismatch,
    #[serde(rename = "provider_rejected")]
    ProviderRejected,
    #[serde(rename = "foreground_required")]
    ForegroundRequired,
    #[serde(rename = "unsafe_credential_store")]
    UnsafeCredentialStore,
    #[serde(rename = "timed_out")]
    TimedOut,
    #[serde(rename = "cancelled")]
    Cancelled,
    #[serde(rename = "sidecar_exited")]
    SidecarExited,
}

impl AuthErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidAuthorizationUrl => "invalid_authorization_url",
            Self::InvalidUserCode => "invalid_user_code",
            Self::ExecutableMissing => "executable_missing",
            Self::UnsupportedVersion => "unsupported_version",
            Self::KeyringUnavailable => "keyring_unavailable",
            Self::ProtocolMismatch => "protocol_mismatch",
            Self::ProviderRejected => "provider_rejected",
            Self::ForegroundRequired => "foreground_required",
            Self::UnsafeCredentialStore => "unsafe_credential_store",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::SidecarExited => "sidecar_exited",
        }
    }
}

impl fmt::Display for AuthErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
#[error("subscription authentication failed: {code}")]
#[serde(transparent)]
pub struct AuthError {
    code: AuthErrorCode,
}

impl AuthError {
    #[must_use]
    pub const fn from_code(code: AuthErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(&self) -> AuthErrorCode {
        self.code
    }
}

impl From<AuthUnavailableCode> for AuthErrorCode {
    fn from(code: AuthUnavailableCode) -> Self {
        match code {
            AuthUnavailableCode::ExecutableMissing => Self::ExecutableMissing,
            AuthUnavailableCode::UnsupportedVersion => Self::UnsupportedVersion,
            AuthUnavailableCode::KeyringUnavailable => Self::KeyringUnavailable,
            AuthUnavailableCode::ProtocolMismatch => Self::ProtocolMismatch,
            AuthUnavailableCode::ProviderRejected => Self::ProviderRejected,
            AuthUnavailableCode::ForegroundRequired => Self::ForegroundRequired,
            AuthUnavailableCode::UnsafeCredentialStore => Self::UnsafeCredentialStore,
            AuthUnavailableCode::TimedOut => Self::TimedOut,
        }
    }
}

impl From<AuthUnavailableCode> for AuthError {
    fn from(code: AuthUnavailableCode) -> Self {
        Self::from_code(code.into())
    }
}

fn deserialize_closed_auth_enum<'de, D, T>(
    deserializer: D,
    parse: impl FnOnce(&str) -> Option<T>,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    let value =
        String::deserialize(deserializer).map_err(|_| D::Error::custom(INVALID_AUTH_DATA))?;
    parse(&value).ok_or_else(|| D::Error::custom(INVALID_AUTH_DATA))
}

macro_rules! impl_closed_auth_deserialize {
    ($type:ty, $($wire_value:literal => $variant:path),+ $(,)?) => {
        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserialize_closed_auth_enum(deserializer, |value| match value {
                    $($wire_value => Some($variant),)+
                    _ => None,
                })
            }
        }
    };
}

impl_closed_auth_deserialize!(
    SubscriptionService,
    "openai_codex" => SubscriptionService::OpenAiCodex,
    "xai_grok" => SubscriptionService::XaiGrok,
);

impl_closed_auth_deserialize!(
    AuthMethod,
    "browser_oauth" => AuthMethod::BrowserOAuth,
    "device_code" => AuthMethod::DeviceCode,
    "provider_managed" => AuthMethod::ProviderManaged,
);

impl_closed_auth_deserialize!(
    SubscriptionPlan,
    "free" => SubscriptionPlan::Free,
    "go" => SubscriptionPlan::Go,
    "plus" => SubscriptionPlan::Plus,
    "pro" => SubscriptionPlan::Pro,
    "pro_lite" => SubscriptionPlan::ProLite,
    "team" => SubscriptionPlan::Team,
    "business" => SubscriptionPlan::Business,
    "enterprise" => SubscriptionPlan::Enterprise,
    "education" => SubscriptionPlan::Education,
    "super_grok" => SubscriptionPlan::SuperGrok,
    "x_premium" => SubscriptionPlan::XPremium,
    "x_premium_plus" => SubscriptionPlan::XPremiumPlus,
    "unknown" => SubscriptionPlan::Unknown,
);

impl_closed_auth_deserialize!(
    AuthUnavailableCode,
    "executable_missing" => AuthUnavailableCode::ExecutableMissing,
    "unsupported_version" => AuthUnavailableCode::UnsupportedVersion,
    "keyring_unavailable" => AuthUnavailableCode::KeyringUnavailable,
    "protocol_mismatch" => AuthUnavailableCode::ProtocolMismatch,
    "provider_rejected" => AuthUnavailableCode::ProviderRejected,
    "foreground_required" => AuthUnavailableCode::ForegroundRequired,
    "unsafe_credential_store" => AuthUnavailableCode::UnsafeCredentialStore,
    "timed_out" => AuthUnavailableCode::TimedOut,
);

impl_closed_auth_deserialize!(
    AuthErrorCode,
    "invalid_authorization_url" => AuthErrorCode::InvalidAuthorizationUrl,
    "invalid_user_code" => AuthErrorCode::InvalidUserCode,
    "executable_missing" => AuthErrorCode::ExecutableMissing,
    "unsupported_version" => AuthErrorCode::UnsupportedVersion,
    "keyring_unavailable" => AuthErrorCode::KeyringUnavailable,
    "protocol_mismatch" => AuthErrorCode::ProtocolMismatch,
    "provider_rejected" => AuthErrorCode::ProviderRejected,
    "foreground_required" => AuthErrorCode::ForegroundRequired,
    "unsafe_credential_store" => AuthErrorCode::UnsafeCredentialStore,
    "timed_out" => AuthErrorCode::TimedOut,
    "cancelled" => AuthErrorCode::Cancelled,
    "sidecar_exited" => AuthErrorCode::SidecarExited,
);
