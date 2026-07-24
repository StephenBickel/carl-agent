use std::fmt;

use carl::auth::{
    AuthError, AuthErrorCode, AuthFuture, AuthMethod, AuthState, AuthUnavailableCode,
    AuthorizationUrl, LoginChallenge, SubscriptionAuthBroker, SubscriptionPlan,
    SubscriptionService, UserCode,
};
use carl::error::{CarlError, ErrorCode};
use carl::events::Event;
use serde_json::{Value, json};

macro_rules! assert_not_impl {
    ($type:ty: $trait:path) => {
        const _: fn() = || {
            trait AmbiguousIfImplemented<A> {
                fn marker() {}
            }

            impl<T: ?Sized> AmbiguousIfImplemented<()> for T {}

            struct TraitMarker;
            impl<T: ?Sized + $trait> AmbiguousIfImplemented<TraitMarker> for T {}

            let _ = <$type as AmbiguousIfImplemented<_>>::marker;
        };
    };
}

assert_not_impl!(AuthorizationUrl: fmt::Display);
assert_not_impl!(AuthorizationUrl: serde::Serialize);
assert_not_impl!(UserCode: fmt::Display);
assert_not_impl!(UserCode: serde::Serialize);
assert_not_impl!(LoginChallenge: serde::Serialize);

const ACCOUNT_EMAIL: &str = "stephen@example.test";
const OAUTH_QUERY: &str = "client_id=carl-review&state=oauth-state-secret";
const BEARER_TOKEN: &str = "Bearer access-token-secret";
const REFRESH_TOKEN: &str = "refresh-token-secret";
const COOKIE: &str = "session_cookie=cookie-secret";
const USER_CODE: &str = "CARL-WREN";
const CREDENTIAL_PATH: &str = "/Users/stephen/.codex/auth.json";
const CURRENT_CODEX_AUTHORIZATION_URL: &str = concat!(
    "https://auth.openai.com/oauth/authorize?",
    "client_id=codex-public-client",
    "&state=oauth-state-secret",
    "&response_type=code",
    "&redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback",
    "&scope=openid%20profile%20email%20offline_access",
    "&code_challenge=challenge-value",
    "&code_challenge_method=S256",
    "&nonce=nonce-value",
    "&prompt=login",
    "&audience=https%3A%2F%2Fapi.openai.com",
    "&resource=https%3A%2F%2Fapi.openai.com",
    "&id_token_add_organizations=true",
    "&codex_cli_simplified_flow=true",
    "&originator=codex_cli_rs",
    "&allowed_workspace_id=workspace-id",
);
const SENTINELS: [&str; 7] = [
    ACCOUNT_EMAIL,
    OAUTH_QUERY,
    BEARER_TOKEN,
    REFRESH_TOKEN,
    COOKIE,
    USER_CODE,
    CREDENTIAL_PATH,
];

#[test]
fn domain_auth_state_has_a_closed_provider_neutral_wire_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (AuthState::SignedOut, json!({"state": "signed_out"})),
        (AuthState::Pending, json!({"state": "pending"})),
        (
            AuthState::SignedIn {
                method: AuthMethod::BrowserOAuth,
                plan: Some(SubscriptionPlan::Plus),
            },
            json!({
                "state": "signed_in",
                "method": "browser_oauth",
                "plan": "plus",
            }),
        ),
        (
            AuthState::Unavailable {
                code: AuthUnavailableCode::UnsupportedVersion,
            },
            json!({
                "state": "unavailable",
                "code": "unsupported_version",
            }),
        ),
    ];

    for (state, expected) in &cases {
        assert_eq!(serde_json::to_value(state)?, *expected);
        assert_eq!(
            serde_json::from_value::<AuthState>(expected.clone())?,
            *state
        );
    }

    let states: Vec<_> = cases.iter().map(|(state, _)| *state).collect();
    let serialized = serde_json::to_string(&states)?;
    let debug = format!("{states:?}");
    assert_contains_no_sentinel(&serialized);
    assert_contains_no_sentinel(&debug);

    for forbidden in [
        json!({"state": "signed_in", "method": "browser_oauth", "account_email": ACCOUNT_EMAIL}),
        json!({"state": "signed_in", "method": "browser_oauth", "access_token": BEARER_TOKEN}),
        json!({"state": "pending", "credential_path": CREDENTIAL_PATH}),
        json!({"state": "signed_in", "method": "private_provider_method"}),
        json!({"state": "signed_in", "method": "browser_oauth", "plan": "private_provider_plan"}),
        json!({"state": "unavailable", "code": "provider_stack_trace"}),
    ] {
        assert!(
            serde_json::from_value::<AuthState>(forbidden.clone()).is_err(),
            "accepted forbidden provider field or value: {forbidden}"
        );
    }

    Ok(())
}

#[test]
fn domain_closed_enums_have_stable_wire_values() -> Result<(), Box<dyn std::error::Error>> {
    assert_wire_values(
        &[
            SubscriptionService::OpenAiCodex,
            SubscriptionService::XaiGrok,
        ],
        &["openai_codex", "xai_grok"],
    )?;
    assert_wire_values(
        &[
            AuthMethod::BrowserOAuth,
            AuthMethod::DeviceCode,
            AuthMethod::ProviderManaged,
        ],
        &["browser_oauth", "device_code", "provider_managed"],
    )?;
    assert_wire_values(
        &[
            SubscriptionPlan::Free,
            SubscriptionPlan::Go,
            SubscriptionPlan::Plus,
            SubscriptionPlan::Pro,
            SubscriptionPlan::ProLite,
            SubscriptionPlan::Team,
            SubscriptionPlan::Business,
            SubscriptionPlan::Enterprise,
            SubscriptionPlan::Education,
            SubscriptionPlan::SuperGrok,
            SubscriptionPlan::XPremium,
            SubscriptionPlan::XPremiumPlus,
            SubscriptionPlan::Unknown,
        ],
        &[
            "free",
            "go",
            "plus",
            "pro",
            "pro_lite",
            "team",
            "business",
            "enterprise",
            "education",
            "super_grok",
            "x_premium",
            "x_premium_plus",
            "unknown",
        ],
    )?;
    assert_wire_values(
        &[
            AuthUnavailableCode::ExecutableMissing,
            AuthUnavailableCode::UnsupportedVersion,
            AuthUnavailableCode::KeyringUnavailable,
            AuthUnavailableCode::ProtocolMismatch,
            AuthUnavailableCode::ProviderRejected,
            AuthUnavailableCode::ForegroundRequired,
            AuthUnavailableCode::UnsafeCredentialStore,
            AuthUnavailableCode::TimedOut,
        ],
        &[
            "executable_missing",
            "unsupported_version",
            "keyring_unavailable",
            "protocol_mismatch",
            "provider_rejected",
            "foreground_required",
            "unsafe_credential_store",
            "timed_out",
        ],
    )?;

    Ok(())
}

#[test]
fn domain_login_challenge_is_redacted_until_explicitly_consumed()
-> Result<(), Box<dyn std::error::Error>> {
    let browser_url = format!("https://auth.example.test/oauth/authorize?{OAUTH_QUERY}");
    let browser = LoginChallenge::Browser {
        authorization_url: AuthorizationUrl::parse(&browser_url)?,
    };
    let browser_debug = format!("{browser:?}");
    assert_contains_no_sentinel(&browser_debug);
    assert!(browser_debug.contains("<redacted>"));

    let LoginChallenge::Browser { authorization_url } = browser else {
        unreachable!("constructed the browser challenge")
    };
    assert_eq!(
        authorization_url.into_foreground_string(),
        browser_url,
        "foreground login is the only intentional URL reveal"
    );

    let verification_url = format!("https://device.example.test/activate?{OAUTH_QUERY}");
    let device = LoginChallenge::Device {
        verification_url: AuthorizationUrl::parse(&verification_url)?,
        user_code: UserCode::parse(USER_CODE)?,
    };
    let device_debug = format!("{device:?}");
    assert_contains_no_sentinel(&device_debug);
    assert_eq!(
        device_debug,
        "Device { verification_url: AuthorizationUrl(<redacted>), user_code: UserCode(<redacted>) }"
    );

    let LoginChallenge::Device {
        verification_url,
        user_code,
    } = device
    else {
        unreachable!("constructed the device challenge")
    };
    assert_eq!(
        verification_url.into_foreground_string(),
        verification_url_string()
    );
    assert_eq!(user_code.into_foreground_string(), USER_CODE);

    let provider_managed = LoginChallenge::ProviderManaged;
    assert_eq!(
        format!("{provider_managed:?}"),
        "ProviderManaged",
        "the terminal-owned challenge must remain fieldless"
    );

    Ok(())
}

#[test]
fn domain_foreground_values_reject_unsafe_or_ambiguous_input() {
    for invalid in [
        "",
        "not a URL",
        "http://auth.example.test/login",
        "ftp://auth.example.test/login",
        "https://user:password@auth.example.test/login",
        "https://auth.example.test/login#access-token-secret",
        "https://auth.example.test/login?state=contains raw whitespace",
        "https://auth.example.test/login?access_token=access-token-secret",
        "https://auth.example.test/login?ACCESS%5FTOKEN=access-token-secret",
        "https://auth.example.test/login?refresh-token=refresh-token-secret",
        "https://auth.example.test/login?id%5Ftoken=id-token-secret",
        "https://auth.example.test/login?state=first&st%61te=second",
        "https://auth.example.test/login?Authorization=Basic%20credential-secret",
        "https://auth.example.test/login?cookie=cookie-secret",
        "https://auth.example.test/login?Set%2DCookie=cookie-secret",
        "https://auth.example.test/login?SESSION_COOKIE=cookie-secret",
        "https://auth.example.test/login?state=bEaReR%20access-token-secret",
        "https://auth.example.test/login?state=%20Bearer+access-token-secret",
        "https://auth.example.test/login?token=access-token-secret",
        "https://auth.example.test/login?api_key=api-key-secret",
        "https://auth.example.test/login?api%5Fkey=api-key-secret",
        "https://auth.example.test/login?id_token_hint=id-token-secret",
        "https://auth.example.test/login?client_secret=client-secret",
        "https://auth.example.test/login?secret=secret-value",
        "https://auth.example.test/login?credential=credential-value",
        "https://auth.example.test/login?credentials=credential-value",
        "https://auth.example.test/login?unknown_parameter=value",
        "https://auth.example.test/login?utm_source=codex",
    ] {
        let error = AuthorizationUrl::parse(invalid).unwrap_err();
        assert_eq!(error.code(), AuthErrorCode::InvalidAuthorizationUrl);
        for diagnostic in [format!("{error:?}"), error.to_string()] {
            assert_contains_no_sentinel(&diagnostic);
            if !invalid.is_empty() {
                assert!(!diagnostic.contains(invalid));
            }
        }
    }
    let oversized_url = format!(
        "https://auth.example.test/login?value={}",
        "x".repeat(8_193)
    );
    assert_eq!(
        AuthorizationUrl::parse(&oversized_url).unwrap_err().code(),
        AuthErrorCode::InvalidAuthorizationUrl
    );

    for invalid in ["", " ", " CODE-123 ", "CODE\n123", "CØDE", "CODE/123"] {
        let error = UserCode::parse(invalid).unwrap_err();
        assert_eq!(error.code(), AuthErrorCode::InvalidUserCode);
        assert_contains_no_sentinel(&format!("{error:?}"));
    }
    assert_eq!(
        UserCode::parse(&"A".repeat(129)).unwrap_err().code(),
        AuthErrorCode::InvalidUserCode
    );
    assert_eq!(
        UserCode::parse("ABCD-1234")
            .expect("human-readable provider code is accepted")
            .into_foreground_string(),
        "ABCD-1234"
    );

    assert_eq!(
        AuthorizationUrl::parse(CURRENT_CODEX_AUTHORIZATION_URL)
            .expect("the current non-secret Codex authorization parameters are supported")
            .into_foreground_string(),
        CURRENT_CODEX_AUTHORIZATION_URL
    );
}

#[test]
fn domain_closed_auth_deserialization_errors_are_static_and_sanitized() {
    assert_static_auth_deserialization_error::<SubscriptionService>(json!(ACCOUNT_EMAIL));
    assert_static_auth_deserialization_error::<AuthMethod>(json!(BEARER_TOKEN));
    assert_static_auth_deserialization_error::<SubscriptionPlan>(json!(REFRESH_TOKEN));
    assert_static_auth_deserialization_error::<AuthUnavailableCode>(json!(COOKIE));
    assert_static_auth_deserialization_error::<AuthErrorCode>(json!(CREDENTIAL_PATH));
    assert_static_auth_deserialization_error::<AuthError>(json!(USER_CODE));

    for hostile_state in [
        json!({"state": ACCOUNT_EMAIL}),
        json!({"state": "signed_in", "method": BEARER_TOKEN}),
        json!({"state": "signed_in", "method": "browser_oauth", "plan": REFRESH_TOKEN}),
        json!({"state": "unavailable", "code": COOKIE}),
        json!({"state": "pending", "/Users/stephen/.codex/auth.json": USER_CODE}),
    ] {
        assert_static_auth_deserialization_error::<AuthState>(hostile_state);
    }
}

#[test]
fn domain_auth_errors_are_typed_serializable_and_sanitized()
-> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            AuthErrorCode::InvalidAuthorizationUrl,
            ErrorCode::Validation,
        ),
        (AuthErrorCode::InvalidUserCode, ErrorCode::Validation),
        (AuthErrorCode::ExecutableMissing, ErrorCode::Configuration),
        (AuthErrorCode::UnsupportedVersion, ErrorCode::Configuration),
        (AuthErrorCode::KeyringUnavailable, ErrorCode::Authentication),
        (AuthErrorCode::ProtocolMismatch, ErrorCode::Authentication),
        (AuthErrorCode::ProviderRejected, ErrorCode::Authentication),
        (AuthErrorCode::ForegroundRequired, ErrorCode::Channel),
        (
            AuthErrorCode::UnsafeCredentialStore,
            ErrorCode::Authentication,
        ),
        (AuthErrorCode::TimedOut, ErrorCode::Timeout),
        (AuthErrorCode::Cancelled, ErrorCode::Cancelled),
        (AuthErrorCode::SidecarExited, ErrorCode::Authentication),
    ];

    for (code, expected_carl_code) in cases {
        let hostile_provider_error = hostile_provider_error();
        let error = map_hostile_provider_error(hostile_provider_error, code);
        assert_eq!(error.code(), code);
        assert_eq!(
            serde_json::to_value(error)?,
            Value::String(code.as_str().into())
        );

        let diagnostics = [
            format!("{error:?}"),
            error.to_string(),
            serde_json::to_string(&error)?,
        ];
        for diagnostic in diagnostics {
            assert_contains_no_sentinel(&diagnostic);
        }

        let carl_error = CarlError::from(error);
        assert_eq!(carl_error.code(), expected_carl_code);
        for diagnostic in [
            format!("{carl_error:?}"),
            carl_error.to_string(),
            carl_error.user_message().into(),
        ] {
            assert_contains_no_sentinel(&diagnostic);
        }
    }

    Ok(())
}

#[test]
fn domain_unavailable_codes_convert_without_provider_details() {
    let cases = [
        (
            AuthUnavailableCode::ExecutableMissing,
            AuthErrorCode::ExecutableMissing,
        ),
        (
            AuthUnavailableCode::UnsupportedVersion,
            AuthErrorCode::UnsupportedVersion,
        ),
        (
            AuthUnavailableCode::KeyringUnavailable,
            AuthErrorCode::KeyringUnavailable,
        ),
        (
            AuthUnavailableCode::ProtocolMismatch,
            AuthErrorCode::ProtocolMismatch,
        ),
        (
            AuthUnavailableCode::ProviderRejected,
            AuthErrorCode::ProviderRejected,
        ),
        (
            AuthUnavailableCode::ForegroundRequired,
            AuthErrorCode::ForegroundRequired,
        ),
        (
            AuthUnavailableCode::UnsafeCredentialStore,
            AuthErrorCode::UnsafeCredentialStore,
        ),
        (AuthUnavailableCode::TimedOut, AuthErrorCode::TimedOut),
    ];

    for (unavailable, expected) in cases {
        let error = AuthError::from(unavailable);
        assert_eq!(error.code(), expected);
        assert_contains_no_sentinel(&format!("{error:?}"));
    }
}

#[tokio::test]
async fn domain_broker_contract_is_provider_neutral_and_send() {
    let mut broker = FakeBroker {
        state: AuthState::SignedOut,
    };
    assert_send(&broker);
    assert_eq!(broker.service(), SubscriptionService::OpenAiCodex);
    assert_eq!(broker.auth_state().await.unwrap(), AuthState::SignedOut);

    let challenge = broker
        .start_login(AuthMethod::DeviceCode)
        .await
        .expect("fake starts a device login");
    assert_eq!(
        broker.auth_state().await.unwrap(),
        AuthState::Pending,
        "the broker owns its queried state"
    );
    let LoginChallenge::Device {
        verification_url,
        user_code,
    } = challenge
    else {
        panic!("expected a device challenge")
    };
    assert_eq!(
        verification_url.into_foreground_string(),
        "https://device.example.test/activate"
    );
    assert_eq!(user_code.into_foreground_string(), "CARL-1234");

    broker.cancel_login().await.unwrap();
    assert_eq!(broker.auth_state().await.unwrap(), AuthState::SignedOut);
    broker.logout().await.unwrap();
}

#[test]
fn domain_auth_state_is_not_a_session_event() {
    let attempted_event = json!({
        "schema_version": 1,
        "type": "auth_state",
        "state": "signed_in",
        "method": "browser_oauth",
    });

    assert!(
        serde_json::from_value::<Event>(attempted_event).is_err(),
        "authentication state is queried from the broker, never journaled"
    );
}

fn verification_url_string() -> String {
    format!("https://device.example.test/activate?{OAUTH_QUERY}")
}

fn hostile_provider_error() -> &'static str {
    concat!(
        "account=stephen@example.test ",
        "client_id=carl-review&state=oauth-state-secret ",
        "Bearer access-token-secret ",
        "refresh-token-secret ",
        "session_cookie=cookie-secret ",
        "CARL-WREN ",
        "/Users/stephen/.codex/auth.json"
    )
}

fn map_hostile_provider_error(_provider_detail: &str, code: AuthErrorCode) -> AuthError {
    AuthError::from_code(code)
}

fn assert_contains_no_sentinel(value: &str) {
    for sentinel in SENTINELS {
        assert!(
            !value.contains(sentinel),
            "diagnostic exposed secret sentinel {sentinel:?}: {value}"
        );
    }
}

fn assert_wire_values<T>(
    variants: &[T],
    expected: &[&str],
) -> Result<(), Box<dyn std::error::Error>>
where
    T: Copy + fmt::Debug + Eq + serde::Serialize + serde::de::DeserializeOwned,
{
    assert_eq!(variants.len(), expected.len());
    for (variant, expected) in variants.iter().copied().zip(expected) {
        assert_eq!(serde_json::to_value(variant)?, *expected);
        assert_eq!(serde_json::from_value::<T>(json!(expected))?, variant);
    }
    Ok(())
}

fn assert_static_auth_deserialization_error<T>(value: Value)
where
    T: fmt::Debug + serde::de::DeserializeOwned,
{
    let error =
        serde_json::from_value::<T>(value).expect_err("hostile provider data must not deserialize");
    let diagnostic = error.to_string();
    assert_eq!(
        diagnostic, "invalid subscription authentication data",
        "auth deserialization errors must be static"
    );
    assert_contains_no_sentinel(&diagnostic);
}

fn assert_send<T: Send>(_: &T) {}

struct FakeBroker {
    state: AuthState,
}

impl SubscriptionAuthBroker for FakeBroker {
    fn service(&self) -> SubscriptionService {
        SubscriptionService::OpenAiCodex
    }

    fn auth_state(&mut self) -> AuthFuture<'_, AuthState> {
        let state = self.state;
        Box::pin(async move { Ok(state) })
    }

    fn start_login(&mut self, method: AuthMethod) -> AuthFuture<'_, LoginChallenge> {
        self.state = AuthState::Pending;
        Box::pin(async move {
            match method {
                AuthMethod::DeviceCode => Ok(LoginChallenge::Device {
                    verification_url: AuthorizationUrl::parse(
                        "https://device.example.test/activate",
                    )?,
                    user_code: UserCode::parse("CARL-1234")?,
                }),
                AuthMethod::BrowserOAuth | AuthMethod::ProviderManaged => {
                    Err(AuthError::from_code(AuthErrorCode::ProviderRejected))
                }
            }
        })
    }

    fn logout(&mut self) -> AuthFuture<'_, ()> {
        self.state = AuthState::SignedOut;
        Box::pin(async { Ok(()) })
    }

    fn cancel_login(&mut self) -> AuthFuture<'_, ()> {
        self.state = AuthState::SignedOut;
        Box::pin(async { Ok(()) })
    }
}
