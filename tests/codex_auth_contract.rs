#[allow(dead_code)]
#[path = "support/sidecar.rs"]
mod support;

use std::env;
use std::ffi::OsString;
use std::fs;
use std::future::Future;
use std::path::Path;
use std::process;
use std::time::{Duration, Instant};

use carl::auth::codex::{CodexAuth, CodexAuthTimeouts};
use carl::auth::{
    AuthErrorCode, AuthMethod, AuthState, LoginChallenge, SubscriptionAuthBroker, SubscriptionPlan,
    SubscriptionService,
};
use carl::sidecar::{
    ExecutableTrustDecision, ProviderEnvironmentProfile, ProviderHome, TrustedExecutable,
};
use libtest_mimic::{Arguments, Failed, Trial};
use serde_json::{Value, json};
use support::{
    CODEX_LOGIN_ID, CODEX_SECRET_SENTINEL, PATH_SENTINEL, SECRET_SENTINEL, TestLayout, TestResult,
    dispatch_codex_auth_fixture, fixture_command, short_limits,
};

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if let Some(exit_code) = dispatch_codex_auth_fixture(&arguments) {
        process::exit(exit_code);
    }

    // SAFETY: this runs before libtest-mimic starts any test threads and proves that
    // the Codex app-server receives the sidecar's closed environment.
    unsafe {
        env::set_var("OPENAI_API_KEY", CODEX_SECRET_SENTINEL);
        env::set_var("TELEGRAM_BOT_TOKEN", SECRET_SENTINEL);
        env::set_var("CODEX_HOME", "/parent/codex/home");
        let inherited_path = env::var_os("PATH").unwrap_or_default();
        let poisoned_path = env::join_paths(
            std::iter::once(PATH_SENTINEL.into()).chain(env::split_paths(&inherited_path)),
        )
        .expect("the poisoned PATH is valid");
        env::set_var("PATH", poisoned_path);
    }

    let trials = vec![
        test(
            "Codex 0.136.0 launch and handshake are exact",
            codex_launch_and_handshake_are_exact,
        ),
        test(
            "only Codex 0.136.0 is accepted",
            only_codex_0136_is_accepted,
        ),
        test(
            "browser and device ceremonies complete through correlated notifications",
            browser_and_device_ceremonies_complete,
        ),
        test(
            "Codex authorization URLs fail closed",
            codex_authorization_urls_fail_closed,
        ),
        test(
            "account plans use the exact 0.136.0 closed mapping",
            account_plans_use_exact_mapping,
        ),
        test(
            "non ChatGPT accounts are signed out",
            non_chatgpt_accounts_are_signed_out,
        ),
        test(
            "incompatible handshakes and account shapes fail closed",
            incompatible_handshakes_fail_closed,
        ),
        test(
            "provider rejection is static and secret free",
            provider_rejection_is_static_and_secret_free,
        ),
        test(
            "terminal notification correlation is strict",
            terminal_notification_correlation_is_strict,
        ),
        test(
            "account updated is advisory and confirmation retries are bounded",
            account_updated_is_advisory_and_retries_are_bounded,
        ),
        test(
            "cancel responses and completion races are reconciled",
            cancel_responses_and_races_are_reconciled,
        ),
        test(
            "logout omits params and leaves signed out state",
            logout_omits_params,
        ),
        test(
            "login and child exit deadlines are typed",
            login_and_child_exit_deadlines_are_typed,
        ),
    ];
    libtest_mimic::run(&Arguments::from_args(), trials).exit();
}

fn test(name: &'static str, body: fn() -> TestResult) -> Trial {
    Trial::test(name, move || {
        body().map_err(|error| Failed::from(error.to_string()))
    })
}

fn run_async<T>(future: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the test Tokio runtime builds")
        .block_on(future)
}

struct Fixture {
    broker: CodexAuth,
    layout: TestLayout,
}

impl Fixture {
    async fn connect(scenario: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let layout = TestLayout::new()?;
        let trusted = trusted_fixture_executable(&layout)?;
        let home = ProviderHome::prepare(
            ProviderEnvironmentProfile::Codex,
            &layout.data,
            &layout.workspace,
            &layout.home,
        )?;
        home.write_static_file("fixture-scenario", scenario.as_bytes())?;
        let broker =
            CodexAuth::connect(&trusted, home, short_limits(), contract_timeouts()).await?;
        Ok(Self { broker, layout })
    }
}

fn trusted_fixture_executable(
    layout: &TestLayout,
) -> Result<TrustedExecutable, Box<dyn std::error::Error + Send + Sync>> {
    Ok(fixture_command(layout, "strict-jsonl", "1.2.3")
        .resolve_executable()?
        .trust(ExecutableTrustDecision::TrustCanonicalPath)?)
}

fn contract_timeouts() -> CodexAuthTimeouts {
    CodexAuthTimeouts::new(
        Duration::from_millis(300),
        Duration::from_millis(120),
        Duration::from_millis(120),
        Duration::from_millis(10),
    )
}

fn codex_launch_and_handshake_are_exact() -> TestResult {
    run_async(async {
        let fixture = Fixture::connect("signed-out").await?;
        assert_eq!(fixture.broker.service(), SubscriptionService::OpenAiCodex);
        assert_send(&fixture.broker);

        assert_eq!(
            fs::read_to_string(fixture.layout.home.join("config.toml"))?,
            "cli_auth_credentials_store = \"keyring\"\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(fixture.layout.home.join("config.toml"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let launch: Value =
            serde_json::from_slice(&fs::read(fixture.layout.home.join("codex-launch.json"))?)?;
        assert_eq!(
            Path::new(
                launch["cwd"]
                    .as_str()
                    .ok_or("launch cwd must be a string")?
            ),
            fs::canonicalize(&fixture.layout.home)?
        );
        let environment = launch["environment"]
            .as_object()
            .ok_or("launch environment must be an object")?;
        assert_eq!(
            environment
                .get("CODEX_HOME")
                .and_then(Value::as_str)
                .map(Path::new)
                .map(fs::canonicalize)
                .transpose()?,
            Some(fs::canonicalize(&fixture.layout.home)?)
        );
        assert!(!environment.contains_key("OPENAI_API_KEY"));
        assert!(!environment.contains_key("TELEGRAM_BOT_TOKEN"));
        assert!(
            !environment
                .values()
                .filter_map(Value::as_str)
                .any(|value| value.contains(PATH_SENTINEL))
        );
        assert!(!launch.to_string().contains(CODEX_SECRET_SENTINEL));

        let requests = read_requests(&fixture.layout)?;
        assert_eq!(
            requests,
            vec![
                json!({
                    "id": 0,
                    "method": "initialize",
                    "params": {
                        "clientInfo": {
                            "name": "carl",
                            "title": "Carl",
                            "version": env!("CARGO_PKG_VERSION"),
                        }
                    }
                }),
                json!({"method": "initialized"}),
                json!({
                    "id": 1,
                    "method": "account/read",
                    "params": {"refreshToken": false},
                }),
            ]
        );
        let raw = fs::read_to_string(fixture.layout.home.join("codex-requests.jsonl"))?;
        assert!(!raw.contains("Content-Length"));
        assert!(!raw.contains("\"jsonrpc\""));
        assert_redacted_broker(&fixture);
        TestResult::Ok(())
    })
}

fn only_codex_0136_is_accepted() -> TestResult {
    run_async(async {
        for (scenario, expected) in [
            ("unsupported-version", AuthErrorCode::UnsupportedVersion),
            ("version-wrong-prefix", AuthErrorCode::ProtocolMismatch),
            ("version-extra-token", AuthErrorCode::ProtocolMismatch),
            ("version-malformed", AuthErrorCode::ProtocolMismatch),
        ] {
            let layout = TestLayout::new()?;
            let trusted = trusted_fixture_executable(&layout)?;
            let home = ProviderHome::prepare(
                ProviderEnvironmentProfile::Codex,
                &layout.data,
                &layout.workspace,
                &layout.home,
            )?;
            home.write_static_file("fixture-scenario", scenario.as_bytes())?;
            let error = CodexAuth::connect(&trusted, home, short_limits(), contract_timeouts())
                .await
                .expect_err("only exact codex-cli 0.136.0 must be accepted");
            assert_eq!(error.code(), expected);
            assert_contains_no_secret(&format!("{error:?}"));
            assert!(
                !error
                    .to_string()
                    .contains(layout.home.to_string_lossy().as_ref())
            );
        }
        Ok(())
    })
}

fn browser_and_device_ceremonies_complete() -> TestResult {
    run_async(async {
        let mut browser = Fixture::connect("browser-success").await?;
        let LoginChallenge::Browser { authorization_url } =
            browser.broker.start_login(AuthMethod::BrowserOAuth).await?
        else {
            return Err("expected a browser challenge".into());
        };
        let url = authorization_url.into_foreground_string();
        let parsed = url::Url::parse(&url)?;
        assert_eq!(
            parsed.origin().ascii_serialization(),
            "https://auth.openai.com"
        );
        assert_eq!(parsed.path(), "/oauth/authorize");
        assert_eq!(
            parsed
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<Vec<_>>(),
            vec![
                ("response_type".to_owned(), "code".to_owned()),
                (
                    "client_id".to_owned(),
                    "app_EMoamEEZ73f0CkXaXp7hrann".to_owned(),
                ),
                (
                    "redirect_uri".to_owned(),
                    "http://localhost:1455/auth/callback".to_owned(),
                ),
                (
                    "scope".to_owned(),
                    "openid profile email offline_access api.connectors.read api.connectors.invoke"
                        .to_owned(),
                ),
                ("code_challenge".to_owned(), "A".repeat(43)),
                ("code_challenge_method".to_owned(), "S256".to_owned()),
                ("id_token_add_organizations".to_owned(), "true".to_owned()),
                ("codex_cli_simplified_flow".to_owned(), "true".to_owned()),
                ("state".to_owned(), "B".repeat(43)),
                ("originator".to_owned(), "carl".to_owned()),
            ]
        );
        assert!(!format!("{:?}", browser.broker).contains(CODEX_LOGIN_ID));
        assert_eq!(
            browser.broker.auth_state().await?,
            AuthState::SignedIn {
                method: AuthMethod::ProviderManaged,
                plan: Some(SubscriptionPlan::Plus),
            }
        );
        assert_redacted_broker(&browser);

        let mut device = Fixture::connect("device-success").await?;
        let LoginChallenge::Device {
            verification_url,
            user_code,
        } = device.broker.start_login(AuthMethod::DeviceCode).await?
        else {
            return Err("expected a device challenge".into());
        };
        assert_eq!(
            verification_url.into_foreground_string(),
            "https://auth.openai.com/codex/device"
        );
        assert_eq!(user_code.into_foreground_string(), "CARL-1360");
        assert_eq!(
            device.broker.auth_state().await?,
            AuthState::SignedIn {
                method: AuthMethod::ProviderManaged,
                plan: Some(SubscriptionPlan::Plus),
            }
        );
        assert_redacted_broker(&device);
        Ok(())
    })
}

fn codex_authorization_urls_fail_closed() -> TestResult {
    run_async(async {
        for scenario in [
            "browser-wrong-host",
            "browser-wrong-path",
            "browser-duplicate-query",
            "browser-invalid-callback",
            "browser-invalid-callback-port",
            "browser-wrong-response-type",
            "browser-wrong-client-id",
            "browser-wrong-scope",
            "browser-invalid-code-challenge",
            "browser-wrong-code-challenge-method",
            "browser-organizations-disabled",
            "browser-simplified-flow-disabled",
            "browser-invalid-state",
            "browser-wrong-originator",
            "browser-extra-nonce",
            "browser-extra-prompt",
            "browser-extra-audience",
            "browser-extra-resource",
            "browser-extra-workspace",
            "browser-wrong-order",
        ] {
            let mut fixture = Fixture::connect(scenario).await?;
            let error = fixture
                .broker
                .start_login(AuthMethod::BrowserOAuth)
                .await
                .expect_err("invalid browser URL must be rejected");
            assert_eq!(error.code(), AuthErrorCode::InvalidAuthorizationUrl);
            assert_contains_no_secret(&format!("{error:?}"));
        }
        let mut alternate_port = Fixture::connect("browser-port-1457").await?;
        let challenge = alternate_port
            .broker
            .start_login(AuthMethod::BrowserOAuth)
            .await?;
        assert!(
            matches!(challenge, LoginChallenge::Browser { .. }),
            "the second pinned callback port must be accepted"
        );
        for scenario in ["device-wrong-path", "device-query"] {
            let mut fixture = Fixture::connect(scenario).await?;
            let error = fixture
                .broker
                .start_login(AuthMethod::DeviceCode)
                .await
                .expect_err("invalid device URL must be rejected");
            assert_eq!(error.code(), AuthErrorCode::InvalidAuthorizationUrl);
        }
        Ok(())
    })
}

fn account_plans_use_exact_mapping() -> TestResult {
    run_async(async {
        let plans = [
            ("free", SubscriptionPlan::Free),
            ("go", SubscriptionPlan::Go),
            ("plus", SubscriptionPlan::Plus),
            ("pro", SubscriptionPlan::Pro),
            ("prolite", SubscriptionPlan::ProLite),
            ("team", SubscriptionPlan::Team),
            ("self_serve_business_usage_based", SubscriptionPlan::Team),
            ("business", SubscriptionPlan::Business),
            ("enterprise_cbp_usage_based", SubscriptionPlan::Business),
            ("enterprise", SubscriptionPlan::Enterprise),
            ("edu", SubscriptionPlan::Education),
            ("unknown", SubscriptionPlan::Unknown),
        ];
        for (wire, expected) in plans {
            let fixture = Fixture::connect(&format!("account-plan-{wire}")).await?;
            assert_eq!(
                fixture.broker.cached_state(),
                AuthState::SignedIn {
                    method: AuthMethod::ProviderManaged,
                    plan: Some(expected),
                }
            );
            assert_contains_no_secret(&format!("{:?}", fixture.broker));
        }
        for wire in ["pro_lite", "education", "future_plan"] {
            let result = Fixture::connect(&format!("account-plan-{wire}")).await;
            let error = match result {
                Ok(_) => return Err(format!("unrecognized plan {wire} was accepted").into()),
                Err(error) => error,
            };
            assert!(error.to_string().contains("protocol_mismatch"));
            assert_contains_no_secret(&error.to_string());
        }
        Ok(())
    })
}

fn non_chatgpt_accounts_are_signed_out() -> TestResult {
    run_async(async {
        for scenario in ["signed-out", "account-api-key", "account-amazon-bedrock"] {
            let fixture = Fixture::connect(scenario).await?;
            assert_eq!(fixture.broker.cached_state(), AuthState::SignedOut);
        }
        Ok(())
    })
}

fn incompatible_handshakes_fail_closed() -> TestResult {
    run_async(async {
        for scenario in [
            "wrong-codex-home",
            "initialize-unknown-field",
            "requires-openai-auth-false",
            "account-read-unknown-field",
            "account-unknown-type",
            "malformed-remote-control-status",
            "startup-account-updated",
            "startup-login-completed",
            "startup-unknown-notification",
            "startup-malformed-config-warning",
        ] {
            let result = Fixture::connect(scenario).await;
            let error = match result {
                Ok(_) => return Err(format!("{scenario} unexpectedly connected").into()),
                Err(error) => error,
            };
            assert!(error.to_string().contains("protocol_mismatch"));
            assert_contains_no_secret(&error.to_string());
        }
        Ok(())
    })
}

fn provider_rejection_is_static_and_secret_free() -> TestResult {
    run_async(async {
        let mut fixture = Fixture::connect("provider-error").await?;
        let error = fixture
            .broker
            .start_login(AuthMethod::BrowserOAuth)
            .await
            .expect_err("opaque provider error must be rejected");
        assert_eq!(error.code(), AuthErrorCode::ProviderRejected);
        assert_eq!(
            error.to_string(),
            "subscription authentication failed: provider_rejected"
        );
        assert_contains_no_secret(&format!("{error:?}"));

        let mut protocol = Fixture::connect("provider-protocol-error").await?;
        let error = protocol
            .broker
            .start_login(AuthMethod::BrowserOAuth)
            .await
            .expect_err("invalid-params JSON-RPC errors signal protocol mismatch");
        assert_eq!(error.code(), AuthErrorCode::ProtocolMismatch);
        assert_contains_no_secret(&format!("{error:?}"));

        let mut rejected = Fixture::connect("login-rejected").await?;
        rejected
            .broker
            .start_login(AuthMethod::BrowserOAuth)
            .await?;
        let error = rejected
            .broker
            .auth_state()
            .await
            .expect_err("failed completion must be provider rejected");
        assert_eq!(error.code(), AuthErrorCode::ProviderRejected);
        assert_contains_no_secret(&format!("{error:?}"));
        Ok(())
    })
}

fn terminal_notification_correlation_is_strict() -> TestResult {
    run_async(async {
        for scenario in [
            "wrong-response-id",
            "mixed-response-id",
            "response-method-bearing",
            "response-result-and-error",
            "response-neither-result-nor-error",
        ] {
            let mut fixture = Fixture::connect(scenario).await?;
            let error = fixture
                .broker
                .start_login(AuthMethod::BrowserOAuth)
                .await
                .expect_err("wrong response ID must fail");
            assert_eq!(error.code(), AuthErrorCode::ProtocolMismatch);
        }

        let mut stale = Fixture::connect("stale-completion").await?;
        stale.broker.start_login(AuthMethod::BrowserOAuth).await?;
        let error = stale
            .broker
            .auth_state()
            .await
            .expect_err("a stale completion must not complete the pending login");
        assert_eq!(error.code(), AuthErrorCode::TimedOut);

        let mut duplicate = Fixture::connect("duplicate-completion").await?;
        duplicate
            .broker
            .start_login(AuthMethod::BrowserOAuth)
            .await?;
        assert_eq!(
            duplicate.broker.auth_state().await?,
            AuthState::SignedIn {
                method: AuthMethod::ProviderManaged,
                plan: Some(SubscriptionPlan::Plus),
            }
        );
        assert_eq!(
            duplicate.broker.auth_state().await?,
            AuthState::SignedIn {
                method: AuthMethod::ProviderManaged,
                plan: Some(SubscriptionPlan::Plus),
            },
            "an identical duplicate must be drained and cannot poison later state"
        );

        for scenario in [
            "conflicting-duplicate-completion",
            "malformed-notification",
            "completion-missing-success",
            "completion-wrong-success-type",
            "success-with-error",
            "failure-without-error",
            "failure-with-null-error",
        ] {
            let mut fixture = Fixture::connect(scenario).await?;
            fixture.broker.start_login(AuthMethod::BrowserOAuth).await?;
            let error = fixture
                .broker
                .auth_state()
                .await
                .expect_err("uncorrelated or malformed completion must fail");
            assert_eq!(error.code(), AuthErrorCode::ProtocolMismatch);
            assert_contains_no_secret(&format!("{error:?}"));
        }

        for scenario in ["completion-null-login-id", "completion-missing-login-id"] {
            let mut fixture = Fixture::connect(scenario).await?;
            fixture.broker.start_login(AuthMethod::BrowserOAuth).await?;
            let error = fixture
                .broker
                .auth_state()
                .await
                .expect_err("a null or omitted login ID cannot correlate");
            assert_eq!(error.code(), AuthErrorCode::TimedOut);
        }
        Ok(())
    })
}

fn account_updated_is_advisory_and_retries_are_bounded() -> TestResult {
    run_async(async {
        for scenario in [
            "advisory-before-completion",
            "stale-account-then-updated",
            "success-without-error",
            "empty-advisory-before-completion",
            "config-warning-before-completion",
            "startup-config-warning",
            "remote-status-before-completion",
        ] {
            let mut fixture = Fixture::connect(scenario).await?;
            fixture.broker.start_login(AuthMethod::BrowserOAuth).await?;
            assert_eq!(
                fixture.broker.auth_state().await?,
                AuthState::SignedIn {
                    method: AuthMethod::ProviderManaged,
                    plan: Some(SubscriptionPlan::Plus),
                }
            );
        }

        for scenario in ["advisory-only", "confirmation-timeout"] {
            let mut fixture = Fixture::connect(scenario).await?;
            fixture.broker.start_login(AuthMethod::BrowserOAuth).await?;
            let started = Instant::now();
            let error = fixture
                .broker
                .auth_state()
                .await
                .expect_err("advisory or stale reads cannot complete a login");
            assert_eq!(error.code(), AuthErrorCode::TimedOut);
            assert!(started.elapsed() < Duration::from_secs(1));
        }
        Ok(())
    })
}

fn cancel_responses_and_races_are_reconciled() -> TestResult {
    run_async(async {
        let mut canceled = Fixture::connect("cancel-canceled").await?;
        canceled
            .broker
            .start_login(AuthMethod::BrowserOAuth)
            .await?;
        canceled.broker.cancel_login().await?;
        assert_eq!(canceled.broker.cached_state(), AuthState::SignedOut);

        let mut raced = Fixture::connect("cancel-not-found-success").await?;
        raced.broker.start_login(AuthMethod::BrowserOAuth).await?;
        raced.broker.cancel_login().await?;
        assert_eq!(
            raced.broker.cached_state(),
            AuthState::SignedIn {
                method: AuthMethod::ProviderManaged,
                plan: Some(SubscriptionPlan::Plus),
            }
        );

        let mut invalid = Fixture::connect("cancel-invalid-status").await?;
        invalid.broker.start_login(AuthMethod::BrowserOAuth).await?;
        let error = invalid
            .broker
            .cancel_login()
            .await
            .expect_err("unknown cancel status must fail");
        assert_eq!(error.code(), AuthErrorCode::ProtocolMismatch);

        let mut late = Fixture::connect("cancel-canceled-late-success").await?;
        late.broker.start_login(AuthMethod::BrowserOAuth).await?;
        late.broker.cancel_login().await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let error = late
            .broker
            .auth_state()
            .await
            .expect_err("a late success must conflict with a canceled tombstone");
        assert_eq!(error.code(), AuthErrorCode::ProtocolMismatch);
        Ok(())
    })
}

fn logout_omits_params() -> TestResult {
    run_async(async {
        let mut fixture = Fixture::connect("account-plan-plus").await?;
        fixture.broker.logout().await?;
        assert_eq!(fixture.broker.cached_state(), AuthState::SignedOut);
        let requests = read_requests(&fixture.layout)?;
        let logout = requests.last().ok_or("missing logout request")?;
        assert_eq!(logout["method"], "account/logout");
        assert!(logout.get("params").is_none());
        assert_eq!(logout.as_object().map(serde_json::Map::len), Some(2));
        TestResult::Ok(())
    })
}

fn login_and_child_exit_deadlines_are_typed() -> TestResult {
    run_async(async {
        let startup = match Fixture::connect("startup-no-remote").await {
            Ok(_) => return Err("missing initial remote-control status was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(
            startup.to_string(),
            "subscription authentication failed: timed_out"
        );

        let mut timed_out = Fixture::connect("login-timeout").await?;
        timed_out
            .broker
            .start_login(AuthMethod::BrowserOAuth)
            .await?;
        let error = timed_out
            .broker
            .auth_state()
            .await
            .expect_err("missing completion must time out");
        assert_eq!(error.code(), AuthErrorCode::TimedOut);
        timed_out
            .broker
            .cancel_login()
            .await
            .expect("a timed-out ceremony must remain cancelable");

        let mut exited = Fixture::connect("child-exit").await?;
        exited.broker.start_login(AuthMethod::BrowserOAuth).await?;
        let error = exited
            .broker
            .auth_state()
            .await
            .expect_err("child exit must wake login");
        assert_eq!(error.code(), AuthErrorCode::SidecarExited);
        Ok(())
    })
}

fn read_requests(layout: &TestLayout) -> TestResult<Vec<Value>> {
    fs::read_to_string(layout.home.join("codex-requests.jsonl"))?
        .lines()
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

fn assert_contains_no_secret(value: &str) {
    for sentinel in [
        "Bearer",
        "codex-access-token-sentinel",
        "refresh-token-sentinel",
        "stephen@example.test",
        CODEX_LOGIN_ID,
        CODEX_SECRET_SENTINEL,
    ] {
        assert!(
            !value.contains(sentinel),
            "diagnostic exposed secret sentinel {sentinel:?}: {value}"
        );
    }
}

fn assert_redacted_broker(fixture: &Fixture) {
    let diagnostic = format!("{:?}", fixture.broker);
    assert_contains_no_secret(&diagnostic);
    assert!(
        !diagnostic.contains(fixture.layout.home.to_string_lossy().as_ref()),
        "broker debug exposed its provider home"
    );
}

fn assert_send<T: Send>(_: &T) {}
