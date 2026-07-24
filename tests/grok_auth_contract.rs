#[allow(dead_code)]
#[path = "support/sidecar.rs"]
mod support;

use std::env;
use std::ffi::OsString;
use std::fs;
use std::future::Future;
use std::process;
use std::time::Duration;

use carl::auth::grok::{GrokAuth, GrokAuthTimeouts};
use carl::auth::{
    AuthError, AuthErrorCode, AuthMethod, AuthState, SubscriptionAuthBroker, SubscriptionService,
};
use carl::sidecar::{
    ExecutableTrustDecision, ProviderEnvironmentProfile, ProviderHome, TrustedExecutable,
};
use libtest_mimic::{Arguments, Failed, Trial};
use serde_json::{Value, json};
use support::{
    GROK_SECRET_SENTINEL, PATH_SENTINEL, SECRET_SENTINEL, TestLayout, TestResult, dispatch_fixture,
    dispatch_grok_auth_fixture, fixture_command, short_limits,
};

const REQUIREMENTS: &[u8] =
    b"[cli]\nauto_update = false\n\n[grok_com_config]\ndisable_api_key_auth = true\n";

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if let Some(exit_code) =
        dispatch_grok_auth_fixture(&arguments).or_else(|| dispatch_fixture(&arguments))
    {
        process::exit(exit_code);
    }

    // SAFETY: this runs before libtest-mimic starts any test threads and proves each
    // Grok process receives only Carl's synthetic environment.
    unsafe {
        env::set_var("XAI_API_KEY", GROK_SECRET_SENTINEL);
        env::set_var("GROK_API_KEY", GROK_SECRET_SENTINEL);
        env::set_var("GROK_HOME", "/parent/grok/home");
        env::set_var("BROWSER", GROK_SECRET_SENTINEL);
        env::set_var("XAI_BASE_URL", "https://attacker.example.test");
        env::set_var("OPENAI_BASE_URL", "https://attacker.example.test");
        env::set_var("TELEGRAM_BOT_TOKEN", SECRET_SENTINEL);
        let inherited_path = env::var_os("PATH").unwrap_or_default();
        let poisoned_path = env::join_paths(
            std::iter::once(PATH_SENTINEL.into()).chain(env::split_paths(&inherited_path)),
        )
        .expect("the poisoned PATH is valid");
        env::set_var("PATH", poisoned_path);
    }

    let trials = vec![
        test(
            "Grok 0.2.111 status handshake is exact and isolated",
            grok_status_handshake_is_exact_and_isolated,
        ),
        test(
            "Grok rejects a Codex provider home before launch",
            grok_rejects_codex_provider_home_before_launch,
        ),
        test(
            "only the pinned Grok release is accepted",
            only_pinned_grok_release_is_accepted,
        ),
        test(
            "Grok ACP authentication outcomes fail closed",
            grok_acp_authentication_outcomes_fail_closed,
        ),
        test(
            "unsafe Grok credential metadata prevents every process",
            unsafe_grok_credentials_prevent_process_start,
        ),
        test(
            "Grok login requires a local foreground terminal",
            grok_login_requires_local_foreground,
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
    broker: GrokAuth,
    layout: TestLayout,
}

impl Fixture {
    async fn connect(scenario: &str) -> Result<Self, AuthError> {
        let layout = TestLayout::new().expect("the fixture layout is created");
        let trusted =
            trusted_fixture_executable(&layout).expect("the fixture executable is trusted");
        let home = ProviderHome::prepare(
            ProviderEnvironmentProfile::Grok,
            &layout.data,
            &layout.workspace,
            &layout.home,
        )
        .expect("the Grok fixture home is prepared");
        home.write_static_file("fixture-scenario", scenario.as_bytes())
            .expect("the fixture scenario is written");
        if matches!(
            scenario,
            "signed-in" | "authenticate-meta" | "cached-with-other"
        ) {
            home.write_static_file("auth.json", GROK_SECRET_SENTINEL.as_bytes())
                .expect("the signed-in fixture credential metadata is safe");
        }
        let broker = GrokAuth::connect(&trusted, home, short_limits(), contract_timeouts()).await?;
        Ok(Self { broker, layout })
    }
}

fn contract_timeouts() -> GrokAuthTimeouts {
    GrokAuthTimeouts::new(Duration::from_millis(500), Duration::from_millis(250))
}

fn trusted_fixture_executable(layout: &TestLayout) -> TestResult<TrustedExecutable> {
    Ok(fixture_command(layout, "strict-jsonl", "1.2.3")
        .resolve_executable()?
        .trust(ExecutableTrustDecision::TrustCanonicalPath)?)
}

fn grok_status_handshake_is_exact_and_isolated() -> TestResult {
    run_async(async {
        let mut fixture = Fixture::connect("signed-in").await?;
        assert_eq!(fixture.broker.service(), SubscriptionService::XaiGrok);
        assert_eq!(
            fixture.broker.cached_state(),
            AuthState::SignedIn {
                method: AuthMethod::ProviderManaged,
                plan: None,
            }
        );
        assert_eq!(
            fixture.broker.auth_state().await?,
            AuthState::SignedIn {
                method: AuthMethod::ProviderManaged,
                plan: None,
            }
        );
        assert_eq!(
            fs::read(fixture.layout.home.join("requirements.toml"))?,
            REQUIREMENTS
        );

        let launches = read_json_lines(fixture.layout.home.join("grok-launches.jsonl"))?;
        assert_eq!(
            launches.len(),
            3,
            "connect probes the version once; later status uses the verified executable"
        );
        assert_eq!(
            launches[0]["arguments"],
            json!(["--no-auto-update", "version"])
        );
        assert_eq!(
            launches[1]["arguments"],
            json!(["--no-auto-update", "agent", "stdio"])
        );
        assert_eq!(
            launches[2]["arguments"],
            json!(["--no-auto-update", "agent", "stdio"])
        );
        for launch in launches {
            assert_eq!(launch["requirementsMatch"], true);
            assert_eq!(
                fs::canonicalize(
                    launch["cwd"]
                        .as_str()
                        .ok_or("fixture working directory was not a string")?
                )?,
                fs::canonicalize(&fixture.layout.home)?
            );
            let environment = launch["environment"]
                .as_object()
                .ok_or("fixture environment was not an object")?;
            for home_key in ["GROK_HOME", "HOME"] {
                let configured = environment
                    .get(home_key)
                    .and_then(Value::as_str)
                    .ok_or("fixture provider home was not a string")?;
                assert_eq!(
                    fs::canonicalize(configured)?,
                    fs::canonicalize(&fixture.layout.home)?
                );
            }
            #[cfg(windows)]
            {
                let configured = environment
                    .get("USERPROFILE")
                    .and_then(Value::as_str)
                    .ok_or("fixture user profile was not a string")?;
                assert_eq!(
                    fs::canonicalize(configured)?,
                    fs::canonicalize(&fixture.layout.home)?
                );
            }
            assert_eq!(
                environment
                    .get("GROK_DISABLE_AUTOUPDATER")
                    .and_then(Value::as_str),
                Some("1")
            );
            for forbidden in [
                "XAI_API_KEY",
                "GROK_API_KEY",
                "BROWSER",
                "XAI_BASE_URL",
                "OPENAI_BASE_URL",
                "TELEGRAM_BOT_TOKEN",
            ] {
                assert!(
                    !environment.contains_key(forbidden),
                    "Grok inherited forbidden environment variable {forbidden}"
                );
            }
        }

        let requests = read_json_lines(fixture.layout.home.join("grok-requests.jsonl"))?;
        assert_eq!(requests.len(), 4);
        for pair in requests.chunks_exact(2) {
            assert_eq!(
                pair[0],
                json!({
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": 1,
                        "clientCapabilities": {
                            "fs": {
                                "readTextFile": false,
                                "writeTextFile": false
                            },
                            "terminal": false
                        },
                        "clientInfo": {
                            "name": "carl",
                            "title": "Carl",
                            "version": "0.1.0"
                        }
                    }
                })
            );
            assert_eq!(
                pair[1],
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "authenticate",
                    "params": {
                        "methodId": "cached_token",
                        "_meta": {"headless": true}
                    }
                })
            );
        }
        assert_contains_no_secret(&format!("{:?}", fixture.broker));
        Ok(())
    })
}

fn grok_rejects_codex_provider_home_before_launch() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let trusted = trusted_fixture_executable(&layout)?;
        let home = ProviderHome::prepare(
            ProviderEnvironmentProfile::Codex,
            &layout.data,
            &layout.workspace,
            &layout.home,
        )?;
        home.write_static_file("fixture-scenario", b"signed-out")?;

        let error = GrokAuth::connect(&trusted, home, short_limits(), contract_timeouts())
            .await
            .expect_err("Grok accepted a Codex provider-home capability");
        assert_eq!(error.code(), AuthErrorCode::ProviderRejected);
        assert!(
            !layout.home.join("grok-launches.jsonl").exists(),
            "Grok launched before rejecting the wrong provider profile"
        );
        assert!(
            !layout.home.join("requirements.toml").exists(),
            "Grok wrote provider policy before rejecting the wrong profile"
        );
        assert_contains_no_secret(&error.to_string());
        assert_contains_no_secret(&format!("{error:?}"));
        Ok(())
    })
}

fn only_pinned_grok_release_is_accepted() -> TestResult {
    run_async(async {
        for (scenario, expected) in [
            ("unsupported-version", AuthErrorCode::UnsupportedVersion),
            ("prerelease-version", AuthErrorCode::UnsupportedVersion),
            ("version-build-metadata", AuthErrorCode::UnsupportedVersion),
            ("version-multiple", AuthErrorCode::ProtocolMismatch),
            ("version-malformed", AuthErrorCode::ProtocolMismatch),
            ("version-oversized", AuthErrorCode::ProtocolMismatch),
            ("wrong-agent-version", AuthErrorCode::UnsupportedVersion),
            ("agent-version-build", AuthErrorCode::UnsupportedVersion),
        ] {
            let error = match Fixture::connect(scenario).await {
                Ok(_) => {
                    return Err(
                        format!("incompatible Grok release was accepted: {scenario}").into(),
                    );
                }
                Err(error) => error,
            };
            assert_eq!(error.code(), expected, "scenario {scenario}");
            assert_contains_no_secret(&error.to_string());
            assert_contains_no_secret(&format!("{error:?}"));
        }

        Fixture::connect("missing-agent-info").await?;
        Fixture::connect("missing-agent-version").await?;
        Fixture::connect("protocol-version-string").await?;
        Ok(())
    })
}

fn grok_acp_authentication_outcomes_fail_closed() -> TestResult {
    run_async(async {
        let missing = Fixture::connect("missing-auth-method").await?;
        assert_eq!(missing.broker.cached_state(), AuthState::SignedOut);

        let other = Fixture::connect("other-auth-method").await?;
        assert_eq!(other.broker.cached_state(), AuthState::SignedOut);

        let lookalike = Fixture::connect("xai-api-key-lookalike").await?;
        assert_eq!(lookalike.broker.cached_state(), AuthState::SignedOut);

        let cached_with_other = Fixture::connect("cached-with-other").await?;
        assert_eq!(
            cached_with_other.broker.cached_state(),
            AuthState::SignedIn {
                method: AuthMethod::ProviderManaged,
                plan: None,
            }
        );

        let signed_out = Fixture::connect("signed-out").await?;
        assert_eq!(signed_out.broker.cached_state(), AuthState::SignedOut);

        let initialize_signed_out = Fixture::connect("initialize-auth-required").await?;
        assert_eq!(
            initialize_signed_out.broker.cached_state(),
            AuthState::SignedOut
        );

        let meta = Fixture::connect("authenticate-meta").await?;
        assert_eq!(
            meta.broker.cached_state(),
            AuthState::SignedIn {
                method: AuthMethod::ProviderManaged,
                plan: None,
            }
        );

        let missing_file = match Fixture::connect("signed-in-missing-auth-file").await {
            Ok(_) => return Err("ACP success without auth.json was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(missing_file.code(), AuthErrorCode::ProtocolMismatch);
        assert_contains_no_secret(&missing_file.to_string());

        for scenario in [
            "xai-api-key",
            "xai-api-key-alone",
            "duplicate-auth-method",
            "duplicate-other-auth-method",
            "too-many-auth-methods",
            "malformed-auth-method",
            "wrong-protocol-version",
            "malformed-agent-info",
            "agent-capabilities-non-object",
            "agent-capabilities-oversized",
            "agent-capabilities-deep",
            "initialize-mixed-result-error",
            "initialize-wrong-id",
            "initialize-wrong-jsonrpc",
            "response-method-confusion",
            "authenticate-wrong-id",
            "authenticate-mixed-result-error",
            "authenticate-extra-field",
            "authenticate-malformed-meta",
            "authenticate-meta-oversized",
            "authenticate-meta-deep",
            "protocol-error",
            "unsupported-request",
        ] {
            let error = match Fixture::connect(scenario).await {
                Ok(_) => {
                    return Err(
                        format!("malformed Grok ACP handshake was accepted: {scenario}").into(),
                    );
                }
                Err(error) => error,
            };
            assert_eq!(
                error.code(),
                AuthErrorCode::ProtocolMismatch,
                "scenario {scenario}"
            );
            assert_contains_no_secret(&error.to_string());
            assert_contains_no_secret(&format!("{error:?}"));
        }

        let rejected = match Fixture::connect("provider-rejected").await {
            Ok(_) => return Err("provider rejection was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(rejected.code(), AuthErrorCode::ProviderRejected);
        assert_contains_no_secret(&rejected.to_string());
        Ok(())
    })
}

fn unsafe_grok_credentials_prevent_process_start() -> TestResult {
    run_async(async {
        for unsafe_kind in ["hard-link", "oversized"] {
            let layout = TestLayout::new()?;
            let trusted = trusted_fixture_executable(&layout)?;
            let home = ProviderHome::prepare(
                ProviderEnvironmentProfile::Grok,
                &layout.data,
                &layout.workspace,
                &layout.home,
            )?;
            home.write_static_file("fixture-scenario", b"signed-in")?;
            match unsafe_kind {
                "hard-link" => {
                    home.write_static_file("auth-target", GROK_SECRET_SENTINEL.as_bytes())?;
                    fs::hard_link(
                        layout.home.join("auth-target"),
                        layout.home.join("auth.json"),
                    )?;
                }
                "oversized" => {
                    home.write_static_file("auth.json", &vec![b'x'; 2 * 1_024 * 1_024])?;
                }
                _ => unreachable!(),
            }

            let error = match GrokAuth::connect(&trusted, home, short_limits(), contract_timeouts())
                .await
            {
                Ok(_) => return Err(format!("unsafe {unsafe_kind} auth.json was accepted").into()),
                Err(error) => error,
            };
            assert_eq!(error.code(), AuthErrorCode::UnsafeCredentialStore);
            assert!(
                !layout.home.join("grok-launches.jsonl").exists(),
                "unsafe {unsafe_kind} auth.json allowed a Grok process to start"
            );
            assert_contains_no_secret(&error.to_string());
        }

        let postflight = match Fixture::connect("postflight-unsafe").await {
            Ok(_) => return Err("unsafe postflight auth.json was accepted".into()),
            Err(error) => error,
        };
        assert_eq!(
            postflight.code(),
            AuthErrorCode::UnsafeCredentialStore,
            "ACP success or rejection must not override unsafe postflight metadata"
        );
        Ok(())
    })
}

fn grok_login_requires_local_foreground() -> TestResult {
    run_async(async {
        let mut fixture = Fixture::connect("signed-out").await?;
        let unsupported = fixture
            .broker
            .start_login(AuthMethod::ProviderManaged)
            .await
            .expect_err("provider-managed is a status method, not a login selector");
        assert_eq!(unsupported.code(), AuthErrorCode::ProviderRejected);
        let error = fixture
            .broker
            .start_login(AuthMethod::BrowserOAuth)
            .await
            .expect_err("non-terminal login was accepted");
        assert_eq!(error.code(), AuthErrorCode::ForegroundRequired);
        let logout = fixture
            .broker
            .logout()
            .await
            .expect_err("a status-only broker initiated provider logout");
        assert_eq!(logout.code(), AuthErrorCode::ForegroundRequired);
        let cancel = fixture
            .broker
            .cancel_login()
            .await
            .expect_err("a status-only broker cancelled a foreground ceremony");
        assert_eq!(cancel.code(), AuthErrorCode::ForegroundRequired);
        assert_eq!(
            fixture.broker.auth_state().await?,
            AuthState::SignedOut,
            "a rejected remote login must not make the broker pending"
        );
        let launches = read_json_lines(fixture.layout.home.join("grok-launches.jsonl"))?;
        assert!(
            launches.iter().all(|launch| {
                launch["arguments"] != json!(["--no-auto-update", "login"])
                    && launch["arguments"] != json!(["--no-auto-update", "login", "--device-auth"])
                    && launch["arguments"] != json!(["--no-auto-update", "logout"])
            }),
            "a remote request started a terminal-owned auth process"
        );
        Ok(())
    })
}

fn read_json_lines(path: impl AsRef<std::path::Path>) -> TestResult<Vec<Value>> {
    fs::read_to_string(path)?
        .lines()
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

fn assert_contains_no_secret(value: &str) {
    for sentinel in [
        "Bearer",
        "grok-access-token-sentinel",
        "refresh-token-sentinel",
        "stephen@example.test",
        GROK_SECRET_SENTINEL,
    ] {
        assert!(
            !value.contains(sentinel),
            "diagnostic exposed secret sentinel {sentinel:?}: {value}"
        );
    }
}
