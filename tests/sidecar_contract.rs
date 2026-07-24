#[path = "support/sidecar.rs"]
mod support;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Duration;

use carl::sidecar::{
    ExecutableTrustDecision, JsonlSidecar, NotificationPolicy, ProviderEnvironmentProfile,
    ProviderHome, SidecarCommand, SidecarError, SidecarErrorCode, SidecarLimits,
    VersionOutputFormat,
};
use libtest_mimic::{Arguments, Failed, Trial};
use semver::{Version, VersionReq};
use serde_json::json;
use support::{
    PATH_SENTINEL, SECRET_SENTINEL, TestLayout, TestResult, dispatch_fixture, fixture_command,
    short_limits, spawn_fixture, wait_for_fixture_pids, wait_for_received_count,
    wait_until_processes_exit, wait_until_processes_reaped,
};

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if let Some(exit_code) = dispatch_fixture(&arguments) {
        process::exit(exit_code);
    }

    // SAFETY: this runs before libtest-mimic starts any test threads. The values are scoped to
    // this custom-harness process and deliberately prove that child env_clear is effective.
    unsafe {
        env::set_var("OPENAI_API_KEY", SECRET_SENTINEL);
        env::set_var("TELEGRAM_BOT_TOKEN", SECRET_SENTINEL);
        env::set_var("AWS_ACCESS_KEY_ID", SECRET_SENTINEL);
        env::set_var("CODEX_HOME", "/parent/credential/home");
        env::set_var("GROK_HOME", "/parent/credential/home");
        let inherited_path = env::var_os("PATH").unwrap_or_default();
        let poisoned_path = env::join_paths(
            std::iter::once(PathBuf::from(PATH_SENTINEL)).chain(env::split_paths(&inherited_path)),
        )
        .expect("the sentinel parent PATH is valid");
        env::set_var("PATH", poisoned_path);
    }

    let trials = vec![
        test("missing executable is typed", missing_executable_is_typed),
        test(
            "executable is canonical regular and trusted",
            executable_is_canonical_regular_and_trusted,
        ),
        test(
            "executable trust precedes every execution",
            executable_trust_precedes_every_execution,
        ),
        test(
            "versions are parsed and pinned",
            versions_are_parsed_and_pinned,
        ),
        test(
            "sidecar limits reject unbounded configurations",
            sidecar_limits_reject_unbounded_configurations,
        ),
        test(
            "provider home is isolated and private",
            provider_home_is_isolated_and_private,
        ),
        test(
            "provider home writes static files through its capability",
            provider_home_writes_static_files_through_its_capability,
        ),
        test(
            "unsafe provider homes are rejected",
            unsafe_provider_homes_are_rejected,
        ),
        test(
            "child environment is allowlisted",
            child_environment_is_allowlisted,
        ),
        test(
            "Grok environment profile is closed",
            grok_environment_profile_is_closed,
        ),
        test(
            "responses correlate out of order",
            responses_correlate_out_of_order,
        ),
        test(
            "abandoned written request consumes one late response",
            abandoned_written_request_consumes_one_late_response,
        ),
        test(
            "prewrite drop permits safe ID reuse",
            prewrite_drop_permits_safe_id_reuse,
        ),
        test(
            "abandoned request budget fails safely",
            abandoned_request_budget_fails_safely,
        ),
        test(
            "leader exit preserves its final response",
            leader_exit_preserves_its_final_response,
        ),
        test(
            "notifications are bounded and delivered",
            notifications_are_bounded_and_delivered,
        ),
        test(
            "outbound notifications and nonblocking receive are bounded",
            outbound_notifications_and_nonblocking_receive_are_bounded,
        ),
        test(
            "notification rejection policy fails closed",
            notification_rejection_policy_fails_closed,
        ),
        test(
            "invalid request IDs are rejected",
            invalid_request_ids_are_rejected,
        ),
        test(
            "unknown response IDs fail closed",
            unknown_response_ids_fail_closed,
        ),
        test(
            "malformed stdout fails closed",
            malformed_stdout_fails_closed,
        ),
        test(
            "oversized stdout fails closed",
            oversized_stdout_fails_closed,
        ),
        test(
            "stderr is bounded and redacted",
            stderr_is_bounded_and_redacted,
        ),
        test(
            "child exit wakes every pending request",
            child_exit_wakes_every_pending_request,
        ),
        test(
            "explicit cancellation removes process group",
            explicit_cancellation_removes_process_group,
        ),
        test(
            "cancellation cannot deadlock on full stdin",
            cancellation_cannot_deadlock_on_full_stdin,
        ),
        test(
            "leader exit removes ordinary descendants",
            leader_exit_removes_ordinary_descendants,
        ),
        test(
            "dropping supervisor removes process group",
            dropping_supervisor_removes_process_group,
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

async fn detect_version(
    command: &SidecarCommand,
    data_root: &Path,
    workspace: &Path,
) -> Result<Version, SidecarError> {
    let trusted = command
        .resolve_executable()?
        .trust(ExecutableTrustDecision::TrustCanonicalPath);
    command
        .detect_trusted_version(&trusted, data_root, workspace, short_limits())
        .await
}

fn missing_executable_is_typed() -> TestResult {
    let layout = TestLayout::new()?;
    let command = SidecarCommand {
        executable: layout.data.join("missing-provider-executable"),
        arguments: Vec::new(),
        version_arguments: vec![OsString::from("--version")],
        version_output: VersionOutputFormat::ExactPrefix("missing-provider"),
        isolated_home: layout.home.clone(),
        supported_versions: VersionReq::parse("^1.2")?,
    };

    let error = command
        .resolve_executable()
        .expect_err("missing executable must fail");
    assert_eq!(error.code(), SidecarErrorCode::ExecutableMissing);
    assert!(!format!("{error:?}").contains("missing-provider-executable"));
    Ok(())
}

fn executable_is_canonical_regular_and_trusted() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let executable = env::current_exe()?;
        let configured = executable
            .parent()
            .ok_or("test executable has no parent")?
            .join(".")
            .join(
                executable
                    .file_name()
                    .ok_or("test executable has no file name")?,
            );
        let mut command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        command.executable = configured;
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let canonical = fs::canonicalize(executable)?;
        assert_eq!(sidecar.executable_path(), canonical);
        let identity = sidecar
            .request(json!({"id": "identity", "method": "identity"}))
            .await?;
        assert_eq!(identity["result"].as_str(), canonical.to_str());
        assert_eq!(
            fs::read_to_string(layout.home.join("version-executable-path"))?,
            canonical.to_string_lossy()
        );
        sidecar.cancel().await?;
        TestResult::Ok(())
    })?;

    let directory_layout = TestLayout::new()?;
    let mut directory = fixture_command(&directory_layout, "strict-jsonl", "1.2.3");
    directory.executable = directory_layout.data.clone();
    let error = directory
        .resolve_executable()
        .expect_err("an executable candidate must be a regular file");
    assert_eq!(error.code(), SidecarErrorCode::ExecutableUnavailable);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let writable_layout = TestLayout::new()?;
        let writable_executable = writable_layout.data.join("writable-sidecar");
        fs::copy(env::current_exe()?, &writable_executable)?;
        fs::set_permissions(&writable_executable, fs::Permissions::from_mode(0o777))?;
        let mut writable = fixture_command(&writable_layout, "strict-jsonl", "1.2.3");
        writable.executable = writable_executable;
        let error = writable
            .resolve_executable()
            .expect_err("a broadly writable executable must be rejected");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);

        let unsafe_parent_layout = TestLayout::new()?;
        let unsafe_parent = unsafe_parent_layout.data.join("unsafe-bin");
        fs::create_dir(&unsafe_parent)?;
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777))?;
        let nested_executable = unsafe_parent.join("provider");
        fs::copy(env::current_exe()?, &nested_executable)?;
        fs::set_permissions(&nested_executable, fs::Permissions::from_mode(0o755))?;
        let mut nested = fixture_command(&unsafe_parent_layout, "strict-jsonl", "1.2.3");
        nested.executable = nested_executable;
        let error = nested
            .resolve_executable()
            .expect_err("an executable under a broadly writable parent must be rejected");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);
    }

    Ok(())
}

fn executable_trust_precedes_every_execution() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let resolved = command.resolve_executable()?;
        let canonical = fs::canonicalize(env::current_exe()?)?;
        assert_eq!(resolved.canonical_path(), canonical);
        assert!(
            !layout.home.join("version-executable-path").exists(),
            "resolving a candidate must not execute it"
        );

        let trusted = resolved.trust(ExecutableTrustDecision::TrustCanonicalPath);
        assert_eq!(
            command
                .detect_trusted_version(&trusted, &layout.data, &layout.workspace, short_limits(),)
                .await?,
            Version::parse("1.2.3")?
        );
        assert!(layout.home.join("version-executable-path").is_file());
        TestResult::Ok(())
    })
}

fn sidecar_limits_reject_unbounded_configurations() -> TestResult {
    run_async(async {
        for limits in [
            SidecarLimits {
                max_stdout_line_bytes: 1024 * 1024 + 1,
                ..short_limits()
            },
            SidecarLimits {
                max_stderr_bytes: 64 * 1024 + 1,
                ..short_limits()
            },
            SidecarLimits {
                graceful_shutdown_timeout: Duration::from_secs(31),
                ..short_limits()
            },
            SidecarLimits {
                process_poll_interval: Duration::from_millis(151),
                ..short_limits()
            },
        ] {
            let layout = TestLayout::new()?;
            let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
            let trusted = command
                .resolve_executable()?
                .trust(ExecutableTrustDecision::TrustCanonicalPath);
            let error = JsonlSidecar::spawn_trusted(
                command,
                &trusted,
                &layout.data,
                &layout.workspace,
                limits,
            )
            .await
            .expect_err("unsafe sidecar limits must be rejected");
            assert_eq!(error.code(), SidecarErrorCode::InvalidConfiguration);
            assert!(!layout.home.join("version-executable-path").exists());
        }
        TestResult::Ok(())
    })
}

fn versions_are_parsed_and_pinned() -> TestResult {
    let supported_layout = TestLayout::new()?;
    let supported = fixture_command(&supported_layout, "strict-jsonl", "1.4.7");
    assert_eq!(
        run_async(detect_version(
            &supported,
            &supported_layout.data,
            &supported_layout.workspace,
        ))?,
        Version::parse("1.4.7")?
    );

    let unsupported_layout = TestLayout::new()?;
    let unsupported = fixture_command(&unsupported_layout, "strict-jsonl", "2.0.0");
    let error = run_async(detect_version(
        &unsupported,
        &unsupported_layout.data,
        &unsupported_layout.workspace,
    ))
    .expect_err("a version outside the pinned range must fail");
    assert_eq!(error.code(), SidecarErrorCode::UnsupportedVersion);
    assert!(!error.to_string().contains("2.0.0"));

    let malformed_layout = TestLayout::new()?;
    let malformed = fixture_command(&malformed_layout, "strict-jsonl", "not-a-version");
    let error = run_async(detect_version(
        &malformed,
        &malformed_layout.data,
        &malformed_layout.workspace,
    ))
    .expect_err("unparseable version output must fail");
    assert_eq!(error.code(), SidecarErrorCode::ProtocolViolation);

    let grok_layout = TestLayout::new()?;
    let mut grok = fixture_command(&grok_layout, "strict-jsonl", "1.8.2");
    grok.version_arguments = vec![
        OsString::from(support::FIXTURE_ARGUMENT),
        OsString::from("version-grok"),
        OsString::from("1.8.2"),
        OsString::from("--no-auto-update"),
        OsString::from("version"),
    ];
    grok.version_output = VersionOutputFormat::SingleSemverToken;
    assert_eq!(
        run_async(detect_version(
            &grok,
            &grok_layout.data,
            &grok_layout.workspace,
        ))?,
        Version::parse("1.8.2")?
    );

    let closed_format_layout = TestLayout::new()?;
    let mut closed_format = fixture_command(&closed_format_layout, "strict-jsonl", "1.8.2");
    closed_format.version_arguments = vec![
        OsString::from(support::FIXTURE_ARGUMENT),
        OsString::from("version-grok"),
        OsString::from("1.8.2"),
        OsString::from("--no-auto-update"),
        OsString::from("version"),
    ];
    closed_format.version_output = VersionOutputFormat::ExactPrefix("codex-cli");
    let error = run_async(detect_version(
        &closed_format,
        &closed_format_layout.data,
        &closed_format_layout.workspace,
    ))
    .expect_err("provider version formats must not be interchangeable");
    assert_eq!(error.code(), SidecarErrorCode::ProtocolViolation);

    for (scenario, expected) in [
        ("version-nonzero", SidecarErrorCode::ProtocolViolation),
        ("version-multiple", SidecarErrorCode::ProtocolViolation),
        ("version-oversized", SidecarErrorCode::ProtocolViolation),
    ] {
        let layout = TestLayout::new()?;
        let mut command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        command.version_arguments = vec![
            OsString::from(support::FIXTURE_ARGUMENT),
            OsString::from(scenario),
            OsString::from("1.2.3"),
        ];
        command.version_output = if scenario == "version-multiple" {
            VersionOutputFormat::SingleSemverToken
        } else {
            VersionOutputFormat::ExactPrefix("carl-sidecar-fixture")
        };
        let error = run_async(detect_version(&command, &layout.data, &layout.workspace))
            .expect_err("invalid or failed version output must fail closed");
        assert_eq!(error.code(), expected);
    }

    let hanging_layout = TestLayout::new()?;
    let mut hanging = fixture_command(&hanging_layout, "strict-jsonl", "1.2.3");
    hanging.version_arguments = vec![
        OsString::from(support::FIXTURE_ARGUMENT),
        OsString::from("version-hanging"),
        OsString::from("1.2.3"),
    ];
    let error = run_async(detect_version(
        &hanging,
        &hanging_layout.data,
        &hanging_layout.workspace,
    ))
    .expect_err("a hanging version probe must time out");
    assert_eq!(error.code(), SidecarErrorCode::TimedOut);
    let pids = run_async(wait_for_fixture_pids(&hanging_layout.home))?;
    run_async(wait_until_processes_reaped(&[pids.0]))?;
    run_async(wait_until_processes_exit(&[pids.1]))?;
    Ok(())
}

fn provider_home_is_isolated_and_private() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;

        assert!(layout.home.is_absolute());
        assert!(layout.home.starts_with(&layout.data));
        assert!(!layout.home.starts_with(&layout.workspace));
        assert!(layout.home.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&layout.home)?.permissions().mode() & 0o777,
                0o700
            );
        }

        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn provider_home_writes_static_files_through_its_capability() -> TestResult {
    let layout = TestLayout::new()?;
    let home = ProviderHome::prepare(
        ProviderEnvironmentProfile::Codex,
        &layout.data,
        &layout.workspace,
        &layout.home,
    )?;
    assert!(home.matches_path(&layout.home));

    home.write_static_file("config.toml", b"first = true\n")?;
    assert_eq!(
        fs::read(layout.home.join("config.toml"))?,
        b"first = true\n"
    );
    home.write_static_file("config.toml", b"second = true\n")?;
    assert_eq!(
        fs::read(layout.home.join("config.toml"))?,
        b"second = true\n"
    );

    let config = layout.home.join("config.toml");
    let hard_link = layout.home.join("config-hard-link.toml");
    fs::hard_link(&config, &hard_link)?;
    let error = home
        .write_static_file("config.toml", b"must not replace a hard link\n")
        .expect_err("hard-linked provider config must fail closed");
    assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
    fs::remove_file(&hard_link)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};

        assert_eq!(fs::metadata(&config)?.permissions().mode() & 0o777, 0o600);
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644))?;
        let error = home
            .write_static_file("config.toml", b"must not replace broad config\n")
            .expect_err("non-owner-only provider config must fail closed");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;

        let outside = layout.data.join("outside-config.toml");
        fs::write(&outside, b"outside\n")?;
        fs::remove_file(&config)?;
        symlink(&outside, &config)?;
        let error = home
            .write_static_file("config.toml", b"must not follow a symlink\n")
            .expect_err("symlinked provider config must fail closed");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
        assert_eq!(fs::read(outside)?, b"outside\n");
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::symlink_file;

        let outside = layout.data.join("outside-config.toml");
        fs::write(&outside, b"outside\r\n")?;
        fs::remove_file(&config)?;
        if symlink_file(&outside, &config).is_ok() {
            let error = home
                .write_static_file("config.toml", b"must not follow a reparse point\r\n")
                .expect_err("reparse-point provider config must fail closed");
            assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
            assert_eq!(fs::read(outside)?, b"outside\r\n");
        }
    }
    Ok(())
}

fn unsafe_provider_homes_are_rejected() -> TestResult {
    let inside_workspace = TestLayout::new()?;
    let mut command = fixture_command(&inside_workspace, "strict-jsonl", "1.2.3");
    command.isolated_home = inside_workspace.workspace.join("provider-home");
    let error = run_async(spawn_fixture(command, &inside_workspace, short_limits()))
        .expect_err("a provider home inside the workspace must be rejected");
    assert_eq!(error.code(), SidecarErrorCode::InvalidProviderHome);

    let relative_root = TestLayout::new()?;
    let command = fixture_command(&relative_root, "strict-jsonl", "1.2.3");
    let trusted = command
        .resolve_executable()?
        .trust(ExecutableTrustDecision::TrustCanonicalPath);
    let error = run_async(JsonlSidecar::spawn_trusted(
        command,
        &trusted,
        PathBuf::from("relative-data-root"),
        &relative_root.workspace,
        short_limits(),
    ))
    .expect_err("a relative Carl data root must be rejected");
    assert_eq!(error.code(), SidecarErrorCode::InvalidProviderHome);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let symlinked = TestLayout::new()?;
        let actual = symlinked.data.join("actual");
        fs::create_dir(&actual)?;
        symlink(&actual, symlinked.data.join("linked"))?;
        let mut command = fixture_command(&symlinked, "strict-jsonl", "1.2.3");
        command.isolated_home = symlinked.data.join("linked").join("provider");
        let error = run_async(spawn_fixture(command, &symlinked, short_limits()))
            .expect_err("a symlink in the provider-home path must be rejected");
        assert_eq!(error.code(), SidecarErrorCode::InvalidProviderHome);
    }

    Ok(())
}

fn child_environment_is_allowlisted() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let response = sidecar
            .request(json!({
                "id": "environment",
                "method": "environment",
            }))
            .await?;
        let environment = response["result"]
            .as_object()
            .ok_or("fixture environment result was not an object")?;
        let canonical_home = fs::canonicalize(&layout.home)?;
        let canonical_temp = fs::canonicalize(layout.home.join(".carl-tmp"))?;

        assert!(
            environment
                .get(support::FIXTURE_HOME_VARIABLE)
                .and_then(serde_json::Value::as_str)
                == canonical_home.to_str()
        );
        for forbidden in [
            "OPENAI_API_KEY",
            "TELEGRAM_BOT_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "GROK_HOME",
            "XDG_CONFIG_HOME",
            "BROWSER",
            "OPENAI_BASE_URL",
            "GROK_API_KEY",
        ] {
            assert!(
                !environment.contains_key(forbidden),
                "forbidden parent variable reached the child: {forbidden}"
            );
        }
        let mut allowed = carl::sidecar::allowed_environment_variables()
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        allowed.push(support::FIXTURE_HOME_VARIABLE.to_owned());
        assert!(
            environment
                .keys()
                .all(|name| allowed.iter().any(|allowed| allowed == name)),
            "child received a variable outside the allowlist: {environment:?}"
        );
        let child_path = environment
            .get("PATH")
            .and_then(serde_json::Value::as_str)
            .ok_or("child PATH was not configured")?;
        assert!(
            env::split_paths(child_path)
                .all(|entry| entry.as_os_str() != OsStr::new(PATH_SENTINEL)),
            "the untrusted parent PATH prefix reached the child"
        );
        assert_eq!(
            environment.get("HOME").and_then(serde_json::Value::as_str),
            canonical_home.to_str()
        );
        for variable in ["TEMP", "TMP"] {
            assert_eq!(
                environment
                    .get(variable)
                    .and_then(serde_json::Value::as_str),
                canonical_temp.to_str()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&canonical_temp)?.permissions().mode() & 0o777,
                0o700
            );
        }

        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn grok_environment_profile_is_closed() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let trusted = command
            .resolve_executable()?
            .trust(ExecutableTrustDecision::TrustCanonicalPath);
        let home = ProviderHome::prepare(
            ProviderEnvironmentProfile::Grok,
            &layout.data,
            &layout.workspace,
            &layout.home,
        )?;
        let sidecar = JsonlSidecar::spawn_in_home(
            command,
            &trusted,
            &home,
            NotificationPolicy::Reject,
            short_limits(),
        )
        .await?;
        let response = sidecar
            .request(json!({"id": "grok-environment", "method": "environment"}))
            .await?;
        let environment = response["result"]
            .as_object()
            .ok_or("Grok fixture environment was not an object")?;
        let canonical_home = fs::canonicalize(&layout.home)?;
        let canonical_temp = fs::canonicalize(layout.home.join(".carl-tmp"))?;
        assert_eq!(
            environment
                .get("GROK_HOME")
                .and_then(serde_json::Value::as_str),
            canonical_home.to_str()
        );
        assert_eq!(
            environment
                .get("GROK_DISABLE_AUTOUPDATER")
                .and_then(serde_json::Value::as_str),
            Some("1")
        );
        assert_eq!(
            environment.get("HOME").and_then(serde_json::Value::as_str),
            canonical_home.to_str()
        );
        for variable in ["TEMP", "TMP"] {
            assert_eq!(
                environment
                    .get(variable)
                    .and_then(serde_json::Value::as_str),
                canonical_temp.to_str()
            );
        }
        assert!(!environment.contains_key("CODEX_HOME"));
        assert!(!environment.contains_key("BROWSER"));
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn responses_correlate_out_of_order() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let first = sidecar.request(json!({
            "id": "first",
            "value": "slow",
            "delay_ms": 75,
        }));
        let second = sidecar.request(json!({
            "id": "second",
            "value": "fast",
            "delay_ms": 0,
        }));
        let (first, second) = tokio::join!(first, second);

        assert_eq!(first?["result"], "slow");
        assert_eq!(second?["result"], "fast");
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn abandoned_written_request_consumes_one_late_response() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = std::sync::Arc::new(spawn_fixture(command, &layout, short_limits()).await?);

        let active_sidecar = std::sync::Arc::clone(&sidecar);
        let active = tokio::spawn(async move {
            active_sidecar
                .request(json!({
                    "id": "active",
                    "method": "delay-after-received",
                    "value": "original",
                    "delay_ms": 50,
                }))
                .await
        });
        assert_eq!(
            sidecar.next_notification().await?["method"],
            "fixture/received"
        );
        let duplicate = sidecar
            .request(json!({"id": "active", "value": "duplicate"}))
            .await
            .expect_err("an active request ID must not be reused");
        assert_eq!(duplicate.code(), SidecarErrorCode::DuplicateRequestId);
        assert_eq!(active.await??["result"], "original");

        let abandoned_sidecar = std::sync::Arc::clone(&sidecar);
        let abandoned = tokio::spawn(async move {
            abandoned_sidecar
                .request(json!({
                    "id": "reusable",
                    "method": "delay-after-received",
                    "value": "late",
                    "delay_ms": 100,
                }))
                .await
        });
        let received = sidecar.next_notification().await?;
        assert_eq!(received["method"], "fixture/received");
        abandoned.abort();
        let _ = abandoned.await;

        let duplicate = sidecar
            .request(json!({"id": "reusable", "value": "too-early"}))
            .await
            .expect_err("an ambiguous request ID must not be reused");
        assert_eq!(duplicate.code(), SidecarErrorCode::DuplicateRequestId);

        let survivor = sidecar
            .request(json!({"id": "survivor", "value": "still-running"}))
            .await?;
        assert_eq!(survivor["result"], "still-running");
        tokio::time::sleep(Duration::from_millis(125)).await;

        let reused = sidecar
            .request(json!({"id": "reusable", "value": "safe-now"}))
            .await?;
        assert_eq!(reused["result"], "safe-now");
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn prewrite_drop_permits_safe_id_reuse() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let never_polled = sidecar.request(json!({"id": "not-written", "value": "discard"}));
        drop(never_polled);
        let response = sidecar
            .request(json!({"id": "not-written", "value": "reused"}))
            .await?;
        assert_eq!(response["result"], "reused");
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn abandoned_request_budget_fails_safely() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = std::sync::Arc::new(spawn_fixture(command, &layout, short_limits()).await?);
        let pid = sidecar.process_id().ok_or("fixture PID was unavailable")?;

        for sequence in 1..=129_u64 {
            let request_sidecar = std::sync::Arc::clone(&sidecar);
            let request = tokio::spawn(async move {
                request_sidecar
                    .request(json!({
                        "id": format!("abandoned-{sequence}"),
                        "method": "delay-recorded",
                        "delay_ms": 30_000,
                    }))
                    .await
            });
            wait_for_received_count(&layout.home, sequence).await?;
            request.abort();
            let _ = request.await;
        }

        let error = sidecar
            .request(json!({"id": "after-budget"}))
            .await
            .expect_err("an exhausted ambiguity budget must stop the sidecar");
        assert!(matches!(
            error.code(),
            SidecarErrorCode::ProtocolViolation | SidecarErrorCode::SidecarExited
        ));
        wait_until_processes_reaped(&[pid]).await?;
        TestResult::Ok(())
    })
}

fn leader_exit_preserves_its_final_response() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "final-response-exit", "1.2.3");
        let sidecar = std::sync::Arc::new(spawn_fixture(command, &layout, short_limits()).await?);
        let pids = wait_for_fixture_pids(&layout.home).await?;
        let first_sidecar = std::sync::Arc::clone(&sidecar);
        let first = tokio::spawn(async move {
            first_sidecar
                .request(json!({"id": "last", "value": "delivered"}))
                .await
        });
        wait_for_received_count(&layout.home, 1).await?;
        let unresolved = sidecar.request(json!({"id": "unresolved", "value": false}));
        let (response, unresolved) = tokio::join!(first, unresolved);
        let response = response??;
        assert_eq!(response["result"], "delivered");
        assert_eq!(
            unresolved
                .expect_err("leader exit must fail the unresolved request")
                .code(),
            SidecarErrorCode::SidecarExited
        );
        wait_until_processes_exit(&[pids.0, pids.1]).await?;
        TestResult::Ok(())
    })
}

fn notifications_are_bounded_and_delivered() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let request = sidecar.request(json!({
            "id": 7,
            "method": "emit-notification",
            "value": "complete",
        }));
        let notification = sidecar.next_notification();
        let (response, notification) = tokio::join!(request, notification);
        assert_eq!(response?["result"], "complete");
        assert_eq!(notification?["method"], "auth/progress");
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn outbound_notifications_and_nonblocking_receive_are_bounded() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        assert_eq!(sidecar.try_next_notification().await?, None);

        sidecar.notify(json!({
            "method": "client/ready",
            "params": {"headless": true},
        }))?;
        let notification_path = layout.home.join("outbound-notification.json");
        for _ in 0..500 {
            if notification_path.is_file() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let outbound: serde_json::Value = serde_json::from_slice(&fs::read(notification_path)?)?;
        assert_eq!(outbound["method"], "client/ready");

        let response = sidecar
            .request(json!({
                "id": "buffer-one",
                "method": "emit-notification",
                "value": true,
            }))
            .await?;
        assert_eq!(response["result"], true);
        let buffered = sidecar
            .try_next_notification()
            .await?
            .ok_or("expected one buffered notification")?;
        assert_eq!(buffered["method"], "auth/progress");
        assert_eq!(sidecar.try_next_notification().await?, None);

        let error = sidecar
            .notify(json!({"method": "client/ready", "value": "x".repeat(16_384)}))
            .expect_err("oversized outbound notification must be rejected");
        assert_eq!(error.code(), SidecarErrorCode::ProtocolViolation);
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn notification_rejection_policy_fails_closed() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let trusted = command
            .resolve_executable()?
            .trust(ExecutableTrustDecision::TrustCanonicalPath);
        let home = ProviderHome::prepare(
            ProviderEnvironmentProfile::Codex,
            &layout.data,
            &layout.workspace,
            &layout.home,
        )?;
        let sidecar = JsonlSidecar::spawn_in_home(
            command,
            &trusted,
            &home,
            NotificationPolicy::Reject,
            short_limits(),
        )
        .await?;
        let error = sidecar
            .request(json!({
                "id": "reject-notification",
                "method": "emit-notification",
            }))
            .await
            .expect_err("a forbidden inbound notification must fail immediately");
        assert_eq!(error.code(), SidecarErrorCode::ProtocolViolation);
        TestResult::Ok(())
    })
}

fn invalid_request_ids_are_rejected() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        for request in [
            json!({"id": 1.5}),
            json!({"id": 18_446_744_073_709_551_615_u64}),
            json!({"id": null}),
            json!({"id": true}),
        ] {
            assert_eq!(
                sidecar.request(request).await.unwrap_err().code(),
                SidecarErrorCode::ProtocolViolation
            );
        }
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn unknown_response_ids_fail_closed() -> TestResult {
    assert_protocol_failure("unknown-id")
}

fn malformed_stdout_fails_closed() -> TestResult {
    assert_protocol_failure("malformed")
}

fn oversized_stdout_fails_closed() -> TestResult {
    assert_protocol_failure("oversized")
}

fn assert_protocol_failure(scenario: &str) -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, scenario, "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let pid = sidecar.process_id().ok_or("fixture PID was unavailable")?;
        let error = sidecar
            .request(json!({"id": "invalid-response"}))
            .await
            .expect_err("invalid sidecar stdout must fail closed");
        assert_eq!(error.code(), SidecarErrorCode::ProtocolViolation);
        wait_until_processes_reaped(&[pid]).await?;
        assert_eq!(sidecar.process_id(), Some(pid));
        Ok(())
    })
}

fn stderr_is_bounded_and_redacted() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "stderr", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        sidecar
            .request(json!({"id": "stderr", "value": true}))
            .await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let stderr = sidecar.stderr_snapshot();
        assert!(stderr.len() <= short_limits().max_stderr_bytes);
        assert!(!stderr.contains(SECRET_SENTINEL));
        assert!(stderr.contains("redacted"));
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn child_exit_wakes_every_pending_request() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "exit-with-pending", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let (first, second) = tokio::join!(
            sidecar.request(json!({"id": "first"})),
            sidecar.request(json!({"id": "second"})),
        );
        for result in [first, second] {
            let error = result.expect_err("child exit must wake each pending request");
            assert_eq!(error.code(), SidecarErrorCode::SidecarExited);
            assert!(!format!("{error:?}").contains("23"));
        }
        TestResult::Ok(())
    })
}

fn explicit_cancellation_removes_process_group() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "grandchild", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let pids = wait_for_fixture_pids(&layout.home).await?;
        assert_eq!(sidecar.process_id(), Some(pids.0));

        sidecar.cancel().await?;
        wait_until_processes_exit(&[pids.0, pids.1]).await?;
        assert_owner_only_pid_file(&layout.home)?;
        TestResult::Ok(())
    })
}

fn cancellation_cannot_deadlock_on_full_stdin() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "blocked-stdin", "1.2.3");
        let sidecar = std::sync::Arc::new(spawn_fixture(command, &layout, short_limits()).await?);
        let mut requests = Vec::new();
        for id in 0..128_i64 {
            let sidecar = std::sync::Arc::clone(&sidecar);
            requests.push(tokio::spawn(async move {
                sidecar
                    .request(json!({"id": id, "value": "x".repeat(7_000)}))
                    .await
            }));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::time::timeout(Duration::from_secs(3), sidecar.cancel())
            .await
            .map_err(|_| "cancel deadlocked behind the full sidecar stdin pipe")??;
        for request in requests {
            let error = request
                .await?
                .expect_err("pending blocked writes must be failed on cancellation");
            assert!(matches!(
                error.code(),
                SidecarErrorCode::Cancelled | SidecarErrorCode::SidecarExited
            ));
        }
        TestResult::Ok(())
    })
}

fn leader_exit_removes_ordinary_descendants() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "grandchild-exit", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let pids = wait_for_fixture_pids(&layout.home).await?;
        wait_until_processes_exit(&[pids.0, pids.1]).await?;
        drop(sidecar);
        TestResult::Ok(())
    })
}

fn dropping_supervisor_removes_process_group() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "grandchild", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let pids = wait_for_fixture_pids(&layout.home).await?;
        drop(sidecar);
        wait_until_processes_exit(&[pids.0, pids.1]).await?;
        TestResult::Ok(())
    })
}

fn assert_owner_only_pid_file(home: &std::path::Path) -> TestResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(home.join("fixture-pids.json"))?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    Ok(())
}
