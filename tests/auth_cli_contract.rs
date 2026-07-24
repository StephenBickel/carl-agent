#[allow(dead_code)]
#[path = "support/sidecar.rs"]
mod support;

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::process;

#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::fd::FromRawFd;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(unix)]
use std::process::{ExitStatus, Stdio};
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use carl::auth::codex::CODEX_LOGOUT_WARNING;
use carl::cli::Cli;
use clap::{CommandFactory, Parser};
use libtest_mimic::{Arguments, Failed, Trial};
use serde_json::Value;
use support::{
    CODEX_SECRET_SENTINEL, GROK_SECRET_SENTINEL, TestLayout, dispatch_codex_auth_fixture,
    dispatch_fixture, dispatch_grok_auth_fixture, processes_have_been_reaped,
    processes_have_exited,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if let Some(exit_code) = dispatch_codex_auth_fixture(&arguments)
        .or_else(|| dispatch_grok_auth_fixture(&arguments))
        .or_else(|| dispatch_fixture(&arguments))
    {
        process::exit(exit_code);
    }

    let mut trials = vec![
        test(
            "the exact seven auth commands parse",
            exact_auth_commands_parse,
        ),
        test(
            "invalid auth command arrangements fail closed",
            invalid_auth_commands_fail_closed,
        ),
        test(
            "auth help exposes only the implemented tree",
            auth_help_is_exact,
        ),
        test(
            "status renders a complete safe array when configuration is missing",
            status_missing_configuration_is_safe,
        ),
        test(
            "redirected login fails before configuration or provider launch",
            redirected_login_requires_foreground,
        ),
        test(
            "status reports both providers in fixed order without mutation",
            status_is_complete_ordered_and_read_only,
        ),
        test(
            "status isolates one unavailable provider and still succeeds",
            status_isolates_provider_failure,
        ),
        test(
            "failed Codex construction is reaped before status returns",
            failed_codex_connect_is_reaped,
        ),
    ];
    trials.push(test(
        "real auth commands contend per root and recover after a crash",
        public_auth_lock_contends_and_recovers,
    ));
    #[cfg(unix)]
    trials.push(test(
        "Grok foreground output is routed to stderr while stdout stays JSON",
        grok_foreground_output_is_stderr_only,
    ));
    #[cfg(unix)]
    trials.push(test(
        "OpenAI browser and device login render only verified challenges",
        openai_login_challenges_are_stderr_only,
    ));
    #[cfg(unix)]
    trials.push(test(
        "already-signed-in login skips the ceremony",
        signed_in_login_is_idempotent,
    ));
    #[cfg(unix)]
    trials.push(test(
        "OpenAI and Grok logout reconcile signed-out state",
        provider_logouts_reconcile_signed_out,
    ));
    #[cfg(unix)]
    trials.push(test(
        "early SIGINT is captured and cleaned before login returns 130",
        early_sigint_cancels_connect_safely,
    ));
    #[cfg(unix)]
    trials.push(test(
        "in-flight Grok cancellation kills and reaps its process tree",
        inflight_grok_sigint_reaps_process_tree,
    ));
    #[cfg(unix)]
    trials.push(test(
        "failed Grok post-login reconciliation stays unavailable",
        grok_failed_reconciliation_is_not_success,
    ));
    libtest_mimic::run(&Arguments::from_args(), trials).exit();
}

fn test(name: &'static str, body: fn() -> TestResult) -> Trial {
    Trial::test(name, move || {
        body().map_err(|error| Failed::from(error.to_string()))
    })
}

fn exact_auth_commands_parse() -> TestResult {
    for arguments in [
        vec!["carl", "auth", "status"],
        vec!["carl", "auth", "login", "openai"],
        vec!["carl", "auth", "login", "openai", "--device"],
        vec!["carl", "auth", "logout", "openai"],
        vec!["carl", "auth", "login", "grok"],
        vec!["carl", "auth", "login", "grok", "--device"],
        vec!["carl", "auth", "logout", "grok"],
    ] {
        Cli::try_parse_from(&arguments)
            .map_err(|error| format!("valid invocation {arguments:?} failed: {error}"))?;
    }
    Ok(())
}

fn invalid_auth_commands_fail_closed() -> TestResult {
    for arguments in [
        vec!["carl", "auth"],
        vec!["carl", "auth", "status", "openai"],
        vec!["carl", "auth", "status", "--device"],
        vec!["carl", "auth", "login"],
        vec!["carl", "auth", "login", "openai_codex"],
        vec!["carl", "auth", "login", "xai_grok"],
        vec!["carl", "auth", "logout"],
        vec!["carl", "auth", "logout", "grok", "--device"],
        vec!["carl", "auth", "authorize", "openai"],
    ] {
        if Cli::try_parse_from(&arguments).is_ok() {
            return Err(format!("invalid invocation parsed successfully: {arguments:?}").into());
        }
    }
    Ok(())
}

fn auth_help_is_exact() -> TestResult {
    let command = Cli::command();
    let auth = command
        .find_subcommand("auth")
        .ok_or("root help omitted auth")?;
    let auth_commands: BTreeSet<_> = auth
        .get_subcommands()
        .map(|subcommand| subcommand.get_name())
        .collect();
    assert_eq!(auth_commands, BTreeSet::from(["login", "logout", "status"]));

    let login = auth
        .find_subcommand("login")
        .ok_or("auth help omitted login")?;
    let help = login.clone().render_long_help().to_string();
    for expected in ["openai", "grok", "--device"] {
        assert!(
            help.contains(expected),
            "auth login help omitted {expected:?}: {help}"
        );
    }

    let root_help = Cli::command().render_long_help().to_string();
    for absent in ["model", "chat", "run", "delegate"] {
        assert!(
            !root_help
                .lines()
                .any(|line| line.split_whitespace().next() == Some(absent)),
            "root help unexpectedly exposed {absent}"
        );
    }
    Ok(())
}

fn status_missing_configuration_is_safe() -> TestResult {
    let layout = TestLayout::new()?;
    let output = carl_command(&layout).args(["auth", "status"]).output()?;

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stdout)?,
        concat!(
            "[{\"service\":\"openai_codex\",\"availability\":\"unavailable\",",
            "\"state\":\"unavailable\",\"method\":null,\"plan\":null,",
            "\"error_code\":\"provider_rejected\"},",
            "{\"service\":\"xai_grok\",\"availability\":\"unavailable\",",
            "\"state\":\"unavailable\",\"method\":null,\"plan\":null,",
            "\"error_code\":\"provider_rejected\"}]\n"
        )
    );
    assert_eq!(output.stderr, b"");
    Ok(())
}

fn redirected_login_requires_foreground() -> TestResult {
    for (provider, service, operation) in [
        ("codex", "openai_codex", ["login", "openai"]),
        ("codex", "openai_codex", ["logout", "openai"]),
        ("grok", "xai_grok", ["login", "grok"]),
        ("grok", "xai_grok", ["logout", "grok"]),
    ] {
        let layout = TestLayout::new()?;
        write_provider_scenario(&layout, provider, "signed-out")?;
        let output = configured_carl_command(&layout)
            .arg("auth")
            .args(operation)
            .output()?;

        assert_eq!(output.status.code(), Some(1));
        assert_eq!(
            String::from_utf8(output.stdout)?,
            format!(
                "{{\"service\":\"{service}\",\"availability\":\"unavailable\",\
                 \"state\":\"unavailable\",\"method\":null,\"plan\":null,\
                 \"error_code\":\"foreground_required\"}}\n"
            )
        );
        assert_eq!(output.stderr, b"");
        assert!(
            !layout
                .data
                .join(format!("providers/{provider}/codex-launch.json"))
                .exists()
        );
        assert!(
            !layout
                .data
                .join(format!("providers/{provider}/grok-launches.jsonl"))
                .exists()
        );
    }
    Ok(())
}

fn status_is_complete_ordered_and_read_only() -> TestResult {
    let layout = TestLayout::new()?;
    write_provider_scenario(&layout, "codex", "account-plan-plus")?;
    write_provider_scenario(&layout, "grok", "signed-out")?;

    let output = configured_carl_command(&layout)
        .args(["auth", "status"])
        .output()?;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stdout)?,
        concat!(
            "[{\"service\":\"openai_codex\",\"availability\":\"available\",",
            "\"state\":\"signed_in\",\"method\":\"provider_managed\",\"plan\":\"plus\",",
            "\"error_code\":null},",
            "{\"service\":\"xai_grok\",\"availability\":\"available\",",
            "\"state\":\"signed_out\",\"method\":null,\"plan\":null,\"error_code\":null}]\n"
        )
    );
    assert_eq!(output.stderr, b"");

    let codex_home = layout.data.join("providers").join("codex");
    let codex_requests = fs::read_to_string(codex_home.join("codex-requests.jsonl"))?;
    assert!(!codex_requests.contains("account/login/start"));
    assert!(!codex_requests.contains("account/logout"));

    let grok_home = layout.data.join("providers").join("grok");
    let grok_launches = fs::read_to_string(grok_home.join("grok-launches.jsonl"))?;
    assert!(!grok_launches.contains("\"login\""));
    assert!(!grok_launches.contains("\"logout\""));
    let codex_launch = fs::read_to_string(codex_home.join("codex-launch.json"))?;
    for sentinel in [CODEX_SECRET_SENTINEL, GROK_SECRET_SENTINEL] {
        assert!(!codex_launch.contains(sentinel));
        assert!(!grok_launches.contains(sentinel));
    }
    let codex_launch_value: Value = serde_json::from_str(&codex_launch)?;
    let codex_pid = codex_launch_value["processId"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or("Codex status PID was not a u32")?;
    assert!(
        processes_have_been_reaped(&[codex_pid]),
        "successful status returned before the Codex sidecar was reaped"
    );
    Ok(())
}

fn status_isolates_provider_failure() -> TestResult {
    let layout = TestLayout::new()?;
    write_provider_scenario(&layout, "codex", "unsupported-version")?;
    write_provider_scenario(&layout, "grok", "signed-out")?;

    let output = configured_carl_command(&layout)
        .args(["auth", "status"])
        .output()?;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stdout)?,
        concat!(
            "[{\"service\":\"openai_codex\",\"availability\":\"unavailable\",",
            "\"state\":\"unavailable\",\"method\":null,\"plan\":null,",
            "\"error_code\":\"unsupported_version\"},",
            "{\"service\":\"xai_grok\",\"availability\":\"available\",",
            "\"state\":\"signed_out\",\"method\":null,\"plan\":null,\"error_code\":null}]\n"
        )
    );
    assert_eq!(output.stderr, b"");
    assert!(
        layout
            .data
            .join("providers/grok/grok-requests.jsonl")
            .exists(),
        "Grok status was skipped after Codex became unavailable"
    );
    Ok(())
}

fn failed_codex_connect_is_reaped() -> TestResult {
    let layout = TestLayout::new()?;
    write_provider_scenario(&layout, "codex", "wrong-codex-home")?;
    write_provider_scenario(&layout, "grok", "signed-out")?;

    let output = configured_carl_command(&layout)
        .args(["auth", "status"])
        .output()?;
    assert_eq!(output.status.code(), Some(0));
    let records: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(records[0]["error_code"], "protocol_mismatch");
    assert_eq!(records[1]["state"], "signed_out");
    assert_eq!(output.stderr, b"");

    let launch: Value = serde_json::from_slice(&fs::read(
        layout.data.join("providers/codex/codex-launch.json"),
    )?)?;
    let pid = launch["processId"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or("Codex launch PID was not a u32")?;
    assert!(
        processes_have_been_reaped(&[pid]),
        "failed Codex construction returned while its sidecar leader still existed"
    );
    Ok(())
}

fn public_auth_lock_contends_and_recovers() -> TestResult {
    let first = TestLayout::new()?;
    write_provider_scenario(&first, "codex", "status-hold")?;
    let mut holder = HoldingStatus::spawn(&first)?;
    holder.wait_until_provider_started()?;

    let lock_path = first.data.join(".carl-instance.lock");
    let lock_identity = lock_file_identity(&lock_path)?;
    let held_pid = fs::read_to_string(first.data.join("providers/codex/status-hold-pid"))?;

    let contended = configured_carl_command(&first)
        .args(["auth", "status"])
        .output()?;
    assert_eq!(contended.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(contended.stdout)?,
        concat!(
            "[{\"service\":\"openai_codex\",\"availability\":\"unavailable\",",
            "\"state\":\"unavailable\",\"method\":null,\"plan\":null,",
            "\"error_code\":\"provider_rejected\"},",
            "{\"service\":\"xai_grok\",\"availability\":\"unavailable\",",
            "\"state\":\"unavailable\",\"method\":null,\"plan\":null,",
            "\"error_code\":\"provider_rejected\"}]\n"
        )
    );
    assert_eq!(contended.stderr, b"");
    assert_eq!(
        fs::read_to_string(first.data.join("providers/codex/status-hold-pid"))?,
        held_pid,
        "the contending command launched a second provider"
    );
    assert!(!first.data.join("providers/grok").exists());

    let second = TestLayout::new()?;
    write_provider_scenario(&second, "codex", "signed-out")?;
    write_provider_scenario(&second, "grok", "signed-out")?;
    let distinct = configured_carl_command(&second)
        .args(["auth", "status"])
        .output()?;
    assert_eq!(distinct.status.code(), Some(0));
    let distinct_records: Value = serde_json::from_slice(&distinct.stdout)?;
    assert_eq!(distinct_records[0]["state"], "signed_out");
    assert_eq!(distinct_records[1]["state"], "signed_out");

    holder.crash()?;
    write_provider_scenario(&first, "codex", "signed-out")?;
    write_provider_scenario(&first, "grok", "signed-out")?;
    let recovered = configured_carl_command(&first)
        .args(["auth", "status"])
        .output()?;
    assert_eq!(recovered.status.code(), Some(0));
    let recovered_records: Value = serde_json::from_slice(&recovered.stdout)?;
    assert_eq!(recovered_records[0]["state"], "signed_out");
    assert_eq!(recovered_records[1]["state"], "signed_out");
    assert_eq!(lock_file_identity(&lock_path)?, lock_identity);
    assert!(lock_path.exists());
    Ok(())
}

#[cfg(unix)]
fn grok_foreground_output_is_stderr_only() -> TestResult {
    for (device, exact_arguments) in [
        (false, "[\"--no-auto-update\",\"login\"]"),
        (true, "[\"--no-auto-update\",\"login\",\"--device-auth\"]"),
    ] {
        let layout = TestLayout::new()?;
        write_provider_scenario(&layout, "grok", "signed-out")?;

        let mut command = configured_carl_command(&layout);
        command.args(["auth", "login", "grok"]);
        if device {
            command.arg("--device");
        }
        let output = run_in_terminals(command)?;
        assert_eq!(output.status.code(), Some(0));

        let stdout = normalize_terminal_output(output.stdout)?;
        assert_eq!(
            stdout,
            concat!(
                "{\"service\":\"xai_grok\",\"availability\":\"available\",",
                "\"state\":\"signed_in\",\"method\":\"provider_managed\",",
                "\"plan\":null,\"error_code\":null}\n"
            )
        );
        assert!(!stdout.contains(GROK_SECRET_SENTINEL));

        let stderr = normalize_terminal_output(output.stderr)?;
        assert!(
            stderr.contains(GROK_SECRET_SENTINEL),
            "provider stdout did not reach Carl's verified stderr terminal: {stderr:?}"
        );
        assert!(
            !stderr.contains("\"service\":\"xai_grok\""),
            "Carl's final JSON leaked into stderr: {stderr:?}"
        );

        let launches = fs::read_to_string(layout.data.join("providers/grok/grok-launches.jsonl"))?;
        assert!(
            launches.contains(&format!("\"arguments\":{exact_arguments}")),
            "Grok login did not use the exact argv: {launches}"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn openai_login_challenges_are_stderr_only() -> TestResult {
    for (device, scenario, request_type) in [
        (false, "browser-success", "\"type\":\"chatgpt\""),
        (true, "device-success", "\"type\":\"chatgptDeviceCode\""),
    ] {
        let layout = TestLayout::new()?;
        write_provider_scenario(&layout, "codex", scenario)?;
        let mut command = configured_carl_command(&layout);
        command.args(["auth", "login", "openai"]);
        if device {
            command.arg("--device");
        }
        let output = run_in_terminals(command)?;
        assert_eq!(output.status.code(), Some(0));
        let stdout = normalize_terminal_output(output.stdout)?;
        assert_eq!(
            stdout,
            concat!(
                "{\"service\":\"openai_codex\",\"availability\":\"available\",",
                "\"state\":\"signed_in\",\"method\":\"provider_managed\",",
                "\"plan\":\"plus\",\"error_code\":null}\n"
            )
        );
        assert!(!stdout.contains("auth.openai.com"));
        assert!(!stdout.contains("CARL-1360"));
        assert!(!stdout.contains(CODEX_SECRET_SENTINEL));

        let stderr = normalize_terminal_output(output.stderr)?;
        if device {
            assert_eq!(
                stderr,
                concat!(
                    "Open this URL on any device:\n",
                    "https://auth.openai.com/codex/device\n",
                    "Enter code:\n",
                    "CARL-1360\n"
                )
            );
        } else {
            assert!(stderr.starts_with("Open this URL in your browser:\n"));
            assert!(stderr.contains("https://auth.openai.com/oauth/authorize?"));
        }
        assert!(!stderr.contains(CODEX_SECRET_SENTINEL));

        let requests =
            fs::read_to_string(layout.data.join("providers/codex/codex-requests.jsonl"))?;
        assert!(
            requests.contains(request_type),
            "Codex login method mapping was wrong: {requests}"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn signed_in_login_is_idempotent() -> TestResult {
    let layout = TestLayout::new()?;
    write_provider_scenario(&layout, "codex", "account-plan-plus")?;
    let mut command = configured_carl_command(&layout);
    command.args(["auth", "login", "openai"]);
    let output = run_in_terminals(command)?;

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        normalize_terminal_output(output.stdout)?,
        concat!(
            "{\"service\":\"openai_codex\",\"availability\":\"available\",",
            "\"state\":\"signed_in\",\"method\":\"provider_managed\",",
            "\"plan\":\"plus\",\"error_code\":null}\n"
        )
    );
    assert_eq!(normalize_terminal_output(output.stderr)?, "");
    let requests = fs::read_to_string(layout.data.join("providers/codex/codex-requests.jsonl"))?;
    assert!(!requests.contains("account/login/start"));
    Ok(())
}

#[cfg(unix)]
fn provider_logouts_reconcile_signed_out() -> TestResult {
    let openai = TestLayout::new()?;
    write_provider_scenario(&openai, "codex", "account-plan-plus")?;
    let mut command = configured_carl_command(&openai);
    command.args(["auth", "logout", "openai"]);
    let output = run_in_terminals(command)?;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        normalize_terminal_output(output.stdout)?,
        concat!(
            "{\"service\":\"openai_codex\",\"availability\":\"available\",",
            "\"state\":\"signed_out\",\"method\":null,\"plan\":null,\"error_code\":null}\n"
        )
    );
    assert_eq!(
        normalize_terminal_output(output.stderr)?,
        format!("{CODEX_LOGOUT_WARNING}\n")
    );
    let requests = fs::read_to_string(openai.data.join("providers/codex/codex-requests.jsonl"))?;
    assert!(requests.contains("\"method\":\"account/logout\""));

    let grok = TestLayout::new()?;
    write_provider_scenario(&grok, "grok", "signed-out")?;
    write_private_file(grok.data.join("providers/grok/auth.json"), b"fixture")?;
    write_private_file(
        grok.data.join("providers/grok/fixture-login-complete"),
        b"complete",
    )?;
    let mut command = configured_carl_command(&grok);
    command.args(["auth", "logout", "grok"]);
    let output = run_in_terminals(command)?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        normalize_terminal_output(output.stdout)?,
        concat!(
            "{\"service\":\"xai_grok\",\"availability\":\"available\",",
            "\"state\":\"signed_out\",\"method\":null,\"plan\":null,\"error_code\":null}\n"
        )
    );
    assert_eq!(normalize_terminal_output(output.stderr)?, "");
    let launches = fs::read_to_string(grok.data.join("providers/grok/grok-launches.jsonl"))?;
    assert!(launches.contains("\"arguments\":[\"--no-auto-update\",\"logout\"]"));
    Ok(())
}

#[cfg(unix)]
fn early_sigint_cancels_connect_safely() -> TestResult {
    let layout = TestLayout::new()?;
    write_provider_scenario(&layout, "grok", "connect-delay")?;
    let mut command = configured_carl_command(&layout);
    command.args(["auth", "login", "grok"]);
    let child = spawn_in_terminals(command)?;

    wait_for_path(
        &layout.data.join("providers/grok/connect-delay-ready"),
        Duration::from_secs(5),
    )?;
    child.send_interrupt()?;
    let output = child.finish()?;
    assert_eq!(output.status.code(), Some(130));
    assert_eq!(
        normalize_terminal_output(output.stdout)?,
        concat!(
            "{\"service\":\"xai_grok\",\"availability\":\"unavailable\",",
            "\"state\":\"unavailable\",\"method\":null,\"plan\":null,",
            "\"error_code\":\"cancelled\"}\n"
        )
    );
    assert_eq!(normalize_terminal_output(output.stderr)?, "");

    let launches = fs::read_to_string(layout.data.join("providers/grok/grok-launches.jsonl"))?;
    let pids = launches
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|launch| {
            launch["processId"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .ok_or("Grok launch PID was not a u32")
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        processes_have_been_reaped(&pids),
        "early SIGINT returned before provider leaders were reaped: {pids:?}"
    );

    write_provider_scenario(&layout, "codex", "signed-out")?;
    write_provider_scenario(&layout, "grok", "signed-out")?;
    let recovered = configured_carl_command(&layout)
        .args(["auth", "status"])
        .output()?;
    assert_eq!(recovered.status.code(), Some(0));
    let records: Value = serde_json::from_slice(&recovered.stdout)?;
    assert_eq!(records[0]["state"], "signed_out");
    assert_eq!(records[1]["state"], "signed_out");
    Ok(())
}

#[cfg(unix)]
fn inflight_grok_sigint_reaps_process_tree() -> TestResult {
    let layout = TestLayout::new()?;
    write_provider_scenario(&layout, "grok", "login-cancel")?;
    let mut command = configured_carl_command(&layout);
    command.args(["auth", "login", "grok"]);
    let child = spawn_in_terminals(command)?;
    let pid_path = layout.data.join("providers/grok/fixture-pids.json");
    wait_for_path(&pid_path, Duration::from_secs(5))?;
    let pids_value: Value = serde_json::from_slice(&fs::read(&pid_path)?)?;
    let pids = ["leader", "grandchild"]
        .into_iter()
        .map(|field| {
            pids_value[field]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .ok_or_else(|| format!("{field} PID was not a u32"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    child.send_interrupt()?;
    let output = child.finish()?;
    assert_eq!(output.status.code(), Some(130));
    assert_eq!(
        normalize_terminal_output(output.stdout)?,
        concat!(
            "{\"service\":\"xai_grok\",\"availability\":\"unavailable\",",
            "\"state\":\"unavailable\",\"method\":null,\"plan\":null,",
            "\"error_code\":\"cancelled\"}\n"
        )
    );
    assert_eq!(normalize_terminal_output(output.stderr)?, "");

    let deadline = Instant::now() + Duration::from_secs(5);
    while !processes_have_been_reaped(&pids) {
        if Instant::now() >= deadline {
            return Err(format!("cancelled Grok process tree was not reaped: {pids:?}").into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

#[cfg(unix)]
fn grok_failed_reconciliation_is_not_success() -> TestResult {
    let layout = TestLayout::new()?;
    write_provider_scenario(&layout, "grok", "login-decline")?;
    let mut command = configured_carl_command(&layout);
    command.args(["auth", "login", "grok"]);
    let output = run_in_terminals(command)?;

    assert_eq!(output.status.code(), Some(1));
    let stdout = normalize_terminal_output(output.stdout)?;
    assert_eq!(
        stdout,
        concat!(
            "{\"service\":\"xai_grok\",\"availability\":\"unavailable\",",
            "\"state\":\"unavailable\",\"method\":null,\"plan\":null,",
            "\"error_code\":\"provider_rejected\"}\n"
        )
    );
    assert!(!stdout.contains(GROK_SECRET_SENTINEL));
    assert!(
        normalize_terminal_output(output.stderr)?.contains(GROK_SECRET_SENTINEL),
        "direct provider diagnostics did not remain on verified stderr"
    );
    Ok(())
}

fn carl_command(layout: &TestLayout) -> process::Command {
    let mut command = process::Command::new(env!("CARGO_BIN_EXE_carl"));
    command
        .current_dir(&layout.workspace)
        .env_remove("CARL_DATA_DIR")
        .env_remove("CARL_CODEX_EXECUTABLE")
        .env_remove("CARL_GROK_EXECUTABLE");
    command
}

fn configured_carl_command(layout: &TestLayout) -> process::Command {
    #[cfg(unix)]
    fs::set_permissions(&layout.data, fs::Permissions::from_mode(0o700))
        .expect("the CLI test data root can be made owner-private");
    let executable = env::current_exe().expect("the auth CLI fixture executable has a path");
    let mut command = carl_command(layout);
    command
        .env("CARL_DATA_DIR", &layout.data)
        .env("CARL_CODEX_EXECUTABLE", &executable)
        .env("CARL_GROK_EXECUTABLE", &executable)
        .env("OPENAI_API_KEY", CODEX_SECRET_SENTINEL)
        .env("XAI_API_KEY", GROK_SECRET_SENTINEL)
        .env("GROK_API_KEY", GROK_SECRET_SENTINEL)
        .env("TELEGRAM_BOT_TOKEN", CODEX_SECRET_SENTINEL);
    command
}

fn write_provider_scenario(layout: &TestLayout, provider: &str, scenario: &str) -> TestResult {
    let home = layout.data.join("providers").join(provider);
    fs::create_dir_all(&home)?;
    fs::write(home.join("fixture-scenario"), scenario)?;
    assert!(Path::new(&home).is_absolute());
    Ok(())
}

#[cfg(unix)]
fn write_private_file(path: impl AsRef<Path>, contents: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true).mode(0o600);
    use std::io::Write as _;
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.flush()
}

#[cfg(unix)]
struct TerminalOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg(unix)]
fn run_in_terminals(command: process::Command) -> TestResult<TerminalOutput> {
    spawn_in_terminals(command)?.finish()
}

#[cfg(unix)]
struct TerminalChild {
    child: process::Child,
    stdin_master: Option<File>,
    stdout_reader: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
    stderr_reader: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
}

#[cfg(unix)]
impl TerminalChild {
    fn finish(mut self) -> TestResult<TerminalOutput> {
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                let _ = self.child.wait();
                return Err("Carl did not exit within the terminal test deadline".into());
            }
            thread::sleep(Duration::from_millis(10));
        };
        drop(self.stdin_master.take());
        let stdout = self
            .stdout_reader
            .take()
            .ok_or("stdout terminal reader was missing")?
            .join()
            .map_err(|_| "stdout terminal reader panicked")??;
        let stderr = self
            .stderr_reader
            .take()
            .ok_or("stderr terminal reader was missing")?
            .join()
            .map_err(|_| "stderr terminal reader panicked")??;
        Ok(TerminalOutput {
            status,
            stdout,
            stderr,
        })
    }

    fn send_interrupt(&self) -> io::Result<()> {
        let pid = i32::try_from(self.child.id())
            .map_err(|_| io::Error::other("Carl PID did not fit i32"))?;
        // SAFETY: pid is the live child process and SIGINT is a valid signal.
        if unsafe { libc::kill(pid, libc::SIGINT) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(unix)]
impl Drop for TerminalChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        drop(self.stdin_master.take());
    }
}

#[cfg(unix)]
fn spawn_in_terminals(mut command: process::Command) -> TestResult<TerminalChild> {
    let (stdin_master, stdin_slave) = open_pty()?;
    let (stdout_master, stdout_slave) = open_pty()?;
    let (stderr_master, stderr_slave) = open_pty()?;
    command
        .stdin(Stdio::from(stdin_slave))
        .stdout(Stdio::from(stdout_slave))
        .stderr(Stdio::from(stderr_slave));
    // SAFETY: the closure invokes only async-signal-safe libc session/terminal
    // operations between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            let process_group = libc::getpgrp();
            if process_group < 0 || libc::tcsetpgrp(libc::STDIN_FILENO, process_group) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = command.spawn()?;
    drop(command);
    let stdout_reader = thread::spawn(move || read_pty(stdout_master));
    let stderr_reader = thread::spawn(move || read_pty(stderr_master));
    Ok(TerminalChild {
        child,
        stdin_master: Some(stdin_master),
        stdout_reader: Some(stdout_reader),
        stderr_reader: Some(stderr_reader),
    })
}

#[cfg(unix)]
fn open_pty() -> io::Result<(File, File)> {
    let mut master = -1;
    let mut slave = -1;
    // SAFETY: openpty initializes both descriptor outputs; optional name and
    // terminal-setting pointers are intentionally null.
    if unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openpty returned two fresh owned descriptors.
    Ok(unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) })
}

#[cfg(unix)]
fn read_pty(mut terminal: File) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4 * 1024];
    loop {
        match terminal.read(&mut buffer) {
            Ok(0) => return Ok(output),
            Ok(read) => output.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.raw_os_error() == Some(libc::EIO) => return Ok(output),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
fn normalize_terminal_output(output: Vec<u8>) -> TestResult<String> {
    Ok(String::from_utf8(output)?.replace("\r\n", "\n"))
}

#[cfg(unix)]
fn wait_for_path(path: &Path, timeout: Duration) -> TestResult {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for fixture path {}", path.display()).into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

struct HoldingStatus {
    child: Option<process::Child>,
    ready: std::path::PathBuf,
    stop: std::path::PathBuf,
    provider_pid: Option<u32>,
}

impl HoldingStatus {
    fn spawn(layout: &TestLayout) -> TestResult<Self> {
        let home = layout.data.join("providers/codex");
        let mut command = configured_carl_command(layout);
        let child = command
            .args(["auth", "status"])
            .stdin(process::Stdio::null())
            .stdout(process::Stdio::null())
            .stderr(process::Stdio::null())
            .spawn()?;
        Ok(Self {
            child: Some(child),
            ready: home.join("status-hold-pid"),
            stop: home.join("status-hold-stop"),
            provider_pid: None,
        })
    }

    fn wait_until_provider_started(&mut self) -> TestResult {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Ok(pid) = fs::read_to_string(&self.ready)
                && let Ok(pid) = pid.trim().parse::<u32>()
            {
                self.provider_pid = Some(pid);
                return Ok(());
            }
            if let Some(status) = self
                .child
                .as_mut()
                .and_then(|child| child.try_wait().ok())
                .flatten()
            {
                return Err(
                    format!("holding auth status exited before readiness: {status}").into(),
                );
            }
            if std::time::Instant::now() >= deadline {
                return Err("holding auth status did not start its provider".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn crash(&mut self) -> TestResult {
        if let Some(mut child) = self.child.take() {
            child.kill()?;
            let _ = child.wait()?;
        }
        fs::write(&self.stop, b"stop")?;
        if let Some(pid) = self.provider_pid {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !processes_have_exited(&[pid]) {
                if std::time::Instant::now() >= deadline {
                    return Err(format!("orphaned status fixture remained alive: {pid}").into());
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        Ok(())
    }
}

impl Drop for HoldingStatus {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::write(&self.stop, b"stop");
    }
}

#[cfg(unix)]
fn lock_file_identity(path: &Path) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn lock_file_identity(path: &Path) -> io::Result<(u32, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let file = File::open(path)?;
    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: file owns a live handle and information points to writable storage.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), information.as_mut_ptr()) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetFileInformationByHandle succeeded and initialized information.
    let information = unsafe { information.assume_init() };
    Ok((
        information.dwVolumeSerialNumber,
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    ))
}
