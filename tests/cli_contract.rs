use carl::cli::{
    AcpEffort, AcpPermissionMode, BaselineCommand, Cli, Command, MaintenanceCommand, TrustCommand,
};
use carl::runtime::task::TaskBudget;
use clap::{CommandFactory, Parser};
use predicates::prelude::PredicateBooleanExt;

#[tokio::test(flavor = "current_thread")]
async fn serve_dispatch_is_implemented() {
    let result =
        carl::cli::run_command_with_cancellation(Command::Serve, std::future::ready(())).await;
    assert!(!result.stderr().contains("not implemented"));
}

#[test]
fn help_exposes_the_v1_commands() {
    let mut command = assert_cmd::Command::cargo_bin("carl").unwrap();
    command.arg("--help").assert().success().stdout(
        predicates::str::contains("serve")
            .and(predicates::str::contains("auth"))
            .and(predicates::str::contains("memory"))
            .and(predicates::str::contains("pair"))
            .and(predicates::str::contains("doctor"))
            .and(predicates::str::contains("sessions")),
    );
}

#[test]
fn maintenance_status_and_prepare_parse_as_closed_owner_commands() {
    for (literal, expected) in [
        ("status", MaintenanceCommand::Status),
        ("prepare", MaintenanceCommand::Prepare),
    ] {
        let parsed = Cli::try_parse_from(["carl", "maintenance", literal]).unwrap();
        assert!(matches!(
            parsed.command,
            Command::Maintenance { command } if command == expected
        ));
    }
    assert!(Cli::try_parse_from(["carl", "maintenance", "shutdown"]).is_err());
}

#[test]
fn direct_codex_baseline_parses_exact_required_values_default_and_bounds() {
    let parsed = Cli::try_parse_from([
        "carl",
        "baseline",
        "codex",
        "--workspace",
        "/tmp/canonical-fixture",
        "--model",
        "gpt-5.6-terra",
        "--effort",
        "low",
    ])
    .expect("the direct Codex baseline command parses");
    let Command::Baseline {
        command: BaselineCommand::Codex(args),
    } = parsed.command
    else {
        panic!("expected direct Codex baseline command");
    };
    assert_eq!(
        args.workspace,
        std::path::Path::new("/tmp/canonical-fixture")
    );
    assert_eq!(args.model, "gpt-5.6-terra");
    assert_eq!(args.effort, AcpEffort::Low);
    assert_eq!(args.timeout_seconds, 7_200);

    for valid in [60, 28_800] {
        assert!(
            Cli::try_parse_from([
                "carl",
                "baseline",
                "codex",
                "--workspace",
                "/tmp/canonical-fixture",
                "--model",
                "gpt-5.6-terra",
                "--effort",
                "low",
                "--timeout-seconds",
                &valid.to_string(),
            ])
            .is_ok()
        );
    }
    for invalid in [59, 28_801] {
        assert!(
            Cli::try_parse_from([
                "carl",
                "baseline",
                "codex",
                "--workspace",
                "/tmp/canonical-fixture",
                "--model",
                "gpt-5.6-terra",
                "--effort",
                "low",
                "--timeout-seconds",
                &invalid.to_string(),
            ])
            .is_err()
        );
    }
    for missing in ["--workspace", "--model", "--effort"] {
        let mut arguments = vec![
            "carl",
            "baseline",
            "codex",
            "--workspace",
            "/tmp/canonical-fixture",
            "--model",
            "gpt-5.6-terra",
            "--effort",
            "low",
        ];
        let index = arguments
            .iter()
            .position(|argument| *argument == missing)
            .expect("required flag is in fixture");
        arguments.drain(index..=index + 1);
        assert!(
            Cli::try_parse_from(arguments).is_err(),
            "accepted missing {missing}"
        );
    }
}

#[test]
fn acp_startup_options_parse_exactly() {
    let parsed = Cli::try_parse_from([
        "carl",
        "acp",
        "--model",
        "gpt-5.6-codex",
        "--effort",
        "high",
        "--permission-mode",
        "default",
    ])
    .unwrap();
    let Command::Acp(args) = parsed.command else {
        panic!("expected ACP command");
    };
    assert_eq!(args.model.as_deref(), Some("gpt-5.6-codex"));
    assert_eq!(args.effort, Some(AcpEffort::High));
    assert_eq!(args.permission_mode, Some(AcpPermissionMode::Default));
    assert!(!args.dangerously_bypass_permissions);

    let parsed = Cli::try_parse_from(["carl", "acp", "--dangerously-bypass-permissions"]).unwrap();
    assert!(matches!(
        parsed.command,
        Command::Acp(args) if args.dangerously_bypass_permissions
    ));

    let parsed = Cli::try_parse_from(["carl", "acp", "--permission-mode", "fullAccess"])
        .expect("canonical full access parses");
    let Command::Acp(args) = parsed.command else {
        panic!("expected ACP command");
    };
    assert_eq!(args.permission_mode, Some(AcpPermissionMode::FullAccess));
    assert_eq!(
        carl::acp::PermissionMode::from(AcpPermissionMode::FullAccess),
        carl::acp::PermissionMode::FullAccess
    );
    assert_eq!(
        carl::acp::PermissionMode::from(AcpPermissionMode::FullAccess).profile(),
        carl::acp::PermissionProfile::FullAccess
    );
    assert!(
        Cli::try_parse_from(["carl", "acp", "--permission-mode", "bypassPermissions"]).is_err(),
        "the legacy wire value must not remain an advertised CLI choice"
    );
}

#[test]
fn acp_task_budget_flags_parse_exact_values_and_defaults() {
    let parsed = Cli::try_parse_from([
        "carl",
        "acp",
        "--max-wall-time-seconds",
        "86400",
        "--max-provider-requests",
        "10000",
        "--max-tool-calls",
        "100000",
        "--soft-epoch-seconds",
        "3600",
        "--soft-epoch-tool-calls",
        "1000",
    ])
    .unwrap();
    let Command::Acp(args) = parsed.command else {
        panic!("expected ACP command");
    };
    assert_eq!(
        args.task_budget(),
        TaskBudget {
            max_wall_time_seconds: Some(86_400),
            max_provider_requests: Some(10_000),
            max_tool_calls: Some(100_000),
            soft_epoch_seconds: 3_600,
            soft_epoch_tool_calls: 1_000,
        }
    );

    let parsed = Cli::try_parse_from(["carl", "acp"]).unwrap();
    let Command::Acp(args) = parsed.command else {
        panic!("expected ACP command");
    };
    assert_eq!(args.task_budget(), TaskBudget::default());
}

#[test]
fn acp_task_budget_flags_reject_values_outside_consumer_bounds() {
    for (flag, maximum) in [
        ("--max-wall-time-seconds", 86_400_u64),
        ("--max-provider-requests", 10_000),
        ("--max-tool-calls", 100_000),
        ("--soft-epoch-seconds", 3_600),
        ("--soft-epoch-tool-calls", 1_000),
    ] {
        for invalid in [0, maximum + 1] {
            assert!(
                Cli::try_parse_from(["carl", "acp", flag, &invalid.to_string()]).is_err(),
                "{flag} accepted {invalid}"
            );
        }
    }
}

#[test]
fn acp_help_exposes_all_budget_flags_and_soft_defaults() {
    let help = Cli::command()
        .find_subcommand_mut("acp")
        .expect("ACP subcommand exists")
        .render_long_help()
        .to_string();

    for flag in [
        "--max-wall-time-seconds",
        "--max-provider-requests",
        "--max-tool-calls",
        "--soft-epoch-seconds",
        "--soft-epoch-tool-calls",
    ] {
        assert!(help.contains(flag), "ACP help omitted {flag}: {help}");
    }
    assert!(
        help.contains("[default: 900]"),
        "soft seconds default missing"
    );
    assert!(help.contains("[default: 40]"), "soft tool default missing");
}

#[test]
fn acp_rejects_ambiguous_bypass_and_secret_flags() {
    assert!(
        Cli::try_parse_from([
            "carl",
            "acp",
            "--dangerously-bypass-permissions",
            "--permission-mode",
            "default",
        ])
        .is_err()
    );
    for flag in ["--buzz-private-key", "--buzz-relay-url", "--openai-api-key"] {
        assert!(Cli::try_parse_from(["carl", "acp", flag, "secret"]).is_err());
    }
}

#[test]
fn local_buzz_trust_command_requires_an_actor_and_absolute_workspace() {
    let parsed = Cli::try_parse_from([
        "carl",
        "trust",
        "buzz",
        "--actor",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--workspace",
        "/tmp/carl-workspace",
    ])
    .expect("trusted owner command parses");
    assert!(matches!(
        parsed.command,
        Command::Trust {
            command: TrustCommand::Buzz { actor, workspace }
        } if actor == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            && workspace == std::path::Path::new("/tmp/carl-workspace")
    ));
}
