use carl::cli::{AcpEffort, AcpPermissionMode, Cli, Command, TrustCommand};
use clap::Parser;
use predicates::prelude::PredicateBooleanExt;

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
