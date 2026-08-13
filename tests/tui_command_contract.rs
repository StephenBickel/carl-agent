use carl::acp::PermissionMode;
use carl::delegates::ReasoningEffort;
use carl::tui::command::{SlashCommand, SubmittedInput, parse_submission};

#[test]
fn prompts_and_every_slice_one_slash_command_parse_exactly() {
    assert_eq!(
        parse_submission("fix it").unwrap(),
        SubmittedInput::Prompt("fix it".to_owned())
    );
    assert_eq!(
        parse_submission("first line\nsecond line").unwrap(),
        SubmittedInput::Prompt("first line\nsecond line".to_owned())
    );
    for (input, expected) in [
        ("/model", SlashCommand::Model(None)),
        (
            "/model gpt-5.6-codex",
            SlashCommand::Model(Some("gpt-5.6-codex".to_owned())),
        ),
        ("/provider", SlashCommand::Provider(None)),
        (
            "/provider openai-subscription",
            SlashCommand::Provider(Some("openai-subscription".to_owned())),
        ),
        (
            "/effort xhigh",
            SlashCommand::Effort(ReasoningEffort::XHigh),
        ),
        (
            "/permissions full-access",
            SlashCommand::Permissions(PermissionMode::FullAccess),
        ),
        ("/compact", SlashCommand::Compact),
        ("/new", SlashCommand::New),
        ("/sessions", SlashCommand::Sessions),
        ("/resume 2", SlashCommand::Resume("2".to_owned())),
        ("/status", SlashCommand::Status),
        ("/cancel", SlashCommand::Cancel),
        ("/login", SlashCommand::Login),
        ("/logout", SlashCommand::Logout),
        ("/help", SlashCommand::Help),
        ("/exit", SlashCommand::Exit),
    ] {
        assert_eq!(
            parse_submission(input).unwrap(),
            SubmittedInput::Command(expected),
            "{input}"
        );
    }
}

#[test]
fn slash_commands_are_closed_bounded_and_never_shell_parsed() {
    for invalid in [
        "",
        "   ",
        "/unknown",
        "/resume",
        "/compact now",
        "/model\nunsafe",
        "/effort impossible",
        "/permissions bypass-permissions",
        "/sessions; rm -rf /",
        "/model $(secret-command)",
        "\0",
    ] {
        assert!(parse_submission(invalid).is_err(), "accepted {invalid:?}");
    }
    assert_eq!(
        parse_submission(" /compact").unwrap(),
        SubmittedInput::Prompt(" /compact".to_owned()),
        "leading whitespace must not create a privileged command"
    );
    assert!(parse_submission(&"a".repeat(16 * 1024 + 1)).is_err());
}

#[test]
fn every_documented_effort_and_permission_value_is_explicit() {
    for effort in ["low", "medium", "high", "xhigh", "max", "ultra"] {
        assert!(parse_submission(&format!("/effort {effort}")).is_ok());
    }
    for permission in ["plan", "default", "accept-edits", "dont-ask", "full-access"] {
        assert!(parse_submission(&format!("/permissions {permission}")).is_ok());
    }
}
