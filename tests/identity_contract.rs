use carl::{cli::Cli, error::CarlError, events::SessionId};
use clap::CommandFactory;
use predicates::prelude::PredicateBooleanExt;

#[test]
fn cargo_and_rust_library_expose_the_carl_identity() {
    assert_eq!(env!("CARGO_PKG_NAME"), "carl-agent");

    let session_id = SessionId::new();
    assert!(!session_id.to_string().is_empty());
    assert_eq!(Cli::command().get_name(), "carl");
}

#[test]
fn carl_binary_exposes_the_reserved_command_tree() {
    let mut command = assert_cmd::Command::cargo_bin("carl").unwrap();
    command.arg("--help").assert().success().stdout(
        predicates::str::contains("Usage: carl [COMMAND]")
            .or(predicates::str::contains("Usage: carl.exe [COMMAND]"))
            .and(predicates::str::contains("tui"))
            .and(predicates::str::contains("serve"))
            .and(predicates::str::contains("auth"))
            .and(predicates::str::contains("pair"))
            .and(predicates::str::contains("doctor"))
            .and(predicates::str::contains("sessions")),
    );
}

#[test]
fn public_error_type_and_product_messages_use_carl() {
    let configuration = CarlError::Configuration {
        detail: "secret path".into(),
    };
    let storage = CarlError::Storage {
        detail: "secret database detail".into(),
    };

    assert_eq!(
        configuration.user_message(),
        "Carl's configuration is invalid."
    );
    assert_eq!(
        storage.user_message(),
        "Carl could not access its local data."
    );
    assert!(!configuration.to_string().contains("secret path"));
    assert!(!storage.to_string().contains("secret database detail"));
}
