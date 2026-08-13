use std::collections::BTreeMap;
use std::ffi::OsString;

use carl::service::client::ServiceClientErrorCode;
use carl::tui::bootstrap::{service_launch_environment, should_launch_service};

#[test]
fn service_launch_environment_is_closed_and_omits_every_provider_secret() {
    let ambient = BTreeMap::from([
        (OsString::from("PATH"), OsString::from("/usr/bin")),
        (OsString::from("HOME"), OsString::from("/home/owner")),
        (
            OsString::from("CARL_CODEX_EXECUTABLE"),
            OsString::from("/trusted/codex"),
        ),
        (
            OsString::from("OPENAI_API_KEY"),
            OsString::from("secret-openai"),
        ),
        (
            OsString::from("CODEX_API_KEY"),
            OsString::from("secret-codex"),
        ),
        (
            OsString::from("AZURE_OPENAI_API_KEY"),
            OsString::from("secret-azure"),
        ),
        (
            OsString::from("OPENROUTER_API_KEY"),
            OsString::from("secret-router"),
        ),
        (
            OsString::from("UNRELATED_SECRET"),
            OsString::from("secret-other"),
        ),
    ]);
    let environment = service_launch_environment(&ambient, "/private/carl-data".as_ref());
    assert_eq!(
        environment.get(&OsString::from("CARL_DATA_DIR")),
        Some(&OsString::from("/private/carl-data"))
    );
    assert_eq!(
        environment.get(&OsString::from("PATH")),
        Some(&OsString::from("/usr/bin"))
    );
    assert_eq!(
        environment.get(&OsString::from("CARL_CODEX_EXECUTABLE")),
        Some(&OsString::from("/trusted/codex"))
    );
    for denied in [
        "OPENAI_API_KEY",
        "CODEX_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "UNRELATED_SECRET",
    ] {
        assert!(
            !environment.contains_key(&OsString::from(denied)),
            "forwarded {denied}"
        );
    }
}

#[test]
fn only_an_unavailable_service_may_trigger_launch() {
    assert!(should_launch_service(ServiceClientErrorCode::Unavailable));
    for code in [
        ServiceClientErrorCode::InvalidEndpoint,
        ServiceClientErrorCode::Rejected,
        ServiceClientErrorCode::InvalidResponse,
    ] {
        assert!(!should_launch_service(code), "unsafe launch for {code:?}");
    }
}
