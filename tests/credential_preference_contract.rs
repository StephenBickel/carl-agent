use std::error::Error;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use carl::credentials::{CredentialVault, load_provider_preference, store_provider_preference};
use carl::providers::catalog::ProviderKind;
use carl::tui::parse_first_run_provider;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
static SERIAL: AtomicU64 = AtomicU64::new(0);

#[test]
fn provider_preferences_are_private_strict_and_never_contain_credentials() -> TestResult {
    let path = std::env::temp_dir().join(format!(
        "carl-provider-preference-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path)?;
    assert_eq!(load_provider_preference(&path)?, None);
    store_provider_preference(&path, ProviderKind::OpenRouter)?;
    assert_eq!(
        load_provider_preference(&path)?,
        Some(ProviderKind::OpenRouter)
    );
    let bytes = fs::read(path.join("provider.json"))?;
    assert_eq!(bytes, br#"{"provider":"openrouter"}"#);
    assert!(!String::from_utf8_lossy(&bytes).contains("key"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(fs::metadata(path.join("provider.json"))?.mode() & 0o077, 0);
    }
    fs::write(
        path.join("provider.json"),
        br#"{"provider":"openrouter","api_key":"forbidden"}"#,
    )?;
    assert!(load_provider_preference(&path).is_err());
    fs::remove_dir_all(path)?;
    Ok(())
}

#[test]
fn vault_diagnostics_are_opaque() {
    assert_eq!(
        format!("{:?}", CredentialVault),
        "CredentialVault(<os-managed>)"
    );
}

#[test]
fn first_run_provider_choice_is_closed_and_defaults_to_subscription() {
    for (input, expected) in [
        ("", ProviderKind::OpenAiSubscription),
        ("1", ProviderKind::OpenAiSubscription),
        ("subscription", ProviderKind::OpenAiSubscription),
        ("2", ProviderKind::OpenAiApi),
        ("openai", ProviderKind::OpenAiApi),
        ("3", ProviderKind::OpenRouter),
        ("openrouter", ProviderKind::OpenRouter),
    ] {
        assert_eq!(parse_first_run_provider(input), Some(expected));
    }
    assert_eq!(parse_first_run_provider("4"), None);
    assert_eq!(parse_first_run_provider("open ai"), None);
}
