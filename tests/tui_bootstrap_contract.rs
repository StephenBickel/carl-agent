use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use carl::service::client::ServiceClientErrorCode;
use carl::sidecar::DataRootLock;
use carl::tui::bootstrap::{
    resolve_or_create_data_root, service_launch_environment, should_launch_service,
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "carl-tui-bootstrap-{}-{serial}",
            std::process::id()
        ));
        let home = root.join("owner");
        fs::create_dir_all(&home).expect("fixture home is created");
        Self { root, home }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn missing_override_creates_an_owner_private_default_data_root() {
    let fixture = Fixture::new();
    let environment = BTreeMap::from([(
        OsString::from(if cfg!(windows) { "USERPROFILE" } else { "HOME" }),
        fixture.home.as_os_str().to_owned(),
    )]);

    let data_root = resolve_or_create_data_root(&environment).expect("default root is prepared");
    assert_eq!(
        data_root,
        fs::canonicalize(&fixture.home)
            .expect("home canonicalizes")
            .join(".carl")
    );
    let lock = DataRootLock::acquire(&data_root).expect("default root is owner-private");
    assert!(lock.guards_data_root(&data_root));
}

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
