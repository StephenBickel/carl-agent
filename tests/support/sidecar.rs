use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use carl::sidecar::{
    ExecutableTrustDecision, JsonlSidecar, ProviderEnvironmentProfile, SidecarCommand,
    SidecarError, SidecarLimits, VersionOutputFormat,
};
use semver::VersionReq;

pub const FIXTURE_ARGUMENT: &str = "--carl-private-sidecar-fixture";
pub const FIXTURE_HOME_VARIABLE: &str = "CODEX_HOME";
pub const SECRET_SENTINEL: &str = "sk-sidecar-contract-secret";
pub const CODEX_SECRET_SENTINEL: &str =
    "Bearer codex-access-token-sentinel refresh-token-sentinel stephen@example.test";
pub const GROK_SECRET_SENTINEL: &str =
    "Bearer grok-access-token-sentinel refresh-token-sentinel stephen@example.test";
pub const CODEX_LOGIN_ID: &str = "94d0b241-47d6-4bec-b77a-29d023cf4f2f";
pub const CODEX_STALE_LOGIN_ID: &str = "40dfe52d-9789-4aec-88bd-4f7510b2c06e";
pub const CODEX_AUTH_MANAGER_RELOADED: &str = "auth-manager-reloaded";
pub const CODEX_DELAYED_CONFIRMATION_READY_ON_READ: u64 = 10;
pub const CODEX_LOGIN_START_RECEIVED: &str = "login-start-received";
pub const CODEX_NOTIFICATION_FLOOD_READY: &str = "notification-flood-ready";
#[cfg(unix)]
pub const PATH_SENTINEL: &str = "/carl-untrusted-path-sentinel";
#[cfg(windows)]
pub const PATH_SENTINEL: &str = r"C:\carl-untrusted-path-sentinel";

static NEXT_TEMPORARY_DIRECTORY: AtomicU64 = AtomicU64::new(0);
static RECEIVED_REQUESTS: AtomicU64 = AtomicU64::new(0);

pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub struct TestLayout {
    root: PathBuf,
    pub data: PathBuf,
    pub workspace: PathBuf,
    pub home: PathBuf,
}

impl TestLayout {
    pub fn new() -> TestResult<Self> {
        let serial = NEXT_TEMPORARY_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        #[cfg(windows)]
        let root =
            env::temp_dir().join(format!("carl-sidecar-contract-{}-{serial}", process::id()));
        #[cfg(not(windows))]
        // Executable trust validates every ancestor; Linux's system temp
        // directory is intentionally world-writable.
        let root = env::current_exe()?
            .parent()
            .ok_or("the contract-test executable has no parent")?
            .join(format!("carl-sidecar-contract-{}-{serial}", process::id()));
        let data = root.join("data");
        let workspace = root.join("workspace");
        let home = data.join("providers").join("fixture");
        fs::create_dir_all(&root)?;
        #[cfg(windows)]
        create_owner_private_test_directory(&data)?;
        #[cfg(not(windows))]
        fs::create_dir_all(&data)?;
        fs::create_dir_all(&workspace)?;
        Ok(Self {
            root,
            data,
            workspace,
            home,
        })
    }
}

#[cfg(windows)]
fn create_owner_private_test_directory(path: &Path) -> io::Result<()> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
        GetLengthSid, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor, IsValidSid,
        OBJECT_INHERIT_ACE, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
        SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{CreateDirectoryW, FILE_ALL_ACCESS};
    use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: OpenProcessToken returned this owned handle and it is closed once.
                let _ = unsafe { CloseHandle(self.0) };
            }
        }
    }

    fn invalid_security_descriptor() -> io::Error {
        io::Error::other("failed to build the Windows test security descriptor")
    }

    let mut token = ptr::null_mut();
    // SAFETY: token points to writable handle storage.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0
        || token.is_null()
    {
        return Err(io::Error::last_os_error());
    }
    let token = OwnedHandle(token);
    let mut required = 0_u32;
    // SAFETY: the first call intentionally queries the required byte count.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required) };
    if required
        < u32::try_from(std::mem::size_of::<TOKEN_USER>())
            .map_err(|_| invalid_security_descriptor())?
    {
        return Err(io::Error::last_os_error());
    }
    let word = std::mem::size_of::<usize>();
    let words = usize::try_from(required)
        .map_err(|_| invalid_security_descriptor())?
        .checked_add(word - 1)
        .ok_or_else(invalid_security_descriptor)?
        / word;
    let mut user_storage = vec![0_usize; words];
    // SAFETY: user_storage is aligned and large enough for the requested TOKEN_USER bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            user_storage.as_mut_ptr().cast::<c_void>(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful query initialized TOKEN_USER at the buffer start.
    let current_user: PSID = unsafe { (*(user_storage.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    // SAFETY: current_user points into the live user_storage buffer.
    if unsafe { IsValidSid(current_user) } == 0 {
        return Err(invalid_security_descriptor());
    }

    // SAFETY: current_user is a valid SID backed by user_storage.
    let sid_bytes = usize::try_from(unsafe { GetLengthSid(current_user) })
        .map_err(|_| invalid_security_descriptor())?;
    let acl_bytes = std::mem::size_of::<ACL>()
        .checked_add(std::mem::size_of::<ACCESS_ALLOWED_ACE>())
        .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<u32>()))
        .and_then(|bytes| bytes.checked_add(sid_bytes))
        .ok_or_else(invalid_security_descriptor)?;
    let acl_words = acl_bytes
        .checked_add(word - 1)
        .ok_or_else(invalid_security_descriptor)?
        / word;
    let mut acl_storage = vec![0_usize; acl_words];
    let acl = acl_storage.as_mut_ptr().cast::<ACL>();
    let acl_length = u32::try_from(acl_bytes).map_err(|_| invalid_security_descriptor())?;
    // SAFETY: acl_storage is aligned writable storage of acl_length bytes.
    if unsafe { InitializeAcl(acl, acl_length, ACL_REVISION) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the initialized ACL has space for this ACE and current_user remains live.
    if unsafe {
        AddAccessAllowedAceEx(
            acl,
            ACL_REVISION,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            FILE_ALL_ACCESS,
            current_user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let descriptor_pointer = (&raw mut descriptor).cast::<c_void>();
    // SAFETY: descriptor is writable SECURITY_DESCRIPTOR storage.
    if unsafe { InitializeSecurityDescriptor(descriptor_pointer, SECURITY_DESCRIPTOR_REVISION) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor is initialized and current_user remains live through creation.
    if unsafe { SetSecurityDescriptorOwner(descriptor_pointer, current_user, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor and ACL are both initialized and remain live through creation.
    if unsafe { SetSecurityDescriptorDacl(descriptor_pointer, 1, acl, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: protecting the DACL prevents broad ACEs from the temp parent being merged.
    if unsafe {
        SetSecurityDescriptorControl(descriptor_pointer, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| invalid_security_descriptor())?,
        lpSecurityDescriptor: descriptor_pointer,
        bInheritHandle: 0,
    };
    let mut path: Vec<u16> = path.as_os_str().encode_wide().collect();
    path.push(0);
    // SAFETY: path is NUL-terminated and attributes references live descriptor storage.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl Drop for TestLayout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn fixture_command(layout: &TestLayout, scenario: &str, version: &str) -> SidecarCommand {
    SidecarCommand {
        executable: env::current_exe().expect("the custom-harness test executable has a path"),
        arguments: vec![
            OsString::from(FIXTURE_ARGUMENT),
            OsString::from(scenario),
            OsString::from(version),
        ],
        version_arguments: vec![
            OsString::from(FIXTURE_ARGUMENT),
            OsString::from("version-codex"),
            OsString::from(version),
            OsString::from("--version"),
        ],
        version_output: VersionOutputFormat::ExactPrefix("carl-sidecar-fixture"),
        isolated_home: layout.home.clone(),
        supported_versions: VersionReq::parse(">=1.2.0, <2.0.0")
            .expect("the fixture version requirement is valid"),
    }
}

pub async fn spawn_fixture(
    command: SidecarCommand,
    layout: &TestLayout,
    limits: SidecarLimits,
) -> Result<JsonlSidecar, SidecarError> {
    let trusted = command
        .resolve_executable()?
        .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
    JsonlSidecar::spawn_trusted(
        command,
        &trusted,
        ProviderEnvironmentProfile::Codex,
        &layout.data,
        &layout.workspace,
        limits,
    )
    .await
}

pub fn short_limits() -> SidecarLimits {
    SidecarLimits {
        max_stdout_line_bytes: 8 * 1_024,
        max_stderr_bytes: 128,
        graceful_shutdown_timeout: Duration::from_millis(150),
        forced_shutdown_timeout: Duration::from_secs(2),
        process_poll_interval: Duration::from_millis(10),
    }
}

pub fn dispatch_fixture(arguments: &[OsString]) -> Option<i32> {
    if arguments.first().map(OsString::as_os_str) != Some(OsStr::new(FIXTURE_ARGUMENT)) {
        return None;
    }

    let scenario = arguments.get(1)?.to_string_lossy().into_owned();
    let version = arguments.get(2)?.to_string_lossy().into_owned();

    Some(match scenario.as_str() {
        "version-codex"
            if arguments.get(3).map(OsString::as_os_str) == Some(OsStr::new("--version"))
                && arguments.len() == 4 =>
        {
            if record_version_executable().is_err() {
                return Some(78);
            }
            println!("carl-sidecar-fixture {version}");
            0
        }
        "version-grok"
            if arguments.get(3).map(OsString::as_os_str)
                == Some(OsStr::new("--no-auto-update"))
                && arguments.get(4).map(OsString::as_os_str) == Some(OsStr::new("version"))
                && arguments.len() == 5 =>
        {
            if record_version_executable().is_err() {
                return Some(78);
            }
            println!("Grok Build CLI release {version} (stable)");
            0
        }
        "version-nonzero" if arguments.len() == 3 => {
            println!("carl-sidecar-fixture {version}");
            19
        }
        "version-multiple" if arguments.len() == 3 => {
            println!("first 1.2.3 second 1.4.5");
            0
        }
        "version-oversized" if arguments.len() == 3 => {
            println!("{}", "v".repeat(16 * 1_024));
            0
        }
        "version-hanging" if arguments.len() == 3 => hanging_version(),
        #[cfg(unix)]
        "version-swap-executable"
            if arguments.get(3).map(OsString::as_os_str) == Some(OsStr::new("--version"))
                && arguments.len() == 4 =>
        {
            if record_version_executable().is_err() || swap_version_executable().is_err() {
                return Some(78);
            }
            println!("carl-sidecar-fixture {version}");
            0
        }
        #[cfg(unix)]
        "replacement-execution-marker" => replacement_execution_marker(),
        "strict-jsonl" => strict_jsonl(false, false),
        "server-request-round-trip" => server_request_round_trip(),
        "duplicate-server-request" => duplicate_server_request(),
        "response-with-method" => confused_response(true),
        "response-without-result-or-error" => confused_response(false),
        "server-request-flood" => server_request_flood(),
        "stderr" => strict_jsonl(true, false),
        "malformed" => malformed_response(false),
        "oversized" => malformed_response(true),
        "unknown-id" => unknown_id_response(),
        "blocked-stdin" => blocked_stdin(),
        "final-response-exit" => final_response_exit(),
        "exit-with-pending" => exit_with_pending(),
        "grandchild" => grandchild_leader(false),
        "grandchild-exit" => grandchild_leader(true),
        "grandchild-process" => grandchild_process(),
        _ => 64,
    })
}

pub fn dispatch_codex_auth_fixture(arguments: &[OsString]) -> Option<i32> {
    // The fallback makes a wrong-profile child observable to the adapter's
    // no-launch regression instead of letting the fixture exit before recording it.
    let home = env::var_os(FIXTURE_HOME_VARIABLE)
        .or_else(|| env::var_os("GROK_HOME"))
        .map(PathBuf::from)?;
    let scenario = fs::read_to_string(home.join("fixture-scenario")).ok()?;
    let scenario = scenario.trim();

    if arguments == [OsString::from("--version")] {
        match scenario {
            "status-hold" => return Some(hold_status_version(&home)),
            "unsupported-version" => println!("codex-cli 0.145.0"),
            "version-build-metadata" => println!("codex-cli 0.146.0+modified"),
            "version-wrong-prefix" => println!("codex 0.146.0"),
            "version-extra-token" => println!("codex-cli 0.146.0 stable"),
            "version-malformed" => println!("codex-cli release"),
            _ => println!("codex-cli 0.146.0"),
        }
        return Some(0);
    }

    let expected = [
        OsString::from("app-server"),
        OsString::from("--strict-config"),
        OsString::from("-c"),
        OsString::from("cli_auth_credentials_store=\"file\""),
        OsString::from("--listen"),
        OsString::from("stdio://"),
    ];
    if arguments != expected {
        return None;
    }

    Some(codex_auth_jsonl_fixture(&home, scenario))
}

fn hold_status_version(home: &Path) -> i32 {
    if fs::write(
        home.join("status-hold-pid"),
        process::id().to_string().as_bytes(),
    )
    .is_err()
    {
        return 73;
    }
    while !home.join("status-hold-stop").exists() {
        thread::sleep(Duration::from_millis(10));
    }
    0
}

pub fn dispatch_grok_auth_fixture(arguments: &[OsString]) -> Option<i32> {
    if arguments.first().map(OsString::as_os_str) != Some(OsStr::new("--no-auto-update")) {
        return None;
    }
    // See the matching Codex fallback: this is a negative-control fixture path,
    // never an accepted production environment contract.
    let home = env::var_os("GROK_HOME")
        .or_else(|| env::var_os(FIXTURE_HOME_VARIABLE))
        .map(PathBuf::from)?;
    let scenario = fs::read_to_string(home.join("fixture-scenario")).ok()?;
    let scenario = scenario.trim();
    let arguments_as_strings: Vec<_> = arguments
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();

    if record_grok_launch(&home, &arguments_as_strings).is_err() {
        return Some(73);
    }

    let version_arguments = ["--no-auto-update", "version"];
    if arguments_as_strings == version_arguments {
        match scenario {
            "connect-delay" => {
                if fs::write(home.join("connect-delay-ready"), b"ready").is_err() {
                    return Some(73);
                }
                thread::sleep(Duration::from_millis(350));
                println!("Grok Build CLI release 0.2.111 (stable)");
            }
            "unsupported-version" => println!("Grok Build CLI release 0.2.110 (stable)"),
            "prerelease-version" => println!("Grok Build CLI release 0.2.111-alpha.1"),
            "version-build-metadata" => {
                println!("Grok Build CLI release 0.2.111+modified")
            }
            "version-multiple" => println!("Grok Build 0.2.111 runtime 1.0.0"),
            "version-malformed" => println!("Grok Build development release"),
            "version-oversized" => println!("{}", "x".repeat(16 * 1_024)),
            _ => println!("Grok Build CLI release 0.2.111 (stable)"),
        }
        return Some(0);
    }

    let agent_arguments = ["--no-auto-update", "agent", "stdio"];
    if arguments_as_strings == agent_arguments {
        return Some(grok_auth_jsonl_fixture(&home, scenario));
    }

    let browser_login = ["--no-auto-update", "login"];
    let device_login = ["--no-auto-update", "login", "--device-auth"];
    if arguments_as_strings == browser_login || arguments_as_strings == device_login {
        return Some(grok_login_fixture(&home, scenario));
    }

    let logout_arguments = ["--no-auto-update", "logout"];
    if arguments_as_strings == logout_arguments {
        let _ = fs::remove_file(home.join("auth.json"));
        let _ = fs::remove_file(home.join("fixture-login-complete"));
        return Some(if scenario == "logout-decline" { 19 } else { 0 });
    }

    Some(64)
}

fn grok_auth_jsonl_fixture(home: &Path, scenario: &str) -> i32 {
    for input in io::stdin().lock().lines() {
        let input = match input {
            Ok(input) => input,
            Err(_) => return 74,
        };
        if record_grok_request(home, &input).is_err() {
            return 73;
        }
        let request: serde_json::Value = match serde_json::from_str(&input) {
            Ok(request) => request,
            Err(_) => return 65,
        };
        let Some(id) = request.get("id").cloned() else {
            return 65;
        };
        let method = request.get("method").and_then(serde_json::Value::as_str);
        match method {
            Some("initialize") => {
                if scenario == "unsupported-request" {
                    if write_grok_message(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 991,
                        "method": "fs/read_text_file",
                        "params": {"path": GROK_SECRET_SENTINEL},
                    }))
                    .is_err()
                    {
                        return 74;
                    }
                    continue;
                }

                let protocol_version = match scenario {
                    "protocol-version-string" => serde_json::Value::String("1".to_owned()),
                    "wrong-protocol-version" => serde_json::Value::from(2),
                    _ => serde_json::Value::from(1),
                };
                let agent_version = match scenario {
                    "wrong-agent-version" => "0.2.110",
                    "agent-version-build" => "0.2.111+modified",
                    _ => "0.2.111",
                };
                let auth_methods = match scenario {
                    "missing-auth-method" => serde_json::json!([]),
                    "other-auth-method" => serde_json::json!([{
                        "id": "browser_oauth",
                        "name": "Browser OAuth",
                        "description": "Interactive provider login"
                    }]),
                    "xai-api-key-lookalike" => serde_json::json!([{
                        "id": "xai.api_key.v2",
                        "name": "Future provider method",
                        "description": "Unknown but well formed"
                    }]),
                    "cached-with-other" => serde_json::json!([
                        {
                            "id": "browser_oauth",
                            "name": "Browser OAuth",
                            "description": "Interactive provider login"
                        },
                        {
                            "id": "cached_token",
                            "name": "Cached token",
                            "description": "Provider managed"
                        }
                    ]),
                    "xai-api-key" => serde_json::json!([
                        {
                            "id": "cached_token",
                            "name": "Cached token",
                            "description": "Provider managed"
                        },
                        {
                            "id": "xai.api_key",
                            "name": "API key",
                            "description": GROK_SECRET_SENTINEL
                        }
                    ]),
                    "xai-api-key-alone" => serde_json::json!([{
                        "id": "xai.api_key",
                        "name": "API key",
                        "description": GROK_SECRET_SENTINEL
                    }]),
                    "duplicate-auth-method" => serde_json::json!([
                        {
                            "id": "cached_token",
                            "name": "Cached token",
                            "description": "Provider managed"
                        },
                        {
                            "id": "cached_token",
                            "name": "Duplicate",
                            "description": GROK_SECRET_SENTINEL
                        }
                    ]),
                    "duplicate-other-auth-method" => serde_json::json!([
                        {
                            "id": "browser_oauth",
                            "name": "Browser OAuth",
                            "description": "Interactive provider login"
                        },
                        {
                            "id": "browser_oauth",
                            "name": "Duplicate",
                            "description": GROK_SECRET_SENTINEL
                        }
                    ]),
                    "too-many-auth-methods" => serde_json::Value::Array(
                        (0..33)
                            .map(|index| {
                                serde_json::json!({
                                    "id": format!("future_method_{index}"),
                                    "name": "Future method",
                                    "description": "Unknown but well formed"
                                })
                            })
                            .collect(),
                    ),
                    "malformed-auth-method" => serde_json::json!([{"id": 7}]),
                    _ => serde_json::json!([{
                        "id": "cached_token",
                        "name": "Cached token",
                        "description": "Provider managed"
                    }]),
                };
                let mut result = serde_json::json!({
                    "protocolVersion": protocol_version,
                    "agentCapabilities": {},
                    "agentInfo": {
                        "name": "grok-build",
                        "title": "Grok Build",
                        "version": agent_version
                    },
                    "authMethods": auth_methods,
                });
                match scenario {
                    "agent-capabilities-non-object" => {
                        result["agentCapabilities"] = serde_json::json!([]);
                    }
                    "agent-capabilities-oversized" => {
                        result["agentCapabilities"] =
                            serde_json::json!({"padding": "x".repeat(5 * 1_024)});
                    }
                    "agent-capabilities-deep" => {
                        result["agentCapabilities"] =
                            serde_json::json!({"a": {"b": {"c": {"d": {"e": true}}}}});
                    }
                    _ => {}
                }
                if scenario == "missing-agent-info" {
                    result
                        .as_object_mut()
                        .expect("fixture initialize result is an object")
                        .remove("agentInfo");
                } else if scenario == "missing-agent-version" {
                    result["agentInfo"]
                        .as_object_mut()
                        .expect("fixture agent info is an object")
                        .remove("version");
                } else if scenario == "malformed-agent-info" {
                    result["agentInfo"] = serde_json::json!({"version": 211});
                }
                let response = if scenario == "initialize-mixed-result-error" {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": result,
                        "error": {"code": -32600, "message": GROK_SECRET_SENTINEL},
                    })
                } else if scenario == "initialize-auth-required" {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32000, "message": GROK_SECRET_SENTINEL},
                    })
                } else if scenario == "initialize-wrong-id" {
                    serde_json::json!({"jsonrpc": "2.0", "id": 91, "result": result})
                } else if scenario == "initialize-wrong-jsonrpc" {
                    serde_json::json!({"jsonrpc": "1.0", "id": id, "result": result})
                } else if scenario == "response-method-confusion" {
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "fs/read_text_file",
                        "params": {"path": GROK_SECRET_SENTINEL},
                    })
                } else {
                    serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result})
                };
                if write_grok_message(&response).is_err() {
                    return 74;
                }
            }
            Some("authenticate") => {
                let logged_in = fs::symlink_metadata(home.join("fixture-login-complete")).is_ok();
                if scenario == "postflight-unsafe" {
                    let target = home.join("auth-target");
                    if write_private_fixture_file(target.clone(), GROK_SECRET_SENTINEL.as_bytes())
                        .is_err()
                        || fs::hard_link(target, home.join("auth.json")).is_err()
                    {
                        return 73;
                    }
                }
                let response = match scenario {
                    "authenticate-wrong-id" => {
                        serde_json::json!({"jsonrpc": "2.0", "id": 92, "result": {}})
                    }
                    "authenticate-mixed-result-error" => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {},
                        "error": {"code": -32000, "message": GROK_SECRET_SENTINEL},
                    }),
                    "authenticate-extra-field" => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {"credential": GROK_SECRET_SENTINEL},
                    }),
                    "authenticate-malformed-meta" => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {"_meta": GROK_SECRET_SENTINEL},
                    }),
                    "authenticate-meta" => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {"_meta": {"provider": "grok"}},
                    }),
                    "authenticate-meta-oversized" => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {"_meta": {"padding": "x".repeat(5 * 1_024)}},
                    }),
                    "authenticate-meta-deep" => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {"_meta": {"a": {"b": {"c": {"d": {"e": true}}}}}},
                    }),
                    "provider-rejected" => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32042, "message": GROK_SECRET_SENTINEL},
                    }),
                    "protocol-error" => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32602, "message": GROK_SECRET_SENTINEL},
                    }),
                    "cached-with-other" => {
                        serde_json::json!({"jsonrpc": "2.0", "id": id, "result": {}})
                    }
                    "signed-in-missing-auth-file" => {
                        serde_json::json!({"jsonrpc": "2.0", "id": id, "result": {}})
                    }
                    "signed-in" if !logged_in => {
                        serde_json::json!({"jsonrpc": "2.0", "id": id, "result": {}})
                    }
                    _ if logged_in => {
                        serde_json::json!({"jsonrpc": "2.0", "id": id, "result": {}})
                    }
                    _ => serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": -32000, "message": GROK_SECRET_SENTINEL},
                    }),
                };
                if write_grok_message(&response).is_err() {
                    return 74;
                }
            }
            _ => {
                if write_grok_message(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": -32601, "message": GROK_SECRET_SENTINEL},
                }))
                .is_err()
                {
                    return 74;
                }
            }
        }
    }
    0
}

fn grok_login_fixture(home: &Path, scenario: &str) -> i32 {
    if matches!(scenario, "login-timeout" | "login-cancel") {
        return grandchild_leader(false);
    }
    if scenario == "login-decline" {
        eprintln!("{GROK_SECRET_SENTINEL}");
        return 19;
    }
    if write_private_fixture_file(home.join("auth.json"), GROK_SECRET_SENTINEL.as_bytes()).is_err()
        || write_private_fixture_file(home.join("fixture-login-complete"), b"complete").is_err()
    {
        return 73;
    }
    println!("{GROK_SECRET_SENTINEL}");
    0
}

fn write_grok_message(value: &serde_json::Value) -> io::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, value)?;
    writeln!(stdout)?;
    stdout.flush()
}

fn record_grok_launch(home: &Path, arguments: &[String]) -> io::Result<()> {
    let environment: BTreeMap<_, _> = env::vars_os()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .collect();
    let requirements_match = fs::read(home.join("requirements.toml")).is_ok_and(|contents| {
        contents
            == b"[cli]\nauto_update = false\n\n[grok_com_config]\ndisable_api_key_auth = true\n"
    });
    let record = serde_json::json!({
        "arguments": arguments,
        "cwd": env::current_dir()?,
        "environment": environment,
        "processId": process::id(),
        "requirementsMatch": requirements_match,
    });
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(home.join("grok-launches.jsonl"))?;
    serde_json::to_writer(&mut file, &record)?;
    writeln!(file)?;
    file.flush()
}

fn record_grok_request(home: &Path, input: &str) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(home.join("grok-requests.jsonl"))?;
    writeln!(file, "{input}")?;
    file.flush()
}

fn write_private_fixture_file(path: PathBuf, contents: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.flush()
}

fn codex_auth_jsonl_fixture(home: &Path, scenario: &str) -> i32 {
    if record_codex_launch(home).is_err() {
        return 73;
    }

    let mut account_reads = 0_u64;
    let mut login_started = false;
    let mut cancel_raced = false;
    let mut logged_out = false;
    for input in io::stdin().lock().lines() {
        let input = match input {
            Ok(input) => input,
            Err(_) => return 74,
        };
        let request: serde_json::Value = match serde_json::from_str(&input) {
            Ok(request) => request,
            Err(_) => return 65,
        };
        if record_codex_request(home, &input).is_err() {
            return 73;
        }

        let Some(object) = request.as_object() else {
            return 65;
        };
        let Some(method) = object.get("method").and_then(serde_json::Value::as_str) else {
            return 65;
        };
        if method == "initialized" {
            if object.len() != 1 {
                return 65;
            }
            if scenario == "startup-no-remote" {
                continue;
            }
            if scenario == "startup-config-warning"
                && write_codex_message(&serde_json::json!({
                    "method": "configWarning",
                    "params": {
                        "summary": CODEX_SECRET_SENTINEL,
                        "details": null,
                    },
                }))
                .is_err()
            {
                return 74;
            }
            let startup_event = match scenario {
                "startup-account-updated" => Some(serde_json::json!({
                    "method": "account/updated",
                    "params": {},
                })),
                "startup-login-completed" => Some(serde_json::json!({
                    "method": "account/login/completed",
                    "params": {
                        "loginId": CODEX_LOGIN_ID,
                        "success": true,
                        "error": null,
                    },
                })),
                "startup-unknown-notification" => Some(serde_json::json!({
                    "method": "thread/started",
                    "params": {},
                })),
                "startup-malformed-config-warning" => Some(serde_json::json!({
                    "method": "configWarning",
                    "params": {
                        "details": CODEX_SECRET_SENTINEL,
                    },
                })),
                _ => None,
            };
            if startup_event
                .as_ref()
                .is_some_and(|event| write_codex_message(event).is_err())
            {
                return 74;
            }
            let remote_status = if scenario == "malformed-remote-control-status" {
                serde_json::json!({
                    "method": "remoteControl/status/changed",
                    "params": {
                        "installationId": "fixture-installation",
                        "serverName": "fixture",
                        "status": "online",
                        "unexpected": CODEX_SECRET_SENTINEL,
                    },
                })
            } else {
                serde_json::json!({
                    "method": "remoteControl/status/changed",
                    "params": {
                        "installationId": "fixture-installation",
                        "serverName": "fixture",
                        "status": "disabled",
                        "environmentId": null,
                    },
                    "emittedAtMs": 1,
                })
            };
            if write_codex_message(&remote_status).is_err() {
                return 74;
            }
            continue;
        }
        let Some(id) = object.get("id").cloned() else {
            return 65;
        };

        match method {
            "initialize" => {
                let codex_home = if scenario == "wrong-codex-home" {
                    home.join("different-home")
                } else {
                    home.to_path_buf()
                };
                let mut result = serde_json::json!({
                    "userAgent": "codex_cli_rs/0.146.0",
                    "codexHome": codex_home,
                    "platformFamily": "unix",
                    "platformOs": "fixture",
                });
                if scenario == "initialize-unknown-field" {
                    result
                        .as_object_mut()
                        .expect("initialize fixture result is an object")
                        .insert("unexpected".into(), serde_json::json!(true));
                }
                if write_codex_message(&serde_json::json!({"id": id, "result": result})).is_err() {
                    return 74;
                }
            }
            "account/read" => {
                if object.len() != 3
                    || object.get("params") != Some(&serde_json::json!({"refreshToken": false}))
                {
                    return 65;
                }
                account_reads = account_reads.saturating_add(1);
                let account = codex_fixture_account(
                    scenario,
                    account_reads,
                    login_started,
                    fixture_marker_is_ready(home, CODEX_AUTH_MANAGER_RELOADED),
                    cancel_raced,
                    logged_out,
                );
                let requires_openai_auth = scenario != "requires-openai-auth-false";
                let mut result = serde_json::json!({
                    "account": account,
                    "requiresOpenaiAuth": requires_openai_auth,
                });
                if scenario == "account-read-unknown-field" {
                    result
                        .as_object_mut()
                        .expect("account fixture result is an object")
                        .insert(
                            "unexpected".into(),
                            serde_json::json!(CODEX_SECRET_SENTINEL),
                        );
                }
                if scenario == "cancel-canceled-late-success"
                    && account_reads == 3
                    && write_login_completion(CODEX_LOGIN_ID, true).is_err()
                {
                    return 74;
                }
                let response = serde_json::json!({"id": id, "result": result});
                let write_result = if scenario == "confirmation-delayed-within-deadline"
                    && login_started
                    && account_reads < CODEX_DELAYED_CONFIRMATION_READY_ON_READ
                {
                    write_codex_message_then_account_updated(&response)
                } else {
                    write_codex_message(&response)
                };
                if write_result.is_err() {
                    return 74;
                }
            }
            "account/login/start" => {
                if object.len() != 3 {
                    return 65;
                }
                login_started = true;
                if write_fixture_marker(home, CODEX_LOGIN_START_RECEIVED).is_err() {
                    return 73;
                }
                if matches!(scenario, "provider-error" | "provider-protocol-error") {
                    let code = if scenario == "provider-protocol-error" {
                        -32602
                    } else {
                        -32000
                    };
                    if write_codex_message(&serde_json::json!({
                        "id": id,
                        "error": {
                            "code": code,
                            "message": CODEX_SECRET_SENTINEL,
                            "data": {"credential": CODEX_SECRET_SENTINEL},
                        }
                    }))
                    .is_err()
                    {
                        return 74;
                    }
                    continue;
                }
                if scenario == "start-response-timeout" {
                    continue;
                }

                let login_type = object
                    .get("params")
                    .and_then(serde_json::Value::as_object)
                    .and_then(|params| params.get("type"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                if object.get("params") != Some(&serde_json::json!({"type": login_type})) {
                    return 65;
                }
                let response_id = match scenario {
                    "wrong-response-id" => serde_json::json!(999),
                    "mixed-response-id" => serde_json::json!(id.to_string()),
                    _ => id,
                };
                let mut result = match login_type {
                    "chatgpt" => serde_json::json!({
                        "type": "chatgpt",
                        "loginId": CODEX_LOGIN_ID,
                        "authUrl": browser_authorization_url(scenario),
                    }),
                    "chatgptDeviceCode" => serde_json::json!({
                        "type": "chatgptDeviceCode",
                        "loginId": CODEX_LOGIN_ID,
                        "verificationUrl": device_verification_url(scenario),
                        "userCode": "CARL-1360",
                    }),
                    _ => return 65,
                };
                if scenario == "start-missing-login-id" {
                    result
                        .as_object_mut()
                        .expect("login fixture result is an object")
                        .remove("loginId");
                }
                let response = match scenario {
                    "response-method-bearing" => serde_json::json!({
                        "id": response_id,
                        "method": "account/login/start",
                        "result": result,
                    }),
                    "response-result-and-error" => serde_json::json!({
                        "id": response_id,
                        "result": result,
                        "error": {
                            "code": -32000,
                            "message": CODEX_SECRET_SENTINEL,
                            "data": CODEX_SECRET_SENTINEL,
                        },
                    }),
                    "response-neither-result-nor-error" => {
                        serde_json::json!({"id": response_id})
                    }
                    _ => serde_json::json!({"id": response_id, "result": result}),
                };
                if write_codex_message(&response).is_err() {
                    return 74;
                }

                match scenario {
                    "browser-success"
                    | "browser-port-1457"
                    | "device-success"
                    | "stale-account-then-updated"
                    | "startup-config-warning" => {
                        if write_login_completion(CODEX_LOGIN_ID, true).is_err() {
                            return 74;
                        }
                        if scenario == "stale-account-then-updated"
                            && write_account_updated().is_err()
                        {
                            return 74;
                        }
                    }
                    "advisory-before-completion" => {
                        if write_account_updated().is_err()
                            || write_login_completion(CODEX_LOGIN_ID, true).is_err()
                        {
                            return 74;
                        }
                    }
                    "success-without-error" => {
                        if write_codex_message(&serde_json::json!({
                            "method": "account/login/completed",
                            "params": {
                                "loginId": CODEX_LOGIN_ID,
                                "success": true,
                            }
                        }))
                        .is_err()
                        {
                            return 74;
                        }
                    }
                    "success-with-error" => {
                        if write_codex_message(&serde_json::json!({
                            "method": "account/login/completed",
                            "params": {
                                "loginId": CODEX_LOGIN_ID,
                                "success": true,
                                "error": CODEX_SECRET_SENTINEL,
                            }
                        }))
                        .is_err()
                        {
                            return 74;
                        }
                    }
                    "failure-without-error" => {
                        if write_codex_message(&serde_json::json!({
                            "method": "account/login/completed",
                            "params": {
                                "loginId": CODEX_LOGIN_ID,
                                "success": false,
                            }
                        }))
                        .is_err()
                        {
                            return 74;
                        }
                    }
                    "failure-with-null-error" => {
                        if write_codex_message(&serde_json::json!({
                            "method": "account/login/completed",
                            "params": {
                                "loginId": CODEX_LOGIN_ID,
                                "success": false,
                                "error": null,
                            }
                        }))
                        .is_err()
                        {
                            return 74;
                        }
                    }
                    "empty-advisory-before-completion" => {
                        if write_codex_message(&serde_json::json!({
                            "method": "account/updated",
                            "params": {},
                        }))
                        .is_err()
                            || write_login_completion(CODEX_LOGIN_ID, true).is_err()
                        {
                            return 74;
                        }
                    }
                    "config-warning-before-completion" => {
                        if write_codex_message(&serde_json::json!({
                            "method": "configWarning",
                            "params": {
                                "summary": CODEX_SECRET_SENTINEL,
                                "details": CODEX_SECRET_SENTINEL,
                                "path": CODEX_SECRET_SENTINEL,
                                "range": {
                                    "start": {"line": 1, "column": 2},
                                    "end": {"line": 3, "column": 4},
                                },
                            }
                        }))
                        .is_err()
                            || write_login_completion(CODEX_LOGIN_ID, true).is_err()
                        {
                            return 74;
                        }
                    }
                    "remote-status-before-completion" => {
                        if write_codex_message(&serde_json::json!({
                            "method": "remoteControl/status/changed",
                            "params": {
                                "installationId": "fixture-installation",
                                "serverName": "fixture",
                                "status": "connected",
                                "environmentId": "fixture-environment",
                            },
                            "emittedAtMs": 2,
                        }))
                        .is_err()
                            || write_login_completion(CODEX_LOGIN_ID, true).is_err()
                        {
                            return 74;
                        }
                    }
                    "duplicate-completion" => {
                        if write_login_completion(CODEX_LOGIN_ID, true).is_err()
                            || write_login_completion(CODEX_LOGIN_ID, true).is_err()
                        {
                            return 74;
                        }
                    }
                    "conflicting-duplicate-completion" => {
                        if write_login_completion(CODEX_LOGIN_ID, true).is_err()
                            || write_login_completion(CODEX_LOGIN_ID, false).is_err()
                        {
                            return 74;
                        }
                    }
                    "stale-completion" => {
                        if write_login_completion(CODEX_STALE_LOGIN_ID, true).is_err() {
                            return 74;
                        }
                    }
                    "login-rejected" => {
                        if write_codex_message(&serde_json::json!({
                            "method": "account/login/completed",
                            "params": {
                                "loginId": CODEX_LOGIN_ID,
                                "success": false,
                                "error": CODEX_SECRET_SENTINEL,
                            }
                        }))
                        .is_err()
                        {
                            return 74;
                        }
                    }
                    "malformed-notification" => {
                        if write_codex_message(&serde_json::json!({
                            "method": "account/login/completed",
                            "params": {
                                "loginId": CODEX_LOGIN_ID,
                                "success": true,
                                "error": null,
                                "unexpected": CODEX_SECRET_SENTINEL,
                            }
                        }))
                        .is_err()
                        {
                            return 74;
                        }
                    }
                    "completion-null-login-id" => {
                        if write_codex_message(&serde_json::json!({
                            "method": "account/login/completed",
                            "params": {
                                "loginId": null,
                                "success": true,
                                "error": null,
                            }
                        }))
                        .is_err()
                        {
                            return 74;
                        }
                    }
                    "completion-missing-login-id" => {
                        if write_codex_message(&serde_json::json!({
                            "method": "account/login/completed",
                            "params": {
                                "success": true,
                                "error": null,
                            }
                        }))
                        .is_err()
                        {
                            return 74;
                        }
                    }
                    "completion-missing-success" => {
                        if write_codex_message(&serde_json::json!({
                            "method": "account/login/completed",
                            "params": {
                                "loginId": CODEX_LOGIN_ID,
                                "error": null,
                            }
                        }))
                        .is_err()
                        {
                            return 74;
                        }
                    }
                    "completion-wrong-success-type" => {
                        if write_codex_message(&serde_json::json!({
                            "method": "account/login/completed",
                            "params": {
                                "loginId": CODEX_LOGIN_ID,
                                "success": "true",
                                "error": null,
                            }
                        }))
                        .is_err()
                        {
                            return 74;
                        }
                    }
                    "advisory-only" => {
                        if write_account_updated().is_err() {
                            return 74;
                        }
                    }
                    "confirmation-timeout" => {
                        if write_login_completion(CODEX_LOGIN_ID, true).is_err() {
                            return 74;
                        }
                    }
                    "confirmation-timeout-then-reload" => {
                        if write_login_completion(CODEX_LOGIN_ID, true).is_err() {
                            return 74;
                        }
                    }
                    "confirmation-delayed-within-deadline" => {
                        if write_login_completion(CODEX_LOGIN_ID, true).is_err() {
                            return 74;
                        }
                    }
                    "advisory-flood" => {
                        for _ in 0..40 {
                            if write_account_updated().is_err() {
                                return 74;
                            }
                        }
                        if write_fixture_marker(home, CODEX_NOTIFICATION_FLOOD_READY).is_err() {
                            return 73;
                        }
                    }
                    "paced-advisory-flood" => {
                        let home = home.to_path_buf();
                        thread::spawn(move || {
                            for notification in 0..80 {
                                if write_account_updated().is_err() {
                                    return;
                                }
                                if notification == 32
                                    && write_fixture_marker(&home, CODEX_NOTIFICATION_FLOOD_READY)
                                        .is_err()
                                {
                                    return;
                                }
                                thread::sleep(Duration::from_millis(2));
                            }
                        });
                    }
                    "completion-advisory-flood" => {
                        if write_login_completion(CODEX_LOGIN_ID, true).is_err() {
                            return 74;
                        }
                        for _ in 0..40 {
                            if write_account_updated().is_err() {
                                return 74;
                            }
                        }
                        if write_fixture_marker(home, CODEX_NOTIFICATION_FLOOD_READY).is_err() {
                            return 73;
                        }
                    }
                    "child-exit" => return 0,
                    _ => {}
                }
            }
            "account/login/cancel" => {
                if object.len() != 3
                    || object.get("params") != Some(&serde_json::json!({"loginId": CODEX_LOGIN_ID}))
                {
                    return 65;
                }
                let status = match scenario {
                    "cancel-not-found-success" | "logout-pending-race" => {
                        cancel_raced = true;
                        if write_login_completion(CODEX_LOGIN_ID, true).is_err()
                            || write_account_updated().is_err()
                        {
                            return 74;
                        }
                        "notFound"
                    }
                    "cancel-invalid-status" | "logout-double-failure" => "alreadyDone",
                    "cancel-canceled-late-success" => "canceled",
                    _ => {
                        if write_login_completion(CODEX_LOGIN_ID, false).is_err() {
                            return 74;
                        }
                        "canceled"
                    }
                };
                if write_codex_message(&serde_json::json!({"id": id, "result": {"status": status}}))
                    .is_err()
                {
                    return 74;
                }
            }
            "account/logout" => {
                if object.len() != 2 {
                    return 65;
                }
                if scenario == "logout-double-failure" {
                    if write_codex_message(&serde_json::json!({
                        "id": id,
                        "error": {
                            "code": -32000,
                            "message": CODEX_SECRET_SENTINEL,
                        },
                    }))
                    .is_err()
                    {
                        return 74;
                    }
                    thread::spawn(|| {
                        thread::sleep(Duration::from_millis(20));
                        let _ = write_login_completion(CODEX_LOGIN_ID, true);
                    });
                    continue;
                }
                logged_out = true;
                if scenario == "logout-pending-race"
                    && write_login_completion(CODEX_LOGIN_ID, true).is_err()
                {
                    return 74;
                }
                if write_codex_message(&serde_json::json!({"id": id, "result": {}})).is_err() {
                    return 74;
                }
                if scenario == "cancel-invalid-status" {
                    thread::spawn(|| {
                        thread::sleep(Duration::from_millis(20));
                        let _ = write_login_completion(CODEX_LOGIN_ID, true);
                    });
                }
            }
            _ => return 65,
        }
    }
    0
}

fn codex_fixture_account(
    scenario: &str,
    account_reads: u64,
    login_started: bool,
    auth_manager_reloaded: bool,
    cancel_raced: bool,
    logged_out: bool,
) -> serde_json::Value {
    if logged_out {
        return serde_json::Value::Null;
    }
    if let Some(plan) = scenario.strip_prefix("account-plan-") {
        return serde_json::json!({
            "type": "chatgpt",
            "email": CODEX_SECRET_SENTINEL,
            "planType": plan,
        });
    }
    match scenario {
        "account-api-key" => serde_json::json!({"type": "apiKey"}),
        "account-amazon-bedrock" => serde_json::json!({"type": "amazonBedrock"}),
        "account-unknown-type" => serde_json::json!({"type": "personalAccessToken"}),
        "stale-account-then-updated" if account_reads < 3 => serde_json::Value::Null,
        "confirmation-timeout" => serde_json::Value::Null,
        "confirmation-timeout-then-reload" if !auth_manager_reloaded => serde_json::Value::Null,
        "confirmation-delayed-within-deadline"
            if account_reads < CODEX_DELAYED_CONFIRMATION_READY_ON_READ =>
        {
            serde_json::Value::Null
        }
        "cancel-not-found-success" if !cancel_raced => serde_json::Value::Null,
        "logout-pending-race" if !cancel_raced => serde_json::Value::Null,
        "cancel-canceled" | "cancel-canceled-late-success" => serde_json::Value::Null,
        "cancel-canceled-preexisting" => serde_json::json!({
            "type": "chatgpt",
            "email": CODEX_SECRET_SENTINEL,
            "planType": "plus",
        }),
        _ if login_started => serde_json::json!({
            "type": "chatgpt",
            "email": CODEX_SECRET_SENTINEL,
            "planType": "plus",
        }),
        _ => serde_json::Value::Null,
    }
}

fn browser_authorization_url(scenario: &str) -> String {
    let mut base = "https://auth.openai.com/oauth/authorize";
    let mut query = vec![
        ("response_type", "code".to_owned()),
        ("client_id", "app_EMoamEEZ73f0CkXaXp7hrann".to_owned()),
        (
            "redirect_uri",
            "http://localhost:1455/auth/callback".to_owned(),
        ),
        (
            "scope",
            "openid profile email offline_access api.connectors.read api.connectors.invoke"
                .to_owned(),
        ),
        ("code_challenge", "A".repeat(43)),
        ("code_challenge_method", "S256".to_owned()),
        ("id_token_add_organizations", "true".to_owned()),
        ("codex_cli_simplified_flow", "true".to_owned()),
        ("state", "B".repeat(43)),
        ("originator", "carl".to_owned()),
    ];
    match scenario {
        "browser-wrong-host" => base = "https://evil.example/oauth/authorize",
        "browser-wrong-path" => base = "https://auth.openai.com/oauth/token",
        "browser-duplicate-query" => query.push(("client_id", "duplicate".to_owned())),
        "browser-invalid-callback" => {
            query[2].1 = "https://evil.example/auth/callback".to_owned();
        }
        "browser-invalid-callback-port" => {
            query[2].1 = "http://localhost:1456/auth/callback".to_owned();
        }
        "browser-port-1457" => {
            query[2].1 = "http://localhost:1457/auth/callback".to_owned();
        }
        "browser-wrong-response-type" => query[0].1 = "token".to_owned(),
        "browser-wrong-client-id" => query[1].1 = "carl".to_owned(),
        "browser-wrong-scope" => query[3].1 = "openid profile email offline_access".to_owned(),
        "browser-invalid-code-challenge" => query[4].1 = "not_base64url".to_owned(),
        "browser-wrong-code-challenge-method" => query[5].1 = "plain".to_owned(),
        "browser-organizations-disabled" => query[6].1 = "false".to_owned(),
        "browser-simplified-flow-disabled" => query[7].1 = "false".to_owned(),
        "browser-invalid-state" => query[8].1 = "not_base64url".to_owned(),
        "browser-wrong-originator" => query[9].1 = "codex_cli_rs".to_owned(),
        "browser-extra-nonce" => query.push(("nonce", CODEX_SECRET_SENTINEL.to_owned())),
        "browser-extra-prompt" => query.push(("prompt", "login".to_owned())),
        "browser-extra-audience" => query.push(("audience", "codex".to_owned())),
        "browser-extra-resource" => query.push(("resource", "codex".to_owned())),
        "browser-extra-workspace" => {
            query.push(("allowed_workspace_id", CODEX_SECRET_SENTINEL.to_owned()));
        }
        "browser-wrong-order" => query.swap(0, 1),
        _ => {}
    }

    let encoded = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(query)
        .finish();
    format!("{base}?{encoded}")
}

fn device_verification_url(scenario: &str) -> &'static str {
    match scenario {
        "device-wrong-path" => "https://auth.openai.com/device",
        "device-query" => "https://auth.openai.com/codex/device?code=secret",
        _ => "https://auth.openai.com/codex/device",
    }
}

fn write_login_completion(login_id: &str, success: bool) -> io::Result<()> {
    write_codex_message(&serde_json::json!({
        "method": "account/login/completed",
        "params": {
            "loginId": login_id,
            "success": success,
            "error": if success {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(CODEX_SECRET_SENTINEL.to_owned())
            },
        }
    }))
}

fn write_account_updated() -> io::Result<()> {
    write_codex_message(&account_updated_message())
}

fn account_updated_message() -> serde_json::Value {
    serde_json::json!({
        "method": "account/updated",
        "params": {"authMode": "chatgpt", "planType": "plus"},
    })
}

fn write_codex_message_then_account_updated(value: &serde_json::Value) -> io::Result<()> {
    let account_updated = account_updated_message();
    write_codex_messages(&[value, &account_updated])
}

fn write_codex_message(value: &serde_json::Value) -> io::Result<()> {
    write_codex_messages(&[value])
}

fn write_codex_messages(values: &[&serde_json::Value]) -> io::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    for value in values {
        serde_json::to_writer(&mut stdout, value)?;
        writeln!(stdout)?;
    }
    stdout.flush()
}

pub fn write_fixture_marker(home: &Path, name: &str) -> io::Result<()> {
    write_private_fixture_file(home.join(name), b"ready")
}

fn fixture_marker_is_ready(home: &Path, name: &str) -> bool {
    fs::read(home.join(name)).is_ok_and(|contents| contents == b"ready")
}

fn record_codex_launch(home: &Path) -> io::Result<()> {
    let cwd = env::current_dir()?;
    let environment: BTreeMap<_, _> = env::vars_os()
        .map(|(key, value)| {
            (
                key.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .collect();
    let record = serde_json::json!({
        "cwd": cwd,
        "environment": environment,
        "processId": process::id(),
    });
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(home.join("codex-launch.json"))?;
    serde_json::to_writer(&mut file, &record)?;
    file.flush()
}

fn record_codex_request(home: &Path, input: &str) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(home.join("codex-requests.jsonl"))?;
    writeln!(file, "{input}")?;
    file.flush()
}

fn strict_jsonl(write_stderr: bool, ignore_term: bool) -> i32 {
    #[cfg(unix)]
    if ignore_term {
        // SAFETY: the fixture is a single-threaded process at this point, and SIG_IGN is
        // async-signal-safe state installed solely to exercise the forced-kill path.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        }
    }
    #[cfg(not(unix))]
    let _ = ignore_term;

    let stdout = Arc::new(Mutex::new(io::stdout()));
    for input in io::stdin().lock().lines() {
        let input = match input {
            Ok(input) => input,
            Err(_) => return 74,
        };
        let request: serde_json::Value = match serde_json::from_str(&input) {
            Ok(request) => request,
            Err(_) => return 65,
        };
        let method = request
            .get("method")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("echo")
            .to_owned();
        let Some(id) = request.get("id").cloned() else {
            if method == "client/ready" {
                let home = match fixture_home() {
                    Ok(home) => home,
                    Err(_) => return 73,
                };
                if fs::write(home.join("outbound-notification.json"), input).is_err() {
                    return 73;
                }
                continue;
            }
            return 65;
        };

        if write_stderr {
            let mut stderr = io::stderr().lock();
            for _ in 0..256 {
                let _ = writeln!(stderr, "{SECRET_SENTINEL}");
            }
            let _ = stderr.flush();
        }

        let result = match method.as_str() {
            "environment" => {
                let environment: BTreeMap<_, _> = env::vars_os()
                    .map(|(key, value)| {
                        (
                            key.to_string_lossy().into_owned(),
                            value.to_string_lossy().into_owned(),
                        )
                    })
                    .collect();
                serde_json::to_value(environment).expect("fixture environment serializes")
            }
            "identity" => serde_json::Value::String(
                fs::canonicalize(env::current_exe().expect("fixture executable path is available"))
                    .expect("fixture executable canonicalizes")
                    .to_string_lossy()
                    .into_owned(),
            ),
            _ => request
                .get("value")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        };
        let delay = request
            .get("delay_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        if matches!(
            method.as_str(),
            "delay-after-received" | "delay-after-received-and-confirm-response"
        ) {
            let mut stdout = stdout.lock().expect("fixture stdout lock is not poisoned");
            serde_json::to_writer(
                &mut *stdout,
                &serde_json::json!({"method": "fixture/received"}),
            )
            .expect("fixture received notification serializes");
            writeln!(stdout).expect("fixture received notification newline writes");
            stdout
                .flush()
                .expect("fixture received notification flushes");
        }
        if method == "delay-recorded" && record_received_request().is_err() {
            return 73;
        }
        let stdout = Arc::clone(&stdout);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(delay));
            let mut stdout = stdout.lock().expect("fixture stdout lock is not poisoned");
            if method == "emit-notification" {
                serde_json::to_writer(
                    &mut *stdout,
                    &serde_json::json!({"method": "auth/progress", "params": {"step": 1}}),
                )
                .expect("fixture notification serializes");
                writeln!(stdout).expect("fixture notification newline writes");
            }
            serde_json::to_writer(
                &mut *stdout,
                &serde_json::json!({"id": id.clone(), "result": result}),
            )
            .expect("fixture response serializes");
            writeln!(stdout).expect("fixture response newline writes");
            if method == "delay-after-received-and-confirm-response" {
                serde_json::to_writer(
                    &mut *stdout,
                    &serde_json::json!({
                        "method": "fixture/responded",
                        "params": {"id": id},
                    }),
                )
                .expect("fixture response confirmation serializes");
                writeln!(stdout).expect("fixture response confirmation newline writes");
            }
            stdout.flush().expect("fixture response flushes");
        });
    }
    0
}

fn server_request_round_trip() -> i32 {
    let Some(trigger) = read_fixture_json_line() else {
        return 74;
    };
    let Some(trigger_id) = trigger.get("id").cloned() else {
        return 65;
    };
    if write_fixture_json_line(&serde_json::json!({
        "id": "approval-7",
        "method": "item/commandExecution/requestApproval",
        "params": {"command": "cargo test"},
    }))
    .is_err()
    {
        return 74;
    }
    let Some(response) = read_fixture_json_line() else {
        return 74;
    };
    let home = match fixture_home() {
        Ok(home) => home,
        Err(_) => return 73,
    };
    if fs::write(
        home.join("server-response.json"),
        serde_json::to_vec(&response).expect("fixture response serializes"),
    )
    .is_err()
    {
        return 73;
    }
    if write_fixture_json_line(&serde_json::json!({
        "id": trigger_id,
        "result": "complete",
    }))
    .is_err()
    {
        return 74;
    }
    thread::sleep(Duration::from_secs(30));
    0
}

fn duplicate_server_request() -> i32 {
    if read_fixture_json_line().is_none() {
        return 74;
    }
    let request = serde_json::json!({
        "id": "duplicate-approval",
        "method": "item/commandExecution/requestApproval",
        "params": {},
    });
    if write_fixture_json_line(&request).is_err() || write_fixture_json_line(&request).is_err() {
        return 74;
    }
    thread::sleep(Duration::from_secs(30));
    0
}

fn confused_response(with_method: bool) -> i32 {
    let Some(trigger) = read_fixture_json_line() else {
        return 74;
    };
    let Some(id) = trigger.get("id").cloned() else {
        return 65;
    };
    let response = if with_method {
        serde_json::json!({"id": id, "method": "not/a/request", "result": null})
    } else {
        serde_json::json!({"id": id})
    };
    if write_fixture_json_line(&response).is_err() {
        return 74;
    }
    thread::sleep(Duration::from_secs(30));
    0
}

fn server_request_flood() -> i32 {
    if read_fixture_json_line().is_none() {
        return 74;
    }
    for id in 0..=64_u64 {
        if write_fixture_json_line(&serde_json::json!({
            "id": format!("approval-{id}"),
            "method": "item/commandExecution/requestApproval",
            "params": {},
        }))
        .is_err()
        {
            return 74;
        }
    }
    thread::sleep(Duration::from_secs(30));
    0
}

fn read_fixture_json_line() -> Option<serde_json::Value> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok()?;
    serde_json::from_str(&input).ok()
}

fn write_fixture_json_line(value: &serde_json::Value) -> io::Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, value)?;
    writeln!(stdout)?;
    stdout.flush()
}

fn record_received_request() -> io::Result<()> {
    let count = RECEIVED_REQUESTS.fetch_add(1, Ordering::Relaxed) + 1;
    let home = fixture_home()?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(home.join("received-count"))?;
    write!(file, "{count}")?;
    file.flush()
}

fn final_response_exit() -> i32 {
    let executable = match env::current_exe() {
        Ok(executable) => executable,
        Err(_) => return 71,
    };
    let grandchild = match Command::new(executable)
        .arg(FIXTURE_ARGUMENT)
        .arg("grandchild-process")
        .arg("1.2.3")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(grandchild) => grandchild,
        Err(_) => return 71,
    };
    if write_fixture_pids(process::id(), grandchild.id()).is_err() {
        return 73;
    }
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return 74;
    }
    let request: serde_json::Value = match serde_json::from_str(&input) {
        Ok(request) => request,
        Err(_) => return 65,
    };
    let Some(id) = request.get("id").cloned() else {
        return 65;
    };
    if record_received_request().is_err() {
        return 73;
    }
    thread::sleep(Duration::from_millis(75));
    let result = request
        .get("value")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if serde_json::to_writer(
        io::stdout(),
        &serde_json::json!({"id": id, "result": result}),
    )
    .is_err()
    {
        return 74;
    }
    println!();
    if io::stdout().flush().is_err() {
        return 74;
    }
    0
}

fn unknown_id_response() -> i32 {
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return 74;
    }
    println!(r#"{{"id":"not-the-request","result":null}}"#);
    let _ = io::stdout().flush();
    thread::sleep(Duration::from_secs(30));
    0
}

fn blocked_stdin() -> i32 {
    thread::sleep(Duration::from_secs(30));
    0
}

#[cfg(unix)]
fn replacement_execution_marker() -> i32 {
    let home = match fixture_home() {
        Ok(home) => home,
        Err(_) => return 73,
    };
    if fs::write(home.join("replacement-executed"), b"replacement-ran").is_err() {
        return 73;
    }
    strict_jsonl(false, false)
}

fn malformed_response(oversized: bool) -> i32 {
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return 74;
    }
    if oversized {
        println!("{}", "x".repeat(16_384));
    } else {
        println!("not-json");
    }
    let _ = io::stdout().flush();
    thread::sleep(Duration::from_secs(30));
    0
}

fn exit_with_pending() -> i32 {
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return 74;
    }
    thread::sleep(Duration::from_millis(75));
    23
}

fn hanging_version() -> i32 {
    let executable = match env::current_exe() {
        Ok(executable) => executable,
        Err(_) => return 71,
    };
    let grandchild = match Command::new(executable)
        .arg(FIXTURE_ARGUMENT)
        .arg("grandchild-process")
        .arg("1.2.3")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(grandchild) => grandchild,
        Err(_) => return 71,
    };
    if write_fixture_pids(process::id(), grandchild.id()).is_err() {
        return 73;
    }
    grandchild_process()
}

fn grandchild_leader(exit_immediately: bool) -> i32 {
    let executable = match env::current_exe() {
        Ok(executable) => executable,
        Err(_) => return 71,
    };
    let grandchild = match Command::new(executable)
        .arg(FIXTURE_ARGUMENT)
        .arg("grandchild-process")
        .arg("1.2.3")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(grandchild) => grandchild,
        Err(_) => return 71,
    };
    if write_fixture_pids(process::id(), grandchild.id()).is_err() {
        return 73;
    }
    if exit_immediately {
        thread::sleep(Duration::from_millis(75));
        return 0;
    }

    strict_jsonl(false, true)
}

fn grandchild_process() -> i32 {
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn write_fixture_pids(leader: u32, grandchild: u32) -> io::Result<()> {
    let home = fixture_home()?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(home.join("fixture-pids.json"))?;
    serde_json::to_writer(
        &mut file,
        &serde_json::json!({"leader": leader, "grandchild": grandchild}),
    )?;
    file.flush()
}

fn record_version_executable() -> io::Result<()> {
    let home = fixture_home()?;
    if fs::canonicalize(env::current_dir()?)? != fs::canonicalize(&home)? {
        return Err(io::Error::other(
            "fixture version probe working directory is not isolated",
        ));
    }
    let executable = fs::canonicalize(env::current_exe()?)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(home.join("version-executable-path"))?;
    file.write_all(executable.to_string_lossy().as_bytes())?;
    file.flush()
}

#[cfg(unix)]
fn swap_version_executable() -> io::Result<()> {
    let home = fixture_home()?;
    fs::rename(home.join("replacement-provider"), env::current_exe()?)
}

fn fixture_home() -> io::Result<PathBuf> {
    env::var_os("CODEX_HOME")
        .or_else(|| env::var_os("GROK_HOME"))
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("fixture home is missing"))
}

pub async fn wait_for_received_count(home: &Path, expected: u64) -> TestResult {
    let path = home.join("received-count");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(value) = fs::read_to_string(&path)
            && value.trim().parse::<u64>().ok() == Some(expected)
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("fixture did not receive request {expected}").into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub async fn wait_for_fixture_marker(home: &Path, name: &str) -> TestResult {
    let path = home.join(name);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if fs::read(&path).is_ok_and(|contents| contents == b"ready") {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("fixture marker {name:?} was not created").into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub async fn wait_for_fixture_json(path: &Path) -> TestResult<serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(contents) = fs::read(path)
            && let Ok(value) = serde_json::from_slice(&contents)
        {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for complete fixture JSON {}",
                path.display()
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub async fn wait_for_fixture_pids(home: &Path) -> TestResult<(u32, u32)> {
    let path = home.join("fixture-pids.json");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(file) = File::open(&path)
            && let Ok(pids) = serde_json::from_reader::<_, serde_json::Value>(file)
        {
            let leader = pids["leader"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok());
            let grandchild = pids["grandchild"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok());
            if let (Some(leader), Some(grandchild)) = (leader, grandchild) {
                return Ok((leader, grandchild));
            }
        }
        if Instant::now() >= deadline {
            return Err("fixture PID file was not created".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub async fn wait_until_processes_exit(pids: &[u32]) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if pids.iter().all(|pid| !process_is_alive(*pid)) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("fixture processes still alive: {pids:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub fn processes_have_exited(pids: &[u32]) -> bool {
    pids.iter().all(|pid| !process_is_alive(*pid))
}

pub async fn wait_until_processes_reaped(pids: &[u32]) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if pids.iter().all(|pid| !process_exists(*pid)) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("fixture process leaders were not reaped: {pids:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

pub fn processes_have_been_reaped(pids: &[u32]) -> bool {
    pids.iter().all(|pid| !process_exists(*pid))
}

#[cfg(unix)]
fn process_is_alive(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: signal zero performs an existence/permission check and does not signal the process.
    let result = unsafe { libc::kill(pid, 0) };
    if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
        return false;
    }

    // `kill(pid, 0)` also reports zombies. A zombie is no longer executing and is
    // acceptable while its new parent performs asynchronous reaping.
    let output = Command::new("ps")
        .args(["-o", "state=", "-p", &pid.to_string()])
        .output();
    match output {
        Ok(output) if output.status.success() => {
            let state = String::from_utf8_lossy(&output.stdout);
            !state.trim_start().starts_with('Z') && !state.trim().is_empty()
        }
        _ => true,
    }
}

#[cfg(unix)]
fn process_exists(pid: u32) -> bool {
    let Ok(pid) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: signal zero only queries whether this PID exists.
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
fn process_is_alive(pid: u32) -> bool {
    type Handle = *mut std::ffi::c_void;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;
    const ERROR_INVALID_PARAMETER: u32 = 87;
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, process_id: u32) -> Handle;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        fn CloseHandle(object: Handle) -> i32;
        fn GetLastError() -> u32;
    }

    // SAFETY: the handle is checked for null, waited without blocking, and closed once.
    unsafe {
        let process = OpenProcess(SYNCHRONIZE, 0, pid);
        if process.is_null() {
            return GetLastError() != ERROR_INVALID_PARAMETER;
        }
        let alive = WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
        let _ = CloseHandle(process);
        alive
    }
}

#[cfg(windows)]
fn process_exists(pid: u32) -> bool {
    process_is_alive(pid)
}
