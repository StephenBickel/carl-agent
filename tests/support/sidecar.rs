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
    ExecutableTrustDecision, JsonlSidecar, SidecarCommand, SidecarError, SidecarLimits,
    VersionOutputFormat,
};
use semver::VersionReq;

pub const FIXTURE_ARGUMENT: &str = "--carl-private-sidecar-fixture";
pub const FIXTURE_HOME_VARIABLE: &str = "CODEX_HOME";
pub const SECRET_SENTINEL: &str = "sk-sidecar-contract-secret";
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
        let root =
            env::temp_dir().join(format!("carl-sidecar-contract-{}-{serial}", process::id()));
        let data = root.join("data");
        let workspace = root.join("workspace");
        let home = data.join("providers").join("fixture");
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
        .trust(ExecutableTrustDecision::TrustCanonicalPath);
    JsonlSidecar::spawn_trusted(command, &trusted, &layout.data, &layout.workspace, limits).await
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
        "strict-jsonl" => strict_jsonl(false, false),
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
        if method == "delay-after-received" {
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
                &serde_json::json!({"id": id, "result": result}),
            )
            .expect("fixture response serializes");
            writeln!(stdout).expect("fixture response newline writes");
            stdout.flush().expect("fixture response flushes");
        });
    }
    0
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
