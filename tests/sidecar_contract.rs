#[allow(dead_code)]
#[path = "support/sidecar.rs"]
mod support;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::{self, Command as StdCommand, ExitStatus, Stdio};
use std::time::Duration;
use std::time::Instant;

#[cfg(unix)]
use carl::sidecar::ExecutableMetadataRisk;
use carl::sidecar::{
    DataRootLock, DataRootLockErrorCode, ExecutableTrustDecision, JsonlSidecar, NotificationPolicy,
    ProviderEnvironmentProfile, ProviderFileMetadata, ProviderHome, SidecarCommand, SidecarError,
    SidecarErrorCode, SidecarLimits, VersionOutputFormat,
};
use libtest_mimic::{Arguments, Failed, Trial};
use semver::{Version, VersionReq};
use serde_json::json;
#[cfg(windows)]
use support::processes_have_exited;
use support::{
    PATH_SENTINEL, SECRET_SENTINEL, TestLayout, TestResult, dispatch_fixture, fixture_command,
    short_limits, spawn_fixture, wait_for_fixture_pids, wait_for_received_count,
    wait_until_processes_exit, wait_until_processes_reaped,
};

fn main() {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    if let Some(exit_code) = dispatch_data_root_lock_fixture(&arguments) {
        process::exit(exit_code);
    }
    if let Some(exit_code) = dispatch_fixture(&arguments) {
        process::exit(exit_code);
    }

    // SAFETY: this runs before libtest-mimic starts any test threads. The values are scoped to
    // this custom-harness process and deliberately prove that child env_clear is effective.
    unsafe {
        env::set_var("OPENAI_API_KEY", SECRET_SENTINEL);
        env::set_var("TELEGRAM_BOT_TOKEN", SECRET_SENTINEL);
        env::set_var("AWS_ACCESS_KEY_ID", SECRET_SENTINEL);
        env::set_var("CODEX_HOME", "/parent/credential/home");
        env::set_var("GROK_HOME", "/parent/credential/home");
        #[cfg(target_os = "linux")]
        {
            env::set_var("XDG_RUNTIME_DIR", "/tmp/carl-poisoned-runtime");
            env::set_var(
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/tmp/carl-poisoned-runtime/bus;tcp:host=attacker",
            );
        }
        let inherited_path = env::var_os("PATH").unwrap_or_default();
        let poisoned_path = env::join_paths(
            std::iter::once(PathBuf::from(PATH_SENTINEL)).chain(env::split_paths(&inherited_path)),
        )
        .expect("the sentinel parent PATH is valid");
        env::set_var("PATH", poisoned_path);
    }

    let trials = vec![
        test(
            "data-root lock requires a private absolute root",
            data_root_lock_requires_a_private_absolute_root,
        ),
        test(
            "data-root lock contends in process and releases on drop",
            data_root_lock_contends_in_process_and_releases_on_drop,
        ),
        test(
            "data-root lock rejects an unsafe persistent component",
            data_root_lock_rejects_an_unsafe_persistent_component,
        ),
        test(
            "data-root lock contends across processes and releases after crash",
            data_root_lock_contends_across_processes_and_releases_after_crash,
        ),
        test(
            "data-root locks for distinct roots do not contend",
            data_root_locks_for_distinct_roots_do_not_contend,
        ),
        test("missing executable is typed", missing_executable_is_typed),
        test(
            "executable is canonical regular and trusted",
            executable_is_canonical_regular_and_trusted,
        ),
        test(
            "official Codex package wrappers resolve to packaged native binaries",
            official_codex_package_wrappers_resolve_to_packaged_native_binaries,
        ),
        test(
            "executable trust precedes every execution",
            executable_trust_precedes_every_execution,
        ),
        test(
            "trusted executable rejects same-path replacement before version",
            trusted_executable_rejects_same_path_replacement_before_version,
        ),
        test(
            "trust rejects replacement after executable resolution",
            trust_rejects_replacement_after_executable_resolution,
        ),
        test(
            "versions are parsed and pinned",
            versions_are_parsed_and_pinned,
        ),
        test(
            "sidecar limits reject unbounded configurations",
            sidecar_limits_reject_unbounded_configurations,
        ),
        test(
            "provider home is isolated and private",
            provider_home_is_isolated_and_private,
        ),
        test(
            "shared workspaces use identity-only validation",
            shared_workspaces_use_identity_only_validation,
        ),
        test(
            "provider home writes static files through its capability",
            provider_home_writes_static_files_through_its_capability,
        ),
        test(
            "provider home rejects ambient replacement",
            provider_home_rejects_ambient_replacement,
        ),
        test(
            "provider file metadata is capability relative",
            provider_file_metadata_is_capability_relative,
        ),
        test(
            "unsafe provider homes are rejected",
            unsafe_provider_homes_are_rejected,
        ),
        test(
            "child environment is allowlisted",
            child_environment_is_allowlisted,
        ),
        test(
            "Grok environment profile is closed",
            grok_environment_profile_is_closed,
        ),
        test(
            "convenience APIs honor Grok environment profile",
            convenience_apis_honor_grok_environment_profile,
        ),
        test(
            "responses correlate out of order",
            responses_correlate_out_of_order,
        ),
        test(
            "abandoned written request consumes one late response",
            abandoned_written_request_consumes_one_late_response,
        ),
        test(
            "prewrite drop permits safe ID reuse",
            prewrite_drop_permits_safe_id_reuse,
        ),
        test(
            "abandoned request budget fails safely",
            abandoned_request_budget_fails_safely,
        ),
        test(
            "leader exit preserves its final response",
            leader_exit_preserves_its_final_response,
        ),
        test(
            "notifications are bounded and delivered",
            notifications_are_bounded_and_delivered,
        ),
        test(
            "outbound notifications and nonblocking receive are bounded",
            outbound_notifications_and_nonblocking_receive_are_bounded,
        ),
        test(
            "notification rejection policy fails closed",
            notification_rejection_policy_fails_closed,
        ),
        test(
            "invalid request IDs are rejected",
            invalid_request_ids_are_rejected,
        ),
        test(
            "unknown response IDs fail closed",
            unknown_response_ids_fail_closed,
        ),
        test(
            "malformed stdout fails closed",
            malformed_stdout_fails_closed,
        ),
        test(
            "oversized stdout fails closed",
            oversized_stdout_fails_closed,
        ),
        test(
            "stderr is bounded and redacted",
            stderr_is_bounded_and_redacted,
        ),
        test(
            "child exit wakes every pending request",
            child_exit_wakes_every_pending_request,
        ),
        test(
            "explicit cancellation removes process group",
            explicit_cancellation_removes_process_group,
        ),
        test(
            "cancellation cannot deadlock on full stdin",
            cancellation_cannot_deadlock_on_full_stdin,
        ),
        test(
            "leader exit removes ordinary descendants",
            leader_exit_removes_ordinary_descendants,
        ),
        test(
            "dropping supervisor removes process group",
            dropping_supervisor_removes_process_group,
        ),
    ];
    #[cfg(unix)]
    let trials = {
        let mut trials = trials;
        trials.push(test(
            "trusted executable revalidates metadata before version",
            trusted_executable_revalidates_metadata_before_version,
        ));
        trials.push(test(
            "trusted executable rejects replacement between version and JSONL spawn",
            trusted_executable_rejects_replacement_between_version_and_jsonl_spawn,
        ));
        trials
    };
    libtest_mimic::run(&Arguments::from_args(), trials).exit();
}

fn test(name: &'static str, body: fn() -> TestResult) -> Trial {
    Trial::test(name, move || {
        body().map_err(|error| Failed::from(error.to_string()))
    })
}

fn run_async<T>(future: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the test Tokio runtime builds")
        .block_on(future)
}

const DATA_ROOT_LOCK_FIXTURE_ARGUMENT: &str = "--carl-private-data-root-lock-fixture";
const DATA_ROOT_LOCK_FILENAME: &str = ".carl-instance.lock";
const LOCK_ATTEMPT_ACQUIRED: i32 = 0;
const LOCK_ATTEMPT_CONTENDED: i32 = 23;

fn dispatch_data_root_lock_fixture(arguments: &[OsString]) -> Option<i32> {
    if arguments.first().map(OsString::as_os_str)
        != Some(OsStr::new(DATA_ROOT_LOCK_FIXTURE_ARGUMENT))
    {
        return None;
    }
    let scenario = arguments.get(1)?.as_os_str();
    let data_root = PathBuf::from(arguments.get(2)?);
    match scenario {
        scenario if scenario == OsStr::new("hold") => {
            let ready = PathBuf::from(arguments.get(3)?);
            let _lock = DataRootLock::acquire(&data_root).ok()?;
            fs::write(ready, b"ready").ok()?;
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        scenario if scenario == OsStr::new("attempt") => {
            Some(match DataRootLock::acquire(&data_root) {
                Ok(_lock) => {
                    println!("acquired");
                    LOCK_ATTEMPT_ACQUIRED
                }
                Err(error) if error.code() == DataRootLockErrorCode::Contended => {
                    println!("contended");
                    LOCK_ATTEMPT_CONTENDED
                }
                Err(_) => 24,
            })
        }
        _ => Some(64),
    }
}

fn data_root_lock_requires_a_private_absolute_root() -> TestResult {
    let layout = TestLayout::new()?;
    make_data_root_private(&layout.data)?;

    let missing = layout.data.join("missing");
    let missing_error = DataRootLock::acquire(&missing).expect_err("missing root is rejected");
    assert_eq!(missing_error.code(), DataRootLockErrorCode::InvalidDataRoot);
    let relative_error =
        DataRootLock::acquire(Path::new("relative-data-root")).expect_err("relative root fails");
    assert_eq!(
        relative_error.code(),
        DataRootLockErrorCode::InvalidDataRoot
    );
    let diagnostics = format!("{missing_error:?} {missing_error}");
    assert!(!diagnostics.contains(&layout.data.to_string_lossy().into_owned()));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(&layout.data, fs::Permissions::from_mode(0o755))?;
        let error = DataRootLock::acquire(&layout.data).expect_err("shared root is rejected");
        assert_eq!(error.code(), DataRootLockErrorCode::InvalidDataRoot);
        fs::set_permissions(&layout.data, fs::Permissions::from_mode(0o700))?;
    }

    let lock = DataRootLock::acquire(&layout.data)?;
    let diagnostics = format!("{lock:?}");
    assert!(!diagnostics.contains(&layout.data.to_string_lossy().into_owned()));
    drop(lock);
    assert_lock_file_is_private(&layout.data.join(DATA_ROOT_LOCK_FILENAME))?;
    Ok(())
}

fn data_root_lock_contends_in_process_and_releases_on_drop() -> TestResult {
    let layout = TestLayout::new()?;
    make_data_root_private(&layout.data)?;
    let first =
        DataRootLock::acquire(&layout.data).expect("the first same-process holder acquires");
    let lock_path = layout.data.join(DATA_ROOT_LOCK_FILENAME);
    let identity = lock_file_identity(&lock_path)?;

    let error = DataRootLock::acquire(&layout.data).expect_err("second holder must contend");
    assert_eq!(error.code(), DataRootLockErrorCode::Contended);
    assert!(!format!("{error:?} {error}").contains(&layout.data.to_string_lossy().into_owned()));

    drop(first);
    let second = DataRootLock::acquire(&layout.data)
        .expect("dropping the first same-process holder releases the lock");
    assert_eq!(lock_file_identity(&lock_path)?, identity);
    drop(second);
    assert!(
        lock_path.exists(),
        "the persistent lock file is never unlinked"
    );
    Ok(())
}

fn data_root_lock_rejects_an_unsafe_persistent_component() -> TestResult {
    let layout = TestLayout::new()?;
    make_data_root_private(&layout.data)?;
    let lock_path = layout.data.join(DATA_ROOT_LOCK_FILENAME);
    let alias = layout.data.join("lock-hard-link");
    drop(DataRootLock::acquire(&layout.data)?);
    fs::hard_link(&lock_path, &alias)?;

    let error = DataRootLock::acquire(&layout.data).expect_err("hard-linked lock is rejected");
    assert_eq!(error.code(), DataRootLockErrorCode::UnsafeLockFile);
    assert!(!format!("{error:?} {error}").contains(&layout.data.to_string_lossy().into_owned()));
    fs::remove_file(alias)?;
    drop(DataRootLock::acquire(&layout.data)?);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        fs::remove_file(&lock_path)?;
        symlink(layout.workspace.join("redirected-lock"), &lock_path)?;
        let error = DataRootLock::acquire(&layout.data).expect_err("symlink lock is rejected");
        assert_eq!(error.code(), DataRootLockErrorCode::UnsafeLockFile);
    }
    Ok(())
}

fn data_root_lock_contends_across_processes_and_releases_after_crash() -> TestResult {
    let layout = TestLayout::new()?;
    make_data_root_private(&layout.data)?;
    let ready = layout.workspace.join("lock-holder-ready");
    let mut holder = spawn_lock_holder(&layout.data, &ready)?;
    wait_for_lock_holder(&mut holder, &ready)?;
    let lock_path = layout.data.join(DATA_ROOT_LOCK_FILENAME);
    let identity = lock_file_identity(&lock_path)?;

    let (status, stdout, elapsed) = run_lock_attempt(&layout.data)?;
    assert_eq!(status.code(), Some(LOCK_ATTEMPT_CONTENDED));
    assert_eq!(stdout, "contended\n");
    assert!(
        elapsed < Duration::from_secs(2),
        "lock contention must fail promptly"
    );

    holder.kill()?;
    let _ = holder.wait()?;

    let (status, stdout, elapsed) = run_lock_attempt(&layout.data)?;
    assert_eq!(status.code(), Some(LOCK_ATTEMPT_ACQUIRED));
    assert_eq!(stdout, "acquired\n");
    assert!(elapsed < Duration::from_secs(2));
    assert_eq!(lock_file_identity(&lock_path)?, identity);
    assert!(
        lock_path.exists(),
        "crash recovery must not unlink the lock"
    );
    drop(
        DataRootLock::acquire(&layout.data)
            .expect("the successful contender's normal exit releases the OS lock"),
    );
    Ok(())
}

fn data_root_locks_for_distinct_roots_do_not_contend() -> TestResult {
    let first = TestLayout::new()?;
    let second = TestLayout::new()?;
    make_data_root_private(&first.data)?;
    make_data_root_private(&second.data)?;
    let ready = first.workspace.join("lock-holder-ready");
    let mut holder = spawn_lock_holder(&first.data, &ready)?;
    wait_for_lock_holder(&mut holder, &ready)?;

    let (status, stdout, elapsed) = run_lock_attempt(&second.data)?;
    holder.kill()?;
    let _ = holder.wait()?;
    assert_eq!(status.code(), Some(LOCK_ATTEMPT_ACQUIRED));
    assert_eq!(stdout, "acquired\n");
    assert!(elapsed < Duration::from_secs(2));
    Ok(())
}

#[cfg(unix)]
fn make_data_root_private(data_root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(data_root, fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn make_data_root_private(_data_root: &Path) -> std::io::Result<()> {
    Ok(())
}

fn spawn_lock_holder(data_root: &Path, ready: &Path) -> std::io::Result<process::Child> {
    StdCommand::new(env::current_exe()?)
        .arg(DATA_ROOT_LOCK_FIXTURE_ARGUMENT)
        .arg("hold")
        .arg(data_root)
        .arg(ready)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

fn wait_for_lock_holder(holder: &mut process::Child, ready: &Path) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if ready.exists() {
            return Ok(());
        }
        if let Some(status) = holder.try_wait()? {
            return Err(format!("lock holder exited before readiness: {status}").into());
        }
        if Instant::now() >= deadline {
            let _ = holder.kill();
            let _ = holder.wait();
            return Err("lock holder did not become ready".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run_lock_attempt(data_root: &Path) -> TestResult<(ExitStatus, String, Duration)> {
    let start = Instant::now();
    let mut child = StdCommand::new(env::current_exe()?)
        .arg(DATA_ROOT_LOCK_FIXTURE_ARGUMENT)
        .arg("attempt")
        .arg(data_root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = start + Duration::from_secs(5);
    loop {
        if child.try_wait()?.is_some() {
            let elapsed = start.elapsed();
            let output = child.wait_with_output()?;
            return Ok((output.status, String::from_utf8(output.stdout)?, elapsed));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("lock attempt did not finish promptly".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn lock_file_identity(path: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn lock_file_identity(path: &Path) -> std::io::Result<(u32, u64)> {
    use std::fs::File;
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
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: GetFileInformationByHandle succeeded.
    let information = unsafe { information.assume_init() };
    Ok((
        information.dwVolumeSerialNumber,
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    ))
}

fn assert_lock_file_is_private(path: &Path) -> TestResult {
    let metadata = fs::symlink_metadata(path)?;
    assert!(metadata.file_type().is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // SAFETY: geteuid has no preconditions.
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }
    Ok(())
}

async fn detect_version(
    command: &SidecarCommand,
    data_root: &Path,
    workspace: &Path,
) -> Result<Version, SidecarError> {
    let trusted = command
        .resolve_executable()?
        .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
    command
        .detect_trusted_version(
            &trusted,
            ProviderEnvironmentProfile::Codex,
            data_root,
            workspace,
            short_limits(),
        )
        .await
}

fn missing_executable_is_typed() -> TestResult {
    let layout = TestLayout::new()?;
    let command = SidecarCommand {
        executable: layout.data.join("missing-provider-executable"),
        arguments: Vec::new(),
        version_arguments: vec![OsString::from("--version")],
        version_output: VersionOutputFormat::ExactPrefix("missing-provider"),
        isolated_home: layout.home.clone(),
        supported_versions: VersionReq::parse("^1.2")?,
    };

    let error = command
        .resolve_executable()
        .expect_err("missing executable must fail");
    assert_eq!(error.code(), SidecarErrorCode::ExecutableMissing);
    assert!(!format!("{error:?}").contains("missing-provider-executable"));
    Ok(())
}

fn executable_is_canonical_regular_and_trusted() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let executable = env::current_exe()?;
        let configured = executable
            .parent()
            .ok_or("test executable has no parent")?
            .join(".")
            .join(
                executable
                    .file_name()
                    .ok_or("test executable has no file name")?,
            );
        let mut command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        command.executable = configured;
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let canonical = fs::canonicalize(executable)?;
        assert_eq!(sidecar.executable_path(), canonical);
        let identity = sidecar
            .request(json!({"id": "identity", "method": "identity"}))
            .await?;
        assert_eq!(identity["result"].as_str(), canonical.to_str());
        assert_eq!(
            fs::read_to_string(layout.home.join("version-executable-path"))?,
            canonical.to_string_lossy()
        );
        sidecar.cancel().await?;
        TestResult::Ok(())
    })?;

    let directory_layout = TestLayout::new()?;
    let mut directory = fixture_command(&directory_layout, "strict-jsonl", "1.2.3");
    directory.executable = directory_layout.data.clone();
    let error = directory
        .resolve_executable()
        .expect_err("an executable candidate must be a regular file");
    assert_eq!(error.code(), SidecarErrorCode::ExecutableUnavailable);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let writable_layout = TestLayout::new()?;
        let writable_executable = writable_layout.data.join("writable-sidecar");
        fs::copy(env::current_exe()?, &writable_executable)?;
        fs::set_permissions(&writable_executable, fs::Permissions::from_mode(0o777))?;
        let mut writable = fixture_command(&writable_layout, "strict-jsonl", "1.2.3");
        writable.executable = writable_executable;
        let error = writable
            .resolve_executable()
            .expect_err("a broadly writable executable must be rejected");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);

        let unsafe_parent_layout = TestLayout::new()?;
        let unsafe_parent = unsafe_parent_layout.data.join("unsafe-bin");
        fs::create_dir(&unsafe_parent)?;
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777))?;
        let nested_executable = unsafe_parent.join("provider");
        fs::copy(env::current_exe()?, &nested_executable)?;
        fs::set_permissions(&nested_executable, fs::Permissions::from_mode(0o755))?;
        let mut nested = fixture_command(&unsafe_parent_layout, "strict-jsonl", "1.2.3");
        nested.executable = nested_executable;
        let error = nested
            .resolve_executable()
            .expect_err("an executable under a broadly writable parent must be rejected");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);

        let metadata_risk_layout = TestLayout::new()?;
        let metadata_risk_parent = metadata_risk_layout.data.join("native-prefix");
        fs::create_dir(&metadata_risk_parent)?;
        fs::set_permissions(&metadata_risk_parent, fs::Permissions::from_mode(0o775))?;
        let metadata_risk_executable = metadata_risk_parent.join("provider");
        fs::copy(env::current_exe()?, &metadata_risk_executable)?;
        fs::set_permissions(&metadata_risk_executable, fs::Permissions::from_mode(0o755))?;
        let mut metadata_risk = fixture_command(&metadata_risk_layout, "strict-jsonl", "1.2.3");
        metadata_risk.executable = metadata_risk_executable;
        let resolved = metadata_risk.resolve_executable()?;
        assert_eq!(
            resolved.metadata_risk(),
            Some(ExecutableMetadataRisk::GroupWritableInstallDirectory)
        );
        let error = resolved
            .trust(ExecutableTrustDecision::TrustCanonicalPath)
            .expect_err("metadata risk requires its own explicit trust decision");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);
        metadata_risk
            .resolve_executable()?
            .trust(ExecutableTrustDecision::TrustCanonicalPathWithMetadataRisk)?;
    }

    Ok(())
}

fn official_codex_package_wrappers_resolve_to_packaged_native_binaries() -> TestResult {
    #[cfg(all(
        unix,
        any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "aarch64"),
            all(target_os = "linux", target_arch = "x86_64")
        )
    ))]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let layout = TestLayout::new()?;
        let package_root = layout
            .data
            .join("lib")
            .join("node_modules")
            .join("@openai")
            .join("codex");
        let wrapper = package_root.join("bin").join("codex.js");
        let native = package_root
            .join("node_modules")
            .join("@openai")
            .join(codex_native_package_name())
            .join("vendor")
            .join(codex_native_target_triple())
            .join("bin")
            .join("codex");
        fs::create_dir_all(wrapper.parent().ok_or("wrapper has no parent")?)?;
        fs::create_dir_all(native.parent().ok_or("native binary has no parent")?)?;
        fs::write(&wrapper, b"#!/usr/bin/env node\nprocess.exit(86)\n")?;
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755))?;
        fs::copy(env::current_exe()?, &native)?;
        fs::set_permissions(&native, fs::Permissions::from_mode(0o755))?;
        let launcher = layout.data.join("bin").join("codex");
        fs::create_dir_all(launcher.parent().ok_or("launcher has no parent")?)?;
        symlink(&wrapper, &launcher)?;

        let mut command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        command.executable = launcher;
        let resolved = command.resolve_executable()?;
        assert_eq!(resolved.canonical_path(), fs::canonicalize(&native)?);
        let trusted = resolved.trust(ExecutableTrustDecision::TrustCanonicalPath)?;
        assert_eq!(
            run_async(command.detect_trusted_version(
                &trusted,
                ProviderEnvironmentProfile::Codex,
                &layout.data,
                &layout.workspace,
                short_limits(),
            ))?,
            Version::parse("1.2.3")?
        );

        let homebrew_layout = TestLayout::new()?;
        let homebrew_package_root = homebrew_layout
            .data
            .join("Cellar")
            .join("codex")
            .join("0.136.0")
            .join("libexec")
            .join("lib")
            .join("node_modules")
            .join("@openai")
            .join("codex");
        let homebrew_wrapper = homebrew_package_root.join("bin").join("codex.js");
        let homebrew_native = homebrew_package_root
            .join("vendor")
            .join(codex_native_target_triple())
            .join("codex")
            .join("codex");
        fs::create_dir_all(
            homebrew_wrapper
                .parent()
                .ok_or("Homebrew wrapper has no parent")?,
        )?;
        fs::create_dir_all(
            homebrew_native
                .parent()
                .ok_or("Homebrew native binary has no parent")?,
        )?;
        fs::write(
            &homebrew_wrapper,
            b"#!/usr/bin/env node\nprocess.exit(86)\n",
        )?;
        fs::set_permissions(&homebrew_wrapper, fs::Permissions::from_mode(0o755))?;
        fs::copy(env::current_exe()?, &homebrew_native)?;
        fs::set_permissions(&homebrew_native, fs::Permissions::from_mode(0o755))?;
        let homebrew_launcher = homebrew_layout.data.join("homebrew-bin").join("codex");
        fs::create_dir_all(
            homebrew_launcher
                .parent()
                .ok_or("Homebrew launcher has no parent")?,
        )?;
        symlink(&homebrew_wrapper, &homebrew_launcher)?;

        let mut homebrew_command = fixture_command(&homebrew_layout, "strict-jsonl", "1.2.3");
        homebrew_command.executable = homebrew_launcher;
        assert_eq!(
            homebrew_command.resolve_executable()?.canonical_path(),
            fs::canonicalize(homebrew_native)?
        );
    }
    Ok(())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn codex_native_package_name() -> &'static str {
    "codex-darwin-arm64"
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn codex_native_package_name() -> &'static str {
    "codex-darwin-x64"
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn codex_native_package_name() -> &'static str {
    "codex-linux-arm64"
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn codex_native_package_name() -> &'static str {
    "codex-linux-x64"
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn codex_native_target_triple() -> &'static str {
    "aarch64-apple-darwin"
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn codex_native_target_triple() -> &'static str {
    "x86_64-apple-darwin"
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
fn codex_native_target_triple() -> &'static str {
    "aarch64-unknown-linux-musl"
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn codex_native_target_triple() -> &'static str {
    "x86_64-unknown-linux-musl"
}

fn executable_trust_precedes_every_execution() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let resolved = command.resolve_executable()?;
        let canonical = fs::canonicalize(env::current_exe()?)?;
        assert_eq!(resolved.canonical_path(), canonical);
        assert!(
            !layout.home.join("version-executable-path").exists(),
            "resolving a candidate must not execute it"
        );

        let trusted = resolved.trust(ExecutableTrustDecision::TrustCanonicalPath)?;
        assert_eq!(
            command
                .detect_trusted_version(
                    &trusted,
                    ProviderEnvironmentProfile::Codex,
                    &layout.data,
                    &layout.workspace,
                    short_limits(),
                )
                .await?,
            Version::parse("1.2.3")?
        );
        assert!(layout.home.join("version-executable-path").is_file());
        TestResult::Ok(())
    })
}

fn trusted_executable_rejects_same_path_replacement_before_version() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let executable = layout.data.join("trusted-provider");
        fs::copy(env::current_exe()?, &executable)?;
        let replacement = layout.data.join("replacement-provider");
        fs::copy(env::current_exe()?, &replacement)?;

        let mut command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        command.executable = executable.clone();
        let trusted = command
            .resolve_executable()?
            .trust(ExecutableTrustDecision::TrustCanonicalPath)?;

        fs::remove_file(&executable)?;
        fs::rename(&replacement, &executable)?;

        let error = command
            .detect_trusted_version(
                &trusted,
                ProviderEnvironmentProfile::Codex,
                &layout.data,
                &layout.workspace,
                short_limits(),
            )
            .await
            .expect_err("replacing a trusted executable at the same path must fail");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);
        assert!(
            !layout.home.join("version-executable-path").exists(),
            "the replacement executable must not run"
        );
        TestResult::Ok(())
    })
}

fn trust_rejects_replacement_after_executable_resolution() -> TestResult {
    let layout = TestLayout::new()?;
    let executable = layout.data.join("resolved-provider");
    fs::copy(env::current_exe()?, &executable)?;
    let replacement = layout.data.join("replacement-provider");
    fs::copy(env::current_exe()?, &replacement)?;

    let mut command = fixture_command(&layout, "strict-jsonl", "1.2.3");
    command.executable = executable.clone();
    let resolved = command.resolve_executable()?;
    fs::remove_file(&executable)?;
    fs::rename(&replacement, &executable)?;

    let error = resolved
        .trust(ExecutableTrustDecision::TrustCanonicalPath)
        .expect_err("the trust decision must remain bound to the inspected file");
    assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);
    Ok(())
}

#[cfg(unix)]
fn trusted_executable_revalidates_metadata_before_version() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    run_async(async {
        let layout = TestLayout::new()?;
        let executable = layout.data.join("trusted-provider");
        fs::copy(env::current_exe()?, &executable)?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;

        let mut command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        command.executable = executable.clone();
        let trusted = command
            .resolve_executable()?
            .trust(ExecutableTrustDecision::TrustCanonicalPath)?;

        fs::set_permissions(&executable, fs::Permissions::from_mode(0o777))?;
        let error = command
            .detect_trusted_version(
                &trusted,
                ProviderEnvironmentProfile::Codex,
                &layout.data,
                &layout.workspace,
                short_limits(),
            )
            .await
            .expect_err("unsafe metadata introduced after trust must fail");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);
        assert!(
            !layout.home.join("version-executable-path").exists(),
            "an executable that became writable must not run"
        );
        TestResult::Ok(())
    })
}

#[cfg(unix)]
fn trusted_executable_rejects_replacement_between_version_and_jsonl_spawn() -> TestResult {
    use std::os::unix::fs::PermissionsExt;

    run_async(async {
        let layout = TestLayout::new()?;
        let executable = layout.data.join("trusted-provider");
        fs::copy(env::current_exe()?, &executable)?;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))?;
        let home = ProviderHome::prepare(
            ProviderEnvironmentProfile::Codex,
            &layout.data,
            &layout.workspace,
            &layout.home,
        )?;
        let replacement = layout.home.join("replacement-provider");
        fs::copy(env::current_exe()?, &replacement)?;
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755))?;

        let mut command = fixture_command(&layout, "replacement-execution-marker", "1.2.3");
        command.executable = executable;
        command.version_arguments = vec![
            OsString::from(support::FIXTURE_ARGUMENT),
            OsString::from("version-swap-executable"),
            OsString::from("1.2.3"),
            OsString::from("--version"),
        ];
        let trusted = command
            .resolve_executable()?
            .trust(ExecutableTrustDecision::TrustCanonicalPath)?;

        let error = match JsonlSidecar::spawn_in_home(
            command,
            &trusted,
            &home,
            NotificationPolicy::Reject,
            short_limits(),
        )
        .await
        {
            Err(error) => error,
            Ok(sidecar) => {
                let replacement_marker = layout.home.join("replacement-executed");
                let deadline = Instant::now() + Duration::from_secs(2);
                while !replacement_marker.exists() && Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let replacement_ran = replacement_marker.exists();
                let version_path = fs::read_to_string(layout.home.join("version-executable-path"))?;
                let configured_path = fs::canonicalize(layout.data.join("trusted-provider"))?;
                let _ = sidecar.cancel().await;
                return Err(format!(
                    "the replaced JSONL executable was accepted (replacement ran: \
                     {replacement_ran}, version path: {version_path}, configured path: {})",
                    configured_path.display()
                )
                .into());
            }
        };
        assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);
        assert!(
            !layout.home.join("replacement-executed").exists(),
            "the replacement executable must not run"
        );
        TestResult::Ok(())
    })
}

fn sidecar_limits_reject_unbounded_configurations() -> TestResult {
    run_async(async {
        for limits in [
            SidecarLimits {
                max_stdout_line_bytes: 1024 * 1024 + 1,
                ..short_limits()
            },
            SidecarLimits {
                max_stderr_bytes: 64 * 1024 + 1,
                ..short_limits()
            },
            SidecarLimits {
                graceful_shutdown_timeout: Duration::from_secs(31),
                ..short_limits()
            },
            SidecarLimits {
                process_poll_interval: Duration::from_millis(151),
                ..short_limits()
            },
        ] {
            let layout = TestLayout::new()?;
            let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
            let trusted = command
                .resolve_executable()?
                .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
            let error = JsonlSidecar::spawn_trusted(
                command,
                &trusted,
                ProviderEnvironmentProfile::Codex,
                &layout.data,
                &layout.workspace,
                limits,
            )
            .await
            .expect_err("unsafe sidecar limits must be rejected");
            assert_eq!(error.code(), SidecarErrorCode::InvalidConfiguration);
            assert!(!layout.home.join("version-executable-path").exists());
        }
        TestResult::Ok(())
    })
}

fn versions_are_parsed_and_pinned() -> TestResult {
    let supported_layout = TestLayout::new()?;
    let supported = fixture_command(&supported_layout, "strict-jsonl", "1.4.7");
    assert_eq!(
        run_async(detect_version(
            &supported,
            &supported_layout.data,
            &supported_layout.workspace,
        ))?,
        Version::parse("1.4.7")?
    );

    let unsupported_layout = TestLayout::new()?;
    let unsupported = fixture_command(&unsupported_layout, "strict-jsonl", "2.0.0");
    let error = run_async(detect_version(
        &unsupported,
        &unsupported_layout.data,
        &unsupported_layout.workspace,
    ))
    .expect_err("a version outside the pinned range must fail");
    assert_eq!(error.code(), SidecarErrorCode::UnsupportedVersion);
    assert!(!error.to_string().contains("2.0.0"));

    let exact_layout = TestLayout::new()?;
    let mut exact = fixture_command(&exact_layout, "strict-jsonl", "1.2.3");
    exact.version_output = VersionOutputFormat::ExactPrefixedVersion {
        prefix: "carl-sidecar-fixture",
        version: "1.2.3",
    };
    assert_eq!(
        run_async(detect_version(
            &exact,
            &exact_layout.data,
            &exact_layout.workspace,
        ))?,
        Version::parse("1.2.3")?
    );

    let modified_layout = TestLayout::new()?;
    let mut modified = fixture_command(&modified_layout, "strict-jsonl", "1.2.3+modified");
    modified.version_output = VersionOutputFormat::ExactPrefixedVersion {
        prefix: "carl-sidecar-fixture",
        version: "1.2.3",
    };
    let error = run_async(detect_version(
        &modified,
        &modified_layout.data,
        &modified_layout.workspace,
    ))
    .expect_err("an exact version format must reject build metadata");
    assert_eq!(error.code(), SidecarErrorCode::UnsupportedVersion);

    let malformed_layout = TestLayout::new()?;
    let malformed = fixture_command(&malformed_layout, "strict-jsonl", "not-a-version");
    let error = run_async(detect_version(
        &malformed,
        &malformed_layout.data,
        &malformed_layout.workspace,
    ))
    .expect_err("unparseable version output must fail");
    assert_eq!(error.code(), SidecarErrorCode::ProtocolViolation);

    let grok_layout = TestLayout::new()?;
    let mut grok = fixture_command(&grok_layout, "strict-jsonl", "1.8.2");
    grok.version_arguments = vec![
        OsString::from(support::FIXTURE_ARGUMENT),
        OsString::from("version-grok"),
        OsString::from("1.8.2"),
        OsString::from("--no-auto-update"),
        OsString::from("version"),
    ];
    grok.version_output = VersionOutputFormat::SingleSemverToken;
    assert_eq!(
        run_async(detect_version(
            &grok,
            &grok_layout.data,
            &grok_layout.workspace,
        ))?,
        Version::parse("1.8.2")?
    );

    let exact_token_layout = TestLayout::new()?;
    let mut exact_token = fixture_command(&exact_token_layout, "strict-jsonl", "1.8.2+modified");
    exact_token.version_arguments = vec![
        OsString::from(support::FIXTURE_ARGUMENT),
        OsString::from("version-grok"),
        OsString::from("1.8.2+modified"),
        OsString::from("--no-auto-update"),
        OsString::from("version"),
    ];
    exact_token.version_output = VersionOutputFormat::SingleExactSemverToken { version: "1.8.2" };
    let error = run_async(detect_version(
        &exact_token,
        &exact_token_layout.data,
        &exact_token_layout.workspace,
    ))
    .expect_err("an exact single-token format must reject build metadata");
    assert_eq!(error.code(), SidecarErrorCode::UnsupportedVersion);

    let closed_format_layout = TestLayout::new()?;
    let mut closed_format = fixture_command(&closed_format_layout, "strict-jsonl", "1.8.2");
    closed_format.version_arguments = vec![
        OsString::from(support::FIXTURE_ARGUMENT),
        OsString::from("version-grok"),
        OsString::from("1.8.2"),
        OsString::from("--no-auto-update"),
        OsString::from("version"),
    ];
    closed_format.version_output = VersionOutputFormat::ExactPrefix("codex-cli");
    let error = run_async(detect_version(
        &closed_format,
        &closed_format_layout.data,
        &closed_format_layout.workspace,
    ))
    .expect_err("provider version formats must not be interchangeable");
    assert_eq!(error.code(), SidecarErrorCode::ProtocolViolation);

    for (scenario, expected) in [
        ("version-nonzero", SidecarErrorCode::ProtocolViolation),
        ("version-multiple", SidecarErrorCode::ProtocolViolation),
        ("version-oversized", SidecarErrorCode::ProtocolViolation),
    ] {
        let layout = TestLayout::new()?;
        let mut command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        command.version_arguments = vec![
            OsString::from(support::FIXTURE_ARGUMENT),
            OsString::from(scenario),
            OsString::from("1.2.3"),
        ];
        command.version_output = if scenario == "version-multiple" {
            VersionOutputFormat::SingleSemverToken
        } else {
            VersionOutputFormat::ExactPrefix("carl-sidecar-fixture")
        };
        let error = run_async(detect_version(&command, &layout.data, &layout.workspace))
            .expect_err("invalid or failed version output must fail closed");
        assert_eq!(error.code(), expected);
    }

    let hanging_layout = TestLayout::new()?;
    let mut hanging = fixture_command(&hanging_layout, "strict-jsonl", "1.2.3");
    hanging.version_arguments = vec![
        OsString::from(support::FIXTURE_ARGUMENT),
        OsString::from("version-hanging"),
        OsString::from("1.2.3"),
    ];
    let error = run_async(detect_version(
        &hanging,
        &hanging_layout.data,
        &hanging_layout.workspace,
    ))
    .expect_err("a hanging version probe must time out");
    assert_eq!(error.code(), SidecarErrorCode::TimedOut);
    let pids = run_async(wait_for_fixture_pids(&hanging_layout.home))?;
    run_async(wait_until_processes_reaped(&[pids.0]))?;
    run_async(wait_until_processes_exit(&[pids.1]))?;
    Ok(())
}

fn provider_home_is_isolated_and_private() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;

        assert!(layout.home.is_absolute());
        assert!(layout.home.starts_with(&layout.data));
        assert!(!layout.home.starts_with(&layout.workspace));
        assert!(layout.home.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&layout.home)?.permissions().mode() & 0o777,
                0o700
            );
        }

        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn shared_workspaces_use_identity_only_validation() -> TestResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let layout = TestLayout::new()?;
        fs::set_permissions(&layout.workspace, fs::Permissions::from_mode(0o775))?;
        let home = ProviderHome::prepare(
            ProviderEnvironmentProfile::Codex,
            &layout.data,
            &layout.workspace,
            &layout.home,
        )?;
        assert!(home.matches_path(&layout.home));
        assert_eq!(
            fs::metadata(&layout.workspace)?.permissions().mode() & 0o777,
            0o775,
            "workspace permissions must remain outside provider-private policy"
        );
    }
    Ok(())
}

fn provider_home_writes_static_files_through_its_capability() -> TestResult {
    let layout = TestLayout::new()?;
    let home = ProviderHome::prepare(
        ProviderEnvironmentProfile::Codex,
        &layout.data,
        &layout.workspace,
        &layout.home,
    )?;
    assert!(home.matches_path(&layout.home));

    home.write_static_file("config.toml", b"first = true\n")?;
    assert_eq!(
        fs::read(layout.home.join("config.toml"))?,
        b"first = true\n"
    );
    home.write_static_file("config.toml", b"second = true\n")?;
    assert_eq!(
        fs::read(layout.home.join("config.toml"))?,
        b"second = true\n"
    );

    let config = layout.home.join("config.toml");
    let hard_link = layout.home.join("config-hard-link.toml");
    fs::hard_link(&config, &hard_link)?;
    let error = home
        .write_static_file("config.toml", b"must not replace a hard link\n")
        .expect_err("hard-linked provider config must fail closed");
    assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
    fs::remove_file(&hard_link)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};

        assert_eq!(fs::metadata(&config)?.permissions().mode() & 0o777, 0o600);
        fs::set_permissions(&config, fs::Permissions::from_mode(0o644))?;
        let error = home
            .write_static_file("config.toml", b"must not replace broad config\n")
            .expect_err("non-owner-only provider config must fail closed");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600))?;

        let outside = layout.data.join("outside-config.toml");
        fs::write(&outside, b"outside\n")?;
        fs::remove_file(&config)?;
        symlink(&outside, &config)?;
        let error = home
            .write_static_file("config.toml", b"must not follow a symlink\n")
            .expect_err("symlinked provider config must fail closed");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
        assert_eq!(fs::read(outside)?, b"outside\n");
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::symlink_file;

        let outside = layout.data.join("outside-config.toml");
        fs::write(&outside, b"outside\r\n")?;
        fs::remove_file(&config)?;
        if symlink_file(&outside, &config).is_ok() {
            let error = home
                .write_static_file("config.toml", b"must not follow a reparse point\r\n")
                .expect_err("reparse-point provider config must fail closed");
            assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
            assert_eq!(fs::read(outside)?, b"outside\r\n");
        }
    }
    Ok(())
}

fn provider_home_rejects_ambient_replacement() -> TestResult {
    let layout = TestLayout::new()?;
    let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
    let trusted = command
        .resolve_executable()?
        .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
    let home = ProviderHome::prepare(
        ProviderEnvironmentProfile::Codex,
        &layout.data,
        &layout.workspace,
        &layout.home,
    )?;
    let moved = layout.data.join("held-provider-home");
    fs::rename(&layout.home, &moved)?;
    fs::create_dir_all(layout.home.join(".carl-tmp"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&layout.home, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(
            layout.home.join(".carl-tmp"),
            fs::Permissions::from_mode(0o700),
        )?;
    }

    assert!(!home.matches_path(&layout.home));
    let error = home
        .write_static_file("replacement-must-stay-empty.toml", b"unsafe = true\n")
        .expect_err("an ambient replacement must invalidate the capability");
    assert_eq!(error.code(), SidecarErrorCode::InvalidProviderHome);
    assert!(
        !layout
            .home
            .join("replacement-must-stay-empty.toml")
            .exists()
    );
    assert!(!moved.join("replacement-must-stay-empty.toml").exists());
    let error = run_async(command.detect_version_in_home(&trusted, &home, short_limits()))
        .expect_err("version probing must reject a replaced provider home");
    assert_eq!(error.code(), SidecarErrorCode::InvalidProviderHome);
    assert!(!layout.home.join("version-executable-path").exists());
    assert!(!moved.join("version-executable-path").exists());
    Ok(())
}

fn provider_file_metadata_is_capability_relative() -> TestResult {
    let layout = TestLayout::new()?;
    let home = ProviderHome::prepare(
        ProviderEnvironmentProfile::Grok,
        &layout.data,
        &layout.workspace,
        &layout.home,
    )?;
    assert_eq!(
        home.inspect_owner_only_file("auth.json", 4 * 1024)?,
        ProviderFileMetadata::Missing
    );

    let auth = layout.home.join("auth.json");
    fs::write(&auth, b"provider-owned-secret")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600))?;
    }
    assert_eq!(
        home.inspect_owner_only_file("auth.json", 4 * 1024)?,
        ProviderFileMetadata::Safe
    );
    let alias = layout.home.join("auth-alias.json");
    fs::hard_link(&auth, &alias)?;
    let error = home
        .inspect_owner_only_file("auth.json", 4 * 1024)
        .expect_err("a hard-linked provider credential file must fail closed");
    assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
    fs::remove_file(alias)?;

    let error = home
        .inspect_owner_only_file("auth.json", 4)
        .expect_err("an oversized provider credential file must fail closed");
    assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);

    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};

        fs::set_permissions(&auth, fs::Permissions::from_mode(0o644))?;
        let error = home
            .inspect_owner_only_file("auth.json", 4 * 1024)
            .expect_err("a broadly readable provider credential file must fail closed");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
        fs::set_permissions(&auth, fs::Permissions::from_mode(0o600))?;

        fs::remove_file(&auth)?;
        let outside = layout.data.join("outside-auth.json");
        fs::write(&outside, b"outside-secret")?;
        symlink(&outside, &auth)?;
        let error = home
            .inspect_owner_only_file("auth.json", 4 * 1024)
            .expect_err("a symlinked provider credential file must fail closed");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
        fs::remove_file(&auth)?;
        fs::create_dir(&auth)?;
        let error = home
            .inspect_owner_only_file("auth.json", 4 * 1024)
            .expect_err("a provider credential directory must fail closed");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::symlink_file;

        fs::remove_file(&auth)?;
        let outside = layout.data.join("outside-auth.json");
        fs::write(&outside, b"outside-secret")?;
        if symlink_file(&outside, &auth).is_ok() {
            let error = home
                .inspect_owner_only_file("auth.json", 4 * 1024)
                .expect_err("a reparse-point provider credential file must fail closed");
            assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
            fs::remove_file(&auth)?;
        }
        fs::create_dir(&auth)?;
        let error = home
            .inspect_owner_only_file("auth.json", 4 * 1024)
            .expect_err("a provider credential directory must fail closed");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeProviderFile);
    }
    Ok(())
}

fn unsafe_provider_homes_are_rejected() -> TestResult {
    let inside_workspace = TestLayout::new()?;
    let mut command = fixture_command(&inside_workspace, "strict-jsonl", "1.2.3");
    command.isolated_home = inside_workspace.workspace.join("provider-home");
    let error = run_async(spawn_fixture(command, &inside_workspace, short_limits()))
        .expect_err("a provider home inside the workspace must be rejected");
    assert_eq!(error.code(), SidecarErrorCode::InvalidProviderHome);

    let relative_root = TestLayout::new()?;
    let command = fixture_command(&relative_root, "strict-jsonl", "1.2.3");
    let trusted = command
        .resolve_executable()?
        .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
    let error = run_async(JsonlSidecar::spawn_trusted(
        command,
        &trusted,
        ProviderEnvironmentProfile::Codex,
        PathBuf::from("relative-data-root"),
        &relative_root.workspace,
        short_limits(),
    ))
    .expect_err("a relative Carl data root must be rejected");
    assert_eq!(error.code(), SidecarErrorCode::InvalidProviderHome);

    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root_inside_workspace = TestLayout::new()?;
        let nested_root = root_inside_workspace.workspace.join("data");
        fs::create_dir(&nested_root)?;
        fs::set_permissions(&nested_root, fs::Permissions::from_mode(0o750))?;
        let mode_before = fs::metadata(&nested_root)?.permissions().mode() & 0o777;
        let nested_home = nested_root.join("providers").join("fixture");
        let error = ProviderHome::prepare(
            ProviderEnvironmentProfile::Codex,
            &nested_root,
            &root_inside_workspace.workspace,
            &nested_home,
        )
        .expect_err("a data root below the workspace must fail before mutation");
        assert_eq!(error.code(), SidecarErrorCode::InvalidProviderHome);
        assert!(!nested_home.exists());
        assert_eq!(
            fs::metadata(&nested_root)?.permissions().mode() & 0o777,
            mode_before
        );

        let workspace_inside_root = TestLayout::new()?;
        let nested_workspace = workspace_inside_root.data.join("workspace-alias");
        fs::create_dir(&nested_workspace)?;
        fs::set_permissions(&nested_workspace, fs::Permissions::from_mode(0o750))?;
        let mode_before = fs::metadata(&nested_workspace)?.permissions().mode() & 0o777;
        let nested_home = nested_workspace.join("providers").join("fixture");
        let error = ProviderHome::prepare(
            ProviderEnvironmentProfile::Codex,
            &workspace_inside_root.data,
            &nested_workspace,
            &nested_home,
        )
        .expect_err("an existing workspace prefix must fail before creating children");
        assert_eq!(error.code(), SidecarErrorCode::InvalidProviderHome);
        assert!(!nested_home.exists());
        assert_eq!(
            fs::metadata(&nested_workspace)?.permissions().mode() & 0o777,
            mode_before
        );

        let workspace_inside_home = TestLayout::new()?;
        fs::create_dir_all(&workspace_inside_home.home)?;
        fs::set_permissions(
            &workspace_inside_home.home,
            fs::Permissions::from_mode(0o750),
        )?;
        let nested_workspace = workspace_inside_home.home.join("project");
        fs::create_dir(&nested_workspace)?;
        fs::set_permissions(&nested_workspace, fs::Permissions::from_mode(0o700))?;
        let home_mode_before = fs::metadata(&workspace_inside_home.home)?
            .permissions()
            .mode()
            & 0o777;
        let error = ProviderHome::prepare(
            ProviderEnvironmentProfile::Codex,
            &workspace_inside_home.data,
            &nested_workspace,
            &workspace_inside_home.home,
        )
        .expect_err("a provider home containing the workspace must be rejected");
        assert_eq!(error.code(), SidecarErrorCode::InvalidProviderHome);
        assert_eq!(
            fs::metadata(&workspace_inside_home.home)?
                .permissions()
                .mode()
                & 0o777,
            home_mode_before,
            "containment must fail before provider-home permissions are mutated"
        );
        assert!(
            !workspace_inside_home.home.join(".carl-tmp").exists(),
            "containment must fail before provider children are created"
        );

        let unsafe_temp = TestLayout::new()?;
        fs::create_dir_all(&unsafe_temp.home)?;
        fs::set_permissions(&unsafe_temp.home, fs::Permissions::from_mode(0o750))?;
        symlink(&unsafe_temp.workspace, unsafe_temp.home.join(".carl-tmp"))?;
        let mode_before = fs::metadata(&unsafe_temp.home)?.permissions().mode() & 0o777;
        let error = ProviderHome::prepare(
            ProviderEnvironmentProfile::Codex,
            &unsafe_temp.data,
            &unsafe_temp.workspace,
            &unsafe_temp.home,
        )
        .expect_err("an unsafe temp prefix must fail before mutating its parent home");
        assert_eq!(error.code(), SidecarErrorCode::InvalidProviderHome);
        assert_eq!(
            fs::metadata(&unsafe_temp.home)?.permissions().mode() & 0o777,
            mode_before
        );

        let symlinked = TestLayout::new()?;
        let actual = symlinked.data.join("actual");
        fs::create_dir(&actual)?;
        symlink(&actual, symlinked.data.join("linked"))?;
        let mut command = fixture_command(&symlinked, "strict-jsonl", "1.2.3");
        command.isolated_home = symlinked.data.join("linked").join("provider");
        let error = run_async(spawn_fixture(command, &symlinked, short_limits()))
            .expect_err("a symlink in the provider-home path must be rejected");
        assert_eq!(error.code(), SidecarErrorCode::InvalidProviderHome);
    }

    Ok(())
}

fn child_environment_is_allowlisted() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let response = sidecar
            .request(json!({
                "id": "environment",
                "method": "environment",
            }))
            .await?;
        let environment = response["result"]
            .as_object()
            .ok_or("fixture environment result was not an object")?;
        let canonical_home = fs::canonicalize(&layout.home)?;
        let canonical_temp = fs::canonicalize(layout.home.join(".carl-tmp"))?;

        assert!(
            environment
                .get(support::FIXTURE_HOME_VARIABLE)
                .and_then(serde_json::Value::as_str)
                == canonical_home.to_str()
        );
        for forbidden in [
            "OPENAI_API_KEY",
            "TELEGRAM_BOT_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "GROK_HOME",
            "XDG_CONFIG_HOME",
            "BROWSER",
            "OPENAI_BASE_URL",
            "GROK_API_KEY",
        ] {
            assert!(
                !environment.contains_key(forbidden),
                "forbidden parent variable reached the child: {forbidden}"
            );
        }
        #[cfg(target_os = "linux")]
        for invalid_keyring_transport in ["DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"] {
            assert!(
                !environment.contains_key(invalid_keyring_transport),
                "invalid Linux keyring transport reached the child"
            );
        }
        let mut allowed = carl::sidecar::allowed_environment_variables()
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        allowed.push(support::FIXTURE_HOME_VARIABLE.to_owned());
        assert!(
            environment
                .keys()
                .all(|name| allowed.iter().any(|allowed| allowed == name)),
            "child received a variable outside the allowlist: {environment:?}"
        );
        let child_path = environment
            .get("PATH")
            .and_then(serde_json::Value::as_str)
            .ok_or("child PATH was not configured")?;
        assert!(
            env::split_paths(child_path)
                .all(|entry| entry.as_os_str() != OsStr::new(PATH_SENTINEL)),
            "the untrusted parent PATH prefix reached the child"
        );
        assert_eq!(
            environment.get("HOME").and_then(serde_json::Value::as_str),
            canonical_home.to_str()
        );
        for variable in ["TEMP", "TMP"] {
            assert_eq!(
                environment
                    .get(variable)
                    .and_then(serde_json::Value::as_str),
                canonical_temp.to_str()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&canonical_temp)?.permissions().mode() & 0o777,
                0o700
            );
        }

        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn grok_environment_profile_is_closed() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let trusted = command
            .resolve_executable()?
            .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
        let home = ProviderHome::prepare(
            ProviderEnvironmentProfile::Grok,
            &layout.data,
            &layout.workspace,
            &layout.home,
        )?;
        let sidecar = JsonlSidecar::spawn_in_home(
            command,
            &trusted,
            &home,
            NotificationPolicy::Reject,
            short_limits(),
        )
        .await?;
        let response = sidecar
            .request(json!({"id": "grok-environment", "method": "environment"}))
            .await?;
        let environment = response["result"]
            .as_object()
            .ok_or("Grok fixture environment was not an object")?;
        let canonical_home = fs::canonicalize(&layout.home)?;
        let canonical_temp = fs::canonicalize(layout.home.join(".carl-tmp"))?;
        assert_eq!(
            environment
                .get("GROK_HOME")
                .and_then(serde_json::Value::as_str),
            canonical_home.to_str()
        );
        assert_eq!(
            environment
                .get("GROK_DISABLE_AUTOUPDATER")
                .and_then(serde_json::Value::as_str),
            Some("1")
        );
        assert_eq!(
            environment.get("HOME").and_then(serde_json::Value::as_str),
            canonical_home.to_str()
        );
        for variable in ["TEMP", "TMP"] {
            assert_eq!(
                environment
                    .get(variable)
                    .and_then(serde_json::Value::as_str),
                canonical_temp.to_str()
            );
        }
        assert!(!environment.contains_key("CODEX_HOME"));
        assert!(!environment.contains_key("BROWSER"));
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn convenience_apis_honor_grok_environment_profile() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let mut command = fixture_command(&layout, "strict-jsonl", "1.8.2");
        command.version_arguments = vec![
            OsString::from(support::FIXTURE_ARGUMENT),
            OsString::from("version-grok"),
            OsString::from("1.8.2"),
            OsString::from("--no-auto-update"),
            OsString::from("version"),
        ];
        command.version_output = VersionOutputFormat::SingleSemverToken;
        let trusted = command
            .resolve_executable()?
            .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
        let sidecar = JsonlSidecar::spawn_trusted(
            command,
            &trusted,
            ProviderEnvironmentProfile::Grok,
            &layout.data,
            &layout.workspace,
            short_limits(),
        )
        .await?;
        let response = sidecar
            .request(json!({"id": "grok-convenience", "method": "environment"}))
            .await?;
        let environment = response["result"]
            .as_object()
            .ok_or("Grok convenience environment was not an object")?;
        assert!(environment.contains_key("GROK_HOME"));
        assert!(!environment.contains_key("CODEX_HOME"));
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn responses_correlate_out_of_order() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let first = sidecar.request(json!({
            "id": "first",
            "value": "slow",
            "delay_ms": 75,
        }));
        let second = sidecar.request(json!({
            "id": "second",
            "value": "fast",
            "delay_ms": 0,
        }));
        let (first, second) = tokio::join!(first, second);

        assert_eq!(first?["result"], "slow");
        assert_eq!(second?["result"], "fast");
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn abandoned_written_request_consumes_one_late_response() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = std::sync::Arc::new(spawn_fixture(command, &layout, short_limits()).await?);

        let active_sidecar = std::sync::Arc::clone(&sidecar);
        let active = tokio::spawn(async move {
            active_sidecar
                .request(json!({
                    "id": "active",
                    "method": "delay-after-received",
                    "value": "original",
                    "delay_ms": 50,
                }))
                .await
        });
        assert_eq!(
            sidecar.next_notification().await?["method"],
            "fixture/received"
        );
        let duplicate = sidecar
            .request(json!({"id": "active", "value": "duplicate"}))
            .await
            .expect_err("an active request ID must not be reused");
        assert_eq!(duplicate.code(), SidecarErrorCode::DuplicateRequestId);
        assert_eq!(active.await??["result"], "original");

        let abandoned_sidecar = std::sync::Arc::clone(&sidecar);
        let abandoned = tokio::spawn(async move {
            abandoned_sidecar
                .request(json!({
                    "id": "reusable",
                    "method": "delay-after-received-and-confirm-response",
                    "value": "late",
                    "delay_ms": 100,
                }))
                .await
        });
        let received = sidecar.next_notification().await?;
        assert_eq!(received["method"], "fixture/received");
        abandoned.abort();
        let _ = abandoned.await;

        let duplicate = sidecar
            .request(json!({"id": "reusable", "value": "too-early"}))
            .await
            .expect_err("an ambiguous request ID must not be reused");
        assert_eq!(duplicate.code(), SidecarErrorCode::DuplicateRequestId);

        let survivor = sidecar
            .request(json!({"id": "survivor", "value": "still-running"}))
            .await?;
        assert_eq!(survivor["result"], "still-running");
        let responded = tokio::time::timeout(Duration::from_secs(5), sidecar.next_notification())
            .await
            .map_err(|_| "fixture did not confirm the late response")??;
        assert_eq!(responded["method"], "fixture/responded");
        assert_eq!(responded["params"]["id"], "reusable");

        let reused = sidecar
            .request(json!({"id": "reusable", "value": "safe-now"}))
            .await?;
        assert_eq!(reused["result"], "safe-now");
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn prewrite_drop_permits_safe_id_reuse() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let never_polled = sidecar.request(json!({"id": "not-written", "value": "discard"}));
        drop(never_polled);
        let response = sidecar
            .request(json!({"id": "not-written", "value": "reused"}))
            .await?;
        assert_eq!(response["result"], "reused");
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn abandoned_request_budget_fails_safely() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = std::sync::Arc::new(spawn_fixture(command, &layout, short_limits()).await?);
        let pid = sidecar.process_id().ok_or("fixture PID was unavailable")?;

        for sequence in 1..=129_u64 {
            let request_sidecar = std::sync::Arc::clone(&sidecar);
            let request = tokio::spawn(async move {
                request_sidecar
                    .request(json!({
                        "id": format!("abandoned-{sequence}"),
                        "method": "delay-recorded",
                        "delay_ms": 30_000,
                    }))
                    .await
            });
            wait_for_received_count(&layout.home, sequence).await?;
            request.abort();
            let _ = request.await;
        }

        let error = sidecar
            .request(json!({"id": "after-budget"}))
            .await
            .expect_err("an exhausted ambiguity budget must stop the sidecar");
        assert!(matches!(
            error.code(),
            SidecarErrorCode::ProtocolViolation | SidecarErrorCode::SidecarExited
        ));
        wait_until_processes_reaped(&[pid]).await?;
        TestResult::Ok(())
    })
}

fn leader_exit_preserves_its_final_response() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "final-response-exit", "1.2.3");
        let sidecar = std::sync::Arc::new(spawn_fixture(command, &layout, short_limits()).await?);
        let pids = wait_for_fixture_pids(&layout.home).await?;
        let first_sidecar = std::sync::Arc::clone(&sidecar);
        let first = tokio::spawn(async move {
            first_sidecar
                .request(json!({"id": "last", "value": "delivered"}))
                .await
        });
        wait_for_received_count(&layout.home, 1).await?;
        let unresolved = sidecar.request(json!({"id": "unresolved", "value": false}));
        let (response, unresolved) = tokio::join!(first, unresolved);
        let response = response??;
        assert_eq!(response["result"], "delivered");
        assert_eq!(
            unresolved
                .expect_err("leader exit must fail the unresolved request")
                .code(),
            SidecarErrorCode::SidecarExited
        );
        wait_until_processes_exit(&[pids.0, pids.1]).await?;
        TestResult::Ok(())
    })
}

fn notifications_are_bounded_and_delivered() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let request = sidecar.request(json!({
            "id": 7,
            "method": "emit-notification",
            "value": "complete",
        }));
        let notification = sidecar.next_notification();
        let (response, notification) = tokio::join!(request, notification);
        assert_eq!(response?["result"], "complete");
        assert_eq!(notification?["method"], "auth/progress");
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn outbound_notifications_and_nonblocking_receive_are_bounded() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        assert_eq!(sidecar.try_next_notification().await?, None);

        sidecar.notify(json!({
            "method": "client/ready",
            "params": {"headless": true},
        }))?;
        let notification_path = layout.home.join("outbound-notification.json");
        for _ in 0..500 {
            if notification_path.is_file() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let outbound: serde_json::Value = serde_json::from_slice(&fs::read(notification_path)?)?;
        assert_eq!(outbound["method"], "client/ready");

        let response = sidecar
            .request(json!({
                "id": "buffer-one",
                "method": "emit-notification",
                "value": true,
            }))
            .await?;
        assert_eq!(response["result"], true);
        let buffered = sidecar
            .try_next_notification()
            .await?
            .ok_or("expected one buffered notification")?;
        assert_eq!(buffered["method"], "auth/progress");
        assert_eq!(sidecar.try_next_notification().await?, None);

        let error = sidecar
            .notify(json!({"method": "client/ready", "value": "x".repeat(16_384)}))
            .expect_err("oversized outbound notification must be rejected");
        assert_eq!(error.code(), SidecarErrorCode::ProtocolViolation);
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn notification_rejection_policy_fails_closed() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let trusted = command
            .resolve_executable()?
            .trust(ExecutableTrustDecision::TrustCanonicalPath)?;
        let home = ProviderHome::prepare(
            ProviderEnvironmentProfile::Codex,
            &layout.data,
            &layout.workspace,
            &layout.home,
        )?;
        let sidecar = JsonlSidecar::spawn_in_home(
            command,
            &trusted,
            &home,
            NotificationPolicy::Reject,
            short_limits(),
        )
        .await?;
        let error = sidecar
            .request(json!({
                "id": "reject-notification",
                "method": "emit-notification",
            }))
            .await
            .expect_err("a forbidden inbound notification must fail immediately");
        assert_eq!(error.code(), SidecarErrorCode::ProtocolViolation);
        TestResult::Ok(())
    })
}

fn invalid_request_ids_are_rejected() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "strict-jsonl", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        for request in [
            json!({"id": 1.5}),
            json!({"id": 18_446_744_073_709_551_615_u64}),
            json!({"id": null}),
            json!({"id": true}),
        ] {
            assert_eq!(
                sidecar.request(request).await.unwrap_err().code(),
                SidecarErrorCode::ProtocolViolation
            );
        }
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn unknown_response_ids_fail_closed() -> TestResult {
    assert_protocol_failure("unknown-id")
}

fn malformed_stdout_fails_closed() -> TestResult {
    assert_protocol_failure("malformed")
}

fn oversized_stdout_fails_closed() -> TestResult {
    assert_protocol_failure("oversized")
}

fn assert_protocol_failure(scenario: &str) -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, scenario, "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let pid = sidecar.process_id().ok_or("fixture PID was unavailable")?;
        let error = sidecar
            .request(json!({"id": "invalid-response"}))
            .await
            .expect_err("invalid sidecar stdout must fail closed");
        assert_eq!(error.code(), SidecarErrorCode::ProtocolViolation);
        wait_until_processes_reaped(&[pid]).await?;
        assert_eq!(sidecar.process_id(), Some(pid));
        Ok(())
    })
}

fn stderr_is_bounded_and_redacted() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "stderr", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        sidecar
            .request(json!({"id": "stderr", "value": true}))
            .await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let stderr = sidecar.stderr_snapshot();
        assert!(stderr.len() <= short_limits().max_stderr_bytes);
        assert!(!stderr.contains(SECRET_SENTINEL));
        assert!(stderr.contains("redacted"));
        sidecar.cancel().await?;
        TestResult::Ok(())
    })
}

fn child_exit_wakes_every_pending_request() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "exit-with-pending", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let (first, second) = tokio::join!(
            sidecar.request(json!({"id": "first"})),
            sidecar.request(json!({"id": "second"})),
        );
        for result in [first, second] {
            let error = result.expect_err("child exit must wake each pending request");
            assert_eq!(error.code(), SidecarErrorCode::SidecarExited);
            assert!(!format!("{error:?}").contains("23"));
        }
        TestResult::Ok(())
    })
}

fn explicit_cancellation_removes_process_group() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "grandchild", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let pids = wait_for_fixture_pids(&layout.home).await?;
        assert_eq!(sidecar.process_id(), Some(pids.0));

        sidecar.cancel().await?;
        #[cfg(windows)]
        assert!(
            processes_have_exited(&[pids.0, pids.1]),
            "Windows cancellation returned before its Job Object became empty"
        );
        wait_until_processes_exit(&[pids.0, pids.1]).await?;
        assert_owner_only_pid_file(&layout.home)?;
        TestResult::Ok(())
    })
}

fn cancellation_cannot_deadlock_on_full_stdin() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "blocked-stdin", "1.2.3");
        let sidecar = std::sync::Arc::new(spawn_fixture(command, &layout, short_limits()).await?);
        let mut requests = Vec::new();
        for id in 0..128_i64 {
            let sidecar = std::sync::Arc::clone(&sidecar);
            requests.push(tokio::spawn(async move {
                sidecar
                    .request(json!({"id": id, "value": "x".repeat(7_000)}))
                    .await
            }));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        tokio::time::timeout(Duration::from_secs(3), sidecar.cancel())
            .await
            .map_err(|_| "cancel deadlocked behind the full sidecar stdin pipe")??;
        for request in requests {
            let error = request
                .await?
                .expect_err("pending blocked writes must be failed on cancellation");
            assert!(matches!(
                error.code(),
                SidecarErrorCode::Cancelled | SidecarErrorCode::SidecarExited
            ));
        }
        TestResult::Ok(())
    })
}

fn leader_exit_removes_ordinary_descendants() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "grandchild-exit", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let pids = wait_for_fixture_pids(&layout.home).await?;
        wait_until_processes_exit(&[pids.0, pids.1]).await?;
        drop(sidecar);
        TestResult::Ok(())
    })
}

fn dropping_supervisor_removes_process_group() -> TestResult {
    run_async(async {
        let layout = TestLayout::new()?;
        let command = fixture_command(&layout, "grandchild", "1.2.3");
        let sidecar = spawn_fixture(command, &layout, short_limits()).await?;
        let pids = wait_for_fixture_pids(&layout.home).await?;
        drop(sidecar);
        wait_until_processes_exit(&[pids.0, pids.1]).await?;
        TestResult::Ok(())
    })
}

fn assert_owner_only_pid_file(home: &std::path::Path) -> TestResult {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(home.join("fixture-pids.json"))?
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    #[cfg(windows)]
    let _ = home;
    Ok(())
}
