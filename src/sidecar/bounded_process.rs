use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use super::{
    ExecutionWorkspace, SidecarError, SidecarErrorCode, SidecarProcessGuard, TrustedExecutable,
    force_kill_and_reap, lock, set_owner_only_child_umask, spawn_trusted_grouped,
    terminate_process,
};

const MAX_EXECUTION_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_ENVIRONMENT_ENTRIES: usize = 64;
const MAX_ENVIRONMENT_BYTES: usize = 64 * 1024;
const MAX_STDIN_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BoundedProcessLimits {
    execution_timeout: Duration,
    max_output_bytes: usize,
    graceful_shutdown_timeout: Duration,
    forced_shutdown_timeout: Duration,
    poll_interval: Duration,
}

impl BoundedProcessLimits {
    pub(crate) fn new(
        execution_timeout: Duration,
        max_output_bytes: usize,
        graceful_shutdown_timeout: Duration,
        forced_shutdown_timeout: Duration,
        poll_interval: Duration,
    ) -> Result<Self, SidecarError> {
        if execution_timeout.is_zero()
            || execution_timeout > MAX_EXECUTION_TIMEOUT
            || max_output_bytes == 0
            || max_output_bytes > MAX_OUTPUT_BYTES
            || graceful_shutdown_timeout.is_zero()
            || graceful_shutdown_timeout > MAX_SHUTDOWN_TIMEOUT
            || forced_shutdown_timeout.is_zero()
            || forced_shutdown_timeout > MAX_SHUTDOWN_TIMEOUT
            || poll_interval.is_zero()
            || poll_interval > MAX_POLL_INTERVAL
            || poll_interval > graceful_shutdown_timeout
            || poll_interval > forced_shutdown_timeout
        {
            return Err(invalid_configuration());
        }
        Ok(Self {
            execution_timeout,
            max_output_bytes,
            graceful_shutdown_timeout,
            forced_shutdown_timeout,
            poll_interval,
        })
    }

    #[cfg(test)]
    const fn execution_timeout(self) -> Duration {
        self.execution_timeout
    }

    #[cfg(test)]
    const fn max_output_bytes(self) -> usize {
        self.max_output_bytes
    }

    pub(crate) const fn graceful_shutdown_timeout(self) -> Duration {
        self.graceful_shutdown_timeout
    }

    pub(crate) const fn forced_shutdown_timeout(self) -> Duration {
        self.forced_shutdown_timeout
    }

    pub(crate) const fn poll_interval(self) -> Duration {
        self.poll_interval
    }
}

pub(crate) struct ClosedEnvironment {
    entries: Vec<(OsString, OsString)>,
}

impl ClosedEnvironment {
    pub(crate) fn new(entries: Vec<(OsString, OsString)>) -> Result<Self, SidecarError> {
        if entries.len() > MAX_ENVIRONMENT_ENTRIES {
            return Err(invalid_configuration());
        }
        let mut names = HashSet::with_capacity(entries.len());
        let mut encoded_bytes = 0_usize;
        for (name, value) in &entries {
            let Some(name_text) = name.to_str() else {
                return Err(invalid_configuration());
            };
            if name_text.is_empty() || name_text.contains(['=', '\0']) || os_str_has_nul(value) {
                return Err(invalid_configuration());
            }
            #[cfg(windows)]
            let normalized_name = name_text.to_uppercase();
            #[cfg(not(windows))]
            let normalized_name = name_text.to_owned();
            if !names.insert(normalized_name) {
                return Err(invalid_configuration());
            }
            encoded_bytes = encoded_bytes
                .checked_add(os_str_encoded_bytes(name))
                .and_then(|bytes| bytes.checked_add(os_str_encoded_bytes(value)))
                .and_then(|bytes| bytes.checked_add(environment_entry_overhead()))
                .ok_or_else(invalid_configuration)?;
            if encoded_bytes > MAX_ENVIRONMENT_BYTES {
                return Err(invalid_configuration());
            }
        }
        Ok(Self { entries })
    }

    fn configure_command(&self, command: &mut tokio::process::Command) {
        command
            .env_clear()
            .envs(self.entries.iter().map(|(name, value)| (name, value)));
    }
}

impl fmt::Debug for ClosedEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClosedEnvironment")
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

#[derive(Debug)]
pub(crate) enum BoundedProcessOutcome {
    Exited(ExitStatus),
    TimedOut,
    Cancelled,
    OutputLimitExceeded,
}

pub(crate) struct BoundedProcessResult {
    outcome: BoundedProcessOutcome,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    duration: Duration,
}

impl BoundedProcessResult {
    pub(crate) const fn outcome(&self) -> &BoundedProcessOutcome {
        &self.outcome
    }

    pub(crate) fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub(crate) fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub(crate) const fn duration(&self) -> Duration {
        self.duration
    }
}

impl fmt::Debug for BoundedProcessResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedProcessResult")
            .field("outcome", &self.outcome)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .field("duration", &self.duration)
            .finish()
    }
}

pub(crate) async fn run_bounded_process(
    executable: &TrustedExecutable,
    arguments: &[OsString],
    environment: &ClosedEnvironment,
    cwd: &ExecutionWorkspace,
    limits: BoundedProcessLimits,
    cancellation: CancellationToken,
) -> Result<BoundedProcessResult, SidecarError> {
    run_bounded_process_inner(
        executable,
        arguments,
        environment,
        cwd,
        limits,
        cancellation,
        None,
    )
    .await
}

pub(crate) async fn run_bounded_process_with_stdin(
    executable: &TrustedExecutable,
    arguments: &[OsString],
    environment: &ClosedEnvironment,
    cwd: &ExecutionWorkspace,
    limits: BoundedProcessLimits,
    cancellation: CancellationToken,
    stdin: &[u8],
) -> Result<BoundedProcessResult, SidecarError> {
    if stdin.len() > MAX_STDIN_BYTES {
        return Err(invalid_configuration());
    }
    run_bounded_process_inner(
        executable,
        arguments,
        environment,
        cwd,
        limits,
        cancellation,
        Some(stdin.to_vec()),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_bounded_process_inner(
    executable: &TrustedExecutable,
    arguments: &[OsString],
    environment: &ClosedEnvironment,
    cwd: &ExecutionWorkspace,
    limits: BoundedProcessLimits,
    cancellation: CancellationToken,
    stdin: Option<Vec<u8>>,
) -> Result<BoundedProcessResult, SidecarError> {
    if cancellation.is_cancelled() {
        return Ok(BoundedProcessResult {
            outcome: BoundedProcessOutcome::Cancelled,
            stdout: Vec::new(),
            stderr: Vec::new(),
            duration: Duration::ZERO,
        });
    }
    cwd.revalidate()?;
    let executable_attestation = executable.verification_attestation()?;

    let mut command = Command::new(executable.canonical_path());
    command
        .args(arguments)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    environment.configure_command(&mut command);
    cwd.configure_command(&mut command)?;
    set_owner_only_child_umask(&mut command);

    cwd.revalidate()?;
    executable.revalidate_verification_attestation(&executable_attestation)?;
    if cancellation.is_cancelled() {
        return Ok(BoundedProcessResult {
            outcome: BoundedProcessOutcome::Cancelled,
            stdout: Vec::new(),
            stderr: Vec::new(),
            duration: Duration::ZERO,
        });
    }
    let supervision_started = Instant::now();
    let mut child = spawn_trusted_grouped(executable, command)?;
    let stdout = child
        .stdout()
        .take()
        .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::SpawnFailed))?;
    let stderr = child
        .stderr()
        .take()
        .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::SpawnFailed))?;
    let mut stdin_task = match stdin {
        Some(input) => {
            let mut pipe = child
                .stdin()
                .take()
                .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::SpawnFailed))?;
            Some(tokio::spawn(async move {
                pipe.write_all(&input).await?;
                pipe.shutdown().await
            }))
        }
        None => None,
    };
    let process = Arc::new(Mutex::new(SidecarProcessGuard::new(child)));
    let mut cleanup = ProcessCleanupGuard::new(Arc::clone(&process), limits);
    let budget = Arc::new(Mutex::new(OutputBudget {
        used: 0,
        maximum: limits.max_output_bytes,
    }));
    let output_limit = CancellationToken::new();
    let mut stdout_task = tokio::spawn(capture_output(
        stdout,
        Arc::clone(&budget),
        output_limit.clone(),
    ));
    let mut stderr_task = tokio::spawn(capture_output(stderr, budget, output_limit.clone()));
    let mut execution_timeout = Box::pin(tokio::time::sleep(limits.execution_timeout));

    let mut outcome = loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                terminate_process(&process, limits).await?;
                break BoundedProcessOutcome::Cancelled;
            }
            () = output_limit.cancelled() => {
                terminate_process(&process, limits).await?;
                break BoundedProcessOutcome::OutputLimitExceeded;
            }
            () = &mut execution_timeout => {
                terminate_process(&process, limits).await?;
                break BoundedProcessOutcome::TimedOut;
            }
            () = tokio::time::sleep(limits.poll_interval) => {
                let status = {
                    let mut process = lock(&process);
                    match process.try_wait() {
                        Ok(Some(status)) => Some(Ok(status)),
                        Ok(None) => None,
                        Err(()) => Some(Err(SidecarError::from_code(
                            SidecarErrorCode::SpawnFailed,
                        ))),
                    }
                };
                match status {
                    Some(Ok(status)) => {
                        force_kill_and_reap(&process, limits).await?;
                        break BoundedProcessOutcome::Exited(status);
                    }
                    Some(Err(error)) => {
                        let _ = force_kill_and_reap(&process, limits).await;
                        return Err(error);
                    }
                    None => {}
                }
            }
        }
    };

    let captured = tokio::time::timeout(limits.forced_shutdown_timeout, async {
        tokio::try_join!(&mut stdout_task, &mut stderr_task)
    })
    .await;
    let (stdout, stderr) = match captured {
        Ok(Ok((stdout, stderr))) => (stdout?, stderr?),
        Ok(Err(_)) => {
            return Err(SidecarError::from_code(SidecarErrorCode::SpawnFailed));
        }
        Err(_) => {
            stdout_task.abort();
            stderr_task.abort();
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            return Err(SidecarError::from_code(SidecarErrorCode::TimedOut));
        }
    };
    let duration = supervision_started.elapsed();

    let stdin_result = match stdin_task.as_mut() {
        Some(task) => tokio::time::timeout(limits.forced_shutdown_timeout, task).await,
        None => Ok(Ok(Ok(()))),
    };
    if matches!(&outcome, BoundedProcessOutcome::Exited(status) if status.success())
        && !matches!(stdin_result, Ok(Ok(Ok(()))))
    {
        return Err(SidecarError::from_code(SidecarErrorCode::SpawnFailed));
    }

    if matches!(outcome, BoundedProcessOutcome::Exited(_)) && output_limit.is_cancelled() {
        outcome = BoundedProcessOutcome::OutputLimitExceeded;
    }
    cleanup.disarm();
    cwd.revalidate()?;
    executable.revalidate_verification_attestation(&executable_attestation)?;
    Ok(BoundedProcessResult {
        outcome,
        stdout,
        stderr,
        duration,
    })
}

struct OutputBudget {
    used: usize,
    maximum: usize,
}

struct ProcessCleanupGuard {
    process: Option<Arc<Mutex<SidecarProcessGuard>>>,
    limits: BoundedProcessLimits,
}

impl ProcessCleanupGuard {
    fn new(
        process: Arc<Mutex<SidecarProcessGuard>>,
        limits: BoundedProcessLimits,
    ) -> ProcessCleanupGuard {
        Self {
            process: Some(process),
            limits,
        }
    }

    fn disarm(&mut self) {
        self.process = None;
    }
}

impl Drop for ProcessCleanupGuard {
    fn drop(&mut self) {
        let Some(process) = self.process.take() else {
            return;
        };
        lock(&process).start_kill();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let limits = self.limits;
            drop(runtime.spawn(async move {
                let _ = force_kill_and_reap(&process, limits).await;
            }));
        }
    }
}

async fn capture_output(
    mut reader: impl AsyncRead + Unpin,
    budget: Arc<Mutex<OutputBudget>>,
    output_limit: CancellationToken,
) -> Result<Vec<u8>, SidecarError> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4 * 1_024];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(0) => return Ok(output),
            Ok(read) => read,
            Err(_) => {
                output_limit.cancel();
                return Err(SidecarError::from_code(SidecarErrorCode::SpawnFailed));
            }
        };
        let (accepted, exceeded) = {
            let mut budget = lock(&budget);
            let remaining = budget.maximum.saturating_sub(budget.used);
            let accepted = remaining.min(read);
            budget.used = budget.used.saturating_add(accepted);
            (accepted, accepted != read)
        };
        output.extend_from_slice(&buffer[..accepted]);
        if exceeded {
            output_limit.cancel();
            return Ok(output);
        }
    }
}

#[cfg(unix)]
fn os_str_encoded_bytes(value: &OsStr) -> usize {
    use std::os::unix::ffi::OsStrExt;

    value.as_bytes().len()
}

#[cfg(windows)]
fn os_str_encoded_bytes(value: &OsStr) -> usize {
    use std::os::windows::ffi::OsStrExt;

    value.encode_wide().count().saturating_mul(2)
}

#[cfg(unix)]
fn os_str_has_nul(value: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;

    value.as_bytes().contains(&0)
}

#[cfg(windows)]
fn os_str_has_nul(value: &OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;

    value.encode_wide().any(|unit| unit == 0)
}

#[cfg(unix)]
const fn environment_entry_overhead() -> usize {
    2
}

#[cfg(windows)]
const fn environment_entry_overhead() -> usize {
    4
}

const fn invalid_configuration() -> SidecarError {
    SidecarError::from_code(SidecarErrorCode::InvalidConfiguration)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    #[cfg(unix)]
    use std::fs::{File, OpenOptions};
    #[cfg(unix)]
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use super::{
        BoundedProcessLimits, ClosedEnvironment, MAX_ENVIRONMENT_BYTES, MAX_ENVIRONMENT_ENTRIES,
        MAX_OUTPUT_BYTES, OutputBudget, capture_output,
    };
    #[cfg(unix)]
    use super::{BoundedProcessOutcome, run_bounded_process};
    use crate::sidecar::SidecarErrorCode;
    #[cfg(windows)]
    use crate::sidecar::{ExecutableTrustDecision, ResolvedExecutable};
    #[cfg(unix)]
    use crate::sidecar::{
        ExecutionWorkspace, MAX_VERIFICATION_EXECUTABLE_BYTES, TrustedExecutable,
    };
    use tokio::io::{AsyncRead, ReadBuf};
    use tokio_util::sync::CancellationToken;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    fn limits() -> BoundedProcessLimits {
        BoundedProcessLimits::new(
            Duration::from_secs(1),
            4 * 1_024,
            Duration::from_millis(100),
            Duration::from_secs(1),
            Duration::from_millis(10),
        )
        .expect("the test limits are valid")
    }

    #[test]
    fn bounded_process_limits_reject_unbounded_values() {
        for invalid in [
            BoundedProcessLimits::new(
                Duration::ZERO,
                1,
                Duration::from_millis(1),
                Duration::from_millis(1),
                Duration::from_millis(1),
            ),
            BoundedProcessLimits::new(
                Duration::from_secs(1),
                MAX_OUTPUT_BYTES + 1,
                Duration::from_millis(1),
                Duration::from_millis(1),
                Duration::from_millis(1),
            ),
            BoundedProcessLimits::new(
                Duration::from_secs(1),
                1,
                Duration::ZERO,
                Duration::from_millis(1),
                Duration::from_millis(1),
            ),
            BoundedProcessLimits::new(
                Duration::from_secs(1),
                1,
                Duration::from_millis(1),
                Duration::ZERO,
                Duration::from_millis(1),
            ),
            BoundedProcessLimits::new(
                Duration::from_secs(1),
                1,
                Duration::from_millis(10),
                Duration::from_millis(10),
                Duration::from_millis(11),
            ),
        ] {
            assert_eq!(
                invalid
                    .expect_err("unbounded process limits must fail")
                    .code(),
                SidecarErrorCode::InvalidConfiguration
            );
        }

        let valid = limits();
        assert_eq!(valid.execution_timeout(), Duration::from_secs(1));
        assert_eq!(valid.max_output_bytes(), 4 * 1_024);
        assert_eq!(
            valid.graceful_shutdown_timeout(),
            Duration::from_millis(100)
        );
        assert_eq!(valid.forced_shutdown_timeout(), Duration::from_secs(1));
        assert_eq!(valid.poll_interval(), Duration::from_millis(10));
    }

    #[test]
    fn closed_environment_rejects_invalid_and_duplicate_names() {
        for entries in [
            vec![(OsString::new(), OsString::from("value"))],
            vec![(OsString::from("BAD=NAME"), OsString::from("value"))],
            vec![(OsString::from("BAD\0NAME"), OsString::from("value"))],
            vec![(OsString::from("GOOD"), OsString::from("bad\0value"))],
            vec![
                (OsString::from("DUPLICATE"), OsString::from("first")),
                (OsString::from("DUPLICATE"), OsString::from("second")),
            ],
        ] {
            assert_eq!(
                ClosedEnvironment::new(entries)
                    .expect_err("invalid environment entries must fail")
                    .code(),
                SidecarErrorCode::InvalidConfiguration
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn closed_environment_rejects_case_insensitive_windows_duplicates() {
        let error = ClosedEnvironment::new(vec![
            (OsString::from("Path"), OsString::from("first")),
            (OsString::from("PATH"), OsString::from("second")),
        ])
        .expect_err("Windows environment names are case-insensitive");
        assert_eq!(error.code(), SidecarErrorCode::InvalidConfiguration);
    }

    #[test]
    fn closed_environment_bounds_entries_and_encoded_bytes() {
        let too_many = (0..=MAX_ENVIRONMENT_ENTRIES)
            .map(|index| {
                (
                    OsString::from(format!("CARL_TEST_{index}")),
                    OsString::from("x"),
                )
            })
            .collect();
        assert_eq!(
            ClosedEnvironment::new(too_many)
                .expect_err("too many environment entries must fail")
                .code(),
            SidecarErrorCode::InvalidConfiguration
        );

        let oversized = vec![(
            OsString::from("CARL_TEST"),
            OsString::from("x".repeat(MAX_ENVIRONMENT_BYTES)),
        )];
        assert_eq!(
            ClosedEnvironment::new(oversized)
                .expect_err("oversized environment values must fail")
                .code(),
            SidecarErrorCode::InvalidConfiguration
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_attestation_rejects_a_shebang_script() {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("fixture directory is private");
        let executable_path = directory.join("fixture-script");
        fs::write(&executable_path, b"#!/bin/sh\nexit 0\n").expect("fixture script is written");
        fs::set_permissions(&executable_path, fs::Permissions::from_mode(0o700))
            .expect("fixture script is private");
        let executable = TrustedExecutable::for_test(executable_path);

        let error = executable
            .verification_attestation()
            .expect_err("a script interpreter must not cross the exact executable boundary");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);

        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    #[cfg(unix)]
    #[test]
    fn executable_attestation_detects_in_place_content_change() {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("fixture directory is private");
        let executable_path = directory.join("fixture-executable");
        fs::copy(
            std::env::current_exe().expect("test executable has a path"),
            &executable_path,
        )
        .expect("fixture executable is copied");
        fs::set_permissions(&executable_path, fs::Permissions::from_mode(0o700))
            .expect("fixture executable is private");
        let executable = TrustedExecutable::for_test(executable_path.clone());

        let attestation = executable
            .verification_attestation()
            .expect("the executable can be attested");
        assert_eq!(
            attestation.canonical_path(),
            executable_path
                .canonicalize()
                .expect("fixture path is canonical")
                .to_str()
                .expect("fixture path is UTF-8")
        );
        assert!(attestation.byte_len() > 0);
        assert_ne!(attestation.content_sha256(), [0_u8; 32]);
        assert!(!attestation.platform_identity_evidence().is_empty());

        let mut changed = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&executable_path)
            .expect("fixture executable opens");
        let mut first = [0_u8; 1];
        changed
            .read_exact(&mut first)
            .expect("fixture executable has one byte");
        changed
            .seek(SeekFrom::Start(0))
            .expect("fixture executable seeks");
        changed
            .write_all(&[first[0].wrapping_add(1)])
            .expect("fixture executable changes in place without changing length");
        changed
            .sync_all()
            .expect("fixture content change is durable");
        let error = executable
            .revalidate_verification_attestation(&attestation)
            .expect_err("an in-place content change must invalidate the attestation");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);

        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    #[cfg(unix)]
    #[test]
    fn executable_attestation_rejects_an_empty_executable() {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("fixture directory is private");
        let executable_path = directory.join("empty-executable");
        File::create(&executable_path).expect("fixture executable is created");
        fs::set_permissions(&executable_path, fs::Permissions::from_mode(0o700))
            .expect("fixture executable is private");
        let executable = TrustedExecutable::for_test(executable_path);

        let error = executable
            .verification_attestation()
            .expect_err("an empty executable must not be hashed or attested");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);

        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    #[cfg(unix)]
    #[test]
    fn executable_attestation_rejects_an_oversized_executable() {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("fixture directory is private");
        let executable_path = directory.join("oversized-executable");
        let file = File::create(&executable_path).expect("fixture executable is created");
        file.set_len(MAX_VERIFICATION_EXECUTABLE_BYTES + 1)
            .expect("fixture executable is a sparse oversized file");
        fs::set_permissions(&executable_path, fs::Permissions::from_mode(0o700))
            .expect("fixture executable is private");
        let executable = TrustedExecutable::for_test(executable_path);

        let error = executable
            .verification_attestation()
            .expect_err("an oversized executable must be rejected before hashing");
        assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);

        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    #[cfg(windows)]
    #[test]
    fn executable_attestation_rejects_windows_batch_files() {
        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        for extension in ["bat", "cmd"] {
            let executable_path = directory.join(format!("fixture.{extension}"));
            fs::copy(
                std::env::current_exe().expect("test executable has a path"),
                &executable_path,
            )
            .expect("fixture executable is copied");
            let executable = ResolvedExecutable::resolve(&executable_path)
                .expect("fixture executable resolves")
                .trust(ExecutableTrustDecision::TrustCanonicalPath)
                .expect("fixture executable is explicitly trusted");

            let error = executable
                .verification_attestation()
                .expect_err("a batch executable must not cross the exact-argv boundary");
            assert_eq!(error.code(), SidecarErrorCode::UnsafeExecutable);
        }

        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn run_uses_exact_arguments_and_a_closed_environment() {
        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        let executable = TrustedExecutable::for_test(PathBuf::from("/bin/sh"));
        let workspace =
            ExecutionWorkspace::open(&directory).expect("fixture workspace is retained");
        let literal_argument = "private; touch should-not-run";
        let arguments = [
            OsString::from("-c"),
            OsString::from(
                "printf '%s\\n' \"$1\"; printf '%s\\n' \"$CARL_TEST_VALUE\"; \
                 printf '%s\\n' \"${HOME-unset}\"",
            ),
            OsString::from("carl-bounded-fixture"),
            OsString::from(literal_argument),
        ];
        let environment = ClosedEnvironment::new(vec![(
            OsString::from("CARL_TEST_VALUE"),
            OsString::from("explicit"),
        )])
        .expect("fixture environment is valid");

        let result = run_bounded_process(
            &executable,
            &arguments,
            &environment,
            &workspace,
            limits(),
            CancellationToken::new(),
        )
        .await
        .expect("bounded process succeeds");

        assert!(matches!(
            result.outcome(),
            BoundedProcessOutcome::Exited(status) if status.success()
        ));
        assert_eq!(
            result.stdout(),
            b"private; touch should-not-run\nexplicit\nunset\n"
        );
        assert!(result.stderr().is_empty());
        assert!(!directory.join("should-not-run").exists());
        assert!(!format!("{result:?}").contains(literal_argument));

        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn output_capture_propagates_pipe_read_failures() {
        let error = capture_output(
            FailingReader,
            Arc::new(Mutex::new(OutputBudget {
                used: 0,
                maximum: 128,
            })),
            CancellationToken::new(),
        )
        .await
        .expect_err("a pipe read failure must not look like clean EOF");
        assert_eq!(error.code(), SidecarErrorCode::SpawnFailed);
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_pre_cancelled_run_never_spawns_the_executable() {
        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        let workspace =
            ExecutionWorkspace::open(&directory).expect("fixture workspace is retained");
        let executable = TrustedExecutable::for_test(PathBuf::from("/bin/sh"));
        let arguments = [OsString::from("-c"), OsString::from("touch spawned-marker")];
        let environment = ClosedEnvironment::new(Vec::new()).expect("empty environment is valid");
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let result = run_bounded_process(
            &executable,
            &arguments,
            &environment,
            &workspace,
            limits(),
            cancellation,
        )
        .await
        .expect("pre-cancellation is an ordinary outcome");

        assert!(matches!(result.outcome(), BoundedProcessOutcome::Cancelled));
        assert_eq!(result.duration(), Duration::ZERO);
        assert!(!directory.join("spawned-marker").exists());
        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn aggregate_output_overflow_cannot_report_success() {
        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        let workspace =
            ExecutionWorkspace::open(&directory).expect("fixture workspace is retained");
        let executable = TrustedExecutable::for_test(PathBuf::from("/bin/sh"));
        let arguments = [
            OsString::from("-c"),
            OsString::from("printf '123456'; printf 'abcdef' >&2"),
        ];
        let environment = ClosedEnvironment::new(Vec::new()).expect("empty environment is valid");
        let limits = BoundedProcessLimits::new(
            Duration::from_secs(1),
            8,
            Duration::from_millis(50),
            Duration::from_secs(1),
            Duration::from_millis(1),
        )
        .expect("test limits are valid");

        let result = run_bounded_process(
            &executable,
            &arguments,
            &environment,
            &workspace,
            limits,
            CancellationToken::new(),
        )
        .await
        .expect("output overflow is an ordinary outcome");

        assert!(matches!(
            result.outcome(),
            BoundedProcessOutcome::OutputLimitExceeded
        ));
        assert!(result.stdout().len() + result.stderr().len() <= 8);
        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn run_uses_the_held_working_directory() {
        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        let workspace =
            ExecutionWorkspace::open(&directory).expect("fixture workspace is retained");
        let executable = TrustedExecutable::for_test(PathBuf::from("/bin/sh"));
        let arguments = [OsString::from("-c"), OsString::from("pwd -P")];
        let environment = ClosedEnvironment::new(Vec::new()).expect("empty environment is valid");

        let result = run_bounded_process(
            &executable,
            &arguments,
            &environment,
            &workspace,
            limits(),
            CancellationToken::new(),
        )
        .await
        .expect("bounded process succeeds");

        let expected = format!(
            "{}\n",
            directory
                .canonicalize()
                .expect("fixture directory is canonical")
                .display()
        );
        assert_eq!(result.stdout(), expected.as_bytes());
        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn nonzero_exit_is_preserved_as_an_ordinary_outcome() {
        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        let workspace =
            ExecutionWorkspace::open(&directory).expect("fixture workspace is retained");
        let executable = TrustedExecutable::for_test(PathBuf::from("/bin/sh"));
        let arguments = [OsString::from("-c"), OsString::from("exit 17")];
        let environment = ClosedEnvironment::new(Vec::new()).expect("empty environment is valid");

        let result = run_bounded_process(
            &executable,
            &arguments,
            &environment,
            &workspace,
            limits(),
            CancellationToken::new(),
        )
        .await
        .expect("nonzero exit remains process evidence");

        assert!(matches!(
            result.outcome(),
            BoundedProcessOutcome::Exited(status) if status.code() == Some(17)
        ));
        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn timeout_reaps_the_leader_and_ordinary_descendants() {
        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        let workspace =
            ExecutionWorkspace::open(&directory).expect("fixture workspace is retained");
        let executable = TrustedExecutable::for_test(PathBuf::from("/bin/sh"));
        let arguments = [
            OsString::from("-c"),
            OsString::from(
                "printf '%s' \"$$\" > leader.pid; sleep 30 & \
                 printf '%s' \"$!\" > child.pid; wait",
            ),
        ];
        let environment = ClosedEnvironment::new(Vec::new()).expect("empty environment is valid");
        let limits = BoundedProcessLimits::new(
            Duration::from_millis(50),
            128,
            Duration::from_millis(50),
            Duration::from_secs(1),
            Duration::from_millis(5),
        )
        .expect("test limits are valid");

        let outer_started = std::time::Instant::now();
        let result = run_bounded_process(
            &executable,
            &arguments,
            &environment,
            &workspace,
            limits,
            CancellationToken::new(),
        )
        .await
        .expect("timeout is an ordinary outcome");
        let outer_duration = outer_started.elapsed();
        let leader = read_pid_file(directory.join("leader.pid"));
        let child = read_pid_file(directory.join("child.pid"));

        assert!(matches!(result.outcome(), BoundedProcessOutcome::TimedOut));
        assert!(
            result.duration() >= limits.execution_timeout(),
            "the supervised duration includes the execution timeout"
        );
        assert!(
            result.duration() <= outer_duration,
            "pre-spawn and post-supervision work is excluded"
        );
        wait_until_processes_are_absent(&[leader, child]).await;
        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_reaps_the_leader_and_ordinary_descendants() {
        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        let workspace =
            ExecutionWorkspace::open(&directory).expect("fixture workspace is retained");
        let executable = TrustedExecutable::for_test(PathBuf::from("/bin/sh"));
        let arguments = [
            OsString::from("-c"),
            OsString::from(
                "printf '%s' \"$$\" > leader.pid; sleep 30 & \
                 printf '%s' \"$!\" > child.pid; wait",
            ),
        ];
        let environment = ClosedEnvironment::new(Vec::new()).expect("empty environment is valid");
        let cancellation = CancellationToken::new();
        let cancel = cancellation.clone();
        let child_pid_path = directory.join("child.pid");
        let canceller = tokio::spawn(async move {
            let _ = wait_for_pid_file(child_pid_path).await;
            cancel.cancel();
        });

        let result = run_bounded_process(
            &executable,
            &arguments,
            &environment,
            &workspace,
            limits(),
            cancellation,
        )
        .await
        .expect("cancellation is an ordinary outcome");
        canceller.await.expect("canceller task completes");
        let leader = read_pid_file(directory.join("leader.pid"));
        let child = read_pid_file(directory.join("child.pid"));

        assert!(matches!(result.outcome(), BoundedProcessOutcome::Cancelled));
        wait_until_processes_are_absent(&[leader, child]).await;
        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn leader_exit_terminates_an_ordinary_descendant() {
        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        let workspace =
            ExecutionWorkspace::open(&directory).expect("fixture workspace is retained");
        let executable = TrustedExecutable::for_test(PathBuf::from("/bin/sh"));
        let arguments = [
            OsString::from("-c"),
            OsString::from("sleep 30 & printf '%s' \"$!\" > child.pid; exit 0"),
        ];
        let environment = ClosedEnvironment::new(Vec::new()).expect("empty environment is valid");

        let result = run_bounded_process(
            &executable,
            &arguments,
            &environment,
            &workspace,
            limits(),
            CancellationToken::new(),
        )
        .await
        .expect("leader exit is supervised");
        let child = read_pid_file(directory.join("child.pid"));

        assert!(matches!(
            result.outcome(),
            BoundedProcessOutcome::Exited(status) if status.success()
        ));
        wait_until_processes_are_absent(&[child]).await;
        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn aborting_the_run_future_still_reaps_its_process_group() {
        let directory = private_fixture_directory();
        fs::create_dir_all(&directory).expect("fixture directory is created");
        let workspace =
            ExecutionWorkspace::open(&directory).expect("fixture workspace is retained");
        let executable = TrustedExecutable::for_test(PathBuf::from("/bin/sh"));
        let arguments = [
            OsString::from("-c"),
            OsString::from(
                "printf '%s' \"$$\" > leader.pid; sleep 30 & \
                 printf '%s' \"$!\" > child.pid; wait",
            ),
        ];
        let environment = ClosedEnvironment::new(Vec::new()).expect("empty environment is valid");
        let task = tokio::spawn(async move {
            run_bounded_process(
                &executable,
                &arguments,
                &environment,
                &workspace,
                limits(),
                CancellationToken::new(),
            )
            .await
        });
        let leader = wait_for_pid_file(directory.join("leader.pid")).await;
        let child = wait_for_pid_file(directory.join("child.pid")).await;

        task.abort();
        let aborted = task.await.expect_err("the run task is aborted");
        assert!(aborted.is_cancelled());
        wait_until_processes_are_absent(&[leader, child]).await;

        fs::remove_dir_all(directory).expect("fixture directory is removed");
    }

    struct FailingReader;

    impl AsyncRead for FailingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::other("fixture read failure")))
        }
    }

    #[cfg(unix)]
    async fn wait_for_pid_file(path: PathBuf) -> u32 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(contents) = fs::read_to_string(&path)
                && let Ok(pid) = contents.parse()
            {
                return pid;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "fixture PID file was not created: {}",
                path.display()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[cfg(unix)]
    fn read_pid_file(path: PathBuf) -> u32 {
        fs::read_to_string(&path)
            .expect("fixture PID file exists")
            .parse()
            .expect("fixture PID is valid")
    }

    #[cfg(unix)]
    async fn wait_until_processes_are_absent(pids: &[u32]) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let all_absent = pids.iter().all(|pid| {
                let Ok(pid) = i32::try_from(*pid) else {
                    return true;
                };
                // SAFETY: signal zero performs only a process-existence query.
                (unsafe { libc::kill(pid, 0) }) != 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM)
            });
            if all_absent {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "fixture processes were not reaped: {pids:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn private_fixture_directory() -> PathBuf {
        std::env::current_exe()
            .expect("test executable has a path")
            .parent()
            .expect("test executable has a parent")
            .join("bounded-process-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ))
    }
}
