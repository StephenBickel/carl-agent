//! Version-pinned, bounded JSONL sidecars with isolated provider homes.
//!
//! On Unix, Carl owns a POSIX process group and terminates ordinary descendants in
//! that group. A hostile descendant can escape by calling `setsid` or moving to a
//! different process group: this is not a cgroup or equivalent process-tree
//! containment. Authentication sidecars are trusted, version-pinned provider
//! executables. Later delegate execution needs stronger OS containment for detached
//! descendants.
//!
//! Unix provider-home creation walks from an already-open Carl data-root directory
//! using `openat`/`mkdirat` and `O_NOFOLLOW`. Windows rejects reparse points and
//! creates protected owner-only DACLs at each creation step, but its path walk assumes
//! the Carl-owned data root remains trusted during creation. A prepared home retains
//! directory identities and rejects ambient path replacement before each provider
//! invocation or file operation.

mod bounded_process;
mod exec_jsonl;
mod jsonl;

pub(crate) use bounded_process::{
    BoundedProcessLimits, BoundedProcessOutcome, ClosedEnvironment, run_bounded_process,
};
pub use exec_jsonl::{ExecutionWorkspace, JsonlEventProcess, JsonlProcessOutcome};

use std::collections::{HashMap, HashSet, VecDeque, hash_map::Entry};
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::future::Future;
use std::io::{IsTerminal, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

#[cfg(windows)]
use process_wrap::tokio::CommandWrapper;
#[cfg(unix)]
use process_wrap::tokio::ProcessGroup;
use process_wrap::tokio::{ChildWrapper, CommandWrap};
use semver::{Version, VersionReq};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout, Command};
use tokio::sync::{Mutex as AsyncMutex, Semaphore, mpsc, oneshot};
use tokio::task::{AbortHandle, JoinHandle};

use self::jsonl::{encode_line, read_bounded_line};

const STATE_RUNNING: u8 = 0;
const STATE_CANCELLING: u8 = 1;
const STATE_STOPPED: u8 = 2;
const VERSION_OUTPUT_LIMIT: usize = 4 * 1_024;
const VERSION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_VERIFICATION_EXECUTABLE_BYTES: u64 = 512 * 1_024 * 1_024;
const REDACTED_STDERR: &str = "<redacted sidecar stderr>";
const MAX_PENDING_REQUESTS: usize = 128;
const MAX_ABANDONED_REQUEST_IDS: usize = 128;
const SUPERVISOR_CHANNEL_CAPACITY: usize = 256;
const WRITER_CHANNEL_CAPACITY: usize = 128;
const NOTIFICATION_CHANNEL_CAPACITY: usize = 64;
const SERVER_REQUEST_CHANNEL_CAPACITY: usize = 64;
const MAX_STDOUT_LINE_BYTES: usize = 1024 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PROCESS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const PRIVATE_TEMP_DIRECTORY: &str = ".carl-tmp";
const DATA_ROOT_LOCK_FILENAME: &str = ".carl-instance.lock";
static NEXT_STATIC_FILE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static PROVIDER_HOME_OPERATION_LOCKS: OnceLock<
    Mutex<HashMap<DirectoryIdentity, Weak<AsyncMutex<()>>>>,
> = OnceLock::new();
static HELD_DATA_ROOT_LOCKS: OnceLock<Mutex<HashMap<DirectoryIdentity, ()>>> = OnceLock::new();

#[cfg(target_os = "linux")]
const ALLOWED_ENVIRONMENT: &[&str] = &[
    "CODEX_HOME",
    "DBUS_SESSION_BUS_ADDRESS",
    "GROK_DISABLE_AUTOUPDATER",
    "GROK_HOME",
    "HOME",
    "PATH",
    "TEMP",
    "TMP",
    "TMPDIR",
    "XDG_RUNTIME_DIR",
];

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const ALLOWED_ENVIRONMENT: &[&str] = &[
    "CODEX_HOME",
    "GROK_DISABLE_AUTOUPDATER",
    "GROK_HOME",
    "HOME",
    "PATH",
    "TEMP",
    "TMP",
    "TMPDIR",
];

#[cfg(target_os = "macos")]
const ALLOWED_ENVIRONMENT: &[&str] = &[
    "CODEX_HOME",
    "GROK_DISABLE_AUTOUPDATER",
    "GROK_HOME",
    "HOME",
    "PATH",
    "TEMP",
    "TMP",
    "TMPDIR",
    // macOS inserts this locale/encoding variable during process startup even
    // after env_clear, so treat that non-credential key as an explicit allowlist entry.
    "__CF_USER_TEXT_ENCODING",
];

#[cfg(windows)]
const ALLOWED_ENVIRONMENT: &[&str] = &[
    "CODEX_HOME",
    "COMSPEC",
    "GROK_DISABLE_AUTOUPDATER",
    "GROK_HOME",
    "HOME",
    "PATHEXT",
    "PATH",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "WINDIR",
];

/// The closed parser selected for a provider's documented version output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionOutputFormat {
    /// Accept exactly `<prefix> <semver>`, apart from surrounding ASCII whitespace.
    ExactPrefix(&'static str),
    /// Accept exactly `<prefix> <version>`, including the version token's literal
    /// spelling, apart from surrounding ASCII whitespace.
    ExactPrefixedVersion {
        prefix: &'static str,
        version: &'static str,
    },
    /// Accept output containing exactly one whitespace-delimited semantic-version token.
    SingleSemverToken,
    /// Accept output containing exactly one semantic-version token whose literal
    /// spelling matches the pinned stable release.
    SingleExactSemverToken { version: &'static str },
}

/// How inbound ID-less JSONL notifications are handled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotificationPolicy {
    QueueBounded,
    Reject,
}

/// A provider process and its version compatibility contract.
pub struct SidecarCommand {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub version_arguments: Vec<OsString>,
    pub version_output: VersionOutputFormat,
    pub isolated_home: PathBuf,
    pub supported_versions: VersionReq,
}

impl SidecarCommand {
    /// Resolve and validate a candidate without executing it.
    pub fn resolve_executable(&self) -> Result<ResolvedExecutable, SidecarError> {
        ResolvedExecutable::resolve(&self.executable)
    }

    /// Probe a previously resolved and explicitly trusted executable.
    pub async fn detect_trusted_version(
        &self,
        executable: &TrustedExecutable,
        profile: ProviderEnvironmentProfile,
        carl_data_root: impl AsRef<Path>,
        workspace: impl AsRef<Path>,
        limits: SidecarLimits,
    ) -> Result<Version, SidecarError> {
        let limits = limits.validate()?;
        let home = ProviderHome::prepare(
            profile,
            carl_data_root.as_ref(),
            workspace.as_ref(),
            &self.isolated_home,
        )?;
        self.detect_version_in_home(executable, &home, limits).await
    }

    /// Probe a trusted executable using an existing provider-home capability.
    pub async fn detect_version_in_home(
        &self,
        executable: &TrustedExecutable,
        home: &ProviderHome,
        limits: SidecarLimits,
    ) -> Result<Version, SidecarError> {
        let limits = limits.validate()?;
        detect_version(self, executable, home, limits).await
    }
}

/// A provider-specific, closed environment profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderEnvironmentProfile {
    Codex,
    Grok,
}

impl ProviderEnvironmentProfile {
    const fn home_variable(self) -> &'static str {
        match self {
            Self::Codex => "CODEX_HOME",
            Self::Grok => "GROK_HOME",
        }
    }
}

/// The explicit foreground decision that converts a resolved candidate into an
/// executable capability. Compatibility probing is forbidden before this decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutableTrustDecision {
    /// Trust the displayed canonical path only when no metadata risk was found.
    TrustCanonicalPath,
    /// Trust the displayed canonical path and its reported closed metadata risk.
    TrustCanonicalPathWithMetadataRisk,
}

/// A platform metadata condition that requires a stronger foreground trust decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutableMetadataRisk {
    /// A current-user- or root-owned install ancestor is group-writable but not
    /// world-writable. This is common in native package-manager prefixes.
    GroupWritableInstallDirectory,
}

/// A canonical executable candidate that has been inspected but never run.
pub struct ResolvedExecutable {
    canonical_path: PathBuf,
    metadata_risk: Option<ExecutableMetadataRisk>,
    file_identity: ExecutableFileIdentity,
}

impl fmt::Debug for ResolvedExecutable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedExecutable")
            .field("canonical_path", &"<foreground-only>")
            .field("metadata_risk", &self.metadata_risk)
            .finish()
    }
}

impl ResolvedExecutable {
    pub(crate) fn resolve(candidate: &Path) -> Result<Self, SidecarError> {
        let discovered = discover_executable(candidate)?;
        let canonical_path = fs::canonicalize(discovered).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SidecarError::from_code(SidecarErrorCode::ExecutableMissing)
            } else {
                SidecarError::from_code(SidecarErrorCode::ExecutableUnavailable)
            }
        })?;
        let canonical_path =
            resolve_packaged_codex_native_binary(&canonical_path)?.unwrap_or(canonical_path);
        let metadata = fs::symlink_metadata(&canonical_path)
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::ExecutableUnavailable))?;
        if !metadata.file_type().is_file() || is_link_or_reparse(&metadata) {
            return Err(SidecarError::from_code(
                SidecarErrorCode::ExecutableUnavailable,
            ));
        }
        let metadata_risk = verify_executable_metadata(&canonical_path, &metadata)?;
        let file_identity = executable_file_identity(&canonical_path, &metadata)?;
        Ok(Self {
            canonical_path,
            metadata_risk,
            file_identity,
        })
    }

    #[must_use]
    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    /// Return the closed metadata risk that must be shown with the canonical path
    /// before a stronger trust decision can be made.
    #[must_use]
    pub const fn metadata_risk(&self) -> Option<ExecutableMetadataRisk> {
        self.metadata_risk
    }

    pub fn trust(
        self,
        decision: ExecutableTrustDecision,
    ) -> Result<TrustedExecutable, SidecarError> {
        let accepted = matches!(
            (self.metadata_risk, decision),
            (None, ExecutableTrustDecision::TrustCanonicalPath)
                | (
                    Some(ExecutableMetadataRisk::GroupWritableInstallDirectory),
                    ExecutableTrustDecision::TrustCanonicalPathWithMetadataRisk,
                )
        );
        if !accepted {
            return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
        }
        let trusted = TrustedExecutable {
            canonical_path: self.canonical_path,
            metadata_risk: self.metadata_risk,
            file_identity: self.file_identity,
        };
        trusted.revalidate_for_spawn()?;
        Ok(trusted)
    }
}

/// An explicitly trusted executable capability reusable across version, JSONL, and
/// foreground provider invocations.
///
/// The capability retains the regular file's platform identity and revalidates its
/// canonical path immediately before each spawn. This narrows path-replacement races,
/// but it is not content or publisher attestation: an owner can modify an owner-writable
/// file without changing its identity, and the path check cannot be made atomic with the
/// operating system's later executable open.
#[derive(Clone)]
pub struct TrustedExecutable {
    canonical_path: PathBuf,
    metadata_risk: Option<ExecutableMetadataRisk>,
    file_identity: ExecutableFileIdentity,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct TrustedExecutableAttestation {
    canonical_path: String,
    metadata_risk_tag: &'static str,
    platform_identity_evidence: Vec<u8>,
    byte_len: u64,
    content_sha256: [u8; 32],
}

impl TrustedExecutableAttestation {
    pub(crate) fn canonical_path(&self) -> &str {
        &self.canonical_path
    }

    pub(crate) const fn metadata_risk_tag(&self) -> &'static str {
        self.metadata_risk_tag
    }

    pub(crate) fn platform_identity_evidence(&self) -> &[u8] {
        &self.platform_identity_evidence
    }

    pub(crate) const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub(crate) const fn content_sha256(&self) -> [u8; 32] {
        self.content_sha256
    }
}

impl fmt::Debug for TrustedExecutableAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedExecutableAttestation")
            .field("canonical_path", &"<foreground-only>")
            .field("metadata_risk_tag", &self.metadata_risk_tag)
            .field("byte_len", &self.byte_len)
            .field("content_sha256", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for TrustedExecutable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedExecutable")
            .field("canonical_path", &"<foreground-only>")
            .finish()
    }
}

impl TrustedExecutable {
    #[must_use]
    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    fn revalidate_for_spawn(&self) -> Result<(), SidecarError> {
        let (metadata_risk, file_identity) = inspect_trusted_executable(&self.canonical_path)?;
        if metadata_risk != self.metadata_risk || file_identity != self.file_identity {
            return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
        }
        Ok(())
    }

    pub(crate) fn verification_attestation(
        &self,
    ) -> Result<TrustedExecutableAttestation, SidecarError> {
        #[cfg(windows)]
        if self
            .canonical_path
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|extension| {
                extension.eq_ignore_ascii_case("bat") || extension.eq_ignore_ascii_case("cmd")
            })
        {
            return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
        }

        self.revalidate_for_spawn()?;
        let canonical_path = self
            .canonical_path
            .to_str()
            .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::UnsafeExecutable))?
            .to_owned();
        let mut file = File::open(&self.canonical_path)
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::UnsafeExecutable))?;
        let before = file
            .metadata()
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::UnsafeExecutable))?;
        if !before.file_type().is_file() {
            return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
        }
        if before.len() == 0 || before.len() > MAX_VERIFICATION_EXECUTABLE_BYTES {
            return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
        }
        let before_identity = executable_identity_from_open_file(&file, &before)?;
        if before_identity != self.file_identity {
            return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
        }

        let mut digest = Sha256::new();
        let mut observed_bytes = 0_u64;
        let mut buffer = [0_u8; 32 * 1_024];
        #[cfg(unix)]
        let mut executable_prefix = [0_u8; 2];
        #[cfg(unix)]
        let mut executable_prefix_len = 0_usize;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| SidecarError::from_code(SidecarErrorCode::UnsafeExecutable))?;
            if read == 0 {
                break;
            }
            #[cfg(unix)]
            if executable_prefix_len < executable_prefix.len() {
                let copied = (executable_prefix.len() - executable_prefix_len).min(read);
                executable_prefix[executable_prefix_len..executable_prefix_len + copied]
                    .copy_from_slice(&buffer[..copied]);
                executable_prefix_len += copied;
                if executable_prefix == *b"#!" {
                    return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
                }
            }
            observed_bytes = observed_bytes
                .checked_add(
                    u64::try_from(read)
                        .map_err(|_| SidecarError::from_code(SidecarErrorCode::UnsafeExecutable))?,
                )
                .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::UnsafeExecutable))?;
            if observed_bytes > MAX_VERIFICATION_EXECUTABLE_BYTES || observed_bytes > before.len() {
                return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
            }
            digest.update(&buffer[..read]);
        }

        let after = file
            .metadata()
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::UnsafeExecutable))?;
        let after_identity = executable_identity_from_open_file(&file, &after)?;
        if before_identity != after_identity
            || before.len() != after.len()
            || before.modified().ok() != after.modified().ok()
            || observed_bytes != after.len()
        {
            return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
        }
        self.revalidate_for_spawn()?;

        Ok(TrustedExecutableAttestation {
            canonical_path,
            metadata_risk_tag: executable_metadata_risk_tag(self.metadata_risk),
            platform_identity_evidence: executable_identity_evidence(self.file_identity),
            byte_len: observed_bytes,
            content_sha256: digest.finalize().into(),
        })
    }

    pub(crate) fn revalidate_verification_attestation(
        &self,
        expected: &TrustedExecutableAttestation,
    ) -> Result<(), SidecarError> {
        let actual = self.verification_attestation()?;
        if &actual != expected {
            return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
        }
        Ok(())
    }

    #[cfg(all(test, unix))]
    pub(crate) fn for_test(canonical_path: PathBuf) -> Self {
        let canonical_path =
            fs::canonicalize(canonical_path).expect("the test executable path is canonicalizable");
        let (metadata_risk, file_identity) = inspect_trusted_executable(&canonical_path)
            .expect("the test executable satisfies executable metadata checks");
        Self {
            canonical_path,
            metadata_risk,
            file_identity,
        }
    }

    /// Spawn a supervised provider command attached directly to the authorized local
    /// foreground terminal.
    pub(crate) fn spawn_foreground(
        &self,
        authorization: &LocalForegroundAuthorization,
        arguments: &[OsString],
        home: &ProviderHome,
        limits: SidecarLimits,
    ) -> Result<ForegroundProcess, SidecarError> {
        let limits = limits.validate()?;
        authorization.validate()?;
        let provider_stdout = duplicate_verified_stderr()?;
        let provider_stderr = duplicate_verified_stderr()?;
        let mut command = Command::new(&self.canonical_path);
        command
            .args(arguments)
            .env_clear()
            .stdin(Stdio::inherit())
            .stdout(provider_stdout)
            .stderr(provider_stderr)
            .kill_on_drop(true);
        home.configure_command(&mut command)?;
        set_owner_only_child_umask(&mut command);
        let child = spawn_trusted_grouped(self, command)?;
        #[cfg(unix)]
        let terminal = if authorization.is_test_only() {
            None
        } else {
            match child
                .id()
                .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::SpawnFailed))
                .and_then(ForegroundTerminalLease::transfer_to)
            {
                Ok(terminal) => Some(terminal),
                Err(error) => {
                    let mut child = SidecarProcessGuard::new(child);
                    child.start_kill();
                    return Err(error);
                }
            }
        };
        #[cfg(windows)]
        let terminal = None;
        Ok(ForegroundProcess {
            process: Arc::new(Mutex::new(SidecarProcessGuard::new(child))),
            terminal,
            limits,
        })
    }
}

/// Proof that a request originated in Carl's local foreground CLI path.
///
/// The constructor is crate-private so remote adapters cannot manufacture this
/// capability merely because the daemon happens to have terminal handles.
pub(crate) struct LocalForegroundAuthorization {
    _private: (),
    #[cfg(test)]
    test_only: bool,
}

impl LocalForegroundAuthorization {
    fn validate(&self) -> Result<(), SidecarError> {
        #[cfg(test)]
        if self.test_only {
            return Ok(());
        }
        validate_local_foreground()
    }

    #[cfg(unix)]
    const fn is_test_only(&self) -> bool {
        #[cfg(test)]
        {
            self.test_only
        }
        #[cfg(not(test))]
        {
            false
        }
    }
}

#[allow(dead_code)]
pub(crate) fn authorize_local_foreground() -> Result<LocalForegroundAuthorization, SidecarError> {
    validate_local_foreground()?;
    Ok(LocalForegroundAuthorization {
        _private: (),
        #[cfg(test)]
        test_only: false,
    })
}

/// Report whether this process currently owns three local terminal streams.
///
/// This is an early no-spawn check only. Callers cannot derive a foreground
/// authorization capability from it; mutation paths validate again at the actual
/// provider spawn.
#[must_use]
pub fn local_foreground_terminal_available() -> bool {
    validate_local_foreground().is_ok()
}

pub(crate) fn write_local_foreground_stderr(message: &[u8]) -> Result<(), SidecarError> {
    validate_local_foreground()?;
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    stderr
        .write_all(message)
        .and_then(|()| stderr.flush())
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::ForegroundRequired))
}

#[cfg(all(test, unix))]
pub(crate) const fn authorize_test_foreground() -> LocalForegroundAuthorization {
    LocalForegroundAuthorization {
        _private: (),
        test_only: true,
    }
}

fn validate_local_foreground() -> Result<(), SidecarError> {
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        return Err(SidecarError::from_code(
            SidecarErrorCode::ForegroundRequired,
        ));
    }
    #[cfg(unix)]
    {
        // SAFETY: both functions only inspect process/terminal group state.
        let foreground = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };
        // SAFETY: getpgrp has no preconditions.
        let own_group = unsafe { libc::getpgrp() };
        if foreground < 0 || foreground != own_group {
            return Err(SidecarError::from_code(
                SidecarErrorCode::ForegroundRequired,
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn duplicate_verified_stderr() -> Result<Stdio, SidecarError> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: STDERR_FILENO names the stderr terminal just verified above. The
    // returned descriptor is uniquely owned and immediately wrapped in OwnedFd.
    let descriptor = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(SidecarError::from_code(
            SidecarErrorCode::ForegroundRequired,
        ));
    }
    // SAFETY: fcntl returned a fresh owned descriptor on success.
    let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor) };
    Ok(Stdio::from(descriptor))
}

#[cfg(windows)]
fn duplicate_verified_stderr() -> Result<Stdio, SidecarError> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // SAFETY: GetStdHandle and GetCurrentProcess have no pointer preconditions.
    let source = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    if source.is_null() || source == INVALID_HANDLE_VALUE {
        return Err(SidecarError::from_code(
            SidecarErrorCode::ForegroundRequired,
        ));
    }
    let process = unsafe { GetCurrentProcess() };
    let mut duplicate = std::ptr::null_mut();
    // SAFETY: source is the verified stderr handle, duplicate points to writable
    // handle storage, and both process pseudo-handles refer to this process.
    let duplicated = unsafe {
        DuplicateHandle(
            process,
            source,
            process,
            &mut duplicate,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if duplicated == 0 || duplicate.is_null() {
        return Err(SidecarError::from_code(
            SidecarErrorCode::ForegroundRequired,
        ));
    }
    // SAFETY: DuplicateHandle returned a fresh owned handle on success.
    let duplicate = unsafe { OwnedHandle::from_raw_handle(duplicate) };
    Ok(Stdio::from(duplicate))
}

/// A terminal-inherited, process-group/job-owned provider process.
pub struct ForegroundProcess {
    process: Arc<Mutex<SidecarProcessGuard>>,
    #[cfg(unix)]
    terminal: Option<ForegroundTerminalLease>,
    #[cfg(windows)]
    terminal: Option<()>,
    limits: SidecarLimits,
}

impl ForegroundProcess {
    /// Wait for the leader, then kill ordinary descendants and restore Carl's
    /// foreground terminal group. Dropping the returned in-flight future starts
    /// synchronous group/job termination while retaining this process for bounded
    /// reconciliation through [`Self::cancel`].
    pub fn wait(&mut self) -> ForegroundWait<'_> {
        let poll_interval = self.limits.process_poll_interval;
        ForegroundWait {
            owner: self,
            sleep: Box::pin(tokio::time::sleep(poll_interval)),
            complete: false,
        }
    }

    /// Gracefully terminate, force-kill if needed, and restore the terminal.
    pub async fn cancel(&mut self) -> Result<(), SidecarError> {
        let process_result = terminate_process(&self.process, self.limits).await;
        let terminal_result = self.restore_terminal();
        match terminal_result {
            Ok(()) => process_result,
            Err(error) => Err(error),
        }
    }

    fn restore_terminal(&mut self) -> Result<(), SidecarError> {
        #[cfg(unix)]
        if let Some(terminal) = self.terminal.as_mut() {
            terminal.restore()?;
            self.terminal = None;
        }
        #[cfg(windows)]
        {
            self.terminal = None;
        }
        Ok(())
    }
}

impl Drop for ForegroundProcess {
    fn drop(&mut self) {
        lock(&self.process).start_kill();
        let _ = self.restore_terminal();
    }
}

/// Cancellation-safe wait guard for a foreground provider process.
pub struct ForegroundWait<'a> {
    owner: &'a mut ForegroundProcess,
    sleep: Pin<Box<tokio::time::Sleep>>,
    complete: bool,
}

impl Future for ForegroundWait<'_> {
    type Output = Result<std::process::ExitStatus, SidecarError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let result = {
            let mut process = lock(&this.owner.process);
            process.try_wait()
        };
        match result {
            Ok(Some(status)) => {
                lock(&this.owner.process).start_kill();
                this.complete = true;
                Poll::Ready(this.owner.restore_terminal().map(|()| status))
            }
            Err(()) => {
                lock(&this.owner.process).start_kill();
                this.complete = true;
                Poll::Ready(match this.owner.restore_terminal() {
                    Ok(()) => Err(SidecarError::from_code(SidecarErrorCode::SpawnFailed)),
                    Err(error) => Err(error),
                })
            }
            Ok(None) => {
                if this.sleep.as_mut().poll(context).is_ready() {
                    this.sleep.as_mut().reset(
                        tokio::time::Instant::now() + this.owner.limits.process_poll_interval,
                    );
                    let _ = this.sleep.as_mut().poll(context);
                }
                Poll::Pending
            }
        }
    }
}

impl Drop for ForegroundWait<'_> {
    fn drop(&mut self) {
        if !self.complete {
            lock(&self.owner.process).start_kill();
            let _ = self.owner.restore_terminal();
        }
    }
}

#[cfg(unix)]
struct ForegroundTerminalLease {
    terminal_fd: libc::c_int,
    parent_group: libc::pid_t,
    restored: bool,
}

#[cfg(unix)]
impl ForegroundTerminalLease {
    fn transfer_to(child_group: u32) -> Result<Self, SidecarError> {
        let child_group = libc::pid_t::try_from(child_group)
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::ForegroundRequired))?;
        // SAFETY: getpgrp has no preconditions.
        let parent_group = unsafe { libc::getpgrp() };
        set_terminal_foreground_group(libc::STDIN_FILENO, child_group)?;
        // The child may have attempted a terminal read in the short spawn-to-transfer
        // window and received SIGTTIN. Resume the whole provider process group.
        // SAFETY: a negative PID addresses the freshly created child process group.
        let _ = unsafe { libc::kill(-child_group, libc::SIGCONT) };
        Ok(Self {
            terminal_fd: libc::STDIN_FILENO,
            parent_group,
            restored: false,
        })
    }

    fn restore(&mut self) -> Result<(), SidecarError> {
        if !self.restored {
            set_terminal_foreground_group(self.terminal_fd, self.parent_group)?;
            self.restored = true;
        }
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for ForegroundTerminalLease {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(unix)]
fn set_terminal_foreground_group(
    terminal_fd: libc::c_int,
    group: libc::pid_t,
) -> Result<(), SidecarError> {
    let mut signal_set = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: signal_set points to writable storage.
    if unsafe { libc::sigemptyset(signal_set.as_mut_ptr()) } != 0 {
        return Err(SidecarError::from_code(
            SidecarErrorCode::ForegroundRequired,
        ));
    }
    // SAFETY: sigemptyset initialized signal_set.
    let mut signal_set = unsafe { signal_set.assume_init() };
    // SAFETY: signal_set is initialized and SIGTTOU is a valid signal.
    if unsafe { libc::sigaddset(&mut signal_set, libc::SIGTTOU) } != 0 {
        return Err(SidecarError::from_code(
            SidecarErrorCode::ForegroundRequired,
        ));
    }
    let mut previous = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: this changes only the calling thread's signal mask and writes previous.
    if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &signal_set, previous.as_mut_ptr()) } != 0 {
        return Err(SidecarError::from_code(
            SidecarErrorCode::ForegroundRequired,
        ));
    }
    // SAFETY: pthread_sigmask succeeded and initialized previous.
    let previous = unsafe { previous.assume_init() };
    // SAFETY: terminal_fd is the authorized controlling terminal and group is a
    // process-group leader created for the child.
    let result = unsafe { libc::tcsetpgrp(terminal_fd, group) };
    // SAFETY: previous is the exact mask returned above.
    let restore_result =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) };
    if result != 0 || restore_result != 0 {
        Err(SidecarError::from_code(
            SidecarErrorCode::ForegroundRequired,
        ))
    } else {
        Ok(())
    }
}

/// Resource limits and shutdown deadlines for a sidecar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SidecarLimits {
    pub max_stdout_line_bytes: usize,
    pub max_stderr_bytes: usize,
    pub graceful_shutdown_timeout: Duration,
    pub forced_shutdown_timeout: Duration,
    pub process_poll_interval: Duration,
}

impl Default for SidecarLimits {
    fn default() -> Self {
        Self {
            max_stdout_line_bytes: 256 * 1_024,
            max_stderr_bytes: 16 * 1_024,
            graceful_shutdown_timeout: Duration::from_secs(2),
            forced_shutdown_timeout: Duration::from_secs(2),
            process_poll_interval: Duration::from_millis(20),
        }
    }
}

impl SidecarLimits {
    fn validate(self) -> Result<Self, SidecarError> {
        if self.max_stdout_line_bytes == 0
            || self.max_stdout_line_bytes > MAX_STDOUT_LINE_BYTES
            || self.max_stderr_bytes == 0
            || self.max_stderr_bytes > MAX_STDERR_BYTES
            || self.graceful_shutdown_timeout.is_zero()
            || self.graceful_shutdown_timeout > MAX_SHUTDOWN_TIMEOUT
            || self.forced_shutdown_timeout.is_zero()
            || self.forced_shutdown_timeout > MAX_SHUTDOWN_TIMEOUT
            || self.process_poll_interval.is_zero()
            || self.process_poll_interval > MAX_PROCESS_POLL_INTERVAL
            || self.process_poll_interval > self.graceful_shutdown_timeout
            || self.process_poll_interval > self.forced_shutdown_timeout
        {
            return Err(SidecarError::from_code(
                SidecarErrorCode::InvalidConfiguration,
            ));
        }
        Ok(self)
    }
}

trait ProcessTerminationLimits: Copy {
    fn graceful_shutdown_timeout(self) -> Duration;
    fn forced_shutdown_timeout(self) -> Duration;
    fn process_poll_interval(self) -> Duration;
}

impl ProcessTerminationLimits for SidecarLimits {
    fn graceful_shutdown_timeout(self) -> Duration {
        self.graceful_shutdown_timeout
    }

    fn forced_shutdown_timeout(self) -> Duration {
        self.forced_shutdown_timeout
    }

    fn process_poll_interval(self) -> Duration {
        self.process_poll_interval
    }
}

impl ProcessTerminationLimits for BoundedProcessLimits {
    fn graceful_shutdown_timeout(self) -> Duration {
        self.graceful_shutdown_timeout()
    }

    fn forced_shutdown_timeout(self) -> Duration {
        self.forced_shutdown_timeout()
    }

    fn process_poll_interval(self) -> Duration {
        self.poll_interval()
    }
}

/// Stable, non-sensitive sidecar failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SidecarErrorCode {
    ExecutableMissing,
    ExecutableUnavailable,
    UnsafeExecutable,
    UnsupportedVersion,
    InvalidProviderHome,
    UnsafeProviderFile,
    InvalidConfiguration,
    SpawnFailed,
    ForegroundRequired,
    ProtocolViolation,
    DuplicateRequestId,
    SidecarExited,
    Cancelled,
    TimedOut,
}

impl SidecarErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecutableMissing => "executable_missing",
            Self::ExecutableUnavailable => "executable_unavailable",
            Self::UnsafeExecutable => "unsafe_executable",
            Self::UnsupportedVersion => "unsupported_version",
            Self::InvalidProviderHome => "invalid_provider_home",
            Self::UnsafeProviderFile => "unsafe_provider_file",
            Self::InvalidConfiguration => "invalid_configuration",
            Self::SpawnFailed => "spawn_failed",
            Self::ForegroundRequired => "foreground_required",
            Self::ProtocolViolation => "protocol_violation",
            Self::DuplicateRequestId => "duplicate_request_id",
            Self::SidecarExited => "sidecar_exited",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }
}

impl fmt::Display for SidecarErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("sidecar operation failed: {code}")]
pub struct SidecarError {
    code: SidecarErrorCode,
}

impl SidecarError {
    #[must_use]
    pub const fn from_code(code: SidecarErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(self) -> SidecarErrorCode {
        self.code
    }
}

/// Closed, non-sensitive failures from acquiring Carl's data-root instance lock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataRootLockErrorCode {
    /// The supplied root was not absolute, pre-existing, owner-private, or a directory.
    InvalidDataRoot,
    /// The persistent lock component was not an owner-only, single-link regular file.
    UnsafeLockFile,
    /// Another live holder owns the lock for this data root.
    Contended,
    /// The operating system could not establish the lock.
    Unavailable,
}

impl DataRootLockErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidDataRoot => "invalid_data_root",
            Self::UnsafeLockFile => "unsafe_data_root_lock",
            Self::Contended => "data_root_lock_contended",
            Self::Unavailable => "data_root_lock_unavailable",
        }
    }
}

impl fmt::Display for DataRootLockErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A sanitized failure to acquire [`DataRootLock`].
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Carl data-root lock failed: {code}")]
pub struct DataRootLockError {
    code: DataRootLockErrorCode,
}

impl DataRootLockError {
    const fn from_code(code: DataRootLockErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(self) -> DataRootLockErrorCode {
        self.code
    }
}

/// An opaque exclusive capability for one verified Carl data root.
///
/// Acquisition is nonblocking. The persistent lock file is never read or unlinked;
/// the operating system releases exclusivity when this capability is dropped or the
/// process exits. Callers must retain the capability through all provider cleanup and
/// reconciliation that belongs to the protected operation.
///
/// This is cooperative process exclusivity, not isolation from the account that owns
/// the private root. In particular, that owner can rename or unlink the lock component
/// on Unix and thereby defeat future path-based acquisition.
#[must_use = "dropping the data-root lock releases process exclusivity"]
pub struct DataRootLock {
    _root_directory: File,
    lock_file: Option<File>,
    root_identity: DirectoryIdentity,
    data_root: PathBuf,
}

impl fmt::Debug for DataRootLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataRootLock")
            .finish_non_exhaustive()
    }
}

impl DataRootLock {
    /// Acquire Carl's fixed exclusive lock beneath an absolute, pre-existing,
    /// owner-private data root.
    pub fn acquire(data_root: impl AsRef<Path>) -> Result<Self, DataRootLockError> {
        let data_root = data_root.as_ref();
        if !data_root.is_absolute() {
            return Err(DataRootLockError::from_code(
                DataRootLockErrorCode::InvalidDataRoot,
            ));
        }
        let root_directory = open_private_data_root(data_root)?;
        let root_identity = directory_identity(&root_directory)
            .map_err(|_| DataRootLockError::from_code(DataRootLockErrorCode::InvalidDataRoot))?;

        let held = HELD_DATA_ROOT_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
        if lock(held).insert(root_identity, ()).is_some() {
            return Err(DataRootLockError::from_code(
                DataRootLockErrorCode::Contended,
            ));
        }

        let lock_file = match open_and_lock_data_root_file(&root_directory) {
            Ok(lock_file) => lock_file,
            Err(error) => {
                lock(held).remove(&root_identity);
                return Err(error);
            }
        };
        Ok(Self {
            _root_directory: root_directory,
            lock_file: Some(lock_file),
            root_identity,
            data_root: data_root.to_path_buf(),
        })
    }

    /// Returns whether this capability was acquired for the exact private root
    /// represented by `data_root`, comparing held directory identities rather
    /// than caller-controlled path text.
    #[must_use]
    pub fn guards_data_root(&self, data_root: impl AsRef<Path>) -> bool {
        let Ok(directory) = open_private_data_root(data_root.as_ref()) else {
            return false;
        };
        directory_identity(&directory)
            .map(|identity| identity == self.root_identity)
            .unwrap_or(false)
    }

    pub(crate) fn runtime_data_root(&self) -> &Path {
        &self.data_root
    }

    pub(crate) fn try_clone_root_directory(&self) -> std::io::Result<File> {
        self._root_directory.try_clone()
    }

    #[cfg(unix)]
    pub(crate) fn try_open_root_directory_for_writes(&self) -> std::io::Result<File> {
        self.try_clone_root_directory()
    }

    #[cfg(windows)]
    pub(crate) fn try_open_root_directory_for_writes(&self) -> std::io::Result<File> {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;

        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };

        let invalid = || {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private writable root verification failed",
            )
        };
        let directory = OpenOptions::new()
            .access_mode(GENERIC_READ | GENERIC_WRITE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&self.data_root)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir()
            || is_link_or_reparse(&metadata)
            || windows_security::verify_private_directory_handle(&directory).is_err()
            || directory_identity(&directory).map_err(|_| invalid())? != self.root_identity
        {
            return Err(invalid());
        }
        Ok(directory)
    }
}

impl Drop for DataRootLock {
    fn drop(&mut self) {
        // Explicitly unlock before close so a concurrently forked pre-exec child
        // cannot transiently retain a duplicated Unix open-file description.
        if let Some(lock_file) = self.lock_file.as_ref() {
            release_data_root_file(lock_file);
        }
        drop(self.lock_file.take());
        if let Some(held) = HELD_DATA_ROOT_LOCKS.get() {
            lock(held).remove(&self.root_identity);
        }
    }
}

/// Closed set of environment names that a provider child may receive.
///
/// Most values are synthesized. On Linux, Codex's keyring transport variables are
/// forwarded only when they identify the current user's private runtime directory
/// and its exact local `bus` socket.
#[must_use]
pub const fn allowed_environment_variables() -> &'static [&'static str] {
    ALLOWED_ENVIRONMENT
}

/// Metadata-only result for a provider-owned credential file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFileMetadata {
    /// The component does not exist beneath the held provider home.
    Missing,
    /// The component is a bounded, owner-only, single-link regular file.
    Safe,
}

/// An opaque capability for one verified provider home.
///
/// Provider adapters use this capability to configure child processes, inspect
/// provider-file metadata, and write static configuration. The capability retains
/// open directory handles and rejects replacement of its ambient bindings.
pub struct ProviderHome {
    profile: ProviderEnvironmentProfile,
    canonical_path: PathBuf,
    private_temp: PathBuf,
    directory: File,
    directory_identity: DirectoryIdentity,
    private_temp_directory: File,
    private_temp_identity: DirectoryIdentity,
    canonical_workspace: PathBuf,
    operation_lock: Arc<AsyncMutex<()>>,
}

impl fmt::Debug for ProviderHome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHome")
            .field("profile", &self.profile)
            .field("canonical_path", &"<opaque>")
            .finish_non_exhaustive()
    }
}

impl ProviderHome {
    /// Create and verify an isolated provider home and its private temporary directory.
    pub fn prepare(
        profile: ProviderEnvironmentProfile,
        carl_data_root: impl AsRef<Path>,
        workspace: impl AsRef<Path>,
        provider_home: impl AsRef<Path>,
    ) -> Result<Self, SidecarError> {
        let carl_data_root = carl_data_root.as_ref();
        let workspace = workspace.as_ref();
        let provider_home = provider_home.as_ref();
        let private_temp = provider_home.join(PRIVATE_TEMP_DIRECTORY);
        // Preflight both paths before either creation walk can chmod or mkdir.
        preflight_provider_home(carl_data_root, workspace, provider_home)?;
        preflight_provider_home(carl_data_root, workspace, &private_temp)?;
        prepare_provider_home(carl_data_root, workspace, provider_home)?;
        prepare_provider_home(carl_data_root, workspace, &private_temp)?;
        let canonical_path = fs::canonicalize(provider_home)
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
        let private_temp = fs::canonicalize(private_temp)
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
        let directory = open_provider_directory(&canonical_path)?;
        let home_identity = directory_identity(&directory)?;
        let private_temp_directory = open_provider_directory(&private_temp)?;
        let private_temp_identity = directory_identity(&private_temp_directory)?;
        let operation_lock = provider_home_operation_lock(home_identity);
        let canonical_workspace = fs::canonicalize(workspace)
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
        Ok(Self {
            profile,
            canonical_path,
            private_temp,
            directory,
            directory_identity: home_identity,
            private_temp_directory,
            private_temp_identity,
            canonical_workspace,
            operation_lock,
        })
    }

    /// Require that this capability was prepared for the adapter that will use it.
    ///
    /// Provider profiles carry different environment and credential-isolation
    /// contracts, so adapters must reject a mismatched capability before writing
    /// configuration or starting a provider process.
    pub(crate) fn require_profile(
        &self,
        expected: ProviderEnvironmentProfile,
    ) -> Result<(), SidecarError> {
        if self.profile == expected {
            Ok(())
        } else {
            Err(SidecarError::from_code(
                SidecarErrorCode::InvalidProviderHome,
            ))
        }
    }

    /// Compare a provider-reported path with this capability without exposing the
    /// capability's path to higher-level adapters.
    pub fn matches_path(&self, path: impl AsRef<Path>) -> bool {
        self.revalidate_bindings().is_ok()
            && open_provider_directory(path.as_ref())
                .and_then(|directory| directory_identity(&directory))
                .is_ok_and(|identity| identity == self.directory_identity)
    }

    /// Atomically create or replace one static, owner-only regular configuration file.
    ///
    /// Only a single normal filename is accepted. Existing symlinks, reparse points,
    /// hard links, non-regular files, or files with unsafe ownership/permissions fail
    /// closed.
    pub fn write_static_file(
        &self,
        filename: impl AsRef<Path>,
        contents: &[u8],
    ) -> Result<(), SidecarError> {
        let filename = filename.as_ref();
        if filename.components().count() != 1
            || !matches!(filename.components().next(), Some(Component::Normal(_)))
        {
            return Err(SidecarError::from_code(
                SidecarErrorCode::InvalidConfiguration,
            ));
        }
        self.revalidate_bindings()?;
        write_static_provider_file(self, filename, contents)
    }

    /// Inspect one provider-owned file through the held home directory capability
    /// without reading its contents.
    pub fn inspect_owner_only_file(
        &self,
        filename: impl AsRef<Path>,
        maximum_bytes: u64,
    ) -> Result<ProviderFileMetadata, SidecarError> {
        let filename = filename.as_ref();
        if maximum_bytes == 0
            || filename.components().count() != 1
            || !matches!(filename.components().next(), Some(Component::Normal(_)))
        {
            return Err(SidecarError::from_code(
                SidecarErrorCode::InvalidConfiguration,
            ));
        }
        self.revalidate_bindings()?;
        inspect_provider_file(self, filename, maximum_bytes)
    }

    /// Return the in-process operation lock shared by every capability holding this
    /// exact provider-home directory identity.
    pub(crate) fn operation_lock(&self) -> Arc<AsyncMutex<()>> {
        Arc::clone(&self.operation_lock)
    }

    fn configure_command(&self, command: &mut Command) -> Result<(), SidecarError> {
        self.revalidate_bindings()?;
        configure_provider_environment(
            command,
            self.profile,
            &self.canonical_path,
            &self.private_temp,
            &self.canonical_workspace,
        )?;
        command.current_dir(&self.canonical_path);
        Ok(())
    }

    fn revalidate_bindings(&self) -> Result<(), SidecarError> {
        let home = open_provider_directory(&self.canonical_path)?;
        let private_temp = open_provider_directory(&self.private_temp)?;
        if directory_identity(&self.directory)? != self.directory_identity
            || directory_identity(&self.private_temp_directory)? != self.private_temp_identity
            || directory_identity(&home)? != self.directory_identity
            || directory_identity(&private_temp)? != self.private_temp_identity
        {
            return Err(SidecarError::from_code(
                SidecarErrorCode::InvalidProviderHome,
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn open_provider_directory(path: &Path) -> Result<File, SidecarError> {
    let directory = open_identity_directory(path)?;
    verify_owned_directory(&directory)?;
    Ok(directory)
}

#[cfg(unix)]
fn open_identity_directory(path: &Path) -> Result<File, SidecarError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))
}

#[cfg(windows)]
fn open_provider_directory(path: &Path) -> Result<File, SidecarError> {
    let directory = open_identity_directory(path)?;
    windows_security::verify_private_directory(path)
        .map_err(|()| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    Ok(directory)
}

#[cfg(windows)]
fn open_identity_directory(path: &Path) -> Result<File, SidecarError> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_READ_ATTRIBUTES, FILE_TRAVERSE, READ_CONTROL, SYNCHRONIZE,
    };

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let directory = OpenOptions::new()
        // Relative creates and renames require traverse access on their held root;
        // identity and DACL revalidation require attributes and READ_CONTROL.
        .access_mode(FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    let metadata = directory
        .metadata()
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    if !metadata.is_dir() || is_link_or_reparse(&metadata) {
        return Err(SidecarError::from_code(
            SidecarErrorCode::InvalidProviderHome,
        ));
    }
    Ok(directory)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn directory_identity(directory: &File) -> Result<DirectoryIdentity, SidecarError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = directory
        .metadata()
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct DirectoryIdentity {
    volume_serial: u32,
    file_index: u64,
}

#[cfg(windows)]
fn directory_identity(directory: &File) -> Result<DirectoryIdentity, SidecarError> {
    let identity = windows_file_identity(directory)
        .map_err(|()| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    Ok(DirectoryIdentity {
        volume_serial: identity.volume_serial,
        file_index: identity.file_index,
    })
}

pub(crate) fn directory_path_matches_held(path: &Path, held: &cap_std::fs::Dir) -> bool {
    let Ok(named) = open_identity_directory(path) else {
        return false;
    };
    let Ok(held) = held.try_clone().map(cap_std::fs::Dir::into_std_file) else {
        return false;
    };
    match (directory_identity(&named), directory_identity(&held)) {
        (Ok(named), Ok(held)) => named == held,
        _ => false,
    }
}

fn provider_home_operation_lock(identity: DirectoryIdentity) -> Arc<AsyncMutex<()>> {
    let locks = PROVIDER_HOME_OPERATION_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = lock(locks);
    locks.retain(|_, operation_lock| operation_lock.strong_count() > 0);
    if let Some(operation_lock) = locks.get(&identity).and_then(Weak::upgrade) {
        return operation_lock;
    }
    let operation_lock = Arc::new(AsyncMutex::new(()));
    locks.insert(identity, Arc::downgrade(&operation_lock));
    operation_lock
}

#[cfg(unix)]
fn open_private_data_root(path: &Path) -> Result<File, DataRootLockError> {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let invalid = || DataRootLockError::from_code(DataRootLockErrorCode::InvalidDataRoot);
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| invalid())?;
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the descriptor is live and status points to writable stat storage.
    if unsafe { libc::fstat(directory.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(invalid());
    }
    // SAFETY: fstat succeeded and initialized status.
    let status = unsafe { status.assume_init() };
    // SAFETY: geteuid has no preconditions.
    if status.st_uid != unsafe { libc::geteuid() }
        || status.st_mode & libc::S_IFMT != libc::S_IFDIR
        || status.st_mode & 0o777 != 0o700
    {
        return Err(invalid());
    }
    Ok(directory)
}

#[cfg(windows)]
fn open_private_data_root(path: &Path) -> Result<File, DataRootLockError> {
    let invalid = || DataRootLockError::from_code(DataRootLockErrorCode::InvalidDataRoot);
    let directory = open_identity_directory(path).map_err(|_| invalid())?;
    windows_security::verify_private_directory_handle(&directory).map_err(|()| invalid())?;
    Ok(directory)
}

#[cfg(unix)]
fn open_and_lock_data_root_file(root: &File) -> Result<File, DataRootLockError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};

    let unsafe_file = || DataRootLockError::from_code(DataRootLockErrorCode::UnsafeLockFile);
    let name = CString::new(DATA_ROOT_LOCK_FILENAME).map_err(|_| unsafe_file())?;
    let flags = libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    // Create exclusively first so a hostile existing component is never repaired.
    // SAFETY: root is live, name is a component-only C string, and mode is supplied
    // because O_CREAT is set.
    let mut descriptor = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )
    };
    let created = descriptor >= 0;
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(unsafe_file());
        }
        // SAFETY: root is live and name is a component-only C string.
        descriptor = unsafe { libc::openat(root.as_raw_fd(), name.as_ptr(), flags) };
        if descriptor < 0 {
            return Err(unsafe_file());
        }
    }
    // SAFETY: openat returned one newly owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    if created {
        // A restrictive ambient umask may remove owner bits; set the exact private
        // mode only on the file this call created exclusively.
        // SAFETY: file owns a live descriptor for the exclusively created component.
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(unsafe_file());
        }
    }
    verify_unix_data_root_lock_file(root, &file, &name)?;

    // SAFETY: file owns a live descriptor. LOCK_NB makes acquisition nonblocking.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Err(DataRootLockError::from_code(
                DataRootLockErrorCode::Contended,
            ))
        } else {
            Err(DataRootLockError::from_code(
                DataRootLockErrorCode::Unavailable,
            ))
        };
    }
    verify_unix_data_root_lock_file(root, &file, &name)?;
    Ok(file)
}

#[cfg(unix)]
fn verify_unix_data_root_lock_file(
    root: &File,
    file: &File,
    name: &std::ffi::CStr,
) -> Result<(), DataRootLockError> {
    use std::os::fd::AsRawFd;

    let unsafe_file = || DataRootLockError::from_code(DataRootLockErrorCode::UnsafeLockFile);
    let mut held = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: file is live and held points to writable stat storage.
    if unsafe { libc::fstat(file.as_raw_fd(), held.as_mut_ptr()) } != 0 {
        return Err(unsafe_file());
    }
    // SAFETY: fstat succeeded.
    let held = unsafe { held.assume_init() };
    let mut named = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: root is live, name is NUL-terminated, and named is writable.
    if unsafe {
        libc::fstatat(
            root.as_raw_fd(),
            name.as_ptr(),
            named.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(unsafe_file());
    }
    // SAFETY: fstatat succeeded.
    let named = unsafe { named.assume_init() };
    // SAFETY: geteuid has no preconditions.
    let effective_user = unsafe { libc::geteuid() };
    let safe = |status: &libc::stat| {
        status.st_mode & libc::S_IFMT == libc::S_IFREG
            && status.st_uid == effective_user
            && status.st_nlink == 1
            && status.st_mode & 0o777 == 0o600
    };
    if !safe(&held) || !safe(&named) || held.st_dev != named.st_dev || held.st_ino != named.st_ino {
        return Err(unsafe_file());
    }
    Ok(())
}

#[cfg(unix)]
fn release_data_root_file(file: &File) {
    use std::os::fd::AsRawFd;

    // SAFETY: file owns the live descriptor on which this process acquired flock.
    let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

#[cfg(windows)]
fn open_and_lock_data_root_file(root: &File) -> Result<File, DataRootLockError> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let unsafe_file = || DataRootLockError::from_code(DataRootLockErrorCode::UnsafeLockFile);
    let file = open_or_create_relative_private_lock_file(root).map_err(|()| unsafe_file())?;
    verify_windows_data_root_lock_file(&file)?;
    let mut overlapped = OVERLAPPED::default();
    // SAFETY: file is live, overlapped is writable and remains live for this
    // synchronous nonblocking call, and the byte range covers the lock namespace.
    if unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    } == 0
    {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
            Err(DataRootLockError::from_code(
                DataRootLockErrorCode::Contended,
            ))
        } else {
            Err(DataRootLockError::from_code(
                DataRootLockErrorCode::Unavailable,
            ))
        };
    }
    verify_windows_data_root_lock_file(&file)?;
    Ok(file)
}

#[cfg(windows)]
fn verify_windows_data_root_lock_file(file: &File) -> Result<(), DataRootLockError> {
    let unsafe_file = || DataRootLockError::from_code(DataRootLockErrorCode::UnsafeLockFile);
    let metadata = file.metadata().map_err(|_| unsafe_file())?;
    let identity = windows_file_identity(file).map_err(|()| unsafe_file())?;
    if !metadata.file_type().is_file() || is_link_or_reparse(&metadata) || identity.links != 1 {
        return Err(unsafe_file());
    }
    windows_security::verify_private_file_handle(file).map_err(|()| unsafe_file())
}

#[cfg(windows)]
fn release_data_root_file(file: &File) {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let mut overlapped = OVERLAPPED::default();
    // SAFETY: file is live and overlapped remains writable for this synchronous call.
    let _ = unsafe { UnlockFileEx(file.as_raw_handle(), 0, u32::MAX, u32::MAX, &mut overlapped) };
}

fn discover_executable(candidate: &Path) -> Result<PathBuf, SidecarError> {
    if candidate.is_absolute() || candidate.components().count() != 1 {
        return Ok(candidate.to_path_buf());
    }

    let path = env::var_os("PATH")
        .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::ExecutableMissing))?;
    for directory in env::split_paths(&path) {
        #[cfg(windows)]
        {
            let extensions =
                env::var_os("PATHEXT").unwrap_or_else(|| OsString::from(".COM;.EXE;.BAT;.CMD"));
            let has_extension = candidate.extension().is_some();
            if has_extension {
                let path = directory.join(candidate);
                if path.is_file() {
                    return Ok(path);
                }
            } else {
                for extension in extensions.to_string_lossy().split(';') {
                    let path = directory.join(format!(
                        "{}{}",
                        candidate.as_os_str().to_string_lossy(),
                        extension
                    ));
                    if path.is_file() {
                        return Ok(path);
                    }
                }
            }
        }
        #[cfg(unix)]
        {
            let path = directory.join(candidate);
            if path.is_file() {
                return Ok(path);
            }
        }
    }

    Err(SidecarError::from_code(SidecarErrorCode::ExecutableMissing))
}

fn resolve_packaged_codex_native_binary(
    canonical_candidate: &Path,
) -> Result<Option<PathBuf>, SidecarError> {
    let unavailable = || SidecarError::from_code(SidecarErrorCode::ExecutableUnavailable);
    if canonical_candidate.file_name() != Some(std::ffi::OsStr::new("codex.js")) {
        return Ok(None);
    }
    let bin = canonical_candidate.parent().ok_or_else(unavailable)?;
    let package_root = bin.parent().ok_or_else(unavailable)?;
    if bin.file_name() != Some(std::ffi::OsStr::new("bin"))
        || package_root.file_name() != Some(std::ffi::OsStr::new("codex"))
        || package_root.parent().and_then(Path::file_name) != Some(std::ffi::OsStr::new("@openai"))
        || package_root
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            != Some(std::ffi::OsStr::new("node_modules"))
    {
        return Ok(None);
    }
    let (platform_package, target, binary_name) =
        codex_native_platform_layout().ok_or_else(unavailable)?;
    let optional_package_vendor = package_root
        .join("node_modules")
        .join("@openai")
        .join(platform_package)
        .join("vendor");
    let local_vendor = package_root.join("vendor");
    let candidates = [
        optional_package_vendor
            .join(target)
            .join("bin")
            .join(binary_name),
        optional_package_vendor
            .join(target)
            .join("codex")
            .join(binary_name),
        local_vendor.join(target).join("bin").join(binary_name),
        local_vendor.join(target).join("codex").join(binary_name),
    ];
    let native = candidates
        .into_iter()
        .find(|candidate| {
            fs::symlink_metadata(candidate).is_ok_and(|metadata| {
                metadata.file_type().is_file() && !is_link_or_reparse(&metadata)
            })
        })
        .ok_or_else(unavailable)?;
    fs::canonicalize(native)
        .map(Some)
        .map_err(|_| unavailable())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const fn codex_native_platform_layout() -> Option<(&'static str, &'static str, &'static str)> {
    Some(("codex-darwin-arm64", "aarch64-apple-darwin", "codex"))
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const fn codex_native_platform_layout() -> Option<(&'static str, &'static str, &'static str)> {
    Some(("codex-darwin-x64", "x86_64-apple-darwin", "codex"))
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const fn codex_native_platform_layout() -> Option<(&'static str, &'static str, &'static str)> {
    Some(("codex-linux-arm64", "aarch64-unknown-linux-musl", "codex"))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const fn codex_native_platform_layout() -> Option<(&'static str, &'static str, &'static str)> {
    Some(("codex-linux-x64", "x86_64-unknown-linux-musl", "codex"))
}

#[cfg(all(windows, target_arch = "aarch64"))]
const fn codex_native_platform_layout() -> Option<(&'static str, &'static str, &'static str)> {
    Some(("codex-win32-arm64", "aarch64-pc-windows-msvc", "codex.exe"))
}

#[cfg(all(windows, target_arch = "x86_64"))]
const fn codex_native_platform_layout() -> Option<(&'static str, &'static str, &'static str)> {
    Some(("codex-win32-x64", "x86_64-pc-windows-msvc", "codex.exe"))
}

#[cfg(not(any(
    all(target_os = "macos", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    all(target_os = "linux", target_arch = "x86_64"),
    all(windows, target_arch = "aarch64"),
    all(windows, target_arch = "x86_64")
)))]
const fn codex_native_platform_layout() -> Option<(&'static str, &'static str, &'static str)> {
    None
}

#[cfg(unix)]
fn verify_executable_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<Option<ExecutableMetadataRisk>, SidecarError> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid has no preconditions.
    let effective_user = unsafe { libc::geteuid() };
    if metadata.uid() != effective_user && metadata.uid() != 0 {
        return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
    }
    if metadata.mode() & 0o111 == 0 {
        return Err(SidecarError::from_code(
            SidecarErrorCode::ExecutableUnavailable,
        ));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
    }
    if metadata.mode() & 0o6000 != 0 {
        return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
    }
    let mut metadata_risk = None;
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent)
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::UnsafeExecutable))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.uid() != effective_user && metadata.uid() != 0)
            || metadata.mode() & 0o002 != 0
        {
            return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
        }
        if metadata.mode() & 0o020 != 0 {
            metadata_risk = Some(ExecutableMetadataRisk::GroupWritableInstallDirectory);
        }
    }
    Ok(metadata_risk)
}

#[cfg(windows)]
fn verify_executable_metadata(
    path: &Path,
    _metadata: &fs::Metadata,
) -> Result<Option<ExecutableMetadataRisk>, SidecarError> {
    for (index, component) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(component)
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::UnsafeExecutable))?;
        if is_link_or_reparse(&metadata) {
            return Err(SidecarError::from_code(SidecarErrorCode::UnsafeExecutable));
        }
        let verification = windows_security::verify_trusted_executable_component(component, index);
        verification.map_err(|()| SidecarError::from_code(SidecarErrorCode::UnsafeExecutable))?;
    }
    Ok(None)
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(windows)]
type ExecutableFileIdentity = WindowsFileIdentity;

const fn executable_metadata_risk_tag(risk: Option<ExecutableMetadataRisk>) -> &'static str {
    match risk {
        None => "none",
        Some(ExecutableMetadataRisk::GroupWritableInstallDirectory) => {
            "group_writable_install_directory"
        }
    }
}

#[cfg(unix)]
fn executable_identity_evidence(identity: ExecutableFileIdentity) -> Vec<u8> {
    let mut evidence = b"unix-file-v1\0".to_vec();
    evidence.extend_from_slice(&identity.device.to_be_bytes());
    evidence.extend_from_slice(&identity.inode.to_be_bytes());
    evidence
}

#[cfg(windows)]
fn executable_identity_evidence(identity: ExecutableFileIdentity) -> Vec<u8> {
    let mut evidence = b"windows-file-v1\0".to_vec();
    evidence.extend_from_slice(&identity.volume_serial.to_be_bytes());
    evidence.extend_from_slice(&identity.file_index.to_be_bytes());
    evidence.extend_from_slice(&identity.links.to_be_bytes());
    evidence
}

#[cfg(unix)]
fn executable_identity_from_open_file(
    _file: &File,
    metadata: &fs::Metadata,
) -> Result<ExecutableFileIdentity, SidecarError> {
    executable_file_identity(Path::new(""), metadata)
}

#[cfg(windows)]
fn executable_identity_from_open_file(
    file: &File,
    _metadata: &fs::Metadata,
) -> Result<ExecutableFileIdentity, SidecarError> {
    windows_file_identity(file)
        .map_err(|()| SidecarError::from_code(SidecarErrorCode::UnsafeExecutable))
}

fn inspect_trusted_executable(
    path: &Path,
) -> Result<(Option<ExecutableMetadataRisk>, ExecutableFileIdentity), SidecarError> {
    let unsafe_executable = || SidecarError::from_code(SidecarErrorCode::UnsafeExecutable);
    let metadata = fs::symlink_metadata(path).map_err(|_| unsafe_executable())?;
    if !metadata.file_type().is_file() || is_link_or_reparse(&metadata) {
        return Err(unsafe_executable());
    }
    let metadata_risk =
        verify_executable_metadata(path, &metadata).map_err(|_| unsafe_executable())?;
    let file_identity =
        executable_file_identity(path, &metadata).map_err(|_| unsafe_executable())?;
    Ok((metadata_risk, file_identity))
}

#[cfg(unix)]
fn executable_file_identity(
    _path: &Path,
    metadata: &fs::Metadata,
) -> Result<ExecutableFileIdentity, SidecarError> {
    use std::os::unix::fs::MetadataExt;

    Ok(ExecutableFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
fn executable_file_identity(
    path: &Path,
    _metadata: &fs::Metadata,
) -> Result<ExecutableFileIdentity, SidecarError> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let unsafe_executable = || SidecarError::from_code(SidecarErrorCode::UnsafeExecutable);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| unsafe_executable())?;
    let metadata = file.metadata().map_err(|_| unsafe_executable())?;
    if !metadata.file_type().is_file() || is_link_or_reparse(&metadata) {
        return Err(unsafe_executable());
    }
    windows_file_identity(&file).map_err(|()| unsafe_executable())
}

async fn detect_version(
    specification: &SidecarCommand,
    executable: &TrustedExecutable,
    provider_home: &ProviderHome,
    limits: SidecarLimits,
) -> Result<Version, SidecarError> {
    let mut command = Command::new(&executable.canonical_path);
    command
        .args(&specification.version_arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    provider_home.configure_command(&mut command)?;
    set_owner_only_child_umask(&mut command);

    let mut process = SidecarProcessGuard::new(spawn_trusted_grouped(executable, command)?);
    let mut stdout = process
        .child
        .stdout()
        .take()
        .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::SpawnFailed))?;
    let result = async {
        let output = tokio::time::timeout(VERSION_TIMEOUT, read_version_output(&mut stdout))
            .await
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::TimedOut))??;

        let status = poll_guard_until(
            &mut process,
            deadline_after(VERSION_TIMEOUT)?,
            limits.process_poll_interval,
        )
        .await?;
        let Some(status) = status else {
            return Err(SidecarError::from_code(SidecarErrorCode::TimedOut));
        };
        if !status.success() {
            return Err(SidecarError::from_code(SidecarErrorCode::ProtocolViolation));
        }

        let output = std::str::from_utf8(&output)
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::ProtocolViolation))?;
        let version = parse_version_output(output, specification.version_output)?;
        if !specification.supported_versions.matches(&version) {
            return Err(SidecarError::from_code(
                SidecarErrorCode::UnsupportedVersion,
            ));
        }
        Ok(version)
    }
    .await;

    // Version commands may spawn helpers. Always kill their process container and
    // bounded-reap the leader, including after read, size, parse, or status failures.
    process.start_kill();
    match poll_guard_until(
        &mut process,
        deadline_after(VERSION_TIMEOUT)?,
        limits.process_poll_interval,
    )
    .await
    {
        Ok(Some(_)) => result,
        Ok(None) => Err(SidecarError::from_code(SidecarErrorCode::TimedOut)),
        Err(error) => Err(error),
    }
}

async fn read_version_output(stdout: &mut ChildStdout) -> Result<Vec<u8>, SidecarError> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 1_024];
    loop {
        let read = stdout
            .read(&mut buffer)
            .await
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::ProtocolViolation))?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > VERSION_OUTPUT_LIMIT {
            return Err(SidecarError::from_code(SidecarErrorCode::ProtocolViolation));
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn parse_version_output(
    output: &str,
    format: VersionOutputFormat,
) -> Result<Version, SidecarError> {
    let parse_error = || SidecarError::from_code(SidecarErrorCode::ProtocolViolation);
    match format {
        VersionOutputFormat::ExactPrefix(prefix) => {
            let mut tokens = output.split_ascii_whitespace();
            if tokens.next() != Some(prefix) {
                return Err(parse_error());
            }
            let version = tokens.next().ok_or_else(parse_error)?;
            if tokens.next().is_some() {
                return Err(parse_error());
            }
            Version::parse(version).map_err(|_| parse_error())
        }
        VersionOutputFormat::ExactPrefixedVersion {
            prefix,
            version: expected,
        } => {
            let mut tokens = output.split_ascii_whitespace();
            if tokens.next() != Some(prefix) {
                return Err(parse_error());
            }
            let version = tokens.next().ok_or_else(parse_error)?;
            if tokens.next().is_some() {
                return Err(parse_error());
            }
            let parsed = Version::parse(version).map_err(|_| parse_error())?;
            if version != expected {
                return Err(SidecarError::from_code(
                    SidecarErrorCode::UnsupportedVersion,
                ));
            }
            Ok(parsed)
        }
        VersionOutputFormat::SingleSemverToken => {
            let (_, version) = parse_single_semver_token(output)?;
            Ok(version)
        }
        VersionOutputFormat::SingleExactSemverToken { version: expected } => {
            let (literal, parsed) = parse_single_semver_token(output)?;
            if literal != expected {
                return Err(SidecarError::from_code(
                    SidecarErrorCode::UnsupportedVersion,
                ));
            }
            Ok(parsed)
        }
    }
}

fn parse_single_semver_token(output: &str) -> Result<(&str, Version), SidecarError> {
    let mut versions = output.split_ascii_whitespace().filter_map(|token| {
        let literal = token
            .trim_matches(|character: char| matches!(character, '(' | ')' | '[' | ']' | ',' | ';'));
        Version::parse(literal)
            .ok()
            .map(|version| (literal, version))
    });
    let version = versions
        .next()
        .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::ProtocolViolation))?;
    if versions.next().is_some() {
        return Err(SidecarError::from_code(SidecarErrorCode::ProtocolViolation));
    }
    Ok(version)
}

/// Static policy and provider-owned credential metadata to check immediately
/// before a compatibility-verified provider process is spawned.
pub(crate) struct ProviderFilePreflight<'a> {
    policy_filename: &'a Path,
    policy_contents: &'a [u8],
    provider_filename: &'a Path,
    maximum_bytes: u64,
}

impl<'a> ProviderFilePreflight<'a> {
    pub(crate) const fn new(
        policy_filename: &'a Path,
        policy_contents: &'a [u8],
        provider_filename: &'a Path,
        maximum_bytes: u64,
    ) -> Self {
        Self {
            policy_filename,
            policy_contents,
            provider_filename,
            maximum_bytes,
        }
    }
}

/// A running JSONL sidecar. Its process wrapper and pipes remain private.
pub struct JsonlSidecar {
    process: Arc<Mutex<SidecarProcessGuard>>,
    supervisor: mpsc::Sender<SupervisorEvent>,
    writer: mpsc::Sender<WriterMessage>,
    notifications: AsyncMutex<mpsc::Receiver<serde_json::Value>>,
    server_requests: AsyncMutex<mpsc::Receiver<serde_json::Value>>,
    request_slots: Arc<Semaphore>,
    abandonments: Arc<Abandonments>,
    pipe_task_aborts: Vec<AbortHandle>,
    supervisor_task: Mutex<Option<JoinHandle<()>>>,
    state: Arc<AtomicU8>,
    stderr: Arc<Mutex<StderrCapture>>,
    limits: SidecarLimits,
    process_id: Option<u32>,
    executable_path: PathBuf,
}

impl fmt::Debug for JsonlSidecar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonlSidecar")
            .field("state", &self.state.load(Ordering::Acquire))
            .field("process_id", &self.process_id)
            .field("executable_path", &"<foreground-only>")
            .finish_non_exhaustive()
    }
}

impl JsonlSidecar {
    /// Convenience entry point that prepares the requested closed provider profile
    /// and then uses the explicitly trusted executable for both invocations.
    pub async fn spawn_trusted(
        specification: SidecarCommand,
        executable: &TrustedExecutable,
        profile: ProviderEnvironmentProfile,
        carl_data_root: impl AsRef<Path>,
        workspace: impl AsRef<Path>,
        limits: SidecarLimits,
    ) -> Result<Self, SidecarError> {
        let limits = limits.validate()?;
        let home = ProviderHome::prepare(
            profile,
            carl_data_root.as_ref(),
            workspace.as_ref(),
            &specification.isolated_home,
        )?;
        Self::spawn_in_home(
            specification,
            executable,
            &home,
            NotificationPolicy::QueueBounded,
            limits,
        )
        .await
    }

    /// Spawn against an existing provider-home capability.
    pub async fn spawn_in_home(
        specification: SidecarCommand,
        executable: &TrustedExecutable,
        home: &ProviderHome,
        notification_policy: NotificationPolicy,
        limits: SidecarLimits,
    ) -> Result<Self, SidecarError> {
        let limits = limits.validate()?;
        detect_version(&specification, executable, home, limits).await?;
        Self::spawn_prechecked(specification, executable, home, notification_policy, limits)
    }

    /// Spawn without another version probe after a provider adapter has already
    /// verified compatibility for this exact [`TrustedExecutable`] capability.
    ///
    /// The caller must perform its pinned compatibility check while constructing
    /// the adapter and must retain the same executable capability. This path still
    /// rewrites static policy, validates credential metadata, and revalidates the
    /// executable's file identity immediately before the auth-bearing spawn.
    /// It is crate-private so ordinary sidecar callers cannot bypass version checks.
    pub(crate) fn spawn_in_home_after_compatibility_check_with_provider_file_preflight(
        specification: SidecarCommand,
        executable: &TrustedExecutable,
        home: &ProviderHome,
        preflight: ProviderFilePreflight<'_>,
        notification_policy: NotificationPolicy,
        limits: SidecarLimits,
    ) -> Result<Self, SidecarError> {
        let limits = limits.validate()?;
        home.write_static_file(preflight.policy_filename, preflight.policy_contents)?;
        home.inspect_owner_only_file(preflight.provider_filename, preflight.maximum_bytes)?;
        Self::spawn_prechecked(specification, executable, home, notification_policy, limits)
    }

    fn spawn_prechecked(
        specification: SidecarCommand,
        executable: &TrustedExecutable,
        home: &ProviderHome,
        notification_policy: NotificationPolicy,
        limits: SidecarLimits,
    ) -> Result<Self, SidecarError> {
        let mut command = Command::new(&executable.canonical_path);
        command
            .args(&specification.arguments)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        home.configure_command(&mut command)?;
        set_owner_only_child_umask(&mut command);

        let mut child = spawn_trusted_grouped(executable, command)?;
        let process_id = child.id();
        let stdin = child
            .stdin()
            .take()
            .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::SpawnFailed))?;
        let stdout = child
            .stdout()
            .take()
            .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::SpawnFailed))?;
        let stderr_pipe = child
            .stderr()
            .take()
            .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::SpawnFailed))?;

        let process = Arc::new(Mutex::new(SidecarProcessGuard::new(child)));
        let state = Arc::new(AtomicU8::new(STATE_RUNNING));
        let stderr = Arc::new(Mutex::new(StderrCapture::default()));
        let abandonments = Arc::new(Abandonments::default());
        let (supervisor_tx, supervisor_rx) = mpsc::channel(SUPERVISOR_CHANNEL_CAPACITY);
        let (writer_tx, writer_rx) = mpsc::channel(WRITER_CHANNEL_CAPACITY);
        let (notification_tx, notification_rx) = mpsc::channel(NOTIFICATION_CHANNEL_CAPACITY);
        let (server_request_tx, server_request_rx) = mpsc::channel(SERVER_REQUEST_CHANNEL_CAPACITY);

        let writer_task = tokio::spawn(writer_worker(stdin, writer_rx, supervisor_tx.clone()));
        let stdout_task = tokio::spawn(stdout_worker(
            stdout,
            limits.max_stdout_line_bytes,
            supervisor_tx.clone(),
        ));
        let stderr_task = tokio::spawn(stderr_worker(
            stderr_pipe,
            Arc::clone(&stderr),
            limits.max_stderr_bytes,
        ));
        let pipe_task_aborts = vec![
            writer_task.abort_handle(),
            stdout_task.abort_handle(),
            stderr_task.abort_handle(),
        ];
        let supervisor_task = tokio::spawn(supervisor_worker(SupervisorContext {
            process: Arc::clone(&process),
            events: supervisor_rx,
            writer: writer_tx.clone(),
            notifications: notification_tx,
            server_requests: server_request_tx,
            abandonments: Arc::clone(&abandonments),
            state: Arc::clone(&state),
            writer_task,
            stdout_task,
            stderr_task,
            limits,
            notification_policy,
        }));

        Ok(Self {
            process,
            supervisor: supervisor_tx,
            writer: writer_tx,
            notifications: AsyncMutex::new(notification_rx),
            server_requests: AsyncMutex::new(server_request_rx),
            request_slots: Arc::new(Semaphore::new(MAX_PENDING_REQUESTS)),
            abandonments,
            pipe_task_aborts,
            supervisor_task: Mutex::new(Some(supervisor_task)),
            state,
            stderr,
            limits,
            process_id,
            executable_path: executable.canonical_path.clone(),
        })
    }

    /// Send one bounded JSON request and await the response with the matching JSON ID.
    pub async fn request(
        &self,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, SidecarError> {
        let _slot = Arc::clone(&self.request_slots)
            .acquire_owned()
            .await
            .map_err(|_| stopped_error(&self.state))?;
        if self.state.load(Ordering::Acquire) != STATE_RUNNING {
            return Err(stopped_error(&self.state));
        }
        let key = correlation_key(&request)?;
        let line = encode_line(&request, self.limits.max_stdout_line_bytes)
            .map_err(|()| SidecarError::from_code(SidecarErrorCode::ProtocolViolation))?;
        let (sender, receiver) = oneshot::channel();
        let (acknowledge, acknowledged) = oneshot::channel();
        self.supervisor
            .send(SupervisorEvent::Register {
                key: key.clone(),
                response: sender,
                acknowledge,
            })
            .await
            .map_err(|_| stopped_error(&self.state))?;
        acknowledged
            .await
            .map_err(|_| stopped_error(&self.state))??;
        let mut registration = PendingRegistration::new(
            key,
            Arc::clone(&self.abandonments),
            Arc::clone(&self.process),
            Arc::clone(&self.state),
        );
        let (enqueue, enqueued) = oneshot::channel();
        self.supervisor
            .send(SupervisorEvent::Enqueue {
                key: registration.key().to_owned(),
                line,
                acknowledge: enqueue,
            })
            .await
            .map_err(|_| stopped_error(&self.state))?;
        registration.mark_enqueued();
        enqueued.await.map_err(|_| stopped_error(&self.state))??;
        let response = receiver
            .await
            .unwrap_or_else(|_| Err(stopped_error(&self.state)));
        registration.disarm();
        response
    }

    /// Receive the next bounded JSONL notification (an object with a method and no ID).
    pub async fn next_notification(&self) -> Result<serde_json::Value, SidecarError> {
        let mut notifications = self.notifications.lock().await;
        notifications
            .recv()
            .await
            .ok_or_else(|| stopped_error(&self.state))
    }

    /// Receive one already-buffered notification without a zero-duration timeout.
    pub async fn try_next_notification(&self) -> Result<Option<serde_json::Value>, SidecarError> {
        let mut notifications = self.notifications.lock().await;
        match notifications.try_recv() {
            Ok(notification) => Ok(Some(notification)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(stopped_error(&self.state)),
        }
    }

    /// Receive the next bounded JSON-RPC request initiated by the sidecar.
    pub async fn next_server_request(&self) -> Result<serde_json::Value, SidecarError> {
        let mut requests = self.server_requests.lock().await;
        requests
            .recv()
            .await
            .ok_or_else(|| stopped_error(&self.state))
    }

    /// Receive one already-buffered sidecar-initiated request without waiting.
    pub async fn try_next_server_request(&self) -> Result<Option<serde_json::Value>, SidecarError> {
        let mut requests = self.server_requests.lock().await;
        match requests.try_recv() {
            Ok(request) => Ok(Some(request)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(stopped_error(&self.state)),
        }
    }

    /// Send one bounded JSON-RPC result or error for a sidecar-initiated request.
    pub fn respond_to_server_request(
        &self,
        response: serde_json::Value,
    ) -> Result<(), SidecarError> {
        if !is_server_response(&response) {
            return Err(SidecarError::from_code(SidecarErrorCode::ProtocolViolation));
        }
        let key = correlation_key(&response)?;
        let line = encode_line(&response, self.limits.max_stdout_line_bytes)
            .map_err(|()| SidecarError::from_code(SidecarErrorCode::ProtocolViolation))?;
        self.supervisor
            .try_send(SupervisorEvent::ServerResponse { key, line })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    SidecarError::from_code(SidecarErrorCode::TimedOut)
                }
                mpsc::error::TrySendError::Closed(_) => stopped_error(&self.state),
            })
    }

    /// Send one bounded ID-less JSONL notification.
    pub fn notify(&self, notification: serde_json::Value) -> Result<(), SidecarError> {
        if !is_notification(&notification) {
            return Err(SidecarError::from_code(SidecarErrorCode::ProtocolViolation));
        }
        let line = encode_line(&notification, self.limits.max_stdout_line_bytes)
            .map_err(|()| SidecarError::from_code(SidecarErrorCode::ProtocolViolation))?;
        self.writer
            .try_send(WriterMessage::Notification(line))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    SidecarError::from_code(SidecarErrorCode::TimedOut)
                }
                mpsc::error::TrySendError::Closed(_) => stopped_error(&self.state),
            })
    }

    /// Close stdin, request graceful group termination, then force group/job
    /// termination and reap the leader within bounded deadlines.
    pub async fn cancel(&self) -> Result<(), SidecarError> {
        let result = if self.state.load(Ordering::Acquire) == STATE_STOPPED {
            Ok(())
        } else {
            let (complete, completion) = oneshot::channel();
            if self
                .supervisor
                .send(SupervisorEvent::Cancel { complete })
                .await
                .is_err()
            {
                Err(stopped_error(&self.state))
            } else {
                completion
                    .await
                    .unwrap_or_else(|_| Err(stopped_error(&self.state)))
            }
        };
        self.wait_for_supervisor().await;
        result
    }

    /// The canonical executable actually used for version probing and sidecar spawn.
    ///
    /// This path is intended for foreground doctor/configuration UI. A matching
    /// version is compatibility evidence, not publisher attestation.
    #[must_use]
    pub fn executable_path(&self) -> &Path {
        &self.executable_path
    }

    #[must_use]
    pub const fn process_id(&self) -> Option<u32> {
        self.process_id
    }

    /// Return a bounded diagnostic marker without returning provider stderr content.
    #[must_use]
    pub fn stderr_snapshot(&self) -> String {
        let capture = lock(&self.stderr);
        if !capture.saw_output {
            return String::new();
        }
        REDACTED_STDERR
            .get(..self.limits.max_stderr_bytes.min(REDACTED_STDERR.len()))
            .unwrap_or_default()
            .to_owned()
    }

    async fn wait_for_supervisor(&self) {
        let task = lock(&self.supervisor_task).take();
        if let Some(task) = task {
            let _ = task.await;
        }
    }
}

impl Drop for JsonlSidecar {
    fn drop(&mut self) {
        self.state.store(STATE_CANCELLING, Ordering::Release);
        lock(&self.process).start_kill();
        for task in &self.pipe_task_aborts {
            task.abort();
        }
        if let Some(task) = lock(&self.supervisor_task).as_ref() {
            task.abort();
        }
        self.state.store(STATE_STOPPED, Ordering::Release);
    }
}

struct PendingRequest {
    response: Option<oneshot::Sender<Result<serde_json::Value, SidecarError>>>,
    enqueued: bool,
    abandoned: bool,
}

type PendingRequests = HashMap<String, PendingRequest>;

struct Abandonment {
    key: String,
    enqueued: bool,
}

#[derive(Default)]
struct Abandonments {
    queue: Mutex<VecDeque<Abandonment>>,
    overflowed: AtomicBool,
}

struct PendingRegistration {
    key: Option<String>,
    enqueued: bool,
    abandonments: Arc<Abandonments>,
    process: Arc<Mutex<SidecarProcessGuard>>,
    state: Arc<AtomicU8>,
}

impl PendingRegistration {
    fn new(
        key: String,
        abandonments: Arc<Abandonments>,
        process: Arc<Mutex<SidecarProcessGuard>>,
        state: Arc<AtomicU8>,
    ) -> Self {
        Self {
            key: Some(key),
            enqueued: false,
            abandonments,
            process,
            state,
        }
    }

    fn key(&self) -> &str {
        self.key.as_deref().unwrap_or_default()
    }

    fn mark_enqueued(&mut self) {
        self.enqueued = true;
    }

    fn disarm(&mut self) {
        self.key = None;
    }
}

impl Drop for PendingRegistration {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            let mut queue = lock(&self.abandonments.queue);
            if queue.len() >= MAX_ABANDONED_REQUEST_IDS {
                self.abandonments.overflowed.store(true, Ordering::Release);
                self.state.store(STATE_STOPPED, Ordering::Release);
                lock(&self.process).start_kill();
            } else {
                queue.push_back(Abandonment {
                    key,
                    enqueued: self.enqueued,
                });
            }
        }
    }
}

enum SupervisorEvent {
    Register {
        key: String,
        response: oneshot::Sender<Result<serde_json::Value, SidecarError>>,
        acknowledge: oneshot::Sender<Result<(), SidecarError>>,
    },
    Enqueue {
        key: String,
        line: Vec<u8>,
        acknowledge: oneshot::Sender<Result<(), SidecarError>>,
    },
    Written(String),
    Incoming(serde_json::Value),
    ServerResponse {
        key: String,
        line: Vec<u8>,
    },
    Failure(SidecarErrorCode),
    Cancel {
        complete: oneshot::Sender<Result<(), SidecarError>>,
    },
}

enum WriterMessage {
    Tracked { key: String, line: Vec<u8> },
    Notification(Vec<u8>),
}

async fn writer_worker(
    mut stdin: ChildStdin,
    mut lines: mpsc::Receiver<WriterMessage>,
    supervisor: mpsc::Sender<SupervisorEvent>,
) {
    while let Some(message) = lines.recv().await {
        let (key, line) = match message {
            WriterMessage::Tracked { key, line } => (Some(key), line),
            WriterMessage::Notification(line) => (None, line),
        };
        if stdin.write_all(&line).await.is_err() {
            let _ = supervisor
                .send(SupervisorEvent::Failure(SidecarErrorCode::SidecarExited))
                .await;
            return;
        }
        if let Some(key) = key
            && supervisor
                .send(SupervisorEvent::Written(key))
                .await
                .is_err()
        {
            return;
        }
    }
}

async fn stdout_worker(
    stdout: ChildStdout,
    maximum_line_bytes: usize,
    supervisor: mpsc::Sender<SupervisorEvent>,
) {
    let mut reader = BufReader::new(stdout);
    loop {
        let line = match read_bounded_line(&mut reader, maximum_line_bytes).await {
            Ok(Some(line)) => line,
            Ok(None) => {
                let _ = supervisor
                    .send(SupervisorEvent::Failure(SidecarErrorCode::SidecarExited))
                    .await;
                return;
            }
            Err(_) => {
                let _ = supervisor
                    .send(SupervisorEvent::Failure(
                        SidecarErrorCode::ProtocolViolation,
                    ))
                    .await;
                return;
            }
        };
        let response: serde_json::Value = match serde_json::from_slice(&line) {
            Ok(response) => response,
            Err(_) => {
                let _ = supervisor
                    .send(SupervisorEvent::Failure(
                        SidecarErrorCode::ProtocolViolation,
                    ))
                    .await;
                return;
            }
        };
        if supervisor
            .send(SupervisorEvent::Incoming(response))
            .await
            .is_err()
        {
            return;
        }
    }
}

#[derive(Default)]
struct StderrCapture {
    saw_output: bool,
    observed_bytes: usize,
}

async fn stderr_worker(
    mut stderr: ChildStderr,
    capture: Arc<Mutex<StderrCapture>>,
    maximum_bytes: usize,
) {
    let mut buffer = [0_u8; 4 * 1_024];
    loop {
        let read = match stderr.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        let mut capture = lock(&capture);
        capture.saw_output = true;
        capture.observed_bytes = capture
            .observed_bytes
            .saturating_add(read)
            .min(maximum_bytes);
    }
}

struct SupervisorContext {
    process: Arc<Mutex<SidecarProcessGuard>>,
    events: mpsc::Receiver<SupervisorEvent>,
    writer: mpsc::Sender<WriterMessage>,
    notifications: mpsc::Sender<serde_json::Value>,
    server_requests: mpsc::Sender<serde_json::Value>,
    abandonments: Arc<Abandonments>,
    state: Arc<AtomicU8>,
    writer_task: JoinHandle<()>,
    stdout_task: JoinHandle<()>,
    stderr_task: JoinHandle<()>,
    limits: SidecarLimits,
    notification_policy: NotificationPolicy,
}

async fn supervisor_worker(context: SupervisorContext) {
    let SupervisorContext {
        process,
        mut events,
        writer,
        notifications,
        server_requests,
        abandonments,
        state,
        mut writer_task,
        mut stdout_task,
        mut stderr_task,
        limits,
        notification_policy,
    } = context;
    let mut pending = PendingRequests::new();
    let mut active_server_requests = HashSet::new();
    let mut abandoned_count = 0_usize;
    loop {
        pending.retain(|_, request| {
            request.enqueued
                || request.abandoned
                || request
                    .response
                    .as_ref()
                    .is_some_and(|response| !response.is_closed())
        });
        if abandonments.overflowed.load(Ordering::Acquire)
            || drain_abandonments(&abandonments, &mut pending, &mut abandoned_count).is_err()
        {
            shutdown_supervisor(
                &process,
                &mut pending,
                &state,
                [&mut writer_task, &mut stdout_task, &mut stderr_task],
                limits,
                SidecarErrorCode::ProtocolViolation,
            )
            .await;
            return;
        }
        let event = tokio::time::timeout(limits.process_poll_interval, events.recv()).await;
        match event {
            Ok(Some(SupervisorEvent::Register {
                key,
                response,
                acknowledge,
            })) => match pending.entry(key) {
                Entry::Vacant(entry)
                    if state.load(Ordering::Acquire) == STATE_RUNNING
                        && !response.is_closed()
                        && !acknowledge.is_closed() =>
                {
                    entry.insert(PendingRequest {
                        response: Some(response),
                        enqueued: false,
                        abandoned: false,
                    });
                    let _ = acknowledge.send(Ok(()));
                }
                Entry::Vacant(_) => {
                    let _ = acknowledge.send(Err(stopped_error(&state)));
                }
                Entry::Occupied(_) => {
                    let _ = acknowledge.send(Err(SidecarError::from_code(
                        SidecarErrorCode::DuplicateRequestId,
                    )));
                }
            },
            Ok(Some(SupervisorEvent::Enqueue {
                key,
                line,
                acknowledge,
            })) => {
                let queued = pending.get_mut(&key).is_some_and(|request| {
                    request.enqueued = true;
                    writer
                        .try_send(WriterMessage::Tracked {
                            key: key.clone(),
                            line,
                        })
                        .is_ok()
                });
                if queued {
                    let _ = acknowledge.send(Ok(()));
                } else {
                    let _ = acknowledge.send(Err(SidecarError::from_code(
                        SidecarErrorCode::ProtocolViolation,
                    )));
                    shutdown_supervisor(
                        &process,
                        &mut pending,
                        &state,
                        [&mut writer_task, &mut stdout_task, &mut stderr_task],
                        limits,
                        SidecarErrorCode::ProtocolViolation,
                    )
                    .await;
                    return;
                }
            }
            Ok(Some(SupervisorEvent::Written(key))) => {
                if let Some(request) = pending.get_mut(&key) {
                    request.enqueued = true;
                }
            }
            Ok(Some(SupervisorEvent::Incoming(message))) => {
                if handle_incoming(
                    message,
                    &mut pending,
                    &mut abandoned_count,
                    &notifications,
                    &server_requests,
                    &mut active_server_requests,
                    notification_policy,
                )
                .is_err()
                {
                    shutdown_supervisor(
                        &process,
                        &mut pending,
                        &state,
                        [&mut writer_task, &mut stdout_task, &mut stderr_task],
                        limits,
                        SidecarErrorCode::ProtocolViolation,
                    )
                    .await;
                    return;
                }
            }
            Ok(Some(SupervisorEvent::ServerResponse { key, line })) => {
                if !active_server_requests.remove(&key)
                    || writer.try_send(WriterMessage::Notification(line)).is_err()
                {
                    shutdown_supervisor(
                        &process,
                        &mut pending,
                        &state,
                        [&mut writer_task, &mut stdout_task, &mut stderr_task],
                        limits,
                        SidecarErrorCode::ProtocolViolation,
                    )
                    .await;
                    return;
                }
            }
            Ok(Some(SupervisorEvent::Failure(code))) => {
                shutdown_supervisor(
                    &process,
                    &mut pending,
                    &state,
                    [&mut writer_task, &mut stdout_task, &mut stderr_task],
                    limits,
                    code,
                )
                .await;
                return;
            }
            Ok(Some(SupervisorEvent::Cancel { complete })) => {
                state.store(STATE_CANCELLING, Ordering::Release);
                writer_task.abort();
                let _ = (&mut writer_task).await;
                let result = terminate_process(&process, limits).await;
                stdout_task.abort();
                stderr_task.abort();
                let _ = (&mut stdout_task).await;
                let _ = (&mut stderr_task).await;
                fail_pending(&mut pending, SidecarErrorCode::Cancelled);
                state.store(STATE_STOPPED, Ordering::Release);
                let _ = complete.send(result);
                return;
            }
            Ok(None) => {
                shutdown_supervisor(
                    &process,
                    &mut pending,
                    &state,
                    [&mut writer_task, &mut stdout_task, &mut stderr_task],
                    limits,
                    SidecarErrorCode::SidecarExited,
                )
                .await;
                return;
            }
            Err(_) => {}
        }

        let exit_result = {
            let mut process = lock(&process);
            match process.try_wait() {
                Ok(Some(_)) => {
                    process.start_kill();
                    Some(SidecarErrorCode::SidecarExited)
                }
                Ok(None) => None,
                Err(()) => {
                    process.start_kill();
                    Some(SidecarErrorCode::SidecarExited)
                }
            }
        };
        if let Some(code) = exit_result {
            drain_after_leader_exit(
                &process,
                &mut events,
                &mut pending,
                &mut abandoned_count,
                &abandonments,
                &notifications,
                &server_requests,
                &mut active_server_requests,
                &state,
                [&mut writer_task, &mut stdout_task, &mut stderr_task],
                limits,
                notification_policy,
                code,
            )
            .await;
            return;
        }
    }
}

fn apply_abandonment(
    abandonment: Abandonment,
    pending: &mut PendingRequests,
    abandoned_count: &mut usize,
) -> Result<(), ()> {
    let Some(request) = pending.get_mut(&abandonment.key) else {
        return Ok(());
    };
    if !abandonment.enqueued && !request.enqueued {
        pending.remove(&abandonment.key);
        return Ok(());
    }
    if !request.abandoned {
        if *abandoned_count >= MAX_ABANDONED_REQUEST_IDS {
            return Err(());
        }
        request.abandoned = true;
        request.response = None;
        *abandoned_count += 1;
    }
    Ok(())
}

fn drain_abandonments(
    abandonments: &Abandonments,
    pending: &mut PendingRequests,
    abandoned_count: &mut usize,
) -> Result<(), ()> {
    let queued = {
        let mut queue = lock(&abandonments.queue);
        queue.drain(..).collect::<Vec<_>>()
    };
    for abandonment in queued {
        apply_abandonment(abandonment, pending, abandoned_count)?;
    }
    Ok(())
}

fn handle_incoming(
    message: serde_json::Value,
    pending: &mut PendingRequests,
    abandoned_count: &mut usize,
    notifications: &mpsc::Sender<serde_json::Value>,
    server_requests: &mpsc::Sender<serde_json::Value>,
    active_server_requests: &mut HashSet<String>,
    notification_policy: NotificationPolicy,
) -> Result<(), ()> {
    if is_server_request(&message) {
        let key = correlation_key(&message).map_err(|_| ())?;
        if !active_server_requests.insert(key) {
            return Err(());
        }
        server_requests.try_send(message).map_err(|_| ())
    } else if is_server_response(&message) {
        let key = correlation_key(&message).map_err(|_| ())?;
        let Some(request) = pending.remove(&key) else {
            return Err(());
        };
        if request.abandoned {
            *abandoned_count = abandoned_count.saturating_sub(1);
        } else if let Some(response) = request.response {
            let _ = response.send(Ok(message));
        }
        Ok(())
    } else if is_notification(&message) && notification_policy == NotificationPolicy::QueueBounded {
        notifications.try_send(message).map_err(|_| ())
    } else {
        Err(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn drain_after_leader_exit(
    process: &Arc<Mutex<SidecarProcessGuard>>,
    events: &mut mpsc::Receiver<SupervisorEvent>,
    pending: &mut PendingRequests,
    abandoned_count: &mut usize,
    abandonments: &Abandonments,
    notifications: &mpsc::Sender<serde_json::Value>,
    server_requests: &mpsc::Sender<serde_json::Value>,
    active_server_requests: &mut HashSet<String>,
    state: &Arc<AtomicU8>,
    tasks: [&mut JoinHandle<()>; 3],
    limits: SidecarLimits,
    notification_policy: NotificationPolicy,
    mut failure_code: SidecarErrorCode,
) {
    let [writer_task, stdout_task, stderr_task] = tasks;
    state.store(STATE_STOPPED, Ordering::Release);
    lock(process).start_kill();
    writer_task.abort();
    let _ = writer_task.await;
    let deadline = match deadline_after(limits.forced_shutdown_timeout) {
        Ok(deadline) => deadline,
        Err(_) => {
            failure_code = SidecarErrorCode::TimedOut;
            Instant::now()
        }
    };

    loop {
        if abandonments.overflowed.load(Ordering::Acquire)
            || drain_abandonments(abandonments, pending, abandoned_count).is_err()
        {
            failure_code = SidecarErrorCode::ProtocolViolation;
        }
        while let Ok(event) = events.try_recv() {
            match event {
                SupervisorEvent::Incoming(message) => {
                    if handle_incoming(
                        message,
                        pending,
                        abandoned_count,
                        notifications,
                        server_requests,
                        active_server_requests,
                        notification_policy,
                    )
                    .is_err()
                    {
                        failure_code = SidecarErrorCode::ProtocolViolation;
                    }
                }
                SupervisorEvent::Written(key) => {
                    if let Some(request) = pending.get_mut(&key) {
                        request.enqueued = true;
                    }
                }
                SupervisorEvent::ServerResponse { .. } => {
                    failure_code = SidecarErrorCode::SidecarExited;
                }
                SupervisorEvent::Register { acknowledge, .. }
                | SupervisorEvent::Enqueue { acknowledge, .. } => {
                    let _ = acknowledge.send(Err(SidecarError::from_code(
                        SidecarErrorCode::SidecarExited,
                    )));
                }
                SupervisorEvent::Failure(code) => {
                    if code == SidecarErrorCode::ProtocolViolation {
                        failure_code = code;
                    }
                }
                SupervisorEvent::Cancel { complete } => {
                    let _ = complete.send(Ok(()));
                }
            }
        }
        if stdout_task.is_finished() && events.is_empty() {
            break;
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            failure_code = SidecarErrorCode::TimedOut;
            break;
        };
        if remaining.is_zero() {
            failure_code = SidecarErrorCode::TimedOut;
            break;
        }
        tokio::time::sleep(limits.process_poll_interval.min(remaining)).await;
    }

    stdout_task.abort();
    stderr_task.abort();
    let _ = stdout_task.await;
    let _ = stderr_task.await;
    fail_pending(pending, failure_code);
    let _ = force_kill_and_reap(process, limits).await;
}

fn correlation_key(value: &serde_json::Value) -> Result<String, SidecarError> {
    let object = value
        .as_object()
        .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::ProtocolViolation))?;
    let id = object
        .get("id")
        .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::ProtocolViolation))?;
    if !id.is_string() && id.as_i64().is_none() {
        return Err(SidecarError::from_code(SidecarErrorCode::ProtocolViolation));
    }
    serde_json::to_string(id)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::ProtocolViolation))
}

fn is_notification(value: &serde_json::Value) -> bool {
    value.as_object().is_some_and(|object| {
        !object.contains_key("id")
            && object
                .get("method")
                .is_some_and(serde_json::Value::is_string)
    })
}

fn is_server_request(value: &serde_json::Value) -> bool {
    value.as_object().is_some_and(|object| {
        object.contains_key("id")
            && object
                .get("method")
                .is_some_and(serde_json::Value::is_string)
            && !object.contains_key("result")
            && !object.contains_key("error")
            && correlation_key(value).is_ok()
    })
}

fn is_server_response(value: &serde_json::Value) -> bool {
    value.as_object().is_some_and(|object| {
        object.contains_key("id")
            && !object.contains_key("method")
            && (object.contains_key("result") ^ object.contains_key("error"))
            && correlation_key(value).is_ok()
    })
}

async fn shutdown_supervisor(
    process: &Arc<Mutex<SidecarProcessGuard>>,
    pending: &mut PendingRequests,
    state: &Arc<AtomicU8>,
    tasks: [&mut JoinHandle<()>; 3],
    limits: SidecarLimits,
    code: SidecarErrorCode,
) {
    let [writer_task, stdout_task, stderr_task] = tasks;
    state.store(STATE_STOPPED, Ordering::Release);
    writer_task.abort();
    lock(process).start_kill();
    stdout_task.abort();
    stderr_task.abort();
    let _ = writer_task.await;
    let _ = stdout_task.await;
    let _ = stderr_task.await;
    fail_pending(pending, code);
    let _ = force_kill_and_reap(process, limits).await;
}

fn fail_pending(pending: &mut PendingRequests, code: SidecarErrorCode) {
    let requests = std::mem::take(pending);
    for request in requests.into_values() {
        if let Some(sender) = request.response {
            let _ = sender.send(Err(SidecarError::from_code(code)));
        }
    }
}

fn stopped_error(state: &AtomicU8) -> SidecarError {
    let code = if state.load(Ordering::Acquire) == STATE_CANCELLING {
        SidecarErrorCode::Cancelled
    } else {
        SidecarErrorCode::SidecarExited
    };
    SidecarError::from_code(code)
}

struct SidecarProcessGuard {
    child: Box<dyn ChildWrapper>,
}

impl SidecarProcessGuard {
    fn new(child: Box<dyn ChildWrapper>) -> Self {
        Self { child }
    }

    fn start_kill(&mut self) {
        let _ = self.child.start_kill();
    }

    fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, ()> {
        self.child.try_wait().map_err(|_| ())
    }

    #[cfg(unix)]
    fn signal(&self, signal: i32) -> Result<(), ()> {
        self.child.signal(signal).map_err(|_| ())
    }
}

impl Drop for SidecarProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

// Compile-time ownership invariant: the private guard is constructed from, and
// permanently owns, the group-aware trait object rather than a bare Tokio child.
const _: fn(Box<dyn ChildWrapper>) -> SidecarProcessGuard = SidecarProcessGuard::new;

async fn poll_guard_until(
    process: &mut SidecarProcessGuard,
    deadline: Instant,
    poll_interval: Duration,
) -> Result<Option<std::process::ExitStatus>, SidecarError> {
    loop {
        match process.try_wait() {
            Ok(Some(status)) => {
                process.start_kill();
                return Ok(Some(status));
            }
            Ok(None) => {}
            Err(()) => {
                process.start_kill();
                return Err(SidecarError::from_code(SidecarErrorCode::SpawnFailed));
            }
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return Ok(None);
        }
        tokio::time::sleep(poll_interval.min(remaining)).await;
    }
}

async fn poll_shared_guard_until(
    process: &Arc<Mutex<SidecarProcessGuard>>,
    deadline: Instant,
    poll_interval: Duration,
) -> Result<bool, SidecarError> {
    loop {
        let status = {
            let mut process = lock(process);
            match process.try_wait() {
                Ok(Some(_)) => {
                    process.start_kill();
                    Some(Ok(true))
                }
                Ok(None) => None,
                Err(()) => {
                    process.start_kill();
                    Some(Err(SidecarError::from_code(SidecarErrorCode::SpawnFailed)))
                }
            }
        };
        if let Some(status) = status {
            return status;
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return Ok(false);
        }
        tokio::time::sleep(poll_interval.min(remaining)).await;
    }
}

fn deadline_after(duration: Duration) -> Result<Instant, SidecarError> {
    Instant::now()
        .checked_add(duration)
        .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::InvalidConfiguration))
}

async fn terminate_process<L: ProcessTerminationLimits>(
    process: &Arc<Mutex<SidecarProcessGuard>>,
    limits: L,
) -> Result<(), SidecarError> {
    #[cfg(unix)]
    {
        let process = lock(process);
        let _ = process.signal(libc::SIGTERM);
    }

    let graceful_exit = poll_shared_guard_until(
        process,
        deadline_after(limits.graceful_shutdown_timeout())?,
        limits.process_poll_interval(),
    )
    .await?;
    if !graceful_exit {
        return force_kill_and_reap(process, limits).await;
    }
    lock(process).start_kill();
    Ok(())
}

async fn force_kill_and_reap<L: ProcessTerminationLimits>(
    process: &Arc<Mutex<SidecarProcessGuard>>,
    limits: L,
) -> Result<(), SidecarError> {
    lock(process).start_kill();
    let reaped = poll_shared_guard_until(
        process,
        deadline_after(limits.forced_shutdown_timeout())?,
        limits.process_poll_interval(),
    )
    .await?;
    lock(process).start_kill();
    if reaped {
        Ok(())
    } else {
        Err(SidecarError::from_code(SidecarErrorCode::TimedOut))
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct CarlJobObject;

#[cfg(windows)]
impl CommandWrapper for CarlJobObject {
    fn pre_spawn(&mut self, command: &mut Command, _core: &CommandWrap) -> std::io::Result<()> {
        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

        command.creation_flags(CREATE_SUSPENDED);
        Ok(())
    }

    fn wrap_child(
        &mut self,
        inner: Box<dyn ChildWrapper>,
        _core: &CommandWrap,
    ) -> std::io::Result<Box<dyn ChildWrapper>> {
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject,
        };
        use windows_sys::Win32::System::Threading::TerminateProcess;

        let process_handle = inner.inner_child().raw_handle().ok_or_else(|| {
            std::io::Error::other("spawned child did not retain a process handle")
        })?;
        // SAFETY: null security attributes and name request a new unnamed job.
        let raw_job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw_job.is_null() {
            // SAFETY: process_handle belongs to the freshly spawned suspended child.
            let _ = unsafe { TerminateProcess(process_handle, 1) };
            return Err(std::io::Error::last_os_error());
        }
        let job = OwnedJobHandle(raw_job);
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let information_size =
            u32::try_from(std::mem::size_of_val(&information)).map_err(std::io::Error::other)?;
        // SAFETY: job is live and information points to its declared structure.
        if unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&information).cast(),
                information_size,
            )
        } == 0
        {
            // SAFETY: process_handle is the still-suspended child.
            let _ = unsafe { TerminateProcess(process_handle, 1) };
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: both handles are live and the child remains suspended.
        if unsafe { AssignProcessToJobObject(job.0, process_handle) } == 0 {
            // SAFETY: process_handle is the still-suspended child.
            let _ = unsafe { TerminateProcess(process_handle, 1) };
            return Err(std::io::Error::last_os_error());
        }
        if let Err(error) = resume_process_threads(process_handle) {
            // SAFETY: the child was assigned to this live job.
            let _ = unsafe { TerminateJobObject(job.0, 1) };
            return Err(error);
        }
        Ok(Box::new(CarlJobChild {
            inner: Some(inner),
            leader_status: None,
            job,
        }))
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct OwnedJobHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
unsafe impl Send for OwnedJobHandle {}
#[cfg(windows)]
unsafe impl Sync for OwnedJobHandle {}

#[cfg(windows)]
impl Drop for OwnedJobHandle {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;

        if !self.0.is_null() {
            // SAFETY: this owned handle is closed exactly once.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct CarlJobChild {
    inner: Option<Box<dyn ChildWrapper>>,
    leader_status: Option<std::process::ExitStatus>,
    job: OwnedJobHandle,
}

#[cfg(windows)]
impl CarlJobChild {
    fn active_processes(&self) -> std::io::Result<u32> {
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };

        let mut information = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let information_size =
            u32::try_from(std::mem::size_of_val(&information)).map_err(std::io::Error::other)?;
        // SAFETY: the job is live and information points to writable storage.
        if unsafe {
            QueryInformationJobObject(
                self.job.0,
                JobObjectBasicAccountingInformation,
                std::ptr::from_mut(&mut information).cast(),
                information_size,
                std::ptr::null_mut(),
            )
        } == 0
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(information.ActiveProcesses)
        }
    }

    fn terminate_job(&self) -> std::io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;

        // SAFETY: the owned job handle remains live.
        if unsafe { TerminateJobObject(self.job.0, 1) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
impl ChildWrapper for CarlJobChild {
    fn inner(&self) -> &dyn ChildWrapper {
        self.inner.as_deref().expect("Carl job child retains inner")
    }

    fn inner_mut(&mut self) -> &mut dyn ChildWrapper {
        self.inner
            .as_deref_mut()
            .expect("Carl job child retains inner")
    }

    fn into_inner(mut self: Box<Self>) -> Box<dyn ChildWrapper> {
        let _ = self.terminate_job();
        self.inner
            .take()
            .expect("Carl job child retains inner")
            .into_inner()
    }

    fn start_kill(&mut self) -> std::io::Result<()> {
        self.terminate_job()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        if self.leader_status.is_none() {
            self.leader_status = self.inner_mut().try_wait()?;
            if self.leader_status.is_some() && self.active_processes()? != 0 {
                self.terminate_job()?;
            }
        }
        if self.active_processes()? == 0 {
            Ok(self.leader_status)
        } else {
            Ok(None)
        }
    }

    fn wait(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<std::process::ExitStatus>> + Send + '_>> {
        Box::pin(async move {
            loop {
                if let Some(status) = self.try_wait()? {
                    return Ok(status);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    }
}

#[cfg(windows)]
fn resume_process_threads(process: windows_sys::Win32::Foundation::HANDLE) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessId, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
    };

    // SAFETY: process is a live process handle.
    let process_id = unsafe { GetProcessId(process) };
    if process_id == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: snapshot flags and PID are valid.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let result = (|| {
        let mut entry = THREADENTRY32 {
            dwSize: u32::try_from(std::mem::size_of::<THREADENTRY32>())
                .map_err(std::io::Error::other)?,
            ..THREADENTRY32::default()
        };
        // SAFETY: snapshot and entry are live.
        let mut found = unsafe { Thread32First(snapshot, &mut entry) } != 0;
        let mut resumed = false;
        while found {
            if entry.th32OwnerProcessID == process_id {
                // SAFETY: the thread ID came from the live snapshot.
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if thread.is_null() {
                    return Err(std::io::Error::last_os_error());
                }
                // SAFETY: thread is a live handle opened with suspend/resume access.
                let resume_result = unsafe { ResumeThread(thread) };
                // SAFETY: the owned thread handle is closed exactly once.
                let _ = unsafe { CloseHandle(thread) };
                if resume_result == u32::MAX {
                    return Err(std::io::Error::last_os_error());
                }
                resumed = true;
            }
            // SAFETY: snapshot and entry remain live.
            found = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
        }
        resumed
            .then_some(())
            .ok_or_else(|| std::io::Error::other("spawned child had no resumable thread"))
    })();
    // SAFETY: the snapshot handle is owned by this function.
    let _ = unsafe { CloseHandle(snapshot) };
    result
}

/// The sole production bridge from a trusted executable capability to an OS spawn.
///
/// Revalidation intentionally sits immediately beside the spawn. It still cannot make
/// the path check and the operating system's executable open one atomic operation.
fn spawn_trusted_grouped(
    executable: &TrustedExecutable,
    command: Command,
) -> Result<Box<dyn ChildWrapper>, SidecarError> {
    executable.revalidate_for_spawn()?;
    spawn_grouped_unchecked(command)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::SpawnFailed))
}

fn spawn_grouped_unchecked(command: Command) -> std::io::Result<Box<dyn ChildWrapper>> {
    let mut command = CommandWrap::from(command);
    #[cfg(unix)]
    command.wrap(ProcessGroup::leader());
    #[cfg(windows)]
    command.wrap(CarlJobObject);
    command.spawn()
}

fn configure_provider_environment(
    command: &mut Command,
    profile: ProviderEnvironmentProfile,
    provider_home: &Path,
    private_temp: &Path,
    workspace: &Path,
) -> Result<(), SidecarError> {
    command
        .env("PATH", minimal_system_path()?)
        .env(profile.home_variable(), provider_home)
        .env("HOME", provider_home)
        .env("TEMP", private_temp)
        .env("TMP", private_temp);
    #[cfg(unix)]
    command.env("TMPDIR", private_temp);
    #[cfg(target_os = "linux")]
    if profile == ProviderEnvironmentProfile::Codex
        && let Some((runtime, address)) = validated_linux_keyring_environment(
            env::var_os("XDG_RUNTIME_DIR"),
            env::var_os("DBUS_SESSION_BUS_ADDRESS"),
            workspace,
            provider_home,
        )
    {
        command
            .env("XDG_RUNTIME_DIR", runtime)
            .env("DBUS_SESSION_BUS_ADDRESS", address);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = workspace;
    #[cfg(windows)]
    {
        let system = windows_system_environment()?;
        command
            .env("USERPROFILE", provider_home)
            .env("SYSTEMROOT", &system.windows)
            .env("WINDIR", &system.windows)
            .env("SYSTEMDRIVE", &system.system_drive)
            .env("COMSPEC", &system.comspec)
            .env("PATHEXT", ".COM;.EXE;.BAT;.CMD");
    }
    if profile == ProviderEnvironmentProfile::Grok {
        command.env("GROK_DISABLE_AUTOUPDATER", "1");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validated_linux_keyring_environment(
    runtime: Option<OsString>,
    address: Option<OsString>,
    workspace: &Path,
    provider_home: &Path,
) -> Option<(OsString, OsString)> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    let runtime = PathBuf::from(runtime?);
    let address = address?;
    if !runtime.is_absolute() {
        return None;
    }
    let bus_path = runtime.join("bus");
    let bus_path = bus_path.to_str()?;
    if bus_path.contains([',', ';']) {
        return None;
    }
    let expected = format!("unix:path={bus_path}");
    if address.to_str()? != expected {
        return None;
    }

    let workspace = open_identity_directory(workspace).ok()?;
    let provider_home = open_provider_directory(provider_home).ok()?;
    let workspace_identity = directory_identity(&workspace).ok()?;
    let provider_identity = directory_identity(&provider_home).ok()?;
    let mut directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .ok()?;
    if !linux_runtime_ancestor_is_replacement_safe(&directory.metadata().ok()?) {
        return None;
    }
    let root_identity = directory_identity(&directory).ok()?;
    if root_identity == workspace_identity || root_identity == provider_identity {
        return None;
    }
    for component in runtime.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(component) => {
                let component = CString::new(component.as_bytes()).ok()?;
                // SAFETY: the parent descriptor is live and component is a
                // component-only, NUL-terminated string.
                let descriptor = unsafe {
                    libc::openat(
                        directory.as_raw_fd(),
                        component.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if descriptor < 0 {
                    return None;
                }
                // SAFETY: openat returned a new owned descriptor.
                directory = unsafe { File::from_raw_fd(descriptor) };
                if !linux_runtime_ancestor_is_replacement_safe(&directory.metadata().ok()?) {
                    return None;
                }
                let identity = directory_identity(&directory).ok()?;
                if identity == workspace_identity || identity == provider_identity {
                    return None;
                }
            }
            _ => return None,
        }
    }

    let metadata = directory.metadata().ok()?;
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
        return None;
    }
    let bus = CString::new("bus").ok()?;
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: directory is live, bus is NUL-terminated, and status is writable.
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            bus.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return None;
    }
    // SAFETY: fstatat succeeded.
    let status = unsafe { status.assume_init() };
    // SAFETY: geteuid has no preconditions.
    if status.st_uid != unsafe { libc::geteuid() }
        || status.st_mode & libc::S_IFMT != libc::S_IFSOCK
    {
        return None;
    }
    let held_runtime_identity = directory_identity(&directory).ok()?;
    let rebound_runtime = open_identity_directory(&runtime).ok()?;
    if directory_identity(&rebound_runtime).ok()? != held_runtime_identity {
        return None;
    }
    Some((runtime.into_os_string(), address))
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn linux_runtime_ancestor_is_replacement_safe(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: geteuid has no preconditions.
    let effective_user = unsafe { libc::geteuid() };
    if !metadata.is_dir() || (metadata.uid() != 0 && metadata.uid() != effective_user) {
        return false;
    }
    let mode = metadata.mode();
    mode & 0o022 == 0 || (metadata.uid() == 0 && mode & 0o1000 != 0)
}

#[cfg(unix)]
fn minimal_system_path() -> Result<OsString, SidecarError> {
    Ok(OsString::from("/usr/bin:/bin:/usr/sbin:/sbin"))
}

#[cfg(windows)]
fn minimal_system_path() -> Result<OsString, SidecarError> {
    use std::os::windows::ffi::OsStringExt;

    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

    // Windows' documented maximum extended path length is 32,767 UTF-16 code units.
    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: `buffer` is writable for its full declared length.
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    let length = usize::try_from(length)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::SpawnFailed))?;
    if length == 0 || length >= buffer.len() {
        return Err(SidecarError::from_code(SidecarErrorCode::SpawnFailed));
    }
    buffer.truncate(length);
    let windows = PathBuf::from(OsString::from_wide(&buffer));
    env::join_paths([windows.join("System32"), windows])
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::SpawnFailed))
}

#[cfg(windows)]
struct WindowsSystemEnvironment {
    windows: PathBuf,
    system_drive: PathBuf,
    comspec: PathBuf,
}

#[cfg(windows)]
fn windows_system_environment() -> Result<WindowsSystemEnvironment, SidecarError> {
    use std::os::windows::ffi::OsStringExt;

    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: buffer is valid writable storage for its declared length.
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    let length = usize::try_from(length)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::SpawnFailed))?;
    if length == 0 || length >= buffer.len() {
        return Err(SidecarError::from_code(SidecarErrorCode::SpawnFailed));
    }
    buffer.truncate(length);
    let windows = PathBuf::from(OsString::from_wide(&buffer));
    let system_drive = windows
        .ancestors()
        .last()
        .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::SpawnFailed))?
        .to_path_buf();
    let comspec = windows.join("System32").join("cmd.exe");
    Ok(WindowsSystemEnvironment {
        windows,
        system_drive,
        comspec,
    })
}

#[cfg(unix)]
fn set_owner_only_child_umask(command: &mut Command) {
    // SAFETY: `umask` is async-signal-safe and this closure performs no allocation.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o077);
            Ok(())
        });
    }
}

#[cfg(windows)]
fn set_owner_only_child_umask(_command: &mut Command) {}

fn prepare_provider_home(
    data_root: &Path,
    workspace: &Path,
    provider_home: &Path,
) -> Result<(), SidecarError> {
    let relative = preflight_provider_home(data_root, workspace, provider_home)?;
    create_provider_home(data_root, &relative)?;

    // Lexical prefix checks are not a security boundary on case-insensitive filesystems
    // or in the presence of Windows short-name aliases. Compare opened directory
    // identities after the traversal has completed.
    let canonical_root = fs::canonicalize(data_root)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    let canonical_workspace = fs::canonicalize(workspace)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    let canonical_home = fs::canonicalize(provider_home)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    if directory_paths_overlap(&canonical_home, &canonical_workspace)? {
        return Err(SidecarError::from_code(
            SidecarErrorCode::InvalidProviderHome,
        ));
    }
    let mut found_data_root = false;
    for ancestor in canonical_home.ancestors() {
        if same_directory_identity(ancestor, &canonical_root)? {
            found_data_root = true;
        }
    }
    if !found_data_root {
        return Err(SidecarError::from_code(
            SidecarErrorCode::InvalidProviderHome,
        ));
    }
    Ok(())
}

fn preflight_provider_home(
    data_root: &Path,
    workspace: &Path,
    provider_home: &Path,
) -> Result<PathBuf, SidecarError> {
    if !data_root.is_absolute() || !workspace.is_absolute() || !provider_home.is_absolute() {
        return Err(SidecarError::from_code(
            SidecarErrorCode::InvalidProviderHome,
        ));
    }
    let relative = provider_home
        .strip_prefix(data_root)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(SidecarError::from_code(
            SidecarErrorCode::InvalidProviderHome,
        ));
    }
    let relative = relative.to_path_buf();

    let root_metadata = fs::symlink_metadata(data_root)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    if !root_metadata.is_dir() || is_link_or_reparse(&root_metadata) {
        return Err(SidecarError::from_code(
            SidecarErrorCode::InvalidProviderHome,
        ));
    }
    let workspace_metadata = fs::symlink_metadata(workspace)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    if !workspace_metadata.is_dir() || is_link_or_reparse(&workspace_metadata) {
        return Err(SidecarError::from_code(
            SidecarErrorCode::InvalidProviderHome,
        ));
    }

    let canonical_root = fs::canonicalize(data_root)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    let canonical_workspace = fs::canonicalize(workspace)
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    if directory_is_same_or_ancestor(&canonical_workspace, &canonical_root)? {
        return Err(SidecarError::from_code(
            SidecarErrorCode::InvalidProviderHome,
        ));
    }
    preflight_existing_provider_prefixes(data_root, &relative, &canonical_workspace)?;
    Ok(relative)
}

#[cfg(unix)]
fn preflight_existing_provider_prefixes(
    data_root: &Path,
    relative: &Path,
    workspace: &Path,
) -> Result<(), SidecarError> {
    use std::ffi::CString;
    use std::fs::OpenOptions;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    fn invalid_home() -> SidecarError {
        SidecarError::from_code(SidecarErrorCode::InvalidProviderHome)
    }

    let workspace_directory = open_identity_directory(workspace)?;
    let workspace_identity = directory_identity(&workspace_directory)?;
    let workspace_ancestors = directory_ancestor_identities(workspace)?;
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(data_root)
        .map_err(|_| invalid_home())?;
    if directory_identity(&directory)? == workspace_identity {
        return Err(invalid_home());
    }
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(invalid_home());
        };
        let component = CString::new(component.as_bytes()).map_err(|_| invalid_home())?;
        // SAFETY: the parent descriptor is live and component is a component-only
        // NUL-terminated string.
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(invalid_home())
            };
        }
        // SAFETY: openat returned a new owned descriptor.
        let next = unsafe { File::from_raw_fd(descriptor) };
        verify_owned_directory(&next)?;
        if workspace_ancestors.contains(&directory_identity(&next)?) {
            return Err(invalid_home());
        }
        directory = next;
    }
    Ok(())
}

#[cfg(windows)]
fn preflight_existing_provider_prefixes(
    data_root: &Path,
    relative: &Path,
    workspace: &Path,
) -> Result<(), SidecarError> {
    let workspace_ancestors = directory_ancestor_identities(workspace)?;
    let mut path = data_root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(SidecarError::from_code(
                SidecarErrorCode::InvalidProviderHome,
            ));
        };
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() && !is_link_or_reparse(&metadata) => {
                let directory = open_provider_directory(&path)?;
                if workspace_ancestors.contains(&directory_identity(&directory)?) {
                    return Err(SidecarError::from_code(
                        SidecarErrorCode::InvalidProviderHome,
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            _ => {
                return Err(SidecarError::from_code(
                    SidecarErrorCode::InvalidProviderHome,
                ));
            }
        }
    }
    Ok(())
}

fn directory_ancestor_identities(path: &Path) -> Result<Vec<DirectoryIdentity>, SidecarError> {
    path.ancestors()
        .map(|ancestor| {
            let directory = open_identity_directory(ancestor)?;
            directory_identity(&directory)
        })
        .collect()
}

fn directory_is_same_or_ancestor(ancestor: &Path, path: &Path) -> Result<bool, SidecarError> {
    for candidate in path.ancestors() {
        if same_directory_identity(ancestor, candidate)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn directory_paths_overlap(left: &Path, right: &Path) -> Result<bool, SidecarError> {
    Ok(directory_is_same_or_ancestor(left, right)? || directory_is_same_or_ancestor(right, left)?)
}

#[cfg(unix)]
fn same_directory_identity(left: &Path, right: &Path) -> Result<bool, SidecarError> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    fn open(path: &Path) -> Result<File, SidecarError> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))
    }
    let left = open(left)?
        .metadata()
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    let right = open(right)?
        .metadata()
        .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(unix)]
fn write_static_provider_file(
    home: &ProviderHome,
    filename: &Path,
    contents: &[u8],
) -> Result<(), SidecarError> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct Identity {
        device: libc::dev_t,
        inode: libc::ino_t,
    }

    fn unsafe_file() -> SidecarError {
        SidecarError::from_code(SidecarErrorCode::UnsafeProviderFile)
    }

    fn inspect(directory: libc::c_int, name: &CString) -> Result<Option<Identity>, SidecarError> {
        let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: directory is a live capability and name is NUL-terminated.
        let result = unsafe {
            libc::fstatat(
                directory,
                name.as_ptr(),
                status.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(unsafe_file())
            };
        }
        // SAFETY: fstatat succeeded.
        let status = unsafe { status.assume_init() };
        // SAFETY: geteuid has no preconditions.
        let effective_user = unsafe { libc::geteuid() };
        if status.st_mode & libc::S_IFMT != libc::S_IFREG
            || status.st_uid != effective_user
            || status.st_nlink != 1
            || status.st_mode & 0o777 != 0o600
        {
            return Err(unsafe_file());
        }
        Ok(Some(Identity {
            device: status.st_dev,
            inode: status.st_ino,
        }))
    }

    let directory = home.directory.as_raw_fd();
    let filename = CString::new(filename.as_os_str().as_bytes()).map_err(|_| unsafe_file())?;
    let before = inspect(directory, &filename)?;
    let serial = NEXT_STATIC_FILE.fetch_add(1, Ordering::Relaxed);
    let temporary = CString::new(format!(".carl-static-{}-{serial}.tmp", std::process::id()))
        .map_err(|_| unsafe_file())?;
    // SAFETY: directory is live and temporary is a component-only C string.
    let descriptor = unsafe {
        libc::openat(
            directory,
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(unsafe_file());
    }
    // SAFETY: openat returned a new owned descriptor.
    let mut temporary_file = unsafe { File::from_raw_fd(descriptor) };
    let result = (|| {
        // SAFETY: the descriptor is live and owned by temporary_file.
        if unsafe { libc::fchmod(temporary_file.as_raw_fd(), 0o600) } != 0 {
            return Err(unsafe_file());
        }
        temporary_file
            .write_all(contents)
            .map_err(|_| unsafe_file())?;
        temporary_file.sync_all().map_err(|_| unsafe_file())?;

        if inspect(directory, &filename)? != before {
            return Err(unsafe_file());
        }
        // SAFETY: both names are component-only C strings relative to the same live
        // directory capability. renameat atomically replaces a verified target.
        if unsafe { libc::renameat(directory, temporary.as_ptr(), directory, filename.as_ptr()) }
            != 0
        {
            return Err(unsafe_file());
        }
        let _ = inspect(directory, &filename)?.ok_or_else(unsafe_file)?;
        // SAFETY: fsync on the live directory persists the rename where supported.
        if unsafe { libc::fsync(directory) } != 0 {
            return Err(unsafe_file());
        }
        Ok(())
    })();
    drop(temporary_file);
    if result.is_err() {
        // SAFETY: best-effort cleanup of the component-only temporary name.
        let _ = unsafe { libc::unlinkat(directory, temporary.as_ptr(), 0) };
    }
    result
}

#[cfg(unix)]
fn inspect_provider_file(
    home: &ProviderHome,
    filename: &Path,
    maximum_bytes: u64,
) -> Result<ProviderFileMetadata, SidecarError> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    let unsafe_file = || SidecarError::from_code(SidecarErrorCode::UnsafeProviderFile);
    let filename = CString::new(filename.as_os_str().as_bytes()).map_err(|_| unsafe_file())?;
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the held directory capability is live, filename is NUL-terminated,
    // and status points to writable storage.
    if unsafe {
        libc::fstatat(
            home.directory.as_raw_fd(),
            filename.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            Ok(ProviderFileMetadata::Missing)
        } else {
            Err(unsafe_file())
        };
    }
    // SAFETY: fstatat succeeded.
    let status = unsafe { status.assume_init() };
    // SAFETY: geteuid has no preconditions.
    let effective_user = unsafe { libc::geteuid() };
    let size = u64::try_from(status.st_size).map_err(|_| unsafe_file())?;
    if status.st_mode & libc::S_IFMT != libc::S_IFREG
        || status.st_uid != effective_user
        || status.st_nlink != 1
        || status.st_mode & 0o777 != 0o600
        || size > maximum_bytes
    {
        return Err(unsafe_file());
    }
    Ok(ProviderFileMetadata::Safe)
}

#[cfg(windows)]
fn same_directory_identity(left: &Path, right: &Path) -> Result<bool, SidecarError> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    fn identity(path: &Path) -> Result<WindowsFileIdentity, SidecarError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
        let metadata = file
            .metadata()
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
        if is_link_or_reparse(&metadata) {
            return Err(SidecarError::from_code(
                SidecarErrorCode::InvalidProviderHome,
            ));
        }
        windows_file_identity(&file)
            .map_err(|()| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))
    }
    Ok(identity(left)? == identity(right)?)
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct WindowsFileIdentity {
    volume_serial: u32,
    file_index: u64,
    links: u32,
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> Result<WindowsFileIdentity, ()> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: file owns a live handle and information points to writable storage.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), information.as_mut_ptr()) }
        == 0
    {
        return Err(());
    }
    // SAFETY: the API call succeeded and initialized the structure.
    let information = unsafe { information.assume_init() };
    Ok(WindowsFileIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        links: information.nNumberOfLinks,
    })
}

#[cfg(windows)]
pub(crate) fn create_relative_private_file(
    directory: &impl std::os::windows::io::AsRawHandle,
    name: &std::ffi::OsStr,
) -> Result<File, ()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::ptr;

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT,
        FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
    };
    use windows_sys::Win32::Security::SECURITY_DESCRIPTOR;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let mut name: Vec<u16> = name.encode_wide().collect();
    if name.is_empty() || name.contains(&0) {
        return Err(());
    }
    let name_bytes = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or(())?;
    let maximum_bytes = name_bytes
        .checked_add(std::mem::size_of::<u16>())
        .ok_or(())?;
    name.push(0);
    let object_name = UNICODE_STRING {
        Length: u16::try_from(name_bytes).map_err(|_| ())?,
        MaximumLength: u16::try_from(maximum_bytes).map_err(|_| ())?,
        Buffer: name.as_mut_ptr(),
    };
    let security = windows_security::owner_only_file_security_descriptor()?;
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>()).map_err(|_| ())?,
        RootDirectory: directory.as_raw_handle(),
        ObjectName: &object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: security.as_ptr().cast::<SECURITY_DESCRIPTOR>(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle: HANDLE = ptr::null_mut();
    // SAFETY: all structures and buffers remain live for the call, RootDirectory is
    // an owned directory handle, and FILE_CREATE makes the component exclusive.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES | DELETE | READ_CONTROL | SYNCHRONIZE,
            &attributes,
            &mut status,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            ptr::null(),
            0,
        )
    };
    if result < 0 || handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(());
    }
    // SAFETY: NtCreateFile returned one new owned file handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
pub(crate) fn create_relative_private_directory(
    directory: &impl std::os::windows::io::AsRawHandle,
    name: &std::ffi::OsStr,
) -> Result<File, ()> {
    open_relative_private_directory_with_disposition(
        directory,
        name,
        windows_sys::Wdk::Storage::FileSystem::FILE_CREATE,
    )
}

#[cfg(windows)]
pub(crate) fn open_relative_private_directory(
    directory: &impl std::os::windows::io::AsRawHandle,
    name: &std::ffi::OsStr,
) -> Result<File, ()> {
    open_relative_private_directory_with_disposition(
        directory,
        name,
        windows_sys::Wdk::Storage::FileSystem::FILE_OPEN,
    )
}

#[cfg(windows)]
fn open_relative_private_directory_with_disposition(
    directory: &impl std::os::windows::io::AsRawHandle,
    name: &std::ffi::OsStr,
    disposition: windows_sys::Wdk::Storage::FileSystem::NTCREATEFILE_CREATE_DISPOSITION,
) -> Result<File, ()> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::ptr;

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
    };
    use windows_sys::Win32::Security::SECURITY_DESCRIPTOR;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, READ_CONTROL, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let mut name: Vec<u16> = name.encode_wide().collect();
    if name.is_empty() || name.contains(&0) {
        return Err(());
    }
    let name_bytes = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or(())?;
    let maximum_bytes = name_bytes
        .checked_add(std::mem::size_of::<u16>())
        .ok_or(())?;
    name.push(0);
    let object_name = UNICODE_STRING {
        Length: u16::try_from(name_bytes).map_err(|_| ())?,
        MaximumLength: u16::try_from(maximum_bytes).map_err(|_| ())?,
        Buffer: name.as_mut_ptr(),
    };
    let security = windows_security::owner_only_directory_security_descriptor()?;
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>()).map_err(|_| ())?,
        RootDirectory: directory.as_raw_handle(),
        ObjectName: &object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: security.as_ptr().cast::<SECURITY_DESCRIPTOR>(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle: HANDLE = ptr::null_mut();
    // SAFETY: every structure and backing buffer remains live for the call,
    // RootDirectory is a held private directory, and disposition is either FILE_OPEN
    // or FILE_CREATE. Creation is exclusive and applies the protected current-user
    // DACL; opening preserves the existing descriptor for subsequent verification.
    // Do not request DELETE here: later identity checks open a second directory
    // handle without FILE_SHARE_DELETE, and Windows requires that handle to share
    // every access requested by this one. Omitting FILE_SHARE_DELETE still pins the
    // directory against rename and deletion while the capability remains live.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | SYNCHRONIZE,
            &attributes,
            &mut status,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            disposition,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            ptr::null(),
            0,
        )
    };
    if result < 0 || handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(());
    }
    // SAFETY: NtCreateFile returned one owned non-inheritable directory handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn open_or_create_relative_private_lock_file(directory: &File) -> Result<File, ()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr;

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_NON_DIRECTORY_FILE, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
        FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{
        HANDLE, INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, UNICODE_STRING,
    };
    use windows_sys::Win32::Security::SECURITY_DESCRIPTOR;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, READ_CONTROL, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    let mut name: Vec<u16> = OsStr::new(DATA_ROOT_LOCK_FILENAME).encode_wide().collect();
    let name_bytes = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .ok_or(())?;
    let maximum_bytes = name_bytes
        .checked_add(std::mem::size_of::<u16>())
        .ok_or(())?;
    name.push(0);
    let object_name = UNICODE_STRING {
        Length: u16::try_from(name_bytes).map_err(|_| ())?,
        MaximumLength: u16::try_from(maximum_bytes).map_err(|_| ())?,
        Buffer: name.as_mut_ptr(),
    };
    let security = windows_security::owner_only_file_security_descriptor()?;
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>()).map_err(|_| ())?,
        RootDirectory: directory.as_raw_handle(),
        ObjectName: &object_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: security.as_ptr().cast::<SECURITY_DESCRIPTOR>(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut status = IO_STATUS_BLOCK::default();
    let mut handle: HANDLE = ptr::null_mut();
    // SAFETY: all structures and buffers remain live, RootDirectory is a held
    // owner-private directory, and FILE_OPEN_IF atomically opens or creates only the
    // fixed non-reparse component.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | SYNCHRONIZE,
            &attributes,
            &mut status,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            ptr::null(),
            0,
        )
    };
    if result < 0 || handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(());
    }
    // SAFETY: NtCreateFile returned one new owned non-inheritable file handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn delete_file_on_close(file: &File) -> Result<(), ()> {
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };

    let information = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: the file handle is live and was opened with DELETE access; information
    // points to a correctly sized disposition structure for the duration of the call.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&raw const information).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>()).map_err(|_| ())?,
        )
    } == 0
    {
        Err(())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn write_static_provider_file(
    home: &ProviderHome,
    filename: &Path,
    contents: &[u8],
) -> Result<(), SidecarError> {
    use std::fs::OpenOptions;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_RENAME_INFORMATION, FileRenameInformation, NtSetInformationFile,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    fn unsafe_file() -> SidecarError {
        SidecarError::from_code(SidecarErrorCode::UnsafeProviderFile)
    }

    fn inspect(path: &Path) -> Result<Option<WindowsFileIdentity>, SidecarError> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(unsafe_file()),
        };
        if !metadata.file_type().is_file() || is_link_or_reparse(&metadata) {
            return Err(unsafe_file());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|_| unsafe_file())?;
        let metadata = file.metadata().map_err(|_| unsafe_file())?;
        if !metadata.file_type().is_file() || is_link_or_reparse(&metadata) {
            return Err(unsafe_file());
        }
        let identity = windows_file_identity(&file).map_err(|()| unsafe_file())?;
        if identity.links != 1 {
            return Err(unsafe_file());
        }
        windows_security::verify_private_file_handle(&file).map_err(|()| unsafe_file())?;
        Ok(Some(identity))
    }

    let held_home = windows_file_identity(&home.directory).map_err(|()| unsafe_file())?;
    let reopened_home = open_provider_directory(&home.canonical_path).map_err(|_| unsafe_file())?;
    let reopened_home = windows_file_identity(&reopened_home).map_err(|()| unsafe_file())?;
    if held_home.volume_serial != reopened_home.volume_serial
        || held_home.file_index != reopened_home.file_index
    {
        return Err(unsafe_file());
    }

    let target = home.canonical_path.join(filename);
    let before = inspect(&target)?;
    let serial = NEXT_STATIC_FILE.fetch_add(1, Ordering::Relaxed);
    let temporary_name =
        OsString::from(format!(".carl-static-{}-{serial}.tmp", std::process::id()));
    let mut temporary_file = create_relative_private_file(&home.directory, &temporary_name)
        .map_err(|()| unsafe_file())?;
    let result = (|| {
        let temporary_identity =
            windows_file_identity(&temporary_file).map_err(|()| unsafe_file())?;
        if temporary_identity.links != 1 {
            return Err(unsafe_file());
        }
        windows_security::verify_private_file_handle(&temporary_file)
            .map_err(|()| unsafe_file())?;
        home.revalidate_bindings().map_err(|_| unsafe_file())?;
        temporary_file
            .write_all(contents)
            .map_err(|_| unsafe_file())?;
        temporary_file.sync_all().map_err(|_| unsafe_file())?;
        windows_security::verify_private_file_handle(&temporary_file)
            .map_err(|()| unsafe_file())?;
        if inspect(&target)? != before {
            return Err(unsafe_file());
        }
        home.revalidate_bindings().map_err(|_| unsafe_file())?;
        let target_name: Vec<u16> = filename.as_os_str().encode_wide().collect();
        let filename_bytes = target_name
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .ok_or_else(unsafe_file)?;
        // Windows requires at least the complete fixed structure plus the supplied
        // filename bytes, even though FileName begins before the structure's trailing
        // alignment padding.
        let bytes = std::mem::size_of::<FILE_RENAME_INFORMATION>()
            .checked_add(filename_bytes)
            .ok_or_else(unsafe_file)?;
        let words = bytes.div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let information = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        let filename_bytes = u32::try_from(filename_bytes).map_err(|_| unsafe_file())?;
        // SAFETY: storage is aligned and sized for the fixed structure plus target name.
        unsafe {
            (*information).Anonymous.ReplaceIfExists = true;
            // NtSetInformationFile interprets a simple name with a null root as a
            // rename within the already-open source file's actual parent directory.
            (*information).RootDirectory = std::ptr::null_mut();
            (*information).FileNameLength = filename_bytes;
            std::ptr::copy_nonoverlapping(
                target_name.as_ptr(),
                std::ptr::addr_of_mut!((*information).FileName).cast::<u16>(),
                target_name.len(),
            );
        }
        let bytes = u32::try_from(bytes).map_err(|_| unsafe_file())?;
        let mut io_status = IO_STATUS_BLOCK::default();
        // SAFETY: the temporary file remains open, io_status is writable, and
        // information points to a correctly sized FILE_RENAME_INFORMATION containing
        // a simple same-directory name.
        let rename_status = unsafe {
            NtSetInformationFile(
                temporary_file.as_raw_handle(),
                &mut io_status,
                information.cast(),
                bytes,
                FileRenameInformation,
            )
        };
        if rename_status < 0 {
            return Err(unsafe_file());
        }
        let after = windows_file_identity(&temporary_file).map_err(|()| unsafe_file())?;
        if after != temporary_identity || after.links != 1 {
            return Err(unsafe_file());
        }
        windows_security::verify_private_file_handle(&temporary_file)
            .map_err(|()| unsafe_file())?;
        let named_identity = inspect(&target)?.ok_or_else(unsafe_file)?;
        if named_identity != temporary_identity {
            return Err(unsafe_file());
        }
        home.revalidate_bindings().map_err(|_| unsafe_file())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = delete_file_on_close(&temporary_file);
    }
    result
}

#[cfg(windows)]
fn inspect_provider_file(
    home: &ProviderHome,
    filename: &Path,
    maximum_bytes: u64,
) -> Result<ProviderFileMetadata, SidecarError> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let unsafe_file = || SidecarError::from_code(SidecarErrorCode::UnsafeProviderFile);
    let path = home.canonical_path.join(filename);
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            home.revalidate_bindings()?;
            return Ok(ProviderFileMetadata::Missing);
        }
        Err(_) => return Err(unsafe_file()),
    };
    home.revalidate_bindings()?;
    let metadata = file.metadata().map_err(|_| unsafe_file())?;
    let identity = windows_file_identity(&file).map_err(|()| unsafe_file())?;
    if !metadata.file_type().is_file()
        || is_link_or_reparse(&metadata)
        || identity.links != 1
        || metadata.len() > maximum_bytes
    {
        return Err(unsafe_file());
    }
    windows_security::verify_private_file_handle(&file).map_err(|()| unsafe_file())?;
    Ok(ProviderFileMetadata::Safe)
}

#[cfg(unix)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn create_provider_home(data_root: &Path, relative: &Path) -> Result<(), SidecarError> {
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;

    fn invalid_home() -> SidecarError {
        SidecarError::from_code(SidecarErrorCode::InvalidProviderHome)
    }

    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(data_root)
        .map_err(|_| invalid_home())?;
    verify_owned_directory(&directory)?;

    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(invalid_home());
        };
        let component = CString::new(component.as_bytes()).map_err(|_| invalid_home())?;
        // SAFETY: both the live directory fd and NUL-terminated component pointer are valid.
        let created = unsafe { libc::mkdirat(directory.as_raw_fd(), component.as_ptr(), 0o700) };
        if created != 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(invalid_home());
        }
        // SAFETY: openat receives a live directory fd and a valid component-only C string.
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if descriptor < 0 {
            return Err(invalid_home());
        }
        // SAFETY: `descriptor` was just returned by openat and ownership transfers to File.
        let next = unsafe { File::from_raw_fd(descriptor) };
        verify_owned_directory(&next)?;
        // SAFETY: `next` owns a live directory descriptor.
        if unsafe { libc::fchmod(next.as_raw_fd(), 0o700) } != 0 {
            return Err(invalid_home());
        }
        directory = next;
    }
    Ok(())
}

#[cfg(unix)]
fn verify_owned_directory(directory: &std::fs::File) -> Result<(), SidecarError> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    let mut status = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the descriptor is live and `status` points to writable stat storage.
    if unsafe { libc::fstat(directory.as_raw_fd(), status.as_mut_ptr()) } != 0 {
        return Err(SidecarError::from_code(
            SidecarErrorCode::InvalidProviderHome,
        ));
    }
    // SAFETY: fstat succeeded and initialized the structure.
    let status = unsafe { status.assume_init() };
    // SAFETY: geteuid has no preconditions.
    let effective_user = unsafe { libc::geteuid() };
    if status.st_uid != effective_user
        || status.st_mode & libc::S_IFMT != libc::S_IFDIR
        || status.st_mode & 0o022 != 0
    {
        return Err(SidecarError::from_code(
            SidecarErrorCode::InvalidProviderHome,
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn create_provider_home(data_root: &Path, relative: &Path) -> Result<(), SidecarError> {
    use std::os::windows::ffi::OsStrExt;

    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    let mut path = data_root.to_path_buf();
    windows_security::verify_private_directory(&path)
        .map_err(|()| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    for component in relative.components() {
        let Component::Normal(component) = component else {
            return Err(SidecarError::from_code(
                SidecarErrorCode::InvalidProviderHome,
            ));
        };
        path.push(component);
        let security = windows_security::owner_only_directory_security_descriptor()
            .map_err(|()| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?,
            lpSecurityDescriptor: security.as_ptr().cast_mut().cast(),
            bInheritHandle: 0,
        };
        let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide_path.push(0);
        // SAFETY: wide_path is NUL-terminated and attributes references a live,
        // protected owner-only security descriptor for the duration of the call.
        if unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(SidecarError::from_code(
                    SidecarErrorCode::InvalidProviderHome,
                ));
            }
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
        if !metadata.is_dir() || is_link_or_reparse(&metadata) {
            return Err(SidecarError::from_code(
                SidecarErrorCode::InvalidProviderHome,
            ));
        }
        windows_security::verify_private_directory(&path)
            .map_err(|()| SidecarError::from_code(SidecarErrorCode::InvalidProviderHome))?;
    }
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(windows)]
pub(crate) mod windows_security {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Component, Path, Prefix};
    use std::ptr;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT,
        ACL, ACL_REVISION, AccessCheck, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
        DACL_SECURITY_INFORMATION, DuplicateToken, EqualSid, GENERIC_MAPPING,
        GROUP_SECURITY_INFORMATION, GetAce, GetLengthSid, GetTokenInformation, INHERIT_ONLY_ACE,
        InitializeAcl, InitializeSecurityDescriptor, IsValidSid, IsWellKnownSid,
        LookupAccountNameW, MapGenericMask, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
        PRIVILEGE_SET, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_DESCRIPTOR,
        SECURITY_MAX_SID_SIZE, SecurityImpersonation, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl, SetSecurityDescriptorOwner, TOKEN_DUPLICATE, TOKEN_QUERY,
        TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_ALL_ACCESS, FILE_APPEND_DATA,
        FILE_DELETE_CHILD, FILE_EXECUTE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_ATTRIBUTES,
        FILE_WRITE_DATA, FILE_WRITE_EA, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    #[derive(Clone, Copy)]
    enum OwnerPolicy {
        TrustedExecutable,
        CurrentUserPrivate,
    }

    #[derive(Clone, Copy)]
    enum ObjectKind {
        File,
        Directory,
        LocalDriveRoot,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DaclVerificationFailure {
        CurrentUser,
        SecurityInfo,
        OwnerPolicy,
        BroadWriter,
        EffectiveAccess,
    }

    // AccessCheck rejects a descriptor without both owner and primary-group SIDs.
    // GROUP_SECURITY_INFORMATION populates the group inside ppSecurityDescriptor;
    // its separate ppGroup output pointer may remain null because callers do not
    // inspect that component directly.
    const ACCESS_CHECK_SECURITY_INFORMATION: u32 =
        DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;

    pub(super) fn verify_trusted_executable_component(
        path: &Path,
        ancestor_depth: usize,
    ) -> Result<(), ()> {
        verify_dacl(
            path,
            OwnerPolicy::TrustedExecutable,
            executable_component_kind(path, ancestor_depth),
        )
        .map_err(|_| ())
    }

    fn executable_component_kind(path: &Path, ancestor_depth: usize) -> ObjectKind {
        if ancestor_depth == 0 {
            ObjectKind::File
        } else if is_local_drive_root(path) {
            ObjectKind::LocalDriveRoot
        } else {
            // All non-root directories stay closed to adjacent DLL, configuration,
            // plugin, metadata, and reparse-point planting.
            ObjectKind::Directory
        }
    }

    fn is_local_drive_root(path: &Path) -> bool {
        let mut components = path.components();
        matches!(
            components.next(),
            Some(Component::Prefix(prefix))
                if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        ) && matches!(components.next(), Some(Component::RootDir))
            && components.next().is_none()
    }

    pub(crate) fn verify_private_directory(path: &Path) -> Result<(), ()> {
        verify_dacl(path, OwnerPolicy::CurrentUserPrivate, ObjectKind::Directory).map_err(|_| ())
    }

    pub(crate) fn verify_private_file_handle(file: &impl AsRawHandle) -> Result<(), ()> {
        verify_private_handle(file, ObjectKind::File)
    }

    pub(crate) fn verify_private_directory_handle(file: &impl AsRawHandle) -> Result<(), ()> {
        verify_private_handle(file, ObjectKind::Directory)
    }

    fn verify_private_handle(file: &impl AsRawHandle, object_kind: ObjectKind) -> Result<(), ()> {
        let current_user = CurrentUser::query()?;
        let mut dacl = ptr::null_mut::<ACL>();
        let mut owner: PSID = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: the file handle is live and all output pointers are writable.
        let result = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                ACCESS_CHECK_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        let _descriptor = LocalDescriptor(descriptor);
        if result != 0 || descriptor.is_null() || dacl.is_null() || owner.is_null() {
            return Err(());
        }
        validate_descriptor(
            descriptor,
            dacl,
            owner,
            &current_user,
            OwnerPolicy::CurrentUserPrivate,
            object_kind,
        )
        .map_err(|_| ())
    }

    struct LocalDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: GetNamedSecurityInfoW allocated this descriptor with LocalAlloc.
                let _ = unsafe { LocalFree(self.0) };
            }
        }
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: this handle was returned by OpenProcessToken and is closed once.
                let _ = unsafe { CloseHandle(self.0) };
            }
        }
    }

    struct CurrentUser {
        storage: Vec<usize>,
        token: OwnedHandle,
    }

    impl CurrentUser {
        fn query() -> Result<Self, ()> {
            let mut token = ptr::null_mut();
            // SAFETY: token points to writable handle storage.
            if unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    &mut token,
                )
            } == 0
                || token.is_null()
            {
                return Err(());
            }
            let token = OwnedHandle(token);
            let mut impersonation_token = ptr::null_mut();
            // SAFETY: token is live and impersonation_token is writable.
            if unsafe { DuplicateToken(token.0, SecurityImpersonation, &mut impersonation_token) }
                == 0
                || impersonation_token.is_null()
            {
                return Err(());
            }
            let impersonation_token = OwnedHandle(impersonation_token);
            let mut required = 0_u32;
            // SAFETY: the first call intentionally queries the required byte count.
            let _ = unsafe {
                GetTokenInformation(
                    impersonation_token.0,
                    TokenUser,
                    ptr::null_mut(),
                    0,
                    &mut required,
                )
            };
            if required < u32::try_from(std::mem::size_of::<TOKEN_USER>()).map_err(|_| ())? {
                return Err(());
            }
            let word = std::mem::size_of::<usize>();
            let words = usize::try_from(required)
                .map_err(|_| ())?
                .checked_add(word - 1)
                .ok_or(())?
                / word;
            let mut storage = vec![0_usize; words];
            // SAFETY: storage is aligned and large enough for the requested TOKEN_USER bytes.
            if unsafe {
                GetTokenInformation(
                    impersonation_token.0,
                    TokenUser,
                    storage.as_mut_ptr().cast::<c_void>(),
                    required,
                    &mut required,
                )
            } == 0
            {
                return Err(());
            }
            let user = Self {
                storage,
                token: impersonation_token,
            };
            // SAFETY: the successful query initialized TOKEN_USER at the buffer start.
            if unsafe { IsValidSid(user.sid()) } == 0 {
                return Err(());
            }
            Ok(user)
        }

        fn sid(&self) -> PSID {
            // SAFETY: query initialized TOKEN_USER and storage lives for this borrow.
            unsafe { (*(self.storage.as_ptr().cast::<TOKEN_USER>())).User.Sid }
        }
    }

    pub(super) struct OwnerOnlySecurityDescriptor {
        _current_user: CurrentUser,
        _acl: Vec<usize>,
        descriptor: SECURITY_DESCRIPTOR,
    }

    impl OwnerOnlySecurityDescriptor {
        pub(super) fn as_ptr(&self) -> *const SECURITY_DESCRIPTOR {
            &raw const self.descriptor
        }
    }

    pub(super) fn owner_only_file_security_descriptor() -> Result<OwnerOnlySecurityDescriptor, ()> {
        owner_only_security_descriptor(0)
    }

    pub(super) fn owner_only_directory_security_descriptor()
    -> Result<OwnerOnlySecurityDescriptor, ()> {
        owner_only_security_descriptor(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)
    }

    fn owner_only_security_descriptor(ace_flags: u32) -> Result<OwnerOnlySecurityDescriptor, ()> {
        let current_user = CurrentUser::query()?;
        // SAFETY: CurrentUser::query validated the SID and its backing storage is live.
        let sid_bytes =
            usize::try_from(unsafe { GetLengthSid(current_user.sid()) }).map_err(|_| ())?;
        let acl_bytes = std::mem::size_of::<ACL>()
            .checked_add(std::mem::size_of::<ACCESS_ALLOWED_ACE>())
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<u32>()))
            .and_then(|bytes| bytes.checked_add(sid_bytes))
            .ok_or(())?;
        let word = std::mem::size_of::<usize>();
        let words = acl_bytes.checked_add(word - 1).ok_or(())? / word;
        let mut acl = vec![0_usize; words];
        let acl_pointer = acl.as_mut_ptr().cast::<ACL>();
        let acl_length = u32::try_from(acl_bytes).map_err(|_| ())?;
        // SAFETY: acl is aligned writable storage of acl_length bytes.
        if unsafe { InitializeAcl(acl_pointer, acl_length, ACL_REVISION) } == 0 {
            return Err(());
        }
        // SAFETY: initialized ACL has capacity for one full allow ACE and the SID
        // remains live in current_user for the lifetime of the resulting descriptor.
        if unsafe {
            AddAccessAllowedAceEx(
                acl_pointer,
                ACL_REVISION,
                ace_flags,
                FILE_ALL_ACCESS,
                current_user.sid(),
            )
        } == 0
        {
            return Err(());
        }
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        let descriptor_pointer = (&raw mut descriptor).cast::<c_void>();
        // SAFETY: descriptor is writable storage for a SECURITY_DESCRIPTOR.
        if unsafe { InitializeSecurityDescriptor(descriptor_pointer, SECURITY_DESCRIPTOR_REVISION) }
            == 0
        {
            return Err(());
        }
        // SAFETY: descriptor is initialized and the owner SID remains live in the
        // CurrentUser field stored alongside it.
        if unsafe { SetSecurityDescriptorOwner(descriptor_pointer, current_user.sid(), 0) } == 0 {
            return Err(());
        }
        // SAFETY: descriptor and initialized ACL are live and stored together.
        if unsafe { SetSecurityDescriptorDacl(descriptor_pointer, 1, acl_pointer, 0) } == 0 {
            return Err(());
        }
        // SAFETY: descriptor is initialized; protecting its DACL prevents inherited
        // parent ACEs from being merged during object creation.
        if unsafe {
            SetSecurityDescriptorControl(descriptor_pointer, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
        } == 0
        {
            return Err(());
        }
        Ok(OwnerOnlySecurityDescriptor {
            _current_user: current_user,
            _acl: acl,
            descriptor,
        })
    }

    fn verify_dacl(
        path: &Path,
        owner_policy: OwnerPolicy,
        object_kind: ObjectKind,
    ) -> Result<(), DaclVerificationFailure> {
        let current_user =
            CurrentUser::query().map_err(|()| DaclVerificationFailure::CurrentUser)?;
        let mut path: Vec<u16> = path.as_os_str().encode_wide().collect();
        path.push(0);
        let mut dacl = ptr::null_mut::<ACL>();
        let mut owner: PSID = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: all output pointers are valid and `path` is NUL-terminated for this call.
        let result = unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                ACCESS_CHECK_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        // Install RAII immediately: Windows may return a descriptor even on a later
        // validation failure.
        let _descriptor = LocalDescriptor(descriptor);
        if result != 0 || dacl.is_null() || owner.is_null() || descriptor.is_null() {
            return Err(DaclVerificationFailure::SecurityInfo);
        }
        validate_descriptor(
            descriptor,
            dacl,
            owner,
            &current_user,
            owner_policy,
            object_kind,
        )
    }

    fn validate_descriptor(
        descriptor: PSECURITY_DESCRIPTOR,
        dacl: *mut ACL,
        owner: PSID,
        current_user: &CurrentUser,
        owner_policy: OwnerPolicy,
        object_kind: ObjectKind,
    ) -> Result<(), DaclVerificationFailure> {
        // SAFETY: owner and current-user SIDs are valid and live with their buffers.
        let owner_is_current = unsafe { EqualSid(owner, current_user.sid()) } != 0;
        // SAFETY: owner was returned by GetNamedSecurityInfoW in the live descriptor.
        let owner_is_privileged = is_privileged_sid(owner);
        let owner_allowed = match owner_policy {
            OwnerPolicy::TrustedExecutable => owner_is_current || owner_is_privileged,
            OwnerPolicy::CurrentUserPrivate => owner_is_current,
        };
        if !owner_allowed {
            return Err(DaclVerificationFailure::OwnerPolicy);
        }
        // SAFETY: DACL and all owner/current-user storage remain live for this call.
        unsafe {
            dacl_has_safe_writers(
                dacl,
                current_user.sid(),
                matches!(owner_policy, OwnerPolicy::CurrentUserPrivate),
                object_kind,
            )
        }
        .then_some(())
        .ok_or(DaclVerificationFailure::BroadWriter)?;
        verify_effective_current_user_access(descriptor, current_user, owner_policy, object_kind)
            .map_err(|()| DaclVerificationFailure::EffectiveAccess)
    }

    fn is_trusted_installer_sid(candidate: PSID) -> bool {
        const TRUSTED_INSTALLER: &str = r"NT SERVICE\TrustedInstaller";
        const MAX_DOMAIN_CHARS: u32 = 256;

        let account: Vec<u16> = TRUSTED_INSTALLER.encode_utf16().chain(Some(0)).collect();
        let mut sid_bytes = 0_u32;
        let mut domain_chars = 0_u32;
        let mut sid_type = 0;
        // SAFETY: null output buffers with zero lengths perform the documented size query.
        let _ = unsafe {
            LookupAccountNameW(
                ptr::null(),
                account.as_ptr(),
                ptr::null_mut(),
                &mut sid_bytes,
                ptr::null_mut(),
                &mut domain_chars,
                &mut sid_type,
            )
        };
        if sid_bytes == 0 || sid_bytes > SECURITY_MAX_SID_SIZE || domain_chars > MAX_DOMAIN_CHARS {
            return false;
        }

        let word = std::mem::size_of::<usize>();
        let Some(sid_words) = usize::try_from(sid_bytes)
            .ok()
            .and_then(|bytes| bytes.checked_add(word - 1))
            .map(|bytes| bytes / word)
        else {
            return false;
        };
        let Ok(domain_len) = usize::try_from(domain_chars) else {
            return false;
        };
        let mut sid = vec![0_usize; sid_words];
        let mut domain = vec![0_u16; domain_len];
        let domain_pointer = if domain.is_empty() {
            ptr::null_mut()
        } else {
            domain.as_mut_ptr()
        };
        // SAFETY: both output buffers are aligned and sized by the preceding query.
        if unsafe {
            LookupAccountNameW(
                ptr::null(),
                account.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut sid_bytes,
                domain_pointer,
                &mut domain_chars,
                &mut sid_type,
            )
        } == 0
        {
            return false;
        }
        let trusted_installer: PSID = sid.as_mut_ptr().cast();
        // SAFETY: the successful lookup initialized the bounded SID buffer; candidate
        // comes from a live security descriptor and was validated by Windows.
        unsafe { IsValidSid(trusted_installer) != 0 && EqualSid(candidate, trusted_installer) != 0 }
    }

    fn is_privileged_sid(candidate: PSID) -> bool {
        // SAFETY: candidate comes from a size-checked ACE or a live Windows
        // security descriptor and has already passed SID validation.
        (unsafe {
            IsWellKnownSid(candidate, WinLocalSystemSid) != 0
                || IsWellKnownSid(candidate, WinBuiltinAdministratorsSid) != 0
        }) || is_trusted_installer_sid(candidate)
    }

    unsafe fn dacl_has_safe_writers(
        dacl: *mut ACL,
        current_user: PSID,
        private: bool,
        object_kind: ObjectKind,
    ) -> bool {
        // SAFETY: caller validated the DACL pointer returned by Windows.
        let ace_count = unsafe { (*dacl).AceCount };
        let mapping = generic_mapping();
        let dangerous_mask = dangerous_mask(object_kind);
        for index in 0..u32::from(ace_count) {
            let mut ace = ptr::null_mut();
            // SAFETY: DACL is live and `ace` is a valid output pointer.
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
                return false;
            }
            // SAFETY: GetAce returned a pointer to at least an ACE header.
            let header = unsafe { &*(ace.cast::<ACE_HEADER>()) };
            if !allow_ace_requires_private_policy_check(
                u32::from(header.AceFlags),
                private,
                object_kind,
            ) {
                continue;
            }
            let ace_size = usize::from(header.AceSize);
            let (mut mask, sid, remaining) = match u32::from(header.AceType) {
                ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
                    let sid_offset = 8;
                    if ace_size < sid_offset + 8 {
                        return false;
                    }
                    // SAFETY: the checked ACE size contains header, mask, and SID prefix.
                    let mask = unsafe { *ace.cast::<u8>().add(4).cast::<u32>() };
                    // SAFETY: same size check; standard allow ACE SID starts after the mask.
                    let sid = unsafe { ace.cast::<u8>().add(8) };
                    (mask, sid, ace_size - sid_offset)
                }
                ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                    if ace_size < 20 {
                        return false;
                    }
                    // SAFETY: object allow ACE has mask and flags at fixed aligned offsets.
                    let mask = unsafe { *ace.cast::<u8>().add(4).cast::<u32>() };
                    // SAFETY: same checked fixed layout.
                    let flags = unsafe { *ace.cast::<u8>().add(8).cast::<u32>() };
                    let mut sid_offset = 12;
                    if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
                        sid_offset += 16;
                    }
                    if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                        sid_offset += 16;
                    }
                    if sid_offset + 8 > ace_size {
                        return false;
                    }
                    // SAFETY: variable offset was bounded by the ACE's declared size.
                    let sid = unsafe { ace.cast::<u8>().add(sid_offset) };
                    (mask, sid, ace_size - sid_offset)
                }
                ACCESS_ALLOWED_COMPOUND_ACE_TYPE => return false,
                _ => continue,
            };
            let sid: PSID = sid.cast();
            // SAFETY: the SID pointer comes from a size-bounded allow ACE layout.
            if !unsafe { sid_fits_ace(sid, remaining) } {
                return false;
            }
            // SAFETY: mask is writable and mapping is initialized.
            unsafe { MapGenericMask(&mut mask, &mapping) };
            // SAFETY: both SIDs have been validated and are live.
            let is_current_user = unsafe { EqualSid(sid, current_user) } != 0;
            // SAFETY: sid passed IsValidSid above.
            let is_privileged = is_privileged_sid(sid);
            if private && mask != 0 && !is_current_user && !is_privileged {
                return false;
            }
            if mask & dangerous_mask == 0 {
                continue;
            }
            if is_current_user {
                continue;
            }
            if !is_privileged {
                return false;
            }
        }
        true
    }

    fn generic_mapping() -> GENERIC_MAPPING {
        GENERIC_MAPPING {
            GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE,
            GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS,
        }
    }

    const fn ace_applies_to_object(flags: u32) -> bool {
        flags & INHERIT_ONLY_ACE == 0
    }

    const fn allow_ace_requires_private_policy_check(
        flags: u32,
        private: bool,
        object_kind: ObjectKind,
    ) -> bool {
        ace_applies_to_object(flags)
            || (private
                && matches!(
                    object_kind,
                    ObjectKind::Directory | ObjectKind::LocalDriveRoot
                )
                && flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) != 0)
    }

    const fn dangerous_mask(object_kind: ObjectKind) -> u32 {
        match object_kind {
            ObjectKind::File => {
                FILE_WRITE_DATA
                    | FILE_APPEND_DATA
                    | FILE_WRITE_EA
                    | FILE_WRITE_ATTRIBUTES
                    | DELETE
                    | WRITE_DAC
                    | WRITE_OWNER
            }
            ObjectKind::Directory => {
                FILE_ADD_FILE
                    | FILE_ADD_SUBDIRECTORY
                    | FILE_WRITE_EA
                    | FILE_WRITE_ATTRIBUTES
                    | FILE_DELETE_CHILD
                    | DELETE
                    | WRITE_DAC
                    | WRITE_OWNER
            }
            ObjectKind::LocalDriveRoot => {
                FILE_ADD_FILE
                    | FILE_WRITE_EA
                    | FILE_WRITE_ATTRIBUTES
                    | FILE_DELETE_CHILD
                    | DELETE
                    | WRITE_DAC
                    | WRITE_OWNER
            }
        }
    }

    fn verify_effective_current_user_access(
        descriptor: PSECURITY_DESCRIPTOR,
        current_user: &CurrentUser,
        owner_policy: OwnerPolicy,
        object_kind: ObjectKind,
    ) -> Result<(), ()> {
        let desired = match (owner_policy, object_kind) {
            (OwnerPolicy::TrustedExecutable, ObjectKind::File) => {
                FILE_READ_DATA | FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL
            }
            (
                OwnerPolicy::TrustedExecutable,
                ObjectKind::Directory | ObjectKind::LocalDriveRoot,
            ) => FILE_EXECUTE | FILE_READ_ATTRIBUTES | READ_CONTROL,
            (OwnerPolicy::CurrentUserPrivate, ObjectKind::File) => {
                FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL
            }
            (
                OwnerPolicy::CurrentUserPrivate,
                ObjectKind::Directory | ObjectKind::LocalDriveRoot,
            ) => {
                FILE_READ_DATA
                    | FILE_ADD_FILE
                    | FILE_ADD_SUBDIRECTORY
                    | FILE_DELETE_CHILD
                    | FILE_READ_ATTRIBUTES
                    | READ_CONTROL
            }
        };
        let mapping = generic_mapping();
        let mut privilege_bytes =
            u32::try_from(std::mem::size_of::<PRIVILEGE_SET>()).map_err(|_| ())?;
        let word = std::mem::size_of::<usize>();
        let words = usize::try_from(privilege_bytes)
            .map_err(|_| ())?
            .checked_add(word - 1)
            .ok_or(())?
            / word;
        let mut privilege_storage = vec![0_usize; words];
        let mut granted = 0_u32;
        let mut access_status = 0;
        // SAFETY: descriptor and token are live; every output buffer is aligned,
        // writable, and sized by privilege_bytes.
        if unsafe {
            AccessCheck(
                descriptor,
                current_user.token.0,
                desired,
                &mapping,
                privilege_storage.as_mut_ptr().cast::<PRIVILEGE_SET>(),
                &mut privilege_bytes,
                &mut granted,
                &mut access_status,
            )
        } == 0
            || access_status == 0
            || granted & desired != desired
        {
            Err(())
        } else {
            Ok(())
        }
    }

    unsafe fn sid_fits_ace(sid: PSID, remaining: usize) -> bool {
        // SAFETY: caller bounded the SID header within the ACE.
        if unsafe { IsValidSid(sid) } == 0 {
            return false;
        }
        // SAFETY: IsValidSid succeeded.
        let length = usize::try_from(unsafe { GetLengthSid(sid) }).unwrap_or(usize::MAX);
        length <= remaining
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn current_test_executable_ancestry_satisfies_policy() {
            let executable = std::env::current_exe().expect("current test executable has a path");
            for (ancestor_depth, component) in executable.ancestors().enumerate() {
                let object_kind = executable_component_kind(component, ancestor_depth);
                if let Err(error) =
                    verify_dacl(component, OwnerPolicy::TrustedExecutable, object_kind)
                {
                    panic!(
                        "trusted-executable policy rejected {} at ancestor depth \
                         {ancestor_depth}: {error:?}",
                        component.display()
                    );
                }
            }
        }

        fn world_allow_acl_is_safe(
            mask: u32,
            object_kind: ObjectKind,
            current_user: &CurrentUser,
        ) -> bool {
            use windows_sys::Win32::Security::{
                CreateWellKnownSid, SECURITY_MAX_SID_SIZE, WinWorldSid,
            };

            let word = std::mem::size_of::<usize>();
            let sid_words = usize::try_from(SECURITY_MAX_SID_SIZE)
                .expect("maximum SID size fits usize")
                .div_ceil(word);
            let mut sid = vec![0_usize; sid_words];
            let mut sid_bytes = SECURITY_MAX_SID_SIZE;
            // SAFETY: sid is aligned writable storage of SECURITY_MAX_SID_SIZE bytes.
            assert_ne!(
                unsafe {
                    CreateWellKnownSid(
                        WinWorldSid,
                        ptr::null_mut(),
                        sid.as_mut_ptr().cast(),
                        &mut sid_bytes,
                    )
                },
                0
            );
            let acl_bytes = std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>()
                - std::mem::size_of::<u32>()
                + usize::try_from(sid_bytes).expect("SID size fits usize");
            let mut acl = vec![0_usize; acl_bytes.div_ceil(word)];
            let acl_pointer = acl.as_mut_ptr().cast::<ACL>();
            // SAFETY: ACL storage is aligned, writable, and large enough.
            assert_ne!(
                unsafe {
                    InitializeAcl(
                        acl_pointer,
                        u32::try_from(acl_bytes).expect("ACL size fits u32"),
                        ACL_REVISION,
                    )
                },
                0
            );
            // SAFETY: ACL is initialized and the world SID remains live.
            assert_ne!(
                unsafe {
                    AddAccessAllowedAceEx(
                        acl_pointer,
                        ACL_REVISION,
                        0,
                        mask,
                        sid.as_mut_ptr().cast(),
                    )
                },
                0
            );
            // SAFETY: ACL and both SID buffers remain live for validation.
            unsafe { dacl_has_safe_writers(acl_pointer, current_user.sid(), false, object_kind) }
        }

        #[test]
        fn inherit_only_allow_aces_do_not_apply_to_the_current_object() {
            assert!(!ace_applies_to_object(INHERIT_ONLY_ACE));
            assert!(ace_applies_to_object(0));
        }

        #[test]
        fn private_directories_reject_broad_inheritable_allow_aces() {
            use windows_sys::Win32::Security::{
                CreateWellKnownSid, SECURITY_MAX_SID_SIZE, WinWorldSid,
            };

            for inheritance in [OBJECT_INHERIT_ACE, CONTAINER_INHERIT_ACE] {
                assert!(allow_ace_requires_private_policy_check(
                    INHERIT_ONLY_ACE | inheritance,
                    true,
                    ObjectKind::Directory,
                ));
                assert!(!allow_ace_requires_private_policy_check(
                    INHERIT_ONLY_ACE | inheritance,
                    true,
                    ObjectKind::File,
                ));
                assert!(!allow_ace_requires_private_policy_check(
                    INHERIT_ONLY_ACE | inheritance,
                    false,
                    ObjectKind::Directory,
                ));

                let word = std::mem::size_of::<usize>();
                let sid_words = usize::try_from(SECURITY_MAX_SID_SIZE)
                    .expect("maximum SID size fits usize")
                    .div_ceil(word);
                let mut sid = vec![0_usize; sid_words];
                let mut sid_bytes = SECURITY_MAX_SID_SIZE;
                // SAFETY: sid is aligned writable storage of SECURITY_MAX_SID_SIZE bytes.
                assert_ne!(
                    unsafe {
                        CreateWellKnownSid(
                            WinWorldSid,
                            ptr::null_mut(),
                            sid.as_mut_ptr().cast(),
                            &mut sid_bytes,
                        )
                    },
                    0
                );
                let acl_bytes = std::mem::size_of::<ACL>()
                    + std::mem::size_of::<ACCESS_ALLOWED_ACE>()
                    - std::mem::size_of::<u32>()
                    + usize::try_from(sid_bytes).expect("SID size fits usize");
                let mut acl = vec![0_usize; acl_bytes.div_ceil(word)];
                let acl_pointer = acl.as_mut_ptr().cast::<ACL>();
                // SAFETY: ACL storage is aligned, writable, and large enough.
                assert_ne!(
                    unsafe {
                        InitializeAcl(
                            acl_pointer,
                            u32::try_from(acl_bytes).expect("ACL size fits u32"),
                            ACL_REVISION,
                        )
                    },
                    0
                );
                // SAFETY: ACL is initialized and the world SID remains live.
                assert_ne!(
                    unsafe {
                        AddAccessAllowedAceEx(
                            acl_pointer,
                            ACL_REVISION,
                            INHERIT_ONLY_ACE | inheritance,
                            FILE_GENERIC_READ,
                            sid.as_mut_ptr().cast(),
                        )
                    },
                    0
                );
                let current_user = CurrentUser::query().expect("current user SID is available");
                // SAFETY: ACL and both SID buffers remain live for validation.
                assert!(!unsafe {
                    dacl_has_safe_writers(
                        acl_pointer,
                        current_user.sid(),
                        true,
                        ObjectKind::Directory,
                    )
                });
            }
        }

        #[test]
        fn owner_only_directory_descriptor_propagates_private_access() {
            use windows_sys::Win32::Security::GetSecurityDescriptorDacl;

            fn ace_flags(descriptor: &OwnerOnlySecurityDescriptor) -> u32 {
                let mut present = 0;
                let mut defaulted = 0;
                let mut dacl = ptr::null_mut::<ACL>();
                // SAFETY: descriptor and every output pointer remain live for the call.
                assert_ne!(
                    unsafe {
                        GetSecurityDescriptorDacl(
                            descriptor.as_ptr().cast_mut().cast(),
                            &mut present,
                            &mut dacl,
                            &mut defaulted,
                        )
                    },
                    0
                );
                assert_ne!(present, 0);
                assert!(!dacl.is_null());
                let mut ace = ptr::null_mut();
                // SAFETY: the initialized owner-only DACL contains exactly one ACE.
                assert_ne!(unsafe { GetAce(dacl, 0, &mut ace) }, 0);
                // SAFETY: GetAce returned a live ACE header in descriptor-owned storage.
                u32::from(unsafe { (*(ace.cast::<ACE_HEADER>())).AceFlags })
            }

            let directory = owner_only_directory_security_descriptor()
                .expect("owner-only directory descriptor is built");
            assert_eq!(
                ace_flags(&directory) & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE),
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            );
            let file =
                owner_only_file_security_descriptor().expect("owner-only file descriptor is built");
            assert_eq!(
                ace_flags(&file) & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE),
                0
            );
        }

        #[test]
        fn replacement_rights_are_interpreted_by_object_kind() {
            assert_eq!(dangerous_mask(ObjectKind::File) & FILE_DELETE_CHILD, 0);
            assert_ne!(dangerous_mask(ObjectKind::Directory) & FILE_DELETE_CHILD, 0);
            assert_ne!(dangerous_mask(ObjectKind::File) & FILE_WRITE_EA, 0);
            assert_ne!(dangerous_mask(ObjectKind::Directory) & FILE_WRITE_EA, 0);
        }

        #[test]
        fn local_drive_root_subdirectory_creation_does_not_imply_replacement() {
            let mask = dangerous_mask(ObjectKind::LocalDriveRoot);
            assert_eq!(mask & FILE_ADD_SUBDIRECTORY, 0);
            for replacement_right in [
                FILE_ADD_FILE,
                FILE_WRITE_EA,
                FILE_WRITE_ATTRIBUTES,
                FILE_DELETE_CHILD,
                DELETE,
                WRITE_DAC,
                WRITE_OWNER,
            ] {
                assert_ne!(mask & replacement_right, 0);
            }
        }

        #[test]
        fn broad_acl_drive_root_exception_is_subdirectory_only() {
            let current_user = CurrentUser::query().expect("current user SID is available");

            assert!(world_allow_acl_is_safe(
                FILE_ADD_SUBDIRECTORY,
                ObjectKind::LocalDriveRoot,
                &current_user,
            ));
            assert!(!world_allow_acl_is_safe(
                FILE_ADD_SUBDIRECTORY,
                ObjectKind::Directory,
                &current_user,
            ));
            for rejected_mask in [
                FILE_ADD_FILE,
                FILE_WRITE_ATTRIBUTES,
                FILE_WRITE_EA,
                FILE_DELETE_CHILD,
                DELETE,
                WRITE_DAC,
                WRITE_OWNER,
                windows_sys::Win32::Foundation::GENERIC_WRITE,
            ] {
                assert!(!world_allow_acl_is_safe(
                    rejected_mask,
                    ObjectKind::LocalDriveRoot,
                    &current_user,
                ));
            }
        }

        #[test]
        fn local_drive_root_classifier_excludes_ancestors_and_unc_roots() {
            for root in [Path::new(r"C:\"), Path::new(r"\\?\C:\")] {
                assert!(is_local_drive_root(root));
            }
            for not_root in [
                Path::new(r"C:\Users"),
                Path::new(r"\\server\share\"),
                Path::new(r"\\?\UNC\server\share\"),
            ] {
                assert!(!is_local_drive_root(not_root));
            }
        }

        #[test]
        fn every_non_root_directory_keeps_creation_and_generic_write_dangerous() {
            let mask = dangerous_mask(ObjectKind::Directory);
            assert_ne!(mask & FILE_ADD_FILE, 0);
            assert_ne!(mask & FILE_ADD_SUBDIRECTORY, 0);
            assert_ne!(mask & FILE_WRITE_EA, 0);
            assert_ne!(mask & FILE_WRITE_ATTRIBUTES, 0);

            let mut generic_write = windows_sys::Win32::Foundation::GENERIC_WRITE;
            // SAFETY: generic_write is writable and generic_mapping is initialized.
            unsafe { MapGenericMask(&mut generic_write, &generic_mapping()) };
            assert_ne!(mask & generic_write, 0);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn dropping_foreground_wait_starts_kill_and_allows_bounded_reap() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let child = spawn_grouped_unchecked(command).expect("foreground fixture spawns");
        let process_id = child.id().expect("foreground fixture has a PID");
        let limits = SidecarLimits {
            graceful_shutdown_timeout: Duration::from_millis(25),
            forced_shutdown_timeout: Duration::from_secs(2),
            process_poll_interval: Duration::from_millis(5),
            ..SidecarLimits::default()
        };
        let mut foreground = ForegroundProcess {
            process: Arc::new(Mutex::new(SidecarProcessGuard::new(child))),
            terminal: None,
            limits,
        };
        let mut wait = Box::pin(foreground.wait());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut wait)
                .await
                .is_err()
        );
        drop(wait);
        foreground
            .cancel()
            .await
            .expect("cancel reaps after the wait guard starts termination");
        // SAFETY: signal zero performs a non-mutating process-existence check.
        assert_eq!(unsafe { libc::kill(process_id as libc::pid_t, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[test]
    fn terminal_lease_marks_restored_only_after_success() {
        let mut lease = ForegroundTerminalLease {
            terminal_fd: -1,
            // SAFETY: getpgrp has no preconditions.
            parent_group: unsafe { libc::getpgrp() },
            restored: false,
        };
        assert_eq!(
            lease
                .restore()
                .expect_err("an invalid terminal fd must fail")
                .code(),
            SidecarErrorCode::ForegroundRequired
        );
        assert!(!lease.restored);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn foreground_cancel_propagates_terminal_restore_failure() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let child = spawn_grouped_unchecked(command).expect("foreground fixture spawns");
        let mut foreground = ForegroundProcess {
            process: Arc::new(Mutex::new(SidecarProcessGuard::new(child))),
            terminal: Some(ForegroundTerminalLease {
                terminal_fd: -1,
                // SAFETY: getpgrp has no preconditions.
                parent_group: unsafe { libc::getpgrp() },
                restored: false,
            }),
            limits: SidecarLimits {
                graceful_shutdown_timeout: Duration::from_millis(25),
                forced_shutdown_timeout: Duration::from_secs(2),
                process_poll_interval: Duration::from_millis(5),
                ..SidecarLimits::default()
            },
        };
        assert_eq!(
            foreground
                .cancel()
                .await
                .expect_err("terminal restoration failure must be surfaced")
                .code(),
            SidecarErrorCode::ForegroundRequired
        );
        assert!(
            foreground
                .terminal
                .as_ref()
                .is_some_and(|lease| !lease.restored)
        );
    }

    #[test]
    fn runtime_ancestor_policy_rejects_current_user_writable_parents() {
        use std::os::unix::fs::PermissionsExt;

        let root = env::temp_dir().join(format!(
            "carl-runtime-ancestor-policy-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("test ancestor is created");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777))
            .expect("replaceable mode is installed");
        assert!(!linux_runtime_ancestor_is_replacement_safe(
            &fs::metadata(&root).expect("replaceable ancestor metadata is available")
        ));
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("private mode is installed");
        assert!(linux_runtime_ancestor_is_replacement_safe(
            &fs::metadata(&root).expect("private ancestor metadata is available")
        ));
        fs::remove_dir(root).expect("test ancestor is removed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_keyring_environment_requires_exact_private_socket_transport() {
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;

        let root = env::temp_dir().join(format!("carl-keyring-environment-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let workspace = root.join("workspace");
        let home = root.join("provider");
        let runtime = root.join("runtime");
        for directory in [&workspace, &home, &runtime] {
            fs::create_dir_all(directory).expect("test directory is created");
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("test directory mode is private");
        }
        let bus = runtime.join("bus");
        let _listener = UnixListener::bind(&bus).expect("test D-Bus socket binds");
        let address = OsString::from(format!(
            "unix:path={}",
            bus.to_str().expect("test path is UTF-8")
        ));
        assert!(
            validated_linux_keyring_environment(
                Some(runtime.clone().into_os_string()),
                Some(address.clone()),
                &workspace,
                &home,
            )
            .is_some()
        );
        assert!(
            validated_linux_keyring_environment(
                Some(runtime.into_os_string()),
                Some(OsString::from(format!(
                    "{};tcp:host=attacker",
                    address.to_string_lossy()
                ))),
                &workspace,
                &home,
            )
            .is_none()
        );

        let unsafe_parent = root.join("unsafe-parent");
        let nested_runtime = unsafe_parent.join("runtime");
        fs::create_dir_all(&nested_runtime).expect("nested runtime is created");
        fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777))
            .expect("unsafe ancestor mode is installed");
        fs::set_permissions(&nested_runtime, fs::Permissions::from_mode(0o700))
            .expect("nested runtime remains private");
        let nested_bus = nested_runtime.join("bus");
        let _nested_listener = UnixListener::bind(&nested_bus).expect("nested D-Bus socket binds");
        let nested_address = OsString::from(format!(
            "unix:path={}",
            nested_bus.to_str().expect("nested test path is UTF-8")
        ));
        assert!(
            validated_linux_keyring_environment(
                Some(nested_runtime.into_os_string()),
                Some(nested_address),
                &workspace,
                &home,
            )
            .is_none(),
            "a private runtime below a replaceable ancestor must be rejected"
        );
        fs::remove_dir_all(root).expect("test directories are removed");
    }
}

#[cfg(all(test, windows))]
mod windows_static_file_tests {
    use super::*;
    use std::ffi::OsStr;
    use std::io::Write;

    #[test]
    fn owner_only_file_handle_verification_uses_a_complete_descriptor() {
        let serial = NEXT_STATIC_FILE.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!(
            "carl-windows-private-handle-{}-{serial}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("test root is created");
        let directory = open_identity_directory(&root).expect("test root opens by identity");
        let temporary_name = OsStr::new("owner-only.tmp");
        let temporary = create_relative_private_file(&directory, temporary_name)
            .expect("owner-only temporary file is created");

        let identity = windows_file_identity(&temporary)
            .expect("the creation handle permits exact identity inspection");
        assert_eq!(identity.links, 1);
        windows_security::verify_private_file_handle(&temporary)
            .expect("AccessCheck receives owner, group, and DACL for the exact created handle");

        delete_file_on_close(&temporary).expect("temporary file is marked for deletion");
        drop(temporary);
        fs::remove_dir_all(root).expect("test root is removed");
    }

    #[test]
    fn static_temporary_creation_and_cleanup_remain_bound_to_open_handles() {
        let serial = NEXT_STATIC_FILE.fetch_add(1, Ordering::Relaxed);
        let root = env::temp_dir().join(format!(
            "carl-windows-relative-static-{}-{serial}",
            std::process::id()
        ));
        let moved_root = root.with_extension("moved");
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&moved_root);
        fs::create_dir(&root).expect("test root is created");
        let directory = open_identity_directory(&root).expect("test root opens by identity");
        fs::rename(&root, &moved_root).expect("held root is renamed");
        fs::create_dir(&root).expect("ambient replacement root is created");

        let temporary_name = OsStr::new("same-name.tmp");
        let mut temporary = create_relative_private_file(&directory, temporary_name)
            .expect("temporary file is created below the held directory");
        windows_security::verify_private_file_handle(&temporary)
            .expect("temporary file is atomically owner-only");
        temporary
            .write_all(b"held")
            .expect("held temporary is writable");
        assert!(moved_root.join(temporary_name).is_file());
        assert!(!root.join(temporary_name).exists());

        let renamed = moved_root.join("renamed.tmp");
        fs::rename(moved_root.join(temporary_name), &renamed).expect("the held file is renamed");
        fs::write(moved_root.join(temporary_name), b"replacement")
            .expect("same-name replacement is created");
        delete_file_on_close(&temporary).expect("held temporary is marked for deletion");
        drop(temporary);
        assert!(!renamed.exists(), "the exact held file is deleted");
        assert_eq!(
            fs::read(moved_root.join(temporary_name)).expect("replacement remains readable"),
            b"replacement",
            "cleanup must not delete an ambient same-name replacement"
        );

        fs::remove_dir_all(root).expect("ambient replacement root is removed");
        fs::remove_dir_all(moved_root).expect("moved root is removed");
    }
}
