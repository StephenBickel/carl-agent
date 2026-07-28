use std::fmt;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::process::{ChildStdout, Command};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};
use tokio::task::{AbortHandle, JoinHandle};

use super::jsonl::read_bounded_line;
use super::{
    DirectoryIdentity, ProviderHome, REDACTED_STDERR, STATE_CANCELLING, STATE_RUNNING,
    STATE_STOPPED, SidecarCommand, SidecarError, SidecarErrorCode, SidecarLimits,
    SidecarProcessGuard, StderrCapture, TrustedExecutable, detect_version, directory_identity,
    force_kill_and_reap, is_link_or_reparse, lock, open_identity_directory,
    set_owner_only_child_umask, spawn_trusted_grouped, stderr_worker, terminate_process,
};

const EVENT_CHANNEL_CAPACITY: usize = 64;
const MAX_STDIN_BYTES: usize = 64 * 1_024;

pub struct ExecutionWorkspace {
    canonical_path: PathBuf,
    directory: File,
    identity: DirectoryIdentity,
}

impl ExecutionWorkspace {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SidecarError> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(invalid_workspace());
        }
        let metadata = fs::symlink_metadata(path).map_err(|_| invalid_workspace())?;
        if !metadata.is_dir() || is_link_or_reparse(&metadata) {
            return Err(invalid_workspace());
        }
        let canonical_path = fs::canonicalize(path).map_err(|_| invalid_workspace())?;
        let directory = open_identity_directory(&canonical_path)?;
        let identity = directory_identity(&directory)?;
        Ok(Self {
            canonical_path,
            directory,
            identity,
        })
    }

    fn configure_command(&self, command: &mut Command) -> Result<(), SidecarError> {
        self.revalidate()?;
        command.current_dir(&self.canonical_path);
        Ok(())
    }

    fn matches_path(&self, path: &Path) -> Result<bool, SidecarError> {
        self.revalidate()?;
        let named = open_identity_directory(path)?;
        Ok(directory_identity(&named)? == self.identity)
    }

    fn revalidate(&self) -> Result<(), SidecarError> {
        let named = open_identity_directory(&self.canonical_path)?;
        if directory_identity(&self.directory)? != self.identity
            || directory_identity(&named)? != self.identity
        {
            return Err(invalid_workspace());
        }
        Ok(())
    }
}

impl fmt::Debug for ExecutionWorkspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExecutionWorkspace(<opaque>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonlProcessOutcome {
    Succeeded,
    Failed,
    Cancelled,
    ProtocolFailed,
    TimedOut,
}

pub struct JsonlEventProcess {
    process: Arc<Mutex<SidecarProcessGuard>>,
    events: AsyncMutex<mpsc::Receiver<Result<serde_json::Value, SidecarError>>>,
    completion: Option<oneshot::Receiver<JsonlProcessOutcome>>,
    cached_outcome: Option<JsonlProcessOutcome>,
    supervisor: Option<JoinHandle<()>>,
    task_aborts: Vec<AbortHandle>,
    state: Arc<AtomicU8>,
    stderr: Arc<Mutex<StderrCapture>>,
    limits: SidecarLimits,
}

impl fmt::Debug for JsonlEventProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonlEventProcess")
            .field("state", &self.state.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl JsonlEventProcess {
    pub async fn spawn_in_home(
        specification: SidecarCommand,
        executable: &TrustedExecutable,
        home: &ProviderHome,
        workspace: &ExecutionWorkspace,
        stdin_payload: &[u8],
        limits: SidecarLimits,
    ) -> Result<Self, SidecarError> {
        let limits = limits.validate()?;
        if stdin_payload.len() > MAX_STDIN_BYTES
            || !workspace.matches_path(&home.canonical_workspace)?
        {
            return Err(SidecarError::from_code(
                SidecarErrorCode::InvalidConfiguration,
            ));
        }
        detect_version(&specification, executable, home, limits).await?;

        let mut command = Command::new(executable.canonical_path());
        command
            .args(&specification.arguments)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        home.configure_command(&mut command)?;
        workspace.configure_command(&mut command)?;
        set_owner_only_child_umask(&mut command);

        let mut child = spawn_trusted_grouped(executable, command)?;
        let mut stdin = child
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
        let stderr_task = tokio::spawn(stderr_worker(
            stderr_pipe,
            Arc::clone(&stderr),
            limits.max_stderr_bytes,
        ));
        let stderr_abort = stderr_task.abort_handle();

        let write_result = tokio::time::timeout(limits.graceful_shutdown_timeout, async {
            stdin.write_all(stdin_payload).await?;
            stdin.shutdown().await
        })
        .await;
        if !matches!(write_result, Ok(Ok(()))) {
            stderr_task.abort();
            let _ = stderr_task.await;
            let _ = force_kill_and_reap(&process, limits).await;
            return Err(SidecarError::from_code(match write_result {
                Err(_) => SidecarErrorCode::TimedOut,
                Ok(Err(_)) | Ok(Ok(())) => SidecarErrorCode::SidecarExited,
            }));
        }

        let (stdout_tx, stdout_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let stdout_task =
            tokio::spawn(read_stdout(stdout, limits.max_stdout_line_bytes, stdout_tx));
        let stdout_abort = stdout_task.abort_handle();
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let (completion_tx, completion_rx) = oneshot::channel();
        let supervisor = tokio::spawn(supervise(
            Arc::clone(&process),
            Arc::clone(&state),
            stdout_rx,
            event_tx,
            stdout_task,
            stderr_task,
            completion_tx,
            limits,
        ));
        let supervisor_abort = supervisor.abort_handle();

        Ok(Self {
            process,
            events: AsyncMutex::new(event_rx),
            completion: Some(completion_rx),
            cached_outcome: None,
            supervisor: Some(supervisor),
            task_aborts: vec![stdout_abort, stderr_abort, supervisor_abort],
            state,
            stderr,
            limits,
        })
    }

    pub async fn next_event(&self) -> Result<Option<serde_json::Value>, SidecarError> {
        let mut events = self.events.lock().await;
        match events.recv().await {
            Some(Ok(event)) => Ok(Some(event)),
            Some(Err(error)) => Err(error),
            None => Ok(None),
        }
    }

    pub async fn wait(&mut self) -> Result<JsonlProcessOutcome, SidecarError> {
        if let Some(outcome) = self.cached_outcome {
            return Ok(outcome);
        }
        let completion = self
            .completion
            .take()
            .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::SidecarExited))?;
        let outcome = completion
            .await
            .map_err(|_| SidecarError::from_code(SidecarErrorCode::SidecarExited))?;
        if let Some(supervisor) = self.supervisor.take() {
            let _ = supervisor.await;
        }
        self.cached_outcome = Some(outcome);
        Ok(outcome)
    }

    pub async fn cancel(&mut self) -> Result<(), SidecarError> {
        if self.state.load(Ordering::Acquire) == STATE_STOPPED {
            return Ok(());
        }
        self.state.store(STATE_CANCELLING, Ordering::Release);
        let result = terminate_process(&self.process, self.limits).await;
        for abort in &self.task_aborts {
            abort.abort();
        }
        if let Some(supervisor) = self.supervisor.take() {
            let _ = supervisor.await;
        }
        self.completion = None;
        self.cached_outcome = Some(JsonlProcessOutcome::Cancelled);
        self.state.store(STATE_STOPPED, Ordering::Release);
        result
    }

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
}

impl Drop for JsonlEventProcess {
    fn drop(&mut self) {
        self.state.store(STATE_CANCELLING, Ordering::Release);
        lock(&self.process).start_kill();
        for abort in &self.task_aborts {
            abort.abort();
        }
        if let Some(supervisor) = self.supervisor.as_ref() {
            supervisor.abort();
        }
        self.state.store(STATE_STOPPED, Ordering::Release);
    }
}

enum StdoutMessage {
    Event(serde_json::Value),
    Eof,
    ProtocolFailed,
}

async fn read_stdout(
    stdout: ChildStdout,
    maximum_line_bytes: usize,
    messages: mpsc::Sender<StdoutMessage>,
) {
    let mut reader = BufReader::new(stdout);
    loop {
        let line = match read_bounded_line(&mut reader, maximum_line_bytes).await {
            Ok(Some(line)) => line,
            Ok(None) => {
                let _ = messages.send(StdoutMessage::Eof).await;
                return;
            }
            Err(_) => {
                let _ = messages.send(StdoutMessage::ProtocolFailed).await;
                return;
            }
        };
        let Ok(event) = serde_json::from_slice::<serde_json::Value>(&line) else {
            let _ = messages.send(StdoutMessage::ProtocolFailed).await;
            return;
        };
        if !event.is_object() {
            let _ = messages.send(StdoutMessage::ProtocolFailed).await;
            return;
        }
        if messages.send(StdoutMessage::Event(event)).await.is_err() {
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn supervise(
    process: Arc<Mutex<SidecarProcessGuard>>,
    state: Arc<AtomicU8>,
    mut stdout: mpsc::Receiver<StdoutMessage>,
    events: mpsc::Sender<Result<serde_json::Value, SidecarError>>,
    mut stdout_task: JoinHandle<()>,
    mut stderr_task: JoinHandle<()>,
    completion: oneshot::Sender<JsonlProcessOutcome>,
    limits: SidecarLimits,
) {
    let outcome = loop {
        match tokio::time::timeout(limits.process_poll_interval, stdout.recv()).await {
            Ok(Some(StdoutMessage::Event(event))) => {
                if events.try_send(Ok(event)).is_err() {
                    break protocol_failure(&process, &events, limits).await;
                }
            }
            Ok(Some(StdoutMessage::Eof)) => {
                break match wait_for_exit(&process, limits).await {
                    Ok(status) if status.success() => JsonlProcessOutcome::Succeeded,
                    Ok(_) => JsonlProcessOutcome::Failed,
                    Err(error) if error.code() == SidecarErrorCode::TimedOut => {
                        JsonlProcessOutcome::TimedOut
                    }
                    Err(_) => JsonlProcessOutcome::ProtocolFailed,
                };
            }
            Ok(Some(StdoutMessage::ProtocolFailed)) => {
                break protocol_failure(&process, &events, limits).await;
            }
            Ok(None) => {
                break protocol_failure(&process, &events, limits).await;
            }
            Err(_) => {
                let status = {
                    let mut process = lock(&process);
                    match process.try_wait() {
                        Ok(Some(status)) => Some(Ok(status)),
                        Ok(None) => None,
                        Err(()) => Some(Err(())),
                    }
                };
                match status {
                    Some(Ok(status)) => {
                        lock(&process).start_kill();
                        break drain_after_exit(
                            status,
                            &mut stdout,
                            &events,
                            &mut stdout_task,
                            limits,
                        )
                        .await;
                    }
                    Some(Err(())) => {
                        break protocol_failure(&process, &events, limits).await;
                    }
                    None => {}
                }
            }
        }
    };

    stdout_task.abort();
    let _ = stdout_task.await;
    if tokio::time::timeout(limits.forced_shutdown_timeout, &mut stderr_task)
        .await
        .is_err()
    {
        stderr_task.abort();
        let _ = stderr_task.await;
    }
    state.store(STATE_STOPPED, Ordering::Release);
    drop(events);
    let _ = completion.send(outcome);
}

async fn drain_after_exit(
    status: ExitStatus,
    stdout: &mut mpsc::Receiver<StdoutMessage>,
    events: &mpsc::Sender<Result<serde_json::Value, SidecarError>>,
    stdout_task: &mut JoinHandle<()>,
    limits: SidecarLimits,
) -> JsonlProcessOutcome {
    let deadline = Instant::now()
        .checked_add(limits.forced_shutdown_timeout)
        .unwrap_or_else(Instant::now);
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return JsonlProcessOutcome::TimedOut;
        }
        match tokio::time::timeout(remaining, stdout.recv()).await {
            Ok(Some(StdoutMessage::Event(event))) => {
                if events.try_send(Ok(event)).is_err() {
                    return JsonlProcessOutcome::ProtocolFailed;
                }
            }
            Ok(Some(StdoutMessage::Eof)) | Ok(None) => {
                let _ = stdout_task.await;
                return if status.success() {
                    JsonlProcessOutcome::Succeeded
                } else {
                    JsonlProcessOutcome::Failed
                };
            }
            Ok(Some(StdoutMessage::ProtocolFailed)) => {
                let _ = events.try_send(Err(SidecarError::from_code(
                    SidecarErrorCode::ProtocolViolation,
                )));
                return JsonlProcessOutcome::ProtocolFailed;
            }
            Err(_) => return JsonlProcessOutcome::TimedOut,
        }
    }
}

async fn wait_for_exit(
    process: &Arc<Mutex<SidecarProcessGuard>>,
    limits: SidecarLimits,
) -> Result<ExitStatus, SidecarError> {
    let deadline = Instant::now()
        .checked_add(limits.forced_shutdown_timeout)
        .ok_or_else(|| SidecarError::from_code(SidecarErrorCode::InvalidConfiguration))?;
    loop {
        let status = {
            let mut process = lock(process);
            process.try_wait()
        };
        match status {
            Ok(Some(status)) => {
                lock(process).start_kill();
                return Ok(status);
            }
            Ok(None) => {}
            Err(()) => {
                return Err(SidecarError::from_code(SidecarErrorCode::SidecarExited));
            }
        }
        if Instant::now() >= deadline {
            let _ = force_kill_and_reap(process, limits).await;
            return Err(SidecarError::from_code(SidecarErrorCode::TimedOut));
        }
        tokio::time::sleep(limits.process_poll_interval).await;
    }
}

async fn protocol_failure(
    process: &Arc<Mutex<SidecarProcessGuard>>,
    events: &mpsc::Sender<Result<serde_json::Value, SidecarError>>,
    limits: SidecarLimits,
) -> JsonlProcessOutcome {
    let _ = events.try_send(Err(SidecarError::from_code(
        SidecarErrorCode::ProtocolViolation,
    )));
    let _ = force_kill_and_reap(process, limits).await;
    JsonlProcessOutcome::ProtocolFailed
}

const fn invalid_workspace() -> SidecarError {
    SidecarError::from_code(SidecarErrorCode::InvalidConfiguration)
}
