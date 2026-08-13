use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

use super::{NativeToolError, NativeToolErrorCode, invalid_arguments, io_error};
use crate::security::SecretFilter;

const MAX_ARGUMENTS: usize = 128;
const MAX_ARGUMENT_BYTES: usize = 8 * 1024;
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CommandArguments {
    argv: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
}

const fn default_timeout() -> u64 {
    120
}

pub(super) struct CommandAction {
    workspace: PathBuf,
    executable: PathBuf,
    arguments: Vec<String>,
    timeout: Duration,
}

impl CommandAction {
    pub(super) fn prepare(root: &Path, args: CommandArguments) -> Result<Self, NativeToolError> {
        if args.argv.is_empty()
            || args.argv.len() > MAX_ARGUMENTS
            || !(1..=120).contains(&args.timeout_seconds)
            || args.argv.iter().any(|value| {
                value.len() > MAX_ARGUMENT_BYTES
                    || value.as_bytes().contains(&0)
                    || value
                        .chars()
                        .any(|character| character == '\n' || character == '\r')
            })
        {
            return Err(invalid_arguments());
        }
        let executable = Path::new(&args.argv[0]);
        if !executable.is_absolute() {
            return Err(invalid_arguments());
        }
        let executable = std::fs::canonicalize(executable).map_err(|_| invalid_arguments())?;
        if !std::fs::metadata(&executable)
            .map_err(|_| invalid_arguments())?
            .is_file()
        {
            return Err(invalid_arguments());
        }
        let name = executable
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(invalid_arguments)?;
        if matches!(
            name,
            "sh" | "bash" | "zsh" | "fish" | "dash" | "cmd" | "cmd.exe" | "powershell" | "pwsh"
        ) {
            return Err(invalid_arguments());
        }
        Ok(Self {
            workspace: root.to_path_buf(),
            executable,
            arguments: args.argv.into_iter().skip(1).collect(),
            timeout: Duration::from_secs(args.timeout_seconds),
        })
    }

    pub(super) fn summary(&self) -> String {
        format!(
            "run {} with {} argument(s)",
            self.executable
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("command"),
            self.arguments.len()
        )
    }

    pub(super) async fn execute(
        self,
        cancellation: CancellationToken,
    ) -> Result<Value, NativeToolError> {
        if cancellation.is_cancelled() {
            return Err(NativeToolError::new(NativeToolErrorCode::Cancelled));
        }
        let mut command = Command::new(&self.executable);
        command
            .args(&self.arguments)
            .current_dir(&self.workspace)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command.spawn().map_err(|_| io_error())?;
        let pid = child.id();
        let stdout = child.stdout.take().ok_or_else(io_error)?;
        let stderr = child.stderr.take().ok_or_else(io_error)?;
        let stdout_task = tokio::spawn(drain_bounded(stdout));
        let stderr_task = tokio::spawn(drain_bounded(stderr));
        let outcome = tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(NativeToolError::new(NativeToolErrorCode::Cancelled)),
            () = tokio::time::sleep(self.timeout) => Err(NativeToolError::new(NativeToolErrorCode::TimedOut)),
            status = child.wait() => status.map_err(|_| io_error()),
        };
        let status = match outcome {
            Ok(status) => {
                terminate_descendants(pid);
                status
            }
            Err(error) => {
                terminate(&mut child, pid).await;
                let _ = stdout_task.await;
                let _ = stderr_task.await;
                return Err(error);
            }
        };
        let stdout = stdout_task.await.map_err(|_| io_error())??;
        let stderr = stderr_task.await.map_err(|_| io_error())??;
        if stdout.overflow || stderr.overflow {
            return Err(NativeToolError::new(NativeToolErrorCode::OutputTooLarge));
        }
        SecretFilter
            .inspect(&stdout.bytes)
            .and_then(|_| SecretFilter.inspect(&stderr.bytes))
            .map_err(|_| NativeToolError::new(NativeToolErrorCode::SecretDetected))?;
        let stdout = String::from_utf8(stdout.bytes).map_err(|_| invalid_arguments())?;
        let stderr = String::from_utf8(stderr.bytes).map_err(|_| invalid_arguments())?;
        Ok(json!({
            "exit_code":status.code(),
            "success":status.success(),
            "stdout":stdout,
            "stderr":stderr
        }))
    }
}

struct CapturedOutput {
    bytes: Vec<u8>,
    overflow: bool,
}

async fn drain_bounded(
    mut pipe: impl tokio::io::AsyncRead + Unpin,
) -> Result<CapturedOutput, NativeToolError> {
    let mut bytes = Vec::new();
    let mut overflow = false;
    let mut chunk = [0_u8; 8192];
    loop {
        let read = pipe.read(&mut chunk).await.map_err(|_| io_error())?;
        if read == 0 {
            break;
        }
        let remaining = MAX_OUTPUT_BYTES.saturating_sub(bytes.len());
        if read > remaining {
            bytes.extend_from_slice(&chunk[..remaining]);
            overflow = true;
        } else if !overflow {
            bytes.extend_from_slice(&chunk[..read]);
        }
    }
    Ok(CapturedOutput { bytes, overflow })
}

async fn terminate(child: &mut tokio::process::Child, pid: Option<u32>) {
    terminate_descendants(pid);
    let _ = child.start_kill();
    let _ = child.wait().await;
}

fn terminate_descendants(pid: Option<u32>) {
    #[cfg(unix)]
    if let Some(pid) = pid.and_then(|value| i32::try_from(value).ok()) {
        // SAFETY: the child was placed in a new process group whose ID is its PID.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}
