mod events;

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use semver::VersionReq;
use thiserror::Error;

use super::{BoundedDelegateTask, ResolvedDelegateSettings};
use crate::sidecar::{
    ExecutionWorkspace, JsonlEventProcess, JsonlProcessOutcome, ProviderEnvironmentProfile,
    ProviderHome, SidecarCommand, SidecarError, SidecarErrorCode, SidecarLimits, TrustedExecutable,
    VersionOutputFormat,
};

pub use events::{
    CodexEventNormalizer, CodexProtocolError, CodexProtocolErrorCode, DelegateActivityKind,
    DelegateEvent, DelegateItemPhase, DelegateTerminal, DelegateUsage,
};

const CODEX_VERSION: &str = "=0.146.0";
const CODEX_CONFIG: &[u8] = concat!(
    "cli_auth_credentials_store = \"keyring\"\n",
    "approval_policy = \"never\"\n",
    "sandbox_mode = \"workspace-write\"\n",
    "\n",
    "[sandbox_workspace_write]\n",
    "network_access = false\n",
)
.as_bytes();
const DELEGATE_PREAMBLE: &str = concat!(
    "You are a coding delegate operating in a Carl-controlled staging workspace.\n",
    "Work only inside the current workspace. Do not seek credentials or weaken sandbox, ",
    "approval, or network controls.\n",
    "Complete the task, verify your work, and finish with a concise summary.\n\n",
    "Task:\n",
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegateErrorCode {
    Configuration,
    AuthenticationRequired,
    Incompatible,
    StartFailed,
    ProtocolFailed,
    BudgetExhausted,
    Cancelled,
    ProviderFailed,
}

#[derive(Error)]
#[error("The subscription delegate failed.")]
pub struct DelegateError {
    code: DelegateErrorCode,
}

impl DelegateError {
    const fn new(code: DelegateErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(&self) -> DelegateErrorCode {
        self.code
    }
}

impl fmt::Debug for DelegateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DelegateError")
            .field("code", &self.code)
            .finish()
    }
}

pub struct CodexExecRequest {
    pub task: BoundedDelegateTask,
    pub settings: ResolvedDelegateSettings,
}

impl fmt::Debug for CodexExecRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexExecRequest")
            .field("task", &"<redacted>")
            .field("settings", &self.settings)
            .finish()
    }
}

pub struct CodexExecAdapter {
    executable: TrustedExecutable,
    home: ProviderHome,
    limits: SidecarLimits,
}

impl fmt::Debug for CodexExecAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexExecAdapter")
            .field("provider", &"openai_codex")
            .finish_non_exhaustive()
    }
}

impl CodexExecAdapter {
    pub fn new(
        executable: TrustedExecutable,
        home: ProviderHome,
        limits: SidecarLimits,
    ) -> Result<Self, DelegateError> {
        home.require_profile(ProviderEnvironmentProfile::Codex)
            .map_err(map_sidecar_error)?;
        home.write_static_file("config.toml", CODEX_CONFIG)
            .map_err(map_sidecar_error)?;
        Ok(Self {
            executable,
            home,
            limits,
        })
    }

    pub async fn start(
        &self,
        workspace: &ExecutionWorkspace,
        request: CodexExecRequest,
    ) -> Result<CodexExecRun, DelegateError> {
        let mut arguments = vec![OsString::from("--strict-config")];
        if let Some(model) = request.settings.model() {
            arguments.push(OsString::from("--model"));
            arguments.push(OsString::from(model.as_str()));
        }
        if let Some(effort) = request.settings.effort() {
            arguments.push(OsString::from("-c"));
            arguments.push(OsString::from(format!(
                "model_reasoning_effort=\"{}\"",
                effort.as_codex_value()
            )));
        }
        arguments.extend(["--ask-for-approval", "never"].map(OsString::from));
        arguments.extend(
            [
                "exec",
                "--json",
                "--ephemeral",
                "--sandbox",
                "workspace-write",
                "--skip-git-repo-check",
                "-",
            ]
            .map(OsString::from),
        );

        let specification = SidecarCommand {
            executable: self.executable.canonical_path().to_path_buf(),
            arguments,
            version_arguments: vec![OsString::from("--version")],
            version_output: VersionOutputFormat::ExactPrefixedVersion {
                prefix: "codex-cli",
                version: "0.146.0",
            },
            isolated_home: PathBuf::new(),
            supported_versions: VersionReq::parse(CODEX_VERSION)
                .expect("the pinned Codex version requirement is valid"),
        };
        let task = format!("{DELEGATE_PREAMBLE}{}\n", request.task.as_str());
        let process = JsonlEventProcess::spawn_in_home(
            specification,
            &self.executable,
            &self.home,
            workspace,
            task.as_bytes(),
            self.limits,
        )
        .await
        .map_err(map_sidecar_error)?;

        Ok(CodexExecRun {
            process,
            normalizer: CodexEventNormalizer::new(),
            terminal: None,
            stream_exhausted: false,
            failure: None,
        })
    }
}

pub struct CodexExecRun {
    process: JsonlEventProcess,
    normalizer: CodexEventNormalizer,
    terminal: Option<DelegateTerminal>,
    stream_exhausted: bool,
    failure: Option<DelegateErrorCode>,
}

impl fmt::Debug for CodexExecRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexExecRun")
            .field("terminal_seen", &self.terminal.is_some())
            .field("stream_exhausted", &self.stream_exhausted)
            .field("failed", &self.failure.is_some())
            .finish()
    }
}

impl CodexExecRun {
    pub async fn next_event(&mut self) -> Result<Option<DelegateEvent>, DelegateError> {
        if let Some(code) = self.failure {
            return Err(DelegateError::new(code));
        }
        if self.stream_exhausted {
            return Ok(None);
        }

        loop {
            let value = match self.process.next_event().await {
                Ok(Some(value)) => value,
                Ok(None) => {
                    self.stream_exhausted = true;
                    return Ok(None);
                }
                Err(error) => return Err(self.fail_process(map_sidecar_error(error).code()).await),
            };
            let event = match self.normalizer.ingest(value) {
                Ok(Some(event)) => event,
                Ok(None) => continue,
                Err(_) => {
                    return Err(self.fail_process(DelegateErrorCode::ProtocolFailed).await);
                }
            };
            if let DelegateEvent::Terminal(terminal) = &event {
                self.terminal = Some(terminal.clone());
            }
            return Ok(Some(event));
        }
    }

    pub async fn finish(mut self) -> Result<DelegateUsage, DelegateError> {
        while self.next_event().await?.is_some() {}
        if let Some(code) = self.failure {
            return Err(DelegateError::new(code));
        }

        let outcome = self.process.wait().await.map_err(map_sidecar_error)?;
        match (&self.terminal, outcome) {
            (Some(DelegateTerminal::Completed { usage }), JsonlProcessOutcome::Succeeded) => {
                Ok(*usage)
            }
            (Some(DelegateTerminal::Failed { error_code }), _) => Err(DelegateError::new(
                classify_terminal_failure(error_code.as_deref()),
            )),
            (None, JsonlProcessOutcome::Succeeded) => {
                Err(DelegateError::new(DelegateErrorCode::ProtocolFailed))
            }
            (_, JsonlProcessOutcome::Cancelled) => {
                Err(DelegateError::new(DelegateErrorCode::Cancelled))
            }
            (_, JsonlProcessOutcome::ProtocolFailed) => {
                Err(DelegateError::new(DelegateErrorCode::ProtocolFailed))
            }
            (_, JsonlProcessOutcome::TimedOut) => {
                Err(DelegateError::new(DelegateErrorCode::BudgetExhausted))
            }
            (_, JsonlProcessOutcome::Failed) => {
                Err(DelegateError::new(DelegateErrorCode::ProviderFailed))
            }
        }
    }

    pub async fn cancel(&mut self) -> Result<(), DelegateError> {
        self.process.cancel().await.map_err(map_sidecar_error)?;
        self.failure = Some(DelegateErrorCode::Cancelled);
        Ok(())
    }

    async fn fail_process(&mut self, code: DelegateErrorCode) -> DelegateError {
        let _ = self.process.cancel().await;
        self.failure = Some(code);
        DelegateError::new(code)
    }
}

fn classify_terminal_failure(error_code: Option<&str>) -> DelegateErrorCode {
    match error_code {
        Some("authentication_required" | "not_logged_in" | "unauthorized") => {
            DelegateErrorCode::AuthenticationRequired
        }
        _ => DelegateErrorCode::ProviderFailed,
    }
}

fn map_sidecar_error(error: SidecarError) -> DelegateError {
    let code = match error.code() {
        SidecarErrorCode::InvalidProviderHome | SidecarErrorCode::InvalidConfiguration => {
            DelegateErrorCode::Configuration
        }
        SidecarErrorCode::UnsupportedVersion => DelegateErrorCode::Incompatible,
        SidecarErrorCode::ProtocolViolation => DelegateErrorCode::ProtocolFailed,
        SidecarErrorCode::Cancelled => DelegateErrorCode::Cancelled,
        SidecarErrorCode::TimedOut => DelegateErrorCode::BudgetExhausted,
        SidecarErrorCode::SidecarExited => DelegateErrorCode::ProviderFailed,
        SidecarErrorCode::ExecutableMissing
        | SidecarErrorCode::ExecutableUnavailable
        | SidecarErrorCode::UnsafeExecutable
        | SidecarErrorCode::SpawnFailed
        | SidecarErrorCode::ForegroundRequired
        | SidecarErrorCode::UnsafeProviderFile
        | SidecarErrorCode::DuplicateRequestId => DelegateErrorCode::StartFailed,
    };
    DelegateError::new(code)
}
