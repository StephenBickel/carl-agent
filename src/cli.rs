use std::env;
use std::ffi::OsString;
use std::fs;
use std::future::{Future, pending};
use std::path::PathBuf;
use std::pin::Pin;

use chrono::{TimeDelta, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use tokio::io::BufReader;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::acp::{
    AcpServer, AcpServerConfig, AcpServerErrorCode, BuzzPublisher, BuzzPublisherBootstrap,
    BuzzPublisherConfig, Kernel, PermissionMode,
};
use crate::auth::codex::{CODEX_LOGOUT_WARNING, CodexAuth, CodexAuthTimeouts};
use crate::auth::grok::{GrokAuth, GrokAuthTimeouts};
use crate::auth::{
    AuthError, AuthErrorCode, AuthMethod, AuthState, AuthUnavailableCode, LoginChallenge,
    SubscriptionAuthBroker, SubscriptionPlan, SubscriptionService,
};
use crate::buzz_mcp;
use crate::delegates::codex::CodexAppServer;
use crate::delegates::{ModelId, ReasoningEffort};
use crate::error::{CarlError, ErrorCode};
use crate::events::SessionId;
use crate::memory::{
    MemoryKind, MemoryPartition, MemoryQuery, MemoryScope, MemorySettings, MemoryWrite,
};
use crate::policy::Frontend;
use crate::sidecar::{
    DataRootLock, DataRootLockErrorCode, ExecutableTrustDecision, ExecutionWorkspace,
    ProviderEnvironmentProfile, ProviderHome, ResolvedExecutable, SidecarError, SidecarErrorCode,
    SidecarLimits, TrustedExecutable, authorize_local_foreground,
    local_foreground_terminal_available, write_local_foreground_stderr,
};
use crate::storage::Store;

#[derive(Debug, Parser)]
#[command(name = "carl")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Serve,
    Acp(AcpArgs),
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    Memory {
        #[command(subcommand)]
        command: MemoryCommand,
    },
    Pair,
    Doctor,
    Sessions,
}

#[derive(Clone, Debug, Args)]
pub struct AcpArgs {
    #[arg(long)]
    pub model: Option<String>,
    #[arg(long, value_enum)]
    pub effort: Option<AcpEffort>,
    #[arg(long, value_enum, conflicts_with = "dangerously_bypass_permissions")]
    pub permission_mode: Option<AcpPermissionMode>,
    #[arg(long, conflicts_with = "permission_mode")]
    pub dangerously_bypass_permissions: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AcpEffort {
    Low,
    Medium,
    High,
    Xhigh,
    Max,
    Ultra,
}

impl From<AcpEffort> for ReasoningEffort {
    fn from(value: AcpEffort) -> Self {
        match value {
            AcpEffort::Low => Self::Low,
            AcpEffort::Medium => Self::Medium,
            AcpEffort::High => Self::High,
            AcpEffort::Xhigh => Self::XHigh,
            AcpEffort::Max => Self::Max,
            AcpEffort::Ultra => Self::Ultra,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum MemoryCommand {
    Status,
    Remember {
        #[arg(long, value_enum, default_value = "fact")]
        kind: MemoryKindArgument,
        #[arg(long)]
        key: String,
        #[arg(long)]
        content: String,
        #[arg(long, value_enum, default_value = "global")]
        scope: MemoryScopeArgument,
        #[arg(long)]
        session: Option<String>,
        #[arg(long, default_value_t = 50)]
        importance: u8,
        #[arg(long)]
        expires_in_days: Option<u32>,
    },
    Search {
        query: String,
        #[arg(long)]
        session: Option<String>,
    },
    List,
    Export,
    Purge,
    Proposals,
    Approve {
        id: Uuid,
    },
    Reject {
        id: Uuid,
    },
    Forget {
        id: Uuid,
    },
    Clear {
        #[arg(long, value_enum)]
        confirm: MemoryClearConfirmation,
    },
    Settings {
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
        #[arg(long)]
        max_context_items: Option<u32>,
        #[arg(long)]
        context_bytes: Option<u32>,
        #[arg(long)]
        max_memories: Option<u32>,
        #[arg(long)]
        max_storage_bytes: Option<u64>,
        #[arg(long)]
        episode_ttl_days: Option<u32>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum MemoryKindArgument {
    Profile,
    Preference,
    Fact,
    Goal,
    Episode,
}

impl From<MemoryKindArgument> for MemoryKind {
    fn from(value: MemoryKindArgument) -> Self {
        match value {
            MemoryKindArgument::Profile => Self::Profile,
            MemoryKindArgument::Preference => Self::Preference,
            MemoryKindArgument::Fact => Self::Fact,
            MemoryKindArgument::Goal => Self::Goal,
            MemoryKindArgument::Episode => Self::Episode,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AcpPermissionMode {
    Plan,
    Default,
    #[value(name = "acceptEdits")]
    AcceptEdits,
    #[value(name = "dontAsk")]
    DontAsk,
    #[value(name = "bypassPermissions")]
    BypassPermissions,
}

impl From<AcpPermissionMode> for PermissionMode {
    fn from(value: AcpPermissionMode) -> Self {
        match value {
            AcpPermissionMode::Plan => Self::Plan,
            AcpPermissionMode::Default => Self::Default,
            AcpPermissionMode::AcceptEdits => Self::AcceptEdits,
            AcpPermissionMode::DontAsk => Self::DontAsk,
            AcpPermissionMode::BypassPermissions => Self::BypassPermissions,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum MemoryScopeArgument {
    Global,
    Workspace,
    Session,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum MemoryClearConfirmation {
    DeleteAll,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Subcommand)]
pub enum AuthCommand {
    Status,
    Login {
        #[arg(value_enum)]
        service: AuthService,
        #[arg(long)]
        device: bool,
    },
    Logout {
        #[arg(value_enum)]
        service: AuthService,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AuthService {
    Openai,
    Grok,
}

impl AuthService {
    const fn subscription_service(self) -> SubscriptionService {
        match self {
            Self::Openai => SubscriptionService::OpenAiCodex,
            Self::Grok => SubscriptionService::XaiGrok,
        }
    }

    const fn executable_variable(self) -> &'static str {
        match self {
            Self::Openai => "CARL_CODEX_EXECUTABLE",
            Self::Grok => "CARL_GROK_EXECUTABLE",
        }
    }

    const fn default_executable(self) -> &'static str {
        match self {
            Self::Openai => "codex",
            Self::Grok => "grok",
        }
    }

    const fn provider_directory(self) -> &'static str {
        match self {
            Self::Openai => "codex",
            Self::Grok => "grok",
        }
    }

    const fn profile(self) -> ProviderEnvironmentProfile {
        match self {
            Self::Openai => ProviderEnvironmentProfile::Codex,
            Self::Grok => ProviderEnvironmentProfile::Grok,
        }
    }
}

/// Stable process outcome for a parsed Carl command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitClassification {
    Success,
    Failure,
    Cancelled,
}

/// Already-sanitized output returned by the library-owned command runner.
#[derive(Debug, Eq, PartialEq)]
pub struct CliRunResult {
    stdout: String,
    stderr: String,
    exit: ExitClassification,
}

impl CliRunResult {
    #[must_use]
    pub fn stdout(&self) -> &str {
        &self.stdout
    }

    #[must_use]
    pub fn stderr(&self) -> &str {
        &self.stderr
    }

    #[must_use]
    pub const fn exit_classification(&self) -> ExitClassification {
        self.exit
    }

    fn auth_record(record: AuthStatusOutput, exit: ExitClassification) -> Self {
        let mut stdout =
            serde_json::to_string(&record).expect("the closed authentication record serializes");
        stdout.push('\n');
        Self {
            stdout,
            stderr: String::new(),
            exit,
        }
    }

    fn auth_status(records: [AuthStatusOutput; 2]) -> Self {
        let mut stdout =
            serde_json::to_string(&records).expect("the closed authentication array serializes");
        stdout.push('\n');
        Self {
            stdout,
            stderr: String::new(),
            exit: ExitClassification::Success,
        }
    }

    fn not_implemented(command: &'static str) -> Self {
        Self {
            stdout: String::new(),
            stderr: format!("{command} is not implemented\n"),
            exit: ExitClassification::Failure,
        }
    }

    fn json_success<T: Serialize>(value: &T) -> Self {
        let mut stdout =
            serde_json::to_string(value).expect("closed CLI output should always serialize");
        stdout.push('\n');
        Self {
            stdout,
            stderr: String::new(),
            exit: ExitClassification::Success,
        }
    }

    fn memory_error(error: &CarlError) -> Self {
        let mut stderr = serde_json::to_string(&CliErrorOutput {
            error_code: error.code(),
            message: error.user_message(),
        })
        .expect("closed CLI error output should always serialize");
        stderr.push('\n');
        Self {
            stdout: String::new(),
            stderr,
            exit: ExitClassification::Failure,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct CliErrorOutput {
    error_code: ErrorCode,
    message: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct MemoryStatusOutput {
    settings: MemorySettings,
    active_memories: usize,
    pending_proposals: usize,
    content_bytes: usize,
    storage: &'static str,
    retrieval: &'static str,
    external_dependency_required: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct MemoryMutationOutput {
    changed: bool,
    deleted: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthAvailability {
    Available,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuthOutputState {
    SignedOut,
    Pending,
    SignedIn,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct AuthStatusOutput {
    service: SubscriptionService,
    availability: AuthAvailability,
    state: AuthOutputState,
    method: Option<AuthMethod>,
    plan: Option<SubscriptionPlan>,
    error_code: Option<AuthErrorCode>,
}

impl AuthStatusOutput {
    const fn unavailable(service: SubscriptionService, error_code: AuthErrorCode) -> Self {
        Self {
            service,
            availability: AuthAvailability::Unavailable,
            state: AuthOutputState::Unavailable,
            method: None,
            plan: None,
            error_code: Some(error_code),
        }
    }

    const fn from_state(service: SubscriptionService, state: AuthState) -> Self {
        match state {
            AuthState::SignedOut => Self {
                service,
                availability: AuthAvailability::Available,
                state: AuthOutputState::SignedOut,
                method: None,
                plan: None,
                error_code: None,
            },
            AuthState::Pending => Self {
                service,
                availability: AuthAvailability::Available,
                state: AuthOutputState::Pending,
                method: None,
                plan: None,
                error_code: None,
            },
            AuthState::SignedIn { method, plan } => Self {
                service,
                availability: AuthAvailability::Available,
                state: AuthOutputState::SignedIn,
                method: Some(method),
                plan,
                error_code: None,
            },
            AuthState::Unavailable { code } => Self::unavailable(service, unavailable_code(code)),
        }
    }
}

const fn unavailable_code(code: AuthUnavailableCode) -> AuthErrorCode {
    match code {
        AuthUnavailableCode::ExecutableMissing => AuthErrorCode::ExecutableMissing,
        AuthUnavailableCode::UnsupportedVersion => AuthErrorCode::UnsupportedVersion,
        AuthUnavailableCode::KeyringUnavailable => AuthErrorCode::KeyringUnavailable,
        AuthUnavailableCode::ProtocolMismatch => AuthErrorCode::ProtocolMismatch,
        AuthUnavailableCode::ProviderRejected => AuthErrorCode::ProviderRejected,
        AuthUnavailableCode::ForegroundRequired => AuthErrorCode::ForegroundRequired,
        AuthUnavailableCode::UnsafeCredentialStore => AuthErrorCode::UnsafeCredentialStore,
        AuthUnavailableCode::TimedOut => AuthErrorCode::TimedOut,
    }
}

struct CommonConfiguration {
    data_root: PathBuf,
    workspace: PathBuf,
}

enum OperationResult<T> {
    Completed(T),
    Cancelled,
}

enum ConnectionResult<T> {
    Completed(T),
    Cancelled(T),
}

/// Run one parsed command with the production Ctrl-C source.
pub async fn run_command(command: Command) -> CliRunResult {
    // These platform constructors synchronously install/register the operating
    // system handler before the runner can touch configuration or a provider.
    let cancellation = registered_ctrl_c();
    run_command_with_cancellation(command, cancellation).await
}

#[cfg(unix)]
fn registered_ctrl_c() -> Pin<Box<dyn Future<Output = ()> + Send>> {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
        Ok(mut listener) => Box::pin(async move {
            let _ = listener.recv().await;
        }),
        Err(_) => Box::pin(pending()),
    }
}

#[cfg(windows)]
fn registered_ctrl_c() -> Pin<Box<dyn Future<Output = ()> + Send>> {
    match tokio::signal::windows::ctrl_c() {
        Ok(mut listener) => Box::pin(async move {
            let _ = listener.recv().await;
        }),
        Err(_) => Box::pin(pending()),
    }
}

/// Run one parsed command with a provider-neutral injected cancellation source.
///
/// This entry point exists so cleanup and exit-130 behavior can be verified without
/// delivering an operating-system signal. It does not grant foreground authority.
pub async fn run_command_with_cancellation<C>(command: Command, cancellation: C) -> CliRunResult
where
    C: Future<Output = ()>,
{
    let mut cancellation = Box::pin(cancellation);
    match command {
        Command::Auth { command } => run_auth(command, cancellation.as_mut()).await,
        Command::Acp(_) => CliRunResult::not_implemented("acp streaming dispatch"),
        Command::Memory { command } => run_memory(command),
        Command::Serve => CliRunResult::not_implemented("serve"),
        Command::Pair => CliRunResult::not_implemented("pair"),
        Command::Doctor => CliRunResult::not_implemented("doctor"),
        Command::Sessions => CliRunResult::not_implemented("sessions"),
    }
}

/// Run Carl's ACP frontend on process stdio until EOF or Ctrl-C.
pub async fn run_acp_stdio(args: AcpArgs) -> ExitClassification {
    if env::var_os("OPENAI_API_KEY").is_some() {
        return acp_failure("carl acp: API-key authentication is not supported");
    }
    let Ok(configuration) = load_common_configuration() else {
        return acp_failure("carl acp: invalid Carl data directory or workspace");
    };
    let Ok(data_root_lock) = acquire_data_root_lock(&configuration) else {
        return acp_failure("carl acp: Carl data directory is unsafe or already in use");
    };
    let Ok((codex_executable, codex_home)) = prepare_provider(AuthService::Openai, &configuration)
    else {
        return acp_failure("carl acp: Codex executable or provider home is invalid");
    };
    let frontend = if env::var_os("BUZZ_ACP_AGENTS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        Frontend::Buzz
    } else {
        Frontend::Acp
    };
    let buzz_publisher = if frontend == Frontend::Buzz {
        let Ok(executable) = prepare_buzz_executable() else {
            return acp_failure("carl acp: Buzz executable is unavailable or untrusted");
        };
        let Ok(workspace) = ExecutionWorkspace::open(&configuration.workspace) else {
            return acp_failure("carl acp: workspace is invalid");
        };
        Some(BuzzPublisherBootstrap::new(executable, workspace))
    } else {
        None
    };
    let Ok(runtime_store) = crate::storage::RuntimeStore::open(data_root_lock, Utc::now()) else {
        return acp_failure("carl acp: durable state failed to open");
    };
    let Ok(codex) =
        CodexAppServer::connect(&codex_executable, codex_home, SidecarLimits::default()).await
    else {
        return acp_failure("carl acp: Codex app-server startup failed");
    };
    let Ok(kernel) = Kernel::start(runtime_store, codex, None).await else {
        return acp_failure("carl acp: Codex model discovery failed");
    };
    let model = match args.model {
        Some(model) => match ModelId::parse(model) {
            Ok(model) => Some(model),
            Err(_) => return shutdown_failure(kernel, "carl acp: model ID is invalid").await,
        },
        None => None,
    };
    let permission_mode = if args.dangerously_bypass_permissions {
        PermissionMode::BypassPermissions
    } else {
        args.permission_mode
            .map(Into::into)
            .unwrap_or(PermissionMode::Default)
    };
    let server = AcpServer::configured(
        kernel.clone(),
        AcpServerConfig {
            frontend,
            model,
            effort: args.effort.map(Into::into),
            permission_mode,
            buzz_publisher,
        },
    );
    let cancellation = CancellationToken::new();
    let signal = cancellation.clone();
    tokio::spawn(async move {
        registered_ctrl_c().await;
        signal.cancel();
    });
    let input = BufReader::new(tokio::io::stdin());
    match server
        .serve_with_cancellation(input, tokio::io::stdout(), cancellation)
        .await
    {
        Ok(()) => ExitClassification::Success,
        Err(error) if error.code() == AcpServerErrorCode::Cancelled => {
            ExitClassification::Cancelled
        }
        Err(_) => acp_failure("carl acp: ACP transport failed"),
    }
}

async fn shutdown_failure(
    kernel: crate::acp::KernelHandle,
    message: &'static str,
) -> ExitClassification {
    let _ = kernel.shutdown().await;
    acp_failure(message)
}

fn acp_failure(message: &'static str) -> ExitClassification {
    eprintln!("{message}");
    ExitClassification::Failure
}

/// Run the restricted Buzz publisher MCP surface selected by the executable name.
pub async fn run_buzz_mcp_stdio() -> ExitClassification {
    let Ok(configuration) = load_common_configuration() else {
        return mcp_failure("carl-buzz-mcp: invalid Carl data directory");
    };
    let Ok(executable) = prepare_buzz_executable() else {
        return mcp_failure("carl-buzz-mcp: Buzz executable is unavailable or untrusted");
    };
    let Ok(workspace) = ExecutionWorkspace::open(&configuration.workspace) else {
        return mcp_failure("carl-buzz-mcp: workspace is invalid");
    };
    let Ok(publisher_config) = BuzzPublisherConfig::from_process_environment() else {
        return mcp_failure("carl-buzz-mcp: Buzz environment is invalid");
    };
    let Ok(publisher) = BuzzPublisher::connect(executable, workspace, publisher_config).await
    else {
        return mcp_failure("carl-buzz-mcp: Buzz publisher startup failed");
    };
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    match buzz_mcp::run_stdio(&mut input, &mut output, &publisher).await {
        Ok(()) => ExitClassification::Success,
        Err(_) => mcp_failure("carl-buzz-mcp: MCP transport failed"),
    }
}

fn mcp_failure(message: &'static str) -> ExitClassification {
    eprintln!("{message}");
    ExitClassification::Failure
}

fn run_memory(command: MemoryCommand) -> CliRunResult {
    let configuration = match load_common_configuration() {
        Ok(configuration) => configuration,
        Err(_) => {
            return CliRunResult::memory_error(&CarlError::Configuration {
                detail: "memory commands require a trusted CARL_DATA_DIR".to_owned(),
            });
        }
    };
    let data_root_lock = match DataRootLock::acquire(&configuration.data_root) {
        Ok(lock) => lock,
        Err(_) => {
            return CliRunResult::memory_error(&CarlError::Storage {
                detail: "the Carl data directory is unavailable".to_owned(),
            });
        }
    };
    let store = match Store::open_locked(&data_root_lock) {
        Ok(store) => store,
        Err(error) => return CliRunResult::memory_error(&error),
    };
    match execute_memory_command(&store, command, &configuration.workspace) {
        Ok(result) => result,
        Err(error) => CliRunResult::memory_error(&error),
    }
}

fn execute_memory_command(
    store: &Store,
    command: MemoryCommand,
    workspace: &std::path::Path,
) -> Result<CliRunResult, CarlError> {
    let partition = MemoryPartition::local_carl();
    let now = Utc::now();
    match command {
        MemoryCommand::Status => {
            let export = store.export_memories(&partition, now)?;
            let content_bytes = export
                .memories
                .iter()
                .map(|memory| memory.content.len())
                .sum();
            Ok(CliRunResult::json_success(&MemoryStatusOutput {
                settings: export.settings,
                active_memories: export.memories.len(),
                pending_proposals: store.list_memory_proposals(&partition, now)?.len(),
                content_bytes,
                storage: "local_sqlite",
                retrieval: "local_lexical",
                external_dependency_required: false,
            }))
        }
        MemoryCommand::Remember {
            kind,
            key,
            content,
            scope,
            session,
            importance,
            expires_in_days,
        } => {
            let session = parse_optional_session(session.as_deref())?;
            let scope = memory_scope(scope, workspace, session)?;
            let mut write = MemoryWrite::new(
                partition,
                scope,
                kind.into(),
                key,
                content,
                "owner explicit CLI request",
            )?
            .with_importance(importance);
            if let Some(days) = expires_in_days {
                if !(1..=3_650).contains(&days) {
                    return Err(CarlError::Validation {
                        detail: "memory expiration is outside supported bounds".to_owned(),
                    });
                }
                write = write.with_expiration(now + TimeDelta::days(i64::from(days)));
            }
            Ok(CliRunResult::json_success(
                &store.remember_memory(write, now)?,
            ))
        }
        MemoryCommand::Search { query, session } => {
            let session = parse_optional_session(session.as_deref())?;
            let workspace = workspace.to_str().ok_or_else(|| CarlError::Configuration {
                detail: "the current workspace path is not valid UTF-8".to_owned(),
            })?;
            let query = MemoryQuery::new(partition, query, Some(workspace), session)?;
            Ok(CliRunResult::json_success(
                &store.retrieve_memories(&query, now, None)?,
            ))
        }
        MemoryCommand::List => {
            let export = store.export_memories(&partition, now)?;
            Ok(CliRunResult::json_success(&export.memories))
        }
        MemoryCommand::Export => Ok(CliRunResult::json_success(
            &store.export_memories(&partition, now)?,
        )),
        MemoryCommand::Purge => Ok(CliRunResult::json_success(
            &store.purge_expired_memory(&partition, now)?,
        )),
        MemoryCommand::Proposals => Ok(CliRunResult::json_success(
            &store.list_memory_proposals(&partition, now)?,
        )),
        MemoryCommand::Approve { id } => Ok(CliRunResult::json_success(
            &store.approve_memory_proposal(&partition, id, now)?,
        )),
        MemoryCommand::Reject { id } => {
            let changed = store.reject_memory_proposal(&partition, id)?;
            Ok(CliRunResult::json_success(&MemoryMutationOutput {
                changed,
                deleted: u64::from(changed),
            }))
        }
        MemoryCommand::Forget { id } => {
            let changed = store.delete_memory(&partition, id)?;
            Ok(CliRunResult::json_success(&MemoryMutationOutput {
                changed,
                deleted: u64::from(changed),
            }))
        }
        MemoryCommand::Clear { confirm: _ } => {
            let deleted = store.clear_memories(&partition)?;
            Ok(CliRunResult::json_success(&MemoryMutationOutput {
                changed: deleted > 0,
                deleted,
            }))
        }
        MemoryCommand::Settings {
            enable,
            disable,
            max_context_items,
            context_bytes,
            max_memories,
            max_storage_bytes,
            episode_ttl_days,
        } => {
            let mut settings = store.memory_settings(&partition)?;
            let changed = enable
                || disable
                || max_context_items.is_some()
                || context_bytes.is_some()
                || max_memories.is_some()
                || max_storage_bytes.is_some()
                || episode_ttl_days.is_some();
            if enable {
                settings.enabled = true;
            } else if disable {
                settings.enabled = false;
            }
            if let Some(value) = max_context_items {
                settings.max_context_items = value;
            }
            if let Some(value) = context_bytes {
                settings.context_bytes = value;
            }
            if let Some(value) = max_memories {
                settings.max_memories = value;
            }
            if let Some(value) = max_storage_bytes {
                settings.max_storage_bytes = value;
            }
            if let Some(value) = episode_ttl_days {
                settings.episode_ttl_days = value;
            }
            if changed {
                store.update_memory_settings(&partition, &settings, now)?;
            }
            Ok(CliRunResult::json_success(&settings))
        }
    }
}

fn parse_optional_session(value: Option<&str>) -> Result<Option<SessionId>, CarlError> {
    value
        .map(|value| {
            value.parse().map_err(|_| CarlError::Validation {
                detail: "memory session ID is invalid".to_owned(),
            })
        })
        .transpose()
}

fn memory_scope(
    scope: MemoryScopeArgument,
    workspace: &std::path::Path,
    session: Option<SessionId>,
) -> Result<MemoryScope, CarlError> {
    match scope {
        MemoryScopeArgument::Global => {
            if session.is_some() {
                return Err(CarlError::Validation {
                    detail: "a global memory cannot include a session scope".to_owned(),
                });
            }
            Ok(MemoryScope::global())
        }
        MemoryScopeArgument::Workspace => {
            if session.is_some() {
                return Err(CarlError::Validation {
                    detail: "a workspace memory cannot include a session scope".to_owned(),
                });
            }
            let workspace = workspace.to_str().ok_or_else(|| CarlError::Configuration {
                detail: "the current workspace path is not valid UTF-8".to_owned(),
            })?;
            MemoryScope::workspace(workspace)
        }
        MemoryScopeArgument::Session => {
            session
                .map(MemoryScope::session)
                .ok_or_else(|| CarlError::Validation {
                    detail: "a session-scoped memory requires --session".to_owned(),
                })
        }
    }
}

async fn run_auth<C>(command: AuthCommand, cancellation: Pin<&mut C>) -> CliRunResult
where
    C: Future<Output = ()> + ?Sized,
{
    match command {
        AuthCommand::Status => run_auth_status().await,
        AuthCommand::Login { service, device } => {
            if !local_foreground_terminal_available() {
                return operation_error(service, AuthErrorCode::ForegroundRequired);
            }
            let Ok(configuration) = load_common_configuration() else {
                return operation_error(service, AuthErrorCode::ProviderRejected);
            };
            let Ok(_data_root_lock) = acquire_data_root_lock(&configuration) else {
                return operation_error(service, AuthErrorCode::ProviderRejected);
            };
            run_login(service, device, &configuration, cancellation).await
        }
        AuthCommand::Logout { service } => {
            if !local_foreground_terminal_available() {
                return operation_error(service, AuthErrorCode::ForegroundRequired);
            }
            let Ok(configuration) = load_common_configuration() else {
                return operation_error(service, AuthErrorCode::ProviderRejected);
            };
            let Ok(_data_root_lock) = acquire_data_root_lock(&configuration) else {
                return operation_error(service, AuthErrorCode::ProviderRejected);
            };
            run_logout(service, &configuration, cancellation).await
        }
    }
}

async fn run_auth_status() -> CliRunResult {
    let Ok(configuration) = load_common_configuration() else {
        return CliRunResult::auth_status([
            AuthStatusOutput::unavailable(
                SubscriptionService::OpenAiCodex,
                AuthErrorCode::ProviderRejected,
            ),
            AuthStatusOutput::unavailable(
                SubscriptionService::XaiGrok,
                AuthErrorCode::ProviderRejected,
            ),
        ]);
    };
    let Ok(_data_root_lock) = acquire_data_root_lock(&configuration) else {
        return CliRunResult::auth_status([
            AuthStatusOutput::unavailable(
                SubscriptionService::OpenAiCodex,
                AuthErrorCode::ProviderRejected,
            ),
            AuthStatusOutput::unavailable(
                SubscriptionService::XaiGrok,
                AuthErrorCode::ProviderRejected,
            ),
        ]);
    };

    let openai = status_for_service(AuthService::Openai, &configuration).await;
    let grok = status_for_service(AuthService::Grok, &configuration).await;
    CliRunResult::auth_status([openai, grok])
}

async fn status_for_service(
    service: AuthService,
    configuration: &CommonConfiguration,
) -> AuthStatusOutput {
    let domain_service = service.subscription_service();
    let mut broker = match connect_broker(service, configuration, false).await {
        Ok(broker) => broker,
        Err(error) => return AuthStatusOutput::unavailable(domain_service, error.code()),
    };
    let record = match broker.auth_state().await {
        Ok(state) => AuthStatusOutput::from_state(domain_service, state),
        Err(error) => AuthStatusOutput::unavailable(domain_service, error.code()),
    };
    match broker.shutdown().await {
        Ok(()) => record,
        Err(error) => AuthStatusOutput::unavailable(domain_service, error.code()),
    }
}

async fn run_login<C>(
    service: AuthService,
    device: bool,
    configuration: &CommonConfiguration,
    mut cancellation: Pin<&mut C>,
) -> CliRunResult
where
    C: Future<Output = ()> + ?Sized,
{
    let connected =
        connect_with_cancellation(service, configuration, true, cancellation.as_mut()).await;
    let mut broker = match connected {
        ConnectionResult::Completed(Ok(broker)) => broker,
        ConnectionResult::Completed(Err(error)) => return operation_error(service, error.code()),
        ConnectionResult::Cancelled(Ok(mut broker)) => {
            let result = cancelled_after_cleanup(service, broker.as_mut()).await;
            return finish_broker(service, broker.as_mut(), result).await;
        }
        ConnectionResult::Cancelled(Err(error)) => {
            return operation_error(service, error.code());
        }
    };
    let result = run_login_operation(service, device, broker.as_mut(), cancellation.as_mut()).await;
    finish_broker(service, broker.as_mut(), result).await
}

async fn run_login_operation<C>(
    service: AuthService,
    device: bool,
    broker: &mut dyn SubscriptionAuthBroker,
    mut cancellation: Pin<&mut C>,
) -> CliRunResult
where
    C: Future<Output = ()> + ?Sized,
{
    let domain_service = service.subscription_service();
    let initial = {
        let state = broker.auth_state();
        tokio::select! {
            result = state => OperationResult::Completed(result),
            () = cancellation.as_mut() => OperationResult::Cancelled,
        }
    };
    let initial_state = match initial {
        OperationResult::Completed(Ok(state)) => state,
        OperationResult::Completed(Err(error)) => {
            return operation_error(service, error.code());
        }
        OperationResult::Cancelled => {
            return cancelled_after_cleanup(service, broker).await;
        }
    };
    if matches!(initial_state, AuthState::SignedIn { .. }) {
        return CliRunResult::auth_record(
            AuthStatusOutput::from_state(domain_service, initial_state),
            ExitClassification::Success,
        );
    }

    let method = if device {
        AuthMethod::DeviceCode
    } else {
        AuthMethod::BrowserOAuth
    };
    if service == AuthService::Openai && !local_foreground_terminal_available() {
        return operation_error(service, AuthErrorCode::ForegroundRequired);
    }
    let started = {
        let login = broker.start_login(method);
        tokio::select! {
            result = login => OperationResult::Completed(result),
            () = cancellation.as_mut() => OperationResult::Cancelled,
        }
    };
    let challenge = match started {
        OperationResult::Completed(Ok(challenge)) => challenge,
        OperationResult::Completed(Err(error)) => {
            return operation_error(service, error.code());
        }
        OperationResult::Cancelled => {
            return cancelled_after_cleanup(service, broker).await;
        }
    };

    if let Err(error) = render_login_challenge(service, challenge) {
        let result = match broker.cancel_login().await {
            Ok(()) => operation_error(service, error.code()),
            Err(cleanup) => operation_error(service, cleanup.code()),
        };
        return result;
    }

    let reconciled = {
        let state = broker.auth_state();
        tokio::select! {
            result = state => OperationResult::Completed(result),
            () = cancellation.as_mut() => OperationResult::Cancelled,
        }
    };
    let state = match reconciled {
        OperationResult::Completed(Ok(state)) => state,
        OperationResult::Completed(Err(error)) => {
            return operation_error(service, error.code());
        }
        OperationResult::Cancelled => {
            return cancelled_after_cleanup(service, broker).await;
        }
    };
    let exit = if matches!(state, AuthState::SignedIn { .. }) {
        ExitClassification::Success
    } else {
        ExitClassification::Failure
    };
    CliRunResult::auth_record(AuthStatusOutput::from_state(domain_service, state), exit)
}

async fn run_logout<C>(
    service: AuthService,
    configuration: &CommonConfiguration,
    mut cancellation: Pin<&mut C>,
) -> CliRunResult
where
    C: Future<Output = ()> + ?Sized,
{
    if service == AuthService::Openai
        && write_local_foreground_stderr(format!("{CODEX_LOGOUT_WARNING}\n").as_bytes()).is_err()
    {
        return operation_error(service, AuthErrorCode::ForegroundRequired);
    }

    let connected =
        connect_with_cancellation(service, configuration, true, cancellation.as_mut()).await;
    let mut broker = match connected {
        ConnectionResult::Completed(Ok(broker)) => broker,
        ConnectionResult::Completed(Err(error)) => return operation_error(service, error.code()),
        ConnectionResult::Cancelled(Ok(mut broker)) => {
            let result = cancelled_after_cleanup(service, broker.as_mut()).await;
            return finish_broker(service, broker.as_mut(), result).await;
        }
        ConnectionResult::Cancelled(Err(error)) => {
            return operation_error(service, error.code());
        }
    };
    let result = run_logout_operation(service, broker.as_mut(), cancellation.as_mut()).await;
    finish_broker(service, broker.as_mut(), result).await
}

async fn run_logout_operation<C>(
    service: AuthService,
    broker: &mut dyn SubscriptionAuthBroker,
    mut cancellation: Pin<&mut C>,
) -> CliRunResult
where
    C: Future<Output = ()> + ?Sized,
{
    let domain_service = service.subscription_service();
    if service == AuthService::Openai && !local_foreground_terminal_available() {
        return operation_error(service, AuthErrorCode::ForegroundRequired);
    }
    let logged_out = {
        let logout = broker.logout();
        tokio::select! {
            result = logout => OperationResult::Completed(result),
            () = cancellation.as_mut() => OperationResult::Cancelled,
        }
    };
    match logged_out {
        OperationResult::Completed(Ok(())) => {}
        OperationResult::Completed(Err(error)) => {
            return operation_error(service, error.code());
        }
        OperationResult::Cancelled => {
            return cancelled_after_cleanup(service, broker).await;
        }
    }

    let reconciled = {
        let state = broker.auth_state();
        tokio::select! {
            result = state => OperationResult::Completed(result),
            () = cancellation.as_mut() => OperationResult::Cancelled,
        }
    };
    let state = match reconciled {
        OperationResult::Completed(Ok(state)) => state,
        OperationResult::Completed(Err(error)) => {
            return operation_error(service, error.code());
        }
        OperationResult::Cancelled => {
            return cancelled_after_cleanup(service, broker).await;
        }
    };
    let exit = if matches!(state, AuthState::SignedOut) {
        ExitClassification::Success
    } else {
        ExitClassification::Failure
    };
    CliRunResult::auth_record(AuthStatusOutput::from_state(domain_service, state), exit)
}

fn render_login_challenge(
    service: AuthService,
    challenge: LoginChallenge,
) -> Result<(), AuthError> {
    let message = match (service, challenge) {
        (AuthService::Openai, LoginChallenge::Browser { authorization_url }) => format!(
            "Open this URL in your browser:\n{}\n",
            authorization_url.into_foreground_string()
        ),
        (
            AuthService::Openai,
            LoginChallenge::Device {
                verification_url,
                user_code,
            },
        ) => format!(
            "Open this URL on any device:\n{}\nEnter code:\n{}\n",
            verification_url.into_foreground_string(),
            user_code.into_foreground_string()
        ),
        (AuthService::Grok, LoginChallenge::ProviderManaged) => return Ok(()),
        (AuthService::Openai, LoginChallenge::ProviderManaged)
        | (AuthService::Grok, LoginChallenge::Browser { .. })
        | (AuthService::Grok, LoginChallenge::Device { .. }) => {
            return Err(AuthError::from_code(AuthErrorCode::ProtocolMismatch));
        }
    };
    write_local_foreground_stderr(message.as_bytes()).map_err(map_sidecar_error)
}

async fn connect_broker(
    service: AuthService,
    configuration: &CommonConfiguration,
    foreground: bool,
) -> Result<Box<dyn SubscriptionAuthBroker>, AuthError> {
    if service == AuthService::Grok && foreground {
        let authorization = authorize_local_foreground().map_err(map_sidecar_error)?;
        let (executable, home) = prepare_provider(service, configuration)?;
        let broker = GrokAuth::connect_local(
            &executable,
            home,
            SidecarLimits::default(),
            GrokAuthTimeouts::default(),
            authorization,
        )
        .await?;
        return Ok(Box::new(broker));
    }

    let (executable, home) = prepare_provider(service, configuration)?;
    match service {
        AuthService::Openai => Ok(Box::new(
            CodexAuth::connect(
                &executable,
                home,
                SidecarLimits::default(),
                CodexAuthTimeouts::default(),
            )
            .await?,
        )),
        AuthService::Grok => Ok(Box::new(
            GrokAuth::connect(
                &executable,
                home,
                SidecarLimits::default(),
                GrokAuthTimeouts::default(),
            )
            .await?,
        )),
    }
}

async fn connect_with_cancellation<C>(
    service: AuthService,
    configuration: &CommonConfiguration,
    foreground: bool,
    mut cancellation: Pin<&mut C>,
) -> ConnectionResult<Result<Box<dyn SubscriptionAuthBroker>, AuthError>>
where
    C: Future<Output = ()> + ?Sized,
{
    let mut connection = Box::pin(connect_broker(service, configuration, foreground));
    tokio::select! {
        result = connection.as_mut() => ConnectionResult::Completed(result),
        () = cancellation.as_mut() => {
            // Do not drop a partially constructed provider. Every constructor is
            // bounded and cleans its own failure path; retain it to completion so
            // the caller can await broker shutdown before releasing the data lock.
            ConnectionResult::Cancelled(connection.await)
        }
    }
}

fn prepare_provider(
    service: AuthService,
    configuration: &CommonConfiguration,
) -> Result<(TrustedExecutable, ProviderHome), AuthError> {
    let (candidate, explicit_override) = configured_executable(service)?;
    let provider_home = configuration
        .data_root
        .join("providers")
        .join(service.provider_directory());
    let home = ProviderHome::prepare(
        service.profile(),
        &configuration.data_root,
        &configuration.workspace,
        provider_home,
    )
    .map_err(map_sidecar_error)?;

    let resolved = ResolvedExecutable::resolve(&candidate).map_err(map_sidecar_error)?;
    let decision = if resolved.metadata_risk().is_none() {
        ExecutableTrustDecision::TrustCanonicalPath
    } else if explicit_override && candidate == resolved.canonical_path() {
        ExecutableTrustDecision::TrustCanonicalPathWithMetadataRisk
    } else {
        ExecutableTrustDecision::TrustCanonicalPath
    };
    let executable = resolved.trust(decision).map_err(map_sidecar_error)?;
    Ok((executable, home))
}

fn configured_executable(service: AuthService) -> Result<(PathBuf, bool), AuthError> {
    match env::var_os(service.executable_variable()) {
        Some(value) => {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                Ok((path, true))
            } else {
                Err(AuthError::from_code(AuthErrorCode::ProviderRejected))
            }
        }
        None => Ok((
            PathBuf::from(OsString::from(service.default_executable())),
            false,
        )),
    }
}

fn prepare_buzz_executable() -> Result<TrustedExecutable, AuthError> {
    let (candidate, explicit_override) = match env::var_os("CARL_BUZZ_EXECUTABLE") {
        Some(value) => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(AuthError::from_code(AuthErrorCode::ProviderRejected));
            }
            (path, true)
        }
        None => (PathBuf::from("buzz"), false),
    };
    let resolved = ResolvedExecutable::resolve(&candidate).map_err(map_sidecar_error)?;
    let decision = if resolved.metadata_risk().is_none() {
        ExecutableTrustDecision::TrustCanonicalPath
    } else if explicit_override && candidate == resolved.canonical_path() {
        ExecutableTrustDecision::TrustCanonicalPathWithMetadataRisk
    } else {
        ExecutableTrustDecision::TrustCanonicalPath
    };
    resolved.trust(decision).map_err(map_sidecar_error)
}

fn load_common_configuration() -> Result<CommonConfiguration, AuthError> {
    let data_root = env::var_os("CARL_DATA_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| AuthError::from_code(AuthErrorCode::ProviderRejected))?;
    let metadata = fs::symlink_metadata(&data_root)
        .map_err(|_| AuthError::from_code(AuthErrorCode::ProviderRejected))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(AuthError::from_code(AuthErrorCode::ProviderRejected));
    }
    let data_root = fs::canonicalize(data_root)
        .map_err(|_| AuthError::from_code(AuthErrorCode::ProviderRejected))?;
    let workspace = env::current_dir()
        .and_then(fs::canonicalize)
        .map_err(|_| AuthError::from_code(AuthErrorCode::ProviderRejected))?;
    Ok(CommonConfiguration {
        data_root,
        workspace,
    })
}

fn acquire_data_root_lock(
    configuration: &CommonConfiguration,
) -> Result<DataRootLock, AuthErrorCode> {
    DataRootLock::acquire(&configuration.data_root).map_err(|error| match error.code() {
        DataRootLockErrorCode::Contended
        | DataRootLockErrorCode::InvalidDataRoot
        | DataRootLockErrorCode::UnsafeLockFile
        | DataRootLockErrorCode::Unavailable => AuthErrorCode::ProviderRejected,
    })
}

fn operation_error(service: AuthService, code: AuthErrorCode) -> CliRunResult {
    CliRunResult::auth_record(
        AuthStatusOutput::unavailable(service.subscription_service(), code),
        ExitClassification::Failure,
    )
}

fn cancelled_operation(service: AuthService) -> CliRunResult {
    CliRunResult::auth_record(
        AuthStatusOutput::unavailable(service.subscription_service(), AuthErrorCode::Cancelled),
        ExitClassification::Cancelled,
    )
}

async fn cancelled_after_cleanup(
    service: AuthService,
    broker: &mut dyn SubscriptionAuthBroker,
) -> CliRunResult {
    match broker.cancel_login().await {
        Ok(()) => cancelled_operation(service),
        Err(error) => operation_error(service, error.code()),
    }
}

async fn finish_broker(
    service: AuthService,
    broker: &mut dyn SubscriptionAuthBroker,
    result: CliRunResult,
) -> CliRunResult {
    match broker.shutdown().await {
        Ok(()) => result,
        Err(error) => operation_error(service, error.code()),
    }
}

fn map_sidecar_error(error: SidecarError) -> AuthError {
    let code = match error.code() {
        SidecarErrorCode::ExecutableMissing => AuthErrorCode::ExecutableMissing,
        SidecarErrorCode::UnsupportedVersion => AuthErrorCode::UnsupportedVersion,
        SidecarErrorCode::ForegroundRequired => AuthErrorCode::ForegroundRequired,
        SidecarErrorCode::UnsafeProviderFile => AuthErrorCode::UnsafeCredentialStore,
        SidecarErrorCode::ProtocolViolation | SidecarErrorCode::DuplicateRequestId => {
            AuthErrorCode::ProtocolMismatch
        }
        SidecarErrorCode::SidecarExited => AuthErrorCode::SidecarExited,
        SidecarErrorCode::Cancelled => AuthErrorCode::Cancelled,
        SidecarErrorCode::TimedOut => AuthErrorCode::TimedOut,
        SidecarErrorCode::ExecutableUnavailable
        | SidecarErrorCode::UnsafeExecutable
        | SidecarErrorCode::InvalidProviderHome
        | SidecarErrorCode::InvalidConfiguration
        | SidecarErrorCode::SpawnFailed => AuthErrorCode::ProviderRejected,
    };
    AuthError::from_code(code)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context, Poll};

    use crate::auth::AuthFuture;

    use super::*;

    struct CancelWhenStarted(Arc<AtomicBool>);

    impl Future for CancelWhenStarted {
        type Output = ();

        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            if self.0.load(Ordering::Acquire) {
                Poll::Ready(())
            } else {
                context.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    struct PendingOperation<T> {
        dropped: Arc<AtomicBool>,
        _output: std::marker::PhantomData<fn() -> T>,
    }

    impl<T> Future for PendingOperation<T> {
        type Output = Result<T, AuthError>;

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl<T> Drop for PendingOperation<T> {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    struct CancellationBroker {
        operation_started: Arc<AtomicBool>,
        operation_dropped: Arc<AtomicBool>,
        cancel_called: Arc<AtomicBool>,
        shutdown_called: Arc<AtomicBool>,
        cancel_error: Option<AuthErrorCode>,
    }

    impl CancellationBroker {
        fn new(cancel_error: Option<AuthErrorCode>) -> Self {
            Self {
                operation_started: Arc::new(AtomicBool::new(false)),
                operation_dropped: Arc::new(AtomicBool::new(false)),
                cancel_called: Arc::new(AtomicBool::new(false)),
                shutdown_called: Arc::new(AtomicBool::new(false)),
                cancel_error,
            }
        }
    }

    impl SubscriptionAuthBroker for CancellationBroker {
        fn service(&self) -> SubscriptionService {
            SubscriptionService::XaiGrok
        }

        fn auth_state(&mut self) -> AuthFuture<'_, AuthState> {
            Box::pin(async { Ok(AuthState::SignedOut) })
        }

        fn start_login(&mut self, _method: AuthMethod) -> AuthFuture<'_, LoginChallenge> {
            self.operation_started.store(true, Ordering::Release);
            Box::pin(PendingOperation {
                dropped: Arc::clone(&self.operation_dropped),
                _output: std::marker::PhantomData,
            })
        }

        fn logout(&mut self) -> AuthFuture<'_, ()> {
            self.operation_started.store(true, Ordering::Release);
            Box::pin(PendingOperation {
                dropped: Arc::clone(&self.operation_dropped),
                _output: std::marker::PhantomData,
            })
        }

        fn cancel_login(&mut self) -> AuthFuture<'_, ()> {
            self.cancel_called.store(true, Ordering::Release);
            let error = self.cancel_error;
            Box::pin(async move {
                match error {
                    Some(code) => Err(AuthError::from_code(code)),
                    None => Ok(()),
                }
            })
        }

        fn shutdown(&mut self) -> AuthFuture<'_, ()> {
            self.shutdown_called.store(true, Ordering::Release);
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn injected_login_cancellation_drops_then_cleans_and_shuts_down() {
        let mut broker = CancellationBroker::new(None);
        let mut cancellation = Box::pin(CancelWhenStarted(Arc::clone(&broker.operation_started)));
        let result =
            run_login_operation(AuthService::Grok, false, &mut broker, cancellation.as_mut()).await;
        let result = finish_broker(AuthService::Grok, &mut broker, result).await;

        assert_eq!(result.exit_classification(), ExitClassification::Cancelled);
        assert_eq!(
            result.stdout(),
            concat!(
                "{\"service\":\"xai_grok\",\"availability\":\"unavailable\",",
                "\"state\":\"unavailable\",\"method\":null,\"plan\":null,",
                "\"error_code\":\"cancelled\"}\n"
            )
        );
        assert!(broker.operation_dropped.load(Ordering::Acquire));
        assert!(broker.cancel_called.load(Ordering::Acquire));
        assert!(broker.shutdown_called.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn injected_logout_cancellation_uses_the_same_cleanup_path() {
        let mut broker = CancellationBroker::new(None);
        let mut cancellation = Box::pin(CancelWhenStarted(Arc::clone(&broker.operation_started)));
        let result =
            run_logout_operation(AuthService::Grok, &mut broker, cancellation.as_mut()).await;
        let result = finish_broker(AuthService::Grok, &mut broker, result).await;

        assert_eq!(result.exit_classification(), ExitClassification::Cancelled);
        assert!(broker.operation_dropped.load(Ordering::Acquire));
        assert!(broker.cancel_called.load(Ordering::Acquire));
        assert!(broker.shutdown_called.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_cleanup_failure_is_not_reported_as_cancelled() {
        let mut broker = CancellationBroker::new(Some(AuthErrorCode::SidecarExited));
        let mut cancellation = Box::pin(CancelWhenStarted(Arc::clone(&broker.operation_started)));
        let result =
            run_login_operation(AuthService::Grok, false, &mut broker, cancellation.as_mut()).await;
        let result = finish_broker(AuthService::Grok, &mut broker, result).await;

        assert_eq!(result.exit_classification(), ExitClassification::Failure);
        assert!(
            result
                .stdout()
                .contains("\"error_code\":\"sidecar_exited\"")
        );
        assert!(!result.stdout().contains("\"error_code\":\"cancelled\""));
        assert!(broker.shutdown_called.load(Ordering::Acquire));
    }
}
