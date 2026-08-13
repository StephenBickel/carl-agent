use std::env;
use std::ffi::OsString;
use std::fs;
use std::future::{Future, pending};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use chrono::{TimeDelta, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use tokio::io::{AsyncReadExt, BufReader};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::acp::{
    AcpServerConfig, BuzzPublisher, BuzzPublisherBootstrap, BuzzPublisherConfig, PermissionMode,
    ServiceAcpServer,
};
use crate::auth::codex::{CODEX_LOGOUT_WARNING, CodexAuth, CodexAuthTimeouts};
use crate::auth::grok::{GrokAuth, GrokAuthTimeouts};
use crate::auth::{
    AuthError, AuthErrorCode, AuthMethod, AuthState, AuthUnavailableCode, LoginChallenge,
    SubscriptionAuthBroker, SubscriptionPlan, SubscriptionService,
};
use crate::buzz_mcp;
use crate::delegates::codex::{
    CodexAppServer, CodexExecAdapter, DirectBaselineErrorCode, DirectCodexBaseline,
    DirectCodexBaselineRequest,
};
use crate::delegates::{BoundedDelegateTask, ModelId, ReasoningEffort};
use crate::error::{CarlError, ErrorCode};
use crate::events::SessionId;
use crate::memory::{
    MemoryKind, MemoryPartition, MemoryQuery, MemoryScope, MemorySettings, MemoryWrite,
};
use crate::policy::Frontend;
use crate::providers::catalog::{ProviderCatalog, ProviderKind, ProviderModel};
use crate::providers::http::{ProviderEndpoint, ProviderHttpClient, SecretCredential};
use crate::providers::openai::OpenAiProvider;
use crate::providers::openrouter::OpenRouterProvider;
use crate::runtime::agent_port::AgentPort;
use crate::runtime::native_port::NativeAgentPort;
use crate::runtime::task::TaskBudget;
use crate::service::client::TaskServiceClient;
use crate::service::protocol::{
    MaintenancePhase, SERVICE_PROTOCOL_VERSION, ServiceCommand, ServiceMaintenanceStatus,
    ServiceRequest, ServiceResult,
};
use crate::service::server::TaskService;
use crate::sidecar::{
    DataRootLock, DataRootLockErrorCode, ExecutableTrustDecision, ExecutionWorkspace,
    ProviderEnvironmentProfile, ProviderHome, ResolvedExecutable, SidecarError, SidecarErrorCode,
    SidecarLimits, TrustedExecutable, authorize_local_foreground,
    local_foreground_terminal_available, write_local_foreground_stderr,
};
use crate::storage::{Store, TrustedFrontendOwnerInput};

#[derive(Debug, Parser)]
#[command(name = "carl")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    #[must_use]
    pub fn selected_command(self) -> Command {
        self.command
            .unwrap_or_else(|| Command::Tui(TuiArgs::default()))
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Tui(TuiArgs),
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
    Trust {
        #[command(subcommand)]
        command: TrustCommand,
    },
    Maintenance {
        #[command(subcommand)]
        command: MaintenanceCommand,
    },
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    Pair,
    Doctor,
    Sessions,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Args)]
pub struct TuiArgs {}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum BaselineCommand {
    Codex(BaselineCodexArgs),
}

#[derive(Clone, Debug, Eq, PartialEq, Args)]
pub struct BaselineCodexArgs {
    #[arg(long)]
    pub workspace: PathBuf,
    #[arg(long)]
    pub model: String,
    #[arg(long, value_enum)]
    pub effort: AcpEffort,
    #[arg(long, default_value_t = 7_200, value_parser = parse_baseline_timeout_seconds)]
    pub timeout_seconds: u64,
}

fn parse_baseline_timeout_seconds(value: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| "value must be an unsigned 64-bit integer".to_owned())?;
    if !(60..=28_800).contains(&parsed) {
        return Err("value must be between 60 and 28800 seconds".to_owned());
    }
    Ok(parsed)
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
    #[arg(long, value_parser = parse_max_wall_time_seconds)]
    pub max_wall_time_seconds: Option<u64>,
    #[arg(long, value_parser = parse_max_provider_requests)]
    pub max_provider_requests: Option<u64>,
    #[arg(long, value_parser = parse_max_tool_calls)]
    pub max_tool_calls: Option<u64>,
    #[arg(long, default_value_t = 900, value_parser = parse_soft_epoch_seconds)]
    pub soft_epoch_seconds: u64,
    #[arg(long, default_value_t = 40, value_parser = parse_soft_epoch_tool_calls)]
    pub soft_epoch_tool_calls: u32,
}

impl AcpArgs {
    #[must_use]
    pub const fn task_budget(&self) -> TaskBudget {
        TaskBudget {
            max_wall_time_seconds: self.max_wall_time_seconds,
            max_provider_requests: self.max_provider_requests,
            max_tool_calls: self.max_tool_calls,
            soft_epoch_seconds: self.soft_epoch_seconds,
            soft_epoch_tool_calls: self.soft_epoch_tool_calls,
        }
    }
}

fn parse_max_wall_time_seconds(value: &str) -> Result<u64, String> {
    parse_budget_u64(value, |budget, parsed| {
        budget.max_wall_time_seconds = Some(parsed);
    })
}

fn parse_max_provider_requests(value: &str) -> Result<u64, String> {
    parse_budget_u64(value, |budget, parsed| {
        budget.max_provider_requests = Some(parsed);
    })
}

fn parse_max_tool_calls(value: &str) -> Result<u64, String> {
    parse_budget_u64(value, |budget, parsed| {
        budget.max_tool_calls = Some(parsed);
    })
}

fn parse_soft_epoch_seconds(value: &str) -> Result<u64, String> {
    parse_budget_u64(value, |budget, parsed| {
        budget.soft_epoch_seconds = parsed;
    })
}

fn parse_soft_epoch_tool_calls(value: &str) -> Result<u32, String> {
    let parsed = value
        .parse::<u32>()
        .map_err(|_| "value must be an unsigned 32-bit integer".to_owned())?;
    let budget = TaskBudget {
        soft_epoch_tool_calls: parsed,
        ..TaskBudget::default()
    };
    budget
        .validate_for_admission()
        .map_err(|error| error.to_string())?;
    Ok(parsed)
}

fn parse_budget_u64(value: &str, assign: impl FnOnce(&mut TaskBudget, u64)) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| "value must be an unsigned 64-bit integer".to_owned())?;
    let mut budget = TaskBudget::default();
    assign(&mut budget, parsed);
    budget
        .validate_for_admission()
        .map_err(|error| error.to_string())?;
    Ok(parsed)
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

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum TrustCommand {
    Buzz {
        #[arg(long)]
        actor: String,
        #[arg(long)]
        workspace: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Subcommand)]
pub enum MaintenanceCommand {
    Status,
    Prepare,
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
    #[value(name = "fullAccess")]
    FullAccess,
}

impl From<AcpPermissionMode> for PermissionMode {
    fn from(value: AcpPermissionMode) -> Self {
        match value {
            AcpPermissionMode::Plan => Self::Plan,
            AcpPermissionMode::Default => Self::Default,
            AcpPermissionMode::AcceptEdits => Self::AcceptEdits,
            AcpPermissionMode::DontAsk => Self::DontAsk,
            AcpPermissionMode::FullAccess => Self::FullAccess,
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
struct TrustOutput {
    trusted: bool,
    frontend: Frontend,
    channel_bound: bool,
    permission_mode: PermissionMode,
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
        Command::Tui(_) => CliRunResult::not_implemented("tui streaming dispatch"),
        Command::Auth { command } => run_auth(command, cancellation.as_mut()).await,
        Command::Acp(_) => CliRunResult::not_implemented("acp streaming dispatch"),
        Command::Memory { command } => run_memory(command),
        Command::Trust { command } => run_trust(command),
        Command::Maintenance { command } => run_maintenance(command, cancellation.as_mut()).await,
        Command::Baseline { command } => run_baseline(command, cancellation.as_mut()).await,
        Command::Serve => run_serve(cancellation.as_mut()).await,
        Command::Pair => CliRunResult::not_implemented("pair"),
        Command::Doctor => CliRunResult::not_implemented("doctor"),
        Command::Sessions => CliRunResult::not_implemented("sessions"),
    }
}

async fn run_baseline<C>(command: BaselineCommand, mut cancellation: Pin<&mut C>) -> CliRunResult
where
    C: Future<Output = ()> + ?Sized,
{
    match command {
        BaselineCommand::Codex(args) => {
            let prepared = match prepare_direct_codex_baseline(&args) {
                Ok(prepared) => prepared,
                Err(code) => return direct_baseline_error(code),
            };
            let mut task_bytes = Vec::with_capacity(16 * 1_024 + 1);
            let mut stdin = tokio::io::stdin().take(16 * 1_024 + 1);
            let read = stdin.read_to_end(&mut task_bytes);
            tokio::pin!(read);
            tokio::select! {
                result = &mut read => {
                    if result.is_err() {
                        return direct_baseline_error(DirectBaselineErrorCode::InvalidRequest);
                    }
                }
                () = cancellation.as_mut() => {
                    return direct_baseline_cancelled();
                }
            }
            run_prepared_direct_codex_baseline(prepared, &task_bytes, cancellation.as_mut()).await
        }
    }
}

/// Run the direct baseline with explicit bytes after performing the same production
/// trust, provider-home, and credential bootstrap used by the stdin command.
#[doc(hidden)]
pub async fn run_baseline_codex_with_input(
    args: BaselineCodexArgs,
    input: &[u8],
    cancellation: CancellationToken,
) -> CliRunResult {
    let prepared = match prepare_direct_codex_baseline(&args) {
        Ok(prepared) => prepared,
        Err(code) => return direct_baseline_error(code),
    };
    let cancellation_future = cancellation.cancelled_owned();
    tokio::pin!(cancellation_future);
    run_prepared_direct_codex_baseline(prepared, input, cancellation_future.as_mut()).await
}

struct PreparedDirectCodexBaseline {
    baseline: DirectCodexBaseline,
    workspace: ExecutionWorkspace,
    model: ModelId,
    effort: ReasoningEffort,
    timeout: Duration,
    _data_root_lock: DataRootLock,
}

fn prepare_direct_codex_baseline(
    args: &BaselineCodexArgs,
) -> Result<PreparedDirectCodexBaseline, DirectBaselineErrorCode> {
    if ["OPENAI_API_KEY", "CODEX_API_KEY", "AZURE_OPENAI_API_KEY"]
        .into_iter()
        .any(|variable| env::var_os(variable).is_some())
    {
        return Err(DirectBaselineErrorCode::InvalidRequest);
    }
    let data_root = env::var_os("CARL_DATA_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or(DirectBaselineErrorCode::StartFailed)?;
    let data_root =
        fs::canonicalize(data_root).map_err(|_| DirectBaselineErrorCode::StartFailed)?;
    let data_root_lock =
        DataRootLock::acquire(&data_root).map_err(|_| DirectBaselineErrorCode::StartFailed)?;
    let canonical_workspace =
        fs::canonicalize(&args.workspace).map_err(|_| DirectBaselineErrorCode::InvalidRequest)?;
    if canonical_workspace != args.workspace {
        return Err(DirectBaselineErrorCode::InvalidRequest);
    }
    let workspace = ExecutionWorkspace::open(&canonical_workspace)
        .map_err(|_| DirectBaselineErrorCode::InvalidRequest)?;
    let provider_home = data_root.join("providers").join("codex");
    let home = ProviderHome::prepare(
        ProviderEnvironmentProfile::Codex,
        &data_root,
        &canonical_workspace,
        provider_home,
    )
    .map_err(|_| DirectBaselineErrorCode::StartFailed)?;
    let (candidate, explicit_override) = configured_executable(AuthService::Openai)
        .map_err(|_| DirectBaselineErrorCode::StartFailed)?;
    let resolved = ResolvedExecutable::resolve(&candidate)
        .map_err(|_| DirectBaselineErrorCode::StartFailed)?;
    let decision = if resolved.metadata_risk().is_none() {
        ExecutableTrustDecision::TrustCanonicalPath
    } else if explicit_override && candidate == resolved.canonical_path() {
        ExecutableTrustDecision::TrustCanonicalPathWithMetadataRisk
    } else {
        ExecutableTrustDecision::TrustCanonicalPath
    };
    let executable = resolved
        .trust(decision)
        .map_err(|_| DirectBaselineErrorCode::StartFailed)?;
    let adapter =
        CodexExecAdapter::new(executable, home, SidecarLimits::default()).map_err(|error| {
            match error.code() {
                crate::delegates::codex::DelegateErrorCode::AuthenticationRequired => {
                    DirectBaselineErrorCode::AuthenticationRequired
                }
                crate::delegates::codex::DelegateErrorCode::Incompatible => {
                    DirectBaselineErrorCode::Incompatible
                }
                _ => DirectBaselineErrorCode::StartFailed,
            }
        })?;
    Ok(PreparedDirectCodexBaseline {
        baseline: DirectCodexBaseline::new(adapter),
        workspace,
        model: ModelId::parse(args.model.clone())
            .map_err(|_| DirectBaselineErrorCode::InvalidRequest)?,
        effort: args.effort.into(),
        timeout: Duration::from_secs(args.timeout_seconds),
        _data_root_lock: data_root_lock,
    })
}

async fn run_prepared_direct_codex_baseline<C>(
    prepared: PreparedDirectCodexBaseline,
    input: &[u8],
    mut cancellation: Pin<&mut C>,
) -> CliRunResult
where
    C: Future<Output = ()> + ?Sized,
{
    let task = match std::str::from_utf8(input) {
        Ok(task) if !task.is_empty() && input.len() <= 16 * 1_024 => task,
        _ => return direct_baseline_error(DirectBaselineErrorCode::InvalidRequest),
    };
    let task = match BoundedDelegateTask::parse(task.to_owned()) {
        Ok(task) => task,
        Err(_) => return direct_baseline_error(DirectBaselineErrorCode::InvalidRequest),
    };
    let token = CancellationToken::new();
    let run = prepared.baseline.run(
        DirectCodexBaselineRequest {
            workspace: prepared.workspace,
            task,
            model: prepared.model,
            effort: prepared.effort,
            timeout: prepared.timeout,
        },
        token.clone(),
    );
    tokio::pin!(run);
    let result = tokio::select! {
        result = &mut run => result,
        () = cancellation.as_mut() => {
            token.cancel();
            run.await
        }
    };
    match result {
        Ok(result) => CliRunResult::json_success(&result),
        Err(error) if error.code() == DirectBaselineErrorCode::Cancelled => {
            direct_baseline_cancelled()
        }
        Err(error) => direct_baseline_error(error.code()),
    }
}

fn direct_baseline_error(code: DirectBaselineErrorCode) -> CliRunResult {
    CliRunResult {
        stdout: String::new(),
        stderr: format!("carl baseline codex: failed ({})\n", code.as_str()),
        exit: ExitClassification::Failure,
    }
}

fn direct_baseline_cancelled() -> CliRunResult {
    CliRunResult {
        stdout: String::new(),
        stderr: "carl baseline codex: cancelled\n".to_owned(),
        exit: ExitClassification::Cancelled,
    }
}

async fn run_maintenance<C>(
    command: MaintenanceCommand,
    mut cancellation: Pin<&mut C>,
) -> CliRunResult
where
    C: Future<Output = ()> + ?Sized,
{
    let Ok(configuration) = load_common_configuration() else {
        return service_cli_result(
            ExitClassification::Failure,
            "carl maintenance: invalid Carl data directory or workspace",
        );
    };
    let connected = TaskServiceClient::connect(&configuration.data_root);
    tokio::pin!(connected);
    let mut client = tokio::select! {
        result = &mut connected => match result {
            Ok(client) => client,
            Err(_) => return service_cli_result(
                ExitClassification::Failure,
                "carl maintenance: persistent task service unavailable",
            ),
        },
        () = cancellation.as_mut() => {
            return service_cli_result(ExitClassification::Cancelled, "");
        }
    };
    let first_command = match command {
        MaintenanceCommand::Status => ServiceCommand::MaintenanceStatus,
        MaintenanceCommand::Prepare => ServiceCommand::PrepareMaintenance,
    };
    let mut status = {
        let initial = maintenance_request(&mut client, first_command);
        tokio::pin!(initial);
        tokio::select! {
            result = &mut initial => match result {
                Some(status) => status,
                None => return service_cli_result(
                    ExitClassification::Failure,
                    "carl maintenance: service command failed",
                ),
            },
            () = cancellation.as_mut() => {
                return service_cli_result(ExitClassification::Cancelled, "");
            }
        }
    };
    let mut poll = maintenance_poll_interval();
    while command == MaintenanceCommand::Prepare && status.phase != MaintenancePhase::Ready {
        tokio::select! {
            _ = poll.tick() => {}
            () = cancellation.as_mut() => {
                return service_cli_result(ExitClassification::Cancelled, "");
            }
        }
        let requested = maintenance_request(&mut client, ServiceCommand::MaintenanceStatus);
        tokio::pin!(requested);
        status = tokio::select! {
            result = &mut requested => match result {
                Some(status) => status,
                None => return service_cli_result(
                    ExitClassification::Failure,
                    "carl maintenance: status polling failed",
                ),
            },
            () = cancellation.as_mut() => {
                return service_cli_result(ExitClassification::Cancelled, "");
            }
        };
    }
    CliRunResult::json_success(&status)
}

fn maintenance_poll_interval() -> tokio::time::Interval {
    let period = Duration::from_millis(100);
    let start = tokio::time::Instant::now() + period;
    let mut interval = tokio::time::interval_at(start, period);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    interval
}

async fn maintenance_request(
    client: &mut TaskServiceClient,
    command: ServiceCommand,
) -> Option<ServiceMaintenanceStatus> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let result = client
        .request(ServiceRequest {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            idempotency_key: format!("maintenance-{request_id}"),
            request_id,
            command,
        })
        .await
        .ok()?;
    match result {
        ServiceResult::Maintenance(status) => Some(status),
        _ => None,
    }
}

async fn run_serve<C>(mut cancellation: Pin<&mut C>) -> CliRunResult
where
    C: Future<Output = ()> + ?Sized,
{
    let Ok(configuration) = load_common_configuration() else {
        return service_cli_result(
            ExitClassification::Failure,
            "carl serve: invalid Carl data directory or workspace",
        );
    };
    let Ok(port) = configured_service_port(&configuration).await else {
        return service_cli_result(
            ExitClassification::Failure,
            "carl serve: configured provider startup failed",
        );
    };
    let Ok(service) = TaskService::bind(&configuration.data_root, port).await else {
        return service_cli_result(
            ExitClassification::Failure,
            "carl serve: Carl data directory is unsafe or already owned",
        );
    };
    let stop = CancellationToken::new();
    let serve = service.serve(stop.clone());
    tokio::pin!(serve);
    let (result, cancelled) = tokio::select! {
        result = &mut serve => (result, false),
        () = cancellation.as_mut() => {
            stop.cancel();
            (serve.await, true)
        }
    };
    match (result, cancelled) {
        (Ok(()), false) => service_cli_result(ExitClassification::Success, ""),
        (Ok(()), true) => service_cli_result(ExitClassification::Cancelled, ""),
        (Err(_), _) => service_cli_result(
            ExitClassification::Failure,
            "carl serve: persistent task service failed",
        ),
    }
}

async fn configured_service_port(
    configuration: &CommonConfiguration,
) -> Result<Box<dyn AgentPort>, ()> {
    match env::var("CARL_PROVIDER").as_deref() {
        Ok("openai") => {
            let credential = environment_credential("OPENAI_API_KEY")?;
            let catalog = native_openai_catalog()?;
            let provider = OpenAiProvider::new(
                ProviderHttpClient::new(ProviderEndpoint::openai()).map_err(|_| ())?,
                credential,
                catalog.clone(),
            )
            .map_err(|_| ())?;
            Ok(Box::new(NativeAgentPort::new(Arc::new(provider), catalog)))
        }
        Ok("openrouter") => {
            let credential = environment_credential("OPENROUTER_API_KEY")?;
            let provider = OpenRouterProvider::discover(
                ProviderHttpClient::new(ProviderEndpoint::openrouter()).map_err(|_| ())?,
                credential,
                CancellationToken::new(),
            )
            .await
            .map_err(|_| ())?;
            let catalog = provider.catalog().clone();
            Ok(Box::new(NativeAgentPort::new(Arc::new(provider), catalog)))
        }
        Ok("subscription") | Err(env::VarError::NotPresent) => {
            let (executable, home) =
                prepare_provider(AuthService::Openai, configuration).map_err(|_| ())?;
            let codex = CodexAppServer::connect(&executable, home, SidecarLimits::default())
                .await
                .map_err(|_| ())?;
            Ok(Box::new(codex))
        }
        Ok(_) | Err(env::VarError::NotUnicode(_)) => Err(()),
    }
}

fn environment_credential(name: &'static str) -> Result<SecretCredential, ()> {
    let value = env::var(name).map_err(|_| ())?;
    SecretCredential::new(value.into_bytes()).map_err(|_| ())
}

fn native_openai_catalog() -> Result<ProviderCatalog, ()> {
    let model = ProviderModel::new(
        ModelId::parse("gpt-5.2-codex").map_err(|_| ())?,
        "GPT 5.2 Codex".to_owned(),
        400_000,
        vec![
            ReasoningEffort::Low,
            ReasoningEffort::Medium,
            ReasoningEffort::High,
            ReasoningEffort::XHigh,
        ],
        ReasoningEffort::High,
        true,
        true,
        true,
    )
    .map_err(|_| ())?;
    ProviderCatalog::new(
        ProviderKind::OpenAiApi,
        vec![model.clone()],
        model.id().clone(),
    )
    .map_err(|_| ())
}

fn service_cli_result(exit: ExitClassification, message: &'static str) -> CliRunResult {
    CliRunResult {
        stdout: String::new(),
        stderr: if message.is_empty() {
            String::new()
        } else {
            format!("{message}\n")
        },
        exit,
    }
}

fn run_trust(command: TrustCommand) -> CliRunResult {
    let configuration = match load_common_configuration() {
        Ok(configuration) => configuration,
        Err(_) => {
            return CliRunResult::memory_error(&CarlError::Configuration {
                detail: "trust commands require a trusted CARL_DATA_DIR".to_owned(),
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
    let result = match command {
        TrustCommand::Buzz { actor, workspace } => {
            if actor.len() != 64
                || !actor
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                Err(CarlError::Validation {
                    detail: "Buzz owner actor ID is invalid".to_owned(),
                })
            } else {
                crate::policy::ActorId::parse(actor)
                    .map_err(|_| CarlError::Validation {
                        detail: "Buzz owner actor ID is invalid".to_owned(),
                    })
                    .and_then(|actor_id| {
                        store.trust_frontend_owner(TrustedFrontendOwnerInput {
                            frontend: Frontend::Buzz,
                            actor_id,
                            workspace,
                            permission_mode: PermissionMode::FullAccess,
                            trusted_at: Utc::now(),
                        })
                    })
            }
        }
    };
    match result {
        Ok(record) => CliRunResult::json_success(&TrustOutput {
            trusted: true,
            frontend: record.frontend,
            channel_bound: record.channel_id.is_some(),
            permission_mode: record.permission_mode,
        }),
        Err(error) => CliRunResult::memory_error(&error),
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
    let frontend = if env::var_os("BUZZ_ACP_AGENTS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        Frontend::Buzz
    } else {
        Frontend::Acp
    };
    try_run_service_acp(&configuration, args, frontend)
        .await
        .unwrap_or_else(|| {
            acp_failure("carl acp: persistent service unavailable; run `carl serve`")
        })
}

async fn try_run_service_acp(
    configuration: &CommonConfiguration,
    args: AcpArgs,
    frontend: Frontend,
) -> Option<ExitClassification> {
    let budget = args.task_budget();
    let model = match args.model {
        Some(model) => match ModelId::parse(model) {
            Ok(model) => Some(model),
            Err(_) => return Some(acp_failure("carl acp: model ID is invalid")),
        },
        None => None,
    };
    let permission_mode = if args.dangerously_bypass_permissions {
        PermissionMode::FullAccess
    } else {
        args.permission_mode
            .map(Into::into)
            .unwrap_or(if frontend == Frontend::Acp {
                PermissionMode::FullAccess
            } else {
                PermissionMode::Default
            })
    };
    let buzz_publisher = if frontend == Frontend::Buzz {
        let executable = prepare_buzz_executable().ok()?;
        let workspace = ExecutionWorkspace::open(&configuration.workspace).ok()?;
        Some(BuzzPublisherBootstrap::new(executable, workspace))
    } else {
        None
    };
    let Ok(server) = ServiceAcpServer::new(
        &configuration.data_root,
        AcpServerConfig {
            frontend,
            model,
            effort: args.effort.map(Into::into),
            permission_mode,
            budget,
            buzz_publisher,
        },
    )
    .await
    else {
        return None;
    };
    let input = BufReader::new(tokio::io::stdin());
    let serving = server.serve(input, tokio::io::stdout());
    tokio::pin!(serving);
    Some(tokio::select! {
        result = &mut serving => match result {
            Ok(()) => ExitClassification::Success,
            Err(_) => acp_failure("carl acp: ACP transport failed"),
        },
        () = registered_ctrl_c() => ExitClassification::Cancelled,
    })
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

    #[test]
    fn maintenance_output_is_one_bounded_closed_json_object() {
        let status = ServiceMaintenanceStatus {
            schema_version: 1,
            phase: MaintenancePhase::Ready,
            task_id: None,
            checkpoint_id: None,
        };
        let result = CliRunResult::json_success(&status);
        assert_eq!(
            result.stdout(),
            "{\"schema_version\":1,\"phase\":\"ready\",\"task_id\":null,\"checkpoint_id\":null}\n"
        );
        assert!(result.stdout().len() < 1024);
        assert!(result.stderr().is_empty());
        for ambient in ["OPENAI_API_KEY", "CARL_DATA_DIR", "/provider/home"] {
            assert!(!result.stdout().contains(ambient));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn maintenance_polling_is_capped_while_draining() {
        let mut poll = maintenance_poll_interval();
        tokio::select! {
            biased;
            _ = poll.tick() => panic!("maintenance polled before its bounded interval"),
            () = tokio::task::yield_now() => {}
        }
        tokio::time::advance(Duration::from_millis(99)).await;
        tokio::select! {
            biased;
            _ = poll.tick() => panic!("maintenance polled before 100 ms elapsed"),
            () = tokio::task::yield_now() => {}
        }
        tokio::time::advance(Duration::from_millis(1)).await;
        poll.tick().await;
        tokio::time::advance(Duration::from_millis(100)).await;
        poll.tick().await;
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
