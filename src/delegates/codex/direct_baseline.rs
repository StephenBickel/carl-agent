use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use super::{
    CodexExecAdapter, CodexExecRequest, CodexExecRun, DelegateActivityKind, DelegateError,
    DelegateErrorCode, DelegateEvent, DelegateItemPhase, DelegateUsage,
};
use crate::delegates::{
    BoundedDelegateTask, DelegateSettings, DelegateSettingsLayers, ModelId, ReasoningEffort,
};
use crate::sidecar::ExecutionWorkspace;

const SCHEMA_VERSION: u16 = 1;
const CODEX_VERSION: &str = "0.146.0";
const MINIMUM_TIMEOUT: Duration = Duration::from_secs(60);
const MAXIMUM_TIMEOUT: Duration = Duration::from_secs(28_800);
const MAXIMUM_TASK_BYTES: usize = 16 * 1_024;
const START_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectBaselineProvider {
    Codex,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DirectCodexBaselineResult {
    #[serde(serialize_with = "serialize_schema_version")]
    pub schema_version: u16,
    pub provider: DirectBaselineProvider,
    #[serde(serialize_with = "serialize_codex_version")]
    pub codex_version: String,
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub completed: bool,
    pub elapsed_milliseconds: u64,
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
    pub command_executions: u64,
    pub file_changes: u64,
    pub mcp_tool_calls: u64,
    pub web_searches: u64,
    pub compatibility_events: u64,
}

fn serialize_schema_version<S>(value: &u16, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if *value != SCHEMA_VERSION {
        return Err(S::Error::custom("invalid direct baseline schema version"));
    }
    serializer.serialize_u16(*value)
}

fn serialize_codex_version<S>(value: &String, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if value != CODEX_VERSION {
        return Err(S::Error::custom("invalid direct baseline Codex version"));
    }
    serializer.serialize_str(value)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectCodexBaselineResultWire {
    schema_version: u16,
    provider: DirectBaselineProvider,
    codex_version: String,
    model: ModelId,
    effort: ReasoningEffort,
    completed: bool,
    elapsed_milliseconds: u64,
    input_tokens: u64,
    cached_input_tokens: u64,
    output_tokens: u64,
    command_executions: u64,
    file_changes: u64,
    mcp_tool_calls: u64,
    web_searches: u64,
    compatibility_events: u64,
}

impl<'de> Deserialize<'de> for DirectCodexBaselineResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = DirectCodexBaselineResultWire::deserialize(deserializer)?;
        if wire.schema_version != SCHEMA_VERSION
            || wire.provider != DirectBaselineProvider::Codex
            || wire.codex_version != CODEX_VERSION
        {
            return Err(D::Error::custom("invalid direct baseline result"));
        }
        Ok(Self {
            schema_version: wire.schema_version,
            provider: wire.provider,
            codex_version: wire.codex_version,
            model: wire.model,
            effort: wire.effort,
            completed: wire.completed,
            elapsed_milliseconds: wire.elapsed_milliseconds,
            input_tokens: wire.input_tokens,
            cached_input_tokens: wire.cached_input_tokens,
            output_tokens: wire.output_tokens,
            command_executions: wire.command_executions,
            file_changes: wire.file_changes,
            mcp_tool_calls: wire.mcp_tool_calls,
            web_searches: wire.web_searches,
            compatibility_events: wire.compatibility_events,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectBaselineErrorCode {
    InvalidRequest,
    AuthenticationRequired,
    Incompatible,
    StartFailed,
    ProtocolFailed,
    BudgetExhausted,
    Cancelled,
    TimedOut,
    ProviderFailed,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Eq, Error, PartialEq)]
#[error("The direct Codex baseline failed.")]
pub struct DirectBaselineError {
    code: DirectBaselineErrorCode,
}

impl DirectBaselineError {
    const fn new(code: DirectBaselineErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(self) -> DirectBaselineErrorCode {
        self.code
    }
}

impl DirectBaselineErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::AuthenticationRequired => "authentication_required",
            Self::Incompatible => "incompatible",
            Self::StartFailed => "start_failed",
            Self::ProtocolFailed => "protocol_failed",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::ProviderFailed => "provider_failed",
            Self::ArithmeticOverflow => "arithmetic_overflow",
        }
    }
}

impl fmt::Debug for DirectBaselineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectBaselineError")
            .field("code", &self.code)
            .finish()
    }
}

pub struct DirectCodexBaselineRequest {
    pub workspace: ExecutionWorkspace,
    pub task: BoundedDelegateTask,
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub timeout: Duration,
}

impl fmt::Debug for DirectCodexBaselineRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectCodexBaselineRequest")
            .field("workspace", &"<opaque>")
            .field("task", &"<redacted>")
            .field("model", &self.model)
            .field("effort", &self.effort)
            .field("timeout", &self.timeout)
            .finish()
    }
}

pub struct DirectCodexBaseline {
    adapter: CodexExecAdapter,
    clock: Arc<dyn DirectBaselineClock>,
    deadline: Arc<dyn DirectBaselineDeadline>,
}

pub trait DirectBaselineClock: Send + Sync + 'static {
    fn now(&self) -> Instant;
}

pub trait DirectBaselineDeadline: Send + Sync + 'static {
    fn wait(&self, timeout: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>>;
}

struct SystemDirectBaselineClock;
struct TokioDirectBaselineDeadline;

impl DirectBaselineClock for SystemDirectBaselineClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

impl DirectBaselineDeadline for TokioDirectBaselineDeadline {
    fn wait(&self, timeout: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(timeout))
    }
}

impl DirectCodexBaseline {
    #[must_use]
    pub fn new(adapter: CodexExecAdapter) -> Self {
        Self {
            adapter,
            clock: Arc::new(SystemDirectBaselineClock),
            deadline: Arc::new(TokioDirectBaselineDeadline),
        }
    }

    #[must_use]
    pub fn with_clock(adapter: CodexExecAdapter, clock: Arc<dyn DirectBaselineClock>) -> Self {
        Self {
            adapter,
            clock,
            deadline: Arc::new(TokioDirectBaselineDeadline),
        }
    }

    #[must_use]
    pub fn with_clock_and_deadline(
        adapter: CodexExecAdapter,
        clock: Arc<dyn DirectBaselineClock>,
        deadline: Arc<dyn DirectBaselineDeadline>,
    ) -> Self {
        Self {
            adapter,
            clock,
            deadline,
        }
    }

    pub async fn run(
        &self,
        request: DirectCodexBaselineRequest,
        cancellation: CancellationToken,
    ) -> Result<DirectCodexBaselineResult, DirectBaselineError> {
        validate_request(&request)?;
        if cancellation.is_cancelled() {
            return Err(DirectBaselineError::new(DirectBaselineErrorCode::Cancelled));
        }
        let started = self.clock.now();
        let DirectCodexBaselineRequest {
            workspace,
            task,
            model,
            effort,
            timeout: timeout_duration,
        } = request;
        let mut timeout = self.deadline.wait(timeout_duration);
        let settings = DelegateSettings::new(Some(model.clone()), Some(effort));
        let started_run = self.adapter.start(
            &workspace,
            CodexExecRequest {
                task,
                settings: DelegateSettingsLayers {
                    per_run: Some(&settings),
                    ..DelegateSettingsLayers::default()
                }
                .resolve(),
            },
        );
        tokio::pin!(started_run);
        enum StartSelection<T> {
            Completed(T),
            Cancelled,
            TimedOut,
        }
        let selected = tokio::select! {
            result = &mut started_run => StartSelection::Completed(result),
            () = cancellation.cancelled() => StartSelection::Cancelled,
            () = timeout.as_mut() => StartSelection::TimedOut,
        };
        let mut run = match selected {
            StartSelection::Completed(result) => result.map_err(map_delegate_error)?,
            StartSelection::Cancelled => {
                self.cleanup_started_run(started_run.as_mut()).await;
                return Err(DirectBaselineError::new(DirectBaselineErrorCode::Cancelled));
            }
            StartSelection::TimedOut => {
                self.cleanup_started_run(started_run.as_mut()).await;
                return Err(DirectBaselineError::new(DirectBaselineErrorCode::TimedOut));
            }
        };
        let mut counters = BaselineCounters::default();
        loop {
            enum Selection<T> {
                Completed(T),
                Cancelled,
                TimedOut,
            }
            let selected = tokio::select! {
                event = run.next_event() => Selection::Completed(event),
                () = cancellation.cancelled() => Selection::Cancelled,
                () = timeout.as_mut() => Selection::TimedOut,
            };
            match selected {
                Selection::Completed(Ok(Some(event))) => counters.observe(event)?,
                Selection::Completed(Ok(None)) => break,
                Selection::Completed(Err(error)) => return Err(map_delegate_error(error)),
                Selection::Cancelled => {
                    let _ = run.cancel().await;
                    return Err(DirectBaselineError::new(DirectBaselineErrorCode::Cancelled));
                }
                Selection::TimedOut => {
                    let _ = run.cancel().await;
                    return Err(DirectBaselineError::new(DirectBaselineErrorCode::TimedOut));
                }
            }
        }

        enum FinishSelection<T> {
            Completed(T),
            Cancelled,
            TimedOut,
        }
        let selected = {
            let finish = run.finish_in_place();
            tokio::pin!(finish);
            tokio::select! {
                result = &mut finish => FinishSelection::Completed(result),
                () = cancellation.cancelled() => FinishSelection::Cancelled,
                () = timeout.as_mut() => FinishSelection::TimedOut,
            }
        };
        let usage = match selected {
            FinishSelection::Completed(result) => result.map_err(map_delegate_error)?,
            FinishSelection::Cancelled => {
                let _ = run.cancel().await;
                return Err(DirectBaselineError::new(DirectBaselineErrorCode::Cancelled));
            }
            FinishSelection::TimedOut => {
                let _ = run.cancel().await;
                return Err(DirectBaselineError::new(DirectBaselineErrorCode::TimedOut));
            }
        };
        let elapsed = self
            .clock
            .now()
            .checked_duration_since(started)
            .ok_or_else(|| DirectBaselineError::new(DirectBaselineErrorCode::ArithmeticOverflow))?;
        let elapsed_milliseconds = elapsed_milliseconds(elapsed)?;
        Ok(counters.result(model, effort, usage, elapsed_milliseconds))
    }

    async fn cleanup_started_run<F>(&self, mut started_run: Pin<&mut F>)
    where
        F: Future<Output = Result<CodexExecRun, DelegateError>>,
    {
        let mut cleanup_timeout = self.deadline.wait(START_CLEANUP_TIMEOUT);
        let run = tokio::select! {
            result = started_run.as_mut() => result.ok(),
            () = cleanup_timeout.as_mut() => None,
        };
        if let Some(mut run) = run {
            let _ = run.cancel().await;
        }
    }
}

impl fmt::Debug for DirectCodexBaseline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DirectCodexBaseline")
            .field("provider", &DirectBaselineProvider::Codex)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct BaselineCounters {
    command_executions: u64,
    file_changes: u64,
    mcp_tool_calls: u64,
    web_searches: u64,
    compatibility_events: u64,
}

impl BaselineCounters {
    fn observe(&mut self, event: DelegateEvent) -> Result<(), DirectBaselineError> {
        match event {
            DelegateEvent::Activity {
                kind,
                phase: DelegateItemPhase::Completed,
                ..
            } => match kind {
                DelegateActivityKind::CommandExecution => increment(&mut self.command_executions)?,
                DelegateActivityKind::FileChange => increment(&mut self.file_changes)?,
                DelegateActivityKind::McpToolCall => increment(&mut self.mcp_tool_calls)?,
                DelegateActivityKind::WebSearch => increment(&mut self.web_searches)?,
                DelegateActivityKind::AgentMessage
                | DelegateActivityKind::Reasoning
                | DelegateActivityKind::PlanUpdate => {}
            },
            DelegateEvent::Compatibility { .. } => increment(&mut self.compatibility_events)?,
            DelegateEvent::ThreadStarted { .. }
            | DelegateEvent::TurnStarted
            | DelegateEvent::AgentMessage { .. }
            | DelegateEvent::Activity { .. }
            | DelegateEvent::Terminal(_) => {}
        }
        Ok(())
    }

    fn result(
        self,
        model: ModelId,
        effort: ReasoningEffort,
        usage: DelegateUsage,
        elapsed_milliseconds: u64,
    ) -> DirectCodexBaselineResult {
        DirectCodexBaselineResult {
            schema_version: SCHEMA_VERSION,
            provider: DirectBaselineProvider::Codex,
            codex_version: CODEX_VERSION.to_owned(),
            model,
            effort,
            completed: true,
            elapsed_milliseconds,
            input_tokens: usage.input_tokens,
            cached_input_tokens: usage.cached_input_tokens,
            output_tokens: usage.output_tokens,
            command_executions: self.command_executions,
            file_changes: self.file_changes,
            mcp_tool_calls: self.mcp_tool_calls,
            web_searches: self.web_searches,
            compatibility_events: self.compatibility_events,
        }
    }
}

fn validate_request(request: &DirectCodexBaselineRequest) -> Result<(), DirectBaselineError> {
    if request.timeout < MINIMUM_TIMEOUT
        || request.timeout > MAXIMUM_TIMEOUT
        || request.task.as_str().len() > MAXIMUM_TASK_BYTES
    {
        return Err(DirectBaselineError::new(
            DirectBaselineErrorCode::InvalidRequest,
        ));
    }
    Ok(())
}

fn increment(counter: &mut u64) -> Result<(), DirectBaselineError> {
    *counter = counter
        .checked_add(1)
        .ok_or_else(|| DirectBaselineError::new(DirectBaselineErrorCode::ArithmeticOverflow))?;
    Ok(())
}

fn elapsed_milliseconds(elapsed: Duration) -> Result<u64, DirectBaselineError> {
    elapsed
        .as_millis()
        .try_into()
        .map_err(|_| DirectBaselineError::new(DirectBaselineErrorCode::ArithmeticOverflow))
}

const fn map_delegate_error(error: DelegateError) -> DirectBaselineError {
    let code = match error.code() {
        DelegateErrorCode::Configuration => DirectBaselineErrorCode::InvalidRequest,
        DelegateErrorCode::AuthenticationRequired => {
            DirectBaselineErrorCode::AuthenticationRequired
        }
        DelegateErrorCode::Incompatible => DirectBaselineErrorCode::Incompatible,
        DelegateErrorCode::StartFailed => DirectBaselineErrorCode::StartFailed,
        DelegateErrorCode::ProtocolFailed => DirectBaselineErrorCode::ProtocolFailed,
        DelegateErrorCode::BudgetExhausted => DirectBaselineErrorCode::BudgetExhausted,
        DelegateErrorCode::Cancelled => DirectBaselineErrorCode::Cancelled,
        DelegateErrorCode::ProviderFailed => DirectBaselineErrorCode::ProviderFailed,
    };
    DirectBaselineError::new(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increment_rejects_overflow() {
        let mut counter = u64::MAX;
        let error = increment(&mut counter).expect_err("counter overflow must fail closed");
        assert_eq!(error.code(), DirectBaselineErrorCode::ArithmeticOverflow);
    }

    #[test]
    fn elapsed_conversion_rejects_overflow() {
        let error = elapsed_milliseconds(Duration::MAX)
            .expect_err("elapsed milliseconds beyond u64 must fail closed");
        assert_eq!(error.code(), DirectBaselineErrorCode::ArithmeticOverflow);
    }
}
