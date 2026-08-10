use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use thiserror::Error;

use crate::acp::PermissionMode;
use crate::delegates::{ModelId, ReasoningEffort};
use crate::policy::Sha256Digest;

const MAX_AGENT_ID_BYTES: usize = 128;

pub type AgentFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AgentPortError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentPortErrorCode {
    Unsupported,
    InvalidRequest,
    InvalidResponse,
    UnavailableContext,
    Transport,
    Cancelled,
}

#[derive(Clone, Eq, Error, PartialEq)]
#[error("The agent provider request failed.")]
pub struct AgentPortError {
    code: AgentPortErrorCode,
}

impl AgentPortError {
    #[must_use]
    pub const fn from_code(code: AgentPortErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn unavailable_context() -> Self {
        Self::from_code(AgentPortErrorCode::UnavailableContext)
    }

    #[must_use]
    pub const fn code(&self) -> AgentPortErrorCode {
        self.code
    }
}

impl fmt::Debug for AgentPortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentPortError")
            .field("code", &self.code)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentCapabilities {
    pub resume: bool,
    pub compact: bool,
    pub token_usage: bool,
    pub pre_dispatch_effects: bool,
    pub history_paging: bool,
    pub background_processes: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentModel {
    pub id: ModelId,
    pub display_name: String,
    pub supported_efforts: Vec<ReasoningEffort>,
    pub default_effort: ReasoningEffort,
}

macro_rules! opaque_agent_id {
    ($name:ident) => {
        #[derive(Clone, Eq, Hash, PartialEq)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, AgentPortError> {
                let value = value.into();
                if value.is_empty()
                    || value.len() > MAX_AGENT_ID_BYTES
                    || value.as_bytes().contains(&0)
                {
                    return Err(AgentPortError::from_code(
                        AgentPortErrorCode::InvalidResponse,
                    ));
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

opaque_agent_id!(AgentContextId);
opaque_agent_id!(AgentEpochId);
opaque_agent_id!(AgentRequestId);

#[derive(Clone)]
pub struct StartAgentContext {
    pub cwd: PathBuf,
    pub model: ModelId,
    pub permission_mode: PermissionMode,
}

impl fmt::Debug for StartAgentContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartAgentContext")
            .field("cwd", &"<redacted>")
            .field("model", &self.model)
            .field("permission_mode", &self.permission_mode)
            .finish()
    }
}

#[derive(Clone)]
pub struct ResumeAgentContext {
    pub context_id: AgentContextId,
    pub cwd: PathBuf,
    pub model: ModelId,
    pub permission_mode: PermissionMode,
}

impl fmt::Debug for ResumeAgentContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResumeAgentContext")
            .field("context_id", &self.context_id)
            .field("cwd", &"<redacted>")
            .field("model", &self.model)
            .field("permission_mode", &self.permission_mode)
            .finish()
    }
}

#[derive(Clone)]
pub struct StartAgentEpoch {
    pub context_id: AgentContextId,
    pub input: String,
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub permission_mode: PermissionMode,
}

impl fmt::Debug for StartAgentEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StartAgentEpoch")
            .field("context_id", &self.context_id)
            .field("input", &"<redacted>")
            .field("model", &self.model)
            .field("effort", &self.effort)
            .field("permission_mode", &self.permission_mode)
            .finish()
    }
}

#[derive(Clone, PartialEq)]
pub enum AgentItem {
    Command {
        item_id: String,
        command: String,
        cwd: PathBuf,
        status: String,
        exit_code: Option<i32>,
        aggregated_output: Option<String>,
        process_id: Option<String>,
    },
    FileChange {
        item_id: String,
        status: String,
        changes: serde_json::Value,
    },
    ContextCompaction {
        item_id: String,
    },
    Other {
        item_id: String,
        item_type: String,
    },
}

impl AgentItem {
    #[must_use]
    pub fn item_id(&self) -> &str {
        match self {
            Self::Command { item_id, .. }
            | Self::FileChange { item_id, .. }
            | Self::ContextCompaction { item_id }
            | Self::Other { item_id, .. } => item_id,
        }
    }
}

impl fmt::Debug for AgentItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command {
                status,
                exit_code,
                aggregated_output,
                process_id,
                ..
            } => formatter
                .debug_struct("AgentItem::Command")
                .field("item_id", &"<redacted>")
                .field("command", &"<redacted>")
                .field("cwd", &"<redacted>")
                .field("status", status)
                .field("exit_code", exit_code)
                .field("has_aggregated_output", &aggregated_output.is_some())
                .field("has_process_id", &process_id.is_some())
                .finish(),
            Self::FileChange {
                status, changes, ..
            } => formatter
                .debug_struct("AgentItem::FileChange")
                .field("item_id", &"<redacted>")
                .field("status", status)
                .field(
                    "change_count",
                    &changes.as_array().map_or(0, std::vec::Vec::len),
                )
                .finish(),
            Self::ContextCompaction { .. } => formatter
                .debug_struct("AgentItem::ContextCompaction")
                .field("item_id", &"<redacted>")
                .finish(),
            Self::Other { .. } => formatter
                .debug_struct("AgentItem::Other")
                .field("item_id", &"<redacted>")
                .field("item_type", &"<redacted>")
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentEffectKind {
    Command,
    FileChange,
    Network,
    External,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectDecision {
    Allow,
    Deny,
}

#[derive(Clone)]
pub struct AgentEffectRequest {
    pub request_id: AgentRequestId,
    pub item_id: String,
    pub kind: AgentEffectKind,
    pub summary: String,
    pub request_digest: Sha256Digest,
}

impl fmt::Debug for AgentEffectRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentEffectRequest")
            .field("request_id", &self.request_id)
            .field("item_id", &"<redacted>")
            .field("kind", &self.kind)
            .field("summary", &"<redacted>")
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentUsage {
    pub last_total_tokens: u64,
    pub total_tokens: u64,
    pub model_context_window: Option<u64>,
}

#[derive(Clone, Debug)]
pub enum AgentEvent {
    ContextStarted {
        context_id: AgentContextId,
    },
    EpochStarted {
        context_id: AgentContextId,
        epoch_id: AgentEpochId,
    },
    ItemStarted {
        epoch_id: AgentEpochId,
        item: AgentItem,
    },
    AssistantDelta {
        epoch_id: AgentEpochId,
        text: String,
    },
    DiffUpdated {
        epoch_id: AgentEpochId,
        diff: String,
    },
    UsageUpdated {
        epoch_id: AgentEpochId,
        usage: AgentUsage,
    },
    EffectRequested(AgentEffectRequest),
    ItemCompleted {
        epoch_id: AgentEpochId,
        item: AgentItem,
    },
    CompactionStarted {
        context_id: AgentContextId,
        item_id: String,
    },
    CompactionCompleted {
        context_id: AgentContextId,
        item_id: String,
    },
    EpochCompleted {
        epoch_id: AgentEpochId,
        status: String,
    },
    ProviderFailed {
        context_id: Option<AgentContextId>,
        epoch_id: Option<AgentEpochId>,
    },
}

#[derive(Clone, PartialEq)]
pub struct AgentProcess {
    pub process_id: String,
    pub item_id: String,
    pub command: String,
    pub cwd: PathBuf,
    pub os_pid: Option<u32>,
}

impl fmt::Debug for AgentProcess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentProcess")
            .field("process_id", &"<redacted>")
            .field("item_id", &"<redacted>")
            .field("command", &"<redacted>")
            .field("cwd", &"<redacted>")
            .field("os_pid", &self.os_pid)
            .finish()
    }
}

pub trait AgentPort: Send {
    fn capabilities(&self) -> AgentCapabilities;
    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>>;
    fn start_context(&mut self, request: StartAgentContext) -> AgentFuture<'_, AgentContextId>;
    fn resume_context(&mut self, request: ResumeAgentContext) -> AgentFuture<'_, AgentContextId>;
    fn compact_context(&mut self, context_id: &AgentContextId) -> AgentFuture<'_, ()>;
    fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId>;
    fn steer(
        &mut self,
        context_id: &AgentContextId,
        epoch_id: &AgentEpochId,
        text: String,
    ) -> AgentFuture<'_, ()>;
    fn interrupt(
        &mut self,
        context_id: &AgentContextId,
        epoch_id: &AgentEpochId,
    ) -> AgentFuture<'_, ()>;
    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent>;
    fn resolve_effect(
        &mut self,
        request_id: &AgentRequestId,
        decision: EffectDecision,
    ) -> AgentFuture<'_, ()>;
    fn list_background_processes(
        &mut self,
        context_id: &AgentContextId,
    ) -> AgentFuture<'_, Vec<AgentProcess>>;
    fn terminate_background_process(
        &mut self,
        context_id: &AgentContextId,
        process_id: &str,
    ) -> AgentFuture<'_, bool>;
    fn shutdown(&mut self) -> AgentFuture<'_, ()>;
}
