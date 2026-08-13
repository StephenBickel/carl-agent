pub mod catalog;
pub mod http;
pub mod openai;
pub mod openrouter;
pub mod scripted;

use std::future::Future;
use std::pin::Pin;

use futures_core::Stream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::delegates::ReasoningEffort;
use crate::error::ErrorCode;
use crate::events::ToolCallId;

pub type ProviderStream =
    Pin<Box<dyn Stream<Item = Result<ProviderEvent, ProviderError>> + Send + 'static>>;
pub type ProviderFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ProviderStream, ProviderError>> + Send + 'a>>;

pub trait Provider: Send + Sync {
    fn capabilities(&self) -> ProviderCapabilities;

    fn stream(&self, request: ModelRequest) -> ProviderFuture<'_>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilities {
    pub streaming: bool,
    pub structured_tool_calls: bool,
    pub parallel_tool_calls: bool,
    pub usage_reporting: bool,
    pub context_window: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRequest {
    pub messages: Vec<Message>,
    pub tools: Vec<ToolDefinition>,
    pub settings: ModelSettings,
    #[serde(skip, default)]
    pub cancellation: CancellationToken,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub role: Role,
    pub content: Vec<MessageContent>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessageContent {
    Text {
        text: String,
    },
    ToolCall {
        tool_call_id: ToolCallId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider_call_id: Option<String>,
        name: String,
        arguments: Value,
    },
    ToolResult {
        tool_call_id: ToolCallId,
        output: Value,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSettings {
    pub model: String,
    pub temperature: Option<f64>,
    pub max_output_tokens: Option<u32>,
    pub reasoning_effort: Option<ReasoningEffort>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderEvent {
    TextDelta {
        text: String,
    },
    ToolCall {
        tool_call_id: ToolCallId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider_call_id: Option<String>,
        name: String,
        arguments: Value,
    },
    Usage {
        input_tokens: u64,
        output_tokens: u64,
    },
    Finish {
        reason: FinishReason,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    ToolCalls,
    Length,
    ContentFilter,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderError {
    #[error("provider authentication failed")]
    Authentication { detail: String },
    #[error("provider rate limit reached")]
    RateLimit {
        detail: String,
        retry_after_millis: Option<u64>,
    },
    #[error("provider transport failed")]
    Transport { detail: String },
    #[error("provider request is invalid")]
    InvalidRequest { detail: String },
    #[error("provider returned an invalid response")]
    InvalidResponse { detail: String },
    #[error("provider operation was cancelled")]
    Cancelled,
    #[error("scripted provider exhausted its {response_count} responses")]
    ScriptExhausted { response_count: usize },
    #[error("scripted provider fixture is invalid")]
    InvalidFixture { detail: String },
}

impl ProviderError {
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::Authentication { .. } => ErrorCode::Authentication,
            Self::RateLimit { .. } => ErrorCode::RateLimit,
            Self::InvalidRequest { .. } | Self::InvalidFixture { .. } => ErrorCode::Validation,
            Self::Cancelled => ErrorCode::Cancelled,
            Self::Transport { .. }
            | Self::InvalidResponse { .. }
            | Self::ScriptExhausted { .. } => ErrorCode::Provider,
        }
    }

    #[must_use]
    pub const fn user_message(&self) -> &'static str {
        match self {
            Self::Authentication { .. } => "Authentication failed.",
            Self::RateLimit { .. } => "The model provider is temporarily rate limited.",
            Self::InvalidRequest { .. } => "The provider request is invalid.",
            Self::Cancelled => "The provider operation was cancelled.",
            Self::InvalidFixture { .. } => "The scripted provider fixture is invalid.",
            Self::Transport { .. }
            | Self::InvalidResponse { .. }
            | Self::ScriptExhausted { .. } => "The model provider request failed.",
        }
    }
}
