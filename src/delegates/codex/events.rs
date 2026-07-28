use serde_json::{Map, Value};
use thiserror::Error;

const MAX_AGENT_MESSAGE_BYTES: usize = 32 * 1_024;
const MAX_EVENT_TYPE_BYTES: usize = 128;
const MAX_ITEM_ID_BYTES: usize = 128;
const MAX_THREAD_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexProtocolErrorCode {
    InvalidLifecycle,
    InvalidEvent,
    LimitExceeded,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("The Codex event stream is invalid.")]
pub struct CodexProtocolError {
    code: CodexProtocolErrorCode,
}

impl CodexProtocolError {
    const fn new(code: CodexProtocolErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(&self) -> CodexProtocolErrorCode {
        self.code
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DelegateEvent {
    ThreadStarted {
        thread_id: String,
    },
    TurnStarted,
    AgentMessage {
        text: String,
    },
    Activity {
        item_id: String,
        kind: DelegateActivityKind,
        phase: DelegateItemPhase,
    },
    Compatibility {
        event_type: String,
    },
    Terminal(DelegateTerminal),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegateActivityKind {
    AgentMessage,
    Reasoning,
    CommandExecution,
    FileChange,
    McpToolCall,
    WebSearch,
    PlanUpdate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegateItemPhase {
    Started,
    Updated,
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DelegateTerminal {
    Completed { usage: DelegateUsage },
    Failed { error_code: Option<String> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegateUsage {
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamState {
    AwaitingThread,
    AwaitingTurn,
    InTurn,
    Terminal,
}

#[derive(Debug)]
pub struct CodexEventNormalizer {
    state: StreamState,
}

impl CodexEventNormalizer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: StreamState::AwaitingThread,
        }
    }

    pub fn ingest(&mut self, value: Value) -> Result<Option<DelegateEvent>, CodexProtocolError> {
        if self.state == StreamState::Terminal {
            return Err(protocol_error(CodexProtocolErrorCode::InvalidLifecycle));
        }
        let object = value
            .as_object()
            .ok_or_else(|| protocol_error(CodexProtocolErrorCode::InvalidEvent))?;
        let event_type = required_bounded_string(object, "type", MAX_EVENT_TYPE_BYTES)?;

        match event_type.as_str() {
            "thread.started" => self.thread_started(object).map(Some),
            "turn.started" => self.turn_started().map(Some),
            "item.started" => self.item_event(object, DelegateItemPhase::Started),
            "item.updated" => self.item_event(object, DelegateItemPhase::Updated),
            "item.completed" => self.item_event(object, DelegateItemPhase::Completed),
            "turn.completed" => self.turn_completed(object).map(Some),
            "turn.failed" | "error" => self.turn_failed(object).map(Some),
            _ => Ok(Some(DelegateEvent::Compatibility { event_type })),
        }
    }

    fn thread_started(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<DelegateEvent, CodexProtocolError> {
        if self.state != StreamState::AwaitingThread {
            return Err(protocol_error(CodexProtocolErrorCode::InvalidLifecycle));
        }
        let thread_id = required_bounded_string(object, "thread_id", MAX_THREAD_ID_BYTES)?;
        self.state = StreamState::AwaitingTurn;
        Ok(DelegateEvent::ThreadStarted { thread_id })
    }

    fn turn_started(&mut self) -> Result<DelegateEvent, CodexProtocolError> {
        if self.state != StreamState::AwaitingTurn {
            return Err(protocol_error(CodexProtocolErrorCode::InvalidLifecycle));
        }
        self.state = StreamState::InTurn;
        Ok(DelegateEvent::TurnStarted)
    }

    fn item_event(
        &self,
        object: &Map<String, Value>,
        phase: DelegateItemPhase,
    ) -> Result<Option<DelegateEvent>, CodexProtocolError> {
        if self.state != StreamState::InTurn {
            return Err(protocol_error(CodexProtocolErrorCode::InvalidLifecycle));
        }
        let item = object
            .get("item")
            .and_then(Value::as_object)
            .ok_or_else(|| protocol_error(CodexProtocolErrorCode::InvalidEvent))?;
        let item_id = required_bounded_string(item, "id", MAX_ITEM_ID_BYTES)?;
        let item_type = required_bounded_string(item, "type", MAX_EVENT_TYPE_BYTES)?;

        if item_type == "agent_message" && phase == DelegateItemPhase::Completed {
            let text = required_bounded_string(item, "text", MAX_AGENT_MESSAGE_BYTES)?;
            return Ok(Some(DelegateEvent::AgentMessage { text }));
        }

        let kind = match item_type.as_str() {
            "agent_message" => DelegateActivityKind::AgentMessage,
            "reasoning" => DelegateActivityKind::Reasoning,
            "command_execution" => DelegateActivityKind::CommandExecution,
            "file_change" => DelegateActivityKind::FileChange,
            "mcp_tool_call" => DelegateActivityKind::McpToolCall,
            "web_search" => DelegateActivityKind::WebSearch,
            "plan_update" => DelegateActivityKind::PlanUpdate,
            _ => {
                let event_type = format!("item.{}:{item_type}", phase.as_str());
                if event_type.len() > MAX_EVENT_TYPE_BYTES {
                    return Err(protocol_error(CodexProtocolErrorCode::LimitExceeded));
                }
                return Ok(Some(DelegateEvent::Compatibility { event_type }));
            }
        };

        Ok(Some(DelegateEvent::Activity {
            item_id,
            kind,
            phase,
        }))
    }

    fn turn_completed(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<DelegateEvent, CodexProtocolError> {
        if self.state != StreamState::InTurn {
            return Err(protocol_error(CodexProtocolErrorCode::InvalidLifecycle));
        }
        let usage = object
            .get("usage")
            .and_then(Value::as_object)
            .ok_or_else(|| protocol_error(CodexProtocolErrorCode::InvalidEvent))?;
        let usage = DelegateUsage {
            input_tokens: required_u64(usage, "input_tokens")?,
            cached_input_tokens: required_u64(usage, "cached_input_tokens")?,
            output_tokens: required_u64(usage, "output_tokens")?,
        };
        self.state = StreamState::Terminal;
        Ok(DelegateEvent::Terminal(DelegateTerminal::Completed {
            usage,
        }))
    }

    fn turn_failed(
        &mut self,
        object: &Map<String, Value>,
    ) -> Result<DelegateEvent, CodexProtocolError> {
        if self.state == StreamState::Terminal {
            return Err(protocol_error(CodexProtocolErrorCode::InvalidLifecycle));
        }
        let error_code = object
            .get("error")
            .and_then(Value::as_object)
            .and_then(|error| error.get("code"))
            .and_then(Value::as_str)
            .map(validate_event_type)
            .transpose()?;
        self.state = StreamState::Terminal;
        Ok(DelegateEvent::Terminal(DelegateTerminal::Failed {
            error_code,
        }))
    }
}

impl Default for CodexEventNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

impl DelegateItemPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Updated => "updated",
            Self::Completed => "completed",
        }
    }
}

fn required_bounded_string(
    object: &Map<String, Value>,
    key: &str,
    maximum_bytes: usize,
) -> Result<String, CodexProtocolError> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_error(CodexProtocolErrorCode::InvalidEvent))?;
    if value.is_empty() || value.as_bytes().contains(&0) {
        return Err(protocol_error(CodexProtocolErrorCode::InvalidEvent));
    }
    if value.len() > maximum_bytes {
        return Err(protocol_error(CodexProtocolErrorCode::LimitExceeded));
    }
    Ok(value.to_owned())
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, CodexProtocolError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| protocol_error(CodexProtocolErrorCode::InvalidEvent))
}

fn validate_event_type(value: &str) -> Result<String, CodexProtocolError> {
    if value.is_empty() || value.len() > MAX_EVENT_TYPE_BYTES || value.as_bytes().contains(&0) {
        return Err(protocol_error(if value.len() > MAX_EVENT_TYPE_BYTES {
            CodexProtocolErrorCode::LimitExceeded
        } else {
            CodexProtocolErrorCode::InvalidEvent
        }));
    }
    Ok(value.to_owned())
}

const fn protocol_error(code: CodexProtocolErrorCode) -> CodexProtocolError {
    CodexProtocolError::new(code)
}
