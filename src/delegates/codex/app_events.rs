use std::fmt;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{DelegateError, DelegateErrorCode};
use crate::policy::Sha256Digest;

const MAX_PROVIDER_ID_BYTES: usize = 128;
const MAX_ITEM_ID_BYTES: usize = 128;
const MAX_EVENT_TEXT_BYTES: usize = 1_048_576;
const MAX_COMMAND_BYTES: usize = 256 * 1_024;
const MAX_AGGREGATED_OUTPUT_BYTES: usize = 512 * 1_024;
const MAX_ITEM_PAYLOAD_BYTES: usize = 1_048_576;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CodexThreadId(String);

impl CodexThreadId {
    pub fn parse(value: impl Into<String>) -> Result<Self, DelegateError> {
        let value = value.into();
        Ok(Self(validate_bounded(&value, MAX_PROVIDER_ID_BYTES)?))
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self, DelegateError> {
        Self::parse(parse_bounded_string(value, MAX_PROVIDER_ID_BYTES)?)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CodexThreadId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CodexThreadId(<redacted>)")
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CodexTurnId(String);

impl CodexTurnId {
    pub fn parse(value: impl Into<String>) -> Result<Self, DelegateError> {
        let value = value.into();
        Ok(Self(validate_bounded(&value, MAX_PROVIDER_ID_BYTES)?))
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self, DelegateError> {
        Self::parse(parse_bounded_string(value, MAX_PROVIDER_ID_BYTES)?)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CodexTurnId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CodexTurnId(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexApprovalKind {
    Command,
    FileChange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexApprovalDecision {
    Allow,
    Deny,
}

impl CodexApprovalDecision {
    pub(crate) const fn as_codex_value(self) -> &'static str {
        match self {
            Self::Allow => "accept",
            Self::Deny => "decline",
        }
    }
}

#[derive(Clone)]
pub struct CodexApprovalRequest {
    provider_id: Value,
    provider_request_id: String,
    thread_id: CodexThreadId,
    turn_id: CodexTurnId,
    item_id: String,
    kind: CodexApprovalKind,
    command: Option<String>,
    reason: Option<String>,
    request_digest: Sha256Digest,
}

impl CodexApprovalRequest {
    pub fn from_provider_request(value: Value) -> Result<Self, DelegateError> {
        parse_approval_request(value)
    }

    #[must_use]
    pub fn provider_request_id(&self) -> &str {
        &self.provider_request_id
    }

    #[must_use]
    pub const fn thread_id(&self) -> &CodexThreadId {
        &self.thread_id
    }

    #[must_use]
    pub const fn turn_id(&self) -> &CodexTurnId {
        &self.turn_id
    }

    #[must_use]
    pub fn item_id(&self) -> &str {
        &self.item_id
    }

    #[must_use]
    pub const fn kind(&self) -> CodexApprovalKind {
        self.kind
    }

    #[must_use]
    pub fn command(&self) -> Option<&str> {
        self.command.as_deref()
    }

    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    pub(crate) fn provider_id(&self) -> &Value {
        &self.provider_id
    }
}

impl fmt::Debug for CodexApprovalRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexApprovalRequest")
            .field("provider_request_id", &self.provider_request_id)
            .field("thread_id", &self.thread_id)
            .field("turn_id", &self.turn_id)
            .field("item_id", &self.item_id)
            .field("kind", &self.kind)
            .field("request_digest", &self.request_digest)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexTokenUsage {
    pub last_total_tokens: u64,
    pub total_tokens: u64,
    pub model_context_window: Option<u64>,
}

#[derive(Clone, PartialEq)]
pub enum CodexItem {
    Command {
        item_id: String,
        command: String,
        cwd: String,
        status: String,
        exit_code: Option<i32>,
        aggregated_output: Option<String>,
        process_id: Option<String>,
    },
    FileChange {
        item_id: String,
        status: String,
        changes: Value,
    },
    ContextCompaction {
        item_id: String,
    },
    Other {
        item_id: String,
        item_type: String,
    },
}

impl fmt::Debug for CodexItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command {
                status,
                exit_code,
                aggregated_output,
                process_id,
                ..
            } => formatter
                .debug_struct("CodexItem::Command")
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
                .debug_struct("CodexItem::FileChange")
                .field("item_id", &"<redacted>")
                .field("status", status)
                .field(
                    "change_count",
                    &changes.as_array().map_or(0, std::vec::Vec::len),
                )
                .finish(),
            Self::ContextCompaction { .. } => formatter
                .debug_struct("CodexItem::ContextCompaction")
                .field("item_id", &"<redacted>")
                .finish(),
            Self::Other { .. } => formatter
                .debug_struct("CodexItem::Other")
                .field("item_id", &"<redacted>")
                .field("item_type", &"<redacted>")
                .finish(),
        }
    }
}

impl CodexItem {
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

#[derive(Clone, Debug)]
pub enum CodexEvent {
    ThreadStarted {
        thread_id: CodexThreadId,
    },
    TurnStarted {
        thread_id: CodexThreadId,
        turn_id: CodexTurnId,
    },
    ItemStarted {
        thread_id: CodexThreadId,
        turn_id: CodexTurnId,
        item: CodexItem,
    },
    AgentMessageDelta {
        thread_id: CodexThreadId,
        turn_id: CodexTurnId,
        item_id: String,
        text: String,
    },
    ItemCompleted {
        thread_id: CodexThreadId,
        turn_id: CodexTurnId,
        item: CodexItem,
    },
    TokenUsageUpdated {
        thread_id: CodexThreadId,
        turn_id: CodexTurnId,
        usage: CodexTokenUsage,
    },
    DiffUpdated {
        thread_id: CodexThreadId,
        turn_id: CodexTurnId,
        diff: String,
    },
    TurnCompleted {
        thread_id: CodexThreadId,
        turn_id: CodexTurnId,
        status: String,
    },
    ProviderError {
        thread_id: Option<CodexThreadId>,
        turn_id: Option<CodexTurnId>,
    },
    ApprovalRequested(CodexApprovalRequest),
}

pub(crate) fn parse_notification(value: Value) -> Result<CodexEvent, DelegateError> {
    let object = exact_object(&value, &["method", "params"])?;
    let method = parse_bounded_string(
        object.get("method").ok_or_else(protocol_error)?,
        MAX_PROVIDER_ID_BYTES,
    )?;
    let params = object
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(protocol_error)?;

    match method.as_str() {
        "thread/started" => {
            require_keys(params, &["thread"], &[])?;
            let thread = params
                .get("thread")
                .and_then(Value::as_object)
                .ok_or_else(protocol_error)?;
            let thread_id = parse_id_field(thread, "id", CodexThreadId::from_value)?;
            Ok(CodexEvent::ThreadStarted { thread_id })
        }
        "turn/started" => {
            require_keys(params, &["threadId", "turn"], &[])?;
            let thread_id = parse_id_field(params, "threadId", CodexThreadId::from_value)?;
            let turn = params
                .get("turn")
                .and_then(Value::as_object)
                .ok_or_else(protocol_error)?;
            let turn_id = parse_id_field(turn, "id", CodexTurnId::from_value)?;
            Ok(CodexEvent::TurnStarted { thread_id, turn_id })
        }
        "item/started" => {
            require_keys(params, &["threadId", "turnId", "item", "startedAtMs"], &[])?;
            if params.get("startedAtMs").and_then(Value::as_i64).is_none() {
                return Err(protocol_error());
            }
            let (thread_id, turn_id) = parse_turn_binding(params)?;
            let item = parse_item(params.get("item").ok_or_else(protocol_error)?)?;
            Ok(CodexEvent::ItemStarted {
                thread_id,
                turn_id,
                item,
            })
        }
        "item/agentMessage/delta" => {
            require_keys(params, &["threadId", "turnId", "itemId", "delta"], &[])?;
            let (thread_id, turn_id) = parse_turn_binding(params)?;
            let item_id = parse_bounded_string(
                params.get("itemId").ok_or_else(protocol_error)?,
                MAX_ITEM_ID_BYTES,
            )?;
            let text = parse_bounded_string(
                params.get("delta").ok_or_else(protocol_error)?,
                MAX_EVENT_TEXT_BYTES,
            )?;
            Ok(CodexEvent::AgentMessageDelta {
                thread_id,
                turn_id,
                item_id,
                text,
            })
        }
        "item/completed" => {
            require_keys(
                params,
                &["threadId", "turnId", "item", "completedAtMs"],
                &[],
            )?;
            if params
                .get("completedAtMs")
                .and_then(Value::as_i64)
                .is_none()
            {
                return Err(protocol_error());
            }
            let (thread_id, turn_id) = parse_turn_binding(params)?;
            let item = parse_item(params.get("item").ok_or_else(protocol_error)?)?;
            Ok(CodexEvent::ItemCompleted {
                thread_id,
                turn_id,
                item,
            })
        }
        "thread/tokenUsage/updated" => {
            require_keys(params, &["threadId", "turnId", "tokenUsage"], &[])?;
            let (thread_id, turn_id) = parse_turn_binding(params)?;
            let usage = parse_token_usage(params.get("tokenUsage").ok_or_else(protocol_error)?)?;
            Ok(CodexEvent::TokenUsageUpdated {
                thread_id,
                turn_id,
                usage,
            })
        }
        "turn/diff/updated" => {
            require_keys(params, &["threadId", "turnId", "diff"], &[])?;
            let (thread_id, turn_id) = parse_turn_binding(params)?;
            let diff = parse_bounded_string(
                params.get("diff").ok_or_else(protocol_error)?,
                MAX_EVENT_TEXT_BYTES,
            )?;
            Ok(CodexEvent::DiffUpdated {
                thread_id,
                turn_id,
                diff,
            })
        }
        "turn/completed" => {
            require_keys(params, &["threadId", "turn"], &[])?;
            let thread_id = parse_id_field(params, "threadId", CodexThreadId::from_value)?;
            let turn = params
                .get("turn")
                .and_then(Value::as_object)
                .ok_or_else(protocol_error)?;
            let turn_id = parse_id_field(turn, "id", CodexTurnId::from_value)?;
            let status = parse_bounded_string(
                turn.get("status").ok_or_else(protocol_error)?,
                MAX_PROVIDER_ID_BYTES,
            )?;
            Ok(CodexEvent::TurnCompleted {
                thread_id,
                turn_id,
                status,
            })
        }
        "error" => {
            require_keys(params, &["error", "willRetry", "threadId", "turnId"], &[])?;
            if params.get("error").and_then(Value::as_object).is_none()
                || params.get("willRetry").and_then(Value::as_bool).is_none()
            {
                return Err(protocol_error());
            }
            Ok(CodexEvent::ProviderError {
                thread_id: Some(parse_id_field(
                    params,
                    "threadId",
                    CodexThreadId::from_value,
                )?),
                turn_id: Some(parse_id_field(params, "turnId", CodexTurnId::from_value)?),
            })
        }
        _ => Err(protocol_error()),
    }
}

fn parse_item(value: &Value) -> Result<CodexItem, DelegateError> {
    let item = value.as_object().ok_or_else(protocol_error)?;
    let item_id = parse_bounded_string(
        item.get("id").ok_or_else(protocol_error)?,
        MAX_ITEM_ID_BYTES,
    )?;
    let item_type = parse_bounded_string(
        item.get("type").ok_or_else(protocol_error)?,
        MAX_PROVIDER_ID_BYTES,
    )?;
    match item_type.as_str() {
        "commandExecution" => {
            require_keys(
                item,
                &["type", "id", "command", "cwd", "status", "commandActions"],
                &[
                    "aggregatedOutput",
                    "durationMs",
                    "exitCode",
                    "pluginId",
                    "processId",
                    "scriptPath",
                    "source",
                ],
            )?;
            let command = parse_bounded_string(
                item.get("command").ok_or_else(protocol_error)?,
                MAX_COMMAND_BYTES,
            )?;
            let cwd = parse_bounded_string(
                item.get("cwd").ok_or_else(protocol_error)?,
                MAX_COMMAND_BYTES,
            )?;
            let status = parse_item_status(item.get("status").ok_or_else(protocol_error)?)?;
            let actions = item
                .get("commandActions")
                .and_then(Value::as_array)
                .ok_or_else(protocol_error)?;
            if actions.len() > 256 || serialized_len(actions)? > MAX_ITEM_PAYLOAD_BYTES {
                return Err(protocol_error());
            }
            for action in actions {
                validate_command_action(action)?;
            }
            let exit_code = optional_i32(item.get("exitCode"))?;
            let aggregated_output =
                optional_string(item.get("aggregatedOutput"), MAX_AGGREGATED_OUTPUT_BYTES)?;
            let process_id = optional_string(item.get("processId"), MAX_PROVIDER_ID_BYTES)?;
            optional_i64(item.get("durationMs"))?;
            optional_string(item.get("pluginId"), MAX_PROVIDER_ID_BYTES)?;
            optional_string(item.get("scriptPath"), MAX_COMMAND_BYTES)?;
            if let Some(source) = item.get("source") {
                parse_bounded_string(source, MAX_PROVIDER_ID_BYTES)?;
            }
            Ok(CodexItem::Command {
                item_id,
                command,
                cwd,
                status,
                exit_code,
                aggregated_output,
                process_id,
            })
        }
        "fileChange" => {
            require_keys(item, &["type", "id", "changes", "status"], &[])?;
            let status = parse_item_status(item.get("status").ok_or_else(protocol_error)?)?;
            let changes = item.get("changes").ok_or_else(protocol_error)?;
            if !changes.is_array() || serialized_len(changes)? > MAX_ITEM_PAYLOAD_BYTES {
                return Err(protocol_error());
            }
            Ok(CodexItem::FileChange {
                item_id,
                status,
                changes: changes.clone(),
            })
        }
        "contextCompaction" => {
            require_keys(item, &["type", "id"], &[])?;
            Ok(CodexItem::ContextCompaction { item_id })
        }
        _ => {
            if serialized_len(value)? > MAX_ITEM_PAYLOAD_BYTES {
                return Err(protocol_error());
            }
            Ok(CodexItem::Other { item_id, item_type })
        }
    }
}

fn validate_command_action(value: &Value) -> Result<(), DelegateError> {
    let action = value.as_object().ok_or_else(protocol_error)?;
    let action_type = parse_bounded_string(
        action.get("type").ok_or_else(protocol_error)?,
        MAX_PROVIDER_ID_BYTES,
    )?;
    match action_type.as_str() {
        "read" => {
            require_keys(action, &["type", "command", "name", "path"], &[])?;
            parse_bounded_string(
                action.get("command").ok_or_else(protocol_error)?,
                MAX_COMMAND_BYTES,
            )?;
            parse_bounded_string(
                action.get("name").ok_or_else(protocol_error)?,
                MAX_PROVIDER_ID_BYTES,
            )?;
            parse_bounded_string(
                action.get("path").ok_or_else(protocol_error)?,
                MAX_COMMAND_BYTES,
            )?;
        }
        "listFiles" => {
            require_keys(action, &["type", "command"], &["path"])?;
            parse_bounded_string(
                action.get("command").ok_or_else(protocol_error)?,
                MAX_COMMAND_BYTES,
            )?;
            optional_string(action.get("path"), MAX_COMMAND_BYTES)?;
        }
        "search" => {
            require_keys(action, &["type", "command"], &["path", "query"])?;
            parse_bounded_string(
                action.get("command").ok_or_else(protocol_error)?,
                MAX_COMMAND_BYTES,
            )?;
            optional_string(action.get("path"), MAX_COMMAND_BYTES)?;
            optional_string(action.get("query"), MAX_COMMAND_BYTES)?;
        }
        "unknown" => {
            require_keys(action, &["type", "command"], &[])?;
            parse_bounded_string(
                action.get("command").ok_or_else(protocol_error)?,
                MAX_COMMAND_BYTES,
            )?;
        }
        _ => return Err(protocol_error()),
    }
    Ok(())
}

fn parse_token_usage(value: &Value) -> Result<CodexTokenUsage, DelegateError> {
    let usage = value.as_object().ok_or_else(protocol_error)?;
    require_keys(usage, &["total", "last"], &["modelContextWindow"])?;
    let total_tokens = parse_token_total(usage.get("total").ok_or_else(protocol_error)?)?;
    let last_total_tokens = parse_token_total(usage.get("last").ok_or_else(protocol_error)?)?;
    let model_context_window = optional_u64(usage.get("modelContextWindow"))?;
    Ok(CodexTokenUsage {
        last_total_tokens,
        total_tokens,
        model_context_window,
    })
}

fn parse_token_total(value: &Value) -> Result<u64, DelegateError> {
    let usage = value.as_object().ok_or_else(protocol_error)?;
    require_keys(
        usage,
        &[
            "totalTokens",
            "inputTokens",
            "cachedInputTokens",
            "outputTokens",
            "reasoningOutputTokens",
        ],
        &["cacheWriteInputTokens"],
    )?;
    if usage.values().any(|value| value.as_u64().is_none()) {
        return Err(protocol_error());
    }
    usage
        .get("totalTokens")
        .and_then(Value::as_u64)
        .ok_or_else(protocol_error)
}

fn parse_item_status(value: &Value) -> Result<String, DelegateError> {
    let status = parse_bounded_string(value, MAX_PROVIDER_ID_BYTES)?;
    if !matches!(
        status.as_str(),
        "inProgress" | "completed" | "failed" | "declined"
    ) {
        return Err(protocol_error());
    }
    Ok(status)
}

fn serialized_len<T: serde::Serialize + ?Sized>(value: &T) -> Result<usize, DelegateError> {
    serde_json::to_vec(value)
        .map(|encoded| encoded.len())
        .map_err(|_| protocol_error())
}

fn optional_i32(value: Option<&Value>) -> Result<Option<i32>, DelegateError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .and_then(|value| i32::try_from(value).ok())
            .map(Some)
            .ok_or_else(protocol_error),
    }
}

fn optional_i64(value: Option<&Value>) -> Result<Option<i64>, DelegateError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or_else(protocol_error),
    }
}

fn optional_u64(value: Option<&Value>) -> Result<Option<u64>, DelegateError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(protocol_error),
    }
}

pub(crate) fn parse_approval_request(value: Value) -> Result<CodexApprovalRequest, DelegateError> {
    let object = exact_object(&value, &["id", "method", "params"])?;
    let provider_id = object.get("id").cloned().ok_or_else(protocol_error)?;
    let provider_request_id = match &provider_id {
        Value::String(value) => validate_bounded(value, MAX_PROVIDER_ID_BYTES)?,
        Value::Number(value) if value.as_u64().is_some() => value.to_string(),
        _ => return Err(protocol_error()),
    };
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(protocol_error)?;
    let params = object
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(protocol_error)?;
    let kind = match method {
        "item/commandExecution/requestApproval" => CodexApprovalKind::Command,
        "item/fileChange/requestApproval" => CodexApprovalKind::FileChange,
        _ => return Err(protocol_error()),
    };
    let optional = match kind {
        CodexApprovalKind::Command => &[
            "additionalPermissions",
            "approvalId",
            "availableDecisions",
            "command",
            "commandActions",
            "cwd",
            "environmentId",
            "networkApprovalContext",
            "proposedExecpolicyAmendment",
            "proposedNetworkPolicyAmendments",
            "reason",
        ][..],
        CodexApprovalKind::FileChange => &["grantRoot", "reason"][..],
    };
    require_keys(
        params,
        &["threadId", "turnId", "itemId", "startedAtMs"],
        optional,
    )?;
    if params.get("startedAtMs").and_then(Value::as_i64).is_none() {
        return Err(protocol_error());
    }
    let (thread_id, turn_id) = parse_turn_binding(params)?;
    let item_id = parse_bounded_string(
        params.get("itemId").ok_or_else(protocol_error)?,
        MAX_ITEM_ID_BYTES,
    )?;
    let command = optional_string(params.get("command"), MAX_EVENT_TEXT_BYTES)?;
    let reason = optional_string(params.get("reason"), 4 * 1_024)?;
    let encoded = serde_json::to_vec(&value).map_err(|_| protocol_error())?;
    let mut hasher = Sha256::new();
    hasher.update(b"carl.codex.approval.v1\0");
    hasher.update(encoded);
    let request_digest = Sha256Digest::from_bytes(hasher.finalize().into());

    Ok(CodexApprovalRequest {
        provider_id,
        provider_request_id,
        thread_id,
        turn_id,
        item_id,
        kind,
        command,
        reason,
        request_digest,
    })
}

fn parse_turn_binding(
    params: &serde_json::Map<String, Value>,
) -> Result<(CodexThreadId, CodexTurnId), DelegateError> {
    Ok((
        parse_id_field(params, "threadId", CodexThreadId::from_value)?,
        parse_id_field(params, "turnId", CodexTurnId::from_value)?,
    ))
}

fn parse_id_field<T>(
    object: &serde_json::Map<String, Value>,
    field: &str,
    parser: fn(&Value) -> Result<T, DelegateError>,
) -> Result<T, DelegateError> {
    parser(object.get(field).ok_or_else(protocol_error)?)
}

fn exact_object<'a>(
    value: &'a Value,
    keys: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, DelegateError> {
    let object = value.as_object().ok_or_else(protocol_error)?;
    let has_emitted_at = object.contains_key("emittedAtMs");
    if object.len() != keys.len() + usize::from(has_emitted_at)
        || keys.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !keys.contains(&key.as_str()) && key.as_str() != "emittedAtMs")
        || object
            .get("emittedAtMs")
            .is_some_and(|value| value.as_u64().is_none())
    {
        return Err(protocol_error());
    }
    Ok(object)
}

fn require_keys(
    object: &serde_json::Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), DelegateError> {
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(protocol_error());
    }
    Ok(())
}

fn optional_string(value: Option<&Value>, maximum: usize) -> Result<Option<String>, DelegateError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => parse_bounded_string(value, maximum).map(Some),
    }
}

fn parse_bounded_string(value: &Value, maximum: usize) -> Result<String, DelegateError> {
    validate_bounded(value.as_str().ok_or_else(protocol_error)?, maximum)
}

fn validate_bounded(value: &str, maximum: usize) -> Result<String, DelegateError> {
    if value.is_empty() || value.len() > maximum || value.as_bytes().contains(&0) {
        return Err(protocol_error());
    }
    Ok(value.to_owned())
}

fn protocol_error() -> DelegateError {
    DelegateError::new(DelegateErrorCode::ProtocolFailed)
}
