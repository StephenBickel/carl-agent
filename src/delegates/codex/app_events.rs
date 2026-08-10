use std::fmt;

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{DelegateError, DelegateErrorCode};
use crate::policy::Sha256Digest;

const MAX_PROVIDER_ID_BYTES: usize = 128;
const MAX_ITEM_ID_BYTES: usize = 128;
const MAX_EVENT_TEXT_BYTES: usize = 1_048_576;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CodexThreadId(String);

impl CodexThreadId {
    pub(crate) fn parse(value: &Value) -> Result<Self, DelegateError> {
        Ok(Self(parse_bounded_string(value, MAX_PROVIDER_ID_BYTES)?))
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
    pub(crate) fn parse(value: &Value) -> Result<Self, DelegateError> {
        Ok(Self(parse_bounded_string(value, MAX_PROVIDER_ID_BYTES)?))
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
        item_id: String,
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
        item_id: String,
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
            let thread_id = parse_id_field(thread, "id", CodexThreadId::parse)?;
            Ok(CodexEvent::ThreadStarted { thread_id })
        }
        "turn/started" => {
            require_keys(params, &["threadId", "turn"], &[])?;
            let thread_id = parse_id_field(params, "threadId", CodexThreadId::parse)?;
            let turn = params
                .get("turn")
                .and_then(Value::as_object)
                .ok_or_else(protocol_error)?;
            let turn_id = parse_id_field(turn, "id", CodexTurnId::parse)?;
            Ok(CodexEvent::TurnStarted { thread_id, turn_id })
        }
        "item/started" => {
            require_keys(params, &["threadId", "turnId", "item", "startedAtMs"], &[])?;
            if params.get("startedAtMs").and_then(Value::as_i64).is_none() {
                return Err(protocol_error());
            }
            let (thread_id, turn_id) = parse_turn_binding(params)?;
            let item = params
                .get("item")
                .and_then(Value::as_object)
                .ok_or_else(protocol_error)?;
            let item_id = parse_bounded_string(
                item.get("id").ok_or_else(protocol_error)?,
                MAX_ITEM_ID_BYTES,
            )?;
            Ok(CodexEvent::ItemStarted {
                thread_id,
                turn_id,
                item_id,
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
            let item = params
                .get("item")
                .and_then(Value::as_object)
                .ok_or_else(protocol_error)?;
            let item_id = parse_bounded_string(
                item.get("id").ok_or_else(protocol_error)?,
                MAX_ITEM_ID_BYTES,
            )?;
            Ok(CodexEvent::ItemCompleted {
                thread_id,
                turn_id,
                item_id,
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
            let thread_id = parse_id_field(params, "threadId", CodexThreadId::parse)?;
            let turn = params
                .get("turn")
                .and_then(Value::as_object)
                .ok_or_else(protocol_error)?;
            let turn_id = parse_id_field(turn, "id", CodexTurnId::parse)?;
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
                thread_id: Some(parse_id_field(params, "threadId", CodexThreadId::parse)?),
                turn_id: Some(parse_id_field(params, "turnId", CodexTurnId::parse)?),
            })
        }
        _ => Err(protocol_error()),
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
        parse_id_field(params, "threadId", CodexThreadId::parse)?,
        parse_id_field(params, "turnId", CodexTurnId::parse)?,
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
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
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
