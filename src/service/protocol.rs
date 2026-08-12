use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::acp::PermissionMode;
use crate::delegates::{ModelId, ReasoningEffort};
use crate::events::{EventEnvelope, SessionId, TurnId};
use crate::policy::{ActorId, Frontend};
use crate::runtime::task::{
    CheckpointId, CompletionClause, OperationId, TaskBudget, TaskId, TaskSnapshot, TaskStatus,
};

pub const SERVICE_PROTOCOL_VERSION: u16 = 2;
pub const MAX_SERVICE_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_TASK_TEXT_BYTES: usize = 16 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_EXTERNAL_SESSION_BYTES: usize = 256;
const MAX_REQUESTS_PER_CONNECTION: usize = 4_096;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub idempotency_key: String,
    pub command: ServiceCommand,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ServiceCommand {
    Info,
    Session {
        external_session_id: String,
    },
    StartTask(StartTaskCommand),
    StartTrustedTask(TrustedStartTaskCommand),
    ConfigureTrustedSession {
        external_session_id: String,
        workspace: PathBuf,
        frontend: Frontend,
        actor_id: ActorId,
        channel_id: String,
        event_id: String,
        permission_mode: PermissionMode,
    },
    ResolveApproval {
        task_id: TaskId,
        external_session_id: String,
        workspace: PathBuf,
        frontend: Frontend,
        actor_id: ActorId,
        channel_id: Option<String>,
        event_id: Option<String>,
        display_code: String,
        session_id: SessionId,
        turn_id: TurnId,
        decision: ServiceApprovalDecision,
    },
    Status {
        task_id: TaskId,
    },
    List,
    Resume {
        task_id: TaskId,
    },
    Steer {
        task_id: TaskId,
        text: String,
    },
    SteerTrusted {
        task_id: TaskId,
        external_session_id: String,
        text: String,
        workspace: PathBuf,
        frontend: Frontend,
        actor_id: ActorId,
        channel_id: String,
        event_id: String,
    },
    Cancel {
        task_id: TaskId,
    },
    Configure {
        task_id: TaskId,
        model: ModelId,
        effort: ReasoningEffort,
        permission_mode: PermissionMode,
    },
    Events {
        task_id: TaskId,
        after_sequence: Option<u64>,
        limit: u16,
    },
    LiveUpdates {
        task_id: TaskId,
        live_generation: String,
        after_cursor: Option<u64>,
        limit: u16,
    },
    Shutdown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartTaskCommand {
    pub external_session_id: String,
    pub workspace: PathBuf,
    pub request: String,
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub permission_mode: PermissionMode,
    pub budget: TaskBudget,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedStartTaskCommand {
    pub start: StartTaskCommand,
    pub frontend: Frontend,
    pub actor_id: ActorId,
    pub channel_id: String,
    pub event_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceApprovalDecision {
    Approve,
    Deny,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceModel {
    pub id: ModelId,
    pub display_name: String,
    pub supported_efforts: Vec<ReasoningEffort>,
    pub default_effort: ReasoningEffort,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCapabilities {
    pub durable_events: bool,
    pub reconnect: bool,
    pub trusted_buzz_admission: bool,
    pub configure_active_task: bool,
    pub explicit_task_budgets: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceInfo {
    pub protocol_version: u16,
    pub live_generation: String,
    pub models: Vec<ServiceModel>,
    pub default_model: Option<ModelId>,
    pub default_effort: Option<ReasoningEffort>,
    pub capabilities: ServiceCapabilities,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSessionInfo {
    pub external_session_id: String,
    pub session_id: SessionId,
    pub frontend: Frontend,
    pub workspace: PathBuf,
    pub channel_id: Option<String>,
    pub permission_mode: PermissionMode,
    pub task_ids: Vec<TaskId>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceFrame {
    Response {
        request_id: String,
        result: Box<ServiceResult>,
    },
    Error {
        request_id: String,
        code: String,
        message: String,
    },
    Event {
        task_id: TaskId,
        sequence: u64,
        update: TaskUpdate,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ServiceResult {
    Info(ServiceInfo),
    Session(ServiceSessionInfo),
    Accepted { task_id: TaskId },
    Snapshot(TaskSnapshot),
    TaskList(Vec<TaskSnapshot>),
    Events(Vec<EventEnvelope>),
    LiveUpdates(LiveUpdatePage),
    Applied,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveUpdatePage {
    pub live_generation: String,
    pub updates: Vec<LiveUpdateEnvelope>,
    pub cursor: Option<u64>,
    pub snapshot: Option<TaskSnapshot>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveUpdateEnvelope {
    pub cursor: u64,
    pub update: TaskUpdate,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum TaskUpdate {
    Status(TaskStatus),
    EpochObjective(String),
    ToolStarted(String),
    ToolCompleted(String),
    AssistantDelta(String),
    Diff(String),
    ApprovalRequired {
        task_id: TaskId,
        operation_id: OperationId,
        display_code: String,
        summary: String,
        request_id: String,
        session_id: SessionId,
        turn_id: TurnId,
        external_session_id: String,
    },
    Checkpoint(CheckpointId),
    ContextUsage {
        used: u64,
        window: u64,
    },
    Compaction {
        generation: u32,
    },
    CompletionClauses(Vec<CompletionClause>),
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProtocolErrorCode {
    #[error("service frame is invalid")]
    InvalidFrame,
    #[error("service frame is too large")]
    FrameTooLarge,
    #[error("service protocol version is unsupported")]
    UnsupportedVersion,
    #[error("service identifier is invalid")]
    InvalidIdentifier,
    #[error("service request is invalid")]
    InvalidRequest,
    #[error("service event limit is invalid")]
    InvalidEventLimit,
    #[error("service request identifier is duplicated")]
    DuplicateRequestId,
    #[error("service idempotency key conflicts with an earlier command")]
    IdempotencyConflict,
    #[error("service connection request ledger is full")]
    LedgerFull,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{code}")]
pub struct ProtocolError {
    code: ProtocolErrorCode,
}

impl ProtocolError {
    #[must_use]
    pub const fn code(&self) -> ProtocolErrorCode {
        self.code
    }

    const fn from_code(code: ProtocolErrorCode) -> Self {
        Self { code }
    }
}

#[derive(Debug, Default)]
pub struct RequestLedger {
    request_ids: BTreeSet<String>,
    request_order: VecDeque<String>,
    idempotency_digests: BTreeMap<String, [u8; 32]>,
    idempotency_order: VecDeque<String>,
}

pub fn decode_request_line(
    line: &[u8],
    ledger: &mut RequestLedger,
) -> Result<ServiceRequest, ProtocolError> {
    let payload = strip_newline(line)?;
    if payload.len() > MAX_SERVICE_FRAME_BYTES {
        return Err(protocol_error(ProtocolErrorCode::FrameTooLarge));
    }
    let request = serde_json::from_slice::<ServiceRequest>(payload)
        .map_err(|_| protocol_error(ProtocolErrorCode::InvalidFrame))?;
    validate_request(&request)?;
    ledger.record(&request)?;
    Ok(request)
}

pub fn encode_request(request: &ServiceRequest) -> Result<Vec<u8>, ProtocolError> {
    encode_json_line(request)
}

pub fn encode_frame(frame: &ServiceFrame) -> Result<Vec<u8>, ProtocolError> {
    encode_json_line(frame)
}

pub fn decode_frame_line(line: &[u8]) -> Result<ServiceFrame, ProtocolError> {
    let payload = strip_newline(line)?;
    if payload.len() > MAX_SERVICE_FRAME_BYTES {
        return Err(protocol_error(ProtocolErrorCode::FrameTooLarge));
    }
    serde_json::from_slice(payload).map_err(|_| protocol_error(ProtocolErrorCode::InvalidFrame))
}

pub fn command_digest(command: &ServiceCommand) -> Result<[u8; 32], ProtocolError> {
    let canonical = serde_json::to_vec(command)
        .map_err(|_| protocol_error(ProtocolErrorCode::InvalidRequest))?;
    Ok(Sha256::digest(canonical).into())
}

impl RequestLedger {
    fn record(&mut self, request: &ServiceRequest) -> Result<(), ProtocolError> {
        if self.request_ids.contains(&request.request_id) {
            return Err(protocol_error(ProtocolErrorCode::DuplicateRequestId));
        }
        let mutation_digest = if is_mutation(&request.command) {
            let digest = command_digest(&request.command)?;
            if self
                .idempotency_digests
                .get(&request.idempotency_key)
                .is_some_and(|existing| existing != &digest)
            {
                return Err(protocol_error(ProtocolErrorCode::IdempotencyConflict));
            }
            Some(digest)
        } else {
            None
        };
        if self.request_ids.len() >= MAX_REQUESTS_PER_CONNECTION
            && let Some(evicted) = self.request_order.pop_front()
        {
            self.request_ids.remove(&evicted);
        }
        self.request_ids.insert(request.request_id.clone());
        self.request_order.push_back(request.request_id.clone());

        if let Some(digest) = mutation_digest
            && !self
                .idempotency_digests
                .contains_key(&request.idempotency_key)
        {
            if self.idempotency_digests.len() >= MAX_REQUESTS_PER_CONNECTION
                && let Some(evicted) = self.idempotency_order.pop_front()
            {
                self.idempotency_digests.remove(&evicted);
            }
            self.idempotency_digests
                .insert(request.idempotency_key.clone(), digest);
            self.idempotency_order
                .push_back(request.idempotency_key.clone());
        }
        Ok(())
    }
}

#[must_use]
pub const fn is_mutation(command: &ServiceCommand) -> bool {
    matches!(
        command,
        ServiceCommand::StartTask(_)
            | ServiceCommand::StartTrustedTask(_)
            | ServiceCommand::ConfigureTrustedSession { .. }
            | ServiceCommand::ResolveApproval { .. }
            | ServiceCommand::Resume { .. }
            | ServiceCommand::Steer { .. }
            | ServiceCommand::SteerTrusted { .. }
            | ServiceCommand::Cancel { .. }
            | ServiceCommand::Configure { .. }
            | ServiceCommand::Shutdown
    )
}

fn validate_request(request: &ServiceRequest) -> Result<(), ProtocolError> {
    if request.protocol_version != SERVICE_PROTOCOL_VERSION {
        return Err(protocol_error(ProtocolErrorCode::UnsupportedVersion));
    }
    validate_identifier(&request.request_id)?;
    validate_identifier(&request.idempotency_key)?;
    match &request.command {
        ServiceCommand::StartTask(command) => validate_start(command)?,
        ServiceCommand::StartTrustedTask(command) => {
            validate_start(&command.start)?;
            if command.frontend != Frontend::Buzz {
                return Err(protocol_error(ProtocolErrorCode::InvalidRequest));
            }
            validate_bounded_text(&command.channel_id, MAX_IDENTIFIER_BYTES, false)?;
            validate_hex_digest(&command.event_id)?;
        }
        ServiceCommand::ConfigureTrustedSession {
            external_session_id,
            workspace: _,
            frontend,
            actor_id: _,
            channel_id,
            event_id,
            permission_mode: _,
        } => {
            if *frontend != Frontend::Buzz {
                return Err(protocol_error(ProtocolErrorCode::InvalidRequest));
            }
            validate_bounded_text(external_session_id, MAX_EXTERNAL_SESSION_BYTES, false)?;
            validate_bounded_text(channel_id, MAX_IDENTIFIER_BYTES, false)?;
            validate_hex_digest(event_id)?;
        }
        ServiceCommand::Steer { text, .. } => {
            validate_bounded_text(text, MAX_TASK_TEXT_BYTES, true)?;
        }
        ServiceCommand::ResolveApproval {
            external_session_id,
            frontend,
            channel_id,
            event_id,
            display_code,
            ..
        } => {
            validate_bounded_text(external_session_id, MAX_EXTERNAL_SESSION_BYTES, false)?;
            validate_bounded_text(display_code, MAX_IDENTIFIER_BYTES, false)?;
            match frontend {
                Frontend::Buzz => {
                    validate_bounded_text(
                        channel_id
                            .as_deref()
                            .ok_or_else(|| protocol_error(ProtocolErrorCode::InvalidRequest))?,
                        MAX_IDENTIFIER_BYTES,
                        false,
                    )?;
                    validate_hex_digest(
                        event_id
                            .as_deref()
                            .ok_or_else(|| protocol_error(ProtocolErrorCode::InvalidRequest))?,
                    )?;
                }
                Frontend::Acp if channel_id.is_none() && event_id.is_none() => {}
                _ => return Err(protocol_error(ProtocolErrorCode::InvalidRequest)),
            }
        }
        ServiceCommand::Session {
            external_session_id,
        } => validate_bounded_text(external_session_id, MAX_EXTERNAL_SESSION_BYTES, false)?,
        ServiceCommand::SteerTrusted {
            text,
            external_session_id,
            frontend,
            channel_id,
            event_id,
            ..
        } => {
            if *frontend != Frontend::Buzz {
                return Err(protocol_error(ProtocolErrorCode::InvalidRequest));
            }
            validate_bounded_text(text, MAX_TASK_TEXT_BYTES, true)?;
            validate_bounded_text(external_session_id, MAX_EXTERNAL_SESSION_BYTES, false)?;
            validate_bounded_text(channel_id, MAX_IDENTIFIER_BYTES, false)?;
            validate_hex_digest(event_id)?;
        }
        ServiceCommand::Events { limit, .. } | ServiceCommand::LiveUpdates { limit, .. }
            if !(1..=512).contains(limit) =>
        {
            return Err(protocol_error(ProtocolErrorCode::InvalidEventLimit));
        }
        ServiceCommand::LiveUpdates {
            live_generation, ..
        } if uuid::Uuid::parse_str(live_generation).is_err() => {
            return Err(protocol_error(ProtocolErrorCode::InvalidRequest));
        }
        ServiceCommand::Info
        | ServiceCommand::Status { .. }
        | ServiceCommand::List
        | ServiceCommand::Resume { .. }
        | ServiceCommand::Cancel { .. }
        | ServiceCommand::Configure { .. }
        | ServiceCommand::Events { .. }
        | ServiceCommand::LiveUpdates { .. }
        | ServiceCommand::Shutdown => {}
    }
    Ok(())
}

fn validate_start(command: &StartTaskCommand) -> Result<(), ProtocolError> {
    validate_bounded_text(
        &command.external_session_id,
        MAX_EXTERNAL_SESSION_BYTES,
        false,
    )?;
    validate_bounded_text(&command.request, MAX_TASK_TEXT_BYTES, true)?;
    command
        .budget
        .validate_for_admission()
        .map_err(|_| protocol_error(ProtocolErrorCode::InvalidRequest))
}

fn validate_hex_digest(value: &str) -> Result<(), ProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(protocol_error(ProtocolErrorCode::InvalidRequest));
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(protocol_error(ProtocolErrorCode::InvalidIdentifier));
    }
    Ok(())
}

fn validate_bounded_text(
    value: &str,
    maximum: usize,
    allow_line_controls: bool,
) -> Result<(), ProtocolError> {
    let invalid_control = value.chars().any(|character| {
        character.is_control() && !(allow_line_controls && matches!(character, '\n' | '\r' | '\t'))
    });
    if value.trim().is_empty() || value.len() > maximum || invalid_control {
        return Err(protocol_error(ProtocolErrorCode::InvalidRequest));
    }
    Ok(())
}

fn strip_newline(line: &[u8]) -> Result<&[u8], ProtocolError> {
    let Some(payload) = line.strip_suffix(b"\n") else {
        if line.len() > MAX_SERVICE_FRAME_BYTES {
            return Err(protocol_error(ProtocolErrorCode::FrameTooLarge));
        }
        return Err(protocol_error(ProtocolErrorCode::InvalidFrame));
    };
    Ok(payload.strip_suffix(b"\r").unwrap_or(payload))
}

fn encode_json_line<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let mut encoded =
        serde_json::to_vec(value).map_err(|_| protocol_error(ProtocolErrorCode::InvalidFrame))?;
    if encoded.len() > MAX_SERVICE_FRAME_BYTES {
        return Err(protocol_error(ProtocolErrorCode::FrameTooLarge));
    }
    encoded.push(b'\n');
    Ok(encoded)
}

const fn protocol_error(code: ProtocolErrorCode) -> ProtocolError {
    ProtocolError::from_code(code)
}
