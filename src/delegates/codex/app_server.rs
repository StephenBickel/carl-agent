use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::PathBuf;

use semver::VersionReq;
use serde_json::{Map, Value, json};

use super::app_events::{parse_approval_request, parse_notification};
use super::{
    CodexApprovalDecision, CodexApprovalKind, CodexApprovalRequest, CodexEvent, CodexThreadId,
    CodexTurnId, DelegateError, DelegateErrorCode, map_sidecar_error,
};
use crate::acp::PermissionMode;
use crate::delegates::{ModelId, ReasoningEffort};
use crate::sidecar::{
    JsonlSidecar, NotificationPolicy, ProviderEnvironmentProfile, ProviderHome, SidecarCommand,
    SidecarLimits, TrustedExecutable, VersionOutputFormat,
};

const CODEX_APP_SERVER_VERSION: &str = "0.146.0";
const CREDENTIAL_FILENAME: &str = "auth.json";
const MAX_CREDENTIAL_FILE_BYTES: u64 = 1024 * 1024;
const MAX_MODELS: usize = 64;
const MAX_MODEL_PAGES: usize = 16;
const MAX_TEXT_BYTES: usize = 256 * 1_024;
const MAX_CURSOR_BYTES: usize = 128;
const APP_SERVER_CONFIG: &[u8] = concat!(
    "cli_auth_credentials_store = \"file\"\n",
    "approval_policy = \"never\"\n",
    "sandbox_mode = \"read-only\"\n",
    "web_search = \"disabled\"\n",
)
.as_bytes();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CodexModel {
    id: ModelId,
    display_name: String,
    supported_efforts: Vec<ReasoningEffort>,
    default_effort: ReasoningEffort,
}

impl CodexModel {
    pub fn new(
        id: ModelId,
        display_name: impl Into<String>,
        supported_efforts: Vec<ReasoningEffort>,
        default_effort: ReasoningEffort,
    ) -> Result<Self, DelegateError> {
        let display_name = display_name.into();
        if display_name.is_empty()
            || display_name.len() > 128
            || supported_efforts.is_empty()
            || supported_efforts.len() > 6
            || supported_efforts
                .iter()
                .copied()
                .collect::<HashSet<_>>()
                .len()
                != supported_efforts.len()
            || !supported_efforts.contains(&default_effort)
        {
            return Err(protocol_error());
        }
        Ok(Self {
            id,
            display_name,
            supported_efforts,
            default_effort,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &ModelId {
        &self.id
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub fn supported_efforts(&self) -> &[ReasoningEffort] {
        &self.supported_efforts
    }

    #[must_use]
    pub const fn default_effort(&self) -> ReasoningEffort {
        self.default_effort
    }
}

#[derive(Clone, Debug)]
pub struct StartThread {
    pub cwd: PathBuf,
    pub model: Option<ModelId>,
    pub mode: PermissionMode,
}

#[derive(Clone, Debug)]
pub struct StartTurn {
    pub thread_id: CodexThreadId,
    pub input: String,
    pub model: Option<ModelId>,
    pub effort: Option<ReasoningEffort>,
    pub mode: PermissionMode,
}

#[derive(Clone, Debug)]
struct ThreadState {
    _cwd: PathBuf,
    mode: PermissionMode,
    active_turn: Option<CodexTurnId>,
}

pub struct CodexAppServer {
    sidecar: JsonlSidecar,
    next_request_id: u64,
    models: Vec<CodexModel>,
    threads: HashMap<String, ThreadState>,
    outstanding_approvals: HashMap<String, crate::policy::Sha256Digest>,
}

impl fmt::Debug for CodexAppServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CodexAppServer")
            .field("provider", &"openai_codex")
            .field("models_loaded", &self.models.len())
            .field("thread_count", &self.threads.len())
            .field("pending_approvals", &self.outstanding_approvals.len())
            .finish()
    }
}

impl CodexAppServer {
    pub fn long_horizon_protocol_contract(codex_version: &str) -> Result<Value, DelegateError> {
        if codex_version != CODEX_APP_SERVER_VERSION {
            return Err(DelegateError::new(DelegateErrorCode::Incompatible));
        }
        Ok(json!({
            "schema_version": 1,
            "codex_version": CODEX_APP_SERVER_VERSION,
            "methods": {
                "thread/resume": ["threadId"],
                "thread/compact/start": ["threadId"]
            },
            "notifications": {
                "thread/tokenUsage/updated": ["threadId", "turnId", "tokenUsage"],
                "item/started": ["threadId", "turnId", "item", "startedAtMs"],
                "item/completed": ["threadId", "turnId", "item", "completedAtMs"]
            },
            "item_types": ["commandExecution", "fileChange", "contextCompaction"]
        }))
    }

    pub async fn connect(
        executable: &TrustedExecutable,
        home: ProviderHome,
        limits: SidecarLimits,
    ) -> Result<Self, DelegateError> {
        home.require_profile(ProviderEnvironmentProfile::Codex)
            .map_err(map_sidecar_error)?;
        home.inspect_owner_only_file(CREDENTIAL_FILENAME, MAX_CREDENTIAL_FILE_BYTES)
            .map_err(map_sidecar_error)?;
        home.write_static_file("config.toml", APP_SERVER_CONFIG)
            .map_err(map_sidecar_error)?;
        let command = SidecarCommand {
            executable: executable.canonical_path().to_path_buf(),
            arguments: [
                "app-server",
                "--strict-config",
                "-c",
                "cli_auth_credentials_store=\"file\"",
                "--listen",
                "stdio://",
            ]
            .map(OsString::from)
            .into(),
            version_arguments: vec![OsString::from("--version")],
            version_output: VersionOutputFormat::ExactPrefixedVersion {
                prefix: "codex-cli",
                version: CODEX_APP_SERVER_VERSION,
            },
            isolated_home: PathBuf::new(),
            supported_versions: VersionReq::parse("=0.146.0")
                .expect("the pinned Codex app-server requirement is valid"),
        };
        let sidecar = JsonlSidecar::spawn_in_home(
            command,
            executable,
            &home,
            NotificationPolicy::QueueBounded,
            limits,
        )
        .await
        .map_err(map_sidecar_error)?;

        let response = sidecar
            .request(json!({
                "id": 0,
                "method": "initialize",
                "params": {
                    "clientInfo": {
                        "name": "carl",
                        "title": "Carl",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "capabilities": null
                }
            }))
            .await
            .map_err(map_sidecar_error)?;
        let result = response_result(response)?;
        validate_initialize_result(&result, &home)?;
        sidecar
            .notify(json!({"method":"initialized"}))
            .map_err(map_sidecar_error)?;

        Ok(Self {
            sidecar,
            next_request_id: 1,
            models: Vec::new(),
            threads: HashMap::new(),
            outstanding_approvals: HashMap::new(),
        })
    }

    pub async fn models(&mut self) -> Result<Vec<CodexModel>, DelegateError> {
        let mut models = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = HashSet::new();
        for _ in 0..MAX_MODEL_PAGES {
            let result = self
                .request("model/list", json!({"cursor":cursor, "limit":MAX_MODELS}))
                .await?;
            let object = result.as_object().ok_or_else(protocol_error)?;
            require_keys(object, &["data", "nextCursor"], &[])?;
            let page = object
                .get("data")
                .and_then(Value::as_array)
                .ok_or_else(protocol_error)?;
            if page.len() > MAX_MODELS || models.len().saturating_add(page.len()) > MAX_MODELS {
                return Err(protocol_error());
            }
            for value in page {
                let model = parse_model(value)?;
                if !model.hidden {
                    models.push(model.model);
                }
            }
            cursor = optional_bounded_string(object.get("nextCursor"), MAX_CURSOR_BYTES)?;
            let Some(next) = cursor.as_ref() else {
                let unique = models
                    .iter()
                    .map(|model| model.id().as_str())
                    .collect::<HashSet<_>>();
                if models.is_empty() || unique.len() != models.len() {
                    return Err(protocol_error());
                }
                self.models.clone_from(&models);
                return Ok(models);
            };
            if !seen_cursors.insert(next.clone()) {
                return Err(protocol_error());
            }
        }
        Err(protocol_error())
    }

    pub async fn start_thread(
        &mut self,
        request: StartThread,
    ) -> Result<CodexThreadId, DelegateError> {
        let cwd = canonical_directory(request.cwd)?;
        if let Some(model) = request.model.as_ref() {
            self.require_model(model, None)?;
        }
        let (approval_policy, sandbox) = thread_mode(request.mode);
        let result = self
            .request(
                "thread/start",
                json!({
                    "cwd": cwd,
                    "model": request.model.as_ref().map(ModelId::as_str),
                    "approvalPolicy": approval_policy,
                    "sandbox": sandbox,
                    "ephemeral": false
                }),
            )
            .await?;
        let object = result.as_object().ok_or_else(protocol_error)?;
        require_keys(
            object,
            &[
                "thread",
                "model",
                "modelProvider",
                "cwd",
                "approvalPolicy",
                "approvalsReviewer",
                "sandbox",
            ],
            &[
                "activePermissionProfile",
                "instructionSources",
                "multiAgentMode",
                "reasoningEffort",
                "runtimeWorkspaceRoots",
                "serviceTier",
            ],
        )?;
        if object.get("cwd").and_then(Value::as_str) != cwd.to_str()
            || object.get("approvalPolicy").and_then(Value::as_str) != Some(approval_policy)
            || !sandbox_matches(object.get("sandbox"), sandbox)
        {
            return Err(protocol_error());
        }
        if let Some(model) = request.model.as_ref()
            && object.get("model").and_then(Value::as_str) != Some(model.as_str())
        {
            return Err(protocol_error());
        }
        let thread = object
            .get("thread")
            .and_then(Value::as_object)
            .ok_or_else(protocol_error)?;
        if thread.get("cwd").and_then(Value::as_str) != cwd.to_str()
            || thread.get("ephemeral").and_then(Value::as_bool) != Some(false)
        {
            return Err(protocol_error());
        }
        let thread_id = CodexThreadId::from_value(thread.get("id").ok_or_else(protocol_error)?)?;
        if self.threads.contains_key(thread_id.as_str()) {
            return Err(protocol_error());
        }
        self.threads.insert(
            thread_id.as_str().to_owned(),
            ThreadState {
                _cwd: cwd,
                mode: request.mode,
                active_turn: None,
            },
        );
        Ok(thread_id)
    }

    pub async fn start_turn(&mut self, request: StartTurn) -> Result<CodexTurnId, DelegateError> {
        validate_text(&request.input)?;
        let state = self
            .threads
            .get(request.thread_id.as_str())
            .ok_or_else(protocol_error)?;
        if state.active_turn.is_some() {
            return Err(protocol_error());
        }
        if let Some(model) = request.model.as_ref() {
            self.require_model(model, request.effort)?;
        } else if request.effort.is_some() {
            return Err(protocol_error());
        }
        let (approval_policy, sandbox_policy) = turn_mode(request.mode);
        let result = self
            .request(
                "turn/start",
                json!({
                    "threadId": request.thread_id.as_str(),
                    "input": [{"type":"text", "text":request.input}],
                    "model": request.model.as_ref().map(ModelId::as_str),
                    "effort": request.effort.map(ReasoningEffort::as_codex_value),
                    "approvalPolicy": approval_policy,
                    "sandboxPolicy": sandbox_policy
                }),
            )
            .await?;
        let object = result.as_object().ok_or_else(protocol_error)?;
        require_keys(object, &["turn"], &[])?;
        let turn = object
            .get("turn")
            .and_then(Value::as_object)
            .ok_or_else(protocol_error)?;
        let turn_id = CodexTurnId::from_value(turn.get("id").ok_or_else(protocol_error)?)?;
        let state = self
            .threads
            .get_mut(request.thread_id.as_str())
            .ok_or_else(protocol_error)?;
        state.mode = request.mode;
        state.active_turn = Some(turn_id.clone());
        Ok(turn_id)
    }

    pub async fn steer(
        &mut self,
        thread_id: &CodexThreadId,
        turn_id: &CodexTurnId,
        input: impl Into<String>,
    ) -> Result<(), DelegateError> {
        let input = input.into();
        validate_text(&input)?;
        self.require_active_turn(thread_id, turn_id)?;
        let result = self
            .request(
                "turn/steer",
                json!({
                    "threadId":thread_id.as_str(),
                    "expectedTurnId":turn_id.as_str(),
                    "input":[{"type":"text","text":input}]
                }),
            )
            .await?;
        let object = result.as_object().ok_or_else(protocol_error)?;
        require_keys(object, &["turnId"], &[])?;
        if object.get("turnId").and_then(Value::as_str) != Some(turn_id.as_str()) {
            return Err(protocol_error());
        }
        Ok(())
    }

    pub async fn interrupt(
        &mut self,
        thread_id: &CodexThreadId,
        turn_id: &CodexTurnId,
    ) -> Result<(), DelegateError> {
        self.require_active_turn(thread_id, turn_id)?;
        let result = self
            .request(
                "turn/interrupt",
                json!({"threadId":thread_id.as_str(),"turnId":turn_id.as_str()}),
            )
            .await?;
        let object = result.as_object().ok_or_else(protocol_error)?;
        require_keys(object, &[], &[])?;
        let state = self
            .threads
            .get_mut(thread_id.as_str())
            .ok_or_else(protocol_error)?;
        state.active_turn = None;
        Ok(())
    }

    pub async fn next_event(&mut self) -> Result<CodexEvent, DelegateError> {
        loop {
            let incoming = if let Some(notification) = self
                .sidecar
                .try_next_notification()
                .await
                .map_err(map_sidecar_error)?
            {
                Incoming::Notification(notification)
            } else if let Some(request) = self
                .sidecar
                .try_next_server_request()
                .await
                .map_err(map_sidecar_error)?
            {
                Incoming::Request(request)
            } else {
                tokio::select! {
                    biased;
                    notification = self.sidecar.next_notification() => {
                        Incoming::Notification(notification.map_err(map_sidecar_error)?)
                    }
                    request = self.sidecar.next_server_request() => {
                        Incoming::Request(request.map_err(map_sidecar_error)?)
                    }
                }
            };

            match incoming {
                Incoming::Notification(value) => {
                    if is_ignorable_notification(&value)? {
                        continue;
                    }
                    let event = parse_notification(value)?;
                    self.validate_event_binding(&event)?;
                    if let CodexEvent::TurnCompleted {
                        thread_id, turn_id, ..
                    } = &event
                    {
                        let state = self
                            .threads
                            .get_mut(thread_id.as_str())
                            .ok_or_else(protocol_error)?;
                        if state.active_turn.as_ref() != Some(turn_id) {
                            return Err(protocol_error());
                        }
                        state.active_turn = None;
                    }
                    return Ok(event);
                }
                Incoming::Request(value) => {
                    let approval = parse_approval_request(value)?;
                    if self
                        .require_active_turn(approval.thread_id(), approval.turn_id())
                        .is_err()
                    {
                        self.send_approval_response(&approval, CodexApprovalDecision::Deny)?;
                        return Err(protocol_error());
                    }
                    let mode = self
                        .threads
                        .get(approval.thread_id().as_str())
                        .ok_or_else(protocol_error)?
                        .mode;
                    let surface = match mode {
                        PermissionMode::Default => true,
                        PermissionMode::AcceptEdits => {
                            approval.kind() == CodexApprovalKind::Command
                        }
                        PermissionMode::BypassPermissions => true,
                        PermissionMode::Plan | PermissionMode::DontAsk => false,
                    };
                    if surface {
                        if self
                            .outstanding_approvals
                            .insert(
                                approval.provider_request_id().to_owned(),
                                approval.request_digest(),
                            )
                            .is_some()
                        {
                            return Err(protocol_error());
                        }
                        return Ok(CodexEvent::ApprovalRequested(approval));
                    }
                    let decision = if mode == PermissionMode::AcceptEdits {
                        CodexApprovalDecision::Allow
                    } else {
                        CodexApprovalDecision::Deny
                    };
                    self.send_approval_response(&approval, decision)?;
                }
            }
        }
    }

    pub async fn resolve_approval(
        &mut self,
        approval: &CodexApprovalRequest,
        decision: CodexApprovalDecision,
    ) -> Result<(), DelegateError> {
        self.require_active_turn(approval.thread_id(), approval.turn_id())?;
        let stored = self
            .outstanding_approvals
            .remove(approval.provider_request_id())
            .ok_or_else(protocol_error)?;
        if stored != approval.request_digest() {
            return Err(protocol_error());
        }
        self.send_approval_response(approval, decision)
    }

    pub async fn cancel(&mut self) -> Result<(), DelegateError> {
        self.sidecar.cancel().await.map_err(map_sidecar_error)
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value, DelegateError> {
        let id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or_else(protocol_error)?;
        let response = self
            .sidecar
            .request(json!({"id":id,"method":method,"params":params}))
            .await
            .map_err(map_sidecar_error)?;
        response_result(response)
    }

    fn require_model(
        &self,
        model: &ModelId,
        effort: Option<ReasoningEffort>,
    ) -> Result<(), DelegateError> {
        let descriptor = self
            .models
            .iter()
            .find(|candidate| candidate.id() == model)
            .ok_or_else(protocol_error)?;
        if effort.is_some_and(|effort| !descriptor.supported_efforts().contains(&effort)) {
            return Err(protocol_error());
        }
        Ok(())
    }

    fn require_active_turn(
        &self,
        thread_id: &CodexThreadId,
        turn_id: &CodexTurnId,
    ) -> Result<(), DelegateError> {
        let state = self
            .threads
            .get(thread_id.as_str())
            .ok_or_else(protocol_error)?;
        if state.active_turn.as_ref() != Some(turn_id) {
            return Err(protocol_error());
        }
        Ok(())
    }

    fn validate_event_binding(&self, event: &CodexEvent) -> Result<(), DelegateError> {
        let (thread, turn) = match event {
            CodexEvent::ThreadStarted { thread_id } => {
                return if self.threads.contains_key(thread_id.as_str()) {
                    Ok(())
                } else {
                    Err(protocol_error())
                };
            }
            CodexEvent::TurnStarted { thread_id, turn_id }
            | CodexEvent::ItemStarted {
                thread_id, turn_id, ..
            }
            | CodexEvent::AgentMessageDelta {
                thread_id, turn_id, ..
            }
            | CodexEvent::ItemCompleted {
                thread_id, turn_id, ..
            }
            | CodexEvent::TokenUsageUpdated {
                thread_id, turn_id, ..
            }
            | CodexEvent::DiffUpdated {
                thread_id, turn_id, ..
            }
            | CodexEvent::TurnCompleted {
                thread_id, turn_id, ..
            } => (Some(thread_id), Some(turn_id)),
            CodexEvent::ProviderError { thread_id, turn_id } => {
                (thread_id.as_ref(), turn_id.as_ref())
            }
            CodexEvent::ApprovalRequested(_) => return Err(protocol_error()),
        };
        match (thread, turn) {
            (Some(thread), Some(turn)) => self.require_active_turn(thread, turn),
            (None, None) => Ok(()),
            _ => Err(protocol_error()),
        }
    }

    fn send_approval_response(
        &self,
        approval: &CodexApprovalRequest,
        decision: CodexApprovalDecision,
    ) -> Result<(), DelegateError> {
        self.sidecar
            .respond_to_server_request(json!({
                "id":approval.provider_id(),
                "result":{"decision":decision.as_codex_value()}
            }))
            .map_err(map_sidecar_error)
    }
}

enum Incoming {
    Notification(Value),
    Request(Value),
}

struct ParsedModel {
    model: CodexModel,
    hidden: bool,
}

fn parse_model(value: &Value) -> Result<ParsedModel, DelegateError> {
    let object = value.as_object().ok_or_else(protocol_error)?;
    require_keys(
        object,
        &[
            "defaultReasoningEffort",
            "description",
            "displayName",
            "hidden",
            "id",
            "isDefault",
            "model",
            "supportedReasoningEfforts",
        ],
        &[
            "additionalSpeedTiers",
            "availabilityNux",
            "defaultServiceTier",
            "inputModalities",
            "serviceTiers",
            "supportsPersonality",
            "upgrade",
            "upgradeInfo",
        ],
    )?;
    let id_text = bounded_string(object.get("id"), 128)?;
    if object.get("model").and_then(Value::as_str) != Some(id_text.as_str()) {
        return Err(protocol_error());
    }
    let id = ModelId::parse(id_text).map_err(|_| protocol_error())?;
    let display_name = bounded_string(object.get("displayName"), 128)?;
    let hidden = object
        .get("hidden")
        .and_then(Value::as_bool)
        .ok_or_else(protocol_error)?;
    if object.get("isDefault").and_then(Value::as_bool).is_none()
        || object.get("description").and_then(Value::as_str).is_none()
    {
        return Err(protocol_error());
    }
    let efforts = object
        .get("supportedReasoningEfforts")
        .and_then(Value::as_array)
        .ok_or_else(protocol_error)?;
    if efforts.is_empty() || efforts.len() > 6 {
        return Err(protocol_error());
    }
    let mut supported_efforts = Vec::with_capacity(efforts.len());
    for effort in efforts {
        let effort = effort.as_object().ok_or_else(protocol_error)?;
        require_keys(effort, &["reasoningEffort", "description"], &[])?;
        if effort.get("description").and_then(Value::as_str).is_none() {
            return Err(protocol_error());
        }
        supported_efforts.push(parse_effort(
            effort
                .get("reasoningEffort")
                .and_then(Value::as_str)
                .ok_or_else(protocol_error)?,
        )?);
    }
    if supported_efforts
        .iter()
        .copied()
        .collect::<HashSet<_>>()
        .len()
        != supported_efforts.len()
    {
        return Err(protocol_error());
    }
    let default_effort = parse_effort(
        object
            .get("defaultReasoningEffort")
            .and_then(Value::as_str)
            .ok_or_else(protocol_error)?,
    )?;
    if !supported_efforts.contains(&default_effort) {
        return Err(protocol_error());
    }
    Ok(ParsedModel {
        model: CodexModel {
            id,
            display_name,
            supported_efforts,
            default_effort,
        },
        hidden,
    })
}

fn validate_initialize_result(result: &Value, home: &ProviderHome) -> Result<(), DelegateError> {
    let object = result.as_object().ok_or_else(protocol_error)?;
    require_keys(
        object,
        &["userAgent", "codexHome", "platformFamily", "platformOs"],
        &[],
    )?;
    if !object
        .get("userAgent")
        .and_then(Value::as_str)
        .is_some_and(valid_user_agent)
        || !object
            .get("codexHome")
            .and_then(Value::as_str)
            .is_some_and(|path| home.matches_path(path))
        || object
            .get("platformFamily")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || object
            .get("platformOs")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(protocol_error());
    }
    Ok(())
}

fn valid_user_agent(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 || value.as_bytes().contains(&0) {
        return false;
    }
    let native_suffix = format!(") unknown (carl; {})", env!("CARGO_PKG_VERSION"));
    let native = value
        .strip_prefix("carl/0.146.0 (")
        .and_then(|platform| platform.strip_suffix(&native_suffix))
        .is_some_and(|platform| {
            !platform.is_empty()
                && platform.len() <= 128
                && platform.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(byte, b' ' | b'.' | b'_' | b'-' | b';' | b',')
                })
        });
    value == "codex_cli_rs/0.146.0"
        || native
        || (value.starts_with("Codex Desktop/0.146.0 ")
            && value.ends_with(&format!("(carl; {})", env!("CARGO_PKG_VERSION"))))
}

fn is_ignorable_notification(value: &Value) -> Result<bool, DelegateError> {
    let object = value.as_object().ok_or_else(protocol_error)?;
    require_keys(object, &["method", "params"], &["emittedAtMs"])?;
    if object
        .get("emittedAtMs")
        .is_some_and(|timestamp| timestamp.as_u64().is_none())
    {
        return Err(protocol_error());
    }
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(protocol_error)?;
    let params = object
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(protocol_error)?;
    match method {
        "remoteControl/status/changed" => {
            require_keys(
                params,
                &["status", "serverName", "installationId", "environmentId"],
                &[],
            )?;
            if !params
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| {
                    matches!(status, "disabled" | "connecting" | "connected" | "errored")
                })
                || !params.get("serverName").is_some_and(Value::is_string)
                || !params.get("installationId").is_some_and(Value::is_string)
                || !params
                    .get("environmentId")
                    .is_some_and(|value| value.is_null() || value.is_string())
            {
                return Err(protocol_error());
            }
            Ok(true)
        }
        "mcpServer/startupStatus/updated" => {
            require_keys(
                params,
                &["threadId", "name", "status", "error", "failureReason"],
                &[],
            )?;
            bounded_string(params.get("threadId"), 128)?;
            bounded_string(params.get("name"), 128)?;
            let status = bounded_string(params.get("status"), 32)?;
            if !matches!(
                status.as_str(),
                "starting" | "ready" | "failed" | "cancelled"
            ) {
                return Err(protocol_error());
            }
            optional_bounded_string(params.get("error"), MAX_TEXT_BYTES)?;
            optional_bounded_string(params.get("failureReason"), MAX_TEXT_BYTES)?;
            Ok(true)
        }
        "thread/status/changed" => {
            require_keys(params, &["threadId", "status"], &[])?;
            bounded_string(params.get("threadId"), 128)?;
            let status = params
                .get("status")
                .and_then(Value::as_object)
                .ok_or_else(protocol_error)?;
            require_keys(status, &["type"], &["activeFlags"])?;
            let status_type = bounded_string(status.get("type"), 32)?;
            if !matches!(status_type.as_str(), "active" | "idle") {
                return Err(protocol_error());
            }
            if let Some(flags) = status.get("activeFlags") {
                let flags = flags.as_array().ok_or_else(protocol_error)?;
                if flags.len() > 16 {
                    return Err(protocol_error());
                }
                for flag in flags {
                    bounded_string(Some(flag), 64)?;
                }
            }
            Ok(true)
        }
        "warning" => {
            require_keys(params, &["threadId", "message"], &[])?;
            bounded_string(params.get("threadId"), 128)?;
            bounded_string(params.get("message"), MAX_TEXT_BYTES)?;
            Ok(true)
        }
        "account/rateLimits/updated" => {
            require_keys(params, &["rateLimits"], &[])?;
            validate_rate_limits(params.get("rateLimits"))?;
            Ok(true)
        }
        "item/commandExecution/outputDelta" | "item/fileChange/outputDelta" => {
            require_keys(params, &["threadId", "turnId", "itemId", "delta"], &[])?;
            bounded_string(params.get("threadId"), 128)?;
            bounded_string(params.get("turnId"), 128)?;
            bounded_string(params.get("itemId"), 128)?;
            bounded_string(params.get("delta"), MAX_TEXT_BYTES)?;
            Ok(true)
        }
        "serverRequest/resolved" => {
            require_keys(params, &["threadId", "requestId"], &[])?;
            bounded_string(params.get("threadId"), 128)?;
            let request_id = params.get("requestId").ok_or_else(protocol_error)?;
            if request_id.as_u64().is_none() && bounded_string(Some(request_id), 128).is_err() {
                return Err(protocol_error());
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn validate_rate_limits(value: Option<&Value>) -> Result<(), DelegateError> {
    let limits = value
        .and_then(Value::as_object)
        .ok_or_else(protocol_error)?;
    require_keys(
        limits,
        &[
            "limitId",
            "limitName",
            "primary",
            "secondary",
            "credits",
            "individualLimit",
            "spendControlReached",
            "planType",
            "rateLimitReachedType",
        ],
        &[],
    )?;
    bounded_string(limits.get("limitId"), 128)?;
    optional_bounded_string(limits.get("limitName"), 128)?;
    validate_rate_limit_window(limits.get("primary"))?;
    validate_rate_limit_window(limits.get("secondary"))?;
    let credits = limits
        .get("credits")
        .and_then(Value::as_object)
        .ok_or_else(protocol_error)?;
    require_keys(credits, &["hasCredits", "unlimited", "balance"], &[])?;
    if !credits.get("hasCredits").is_some_and(Value::is_boolean)
        || !credits.get("unlimited").is_some_and(Value::is_boolean)
    {
        return Err(protocol_error());
    }
    bounded_string(credits.get("balance"), 128)?;
    if !limits
        .get("individualLimit")
        .is_some_and(|value| value.is_null() || value.is_object())
        || !limits
            .get("spendControlReached")
            .is_some_and(|value| value.is_null() || value.is_boolean())
    {
        return Err(protocol_error());
    }
    optional_bounded_string(limits.get("planType"), 128)?;
    optional_bounded_string(limits.get("rateLimitReachedType"), 128)?;
    Ok(())
}

fn validate_rate_limit_window(value: Option<&Value>) -> Result<(), DelegateError> {
    let Some(value) = value else {
        return Err(protocol_error());
    };
    if value.is_null() {
        return Ok(());
    }
    let window = value.as_object().ok_or_else(protocol_error)?;
    require_keys(
        window,
        &["usedPercent", "windowDurationMins", "resetsAt"],
        &[],
    )?;
    if window.values().any(|value| value.as_u64().is_none()) {
        return Err(protocol_error());
    }
    Ok(())
}

fn response_result(response: Value) -> Result<Value, DelegateError> {
    let object = response.as_object().ok_or_else(protocol_error)?;
    let allowed = ["id", "result", "error", "jsonrpc"];
    if !object.contains_key("id")
        || object.keys().any(|key| !allowed.contains(&key.as_str()))
        || object.contains_key("result") == object.contains_key("error")
        || object
            .get("jsonrpc")
            .is_some_and(|value| value.as_str() != Some("2.0"))
    {
        return Err(protocol_error());
    }
    object
        .get("result")
        .cloned()
        .ok_or_else(|| DelegateError::new(DelegateErrorCode::ProviderFailed))
}

fn canonical_directory(path: PathBuf) -> Result<PathBuf, DelegateError> {
    if !path.is_absolute() {
        return Err(DelegateError::new(DelegateErrorCode::Configuration));
    }
    let canonical = fs::canonicalize(&path)
        .map_err(|_| DelegateError::new(DelegateErrorCode::Configuration))?;
    if canonical != path || !canonical.is_dir() {
        return Err(DelegateError::new(DelegateErrorCode::Configuration));
    }
    Ok(canonical)
}

fn validate_text(value: &str) -> Result<(), DelegateError> {
    if value.trim().is_empty() || value.len() > MAX_TEXT_BYTES || value.as_bytes().contains(&0) {
        return Err(DelegateError::new(DelegateErrorCode::Configuration));
    }
    Ok(())
}

fn bounded_string(value: Option<&Value>, maximum: usize) -> Result<String, DelegateError> {
    let value = value.and_then(Value::as_str).ok_or_else(protocol_error)?;
    if value.is_empty() || value.len() > maximum || value.as_bytes().contains(&0) {
        return Err(protocol_error());
    }
    Ok(value.to_owned())
}

fn optional_bounded_string(
    value: Option<&Value>,
    maximum: usize,
) -> Result<Option<String>, DelegateError> {
    match value {
        Some(Value::Null) => Ok(None),
        Some(value) => bounded_string(Some(value), maximum).map(Some),
        None => Err(protocol_error()),
    }
}

fn require_keys(
    object: &Map<String, Value>,
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

fn parse_effort(value: &str) -> Result<ReasoningEffort, DelegateError> {
    match value {
        "low" => Ok(ReasoningEffort::Low),
        "medium" => Ok(ReasoningEffort::Medium),
        "high" => Ok(ReasoningEffort::High),
        "xhigh" => Ok(ReasoningEffort::XHigh),
        "max" => Ok(ReasoningEffort::Max),
        "ultra" => Ok(ReasoningEffort::Ultra),
        _ => Err(protocol_error()),
    }
}

fn thread_mode(mode: PermissionMode) -> (&'static str, &'static str) {
    match mode {
        PermissionMode::Plan => ("never", "read-only"),
        PermissionMode::Default | PermissionMode::AcceptEdits => ("on-request", "workspace-write"),
        PermissionMode::DontAsk => ("never", "workspace-write"),
        PermissionMode::BypassPermissions => ("on-request", "read-only"),
    }
}

fn turn_mode(mode: PermissionMode) -> (&'static str, Value) {
    let (approval, sandbox) = match mode {
        PermissionMode::Plan => ("never", json!({"type":"readOnly","networkAccess":false})),
        PermissionMode::Default | PermissionMode::AcceptEdits => (
            "on-request",
            json!({
                "type":"workspaceWrite",
                "writableRoots":[],
                "networkAccess":false,
                "excludeTmpdirEnvVar":false,
                "excludeSlashTmp":false
            }),
        ),
        PermissionMode::DontAsk => (
            "never",
            json!({
                "type":"workspaceWrite",
                "writableRoots":[],
                "networkAccess":false,
                "excludeTmpdirEnvVar":false,
                "excludeSlashTmp":false
            }),
        ),
        PermissionMode::BypassPermissions => (
            "on-request",
            json!({"type":"readOnly","networkAccess":false}),
        ),
    };
    (approval, sandbox)
}

fn sandbox_matches(value: Option<&Value>, expected: &str) -> bool {
    value.is_some_and(|value| {
        value.as_str() == Some(expected)
            || value.get("type").and_then(Value::as_str)
                == Some(match expected {
                    "read-only" => "readOnly",
                    "workspace-write" => "workspaceWrite",
                    "danger-full-access" => "dangerFullAccess",
                    _ => return false,
                })
    })
}

fn protocol_error() -> DelegateError {
    DelegateError::new(DelegateErrorCode::ProtocolFailed)
}
