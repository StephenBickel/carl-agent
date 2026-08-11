use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use semver::VersionReq;
use serde_json::{Map, Value, json};

use super::app_events::{parse_approval_request, parse_notification};
use super::{
    CodexApprovalDecision, CodexApprovalKind, CodexApprovalRequest, CodexEvent, CodexItem,
    CodexThreadId, CodexTurnId, DelegateError, DelegateErrorCode, map_sidecar_error,
};
use crate::acp::PermissionMode;
use crate::delegates::{ModelId, ReasoningEffort};
use crate::runtime::agent_port::{
    AgentCapabilities, AgentContextId, AgentEffectKind, AgentEffectRequest, AgentEpochId,
    AgentEvent, AgentFuture, AgentItem, AgentModel, AgentPort, AgentPortError, AgentPortErrorCode,
    AgentProcess, AgentRequestId, AgentUsage, EffectDecision, ResumeAgentContext,
    StartAgentContext, StartAgentEpoch,
};
use crate::sidecar::{
    JsonlSidecar, NotificationPolicy, ProviderEnvironmentProfile, ProviderHome, SidecarCommand,
    SidecarLimits, TrustedExecutable, VersionOutputFormat,
};

const CODEX_APP_SERVER_VERSION: &str = "0.146.0";
const CREDENTIAL_FILENAME: &str = "auth.json";
const MAX_CREDENTIAL_FILE_BYTES: u64 = 1024 * 1024;
const MAX_MODELS: usize = 64;
const MAX_MODEL_PAGES: usize = 16;
const MAX_BACKGROUND_PROCESSES: usize = 64;
const MAX_BACKGROUND_PROCESS_PAGES: usize = 16;
const MAX_TEXT_BYTES: usize = 256 * 1_024;
const MAX_CURSOR_BYTES: usize = 128;
const MAX_EFFECT_SUMMARY_BYTES: usize = 32 * 1_024;
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
    cwd: PathBuf,
    mode: PermissionMode,
    active_turn: Option<CodexTurnId>,
    compaction: Option<CompactionState>,
}

#[derive(Clone, Debug)]
struct CompactionState {
    item_id: Option<String>,
}

#[derive(Clone)]
struct OutstandingApproval {
    request: CodexApprovalRequest,
    request_digest: crate::policy::Sha256Digest,
}

pub struct CodexAppServer {
    sidecar: JsonlSidecar,
    experimental_api_negotiated: bool,
    next_request_id: u64,
    models: Vec<CodexModel>,
    threads: HashMap<String, ThreadState>,
    outstanding_approvals: HashMap<String, OutstandingApproval>,
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
                    "capabilities": {"experimentalApi":true}
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
            experimental_api_negotiated: true,
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
                cwd,
                mode: request.mode,
                active_turn: None,
                compaction: None,
            },
        );
        Ok(thread_id)
    }

    async fn resume_thread(
        &mut self,
        request: ResumeAgentContext,
    ) -> Result<CodexThreadId, ResumeThreadError> {
        let cwd = canonical_directory(request.cwd)?;
        self.require_model(&request.model, None)?;
        if self.threads.contains_key(request.context_id.as_str()) {
            return Err(protocol_error().into());
        }
        let thread_id = CodexThreadId::parse(request.context_id.as_str())?;
        let (approval_policy, _) = thread_mode(request.permission_mode);
        let sandbox = "read-only";
        let response = self
            .request_raw(
                "thread/resume",
                json!({
                    "threadId": thread_id.as_str(),
                    "cwd": cwd,
                    "model": request.model.as_str(),
                    "approvalPolicy": approval_policy,
                    "sandbox": sandbox,
                    "excludeTurns": true
                }),
            )
            .await?;
        let result = resume_response_result(response, &thread_id)?;
        validate_resumed_thread(
            &result,
            &thread_id,
            &cwd,
            &request.model,
            approval_policy,
            sandbox,
        )?;
        self.threads.insert(
            thread_id.as_str().to_owned(),
            ThreadState {
                cwd,
                mode: request.permission_mode,
                active_turn: None,
                compaction: None,
            },
        );
        Ok(thread_id)
    }

    async fn compact_thread(&mut self, thread_id: &CodexThreadId) -> Result<(), DelegateError> {
        let state = self
            .threads
            .get(thread_id.as_str())
            .ok_or_else(protocol_error)?;
        if state.active_turn.is_some() {
            return Err(protocol_error());
        }
        if state.compaction.is_some() {
            return Ok(());
        }
        let result = self
            .request(
                "thread/compact/start",
                json!({"threadId":thread_id.as_str()}),
            )
            .await?;
        let object = result.as_object().ok_or_else(protocol_error)?;
        require_keys(object, &[], &[])?;
        let state = self
            .threads
            .get_mut(thread_id.as_str())
            .ok_or_else(protocol_error)?;
        state.compaction = Some(CompactionState { item_id: None });
        Ok(())
    }

    pub async fn start_turn(&mut self, request: StartTurn) -> Result<CodexTurnId, DelegateError> {
        validate_text(&request.input)?;
        let state = self
            .threads
            .get(request.thread_id.as_str())
            .ok_or_else(protocol_error)?;
        if state.active_turn.is_some() || state.compaction.is_some() {
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

    async fn background_processes(
        &mut self,
        thread_id: &CodexThreadId,
    ) -> Result<Vec<AgentProcess>, DelegateError> {
        let workspace = self
            .threads
            .get(thread_id.as_str())
            .ok_or_else(protocol_error)?
            .cwd
            .clone();
        let mut processes = Vec::new();
        let mut process_ids = HashSet::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = HashSet::new();
        for _ in 0..MAX_BACKGROUND_PROCESS_PAGES {
            let result = self
                .request(
                    "thread/backgroundTerminals/list",
                    json!({
                        "threadId":thread_id.as_str(),
                        "cursor":cursor,
                        "limit":MAX_BACKGROUND_PROCESSES
                    }),
                )
                .await?;
            let object = result.as_object().ok_or_else(protocol_error)?;
            require_keys(object, &["data"], &["nextCursor"])?;
            let page = object
                .get("data")
                .and_then(Value::as_array)
                .ok_or_else(protocol_error)?;
            if page.len() > MAX_BACKGROUND_PROCESSES
                || processes.len().saturating_add(page.len()) > MAX_BACKGROUND_PROCESSES
            {
                return Err(protocol_error());
            }
            for value in page {
                let process = parse_background_process(value, &workspace)?;
                if !process_ids.insert(process.process_id.clone()) {
                    return Err(protocol_error());
                }
                processes.push(process);
            }
            cursor = optional_response_string(object.get("nextCursor"), MAX_CURSOR_BYTES)?;
            let Some(next) = cursor.as_ref() else {
                return Ok(processes);
            };
            if !seen_cursors.insert(next.clone()) {
                return Err(protocol_error());
            }
        }
        Err(protocol_error())
    }

    async fn terminate_background(
        &mut self,
        thread_id: &CodexThreadId,
        process_id: &str,
    ) -> Result<bool, DelegateError> {
        if !self.threads.contains_key(thread_id.as_str()) {
            return Err(protocol_error());
        }
        validate_text_bound(process_id, MAX_CURSOR_BYTES)?;
        let result = self
            .request(
                "thread/backgroundTerminals/terminate",
                json!({"threadId":thread_id.as_str(),"processId":process_id}),
            )
            .await?;
        let object = result.as_object().ok_or_else(protocol_error)?;
        require_keys(object, &["terminated"], &[])?;
        object
            .get("terminated")
            .and_then(Value::as_bool)
            .ok_or_else(protocol_error)
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
                        PermissionMode::FullAccess | PermissionMode::BypassPermissions => true,
                        PermissionMode::Plan | PermissionMode::DontAsk => false,
                    };
                    if surface {
                        if self
                            .outstanding_approvals
                            .insert(
                                approval.provider_request_id().to_owned(),
                                OutstandingApproval {
                                    request: approval.clone(),
                                    request_digest: approval.request_digest(),
                                },
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
        if stored.request.provider_id() != approval.provider_id()
            || stored.request_digest != approval.request_digest()
        {
            return Err(protocol_error());
        }
        self.send_approval_response(approval, decision)
    }

    pub async fn cancel(&mut self) -> Result<(), DelegateError> {
        self.sidecar.cancel().await.map_err(map_sidecar_error)
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value, DelegateError> {
        response_result(self.request_raw(method, params).await?)
    }

    async fn request_raw(&mut self, method: &str, params: Value) -> Result<Value, DelegateError> {
        let id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or_else(protocol_error)?;
        self.sidecar
            .request(json!({"id":id,"method":method,"params":params}))
            .await
            .map_err(map_sidecar_error)
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

    fn validate_event_binding(&mut self, event: &CodexEvent) -> Result<(), DelegateError> {
        if let CodexEvent::ItemStarted {
            thread_id,
            item: CodexItem::ContextCompaction { item_id },
            ..
        } = event
            && let Some(compaction) = self
                .threads
                .get_mut(thread_id.as_str())
                .ok_or_else(protocol_error)?
                .compaction
                .as_mut()
        {
            if compaction.item_id.is_some() {
                return Err(protocol_error());
            }
            compaction.item_id = Some(item_id.clone());
            return Ok(());
        }
        if let CodexEvent::ItemCompleted {
            thread_id,
            item: CodexItem::ContextCompaction { item_id },
            ..
        } = event
        {
            let state = self
                .threads
                .get_mut(thread_id.as_str())
                .ok_or_else(protocol_error)?;
            if let Some(compaction) = state.compaction.as_ref() {
                if compaction.item_id.as_deref() != Some(item_id) {
                    return Err(protocol_error());
                }
                state.compaction = None;
                return Ok(());
            }
        }
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

impl AgentPort for CodexAppServer {
    fn supports_autonomous_tasks(&self) -> bool {
        true
    }

    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            resume: self.experimental_api_negotiated,
            compact: self.experimental_api_negotiated,
            token_usage: true,
            pre_dispatch_effects: true,
            history_paging: false,
            background_processes: self.experimental_api_negotiated,
        }
    }

    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>> {
        Box::pin(async move {
            CodexAppServer::models(self)
                .await
                .map(|models| {
                    models
                        .into_iter()
                        .map(|model| AgentModel {
                            id: model.id,
                            display_name: model.display_name,
                            supported_efforts: model.supported_efforts,
                            default_effort: model.default_effort,
                        })
                        .collect()
                })
                .map_err(map_agent_error)
        })
    }

    fn start_context(&mut self, request: StartAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async move {
            let thread_id = CodexAppServer::start_thread(
                self,
                StartThread {
                    cwd: request.cwd,
                    model: Some(request.model),
                    mode: request.permission_mode,
                },
            )
            .await
            .map_err(map_agent_error)?;
            AgentContextId::parse(thread_id.as_str())
        })
    }

    fn resume_context(&mut self, request: ResumeAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async move {
            if !self.experimental_api_negotiated {
                return Err(AgentPortError::definitely_not_applied(
                    AgentPortErrorCode::Unsupported,
                ));
            }
            let thread_id = match CodexAppServer::resume_thread(self, request).await {
                Ok(thread_id) => thread_id,
                Err(ResumeThreadError::Unavailable) => {
                    return Err(AgentPortError::definitely_not_applied(
                        AgentPortErrorCode::UnavailableContext,
                    ));
                }
                Err(ResumeThreadError::Delegate(error)) => return Err(map_agent_error(error)),
            };
            AgentContextId::parse(thread_id.as_str())
        })
    }

    fn compact_context(&mut self, context_id: &AgentContextId) -> AgentFuture<'_, ()> {
        let context_id = context_id.clone();
        Box::pin(async move {
            if !self.experimental_api_negotiated {
                return Err(AgentPortError::definitely_not_applied(
                    AgentPortErrorCode::Unsupported,
                ));
            }
            let thread_id = CodexThreadId::parse(context_id.as_str()).map_err(map_agent_error)?;
            CodexAppServer::compact_thread(self, &thread_id)
                .await
                .map_err(map_agent_error)
        })
    }

    fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
        Box::pin(async move {
            if self
                .threads
                .get(request.context_id.as_str())
                .is_some_and(|state| state.compaction.is_some())
            {
                return Err(AgentPortError::from_code(
                    AgentPortErrorCode::InvalidRequest,
                ));
            }
            let turn_id = CodexAppServer::start_turn(
                self,
                StartTurn {
                    thread_id: CodexThreadId::parse(request.context_id.as_str())
                        .map_err(map_agent_error)?,
                    input: request.input,
                    model: Some(request.model),
                    effort: Some(request.effort),
                    mode: request.permission_mode,
                },
            )
            .await
            .map_err(map_agent_error)?;
            AgentEpochId::parse(turn_id.as_str())
        })
    }

    fn steer(
        &mut self,
        context_id: &AgentContextId,
        epoch_id: &AgentEpochId,
        text: String,
    ) -> AgentFuture<'_, ()> {
        let context_id = context_id.clone();
        let epoch_id = epoch_id.clone();
        Box::pin(async move {
            let thread_id = CodexThreadId::parse(context_id.as_str()).map_err(map_agent_error)?;
            let turn_id = CodexTurnId::parse(epoch_id.as_str()).map_err(map_agent_error)?;
            CodexAppServer::steer(self, &thread_id, &turn_id, text)
                .await
                .map_err(map_agent_error)
        })
    }

    fn interrupt(
        &mut self,
        context_id: &AgentContextId,
        epoch_id: &AgentEpochId,
    ) -> AgentFuture<'_, ()> {
        let context_id = context_id.clone();
        let epoch_id = epoch_id.clone();
        Box::pin(async move {
            let thread_id = CodexThreadId::parse(context_id.as_str()).map_err(map_agent_error)?;
            let turn_id = CodexTurnId::parse(epoch_id.as_str()).map_err(map_agent_error)?;
            CodexAppServer::interrupt(self, &thread_id, &turn_id)
                .await
                .map_err(map_agent_error)
        })
    }

    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent> {
        Box::pin(async move {
            let event = CodexAppServer::next_event(self)
                .await
                .map_err(map_agent_error)?;
            translate_codex_event(event)
        })
    }

    fn resolve_effect(
        &mut self,
        request_id: &AgentRequestId,
        decision: EffectDecision,
    ) -> AgentFuture<'_, ()> {
        let request_id = request_id.clone();
        Box::pin(async move {
            let stored = self
                .outstanding_approvals
                .get(request_id.as_str())
                .cloned()
                .ok_or_else(|| AgentPortError::from_code(AgentPortErrorCode::InvalidRequest))?;
            if stored.request.provider_request_id() != request_id.as_str()
                || stored.request.request_digest() != stored.request_digest
            {
                return Err(AgentPortError::from_code(
                    AgentPortErrorCode::InvalidResponse,
                ));
            }
            CodexAppServer::resolve_approval(
                self,
                &stored.request,
                match decision {
                    EffectDecision::Allow => CodexApprovalDecision::Allow,
                    EffectDecision::Deny => CodexApprovalDecision::Deny,
                },
            )
            .await
            .map_err(map_agent_error)
        })
    }

    fn list_background_processes(
        &mut self,
        context_id: &AgentContextId,
    ) -> AgentFuture<'_, Vec<AgentProcess>> {
        let context_id = context_id.clone();
        Box::pin(async move {
            if !self.experimental_api_negotiated {
                return Err(AgentPortError::definitely_not_applied(
                    AgentPortErrorCode::Unsupported,
                ));
            }
            let thread_id = CodexThreadId::parse(context_id.as_str()).map_err(map_agent_error)?;
            CodexAppServer::background_processes(self, &thread_id)
                .await
                .map_err(map_agent_error)
        })
    }

    fn terminate_background_process(
        &mut self,
        context_id: &AgentContextId,
        process_id: &str,
    ) -> AgentFuture<'_, bool> {
        let context_id = context_id.clone();
        let process_id = process_id.to_owned();
        Box::pin(async move {
            if !self.experimental_api_negotiated {
                return Err(AgentPortError::definitely_not_applied(
                    AgentPortErrorCode::Unsupported,
                ));
            }
            let thread_id = CodexThreadId::parse(context_id.as_str()).map_err(map_agent_error)?;
            CodexAppServer::terminate_background(self, &thread_id, &process_id)
                .await
                .map_err(map_agent_error)
        })
    }

    fn shutdown(&mut self) -> AgentFuture<'_, ()> {
        Box::pin(async move { CodexAppServer::cancel(self).await.map_err(map_agent_error) })
    }
}

fn translate_codex_event(event: CodexEvent) -> Result<AgentEvent, AgentPortError> {
    match event {
        CodexEvent::ThreadStarted { thread_id } => Ok(AgentEvent::ContextStarted {
            context_id: AgentContextId::parse(thread_id.as_str())?,
        }),
        CodexEvent::TurnStarted { thread_id, turn_id } => Ok(AgentEvent::EpochStarted {
            context_id: AgentContextId::parse(thread_id.as_str())?,
            epoch_id: AgentEpochId::parse(turn_id.as_str())?,
        }),
        CodexEvent::ItemStarted {
            thread_id,
            turn_id,
            item,
        } => translate_item_event(thread_id, turn_id, item, false),
        CodexEvent::AgentMessageDelta {
            thread_id,
            turn_id,
            text,
            ..
        } => Ok(AgentEvent::AssistantDelta {
            context_id: AgentContextId::parse(thread_id.as_str())?,
            epoch_id: AgentEpochId::parse(turn_id.as_str())?,
            text,
        }),
        CodexEvent::ItemCompleted {
            thread_id,
            turn_id,
            item,
        } => translate_item_event(thread_id, turn_id, item, true),
        CodexEvent::TokenUsageUpdated {
            thread_id,
            turn_id,
            usage,
        } => Ok(AgentEvent::UsageUpdated {
            context_id: AgentContextId::parse(thread_id.as_str())?,
            epoch_id: AgentEpochId::parse(turn_id.as_str())?,
            usage: AgentUsage {
                last_total_tokens: usage.last_total_tokens,
                total_tokens: usage.total_tokens,
                model_context_window: usage.model_context_window,
            },
        }),
        CodexEvent::DiffUpdated {
            thread_id,
            turn_id,
            diff,
        } => Ok(AgentEvent::DiffUpdated {
            context_id: AgentContextId::parse(thread_id.as_str())?,
            epoch_id: AgentEpochId::parse(turn_id.as_str())?,
            diff,
        }),
        CodexEvent::TurnCompleted {
            thread_id,
            turn_id,
            status,
        } => Ok(AgentEvent::EpochCompleted {
            context_id: AgentContextId::parse(thread_id.as_str())?,
            epoch_id: AgentEpochId::parse(turn_id.as_str())?,
            status,
        }),
        CodexEvent::ProviderError { thread_id, turn_id } => Ok(AgentEvent::ProviderFailed {
            context_id: thread_id
                .map(|thread_id| AgentContextId::parse(thread_id.as_str()))
                .transpose()?,
            epoch_id: turn_id
                .map(|turn_id| AgentEpochId::parse(turn_id.as_str()))
                .transpose()?,
        }),
        CodexEvent::ApprovalRequested(approval) => {
            let kind = match approval.kind() {
                CodexApprovalKind::Command => AgentEffectKind::Command,
                CodexApprovalKind::FileChange => AgentEffectKind::FileChange,
            };
            let summary = effect_summary(&approval, kind)?;
            Ok(AgentEvent::EffectRequested(AgentEffectRequest {
                context_id: AgentContextId::parse(approval.thread_id().as_str())?,
                epoch_id: AgentEpochId::parse(approval.turn_id().as_str())?,
                request_id: AgentRequestId::parse(approval.provider_request_id())?,
                item_id: approval.item_id().to_owned(),
                kind,
                summary,
                request_digest: approval.request_digest(),
            }))
        }
    }
}

fn translate_item_event(
    thread_id: CodexThreadId,
    turn_id: CodexTurnId,
    item: CodexItem,
    completed: bool,
) -> Result<AgentEvent, AgentPortError> {
    if let CodexItem::ContextCompaction { item_id } = item {
        let context_id = AgentContextId::parse(thread_id.as_str())?;
        return Ok(if completed {
            AgentEvent::CompactionCompleted {
                context_id,
                item_id,
            }
        } else {
            AgentEvent::CompactionStarted {
                context_id,
                item_id,
            }
        });
    }
    let context_id = AgentContextId::parse(thread_id.as_str())?;
    let epoch_id = AgentEpochId::parse(turn_id.as_str())?;
    let item = translate_codex_item(item);
    Ok(if completed {
        AgentEvent::ItemCompleted {
            context_id,
            epoch_id,
            item,
        }
    } else {
        AgentEvent::ItemStarted {
            context_id,
            epoch_id,
            item,
        }
    })
}

fn translate_codex_item(item: CodexItem) -> AgentItem {
    match item {
        CodexItem::Command {
            item_id,
            command,
            cwd,
            status,
            exit_code,
            aggregated_output,
            process_id,
        } => AgentItem::Command {
            item_id,
            command,
            cwd: PathBuf::from(cwd),
            status,
            exit_code,
            aggregated_output,
            process_id,
        },
        CodexItem::FileChange {
            item_id,
            status,
            changes,
        } => AgentItem::FileChange {
            item_id,
            status,
            changes,
        },
        CodexItem::ContextCompaction { item_id } => AgentItem::ContextCompaction { item_id },
        CodexItem::Other { item_id, item_type } => AgentItem::Other { item_id, item_type },
    }
}

fn effect_summary(
    approval: &CodexApprovalRequest,
    kind: AgentEffectKind,
) -> Result<String, AgentPortError> {
    let kind = match kind {
        AgentEffectKind::Command => "Command",
        AgentEffectKind::FileChange => "File changes",
        AgentEffectKind::Network => "Network access",
        AgentEffectKind::External => "External effect",
    };
    let mut summary = kind.to_owned();
    if let Some(command) = approval.command() {
        summary.push_str(": ");
        summary.push_str(command);
    }
    if let Some(reason) = approval.reason() {
        summary.push_str("\nReason: ");
        summary.push_str(reason);
    }
    if summary.len() > MAX_EFFECT_SUMMARY_BYTES || summary.as_bytes().contains(&0) {
        return Err(AgentPortError::from_code(
            AgentPortErrorCode::InvalidResponse,
        ));
    }
    Ok(summary)
}

fn map_agent_error(error: DelegateError) -> AgentPortError {
    let code = match error.code() {
        DelegateErrorCode::Configuration => AgentPortErrorCode::InvalidRequest,
        DelegateErrorCode::ProtocolFailed => AgentPortErrorCode::InvalidResponse,
        DelegateErrorCode::Cancelled => AgentPortErrorCode::Cancelled,
        DelegateErrorCode::AuthenticationRequired
        | DelegateErrorCode::Incompatible
        | DelegateErrorCode::StartFailed
        | DelegateErrorCode::BudgetExhausted
        | DelegateErrorCode::ProviderFailed => AgentPortErrorCode::Transport,
    };
    AgentPortError::from_code(code)
}

enum Incoming {
    Notification(Value),
    Request(Value),
}

struct ParsedModel {
    model: CodexModel,
    hidden: bool,
}

fn validate_resumed_thread(
    result: &Value,
    expected_thread_id: &CodexThreadId,
    expected_cwd: &Path,
    expected_model: &ModelId,
    expected_approval_policy: &str,
    expected_sandbox: &str,
) -> Result<(), DelegateError> {
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
            "initialTurnsPage",
            "instructionSources",
            "itemsBackwardsCursor",
            "multiAgentMode",
            "reasoningEffort",
            "runtimeWorkspaceRoots",
            "serviceTier",
            "turnsBackwardsCursor",
        ],
    )?;
    if object.get("cwd").and_then(Value::as_str) != expected_cwd.to_str()
        || object.get("model").and_then(Value::as_str) != Some(expected_model.as_str())
        || object.get("modelProvider").and_then(Value::as_str) != Some("openai")
        || object.get("approvalPolicy").and_then(Value::as_str) != Some(expected_approval_policy)
        || object.get("approvalsReviewer").and_then(Value::as_str) != Some("user")
        || !resume_sandbox_matches(object.get("sandbox"), expected_sandbox)
    {
        return Err(protocol_error());
    }
    if object
        .get("initialTurnsPage")
        .is_some_and(|value| !value.is_null())
    {
        return Err(protocol_error());
    }
    optional_response_string(object.get("itemsBackwardsCursor"), MAX_CURSOR_BYTES)?;
    optional_response_string(object.get("turnsBackwardsCursor"), MAX_CURSOR_BYTES)?;
    validate_active_permission_profile(object.get("activePermissionProfile"), expected_sandbox)?;
    validate_runtime_workspace_roots(object.get("runtimeWorkspaceRoots"), expected_cwd)?;
    validate_instruction_sources(object.get("instructionSources"))?;
    if object
        .get("multiAgentMode")
        .is_some_and(|value| value.as_str() != Some("explicitRequestOnly"))
        || object.get("reasoningEffort").is_some_and(|value| {
            !value.is_null()
                && !value.as_str().is_some_and(|effort| {
                    matches!(
                        effort,
                        "low" | "medium" | "high" | "xhigh" | "max" | "ultra"
                    )
                })
        })
    {
        return Err(protocol_error());
    }
    optional_response_string(object.get("serviceTier"), MAX_CURSOR_BYTES)?;
    let thread = object
        .get("thread")
        .and_then(Value::as_object)
        .ok_or_else(protocol_error)?;
    require_keys(
        thread,
        &[
            "cliVersion",
            "createdAt",
            "cwd",
            "ephemeral",
            "id",
            "modelProvider",
            "preview",
            "sessionId",
            "source",
            "status",
            "turns",
            "updatedAt",
        ],
        &[
            "agentNickname",
            "agentRole",
            "canAcceptDirectInput",
            "extra",
            "forkedFromId",
            "gitInfo",
            "historyMode",
            "isPinned",
            "name",
            "parentThreadId",
            "path",
            "recencyAt",
            "threadSource",
        ],
    )?;
    let returned_id = CodexThreadId::from_value(thread.get("id").ok_or_else(protocol_error)?)?;
    let status = thread
        .get("status")
        .and_then(Value::as_object)
        .ok_or_else(protocol_error)?;
    require_keys(status, &["type"], &[])?;
    let turns = thread
        .get("turns")
        .and_then(Value::as_array)
        .ok_or_else(protocol_error)?;
    if returned_id != *expected_thread_id
        || thread.get("cwd").and_then(Value::as_str) != expected_cwd.to_str()
        || thread.get("modelProvider").and_then(Value::as_str) != Some("openai")
        || thread.get("ephemeral").and_then(Value::as_bool) != Some(false)
        || status.get("type").and_then(Value::as_str) != Some("idle")
        || !turns.is_empty()
        || thread.get("createdAt").and_then(Value::as_i64).is_none()
        || thread.get("updatedAt").and_then(Value::as_i64).is_none()
        || !thread
            .get("cliVersion")
            .and_then(Value::as_str)
            .is_some_and(|value| valid_response_text(value, MAX_CURSOR_BYTES, false))
        || !thread
            .get("preview")
            .and_then(Value::as_str)
            .is_some_and(|value| valid_response_text(value, MAX_TEXT_BYTES, true))
        || !thread
            .get("sessionId")
            .and_then(Value::as_str)
            .is_some_and(|value| valid_response_text(value, MAX_CURSOR_BYTES, false))
        || !valid_thread_source(thread.get("source"))
    {
        return Err(protocol_error());
    }
    Ok(())
}

fn validate_active_permission_profile(
    value: Option<&Value>,
    expected_sandbox: &str,
) -> Result<(), DelegateError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let profile = value.as_object().ok_or_else(protocol_error)?;
    require_keys(profile, &["id"], &["extends"])?;
    let expected_id = match expected_sandbox {
        "read-only" => ":read-only",
        _ => return Err(protocol_error()),
    };
    if profile.get("id").and_then(Value::as_str) != Some(expected_id)
        || profile.get("extends").is_some_and(|value| !value.is_null())
    {
        return Err(protocol_error());
    }
    Ok(())
}

fn validate_runtime_workspace_roots(
    value: Option<&Value>,
    expected_cwd: &Path,
) -> Result<(), DelegateError> {
    let Some(value) = value else {
        return Ok(());
    };
    let roots = value.as_array().ok_or_else(protocol_error)?;
    if roots.len() > 16 {
        return Err(protocol_error());
    }
    for root in roots {
        let supplied = PathBuf::from(bounded_string(Some(root), MAX_TEXT_BYTES)?);
        let canonical = fs::canonicalize(&supplied).map_err(|_| protocol_error())?;
        if supplied != canonical || !canonical.is_dir() || !canonical.starts_with(expected_cwd) {
            return Err(protocol_error());
        }
    }
    Ok(())
}

fn validate_instruction_sources(value: Option<&Value>) -> Result<(), DelegateError> {
    let Some(value) = value else {
        return Ok(());
    };
    let sources = value.as_array().ok_or_else(protocol_error)?;
    if sources.len() > 64 {
        return Err(protocol_error());
    }
    for source in sources {
        bounded_string(Some(source), MAX_TEXT_BYTES)?;
    }
    Ok(())
}

fn valid_response_text(value: &str, maximum: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty()) && value.len() <= maximum && !value.as_bytes().contains(&0)
}

fn valid_thread_source(value: Option<&Value>) -> bool {
    value.is_some_and(|value| {
        value.as_str().is_some_and(|source| {
            matches!(
                source,
                "cli" | "vscode" | "exec" | "appServer" | "unknown" | "subAgent"
            )
        }) || value
            .get("custom")
            .and_then(Value::as_str)
            .is_some_and(|source| valid_response_text(source, MAX_CURSOR_BYTES, false))
    })
}

fn parse_background_process(
    value: &Value,
    workspace: &Path,
) -> Result<AgentProcess, DelegateError> {
    let object = value.as_object().ok_or_else(protocol_error)?;
    require_keys(
        object,
        &["processId", "itemId", "command", "cwd"],
        &["cpuPercent", "osPid", "rssKb"],
    )?;
    let process_id = bounded_string(object.get("processId"), MAX_CURSOR_BYTES)?;
    let item_id = bounded_string(object.get("itemId"), MAX_CURSOR_BYTES)?;
    let command = bounded_string(object.get("command"), MAX_TEXT_BYTES)?;
    let supplied_cwd = PathBuf::from(bounded_string(object.get("cwd"), MAX_TEXT_BYTES)?);
    let cwd = fs::canonicalize(&supplied_cwd).map_err(|_| protocol_error())?;
    if supplied_cwd != cwd || !cwd.is_dir() || !cwd.starts_with(workspace) {
        return Err(protocol_error());
    }
    let os_pid = match object.get("osPid") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            u32::try_from(value.as_u64().ok_or_else(protocol_error)?)
                .map_err(|_| protocol_error())?,
        ),
    };
    if let Some(value) = object.get("cpuPercent")
        && !value.is_null()
        && !value
            .as_f64()
            .is_some_and(|cpu| cpu.is_finite() && cpu >= 0.0)
    {
        return Err(protocol_error());
    }
    if let Some(value) = object.get("rssKb")
        && !value.is_null()
        && value.as_u64().is_none()
    {
        return Err(protocol_error());
    }
    Ok(AgentProcess {
        process_id,
        item_id,
        command,
        cwd,
        os_pid,
    })
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

fn resume_response_result(
    response: Value,
    thread_id: &CodexThreadId,
) -> Result<Value, ResumeThreadError> {
    if exact_missing_rollout_response(&response, thread_id) {
        return Err(ResumeThreadError::Unavailable);
    }
    response_result(response).map_err(ResumeThreadError::Delegate)
}

fn exact_missing_rollout_response(response: &Value, thread_id: &CodexThreadId) -> bool {
    let Some(object) = response.as_object() else {
        return false;
    };
    if !object.contains_key("id")
        || object
            .keys()
            .any(|key| !["id", "error", "jsonrpc"].contains(&key.as_str()))
        || object
            .get("jsonrpc")
            .is_some_and(|value| value.as_str() != Some("2.0"))
    {
        return false;
    }
    let Some(error) = object.get("error").and_then(Value::as_object) else {
        return false;
    };
    error.len() == 2
        && error.get("code").and_then(Value::as_i64) == Some(-32600)
        && error.get("message").and_then(Value::as_str)
            == Some(format!("no rollout found for thread id {}", thread_id.as_str()).as_str())
}

enum ResumeThreadError {
    Unavailable,
    Delegate(DelegateError),
}

impl From<DelegateError> for ResumeThreadError {
    fn from(error: DelegateError) -> Self {
        Self::Delegate(error)
    }
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

fn validate_text_bound(value: &str, maximum: usize) -> Result<(), DelegateError> {
    if value.is_empty() || value.len() > maximum || value.as_bytes().contains(&0) {
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

fn optional_response_string(
    value: Option<&Value>,
    maximum: usize,
) -> Result<Option<String>, DelegateError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => bounded_string(Some(value), maximum).map(Some),
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
        PermissionMode::FullAccess | PermissionMode::BypassPermissions => {
            ("on-request", "read-only")
        }
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
        PermissionMode::FullAccess | PermissionMode::BypassPermissions => (
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

fn resume_sandbox_matches(value: Option<&Value>, expected: &str) -> bool {
    let Some(value) = value else {
        return false;
    };
    let Some(object) = value.as_object() else {
        return false;
    };
    let expected_type = match expected {
        "read-only" => "readOnly",
        "workspace-write" => "workspaceWrite",
        "danger-full-access" => "dangerFullAccess",
        _ => return false,
    };
    if object.get("type").and_then(Value::as_str) != Some(expected_type) {
        return false;
    }
    match expected {
        "read-only" => {
            require_keys(object, &["type"], &["networkAccess"]).is_ok()
                && object
                    .get("networkAccess")
                    .is_none_or(|network| network.as_bool() == Some(false))
        }
        "danger-full-access" => require_keys(object, &["type"], &[]).is_ok(),
        "workspace-write" => false,
        _ => false,
    }
}

fn protocol_error() -> DelegateError {
    DelegateError::new(DelegateErrorCode::ProtocolFailed)
}
