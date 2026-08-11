use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{TimeDelta, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::mpsc;

use crate::acp::{PermissionMode, PermissionProfile};
use crate::delegates::{ModelId, ReasoningEffort};
use crate::events::{SessionId, ToolCallId, TurnId};
use crate::policy::ActorId;
use crate::runtime::agent_port::{
    AgentContextId, AgentEffectRequest, AgentEpochId, AgentErrorProvenance, AgentEvent, AgentItem,
    AgentPort, AgentPortError, AgentPortErrorCode, AgentUsage, ContextRecovery, EffectDecision,
    ResumeAgentContext, StartAgentContext, StartAgentEpoch,
};
use crate::security::SecretFilter;
use crate::storage::{
    ApprovalStatus, BoundApprovalBinding, ExternalSessionId, NewCheckpoint, NewRemoteCode, NewTask,
    ProviderRequestId, RemoteCodeClaim, RemoteCodeKind, RuntimeStore, Store, TaskRecord,
};

use super::{
    CanonicalCheckpoint, CheckpointBuildInput, CheckpointId, ClauseStatus, CompactionDecision,
    CompletionClause, CompletionContract, CompletionDecision, ContextBudget, ContextEngine,
    ContextInput, EpochId, EpochReport, EvidenceRef, ExactIdentifier, NormalizedOperationEvidence,
    OperationEvidence, OperationId, OperationStatus, ProcessCheckpoint, ProgressAssessment,
    ProviderCheckpoint, ProviderRequestPurpose, RecoveryAttempt, RecoveryAttemptOutcome,
    RecoveryStrategy, RepositoryCheckpoint, TaskBudget, TaskEvent, TaskId, TaskSnapshot,
    TaskStatus, assess_progress_with_recovery_attempts, classify_effect, decide_completion,
    parse_epoch_report, recovery_attempt_fingerprint,
};

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_CONTRACT_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_EPOCH_TRANSCRIPT_BYTES: usize = 256 * 1024;
const MAX_EPOCH_DIFF_BYTES: usize = 1024 * 1024;
const MAX_EPOCH_PROVIDER_EVENTS: usize = 8_192;
const MAX_ENGINE_UPDATES: usize = 4_096;
const MAX_ENGINE_UPDATE_BYTES: usize = 2 * 1024 * 1024;
const RESERVED_STATUS_UPDATE_BYTES: usize = 256;
const DEFAULT_CONTEXT_WINDOW: u64 = 128_000;
const CONTEXT_TRIGGER_PERCENT: u8 = 80;
const CONTEXT_TARGET_PERCENT: u8 = 60;
const CONTRACT_OPEN: &str = "<carl-completion-contract>";
const CONTRACT_CLOSE: &str = "</carl-completion-contract>";
const SAFE_BOUNDARY_MESSAGE: &str = "Carl soft epoch boundary reached. Finish the active operation, then emit a safe checkpoint report.";
const APPROVAL_LIFETIME: TimeDelta = TimeDelta::minutes(15);

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TaskEngineErrorCode {
    #[error("task input is invalid")]
    InvalidTask,
    #[error("durable task storage failed")]
    Storage,
    #[error("agent provider failed")]
    Provider,
    #[error("task context assembly failed")]
    Context,
    #[error("task verification failed")]
    Verification,
    #[error("task was cancelled")]
    Cancelled,
    #[error("task is blocked")]
    Blocked,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{code}")]
pub struct TaskEngineError {
    code: TaskEngineErrorCode,
}

impl TaskEngineError {
    const fn from_code(code: TaskEngineErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(&self) -> TaskEngineErrorCode {
        self.code
    }
}

#[derive(Clone, Debug)]
pub struct StartTask {
    pub session_id: SessionId,
    pub workspace: PathBuf,
    pub request: String,
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub permission_mode: PermissionMode,
    pub budget: TaskBudget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineToolKind {
    Execute,
    Edit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineToolStatus {
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TaskEngineUpdate {
    TaskStatus {
        task_id: TaskId,
        status: TaskStatus,
    },
    EpochObjective {
        task_id: TaskId,
        epoch_id: EpochId,
        objective: String,
    },
    CheckpointCommitted {
        task_id: TaskId,
        checkpoint_id: CheckpointId,
        digest: String,
    },
    ContextUsage {
        task_id: TaskId,
        total_tokens: u64,
        context_window: Option<u64>,
    },
    Compaction {
        task_id: TaskId,
        generation: u32,
        replaced_provider: bool,
    },
    RecoveryStrategy {
        task_id: TaskId,
        strategy: RecoveryStrategy,
    },
    CompletionClauses {
        task_id: TaskId,
        clauses: Vec<CompletionClause>,
    },
    AgentMessageChunk(String),
    ToolStarted {
        title: String,
        kind: EngineToolKind,
    },
    ToolCompleted {
        title: String,
        status: EngineToolStatus,
    },
    DiffUpdated(String),
    PermissionRequired {
        request_id: String,
        summary: String,
    },
}

pub(crate) enum TaskEngineControl {
    Steer {
        text: String,
        session_id: SessionId,
        turn_id: crate::events::TurnId,
        acknowledgement: u64,
    },
    Cancel {
        session_id: SessionId,
        turn_id: crate::events::TurnId,
        acknowledgement: u64,
    },
    Approval {
        display_code: String,
        decision: EffectDecision,
        session_id: SessionId,
        turn_id: crate::events::TurnId,
        acknowledgement: u64,
    },
}

pub(crate) type TaskEngineAcknowledgement = (u64, Result<(), TaskEngineError>);

#[derive(Clone)]
pub(crate) struct TaskEngineFrontendContext {
    pub session_id: SessionId,
    pub turn_id: crate::events::TurnId,
    pub external_session_id: ExternalSessionId,
    pub actor_id: ActorId,
}

pub(crate) struct TaskEnginePermissionNotice {
    pub display_code: String,
    pub summary: String,
    pub request_id: String,
}

struct RuntimeTask {
    workspace: PathBuf,
    request: String,
    model: ModelId,
    effort: ReasoningEffort,
    permission_mode: PermissionMode,
    context_id: AgentContextId,
    next_objective: String,
    previous_checkpoint: Option<CanonicalCheckpoint>,
    progress: Vec<ProgressAssessment>,
    recovery_attempts: Vec<RecoveryAttempt>,
    pending_recovery: Option<PendingRecovery>,
    steering: VecDeque<String>,
    steering_sequence: u64,
    operation_evidence: Vec<OperationEvidence>,
    file_hashes: BTreeMap<String, String>,
    observed_total_tokens: Option<u64>,
    observed_context_window: Option<u64>,
    estimated_tokens_since_usage: u64,
    completed_tools: u64,
    started_tools: u64,
    provider_requests: u64,
}

struct ActiveOperation {
    operation_id: OperationId,
    item: AgentItem,
    frontend_tool_call_id: Option<ToolCallId>,
}

struct PendingRecovery {
    epoch_id: EpochId,
    strategy: RecoveryStrategy,
    strategy_fingerprint: String,
}

struct WorkEpochOutput {
    transcript: String,
    terminal_status: String,
}

pub trait TaskEngineStore: Send {
    fn task_store(&self) -> &Store;
    fn task_store_mut(&mut self) -> &mut Store;
}

impl TaskEngineStore for Store {
    fn task_store(&self) -> &Store {
        self
    }

    fn task_store_mut(&mut self) -> &mut Store {
        self
    }
}

impl TaskEngineStore for RuntimeStore {
    fn task_store(&self) -> &Store {
        self.store()
    }

    fn task_store_mut(&mut self) -> &mut Store {
        self.store_mut()
    }
}

pub struct TaskEngine<P: AgentPort, S: TaskEngineStore = Store> {
    store: S,
    port: P,
    tasks: HashMap<TaskId, RuntimeTask>,
    updates: Vec<TaskEngineUpdate>,
    controls: Option<mpsc::Receiver<TaskEngineControl>>,
    acknowledgements: Option<mpsc::Sender<TaskEngineAcknowledgement>>,
    frontend_context: Option<TaskEngineFrontendContext>,
    permission_notices: Option<mpsc::Sender<TaskEnginePermissionNotice>>,
}

impl<P: AgentPort, S: TaskEngineStore> fmt::Debug for TaskEngine<P, S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskEngine")
            .field("active_tasks", &self.tasks.len())
            .field("pending_updates", &self.updates.len())
            .finish_non_exhaustive()
    }
}

impl<P: AgentPort> TaskEngine<P, Store> {
    #[must_use]
    pub fn new(store: Store, port: P) -> Self {
        Self {
            store,
            port,
            tasks: HashMap::new(),
            updates: Vec::new(),
            controls: None,
            acknowledgements: None,
            frontend_context: None,
            permission_notices: None,
        }
    }
}

impl<P: AgentPort> TaskEngine<P, RuntimeStore> {
    #[must_use]
    pub fn new_runtime(store: RuntimeStore, port: P) -> Self {
        Self {
            store,
            port,
            tasks: HashMap::new(),
            updates: Vec::new(),
            controls: None,
            acknowledgements: None,
            frontend_context: None,
            permission_notices: None,
        }
    }

    #[must_use]
    pub const fn runtime_store(&self) -> &RuntimeStore {
        &self.store
    }
}

impl<P: AgentPort, S: TaskEngineStore> TaskEngine<P, S> {
    #[must_use]
    pub fn store(&self) -> &Store {
        self.store.task_store()
    }

    #[must_use]
    pub fn store_mut(&mut self) -> &mut Store {
        self.store.task_store_mut()
    }

    #[must_use]
    pub const fn port_mut(&mut self) -> &mut P {
        &mut self.port
    }

    #[must_use]
    pub fn into_parts(self) -> (S, P) {
        (self.store, self.port)
    }

    #[must_use]
    pub fn take_updates(&mut self) -> Vec<TaskEngineUpdate> {
        std::mem::take(&mut self.updates)
    }

    fn can_accumulate_update(&self, additional_bytes: usize) -> bool {
        self.updates.len() < MAX_ENGINE_UPDATES.saturating_sub(1)
            && self
                .updates
                .iter()
                .map(engine_update_size)
                .sum::<usize>()
                .saturating_add(additional_bytes)
                .saturating_add(RESERVED_STATUS_UPDATE_BYTES)
                <= MAX_ENGINE_UPDATE_BYTES
    }

    pub(crate) fn install_controls(
        &mut self,
        controls: mpsc::Receiver<TaskEngineControl>,
        acknowledgements: mpsc::Sender<TaskEngineAcknowledgement>,
        permission_notices: mpsc::Sender<TaskEnginePermissionNotice>,
    ) {
        self.controls = Some(controls);
        self.acknowledgements = Some(acknowledgements);
        self.permission_notices = Some(permission_notices);
    }

    pub(crate) fn install_frontend_context(&mut self, context: TaskEngineFrontendContext) {
        self.frontend_context = Some(context);
    }

    pub async fn start(&mut self, input: StartTask) -> Result<TaskSnapshot, TaskEngineError> {
        validate_start(&input)?;
        let context_id = self
            .port
            .start_context(StartAgentContext {
                cwd: input.workspace.clone(),
                model: input.model.clone(),
                permission_mode: input.permission_mode,
            })
            .await
            .map_err(provider_error)?;
        self.start_in_context(input, context_id).await
    }

    pub async fn start_in_context(
        &mut self,
        input: StartTask,
        context_id: AgentContextId,
    ) -> Result<TaskSnapshot, TaskEngineError> {
        validate_start(&input)?;
        let contract = fallback_contract(&input.request);
        let created = self
            .store_mut()
            .create_task(NewTask {
                session_id: input.session_id,
                workspace: input.workspace.clone(),
                contract: contract.clone(),
                model: input.model.clone(),
                effort: input.effort,
                permission_mode: input.permission_mode,
                budget: input.budget,
                created_at: Utc::now(),
            })
            .map_err(storage_error)?;
        let task_id = created.snapshot.task_id;
        let active = self.append(
            task_id,
            TaskEvent::StateTransitioned {
                from: TaskStatus::Queued,
                to: TaskStatus::Active,
                reason: "autonomous execution started".to_owned(),
            },
        )?;
        self.updates.push(TaskEngineUpdate::TaskStatus {
            task_id,
            status: active.snapshot.status,
        });
        self.append(
            task_id,
            TaskEvent::ProviderContextBound {
                context_id: context_id.as_str().to_owned(),
            },
        )?;
        let mut runtime = RuntimeTask {
            workspace: input.workspace.clone(),
            request: input.request.clone(),
            model: input.model.clone(),
            effort: input.effort,
            permission_mode: input.permission_mode,
            context_id,
            next_objective: format!(
                "Implement and explicitly verify: {}",
                normalized_contract_goal(&input.request)
            ),
            previous_checkpoint: None,
            progress: Vec::new(),
            recovery_attempts: Vec::new(),
            pending_recovery: None,
            steering: VecDeque::new(),
            steering_sequence: 0,
            operation_evidence: Vec::new(),
            file_hashes: BTreeMap::new(),
            observed_total_tokens: None,
            observed_context_window: None,
            estimated_tokens_since_usage: 0,
            completed_tools: 0,
            started_tools: 0,
            provider_requests: 0,
        };
        let planned = self.plan_contract(task_id, &mut runtime, &input).await;
        self.tasks.insert(task_id, runtime);
        let mut planned = planned?;
        if planned != contract {
            planned.version = contract.version.saturating_add(1);
            self.append(task_id, TaskEvent::ContractRevised { contract: planned })?;
        }
        self.run(task_id).await
    }

    pub async fn run(&mut self, task_id: TaskId) -> Result<TaskSnapshot, TaskEngineError> {
        let record = self
            .store()
            .get_task(task_id)
            .map_err(storage_error)?
            .ok_or_else(invalid_task)?;
        if record.snapshot.status.is_terminal() {
            return Ok(record.snapshot);
        }
        if record.snapshot.status == TaskStatus::Cancelling {
            return Err(error(TaskEngineErrorCode::Cancelled));
        }
        if record.snapshot.status == TaskStatus::Blocked {
            return Err(error(TaskEngineErrorCode::Blocked));
        }
        if !self.tasks.contains_key(&task_id) {
            let runtime = self.rehydrate_runtime(task_id, &record.snapshot)?;
            self.tasks.insert(task_id, runtime);
        }
        let mut runtime = self.tasks.remove(&task_id).ok_or_else(invalid_task)?;
        let recovered = if record.snapshot.status == TaskStatus::Checkpointing {
            self.recover_checkpointing(task_id, &runtime)?
        } else {
            None
        };
        let result = if let Some(result) = recovered {
            result
        } else {
            self.run_loop(task_id, &mut runtime).await
        };
        self.tasks.insert(task_id, runtime);
        result
    }

    fn recover_checkpointing(
        &mut self,
        task_id: TaskId,
        runtime: &RuntimeTask,
    ) -> Result<Option<Result<TaskSnapshot, TaskEngineError>>, TaskEngineError> {
        let Some(checkpoint) = runtime.previous_checkpoint.as_ref() else {
            self.block_task(
                task_id,
                "checkpoint transaction did not commit; completed work will not be repeated",
            )?;
            return Ok(Some(Err(error(TaskEngineErrorCode::Blocked))));
        };
        let latest_finished_sequence = self
            .store()
            .read_task_events(task_id)
            .map_err(storage_error)?
            .iter()
            .filter_map(|envelope| match envelope.event {
                crate::events::Event::TaskLifecycle {
                    event: TaskEvent::EpochFinished { .. },
                    ..
                } => Some(envelope.sequence),
                _ => None,
            })
            .max()
            .ok_or_else(invalid_task)?;
        if checkpoint.source_sequence_end < latest_finished_sequence {
            self.block_task(
                task_id,
                "latest completed epoch is not covered by an atomic checkpoint",
            )?;
            return Ok(Some(Err(error(TaskEngineErrorCode::Blocked))));
        }
        self.append(
            task_id,
            TaskEvent::StateTransitioned {
                from: TaskStatus::Checkpointing,
                to: TaskStatus::Active,
                reason: "recovered atomically committed checkpoint".to_owned(),
            },
        )?;
        if checkpoint.contract.required_clauses_satisfied() {
            self.append(
                task_id,
                TaskEvent::StateTransitioned {
                    from: TaskStatus::Active,
                    to: TaskStatus::Completing,
                    reason: "recovered checkpoint has complete durable evidence".to_owned(),
                },
            )?;
            let completed = self.append(task_id, TaskEvent::Completed)?;
            self.updates.push(TaskEngineUpdate::TaskStatus {
                task_id,
                status: completed.snapshot.status,
            });
            Ok(Some(Ok(completed.snapshot)))
        } else {
            self.updates.push(TaskEngineUpdate::TaskStatus {
                task_id,
                status: TaskStatus::Active,
            });
            Ok(None)
        }
    }

    pub async fn steer(&mut self, task_id: TaskId, text: String) -> Result<(), TaskEngineError> {
        validate_steering(&text)?;
        let runtime = self.tasks.get_mut(&task_id).ok_or_else(invalid_task)?;
        let digest = sha256(text.as_bytes());
        let steering_sequence = runtime.steering_sequence;
        runtime.steering_sequence = runtime
            .steering_sequence
            .checked_add(1)
            .ok_or_else(invalid_task)?;
        runtime.steering.push_back(text);
        self.append(
            task_id,
            TaskEvent::SteeringQueued {
                steering_sequence,
                text_digest: digest,
            },
        )?;
        Ok(())
    }

    pub async fn cancel(&mut self, task_id: TaskId) -> Result<(), TaskEngineError> {
        let record = self
            .store()
            .get_task(task_id)
            .map_err(storage_error)?
            .ok_or_else(invalid_task)?;
        if record.snapshot.status == TaskStatus::Cancelled {
            return Ok(());
        }
        if record.snapshot.status.is_terminal() {
            return Err(invalid_task());
        }
        let logical_epoch_id = record.snapshot.active_epoch;
        let started_operation_ids = record.snapshot.started_operation_ids();
        let provider_epoch_id = active_provider_epoch(self.store(), task_id)?;
        let context_id = self
            .tasks
            .get(&task_id)
            .map(|runtime| runtime.context_id.clone())
            .or_else(|| {
                record
                    .snapshot
                    .provider_context
                    .as_deref()
                    .and_then(|context_id| AgentContextId::parse(context_id).ok())
            });
        match self
            .cancel_active_epoch(
                task_id,
                logical_epoch_id,
                context_id.as_ref(),
                provider_epoch_id.as_ref(),
                &started_operation_ids,
                None,
            )
            .await
        {
            Err(error) if error.code() == TaskEngineErrorCode::Cancelled => Ok(()),
            result => result,
        }
    }

    async fn plan_contract(
        &mut self,
        task_id: TaskId,
        runtime: &mut RuntimeTask,
        input: &StartTask,
    ) -> Result<CompletionContract, TaskEngineError> {
        let initial = format!(
            "Read-only contract planning. Derive a bounded CompletionContract for this owner request without asking the owner to restate it. Return exactly one {CONTRACT_OPEN} JSON object {CONTRACT_CLOSE}. Request: {}",
            input.request
        );
        let repair = format!(
            "Repair the prior invalid contract. Return exactly one valid {CONTRACT_OPEN} JSON object {CONTRACT_CLOSE}; no trailing prose."
        );
        for (attempt, prompt) in [initial, repair].into_iter().enumerate() {
            let output = self
                .run_planning_epoch(task_id, runtime, input, prompt, attempt)
                .await?;
            if let Ok(contract) = parse_contract(&output) {
                return Ok(contract);
            }
        }
        Ok(fallback_contract(&input.request))
    }

    async fn run_planning_epoch(
        &mut self,
        task_id: TaskId,
        runtime: &mut RuntimeTask,
        input: &StartTask,
        prompt: String,
        attempt: usize,
    ) -> Result<String, TaskEngineError> {
        let epoch_id = EpochId::new();
        self.append(
            task_id,
            TaskEvent::EpochStarted {
                epoch_id,
                objective: format!("Derive completion contract attempt {}", attempt + 1),
            },
        )?;
        self.updates.push(TaskEngineUpdate::EpochObjective {
            task_id,
            epoch_id,
            objective: "Derive the bounded completion contract".to_owned(),
        });
        let provider_epoch_id = self
            .start_provider_epoch(
                task_id,
                epoch_id,
                ProviderRequestPurpose::ContractPlanning,
                runtime,
                StartAgentEpoch {
                    context_id: runtime.context_id.clone(),
                    input: prompt,
                    model: input.model.clone(),
                    effort: input.effort,
                    permission_mode: PermissionMode::Plan,
                },
            )
            .await?;
        let record = self
            .store()
            .get_task(task_id)
            .map_err(storage_error)?
            .ok_or_else(invalid_task)?;
        let hard_wall_remaining = remaining_wall_budget(&record);
        let hard_wall_enabled = hard_wall_remaining.is_some();
        let hard_wall_timer = tokio::time::sleep(hard_wall_remaining.unwrap_or_default());
        tokio::pin!(hard_wall_timer);
        let mut output = String::new();
        let mut usage_observed = false;
        let mut provider_events = 0_usize;
        loop {
            enum Next {
                Provider(Result<AgentEvent, AgentPortError>),
                HardBudget,
                Control(Option<TaskEngineControl>),
            }
            let controls_enabled = self.controls.is_some();
            let next = {
                let port = &mut self.port;
                let controls = &mut self.controls;
                tokio::select! {
                    event = port.next_event() => Next::Provider(event),
                    () = &mut hard_wall_timer, if hard_wall_enabled => Next::HardBudget,
                    control = receive_control(controls), if controls_enabled => Next::Control(control),
                }
            };
            let event = match next {
                Next::Provider(Ok(event)) => event,
                Next::Provider(Err(_)) => {
                    self.interrupt_planning_and_block(
                        task_id,
                        epoch_id,
                        runtime,
                        &provider_epoch_id,
                        "planning provider event delivery failed",
                    )
                    .await?;
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
                Next::Control(Some(control)) => {
                    let acknowledgement = control_acknowledgement(&control);
                    let result = self
                        .apply_planning_control(
                            task_id,
                            epoch_id,
                            runtime,
                            &provider_epoch_id,
                            control,
                        )
                        .await;
                    self.acknowledge(acknowledgement, result.clone()).await;
                    if let Err(control_error) = result {
                        if control_error.code() == TaskEngineErrorCode::Cancelled {
                            return Err(control_error);
                        }
                        self.interrupt_planning_and_block(
                            task_id,
                            epoch_id,
                            runtime,
                            &provider_epoch_id,
                            "planning control delivery failed",
                        )
                        .await?;
                        return Err(error(TaskEngineErrorCode::Blocked));
                    }
                    continue;
                }
                Next::Control(None) => {
                    self.controls = None;
                    self.acknowledgements = None;
                    self.interrupt_planning_and_block(
                        task_id,
                        epoch_id,
                        runtime,
                        &provider_epoch_id,
                        "planning control channel closed",
                    )
                    .await?;
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
                Next::HardBudget => {
                    self.interrupt_planning_and_block(
                        task_id,
                        epoch_id,
                        runtime,
                        &provider_epoch_id,
                        "maximum task wall time exhausted during contract planning",
                    )
                    .await?;
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
            };
            if event.validate().is_err() {
                self.interrupt_planning_and_block(
                    task_id,
                    epoch_id,
                    runtime,
                    &provider_epoch_id,
                    "planning provider event validation failed",
                )
                .await?;
                return Err(error(TaskEngineErrorCode::Blocked));
            }
            provider_events = provider_events.saturating_add(1);
            if provider_events > MAX_EPOCH_PROVIDER_EVENTS {
                self.interrupt_planning_and_block(
                    task_id,
                    epoch_id,
                    runtime,
                    &provider_epoch_id,
                    "maximum provider events exhausted during contract planning",
                )
                .await?;
                return Err(error(TaskEngineErrorCode::Blocked));
            }
            match event {
                AgentEvent::ContextStarted { .. } => {}
                AgentEvent::EpochStarted {
                    context_id: observed_context,
                    epoch_id: observed_epoch,
                } if observed_context == runtime.context_id
                    && observed_epoch == provider_epoch_id => {}
                AgentEvent::AssistantDelta {
                    context_id: observed_context,
                    epoch_id: observed_epoch,
                    text,
                } if observed_context == runtime.context_id
                    && observed_epoch == provider_epoch_id =>
                {
                    self.account_estimated_tokens(runtime, text.len())?;
                    if output
                        .len()
                        .checked_add(text.len())
                        .is_none_or(|size| size > MAX_CONTRACT_OUTPUT_BYTES)
                    {
                        self.interrupt_planning_and_block(
                            task_id,
                            epoch_id,
                            runtime,
                            &provider_epoch_id,
                            "aggregate contract planning output exceeded its bound",
                        )
                        .await?;
                        return Err(error(TaskEngineErrorCode::Blocked));
                    }
                    output.push_str(&text);
                }
                AgentEvent::UsageUpdated {
                    context_id: observed_context,
                    epoch_id: observed_epoch,
                    usage,
                } if observed_context == runtime.context_id
                    && observed_epoch == provider_epoch_id =>
                {
                    usage_observed = true;
                    self.record_usage(task_id, epoch_id, runtime, usage)?;
                }
                AgentEvent::ItemStarted {
                    context_id: observed_context,
                    epoch_id: observed_epoch,
                    item: AgentItem::Other { .. } | AgentItem::ContextCompaction { .. },
                }
                | AgentEvent::ItemCompleted {
                    context_id: observed_context,
                    epoch_id: observed_epoch,
                    item: AgentItem::Other { .. } | AgentItem::ContextCompaction { .. },
                } if observed_context == runtime.context_id
                    && observed_epoch == provider_epoch_id => {}
                AgentEvent::CompactionStarted { context_id, .. }
                | AgentEvent::CompactionCompleted { context_id, .. }
                    if context_id == runtime.context_id => {}
                AgentEvent::EpochCompleted {
                    context_id: observed_context,
                    epoch_id: observed_epoch,
                    ..
                } if observed_context == runtime.context_id
                    && observed_epoch == provider_epoch_id =>
                {
                    if !usage_observed || runtime.estimated_tokens_since_usage > 0 {
                        self.record_estimated_usage(task_id, epoch_id, runtime)?;
                    }
                    self.append(
                        task_id,
                        TaskEvent::EpochFinished {
                            epoch_id,
                            report_digest: sha256(output.as_bytes()),
                        },
                    )?;
                    return Ok(output);
                }
                AgentEvent::ProviderFailed { .. } => {
                    self.interrupt_planning_and_block(
                        task_id,
                        epoch_id,
                        runtime,
                        &provider_epoch_id,
                        "planning provider reported failure",
                    )
                    .await?;
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
                _ => {
                    self.interrupt_planning_and_block(
                        task_id,
                        epoch_id,
                        runtime,
                        &provider_epoch_id,
                        "planning provider emitted an unexpected event",
                    )
                    .await?;
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
            }
        }
    }

    async fn interrupt_planning_and_block(
        &mut self,
        task_id: TaskId,
        epoch_id: EpochId,
        runtime: &RuntimeTask,
        provider_epoch_id: &AgentEpochId,
        reason: &str,
    ) -> Result<(), TaskEngineError> {
        let _ = self
            .port
            .interrupt(&runtime.context_id, provider_epoch_id)
            .await;
        self.append(
            task_id,
            TaskEvent::EpochFinished {
                epoch_id,
                report_digest: sha256(reason.as_bytes()),
            },
        )?;
        self.block_task(task_id, reason)
    }

    async fn apply_planning_control(
        &mut self,
        task_id: TaskId,
        epoch_id: EpochId,
        runtime: &mut RuntimeTask,
        provider_epoch_id: &AgentEpochId,
        control: TaskEngineControl,
    ) -> Result<(), TaskEngineError> {
        match control {
            TaskEngineControl::Cancel {
                session_id,
                turn_id,
                ..
            } => {
                self.cancel_active_epoch(
                    task_id,
                    Some(epoch_id),
                    Some(&runtime.context_id),
                    Some(provider_epoch_id),
                    &[],
                    Some((session_id, turn_id)),
                )
                .await
            }
            control => {
                self.apply_control(task_id, epoch_id, runtime, provider_epoch_id, &[], control)
                    .await
            }
        }
    }

    async fn run_loop(
        &mut self,
        task_id: TaskId,
        runtime: &mut RuntimeTask,
    ) -> Result<TaskSnapshot, TaskEngineError> {
        loop {
            let record = self
                .store_mut()
                .get_task(task_id)
                .map_err(storage_error)?
                .ok_or_else(invalid_task)?;
            if record.snapshot.status.is_terminal() {
                return Ok(record.snapshot);
            }
            if let Some(reason) = exhausted_budget_reason(&record, runtime) {
                let blocked = self.append(
                    task_id,
                    TaskEvent::Blocked {
                        reason: reason.to_owned(),
                    },
                )?;
                self.updates.push(TaskEngineUpdate::TaskStatus {
                    task_id,
                    status: blocked.snapshot.status,
                });
                return Err(error(TaskEngineErrorCode::Blocked));
            }
            if !self.can_accumulate_update(0) {
                self.block_task(task_id, "accumulated engine updates exceeded their bound")?;
                return Err(error(TaskEngineErrorCode::Blocked));
            }

            let objective = recovery_objective(runtime);
            let epoch_id = runtime
                .pending_recovery
                .as_ref()
                .map_or_else(EpochId::new, |pending| pending.epoch_id);
            self.append(
                task_id,
                TaskEvent::EpochStarted {
                    epoch_id,
                    objective: objective.clone(),
                },
            )?;
            self.updates.push(TaskEngineUpdate::EpochObjective {
                task_id,
                epoch_id,
                objective: objective.clone(),
            });
            let provider_input = self.assemble_epoch_context(task_id, runtime, &objective)?;
            let purpose = if runtime.pending_recovery.is_some() {
                ProviderRequestPurpose::Recovery
            } else {
                ProviderRequestPurpose::Work
            };
            let provider_epoch_id = self
                .start_provider_epoch(
                    task_id,
                    epoch_id,
                    purpose,
                    runtime,
                    StartAgentEpoch {
                        context_id: runtime.context_id.clone(),
                        input: provider_input,
                        model: runtime.model.clone(),
                        effort: runtime.effort,
                        permission_mode: runtime.permission_mode,
                    },
                )
                .await?;
            let queued_steering = runtime.steering.drain(..).collect::<Vec<_>>();
            for steering in queued_steering {
                if self
                    .port
                    .steer(&runtime.context_id, &provider_epoch_id, steering)
                    .await
                    .is_err()
                {
                    self.interrupt_and_block_epoch(
                        task_id,
                        epoch_id,
                        runtime,
                        &provider_epoch_id,
                        &HashMap::new(),
                        "provider rejected queued steering",
                    )
                    .await?;
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
            }
            let epoch_output = self
                .drain_work_epoch(task_id, epoch_id, &provider_epoch_id, runtime)
                .await?;
            let report = parse_epoch_report(&epoch_output.transcript)
                .map_err(|_| error(TaskEngineErrorCode::Verification))?;
            self.append(
                task_id,
                TaskEvent::EpochFinished {
                    epoch_id,
                    report_digest: sha256(epoch_output.transcript.as_bytes()),
                },
            )?;
            if let Some(pending) = runtime
                .pending_recovery
                .take()
                .filter(|pending| pending.epoch_id == epoch_id)
            {
                let attempt = RecoveryAttempt {
                    strategy: pending.strategy,
                    strategy_fingerprint: pending.strategy_fingerprint,
                    outcome: recovery_terminal_outcome(&epoch_output.terminal_status),
                };
                self.append(
                    task_id,
                    TaskEvent::RecoveryAttemptRecorded {
                        epoch_id,
                        strategy: attempt.strategy,
                        strategy_fingerprint: attempt.strategy_fingerprint.clone(),
                        outcome: attempt.outcome,
                    },
                )?;
                runtime.recovery_attempts.push(attempt);
            }

            let checkpoint_id = CheckpointId::new();
            let tentative = self.build_checkpoint(
                task_id,
                runtime,
                checkpoint_id,
                &report,
                report_next_objective(&report, runtime),
            )?;
            let preliminary_decision =
                decide_completion(&report, &tentative, &runtime.operation_evidence)
                    .map_err(|_| error(TaskEngineErrorCode::Verification))?;
            self.apply_clause_evidence(task_id, &report, &tentative)?;
            let checkpointing = self.append(
                task_id,
                TaskEvent::StateTransitioned {
                    from: TaskStatus::Active,
                    to: TaskStatus::Checkpointing,
                    reason: "safe epoch boundary reached".to_owned(),
                },
            )?;
            self.updates.push(TaskEngineUpdate::TaskStatus {
                task_id,
                status: checkpointing.snapshot.status,
            });

            let mut checkpoint = self.build_checkpoint(
                task_id,
                runtime,
                checkpoint_id,
                &report,
                report_next_objective(&report, runtime),
            )?;
            let assessment = assess_progress_with_recovery_attempts(
                &checkpoint,
                &report,
                &runtime.progress,
                &runtime.recovery_attempts,
            )
            .map_err(|_| error(TaskEngineErrorCode::Verification))?;
            self.append(
                task_id,
                TaskEvent::ProgressAssessed {
                    fingerprint: assessment.fingerprint.clone(),
                    stalled: !assessment.new_information,
                },
            )?;
            checkpoint = self.build_checkpoint(
                task_id,
                runtime,
                checkpoint_id,
                &report,
                report_next_objective(&report, runtime),
            )?;
            let context_package = context_engine(runtime)?
                .assemble(ContextInput {
                    runtime_instructions: runtime_instructions().to_owned(),
                    owner_instructions: runtime.request.clone(),
                    project_instructions:
                        "Use the trusted project instructions present in the workspace.".to_owned(),
                    contract: checkpoint.contract.clone(),
                    checkpoint: checkpoint.clone(),
                    recent_tail: Vec::new(),
                    retrieved_evidence: Vec::new(),
                    epoch_objective: checkpoint.next_objective.clone(),
                })
                .map_err(|_| error(TaskEngineErrorCode::Context))?;
            let checkpoint_digest = checkpoint
                .digest()
                .map_err(|_| error(TaskEngineErrorCode::Context))?;
            let context_package_digest = context_package
                .digest()
                .map_err(|_| error(TaskEngineErrorCode::Context))?;
            let expected_revision = self.current_revision(task_id)?;
            self.store_mut()
                .commit_checkpoint(
                    NewCheckpoint {
                        task_id,
                        checkpoint: checkpoint.clone(),
                        checkpoint_digest: checkpoint_digest.clone(),
                        context_package: context_package.clone(),
                        context_package_digest,
                        created_at: Utc::now(),
                    },
                    expected_revision,
                )
                .map_err(storage_error)?
                .ok_or_else(|| error(TaskEngineErrorCode::Storage))?;
            self.updates.push(TaskEngineUpdate::CheckpointCommitted {
                task_id,
                checkpoint_id,
                digest: checkpoint_digest,
            });
            self.updates.push(TaskEngineUpdate::CompletionClauses {
                task_id,
                clauses: checkpoint.contract.clauses.clone(),
            });
            runtime.previous_checkpoint = Some(checkpoint.clone());
            runtime.progress.push(assessment.clone());

            self.compact_if_needed(task_id, runtime, &checkpoint, &context_package)
                .await?;

            match preliminary_decision {
                CompletionDecision::Complete => {
                    self.append(
                        task_id,
                        TaskEvent::StateTransitioned {
                            from: TaskStatus::Checkpointing,
                            to: TaskStatus::Active,
                            reason: "checkpoint committed".to_owned(),
                        },
                    )?;
                    self.append(
                        task_id,
                        TaskEvent::StateTransitioned {
                            from: TaskStatus::Active,
                            to: TaskStatus::Completing,
                            reason: "every required clause has durable evidence".to_owned(),
                        },
                    )?;
                    let completed = self.append(task_id, TaskEvent::Completed)?;
                    self.updates.push(TaskEngineUpdate::TaskStatus {
                        task_id,
                        status: completed.snapshot.status,
                    });
                    return Ok(completed.snapshot);
                }
                CompletionDecision::Blocked { reason } => {
                    let blocked = self.append(task_id, TaskEvent::Blocked { reason })?;
                    self.updates.push(TaskEngineUpdate::TaskStatus {
                        task_id,
                        status: blocked.snapshot.status,
                    });
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
                CompletionDecision::Continue { next_objective } => {
                    if assessment.recovery == Some(RecoveryStrategy::DeclareBlocked) {
                        let blocked = self.append(
                            task_id,
                            TaskEvent::Blocked {
                                reason: "three materially distinct recovery attempts failed"
                                    .to_owned(),
                            },
                        )?;
                        self.updates.push(TaskEngineUpdate::TaskStatus {
                            task_id,
                            status: blocked.snapshot.status,
                        });
                        return Err(error(TaskEngineErrorCode::Blocked));
                    }
                    runtime.next_objective = next_objective;
                    if let Some(strategy) = assessment.recovery {
                        self.updates
                            .push(TaskEngineUpdate::RecoveryStrategy { task_id, strategy });
                        let recovery_epoch_id = EpochId::new();
                        let strategy_fingerprint =
                            recovery_attempt_fingerprint(&assessment.fingerprint, strategy);
                        self.append(
                            task_id,
                            TaskEvent::RecoveryAttemptStarted {
                                epoch_id: recovery_epoch_id,
                                strategy,
                                strategy_fingerprint: strategy_fingerprint.clone(),
                            },
                        )?;
                        runtime.pending_recovery = Some(PendingRecovery {
                            epoch_id: recovery_epoch_id,
                            strategy,
                            strategy_fingerprint,
                        });
                    }
                    let active = self.append(
                        task_id,
                        TaskEvent::StateTransitioned {
                            from: TaskStatus::Checkpointing,
                            to: TaskStatus::Active,
                            reason: "checkpoint committed; continuing autonomously".to_owned(),
                        },
                    )?;
                    self.updates.push(TaskEngineUpdate::TaskStatus {
                        task_id,
                        status: active.snapshot.status,
                    });
                }
            }
        }
    }

    async fn start_provider_epoch(
        &mut self,
        task_id: TaskId,
        epoch_id: EpochId,
        purpose: ProviderRequestPurpose,
        runtime: &mut RuntimeTask,
        request: StartAgentEpoch,
    ) -> Result<AgentEpochId, TaskEngineError> {
        let record = self
            .store()
            .get_task(task_id)
            .map_err(storage_error)?
            .ok_or_else(invalid_task)?;
        if let Some(reason) = provider_dispatch_budget_reason(&record, runtime) {
            self.append(
                task_id,
                TaskEvent::EpochFinished {
                    epoch_id,
                    report_digest: sha256(reason.as_bytes()),
                },
            )?;
            self.block_task(task_id, reason)?;
            return Err(error(TaskEngineErrorCode::Blocked));
        }
        self.account_estimated_tokens(runtime, request.input.len())?;
        self.append(
            task_id,
            TaskEvent::ProviderRequestRecorded {
                epoch_id,
                purpose,
                request_sequence: runtime.provider_requests,
                request_digest: sha256(request.input.as_bytes()),
            },
        )?;
        runtime.provider_requests = runtime
            .provider_requests
            .checked_add(1)
            .ok_or_else(invalid_task)?;
        match self.port.start_epoch(request).await {
            Ok(provider_epoch_id) => {
                self.append(
                    task_id,
                    TaskEvent::ProviderEpochBound {
                        epoch_id,
                        provider_epoch_id: provider_epoch_id.as_str().to_owned(),
                    },
                )?;
                Ok(provider_epoch_id)
            }
            Err(port_error)
                if port_error.provenance() == AgentErrorProvenance::DefinitelyNotApplied =>
            {
                self.append(
                    task_id,
                    TaskEvent::EpochFinished {
                        epoch_id,
                        report_digest: sha256(b"provider-epoch-definitely-not-applied"),
                    },
                )?;
                if runtime
                    .pending_recovery
                    .as_ref()
                    .is_some_and(|pending| pending.epoch_id == epoch_id)
                {
                    self.record_pending_recovery_failure(task_id, epoch_id, runtime)?;
                    self.block_task(task_id, "recovery provider epoch did not start")?;
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
                if purpose == ProviderRequestPurpose::ContractPlanning {
                    self.block_task(task_id, "planning provider epoch did not start")?;
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
                Err(provider_error(port_error))
            }
            Err(_) => {
                self.append(
                    task_id,
                    TaskEvent::EpochFinished {
                        epoch_id,
                        report_digest: sha256(b"provider-epoch-dispatch-uncertain"),
                    },
                )?;
                if runtime
                    .pending_recovery
                    .as_ref()
                    .is_some_and(|pending| pending.epoch_id == epoch_id)
                {
                    self.record_pending_recovery_failure(task_id, epoch_id, runtime)?;
                }
                self.block_task(task_id, "provider epoch dispatch is uncertain")?;
                Err(error(TaskEngineErrorCode::Blocked))
            }
        }
    }

    fn record_pending_recovery_failure(
        &mut self,
        task_id: TaskId,
        epoch_id: EpochId,
        runtime: &mut RuntimeTask,
    ) -> Result<(), TaskEngineError> {
        let pending = runtime.pending_recovery.take().ok_or_else(invalid_task)?;
        if pending.epoch_id != epoch_id {
            runtime.pending_recovery = Some(pending);
            return Err(invalid_task());
        }
        let attempt = RecoveryAttempt {
            strategy: pending.strategy,
            strategy_fingerprint: pending.strategy_fingerprint,
            outcome: RecoveryAttemptOutcome::Failed,
        };
        self.append(
            task_id,
            TaskEvent::RecoveryAttemptRecorded {
                epoch_id,
                strategy: attempt.strategy,
                strategy_fingerprint: attempt.strategy_fingerprint.clone(),
                outcome: attempt.outcome,
            },
        )?;
        runtime.recovery_attempts.push(attempt);
        Ok(())
    }

    fn account_estimated_tokens(
        &self,
        runtime: &mut RuntimeTask,
        byte_count: usize,
    ) -> Result<(), TaskEngineError> {
        let byte_count = u64::try_from(byte_count).map_err(|_| invalid_task())?;
        let (estimated, actual) = context_engine(runtime)?
            .account_tokens(byte_count, None)
            .map_err(|_| error(TaskEngineErrorCode::Context))?;
        debug_assert!(!actual);
        runtime.estimated_tokens_since_usage = runtime
            .estimated_tokens_since_usage
            .checked_add(estimated)
            .ok_or_else(invalid_task)?;
        Ok(())
    }

    fn record_usage(
        &mut self,
        task_id: TaskId,
        epoch_id: EpochId,
        runtime: &mut RuntimeTask,
        usage: AgentUsage,
    ) -> Result<(), TaskEngineError> {
        runtime.observed_total_tokens = Some(usage.total_tokens);
        runtime.estimated_tokens_since_usage = 0;
        if usage.model_context_window.is_some() {
            runtime.observed_context_window = usage.model_context_window;
        }
        self.append(
            task_id,
            TaskEvent::UsageObserved {
                epoch_id,
                total_tokens: usage.total_tokens,
                context_window: usage.model_context_window,
            },
        )?;
        self.updates.push(TaskEngineUpdate::ContextUsage {
            task_id,
            total_tokens: usage.total_tokens,
            context_window: usage.model_context_window,
        });
        Ok(())
    }

    fn record_estimated_usage(
        &mut self,
        task_id: TaskId,
        epoch_id: EpochId,
        runtime: &mut RuntimeTask,
    ) -> Result<(), TaskEngineError> {
        let total_tokens = runtime
            .observed_total_tokens
            .unwrap_or(0)
            .checked_add(runtime.estimated_tokens_since_usage)
            .ok_or_else(invalid_task)?;
        runtime.observed_total_tokens = Some(total_tokens);
        runtime.estimated_tokens_since_usage = 0;
        self.append(
            task_id,
            TaskEvent::UsageObserved {
                epoch_id,
                total_tokens,
                context_window: runtime.observed_context_window,
            },
        )?;
        self.updates.push(TaskEngineUpdate::ContextUsage {
            task_id,
            total_tokens,
            context_window: runtime.observed_context_window,
        });
        Ok(())
    }

    fn block_task(&mut self, task_id: TaskId, reason: &str) -> Result<(), TaskEngineError> {
        let blocked = self.append(
            task_id,
            TaskEvent::Blocked {
                reason: reason.to_owned(),
            },
        )?;
        self.updates.push(TaskEngineUpdate::TaskStatus {
            task_id,
            status: blocked.snapshot.status,
        });
        Ok(())
    }

    fn assemble_epoch_context(
        &self,
        task_id: TaskId,
        runtime: &mut RuntimeTask,
        objective: &str,
    ) -> Result<String, TaskEngineError> {
        let report = EpochReport {
            schema_version: 1,
            disposition: super::EpochDisposition::Continue,
            summary: "Epoch has not run yet".to_owned(),
            next_objective: Some(objective.to_owned()),
            clause_evidence: Vec::new(),
            exact_identifiers: Vec::new(),
        };
        let provisional =
            self.build_checkpoint(task_id, runtime, CheckpointId::new(), &report, objective)?;
        let package = context_engine(runtime)?
            .assemble(ContextInput {
                runtime_instructions: runtime_instructions().to_owned(),
                owner_instructions: runtime.request.clone(),
                project_instructions:
                    "Use the trusted project instructions present in the workspace.".to_owned(),
                contract: provisional.contract.clone(),
                checkpoint: provisional,
                recent_tail: Vec::new(),
                retrieved_evidence: Vec::new(),
                epoch_objective: objective.to_owned(),
            })
            .map_err(|_| error(TaskEngineErrorCode::Context))?;
        Ok(package.rendered)
    }

    async fn drain_work_epoch(
        &mut self,
        task_id: TaskId,
        epoch_id: EpochId,
        provider_epoch_id: &AgentEpochId,
        runtime: &mut RuntimeTask,
    ) -> Result<WorkEpochOutput, TaskEngineError> {
        let mut output = String::new();
        let mut items = HashMap::<String, AgentItem>::new();
        let mut operations = HashMap::<String, ActiveOperation>::new();
        let mut boundary_requested = false;
        let mut usage_observed = false;
        let mut definitely_not_applied_read_retries = 0_u8;
        let mut provider_events = 0_usize;
        let mut diff_bytes = 0_usize;
        let epoch_tool_start = runtime.completed_tools;
        let record = self
            .store()
            .get_task(task_id)
            .map_err(storage_error)?
            .ok_or_else(invalid_task)?;
        let hard_wall_remaining = remaining_wall_budget(&record);
        let hard_wall_enabled = hard_wall_remaining.is_some();
        let hard_wall_timer = tokio::time::sleep(hard_wall_remaining.unwrap_or_default());
        tokio::pin!(hard_wall_timer);
        let timer = tokio::time::sleep(Duration::from_secs(
            record.snapshot.budget.soft_epoch_seconds,
        ));
        tokio::pin!(timer);
        loop {
            enum Next {
                Provider(Result<AgentEvent, AgentPortError>),
                Boundary,
                HardBudget,
                Control(Option<TaskEngineControl>),
            }
            let controls_enabled = self.controls.is_some();
            let next = {
                let port = &mut self.port;
                let controls = &mut self.controls;
                tokio::select! {
                    event = port.next_event() => Next::Provider(event),
                    () = &mut timer, if !boundary_requested => Next::Boundary,
                    () = &mut hard_wall_timer, if hard_wall_enabled => Next::HardBudget,
                    control = receive_control(controls), if controls_enabled => Next::Control(control),
                }
            };
            match next {
                Next::Provider(event) => {
                    let event = match event {
                        Ok(event) => event,
                        Err(port_error)
                            if port_error.provenance()
                                == AgentErrorProvenance::DefinitelyNotApplied
                                && definitely_not_applied_read_retries == 0 =>
                        {
                            definitely_not_applied_read_retries = 1;
                            continue;
                        }
                        Err(_) => {
                            self.interrupt_and_block_epoch(
                                task_id,
                                epoch_id,
                                runtime,
                                provider_epoch_id,
                                &operations,
                                "provider event delivery failed with an ambiguous operation outcome",
                            )
                            .await?;
                            return Err(error(TaskEngineErrorCode::Blocked));
                        }
                    };
                    definitely_not_applied_read_retries = 0;
                    if event.validate().is_err() {
                        self.interrupt_and_block_epoch(
                            task_id,
                            epoch_id,
                            runtime,
                            provider_epoch_id,
                            &operations,
                            "provider event validation failed after operation binding",
                        )
                        .await?;
                        return Err(error(TaskEngineErrorCode::Blocked));
                    }
                    provider_events = provider_events.saturating_add(1);
                    let transcript_exceeded = match &event {
                        AgentEvent::AssistantDelta { text, .. } => output
                            .len()
                            .checked_add(text.len())
                            .is_none_or(|size| size > MAX_EPOCH_TRANSCRIPT_BYTES),
                        _ => false,
                    };
                    let next_diff_bytes = match &event {
                        AgentEvent::DiffUpdated { diff, .. } => diff_bytes.checked_add(diff.len()),
                        _ => Some(diff_bytes),
                    };
                    let event_update_bytes = match &event {
                        AgentEvent::AssistantDelta { text, .. } => text.len().saturating_add(128),
                        AgentEvent::DiffUpdated { diff, .. } => diff.len().saturating_add(128),
                        AgentEvent::ItemStarted { item, .. }
                        | AgentEvent::ItemCompleted { item, .. }
                            if engine_tool_kind(item).is_some() =>
                        {
                            item.item_id().len().saturating_add(128)
                        }
                        _ => 0,
                    };
                    let stream_bound_reason = if provider_events > MAX_EPOCH_PROVIDER_EVENTS {
                        Some("maximum provider events exhausted during work epoch")
                    } else if transcript_exceeded {
                        Some("aggregate work transcript exceeded its bound")
                    } else if next_diff_bytes.is_none_or(|size| size > MAX_EPOCH_DIFF_BYTES) {
                        Some("aggregate diff stream exceeded its bound")
                    } else if !self.can_accumulate_update(event_update_bytes) {
                        Some("accumulated engine updates exceeded their bound")
                    } else {
                        None
                    };
                    if let Some(reason) = stream_bound_reason {
                        self.interrupt_and_block_epoch(
                            task_id,
                            epoch_id,
                            runtime,
                            provider_epoch_id,
                            &operations,
                            reason,
                        )
                        .await?;
                        return Err(error(TaskEngineErrorCode::Blocked));
                    }
                    diff_bytes = next_diff_bytes.expect("diff byte bound was checked");
                    if matches!(&event, AgentEvent::EffectRequested(_))
                        && self
                            .snapshot(task_id)?
                            .budget
                            .max_tool_calls
                            .is_some_and(|maximum| runtime.started_tools >= maximum)
                    {
                        self.interrupt_and_block_epoch(
                            task_id,
                            epoch_id,
                            runtime,
                            provider_epoch_id,
                            &operations,
                            "maximum tool calls exhausted during provider stream",
                        )
                        .await?;
                        return Err(error(TaskEngineErrorCode::Blocked));
                    }
                    let processed = self
                        .process_work_event(
                            task_id,
                            epoch_id,
                            provider_epoch_id,
                            runtime,
                            event,
                            &mut items,
                            &mut operations,
                            &mut output,
                            &mut usage_observed,
                        )
                        .await;
                    let terminal_status = match processed {
                        Ok(terminal_status) => terminal_status,
                        Err(process_error) => {
                            self.interrupt_and_block_epoch(
                                task_id,
                                epoch_id,
                                runtime,
                                provider_epoch_id,
                                &operations,
                                "provider work event sequencing failed",
                            )
                            .await?;
                            let _ = process_error;
                            return Err(error(TaskEngineErrorCode::Blocked));
                        }
                    };
                    if let Some(terminal_status) = terminal_status {
                        if !operations.is_empty() {
                            self.interrupt_and_block_epoch(
                                task_id,
                                epoch_id,
                                runtime,
                                provider_epoch_id,
                                &operations,
                                "provider completed an epoch with operations still active",
                            )
                            .await?;
                            return Err(error(TaskEngineErrorCode::Blocked));
                        }
                        if !usage_observed || runtime.estimated_tokens_since_usage > 0 {
                            self.record_estimated_usage(task_id, epoch_id, runtime)?;
                        }
                        return Ok(WorkEpochOutput {
                            transcript: output,
                            terminal_status,
                        });
                    }
                    if !boundary_requested
                        && runtime.completed_tools.saturating_sub(epoch_tool_start)
                            >= u64::from(self.snapshot(task_id)?.budget.soft_epoch_tool_calls)
                    {
                        boundary_requested = true;
                        if self
                            .request_safe_boundary(task_id, runtime, provider_epoch_id)
                            .await
                            .is_err()
                        {
                            self.interrupt_and_block_epoch(
                                task_id,
                                epoch_id,
                                runtime,
                                provider_epoch_id,
                                &operations,
                                "provider rejected the soft epoch boundary request",
                            )
                            .await?;
                            return Err(error(TaskEngineErrorCode::Blocked));
                        }
                    }
                }
                Next::Boundary => {
                    boundary_requested = true;
                    if self
                        .request_safe_boundary(task_id, runtime, provider_epoch_id)
                        .await
                        .is_err()
                    {
                        self.interrupt_and_block_epoch(
                            task_id,
                            epoch_id,
                            runtime,
                            provider_epoch_id,
                            &operations,
                            "provider rejected the soft epoch boundary request",
                        )
                        .await?;
                        return Err(error(TaskEngineErrorCode::Blocked));
                    }
                }
                Next::HardBudget => {
                    self.interrupt_and_block_epoch(
                        task_id,
                        epoch_id,
                        runtime,
                        provider_epoch_id,
                        &operations,
                        "maximum task wall time exhausted during provider stream",
                    )
                    .await?;
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
                Next::Control(Some(control)) => {
                    let acknowledgement = match &control {
                        TaskEngineControl::Steer {
                            acknowledgement, ..
                        }
                        | TaskEngineControl::Cancel {
                            acknowledgement, ..
                        }
                        | TaskEngineControl::Approval {
                            acknowledgement, ..
                        } => *acknowledgement,
                    };
                    let result = self
                        .apply_control(
                            task_id,
                            epoch_id,
                            runtime,
                            provider_epoch_id,
                            &operations
                                .values()
                                .map(|operation| operation.operation_id)
                                .collect::<Vec<_>>(),
                            control,
                        )
                        .await;
                    self.acknowledge(acknowledgement, result.clone()).await;
                    if let Err(control_error) = result {
                        if control_error.code() == TaskEngineErrorCode::Cancelled {
                            return Err(control_error);
                        }
                        self.interrupt_and_block_epoch(
                            task_id,
                            epoch_id,
                            runtime,
                            provider_epoch_id,
                            &operations,
                            "provider work control failed",
                        )
                        .await?;
                        return Err(error(TaskEngineErrorCode::Blocked));
                    }
                }
                Next::Control(None) => {
                    self.controls = None;
                    self.acknowledgements = None;
                    self.interrupt_and_block_epoch(
                        task_id,
                        epoch_id,
                        runtime,
                        provider_epoch_id,
                        &operations,
                        "provider work control channel closed",
                    )
                    .await?;
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
            }
        }
    }

    async fn interrupt_and_block_epoch(
        &mut self,
        task_id: TaskId,
        epoch_id: EpochId,
        runtime: &RuntimeTask,
        provider_epoch_id: &AgentEpochId,
        operations: &HashMap<String, ActiveOperation>,
        reason: &str,
    ) -> Result<(), TaskEngineError> {
        if self.snapshot(task_id)?.active_epoch != Some(epoch_id) {
            if self.snapshot(task_id)?.status != TaskStatus::Blocked {
                self.block_task(task_id, reason)?;
            }
            return Ok(());
        }
        let _ = self
            .port
            .interrupt(&runtime.context_id, provider_epoch_id)
            .await;
        let snapshot = self.snapshot(task_id)?;
        for operation in operations.values() {
            if snapshot.operation_status(operation.operation_id) == Some(OperationStatus::Started) {
                self.close_operation_with_evidence(
                    task_id,
                    operation.operation_id,
                    OperationStatus::Uncertain,
                    reason,
                )?;
            }
        }
        if self.snapshot(task_id)?.active_epoch == Some(epoch_id) {
            self.append(
                task_id,
                TaskEvent::EpochFinished {
                    epoch_id,
                    report_digest: sha256(reason.as_bytes()),
                },
            )?;
        }
        if self.snapshot(task_id)?.status != TaskStatus::Blocked {
            self.block_task(task_id, reason)
        } else {
            Ok(())
        }
    }

    async fn apply_control(
        &mut self,
        task_id: TaskId,
        logical_epoch_id: EpochId,
        runtime: &mut RuntimeTask,
        provider_epoch_id: &AgentEpochId,
        active_operation_ids: &[OperationId],
        control: TaskEngineControl,
    ) -> Result<(), TaskEngineError> {
        match control {
            TaskEngineControl::Steer {
                text,
                session_id,
                turn_id,
                ..
            } => {
                validate_steering(&text)?;
                self.store_mut()
                    .append(
                        session_id,
                        Some(turn_id),
                        crate::events::Event::UserInput { text: text.clone() },
                    )
                    .map_err(storage_error)?;
                let steering_sequence = runtime.steering_sequence;
                runtime.steering_sequence = runtime
                    .steering_sequence
                    .checked_add(1)
                    .ok_or_else(invalid_task)?;
                self.append(
                    task_id,
                    TaskEvent::SteeringQueued {
                        steering_sequence,
                        text_digest: sha256(text.as_bytes()),
                    },
                )?;
                self.port
                    .steer(&runtime.context_id, provider_epoch_id, text)
                    .await
                    .map_err(provider_error)
            }
            TaskEngineControl::Cancel {
                session_id,
                turn_id,
                ..
            } => {
                self.cancel_active_epoch(
                    task_id,
                    Some(logical_epoch_id),
                    Some(&runtime.context_id),
                    Some(provider_epoch_id),
                    active_operation_ids,
                    Some((session_id, turn_id)),
                )
                .await
            }
            TaskEngineControl::Approval { .. } => Err(error(TaskEngineErrorCode::Blocked)),
        }
    }

    async fn cancel_active_epoch(
        &mut self,
        task_id: TaskId,
        logical_epoch_id: Option<EpochId>,
        context_id: Option<&AgentContextId>,
        provider_epoch_id: Option<&AgentEpochId>,
        active_operation_ids: &[OperationId],
        turn: Option<(SessionId, TurnId)>,
    ) -> Result<(), TaskEngineError> {
        let cancelling = self.append(task_id, TaskEvent::CancellationRequested)?;
        if logical_epoch_id.is_some() {
            let interrupt_result = match (context_id, provider_epoch_id) {
                (Some(context_id), Some(provider_epoch_id)) => {
                    self.port.interrupt(context_id, provider_epoch_id).await
                }
                _ => Err(AgentPortError::from_code(AgentPortErrorCode::Transport)),
            };
            if interrupt_result.is_err() {
                if active_operation_ids.is_empty() {
                    self.block_task(task_id, "provider interruption could not be confirmed")?;
                } else {
                    self.block_uncertain_operation_ids(
                        task_id,
                        active_operation_ids,
                        "provider interruption failed with operations in flight",
                    )?;
                }
                if let Some(epoch_id) = logical_epoch_id {
                    self.finish_epoch_if_active(
                        task_id,
                        epoch_id,
                        "provider-interruption-unconfirmed",
                    )?;
                }
                self.record_turn_interrupted(turn, "cancellation blocked")?;
                return Err(error(TaskEngineErrorCode::Blocked));
            }
        }

        if !active_operation_ids.is_empty() {
            self.block_uncertain_operation_ids(
                task_id,
                active_operation_ids,
                "provider was interrupted with operations in flight",
            )?;
            if let Some(epoch_id) = logical_epoch_id {
                self.finish_epoch_if_active(
                    task_id,
                    epoch_id,
                    "cancelled-with-uncertain-operations",
                )?;
            }
            self.record_turn_interrupted(turn, "cancelled with uncertain operations")?;
            return Err(error(TaskEngineErrorCode::Blocked));
        }

        if let Some(epoch_id) = logical_epoch_id {
            self.append(
                task_id,
                TaskEvent::EpochFinished {
                    epoch_id,
                    report_digest: sha256(b"cancelled-at-safe-boundary"),
                },
            )?;
        }
        let cancelled = self.append(
            task_id,
            TaskEvent::StateTransitioned {
                from: cancelling.snapshot.status,
                to: TaskStatus::Cancelled,
                reason: "owner cancellation completed at a safe boundary".to_owned(),
            },
        )?;
        self.record_turn_interrupted(turn, "cancelled")?;
        self.updates.push(TaskEngineUpdate::TaskStatus {
            task_id,
            status: cancelled.snapshot.status,
        });
        Err(error(TaskEngineErrorCode::Cancelled))
    }

    fn finish_epoch_if_active(
        &mut self,
        task_id: TaskId,
        epoch_id: EpochId,
        reason: &str,
    ) -> Result<(), TaskEngineError> {
        if self.snapshot(task_id)?.active_epoch == Some(epoch_id) {
            self.append(
                task_id,
                TaskEvent::EpochFinished {
                    epoch_id,
                    report_digest: sha256(reason.as_bytes()),
                },
            )?;
        }
        Ok(())
    }

    fn record_turn_interrupted(
        &mut self,
        turn: Option<(SessionId, TurnId)>,
        reason: &str,
    ) -> Result<(), TaskEngineError> {
        let Some((session_id, turn_id)) = turn else {
            return Ok(());
        };
        self.store_mut()
            .append(
                session_id,
                Some(turn_id),
                crate::events::Event::TurnInterrupted {
                    reason: reason.to_owned(),
                },
            )
            .map_err(storage_error)?;
        Ok(())
    }

    async fn acknowledge(&mut self, acknowledgement: u64, result: Result<(), TaskEngineError>) {
        if let Some(sender) = &self.acknowledgements {
            let _ = sender.send((acknowledgement, result)).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_work_event(
        &mut self,
        task_id: TaskId,
        epoch_id: EpochId,
        provider_epoch_id: &AgentEpochId,
        runtime: &mut RuntimeTask,
        event: AgentEvent,
        items: &mut HashMap<String, AgentItem>,
        operations: &mut HashMap<String, ActiveOperation>,
        output: &mut String,
        usage_observed: &mut bool,
    ) -> Result<Option<String>, TaskEngineError> {
        match event {
            AgentEvent::ContextStarted { .. } => {}
            AgentEvent::EpochStarted {
                context_id,
                epoch_id,
            } if context_id == runtime.context_id && epoch_id == *provider_epoch_id => {}
            AgentEvent::ItemStarted {
                context_id,
                epoch_id: observed_epoch,
                item,
            } if context_id == runtime.context_id && observed_epoch == *provider_epoch_id => {
                let item_id = item.item_id().to_owned();
                if items.insert(item_id.clone(), item.clone()).is_some() {
                    return Err(error(TaskEngineErrorCode::Provider));
                }
                if let Some(kind) = engine_tool_kind(&item) {
                    self.updates.push(TaskEngineUpdate::ToolStarted {
                        title: item_id,
                        kind,
                    });
                }
            }
            AgentEvent::EffectRequested(request)
                if request.context_id == runtime.context_id
                    && request.epoch_id == *provider_epoch_id =>
            {
                let item = items
                    .get(&request.item_id)
                    .cloned()
                    .ok_or_else(|| error(TaskEngineErrorCode::Provider))?;
                if operations.contains_key(&request.item_id) {
                    return Err(error(TaskEngineErrorCode::Provider));
                }
                let operation_id = OperationId::new();
                self.append(
                    task_id,
                    TaskEvent::OperationIntentRecorded {
                        operation_id,
                        epoch_id,
                        item_id: request.item_id.clone(),
                        effect_class: classify_effect(&request, &item),
                        request_digest: request.request_digest.to_string(),
                    },
                )?;
                self.append(
                    task_id,
                    TaskEvent::OperationTransitioned {
                        operation_id,
                        from: OperationStatus::IntentRecorded,
                        to: OperationStatus::Started,
                        evidence_sequences: Vec::new(),
                    },
                )?;
                runtime.started_tools = runtime
                    .started_tools
                    .checked_add(1)
                    .ok_or_else(invalid_task)?;
                let frontend_tool_call_id =
                    self.frontend_context.as_ref().map(|_| ToolCallId::new());
                operations.insert(
                    request.item_id.clone(),
                    ActiveOperation {
                        operation_id,
                        item,
                        frontend_tool_call_id,
                    },
                );
                if let Err(port_error) = self
                    .port
                    .steer(
                        &runtime.context_id,
                        provider_epoch_id,
                        format!("carl-operation-id: {operation_id}"),
                    )
                    .await
                {
                    let status = match port_error.provenance() {
                        AgentErrorProvenance::DefinitelyNotApplied => OperationStatus::Failed,
                        AgentErrorProvenance::PossiblyApplied => OperationStatus::Uncertain,
                    };
                    self.close_operation_with_evidence(
                        task_id,
                        operation_id,
                        status,
                        "provider operation binding failed",
                    )?;
                    self.block_task(task_id, "provider operation binding failed")?;
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
                self.resolve_effect(
                    task_id,
                    epoch_id,
                    runtime,
                    request,
                    operation_id,
                    frontend_tool_call_id,
                )
                .await?;
            }
            AgentEvent::ItemCompleted {
                context_id,
                epoch_id: observed_epoch,
                item,
            } if context_id == runtime.context_id && observed_epoch == *provider_epoch_id => {
                let item_id = item.item_id().to_owned();
                let active = operations
                    .remove(&item_id)
                    .ok_or_else(|| error(TaskEngineErrorCode::Provider))?;
                if active.item.item_id() != item.item_id() {
                    return Err(error(TaskEngineErrorCode::Provider));
                }
                let terminal = terminal_status(&item);
                let result_digest = normalized_item_digest(&item)?;
                if let (Some(context), Some(tool_call_id)) =
                    (self.frontend_context.clone(), active.frontend_tool_call_id)
                {
                    self.store_mut()
                        .append(
                            context.session_id,
                            Some(context.turn_id),
                            crate::events::Event::ToolCompleted {
                                tool_call_id,
                                output: serde_json::json!({"status": operation_status_name(terminal)}),
                            },
                        )
                        .map_err(storage_error)?;
                }
                self.append(
                    task_id,
                    TaskEvent::NormalizedOperationEvidenceRecorded {
                        operation_id: active.operation_id,
                        evidence: normalize_operation_evidence(&item, terminal)?,
                    },
                )?;
                self.append(
                    task_id,
                    TaskEvent::OperationEvidenceRecorded {
                        operation_id: active.operation_id,
                        result_digest,
                    },
                )?;
                let evidence_sequence = self.last_task_sequence(task_id)?;
                self.append(
                    task_id,
                    TaskEvent::OperationTransitioned {
                        operation_id: active.operation_id,
                        from: OperationStatus::Started,
                        to: terminal,
                        evidence_sequences: vec![evidence_sequence],
                    },
                )?;
                retain_normalized_evidence(runtime, active.operation_id, &item, terminal)?;
                runtime.completed_tools = runtime
                    .completed_tools
                    .checked_add(1)
                    .ok_or_else(invalid_task)?;
                self.updates.push(TaskEngineUpdate::ToolCompleted {
                    title: item_id.clone(),
                    status: engine_tool_status(terminal),
                });
                items.remove(&item_id);
            }
            AgentEvent::AssistantDelta {
                context_id,
                epoch_id,
                text,
            } if context_id == runtime.context_id && epoch_id == *provider_epoch_id => {
                self.account_estimated_tokens(runtime, text.len())?;
                output.push_str(&text);
                self.updates.push(TaskEngineUpdate::AgentMessageChunk(text));
            }
            AgentEvent::DiffUpdated {
                context_id,
                epoch_id,
                diff,
            } if context_id == runtime.context_id && epoch_id == *provider_epoch_id => {
                self.account_estimated_tokens(runtime, diff.len())?;
                self.updates.push(TaskEngineUpdate::DiffUpdated(diff));
            }
            AgentEvent::UsageUpdated {
                context_id,
                epoch_id: observed_epoch,
                usage,
            } if context_id == runtime.context_id && observed_epoch == *provider_epoch_id => {
                *usage_observed = true;
                self.record_usage(task_id, epoch_id, runtime, usage)?;
            }
            AgentEvent::EpochCompleted {
                context_id,
                epoch_id,
                status,
            } if context_id == runtime.context_id && epoch_id == *provider_epoch_id => {
                return Ok(Some(status));
            }
            AgentEvent::ProviderFailed { .. } => {
                return Err(error(TaskEngineErrorCode::Provider));
            }
            AgentEvent::CompactionStarted { context_id, .. }
            | AgentEvent::CompactionCompleted { context_id, .. }
                if context_id == runtime.context_id => {}
            _ => return Err(error(TaskEngineErrorCode::Provider)),
        }
        Ok(None)
    }

    async fn resolve_effect(
        &mut self,
        task_id: TaskId,
        epoch_id: EpochId,
        runtime: &mut RuntimeTask,
        request: AgentEffectRequest,
        operation_id: OperationId,
        frontend_tool_call_id: Option<ToolCallId>,
    ) -> Result<(), TaskEngineError> {
        let supported = matches!(
            request.kind,
            crate::runtime::agent_port::AgentEffectKind::Command
                | crate::runtime::agent_port::AgentEffectKind::FileChange
        );
        let summary_safe = SecretFilter.inspect(request.summary.as_bytes()).is_ok();
        let decision = if !supported || !summary_safe {
            EffectDecision::Deny
        } else {
            match runtime.permission_mode.profile() {
                PermissionProfile::FullAccess => EffectDecision::Allow,
                PermissionProfile::Approval if self.frontend_context.is_some() => {
                    self.await_approval(
                        task_id,
                        epoch_id,
                        runtime,
                        &request,
                        operation_id,
                        frontend_tool_call_id,
                    )
                    .await?
                }
                PermissionProfile::ReadOnly | PermissionProfile::Approval => EffectDecision::Deny,
            }
        };
        if decision == EffectDecision::Allow && self.hard_wall_deadline_reached(task_id)? {
            self.close_operation_with_evidence(
                task_id,
                operation_id,
                OperationStatus::Failed,
                "maximum task wall time exhausted before effect dispatch",
            )?;
            self.block_task(
                task_id,
                "maximum task wall time exhausted before effect dispatch",
            )?;
            return Err(error(TaskEngineErrorCode::Blocked));
        }
        if runtime.permission_mode.profile() == PermissionProfile::FullAccess
            && decision == EffectDecision::Allow
            && let (Some(context), Some(tool_call_id)) =
                (self.frontend_context.clone(), frontend_tool_call_id)
        {
            let tool_name = match request.kind {
                crate::runtime::agent_port::AgentEffectKind::Command => "execute",
                crate::runtime::agent_port::AgentEffectKind::FileChange => "edit",
                crate::runtime::agent_port::AgentEffectKind::Network
                | crate::runtime::agent_port::AgentEffectKind::External => {
                    unreachable!("unsupported effects are denied before automatic dispatch")
                }
            };
            self.store_mut()
                .append(
                    context.session_id,
                    Some(context.turn_id),
                    crate::events::Event::ToolProposed {
                        tool_call_id,
                        tool_name: tool_name.to_owned(),
                        arguments: serde_json::json!({"summary":request.summary}),
                    },
                )
                .map_err(storage_error)?;
            self.store_mut()
                .append(
                    context.session_id,
                    Some(context.turn_id),
                    crate::events::Event::ToolDispatchAuthorized {
                        tool_call_id,
                        request_digest: request.request_digest.to_string(),
                        automatic: true,
                    },
                )
                .map_err(storage_error)?;
        }
        if decision == EffectDecision::Allow && self.hard_wall_deadline_reached(task_id)? {
            self.close_operation_with_evidence(
                task_id,
                operation_id,
                OperationStatus::Failed,
                "maximum task wall time exhausted before allow dispatch",
            )?;
            self.block_task(
                task_id,
                "maximum task wall time exhausted before allow dispatch",
            )?;
            return Err(error(TaskEngineErrorCode::Blocked));
        }
        let record = self
            .store()
            .get_task(task_id)
            .map_err(storage_error)?
            .ok_or_else(invalid_task)?;
        let remaining = remaining_wall_budget(&record);
        enum Resolution {
            Completed(Result<(), AgentPortError>),
            HardBudget,
        }
        let resolution = if let Some(remaining) = remaining {
            tokio::select! {
                result = self.port.resolve_effect(&request.request_id, decision) => {
                    Resolution::Completed(result)
                }
                () = tokio::time::sleep(remaining) => Resolution::HardBudget,
            }
        } else {
            Resolution::Completed(
                self.port
                    .resolve_effect(&request.request_id, decision)
                    .await,
            )
        };
        let port_error = match resolution {
            Resolution::Completed(Ok(())) => None,
            Resolution::Completed(Err(port_error)) => Some(port_error),
            Resolution::HardBudget => {
                self.close_operation_with_evidence(
                    task_id,
                    operation_id,
                    OperationStatus::Uncertain,
                    "maximum task wall time exhausted during effect resolution",
                )?;
                self.block_task(
                    task_id,
                    "maximum task wall time exhausted during effect resolution",
                )?;
                return Err(error(TaskEngineErrorCode::Blocked));
            }
        };
        if let Some(port_error) = port_error {
            let status = match port_error.provenance() {
                AgentErrorProvenance::DefinitelyNotApplied => OperationStatus::Failed,
                AgentErrorProvenance::PossiblyApplied => OperationStatus::Uncertain,
            };
            self.close_operation_with_evidence(
                task_id,
                operation_id,
                status,
                "provider effect resolution failed",
            )?;
            self.block_task(task_id, "provider effect resolution failed")?;
            return Err(error(TaskEngineErrorCode::Blocked));
        }
        if decision == EffectDecision::Deny {
            self.close_operation_with_evidence(
                task_id,
                operation_id,
                OperationStatus::Failed,
                "permission-denied",
            )?;
            self.block_task(task_id, "operation denied by permission policy")?;
            return Err(error(TaskEngineErrorCode::Blocked));
        }
        Ok(())
    }

    fn hard_wall_deadline_reached(&self, task_id: TaskId) -> Result<bool, TaskEngineError> {
        let record = self
            .store()
            .get_task(task_id)
            .map_err(storage_error)?
            .ok_or_else(invalid_task)?;
        Ok(remaining_wall_budget(&record).is_some_and(|remaining| remaining.is_zero()))
    }

    async fn await_approval(
        &mut self,
        task_id: TaskId,
        epoch_id: EpochId,
        runtime: &mut RuntimeTask,
        request: &AgentEffectRequest,
        operation_id: OperationId,
        frontend_tool_call_id: Option<ToolCallId>,
    ) -> Result<EffectDecision, TaskEngineError> {
        let context = self.frontend_context.clone().ok_or_else(invalid_task)?;
        let tool_call_id = frontend_tool_call_id.ok_or_else(invalid_task)?;
        if SecretFilter.inspect(request.summary.as_bytes()).is_err() {
            return Ok(EffectDecision::Deny);
        }
        let tool_name = match request.kind {
            crate::runtime::agent_port::AgentEffectKind::Command => "execute",
            crate::runtime::agent_port::AgentEffectKind::FileChange => "edit",
            crate::runtime::agent_port::AgentEffectKind::Network
            | crate::runtime::agent_port::AgentEffectKind::External => {
                return Ok(EffectDecision::Deny);
            }
        };
        let approval_id = crate::events::ApprovalId::new();
        let now = Utc::now();
        let binding = BoundApprovalBinding::new(
            context.session_id,
            context.turn_id,
            tool_call_id,
            context.actor_id.clone(),
            request.request_digest,
            now,
            now + APPROVAL_LIFETIME,
        )
        .map_err(storage_error)?;
        self.store_mut()
            .append(
                context.session_id,
                Some(context.turn_id),
                crate::events::Event::ToolProposed {
                    tool_call_id,
                    tool_name: tool_name.to_owned(),
                    arguments: serde_json::json!({"summary":request.summary}),
                },
            )
            .map_err(storage_error)?;
        self.store()
            .create_bound_approval(approval_id, binding.clone(), request.summary.clone())
            .map_err(storage_error)?;
        self.store_mut()
            .append(
                context.session_id,
                Some(context.turn_id),
                crate::events::Event::ApprovalRequested {
                    approval_id,
                    tool_call_id,
                    summary: request.summary.clone(),
                },
            )
            .map_err(storage_error)?;
        let provider_request_id =
            ProviderRequestId::try_from(request.request_id.as_str()).map_err(|_| invalid_task())?;
        let display_code = create_task_remote_code(
            self.store(),
            &context,
            approval_id,
            provider_request_id.clone(),
            request.request_digest,
            now,
        )?;
        self.updates.push(TaskEngineUpdate::PermissionRequired {
            request_id: request.request_id.as_str().to_owned(),
            summary: request.summary.clone(),
        });
        if let Some(sender) = self.permission_notices.clone() {
            let notice = TaskEnginePermissionNotice {
                display_code,
                summary: request.summary.clone(),
                request_id: request.request_id.as_str().to_owned(),
            };
            let record = self
                .store()
                .get_task(task_id)
                .map_err(storage_error)?
                .ok_or_else(invalid_task)?;
            let remaining = remaining_wall_budget(&record);
            enum NoticeDelivery {
                Sent(Result<(), mpsc::error::SendError<TaskEnginePermissionNotice>>),
                HardBudget,
            }
            let delivery = if let Some(remaining) = remaining {
                tokio::select! {
                    result = sender.send(notice) => NoticeDelivery::Sent(result),
                    () = tokio::time::sleep(remaining) => NoticeDelivery::HardBudget,
                }
            } else {
                NoticeDelivery::Sent(sender.send(notice).await)
            };
            if !matches!(delivery, NoticeDelivery::Sent(Ok(()))) {
                self.fail_before_effect_dispatch(
                    task_id,
                    operation_id,
                    "approval notice delivery failed or exceeded the task wall deadline",
                )?;
                return Err(error(TaskEngineErrorCode::Blocked));
            }
        }
        loop {
            let record = self
                .store()
                .get_task(task_id)
                .map_err(storage_error)?
                .ok_or_else(invalid_task)?;
            let remaining = remaining_wall_budget(&record);
            enum ApprovalWait {
                Control(Option<TaskEngineControl>),
                HardBudget,
            }
            let wait = if let Some(remaining) = remaining {
                tokio::select! {
                    control = receive_control(&mut self.controls) => {
                        ApprovalWait::Control(control)
                    }
                    () = tokio::time::sleep(remaining) => ApprovalWait::HardBudget,
                }
            } else {
                ApprovalWait::Control(receive_control(&mut self.controls).await)
            };
            let control = match wait {
                ApprovalWait::Control(Some(control)) => control,
                ApprovalWait::Control(None) => {
                    self.fail_before_effect_dispatch(
                        task_id,
                        operation_id,
                        "approval control channel closed before effect dispatch",
                    )?;
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
                ApprovalWait::HardBudget => {
                    self.fail_before_effect_dispatch(
                        task_id,
                        operation_id,
                        "maximum task wall time exhausted while awaiting approval",
                    )?;
                    return Err(error(TaskEngineErrorCode::Blocked));
                }
            };
            let acknowledgement = match &control {
                TaskEngineControl::Steer {
                    acknowledgement, ..
                }
                | TaskEngineControl::Cancel {
                    acknowledgement, ..
                }
                | TaskEngineControl::Approval {
                    acknowledgement, ..
                } => *acknowledgement,
            };
            match control {
                TaskEngineControl::Approval {
                    display_code,
                    decision,
                    session_id,
                    turn_id,
                    ..
                } => {
                    let status = match decision {
                        EffectDecision::Allow => ApprovalStatus::Allowed,
                        EffectDecision::Deny => ApprovalStatus::Denied,
                    };
                    let result = if session_id != context.session_id || turn_id != context.turn_id {
                        Err(invalid_task())
                    } else {
                        self.store_mut()
                            .consume_remote_bound_approval(
                                RemoteCodeClaim {
                                    display_code: &display_code,
                                    kind: RemoteCodeKind::Approval,
                                    external_session_id: context.external_session_id.clone(),
                                    approval_id: Some(approval_id),
                                    provider_request_id: Some(provider_request_id.clone()),
                                    request_digest: request.request_digest,
                                    actor_id: context.actor_id.clone(),
                                    now: Utc::now(),
                                },
                                &binding,
                                status,
                            )
                            .map_err(storage_error)
                            .map(|_| ())
                    };
                    if result.is_ok() {
                        self.store_mut()
                            .append(
                                context.session_id,
                                Some(context.turn_id),
                                crate::events::Event::UserInput {
                                    text: match decision {
                                        EffectDecision::Allow => "/approve <redacted>",
                                        EffectDecision::Deny => "/deny <redacted>",
                                    }
                                    .to_owned(),
                                },
                            )
                            .map_err(storage_error)?;
                    }
                    if result.is_ok()
                        && decision == EffectDecision::Allow
                        && self.hard_wall_deadline_reached(task_id)?
                    {
                        self.fail_before_effect_dispatch(
                            task_id,
                            operation_id,
                            "maximum task wall time exhausted before approved effect dispatch",
                        )?;
                        let blocked = Err(error(TaskEngineErrorCode::Blocked));
                        self.acknowledge(acknowledgement, blocked.clone()).await;
                        blocked?;
                    }
                    self.acknowledge(acknowledgement, result.clone()).await;
                    if let Err(result_error) = result {
                        self.fail_before_effect_dispatch(
                            task_id,
                            operation_id,
                            "approval validation failed before effect dispatch",
                        )?;
                        return Err(result_error);
                    }
                    return Ok(decision);
                }
                TaskEngineControl::Cancel { .. } => {
                    let result = self
                        .apply_control(
                            task_id,
                            epoch_id,
                            runtime,
                            &request.epoch_id,
                            &[operation_id],
                            control,
                        )
                        .await;
                    self.acknowledge(acknowledgement, result.clone()).await;
                    return result.map(|()| EffectDecision::Deny);
                }
                TaskEngineControl::Steer { .. } => {
                    self.acknowledge(acknowledgement, Err(error(TaskEngineErrorCode::Blocked)))
                        .await;
                }
            }
        }
    }

    fn fail_before_effect_dispatch(
        &mut self,
        task_id: TaskId,
        operation_id: OperationId,
        reason: &str,
    ) -> Result<(), TaskEngineError> {
        if self.snapshot(task_id)?.operation_status(operation_id) == Some(OperationStatus::Started)
        {
            self.close_operation_with_evidence(
                task_id,
                operation_id,
                OperationStatus::Failed,
                reason,
            )?;
        }
        if self.snapshot(task_id)?.status != TaskStatus::Blocked {
            self.block_task(task_id, reason)?;
        }
        Ok(())
    }

    fn block_uncertain_operation_ids(
        &mut self,
        task_id: TaskId,
        operation_ids: &[OperationId],
        reason: &str,
    ) -> Result<(), TaskEngineError> {
        for operation_id in operation_ids {
            self.append(
                task_id,
                TaskEvent::OperationEvidenceRecorded {
                    operation_id: *operation_id,
                    result_digest: sha256(reason.as_bytes()),
                },
            )?;
            let evidence_sequence = self.last_task_sequence(task_id)?;
            self.append(
                task_id,
                TaskEvent::OperationTransitioned {
                    operation_id: *operation_id,
                    from: OperationStatus::Started,
                    to: OperationStatus::Uncertain,
                    evidence_sequences: vec![evidence_sequence],
                },
            )?;
        }
        let blocked = self.append(
            task_id,
            TaskEvent::Blocked {
                reason: reason.to_owned(),
            },
        )?;
        self.updates.push(TaskEngineUpdate::TaskStatus {
            task_id,
            status: blocked.snapshot.status,
        });
        Ok(())
    }

    fn close_operation_with_evidence(
        &mut self,
        task_id: TaskId,
        operation_id: OperationId,
        status: OperationStatus,
        reason: &str,
    ) -> Result<(), TaskEngineError> {
        self.append(
            task_id,
            TaskEvent::OperationEvidenceRecorded {
                operation_id,
                result_digest: sha256(reason.as_bytes()),
            },
        )?;
        let evidence_sequence = self.last_task_sequence(task_id)?;
        self.append(
            task_id,
            TaskEvent::OperationTransitioned {
                operation_id,
                from: OperationStatus::Started,
                to: status,
                evidence_sequences: vec![evidence_sequence],
            },
        )?;
        Ok(())
    }

    async fn request_safe_boundary(
        &mut self,
        task_id: TaskId,
        runtime: &mut RuntimeTask,
        provider_epoch_id: &AgentEpochId,
    ) -> Result<(), TaskEngineError> {
        let steering_sequence = runtime.steering_sequence;
        runtime.steering_sequence = runtime
            .steering_sequence
            .checked_add(1)
            .ok_or_else(invalid_task)?;
        self.append(
            task_id,
            TaskEvent::SteeringQueued {
                steering_sequence,
                text_digest: sha256(SAFE_BOUNDARY_MESSAGE.as_bytes()),
            },
        )?;
        match self
            .port
            .steer(
                &runtime.context_id,
                provider_epoch_id,
                SAFE_BOUNDARY_MESSAGE.to_owned(),
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if error.code() == AgentPortErrorCode::Unsupported => self
                .port
                .interrupt(&runtime.context_id, provider_epoch_id)
                .await
                .map_err(provider_error),
            Err(error) => Err(provider_error(error)),
        }
    }

    fn apply_clause_evidence(
        &mut self,
        task_id: TaskId,
        report: &EpochReport,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<(), TaskEngineError> {
        if report.clause_evidence.is_empty() {
            return Ok(());
        }
        let mut contract = checkpoint.contract.clone();
        contract.version = contract.version.checked_add(1).ok_or_else(invalid_task)?;
        for claim in &report.clause_evidence {
            let clause = contract
                .clauses
                .iter_mut()
                .find(|clause| clause.id == claim.clause_id)
                .ok_or_else(|| error(TaskEngineErrorCode::Verification))?;
            for operation_id in &claim.operation_ids {
                let operation = checkpoint
                    .operations
                    .iter()
                    .find(|operation| operation.operation_id == *operation_id)
                    .ok_or_else(|| error(TaskEngineErrorCode::Verification))?;
                let sequences = if claim.event_sequences.is_empty() {
                    operation.evidence_sequences.as_slice()
                } else {
                    claim.event_sequences.as_slice()
                };
                clause
                    .evidence
                    .extend(sequences.iter().map(|sequence| EvidenceRef {
                        event_sequence: *sequence,
                        artifact_digest: None,
                        operation_id: Some(*operation_id),
                    }));
            }
            clause.evidence.sort_by_key(|evidence| {
                (
                    evidence.event_sequence,
                    evidence.artifact_digest.clone(),
                    evidence.operation_id,
                )
            });
            clause.evidence.dedup();
            clause.status = ClauseStatus::Satisfied;
        }
        contract
            .validate()
            .map_err(|_| error(TaskEngineErrorCode::Verification))?;
        self.append(task_id, TaskEvent::ContractRevised { contract })?;
        Ok(())
    }

    fn build_checkpoint(
        &self,
        task_id: TaskId,
        runtime: &RuntimeTask,
        checkpoint_id: CheckpointId,
        report: &EpochReport,
        next_objective: &str,
    ) -> Result<CanonicalCheckpoint, TaskEngineError> {
        let snapshot = self.snapshot(task_id)?;
        let mut events = self
            .store()
            .read_task_events(task_id)
            .map_err(storage_error)?;
        if let Some(previous) = &runtime.previous_checkpoint {
            events.retain(|event| event.sequence > previous.source_sequence_end);
        }
        let exact_identifiers = report
            .exact_identifiers
            .iter()
            .cloned()
            .map(|value| ExactIdentifier {
                kind: "provider_report".to_owned(),
                value,
            })
            .collect();
        let generation = runtime
            .previous_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| {
                checkpoint.compaction_generation.saturating_add(1)
            });
        CanonicalCheckpoint::build(CheckpointBuildInput {
            checkpoint_id,
            snapshot,
            events,
            completed_work: Vec::new(),
            decisions: Vec::new(),
            exact_identifiers,
            required_identifiers: Vec::new(),
            repository: RepositoryCheckpoint {
                workspace_digest: sha256(runtime.workspace.as_os_str().as_encoded_bytes()),
                git_head: None,
                git_status_digest: None,
                diff_artifact_digest: None,
                file_hashes: runtime.file_hashes.clone(),
            },
            running_processes: Vec::<ProcessCheckpoint>::new(),
            pending_approval_digests: Vec::new(),
            pending_steering_digests: runtime
                .steering
                .iter()
                .map(|steering| sha256(steering.as_bytes()))
                .collect(),
            uncertain_delivery_digests: Vec::new(),
            next_objective: next_objective.to_owned(),
            blockers: Vec::new(),
            provider: ProviderCheckpoint {
                provider: "codex".to_owned(),
                model: runtime.model.as_str().to_owned(),
                effort: runtime.effort.as_codex_value().to_owned(),
                context_id: Some(runtime.context_id.as_str().to_owned()),
                observed_total_tokens: runtime.observed_total_tokens,
                observed_context_window: runtime.observed_context_window,
            },
            compaction_generation: generation,
            previous_checkpoint: runtime.previous_checkpoint.clone(),
            artifact_contents: BTreeMap::new(),
            model_narrative: None,
        })
        .map_err(|_| error(TaskEngineErrorCode::Context))
    }

    async fn compact_if_needed(
        &mut self,
        task_id: TaskId,
        runtime: &mut RuntimeTask,
        checkpoint: &CanonicalCheckpoint,
        context_package: &super::ContextPackage,
    ) -> Result<(), TaskEngineError> {
        let Some(total_tokens) = runtime.observed_total_tokens else {
            return Ok(());
        };
        let decision = context_engine(runtime)?.decide(total_tokens);
        if !matches!(
            decision,
            CompactionDecision::Compact | CompactionDecision::ReplaceProviderContext
        ) {
            return Ok(());
        }
        self.append(
            task_id,
            TaskEvent::CompactionRequested {
                generation: checkpoint.compaction_generation,
                reason: "provider context pressure reached the durable threshold".to_owned(),
            },
        )?;
        let old_context = runtime.context_id.clone();
        let recovery = self
            .port
            .compact_or_replace_context(
                ResumeAgentContext {
                    context_id: old_context.clone(),
                    cwd: runtime.workspace.clone(),
                    model: runtime.model.clone(),
                    permission_mode: runtime.permission_mode,
                },
                context_package,
            )
            .await
            .map_err(provider_error)?;
        let replaced_provider = match recovery {
            ContextRecovery::Resumed(context_id) | ContextRecovery::Compacted(context_id) => {
                runtime.context_id = context_id;
                false
            }
            ContextRecovery::Replaced(context_id) => {
                self.append(
                    task_id,
                    TaskEvent::ProviderContextLost {
                        context_id: old_context.as_str().to_owned(),
                        reason: "provider context replaced after compaction threshold".to_owned(),
                    },
                )?;
                self.append(
                    task_id,
                    TaskEvent::ProviderContextBound {
                        context_id: context_id.as_str().to_owned(),
                    },
                )?;
                runtime.context_id = context_id;
                true
            }
        };
        self.append(
            task_id,
            TaskEvent::CompactionCompleted {
                generation: checkpoint.compaction_generation,
                checkpoint_id: checkpoint.checkpoint_id,
                context_package_id: context_package.package_id,
            },
        )?;
        self.updates.push(TaskEngineUpdate::Compaction {
            task_id,
            generation: checkpoint.compaction_generation,
            replaced_provider,
        });
        Ok(())
    }

    fn append(&mut self, task_id: TaskId, event: TaskEvent) -> Result<TaskRecord, TaskEngineError> {
        let revision = self.current_revision(task_id)?;
        self.store_mut()
            .append_task_event(task_id, revision, event, Utc::now())
            .map_err(storage_error)?
            .ok_or_else(|| error(TaskEngineErrorCode::Storage))
    }

    fn current_revision(&self, task_id: TaskId) -> Result<u64, TaskEngineError> {
        self.store()
            .get_task(task_id)
            .map_err(storage_error)?
            .map(|record| record.revision)
            .ok_or_else(invalid_task)
    }

    fn snapshot(&self, task_id: TaskId) -> Result<TaskSnapshot, TaskEngineError> {
        self.store()
            .get_task(task_id)
            .map_err(storage_error)?
            .map(|record| record.snapshot)
            .ok_or_else(invalid_task)
    }

    fn last_task_sequence(&self, task_id: TaskId) -> Result<u64, TaskEngineError> {
        self.store()
            .read_task_events(task_id)
            .map_err(storage_error)?
            .last()
            .map(|event| event.sequence)
            .ok_or_else(invalid_task)
    }

    fn rehydrate_runtime(
        &self,
        task_id: TaskId,
        snapshot: &TaskSnapshot,
    ) -> Result<RuntimeTask, TaskEngineError> {
        let events = self
            .store()
            .read_task_events(task_id)
            .map_err(storage_error)?;
        let mut configuration = None;
        let mut progress = Vec::new();
        let mut recovery_attempts = Vec::new();
        let mut pending_recovery = None;
        let mut operation_evidence = Vec::new();
        let mut steering_sequence = 0_u64;
        let mut completed_tools = 0_u64;
        let mut started_tools = 0_u64;
        let mut provider_requests = 0_u64;
        let mut observed_total_tokens = None;
        let mut observed_context_window = None;
        for envelope in &events {
            let crate::events::Event::TaskLifecycle { event, .. } = &envelope.event else {
                return Err(error(TaskEngineErrorCode::Storage));
            };
            match event {
                TaskEvent::Created {
                    workspace,
                    model,
                    effort,
                    permission_mode,
                    ..
                } => {
                    configuration =
                        Some((workspace.clone(), model.clone(), *effort, *permission_mode));
                }
                TaskEvent::ProviderRequestRecorded { .. } => {
                    provider_requests = provider_requests.saturating_add(1);
                }
                TaskEvent::UsageObserved {
                    total_tokens,
                    context_window,
                    ..
                } => {
                    observed_total_tokens = Some(*total_tokens);
                    if context_window.is_some() {
                        observed_context_window = *context_window;
                    }
                }
                TaskEvent::ProgressAssessed {
                    fingerprint,
                    stalled,
                } => progress.push(ProgressAssessment {
                    fingerprint: fingerprint.clone(),
                    new_information: !stalled,
                    resolved_clause_ids: snapshot
                        .contract
                        .clauses
                        .iter()
                        .filter(|clause| clause.status == ClauseStatus::Satisfied)
                        .map(|clause| clause.id.clone())
                        .collect(),
                    stall_count: u8::from(*stalled),
                    recovery: None,
                }),
                TaskEvent::RecoveryAttemptStarted {
                    epoch_id,
                    strategy,
                    strategy_fingerprint,
                } => {
                    if pending_recovery.is_some() {
                        return Err(error(TaskEngineErrorCode::Storage));
                    }
                    pending_recovery = Some(PendingRecovery {
                        epoch_id: *epoch_id,
                        strategy: *strategy,
                        strategy_fingerprint: strategy_fingerprint.clone(),
                    });
                }
                TaskEvent::RecoveryAttemptRecorded {
                    epoch_id,
                    strategy,
                    strategy_fingerprint,
                    outcome,
                } => {
                    let matching = pending_recovery.as_ref().is_some_and(|pending| {
                        pending.epoch_id == *epoch_id
                            && pending.strategy == *strategy
                            && pending.strategy_fingerprint == *strategy_fingerprint
                    });
                    if !matching {
                        return Err(error(TaskEngineErrorCode::Storage));
                    }
                    pending_recovery = None;
                    recovery_attempts.push(RecoveryAttempt {
                        strategy: *strategy,
                        strategy_fingerprint: strategy_fingerprint.clone(),
                        outcome: *outcome,
                    });
                }
                TaskEvent::NormalizedOperationEvidenceRecorded {
                    operation_id,
                    evidence,
                } => {
                    operation_evidence.push(operation_evidence_from_event(*operation_id, evidence));
                    completed_tools = completed_tools.saturating_add(1);
                }
                TaskEvent::OperationIntentRecorded { .. } => {
                    started_tools = started_tools.saturating_add(1);
                }
                TaskEvent::SteeringQueued {
                    steering_sequence: sequence,
                    ..
                } => {
                    steering_sequence = steering_sequence.max(sequence.saturating_add(1));
                }
                _ => {}
            }
        }
        let (workspace, model, effort, permission_mode) = configuration.ok_or_else(invalid_task)?;
        let previous_checkpoint = self
            .store()
            .get_latest_task_checkpoint(task_id)
            .map_err(storage_error)?;
        let next_objective = previous_checkpoint.as_ref().map_or_else(
            || {
                format!(
                    "Implement and explicitly verify: {}",
                    snapshot.contract.goal
                )
            },
            |checkpoint| checkpoint.next_objective.clone(),
        );
        let file_hashes = previous_checkpoint
            .as_ref()
            .map_or_else(BTreeMap::new, |checkpoint| {
                checkpoint.repository.file_hashes.clone()
            });
        let context_id = snapshot
            .provider_context
            .as_deref()
            .ok_or_else(invalid_task)
            .and_then(|context| AgentContextId::parse(context).map_err(provider_error))?;
        Ok(RuntimeTask {
            workspace,
            request: snapshot.contract.goal.clone(),
            model,
            effort,
            permission_mode,
            context_id,
            next_objective,
            previous_checkpoint,
            progress,
            recovery_attempts,
            pending_recovery,
            steering: VecDeque::new(),
            steering_sequence,
            operation_evidence,
            file_hashes,
            observed_total_tokens,
            observed_context_window,
            estimated_tokens_since_usage: 0,
            completed_tools,
            started_tools,
            provider_requests,
        })
    }
}

fn validate_start(input: &StartTask) -> Result<(), TaskEngineError> {
    if input.request.trim().is_empty()
        || input.request.len() > MAX_REQUEST_BYTES
        || input.request.as_bytes().contains(&0)
        || !input.workspace.is_absolute()
        || !input.workspace.is_dir()
        || input.budget.soft_epoch_seconds == 0
        || input.budget.soft_epoch_tool_calls == 0
    {
        return Err(invalid_task());
    }
    Ok(())
}

async fn receive_control(
    controls: &mut Option<mpsc::Receiver<TaskEngineControl>>,
) -> Option<TaskEngineControl> {
    match controls {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

const fn control_acknowledgement(control: &TaskEngineControl) -> u64 {
    match control {
        TaskEngineControl::Steer {
            acknowledgement, ..
        }
        | TaskEngineControl::Cancel {
            acknowledgement, ..
        }
        | TaskEngineControl::Approval {
            acknowledgement, ..
        } => *acknowledgement,
    }
}

fn create_task_remote_code(
    store: &Store,
    context: &TaskEngineFrontendContext,
    approval_id: crate::events::ApprovalId,
    provider_request_id: ProviderRequestId,
    request_digest: crate::policy::Sha256Digest,
    now: chrono::DateTime<Utc>,
) -> Result<String, TaskEngineError> {
    for _ in 0..16 {
        let display_code = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(10)
            .collect::<String>();
        if store
            .create_remote_code(NewRemoteCode {
                display_code: &display_code,
                kind: RemoteCodeKind::Approval,
                external_session_id: context.external_session_id.clone(),
                approval_id: Some(approval_id),
                provider_request_id: Some(provider_request_id.clone()),
                request_digest,
                actor_id: context.actor_id.clone(),
                created_at: now,
                expires_at: now + APPROVAL_LIFETIME,
            })
            .is_ok()
        {
            return Ok(display_code);
        }
    }
    Err(error(TaskEngineErrorCode::Storage))
}

fn validate_steering(text: &str) -> Result<(), TaskEngineError> {
    if text.trim().is_empty() || text.len() > MAX_REQUEST_BYTES || text.as_bytes().contains(&0) {
        Err(invalid_task())
    } else {
        Ok(())
    }
}

fn parse_contract(output: &str) -> Result<CompletionContract, TaskEngineError> {
    if output.len() > MAX_CONTRACT_OUTPUT_BYTES {
        return Err(error(TaskEngineErrorCode::Verification));
    }
    let start = output
        .find(CONTRACT_OPEN)
        .ok_or_else(|| error(TaskEngineErrorCode::Verification))?;
    let body_start = start + CONTRACT_OPEN.len();
    let relative_end = output[body_start..]
        .find(CONTRACT_CLOSE)
        .ok_or_else(|| error(TaskEngineErrorCode::Verification))?;
    let end = body_start + relative_end;
    if output[..start].contains("carl-completion-contract")
        || output[end + CONTRACT_CLOSE.len()..].contains("carl-completion-contract")
        || !output[end + CONTRACT_CLOSE.len()..].trim().is_empty()
    {
        return Err(error(TaskEngineErrorCode::Verification));
    }
    let mut contract: CompletionContract = serde_json::from_str(&output[body_start..end])
        .map_err(|_| error(TaskEngineErrorCode::Verification))?;
    if contract.clauses.is_empty() {
        return Err(error(TaskEngineErrorCode::Verification));
    }
    contract.version = 1;
    for clause in &mut contract.clauses {
        clause.status = ClauseStatus::Pending;
        clause.evidence.clear();
    }
    contract
        .validate()
        .map_err(|_| error(TaskEngineErrorCode::Verification))?;
    Ok(contract)
}

fn fallback_contract(request: &str) -> CompletionContract {
    CompletionContract {
        version: 1,
        goal: normalized_contract_goal(request),
        constraints: Vec::new(),
        clauses: vec![
            CompletionClause {
                id: "requested-outcome".to_owned(),
                description: "The owner's requested outcome is implemented".to_owned(),
                required: true,
                status: ClauseStatus::Pending,
                evidence: Vec::new(),
            },
            CompletionClause {
                id: "explicit-verification".to_owned(),
                description: "The requested outcome has explicit successful verification"
                    .to_owned(),
                required: true,
                status: ClauseStatus::Pending,
                evidence: Vec::new(),
            },
        ],
    }
}

fn normalized_contract_goal(request: &str) -> String {
    let normalized = request
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let normalized = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        "Complete the owner request".to_owned()
    } else {
        normalized
    }
}

fn report_next_objective<'a>(report: &'a EpochReport, runtime: &'a RuntimeTask) -> &'a str {
    report
        .next_objective
        .as_deref()
        .unwrap_or(runtime.next_objective.as_str())
}

fn recovery_objective(runtime: &RuntimeTask) -> String {
    runtime.pending_recovery.as_ref().map_or_else(
        || runtime.next_objective.clone(),
        |pending| {
            format!(
                "Use recovery strategy {strategy:?}: {}",
                runtime.next_objective,
                strategy = pending.strategy,
            )
        },
    )
}

fn recovery_terminal_outcome(status: &str) -> RecoveryAttemptOutcome {
    if ["completed", "success", "succeeded"]
        .iter()
        .any(|terminal| status.eq_ignore_ascii_case(terminal))
    {
        RecoveryAttemptOutcome::Succeeded
    } else {
        RecoveryAttemptOutcome::Failed
    }
}

fn runtime_instructions() -> &'static str {
    "Advance only the bounded epoch objective. Do not claim completion without tool evidence. End with exactly one <carl-epoch-report> JSON block."
}

fn context_engine(runtime: &RuntimeTask) -> Result<ContextEngine, TaskEngineError> {
    ContextEngine::new(ContextBudget {
        context_window: runtime
            .observed_context_window
            .unwrap_or(DEFAULT_CONTEXT_WINDOW),
        trigger_percent: CONTEXT_TRIGGER_PERCENT,
        target_percent: CONTEXT_TARGET_PERCENT,
    })
    .map_err(|_| error(TaskEngineErrorCode::Context))
}

fn exhausted_budget_reason(record: &TaskRecord, runtime: &RuntimeTask) -> Option<&'static str> {
    let budget = &record.snapshot.budget;
    if budget.max_wall_time_seconds.is_some_and(|maximum| {
        let elapsed = Utc::now().signed_duration_since(record.created_at);
        elapsed.num_seconds() >= i64::try_from(maximum).unwrap_or(i64::MAX)
    }) {
        Some("maximum task wall time exhausted")
    } else if budget
        .max_provider_requests
        .is_some_and(|maximum| runtime.provider_requests >= maximum)
    {
        Some("maximum provider requests exhausted")
    } else if budget
        .max_tool_calls
        .is_some_and(|maximum| runtime.started_tools >= maximum)
    {
        Some("maximum tool calls exhausted")
    } else {
        None
    }
}

fn remaining_wall_budget(record: &TaskRecord) -> Option<Duration> {
    let maximum = record.snapshot.budget.max_wall_time_seconds?;
    let maximum = i64::try_from(maximum).unwrap_or(i64::MAX);
    let deadline = record.created_at + TimeDelta::seconds(maximum);
    deadline
        .signed_duration_since(Utc::now())
        .to_std()
        .ok()
        .or(Some(Duration::ZERO))
}

fn provider_dispatch_budget_reason(
    record: &TaskRecord,
    runtime: &RuntimeTask,
) -> Option<&'static str> {
    let budget = &record.snapshot.budget;
    if budget.max_wall_time_seconds.is_some_and(|maximum| {
        let elapsed = Utc::now().signed_duration_since(record.created_at);
        elapsed.num_seconds() >= i64::try_from(maximum).unwrap_or(i64::MAX)
    }) {
        Some("maximum task wall time exhausted")
    } else if budget
        .max_provider_requests
        .is_some_and(|maximum| runtime.provider_requests >= maximum)
    {
        Some("maximum provider requests exhausted")
    } else {
        None
    }
}

fn retain_normalized_evidence(
    runtime: &mut RuntimeTask,
    operation_id: OperationId,
    item: &AgentItem,
    status: OperationStatus,
) -> Result<(), TaskEngineError> {
    match item {
        AgentItem::Command { exit_code, .. } => {
            runtime.operation_evidence.push(OperationEvidence::Command {
                operation_id,
                completed: status == OperationStatus::Succeeded,
                exit_code: *exit_code,
            });
        }
        AgentItem::FileChange { changes, .. } => {
            let bytes = serde_json::to_vec(changes)
                .map_err(|_| error(TaskEngineErrorCode::Verification))?;
            let artifact_digest = sha256(&bytes);
            let paths = changes
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|change| change.get("path").and_then(Value::as_str))
                .collect::<Vec<_>>();
            if paths.is_empty() {
                runtime.file_hashes.insert(
                    format!("provider-item:{}", item.item_id()),
                    artifact_digest.clone(),
                );
            } else {
                for path in paths {
                    runtime
                        .file_hashes
                        .insert(path.to_owned(), artifact_digest.clone());
                }
            }
            runtime
                .operation_evidence
                .push(OperationEvidence::FileChange {
                    operation_id,
                    completed: status == OperationStatus::Succeeded,
                    artifact_digests: vec![artifact_digest],
                });
        }
        AgentItem::ContextCompaction { .. } | AgentItem::Other { .. } => {}
    }
    Ok(())
}

fn normalize_operation_evidence(
    item: &AgentItem,
    status: OperationStatus,
) -> Result<NormalizedOperationEvidence, TaskEngineError> {
    match item {
        AgentItem::Command { exit_code, .. } => Ok(NormalizedOperationEvidence::Command {
            completed: status == OperationStatus::Succeeded,
            exit_code: *exit_code,
        }),
        AgentItem::FileChange { changes, .. } => {
            let bytes = serde_json::to_vec(changes)
                .map_err(|_| error(TaskEngineErrorCode::Verification))?;
            Ok(NormalizedOperationEvidence::FileChange {
                completed: status == OperationStatus::Succeeded,
                artifact_digests: vec![sha256(&bytes)],
            })
        }
        AgentItem::ContextCompaction { .. } | AgentItem::Other { .. } => {
            Err(error(TaskEngineErrorCode::Verification))
        }
    }
}

fn operation_evidence_from_event(
    operation_id: OperationId,
    evidence: &NormalizedOperationEvidence,
) -> OperationEvidence {
    match evidence {
        NormalizedOperationEvidence::Command {
            completed,
            exit_code,
        } => OperationEvidence::Command {
            operation_id,
            completed: *completed,
            exit_code: *exit_code,
        },
        NormalizedOperationEvidence::FileChange {
            completed,
            artifact_digests,
        } => OperationEvidence::FileChange {
            operation_id,
            completed: *completed,
            artifact_digests: artifact_digests.clone(),
        },
    }
}

fn terminal_status(item: &AgentItem) -> OperationStatus {
    let (status, succeeded) = match item {
        AgentItem::Command {
            status, exit_code, ..
        } => (status.as_str(), *exit_code == Some(0)),
        AgentItem::FileChange { status, .. } => (status.as_str(), true),
        AgentItem::ContextCompaction { .. } | AgentItem::Other { .. } => {
            return OperationStatus::Failed;
        }
    };
    if status.eq_ignore_ascii_case("cancelled") {
        OperationStatus::Cancelled
    } else if succeeded
        && ["completed", "success", "succeeded"]
            .iter()
            .any(|terminal| status.eq_ignore_ascii_case(terminal))
    {
        OperationStatus::Succeeded
    } else {
        OperationStatus::Failed
    }
}

fn engine_tool_kind(item: &AgentItem) -> Option<EngineToolKind> {
    match item {
        AgentItem::Command { .. } => Some(EngineToolKind::Execute),
        AgentItem::FileChange { .. } => Some(EngineToolKind::Edit),
        AgentItem::ContextCompaction { .. } | AgentItem::Other { .. } => None,
    }
}

const fn engine_tool_status(status: OperationStatus) -> EngineToolStatus {
    match status {
        OperationStatus::Succeeded | OperationStatus::Reconciled => EngineToolStatus::Completed,
        OperationStatus::Cancelled => EngineToolStatus::Cancelled,
        OperationStatus::IntentRecorded
        | OperationStatus::Started
        | OperationStatus::Failed
        | OperationStatus::Uncertain => EngineToolStatus::Failed,
    }
}

const fn operation_status_name(status: OperationStatus) -> &'static str {
    match status {
        OperationStatus::Succeeded | OperationStatus::Reconciled => "completed",
        OperationStatus::Cancelled => "cancelled",
        OperationStatus::IntentRecorded
        | OperationStatus::Started
        | OperationStatus::Failed
        | OperationStatus::Uncertain => "failed",
    }
}

fn normalized_item_digest(item: &AgentItem) -> Result<String, TaskEngineError> {
    let bytes = match item {
        AgentItem::Command {
            item_id,
            command,
            cwd,
            status,
            exit_code,
            aggregated_output,
            process_id,
        } => serde_json::to_vec(&(
            "command",
            item_id,
            command,
            cwd,
            status,
            exit_code,
            aggregated_output,
            process_id,
        )),
        AgentItem::FileChange {
            item_id,
            status,
            changes,
        } => serde_json::to_vec(&("file_change", item_id, status, changes)),
        AgentItem::ContextCompaction { item_id } => {
            serde_json::to_vec(&("context_compaction", item_id))
        }
        AgentItem::Other { item_id, item_type } => {
            serde_json::to_vec(&("other", item_id, item_type))
        }
    }
    .map_err(|_| error(TaskEngineErrorCode::Verification))?;
    Ok(sha256(&bytes))
}

fn active_provider_epoch(
    store: &Store,
    task_id: TaskId,
) -> Result<Option<AgentEpochId>, TaskEngineError> {
    let active_epoch = store
        .get_task(task_id)
        .map_err(storage_error)?
        .and_then(|record| record.snapshot.active_epoch);
    let Some(active_epoch) = active_epoch else {
        return Ok(None);
    };
    store
        .read_task_events(task_id)
        .map_err(storage_error)?
        .into_iter()
        .rev()
        .find_map(|envelope| match envelope.event {
            crate::events::Event::TaskLifecycle {
                event:
                    TaskEvent::ProviderEpochBound {
                        epoch_id,
                        provider_epoch_id,
                    },
                ..
            } if epoch_id == active_epoch => Some(provider_epoch_id),
            _ => None,
        })
        .map(|provider_epoch_id| AgentEpochId::parse(provider_epoch_id).map_err(provider_error))
        .transpose()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn engine_update_size(update: &TaskEngineUpdate) -> usize {
    let payload = match update {
        TaskEngineUpdate::EpochObjective { objective, .. } => objective.len(),
        TaskEngineUpdate::CheckpointCommitted { digest, .. } => digest.len(),
        TaskEngineUpdate::CompletionClauses { clauses, .. } => clauses
            .iter()
            .map(|clause| {
                clause.id.len()
                    + clause.description.len()
                    + clause
                        .evidence
                        .iter()
                        .map(|evidence| evidence.artifact_digest.as_ref().map_or(0, String::len))
                        .sum::<usize>()
            })
            .sum(),
        TaskEngineUpdate::AgentMessageChunk(text) | TaskEngineUpdate::DiffUpdated(text) => {
            text.len()
        }
        TaskEngineUpdate::ToolStarted { title, .. }
        | TaskEngineUpdate::ToolCompleted { title, .. } => title.len(),
        TaskEngineUpdate::PermissionRequired {
            request_id,
            summary,
        } => request_id.len() + summary.len(),
        TaskEngineUpdate::TaskStatus { .. }
        | TaskEngineUpdate::ContextUsage { .. }
        | TaskEngineUpdate::Compaction { .. }
        | TaskEngineUpdate::RecoveryStrategy { .. } => 0,
    };
    payload.saturating_add(128)
}

const fn error(code: TaskEngineErrorCode) -> TaskEngineError {
    TaskEngineError::from_code(code)
}

const fn invalid_task() -> TaskEngineError {
    error(TaskEngineErrorCode::InvalidTask)
}

fn storage_error(_error: crate::error::CarlError) -> TaskEngineError {
    error(TaskEngineErrorCode::Storage)
}

fn provider_error(_error: AgentPortError) -> TaskEngineError {
    error(TaskEngineErrorCode::Provider)
}

#[cfg(test)]
mod tests;
