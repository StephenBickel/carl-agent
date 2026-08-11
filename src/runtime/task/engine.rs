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
use crate::events::{SessionId, ToolCallId};
use crate::policy::ActorId;
use crate::runtime::agent_port::{
    AgentContextId, AgentEffectRequest, AgentEpochId, AgentErrorProvenance, AgentEvent, AgentItem,
    AgentPort, AgentPortError, AgentPortErrorCode, ContextRecovery, EffectDecision,
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
    ProviderCheckpoint, RecoveryAttempt, RecoveryAttemptOutcome, RecoveryStrategy,
    RepositoryCheckpoint, TaskBudget, TaskEvent, TaskId, TaskSnapshot, TaskStatus,
    assess_progress_with_recovery_attempts, classify_effect, decide_completion, parse_epoch_report,
    recovery_attempt_fingerprint,
};

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_CONTRACT_OUTPUT_BYTES: usize = 64 * 1024;
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
    pending_recovery: Option<(RecoveryStrategy, String)>,
    steering: VecDeque<String>,
    steering_sequence: u64,
    operation_evidence: Vec<OperationEvidence>,
    file_hashes: BTreeMap<String, String>,
    observed_total_tokens: Option<u64>,
    observed_context_window: Option<u64>,
    completed_tools: u64,
    provider_requests: u64,
}

struct ActiveOperation {
    operation_id: OperationId,
    item: AgentItem,
    frontend_tool_call_id: Option<ToolCallId>,
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
        let contract = self.plan_contract(&input, &context_id).await?;
        let created = self
            .store_mut()
            .create_task(NewTask {
                session_id: input.session_id,
                workspace: input.workspace.clone(),
                contract,
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
        self.tasks.insert(
            task_id,
            RuntimeTask {
                workspace: input.workspace,
                request: input.request.clone(),
                model: input.model,
                effort: input.effort,
                permission_mode: input.permission_mode,
                context_id,
                next_objective: format!("Implement and explicitly verify: {}", input.request),
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
                completed_tools: 0,
                provider_requests: 1,
            },
        );
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
        let result = self.run_loop(task_id, &mut runtime).await;
        self.tasks.insert(task_id, runtime);
        result
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
        let cancelling = self.append(task_id, TaskEvent::CancellationRequested)?;
        if let Some(runtime) = self.tasks.get(&task_id)
            && let Some(epoch_id) = active_provider_epoch(self.store(), task_id)?
        {
            let _ = self.port.interrupt(&runtime.context_id, &epoch_id).await;
        }
        let cancelled = self.append(
            task_id,
            TaskEvent::StateTransitioned {
                from: cancelling.snapshot.status,
                to: TaskStatus::Cancelled,
                reason: "owner cancellation completed".to_owned(),
            },
        )?;
        self.updates.push(TaskEngineUpdate::TaskStatus {
            task_id,
            status: cancelled.snapshot.status,
        });
        Ok(())
    }

    async fn plan_contract(
        &mut self,
        input: &StartTask,
        context_id: &AgentContextId,
    ) -> Result<CompletionContract, TaskEngineError> {
        let initial = format!(
            "Read-only contract planning. Derive a bounded CompletionContract for this owner request without asking the owner to restate it. Return exactly one {CONTRACT_OPEN} JSON object {CONTRACT_CLOSE}. Request: {}",
            input.request
        );
        let repair = format!(
            "Repair the prior invalid contract. Return exactly one valid {CONTRACT_OPEN} JSON object {CONTRACT_CLOSE}; no trailing prose."
        );
        for prompt in [initial, repair] {
            let output = self.run_planning_epoch(input, context_id, prompt).await?;
            if let Ok(contract) = parse_contract(&output) {
                return Ok(contract);
            }
        }
        Ok(fallback_contract(&input.request))
    }

    async fn run_planning_epoch(
        &mut self,
        input: &StartTask,
        context_id: &AgentContextId,
        prompt: String,
    ) -> Result<String, TaskEngineError> {
        let epoch_id = self
            .port
            .start_epoch(StartAgentEpoch {
                context_id: context_id.clone(),
                input: prompt,
                model: input.model.clone(),
                effort: input.effort,
                permission_mode: PermissionMode::Plan,
            })
            .await
            .map_err(provider_error)?;
        let mut output = String::new();
        loop {
            let event = self.port.next_event().await.map_err(provider_error)?;
            event.validate().map_err(provider_error)?;
            match event {
                AgentEvent::ContextStarted {
                    context_id: observed,
                } if observed == *context_id => {}
                AgentEvent::EpochStarted {
                    context_id: observed_context,
                    epoch_id: observed_epoch,
                } if observed_context == *context_id && observed_epoch == epoch_id => {}
                AgentEvent::AssistantDelta {
                    context_id: observed_context,
                    epoch_id: observed_epoch,
                    text,
                } if observed_context == *context_id && observed_epoch == epoch_id => {
                    output.push_str(&text);
                    if output.len() > MAX_CONTRACT_OUTPUT_BYTES {
                        return Err(error(TaskEngineErrorCode::Verification));
                    }
                }
                AgentEvent::EpochCompleted {
                    context_id: observed_context,
                    epoch_id: observed_epoch,
                    ..
                } if observed_context == *context_id && observed_epoch == epoch_id => {
                    return Ok(output);
                }
                AgentEvent::ProviderFailed { .. } => {
                    return Err(error(TaskEngineErrorCode::Provider));
                }
                _ => return Err(error(TaskEngineErrorCode::Provider)),
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

            let objective = recovery_objective(runtime);
            let epoch_id = EpochId::new();
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
            let provider_epoch_id = match self
                .port
                .start_epoch(StartAgentEpoch {
                    context_id: runtime.context_id.clone(),
                    input: provider_input,
                    model: runtime.model.clone(),
                    effort: runtime.effort,
                    permission_mode: runtime.permission_mode,
                })
                .await
            {
                Ok(epoch_id) => epoch_id,
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
                    return Err(provider_error(port_error));
                }
                Err(port_error) => {
                    self.append(
                        task_id,
                        TaskEvent::Blocked {
                            reason: "provider epoch dispatch is uncertain".to_owned(),
                        },
                    )?;
                    return Err(provider_error(port_error));
                }
            };
            runtime.provider_requests = runtime
                .provider_requests
                .checked_add(1)
                .ok_or_else(invalid_task)?;
            for steering in runtime.steering.drain(..) {
                self.port
                    .steer(&runtime.context_id, &provider_epoch_id, steering)
                    .await
                    .map_err(provider_error)?;
            }
            let output = self
                .drain_work_epoch(task_id, epoch_id, &provider_epoch_id, runtime)
                .await?;
            let report = parse_epoch_report(&output)
                .map_err(|_| error(TaskEngineErrorCode::Verification))?;
            self.append(
                task_id,
                TaskEvent::EpochFinished {
                    epoch_id,
                    report_digest: sha256(output.as_bytes()),
                },
            )?;

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
            let mut assessment = assess_progress_with_recovery_attempts(
                &checkpoint,
                &report,
                &runtime.progress,
                &runtime.recovery_attempts,
            )
            .map_err(|_| error(TaskEngineErrorCode::Verification))?;
            if let Some((strategy, fingerprint)) = runtime.pending_recovery.take() {
                let attempt = RecoveryAttempt {
                    strategy,
                    strategy_fingerprint: fingerprint,
                    outcome: if assessment.new_information {
                        RecoveryAttemptOutcome::Succeeded
                    } else {
                        RecoveryAttemptOutcome::Failed
                    },
                };
                self.append(
                    task_id,
                    TaskEvent::RecoveryAttemptRecorded {
                        strategy: attempt.strategy,
                        strategy_fingerprint: attempt.strategy_fingerprint.clone(),
                        outcome: attempt.outcome,
                    },
                )?;
                runtime.recovery_attempts.push(attempt);
                assessment = assess_progress_with_recovery_attempts(
                    &checkpoint,
                    &report,
                    &runtime.progress,
                    &runtime.recovery_attempts,
                )
                .map_err(|_| error(TaskEngineErrorCode::Verification))?;
            }
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
                        runtime.pending_recovery = Some((
                            strategy,
                            recovery_attempt_fingerprint(&assessment.fingerprint, strategy),
                        ));
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
    ) -> Result<String, TaskEngineError> {
        let mut output = String::new();
        let mut items = HashMap::<String, AgentItem>::new();
        let mut operations = HashMap::<String, ActiveOperation>::new();
        let mut boundary_requested = false;
        let epoch_tool_start = runtime.completed_tools;
        let timer = tokio::time::sleep(Duration::from_secs(
            self.snapshot(task_id)?.budget.soft_epoch_seconds,
        ));
        tokio::pin!(timer);
        loop {
            enum Next {
                Provider(Result<AgentEvent, AgentPortError>),
                Boundary,
                Control(Option<TaskEngineControl>),
            }
            let controls_enabled = self.controls.is_some();
            let next = {
                let port = &mut self.port;
                let controls = &mut self.controls;
                tokio::select! {
                    event = port.next_event() => Next::Provider(event),
                    () = &mut timer, if !boundary_requested => Next::Boundary,
                    control = receive_control(controls), if controls_enabled => Next::Control(control),
                }
            };
            match next {
                Next::Provider(event) => {
                    let event = match event {
                        Ok(event) => event,
                        Err(port_error) => {
                            self.block_uncertain_operations(
                                task_id,
                                &operations,
                                "provider event delivery failed with an ambiguous operation outcome",
                            )?;
                            return Err(provider_error(port_error));
                        }
                    };
                    event.validate().map_err(provider_error)?;
                    if self
                        .process_work_event(
                            task_id,
                            epoch_id,
                            provider_epoch_id,
                            runtime,
                            event,
                            &mut items,
                            &mut operations,
                            &mut output,
                        )
                        .await?
                    {
                        if !operations.is_empty() {
                            return Err(error(TaskEngineErrorCode::Verification));
                        }
                        return Ok(output);
                    }
                    if !boundary_requested
                        && runtime.completed_tools.saturating_sub(epoch_tool_start)
                            >= u64::from(self.snapshot(task_id)?.budget.soft_epoch_tool_calls)
                    {
                        boundary_requested = true;
                        self.request_safe_boundary(task_id, runtime, provider_epoch_id)
                            .await?;
                    }
                }
                Next::Boundary => {
                    boundary_requested = true;
                    self.request_safe_boundary(task_id, runtime, provider_epoch_id)
                        .await?;
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
                        .apply_control(task_id, runtime, provider_epoch_id, control)
                        .await;
                    self.acknowledge(acknowledgement, result.clone()).await;
                    result?;
                }
                Next::Control(None) => {
                    self.controls = None;
                    self.acknowledgements = None;
                }
            }
        }
    }

    async fn apply_control(
        &mut self,
        task_id: TaskId,
        runtime: &mut RuntimeTask,
        provider_epoch_id: &AgentEpochId,
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
                let cancelling = self.append(task_id, TaskEvent::CancellationRequested)?;
                self.port
                    .interrupt(&runtime.context_id, provider_epoch_id)
                    .await
                    .map_err(provider_error)?;
                let cancelled = self.append(
                    task_id,
                    TaskEvent::StateTransitioned {
                        from: cancelling.snapshot.status,
                        to: TaskStatus::Cancelled,
                        reason: "owner cancellation completed".to_owned(),
                    },
                )?;
                self.store_mut()
                    .append(
                        session_id,
                        Some(turn_id),
                        crate::events::Event::TurnInterrupted {
                            reason: "cancelled".to_owned(),
                        },
                    )
                    .map_err(storage_error)?;
                self.updates.push(TaskEngineUpdate::TaskStatus {
                    task_id,
                    status: cancelled.snapshot.status,
                });
                Err(error(TaskEngineErrorCode::Cancelled))
            }
            TaskEngineControl::Approval { .. } => Err(error(TaskEngineErrorCode::Blocked)),
        }
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
    ) -> Result<bool, TaskEngineError> {
        match event {
            AgentEvent::ContextStarted { context_id } if context_id == runtime.context_id => {}
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
                self.port
                    .steer(
                        &runtime.context_id,
                        provider_epoch_id,
                        format!("carl-operation-id: {operation_id}"),
                    )
                    .await
                    .map_err(provider_error)?;
                self.resolve_effect(
                    task_id,
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
                output.push_str(&text);
                self.updates.push(TaskEngineUpdate::AgentMessageChunk(text));
            }
            AgentEvent::DiffUpdated {
                context_id,
                epoch_id,
                diff,
            } if context_id == runtime.context_id && epoch_id == *provider_epoch_id => {
                self.updates.push(TaskEngineUpdate::DiffUpdated(diff));
            }
            AgentEvent::UsageUpdated {
                context_id,
                epoch_id: observed_epoch,
                usage,
            } if context_id == runtime.context_id && observed_epoch == *provider_epoch_id => {
                runtime.observed_total_tokens = Some(usage.total_tokens);
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
            }
            AgentEvent::EpochCompleted {
                context_id,
                epoch_id,
                ..
            } if context_id == runtime.context_id && epoch_id == *provider_epoch_id => {
                return Ok(true);
            }
            AgentEvent::ProviderFailed { .. } => {
                self.block_uncertain_operations(
                    task_id,
                    operations,
                    "provider reported failure with an ambiguous operation outcome",
                )?;
                return Err(error(TaskEngineErrorCode::Provider));
            }
            AgentEvent::CompactionStarted { context_id, .. }
            | AgentEvent::CompactionCompleted { context_id, .. }
                if context_id == runtime.context_id => {}
            _ => return Err(error(TaskEngineErrorCode::Provider)),
        }
        Ok(false)
    }

    async fn resolve_effect(
        &mut self,
        task_id: TaskId,
        runtime: &mut RuntimeTask,
        request: AgentEffectRequest,
        operation_id: OperationId,
        frontend_tool_call_id: Option<ToolCallId>,
    ) -> Result<(), TaskEngineError> {
        let decision = match runtime.permission_mode.profile() {
            PermissionProfile::FullAccess => EffectDecision::Allow,
            PermissionProfile::Approval if self.frontend_context.is_some() => {
                self.await_approval(task_id, runtime, &request, frontend_tool_call_id)
                    .await?
            }
            PermissionProfile::ReadOnly | PermissionProfile::Approval => EffectDecision::Deny,
        };
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
                    return Err(error(TaskEngineErrorCode::Blocked));
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
        if let Err(port_error) = self
            .port
            .resolve_effect(&request.request_id, decision)
            .await
        {
            if port_error.provenance() == AgentErrorProvenance::PossiblyApplied {
                let evidence =
                    sha256(format!("effect-resolution:{:?}", port_error.code()).as_bytes());
                self.append(
                    task_id,
                    TaskEvent::OperationEvidenceRecorded {
                        operation_id,
                        result_digest: evidence,
                    },
                )?;
                let sequence = self.last_task_sequence(task_id)?;
                self.append(
                    task_id,
                    TaskEvent::OperationTransitioned {
                        operation_id,
                        from: OperationStatus::Started,
                        to: OperationStatus::Uncertain,
                        evidence_sequences: vec![sequence],
                    },
                )?;
            }
            return Err(provider_error(port_error));
        }
        if decision == EffectDecision::Deny {
            let evidence = sha256(b"permission-denied");
            self.append(
                task_id,
                TaskEvent::OperationEvidenceRecorded {
                    operation_id,
                    result_digest: evidence,
                },
            )?;
            let sequence = self.last_task_sequence(task_id)?;
            self.append(
                task_id,
                TaskEvent::OperationTransitioned {
                    operation_id,
                    from: OperationStatus::Started,
                    to: OperationStatus::Failed,
                    evidence_sequences: vec![sequence],
                },
            )?;
            let blocked = self.append(
                task_id,
                TaskEvent::Blocked {
                    reason: "operation denied by permission policy".to_owned(),
                },
            )?;
            self.updates.push(TaskEngineUpdate::TaskStatus {
                task_id,
                status: blocked.snapshot.status,
            });
            return Err(error(TaskEngineErrorCode::Blocked));
        }
        Ok(())
    }

    async fn await_approval(
        &mut self,
        task_id: TaskId,
        runtime: &mut RuntimeTask,
        request: &AgentEffectRequest,
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
        if let Some(sender) = &self.permission_notices {
            sender
                .send(TaskEnginePermissionNotice {
                    display_code,
                    summary: request.summary.clone(),
                    request_id: request.request_id.as_str().to_owned(),
                })
                .await
                .map_err(|_| error(TaskEngineErrorCode::Blocked))?;
        }
        loop {
            let control = receive_control(&mut self.controls)
                .await
                .ok_or_else(|| error(TaskEngineErrorCode::Blocked))?;
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
                    self.acknowledge(acknowledgement, result.clone()).await;
                    result?;
                    return Ok(decision);
                }
                TaskEngineControl::Cancel { .. } => {
                    let result = self
                        .apply_control(task_id, runtime, &request.epoch_id, control)
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

    fn block_uncertain_operations(
        &mut self,
        task_id: TaskId,
        operations: &HashMap<String, ActiveOperation>,
        reason: &str,
    ) -> Result<(), TaskEngineError> {
        let operation_ids = operations
            .values()
            .map(|operation| operation.operation_id)
            .collect::<Vec<_>>();
        for operation_id in operation_ids {
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
        let mut operation_evidence = Vec::new();
        let mut steering_sequence = 0_u64;
        let mut completed_tools = 0_u64;
        let mut provider_requests = 1_u64;
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
                TaskEvent::EpochStarted { .. } => {
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
                TaskEvent::RecoveryAttemptRecorded {
                    strategy,
                    strategy_fingerprint,
                    outcome,
                } => recovery_attempts.push(RecoveryAttempt {
                    strategy: *strategy,
                    strategy_fingerprint: strategy_fingerprint.clone(),
                    outcome: *outcome,
                }),
                TaskEvent::NormalizedOperationEvidenceRecorded {
                    operation_id,
                    evidence,
                } => {
                    operation_evidence.push(operation_evidence_from_event(*operation_id, evidence));
                    completed_tools = completed_tools.saturating_add(1);
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
            pending_recovery: None,
            steering: VecDeque::new(),
            steering_sequence,
            operation_evidence,
            file_hashes,
            observed_total_tokens,
            observed_context_window,
            completed_tools,
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
        goal: request.to_owned(),
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

fn report_next_objective<'a>(report: &'a EpochReport, runtime: &'a RuntimeTask) -> &'a str {
    report
        .next_objective
        .as_deref()
        .unwrap_or(runtime.next_objective.as_str())
}

fn recovery_objective(runtime: &RuntimeTask) -> String {
    runtime.pending_recovery.as_ref().map_or_else(
        || runtime.next_objective.clone(),
        |(strategy, _)| {
            format!(
                "Use recovery strategy {strategy:?}: {}",
                runtime.next_objective
            )
        },
    )
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
        .is_some_and(|maximum| runtime.completed_tools >= maximum)
    {
        Some("maximum tool calls exhausted")
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
    let active = store
        .get_task(task_id)
        .map_err(storage_error)?
        .and_then(|record| record.snapshot.active_epoch);
    active
        .map(|epoch_id| AgentEpochId::parse(epoch_id.to_string()).map_err(provider_error))
        .transpose()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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
