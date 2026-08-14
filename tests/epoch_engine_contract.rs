#[path = "support/private_dir.rs"]
mod private_dir;

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::events::SessionId;
use carl::policy::{Frontend, Sha256Digest};
use carl::runtime::agent_port::{
    AgentCapabilities, AgentContextId, AgentEffectKind, AgentEffectRequest, AgentEpochId,
    AgentErrorProvenance, AgentEvent, AgentFuture, AgentItem, AgentModel, AgentPort,
    AgentPortError, AgentPortErrorCode, AgentProcess, AgentRequestId, EffectDecision,
    ResumeAgentContext, StartAgentContext, StartAgentEpoch,
};
use carl::runtime::task::{
    CanonicalCheckpoint, CheckpointId, ClauseEvidence, ClauseStatus, CompletionClause,
    CompletionContract, DecisionRecord, EffectClass, EpochDisposition, EpochId, EvidenceRef,
    ExactIdentifier, OperationCheckpoint, OperationEvidence, OperationId, OperationStatus,
    ProcessCheckpoint, ProgressAssessment, ProviderCheckpoint, ProviderRequestPurpose,
    RecoveryAttempt, RecoveryAttemptOutcome, RecoveryStrategy, ReportErrorCode,
    RepositoryCheckpoint, StartTask, TaskBudget, TaskEngine, TaskEngineUpdate, TaskId, TaskStatus,
    WorkEvidence, assess_progress, assess_progress_with_recovery_attempts, decide_completion,
    parse_epoch_report, recovery_attempt_fingerprint, reduce_task,
};
use carl::sidecar::DataRootLock;
use carl::storage::{
    ClientName, ExternalSessionId, NewFrontendSession, NewTask, RuntimeStore, Store,
    TaskControlMutationClaim, TaskControlMutationInput,
};
use rusqlite::Connection;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).unwrap()
}

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

struct EngineFixture {
    root: PathBuf,
    workspace: PathBuf,
    database: PathBuf,
}

impl EngineFixture {
    fn new() -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!("carl-epoch-engine-{}", Uuid::new_v4()));
        let workspace = root.join("workspace");
        let database = root.join("carl.sqlite3");
        fs::create_dir_all(&workspace)?;
        private_dir::make_owner_only_directory(&root)?;
        Ok(Self {
            root,
            workspace,
            database,
        })
    }
}

fn install_postcondition_crash_cut(database: &Path) -> TestResult {
    Connection::open(database)?.execute_batch(
        "CREATE TRIGGER crash_after_postcondition_bound
         BEFORE INSERT ON events
         WHEN instr(NEW.event_json, 'normalized_operation_evidence_recorded') > 0
          AND EXISTS (
              SELECT 1 FROM events
              WHERE instr(event_json, 'operation_file_postcondition_bound') > 0
          )
         BEGIN
             SELECT RAISE(ABORT, 'scripted crash after postcondition binding');
         END;",
    )?;
    Ok(())
}

fn remove_postcondition_crash_cut(database: &Path) -> TestResult {
    Connection::open(database)?
        .execute_batch("DROP TRIGGER IF EXISTS crash_after_postcondition_bound;")?;
    Ok(())
}

fn install_engine_event_cut(
    database: &Path,
    abort_event_fragment: &str,
    prerequisite_fragment: Option<&str>,
) -> TestResult {
    let prerequisite = prerequisite_fragment.map_or_else(String::new, |fragment| {
        format!(" AND EXISTS (SELECT 1 FROM events WHERE instr(event_json, '{fragment}') > 0)")
    });
    Connection::open(database)?.execute_batch(&format!(
        "CREATE TRIGGER engine_crash_cut
         BEFORE INSERT ON events
         WHEN instr(NEW.event_json, '{abort_event_fragment}') > 0{prerequisite}
         BEGIN SELECT RAISE(ABORT, 'scripted engine crash cut'); END;"
    ))?;
    Ok(())
}

fn remove_engine_event_cut(database: &Path) -> TestResult {
    Connection::open(database)?.execute_batch("DROP TRIGGER IF EXISTS engine_crash_cut;")?;
    Ok(())
}

fn assert_task_projection_matches_replay(store: &Store, task_id: TaskId, cut: &str) -> TestResult {
    let events = store.read_task_events(task_id)?;
    let mut replayed = None;
    for envelope in &events {
        replayed = Some(reduce_task(replayed, envelope)?);
    }
    assert_eq!(
        store
            .get_task(task_id)?
            .expect("task remains projected")
            .snapshot,
        replayed.expect("created event exists"),
        "projection diverged from replay at {cut}"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MatrixOutcome {
    Completed,
    Blocked,
}

async fn restart_matrix_task(
    fixture: &EngineFixture,
    first: TaskEngine<EnginePort>,
    task_id: TaskId,
    restart_port: EnginePort,
    outcome: MatrixOutcome,
    cut: &str,
) -> TestResult<TaskEngine<EnginePort, RuntimeStore>> {
    assert_task_projection_matches_replay(first.store(), task_id, cut)?;
    let (store, _) = first.into_parts();
    drop(store);
    remove_engine_event_cut(&fixture.database)?;
    let runtime = RuntimeStore::open(DataRootLock::acquire(&fixture.root)?, chrono::Utc::now())?;
    let mut restarted = TaskEngine::new_runtime(runtime, restart_port);
    assert_task_projection_matches_replay(restarted.store(), task_id, cut)?;
    match outcome {
        MatrixOutcome::Completed => assert_eq!(
            restarted.run(task_id).await?.status,
            TaskStatus::Completed,
            "restart cut {cut}"
        ),
        MatrixOutcome::Blocked => assert_eq!(
            restarted.run(task_id).await.unwrap_err().code(),
            carl::runtime::task::TaskEngineErrorCode::Blocked,
            "restart cut {cut}"
        ),
    }
    assert_task_projection_matches_replay(restarted.store(), task_id, cut)?;
    Ok(restarted)
}

async fn restart_matrix_runtime_task(
    fixture: &EngineFixture,
    first: TaskEngine<EnginePort, RuntimeStore>,
    task_id: TaskId,
    restart_port: EnginePort,
    outcome: MatrixOutcome,
    cut: &str,
) -> TestResult<TaskEngine<EnginePort, RuntimeStore>> {
    assert_task_projection_matches_replay(first.store(), task_id, cut)?;
    let (runtime, _) = first.into_parts();
    drop(runtime);
    remove_engine_event_cut(&fixture.database)?;
    let runtime = RuntimeStore::open(DataRootLock::acquire(&fixture.root)?, chrono::Utc::now())?;
    let mut restarted = TaskEngine::new_runtime(runtime, restart_port);
    assert_task_projection_matches_replay(restarted.store(), task_id, cut)?;
    match outcome {
        MatrixOutcome::Completed => assert_eq!(
            restarted.run(task_id).await?.status,
            TaskStatus::Completed,
            "restart cut {cut}"
        ),
        MatrixOutcome::Blocked => assert_eq!(
            restarted.run(task_id).await.unwrap_err().code(),
            carl::runtime::task::TaskEngineErrorCode::Blocked,
            "restart cut {cut}"
        ),
    }
    assert_task_projection_matches_replay(restarted.store(), task_id, cut)?;
    Ok(restarted)
}

#[derive(Clone, Copy, Debug)]
enum RequiredEngineRestartCut {
    TaskCreated,
    EpochStarted,
    OperationIntentRecorded,
    EffectAuthorized,
    ItemStarted,
    WorkspaceMutated,
    ItemCompleted,
    CheckpointCandidateBuilt,
    CheckpointCommitted,
    CompactionRequested,
    ProviderReplacementStarted,
    ProviderBindingCommitted,
}

impl Drop for EngineFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Clone, Copy)]
enum WorkKind {
    Command,
    FileChange,
}

#[derive(Clone, Copy)]
enum PlanningFault {
    Next(AgentErrorProvenance),
    Invalid,
    Unexpected,
}

#[derive(Clone, Copy)]
enum WorkFault {
    DuplicateItemStarted,
    UnexpectedEvent,
}

#[derive(Clone)]
struct EnginePort {
    state: Arc<Mutex<EnginePortState>>,
}

struct EnginePortState {
    context_starts: usize,
    epoch_starts: Vec<StartAgentEpoch>,
    epoch_number: usize,
    planning_attempts: usize,
    work_number: usize,
    events: VecDeque<AgentEvent>,
    work: VecDeque<(WorkKind, &'static str, &'static str)>,
    latest_operation_id: Option<String>,
    steers: Vec<String>,
    resolved: Vec<EffectDecision>,
    compactions: usize,
    replacements: usize,
    usage: Option<(u64, u64)>,
    usage_last_total: Option<u64>,
    ambiguous_event_failure: bool,
    definitely_not_applied_event_failure: bool,
    invalid_event_after_binding: bool,
    binding_failure: Option<AgentErrorProvenance>,
    resolve_failure: Option<AgentErrorProvenance>,
    work_effect_kind: Option<AgentEffectKind>,
    work_effect_summary: Option<String>,
    work_start_failure: Option<AgentErrorProvenance>,
    invalid_first_contract: bool,
    large_invalid_planning_outputs: bool,
    planning_usage: Option<(u64, u64)>,
    compaction_failure_once: bool,
    terminal_statuses: VecDeque<&'static str>,
    additional_effects_in_epoch: usize,
    current_item_id: Option<String>,
    item_started_deliveries: usize,
    interrupts: usize,
    pending_work_stream: bool,
    pending_after_item_started: bool,
    pending_planning_stream: bool,
    oversized_planning_stream: bool,
    oversized_work_stream: bool,
    planning_event_flood: bool,
    oversized_diff_stream: bool,
    planning_fault: Option<PlanningFault>,
    work_fault: Option<WorkFault>,
    soft_boundary_failure: Option<AgentErrorProvenance>,
    soft_boundary_unsupported: bool,
    invalid_work_report: bool,
    post_usage_diff_bytes: usize,
    pending_resolve: bool,
    pending_replacement: bool,
    durable_effect_count: u64,
    durable_mutation_count: u64,
    resume_attempts: Vec<String>,
    resume_unavailable: bool,
    reject_missing_resume_workspace: bool,
    active_context_id: String,
    background_capable: bool,
    background_processes: Vec<AgentProcess>,
    background_lists: usize,
    termination_result: bool,
    terminations: Vec<String>,
    started_process: Option<AgentProcess>,
    completed_process: Option<AgentProcess>,
    file_mutation: Option<(PathBuf, Vec<u8>)>,
    file_change_path: String,
    implicit_observation_first: bool,
}

impl EnginePort {
    fn three_epochs() -> Self {
        Self::new([
            (
                WorkKind::Command,
                "Reproduced the failure",
                "continue:Implement the repair",
            ),
            (
                WorkKind::Command,
                "Edited the parser and ran focused tests",
                "continue:Run final verification",
            ),
            (
                WorkKind::Command,
                "All final checks passed",
                "complete:requested-outcome,explicit-verification",
            ),
        ])
    }

    fn small_edit() -> Self {
        Self::new([(
            WorkKind::FileChange,
            "Edited src/lib.rs and verified it",
            "complete:requested-outcome,explicit-verification",
        )])
    }

    fn implicit_observation_then_edit() -> Self {
        let port = Self::new([
            (
                WorkKind::Command,
                "Inspected repository state",
                "continue:Implement the repair",
            ),
            (
                WorkKind::FileChange,
                "Implemented and verified the repair",
                "complete:requested-outcome,explicit-verification",
            ),
        ]);
        port.state.lock().unwrap().implicit_observation_first = true;
        port
    }

    fn new<const N: usize>(work: [(WorkKind, &'static str, &'static str); N]) -> Self {
        Self {
            state: Arc::new(Mutex::new(EnginePortState {
                context_starts: 0,
                epoch_starts: Vec::new(),
                epoch_number: 0,
                planning_attempts: 0,
                work_number: 0,
                events: VecDeque::new(),
                work: work.into(),
                latest_operation_id: None,
                steers: Vec::new(),
                resolved: Vec::new(),
                compactions: 0,
                replacements: 0,
                usage: None,
                usage_last_total: None,
                ambiguous_event_failure: false,
                definitely_not_applied_event_failure: false,
                invalid_event_after_binding: false,
                binding_failure: None,
                resolve_failure: None,
                work_effect_kind: None,
                work_effect_summary: None,
                work_start_failure: None,
                invalid_first_contract: false,
                large_invalid_planning_outputs: false,
                planning_usage: None,
                compaction_failure_once: false,
                terminal_statuses: VecDeque::new(),
                additional_effects_in_epoch: 0,
                current_item_id: None,
                item_started_deliveries: 0,
                interrupts: 0,
                pending_work_stream: false,
                pending_after_item_started: false,
                pending_planning_stream: false,
                oversized_planning_stream: false,
                oversized_work_stream: false,
                planning_event_flood: false,
                oversized_diff_stream: false,
                planning_fault: None,
                work_fault: None,
                soft_boundary_failure: None,
                soft_boundary_unsupported: false,
                invalid_work_report: false,
                post_usage_diff_bytes: 0,
                pending_resolve: false,
                pending_replacement: false,
                durable_effect_count: 0,
                durable_mutation_count: 0,
                resume_attempts: Vec::new(),
                resume_unavailable: false,
                reject_missing_resume_workspace: false,
                active_context_id: "engine-context".to_owned(),
                background_capable: false,
                background_processes: Vec::new(),
                background_lists: 0,
                termination_result: false,
                terminations: Vec::new(),
                started_process: None,
                completed_process: None,
                file_mutation: None,
                file_change_path: "src/lib.rs".to_owned(),
                implicit_observation_first: false,
            })),
        }
    }

    fn repaired_contract() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().invalid_first_contract = true;
        port
    }

    fn repaired_contract_then_unavailable_work() -> Self {
        let port = Self::new([]);
        port.state.lock().unwrap().invalid_first_contract = true;
        port
    }

    fn fallback_contract_under_estimated_pressure() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().large_invalid_planning_outputs = true;
        port
    }

    fn planning_usage_under_context_pressure() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().planning_usage = Some((102_400, 128_000));
        port
    }

    fn completion_checkpoint_then_compaction_failure() -> Self {
        let port = Self::small_edit_under_context_pressure();
        port.state.lock().unwrap().compaction_failure_once = true;
        port
    }

    fn continuation_checkpoint_then_compaction_failure() -> Self {
        let port = Self::new([(
            WorkKind::Command,
            "first epoch completed before crash",
            "continue:Finish without repeating first epoch",
        )]);
        {
            let mut state = port.state.lock().unwrap();
            state.usage = Some((102_400, 128_000));
            state.compaction_failure_once = true;
        }
        port
    }

    fn continuation_checkpoint_with_process_then_compaction_failure(
        started_process: AgentProcess,
        completed_process: Option<AgentProcess>,
    ) -> Self {
        let port = Self::continuation_checkpoint_then_compaction_failure();
        let mut state = port.state.lock().unwrap();
        state.started_process = Some(started_process);
        if let Some(completed_process) = completed_process {
            state.background_capable = true;
            state.background_processes = vec![completed_process.clone()];
            state.completed_process = Some(completed_process);
        }
        drop(state);
        port
    }

    fn continuation_checkpoint_with_terminal_process_then_compaction_failure(
        started_process: AgentProcess,
        completed_process: AgentProcess,
    ) -> Self {
        let port = Self::continuation_checkpoint_with_process_then_compaction_failure(
            started_process,
            Some(completed_process),
        );
        port.state.lock().unwrap().background_processes.clear();
        port
    }

    fn ambiguous_event_failure() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().ambiguous_event_failure = true;
        port
    }

    fn definitely_not_applied_event_failure() -> Self {
        let port = Self::small_edit();
        port.state
            .lock()
            .unwrap()
            .definitely_not_applied_event_failure = true;
        port
    }

    fn invalid_event_after_binding() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().invalid_event_after_binding = true;
        port
    }

    fn binding_failure(provenance: AgentErrorProvenance) -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().binding_failure = Some(provenance);
        port
    }

    fn resolve_failure(provenance: AgentErrorProvenance) -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().resolve_failure = Some(provenance);
        port
    }

    fn unsupported_network_effect() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().work_effect_kind = Some(AgentEffectKind::Network);
        port
    }

    fn work_start_failure(provenance: AgentErrorProvenance) -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().work_start_failure = Some(provenance);
        port
    }

    fn small_edit_under_context_pressure() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().usage = Some((102_400, 128_000));
        port
    }

    fn cumulative_usage_after_compaction() -> Self {
        let port = Self::small_edit();
        let mut state = port.state.lock().unwrap();
        state.usage = Some((900_000, 128_000));
        state.usage_last_total = Some(10_000);
        drop(state);
        port
    }

    fn two_effects_in_one_epoch() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().additional_effects_in_epoch = 1;
        port
    }

    fn effect_after_soft_boundary_then_next_epoch() -> Self {
        let port = Self::new([
            (
                WorkKind::Command,
                "First operation reached the safe boundary",
                "continue:Retry denied work after the checkpoint",
            ),
            (
                WorkKind::FileChange,
                "Retried after the checkpoint and verified the repair",
                "complete:requested-outcome,explicit-verification",
            ),
        ]);
        port.state.lock().unwrap().additional_effects_in_epoch = 1;
        port
    }

    fn pending_effect() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().pending_work_stream = true;
        port
    }

    fn pending_after_item_started() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().pending_after_item_started = true;
        port
    }

    fn pending_file_effect(workspace: &Path, contents: &[u8]) -> Self {
        Self::file_effect_with_path(workspace, "src/lib.rs", contents)
    }

    fn pending_workspace_mutation(workspace: &Path, contents: &[u8]) -> Self {
        let port = Self::pending_file_effect(workspace, contents);
        port.state.lock().unwrap().pending_work_stream = true;
        port
    }

    fn file_effect_with_path(workspace: &Path, path: &str, contents: &[u8]) -> Self {
        let port = Self::small_edit();
        let mut state = port.state.lock().unwrap();
        state.file_change_path = path.to_owned();
        state.file_mutation = Some((workspace.join(path), contents.to_vec()));
        drop(state);
        port
    }

    fn pending_ambiguous_effect() -> Self {
        let port = Self::new([(
            WorkKind::Command,
            "external effect applied before disconnect",
            "complete:requested-outcome,explicit-verification",
        )]);
        port.state.lock().unwrap().pending_work_stream = true;
        port
    }

    fn pending_planning() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().pending_planning_stream = true;
        port
    }

    fn oversized_planning_stream() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().oversized_planning_stream = true;
        port
    }

    fn oversized_work_stream() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().oversized_work_stream = true;
        port
    }

    fn planning_event_flood() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().planning_event_flood = true;
        port
    }

    fn oversized_diff_stream() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().oversized_diff_stream = true;
        port
    }

    fn planning_fault(fault: PlanningFault) -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().planning_fault = Some(fault);
        port
    }

    fn work_fault(fault: WorkFault) -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().work_fault = Some(fault);
        port
    }

    fn soft_boundary_failure(provenance: AgentErrorProvenance) -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().soft_boundary_failure = Some(provenance);
        port
    }

    fn pending_effect_with_unsupported_soft_boundary() -> Self {
        let port = Self::pending_effect();
        port.state.lock().unwrap().soft_boundary_unsupported = true;
        port
    }

    fn malformed_terminal_work_report() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().invalid_work_report = true;
        port
    }

    fn post_usage_diff_pressure() -> Self {
        let port = Self::small_edit();
        let mut state = port.state.lock().unwrap();
        state.usage = Some((101_000, 128_000));
        state.post_usage_diff_bytes = 4_096;
        drop(state);
        port
    }

    fn pending_resolve() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().pending_resolve = true;
        port
    }

    fn resume_small_edit() -> Self {
        let port = Self::small_edit();
        port.state.lock().unwrap().epoch_number = 1;
        port
    }

    fn unavailable_context_then_small_edit() -> Self {
        let port = Self::resume_small_edit();
        port.state.lock().unwrap().resume_unavailable = true;
        port
    }

    fn unavailable_context_with_pending_replacement() -> Self {
        let port = Self::unavailable_context_then_small_edit();
        port.state.lock().unwrap().pending_replacement = true;
        port
    }

    fn resume_with_background_process(process: AgentProcess, termination_result: bool) -> Self {
        let port = Self::resume_small_edit();
        let mut state = port.state.lock().unwrap();
        state.background_capable = true;
        state.background_processes = vec![process];
        state.termination_result = termination_result;
        drop(state);
        port
    }

    fn resume_with_missing_background_process() -> Self {
        let port = Self::resume_small_edit();
        port.state.lock().unwrap().background_capable = true;
        port
    }

    fn resume_with_work_start_failure(provenance: AgentErrorProvenance) -> Self {
        let port = Self::resume_small_edit();
        port.state.lock().unwrap().work_start_failure = Some(provenance);
        port
    }

    fn shared(&self) -> Arc<Mutex<EnginePortState>> {
        Arc::clone(&self.state)
    }

    fn prepare_after_crash(&self) {
        let mut state = self.state.lock().unwrap();
        state.events.clear();
        state.latest_operation_id = None;
        state.current_item_id = None;
        state.pending_work_stream = false;
        state.pending_after_item_started = false;
        state.pending_resolve = false;
        state.pending_replacement = false;
    }
}

impl AgentPort for EnginePort {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            resume: true,
            compact: true,
            token_usage: true,
            pre_dispatch_effects: true,
            history_paging: false,
            background_processes: self.state.lock().unwrap().background_capable,
        }
    }

    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn start_context(&mut self, _request: StartAgentContext) -> AgentFuture<'_, AgentContextId> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().unwrap().context_starts += 1;
            AgentContextId::parse("engine-context")
        })
    }

    fn resume_context(&mut self, request: ResumeAgentContext) -> AgentFuture<'_, AgentContextId> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut state = state.lock().unwrap();
            if state.reject_missing_resume_workspace && !request.cwd.is_dir() {
                return Err(AgentPortError::definitely_not_applied(
                    AgentPortErrorCode::InvalidRequest,
                ));
            }
            state
                .resume_attempts
                .push(request.context_id.as_str().to_owned());
            if state.resume_unavailable {
                state.resume_unavailable = false;
                return Err(AgentPortError::unavailable_context());
            }
            state.active_context_id = request.context_id.as_str().to_owned();
            Ok(request.context_id)
        })
    }

    fn compact_context(&mut self, _context_id: &AgentContextId) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut state = state.lock().unwrap();
            state.compactions += 1;
            if state.compaction_failure_once {
                state.compaction_failure_once = false;
                return Err(AgentPortError::from_code(AgentPortErrorCode::Transport));
            }
            Ok(())
        })
    }

    fn replace_context<'a>(
        &'a mut self,
        _request: ResumeAgentContext,
        _context_package: &'a carl::runtime::task::ContextPackage,
    ) -> AgentFuture<'a, carl::runtime::agent_port::ContextRecovery> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let pending = {
                let mut state = state.lock().unwrap();
                state.replacements += 1;
                state.pending_replacement
            };
            if pending {
                return std::future::pending().await;
            }
            let context_id = AgentContextId::parse("replacement-context")?;
            state.lock().unwrap().active_context_id = context_id.as_str().to_owned();
            Ok(carl::runtime::agent_port::ContextRecovery::Replaced(
                context_id,
            ))
        })
    }

    fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut state = state.lock().unwrap();
            let planning = request.permission_mode == PermissionMode::Plan;
            let context_id = request.context_id.clone();
            state.active_context_id = context_id.as_str().to_owned();
            state.epoch_starts.push(request);
            state.epoch_number += 1;
            let epoch_number = state.epoch_number;
            let epoch_id = AgentEpochId::parse(format!("engine-epoch-{epoch_number}"))?;
            if !planning && let Some(provenance) = state.work_start_failure.take() {
                return Err(scripted_error(provenance));
            }
            state.events.push_back(AgentEvent::EpochStarted {
                context_id: context_id.clone(),
                epoch_id: epoch_id.clone(),
            });
            if planning {
                state.planning_attempts += 1;
                if state.pending_planning_stream {
                    return Ok(epoch_id);
                }
                match state.planning_fault {
                    Some(PlanningFault::Next(_)) => return Ok(epoch_id),
                    Some(PlanningFault::Invalid) => {
                        state.events.push_back(AgentEvent::AssistantDelta {
                            context_id,
                            epoch_id: epoch_id.clone(),
                            text: "x".repeat(1_048_577),
                        });
                        return Ok(epoch_id);
                    }
                    Some(PlanningFault::Unexpected) => {
                        state.events.push_back(AgentEvent::ItemStarted {
                            context_id,
                            epoch_id: epoch_id.clone(),
                            item: work_item(
                                WorkKind::Command,
                                "unexpected-planning-item",
                                "inProgress",
                            ),
                        });
                        return Ok(epoch_id);
                    }
                    None => {}
                }
                let planning_attempt = state.planning_attempts;
                let text = if state.large_invalid_planning_outputs {
                    "x".repeat(60 * 1024)
                } else if state.invalid_first_contract && planning_attempt == 1 {
                    "invalid contract".to_owned()
                } else {
                    "<carl-completion-contract>{\"version\":1,\"goal\":\"Complete the owner request\",\"constraints\":[],\"clauses\":[{\"id\":\"requested-outcome\",\"description\":\"The requested change is implemented\",\"required\":true,\"status\":\"pending\",\"evidence\":[]},{\"id\":\"explicit-verification\",\"description\":\"The change is explicitly verified\",\"required\":true,\"status\":\"pending\",\"evidence\":[]}]}</carl-completion-contract>".to_owned()
                };
                let planning_chunks = if state.oversized_planning_stream {
                    vec!["x".repeat(40 * 1024), "y".repeat(40 * 1024)]
                } else {
                    vec![text]
                };
                if state.planning_event_flood {
                    for event_number in 0..8_193 {
                        state.events.push_back(AgentEvent::CompactionStarted {
                            context_id: context_id.clone(),
                            item_id: format!("compact-{event_number}"),
                        });
                    }
                }
                for text in planning_chunks {
                    state.events.push_back(AgentEvent::AssistantDelta {
                        context_id: context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        text,
                    });
                }
                if let Some((total_tokens, context_window)) = state.planning_usage.take() {
                    state.events.push_back(AgentEvent::UsageUpdated {
                        context_id: context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        usage: carl::runtime::agent_port::AgentUsage {
                            last_total_tokens: total_tokens,
                            total_tokens,
                            model_context_window: Some(context_window),
                        },
                    });
                }
                state.events.push_back(AgentEvent::EpochCompleted {
                    context_id,
                    epoch_id: epoch_id.clone(),
                    status: "completed".into(),
                });
            } else {
                state.work_number += 1;
                let work_number = state.work_number;
                let Some((kind, _, _)) = state.work.front().copied() else {
                    return Err(AgentPortError::definitely_not_applied(
                        AgentPortErrorCode::Transport,
                    ));
                };
                let item_id = format!("work-item-{work_number}");
                state.current_item_id = Some(item_id.clone());
                let item = work_item_with_process(
                    kind,
                    &item_id,
                    "inProgress",
                    state.started_process.as_ref(),
                );
                let item = work_item_with_file_change_path(item, &state.file_change_path);
                if state.implicit_observation_first && work_number == 1 {
                    let message = AgentItem::Other {
                        item_id: "provider-message-1".into(),
                        item_type: "agentMessage".into(),
                    };
                    state.events.push_back(AgentEvent::ItemStarted {
                        context_id: context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        item: message.clone(),
                    });
                    state.events.push_back(AgentEvent::ItemCompleted {
                        context_id: context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        item: message,
                    });
                }
                state.events.push_back(AgentEvent::ItemStarted {
                    context_id: context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    item,
                });
                if state.implicit_observation_first && work_number == 1 {
                    state.events.push_back(AgentEvent::ItemCompleted {
                        context_id: context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        item: work_item(WorkKind::Command, &item_id, "completed"),
                    });
                    state.events.push_back(AgentEvent::AssistantDelta {
                        context_id: context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        text: concat!(
                            "<carl-epoch-report>{\"schema_version\":1,",
                            "\"disposition\":\"continue\",",
                            "\"summary\":\"Inspected repository state\",",
                            "\"next_objective\":\"Implement the repair\",",
                            "\"clause_evidence\":[],\"exact_identifiers\":[]}",
                            "</carl-epoch-report>"
                        )
                        .to_owned(),
                    });
                    state.events.push_back(AgentEvent::EpochCompleted {
                        context_id,
                        epoch_id: epoch_id.clone(),
                        status: "completed".into(),
                    });
                    state.current_item_id = None;
                    state.work.pop_front();
                    return Ok(epoch_id);
                }
                let effect_kind = state.work_effect_kind.unwrap_or(match kind {
                    WorkKind::Command => AgentEffectKind::Command,
                    WorkKind::FileChange => AgentEffectKind::FileChange,
                });
                let effect_summary = state
                    .work_effect_summary
                    .clone()
                    .unwrap_or_else(|| "bounded scripted work".into());
                state
                    .events
                    .push_back(AgentEvent::EffectRequested(AgentEffectRequest {
                        context_id,
                        epoch_id: epoch_id.clone(),
                        request_id: AgentRequestId::parse(format!("request-{epoch_number}"))?,
                        item_id,
                        kind: effect_kind,
                        summary: effect_summary,
                        request_digest: Sha256Digest::parse(format!("{:064x}", epoch_number))
                            .expect("fixed digest is valid"),
                    }));
            }
            Ok(epoch_id)
        })
    }

    fn steer(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
        text: String,
    ) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut state = state.lock().unwrap();
            if text.starts_with("carl-operation-id:")
                && let Some(provenance) = state.binding_failure.take()
            {
                return Err(scripted_error(provenance));
            }
            if text.starts_with("Carl soft epoch boundary")
                && let Some(provenance) = state.soft_boundary_failure.take()
            {
                return Err(scripted_error(provenance));
            }
            if text.starts_with("Carl soft epoch boundary") && state.soft_boundary_unsupported {
                state.soft_boundary_unsupported = false;
                return Err(AgentPortError::from_code(AgentPortErrorCode::Unsupported));
            }
            state.steers.push(text.clone());
            if let Some(operation_id) = text.strip_prefix("carl-operation-id:") {
                state.latest_operation_id = Some(operation_id.trim().to_owned());
            }
            Ok(())
        })
    }

    fn interrupt(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
    ) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().unwrap().interrupts += 1;
            Ok(())
        })
    }

    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let pending_after_item_started = {
                let state = state.lock().unwrap();
                state.pending_after_item_started
                    && matches!(state.events.front(), Some(AgentEvent::EffectRequested(_)))
            };
            if pending_after_item_started {
                return std::future::pending().await;
            }
            let pending_work_stream = {
                let mut state = state.lock().unwrap();
                if let Some(event) = state.events.pop_front() {
                    if matches!(event, AgentEvent::ItemStarted { .. }) {
                        state.item_started_deliveries += 1;
                    }
                    return Ok(event);
                }
                (state.pending_work_stream && state.latest_operation_id.is_some())
                    || (state.pending_planning_stream && state.work_number == 0)
            };
            if pending_work_stream {
                return std::future::pending().await;
            }
            let mut state = state.lock().unwrap();
            if let Some(PlanningFault::Next(provenance)) = state.planning_fault.take() {
                return Err(scripted_error(provenance));
            }
            if state.latest_operation_id.is_some()
                && let Some(fault) = state.work_fault.take()
            {
                let context_id = AgentContextId::parse(state.active_context_id.clone())?;
                let epoch_id = AgentEpochId::parse(format!("engine-epoch-{}", state.epoch_number))?;
                return match fault {
                    WorkFault::DuplicateItemStarted => Ok(AgentEvent::ItemStarted {
                        context_id,
                        epoch_id,
                        item: work_item(
                            WorkKind::Command,
                            state
                                .current_item_id
                                .as_deref()
                                .expect("the active item is known"),
                            "inProgress",
                        ),
                    }),
                    WorkFault::UnexpectedEvent => Ok(AgentEvent::AssistantDelta {
                        context_id: AgentContextId::parse("foreign-context")?,
                        epoch_id,
                        text: "unexpected cross-bound event".to_owned(),
                    }),
                };
            }
            if state.ambiguous_event_failure && state.latest_operation_id.is_some() {
                state.ambiguous_event_failure = false;
                return Err(AgentPortError::from_code(AgentPortErrorCode::Transport));
            }
            if state.definitely_not_applied_event_failure && state.latest_operation_id.is_some() {
                state.definitely_not_applied_event_failure = false;
                return Err(AgentPortError::definitely_not_applied(
                    AgentPortErrorCode::Transport,
                ));
            }
            if state.invalid_event_after_binding && state.latest_operation_id.is_some() {
                state.invalid_event_after_binding = false;
                return Ok(AgentEvent::AssistantDelta {
                    context_id: AgentContextId::parse(state.active_context_id.clone())?,
                    epoch_id: AgentEpochId::parse(format!("engine-epoch-{}", state.epoch_number))?,
                    text: "x".repeat(1_048_577),
                });
            }
            let (kind, summary, disposition) = state.work.front().copied().expect("scripted event");
            let epoch_number = state.epoch_number;
            let work_number = state.work_number;
            let context_id = AgentContextId::parse(state.active_context_id.clone())?;
            let epoch_id = AgentEpochId::parse(format!("engine-epoch-{epoch_number}"))?;
            let item_id = state
                .current_item_id
                .clone()
                .expect("the active work item is known");
            let operation_id = state
                .latest_operation_id
                .take()
                .expect("engine reports the durable operation binding");
            let completed_item = work_item_with_process(
                kind,
                &item_id,
                if state.resolved.last() == Some(&EffectDecision::Deny) {
                    "failed"
                } else {
                    "completed"
                },
                state.completed_process.as_ref(),
            );
            let completed_item =
                work_item_with_file_change_path(completed_item, &state.file_change_path);
            state.events.push_back(AgentEvent::ItemCompleted {
                context_id: context_id.clone(),
                epoch_id: epoch_id.clone(),
                item: completed_item,
            });
            if state.additional_effects_in_epoch > 0 {
                state.additional_effects_in_epoch -= 1;
                let extra_number = state.additional_effects_in_epoch + 1;
                let next_item_id = format!("work-item-{work_number}-extra-{extra_number}");
                state.current_item_id = Some(next_item_id.clone());
                state.events.push_back(AgentEvent::ItemStarted {
                    context_id: context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    item: work_item(kind, &next_item_id, "inProgress"),
                });
                state
                    .events
                    .push_back(AgentEvent::EffectRequested(AgentEffectRequest {
                        context_id,
                        epoch_id,
                        request_id: AgentRequestId::parse(format!(
                            "request-{epoch_number}-extra-{extra_number}"
                        ))?,
                        item_id: next_item_id,
                        kind: match kind {
                            WorkKind::Command => AgentEffectKind::Command,
                            WorkKind::FileChange => AgentEffectKind::FileChange,
                        },
                        summary: "second bounded scripted work".into(),
                        request_digest: Sha256Digest::parse(format!(
                            "{:064x}",
                            epoch_number * 100 + extra_number
                        ))
                        .expect("fixed digest is valid"),
                    }));
                return Ok(state.events.pop_front().expect("completion event queued"));
            }
            state.current_item_id = None;
            state.work.pop_front();
            if let Some((total_tokens, context_window)) = state.usage.take() {
                let last_total_tokens = state.usage_last_total.take().unwrap_or(total_tokens);
                state.events.push_back(AgentEvent::UsageUpdated {
                    context_id: context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    usage: carl::runtime::agent_port::AgentUsage {
                        last_total_tokens,
                        total_tokens,
                        model_context_window: Some(context_window),
                    },
                });
            }
            if state.post_usage_diff_bytes > 0 {
                let diff = "d".repeat(state.post_usage_diff_bytes);
                state.events.push_back(AgentEvent::DiffUpdated {
                    context_id: context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    diff,
                });
            }
            if state.oversized_work_stream {
                for chunk in *b"abcd" {
                    state.events.push_back(AgentEvent::AssistantDelta {
                        context_id: context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        text: char::from(chunk).to_string().repeat(80 * 1024),
                    });
                }
            }
            if state.oversized_diff_stream {
                for chunk in *b"ab" {
                    state.events.push_back(AgentEvent::DiffUpdated {
                        context_id: context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        diff: char::from(chunk).to_string().repeat(600 * 1024),
                    });
                }
            }
            let (disposition, next_objective, clauses) = if let Some(next) =
                disposition.strip_prefix("continue:")
            {
                (
                    "continue",
                    format!(",\"next_objective\":{next:?}"),
                    String::new(),
                )
            } else {
                let clause_ids = disposition
                    .strip_prefix("complete:")
                    .expect("complete script")
                    .split(',');
                let clauses = clause_ids
                    .map(|clause_id| {
                        format!("{{\"clause_id\":{clause_id:?},\"operation_ids\":[{operation_id:?}],\"event_sequences\":[],\"artifact_digests\":[]}}")
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                ("complete", String::new(), clauses)
            };
            let report = if state.invalid_work_report {
                "malformed terminal report".to_owned()
            } else {
                format!(
                    "<carl-epoch-report>{{\"schema_version\":1,\"disposition\":{disposition:?},\"summary\":{summary:?}{next_objective},\"clause_evidence\":[{clauses}],\"exact_identifiers\":[]}}</carl-epoch-report>"
                )
            };
            state.events.push_back(AgentEvent::AssistantDelta {
                context_id: context_id.clone(),
                epoch_id: epoch_id.clone(),
                text: report,
            });
            let terminal_status = state.terminal_statuses.pop_front().unwrap_or("completed");
            state.events.push_back(AgentEvent::EpochCompleted {
                context_id,
                epoch_id,
                status: terminal_status.into(),
            });
            Ok(state.events.pop_front().expect("completion event queued"))
        })
    }

    fn resolve_effect(
        &mut self,
        _request_id: &AgentRequestId,
        decision: EffectDecision,
    ) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let (failure, pending) = {
                let mut state = state.lock().unwrap();
                state.resolved.push(decision);
                let pending = state.pending_resolve;
                if decision == EffectDecision::Allow && !pending {
                    state.durable_effect_count = state.durable_effect_count.saturating_add(1);
                    if let Some((path, contents)) = state.file_mutation.clone() {
                        state.durable_mutation_count =
                            state.durable_mutation_count.saturating_add(1);
                        fs::create_dir_all(path.parent().expect("the file has a parent"))
                            .expect("the fake creates the mutation parent");
                        fs::write(path, contents).expect("the fake applies the file mutation");
                    }
                }
                (state.resolve_failure.take(), pending)
            };
            if let Some(provenance) = failure {
                return Err(scripted_error(provenance));
            }
            if pending {
                return std::future::pending().await;
            }
            Ok(())
        })
    }

    fn list_background_processes(
        &mut self,
        _context_id: &AgentContextId,
    ) -> AgentFuture<'_, Vec<AgentProcess>> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut state = state.lock().unwrap();
            state.background_lists += 1;
            Ok(state.background_processes.clone())
        })
    }

    fn terminate_background_process(
        &mut self,
        _context_id: &AgentContextId,
        process_id: &str,
    ) -> AgentFuture<'_, bool> {
        let state = Arc::clone(&self.state);
        let process_id = process_id.to_owned();
        Box::pin(async move {
            let mut state = state.lock().unwrap();
            state.terminations.push(process_id);
            Ok(state.termination_result)
        })
    }

    fn shutdown(&mut self) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

const fn scripted_error(provenance: AgentErrorProvenance) -> AgentPortError {
    match provenance {
        AgentErrorProvenance::DefinitelyNotApplied => {
            AgentPortError::definitely_not_applied(AgentPortErrorCode::Transport)
        }
        AgentErrorProvenance::PossiblyApplied => {
            AgentPortError::from_code(AgentPortErrorCode::Transport)
        }
    }
}

fn work_item(kind: WorkKind, item_id: &str, status: &str) -> AgentItem {
    work_item_with_process(kind, item_id, status, None)
}

fn work_item_with_process(
    kind: WorkKind,
    item_id: &str,
    status: &str,
    process: Option<&AgentProcess>,
) -> AgentItem {
    match kind {
        WorkKind::Command => AgentItem::Command {
            item_id: item_id.into(),
            command: process.map_or_else(|| "cargo test".into(), |process| process.command.clone()),
            cwd: process.map_or_else(
                || PathBuf::from("/workspace"),
                |process| process.cwd.clone(),
            ),
            status: status.into(),
            exit_code: (status == "completed").then_some(0),
            aggregated_output: Some("ok".into()),
            process_id: process.map(|process| process.process_id.clone()),
        },
        WorkKind::FileChange => AgentItem::FileChange {
            item_id: item_id.into(),
            status: status.into(),
            changes: json!([{"path":"src/lib.rs","kind":"update"}]),
        },
    }
}

fn work_item_with_file_change_path(item: AgentItem, path: &str) -> AgentItem {
    match item {
        AgentItem::FileChange {
            item_id, status, ..
        } => AgentItem::FileChange {
            item_id,
            status,
            changes: json!([{"path":path,"kind":"update"}]),
        },
        item => item,
    }
}

fn start_task(session_id: SessionId, workspace: &Path) -> TestResult<StartTask> {
    Ok(StartTask {
        session_id,
        workspace: workspace.to_owned(),
        request: "Fix the parser and prove the fix".into(),
        model: ModelId::parse("gpt-5.6-codex")?,
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::BypassPermissions,
        budget: TaskBudget::default(),
    })
}

fn only_operation_status(store: &Store, task_id: TaskId) -> TestResult<OperationStatus> {
    let operation_id = store
        .read_task_events(task_id)?
        .into_iter()
        .find_map(|envelope| match envelope.event {
            carl::events::Event::TaskLifecycle {
                event: carl::runtime::task::TaskEvent::OperationIntentRecorded { operation_id, .. },
                ..
            } => Some(operation_id),
            _ => None,
        })
        .expect("one operation intent is durable");
    Ok(store
        .get_task(task_id)?
        .expect("task remains projected")
        .snapshot
        .operation_status(operation_id)
        .expect("operation remains projected"))
}

fn operation_statuses(store: &Store, task_id: TaskId) -> TestResult<Vec<OperationStatus>> {
    let operation_ids = store
        .read_task_events(task_id)?
        .into_iter()
        .filter_map(|envelope| match envelope.event {
            carl::events::Event::TaskLifecycle {
                event: carl::runtime::task::TaskEvent::OperationIntentRecorded { operation_id, .. },
                ..
            } => Some(operation_id),
            _ => None,
        })
        .collect::<Vec<_>>();
    let snapshot = store
        .get_task(task_id)?
        .expect("task remains projected")
        .snapshot;
    Ok(operation_ids
        .into_iter()
        .map(|operation_id| {
            snapshot
                .operation_status(operation_id)
                .expect("operation remains projected")
        })
        .collect())
}

#[tokio::test(flavor = "current_thread")]
async fn task_and_context_binding_precede_the_first_planning_provider_request() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut engine = TaskEngine::new(store, EnginePort::small_edit());

    let snapshot = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await?;
    let events = engine.store().read_task_events(snapshot.task_id)?;
    let created = events
        .iter()
        .position(|envelope| {
            matches!(
                envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::Created { .. },
                    ..
                }
            )
        })
        .expect("task creation is durable");
    let bound = events
        .iter()
        .position(|envelope| {
            matches!(
                envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::ProviderContextBound { .. },
                    ..
                }
            )
        })
        .expect("provider context binding is durable");
    let planning_request = events
        .iter()
        .position(|envelope| {
            matches!(
                envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::ProviderRequestRecorded {
                        purpose: ProviderRequestPurpose::ContractPlanning,
                        ..
                    },
                    ..
                }
            )
        })
        .expect("planning provider request is durable");

    assert!(created < bound && bound < planning_request);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn multiline_frontend_requests_create_a_valid_durable_fallback_contract() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut engine = TaskEngine::new(store, EnginePort::small_edit());
    let mut input = start_task(session.id, &fixture.workspace)?;
    input.request = "Event ID: abc\nChannel: test\nContent: verify the repository".into();

    let snapshot = engine.start(input).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    assert!(!snapshot.contract.goal.chars().any(char::is_control));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_contract_repair_records_exactly_two_planning_provider_requests() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut engine = TaskEngine::new(store, EnginePort::repaired_contract());

    let snapshot = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await?;
    let requests = engine
        .store()
        .read_task_events(snapshot.task_id)?
        .into_iter()
        .filter_map(|envelope| match envelope.event {
            carl::events::Event::TaskLifecycle {
                event:
                    carl::runtime::task::TaskEvent::ProviderRequestRecorded {
                        purpose,
                        request_sequence,
                        ..
                    },
                ..
            } => Some((purpose, request_sequence)),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert_eq!(
        requests,
        [
            (ProviderRequestPurpose::ContractPlanning, 0),
            (ProviderRequestPurpose::ContractPlanning, 1),
            (ProviderRequestPurpose::Work, 2),
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restart_rehydrates_exact_planning_and_work_request_accounting() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut first = TaskEngine::new(store, EnginePort::repaired_contract_then_unavailable_work());
    let mut input = start_task(session.id, &fixture.workspace)?;
    input.budget.max_provider_requests = Some(4);

    assert_eq!(
        first.start(input).await.unwrap_err().code(),
        carl::runtime::task::TaskEngineErrorCode::Provider
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let (store, _) = first.into_parts();
    let mut resumed = TaskEngine::new(store, EnginePort::resume_small_edit());

    let snapshot = resumed.run(task_id).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    let sequences = resumed
        .store()
        .read_task_events(task_id)?
        .into_iter()
        .filter_map(|envelope| match envelope.event {
            carl::events::Event::TaskLifecycle {
                event:
                    carl::runtime::task::TaskEvent::ProviderRequestRecorded {
                        request_sequence, ..
                    },
                ..
            } => Some(request_sequence),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(sequences, [0, 1, 2, 3]);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn planning_usage_is_durable_and_triggers_context_compaction() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::planning_usage_under_context_pressure();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let snapshot = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await?;

    assert!(
        engine
            .store()
            .read_task_events(snapshot.task_id)?
            .iter()
            .any(|envelope| matches!(
                envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::UsageObserved {
                        total_tokens: 102_400,
                        ..
                    },
                    ..
                }
            ))
    );
    assert_eq!(shared.lock().unwrap().compactions, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn missing_provider_usage_uses_conservative_planning_estimates_for_compaction() -> TestResult
{
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::fallback_contract_under_estimated_pressure();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let snapshot = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    assert_eq!(shared.lock().unwrap().planning_attempts, 2);
    assert_eq!(shared.lock().unwrap().compactions, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn post_usage_assistant_and_diff_bytes_are_merged_before_terminal_compaction() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::post_usage_diff_pressure();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let snapshot = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await?;

    let totals = engine
        .store()
        .read_task_events(snapshot.task_id)?
        .into_iter()
        .filter_map(|envelope| match envelope.event {
            carl::events::Event::TaskLifecycle {
                event: carl::runtime::task::TaskEvent::UsageObserved { total_tokens, .. },
                ..
            } => Some(total_tokens),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(totals.contains(&101_000));
    assert!(totals.last().is_some_and(|total| *total >= 105_096));
    assert_eq!(shared.lock().unwrap().compactions, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn one_owner_request_runs_three_durable_epochs_to_evidenced_completion() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::three_epochs();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let snapshot = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    assert!(snapshot.contract.required_clauses_satisfied());
    assert!(
        snapshot.contract.clauses.iter().all(|clause| {
            clause.status == ClauseStatus::Satisfied && !clause.evidence.is_empty()
        })
    );
    let connection = Connection::open(&fixture.database)?;
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM task_epochs", [], |row| row
            .get::<_, u64>(0))?,
        4,
        "one durable planning epoch plus three durable work epochs"
    );
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM task_checkpoints", [], |row| row
            .get::<_, u64>(0))?,
        3
    );
    assert_eq!(
        engine
            .store()
            .read_task_events(snapshot.task_id)?
            .iter()
            .filter(|event| matches!(
                event.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::ProviderContextBound { .. },
                    ..
                }
            ))
            .count(),
        1
    );
    let state = shared.lock().unwrap();
    assert_eq!(state.context_starts, 1);
    assert_eq!(
        state.epoch_starts.len(),
        4,
        "one planner plus three work epochs"
    );
    assert_eq!(state.resolved, vec![EffectDecision::Allow; 3]);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn small_full_access_edit_uses_one_plan_one_work_and_no_compaction_ceremony() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::small_edit();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let snapshot = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    let state = shared.lock().unwrap();
    assert_eq!(state.epoch_starts.len(), 2);
    assert_eq!(state.epoch_starts[0].permission_mode, PermissionMode::Plan);
    assert_eq!(
        state.epoch_starts[1].permission_mode,
        PermissionMode::BypassPermissions
    );
    assert!(
        state.epoch_starts[1].input.contains(concat!(
            "<carl-epoch-report>{\"schema_version\":1,",
            "\"disposition\":\"continue\",",
            "\"summary\":\"Describe verified progress\",",
            "\"next_objective\":\"State one bounded next objective\",",
            "\"clause_evidence\":[],\"exact_identifiers\":[]}",
            "</carl-epoch-report>"
        )),
        "the live provider receives the exact terminal report schema"
    );
    assert!(
        state.epoch_starts[1].input.contains(concat!(
            "{\"clause_id\":\"exact-clause-id\",",
            "\"operation_ids\":[\"successful-operation-uuid\"],",
            "\"event_sequences\":[],\"artifact_digests\":[]}"
        )),
        "complete reports receive the full deny-unknown-fields clause evidence schema"
    );
    assert!(
        state.epoch_starts[1]
            .input
            .contains("\"exact_identifiers\":[\"literal-string-only\"]"),
        "exact identifiers are explicitly declared as strings rather than objects"
    );
    assert!(
        state.epoch_starts[1].input.contains(
            "The provider base sandbox is intentionally read-only. Request Carl approval for every mutation"
        ),
        "the provider is told how to cross the Carl-owned mutation boundary"
    );
    assert_eq!(state.compactions, 0);
    assert_eq!(state.replacements, 0);
    assert_eq!(state.resolved, [EffectDecision::Allow]);
    assert!(
        engine
            .take_updates()
            .iter()
            .all(|update| !matches!(update, TaskEngineUpdate::PermissionRequired { .. }))
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn provider_absolute_file_change_under_workspace_is_normalized() -> TestResult {
    let fixture = EngineFixture::new()?;
    let absolute_path = fixture.workspace.join("src/lib.rs");
    let absolute_path = absolute_path.to_str().expect("the test workspace is UTF-8");
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::file_effect_with_path(
        &fixture.workspace,
        absolute_path,
        b"pub fn fixed() -> bool { true }\n",
    );
    let mut engine = TaskEngine::new(store, port);

    let snapshot = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    let checkpoint = engine
        .store()
        .get_latest_task_checkpoint(snapshot.task_id)?
        .expect("completion commits a checkpoint");
    assert!(checkpoint.repository.file_hashes.contains_key("src/lib.rs"));
    assert!(
        !checkpoint
            .repository
            .file_hashes
            .contains_key(absolute_path)
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn exhausted_provider_budget_is_durably_blocked_before_work_dispatch() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::small_edit();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);
    let mut input = start_task(session.id, &fixture.workspace)?;
    input.budget.max_provider_requests = Some(1);

    let error = engine.start(input).await.unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let resumable = engine.store().list_resumable_tasks()?;
    assert_eq!(resumable.len(), 1);
    assert_eq!(resumable[0].snapshot.status, TaskStatus::Blocked);
    assert_eq!(
        shared.lock().unwrap().epoch_starts.len(),
        1,
        "the read-only planning request consumes the entire provider budget"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn exhausted_wall_budget_blocks_before_the_first_provider_request() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::small_edit();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);
    let mut input = start_task(session.id, &fixture.workspace)?;
    input.budget.max_wall_time_seconds = Some(0);

    let error = engine.start(input).await.unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert!(shared.lock().unwrap().epoch_starts.is_empty());
    assert_eq!(
        engine.store().list_resumable_tasks()?[0].snapshot.status,
        TaskStatus::Blocked
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn hard_tool_budget_interrupts_the_current_stream_before_a_second_effect_dispatch()
-> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::two_effects_in_one_epoch();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);
    let mut input = start_task(session.id, &fixture.workspace)?;
    input.budget.max_tool_calls = Some(1);

    let error = engine.start(input).await.unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    let state = shared.lock().unwrap();
    assert_eq!(state.resolved, [EffectDecision::Allow]);
    assert_eq!(state.interrupts, 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn hard_wall_budget_interrupts_a_pending_effect_inside_the_provider_stream() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::pending_resolve();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);
    let mut input = start_task(session.id, &fixture.workspace)?;
    input.budget.max_wall_time_seconds = Some(60);

    let error = tokio::time::timeout(std::time::Duration::from_secs(65), engine.start(input))
        .await
        .expect("hard wall budget must wake a pending provider read")
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    assert_eq!(
        only_operation_status(engine.store(), record.snapshot.task_id)?,
        OperationStatus::Uncertain
    );
    assert_eq!(shared.lock().unwrap().interrupts, 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn hard_wall_budget_covers_pending_allow_resolution_and_closes_the_epoch() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::pending_resolve();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);
    let mut input = start_task(session.id, &fixture.workspace)?;
    input.budget.max_wall_time_seconds = Some(60);

    let error = tokio::time::timeout(std::time::Duration::from_secs(65), engine.start(input))
        .await
        .expect("hard wall budget must wake a pending allow resolution")
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    assert_eq!(record.snapshot.active_epoch, None);
    assert_eq!(
        only_operation_status(engine.store(), record.snapshot.task_id)?,
        OperationStatus::Uncertain
    );
    let state = shared.lock().unwrap();
    assert_eq!(state.resolved, [EffectDecision::Allow]);
    assert_eq!(state.interrupts, 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn hard_wall_budget_interrupts_a_pending_contract_planning_stream() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::pending_planning();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);
    let mut input = start_task(session.id, &fixture.workspace)?;
    input.budget.max_wall_time_seconds = Some(60);

    let error = tokio::time::timeout(std::time::Duration::from_secs(65), engine.start(input))
        .await
        .expect("hard wall budget must wake a pending planning read")
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(
        engine.store().list_resumable_tasks()?[0].snapshot.status,
        TaskStatus::Blocked
    );
    assert_eq!(shared.lock().unwrap().interrupts, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn aggregate_contract_planning_output_is_bounded_across_individually_valid_deltas()
-> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::oversized_planning_stream();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let error = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(
        engine.store().list_resumable_tasks()?[0].snapshot.status,
        TaskStatus::Blocked
    );
    assert_eq!(shared.lock().unwrap().interrupts, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn aggregate_work_transcript_and_engine_updates_are_bounded_across_valid_deltas() -> TestResult
{
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::oversized_work_stream();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let error = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(
        engine.store().list_resumable_tasks()?[0].snapshot.status,
        TaskStatus::Blocked
    );
    let updates = engine.take_updates();
    let streamed_bytes = updates
        .iter()
        .filter_map(|update| match update {
            TaskEngineUpdate::AgentMessageChunk(text) | TaskEngineUpdate::DiffUpdated(text) => {
                Some(text.len())
            }
            _ => None,
        })
        .sum::<usize>();
    assert!(streamed_bytes <= 256 * 1024);
    assert!(updates.len() <= 4_096);
    assert_eq!(shared.lock().unwrap().interrupts, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn aggregate_diff_updates_are_bounded_across_individually_valid_events() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::oversized_diff_stream();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let error = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(
        engine.store().list_resumable_tasks()?[0].snapshot.status,
        TaskStatus::Blocked
    );
    assert_eq!(shared.lock().unwrap().interrupts, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn provider_event_count_is_bounded_even_when_events_have_no_transcript_payload() -> TestResult
{
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::planning_event_flood();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let error = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(
        engine.store().list_resumable_tasks()?[0].snapshot.status,
        TaskStatus::Blocked
    );
    assert_eq!(shared.lock().unwrap().interrupts, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn planning_provider_faults_close_the_epoch_and_return_typed_blocked() -> TestResult {
    for fault in [
        PlanningFault::Next(AgentErrorProvenance::DefinitelyNotApplied),
        PlanningFault::Next(AgentErrorProvenance::PossiblyApplied),
        PlanningFault::Invalid,
        PlanningFault::Unexpected,
    ] {
        let fixture = EngineFixture::new()?;
        let store = Store::open(&fixture.database)?;
        let session = store.create_session()?;
        let mut engine = TaskEngine::new(store, EnginePort::planning_fault(fault));

        let error = engine
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err();

        assert_eq!(
            error.code(),
            carl::runtime::task::TaskEngineErrorCode::Blocked
        );
        let record = engine.store().list_resumable_tasks()?.remove(0);
        assert_eq!(record.snapshot.status, TaskStatus::Blocked);
        assert_eq!(record.snapshot.active_epoch, None);
        assert!(engine.take_updates().iter().any(|update| matches!(
            update,
            TaskEngineUpdate::TaskStatus {
                status: TaskStatus::Blocked,
                ..
            }
        )));
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn provider_implicit_read_is_recorded_as_a_durable_observation() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::implicit_observation_then_edit();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let snapshot = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    let events = engine.store().read_task_events(snapshot.task_id)?;
    let classes = events
        .iter()
        .filter_map(|envelope| match &envelope.event {
            carl::events::Event::TaskLifecycle {
                event: carl::runtime::task::TaskEvent::OperationIntentRecorded { effect_class, .. },
                ..
            } => Some(*effect_class),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        classes,
        vec![EffectClass::Observation, EffectClass::IdempotentMutation]
    );
    assert_eq!(
        operation_statuses(engine.store(), snapshot.task_id)?,
        vec![OperationStatus::Succeeded, OperationStatus::Succeeded]
    );
    assert_eq!(shared.lock().unwrap().resolved, vec![EffectDecision::Allow]);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn work_sequencing_catch_all_and_soft_steer_faults_close_before_blocking() -> TestResult {
    for port in [
        EnginePort::work_fault(WorkFault::DuplicateItemStarted),
        EnginePort::work_fault(WorkFault::UnexpectedEvent),
        EnginePort::soft_boundary_failure(AgentErrorProvenance::PossiblyApplied),
    ] {
        let fixture = EngineFixture::new()?;
        let store = Store::open(&fixture.database)?;
        let session = store.create_session()?;
        let shared = port.shared();
        let mut engine = TaskEngine::new(store, port);
        let mut input = start_task(session.id, &fixture.workspace)?;
        input.budget.soft_epoch_tool_calls = 1;

        let error = engine.start(input).await.unwrap_err();

        assert_eq!(
            error.code(),
            carl::runtime::task::TaskEngineErrorCode::Blocked
        );
        let record = engine.store().list_resumable_tasks()?.remove(0);
        assert_eq!(record.snapshot.status, TaskStatus::Blocked);
        assert_eq!(record.snapshot.active_epoch, None);
        assert!(
            operation_statuses(engine.store(), record.snapshot.task_id)?
                .iter()
                .all(|status| *status != OperationStatus::Started)
        );
        assert_eq!(shared.lock().unwrap().interrupts, 1);
        assert!(engine.take_updates().iter().any(|update| matches!(
            update,
            TaskEngineUpdate::TaskStatus {
                status: TaskStatus::Blocked,
                ..
            }
        )));
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ambiguous_provider_failure_marks_started_operation_uncertain_and_blocks() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut engine = TaskEngine::new(store, EnginePort::ambiguous_event_failure());

    let error = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    assert_eq!(record.snapshot.active_epoch, None);
    let operation_id = engine
        .store()
        .read_task_events(record.snapshot.task_id)?
        .into_iter()
        .find_map(|event| match event.event {
            carl::events::Event::TaskLifecycle {
                event: carl::runtime::task::TaskEvent::OperationIntentRecorded { operation_id, .. },
                ..
            } => Some(operation_id),
            _ => None,
        })
        .expect("operation intent is durable");
    assert_eq!(
        record.snapshot.operation_status(operation_id),
        Some(OperationStatus::Uncertain)
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn possibly_applied_effect_resolution_failure_is_uncertain_and_typed_blocked() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::resolve_failure(AgentErrorProvenance::PossiblyApplied);
    let mut engine = TaskEngine::new(store, port);

    let error = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    assert_eq!(
        only_operation_status(engine.store(), record.snapshot.task_id)?,
        OperationStatus::Uncertain
    );
    assert!(engine.take_updates().iter().any(|update| matches!(
        update,
        TaskEngineUpdate::TaskStatus {
            status: TaskStatus::Blocked,
            ..
        }
    )));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn definitely_not_applied_effect_resolution_failure_closes_failed_and_blocks() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::resolve_failure(AgentErrorProvenance::DefinitelyNotApplied);
    let mut engine = TaskEngine::new(store, port);

    let error = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    assert_eq!(
        only_operation_status(engine.store(), record.snapshot.task_id)?,
        OperationStatus::Failed
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn definitely_not_applied_event_read_is_retried_without_replaying_the_effect() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::definitely_not_applied_event_failure();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let snapshot = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    assert_eq!(shared.lock().unwrap().resolved, [EffectDecision::Allow]);
    assert_eq!(shared.lock().unwrap().epoch_starts.len(), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_provider_event_after_effect_binding_closes_uncertain_and_blocks() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut engine = TaskEngine::new(store, EnginePort::invalid_event_after_binding());

    let error = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    assert_eq!(
        only_operation_status(engine.store(), record.snapshot.task_id)?,
        OperationStatus::Uncertain
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn definitely_not_applied_operation_binding_failure_closes_failed_and_blocks() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut engine = TaskEngine::new(
        store,
        EnginePort::binding_failure(AgentErrorProvenance::DefinitelyNotApplied),
    );

    let error = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    assert_eq!(
        only_operation_status(engine.store(), record.snapshot.task_id)?,
        OperationStatus::Failed
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unsupported_network_effect_is_denied_before_durable_blocking() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::unsupported_network_effect();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let error = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(shared.lock().unwrap().resolved, [EffectDecision::Deny]);
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    assert_eq!(
        only_operation_status(engine.store(), record.snapshot.task_id)?,
        OperationStatus::Failed
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn uncertain_work_dispatch_failure_returns_typed_blocked_update() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::work_start_failure(AgentErrorProvenance::PossiblyApplied);
    let mut engine = TaskEngine::new(store, port);

    let error = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert!(engine.take_updates().iter().any(|update| matches!(
        update,
        TaskEngineUpdate::TaskStatus {
            status: TaskStatus::Blocked,
            ..
        }
    )));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_terminal_work_report_closes_the_epoch_and_blocks_restart() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut engine = TaskEngine::new(store, EnginePort::malformed_terminal_work_report());

    let error = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    assert_eq!(record.snapshot.active_epoch, None);
    assert!(
        operation_statuses(engine.store(), record.snapshot.task_id)?
            .iter()
            .all(|status| *status != OperationStatus::Started)
    );
    assert!(engine.take_updates().iter().any(|update| matches!(
        update,
        TaskEngineUpdate::TaskStatus {
            status: TaskStatus::Blocked,
            ..
        }
    )));

    let task_id = record.snapshot.task_id;
    let (store, _) = engine.into_parts();
    let mut restarted = TaskEngine::new(store, EnginePort::resume_small_edit());
    assert_eq!(
        restarted.run(task_id).await.unwrap_err().code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(
        restarted
            .store()
            .get_task(task_id)?
            .unwrap()
            .snapshot
            .active_epoch,
        None
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unsupported_soft_boundary_interrupt_closes_started_work_and_returns_blocked() -> TestResult
{
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::pending_effect_with_unsupported_soft_boundary();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);
    let mut input = start_task(session.id, &fixture.workspace)?;
    input.budget.soft_epoch_seconds = 1;

    let error = tokio::time::timeout(Duration::from_secs(3), engine.start(input))
        .await
        .expect("unsupported boundary steering must not strand the interrupted epoch")
        .unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    assert_eq!(record.snapshot.active_epoch, None);
    assert_eq!(
        only_operation_status(engine.store(), record.snapshot.task_id)?,
        OperationStatus::Uncertain
    );
    assert_eq!(shared.lock().unwrap().interrupts, 1);
    assert!(engine.take_updates().iter().any(|update| matches!(
        update,
        TaskEngineUpdate::TaskStatus {
            status: TaskStatus::Blocked,
            ..
        }
    )));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn recovery_attempt_outcomes_are_persisted_only_after_the_recovery_epoch_finishes()
-> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::new([
        (WorkKind::Command, "diagnosed", "continue:Repeat diagnosis"),
        (
            WorkKind::Command,
            "same diagnosis",
            "continue:Repeat diagnosis",
        ),
        (
            WorkKind::Command,
            "recovery failed",
            "continue:Repeat diagnosis",
        ),
        (
            WorkKind::Command,
            "independent verification passed",
            "complete:requested-outcome,explicit-verification",
        ),
    ]);
    port.state.lock().unwrap().terminal_statuses =
        VecDeque::from(["completed", "completed", "failed", "completed"]);
    let mut engine = TaskEngine::new(store, port);

    let snapshot = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await?;

    let events = engine
        .store()
        .read_task_events(snapshot.task_id)?
        .into_iter();
    let mut started = Vec::new();
    let mut attempts = Vec::new();
    for event in events {
        match event.event {
            carl::events::Event::TaskLifecycle {
                event:
                    carl::runtime::task::TaskEvent::RecoveryAttemptStarted {
                        epoch_id,
                        strategy,
                        strategy_fingerprint,
                    },
                ..
            } => started.push((epoch_id, strategy, strategy_fingerprint)),
            carl::events::Event::TaskLifecycle {
                event:
                    carl::runtime::task::TaskEvent::RecoveryAttemptRecorded {
                        epoch_id,
                        strategy,
                        strategy_fingerprint,
                        outcome,
                    },
                ..
            } => attempts.push((epoch_id, strategy, strategy_fingerprint, outcome)),
            _ => {}
        }
    }
    assert_eq!(started.len(), 2);
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].1, RecoveryStrategy::ReconstructFromEvidence);
    assert_eq!(attempts[0].3, RecoveryAttemptOutcome::Failed);
    assert_eq!(attempts[1].1, RecoveryStrategy::ReplaceApproach);
    assert_eq!(attempts[1].3, RecoveryAttemptOutcome::Succeeded);
    assert!(attempts.iter().all(|attempt| attempt.2.len() == 64));
    assert_eq!(
        started[0],
        (attempts[0].0, attempts[0].1, attempts[0].2.clone())
    );
    assert_eq!(
        started[1],
        (attempts[1].0, attempts[1].1, attempts[1].2.clone())
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn completed_tool_soft_limit_durably_requests_a_safe_boundary_before_steering() -> TestResult
{
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::small_edit();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);
    let mut input = start_task(session.id, &fixture.workspace)?;
    input.budget.soft_epoch_tool_calls = 1;

    let snapshot = engine.start(input).await?;

    let state = shared.lock().unwrap();
    let boundary_steer = state
        .steers
        .iter()
        .position(|steer| steer.contains("soft epoch boundary"))
        .expect("soft boundary is steered");
    assert!(
        boundary_steer > 0,
        "operation binding precedes boundary steering"
    );
    assert!(
        state.steers[boundary_steer].contains("<carl-epoch-report>")
            && state.steers[boundary_steer].contains("no text after the closing tag"),
        "boundary steering preserves the exact terminal report contract"
    );
    drop(state);
    assert!(
        engine
            .store()
            .read_task_events(snapshot.task_id)?
            .iter()
            .any(|event| matches!(
                event.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::SteeringQueued { .. },
                    ..
                }
            ))
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn effect_requested_after_soft_boundary_is_denied_before_dispatch_and_retried_next_epoch()
-> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::effect_after_soft_boundary_then_next_epoch();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);
    let mut input = start_task(session.id, &fixture.workspace)?;
    input.budget.soft_epoch_tool_calls = 1;

    let snapshot = engine.start(input).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    assert_eq!(
        shared.lock().unwrap().resolved,
        [
            EffectDecision::Allow,
            EffectDecision::Deny,
            EffectDecision::Allow
        ]
    );
    assert_eq!(
        operation_statuses(engine.store(), snapshot.task_id)?,
        [
            OperationStatus::Succeeded,
            OperationStatus::Failed,
            OperationStatus::Succeeded,
        ]
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn context_pressure_compacts_only_after_the_checkpoint_is_committed() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::small_edit_under_context_pressure();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let snapshot = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await?;

    let events = engine.store().read_task_events(snapshot.task_id)?;
    let checkpoint = events
        .iter()
        .position(|event| {
            matches!(
                event.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::CheckpointCommitted { .. },
                    ..
                }
            )
        })
        .expect("checkpoint committed");
    let requested = events
        .iter()
        .position(|event| {
            matches!(
                event.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::CompactionRequested { .. },
                    ..
                }
            )
        })
        .expect("compaction requested");
    let completed = events
        .iter()
        .position(|event| {
            matches!(
                event.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::CompactionCompleted { .. },
                    ..
                }
            )
        })
        .expect("compaction completed");
    assert!(checkpoint < requested && requested < completed);
    assert_eq!(shared.lock().unwrap().compactions, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cumulative_thread_usage_does_not_recompact_a_small_current_context() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::cumulative_usage_after_compaction();
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    let snapshot = engine
        .start(start_task(session.id, &fixture.workspace)?)
        .await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    assert_eq!(shared.lock().unwrap().compactions, 0);
    assert_eq!(
        engine
            .store()
            .task_metrics(snapshot.task_id)?
            .expect("completed task metrics exist")
            .compactions_completed,
        0
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn failed_checkpoint_transaction_recovers_as_blocked_without_repeating_completed_work()
-> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    Connection::open(&fixture.database)?.execute_batch(
        "CREATE TRIGGER fail_task_checkpoint
         BEFORE INSERT ON task_checkpoints
         BEGIN SELECT RAISE(ABORT, 'injected checkpoint crash'); END;",
    )?;
    let mut first = TaskEngine::new(store, EnginePort::small_edit());

    assert_eq!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Storage
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    assert_eq!(
        first.store().get_task(task_id)?.unwrap().snapshot.status,
        TaskStatus::Checkpointing
    );
    Connection::open(&fixture.database)?.execute_batch("DROP TRIGGER fail_task_checkpoint;")?;
    let (store, _) = first.into_parts();
    let port = EnginePort::resume_small_edit();
    let shared = port.shared();
    let mut resumed = TaskEngine::new(store, port);

    let error = resumed.run(task_id).await.unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(
        resumed.store().get_task(task_id)?.unwrap().snapshot.status,
        TaskStatus::Blocked
    );
    assert!(shared.lock().unwrap().epoch_starts.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn committed_completion_checkpoint_finishes_after_crash_without_another_provider_epoch()
-> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut first = TaskEngine::new(
        store,
        EnginePort::completion_checkpoint_then_compaction_failure(),
    );

    assert_eq!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Provider
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    assert_eq!(
        first.store().get_task(task_id)?.unwrap().snapshot.status,
        TaskStatus::Checkpointing
    );
    let (store, _) = first.into_parts();
    let port = EnginePort::resume_small_edit();
    let shared = port.shared();
    let mut resumed = TaskEngine::new(store, port);

    let snapshot = resumed.run(task_id).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    assert!(shared.lock().unwrap().epoch_starts.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn committed_continuation_checkpoint_resumes_next_epoch_without_repeating_completed_work()
-> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_then_compaction_failure(),
    );

    assert_eq!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Provider
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let (store, _) = first.into_parts();
    let port = EnginePort::resume_small_edit();
    let shared = port.shared();
    let mut resumed = TaskEngine::new(store, port);

    let snapshot = resumed.run(task_id).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    assert_eq!(shared.lock().unwrap().epoch_starts.len(), 1);
    assert_eq!(
        resumed
            .store()
            .read_task_events(task_id)?
            .iter()
            .filter(|envelope| matches!(
                envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::EpochStarted { .. },
                    ..
                }
            ))
            .count(),
        3,
        "planning, completed pre-crash work, and resumed work each start once"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restart_resumes_the_bound_provider_context_before_dispatching_the_next_epoch() -> TestResult
{
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_then_compaction_failure(),
    );
    assert_eq!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Provider
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let (store, _) = first.into_parts();
    let port = EnginePort::resume_small_edit();
    let shared = port.shared();
    let mut restarted = TaskEngine::new(store, port);

    let snapshot = restarted.run(task_id).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    let state = shared.lock().unwrap();
    assert_eq!(state.resume_attempts, ["engine-context"]);
    assert_eq!(state.epoch_starts.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unavailable_provider_context_is_journaled_then_replaced_for_fresh_diagnosis() -> TestResult
{
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_then_compaction_failure(),
    );
    assert_eq!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Provider
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let (store, _) = first.into_parts();
    let port = EnginePort::unavailable_context_then_small_edit();
    let shared = port.shared();
    let mut restarted = TaskEngine::new(store, port);

    let snapshot = restarted.run(task_id).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    let events = restarted.store().read_task_events(task_id)?;
    let lost = events
        .iter()
        .position(|envelope| {
            matches!(
                &envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::ProviderContextLost {
                        context_id,
                        ..
                    },
                    ..
                } if context_id == "engine-context"
            )
        })
        .expect("the unavailable old context is retained as lost history");
    let rebound = events
        .iter()
        .rposition(|envelope| {
            matches!(
                &envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::ProviderContextBound { context_id },
                    ..
                } if context_id == "replacement-context"
            )
        })
        .expect("the replacement context is durably bound");
    assert!(lost < rebound);
    let state = shared.lock().unwrap();
    assert_eq!(state.resume_attempts, ["engine-context"]);
    assert_eq!(state.replacements, 1);
    assert!(
        state.epoch_starts[0]
            .input
            .contains("Fresh provider context diagnosis")
    );
    drop(state);
    assert!(restarted.take_updates().iter().any(|update| matches!(
        update,
        TaskEngineUpdate::RecoveryStrategy {
            strategy: RecoveryStrategy::FreshContextDiagnosis,
            ..
        }
    )));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restart_after_provider_context_lost_starts_one_replacement_without_resuming_the_old_id()
-> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_then_compaction_failure(),
    );
    assert!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .is_err()
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let (mut store, _) = first.into_parts();
    let revision = store.get_task(task_id)?.unwrap().revision;
    store
        .append_task_event(
            task_id,
            revision,
            carl::runtime::task::TaskEvent::ProviderContextLost {
                context_id: "engine-context".to_owned(),
                reason: "injected crash after provider replacement started".to_owned(),
            },
            chrono::Utc::now(),
        )?
        .expect("provider loss is durable");
    let port = EnginePort::resume_small_edit();
    let shared = port.shared();
    let mut restarted = TaskEngine::new(store, port);

    let snapshot = restarted.run(task_id).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    let state = shared.lock().unwrap();
    assert!(state.resume_attempts.is_empty());
    assert_eq!(state.replacements, 1);
    assert!(
        state.epoch_starts[0]
            .input
            .contains("Fresh provider context diagnosis")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restart_after_replacement_binding_retains_fresh_context_diagnosis() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_then_compaction_failure(),
    );
    assert!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .is_err()
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let (mut store, _) = first.into_parts();
    for event in [
        carl::runtime::task::TaskEvent::ProviderContextLost {
            context_id: "engine-context".to_owned(),
            reason: "injected unavailable provider context".to_owned(),
        },
        carl::runtime::task::TaskEvent::ProviderContextBound {
            context_id: "replacement-context".to_owned(),
        },
    ] {
        let revision = store.get_task(task_id)?.unwrap().revision;
        store
            .append_task_event(task_id, revision, event, chrono::Utc::now())?
            .expect("provider replacement cut appends");
    }
    let port = EnginePort::resume_small_edit();
    let shared = port.shared();
    let mut restarted = TaskEngine::new(store, port);

    let snapshot = restarted.run(task_id).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    let state = shared.lock().unwrap();
    assert_eq!(state.resume_attempts, ["replacement-context"]);
    assert_eq!(state.replacements, 0);
    assert!(
        state.epoch_starts[0]
            .input
            .contains("Fresh provider context diagnosis")
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn completed_command_with_process_id_is_not_restored_as_background() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let started_process = AgentProcess {
        process_id: "process-123".to_owned(),
        item_id: "work-item-1".to_owned(),
        command: "cargo test old".to_owned(),
        cwd: fixture.workspace.join("old-cwd"),
        os_pid: Some(123),
    };
    let completed_process = AgentProcess {
        process_id: "process-123".to_owned(),
        item_id: "work-item-1".to_owned(),
        command: "cargo test new".to_owned(),
        cwd: fixture.workspace.join("new-cwd"),
        os_pid: Some(456),
    };
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_with_terminal_process_then_compaction_failure(
            started_process,
            completed_process.clone(),
        ),
    );
    assert!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .is_err()
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let checkpoint = first
        .store()
        .get_latest_task_checkpoint(task_id)?
        .expect("the engine committed a checkpoint before compaction");
    assert!(
        checkpoint.running_processes.is_empty(),
        "a terminal command process id is identity evidence, not a live background handle"
    );
    let (store, _) = first.into_parts();
    let port = EnginePort::resume_with_background_process(completed_process, true);
    let shared = port.shared();
    let mut restarted = TaskEngine::new(store, port);

    let snapshot = restarted.run(task_id).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    let state = shared.lock().unwrap();
    assert_eq!(state.background_lists, 0);
    assert!(state.terminations.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn completed_command_without_a_process_removes_the_started_process_from_checkpoint()
-> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let started_process = AgentProcess {
        process_id: "process-finished".to_owned(),
        item_id: "work-item-1".to_owned(),
        command: "cargo test --workspace".to_owned(),
        cwd: fs::canonicalize(&fixture.workspace)?,
        os_pid: Some(123),
    };
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_with_process_then_compaction_failure(
            started_process,
            None,
        ),
    );

    assert!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .is_err()
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let checkpoint = first
        .store()
        .get_latest_task_checkpoint(task_id)?
        .expect("the engine committed a checkpoint before compaction");
    assert!(checkpoint.running_processes.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn every_background_process_identity_field_mismatch_blocks_before_new_epoch() -> TestResult {
    for field in ["process_id", "item_id", "command", "cwd"] {
        let fixture = EngineFixture::new()?;
        let store = Store::open(&fixture.database)?;
        let session = store.create_session()?;
        let expected = AgentProcess {
            process_id: "process-exact".to_owned(),
            item_id: "work-item-1".to_owned(),
            command: "cargo test --workspace".to_owned(),
            cwd: fs::canonicalize(&fixture.workspace)?,
            os_pid: Some(123),
        };
        let mut first = TaskEngine::new(
            store,
            EnginePort::continuation_checkpoint_with_process_then_compaction_failure(
                expected.clone(),
                Some(expected.clone()),
            ),
        );
        assert!(
            first
                .start(start_task(session.id, &fixture.workspace)?)
                .await
                .is_err()
        );
        let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
        let (store, _) = first.into_parts();
        let mut observed = expected;
        match field {
            "process_id" => observed.process_id = "process-other".to_owned(),
            "item_id" => observed.item_id = "work-item-other".to_owned(),
            "command" => observed.command = "cargo test --other".to_owned(),
            "cwd" => observed.cwd = fixture.workspace.join("other-cwd"),
            _ => unreachable!(),
        }
        let port = EnginePort::resume_with_background_process(observed, true);
        let shared = port.shared();
        let mut restarted = TaskEngine::new(store, port);

        assert_eq!(
            restarted.run(task_id).await.unwrap_err().code(),
            carl::runtime::task::TaskEngineErrorCode::Blocked,
            "mismatch in {field} must block"
        );
        let state = shared.lock().unwrap();
        assert_eq!(state.background_lists, 1, "mismatch in {field}");
        assert!(state.epoch_starts.is_empty(), "mismatch in {field}");
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn missing_background_process_blocks_before_any_new_provider_epoch() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let process = AgentProcess {
        process_id: "process-missing".to_owned(),
        item_id: "work-item-1".to_owned(),
        command: "cargo test --workspace".to_owned(),
        cwd: fs::canonicalize(&fixture.workspace)?,
        os_pid: Some(123),
    };
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_with_process_then_compaction_failure(
            process.clone(),
            Some(process),
        ),
    );
    assert!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .is_err()
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let (store, _) = first.into_parts();
    let port = EnginePort::resume_with_missing_background_process();
    let shared = port.shared();
    let mut restarted = TaskEngine::new(store, port);

    assert_eq!(
        restarted.run(task_id).await.unwrap_err().code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let state = shared.lock().unwrap();
    assert_eq!(state.background_lists, 1);
    assert!(state.epoch_starts.is_empty());
    drop(state);
    assert!(
        restarted
            .store()
            .read_task_events(task_id)?
            .iter()
            .any(|event| {
                matches!(
                    &event.event,
                    carl::events::Event::TaskLifecycle {
                        event: carl::runtime::task::TaskEvent::Blocked { reason },
                        ..
                    } if reason.contains("process-missing")
                )
            })
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn background_process_cancellation_journals_the_true_termination_result() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let process = AgentProcess {
        process_id: "process-cancel".to_owned(),
        item_id: "work-item-1".to_owned(),
        command: "cargo test --workspace".to_owned(),
        cwd: fs::canonicalize(&fixture.workspace)?,
        os_pid: Some(123),
    };
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_with_process_then_compaction_failure(
            process.clone(),
            Some(process.clone()),
        ),
    );
    assert!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .is_err()
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let (store, _) = first.into_parts();
    let port = EnginePort::resume_with_background_process(process, true);
    let shared = port.shared();
    let mut restarted = TaskEngine::new(store, port);

    restarted.cancel(task_id).await?;

    assert_eq!(
        restarted
            .store()
            .get_task(task_id)?
            .unwrap()
            .snapshot
            .status,
        TaskStatus::Cancelled
    );
    assert_eq!(shared.lock().unwrap().terminations, ["process-cancel"]);
    assert!(restarted.store().read_task_events(task_id)?.iter().any(|event| {
        matches!(
            &event.event,
            carl::events::Event::TaskLifecycle {
                event: carl::runtime::task::TaskEvent::BackgroundProcessTerminationRecorded {
                    process_id,
                    item_id,
                    terminated: true,
                },
                ..
            } if process_id == "process-cancel" && item_id == "work-item-1"
        )
    }));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn failed_background_termination_is_journaled_false_and_cleanup_stays_blocked() -> TestResult
{
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let process = AgentProcess {
        process_id: "process-still-running".to_owned(),
        item_id: "work-item-1".to_owned(),
        command: "cargo test --workspace".to_owned(),
        cwd: fs::canonicalize(&fixture.workspace)?,
        os_pid: Some(123),
    };
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_with_process_then_compaction_failure(
            process.clone(),
            Some(process.clone()),
        ),
    );
    assert!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .is_err()
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let (store, _) = first.into_parts();
    let port = EnginePort::resume_with_background_process(process, false);
    let mut restarted = TaskEngine::new(store, port);

    assert_eq!(
        restarted.cancel(task_id).await.unwrap_err().code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(
        restarted
            .store()
            .get_task(task_id)?
            .unwrap()
            .snapshot
            .status,
        TaskStatus::Blocked
    );
    assert!(restarted.store().read_task_events(task_id)?.iter().any(|event| {
        matches!(
            &event.event,
            carl::events::Event::TaskLifecycle {
                event: carl::runtime::task::TaskEvent::BackgroundProcessTerminationRecorded {
                    process_id,
                    item_id,
                    terminated: false,
                },
                ..
            } if process_id == "process-still-running" && item_id == "work-item-1"
        )
    }));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn pending_recovery_attempt_rehydrates_with_the_exact_epoch_identity() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_then_compaction_failure(),
    );

    assert_eq!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Provider
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let (mut store, _) = first.into_parts();
    let recovery_epoch_id = carl::runtime::task::EpochId::new();
    let strategy = RecoveryStrategy::ReconstructFromEvidence;
    let strategy_fingerprint = recovery_attempt_fingerprint(&digest(b"pending-recovery"), strategy);
    let revision = store.get_task(task_id)?.unwrap().revision;
    store
        .append_task_event(
            task_id,
            revision,
            carl::runtime::task::TaskEvent::RecoveryAttemptStarted {
                epoch_id: recovery_epoch_id,
                strategy,
                strategy_fingerprint: strategy_fingerprint.clone(),
            },
            chrono::Utc::now(),
        )?
        .expect("the pending recovery event must append");
    let port = EnginePort::resume_small_edit();
    let shared = port.shared();
    let mut resumed = TaskEngine::new(store, port);

    let snapshot = resumed.run(task_id).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    assert_eq!(shared.lock().unwrap().epoch_starts.len(), 1);
    let events = resumed.store().read_task_events(task_id)?;
    assert!(events.iter().any(|envelope| matches!(
        &envelope.event,
        carl::events::Event::TaskLifecycle {
            event: carl::runtime::task::TaskEvent::EpochStarted { epoch_id, .. },
            ..
        } if *epoch_id == recovery_epoch_id
    )));
    assert!(events.iter().any(|envelope| matches!(
        &envelope.event,
        carl::events::Event::TaskLifecycle {
            event: carl::runtime::task::TaskEvent::RecoveryAttemptRecorded {
                epoch_id,
                strategy: recorded_strategy,
                strategy_fingerprint: recorded_fingerprint,
                outcome: RecoveryAttemptOutcome::Succeeded,
            },
            ..
        } if *epoch_id == recovery_epoch_id
            && *recorded_strategy == strategy
            && recorded_fingerprint == &strategy_fingerprint
    )));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn definitely_not_applied_recovery_start_is_recorded_failed_and_restart_safe() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_then_compaction_failure(),
    );
    assert_eq!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Provider
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let (mut store, _) = first.into_parts();
    let recovery_epoch_id = carl::runtime::task::EpochId::new();
    let strategy = RecoveryStrategy::ReconstructFromEvidence;
    let strategy_fingerprint = recovery_attempt_fingerprint(&digest(b"failed-start"), strategy);
    let revision = store.get_task(task_id)?.unwrap().revision;
    store
        .append_task_event(
            task_id,
            revision,
            carl::runtime::task::TaskEvent::RecoveryAttemptStarted {
                epoch_id: recovery_epoch_id,
                strategy,
                strategy_fingerprint: strategy_fingerprint.clone(),
            },
            chrono::Utc::now(),
        )?
        .expect("the pending recovery event must append");
    let mut failed = TaskEngine::new(
        store,
        EnginePort::resume_with_work_start_failure(AgentErrorProvenance::DefinitelyNotApplied),
    );

    let error = failed.run(task_id).await.unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let events = failed.store().read_task_events(task_id)?;
    assert_eq!(
        events
            .iter()
            .filter(|envelope| matches!(
                &envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::EpochStarted { epoch_id, .. },
                    ..
                } if *epoch_id == recovery_epoch_id
            ))
            .count(),
        1
    );
    assert!(events.iter().any(|envelope| matches!(
        &envelope.event,
        carl::events::Event::TaskLifecycle {
            event: carl::runtime::task::TaskEvent::RecoveryAttemptRecorded {
                epoch_id,
                strategy: recorded_strategy,
                strategy_fingerprint: recorded_fingerprint,
                outcome: RecoveryAttemptOutcome::Failed,
            },
            ..
        } if *epoch_id == recovery_epoch_id
            && *recorded_strategy == strategy
            && recorded_fingerprint == &strategy_fingerprint
    )));
    let (store, _) = failed.into_parts();
    let mut restarted = TaskEngine::new(store, EnginePort::resume_small_edit());

    assert_eq!(
        restarted.run(task_id).await.unwrap_err().code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let snapshot = restarted.store().get_task(task_id)?.unwrap().snapshot;
    assert_eq!(snapshot.status, TaskStatus::Blocked);
    assert_eq!(snapshot.active_epoch, None);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn possibly_applied_recovery_start_remains_pending_and_cannot_be_retried_after_restart()
-> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_then_compaction_failure(),
    );
    assert_eq!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Provider
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let (mut store, _) = first.into_parts();
    let recovery_epoch_id = carl::runtime::task::EpochId::new();
    let strategy = RecoveryStrategy::ReconstructFromEvidence;
    let strategy_fingerprint = recovery_attempt_fingerprint(&digest(b"uncertain-start"), strategy);
    let revision = store.get_task(task_id)?.unwrap().revision;
    store
        .append_task_event(
            task_id,
            revision,
            carl::runtime::task::TaskEvent::RecoveryAttemptStarted {
                epoch_id: recovery_epoch_id,
                strategy,
                strategy_fingerprint: strategy_fingerprint.clone(),
            },
            chrono::Utc::now(),
        )?
        .expect("the pending recovery event must append");
    let mut uncertain = TaskEngine::new(
        store,
        EnginePort::resume_with_work_start_failure(AgentErrorProvenance::PossiblyApplied),
    );

    let error = uncertain.run(task_id).await.unwrap_err();

    assert_eq!(
        error.code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let events = uncertain.store().read_task_events(task_id)?;
    assert_eq!(
        events
            .iter()
            .filter(|envelope| matches!(
                &envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::EpochStarted { epoch_id, .. },
                    ..
                } if *epoch_id == recovery_epoch_id
            ))
            .count(),
        1
    );
    assert!(events.iter().all(|envelope| !matches!(
        &envelope.event,
        carl::events::Event::TaskLifecycle {
            event: carl::runtime::task::TaskEvent::RecoveryAttemptRecorded { epoch_id, .. },
            ..
        } if *epoch_id == recovery_epoch_id
    )));
    let (store, _) = uncertain.into_parts();
    let restart_port = EnginePort::resume_small_edit();
    let shared = restart_port.shared();
    let mut restarted = TaskEngine::new(store, restart_port);

    assert_eq!(
        restarted.run(task_id).await.unwrap_err().code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let snapshot = restarted.store().get_task(task_id)?.unwrap().snapshot;
    assert_eq!(snapshot.status, TaskStatus::Blocked);
    assert_eq!(snapshot.active_epoch, None);
    assert_eq!(shared.lock().unwrap().epoch_starts.len(), 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_new_engine_continues_a_safe_checkpoint_without_another_owner_prompt() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let first_port = EnginePort::new([(
        WorkKind::Command,
        "reproduced before restart",
        "continue:Finish after restart",
    )]);
    let mut first_engine = TaskEngine::new(store, first_port);

    assert_eq!(
        first_engine
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Provider
    );
    let task_id = first_engine.store().list_resumable_tasks()?[0]
        .snapshot
        .task_id;
    let (store, _) = first_engine.into_parts();
    let mut resumed = TaskEngine::new(store, EnginePort::resume_small_edit());

    let snapshot = resumed.run(task_id).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    assert_eq!(
        resumed
            .store()
            .read_task_events(task_id)?
            .iter()
            .filter(|event| matches!(
                event.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::EpochStarted { .. },
                    ..
                }
            ))
            .count(),
        4,
        "planning, completed work, definitely-not-applied work, and resumed work are durable"
    );
    assert_eq!(snapshot.active_epoch, None);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restart_never_replays_an_ambiguous_effect_with_an_uncertain_durable_outcome() -> TestResult
{
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::pending_ambiguous_effect();
    let shared = port.shared();
    let mut first = TaskEngine::new(store, port);

    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            first.start(start_task(session.id, &fixture.workspace)?)
        )
        .await
        .is_err(),
        "the fake disconnects after applying the ambiguous effect"
    );
    assert_eq!(shared.lock().unwrap().durable_effect_count, 1);
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let operation_id = first
        .store()
        .read_task_events(task_id)?
        .into_iter()
        .find_map(|envelope| match envelope.event {
            carl::events::Event::TaskLifecycle {
                event:
                    carl::runtime::task::TaskEvent::OperationIntentRecorded {
                        operation_id,
                        effect_class: EffectClass::AmbiguousConsequential,
                        ..
                    },
                ..
            } => Some(operation_id),
            _ => None,
        })
        .expect("the ambiguous operation ID is durable");
    let (store, port) = first.into_parts();
    drop(store);

    let runtime = RuntimeStore::open(DataRootLock::acquire(&fixture.root)?, chrono::Utc::now())?;
    assert_eq!(
        runtime
            .get_task(task_id)?
            .unwrap()
            .snapshot
            .operation_status(operation_id),
        Some(OperationStatus::Uncertain)
    );
    let mut restarted = TaskEngine::new_runtime(runtime, port);

    assert_eq!(
        restarted.run(task_id).await.unwrap_err().code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(shared.lock().unwrap().durable_effect_count, 1);
    assert!(
        restarted
            .store()
            .read_task_events(task_id)?
            .iter()
            .any(|envelope| matches!(
                &envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::Blocked { reason },
                    ..
                } if reason.contains(&operation_id.to_string())
            )),
        "the blocker identifies the exact uncertain operation"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restart_requires_postcondition_proof_before_retrying_an_idempotent_mutation() -> TestResult
{
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::pending_effect();
    let shared = port.shared();
    let mut first = TaskEngine::new(store, port);

    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            first.start(start_task(session.id, &fixture.workspace)?)
        )
        .await
        .is_err(),
        "the fake disconnects after applying the idempotent mutation"
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let operation_id = first
        .store()
        .read_task_events(task_id)?
        .into_iter()
        .find_map(|envelope| match envelope.event {
            carl::events::Event::TaskLifecycle {
                event:
                    carl::runtime::task::TaskEvent::OperationIntentRecorded {
                        operation_id,
                        effect_class: EffectClass::IdempotentMutation,
                        ..
                    },
                ..
            } => Some(operation_id),
            _ => None,
        })
        .expect("the idempotent operation ID is durable");
    assert!(
        first
            .store()
            .read_task_events(task_id)?
            .iter()
            .all(|envelope| {
                !matches!(
                    envelope.event,
                    carl::events::Event::TaskLifecycle {
                        event: carl::runtime::task::TaskEvent::OperationFilePostconditionBound { .. },
                        ..
                    }
                )
            })
    );
    let (store, port) = first.into_parts();
    drop(store);

    let runtime = RuntimeStore::open(DataRootLock::acquire(&fixture.root)?, chrono::Utc::now())?;
    let mut restarted = TaskEngine::new_runtime(runtime, port);

    assert_eq!(
        restarted.run(task_id).await.unwrap_err().code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(shared.lock().unwrap().durable_effect_count, 1);
    assert!(
        restarted
            .store()
            .read_task_events(task_id)?
            .iter()
            .any(|envelope| matches!(
                &envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::Blocked { reason },
                    ..
                } if reason.contains(&operation_id.to_string())
            )),
        "without postcondition evidence, the exact operation stays blocked"
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_postcondition_digest_never_reconciles_an_uncertain_file_mutation() -> TestResult {
    let fixture = EngineFixture::new()?;
    fs::create_dir_all(fixture.workspace.join("src"))?;
    fs::write(fixture.workspace.join("src/lib.rs"), b"legacy file bytes\n")?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let created = store.create_task(NewTask {
        session_id: session.id,
        workspace: fixture.workspace.clone(),
        contract: CompletionContract {
            version: 1,
            goal: "Recover a legacy mutation safely".to_owned(),
            constraints: Vec::new(),
            clauses: vec![CompletionClause {
                id: "safe-recovery".to_owned(),
                description: "The legacy mutation is not replayed".to_owned(),
                required: true,
                status: ClauseStatus::Pending,
                evidence: Vec::new(),
            }],
        },
        model: ModelId::parse("gpt-5.6-codex")?,
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::BypassPermissions,
        budget: TaskBudget::default(),
        created_at: chrono::Utc::now(),
    })?;
    let task_id = created.snapshot.task_id;
    let epoch_id = EpochId::new();
    let operation_id = OperationId::new();
    let mut revision = created.revision;
    for event in [
        carl::runtime::task::TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "legacy execution started".to_owned(),
        },
        carl::runtime::task::TaskEvent::ProviderContextBound {
            context_id: "legacy-context".to_owned(),
        },
        carl::runtime::task::TaskEvent::EpochStarted {
            epoch_id,
            objective: "legacy file mutation".to_owned(),
        },
        carl::runtime::task::TaskEvent::OperationIntentRecorded {
            operation_id,
            epoch_id,
            item_id: "legacy-file-change".to_owned(),
            effect_class: EffectClass::IdempotentMutation,
            request_digest: "legacy-request".to_owned(),
        },
        carl::runtime::task::TaskEvent::OperationPostconditionBound {
            operation_id,
            postcondition_digest: Sha256Digest::parse(digest(b"legacy file bytes\n"))
                .expect("fixed digest is valid"),
        },
        carl::runtime::task::TaskEvent::OperationTransitioned {
            operation_id,
            from: OperationStatus::IntentRecorded,
            to: OperationStatus::Started,
            evidence_sequences: Vec::new(),
        },
    ] {
        revision = store
            .append_task_event(task_id, revision, event, chrono::Utc::now())?
            .expect("legacy event appends")
            .revision;
    }
    drop(store);

    let runtime = RuntimeStore::open(DataRootLock::acquire(&fixture.root)?, chrono::Utc::now())?;
    let port = EnginePort::resume_small_edit();
    let shared = port.shared();
    let mut restarted = TaskEngine::new_runtime(runtime, port);

    assert_eq!(
        restarted.run(task_id).await.unwrap_err().code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    let snapshot = restarted.store().get_task(task_id)?.unwrap().snapshot;
    assert_eq!(snapshot.status, TaskStatus::Blocked);
    assert_eq!(
        snapshot.operation_status(operation_id),
        Some(OperationStatus::Uncertain)
    );
    let state = shared.lock().unwrap();
    assert_eq!(state.durable_effect_count, 0);
    assert!(state.epoch_starts.is_empty());
    drop(state);
    assert_task_projection_matches_replay(restarted.store(), task_id, "legacy digest recovery")?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn queued_permission_tightening_survives_each_interrupt_restart_cut() -> TestResult {
    for (cut, close_interrupted_epoch) in [
        ("after configuration event append", false),
        ("before provider interrupt confirmation", false),
        ("after provider interrupt confirmation", false),
        ("before next epoch dispatch", true),
    ] {
        let fixture = EngineFixture::new()?;
        let mut store = Store::open(&fixture.database)?;
        let session = store.create_session()?;
        let created = store.create_task(NewTask {
            session_id: session.id,
            workspace: fixture.workspace.clone(),
            contract: CompletionContract {
                version: 1,
                goal: "Resume under the durable authorization ceiling".to_owned(),
                constraints: Vec::new(),
                clauses: Vec::new(),
            },
            model: ModelId::parse("gpt-5.6-codex")?,
            effort: ReasoningEffort::High,
            permission_mode: PermissionMode::FullAccess,
            budget: TaskBudget::default(),
            created_at: chrono::Utc::now(),
        })?;
        let task_id = created.snapshot.task_id;
        let epoch_id = EpochId::new();
        let mut revision = created.revision;
        for event in [
            carl::runtime::task::TaskEvent::StateTransitioned {
                from: TaskStatus::Queued,
                to: TaskStatus::Active,
                reason: "execution started".to_owned(),
            },
            carl::runtime::task::TaskEvent::ProviderContextBound {
                context_id: "engine-context".to_owned(),
            },
            carl::runtime::task::TaskEvent::EpochStarted {
                epoch_id,
                objective: "work under full access".to_owned(),
            },
            carl::runtime::task::TaskEvent::ConfigurationQueued {
                control_id: "a".repeat(64),
                model: ModelId::parse("gpt-5.6-codex")?,
                effort: ReasoningEffort::Ultra,
                permission_mode: PermissionMode::Plan,
            },
        ] {
            revision = store
                .append_task_event(task_id, revision, event, chrono::Utc::now())?
                .unwrap_or_else(|| panic!("{cut}: event revision matches"))
                .revision;
        }
        if close_interrupted_epoch {
            store
                .append_task_event(
                    task_id,
                    revision,
                    carl::runtime::task::TaskEvent::EpochInterrupted {
                        epoch_id,
                        reason: carl::runtime::task::EpochInterruptReason::PermissionTightening,
                    },
                    chrono::Utc::now(),
                )?
                .unwrap_or_else(|| panic!("{cut}: interruption revision matches"));
        }
        drop(store);

        let runtime =
            RuntimeStore::open(DataRootLock::acquire(&fixture.root)?, chrono::Utc::now())?;
        let port = EnginePort::resume_small_edit();
        let shared = port.shared();
        let mut restarted = TaskEngine::new_runtime(runtime, port);
        let _ = restarted.run(task_id).await;
        let state = shared.lock().unwrap();
        let dispatched = state
            .epoch_starts
            .last()
            .unwrap_or_else(|| panic!("{cut}: a replacement work epoch starts"));
        assert_eq!(dispatched.permission_mode, PermissionMode::Plan, "{cut}");
        assert_eq!(dispatched.effort, ReasoningEffort::Ultra, "{cut}");
        assert_eq!(state.durable_effect_count, 0, "{cut}");
        drop(state);
        let configuration = restarted
            .store()
            .get_task_configuration(task_id)?
            .expect("configuration remains projected");
        assert_eq!(
            configuration.active_permission_mode,
            PermissionMode::Plan,
            "{cut}"
        );
        assert_eq!(
            configuration.effective_permission_mode,
            PermissionMode::Plan,
            "{cut}"
        );
        assert!(configuration.pending_control_id.is_none(), "{cut}");
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cancel_and_resume_receipts_recover_after_engine_restart_without_duplicate_actions()
-> TestResult {
    for method in ["resume", "cancel"] {
        let fixture = EngineFixture::new()?;
        let mut store = Store::open(&fixture.database)?;
        let session = store.create_session()?;
        let external_session_id = ExternalSessionId::try_from(format!("{method}-restart-session"))?;
        store.bind_frontend_session(NewFrontendSession {
            frontend: Frontend::Acp,
            external_session_id: external_session_id.clone(),
            session_id: session.id,
            cwd: fs::canonicalize(&fixture.workspace)?,
            protocol_version: 2,
            client_name: ClientName::try_from("receipt-restart-test")?,
            permission_mode: PermissionMode::FullAccess,
            channel_id: None,
            created_at: chrono::Utc::now(),
        })?;
        let created = store.create_task(NewTask {
            session_id: session.id,
            workspace: fixture.workspace.clone(),
            contract: CompletionContract {
                version: 1,
                goal: "Complete one receipt-scoped action".to_owned(),
                constraints: Vec::new(),
                clauses: vec![
                    CompletionClause {
                        id: "requested-outcome".to_owned(),
                        description: "Complete the action".to_owned(),
                        required: true,
                        status: ClauseStatus::Pending,
                        evidence: Vec::new(),
                    },
                    CompletionClause {
                        id: "explicit-verification".to_owned(),
                        description: "Verify the action".to_owned(),
                        required: true,
                        status: ClauseStatus::Pending,
                        evidence: Vec::new(),
                    },
                ],
            },
            model: ModelId::parse("gpt-5.6-codex")?,
            effort: ReasoningEffort::High,
            permission_mode: PermissionMode::FullAccess,
            budget: TaskBudget::default(),
            created_at: chrono::Utc::now(),
        })?;
        let task_id = created.snapshot.task_id;
        let control_id = if method == "resume" {
            "d".repeat(64)
        } else {
            "e".repeat(64)
        };
        let receipt = TaskControlMutationInput {
            external_session_id,
            idempotency_key: format!("{method}-restart-key"),
            task_id,
            method: method.to_owned(),
            request_digest: Sha256Digest::parse("f".repeat(64))?,
            result_json: format!(r#"{{"outcome":"accepted","taskId":"{task_id}"}}"#),
            created_at: chrono::Utc::now(),
        };
        assert_eq!(
            store.claim_task_control_mutation(receipt.clone())?,
            TaskControlMutationClaim::Fresh
        );
        let mut revision = created.revision;
        if method == "cancel" {
            let epoch_id = EpochId::new();
            for event in [
                carl::runtime::task::TaskEvent::StateTransitioned {
                    from: TaskStatus::Queued,
                    to: TaskStatus::Active,
                    reason: "prepare cancellation".to_owned(),
                },
                carl::runtime::task::TaskEvent::ProviderContextBound {
                    context_id: "engine-context".to_owned(),
                },
                carl::runtime::task::TaskEvent::EpochStarted {
                    epoch_id,
                    objective: "cancel this active epoch".to_owned(),
                },
                carl::runtime::task::TaskEvent::ProviderEpochBound {
                    epoch_id,
                    provider_epoch_id: "engine-epoch-1".to_owned(),
                },
            ] {
                revision = store
                    .append_task_event(task_id, revision, event, chrono::Utc::now())?
                    .expect("cancel setup revision matches")
                    .revision;
            }
        }
        store
            .append_task_event(
                task_id,
                revision,
                carl::runtime::task::TaskEvent::ControlRequested {
                    control_id: control_id.clone(),
                    kind: if method == "resume" {
                        carl::runtime::task::TaskControlKind::Resume
                    } else {
                        carl::runtime::task::TaskControlKind::Cancel
                    },
                },
                chrono::Utc::now(),
            )?
            .expect("control marker revision matches");

        let first_port = if method == "resume" {
            EnginePort::small_edit()
        } else {
            EnginePort::resume_small_edit()
        };
        let first_state = first_port.shared();
        let mut first = TaskEngine::new(store, first_port);
        if method == "resume" {
            assert_eq!(first.run(task_id).await?.status, TaskStatus::Completed);
            assert_eq!(first_state.lock().unwrap().epoch_starts.len(), 1);
        } else {
            first.cancel(task_id).await?;
            assert_eq!(first_state.lock().unwrap().interrupts, 1);
        }
        Connection::open(&fixture.database)?.execute_batch(&format!(
            "CREATE TRIGGER fail_{method}_receipt_completion
             BEFORE UPDATE OF state ON task_control_receipts
             WHEN NEW.state = 'completed' AND NEW.method = '{method}'
             BEGIN SELECT RAISE(ABORT, 'injected receipt completion crash'); END;"
        ))?;
        assert!(
            first
                .store()
                .complete_task_control_mutation(receipt.clone())
                .is_err(),
            "{method}: completion crash is injected after the action"
        );
        let (store, _) = first.into_parts();
        drop(store);

        Connection::open(&fixture.database)?
            .execute_batch(&format!("DROP TRIGGER fail_{method}_receipt_completion;"))?;
        let reopened = Store::open(&fixture.database)?;
        assert_eq!(
            reopened.claim_task_control_mutation(receipt.clone())?,
            TaskControlMutationClaim::Pending,
            "{method}: receipt remains pending across restart"
        );
        let restart_port = EnginePort::new([]);
        let restart_state = restart_port.shared();
        let mut restarted = TaskEngine::new(reopened, restart_port);
        if method == "resume" {
            assert_eq!(restarted.run(task_id).await?.status, TaskStatus::Completed);
            assert!(restart_state.lock().unwrap().epoch_starts.is_empty());
        } else {
            restarted.cancel(task_id).await?;
            assert_eq!(restart_state.lock().unwrap().interrupts, 0);
        }
        let completed = restarted
            .store()
            .complete_task_control_mutation(receipt.clone())?;
        assert_eq!(
            restarted.store().claim_task_control_mutation(receipt)?,
            TaskControlMutationClaim::Replay {
                result_json: completed,
                failure_code: None,
            }
        );
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn startup_reconciles_a_matching_bound_postcondition_without_redispatch() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::pending_file_effect(&fixture.workspace, b"trusted postcondition\n");
    let shared = port.shared();
    let mut first = TaskEngine::new(store, port);
    install_postcondition_crash_cut(&fixture.database)?;

    assert_eq!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Storage
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let events = first.store().read_task_events(task_id)?;
    let operation_id = events
        .iter()
        .find_map(|envelope| match envelope.event {
            carl::events::Event::TaskLifecycle {
                event: carl::runtime::task::TaskEvent::OperationIntentRecorded { operation_id, .. },
                ..
            } => Some(operation_id),
            _ => None,
        })
        .expect("the operation intent is durable");
    let started = events
        .iter()
        .position(|envelope| {
            matches!(
                envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::OperationTransitioned {
                        to: OperationStatus::Started,
                        ..
                    },
                    ..
                }
            )
        })
        .expect("dispatch start is durable");
    let postcondition = events
        .iter()
        .position(|envelope| {
            matches!(
                envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::OperationFilePostconditionBound { .. },
                    ..
                }
            )
        })
        .expect("Carl binds directly observed filesystem state");
    assert!(
        started < postcondition,
        "postcondition observation follows dispatch"
    );
    let epoch_starts_before = shared.lock().unwrap().epoch_starts.len();
    let (store, port) = first.into_parts();
    drop(store);
    remove_postcondition_crash_cut(&fixture.database)?;
    let runtime = RuntimeStore::open(DataRootLock::acquire(&fixture.root)?, chrono::Utc::now())?;
    let mut restarted = TaskEngine::new_runtime(runtime, Box::new(port));

    assert_eq!(restarted.reconcile_startup().await?, [task_id]);
    let snapshot = restarted.store().get_task(task_id)?.unwrap().snapshot;
    assert_eq!(
        snapshot.operation_status(operation_id),
        Some(OperationStatus::Reconciled)
    );
    let state = shared.lock().unwrap();
    assert_eq!(state.durable_effect_count, 1);
    assert_eq!(state.epoch_starts.len(), epoch_starts_before);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn startup_quarantines_a_missing_workspace_without_contacting_the_provider() -> TestResult {
    let fixture = EngineFixture::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let created = store.create_task(NewTask {
        session_id: session.id,
        workspace: fixture.workspace.clone(),
        contract: CompletionContract {
            version: 1,
            goal: "Resume only from a trustworthy workspace".to_owned(),
            constraints: Vec::new(),
            clauses: vec![CompletionClause {
                id: "workspace-authority".to_owned(),
                description: "The original workspace remains authoritative".to_owned(),
                required: true,
                status: ClauseStatus::Pending,
                evidence: Vec::new(),
            }],
        },
        model: ModelId::parse("gpt-5.6-codex")?,
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::BypassPermissions,
        budget: TaskBudget::default(),
        created_at: chrono::Utc::now(),
    })?;
    let active = store
        .append_task_event(
            created.snapshot.task_id,
            created.revision,
            carl::runtime::task::TaskEvent::StateTransitioned {
                from: TaskStatus::Queued,
                to: TaskStatus::Active,
                reason: "fixture activated".to_owned(),
            },
            chrono::Utc::now(),
        )?
        .expect("activation is durable");
    store
        .append_task_event(
            created.snapshot.task_id,
            active.revision,
            carl::runtime::task::TaskEvent::ProviderContextBound {
                context_id: "missing-workspace-context".to_owned(),
            },
            chrono::Utc::now(),
        )?
        .expect("provider binding is durable");
    drop(store);
    fs::remove_dir(&fixture.workspace)?;

    let runtime = RuntimeStore::open(DataRootLock::acquire(&fixture.root)?, chrono::Utc::now())?;
    let port = EnginePort::resume_small_edit();
    let shared = port.shared();
    port.state.lock().unwrap().reject_missing_resume_workspace = true;
    let mut restarted = TaskEngine::new_runtime(runtime, port);

    assert!(restarted.reconcile_startup().await?.is_empty());
    let snapshot = restarted
        .store()
        .get_task(created.snapshot.task_id)?
        .expect("task remains durable")
        .snapshot;
    assert_eq!(snapshot.status, TaskStatus::Blocked);
    assert!(shared.lock().unwrap().resume_attempts.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn startup_blocks_a_mismatched_bound_postcondition_without_redispatch() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::pending_file_effect(&fixture.workspace, b"trusted postcondition\n");
    let shared = port.shared();
    let mut first = TaskEngine::new(store, port);
    install_postcondition_crash_cut(&fixture.database)?;

    assert_eq!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Storage
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let operation_id = first
        .store()
        .read_task_events(task_id)?
        .into_iter()
        .find_map(|envelope| match envelope.event {
            carl::events::Event::TaskLifecycle {
                event:
                    carl::runtime::task::TaskEvent::OperationFilePostconditionBound {
                        operation_id, ..
                    },
                ..
            } => Some(operation_id),
            _ => None,
        })
        .expect("the postcondition binding is durable");
    let epoch_starts_before = shared.lock().unwrap().epoch_starts.len();
    let (store, port) = first.into_parts();
    drop(store);
    remove_postcondition_crash_cut(&fixture.database)?;
    fs::write(
        fixture.workspace.join("src/lib.rs"),
        b"mismatched filesystem state\n",
    )?;
    let runtime = RuntimeStore::open(DataRootLock::acquire(&fixture.root)?, chrono::Utc::now())?;
    let mut restarted = TaskEngine::new_runtime(runtime, port);

    assert!(restarted.reconcile_startup().await?.is_empty());
    let snapshot = restarted.store().get_task(task_id)?.unwrap().snapshot;
    assert_eq!(snapshot.status, TaskStatus::Blocked);
    assert_eq!(
        snapshot.operation_status(operation_id),
        Some(OperationStatus::Uncertain)
    );
    let state = shared.lock().unwrap();
    assert_eq!(state.durable_effect_count, 1);
    assert_eq!(state.epoch_starts.len(), epoch_starts_before);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn postcondition_rejects_parent_traversal_before_dispatch() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::file_effect_with_path(
        &fixture.workspace,
        "../outside.txt",
        b"must not be written\n",
    );
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    assert_eq!(
        engine
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(shared.lock().unwrap().durable_effect_count, 0);
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(
        only_operation_status(engine.store(), record.snapshot.task_id)?,
        OperationStatus::Failed
    );
    let rendered = format!(
        "{:?}",
        engine.store().read_task_events(record.snapshot.task_id)?
    );
    assert!(!rendered.contains("../outside.txt"));
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn postcondition_rejects_a_symlink_target_after_mutation() -> TestResult {
    use std::os::unix::fs::symlink;

    let fixture = EngineFixture::new()?;
    fs::create_dir_all(fixture.workspace.join("src"))?;
    let outside = fixture.root.join("outside.txt");
    fs::write(&outside, b"before\n")?;
    symlink(&outside, fixture.workspace.join("src/lib.rs"))?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::pending_file_effect(&fixture.workspace, b"mutated\n");
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    assert_eq!(
        engine
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(fs::read(&outside)?, b"mutated\n");
    assert_eq!(shared.lock().unwrap().durable_effect_count, 1);
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(
        only_operation_status(engine.store(), record.snapshot.task_id)?,
        OperationStatus::Uncertain
    );
    assert!(
        engine
            .store()
            .read_task_events(record.snapshot.task_id)?
            .iter()
            .all(|envelope| !matches!(
                envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::OperationFilePostconditionBound { .. },
                    ..
                }
            ))
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn postcondition_rejects_a_hard_link_after_mutation() -> TestResult {
    let fixture = EngineFixture::new()?;
    fs::create_dir_all(fixture.workspace.join("src"))?;
    let sibling = fixture.root.join("same-inode.txt");
    fs::write(&sibling, b"before\n")?;
    fs::hard_link(&sibling, fixture.workspace.join("src/lib.rs"))?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = EnginePort::pending_file_effect(&fixture.workspace, b"mutated\n");
    let shared = port.shared();
    let mut engine = TaskEngine::new(store, port);

    assert_eq!(
        engine
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .unwrap_err()
            .code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(fs::read(&sibling)?, b"mutated\n");
    assert_eq!(shared.lock().unwrap().durable_effect_count, 1);
    let record = engine.store().list_resumable_tasks()?.remove(0);
    assert_eq!(
        only_operation_status(engine.store(), record.snapshot.task_id)?,
        OperationStatus::Uncertain
    );
    assert!(
        engine
            .store()
            .read_task_events(record.snapshot.task_id)?
            .iter()
            .all(|envelope| !matches!(
                envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::OperationFilePostconditionBound { .. },
                    ..
                }
            ))
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restart_after_task_creation_activates_and_binds_a_new_context_once() -> TestResult {
    let fixture = EngineFixture::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let created = store.create_task(NewTask {
        session_id: session.id,
        workspace: fixture.workspace.clone(),
        contract: CompletionContract {
            version: 1,
            goal: "Finish the durable task after startup".to_owned(),
            constraints: Vec::new(),
            clauses: vec![
                CompletionClause {
                    id: "requested-outcome".to_owned(),
                    description: "The requested outcome is implemented".to_owned(),
                    required: true,
                    status: ClauseStatus::Pending,
                    evidence: Vec::new(),
                },
                CompletionClause {
                    id: "explicit-verification".to_owned(),
                    description: "The outcome is verified".to_owned(),
                    required: true,
                    status: ClauseStatus::Pending,
                    evidence: Vec::new(),
                },
            ],
        },
        model: ModelId::parse("gpt-5.6-codex")?,
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::BypassPermissions,
        budget: TaskBudget::default(),
        created_at: chrono::Utc::now(),
    })?;
    let task_id = created.snapshot.task_id;
    let port = EnginePort::resume_small_edit();
    let shared = port.shared();
    let mut restarted = TaskEngine::new(store, port);

    let snapshot = restarted.run(task_id).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    let state = shared.lock().unwrap();
    assert_eq!(state.context_starts, 1);
    assert!(state.resume_attempts.is_empty());
    assert_eq!(state.epoch_starts.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn restart_after_activation_commit_binds_a_fresh_context_once() -> TestResult {
    let fixture = EngineFixture::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let created = store.create_task(NewTask {
        session_id: session.id,
        workspace: fixture.workspace.clone(),
        contract: CompletionContract {
            version: 1,
            goal: "Finish after activation recovery".to_owned(),
            constraints: Vec::new(),
            clauses: vec![
                CompletionClause {
                    id: "requested-outcome".to_owned(),
                    description: "The requested outcome is implemented".to_owned(),
                    required: true,
                    status: ClauseStatus::Pending,
                    evidence: Vec::new(),
                },
                CompletionClause {
                    id: "explicit-verification".to_owned(),
                    description: "The outcome is verified".to_owned(),
                    required: true,
                    status: ClauseStatus::Pending,
                    evidence: Vec::new(),
                },
            ],
        },
        model: ModelId::parse("gpt-5.6-codex")?,
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::BypassPermissions,
        budget: TaskBudget::default(),
        created_at: chrono::Utc::now(),
    })?;
    let task_id = created.snapshot.task_id;
    store
        .append_task_event(
            task_id,
            created.revision,
            carl::runtime::task::TaskEvent::StateTransitioned {
                from: TaskStatus::Queued,
                to: TaskStatus::Active,
                reason: "activation committed before provider binding".to_owned(),
            },
            chrono::Utc::now(),
        )?
        .expect("activation is appended");
    drop(store);
    let store = Store::open(&fixture.database)?;
    let port = EnginePort::resume_small_edit();
    let shared = port.shared();
    let mut restarted = TaskEngine::new(store, port);

    let snapshot = restarted.run(task_id).await?;

    assert_eq!(snapshot.status, TaskStatus::Completed);
    let state = shared.lock().unwrap();
    assert_eq!(state.context_starts, 1);
    assert!(state.resume_attempts.is_empty());
    assert_eq!(state.epoch_starts.len(), 1);
    drop(state);
    let events = restarted.store().read_task_events(task_id)?;
    assert_eq!(
        events
            .iter()
            .filter(|envelope| matches!(
                envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::StateTransitioned {
                        from: TaskStatus::Queued,
                        to: TaskStatus::Active,
                        ..
                    },
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|envelope| matches!(
                envelope.event,
                carl::events::Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::ProviderContextBound { .. },
                    ..
                }
            ))
            .count(),
        1
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn missing_binding_with_durable_provider_work_blocks_instead_of_fresh_binding() -> TestResult
{
    let fixture = EngineFixture::new()?;
    let mut store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let created = store.create_task(NewTask {
        session_id: session.id,
        workspace: fixture.workspace.clone(),
        contract: CompletionContract {
            version: 1,
            goal: "Do not replay provider work without a binding".to_owned(),
            constraints: Vec::new(),
            clauses: vec![CompletionClause {
                id: "safe-recovery".to_owned(),
                description: "Recovery is safe".to_owned(),
                required: true,
                status: ClauseStatus::Pending,
                evidence: Vec::new(),
            }],
        },
        model: ModelId::parse("gpt-5.6-codex")?,
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::BypassPermissions,
        budget: TaskBudget::default(),
        created_at: chrono::Utc::now(),
    })?;
    let task_id = created.snapshot.task_id;
    let mut revision = created.revision;
    for event in [
        carl::runtime::task::TaskEvent::StateTransitioned {
            from: TaskStatus::Queued,
            to: TaskStatus::Active,
            reason: "activation committed".to_owned(),
        },
        carl::runtime::task::TaskEvent::EpochStarted {
            epoch_id: EpochId::new(),
            objective: "provider work may have started".to_owned(),
        },
    ] {
        revision = store
            .append_task_event(task_id, revision, event, chrono::Utc::now())?
            .expect("setup event appends")
            .revision;
    }
    let port = EnginePort::resume_small_edit();
    let shared = port.shared();
    let mut restarted = TaskEngine::new(store, port);

    assert_eq!(
        restarted.run(task_id).await.unwrap_err().code(),
        carl::runtime::task::TaskEngineErrorCode::Blocked
    );
    assert_eq!(
        restarted
            .store()
            .get_task(task_id)?
            .unwrap()
            .snapshot
            .status,
        TaskStatus::Blocked
    );
    let state = shared.lock().unwrap();
    assert_eq!(state.context_starts, 0);
    assert!(state.resume_attempts.is_empty());
    assert!(state.epoch_starts.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn startup_reconciliation_prepares_resumable_tasks_without_dispatching_work() -> TestResult {
    let fixture = EngineFixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut first = TaskEngine::new(
        store,
        EnginePort::continuation_checkpoint_then_compaction_failure(),
    );
    assert!(
        first
            .start(start_task(session.id, &fixture.workspace)?)
            .await
            .is_err()
    );
    let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
    let (store, _) = first.into_parts();
    let port = EnginePort::resume_small_edit();
    let shared = port.shared();
    let mut restarted = TaskEngine::new(store, port);

    assert_eq!(restarted.reconcile_startup().await?, [task_id]);
    {
        let state = shared.lock().unwrap();
        assert_eq!(state.resume_attempts, ["engine-context"]);
        assert!(state.epoch_starts.is_empty());
    }

    let snapshot = restarted.run(task_id).await?;
    assert_eq!(snapshot.status, TaskStatus::Completed);
    assert_eq!(shared.lock().unwrap().resume_attempts, ["engine-context"]);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn every_required_engine_restart_cut_restarts_from_real_engine_state() -> TestResult {
    for cut in [
        RequiredEngineRestartCut::TaskCreated,
        RequiredEngineRestartCut::EpochStarted,
        RequiredEngineRestartCut::OperationIntentRecorded,
        RequiredEngineRestartCut::EffectAuthorized,
        RequiredEngineRestartCut::ItemStarted,
        RequiredEngineRestartCut::WorkspaceMutated,
        RequiredEngineRestartCut::ItemCompleted,
        RequiredEngineRestartCut::CheckpointCandidateBuilt,
        RequiredEngineRestartCut::CheckpointCommitted,
        RequiredEngineRestartCut::CompactionRequested,
        RequiredEngineRestartCut::ProviderReplacementStarted,
        RequiredEngineRestartCut::ProviderBindingCommitted,
    ] {
        match cut {
            RequiredEngineRestartCut::TaskCreated => {
                let fixture = EngineFixture::new()?;
                let store = Store::open(&fixture.database)?;
                let session = store.create_session()?;
                install_engine_event_cut(&fixture.database, "state_transitioned", None)?;
                let port = EnginePort::small_edit();
                let shared = port.shared();
                let mut first = TaskEngine::new(store, port.clone());
                assert_eq!(
                    first
                        .start(start_task(session.id, &fixture.workspace)?)
                        .await
                        .unwrap_err()
                        .code(),
                    carl::runtime::task::TaskEngineErrorCode::Storage
                );
                let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
                port.prepare_after_crash();
                let _restarted = restart_matrix_task(
                    &fixture,
                    first,
                    task_id,
                    port,
                    MatrixOutcome::Completed,
                    "task created",
                )
                .await?;
                let state = shared.lock().unwrap();
                assert_eq!(state.context_starts, 2);
                assert_eq!(state.epoch_starts.len(), 1);
                assert_eq!(state.durable_effect_count, 1);
            }
            RequiredEngineRestartCut::EpochStarted => {
                let fixture = EngineFixture::new()?;
                let store = Store::open(&fixture.database)?;
                let session = store.create_session()?;
                install_engine_event_cut(&fixture.database, "provider_request_recorded", None)?;
                let port = EnginePort::small_edit();
                let shared = port.shared();
                let mut first = TaskEngine::new(store, port.clone());
                assert_eq!(
                    first
                        .start(start_task(session.id, &fixture.workspace)?)
                        .await
                        .unwrap_err()
                        .code(),
                    carl::runtime::task::TaskEngineErrorCode::Storage
                );
                let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
                port.prepare_after_crash();
                let _restarted = restart_matrix_task(
                    &fixture,
                    first,
                    task_id,
                    port,
                    MatrixOutcome::Completed,
                    "epoch started",
                )
                .await?;
                let state = shared.lock().unwrap();
                assert_eq!(state.context_starts, 1);
                assert_eq!(state.resume_attempts, ["engine-context"]);
                assert_eq!(state.epoch_starts.len(), 1);
                assert_eq!(state.durable_effect_count, 1);
            }
            RequiredEngineRestartCut::OperationIntentRecorded => {
                let fixture = EngineFixture::new()?;
                let store = Store::open(&fixture.database)?;
                let session = store.create_session()?;
                install_engine_event_cut(
                    &fixture.database,
                    "operation_transitioned",
                    Some("operation_intent_recorded"),
                )?;
                let port = EnginePort::small_edit();
                let shared = port.shared();
                let mut first = TaskEngine::new(store, port.clone());
                assert_eq!(
                    first
                        .start(start_task(session.id, &fixture.workspace)?)
                        .await
                        .unwrap_err()
                        .code(),
                    carl::runtime::task::TaskEngineErrorCode::Storage
                );
                let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
                assert_eq!(
                    only_operation_status(first.store(), task_id)?,
                    OperationStatus::IntentRecorded
                );
                port.prepare_after_crash();
                let _restarted = restart_matrix_task(
                    &fixture,
                    first,
                    task_id,
                    port,
                    MatrixOutcome::Completed,
                    "operation intent recorded",
                )
                .await?;
                let state = shared.lock().unwrap();
                assert_eq!(state.epoch_starts.len(), 3);
                assert_eq!(state.resolved, [EffectDecision::Allow]);
                assert_eq!(state.durable_effect_count, 1);
            }
            RequiredEngineRestartCut::EffectAuthorized => {
                let fixture = EngineFixture::new()?;
                let store = Store::open(&fixture.database)?;
                let session = store.create_session()?;
                let port = EnginePort::pending_resolve();
                let shared = port.shared();
                let mut first = TaskEngine::new(store, port.clone());
                assert!(
                    tokio::time::timeout(
                        Duration::from_millis(50),
                        first.start(start_task(session.id, &fixture.workspace)?)
                    )
                    .await
                    .is_err()
                );
                let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
                {
                    let state = shared.lock().unwrap();
                    assert_eq!(state.resolved, [EffectDecision::Allow]);
                    assert_eq!(state.durable_effect_count, 0);
                }
                port.prepare_after_crash();
                let _restarted = restart_matrix_task(
                    &fixture,
                    first,
                    task_id,
                    port,
                    MatrixOutcome::Blocked,
                    "effect authorized",
                )
                .await?;
                let state = shared.lock().unwrap();
                assert_eq!(state.resolved, [EffectDecision::Allow]);
                assert_eq!(state.durable_effect_count, 0);
                assert_eq!(state.epoch_starts.len(), 2);
            }
            RequiredEngineRestartCut::ItemStarted => {
                let fixture = EngineFixture::new()?;
                let store = Store::open(&fixture.database)?;
                let session = store.create_session()?;
                let port = EnginePort::pending_after_item_started();
                let shared = port.shared();
                let mut first = TaskEngine::new(store, port.clone());
                assert!(
                    tokio::time::timeout(
                        Duration::from_millis(50),
                        first.start(start_task(session.id, &fixture.workspace)?)
                    )
                    .await
                    .is_err()
                );
                let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
                assert!(operation_statuses(first.store(), task_id)?.is_empty());
                assert_eq!(shared.lock().unwrap().item_started_deliveries, 1);
                port.prepare_after_crash();
                let _restarted = restart_matrix_task(
                    &fixture,
                    first,
                    task_id,
                    port,
                    MatrixOutcome::Completed,
                    "item started",
                )
                .await?;
                let state = shared.lock().unwrap();
                assert_eq!(state.item_started_deliveries, 2);
                assert_eq!(state.durable_effect_count, 1);
                assert_eq!(state.epoch_starts.len(), 3);
            }
            RequiredEngineRestartCut::WorkspaceMutated => {
                let fixture = EngineFixture::new()?;
                let store = Store::open(&fixture.database)?;
                let session = store.create_session()?;
                let port = EnginePort::pending_workspace_mutation(
                    &fixture.workspace,
                    b"matrix mutation\n",
                );
                let shared = port.shared();
                let mut first = TaskEngine::new(store, port.clone());
                assert!(
                    tokio::time::timeout(
                        Duration::from_millis(50),
                        first.start(start_task(session.id, &fixture.workspace)?)
                    )
                    .await
                    .is_err()
                );
                let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
                assert_eq!(shared.lock().unwrap().durable_mutation_count, 1);
                port.prepare_after_crash();
                let _restarted = restart_matrix_task(
                    &fixture,
                    first,
                    task_id,
                    port,
                    MatrixOutcome::Blocked,
                    "workspace mutated",
                )
                .await?;
                let state = shared.lock().unwrap();
                assert_eq!(state.durable_effect_count, 1);
                assert_eq!(state.durable_mutation_count, 1);
                assert_eq!(state.epoch_starts.len(), 2);
            }
            RequiredEngineRestartCut::ItemCompleted => {
                let fixture = EngineFixture::new()?;
                let store = Store::open(&fixture.database)?;
                let session = store.create_session()?;
                install_engine_event_cut(
                    &fixture.database,
                    "usage_observed",
                    Some("operation_file_postcondition_bound"),
                )?;
                let first_port =
                    EnginePort::pending_file_effect(&fixture.workspace, b"item complete\n");
                let first_shared = first_port.shared();
                let mut first = TaskEngine::new(store, first_port);
                assert_eq!(
                    first
                        .start(start_task(session.id, &fixture.workspace)?)
                        .await
                        .unwrap_err()
                        .code(),
                    carl::runtime::task::TaskEngineErrorCode::Storage
                );
                let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
                assert_eq!(
                    only_operation_status(first.store(), task_id)?,
                    OperationStatus::Succeeded
                );
                let restart_port = EnginePort::resume_small_edit();
                let restart_shared = restart_port.shared();
                let _restarted = restart_matrix_task(
                    &fixture,
                    first,
                    task_id,
                    restart_port,
                    MatrixOutcome::Completed,
                    "item completed",
                )
                .await?;
                assert_eq!(first_shared.lock().unwrap().durable_mutation_count, 1);
                assert_eq!(restart_shared.lock().unwrap().durable_effect_count, 1);
                assert_eq!(
                    first_shared.lock().unwrap().durable_effect_count
                        + restart_shared.lock().unwrap().durable_effect_count,
                    2
                );
            }
            RequiredEngineRestartCut::CheckpointCandidateBuilt => {
                let fixture = EngineFixture::new()?;
                let store = Store::open(&fixture.database)?;
                let session = store.create_session()?;
                install_engine_event_cut(&fixture.database, "checkpoint_committed", None)?;
                let first_port =
                    EnginePort::pending_file_effect(&fixture.workspace, b"candidate\n");
                let first_shared = first_port.shared();
                let mut first = TaskEngine::new(store, first_port);
                assert_eq!(
                    first
                        .start(start_task(session.id, &fixture.workspace)?)
                        .await
                        .unwrap_err()
                        .code(),
                    carl::runtime::task::TaskEngineErrorCode::Storage
                );
                let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
                assert_eq!(
                    first.store().get_task(task_id)?.unwrap().snapshot.status,
                    TaskStatus::Checkpointing
                );
                assert!(first.store().get_latest_task_checkpoint(task_id)?.is_none());
                let restart_port = EnginePort::resume_small_edit();
                let restart_shared = restart_port.shared();
                let _restarted = restart_matrix_task(
                    &fixture,
                    first,
                    task_id,
                    restart_port,
                    MatrixOutcome::Blocked,
                    "checkpoint candidate built",
                )
                .await?;
                assert_eq!(first_shared.lock().unwrap().durable_effect_count, 1);
                assert_eq!(restart_shared.lock().unwrap().durable_effect_count, 0);
            }
            RequiredEngineRestartCut::CheckpointCommitted => {
                let fixture = EngineFixture::new()?;
                let store = Store::open(&fixture.database)?;
                let session = store.create_session()?;
                install_engine_event_cut(
                    &fixture.database,
                    "\"to\":\"completing\"",
                    Some("checkpoint_committed"),
                )?;
                let first_port =
                    EnginePort::pending_file_effect(&fixture.workspace, b"committed\n");
                let first_shared = first_port.shared();
                let mut first = TaskEngine::new(store, first_port);
                assert_eq!(
                    first
                        .start(start_task(session.id, &fixture.workspace)?)
                        .await
                        .unwrap_err()
                        .code(),
                    carl::runtime::task::TaskEngineErrorCode::Storage
                );
                let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
                assert!(first.store().get_latest_task_checkpoint(task_id)?.is_some());
                let restart_port = EnginePort::resume_small_edit();
                let restart_shared = restart_port.shared();
                let _restarted = restart_matrix_task(
                    &fixture,
                    first,
                    task_id,
                    restart_port,
                    MatrixOutcome::Completed,
                    "checkpoint committed",
                )
                .await?;
                assert_eq!(first_shared.lock().unwrap().durable_effect_count, 1);
                let restarted = restart_shared.lock().unwrap();
                assert_eq!(restarted.durable_effect_count, 1);
                assert_eq!(restarted.durable_mutation_count, 0);
            }
            RequiredEngineRestartCut::CompactionRequested => {
                let fixture = EngineFixture::new()?;
                let store = Store::open(&fixture.database)?;
                let session = store.create_session()?;
                let first_port = EnginePort::continuation_checkpoint_then_compaction_failure();
                let first_shared = first_port.shared();
                let mut first = TaskEngine::new(store, first_port);
                assert_eq!(
                    first
                        .start(start_task(session.id, &fixture.workspace)?)
                        .await
                        .unwrap_err()
                        .code(),
                    carl::runtime::task::TaskEngineErrorCode::Provider
                );
                let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
                assert!(first.store().read_task_events(task_id)?.iter().any(|envelope| {
                    matches!(
                        envelope.event,
                        carl::events::Event::TaskLifecycle {
                            event: carl::runtime::task::TaskEvent::CompactionRequested { .. },
                            ..
                        }
                    )
                }));
                let restart_port = EnginePort::resume_small_edit();
                let restart_shared = restart_port.shared();
                let _restarted = restart_matrix_task(
                    &fixture,
                    first,
                    task_id,
                    restart_port,
                    MatrixOutcome::Completed,
                    "compaction requested",
                )
                .await?;
                assert_eq!(first_shared.lock().unwrap().durable_effect_count, 1);
                assert_eq!(restart_shared.lock().unwrap().durable_effect_count, 1);
                assert_eq!(
                    restart_shared.lock().unwrap().resume_attempts,
                    ["engine-context"]
                );
            }
            RequiredEngineRestartCut::ProviderReplacementStarted => {
                let fixture = EngineFixture::new()?;
                let store = Store::open(&fixture.database)?;
                let session = store.create_session()?;
                let first_port = EnginePort::continuation_checkpoint_then_compaction_failure();
                let first_shared = first_port.shared();
                let mut first = TaskEngine::new(store, first_port);
                assert!(
                    first
                        .start(start_task(session.id, &fixture.workspace)?)
                        .await
                        .is_err()
                );
                let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
                assert_task_projection_matches_replay(
                    first.store(),
                    task_id,
                    "provider replacement setup",
                )?;
                let (store, _) = first.into_parts();
                drop(store);
                let runtime =
                    RuntimeStore::open(DataRootLock::acquire(&fixture.root)?, chrono::Utc::now())?;
                let replacement_port = EnginePort::unavailable_context_with_pending_replacement();
                let replacement_shared = replacement_port.shared();
                let mut replacement = TaskEngine::new_runtime(runtime, replacement_port.clone());
                assert!(
                    tokio::time::timeout(Duration::from_millis(50), replacement.run(task_id))
                        .await
                        .is_err()
                );
                assert!(
                    replacement
                        .store()
                        .read_task_events(task_id)?
                        .iter()
                        .any(|envelope| {
                            matches!(
                                &envelope.event,
                                carl::events::Event::TaskLifecycle {
                                    event: carl::runtime::task::TaskEvent::ProviderContextLost {
                                        context_id,
                                        ..
                                    },
                                    ..
                                } if context_id == "engine-context"
                            )
                        })
                );
                assert_eq!(replacement_shared.lock().unwrap().replacements, 1);
                replacement_port.prepare_after_crash();
                let _restarted = restart_matrix_runtime_task(
                    &fixture,
                    replacement,
                    task_id,
                    replacement_port,
                    MatrixOutcome::Completed,
                    "provider replacement started",
                )
                .await?;
                assert_eq!(first_shared.lock().unwrap().durable_effect_count, 1);
                let state = replacement_shared.lock().unwrap();
                assert_eq!(state.replacements, 2);
                assert_eq!(state.durable_effect_count, 1);
                assert_eq!(state.resume_attempts, ["engine-context"]);
            }
            RequiredEngineRestartCut::ProviderBindingCommitted => {
                let fixture = EngineFixture::new()?;
                let store = Store::open(&fixture.database)?;
                let session = store.create_session()?;
                let first_port = EnginePort::continuation_checkpoint_then_compaction_failure();
                let first_shared = first_port.shared();
                let mut first = TaskEngine::new(store, first_port);
                assert!(
                    first
                        .start(start_task(session.id, &fixture.workspace)?)
                        .await
                        .is_err()
                );
                let task_id = first.store().list_resumable_tasks()?[0].snapshot.task_id;
                assert_task_projection_matches_replay(
                    first.store(),
                    task_id,
                    "provider binding setup",
                )?;
                let (store, _) = first.into_parts();
                drop(store);
                let runtime =
                    RuntimeStore::open(DataRootLock::acquire(&fixture.root)?, chrono::Utc::now())?;
                install_engine_event_cut(
                    &fixture.database,
                    "epoch_started",
                    Some("replacement-context"),
                )?;
                let replacement_port = EnginePort::unavailable_context_then_small_edit();
                let replacement_shared = replacement_port.shared();
                let mut replacement = TaskEngine::new_runtime(runtime, replacement_port);
                assert_eq!(
                    replacement.run(task_id).await.unwrap_err().code(),
                    carl::runtime::task::TaskEngineErrorCode::Storage
                );
                assert!(
                    replacement
                        .store()
                        .read_task_events(task_id)?
                        .iter()
                        .any(|envelope| {
                            matches!(
                                &envelope.event,
                                carl::events::Event::TaskLifecycle {
                                    event: carl::runtime::task::TaskEvent::ProviderContextBound {
                                        context_id
                                    },
                                    ..
                                } if context_id == "replacement-context"
                            )
                        })
                );
                let restart_port = EnginePort::resume_small_edit();
                let restart_shared = restart_port.shared();
                let _restarted = restart_matrix_runtime_task(
                    &fixture,
                    replacement,
                    task_id,
                    restart_port,
                    MatrixOutcome::Completed,
                    "provider binding committed",
                )
                .await?;
                assert_eq!(first_shared.lock().unwrap().durable_effect_count, 1);
                let replacement = replacement_shared.lock().unwrap();
                assert_eq!(replacement.resume_attempts, ["engine-context"]);
                assert_eq!(replacement.replacements, 1);
                assert_eq!(replacement.durable_effect_count, 0);
                drop(replacement);
                let restarted = restart_shared.lock().unwrap();
                assert_eq!(restarted.resume_attempts, ["replacement-context"]);
                assert_eq!(restarted.durable_effect_count, 1);
            }
        }
    }
    Ok(())
}

fn report(disposition: &str, clauses: &str) -> String {
    format!(
        "<carl-epoch-report>{{\"schema_version\":1,\"disposition\":\"{disposition}\",\"summary\":\"Regression reproduced\",\"next_objective\":\"Implement the fix\",\"clause_evidence\":[{clauses}],\"exact_identifiers\":[\"parser::decode\"]}}</carl-epoch-report>"
    )
}

fn checkpoint(operation_id: OperationId, artifact_digest: String) -> CanonicalCheckpoint {
    CanonicalCheckpoint {
        schema_version: 1,
        checkpoint_id: CheckpointId::from_uuid(uuid("11111111-1111-4111-8111-111111111111")),
        task_id: TaskId::from_uuid(uuid("22222222-2222-4222-8222-222222222222")),
        contract: CompletionContract {
            version: 1,
            goal: "Fix the parser".to_owned(),
            constraints: Vec::new(),
            clauses: vec![CompletionClause {
                id: "parser-fixed".to_owned(),
                description: "The parser decodes the input".to_owned(),
                required: true,
                status: ClauseStatus::Pending,
                evidence: Vec::new(),
            }],
        },
        completed_work: vec![WorkEvidence {
            summary: "Canonical artifact".to_owned(),
            event_sequences: vec![7],
            artifact_digests: vec![artifact_digest.clone()],
        }],
        decisions: vec![DecisionRecord {
            id: "decision-1".to_owned(),
            decision: "repair".to_owned(),
            rationale: "evidence".to_owned(),
        }],
        exact_identifiers: vec![ExactIdentifier {
            kind: "symbol".to_owned(),
            value: "parser::decode".to_owned(),
        }],
        operations: vec![OperationCheckpoint {
            operation_id,
            status: OperationStatus::Succeeded,
            effect_class: EffectClass::AmbiguousConsequential,
            request_digest: digest(b"request"),
            evidence_sequences: vec![7],
        }],
        repository: RepositoryCheckpoint {
            workspace_digest: digest(b"workspace"),
            git_head: None,
            git_status_digest: None,
            diff_artifact_digest: Some(artifact_digest),
            file_hashes: BTreeMap::from([("src/parser.rs".to_owned(), digest(b"parser"))]),
        },
        running_processes: Vec::<ProcessCheckpoint>::new(),
        pending_approval_digests: Vec::new(),
        pending_steering_digests: Vec::new(),
        uncertain_delivery_digests: Vec::new(),
        verification: vec![ClauseEvidence {
            clause_id: "parser-fixed".to_owned(),
            evidence: Vec::new(),
        }],
        next_objective: "Implement the fix".to_owned(),
        blockers: Vec::new(),
        provider: ProviderCheckpoint {
            provider: "provider-a".to_owned(),
            model: "model-a".to_owned(),
            effort: "high".to_owned(),
            context_id: Some("ctx-a".to_owned()),
            observed_total_tokens: Some(42),
            observed_context_window: Some(128),
        },
        compaction_generation: 0,
        source_sequence_start: 1,
        source_sequence_end: 8,
        previous_digest: None,
    }
}

#[test]
fn parses_one_final_epoch_report_block() -> TestResult {
    let parsed = parse_epoch_report(&format!(
        "provider transcript\n{}\n",
        report("continue", "")
    ))?;
    assert_eq!(parsed.schema_version, 1);
    assert_eq!(parsed.disposition, EpochDisposition::Continue);
    assert_eq!(parsed.next_objective.as_deref(), Some("Implement the fix"));
    Ok(())
}

#[test]
fn rejects_ambiguous_or_unbounded_epoch_reports() {
    let valid = report("continue", "");
    for output in [
        format!("{valid}{valid}"),
        format!("{valid}\n<carl-epoch-report>later"),
        format!("{valid}\nprovider appended report-like text"),
        "<carl-epoch-report>{\"schema_version\":1,\"disposition\":\"continue\",\"summary\":\"x\",\"next_objective\":\"next\",\"clause_evidence\":[],\"exact_identifiers\":[],\"unknown\":true}</carl-epoch-report>".to_owned(),
        "x".repeat(64 * 1024 + 1),
    ] {
        assert_eq!(
            parse_epoch_report(&output).unwrap_err().code(),
            ReportErrorCode::InvalidReport
        );
    }
}

#[test]
fn completion_requires_normalized_successful_command_evidence() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let artifact = digest(b"diff");
    let checkpoint = checkpoint(operation_id, artifact);
    let parsed = parse_epoch_report(&report(
        "complete",
        &format!(
            "{{\"clause_id\":\"parser-fixed\",\"operation_ids\":[\"{operation_id}\"],\"event_sequences\":[7],\"artifact_digests\":[]}}"
        ),
    ))?;

    let completion = decide_completion(
        &parsed,
        &checkpoint,
        &[OperationEvidence::Command {
            operation_id,
            completed: true,
            exit_code: Some(0),
        }],
    )?;
    assert!(matches!(
        completion,
        carl::runtime::task::CompletionDecision::Complete
    ));

    assert_eq!(
        decide_completion(
            &parsed,
            &checkpoint,
            &[OperationEvidence::Command {
                operation_id,
                completed: true,
                exit_code: Some(1),
            }],
        )
        .unwrap_err()
        .code(),
        ReportErrorCode::InsufficientEvidence
    );
    Ok(())
}

#[test]
fn rejects_duplicate_operation_evidence_claims() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let checkpoint = checkpoint(operation_id, digest(b"diff"));
    let parsed = parse_epoch_report(&report(
        "complete",
        &format!(
            "{{\"clause_id\":\"parser-fixed\",\"operation_ids\":[\"{operation_id}\",\"{operation_id}\"],\"event_sequences\":[7],\"artifact_digests\":[]}}"
        ),
    ))?;
    assert_eq!(
        decide_completion(
            &parsed,
            &checkpoint,
            &[OperationEvidence::Command {
                operation_id,
                completed: true,
                exit_code: Some(0),
            }],
        )
        .unwrap_err()
        .code(),
        ReportErrorCode::InvalidReport
    );
    Ok(())
}

#[test]
fn rejects_unknown_clause_or_operation_claims() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let checkpoint = checkpoint(operation_id, digest(b"diff"));
    let parsed = parse_epoch_report(&report(
        "continue",
        &format!(
            "{{\"clause_id\":\"unknown\",\"operation_ids\":[\"{operation_id}\"],\"event_sequences\":[7],\"artifact_digests\":[]}}"
        ),
    ))?;
    assert_eq!(
        decide_completion(&parsed, &checkpoint, &[])
            .unwrap_err()
            .code(),
        ReportErrorCode::UnknownClause
    );
    let unknown_operation = OperationId::from_uuid(uuid("44444444-4444-4444-8444-444444444444"));
    let parsed = parse_epoch_report(&report(
        "continue",
        &format!(
            "{{\"clause_id\":\"parser-fixed\",\"operation_ids\":[\"{unknown_operation}\"],\"event_sequences\":[7],\"artifact_digests\":[]}}"
        ),
    ))?;
    assert_eq!(
        decide_completion(&parsed, &checkpoint, &[])
            .unwrap_err()
            .code(),
        ReportErrorCode::UnknownOperation
    );
    Ok(())
}

#[test]
fn completion_requires_a_matching_canonical_file_artifact() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let artifact = digest(b"diff");
    let mut checkpoint = checkpoint(operation_id, artifact.clone());
    checkpoint.operations[0].effect_class = EffectClass::IdempotentMutation;
    let parsed = parse_epoch_report(&report(
        "complete",
        &format!(
            "{{\"clause_id\":\"parser-fixed\",\"operation_ids\":[\"{operation_id}\"],\"event_sequences\":[7],\"artifact_digests\":[\"{artifact}\"]}}"
        ),
    ))?;
    assert!(matches!(
        decide_completion(
            &parsed,
            &checkpoint,
            &[OperationEvidence::FileChange {
                operation_id,
                completed: true,
                artifact_digests: vec![artifact.clone()],
            }],
        )?,
        carl::runtime::task::CompletionDecision::Complete
    ));
    assert_eq!(
        decide_completion(
            &parsed,
            &checkpoint,
            &[OperationEvidence::FileChange {
                operation_id,
                completed: true,
                artifact_digests: Vec::new(),
            }],
        )
        .unwrap_err()
        .code(),
        ReportErrorCode::InsufficientEvidence
    );
    Ok(())
}

#[test]
fn fingerprints_carl_owned_state_not_provider_metadata_or_prose() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let artifact = digest(b"diff");
    let checkpoint = checkpoint(operation_id, artifact);
    let first_report = parse_epoch_report(&report("continue", ""))?;
    let mut second_report = first_report.clone();
    second_report.summary = "Provider chose different prose".to_owned();
    let first = assess_progress(&checkpoint, &first_report, &[])?;
    let second = assess_progress(&checkpoint, &second_report, &[])?;
    assert_eq!(first.fingerprint, second.fingerprint);
    Ok(())
}

#[test]
fn fingerprints_verification_outcomes_in_canonical_order() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let artifact = digest(b"diff");
    let mut first = checkpoint(operation_id, artifact.clone());
    let mut second = checkpoint(operation_id, artifact);
    let second_clause = CompletionClause {
        id: "repository-clean".to_owned(),
        description: "The repository is clean".to_owned(),
        required: false,
        status: ClauseStatus::Failed,
        evidence: Vec::new(),
    };
    first.contract.clauses.push(second_clause.clone());
    second.contract.clauses.insert(0, second_clause);
    let report = parse_epoch_report(&report("continue", ""))?;
    assert_eq!(
        assess_progress(&first, &report, &[])?.fingerprint,
        assess_progress(&second, &report, &[])?.fingerprint
    );
    Ok(())
}

#[test]
fn fingerprints_exact_canonical_verification_evidence() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let mut first = checkpoint(operation_id, digest(b"diff"));
    let mut second = first.clone();
    first.verification[0].evidence = vec![EvidenceRef {
        event_sequence: 7,
        artifact_digest: Some(digest(b"artifact-one")),
        operation_id: Some(operation_id),
    }];
    second.verification[0].evidence = vec![EvidenceRef {
        event_sequence: 7,
        artifact_digest: Some(digest(b"artifact-two")),
        operation_id: Some(operation_id),
    }];
    let report = parse_epoch_report(&report("continue", ""))?;
    assert_ne!(
        assess_progress(&first, &report, &[])?.fingerprint,
        assess_progress(&second, &report, &[])?.fingerprint
    );
    Ok(())
}

#[test]
fn fingerprints_changed_files_with_identity_and_multiplicity() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let mut first = checkpoint(operation_id, digest(b"diff"));
    let mut second = first.clone();
    let file_digest = digest(b"same file contents");
    first
        .repository
        .file_hashes
        .insert("src/first.rs".to_owned(), file_digest.clone());
    first
        .repository
        .file_hashes
        .insert("src/second.rs".to_owned(), file_digest.clone());
    second
        .repository
        .file_hashes
        .insert("src/renamed.rs".to_owned(), file_digest);
    let report = parse_epoch_report(&report("continue", ""))?;
    assert_ne!(
        assess_progress(&first, &report, &[])?.fingerprint,
        assess_progress(&second, &report, &[])?.fingerprint
    );
    Ok(())
}

#[test]
fn stalls_only_block_after_three_distinct_recovery_strategies_failed() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let checkpoint = checkpoint(operation_id, digest(b"diff"));
    let report = parse_epoch_report(&report("continue", ""))?;
    let baseline = assess_progress(&checkpoint, &report, &[])?;
    let mut history: Vec<ProgressAssessment> = vec![baseline.clone()];
    let mut attempts = Vec::new();
    for expected in [
        RecoveryStrategy::ReconstructFromEvidence,
        RecoveryStrategy::ReplaceApproach,
        RecoveryStrategy::MinimizeReproduction,
    ] {
        let assessment =
            assess_progress_with_recovery_attempts(&checkpoint, &report, &history, &attempts)?;
        assert_eq!(assessment.recovery, Some(expected));
        attempts.push(RecoveryAttempt {
            strategy: expected,
            strategy_fingerprint: recovery_attempt_fingerprint(&assessment.fingerprint, expected),
            outcome: RecoveryAttemptOutcome::Failed,
        });
        history.push(assessment);
    }
    let blocked =
        assess_progress_with_recovery_attempts(&checkpoint, &report, &history, &attempts)?;
    assert_eq!(blocked.recovery, Some(RecoveryStrategy::DeclareBlocked));
    assert_eq!(blocked.stall_count, 4);
    Ok(())
}

#[test]
fn recovery_recommendations_are_not_failed_recovery_attempts() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let checkpoint = checkpoint(operation_id, digest(b"diff"));
    let report = parse_epoch_report(&report("continue", ""))?;
    let baseline = assess_progress(&checkpoint, &report, &[])?;
    let history = [
        ProgressAssessment {
            recovery: Some(RecoveryStrategy::ReconstructFromEvidence),
            ..baseline.clone()
        },
        ProgressAssessment {
            recovery: Some(RecoveryStrategy::ReplaceApproach),
            ..baseline.clone()
        },
        ProgressAssessment {
            recovery: Some(RecoveryStrategy::FreshContextDiagnosis),
            ..baseline
        },
    ];
    assert_eq!(
        assess_progress(&checkpoint, &report, &history)?.recovery,
        Some(RecoveryStrategy::ReconstructFromEvidence)
    );
    Ok(())
}

#[test]
fn only_three_distinct_terminal_failed_recovery_attempts_can_block() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let checkpoint = checkpoint(operation_id, digest(b"diff"));
    let report = parse_epoch_report(&report("continue", ""))?;
    let baseline = assess_progress(&checkpoint, &report, &[])?;
    let attempts = [
        RecoveryAttempt {
            strategy: RecoveryStrategy::ReconstructFromEvidence,
            strategy_fingerprint: recovery_attempt_fingerprint(
                &baseline.fingerprint,
                RecoveryStrategy::ReconstructFromEvidence,
            ),
            outcome: RecoveryAttemptOutcome::Failed,
        },
        RecoveryAttempt {
            strategy: RecoveryStrategy::ReplaceApproach,
            strategy_fingerprint: recovery_attempt_fingerprint(
                &baseline.fingerprint,
                RecoveryStrategy::ReplaceApproach,
            ),
            outcome: RecoveryAttemptOutcome::Failed,
        },
        RecoveryAttempt {
            strategy: RecoveryStrategy::MinimizeReproduction,
            strategy_fingerprint: recovery_attempt_fingerprint(
                &baseline.fingerprint,
                RecoveryStrategy::MinimizeReproduction,
            ),
            outcome: RecoveryAttemptOutcome::Failed,
        },
    ];
    assert_eq!(
        assess_progress_with_recovery_attempts(&checkpoint, &report, &[baseline], &attempts)?
            .recovery,
        Some(RecoveryStrategy::DeclareBlocked)
    );
    Ok(())
}

#[test]
fn missing_authority_blocks_without_a_prior_stall() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let mut checkpoint = checkpoint(operation_id, digest(b"diff"));
    checkpoint.blockers.push("missing_authority".to_owned());
    let report = parse_epoch_report(&report("continue", ""))?;
    assert_eq!(
        assess_progress(&checkpoint, &report, &[])?.recovery,
        Some(RecoveryStrategy::DeclareBlocked)
    );
    Ok(())
}

#[test]
fn recovery_selection_is_independent_of_provider_metadata() -> TestResult {
    let operation_id = OperationId::from_uuid(uuid("33333333-3333-4333-8333-333333333333"));
    let mut first = checkpoint(operation_id, digest(b"diff"));
    let mut second = first.clone();
    first.provider.context_id = None;
    second.provider.provider = "different-provider".to_owned();
    second.provider.model = "different-model".to_owned();
    second.provider.context_id = Some("different-context".to_owned());
    let report = parse_epoch_report(&report("continue", ""))?;
    let first_baseline = assess_progress(&first, &report, &[])?;
    let second_baseline = assess_progress(&second, &report, &[])?;
    assert_eq!(first_baseline.fingerprint, second_baseline.fingerprint);
    assert_eq!(
        assess_progress(&first, &report, std::slice::from_ref(&first_baseline))?.recovery,
        assess_progress(&second, &report, std::slice::from_ref(&second_baseline))?.recovery
    );
    Ok(())
}
