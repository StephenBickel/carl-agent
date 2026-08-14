use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, mpsc};
use uuid::Uuid;

use super::*;
use crate::delegates::{ModelId, ReasoningEffort};
use crate::policy::{Frontend, Sha256Digest};
use crate::runtime::agent_port::{
    AgentCapabilities, AgentEffectKind, AgentFuture, AgentModel, AgentProcess, AgentRequestId,
};
use crate::storage::{
    ClientName, ExternalSessionId, NewFrontendSession, TrustedFrontendOwnerInput,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn trusted_taskless_session_configuration_persists_the_explicit_ceiling() -> TestResult {
    let fixture = Fixture::new()?;
    let store = Store::open(&fixture.database)?;
    let actor_id = ActorId::parse("b".repeat(64))?;
    store.trust_frontend_owner(TrustedFrontendOwnerInput {
        frontend: Frontend::Buzz,
        actor_id: actor_id.clone(),
        workspace: fixture.workspace.clone(),
        permission_mode: PermissionMode::FullAccess,
        trusted_at: Utc::now(),
    })?;
    let engine = TaskEngine::new(store, ApprovalPort::approval());
    engine.configure_owner_session(OwnerConfigureSession {
        external_session_id: "taskless-session".to_owned(),
        workspace: fixture.workspace.clone(),
        permission_mode: PermissionMode::Plan,
        admission: OwnerTrustedAdmission {
            frontend: Frontend::Buzz,
            actor_id,
            channel_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            event_id: "a".repeat(64),
            recover_existing: false,
        },
    })?;

    let binding = engine
        .store()
        .get_frontend_session("taskless-session")?
        .ok_or("taskless binding missing")?;
    assert_eq!(binding.permission_mode, PermissionMode::Plan);
    assert_eq!(
        binding.channel_id.as_ref().map(ChannelId::as_str),
        Some("11111111-1111-4111-8111-111111111111")
    );
    Ok(())
}

struct ApprovalPort {
    events: VecDeque<AgentEvent>,
    starts: usize,
    interrupts: usize,
    decisions: Vec<EffectDecision>,
    pending_planning: bool,
}

impl ApprovalPort {
    fn approval() -> Self {
        Self {
            events: VecDeque::new(),
            starts: 0,
            interrupts: 0,
            decisions: Vec::new(),
            pending_planning: false,
        }
    }

    fn pending_planning() -> Self {
        Self {
            pending_planning: true,
            ..Self::approval()
        }
    }
}

impl AgentPort for ApprovalPort {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            resume: true,
            compact: true,
            token_usage: true,
            pre_dispatch_effects: true,
            history_paging: false,
            background_processes: false,
        }
    }

    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn start_context(&mut self, _request: StartAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async { AgentContextId::parse("approval-context") })
    }

    fn resume_context(&mut self, request: ResumeAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async move { Ok(request.context_id) })
    }

    fn compact_context(&mut self, _context_id: &AgentContextId) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
        self.starts += 1;
        let context_id = request.context_id;
        let epoch_id = AgentEpochId::parse(format!("approval-epoch-{}", self.starts));
        let Ok(epoch_id) = epoch_id else {
            return Box::pin(async {
                Err(AgentPortError::from_code(
                    AgentPortErrorCode::InvalidResponse,
                ))
            });
        };
        self.events.push_back(AgentEvent::EpochStarted {
            context_id: context_id.clone(),
            epoch_id: epoch_id.clone(),
        });
        if request.permission_mode == PermissionMode::Plan {
            if !self.pending_planning {
                self.events.push_back(AgentEvent::AssistantDelta {
                    context_id: context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    text: "<carl-completion-contract>{\"version\":1,\"goal\":\"Approve bounded work\",\"constraints\":[],\"clauses\":[{\"id\":\"done\",\"description\":\"The work is done\",\"required\":true,\"status\":\"pending\",\"evidence\":[]}]}</carl-completion-contract>".to_owned(),
                });
                self.events.push_back(AgentEvent::EpochCompleted {
                    context_id,
                    epoch_id: epoch_id.clone(),
                    status: "completed".to_owned(),
                });
            }
        } else {
            let item_id = "approval-item".to_owned();
            self.events.push_back(AgentEvent::ItemStarted {
                context_id: context_id.clone(),
                epoch_id: epoch_id.clone(),
                item: AgentItem::Command {
                    item_id: item_id.clone(),
                    command: "cargo test".to_owned(),
                    cwd: PathBuf::from("/workspace"),
                    status: "inProgress".to_owned(),
                    exit_code: None,
                    aggregated_output: None,
                    process_id: None,
                },
            });
            self.events
                .push_back(AgentEvent::EffectRequested(AgentEffectRequest {
                    context_id,
                    epoch_id: epoch_id.clone(),
                    request_id: AgentRequestId::parse("approval-request")
                        .expect("fixed request ID is valid"),
                    item_id,
                    kind: AgentEffectKind::Command,
                    summary: "Run bounded verification".to_owned(),
                    request_digest: Sha256Digest::parse("a".repeat(64))
                        .expect("fixed digest is valid"),
                }));
        }
        Box::pin(async move { Ok(epoch_id) })
    }

    fn steer(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
        _text: String,
    ) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn interrupt(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
    ) -> AgentFuture<'_, ()> {
        self.interrupts += 1;
        Box::pin(async { Ok(()) })
    }

    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent> {
        let event = self.events.pop_front();
        Box::pin(async move {
            match event {
                Some(event) => Ok(event),
                None => std::future::pending().await,
            }
        })
    }

    fn resolve_effect(
        &mut self,
        _request_id: &AgentRequestId,
        decision: EffectDecision,
    ) -> AgentFuture<'_, ()> {
        self.decisions.push(decision);
        Box::pin(async { Ok(()) })
    }

    fn list_background_processes(
        &mut self,
        _context_id: &AgentContextId,
    ) -> AgentFuture<'_, Vec<AgentProcess>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn terminate_background_process(
        &mut self,
        _context_id: &AgentContextId,
        _process_id: &str,
    ) -> AgentFuture<'_, bool> {
        Box::pin(async { Ok(false) })
    }

    fn shutdown(&mut self) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

struct Fixture {
    root: PathBuf,
    workspace: PathBuf,
    database: PathBuf,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!("carl-engine-approval-{}", Uuid::new_v4()));
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace)?;
        let workspace = fs::canonicalize(workspace)?;
        Ok(Self {
            database: root.join("carl.sqlite3"),
            root,
            workspace,
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn input(
    session_id: SessionId,
    fixture: &Fixture,
    max_wall_time_seconds: Option<u64>,
) -> StartTask {
    StartTask {
        session_id,
        workspace: fixture.workspace.clone(),
        request: "Run the bounded verification".to_owned(),
        model: ModelId::parse("gpt-5.6-codex").expect("fixed model is valid"),
        effort: ReasoningEffort::High,
        permission_mode: PermissionMode::Default,
        budget: TaskBudget {
            max_wall_time_seconds,
            ..TaskBudget::default()
        },
    }
}

fn install_frontend<P: AgentPort>(
    engine: &mut TaskEngine<P>,
    session_id: SessionId,
    workspace: PathBuf,
) -> TurnId {
    let turn_id = TurnId::new();
    let external_session_id = ExternalSessionId::try_from(format!("session-{}", Uuid::new_v4()))
        .expect("fixed external session is valid");
    engine
        .store()
        .bind_frontend_session(NewFrontendSession {
            frontend: Frontend::Acp,
            external_session_id: external_session_id.clone(),
            session_id,
            cwd: workspace,
            protocol_version: 2,
            client_name: ClientName::try_from("engine-contract")
                .expect("fixed client name is valid"),
            permission_mode: PermissionMode::Default,
            channel_id: None,
            created_at: Utc::now(),
        })
        .expect("frontend session binding succeeds");
    engine.install_frontend_context(TaskEngineFrontendContext {
        session_id,
        turn_id,
        external_session_id,
        actor_id: ActorId::parse("owner").expect("fixed actor is valid"),
    });
    turn_id
}

fn only_operation_status(engine: &TaskEngine<ApprovalPort>, task_id: TaskId) -> OperationStatus {
    let operation_id = engine
        .store()
        .read_task_events(task_id)
        .expect("task events remain readable")
        .into_iter()
        .find_map(|envelope| match envelope.event {
            crate::events::Event::TaskLifecycle {
                event: TaskEvent::OperationIntentRecorded { operation_id, .. },
                ..
            } => Some(operation_id),
            _ => None,
        })
        .expect("one operation was recorded");
    engine
        .store()
        .get_task(task_id)
        .expect("task lookup succeeds")
        .expect("task remains projected")
        .snapshot
        .operation_status(operation_id)
        .expect("operation remains projected")
}

fn assert_safely_blocked(engine: &mut TaskEngine<ApprovalPort>) -> TestResult {
    let record = engine.store().list_resumable_tasks()?.remove(0);
    let events = engine.store().read_task_events(record.snapshot.task_id)?;
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    assert_eq!(record.snapshot.active_epoch, None);
    assert_eq!(
        only_operation_status(engine, record.snapshot.task_id),
        OperationStatus::Failed,
        "{events:?}"
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

#[tokio::test(start_paused = true)]
async fn owner_approval_wait_is_bounded_by_the_hard_wall_deadline() -> TestResult {
    let fixture = Fixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut engine = TaskEngine::new(store, ApprovalPort::approval());
    install_frontend(&mut engine, session.id, fixture.workspace.clone());
    let (control_sender, control_receiver) = mpsc::channel(1);
    let (acknowledgement_sender, _acknowledgement_receiver) = mpsc::channel(1);
    let (permission_sender, mut permission_receiver) = mpsc::channel(1);
    engine.install_controls(control_receiver, acknowledgement_sender, permission_sender);
    let notice = tokio::spawn(async move {
        permission_receiver
            .recv()
            .await
            .expect("approval notice remains deliverable");
        std::future::pending::<()>().await;
    });

    // The engine derives the budget from real UTC before arming Tokio's paused
    // timer. Leave ample setup headroom so parallel CI load cannot exhaust the
    // budget before the approval operation is durably recorded.
    let error = tokio::time::timeout(
        Duration::from_secs(65),
        engine.start(input(session.id, &fixture, Some(60))),
    )
    .await
    .expect("approval wait must observe the task wall deadline")
    .unwrap_err();

    notice.abort();
    drop(control_sender);
    assert_eq!(error.code(), TaskEngineErrorCode::Blocked);
    assert_safely_blocked(&mut engine)?;
    assert!(engine.port.decisions.is_empty());
    assert_eq!(engine.port.interrupts, 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn approval_notice_delivery_failure_safely_blocks_before_dispatch() -> TestResult {
    let fixture = Fixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut engine = TaskEngine::new(store, ApprovalPort::approval());
    install_frontend(&mut engine, session.id, fixture.workspace.clone());
    let (_control_sender, control_receiver) = mpsc::channel(1);
    let (acknowledgement_sender, _acknowledgement_receiver) = mpsc::channel(1);
    let (permission_sender, permission_receiver) = mpsc::channel(1);
    drop(permission_receiver);
    engine.install_controls(control_receiver, acknowledgement_sender, permission_sender);

    let error = tokio::time::timeout(
        Duration::from_secs(2),
        engine.start(input(session.id, &fixture, None)),
    )
    .await
    .expect("closed approval controls must wake the engine")
    .unwrap_err();

    assert_eq!(error.code(), TaskEngineErrorCode::Blocked);
    assert_safely_blocked(&mut engine)?;
    assert!(engine.port.decisions.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn approval_control_channel_closure_safely_blocks_before_dispatch() -> TestResult {
    let fixture = Fixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut engine = TaskEngine::new(store, ApprovalPort::approval());
    install_frontend(&mut engine, session.id, fixture.workspace.clone());
    let (control_sender, control_receiver) = mpsc::channel(1);
    let (acknowledgement_sender, _acknowledgement_receiver) = mpsc::channel(1);
    let (permission_sender, mut permission_receiver) = mpsc::channel(1);
    engine.install_controls(control_receiver, acknowledgement_sender, permission_sender);
    let close_controls = tokio::spawn(async move {
        permission_receiver
            .recv()
            .await
            .expect("approval notice remains deliverable");
        drop(control_sender);
    });

    let error = tokio::time::timeout(
        Duration::from_secs(2),
        engine.start(input(session.id, &fixture, None)),
    )
    .await
    .expect("closed approval controls must wake the engine")
    .unwrap_err();

    close_controls.await?;
    assert_eq!(error.code(), TaskEngineErrorCode::Blocked);
    assert_safely_blocked(&mut engine)?;
    assert!(engine.port.decisions.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_approval_acknowledges_the_same_typed_blocked_outcome_as_the_task() -> TestResult {
    let fixture = Fixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut engine = TaskEngine::new(store, ApprovalPort::approval());
    let turn_id = install_frontend(&mut engine, session.id, fixture.workspace.clone());
    let (control_sender, control_receiver) = mpsc::channel(1);
    let (acknowledgement_sender, mut acknowledgement_receiver) = mpsc::channel(1);
    let (permission_sender, mut permission_receiver) = mpsc::channel(1);
    engine.install_controls(control_receiver, acknowledgement_sender, permission_sender);
    let invalid_approval = tokio::spawn(async move {
        permission_receiver
            .recv()
            .await
            .expect("approval notice remains deliverable");
        control_sender
            .send(TaskEngineControl::Approval {
                display_code: "invalid-approval-code".to_owned(),
                decision: EffectDecision::Allow,
                session_id: session.id,
                turn_id,
                acknowledgement: 7,
            })
            .await
            .expect("invalid approval remains deliverable");
    });

    let error = engine
        .start(input(session.id, &fixture, None))
        .await
        .unwrap_err();
    invalid_approval.await?;
    let (acknowledgement, acknowledged) = acknowledgement_receiver
        .recv()
        .await
        .expect("approval receives one acknowledgement");

    assert_eq!(error.code(), TaskEngineErrorCode::Blocked);
    assert_eq!(acknowledgement, 7);
    assert_eq!(
        acknowledged.unwrap_err().code(),
        TaskEngineErrorCode::Blocked
    );
    assert_safely_blocked(&mut engine)?;
    assert!(engine.port.decisions.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn planning_approval_control_closes_the_epoch_with_typed_blocked() -> TestResult {
    let fixture = Fixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let mut engine = TaskEngine::new(store, ApprovalPort::pending_planning());
    let turn_id = install_frontend(&mut engine, session.id, fixture.workspace.clone());
    let (control_sender, control_receiver) = mpsc::channel(1);
    let (acknowledgement_sender, _acknowledgement_receiver) = mpsc::channel(1);
    let (permission_sender, _permission_receiver) = mpsc::channel(1);
    engine.install_controls(control_receiver, acknowledgement_sender, permission_sender);
    control_sender
        .send(TaskEngineControl::Approval {
            display_code: "invalid-planning-code".to_owned(),
            decision: EffectDecision::Allow,
            session_id: session.id,
            turn_id,
            acknowledgement: 1,
        })
        .await?;

    let error = engine
        .start(input(session.id, &fixture, None))
        .await
        .unwrap_err();

    assert_eq!(error.code(), TaskEngineErrorCode::Blocked);
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
    assert_eq!(engine.port.interrupts, 1);
    Ok(())
}

#[derive(Clone)]
struct QuiescePort {
    state: Arc<Mutex<QuiescePortState>>,
    changed: Arc<Notify>,
}

#[derive(Default)]
struct QuiescePortState {
    events: VecDeque<AgentEvent>,
    epoch_starts: usize,
    work_epoch_starts: usize,
    effect_count: usize,
    boundary_requests: usize,
    compactions: usize,
    operation_id: Option<String>,
    boundary_released: bool,
    work_completion_queued: bool,
    workspace: PathBuf,
}

impl QuiescePort {
    fn new(workspace: PathBuf) -> Self {
        Self {
            state: Arc::new(Mutex::new(QuiescePortState {
                workspace,
                ..QuiescePortState::default()
            })),
            changed: Arc::new(Notify::new()),
        }
    }

    fn release_boundary(&self) {
        self.state.lock().unwrap().boundary_released = true;
        self.changed.notify_waiters();
    }

    async fn wait_for_effect(&self) {
        loop {
            let changed = self.changed.notified();
            if self.state.lock().unwrap().effect_count == 1 {
                return;
            }
            changed.await;
        }
    }
}

impl AgentPort for QuiescePort {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            resume: true,
            compact: true,
            token_usage: true,
            pre_dispatch_effects: true,
            history_paging: false,
            background_processes: false,
        }
    }

    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn start_context(&mut self, _request: StartAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async { AgentContextId::parse("quiesce-context") })
    }

    fn resume_context(&mut self, request: ResumeAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async move { Ok(request.context_id) })
    }

    fn compact_context(&mut self, _context_id: &AgentContextId) -> AgentFuture<'_, ()> {
        self.state.lock().unwrap().compactions += 1;
        Box::pin(async { Ok(()) })
    }

    fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
        let mut state = self.state.lock().unwrap();
        state.epoch_starts += 1;
        let epoch_id = AgentEpochId::parse(format!("quiesce-epoch-{}", state.epoch_starts));
        let Ok(epoch_id) = epoch_id else {
            return Box::pin(async {
                Err(AgentPortError::from_code(
                    AgentPortErrorCode::InvalidResponse,
                ))
            });
        };
        let context_id = request.context_id;
        state.events.push_back(AgentEvent::EpochStarted {
            context_id: context_id.clone(),
            epoch_id: epoch_id.clone(),
        });
        if request.permission_mode == PermissionMode::Plan {
            state.events.push_back(AgentEvent::AssistantDelta {
                context_id: context_id.clone(),
                epoch_id: epoch_id.clone(),
                text: "<carl-completion-contract>{\"version\":1,\"goal\":\"Quiesce bounded work\",\"constraints\":[],\"clauses\":[{\"id\":\"done\",\"description\":\"The work is done\",\"required\":true,\"status\":\"pending\",\"evidence\":[]}]}</carl-completion-contract>".to_owned(),
            });
            state.events.push_back(AgentEvent::EpochCompleted {
                context_id,
                epoch_id: epoch_id.clone(),
                status: "completed".to_owned(),
            });
        } else {
            state.work_epoch_starts += 1;
            let item_id = "quiesce-command".to_owned();
            let workspace = state.workspace.clone();
            state.events.push_back(AgentEvent::ItemStarted {
                context_id: context_id.clone(),
                epoch_id: epoch_id.clone(),
                item: AgentItem::Command {
                    item_id: item_id.clone(),
                    command: "cargo test --test focused".to_owned(),
                    cwd: workspace,
                    status: "inProgress".to_owned(),
                    exit_code: None,
                    aggregated_output: None,
                    process_id: None,
                },
            });
            state
                .events
                .push_back(AgentEvent::EffectRequested(AgentEffectRequest {
                    context_id,
                    epoch_id: epoch_id.clone(),
                    request_id: AgentRequestId::parse("quiesce-request")
                        .expect("fixed request is valid"),
                    item_id,
                    kind: AgentEffectKind::Command,
                    summary: "Run focused verification".to_owned(),
                    request_digest: Sha256Digest::parse("a".repeat(64))
                        .expect("fixed digest is valid"),
                }));
        }
        Box::pin(async move { Ok(epoch_id) })
    }

    fn steer(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
        text: String,
    ) -> AgentFuture<'_, ()> {
        let mut state = self.state.lock().unwrap();
        if let Some(operation_id) = text.strip_prefix("carl-operation-id:") {
            state.operation_id = Some(operation_id.trim().to_owned());
        } else if text.starts_with("Carl soft epoch boundary") {
            state.boundary_requests += 1;
        }
        drop(state);
        self.changed.notify_waiters();
        Box::pin(async { Ok(()) })
    }

    fn interrupt(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
    ) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent> {
        let state = Arc::clone(&self.state);
        let changed = Arc::clone(&self.changed);
        Box::pin(async move {
            loop {
                if let Some(event) = state.lock().unwrap().events.pop_front() {
                    return Ok(event);
                }
                {
                    let mut state = state.lock().unwrap();
                    if state.boundary_released && !state.work_completion_queued {
                        let operation_id = state
                            .operation_id
                            .clone()
                            .expect("the real operation was bound before release");
                        let context_id = AgentContextId::parse("quiesce-context")?;
                        let epoch_id =
                            AgentEpochId::parse(format!("quiesce-epoch-{}", state.epoch_starts))?;
                        let workspace = state.workspace.clone();
                        state.events.push_back(AgentEvent::ItemCompleted {
                            context_id: context_id.clone(),
                            epoch_id: epoch_id.clone(),
                            item: AgentItem::Command {
                                item_id: "quiesce-command".to_owned(),
                                command: "cargo test --test focused".to_owned(),
                                cwd: workspace,
                                status: "completed".to_owned(),
                                exit_code: Some(0),
                                aggregated_output: Some("focused verification passed".to_owned()),
                                process_id: None,
                            },
                        });
                        state.events.push_back(AgentEvent::AssistantDelta {
                            context_id: context_id.clone(),
                            epoch_id: epoch_id.clone(),
                            text: format!(
                                "<carl-epoch-report>{{\"schema_version\":1,\"disposition\":\"continue\",\"summary\":\"First operation committed\",\"next_objective\":\"Finish the task\",\"clause_evidence\":[],\"exact_identifiers\":[{operation_id:?}]}}</carl-epoch-report>"
                            ),
                        });
                        state.events.push_back(AgentEvent::EpochCompleted {
                            context_id,
                            epoch_id,
                            status: "completed".to_owned(),
                        });
                        state.work_completion_queued = true;
                        continue;
                    }
                }
                changed.notified().await;
            }
        })
    }

    fn resolve_effect(
        &mut self,
        _request_id: &AgentRequestId,
        decision: EffectDecision,
    ) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        let changed = Arc::clone(&self.changed);
        Box::pin(async move {
            assert_eq!(decision, EffectDecision::Allow);
            state.lock().unwrap().effect_count += 1;
            changed.notify_waiters();
            Ok(())
        })
    }

    fn list_background_processes(
        &mut self,
        _context_id: &AgentContextId,
    ) -> AgentFuture<'_, Vec<AgentProcess>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn terminate_background_process(
        &mut self,
        _context_id: &AgentContextId,
        _process_id: &str,
    ) -> AgentFuture<'_, bool> {
        Box::pin(async { Ok(false) })
    }

    fn shutdown(&mut self) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test(start_paused = true)]
async fn repeated_quiesce_coalesces_one_boundary_and_returns_the_committed_active_snapshot()
-> TestResult {
    let fixture = Fixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = QuiescePort::new(fixture.workspace.clone());
    let observed = port.clone();
    let release = port.clone();
    let mut engine = TaskEngine::new(store, port);
    install_frontend(&mut engine, session.id, fixture.workspace.clone());
    let mut task_input = input(session.id, &fixture, None);
    task_input.permission_mode = PermissionMode::FullAccess;
    let task_id = engine.enqueue_with_receipt(task_input, None)?.task_id;
    let (control_sender, control_receiver) = mpsc::channel(2);
    let control_keepalive = control_sender.clone();
    let (acknowledgement_sender, mut acknowledgement_receiver) = mpsc::channel(2);
    let (permission_sender, _permission_receiver) = mpsc::channel(1);
    engine.install_controls(control_receiver, acknowledgement_sender, permission_sender);

    let controls = tokio::spawn(async move {
        observed.wait_for_effect().await;
        control_sender
            .send(TaskEngineControl::Quiesce {
                task_id,
                acknowledgement: 41,
            })
            .await
            .expect("first quiesce remains deliverable");
        assert_eq!(acknowledgement_receiver.recv().await.unwrap().0, 41);
        control_sender
            .send(TaskEngineControl::Quiesce {
                task_id,
                acknowledgement: 42,
            })
            .await
            .expect("repeated quiesce remains deliverable");
        assert_eq!(acknowledgement_receiver.recv().await.unwrap().0, 42);
        release.release_boundary();
    });

    let result = tokio::time::timeout(Duration::from_secs(2), engine.run(task_id))
        .await
        .expect("quiesce must return after the committed checkpoint");
    controls.await?;
    let snapshot = result.unwrap_or_else(|error| {
        panic!(
            "quiesce failed {error:?}: {:?}",
            engine.store().read_task_events(task_id).unwrap()
        )
    });
    drop(control_keepalive);

    assert_eq!(snapshot.status, TaskStatus::Active);
    assert_eq!(snapshot.active_epoch, None);
    assert!(snapshot.latest_checkpoint.is_some());
    let state = engine.port.state.lock().unwrap();
    assert_eq!(state.effect_count, 1);
    assert_eq!(state.boundary_requests, 1);
    assert_eq!(state.work_epoch_starts, 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn explicit_compaction_waits_for_one_safe_checkpoint_and_compacts_below_pressure()
-> TestResult {
    let fixture = Fixture::new()?;
    let store = Store::open(&fixture.database)?;
    let session = store.create_session()?;
    let port = QuiescePort::new(fixture.workspace.clone());
    let observed = port.clone();
    let release = port.clone();
    let mut engine = TaskEngine::new(store, port);
    install_frontend(&mut engine, session.id, fixture.workspace.clone());
    let mut task_input = input(session.id, &fixture, None);
    task_input.permission_mode = PermissionMode::FullAccess;
    let task_id = engine.enqueue_with_receipt(task_input, None)?.task_id;
    let (control_sender, control_receiver) = mpsc::channel(1);
    let control_keepalive = control_sender.clone();
    let (acknowledgement_sender, mut acknowledgement_receiver) = mpsc::channel(1);
    let (permission_sender, _permission_receiver) = mpsc::channel(1);
    engine.install_controls(control_receiver, acknowledgement_sender, permission_sender);

    let controls = tokio::spawn(async move {
        observed.wait_for_effect().await;
        control_sender
            .send(TaskEngineControl::Compact {
                task_id,
                acknowledgement: 51,
            })
            .await
            .expect("explicit compaction remains deliverable");
        assert_eq!(acknowledgement_receiver.recv().await.unwrap().0, 51);
        release.release_boundary();
    });

    let result = tokio::time::timeout(Duration::from_secs(2), engine.run(task_id))
        .await
        .expect("explicit compaction must reach a safe checkpoint");
    controls.await?;
    let snapshot = result.unwrap_or_else(|error| {
        panic!(
            "explicit compaction failed {error:?}: {:?}",
            engine.store().read_task_events(task_id).unwrap()
        )
    });
    drop(control_keepalive);

    assert_eq!(snapshot.status, TaskStatus::Active);
    let state = engine.port.state.lock().unwrap();
    assert_eq!(state.boundary_requests, 1);
    assert_eq!(state.compactions, 1);
    drop(state);
    let events = engine.store().read_task_events(task_id)?;
    assert_eq!(
        events
            .iter()
            .filter(|envelope| matches!(
                envelope.event,
                crate::events::Event::TaskLifecycle {
                    event: TaskEvent::CompactionRequested { .. },
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
                crate::events::Event::TaskLifecycle {
                    event: TaskEvent::CompactionCompleted { .. },
                    ..
                }
            ))
            .count(),
        1
    );
    Ok(())
}
