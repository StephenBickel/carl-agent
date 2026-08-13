#![cfg(unix)]

use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::runtime::agent_port::{
    AgentCapabilities, AgentContextId, AgentEpochId, AgentEvent, AgentFuture, AgentModel,
    AgentPort, AgentProcess, AgentRequestId, EffectDecision, ResumeAgentContext, StartAgentContext,
    StartAgentEpoch,
};
use carl::runtime::task::TaskStatus;
use carl::service::client::TaskServiceClient;
use carl::service::protocol::{
    SERVICE_PROTOCOL_VERSION, ServiceCommand, ServiceRequest, ServiceResult,
};
use carl::service::server::TaskService;
use carl::tui::command::{SlashCommand, SubmittedInput};
use carl::tui::controller::{ServiceTuiBackend, TuiController};
use carl::tui::state::{Overlay, TuiEvent, TuiState};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[tokio::test(flavor = "current_thread")]
async fn durable_tui_sessions_survive_reconnect_without_duplicate_provider_effects() -> TestResult {
    let layout = Layout::new()?;
    let provider = PendingPort::new();
    let observations = Arc::clone(&provider.state);
    let service = TaskService::bind(&layout.data, provider).await?;
    let running = tokio::spawn(service.serve(CancellationToken::new()));

    let client = TaskServiceClient::connect(&layout.data).await?;
    let mut controller =
        TuiController::new(ServiceTuiBackend::new(client), layout.workspace.clone());
    let mut state = TuiState::default();
    apply(&mut state, controller.initialize().await?)?;
    apply(
        &mut state,
        controller
            .submit(SubmittedInput::Prompt(
                "inspect the repository safely".to_owned(),
            ))
            .await?,
    )?;
    let first_session = state
        .external_session_id()
        .ok_or("first TUI session was not bound")?
        .to_owned();

    tokio::time::timeout(Duration::from_secs(5), async {
        while state.status().is_none() {
            apply(&mut state, controller.poll_updates().await.unwrap()).unwrap();
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "initial TUI status was not published")?;
    apply(
        &mut state,
        controller
            .submit(SubmittedInput::Command(SlashCommand::Effort(
                ReasoningEffort::High,
            )))
            .await?,
    )?;
    apply(
        &mut state,
        controller
            .submit(SubmittedInput::Command(SlashCommand::Permissions(
                PermissionMode::FullAccess,
            )))
            .await?,
    )?;
    drop(controller);

    let client = TaskServiceClient::connect(&layout.data).await?;
    let mut reconnected =
        TuiController::new(ServiceTuiBackend::new(client), layout.workspace.clone());
    let loaded = reconnected.initialize().await?;
    apply(&mut state, loaded)?;
    let Some(Overlay::Sessions(sessions)) = state.overlay() else {
        return Err("durable session overlay was not restored".into());
    };
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].external_session_id, first_session);
    apply(
        &mut state,
        reconnected
            .submit(SubmittedInput::Command(SlashCommand::Resume(
                "1".to_owned(),
            )))
            .await?,
    )?;
    apply(
        &mut state,
        reconnected
            .submit(SubmittedInput::Command(SlashCommand::Cancel))
            .await?,
    )?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !state.status().is_some_and(TaskStatus::is_terminal) {
            apply(&mut state, reconnected.poll_updates().await.unwrap()).unwrap();
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        format!(
            "cancel did not become terminal; last status: {:?}",
            state.status()
        )
    })?;

    apply(
        &mut state,
        reconnected
            .submit(SubmittedInput::Command(SlashCommand::New))
            .await?,
    )?;
    assert!(state.external_session_id().is_none());
    apply(
        &mut state,
        reconnected
            .submit(SubmittedInput::Prompt(
                "start a second durable task".to_owned(),
            ))
            .await?,
    )?;
    apply(
        &mut state,
        reconnected
            .submit(SubmittedInput::Command(SlashCommand::Sessions))
            .await?,
    )?;
    let Some(Overlay::Sessions(sessions)) = state.overlay() else {
        return Err("second durable session list was not shown".into());
    };
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|session| session.provider == "openai_subscription")
    );
    assert!(
        sessions
            .iter()
            .all(|session| session.permission_mode == PermissionMode::FullAccess)
    );
    {
        let observations = observations.lock().unwrap();
        assert_eq!(observations.effect_resolutions, 0);
        assert!(observations.started_contexts <= 2);
    }

    let mut owner = TaskServiceClient::connect(&layout.data).await?;
    assert_eq!(
        owner
            .request(ServiceRequest {
                protocol_version: SERVICE_PROTOCOL_VERSION,
                request_id: "tui-e2e-shutdown".to_owned(),
                idempotency_key: "tui-e2e-shutdown-key".to_owned(),
                command: ServiceCommand::Shutdown,
            })
            .await?,
        ServiceResult::Applied
    );
    running.await??;
    Ok(())
}

fn apply(state: &mut TuiState, events: Vec<TuiEvent>) -> TestResult {
    for event in events {
        state.apply(event)?;
    }
    Ok(())
}

struct Layout {
    root: PathBuf,
    data: PathBuf,
    workspace: PathBuf,
}

impl Layout {
    fn new() -> TestResult<Self> {
        let root = PathBuf::from("/tmp").join(format!("carl-tui-e2e-{}", Uuid::new_v4()));
        let data = root.join("data");
        let workspace = root.join("workspace");
        fs::create_dir_all(&data)?;
        fs::create_dir_all(&workspace)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            root,
            data: fs::canonicalize(data)?,
            workspace: fs::canonicalize(workspace)?,
        })
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Default)]
struct PendingState {
    events: VecDeque<AgentEvent>,
    started_contexts: u64,
    epochs: u64,
    effect_resolutions: u64,
}

struct PendingPort {
    state: Arc<Mutex<PendingState>>,
}

impl PendingPort {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(PendingState::default())),
        }
    }
}

impl AgentPort for PendingPort {
    fn supports_autonomous_tasks(&self) -> bool {
        true
    }

    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            resume: true,
            compact: true,
            token_usage: false,
            pre_dispatch_effects: true,
            history_paging: false,
            background_processes: false,
        }
    }

    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>> {
        Box::pin(async {
            Ok(vec![AgentModel {
                id: ModelId::parse("gpt-test").expect("model fixture is valid"),
                display_name: "GPT Test".to_owned(),
                supported_efforts: vec![ReasoningEffort::Medium, ReasoningEffort::High],
                default_effort: ReasoningEffort::Medium,
            }])
        })
    }

    fn start_context(&mut self, _request: StartAgentContext) -> AgentFuture<'_, AgentContextId> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut state = state.lock().unwrap();
            state.started_contexts += 1;
            AgentContextId::parse(format!("tui-context-{}", state.started_contexts))
        })
    }

    fn resume_context(&mut self, request: ResumeAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async move { Ok(request.context_id) })
    }

    fn compact_context(&mut self, _context_id: &AgentContextId) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            let mut state = state.lock().unwrap();
            state.epochs += 1;
            let epoch_id = AgentEpochId::parse(format!("tui-epoch-{}", state.epochs))?;
            state.events.push_back(AgentEvent::EpochStarted {
                context_id: request.context_id,
                epoch_id: epoch_id.clone(),
            });
            Ok(epoch_id)
        })
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
        Box::pin(async { Ok(()) })
    }

    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            loop {
                if let Some(event) = state.lock().unwrap().events.pop_front() {
                    return Ok(event);
                }
                tokio::task::yield_now().await;
            }
        })
    }

    fn resolve_effect(
        &mut self,
        _request_id: &AgentRequestId,
        _decision: EffectDecision,
    ) -> AgentFuture<'_, ()> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.lock().unwrap().effect_resolutions += 1;
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
        Box::pin(async { Ok(true) })
    }

    fn shutdown(&mut self) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}
