use std::collections::VecDeque;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::events::{SessionId, TurnId};
use carl::policy::Frontend;
use carl::runtime::task::{OperationId, TaskBudget, TaskId, TaskStatus};
use carl::service::protocol::{
    LiveUpdateEnvelope, LiveUpdatePage, SERVICE_PROTOCOL_VERSION, ServiceApprovalDecision,
    ServiceCapabilities, ServiceCommand, ServiceInfo, ServiceModel, ServiceResult,
    ServiceSessionSummary, TaskUpdate,
};
use carl::tui::command::{SlashCommand, SubmittedInput};
use carl::tui::controller::{TuiBackend, TuiController, TuiError};
use carl::tui::state::TuiEvent;
use chrono::{TimeZone, Utc};

struct FakeBackend {
    info: ServiceInfo,
    responses: VecDeque<ServiceResult>,
    commands: Vec<ServiceCommand>,
}

impl TuiBackend for FakeBackend {
    fn info(&self) -> &ServiceInfo {
        &self.info
    }

    fn request<'a>(
        &'a mut self,
        command: ServiceCommand,
    ) -> Pin<Box<dyn Future<Output = Result<ServiceResult, TuiError>> + Send + 'a>> {
        self.commands.push(command);
        Box::pin(async move { self.responses.pop_front().ok_or(TuiError::InvalidResponse) })
    }
}

#[tokio::test]
async fn prompt_and_configuration_are_exact_service_commands() {
    let task_id = TaskId::new();
    let backend = FakeBackend {
        info: info(),
        responses: VecDeque::from([
            ServiceResult::SessionList(Vec::new()),
            ServiceResult::Accepted { task_id },
            ServiceResult::Applied,
            ServiceResult::Applied,
            ServiceResult::Applied,
            ServiceResult::Applied,
        ]),
        commands: Vec::new(),
    };
    let workspace = PathBuf::from("/workspace");
    let mut controller = TuiController::new(backend, workspace.clone());
    controller.initialize().await.unwrap();
    let events = controller
        .submit(SubmittedInput::Prompt("fix it".to_owned()))
        .await
        .unwrap();
    assert!(events.iter().any(
        |event| matches!(event, TuiEvent::TaskBound { task_id: bound, .. } if *bound == task_id)
    ));
    controller
        .submit(SubmittedInput::Prompt("also run tests".to_owned()))
        .await
        .unwrap();
    controller
        .submit(SubmittedInput::Command(SlashCommand::Effort(
            ReasoningEffort::High,
        )))
        .await
        .unwrap();
    controller
        .submit(SubmittedInput::Command(SlashCommand::Permissions(
            PermissionMode::Plan,
        )))
        .await
        .unwrap();
    controller
        .submit(SubmittedInput::Command(SlashCommand::Compact))
        .await
        .unwrap();

    let backend = controller.into_backend();
    assert!(matches!(
        backend.commands[0],
        ServiceCommand::Sessions {
            frontend: Frontend::Tui,
            limit: 64
        }
    ));
    let ServiceCommand::StartTask(start) = &backend.commands[1] else {
        panic!("expected start")
    };
    assert_eq!(start.frontend, Frontend::Tui);
    assert_eq!(start.workspace, workspace);
    assert_eq!(start.request, "fix it");
    assert_eq!(start.permission_mode, PermissionMode::FullAccess);
    assert_eq!(start.budget, TaskBudget::default());
    assert!(
        matches!(&backend.commands[2], ServiceCommand::Steer { task_id: id, text } if *id == task_id && text == "also run tests")
    );
    assert!(
        matches!(&backend.commands[3], ServiceCommand::Configure { task_id: id, effort: ReasoningEffort::High, .. } if *id == task_id)
    );
    assert!(
        matches!(&backend.commands[4], ServiceCommand::Configure { task_id: id, permission_mode: PermissionMode::Plan, .. } if *id == task_id)
    );
    assert!(
        matches!(&backend.commands[5], ServiceCommand::Compact { task_id: id } if *id == task_id)
    );
}

#[tokio::test]
async fn sessions_resume_and_slice_one_provider_commands_are_honest() {
    let task_id = TaskId::new();
    let summary = ServiceSessionSummary {
        external_session_id: "tui-existing".to_owned(),
        session_id: SessionId::new(),
        workspace: PathBuf::from("/workspace"),
        permission_mode: PermissionMode::FullAccess,
        provider: "openai_subscription".to_owned(),
        latest_task_id: Some(task_id),
        latest_task_status: Some(TaskStatus::Active),
        model: Some(ModelId::parse("gpt-5.6-codex").unwrap()),
        effort: Some(ReasoningEffort::High),
        created_at: Utc.with_ymd_and_hms(2026, 8, 13, 12, 0, 0).unwrap(),
        updated_at: Utc.with_ymd_and_hms(2026, 8, 13, 12, 1, 0).unwrap(),
    };
    let backend = FakeBackend {
        info: info(),
        responses: VecDeque::from([
            ServiceResult::SessionList(vec![summary.clone()]),
            ServiceResult::SessionList(vec![summary]),
            ServiceResult::Applied,
        ]),
        commands: Vec::new(),
    };
    let mut controller = TuiController::new(backend, PathBuf::from("/workspace"));
    controller.initialize().await.unwrap();
    controller
        .submit(SubmittedInput::Command(SlashCommand::Sessions))
        .await
        .unwrap();
    controller
        .submit(SubmittedInput::Command(SlashCommand::Resume(
            "1".to_owned(),
        )))
        .await
        .unwrap();
    for command in [
        SlashCommand::Provider(None),
        SlashCommand::Login,
        SlashCommand::Logout,
    ] {
        let events = controller
            .submit(SubmittedInput::Command(command))
            .await
            .unwrap();
        assert!(
            events.iter().any(
                |event| matches!(event, TuiEvent::Notice(text) if text.contains("subscription"))
            )
        );
    }
    let backend = controller.into_backend();
    assert!(
        matches!(backend.commands.last(), Some(ServiceCommand::Resume { task_id: id }) if *id == task_id)
    );
}

#[tokio::test]
async fn new_session_clears_the_previous_binding_before_the_next_prompt() {
    let first_task = TaskId::new();
    let second_task = TaskId::new();
    let backend = FakeBackend {
        info: info(),
        responses: VecDeque::from([
            ServiceResult::SessionList(Vec::new()),
            ServiceResult::Accepted {
                task_id: first_task,
            },
            ServiceResult::Accepted {
                task_id: second_task,
            },
        ]),
        commands: Vec::new(),
    };
    let mut controller = TuiController::new(backend, PathBuf::from("/workspace"));
    controller.initialize().await.unwrap();
    controller
        .submit(SubmittedInput::Prompt("first".to_owned()))
        .await
        .unwrap();
    let cleared = controller
        .submit(SubmittedInput::Command(SlashCommand::New))
        .await
        .unwrap();
    assert_eq!(cleared, vec![TuiEvent::SessionCleared]);
    controller
        .submit(SubmittedInput::Prompt("second".to_owned()))
        .await
        .unwrap();
    let backend = controller.into_backend();
    assert!(matches!(backend.commands[2], ServiceCommand::StartTask(_)));
}

#[tokio::test]
async fn approval_resolution_is_bound_to_the_exact_durable_tui_notice() {
    let task_id = TaskId::new();
    let session_id = SessionId::new();
    let turn_id = TurnId::new();
    let summary = ServiceSessionSummary {
        external_session_id: "tui-approval".to_owned(),
        session_id,
        workspace: PathBuf::from("/workspace"),
        permission_mode: PermissionMode::Default,
        provider: "openai_subscription".to_owned(),
        latest_task_id: Some(task_id),
        latest_task_status: Some(TaskStatus::Active),
        model: Some(ModelId::parse("gpt-5.6-codex").unwrap()),
        effort: Some(ReasoningEffort::Medium),
        created_at: Utc.with_ymd_and_hms(2026, 8, 13, 12, 0, 0).unwrap(),
        updated_at: Utc.with_ymd_and_hms(2026, 8, 13, 12, 1, 0).unwrap(),
    };
    let approval = TaskUpdate::ApprovalRequired {
        task_id,
        operation_id: OperationId::new(),
        display_code: "approve-123".to_owned(),
        summary: "write src/lib.rs".to_owned(),
        request_id: "provider-request".to_owned(),
        session_id,
        turn_id,
        external_session_id: "tui-approval".to_owned(),
    };
    let backend = FakeBackend {
        info: info(),
        responses: VecDeque::from([
            ServiceResult::SessionList(vec![summary]),
            ServiceResult::Applied,
            ServiceResult::LiveUpdates(LiveUpdatePage {
                live_generation: "11111111-1111-4111-8111-111111111111".to_owned(),
                updates: vec![LiveUpdateEnvelope {
                    cursor: 1,
                    update: approval,
                }],
                cursor: Some(1),
                snapshot: None,
            }),
            ServiceResult::Applied,
        ]),
        commands: Vec::new(),
    };
    let mut controller = TuiController::new(backend, PathBuf::from("/workspace"));
    controller.initialize().await.unwrap();
    controller
        .submit(SubmittedInput::Command(SlashCommand::Resume(
            "1".to_owned(),
        )))
        .await
        .unwrap();
    controller.poll_updates().await.unwrap();
    controller
        .resolve_approval(ServiceApprovalDecision::Approve)
        .await
        .unwrap();
    let backend = controller.into_backend();
    assert!(matches!(
        backend.commands.last(),
        Some(ServiceCommand::ResolveApproval {
            task_id: id,
            external_session_id,
            frontend: Frontend::Tui,
            channel_id: None,
            event_id: None,
            display_code,
            session_id: bound_session,
            turn_id: bound_turn,
            decision: ServiceApprovalDecision::Approve,
            ..
        }) if *id == task_id
            && external_session_id == "tui-approval"
            && display_code == "approve-123"
            && *bound_session == session_id
            && *bound_turn == turn_id
    ));
}

fn info() -> ServiceInfo {
    ServiceInfo {
        protocol_version: SERVICE_PROTOCOL_VERSION,
        live_generation: "11111111-1111-4111-8111-111111111111".to_owned(),
        provider: "openai_subscription".to_owned(),
        models: vec![ServiceModel {
            id: ModelId::parse("gpt-5.6-codex").unwrap(),
            display_name: "GPT 5.6 Codex".to_owned(),
            supported_efforts: vec![ReasoningEffort::Medium, ReasoningEffort::High],
            default_effort: ReasoningEffort::Medium,
        }],
        default_model: Some(ModelId::parse("gpt-5.6-codex").unwrap()),
        default_effort: Some(ReasoningEffort::Medium),
        capabilities: ServiceCapabilities {
            durable_events: true,
            reconnect: true,
            trusted_buzz_admission: true,
            configure_active_task: true,
            explicit_task_budgets: true,
            sanitized_task_metrics: true,
            recoverable_maintenance: true,
            explicit_task_compaction: true,
            durable_frontend_sessions: true,
        },
    }
}
