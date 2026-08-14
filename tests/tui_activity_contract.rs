use std::time::Duration;

use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::events::{SessionId, TurnId};
use carl::runtime::task::{CheckpointId, OperationId, TaskId, TaskStatus};
use carl::service::protocol::TaskUpdate;
use carl::tui::activity::{ActivityPhase, ActivityTone};
use carl::tui::state::{TuiEvent, TuiState, TuiStateError};

#[test]
fn active_activity_pulses_and_reports_authoritative_staleness() {
    let mut state = bound_state();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::Status(TaskStatus::Active)))
        .unwrap();

    state
        .apply(TuiEvent::Tick {
            elapsed: Duration::from_millis(80),
        })
        .unwrap();
    let activity = state.activity();
    assert_eq!(activity.symbol, "⠙");
    assert_eq!(activity.phase, ActivityPhase::Thinking);
    assert_eq!(activity.label, "Thinking…");
    assert_eq!(activity.tone, ActivityTone::Active);
    assert!(activity.animated);
    assert_eq!(activity.elapsed_seconds, None);

    state
        .apply(TuiEvent::Tick {
            elapsed: Duration::from_secs(11),
        })
        .unwrap();
    let stale = state.activity();
    assert_eq!(stale.elapsed_seconds, Some(11));
    assert_eq!(stale.stale_seconds, Some(11));

    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::AssistantDelta(
            "still working".to_owned(),
        )))
        .unwrap();
    assert_eq!(state.activity().stale_seconds, None);
    state
        .apply(TuiEvent::Tick {
            elapsed: Duration::from_secs(21),
        })
        .unwrap();
    assert_eq!(state.activity().stale_seconds, Some(10));
}

#[test]
fn phase_priority_uses_running_tools_but_terminal_status_wins() {
    let mut state = bound_state();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::Status(TaskStatus::Active)))
        .unwrap();
    for (summary, label) in [
        ("read_file src/lib.rs", "Reading src/lib.rs"),
        ("list_files src", "Listing src"),
        ("search_files parser", "Searching parser"),
        ("apply_patch src/lib.rs", "Editing src/lib.rs"),
        ("run_command cargo test", "Running cargo test"),
    ] {
        state
            .apply(TuiEvent::TaskUpdate(TaskUpdate::ToolStarted(
                summary.to_owned(),
            )))
            .unwrap();
        assert_eq!(state.activity().label, label);
        state
            .apply(TuiEvent::TaskUpdate(TaskUpdate::ToolCompleted(
                summary.to_owned(),
            )))
            .unwrap();
    }

    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::ToolStarted(
            "custom_tool opaque detail".to_owned(),
        )))
        .unwrap();
    assert_eq!(state.activity().label, "custom_tool opaque detail");
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::Status(
            TaskStatus::Completed,
        )))
        .unwrap();
    let completed = state.activity();
    assert_eq!(completed.phase, ActivityPhase::Completed);
    assert_eq!(completed.symbol, "✓");
    assert!(!completed.animated);
}

#[test]
fn waiting_compaction_and_connection_phases_are_honest() {
    let mut state = bound_state();
    assert_eq!(state.activity().phase, ActivityPhase::Starting);

    state.apply(TuiEvent::CompactionRequested).unwrap();
    assert_eq!(state.activity().phase, ActivityPhase::Compacting);
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::Checkpoint(
            CheckpointId::new(),
        )))
        .unwrap();
    assert_eq!(state.activity().phase, ActivityPhase::Starting);

    let task_id = TaskId::new();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::ApprovalRequired {
            task_id,
            operation_id: OperationId::new(),
            display_code: "approve-123".to_owned(),
            summary: "write src/lib.rs".to_owned(),
            request_id: "provider-request".to_owned(),
            session_id: SessionId::new(),
            turn_id: TurnId::new(),
            external_session_id: "tui-session".to_owned(),
        }))
        .unwrap();
    let waiting = state.activity();
    assert_eq!(waiting.phase, ActivityPhase::WaitingApproval);
    assert_eq!(waiting.symbol, "?");
    assert!(!waiting.animated);

    state.apply(TuiEvent::Disconnected).unwrap();
    let reconnecting = state.activity();
    assert_eq!(reconnecting.phase, ActivityPhase::Reconnecting);
    assert!(reconnecting.animated);
}

#[test]
fn ready_and_terminal_phases_never_animate() {
    let state = TuiState::default();
    assert_eq!(state.activity().phase, ActivityPhase::Ready);
    assert_eq!(state.activity().symbol, "●");
    assert!(!state.activity_is_animated());

    for (status, phase, symbol) in [
        (TaskStatus::Paused, ActivityPhase::Paused, "Ⅱ"),
        (TaskStatus::Blocked, ActivityPhase::Blocked, "!"),
        (TaskStatus::Cancelled, ActivityPhase::Cancelled, "■"),
        (TaskStatus::Completed, ActivityPhase::Completed, "✓"),
        (TaskStatus::Failed, ActivityPhase::Failed, "×"),
    ] {
        let mut state = bound_state();
        state
            .apply(TuiEvent::TaskUpdate(TaskUpdate::Status(status)))
            .unwrap();
        let activity = state.activity();
        assert_eq!(activity.phase, phase);
        assert_eq!(activity.symbol, symbol);
        assert!(!activity.animated);
    }
}

#[test]
fn monotonic_activity_clock_rejects_regression() {
    let mut state = bound_state();
    state
        .apply(TuiEvent::Tick {
            elapsed: Duration::from_secs(2),
        })
        .unwrap();
    assert_eq!(
        state.apply(TuiEvent::Tick {
            elapsed: Duration::from_secs(1),
        }),
        Err(TuiStateError::ClockRegression)
    );
}

fn bound_state() -> TuiState {
    let mut state = TuiState::default();
    state
        .apply(TuiEvent::TaskBound {
            external_session_id: "tui-session".to_owned(),
            task_id: TaskId::new(),
            model: ModelId::parse("gpt-5.6-codex").unwrap(),
            effort: ReasoningEffort::High,
            permission_mode: PermissionMode::FullAccess,
        })
        .unwrap();
    state
}
