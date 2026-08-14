use std::time::Duration;

use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::events::{SessionId, TurnId};
use carl::runtime::task::{OperationId, TaskId, TaskStatus};
use carl::service::protocol::ServiceSessionSummary;
use carl::service::protocol::TaskUpdate;
use carl::tui::render::render;
use carl::tui::state::{TuiEvent, TuiState};
use ratatui::Terminal;
use ratatui::backend::TestBackend;

#[test]
fn minimal_layout_renders_status_transcript_tools_and_prompt() {
    let mut state = TuiState::default();
    state
        .apply(TuiEvent::TaskBound {
            external_session_id: "tui-7c2abcdef".to_owned(),
            task_id: TaskId::new(),
            model: ModelId::parse("gpt-5.6-codex").unwrap(),
            effort: ReasoningEffort::High,
            permission_mode: PermissionMode::FullAccess,
        })
        .unwrap();
    state
        .apply(TuiEvent::UserSubmitted("Fix the parser".to_owned()))
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::AssistantDelta(
            "I found the bug.".to_owned(),
        )))
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::Status(TaskStatus::Active)))
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::ToolStarted(
            "run_command cargo test".to_owned(),
        )))
        .unwrap();
    state
        .apply(TuiEvent::Tick {
            elapsed: Duration::from_millis(80),
        })
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::ContextUsage {
            used: 42,
            window: 100,
        }))
        .unwrap();
    state.set_input("next instruction".to_owned());

    let backend = TestBackend::new(100, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render(frame, &state)).unwrap();
    let screen = screen(terminal.backend());
    assert!(
        screen
            .contains("CARL  gpt-5.6-codex · high · full access · session tui-7c2a… · 42% context"),
        "{screen}"
    );
    assert!(screen.contains("You  Fix the parser"), "{screen}");
    assert!(screen.contains("Carl  I found the bug."), "{screen}");
    assert!(screen.contains("● run_command cargo test"), "{screen}");
    assert!(screen.contains("⠙ Running cargo test"), "{screen}");
    assert!(screen.contains("❯ next instruction"), "{screen}");
}

#[test]
fn activity_row_shows_elapsed_stale_waiting_reconnecting_and_completed_states() {
    let mut state = bound_state();
    state
        .apply(TuiEvent::Tick {
            elapsed: Duration::from_secs(1),
        })
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::Status(TaskStatus::Active)))
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::ToolStarted(
            "run_command cargo test".to_owned(),
        )))
        .unwrap();
    state
        .apply(TuiEvent::Tick {
            elapsed: Duration::from_secs(2),
        })
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::AssistantDelta(
            "checking".to_owned(),
        )))
        .unwrap();
    state
        .apply(TuiEvent::Tick {
            elapsed: Duration::from_millis(13_320),
        })
        .unwrap();
    let screen = render_screen(&state, 100, 12);
    assert!(
        screen.contains("⠹ Running cargo test · 12s · last update 11s ago"),
        "{screen}"
    );

    let mut waiting = bound_state();
    waiting
        .apply(TuiEvent::TaskUpdate(TaskUpdate::Status(TaskStatus::Active)))
        .unwrap();
    waiting
        .apply(TuiEvent::TaskUpdate(TaskUpdate::ApprovalRequired {
            task_id: TaskId::new(),
            operation_id: OperationId::new(),
            display_code: "approve-123".to_owned(),
            summary: "write src/lib.rs".to_owned(),
            request_id: "provider-request".to_owned(),
            session_id: SessionId::new(),
            turn_id: TurnId::new(),
            external_session_id: "tui-session".to_owned(),
        }))
        .unwrap();
    assert!(render_screen(&waiting, 100, 12).contains("? Waiting for approval"));

    let mut reconnecting = TuiState::default();
    reconnecting.apply(TuiEvent::Disconnected).unwrap();
    reconnecting
        .apply(TuiEvent::Tick {
            elapsed: Duration::from_millis(80),
        })
        .unwrap();
    assert!(render_screen(&reconnecting, 100, 12).contains("⠙ Reconnecting…"));

    let mut completed = bound_state();
    completed
        .apply(TuiEvent::TaskUpdate(TaskUpdate::Status(
            TaskStatus::Completed,
        )))
        .unwrap();
    assert!(render_screen(&completed, 100, 12).contains("✓ Completed"));
}

#[test]
fn activity_row_is_unicode_safe_and_bounded_in_a_narrow_terminal() {
    let mut state = bound_state();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::Status(TaskStatus::Active)))
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::ToolStarted(
            "run_command cargo test --workspace --all-features".to_owned(),
        )))
        .unwrap();
    state.set_input("next".to_owned());
    let screen = render_screen(&state, 24, 8);
    assert!(screen.contains("⠋ Running cargo test"), "{screen}");
    assert!(screen.contains("❯ next"), "{screen}");
    assert!(screen.lines().all(|line| line.chars().count() <= 24));
}

#[test]
fn disconnected_and_narrow_layout_remain_honest_and_bounded() {
    let mut state = TuiState::default();
    state.apply(TuiEvent::Disconnected).unwrap();
    let backend = TestBackend::new(36, 8);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render(frame, &state)).unwrap();
    let screen = screen(terminal.backend());
    assert!(screen.contains("CARL"));
    assert!(screen.contains("Reconnecting…"));
    assert!(screen.contains("❯"));
}

#[test]
fn sessions_overlay_renders_numbered_resumable_sessions() {
    let mut state = TuiState::default();
    state
        .apply(TuiEvent::SessionsLoaded(vec![ServiceSessionSummary {
            external_session_id: "tui-existing-session".to_owned(),
            session_id: carl::events::SessionId::new(),
            workspace: std::path::PathBuf::from("/workspace"),
            permission_mode: PermissionMode::FullAccess,
            provider: "openai_subscription".to_owned(),
            latest_task_id: Some(TaskId::new()),
            latest_task_status: Some(carl::runtime::task::TaskStatus::Active),
            model: Some(ModelId::parse("gpt-5.6-codex").unwrap()),
            effort: Some(ReasoningEffort::High),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }]))
        .unwrap();
    let backend = TestBackend::new(100, 12);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render(frame, &state)).unwrap();
    let screen = screen(terminal.backend());
    assert!(screen.contains("Sessions"), "{screen}");
    assert!(screen.contains("1. tui-existing-session"), "{screen}");
    assert!(screen.contains("openai_subscription"), "{screen}");
}

fn screen(backend: &TestBackend) -> String {
    let area = backend.buffer().area;
    (area.y..area.y + area.height)
        .map(|y| {
            (area.x..area.x + area.width)
                .map(|x| backend.buffer()[(x, y)].symbol())
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_screen(state: &TuiState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|frame| render(frame, state)).unwrap();
    screen(terminal.backend())
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
