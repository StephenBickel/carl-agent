use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::runtime::task::TaskId;
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
        .apply(TuiEvent::TaskUpdate(TaskUpdate::ToolStarted(
            "run_command cargo test".to_owned(),
        )))
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
    assert!(screen.contains("❯ next instruction"), "{screen}");
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
    assert!(screen.contains("disconnected"));
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
