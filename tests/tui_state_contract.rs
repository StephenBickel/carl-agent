use carl::acp::PermissionMode;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::runtime::task::{TaskId, TaskStatus};
use carl::service::protocol::TaskUpdate;
use carl::tui::state::{ToolPresentationStatus, TranscriptItem, TuiEvent, TuiInbox, TuiState};

#[test]
fn reducer_coalesces_assistant_text_and_tracks_authoritative_activity() {
    let mut state = TuiState::default();
    let task_id = TaskId::new();
    state
        .apply(TuiEvent::TaskBound {
            external_session_id: "tui-session".to_owned(),
            task_id,
            model: ModelId::parse("gpt-5.6-codex").unwrap(),
            effort: ReasoningEffort::High,
            permission_mode: PermissionMode::FullAccess,
        })
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::AssistantDelta(
            "hel".into(),
        )))
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::AssistantDelta(
            "lo".into(),
        )))
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::ToolStarted(
            "read_file src/lib.rs".into(),
        )))
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::ToolCompleted(
            "read_file src/lib.rs".into(),
        )))
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::ContextUsage {
            used: 42,
            window: 100,
        }))
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::Compaction {
            generation: 3,
        }))
        .unwrap();
    state
        .apply(TuiEvent::TaskUpdate(TaskUpdate::Status(TaskStatus::Active)))
        .unwrap();

    assert_eq!(state.last_assistant_text(), Some("hello"));
    assert_eq!(state.context_percent(), Some(42));
    assert_eq!(state.compaction_generation(), 3);
    assert_eq!(state.status(), Some(TaskStatus::Active));
    assert_eq!(state.tools().len(), 1);
    assert_eq!(state.tools()[0].status, ToolPresentationStatus::Completed);
    assert!(matches!(
        state.transcript().last(),
        Some(TranscriptItem::Compaction(3))
    ));
}

#[test]
fn disconnect_freezes_mutations_and_reconnect_rejects_cursor_regression() {
    let mut state = TuiState::default();
    state.apply(TuiEvent::Disconnected).unwrap();
    assert!(!state.mutations_enabled());
    state
        .apply(TuiEvent::Reconnected {
            live_generation: "generation-one".to_owned(),
            cursor: Some(9),
            snapshot: None,
        })
        .unwrap();
    assert!(state.mutations_enabled());
    assert!(
        state
            .apply(TuiEvent::DurableUpdate {
                live_generation: "generation-one".to_owned(),
                cursor: 8,
                update: TaskUpdate::Status(TaskStatus::Active),
            })
            .is_err()
    );
    state
        .apply(TuiEvent::DurableUpdate {
            live_generation: "generation-two".to_owned(),
            cursor: 1,
            update: TaskUpdate::Status(TaskStatus::Checkpointing),
        })
        .unwrap();
    assert_eq!(state.live_generation(), Some("generation-two"));
    assert_eq!(state.last_cursor(), Some(1));
}

#[test]
fn bounded_inbox_coalesces_replaceable_progress_without_losing_outcomes() {
    let mut inbox = TuiInbox::new(3).unwrap();
    inbox.push(TuiEvent::Tick).unwrap();
    inbox
        .push(TuiEvent::TaskUpdate(TaskUpdate::ContextUsage {
            used: 1,
            window: 10,
        }))
        .unwrap();
    inbox
        .push(TuiEvent::TaskUpdate(TaskUpdate::Status(TaskStatus::Active)))
        .unwrap();
    inbox
        .push(TuiEvent::TaskUpdate(TaskUpdate::ToolCompleted(
            "command".into(),
        )))
        .unwrap();
    assert_eq!(inbox.len(), 3);
    assert!(
        inbox
            .iter()
            .any(|event| matches!(event, TuiEvent::TaskUpdate(TaskUpdate::ToolCompleted(_))))
    );

    let mut authoritative = TuiInbox::new(1).unwrap();
    authoritative
        .push(TuiEvent::TaskUpdate(TaskUpdate::ToolCompleted(
            "one".into(),
        )))
        .unwrap();
    let rejected = authoritative.push(TuiEvent::TaskUpdate(TaskUpdate::Compaction {
        generation: 1,
    }));
    assert!(
        rejected.is_err(),
        "authoritative event must backpressure instead of being discarded"
    );
    assert!(matches!(
        authoritative.pop(),
        Some(TuiEvent::TaskUpdate(TaskUpdate::ToolCompleted(_)))
    ));
}
