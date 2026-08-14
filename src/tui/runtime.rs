use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::service::protocol::{ServiceApprovalDecision, TaskUpdate};

use crossterm::event::KeyEvent;

use super::command::{SlashCommand, SubmittedInput, parse_submission};
use super::controller::{TuiBackend, TuiController};
use super::state::{TuiEvent, TuiState, TuiStateError};
use super::terminal::{EditorAction, InputEditor};

pub const INTENT_CHANNEL_CAPACITY: usize = 32;
pub const OUTPUT_CHANNEL_CAPACITY: usize = 256;
pub const ACTIVE_POLL_INTERVAL: Duration = Duration::from_millis(50);
pub const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(250);
pub const RENDER_INTERVAL: Duration = Duration::from_millis(33);

#[derive(Clone, Debug, PartialEq)]
pub enum RuntimeIntent {
    Submit(SubmittedInput),
    ResolveApproval(ServiceApprovalDecision),
    Cancel,
    Shutdown,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RuntimeOutput {
    Events(Vec<TuiEvent>),
    Disconnected,
}

#[derive(Clone, Debug, PartialEq)]
pub enum LocalAction {
    None,
    Intent {
        intent: RuntimeIntent,
        original_submission: Option<String>,
    },
    Exit,
}

pub struct FrameScheduler {
    dirty: bool,
    next_draw_at: Duration,
}

impl FrameScheduler {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            dirty: true,
            next_draw_at: Duration::ZERO,
        }
    }

    pub const fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    pub fn take_draw(&mut self, now: Duration) -> bool {
        if !self.dirty || now < self.next_draw_at {
            return false;
        }
        self.dirty = false;
        self.next_draw_at = now.saturating_add(RENDER_INTERVAL);
        true
    }
}

impl Default for FrameScheduler {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LocalTui {
    state: TuiState,
    editor: InputEditor,
    frames: FrameScheduler,
}

impl LocalTui {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: TuiState::default(),
            editor: InputEditor::default(),
            frames: FrameScheduler::new(),
        }
    }

    #[must_use]
    pub const fn state(&self) -> &TuiState {
        &self.state
    }

    pub fn apply_output(&mut self, output: RuntimeOutput) -> Result<(), TuiStateError> {
        match output {
            RuntimeOutput::Events(events) => {
                if !self.state.connected() {
                    self.state.apply(TuiEvent::ConnectionRestored)?;
                }
                for event in events {
                    self.state.apply(event)?;
                }
            }
            RuntimeOutput::Disconnected => self.state.apply(TuiEvent::Disconnected)?,
        }
        self.frames.mark_dirty();
        Ok(())
    }

    pub fn tick(&mut self, elapsed: Duration) -> Result<(), TuiStateError> {
        let animated = self.state.activity_is_animated();
        self.state.apply(TuiEvent::Tick { elapsed })?;
        if animated {
            self.frames.mark_dirty();
        }
        Ok(())
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Result<LocalAction, TuiStateError> {
        let task_active = self
            .state
            .status()
            .is_some_and(|status| !status.is_terminal());
        let action = match self.editor.handle(key, task_active) {
            EditorAction::None => LocalAction::None,
            EditorAction::Exit => {
                self.state.apply(TuiEvent::ExitRequested)?;
                LocalAction::Exit
            }
            EditorAction::CancelTask => LocalAction::Intent {
                intent: RuntimeIntent::Cancel,
                original_submission: None,
            },
            EditorAction::Submit(text) => {
                let intent = if self.state.approval_pending() {
                    match text.trim().to_ascii_lowercase().as_str() {
                        "y" | "yes" => Some(RuntimeIntent::ResolveApproval(
                            ServiceApprovalDecision::Approve,
                        )),
                        "n" | "no" => Some(RuntimeIntent::ResolveApproval(
                            ServiceApprovalDecision::Deny,
                        )),
                        _ => {
                            self.state.apply(TuiEvent::Notice(
                                "approval requires y/yes or n/no".to_owned(),
                            ))?;
                            None
                        }
                    }
                } else {
                    match parse_submission(&text) {
                        Ok(input) => Some(RuntimeIntent::Submit(input)),
                        Err(_) => {
                            self.state.apply(TuiEvent::Notice(
                                "invalid input; use /help for commands".to_owned(),
                            ))?;
                            None
                        }
                    }
                };
                intent.map_or(LocalAction::None, |intent| LocalAction::Intent {
                    intent,
                    original_submission: Some(text),
                })
            }
        };
        self.state.set_input(self.editor.text().to_owned());
        self.frames.mark_dirty();
        Ok(action)
    }

    pub fn reject_intent(
        &mut self,
        original_submission: Option<String>,
    ) -> Result<(), TuiStateError> {
        if let Some(text) = original_submission {
            self.editor.restore_submission(text);
        }
        self.state.set_input(self.editor.text().to_owned());
        self.state.apply(TuiEvent::Notice(
            "controller busy; input not submitted".to_owned(),
        ))?;
        self.frames.mark_dirty();
        Ok(())
    }

    pub const fn mark_dirty(&mut self) {
        self.frames.mark_dirty();
    }

    pub fn take_draw(&mut self, now: Duration) -> bool {
        self.frames.take_draw(now)
    }
}

impl Default for LocalTui {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn run_controller_worker<B>(
    mut controller: TuiController<B>,
    mut intent_rx: mpsc::Receiver<RuntimeIntent>,
    output_tx: mpsc::Sender<RuntimeOutput>,
) where
    B: TuiBackend + Send,
{
    let mut fast_poll = false;
    match controller.initialize().await {
        Ok(events) => {
            update_poll_mode(&events, &mut fast_poll);
            if !send_output(&output_tx, RuntimeOutput::Events(events)).await {
                return;
            }
        }
        Err(_) => {
            if !send_output(&output_tx, RuntimeOutput::Disconnected).await {
                return;
            }
        }
    }

    let mut next_poll = Instant::now() + poll_interval(fast_poll);
    loop {
        let poll_delay = tokio::time::sleep_until(next_poll);
        tokio::pin!(poll_delay);
        tokio::select! {
            biased;
            intent = intent_rx.recv() => {
                let Some(intent) = intent else {
                    break;
                };
                if intent == RuntimeIntent::Shutdown {
                    break;
                }
                let result = match intent {
                    RuntimeIntent::Submit(input) => controller.submit(input).await,
                    RuntimeIntent::ResolveApproval(decision) => {
                        controller.resolve_approval(decision).await
                    }
                    RuntimeIntent::Cancel => controller
                        .submit(SubmittedInput::Command(SlashCommand::Cancel))
                        .await,
                    RuntimeIntent::Shutdown => unreachable!("shutdown is handled before dispatch"),
                };
                match result {
                    Ok(events) => {
                        update_poll_mode(&events, &mut fast_poll);
                        if !send_output(&output_tx, RuntimeOutput::Events(events)).await {
                            break;
                        }
                    }
                    Err(_) => {
                        if !send_output(&output_tx, RuntimeOutput::Disconnected).await {
                            break;
                        }
                    }
                }
                next_poll = Instant::now() + poll_interval(fast_poll);
            }
            () = &mut poll_delay => {
                match controller.poll_updates().await {
                    Ok(events) => {
                        update_poll_mode(&events, &mut fast_poll);
                        if !events.is_empty()
                            && !send_output(&output_tx, RuntimeOutput::Events(events)).await
                        {
                            break;
                        }
                    }
                    Err(_) => {
                        if !send_output(&output_tx, RuntimeOutput::Disconnected).await {
                            break;
                        }
                    }
                }
                next_poll = Instant::now() + poll_interval(fast_poll);
            }
        }
    }
}

async fn send_output(output_tx: &mpsc::Sender<RuntimeOutput>, output: RuntimeOutput) -> bool {
    output_tx.send(output).await.is_ok()
}

const fn poll_interval(fast_poll: bool) -> Duration {
    if fast_poll {
        ACTIVE_POLL_INTERVAL
    } else {
        IDLE_POLL_INTERVAL
    }
}

fn update_poll_mode(events: &[TuiEvent], fast_poll: &mut bool) {
    for event in events {
        match event {
            TuiEvent::TaskBound { .. } => *fast_poll = true,
            TuiEvent::SessionCleared | TuiEvent::ExitRequested => *fast_poll = false,
            TuiEvent::TaskUpdate(TaskUpdate::Status(status))
            | TuiEvent::DurableUpdate {
                update: TaskUpdate::Status(status),
                ..
            } => *fast_poll = !status.is_terminal(),
            TuiEvent::AuthoritativeSnapshot(snapshot) => {
                *fast_poll = !snapshot.status.is_terminal();
            }
            TuiEvent::Reconnected {
                snapshot: Some(snapshot),
                ..
            } => *fast_poll = !snapshot.status.is_terminal(),
            TuiEvent::Tick { .. }
            | TuiEvent::UserSubmitted(_)
            | TuiEvent::TaskUpdate(_)
            | TuiEvent::DurableUpdate { .. }
            | TuiEvent::SessionsLoaded(_)
            | TuiEvent::CompactionRequested
            | TuiEvent::Notice(_)
            | TuiEvent::Disconnected
            | TuiEvent::ConnectionRestored
            | TuiEvent::Reconnected { snapshot: None, .. }
            | TuiEvent::ApprovalResolved => {}
        }
    }
}
