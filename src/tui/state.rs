use std::collections::VecDeque;
use std::time::Duration;

use thiserror::Error;

use crate::acp::PermissionMode;
use crate::delegates::{ModelId, ReasoningEffort};
use crate::runtime::task::{TaskId, TaskSnapshot, TaskStatus};
use crate::service::protocol::{ServiceSessionSummary, TaskUpdate};

use super::activity::{ActivityPhase, ActivityView, activity_view, tool_label};

#[derive(Clone, Debug, PartialEq)]
pub enum TranscriptItem {
    User(String),
    Assistant(String),
    Diff(String),
    Approval {
        display_code: String,
        summary: String,
    },
    Compaction(u32),
    Notice(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolPresentationStatus {
    Running,
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolActivity {
    pub summary: String,
    pub status: ToolPresentationStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Overlay {
    Help,
    Models,
    Sessions(Vec<ServiceSessionSummary>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum TuiEvent {
    Tick {
        elapsed: Duration,
    },
    UserSubmitted(String),
    TaskBound {
        external_session_id: String,
        task_id: TaskId,
        model: ModelId,
        effort: ReasoningEffort,
        permission_mode: PermissionMode,
    },
    TaskUpdate(TaskUpdate),
    DurableUpdate {
        live_generation: String,
        cursor: u64,
        update: TaskUpdate,
    },
    AuthoritativeSnapshot(TaskSnapshot),
    SessionsLoaded(Vec<ServiceSessionSummary>),
    SessionCleared,
    CompactionRequested,
    Notice(String),
    Disconnected,
    ConnectionRestored,
    Reconnected {
        live_generation: String,
        cursor: Option<u64>,
        snapshot: Option<TaskSnapshot>,
    },
    ExitRequested,
    ApprovalResolved,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TuiStateError {
    #[error("TUI durable cursor regressed")]
    CursorRegression,
    #[error("TUI context measurement is invalid")]
    InvalidContextUsage,
    #[error("TUI activity clock regressed")]
    ClockRegression,
}

#[derive(Clone, Debug)]
pub struct TuiState {
    input: String,
    transcript: Vec<TranscriptItem>,
    tools: Vec<ToolActivity>,
    overlay: Option<Overlay>,
    external_session_id: Option<String>,
    task_id: Option<TaskId>,
    model: Option<ModelId>,
    effort: Option<ReasoningEffort>,
    permission_mode: PermissionMode,
    status: Option<TaskStatus>,
    context: Option<(u64, u64)>,
    compaction_generation: u32,
    connected: bool,
    live_generation: Option<String>,
    last_cursor: Option<u64>,
    exit_requested: bool,
    approval_pending: bool,
    now: Duration,
    phase_started_at: Duration,
    last_authoritative_at: Duration,
    compaction_requested: bool,
}

impl Default for TuiState {
    fn default() -> Self {
        Self {
            input: String::new(),
            transcript: Vec::new(),
            tools: Vec::new(),
            overlay: None,
            external_session_id: None,
            task_id: None,
            model: None,
            effort: None,
            permission_mode: PermissionMode::FullAccess,
            status: None,
            context: None,
            compaction_generation: 0,
            connected: true,
            live_generation: None,
            last_cursor: None,
            exit_requested: false,
            approval_pending: false,
            now: Duration::ZERO,
            phase_started_at: Duration::ZERO,
            last_authoritative_at: Duration::ZERO,
            compaction_requested: false,
        }
    }
}

impl TuiState {
    pub fn apply(&mut self, event: TuiEvent) -> Result<(), TuiStateError> {
        let previous_phase = self.activity_phase();
        let mut authoritative = false;
        match event {
            TuiEvent::Tick { elapsed } => {
                if elapsed < self.now {
                    return Err(TuiStateError::ClockRegression);
                }
                self.now = elapsed;
            }
            TuiEvent::UserSubmitted(text) => self.transcript.push(TranscriptItem::User(text)),
            TuiEvent::TaskBound {
                external_session_id,
                task_id,
                model,
                effort,
                permission_mode,
            } => {
                self.external_session_id = Some(external_session_id);
                self.task_id = Some(task_id);
                self.model = Some(model);
                self.effort = Some(effort);
                self.permission_mode = permission_mode;
                self.status = None;
                self.overlay = None;
            }
            TuiEvent::TaskUpdate(update) => {
                self.apply_update(update)?;
                authoritative = true;
            }
            TuiEvent::DurableUpdate {
                live_generation,
                cursor,
                update,
            } => {
                if self.live_generation.as_deref() != Some(live_generation.as_str()) {
                    self.live_generation = Some(live_generation);
                    self.last_cursor = None;
                }
                if let Some(previous) = self.last_cursor {
                    if cursor < previous {
                        return Err(TuiStateError::CursorRegression);
                    }
                    if cursor == previous {
                        return Ok(());
                    }
                }
                self.apply_update(update)?;
                self.last_cursor = Some(cursor);
                authoritative = true;
            }
            TuiEvent::AuthoritativeSnapshot(snapshot) => {
                self.apply_snapshot(&snapshot);
                authoritative = true;
            }
            TuiEvent::SessionsLoaded(sessions) => {
                self.overlay = Some(Overlay::Sessions(sessions));
            }
            TuiEvent::SessionCleared => {
                self.external_session_id = None;
                self.task_id = None;
                self.status = None;
                self.context = None;
                self.live_generation = None;
                self.last_cursor = None;
                self.overlay = None;
                self.tools.clear();
                self.transcript.clear();
                self.approval_pending = false;
                self.compaction_requested = false;
            }
            TuiEvent::CompactionRequested => self.compaction_requested = true,
            TuiEvent::Notice(notice) => self.transcript.push(TranscriptItem::Notice(notice)),
            TuiEvent::Disconnected => self.connected = false,
            TuiEvent::ConnectionRestored => self.connected = true,
            TuiEvent::Reconnected {
                live_generation,
                cursor,
                snapshot,
            } => {
                self.connected = true;
                self.live_generation = Some(live_generation);
                self.last_cursor = cursor;
                if let Some(snapshot) = snapshot {
                    self.apply_snapshot(&snapshot);
                }
                authoritative = true;
            }
            TuiEvent::ExitRequested => self.exit_requested = true,
            TuiEvent::ApprovalResolved => self.approval_pending = false,
        }
        if authoritative {
            self.last_authoritative_at = self.now;
        }
        if self.activity_phase() != previous_phase {
            self.phase_started_at = self.now;
        }
        Ok(())
    }

    #[must_use]
    pub fn input(&self) -> &str {
        &self.input
    }

    pub fn set_input(&mut self, input: String) {
        self.input = input;
    }

    #[must_use]
    pub fn external_session_id(&self) -> Option<&str> {
        self.external_session_id.as_deref()
    }

    #[must_use]
    pub fn model(&self) -> Option<&ModelId> {
        self.model.as_ref()
    }

    #[must_use]
    pub const fn effort(&self) -> Option<ReasoningEffort> {
        self.effort
    }

    #[must_use]
    pub const fn permission_mode(&self) -> PermissionMode {
        self.permission_mode
    }

    #[must_use]
    pub const fn connected(&self) -> bool {
        self.connected
    }

    #[must_use]
    pub fn overlay(&self) -> Option<&Overlay> {
        self.overlay.as_ref()
    }

    #[must_use]
    pub const fn exit_requested(&self) -> bool {
        self.exit_requested
    }

    #[must_use]
    pub const fn approval_pending(&self) -> bool {
        self.approval_pending
    }

    fn apply_snapshot(&mut self, snapshot: &TaskSnapshot) {
        self.task_id = Some(snapshot.task_id);
        self.status = Some(snapshot.status);
    }

    fn apply_update(&mut self, update: TaskUpdate) -> Result<(), TuiStateError> {
        match update {
            TaskUpdate::Status(status) => self.status = Some(status),
            TaskUpdate::EpochObjective(objective) => {
                self.transcript.push(TranscriptItem::Notice(objective));
            }
            TaskUpdate::ToolStarted(summary) => self.tools.push(ToolActivity {
                summary,
                status: ToolPresentationStatus::Running,
            }),
            TaskUpdate::ToolCompleted(summary) => {
                if let Some(tool) = self.tools.iter_mut().rev().find(|tool| {
                    tool.summary == summary && tool.status == ToolPresentationStatus::Running
                }) {
                    tool.status = ToolPresentationStatus::Completed;
                } else {
                    self.tools.push(ToolActivity {
                        summary,
                        status: ToolPresentationStatus::Completed,
                    });
                }
            }
            TaskUpdate::AssistantDelta(delta) => {
                if let Some(TranscriptItem::Assistant(text)) = self.transcript.last_mut() {
                    text.push_str(&delta);
                } else {
                    self.transcript.push(TranscriptItem::Assistant(delta));
                }
            }
            TaskUpdate::Diff(diff) => self.transcript.push(TranscriptItem::Diff(diff)),
            TaskUpdate::ApprovalRequired {
                display_code,
                summary,
                ..
            } => {
                self.approval_pending = true;
                self.transcript.push(TranscriptItem::Approval {
                    display_code,
                    summary,
                });
            }
            TaskUpdate::Checkpoint(checkpoint) => {
                self.compaction_requested = false;
                self.transcript
                    .push(TranscriptItem::Notice(format!("checkpoint {checkpoint}")));
            }
            TaskUpdate::ContextUsage { used, window } => {
                if window == 0 || used > window {
                    return Err(TuiStateError::InvalidContextUsage);
                }
                self.context = Some((used, window));
            }
            TaskUpdate::Compaction { generation } => {
                self.compaction_requested = false;
                self.compaction_generation = generation;
                self.transcript.push(TranscriptItem::Compaction(generation));
            }
            TaskUpdate::CompletionClauses(clauses) => self.transcript.push(TranscriptItem::Notice(
                format!("{} completion clauses", clauses.len()),
            )),
        }
        Ok(())
    }

    #[must_use]
    pub fn last_assistant_text(&self) -> Option<&str> {
        self.transcript.iter().rev().find_map(|item| match item {
            TranscriptItem::Assistant(text) => Some(text.as_str()),
            _ => None,
        })
    }

    #[must_use]
    pub fn context_percent(&self) -> Option<u64> {
        self.context.map(|(used, window)| {
            u64::try_from((u128::from(used) * 100) / u128::from(window)).unwrap_or(100)
        })
    }

    #[must_use]
    pub const fn compaction_generation(&self) -> u32 {
        self.compaction_generation
    }

    #[must_use]
    pub const fn status(&self) -> Option<TaskStatus> {
        self.status
    }

    #[must_use]
    pub fn tools(&self) -> &[ToolActivity] {
        &self.tools
    }

    #[must_use]
    pub fn transcript(&self) -> &[TranscriptItem] {
        &self.transcript
    }

    #[must_use]
    pub const fn mutations_enabled(&self) -> bool {
        self.connected && !self.exit_requested
    }

    #[must_use]
    pub fn live_generation(&self) -> Option<&str> {
        self.live_generation.as_deref()
    }

    #[must_use]
    pub const fn last_cursor(&self) -> Option<u64> {
        self.last_cursor
    }

    #[must_use]
    pub fn activity(&self) -> ActivityView {
        activity_view(
            self.activity_phase(),
            self.now,
            self.phase_started_at,
            self.last_authoritative_at,
        )
    }

    #[must_use]
    pub fn activity_is_animated(&self) -> bool {
        self.activity_phase().is_animated()
    }

    fn activity_phase(&self) -> ActivityPhase {
        if !self.connected {
            return ActivityPhase::Reconnecting;
        }
        match self.status {
            Some(TaskStatus::Cancelled) => return ActivityPhase::Cancelled,
            Some(TaskStatus::Completed) => return ActivityPhase::Completed,
            Some(TaskStatus::Failed) => return ActivityPhase::Failed,
            Some(TaskStatus::Paused) => return ActivityPhase::Paused,
            Some(TaskStatus::Blocked) => return ActivityPhase::Blocked,
            Some(TaskStatus::Cancelling) => return ActivityPhase::Cancelling,
            Some(TaskStatus::Completing) => return ActivityPhase::Finishing,
            Some(TaskStatus::Queued) => return ActivityPhase::Queued,
            Some(TaskStatus::Checkpointing) => return ActivityPhase::Compacting,
            Some(TaskStatus::Active) | None => {}
        }
        if self.approval_pending {
            return ActivityPhase::WaitingApproval;
        }
        if self.compaction_requested {
            return ActivityPhase::Compacting;
        }
        if self.status == Some(TaskStatus::Active)
            && let Some(tool) = self
                .tools
                .iter()
                .rev()
                .find(|tool| tool.status == ToolPresentationStatus::Running)
        {
            return ActivityPhase::Tool(tool_label(&tool.summary));
        }
        if self.status == Some(TaskStatus::Active) {
            ActivityPhase::Thinking
        } else if self.task_id.is_some() {
            ActivityPhase::Starting
        } else {
            ActivityPhase::Ready
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("TUI inbox is full of authoritative events")]
pub struct TuiInboxFull;

pub struct TuiInbox {
    capacity: usize,
    events: VecDeque<TuiEvent>,
}

impl TuiInbox {
    pub fn new(capacity: usize) -> Result<Self, TuiInboxFull> {
        if capacity == 0 {
            return Err(TuiInboxFull);
        }
        Ok(Self {
            capacity,
            events: VecDeque::with_capacity(capacity),
        })
    }

    pub fn push(&mut self, event: TuiEvent) -> Result<(), TuiInboxFull> {
        if self.events.len() == self.capacity {
            let removable = self.events.iter().position(is_replaceable);
            if let Some(index) = removable {
                self.events.remove(index);
            } else {
                return Err(TuiInboxFull);
            }
        }
        self.events.push_back(event);
        Ok(())
    }

    #[must_use]
    pub fn pop(&mut self) -> Option<TuiEvent> {
        self.events.pop_front()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &TuiEvent> {
        self.events.iter()
    }
}

fn is_replaceable(event: &TuiEvent) -> bool {
    matches!(
        event,
        TuiEvent::Tick { .. }
            | TuiEvent::TaskUpdate(TaskUpdate::Status(_) | TaskUpdate::ContextUsage { .. })
            | TuiEvent::DurableUpdate {
                update: TaskUpdate::Status(_) | TaskUpdate::ContextUsage { .. },
                ..
            }
    )
}
