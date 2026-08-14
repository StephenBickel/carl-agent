use std::time::Duration;

pub const ACTIVITY_INTERVAL: Duration = Duration::from_millis(80);
const PULSE_FRAMES: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
const ELAPSED_THRESHOLD_SECONDS: u64 = 3;
const STALE_THRESHOLD_SECONDS: u64 = 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActivityPhase {
    Ready,
    Starting,
    Queued,
    Thinking,
    Tool(String),
    Compacting,
    WaitingApproval,
    Reconnecting,
    Paused,
    Blocked,
    Cancelling,
    Finishing,
    Completed,
    Failed,
    Cancelled,
}

impl ActivityPhase {
    #[must_use]
    pub const fn is_animated(&self) -> bool {
        matches!(
            self,
            Self::Starting
                | Self::Queued
                | Self::Thinking
                | Self::Tool(_)
                | Self::Compacting
                | Self::Reconnecting
                | Self::Cancelling
                | Self::Finishing
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivityTone {
    Active,
    Idle,
    Waiting,
    Success,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityView {
    pub symbol: &'static str,
    pub label: String,
    pub elapsed_seconds: Option<u64>,
    pub stale_seconds: Option<u64>,
    pub tone: ActivityTone,
    pub animated: bool,
    pub phase: ActivityPhase,
}

#[must_use]
pub(crate) fn activity_view(
    phase: ActivityPhase,
    now: Duration,
    phase_started_at: Duration,
    last_authoritative_at: Duration,
) -> ActivityView {
    let phase_elapsed = now.saturating_sub(phase_started_at);
    let authoritative_elapsed = now.saturating_sub(last_authoritative_at);
    let animated = phase.is_animated();
    let symbol = if animated {
        let frame = usize::try_from(
            phase_elapsed.as_millis() / ACTIVITY_INTERVAL.as_millis()
                % u128::try_from(PULSE_FRAMES.len()).unwrap_or(1),
        )
        .unwrap_or(0);
        PULSE_FRAMES[frame]
    } else {
        static_symbol(&phase)
    };
    let elapsed_seconds = animated
        .then_some(phase_elapsed.as_secs())
        .filter(|elapsed| *elapsed >= ELAPSED_THRESHOLD_SECONDS);
    let stale_seconds = animated
        .then_some(authoritative_elapsed.as_secs())
        .filter(|elapsed| *elapsed >= STALE_THRESHOLD_SECONDS);
    let tone = tone(&phase);
    let label = label(&phase);
    ActivityView {
        symbol,
        label,
        elapsed_seconds,
        stale_seconds,
        tone,
        animated,
        phase,
    }
}

#[must_use]
pub(crate) fn tool_label(summary: &str) -> String {
    for (prefix, verb) in [
        ("read_file ", "Reading "),
        ("list_files ", "Listing "),
        ("search_files ", "Searching "),
        ("apply_patch ", "Editing "),
        ("run_command ", "Running "),
    ] {
        if let Some(detail) = summary.strip_prefix(prefix) {
            return format!("{verb}{detail}");
        }
    }
    summary.to_owned()
}

fn static_symbol(phase: &ActivityPhase) -> &'static str {
    match phase {
        ActivityPhase::Ready => "●",
        ActivityPhase::WaitingApproval => "?",
        ActivityPhase::Paused => "Ⅱ",
        ActivityPhase::Blocked => "!",
        ActivityPhase::Completed => "✓",
        ActivityPhase::Failed => "×",
        ActivityPhase::Cancelled => "■",
        ActivityPhase::Starting
        | ActivityPhase::Queued
        | ActivityPhase::Thinking
        | ActivityPhase::Tool(_)
        | ActivityPhase::Compacting
        | ActivityPhase::Reconnecting
        | ActivityPhase::Cancelling
        | ActivityPhase::Finishing => "●",
    }
}

fn label(phase: &ActivityPhase) -> String {
    match phase {
        ActivityPhase::Ready => "Ready".to_owned(),
        ActivityPhase::Starting => "Starting…".to_owned(),
        ActivityPhase::Queued => "Queued…".to_owned(),
        ActivityPhase::Thinking => "Thinking…".to_owned(),
        ActivityPhase::Tool(summary) => summary.clone(),
        ActivityPhase::Compacting => "Compacting context".to_owned(),
        ActivityPhase::WaitingApproval => "Waiting for approval".to_owned(),
        ActivityPhase::Reconnecting => "Reconnecting…".to_owned(),
        ActivityPhase::Paused => "Paused".to_owned(),
        ActivityPhase::Blocked => "Blocked".to_owned(),
        ActivityPhase::Cancelling => "Cancelling…".to_owned(),
        ActivityPhase::Finishing => "Finishing…".to_owned(),
        ActivityPhase::Completed => "Completed".to_owned(),
        ActivityPhase::Failed => "Failed".to_owned(),
        ActivityPhase::Cancelled => "Cancelled".to_owned(),
    }
}

const fn tone(phase: &ActivityPhase) -> ActivityTone {
    match phase {
        ActivityPhase::Completed => ActivityTone::Success,
        ActivityPhase::Failed | ActivityPhase::Reconnecting => ActivityTone::Error,
        ActivityPhase::WaitingApproval
        | ActivityPhase::Paused
        | ActivityPhase::Blocked
        | ActivityPhase::Cancelling => ActivityTone::Waiting,
        ActivityPhase::Ready | ActivityPhase::Cancelled => ActivityTone::Idle,
        ActivityPhase::Starting
        | ActivityPhase::Queued
        | ActivityPhase::Thinking
        | ActivityPhase::Tool(_)
        | ActivityPhase::Compacting
        | ActivityPhase::Finishing => ActivityTone::Active,
    }
}
