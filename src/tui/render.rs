use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::acp::PermissionMode;

use super::activity::ActivityTone;
use super::state::{Overlay, ToolPresentationStatus, TranscriptItem, TuiState};

pub fn render(frame: &mut Frame<'_>, state: &TuiState) {
    let areas = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(3),
    ])
    .split(frame.area());

    let model = state.model().map_or("no model", |model| model.as_str());
    let effort = state
        .effort()
        .map_or("no effort", |effort| effort.as_codex_value());
    let session = state
        .external_session_id()
        .map_or_else(|| "new".to_owned(), short_session);
    let context = state.context_percent().map_or_else(
        || "?% context".to_owned(),
        |percent| format!("{percent}% context"),
    );
    let status = format!(
        " CARL  {model} · {effort} · {} · session {session} · {context}",
        permission_label(state.permission_mode())
    );
    frame.render_widget(
        Paragraph::new(status).style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        areas[0],
    );

    let mut lines = match state.overlay() {
        Some(Overlay::Sessions(sessions)) => {
            let mut rows = vec![Line::styled(
                "Sessions",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )];
            if sessions.is_empty() {
                rows.push(Line::raw("No durable TUI sessions yet."));
            }
            for (index, session) in sessions.iter().enumerate() {
                let status = session.latest_task_status.map_or_else(
                    || "new".to_owned(),
                    |status| format!("{status:?}").to_lowercase(),
                );
                rows.push(Line::raw(format!(
                    "{}. {} · {} · {}",
                    index + 1,
                    session.external_session_id,
                    session.provider,
                    status
                )));
            }
            rows
        }
        Some(Overlay::Help) => vec![Line::raw(
            "/model /effort /permissions /compact /new /sessions /resume /status /cancel /help /exit",
        )],
        Some(Overlay::Models) | None => Vec::new(),
    };
    for item in state.transcript() {
        match item {
            TranscriptItem::User(text) => lines.push(Line::from(vec![
                Span::styled("You  ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(text),
            ])),
            TranscriptItem::Assistant(text) => lines.push(Line::from(vec![
                Span::styled(
                    "Carl  ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(text),
            ])),
            TranscriptItem::Diff(diff) => {
                lines.push(Line::styled(diff, Style::default().fg(Color::Yellow)))
            }
            TranscriptItem::Approval {
                display_code,
                summary,
            } => lines.push(Line::styled(
                format!("approval {display_code}: {summary}"),
                Style::default().fg(Color::Yellow),
            )),
            TranscriptItem::Compaction(generation) => lines.push(Line::styled(
                format!("↻ context compacted · generation {generation}"),
                Style::default().fg(Color::Magenta),
            )),
            TranscriptItem::Notice(notice) => {
                lines.push(Line::styled(notice, Style::default().fg(Color::DarkGray)))
            }
        }
    }
    for tool in state.tools() {
        let (symbol, color) = match tool.status {
            ToolPresentationStatus::Running => ("●", Color::Yellow),
            ToolPresentationStatus::Completed => ("✓", Color::Green),
        };
        lines.push(Line::styled(
            format!("{symbol} {}", tool.summary),
            Style::default().fg(color),
        ));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), areas[1]);

    let activity = state.activity();
    let mut activity_line = format!("{} {}", activity.symbol, activity.label);
    if let Some(elapsed) = activity.elapsed_seconds {
        activity_line.push_str(&format!(" · {elapsed}s"));
    }
    if let Some(stale) = activity.stale_seconds {
        activity_line.push_str(&format!(" · last update {stale}s ago"));
    }
    let activity_line = truncate_chars(&activity_line, usize::from(areas[2].width));
    let activity_color = match activity.tone {
        ActivityTone::Active => Color::Cyan,
        ActivityTone::Idle => Color::DarkGray,
        ActivityTone::Waiting => Color::Yellow,
        ActivityTone::Success => Color::Green,
        ActivityTone::Error => Color::Red,
    };
    frame.render_widget(
        Paragraph::new(activity_line).style(Style::default().fg(activity_color)),
        areas[2],
    );

    frame.render_widget(
        Paragraph::new(format!("❯ {}", state.input()))
            .block(Block::default().borders(Borders::TOP))
            .wrap(Wrap { trim: false }),
        areas[3],
    );
}

fn truncate_chars(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

fn short_session(session: &str) -> String {
    session.char_indices().nth(8).map_or_else(
        || session.to_owned(),
        |(index, _)| format!("{}…", &session[..index]),
    )
}

const fn permission_label(permission: PermissionMode) -> &'static str {
    match permission {
        PermissionMode::Plan => "plan",
        PermissionMode::Default => "default",
        PermissionMode::AcceptEdits => "accept edits",
        PermissionMode::DontAsk => "don't ask",
        PermissionMode::FullAccess | PermissionMode::BypassPermissions => "full access",
    }
}
