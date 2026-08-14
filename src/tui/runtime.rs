use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::service::protocol::{ServiceApprovalDecision, TaskUpdate};

use super::command::{SlashCommand, SubmittedInput};
use super::controller::{TuiBackend, TuiController};
use super::state::TuiEvent;

pub const INTENT_CHANNEL_CAPACITY: usize = 32;
pub const OUTPUT_CHANNEL_CAPACITY: usize = 256;
pub const ACTIVE_POLL_INTERVAL: Duration = Duration::from_millis(50);
pub const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(250);

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
            | TuiEvent::Reconnected { snapshot: None, .. }
            | TuiEvent::ApprovalResolved => {}
        }
    }
}
