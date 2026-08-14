use std::env;
use std::io;
use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{Event, EventStream, KeyEventKind};
use futures_util::StreamExt as _;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior};

use self::bootstrap::connect_or_launch;
use self::controller::{ServiceTuiBackend, TuiController};
use self::render::render;
use self::runtime::{
    INTENT_CHANNEL_CAPACITY, LocalAction, LocalTui, OUTPUT_CHANNEL_CAPACITY, RuntimeIntent,
    run_controller_worker,
};
use self::terminal::{CrosstermControl, TerminalOwner};
use crate::cli::{ExitClassification, TuiArgs};
use crate::credentials::{CredentialVault, load_provider_preference, store_provider_preference};
use crate::providers::catalog::ProviderKind;
use crate::providers::http::SecretCredential;

pub mod activity;
pub mod bootstrap;
pub mod command;
pub mod controller;
pub mod render;
pub mod runtime;
pub mod state;
pub mod terminal;

/// Run Carl's interactive terminal frontend.
pub async fn run(_args: TuiArgs) -> ExitClassification {
    match run_inner().await {
        Ok(()) => ExitClassification::Success,
        Err(message) => {
            eprintln!("carl tui: {message}");
            ExitClassification::Failure
        }
    }
}

async fn run_inner() -> Result<(), &'static str> {
    let data_root = env::var_os("CARL_DATA_DIR")
        .map(PathBuf::from)
        .ok_or("CARL_DATA_DIR must name a private absolute directory")?;
    let workspace = env::current_dir()
        .and_then(std::fs::canonicalize)
        .map_err(|_| "the current workspace is unavailable")?;
    ensure_first_run_provider(&data_root).await?;
    let client = connect_or_launch(&data_root, &workspace)
        .await
        .map_err(|_| "the persistent task service is unavailable")?;
    let backend = ServiceTuiBackend::new(client);
    let controller = TuiController::new(backend, workspace);
    let (intent_tx, intent_rx) = mpsc::channel(INTENT_CHANNEL_CAPACITY);
    let (output_tx, mut output_rx) = mpsc::channel(OUTPUT_CHANNEL_CAPACITY);
    let mut worker = tokio::spawn(run_controller_worker(controller, intent_rx, output_tx));

    let mut owner = TerminalOwner::enter(CrosstermControl::default())
        .map_err(|_| "the terminal could not enter interactive mode")?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|_| "the terminal could not initialize")?;
    let mut terminal_events = EventStream::new();
    let mut local = LocalTui::new();
    let runtime_start = Instant::now();
    let mut animation = tokio::time::interval_at(
        runtime_start + activity::ACTIVITY_INTERVAL,
        activity::ACTIVITY_INTERVAL,
    );
    animation.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut render_gate = tokio::time::interval_at(runtime_start, runtime::RENDER_INTERVAL);
    render_gate.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let loop_result = async {
        loop {
            if local.state().exit_requested() {
                break;
            }
            tokio::select! {
                biased;
                terminal_event = terminal_events.next() => {
                    match terminal_event {
                        Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                            match local
                                .handle_key(key)
                                .map_err(|_| "the terminal state became invalid")?
                            {
                                LocalAction::None => {}
                                LocalAction::Exit => continue,
                                LocalAction::Intent {
                                    intent,
                                    original_submission,
                                } => {
                                    if intent_tx.try_send(intent).is_err() {
                                        local
                                            .reject_intent(original_submission)
                                            .map_err(|_| "the terminal state became invalid")?;
                                    }
                                }
                            }
                        }
                        Some(Ok(Event::Resize(_, _))) => local.mark_dirty(),
                        Some(Ok(_)) => {}
                        Some(Err(_)) | None => return Err("terminal input failed"),
                    }
                }
                _ = animation.tick() => {
                    local
                        .tick(runtime_start.elapsed())
                        .map_err(|_| "the terminal state became invalid")?;
                }
                output = output_rx.recv() => {
                    let Some(output) = output else {
                        return Err("the persistent task service became unavailable");
                    };
                    local
                        .apply_output(output)
                        .map_err(|_| "the terminal state became invalid")?;
                }
                _ = render_gate.tick() => {
                    let elapsed = runtime_start.elapsed();
                    if local.take_draw(elapsed) {
                        terminal
                            .draw(|frame| render(frame, local.state()))
                            .map_err(|_| "the terminal could not render")?;
                    }
                }
            }
        }
        Ok::<(), &'static str>(())
    }
    .await;
    let _ = intent_tx.try_send(RuntimeIntent::Shutdown);
    if tokio::time::timeout(Duration::from_millis(500), &mut worker)
        .await
        .is_err()
    {
        worker.abort();
        let _ = worker.await;
    }
    drop(terminal);
    owner
        .restore()
        .map_err(|_| "the terminal could not restore its mode")?;
    loop_result
}

async fn ensure_first_run_provider(data_root: &std::path::Path) -> Result<(), &'static str> {
    match load_provider_preference(data_root) {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {}
        Err(_) => return Err("the provider preference is invalid"),
    }
    if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
        return Ok(());
    }
    let selection = tokio::task::spawn_blocking(|| {
        eprintln!("Choose Carl provider:");
        eprintln!("  1) OpenAI subscription (recommended)");
        eprintln!("  2) OpenAI API key");
        eprintln!("  3) OpenRouter API key");
        eprint!("Selection [1]: ");
        use std::io::Write as _;
        io::stderr().flush().map_err(|_| ())?;
        let mut value = String::new();
        io::stdin().read_line(&mut value).map_err(|_| ())?;
        parse_first_run_provider(&value).ok_or(())
    })
    .await
    .map_err(|_| "provider selection failed")?
    .map_err(|_| "provider selection is invalid")?;
    if matches!(
        selection,
        ProviderKind::OpenAiApi | ProviderKind::OpenRouter
    ) {
        let label = if selection == ProviderKind::OpenAiApi {
            "OpenAI"
        } else {
            "OpenRouter"
        };
        let secret = tokio::task::spawn_blocking(move || {
            rpassword::prompt_password(format!("{label} API key: "))
        })
        .await
        .map_err(|_| "secure credential input failed")?
        .map_err(|_| "secure credential input failed")?;
        let credential = SecretCredential::new(secret.into_bytes())
            .map_err(|_| "the provider credential is invalid")?;
        CredentialVault::store(selection, credential)
            .map_err(|_| "the OS credential vault is unavailable")?;
    }
    store_provider_preference(data_root, selection)
        .map_err(|_| "the provider preference could not be saved")
}

#[doc(hidden)]
#[must_use]
pub fn parse_first_run_provider(input: &str) -> Option<ProviderKind> {
    match input.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "subscription" => Some(ProviderKind::OpenAiSubscription),
        "2" | "openai" => Some(ProviderKind::OpenAiApi),
        "3" | "openrouter" => Some(ProviderKind::OpenRouter),
        _ => None,
    }
}
