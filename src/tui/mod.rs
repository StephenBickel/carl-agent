use std::env;
use std::io;
use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{self, Event, KeyEventKind};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::cli::{ExitClassification, TuiArgs};
use crate::credentials::{CredentialVault, load_provider_preference, store_provider_preference};
use crate::providers::catalog::ProviderKind;
use crate::providers::http::SecretCredential;
use crate::service::protocol::ServiceApprovalDecision;

use self::bootstrap::connect_or_launch;
use self::command::{SlashCommand, SubmittedInput, parse_submission};
use self::controller::{ServiceTuiBackend, TuiController};
use self::render::render;
use self::state::{TuiEvent, TuiState};
use self::terminal::{CrosstermControl, EditorAction, InputEditor, TerminalOwner};

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
    let mut controller = TuiController::new(backend, workspace);
    let mut state = TuiState::default();
    apply_events(
        &mut state,
        controller
            .initialize()
            .await
            .map_err(|_| "the persistent task service returned invalid session state")?,
    )?;

    let mut owner = TerminalOwner::enter(CrosstermControl::default())
        .map_err(|_| "the terminal could not enter interactive mode")?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).map_err(|_| "the terminal could not initialize")?;
    let mut editor = InputEditor::default();
    let loop_result = async {
        loop {
            state.set_input(editor.text().to_owned());
            terminal
                .draw(|frame| render(frame, &state))
                .map_err(|_| "the terminal could not render")?;
            if state.exit_requested() {
                break;
            }

            if event::poll(Duration::ZERO).map_err(|_| "terminal input failed")?
                && let Event::Key(key) = event::read().map_err(|_| "terminal input failed")?
                && key.kind == KeyEventKind::Press
            {
                let task_active = state.status().is_some_and(|status| !status.is_terminal());
                match editor.handle(key, task_active) {
                    EditorAction::None => {}
                    EditorAction::Exit => state
                        .apply(TuiEvent::ExitRequested)
                        .map_err(|_| "the terminal state became invalid")?,
                    EditorAction::CancelTask => {
                        let events = controller
                            .submit(SubmittedInput::Command(SlashCommand::Cancel))
                            .await
                            .map_err(|_| "the active task could not be cancelled")?;
                        apply_events(&mut state, events)?;
                    }
                    EditorAction::Submit(text) => {
                        let events = if state.approval_pending() {
                            match text.trim().to_ascii_lowercase().as_str() {
                                "y" | "yes" => controller
                                    .resolve_approval(ServiceApprovalDecision::Approve)
                                    .await
                                    .map_err(|_| "the approval could not be applied")?,
                                "n" | "no" => controller
                                    .resolve_approval(ServiceApprovalDecision::Deny)
                                    .await
                                    .map_err(|_| "the denial could not be applied")?,
                                _ => vec![TuiEvent::Notice(
                                    "approval requires y/yes or n/no".to_owned(),
                                )],
                            }
                        } else {
                            match parse_submission(&text) {
                                Ok(input) => controller
                                    .submit(input)
                                    .await
                                    .map_err(|_| "the TUI command was rejected")?,
                                Err(_) => vec![TuiEvent::Notice(
                                    "invalid input; use /help for commands".to_owned(),
                                )],
                            }
                        };
                        apply_events(&mut state, events)?;
                    }
                }
            }

            match controller.poll_updates().await {
                Ok(events) => apply_events(&mut state, events)?,
                Err(_) => {
                    state
                        .apply(TuiEvent::Disconnected)
                        .map_err(|_| "the terminal state became invalid")?;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok::<(), &'static str>(())
    }
    .await;
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

fn apply_events(state: &mut TuiState, events: Vec<TuiEvent>) -> Result<(), &'static str> {
    for event in events {
        state
            .apply(event)
            .map_err(|_| "the terminal state became invalid")?;
    }
    Ok(())
}
