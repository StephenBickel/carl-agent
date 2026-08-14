use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use carl::delegates::{ModelId, ReasoningEffort};
use carl::runtime::task::{TaskId, TaskStatus};
use carl::service::protocol::{
    LiveUpdateEnvelope, LiveUpdatePage, SERVICE_PROTOCOL_VERSION, ServiceCapabilities,
    ServiceCommand, ServiceInfo, ServiceModel, ServiceResult, TaskUpdate,
};
use carl::tui::command::SubmittedInput;
use carl::tui::controller::{TuiBackend, TuiController, TuiError};
use carl::tui::runtime::{RuntimeIntent, RuntimeOutput, run_controller_worker};
use carl::tui::state::TuiEvent;
use tokio::sync::{Mutex, Notify, mpsc};

#[tokio::test(start_paused = true)]
async fn delayed_poll_is_single_flight_and_queued_command_precedes_the_next_poll() {
    let task_id = TaskId::new();
    let shared = Arc::new(FakeShared::new(true));
    let backend = FakeBackend::new(task_id, Arc::clone(&shared));
    let controller = TuiController::new(backend, PathBuf::from("/workspace"));
    let (intent_tx, intent_rx) = mpsc::channel(32);
    let (output_tx, mut output_rx) = mpsc::channel(256);
    let worker = tokio::spawn(run_controller_worker(controller, intent_rx, output_tx));

    assert!(matches!(
        output_rx.recv().await,
        Some(RuntimeOutput::Events(events))
            if matches!(events.as_slice(), [TuiEvent::SessionsLoaded(sessions)] if sessions.is_empty())
    ));
    intent_tx
        .send(RuntimeIntent::Submit(SubmittedInput::Prompt(
            "fix it".to_owned(),
        )))
        .await
        .unwrap();
    assert!(matches!(
        output_rx.recv().await,
        Some(RuntimeOutput::Events(events))
            if events.iter().any(|event| matches!(event, TuiEvent::TaskBound { task_id: bound, .. } if *bound == task_id))
    ));

    tokio::time::advance(Duration::from_millis(49)).await;
    tokio::task::yield_now().await;
    assert_eq!(shared.live_started.load(Ordering::SeqCst), 0);
    tokio::time::advance(Duration::from_millis(1)).await;
    wait_for_count(&shared.live_started, 1).await;
    assert_eq!(shared.maximum_inflight.load(Ordering::SeqCst), 1);

    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(shared.live_started.load(Ordering::SeqCst), 1);
    intent_tx
        .send(RuntimeIntent::Submit(SubmittedInput::Prompt(
            "also explain it".to_owned(),
        )))
        .await
        .unwrap();
    shared.poll_release.notify_one();

    let polled = output_rx.recv().await.unwrap();
    let RuntimeOutput::Events(polled) = polled else {
        panic!("delayed poll must return an ordered event batch");
    };
    assert!(matches!(
        polled.as_slice(),
        [
            TuiEvent::DurableUpdate { cursor: 1, .. },
            TuiEvent::DurableUpdate { cursor: 2, .. }
        ]
    ));
    assert!(matches!(
        output_rx.recv().await,
        Some(RuntimeOutput::Events(events))
            if matches!(events.as_slice(), [TuiEvent::UserSubmitted(text)] if text == "also explain it")
    ));
    let commands = shared.commands.lock().await;
    let live_index = commands
        .iter()
        .position(|command| matches!(command, ServiceCommand::LiveUpdates { .. }))
        .unwrap();
    let steer_index = commands
        .iter()
        .position(|command| matches!(command, ServiceCommand::Steer { .. }))
        .unwrap();
    assert_eq!(steer_index, live_index + 1);
    drop(commands);

    intent_tx.send(RuntimeIntent::Shutdown).await.unwrap();
    worker.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn bounded_output_backpressure_preserves_the_complete_event_batch() {
    let task_id = TaskId::new();
    let shared = Arc::new(FakeShared::new(false));
    let backend = FakeBackend::new(task_id, shared);
    let controller = TuiController::new(backend, PathBuf::from("/workspace"));
    let (intent_tx, intent_rx) = mpsc::channel(1);
    let (output_tx, mut output_rx) = mpsc::channel(1);
    let worker = tokio::spawn(run_controller_worker(controller, intent_rx, output_tx));

    intent_tx
        .send(RuntimeIntent::Submit(SubmittedInput::Prompt(
            "preserve me".to_owned(),
        )))
        .await
        .unwrap();
    assert!(matches!(
        output_rx.recv().await,
        Some(RuntimeOutput::Events(events))
            if matches!(events.as_slice(), [TuiEvent::SessionsLoaded(_)])
    ));
    let submitted = output_rx.recv().await.unwrap();
    let RuntimeOutput::Events(events) = submitted else {
        panic!("accepted prompt must remain an event batch");
    };
    assert!(matches!(
        events.as_slice(),
        [TuiEvent::UserSubmitted(text), TuiEvent::TaskBound { task_id: bound, .. }]
            if text == "preserve me" && *bound == task_id
    ));

    intent_tx.send(RuntimeIntent::Shutdown).await.unwrap();
    worker.await.unwrap();
}

struct FakeBackend {
    info: ServiceInfo,
    task_id: TaskId,
    shared: Arc<FakeShared>,
}

impl FakeBackend {
    fn new(task_id: TaskId, shared: Arc<FakeShared>) -> Self {
        Self {
            info: info(),
            task_id,
            shared,
        }
    }
}

impl TuiBackend for FakeBackend {
    fn info(&self) -> &ServiceInfo {
        &self.info
    }

    fn request<'a>(
        &'a mut self,
        command: ServiceCommand,
    ) -> Pin<Box<dyn Future<Output = Result<ServiceResult, TuiError>> + Send + 'a>> {
        let shared = Arc::clone(&self.shared);
        let task_id = self.task_id;
        Box::pin(async move {
            shared.commands.lock().await.push(command.clone());
            match command {
                ServiceCommand::Sessions { .. } => Ok(ServiceResult::SessionList(Vec::new())),
                ServiceCommand::StartTask(_) => Ok(ServiceResult::Accepted { task_id }),
                ServiceCommand::LiveUpdates { .. } => {
                    let inflight = shared.inflight.fetch_add(1, Ordering::SeqCst) + 1;
                    shared
                        .maximum_inflight
                        .fetch_max(inflight, Ordering::SeqCst);
                    shared.live_started.fetch_add(1, Ordering::SeqCst);
                    if shared.delay_poll.load(Ordering::SeqCst) {
                        shared.poll_release.notified().await;
                    }
                    shared.inflight.fetch_sub(1, Ordering::SeqCst);
                    Ok(ServiceResult::LiveUpdates(LiveUpdatePage {
                        live_generation: "11111111-1111-4111-8111-111111111111".to_owned(),
                        updates: vec![
                            LiveUpdateEnvelope {
                                cursor: 1,
                                update: TaskUpdate::Status(TaskStatus::Active),
                            },
                            LiveUpdateEnvelope {
                                cursor: 2,
                                update: TaskUpdate::AssistantDelta("working".to_owned()),
                            },
                        ],
                        cursor: Some(2),
                        snapshot: None,
                    }))
                }
                ServiceCommand::Steer { .. }
                | ServiceCommand::Cancel { .. }
                | ServiceCommand::Configure { .. }
                | ServiceCommand::Compact { .. }
                | ServiceCommand::ResolveApproval { .. } => Ok(ServiceResult::Applied),
                _ => Err(TuiError::InvalidResponse),
            }
        })
    }
}

struct FakeShared {
    commands: Mutex<Vec<ServiceCommand>>,
    delay_poll: AtomicBool,
    poll_release: Notify,
    live_started: AtomicUsize,
    inflight: AtomicUsize,
    maximum_inflight: AtomicUsize,
}

impl FakeShared {
    fn new(delay_poll: bool) -> Self {
        Self {
            commands: Mutex::new(Vec::new()),
            delay_poll: AtomicBool::new(delay_poll),
            poll_release: Notify::new(),
            live_started: AtomicUsize::new(0),
            inflight: AtomicUsize::new(0),
            maximum_inflight: AtomicUsize::new(0),
        }
    }
}

async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
    for _ in 0..32 {
        if counter.load(Ordering::SeqCst) == expected {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(counter.load(Ordering::SeqCst), expected);
}

fn info() -> ServiceInfo {
    ServiceInfo {
        protocol_version: SERVICE_PROTOCOL_VERSION,
        live_generation: "11111111-1111-4111-8111-111111111111".to_owned(),
        provider: "openai_subscription".to_owned(),
        models: vec![ServiceModel {
            id: ModelId::parse("gpt-5.6-codex").unwrap(),
            display_name: "GPT 5.6 Codex".to_owned(),
            supported_efforts: vec![ReasoningEffort::Medium, ReasoningEffort::High],
            default_effort: ReasoningEffort::Medium,
        }],
        default_model: Some(ModelId::parse("gpt-5.6-codex").unwrap()),
        default_effort: Some(ReasoningEffort::Medium),
        capabilities: ServiceCapabilities {
            durable_events: true,
            reconnect: true,
            trusted_buzz_admission: true,
            configure_active_task: true,
            explicit_task_budgets: true,
            sanitized_task_metrics: true,
            recoverable_maintenance: true,
            explicit_task_compaction: true,
            durable_frontend_sessions: true,
        },
    }
}
