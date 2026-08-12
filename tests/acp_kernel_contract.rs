#[path = "support/private_dir.rs"]
mod private_dir;

use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use carl::acp::{
    BuzzContext, CodexPort, ConfigOutcome, ConfigSelection, Kernel, KernelPublisher,
    NewSessionRequest, PermissionMode, PortFuture, Prompt, PromptStopReason, PublicationFailure,
};
use carl::delegates::codex::{
    CodexAppServer, CodexApprovalDecision, CodexApprovalRequest, CodexEvent, CodexModel,
    CodexThreadId, CodexTurnId, StartThread, StartTurn,
};
use carl::delegates::{ModelId, ReasoningEffort};
use carl::events::Event;
use carl::policy::{ActorId, Frontend};
use carl::sidecar::DataRootLock;
use carl::storage::{ChannelId, ClientName, ExternalSessionId, RuntimeStore, Store};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[tokio::test(flavor = "current_thread")]
async fn kernel_persists_provider_events_before_returning_updates() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::lifecycle()?;
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let outcome = kernel
        .prompt(session.id(), Prompt::new(vec!["inspect this repo".into()])?)
        .await?;
    assert_eq!(outcome.stop_reason, PromptStopReason::EndTurn);
    assert_eq!(
        outcome
            .updates
            .iter()
            .filter_map(|update| match update {
                carl::acp::KernelUpdate::AgentMessageChunk(text) => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>(),
        ["Working", "Fixed and verified."]
    );
    let events = Store::open(&layout.database)?.read_events(session.id())?;
    assert!(matches!(
        events.first().map(|event| &event.event),
        Some(Event::FrontendSessionBound { .. })
    ));
    assert!(
        events
            .iter()
            .any(|event| matches!(event.event, Event::UserInput { .. }))
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event.event, Event::ProviderLifecycle { .. }))
    );
    assert!(matches!(
        events.last().map(|event| &event.event),
        Some(Event::TurnCompleted)
    ));
    assert_eq!(shared.lock().unwrap().starts, 1);
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn remote_approval_is_exact_single_use_and_resumes_the_same_turn() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::approval()?;
    let shared = Arc::clone(&port.shared);
    let publisher = RecordingPublisher::default();
    let messages = Arc::clone(&publisher.messages);
    let context = BuzzContext::from_transport(
        "018f0d89-2f58-7b34-b4ad-111111111111",
        &"a".repeat(64),
        &"b".repeat(64),
    )?;
    let kernel =
        Kernel::start_with_ports(layout.runtime()?, Box::new(port), Some(Box::new(publisher)))
            .await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Buzz, Some(context))?)
        .await?;
    let waiting = kernel
        .prompt(session.id(), Prompt::new(vec!["run the tests".into()])?)
        .await?;
    assert_eq!(waiting.stop_reason, PromptStopReason::WaitingForApproval);
    assert!(shared.lock().unwrap().resolved.is_empty());
    let approval_message = messages.lock().unwrap()[0].clone();
    let code = approval_message
        .split("/approve ")
        .nth(1)
        .and_then(|suffix| suffix.split_whitespace().next())
        .ok_or("approval code missing")?;
    assert_eq!(code.len(), 10);
    assert!(
        code.bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );

    let wrong_actor = kernel
        .prompt(
            session.id(),
            Prompt::new(vec![format!("/approve {code}")])?.with_actor(ActorId::parse("intruder")?),
        )
        .await
        .expect_err("approval is bound to the admitted actor");
    assert_eq!(
        wrong_actor.code(),
        carl::acp::KernelErrorCode::ApprovalUnavailable
    );
    assert!(shared.lock().unwrap().resolved.is_empty());

    let finished = kernel
        .prompt(session.id(), Prompt::new(vec![format!("/approve {code}")])?)
        .await?;
    assert_eq!(finished.stop_reason, PromptStopReason::EndTurn);
    assert_eq!(
        shared.lock().unwrap().resolved,
        [CodexApprovalDecision::Allow]
    );
    let replay = kernel
        .prompt(session.id(), Prompt::new(vec![format!("/approve {code}")])?)
        .await
        .expect_err("consumed approval codes cannot be replayed");
    assert_eq!(
        replay.code(),
        carl::acp::KernelErrorCode::ApprovalUnavailable
    );
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn local_acp_approval_surfaces_the_exact_resume_commands() -> TestResult {
    let layout = Layout::new()?;
    let kernel =
        Kernel::start_with_ports(layout.runtime()?, Box::new(ScriptedPort::approval()?), None)
            .await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let waiting = kernel
        .prompt(session.id(), Prompt::new(vec!["run the tests".into()])?)
        .await?;
    assert_eq!(waiting.stop_reason, PromptStopReason::WaitingForApproval);
    let message = waiting
        .updates
        .iter()
        .find_map(|update| match update {
            carl::acp::KernelUpdate::AgentMessageChunk(text) => Some(text.as_str()),
            _ => None,
        })
        .ok_or("local approval command was not surfaced")?;
    assert!(message.contains("Approve with /approve "));
    assert!(message.contains(" or deny with /deny "));
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn remote_bypass_requires_a_later_exact_confirmation() -> TestResult {
    let layout = Layout::new()?;
    let kernel =
        Kernel::start_with_ports(layout.runtime()?, Box::new(ScriptedPort::idle()?), None).await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let ConfigOutcome::PendingBypass { display_code } = kernel
        .set_config(
            session.id(),
            ConfigSelection::Mode {
                mode: PermissionMode::BypassPermissions,
                remote: true,
            },
        )
        .await?
    else {
        return Err("bypass did not require confirmation".into());
    };
    assert_eq!(session.configuration().mode(), PermissionMode::Default);
    let confirmed = kernel
        .prompt(
            session.id(),
            Prompt::new(vec![format!("/confirm-bypass {display_code}")])?,
        )
        .await?;
    let carl::acp::KernelUpdate::SessionInfoChanged { configuration } = &confirmed.updates[0]
    else {
        return Err("confirmation did not update session information".into());
    };
    assert_eq!(configuration.mode(), PermissionMode::BypassPermissions);
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn active_turn_accepts_steering_rejects_concurrency_and_cancels() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::idle()?;
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let prompt_kernel = kernel.clone();
    let session_id = session.id();
    let prompt = Prompt::new(vec!["keep working".into()])?;
    let running = tokio::spawn(async move { prompt_kernel.prompt(session_id, prompt).await });
    for _ in 0..100 {
        if shared.lock().unwrap().starts == 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(shared.lock().unwrap().starts, 1);
    kernel
        .steer(session.id(), "focus on parsing".into())
        .await?;
    let busy = kernel
        .prompt(session.id(), Prompt::new(vec!["second prompt".into()])?)
        .await
        .expect_err("a session cannot run two prompts concurrently");
    assert_eq!(busy.code(), carl::acp::KernelErrorCode::SessionBusy);
    kernel.cancel(session.id()).await?;
    let outcome = running.await??;
    assert_eq!(outcome.stop_reason, PromptStopReason::Cancelled);
    {
        let state = shared.lock().unwrap();
        assert_eq!(state.steers, ["focus on parsing"]);
        assert_eq!(state.interrupts, 1);
    }
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn secret_bearing_approval_is_declined_before_persistence_or_publication() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::secret_approval()?;
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let outcome = kernel
        .prompt(session.id(), Prompt::new(vec!["do the thing".into()])?)
        .await?;
    assert_eq!(outcome.stop_reason, PromptStopReason::Failed);
    assert_eq!(
        shared.lock().unwrap().resolved,
        [CodexApprovalDecision::Deny]
    );
    let events = Store::open(&layout.database)?.read_events(session.id())?;
    assert!(!events.iter().any(|event| {
        matches!(
            event.event,
            Event::ToolProposed { .. } | Event::ApprovalRequested { .. }
        )
    }));
    assert!(matches!(
        events.last().map(|event| &event.event),
        Some(Event::TurnInterrupted { reason }) if reason == "approval_secret_rejected"
    ));
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ambiguous_buzz_delivery_is_durable_and_distinct_from_provider_failure() -> TestResult {
    let layout = Layout::new()?;
    let context = BuzzContext::from_transport(
        "018f0d89-2f58-7b34-b4ad-222222222222",
        &"c".repeat(64),
        &"d".repeat(64),
    )?;
    let kernel = Kernel::start_with_ports(
        layout.runtime()?,
        Box::new(ScriptedPort::lifecycle()?),
        Some(Box::new(FailingPublisher(PublicationFailure::Uncertain))),
    )
    .await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Buzz, Some(context))?)
        .await?;
    let error = kernel
        .prompt(session.id(), Prompt::new(vec!["finish the task".into()])?)
        .await
        .expect_err("an ambiguous delivery cannot report turn success");
    assert_eq!(error.code(), carl::acp::KernelErrorCode::DeliveryUncertain);
    let events = Store::open(&layout.database)?.read_events(session.id())?;
    assert!(events.iter().any(|event| matches!(
        event.event,
        Event::FrontendDeliveryTransitioned {
            status: carl::events::FrontendDeliveryStatus::Uncertain,
            ..
        }
    )));
    assert!(matches!(
        events.last().map(|event| &event.event),
        Some(Event::TurnInterrupted { .. })
    ));
    kernel.shutdown().await?;
    Ok(())
}

struct ScriptedPort {
    shared: Arc<Mutex<PortState>>,
}

struct PortState {
    events: VecDeque<CodexEvent>,
    continuation: VecDeque<CodexEvent>,
    resolved: Vec<CodexApprovalDecision>,
    starts: usize,
    steers: Vec<String>,
    interrupts: usize,
}

impl ScriptedPort {
    fn lifecycle() -> TestResult<Self> {
        Ok(Self::with_events([
            CodexEvent::TurnStarted {
                thread_id: thread()?,
                turn_id: turn()?,
            },
            CodexEvent::AgentMessageDelta {
                thread_id: thread()?,
                turn_id: turn()?,
                item_id: "message-1".into(),
                text: "Working".into(),
            },
            CodexEvent::AgentMessageDelta {
                thread_id: thread()?,
                turn_id: turn()?,
                item_id: "message-1".into(),
                text: "Fixed and verified.".into(),
            },
            CodexEvent::TurnCompleted {
                thread_id: thread()?,
                turn_id: turn()?,
                status: "completed".into(),
            },
        ]))
    }

    fn approval() -> TestResult<Self> {
        let approval = CodexApprovalRequest::from_provider_request(json!({
            "id":"approval-7",
            "method":"item/commandExecution/requestApproval",
            "params":{
                "threadId":"thr_123", "turnId":"turn_123", "itemId":"item_123",
                "startedAtMs":2, "command":"cargo test", "reason":"Run the test suite",
                "cwd":null
            }
        }))?;
        let port = Self::with_events([
            CodexEvent::ItemStarted {
                thread_id: thread()?,
                turn_id: turn()?,
                item_id: "item_123".into(),
            },
            CodexEvent::ApprovalRequested(approval),
        ]);
        port.shared.lock().unwrap().continuation = VecDeque::from([
            CodexEvent::AgentMessageDelta {
                thread_id: thread()?,
                turn_id: turn()?,
                item_id: "message-2".into(),
                text: "Tests passed.".into(),
            },
            CodexEvent::TurnCompleted {
                thread_id: thread()?,
                turn_id: turn()?,
                status: "completed".into(),
            },
        ]);
        Ok(port)
    }

    fn secret_approval() -> TestResult<Self> {
        let approval = CodexApprovalRequest::from_provider_request(json!({
            "id":"approval-secret",
            "method":"item/commandExecution/requestApproval",
            "params":{
                "threadId":"thr_123", "turnId":"turn_123", "itemId":"item_secret",
                "startedAtMs":2,
                "command":"curl -H 'Authorization: Bearer sk-123456789012345678901234'",
                "reason":"Run a command", "cwd":null
            }
        }))?;
        Ok(Self::with_events([CodexEvent::ApprovalRequested(approval)]))
    }

    fn idle() -> TestResult<Self> {
        Ok(Self::with_events([]))
    }

    fn with_events<const N: usize>(events: [CodexEvent; N]) -> Self {
        Self {
            shared: Arc::new(Mutex::new(PortState {
                events: events.into(),
                continuation: VecDeque::new(),
                resolved: Vec::new(),
                starts: 0,
                steers: Vec::new(),
                interrupts: 0,
            })),
        }
    }
}

impl CodexPort for ScriptedPort {
    fn models(&mut self) -> PortFuture<'_, Vec<CodexModel>> {
        Box::pin(async {
            Ok(vec![
                CodexModel::new(
                    ModelId::parse("gpt-5.6-codex").map_err(|_| invalid())?,
                    "GPT-5.6 Codex",
                    vec![ReasoningEffort::Medium, ReasoningEffort::High],
                    ReasoningEffort::Medium,
                )
                .map_err(|_| invalid())?,
            ])
        })
    }

    fn start_thread(&mut self, _request: StartThread) -> PortFuture<'_, CodexThreadId> {
        Box::pin(async { thread().map_err(|_| invalid()) })
    }

    fn start_turn(&mut self, _request: StartTurn) -> PortFuture<'_, CodexTurnId> {
        let shared = Arc::clone(&self.shared);
        Box::pin(async move {
            shared.lock().unwrap().starts += 1;
            turn().map_err(|_| invalid())
        })
    }

    fn steer(
        &mut self,
        _thread_id: &CodexThreadId,
        _turn_id: &CodexTurnId,
        input: String,
    ) -> PortFuture<'_, ()> {
        let shared = Arc::clone(&self.shared);
        Box::pin(async move {
            shared.lock().unwrap().steers.push(input);
            Ok(())
        })
    }

    fn interrupt(
        &mut self,
        _thread_id: &CodexThreadId,
        _turn_id: &CodexTurnId,
    ) -> PortFuture<'_, ()> {
        let shared = Arc::clone(&self.shared);
        Box::pin(async move {
            shared.lock().unwrap().interrupts += 1;
            Ok(())
        })
    }

    fn next_event(&mut self) -> PortFuture<'_, CodexEvent> {
        let event = self.shared.lock().unwrap().events.pop_front();
        Box::pin(async move {
            match event {
                Some(event) => Ok(event),
                None => std::future::pending().await,
            }
        })
    }

    fn resolve_approval(
        &mut self,
        _approval: &CodexApprovalRequest,
        decision: CodexApprovalDecision,
    ) -> PortFuture<'_, ()> {
        let shared = Arc::clone(&self.shared);
        Box::pin(async move {
            let mut state = shared.lock().unwrap();
            state.resolved.push(decision);
            let continuation = std::mem::take(&mut state.continuation);
            state.events.extend(continuation);
            Ok(())
        })
    }

    fn cancel(&mut self) -> PortFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Default)]
struct RecordingPublisher {
    messages: Arc<Mutex<Vec<String>>>,
}

impl KernelPublisher for RecordingPublisher {
    fn send_message<'a>(
        &'a mut self,
        _context: &'a BuzzContext,
        content: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), PublicationFailure>> + Send + 'a>,
    > {
        let messages = Arc::clone(&self.messages);
        let content = content.to_owned();
        Box::pin(async move {
            messages.lock().unwrap().push(content);
            Ok(())
        })
    }

    fn send_diff<'a>(
        &'a mut self,
        context: &'a BuzzContext,
        diff: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), PublicationFailure>> + Send + 'a>,
    > {
        self.send_message(context, diff)
    }
}

struct FailingPublisher(PublicationFailure);

impl KernelPublisher for FailingPublisher {
    fn send_message<'a>(
        &'a mut self,
        _context: &'a BuzzContext,
        _content: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), PublicationFailure>> + Send + 'a>,
    > {
        let failure = self.0;
        Box::pin(async move { Err(failure) })
    }

    fn send_diff<'a>(
        &'a mut self,
        context: &'a BuzzContext,
        diff: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), PublicationFailure>> + Send + 'a>,
    > {
        self.send_message(context, diff)
    }
}

fn new_session(
    layout: &Layout,
    frontend: Frontend,
    buzz_context: Option<BuzzContext>,
) -> TestResult<NewSessionRequest> {
    let channel_id = buzz_context
        .as_ref()
        .map(|context| ChannelId::try_from(context.channel_id().to_string()))
        .transpose()?;
    Ok(NewSessionRequest {
        external_session_id: ExternalSessionId::try_from(format!("session-{}", Uuid::new_v4()))?,
        frontend,
        client_name: ClientName::try_from("kernel-contract")?,
        protocol_version: 2,
        cwd: layout.workspace.clone(),
        actor_id: ActorId::parse("owner")?,
        channel_id,
        buzz_context,
        model: Some(ModelId::parse("gpt-5.6-codex")?),
        effort: Some(ReasoningEffort::High),
        mode: PermissionMode::Default,
    })
}

fn thread() -> Result<CodexThreadId, carl::delegates::codex::DelegateError> {
    CodexThreadId::parse("thr_123")
}

fn turn() -> Result<CodexTurnId, carl::delegates::codex::DelegateError> {
    CodexTurnId::parse("turn_123")
}

fn invalid() -> carl::acp::KernelError {
    carl::acp::KernelError::from_code(carl::acp::KernelErrorCode::ProviderFailed)
}

struct Layout {
    root: PathBuf,
    workspace: PathBuf,
    database: PathBuf,
}

impl Layout {
    fn new() -> TestResult<Self> {
        let root = std::env::temp_dir().join(format!("carl-acp-kernel-{}", Uuid::new_v4()));
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace)?;
        private_dir::make_owner_only_directory(&root)?;
        private_dir::make_owner_only_directory(&workspace)?;
        let workspace = fs::canonicalize(workspace)?;
        Ok(Self {
            database: root.join("carl.sqlite3"),
            root,
            workspace,
        })
    }

    fn runtime(&self) -> TestResult<RuntimeStore> {
        Ok(RuntimeStore::open(
            DataRootLock::acquire(&self.root)?,
            Utc::now(),
        )?)
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn _assert_concrete_start_signature(
    store: RuntimeStore,
    codex: CodexAppServer,
) -> impl std::future::Future<Output = Result<carl::acp::KernelHandle, carl::acp::KernelError>> {
    Kernel::start(store, codex, None)
}
