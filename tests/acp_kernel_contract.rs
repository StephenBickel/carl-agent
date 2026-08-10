use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use carl::acp::{
    BuzzContext, CodexPort, ConfigOutcome, ConfigSelection, Kernel, KernelPublisher,
    NewSessionRequest, PermissionMode, PermissionProfile, PortFuture, Prompt, PromptStopReason,
    PublicationFailure,
};
use carl::delegates::codex::{
    CodexAppServer, CodexApprovalDecision, CodexApprovalRequest, CodexEvent, CodexItem, CodexModel,
    CodexThreadId, CodexTurnId, StartThread, StartTurn,
};
use carl::delegates::{ModelId, ReasoningEffort};
use carl::events::Event;
use carl::policy::{ActorId, Frontend};
use carl::sidecar::DataRootLock;
use carl::storage::{ChannelId, ClientName, ExternalSessionId, RuntimeStore, Store};
use chrono::Utc;
use rusqlite::Connection;
use serde_json::json;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn permission_modes_have_canonical_product_authority_profiles() {
    assert_eq!(PermissionMode::Plan.profile(), PermissionProfile::ReadOnly);
    assert_eq!(
        PermissionMode::Default.profile(),
        PermissionProfile::Approval
    );
    assert_eq!(
        PermissionMode::BypassPermissions.profile(),
        PermissionProfile::FullAccess,
    );
}

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
async fn unknown_codex_items_are_not_reported_as_successful_tools() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::with_events([
        CodexEvent::ItemStarted {
            thread_id: thread()?,
            turn_id: turn()?,
            item: CodexItem::Other {
                item_id: "future-item".into(),
                item_type: "futureTool".into(),
            },
        },
        CodexEvent::ItemCompleted {
            thread_id: thread()?,
            turn_id: turn()?,
            item: CodexItem::Other {
                item_id: "future-item".into(),
                item_type: "futureTool".into(),
            },
        },
        CodexEvent::TurnCompleted {
            thread_id: thread()?,
            turn_id: turn()?,
            status: "completed".into(),
        },
    ]);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let outcome = kernel
        .prompt(session.id(), Prompt::new(vec!["inspect this repo".into()])?)
        .await?;
    assert!(
        outcome
            .updates
            .iter()
            .all(|update| !matches!(update, carl::acp::KernelUpdate::ToolCompleted { .. }))
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn orphaned_known_tool_completion_fails_without_a_completion_journal() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::with_events([
        CodexEvent::ItemCompleted {
            thread_id: thread()?,
            turn_id: turn()?,
            item: command_item("orphan-command", "completed"),
        },
        CodexEvent::TurnCompleted {
            thread_id: thread()?,
            turn_id: turn()?,
            status: "completed".into(),
        },
    ]);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let error = kernel
        .prompt(session.id(), Prompt::new(vec!["inspect this repo".into()])?)
        .await
        .expect_err("a known completion must bind to a started item");
    assert_eq!(error.code(), carl::acp::KernelErrorCode::ProviderFailed);
    let events = Store::open(&layout.database)?.read_events(session.id())?;
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.event, Event::ToolCompleted { .. }))
    );
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn known_tool_completion_kind_mismatch_fails_without_a_completion_journal() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::with_events([
        CodexEvent::ItemStarted {
            thread_id: thread()?,
            turn_id: turn()?,
            item: command_item("changed-kind", "inProgress"),
        },
        CodexEvent::ItemCompleted {
            thread_id: thread()?,
            turn_id: turn()?,
            item: file_change_item("changed-kind", "completed"),
        },
        CodexEvent::TurnCompleted {
            thread_id: thread()?,
            turn_id: turn()?,
            status: "completed".into(),
        },
    ]);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let error = kernel
        .prompt(session.id(), Prompt::new(vec!["inspect this repo".into()])?)
        .await
        .expect_err("a completion cannot change the started item kind");
    assert_eq!(error.code(), carl::acp::KernelErrorCode::ProviderFailed);
    let events = Store::open(&layout.database)?.read_events(session.id())?;
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.event, Event::ToolCompleted { .. }))
    );
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn duplicate_known_tool_completion_fails_without_a_second_completion_journal() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::with_events([
        CodexEvent::ItemStarted {
            thread_id: thread()?,
            turn_id: turn()?,
            item: command_item("duplicate-command", "inProgress"),
        },
        CodexEvent::ItemCompleted {
            thread_id: thread()?,
            turn_id: turn()?,
            item: command_item("duplicate-command", "completed"),
        },
        CodexEvent::ItemCompleted {
            thread_id: thread()?,
            turn_id: turn()?,
            item: command_item("duplicate-command", "completed"),
        },
        CodexEvent::TurnCompleted {
            thread_id: thread()?,
            turn_id: turn()?,
            status: "completed".into(),
        },
    ]);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let error = kernel
        .prompt(session.id(), Prompt::new(vec!["inspect this repo".into()])?)
        .await
        .expect_err("a completed item cannot complete a second time");
    assert_eq!(error.code(), carl::acp::KernelErrorCode::ProviderFailed);
    let events = Store::open(&layout.database)?.read_events(session.id())?;
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.event, Event::ToolCompleted { .. }))
            .count(),
        1
    );
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn failed_and_declined_tool_statuses_are_durable() -> TestResult {
    for terminal_status in ["failed", "declined"] {
        let layout = Layout::new()?;
        let item_id = format!("command-{terminal_status}");
        let port = ScriptedPort::with_events([
            CodexEvent::ItemStarted {
                thread_id: thread()?,
                turn_id: turn()?,
                item: command_item(&item_id, "inProgress"),
            },
            CodexEvent::ItemCompleted {
                thread_id: thread()?,
                turn_id: turn()?,
                item: command_item(&item_id, terminal_status),
            },
            CodexEvent::TurnCompleted {
                thread_id: thread()?,
                turn_id: turn()?,
                status: "completed".into(),
            },
        ]);
        let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
        let session = kernel
            .new_session(new_session(&layout, Frontend::Acp, None)?)
            .await?;
        let outcome = kernel
            .prompt(session.id(), Prompt::new(vec!["inspect this repo".into()])?)
            .await?;
        assert!(outcome.updates.iter().any(|update| matches!(
            update,
            carl::acp::KernelUpdate::ToolCompleted {
                status: carl::acp::ToolStatus::Failed,
                ..
            }
        )));
        let events = Store::open(&layout.database)?.read_events(session.id())?;
        let output = events.iter().find_map(|event| match &event.event {
            Event::ToolCompleted { output, .. } => Some(output),
            _ => None,
        });
        assert_eq!(output, Some(&json!({"status":terminal_status})));
        kernel.shutdown().await?;
    }
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
async fn full_access_authorization_is_durable_before_the_automatic_effect() -> TestResult {
    let layout = Layout::new()?;
    let (port, expected_request_digest) = ScriptedPort::automatic_approval()?;
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let mut request = new_session(&layout, Frontend::Acp, None)?;
    request.mode = PermissionMode::BypassPermissions;
    let session = kernel.new_session(request).await?;

    let outcome = kernel
        .prompt(session.id(), Prompt::new(vec!["run the tests".into()])?)
        .await?;

    assert_eq!(outcome.stop_reason, PromptStopReason::EndTurn);
    assert_eq!(shared.lock().unwrap().allowed_effects, 1);
    assert!(!outcome.updates.iter().any(|update| matches!(
        update,
        carl::acp::KernelUpdate::AgentMessageChunk(message)
            if message.contains("Approval required")
    )));
    assert_eq!(
        outcome
            .updates
            .iter()
            .filter(|update| matches!(update, carl::acp::KernelUpdate::ToolCompleted { .. }))
            .count(),
        1
    );

    let events = Store::open(&layout.database)?.read_events(session.id())?;
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event.event, Event::ToolDispatchAuthorized { .. }))
            .count(),
        1
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event.event, Event::ApprovalRequested { .. }))
    );
    let proposed = events
        .iter()
        .find(|event| matches!(event.event, Event::ToolProposed { .. }))
        .ok_or("tool proposal was not persisted")?;
    let authorized = events
        .iter()
        .find(|event| matches!(event.event, Event::ToolDispatchAuthorized { .. }))
        .ok_or("tool authorization was not persisted")?;
    let completed = events
        .iter()
        .find(|event| matches!(event.event, Event::ToolCompleted { .. }))
        .ok_or("tool completion was not persisted")?;
    assert!(proposed.sequence < authorized.sequence);
    assert!(authorized.sequence < completed.sequence);
    let Event::ToolDispatchAuthorized {
        tool_call_id,
        request_digest,
        automatic,
    } = &authorized.event
    else {
        unreachable!();
    };
    assert_eq!(request_digest, &expected_request_digest);
    assert!(*automatic);
    assert!(matches!(
        proposed.event,
        Event::ToolProposed {
            tool_call_id: proposed_id,
            ..
        } if proposed_id == *tool_call_id
    ));
    assert!(matches!(
        completed.event,
        Event::ToolCompleted {
            tool_call_id: completed_id,
            ..
        } if completed_id == *tool_call_id
    ));
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn failed_authorization_append_prevents_the_full_access_effect() -> TestResult {
    let layout = Layout::new()?;
    let (port, _expected_request_digest) = ScriptedPort::automatic_approval()?;
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let mut request = new_session(&layout, Frontend::Acp, None)?;
    request.mode = PermissionMode::BypassPermissions;
    let session = kernel.new_session(request).await?;
    let connection = Connection::open(&layout.database)?;
    connection.execute_batch(
        "CREATE TRIGGER reject_tool_authorization
         BEFORE INSERT ON events
         WHEN json_extract(NEW.event_json, '$.type') = 'tool_dispatch_authorized'
         BEGIN
             SELECT RAISE(ABORT, 'injected authorization append failure');
         END;",
    )?;

    let outcome = kernel
        .prompt(session.id(), Prompt::new(vec!["run the tests".into()])?)
        .await;

    assert_eq!(shared.lock().unwrap().allowed_effects, 0);
    assert_eq!(
        outcome.unwrap_err().code(),
        carl::acp::KernelErrorCode::StorageFailed
    );
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn full_access_denies_unknown_completed_and_cross_turn_approval_items() -> TestResult {
    for case in [
        InvalidApprovalCase::Unknown,
        InvalidApprovalCase::Completed,
        InvalidApprovalCase::CrossTurn,
    ] {
        let layout = Layout::new()?;
        let port = ScriptedPort::invalid_automatic_approval(case)?;
        let shared = Arc::clone(&port.shared);
        let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
        let mut request = new_session(&layout, Frontend::Acp, None)?;
        request.mode = PermissionMode::BypassPermissions;
        let session = kernel.new_session(request).await?;

        let error = kernel
            .prompt(session.id(), Prompt::new(vec!["run the tests".into()])?)
            .await
            .expect_err("an approval must bind to an active item in the current turn");

        assert_eq!(error.code(), carl::acp::KernelErrorCode::ProviderFailed);
        {
            let state = shared.lock().unwrap();
            assert_eq!(state.allowed_effects, 0);
            assert_eq!(state.resolved, [CodexApprovalDecision::Deny]);
        }
        let events = Store::open(&layout.database)?.read_events(session.id())?;
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.event, Event::ToolDispatchAuthorized { .. }))
        );
        kernel.shutdown().await?;
    }
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
    allowed_effects: usize,
    starts: usize,
    steers: Vec<String>,
    interrupts: usize,
}

#[derive(Clone, Copy)]
enum InvalidApprovalCase {
    Unknown,
    Completed,
    CrossTurn,
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
                item: command_item("item_123", "inProgress"),
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

    fn automatic_approval() -> TestResult<(Self, String)> {
        let approval = CodexApprovalRequest::from_provider_request(json!({
            "id":"approval-auto",
            "method":"item/commandExecution/requestApproval",
            "params":{
                "threadId":"thr_123", "turnId":"turn_123", "itemId":"item_auto",
                "startedAtMs":2, "command":"cargo test", "reason":"Run the test suite",
                "cwd":null
            }
        }))?;
        let request_digest = approval.request_digest().to_string();
        let port = Self::with_events([
            CodexEvent::ItemStarted {
                thread_id: thread()?,
                turn_id: turn()?,
                item: command_item("item_auto", "inProgress"),
            },
            CodexEvent::ApprovalRequested(approval),
        ]);
        port.shared.lock().unwrap().continuation = VecDeque::from([
            CodexEvent::ItemCompleted {
                thread_id: thread()?,
                turn_id: turn()?,
                item: command_item("item_auto", "completed"),
            },
            CodexEvent::TurnCompleted {
                thread_id: thread()?,
                turn_id: turn()?,
                status: "completed".into(),
            },
        ]);
        Ok((port, request_digest))
    }

    fn invalid_automatic_approval(case: InvalidApprovalCase) -> TestResult<Self> {
        let approval_turn = match case {
            InvalidApprovalCase::CrossTurn => "turn_other",
            InvalidApprovalCase::Unknown | InvalidApprovalCase::Completed => "turn_123",
        };
        let approval = CodexApprovalRequest::from_provider_request(json!({
            "id":"approval-invalid",
            "method":"item/commandExecution/requestApproval",
            "params":{
                "threadId":"thr_123", "turnId":approval_turn, "itemId":"item_invalid",
                "startedAtMs":2, "command":"cargo test", "reason":"Run the test suite",
                "cwd":null
            }
        }))?;
        let events = match case {
            InvalidApprovalCase::Unknown => {
                vec![CodexEvent::ApprovalRequested(approval)]
            }
            InvalidApprovalCase::Completed => vec![
                CodexEvent::ItemStarted {
                    thread_id: thread()?,
                    turn_id: turn()?,
                    item: command_item("item_invalid", "inProgress"),
                },
                CodexEvent::ItemCompleted {
                    thread_id: thread()?,
                    turn_id: turn()?,
                    item: command_item("item_invalid", "completed"),
                },
                CodexEvent::ApprovalRequested(approval),
            ],
            InvalidApprovalCase::CrossTurn => vec![
                CodexEvent::ItemStarted {
                    thread_id: thread()?,
                    turn_id: turn()?,
                    item: command_item("item_invalid", "inProgress"),
                },
                CodexEvent::ApprovalRequested(approval),
            ],
        };
        let port = Self {
            shared: Arc::new(Mutex::new(PortState {
                events: events.into(),
                continuation: VecDeque::new(),
                resolved: Vec::new(),
                allowed_effects: 0,
                starts: 0,
                steers: Vec::new(),
                interrupts: 0,
            })),
        };
        if matches!(case, InvalidApprovalCase::CrossTurn) {
            port.shared.lock().unwrap().continuation =
                VecDeque::from([CodexEvent::TurnCompleted {
                    thread_id: thread()?,
                    turn_id: turn()?,
                    status: "completed".into(),
                }]);
        }
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
                allowed_effects: 0,
                starts: 0,
                steers: Vec::new(),
                interrupts: 0,
            })),
        }
    }
}

fn command_item(item_id: &str, status: &str) -> CodexItem {
    CodexItem::Command {
        item_id: item_id.into(),
        command: "cargo test".into(),
        cwd: "/workspace".into(),
        status: status.into(),
        exit_code: (status == "completed").then_some(0),
        aggregated_output: None,
        process_id: None,
    }
}

fn file_change_item(item_id: &str, status: &str) -> CodexItem {
    CodexItem::FileChange {
        item_id: item_id.into(),
        status: status.into(),
        changes: json!([]),
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
            if decision == CodexApprovalDecision::Allow {
                state.allowed_effects += 1;
            }
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
        make_owner_only(&root)?;
        make_owner_only(&workspace)?;
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

#[cfg(unix)]
fn make_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(windows)]
fn make_owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn _assert_concrete_start_signature(
    store: RuntimeStore,
    codex: CodexAppServer,
) -> impl std::future::Future<Output = Result<carl::acp::KernelHandle, carl::acp::KernelError>> {
    Kernel::start(store, codex, None)
}
