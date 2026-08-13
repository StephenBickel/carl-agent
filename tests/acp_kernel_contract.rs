#[path = "support/private_dir.rs"]
mod private_dir;

use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use carl::acp::{
    BuzzContext, ConfigOutcome, ConfigSelection, Kernel, KernelPublisher, NewSessionRequest,
    PermissionMode, PermissionProfile, Prompt, PromptOutcome, PromptStopReason, PublicationFailure,
};
use carl::delegates::codex::CodexAppServer;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::events::Event;
use carl::policy::{ActorId, Frontend, Sha256Digest};
use carl::runtime::agent_port::{
    AgentCapabilities, AgentContextId, AgentEffectKind, AgentEffectRequest, AgentEpochId,
    AgentEvent, AgentFuture, AgentItem, AgentModel, AgentPort, AgentPortError, AgentPortErrorCode,
    AgentProcess, AgentRequestId, AgentUsage, EffectDecision, ResumeAgentContext,
    StartAgentContext, StartAgentEpoch,
};
use carl::runtime::task::{
    CheckpointId, ClauseStatus, CompletionClause, EpochId, OperationStatus, RecoveryStrategy,
    TaskBudget, TaskEngineUpdate, TaskId, TaskStatus,
};
use carl::sidecar::DataRootLock;
use carl::storage::{ChannelId, ClientName, ExternalSessionId, RuntimeStore, Store};
use chrono::Utc;
use rusqlite::Connection;
use serde_json::json;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn metrics_slash_requires_one_exact_raw_prompt_block() -> TestResult {
    for blocks in [
        vec!["\n/metrics".to_owned()],
        vec!["\r\n/metrics".to_owned()],
        vec!["\t/metrics".to_owned()],
        vec![" /metrics".to_owned()],
        vec!["/metrics\n".to_owned()],
        vec!["/metrics ".to_owned()],
        vec!["/metrics".to_owned(), "second block".to_owned()],
        vec!["please run /metrics now".to_owned()],
        vec!["\"/metrics\"".to_owned()],
        vec!["prefix\n/metrics".to_owned()],
    ] {
        let prompt = Prompt::new(blocks.clone())?;
        assert_eq!(prompt.task_slash_command(), None, "{blocks:?}");
    }
    let exact = Prompt::new(vec!["/metrics".to_owned()])?;
    assert_eq!(exact.task_slash_command(), Some("/metrics"));
    Ok(())
}

#[test]
fn durable_engine_updates_map_to_frontend_kernel_updates() {
    let task_id = TaskId::new();
    let epoch_id = EpochId::new();
    let checkpoint_id = CheckpointId::new();
    let clauses = vec![CompletionClause {
        id: "verified".into(),
        description: "The change is verified".into(),
        required: true,
        status: ClauseStatus::Satisfied,
        evidence: Vec::new(),
    }];
    let updates = vec![
        TaskEngineUpdate::TaskStatus {
            task_id,
            status: TaskStatus::Active,
        },
        TaskEngineUpdate::EpochObjective {
            task_id,
            epoch_id,
            objective: "Reproduce the failure".into(),
        },
        TaskEngineUpdate::CheckpointCommitted {
            task_id,
            checkpoint_id,
            digest: "a".repeat(64),
        },
        TaskEngineUpdate::ContextUsage {
            task_id,
            total_tokens: 80,
            context_window: Some(100),
        },
        TaskEngineUpdate::Compaction {
            task_id,
            generation: 2,
            replaced_provider: true,
        },
        TaskEngineUpdate::RecoveryStrategy {
            task_id,
            strategy: RecoveryStrategy::ReplaceApproach,
        },
        TaskEngineUpdate::CompletionClauses {
            task_id,
            clauses: clauses.clone(),
        },
    ]
    .into_iter()
    .map(carl::acp::KernelUpdate::from)
    .collect::<Vec<_>>();

    assert_eq!(
        updates,
        vec![
            carl::acp::KernelUpdate::TaskStatus {
                task_id,
                status: TaskStatus::Active,
            },
            carl::acp::KernelUpdate::EpochObjective {
                task_id,
                epoch_id,
                objective: "Reproduce the failure".into(),
            },
            carl::acp::KernelUpdate::CheckpointCommitted {
                task_id,
                checkpoint_id,
                digest: "a".repeat(64),
            },
            carl::acp::KernelUpdate::ContextUsage {
                task_id,
                total_tokens: 80,
                context_window: Some(100),
            },
            carl::acp::KernelUpdate::Compaction {
                task_id,
                generation: 2,
                replaced_provider: true,
            },
            carl::acp::KernelUpdate::RecoveryStrategy {
                task_id,
                strategy: RecoveryStrategy::ReplaceApproach,
            },
            carl::acp::KernelUpdate::CompletionClauses { task_id, clauses },
        ]
    );
}

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
async fn autonomous_capability_routes_initial_prompt_through_the_durable_task_engine() -> TestResult
{
    let layout = Layout::new()?;
    let port = ScriptedPort::autonomous_small_edit();
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let mut request = new_session(&layout, Frontend::Acp, None)?;
    request.mode = PermissionMode::BypassPermissions;
    let session = kernel.new_session(request).await?;

    let outcome = kernel
        .prompt(
            session.id(),
            Prompt::new(vec!["edit the file and verify it".into()])?,
        )
        .await?;

    assert_eq!(outcome.stop_reason, PromptStopReason::EndTurn);
    assert!(outcome.updates.iter().any(|update| matches!(
        update,
        carl::acp::KernelUpdate::TaskStatus {
            status: TaskStatus::Completed,
            ..
        }
    )));
    let tasks = Store::open(&layout.database)?.list_resumable_tasks()?;
    assert!(tasks.is_empty(), "the routed durable task completed");
    let events = Store::open(&layout.database)?.read_events(session.id())?;
    assert!(
        events
            .iter()
            .any(|event| matches!(event.event, Event::TaskLifecycle { .. }))
    );
    let operation_started = events
        .iter()
        .position(|event| {
            matches!(
                event.event,
                Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::OperationTransitioned {
                        to: OperationStatus::Started,
                        ..
                    },
                    ..
                }
            )
        })
        .expect("task operation start is durable");
    let dispatch_authorized = events
        .iter()
        .position(|event| {
            matches!(
                event.event,
                Event::ToolDispatchAuthorized {
                    automatic: true,
                    ..
                }
            )
        })
        .expect("Task 1 dispatch authority is durable");
    assert!(operation_started < dispatch_authorized);
    assert_eq!(
        shared.lock().unwrap().starts,
        2,
        "one planning request plus one work request proves the legacy one-turn path was not used"
    );
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn direct_acp_admission_budget_reaches_the_durable_task() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::autonomous_small_edit();
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let expected = TaskBudget {
        max_wall_time_seconds: Some(7_200),
        max_provider_requests: Some(321),
        max_tool_calls: Some(654),
        soft_epoch_seconds: 600,
        soft_epoch_tool_calls: 77,
    };
    let mut request = new_session(&layout, Frontend::Acp, None)?;
    request.mode = PermissionMode::BypassPermissions;
    request.budget = expected;
    let session = kernel.new_session(request).await?;

    kernel
        .prompt(
            session.id(),
            Prompt::new(vec!["complete a directly admitted durable edit".into()])?,
        )
        .await?;

    let events = Store::open(&layout.database)?.read_events(session.id())?;
    let persisted = events.iter().find_map(|envelope| match &envelope.event {
        Event::TaskLifecycle {
            event: carl::runtime::task::TaskEvent::Created { budget, .. },
            ..
        } => Some(*budget),
        _ => None,
    });
    assert_eq!(persisted, Some(expected));
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn direct_acp_rejects_a_budget_outside_consumer_policy() -> TestResult {
    let layout = Layout::new()?;
    let kernel = Kernel::start_with_ports(
        layout.runtime()?,
        Box::new(ScriptedPort::autonomous_small_edit()),
        None,
    )
    .await?;
    let mut request = new_session(&layout, Frontend::Acp, None)?;
    request.budget.soft_epoch_seconds = 29;

    assert_eq!(
        kernel
            .new_session(request)
            .await
            .expect_err("programmatic ACP admission must share consumer budget policy")
            .code(),
        carl::acp::KernelErrorCode::InvalidInput
    );
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_prompt_after_terminal_completion_starts_a_new_durable_task() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::autonomous_small_edit();
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let mut request = new_session(&layout, Frontend::Acp, None)?;
    request.mode = PermissionMode::BypassPermissions;
    let session = kernel.new_session(request).await?;

    let first = kernel
        .prompt(
            session.id(),
            Prompt::new(vec!["complete the first durable edit".into()])?,
        )
        .await?;
    let second = kernel
        .prompt(
            session.id(),
            Prompt::new(vec!["complete a second durable edit".into()])?,
        )
        .await?;

    assert_eq!(first.stop_reason, PromptStopReason::EndTurn);
    assert_eq!(second.stop_reason, PromptStopReason::EndTurn);
    assert_eq!(
        shared.lock().unwrap().starts,
        4,
        "each durable task has one planning and one work request"
    );
    let events = Store::open(&layout.database)?.read_events(session.id())?;
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event.event,
                Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::Created { .. },
                    ..
                }
            ))
            .count(),
        2
    );

    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn autonomous_prompt_durably_steers_and_cancels_while_provider_read_is_pending() -> TestResult
{
    let layout = Layout::new()?;
    let port = ScriptedPort::autonomous_pending_edit();
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let mut request = new_session(&layout, Frontend::Acp, None)?;
    request.mode = PermissionMode::BypassPermissions;
    let session = kernel.new_session(request).await?;
    let prompt_kernel = kernel.clone();
    let session_id = session.id();
    let prompt = tokio::spawn(async move {
        prompt_kernel
            .prompt(
                session_id,
                Prompt::new(vec!["start the durable edit".into()]).expect("prompt is valid"),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if shared.lock().unwrap().starts >= 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;

    let metrics = kernel
        .prompt(session.id(), Prompt::new(vec!["/metrics".into()])?)
        .await?;
    assert_eq!(metrics.stop_reason, PromptStopReason::EndTurn);
    let [carl::acp::KernelUpdate::AgentMessageChunk(metrics_text)] = metrics.updates.as_slice()
    else {
        return Err("active metrics slash did not return one sanitized message".into());
    };
    let metrics_json: serde_json::Value = serde_json::from_str(metrics_text)?;
    assert_eq!(metrics_json["metrics"]["status"], "active");
    assert_eq!(metrics_json["metrics"]["operation_intents"], 1);
    let after_metrics = Store::open(&layout.database)?.read_events(session.id())?;
    assert!(!after_metrics.iter().any(|event| matches!(
        &event.event,
        Event::UserInput { text } if text == "/metrics"
    )));

    let steered = kernel
        .prompt(
            session.id(),
            Prompt::new(vec!["also verify the regression case".into()])?,
        )
        .await?;
    assert_eq!(steered.stop_reason, PromptStopReason::EndTurn);
    let events = Store::open(&layout.database)?.read_events(session.id())?;
    let task_id = events
        .iter()
        .find_map(|event| match event.event {
            Event::TaskLifecycle { task_id, .. } => Some(task_id),
            _ => None,
        })
        .expect("durable task exists");
    assert!(events.iter().any(|event| matches!(
        &event.event,
        Event::UserInput { text } if text == "also verify the regression case"
    )));
    assert!(events.iter().any(|event| matches!(
        event.event,
        Event::TaskLifecycle {
            event: carl::runtime::task::TaskEvent::SteeringQueued { .. },
            ..
        }
    )));

    kernel.cancel(session.id()).await?;
    let initial = prompt.await??;
    assert_eq!(initial.stop_reason, PromptStopReason::Failed);
    let record = Store::open(&layout.database)?
        .get_task(task_id)?
        .expect("blocked durable task remains projected");
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    let operation_id = events
        .iter()
        .find_map(|envelope| match envelope.event {
            Event::TaskLifecycle {
                event: carl::runtime::task::TaskEvent::OperationIntentRecorded { operation_id, .. },
                ..
            } => Some(operation_id),
            _ => None,
        })
        .expect("the pending effect has a durable operation identity");
    assert_eq!(
        record.snapshot.operation_status(operation_id),
        Some(carl::runtime::task::OperationStatus::Uncertain)
    );
    assert_eq!(shared.lock().unwrap().interrupts, 1);
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn autonomous_planning_control_pump_durably_steers_and_cancels_at_a_safe_boundary()
-> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::autonomous_pending_plan();
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let mut request = new_session(&layout, Frontend::Acp, None)?;
    request.mode = PermissionMode::BypassPermissions;
    let session = kernel.new_session(request).await?;
    let prompt_kernel = kernel.clone();
    let session_id = session.id();
    let prompt = tokio::spawn(async move {
        prompt_kernel
            .prompt(
                session_id,
                Prompt::new(vec!["plan and run the durable edit".into()]).expect("prompt is valid"),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if shared.lock().unwrap().starts >= 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;

    let steered = tokio::time::timeout(
        Duration::from_secs(2),
        kernel.prompt(
            session.id(),
            Prompt::new(vec!["include the parser edge case".into()])?,
        ),
    )
    .await
    .expect("planning steering remains responsive")
    .expect("planning steering is accepted");
    assert_eq!(steered.stop_reason, PromptStopReason::EndTurn);
    tokio::time::timeout(Duration::from_secs(2), kernel.cancel(session.id()))
        .await
        .expect("planning cancellation remains responsive")
        .expect("planning cancellation is accepted");
    let initial = prompt
        .await
        .expect("initial prompt task joins")
        .expect("initial prompt reports cancellation");
    assert_eq!(initial.stop_reason, PromptStopReason::Cancelled);

    let store = Store::open(&layout.database)?;
    let events = store.read_events(session.id())?;
    let task_id = events
        .iter()
        .find_map(|envelope| match envelope.event {
            Event::TaskLifecycle { task_id, .. } => Some(task_id),
            _ => None,
        })
        .expect("planning task is durable");
    let record = store
        .get_task(task_id)?
        .expect("cancelled planning task remains projected");
    assert_eq!(record.snapshot.status, TaskStatus::Cancelled);
    assert_eq!(record.snapshot.active_epoch, None);
    assert!(events.iter().any(|envelope| matches!(
        envelope.event,
        Event::TaskLifecycle {
            event: carl::runtime::task::TaskEvent::SteeringQueued { .. },
            ..
        }
    )));
    assert_eq!(shared.lock().unwrap().interrupts, 1);
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_an_autonomous_prompt_caller_does_not_cancel_the_durable_task() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::autonomous_pending_edit();
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let mut request = new_session(&layout, Frontend::Acp, None)?;
    request.mode = PermissionMode::BypassPermissions;
    let session = kernel.new_session(request).await?;
    let prompt_kernel = kernel.clone();
    let session_id = session.id();
    let prompt = tokio::spawn(async move {
        prompt_kernel
            .prompt(
                session_id,
                Prompt::new(vec!["start the durable edit".into()]).expect("prompt is valid"),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if shared.lock().unwrap().starts >= 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;

    prompt.abort();
    assert!(
        prompt
            .await
            .expect_err("the caller was dropped")
            .is_cancelled()
    );
    tokio::task::yield_now().await;
    assert_eq!(shared.lock().unwrap().interrupts, 0);
    let task = Store::open(&layout.database)?
        .list_resumable_tasks()?
        .into_iter()
        .next()
        .expect("disconnect leaves the durable task resumable");
    assert_eq!(task.snapshot.status, TaskStatus::Active);

    kernel.cancel(session.id()).await?;
    assert_eq!(shared.lock().unwrap().interrupts, 1);
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn autonomous_task_pauses_for_exact_approval_and_resumes_the_same_provider_epoch()
-> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::autonomous_small_edit();
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;

    let waiting = kernel
        .prompt(
            session.id(),
            Prompt::new(vec!["edit the file after approval".into()])?,
        )
        .await?;
    assert_eq!(waiting.stop_reason, PromptStopReason::WaitingForApproval);
    let code = local_approval_code(&waiting)?;

    let completed = kernel
        .prompt(session.id(), Prompt::new(vec![format!("/approve {code}")])?)
        .await?;
    assert_eq!(completed.stop_reason, PromptStopReason::EndTurn);
    assert!(completed.updates.iter().any(|update| matches!(
        update,
        carl::acp::KernelUpdate::TaskStatus {
            status: TaskStatus::Completed,
            ..
        }
    )));
    {
        let state = shared.lock().unwrap();
        assert_eq!(state.resolved, [EffectDecision::Allow]);
        assert_eq!(state.starts, 2, "approval resumes the same work epoch");
    }
    let events = Store::open(&layout.database)?.read_events(session.id())?;
    let operation_started = events
        .iter()
        .position(|event| {
            matches!(
                event.event,
                Event::TaskLifecycle {
                    event: carl::runtime::task::TaskEvent::OperationTransitioned {
                        to: OperationStatus::Started,
                        ..
                    },
                    ..
                }
            )
        })
        .expect("operation starts durably");
    let approval_requested = events
        .iter()
        .position(|event| matches!(event.event, Event::ApprovalRequested { .. }))
        .expect("approval is durable before provider resolution");
    assert!(operation_started < approval_requested);
    let replay = kernel
        .prompt(session.id(), Prompt::new(vec![format!("/approve {code}")])?)
        .await
        .expect_err("approval code is exact and single use");
    assert_eq!(
        replay.code(),
        carl::acp::KernelErrorCode::ApprovalUnavailable
    );
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn autonomous_task_denial_blocks_the_task_without_restarting_the_provider_epoch() -> TestResult
{
    let layout = Layout::new()?;
    let port = ScriptedPort::autonomous_small_edit();
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;

    let waiting = kernel
        .prompt(
            session.id(),
            Prompt::new(vec!["edit the file after approval".into()])?,
        )
        .await?;
    assert_eq!(waiting.stop_reason, PromptStopReason::WaitingForApproval);
    let code = local_approval_code(&waiting)?;

    let denied = kernel
        .prompt(session.id(), Prompt::new(vec![format!("/deny {code}")])?)
        .await?;
    assert_eq!(denied.stop_reason, PromptStopReason::Failed);
    assert!(denied.updates.iter().any(|update| matches!(
        update,
        carl::acp::KernelUpdate::TaskStatus {
            status: TaskStatus::Blocked,
            ..
        }
    )));

    let events = Store::open(&layout.database)?.read_events(session.id())?;
    let task_id = events
        .iter()
        .find_map(|event| match event.event {
            Event::TaskLifecycle { task_id, .. } => Some(task_id),
            _ => None,
        })
        .expect("durable task exists");
    let record = Store::open(&layout.database)?
        .get_task(task_id)?
        .expect("denied durable task remains projected");
    assert_eq!(record.snapshot.status, TaskStatus::Blocked);
    {
        let state = shared.lock().unwrap();
        assert_eq!(state.resolved, [EffectDecision::Deny]);
        assert_eq!(state.starts, 2, "denial does not restart the work epoch");
    }

    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn autonomous_full_access_secret_effect_is_denied_before_frontend_persistence() -> TestResult
{
    let layout = Layout::new()?;
    let port = ScriptedPort::autonomous_secret_effect();
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let mut request = new_session(&layout, Frontend::Acp, None)?;
    request.mode = PermissionMode::BypassPermissions;
    let session = kernel.new_session(request).await?;

    let outcome = kernel
        .prompt(
            session.id(),
            Prompt::new(vec!["run the requested verification".into()])?,
        )
        .await?;

    assert_eq!(outcome.stop_reason, PromptStopReason::Failed);
    assert_eq!(shared.lock().unwrap().resolved, [EffectDecision::Deny]);
    let events = Store::open(&layout.database)?.read_events(session.id())?;
    assert!(!events.iter().any(|envelope| matches!(
        envelope.event,
        Event::ToolProposed { .. }
            | Event::ToolDispatchAuthorized { .. }
            | Event::ApprovalRequested { .. }
    )));
    let task_id = events
        .iter()
        .find_map(|envelope| match envelope.event {
            Event::TaskLifecycle { task_id, .. } => Some(task_id),
            _ => None,
        })
        .expect("durable task exists");
    assert_eq!(
        Store::open(&layout.database)?
            .get_task(task_id)?
            .expect("blocked task remains projected")
            .snapshot
            .status,
        TaskStatus::Blocked
    );
    kernel.shutdown().await?;
    Ok(())
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
async fn unknown_agent_items_are_not_reported_as_successful_tools() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::with_events([
        AgentEvent::ItemStarted {
            context_id: context()?,
            epoch_id: epoch()?,
            item: AgentItem::Other {
                item_id: "future-item".into(),
                item_type: "futureTool".into(),
            },
        },
        AgentEvent::ItemCompleted {
            context_id: context()?,
            epoch_id: epoch()?,
            item: AgentItem::Other {
                item_id: "future-item".into(),
                item_type: "futureTool".into(),
            },
        },
        AgentEvent::EpochCompleted {
            context_id: context()?,
            epoch_id: epoch()?,
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
async fn cross_bound_agent_events_are_quarantined_before_mutating_the_active_turn() -> TestResult {
    let expected_context = context()?;
    let expected_epoch = epoch()?;
    let other_context = AgentContextId::parse("thr_other")?;
    let other_epoch = AgentEpochId::parse("turn_other")?;
    let cases = vec![
        (
            "context start",
            AgentEvent::ContextStarted {
                context_id: other_context.clone(),
            },
        ),
        (
            "epoch start context",
            AgentEvent::EpochStarted {
                context_id: other_context.clone(),
                epoch_id: expected_epoch.clone(),
            },
        ),
        (
            "epoch start epoch",
            AgentEvent::EpochStarted {
                context_id: expected_context.clone(),
                epoch_id: other_epoch.clone(),
            },
        ),
        (
            "item start",
            AgentEvent::ItemStarted {
                context_id: expected_context.clone(),
                epoch_id: other_epoch.clone(),
                item: AgentItem::Other {
                    item_id: "item-start".into(),
                    item_type: "reasoning".into(),
                },
            },
        ),
        (
            "assistant delta",
            AgentEvent::AssistantDelta {
                context_id: expected_context.clone(),
                epoch_id: other_epoch.clone(),
                text: "stale text".into(),
            },
        ),
        (
            "item completion",
            AgentEvent::ItemCompleted {
                context_id: expected_context.clone(),
                epoch_id: other_epoch.clone(),
                item: AgentItem::Other {
                    item_id: "item-complete".into(),
                    item_type: "reasoning".into(),
                },
            },
        ),
        (
            "usage",
            AgentEvent::UsageUpdated {
                context_id: expected_context.clone(),
                epoch_id: other_epoch.clone(),
                usage: AgentUsage {
                    last_total_tokens: 3,
                    total_tokens: 5,
                    model_context_window: Some(8_192),
                },
            },
        ),
        (
            "diff",
            AgentEvent::DiffUpdated {
                context_id: expected_context.clone(),
                epoch_id: other_epoch.clone(),
                diff: "@@ stale @@".into(),
            },
        ),
        (
            "epoch completion",
            AgentEvent::EpochCompleted {
                context_id: expected_context.clone(),
                epoch_id: other_epoch.clone(),
                status: "completed".into(),
            },
        ),
        (
            "provider failure",
            AgentEvent::ProviderFailed {
                context_id: Some(expected_context.clone()),
                epoch_id: Some(other_epoch.clone()),
            },
        ),
        (
            "compaction start",
            AgentEvent::CompactionStarted {
                context_id: other_context.clone(),
                item_id: "compact-start".into(),
            },
        ),
        (
            "compaction completion",
            AgentEvent::CompactionCompleted {
                context_id: other_context.clone(),
                item_id: "compact-complete".into(),
            },
        ),
    ];

    for (case, event) in cases {
        let forbidden_provider_id = match &event {
            AgentEvent::ContextStarted { context_id }
            | AgentEvent::CompactionStarted { context_id, .. }
            | AgentEvent::CompactionCompleted { context_id, .. } => Some(context_id.as_str()),
            AgentEvent::EpochStarted { epoch_id, .. }
            | AgentEvent::ItemStarted { epoch_id, .. }
            | AgentEvent::AssistantDelta { epoch_id, .. }
            | AgentEvent::ItemCompleted { epoch_id, .. }
            | AgentEvent::UsageUpdated { epoch_id, .. }
            | AgentEvent::DiffUpdated { epoch_id, .. }
            | AgentEvent::EpochCompleted { epoch_id, .. } => Some(epoch_id.as_str()),
            AgentEvent::ProviderFailed { epoch_id, .. } => {
                epoch_id.as_ref().map(AgentEpochId::as_str)
            }
            AgentEvent::EffectRequested(_) => None,
        }
        .map(str::to_owned);
        let layout = Layout::new()?;
        let port = ScriptedPort::with_events([
            event,
            AgentEvent::EpochCompleted {
                context_id: expected_context.clone(),
                epoch_id: expected_epoch.clone(),
                status: "completed".into(),
            },
        ]);
        let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
        let session = kernel
            .new_session(new_session(&layout, Frontend::Acp, None)?)
            .await?;
        let outcome = kernel
            .prompt(session.id(), Prompt::new(vec![format!("reject {case}")])?)
            .await?;
        assert_eq!(outcome.stop_reason, PromptStopReason::EndTurn);
        let events = Store::open(&layout.database)?.read_events(session.id())?;
        assert!(!events.iter().any(|event| matches!(
            event.event,
            Event::AssistantTextDelta { .. }
                | Event::WorkspaceDiffUpdated { .. }
                | Event::ToolCompleted { .. }
                | Event::TurnInterrupted { .. }
        )));
        if let Some(forbidden_provider_id) = forbidden_provider_id {
            assert!(!events.iter().any(|event| matches!(
                &event.event,
                Event::ProviderLifecycle {
                    provider_id: Some(provider_id),
                    ..
                } if provider_id == &forbidden_provider_id
            )));
        }
        assert!(matches!(
            events.last().map(|event| &event.event),
            Some(Event::TurnCompleted)
        ));
        kernel.shutdown().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn unbounded_agent_events_fail_before_mutating_the_active_turn() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::with_events([
        AgentEvent::ItemStarted {
            context_id: context()?,
            epoch_id: epoch()?,
            item: AgentItem::Other {
                item_id: "i".repeat(129),
                item_type: "reasoning".into(),
            },
        },
        AgentEvent::EpochCompleted {
            context_id: context()?,
            epoch_id: epoch()?,
            status: "completed".into(),
        },
    ]);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let session = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;

    let error = kernel
        .prompt(
            session.id(),
            Prompt::new(vec!["reject oversized item".into()])?,
        )
        .await
        .expect_err("an unbounded neutral event must fail at the kernel boundary");

    assert_eq!(error.code(), carl::acp::KernelErrorCode::ProviderFailed);
    let events = Store::open(&layout.database)?.read_events(session.id())?;
    assert!(!events.iter().any(|event| matches!(
        event.event,
        Event::ProviderLifecycle { .. } | Event::TurnCompleted
    )));
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn foreign_events_are_delivered_once_and_in_order_to_the_owning_session() -> TestResult {
    let layout = Layout::new()?;
    let owner_context = AgentContextId::parse("thr_owner")?;
    let current_context = AgentContextId::parse("thr_current")?;
    let owner_epoch = AgentEpochId::parse("turn_owner_1")?;
    let current_epoch = AgentEpochId::parse("turn_current")?;
    let owner_next_epoch = AgentEpochId::parse("turn_owner_2")?;
    let port = ScriptedPort::with_routing(
        vec![
            owned_item_started(&owner_context, &owner_epoch, "owner-item"),
            AgentEvent::EffectRequested(owned_effect_request(
                &owner_context,
                &owner_epoch,
                "owner-approval",
                "owner-item",
                AgentEffectKind::Command,
            )?),
            AgentEvent::AssistantDelta {
                context_id: owner_context.clone(),
                epoch_id: owner_epoch.clone(),
                text: "owner-only output".into(),
            },
            owned_epoch_completed(&current_context, &current_epoch),
            owned_epoch_completed(&owner_context, &owner_epoch),
            owned_epoch_completed(&owner_context, &owner_next_epoch),
        ],
        vec![owner_context, current_context],
        vec![owner_epoch, current_epoch, owner_next_epoch],
    );
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let owner = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let current = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;

    let waiting = kernel
        .prompt(owner.id(), Prompt::new(vec!["pause owner".into()])?)
        .await?;
    let code = local_approval_code(&waiting)?;
    let current_outcome = kernel
        .prompt(current.id(), Prompt::new(vec!["run current".into()])?)
        .await?;
    assert_eq!(current_outcome.stop_reason, PromptStopReason::EndTurn);
    assert!(current_outcome.updates.iter().all(|update| !matches!(
        update,
        carl::acp::KernelUpdate::AgentMessageChunk(text) if text == "owner-only output"
    )));

    let owner_outcome = kernel
        .prompt(owner.id(), Prompt::new(vec![format!("/approve {code}")])?)
        .await?;
    assert_eq!(owner_outcome.stop_reason, PromptStopReason::EndTurn);
    assert_eq!(
        owner_outcome
            .updates
            .iter()
            .filter(|update| matches!(
                update,
                carl::acp::KernelUpdate::AgentMessageChunk(text)
                    if text == "owner-only output"
            ))
            .count(),
        1
    );

    let replay_check = kernel
        .prompt(owner.id(), Prompt::new(vec!["next owner turn".into()])?)
        .await?;
    assert_eq!(replay_check.stop_reason, PromptStopReason::EndTurn);
    assert!(replay_check.updates.iter().all(|update| !matches!(
        update,
        carl::acp::KernelUpdate::AgentMessageChunk(text) if text == "owner-only output"
    )));
    let events = Store::open(&layout.database)?.read_events(owner.id())?;
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                &event.event,
                Event::AssistantTextDelta { text } if text == "owner-only output"
            ))
            .count(),
        1
    );
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn foreign_effect_requests_are_resolved_only_while_the_owner_is_driving() -> TestResult {
    let layout = Layout::new()?;
    let owner_context = AgentContextId::parse("thr_effect_owner")?;
    let current_context = AgentContextId::parse("thr_effect_current")?;
    let owner_epoch = AgentEpochId::parse("turn_effect_owner")?;
    let current_epoch = AgentEpochId::parse("turn_effect_current")?;
    let port = ScriptedPort::with_routing(
        vec![
            owned_item_started(&owner_context, &owner_epoch, "effect-owner-item"),
            AgentEvent::EffectRequested(owned_effect_request(
                &owner_context,
                &owner_epoch,
                "initial-owner-approval",
                "effect-owner-item",
                AgentEffectKind::Command,
            )?),
            AgentEvent::EffectRequested(owned_effect_request(
                &owner_context,
                &owner_epoch,
                "foreign-network",
                "network-owner-item",
                AgentEffectKind::Network,
            )?),
            owned_epoch_completed(&current_context, &current_epoch),
        ],
        vec![owner_context, current_context],
        vec![owner_epoch, current_epoch],
    );
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let owner = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let current = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let waiting = kernel
        .prompt(owner.id(), Prompt::new(vec!["pause effect owner".into()])?)
        .await?;
    let code = local_approval_code(&waiting)?;

    let current_outcome = kernel
        .prompt(current.id(), Prompt::new(vec!["run current".into()])?)
        .await?;
    assert_eq!(current_outcome.stop_reason, PromptStopReason::EndTurn);
    assert!(shared.lock().unwrap().resolved_requests.is_empty());

    let owner_error = kernel
        .prompt(owner.id(), Prompt::new(vec![format!("/approve {code}")])?)
        .await
        .expect_err("the owner must terminally deny its unsupported effect");
    assert_eq!(
        owner_error.code(),
        carl::acp::KernelErrorCode::ProviderFailed
    );
    assert_eq!(
        shared.lock().unwrap().resolved_requests,
        [
            ("initial-owner-approval".into(), EffectDecision::Allow),
            ("foreign-network".into(), EffectDecision::Deny),
        ]
    );
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_foreign_events_fail_the_owner_without_replay_or_cross_session_failure()
-> TestResult {
    let layout = Layout::new()?;
    let owner_context = AgentContextId::parse("thr_malformed_owner")?;
    let current_context = AgentContextId::parse("thr_malformed_current")?;
    let owner_epoch = AgentEpochId::parse("turn_malformed_owner_1")?;
    let stale_owner_epoch = AgentEpochId::parse("turn_malformed_owner_stale")?;
    let current_epoch = AgentEpochId::parse("turn_malformed_current")?;
    let owner_next_epoch = AgentEpochId::parse("turn_malformed_owner_2")?;
    let port = ScriptedPort::with_routing(
        vec![
            owned_item_started(&owner_context, &owner_epoch, "malformed-owner-item"),
            AgentEvent::EffectRequested(owned_effect_request(
                &owner_context,
                &owner_epoch,
                "malformed-owner-approval",
                "malformed-owner-item",
                AgentEffectKind::Command,
            )?),
            AgentEvent::AssistantDelta {
                context_id: owner_context.clone(),
                epoch_id: stale_owner_epoch,
                text: "s".repeat(1_048_577),
            },
            AgentEvent::AssistantDelta {
                context_id: owner_context.clone(),
                epoch_id: owner_epoch.clone(),
                text: "x".repeat(1_048_577),
            },
            owned_epoch_completed(&current_context, &current_epoch),
            owned_epoch_completed(&owner_context, &owner_next_epoch),
        ],
        vec![owner_context, current_context],
        vec![owner_epoch, current_epoch, owner_next_epoch],
    );
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let owner = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let current = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let waiting = kernel
        .prompt(
            owner.id(),
            Prompt::new(vec!["pause malformed owner".into()])?,
        )
        .await?;
    let code = local_approval_code(&waiting)?;

    let current_outcome = kernel
        .prompt(current.id(), Prompt::new(vec!["run current".into()])?)
        .await?;
    assert_eq!(current_outcome.stop_reason, PromptStopReason::EndTurn);
    let owner_error = kernel
        .prompt(owner.id(), Prompt::new(vec![format!("/approve {code}")])?)
        .await
        .expect_err("the malformed event must fail only its owner");
    assert_eq!(
        owner_error.code(),
        carl::acp::KernelErrorCode::ProviderFailed
    );

    let owner_next = kernel
        .prompt(owner.id(), Prompt::new(vec!["owner recovers".into()])?)
        .await?;
    assert_eq!(owner_next.stop_reason, PromptStopReason::EndTurn);
    let owner_events = Store::open(&layout.database)?.read_events(owner.id())?;
    assert!(
        !owner_events
            .iter()
            .any(|event| matches!(event.event, Event::AssistantTextDelta { .. }))
    );
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn foreign_backlog_overflow_fails_only_the_owner_once() -> TestResult {
    let layout = Layout::new()?;
    let owner_context = AgentContextId::parse("thr_overflow_owner")?;
    let current_context = AgentContextId::parse("thr_overflow_current")?;
    let owner_epoch = AgentEpochId::parse("turn_overflow_owner_1")?;
    let current_epoch = AgentEpochId::parse("turn_overflow_current")?;
    let owner_next_epoch = AgentEpochId::parse("turn_overflow_owner_2")?;
    let mut provider_events = vec![
        owned_item_started(&owner_context, &owner_epoch, "overflow-owner-item"),
        AgentEvent::EffectRequested(owned_effect_request(
            &owner_context,
            &owner_epoch,
            "overflow-owner-approval",
            "overflow-owner-item",
            AgentEffectKind::Command,
        )?),
    ];
    provider_events.extend((0..257).map(|token_count| AgentEvent::UsageUpdated {
        context_id: owner_context.clone(),
        epoch_id: owner_epoch.clone(),
        usage: AgentUsage {
            last_total_tokens: token_count,
            total_tokens: token_count,
            model_context_window: Some(8_192),
        },
    }));
    provider_events.extend([
        owned_epoch_completed(&current_context, &current_epoch),
        owned_epoch_completed(&owner_context, &owner_next_epoch),
    ]);
    let port = ScriptedPort::with_routing(
        provider_events,
        vec![owner_context, current_context],
        vec![owner_epoch, current_epoch, owner_next_epoch],
    );
    let shared = Arc::clone(&port.shared);
    let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
    let owner = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let current = kernel
        .new_session(new_session(&layout, Frontend::Acp, None)?)
        .await?;
    let waiting = kernel
        .prompt(
            owner.id(),
            Prompt::new(vec!["pause overflow owner".into()])?,
        )
        .await?;
    let code = local_approval_code(&waiting)?;

    let current_outcome = kernel
        .prompt(current.id(), Prompt::new(vec!["run current".into()])?)
        .await?;
    assert_eq!(current_outcome.stop_reason, PromptStopReason::EndTurn);
    let current_events = Store::open(&layout.database)?.read_events(current.id())?;
    assert!(matches!(
        current_events.last().map(|event| &event.event),
        Some(Event::TurnCompleted)
    ));
    let owner_terminal_events = Store::open(&layout.database)?.read_events(owner.id())?;
    assert!(matches!(
        owner_terminal_events.last().map(|event| &event.event),
        Some(Event::TurnInterrupted { reason }) if reason == "provider_backlog_overflow"
    ));
    assert_eq!(
        shared.lock().unwrap().resolved_requests,
        [("overflow-owner-approval".into(), EffectDecision::Deny)]
    );

    let owner_result = tokio::time::timeout(
        Duration::from_secs(1),
        kernel.prompt(owner.id(), Prompt::new(vec![format!("/approve {code}")])?),
    )
    .await
    .map_err(|_| "overflow owner did not receive a terminal result")?;
    let owner_error = owner_result.expect_err("overflow must terminally fail only its owner");
    assert_eq!(
        owner_error.code(),
        carl::acp::KernelErrorCode::ProviderFailed
    );

    let owner_next = kernel
        .prompt(
            owner.id(),
            Prompt::new(vec!["owner after overflow".into()])?,
        )
        .await?;
    assert_eq!(owner_next.stop_reason, PromptStopReason::EndTurn);
    let owner_events = Store::open(&layout.database)?.read_events(owner.id())?;
    assert_eq!(
        owner_events
            .iter()
            .filter(|event| matches!(event.event, Event::TurnInterrupted { .. }))
            .count(),
        1
    );
    assert!(matches!(
        owner_events.last().map(|event| &event.event),
        Some(Event::TurnCompleted)
    ));
    kernel.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn orphaned_known_tool_completion_fails_without_a_completion_journal() -> TestResult {
    let layout = Layout::new()?;
    let port = ScriptedPort::with_events([
        AgentEvent::ItemCompleted {
            context_id: context()?,
            epoch_id: epoch()?,
            item: command_item("orphan-command", "completed"),
        },
        AgentEvent::EpochCompleted {
            context_id: context()?,
            epoch_id: epoch()?,
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
        AgentEvent::ItemStarted {
            context_id: context()?,
            epoch_id: epoch()?,
            item: command_item("changed-kind", "inProgress"),
        },
        AgentEvent::ItemCompleted {
            context_id: context()?,
            epoch_id: epoch()?,
            item: file_change_item("changed-kind", "completed"),
        },
        AgentEvent::EpochCompleted {
            context_id: context()?,
            epoch_id: epoch()?,
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
        AgentEvent::ItemStarted {
            context_id: context()?,
            epoch_id: epoch()?,
            item: command_item("duplicate-command", "inProgress"),
        },
        AgentEvent::ItemCompleted {
            context_id: context()?,
            epoch_id: epoch()?,
            item: command_item("duplicate-command", "completed"),
        },
        AgentEvent::ItemCompleted {
            context_id: context()?,
            epoch_id: epoch()?,
            item: command_item("duplicate-command", "completed"),
        },
        AgentEvent::EpochCompleted {
            context_id: context()?,
            epoch_id: epoch()?,
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
            AgentEvent::ItemStarted {
                context_id: context()?,
                epoch_id: epoch()?,
                item: command_item(&item_id, "inProgress"),
            },
            AgentEvent::ItemCompleted {
                context_id: context()?,
                epoch_id: epoch()?,
                item: command_item(&item_id, terminal_status),
            },
            AgentEvent::EpochCompleted {
                context_id: context()?,
                epoch_id: epoch()?,
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
    assert_eq!(shared.lock().unwrap().resolved, [EffectDecision::Allow]);
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
async fn full_access_denies_unknown_and_completed_approval_items() -> TestResult {
    for case in [InvalidApprovalCase::Unknown, InvalidApprovalCase::Completed] {
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
            assert_eq!(state.resolved, [EffectDecision::Deny]);
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
async fn unsupported_effect_kinds_are_denied_before_turn_failure() -> TestResult {
    for mode in [PermissionMode::Default, PermissionMode::BypassPermissions] {
        for kind in [AgentEffectKind::Network, AgentEffectKind::External] {
            let layout = Layout::new()?;
            let port =
                ScriptedPort::with_events([AgentEvent::EffectRequested(effect_request_with_kind(
                    "approval-unsupported",
                    "item-unsupported",
                    kind,
                    "unsupported consequential effect",
                )?)]);
            let shared = Arc::clone(&port.shared);
            let kernel = Kernel::start_with_ports(layout.runtime()?, Box::new(port), None).await?;
            let mut request = new_session(&layout, Frontend::Acp, None)?;
            request.mode = mode;
            let session = kernel.new_session(request).await?;

            let error = kernel
                .prompt(session.id(), Prompt::new(vec!["request effect".into()])?)
                .await
                .expect_err("an unsupported consequential effect must fail the turn");

            assert_eq!(error.code(), carl::acp::KernelErrorCode::ProviderFailed);
            {
                let state = shared.lock().unwrap();
                assert_eq!(state.resolved, [EffectDecision::Deny]);
                assert_eq!(state.allowed_effects, 0);
            }
            kernel.shutdown().await?;
        }
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
    assert_eq!(shared.lock().unwrap().resolved, [EffectDecision::Deny]);
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
    events: VecDeque<AgentEvent>,
    continuation: VecDeque<AgentEvent>,
    resolved: Vec<EffectDecision>,
    resolved_requests: Vec<(String, EffectDecision)>,
    context_ids: VecDeque<AgentContextId>,
    epoch_ids: VecDeque<AgentEpochId>,
    allowed_effects: usize,
    starts: usize,
    steers: Vec<String>,
    interrupts: usize,
    autonomous: bool,
    latest_operation_id: Option<String>,
    hold_autonomous_work: bool,
    hold_autonomous_planning: bool,
    autonomous_effect_summary: Option<String>,
}

#[derive(Clone, Copy)]
enum InvalidApprovalCase {
    Unknown,
    Completed,
}

impl ScriptedPort {
    fn autonomous_small_edit() -> Self {
        let port = Self::with_events([]);
        port.shared.lock().unwrap().autonomous = true;
        port
    }

    fn autonomous_pending_edit() -> Self {
        let port = Self::autonomous_small_edit();
        port.shared.lock().unwrap().hold_autonomous_work = true;
        port
    }

    fn autonomous_pending_plan() -> Self {
        let port = Self::autonomous_small_edit();
        port.shared.lock().unwrap().hold_autonomous_planning = true;
        port
    }

    fn autonomous_secret_effect() -> Self {
        let port = Self::autonomous_small_edit();
        port.shared.lock().unwrap().autonomous_effect_summary =
            Some("Command: curl -H 'Authorization: Bearer sk-123456789012345678901234'".into());
        port
    }

    fn lifecycle() -> TestResult<Self> {
        Ok(Self::with_events([
            AgentEvent::EpochStarted {
                context_id: context()?,
                epoch_id: epoch()?,
            },
            AgentEvent::AssistantDelta {
                context_id: context()?,
                epoch_id: epoch()?,
                text: "Working".into(),
            },
            AgentEvent::AssistantDelta {
                context_id: context()?,
                epoch_id: epoch()?,
                text: "Fixed and verified.".into(),
            },
            AgentEvent::EpochCompleted {
                context_id: context()?,
                epoch_id: epoch()?,
                status: "completed".into(),
            },
        ]))
    }

    fn approval() -> TestResult<Self> {
        let approval = effect_request(
            "approval-7",
            "item_123",
            "Command: cargo test\nReason: Run the test suite",
        )?;
        let port = Self::with_events([
            AgentEvent::ItemStarted {
                context_id: context()?,
                epoch_id: epoch()?,
                item: command_item("item_123", "inProgress"),
            },
            AgentEvent::EffectRequested(approval),
        ]);
        port.shared.lock().unwrap().continuation = VecDeque::from([
            AgentEvent::AssistantDelta {
                context_id: context()?,
                epoch_id: epoch()?,
                text: "Tests passed.".into(),
            },
            AgentEvent::EpochCompleted {
                context_id: context()?,
                epoch_id: epoch()?,
                status: "completed".into(),
            },
        ]);
        Ok(port)
    }

    fn automatic_approval() -> TestResult<(Self, String)> {
        let approval = effect_request(
            "approval-auto",
            "item_auto",
            "Command: cargo test\nReason: Run the test suite",
        )?;
        let request_digest = approval.request_digest.to_string();
        let port = Self::with_events([
            AgentEvent::ItemStarted {
                context_id: context()?,
                epoch_id: epoch()?,
                item: command_item("item_auto", "inProgress"),
            },
            AgentEvent::EffectRequested(approval),
        ]);
        port.shared.lock().unwrap().continuation = VecDeque::from([
            AgentEvent::ItemCompleted {
                context_id: context()?,
                epoch_id: epoch()?,
                item: command_item("item_auto", "completed"),
            },
            AgentEvent::EpochCompleted {
                context_id: context()?,
                epoch_id: epoch()?,
                status: "completed".into(),
            },
        ]);
        Ok((port, request_digest))
    }

    fn invalid_automatic_approval(case: InvalidApprovalCase) -> TestResult<Self> {
        let approval = effect_request(
            "approval-invalid",
            "item_invalid",
            "Command: cargo test\nReason: Run the test suite",
        )?;
        let events = match case {
            InvalidApprovalCase::Unknown => {
                vec![AgentEvent::EffectRequested(approval)]
            }
            InvalidApprovalCase::Completed => vec![
                AgentEvent::ItemStarted {
                    context_id: context()?,
                    epoch_id: epoch()?,
                    item: command_item("item_invalid", "inProgress"),
                },
                AgentEvent::ItemCompleted {
                    context_id: context()?,
                    epoch_id: epoch()?,
                    item: command_item("item_invalid", "completed"),
                },
                AgentEvent::EffectRequested(approval),
            ],
        };
        Ok(Self {
            shared: Arc::new(Mutex::new(PortState {
                events: events.into(),
                continuation: VecDeque::new(),
                resolved: Vec::new(),
                resolved_requests: Vec::new(),
                context_ids: VecDeque::new(),
                epoch_ids: VecDeque::new(),
                allowed_effects: 0,
                starts: 0,
                steers: Vec::new(),
                interrupts: 0,
                autonomous: false,
                latest_operation_id: None,
                hold_autonomous_work: false,
                hold_autonomous_planning: false,
                autonomous_effect_summary: None,
            })),
        })
    }

    fn secret_approval() -> TestResult<Self> {
        let approval = effect_request(
            "approval-secret",
            "item_secret",
            "Command: curl -H 'Authorization: Bearer sk-123456789012345678901234'\nReason: Run a command",
        )?;
        Ok(Self::with_events([AgentEvent::EffectRequested(approval)]))
    }

    fn idle() -> TestResult<Self> {
        Ok(Self::with_events([]))
    }

    fn with_events<const N: usize>(events: [AgentEvent; N]) -> Self {
        Self {
            shared: Arc::new(Mutex::new(PortState {
                events: events.into(),
                continuation: VecDeque::new(),
                resolved: Vec::new(),
                resolved_requests: Vec::new(),
                context_ids: VecDeque::new(),
                epoch_ids: VecDeque::new(),
                allowed_effects: 0,
                starts: 0,
                steers: Vec::new(),
                interrupts: 0,
                autonomous: false,
                latest_operation_id: None,
                hold_autonomous_work: false,
                hold_autonomous_planning: false,
                autonomous_effect_summary: None,
            })),
        }
    }

    fn with_routing(
        events: Vec<AgentEvent>,
        context_ids: Vec<AgentContextId>,
        epoch_ids: Vec<AgentEpochId>,
    ) -> Self {
        Self {
            shared: Arc::new(Mutex::new(PortState {
                events: events.into(),
                continuation: VecDeque::new(),
                resolved: Vec::new(),
                resolved_requests: Vec::new(),
                context_ids: context_ids.into(),
                epoch_ids: epoch_ids.into(),
                allowed_effects: 0,
                starts: 0,
                steers: Vec::new(),
                interrupts: 0,
                autonomous: false,
                latest_operation_id: None,
                hold_autonomous_work: false,
                hold_autonomous_planning: false,
                autonomous_effect_summary: None,
            })),
        }
    }
}

fn command_item(item_id: &str, status: &str) -> AgentItem {
    AgentItem::Command {
        item_id: item_id.into(),
        command: "cargo test".into(),
        cwd: PathBuf::from("/workspace"),
        status: status.into(),
        exit_code: (status == "completed").then_some(0),
        aggregated_output: None,
        process_id: None,
    }
}

fn file_change_item(item_id: &str, status: &str) -> AgentItem {
    AgentItem::FileChange {
        item_id: item_id.into(),
        status: status.into(),
        changes: json!([]),
    }
}

impl AgentPort for ScriptedPort {
    fn supports_autonomous_tasks(&self) -> bool {
        self.shared.lock().unwrap().autonomous
    }

    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            resume: true,
            compact: true,
            token_usage: true,
            pre_dispatch_effects: true,
            history_paging: false,
            background_processes: false,
        }
    }

    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>> {
        Box::pin(async {
            Ok(vec![AgentModel {
                id: ModelId::parse("gpt-5.6-codex").map_err(|_| invalid())?,
                display_name: "GPT-5.6 Codex".into(),
                supported_efforts: vec![ReasoningEffort::Medium, ReasoningEffort::High],
                default_effort: ReasoningEffort::Medium,
            }])
        })
    }

    fn start_context(&mut self, _request: StartAgentContext) -> AgentFuture<'_, AgentContextId> {
        let context_id = self.shared.lock().unwrap().context_ids.pop_front();
        Box::pin(async move { context_id.map_or_else(context, Ok) })
    }

    fn resume_context(&mut self, request: ResumeAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async move { Ok(request.context_id) })
    }

    fn compact_context(&mut self, _context_id: &AgentContextId) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
        let shared = Arc::clone(&self.shared);
        Box::pin(async move {
            let mut state = shared.lock().unwrap();
            state.starts += 1;
            if !state.autonomous {
                return state.epoch_ids.pop_front().map_or_else(epoch, Ok);
            }
            let epoch_id = AgentEpochId::parse(format!("durable-turn-{}", state.starts))?;
            state.events.push_back(AgentEvent::EpochStarted {
                context_id: request.context_id.clone(),
                epoch_id: epoch_id.clone(),
            });
            if state.starts % 2 == 1 && state.hold_autonomous_planning {
                return Ok(epoch_id);
            }
            if state.starts % 2 == 1 {
                state.events.push_back(AgentEvent::AssistantDelta {
                    context_id: request.context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    text: "<carl-completion-contract>{\"version\":1,\"goal\":\"Edit and verify\",\"constraints\":[],\"clauses\":[{\"id\":\"requested-outcome\",\"description\":\"edit\",\"required\":true,\"status\":\"pending\",\"evidence\":[]},{\"id\":\"explicit-verification\",\"description\":\"verify\",\"required\":true,\"status\":\"pending\",\"evidence\":[]}]}</carl-completion-contract>".into(),
                });
                state.events.push_back(AgentEvent::EpochCompleted {
                    context_id: request.context_id,
                    epoch_id: epoch_id.clone(),
                    status: "completed".into(),
                });
            } else {
                let work_number = state.starts / 2;
                let item_id = format!("durable-item-{work_number}");
                let request_id = format!("durable-request-{work_number}");
                let summary = state
                    .autonomous_effect_summary
                    .clone()
                    .unwrap_or_else(|| "run focused verification".into());
                let item = command_item(&item_id, "inProgress");
                state.events.push_back(AgentEvent::ItemStarted {
                    context_id: request.context_id.clone(),
                    epoch_id: epoch_id.clone(),
                    item,
                });
                state
                    .events
                    .push_back(AgentEvent::EffectRequested(AgentEffectRequest {
                        context_id: request.context_id,
                        epoch_id: epoch_id.clone(),
                        request_id: AgentRequestId::parse(request_id)?,
                        item_id,
                        kind: AgentEffectKind::Command,
                        summary,
                        request_digest: Sha256Digest::parse("44".repeat(32))
                            .map_err(|_| invalid())?,
                    }));
            }
            Ok(epoch_id)
        })
    }

    fn steer(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
        input: String,
    ) -> AgentFuture<'_, ()> {
        let shared = Arc::clone(&self.shared);
        Box::pin(async move {
            let mut state = shared.lock().unwrap();
            if let Some(operation_id) = input.strip_prefix("carl-operation-id:") {
                state.latest_operation_id = Some(operation_id.trim().to_owned());
            }
            state.steers.push(input);
            Ok(())
        })
    }

    fn interrupt(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
    ) -> AgentFuture<'_, ()> {
        let shared = Arc::clone(&self.shared);
        Box::pin(async move {
            shared.lock().unwrap().interrupts += 1;
            Ok(())
        })
    }

    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent> {
        let shared = Arc::clone(&self.shared);
        Box::pin(async move {
            let event = {
                let mut state = shared.lock().unwrap();
                if let Some(event) = state.events.pop_front() {
                    Some(event)
                } else if state.autonomous
                    && state.hold_autonomous_planning
                    && state.starts % 2 == 1
                {
                    None
                } else if state.autonomous && !state.hold_autonomous_work {
                    let operation_id = state
                        .latest_operation_id
                        .take()
                        .expect("durable operation binding");
                    let context_id = context()?;
                    let epoch_id = AgentEpochId::parse(format!("durable-turn-{}", state.starts))?;
                    let item_id = format!("durable-item-{}", state.starts / 2);
                    state.events.push_back(AgentEvent::ItemCompleted {
                        context_id: context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        item: command_item(&item_id, "completed"),
                    });
                    state.events.push_back(AgentEvent::AssistantDelta {
                        context_id: context_id.clone(),
                        epoch_id: epoch_id.clone(),
                        text: format!("<carl-epoch-report>{{\"schema_version\":1,\"disposition\":\"complete\",\"summary\":\"done\",\"clause_evidence\":[{{\"clause_id\":\"requested-outcome\",\"operation_ids\":[{operation_id:?}],\"event_sequences\":[],\"artifact_digests\":[]}},{{\"clause_id\":\"explicit-verification\",\"operation_ids\":[{operation_id:?}],\"event_sequences\":[],\"artifact_digests\":[]}}],\"exact_identifiers\":[]}}</carl-epoch-report>"),
                    });
                    state.events.push_back(AgentEvent::EpochCompleted {
                        context_id,
                        epoch_id,
                        status: "completed".into(),
                    });
                    state.events.pop_front()
                } else {
                    None
                }
            };
            if let Some(event) = event {
                return Ok(event);
            }
            std::future::pending().await
        })
    }

    fn resolve_effect(
        &mut self,
        request_id: &AgentRequestId,
        decision: EffectDecision,
    ) -> AgentFuture<'_, ()> {
        let shared = Arc::clone(&self.shared);
        let request_id = request_id.as_str().to_owned();
        Box::pin(async move {
            let mut state = shared.lock().unwrap();
            state.resolved.push(decision);
            state.resolved_requests.push((request_id, decision));
            if decision == EffectDecision::Allow {
                state.allowed_effects += 1;
            }
            let continuation = std::mem::take(&mut state.continuation);
            state.events.extend(continuation);
            Ok(())
        })
    }

    fn list_background_processes(
        &mut self,
        _context_id: &AgentContextId,
    ) -> AgentFuture<'_, Vec<AgentProcess>> {
        Box::pin(async { Err(invalid()) })
    }

    fn terminate_background_process(
        &mut self,
        _context_id: &AgentContextId,
        _process_id: &str,
    ) -> AgentFuture<'_, bool> {
        Box::pin(async { Err(invalid()) })
    }

    fn shutdown(&mut self) -> AgentFuture<'_, ()> {
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
        budget: TaskBudget::default(),
    })
}

fn context() -> Result<AgentContextId, AgentPortError> {
    AgentContextId::parse("thr_123")
}

fn epoch() -> Result<AgentEpochId, AgentPortError> {
    AgentEpochId::parse("turn_123")
}

fn effect_request(
    request_id: &str,
    item_id: &str,
    summary: &str,
) -> TestResult<AgentEffectRequest> {
    effect_request_with_kind(request_id, item_id, AgentEffectKind::Command, summary)
}

fn effect_request_with_kind(
    request_id: &str,
    item_id: &str,
    kind: AgentEffectKind,
    summary: &str,
) -> TestResult<AgentEffectRequest> {
    Ok(AgentEffectRequest {
        context_id: context()?,
        epoch_id: epoch()?,
        request_id: AgentRequestId::parse(request_id)?,
        item_id: item_id.into(),
        kind,
        summary: summary.into(),
        request_digest: Sha256Digest::parse("11".repeat(32))?,
    })
}

fn owned_effect_request(
    context_id: &AgentContextId,
    epoch_id: &AgentEpochId,
    request_id: &str,
    item_id: &str,
    kind: AgentEffectKind,
) -> TestResult<AgentEffectRequest> {
    Ok(AgentEffectRequest {
        context_id: context_id.clone(),
        epoch_id: epoch_id.clone(),
        request_id: AgentRequestId::parse(request_id)?,
        item_id: item_id.into(),
        kind,
        summary: "owner-scoped effect".into(),
        request_digest: Sha256Digest::parse("33".repeat(32))?,
    })
}

fn owned_item_started(
    context_id: &AgentContextId,
    epoch_id: &AgentEpochId,
    item_id: &str,
) -> AgentEvent {
    AgentEvent::ItemStarted {
        context_id: context_id.clone(),
        epoch_id: epoch_id.clone(),
        item: command_item(item_id, "inProgress"),
    }
}

fn owned_epoch_completed(context_id: &AgentContextId, epoch_id: &AgentEpochId) -> AgentEvent {
    AgentEvent::EpochCompleted {
        context_id: context_id.clone(),
        epoch_id: epoch_id.clone(),
        status: "completed".into(),
    }
}

fn local_approval_code(outcome: &PromptOutcome) -> TestResult<String> {
    let message = outcome
        .updates
        .iter()
        .find_map(|update| match update {
            carl::acp::KernelUpdate::AgentMessageChunk(text) => Some(text.as_str()),
            _ => None,
        })
        .ok_or("local approval command was not surfaced")?;
    message
        .split("/approve ")
        .nth(1)
        .and_then(|suffix| suffix.split_whitespace().next())
        .map(str::to_owned)
        .ok_or_else(|| "approval code missing".into())
}

fn invalid() -> AgentPortError {
    AgentPortError::from_code(AgentPortErrorCode::InvalidResponse)
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
