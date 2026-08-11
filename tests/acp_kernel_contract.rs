use std::collections::VecDeque;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
}

#[derive(Clone, Copy)]
enum InvalidApprovalCase {
    Unknown,
    Completed,
}

impl ScriptedPort {
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

    fn start_epoch(&mut self, _request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
        let shared = Arc::clone(&self.shared);
        Box::pin(async move {
            let mut state = shared.lock().unwrap();
            state.starts += 1;
            state.epoch_ids.pop_front().map_or_else(epoch, Ok)
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
            shared.lock().unwrap().steers.push(input);
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
        let event = self.shared.lock().unwrap().events.pop_front();
        Box::pin(async move {
            match event {
                Some(event) => Ok(event),
                None => std::future::pending().await,
            }
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
