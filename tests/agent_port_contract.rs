use std::collections::VecDeque;
use std::path::PathBuf;

use carl::acp::{Kernel, KernelHandle, PermissionMode};
use carl::delegates::codex::CodexAppServer;
use carl::delegates::{ModelId, ReasoningEffort};
use carl::policy::Sha256Digest;
use carl::runtime::agent_port::{
    AgentCapabilities, AgentContextId, AgentEffectKind, AgentEffectRequest, AgentEpochId,
    AgentEvent, AgentFuture, AgentItem, AgentModel, AgentPort, AgentPortError, AgentPortErrorCode,
    AgentProcess, AgentRequestId, AgentUsage, EffectDecision, ResumeAgentContext,
    StartAgentContext, StartAgentEpoch,
};
use carl::storage::RuntimeStore;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test(flavor = "current_thread")]
async fn fake_port_exercises_the_provider_neutral_lifecycle() -> TestResult {
    let context_id = AgentContextId::parse("context-123")?;
    let epoch_id = AgentEpochId::parse("epoch-123")?;
    let request_id = AgentRequestId::parse("request-123")?;
    let model = ModelId::parse("model-123")?;
    let digest = Sha256Digest::parse("11".repeat(32))?;
    let mut port: Box<dyn AgentPort> = Box::new(FakePort {
        context_id: context_id.clone(),
        epoch_id: epoch_id.clone(),
        events: VecDeque::from([
            AgentEvent::ContextStarted {
                context_id: context_id.clone(),
            },
            AgentEvent::EffectRequested(AgentEffectRequest {
                request_id: request_id.clone(),
                item_id: "item-123".into(),
                kind: AgentEffectKind::Command,
                summary: "Run the contract suite".into(),
                request_digest: digest,
            }),
        ]),
        resolved: Vec::new(),
        shutdown: false,
    });

    assert_eq!(
        port.capabilities(),
        AgentCapabilities {
            resume: true,
            compact: true,
            token_usage: true,
            pre_dispatch_effects: true,
            history_paging: false,
            background_processes: true,
        }
    );
    let models = port.models().await?;
    assert_eq!(models[0].id.as_str(), "model-123");
    assert_eq!(models[0].display_name, "Model 123");
    assert_eq!(models[0].supported_efforts, [ReasoningEffort::High]);
    assert_eq!(models[0].default_effort, ReasoningEffort::High);

    assert_eq!(
        port.start_context(StartAgentContext {
            cwd: PathBuf::from("/workspace"),
            model: model.clone(),
            permission_mode: PermissionMode::Default,
        })
        .await?,
        context_id
    );
    assert_eq!(
        port.resume_context(ResumeAgentContext {
            context_id: context_id.clone(),
            cwd: PathBuf::from("/workspace"),
            model: model.clone(),
            permission_mode: PermissionMode::Default,
        })
        .await?,
        context_id
    );
    port.compact_context(&context_id).await?;
    assert_eq!(
        port.start_epoch(StartAgentEpoch {
            context_id: context_id.clone(),
            input: "Do the work".into(),
            model,
            effort: ReasoningEffort::High,
            permission_mode: PermissionMode::Default,
        })
        .await?,
        epoch_id
    );
    port.steer(&context_id, &epoch_id, "Focus on the port".into())
        .await?;
    port.interrupt(&context_id, &epoch_id).await?;
    assert!(matches!(
        port.next_event().await?,
        AgentEvent::ContextStarted { context_id: seen } if seen == context_id
    ));
    assert!(matches!(
        port.next_event().await?,
        AgentEvent::EffectRequested(request)
            if request.request_id == request_id
                && request.kind == AgentEffectKind::Command
                && request.request_digest == digest
    ));
    port.resolve_effect(&request_id, EffectDecision::Allow)
        .await?;
    assert_eq!(
        port.list_background_processes(&context_id).await?,
        [AgentProcess {
            process_id: "process-123".into(),
            item_id: "item-123".into(),
            command: "cargo test".into(),
            cwd: PathBuf::from("/workspace"),
            os_pid: Some(42),
        }]
    );
    assert!(
        port.terminate_background_process(&context_id, "process-123")
            .await?
    );
    port.shutdown().await?;
    Ok(())
}

#[test]
fn opaque_agent_ids_are_bounded_and_redacted() -> TestResult {
    let context = AgentContextId::parse("context-secret-4cf7")?;
    let epoch = AgentEpochId::parse("epoch-secret-4cf7")?;
    let request = AgentRequestId::parse("request-secret-4cf7")?;

    assert_eq!(context.as_str(), "context-secret-4cf7");
    assert_eq!(epoch.as_str(), "epoch-secret-4cf7");
    assert_eq!(request.as_str(), "request-secret-4cf7");
    for (rendered, secret) in [
        (format!("{context:?}"), "context-secret-4cf7"),
        (format!("{epoch:?}"), "epoch-secret-4cf7"),
        (format!("{request:?}"), "request-secret-4cf7"),
    ] {
        assert!(!rendered.contains(secret));
        assert!(rendered.contains("<redacted>"));
    }
    for invalid in [String::new(), "\0".into(), "x".repeat(129)] {
        assert!(AgentContextId::parse(invalid.clone()).is_err());
        assert!(AgentEpochId::parse(invalid.clone()).is_err());
        assert!(AgentRequestId::parse(invalid).is_err());
    }
    Ok(())
}

#[test]
fn neutral_payload_bounds_reject_untrusted_adapter_values() -> TestResult {
    let epoch_id = AgentEpochId::parse("epoch-bounds")?;
    let context_id = AgentContextId::parse("context-bounds")?;
    let request_id = AgentRequestId::parse("request-bounds")?;
    let digest = Sha256Digest::parse("22".repeat(32))?;
    let oversized_id = "i".repeat(129);

    for event in [
        AgentEvent::ItemStarted {
            epoch_id: epoch_id.clone(),
            item: AgentItem::Other {
                item_id: oversized_id.clone(),
                item_type: "reasoning".into(),
            },
        },
        AgentEvent::ItemStarted {
            epoch_id: epoch_id.clone(),
            item: AgentItem::Command {
                item_id: "command-bounds".into(),
                command: "cargo test".into(),
                cwd: PathBuf::from("/workspace"),
                status: "inProgress".into(),
                exit_code: None,
                aggregated_output: None,
                process_id: Some(oversized_id.clone()),
            },
        },
        AgentEvent::EffectRequested(AgentEffectRequest {
            request_id: request_id.clone(),
            item_id: oversized_id.clone(),
            kind: AgentEffectKind::Command,
            summary: "Run tests".into(),
            request_digest: digest,
        }),
        AgentEvent::EffectRequested(AgentEffectRequest {
            request_id,
            item_id: "effect-bounds".into(),
            kind: AgentEffectKind::Command,
            summary: "s".repeat(32 * 1_024 + 1),
            request_digest: digest,
        }),
        AgentEvent::CompactionStarted {
            context_id,
            item_id: oversized_id.clone(),
        },
    ] {
        let error = event
            .validate()
            .expect_err("an untrusted adapter value must be rejected at the seam");
        assert_eq!(error.code(), AgentPortErrorCode::InvalidResponse);
    }

    let process_error = AgentProcess {
        process_id: oversized_id,
        item_id: "process-item".into(),
        command: "cargo test".into(),
        cwd: PathBuf::from("/workspace"),
        os_pid: None,
    }
    .validate()
    .expect_err("an oversized process identifier must be rejected");
    assert_eq!(process_error.code(), AgentPortErrorCode::InvalidResponse);
    Ok(())
}

#[test]
fn agent_event_diagnostics_redact_text_diffs_and_item_ids() -> TestResult {
    let epoch_id = AgentEpochId::parse("epoch-debug")?;
    let context_id = AgentContextId::parse("context-debug")?;
    let rendered = [
        format!(
            "{:?}",
            AgentEvent::AssistantDelta {
                epoch_id: epoch_id.clone(),
                text: "assistant-secret-bf92".into(),
            }
        ),
        format!(
            "{:?}",
            AgentEvent::DiffUpdated {
                epoch_id,
                diff: "diff-secret-bf92".into(),
            }
        ),
        format!(
            "{:?}",
            AgentEvent::CompactionCompleted {
                context_id,
                item_id: "item-secret-bf92".into(),
            }
        ),
    ]
    .join("\n");

    for secret in [
        "assistant-secret-bf92",
        "diff-secret-bf92",
        "item-secret-bf92",
    ] {
        assert!(!rendered.contains(secret));
    }
    assert!(rendered.contains("AssistantDelta"));
    assert!(rendered.contains("DiffUpdated"));
    assert!(rendered.contains("CompactionCompleted"));
    Ok(())
}

#[test]
fn codex_app_server_implements_the_neutral_port() {
    fn assert_agent_port<T: AgentPort>() {}
    assert_agent_port::<CodexAppServer>();
}

#[allow(dead_code)]
fn kernel_accepts_only_the_neutral_port(
    store: RuntimeStore,
    port: Box<dyn AgentPort>,
) -> impl std::future::Future<Output = Result<KernelHandle, carl::acp::KernelError>> {
    Kernel::start_with_ports(store, port, None)
}

#[allow(dead_code)]
fn kernel_convenience_start_is_provider_neutral(
    store: RuntimeStore,
    port: FakePort,
) -> impl std::future::Future<Output = Result<KernelHandle, carl::acp::KernelError>> {
    Kernel::start(store, port, None)
}

struct FakePort {
    context_id: AgentContextId,
    epoch_id: AgentEpochId,
    events: VecDeque<AgentEvent>,
    resolved: Vec<EffectDecision>,
    shutdown: bool,
}

impl AgentPort for FakePort {
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            resume: true,
            compact: true,
            token_usage: true,
            pre_dispatch_effects: true,
            history_paging: false,
            background_processes: true,
        }
    }

    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>> {
        Box::pin(async {
            Ok(vec![AgentModel {
                id: ModelId::parse("model-123").expect("literal model identifier is valid"),
                display_name: "Model 123".into(),
                supported_efforts: vec![ReasoningEffort::High],
                default_effort: ReasoningEffort::High,
            }])
        })
    }

    fn start_context(&mut self, _request: StartAgentContext) -> AgentFuture<'_, AgentContextId> {
        let context_id = self.context_id.clone();
        Box::pin(async move { Ok(context_id) })
    }

    fn resume_context(&mut self, _request: ResumeAgentContext) -> AgentFuture<'_, AgentContextId> {
        let context_id = self.context_id.clone();
        Box::pin(async move { Ok(context_id) })
    }

    fn compact_context(&mut self, _context_id: &AgentContextId) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn start_epoch(&mut self, _request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
        let epoch_id = self.epoch_id.clone();
        Box::pin(async move { Ok(epoch_id) })
    }

    fn steer(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
        _text: String,
    ) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn interrupt(
        &mut self,
        _context_id: &AgentContextId,
        _epoch_id: &AgentEpochId,
    ) -> AgentFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent> {
        let event = self.events.pop_front();
        Box::pin(async move { event.ok_or_else(AgentPortError::unavailable_context) })
    }

    fn resolve_effect(
        &mut self,
        _request_id: &AgentRequestId,
        decision: EffectDecision,
    ) -> AgentFuture<'_, ()> {
        self.resolved.push(decision);
        Box::pin(async { Ok(()) })
    }

    fn list_background_processes(
        &mut self,
        _context_id: &AgentContextId,
    ) -> AgentFuture<'_, Vec<AgentProcess>> {
        Box::pin(async {
            Ok(vec![AgentProcess {
                process_id: "process-123".into(),
                item_id: "item-123".into(),
                command: "cargo test".into(),
                cwd: PathBuf::from("/workspace"),
                os_pid: Some(42),
            }])
        })
    }

    fn terminate_background_process(
        &mut self,
        _context_id: &AgentContextId,
        process_id: &str,
    ) -> AgentFuture<'_, bool> {
        let terminated = process_id == "process-123";
        Box::pin(async move { Ok(terminated) })
    }

    fn shutdown(&mut self) -> AgentFuture<'_, ()> {
        self.shutdown = true;
        Box::pin(async { Ok(()) })
    }
}

#[allow(dead_code)]
fn normalized_event_surface_is_provider_neutral(
    context_id: AgentContextId,
    epoch_id: AgentEpochId,
    request_id: AgentRequestId,
    digest: Sha256Digest,
) -> [AgentEvent; 13] {
    [
        AgentEvent::ContextStarted {
            context_id: context_id.clone(),
        },
        AgentEvent::EpochStarted {
            context_id: context_id.clone(),
            epoch_id: epoch_id.clone(),
        },
        AgentEvent::ItemStarted {
            epoch_id: epoch_id.clone(),
            item: AgentItem::Other {
                item_id: "other-1".into(),
                item_type: "reasoning".into(),
            },
        },
        AgentEvent::AssistantDelta {
            epoch_id: epoch_id.clone(),
            text: "Working".into(),
        },
        AgentEvent::DiffUpdated {
            epoch_id: epoch_id.clone(),
            diff: "@@ -1 +1 @@".into(),
        },
        AgentEvent::UsageUpdated {
            epoch_id: epoch_id.clone(),
            usage: AgentUsage {
                last_total_tokens: 3,
                total_tokens: 5,
                model_context_window: Some(258_400),
            },
        },
        AgentEvent::EffectRequested(AgentEffectRequest {
            request_id,
            item_id: "command-1".into(),
            kind: AgentEffectKind::Command,
            summary: "Run tests".into(),
            request_digest: digest,
        }),
        AgentEvent::ItemCompleted {
            epoch_id: epoch_id.clone(),
            item: AgentItem::FileChange {
                item_id: "file-1".into(),
                status: "completed".into(),
                changes: serde_json::json!([]),
            },
        },
        AgentEvent::CompactionStarted {
            context_id: context_id.clone(),
            item_id: "compact-1".into(),
        },
        AgentEvent::CompactionCompleted {
            context_id: context_id.clone(),
            item_id: "compact-1".into(),
        },
        AgentEvent::EpochCompleted {
            epoch_id: epoch_id.clone(),
            status: "completed".into(),
        },
        AgentEvent::ProviderFailed {
            context_id: Some(context_id),
            epoch_id: Some(epoch_id.clone()),
        },
        AgentEvent::ItemStarted {
            epoch_id,
            item: AgentItem::Command {
                item_id: "command-1".into(),
                command: "cargo test".into(),
                cwd: PathBuf::from("/workspace"),
                status: "inProgress".into(),
                exit_code: None,
                aggregated_output: None,
                process_id: Some("process-1".into()),
            },
        },
    ]
}
