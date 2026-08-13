use std::collections::{HashMap, VecDeque};
use std::future;
use std::path::PathBuf;
use std::sync::Arc;

use futures_util::StreamExt;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::agent_port::{
    AgentCapabilities, AgentContextId, AgentEffectKind, AgentEffectRequest, AgentEpochId,
    AgentEvent, AgentFuture, AgentItem, AgentModel, AgentPort, AgentPortError, AgentPortErrorCode,
    AgentProcess, AgentRequestId, AgentUsage, ContextRecovery, EffectDecision, ResumeAgentContext,
    StartAgentContext, StartAgentEpoch,
};
use super::task::ContextPackage;
use crate::acp::PermissionMode;
use crate::delegates::{ModelId, ReasoningEffort};
use crate::policy::Sha256Digest;
use crate::providers::catalog::ProviderCatalog;
use crate::providers::{
    FinishReason, Message, MessageContent, ModelRequest, ModelSettings, Provider, ProviderError,
    ProviderEvent, Role,
};
use crate::tools::{NativeToolRuntime, PreparedNativeTool, ToolEffectKind};

const MAX_TOOL_ROUNDS: u32 = 64;
const DEFAULT_OUTPUT_TOKENS: u32 = 16_384;

pub struct NativeAgentPort {
    provider: Arc<dyn Provider>,
    catalog: ProviderCatalog,
    contexts: HashMap<String, NativeContext>,
    events: VecDeque<AgentEvent>,
    pending: HashMap<String, PendingEffect>,
    active: Option<ActiveEpoch>,
}

struct NativeContext {
    cwd: PathBuf,
    model: ModelId,
    permission: PermissionMode,
    messages: Vec<Message>,
    tools: NativeToolRuntime,
    total_tokens: u64,
}

struct ActiveEpoch {
    context_id: AgentContextId,
    epoch_id: AgentEpochId,
    model: ModelId,
    effort: ReasoningEffort,
    cancellation: CancellationToken,
    rounds: u32,
}

struct PendingEffect {
    context_id: AgentContextId,
    epoch_id: AgentEpochId,
    item: AgentItem,
    tool_call_id: crate::events::ToolCallId,
    tool: PreparedNativeTool,
}

impl NativeAgentPort {
    #[must_use]
    pub fn new(provider: Arc<dyn Provider>, catalog: ProviderCatalog) -> Self {
        Self {
            provider,
            catalog,
            contexts: HashMap::new(),
            events: VecDeque::new(),
            pending: HashMap::new(),
            active: None,
        }
    }

    async fn drive_provider(&mut self) -> Result<(), AgentPortError> {
        loop {
            let active = self.active.as_mut().ok_or_else(invalid_request)?;
            active.rounds = active.rounds.checked_add(1).ok_or_else(invalid_response)?;
            if active.rounds > MAX_TOOL_ROUNDS {
                return Err(invalid_response());
            }
            let context = self
                .contexts
                .get(active.context_id.as_str())
                .ok_or_else(invalid_request)?;
            let request = ModelRequest {
                messages: context.messages.clone(),
                tools: context.tools.definitions().to_vec(),
                settings: ModelSettings {
                    model: active.model.as_str().to_owned(),
                    temperature: None,
                    max_output_tokens: Some(DEFAULT_OUTPUT_TOKENS),
                    reasoning_effort: Some(active.effort),
                },
                cancellation: active.cancellation.clone(),
            };
            let mut stream = self
                .provider
                .stream(request)
                .await
                .map_err(map_provider_error)?;
            let mut assistant_content = Vec::new();
            let mut calls = Vec::new();
            let mut finish = None;
            while let Some(event) = stream.next().await {
                match event.map_err(map_provider_error)? {
                    ProviderEvent::TextDelta { text } => {
                        self.events.push_back(AgentEvent::AssistantDelta {
                            context_id: active.context_id.clone(),
                            epoch_id: active.epoch_id.clone(),
                            text: text.clone(),
                        });
                        assistant_content.push(MessageContent::Text { text });
                    }
                    ProviderEvent::ToolCall {
                        tool_call_id,
                        provider_call_id,
                        name,
                        arguments,
                    } => {
                        assistant_content.push(MessageContent::ToolCall {
                            tool_call_id,
                            provider_call_id: provider_call_id.clone(),
                            name: name.clone(),
                            arguments: arguments.clone(),
                        });
                        calls.push((tool_call_id, provider_call_id, name, arguments));
                    }
                    ProviderEvent::Usage {
                        input_tokens,
                        output_tokens,
                    } => {
                        let context = self
                            .contexts
                            .get_mut(active.context_id.as_str())
                            .ok_or_else(invalid_request)?;
                        let previous = context.total_tokens;
                        context.total_tokens = input_tokens
                            .checked_add(output_tokens)
                            .ok_or_else(invalid_response)?;
                        self.events.push_back(AgentEvent::UsageUpdated {
                            context_id: active.context_id.clone(),
                            epoch_id: active.epoch_id.clone(),
                            usage: AgentUsage {
                                last_total_tokens: previous,
                                total_tokens: context.total_tokens,
                                model_context_window: self.provider.capabilities().context_window,
                            },
                        });
                    }
                    ProviderEvent::Finish { reason } => {
                        if finish.replace(reason).is_some() {
                            return Err(invalid_response());
                        }
                    }
                }
            }
            let finish = finish.ok_or_else(invalid_response)?;
            if !assistant_content.is_empty() {
                self.contexts
                    .get_mut(active.context_id.as_str())
                    .ok_or_else(invalid_request)?
                    .messages
                    .push(Message {
                        role: Role::Assistant,
                        content: assistant_content,
                    });
            }
            match finish {
                FinishReason::ToolCalls if !calls.is_empty() => {
                    let mut has_pending = false;
                    for (tool_call_id, _provider_call_id, name, arguments) in calls {
                        let tool = self
                            .contexts
                            .get(active.context_id.as_str())
                            .ok_or_else(invalid_request)?
                            .tools
                            .prepare(&name, arguments)
                            .map_err(|_| invalid_response())?;
                        let item_id = format!("native-tool-{tool_call_id}");
                        let item = item_for(
                            &item_id,
                            &tool,
                            self.contexts
                                .get(active.context_id.as_str())
                                .ok_or_else(invalid_request)?
                                .cwd
                                .clone(),
                        );
                        self.events.push_back(AgentEvent::ItemStarted {
                            context_id: active.context_id.clone(),
                            epoch_id: active.epoch_id.clone(),
                            item: item.clone(),
                        });
                        if tool.effect_kind() == ToolEffectKind::Read {
                            let output = tool
                                .execute(active.cancellation.clone())
                                .await
                                .map_err(|_| invalid_response())?;
                            self.contexts
                                .get_mut(active.context_id.as_str())
                                .ok_or_else(invalid_request)?
                                .messages
                                .push(Message {
                                    role: Role::Tool,
                                    content: vec![MessageContent::ToolResult {
                                        tool_call_id,
                                        output,
                                    }],
                                });
                            self.events.push_back(AgentEvent::ItemCompleted {
                                context_id: active.context_id.clone(),
                                epoch_id: active.epoch_id.clone(),
                                item: complete_item(item, true, None),
                            });
                        } else {
                            has_pending = true;
                            let request_id = AgentRequestId::parse(Uuid::new_v4().to_string())?;
                            let request_digest = Sha256Digest::parse(
                                tool.digest()
                                    .strip_prefix("sha256:")
                                    .ok_or_else(invalid_response)?,
                            )
                            .map_err(|_| invalid_response())?;
                            self.events.push_back(AgentEvent::EffectRequested(
                                AgentEffectRequest {
                                    context_id: active.context_id.clone(),
                                    epoch_id: active.epoch_id.clone(),
                                    request_id: request_id.clone(),
                                    item_id: item_id.clone(),
                                    kind: match tool.effect_kind() {
                                        ToolEffectKind::Command => AgentEffectKind::Command,
                                        ToolEffectKind::Write => AgentEffectKind::FileChange,
                                        ToolEffectKind::Read => unreachable!(),
                                    },
                                    summary: tool.summary().to_owned(),
                                    request_digest,
                                },
                            ));
                            self.pending.insert(
                                request_id.as_str().to_owned(),
                                PendingEffect {
                                    context_id: active.context_id.clone(),
                                    epoch_id: active.epoch_id.clone(),
                                    item,
                                    tool_call_id,
                                    tool,
                                },
                            );
                        }
                    }
                    if has_pending {
                        return Ok(());
                    }
                }
                FinishReason::Stop | FinishReason::Length | FinishReason::ContentFilter
                    if calls.is_empty() =>
                {
                    let status = match finish {
                        FinishReason::Stop => "completed",
                        FinishReason::Length => "incomplete",
                        FinishReason::ContentFilter => "blocked",
                        FinishReason::ToolCalls => unreachable!(),
                    };
                    self.events.push_back(AgentEvent::EpochCompleted {
                        context_id: active.context_id.clone(),
                        epoch_id: active.epoch_id.clone(),
                        status: status.to_owned(),
                    });
                    self.active = None;
                    return Ok(());
                }
                _ => return Err(invalid_response()),
            }
        }
    }
}

impl AgentPort for NativeAgentPort {
    fn provider_name(&self) -> &'static str {
        self.catalog.provider().as_str()
    }

    fn supports_autonomous_tasks(&self) -> bool {
        true
    }

    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            resume: false,
            compact: true,
            token_usage: true,
            pre_dispatch_effects: true,
            history_paging: false,
            background_processes: false,
        }
    }

    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>> {
        Box::pin(async move {
            Ok(self
                .catalog
                .models()
                .iter()
                .map(|model| AgentModel {
                    id: model.id().clone(),
                    display_name: model.display_name().to_owned(),
                    supported_efforts: model.supported_efforts().to_vec(),
                    default_effort: model.default_effort(),
                })
                .collect())
        })
    }

    fn start_context(&mut self, request: StartAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async move {
            if !self
                .catalog
                .models()
                .iter()
                .any(|model| model.id() == &request.model)
            {
                return Err(invalid_request());
            }
            let id = AgentContextId::parse(Uuid::new_v4().to_string())?;
            let tools = NativeToolRuntime::new(&request.cwd, request.permission_mode)
                .map_err(|_| invalid_request())?;
            self.contexts.insert(id.as_str().to_owned(), NativeContext { cwd: request.cwd, model: request.model, permission: request.permission_mode, messages: vec![Message { role: Role::System, content: vec![MessageContent::Text { text: "You are Carl, an autonomous coding agent. Use the provided tools, preserve user work, verify changes, and finish with Carl's requested epoch report.".to_owned() }] }], tools, total_tokens: 0 });
            self.events.push_back(AgentEvent::ContextStarted {
                context_id: id.clone(),
            });
            Ok(id)
        })
    }

    fn resume_context(&mut self, _: ResumeAgentContext) -> AgentFuture<'_, AgentContextId> {
        Box::pin(async {
            Err(AgentPortError::definitely_not_applied(
                AgentPortErrorCode::UnavailableContext,
            ))
        })
    }

    fn compact_context(&mut self, context_id: &AgentContextId) -> AgentFuture<'_, ()> {
        let id = context_id.clone();
        Box::pin(async move {
            let context = self
                .contexts
                .get_mut(id.as_str())
                .ok_or_else(invalid_request)?;
            let summary = context
                .messages
                .iter()
                .rev()
                .find_map(|message| {
                    message.content.iter().find_map(|content| match content {
                        MessageContent::Text { text } => Some(text.clone()),
                        _ => None,
                    })
                })
                .unwrap_or_else(|| "Continue from Carl's durable checkpoint.".to_owned());
            context.messages.truncate(1);
            context.messages.push(Message {
                role: Role::User,
                content: vec![MessageContent::Text {
                    text: format!("Compacted context:\n{summary}"),
                }],
            });
            let item_id = format!("native-compact-{}", Uuid::new_v4());
            self.events.push_back(AgentEvent::CompactionStarted {
                context_id: id.clone(),
                item_id: item_id.clone(),
            });
            self.events.push_back(AgentEvent::CompactionCompleted {
                context_id: id,
                item_id,
            });
            Ok(())
        })
    }

    fn replace_context<'a>(
        &'a mut self,
        request: ResumeAgentContext,
        package: &'a ContextPackage,
    ) -> AgentFuture<'a, ContextRecovery> {
        Box::pin(async move {
            let rendered = package.rendered.clone();
            let id = self
                .start_context(StartAgentContext {
                    cwd: request.cwd,
                    model: request.model,
                    permission_mode: request.permission_mode,
                })
                .await?;
            self.contexts
                .get_mut(id.as_str())
                .ok_or_else(invalid_request)?
                .messages
                .push(Message {
                    role: Role::User,
                    content: vec![MessageContent::Text { text: rendered }],
                });
            Ok(ContextRecovery::Replaced(id))
        })
    }

    fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId> {
        Box::pin(async move {
            if self.active.is_some() || !self.pending.is_empty() {
                return Err(invalid_request());
            }
            let context = self
                .contexts
                .get_mut(request.context_id.as_str())
                .ok_or_else(invalid_request)?;
            if context.model != request.model || context.permission != request.permission_mode {
                return Err(invalid_request());
            }
            context.messages.push(Message {
                role: Role::User,
                content: vec![MessageContent::Text {
                    text: request.input,
                }],
            });
            let epoch_id = AgentEpochId::parse(Uuid::new_v4().to_string())?;
            self.events.push_back(AgentEvent::EpochStarted {
                context_id: request.context_id.clone(),
                epoch_id: epoch_id.clone(),
            });
            self.active = Some(ActiveEpoch {
                context_id: request.context_id,
                epoch_id: epoch_id.clone(),
                model: request.model,
                effort: request.effort,
                cancellation: CancellationToken::new(),
                rounds: 0,
            });
            self.drive_provider().await?;
            Ok(epoch_id)
        })
    }

    fn steer(
        &mut self,
        context_id: &AgentContextId,
        epoch_id: &AgentEpochId,
        text: String,
    ) -> AgentFuture<'_, ()> {
        let context_id = context_id.clone();
        let epoch_id = epoch_id.clone();
        Box::pin(async move {
            let active = self.active.as_ref().ok_or_else(invalid_request)?;
            if active.context_id != context_id || active.epoch_id != epoch_id {
                return Err(invalid_request());
            }
            self.contexts
                .get_mut(context_id.as_str())
                .ok_or_else(invalid_request)?
                .messages
                .push(Message {
                    role: Role::User,
                    content: vec![MessageContent::Text { text }],
                });
            Ok(())
        })
    }

    fn interrupt(
        &mut self,
        context_id: &AgentContextId,
        epoch_id: &AgentEpochId,
    ) -> AgentFuture<'_, ()> {
        let matches = self
            .active
            .as_ref()
            .is_some_and(|active| &active.context_id == context_id && &active.epoch_id == epoch_id);
        Box::pin(async move {
            if !matches {
                return Err(invalid_request());
            }
            self.active
                .as_ref()
                .expect("active checked")
                .cancellation
                .cancel();
            Ok(())
        })
    }

    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent> {
        Box::pin(async move {
            match self.events.pop_front() {
                Some(event) => Ok(event),
                None => future::pending().await,
            }
        })
    }

    fn resolve_effect(
        &mut self,
        request_id: &AgentRequestId,
        decision: EffectDecision,
    ) -> AgentFuture<'_, ()> {
        let request_id = request_id.clone();
        Box::pin(async move {
            let pending = self
                .pending
                .remove(request_id.as_str())
                .ok_or_else(invalid_request)?;
            let (output, success) = match decision {
                EffectDecision::Allow => match pending
                    .tool
                    .execute(
                        self.active
                            .as_ref()
                            .ok_or_else(invalid_request)?
                            .cancellation
                            .clone(),
                    )
                    .await
                {
                    Ok(output) => (output, true),
                    Err(error) => (json!({"error":format!("{:?}", error.code())}), false),
                },
                EffectDecision::Deny => (json!({"error":"permission_denied"}), false),
            };
            self.contexts
                .get_mut(pending.context_id.as_str())
                .ok_or_else(invalid_request)?
                .messages
                .push(Message {
                    role: Role::Tool,
                    content: vec![MessageContent::ToolResult {
                        tool_call_id: pending.tool_call_id,
                        output: output.clone(),
                    }],
                });
            let item = complete_item(pending.item, success, Some(output));
            self.events.push_back(AgentEvent::ItemCompleted {
                context_id: pending.context_id,
                epoch_id: pending.epoch_id,
                item,
            });
            if self.pending.is_empty() {
                self.drive_provider().await?;
            }
            Ok(())
        })
    }

    fn list_background_processes(
        &mut self,
        _: &AgentContextId,
    ) -> AgentFuture<'_, Vec<AgentProcess>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn terminate_background_process(
        &mut self,
        _: &AgentContextId,
        _: &str,
    ) -> AgentFuture<'_, bool> {
        Box::pin(async { Ok(false) })
    }
    fn shutdown(&mut self) -> AgentFuture<'_, ()> {
        Box::pin(async move {
            if let Some(active) = &self.active {
                active.cancellation.cancel();
            }
            self.active = None;
            self.pending.clear();
            Ok(())
        })
    }
}

fn item_for(item_id: &str, tool: &PreparedNativeTool, cwd: PathBuf) -> AgentItem {
    match tool.effect_kind() {
        ToolEffectKind::Command => AgentItem::Command {
            item_id: item_id.to_owned(),
            command: tool.summary().to_owned(),
            cwd,
            status: "in_progress".to_owned(),
            exit_code: None,
            aggregated_output: None,
            process_id: None,
        },
        ToolEffectKind::Write => AgentItem::FileChange {
            item_id: item_id.to_owned(),
            status: "in_progress".to_owned(),
            changes: json!([]),
        },
        ToolEffectKind::Read => AgentItem::Other {
            item_id: item_id.to_owned(),
            item_type: tool.name().to_owned(),
        },
    }
}

fn complete_item(item: AgentItem, success: bool, output: Option<serde_json::Value>) -> AgentItem {
    match item {
        AgentItem::Command {
            item_id,
            command,
            cwd,
            ..
        } => AgentItem::Command {
            item_id,
            command,
            cwd,
            status: if success { "completed" } else { "failed" }.to_owned(),
            exit_code: output
                .as_ref()
                .and_then(|value| value.get("exit_code"))
                .and_then(serde_json::Value::as_i64)
                .and_then(|value| i32::try_from(value).ok()),
            aggregated_output: output.map(|value| value.to_string()),
            process_id: None,
        },
        AgentItem::FileChange { item_id, .. } => AgentItem::FileChange {
            item_id,
            status: if success { "completed" } else { "failed" }.to_owned(),
            changes: output.map_or_else(|| json!([]), |value| json!([value])),
        },
        AgentItem::Other { item_id, item_type } => AgentItem::Other { item_id, item_type },
        item @ AgentItem::ContextCompaction { .. } => item,
    }
}

fn map_provider_error(error: ProviderError) -> AgentPortError {
    match error {
        ProviderError::Cancelled => {
            AgentPortError::definitely_not_applied(AgentPortErrorCode::Cancelled)
        }
        ProviderError::InvalidRequest { .. } | ProviderError::InvalidFixture { .. } => {
            AgentPortError::definitely_not_applied(AgentPortErrorCode::InvalidRequest)
        }
        ProviderError::InvalidResponse { .. } | ProviderError::ScriptExhausted { .. } => {
            AgentPortError::definitely_not_applied(AgentPortErrorCode::InvalidResponse)
        }
        ProviderError::Authentication { .. }
        | ProviderError::RateLimit { .. }
        | ProviderError::Transport { .. } => {
            AgentPortError::definitely_not_applied(AgentPortErrorCode::Transport)
        }
    }
}

const fn invalid_request() -> AgentPortError {
    AgentPortError::definitely_not_applied(AgentPortErrorCode::InvalidRequest)
}
const fn invalid_response() -> AgentPortError {
    AgentPortError::definitely_not_applied(AgentPortErrorCode::InvalidResponse)
}
