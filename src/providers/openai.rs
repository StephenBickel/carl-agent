use std::collections::{HashMap, HashSet, VecDeque};

use futures_util::{StreamExt, stream};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::catalog::{ProviderCatalog, ProviderKind};
use super::http::{ProviderHttpClient, ProviderHttpError, ProviderHttpErrorCode, SecretCredential};
use super::{
    FinishReason, MessageContent, ModelRequest, Provider, ProviderCapabilities, ProviderError,
    ProviderEvent, ProviderFuture, ProviderStream, Role,
};
use crate::delegates::ModelId;
use crate::events::ToolCallId;

const MAX_INPUT_ITEMS: usize = 4_096;
const MAX_TOOL_CALLS: usize = 128;
const MAX_AGGREGATE_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 256;

pub struct OpenAiProvider {
    client: ProviderHttpClient,
    credential: SecretCredential,
    catalog: ProviderCatalog,
}

impl OpenAiProvider {
    pub fn new(
        client: ProviderHttpClient,
        credential: SecretCredential,
        catalog: ProviderCatalog,
    ) -> Result<Self, ProviderError> {
        if catalog.provider() != ProviderKind::OpenAiApi {
            return Err(invalid_request(
                "OpenAI provider requires an OpenAI API catalog",
            ));
        }
        Ok(Self {
            client,
            credential,
            catalog,
        })
    }

    #[must_use]
    pub const fn catalog(&self) -> &ProviderCatalog {
        &self.catalog
    }

    async fn start_stream(&self, request: ModelRequest) -> Result<ProviderStream, ProviderError> {
        let body = encode_request(&request, &self.catalog)?;
        let incoming = self
            .client
            .post_sse(
                "/v1/responses",
                &self.credential,
                &body,
                request.cancellation.clone(),
            )
            .await
            .map_err(map_http_error)?;
        let state = StreamState {
            incoming,
            codec: ResponsesCodec::default(),
            queued: VecDeque::new(),
            failed: false,
        };
        Ok(Box::pin(stream::unfold(state, next_provider_event)))
    }
}

impl Provider for OpenAiProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        let context_window = self
            .catalog
            .models()
            .iter()
            .find(|model| model.id() == self.catalog.default_model())
            .map(|model| model.context_window());
        ProviderCapabilities {
            streaming: true,
            structured_tool_calls: true,
            parallel_tool_calls: true,
            usage_reporting: true,
            context_window,
        }
    }

    fn stream(&self, request: ModelRequest) -> ProviderFuture<'_> {
        Box::pin(self.start_stream(request))
    }
}

fn encode_request(
    request: &ModelRequest,
    catalog: &ProviderCatalog,
) -> Result<Value, ProviderError> {
    let model_id = ModelId::parse(request.settings.model.clone())
        .map_err(|_| invalid_request("OpenAI model identifier is invalid"))?;
    let model = catalog
        .models()
        .iter()
        .find(|candidate| candidate.id() == &model_id)
        .ok_or_else(|| invalid_request("OpenAI model is not in the configured catalog"))?;
    if let Some(effort) = request.settings.reasoning_effort
        && !model.supported_efforts().contains(&effort)
    {
        return Err(invalid_request(
            "reasoning effort is not supported by the selected model",
        ));
    }
    if request
        .settings
        .temperature
        .is_some_and(|value| !value.is_finite() || !(0.0..=2.0).contains(&value))
        || request.settings.max_output_tokens == Some(0)
    {
        return Err(invalid_request("OpenAI model settings are invalid"));
    }

    let mut call_ids = HashMap::new();
    for message in &request.messages {
        for content in &message.content {
            if let MessageContent::ToolCall {
                tool_call_id,
                provider_call_id,
                ..
            } = content
            {
                let provider_call_id = provider_call_id.as_deref().ok_or_else(|| {
                    invalid_request("OpenAI tool call is missing its provider ID")
                })?;
                validate_identifier(provider_call_id)?;
                if call_ids
                    .insert(*tool_call_id, provider_call_id.to_owned())
                    .is_some()
                {
                    return Err(invalid_request("OpenAI tool call ID is duplicated"));
                }
            }
        }
    }

    let mut input = Vec::new();
    for message in &request.messages {
        let mut text_content = Vec::new();
        for content in &message.content {
            match content {
                MessageContent::Text { text } => {
                    if text.is_empty() || text.len() > MAX_AGGREGATE_OUTPUT_BYTES {
                        return Err(invalid_request("OpenAI message text is invalid"));
                    }
                    let kind = match message.role {
                        Role::Assistant => "output_text",
                        Role::System | Role::User => "input_text",
                        Role::Tool => {
                            return Err(invalid_request("tool messages cannot contain plain text"));
                        }
                    };
                    text_content.push(json!({"type":kind,"text":text}));
                }
                MessageContent::ToolCall {
                    tool_call_id,
                    name,
                    arguments,
                    ..
                } => {
                    if message.role != Role::Assistant || !arguments.is_object() {
                        return Err(invalid_request("OpenAI tool call message is invalid"));
                    }
                    validate_identifier(name)?;
                    input.push(json!({
                        "type":"function_call",
                        "call_id":call_ids.get(tool_call_id).expect("tool call map is complete"),
                        "name":name,
                        "arguments":bounded_json_string(arguments)?,
                    }));
                }
                MessageContent::ToolResult {
                    tool_call_id,
                    output,
                } => {
                    if message.role != Role::Tool {
                        return Err(invalid_request("OpenAI tool result message is invalid"));
                    }
                    let call_id = call_ids.get(tool_call_id).ok_or_else(|| {
                        invalid_request("OpenAI tool result has no matching tool call")
                    })?;
                    input.push(json!({
                        "type":"function_call_output",
                        "call_id":call_id,
                        "output":bounded_json_string(output)?,
                    }));
                }
            }
        }
        if !text_content.is_empty() {
            let role = match message.role {
                Role::System => "developer",
                Role::User => "user",
                Role::Assistant => "assistant",
                Role::Tool => unreachable!("tool text was rejected above"),
            };
            let index = input
                .iter()
                .rposition(|item| item.get("type").is_some())
                .unwrap_or(input.len());
            if message.role == Role::Assistant && index < input.len() {
                input.insert(index, json!({"role":role,"content":text_content}));
            } else {
                input.push(json!({"role":role,"content":text_content}));
            }
        }
        if input.len() > MAX_INPUT_ITEMS {
            return Err(invalid_request("OpenAI request has too many input items"));
        }
    }

    let mut tools = Vec::with_capacity(request.tools.len());
    for tool in &request.tools {
        validate_identifier(&tool.name)?;
        if tool.description.is_empty()
            || tool.description.len() > 4_096
            || !tool.input_schema.is_object()
        {
            return Err(invalid_request("OpenAI tool definition is invalid"));
        }
        tools.push(json!({
            "type":"function",
            "name":tool.name,
            "description":tool.description,
            "parameters":tool.input_schema,
            "strict":true,
        }));
    }
    if tools.len() > MAX_TOOL_CALLS {
        return Err(invalid_request("OpenAI request has too many tools"));
    }

    let mut body = Map::from_iter([
        ("model".to_owned(), json!(request.settings.model)),
        ("store".to_owned(), json!(false)),
        ("stream".to_owned(), json!(true)),
        ("input".to_owned(), Value::Array(input)),
        ("tools".to_owned(), Value::Array(tools)),
    ]);
    if let Some(temperature) = request.settings.temperature {
        body.insert("temperature".to_owned(), json!(temperature));
    }
    if let Some(maximum) = request.settings.max_output_tokens {
        body.insert("max_output_tokens".to_owned(), json!(maximum));
    }
    if let Some(effort) = request.settings.reasoning_effort {
        body.insert(
            "reasoning".to_owned(),
            json!({"effort":effort.as_codex_value()}),
        );
    }
    Ok(Value::Object(body))
}

fn bounded_json_string(value: &Value) -> Result<String, ProviderError> {
    let encoded = serde_json::to_string(value)
        .map_err(|_| invalid_request("OpenAI message JSON is invalid"))?;
    if encoded.len() > MAX_AGGREGATE_OUTPUT_BYTES {
        return Err(invalid_request("OpenAI message JSON is too large"));
    }
    Ok(encoded)
}

fn validate_identifier(value: &str) -> Result<(), ProviderError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(invalid_request("OpenAI identifier is invalid"));
    }
    Ok(())
}

struct StreamState {
    incoming: super::http::ProviderSseStream,
    codec: ResponsesCodec,
    queued: VecDeque<ProviderEvent>,
    failed: bool,
}

async fn next_provider_event(
    mut state: StreamState,
) -> Option<(Result<ProviderEvent, ProviderError>, StreamState)> {
    loop {
        if let Some(event) = state.queued.pop_front() {
            return Some((Ok(event), state));
        }
        if state.failed {
            return None;
        }
        match state.incoming.next().await {
            Some(Ok(frame)) => match state.codec.consume(&frame) {
                Ok(events) => state.queued.extend(events),
                Err(error) => {
                    state.failed = true;
                    return Some((Err(error), state));
                }
            },
            Some(Err(error)) => {
                state.failed = true;
                return Some((Err(map_http_error(error)), state));
            }
            None => {
                if let Err(error) = state.codec.finish() {
                    state.failed = true;
                    return Some((Err(error), state));
                }
                return None;
            }
        }
    }
}

#[derive(Default)]
struct ResponsesCodec {
    calls: HashMap<String, CallAssembly>,
    completed_call_ids: HashSet<String>,
    aggregate_bytes: usize,
    emitted_tools: bool,
    terminal: bool,
    done_marker: bool,
}

struct CallAssembly {
    call_id: String,
    name: String,
    arguments: String,
}

impl ResponsesCodec {
    fn consume(&mut self, frame: &str) -> Result<Vec<ProviderEvent>, ProviderError> {
        if self.done_marker {
            return Err(invalid_response(
                "OpenAI emitted data after the done marker",
            ));
        }
        if frame == "[DONE]" {
            if !self.terminal {
                return Err(invalid_response("OpenAI ended before a terminal response"));
            }
            self.done_marker = true;
            return Ok(Vec::new());
        }
        if self.terminal {
            return Err(invalid_response(
                "OpenAI emitted data after a terminal response",
            ));
        }
        self.aggregate_bytes = self.aggregate_bytes.saturating_add(frame.len());
        if self.aggregate_bytes > MAX_AGGREGATE_OUTPUT_BYTES {
            return Err(invalid_response(
                "OpenAI response exceeded its output limit",
            ));
        }
        let value: Value = serde_json::from_str(frame)
            .map_err(|_| invalid_response("OpenAI response event is malformed"))?;
        let kind = required_str(&value, "type")?;
        match kind {
            "response.created"
            | "response.in_progress"
            | "response.output_text.done"
            | "response.content_part.added"
            | "response.content_part.done"
            | "response.reasoning_summary_part.added"
            | "response.reasoning_summary_part.done"
            | "response.reasoning_summary_text.delta"
            | "response.reasoning_summary_text.done" => Ok(Vec::new()),
            "response.output_text.delta" => {
                let text = required_str(&value, "delta")?;
                if text.is_empty() {
                    return Err(invalid_response("OpenAI emitted an empty text delta"));
                }
                Ok(vec![ProviderEvent::TextDelta {
                    text: text.to_owned(),
                }])
            }
            "response.output_item.added" => {
                let item = required_object(&value, "item")?;
                match required_str_value(item, "type")? {
                    "message" | "reasoning" => return Ok(Vec::new()),
                    "function_call" => {}
                    _ => return Err(invalid_response("OpenAI emitted an unknown output item")),
                }
                let id = required_str_value(item, "id")?;
                let call_id = required_str_value(item, "call_id")?;
                let name = required_str_value(item, "name")?;
                validate_response_identifier(id)?;
                validate_response_identifier(call_id)?;
                validate_response_identifier(name)?;
                if self.calls.len() >= MAX_TOOL_CALLS
                    || self
                        .calls
                        .insert(
                            id.to_owned(),
                            CallAssembly {
                                call_id: call_id.to_owned(),
                                name: name.to_owned(),
                                arguments: String::new(),
                            },
                        )
                        .is_some()
                {
                    return Err(invalid_response("OpenAI duplicated a function call item"));
                }
                Ok(Vec::new())
            }
            "response.function_call_arguments.delta" => {
                let id = required_str(&value, "item_id")?;
                let delta = required_str(&value, "delta")?;
                let call = self.calls.get_mut(id).ok_or_else(|| {
                    invalid_response("OpenAI arguments referenced an unknown function call")
                })?;
                if call.arguments.len().saturating_add(delta.len()) > MAX_AGGREGATE_OUTPUT_BYTES {
                    return Err(invalid_response("OpenAI tool arguments are too large"));
                }
                call.arguments.push_str(delta);
                Ok(Vec::new())
            }
            "response.function_call_arguments.done" => {
                let id = required_str(&value, "item_id")?;
                let arguments = required_str(&value, "arguments")?;
                let call = self.calls.get(id).ok_or_else(|| {
                    invalid_response("OpenAI completed unknown function arguments")
                })?;
                if call.arguments != arguments {
                    return Err(invalid_response("OpenAI function arguments changed"));
                }
                Ok(Vec::new())
            }
            "response.output_item.done" => self.complete_item(&value),
            "response.completed" => self.complete_response(&value, FinishReason::Stop),
            "response.incomplete" => {
                let response = required_object(&value, "response")?;
                let details = response
                    .get("incomplete_details")
                    .and_then(Value::as_object)
                    .ok_or_else(|| invalid_response("OpenAI incomplete details are missing"))?;
                let reason = required_str_value(details, "reason")?;
                let reason = match reason {
                    "max_output_tokens" => FinishReason::Length,
                    "content_filter" => FinishReason::ContentFilter,
                    _ => return Err(invalid_response("OpenAI incomplete reason is unknown")),
                };
                self.complete_response(&value, reason)
            }
            "error" | "response.failed" => {
                Err(invalid_response("OpenAI reported a provider error"))
            }
            _ => Err(invalid_response("OpenAI response event type is unknown")),
        }
    }

    fn complete_item(&mut self, value: &Value) -> Result<Vec<ProviderEvent>, ProviderError> {
        let item = required_object(value, "item")?;
        match required_str_value(item, "type")? {
            "message" | "reasoning" => return Ok(Vec::new()),
            "function_call" => {}
            _ => return Err(invalid_response("OpenAI completed an unknown output item")),
        }
        let id = required_str_value(item, "id")?;
        let call_id = required_str_value(item, "call_id")?;
        let name = required_str_value(item, "name")?;
        let arguments = required_str_value(item, "arguments")?;
        validate_response_identifier(id)?;
        validate_response_identifier(call_id)?;
        validate_response_identifier(name)?;
        if !self.completed_call_ids.insert(call_id.to_owned()) {
            return Err(invalid_response("OpenAI duplicated a provider call ID"));
        }
        if let Some(assembly) = self.calls.remove(id)
            && (assembly.call_id != call_id
                || assembly.name != name
                || assembly.arguments != arguments)
        {
            return Err(invalid_response("OpenAI function call fields changed"));
        }
        let arguments: Value = serde_json::from_str(arguments)
            .map_err(|_| invalid_response("OpenAI tool arguments are malformed"))?;
        if !arguments.is_object() {
            return Err(invalid_response("OpenAI tool arguments are not an object"));
        }
        self.emitted_tools = true;
        Ok(vec![ProviderEvent::ToolCall {
            tool_call_id: normalized_tool_call_id(call_id),
            provider_call_id: Some(call_id.to_owned()),
            name: name.to_owned(),
            arguments,
        }])
    }

    fn complete_response(
        &mut self,
        value: &Value,
        default_reason: FinishReason,
    ) -> Result<Vec<ProviderEvent>, ProviderError> {
        if !self.calls.is_empty() || self.terminal {
            return Err(invalid_response("OpenAI response terminated ambiguously"));
        }
        let response = required_object(value, "response")?;
        let usage = response
            .get("usage")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_response("OpenAI response usage is missing"))?;
        let input_tokens = required_u64(usage, "input_tokens")?;
        let output_tokens = required_u64(usage, "output_tokens")?;
        self.terminal = true;
        let reason = if self.emitted_tools && default_reason == FinishReason::Stop {
            FinishReason::ToolCalls
        } else {
            default_reason
        };
        Ok(vec![
            ProviderEvent::Usage {
                input_tokens,
                output_tokens,
            },
            ProviderEvent::Finish { reason },
        ])
    }

    fn finish(&self) -> Result<(), ProviderError> {
        if self.terminal && self.done_marker {
            Ok(())
        } else {
            Err(invalid_response(
                "OpenAI stream ended without a terminal marker",
            ))
        }
    }
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, ProviderError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_response("OpenAI response field is invalid"))
}

fn required_object<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a Map<String, Value>, ProviderError> {
    value
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_response("OpenAI response object is invalid"))
}

fn required_str_value<'a>(
    value: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, ProviderError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_response("OpenAI response field is invalid"))
}

fn required_u64(value: &Map<String, Value>, field: &str) -> Result<u64, ProviderError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_response("OpenAI usage field is invalid"))
}

fn validate_response_identifier(value: &str) -> Result<(), ProviderError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        Err(invalid_response("OpenAI response identifier is invalid"))
    } else {
        Ok(())
    }
}

fn normalized_tool_call_id(provider_call_id: &str) -> ToolCallId {
    let digest =
        Sha256::digest([b"carl:openai:call:".as_slice(), provider_call_id.as_bytes()].concat());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ToolCallId::from_uuid(Uuid::from_bytes(bytes))
}

fn map_http_error(error: ProviderHttpError) -> ProviderError {
    match error.code() {
        ProviderHttpErrorCode::Authentication => ProviderError::Authentication {
            detail: "OpenAI authentication failed".to_owned(),
        },
        ProviderHttpErrorCode::RateLimit => ProviderError::RateLimit {
            detail: "OpenAI rate limit reached".to_owned(),
            retry_after_millis: None,
        },
        ProviderHttpErrorCode::InvalidRequest => ProviderError::InvalidRequest {
            detail: "OpenAI request was rejected".to_owned(),
        },
        ProviderHttpErrorCode::InvalidResponse => ProviderError::InvalidResponse {
            detail: "OpenAI response was invalid".to_owned(),
        },
        ProviderHttpErrorCode::Transport => ProviderError::Transport {
            detail: "OpenAI transport failed".to_owned(),
        },
        ProviderHttpErrorCode::Cancelled => ProviderError::Cancelled,
    }
}

fn invalid_request(detail: &'static str) -> ProviderError {
    ProviderError::InvalidRequest {
        detail: detail.to_owned(),
    }
}

fn invalid_response(detail: &'static str) -> ProviderError {
    ProviderError::InvalidResponse {
        detail: detail.to_owned(),
    }
}
