use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use futures_util::{StreamExt, stream};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::catalog::{ProviderCatalog, ProviderKind, ProviderModel};
use super::http::{ProviderHttpClient, ProviderHttpError, ProviderHttpErrorCode, SecretCredential};
use super::{
    FinishReason, MessageContent, ModelRequest, Provider, ProviderCapabilities, ProviderError,
    ProviderEvent, ProviderFuture, ProviderStream, Role,
};
use crate::delegates::{ModelId, ReasoningEffort};
use crate::events::ToolCallId;

const OPENROUTER_HEADERS: [(&str, &str); 2] = [
    (
        "http-referer",
        "https://github.com/StephenBickel/carl-agent",
    ),
    ("x-title", "Carl"),
];
const MAX_DISCOVERY_BYTES: usize = 2 * 1024 * 1024;
const MAX_DISCOVERY_MODELS: usize = 512;
const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOOL_CALLS: usize = 128;
const MAX_IDENTIFIER_BYTES: usize = 256;

pub struct OpenRouterProvider {
    client: ProviderHttpClient,
    credential: SecretCredential,
    catalog: ProviderCatalog,
    reasoning_models: HashSet<String>,
}

impl OpenRouterProvider {
    pub async fn discover(
        client: ProviderHttpClient,
        credential: SecretCredential,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<Self, ProviderError> {
        let response = client
            .get_json(
                "/api/v1/models?supported_parameters=tools&output_modalities=text",
                &credential,
                &OPENROUTER_HEADERS,
                cancellation,
            )
            .await
            .map_err(map_http_error)?;
        Self::from_models_response(client, credential, response)
    }

    pub fn from_models_response(
        client: ProviderHttpClient,
        credential: SecretCredential,
        response: Value,
    ) -> Result<Self, ProviderError> {
        let encoded = serde_json::to_vec(&response)
            .map_err(|_| invalid_response("OpenRouter model response is malformed"))?;
        if encoded.len() > MAX_DISCOVERY_BYTES {
            return Err(invalid_response("OpenRouter model response is too large"));
        }
        let entries = response
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_response("OpenRouter model list is missing"))?;
        if entries.len() > MAX_DISCOVERY_MODELS {
            return Err(invalid_response("OpenRouter returned too many models"));
        }

        let mut models = Vec::new();
        let mut reasoning_models = HashSet::new();
        for entry in entries {
            let Some(object) = entry.as_object() else {
                return Err(invalid_response("OpenRouter model entry is invalid"));
            };
            let Some(id) = object.get("id").and_then(Value::as_str) else {
                return Err(invalid_response("OpenRouter model identifier is missing"));
            };
            let Ok(id) = ModelId::parse(id) else { continue };
            let name = object
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(id.as_str());
            let Some(context) = object.get("context_length").and_then(Value::as_u64) else {
                continue;
            };
            let Some(parameters) = string_set(object.get("supported_parameters")) else {
                continue;
            };
            let architecture = object.get("architecture").and_then(Value::as_object);
            let Some(input) =
                architecture.and_then(|value| string_set(value.get("input_modalities")))
            else {
                continue;
            };
            let Some(output) =
                architecture.and_then(|value| string_set(value.get("output_modalities")))
            else {
                continue;
            };
            if !parameters.contains("tools") || !input.contains("text") || !output.contains("text")
            {
                continue;
            }
            let supports_reasoning = parameters.contains("reasoning");
            let efforts = if supports_reasoning {
                vec![
                    ReasoningEffort::Low,
                    ReasoningEffort::Medium,
                    ReasoningEffort::High,
                ]
            } else {
                vec![ReasoningEffort::Medium]
            };
            let Ok(model) = ProviderModel::new(
                id.clone(),
                name.to_owned(),
                context,
                efforts,
                ReasoningEffort::Medium,
                true,
                true,
                true,
            ) else {
                continue;
            };
            if supports_reasoning {
                reasoning_models.insert(id.as_str().to_owned());
            }
            models.push(model);
        }
        models.sort_by(|left, right| left.id().as_str().cmp(right.id().as_str()));
        let default_model = models
            .first()
            .map(|model| model.id().clone())
            .ok_or_else(|| invalid_response("OpenRouter returned no compatible coding models"))?;
        let catalog = ProviderCatalog::new(ProviderKind::OpenRouter, models, default_model)
            .map_err(|_| invalid_response("OpenRouter model catalog is invalid"))?;
        Ok(Self {
            client,
            credential,
            catalog,
            reasoning_models,
        })
    }

    #[must_use]
    pub const fn catalog(&self) -> &ProviderCatalog {
        &self.catalog
    }

    async fn start_stream(&self, request: ModelRequest) -> Result<ProviderStream, ProviderError> {
        let body = encode_request(&request, &self.catalog, &self.reasoning_models)?;
        let incoming = self
            .client
            .post_sse_with_headers(
                "/api/v1/chat/completions",
                &self.credential,
                &body,
                &OPENROUTER_HEADERS,
                request.cancellation.clone(),
            )
            .await
            .map_err(map_http_error)?;
        let state = RouterStreamState {
            incoming,
            codec: ChatCodec::default(),
            queued: VecDeque::new(),
            failed: false,
        };
        Ok(Box::pin(stream::unfold(state, next_provider_event)))
    }
}

impl Provider for OpenRouterProvider {
    fn capabilities(&self) -> ProviderCapabilities {
        let context_window = self
            .catalog
            .models()
            .iter()
            .find(|model| model.id() == self.catalog.default_model())
            .map(ProviderModel::context_window);
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

fn string_set(value: Option<&Value>) -> Option<HashSet<&str>> {
    value?
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect::<Option<HashSet<_>>>()
}

fn encode_request(
    request: &ModelRequest,
    catalog: &ProviderCatalog,
    reasoning_models: &HashSet<String>,
) -> Result<Value, ProviderError> {
    let model_id = ModelId::parse(request.settings.model.clone())
        .map_err(|_| invalid_request("OpenRouter model identifier is invalid"))?;
    if !catalog.models().iter().any(|model| model.id() == &model_id) {
        return Err(invalid_request("OpenRouter model is not in the catalog"));
    }
    if request.settings.reasoning_effort.is_some() && !reasoning_models.contains(model_id.as_str())
    {
        return Err(invalid_request(
            "OpenRouter model does not advertise reasoning",
        ));
    }

    let mut known_calls = HashMap::new();
    for message in &request.messages {
        for content in &message.content {
            if let MessageContent::ToolCall {
                tool_call_id,
                provider_call_id,
                ..
            } = content
            {
                let provider_id = provider_call_id.as_deref().ok_or_else(|| {
                    invalid_request("OpenRouter tool call is missing provider ID")
                })?;
                validate_identifier(provider_id, true)?;
                if known_calls
                    .insert(*tool_call_id, provider_id.to_owned())
                    .is_some()
                {
                    return Err(invalid_request("OpenRouter tool call is duplicated"));
                }
            }
        }
    }

    let mut messages = Vec::new();
    for message in &request.messages {
        let mut text = String::new();
        let mut tool_calls = Vec::new();
        for content in &message.content {
            match content {
                MessageContent::Text { text: part } => {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(part);
                }
                MessageContent::ToolCall {
                    tool_call_id,
                    name,
                    arguments,
                    ..
                } => {
                    if message.role != Role::Assistant || !arguments.is_object() {
                        return Err(invalid_request("OpenRouter tool call message is invalid"));
                    }
                    validate_identifier(name, false)?;
                    tool_calls.push(json!({
                        "id": known_calls.get(tool_call_id).expect("known call map is complete"),
                        "type":"function",
                        "function":{"name":name,"arguments":bounded_json(arguments)?}
                    }));
                }
                MessageContent::ToolResult {
                    tool_call_id,
                    output,
                } => {
                    if message.role != Role::Tool || message.content.len() != 1 {
                        return Err(invalid_request("OpenRouter tool result message is invalid"));
                    }
                    messages.push(json!({
                        "role":"tool",
                        "tool_call_id":known_calls.get(tool_call_id).ok_or_else(|| invalid_request("OpenRouter tool result has no call"))?,
                        "content":bounded_json(output)?
                    }));
                }
            }
        }
        if message.role != Role::Tool {
            let role = match message.role {
                Role::System => "system",
                Role::User => "user",
                Role::Assistant => "assistant",
                Role::Tool => unreachable!(),
            };
            let mut encoded = Map::new();
            encoded.insert("role".to_owned(), json!(role));
            encoded.insert("content".to_owned(), json!(text));
            if !tool_calls.is_empty() {
                encoded.insert("tool_calls".to_owned(), Value::Array(tool_calls));
            }
            messages.push(Value::Object(encoded));
        }
    }

    let mut tools = Vec::new();
    for tool in &request.tools {
        validate_identifier(&tool.name, false)?;
        if tool.description.is_empty() || !tool.input_schema.is_object() {
            return Err(invalid_request("OpenRouter tool definition is invalid"));
        }
        tools.push(json!({
            "type":"function",
            "function":{
                "name":tool.name,"description":tool.description,
                "parameters":tool.input_schema,"strict":true
            }
        }));
    }
    if tools.len() > MAX_TOOL_CALLS {
        return Err(invalid_request("OpenRouter request has too many tools"));
    }
    let mut body = Map::from_iter([
        ("model".to_owned(), json!(request.settings.model)),
        ("messages".to_owned(), Value::Array(messages)),
        ("tools".to_owned(), Value::Array(tools)),
        ("stream".to_owned(), json!(true)),
        ("stream_options".to_owned(), json!({"include_usage":true})),
    ]);
    if let Some(value) = request.settings.temperature {
        if !value.is_finite() || !(0.0..=2.0).contains(&value) {
            return Err(invalid_request("OpenRouter temperature is invalid"));
        }
        body.insert("temperature".to_owned(), json!(value));
    }
    if let Some(value) = request.settings.max_output_tokens {
        if value == 0 {
            return Err(invalid_request("OpenRouter output limit is invalid"));
        }
        body.insert("max_tokens".to_owned(), json!(value));
    }
    if let Some(effort) = request.settings.reasoning_effort {
        body.insert(
            "reasoning".to_owned(),
            json!({"effort":effort.as_codex_value()}),
        );
    }
    Ok(Value::Object(body))
}

fn bounded_json(value: &Value) -> Result<String, ProviderError> {
    let encoded = serde_json::to_string(value)
        .map_err(|_| invalid_request("OpenRouter message JSON is invalid"))?;
    if encoded.len() > MAX_STREAM_BYTES {
        return Err(invalid_request("OpenRouter message JSON is too large"));
    }
    Ok(encoded)
}

fn validate_identifier(value: &str, provider: bool) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || (!provider
            && !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
    {
        return Err(invalid_request("OpenRouter identifier is invalid"));
    }
    Ok(())
}

struct RouterStreamState {
    incoming: super::http::ProviderSseStream,
    codec: ChatCodec,
    queued: VecDeque<ProviderEvent>,
    failed: bool,
}

async fn next_provider_event(
    mut state: RouterStreamState,
) -> Option<(Result<ProviderEvent, ProviderError>, RouterStreamState)> {
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
struct ChatCodec {
    calls: BTreeMap<usize, ChatCall>,
    usage: Option<(u64, u64)>,
    finish_reason: Option<FinishReason>,
    bytes: usize,
    done: bool,
}

#[derive(Default)]
struct ChatCall {
    id: Option<String>,
    name: Option<String>,
    arguments: String,
}

impl ChatCodec {
    fn consume(&mut self, frame: &str) -> Result<Vec<ProviderEvent>, ProviderError> {
        if self.done {
            return Err(invalid_response("OpenRouter emitted data after completion"));
        }
        if frame == "[DONE]" {
            return self.complete();
        }
        self.bytes = self.bytes.saturating_add(frame.len());
        if self.bytes > MAX_STREAM_BYTES {
            return Err(invalid_response("OpenRouter response is too large"));
        }
        let value: Value = serde_json::from_str(frame)
            .map_err(|_| invalid_response("OpenRouter stream JSON is malformed"))?;
        if value.get("error").is_some() {
            return Err(invalid_response("OpenRouter reported a provider error"));
        }
        if let Some(usage) = value.get("usage") {
            if self.usage.is_some() {
                return Err(invalid_response("OpenRouter duplicated usage"));
            }
            self.usage = Some((
                required_u64(usage, "prompt_tokens")?,
                required_u64(usage, "completion_tokens")?,
            ));
        }
        let choices = value
            .get("choices")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_response("OpenRouter choices are missing"))?;
        if choices.is_empty() {
            return Ok(Vec::new());
        }
        if choices.len() != 1 || choices[0].get("index").and_then(Value::as_u64) != Some(0) {
            return Err(invalid_response("OpenRouter choice index is invalid"));
        }
        let choice = &choices[0];
        let delta = choice
            .get("delta")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_response("OpenRouter choice delta is invalid"))?;
        let mut events = Vec::new();
        if let Some(content) = delta.get("content") {
            let content = content
                .as_str()
                .ok_or_else(|| invalid_response("OpenRouter text delta is invalid"))?;
            if !content.is_empty() {
                events.push(ProviderEvent::TextDelta {
                    text: content.to_owned(),
                });
            }
        }
        if let Some(tool_calls) = delta.get("tool_calls") {
            let tool_calls = tool_calls
                .as_array()
                .ok_or_else(|| invalid_response("OpenRouter tool deltas are invalid"))?;
            for delta in tool_calls {
                self.consume_tool_delta(delta)?;
            }
        }
        if let Some(reason) = choice.get("finish_reason").filter(|value| !value.is_null()) {
            if self.finish_reason.is_some() {
                return Err(invalid_response("OpenRouter duplicated finish reason"));
            }
            self.finish_reason = Some(match reason.as_str() {
                Some("stop") => FinishReason::Stop,
                Some("tool_calls") => FinishReason::ToolCalls,
                Some("length") => FinishReason::Length,
                Some("content_filter") => FinishReason::ContentFilter,
                _ => return Err(invalid_response("OpenRouter finish reason is unknown")),
            });
        }
        Ok(events)
    }

    fn consume_tool_delta(&mut self, value: &Value) -> Result<(), ProviderError> {
        let index = value
            .get("index")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(|| invalid_response("OpenRouter tool index is invalid"))?;
        if index >= MAX_TOOL_CALLS || index > self.calls.len() {
            return Err(invalid_response(
                "OpenRouter tool indices are not contiguous",
            ));
        }
        let call = self.calls.entry(index).or_default();
        if let Some(id) = value.get("id").and_then(Value::as_str) {
            bind_once(&mut call.id, id, "OpenRouter tool ID changed")?;
        }
        if let Some(kind) = value.get("type").and_then(Value::as_str)
            && kind != "function"
        {
            return Err(invalid_response("OpenRouter tool type is unknown"));
        }
        if let Some(function) = value.get("function") {
            let function = function
                .as_object()
                .ok_or_else(|| invalid_response("OpenRouter tool function is invalid"))?;
            if let Some(name) = function.get("name").and_then(Value::as_str) {
                bind_once(&mut call.name, name, "OpenRouter tool name changed")?;
            }
            if let Some(arguments) = function.get("arguments").and_then(Value::as_str) {
                if call.arguments.len().saturating_add(arguments.len()) > MAX_STREAM_BYTES {
                    return Err(invalid_response("OpenRouter tool arguments are too large"));
                }
                call.arguments.push_str(arguments);
            }
        }
        Ok(())
    }

    fn complete(&mut self) -> Result<Vec<ProviderEvent>, ProviderError> {
        let reason = self
            .finish_reason
            .ok_or_else(|| invalid_response("OpenRouter finish reason is missing"))?;
        let (input_tokens, output_tokens) = self
            .usage
            .ok_or_else(|| invalid_response("OpenRouter usage is missing"))?;
        if (reason == FinishReason::ToolCalls) != !self.calls.is_empty() {
            return Err(invalid_response("OpenRouter tool finish is inconsistent"));
        }
        let mut events = Vec::new();
        for (_, call) in std::mem::take(&mut self.calls) {
            let id = call
                .id
                .ok_or_else(|| invalid_response("OpenRouter tool ID is missing"))?;
            let name = call
                .name
                .ok_or_else(|| invalid_response("OpenRouter tool name is missing"))?;
            validate_response_identifier(&id)?;
            validate_response_identifier(&name)?;
            let arguments: Value = serde_json::from_str(&call.arguments)
                .map_err(|_| invalid_response("OpenRouter tool arguments are malformed"))?;
            if !arguments.is_object() {
                return Err(invalid_response(
                    "OpenRouter tool arguments are not an object",
                ));
            }
            events.push(ProviderEvent::ToolCall {
                tool_call_id: normalized_tool_call_id(&id),
                provider_call_id: Some(id),
                name,
                arguments,
            });
        }
        events.push(ProviderEvent::Usage {
            input_tokens,
            output_tokens,
        });
        events.push(ProviderEvent::Finish { reason });
        self.done = true;
        Ok(events)
    }

    fn finish(&self) -> Result<(), ProviderError> {
        if self.done {
            Ok(())
        } else {
            Err(invalid_response("OpenRouter stream ended without done"))
        }
    }
}

fn bind_once(
    slot: &mut Option<String>,
    value: &str,
    error: &'static str,
) -> Result<(), ProviderError> {
    if let Some(existing) = slot {
        if existing != value {
            return Err(invalid_response(error));
        }
    } else {
        *slot = Some(value.to_owned());
    }
    Ok(())
}

fn required_u64(value: &Value, field: &str) -> Result<u64, ProviderError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_response("OpenRouter usage field is invalid"))
}

fn validate_response_identifier(value: &str) -> Result<(), ProviderError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        Err(invalid_response(
            "OpenRouter response identifier is invalid",
        ))
    } else {
        Ok(())
    }
}

fn normalized_tool_call_id(provider_call_id: &str) -> ToolCallId {
    let digest = Sha256::digest(
        [
            b"carl:openrouter:call:".as_slice(),
            provider_call_id.as_bytes(),
        ]
        .concat(),
    );
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ToolCallId::from_uuid(Uuid::from_bytes(bytes))
}

fn map_http_error(error: ProviderHttpError) -> ProviderError {
    match error.code() {
        ProviderHttpErrorCode::Authentication => ProviderError::Authentication {
            detail: "OpenRouter authentication failed".to_owned(),
        },
        ProviderHttpErrorCode::RateLimit => ProviderError::RateLimit {
            detail: "OpenRouter rate limit reached".to_owned(),
            retry_after_millis: None,
        },
        ProviderHttpErrorCode::Transport => ProviderError::Transport {
            detail: "OpenRouter transport failed".to_owned(),
        },
        ProviderHttpErrorCode::InvalidRequest => ProviderError::InvalidRequest {
            detail: "OpenRouter request was rejected".to_owned(),
        },
        ProviderHttpErrorCode::InvalidResponse => ProviderError::InvalidResponse {
            detail: "OpenRouter response was invalid".to_owned(),
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
