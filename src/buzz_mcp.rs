//! Restricted MCP surface for Buzz publication.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;

use serde_json::{Map, Value, json};
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use crate::acp::{
    AcpError, BuzzContext, BuzzError, BuzzPublisher, OutgoingFrame, read_frame, write_frame,
};

const MCP_FRAME_LIMIT: usize = 1_048_576;
const MAX_TOOL_CONTENT_BYTES: usize = 256 * 1024;

pub trait BuzzToolBackend: Send + Sync {
    fn send_message<'a>(
        &'a self,
        context: &'a BuzzContext,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BuzzError>> + Send + 'a>>;

    fn send_diff<'a>(
        &'a self,
        context: &'a BuzzContext,
        diff: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BuzzError>> + Send + 'a>>;
}

impl BuzzToolBackend for BuzzPublisher {
    fn send_message<'a>(
        &'a self,
        context: &'a BuzzContext,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BuzzError>> + Send + 'a>> {
        Box::pin(async move {
            self.send_message(context, content, CancellationToken::new())
                .await
        })
    }

    fn send_diff<'a>(
        &'a self,
        context: &'a BuzzContext,
        diff: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), BuzzError>> + Send + 'a>> {
        Box::pin(async move {
            self.send_diff(context, diff, CancellationToken::new())
                .await
        })
    }
}

#[derive(Debug, Error)]
#[error("Buzz MCP transport failed")]
pub struct BuzzMcpError;

impl From<AcpError> for BuzzMcpError {
    fn from(_: AcpError) -> Self {
        Self
    }
}

pub async fn run_stdio<R, W, B>(
    reader: &mut R,
    writer: &mut W,
    backend: &B,
) -> Result<(), BuzzMcpError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    B: BuzzToolBackend,
{
    while let Some(frame) = read_frame(reader, MCP_FRAME_LIMIT).await? {
        let method = frame.method().ok_or(BuzzMcpError)?;
        let Some(id) = frame.id().cloned() else {
            if method == "notifications/initialized" {
                continue;
            }
            return Err(BuzzMcpError);
        };
        let response = match method {
            "initialize" => OutgoingFrame::result(id, initialize_result()),
            "tools/list" => OutgoingFrame::result(id, tools_result()),
            "tools/call" => match call_tool(frame.value(), backend).await {
                Ok(result) => OutgoingFrame::result(id, result),
                Err(code) => OutgoingFrame::error(id, code, error_message(code)),
            },
            _ => OutgoingFrame::error(id, -32601, "method not found"),
        };
        write_frame(writer, &response, MCP_FRAME_LIMIT).await?;
    }
    Ok(())
}

async fn call_tool<B: BuzzToolBackend>(frame: &Value, backend: &B) -> Result<Value, i64> {
    let params = frame
        .get("params")
        .and_then(Value::as_object)
        .ok_or(-32602)?;
    require_keys(params, &["name", "arguments"]).map_err(|()| -32602)?;
    let name = params.get("name").and_then(Value::as_str).ok_or(-32602)?;
    let arguments = params
        .get("arguments")
        .and_then(Value::as_object)
        .ok_or(-32602)?;
    let content_key = match name {
        "send_message" => "content",
        "send_diff" => "diff",
        _ => return Err(-32602),
    };
    require_keys(
        arguments,
        &["channel_id", "reply_to", "actor_hex", content_key],
    )
    .map_err(|()| -32602)?;
    let context = BuzzContext::from_transport(
        string_argument(arguments, "channel_id")?,
        string_argument(arguments, "reply_to")?,
        string_argument(arguments, "actor_hex")?,
    )
    .map_err(|_| -32602)?;
    let content = string_argument(arguments, content_key)?;
    if content.is_empty()
        || content.len() > MAX_TOOL_CONTENT_BYTES
        || content.as_bytes().contains(&0)
    {
        return Err(-32602);
    }
    let result = match name {
        "send_message" => backend.send_message(&context, content).await,
        "send_diff" => backend.send_diff(&context, content).await,
        _ => unreachable!("tool name was matched above"),
    };
    Ok(match result {
        Ok(()) => json!({
            "content": [{"type": "text", "text": "sent"}],
            "isError": false,
        }),
        Err(_) => json!({
            "content": [{"type": "text", "text": "publication failed"}],
            "isError": true,
        }),
    })
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "carl-buzz-mcp", "version": env!("CARGO_PKG_VERSION")},
    })
}

fn tools_result() -> Value {
    json!({
        "tools": [
            tool_schema("send_message", "Publish a message to the current Buzz conversation", "content"),
            tool_schema("send_diff", "Publish a diff to the current Buzz conversation", "diff"),
        ]
    })
}

fn tool_schema(name: &str, description: &str, content_key: &str) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel_id": {"type": "string", "format": "uuid"},
                "reply_to": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "actor_hex": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                (content_key): {"type": "string", "minLength": 1, "maxLength": MAX_TOOL_CONTENT_BYTES},
            },
            "required": ["channel_id", "reply_to", "actor_hex", content_key],
            "additionalProperties": false,
        }
    })
}

fn string_argument<'a>(arguments: &'a Map<String, Value>, name: &str) -> Result<&'a str, i64> {
    arguments.get(name).and_then(Value::as_str).ok_or(-32602)
}

fn require_keys(object: &Map<String, Value>, required: &[&str]) -> Result<(), ()> {
    let actual = object.keys().map(String::as_str).collect::<HashSet<_>>();
    let required = required.iter().copied().collect::<HashSet<_>>();
    if actual == required { Ok(()) } else { Err(()) }
}

const fn error_message(code: i64) -> &'static str {
    match code {
        -32602 => "invalid params",
        _ => "internal error",
    }
}
