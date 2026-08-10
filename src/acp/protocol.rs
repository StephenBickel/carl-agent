use std::collections::HashSet;
use std::fmt;

use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value, json};
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

const MAX_JSON_RPC_STRING_BYTES: usize = 128;
const MAX_ACP_FRAME_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AcpErrorCode {
    #[error("ACP protocol violation")]
    ProtocolViolation,
    #[error("ACP frame exceeds its configured limit")]
    FrameTooLarge,
    #[error("ACP transport failed")]
    Transport,
}

#[derive(Debug, Error)]
#[error("{code}")]
pub struct AcpError {
    code: AcpErrorCode,
}

impl AcpError {
    #[must_use]
    pub const fn code(&self) -> AcpErrorCode {
        self.code
    }

    const fn from_code(code: AcpErrorCode) -> Self {
        Self { code }
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct BoundedJsonRpcString(String);

impl BoundedJsonRpcString {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for BoundedJsonRpcString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundedJsonRpcString(<redacted>)")
    }
}

impl TryFrom<&str> for BoundedJsonRpcString {
    type Error = AcpError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.to_owned())
    }
}

impl TryFrom<String> for BoundedJsonRpcString {
    type Error = AcpError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > MAX_JSON_RPC_STRING_BYTES
            || value.as_bytes().contains(&0)
        {
            return Err(AcpError::from_code(AcpErrorCode::ProtocolViolation));
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum JsonRpcId {
    Number(u64),
    String(BoundedJsonRpcString),
}

impl JsonRpcId {
    fn from_value(value: &Value) -> Result<Self, AcpError> {
        if let Some(number) = value.as_u64() {
            return Ok(Self::Number(number));
        }
        if let Some(string) = value.as_str() {
            return Ok(Self::String(string.try_into()?));
        }
        Err(AcpError::from_code(AcpErrorCode::ProtocolViolation))
    }

    fn to_value(&self) -> Value {
        match self {
            Self::Number(number) => Value::Number((*number).into()),
            Self::String(string) => Value::String(string.0.clone()),
        }
    }
}

pub struct IncomingFrame {
    value: Value,
    id: Option<JsonRpcId>,
    method: Option<String>,
}

impl fmt::Debug for IncomingFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IncomingFrame")
            .field("id", &self.id)
            .field("method", &self.method)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl IncomingFrame {
    fn parse(value: Value) -> Result<Self, AcpError> {
        let object = value
            .as_object()
            .ok_or_else(|| AcpError::from_code(AcpErrorCode::ProtocolViolation))?;
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Err(AcpError::from_code(AcpErrorCode::ProtocolViolation));
        }

        let id = object.get("id").map(JsonRpcId::from_value).transpose()?;
        let method = object
            .get("method")
            .map(|method| {
                let method = method
                    .as_str()
                    .ok_or_else(|| AcpError::from_code(AcpErrorCode::ProtocolViolation))?;
                validate_method(method)?;
                Ok::<_, AcpError>(method.to_owned())
            })
            .transpose()?;
        let has_result = object.contains_key("result");
        let has_error = object.contains_key("error");

        if method.is_some() {
            if has_result || has_error {
                return Err(AcpError::from_code(AcpErrorCode::ProtocolViolation));
            }
            if let Some(params) = object.get("params")
                && !params.is_object()
                && !params.is_array()
            {
                return Err(AcpError::from_code(AcpErrorCode::ProtocolViolation));
            }
        } else if id.is_none() || !(has_result ^ has_error) || object.contains_key("params") {
            return Err(AcpError::from_code(AcpErrorCode::ProtocolViolation));
        }

        Ok(Self { value, id, method })
    }

    #[must_use]
    pub const fn id(&self) -> Option<&JsonRpcId> {
        self.id.as_ref()
    }

    #[must_use]
    pub fn method(&self) -> Option<&str> {
        self.method.as_deref()
    }

    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }

    #[must_use]
    pub fn into_value(self) -> Value {
        self.value
    }
}

pub struct OutgoingFrame {
    value: Value,
}

impl fmt::Debug for OutgoingFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OutgoingFrame(<redacted>)")
    }
}

impl OutgoingFrame {
    #[must_use]
    pub fn result(id: JsonRpcId, result: Value) -> Self {
        Self {
            value: json!({"jsonrpc": "2.0", "id": id.to_value(), "result": result}),
        }
    }

    #[must_use]
    pub fn error(id: JsonRpcId, code: i64, message: &str) -> Self {
        let message =
            if message.is_empty() || message.len() > 256 || message.as_bytes().contains(&0) {
                "protocol error"
            } else {
                message
            };
        Self {
            value: json!({
                "jsonrpc": "2.0",
                "id": id.to_value(),
                "error": {"code": code, "message": message},
            }),
        }
    }

    pub fn notification(method: &str, params: Value) -> Result<Self, AcpError> {
        validate_method(method)?;
        if !params.is_object() && !params.is_array() {
            return Err(AcpError::from_code(AcpErrorCode::ProtocolViolation));
        }
        Ok(Self {
            value: json!({"jsonrpc": "2.0", "method": method, "params": params}),
        })
    }

    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }
}

pub async fn read_frame<R>(
    reader: &mut R,
    maximum_bytes: usize,
) -> Result<Option<IncomingFrame>, AcpError>
where
    R: AsyncBufRead + Unpin,
{
    if maximum_bytes == 0 || maximum_bytes > MAX_ACP_FRAME_BYTES {
        return Err(AcpError::from_code(AcpErrorCode::FrameTooLarge));
    }
    let mut bytes = Vec::with_capacity(maximum_bytes.min(8 * 1_024));
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|_| AcpError::from_code(AcpErrorCode::Transport))?;
        if available.is_empty() {
            if bytes.is_empty() {
                return Ok(None);
            }
            return Err(AcpError::from_code(AcpErrorCode::ProtocolViolation));
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let wanted = newline.map_or(available.len(), |position| position + 1);
        let remaining = maximum_bytes.saturating_add(1).saturating_sub(bytes.len());
        let consumed = wanted.min(remaining);
        bytes.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);
        if bytes.len() > maximum_bytes {
            return Err(AcpError::from_code(AcpErrorCode::FrameTooLarge));
        }
        if newline.is_some() && consumed == wanted {
            break;
        }
        if consumed < wanted {
            return Err(AcpError::from_code(AcpErrorCode::FrameTooLarge));
        }
    }

    if bytes == *b"\n" {
        return Err(AcpError::from_code(AcpErrorCode::ProtocolViolation));
    }
    bytes.pop();
    let value = parse_strict_json(&bytes)?;
    IncomingFrame::parse(value).map(Some)
}

pub async fn write_frame<W>(
    writer: &mut W,
    frame: &OutgoingFrame,
    maximum_bytes: usize,
) -> Result<(), AcpError>
where
    W: AsyncWrite + Unpin,
{
    if maximum_bytes == 0 || maximum_bytes > MAX_ACP_FRAME_BYTES {
        return Err(AcpError::from_code(AcpErrorCode::FrameTooLarge));
    }
    let mut bytes = serde_json::to_vec(frame.value())
        .map_err(|_| AcpError::from_code(AcpErrorCode::ProtocolViolation))?;
    let encoded_len = bytes
        .len()
        .checked_add(1)
        .ok_or_else(|| AcpError::from_code(AcpErrorCode::FrameTooLarge))?;
    if encoded_len > maximum_bytes {
        return Err(AcpError::from_code(AcpErrorCode::FrameTooLarge));
    }
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|_| AcpError::from_code(AcpErrorCode::Transport))?;
    writer
        .flush()
        .await
        .map_err(|_| AcpError::from_code(AcpErrorCode::Transport))
}

fn validate_method(method: &str) -> Result<(), AcpError> {
    if method.is_empty()
        || method.len() > MAX_JSON_RPC_STRING_BYTES
        || method.as_bytes().contains(&0)
    {
        return Err(AcpError::from_code(AcpErrorCode::ProtocolViolation));
    }
    Ok(())
}

fn parse_strict_json(bytes: &[u8]) -> Result<Value, AcpError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|_| AcpError::from_code(AcpErrorCode::ProtocolViolation))?
        .0;
    deserializer
        .end()
        .map_err(|_| AcpError::from_code(AcpErrorCode::ProtocolViolation))?;
    Ok(value)
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            let value = object.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}
