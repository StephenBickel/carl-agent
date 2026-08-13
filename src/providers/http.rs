use std::collections::VecDeque;
use std::fmt;
use std::pin::Pin;
use std::time::Duration;

use futures_core::Stream;
use futures_util::{StreamExt, stream};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use reqwest::{Client, Response, StatusCode, Url, redirect};
use serde_json::Value;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

const MAX_CREDENTIAL_BYTES: usize = 512;
const MAX_JSON_BYTES: usize = 10 * 1024 * 1024;
const MAX_SSE_LINE_BYTES: usize = 256 * 1024;
const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

pub type ProviderSseStream =
    Pin<Box<dyn Stream<Item = Result<String, ProviderHttpError>> + Send + 'static>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderHttpErrorCode {
    Authentication,
    RateLimit,
    Transport,
    InvalidRequest,
    InvalidResponse,
    Cancelled,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct ProviderHttpError {
    code: ProviderHttpErrorCode,
    message: &'static str,
}

impl ProviderHttpError {
    const fn new(code: ProviderHttpErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }

    #[must_use]
    pub const fn code(&self) -> ProviderHttpErrorCode {
        self.code
    }
}

pub struct SecretCredential(Zeroizing<Vec<u8>>);

impl SecretCredential {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProviderHttpError> {
        if bytes.is_empty()
            || bytes.len() > MAX_CREDENTIAL_BYTES
            || bytes.iter().any(|byte| byte.is_ascii_control())
        {
            return Err(invalid_request("provider credential is invalid"));
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn with_bytes<T>(&self, operation: impl FnOnce(&[u8]) -> T) -> T {
        operation(self.0.as_slice())
    }
}

impl fmt::Debug for SecretCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretCredential(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProviderEndpoint {
    base: Url,
}

impl ProviderEndpoint {
    #[must_use]
    pub fn openai() -> Self {
        Self::official("https://api.openai.com")
    }

    #[must_use]
    pub fn openrouter() -> Self {
        Self::official("https://openrouter.ai")
    }

    pub fn loopback(origin: &str) -> Result<Self, ProviderHttpError> {
        let base =
            Url::parse(origin).map_err(|_| invalid_request("provider endpoint is invalid"))?;
        let literal_loopback = base
            .host_str()
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
        if base.scheme() != "http"
            || !literal_loopback
            || base.cannot_be_a_base()
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
            || !base.username().is_empty()
            || base.password().is_some()
        {
            return Err(invalid_request("provider endpoint is not permitted"));
        }
        Ok(Self { base })
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        self.base.as_str().trim_end_matches('/')
    }

    fn official(origin: &'static str) -> Self {
        Self {
            base: Url::parse(origin).expect("static provider origin must be valid"),
        }
    }

    fn request_url(&self, path: &str) -> Result<Url, ProviderHttpError> {
        if !path.starts_with('/')
            || path.starts_with("//")
            || path.contains(['?', '#', '\\'])
            || path.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(invalid_request("provider request path is invalid"));
        }
        let url = Url::parse(&format!("{}{path}", self.origin()))
            .map_err(|_| invalid_request("provider request path is invalid"))?;
        if url.origin() != self.base.origin() {
            return Err(invalid_request("provider request origin changed"));
        }
        Ok(url)
    }
}

impl fmt::Debug for ProviderEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderEndpoint")
            .field("origin", &self.origin())
            .finish()
    }
}

pub struct ProviderHttpClient {
    endpoint: ProviderEndpoint,
    client: Client,
}

impl ProviderHttpClient {
    pub fn new(endpoint: ProviderEndpoint) -> Result<Self, ProviderHttpError> {
        let client = Client::builder()
            .redirect(redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(120))
            .user_agent(concat!("carl-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| transport("provider HTTP client could not be built"))?;
        Ok(Self { endpoint, client })
    }

    pub async fn post_json(
        &self,
        path: &str,
        credential: &SecretCredential,
        body: &Value,
        cancellation: CancellationToken,
    ) -> Result<Value, ProviderHttpError> {
        let response = self
            .send(path, credential, body, &cancellation, "application/json")
            .await?;
        require_content_type(&response, "application/json")?;
        let bytes = read_bounded(response, MAX_JSON_BYTES, &cancellation).await?;
        serde_json::from_slice(&bytes)
            .map_err(|_| invalid_response("provider JSON response is malformed"))
    }

    pub async fn post_sse(
        &self,
        path: &str,
        credential: &SecretCredential,
        body: &Value,
        cancellation: CancellationToken,
    ) -> Result<ProviderSseStream, ProviderHttpError> {
        let response = self
            .send(path, credential, body, &cancellation, "text/event-stream")
            .await?;
        require_content_type(&response, "text/event-stream")?;
        let state = SseState {
            body: Box::pin(response.bytes_stream()),
            buffer: Vec::new(),
            event_data: Vec::new(),
            queued: VecDeque::new(),
            cancellation,
            done: false,
        };
        Ok(Box::pin(stream::unfold(state, next_sse_item)))
    }

    async fn send(
        &self,
        path: &str,
        credential: &SecretCredential,
        body: &Value,
        cancellation: &CancellationToken,
        accept: &'static str,
    ) -> Result<Response, ProviderHttpError> {
        if cancellation.is_cancelled() {
            return Err(cancelled());
        }
        let url = self.endpoint.request_url(path)?;
        let encoded = serde_json::to_vec(body)
            .map_err(|_| invalid_request("provider request JSON is invalid"))?;
        if encoded.len() > MAX_JSON_BYTES {
            return Err(invalid_request("provider request is too large"));
        }
        let authorization = credential.with_bytes(|secret| {
            let mut value = Zeroizing::new(Vec::with_capacity(7 + secret.len()));
            value.extend_from_slice(b"Bearer ");
            value.extend_from_slice(secret);
            HeaderValue::from_bytes(&value)
                .map_err(|_| invalid_request("provider credential is invalid"))
        })?;
        let request = self
            .client
            .post(url)
            .header(AUTHORIZATION, authorization)
            .header(reqwest::header::ACCEPT, accept)
            .header(CONTENT_TYPE, "application/json")
            .body(encoded);
        let response = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(cancelled()),
            response = request.send() => response.map_err(|_| transport("provider request failed"))?,
        };
        ensure_success(response.status())?;
        Ok(response)
    }
}

impl fmt::Debug for ProviderHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderHttpClient")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

async fn read_bounded(
    response: Response,
    limit: usize,
    cancellation: &CancellationToken,
) -> Result<Vec<u8>, ProviderHttpError> {
    let mut body = response.bytes_stream();
    let mut bytes = Vec::new();
    loop {
        let chunk = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Err(cancelled()),
            chunk = body.next() => chunk,
        };
        let Some(chunk) = chunk else { break };
        let chunk = chunk.map_err(|_| transport("provider response body failed"))?;
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(invalid_response("provider response is too large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

struct SseState {
    body: Pin<Box<dyn Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send + 'static>>,
    buffer: Vec<u8>,
    event_data: Vec<String>,
    queued: VecDeque<String>,
    cancellation: CancellationToken,
    done: bool,
}

async fn next_sse_item(
    mut state: SseState,
) -> Option<(Result<String, ProviderHttpError>, SseState)> {
    loop {
        if let Some(item) = state.queued.pop_front() {
            return Some((Ok(item), state));
        }
        if state.done {
            return None;
        }
        if state.cancellation.is_cancelled() {
            state.done = true;
            return Some((Err(cancelled()), state));
        }
        let next = tokio::select! {
            biased;
            () = state.cancellation.cancelled() => {
                state.done = true;
                return Some((Err(cancelled()), state));
            }
            next = state.body.next() => next,
        };
        match next {
            Some(Ok(chunk)) => {
                if state.buffer.len().saturating_add(chunk.len()) > MAX_SSE_EVENT_BYTES {
                    state.done = true;
                    return Some((
                        Err(invalid_response("provider SSE event is too large")),
                        state,
                    ));
                }
                state.buffer.extend_from_slice(&chunk);
                if let Err(error) = parse_complete_sse_lines(&mut state) {
                    state.done = true;
                    return Some((Err(error), state));
                }
            }
            Some(Err(_)) => {
                state.done = true;
                return Some((Err(transport("provider SSE stream failed")), state));
            }
            None => {
                if !state.buffer.is_empty() {
                    let line = std::mem::take(&mut state.buffer);
                    if let Err(error) = consume_sse_line(&mut state, &line) {
                        state.done = true;
                        return Some((Err(error), state));
                    }
                }
                queue_sse_event(&mut state);
                state.done = true;
            }
        }
    }
}

fn parse_complete_sse_lines(state: &mut SseState) -> Result<(), ProviderHttpError> {
    while let Some(index) = state.buffer.iter().position(|byte| *byte == b'\n') {
        if index > MAX_SSE_LINE_BYTES {
            return Err(invalid_response("provider SSE line is too large"));
        }
        let mut line: Vec<u8> = state.buffer.drain(..=index).collect();
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        consume_sse_line(state, &line)?;
    }
    if state.buffer.len() > MAX_SSE_LINE_BYTES {
        return Err(invalid_response("provider SSE line is too large"));
    }
    Ok(())
}

fn consume_sse_line(state: &mut SseState, line: &[u8]) -> Result<(), ProviderHttpError> {
    if line.len() > MAX_SSE_LINE_BYTES {
        return Err(invalid_response("provider SSE line is too large"));
    }
    if line.is_empty() {
        queue_sse_event(state);
        return Ok(());
    }
    if line[0] == b':' {
        return Ok(());
    }
    let text = std::str::from_utf8(line)
        .map_err(|_| invalid_response("provider SSE line is not UTF-8"))?;
    if let Some(data) = text.strip_prefix("data:") {
        let data = data.strip_prefix(' ').unwrap_or(data);
        let current = state.event_data.iter().map(String::len).sum::<usize>();
        if current.saturating_add(data.len()) > MAX_SSE_EVENT_BYTES {
            return Err(invalid_response("provider SSE event is too large"));
        }
        state.event_data.push(data.to_owned());
    }
    Ok(())
}

fn queue_sse_event(state: &mut SseState) {
    if !state.event_data.is_empty() {
        state.queued.push_back(state.event_data.join("\n"));
        state.event_data.clear();
    }
}

fn require_content_type(
    response: &Response,
    expected: &'static str,
) -> Result<(), ProviderHttpError> {
    let valid = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case(expected))
        });
    if valid {
        Ok(())
    } else {
        Err(invalid_response(
            "provider response content type is invalid",
        ))
    }
}

fn ensure_success(status: StatusCode) -> Result<(), ProviderHttpError> {
    if status.is_success() {
        return Ok(());
    }
    let error = match status.as_u16() {
        401 | 403 => ProviderHttpError::new(
            ProviderHttpErrorCode::Authentication,
            "provider authentication failed",
        ),
        429 => ProviderHttpError::new(
            ProviderHttpErrorCode::RateLimit,
            "provider rate limit reached",
        ),
        400..=499 => invalid_request("provider rejected the request"),
        500..=599 => transport("provider service failed"),
        _ => invalid_response("provider returned an invalid status"),
    };
    Err(error)
}

const fn invalid_request(message: &'static str) -> ProviderHttpError {
    ProviderHttpError::new(ProviderHttpErrorCode::InvalidRequest, message)
}

const fn invalid_response(message: &'static str) -> ProviderHttpError {
    ProviderHttpError::new(ProviderHttpErrorCode::InvalidResponse, message)
}

const fn transport(message: &'static str) -> ProviderHttpError {
    ProviderHttpError::new(ProviderHttpErrorCode::Transport, message)
}

const fn cancelled() -> ProviderHttpError {
    ProviderHttpError::new(
        ProviderHttpErrorCode::Cancelled,
        "provider request was cancelled",
    )
}
