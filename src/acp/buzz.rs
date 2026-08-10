use std::collections::{BTreeMap, HashSet};
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::path::Path;
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use crate::sidecar::{
    BoundedProcessLimits, BoundedProcessOutcome, ClosedEnvironment, ExecutionWorkspace,
    TrustedExecutable, run_bounded_process, run_bounded_process_with_stdin,
};

const MAX_PROMPT_BLOCKS: usize = 12;
const MAX_PROMPT_BYTES: usize = 256 * 1024;
const MAX_PUBLISH_BYTES: usize = 256 * 1024;
const BUZZ_VERSION_OUTPUT: &[u8] = b"buzz 0.1.0\n";

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BuzzErrorCode {
    #[error("Buzz transport context is invalid")]
    InvalidContext,
    #[error("Buzz publisher configuration is invalid")]
    InvalidConfiguration,
    #[error("Buzz CLI version is unsupported")]
    UnsupportedVersion,
    #[error("Buzz publication failed")]
    PublicationFailed,
    #[error("Buzz publication was cancelled")]
    Cancelled,
    #[error("Buzz publication timed out")]
    TimedOut,
}

#[derive(Debug, Error)]
#[error("{code}")]
pub struct BuzzError {
    code: BuzzErrorCode,
}

impl BuzzError {
    #[must_use]
    pub const fn code(&self) -> BuzzErrorCode {
        self.code
    }

    const fn from_code(code: BuzzErrorCode) -> Self {
        Self { code }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BuzzContext {
    channel_id: Uuid,
    reply_to: String,
    actor_hex: String,
}

impl fmt::Debug for BuzzContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuzzContext")
            .field("channel_id", &self.channel_id)
            .field("reply_to", &"<redacted>")
            .field("actor_hex", &"<redacted>")
            .finish()
    }
}

impl BuzzContext {
    pub fn parse(blocks: &[&str]) -> Result<Self, BuzzError> {
        validate_prompt_bounds(blocks)?;
        let candidates = blocks
            .iter()
            .filter_map(|block| structural_event_lines(block))
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            return Err(invalid_context());
        }
        let lines = &candidates[0];
        if lines.len() < 5 {
            return Err(invalid_context());
        }
        let event_id = exact_field(lines[0], "Event ID: ")?;
        validate_lower_hex(event_id, 64)?;
        let channel = exact_field(lines[1], "Channel: ")?;
        let channel_id = parse_channel_id(channel)?;
        exact_field(lines[2], "Kind: ")?
            .parse::<u32>()
            .map_err(|_| invalid_context())?;
        let actor_hex = parse_actor_hex(exact_field(lines[3], "From: ")?)?;
        if !lines[4].starts_with("Time: ") && !lines[4].starts_with("Content: ") {
            return Err(invalid_context());
        }
        if lines[4].starts_with("Time: ")
            && lines
                .get(5)
                .is_none_or(|line| !line.starts_with("Content: "))
        {
            return Err(invalid_context());
        }
        Ok(Self {
            channel_id,
            reply_to: event_id.to_owned(),
            actor_hex,
        })
    }

    pub fn from_transport(
        channel_id: &str,
        reply_to: &str,
        actor_hex: &str,
    ) -> Result<Self, BuzzError> {
        validate_lower_hex(reply_to, 64)?;
        validate_lower_hex(actor_hex, 64)?;
        Ok(Self {
            channel_id: Uuid::parse_str(channel_id).map_err(|_| invalid_context())?,
            reply_to: reply_to.to_owned(),
            actor_hex: actor_hex.to_owned(),
        })
    }

    #[must_use]
    pub const fn channel_id(&self) -> Uuid {
        self.channel_id
    }

    #[must_use]
    pub fn reply_to(&self) -> &str {
        &self.reply_to
    }

    #[must_use]
    pub fn actor_hex(&self) -> &str {
        &self.actor_hex
    }
}

pub fn leading_slash_command(blocks: &[&str]) -> Result<Option<String>, BuzzError> {
    validate_prompt_bounds(blocks)?;
    let Some(first) = blocks.first().map(|block| block.trim()) else {
        return Ok(None);
    };
    if !first.starts_with('/') {
        return Ok(None);
    }
    if first.len() > 1024 || first.as_bytes().contains(&0) || first.contains(['\n', '\r']) {
        return Err(invalid_context());
    }
    Ok(Some(first.to_owned()))
}

#[derive(Clone)]
pub struct BuzzPublisherConfig {
    environment: Vec<(OsString, OsString)>,
}

impl fmt::Debug for BuzzPublisherConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuzzPublisherConfig")
            .field("environment_entries", &self.environment.len())
            .finish()
    }
}

impl BuzzPublisherConfig {
    pub fn from_process_environment() -> Result<Self, BuzzError> {
        let mut values = BTreeMap::new();
        for name in [
            "BUZZ_RELAY_URL",
            "BUZZ_PRIVATE_KEY",
            "BUZZ_AUTH_TAG",
            "BUZZ_ACP_DISPLAY_NAME",
        ] {
            if let Some(value) = env::var_os(name) {
                let value = value.into_string().map_err(|_| invalid_configuration())?;
                values.insert(name, value);
            }
        }
        Self::from_values(values)
    }

    pub fn from_mcp_servers(servers: &Value) -> Result<Self, BuzzError> {
        let servers = servers.as_array().ok_or_else(invalid_configuration)?;
        if servers.len() != 1 {
            return Err(invalid_configuration());
        }
        let server = servers[0].as_object().ok_or_else(invalid_configuration)?;
        require_exact_keys(
            server.keys().map(String::as_str),
            &["name", "command", "args", "env"],
        )?;
        if server.get("name").and_then(Value::as_str) != Some("carl-buzz-mcp") {
            return Err(invalid_configuration());
        }
        let command = server
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(invalid_configuration)?;
        let executable_name = Path::new(command)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(invalid_configuration)?;
        if !matches!(executable_name, "carl-buzz-mcp" | "carl-buzz-mcp.exe") {
            return Err(invalid_configuration());
        }
        if !server
            .get("args")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            return Err(invalid_configuration());
        }
        let environment = server
            .get("env")
            .and_then(Value::as_array)
            .ok_or_else(invalid_configuration)?;
        if !(2..=4).contains(&environment.len()) {
            return Err(invalid_configuration());
        }
        let allowed = [
            "BUZZ_RELAY_URL",
            "BUZZ_PRIVATE_KEY",
            "BUZZ_AUTH_TAG",
            "BUZZ_ACP_DISPLAY_NAME",
        ];
        let mut seen = HashSet::new();
        let mut values = BTreeMap::new();
        for entry in environment {
            let entry = entry.as_object().ok_or_else(invalid_configuration)?;
            require_exact_keys(entry.keys().map(String::as_str), &["name", "value"])?;
            let name = entry
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(invalid_configuration)?;
            let value = entry
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(invalid_configuration)?;
            if !allowed.contains(&name)
                || !seen.insert(name)
                || value.is_empty()
                || value.len() > 8 * 1024
                || value.as_bytes().contains(&0)
            {
                return Err(invalid_configuration());
            }
            values.insert(name, value.to_owned());
        }
        Self::from_values(values)
    }

    fn from_values(values: BTreeMap<&str, String>) -> Result<Self, BuzzError> {
        if !(2..=4).contains(&values.len())
            || values.values().any(|value| {
                value.is_empty() || value.len() > 8 * 1024 || value.as_bytes().contains(&0)
            })
            || ["BUZZ_RELAY_URL", "BUZZ_PRIVATE_KEY"]
                .iter()
                .any(|required| !values.contains_key(required))
        {
            return Err(invalid_configuration());
        }
        let relay =
            Url::parse(values["BUZZ_RELAY_URL"].as_str()).map_err(|_| invalid_configuration())?;
        if !matches!(relay.scheme(), "ws" | "wss")
            || relay.host_str().is_none()
            || !relay.username().is_empty()
            || relay.password().is_some()
        {
            return Err(invalid_configuration());
        }
        Ok(Self {
            environment: values
                .into_iter()
                .map(|(name, value)| (OsString::from(name), OsString::from(value)))
                .collect(),
        })
    }
}

pub struct BuzzPublisher {
    executable: TrustedExecutable,
    workspace: ExecutionWorkspace,
    environment: ClosedEnvironment,
}

impl fmt::Debug for BuzzPublisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BuzzPublisher(<redacted>)")
    }
}

impl BuzzPublisher {
    pub async fn connect(
        executable: TrustedExecutable,
        workspace: ExecutionWorkspace,
        configuration: BuzzPublisherConfig,
    ) -> Result<Self, BuzzError> {
        let empty = ClosedEnvironment::new(Vec::new()).map_err(|_| invalid_configuration())?;
        let result = run_bounded_process(
            &executable,
            &[OsString::from("--version")],
            &empty,
            &workspace,
            version_limits()?,
            CancellationToken::new(),
        )
        .await
        .map_err(|_| BuzzError::from_code(BuzzErrorCode::UnsupportedVersion))?;
        if !matches!(result.outcome(), BoundedProcessOutcome::Exited(status) if status.success())
            || result.stdout() != BUZZ_VERSION_OUTPUT
            || !result.stderr().is_empty()
        {
            return Err(BuzzError::from_code(BuzzErrorCode::UnsupportedVersion));
        }
        let environment = ClosedEnvironment::new(configuration.environment)
            .map_err(|_| invalid_configuration())?;
        Ok(Self {
            executable,
            workspace,
            environment,
        })
    }

    pub async fn send_message(
        &self,
        context: &BuzzContext,
        content: &str,
        cancellation: CancellationToken,
    ) -> Result<(), BuzzError> {
        validate_publish_content(content)?;
        let arguments = message_arguments(context);
        let result = run_bounded_process_with_stdin(
            &self.executable,
            &arguments,
            &self.environment,
            &self.workspace,
            publish_limits()?,
            cancellation,
            content.as_bytes(),
        )
        .await
        .map_err(|_| BuzzError::from_code(BuzzErrorCode::PublicationFailed))?;
        match result.outcome() {
            BoundedProcessOutcome::Exited(status) if status.success() => Ok(()),
            BoundedProcessOutcome::Cancelled => Err(BuzzError::from_code(BuzzErrorCode::Cancelled)),
            BoundedProcessOutcome::TimedOut => Err(BuzzError::from_code(BuzzErrorCode::TimedOut)),
            BoundedProcessOutcome::Exited(_) | BoundedProcessOutcome::OutputLimitExceeded => {
                Err(BuzzError::from_code(BuzzErrorCode::PublicationFailed))
            }
        }
    }

    pub async fn send_diff(
        &self,
        context: &BuzzContext,
        diff: &str,
        cancellation: CancellationToken,
    ) -> Result<(), BuzzError> {
        if diff.len() > MAX_PUBLISH_BYTES.saturating_sub(12) {
            return Err(BuzzError::from_code(BuzzErrorCode::PublicationFailed));
        }
        self.send_message(context, &format!("```diff\n{diff}\n```"), cancellation)
            .await
    }
}

fn validate_prompt_bounds(blocks: &[&str]) -> Result<(), BuzzError> {
    if blocks.is_empty() || blocks.len() > MAX_PROMPT_BLOCKS {
        return Err(invalid_context());
    }
    let bytes = blocks.iter().try_fold(0_usize, |total, block| {
        total.checked_add(block.len()).ok_or_else(invalid_context)
    })?;
    if bytes > MAX_PROMPT_BYTES || blocks.iter().any(|block| block.as_bytes().contains(&0)) {
        return Err(invalid_context());
    }
    Ok(())
}

fn structural_event_lines(block: &str) -> Option<Vec<&str>> {
    let lines = block.lines().collect::<Vec<_>>();
    let start = if lines
        .first()
        .is_some_and(|line| line.starts_with("Event ID: "))
    {
        0
    } else if lines
        .first()
        .is_some_and(|line| line.starts_with("[Buzz event:"))
        && lines
            .get(1)
            .is_some_and(|line| line.starts_with("Event ID: "))
    {
        1
    } else {
        return None;
    };
    Some(lines[start..].to_vec())
}

fn exact_field<'a>(line: &'a str, prefix: &str) -> Result<&'a str, BuzzError> {
    let value = line.strip_prefix(prefix).ok_or_else(invalid_context)?;
    if value.is_empty() {
        return Err(invalid_context());
    }
    Ok(value)
}

fn parse_channel_id(channel: &str) -> Result<Uuid, BuzzError> {
    let candidate = channel
        .rsplit_once("(#")
        .and_then(|(_, suffix)| suffix.strip_suffix(')'))
        .unwrap_or(channel);
    Uuid::parse_str(candidate).map_err(|_| invalid_context())
}

fn parse_actor_hex(from: &str) -> Result<String, BuzzError> {
    let (_, suffix) = from.rsplit_once("hex: ").ok_or_else(invalid_context)?;
    let candidate = suffix.strip_suffix(')').ok_or_else(invalid_context)?;
    validate_lower_hex(candidate, 64)?;
    Ok(candidate.to_owned())
}

fn validate_lower_hex(value: &str, length: usize) -> Result<(), BuzzError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_context());
    }
    Ok(())
}

fn require_exact_keys<'a>(
    actual: impl Iterator<Item = &'a str>,
    expected: &[&str],
) -> Result<(), BuzzError> {
    let actual = actual.collect::<HashSet<_>>();
    let expected = expected.iter().copied().collect::<HashSet<_>>();
    if actual != expected {
        return Err(invalid_configuration());
    }
    Ok(())
}

fn validate_publish_content(content: &str) -> Result<(), BuzzError> {
    if content.is_empty() || content.len() > MAX_PUBLISH_BYTES || content.as_bytes().contains(&0) {
        return Err(BuzzError::from_code(BuzzErrorCode::PublicationFailed));
    }
    Ok(())
}

fn message_arguments(context: &BuzzContext) -> Vec<OsString> {
    [
        "messages".to_owned(),
        "send".to_owned(),
        "--channel".to_owned(),
        context.channel_id.to_string(),
        "--content".to_owned(),
        "-".to_owned(),
        "--reply-to".to_owned(),
        context.reply_to.clone(),
        "--broadcast".to_owned(),
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn version_limits() -> Result<BoundedProcessLimits, BuzzError> {
    BoundedProcessLimits::new(
        Duration::from_secs(5),
        4 * 1024,
        Duration::from_millis(250),
        Duration::from_secs(2),
        Duration::from_millis(10),
    )
    .map_err(|_| invalid_configuration())
}

fn publish_limits() -> Result<BoundedProcessLimits, BuzzError> {
    BoundedProcessLimits::new(
        Duration::from_secs(60),
        256 * 1024,
        Duration::from_millis(250),
        Duration::from_secs(2),
        Duration::from_millis(10),
    )
    .map_err(|_| invalid_configuration())
}

const fn invalid_context() -> BuzzError {
    BuzzError::from_code(BuzzErrorCode::InvalidContext)
}

const fn invalid_configuration() -> BuzzError {
    BuzzError::from_code(BuzzErrorCode::InvalidConfiguration)
}
