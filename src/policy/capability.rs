use std::collections::BTreeSet;
use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::delegates::{ModelId, ReasoningEffort};
use crate::error::CarlError;
use crate::events::{SessionId, TurnId};

const MAX_ACTOR_ID_BYTES: usize = 128;
const MAX_TOOL_NAME_BYTES: usize = 128;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, CarlError> {
        let value = value.as_ref();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(validation_error("SHA-256 digest is invalid"));
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest(<redacted>)")
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(|_| D::Error::custom("invalid SHA-256 digest"))
    }
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ActorId(String);

impl ActorId {
    pub fn parse(value: impl Into<String>) -> Result<Self, CarlError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_ACTOR_ID_BYTES
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            });
        if !valid {
            return Err(validation_error("actor identifier is invalid"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ActorId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActorId(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for ActorId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(|_| D::Error::custom("invalid actor identifier"))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Frontend {
    Cli,
    Tui,
    Telegram,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ActorIdentity {
    id: ActorId,
    frontend: Frontend,
}

impl ActorIdentity {
    #[must_use]
    pub const fn new(id: ActorId, frontend: Frontend) -> Self {
        Self { id, frontend }
    }

    #[must_use]
    pub const fn id(&self) -> &ActorId {
        &self.id
    }

    #[must_use]
    pub const fn frontend(&self) -> Frontend {
        self.frontend
    }
}

impl fmt::Debug for ActorIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActorIdentity")
            .field("id", &"<redacted>")
            .field("frontend", &self.frontend)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderNetwork {
    #[serde(rename = "openai_codex")]
    OpenAiCodex,
    #[serde(rename = "xai_grok")]
    XaiGrok,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentGrant {
    Credential,
    UserHome,
    NetworkProxy,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum SideEffect {
    ExternalAgent,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum RiskClass {
    High,
}

#[derive(Clone, Serialize)]
pub struct CapabilityRequest {
    tool: String,
    schema_version: u16,
    actor: ActorIdentity,
    session_id: SessionId,
    turn_id: TurnId,
    prompt_digest: Sha256Digest,
    stage_manifest_digest: Sha256Digest,
    verification_specification_digest: Sha256Digest,
    model: Option<ModelId>,
    effort: Option<ReasoningEffort>,
    provider_network: ProviderNetwork,
    environment_grants: BTreeSet<EnvironmentGrant>,
    side_effect: SideEffect,
    risk: RiskClass,
    live_workspace_writable: bool,
}

impl CapabilityRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn external_agent(
        tool: impl Into<String>,
        actor: ActorIdentity,
        session_id: SessionId,
        turn_id: TurnId,
        prompt_digest: Sha256Digest,
        stage_manifest_digest: Sha256Digest,
        verification_specification_digest: Sha256Digest,
        model: Option<ModelId>,
        effort: Option<ReasoningEffort>,
        provider_network: ProviderNetwork,
        environment_grants: BTreeSet<EnvironmentGrant>,
        live_workspace_writable: bool,
    ) -> Result<Self, CarlError> {
        let tool = tool.into();
        let valid_tool = !tool.is_empty()
            && tool.len() <= MAX_TOOL_NAME_BYTES
            && tool.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            });
        if !valid_tool {
            return Err(validation_error("capability tool name is invalid"));
        }
        Ok(Self {
            tool,
            schema_version: 2,
            actor,
            session_id,
            turn_id,
            prompt_digest,
            stage_manifest_digest,
            verification_specification_digest,
            model,
            effort,
            provider_network,
            environment_grants,
            side_effect: SideEffect::ExternalAgent,
            risk: RiskClass::High,
            live_workspace_writable,
        })
    }

    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        let encoded = serde_json::to_vec(self)
            .expect("normalized capability request serialization is closed");
        Sha256Digest::from_bytes(Sha256::digest(encoded).into())
    }

    #[must_use]
    pub const fn actor(&self) -> &ActorIdentity {
        &self.actor
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn turn_id(&self) -> TurnId {
        self.turn_id
    }

    #[must_use]
    pub const fn verification_specification_digest(&self) -> Sha256Digest {
        self.verification_specification_digest
    }

    #[must_use]
    pub const fn environment_grants(&self) -> &BTreeSet<EnvironmentGrant> {
        &self.environment_grants
    }

    #[must_use]
    pub const fn live_workspace_writable(&self) -> bool {
        self.live_workspace_writable
    }

    pub(crate) fn provider_matches_tool(&self) -> bool {
        matches!(
            (self.tool.as_str(), self.provider_network),
            ("delegate.codex", ProviderNetwork::OpenAiCodex)
                | ("delegate.grok", ProviderNetwork::XaiGrok)
        )
    }
}

impl fmt::Debug for CapabilityRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityRequest")
            .field("tool", &self.tool)
            .field("schema_version", &self.schema_version)
            .field("frontend", &self.actor.frontend)
            .field("side_effect", &self.side_effect)
            .field("risk", &self.risk)
            .field("live_workspace_writable", &self.live_workspace_writable)
            .finish_non_exhaustive()
    }
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn validation_error(detail: &str) -> CarlError {
    CarlError::Validation {
        detail: detail.to_owned(),
    }
}
