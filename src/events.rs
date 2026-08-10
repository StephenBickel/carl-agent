use chrono::{DateTime, Utc};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::acp::PermissionMode;
use crate::policy::Frontend;
use crate::runtime::subscription::{
    RunConfigSnapshot, RunId, RunState, RunTransition, RunTrustLabel,
};

pub const EVENT_SCHEMA_VERSION: u32 = 3;

macro_rules! define_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self::from_uuid(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.as_uuid()
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self::from_uuid)
            }
        }
    };
}

define_id!(SessionId);
define_id!(TurnId);
define_id!(EventId);
define_id!(ToolCallId);
define_id!(ApprovalId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrontendDeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Uncertain,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    UserInput {
        text: String,
    },
    AssistantTextDelta {
        text: String,
    },
    ProviderLifecycle {
        phase: String,
        provider_id: Option<String>,
    },
    WorkspaceDiffUpdated {
        diff: String,
    },
    ToolProposed {
        tool_call_id: ToolCallId,
        tool_name: String,
        arguments: Value,
    },
    ApprovalRequested {
        approval_id: ApprovalId,
        tool_call_id: ToolCallId,
        summary: String,
    },
    ToolCompleted {
        tool_call_id: ToolCallId,
        output: Value,
    },
    TurnCompleted,
    TurnInterrupted {
        reason: String,
    },
    FrontendSessionBound {
        frontend: Frontend,
        external_session_id: String,
        protocol_version: u32,
    },
    FrontendPermissionChanged {
        external_session_id: String,
        permission_mode: PermissionMode,
    },
    FrontendDeliveryTransitioned {
        action_digest: String,
        status: FrontendDeliveryStatus,
    },
    SubscriptionRunPrepared {
        run_id: RunId,
        run_sequence: u64,
        configuration: RunConfigSnapshot,
        state: RunState,
        trust_label: RunTrustLabel,
    },
    SubscriptionRunConfigurationObserved {
        run_id: RunId,
        run_sequence: u64,
        configuration: RunConfigSnapshot,
        trust_label: RunTrustLabel,
    },
    SubscriptionRunTransitioned {
        run_id: RunId,
        run_sequence: u64,
        transition: RunTransition,
        trust_label: RunTrustLabel,
    },
}

impl Event {
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        EVENT_SCHEMA_VERSION
    }
}

#[derive(Serialize)]
struct VersionedEventRef<'a> {
    schema_version: u32,
    #[serde(flatten)]
    payload: EventRef<'a>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum EventRef<'a> {
    UserInput {
        text: &'a str,
    },
    AssistantTextDelta {
        text: &'a str,
    },
    ProviderLifecycle {
        phase: &'a str,
        provider_id: Option<&'a str>,
    },
    WorkspaceDiffUpdated {
        diff: &'a str,
    },
    ToolProposed {
        tool_call_id: ToolCallId,
        tool_name: &'a str,
        arguments: &'a Value,
    },
    ApprovalRequested {
        approval_id: ApprovalId,
        tool_call_id: ToolCallId,
        summary: &'a str,
    },
    ToolCompleted {
        tool_call_id: ToolCallId,
        output: &'a Value,
    },
    TurnCompleted,
    TurnInterrupted {
        reason: &'a str,
    },
    FrontendSessionBound {
        frontend: Frontend,
        external_session_id: &'a str,
        protocol_version: u32,
    },
    FrontendPermissionChanged {
        external_session_id: &'a str,
        permission_mode: PermissionMode,
    },
    FrontendDeliveryTransitioned {
        action_digest: &'a str,
        status: FrontendDeliveryStatus,
    },
    SubscriptionRunPrepared {
        run_id: RunId,
        run_sequence: u64,
        configuration: &'a RunConfigSnapshot,
        state: RunState,
        trust_label: RunTrustLabel,
    },
    SubscriptionRunConfigurationObserved {
        run_id: RunId,
        run_sequence: u64,
        configuration: &'a RunConfigSnapshot,
        trust_label: RunTrustLabel,
    },
    SubscriptionRunTransitioned {
        run_id: RunId,
        run_sequence: u64,
        transition: &'a RunTransition,
        trust_label: RunTrustLabel,
    },
}

impl<'a> From<&'a Event> for EventRef<'a> {
    fn from(event: &'a Event) -> Self {
        match event {
            Event::UserInput { text } => Self::UserInput { text },
            Event::AssistantTextDelta { text } => Self::AssistantTextDelta { text },
            Event::ProviderLifecycle { phase, provider_id } => Self::ProviderLifecycle {
                phase,
                provider_id: provider_id.as_deref(),
            },
            Event::WorkspaceDiffUpdated { diff } => Self::WorkspaceDiffUpdated { diff },
            Event::ToolProposed {
                tool_call_id,
                tool_name,
                arguments,
            } => Self::ToolProposed {
                tool_call_id: *tool_call_id,
                tool_name,
                arguments,
            },
            Event::ApprovalRequested {
                approval_id,
                tool_call_id,
                summary,
            } => Self::ApprovalRequested {
                approval_id: *approval_id,
                tool_call_id: *tool_call_id,
                summary,
            },
            Event::ToolCompleted {
                tool_call_id,
                output,
            } => Self::ToolCompleted {
                tool_call_id: *tool_call_id,
                output,
            },
            Event::TurnCompleted => Self::TurnCompleted,
            Event::TurnInterrupted { reason } => Self::TurnInterrupted { reason },
            Event::FrontendSessionBound {
                frontend,
                external_session_id,
                protocol_version,
            } => Self::FrontendSessionBound {
                frontend: *frontend,
                external_session_id,
                protocol_version: *protocol_version,
            },
            Event::FrontendPermissionChanged {
                external_session_id,
                permission_mode,
            } => Self::FrontendPermissionChanged {
                external_session_id,
                permission_mode: *permission_mode,
            },
            Event::FrontendDeliveryTransitioned {
                action_digest,
                status,
            } => Self::FrontendDeliveryTransitioned {
                action_digest,
                status: *status,
            },
            Event::SubscriptionRunPrepared {
                run_id,
                run_sequence,
                configuration,
                state,
                trust_label,
            } => Self::SubscriptionRunPrepared {
                run_id: *run_id,
                run_sequence: *run_sequence,
                configuration,
                state: *state,
                trust_label: *trust_label,
            },
            Event::SubscriptionRunConfigurationObserved {
                run_id,
                run_sequence,
                configuration,
                trust_label,
            } => Self::SubscriptionRunConfigurationObserved {
                run_id: *run_id,
                run_sequence: *run_sequence,
                configuration,
                trust_label: *trust_label,
            },
            Event::SubscriptionRunTransitioned {
                run_id,
                run_sequence,
                transition,
                trust_label,
            } => Self::SubscriptionRunTransitioned {
                run_id: *run_id,
                run_sequence: *run_sequence,
                transition,
                trust_label: *trust_label,
            },
        }
    }
}

impl Serialize for Event {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        VersionedEventRef {
            schema_version: EVENT_SCHEMA_VERSION,
            payload: EventRef::from(self),
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
struct EventVersion {
    schema_version: u32,
}

#[derive(Deserialize)]
struct VersionedEventV1 {
    #[serde(rename = "schema_version")]
    _schema_version: u32,
    #[serde(flatten)]
    payload: EventPayloadV1,
}

#[derive(Deserialize)]
struct VersionedEventV2 {
    #[serde(rename = "schema_version")]
    _schema_version: u32,
    #[serde(flatten)]
    payload: EventPayloadV2,
}

#[derive(Deserialize)]
struct VersionedEventV3 {
    #[serde(rename = "schema_version")]
    _schema_version: u32,
    #[serde(flatten)]
    payload: EventPayloadV3,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum EventPayloadV1 {
    UserInput {
        text: String,
    },
    AssistantTextDelta {
        text: String,
    },
    ToolProposed {
        tool_call_id: ToolCallId,
        tool_name: String,
        arguments: Value,
    },
    ApprovalRequested {
        approval_id: ApprovalId,
        tool_call_id: ToolCallId,
        summary: String,
    },
    ToolCompleted {
        tool_call_id: ToolCallId,
        output: Value,
    },
    TurnCompleted,
    TurnInterrupted {
        reason: String,
    },
}

impl From<EventPayloadV1> for Event {
    fn from(payload: EventPayloadV1) -> Self {
        match payload {
            EventPayloadV1::UserInput { text } => Self::UserInput { text },
            EventPayloadV1::AssistantTextDelta { text } => Self::AssistantTextDelta { text },
            EventPayloadV1::ToolProposed {
                tool_call_id,
                tool_name,
                arguments,
            } => Self::ToolProposed {
                tool_call_id,
                tool_name,
                arguments,
            },
            EventPayloadV1::ApprovalRequested {
                approval_id,
                tool_call_id,
                summary,
            } => Self::ApprovalRequested {
                approval_id,
                tool_call_id,
                summary,
            },
            EventPayloadV1::ToolCompleted {
                tool_call_id,
                output,
            } => Self::ToolCompleted {
                tool_call_id,
                output,
            },
            EventPayloadV1::TurnCompleted => Self::TurnCompleted,
            EventPayloadV1::TurnInterrupted { reason } => Self::TurnInterrupted { reason },
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum EventPayloadV2 {
    UserInput {
        text: String,
    },
    AssistantTextDelta {
        text: String,
    },
    ToolProposed {
        tool_call_id: ToolCallId,
        tool_name: String,
        arguments: Value,
    },
    ApprovalRequested {
        approval_id: ApprovalId,
        tool_call_id: ToolCallId,
        summary: String,
    },
    ToolCompleted {
        tool_call_id: ToolCallId,
        output: Value,
    },
    TurnCompleted,
    TurnInterrupted {
        reason: String,
    },
    SubscriptionRunPrepared {
        run_id: RunId,
        run_sequence: u64,
        configuration: RunConfigSnapshot,
        state: RunState,
        trust_label: RunTrustLabel,
    },
    SubscriptionRunConfigurationObserved {
        run_id: RunId,
        run_sequence: u64,
        configuration: RunConfigSnapshot,
        trust_label: RunTrustLabel,
    },
    SubscriptionRunTransitioned {
        run_id: RunId,
        run_sequence: u64,
        transition: RunTransition,
        trust_label: RunTrustLabel,
    },
}

impl From<EventPayloadV2> for Event {
    fn from(payload: EventPayloadV2) -> Self {
        match payload {
            EventPayloadV2::UserInput { text } => Self::UserInput { text },
            EventPayloadV2::AssistantTextDelta { text } => Self::AssistantTextDelta { text },
            EventPayloadV2::ToolProposed {
                tool_call_id,
                tool_name,
                arguments,
            } => Self::ToolProposed {
                tool_call_id,
                tool_name,
                arguments,
            },
            EventPayloadV2::ApprovalRequested {
                approval_id,
                tool_call_id,
                summary,
            } => Self::ApprovalRequested {
                approval_id,
                tool_call_id,
                summary,
            },
            EventPayloadV2::ToolCompleted {
                tool_call_id,
                output,
            } => Self::ToolCompleted {
                tool_call_id,
                output,
            },
            EventPayloadV2::TurnCompleted => Self::TurnCompleted,
            EventPayloadV2::TurnInterrupted { reason } => Self::TurnInterrupted { reason },
            EventPayloadV2::SubscriptionRunPrepared {
                run_id,
                run_sequence,
                configuration,
                state,
                trust_label,
            } => Self::SubscriptionRunPrepared {
                run_id,
                run_sequence,
                configuration,
                state,
                trust_label,
            },
            EventPayloadV2::SubscriptionRunConfigurationObserved {
                run_id,
                run_sequence,
                configuration,
                trust_label,
            } => Self::SubscriptionRunConfigurationObserved {
                run_id,
                run_sequence,
                configuration,
                trust_label,
            },
            EventPayloadV2::SubscriptionRunTransitioned {
                run_id,
                run_sequence,
                transition,
                trust_label,
            } => Self::SubscriptionRunTransitioned {
                run_id,
                run_sequence,
                transition,
                trust_label,
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum EventPayloadV3 {
    UserInput {
        text: String,
    },
    AssistantTextDelta {
        text: String,
    },
    ProviderLifecycle {
        phase: String,
        provider_id: Option<String>,
    },
    WorkspaceDiffUpdated {
        diff: String,
    },
    ToolProposed {
        tool_call_id: ToolCallId,
        tool_name: String,
        arguments: Value,
    },
    ApprovalRequested {
        approval_id: ApprovalId,
        tool_call_id: ToolCallId,
        summary: String,
    },
    ToolCompleted {
        tool_call_id: ToolCallId,
        output: Value,
    },
    TurnCompleted,
    TurnInterrupted {
        reason: String,
    },
    FrontendSessionBound {
        frontend: Frontend,
        external_session_id: String,
        protocol_version: u32,
    },
    FrontendPermissionChanged {
        external_session_id: String,
        permission_mode: PermissionMode,
    },
    FrontendDeliveryTransitioned {
        action_digest: String,
        status: FrontendDeliveryStatus,
    },
    SubscriptionRunPrepared {
        run_id: RunId,
        run_sequence: u64,
        configuration: RunConfigSnapshot,
        state: RunState,
        trust_label: RunTrustLabel,
    },
    SubscriptionRunConfigurationObserved {
        run_id: RunId,
        run_sequence: u64,
        configuration: RunConfigSnapshot,
        trust_label: RunTrustLabel,
    },
    SubscriptionRunTransitioned {
        run_id: RunId,
        run_sequence: u64,
        transition: RunTransition,
        trust_label: RunTrustLabel,
    },
}

impl From<EventPayloadV3> for Event {
    fn from(payload: EventPayloadV3) -> Self {
        match payload {
            EventPayloadV3::UserInput { text } => Self::UserInput { text },
            EventPayloadV3::AssistantTextDelta { text } => Self::AssistantTextDelta { text },
            EventPayloadV3::ProviderLifecycle { phase, provider_id } => {
                Self::ProviderLifecycle { phase, provider_id }
            }
            EventPayloadV3::WorkspaceDiffUpdated { diff } => Self::WorkspaceDiffUpdated { diff },
            EventPayloadV3::ToolProposed {
                tool_call_id,
                tool_name,
                arguments,
            } => Self::ToolProposed {
                tool_call_id,
                tool_name,
                arguments,
            },
            EventPayloadV3::ApprovalRequested {
                approval_id,
                tool_call_id,
                summary,
            } => Self::ApprovalRequested {
                approval_id,
                tool_call_id,
                summary,
            },
            EventPayloadV3::ToolCompleted {
                tool_call_id,
                output,
            } => Self::ToolCompleted {
                tool_call_id,
                output,
            },
            EventPayloadV3::TurnCompleted => Self::TurnCompleted,
            EventPayloadV3::TurnInterrupted { reason } => Self::TurnInterrupted { reason },
            EventPayloadV3::FrontendSessionBound {
                frontend,
                external_session_id,
                protocol_version,
            } => Self::FrontendSessionBound {
                frontend,
                external_session_id,
                protocol_version,
            },
            EventPayloadV3::FrontendPermissionChanged {
                external_session_id,
                permission_mode,
            } => Self::FrontendPermissionChanged {
                external_session_id,
                permission_mode,
            },
            EventPayloadV3::FrontendDeliveryTransitioned {
                action_digest,
                status,
            } => Self::FrontendDeliveryTransitioned {
                action_digest,
                status,
            },
            EventPayloadV3::SubscriptionRunPrepared {
                run_id,
                run_sequence,
                configuration,
                state,
                trust_label,
            } => Self::SubscriptionRunPrepared {
                run_id,
                run_sequence,
                configuration,
                state,
                trust_label,
            },
            EventPayloadV3::SubscriptionRunConfigurationObserved {
                run_id,
                run_sequence,
                configuration,
                trust_label,
            } => Self::SubscriptionRunConfigurationObserved {
                run_id,
                run_sequence,
                configuration,
                trust_label,
            },
            EventPayloadV3::SubscriptionRunTransitioned {
                run_id,
                run_sequence,
                transition,
                trust_label,
            } => Self::SubscriptionRunTransitioned {
                run_id,
                run_sequence,
                transition,
                trust_label,
            },
        }
    }
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let version = serde_json::from_value::<EventVersion>(value.clone())
            .map_err(|error| D::Error::custom(error.to_string()))?;
        match version.schema_version {
            1 => serde_json::from_value::<VersionedEventV1>(value)
                .map(|event| event.payload.into())
                .map_err(|error| D::Error::custom(error.to_string())),
            2 => serde_json::from_value::<VersionedEventV2>(value)
                .map(|event| event.payload.into())
                .map_err(|error| D::Error::custom(error.to_string())),
            3 => serde_json::from_value::<VersionedEventV3>(value)
                .map(|event| event.payload.into())
                .map_err(|error| D::Error::custom(error.to_string())),
            unsupported => Err(D::Error::custom(format_args!(
                "unsupported event schema version {unsupported}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EventEnvelope {
    pub id: EventId,
    pub session_id: SessionId,
    pub turn_id: Option<TurnId>,
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    #[serde(flatten)]
    pub event: Event,
}

impl EventEnvelope {
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.event.schema_version()
    }
}
