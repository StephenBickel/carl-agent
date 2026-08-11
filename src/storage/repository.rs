use std::collections::{BTreeMap, HashSet};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, io};

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::acp::PermissionMode;
use crate::artifacts::{ArtifactId, ArtifactStore};
use crate::delegates::{DelegateSettings, ModelId, ReasoningEffort, SettingSource};
use crate::error::CarlError;
use crate::events::{
    ApprovalId, EVENT_SCHEMA_VERSION, Event, EventEnvelope, EventId, SessionId, ToolCallId, TurnId,
};
use crate::memory::{
    DEFAULT_PROPOSAL_TTL_DAYS, MemoryContext, MemoryExport, MemoryKind, MemoryPartition,
    MemoryProposal, MemoryPurgeReport, MemoryQuery, MemoryRecord, MemoryScope, MemorySettings,
    MemoryWrite, ProposalOrigin, SemanticMemoryRanker, default_expiration, rank_memories,
    validate_memory_capture_text,
};
use crate::policy::{ActorId, Frontend, Sha256Digest};
use crate::runtime::subscription::{
    ProviderReported, RunConfigSnapshot, RunFailureCode, RunId, RunState, RunTransition,
    RunTrustLabel, VerificationId,
};
use crate::runtime::task::{
    CanonicalCheckpoint, CompletionContract, ContextPackage, EffectClass, OperationEvidenceState,
    OperationStatus, TaskBudget, TaskEvent, TaskId, TaskSnapshot, TaskStatus, reduce_task,
};
use crate::security::SecretFilter;
use crate::sidecar::DataRootLock;
use crate::staging::{
    ExactReplacementProposal, ProposalLimits, ProposalOutcome, SanitizedStage, SealedBaseline,
    SourcePreconditionRef, canonical_source_preconditions,
};
use crate::verification::{
    VerificationEnvironmentProfile, VerificationExecutableEvidence, VerificationLimits,
    VerificationOutcome, VerificationRequest, VerificationResult, VerificationSpec,
    VerificationSpecEvidence, VerifiedProposal,
};

use super::schema;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BOUND_APPROVAL_LIFETIME: chrono::TimeDelta = chrono::TimeDelta::minutes(15);
const MAX_APPROVAL_SUMMARY_BYTES: usize = 4 * 1_024;
const RUNTIME_DATABASE_FILENAME: &str = "carl.sqlite3";
const EXACT_REPLACEMENT_DOMAIN: &[u8] = b"carl.exact-replacement.v1\0";
const BASELINE_DIRECTORIES_DOMAIN: &[u8] = b"carl.baseline-directories.v1\0";
const MAX_BASELINE_DIRECTORY_PATH_BYTES: usize = 8 * 1024 * 1024;
const MAX_FRONTEND_VALUE_BYTES: usize = 128;
const MAX_FRONTEND_CWD_BYTES: usize = 32 * 1024;
const REMOTE_CODE_DOMAIN: &[u8] = b"carl.remote-code.v1\0";

macro_rules! bounded_frontend_value {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = CarlError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::try_from(value.to_owned())
            }
        }

        impl TryFrom<String> for $name {
            type Error = CarlError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                let valid = !value.is_empty()
                    && value.len() <= MAX_FRONTEND_VALUE_BYTES
                    && !value.as_bytes().contains(&0)
                    && !value.chars().any(char::is_control);
                if !valid {
                    return Err(CarlError::Validation {
                        detail: concat!($label, " is invalid").to_owned(),
                    });
                }
                Ok(Self(value))
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    };
}

bounded_frontend_value!(ExternalSessionId, "external session ID");
bounded_frontend_value!(ClientName, "ACP client name");
bounded_frontend_value!(ChannelId, "frontend channel ID");
bounded_frontend_value!(ProviderThreadId, "provider thread ID");
bounded_frontend_value!(ProviderRequestId, "provider request ID");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewFrontendSession {
    pub frontend: Frontend,
    pub external_session_id: ExternalSessionId,
    pub session_id: SessionId,
    pub cwd: PathBuf,
    pub protocol_version: u32,
    pub client_name: ClientName,
    pub permission_mode: PermissionMode,
    pub channel_id: Option<ChannelId>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontendSessionRecord {
    pub frontend: Frontend,
    pub external_session_id: ExternalSessionId,
    pub session_id: SessionId,
    pub cwd: PathBuf,
    pub protocol_version: u32,
    pub client_name: ClientName,
    pub permission_mode: PermissionMode,
    pub channel_id: Option<ChannelId>,
    pub provider_thread_id: Option<ProviderThreadId>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteCodeKind {
    Approval,
    BypassConfirmation,
}

impl RemoteCodeKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::BypassConfirmation => "bypass_confirmation",
        }
    }

    fn parse(value: &str) -> Result<Self, CarlError> {
        match value {
            "approval" => Ok(Self::Approval),
            "bypass_confirmation" => Ok(Self::BypassConfirmation),
            other => Err(invalid_stored_value("remote code kind", other)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewRemoteCode<'a> {
    pub display_code: &'a str,
    pub kind: RemoteCodeKind,
    pub external_session_id: ExternalSessionId,
    pub approval_id: Option<ApprovalId>,
    pub provider_request_id: Option<ProviderRequestId>,
    pub request_digest: Sha256Digest,
    pub actor_id: ActorId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteCodeClaim<'a> {
    pub display_code: &'a str,
    pub kind: RemoteCodeKind,
    pub external_session_id: ExternalSessionId,
    pub approval_id: Option<ApprovalId>,
    pub provider_request_id: Option<ProviderRequestId>,
    pub request_digest: Sha256Digest,
    pub actor_id: ActorId,
    pub now: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteCodeRecord {
    pub code_digest: Sha256Digest,
    pub kind: RemoteCodeKind,
    pub external_session_id: ExternalSessionId,
    pub approval_id: Option<ApprovalId>,
    pub provider_request_id: Option<ProviderRequestId>,
    pub request_digest: Sha256Digest,
    pub actor_id: ActorId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryKind {
    Message,
    Diff,
}

impl DeliveryKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Diff => "diff",
        }
    }

    fn parse(value: &str) -> Result<Self, CarlError> {
        match value {
            "message" => Ok(Self::Message),
            "diff" => Ok(Self::Diff),
            other => Err(invalid_stored_value("delivery kind", other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    Failed,
    Uncertain,
}

impl DeliveryStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Failed => "failed",
            Self::Uncertain => "uncertain",
        }
    }

    fn parse(value: &str) -> Result<Self, CarlError> {
        match value {
            "pending" => Ok(Self::Pending),
            "delivered" => Ok(Self::Delivered),
            "failed" => Ok(Self::Failed),
            "uncertain" => Ok(Self::Uncertain),
            other => Err(invalid_stored_value("delivery status", other)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewDelivery {
    pub action_digest: Sha256Digest,
    pub external_session_id: ExternalSessionId,
    pub kind: DeliveryKind,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryRecord {
    pub action_digest: Sha256Digest,
    pub external_session_id: ExternalSessionId,
    pub kind: DeliveryKind,
    pub status: DeliveryStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    pub id: SessionId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewTask {
    pub session_id: SessionId,
    pub workspace: PathBuf,
    pub contract: CompletionContract,
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub permission_mode: PermissionMode,
    pub budget: TaskBudget,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskRecord {
    pub snapshot: TaskSnapshot,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewCheckpoint {
    pub task_id: TaskId,
    pub checkpoint: CanonicalCheckpoint,
    pub checkpoint_digest: String,
    pub context_package: ContextPackage,
    pub context_package_digest: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointRecord {
    pub checkpoint: CanonicalCheckpoint,
    pub checkpoint_digest: String,
    pub context_package_digest: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Allowed,
    Denied,
    Expired,
}

impl ApprovalStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Expired => "expired",
        }
    }

    fn parse(value: &str) -> Result<Self, CarlError> {
        match value {
            "pending" => Ok(Self::Pending),
            "allowed" => Ok(Self::Allowed),
            "denied" => Ok(Self::Denied),
            "expired" => Ok(Self::Expired),
            other => Err(invalid_stored_value("approval status", other)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRecord {
    pub id: ApprovalId,
    pub session_id: SessionId,
    pub tool_call_id: ToolCallId,
    pub summary: String,
    pub status: ApprovalStatus,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Eq, PartialEq)]
pub struct BoundApprovalBinding {
    session_id: SessionId,
    turn_id: TurnId,
    tool_call_id: ToolCallId,
    actor_id: ActorId,
    request_digest: Sha256Digest,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl BoundApprovalBinding {
    pub fn new(
        session_id: SessionId,
        turn_id: TurnId,
        tool_call_id: ToolCallId,
        actor_id: ActorId,
        request_digest: Sha256Digest,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, CarlError> {
        let lifetime = expires_at.signed_duration_since(created_at);
        if lifetime <= chrono::TimeDelta::zero() || lifetime > MAX_BOUND_APPROVAL_LIFETIME {
            return Err(CarlError::Validation {
                detail: "bound approval lifetime is invalid".to_owned(),
            });
        }
        Ok(Self {
            session_id,
            turn_id,
            tool_call_id,
            actor_id,
            request_digest,
            created_at,
            expires_at,
        })
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
    pub const fn tool_call_id(&self) -> ToolCallId {
        self.tool_call_id
    }

    #[must_use]
    pub const fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }

    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

impl std::fmt::Debug for BoundApprovalBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundApprovalBinding")
            .field("session_id", &self.session_id)
            .field("turn_id", &self.turn_id)
            .field("tool_call_id", &self.tool_call_id)
            .field("actor_id", &"<redacted>")
            .field("request_digest", &"<redacted>")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct BoundApprovalRecord {
    pub id: ApprovalId,
    pub binding: BoundApprovalBinding,
    pub summary: String,
    pub status: ApprovalStatus,
    pub resolved_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for BoundApprovalRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundApprovalRecord")
            .field("id", &self.id)
            .field("binding", &self.binding)
            .field("summary", &"<redacted>")
            .field("status", &self.status)
            .field("resolved_at", &self.resolved_at)
            .field("consumed_at", &self.consumed_at)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumedApproval {
    pub id: ApprovalId,
    pub request_digest: Sha256Digest,
    pub consumed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionDelegateSettingsRecord {
    pub session_id: SessionId,
    pub settings: DelegateSettings,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewSubscriptionRun {
    id: RunId,
    session_id: SessionId,
    turn_id: TurnId,
    per_run_settings: DelegateSettings,
    configuration: RunConfigSnapshot,
    created_at: DateTime<Utc>,
}

impl NewSubscriptionRun {
    pub fn new(
        id: RunId,
        session_id: SessionId,
        turn_id: TurnId,
        per_run_settings: DelegateSettings,
        configuration: RunConfigSnapshot,
        created_at: DateTime<Utc>,
    ) -> Result<Self, CarlError> {
        validate_per_run_configuration(&per_run_settings, &configuration)?;
        if !matches!(
            configuration.provider_model(),
            ProviderReported::NotReported
        ) || !matches!(
            configuration.provider_effort(),
            ProviderReported::NotReported
        ) {
            return Err(CarlError::Validation {
                detail: "provider-reported configuration is unavailable before run creation"
                    .to_owned(),
            });
        }
        Ok(Self {
            id,
            session_id,
            turn_id,
            per_run_settings,
            configuration,
            created_at,
        })
    }

    #[must_use]
    pub const fn id(&self) -> RunId {
        self.id
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
    pub const fn per_run_settings(&self) -> &DelegateSettings {
        &self.per_run_settings
    }

    #[must_use]
    pub const fn configuration(&self) -> &RunConfigSnapshot {
        &self.configuration
    }

    #[must_use]
    pub const fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionRunRecord {
    pub id: RunId,
    pub session_id: SessionId,
    pub turn_id: TurnId,
    pub state: RunState,
    pub revision: u64,
    pub per_run_settings: DelegateSettings,
    pub configuration: RunConfigSnapshot,
    pub provider_configuration_observed: bool,
    pub failure_code: Option<RunFailureCode>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionRunBaselineEntryRecord {
    pub ordinal: u64,
    pub path: String,
    pub byte_length: u64,
    pub content_digest: Sha256Digest,
    pub content_artifact_id: ArtifactId,
    pub identity_platform: String,
    pub identity_a: String,
    pub identity_b: String,
    pub owner_id: String,
    pub owner_mode: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionRunBaselineRecord {
    pub run_id: RunId,
    pub manifest_artifact_id: ArtifactId,
    pub manifest_digest: Sha256Digest,
    pub source_preconditions_artifact_id: ArtifactId,
    pub source_preconditions_digest: Sha256Digest,
    pub entry_count: u64,
    pub total_bytes: u64,
    pub directory_count: u64,
    pub directory_manifest_digest: Sha256Digest,
    pub entries: Vec<SubscriptionRunBaselineEntryRecord>,
    pub directories: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionRunInspectionOutcome {
    NoChanges,
    ExactReplacement,
}

impl SubscriptionRunInspectionOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NoChanges => "no_changes",
            Self::ExactReplacement => "exact_replacement",
        }
    }

    fn parse(value: &str) -> Result<Self, CarlError> {
        match value {
            "no_changes" => Ok(Self::NoChanges),
            "exact_replacement" => Ok(Self::ExactReplacement),
            other => Err(invalid_stored_value(
                "subscription run inspection outcome",
                other,
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionRunInspectionRecord {
    pub run_id: RunId,
    pub outcome: SubscriptionRunInspectionOutcome,
    pub stage_manifest_digest: Sha256Digest,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionRunProposalRecord {
    pub run_id: RunId,
    pub proposal_artifact_id: ArtifactId,
    pub payload_artifact_id: ArtifactId,
    pub baseline_manifest_artifact_id: ArtifactId,
    pub candidate_manifest_digest: Sha256Digest,
    pub path: String,
    pub expected_live_hash: Sha256Digest,
    pub before_hash: Sha256Digest,
    pub after_hash: Sha256Digest,
    pub payload_hash: Sha256Digest,
    pub payload_bytes: u64,
    pub created_at: DateTime<Utc>,
}

pub struct VerificationCompletionRecord {
    run: SubscriptionRunRecord,
    result: VerificationResult,
    verified_proposal: Option<VerifiedProposal>,
}

pub(crate) struct VerificationResultRehydrationAuthority {
    _repository_loader_only: (),
}

impl VerificationCompletionRecord {
    #[must_use]
    pub const fn run(&self) -> &SubscriptionRunRecord {
        &self.run
    }

    #[must_use]
    pub const fn result(&self) -> &VerificationResult {
        &self.result
    }

    #[must_use]
    pub const fn verified_proposal(&self) -> Option<&VerifiedProposal> {
        self.verified_proposal.as_ref()
    }
}

struct StoredVerificationRequest {
    verification_id: String,
    started_run_sequence: i64,
    inspection_outcome: String,
    baseline_manifest_artifact_id: String,
    source_preconditions_artifact_id: String,
    source_preconditions_digest: String,
    baseline_directory_manifest_digest: String,
    proposal_artifact_id: String,
    payload_artifact_id: String,
    candidate_manifest_digest: String,
    executable_path: String,
    executable_metadata_risk: String,
    executable_platform_identity: Vec<u8>,
    executable_byte_length: i64,
    executable_content_sha256: String,
    executable_attestation_digest: String,
    verification_spec_digest: String,
    request_digest: String,
    argv_digest: String,
    environment_profile: String,
    execution_timeout_nanos: i64,
    max_output_bytes: i64,
    graceful_shutdown_timeout_nanos: i64,
    forced_shutdown_timeout_nanos: i64,
    poll_interval_nanos: i64,
    argv_count: i64,
    argv_bytes: i64,
    created_at: String,
}

struct StoredVerificationResult {
    verification_id: String,
    completed_run_sequence: i64,
    request_digest: String,
    expected_candidate_manifest_digest: String,
    expected_directory_manifest_digest: String,
    outcome: String,
    exit_code: Option<i64>,
    observed_candidate_manifest_digest: Option<String>,
    observed_directory_manifest_digest: Option<String>,
    executable_attestation_evidence: String,
    executable_attestation_digest: String,
    stdout_text: String,
    stdout_bytes: i64,
    stdout_digest: String,
    stderr_text: String,
    stderr_bytes: i64,
    stderr_digest: String,
    max_output_bytes: i64,
    duration_nanos: i64,
    result_digest: String,
    completed_at: String,
}

pub struct Store {
    connection: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CarlError> {
        let mut connection = Connection::open(path).map_err(storage_error)?;
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(storage_error)?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(storage_error)?;
        connection
            .pragma_update(None, "secure_delete", "ON")
            .map_err(storage_error)?;
        connection
            .pragma_update(None, "journal_size_limit", 0_i64)
            .map_err(storage_error)?;
        let journal_mode = connection
            .query_row("PRAGMA journal_mode = WAL", [], |row| {
                row.get::<_, String>(0)
            })
            .map_err(storage_error)?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(CarlError::Storage {
                detail: format!(
                    "SQLite journal mode is {journal_mode:?}; WAL is required for durable storage"
                ),
            });
        }
        schema::migrate(&mut connection)?;
        validate_task_projection_completeness(&connection)?;
        validate_task_canonical_payloads(&connection)?;
        checkpoint_for_secure_deletion(&connection)?;

        Ok(Self { connection })
    }

    pub(crate) fn open_locked(data_root_lock: &DataRootLock) -> Result<Self, CarlError> {
        let data_root = data_root_lock.runtime_data_root();
        if !data_root_lock.guards_data_root(data_root) {
            return Err(storage_invariant(
                "runtime data root changed after lock acquisition",
            ));
        }
        let path = data_root.join(RUNTIME_DATABASE_FILENAME);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(storage_invariant("runtime database is not a regular file"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(storage_invariant(
                    "runtime database metadata is unavailable",
                ));
            }
        }
        Self::open(path)
    }

    pub fn journal_mode(&self) -> Result<String, CarlError> {
        self.connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(storage_error)
    }

    pub fn foreign_keys_enabled(&self) -> Result<bool, CarlError> {
        self.connection
            .pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))
            .map_err(storage_error)
    }

    pub fn busy_timeout_millis(&self) -> Result<u64, CarlError> {
        let timeout = self
            .connection
            .pragma_query_value(None, "busy_timeout", |row| row.get::<_, i64>(0))
            .map_err(storage_error)?;
        u64::try_from(timeout).map_err(|error| CarlError::Storage {
            detail: format!("invalid busy timeout {timeout}: {error}"),
        })
    }

    pub fn create_session(&self) -> Result<SessionRecord, CarlError> {
        let now = Utc::now();
        let session = SessionRecord {
            id: SessionId::new(),
            created_at: now,
            updated_at: now,
        };
        let timestamp = format_timestamp(now);
        self.connection
            .execute(
                "INSERT INTO sessions (id, created_at, updated_at) VALUES (?1, ?2, ?2)",
                params![session.id.to_string(), timestamp],
            )
            .map_err(storage_error)?;
        Ok(session)
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionRecord>, CarlError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, created_at, updated_at
                 FROM sessions
                 ORDER BY created_at DESC, rowid DESC",
            )
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;

        rows.into_iter()
            .map(|(id, created_at, updated_at)| {
                Ok(SessionRecord {
                    id: parse_id("session ID", &id)?,
                    created_at: parse_timestamp(&created_at)?,
                    updated_at: parse_timestamp(&updated_at)?,
                })
            })
            .collect()
    }

    pub fn bind_frontend_session(
        &self,
        input: NewFrontendSession,
    ) -> Result<FrontendSessionRecord, CarlError> {
        if !matches!(input.frontend, Frontend::Acp | Frontend::Buzz)
            || !matches!(input.protocol_version, 1 | 2)
        {
            return Err(CarlError::Validation {
                detail: "frontend session protocol is invalid".to_owned(),
            });
        }
        validate_canonical_frontend_cwd(&input.cwd)?;
        let record = FrontendSessionRecord {
            frontend: input.frontend,
            external_session_id: input.external_session_id,
            session_id: input.session_id,
            cwd: input.cwd,
            protocol_version: input.protocol_version,
            client_name: input.client_name,
            permission_mode: input.permission_mode,
            channel_id: input.channel_id,
            provider_thread_id: None,
            created_at: input.created_at,
            updated_at: input.created_at,
        };
        if let Some(existing) = self.get_frontend_session(record.external_session_id.as_str())? {
            if existing == record {
                return Ok(existing);
            }
            return Err(policy_error(
                "frontend session binding conflicts with durable state",
            ));
        }
        self.connection
            .execute(
                "INSERT INTO frontend_sessions (
                    external_session_id, frontend, session_id, client_name, protocol_version,
                    cwd, channel_id, provider_thread_id, permission_mode, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8, ?9, ?9)",
                params![
                    record.external_session_id.as_str(),
                    record.frontend.as_str(),
                    record.session_id.to_string(),
                    record.client_name.as_str(),
                    i64::from(record.protocol_version),
                    record.cwd.to_str(),
                    record.channel_id.as_ref().map(ChannelId::as_str),
                    record.permission_mode.as_wire_str(),
                    format_timestamp(record.created_at),
                ],
            )
            .map_err(storage_error)?;
        Ok(record)
    }

    pub fn get_frontend_session(
        &self,
        external_session_id: &str,
    ) -> Result<Option<FrontendSessionRecord>, CarlError> {
        let raw = self
            .connection
            .query_row(
                "SELECT frontend, session_id, client_name, protocol_version, cwd, channel_id,
                        provider_thread_id, permission_mode, created_at, updated_at
                 FROM frontend_sessions
                 WHERE external_session_id = ?1",
                [external_session_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?;
        raw.map(
            |(
                frontend,
                session_id,
                client_name,
                protocol_version,
                cwd,
                channel_id,
                provider_thread_id,
                permission_mode,
                created_at,
                updated_at,
            )| {
                let protocol_version = u32::try_from(protocol_version)
                    .map_err(|_| invalid_stored_value("protocol version", "out of range"))?;
                let permission_mode = permission_mode
                    .parse()
                    .map_err(|_| invalid_stored_value("permission mode", &permission_mode))?;
                Ok(FrontendSessionRecord {
                    frontend: Frontend::parse(&frontend)?,
                    external_session_id: ExternalSessionId::try_from(external_session_id)?,
                    session_id: parse_id("session ID", &session_id)?,
                    cwd: PathBuf::from(cwd),
                    protocol_version,
                    client_name: ClientName::try_from(client_name)?,
                    permission_mode,
                    channel_id: channel_id.map(ChannelId::try_from).transpose()?,
                    provider_thread_id: provider_thread_id
                        .map(ProviderThreadId::try_from)
                        .transpose()?,
                    created_at: parse_timestamp(&created_at)?,
                    updated_at: parse_timestamp(&updated_at)?,
                })
            },
        )
        .transpose()
    }

    pub fn configure_frontend_session(
        &self,
        external_session_id: &ExternalSessionId,
        provider_thread_id: Option<&ProviderThreadId>,
        permission_mode: PermissionMode,
        updated_at: DateTime<Utc>,
    ) -> Result<FrontendSessionRecord, CarlError> {
        let changed = self
            .connection
            .execute(
                "UPDATE frontend_sessions
                 SET provider_thread_id = ?2, permission_mode = ?3, updated_at = ?4
                 WHERE external_session_id = ?1 AND updated_at <= ?4",
                params![
                    external_session_id.as_str(),
                    provider_thread_id.map(ProviderThreadId::as_str),
                    permission_mode.as_wire_str(),
                    format_timestamp(updated_at),
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(policy_error("frontend session is unavailable"));
        }
        self.get_frontend_session(external_session_id.as_str())?
            .ok_or_else(|| storage_invariant("configured frontend session disappeared"))
    }

    pub fn attach_frontend_channel(
        &self,
        external_session_id: &ExternalSessionId,
        channel_id: &ChannelId,
        updated_at: DateTime<Utc>,
    ) -> Result<FrontendSessionRecord, CarlError> {
        let changed = self
            .connection
            .execute(
                "UPDATE frontend_sessions
                 SET channel_id = COALESCE(channel_id, ?2), updated_at = ?3
                 WHERE external_session_id = ?1
                   AND (channel_id IS NULL OR channel_id = ?2)
                   AND updated_at <= ?3",
                params![
                    external_session_id.as_str(),
                    channel_id.as_str(),
                    format_timestamp(updated_at),
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(policy_error(
                "frontend channel binding conflicts with durable state",
            ));
        }
        self.get_frontend_session(external_session_id.as_str())?
            .ok_or_else(|| storage_invariant("attached frontend session disappeared"))
    }

    /// Atomically move a stable Buzz channel from a prior process-owned branch to
    /// the newly created branch for the same canonical workspace.
    pub fn claim_frontend_channel(
        &self,
        external_session_id: &ExternalSessionId,
        channel_id: &ChannelId,
        updated_at: DateTime<Utc>,
    ) -> Result<FrontendSessionRecord, CarlError> {
        let target = self
            .get_frontend_session(external_session_id.as_str())?
            .ok_or_else(|| storage_invariant("frontend channel target is missing"))?;
        if target.frontend != Frontend::Buzz
            || target
                .channel_id
                .as_ref()
                .is_some_and(|existing| existing != channel_id)
            || target.updated_at > updated_at
        {
            return Err(policy_error(
                "frontend channel claim conflicts with durable state",
            ));
        }
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(storage_error)?;
        transaction
            .execute(
                "DELETE FROM remote_codes
                 WHERE external_session_id IN (
                    SELECT external_session_id FROM frontend_sessions
                    WHERE external_session_id != ?1 AND frontend = 'buzz'
                      AND channel_id = ?2 AND cwd = ?3
                 )",
                params![
                    external_session_id.as_str(),
                    channel_id.as_str(),
                    target.cwd.to_str(),
                ],
            )
            .map_err(storage_error)?;
        transaction
            .execute(
                "UPDATE frontend_sessions
                 SET channel_id = NULL, updated_at = ?4
                 WHERE external_session_id != ?1 AND frontend = 'buzz'
                   AND channel_id = ?2 AND cwd = ?3",
                params![
                    external_session_id.as_str(),
                    channel_id.as_str(),
                    target.cwd.to_str(),
                    format_timestamp(updated_at),
                ],
            )
            .map_err(storage_error)?;
        let changed = transaction
            .execute(
                "UPDATE frontend_sessions
                 SET channel_id = COALESCE(channel_id, ?2), updated_at = ?3
                 WHERE external_session_id = ?1
                   AND (channel_id IS NULL OR channel_id = ?2)",
                params![
                    external_session_id.as_str(),
                    channel_id.as_str(),
                    format_timestamp(updated_at),
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(policy_error("frontend channel claim was not applied"));
        }
        transaction.commit().map_err(storage_error)?;
        self.get_frontend_session(external_session_id.as_str())?
            .ok_or_else(|| storage_invariant("claimed frontend session disappeared"))
    }

    pub fn create_remote_code(
        &self,
        input: NewRemoteCode<'_>,
    ) -> Result<RemoteCodeRecord, CarlError> {
        validate_remote_display_code(input.display_code)?;
        validate_remote_code_shape(
            input.kind,
            input.approval_id,
            input.provider_request_id.as_ref(),
        )?;
        let lifetime = input.expires_at.signed_duration_since(input.created_at);
        if lifetime <= chrono::TimeDelta::zero() || lifetime > MAX_BOUND_APPROVAL_LIFETIME {
            return Err(CarlError::Validation {
                detail: "remote code lifetime is invalid".to_owned(),
            });
        }
        let record = RemoteCodeRecord {
            code_digest: remote_code_digest(input.display_code),
            kind: input.kind,
            external_session_id: input.external_session_id,
            approval_id: input.approval_id,
            provider_request_id: input.provider_request_id,
            request_digest: input.request_digest,
            actor_id: input.actor_id,
            created_at: input.created_at,
            expires_at: input.expires_at,
            consumed_at: None,
        };
        self.connection
            .execute(
                "INSERT INTO remote_codes (
                    code_digest, kind, external_session_id, approval_id, provider_request_id,
                    request_digest, actor_id, created_at, expires_at, consumed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)",
                params![
                    record.code_digest.to_string(),
                    record.kind.as_str(),
                    record.external_session_id.as_str(),
                    record.approval_id.map(|id| id.to_string()),
                    record
                        .provider_request_id
                        .as_ref()
                        .map(ProviderRequestId::as_str),
                    record.request_digest.to_string(),
                    record.actor_id.as_str(),
                    format_timestamp(record.created_at),
                    format_timestamp(record.expires_at),
                ],
            )
            .map_err(storage_error)?;
        Ok(record)
    }

    pub fn get_remote_code(
        &self,
        code_digest: Sha256Digest,
    ) -> Result<Option<RemoteCodeRecord>, CarlError> {
        let raw = self
            .connection
            .query_row(
                "SELECT kind, external_session_id, approval_id, provider_request_id,
                        request_digest, actor_id, created_at, expires_at, consumed_at
                 FROM remote_codes WHERE code_digest = ?1",
                [code_digest.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, Option<String>>(8)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?;
        raw.map(
            |(
                kind,
                external_session_id,
                approval_id,
                provider_request_id,
                request_digest,
                actor_id,
                created_at,
                expires_at,
                consumed_at,
            )| {
                Ok(RemoteCodeRecord {
                    code_digest,
                    kind: RemoteCodeKind::parse(&kind)?,
                    external_session_id: ExternalSessionId::try_from(external_session_id)?,
                    approval_id: approval_id
                        .as_deref()
                        .map(|value| parse_id("approval ID", value))
                        .transpose()?,
                    provider_request_id: provider_request_id
                        .map(ProviderRequestId::try_from)
                        .transpose()?,
                    request_digest: Sha256Digest::parse(request_digest)?,
                    actor_id: ActorId::parse(actor_id)?,
                    created_at: parse_timestamp(&created_at)?,
                    expires_at: parse_timestamp(&expires_at)?,
                    consumed_at: consumed_at.as_deref().map(parse_timestamp).transpose()?,
                })
            },
        )
        .transpose()
    }

    pub fn consume_remote_code(
        &mut self,
        claim: RemoteCodeClaim<'_>,
    ) -> Result<RemoteCodeRecord, CarlError> {
        validate_remote_display_code(claim.display_code)?;
        validate_remote_code_shape(
            claim.kind,
            claim.approval_id,
            claim.provider_request_id.as_ref(),
        )?;
        let code_digest = remote_code_digest(claim.display_code);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let existing = load_remote_code(&transaction, code_digest)?
            .ok_or_else(|| policy_error("remote code is unavailable"))?;
        if existing.kind != claim.kind
            || existing.external_session_id != claim.external_session_id
            || existing.approval_id != claim.approval_id
            || existing.provider_request_id != claim.provider_request_id
            || existing.request_digest != claim.request_digest
            || existing.actor_id != claim.actor_id
            || existing.consumed_at.is_some()
            || claim.now >= existing.expires_at
        {
            return Err(policy_error("remote code does not match the request"));
        }
        let changed = transaction
            .execute(
                "UPDATE remote_codes SET consumed_at = ?2
                 WHERE code_digest = ?1 AND consumed_at IS NULL AND expires_at > ?2",
                params![code_digest.to_string(), format_timestamp(claim.now)],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(policy_error("remote code is unavailable"));
        }
        transaction.commit().map_err(storage_error)?;
        self.get_remote_code(code_digest)?
            .ok_or_else(|| storage_invariant("consumed remote code disappeared"))
    }

    /// Atomically consume an approval display code and resolve its exact bound
    /// approval. This prevents a crash between code consumption and approval
    /// resolution from making a provider request appear reusable.
    pub fn consume_remote_bound_approval(
        &mut self,
        claim: RemoteCodeClaim<'_>,
        binding: &BoundApprovalBinding,
        status: ApprovalStatus,
    ) -> Result<RemoteCodeRecord, CarlError> {
        validate_remote_display_code(claim.display_code)?;
        validate_remote_code_shape(
            claim.kind,
            claim.approval_id,
            claim.provider_request_id.as_ref(),
        )?;
        if claim.kind != RemoteCodeKind::Approval
            || !matches!(status, ApprovalStatus::Allowed | ApprovalStatus::Denied)
            || claim.request_digest != binding.request_digest()
            || claim.actor_id != *binding.actor_id()
            || claim.now >= binding.expires_at()
        {
            return Err(policy_error("remote approval claim is invalid"));
        }
        let approval_id = claim
            .approval_id
            .ok_or_else(|| policy_error("remote approval has no bound approval"))?;
        let code_digest = remote_code_digest(claim.display_code);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let existing = load_remote_code(&transaction, code_digest)?
            .ok_or_else(|| policy_error("remote code is unavailable"))?;
        if existing.kind != claim.kind
            || existing.external_session_id != claim.external_session_id
            || existing.approval_id != claim.approval_id
            || existing.provider_request_id != claim.provider_request_id
            || existing.request_digest != claim.request_digest
            || existing.actor_id != claim.actor_id
            || existing.consumed_at.is_some()
            || claim.now >= existing.expires_at
        {
            return Err(policy_error("remote code does not match the request"));
        }
        let raw = transaction
            .query_row(
                "SELECT session_id, turn_id, tool_call_id, actor_id, request_digest,
                        summary, status, created_at, expires_at, resolved_at, consumed_at
                 FROM bound_approvals WHERE id = ?1",
                [approval_id.to_string()],
                raw_bound_approval,
            )
            .optional()
            .map_err(storage_error)?
            .ok_or_else(|| policy_error("bound approval is unavailable"))?;
        let approval = bound_record_from_raw(approval_id, raw)?;
        if approval.binding != *binding
            || approval.status != ApprovalStatus::Pending
            || approval.consumed_at.is_some()
            || claim.now >= approval.binding.expires_at()
        {
            return Err(policy_error("bound approval does not match the request"));
        }
        let timestamp = format_timestamp(claim.now);
        let code_changed = transaction
            .execute(
                "UPDATE remote_codes SET consumed_at = ?2
                 WHERE code_digest = ?1 AND consumed_at IS NULL AND expires_at > ?2",
                params![code_digest.to_string(), timestamp],
            )
            .map_err(storage_error)?;
        let approval_changed = transaction
            .execute(
                "UPDATE bound_approvals
                 SET status = ?2, resolved_at = ?3,
                     consumed_at = CASE WHEN ?2 = 'allowed' THEN ?3 ELSE NULL END
                 WHERE id = ?1 AND status = 'pending' AND consumed_at IS NULL
                   AND expires_at > ?3",
                params![approval_id.to_string(), status.as_str(), timestamp],
            )
            .map_err(storage_error)?;
        if code_changed != 1 || approval_changed != 1 {
            return Err(policy_error("remote approval is unavailable"));
        }
        transaction.commit().map_err(storage_error)?;
        Ok(RemoteCodeRecord {
            consumed_at: Some(claim.now),
            ..existing
        })
    }

    pub fn create_delivery(&self, input: NewDelivery) -> Result<DeliveryRecord, CarlError> {
        let record = DeliveryRecord {
            action_digest: input.action_digest,
            external_session_id: input.external_session_id,
            kind: input.kind,
            status: DeliveryStatus::Pending,
            created_at: input.created_at,
            updated_at: input.created_at,
        };
        self.connection
            .execute(
                "INSERT INTO frontend_deliveries (
                    action_digest, external_session_id, kind, status, created_at, updated_at
                 ) VALUES (?1, ?2, ?3, 'pending', ?4, ?4)",
                params![
                    record.action_digest.to_string(),
                    record.external_session_id.as_str(),
                    record.kind.as_str(),
                    format_timestamp(record.created_at),
                ],
            )
            .map_err(storage_error)?;
        Ok(record)
    }

    pub fn get_delivery(
        &self,
        action_digest: Sha256Digest,
    ) -> Result<Option<DeliveryRecord>, CarlError> {
        let raw = self
            .connection
            .query_row(
                "SELECT external_session_id, kind, status, created_at, updated_at
                 FROM frontend_deliveries WHERE action_digest = ?1",
                [action_digest.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?;
        raw.map(
            |(external_session_id, kind, status, created_at, updated_at)| {
                Ok(DeliveryRecord {
                    action_digest,
                    external_session_id: ExternalSessionId::try_from(external_session_id)?,
                    kind: DeliveryKind::parse(&kind)?,
                    status: DeliveryStatus::parse(&status)?,
                    created_at: parse_timestamp(&created_at)?,
                    updated_at: parse_timestamp(&updated_at)?,
                })
            },
        )
        .transpose()
    }

    pub fn transition_delivery(
        &self,
        action_digest: Sha256Digest,
        status: DeliveryStatus,
        updated_at: DateTime<Utc>,
    ) -> Result<DeliveryRecord, CarlError> {
        if status == DeliveryStatus::Pending {
            return Err(CarlError::Validation {
                detail: "delivery must transition to a terminal status".to_owned(),
            });
        }
        let changed = self
            .connection
            .execute(
                "UPDATE frontend_deliveries SET status = ?2, updated_at = ?3
                 WHERE action_digest = ?1 AND status = 'pending' AND created_at <= ?3",
                params![
                    action_digest.to_string(),
                    status.as_str(),
                    format_timestamp(updated_at),
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(policy_error("delivery is unavailable or already terminal"));
        }
        self.get_delivery(action_digest)?
            .ok_or_else(|| storage_invariant("transitioned delivery disappeared"))
    }

    pub fn append(
        &mut self,
        session_id: SessionId,
        turn_id: Option<TurnId>,
        event: Event,
    ) -> Result<EventEnvelope, CarlError> {
        if is_subscription_run_event(&event) {
            return Err(CarlError::Validation {
                detail: "subscription run events require the transactional run API".to_owned(),
            });
        }
        if matches!(event, Event::TaskLifecycle { .. }) {
            return Err(CarlError::Validation {
                detail: "task lifecycle events require the transactional task API".to_owned(),
            });
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let envelope =
            append_event_in_transaction(&transaction, session_id, turn_id, event, Utc::now())?;
        transaction.commit().map_err(storage_error)?;

        Ok(envelope)
    }

    pub fn read_events(&self, session_id: SessionId) -> Result<Vec<EventEnvelope>, CarlError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, turn_id, sequence, timestamp, schema_version, event_json
                 FROM events
                 WHERE session_id = ?1
                 ORDER BY sequence ASC",
            )
            .map_err(storage_error)?;
        let rows = statement
            .query_map([session_id.to_string()], |row| {
                Ok(RawEvent {
                    id: row.get(0)?,
                    turn_id: row.get(1)?,
                    sequence: row.get(2)?,
                    timestamp: row.get(3)?,
                    schema_version: row.get(4)?,
                    event_json: row.get(5)?,
                })
            })
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;

        rows.into_iter()
            .map(|row| row.into_envelope(session_id))
            .collect()
    }

    pub fn create_task(&mut self, input: NewTask) -> Result<TaskRecord, CarlError> {
        let workspace = fs::canonicalize(&input.workspace).map_err(|_| CarlError::Validation {
            detail: "task workspace is unavailable".to_owned(),
        })?;
        if !workspace.is_dir() {
            return Err(CarlError::Validation {
                detail: "task workspace is not a directory".to_owned(),
            });
        }
        let task_id = TaskId::new();
        let created_event = TaskEvent::Created {
            session_id: input.session_id,
            workspace: workspace.clone(),
            contract: input.contract,
            budget: input.budget,
            model: input.model.clone(),
            effort: input.effort,
            permission_mode: input.permission_mode,
        };
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let envelope = append_event_in_transaction(
            &transaction,
            input.session_id,
            None,
            Event::TaskLifecycle {
                task_id,
                event: created_event,
            },
            input.created_at,
        )?;
        let snapshot = reduce_task(None, &envelope).map_err(task_reduce_error)?;
        insert_task_projection(
            &transaction,
            &snapshot,
            &workspace,
            &input.model,
            input.effort,
            input.permission_mode,
            input.created_at,
        )?;
        transaction.commit().map_err(storage_error)?;
        Ok(TaskRecord {
            revision: snapshot.revision,
            snapshot,
            created_at: input.created_at,
            updated_at: input.created_at,
        })
    }

    pub fn append_task_event(
        &mut self,
        task_id: TaskId,
        expected_revision: u64,
        event: TaskEvent,
        at: DateTime<Utc>,
    ) -> Result<Option<TaskRecord>, CarlError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let Some(current) = load_task_record(&transaction, task_id)? else {
            return Ok(None);
        };
        if current.revision != expected_revision {
            return Ok(None);
        }
        let envelope = append_event_in_transaction(
            &transaction,
            current.snapshot.session_id,
            None,
            Event::TaskLifecycle { task_id, event },
            at,
        )?;
        let snapshot = reduce_task(Some(current.snapshot), &envelope).map_err(task_reduce_error)?;
        apply_task_child_projection(&transaction, task_id, &envelope, &snapshot)?;
        update_task_projection(&transaction, &snapshot, at)?;
        transaction.commit().map_err(storage_error)?;
        Ok(Some(TaskRecord {
            revision: snapshot.revision,
            snapshot,
            created_at: current.created_at,
            updated_at: at,
        }))
    }

    pub fn commit_checkpoint(
        &mut self,
        input: NewCheckpoint,
        expected_task_revision: u64,
    ) -> Result<Option<CheckpointRecord>, CarlError> {
        validate_checkpoint_input(&input)?;
        let checkpoint_json = String::from_utf8(
            input
                .checkpoint
                .canonical_bytes()
                .map_err(checkpoint_validation_error)?,
        )
        .map_err(|_| checkpoint_validation("canonical checkpoint is not UTF-8"))?;
        let package_json = String::from_utf8(
            input
                .context_package
                .canonical_bytes()
                .map_err(context_validation_error)?,
        )
        .map_err(|_| checkpoint_validation("canonical context package is not UTF-8"))?;

        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let Some(current) = load_task_record(&transaction, input.task_id)? else {
            return Ok(None);
        };
        if current.revision != expected_task_revision {
            return Ok(None);
        }
        validate_checkpoint_history(&transaction, &current, &input)?;
        validate_checkpoint_authority(&transaction, &current, &input.checkpoint)?;
        validate_checkpoint_artifacts(&transaction, &input.checkpoint)?;

        let envelope = append_event_in_transaction(
            &transaction,
            current.snapshot.session_id,
            None,
            Event::TaskLifecycle {
                task_id: input.task_id,
                event: TaskEvent::CheckpointCommitted {
                    checkpoint_id: input.checkpoint.checkpoint_id,
                    digest: input.checkpoint_digest.clone(),
                },
            },
            input.created_at,
        )?;
        let snapshot = reduce_task(Some(current.snapshot), &envelope).map_err(task_reduce_error)?;
        let event_sequence = revision_to_sql(envelope.sequence)?;
        let timestamp = format_timestamp(input.created_at);
        transaction
            .execute(
                "INSERT INTO task_checkpoints (
                    id, task_id, digest, event_sequence, checkpoint_json, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    input.checkpoint.checkpoint_id.to_string(),
                    input.task_id.to_string(),
                    input.checkpoint_digest,
                    event_sequence,
                    checkpoint_json,
                    timestamp,
                ],
            )
            .map_err(storage_error)?;
        transaction
            .execute(
                "INSERT INTO task_context_packages (
                    id, task_id, checkpoint_id, generation, event_sequence,
                    package_json, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    input.context_package.package_id.to_string(),
                    input.task_id.to_string(),
                    input.checkpoint.checkpoint_id.to_string(),
                    i64::from(input.checkpoint.compaction_generation),
                    event_sequence,
                    package_json,
                    timestamp,
                ],
            )
            .map_err(storage_error)?;
        update_task_projection(&transaction, &snapshot, input.created_at)?;
        transaction.commit().map_err(storage_error)?;
        Ok(Some(CheckpointRecord {
            checkpoint: input.checkpoint,
            checkpoint_digest: input.checkpoint_digest,
            context_package_digest: input.context_package_digest,
            created_at: input.created_at,
        }))
    }

    pub fn get_task(&self, task_id: TaskId) -> Result<Option<TaskRecord>, CarlError> {
        load_task_record(&self.connection, task_id)
    }

    pub fn get_latest_task_checkpoint(
        &self,
        task_id: TaskId,
    ) -> Result<Option<CanonicalCheckpoint>, CarlError> {
        let Some(record) = self.get_task(task_id)? else {
            return Ok(None);
        };
        let Some(checkpoint_id) = record.snapshot.latest_checkpoint else {
            return Ok(None);
        };
        let raw = self
            .connection
            .query_row(
                "SELECT digest, checkpoint_json FROM task_checkpoints
                 WHERE task_id = ?1 AND id = ?2",
                params![task_id.to_string(), checkpoint_id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()
            .map_err(storage_error)?;
        let Some((stored_digest, Some(checkpoint_json))) = raw else {
            return Err(storage_invariant(
                "latest task checkpoint has no canonical payload",
            ));
        };
        let checkpoint = serde_json::from_str::<CanonicalCheckpoint>(&checkpoint_json)
            .map_err(|_| storage_invariant("latest task checkpoint is invalid"))?;
        if checkpoint.task_id != task_id
            || checkpoint.checkpoint_id != checkpoint_id
            || checkpoint
                .digest()
                .map_err(|_| storage_invariant("latest task checkpoint is invalid"))?
                != stored_digest
        {
            return Err(storage_invariant(
                "latest task checkpoint does not match its projection",
            ));
        }
        Ok(Some(checkpoint))
    }

    pub fn list_resumable_tasks(&self) -> Result<Vec<TaskRecord>, CarlError> {
        let mut records = Vec::new();
        visit_authoritative_task_records(&self.connection, |record| {
            if !record.snapshot.status.is_terminal() {
                records.push(record);
            }
            Ok(())
        })?;
        records.sort_by(|left, right| {
            left.updated_at
                .cmp(&right.updated_at)
                .then_with(|| left.snapshot.task_id.cmp(&right.snapshot.task_id))
        });
        Ok(records)
    }

    pub fn read_task_events(&self, task_id: TaskId) -> Result<Vec<EventEnvelope>, CarlError> {
        let mut events = Vec::new();
        let mut after_sequence = None;
        loop {
            let page = self.read_task_event_page(task_id, after_sequence, 512)?;
            if page.is_empty() {
                break;
            }
            after_sequence = page.last().map(|event| event.sequence);
            events.extend(page);
        }
        Ok(events)
    }

    pub fn read_task_event_page(
        &self,
        task_id: TaskId,
        after_sequence: Option<u64>,
        limit: u16,
    ) -> Result<Vec<EventEnvelope>, CarlError> {
        read_task_event_page_from_connection(&self.connection, task_id, after_sequence, limit)
    }

    pub fn set_session_delegate_settings(
        &self,
        session_id: SessionId,
        settings: DelegateSettings,
        updated_at: DateTime<Utc>,
    ) -> Result<SessionDelegateSettingsRecord, CarlError> {
        if settings.model().is_none() && settings.effort().is_none() {
            return Err(CarlError::Validation {
                detail: "session delegate settings cannot be empty".to_owned(),
            });
        }
        self.connection
            .execute(
                "INSERT INTO session_delegate_settings (
                    session_id, provider, model, effort, updated_at
                 ) VALUES (?1, 'codex', ?2, ?3, ?4)
                 ON CONFLICT (session_id, provider) DO UPDATE SET
                    model = excluded.model,
                    effort = excluded.effort,
                    updated_at = excluded.updated_at",
                params![
                    session_id.to_string(),
                    settings.model().map(ModelId::as_str),
                    settings.effort().map(ReasoningEffort::as_codex_value),
                    format_timestamp(updated_at),
                ],
            )
            .map_err(storage_error)?;
        Ok(SessionDelegateSettingsRecord {
            session_id,
            settings,
            updated_at,
        })
    }

    pub fn get_session_delegate_settings(
        &self,
        session_id: SessionId,
    ) -> Result<Option<SessionDelegateSettingsRecord>, CarlError> {
        let row = self
            .connection
            .query_row(
                "SELECT model, effort, updated_at
                 FROM session_delegate_settings
                 WHERE session_id = ?1 AND provider = 'codex'",
                [session_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?;
        row.map(|(model, effort, updated_at)| {
            Ok(SessionDelegateSettingsRecord {
                session_id,
                settings: parse_delegate_settings(model.as_deref(), effort.as_deref())?,
                updated_at: parse_timestamp(&updated_at)?,
            })
        })
        .transpose()
    }

    pub fn create_subscription_run(
        &mut self,
        request: NewSubscriptionRun,
    ) -> Result<SubscriptionRunRecord, CarlError> {
        validate_new_subscription_run(&request)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        validate_persisted_session_configuration(
            &transaction,
            request.session_id,
            &request.configuration,
        )?;
        insert_subscription_run(&transaction, &request)?;
        let event = Event::SubscriptionRunPrepared {
            run_id: request.id,
            run_sequence: 1,
            configuration: request.configuration.clone(),
            state: RunState::Prepared,
            trust_label: RunTrustLabel::TrustedCarlState,
        };
        let envelope = append_event_in_transaction(
            &transaction,
            request.session_id,
            Some(request.turn_id),
            event,
            request.created_at,
        )?;
        link_subscription_run_event(&transaction, request.id, 1, envelope.id)?;
        transaction.commit().map_err(storage_error)?;

        Ok(SubscriptionRunRecord {
            id: request.id,
            session_id: request.session_id,
            turn_id: request.turn_id,
            state: RunState::Prepared,
            revision: 1,
            per_run_settings: request.per_run_settings,
            configuration: request.configuration,
            provider_configuration_observed: false,
            failure_code: None,
            created_at: request.created_at,
            updated_at: request.created_at,
        })
    }

    pub fn get_subscription_run(
        &self,
        id: RunId,
    ) -> Result<Option<SubscriptionRunRecord>, CarlError> {
        load_subscription_run(&self.connection, id)
    }

    pub fn read_subscription_run_events(
        &self,
        run_id: RunId,
    ) -> Result<Vec<EventEnvelope>, CarlError> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(storage_error)?;
        let projection = load_subscription_run(&transaction, run_id)?
            .ok_or_else(|| storage_invariant("subscription run is unavailable"))?;
        let events = load_and_validate_subscription_run_events(&transaction, &projection)?;
        transaction.commit().map_err(storage_error)?;
        Ok(events)
    }

    fn record_subscription_run_baseline(
        &mut self,
        run_id: RunId,
        expected_state: RunState,
        expected_revision: u64,
        baseline: &SealedBaseline,
        artifacts: &ArtifactStore,
        created_at: DateTime<Utc>,
    ) -> Result<Option<SubscriptionRunBaselineRecord>, CarlError> {
        if expected_state != RunState::Prepared {
            return Err(CarlError::Validation {
                detail: "a sealed baseline can only be recorded for a prepared run".to_owned(),
            });
        }
        let (manifest_bytes, source_preconditions_bytes) = validate_sealed_baseline(baseline)?;
        let directory_manifest = canonical_baseline_directories(baseline.directories())?;
        let directory_manifest_digest = digest_bytes(&directory_manifest);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        if !subscription_run_matches(&transaction, run_id, expected_state, expected_revision)? {
            transaction.commit().map_err(storage_error)?;
            return Ok(None);
        }
        if subscription_run_has_baseline(&transaction, run_id)? {
            return Err(CarlError::Validation {
                detail: "the subscription run baseline is already recorded".to_owned(),
            });
        }

        register_artifact_object(
            &transaction,
            baseline.manifest_artifact_id(),
            usize_to_u64(manifest_bytes.len(), "baseline manifest length")?,
            created_at,
        )?;
        register_artifact_object(
            &transaction,
            baseline.source_preconditions_artifact_id(),
            usize_to_u64(
                source_preconditions_bytes.len(),
                "source preconditions length",
            )?,
            created_at,
        )?;
        transaction
            .execute(
                "INSERT INTO subscription_run_baselines (
                    run_id, manifest_artifact_id, manifest_digest,
                    source_preconditions_artifact_id, source_preconditions_digest,
                    entry_count, total_bytes,
                    directory_count, directory_manifest_digest, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    run_id.to_string(),
                    baseline.manifest_artifact_id().as_str(),
                    baseline.manifest().digest().to_string(),
                    baseline.source_preconditions_artifact_id().as_str(),
                    baseline.source_preconditions_digest().to_string(),
                    usize_to_sql(baseline.entries().len(), "baseline entry count")?,
                    revision_to_sql(baseline.manifest().total_bytes())?,
                    usize_to_sql(baseline.directories().len(), "baseline directory count")?,
                    directory_manifest_digest.to_string(),
                    format_timestamp(created_at),
                ],
            )
            .map_err(storage_error)?;
        for (ordinal, entry) in baseline.entries().iter().enumerate() {
            register_artifact_object(
                &transaction,
                entry.content_artifact_id(),
                entry.bytes(),
                created_at,
            )?;
            let identity = entry.source_identity();
            transaction
                .execute(
                    "INSERT INTO subscription_run_baseline_entries (
                        run_id, ordinal, path, byte_length,
                        content_sha256, content_artifact_id,
                        identity_platform, identity_a, identity_b,
                        owner_id, owner_mode
                     ) VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11
                     )",
                    params![
                        run_id.to_string(),
                        usize_to_sql(ordinal, "baseline entry ordinal")?,
                        entry.path(),
                        revision_to_sql(entry.bytes())?,
                        entry.content_digest().to_string(),
                        entry.content_artifact_id().as_str(),
                        identity.platform,
                        identity.identity_a,
                        identity.identity_b,
                        identity.owner_id,
                        identity.owner_mode.map(i64::from),
                    ],
                )
                .map_err(storage_error)?;
        }
        for (ordinal, path) in baseline.directories().iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO subscription_run_baseline_directories (
                        run_id, ordinal, path
                     ) VALUES (?1, ?2, ?3)",
                    params![
                        run_id.to_string(),
                        usize_to_sql(ordinal, "baseline directory ordinal")?,
                        path,
                    ],
                )
                .map_err(storage_error)?;
        }
        verify_sealed_baseline_artifacts(artifacts, baseline)?;
        transaction.commit().map_err(storage_error)?;

        self.get_subscription_run_baseline(run_id)?
            .map(Some)
            .ok_or_else(|| storage_invariant("recorded subscription run baseline disappeared"))
    }

    fn get_subscription_run_baseline(
        &self,
        run_id: RunId,
    ) -> Result<Option<SubscriptionRunBaselineRecord>, CarlError> {
        load_subscription_run_baseline(&self.connection, run_id)
    }

    fn record_subscription_run_no_changes(
        &mut self,
        run_id: RunId,
        expected_state: RunState,
        expected_revision: u64,
        created_at: DateTime<Utc>,
    ) -> Result<Option<SubscriptionRunInspectionRecord>, CarlError> {
        if expected_state != RunState::Inspecting {
            return Err(CarlError::Validation {
                detail: "a no-change result can only be recorded while inspecting".to_owned(),
            });
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        if !subscription_run_matches(&transaction, run_id, expected_state, expected_revision)? {
            transaction.commit().map_err(storage_error)?;
            return Ok(None);
        }
        reject_existing_subscription_run_inspection(&transaction, run_id)?;
        let baseline = load_subscription_run_baseline(&transaction, run_id)?
            .ok_or_else(|| storage_invariant("subscription run has no sealed baseline"))?;
        insert_subscription_run_inspection(
            &transaction,
            run_id,
            SubscriptionRunInspectionOutcome::NoChanges,
            baseline.manifest_digest,
            created_at,
        )?;
        transaction.commit().map_err(storage_error)?;

        self.get_subscription_run_inspection(run_id)?
            .map(Some)
            .ok_or_else(|| storage_invariant("recorded no-change inspection disappeared"))
    }

    fn record_subscription_run_exact_proposal(
        &mut self,
        run_id: RunId,
        expected_state: RunState,
        expected_revision: u64,
        proposal: &ExactReplacementProposal,
        artifacts: &ArtifactStore,
        created_at: DateTime<Utc>,
    ) -> Result<Option<SubscriptionRunProposalRecord>, CarlError> {
        if expected_state != RunState::Inspecting {
            return Err(CarlError::Validation {
                detail: "an exact proposal can only be recorded while inspecting".to_owned(),
            });
        }
        let proposal_envelope = validate_exact_replacement_proposal(proposal)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        if !subscription_run_matches(&transaction, run_id, expected_state, expected_revision)? {
            transaction.commit().map_err(storage_error)?;
            return Ok(None);
        }
        reject_existing_subscription_run_inspection(&transaction, run_id)?;
        let baseline = load_subscription_run_baseline(&transaction, run_id)?
            .ok_or_else(|| storage_invariant("subscription run has no sealed baseline"))?;
        validate_proposal_against_baseline(proposal, &baseline)?;

        register_artifact_object(
            &transaction,
            proposal.artifact_id(),
            usize_to_u64(proposal_envelope.len(), "proposal envelope length")?,
            created_at,
        )?;
        register_artifact_object(
            &transaction,
            proposal.payload_artifact_id(),
            usize_to_u64(proposal.payload().len(), "proposal payload length")?,
            created_at,
        )?;
        insert_subscription_run_inspection(
            &transaction,
            run_id,
            SubscriptionRunInspectionOutcome::ExactReplacement,
            proposal.candidate_manifest_digest(),
            created_at,
        )?;
        transaction
            .execute(
                "INSERT INTO subscription_run_proposals (
                    run_id, outcome, proposal_artifact_id,
                    baseline_manifest_artifact_id, path,
                    expected_live_sha256, before_sha256, after_sha256,
                    payload_sha256, payload_bytes, created_at
                 ) VALUES (
                    ?1, 'exact_replacement', ?2, ?3, ?4,
                    ?5, ?6, ?7, ?8, ?9, ?10
                 )",
                params![
                    run_id.to_string(),
                    proposal.artifact_id().as_str(),
                    baseline.manifest_artifact_id.as_str(),
                    proposal.path(),
                    proposal.expected_live_hash().to_string(),
                    proposal.before_hash().to_string(),
                    proposal.after_hash().to_string(),
                    proposal.payload_hash().to_string(),
                    usize_to_sql(proposal.payload().len(), "proposal payload length")?,
                    format_timestamp(created_at),
                ],
            )
            .map_err(storage_error)?;
        verify_exact_proposal_artifacts(artifacts, proposal)?;
        transaction.commit().map_err(storage_error)?;

        self.get_subscription_run_proposal(run_id)?
            .map(Some)
            .ok_or_else(|| storage_invariant("recorded exact proposal disappeared"))
    }

    fn get_subscription_run_inspection(
        &self,
        run_id: RunId,
    ) -> Result<Option<SubscriptionRunInspectionRecord>, CarlError> {
        let inspection = load_subscription_run_inspection(&self.connection, run_id)?;
        let has_proposal = subscription_run_has_proposal(&self.connection, run_id)?;
        if has_proposal
            != inspection.as_ref().is_some_and(|inspection| {
                inspection.outcome == SubscriptionRunInspectionOutcome::ExactReplacement
            })
        {
            return Err(storage_invariant(
                "subscription run inspection and proposal disagree",
            ));
        }
        Ok(inspection)
    }

    fn get_subscription_run_proposal(
        &self,
        run_id: RunId,
    ) -> Result<Option<SubscriptionRunProposalRecord>, CarlError> {
        let proposal = load_subscription_run_proposal(&self.connection, run_id)?;
        if proposal.is_none() && subscription_run_has_proposal(&self.connection, run_id)? {
            return Err(storage_invariant(
                "subscription run proposal has no matching inspection",
            ));
        }
        Ok(proposal)
    }

    fn get_subscription_run_verification_request(
        &self,
        run_id: RunId,
    ) -> Result<Option<VerificationRequest>, CarlError> {
        load_subscription_run_verification_request(&self.connection, run_id)
    }

    fn get_subscription_run_verification_result(
        &self,
        run_id: RunId,
    ) -> Result<Option<VerificationResult>, CarlError> {
        load_subscription_run_verification_result(&self.connection, run_id)
    }

    fn begin_subscription_run_verification(
        &mut self,
        run_id: RunId,
        expected_revision: u64,
        specification: &VerificationSpec,
        created_at: DateTime<Utc>,
    ) -> Result<Option<VerificationRequest>, CarlError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let Some(mut run) = load_subscription_run(&transaction, run_id)? else {
            transaction.commit().map_err(storage_error)?;
            return Ok(None);
        };
        if run.state != RunState::Inspecting || run.revision != expected_revision {
            transaction.commit().map_err(storage_error)?;
            return Ok(None);
        }
        let baseline = load_subscription_run_baseline(&transaction, run_id)?
            .ok_or_else(|| storage_invariant("subscription run has no sealed baseline"))?;
        let proposal = load_subscription_run_proposal(&transaction, run_id)?
            .ok_or_else(|| storage_invariant("subscription run has no exact proposal"))?;
        let request = VerificationRequest::from_persisted(
            VerificationId::new(),
            run_id,
            &baseline,
            &proposal,
            specification,
        )
        .map_err(verification_storage_error)?;
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| storage_invariant("subscription run revision overflow"))?;
        let evidence = specification.evidence();
        let executable = evidence.executable();
        let limits = specification.limits();
        transaction
            .execute(
                "INSERT INTO subscription_run_verification_requests (
                    id, run_id, started_run_sequence, inspection_outcome,
                    baseline_manifest_artifact_id,
                    source_preconditions_artifact_id,
                    source_preconditions_digest,
                    baseline_directory_manifest_digest,
                    proposal_artifact_id, payload_artifact_id,
                    candidate_manifest_digest, executable_path,
                    executable_metadata_risk, executable_platform_identity,
                    executable_byte_length, executable_content_sha256,
                    executable_attestation_digest, verification_spec_digest,
                    request_digest, argv_digest,
                    environment_profile, execution_timeout_nanos,
                    max_output_bytes, graceful_shutdown_timeout_nanos,
                    forced_shutdown_timeout_nanos, poll_interval_nanos,
                    argv_count, argv_bytes, created_at
                 ) VALUES (
                    ?1, ?2, ?3, 'exact_replacement', ?4, ?5, ?6, ?7,
                    ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                    ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27,
                    ?28
                 )",
                params![
                    request.verification_id().to_string(),
                    run_id.to_string(),
                    revision_to_sql(next_revision)?,
                    request.baseline_manifest_artifact_id().as_str(),
                    request.source_preconditions_artifact_id().as_str(),
                    request.source_preconditions_digest().to_string(),
                    request.baseline_directory_manifest_digest().to_string(),
                    request.proposal_artifact_id().as_str(),
                    request.payload_artifact_id().as_str(),
                    request.candidate_manifest_digest().to_string(),
                    executable.canonical_path(),
                    executable.metadata_risk_tag(),
                    executable.platform_identity_evidence(),
                    revision_to_sql(executable.byte_len())?,
                    executable.content_sha256().to_string(),
                    evidence.executable_attestation_digest().to_string(),
                    request.specification_digest().to_string(),
                    request.request_digest().to_string(),
                    evidence.argument_vector_digest().to_string(),
                    specification.environment_profile().as_storage_str(),
                    duration_to_sql_nanos(
                        limits.execution_timeout(),
                        "verification execution timeout",
                    )?,
                    usize_to_sql(
                        limits.max_output_bytes(),
                        "verification maximum output bytes",
                    )?,
                    duration_to_sql_nanos(
                        limits.graceful_shutdown_timeout(),
                        "verification graceful shutdown timeout",
                    )?,
                    duration_to_sql_nanos(
                        limits.forced_shutdown_timeout(),
                        "verification forced shutdown timeout",
                    )?,
                    duration_to_sql_nanos(limits.poll_interval(), "verification poll interval",)?,
                    usize_to_sql(
                        specification.arguments().len(),
                        "verification argument count",
                    )?,
                    usize_to_sql(evidence.argument_bytes(), "verification argument bytes",)?,
                    format_timestamp(created_at),
                ],
            )
            .map_err(storage_error)?;
        for (ordinal, argument) in specification.arguments().iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO subscription_run_verification_argv (
                        verification_id, ordinal, value
                     ) VALUES (?1, ?2, ?3)",
                    params![
                        request.verification_id().to_string(),
                        usize_to_sql(ordinal, "verification argument ordinal")?,
                        argument,
                    ],
                )
                .map_err(storage_error)?;
        }
        let transition = RunTransition::new(RunState::Inspecting, RunState::Verifying, None)?;
        let changed = transaction
            .execute(
                "UPDATE subscription_runs
                 SET state = ?4, revision = ?5, updated_at = ?6
                 WHERE id = ?1 AND state = ?2 AND revision = ?3",
                params![
                    run_id.to_string(),
                    RunState::Inspecting.as_str(),
                    revision_to_sql(expected_revision)?,
                    RunState::Verifying.as_str(),
                    revision_to_sql(next_revision)?,
                    format_timestamp(created_at),
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(storage_invariant(
                "subscription run changed while beginning verification",
            ));
        }
        let envelope = append_event_in_transaction(
            &transaction,
            run.session_id,
            Some(run.turn_id),
            Event::SubscriptionRunTransitioned {
                run_id,
                run_sequence: next_revision,
                transition,
                trust_label: RunTrustLabel::TrustedCarlState,
            },
            created_at,
        )?;
        link_subscription_run_event(&transaction, run_id, next_revision, envelope.id)?;
        transaction.commit().map_err(storage_error)?;

        run.state = RunState::Verifying;
        run.revision = next_revision;
        run.updated_at = created_at;
        Ok(Some(request))
    }

    fn complete_subscription_run_verification(
        &mut self,
        run_id: RunId,
        expected_revision: u64,
        result: &VerificationResult,
        completed_at: DateTime<Utc>,
    ) -> Result<Option<VerificationCompletionRecord>, CarlError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let Some(mut run) = load_subscription_run(&transaction, run_id)? else {
            transaction.commit().map_err(storage_error)?;
            return Ok(None);
        };
        if run.state != RunState::Verifying || run.revision != expected_revision {
            transaction.commit().map_err(storage_error)?;
            return Ok(None);
        }
        let request = load_subscription_run_verification_request(&transaction, run_id)?
            .ok_or_else(|| storage_invariant("verifying run has no durable request"))?;
        result
            .validate_recomputed(&request)
            .map_err(verification_storage_error)?;
        if result.run_id() != run_id {
            return Err(CarlError::Validation {
                detail: "verification result belongs to a different subscription run".to_owned(),
            });
        }
        if subscription_run_has_verification_result(&transaction, run_id)? {
            return Err(CarlError::Validation {
                detail: "the subscription run verification result is already recorded".to_owned(),
            });
        }
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| storage_invariant("subscription run revision overflow"))?;
        let (next_state, failure_code) = match result.outcome() {
            VerificationOutcome::Passed => (RunState::AwaitingPromotionApproval, None),
            VerificationOutcome::Cancelled => (RunState::Cancelled, None),
            _ => (RunState::Failed, Some(RunFailureCode::VerificationFailed)),
        };
        let transition = RunTransition::new(RunState::Verifying, next_state, failure_code)?;
        let maximum_output_bytes = request.specification().limits().max_output_bytes();
        transaction
            .execute(
                "INSERT INTO subscription_run_verification_results (
                    verification_id, run_id, completed_run_sequence,
                    request_digest, expected_candidate_manifest_digest,
                    expected_directory_manifest_digest, outcome, exit_code,
                    observed_candidate_manifest_digest,
                    observed_directory_manifest_digest,
                    executable_attestation_evidence,
                    executable_attestation_digest,
                    stdout_text, stdout_bytes, stdout_digest,
                    stderr_text, stderr_bytes, stderr_digest,
                    max_output_bytes, duration_nanos, result_digest,
                    completed_at
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                    ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                    ?21, ?22
                 )",
                params![
                    result.verification_id().to_string(),
                    run_id.to_string(),
                    revision_to_sql(next_revision)?,
                    result.request_digest().to_string(),
                    result.expected_candidate_manifest_digest().to_string(),
                    result.expected_directory_manifest_digest().to_string(),
                    result.outcome().as_storage_str(),
                    result.exit_code(),
                    result
                        .observed_candidate_manifest_digest()
                        .map(|digest| digest.to_string()),
                    result
                        .observed_directory_manifest_digest()
                        .map(|digest| digest.to_string()),
                    result.executable_attestation_evidence(),
                    result.executable_attestation_digest().to_string(),
                    result.stdout().text(),
                    revision_to_sql(result.stdout().byte_length())?,
                    result.stdout().digest().to_string(),
                    result.stderr().text(),
                    revision_to_sql(result.stderr().byte_length())?,
                    result.stderr().digest().to_string(),
                    usize_to_sql(maximum_output_bytes, "verification maximum output bytes",)?,
                    duration_to_sql_nanos(result.duration(), "verification result duration")?,
                    result.result_digest().to_string(),
                    format_timestamp(completed_at),
                ],
            )
            .map_err(storage_error)?;
        let changed = transaction
            .execute(
                "UPDATE subscription_runs
                 SET state = ?4, revision = ?5, failure_code = ?6, updated_at = ?7
                 WHERE id = ?1 AND state = ?2 AND revision = ?3",
                params![
                    run_id.to_string(),
                    RunState::Verifying.as_str(),
                    revision_to_sql(expected_revision)?,
                    next_state.as_str(),
                    revision_to_sql(next_revision)?,
                    failure_code.map(RunFailureCode::as_str),
                    format_timestamp(completed_at),
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(storage_invariant(
                "subscription run changed while completing verification",
            ));
        }
        let envelope = append_event_in_transaction(
            &transaction,
            run.session_id,
            Some(run.turn_id),
            Event::SubscriptionRunTransitioned {
                run_id,
                run_sequence: next_revision,
                transition,
                trust_label: RunTrustLabel::TrustedCarlVerification,
            },
            completed_at,
        )?;
        link_subscription_run_event(&transaction, run_id, next_revision, envelope.id)?;
        transaction.commit().map_err(storage_error)?;

        run.state = next_state;
        run.revision = next_revision;
        run.failure_code = failure_code;
        run.updated_at = completed_at;
        let committed_result = result.clone();
        let verified_proposal = if committed_result.outcome() == VerificationOutcome::Passed {
            Some(
                VerifiedProposal::from_committed_result(&request, &committed_result)
                    .map_err(|_| storage_invariant("committed verification result is invalid"))?,
            )
        } else {
            None
        };
        Ok(Some(VerificationCompletionRecord {
            run,
            result: committed_result,
            verified_proposal,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_subscription_run_provider_configuration(
        &mut self,
        id: RunId,
        expected_state: RunState,
        expected_revision: u64,
        provider_model: ProviderReported<ModelId>,
        provider_effort: ProviderReported<ReasoningEffort>,
        updated_at: DateTime<Utc>,
    ) -> Result<Option<SubscriptionRunRecord>, CarlError> {
        if expected_state != RunState::Running {
            return Err(CarlError::Validation {
                detail: "provider configuration can only be observed for a running delegate"
                    .to_owned(),
            });
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let Some(mut record) = load_subscription_run(&transaction, id)? else {
            transaction.commit().map_err(storage_error)?;
            return Ok(None);
        };
        if record.state != expected_state || record.revision != expected_revision {
            transaction.commit().map_err(storage_error)?;
            return Ok(None);
        }
        if record.provider_configuration_observed {
            return Err(CarlError::Validation {
                detail: "provider configuration was already observed".to_owned(),
            });
        }

        let next_revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| storage_invariant("subscription run revision overflow"))?;
        let configuration = record
            .configuration
            .with_provider_reported(provider_model, provider_effort);
        let (provider_model_status, provider_model_value) =
            provider_model_parts(configuration.provider_model());
        let (provider_effort_status, provider_effort_value) =
            provider_effort_parts(configuration.provider_effort());
        let changed = transaction
            .execute(
                "UPDATE subscription_runs
                 SET revision = ?4,
                     provider_model_status = ?5,
                     provider_model_value = ?6,
                     provider_effort_status = ?7,
                     provider_effort_value = ?8,
                     provider_configuration_observed = 1,
                     updated_at = ?9
                 WHERE id = ?1 AND state = ?2 AND revision = ?3",
                params![
                    id.to_string(),
                    expected_state.as_str(),
                    revision_to_sql(expected_revision)?,
                    revision_to_sql(next_revision)?,
                    provider_model_status,
                    provider_model_value,
                    provider_effort_status,
                    provider_effort_value,
                    format_timestamp(updated_at),
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(storage_invariant(
                "subscription run changed while recording provider configuration",
            ));
        }
        let envelope = append_event_in_transaction(
            &transaction,
            record.session_id,
            Some(record.turn_id),
            Event::SubscriptionRunConfigurationObserved {
                run_id: id,
                run_sequence: next_revision,
                configuration: configuration.clone(),
                trust_label: RunTrustLabel::UntrustedProviderEvidence,
            },
            updated_at,
        )?;
        link_subscription_run_event(&transaction, id, next_revision, envelope.id)?;
        transaction.commit().map_err(storage_error)?;

        record.revision = next_revision;
        record.configuration = configuration;
        record.provider_configuration_observed = true;
        record.updated_at = updated_at;
        Ok(Some(record))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compare_and_transition_subscription_run(
        &mut self,
        id: RunId,
        expected_state: RunState,
        expected_revision: u64,
        transition: RunTransition,
        trust_label: RunTrustLabel,
        updated_at: DateTime<Utc>,
    ) -> Result<Option<SubscriptionRunRecord>, CarlError> {
        if transition.from() != expected_state {
            return Err(CarlError::Validation {
                detail: "subscription run transition does not match its precondition".to_owned(),
            });
        }
        if transition.to() == RunState::Verifying || transition.from() == RunState::Verifying {
            return Err(CarlError::Validation {
                detail: "the dedicated verification APIs must own verification transitions"
                    .to_owned(),
            });
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let Some(mut record) = load_subscription_run(&transaction, id)? else {
            transaction.commit().map_err(storage_error)?;
            return Ok(None);
        };
        if record.state != expected_state || record.revision != expected_revision {
            transaction.commit().map_err(storage_error)?;
            return Ok(None);
        }

        let next_revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| storage_invariant("subscription run revision overflow"))?;
        let changed = transaction
            .execute(
                "UPDATE subscription_runs
                 SET state = ?4, revision = ?5, failure_code = ?6, updated_at = ?7
                 WHERE id = ?1 AND state = ?2 AND revision = ?3",
                params![
                    id.to_string(),
                    expected_state.as_str(),
                    revision_to_sql(expected_revision)?,
                    transition.to().as_str(),
                    revision_to_sql(next_revision)?,
                    transition.failure_code().map(RunFailureCode::as_str),
                    format_timestamp(updated_at),
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(storage_invariant(
                "subscription run changed while holding an immediate transaction",
            ));
        }
        let event = Event::SubscriptionRunTransitioned {
            run_id: id,
            run_sequence: next_revision,
            transition: transition.clone(),
            trust_label,
        };
        let envelope = append_event_in_transaction(
            &transaction,
            record.session_id,
            Some(record.turn_id),
            event,
            updated_at,
        )?;
        link_subscription_run_event(&transaction, id, next_revision, envelope.id)?;
        transaction.commit().map_err(storage_error)?;

        record.state = transition.to();
        record.revision = next_revision;
        record.failure_code = transition.failure_code();
        record.updated_at = updated_at;
        Ok(Some(record))
    }

    fn interrupt_abandoned_subscription_runs(
        &mut self,
        updated_at: DateTime<Utc>,
    ) -> Result<Vec<SubscriptionRunRecord>, CarlError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let raw_runs = {
            let mut statement = transaction
                .prepare(
                    "SELECT id, session_id, turn_id, state, revision,
                            per_run_model, per_run_effort,
                            resolved_model, resolved_effort, model_source, effort_source,
                            provider_model_status, provider_model_value,
                            provider_effort_status, provider_effort_value,
                            provider_configuration_observed,
                            failure_code, created_at, updated_at
                     FROM subscription_runs
                     WHERE state NOT IN (
                        'promoted', 'completed_no_changes', 'failed', 'cancelled', 'interrupted'
                     )
                     ORDER BY created_at ASC, id ASC",
                )
                .map_err(storage_error)?;
            statement
                .query_map([], raw_subscription_run)
                .map_err(storage_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(storage_error)?
        };
        let records = raw_runs
            .into_iter()
            .map(SubscriptionRunRecord::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        for record in &records {
            load_and_validate_subscription_run_events(&transaction, record)?;
        }

        let mut recovered = Vec::with_capacity(records.len());
        for mut record in records {
            let transition = RunTransition::new(record.state, RunState::Interrupted, None)?;
            let next_revision = record
                .revision
                .checked_add(1)
                .ok_or_else(|| storage_invariant("subscription run revision overflow"))?;
            let changed = transaction
                .execute(
                    "UPDATE subscription_runs
                     SET state = 'interrupted', revision = ?4, failure_code = NULL, updated_at = ?5
                     WHERE id = ?1 AND state = ?2 AND revision = ?3",
                    params![
                        record.id.to_string(),
                        record.state.as_str(),
                        revision_to_sql(record.revision)?,
                        revision_to_sql(next_revision)?,
                        format_timestamp(updated_at),
                    ],
                )
                .map_err(storage_error)?;
            if changed != 1 {
                return Err(storage_invariant(
                    "subscription run changed during startup recovery",
                ));
            }
            let envelope = append_event_in_transaction(
                &transaction,
                record.session_id,
                Some(record.turn_id),
                Event::SubscriptionRunTransitioned {
                    run_id: record.id,
                    run_sequence: next_revision,
                    transition,
                    trust_label: RunTrustLabel::TrustedCarlState,
                },
                updated_at,
            )?;
            link_subscription_run_event(&transaction, record.id, next_revision, envelope.id)?;
            record.state = RunState::Interrupted;
            record.revision = next_revision;
            record.failure_code = None;
            record.updated_at = updated_at;
            recovered.push(record);
        }
        transaction.commit().map_err(storage_error)?;
        Ok(recovered)
    }

    pub fn create_approval(
        &self,
        session_id: SessionId,
        id: ApprovalId,
        tool_call_id: ToolCallId,
        summary: impl Into<String>,
    ) -> Result<ApprovalRecord, CarlError> {
        let approval = ApprovalRecord {
            id,
            session_id,
            tool_call_id,
            summary: summary.into(),
            status: ApprovalStatus::Pending,
            created_at: Utc::now(),
            resolved_at: None,
        };
        self.connection
            .execute(
                "INSERT INTO approvals (
                    id, session_id, tool_call_id, summary, status, created_at, resolved_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                params![
                    approval.id.to_string(),
                    approval.session_id.to_string(),
                    approval.tool_call_id.to_string(),
                    approval.summary,
                    approval.status.as_str(),
                    format_timestamp(approval.created_at),
                ],
            )
            .map_err(storage_error)?;
        Ok(approval)
    }

    pub fn get_approval(&self, id: ApprovalId) -> Result<Option<ApprovalRecord>, CarlError> {
        let row = self
            .connection
            .query_row(
                "SELECT session_id, tool_call_id, summary, status, created_at, resolved_at
                 FROM approvals
                 WHERE id = ?1",
                [id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?;

        row.map(
            |(session_id, tool_call_id, summary, status, created_at, resolved_at)| {
                Ok(ApprovalRecord {
                    id,
                    session_id: parse_id("session ID", &session_id)?,
                    tool_call_id: parse_id("tool call ID", &tool_call_id)?,
                    summary,
                    status: ApprovalStatus::parse(&status)?,
                    created_at: parse_timestamp(&created_at)?,
                    resolved_at: resolved_at.as_deref().map(parse_timestamp).transpose()?,
                })
            },
        )
        .transpose()
    }

    pub fn resolve_approval(
        &self,
        id: ApprovalId,
        status: ApprovalStatus,
    ) -> Result<ApprovalRecord, CarlError> {
        if status == ApprovalStatus::Pending {
            return Err(CarlError::Storage {
                detail: "a pending approval must resolve to a terminal status".to_owned(),
            });
        }
        let updated = self
            .connection
            .execute(
                "UPDATE approvals
                 SET status = ?2, resolved_at = ?3
                 WHERE id = ?1 AND status = 'pending'",
                params![
                    id.to_string(),
                    status.as_str(),
                    format_timestamp(Utc::now()),
                ],
            )
            .map_err(storage_error)?;
        if updated != 1 {
            return Err(CarlError::Storage {
                detail: format!("approval {id} is missing or already resolved"),
            });
        }
        self.get_approval(id)?.ok_or_else(|| CarlError::Storage {
            detail: format!("approval {id} disappeared after resolution"),
        })
    }

    pub fn create_bound_approval(
        &self,
        id: ApprovalId,
        binding: BoundApprovalBinding,
        summary: impl Into<String>,
    ) -> Result<BoundApprovalRecord, CarlError> {
        let summary = summary.into();
        if summary.trim().is_empty() || summary.len() > MAX_APPROVAL_SUMMARY_BYTES {
            return Err(CarlError::Validation {
                detail: "bound approval summary is invalid".to_owned(),
            });
        }
        let record = BoundApprovalRecord {
            id,
            binding,
            summary,
            status: ApprovalStatus::Pending,
            resolved_at: None,
            consumed_at: None,
        };
        self.connection
            .execute(
                "INSERT INTO bound_approvals (
                    id, session_id, turn_id, tool_call_id, actor_id, request_digest,
                    summary, status, created_at, expires_at, resolved_at, consumed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9, NULL, NULL)",
                params![
                    record.id.to_string(),
                    record.binding.session_id.to_string(),
                    record.binding.turn_id.to_string(),
                    record.binding.tool_call_id.to_string(),
                    record.binding.actor_id.as_str(),
                    record.binding.request_digest.to_string(),
                    record.summary,
                    format_timestamp(record.binding.created_at),
                    format_timestamp(record.binding.expires_at),
                ],
            )
            .map_err(storage_error)?;
        Ok(record)
    }

    pub fn get_bound_approval(
        &self,
        id: ApprovalId,
    ) -> Result<Option<BoundApprovalRecord>, CarlError> {
        let raw = self
            .connection
            .query_row(
                "SELECT session_id, turn_id, tool_call_id, actor_id, request_digest,
                        summary, status, created_at, expires_at, resolved_at, consumed_at
                 FROM bound_approvals
                 WHERE id = ?1",
                [id.to_string()],
                raw_bound_approval,
            )
            .optional()
            .map_err(storage_error)?;
        raw.map(|raw| bound_record_from_raw(id, raw)).transpose()
    }

    pub fn resolve_bound_approval(
        &self,
        id: ApprovalId,
        status: ApprovalStatus,
        resolved_at: DateTime<Utc>,
    ) -> Result<BoundApprovalRecord, CarlError> {
        if status == ApprovalStatus::Pending {
            return Err(CarlError::Validation {
                detail: "a bound approval must resolve to a terminal status".to_owned(),
            });
        }
        let existing = self
            .get_bound_approval(id)?
            .ok_or_else(|| policy_error("bound approval is unavailable"))?;
        if resolved_at < existing.binding.created_at
            || (resolved_at >= existing.binding.expires_at && status != ApprovalStatus::Expired)
        {
            return Err(policy_error(
                "bound approval resolution is outside its lifetime",
            ));
        }
        let changed = self
            .connection
            .execute(
                "UPDATE bound_approvals
                 SET status = ?2, resolved_at = ?3
                 WHERE id = ?1 AND status = 'pending' AND consumed_at IS NULL",
                params![
                    id.to_string(),
                    status.as_str(),
                    format_timestamp(resolved_at)
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(policy_error("bound approval is unavailable"));
        }
        self.get_bound_approval(id)?
            .ok_or_else(|| storage_invariant("bound approval disappeared after resolution"))
    }

    pub fn consume_bound_approval(
        &mut self,
        id: ApprovalId,
        binding: &BoundApprovalBinding,
        now: DateTime<Utc>,
    ) -> Result<ConsumedApproval, CarlError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let raw = transaction
            .query_row(
                "SELECT session_id, turn_id, tool_call_id, actor_id, request_digest,
                        summary, status, created_at, expires_at, resolved_at, consumed_at
                 FROM bound_approvals
                 WHERE id = ?1",
                [id.to_string()],
                raw_bound_approval,
            )
            .optional()
            .map_err(storage_error)?
            .ok_or_else(|| policy_error("bound approval is unavailable"))?;
        let record = bound_record_from_raw(id, raw)?;
        if record.binding != *binding
            || record.status != ApprovalStatus::Allowed
            || record.consumed_at.is_some()
        {
            return Err(policy_error("bound approval does not match the request"));
        }
        if now >= record.binding.expires_at {
            transaction
                .execute(
                    "UPDATE bound_approvals
                     SET status = 'expired', resolved_at = COALESCE(resolved_at, ?2)
                     WHERE id = ?1 AND consumed_at IS NULL",
                    params![id.to_string(), format_timestamp(now)],
                )
                .map_err(storage_error)?;
            transaction.commit().map_err(storage_error)?;
            return Err(policy_error("bound approval has expired"));
        }
        let consumed_at = format_timestamp(now);
        let changed = transaction
            .execute(
                "UPDATE bound_approvals
                 SET consumed_at = ?2
                 WHERE id = ?1
                   AND status = 'allowed'
                   AND consumed_at IS NULL
                   AND expires_at > ?2",
                params![id.to_string(), consumed_at],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            return Err(policy_error("bound approval is unavailable"));
        }
        transaction.commit().map_err(storage_error)?;
        Ok(ConsumedApproval {
            id,
            request_digest: binding.request_digest,
            consumed_at: now,
        })
    }

    pub fn memory_settings(
        &self,
        partition: &MemoryPartition,
    ) -> Result<MemorySettings, CarlError> {
        load_memory_settings(&self.connection, partition)
    }

    pub fn update_memory_settings(
        &self,
        partition: &MemoryPartition,
        settings: &MemorySettings,
        updated_at: DateTime<Utc>,
    ) -> Result<(), CarlError> {
        settings.validate()?;
        self.connection
            .execute(
                "INSERT INTO memory_settings (
                    owner_id, agent_id, enabled, max_context_items, context_bytes,
                    max_memories, max_storage_bytes, episode_ttl_days, updated_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT (owner_id, agent_id) DO UPDATE SET
                    enabled = excluded.enabled,
                    max_context_items = excluded.max_context_items,
                    context_bytes = excluded.context_bytes,
                    max_memories = excluded.max_memories,
                    max_storage_bytes = excluded.max_storage_bytes,
                    episode_ttl_days = excluded.episode_ttl_days,
                    updated_at = excluded.updated_at",
                params![
                    partition.owner_id(),
                    partition.agent_id(),
                    settings.enabled,
                    settings.max_context_items,
                    settings.context_bytes,
                    settings.max_memories,
                    settings.max_storage_bytes,
                    settings.episode_ttl_days,
                    format_timestamp(updated_at),
                ],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    pub fn remember_memory(
        &self,
        write: MemoryWrite,
        now: DateTime<Utc>,
    ) -> Result<MemoryRecord, CarlError> {
        validate_memory_write(&write)?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(storage_error)?;
        let record = remember_memory_in_transaction(&transaction, &write, now)?;
        transaction.commit().map_err(storage_error)?;
        checkpoint_for_secure_deletion(&self.connection)?;
        Ok(record)
    }

    pub fn retrieve_memories(
        &self,
        query: &MemoryQuery,
        now: DateTime<Utc>,
        semantic_ranker: Option<&dyn SemanticMemoryRanker>,
    ) -> Result<MemoryContext, CarlError> {
        let settings = self.memory_settings(query.partition())?;
        if !settings.enabled {
            return Ok(MemoryContext::disabled());
        }
        let workspace = query.workspace.as_deref().unwrap_or("");
        let session = query.session.map(|id| id.to_string()).unwrap_or_default();
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, owner_id, agent_id, scope_kind, scope_key, kind, memory_key,
                        content, provenance, importance, revision, created_at, updated_at,
                        expires_at
                 FROM memories
                 WHERE owner_id = ?1 AND agent_id = ?2
                   AND (expires_at IS NULL OR expires_at > ?3)
                   AND (
                        scope_kind = 'global'
                        OR (scope_kind = 'workspace' AND scope_key = ?4)
                        OR (scope_kind = 'session' AND scope_key = ?5)
                   )
                 ORDER BY updated_at DESC, id ASC",
            )
            .map_err(storage_error)?;
        let rows = statement
            .query_map(
                params![
                    query.partition.owner_id(),
                    query.partition.agent_id(),
                    format_timestamp(now),
                    workspace,
                    session,
                ],
                raw_memory_record,
            )
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        let memories = rows
            .into_iter()
            .map(MemoryRecord::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rank_memories(
            query,
            &settings,
            memories,
            now,
            semantic_ranker,
        ))
    }

    pub fn export_memories(
        &self,
        partition: &MemoryPartition,
        now: DateTime<Utc>,
    ) -> Result<MemoryExport, CarlError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, owner_id, agent_id, scope_kind, scope_key, kind, memory_key,
                        content, provenance, importance, revision, created_at, updated_at,
                        expires_at
                 FROM memories
                 WHERE owner_id = ?1 AND agent_id = ?2
                   AND (expires_at IS NULL OR expires_at > ?3)
                 ORDER BY created_at ASC, id ASC",
            )
            .map_err(storage_error)?;
        let rows = statement
            .query_map(
                params![
                    partition.owner_id(),
                    partition.agent_id(),
                    format_timestamp(now),
                ],
                raw_memory_record,
            )
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        Ok(MemoryExport {
            schema_version: 1,
            partition: partition.clone(),
            settings: self.memory_settings(partition)?,
            memories: rows
                .into_iter()
                .map(MemoryRecord::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    pub fn list_memory_proposals(
        &self,
        partition: &MemoryPartition,
        now: DateTime<Utc>,
    ) -> Result<Vec<MemoryProposal>, CarlError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, owner_id, agent_id, scope_kind, scope_key, kind, memory_key,
                        content, provenance, importance, memory_expires_at, origin,
                        source_session_id, created_at, expires_at
                 FROM memory_proposals
                 WHERE owner_id = ?1 AND agent_id = ?2 AND expires_at > ?3
                 ORDER BY created_at ASC, id ASC",
            )
            .map_err(storage_error)?;
        statement
            .query_map(
                params![
                    partition.owner_id(),
                    partition.agent_id(),
                    format_timestamp(now),
                ],
                raw_memory_proposal,
            )
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?
            .into_iter()
            .map(MemoryProposal::try_from)
            .collect()
    }

    pub fn delete_memory(&self, partition: &MemoryPartition, id: Uuid) -> Result<bool, CarlError> {
        let deleted = self
            .connection
            .execute(
                "DELETE FROM memories
                 WHERE id = ?1 AND owner_id = ?2 AND agent_id = ?3",
                params![id.to_string(), partition.owner_id(), partition.agent_id()],
            )
            .map_err(storage_error)?;
        checkpoint_for_secure_deletion(&self.connection)?;
        Ok(deleted == 1)
    }

    pub fn clear_memories(&self, partition: &MemoryPartition) -> Result<u64, CarlError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(storage_error)?;
        let memories = transaction
            .execute(
                "DELETE FROM memories WHERE owner_id = ?1 AND agent_id = ?2",
                params![partition.owner_id(), partition.agent_id()],
            )
            .map_err(storage_error)?;
        let proposals = transaction
            .execute(
                "DELETE FROM memory_proposals WHERE owner_id = ?1 AND agent_id = ?2",
                params![partition.owner_id(), partition.agent_id()],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        checkpoint_for_secure_deletion(&self.connection)?;
        let deleted = memories
            .checked_add(proposals)
            .ok_or_else(|| storage_invariant("deleted memory count overflowed"))?;
        usize_to_u64(deleted, "deleted memory and proposal count")
    }

    pub fn purge_expired_memory(
        &self,
        partition: &MemoryPartition,
        now: DateTime<Utc>,
    ) -> Result<MemoryPurgeReport, CarlError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(storage_error)?;
        let timestamp = format_timestamp(now);
        let memories = transaction
            .execute(
                "DELETE FROM memories
                 WHERE owner_id = ?1 AND agent_id = ?2
                   AND expires_at IS NOT NULL AND expires_at <= ?3",
                params![partition.owner_id(), partition.agent_id(), timestamp],
            )
            .map_err(storage_error)?;
        let proposals = transaction
            .execute(
                "DELETE FROM memory_proposals
                 WHERE owner_id = ?1 AND agent_id = ?2 AND expires_at <= ?3",
                params![partition.owner_id(), partition.agent_id(), timestamp],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        checkpoint_for_secure_deletion(&self.connection)?;
        Ok(MemoryPurgeReport {
            memories_deleted: usize_to_u64(memories, "expired memory count")?,
            proposals_deleted: usize_to_u64(proposals, "expired proposal count")?,
        })
    }

    pub fn propose_memory(
        &self,
        write: MemoryWrite,
        origin: ProposalOrigin,
        source_session: Option<SessionId>,
        now: DateTime<Utc>,
    ) -> Result<MemoryProposal, CarlError> {
        validate_memory_write(&write)?;
        if origin == ProposalOrigin::VerifiedEpisode && write.kind != MemoryKind::Episode {
            return Err(CarlError::Validation {
                detail: "verified-event proposals must be episodic memories".to_owned(),
            });
        }
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(storage_error)?;
        let settings = load_memory_settings(&transaction, &write.partition)?;
        if !settings.enabled {
            return Err(CarlError::Policy {
                detail: "memory capture is disabled".to_owned(),
            });
        }
        let purged = transaction
            .execute(
                "DELETE FROM memory_proposals
                 WHERE owner_id = ?1 AND agent_id = ?2 AND expires_at <= ?3",
                params![
                    write.partition.owner_id(),
                    write.partition.agent_id(),
                    format_timestamp(now),
                ],
            )
            .map_err(storage_error)?;
        let pending: u64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM memory_proposals
                 WHERE owner_id = ?1 AND agent_id = ?2 AND expires_at > ?3",
                params![
                    write.partition.owner_id(),
                    write.partition.agent_id(),
                    format_timestamp(now),
                ],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        if pending >= 50 {
            return Err(CarlError::BudgetExceeded {
                resource: crate::error::BudgetResource::MemoryProposals,
                limit: 50,
            });
        }
        let proposal = MemoryProposal {
            id: Uuid::new_v4(),
            write,
            origin,
            source_session,
            created_at: now,
            expires_at: now + chrono::TimeDelta::days(DEFAULT_PROPOSAL_TTL_DAYS),
        };
        transaction
            .execute(
                "INSERT INTO memory_proposals (
                    id, owner_id, agent_id, scope_kind, scope_key, kind, memory_key,
                    content, provenance, importance, memory_expires_at, origin,
                    source_session_id, created_at, expires_at
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15
                 )",
                params![
                    proposal.id.to_string(),
                    proposal.write.partition.owner_id(),
                    proposal.write.partition.agent_id(),
                    proposal.write.scope.kind().as_str(),
                    proposal.write.scope.key(),
                    proposal.write.kind.as_str(),
                    proposal.write.key,
                    proposal.write.content,
                    proposal.write.provenance,
                    proposal.write.importance,
                    proposal.write.expires_at.map(format_timestamp),
                    proposal.origin.as_str(),
                    proposal.source_session.map(|id| id.to_string()),
                    format_timestamp(proposal.created_at),
                    format_timestamp(proposal.expires_at),
                ],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        if purged > 0 {
            checkpoint_for_secure_deletion(&self.connection)?;
        }
        Ok(proposal)
    }

    pub fn approve_memory_proposal(
        &self,
        partition: &MemoryPartition,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<MemoryRecord, CarlError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(storage_error)?;
        let raw = transaction
            .query_row(
                "SELECT id, owner_id, agent_id, scope_kind, scope_key, kind, memory_key,
                        content, provenance, importance, memory_expires_at, origin,
                        source_session_id, created_at, expires_at
                 FROM memory_proposals
                 WHERE id = ?1 AND owner_id = ?2 AND agent_id = ?3",
                params![id.to_string(), partition.owner_id(), partition.agent_id()],
                raw_memory_proposal,
            )
            .optional()
            .map_err(storage_error)?
            .ok_or_else(|| CarlError::Validation {
                detail: "memory proposal is unavailable".to_owned(),
            })?;
        let proposal = MemoryProposal::try_from(raw)?;
        if proposal.expires_at <= now {
            transaction
                .execute(
                    "DELETE FROM memory_proposals WHERE id = ?1",
                    [id.to_string()],
                )
                .map_err(storage_error)?;
            transaction.commit().map_err(storage_error)?;
            checkpoint_for_secure_deletion(&self.connection)?;
            return Err(CarlError::Validation {
                detail: "memory proposal has expired".to_owned(),
            });
        }
        validate_memory_write(&proposal.write)?;
        let record = remember_memory_in_transaction(&transaction, &proposal.write, now)?;
        transaction
            .execute(
                "DELETE FROM memory_proposals WHERE id = ?1",
                [id.to_string()],
            )
            .map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        checkpoint_for_secure_deletion(&self.connection)?;
        Ok(record)
    }

    pub fn reject_memory_proposal(
        &self,
        partition: &MemoryPartition,
        id: Uuid,
    ) -> Result<bool, CarlError> {
        let deleted = self
            .connection
            .execute(
                "DELETE FROM memory_proposals
                 WHERE id = ?1 AND owner_id = ?2 AND agent_id = ?3",
                params![id.to_string(), partition.owner_id(), partition.agent_id()],
            )
            .map_err(storage_error)?;
        checkpoint_for_secure_deletion(&self.connection)?;
        Ok(deleted == 1)
    }
}

/// The only live-runtime owner of Carl's durable state. The wrapper consumes
/// the matching data-root lock, derives the fixed database location from that
/// capability, performs startup recovery, and retains exclusivity until drop.
pub struct RuntimeStore {
    store: Store,
    artifacts: ArtifactStore,
    startup_recoveries: Vec<RunId>,
    _data_root_lock: DataRootLock,
}

impl RuntimeStore {
    pub fn open(
        data_root_lock: DataRootLock,
        startup_at: DateTime<Utc>,
    ) -> Result<Self, CarlError> {
        let data_root = data_root_lock.runtime_data_root();
        if !data_root_lock.guards_data_root(data_root) {
            return Err(storage_invariant(
                "runtime data root changed after lock acquisition",
            ));
        }
        let artifacts = ArtifactStore::open_or_create_for_runtime(&data_root_lock)
            .map_err(artifact_storage_error)?;
        let path = data_root.join(RUNTIME_DATABASE_FILENAME);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(storage_invariant("runtime database is not a regular file"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(storage_invariant(
                    "runtime database metadata is unavailable",
                ));
            }
        }
        let mut store = Store::open_locked(&data_root_lock)?;
        if !data_root_lock.guards_data_root(data_root) {
            return Err(storage_invariant(
                "runtime data root changed while opening durable state",
            ));
        }
        reconcile_runtime_artifacts(&mut store, &artifacts)?;
        let startup_recoveries = store
            .interrupt_abandoned_subscription_runs(startup_at)?
            .into_iter()
            .map(|record| record.id)
            .collect();
        Ok(Self {
            store,
            artifacts,
            startup_recoveries,
            _data_root_lock: data_root_lock,
        })
    }

    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    #[must_use]
    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    #[must_use]
    pub const fn artifacts(&self) -> &ArtifactStore {
        &self.artifacts
    }

    pub fn record_subscription_run_baseline(
        &mut self,
        run_id: RunId,
        expected_state: RunState,
        expected_revision: u64,
        baseline: &SealedBaseline,
        created_at: DateTime<Utc>,
    ) -> Result<Option<SubscriptionRunBaselineRecord>, CarlError> {
        verify_sealed_baseline_artifacts(&self.artifacts, baseline)?;
        match self.store.record_subscription_run_baseline(
            run_id,
            expected_state,
            expected_revision,
            baseline,
            &self.artifacts,
            created_at,
        )? {
            None => Ok(None),
            Some(_) => self
                .get_subscription_run_baseline(run_id)?
                .map(Some)
                .ok_or_else(|| storage_invariant("recorded subscription run baseline disappeared")),
        }
    }

    pub fn get_subscription_run_baseline(
        &self,
        run_id: RunId,
    ) -> Result<Option<SubscriptionRunBaselineRecord>, CarlError> {
        let baseline = self.store.get_subscription_run_baseline(run_id)?;
        if let Some(baseline) = &baseline {
            verify_loaded_baseline_artifacts(&self.artifacts, baseline)?;
        }
        Ok(baseline)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_subscription_run_no_changes(
        &mut self,
        run_id: RunId,
        expected_state: RunState,
        expected_revision: u64,
        stage: &SanitizedStage,
        limits: ProposalLimits,
        secret_filter: SecretFilter,
        created_at: DateTime<Utc>,
    ) -> Result<Option<SubscriptionRunInspectionRecord>, CarlError> {
        match stage
            .inspect_proposal(&self.artifacts, limits, secret_filter)
            .map_err(proposal_storage_error)?
        {
            ProposalOutcome::NoChanges => {}
            ProposalOutcome::ExactReplacement(_) => {
                return Err(artifact_validation_error(
                    "a changed stage cannot be recorded as no changes",
                ));
            }
        }
        verify_sealed_baseline_artifacts(&self.artifacts, stage.sealed_baseline())?;
        let persisted = self
            .get_subscription_run_baseline(run_id)?
            .ok_or_else(|| storage_invariant("subscription run has no sealed baseline"))?;
        if persisted.manifest_artifact_id != *stage.sealed_baseline().manifest_artifact_id()
            || persisted.manifest_digest != stage.baseline_manifest().digest()
        {
            return Err(artifact_validation_error(
                "no-change inspection references a different sealed baseline",
            ));
        }
        match self.store.record_subscription_run_no_changes(
            run_id,
            expected_state,
            expected_revision,
            created_at,
        )? {
            None => Ok(None),
            Some(_) => self
                .get_subscription_run_inspection(run_id)?
                .map(Some)
                .ok_or_else(|| storage_invariant("recorded no-change inspection disappeared")),
        }
    }

    pub fn record_subscription_run_exact_proposal(
        &mut self,
        run_id: RunId,
        expected_state: RunState,
        expected_revision: u64,
        proposal: &ExactReplacementProposal,
        created_at: DateTime<Utc>,
    ) -> Result<Option<SubscriptionRunProposalRecord>, CarlError> {
        verify_exact_proposal_artifacts(&self.artifacts, proposal)?;
        let baseline = self
            .get_subscription_run_baseline(run_id)?
            .ok_or_else(|| storage_invariant("subscription run has no sealed baseline"))?;
        validate_proposal_against_baseline(proposal, &baseline)?;
        if candidate_manifest_digest(
            &baseline,
            proposal.path(),
            proposal.payload(),
            proposal.payload_hash(),
        )? != proposal.candidate_manifest_digest()
        {
            return Err(artifact_validation_error(
                "proposal candidate manifest digest is inconsistent",
            ));
        }
        match self.store.record_subscription_run_exact_proposal(
            run_id,
            expected_state,
            expected_revision,
            proposal,
            &self.artifacts,
            created_at,
        )? {
            None => Ok(None),
            Some(_) => self
                .get_subscription_run_proposal(run_id)?
                .map(Some)
                .ok_or_else(|| storage_invariant("recorded exact proposal disappeared")),
        }
    }

    pub fn get_subscription_run_inspection(
        &self,
        run_id: RunId,
    ) -> Result<Option<SubscriptionRunInspectionRecord>, CarlError> {
        let inspection = self.store.get_subscription_run_inspection(run_id)?;
        if let Some(inspection) = &inspection {
            match inspection.outcome {
                SubscriptionRunInspectionOutcome::NoChanges => {
                    let baseline =
                        self.get_subscription_run_baseline(run_id)?.ok_or_else(|| {
                            storage_invariant("no-change inspection has no sealed baseline")
                        })?;
                    if inspection.stage_manifest_digest != baseline.manifest_digest {
                        return Err(storage_invariant(
                            "no-change inspection digest disagrees with its sealed baseline",
                        ));
                    }
                }
                SubscriptionRunInspectionOutcome::ExactReplacement => {
                    self.get_subscription_run_proposal(run_id)?.ok_or_else(|| {
                        storage_invariant("exact inspection has no verified proposal")
                    })?;
                }
            }
        }
        Ok(inspection)
    }

    pub fn get_subscription_run_proposal(
        &self,
        run_id: RunId,
    ) -> Result<Option<SubscriptionRunProposalRecord>, CarlError> {
        let proposal = self.store.get_subscription_run_proposal(run_id)?;
        let Some(proposal) = proposal else {
            return Ok(None);
        };
        let baseline = self
            .get_subscription_run_baseline(run_id)?
            .ok_or_else(|| storage_invariant("stored proposal has no sealed baseline"))?;
        verify_loaded_proposal_artifacts(&self.artifacts, &baseline, &proposal)?;
        Ok(Some(proposal))
    }

    pub fn begin_subscription_run_verification(
        &mut self,
        run_id: RunId,
        expected_revision: u64,
        specification: &VerificationSpec,
        created_at: DateTime<Utc>,
    ) -> Result<Option<VerificationRequest>, CarlError> {
        self.get_subscription_run_baseline(run_id)?
            .ok_or_else(|| storage_invariant("subscription run has no sealed baseline"))?;
        self.get_subscription_run_proposal(run_id)?
            .ok_or_else(|| storage_invariant("subscription run has no exact proposal"))?;
        self.store.begin_subscription_run_verification(
            run_id,
            expected_revision,
            specification,
            created_at,
        )
    }

    pub fn get_subscription_run_verification_request(
        &self,
        run_id: RunId,
    ) -> Result<Option<VerificationRequest>, CarlError> {
        let request = self
            .store
            .get_subscription_run_verification_request(run_id)?;
        if request.is_some() {
            self.get_subscription_run_baseline(run_id)?
                .ok_or_else(|| storage_invariant("verification request has no sealed baseline"))?;
            self.get_subscription_run_proposal(run_id)?
                .ok_or_else(|| storage_invariant("verification request has no exact proposal"))?;
        }
        Ok(request)
    }

    pub fn complete_subscription_run_verification(
        &mut self,
        run_id: RunId,
        expected_revision: u64,
        result: &VerificationResult,
        completed_at: DateTime<Utc>,
    ) -> Result<Option<VerificationCompletionRecord>, CarlError> {
        let Some(run) = self.store.get_subscription_run(run_id)? else {
            return Ok(None);
        };
        if run.state != RunState::Verifying || run.revision != expected_revision {
            return Ok(None);
        }
        self.get_subscription_run_verification_request(run_id)?
            .ok_or_else(|| storage_invariant("verifying run has no durable request"))?;
        self.store.complete_subscription_run_verification(
            run_id,
            expected_revision,
            result,
            completed_at,
        )
    }

    pub fn get_subscription_run_verification_result(
        &self,
        run_id: RunId,
    ) -> Result<Option<VerificationResult>, CarlError> {
        let result = self
            .store
            .get_subscription_run_verification_result(run_id)?;
        if result.is_some() {
            self.get_subscription_run_baseline(run_id)?
                .ok_or_else(|| storage_invariant("verification result has no sealed baseline"))?;
            self.get_subscription_run_proposal(run_id)?
                .ok_or_else(|| storage_invariant("verification result has no exact proposal"))?;
        }
        Ok(result)
    }

    #[must_use]
    pub fn startup_recoveries(&self) -> &[RunId] {
        &self.startup_recoveries
    }
}

fn reconcile_runtime_artifacts(
    store: &mut Store,
    artifacts: &ArtifactStore,
) -> Result<(), CarlError> {
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage_error)?;
    let referenced = referenced_artifact_ids(&transaction)?;
    artifacts
        .retain_only(&referenced)
        .map_err(artifact_storage_error)?;
    let registered = transaction
        .prepare("SELECT id FROM artifact_objects ORDER BY id")
        .map_err(storage_error)?
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    for identifier in registered {
        let artifact_id = ArtifactId::parse(&identifier)
            .map_err(|_| storage_invariant("registered artifact identifier is invalid"))?;
        if !referenced.contains(&artifact_id) {
            transaction
                .execute("DELETE FROM artifact_objects WHERE id = ?1", [identifier])
                .map_err(storage_error)?;
        }
    }
    transaction.commit().map_err(storage_error)
}

fn referenced_artifact_ids(connection: &Connection) -> Result<HashSet<ArtifactId>, CarlError> {
    let mut statement = connection
        .prepare(
            "SELECT manifest_artifact_id FROM subscription_run_baselines
             UNION
             SELECT source_preconditions_artifact_id FROM subscription_run_baselines
             UNION
             SELECT content_artifact_id FROM subscription_run_baseline_entries
             UNION
             SELECT proposal_artifact_id FROM subscription_run_proposals
             UNION
             SELECT payload_sha256 FROM subscription_run_proposals
             ORDER BY 1",
        )
        .map_err(storage_error)?;
    let identifiers = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    let mut referenced = identifiers
        .into_iter()
        .map(|identifier| {
            ArtifactId::parse(identifier)
                .map_err(|_| storage_invariant("durable artifact identifier is invalid"))
        })
        .collect::<Result<HashSet<_>, _>>()?;
    let checkpoints = connection
        .prepare(
            "SELECT checkpoint_json, digest
             FROM task_checkpoints
             WHERE checkpoint_json IS NOT NULL
             ORDER BY task_id, event_sequence",
        )
        .map_err(storage_error)?
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    for (checkpoint_json, stored_digest) in checkpoints {
        let checkpoint = serde_json::from_str::<CanonicalCheckpoint>(&checkpoint_json)
            .map_err(|_| storage_invariant("stored canonical checkpoint is invalid"))?;
        let canonical_digest = checkpoint
            .digest()
            .map_err(|_| storage_invariant("stored canonical checkpoint is invalid"))?;
        if canonical_digest != stored_digest {
            return Err(storage_invariant(
                "stored canonical checkpoint digest does not match",
            ));
        }
        for digest in checkpoint.artifact_digests() {
            referenced.insert(
                ArtifactId::parse(digest)
                    .map_err(|_| storage_invariant("checkpoint artifact identifier is invalid"))?,
            );
        }
    }
    Ok(referenced)
}

impl Deref for RuntimeStore {
    type Target = Store;

    fn deref(&self) -> &Self::Target {
        self.store()
    }
}

impl DerefMut for RuntimeStore {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.store_mut()
    }
}

fn subscription_run_matches(
    connection: &Connection,
    run_id: RunId,
    expected_state: RunState,
    expected_revision: u64,
) -> Result<bool, CarlError> {
    Ok(
        load_subscription_run(connection, run_id)?.is_some_and(|record| {
            record.state == expected_state && record.revision == expected_revision
        }),
    )
}

fn subscription_run_has_baseline(
    connection: &Connection,
    run_id: RunId,
) -> Result<bool, CarlError> {
    connection
        .query_row(
            "SELECT 1 FROM subscription_run_baselines WHERE run_id = ?1",
            [run_id.to_string()],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(storage_error)
}

fn subscription_run_has_proposal(
    connection: &Connection,
    run_id: RunId,
) -> Result<bool, CarlError> {
    connection
        .query_row(
            "SELECT 1 FROM subscription_run_proposals WHERE run_id = ?1",
            [run_id.to_string()],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(storage_error)
}

fn subscription_run_has_verification_result(
    connection: &Connection,
    run_id: RunId,
) -> Result<bool, CarlError> {
    connection
        .query_row(
            "SELECT 1 FROM subscription_run_verification_results WHERE run_id = ?1",
            [run_id.to_string()],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(storage_error)
}

fn reject_existing_subscription_run_inspection(
    connection: &Connection,
    run_id: RunId,
) -> Result<(), CarlError> {
    let exists = connection
        .query_row(
            "SELECT 1 FROM subscription_run_inspections WHERE run_id = ?1",
            [run_id.to_string()],
            |_| Ok(()),
        )
        .optional()
        .map_err(storage_error)?
        .is_some();
    if exists {
        Err(CarlError::Validation {
            detail: "the subscription run inspection is already recorded".to_owned(),
        })
    } else {
        Ok(())
    }
}

fn register_artifact_object(
    transaction: &Transaction<'_>,
    id: &ArtifactId,
    byte_length: u64,
    created_at: DateTime<Utc>,
) -> Result<(), CarlError> {
    transaction
        .execute(
            "INSERT INTO artifact_objects (id, byte_length, created_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (id) DO NOTHING",
            params![
                id.as_str(),
                revision_to_sql(byte_length)?,
                format_timestamp(created_at),
            ],
        )
        .map_err(storage_error)?;
    let stored_length = transaction
        .query_row(
            "SELECT byte_length FROM artifact_objects WHERE id = ?1",
            [id.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .map_err(storage_error)?;
    if u64::try_from(stored_length).ok() != Some(byte_length) {
        return Err(storage_invariant(
            "content-addressed artifact length is inconsistent",
        ));
    }
    Ok(())
}

fn require_registered_artifact_object(
    connection: &Connection,
    id: &ArtifactId,
    byte_length: u64,
) -> Result<(), CarlError> {
    let stored_length = connection
        .query_row(
            "SELECT byte_length FROM artifact_objects WHERE id = ?1",
            [id.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(storage_error)?;
    if stored_length.and_then(|length| u64::try_from(length).ok()) != Some(byte_length) {
        return Err(storage_invariant(
            "content-addressed artifact registration is missing or inconsistent",
        ));
    }
    Ok(())
}

fn insert_subscription_run_inspection(
    transaction: &Transaction<'_>,
    run_id: RunId,
    outcome: SubscriptionRunInspectionOutcome,
    stage_manifest_digest: Sha256Digest,
    created_at: DateTime<Utc>,
) -> Result<(), CarlError> {
    transaction
        .execute(
            "INSERT INTO subscription_run_inspections (
                run_id, outcome, stage_manifest_digest, created_at
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                run_id.to_string(),
                outcome.as_str(),
                stage_manifest_digest.to_string(),
                format_timestamp(created_at),
            ],
        )
        .map_err(storage_error)?;
    Ok(())
}

fn validate_sealed_baseline(baseline: &SealedBaseline) -> Result<(Vec<u8>, Vec<u8>), CarlError> {
    let manifest = baseline.manifest();
    let manifest_bytes = manifest
        .canonical_bytes()
        .map_err(|_| artifact_validation_error("sealed baseline manifest is invalid"))?;
    let manifest_id = artifact_id_for_bytes(&manifest_bytes)?;
    if &manifest_id != baseline.manifest_artifact_id()
        || manifest_id.as_str() != manifest.digest().to_string()
        || manifest.entries().len() != baseline.entries().len()
    {
        return Err(artifact_validation_error(
            "sealed baseline manifest and artifact disagree",
        ));
    }

    let mut total_bytes = 0_u64;
    let mut previous_path: Option<&str> = None;
    for (manifest_entry, sealed_entry) in manifest.entries().iter().zip(baseline.entries().iter()) {
        if manifest_entry.path() != sealed_entry.path()
            || manifest_entry.bytes() != sealed_entry.bytes()
            || manifest_entry.content_digest() != sealed_entry.content_digest()
            || sealed_entry.content_artifact_id().as_str()
                != sealed_entry.content_digest().to_string()
            || previous_path.is_some_and(|previous| previous >= sealed_entry.path())
        {
            return Err(artifact_validation_error(
                "sealed baseline entry metadata is inconsistent",
            ));
        }
        let identity = sealed_entry.source_identity();
        let valid_identity = !identity.identity_a.is_empty()
            && !identity.identity_b.is_empty()
            && !identity.owner_id.is_empty()
            && matches!(
                (identity.platform, identity.owner_mode),
                ("unix", Some(0..=0o7777)) | ("windows", None)
            );
        if !valid_identity {
            return Err(artifact_validation_error(
                "sealed baseline source identity is invalid",
            ));
        }
        total_bytes = total_bytes
            .checked_add(sealed_entry.bytes())
            .ok_or_else(|| artifact_validation_error("sealed baseline size overflows"))?;
        previous_path = Some(sealed_entry.path());
    }
    if total_bytes != manifest.total_bytes() {
        return Err(artifact_validation_error(
            "sealed baseline total size is inconsistent",
        ));
    }
    canonical_baseline_directories(baseline.directories())?;
    let source_preconditions = canonical_source_preconditions(
        manifest.digest(),
        baseline.entries().iter().map(|entry| {
            let identity = entry.source_identity();
            SourcePreconditionRef {
                path: entry.path(),
                bytes: entry.bytes(),
                content_digest: entry.content_digest(),
                platform: identity.platform,
                identity_a: &identity.identity_a,
                identity_b: &identity.identity_b,
                owner_id: &identity.owner_id,
                owner_mode: identity.owner_mode,
            }
        }),
    )
    .map_err(|_| artifact_validation_error("source precondition evidence is invalid"))?;
    let source_preconditions_id = artifact_id_for_bytes(&source_preconditions)?;
    if &source_preconditions_id != baseline.source_preconditions_artifact_id()
        || source_preconditions_id.as_str() != baseline.source_preconditions_digest().to_string()
    {
        return Err(artifact_validation_error(
            "source precondition evidence and artifact disagree",
        ));
    }
    Ok((manifest_bytes, source_preconditions))
}

fn verify_sealed_baseline_artifacts(
    artifacts: &ArtifactStore,
    baseline: &SealedBaseline,
) -> Result<(), CarlError> {
    let (canonical_manifest, canonical_preconditions) = validate_sealed_baseline(baseline)?;
    let manifest = artifacts
        .read_verified(baseline.manifest_artifact_id())
        .map_err(artifact_storage_error)?;
    if manifest.bytes() != canonical_manifest {
        return Err(artifact_validation_error(
            "sealed baseline manifest object is unavailable or inconsistent",
        ));
    }
    let preconditions = artifacts
        .read_verified(baseline.source_preconditions_artifact_id())
        .map_err(artifact_storage_error)?;
    if preconditions.bytes() != canonical_preconditions {
        return Err(artifact_validation_error(
            "source precondition evidence object is unavailable or inconsistent",
        ));
    }
    for entry in baseline.entries() {
        let content = artifacts
            .read_verified(entry.content_artifact_id())
            .map_err(artifact_storage_error)?;
        if usize_to_u64(content.bytes().len(), "baseline content length")? != entry.bytes()
            || digest_bytes(content.bytes()) != entry.content_digest()
        {
            return Err(artifact_validation_error(
                "sealed baseline content object is inconsistent",
            ));
        }
    }
    Ok(())
}

fn verify_loaded_baseline_artifacts(
    artifacts: &ArtifactStore,
    baseline: &SubscriptionRunBaselineRecord,
) -> Result<(), CarlError> {
    let canonical_directories = canonical_baseline_directories(&baseline.directories)
        .map_err(|_| storage_invariant("stored baseline directory topology is invalid"))?;
    if usize_to_u64(
        baseline.directories.len(),
        "stored baseline directory count",
    )? != baseline.directory_count
        || digest_bytes(&canonical_directories) != baseline.directory_manifest_digest
    {
        return Err(storage_invariant(
            "stored baseline directory topology is inconsistent",
        ));
    }
    let canonical_manifest = canonical_manifest_bytes(&baseline.entries)?;
    if digest_bytes(&canonical_manifest) != baseline.manifest_digest
        || artifact_id_for_bytes(&canonical_manifest)? != baseline.manifest_artifact_id
    {
        return Err(storage_invariant(
            "stored baseline manifest metadata is inconsistent",
        ));
    }
    let manifest = artifacts
        .read_verified(&baseline.manifest_artifact_id)
        .map_err(artifact_storage_error)?;
    if manifest.bytes() != canonical_manifest {
        return Err(storage_invariant(
            "stored baseline manifest object is inconsistent",
        ));
    }
    let canonical_preconditions = canonical_source_preconditions(
        baseline.manifest_digest,
        baseline.entries.iter().map(|entry| SourcePreconditionRef {
            path: &entry.path,
            bytes: entry.byte_length,
            content_digest: entry.content_digest,
            platform: &entry.identity_platform,
            identity_a: &entry.identity_a,
            identity_b: &entry.identity_b,
            owner_id: &entry.owner_id,
            owner_mode: entry.owner_mode,
        }),
    )
    .map_err(|_| storage_invariant("stored source precondition evidence is invalid"))?;
    if digest_bytes(&canonical_preconditions) != baseline.source_preconditions_digest
        || artifact_id_for_bytes(&canonical_preconditions)?
            != baseline.source_preconditions_artifact_id
    {
        return Err(storage_invariant(
            "stored source precondition evidence metadata is inconsistent",
        ));
    }
    let preconditions = artifacts
        .read_verified(&baseline.source_preconditions_artifact_id)
        .map_err(artifact_storage_error)?;
    if preconditions.bytes() != canonical_preconditions {
        return Err(storage_invariant(
            "stored source precondition evidence object is inconsistent",
        ));
    }
    for entry in &baseline.entries {
        let content = artifacts
            .read_verified(&entry.content_artifact_id)
            .map_err(artifact_storage_error)?;
        if usize_to_u64(content.bytes().len(), "stored baseline content length")?
            != entry.byte_length
            || digest_bytes(content.bytes()) != entry.content_digest
        {
            return Err(storage_invariant(
                "stored baseline content object is inconsistent",
            ));
        }
    }
    Ok(())
}

fn validate_exact_replacement_proposal(
    proposal: &ExactReplacementProposal,
) -> Result<Vec<u8>, CarlError> {
    let envelope = proposal.canonical_envelope();
    if artifact_id_for_bytes(&envelope)? != *proposal.artifact_id()
        || artifact_id_for_bytes(proposal.payload())? != *proposal.payload_artifact_id()
        || digest_bytes(proposal.payload()) != proposal.payload_hash()
        || proposal.expected_live_hash() != proposal.before_hash()
        || proposal.after_hash() != proposal.payload_hash()
    {
        return Err(artifact_validation_error(
            "exact replacement proposal metadata is inconsistent",
        ));
    }
    Ok(envelope)
}

fn verify_exact_proposal_artifacts(
    artifacts: &ArtifactStore,
    proposal: &ExactReplacementProposal,
) -> Result<(), CarlError> {
    let canonical_envelope = validate_exact_replacement_proposal(proposal)?;
    let envelope = artifacts
        .read_verified(proposal.artifact_id())
        .map_err(artifact_storage_error)?;
    if envelope.bytes() != canonical_envelope {
        return Err(artifact_validation_error(
            "exact proposal envelope object is inconsistent",
        ));
    }
    let payload = artifacts
        .read_verified(proposal.payload_artifact_id())
        .map_err(artifact_storage_error)?;
    if payload.bytes() != proposal.payload() {
        return Err(artifact_validation_error(
            "exact proposal payload object is inconsistent",
        ));
    }
    Ok(())
}

fn validate_proposal_against_baseline(
    proposal: &ExactReplacementProposal,
    baseline: &SubscriptionRunBaselineRecord,
) -> Result<(), CarlError> {
    if proposal.baseline_manifest_digest() != baseline.manifest_digest
        || proposal.baseline_manifest_digest().to_string() != baseline.manifest_artifact_id.as_str()
    {
        return Err(artifact_validation_error(
            "proposal references a different sealed baseline",
        ));
    }
    let Some(entry) = baseline
        .entries
        .iter()
        .find(|entry| entry.path == proposal.path())
    else {
        return Err(artifact_validation_error(
            "proposal path is absent from the sealed baseline",
        ));
    };
    if entry.content_digest != proposal.before_hash()
        || proposal.expected_live_hash() != entry.content_digest
    {
        return Err(artifact_validation_error(
            "proposal before hash disagrees with the sealed baseline",
        ));
    }
    Ok(())
}

fn verify_loaded_proposal_artifacts(
    artifacts: &ArtifactStore,
    baseline: &SubscriptionRunBaselineRecord,
    proposal: &SubscriptionRunProposalRecord,
) -> Result<(), CarlError> {
    if proposal.baseline_manifest_artifact_id != baseline.manifest_artifact_id {
        return Err(storage_invariant(
            "stored proposal references a different baseline object",
        ));
    }
    let payload = artifacts
        .read_verified(&proposal.payload_artifact_id)
        .map_err(artifact_storage_error)?;
    if usize_to_u64(payload.bytes().len(), "stored proposal payload length")?
        != proposal.payload_bytes
        || digest_bytes(payload.bytes()) != proposal.payload_hash
        || proposal.payload_artifact_id.as_str() != proposal.payload_hash.to_string()
        || proposal.after_hash != proposal.payload_hash
    {
        return Err(storage_invariant(
            "stored proposal payload object is inconsistent",
        ));
    }
    if candidate_manifest_digest(
        baseline,
        &proposal.path,
        payload.bytes(),
        proposal.payload_hash,
    )? != proposal.candidate_manifest_digest
    {
        return Err(storage_invariant(
            "stored proposal candidate manifest digest is inconsistent",
        ));
    }
    let canonical_envelope = canonical_proposal_envelope(
        baseline.manifest_digest,
        &proposal.path,
        proposal.expected_live_hash,
        proposal.before_hash,
        proposal.after_hash,
        proposal.payload_hash,
        payload.bytes(),
    )?;
    if artifact_id_for_bytes(&canonical_envelope)? != proposal.proposal_artifact_id {
        return Err(storage_invariant(
            "stored proposal envelope ID is inconsistent",
        ));
    }
    let envelope = artifacts
        .read_verified(&proposal.proposal_artifact_id)
        .map_err(artifact_storage_error)?;
    if envelope.bytes() != canonical_envelope {
        return Err(storage_invariant(
            "stored proposal envelope object is inconsistent",
        ));
    }
    Ok(())
}

fn candidate_manifest_digest(
    baseline: &SubscriptionRunBaselineRecord,
    changed_path: &str,
    payload: &[u8],
    payload_digest: Sha256Digest,
) -> Result<Sha256Digest, CarlError> {
    if digest_bytes(payload) != payload_digest {
        return Err(artifact_validation_error(
            "candidate payload digest is inconsistent",
        ));
    }
    let mut found = false;
    let mut bytes = Vec::new();
    for entry in &baseline.entries {
        let path = entry.path.as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(path.len())
                .map_err(|_| artifact_validation_error("candidate path is too long"))?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(path);
        if entry.path == changed_path {
            bytes.extend_from_slice(
                &usize_to_u64(payload.len(), "candidate payload length")?.to_be_bytes(),
            );
            bytes.extend_from_slice(payload_digest.as_bytes());
            found = true;
        } else {
            bytes.extend_from_slice(&entry.byte_length.to_be_bytes());
            bytes.extend_from_slice(entry.content_digest.as_bytes());
        }
    }
    if !found {
        return Err(artifact_validation_error(
            "candidate path is absent from the sealed baseline",
        ));
    }
    Ok(digest_bytes(&bytes))
}

fn canonical_baseline_directories(directories: &[String]) -> Result<Vec<u8>, CarlError> {
    let mut bytes = Vec::new();
    let mut aggregate_path_bytes = 0_usize;
    let mut previous: Option<&str> = None;
    bytes.extend_from_slice(BASELINE_DIRECTORIES_DOMAIN);
    bytes.extend_from_slice(
        &u32::try_from(directories.len())
            .map_err(|_| artifact_validation_error("baseline directory count is invalid"))?
            .to_be_bytes(),
    );
    for directory in directories {
        let path = directory.as_str();
        if path.is_empty()
            || path.len() > 4_096
            || path.starts_with('/')
            || path.ends_with('/')
            || path.contains(['\\', '\0'])
            || path
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
            || previous.is_some_and(|previous| previous >= path)
        {
            return Err(artifact_validation_error(
                "sealed baseline directory topology is invalid",
            ));
        }
        if let Some((parent, _)) = path.rsplit_once('/')
            && directories
                .binary_search_by(|candidate| candidate.as_str().cmp(parent))
                .is_err()
        {
            return Err(artifact_validation_error(
                "sealed baseline directory parent is missing",
            ));
        }
        aggregate_path_bytes = aggregate_path_bytes
            .checked_add(path.len())
            .filter(|total| *total <= MAX_BASELINE_DIRECTORY_PATH_BYTES)
            .ok_or_else(|| {
                artifact_validation_error("baseline directory paths exceed the limit")
            })?;
        bytes.extend_from_slice(
            &u32::try_from(path.len())
                .map_err(|_| artifact_validation_error("baseline directory path is too long"))?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(path.as_bytes());
        previous = Some(path);
    }
    Ok(bytes)
}

fn canonical_manifest_bytes(
    entries: &[SubscriptionRunBaselineEntryRecord],
) -> Result<Vec<u8>, CarlError> {
    let mut bytes = Vec::new();
    for entry in entries {
        let path = entry.path.as_bytes();
        bytes.extend_from_slice(
            &u32::try_from(path.len())
                .map_err(|_| storage_invariant("stored baseline path is too long"))?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(path);
        bytes.extend_from_slice(&entry.byte_length.to_be_bytes());
        bytes.extend_from_slice(entry.content_digest.as_bytes());
    }
    Ok(bytes)
}

fn canonical_proposal_envelope(
    baseline: Sha256Digest,
    path: &str,
    expected_live: Sha256Digest,
    before: Sha256Digest,
    after: Sha256Digest,
    payload_hash: Sha256Digest,
    payload: &[u8],
) -> Result<Vec<u8>, CarlError> {
    let path_length = u32::try_from(path.len())
        .map_err(|_| artifact_validation_error("proposal path is too long"))?;
    let payload_length = usize_to_u64(payload.len(), "proposal payload length")?;
    let mut bytes = Vec::with_capacity(
        EXACT_REPLACEMENT_DOMAIN.len() + 32 + 4 + path.len() + (32 * 4) + 8 + payload.len(),
    );
    bytes.extend_from_slice(EXACT_REPLACEMENT_DOMAIN);
    bytes.extend_from_slice(baseline.as_bytes());
    bytes.extend_from_slice(&path_length.to_be_bytes());
    bytes.extend_from_slice(path.as_bytes());
    bytes.extend_from_slice(expected_live.as_bytes());
    bytes.extend_from_slice(before.as_bytes());
    bytes.extend_from_slice(after.as_bytes());
    bytes.extend_from_slice(payload_hash.as_bytes());
    bytes.extend_from_slice(&payload_length.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn load_subscription_run_baseline(
    connection: &Connection,
    run_id: RunId,
) -> Result<Option<SubscriptionRunBaselineRecord>, CarlError> {
    let header = connection
        .query_row(
            "SELECT baseline.manifest_artifact_id, baseline.manifest_digest,
                    baseline.source_preconditions_artifact_id,
                    baseline.source_preconditions_digest,
                    baseline.entry_count, baseline.total_bytes,
                    baseline.directory_count, baseline.directory_manifest_digest,
                    baseline.created_at,
                    manifest_object.byte_length, preconditions_object.byte_length
             FROM subscription_run_baselines AS baseline
             JOIN artifact_objects AS manifest_object
               ON manifest_object.id = baseline.manifest_artifact_id
             JOIN artifact_objects AS preconditions_object
               ON preconditions_object.id = baseline.source_preconditions_artifact_id
             WHERE baseline.run_id = ?1",
            [run_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()
        .map_err(storage_error)?;
    let Some((
        manifest_artifact_id,
        manifest_digest,
        source_preconditions_artifact_id,
        source_preconditions_digest,
        entry_count,
        total_bytes,
        directory_count,
        directory_manifest_digest,
        created_at,
        manifest_byte_length,
        source_preconditions_byte_length,
    )) = header
    else {
        if subscription_run_has_baseline(connection, run_id)? {
            return Err(storage_invariant(
                "stored baseline has no registered manifest object",
            ));
        }
        return Ok(None);
    };
    let manifest_artifact_id = ArtifactId::parse(manifest_artifact_id)
        .map_err(|_| storage_invariant("stored baseline artifact ID is invalid"))?;
    let manifest_digest = Sha256Digest::parse(manifest_digest)
        .map_err(|_| storage_invariant("stored baseline digest is invalid"))?;
    if manifest_artifact_id.as_str() != manifest_digest.to_string() {
        return Err(storage_invariant(
            "stored baseline artifact and digest disagree",
        ));
    }
    let source_preconditions_artifact_id = ArtifactId::parse(source_preconditions_artifact_id)
        .map_err(|_| storage_invariant("stored source preconditions artifact ID is invalid"))?;
    let source_preconditions_digest = Sha256Digest::parse(source_preconditions_digest)
        .map_err(|_| storage_invariant("stored source preconditions digest is invalid"))?;
    if source_preconditions_artifact_id.as_str() != source_preconditions_digest.to_string() {
        return Err(storage_invariant(
            "stored source preconditions artifact and digest disagree",
        ));
    }
    let entry_count = stored_u64(entry_count, "baseline entry count")?;
    let total_bytes = stored_u64(total_bytes, "baseline total bytes")?;
    let directory_count = directory_count
        .ok_or_else(|| storage_invariant("stored baseline directory count is missing"))
        .and_then(|count| stored_u64(count, "baseline directory count"))?;
    let directory_manifest_digest = directory_manifest_digest
        .ok_or_else(|| storage_invariant("stored baseline directory digest is missing"))
        .and_then(|digest| {
            Sha256Digest::parse(digest)
                .map_err(|_| storage_invariant("stored baseline directory digest is invalid"))
        })?;
    let manifest_byte_length = stored_u64(manifest_byte_length, "baseline manifest length")?;
    let source_preconditions_byte_length = stored_u64(
        source_preconditions_byte_length,
        "source preconditions length",
    )?;

    let rows = {
        let mut statement = connection
            .prepare(
                "SELECT ordinal, path, byte_length, content_sha256,
                        content_artifact_id, identity_platform,
                        identity_a, identity_b, owner_id, owner_mode
                 FROM subscription_run_baseline_entries
                 WHERE run_id = ?1
                 ORDER BY ordinal ASC",
            )
            .map_err(storage_error)?;
        statement
            .query_map([run_id.to_string()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                ))
            })
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?
    };
    let mut entries = Vec::with_capacity(rows.len());
    let mut measured_total = 0_u64;
    let mut canonical_manifest = Vec::new();
    for (
        index,
        (
            ordinal,
            path,
            byte_length,
            content_digest,
            content_artifact_id,
            identity_platform,
            identity_a,
            identity_b,
            owner_id,
            owner_mode,
        ),
    ) in rows.into_iter().enumerate()
    {
        let ordinal = stored_u64(ordinal, "baseline entry ordinal")?;
        if usize_to_u64(index, "baseline entry index")? != ordinal {
            return Err(storage_invariant("stored baseline entry order has a gap"));
        }
        let byte_length = stored_u64(byte_length, "baseline entry length")?;
        let content_digest = Sha256Digest::parse(content_digest)
            .map_err(|_| storage_invariant("stored baseline content digest is invalid"))?;
        let content_artifact_id = ArtifactId::parse(content_artifact_id)
            .map_err(|_| storage_invariant("stored baseline content artifact ID is invalid"))?;
        if content_artifact_id.as_str() != content_digest.to_string() {
            return Err(storage_invariant(
                "stored baseline content artifact and digest disagree",
            ));
        }
        require_registered_artifact_object(connection, &content_artifact_id, byte_length)?;
        let owner_mode = owner_mode
            .map(|mode| {
                u32::try_from(mode)
                    .map_err(|_| storage_invariant("stored baseline owner mode is invalid"))
            })
            .transpose()?;
        if !matches!(
            (identity_platform.as_str(), owner_mode),
            ("unix", Some(0..=0o7777)) | ("windows", None)
        ) {
            return Err(storage_invariant(
                "stored baseline identity platform and mode disagree",
            ));
        }
        let path_bytes = path.as_bytes();
        canonical_manifest.extend_from_slice(
            &u32::try_from(path_bytes.len())
                .map_err(|_| storage_invariant("stored baseline path is too long"))?
                .to_be_bytes(),
        );
        canonical_manifest.extend_from_slice(path_bytes);
        canonical_manifest.extend_from_slice(&byte_length.to_be_bytes());
        canonical_manifest.extend_from_slice(content_digest.as_bytes());
        measured_total = measured_total
            .checked_add(byte_length)
            .ok_or_else(|| storage_invariant("stored baseline size overflows"))?;
        entries.push(SubscriptionRunBaselineEntryRecord {
            ordinal,
            path,
            byte_length,
            content_digest,
            content_artifact_id,
            identity_platform,
            identity_a,
            identity_b,
            owner_id,
            owner_mode,
        });
    }
    if usize_to_u64(entries.len(), "stored baseline entries")? != entry_count
        || measured_total != total_bytes
        || usize_to_u64(canonical_manifest.len(), "stored baseline manifest length")?
            != manifest_byte_length
        || digest_bytes(&canonical_manifest) != manifest_digest
    {
        return Err(storage_invariant(
            "stored baseline projection is internally inconsistent",
        ));
    }
    let directory_rows = {
        let mut statement = connection
            .prepare(
                "SELECT ordinal, path
                 FROM subscription_run_baseline_directories
                 WHERE run_id = ?1
                 ORDER BY ordinal ASC",
            )
            .map_err(storage_error)?;
        statement
            .query_map([run_id.to_string()], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?
    };
    let mut directories = Vec::with_capacity(directory_rows.len());
    for (index, (ordinal, path)) in directory_rows.into_iter().enumerate() {
        let ordinal = stored_u64(ordinal, "baseline directory ordinal")?;
        if usize_to_u64(index, "baseline directory index")? != ordinal {
            return Err(storage_invariant(
                "stored baseline directory order has a gap",
            ));
        }
        directories.push(path);
    }
    let canonical_directories = canonical_baseline_directories(&directories)
        .map_err(|_| storage_invariant("stored baseline directory topology is invalid"))?;
    if usize_to_u64(directories.len(), "stored baseline directories")? != directory_count
        || digest_bytes(&canonical_directories) != directory_manifest_digest
    {
        return Err(storage_invariant(
            "stored baseline directory topology is internally inconsistent",
        ));
    }
    let canonical_preconditions = canonical_source_preconditions(
        manifest_digest,
        entries.iter().map(|entry| SourcePreconditionRef {
            path: &entry.path,
            bytes: entry.byte_length,
            content_digest: entry.content_digest,
            platform: &entry.identity_platform,
            identity_a: &entry.identity_a,
            identity_b: &entry.identity_b,
            owner_id: &entry.owner_id,
            owner_mode: entry.owner_mode,
        }),
    )
    .map_err(|_| storage_invariant("stored source precondition evidence is invalid"))?;
    if usize_to_u64(
        canonical_preconditions.len(),
        "stored source preconditions length",
    )? != source_preconditions_byte_length
        || digest_bytes(&canonical_preconditions) != source_preconditions_digest
    {
        return Err(storage_invariant(
            "stored source precondition evidence is internally inconsistent",
        ));
    }
    Ok(Some(SubscriptionRunBaselineRecord {
        run_id,
        manifest_artifact_id,
        manifest_digest,
        source_preconditions_artifact_id,
        source_preconditions_digest,
        entry_count,
        total_bytes,
        directory_count,
        directory_manifest_digest,
        entries,
        directories,
        created_at: parse_timestamp(&created_at)?,
    }))
}

fn load_subscription_run_inspection(
    connection: &Connection,
    run_id: RunId,
) -> Result<Option<SubscriptionRunInspectionRecord>, CarlError> {
    connection
        .query_row(
            "SELECT outcome, stage_manifest_digest, created_at
             FROM subscription_run_inspections
             WHERE run_id = ?1",
            [run_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(storage_error)?
        .map(|(outcome, stage_manifest_digest, created_at)| {
            Ok(SubscriptionRunInspectionRecord {
                run_id,
                outcome: SubscriptionRunInspectionOutcome::parse(&outcome)?,
                stage_manifest_digest: Sha256Digest::parse(stage_manifest_digest).map_err(
                    |_| storage_invariant("stored inspection manifest digest is invalid"),
                )?,
                created_at: parse_timestamp(&created_at)?,
            })
        })
        .transpose()
}

fn load_subscription_run_proposal(
    connection: &Connection,
    run_id: RunId,
) -> Result<Option<SubscriptionRunProposalRecord>, CarlError> {
    let raw = connection
        .query_row(
            "SELECT proposal.proposal_artifact_id,
                    proposal.baseline_manifest_artifact_id,
                    proposal.path, proposal.expected_live_sha256,
                    proposal.before_sha256, proposal.after_sha256,
                    proposal.payload_sha256, proposal.payload_bytes,
                    proposal.created_at, inspection.outcome,
                    inspection.stage_manifest_digest
             FROM subscription_run_proposals AS proposal
             JOIN subscription_run_inspections AS inspection
               ON inspection.run_id = proposal.run_id
             WHERE proposal.run_id = ?1",
            [run_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                ))
            },
        )
        .optional()
        .map_err(storage_error)?;
    let Some((
        proposal_artifact_id,
        baseline_manifest_artifact_id,
        path,
        expected_live_hash,
        before_hash,
        after_hash,
        payload_hash,
        payload_bytes,
        created_at,
        outcome,
        candidate_manifest_digest,
    )) = raw
    else {
        return Ok(None);
    };
    if SubscriptionRunInspectionOutcome::parse(&outcome)?
        != SubscriptionRunInspectionOutcome::ExactReplacement
    {
        return Err(storage_invariant(
            "stored proposal has a non-proposal inspection outcome",
        ));
    }
    let proposal_artifact_id = ArtifactId::parse(proposal_artifact_id)
        .map_err(|_| storage_invariant("stored proposal artifact ID is invalid"))?;
    let baseline_manifest_artifact_id = ArtifactId::parse(baseline_manifest_artifact_id)
        .map_err(|_| storage_invariant("stored proposal baseline artifact ID is invalid"))?;
    let expected_live_hash = Sha256Digest::parse(expected_live_hash)
        .map_err(|_| storage_invariant("stored proposal live hash is invalid"))?;
    let before_hash = Sha256Digest::parse(before_hash)
        .map_err(|_| storage_invariant("stored proposal before hash is invalid"))?;
    let after_hash = Sha256Digest::parse(after_hash)
        .map_err(|_| storage_invariant("stored proposal after hash is invalid"))?;
    let payload_hash = Sha256Digest::parse(payload_hash)
        .map_err(|_| storage_invariant("stored proposal payload hash is invalid"))?;
    let payload_artifact_id = ArtifactId::parse(payload_hash.to_string())
        .map_err(|_| storage_invariant("stored proposal payload artifact ID is invalid"))?;
    let candidate_manifest_digest = Sha256Digest::parse(candidate_manifest_digest)
        .map_err(|_| storage_invariant("stored candidate manifest digest is invalid"))?;
    let payload_bytes = stored_u64(payload_bytes, "proposal payload length")?;
    require_registered_artifact_object(connection, &payload_artifact_id, payload_bytes)?;
    let envelope_bytes = usize_to_u64(
        EXACT_REPLACEMENT_DOMAIN.len() + 32 + 4 + path.len() + (32 * 4) + 8,
        "proposal envelope metadata length",
    )?
    .checked_add(payload_bytes)
    .ok_or_else(|| storage_invariant("stored proposal envelope length overflows"))?;
    require_registered_artifact_object(connection, &proposal_artifact_id, envelope_bytes)?;
    if expected_live_hash != before_hash || after_hash != payload_hash {
        return Err(storage_invariant(
            "stored proposal hash relationships are inconsistent",
        ));
    }
    let baseline = load_subscription_run_baseline(connection, run_id)?
        .ok_or_else(|| storage_invariant("stored proposal has no sealed baseline"))?;
    if baseline.manifest_artifact_id != baseline_manifest_artifact_id
        || !baseline
            .entries
            .iter()
            .any(|entry| entry.path == path && entry.content_digest == before_hash)
    {
        return Err(storage_invariant(
            "stored proposal disagrees with its sealed baseline",
        ));
    }
    Ok(Some(SubscriptionRunProposalRecord {
        run_id,
        proposal_artifact_id,
        payload_artifact_id,
        baseline_manifest_artifact_id,
        candidate_manifest_digest,
        path,
        expected_live_hash,
        before_hash,
        after_hash,
        payload_hash,
        payload_bytes,
        created_at: parse_timestamp(&created_at)?,
    }))
}

fn load_subscription_run_verification_request(
    connection: &Connection,
    run_id: RunId,
) -> Result<Option<VerificationRequest>, CarlError> {
    let raw = connection
        .query_row(
            "SELECT id, started_run_sequence, inspection_outcome,
                    baseline_manifest_artifact_id,
                    source_preconditions_artifact_id,
                    source_preconditions_digest,
                    baseline_directory_manifest_digest,
                    proposal_artifact_id, payload_artifact_id,
                    candidate_manifest_digest, executable_path,
                    executable_metadata_risk, executable_platform_identity,
                    executable_byte_length, executable_content_sha256,
                    executable_attestation_digest,
                    verification_spec_digest, request_digest, argv_digest,
                    environment_profile, execution_timeout_nanos,
                    max_output_bytes, graceful_shutdown_timeout_nanos,
                    forced_shutdown_timeout_nanos, poll_interval_nanos,
                    argv_count, argv_bytes, created_at
             FROM subscription_run_verification_requests
             WHERE run_id = ?1",
            [run_id.to_string()],
            |row| {
                Ok(StoredVerificationRequest {
                    verification_id: row.get(0)?,
                    started_run_sequence: row.get(1)?,
                    inspection_outcome: row.get(2)?,
                    baseline_manifest_artifact_id: row.get(3)?,
                    source_preconditions_artifact_id: row.get(4)?,
                    source_preconditions_digest: row.get(5)?,
                    baseline_directory_manifest_digest: row.get(6)?,
                    proposal_artifact_id: row.get(7)?,
                    payload_artifact_id: row.get(8)?,
                    candidate_manifest_digest: row.get(9)?,
                    executable_path: row.get(10)?,
                    executable_metadata_risk: row.get(11)?,
                    executable_platform_identity: row.get(12)?,
                    executable_byte_length: row.get(13)?,
                    executable_content_sha256: row.get(14)?,
                    executable_attestation_digest: row.get(15)?,
                    verification_spec_digest: row.get(16)?,
                    request_digest: row.get(17)?,
                    argv_digest: row.get(18)?,
                    environment_profile: row.get(19)?,
                    execution_timeout_nanos: row.get(20)?,
                    max_output_bytes: row.get(21)?,
                    graceful_shutdown_timeout_nanos: row.get(22)?,
                    forced_shutdown_timeout_nanos: row.get(23)?,
                    poll_interval_nanos: row.get(24)?,
                    argv_count: row.get(25)?,
                    argv_bytes: row.get(26)?,
                    created_at: row.get(27)?,
                })
            },
        )
        .optional()
        .map_err(storage_error)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.inspection_outcome != SubscriptionRunInspectionOutcome::ExactReplacement.as_str() {
        return Err(storage_invariant(
            "stored verification request has an invalid inspection outcome",
        ));
    }

    let baseline = load_subscription_run_baseline(connection, run_id)?
        .ok_or_else(|| storage_invariant("stored verification request has no sealed baseline"))?;
    let proposal = load_subscription_run_proposal(connection, run_id)?
        .ok_or_else(|| storage_invariant("stored verification request has no exact proposal"))?;
    let argv_rows = {
        let mut statement = connection
            .prepare(
                "SELECT ordinal, value
                 FROM subscription_run_verification_argv
                 WHERE verification_id = ?1
                 ORDER BY ordinal ASC",
            )
            .map_err(storage_error)?;
        statement
            .query_map([raw.verification_id.as_str()], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?
    };
    let mut arguments = Vec::with_capacity(argv_rows.len());
    let mut argument_bytes = 0_u64;
    for (index, (ordinal, value)) in argv_rows.into_iter().enumerate() {
        if stored_u64(ordinal, "verification argument ordinal")?
            != usize_to_u64(index, "verification argument index")?
        {
            return Err(storage_invariant(
                "stored verification argument order has a gap",
            ));
        }
        argument_bytes = argument_bytes
            .checked_add(usize_to_u64(
                value.len(),
                "stored verification argument length",
            )?)
            .ok_or_else(|| storage_invariant("stored verification argument bytes overflow"))?;
        arguments.push(value);
    }
    if usize_to_u64(arguments.len(), "stored verification argument count")?
        != stored_u64(raw.argv_count, "verification argument count")?
        || argument_bytes != stored_u64(raw.argv_bytes, "verification argument bytes")?
    {
        return Err(storage_invariant(
            "stored verification argument projection is inconsistent",
        ));
    }

    let executable = VerificationExecutableEvidence::rehydrate(
        raw.executable_path,
        raw.executable_metadata_risk,
        raw.executable_platform_identity,
        stored_u64(
            raw.executable_byte_length,
            "verification executable byte length",
        )?,
        parse_stored_digest(
            raw.executable_content_sha256,
            "verification executable content digest",
        )?,
    )
    .map_err(|_| storage_invariant("stored verification executable evidence is invalid"))?;
    let limits = VerificationLimits::new(
        stored_duration_nanos(
            raw.execution_timeout_nanos,
            "verification execution timeout",
        )?,
        stored_usize(raw.max_output_bytes, "verification maximum output bytes")?,
        stored_duration_nanos(
            raw.graceful_shutdown_timeout_nanos,
            "verification graceful shutdown timeout",
        )?,
        stored_duration_nanos(
            raw.forced_shutdown_timeout_nanos,
            "verification forced shutdown timeout",
        )?,
        stored_duration_nanos(raw.poll_interval_nanos, "verification poll interval")?,
    )
    .map_err(|_| storage_invariant("stored verification limits are invalid"))?;
    let specification = VerificationSpecEvidence::rehydrate(
        executable,
        arguments,
        VerificationEnvironmentProfile::from_storage_str(&raw.environment_profile)
            .map_err(|_| storage_invariant("stored verification environment is invalid"))?,
        limits,
        parse_stored_digest(
            raw.executable_attestation_digest,
            "verification executable attestation digest",
        )?,
        parse_stored_digest(raw.argv_digest, "verification argument vector digest")?,
        parse_stored_digest(
            raw.verification_spec_digest,
            "verification specification digest",
        )?,
    )
    .map_err(|_| storage_invariant("stored verification specification is inconsistent"))?;
    let verification_id = parse_id::<VerificationId>("verification ID", &raw.verification_id)?;
    let baseline_manifest_artifact_id = ArtifactId::parse(raw.baseline_manifest_artifact_id)
        .map_err(|_| storage_invariant("stored verification baseline artifact ID is invalid"))?;
    let source_preconditions_artifact_id = ArtifactId::parse(raw.source_preconditions_artifact_id)
        .map_err(|_| {
            storage_invariant("stored verification source-preconditions artifact ID is invalid")
        })?;
    let proposal_artifact_id = ArtifactId::parse(raw.proposal_artifact_id)
        .map_err(|_| storage_invariant("stored verification proposal artifact ID is invalid"))?;
    let payload_artifact_id = ArtifactId::parse(raw.payload_artifact_id)
        .map_err(|_| storage_invariant("stored verification payload artifact ID is invalid"))?;
    let request = VerificationRequest::rehydrate(
        verification_id,
        run_id,
        baseline_manifest_artifact_id,
        baseline.manifest_digest,
        source_preconditions_artifact_id,
        parse_stored_digest(
            raw.source_preconditions_digest,
            "verification source-preconditions digest",
        )?,
        parse_stored_digest(
            raw.baseline_directory_manifest_digest,
            "verification directory-manifest digest",
        )?,
        proposal_artifact_id,
        payload_artifact_id,
        proposal.payload_hash,
        parse_stored_digest(
            raw.candidate_manifest_digest,
            "verification candidate-manifest digest",
        )?,
        specification,
        parse_stored_digest(raw.request_digest, "verification request digest")?,
    )
    .map_err(|_| storage_invariant("stored verification request is inconsistent"))?;
    if request.baseline_manifest_artifact_id() != &baseline.manifest_artifact_id
        || request.source_preconditions_artifact_id() != &baseline.source_preconditions_artifact_id
        || request.source_preconditions_digest() != baseline.source_preconditions_digest
        || request.baseline_directory_manifest_digest() != baseline.directory_manifest_digest
        || request.proposal_artifact_id() != &proposal.proposal_artifact_id
        || request.payload_artifact_id() != &proposal.payload_artifact_id
        || request.candidate_manifest_digest() != proposal.candidate_manifest_digest
    {
        return Err(storage_invariant(
            "stored verification request disagrees with baseline or proposal evidence",
        ));
    }

    let started_run_sequence =
        stored_u64(raw.started_run_sequence, "verification start run sequence")?;
    let created_at = parse_timestamp(&raw.created_at)?;
    let run = load_subscription_run(connection, run_id)?
        .ok_or_else(|| storage_invariant("stored verification request has no subscription run"))?;
    let events = load_and_validate_subscription_run_events(connection, &run)?;
    let start_index = usize::try_from(
        started_run_sequence
            .checked_sub(1)
            .ok_or_else(|| storage_invariant("verification start sequence is invalid"))?,
    )
    .map_err(|_| storage_invariant("verification start sequence is too large"))?;
    match events.get(start_index) {
        Some(EventEnvelope {
            timestamp,
            event:
                Event::SubscriptionRunTransitioned {
                    transition,
                    trust_label,
                    ..
                },
            ..
        }) if *timestamp == created_at
            && transition.from() == RunState::Inspecting
            && transition.to() == RunState::Verifying
            && *trust_label == RunTrustLabel::TrustedCarlState => {}
        _ => {
            return Err(storage_invariant(
                "stored verification request has no matching start transition",
            ));
        }
    }
    Ok(Some(request))
}

fn load_subscription_run_verification_result(
    connection: &Connection,
    run_id: RunId,
) -> Result<Option<VerificationResult>, CarlError> {
    let raw = connection
        .query_row(
            "SELECT verification_id, completed_run_sequence,
                    request_digest,
                    expected_candidate_manifest_digest,
                    expected_directory_manifest_digest,
                    outcome, exit_code,
                    observed_candidate_manifest_digest,
                    observed_directory_manifest_digest,
                    executable_attestation_evidence,
                    executable_attestation_digest,
                    stdout_text, stdout_bytes, stdout_digest,
                    stderr_text, stderr_bytes, stderr_digest,
                    max_output_bytes, duration_nanos, result_digest,
                    completed_at
             FROM subscription_run_verification_results
             WHERE run_id = ?1",
            [run_id.to_string()],
            |row| {
                Ok(StoredVerificationResult {
                    verification_id: row.get(0)?,
                    completed_run_sequence: row.get(1)?,
                    request_digest: row.get(2)?,
                    expected_candidate_manifest_digest: row.get(3)?,
                    expected_directory_manifest_digest: row.get(4)?,
                    outcome: row.get(5)?,
                    exit_code: row.get(6)?,
                    observed_candidate_manifest_digest: row.get(7)?,
                    observed_directory_manifest_digest: row.get(8)?,
                    executable_attestation_evidence: row.get(9)?,
                    executable_attestation_digest: row.get(10)?,
                    stdout_text: row.get(11)?,
                    stdout_bytes: row.get(12)?,
                    stdout_digest: row.get(13)?,
                    stderr_text: row.get(14)?,
                    stderr_bytes: row.get(15)?,
                    stderr_digest: row.get(16)?,
                    max_output_bytes: row.get(17)?,
                    duration_nanos: row.get(18)?,
                    result_digest: row.get(19)?,
                    completed_at: row.get(20)?,
                })
            },
        )
        .optional()
        .map_err(storage_error)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let request = load_subscription_run_verification_request(connection, run_id)?
        .ok_or_else(|| storage_invariant("stored verification result has no request"))?;
    let verification_id = parse_id::<VerificationId>("verification ID", &raw.verification_id)?;
    let request_digest =
        parse_stored_digest(raw.request_digest, "verification result request digest")?;
    let expected_candidate_manifest_digest = parse_stored_digest(
        raw.expected_candidate_manifest_digest,
        "verification expected candidate-manifest digest",
    )?;
    let expected_directory_manifest_digest = parse_stored_digest(
        raw.expected_directory_manifest_digest,
        "verification expected directory-manifest digest",
    )?;
    if verification_id != request.verification_id()
        || request_digest != request.request_digest()
        || expected_candidate_manifest_digest != request.candidate_manifest_digest()
        || expected_directory_manifest_digest != request.baseline_directory_manifest_digest()
        || stored_usize(
            raw.max_output_bytes,
            "verification result maximum output bytes",
        )? != request.specification().limits().max_output_bytes()
    {
        return Err(storage_invariant(
            "stored verification result disagrees with its request",
        ));
    }
    let outcome = VerificationOutcome::from_storage_str(&raw.outcome)
        .map_err(|_| storage_invariant("stored verification outcome is invalid"))?;
    let rehydration_authority = VerificationResultRehydrationAuthority {
        _repository_loader_only: (),
    };
    let result = VerificationResult::rehydrate(
        &rehydration_authority,
        &request,
        outcome,
        raw.exit_code
            .map(|code| {
                i32::try_from(code)
                    .map_err(|_| storage_invariant("stored verification exit code is invalid"))
            })
            .transpose()?,
        parse_optional_stored_digest(
            raw.observed_candidate_manifest_digest,
            "verification observed candidate-manifest digest",
        )?,
        parse_optional_stored_digest(
            raw.observed_directory_manifest_digest,
            "verification observed directory-manifest digest",
        )?,
        raw.executable_attestation_evidence,
        parse_stored_digest(
            raw.executable_attestation_digest,
            "verification result executable attestation digest",
        )?,
        raw.stdout_text,
        stored_u64(raw.stdout_bytes, "verification stdout bytes")?,
        parse_stored_digest(raw.stdout_digest, "verification stdout digest")?,
        raw.stderr_text,
        stored_u64(raw.stderr_bytes, "verification stderr bytes")?,
        parse_stored_digest(raw.stderr_digest, "verification stderr digest")?,
        stored_duration_nanos(raw.duration_nanos, "verification result duration")?,
        parse_stored_digest(raw.result_digest, "verification result digest")?,
    )
    .map_err(|_| storage_invariant("stored verification result is inconsistent"))?;

    let completed_run_sequence = stored_u64(
        raw.completed_run_sequence,
        "verification completion run sequence",
    )?;
    let completed_at = parse_timestamp(&raw.completed_at)?;
    let run = load_subscription_run(connection, run_id)?
        .ok_or_else(|| storage_invariant("stored verification result has no subscription run"))?;
    let events = load_and_validate_subscription_run_events(connection, &run)?;
    let completion_index = usize::try_from(
        completed_run_sequence
            .checked_sub(1)
            .ok_or_else(|| storage_invariant("verification completion sequence is invalid"))?,
    )
    .map_err(|_| storage_invariant("verification completion sequence is too large"))?;
    let (expected_state, expected_failure) = match outcome {
        VerificationOutcome::Passed => (RunState::AwaitingPromotionApproval, None),
        VerificationOutcome::Cancelled => (RunState::Cancelled, None),
        _ => (RunState::Failed, Some(RunFailureCode::VerificationFailed)),
    };
    match events.get(completion_index) {
        Some(EventEnvelope {
            timestamp,
            event:
                Event::SubscriptionRunTransitioned {
                    transition,
                    trust_label,
                    ..
                },
            ..
        }) if *timestamp == completed_at
            && transition.from() == RunState::Verifying
            && transition.to() == expected_state
            && transition.failure_code() == expected_failure
            && *trust_label == RunTrustLabel::TrustedCarlVerification => {}
        _ => {
            return Err(storage_invariant(
                "stored verification result has no matching completion transition",
            ));
        }
    }
    Ok(Some(result))
}

fn artifact_id_for_bytes(bytes: &[u8]) -> Result<ArtifactId, CarlError> {
    ArtifactId::parse(format!("{:x}", Sha256::digest(bytes)))
        .map_err(|_| artifact_validation_error("content-addressed artifact ID is invalid"))
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn artifact_validation_error(detail: &str) -> CarlError {
    CarlError::Validation {
        detail: detail.to_owned(),
    }
}

fn artifact_storage_error(error: crate::artifacts::ArtifactError) -> CarlError {
    CarlError::Storage {
        detail: error.to_string(),
    }
}

fn proposal_storage_error(error: crate::staging::ProposalError) -> CarlError {
    CarlError::Validation {
        detail: error.to_string(),
    }
}

fn verification_storage_error(error: crate::verification::VerificationError) -> CarlError {
    CarlError::Validation {
        detail: error.to_string(),
    }
}

fn duration_to_sql_nanos(value: Duration, kind: &str) -> Result<i64, CarlError> {
    i64::try_from(value.as_nanos())
        .map_err(|_| storage_invariant(&format!("{kind} cannot be represented durably")))
}

fn stored_duration_nanos(value: i64, kind: &str) -> Result<Duration, CarlError> {
    stored_u64(value, kind).map(Duration::from_nanos)
}

fn stored_usize(value: i64, kind: &str) -> Result<usize, CarlError> {
    usize::try_from(stored_u64(value, kind)?)
        .map_err(|_| storage_invariant(&format!("stored {kind} is too large")))
}

fn parse_stored_digest(value: String, kind: &str) -> Result<Sha256Digest, CarlError> {
    Sha256Digest::parse(value).map_err(|_| storage_invariant(&format!("stored {kind} is invalid")))
}

fn parse_optional_stored_digest(
    value: Option<String>,
    kind: &str,
) -> Result<Option<Sha256Digest>, CarlError> {
    value
        .map(|value| parse_stored_digest(value, kind))
        .transpose()
}

fn usize_to_u64(value: usize, kind: &str) -> Result<u64, CarlError> {
    u64::try_from(value)
        .map_err(|_| storage_invariant(&format!("{kind} cannot be represented durably")))
}

fn usize_to_sql(value: usize, kind: &str) -> Result<i64, CarlError> {
    i64::try_from(value)
        .map_err(|_| storage_invariant(&format!("{kind} cannot be represented durably")))
}

fn stored_u64(value: i64, kind: &str) -> Result<u64, CarlError> {
    u64::try_from(value).map_err(|_| storage_invariant(&format!("stored {kind} is invalid")))
}

fn validate_checkpoint_input(input: &NewCheckpoint) -> Result<(), CarlError> {
    if input.checkpoint.task_id != input.task_id
        || input.context_package.checkpoint_id != input.checkpoint.checkpoint_id
        || input.context_package.source_sequence_start != input.checkpoint.source_sequence_start
        || input.context_package.source_sequence_end != input.checkpoint.source_sequence_end
    {
        return Err(checkpoint_validation(
            "checkpoint and context package metadata do not match",
        ));
    }
    let checkpoint_digest = input
        .checkpoint
        .digest()
        .map_err(checkpoint_validation_error)?;
    if checkpoint_digest != input.checkpoint_digest {
        return Err(checkpoint_validation(
            "canonical checkpoint digest does not match",
        ));
    }
    let package_digest = input
        .context_package
        .digest()
        .map_err(context_validation_error)?;
    if package_digest != input.context_package_digest {
        return Err(checkpoint_validation(
            "canonical context package digest does not match",
        ));
    }
    Ok(())
}

fn validate_checkpoint_authority(
    transaction: &Transaction<'_>,
    current: &TaskRecord,
    checkpoint: &CanonicalCheckpoint,
) -> Result<(), CarlError> {
    if current.snapshot.active_epoch.is_some() || current.snapshot.has_unresolved_operations() {
        return Err(checkpoint_validation(
            "checkpoint requires an authoritative safe boundary",
        ));
    }
    if checkpoint.contract != current.snapshot.contract
        || checkpoint.provider.context_id != current.snapshot.provider_context
    {
        return Err(checkpoint_validation(
            "checkpoint contract or provider context does not match the task projection",
        ));
    }

    let (provider, model, effort) = transaction
        .query_row(
            "SELECT provider, model, effort FROM agent_tasks WHERE id = ?1",
            [checkpoint.task_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .map_err(storage_error)?;
    if checkpoint.provider.provider != provider
        || checkpoint.provider.model != model
        || checkpoint.provider.effort != effort
    {
        return Err(checkpoint_validation(
            "checkpoint provider metadata does not match the task projection",
        ));
    }

    let mut observed_total_tokens = None;
    let mut observed_context_window = None;
    let mut journal_operations = BTreeMap::new();
    let mut after_sequence = None;
    loop {
        let page = read_task_event_page_from_connection(
            transaction,
            checkpoint.task_id,
            after_sequence,
            512,
        )?;
        if page.is_empty() {
            break;
        }
        for envelope in &page {
            let Event::TaskLifecycle { event, .. } = &envelope.event else {
                return Err(storage_invariant(
                    "task event page returned a non-task event",
                ));
            };
            match event {
                TaskEvent::UsageObserved {
                    total_tokens,
                    context_window,
                    ..
                } => {
                    observed_total_tokens = Some(*total_tokens);
                    if context_window.is_some() {
                        observed_context_window = *context_window;
                    }
                }
                TaskEvent::OperationIntentRecorded {
                    operation_id,
                    effect_class,
                    request_digest,
                    ..
                } => {
                    if journal_operations
                        .insert(
                            *operation_id,
                            JournalOperationState {
                                status: OperationStatus::IntentRecorded,
                                effect_class: *effect_class,
                                request_digest: request_digest.clone(),
                                last_transition_sequence: envelope.sequence,
                                evidence: OperationEvidenceState::default(),
                            },
                        )
                        .is_some()
                    {
                        return Err(storage_invariant(
                            "task journal contains a duplicate operation",
                        ));
                    }
                }
                TaskEvent::OperationTransitioned {
                    operation_id,
                    from,
                    to,
                    evidence_sequences,
                } => {
                    let operation = journal_operations.get_mut(operation_id).ok_or_else(|| {
                        storage_invariant("task journal operation transition has no intent")
                    })?;
                    operation
                        .evidence
                        .transition(
                            operation.status,
                            *from,
                            *to,
                            operation.last_transition_sequence,
                            envelope.sequence,
                            evidence_sequences,
                        )
                        .map_err(|_| {
                            storage_invariant(
                                "task journal operation transition has invalid evidence",
                            )
                        })?;
                    operation.status = *to;
                    operation.last_transition_sequence = envelope.sequence;
                }
                TaskEvent::OperationEvidenceRecorded { operation_id, .. } => {
                    let operation = journal_operations.get_mut(operation_id).ok_or_else(|| {
                        storage_invariant("task journal operation evidence has no intent")
                    })?;
                    operation
                        .evidence
                        .record(
                            operation.status,
                            operation.last_transition_sequence,
                            envelope.sequence,
                        )
                        .map_err(|_| {
                            storage_invariant("task journal operation evidence is invalid")
                        })?;
                }
                _ => {}
            }
        }
        after_sequence = page.last().map(|event| event.sequence);
    }
    if checkpoint.provider.observed_total_tokens != observed_total_tokens
        || checkpoint.provider.observed_context_window != observed_context_window
    {
        return Err(checkpoint_validation(
            "checkpoint usage metadata does not match the task journal",
        ));
    }

    let mut checkpoint_operations = checkpoint
        .operations
        .iter()
        .map(|operation| {
            (
                operation.operation_id,
                operation.status,
                operation.effect_class,
                operation.request_digest.clone(),
                operation.evidence_sequences.clone(),
            )
        })
        .collect::<Vec<_>>();
    checkpoint_operations.sort_by_key(|operation| operation.0);
    let authoritative_operations = journal_operations
        .into_iter()
        .map(|(operation_id, operation)| {
            (
                operation_id,
                operation.status,
                operation.effect_class,
                operation.request_digest,
                operation.evidence.consumed_sequences().to_vec(),
            )
        })
        .collect::<Vec<_>>();
    if checkpoint_operations != authoritative_operations {
        return Err(checkpoint_validation(
            "checkpoint operations do not match the authoritative projection",
        ));
    }

    let expected_generation = match current.snapshot.latest_checkpoint {
        None => 0,
        Some(checkpoint_id) => {
            let json = transaction
                .query_row(
                    "SELECT checkpoint_json
                     FROM task_checkpoints
                     WHERE task_id = ?1 AND id = ?2",
                    params![checkpoint.task_id.to_string(), checkpoint_id.to_string()],
                    |row| row.get::<_, Option<String>>(0),
                )
                .map_err(storage_error)?
                .ok_or_else(|| {
                    checkpoint_validation("previous checkpoint has no canonical payload")
                })?;
            let previous = serde_json::from_str::<CanonicalCheckpoint>(&json)
                .map_err(|_| checkpoint_validation("previous canonical checkpoint is invalid"))?;
            previous
                .compaction_generation
                .checked_add(1)
                .ok_or_else(|| checkpoint_validation("checkpoint generation overflowed"))?
        }
    };
    if checkpoint.compaction_generation != expected_generation {
        return Err(checkpoint_validation(
            "checkpoint generation does not match durable history",
        ));
    }
    Ok(())
}

struct JournalOperationState {
    status: OperationStatus,
    effect_class: EffectClass,
    request_digest: String,
    last_transition_sequence: u64,
    evidence: OperationEvidenceState,
}

fn validate_checkpoint_history(
    transaction: &Transaction<'_>,
    current: &TaskRecord,
    input: &NewCheckpoint,
) -> Result<(), CarlError> {
    let task_id = input.task_id.to_string();
    let bounds = transaction
        .query_row(
            "SELECT MIN(sequence), MAX(sequence)
             FROM events
             WHERE session_id = ?1
               AND json_extract(event_json, '$.type') = 'task_lifecycle'
               AND json_extract(event_json, '$.task_id') = ?2",
            params![current.snapshot.session_id.to_string(), task_id],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .map_err(storage_error)?;
    let (Some(start), Some(end)) = bounds else {
        return Err(storage_invariant(
            "checkpoint task has no authoritative journal",
        ));
    };
    let start = stored_u64(start, "checkpoint source start")?;
    let end = stored_u64(end, "checkpoint source end")?;
    if input.checkpoint.source_sequence_start != start
        || input.checkpoint.source_sequence_end != end
    {
        return Err(checkpoint_validation(
            "checkpoint source range does not match the task journal",
        ));
    }

    let expected_previous = current
        .snapshot
        .latest_checkpoint
        .map(|checkpoint_id| {
            transaction
                .query_row(
                    "SELECT digest
                     FROM task_checkpoints
                     WHERE task_id = ?1 AND id = ?2",
                    params![input.task_id.to_string(), checkpoint_id.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(storage_error)?
                .ok_or_else(|| storage_invariant("latest task checkpoint projection is missing"))
        })
        .transpose()?;
    if input.checkpoint.previous_digest != expected_previous {
        return Err(checkpoint_validation(
            "checkpoint previous digest does not match durable history",
        ));
    }
    Ok(())
}

fn validate_checkpoint_artifacts(
    transaction: &Connection,
    checkpoint: &CanonicalCheckpoint,
) -> Result<(), CarlError> {
    for digest in checkpoint.artifact_digests() {
        let registered = transaction
            .query_row(
                "SELECT 1 FROM artifact_objects WHERE id = ?1",
                [&digest],
                |_| Ok(()),
            )
            .optional()
            .map_err(storage_error)?;
        if registered.is_none() {
            return Err(checkpoint_validation(
                "checkpoint references an unknown artifact",
            ));
        }
    }
    Ok(())
}

fn validate_task_canonical_payloads(connection: &Connection) -> Result<(), CarlError> {
    let rows = connection
        .prepare(
            "SELECT checkpoint.id, checkpoint.task_id, checkpoint.digest,
                    checkpoint.event_sequence, checkpoint.checkpoint_json,
                    package.id, package.generation, package.event_sequence,
                    package.package_json
             FROM task_checkpoints AS checkpoint
             LEFT JOIN task_context_packages AS package
               ON package.task_id = checkpoint.task_id
              AND package.checkpoint_id = checkpoint.id
             WHERE checkpoint.checkpoint_json IS NOT NULL
                OR package.package_json IS NOT NULL
             ORDER BY checkpoint.task_id, checkpoint.event_sequence, package.generation",
        )
        .map_err(storage_error)?
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;

    for (
        checkpoint_id,
        task_id,
        stored_digest,
        checkpoint_event_sequence,
        checkpoint_json,
        package_id,
        package_generation,
        package_event_sequence,
        package_json,
    ) in rows
    {
        let (
            Some(checkpoint_json),
            Some(package_id),
            Some(package_generation),
            Some(package_event_sequence),
            Some(package_json),
        ) = (
            checkpoint_json,
            package_id,
            package_generation,
            package_event_sequence,
            package_json,
        )
        else {
            return Err(storage_invariant(
                "canonical checkpoint and context package are not atomic",
            ));
        };
        let checkpoint = serde_json::from_str::<CanonicalCheckpoint>(&checkpoint_json)
            .map_err(|_| storage_invariant("stored canonical checkpoint is invalid"))?;
        let context_package = serde_json::from_str::<ContextPackage>(&package_json)
            .map_err(|_| storage_invariant("stored canonical context package is invalid"))?;
        let stored_task_id = task_id
            .parse::<TaskId>()
            .map_err(|_| storage_invariant("stored checkpoint task identifier is invalid"))?;
        let stored_checkpoint_id = checkpoint_id
            .parse()
            .map_err(|_| storage_invariant("stored checkpoint identifier is invalid"))?;
        let stored_package_id = package_id
            .parse()
            .map_err(|_| storage_invariant("stored context package identifier is invalid"))?;
        let stored_generation = u32::try_from(stored_u64(
            package_generation,
            "context package generation",
        )?)
        .map_err(|_| storage_invariant("stored context package generation is too large"))?;
        if checkpoint.task_id != stored_task_id
            || checkpoint.checkpoint_id != stored_checkpoint_id
            || context_package.package_id != stored_package_id
            || context_package.checkpoint_id != stored_checkpoint_id
            || checkpoint.compaction_generation != stored_generation
            || package_event_sequence != checkpoint_event_sequence
            || context_package.source_sequence_start != checkpoint.source_sequence_start
            || context_package.source_sequence_end != checkpoint.source_sequence_end
        {
            return Err(storage_invariant(
                "stored canonical checkpoint metadata is inconsistent",
            ));
        }
        if checkpoint
            .digest()
            .map_err(|_| storage_invariant("stored canonical checkpoint is invalid"))?
            != stored_digest
        {
            return Err(storage_invariant(
                "stored canonical checkpoint digest does not match",
            ));
        }
        context_package
            .canonical_bytes()
            .map_err(|_| storage_invariant("stored canonical context package is invalid"))?;
        validate_canonical_source_bounds(connection, &checkpoint, checkpoint_event_sequence)?;
        let expected_previous = connection
            .query_row(
                "SELECT digest
                 FROM task_checkpoints
                 WHERE task_id = ?1 AND event_sequence < ?2
                 ORDER BY event_sequence DESC
                 LIMIT 1",
                params![task_id, checkpoint_event_sequence],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(storage_error)?;
        if checkpoint.previous_digest != expected_previous {
            return Err(storage_invariant(
                "stored canonical checkpoint previous digest does not match",
            ));
        }
        validate_checkpoint_artifacts(connection, &checkpoint).map_err(|_| {
            storage_invariant("stored canonical checkpoint references an unknown artifact")
        })?;
    }
    Ok(())
}

fn validate_canonical_source_bounds(
    connection: &Connection,
    checkpoint: &CanonicalCheckpoint,
    checkpoint_event_sequence: i64,
) -> Result<(), CarlError> {
    let bounds = connection
        .query_row(
            "SELECT MIN(sequence), MAX(sequence)
             FROM events
             WHERE json_extract(event_json, '$.type') = 'task_lifecycle'
               AND json_extract(event_json, '$.task_id') = ?1
               AND sequence < ?2",
            params![checkpoint.task_id.to_string(), checkpoint_event_sequence],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .map_err(storage_error)?;
    let (Some(start), Some(end)) = bounds else {
        return Err(storage_invariant(
            "stored canonical checkpoint has no source journal",
        ));
    };
    if checkpoint.source_sequence_start != stored_u64(start, "checkpoint source start")?
        || checkpoint.source_sequence_end != stored_u64(end, "checkpoint source end")?
    {
        return Err(storage_invariant(
            "stored canonical checkpoint source range does not match the journal",
        ));
    }
    let committed = connection
        .query_row(
            "SELECT 1
             FROM events
             WHERE sequence = ?1
               AND json_extract(event_json, '$.type') = 'task_lifecycle'
               AND json_extract(event_json, '$.task_id') = ?2
               AND json_extract(event_json, '$.event.task_event') = 'checkpoint_committed'
               AND json_extract(event_json, '$.event.checkpoint_id') = ?3
               AND json_extract(event_json, '$.event.digest') = ?4",
            params![
                checkpoint_event_sequence,
                checkpoint.task_id.to_string(),
                checkpoint.checkpoint_id.to_string(),
                checkpoint
                    .digest()
                    .map_err(|_| { storage_invariant("stored canonical checkpoint is invalid") })?,
            ],
            |_| Ok(()),
        )
        .optional()
        .map_err(storage_error)?;
    if committed.is_none() {
        return Err(storage_invariant(
            "stored canonical checkpoint has no matching journal event",
        ));
    }
    Ok(())
}

fn checkpoint_validation_error(_error: crate::runtime::task::CheckpointError) -> CarlError {
    checkpoint_validation("canonical checkpoint is invalid")
}

fn context_validation_error(_error: crate::runtime::task::ContextError) -> CarlError {
    checkpoint_validation("canonical context package is invalid")
}

fn checkpoint_validation(detail: &str) -> CarlError {
    CarlError::Validation {
        detail: detail.to_owned(),
    }
}

fn insert_task_projection(
    transaction: &Transaction<'_>,
    snapshot: &TaskSnapshot,
    workspace: &Path,
    model: &ModelId,
    effort: ReasoningEffort,
    permission_mode: PermissionMode,
    created_at: DateTime<Utc>,
) -> Result<(), CarlError> {
    let workspace = workspace.to_str().ok_or_else(|| CarlError::Validation {
        detail: "task workspace is not UTF-8".to_owned(),
    })?;
    let contract_json = serde_json::to_string(&snapshot.contract).map_err(storage_error)?;
    let budget_json = serde_json::to_string(&snapshot.budget).map_err(storage_error)?;
    let snapshot_json = serde_json::to_string(snapshot).map_err(storage_error)?;
    transaction
        .execute(
            "INSERT INTO agent_tasks (
                id, session_id, status, contract_json, budget_json, snapshot_json,
                canonical_workspace, provider, model, effort, permission_mode,
                revision, current_epoch_id, latest_checkpoint_id, provider_context,
                created_at, updated_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, 'codex', ?8, ?9, ?10,
                ?11, NULL, NULL, NULL, ?12, ?12
             )",
            params![
                snapshot.task_id.to_string(),
                snapshot.session_id.to_string(),
                task_status_str(snapshot.status),
                contract_json,
                budget_json,
                snapshot_json,
                workspace,
                model.as_str(),
                effort.as_codex_value(),
                permission_mode.as_wire_str(),
                revision_to_sql(snapshot.revision)?,
                format_timestamp(created_at),
            ],
        )
        .map_err(storage_error)?;
    Ok(())
}

fn update_task_projection(
    transaction: &Transaction<'_>,
    snapshot: &TaskSnapshot,
    updated_at: DateTime<Utc>,
) -> Result<(), CarlError> {
    let changed = transaction
        .execute(
            "UPDATE agent_tasks SET
                status = ?2,
                contract_json = ?3,
                budget_json = ?4,
                snapshot_json = ?5,
                revision = ?6,
                current_epoch_id = ?7,
                latest_checkpoint_id = ?8,
                provider_context = ?9,
                updated_at = ?10
             WHERE id = ?1 AND revision = ?11",
            params![
                snapshot.task_id.to_string(),
                task_status_str(snapshot.status),
                serde_json::to_string(&snapshot.contract).map_err(storage_error)?,
                serde_json::to_string(&snapshot.budget).map_err(storage_error)?,
                serde_json::to_string(snapshot).map_err(storage_error)?,
                revision_to_sql(snapshot.revision)?,
                snapshot.active_epoch.map(|id| id.to_string()),
                snapshot.latest_checkpoint.map(|id| id.to_string()),
                snapshot.provider_context.as_deref(),
                format_timestamp(updated_at),
                revision_to_sql(snapshot.revision.saturating_sub(1))?,
            ],
        )
        .map_err(storage_error)?;
    if changed != 1 {
        return Err(storage_invariant(
            "task projection revision changed during transactional append",
        ));
    }
    Ok(())
}

fn apply_task_child_projection(
    transaction: &Transaction<'_>,
    task_id: TaskId,
    envelope: &EventEnvelope,
    _snapshot: &TaskSnapshot,
) -> Result<(), CarlError> {
    let Event::TaskLifecycle { event, .. } = &envelope.event else {
        return Err(storage_invariant(
            "task projection received a non-task event",
        ));
    };
    let task_id = task_id.to_string();
    let event_sequence = revision_to_sql(envelope.sequence)?;
    let timestamp = format_timestamp(envelope.timestamp);
    match event {
        TaskEvent::EpochStarted {
            epoch_id,
            objective,
        } => {
            transaction
                .execute(
                    "INSERT INTO task_epochs (
                        id, task_id, objective, status, started_sequence,
                        finished_sequence, report_digest, created_at, updated_at
                     ) VALUES (?1, ?2, ?3, 'active', ?4, NULL, NULL, ?5, ?5)",
                    params![
                        epoch_id.to_string(),
                        task_id,
                        objective,
                        event_sequence,
                        timestamp,
                    ],
                )
                .map_err(storage_error)?;
        }
        TaskEvent::EpochFinished {
            epoch_id,
            report_digest,
        } => {
            let changed = transaction
                .execute(
                    "UPDATE task_epochs
                     SET status = 'finished', finished_sequence = ?3,
                         report_digest = ?4, updated_at = ?5
                     WHERE id = ?1 AND task_id = ?2 AND status = 'active'",
                    params![
                        epoch_id.to_string(),
                        task_id,
                        event_sequence,
                        report_digest,
                        timestamp,
                    ],
                )
                .map_err(storage_error)?;
            require_projection_change(changed, "active task epoch projection is missing")?;
        }
        TaskEvent::OperationIntentRecorded {
            operation_id,
            epoch_id,
            item_id,
            effect_class,
            request_digest,
        } => {
            transaction
                .execute(
                    "INSERT INTO task_operations (
                        id, task_id, epoch_id, item_id, effect_class, request_digest,
                        status, intent_sequence, last_transition_sequence,
                        evidence_sequences_json, created_at, updated_at
                     ) VALUES (
                        ?1, ?2, ?3, ?4, ?5, ?6, 'intent_recorded', ?7, ?7, '[]', ?8, ?8
                     )",
                    params![
                        operation_id.to_string(),
                        task_id,
                        epoch_id.to_string(),
                        item_id,
                        effect_class_str(*effect_class),
                        request_digest,
                        event_sequence,
                        timestamp,
                    ],
                )
                .map_err(storage_error)?;
        }
        TaskEvent::OperationTransitioned {
            operation_id,
            from,
            to,
            evidence_sequences,
        } => {
            let changed = transaction
                .execute(
                    "UPDATE task_operations
                     SET status = ?4, last_transition_sequence = ?5,
                         evidence_sequences_json = ?6, updated_at = ?7
                     WHERE id = ?1 AND task_id = ?2 AND status = ?3",
                    params![
                        operation_id.to_string(),
                        task_id,
                        operation_status_str(*from),
                        operation_status_str(*to),
                        event_sequence,
                        serde_json::to_string(evidence_sequences).map_err(storage_error)?,
                        timestamp,
                    ],
                )
                .map_err(storage_error)?;
            require_projection_change(changed, "task operation projection is missing")?;
        }
        TaskEvent::CheckpointCommitted {
            checkpoint_id,
            digest,
        } => {
            transaction
                .execute(
                    "INSERT INTO task_checkpoints (
                        id, task_id, digest, event_sequence, checkpoint_json, created_at
                     ) VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
                    params![
                        checkpoint_id.to_string(),
                        task_id,
                        digest,
                        event_sequence,
                        timestamp,
                    ],
                )
                .map_err(storage_error)?;
        }
        TaskEvent::CompactionCompleted {
            generation,
            checkpoint_id,
            context_package_id,
        } => {
            let existing = transaction
                .query_row(
                    "SELECT task_id, checkpoint_id, generation, package_json
                     FROM task_context_packages WHERE id = ?1",
                    [context_package_id.to_string()],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Option<String>>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(storage_error)?;
            if let Some((stored_task, stored_checkpoint, stored_generation, package_json)) =
                existing
            {
                if stored_task != task_id
                    || stored_checkpoint != checkpoint_id.to_string()
                    || stored_generation != i64::from(*generation)
                    || package_json.is_none()
                {
                    return Err(storage_invariant(
                        "completed compaction does not match its atomic context package",
                    ));
                }
            } else {
                transaction
                    .execute(
                        "INSERT INTO task_context_packages (
                            id, task_id, checkpoint_id, generation, event_sequence,
                            package_json, created_at
                         ) VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
                        params![
                            context_package_id.to_string(),
                            task_id,
                            checkpoint_id.to_string(),
                            i64::from(*generation),
                            event_sequence,
                            timestamp,
                        ],
                    )
                    .map_err(storage_error)?;
            }
        }
        TaskEvent::SteeringQueued {
            steering_sequence,
            text_digest,
        } => {
            transaction
                .execute(
                    "INSERT INTO task_steering (
                        task_id, steering_sequence, text_digest, event_sequence, created_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        task_id,
                        revision_to_sql(*steering_sequence)?,
                        text_digest,
                        event_sequence,
                        timestamp,
                    ],
                )
                .map_err(storage_error)?;
        }
        TaskEvent::Created { .. }
        | TaskEvent::StateTransitioned { .. }
        | TaskEvent::ContractRevised { .. }
        | TaskEvent::UsageObserved { .. }
        | TaskEvent::OperationEvidenceRecorded { .. }
        | TaskEvent::NormalizedOperationEvidenceRecorded { .. }
        | TaskEvent::ProgressAssessed { .. }
        | TaskEvent::RecoveryAttemptRecorded { .. }
        | TaskEvent::CompactionRequested { .. }
        | TaskEvent::ProviderContextBound { .. }
        | TaskEvent::ProviderContextLost { .. }
        | TaskEvent::CancellationRequested
        | TaskEvent::Blocked { .. }
        | TaskEvent::Completed => {}
    }
    Ok(())
}

fn require_projection_change(changed: usize, detail: &str) -> Result<(), CarlError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(storage_invariant(detail))
    }
}

fn load_task_record(
    connection: &Connection,
    task_id: TaskId,
) -> Result<Option<TaskRecord>, CarlError> {
    let raw = connection
        .query_row(
            "SELECT session_id, status, contract_json, budget_json, snapshot_json,
                    revision, current_epoch_id, latest_checkpoint_id, provider_context,
                    created_at, updated_at
             FROM agent_tasks WHERE id = ?1",
            [task_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                ))
            },
        )
        .optional()
        .map_err(storage_error)?;
    raw.map(
        |(
            session_id,
            status,
            contract_json,
            budget_json,
            snapshot_json,
            revision,
            current_epoch_id,
            latest_checkpoint_id,
            provider_context,
            created_at,
            updated_at,
        )| {
            let snapshot: TaskSnapshot =
                serde_json::from_str(&snapshot_json).map_err(storage_error)?;
            let contract: CompletionContract =
                serde_json::from_str(&contract_json).map_err(storage_error)?;
            let budget: TaskBudget = serde_json::from_str(&budget_json).map_err(storage_error)?;
            let stored_revision = stored_u64(revision, "task revision")?;
            let stored_status = parse_task_status(&status)?;
            let stored_session_id = parse_id("task session ID", &session_id)?;
            let stored_epoch = current_epoch_id
                .as_deref()
                .map(|value| parse_id("task epoch ID", value))
                .transpose()?;
            let stored_checkpoint = latest_checkpoint_id
                .as_deref()
                .map(|value| parse_id("task checkpoint ID", value))
                .transpose()?;
            if snapshot.task_id != task_id
                || snapshot.session_id != stored_session_id
                || snapshot.status != stored_status
                || snapshot.contract != contract
                || snapshot.budget != budget
                || snapshot.revision != stored_revision
                || snapshot.active_epoch != stored_epoch
                || snapshot.latest_checkpoint != stored_checkpoint
                || snapshot.provider_context != provider_context
            {
                return Err(storage_invariant(
                    "stored task projection is internally inconsistent",
                ));
            }
            Ok(TaskRecord {
                snapshot,
                revision: stored_revision,
                created_at: parse_timestamp(&created_at)?,
                updated_at: parse_timestamp(&updated_at)?,
            })
        },
    )
    .transpose()
}

fn read_task_event_page_from_connection(
    connection: &Connection,
    task_id: TaskId,
    after_sequence: Option<u64>,
    limit: u16,
) -> Result<Vec<EventEnvelope>, CarlError> {
    if !(1..=512).contains(&limit) {
        return Err(CarlError::Validation {
            detail: "task event page limit must be between 1 and 512".to_owned(),
        });
    }
    let after_sequence = match after_sequence {
        Some(sequence) => i64::try_from(sequence).map_err(|_| CarlError::Validation {
            detail: "task event page cursor is too large".to_owned(),
        })?,
        None => 0,
    };
    let task_id_text = task_id.to_string();
    let session_ids = connection
        .prepare(
            "SELECT DISTINCT session_id
             FROM events
             WHERE json_extract(event_json, '$.type') = 'task_lifecycle'
               AND json_extract(event_json, '$.task_id') = ?1
             ORDER BY session_id ASC
             LIMIT 2",
        )
        .map_err(storage_error)?
        .query_map([&task_id_text], |row| row.get::<_, String>(0))
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    let [session_id] = session_ids.as_slice() else {
        if session_ids.is_empty() {
            return Ok(Vec::new());
        }
        return Err(storage_invariant(
            "task journal identifier appears in multiple sessions",
        ));
    };
    let session_id: SessionId = session_id
        .parse()
        .map_err(|_| storage_invariant("task journal contains an invalid session identifier"))?;
    let rows = connection
        .prepare(
            "SELECT id, turn_id, sequence, timestamp, schema_version, event_json
             FROM events
             WHERE session_id = ?1
               AND sequence > ?2
               AND json_extract(event_json, '$.type') = 'task_lifecycle'
               AND json_extract(event_json, '$.task_id') = ?3
             ORDER BY sequence ASC
             LIMIT ?4",
        )
        .map_err(storage_error)?
        .query_map(
            params![
                session_id.to_string(),
                after_sequence,
                task_id_text,
                i64::from(limit),
            ],
            |row| {
                Ok(RawEvent {
                    id: row.get(0)?,
                    turn_id: row.get(1)?,
                    sequence: row.get(2)?,
                    timestamp: row.get(3)?,
                    schema_version: row.get(4)?,
                    event_json: row.get(5)?,
                })
            },
        )
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    rows.into_iter()
        .map(|row| row.into_envelope(session_id))
        .collect()
}

fn validate_task_projection_completeness(connection: &Connection) -> Result<(), CarlError> {
    visit_authoritative_task_records(connection, |_| Ok(()))
}

fn visit_authoritative_task_records(
    connection: &Connection,
    mut visitor: impl FnMut(TaskRecord) -> Result<(), CarlError>,
) -> Result<(), CarlError> {
    let mut after_task_id = None;
    loop {
        let task_ids = read_journal_task_id_page(connection, after_task_id.as_deref())?;
        if task_ids.is_empty() {
            break;
        }
        after_task_id = task_ids.last().cloned();
        for stored_task_id in task_ids {
            let task_id = stored_task_id.parse::<TaskId>().map_err(|_| {
                storage_invariant("task journal contains an invalid task identifier")
            })?;
            visitor(validate_task_projection_from_journal(connection, task_id)?)?;
        }
    }

    let orphan_projection = connection
        .query_row(
            "SELECT 1
             FROM agent_tasks AS task
             WHERE NOT EXISTS (
                SELECT 1
                FROM events AS event
                WHERE json_extract(event.event_json, '$.type') = 'task_lifecycle'
                  AND json_extract(event.event_json, '$.task_id') = task.id
             )
             LIMIT 1",
            [],
            |_| Ok(()),
        )
        .optional()
        .map_err(storage_error)?;
    if orphan_projection.is_some() {
        return Err(storage_invariant(
            "task projection has no authoritative journal",
        ));
    }
    Ok(())
}

fn read_journal_task_id_page(
    connection: &Connection,
    after_task_id: Option<&str>,
) -> Result<Vec<String>, CarlError> {
    connection
        .prepare(
            "SELECT json_extract(event_json, '$.task_id') AS task_id
             FROM events
             WHERE json_extract(event_json, '$.type') = 'task_lifecycle'
               AND (?1 IS NULL OR json_extract(event_json, '$.task_id') > ?1)
             GROUP BY json_extract(event_json, '$.task_id')
             ORDER BY json_extract(event_json, '$.task_id') ASC
             LIMIT 512",
        )
        .map_err(storage_error)?
        .query_map([after_task_id], |row| row.get::<_, String>(0))
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| storage_invariant("task journal contains invalid task metadata"))
}

fn validate_task_projection_from_journal(
    connection: &Connection,
    task_id: TaskId,
) -> Result<TaskRecord, CarlError> {
    let projection = load_task_record(connection, task_id)?
        .ok_or_else(|| storage_invariant("task journal has no matching task projection"))?;
    let mut replayed = None;
    let mut after_sequence = None;
    loop {
        let page = read_task_event_page_from_connection(connection, task_id, after_sequence, 512)?;
        if page.is_empty() {
            break;
        }
        after_sequence = page.last().map(|event| event.sequence);
        for envelope in page {
            replayed = Some(reduce_task(replayed, &envelope).map_err(task_replay_error)?);
        }
    }
    let replayed = replayed
        .ok_or_else(|| storage_invariant("task projection has no authoritative journal"))?;
    if replayed.revision != projection.revision
        || replayed.status != projection.snapshot.status
        || replayed.active_epoch != projection.snapshot.active_epoch
        || replayed.latest_checkpoint != projection.snapshot.latest_checkpoint
        || replayed != projection.snapshot
    {
        return Err(storage_invariant(
            "task projection disagrees with journal replay",
        ));
    }
    Ok(projection)
}

const fn task_status_str(status: TaskStatus) -> &'static str {
    match status {
        TaskStatus::Queued => "queued",
        TaskStatus::Active => "active",
        TaskStatus::Checkpointing => "checkpointing",
        TaskStatus::Paused => "paused",
        TaskStatus::Blocked => "blocked",
        TaskStatus::Cancelling => "cancelling",
        TaskStatus::Cancelled => "cancelled",
        TaskStatus::Completing => "completing",
        TaskStatus::Completed => "completed",
        TaskStatus::Failed => "failed",
    }
}

fn parse_task_status(value: &str) -> Result<TaskStatus, CarlError> {
    match value {
        "queued" => Ok(TaskStatus::Queued),
        "active" => Ok(TaskStatus::Active),
        "checkpointing" => Ok(TaskStatus::Checkpointing),
        "paused" => Ok(TaskStatus::Paused),
        "blocked" => Ok(TaskStatus::Blocked),
        "cancelling" => Ok(TaskStatus::Cancelling),
        "cancelled" => Ok(TaskStatus::Cancelled),
        "completing" => Ok(TaskStatus::Completing),
        "completed" => Ok(TaskStatus::Completed),
        "failed" => Ok(TaskStatus::Failed),
        other => Err(invalid_stored_value("task status", other)),
    }
}

const fn operation_status_str(status: OperationStatus) -> &'static str {
    match status {
        OperationStatus::IntentRecorded => "intent_recorded",
        OperationStatus::Started => "started",
        OperationStatus::Succeeded => "succeeded",
        OperationStatus::Failed => "failed",
        OperationStatus::Cancelled => "cancelled",
        OperationStatus::Uncertain => "uncertain",
        OperationStatus::Reconciled => "reconciled",
    }
}

const fn effect_class_str(effect_class: EffectClass) -> &'static str {
    match effect_class {
        EffectClass::Observation => "observation",
        EffectClass::IdempotentMutation => "idempotent_mutation",
        EffectClass::AmbiguousConsequential => "ambiguous_consequential",
    }
}

fn task_reduce_error(error: crate::runtime::task::TaskReduceError) -> CarlError {
    CarlError::Validation {
        detail: format!("task event cannot be applied: {}", error.code().as_str()),
    }
}

fn task_replay_error(error: crate::runtime::task::TaskReduceError) -> CarlError {
    CarlError::Storage {
        detail: format!("task journal replay failed: {}", error.code().as_str()),
    }
}

fn append_event_in_transaction(
    transaction: &Transaction<'_>,
    session_id: SessionId,
    turn_id: Option<TurnId>,
    event: Event,
    timestamp: DateTime<Utc>,
) -> Result<EventEnvelope, CarlError> {
    let sequence = transaction
        .query_row(
            "UPDATE sessions
             SET next_sequence = next_sequence + 1, updated_at = ?2
             WHERE id = ?1
             RETURNING next_sequence - 1",
            params![session_id.to_string(), format_timestamp(timestamp)],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(storage_error)?
        .ok_or_else(|| CarlError::Storage {
            detail: format!("session {session_id} does not exist"),
        })?;
    let sequence = u64::try_from(sequence).map_err(|error| CarlError::Storage {
        detail: format!("invalid event sequence {sequence}: {error}"),
    })?;
    let envelope = EventEnvelope {
        id: EventId::new(),
        session_id,
        turn_id,
        sequence,
        timestamp,
        event,
    };
    let event_json = serde_json::to_string(&envelope.event).map_err(storage_error)?;
    transaction
        .execute(
            "INSERT INTO events (
                id, session_id, turn_id, sequence, timestamp, schema_version, event_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                envelope.id.to_string(),
                envelope.session_id.to_string(),
                envelope.turn_id.map(|id| id.to_string()),
                revision_to_sql(envelope.sequence)?,
                format_timestamp(envelope.timestamp),
                i64::from(envelope.schema_version()),
                event_json,
            ],
        )
        .map_err(storage_error)?;
    Ok(envelope)
}

fn insert_subscription_run(
    transaction: &Transaction<'_>,
    request: &NewSubscriptionRun,
) -> Result<(), CarlError> {
    let (provider_model_status, provider_model_value) =
        provider_model_parts(request.configuration.provider_model());
    let (provider_effort_status, provider_effort_value) =
        provider_effort_parts(request.configuration.provider_effort());
    transaction
        .execute(
            "INSERT INTO subscription_runs (
                id, session_id, turn_id, provider, state, revision,
                per_run_model, per_run_effort,
                resolved_model, resolved_effort, model_source, effort_source,
                provider_model_status, provider_model_value,
                provider_effort_status, provider_effort_value,
                provider_configuration_observed,
                failure_code, created_at, updated_at
             ) VALUES (
                ?1, ?2, ?3, 'codex', 'prepared', 1,
                ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 0, NULL, ?14, ?14
             )",
            params![
                request.id.to_string(),
                request.session_id.to_string(),
                request.turn_id.to_string(),
                request.per_run_settings.model().map(ModelId::as_str),
                request
                    .per_run_settings
                    .effort()
                    .map(ReasoningEffort::as_codex_value),
                request.configuration.model().map(ModelId::as_str),
                request
                    .configuration
                    .effort()
                    .map(ReasoningEffort::as_codex_value),
                request.configuration.model_source().as_str(),
                request.configuration.effort_source().as_str(),
                provider_model_status,
                provider_model_value,
                provider_effort_status,
                provider_effort_value,
                format_timestamp(request.created_at),
            ],
        )
        .map_err(storage_error)?;
    Ok(())
}

fn link_subscription_run_event(
    transaction: &Transaction<'_>,
    run_id: RunId,
    run_sequence: u64,
    event_id: EventId,
) -> Result<(), CarlError> {
    transaction
        .execute(
            "INSERT INTO subscription_run_events (run_id, run_sequence, event_id)
             VALUES (?1, ?2, ?3)",
            params![
                run_id.to_string(),
                revision_to_sql(run_sequence)?,
                event_id.to_string(),
            ],
        )
        .map_err(storage_error)?;
    Ok(())
}

fn is_subscription_run_event(event: &Event) -> bool {
    matches!(
        event,
        Event::SubscriptionRunPrepared { .. }
            | Event::SubscriptionRunConfigurationObserved { .. }
            | Event::SubscriptionRunTransitioned { .. }
    )
}

fn validate_linked_subscription_event(
    expected_run_id: RunId,
    expected_run_sequence: u64,
    event: &Event,
) -> Result<(), CarlError> {
    let (run_id, run_sequence) = match event {
        Event::SubscriptionRunPrepared {
            run_id,
            run_sequence,
            ..
        }
        | Event::SubscriptionRunConfigurationObserved {
            run_id,
            run_sequence,
            ..
        }
        | Event::SubscriptionRunTransitioned {
            run_id,
            run_sequence,
            ..
        } => (*run_id, *run_sequence),
        _ => {
            return Err(storage_invariant(
                "subscription run index references a non-run event",
            ));
        }
    };
    if run_id != expected_run_id || run_sequence != expected_run_sequence {
        return Err(storage_invariant(
            "subscription run event does not match its durable index",
        ));
    }
    Ok(())
}

fn load_and_validate_subscription_run_events(
    connection: &Connection,
    projection: &SubscriptionRunRecord,
) -> Result<Vec<EventEnvelope>, CarlError> {
    let rows = {
        let mut statement = connection
            .prepare(
                "SELECT links.run_sequence, events.id, events.session_id, events.turn_id,
                        events.sequence, events.timestamp, events.schema_version,
                        events.event_json
                 FROM subscription_run_events AS links
                 JOIN events ON events.id = links.event_id
                 WHERE links.run_id = ?1
                 ORDER BY links.run_sequence ASC",
            )
            .map_err(storage_error)?;
        statement
            .query_map([projection.id.to_string()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(2)?,
                    RawEvent {
                        id: row.get(1)?,
                        turn_id: row.get(3)?,
                        sequence: row.get(4)?,
                        timestamp: row.get(5)?,
                        schema_version: row.get(6)?,
                        event_json: row.get(7)?,
                    },
                ))
            })
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?
    };
    let events = rows
        .into_iter()
        .enumerate()
        .map(|(index, (run_sequence, session_id, raw))| {
            let expected_sequence =
                u64::try_from(index + 1).map_err(|_| storage_invariant("too many run events"))?;
            let run_sequence = u64::try_from(run_sequence)
                .map_err(|_| storage_invariant("invalid run event sequence"))?;
            if run_sequence != expected_sequence {
                return Err(storage_invariant(
                    "subscription run event sequence has a gap",
                ));
            }
            let envelope = raw.into_envelope(parse_id("session ID", &session_id)?)?;
            if envelope.session_id != projection.session_id
                || envelope.turn_id != Some(projection.turn_id)
            {
                return Err(storage_invariant(
                    "subscription run event belongs to a different session or turn",
                ));
            }
            validate_linked_subscription_event(projection.id, run_sequence, &envelope.event)?;
            Ok(envelope)
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_subscription_run_replay(projection, &events)?;
    Ok(events)
}

fn validate_subscription_run_replay(
    projection: &SubscriptionRunRecord,
    events: &[EventEnvelope],
) -> Result<(), CarlError> {
    if u64::try_from(events.len()).ok() != Some(projection.revision) {
        return Err(storage_invariant(
            "subscription run replay length disagrees with its projection",
        ));
    }
    let Some(first) = events.first() else {
        return Err(storage_invariant("subscription run replay is empty"));
    };
    match &first.event {
        Event::SubscriptionRunPrepared {
            run_id,
            run_sequence,
            configuration,
            state,
            trust_label,
        } if *run_id == projection.id
            && *run_sequence == 1
            && *state == RunState::Prepared
            && *trust_label == RunTrustLabel::TrustedCarlState
            && configuration.model() == projection.configuration.model()
            && configuration.model_source() == projection.configuration.model_source()
            && configuration.effort() == projection.configuration.effort()
            && configuration.effort_source() == projection.configuration.effort_source()
            && matches!(
                configuration.provider_model(),
                ProviderReported::NotReported
            )
            && matches!(
                configuration.provider_effort(),
                ProviderReported::NotReported
            ) => {}
        _ => {
            return Err(storage_invariant(
                "subscription run replay has an invalid prepared event",
            ));
        }
    }

    let mut state = RunState::Prepared;
    let mut failure_code = None;
    let mut provider_configuration_observed = false;
    let mut configuration = match &first.event {
        Event::SubscriptionRunPrepared { configuration, .. } => configuration.clone(),
        _ => unreachable!("the prepared event was validated above"),
    };
    for envelope in &events[1..] {
        match &envelope.event {
            Event::SubscriptionRunConfigurationObserved {
                configuration: observed,
                trust_label,
                ..
            } => {
                if state != RunState::Running
                    || provider_configuration_observed
                    || *trust_label != RunTrustLabel::UntrustedProviderEvidence
                    || observed.model() != configuration.model()
                    || observed.model_source() != configuration.model_source()
                    || observed.effort() != configuration.effort()
                    || observed.effort_source() != configuration.effort_source()
                {
                    return Err(storage_invariant(
                        "subscription run replay contains an invalid provider observation",
                    ));
                }
                configuration = observed.clone();
                provider_configuration_observed = true;
            }
            Event::SubscriptionRunTransitioned { transition, .. } => {
                if transition.from() != state {
                    return Err(storage_invariant(
                        "subscription run replay contains a discontinuous transition",
                    ));
                }
                state = transition.to();
                failure_code = transition.failure_code();
            }
            _ => {
                return Err(storage_invariant(
                    "subscription run replay contains an unexpected event",
                ));
            }
        }
    }
    if state != projection.state
        || failure_code != projection.failure_code
        || configuration != projection.configuration
        || provider_configuration_observed != projection.provider_configuration_observed
    {
        return Err(storage_invariant(
            "subscription run replay disagrees with its projection",
        ));
    }
    Ok(())
}

fn validate_per_run_configuration(
    per_run: &DelegateSettings,
    configuration: &RunConfigSnapshot,
) -> Result<(), CarlError> {
    let model_matches = match per_run.model() {
        Some(model) => {
            configuration.model_source() == SettingSource::PerRun
                && configuration.model() == Some(model)
        }
        None => configuration.model_source() != SettingSource::PerRun,
    };
    let effort_matches = match per_run.effort() {
        Some(effort) => {
            configuration.effort_source() == SettingSource::PerRun
                && configuration.effort() == Some(effort)
        }
        None => configuration.effort_source() != SettingSource::PerRun,
    };
    if model_matches && effort_matches {
        Ok(())
    } else {
        Err(CarlError::Validation {
            detail: "per-run delegate settings do not match the resolved configuration".to_owned(),
        })
    }
}

fn validate_new_subscription_run(request: &NewSubscriptionRun) -> Result<(), CarlError> {
    validate_per_run_configuration(&request.per_run_settings, &request.configuration)?;
    if matches!(
        request.configuration.provider_model(),
        ProviderReported::NotReported
    ) && matches!(
        request.configuration.provider_effort(),
        ProviderReported::NotReported
    ) {
        Ok(())
    } else {
        Err(CarlError::Validation {
            detail: "provider-reported configuration is unavailable before run creation".to_owned(),
        })
    }
}

fn validate_persisted_session_configuration(
    connection: &Connection,
    session_id: SessionId,
    configuration: &RunConfigSnapshot,
) -> Result<(), CarlError> {
    let persisted = connection
        .query_row(
            "SELECT model, effort
             FROM session_delegate_settings
             WHERE session_id = ?1 AND provider = 'codex'",
            [session_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .optional()
        .map_err(storage_error)?
        .map(|(model, effort)| parse_delegate_settings(model.as_deref(), effort.as_deref()))
        .transpose()?;
    let persisted_model = persisted.as_ref().and_then(DelegateSettings::model);
    let persisted_effort = persisted.as_ref().and_then(DelegateSettings::effort);
    let model_is_valid = if configuration.model_source() == SettingSource::PerRun {
        true
    } else {
        match persisted_model {
            Some(model) => {
                configuration.model_source() == SettingSource::Session
                    && configuration.model() == Some(model)
            }
            None => configuration.model_source() != SettingSource::Session,
        }
    };
    if !model_is_valid {
        return Err(CarlError::Validation {
            detail: "resolved model does not honor the persisted session setting".to_owned(),
        });
    }
    let effort_is_valid = if configuration.effort_source() == SettingSource::PerRun {
        true
    } else {
        match persisted_effort {
            Some(effort) => {
                configuration.effort_source() == SettingSource::Session
                    && configuration.effort() == Some(effort)
            }
            None => configuration.effort_source() != SettingSource::Session,
        }
    };
    if !effort_is_valid {
        return Err(CarlError::Validation {
            detail: "resolved effort does not honor the persisted session setting".to_owned(),
        });
    }
    Ok(())
}

fn load_subscription_run(
    connection: &Connection,
    id: RunId,
) -> Result<Option<SubscriptionRunRecord>, CarlError> {
    connection
        .query_row(
            "SELECT id, session_id, turn_id, state, revision,
                    per_run_model, per_run_effort,
                    resolved_model, resolved_effort, model_source, effort_source,
                    provider_model_status, provider_model_value,
                    provider_effort_status, provider_effort_value,
                    provider_configuration_observed,
                    failure_code, created_at, updated_at
             FROM subscription_runs
             WHERE id = ?1",
            [id.to_string()],
            raw_subscription_run,
        )
        .optional()
        .map_err(storage_error)?
        .map(SubscriptionRunRecord::try_from)
        .transpose()
}

struct RawSubscriptionRun {
    id: String,
    session_id: String,
    turn_id: String,
    state: String,
    revision: i64,
    per_run_model: Option<String>,
    per_run_effort: Option<String>,
    resolved_model: Option<String>,
    resolved_effort: Option<String>,
    model_source: String,
    effort_source: String,
    provider_model_status: String,
    provider_model_value: Option<String>,
    provider_effort_status: String,
    provider_effort_value: Option<String>,
    provider_configuration_observed: i64,
    failure_code: Option<String>,
    created_at: String,
    updated_at: String,
}

fn raw_subscription_run(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawSubscriptionRun> {
    Ok(RawSubscriptionRun {
        id: row.get(0)?,
        session_id: row.get(1)?,
        turn_id: row.get(2)?,
        state: row.get(3)?,
        revision: row.get(4)?,
        per_run_model: row.get(5)?,
        per_run_effort: row.get(6)?,
        resolved_model: row.get(7)?,
        resolved_effort: row.get(8)?,
        model_source: row.get(9)?,
        effort_source: row.get(10)?,
        provider_model_status: row.get(11)?,
        provider_model_value: row.get(12)?,
        provider_effort_status: row.get(13)?,
        provider_effort_value: row.get(14)?,
        provider_configuration_observed: row.get(15)?,
        failure_code: row.get(16)?,
        created_at: row.get(17)?,
        updated_at: row.get(18)?,
    })
}

impl TryFrom<RawSubscriptionRun> for SubscriptionRunRecord {
    type Error = CarlError;

    fn try_from(raw: RawSubscriptionRun) -> Result<Self, Self::Error> {
        let state = RunState::parse(&raw.state)
            .map_err(|_| storage_invariant("stored subscription run state is invalid"))?;
        let failure_code = raw
            .failure_code
            .as_deref()
            .map(RunFailureCode::parse)
            .transpose()
            .map_err(|_| storage_invariant("stored subscription run failure code is invalid"))?;
        if (state == RunState::Failed) != failure_code.is_some() {
            return Err(storage_invariant(
                "stored subscription run failure state is inconsistent",
            ));
        }
        let per_run_settings =
            parse_delegate_settings(raw.per_run_model.as_deref(), raw.per_run_effort.as_deref())?;
        let model = raw
            .resolved_model
            .map(ModelId::parse)
            .transpose()
            .map_err(|_| storage_invariant("stored resolved model is invalid"))?;
        let effort = raw
            .resolved_effort
            .as_deref()
            .map(parse_reasoning_effort)
            .transpose()?;
        let model_source = SettingSource::parse(&raw.model_source)
            .map_err(|_| storage_invariant("stored model source is invalid"))?;
        let effort_source = SettingSource::parse(&raw.effort_source)
            .map_err(|_| storage_invariant("stored effort source is invalid"))?;
        let provider_model =
            parse_provider_model(&raw.provider_model_status, raw.provider_model_value)?;
        let provider_effort =
            parse_provider_effort(&raw.provider_effort_status, raw.provider_effort_value)?;
        let configuration = RunConfigSnapshot::reconstruct(
            model,
            model_source,
            effort,
            effort_source,
            provider_model,
            provider_effort,
        )
        .map_err(|_| storage_invariant("stored run configuration is invalid"))?;
        validate_per_run_configuration(&per_run_settings, &configuration)
            .map_err(|_| storage_invariant("stored per-run configuration is inconsistent"))?;
        let provider_configuration_observed = match raw.provider_configuration_observed {
            0 => false,
            1 => true,
            _ => {
                return Err(storage_invariant(
                    "stored provider observation state is invalid",
                ));
            }
        };
        if !provider_configuration_observed
            && (!matches!(
                configuration.provider_model(),
                ProviderReported::NotReported
            ) || !matches!(
                configuration.provider_effort(),
                ProviderReported::NotReported
            ))
        {
            return Err(storage_invariant(
                "stored provider values precede their observation",
            ));
        }
        Ok(Self {
            id: parse_id("subscription run ID", &raw.id)?,
            session_id: parse_id("session ID", &raw.session_id)?,
            turn_id: parse_id("turn ID", &raw.turn_id)?,
            state,
            revision: u64::try_from(raw.revision)
                .map_err(|_| storage_invariant("stored subscription run revision is invalid"))?,
            per_run_settings,
            configuration,
            provider_configuration_observed,
            failure_code,
            created_at: parse_timestamp(&raw.created_at)?,
            updated_at: parse_timestamp(&raw.updated_at)?,
        })
    }
}

fn parse_delegate_settings(
    model: Option<&str>,
    effort: Option<&str>,
) -> Result<DelegateSettings, CarlError> {
    let model = model
        .map(ModelId::parse)
        .transpose()
        .map_err(|_| storage_invariant("stored delegate model is invalid"))?;
    let effort = effort.map(parse_reasoning_effort).transpose()?;
    Ok(DelegateSettings::new(model, effort))
}

fn parse_reasoning_effort(value: &str) -> Result<ReasoningEffort, CarlError> {
    match value {
        "low" => Ok(ReasoningEffort::Low),
        "medium" => Ok(ReasoningEffort::Medium),
        "high" => Ok(ReasoningEffort::High),
        "xhigh" => Ok(ReasoningEffort::XHigh),
        "max" => Ok(ReasoningEffort::Max),
        "ultra" => Ok(ReasoningEffort::Ultra),
        _ => Err(storage_invariant("stored reasoning effort is invalid")),
    }
}

fn parse_provider_model(
    status: &str,
    value: Option<String>,
) -> Result<ProviderReported<ModelId>, CarlError> {
    match (status, value) {
        ("not_reported", None) => Ok(ProviderReported::NotReported),
        ("reported", Some(value)) => ModelId::parse(value)
            .map(ProviderReported::Reported)
            .map_err(|_| storage_invariant("stored provider model is invalid")),
        _ => Err(storage_invariant(
            "stored provider model report is inconsistent",
        )),
    }
}

fn parse_provider_effort(
    status: &str,
    value: Option<String>,
) -> Result<ProviderReported<ReasoningEffort>, CarlError> {
    match (status, value) {
        ("not_reported", None) => Ok(ProviderReported::NotReported),
        ("reported", Some(value)) => parse_reasoning_effort(&value).map(ProviderReported::Reported),
        _ => Err(storage_invariant(
            "stored provider effort report is inconsistent",
        )),
    }
}

fn provider_model_parts(value: &ProviderReported<ModelId>) -> (&'static str, Option<&str>) {
    match value {
        ProviderReported::NotReported => ("not_reported", None),
        ProviderReported::Reported(model) => ("reported", Some(model.as_str())),
    }
}

fn provider_effort_parts(
    value: &ProviderReported<ReasoningEffort>,
) -> (&'static str, Option<&'static str>) {
    match value {
        ProviderReported::NotReported => ("not_reported", None),
        ProviderReported::Reported(effort) => ("reported", Some(effort.as_codex_value())),
    }
}

fn revision_to_sql(value: u64) -> Result<i64, CarlError> {
    i64::try_from(value).map_err(|_| storage_invariant("subscription run sequence is too large"))
}

fn load_memory_settings(
    connection: &Connection,
    partition: &MemoryPartition,
) -> Result<MemorySettings, CarlError> {
    let stored = connection
        .query_row(
            "SELECT enabled, max_context_items, context_bytes, max_memories,
                    max_storage_bytes, episode_ttl_days
             FROM memory_settings
             WHERE owner_id = ?1 AND agent_id = ?2",
            params![partition.owner_id(), partition.agent_id()],
            |row| {
                Ok((
                    row.get::<_, bool>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(storage_error)?;
    let Some((
        enabled,
        max_context_items,
        context_bytes,
        max_memories,
        max_storage_bytes,
        episode_ttl_days,
    )) = stored
    else {
        return Ok(MemorySettings::default());
    };
    let settings = MemorySettings {
        enabled,
        max_context_items: u32::try_from(max_context_items)
            .map_err(|_| storage_invariant("stored memory context-item limit is invalid"))?,
        context_bytes: u32::try_from(context_bytes)
            .map_err(|_| storage_invariant("stored memory context-byte limit is invalid"))?,
        max_memories: u32::try_from(max_memories)
            .map_err(|_| storage_invariant("stored memory count limit is invalid"))?,
        max_storage_bytes: u64::try_from(max_storage_bytes)
            .map_err(|_| storage_invariant("stored memory storage limit is invalid"))?,
        episode_ttl_days: u32::try_from(episode_ttl_days)
            .map_err(|_| storage_invariant("stored memory retention is invalid"))?,
    };
    settings
        .validate()
        .map_err(|_| storage_invariant("stored memory settings are invalid"))?;
    Ok(settings)
}

fn validate_memory_write(write: &MemoryWrite) -> Result<(), CarlError> {
    SecretFilter
        .inspect(write.content.as_bytes())
        .map_err(|finding| CarlError::Validation {
            detail: format!(
                "memory capture was rejected by secret filter rule {:?}",
                finding.rule()
            ),
        })?;
    SecretFilter
        .inspect(write.provenance.as_bytes())
        .map_err(|finding| CarlError::Validation {
            detail: format!(
                "memory provenance was rejected by secret filter rule {:?}",
                finding.rule()
            ),
        })?;
    validate_memory_capture_text(&write.content)?;
    validate_memory_capture_text(&write.provenance)
}

fn remember_memory_in_transaction(
    connection: &Connection,
    write: &MemoryWrite,
    now: DateTime<Utc>,
) -> Result<MemoryRecord, CarlError> {
    let settings = load_memory_settings(connection, &write.partition)?;
    if !settings.enabled {
        return Err(CarlError::Policy {
            detail: "memory capture is disabled".to_owned(),
        });
    }
    let expires_at = default_expiration(write.kind, write.expires_at, &settings, now);
    if expires_at.is_some_and(|expires_at| expires_at <= now) {
        return Err(CarlError::Validation {
            detail: "memory expiration must be in the future".to_owned(),
        });
    }

    connection
        .execute(
            "DELETE FROM memories
             WHERE owner_id = ?1 AND agent_id = ?2
               AND expires_at IS NOT NULL AND expires_at <= ?3",
            params![
                write.partition.owner_id(),
                write.partition.agent_id(),
                format_timestamp(now),
            ],
        )
        .map_err(storage_error)?;
    let (count, total_bytes): (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(length(CAST(content AS BLOB))), 0)
             FROM memories WHERE owner_id = ?1 AND agent_id = ?2",
            params![write.partition.owner_id(), write.partition.agent_id()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(storage_error)?;
    let existing = connection
        .query_row(
            "SELECT id, length(CAST(content AS BLOB)), revision, created_at
             FROM memories
             WHERE owner_id = ?1 AND agent_id = ?2 AND scope_kind = ?3
               AND scope_key = ?4 AND kind = ?5 AND memory_key = ?6",
            params![
                write.partition.owner_id(),
                write.partition.agent_id(),
                write.scope.kind().as_str(),
                write.scope.key(),
                write.kind.as_str(),
                write.key,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(storage_error)?;
    let content_bytes = i64::try_from(write.content.len())
        .map_err(|_| storage_invariant("memory content length is invalid"))?;
    let retained_bytes = existing
        .as_ref()
        .map_or(total_bytes, |(_, previous_bytes, _, _)| {
            total_bytes - previous_bytes
        });
    let projected_bytes = retained_bytes
        .checked_add(content_bytes)
        .ok_or_else(|| storage_invariant("memory storage accounting overflowed"))?;
    if u64::try_from(projected_bytes).map_or(true, |bytes| bytes > settings.max_storage_bytes) {
        return Err(CarlError::BudgetExceeded {
            resource: crate::error::BudgetResource::MemoryBytes,
            limit: u32::try_from(settings.max_storage_bytes).unwrap_or(u32::MAX),
        });
    }

    let (id, revision, created_at) = match existing {
        Some((id, _, revision, created_at)) => {
            let revision = revision
                .checked_add(1)
                .ok_or_else(|| storage_invariant("memory revision overflowed"))?;
            connection
                .execute(
                    "UPDATE memories SET
                        content = ?2, provenance = ?3, importance = ?4,
                        revision = ?5, updated_at = ?6, expires_at = ?7
                     WHERE id = ?1",
                    params![
                        id,
                        write.content,
                        write.provenance,
                        write.importance,
                        revision,
                        format_timestamp(now),
                        expires_at.map(format_timestamp),
                    ],
                )
                .map_err(storage_error)?;
            (id, revision, parse_timestamp(&created_at)?)
        }
        None => {
            if u64::try_from(count).map_or(true, |count| count >= u64::from(settings.max_memories))
            {
                return Err(CarlError::BudgetExceeded {
                    resource: crate::error::BudgetResource::MemoryItems,
                    limit: settings.max_memories,
                });
            }
            let id = Uuid::new_v4().to_string();
            connection
                .execute(
                    "INSERT INTO memories (
                        id, owner_id, agent_id, scope_kind, scope_key, kind, memory_key,
                        content, provenance, importance, revision, created_at, updated_at,
                        expires_at
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?11, ?11, ?12)",
                    params![
                        id,
                        write.partition.owner_id(),
                        write.partition.agent_id(),
                        write.scope.kind().as_str(),
                        write.scope.key(),
                        write.kind.as_str(),
                        write.key,
                        write.content,
                        write.provenance,
                        write.importance,
                        format_timestamp(now),
                        expires_at.map(format_timestamp),
                    ],
                )
                .map_err(storage_error)?;
            (id, 1_i64, now)
        }
    };
    Ok(MemoryRecord {
        id: parse_id("memory ID", &id)?,
        partition: write.partition.clone(),
        scope: write.scope.clone(),
        kind: write.kind,
        key: write.key.clone(),
        content: write.content.clone(),
        provenance: write.provenance.clone(),
        importance: write.importance,
        revision: u32::try_from(revision)
            .map_err(|_| storage_invariant("memory revision is invalid"))?,
        created_at,
        updated_at: now,
        expires_at,
    })
}

fn checkpoint_for_secure_deletion(connection: &Connection) -> Result<(), CarlError> {
    let (busy, _, _): (i64, i64, i64) = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(storage_error)?;
    if busy != 0 {
        return Err(CarlError::Storage {
            detail: "SQLite could not truncate the write-ahead log after a secure deletion"
                .to_owned(),
        });
    }
    Ok(())
}

struct RawEvent {
    id: String,
    turn_id: Option<String>,
    sequence: i64,
    timestamp: String,
    schema_version: i64,
    event_json: String,
}

impl RawEvent {
    fn into_envelope(self, session_id: SessionId) -> Result<EventEnvelope, CarlError> {
        if self.schema_version < 1 || self.schema_version > i64::from(EVENT_SCHEMA_VERSION) {
            return Err(CarlError::Storage {
                detail: format!("unsupported event schema version {}", self.schema_version),
            });
        }
        let sequence = u64::try_from(self.sequence).map_err(|error| CarlError::Storage {
            detail: format!("invalid event sequence {}: {error}", self.sequence),
        })?;
        let value: serde_json::Value =
            serde_json::from_str(&self.event_json).map_err(storage_error)?;
        let embedded_version = value
            .get("schema_version")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| storage_invariant("stored event schema version is missing"))?;
        if embedded_version != self.schema_version {
            return Err(storage_invariant(
                "stored event schema versions do not match",
            ));
        }
        let event = serde_json::from_value(value).map_err(storage_error)?;
        Ok(EventEnvelope {
            id: parse_id("event ID", &self.id)?,
            session_id,
            turn_id: self
                .turn_id
                .as_deref()
                .map(|value| parse_id("turn ID", value))
                .transpose()?,
            sequence,
            timestamp: parse_timestamp(&self.timestamp)?,
            event,
        })
    }
}

struct RawMemoryRecord {
    id: String,
    owner_id: String,
    agent_id: String,
    scope_kind: String,
    scope_key: String,
    kind: String,
    key: String,
    content: String,
    provenance: String,
    importance: i64,
    revision: i64,
    created_at: String,
    updated_at: String,
    expires_at: Option<String>,
}

impl TryFrom<RawMemoryRecord> for MemoryRecord {
    type Error = CarlError;

    fn try_from(value: RawMemoryRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            id: parse_id("memory ID", &value.id)?,
            partition: MemoryPartition::new(value.owner_id, value.agent_id)?,
            scope: MemoryScope::from_stored(&value.scope_kind, value.scope_key)?,
            kind: MemoryKind::parse(&value.kind)?,
            key: value.key,
            content: value.content,
            provenance: value.provenance,
            importance: u8::try_from(value.importance)
                .map_err(|_| storage_invariant("stored memory importance is invalid"))?,
            revision: u32::try_from(value.revision)
                .map_err(|_| storage_invariant("stored memory revision is invalid"))?,
            created_at: parse_timestamp(&value.created_at)?,
            updated_at: parse_timestamp(&value.updated_at)?,
            expires_at: value
                .expires_at
                .as_deref()
                .map(parse_timestamp)
                .transpose()?,
        })
    }
}

fn raw_memory_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawMemoryRecord> {
    Ok(RawMemoryRecord {
        id: row.get(0)?,
        owner_id: row.get(1)?,
        agent_id: row.get(2)?,
        scope_kind: row.get(3)?,
        scope_key: row.get(4)?,
        kind: row.get(5)?,
        key: row.get(6)?,
        content: row.get(7)?,
        provenance: row.get(8)?,
        importance: row.get(9)?,
        revision: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
        expires_at: row.get(13)?,
    })
}

struct RawMemoryProposal {
    id: String,
    owner_id: String,
    agent_id: String,
    scope_kind: String,
    scope_key: String,
    kind: String,
    key: String,
    content: String,
    provenance: String,
    importance: i64,
    memory_expires_at: Option<String>,
    origin: String,
    source_session_id: Option<String>,
    created_at: String,
    expires_at: String,
}

impl TryFrom<RawMemoryProposal> for MemoryProposal {
    type Error = CarlError;

    fn try_from(value: RawMemoryProposal) -> Result<Self, Self::Error> {
        let importance = u8::try_from(value.importance)
            .map_err(|_| storage_invariant("stored memory proposal importance is invalid"))?;
        let write = MemoryWrite::new(
            MemoryPartition::new(value.owner_id, value.agent_id)?,
            MemoryScope::from_stored(&value.scope_kind, value.scope_key)?,
            MemoryKind::parse(&value.kind)?,
            value.key,
            value.content,
            value.provenance,
        )?
        .with_importance(importance);
        let write = match value.memory_expires_at.as_deref() {
            Some(expires_at) => write.with_expiration(parse_timestamp(expires_at)?),
            None => write,
        };
        Ok(Self {
            id: parse_id("memory proposal ID", &value.id)?,
            write,
            origin: ProposalOrigin::parse(&value.origin)?,
            source_session: value
                .source_session_id
                .as_deref()
                .map(|id| parse_id("memory proposal session ID", id))
                .transpose()?,
            created_at: parse_timestamp(&value.created_at)?,
            expires_at: parse_timestamp(&value.expires_at)?,
        })
    }
}

fn raw_memory_proposal(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawMemoryProposal> {
    Ok(RawMemoryProposal {
        id: row.get(0)?,
        owner_id: row.get(1)?,
        agent_id: row.get(2)?,
        scope_kind: row.get(3)?,
        scope_key: row.get(4)?,
        kind: row.get(5)?,
        key: row.get(6)?,
        content: row.get(7)?,
        provenance: row.get(8)?,
        importance: row.get(9)?,
        memory_expires_at: row.get(10)?,
        origin: row.get(11)?,
        source_session_id: row.get(12)?,
        created_at: row.get(13)?,
        expires_at: row.get(14)?,
    })
}

type RawBoundApproval = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);

fn raw_bound_approval(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawBoundApproval> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

fn bound_record_from_raw(
    id: ApprovalId,
    raw: RawBoundApproval,
) -> Result<BoundApprovalRecord, CarlError> {
    let (
        session_id,
        turn_id,
        tool_call_id,
        actor_id,
        request_digest,
        summary,
        status,
        created_at,
        expires_at,
        resolved_at,
        consumed_at,
    ) = raw;
    let created_at = parse_timestamp(&created_at)?;
    let expires_at = parse_timestamp(&expires_at)?;
    let actor_id = ActorId::parse(actor_id)
        .map_err(|_| storage_invariant("stored bound approval actor is invalid"))?;
    let request_digest = Sha256Digest::parse(request_digest)
        .map_err(|_| storage_invariant("stored bound approval digest is invalid"))?;
    Ok(BoundApprovalRecord {
        id,
        binding: BoundApprovalBinding::new(
            parse_id("session ID", &session_id)?,
            parse_id("turn ID", &turn_id)?,
            parse_id("tool call ID", &tool_call_id)?,
            actor_id,
            request_digest,
            created_at,
            expires_at,
        )
        .map_err(|_| storage_invariant("stored bound approval lifetime is invalid"))?,
        summary,
        status: ApprovalStatus::parse(&status)?,
        resolved_at: resolved_at.as_deref().map(parse_timestamp).transpose()?,
        consumed_at: consumed_at.as_deref().map(parse_timestamp).transpose()?,
    })
}

fn validate_canonical_frontend_cwd(cwd: &Path) -> Result<(), CarlError> {
    let encoded = cwd.to_str().ok_or_else(|| CarlError::Validation {
        detail: "frontend working directory is not UTF-8".to_owned(),
    })?;
    if !cwd.is_absolute()
        || encoded.is_empty()
        || encoded.len() > MAX_FRONTEND_CWD_BYTES
        || encoded.as_bytes().contains(&0)
    {
        return Err(CarlError::Validation {
            detail: "frontend working directory is invalid".to_owned(),
        });
    }
    let canonical = fs::canonicalize(cwd).map_err(|_| CarlError::Validation {
        detail: "frontend working directory is unavailable".to_owned(),
    })?;
    if canonical != cwd || !canonical.is_dir() {
        return Err(CarlError::Validation {
            detail: "frontend working directory is not canonical".to_owned(),
        });
    }
    Ok(())
}

fn validate_remote_display_code(display_code: &str) -> Result<(), CarlError> {
    if display_code.len() != 10
        || !display_code
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CarlError::Validation {
            detail: "remote display code is invalid".to_owned(),
        });
    }
    Ok(())
}

fn validate_remote_code_shape(
    kind: RemoteCodeKind,
    approval_id: Option<ApprovalId>,
    provider_request_id: Option<&ProviderRequestId>,
) -> Result<(), CarlError> {
    let valid = match kind {
        RemoteCodeKind::Approval => approval_id.is_some() && provider_request_id.is_some(),
        RemoteCodeKind::BypassConfirmation => {
            approval_id.is_none() && provider_request_id.is_none()
        }
    };
    if !valid {
        return Err(CarlError::Validation {
            detail: "remote code binding is invalid".to_owned(),
        });
    }
    Ok(())
}

fn remote_code_digest(display_code: &str) -> Sha256Digest {
    let mut digest = Sha256::new();
    digest.update(REMOTE_CODE_DOMAIN);
    digest.update(display_code.as_bytes());
    Sha256Digest::from_bytes(digest.finalize().into())
}

fn load_remote_code(
    transaction: &Transaction<'_>,
    code_digest: Sha256Digest,
) -> Result<Option<RemoteCodeRecord>, CarlError> {
    let raw = transaction
        .query_row(
            "SELECT kind, external_session_id, approval_id, provider_request_id,
                    request_digest, actor_id, created_at, expires_at, consumed_at
             FROM remote_codes WHERE code_digest = ?1",
            [code_digest.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(storage_error)?;
    raw.map(
        |(
            kind,
            external_session_id,
            approval_id,
            provider_request_id,
            request_digest,
            actor_id,
            created_at,
            expires_at,
            consumed_at,
        )| {
            Ok(RemoteCodeRecord {
                code_digest,
                kind: RemoteCodeKind::parse(&kind)?,
                external_session_id: ExternalSessionId::try_from(external_session_id)?,
                approval_id: approval_id
                    .as_deref()
                    .map(|value| parse_id("approval ID", value))
                    .transpose()?,
                provider_request_id: provider_request_id
                    .map(ProviderRequestId::try_from)
                    .transpose()?,
                request_digest: Sha256Digest::parse(request_digest)?,
                actor_id: ActorId::parse(actor_id)?,
                created_at: parse_timestamp(&created_at)?,
                expires_at: parse_timestamp(&expires_at)?,
                consumed_at: consumed_at.as_deref().map(parse_timestamp).transpose()?,
            })
        },
    )
    .transpose()
}

fn format_timestamp(timestamp: DateTime<Utc>) -> String {
    timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>, CarlError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(storage_error)
}

fn parse_id<T>(kind: &str, value: &str) -> Result<T, CarlError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value.parse().map_err(|error| CarlError::Storage {
        detail: format!("invalid {kind} {value:?}: {error}"),
    })
}

fn invalid_stored_value(kind: &str, value: &str) -> CarlError {
    CarlError::Storage {
        detail: format!("invalid stored {kind} {value:?}"),
    }
}

fn policy_error(detail: &str) -> CarlError {
    CarlError::Policy {
        detail: detail.to_owned(),
    }
}

fn storage_invariant(detail: &str) -> CarlError {
    CarlError::Storage {
        detail: detail.to_owned(),
    }
}

fn storage_error(error: impl std::fmt::Display) -> CarlError {
    CarlError::Storage {
        detail: error.to_string(),
    }
}

#[cfg(all(test, unix))]
mod verification_persistence_tests {
    use std::error::Error;
    use std::ffi::OsString;
    use std::path::PathBuf;

    use chrono::TimeDelta;
    use semver::VersionReq;

    use super::*;
    use crate::delegates::DelegateSettingsLayers;
    use crate::sidecar::{ExecutableTrustDecision, SidecarCommand, VersionOutputFormat};
    use crate::staging::{ProposalLimits, ProposalOutcome, SanitizedStageBuilder, StageLimits};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    const BEFORE: &[u8] = b"pub fn answer() -> u32 { 41 }\n";
    const AFTER: &[u8] = b"pub fn answer() -> u32 { 42 }\n";

    struct VerificationLayout {
        root: PathBuf,
        source: PathBuf,
        stages: PathBuf,
    }

    impl VerificationLayout {
        fn new() -> TestResult<Self> {
            use std::os::unix::fs::PermissionsExt as _;

            let root = PathBuf::from("/tmp")
                .join(format!("carl-verification-storage-unit-{}", Uuid::new_v4()));
            let source = root.join("source");
            let stages = root.join("stages");
            fs::create_dir_all(source.join("src"))?;
            fs::create_dir_all(&stages)?;
            for path in [&root, &source, &stages] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
            fs::write(source.join("src/lib.rs"), BEFORE)?;
            Ok(Self {
                root,
                source,
                stages,
            })
        }
    }

    impl Drop for VerificationLayout {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn completion_matrix_is_atomic_capability_safe_and_durable() -> TestResult {
        let layout = VerificationLayout::new()?;
        let mut runtime =
            RuntimeStore::open(DataRootLock::acquire(&layout.root)?, test_instant(0))?;
        let specification = verification_specification()?;
        let matrix = [
            (
                VerificationOutcome::Passed,
                Some(0),
                RunState::AwaitingPromotionApproval,
                None,
                true,
            ),
            (
                VerificationOutcome::Cancelled,
                None,
                RunState::Cancelled,
                None,
                false,
            ),
            (
                VerificationOutcome::NonZeroExit,
                Some(2),
                RunState::Failed,
                Some(RunFailureCode::VerificationFailed),
                false,
            ),
            (
                VerificationOutcome::TimedOut,
                None,
                RunState::Failed,
                Some(RunFailureCode::VerificationFailed),
                false,
            ),
            (
                VerificationOutcome::OutputLimitExceeded,
                None,
                RunState::Failed,
                Some(RunFailureCode::VerificationFailed),
                false,
            ),
            (
                VerificationOutcome::ProcessFailed,
                None,
                RunState::Failed,
                Some(RunFailureCode::VerificationFailed),
                false,
            ),
            (
                VerificationOutcome::CandidateMutated,
                Some(0),
                RunState::Failed,
                Some(RunFailureCode::VerificationFailed),
                false,
            ),
            (
                VerificationOutcome::OutputRejected,
                None,
                RunState::Failed,
                Some(RunFailureCode::VerificationFailed),
                false,
            ),
        ];
        let mut persisted = Vec::new();
        for (index, (outcome, exit_code, state, failure_code, should_verify)) in
            matrix.into_iter().enumerate()
        {
            let offset = i64::try_from(index)? * 20;
            let (run_id, request, verifying_revision) =
                prepare_verifying_run(&mut runtime, &layout, &specification, offset)?;
            let observed_candidate = if outcome == VerificationOutcome::CandidateMutated {
                Some(Sha256Digest::from_bytes([7; 32]))
            } else {
                Some(request.candidate_manifest_digest())
            };
            let (stdout, stderr) = if outcome == VerificationOutcome::OutputRejected {
                (
                    vec![0xff],
                    b"diagnostic must be redacted as one unit".to_vec(),
                )
            } else {
                (b"bounded stdout\n".to_vec(), b"bounded stderr\n".to_vec())
            };
            let result = VerificationResult::from_execution_observation(
                &request,
                outcome,
                exit_code,
                observed_candidate,
                Some(request.baseline_directory_manifest_digest()),
                stdout,
                stderr,
                Duration::from_nanos(12_345_678),
            )?;
            assert!(
                runtime
                    .complete_subscription_run_verification(
                        run_id,
                        verifying_revision + 1,
                        &result,
                        test_instant(offset + 8),
                    )?
                    .is_none(),
                "a stale completion must not persist a result"
            );
            assert!(
                runtime
                    .get_subscription_run_verification_result(run_id)?
                    .is_none()
            );

            let completion = runtime
                .complete_subscription_run_verification(
                    run_id,
                    verifying_revision,
                    &result,
                    test_instant(offset + 8),
                )?
                .expect("current verification completion wins");
            assert_eq!(completion.run().state, state);
            assert_eq!(completion.run().failure_code, failure_code);
            assert_eq!(
                completion.verified_proposal().is_some(),
                should_verify,
                "only a committed pass may mint VerifiedProposal"
            );
            assert_eq!(completion.result().result_digest(), result.result_digest());
            let durable = runtime
                .get_subscription_run_verification_result(run_id)?
                .expect("committed verification result is loadable");
            assert_eq!(durable.result_digest(), result.result_digest());
            persisted.push((run_id, outcome, result.result_digest()));
        }

        drop(runtime);
        let reopened = RuntimeStore::open(DataRootLock::acquire(&layout.root)?, test_instant(200))?;
        for (run_id, outcome, result_digest) in persisted {
            let durable = reopened
                .get_subscription_run_verification_result(run_id)?
                .expect("verification result survives restart and recomputation");
            assert_eq!(durable.outcome(), outcome);
            assert_eq!(durable.result_digest(), result_digest);
        }
        Ok(())
    }

    #[test]
    fn completion_failure_rolls_back_result_state_event_and_capability() -> TestResult {
        let layout = VerificationLayout::new()?;
        let mut runtime =
            RuntimeStore::open(DataRootLock::acquire(&layout.root)?, test_instant(0))?;
        let specification = verification_specification()?;
        let (run_id, request, verifying_revision) =
            prepare_verifying_run(&mut runtime, &layout, &specification, 0)?;
        let result = VerificationResult::from_execution_observation(
            &request,
            VerificationOutcome::Passed,
            Some(0),
            Some(request.candidate_manifest_digest()),
            Some(request.baseline_directory_manifest_digest()),
            Vec::new(),
            Vec::new(),
            Duration::from_nanos(9_999_991),
        )?;
        runtime.store.connection.execute_batch(
            "CREATE TRIGGER test_reject_verification_completion
             BEFORE UPDATE OF state ON subscription_runs
             WHEN OLD.state = 'verifying'
             BEGIN
                 SELECT RAISE(ABORT, 'injected completion failure');
             END;",
        )?;

        assert!(
            runtime
                .complete_subscription_run_verification(
                    run_id,
                    verifying_revision,
                    &result,
                    test_instant(8),
                )
                .is_err(),
            "the injected failure must escape without a capability"
        );
        runtime
            .store
            .connection
            .execute_batch("DROP TRIGGER test_reject_verification_completion;")?;
        let run = runtime
            .get_subscription_run(run_id)?
            .expect("run remains present");
        assert_eq!(run.state, RunState::Verifying);
        assert_eq!(run.revision, verifying_revision);
        assert!(
            runtime
                .get_subscription_run_verification_result(run_id)?
                .is_none(),
            "the result insert must roll back with the failed transition"
        );
        assert_eq!(
            runtime.store.connection.query_row(
                "SELECT COUNT(*)
                 FROM subscription_run_verification_results
                 WHERE run_id = ?1",
                [run_id.to_string()],
                |row| row.get::<_, u64>(0),
            )?,
            0,
            "the failed transaction must leave no raw result row behind"
        );
        assert_eq!(
            runtime.read_subscription_run_events(run_id)?.len(),
            usize::try_from(verifying_revision)?
        );
        Ok(())
    }

    #[test]
    fn begin_failure_rolls_back_request_arguments_state_and_event() -> TestResult {
        let layout = VerificationLayout::new()?;
        let mut runtime =
            RuntimeStore::open(DataRootLock::acquire(&layout.root)?, test_instant(0))?;
        let specification = verification_specification()?;
        let (run_id, inspecting_revision) = prepare_inspecting_run(&mut runtime, &layout, 0)?;
        runtime.store.connection.execute_batch(
            "CREATE TRIGGER test_reject_verification_begin
             BEFORE UPDATE OF state ON subscription_runs
             WHEN NEW.state = 'verifying'
             BEGIN
                 SELECT RAISE(ABORT, 'injected begin failure');
             END;",
        )?;

        assert!(
            runtime
                .begin_subscription_run_verification(
                    run_id,
                    inspecting_revision,
                    &specification,
                    test_instant(7),
                )
                .is_err()
        );
        runtime
            .store
            .connection
            .execute_batch("DROP TRIGGER test_reject_verification_begin;")?;
        assert!(
            runtime
                .get_subscription_run_verification_request(run_id)?
                .is_none()
        );
        let run = runtime
            .get_subscription_run(run_id)?
            .expect("run remains present");
        assert_eq!(run.state, RunState::Inspecting);
        assert_eq!(run.revision, inspecting_revision);
        assert_eq!(
            runtime.read_subscription_run_events(run_id)?.len(),
            usize::try_from(inspecting_revision)?
        );
        let argv_count = runtime.store.connection.query_row(
            "SELECT COUNT(*)
             FROM subscription_run_verification_argv AS argv
             JOIN subscription_run_verification_requests AS request
               ON request.id = argv.verification_id
             WHERE request.run_id = ?1",
            [run_id.to_string()],
            |row| row.get::<_, u64>(0),
        )?;
        assert_eq!(argv_count, 0);
        Ok(())
    }

    #[test]
    fn verification_loaders_reject_replay_and_digest_corruption() -> TestResult {
        let layout = VerificationLayout::new()?;
        let mut runtime =
            RuntimeStore::open(DataRootLock::acquire(&layout.root)?, test_instant(0))?;
        let specification = verification_specification()?;
        let (run_id, request, verifying_revision) =
            prepare_verifying_run(&mut runtime, &layout, &specification, 0)?;
        runtime
            .store
            .connection
            .execute_batch("DROP TRIGGER subscription_run_verification_requests_immutable;")?;
        runtime.store.connection.execute(
            "UPDATE subscription_run_verification_requests
             SET started_run_sequence = started_run_sequence - 1
             WHERE run_id = ?1",
            [run_id.to_string()],
        )?;
        assert!(
            runtime
                .get_subscription_run_verification_request(run_id)
                .is_err(),
            "a request must point at its exact Inspecting-to-Verifying event"
        );
        runtime.store.connection.execute(
            "UPDATE subscription_run_verification_requests
             SET started_run_sequence = ?2
             WHERE run_id = ?1",
            params![run_id.to_string(), revision_to_sql(verifying_revision)?,],
        )?;
        assert!(
            runtime
                .get_subscription_run_verification_request(run_id)?
                .is_some()
        );
        runtime.store.connection.execute(
            "UPDATE subscription_run_verification_requests
             SET argv_digest = ?2
             WHERE run_id = ?1",
            params![run_id.to_string(), "0".repeat(64)],
        )?;
        assert!(
            runtime
                .get_subscription_run_verification_request(run_id)
                .is_err(),
            "argv evidence must be recomputed rather than trusted"
        );

        let (result_run_id, result_request, result_revision) =
            prepare_verifying_run(&mut runtime, &layout, &specification, 20)?;
        let result = VerificationResult::from_execution_observation(
            &result_request,
            VerificationOutcome::Passed,
            Some(0),
            Some(result_request.candidate_manifest_digest()),
            Some(result_request.baseline_directory_manifest_digest()),
            b"ok\n".to_vec(),
            Vec::new(),
            Duration::from_nanos(2_000_001),
        )?;
        runtime
            .complete_subscription_run_verification(
                result_run_id,
                result_revision,
                &result,
                test_instant(28),
            )?
            .expect("result persists");
        runtime
            .store
            .connection
            .execute_batch("DROP TRIGGER subscription_run_verification_results_immutable;")?;
        runtime.store.connection.execute(
            "UPDATE subscription_run_verification_results
             SET completed_run_sequence = completed_run_sequence - 1
             WHERE run_id = ?1",
            [result_run_id.to_string()],
        )?;
        assert!(
            runtime
                .get_subscription_run_verification_result(result_run_id)
                .is_err(),
            "a result must point at its exact completion event"
        );
        runtime.store.connection.execute(
            "UPDATE subscription_run_verification_results
             SET completed_run_sequence = ?2
             WHERE run_id = ?1",
            params![
                result_run_id.to_string(),
                revision_to_sql(result_revision + 1)?,
            ],
        )?;
        assert!(
            runtime
                .get_subscription_run_verification_result(result_run_id)?
                .is_some()
        );
        runtime.store.connection.execute(
            "UPDATE subscription_run_verification_results
             SET duration_nanos = duration_nanos + 1
             WHERE run_id = ?1",
            [result_run_id.to_string()],
        )?;
        assert!(
            runtime
                .get_subscription_run_verification_result(result_run_id)
                .is_err(),
            "result duration is digest-bound and must be recomputed"
        );
        assert_eq!(request.run_id(), run_id);
        Ok(())
    }

    fn prepare_verifying_run(
        runtime: &mut RuntimeStore,
        layout: &VerificationLayout,
        specification: &VerificationSpec,
        offset: i64,
    ) -> TestResult<(RunId, VerificationRequest, u64)> {
        let (run_id, inspecting) = prepare_inspecting_run(runtime, layout, offset)?;
        let request = runtime
            .begin_subscription_run_verification(
                run_id,
                inspecting,
                specification,
                test_instant(offset + 7),
            )?
            .expect("verification begins");
        Ok((run_id, request, inspecting + 1))
    }

    fn prepare_inspecting_run(
        runtime: &mut RuntimeStore,
        layout: &VerificationLayout,
        offset: i64,
    ) -> TestResult<(RunId, u64)> {
        fs::write(layout.source.join("src/lib.rs"), BEFORE)?;
        let stage = SanitizedStageBuilder::open(
            &layout.source,
            &layout.stages,
            StageLimits::new(32, 4_096, 64 * 1_024)?,
            SecretFilter,
        )?
        .prepare(runtime.artifacts())?;
        let run_id = create_test_run(runtime, test_instant(offset + 1))?;
        runtime
            .record_subscription_run_baseline(
                run_id,
                RunState::Prepared,
                1,
                stage.sealed_baseline(),
                test_instant(offset + 2),
            )?
            .expect("baseline persists");
        let awaiting = transition_test_run(
            runtime,
            run_id,
            RunState::Prepared,
            1,
            RunState::AwaitingDelegateApproval,
            test_instant(offset + 3),
        )?;
        let running = transition_test_run(
            runtime,
            run_id,
            RunState::AwaitingDelegateApproval,
            awaiting,
            RunState::Running,
            test_instant(offset + 4),
        )?;
        let inspecting = transition_test_run(
            runtime,
            run_id,
            RunState::Running,
            running,
            RunState::Inspecting,
            test_instant(offset + 5),
        )?;
        fs::write(stage.path().join("src/lib.rs"), AFTER)?;
        let proposal = match stage.inspect_proposal(
            runtime.artifacts(),
            ProposalLimits::new(4_096)?,
            SecretFilter,
        )? {
            ProposalOutcome::ExactReplacement(proposal) => proposal,
            ProposalOutcome::NoChanges => return Err("changed stage produced no proposal".into()),
        };
        runtime
            .record_subscription_run_exact_proposal(
                run_id,
                RunState::Inspecting,
                inspecting,
                &proposal,
                test_instant(offset + 6),
            )?
            .expect("proposal persists");
        Ok((run_id, inspecting))
    }

    fn create_test_run(runtime: &mut RuntimeStore, at: DateTime<Utc>) -> TestResult<RunId> {
        let session = runtime.create_session()?;
        let resolved = DelegateSettingsLayers::default().resolve();
        let run_id = RunId::new();
        runtime.create_subscription_run(NewSubscriptionRun::new(
            run_id,
            session.id,
            TurnId::new(),
            DelegateSettings::default(),
            RunConfigSnapshot::from_resolved(&resolved),
            at,
        )?)?;
        Ok(run_id)
    }

    fn transition_test_run(
        runtime: &mut RuntimeStore,
        run_id: RunId,
        from: RunState,
        revision: u64,
        to: RunState,
        at: DateTime<Utc>,
    ) -> TestResult<u64> {
        Ok(runtime
            .compare_and_transition_subscription_run(
                run_id,
                from,
                revision,
                RunTransition::new(from, to, None)?,
                RunTrustLabel::TrustedCarlState,
                at,
            )?
            .expect("transition succeeds")
            .revision)
    }

    fn verification_specification() -> TestResult<VerificationSpec> {
        let command = SidecarCommand {
            executable: std::env::current_exe()?,
            arguments: Vec::new(),
            version_arguments: vec![OsString::from("--version")],
            version_output: VersionOutputFormat::SingleSemverToken,
            isolated_home: PathBuf::from("verification-storage-unit"),
            supported_versions: VersionReq::parse(">=0.0.0")?,
        };
        let resolved = command.resolve_executable()?;
        let decision = if resolved.metadata_risk().is_some() {
            ExecutableTrustDecision::TrustCanonicalPathWithMetadataRisk
        } else {
            ExecutableTrustDecision::TrustCanonicalPath
        };
        Ok(VerificationSpec::new(
            resolved.trust(decision)?,
            vec![String::new(), "--check".to_owned()],
            VerificationEnvironmentProfile::CleanV1,
            VerificationLimits::new(
                Duration::from_nanos(123_456_789),
                64 * 1_024,
                Duration::from_nanos(20_000_003),
                Duration::from_nanos(30_000_007),
                Duration::from_nanos(1_000_009),
            )?,
        )?)
    }

    fn test_instant(offset_seconds: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-30T12:00:00Z")
            .expect("valid test timestamp")
            .with_timezone(&Utc)
            + TimeDelta::seconds(offset_seconds)
    }
}
