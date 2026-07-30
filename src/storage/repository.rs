use std::collections::HashSet;
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::time::Duration;
use std::{fs, io};

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::artifacts::{ArtifactId, ArtifactStore};
use crate::delegates::{DelegateSettings, ModelId, ReasoningEffort, SettingSource};
use crate::error::CarlError;
use crate::events::{
    ApprovalId, EVENT_SCHEMA_VERSION, Event, EventEnvelope, EventId, SessionId, ToolCallId, TurnId,
};
use crate::policy::{ActorId, Sha256Digest};
use crate::runtime::subscription::{
    ProviderReported, RunConfigSnapshot, RunFailureCode, RunId, RunState, RunTransition,
    RunTrustLabel,
};
use crate::security::SecretFilter;
use crate::sidecar::DataRootLock;
use crate::staging::{
    ExactReplacementProposal, ProposalLimits, ProposalOutcome, SanitizedStage, SealedBaseline,
    SourcePreconditionRef, canonical_source_preconditions,
};

use super::schema;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BOUND_APPROVAL_LIFETIME: chrono::TimeDelta = chrono::TimeDelta::minutes(15);
const MAX_APPROVAL_SUMMARY_BYTES: usize = 4 * 1_024;
const RUNTIME_DATABASE_FILENAME: &str = "carl.sqlite3";
const EXACT_REPLACEMENT_DOMAIN: &[u8] = b"carl.exact-replacement.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRecord {
    pub id: SessionId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryState {
    Active,
    Forgotten,
}

impl MemoryState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Forgotten => "forgotten",
        }
    }

    fn parse(value: &str) -> Result<Self, CarlError> {
        match value {
            "active" => Ok(Self::Active),
            "forgotten" => Ok(Self::Forgotten),
            other => Err(invalid_stored_value("memory state", other)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryRecord {
    pub id: Uuid,
    pub content: String,
    pub provenance: String,
    pub state: MemoryState,
    pub created_at: DateTime<Utc>,
    pub forgotten_at: Option<DateTime<Utc>>,
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
    pub entries: Vec<SubscriptionRunBaselineEntryRecord>,
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

        Ok(Self { connection })
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
                    entry_count, total_bytes, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    run_id.to_string(),
                    baseline.manifest_artifact_id().as_str(),
                    baseline.manifest().digest().to_string(),
                    baseline.source_preconditions_artifact_id().as_str(),
                    baseline.source_preconditions_digest().to_string(),
                    usize_to_sql(baseline.entries().len(), "baseline entry count")?,
                    revision_to_sql(baseline.manifest().total_bytes())?,
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

    pub fn remember_explicit(
        &self,
        content: impl Into<String>,
        provenance: impl Into<String>,
    ) -> Result<MemoryRecord, CarlError> {
        let memory = MemoryRecord {
            id: Uuid::new_v4(),
            content: content.into(),
            provenance: provenance.into(),
            state: MemoryState::Active,
            created_at: Utc::now(),
            forgotten_at: None,
        };
        self.connection
            .execute(
                "INSERT INTO memories (
                    id, content, provenance, kind, state, created_at, forgotten_at
                 ) VALUES (?1, ?2, ?3, 'explicit', ?4, ?5, NULL)",
                params![
                    memory.id.to_string(),
                    memory.content,
                    memory.provenance,
                    memory.state.as_str(),
                    format_timestamp(memory.created_at),
                ],
            )
            .map_err(storage_error)?;
        Ok(memory)
    }

    pub fn list_active_memories(&self) -> Result<Vec<MemoryRecord>, CarlError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, content, provenance, state, created_at, forgotten_at
                 FROM memories
                 WHERE kind = 'explicit' AND state = 'active'
                 ORDER BY created_at ASC, rowid ASC",
            )
            .map_err(storage_error)?;
        let rows = statement
            .query_map([], raw_memory)
            .map_err(storage_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage_error)?;
        rows.into_iter().map(MemoryRecord::try_from).collect()
    }

    pub fn get_memory(&self, id: Uuid) -> Result<Option<MemoryRecord>, CarlError> {
        self.connection
            .query_row(
                "SELECT id, content, provenance, state, created_at, forgotten_at
                 FROM memories
                 WHERE id = ?1",
                [id.to_string()],
                raw_memory,
            )
            .optional()
            .map_err(storage_error)?
            .map(MemoryRecord::try_from)
            .transpose()
    }

    pub fn forget_memory(&self, id: Uuid) -> Result<MemoryRecord, CarlError> {
        let updated = self
            .connection
            .execute(
                "UPDATE memories
                 SET state = 'forgotten', forgotten_at = ?2
                 WHERE id = ?1 AND kind = 'explicit' AND state = 'active'",
                params![id.to_string(), format_timestamp(Utc::now())],
            )
            .map_err(storage_error)?;
        if updated != 1 {
            return Err(CarlError::Storage {
                detail: format!("memory {id} is missing or already forgotten"),
            });
        }
        self.get_memory(id)?.ok_or_else(|| CarlError::Storage {
            detail: format!("memory {id} disappeared after being forgotten"),
        })
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
        let mut store = Store::open(path)?;
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
    transaction
        .execute(
            "DELETE FROM artifact_objects
             WHERE id NOT IN (
                 SELECT manifest_artifact_id FROM subscription_run_baselines
                 UNION
                 SELECT source_preconditions_artifact_id FROM subscription_run_baselines
                 UNION
                 SELECT content_artifact_id FROM subscription_run_baseline_entries
                 UNION
                 SELECT proposal_artifact_id FROM subscription_run_proposals
                 UNION
                 SELECT payload_sha256 FROM subscription_run_proposals
             )",
            [],
        )
        .map_err(storage_error)?;
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
    identifiers
        .into_iter()
        .map(|identifier| {
            ArtifactId::parse(identifier)
                .map_err(|_| storage_invariant("durable artifact identifier is invalid"))
        })
        .collect()
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
                    baseline.entry_count, baseline.total_bytes, baseline.created_at,
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
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
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
        entries,
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

struct RawMemory {
    id: String,
    content: String,
    provenance: String,
    state: String,
    created_at: String,
    forgotten_at: Option<String>,
}

impl TryFrom<RawMemory> for MemoryRecord {
    type Error = CarlError;

    fn try_from(value: RawMemory) -> Result<Self, Self::Error> {
        Ok(Self {
            id: parse_id("memory ID", &value.id)?,
            content: value.content,
            provenance: value.provenance,
            state: MemoryState::parse(&value.state)?,
            created_at: parse_timestamp(&value.created_at)?,
            forgotten_at: value
                .forgotten_at
                .as_deref()
                .map(parse_timestamp)
                .transpose()?,
        })
    }
}

fn raw_memory(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawMemory> {
    Ok(RawMemory {
        id: row.get(0)?,
        content: row.get(1)?,
        provenance: row.get(2)?,
        state: row.get(3)?,
        created_at: row.get(4)?,
        forgotten_at: row.get(5)?,
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
