use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::time::Duration;
use std::{fs, io};

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
use crate::sidecar::DataRootLock;

use super::schema;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BOUND_APPROVAL_LIFETIME: chrono::TimeDelta = chrono::TimeDelta::minutes(15);
const MAX_APPROVAL_SUMMARY_BYTES: usize = 4 * 1_024;
const RUNTIME_DATABASE_FILENAME: &str = "carl.sqlite3";

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
        let startup_recoveries = store
            .interrupt_abandoned_subscription_runs(startup_at)?
            .into_iter()
            .map(|record| record.id)
            .collect();
        Ok(Self {
            store,
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
    pub fn startup_recoveries(&self) -> &[RunId] {
        &self.startup_recoveries
    }
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
