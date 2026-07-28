use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::CarlError;
use crate::events::{
    ApprovalId, EVENT_SCHEMA_VERSION, Event, EventEnvelope, EventId, SessionId, ToolCallId, TurnId,
};
use crate::policy::{ActorId, Sha256Digest};

use super::schema;

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BOUND_APPROVAL_LIFETIME: chrono::TimeDelta = chrono::TimeDelta::minutes(15);
const MAX_APPROVAL_SUMMARY_BYTES: usize = 4 * 1_024;

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
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let sequence = transaction
            .query_row(
                "UPDATE sessions
                 SET next_sequence = next_sequence + 1, updated_at = ?2
                 WHERE id = ?1
                 RETURNING next_sequence - 1",
                params![session_id.to_string(), format_timestamp(Utc::now())],
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
            timestamp: Utc::now(),
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
                    i64::try_from(envelope.sequence).map_err(|error| CarlError::Storage {
                        detail: format!("event sequence is too large: {error}"),
                    })?,
                    format_timestamp(envelope.timestamp),
                    i64::from(envelope.schema_version()),
                    event_json,
                ],
            )
            .map_err(storage_error)?;
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
        if self.schema_version > i64::from(EVENT_SCHEMA_VERSION) {
            return Err(CarlError::Storage {
                detail: format!("unsupported event schema version {}", self.schema_version),
            });
        }
        let sequence = u64::try_from(self.sequence).map_err(|error| CarlError::Storage {
            detail: format!("invalid event sequence {}: {error}", self.sequence),
        })?;
        let event = serde_json::from_str(&self.event_json).map_err(storage_error)?;
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
