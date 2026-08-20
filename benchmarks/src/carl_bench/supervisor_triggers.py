"""Owner-private durable handoff records for autonomous-loop supervision."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from carl_bench.canonical import canonical_json_bytes

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_OUTCOME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class SupervisorTriggerError(ValueError):
    """A stable trigger-store failure that does not expose private state."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _valid_key(value: object) -> bool:
    return isinstance(value, str) and _KEY_RE.fullmatch(value) is not None


def _validate_timestamp(value: object) -> None:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise SupervisorTriggerError("invalid_trigger_timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise SupervisorTriggerError("invalid_trigger_timestamp") from error
    if parsed.tzinfo != UTC:
        raise SupervisorTriggerError("invalid_trigger_timestamp")


@dataclass(frozen=True, slots=True)
class RecoveryAttempt:
    attempt_id: str
    action_digest: str
    occurred_at: str
    outcome: str

    def __post_init__(self) -> None:
        if not _valid_key(self.attempt_id):
            raise SupervisorTriggerError("invalid_attempt_id")
        if not isinstance(self.action_digest, str) or not _DIGEST_RE.fullmatch(
            self.action_digest
        ):
            raise SupervisorTriggerError("invalid_action_digest")
        _validate_timestamp(self.occurred_at)
        if not isinstance(self.outcome, str) or not _OUTCOME_RE.fullmatch(self.outcome):
            raise SupervisorTriggerError("invalid_attempt_outcome")

    def to_canonical_dict(self) -> dict[str, str]:
        return {
            "action_digest": self.action_digest,
            "attempt_id": self.attempt_id,
            "occurred_at": self.occurred_at,
            "outcome": self.outcome,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> RecoveryAttempt:
        if not isinstance(value, dict) or set(value) != {
            "action_digest",
            "attempt_id",
            "occurred_at",
            "outcome",
        }:
            raise SupervisorTriggerError("invalid_attempt_record")
        try:
            return cls(**value)
        except TypeError as error:
            raise SupervisorTriggerError("invalid_attempt_record") from error


@dataclass(frozen=True, slots=True)
class SupervisorTrigger:
    schema_version: int
    trigger_id: str
    evidence_digest: str
    unsafe_boundary: str
    attempt_history: tuple[RecoveryAttempt, ...]
    next_safe_node_key: str
    created_at: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise SupervisorTriggerError("invalid_trigger_schema")
        if not _valid_key(self.trigger_id):
            raise SupervisorTriggerError("invalid_trigger_id")
        if not isinstance(self.evidence_digest, str) or not _DIGEST_RE.fullmatch(
            self.evidence_digest
        ):
            raise SupervisorTriggerError("invalid_evidence_digest")
        if not _valid_key(self.unsafe_boundary):
            raise SupervisorTriggerError("invalid_unsafe_boundary")
        if not isinstance(self.attempt_history, tuple) or not all(
            isinstance(attempt, RecoveryAttempt) for attempt in self.attempt_history
        ):
            raise SupervisorTriggerError("invalid_attempt_history")
        attempt_ids = tuple(attempt.attempt_id for attempt in self.attempt_history)
        if len(set(attempt_ids)) != len(attempt_ids):
            raise SupervisorTriggerError("duplicate_attempt_id")
        if not _valid_key(self.next_safe_node_key):
            raise SupervisorTriggerError("invalid_next_safe_node_key")
        _validate_timestamp(self.created_at)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "attempt_history": [attempt.to_canonical_dict() for attempt in self.attempt_history],
            "created_at": self.created_at,
            "evidence_digest": self.evidence_digest,
            "next_safe_node_key": self.next_safe_node_key,
            "schema_version": self.schema_version,
            "trigger_id": self.trigger_id,
            "unsafe_boundary": self.unsafe_boundary,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> SupervisorTrigger:
        if not isinstance(value, dict) or set(value) != {
            "attempt_history",
            "created_at",
            "evidence_digest",
            "next_safe_node_key",
            "schema_version",
            "trigger_id",
            "unsafe_boundary",
        }:
            raise SupervisorTriggerError("invalid_trigger_record")
        history = value.get("attempt_history")
        if not isinstance(history, list):
            raise SupervisorTriggerError("invalid_attempt_history")
        try:
            return cls(
                schema_version=value["schema_version"],
                trigger_id=value["trigger_id"],
                evidence_digest=value["evidence_digest"],
                unsafe_boundary=value["unsafe_boundary"],
                attempt_history=tuple(
                    RecoveryAttempt.from_canonical_dict(attempt) for attempt in history
                ),
                next_safe_node_key=value["next_safe_node_key"],
                created_at=value["created_at"],
            )
        except KeyError as error:
            raise SupervisorTriggerError("invalid_trigger_record") from error


@dataclass(frozen=True, slots=True)
class StoredSupervisorTrigger:
    trigger: SupervisorTrigger
    revision: int
    claim_id: str | None


@dataclass(frozen=True, slots=True)
class TriggerMutation:
    applied: bool
    revision: int
    record: StoredSupervisorTrigger


def _owner_private_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return False
    return os.name == "nt" or not (
        stat.S_IMODE(metadata.st_mode) & 0o077
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    )


def _owner_private_file(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return False
    if metadata.st_nlink != 1:
        return False
    return os.name == "nt" or not (
        stat.S_IMODE(metadata.st_mode) & 0o077
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    )


class SupervisorTriggerStore:
    """Append and atomically claim versioned supervisor handoffs."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().absolute()
        self._prepare_path()
        self._initialize_schema()

    def _prepare_path(self) -> None:
        parent = self.path.parent
        try:
            if parent.exists() or parent.is_symlink():
                if not _owner_private_directory(parent):
                    raise SupervisorTriggerError("unsafe_trigger_store_parent")
            else:
                parent.mkdir(mode=0o700, parents=True)
                if os.name != "nt":
                    parent.chmod(0o700)
                if not _owner_private_directory(parent):
                    raise SupervisorTriggerError("unsafe_trigger_store_parent")

            if self.path.exists() or self.path.is_symlink():
                if not _owner_private_file(self.path):
                    raise SupervisorTriggerError("unsafe_trigger_store_file")
                return
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.path, flags, 0o600)
            os.close(descriptor)
        except SupervisorTriggerError:
            raise
        except OSError as error:
            raise SupervisorTriggerError("trigger_store_unavailable") from error

    def _connect(self) -> sqlite3.Connection:
        if not _owner_private_directory(self.path.parent):
            raise SupervisorTriggerError("unsafe_trigger_store_parent")
        if not _owner_private_file(self.path):
            raise SupervisorTriggerError("unsafe_trigger_store_file")
        try:
            connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as error:
            raise SupervisorTriggerError("trigger_store_database_error") from error

    def _initialize_schema(self) -> None:
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS store_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    ) STRICT
                    """
                )
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS supervisor_triggers (
                        trigger_id TEXT PRIMARY KEY,
                        trigger_json TEXT NOT NULL,
                        revision INTEGER NOT NULL CHECK (revision >= 0),
                        claim_id TEXT
                    ) STRICT
                    """
                )
                row = connection.execute(
                    "SELECT value FROM store_metadata WHERE key = 'schema_version'"
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO store_metadata(key, value) VALUES('schema_version', '1')"
                    )
                elif row["value"] != "1":
                    raise SupervisorTriggerError("unsupported_trigger_store_schema")
                connection.commit()
            except SupervisorTriggerError:
                connection.rollback()
                raise
            except sqlite3.Error as error:
                connection.rollback()
                raise SupervisorTriggerError("trigger_store_database_error") from error

    @staticmethod
    def _decode_trigger(value: str) -> SupervisorTrigger:
        try:
            decoded = json.loads(value)
        except (json.JSONDecodeError, UnicodeError) as error:
            raise SupervisorTriggerError("invalid_trigger_record") from error
        return SupervisorTrigger.from_canonical_dict(decoded)

    @classmethod
    def _record(cls, row: sqlite3.Row) -> StoredSupervisorTrigger:
        revision = row["revision"]
        claim_id = row["claim_id"]
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise SupervisorTriggerError("invalid_trigger_revision")
        if claim_id is not None and not _valid_key(claim_id):
            raise SupervisorTriggerError("invalid_claim_id")
        return StoredSupervisorTrigger(
            trigger=cls._decode_trigger(row["trigger_json"]),
            revision=revision,
            claim_id=claim_id,
        )

    def append(self, trigger: SupervisorTrigger) -> TriggerMutation:
        if not isinstance(trigger, SupervisorTrigger):
            raise SupervisorTriggerError("invalid_trigger")
        encoded = canonical_json_bytes(trigger.to_canonical_dict()).decode("utf-8")
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT trigger_json, revision, claim_id FROM supervisor_triggers "
                    "WHERE trigger_id = ?",
                    (trigger.trigger_id,),
                ).fetchone()
                if row is not None:
                    record = self._record(row)
                    if canonical_json_bytes(record.trigger.to_canonical_dict()) != encoded.encode():
                        raise SupervisorTriggerError("trigger_id_conflict")
                    connection.commit()
                    return TriggerMutation(False, record.revision, record)
                connection.execute(
                    "INSERT INTO supervisor_triggers"
                    "(trigger_id, trigger_json, revision, claim_id) VALUES(?, ?, 0, NULL)",
                    (trigger.trigger_id, encoded),
                )
                connection.commit()
                record = StoredSupervisorTrigger(trigger=trigger, revision=0, claim_id=None)
                return TriggerMutation(True, 0, record)
            except SupervisorTriggerError:
                connection.rollback()
                raise
            except sqlite3.Error as error:
                connection.rollback()
                raise SupervisorTriggerError("trigger_store_database_error") from error

    def claim_and_record_action(
        self,
        *,
        trigger_id: str,
        claim_id: str,
        expected_revision: int,
        attempt: RecoveryAttempt,
    ) -> TriggerMutation:
        if not _valid_key(trigger_id):
            raise SupervisorTriggerError("invalid_trigger_id")
        if not _valid_key(claim_id):
            raise SupervisorTriggerError("invalid_claim_id")
        if (
            isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision < 0
        ):
            raise SupervisorTriggerError("invalid_expected_revision")
        if not isinstance(attempt, RecoveryAttempt):
            raise SupervisorTriggerError("invalid_attempt_record")

        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT trigger_json, revision, claim_id FROM supervisor_triggers "
                    "WHERE trigger_id = ?",
                    (trigger_id,),
                ).fetchone()
                if row is None:
                    raise SupervisorTriggerError("trigger_not_found")
                record = self._record(row)
                existing_by_id = {
                    item.attempt_id: item for item in record.trigger.attempt_history
                }
                existing = existing_by_id.get(attempt.attempt_id)
                if record.claim_id == claim_id and existing == attempt:
                    connection.commit()
                    return TriggerMutation(False, record.revision, record)
                if existing is not None:
                    raise SupervisorTriggerError("attempt_id_conflict")
                if record.claim_id is not None and record.claim_id != claim_id:
                    raise SupervisorTriggerError("trigger_claim_conflict")
                if record.revision != expected_revision:
                    raise SupervisorTriggerError("trigger_cas_mismatch")
                if any(
                    item.action_digest == attempt.action_digest
                    for item in record.trigger.attempt_history
                ):
                    raise SupervisorTriggerError("recovery_action_unchanged")

                updated_trigger = replace(
                    record.trigger,
                    attempt_history=(*record.trigger.attempt_history, attempt),
                )
                updated_revision = record.revision + 1
                updated_json = canonical_json_bytes(
                    updated_trigger.to_canonical_dict()
                ).decode("utf-8")
                cursor = connection.execute(
                    "UPDATE supervisor_triggers SET trigger_json = ?, revision = ?, claim_id = ? "
                    "WHERE trigger_id = ? AND revision = ? "
                    "AND (claim_id IS NULL OR claim_id = ?)",
                    (
                        updated_json,
                        updated_revision,
                        claim_id,
                        trigger_id,
                        expected_revision,
                        claim_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise SupervisorTriggerError("trigger_cas_mismatch")
                connection.commit()
                updated_record = StoredSupervisorTrigger(
                    trigger=updated_trigger,
                    revision=updated_revision,
                    claim_id=claim_id,
                )
                return TriggerMutation(True, updated_revision, updated_record)
            except SupervisorTriggerError:
                connection.rollback()
                raise
            except sqlite3.Error as error:
                connection.rollback()
                raise SupervisorTriggerError("trigger_store_database_error") from error
