"""Owner-local append-only SQLite ledger for dry-run experiments."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from carl_bench.autonomy import AutonomyProjection, reduce_autonomy_events
from carl_bench.canonical import canonical_json_bytes
from carl_bench.experiment import (
    _ISOLATED_AUTHORITY_REQUIRED_EVENTS,
    EventType,
    ExperimentEvent,
    ExperimentManifest,
    ExperimentProjection,
    GraphContractError,
    reduce_events,
)

_ZERO_DIGEST = "0" * 64
_TRUSTED_AUTHORITY_EVENT_TYPES = frozenset(
    {
        EventType.PAIRED_EVIDENCE_RECORDED,
        EventType.PROTECTED_VALIDATION_RECORDED,
        EventType.PROMOTION_RECORDED,
        EventType.SOAK_OBSERVED,
        EventType.REVERT_RECORDED,
    }
)
_TRUSTED_CANONICAL_EVENT_TYPES = frozenset(
    {
        EventType.PAIRED_EVIDENCE_RECORDED,
        EventType.PROTECTED_VALIDATION_RECORDED,
    }
)


def _trusted_canonical_digests(
    events: tuple[ExperimentEvent, ...],
) -> frozenset[str]:
    return frozenset(
        event.digest for event in events if event.event_type in _TRUSTED_CANONICAL_EVENT_TYPES
    )


class LedgerIntegrityError(ValueError):
    """A stable ledger failure that never exposes stored private content."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class AppendResult:
    ordinal: int
    event_digest: str
    chain_digest: str
    appended: bool


@dataclass(frozen=True, slots=True)
class BudgetDispatchDecision:
    allowed: bool
    reasons: tuple[str, ...]
    experiment_after_microdollars: int
    daily_after_microdollars: int
    weekly_after_microdollars: int
    active_live_workers: int
    experiment_elapsed_seconds: int


class _SafeConnection(sqlite3.Connection):
    def execute(self, sql: str, parameters: Any = (), /) -> sqlite3.Cursor:
        try:
            return super().execute(sql, parameters)
        except sqlite3.Error as error:
            raise LedgerIntegrityError("ledger_database_error") from error

    def commit(self) -> None:
        try:
            super().commit()
        except sqlite3.Error as error:
            raise LedgerIntegrityError("ledger_database_error") from error

    def rollback(self) -> None:
        try:
            super().rollback()
        except sqlite3.Error as error:
            raise LedgerIntegrityError("ledger_database_error") from error


def _utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise LedgerIntegrityError("invalid_budget_timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise LedgerIntegrityError("invalid_budget_timestamp") from error
    if parsed.tzinfo != UTC:
        raise LedgerIntegrityError("invalid_budget_timestamp")
    return parsed


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise LedgerIntegrityError("duplicate_json_key")
        value[key] = item
    return value


def _decode_object(value: str, code: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value, object_pairs_hook=_object_without_duplicates)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise LedgerIntegrityError(code) from error
    if not isinstance(parsed, dict):
        raise LedgerIntegrityError(code)
    return parsed


def _chain_digest(
    *,
    experiment_id: str,
    manifest_digest: str,
    ordinal: int,
    event_digest: str,
    previous_chain_digest: str,
) -> str:
    value = {
        "event_digest": event_digest,
        "experiment_id": experiment_id,
        "manifest_digest": manifest_digest,
        "ordinal": ordinal,
        "previous_chain_digest": previous_chain_digest,
    }
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


class ExperimentLedger:
    """Append and replay normalized experiment facts with integrity verification."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().absolute()
        self._prepare_path()
        self._initialize_schema()

    def _prepare_path(self) -> None:
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            parent_metadata = self.path.parent.lstat()
            if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(parent_metadata.st_mode):
                raise LedgerIntegrityError("unsafe_ledger_parent")
            if os.name != "nt" and (
                stat.S_IMODE(parent_metadata.st_mode) & 0o077
                or parent_metadata.st_uid != os.getuid()
            ):
                raise LedgerIntegrityError("unsafe_ledger_parent")
            if self.path.exists() or self.path.is_symlink():
                metadata = self.path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                    raise LedgerIntegrityError("unsafe_ledger_file")
                if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
                    raise LedgerIntegrityError("unsafe_ledger_permissions")
                if metadata.st_nlink != 1:
                    raise LedgerIntegrityError("unsafe_ledger_links")
                if os.name != "nt" and metadata.st_uid != os.getuid():
                    raise LedgerIntegrityError("unsafe_ledger_owner")
                return
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self.path, flags, 0o600)
            os.close(descriptor)
        except LedgerIntegrityError:
            raise
        except OSError as error:
            raise LedgerIntegrityError("ledger_unavailable") from error

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=5.0,
                isolation_level=None,
                factory=_SafeConnection,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as error:
            raise LedgerIntegrityError("ledger_database_error") from error

    def _initialize_schema(self) -> None:
        statements = (
            """
            CREATE TABLE IF NOT EXISTS ledger_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) STRICT
            """,
            """
            CREATE TABLE IF NOT EXISTS experiment_manifests (
                experiment_id TEXT PRIMARY KEY,
                parent_experiment_id TEXT,
                manifest_json TEXT NOT NULL,
                manifest_digest TEXT NOT NULL UNIQUE,
                FOREIGN KEY (parent_experiment_id) REFERENCES experiment_manifests(experiment_id)
            ) STRICT
            """,
            """
            CREATE TABLE IF NOT EXISTS experiment_events (
                row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                experiment_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                schema_version INTEGER NOT NULL,
                stage_attempt_id TEXT NOT NULL UNIQUE,
                event_type TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                event_digest TEXT NOT NULL,
                previous_chain_digest TEXT NOT NULL,
                chain_digest TEXT NOT NULL UNIQUE,
                FOREIGN KEY (experiment_id) REFERENCES experiment_manifests(experiment_id),
                UNIQUE (experiment_id, ordinal)
            ) STRICT
            """,
        )
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                for statement in statements:
                    connection.execute(statement)
                row = connection.execute(
                    "SELECT value FROM ledger_metadata WHERE key = 'schema_version'"
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO ledger_metadata(key, value) VALUES('schema_version', '1')"
                    )
                elif row["value"] != "1":
                    raise LedgerIntegrityError("unsupported_ledger_schema")
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def register_manifest(self, manifest: ExperimentManifest) -> bool:
        manifest_json = canonical_json_bytes(manifest.to_canonical_dict()).decode("utf-8")
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """
                    SELECT parent_experiment_id, manifest_json, manifest_digest
                    FROM experiment_manifests
                    WHERE experiment_id = ?
                    """,
                    (manifest.experiment_id,),
                ).fetchone()
                if row is not None:
                    if (
                        row["parent_experiment_id"] != manifest.parent_experiment_id
                        or row["manifest_json"] != manifest_json
                        or row["manifest_digest"] != manifest.digest
                    ):
                        raise LedgerIntegrityError("manifest_conflict")
                    connection.commit()
                    return False
                if manifest.parent_experiment_id is not None:
                    parent_row = connection.execute(
                        "SELECT 1 FROM experiment_manifests WHERE experiment_id = ?",
                        (manifest.parent_experiment_id,),
                    ).fetchone()
                    if parent_row is None:
                        raise LedgerIntegrityError("parent_experiment_not_found")
                    parent = self._load_manifest(connection, manifest.parent_experiment_id)
                    if _utc(manifest.registered_at) < _utc(parent.registered_at):
                        raise LedgerIntegrityError("child_precedes_parent")
                connection.execute(
                    """
                    INSERT INTO experiment_manifests(
                        experiment_id, parent_experiment_id, manifest_json, manifest_digest
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (
                        manifest.experiment_id,
                        manifest.parent_experiment_id,
                        manifest_json,
                        manifest.digest,
                    ),
                )
                connection.commit()
                return True
            except Exception:
                connection.rollback()
                raise

    def _load_manifest(
        self, connection: sqlite3.Connection, experiment_id: str
    ) -> ExperimentManifest:
        row = connection.execute(
            """
            SELECT parent_experiment_id, manifest_json, manifest_digest
            FROM experiment_manifests
            WHERE experiment_id = ?
            """,
            (experiment_id,),
        ).fetchone()
        if row is None:
            raise LedgerIntegrityError("experiment_not_found")
        value = _decode_object(row["manifest_json"], "manifest_json_invalid")
        try:
            manifest = ExperimentManifest.from_canonical_dict(value)
        except GraphContractError as error:
            raise LedgerIntegrityError("manifest_contract_invalid") from error
        canonical = canonical_json_bytes(manifest.to_canonical_dict()).decode("utf-8")
        if canonical != row["manifest_json"] or manifest.digest != row["manifest_digest"]:
            raise LedgerIntegrityError("manifest_digest_mismatch")
        if manifest.parent_experiment_id != row["parent_experiment_id"]:
            raise LedgerIntegrityError("manifest_parent_mismatch")
        return manifest

    def _all_manifests(self, connection: sqlite3.Connection) -> tuple[ExperimentManifest, ...]:
        rows = connection.execute(
            "SELECT experiment_id FROM experiment_manifests ORDER BY experiment_id"
        ).fetchall()
        return tuple(self._load_manifest(connection, row["experiment_id"]) for row in rows)

    def load_manifest(self, experiment_id: str) -> ExperimentManifest:
        with self._connect() as connection:
            return self._load_manifest(connection, experiment_id)

    def _read_events(
        self,
        connection: sqlite3.Connection,
        manifest: ExperimentManifest,
    ) -> tuple[tuple[ExperimentEvent, ...], tuple[str, ...]]:
        rows = connection.execute(
            """
            SELECT ordinal, schema_version, stage_attempt_id, event_type, occurred_at,
                   payload_json, event_digest, previous_chain_digest, chain_digest
            FROM experiment_events
            WHERE experiment_id = ?
            ORDER BY ordinal
            """,
            (manifest.experiment_id,),
        ).fetchall()
        events: list[ExperimentEvent] = []
        chains: list[str] = []
        previous = _ZERO_DIGEST
        for expected_ordinal, row in enumerate(rows, start=1):
            if row["ordinal"] != expected_ordinal:
                raise LedgerIntegrityError("event_ordinal_gap")
            if row["previous_chain_digest"] != previous:
                raise LedgerIntegrityError("event_chain_link_mismatch")
            try:
                event = ExperimentEvent(
                    schema_version=row["schema_version"],
                    experiment_id=manifest.experiment_id,
                    stage_attempt_id=row["stage_attempt_id"],
                    event_type=EventType(row["event_type"]),
                    occurred_at=row["occurred_at"],
                    payload_json=row["payload_json"],
                )
            except (GraphContractError, TypeError, ValueError) as error:
                raise LedgerIntegrityError("event_contract_invalid") from error
            if event.digest != row["event_digest"]:
                raise LedgerIntegrityError("event_digest_mismatch")
            expected_chain = _chain_digest(
                experiment_id=manifest.experiment_id,
                manifest_digest=manifest.digest,
                ordinal=expected_ordinal,
                event_digest=event.digest,
                previous_chain_digest=previous,
            )
            if expected_chain != row["chain_digest"]:
                raise LedgerIntegrityError("event_chain_digest_mismatch")
            events.append(event)
            chains.append(expected_chain)
            previous = expected_chain
        return tuple(events), tuple(chains)

    def append(self, event: ExperimentEvent) -> AppendResult:
        """Append candidate-authority facts without bypassing isolation gates."""
        return self._append(event, trusted_authority=False)

    def append_trusted_authority(self, event: ExperimentEvent) -> AppendResult:
        """Append a protected lifecycle fact from the isolated trusted authority."""
        if event.event_type not in _TRUSTED_AUTHORITY_EVENT_TYPES:
            raise LedgerIntegrityError("trusted_authority_event_required")
        return self._append(event, trusted_authority=True)

    def _append(self, event: ExperimentEvent, *, trusted_authority: bool) -> AppendResult:
        if event.event_type in _ISOLATED_AUTHORITY_REQUIRED_EVENTS and not trusted_authority:
            raise LedgerIntegrityError("isolated_signer_required")
        with self._connect() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                manifest = self._load_manifest(connection, event.experiment_id)
                events, chains = self._read_events(connection, manifest)
                existing = connection.execute(
                    """
                    SELECT experiment_id, ordinal, event_digest, chain_digest
                    FROM experiment_events
                    WHERE stage_attempt_id = ?
                    """,
                    (event.stage_attempt_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        existing["experiment_id"] != event.experiment_id
                        or existing["event_digest"] != event.digest
                    ):
                        raise LedgerIntegrityError("stage_attempt_conflict")
                    connection.commit()
                    return AppendResult(
                        ordinal=existing["ordinal"],
                        event_digest=event.digest,
                        chain_digest=existing["chain_digest"],
                        appended=False,
                    )
                if event.event_type is EventType.LEASE_ACQUIRED:
                    for other_manifest in self._all_manifests(connection):
                        other_events, _ = self._read_events(connection, other_manifest)
                        try:
                            other_projection = reduce_events(
                                other_manifest,
                                other_events,
                                trusted_authority_event_digests=(
                                    _trusted_canonical_digests(other_events)
                                ),
                            )
                        except GraphContractError as error:
                            raise LedgerIntegrityError(error.code) from error
                        if (
                            other_projection.lease is not None
                            and not other_projection.lease.stale_reconciled
                        ):
                            raise LedgerIntegrityError("mutable_lease_conflict")
                try:
                    proposed_events = (*events, event)
                    trusted_digests = _trusted_canonical_digests(events)
                    if trusted_authority and event.event_type in _TRUSTED_CANONICAL_EVENT_TYPES:
                        trusted_digests = trusted_digests | {event.digest}
                    reduce_events(
                        manifest,
                        proposed_events,
                        trusted_authority_event_digests=trusted_digests,
                    )
                    reduce_autonomy_events(manifest, proposed_events)
                except GraphContractError as error:
                    raise LedgerIntegrityError(error.code) from error
                ordinal = len(events) + 1
                previous = chains[-1] if chains else _ZERO_DIGEST
                chain = _chain_digest(
                    experiment_id=event.experiment_id,
                    manifest_digest=manifest.digest,
                    ordinal=ordinal,
                    event_digest=event.digest,
                    previous_chain_digest=previous,
                )
                connection.execute(
                    """
                    INSERT INTO experiment_events(
                        experiment_id, ordinal, schema_version, stage_attempt_id,
                        event_type, occurred_at, payload_json, event_digest,
                        previous_chain_digest, chain_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.experiment_id,
                        ordinal,
                        event.schema_version,
                        event.stage_attempt_id,
                        event.event_type.value,
                        event.occurred_at,
                        event.payload_json,
                        event.digest,
                        previous,
                        chain,
                    ),
                )
                connection.commit()
                return AppendResult(
                    ordinal=ordinal,
                    event_digest=event.digest,
                    chain_digest=chain,
                    appended=True,
                )
            except Exception:
                connection.rollback()
                raise

    def events(self, experiment_id: str) -> tuple[ExperimentEvent, ...]:
        with self._connect() as connection:
            manifest = self._load_manifest(connection, experiment_id)
            events, _ = self._read_events(connection, manifest)
            return events

    def projection(self, experiment_id: str) -> ExperimentProjection:
        with self._connect() as connection:
            manifest = self._load_manifest(connection, experiment_id)
            events, _ = self._read_events(connection, manifest)
        try:
            return reduce_events(
                manifest,
                events,
                trusted_authority_event_digests=_trusted_canonical_digests(events),
            )
        except GraphContractError as error:
            raise LedgerIntegrityError(error.code) from error

    def autonomy_projection(self, experiment_id: str) -> AutonomyProjection:
        with self._connect() as connection:
            manifest = self._load_manifest(connection, experiment_id)
            events, _ = self._read_events(connection, manifest)
        try:
            return reduce_autonomy_events(manifest, events)
        except GraphContractError as error:
            raise LedgerIntegrityError(error.code) from error

    def event_count(self, experiment_id: str) -> int:
        with self._connect() as connection:
            manifest = self._load_manifest(connection, experiment_id)
            events, _ = self._read_events(connection, manifest)
            return len(events)

    def can_dispatch_live_run(
        self,
        experiment_id: str,
        *,
        requested_microdollars: int,
        at: str,
        active_live_workers: int,
    ) -> BudgetDispatchDecision:
        """Check exact local and portfolio limits without reserving or spending funds."""
        if (
            isinstance(requested_microdollars, bool)
            or not isinstance(requested_microdollars, int)
            or requested_microdollars <= 0
        ):
            raise LedgerIntegrityError("invalid_requested_budget")
        if (
            isinstance(active_live_workers, bool)
            or not isinstance(active_live_workers, int)
            or active_live_workers < 0
        ):
            raise LedgerIntegrityError("invalid_active_live_workers")
        instant = _utc(at)
        lower_week = instant - timedelta(days=7)
        daily_spend = 0
        weekly_spend = 0
        target_spend = 0
        with self._connect() as connection:
            target_manifest = self._load_manifest(connection, experiment_id)
            registered_at = _utc(target_manifest.registered_at)
            if instant < registered_at:
                raise LedgerIntegrityError("budget_snapshot_precedes_registration")
            for item in self._all_manifests(connection):
                events, _ = self._read_events(connection, item)
                try:
                    projection = reduce_events(item, events)
                except GraphContractError as error:
                    raise LedgerIntegrityError(error.code) from error
                if item.experiment_id == experiment_id:
                    target_spend = projection.live_spend_microdollars
                for event in events:
                    if event.event_type is not EventType.LIVE_SPEND_RECORDED:
                        continue
                    occurred_at = _utc(event.occurred_at)
                    amount = event.payload["live_microdollars"]
                    if occurred_at > instant:
                        raise LedgerIntegrityError("budget_snapshot_precedes_recorded_spend")
                    if occurred_at.date() == instant.date() and occurred_at <= instant:
                        daily_spend += amount
                    if lower_week < occurred_at <= instant:
                        weekly_spend += amount

        experiment_after = target_spend + requested_microdollars
        daily_after = daily_spend + requested_microdollars
        weekly_after = weekly_spend + requested_microdollars
        elapsed_seconds = int((instant - registered_at).total_seconds())
        reasons: list[str] = []
        if experiment_after > target_manifest.budget.experiment_live_microdollars:
            reasons.append("experiment_live_budget_exceeded")
        if daily_after > target_manifest.budget.daily_live_microdollars:
            reasons.append("daily_live_budget_exceeded")
        if weekly_after > target_manifest.budget.weekly_live_microdollars:
            reasons.append("weekly_live_budget_exceeded")
        if elapsed_seconds > target_manifest.budget.elapsed_seconds:
            reasons.append("experiment_elapsed_budget_exceeded")
        if active_live_workers >= target_manifest.budget.live_concurrency:
            reasons.append("live_concurrency_exhausted")
        ordered = tuple(sorted(reasons))
        return BudgetDispatchDecision(
            allowed=not ordered,
            reasons=ordered,
            experiment_after_microdollars=experiment_after,
            daily_after_microdollars=daily_after,
            weekly_after_microdollars=weekly_after,
            active_live_workers=active_live_workers,
            experiment_elapsed_seconds=elapsed_seconds,
        )
