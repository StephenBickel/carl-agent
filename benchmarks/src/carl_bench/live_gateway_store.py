"""Tightly scoped durable state for the protected live gateway."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from carl_bench.canonical import canonical_json_bytes

_STATE_PATH = Path("/var/lib/carl/live-gateway/state.sqlite3")
_MAX_DOCUMENT_BYTES = 1_048_576


class LiveGatewayStateError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _canonical_text(value: dict[str, Any], code: str) -> str:
    try:
        payload = canonical_json_bytes(value)
    except (TypeError, ValueError) as error:
        raise LiveGatewayStateError(code) from error
    if not 0 < len(payload) <= _MAX_DOCUMENT_BYTES:
        raise LiveGatewayStateError(code)
    return payload.decode("utf-8")


def _decode(value: object, code: str) -> dict[str, Any]:
    if not isinstance(value, str) or not 0 < len(value.encode()) <= _MAX_DOCUMENT_BYTES:
        raise LiveGatewayStateError(code)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = item
        return result

    try:
        decoded = json.loads(value, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise LiveGatewayStateError(code) from error
    if type(decoded) is not dict or canonical_json_bytes(decoded).decode() != value:
        raise LiveGatewayStateError(code)
    return decoded


class SQLiteLiveGatewayStateStore:
    """One private SQLite authority for grants, retries, and one-use results."""

    __slots__ = ("_path",)

    def __new__(cls, *args: object, **kwargs: object) -> SQLiteLiveGatewayStateStore:
        del cls, args, kwargs
        raise LiveGatewayStateError("live_gateway_state_protected_construction_required")

    @classmethod
    def from_protected_process(cls) -> SQLiteLiveGatewayStateStore:
        return cls._construct(path=_STATE_PATH, expected_uid=os.geteuid())

    @classmethod
    def _for_testing(cls, path: Path) -> SQLiteLiveGatewayStateStore:
        return cls._construct(path=path, expected_uid=os.geteuid())

    @classmethod
    def _construct(cls, *, path: Path, expected_uid: int) -> SQLiteLiveGatewayStateStore:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or path.name in {"", ".", ".."}
            or path.is_symlink()
            or not path.parent.is_dir()
            or path.parent.is_symlink()
        ):
            raise LiveGatewayStateError("live_gateway_state_configuration_invalid")
        parent = path.parent.stat()
        if parent.st_uid != expected_uid or stat.S_IMODE(parent.st_mode) & 0o022:
            raise LiveGatewayStateError("live_gateway_state_configuration_invalid")
        if not path.exists():
            try:
                descriptor = os.open(
                    path,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                )
            except OSError as error:
                raise LiveGatewayStateError("live_gateway_state_unavailable") from error
            os.close(descriptor)
        details = path.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != expected_uid
            or stat.S_IMODE(details.st_mode) != 0o600
        ):
            raise LiveGatewayStateError("live_gateway_state_configuration_invalid")
        value = object.__new__(cls)
        value._path = path
        value._initialize()
        return value

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self._path, timeout=5, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as error:
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS gateway_grants (
                    token_digest TEXT PRIMARY KEY CHECK(length(token_digest) = 64),
                    issue_key TEXT NOT NULL UNIQUE,
                    pair_request_digest TEXT NOT NULL CHECK(length(pair_request_digest) = 64),
                    task_id TEXT NOT NULL,
                    attempt INTEGER NOT NULL CHECK(attempt BETWEEN 1 AND 3),
                    subject TEXT NOT NULL CHECK(subject IN ('parent', 'candidate')),
                    grant_json TEXT NOT NULL,
                    consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0, 1)),
                    result_json TEXT,
                    collected INTEGER NOT NULL DEFAULT 0 CHECK(collected IN (0, 1)),
                    infrastructure_code TEXT,
                    claim_state TEXT NOT NULL DEFAULT 'ready',
                    claim_id TEXT,
                    claim_boot_id TEXT,
                    claim_pid INTEGER,
                    claim_process_start TEXT,
                    claim_started_at INTEGER,
                    claim_expires_at INTEGER
                );
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(gateway_grants)")}
            additions = {
                "claim_state": "TEXT NOT NULL DEFAULT 'ready'",
                "claim_id": "TEXT",
                "claim_boot_id": "TEXT",
                "claim_pid": "INTEGER",
                "claim_process_start": "TEXT",
                "claim_started_at": "INTEGER",
                "claim_expires_at": "INTEGER",
            }
            for name, definition in additions.items():
                if name not in columns:
                    connection.execute(f"ALTER TABLE gateway_grants ADD COLUMN {name} {definition}")
            connection.execute(
                """UPDATE gateway_grants
                   SET claim_state = CASE
                       WHEN result_json IS NOT NULL THEN 'completed'
                       WHEN infrastructure_code IS NOT NULL THEN 'invalid'
                       WHEN consumed = 1 THEN 'invalid'
                       ELSE 'ready'
                   END,
                   infrastructure_code = CASE
                       WHEN consumed = 1 AND result_json IS NULL
                            AND infrastructure_code IS NULL
                       THEN 'gateway_legacy_claim_unreconciled'
                       ELSE infrastructure_code
                   END
                   WHERE claim_state = 'ready'"""
            )
        except sqlite3.Error as error:
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()

    def reserve_grant(
        self,
        *,
        token_digest: str,
        issue_key: str,
        pair_request_digest: str,
        task_id: str,
        attempt: int,
        subject: str,
        grant: dict[str, Any],
    ) -> None:
        payload = _canonical_text(grant, "live_gateway_grant_invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO gateway_grants (
                       token_digest, issue_key, pair_request_digest, task_id, attempt, subject,
                       grant_json
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    token_digest,
                    issue_key,
                    pair_request_digest,
                    task_id,
                    attempt,
                    subject,
                    payload,
                ),
            )
            connection.commit()
        except sqlite3.IntegrityError as error:
            connection.rollback()
            raise LiveGatewayStateError("live_gateway_grant_conflict") from error
        except sqlite3.Error as error:
            connection.rollback()
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()

    def load_grant(self, token_digest: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT grant_json FROM gateway_grants WHERE token_digest = ?",
                (token_digest,),
            ).fetchone()
            if row is None:
                raise LiveGatewayStateError("live_gateway_capability_invalid")
            return _decode(row["grant_json"], "live_gateway_grant_invalid")
        except LiveGatewayStateError:
            raise
        except sqlite3.Error as error:
            connection.rollback()
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()

    def claim_grant(
        self,
        token_digest: str,
        *,
        claim_id: str,
        boot_id: str,
        process_id: int,
        process_start: str,
        started_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT grant_json, claim_state FROM gateway_grants WHERE token_digest = ?",
                (token_digest,),
            ).fetchone()
            if row is None:
                raise LiveGatewayStateError("live_gateway_capability_invalid")
            if row["claim_state"] == "in_progress":
                raise LiveGatewayStateError("live_gateway_capability_in_progress")
            if row["claim_state"] != "ready":
                raise LiveGatewayStateError("live_gateway_capability_consumed")
            connection.execute(
                """UPDATE gateway_grants
                   SET consumed = 1, claim_state = 'in_progress', claim_id = ?,
                       claim_boot_id = ?, claim_pid = ?, claim_process_start = ?,
                       claim_started_at = ?, claim_expires_at = ?
                   WHERE token_digest = ? AND claim_state = 'ready'""",
                (
                    claim_id,
                    boot_id,
                    process_id,
                    process_start,
                    started_at,
                    expires_at,
                    token_digest,
                ),
            )
            connection.commit()
            return _decode(row["grant_json"], "live_gateway_grant_invalid")
        except LiveGatewayStateError:
            connection.rollback()
            raise
        except sqlite3.Error as error:
            connection.rollback()
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()

    def complete_result(self, token_digest: str, claim_id: str, result: dict[str, Any]) -> None:
        payload = _canonical_text(result, "live_gateway_result_invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT claim_state, claim_id, result_json FROM gateway_grants
                   WHERE token_digest = ?""",
                (token_digest,),
            ).fetchone()
            if row is None or row["claim_state"] != "in_progress" or row["claim_id"] != claim_id:
                raise LiveGatewayStateError("live_gateway_capability_invalid")
            if row["result_json"] not in {None, payload}:
                raise LiveGatewayStateError("live_gateway_result_conflict")
            connection.execute(
                """UPDATE gateway_grants
                   SET result_json = ?, claim_state = 'completed'
                   WHERE token_digest = ?""",
                (payload, token_digest),
            )
            connection.commit()
        except LiveGatewayStateError:
            connection.rollback()
            raise
        except sqlite3.Error as error:
            connection.rollback()
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()

    def take_result(self, token_digest: str) -> tuple[dict[str, Any], dict[str, Any]]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT grant_json, result_json, collected, claim_state
                   FROM gateway_grants WHERE token_digest = ?""",
                (token_digest,),
            ).fetchone()
            if row is None:
                raise LiveGatewayStateError("live_gateway_capability_invalid")
            if row["collected"]:
                raise LiveGatewayStateError("live_gateway_result_consumed")
            if row["claim_state"] != "completed" or row["result_json"] is None:
                raise LiveGatewayStateError("live_gateway_result_unavailable")
            connection.execute(
                "UPDATE gateway_grants SET collected = 1 WHERE token_digest = ?",
                (token_digest,),
            )
            connection.commit()
            return (
                _decode(row["grant_json"], "live_gateway_grant_invalid"),
                _decode(row["result_json"], "live_gateway_result_invalid"),
            )
        except LiveGatewayStateError:
            connection.rollback()
            raise
        except sqlite3.Error as error:
            connection.rollback()
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()

    def record_infrastructure_invalid(self, token_digest: str, code: str) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT claim_state, infrastructure_code, result_json FROM gateway_grants
                   WHERE token_digest = ?""",
                (token_digest,),
            ).fetchone()
            if row is None:
                raise LiveGatewayStateError("live_gateway_capability_invalid")
            if row["result_json"] is not None or row["infrastructure_code"] not in {None, code}:
                raise LiveGatewayStateError("live_infrastructure_result_conflict")
            connection.execute(
                """UPDATE gateway_grants
                   SET consumed = 1, claim_state = 'invalid', infrastructure_code = ?
                   WHERE token_digest = ?""",
                (code, token_digest),
            )
            connection.commit()
        except LiveGatewayStateError:
            connection.rollback()
            raise
        except sqlite3.Error as error:
            connection.rollback()
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()

    def invalidate_execution(self, token_digest: str, code: str) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT collected, infrastructure_code FROM gateway_grants
                   WHERE token_digest = ?""",
                (token_digest,),
            ).fetchone()
            if row is None or row["collected"] or row["infrastructure_code"] not in {None, code}:
                raise LiveGatewayStateError("live_infrastructure_result_conflict")
            connection.execute(
                """UPDATE gateway_grants
                   SET consumed = 1, claim_state = 'invalid', result_json = NULL,
                       infrastructure_code = ?
                   WHERE token_digest = ?""",
                (code, token_digest),
            )
            connection.commit()
        except LiveGatewayStateError:
            connection.rollback()
            raise
        except sqlite3.Error as error:
            connection.rollback()
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()

    def retry_codes(self, pair_request_digest: str, task_id: str, attempt: int) -> dict[str, str]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """SELECT subject, infrastructure_code FROM gateway_grants
                   WHERE pair_request_digest = ? AND task_id = ? AND attempt = ?
                   ORDER BY subject""",
                (pair_request_digest, task_id, attempt),
            ).fetchall()
        except sqlite3.Error as error:
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()
        return {
            row["subject"]: row["infrastructure_code"]
            for row in rows
            if row["infrastructure_code"] is not None
        }

    def reconcile_abandoned_claims(
        self,
        *,
        observed_at: int,
        current_boot_id: str,
        process_identity: Callable[[int], str | None],
    ) -> tuple[str, ...]:
        connection = self._connect()
        reconciled: list[str] = []
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """SELECT token_digest, claim_boot_id, claim_pid, claim_process_start
                   FROM gateway_grants
                   WHERE claim_state = 'in_progress' AND claim_expires_at <= ?
                   ORDER BY token_digest""",
                (observed_at,),
            ).fetchall()
            for row in rows:
                process_id = row["claim_pid"]
                alive_identity = (
                    process_identity(process_id)
                    if row["claim_boot_id"] == current_boot_id
                    else None
                )
                if alive_identity == row["claim_process_start"]:
                    continue
                connection.execute(
                    """UPDATE gateway_grants
                       SET claim_state = 'invalid',
                           infrastructure_code = 'gateway_claim_abandoned'
                       WHERE token_digest = ? AND claim_state = 'in_progress'
                             AND claim_expires_at <= ?""",
                    (row["token_digest"], observed_at),
                )
                reconciled.append(row["token_digest"])
            connection.commit()
            return tuple(reconciled)
        except Exception as error:
            connection.rollback()
            if isinstance(error, LiveGatewayStateError):
                raise
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()
