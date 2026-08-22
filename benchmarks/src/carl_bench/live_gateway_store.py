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


def _valid_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


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
                    claim_expires_at INTEGER,
                    provider_request_digest TEXT,
                    dispatched_at INTEGER,
                    runner_request_digest TEXT UNIQUE,
                    runner_context_json TEXT,
                    sealed_bundle_json TEXT
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
                "provider_request_digest": "TEXT",
                "dispatched_at": "INTEGER",
                "runner_request_digest": "TEXT",
                "runner_context_json": "TEXT",
                "sealed_bundle_json": "TEXT",
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
            connection.execute(
                """UPDATE gateway_grants
                   SET claim_state = 'dispatch_ambiguous',
                       infrastructure_code = COALESCE(
                           infrastructure_code, 'gateway_legacy_dispatch_ambiguous'
                       )
                   WHERE claim_state = 'in_progress'"""
            )
            connection.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS gateway_grants_runner_request
                   ON gateway_grants(runner_request_digest)
                   WHERE runner_request_digest IS NOT NULL"""
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
        runner_request_digest: str | None = None,
        runner_context: dict[str, Any] | None = None,
    ) -> None:
        payload = _canonical_text(grant, "live_gateway_grant_invalid")
        if (
            (runner_request_digest is None) != (runner_context is None)
            or (runner_request_digest is not None and not _valid_digest(runner_request_digest))
            or (runner_context is not None and type(runner_context) is not dict)
        ):
            raise LiveGatewayStateError("live_gateway_runner_binding_invalid")
        context_payload = (
            None
            if runner_context is None
            else _canonical_text(runner_context, "live_gateway_runner_binding_invalid")
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO gateway_grants (
                       token_digest, issue_key, pair_request_digest, task_id, attempt, subject,
                       grant_json, runner_request_digest, runner_context_json
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    token_digest,
                    issue_key,
                    pair_request_digest,
                    task_id,
                    attempt,
                    subject,
                    payload,
                    runner_request_digest,
                    context_payload,
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
            if row["claim_state"] == "dispatch_ambiguous":
                raise LiveGatewayStateError("live_gateway_dispatch_ambiguous")
            if row["claim_state"] in {"pre_dispatch", "dispatched"}:
                raise LiveGatewayStateError("live_gateway_capability_in_progress")
            if row["claim_state"] != "ready":
                raise LiveGatewayStateError("live_gateway_capability_consumed")
            connection.execute(
                """UPDATE gateway_grants
                   SET consumed = 1, claim_state = 'pre_dispatch', claim_id = ?,
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

    def mark_provider_dispatched(
        self,
        token_digest: str,
        claim_id: str,
        *,
        request_digest: str,
        dispatched_at: int,
    ) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                """UPDATE gateway_grants
                   SET claim_state = 'dispatched', provider_request_digest = ?, dispatched_at = ?
                   WHERE token_digest = ? AND claim_state = 'pre_dispatch' AND claim_id = ?""",
                (request_digest, dispatched_at, token_digest, claim_id),
            )
            if updated.rowcount != 1:
                raise LiveGatewayStateError("live_gateway_capability_invalid")
            connection.commit()
        except LiveGatewayStateError:
            connection.rollback()
            raise
        except sqlite3.Error as error:
            connection.rollback()
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()

    def mark_dispatch_ambiguous(
        self,
        token_digest: str,
        claim_id: str,
        *,
        code: str,
    ) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                """UPDATE gateway_grants
                   SET claim_state = 'dispatch_ambiguous', infrastructure_code = ?
                   WHERE token_digest = ? AND claim_state = 'dispatched' AND claim_id = ?""",
                (code, token_digest, claim_id),
            )
            if updated.rowcount != 1:
                raise LiveGatewayStateError("live_gateway_capability_invalid")
            connection.commit()
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
                """SELECT claim_state, claim_id, result_json, provider_request_digest
                   FROM gateway_grants
                   WHERE token_digest = ?""",
                (token_digest,),
            ).fetchone()
            if row is None or row["claim_state"] != "dispatched" or row["claim_id"] != claim_id:
                raise LiveGatewayStateError("live_gateway_capability_invalid")
            if result.get("request_digest") != row["provider_request_digest"]:
                raise LiveGatewayStateError("live_gateway_result_conflict")
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

    def reconcile_dispatched_result(self, token_digest: str, result: dict[str, Any]) -> None:
        payload = _canonical_text(result, "live_gateway_result_invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT claim_state, provider_request_digest, result_json
                   FROM gateway_grants WHERE token_digest = ?""",
                (token_digest,),
            ).fetchone()
            if row is None or row["claim_state"] != "dispatch_ambiguous":
                raise LiveGatewayStateError("live_gateway_reconciliation_not_authorized")
            if (
                row["result_json"] is not None
                or result.get("request_digest") != row["provider_request_digest"]
            ):
                raise LiveGatewayStateError("live_gateway_result_conflict")
            connection.execute(
                """UPDATE gateway_grants
                   SET result_json = ?, claim_state = 'completed', infrastructure_code = NULL
                   WHERE token_digest = ? AND claim_state = 'dispatch_ambiguous'""",
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

    def peek_result(self, token_digest: str) -> tuple[dict[str, Any], dict[str, Any]]:
        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT grant_json, result_json, claim_state
                   FROM gateway_grants WHERE token_digest = ?""",
                (token_digest,),
            ).fetchone()
            if row is None:
                raise LiveGatewayStateError("live_gateway_capability_invalid")
            if row["claim_state"] != "completed" or row["result_json"] is None:
                raise LiveGatewayStateError("live_gateway_result_unavailable")
            return (
                _decode(row["grant_json"], "live_gateway_grant_invalid"),
                _decode(row["result_json"], "live_gateway_result_invalid"),
            )
        except LiveGatewayStateError:
            raise
        except sqlite3.Error as error:
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()

    def load_sealed_bundle(self, runner_request_digest: str) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT sealed_bundle_json FROM gateway_grants
                   WHERE runner_request_digest = ?""",
                (runner_request_digest,),
            ).fetchone()
            if row is None:
                return None
            if row["sealed_bundle_json"] is None:
                return None
            return _decode(row["sealed_bundle_json"], "live_gateway_bundle_invalid")
        except LiveGatewayStateError:
            raise
        except sqlite3.Error as error:
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()

    def load_resumable_result(
        self, runner_request_digest: str
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                """SELECT grant_json, result_json, runner_context_json, claim_state,
                          sealed_bundle_json
                   FROM gateway_grants WHERE runner_request_digest = ?""",
                (runner_request_digest,),
            ).fetchone()
            if row is None or row["sealed_bundle_json"] is not None:
                return None
            if (
                row["claim_state"] != "completed"
                or row["result_json"] is None
                or row["runner_context_json"] is None
            ):
                raise LiveGatewayStateError("live_gateway_execution_resume_unavailable")
            return (
                _decode(row["grant_json"], "live_gateway_grant_invalid"),
                _decode(row["result_json"], "live_gateway_result_invalid"),
                _decode(
                    row["runner_context_json"],
                    "live_gateway_runner_binding_invalid",
                ),
            )
        except LiveGatewayStateError:
            raise
        except sqlite3.Error as error:
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()

    def seal_resumed_result_bundle(
        self,
        runner_request_digest: str,
        *,
        bundle: dict[str, Any],
    ) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT token_digest FROM gateway_grants WHERE runner_request_digest = ?",
                (runner_request_digest,),
            ).fetchone()
        except sqlite3.Error as error:
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            connection.close()
        if row is None:
            raise LiveGatewayStateError("live_gateway_execution_resume_unavailable")
        return self.seal_result_bundle(
            row["token_digest"],
            runner_request_digest=runner_request_digest,
            bundle=bundle,
        )

    def seal_result_bundle(
        self,
        token_digest: str,
        *,
        runner_request_digest: str,
        bundle: dict[str, Any],
    ) -> dict[str, Any]:
        payload = _canonical_text(bundle, "live_gateway_bundle_invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT result_json, collected, claim_state, runner_request_digest,
                          sealed_bundle_json
                   FROM gateway_grants WHERE token_digest = ?""",
                (token_digest,),
            ).fetchone()
            if row is None:
                raise LiveGatewayStateError("live_gateway_capability_invalid")
            if row["sealed_bundle_json"] is not None:
                if (
                    row["runner_request_digest"] != runner_request_digest
                    or row["sealed_bundle_json"] != payload
                ):
                    raise LiveGatewayStateError("live_gateway_bundle_conflict")
                connection.commit()
                return _decode(row["sealed_bundle_json"], "live_gateway_bundle_invalid")
            if (
                row["collected"]
                or row["claim_state"] != "completed"
                or row["result_json"] is None
                or row["runner_request_digest"] not in {None, runner_request_digest}
                or type(bundle.get("model_result")) is not dict
                or _canonical_text(bundle["model_result"], "live_gateway_bundle_invalid")
                != row["result_json"]
            ):
                raise LiveGatewayStateError("live_gateway_bundle_conflict")
            updated = connection.execute(
                """UPDATE gateway_grants
                   SET runner_request_digest = ?, sealed_bundle_json = ?, collected = 1
                   WHERE token_digest = ? AND collected = 0 AND sealed_bundle_json IS NULL""",
                (runner_request_digest, payload, token_digest),
            )
            if updated.rowcount != 1:
                raise LiveGatewayStateError("live_gateway_bundle_conflict")
            connection.commit()
            return _decode(payload, "live_gateway_bundle_invalid")
        except sqlite3.IntegrityError as error:
            connection.rollback()
            raise LiveGatewayStateError("live_gateway_bundle_conflict") from error
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
            if (
                row["claim_state"] in {"dispatched", "dispatch_ambiguous"}
                or row["result_json"] is not None
                or row["infrastructure_code"] not in {None, code}
            ):
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
                """SELECT collected, claim_state, infrastructure_code FROM gateway_grants
                   WHERE token_digest = ?""",
                (token_digest,),
            ).fetchone()
            if (
                row is None
                or row["collected"]
                or row["claim_state"] in {"dispatched", "dispatch_ambiguous"}
                or row["infrastructure_code"] not in {None, code}
            ):
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
                """SELECT subject, infrastructure_code, claim_state FROM gateway_grants
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
            if row["infrastructure_code"] is not None and row["claim_state"] == "invalid"
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
                """SELECT token_digest, claim_state, claim_boot_id, claim_pid,
                          claim_process_start
                   FROM gateway_grants
                   WHERE claim_state IN ('pre_dispatch', 'dispatched')
                         AND claim_expires_at <= ?
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
                if row["claim_state"] == "pre_dispatch":
                    next_state = "invalid"
                    code = "gateway_pre_dispatch_abandoned"
                else:
                    next_state = "dispatch_ambiguous"
                    code = "gateway_dispatch_ambiguous"
                connection.execute(
                    """UPDATE gateway_grants
                       SET claim_state = ?, infrastructure_code = ?
                       WHERE token_digest = ? AND claim_state = ? AND claim_expires_at <= ?""",
                    (next_state, code, row["token_digest"], row["claim_state"], observed_at),
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


class SQLiteLiveGatewayCommissioningReader:
    """Read-only view of pre-dispatch execution observations for the evaluator."""

    __slots__ = ("_uri",)

    def __new__(cls, *args: object, **kwargs: object) -> SQLiteLiveGatewayCommissioningReader:
        del cls, args, kwargs
        raise LiveGatewayStateError("live_gateway_state_protected_construction_required")

    @classmethod
    def from_protected_process(cls) -> SQLiteLiveGatewayCommissioningReader:
        if os.geteuid() != 0:
            raise LiveGatewayStateError("live_gateway_state_configuration_invalid")
        return cls._construct(path=_STATE_PATH, expected_uid=0)

    @classmethod
    def _for_testing(cls, path: Path) -> SQLiteLiveGatewayCommissioningReader:
        return cls._construct(path=path, expected_uid=os.geteuid())

    @classmethod
    def _construct(cls, *, path: Path, expected_uid: int) -> SQLiteLiveGatewayCommissioningReader:
        try:
            parent = path.parent.lstat()
            details = path.lstat()
        except OSError as error:
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        if (
            not path.is_absolute()
            or path.is_symlink()
            or not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(parent.st_mode)
            or parent.st_uid != expected_uid
            or stat.S_IMODE(parent.st_mode) & 0o022
            or not stat.S_ISREG(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != expected_uid
            or stat.S_IMODE(details.st_mode) != 0o600
        ):
            raise LiveGatewayStateError("live_gateway_state_configuration_invalid")
        value = object.__new__(cls)
        value._uri = f"{path.as_uri()}?mode=ro"
        return value

    def expected_actuals(
        self,
        *,
        pair_request_digest: str,
        task_id: str,
        attempt: int,
        subject: str,
    ) -> tuple[int, str] | None:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self._uri, timeout=5, uri=True)
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """SELECT runner_context_json FROM gateway_grants
                   WHERE pair_request_digest = ? AND task_id = ? AND attempt = ?
                         AND subject = ?""",
                (pair_request_digest, task_id, attempt, subject),
            ).fetchall()
        except sqlite3.Error as error:
            raise LiveGatewayStateError("live_gateway_state_unavailable") from error
        finally:
            if connection is not None:
                connection.close()
        if not rows:
            return None
        if len(rows) != 1 or rows[0]["runner_context_json"] is None:
            raise LiveGatewayStateError("live_gateway_runner_binding_invalid")
        context = _decode(
            rows[0]["runner_context_json"],
            "live_gateway_runner_binding_invalid",
        )
        process_id = context.get("process_id")
        observation_digest = context.get("cgroup_observation_digest")
        if type(process_id) is not int or process_id <= 0 or not _valid_digest(observation_digest):
            raise LiveGatewayStateError("live_gateway_runner_binding_invalid")
        return process_id, observation_digest
