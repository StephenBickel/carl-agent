"""Restart-safe local controller for synthetic commissioning Git effects."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import signal
import sqlite3
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from carl_bench.artifacts import ArtifactRef, PrivateArtifactStore
from carl_bench.canonical import canonical_json_bytes

_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_REF_RE = re.compile(r"^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,191}$")
_KINDS = frozenset(
    {
        "experimental_publish",
        "promotion_merge",
        "hard_regression_merge",
        "revert_merge",
    }
)
_ZERO_OBJECT = "0" * 40


class CommissioningControllerError(ValueError):
    """Stable controller failure without exposing private paths or evidence."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _key(value: object, code: str) -> str:
    if not isinstance(value, str) or _KEY_RE.fullmatch(value) is None:
        raise CommissioningControllerError(code)
    return value


def _object(value: object, code: str, *, zero_allowed: bool = False) -> str:
    if not isinstance(value, str) or (
        _OBJECT_RE.fullmatch(value) is None and not (zero_allowed and value == _ZERO_OBJECT)
    ):
        raise CommissioningControllerError(code)
    return value


def _timestamp(value: object, code: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise CommissioningControllerError(code)
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise CommissioningControllerError(code) from error
    if parsed.tzinfo != UTC:
        raise CommissioningControllerError(code)
    return value


def _local_directory(value: object, code: str) -> str:
    if not isinstance(value, str) or not value or "://" in value or "\x00" in value:
        raise CommissioningControllerError(code)
    path = Path(value).expanduser().absolute()
    if not path.is_dir():
        raise CommissioningControllerError(code)
    return os.fspath(path)


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
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        return False
    return os.name == "nt" or not (
        stat.S_IMODE(metadata.st_mode) & 0o077
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    )


@dataclass(frozen=True, slots=True)
class ProtectedPullRequestRecord:
    role: str
    promotion_id: str
    number: int
    base_branch: str
    head_branch: str
    head_commit: str
    head_tree: str

    @classmethod
    def from_canonical_dict(cls, value: Any) -> ProtectedPullRequestRecord:
        expected = {
            "base_branch",
            "head_branch",
            "head_commit",
            "head_tree",
            "number",
            "promotion_id",
            "role",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise CommissioningControllerError("invalid_protected_pr")
        try:
            record = cls(**value)
        except TypeError as error:
            raise CommissioningControllerError("invalid_protected_pr") from error
        if record.role not in {"promotion", "hard_regression", "revert"}:
            raise CommissioningControllerError("invalid_protected_pr_role")
        _key(record.promotion_id, "invalid_promotion_id")
        if (
            isinstance(record.number, bool)
            or not isinstance(record.number, int)
            or record.number <= 0
        ):
            raise CommissioningControllerError("invalid_protected_pr_number")
        if record.base_branch != "main":
            raise CommissioningControllerError("invalid_protected_pr_base")
        for name in ("head_branch",):
            _key(getattr(record, name), f"invalid_protected_pr_{name}")
        _object(record.head_commit, "invalid_protected_pr_commit")
        _object(record.head_tree, "invalid_protected_pr_tree")
        return record

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "base_branch": self.base_branch,
            "head_branch": self.head_branch,
            "head_commit": self.head_commit,
            "head_tree": self.head_tree,
            "number": self.number,
            "promotion_id": self.promotion_id,
            "role": self.role,
        }


@dataclass(frozen=True, slots=True)
class EffectRequest:
    schema_version: int
    effect_key: str
    kind: str
    ref: str
    expected_old_commit: str
    target_commit: str
    target_tree: str
    source_repository: str
    occurred_at: str
    pr: ProtectedPullRequestRecord | None

    @classmethod
    def from_canonical_dict(cls, value: Any) -> EffectRequest:
        expected = {
            "effect_key",
            "expected_old_commit",
            "kind",
            "occurred_at",
            "pr",
            "ref",
            "schema_version",
            "source_repository",
            "target_commit",
            "target_tree",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise CommissioningControllerError("invalid_effect_request")
        normalized = dict(value)
        if value["pr"] is not None:
            normalized["pr"] = ProtectedPullRequestRecord.from_canonical_dict(value["pr"])
        try:
            request = cls(**normalized)
        except TypeError as error:
            raise CommissioningControllerError("invalid_effect_request") from error
        if request.schema_version != 1:
            raise CommissioningControllerError("invalid_effect_request_schema")
        _key(request.effect_key, "invalid_effect_key")
        if request.kind not in _KINDS:
            raise CommissioningControllerError("invalid_effect_kind")
        if not isinstance(request.ref, str) or _REF_RE.fullmatch(request.ref) is None:
            raise CommissioningControllerError("invalid_effect_ref")
        _object(request.expected_old_commit, "invalid_effect_parent", zero_allowed=True)
        _object(request.target_commit, "invalid_effect_target")
        _object(request.target_tree, "invalid_effect_tree")
        _local_directory(request.source_repository, "invalid_effect_source")
        _timestamp(request.occurred_at, "invalid_effect_timestamp")
        if request.kind == "experimental_publish":
            if request.pr is not None or not request.ref.startswith("refs/heads/experimental/"):
                raise CommissioningControllerError("invalid_experimental_effect")
        elif request.pr is None or request.ref != "refs/heads/main":
            raise CommissioningControllerError("invalid_protected_effect")
        return request

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "effect_key": self.effect_key,
            "expected_old_commit": self.expected_old_commit,
            "kind": self.kind,
            "occurred_at": self.occurred_at,
            "pr": self.pr.to_canonical_dict() if self.pr is not None else None,
            "ref": self.ref,
            "schema_version": self.schema_version,
            "source_repository": self.source_repository,
            "target_commit": self.target_commit,
            "target_tree": self.target_tree,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


class CommissioningEffectStore:
    """Owner-private durable effect, PR, recovery, and invocation journal."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().absolute()
        parent = self.path.parent
        if not _owner_private_directory(parent):
            raise CommissioningControllerError("unsafe_effect_store_parent")
        if (self.path.exists() or self.path.is_symlink()) and not _owner_private_file(
            self.path
        ):
            raise CommissioningControllerError("unsafe_effect_store_file")
        try:
            with self._connect() as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS commissioning_metadata(
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS commissioning_effects(
                        effect_key TEXT PRIMARY KEY,
                        kind TEXT NOT NULL,
                        request_digest TEXT NOT NULL,
                        request_json TEXT NOT NULL,
                        status TEXT NOT NULL,
                        result_json TEXT,
                        receipt_ref_json TEXT
                    );
                    CREATE TABLE IF NOT EXISTS protected_pull_requests(
                        effect_key TEXT PRIMARY KEY,
                        role TEXT NOT NULL,
                        promotion_id TEXT NOT NULL UNIQUE,
                        number INTEGER NOT NULL UNIQUE,
                        base_branch TEXT NOT NULL,
                        head_branch TEXT NOT NULL,
                        head_commit TEXT NOT NULL,
                        head_tree TEXT NOT NULL,
                        state TEXT NOT NULL,
                        merge_commit TEXT,
                        merge_tree TEXT
                    );
                    CREATE TABLE IF NOT EXISTS effect_recoveries(
                        recovery_id TEXT PRIMARY KEY,
                        effect_key TEXT NOT NULL,
                        boundary TEXT NOT NULL,
                        observed_commit TEXT NOT NULL,
                        occurred_at TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS controller_invocations(
                        ordinal INTEGER PRIMARY KEY AUTOINCREMENT,
                        effect_key TEXT NOT NULL,
                        action TEXT NOT NULL,
                        observed_commit TEXT NOT NULL,
                        occurred_at TEXT NOT NULL,
                        receipt_digest TEXT
                    );
                    """
                )
                row = connection.execute(
                    "SELECT value FROM commissioning_metadata WHERE key = 'schema_version'"
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO commissioning_metadata(key, value) "
                        "VALUES('schema_version', '1')"
                    )
                elif row[0] != "1":
                    raise CommissioningControllerError("unsupported_effect_store_schema")
        except CommissioningControllerError:
            raise
        except sqlite3.Error as error:
            raise CommissioningControllerError("effect_store_unavailable") from error
        if os.name != "nt":
            self.path.chmod(0o600)
        if not _owner_private_file(self.path):
            raise CommissioningControllerError("unsafe_effect_store_file")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def begin(self, request: EffectRequest) -> str:
        encoded = canonical_json_bytes(request.to_canonical_dict()).decode("utf-8")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT request_digest, request_json, status FROM commissioning_effects "
                "WHERE effect_key = ?",
                (request.effect_key,),
            ).fetchone()
            if row is not None:
                if row["request_digest"] != request.digest or row["request_json"] != encoded:
                    raise CommissioningControllerError("effect_request_conflict")
                connection.commit()
                return str(row["status"])
            connection.execute(
                "INSERT INTO commissioning_effects"
                "(effect_key, kind, request_digest, request_json, status) "
                "VALUES(?, ?, ?, ?, 'pending')",
                (request.effect_key, request.kind, request.digest, encoded),
            )
            if request.pr is not None:
                pr = request.pr
                connection.execute(
                    "INSERT INTO protected_pull_requests("
                    "effect_key, role, promotion_id, number, base_branch, head_branch, "
                    "head_commit, head_tree, state) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'OPEN')",
                    (
                        request.effect_key,
                        pr.role,
                        pr.promotion_id,
                        pr.number,
                        pr.base_branch,
                        pr.head_branch,
                        pr.head_commit,
                        pr.head_tree,
                    ),
                )
            connection.commit()
        return "pending"

    def mark_applied(self, request: EffectRequest, result: dict[str, Any]) -> None:
        encoded = canonical_json_bytes(result).decode("utf-8")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status, result_json FROM commissioning_effects WHERE effect_key = ?",
                (request.effect_key,),
            ).fetchone()
            if row is None:
                raise CommissioningControllerError("effect_not_found")
            if row["status"] in {"applied", "receipted"}:
                if row["result_json"] != encoded:
                    raise CommissioningControllerError("effect_result_conflict")
                connection.commit()
                return
            if row["status"] != "pending":
                raise CommissioningControllerError("effect_state_invalid")
            connection.execute(
                "UPDATE commissioning_effects SET status = 'applied', result_json = ? "
                "WHERE effect_key = ? AND status = 'pending'",
                (encoded, request.effect_key),
            )
            if request.pr is not None:
                connection.execute(
                    "UPDATE protected_pull_requests SET state = 'MERGED', merge_commit = ?, "
                    "merge_tree = ? WHERE effect_key = ? AND state = 'OPEN'",
                    (request.target_commit, request.target_tree, request.effect_key),
                )
            connection.commit()

    def record_recovery(self, request: EffectRequest, observed_commit: str) -> None:
        recovery_id = hashlib.sha256(
            canonical_json_bytes(
                {
                    "boundary": "effect_without_receipt",
                    "effect_key": request.effect_key,
                    "observed_commit": observed_commit,
                }
            )
        ).hexdigest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR IGNORE INTO effect_recoveries("
                "recovery_id, effect_key, boundary, observed_commit, occurred_at) "
                "VALUES(?, ?, 'effect_without_receipt', ?, ?)",
                (recovery_id, request.effect_key, observed_commit, request.occurred_at),
            )
            connection.commit()

    def attach_receipt(self, request: EffectRequest, ref: ArtifactRef) -> None:
        encoded = canonical_json_bytes(ref.to_canonical_dict()).decode("utf-8")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status, receipt_ref_json FROM commissioning_effects WHERE effect_key = ?",
                (request.effect_key,),
            ).fetchone()
            if row is None:
                raise CommissioningControllerError("effect_not_found")
            if row["status"] == "receipted":
                if row["receipt_ref_json"] != encoded:
                    raise CommissioningControllerError("effect_receipt_conflict")
                connection.commit()
                return
            if row["status"] != "applied":
                raise CommissioningControllerError("effect_not_applied")
            connection.execute(
                "UPDATE commissioning_effects SET status = 'receipted', receipt_ref_json = ? "
                "WHERE effect_key = ? AND status = 'applied'",
                (encoded, request.effect_key),
            )
            connection.commit()

    def record_invocation(
        self,
        *,
        request: EffectRequest,
        action: str,
        observed_commit: str,
        receipt_digest: str | None,
    ) -> None:
        _key(action, "invalid_controller_action")
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO controller_invocations("
                "effect_key, action, observed_commit, occurred_at, receipt_digest) "
                "VALUES(?, ?, ?, ?, ?)",
                (
                    request.effect_key,
                    action,
                    observed_commit,
                    request.occurred_at,
                    receipt_digest,
                ),
            )

    def inspect(self, effect_key: str) -> dict[str, Any]:
        _key(effect_key, "invalid_effect_key")
        with self._connect() as connection:
            effect = connection.execute(
                "SELECT status, result_json, receipt_ref_json FROM commissioning_effects "
                "WHERE effect_key = ?",
                (effect_key,),
            ).fetchone()
            if effect is None:
                raise CommissioningControllerError("effect_not_found")
            recoveries = connection.execute(
                "SELECT recovery_id, boundary, observed_commit, occurred_at "
                "FROM effect_recoveries WHERE effect_key = ? ORDER BY recovery_id",
                (effect_key,),
            ).fetchall()
            invocations = connection.execute(
                "SELECT action, observed_commit, occurred_at, receipt_digest "
                "FROM controller_invocations WHERE effect_key = ? ORDER BY ordinal",
                (effect_key,),
            ).fetchall()
            pr = connection.execute(
                "SELECT effect_key, role, promotion_id, number, base_branch, head_branch, "
                "head_commit, head_tree, state, merge_commit, merge_tree "
                "FROM protected_pull_requests WHERE effect_key = ?",
                (effect_key,),
            ).fetchone()
        return {
            "effect_key": effect_key,
            "invocations": [dict(row) for row in invocations],
            "pull_request": dict(pr) if pr is not None else None,
            "receipt_ref": (
                json.loads(effect["receipt_ref_json"])
                if effect["receipt_ref_json"] is not None
                else None
            ),
            "recoveries": [dict(row) for row in recoveries],
            "result": (
                json.loads(effect["result_json"])
                if effect["result_json"] is not None
                else None
            ),
            "status": effect["status"],
        }


def _git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ("git", *arguments),
            check=check,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CommissioningControllerError("commissioning_git_failed") from error


def _read_ref(bare_repository: Path, ref: str) -> str:
    completed = _git(
        "--git-dir",
        os.fspath(bare_repository),
        "rev-parse",
        "--verify",
        ref,
        check=False,
    )
    if completed.returncode != 0:
        return _ZERO_OBJECT
    value = completed.stdout.strip()
    return _object(value, "commissioning_ref_invalid")


def _import_target(request: EffectRequest, bare_repository: Path) -> None:
    _git(
        "--git-dir",
        os.fspath(bare_repository),
        "fetch",
        "--no-tags",
        request.source_repository,
        request.target_commit,
    )
    tree = _git(
        "--git-dir",
        os.fspath(bare_repository),
        "rev-parse",
        f"{request.target_commit}^{{tree}}",
    ).stdout.strip()
    if tree != request.target_tree:
        raise CommissioningControllerError("commissioning_target_tree_mismatch")


def _apply_effect(request: EffectRequest, bare_repository: Path) -> str:
    observed = _read_ref(bare_repository, request.ref)
    if observed == request.target_commit:
        return observed
    if observed != request.expected_old_commit:
        raise CommissioningControllerError("commissioning_ref_precondition_failed")
    _import_target(request, bare_repository)
    _git(
        "--git-dir",
        os.fspath(bare_repository),
        "update-ref",
        request.ref,
        request.target_commit,
        request.expected_old_commit,
    )
    observed = _read_ref(bare_repository, request.ref)
    if observed != request.target_commit:
        raise CommissioningControllerError("commissioning_effect_not_observed")
    return observed


def _sign_receipt(
    *,
    request: EffectRequest,
    observed_commit: str,
    recovered: bool,
    signing_key: Path,
    key_id: str,
    artifacts: PrivateArtifactStore,
) -> ArtifactRef:
    if not _owner_private_file(signing_key):
        raise CommissioningControllerError("unsafe_controller_signing_key")
    try:
        private_key = serialization.load_pem_private_key(
            signing_key.read_bytes(),
            password=None,
        )
    except (OSError, TypeError, ValueError) as error:
        raise CommissioningControllerError("invalid_controller_signing_key") from error
    if not isinstance(private_key, Ed25519PrivateKey):
        raise CommissioningControllerError("invalid_controller_signing_key")
    payload = {
        "effect_key": request.effect_key,
        "kind": request.kind,
        "observed_commit": observed_commit,
        "occurred_at": request.occurred_at,
        "recovered": recovered,
        "ref": request.ref,
        "request_digest": request.digest,
        "schema_version": 1,
        "target_tree": request.target_tree,
    }
    encoded = canonical_json_bytes(payload)
    envelope = {
        "key_id": _key(key_id, "invalid_controller_key_id"),
        "payload": payload,
        "signature_base64": base64.b64encode(private_key.sign(encoded)).decode("ascii"),
    }
    return artifacts.put(
        evidence_kind="commissioning_effect_receipt",
        media_type="application/json",
        content=canonical_json_bytes(envelope),
    )


def verify_effect_receipt(
    *,
    artifact_store_path: Path,
    repository_root: Path,
    receipt_ref_path: Path,
    public_key_path: Path,
    request_path: Path,
) -> dict[str, Any]:
    for path, code in (
        (receipt_ref_path, "unsafe_effect_receipt_ref"),
        (public_key_path, "unsafe_controller_public_key"),
        (request_path, "unsafe_effect_request_file"),
    ):
        if not _owner_private_file(path):
            raise CommissioningControllerError(code)
    try:
        ref = ArtifactRef.from_canonical_dict(
            json.loads(receipt_ref_path.read_text(encoding="utf-8"))
        )
        request = EffectRequest.from_canonical_dict(
            json.loads(request_path.read_text(encoding="utf-8"))
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise CommissioningControllerError("invalid_effect_receipt_input") from error
    if (
        ref.evidence_kind != "commissioning_effect_receipt"
        or ref.media_type != "application/json"
    ):
        raise CommissioningControllerError("invalid_effect_receipt_ref")
    root = Path(_local_directory(os.fspath(repository_root), "invalid_repository_root"))
    artifacts = PrivateArtifactStore(artifact_store_path, root)
    try:
        envelope = json.loads(artifacts.read(ref))
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise CommissioningControllerError("invalid_effect_receipt") from error
    if not isinstance(envelope, dict) or set(envelope) != {
        "key_id",
        "payload",
        "signature_base64",
    }:
        raise CommissioningControllerError("invalid_effect_receipt")
    _key(envelope["key_id"], "invalid_controller_key_id")
    payload = envelope["payload"]
    expected_payload_keys = {
        "effect_key",
        "kind",
        "observed_commit",
        "occurred_at",
        "recovered",
        "ref",
        "request_digest",
        "schema_version",
        "target_tree",
    }
    if not isinstance(payload, dict) or set(payload) != expected_payload_keys:
        raise CommissioningControllerError("invalid_effect_receipt")
    expected_bindings = {
        "effect_key": request.effect_key,
        "kind": request.kind,
        "observed_commit": request.target_commit,
        "occurred_at": request.occurred_at,
        "ref": request.ref,
        "request_digest": request.digest,
        "schema_version": 1,
        "target_tree": request.target_tree,
    }
    if any(payload.get(name) != value for name, value in expected_bindings.items()):
        raise CommissioningControllerError("effect_receipt_binding_mismatch")
    if not isinstance(payload["recovered"], bool):
        raise CommissioningControllerError("invalid_effect_receipt")
    try:
        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
        signature = base64.b64decode(envelope["signature_base64"], validate=True)
    except (OSError, TypeError, ValueError) as error:
        raise CommissioningControllerError("invalid_effect_receipt_signature") from error
    if not isinstance(public_key, Ed25519PublicKey):
        raise CommissioningControllerError("invalid_controller_public_key")
    try:
        public_key.verify(signature, canonical_json_bytes(payload))
    except InvalidSignature as error:
        raise CommissioningControllerError("effect_receipt_signature_invalid") from error
    return {
        "action": "verified_effect_receipt",
        "effect_key": request.effect_key,
        "receipt_digest": ref.digest,
        "recovered": payload["recovered"],
    }


def run_controller(
    *,
    effect_store_path: Path,
    artifact_store_path: Path,
    repository_root: Path,
    bare_repository: Path,
    request_path: Path,
    signing_key: Path,
    key_id: str,
    pause_after_effect: Path | None,
) -> dict[str, Any]:
    if not _owner_private_file(request_path):
        raise CommissioningControllerError("unsafe_effect_request_file")
    try:
        value = json.loads(request_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CommissioningControllerError("invalid_effect_request") from error
    request = EffectRequest.from_canonical_dict(value)
    bare = Path(_local_directory(os.fspath(bare_repository), "invalid_bare_repository"))
    source_root = Path(_local_directory(os.fspath(repository_root), "invalid_repository_root"))
    store = CommissioningEffectStore(effect_store_path)
    artifacts = PrivateArtifactStore(artifact_store_path, source_root)
    initial_status = store.begin(request)

    observed = _read_ref(bare, request.ref)
    if initial_status == "receipted":
        if observed != request.target_commit:
            raise CommissioningControllerError("receipted_effect_identity_mismatch")
        record = store.inspect(request.effect_key)
        receipt_ref = record["receipt_ref"]
        assert isinstance(receipt_ref, dict)
        store.record_invocation(
            request=request,
            action="already_receipted",
            observed_commit=observed,
            receipt_digest=str(receipt_ref["digest"]),
        )
        return {
            "action": "already_receipted",
            "effect_key": request.effect_key,
            "receipt_ref": receipt_ref,
        }

    recovered = initial_status == "applied" or (
        initial_status == "pending" and observed == request.target_commit
    )
    observed = _apply_effect(request, bare)
    result = {
        "observed_commit": observed,
        "ref": request.ref,
        "target_tree": request.target_tree,
    }
    store.mark_applied(request, result)
    if recovered:
        store.record_recovery(request, observed)
    else:
        store.record_invocation(
            request=request,
            action="effect_applied",
            observed_commit=observed,
            receipt_digest=None,
        )
        if pause_after_effect is not None:
            marker_parent = pause_after_effect.parent
            if not _owner_private_directory(marker_parent):
                raise CommissioningControllerError("unsafe_pause_marker_parent")
            pause_after_effect.write_bytes(
                canonical_json_bytes(
                    {
                        "effect_key": request.effect_key,
                        "observed_commit": observed,
                        "schema_version": 1,
                    }
                )
            )
            if os.name != "nt":
                pause_after_effect.chmod(0o600)
            signal.pause()

    receipt_ref = _sign_receipt(
        request=request,
        observed_commit=observed,
        recovered=recovered,
        signing_key=signing_key,
        key_id=key_id,
        artifacts=artifacts,
    )
    store.attach_receipt(request, receipt_ref)
    action = "recovered_effect_receipt" if recovered else "effect_receipted"
    store.record_invocation(
        request=request,
        action=action,
        observed_commit=observed,
        receipt_digest=receipt_ref.digest,
    )
    return {
        "action": action,
        "effect_key": request.effect_key,
        "receipt_ref": receipt_ref.to_canonical_dict(),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="carl-commissioning-controller")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--effect-store", required=True, type=Path)
    run.add_argument("--artifact-store", required=True, type=Path)
    run.add_argument("--repository-root", required=True, type=Path)
    run.add_argument("--bare-repository", required=True, type=Path)
    run.add_argument("--request", required=True, type=Path)
    run.add_argument("--signing-key", required=True, type=Path)
    run.add_argument("--key-id", required=True)
    run.add_argument("--pause-after-effect", type=Path)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--effect-store", required=True, type=Path)
    inspect.add_argument("--effect-key", required=True)
    verify = commands.add_parser("verify-receipt")
    verify.add_argument("--artifact-store", required=True, type=Path)
    verify.add_argument("--repository-root", required=True, type=Path)
    verify.add_argument("--receipt-ref", required=True, type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    verify.add_argument("--request", required=True, type=Path)
    return parser


def main(arguments: list[str] | None = None) -> int:
    values = _parser().parse_args(arguments)
    try:
        if values.command == "inspect":
            result = CommissioningEffectStore(values.effect_store).inspect(values.effect_key)
        elif values.command == "verify-receipt":
            result = verify_effect_receipt(
                artifact_store_path=values.artifact_store,
                repository_root=values.repository_root,
                receipt_ref_path=values.receipt_ref,
                public_key_path=values.public_key,
                request_path=values.request,
            )
        else:
            result = run_controller(
                effect_store_path=values.effect_store,
                artifact_store_path=values.artifact_store,
                repository_root=values.repository_root,
                bare_repository=values.bare_repository,
                request_path=values.request,
                signing_key=values.signing_key,
                key_id=values.key_id,
                pause_after_effect=values.pause_after_effect,
            )
    except CommissioningControllerError as error:
        sys.stderr.write(
            canonical_json_bytes({"error": error.code, "schema_version": 1}).decode("utf-8")
            + "\n"
        )
        return 2
    sys.stdout.write(canonical_json_bytes(result).decode("utf-8") + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through subprocess tests
    raise SystemExit(main())
