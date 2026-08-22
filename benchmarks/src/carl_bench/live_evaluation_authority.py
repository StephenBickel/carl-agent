"""Archive-backed protected authority for deterministic/live capability joining."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_harness import (
    CloudHarnessResult,
    _is_executed_cloud_harness_result,
    evaluate_carl_pair,
)
from carl_bench.live_capability import (
    LiveEvaluationIdentity,
    LivePairPolicy,
    LiveTaskIdentity,
    LiveTrialEvidence,
    ProtectedLivePair,
)
from carl_bench.openai_gateway import (
    OpenAIGatewayError,
    OpenAIModelGateway,
    ProtectedOpenAIModelResult,
)
from carl_bench.run_attestation import attest_bound_payload, verify_bound_payload_attestation

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+=-]{0,255}$")
_OBJECT_KEY = re.compile(r"^carl-evidence/v1/sha256/[0-9a-f]{2}/[0-9a-f]{64}$")
_REASON = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_DETERMINISTIC = "protected_deterministic_pair"
_LIVE = "protected_live_pair"
_RESULT_PURPOSE = "protected-combined-capability"
_GRADER_PURPOSE = "protected-live-grader-outcome"
_MAX_BYTES = 8_388_608
_LIFETIME = timedelta(hours=6)


class LiveEvaluationAuthorityError(ValueError):
    """Stable redacted protected-authority failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _require_digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise LiveEvaluationAuthorityError(code)
    return value


def _timestamp(value: datetime, code: str = "live_authority_clock_invalid") -> str:
    if not isinstance(value, datetime) or value.tzinfo != UTC:
        raise LiveEvaluationAuthorityError(code)
    return value.isoformat().replace("+00:00", "Z")


def _parse_time(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LiveEvaluationAuthorityError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise LiveEvaluationAuthorityError(code) from error
    if parsed.tzinfo != UTC or _timestamp(parsed, code) != value:
        raise LiveEvaluationAuthorityError(code)
    return parsed


def _strict_document(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= _MAX_BYTES:
        raise LiveEvaluationAuthorityError("live_authority_evidence_invalid")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate")
            value[key] = item
        return value

    try:
        value = json.loads(payload, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise LiveEvaluationAuthorityError("live_authority_evidence_invalid") from error
    if type(value) is not dict or canonical_json_bytes(value) != payload:
        raise LiveEvaluationAuthorityError("live_authority_evidence_invalid")
    return value


def _wire_identity(value: object) -> LiveEvaluationIdentity:
    if type(value) is not dict:
        raise LiveEvaluationAuthorityError("live_authority_identity_invalid")
    fields = dict(value)
    if type(fields.get("task_order")) is not list or type(fields.get("seeds")) is not list:
        raise LiveEvaluationAuthorityError("live_authority_identity_invalid")
    fields["task_order"] = tuple(fields["task_order"])
    fields["seeds"] = tuple(fields["seeds"])
    try:
        return LiveEvaluationIdentity.create(**fields)
    except (TypeError, ValueError) as error:
        raise LiveEvaluationAuthorityError("live_authority_identity_invalid") from error


def _reasons(value: object, code: str) -> tuple[str, ...]:
    if (
        type(value) is not list
        or value != sorted(set(value))
        or any(not isinstance(item, str) or _REASON.fullmatch(item) is None for item in value)
    ):
        raise LiveEvaluationAuthorityError(code)
    return tuple(value)


@dataclass(frozen=True, slots=True)
class ProtectedEvidenceLocator:
    kind: str
    object_key: str
    version_id: str
    payload_digest: str

    def __post_init__(self) -> None:
        digest = _require_digest(self.payload_digest, "live_authority_locator_invalid")
        if (
            self.kind not in {_DETERMINISTIC, _LIVE}
            or not isinstance(self.object_key, str)
            or _OBJECT_KEY.fullmatch(self.object_key) is None
            or self.object_key != f"carl-evidence/v1/sha256/{digest[:2]}/{digest}"
            or not isinstance(self.version_id, str)
            or _VERSION.fullmatch(self.version_id) is None
        ):
            raise LiveEvaluationAuthorityError("live_authority_locator_invalid")

    def to_canonical_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "object_key": self.object_key,
            "payload_digest": self.payload_digest,
            "version_id": self.version_id,
        }


@dataclass(frozen=True, slots=True)
class ProtectedArchiveVersion:
    object_key: str
    version_id: str
    payload: bytes
    checksum_sha256: str
    byte_length: int
    retention_mode: str
    retain_until: str
    created_at: str


class ProtectedArchiveReader(Protocol):
    def read_exact(self, object_key: str, version_id: str) -> ProtectedArchiveVersion: ...


class ProtectedLiveGrader(Protocol):
    def grade(self, *, identity: object, task: object, result: object) -> int: ...


@dataclass(frozen=True, slots=True, init=False)
class DeterministicRunLease:
    request_digest: str
    checkout_digest: str
    _token: str = field(repr=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise LiveEvaluationAuthorityError("deterministic_run_lease_invalid")

    @classmethod
    def _mint(
        cls, *, request_digest: str, checkout_digest: str, token: str
    ) -> DeterministicRunLease:
        value = object.__new__(cls)
        object.__setattr__(value, "request_digest", request_digest)
        object.__setattr__(value, "checkout_digest", checkout_digest)
        object.__setattr__(value, "_token", token)
        return value


@dataclass(slots=True)
class _DeterministicRunState:
    identity: LiveEvaluationIdentity
    parent_checkout: Path
    candidate_checkout: Path
    parent_binary: Path
    candidate_binary: Path
    snapshot: dict[str, Any]
    checkout_digest: str
    started: bool = False
    result: CloudHarnessResult | None = None
    result_digest: str | None = None
    consumed: bool = False


@dataclass(frozen=True, slots=True)
class ProtectedCombinedCapabilityReceipt:
    schema_version: int
    request_digest: str
    identity: LiveEvaluationIdentity
    deterministic_locator: ProtectedEvidenceLocator
    live_locator: ProtectedEvidenceLocator
    eligible: bool
    disposition: str
    reasons: tuple[str, ...]
    task_deltas: tuple[tuple[str, int], ...]
    issued_at: str
    key_id: str
    signature: str

    def unsigned_canonical_dict(self) -> dict[str, Any]:
        return {
            "deterministic_locator": self.deterministic_locator.to_canonical_dict(),
            "disposition": self.disposition,
            "eligible": self.eligible,
            "identity": self.identity.to_canonical_dict(),
            "issued_at": self.issued_at,
            "kind": "protected_combined_capability",
            "live_locator": self.live_locator.to_canonical_dict(),
            "reasons": list(self.reasons),
            "request_digest": self.request_digest,
            "schema_version": self.schema_version,
            "task_deltas": [
                {"delta_basis_points": delta, "task_id": task_id}
                for task_id, delta in self.task_deltas
            ],
        }

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            **self.unsigned_canonical_dict(),
            "key_id": self.key_id,
            "signature": self.signature,
        }


def _signed_bytes(*, kind: str, payload: dict[str, Any], key: bytes, now: datetime) -> bytes:
    issued_at = _timestamp(now)
    expires_at = _timestamp(now + _LIFETIME)
    unsigned = canonical_json_bytes(
        {
            "expires_at": expires_at,
            "issued_at": issued_at,
            "kind": kind,
            "payload": payload,
            "schema_version": 1,
        }
    )
    try:
        key_id, signature = attest_bound_payload(unsigned, purpose=kind, key=key)
    except ValueError as error:
        raise LiveEvaluationAuthorityError("live_authority_key_invalid") from error
    return canonical_json_bytes({**json.loads(unsigned), "key_id": key_id, "signature": signature})


def _model_digest(result: ProtectedOpenAIModelResult) -> str:
    usage = result.usage
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "latency_ms": result.latency_ms,
                "model": result.model,
                "output_digest": result.output_digest,
                "provenance_tag": result.provenance_tag,
                "request_digest": result.request_digest,
                "response_id": result.response_id,
                "status": result.status,
                "usage": {name: getattr(usage, name) for name in usage.__dataclass_fields__},
            }
        )
    ).hexdigest()


class ProtectedLiveEvaluationAuthority:
    """Own pinned keys, verifier policy, archive reads, clock, and result signing."""

    __slots__ = (
        "_archive",
        "_clock",
        "_det_key",
        "_deterministic_runs",
        "_gateway",
        "_grader",
        "_grader_key",
        "_live_key",
        "_result_key",
        "_worker_identities",
    )

    def __new__(cls, *args: object, **kwargs: object) -> ProtectedLiveEvaluationAuthority:
        del cls, args, kwargs
        raise LiveEvaluationAuthorityError("live_authority_protected_construction_required")

    @staticmethod
    def _environment_key(name: str) -> bytes:
        encoded = os.environ.get(name)
        if not isinstance(encoded, str):
            raise LiveEvaluationAuthorityError("live_acp_credential_missing")
        try:
            key = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise LiveEvaluationAuthorityError("live_authority_key_invalid") from None
        if len(key) != 32 or base64.b64encode(key).decode() != encoded:
            raise LiveEvaluationAuthorityError("live_authority_key_invalid")
        return key

    @staticmethod
    def _environment_worker_identity(prefix: str) -> tuple[int, int]:
        uid_text = os.environ.get(f"CARL_{prefix}_WORKER_UID")
        gid_text = os.environ.get(f"CARL_{prefix}_WORKER_GID")
        if (
            not isinstance(uid_text, str)
            or not isinstance(gid_text, str)
            or not uid_text.isdecimal()
            or not gid_text.isdecimal()
            or str(int(uid_text)) != uid_text
            or str(int(gid_text)) != gid_text
        ):
            raise LiveEvaluationAuthorityError("live_worker_identity_missing")
        uid, gid = int(uid_text), int(gid_text)
        if not 1 <= uid <= 2_147_483_647 or not 1 <= gid <= 2_147_483_647:
            raise LiveEvaluationAuthorityError("live_worker_identity_invalid")
        return uid, gid

    @classmethod
    def from_protected_process(cls) -> ProtectedLiveEvaluationAuthority:
        """Construct every production dependency from fixed protected-process policy."""
        from carl_bench.live_archive_client import ProtectedArchiveSocketReader
        from carl_bench.live_grader import ProtectedGraderBundle

        try:
            gateway = OpenAIModelGateway.from_protected_environment()
        except OpenAIGatewayError as error:
            if error.code in {
                "openai_credentials_missing",
                "openai_provenance_key_missing",
            }:
                raise LiveEvaluationAuthorityError("live_acp_credential_missing") from error
            raise LiveEvaluationAuthorityError("live_gateway_unavailable") from error
        worker_identities = (
            cls._environment_worker_identity("PARENT"),
            cls._environment_worker_identity("CANDIDATE"),
        )
        if worker_identities[0][0] == worker_identities[1][0] or os.geteuid() in {
            worker_identities[0][0],
            worker_identities[1][0],
        }:
            raise LiveEvaluationAuthorityError("live_worker_identity_invalid")
        return cls._construct(
            archive=ProtectedArchiveSocketReader.from_protected_environment(),
            gateway=gateway,
            grader=ProtectedGraderBundle.from_protected_process(),
            clock=lambda: datetime.now(UTC),
            deterministic_key=cls._environment_key("CARL_DETERMINISTIC_ATTESTATION_KEY_B64"),
            live_key=cls._environment_key("CARL_LIVE_ATTESTATION_KEY_B64"),
            result_key=cls._environment_key("CARL_COMBINED_EVIDENCE_KEY_B64"),
            grader_key=cls._environment_key("CARL_GRADER_ATTESTATION_KEY_B64"),
            worker_identities=worker_identities,
        )

    @classmethod
    def _for_testing(
        cls,
        *,
        archive: ProtectedArchiveReader,
        gateway: object,
        grader: object | None = None,
        clock: Callable[[], datetime],
        deterministic_key: bytes,
        live_key: bytes,
        result_key: bytes,
        grader_key: bytes | None = None,
        worker_identities: tuple[tuple[int, int], tuple[int, int]] | None = None,
    ) -> ProtectedLiveEvaluationAuthority:
        if (
            not callable(getattr(archive, "read_exact", None))
            or not callable(getattr(gateway, "protected_execution_policy", None))
            or not callable(getattr(gateway, "verify_protected_result", None))
            or not callable(clock)
        ):
            raise LiveEvaluationAuthorityError("live_authority_test_configuration_invalid")
        return cls._construct(
            archive=archive,
            gateway=gateway,
            grader=grader,
            clock=clock,
            deterministic_key=deterministic_key,
            live_key=live_key,
            result_key=result_key,
            grader_key=grader_key,
            worker_identities=worker_identities,
        )

    @classmethod
    def _construct(
        cls,
        *,
        archive: ProtectedArchiveReader,
        gateway: object,
        grader: object | None,
        clock: Callable[[], datetime],
        deterministic_key: bytes,
        live_key: bytes,
        result_key: bytes,
        grader_key: bytes | None,
        worker_identities: tuple[tuple[int, int], tuple[int, int]] | None,
    ) -> ProtectedLiveEvaluationAuthority:
        if worker_identities is not None and worker_identities[0][0] == worker_identities[1][0]:
            raise LiveEvaluationAuthorityError("live_worker_identity_invalid")
        if (grader is None) != (grader_key is None) or (
            grader is not None and not callable(getattr(grader, "grade", None))
        ):
            raise LiveEvaluationAuthorityError("live_authority_grader_invalid")
        for key in (deterministic_key, live_key, result_key):
            try:
                attest_bound_payload(b"key-check", purpose="key-check", key=key)
            except ValueError as error:
                raise LiveEvaluationAuthorityError("live_authority_key_invalid") from error
        if grader_key is not None:
            try:
                attest_bound_payload(b"key-check", purpose="key-check", key=grader_key)
            except ValueError as error:
                raise LiveEvaluationAuthorityError("live_authority_key_invalid") from error
        value = object.__new__(cls)
        value._archive = archive
        value._gateway = gateway
        value._grader = grader
        value._grader_key = grader_key
        value._clock = clock
        value._det_key = deterministic_key
        value._live_key = live_key
        value._result_key = result_key
        value._worker_identities = worker_identities
        value._deterministic_runs: dict[str, _DeterministicRunState] = {}
        return value

    def _now(self) -> datetime:
        now = self._clock()
        _timestamp(now)
        return now

    @staticmethod
    def _deterministic_payload(
        *,
        identity: LiveEvaluationIdentity,
        contract_eligible: bool,
        contract_reasons: tuple[str, ...],
        harness_digest: str,
        parent_binary_digest: str,
        candidate_binary_digest: str,
        observation_digests: list[str],
        checkout_attestation_digest: str,
    ) -> dict[str, Any]:
        immutable = {
            "experiment": identity.experiment_digest,
            "metric_pack": identity.metric_pack_digest,
            "policy": identity.policy_digest,
            "task_set": identity.task_set_digest,
        }
        manifest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "environment_digest": identity.environment_digest,
                    "harness_result_digest": harness_digest,
                    "checkout_attestation_digest": checkout_attestation_digest,
                    "identity": identity.to_canonical_dict(),
                    "immutable_inputs": immutable,
                }
            )
        ).hexdigest()
        return {
            "candidate_binary_digest": candidate_binary_digest,
            "candidate_tree": identity.candidate_tree,
            "checkout_attestation_digest": checkout_attestation_digest,
            "contract_eligible": contract_eligible,
            "contract_reasons": list(contract_reasons),
            "execution_manifest_digest": manifest,
            "harness_result_digest": harness_digest,
            "identity": identity.to_canonical_dict(),
            "immutable_inputs": immutable,
            "observation_digests": observation_digests,
            "parent_binary_digest": parent_binary_digest,
            "parent_tree": identity.parent_tree,
        }

    @staticmethod
    def _git(checkout: Path, *arguments: str) -> bytes:
        try:
            completed = subprocess.run(
                ("git", "-C", os.fspath(checkout), *arguments),
                check=False,
                capture_output=True,
                env={"LANG": "C", "LC_ALL": "C", "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise LiveEvaluationAuthorityError("deterministic_checkout_invalid") from error
        if completed.returncode != 0 or completed.stderr:
            raise LiveEvaluationAuthorityError("deterministic_checkout_invalid")
        return completed.stdout

    @staticmethod
    def _binary_snapshot(binary: Path, checkout: Path) -> dict[str, int | str]:
        try:
            relative = binary.relative_to(checkout)
            before = binary.lstat()
        except (OSError, ValueError) as error:
            raise LiveEvaluationAuthorityError("deterministic_checkout_invalid") from error
        if (
            str(relative) in {"", ".", ".."}
            or ".." in relative.parts
            or not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or not before.st_mode & stat.S_IXUSR
        ):
            raise LiveEvaluationAuthorityError("deterministic_checkout_invalid")
        digest = hashlib.sha256()
        try:
            with binary.open("rb") as source:
                while chunk := source.read(65_536):
                    digest.update(chunk)
            after = binary.lstat()
        except OSError as error:
            raise LiveEvaluationAuthorityError("deterministic_checkout_invalid") from error
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mode,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mode,
            after.st_mtime_ns,
        ):
            raise LiveEvaluationAuthorityError("deterministic_checkout_invalid")
        return {
            "device": before.st_dev,
            "digest": digest.hexdigest(),
            "inode": before.st_ino,
            "mode": before.st_mode,
            "size": before.st_size,
        }

    @classmethod
    def _checkout_snapshot(
        cls,
        *,
        checkout: Path,
        binary: Path,
        expected_commit: str,
        expected_tree: str,
    ) -> dict[str, Any]:
        if (
            not isinstance(checkout, Path)
            or not checkout.is_absolute()
            or checkout.is_symlink()
            or not checkout.is_dir()
            or not isinstance(binary, Path)
            or not binary.is_absolute()
        ):
            raise LiveEvaluationAuthorityError("deterministic_checkout_invalid")
        try:
            root_before = checkout.lstat()
        except OSError as error:
            raise LiveEvaluationAuthorityError("deterministic_checkout_invalid") from error
        root = os.fsdecode(cls._git(checkout, "rev-parse", "--show-toplevel")).strip()
        commit = os.fsdecode(cls._git(checkout, "rev-parse", "--verify", "HEAD^{commit}")).strip()
        tree = os.fsdecode(cls._git(checkout, "rev-parse", "--verify", "HEAD^{tree}")).strip()
        status = cls._git(checkout, "status", "--porcelain=v1", "-z", "--untracked-files=all")
        binary_snapshot = cls._binary_snapshot(binary, checkout)
        try:
            root_after = checkout.lstat()
        except OSError as error:
            raise LiveEvaluationAuthorityError("deterministic_checkout_invalid") from error
        if (
            root != os.fspath(checkout)
            or status
            or commit != expected_commit
            or tree != expected_tree
            or (
                root_before.st_dev,
                root_before.st_ino,
                root_before.st_mode,
                root_before.st_mtime_ns,
            )
            != (
                root_after.st_dev,
                root_after.st_ino,
                root_after.st_mode,
                root_after.st_mtime_ns,
            )
        ):
            raise LiveEvaluationAuthorityError("deterministic_checkout_invalid")
        return {
            "binary": binary_snapshot,
            "commit": commit,
            "device": root_before.st_dev,
            "inode": root_before.st_ino,
            "mode": root_before.st_mode,
            "tree": tree,
        }

    def begin_deterministic_run(
        self,
        *,
        identity: LiveEvaluationIdentity,
        parent_checkout: Path,
        candidate_checkout: Path,
        parent_binary: Path,
        candidate_binary: Path,
    ) -> DeterministicRunLease:
        if not isinstance(identity, LiveEvaluationIdentity):
            raise LiveEvaluationAuthorityError("deterministic_run_lease_invalid")
        try:
            parent_identity = parent_checkout.stat()
            candidate_identity = candidate_checkout.stat()
        except OSError as error:
            raise LiveEvaluationAuthorityError("deterministic_checkout_invalid") from error
        if (parent_identity.st_dev, parent_identity.st_ino) == (
            candidate_identity.st_dev,
            candidate_identity.st_ino,
        ):
            raise LiveEvaluationAuthorityError("deterministic_checkout_isolation_invalid")
        snapshot = {
            "candidate": self._checkout_snapshot(
                checkout=candidate_checkout,
                binary=candidate_binary,
                expected_commit=identity.candidate_commit,
                expected_tree=identity.candidate_tree,
            ),
            "identity": identity.to_canonical_dict(),
            "parent": self._checkout_snapshot(
                checkout=parent_checkout,
                binary=parent_binary,
                expected_commit=identity.parent_commit,
                expected_tree=identity.parent_tree,
            ),
        }
        checkout_digest = hashlib.sha256(canonical_json_bytes(snapshot)).hexdigest()
        token = secrets.token_urlsafe(32)
        token_digest = hashlib.sha256(token.encode()).hexdigest()
        if token_digest in self._deterministic_runs:  # pragma: no cover - cryptographic collision
            raise LiveEvaluationAuthorityError("deterministic_run_lease_invalid")
        self._deterministic_runs[token_digest] = _DeterministicRunState(
            identity=identity,
            parent_checkout=parent_checkout,
            candidate_checkout=candidate_checkout,
            parent_binary=parent_binary,
            candidate_binary=candidate_binary,
            snapshot=snapshot,
            checkout_digest=checkout_digest,
        )
        return DeterministicRunLease._mint(
            request_digest=identity.request_digest,
            checkout_digest=checkout_digest,
            token=token,
        )

    def _deterministic_state(self, lease: DeterministicRunLease) -> _DeterministicRunState:
        if not isinstance(lease, DeterministicRunLease):
            raise LiveEvaluationAuthorityError("deterministic_run_lease_invalid")
        token_digest = hashlib.sha256(lease._token.encode()).hexdigest()
        run = self._deterministic_runs.get(token_digest)
        if (
            run is None
            or lease.request_digest != run.identity.request_digest
            or lease.checkout_digest != run.checkout_digest
        ):
            raise LiveEvaluationAuthorityError("deterministic_run_lease_invalid")
        return run

    def execute_deterministic_run(
        self,
        *,
        lease: DeterministicRunLease,
        experiment_path: Path,
        task_set_path: Path,
        metric_pack_path: Path,
        policy_path: Path,
    ) -> CloudHarnessResult:
        """Execute the exact pair once while the protected clean-checkout lease is active."""
        run = self._deterministic_state(lease)
        if run.consumed:
            raise LiveEvaluationAuthorityError("deterministic_run_lease_consumed")
        if run.started:
            raise LiveEvaluationAuthorityError("deterministic_run_lease_executed")
        before = {
            "candidate": self._checkout_snapshot(
                checkout=run.candidate_checkout,
                binary=run.candidate_binary,
                expected_commit=run.identity.candidate_commit,
                expected_tree=run.identity.candidate_tree,
            ),
            "identity": run.identity.to_canonical_dict(),
            "parent": self._checkout_snapshot(
                checkout=run.parent_checkout,
                binary=run.parent_binary,
                expected_commit=run.identity.parent_commit,
                expected_tree=run.identity.parent_tree,
            ),
        }
        if before != run.snapshot:
            raise LiveEvaluationAuthorityError("deterministic_checkout_changed")
        run.started = True
        result = evaluate_carl_pair(
            parent_binary=run.parent_binary,
            candidate_binary=run.candidate_binary,
            parent_commit=run.identity.parent_commit,
            candidate_commit=run.identity.candidate_commit,
            experiment_path=experiment_path,
            task_set_path=task_set_path,
            metric_pack_path=metric_pack_path,
            policy_path=policy_path,
            mode="improvement",
            parent_identity=(
                self._worker_identities[0] if self._worker_identities is not None else None
            ),
            candidate_identity=(
                self._worker_identities[1] if self._worker_identities is not None else None
            ),
            live_evaluation_identity=run.identity,
        )
        after = {
            "candidate": self._checkout_snapshot(
                checkout=run.candidate_checkout,
                binary=run.candidate_binary,
                expected_commit=run.identity.candidate_commit,
                expected_tree=run.identity.candidate_tree,
            ),
            "identity": run.identity.to_canonical_dict(),
            "parent": self._checkout_snapshot(
                checkout=run.parent_checkout,
                binary=run.parent_binary,
                expected_commit=run.identity.parent_commit,
                expected_tree=run.identity.parent_tree,
            ),
        }
        if after != run.snapshot:
            raise LiveEvaluationAuthorityError("deterministic_checkout_changed")
        run.result = result
        run.result_digest = hashlib.sha256(
            canonical_json_bytes(result.to_canonical_dict())
        ).hexdigest()
        return result

    def seal_deterministic_run(
        self, result: CloudHarnessResult, *, lease: DeterministicRunLease
    ) -> bytes:
        """Sign only an exact result minted by the real harness path in this process."""
        run = self._deterministic_state(lease)
        if run.consumed:
            raise LiveEvaluationAuthorityError("deterministic_run_lease_consumed")
        run.consumed = True
        if (
            not _is_executed_cloud_harness_result(result)
            or result is not run.result
            or not isinstance(result.live_evaluation_identity, LiveEvaluationIdentity)
            or result.live_evaluation_identity != run.identity
        ):
            raise LiveEvaluationAuthorityError("deterministic_evidence_unprotected")
        harness = canonical_json_bytes(result.to_canonical_dict())
        if hashlib.sha256(harness).hexdigest() != run.result_digest:
            raise LiveEvaluationAuthorityError("deterministic_evidence_unprotected")
        identity = result.live_evaluation_identity
        after = {
            "candidate": self._checkout_snapshot(
                checkout=run.candidate_checkout,
                binary=run.candidate_binary,
                expected_commit=identity.candidate_commit,
                expected_tree=identity.candidate_tree,
            ),
            "identity": identity.to_canonical_dict(),
            "parent": self._checkout_snapshot(
                checkout=run.parent_checkout,
                binary=run.parent_binary,
                expected_commit=identity.parent_commit,
                expected_tree=identity.parent_tree,
            ),
        }
        if after != run.snapshot:
            raise LiveEvaluationAuthorityError("deterministic_checkout_changed")
        observations = (*result.parent.observations, *result.candidate.observations)
        if (
            len(observations) != 2 * len(identity.task_order)
            or any(len(item.attempt_observations) != identity.attempts for item in observations)
            or result.parent.binary_digest != run.snapshot["parent"]["binary"]["digest"]
            or result.candidate.binary_digest != run.snapshot["candidate"]["binary"]["digest"]
        ):
            raise LiveEvaluationAuthorityError("deterministic_run_attestation_invalid")
        payload = self._deterministic_payload(
            identity=identity,
            contract_eligible=result.contract_eligible,
            contract_reasons=tuple(sorted(result.contract_reasons)),
            harness_digest=hashlib.sha256(harness).hexdigest(),
            parent_binary_digest=result.parent.binary_digest,
            candidate_binary_digest=result.candidate.binary_digest,
            observation_digests=[
                hashlib.sha256(canonical_json_bytes(item.to_canonical_dict())).hexdigest()
                for item in observations
            ],
            checkout_attestation_digest=run.checkout_digest,
        )
        return _signed_bytes(
            kind=_DETERMINISTIC, payload=payload, key=self._det_key, now=self._now()
        )

    def _seal_deterministic_summary_for_testing(
        self,
        *,
        identity: LiveEvaluationIdentity,
        contract_eligible: bool,
        contract_reasons: tuple[str, ...],
    ) -> bytes:
        harness = hashlib.sha256(
            canonical_json_bytes(
                {
                    "contract_eligible": contract_eligible,
                    "contract_reasons": list(contract_reasons),
                    "identity": identity.to_canonical_dict(),
                }
            )
        ).hexdigest()
        payload = self._deterministic_payload(
            identity=identity,
            contract_eligible=contract_eligible,
            contract_reasons=contract_reasons,
            harness_digest=harness,
            parent_binary_digest=hashlib.sha256(b"parent-binary").hexdigest(),
            candidate_binary_digest=hashlib.sha256(b"candidate-binary").hexdigest(),
            observation_digests=[
                hashlib.sha256(f"{subject}:{task}".encode()).hexdigest()
                for subject in ("parent", "candidate")
                for task in identity.task_order
            ],
            checkout_attestation_digest=hashlib.sha256(
                canonical_json_bytes({"identity": identity.to_canonical_dict(), "testing": True})
            ).hexdigest(),
        )
        return _signed_bytes(
            kind=_DETERMINISTIC, payload=payload, key=self._det_key, now=self._now()
        )

    def _grader_receipt(
        self,
        *,
        pair: ProtectedLivePair,
        trial: LiveTrialEvidence,
        model_result_digest: str,
    ) -> dict[str, Any]:
        if self._grader is None or self._grader_key is None:
            raise LiveEvaluationAuthorityError("live_grader_receipt_invalid")
        if trial.status == "valid":
            if type(trial.model_result) is not ProtectedOpenAIModelResult:
                raise LiveEvaluationAuthorityError("live_grader_receipt_invalid")
            try:
                protected_score = self._grader.grade(
                    identity=pair.identity,
                    task=trial.task,
                    result=trial.model_result,
                )
            except Exception as error:
                raise LiveEvaluationAuthorityError("live_grader_receipt_invalid") from error
            if (
                isinstance(protected_score, bool)
                or not isinstance(protected_score, int)
                or not 0 <= protected_score <= 10_000
                or protected_score != trial.score_basis_points
            ):
                raise LiveEvaluationAuthorityError("live_grader_receipt_invalid")
            model_request_digest: str | None = trial.model_result.request_digest
            model_output_digest: str | None = trial.model_result.output_digest
        else:
            protected_score = 0
            model_request_digest = None
            model_output_digest = None
        unsigned = {
            "attempt": trial.attempt,
            "attempt_identity": trial.attempt_identity,
            "domain": "carl.protected-live-grader-outcome.v1",
            "evaluation_request_digest": pair.identity.request_digest,
            "execution_context_digest": pair.identity.execution_context_digest(
                subject=trial.subject,
                task=trial.task,
                policy=pair.policy,
                seed=trial.seed,
                attempt=trial.attempt,
            ),
            "infrastructure_code": trial.infrastructure_code,
            "live_policy_digest": hashlib.sha256(
                canonical_json_bytes(pair.policy.to_canonical_dict())
            ).hexdigest(),
            "model_output_digest": model_output_digest,
            "model_request_digest": model_request_digest,
            "model_result_digest": model_result_digest,
            "schema_version": 1,
            "score_basis_points": protected_score,
            "seed": trial.seed,
            "status": trial.status,
            "subject": trial.subject,
            "subject_commit": trial.subject_commit,
            "subject_tree": (
                pair.identity.parent_tree
                if trial.subject == "parent"
                else pair.identity.candidate_tree
            ),
            "task": trial.task.to_canonical_dict(),
            "workflow_digest": pair.identity.workflow_digest,
            "workflow_revision": pair.identity.workflow_revision,
        }
        try:
            key_id, signature = attest_bound_payload(
                canonical_json_bytes(unsigned),
                purpose=_GRADER_PURPOSE,
                key=self._grader_key,
            )
        except ValueError as error:
            raise LiveEvaluationAuthorityError("live_grader_receipt_invalid") from error
        return {**unsigned, "key_id": key_id, "signature": signature}

    def seal_live_pair(self, pair: ProtectedLivePair) -> bytes:
        if not isinstance(pair, ProtectedLivePair):
            raise LiveEvaluationAuthorityError("live_evidence_invalid")
        try:
            rebuilt = ProtectedLivePair.create(
                identity=pair.identity,
                policy=pair.policy,
                tasks=pair.tasks,
                parent_trials=pair.parent_trials,
                candidate_trials=pair.candidate_trials,
                gateway=self._gateway,
            )
        except ValueError as error:
            raise LiveEvaluationAuthorityError("live_model_provenance_invalid") from error
        if rebuilt != pair:
            raise LiveEvaluationAuthorityError("live_evidence_mutated")
        contexts: list[str] = []
        results: list[str] = []
        grader_receipts: list[dict[str, Any]] = []
        for subject, trials in (
            ("parent", pair.parent_trials),
            ("candidate", pair.candidate_trials),
        ):
            for trial in trials:
                contexts.append(
                    pair.identity.execution_context_digest(
                        subject=subject,
                        task=trial.task,
                        policy=pair.policy,
                        seed=trial.seed,
                        attempt=trial.attempt,
                    )
                )
                if trial.status == "valid":
                    if type(trial.model_result) is not ProtectedOpenAIModelResult:
                        raise LiveEvaluationAuthorityError("live_model_provenance_invalid")
                    model_result_digest = _model_digest(trial.model_result)
                else:
                    model_result_digest = hashlib.sha256(
                        canonical_json_bytes(
                            {"code": trial.infrastructure_code, "status": trial.status}
                        )
                    ).hexdigest()
                results.append(model_result_digest)
                grader_receipts.append(
                    self._grader_receipt(
                        pair=pair,
                        trial=trial,
                        model_result_digest=model_result_digest,
                    )
                )
        payload = {
            "eligible": pair.eligible,
            "execution_context_digests": contexts,
            "grader_receipts": grader_receipts,
            "identity": pair.identity.to_canonical_dict(),
            "inconclusive": pair.inconclusive,
            "live_pair_digest": pair.digest,
            "model_result_digests": results,
            "policy": pair.policy.to_canonical_dict(),
            "reasons": list(pair.reasons),
            "task_deltas": [
                {"delta_basis_points": delta, "task_id": task_id}
                for task_id, delta in pair.task_deltas
            ],
            "tasks": [task.to_canonical_dict() for task in pair.tasks],
        }
        return _signed_bytes(kind=_LIVE, payload=payload, key=self._live_key, now=self._now())

    def _read(self, locator: ProtectedEvidenceLocator) -> tuple[dict[str, Any], datetime]:
        try:
            archived = self._archive.read_exact(locator.object_key, locator.version_id)
        except Exception as error:
            raise LiveEvaluationAuthorityError("live_authority_archive_unavailable") from error
        if not isinstance(archived, ProtectedArchiveVersion):
            raise LiveEvaluationAuthorityError("live_authority_archive_invalid")
        now = self._now()
        retain_until = _parse_time(
            archived.retain_until, "live_authority_archive_retention_invalid"
        )
        created_at = _parse_time(archived.created_at, "live_authority_archive_time_invalid")
        if retain_until <= now:
            raise LiveEvaluationAuthorityError("live_authority_archive_retention_invalid")
        digest = hashlib.sha256(archived.payload).hexdigest()
        if (
            archived.object_key != locator.object_key
            or archived.version_id != locator.version_id
            or archived.checksum_sha256 != digest
            or locator.payload_digest != digest
            or archived.byte_length != len(archived.payload)
            or archived.retention_mode != "COMPLIANCE"
            or created_at > now
        ):
            raise LiveEvaluationAuthorityError("live_authority_archive_invalid")
        return _strict_document(archived.payload), retain_until

    def _verify_document(
        self,
        *,
        document: dict[str, Any],
        locator: ProtectedEvidenceLocator,
        key: bytes,
        retention: datetime,
    ) -> dict[str, Any]:
        if (
            set(document)
            != {
                "expires_at",
                "issued_at",
                "key_id",
                "kind",
                "payload",
                "schema_version",
                "signature",
            }
            or document.get("schema_version") != 1
        ):
            raise LiveEvaluationAuthorityError("live_authority_evidence_invalid")
        if document["kind"] != locator.kind or type(document["payload"]) is not dict:
            raise LiveEvaluationAuthorityError("live_authority_evidence_invalid")
        now = self._now()
        issued = _parse_time(document["issued_at"], "live_authority_evidence_time_invalid")
        expires = _parse_time(document["expires_at"], "live_authority_evidence_time_invalid")
        if not issued <= now < expires or expires > retention:
            raise LiveEvaluationAuthorityError("live_authority_evidence_expired")
        unsigned = canonical_json_bytes(
            {
                "expires_at": document["expires_at"],
                "issued_at": document["issued_at"],
                "kind": locator.kind,
                "payload": document["payload"],
                "schema_version": 1,
            }
        )
        if not verify_bound_payload_attestation(
            unsigned,
            purpose=locator.kind,
            key=key,
            expected_key_id=document["key_id"],
            signature=document["signature"],
        ):
            raise LiveEvaluationAuthorityError("live_authority_signature_invalid")
        return document["payload"]

    @staticmethod
    def _verify_deterministic(
        value: dict[str, Any],
    ) -> tuple[LiveEvaluationIdentity, bool, tuple[str, ...]]:
        if set(value) != {
            "candidate_binary_digest",
            "candidate_tree",
            "checkout_attestation_digest",
            "contract_eligible",
            "contract_reasons",
            "execution_manifest_digest",
            "harness_result_digest",
            "identity",
            "immutable_inputs",
            "observation_digests",
            "parent_binary_digest",
            "parent_tree",
        }:
            raise LiveEvaluationAuthorityError("deterministic_run_attestation_invalid")
        identity = _wire_identity(value["identity"])
        reasons = _reasons(value["contract_reasons"], "deterministic_run_attestation_invalid")
        eligible = value["contract_eligible"]
        observations = value["observation_digests"]
        immutable = value["immutable_inputs"]
        for digest_field in (
            "candidate_binary_digest",
            "checkout_attestation_digest",
            "execution_manifest_digest",
            "harness_result_digest",
            "parent_binary_digest",
        ):
            _require_digest(value[digest_field], "deterministic_run_attestation_invalid")
        if (
            type(eligible) is not bool
            or eligible == bool(reasons)
            or value["parent_tree"] != identity.parent_tree
            or value["candidate_tree"] != identity.candidate_tree
            or immutable
            != {
                "experiment": identity.experiment_digest,
                "metric_pack": identity.metric_pack_digest,
                "policy": identity.policy_digest,
                "task_set": identity.task_set_digest,
            }
            or type(observations) is not list
            or len(observations) != 2 * len(identity.task_order)
            or any(
                not isinstance(item, str) or _DIGEST.fullmatch(item) is None
                for item in observations
            )
        ):
            raise LiveEvaluationAuthorityError("deterministic_run_attestation_invalid")
        manifest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "environment_digest": identity.environment_digest,
                    "harness_result_digest": value["harness_result_digest"],
                    "checkout_attestation_digest": value["checkout_attestation_digest"],
                    "identity": identity.to_canonical_dict(),
                    "immutable_inputs": immutable,
                }
            )
        ).hexdigest()
        if value["execution_manifest_digest"] != manifest:
            raise LiveEvaluationAuthorityError("deterministic_run_attestation_invalid")
        return identity, eligible, reasons

    def _verify_live(
        self, value: dict[str, Any]
    ) -> tuple[LiveEvaluationIdentity, bool, bool, tuple[str, ...], tuple[tuple[str, int], ...]]:
        if set(value) != {
            "eligible",
            "execution_context_digests",
            "grader_receipts",
            "identity",
            "inconclusive",
            "live_pair_digest",
            "model_result_digests",
            "policy",
            "reasons",
            "task_deltas",
            "tasks",
        }:
            raise LiveEvaluationAuthorityError("live_run_attestation_invalid")
        identity = _wire_identity(value["identity"])
        try:
            policy = LivePairPolicy(**value["policy"])
            tasks = tuple(LiveTaskIdentity(**item) for item in value["tasks"])
        except (TypeError, ValueError) as error:
            raise LiveEvaluationAuthorityError("live_run_attestation_invalid") from error
        reasons = _reasons(value["reasons"], "live_run_attestation_invalid")
        eligible = value["eligible"]
        inconclusive = value["inconclusive"]
        if (
            tuple(task.task_id for task in tasks) != identity.task_order
            or any(task.grader_digest != identity.grader_digest for task in tasks)
            or type(eligible) is not bool
            or type(inconclusive) is not bool
            or eligible == bool(reasons)
            or (inconclusive and "pair_infrastructure_invalid" not in reasons)
        ):
            raise LiveEvaluationAuthorityError("live_run_attestation_invalid")
        try:
            deltas = tuple(
                (item["task_id"], item["delta_basis_points"]) for item in value["task_deltas"]
            )
        except (TypeError, KeyError) as error:
            raise LiveEvaluationAuthorityError("live_run_attestation_invalid") from error
        if tuple(task_id for task_id, _ in deltas) != identity.task_order or any(
            isinstance(delta, bool) or not isinstance(delta, int) or not -10_000 <= delta <= 10_000
            for _, delta in deltas
        ):
            raise LiveEvaluationAuthorityError("live_run_attestation_invalid")
        contexts = value["execution_context_digests"]
        results = value["model_result_digests"]
        expected_count = 2 * len(tasks) * identity.attempts
        if (
            type(contexts) is not list
            or type(results) is not list
            or len(contexts) != expected_count
            or len(results) != expected_count
            or any(
                not isinstance(item, str) or _DIGEST.fullmatch(item) is None
                for item in (*contexts, *results)
            )
        ):
            raise LiveEvaluationAuthorityError("live_run_attestation_invalid")
        expected_contexts = [
            identity.execution_context_digest(
                subject=subject,
                task=task,
                policy=policy,
                seed=seed,
                attempt=attempt,
            )
            for subject in ("parent", "candidate")
            for task in tasks
            for attempt, seed in enumerate(identity.seeds, start=1)
        ]
        grader_receipts = value["grader_receipts"]
        if (
            type(grader_receipts) is not list
            or len(grader_receipts) != expected_count
            or self._grader_key is None
        ):
            raise LiveEvaluationAuthorityError("live_grader_receipt_invalid")
        expected_rows = [
            (subject, task, attempt, seed)
            for subject in ("parent", "candidate")
            for task in tasks
            for attempt, seed in enumerate(identity.seeds, start=1)
        ]
        scores: dict[tuple[str, str], list[int]] = {
            (subject, task.task_id): [] for subject in ("parent", "candidate") for task in tasks
        }
        receipt_fields = {
            "attempt",
            "attempt_identity",
            "domain",
            "evaluation_request_digest",
            "execution_context_digest",
            "infrastructure_code",
            "key_id",
            "live_policy_digest",
            "model_output_digest",
            "model_request_digest",
            "model_result_digest",
            "schema_version",
            "score_basis_points",
            "seed",
            "signature",
            "status",
            "subject",
            "subject_commit",
            "subject_tree",
            "task",
            "workflow_digest",
            "workflow_revision",
        }
        policy_digest = hashlib.sha256(canonical_json_bytes(policy.to_canonical_dict())).hexdigest()
        for index, (receipt, expected_row) in enumerate(
            zip(grader_receipts, expected_rows, strict=True)
        ):
            subject, task, attempt, seed = expected_row
            if type(receipt) is not dict or set(receipt) != receipt_fields:
                raise LiveEvaluationAuthorityError("live_grader_receipt_invalid")
            unsigned = {
                key: item for key, item in receipt.items() if key not in {"key_id", "signature"}
            }
            if not verify_bound_payload_attestation(
                canonical_json_bytes(unsigned),
                purpose=_GRADER_PURPOSE,
                key=self._grader_key,
                expected_key_id=receipt["key_id"],
                signature=receipt["signature"],
            ):
                raise LiveEvaluationAuthorityError("live_grader_receipt_invalid")
            expected_commit = (
                identity.parent_commit if subject == "parent" else identity.candidate_commit
            )
            expected_tree = identity.parent_tree if subject == "parent" else identity.candidate_tree
            expected_request = identity.model_request_digest(
                subject=subject,
                task=task,
                policy=policy,
                seed=seed,
                attempt=attempt,
            )
            score = receipt["score_basis_points"]
            status = receipt["status"]
            if (
                receipt["domain"] != "carl.protected-live-grader-outcome.v1"
                or receipt["schema_version"] != 1
                or receipt["evaluation_request_digest"] != identity.request_digest
                or receipt["execution_context_digest"] != expected_contexts[index]
                or receipt["live_policy_digest"] != policy_digest
                or receipt["model_result_digest"] != results[index]
                or receipt["subject"] != subject
                or receipt["subject_commit"] != expected_commit
                or receipt["subject_tree"] != expected_tree
                or receipt["task"] != task.to_canonical_dict()
                or receipt["attempt"] != attempt
                or receipt["seed"] != seed
                or receipt["workflow_digest"] != identity.workflow_digest
                or receipt["workflow_revision"] != identity.workflow_revision
                or not isinstance(receipt["attempt_identity"], str)
                or _DIGEST.fullmatch(receipt["attempt_identity"]) is None
                or isinstance(score, bool)
                or not isinstance(score, int)
                or not 0 <= score <= 10_000
            ):
                raise LiveEvaluationAuthorityError("live_grader_receipt_invalid")
            if status == "valid":
                if (
                    receipt["infrastructure_code"] is not None
                    or receipt["model_request_digest"] != expected_request
                    or not isinstance(receipt["model_output_digest"], str)
                    or _DIGEST.fullmatch(receipt["model_output_digest"]) is None
                ):
                    raise LiveEvaluationAuthorityError("live_grader_receipt_invalid")
            elif status == "infrastructure_invalid":
                if (
                    not isinstance(receipt["infrastructure_code"], str)
                    or receipt["model_request_digest"] is not None
                    or receipt["model_output_digest"] is not None
                    or score != 0
                ):
                    raise LiveEvaluationAuthorityError("live_grader_receipt_invalid")
            else:
                raise LiveEvaluationAuthorityError("live_grader_receipt_invalid")
            scores[(subject, task.task_id)].append(score)
        protected_deltas = tuple(
            (
                task.task_id,
                sum(scores[("candidate", task.task_id)]) // identity.attempts
                - sum(scores[("parent", task.task_id)]) // identity.attempts,
            )
            for task in tasks
        )
        if protected_deltas != deltas:
            raise LiveEvaluationAuthorityError("live_grader_receipt_invalid")
        try:
            gateway_policy = self._gateway.protected_execution_policy()
        except Exception as error:
            raise LiveEvaluationAuthorityError("live_execution_binding_mismatch") from error
        if (
            contexts != expected_contexts
            or hashlib.sha256(canonical_json_bytes(gateway_policy)).hexdigest()
            != identity.model_policy_digest
        ):
            raise LiveEvaluationAuthorityError("live_execution_binding_mismatch")
        _require_digest(value["live_pair_digest"], "live_run_attestation_invalid")
        return identity, eligible, inconclusive, reasons, deltas

    def combine(
        self,
        *,
        request_digest: str,
        deterministic_locator: ProtectedEvidenceLocator,
        live_locator: ProtectedEvidenceLocator,
    ) -> ProtectedCombinedCapabilityReceipt:
        _require_digest(request_digest, "live_authority_request_invalid")
        if (
            not isinstance(deterministic_locator, ProtectedEvidenceLocator)
            or deterministic_locator.kind != _DETERMINISTIC
            or not isinstance(live_locator, ProtectedEvidenceLocator)
            or live_locator.kind != _LIVE
        ):
            raise LiveEvaluationAuthorityError("live_authority_locator_invalid")
        deterministic_doc, deterministic_retention = self._read(deterministic_locator)
        live_doc, live_retention = self._read(live_locator)
        deterministic = self._verify_document(
            document=deterministic_doc,
            locator=deterministic_locator,
            key=self._det_key,
            retention=deterministic_retention,
        )
        live = self._verify_document(
            document=live_doc,
            locator=live_locator,
            key=self._live_key,
            retention=live_retention,
        )
        det_identity, det_eligible, det_reasons = self._verify_deterministic(deterministic)
        live_identity, live_eligible, inconclusive, live_reasons, deltas = self._verify_live(live)
        if det_identity != live_identity:
            raise LiveEvaluationAuthorityError("deterministic_live_identity_mismatch")
        if not det_eligible:
            eligible, disposition, reasons = False, "rejected", det_reasons
        else:
            eligible = live_eligible
            disposition = (
                "improvement" if live_eligible else ("inconclusive" if inconclusive else "rejected")
            )
            reasons = live_reasons
        issued_at = _timestamp(self._now())
        unsigned = {
            "deterministic_locator": deterministic_locator.to_canonical_dict(),
            "disposition": disposition,
            "eligible": eligible,
            "identity": det_identity.to_canonical_dict(),
            "issued_at": issued_at,
            "kind": "protected_combined_capability",
            "live_locator": live_locator.to_canonical_dict(),
            "reasons": list(reasons),
            "request_digest": request_digest,
            "schema_version": 1,
            "task_deltas": [
                {"delta_basis_points": delta, "task_id": task_id} for task_id, delta in deltas
            ],
        }
        key_id, signature = attest_bound_payload(
            canonical_json_bytes(unsigned), purpose=_RESULT_PURPOSE, key=self._result_key
        )
        return ProtectedCombinedCapabilityReceipt(
            1,
            request_digest,
            det_identity,
            deterministic_locator,
            live_locator,
            eligible,
            disposition,
            reasons,
            deltas,
            issued_at,
            key_id,
            signature,
        )

    def verify_combined_receipt(self, receipt: object) -> bool:
        if not isinstance(receipt, ProtectedCombinedCapabilityReceipt):
            return False
        return verify_bound_payload_attestation(
            canonical_json_bytes(receipt.unsigned_canonical_dict()),
            purpose=_RESULT_PURPOSE,
            key=self._result_key,
            expected_key_id=receipt.key_id,
            signature=receipt.signature,
        )
