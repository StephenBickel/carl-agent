"""Owner-private artifacts for non-production autonomy commissioning."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from carl_bench.artifacts import (
    MAX_ARTIFACT_BYTES,
    ArtifactIntegrityError,
    ArtifactRef,
    PrivateArtifactStore,
)
from carl_bench.canonical import canonical_json_bytes
from carl_bench.experiment import ExperimentState
from carl_bench.ledger import ExperimentLedger, LedgerIntegrityError

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_OUTCOME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class CommissioningArtifactError(ValueError):
    """A stable commissioning-artifact failure without private path disclosure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _anchored(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    return absolute.parent.resolve(strict=False) / absolute.name


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


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


def _prepare_private_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        if not _owner_private_directory(path):
            raise CommissioningArtifactError("commissioning_store_unsafe")
        return
    try:
        path.mkdir(mode=0o700)
        if os.name != "nt":
            path.chmod(0o700)
    except OSError as error:
        raise CommissioningArtifactError("commissioning_store_unavailable") from error
    if not _owner_private_directory(path):
        raise CommissioningArtifactError("commissioning_store_unsafe")


def _prepare_automation_data_root(path: Path) -> None:
    if not (path.exists() or path.is_symlink()):
        try:
            path.mkdir(mode=0o700, parents=True)
            if os.name != "nt":
                path.chmod(0o700)
        except OSError as error:
            raise CommissioningArtifactError("commissioning_store_unavailable") from error
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CommissioningArtifactError("commissioning_store_unavailable") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise CommissioningArtifactError("commissioning_store_unsafe")
    if os.name != "nt" and (
        stat.S_IMODE(metadata.st_mode) & 0o022
        or (hasattr(os, "getuid") and metadata.st_uid != os.getuid())
    ):
        raise CommissioningArtifactError("commissioning_store_unsafe")


def _identifier(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise CommissioningArtifactError(code)
    return value


def _digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise CommissioningArtifactError(code)
    return value


def _object(value: Any, code: str) -> str:
    if not isinstance(value, str) or not _OBJECT_RE.fullmatch(value):
        raise CommissioningArtifactError(code)
    return value


def _outcomes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise CommissioningArtifactError("invalid_commissioning_outcomes")
    normalized = tuple(_identifier(item, "invalid_commissioning_outcome") for item in value)
    if (
        not normalized
        or normalized != tuple(sorted(set(normalized)))
        or any(_OUTCOME_RE.fullmatch(item) is None for item in normalized)
    ):
        raise CommissioningArtifactError("invalid_commissioning_outcomes")
    return normalized


@dataclass(frozen=True, slots=True)
class SyntheticCommissioningReceipt:
    """Full synthetic lifecycle result; never valid as remote cloud evidence."""

    schema_version: int
    synthetic_test_only: bool
    experiment_id: str
    terminal_state: str
    experimental_ref: str
    candidate_commit: str
    candidate_tree: str
    promotion_id: str
    pull_request_number: int
    merge_commit: str
    restart_recoveries: int
    lifecycle_ledger_digest: str
    protected_receipt_digest: str
    capability_report_digest: str
    prompt_portfolio_digest: str
    supervisor_result_digest: str
    remote_cloud_acceptance: str
    adversarial_outcomes: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise CommissioningArtifactError("invalid_commissioning_receipt_schema")
        if self.synthetic_test_only is not True:
            raise CommissioningArtifactError("commissioning_receipt_must_be_synthetic")
        _identifier(self.experiment_id, "invalid_commissioning_experiment")
        if self.terminal_state not in {"accepted", "reverted"}:
            raise CommissioningArtifactError("invalid_commissioning_terminal_state")
        if self.experimental_ref != f"refs/heads/experimental/{self.experiment_id}":
            raise CommissioningArtifactError("invalid_commissioning_experimental_ref")
        _object(self.candidate_commit, "invalid_commissioning_candidate_commit")
        _object(self.candidate_tree, "invalid_commissioning_candidate_tree")
        _identifier(self.promotion_id, "invalid_commissioning_promotion")
        if (
            isinstance(self.pull_request_number, bool)
            or not isinstance(self.pull_request_number, int)
            or self.pull_request_number <= 0
        ):
            raise CommissioningArtifactError("invalid_commissioning_pull_request")
        _object(self.merge_commit, "invalid_commissioning_merge_commit")
        if (
            isinstance(self.restart_recoveries, bool)
            or not isinstance(self.restart_recoveries, int)
            or self.restart_recoveries < 2
        ):
            raise CommissioningArtifactError("insufficient_commissioning_restarts")
        for name in (
            "lifecycle_ledger_digest",
            "protected_receipt_digest",
            "capability_report_digest",
            "prompt_portfolio_digest",
            "supervisor_result_digest",
        ):
            _digest(getattr(self, name), f"invalid_{name}")
        if self.remote_cloud_acceptance != "uncommissioned":
            raise CommissioningArtifactError("synthetic_cloud_acceptance_must_be_uncommissioned")
        _outcomes(self.adversarial_outcomes)

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "adversarial_outcomes": list(self.adversarial_outcomes),
            "candidate_commit": self.candidate_commit,
            "candidate_tree": self.candidate_tree,
            "capability_report_digest": self.capability_report_digest,
            "experiment_id": self.experiment_id,
            "experimental_ref": self.experimental_ref,
            "lifecycle_ledger_digest": self.lifecycle_ledger_digest,
            "merge_commit": self.merge_commit,
            "promotion_id": self.promotion_id,
            "prompt_portfolio_digest": self.prompt_portfolio_digest,
            "protected_receipt_digest": self.protected_receipt_digest,
            "pull_request_number": self.pull_request_number,
            "remote_cloud_acceptance": self.remote_cloud_acceptance,
            "restart_recoveries": self.restart_recoveries,
            "schema_version": self.schema_version,
            "supervisor_result_digest": self.supervisor_result_digest,
            "synthetic_test_only": self.synthetic_test_only,
            "terminal_state": self.terminal_state,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> SyntheticCommissioningReceipt:
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise CommissioningArtifactError("invalid_commissioning_receipt")
        normalized = dict(value)
        outcomes = normalized.get("adversarial_outcomes")
        if not isinstance(outcomes, list):
            raise CommissioningArtifactError("invalid_commissioning_outcomes")
        normalized["adversarial_outcomes"] = tuple(outcomes)
        try:
            return cls(**normalized)
        except TypeError as error:
            raise CommissioningArtifactError("invalid_commissioning_receipt") from error

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class SanitizedCommissioningReport:
    schema_version: int
    synthetic_test_only: bool
    status: str
    experiment_id: str
    terminal_state: str
    experimental_ref: str
    promotion_id: str
    pull_request_number: int
    merge_commit: str
    restart_recoveries: int
    remote_cloud_acceptance: str
    adversarial_outcomes: tuple[str, ...]
    artifact_digests: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if self.schema_version != 1 or self.synthetic_test_only is not True:
            raise CommissioningArtifactError("invalid_commissioning_report_schema")
        if self.status != "synthetic_passed":
            raise CommissioningArtifactError("invalid_commissioning_report_status")
        _identifier(self.experiment_id, "invalid_commissioning_experiment")
        if self.terminal_state not in {"accepted", "reverted"}:
            raise CommissioningArtifactError("invalid_commissioning_terminal_state")
        if self.experimental_ref != f"refs/heads/experimental/{self.experiment_id}":
            raise CommissioningArtifactError("invalid_commissioning_experimental_ref")
        _identifier(self.promotion_id, "invalid_commissioning_promotion")
        if (
            isinstance(self.pull_request_number, bool)
            or not isinstance(self.pull_request_number, int)
            or self.pull_request_number <= 0
        ):
            raise CommissioningArtifactError("invalid_commissioning_pull_request")
        _object(self.merge_commit, "invalid_commissioning_merge_commit")
        if (
            isinstance(self.restart_recoveries, bool)
            or not isinstance(self.restart_recoveries, int)
            or self.restart_recoveries < 2
        ):
            raise CommissioningArtifactError("insufficient_commissioning_restarts")
        if self.remote_cloud_acceptance != "uncommissioned":
            raise CommissioningArtifactError("synthetic_cloud_acceptance_must_be_uncommissioned")
        _outcomes(self.adversarial_outcomes)
        if not isinstance(self.artifact_digests, tuple):
            raise CommissioningArtifactError("invalid_commissioning_artifact_digests")
        names = tuple(name for name, _ in self.artifact_digests)
        if names != tuple(sorted(set(names))) or not names:
            raise CommissioningArtifactError("invalid_commissioning_artifact_digests")
        for name, digest in self.artifact_digests:
            _identifier(name, "invalid_commissioning_artifact_name")
            _digest(digest, "invalid_commissioning_artifact_digest")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "adversarial_outcomes": list(self.adversarial_outcomes),
            "artifact_digests": [
                {"digest": digest, "name": name} for name, digest in self.artifact_digests
            ],
            "experiment_id": self.experiment_id,
            "experimental_ref": self.experimental_ref,
            "merge_commit": self.merge_commit,
            "promotion_id": self.promotion_id,
            "pull_request_number": self.pull_request_number,
            "remote_cloud_acceptance": self.remote_cloud_acceptance,
            "restart_recoveries": self.restart_recoveries,
            "schema_version": self.schema_version,
            "status": self.status,
            "synthetic_test_only": self.synthetic_test_only,
            "terminal_state": self.terminal_state,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> SanitizedCommissioningReport:
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise CommissioningArtifactError("invalid_commissioning_report")
        outcomes = value.get("adversarial_outcomes")
        artifacts = value.get("artifact_digests")
        if not isinstance(outcomes, list) or not isinstance(artifacts, list):
            raise CommissioningArtifactError("invalid_commissioning_report")
        pairs: list[tuple[str, str]] = []
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {"digest", "name"}:
                raise CommissioningArtifactError("invalid_commissioning_artifact_digests")
            pairs.append((artifact["name"], artifact["digest"]))
        normalized = dict(value)
        normalized["adversarial_outcomes"] = tuple(outcomes)
        normalized["artifact_digests"] = tuple(pairs)
        try:
            return cls(**normalized)
        except TypeError as error:
            raise CommissioningArtifactError("invalid_commissioning_report") from error

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class CommissioningArtifactBundle:
    receipt: SyntheticCommissioningReceipt | None
    receipt_ref: ArtifactRef | None
    report: SanitizedCommissioningReport | SourceDerivedCommissioningReport
    report_ref: ArtifactRef


@dataclass(frozen=True, slots=True)
class SourceDerivedCommissioningReport:
    """Schema-v2 report whose fields are reconstructed from referenced bytes."""

    schema_version: int
    synthetic_test_only: bool
    status: str
    experiment_id: str
    terminal_state: str
    experimental_ref: str
    candidate_commit: str
    candidate_tree: str
    promotion_id: str
    pull_request_number: int
    merge_commit: str
    merge_tree: str
    production_ref: str
    hard_failure_promotion_id: str
    hard_failure_pull_request_number: int
    hard_failure_candidate_commit: str
    hard_failure_merge_commit: str
    revert_promotion_id: str
    revert_pull_request_number: int
    revert_candidate_commit: str
    revert_merge_commit: str
    restored_tree: str
    restart_recoveries: int
    remote_cloud_acceptance: str
    adversarial_outcomes: tuple[str, ...]
    artifact_refs: tuple[tuple[str, ArtifactRef], ...]

    def __post_init__(self) -> None:
        if self.schema_version != 2 or self.synthetic_test_only is not True:
            raise CommissioningArtifactError("invalid_commissioning_report_schema")
        if self.status != "synthetic_passed" or self.terminal_state != "accepted":
            raise CommissioningArtifactError("invalid_commissioning_report_status")
        _identifier(self.experiment_id, "invalid_commissioning_experiment")
        if self.experimental_ref != f"refs/heads/experimental/{self.experiment_id}":
            raise CommissioningArtifactError("invalid_commissioning_experimental_ref")
        for name in (
            "candidate_commit",
            "candidate_tree",
            "merge_commit",
            "merge_tree",
            "hard_failure_candidate_commit",
            "hard_failure_merge_commit",
            "revert_candidate_commit",
            "revert_merge_commit",
            "restored_tree",
        ):
            _object(getattr(self, name), f"invalid_commissioning_{name}")
        if self.production_ref != "refs/heads/main":
            raise CommissioningArtifactError("invalid_commissioning_production_ref")
        for name in (
            "promotion_id",
            "hard_failure_promotion_id",
            "revert_promotion_id",
        ):
            _identifier(getattr(self, name), f"invalid_commissioning_{name}")
        for name in (
            "pull_request_number",
            "hard_failure_pull_request_number",
            "revert_pull_request_number",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise CommissioningArtifactError(f"invalid_commissioning_{name}")
        if (
            isinstance(self.restart_recoveries, bool)
            or not isinstance(self.restart_recoveries, int)
            or self.restart_recoveries < 2
        ):
            raise CommissioningArtifactError("insufficient_commissioning_restarts")
        if self.remote_cloud_acceptance != "uncommissioned":
            raise CommissioningArtifactError("synthetic_cloud_acceptance_must_be_uncommissioned")
        _outcomes(self.adversarial_outcomes)
        if not isinstance(self.artifact_refs, tuple) or not self.artifact_refs:
            raise CommissioningArtifactError("invalid_commissioning_artifact_refs")
        names = tuple(name for name, _ in self.artifact_refs)
        if names != tuple(sorted(set(names))):
            raise CommissioningArtifactError("invalid_commissioning_artifact_refs")
        for name, ref in self.artifact_refs:
            _identifier(name, "invalid_commissioning_artifact_name")
            if not isinstance(ref, ArtifactRef):
                raise CommissioningArtifactError("invalid_commissioning_artifact_ref")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "adversarial_outcomes": list(self.adversarial_outcomes),
            "artifact_refs": [
                {"name": name, "ref": ref.to_canonical_dict()} for name, ref in self.artifact_refs
            ],
            "candidate_commit": self.candidate_commit,
            "candidate_tree": self.candidate_tree,
            "experiment_id": self.experiment_id,
            "experimental_ref": self.experimental_ref,
            "hard_failure_candidate_commit": self.hard_failure_candidate_commit,
            "hard_failure_merge_commit": self.hard_failure_merge_commit,
            "hard_failure_promotion_id": self.hard_failure_promotion_id,
            "hard_failure_pull_request_number": self.hard_failure_pull_request_number,
            "merge_commit": self.merge_commit,
            "merge_tree": self.merge_tree,
            "production_ref": self.production_ref,
            "promotion_id": self.promotion_id,
            "pull_request_number": self.pull_request_number,
            "remote_cloud_acceptance": self.remote_cloud_acceptance,
            "restart_recoveries": self.restart_recoveries,
            "restored_tree": self.restored_tree,
            "revert_candidate_commit": self.revert_candidate_commit,
            "revert_merge_commit": self.revert_merge_commit,
            "revert_promotion_id": self.revert_promotion_id,
            "revert_pull_request_number": self.revert_pull_request_number,
            "schema_version": self.schema_version,
            "status": self.status,
            "synthetic_test_only": self.synthetic_test_only,
            "terminal_state": self.terminal_state,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> SourceDerivedCommissioningReport:
        expected = set(cls.__dataclass_fields__)
        if not isinstance(value, dict) or set(value) != expected:
            raise CommissioningArtifactError("invalid_commissioning_report")
        refs = value.get("artifact_refs")
        outcomes = value.get("adversarial_outcomes")
        if not isinstance(refs, list) or not isinstance(outcomes, list):
            raise CommissioningArtifactError("invalid_commissioning_report")
        normalized_refs: list[tuple[str, ArtifactRef]] = []
        try:
            for item in refs:
                if not isinstance(item, dict) or set(item) != {"name", "ref"}:
                    raise CommissioningArtifactError("invalid_commissioning_artifact_refs")
                normalized_refs.append((item["name"], ArtifactRef.from_canonical_dict(item["ref"])))
        except ArtifactIntegrityError as error:
            raise CommissioningArtifactError("invalid_commissioning_artifact_refs") from error
        normalized = dict(value)
        normalized["artifact_refs"] = tuple(normalized_refs)
        normalized["adversarial_outcomes"] = tuple(outcomes)
        try:
            return cls(**normalized)
        except TypeError as error:
            raise CommissioningArtifactError("invalid_commissioning_report") from error

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class SyntheticCommissioningSources:
    """Typed durable inputs from which a synthetic pass may be derived."""

    experiment_id: str
    ledger_path: Path
    lifecycle_export_ref: ArtifactRef
    lifecycle_chain_receipt_ref: ArtifactRef
    bare_repository: Path
    bare_refs_snapshot_ref: ArtifactRef
    effect_store_path: Path
    effects_snapshot_ref: ArtifactRef
    capability_evidence_refs: tuple[ArtifactRef, ...]
    signed_protected_receipt_ref: ArtifactRef
    protected_public_key_path: Path
    supervisor_store_path: Path
    supervisor_trigger_id: str
    supervisor_result_ref: ArtifactRef

    def __post_init__(self) -> None:
        _identifier(self.experiment_id, "invalid_commissioning_experiment")
        for name in (
            "ledger_path",
            "bare_repository",
            "effect_store_path",
            "protected_public_key_path",
            "supervisor_store_path",
        ):
            if not isinstance(getattr(self, name), Path):
                raise CommissioningArtifactError("invalid_commissioning_source_path")
        for name in (
            "lifecycle_export_ref",
            "lifecycle_chain_receipt_ref",
            "bare_refs_snapshot_ref",
            "effects_snapshot_ref",
            "signed_protected_receipt_ref",
            "supervisor_result_ref",
        ):
            if not isinstance(getattr(self, name), ArtifactRef):
                raise CommissioningArtifactError("invalid_commissioning_source_ref")
        expected_kinds = {
            "lifecycle_export_ref": "lifecycle_export",
            "lifecycle_chain_receipt_ref": "lifecycle_chain_receipt",
            "bare_refs_snapshot_ref": "bare_refs_snapshot",
            "effects_snapshot_ref": "commissioning_effects_snapshot",
            "signed_protected_receipt_ref": "signed_protected_receipt",
            "supervisor_result_ref": "supervisor_result",
        }
        if any(
            getattr(self, name).evidence_kind != kind
            or getattr(self, name).media_type != "application/json"
            for name, kind in expected_kinds.items()
        ):
            raise CommissioningArtifactError("invalid_commissioning_source_ref")
        if not isinstance(self.capability_evidence_refs, tuple) or not all(
            isinstance(ref, ArtifactRef)
            and ref.evidence_kind == "capability_evidence_bundle"
            and ref.media_type == "application/json"
            for ref in self.capability_evidence_refs
        ):
            raise CommissioningArtifactError("invalid_commissioning_capability_refs")
        _identifier(self.supervisor_trigger_id, "invalid_supervisor_trigger_id")


@dataclass(frozen=True, slots=True)
class VerifiedAcceptedLifecycle:
    """Identities derived from a fresh ledger replay and local bare Git refs."""

    experiment_id: str
    terminal_state: str
    experimental_ref: str
    candidate_commit: str
    candidate_tree: str
    promotion_commit: str
    promotion_tree: str
    production_commit: str
    soak_elapsed_seconds: int
    lifecycle_artifact_ref: ArtifactRef


def _canonical_lifecycle_export(ledger: ExperimentLedger, experiment_id: str) -> bytes:
    projection = ledger.projection(experiment_id)
    autonomy = ledger.autonomy_projection(experiment_id)
    return canonical_json_bytes(
        {
            "autonomy": autonomy.to_canonical_dict(),
            "events": [event.to_canonical_dict() for event in ledger.events(experiment_id)],
            "experiment_id": experiment_id,
            "projection_digest": projection.digest,
            "schema_version": 1,
            "terminal_state": projection.state.value,
        }
    )


def _canonical_lifecycle_v2(
    ledger: ExperimentLedger, experiment_id: str
) -> tuple[bytes, dict[str, Any]]:
    manifest = ledger.load_manifest(experiment_id)
    events = ledger.events(experiment_id)
    projection = ledger.projection(experiment_id)
    autonomy = ledger.autonomy_projection(experiment_id)
    export = canonical_json_bytes(
        {
            "autonomy": autonomy.to_canonical_dict(),
            "events": [event.to_canonical_dict() for event in events],
            "experiment_id": experiment_id,
            "manifest": manifest.to_canonical_dict(),
            "projection": {
                "digest": projection.digest,
                "last_sequence": projection.last_sequence,
                "state": projection.state.value,
            },
            "schema_version": 2,
        }
    )
    previous = "0" * 64
    for ordinal, event in enumerate(events, start=1):
        previous = hashlib.sha256(
            canonical_json_bytes(
                {
                    "event_digest": event.digest,
                    "experiment_id": experiment_id,
                    "manifest_digest": manifest.digest,
                    "ordinal": ordinal,
                    "previous_chain_digest": previous,
                }
            )
        ).hexdigest()
    chain_receipt = {
        "event_count": len(events),
        "experiment_id": experiment_id,
        "lifecycle_export_digest": hashlib.sha256(export).hexdigest(),
        "manifest_digest": manifest.digest,
        "schema_version": 1,
        "terminal_chain_digest": previous,
    }
    return export, chain_receipt


def _parse_utc(value: str, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise CommissioningArtifactError(code)
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise CommissioningArtifactError(code) from error
    if parsed.tzinfo != UTC:
        raise CommissioningArtifactError(code)
    return parsed


def _bare_git(repository: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ("git", "--git-dir", os.fspath(repository), *arguments),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CommissioningArtifactError("commissioning_bare_git_invalid") from error
    return completed.stdout.strip()


class CommissioningArtifactStore:
    """Persist discoverable synthetic receipts beneath an owner-private automation root."""

    def __init__(self, *, automation_data_root: Path, repository_root: Path) -> None:
        self.automation_data_root = _anchored(automation_data_root)
        repository = _anchored(repository_root)
        if _inside(self.automation_data_root, repository):
            raise CommissioningArtifactError("commissioning_store_inside_repository")
        _prepare_automation_data_root(self.automation_data_root)
        self.private_root = self.automation_data_root / ".shared-private"
        _prepare_private_directory(self.private_root)
        self.root = self.private_root / "carl-autonomy-commissioning"
        _prepare_private_directory(self.root)
        self.objects_root = self.root / "objects"
        try:
            self._objects = PrivateArtifactStore(self.objects_root, repository)
        except ArtifactIntegrityError as error:
            raise CommissioningArtifactError("commissioning_store_unsafe") from error
        self.index_path = self.root / "latest-synthetic.json"

    def read(self, ref: ArtifactRef) -> bytes:
        try:
            return self._objects.read(ref)
        except ArtifactIntegrityError as error:
            raise CommissioningArtifactError("commissioning_artifact_invalid") from error

    def capture_lifecycle_sources(
        self, *, experiment_id: str, ledger_path: Path
    ) -> tuple[ArtifactRef, ArtifactRef]:
        """Snapshot a freshly replayed ledger and its independently derived hash chain."""
        ledger_file = _anchored(ledger_path)
        if not _inside(ledger_file, self.automation_data_root):
            raise CommissioningArtifactError("commissioning_ledger_outside_automation_root")
        try:
            export, chain_receipt = _canonical_lifecycle_v2(
                ExperimentLedger(ledger_file), experiment_id
            )
            export_ref = self._objects.put(
                evidence_kind="lifecycle_export",
                media_type="application/json",
                content=export,
            )
            chain_ref = self._objects.put(
                evidence_kind="lifecycle_chain_receipt",
                media_type="application/json",
                content=canonical_json_bytes(chain_receipt),
            )
        except (ArtifactIntegrityError, LedgerIntegrityError) as error:
            raise CommissioningArtifactError("commissioning_lifecycle_invalid") from error
        return export_ref, chain_ref

    def capture_bare_refs(self, bare_repository: Path) -> ArtifactRef:
        """Snapshot every branch ref and its resolved commit/tree from a local bare repo."""
        repository = _anchored(bare_repository)
        if (
            not repository.is_dir()
            or _bare_git(repository, "rev-parse", "--is-bare-repository") != "true"
        ):
            raise CommissioningArtifactError("commissioning_bare_git_invalid")
        ref_names = tuple(
            item
            for item in _bare_git(
                repository,
                "for-each-ref",
                "--format=%(refname)",
                "refs/heads",
            ).splitlines()
            if item
        )
        refs = [
            {
                "commit": _bare_git(repository, "rev-parse", ref),
                "ref": ref,
                "tree": _bare_git(repository, "rev-parse", f"{ref}^{{tree}}"),
            }
            for ref in ref_names
        ]
        try:
            return self._objects.put(
                evidence_kind="bare_refs_snapshot",
                media_type="application/json",
                content=canonical_json_bytes({"refs": refs, "schema_version": 1}),
            )
        except ArtifactIntegrityError as error:
            raise CommissioningArtifactError("commissioning_artifact_write_failed") from error

    def capture_effects_snapshot(self, effect_store_path: Path) -> ArtifactRef:
        """Snapshot the controller journal after its own durable identity validation."""
        from carl_bench.commissioning_controller import (
            CommissioningControllerError,
            CommissioningEffectStore,
        )

        path = _anchored(effect_store_path)
        if not _inside(path, self.automation_data_root):
            raise CommissioningArtifactError("commissioning_effects_outside_automation_root")
        try:
            snapshot = CommissioningEffectStore(path).validated_snapshot()
            return self._objects.put(
                evidence_kind="commissioning_effects_snapshot",
                media_type="application/json",
                content=canonical_json_bytes(snapshot),
            )
        except (ArtifactIntegrityError, CommissioningControllerError) as error:
            raise CommissioningArtifactError("commissioning_effects_invalid") from error

    def verify_accepted_lifecycle(
        self,
        *,
        experiment_id: str,
        ledger_path: Path,
        bare_repository: Path,
        lifecycle_artifact_ref: ArtifactRef,
    ) -> VerifiedAcceptedLifecycle:
        """Derive accepted identities without trusting caller-authored outcome fields."""
        _identifier(experiment_id, "invalid_commissioning_experiment")
        if not isinstance(lifecycle_artifact_ref, ArtifactRef):
            raise CommissioningArtifactError("invalid_lifecycle_artifact_ref")
        if (
            lifecycle_artifact_ref.evidence_kind != "lifecycle_ledger"
            or lifecycle_artifact_ref.media_type != "application/json"
        ):
            raise CommissioningArtifactError("invalid_lifecycle_artifact_ref")

        ledger_file = _anchored(ledger_path)
        if not _inside(ledger_file, self.automation_data_root):
            raise CommissioningArtifactError("commissioning_ledger_outside_automation_root")
        repository = _anchored(bare_repository)
        is_bare = _bare_git(repository, "rev-parse", "--is-bare-repository")
        if not repository.is_dir() or is_bare != "true":
            raise CommissioningArtifactError("commissioning_bare_git_invalid")

        try:
            ledger = ExperimentLedger(ledger_file)
            projection = ledger.projection(experiment_id)
            autonomy = ledger.autonomy_projection(experiment_id)
            lifecycle_bytes = _canonical_lifecycle_export(ledger, experiment_id)
        except LedgerIntegrityError as error:
            raise CommissioningArtifactError("commissioning_lifecycle_invalid") from error
        if projection.state is not ExperimentState.ACCEPTED:
            raise CommissioningArtifactError("commissioning_lifecycle_not_accepted")
        if projection.lease is not None or projection.candidate is None:
            raise CommissioningArtifactError("commissioning_lifecycle_incomplete")

        publication = autonomy.experimental_publication
        validation = autonomy.protected_validation
        promotion = autonomy.promotion
        observations = autonomy.soak_observations
        if (
            publication is None
            or validation is None
            or promotion is None
            or autonomy.revert is not None
            or not observations
        ):
            raise CommissioningArtifactError("commissioning_lifecycle_incomplete")
        candidate = projection.candidate
        if (
            publication.candidate_packet_digest != candidate.digest
            or publication.commit != candidate.candidate_commit
            or validation.candidate_commit != publication.commit
            or validation.candidate_tree != publication.tree
            or promotion.merge_tree != publication.tree
        ):
            raise CommissioningArtifactError("commissioning_lifecycle_identity_mismatch")
        if any(
            not observation.healthy or observation.merge_commit != promotion.merge_commit
            for observation in observations
        ):
            raise CommissioningArtifactError("commissioning_lifecycle_unhealthy")
        merged_at = _parse_utc(promotion.merged_at, "commissioning_promotion_time_invalid")
        latest_soak = max(
            _parse_utc(item.observed_at, "commissioning_soak_time_invalid") for item in observations
        )
        soak_elapsed = int((latest_soak - merged_at).total_seconds())
        if soak_elapsed < 24 * 60 * 60:
            raise CommissioningArtifactError("commissioning_soak_incomplete")

        experimental_ref = f"refs/heads/experimental/{experiment_id}"
        if publication.branch != experimental_ref.removeprefix("refs/heads/"):
            raise CommissioningArtifactError("commissioning_experimental_ref_mismatch")
        experimental_refs = tuple(
            line
            for line in _bare_git(
                repository,
                "for-each-ref",
                "--format=%(refname)",
                "refs/heads/experimental",
            ).splitlines()
            if line
        )
        if experimental_refs != (experimental_ref,):
            raise CommissioningArtifactError("commissioning_experimental_ref_set_mismatch")
        experimental_commit = _bare_git(repository, "rev-parse", experimental_ref)
        experimental_tree = _bare_git(repository, "rev-parse", f"{experimental_ref}^{{tree}}")
        production_commit = _bare_git(repository, "rev-parse", "refs/heads/main")
        production_tree = _bare_git(repository, "rev-parse", "refs/heads/main^{tree}")
        if experimental_commit != publication.commit or experimental_tree != publication.tree:
            raise CommissioningArtifactError("commissioning_experimental_identity_mismatch")
        if production_commit != promotion.merge_commit or production_tree != promotion.merge_tree:
            raise CommissioningArtifactError("commissioning_production_identity_mismatch")

        if self.read(lifecycle_artifact_ref) != lifecycle_bytes:
            raise CommissioningArtifactError("commissioning_lifecycle_artifact_mismatch")
        return VerifiedAcceptedLifecycle(
            experiment_id=experiment_id,
            terminal_state=projection.state.value,
            experimental_ref=experimental_ref,
            candidate_commit=publication.commit,
            candidate_tree=publication.tree,
            promotion_commit=promotion.merge_commit,
            promotion_tree=promotion.merge_tree,
            production_commit=production_commit,
            soak_elapsed_seconds=soak_elapsed,
            lifecycle_artifact_ref=lifecycle_artifact_ref,
        )

    @staticmethod
    def _report(
        receipt: SyntheticCommissioningReceipt,
        receipt_ref: ArtifactRef,
    ) -> SanitizedCommissioningReport:
        return SanitizedCommissioningReport(
            schema_version=1,
            synthetic_test_only=True,
            status="synthetic_passed",
            experiment_id=receipt.experiment_id,
            terminal_state=receipt.terminal_state,
            experimental_ref=receipt.experimental_ref,
            promotion_id=receipt.promotion_id,
            pull_request_number=receipt.pull_request_number,
            merge_commit=receipt.merge_commit,
            restart_recoveries=receipt.restart_recoveries,
            remote_cloud_acceptance="uncommissioned",
            adversarial_outcomes=receipt.adversarial_outcomes,
            artifact_digests=tuple(
                sorted(
                    (
                        ("capability_report", receipt.capability_report_digest),
                        ("lifecycle_ledger", receipt.lifecycle_ledger_digest),
                        ("prompt_portfolio", receipt.prompt_portfolio_digest),
                        ("protected_receipt", receipt.protected_receipt_digest),
                        ("supervisor_result", receipt.supervisor_result_digest),
                        ("synthetic_receipt", receipt_ref.digest),
                    )
                )
            ),
        )

    def persist_synthetic(
        self, receipt: SyntheticCommissioningReceipt
    ) -> CommissioningArtifactBundle:
        if isinstance(receipt, SyntheticCommissioningReceipt):
            raise CommissioningArtifactError("caller_authored_commissioning_receipt_forbidden")
        raise CommissioningArtifactError("invalid_commissioning_evidence_sources")

    @staticmethod
    def _json_object(content: bytes, code: str) -> dict[str, Any]:
        try:
            value = json.loads(content)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise CommissioningArtifactError(code) from error
        if not isinstance(value, dict):
            raise CommissioningArtifactError(code)
        return value

    @staticmethod
    def _artifact_map(refs: tuple[tuple[str, ArtifactRef], ...]) -> dict[str, ArtifactRef]:
        return {name: ref for name, ref in refs}

    def _replay_lifecycle_export(
        self,
        *,
        export_ref: ArtifactRef,
        chain_ref: ArtifactRef,
    ) -> tuple[Any, Any, Any]:
        from carl_bench.experiment import EventType, ExperimentEvent, ExperimentManifest

        export = self._json_object(self.read(export_ref), "commissioning_lifecycle_export_invalid")
        if (
            set(export)
            != {
                "autonomy",
                "events",
                "experiment_id",
                "manifest",
                "projection",
                "schema_version",
            }
            or export.get("schema_version") != 2
        ):
            raise CommissioningArtifactError("commissioning_lifecycle_export_invalid")
        try:
            manifest = ExperimentManifest.from_canonical_dict(export["manifest"])
        except (TypeError, ValueError) as error:
            raise CommissioningArtifactError("commissioning_lifecycle_export_invalid") from error
        if manifest.experiment_id != export["experiment_id"]:
            raise CommissioningArtifactError("commissioning_lifecycle_identity_mismatch")
        raw_events = export["events"]
        if not isinstance(raw_events, list):
            raise CommissioningArtifactError("commissioning_lifecycle_export_invalid")
        events: list[ExperimentEvent] = []
        for value in raw_events:
            if not isinstance(value, dict) or set(value) != {
                "event_type",
                "experiment_id",
                "occurred_at",
                "payload",
                "schema_version",
                "stage_attempt_id",
            }:
                raise CommissioningArtifactError("commissioning_lifecycle_export_invalid")
            try:
                event = ExperimentEvent.create(
                    experiment_id=value["experiment_id"],
                    stage_attempt_id=value["stage_attempt_id"],
                    event_type=EventType(value["event_type"]),
                    occurred_at=value["occurred_at"],
                    payload=value["payload"],
                )
            except (TypeError, ValueError) as error:
                raise CommissioningArtifactError(
                    "commissioning_lifecycle_export_invalid"
                ) from error
            if event.to_canonical_dict() != value:
                raise CommissioningArtifactError("commissioning_lifecycle_export_invalid")
            events.append(event)

        replay_root = Path(tempfile.mkdtemp(prefix=".replay-", dir=self.root))
        if os.name != "nt":
            replay_root.chmod(0o700)
        try:
            replay = ExperimentLedger(replay_root / "ledger.sqlite3")
            replay.register_manifest(manifest)
            trusted = {
                EventType.PAIRED_EVIDENCE_RECORDED,
                EventType.PROTECTED_VALIDATION_RECORDED,
                EventType.PROMOTION_RECORDED,
                EventType.SOAK_OBSERVED,
                EventType.REVERT_RECORDED,
            }
            for event in events:
                if event.event_type in trusted:
                    replay.append_trusted_authority(event)
                else:
                    replay.append(event)
            projection = replay.projection(manifest.experiment_id)
            autonomy = replay.autonomy_projection(manifest.experiment_id)
        except LedgerIntegrityError as error:
            raise CommissioningArtifactError("commissioning_lifecycle_invalid") from error
        finally:
            for child in replay_root.iterdir():
                child.unlink(missing_ok=True)
            replay_root.rmdir()
        expected_projection = {
            "digest": projection.digest,
            "last_sequence": projection.last_sequence,
            "state": projection.state.value,
        }
        if (
            export["projection"] != expected_projection
            or export["autonomy"] != autonomy.to_canonical_dict()
            or projection.state is not ExperimentState.ACCEPTED
            or projection.lease is not None
        ):
            raise CommissioningArtifactError("commissioning_lifecycle_not_accepted")

        chain = self._json_object(self.read(chain_ref), "commissioning_lifecycle_chain_invalid")
        previous = "0" * 64
        for ordinal, event in enumerate(events, start=1):
            previous = hashlib.sha256(
                canonical_json_bytes(
                    {
                        "event_digest": event.digest,
                        "experiment_id": manifest.experiment_id,
                        "manifest_digest": manifest.digest,
                        "ordinal": ordinal,
                        "previous_chain_digest": previous,
                    }
                )
            ).hexdigest()
        expected_chain = {
            "event_count": len(events),
            "experiment_id": manifest.experiment_id,
            "lifecycle_export_digest": export_ref.digest,
            "manifest_digest": manifest.digest,
            "schema_version": 1,
            "terminal_chain_digest": previous,
        }
        if chain != expected_chain:
            raise CommissioningArtifactError("commissioning_lifecycle_chain_invalid")
        return manifest, projection, autonomy

    def _derive_source_report(
        self, artifact_refs: tuple[tuple[str, ArtifactRef], ...]
    ) -> SourceDerivedCommissioningReport:
        from carl_bench.commissioning_controller import (
            EffectRequest,
            verify_effect_receipt_ref,
        )
        from carl_bench.commissioning_runner import verify_protected_pair_evaluation
        from carl_bench.promotion import (
            PromotionExpectation,
            ProtectedValidationReceipt,
            SignedProtectedValidation,
            verify_protected_validation,
        )

        refs = self._artifact_map(artifact_refs)
        required = {
            "bare_refs_snapshot",
            "commissioning_effects_snapshot",
            "lifecycle_chain_receipt",
            "lifecycle_export",
            "protected_public_key",
            "signed_protected_receipt",
            "supervisor_record",
            "supervisor_result",
            "tamper_probe",
        }
        if not required.issubset(refs):
            raise CommissioningArtifactError("commissioning_source_artifact_missing")
        for ref in refs.values():
            self.read(ref)

        manifest, projection, autonomy = self._replay_lifecycle_export(
            export_ref=refs["lifecycle_export"],
            chain_ref=refs["lifecycle_chain_receipt"],
        )
        publication = autonomy.experimental_publication
        validation = autonomy.protected_validation
        promotion = autonomy.promotion
        if (
            projection.candidate is None
            or publication is None
            or validation is None
            or promotion is None
            or autonomy.revert is not None
            or not autonomy.soak_observations
        ):
            raise CommissioningArtifactError("commissioning_lifecycle_incomplete")
        candidate = projection.candidate
        if (
            candidate.digest != publication.candidate_packet_digest
            or candidate.candidate_commit != publication.commit
            or validation.candidate_commit != publication.commit
            or validation.candidate_tree != publication.tree
            or promotion.merge_tree != publication.tree
            or any(
                not item.healthy or item.merge_commit != promotion.merge_commit
                for item in autonomy.soak_observations
            )
        ):
            raise CommissioningArtifactError("commissioning_lifecycle_identity_mismatch")
        merged_at = _parse_utc(promotion.merged_at, "commissioning_promotion_time_invalid")
        latest_soak = max(
            _parse_utc(item.observed_at, "commissioning_soak_time_invalid")
            for item in autonomy.soak_observations
        )
        if (latest_soak - merged_at).total_seconds() < 24 * 60 * 60:
            raise CommissioningArtifactError("commissioning_soak_incomplete")

        capability_refs = tuple(
            ref for name, ref in artifact_refs if name.startswith("capability_bundle_")
        )
        if len(capability_refs) != 3:
            raise CommissioningArtifactError("commissioning_capability_evidence_incomplete")
        evaluations = tuple(
            verify_protected_pair_evaluation(
                artifacts=self._objects,
                evidence_bundle_ref=ref,
            )
            for ref in capability_refs
        )
        eligible = tuple(item for item in evaluations if item.report.eligible)
        if len(eligible) != 1:
            raise CommissioningArtifactError("commissioning_capability_evidence_invalid")
        accepted_evaluation = eligible[0]
        if (
            accepted_evaluation.baseline_commit != manifest.parent_commit
            or accepted_evaluation.candidate_commit != publication.commit
            or accepted_evaluation.candidate_tree != publication.tree
        ):
            raise CommissioningArtifactError("commissioning_capability_identity_mismatch")
        rejected = tuple(item for item in evaluations if not item.report.eligible)
        gaming = any(
            any(path.endswith("/task.toml") for path in item.changed_paths)
            and "active_evaluator_modified" in item.report.reasons
            and "transfer_gain_required" in item.report.reasons
            for item in rejected
        )
        evaluator_altered = any(
            any(path.endswith("/evaluator.json") for path in item.changed_paths)
            and "active_evaluator_modified" in item.report.reasons
            for item in rejected
        )
        if not gaming or not evaluator_altered:
            raise CommissioningArtifactError("commissioning_adversarial_capability_missing")

        envelope_value = self._json_object(
            self.read(refs["signed_protected_receipt"]),
            "commissioning_protected_receipt_invalid",
        )
        if set(envelope_value) != {"key_id", "receipt", "signature_base64"}:
            raise CommissioningArtifactError("commissioning_protected_receipt_invalid")
        try:
            receipt = ProtectedValidationReceipt(**envelope_value["receipt"])
            envelope = SignedProtectedValidation(
                receipt=receipt,
                key_id=envelope_value["key_id"],
                signature_base64=envelope_value["signature_base64"],
            )
            expected = PromotionExpectation(
                experiment_id=manifest.experiment_id,
                manifest_digest=manifest.digest,
                policy_digest=receipt.policy_digest,
                parent_commit=manifest.parent_commit,
                candidate_commit=publication.commit,
                candidate_tree=publication.tree,
                executable_digest=receipt.executable_digest,
                adapter_digest=receipt.adapter_digest,
                task_set_digest=receipt.task_set_digest,
                metric_pack_digest=receipt.metric_pack_digest,
                model=receipt.model,
                effort=receipt.effort,
                environment_digest=receipt.environment_digest,
                capability_report_digest=accepted_evaluation.report.digest,
                transfer_gain_basis_points=(accepted_evaluation.report.transfer_gain_basis_points),
                capability_claim_type=accepted_evaluation.report.claim_type,
                affected_contract_cases_improved=(
                    accepted_evaluation.report.affected_contract_cases_improved
                ),
                capability_guards_non_inferior=(accepted_evaluation.report.guards_non_inferior),
            )
            verify_protected_validation(
                envelope,
                public_key_pem=self.read(refs["protected_public_key"]),
                expected=expected,
                now=_parse_utc(receipt.created_at, "commissioning_receipt_time_invalid"),
                changed_paths=accepted_evaluation.changed_paths,
            )
        except (TypeError, ValueError) as error:
            raise CommissioningArtifactError("commissioning_protected_receipt_invalid") from error
        if validation.receipt_digest != receipt.digest:
            raise CommissioningArtifactError("commissioning_protected_receipt_mismatch")

        effects = self._json_object(
            self.read(refs["commissioning_effects_snapshot"]),
            "commissioning_effects_invalid",
        )
        if effects.get("schema_version") != 1:
            raise CommissioningArtifactError("commissioning_effects_invalid")
        effect_items = effects.get("effects")
        if not isinstance(effect_items, list):
            raise CommissioningArtifactError("commissioning_effects_invalid")
        by_kind: dict[str, list[dict[str, Any]]] = {}
        for item in effect_items:
            if not isinstance(item, dict) or not isinstance(item.get("request"), dict):
                raise CommissioningArtifactError("commissioning_effects_invalid")
            try:
                request = EffectRequest.from_canonical_dict(item["request"])
            except ValueError as error:
                raise CommissioningArtifactError("commissioning_effects_invalid") from error
            if item.get("request_digest") != request.digest:
                raise CommissioningArtifactError("commissioning_effects_invalid")
            by_kind.setdefault(request.kind, []).append(item)
            if item.get("status") == "receipted":
                receipt_ref_value = item.get("receipt_ref")
                try:
                    effect_receipt_ref = ArtifactRef.from_canonical_dict(receipt_ref_value)
                except (ArtifactIntegrityError, TypeError, ValueError) as error:
                    raise CommissioningArtifactError("commissioning_effects_invalid") from error
                if effect_receipt_ref not in refs.values():
                    raise CommissioningArtifactError("commissioning_effect_receipt_missing")
                try:
                    verify_effect_receipt_ref(
                        artifacts=self._objects,
                        receipt_ref=effect_receipt_ref,
                        public_key_pem=self.read(refs["protected_public_key"]),
                        request=request,
                    )
                except ValueError as error:
                    raise CommissioningArtifactError(
                        "commissioning_effect_receipt_invalid"
                    ) from error

        def one(kind: str, status: str) -> tuple[dict[str, Any], EffectRequest]:
            items = [item for item in by_kind.get(kind, []) if item.get("status") == status]
            if len(items) != 1:
                raise CommissioningArtifactError("commissioning_effect_identity_missing")
            return items[0], EffectRequest.from_canonical_dict(items[0]["request"])

        _, promotion_effect = one("promotion_merge", "receipted")
        _, hard_effect = one("hard_regression_merge", "receipted")
        _, revert_effect = one("revert_merge", "receipted")
        changed_item, _ = one("main_precondition", "rejected")
        if (
            not isinstance(changed_item.get("result"), dict)
            or changed_item["result"].get("reason") != "production_parent_changed"
            or promotion_effect.pr is None
            or hard_effect.pr is None
            or revert_effect.pr is None
            or promotion_effect.target_commit != promotion.merge_commit
            or promotion_effect.target_tree != promotion.merge_tree
            or promotion_effect.pr.head_commit != publication.commit
            or promotion_effect.pr.head_tree != publication.tree
            or hard_effect.expected_old_commit != promotion_effect.target_commit
            or revert_effect.expected_old_commit != hard_effect.target_commit
            or revert_effect.target_tree != promotion_effect.target_tree
        ):
            raise CommissioningArtifactError("commissioning_effect_identity_mismatch")

        recoveries = effects.get("recoveries")
        invocations = effects.get("invocations")
        attempts = effects.get("protected_receipt_attempts")
        consumptions = effects.get("protected_receipt_consumptions")
        durable_lists = (recoveries, invocations, attempts, consumptions)
        if not all(isinstance(value, list) for value in durable_lists):
            raise CommissioningArtifactError("commissioning_effects_invalid")
        recovered_keys = {
            item.get("effect_key")
            for item in recoveries
            if isinstance(item, dict) and item.get("boundary") == "effect_without_receipt"
        }
        if len(recovered_keys) < 2 or not all(
            any(
                isinstance(item, dict)
                and item.get("effect_key") == key
                and item.get("action") == "recovered_effect_receipt"
                for item in invocations
            )
            and any(
                isinstance(item, dict)
                and item.get("effect_key") == key
                and item.get("action") == "already_receipted"
                for item in invocations
            )
            for key in recovered_keys
        ):
            raise CommissioningArtifactError("commissioning_recovery_evidence_invalid")
        attempt_outcomes = [
            item.get("outcome")
            for item in attempts
            if isinstance(item, dict) and item.get("receipt_digest") == receipt.digest
        ]
        if attempt_outcomes != ["consumed", "replay_rejected"] or not any(
            isinstance(item, dict)
            and item.get("receipt_digest") == receipt.digest
            and item.get("envelope_ref") == refs["signed_protected_receipt"].to_canonical_dict()
            for item in consumptions
        ):
            raise CommissioningArtifactError("commissioning_receipt_replay_missing")
        if any(
            not isinstance(item, dict)
            or item.get("envelope_ref") != refs["signed_protected_receipt"].to_canonical_dict()
            for item in attempts
            if isinstance(item, dict) and item.get("receipt_digest") == receipt.digest
        ):
            raise CommissioningArtifactError("commissioning_receipt_replay_missing")

        bare = self._json_object(
            self.read(refs["bare_refs_snapshot"]),
            "commissioning_bare_refs_invalid",
        )
        if set(bare) != {"refs", "schema_version"} or bare["schema_version"] != 1:
            raise CommissioningArtifactError("commissioning_bare_refs_invalid")
        raw_refs = bare["refs"]
        if not isinstance(raw_refs, list):
            raise CommissioningArtifactError("commissioning_bare_refs_invalid")
        git_refs = {
            item.get("ref"): (item.get("commit"), item.get("tree"))
            for item in raw_refs
            if isinstance(item, dict) and set(item) == {"commit", "ref", "tree"}
        }
        experimental_ref = f"refs/heads/experimental/{manifest.experiment_id}"
        if git_refs.get(experimental_ref) != (publication.commit, publication.tree) or git_refs.get(
            "refs/heads/main"
        ) != (revert_effect.target_commit, revert_effect.target_tree):
            raise CommissioningArtifactError("commissioning_bare_refs_mismatch")

        from carl_bench.supervisor_triggers import (
            SupervisorTrigger,
            SupervisorTriggerError,
            TriggerResolution,
        )

        supervisor = self._json_object(
            self.read(refs["supervisor_record"]),
            "commissioning_supervisor_invalid",
        )
        if (
            set(supervisor)
            != {
                "claim_id",
                "resolution",
                "revision",
                "schema_version",
                "trigger",
            }
            or supervisor.get("schema_version") != 1
        ):
            raise CommissioningArtifactError("commissioning_supervisor_invalid")
        try:
            trigger = SupervisorTrigger.from_canonical_dict(supervisor["trigger"])
            resolution = TriggerResolution.from_canonical_dict(supervisor["resolution"])
        except SupervisorTriggerError as error:
            raise CommissioningArtifactError("commissioning_supervisor_invalid") from error
        if (
            resolution.status != "resolved"
            or resolution.evidence_digest != receipt.digest
            or resolution.evidence_digest != trigger.evidence_digest
            or resolution.result_digest != refs["supervisor_result"].digest
            or not trigger.attempt_history
            or trigger.attempt_history[-1] != resolution.recovery_action
            or not isinstance(supervisor["claim_id"], str)
            or not supervisor["claim_id"]
            or isinstance(supervisor["revision"], bool)
            or not isinstance(supervisor["revision"], int)
            or supervisor["revision"] < 2
        ):
            raise CommissioningArtifactError("commissioning_supervisor_invalid")
        self._json_object(
            self.read(refs["supervisor_result"]),
            "commissioning_supervisor_result_invalid",
        )

        tamper_probe = self._json_object(
            self.read(refs["tamper_probe"]),
            "commissioning_tamper_probe_invalid",
        )
        source_ref = refs["commissioning_effects_snapshot"]
        forged_size = source_ref.byte_size + 1
        if forged_size > MAX_ARTIFACT_BYTES:
            forged_size = source_ref.byte_size - 1
        expected_probe = {
            "attack": "artifact_size_mismatch",
            "error_code": "artifact_size_mismatch",
            "forged_byte_size": forged_size,
            "outcome": "rejected",
            "schema_version": 1,
            "source_digest": source_ref.digest,
        }
        if tamper_probe != expected_probe:
            raise CommissioningArtifactError("commissioning_tamper_probe_invalid")
        try:
            self.read(
                ArtifactRef(
                    schema_version=source_ref.schema_version,
                    digest=source_ref.digest,
                    byte_size=forged_size,
                    media_type=source_ref.media_type,
                    evidence_kind=source_ref.evidence_kind,
                )
            )
        except CommissioningArtifactError as error:
            if error.code != "commissioning_artifact_invalid":
                raise CommissioningArtifactError("commissioning_tamper_probe_invalid") from error
        else:
            raise CommissioningArtifactError("commissioning_tamper_probe_invalid")

        outcomes = (
            "benchmark_gaming_rejected",
            "changed_main_rejected",
            "controller_effect_recovered",
            "duplicate_tick_idempotent",
            "evaluator_alteration_rejected",
            "exact_revert_restored_tree",
            "receipt_replay_rejected",
            "tampered_evidence_rejected",
        )
        return SourceDerivedCommissioningReport(
            schema_version=2,
            synthetic_test_only=True,
            status="synthetic_passed",
            experiment_id=manifest.experiment_id,
            terminal_state="accepted",
            experimental_ref=experimental_ref,
            candidate_commit=publication.commit,
            candidate_tree=publication.tree,
            promotion_id=promotion_effect.pr.promotion_id,
            pull_request_number=promotion_effect.pr.number,
            merge_commit=promotion_effect.target_commit,
            merge_tree=promotion_effect.target_tree,
            production_ref="refs/heads/main",
            hard_failure_promotion_id=hard_effect.pr.promotion_id,
            hard_failure_pull_request_number=hard_effect.pr.number,
            hard_failure_candidate_commit=hard_effect.pr.head_commit,
            hard_failure_merge_commit=hard_effect.target_commit,
            revert_promotion_id=revert_effect.pr.promotion_id,
            revert_pull_request_number=revert_effect.pr.number,
            revert_candidate_commit=revert_effect.pr.head_commit,
            revert_merge_commit=revert_effect.target_commit,
            restored_tree=revert_effect.target_tree,
            restart_recoveries=len(recovered_keys),
            remote_cloud_acceptance="uncommissioned",
            adversarial_outcomes=outcomes,
            artifact_refs=artifact_refs,
        )

    def build_synthetic(
        self, sources: SyntheticCommissioningSources
    ) -> CommissioningArtifactBundle:
        if not isinstance(sources, SyntheticCommissioningSources):
            raise CommissioningArtifactError("invalid_commissioning_evidence_sources")
        from carl_bench.commissioning_controller import (
            CommissioningControllerError,
            CommissioningEffectStore,
        )
        from carl_bench.commissioning_runner import verify_protected_pair_evaluation
        from carl_bench.supervisor_triggers import SupervisorTriggerError, SupervisorTriggerStore

        for path in (
            sources.ledger_path,
            sources.effect_store_path,
            sources.protected_public_key_path,
            sources.supervisor_store_path,
        ):
            if not _inside(_anchored(path), self.automation_data_root):
                raise CommissioningArtifactError("commissioning_source_outside_automation_root")
        captured_export, captured_chain = self.capture_lifecycle_sources(
            experiment_id=sources.experiment_id,
            ledger_path=sources.ledger_path,
        )
        if (
            captured_export != sources.lifecycle_export_ref
            or captured_chain != sources.lifecycle_chain_receipt_ref
        ):
            raise CommissioningArtifactError("commissioning_lifecycle_source_mismatch")
        if self.capture_bare_refs(sources.bare_repository) != sources.bare_refs_snapshot_ref:
            raise CommissioningArtifactError("commissioning_bare_refs_mismatch")
        if self.capture_effects_snapshot(sources.effect_store_path) != sources.effects_snapshot_ref:
            raise CommissioningArtifactError("commissioning_effects_source_mismatch")
        if len(sources.capability_evidence_refs) != 3:
            raise CommissioningArtifactError("commissioning_capability_evidence_incomplete")
        verified_capabilities = tuple(
            verify_protected_pair_evaluation(
                artifacts=self._objects,
                evidence_bundle_ref=ref,
            )
            for ref in sources.capability_evidence_refs
        )
        if not _owner_private_file(_anchored(sources.protected_public_key_path)):
            raise CommissioningArtifactError("commissioning_protected_public_key_invalid")
        public_key_ref = self._objects.put(
            evidence_kind="protected_public_key",
            media_type="application/x-pem-file",
            content=_anchored(sources.protected_public_key_path).read_bytes(),
        )
        try:
            supervisor = SupervisorTriggerStore(sources.supervisor_store_path).get(
                sources.supervisor_trigger_id
            )
        except SupervisorTriggerError as error:
            raise CommissioningArtifactError("commissioning_supervisor_invalid") from error
        if supervisor.resolution is None:
            raise CommissioningArtifactError("commissioning_supervisor_invalid")
        if self.read(sources.supervisor_result_ref) is None:  # pragma: no cover
            raise AssertionError("artifact read unexpectedly returned no bytes")
        supervisor_record_ref = self._objects.put(
            evidence_kind="supervisor_record",
            media_type="application/json",
            content=canonical_json_bytes(
                {
                    "claim_id": supervisor.claim_id,
                    "resolution": supervisor.resolution.to_canonical_dict(),
                    "revision": supervisor.revision,
                    "schema_version": 1,
                    "trigger": supervisor.trigger.to_canonical_dict(),
                }
            ),
        )
        try:
            effect_snapshot = CommissioningEffectStore(
                sources.effect_store_path
            ).validated_snapshot()
        except CommissioningControllerError as error:
            raise CommissioningArtifactError("commissioning_effects_invalid") from error

        named_refs: list[tuple[str, ArtifactRef]] = [
            ("bare_refs_snapshot", sources.bare_refs_snapshot_ref),
            ("commissioning_effects_snapshot", sources.effects_snapshot_ref),
            ("lifecycle_chain_receipt", sources.lifecycle_chain_receipt_ref),
            ("lifecycle_export", sources.lifecycle_export_ref),
            ("protected_public_key", public_key_ref),
            ("signed_protected_receipt", sources.signed_protected_receipt_ref),
            ("supervisor_record", supervisor_record_ref),
            ("supervisor_result", sources.supervisor_result_ref),
        ]
        tamper_source = sources.effects_snapshot_ref
        forged_size = tamper_source.byte_size + 1
        if forged_size > MAX_ARTIFACT_BYTES:
            forged_size = tamper_source.byte_size - 1
        try:
            self.read(
                ArtifactRef(
                    schema_version=tamper_source.schema_version,
                    digest=tamper_source.digest,
                    byte_size=forged_size,
                    media_type=tamper_source.media_type,
                    evidence_kind=tamper_source.evidence_kind,
                )
            )
        except CommissioningArtifactError as error:
            if error.code != "commissioning_artifact_invalid":
                raise CommissioningArtifactError("commissioning_tamper_probe_invalid") from error
        else:
            raise CommissioningArtifactError("commissioning_tamper_probe_invalid")
        tamper_probe_ref = self._objects.put(
            evidence_kind="commissioning_tamper_probe",
            media_type="application/json",
            content=canonical_json_bytes(
                {
                    "attack": "artifact_size_mismatch",
                    "error_code": "artifact_size_mismatch",
                    "forged_byte_size": forged_size,
                    "outcome": "rejected",
                    "schema_version": 1,
                    "source_digest": tamper_source.digest,
                }
            ),
        )
        named_refs.append(("tamper_probe", tamper_probe_ref))
        for index, (source_ref, verified) in enumerate(
            zip(sources.capability_evidence_refs, verified_capabilities, strict=True)
        ):
            named_refs.append((f"capability_bundle_{index}", source_ref))
            named_refs.extend(
                (f"capability_{index}_{name}", ref) for name, ref in verified.artifact_refs
            )
        for index, effect in enumerate(effect_snapshot["effects"]):
            if effect["receipt_ref"] is not None:
                named_refs.append(
                    (
                        f"effect_receipt_{index}",
                        ArtifactRef.from_canonical_dict(effect["receipt_ref"]),
                    )
                )
        artifact_refs = tuple(sorted(named_refs, key=lambda item: item[0]))
        report = self._derive_source_report(artifact_refs)
        try:
            report_ref = self._objects.put(
                evidence_kind="commissioning_report",
                media_type="application/json",
                content=canonical_json_bytes(report.to_canonical_dict()),
            )
        except ArtifactIntegrityError as error:
            raise CommissioningArtifactError("commissioning_artifact_write_failed") from error
        bundle = CommissioningArtifactBundle(None, None, report, report_ref)
        self._write_v2_index(bundle)
        return bundle

    def _persist_verified_receipt(
        self, receipt: SyntheticCommissioningReceipt
    ) -> CommissioningArtifactBundle:
        """Persist only a receipt produced internally after source verification."""
        try:
            receipt_ref = self._objects.put(
                evidence_kind="commissioning_receipt",
                media_type="application/json",
                content=canonical_json_bytes(receipt.to_canonical_dict()),
            )
            report = self._report(receipt, receipt_ref)
            report_ref = self._objects.put(
                evidence_kind="commissioning_report",
                media_type="application/json",
                content=canonical_json_bytes(report.to_canonical_dict()),
            )
        except ArtifactIntegrityError as error:
            raise CommissioningArtifactError("commissioning_artifact_write_failed") from error
        bundle = CommissioningArtifactBundle(receipt, receipt_ref, report, report_ref)
        self._write_index(bundle)
        return bundle

    def _write_index(self, bundle: CommissioningArtifactBundle) -> None:
        if bundle.receipt is None or bundle.receipt_ref is None:
            raise CommissioningArtifactError("invalid_legacy_commissioning_bundle")
        encoded = canonical_json_bytes(
            {
                "report_ref": bundle.report_ref.to_canonical_dict(),
                "receipt_ref": bundle.receipt_ref.to_canonical_dict(),
                "schema_version": 1,
                "synthetic_test_only": True,
            }
        )
        temporary: Path | None = None
        try:
            descriptor, name = tempfile.mkstemp(prefix=".pending-", dir=self.root)
            temporary = Path(name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            if os.name != "nt":
                temporary.chmod(0o600)
            os.replace(temporary, self.index_path)
            temporary = None
        except OSError as error:
            raise CommissioningArtifactError("commissioning_index_write_failed") from error
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        if not _owner_private_file(self.index_path):
            raise CommissioningArtifactError("commissioning_index_unsafe")

    def _write_v2_index(self, bundle: CommissioningArtifactBundle) -> None:
        encoded = canonical_json_bytes(
            {
                "report_ref": bundle.report_ref.to_canonical_dict(),
                "schema_version": 2,
                "synthetic_test_only": True,
            }
        )
        temporary: Path | None = None
        try:
            descriptor, name = tempfile.mkstemp(prefix=".pending-", dir=self.root)
            temporary = Path(name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            if os.name != "nt":
                temporary.chmod(0o600)
            os.replace(temporary, self.index_path)
            temporary = None
        except OSError as error:
            raise CommissioningArtifactError("commissioning_index_write_failed") from error
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        if not _owner_private_file(self.index_path):
            raise CommissioningArtifactError("commissioning_index_unsafe")

    def load_latest_synthetic(self) -> CommissioningArtifactBundle:
        if not _owner_private_file(self.index_path):
            raise CommissioningArtifactError("commissioning_index_unsafe")
        try:
            value = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise CommissioningArtifactError("commissioning_index_invalid") from error
        if isinstance(value, dict) and value.get("schema_version") == 1:
            raise CommissioningArtifactError("commissioning_verified_sources_required")
        if isinstance(value, dict) and value.get("schema_version") == 2:
            if set(value) != {"report_ref", "schema_version", "synthetic_test_only"} or (
                value.get("synthetic_test_only") is not True
            ):
                raise CommissioningArtifactError("commissioning_index_invalid")
            try:
                report_ref = ArtifactRef.from_canonical_dict(value["report_ref"])
                report = SourceDerivedCommissioningReport.from_canonical_dict(
                    json.loads(self.read(report_ref))
                )
            except (ArtifactIntegrityError, UnicodeError, json.JSONDecodeError) as error:
                raise CommissioningArtifactError("commissioning_index_invalid") from error
            expected = self._derive_source_report(report.artifact_refs)
            if report != expected or report.digest != report_ref.digest:
                raise CommissioningArtifactError("commissioning_report_mismatch")
            return CommissioningArtifactBundle(None, None, report, report_ref)
        if not isinstance(value, dict) or set(value) != {
            "report_ref",
            "receipt_ref",
            "schema_version",
            "synthetic_test_only",
        }:
            raise CommissioningArtifactError("commissioning_index_invalid")
        if value["schema_version"] != 1 or value["synthetic_test_only"] is not True:
            raise CommissioningArtifactError("commissioning_index_invalid")
        try:
            receipt_ref = ArtifactRef.from_canonical_dict(value["receipt_ref"])
            report_ref = ArtifactRef.from_canonical_dict(value["report_ref"])
            receipt = SyntheticCommissioningReceipt.from_canonical_dict(
                json.loads(self.read(receipt_ref))
            )
            report = SanitizedCommissioningReport.from_canonical_dict(
                json.loads(self.read(report_ref))
            )
        except (ArtifactIntegrityError, UnicodeError, json.JSONDecodeError) as error:
            raise CommissioningArtifactError("commissioning_index_invalid") from error
        expected = self._report(receipt, receipt_ref)
        if report != expected or report.digest != report_ref.digest:
            raise CommissioningArtifactError("commissioning_report_mismatch")
        return CommissioningArtifactBundle(receipt, receipt_ref, report, report_ref)
