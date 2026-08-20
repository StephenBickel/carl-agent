"""Owner-private artifacts for non-production autonomy commissioning."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from carl_bench.artifacts import ArtifactIntegrityError, ArtifactRef, PrivateArtifactStore
from carl_bench.canonical import canonical_json_bytes

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
    receipt: SyntheticCommissioningReceipt
    receipt_ref: ArtifactRef
    report: SanitizedCommissioningReport
    report_ref: ArtifactRef


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
        if not isinstance(receipt, SyntheticCommissioningReceipt):
            raise CommissioningArtifactError("invalid_commissioning_receipt")
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

    def load_latest_synthetic(self) -> CommissioningArtifactBundle:
        if not _owner_private_file(self.index_path):
            raise CommissioningArtifactError("commissioning_index_unsafe")
        try:
            value = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise CommissioningArtifactError("commissioning_index_invalid") from error
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
