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

from carl_bench.artifacts import ArtifactIntegrityError, ArtifactRef, PrivateArtifactStore
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
    receipt: SyntheticCommissioningReceipt
    receipt_ref: ArtifactRef
    report: SanitizedCommissioningReport
    report_ref: ArtifactRef


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
            _parse_utc(item.observed_at, "commissioning_soak_time_invalid")
            for item in observations
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
            raise CommissioningArtifactError(
                "caller_authored_commissioning_receipt_forbidden"
            )
        raise CommissioningArtifactError("invalid_commissioning_evidence_sources")

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
        if isinstance(value, dict) and value.get("schema_version") == 1:
            raise CommissioningArtifactError("commissioning_verified_sources_required")
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
