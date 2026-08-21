"""Narrow, idempotent publication of immutable experimental candidate refs."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from carl_bench.candidate import SealedCandidate
from carl_bench.canonical import CanonicalizationError, canonical_json_bytes
from carl_bench.capability_validation import (
    ExperimentalCheckResult,
    ExperimentalPublicationEligibility,
    experimental_publication_request_digest,
    experimental_remote_url,
    experimental_repository_id,
)

_OBJECT_ID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SIGNATURE_DOMAIN = "carl.experimental-publication-eligibility.v1"
_PROTECTED_GIT_EXECUTABLE = Path("/usr/bin/git")

PublicationOutcome = Literal[
    "push_branch",
    "record_existing_exact_branch",
    "blocked_branch_identity_mismatch",
    "blocked_candidate_packet_incomplete",
    "blocked_candidate_not_locally_eligible",
]


class ExperimentalPublicationError(ValueError):
    """A stable publication-gateway failure that does not echo Git output."""


def _canonical_signature(value: object) -> bytes:
    if not isinstance(value, str):
        raise ExperimentalPublicationError("experimental_eligibility_signature_invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ExperimentalPublicationError("experimental_eligibility_signature_invalid") from error
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        raise ExperimentalPublicationError("experimental_eligibility_signature_invalid")
    return decoded


@dataclass(frozen=True, slots=True)
class ExperimentalPublicationPolicy:
    """Backend-owned trust root and exact Git destination for experimental publication."""

    schema_version: int
    key_id: str
    public_key_pem: bytes
    repository_id: str
    remote_url: str

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("ExperimentalPublicationPolicy cannot be subclassed")

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ExperimentalPublicationError("experimental_policy_schema_invalid")
        if not isinstance(self.key_id, str) or _KEY_ID_RE.fullmatch(self.key_id) is None:
            raise ExperimentalPublicationError("experimental_eligibility_key_id_invalid")
        if not isinstance(self.public_key_pem, bytes) or len(self.public_key_pem) > 16_384:
            raise ExperimentalPublicationError("experimental_eligibility_public_key_invalid")
        try:
            key = serialization.load_pem_public_key(self.public_key_pem)
        except (TypeError, ValueError) as error:
            raise ExperimentalPublicationError(
                "experimental_eligibility_public_key_invalid"
            ) from error
        if not isinstance(key, Ed25519PublicKey):
            raise ExperimentalPublicationError("experimental_eligibility_public_key_invalid")
        try:
            experimental_repository_id(self.repository_id)
            experimental_remote_url(self.remote_url, self.repository_id)
        except ValueError as error:
            raise ExperimentalPublicationError(str(error)) from error

    @property
    def public_key(self) -> Ed25519PublicKey:
        key = serialization.load_pem_public_key(self.public_key_pem)
        if not isinstance(key, Ed25519PublicKey):  # pragma: no cover - constructor guards
            raise ExperimentalPublicationError("experimental_eligibility_public_key_invalid")
        return key

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "public_key_pem": self.public_key_pem.decode("ascii"),
            "remote_url": self.remote_url,
            "repository_id": self.repository_id,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_canonical_dict(cls, value: object) -> ExperimentalPublicationPolicy:
        if type(value) is not dict or set(value) != {
            "key_id",
            "public_key_pem",
            "remote_url",
            "repository_id",
            "schema_version",
        }:
            raise ExperimentalPublicationError("experimental_policy_keys_invalid")
        public_key_pem = value["public_key_pem"]
        if not isinstance(public_key_pem, str):
            raise ExperimentalPublicationError("experimental_eligibility_public_key_invalid")
        try:
            return cls(
                schema_version=value["schema_version"],
                key_id=value["key_id"],
                public_key_pem=public_key_pem.encode("ascii"),
                repository_id=value["repository_id"],
                remote_url=value["remote_url"],
            )
        except (TypeError, UnicodeEncodeError, ValueError) as error:
            if isinstance(error, ExperimentalPublicationError):
                raise
            raise ExperimentalPublicationError("experimental_policy_invalid") from error


@dataclass(frozen=True, slots=True)
class SignedExperimentalPublicationEligibility:
    """Raw signed experimental receipt wire, nominally distinct from production validation."""

    receipt: ExperimentalPublicationEligibility
    signature_base64: str

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("SignedExperimentalPublicationEligibility cannot be subclassed")

    def __post_init__(self) -> None:
        if type(self.receipt) is not ExperimentalPublicationEligibility:
            raise ExperimentalPublicationError("experimental_eligibility_receipt_invalid")
        _canonical_signature(self.signature_base64)

    def signing_payload(self) -> bytes:
        try:
            return canonical_json_bytes(
                {
                    "domain": _SIGNATURE_DOMAIN,
                    "receipt": self.receipt.to_canonical_dict(),
                    "schema_version": 1,
                }
            )
        except CanonicalizationError as error:
            raise ExperimentalPublicationError(
                "experimental_eligibility_receipt_invalid"
            ) from error

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "receipt": self.receipt.to_canonical_dict(),
            "signature_base64": self.signature_base64,
        }

    @classmethod
    def from_canonical_dict(cls, value: object) -> SignedExperimentalPublicationEligibility:
        if type(value) is not dict or set(value) != {"receipt", "signature_base64"}:
            raise ExperimentalPublicationError("experimental_eligibility_envelope_invalid")
        try:
            return cls(
                receipt=ExperimentalPublicationEligibility.from_canonical_dict(value["receipt"]),
                signature_base64=value["signature_base64"],
            )
        except (TypeError, ValueError) as error:
            if isinstance(error, ExperimentalPublicationError):
                raise
            raise ExperimentalPublicationError(
                "experimental_eligibility_envelope_invalid"
            ) from error


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ExperimentalEligibilityVerifier:
    """Immutable verifier for one signed publication effect using controller-owned time.

    A valid envelope is safe to replay only for the same immutable effect. Persistence and atomic
    consumption of that effect key belong to the durable command boundary introduced by Task 7.
    Hostile code already executing inside this trusted process is outside this object boundary.
    """

    __slots__ = ("_clock", "_policy")

    def __init_subclass__(cls, **kwargs: object) -> None:
        raise TypeError("ExperimentalEligibilityVerifier cannot be subclassed")

    def __init__(
        self,
        *,
        policy: ExperimentalPublicationPolicy,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if type(policy) is not ExperimentalPublicationPolicy:
            raise ExperimentalPublicationError("experimental_eligibility_policy_missing")
        if not callable(clock):
            raise ExperimentalPublicationError("experimental_eligibility_trusted_clock_missing")
        object.__setattr__(self, "_policy", policy)
        object.__setattr__(self, "_clock", clock)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ExperimentalEligibilityVerifier is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("ExperimentalEligibilityVerifier is immutable")

    def __copy__(self) -> ExperimentalEligibilityVerifier:
        raise TypeError("ExperimentalEligibilityVerifier cannot be copied or serialized")

    def __deepcopy__(self, memo: object) -> ExperimentalEligibilityVerifier:
        raise TypeError("ExperimentalEligibilityVerifier cannot be copied or serialized")

    def __reduce__(self) -> object:
        raise TypeError("ExperimentalEligibilityVerifier cannot be copied or serialized")

    def __reduce_ex__(self, protocol: int) -> object:
        raise TypeError("ExperimentalEligibilityVerifier cannot be copied or serialized")

    @property
    def repository_id(self) -> str:
        return object.__getattribute__(self, "_policy").repository_id

    @property
    def remote_url(self) -> str:
        return object.__getattribute__(self, "_policy").remote_url

    def require(
        self,
        envelope: SignedExperimentalPublicationEligibility,
        request: ExperimentalPublicationRequest,
    ) -> None:
        now = object.__getattribute__(self, "_clock")()
        if not isinstance(now, datetime) or now.tzinfo != UTC:
            raise ExperimentalPublicationError("experimental_eligibility_trusted_clock_invalid")
        if type(envelope) is not SignedExperimentalPublicationEligibility:
            raise ExperimentalPublicationError("experimental_eligibility_envelope_invalid")
        receipt = envelope.receipt
        policy = object.__getattribute__(self, "_policy")
        if receipt.key_id != policy.key_id:
            raise ExperimentalPublicationError("experimental_eligibility_key_mismatch")
        if (
            request.repository_id != policy.repository_id
            or request.remote_url != policy.remote_url
            or receipt.repository_id != policy.repository_id
            or receipt.remote_url != policy.remote_url
        ):
            raise ExperimentalPublicationError("experimental_eligibility_destination_mismatch")
        try:
            policy.public_key.verify(
                _canonical_signature(envelope.signature_base64),
                SignedExperimentalPublicationEligibility.signing_payload(envelope),
            )
        except InvalidSignature as error:
            raise ExperimentalPublicationError(
                "experimental_eligibility_signature_invalid"
            ) from error
        issued = datetime.fromisoformat(receipt.issued_at.removesuffix("Z") + "+00:00")
        expires = datetime.fromisoformat(receipt.expires_at.removesuffix("Z") + "+00:00")
        if now < issued:
            raise ExperimentalPublicationError("experimental_eligibility_not_yet_valid")
        if now >= expires:
            raise ExperimentalPublicationError("experimental_eligibility_expired")
        if not receipt.eligible or not _eligible_for_request(receipt, request):
            raise ExperimentalPublicationError("experimental_eligibility_effect_mismatch")


@dataclass(frozen=True, slots=True)
class ExperimentalPublicationRequest:
    experiment_id: str
    branch: str
    candidate_packet: SealedCandidate
    candidate_tree: str
    request_id: str
    requested_at: str
    repository_id: str
    remote_url: str

    def __post_init__(self) -> None:
        try:
            experimental_repository_id(self.repository_id)
            experimental_remote_url(self.remote_url, self.repository_id)
        except ValueError as error:
            raise ExperimentalPublicationError(str(error)) from error


@dataclass(frozen=True, slots=True)
class ExperimentalPublicationDecision:
    outcome: PublicationOutcome
    ref: str
    candidate_commit: str | None
    candidate_tree: str | None
    candidate_packet_digest: str | None


def _ref(experiment_id: str, branch: str) -> str:
    if not isinstance(experiment_id, str) or not experiment_id:
        raise ExperimentalPublicationError("experimental_experiment_invalid")
    if branch != f"experimental/{experiment_id}":
        raise ExperimentalPublicationError("experimental_branch_invalid")
    return f"refs/heads/{branch}"


def _decision(
    outcome: PublicationOutcome,
    request: ExperimentalPublicationRequest,
    ref: str,
) -> ExperimentalPublicationDecision:
    packet = request.candidate_packet
    if not isinstance(packet, SealedCandidate):
        return ExperimentalPublicationDecision(outcome, ref, None, None, None)
    return ExperimentalPublicationDecision(
        outcome,
        ref,
        packet.candidate_commit,
        request.candidate_tree if isinstance(request.candidate_tree, str) else None,
        packet.digest,
    )


def reconcile_experimental_publication(
    request: ExperimentalPublicationRequest,
    remote_snapshot: str | None,
    *,
    verifier: ExperimentalEligibilityVerifier,
    eligibility: SignedExperimentalPublicationEligibility,
) -> ExperimentalPublicationDecision:
    """Choose the only permitted immutable effect after point-of-use receipt verification."""
    ref = _ref(request.experiment_id, request.branch)
    packet = request.candidate_packet
    if (
        not isinstance(packet, SealedCandidate)
        or packet.experiment_id != request.experiment_id
        or not packet.all_checks_passed
        or not isinstance(request.candidate_tree, str)
        or not _OBJECT_ID_RE.fullmatch(request.candidate_tree)
    ):
        return _decision("blocked_candidate_packet_incomplete", request, ref)
    if type(verifier) is not ExperimentalEligibilityVerifier:
        raise ExperimentalPublicationError("experimental_eligibility_verifier_missing")
    try:
        ExperimentalEligibilityVerifier.require(verifier, eligibility, request)
    except ExperimentalPublicationError:
        return _decision("blocked_candidate_not_locally_eligible", request, ref)
    if remote_snapshot is None:
        return _decision("push_branch", request, ref)
    if not isinstance(remote_snapshot, str) or not _OBJECT_ID_RE.fullmatch(remote_snapshot):
        raise ExperimentalPublicationError("experimental_remote_snapshot_invalid")
    if remote_snapshot != packet.candidate_commit:
        return _decision("blocked_branch_identity_mismatch", request, ref)
    return _decision("record_existing_exact_branch", request, ref)


def _eligible_for_request(
    receipt: ExperimentalPublicationEligibility,
    request: ExperimentalPublicationRequest,
) -> bool:
    packet = request.candidate_packet
    checks = tuple(
        ExperimentalCheckResult(
            check_id=check.check_id,
            status=check.status,
            exit_code=check.exit_code,
            output_digest=check.output_artifact.digest,
        )
        for check in packet.checks
    )
    try:
        request_digest = experimental_publication_request_digest(
            request_id=request.request_id,
            requested_at=request.requested_at,
            experiment_id=request.experiment_id,
            branch=request.branch,
            candidate_packet_digest=packet.digest,
            candidate_commit=packet.candidate_commit,
            candidate_tree=request.candidate_tree,
            repository_id=request.repository_id,
            remote_url=request.remote_url,
        )
    except ValueError:
        return False
    return (
        receipt.request_id == request.request_id
        and receipt.requested_at == request.requested_at
        and receipt.request_digest == request_digest
        and receipt.effect_digest == request_digest
        and receipt.experiment_id == request.experiment_id
        and receipt.branch == request.branch
        and receipt.ref == f"refs/heads/{request.branch}"
        and receipt.candidate_packet_digest == packet.digest
        and receipt.candidate_commit == packet.candidate_commit
        and receipt.candidate_tree == request.candidate_tree
        and receipt.repository_id == request.repository_id
        and receipt.remote_url == request.remote_url
        and receipt.required_checks == checks
    )


class _ProtectedGitTransport:
    """Fixed, identity-pinned Git transport with a caller-independent environment."""

    __slots__ = ("_digest", "_identity")

    def __init__(self) -> None:
        identity, digest = self._read_identity()
        object.__setattr__(self, "_identity", identity)
        object.__setattr__(self, "_digest", digest)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("protected Git transport is immutable")

    @staticmethod
    def _read_identity() -> tuple[tuple[int, int, int, int, int], bytes]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(_PROTECTED_GIT_EXECUTABLE, flags)
        except OSError as error:
            raise ExperimentalPublicationError("experimental_git_unavailable") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise ExperimentalPublicationError("experimental_git_identity_invalid")
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 1024 * 1024):
                digest.update(chunk)
            identity = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_uid,
            )
            return identity, digest.digest()
        finally:
            os.close(descriptor)

    def _command(self, *args: str) -> str:
        identity, digest = self._read_identity()
        if identity != self._identity or digest != self._digest:
            raise ExperimentalPublicationError("experimental_git_identity_changed")
        environment = {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": "/var/empty",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
        try:
            result = subprocess.run(
                (os.fspath(_PROTECTED_GIT_EXECUTABLE), *args),
                check=False,
                capture_output=True,
                env=environment,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ExperimentalPublicationError("experimental_git_unavailable") from error
        if result.returncode != 0:
            raise ExperimentalPublicationError("experimental_git_failed")
        return result.stdout.strip()

    def local(self, repository: Path, *args: str) -> str:
        return self._command("-C", os.fspath(repository), *args)

    def network(self, repository: Path, operation: str, remote_url: str, *args: str) -> str:
        if operation not in {"fetch", "ls-remote", "push"}:
            raise ExperimentalPublicationError("experimental_git_operation_invalid")
        # The exact URL is repeated as a same-to-same longest-prefix rewrite. This prevents a
        # repository-local url.*.insteadOf rule from replacing the signed destination.
        protected_config = (
            "-c",
            "credential.helper=",
            "-c",
            "core.askPass=",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "http.proxy=",
            "-c",
            f"http.{remote_url}.proxy=",
            "-c",
            "http.curloptResolve=",
            "-c",
            f"http.{remote_url}.curloptResolve=",
            "-c",
            "http.followRedirects=initial",
            "-c",
            f"http.{remote_url}.followRedirects=initial",
            "-c",
            "http.sslVerify=true",
            "-c",
            f"http.{remote_url}.sslVerify=true",
            "-c",
            f"url.{remote_url}.insteadOf={remote_url}",
        )
        if operation == "ls-remote":
            return self._command(
                *protected_config,
                "-C",
                os.fspath(repository),
                operation,
                "--refs",
                remote_url,
                *args,
            )
        if len(args) != 2:
            raise ExperimentalPublicationError("experimental_git_operation_invalid")
        return self._command(
            *protected_config,
            "-C",
            os.fspath(repository),
            operation,
            args[0],
            remote_url,
            args[1],
        )


def _protected_git_transport() -> _ProtectedGitTransport:
    return _ProtectedGitTransport()


def candidate_tree(repository: Path, candidate_commit: str) -> str:
    """Resolve the tree object for the exact candidate commit with an argument vector."""
    tree = _protected_git_transport().local(repository, "rev-parse", f"{candidate_commit}^{{tree}}")
    if not _OBJECT_ID_RE.fullmatch(tree):
        raise ExperimentalPublicationError("experimental_candidate_tree_invalid")
    return tree


def publish_experimental_branch(
    request: ExperimentalPublicationRequest,
    *,
    verifier: ExperimentalEligibilityVerifier,
    eligibility: SignedExperimentalPublicationEligibility,
    repository: Path,
) -> ExperimentalPublicationDecision:
    """Push one exact non-force ref, refetch it, and confirm the resulting object identity."""
    transport = _protected_git_transport()
    ref = _ref(request.experiment_id, request.branch)
    snapshot = _remote_snapshot(transport, repository, request.remote_url, ref)
    decision = reconcile_experimental_publication(
        request,
        snapshot,
        verifier=verifier,
        eligibility=eligibility,
    )
    if decision.outcome != "push_branch":
        return decision
    assert decision.candidate_commit is not None
    transport.network(
        repository,
        "push",
        request.remote_url,
        f"--force-with-lease={decision.ref}:",
        f"{decision.candidate_commit}:{decision.ref}",
    )
    tracking_ref = f"refs/carl/experimental-verification/{request.experiment_id}"
    transport.network(
        repository,
        "fetch",
        request.remote_url,
        "--no-tags",
        f"{decision.ref}:{tracking_ref}",
    )
    fetched = transport.local(repository, "rev-parse", tracking_ref)
    if fetched != decision.candidate_commit:
        raise ExperimentalPublicationError("experimental_remote_verification_failed")
    verified = _remote_snapshot(transport, repository, request.remote_url, decision.ref)
    if verified != decision.candidate_commit:
        raise ExperimentalPublicationError("experimental_remote_verification_failed")
    return replace(decision, outcome="record_existing_exact_branch")


def _remote_snapshot(
    transport: _ProtectedGitTransport, repository: Path, remote_url: str, ref: str
) -> str | None:
    result = transport.network(repository, "ls-remote", remote_url, ref)
    if not result:
        return None
    lines = result.splitlines()
    if len(lines) != 1:
        raise ExperimentalPublicationError("experimental_remote_snapshot_invalid")
    fields = lines[0].split()
    if len(fields) != 2 or fields[1] != ref or not _OBJECT_ID_RE.fullmatch(fields[0]):
        raise ExperimentalPublicationError("experimental_remote_snapshot_invalid")
    return fields[0]
