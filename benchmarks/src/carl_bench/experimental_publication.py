"""Narrow, idempotent publication of immutable experimental candidate refs."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from carl_bench.candidate import SealedCandidate
from carl_bench.capability_validation import CapabilityValidationReport

_OBJECT_ID_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

PublicationOutcome = Literal[
    "push_branch",
    "record_existing_exact_branch",
    "blocked_branch_identity_mismatch",
    "blocked_candidate_packet_incomplete",
    "blocked_candidate_not_locally_eligible",
]


class ExperimentalPublicationError(ValueError):
    """A stable publication-gateway failure that does not echo Git output."""


@dataclass(frozen=True, slots=True)
class ExperimentalPublicationRequest:
    experiment_id: str
    branch: str
    candidate_packet: SealedCandidate
    candidate_tree: str
    capability_report: CapabilityValidationReport


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
    request: ExperimentalPublicationRequest, remote_snapshot: str | None
) -> ExperimentalPublicationDecision:
    """Choose the only permitted immutable experimental-ref action for a remote snapshot."""
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
    report = request.capability_report
    if not isinstance(report, CapabilityValidationReport) or not report.eligible:
        return _decision("blocked_candidate_not_locally_eligible", request, ref)
    if remote_snapshot is None:
        return _decision("push_branch", request, ref)
    if not isinstance(remote_snapshot, str) or not _OBJECT_ID_RE.fullmatch(remote_snapshot):
        raise ExperimentalPublicationError("experimental_remote_snapshot_invalid")
    if remote_snapshot != packet.candidate_commit:
        return _decision("blocked_branch_identity_mismatch", request, ref)
    return _decision("record_existing_exact_branch", request, ref)


def candidate_tree(
    repository: Path, candidate_commit: str, git_executable: Path
) -> str:
    """Resolve the tree object for the exact candidate commit with an argument vector."""
    tree = _git(
        git_executable,
        "-C",
        str(repository),
        "rev-parse",
        f"{candidate_commit}^{{tree}}",
    )
    if not _OBJECT_ID_RE.fullmatch(tree):
        raise ExperimentalPublicationError("experimental_candidate_tree_invalid")
    return tree


def publish_experimental_branch(
    request: ExperimentalPublicationRequest,
    *,
    repository: Path,
    remote: str,
    git_executable: Path,
) -> ExperimentalPublicationDecision:
    """Push one exact non-force ref, refetch it, and confirm the resulting object identity."""
    if not isinstance(remote, str) or not _REMOTE_RE.fullmatch(remote):
        raise ExperimentalPublicationError("experimental_remote_invalid")
    ref = _ref(request.experiment_id, request.branch)
    snapshot = _remote_snapshot(git_executable, repository, remote, ref)
    decision = reconcile_experimental_publication(request, snapshot)
    if decision.outcome != "push_branch":
        return decision
    assert decision.candidate_commit is not None
    _git(
        git_executable,
        "-C",
        str(repository),
        "push",
        remote,
        f"{decision.candidate_commit}:{decision.ref}",
    )
    tracking_ref = f"refs/remotes/{remote}/{request.branch}"
    _git(
        git_executable,
        "-C",
        str(repository),
        "fetch",
        "--no-tags",
        remote,
        f"{decision.ref}:{tracking_ref}",
    )
    fetched = _git(git_executable, "-C", str(repository), "rev-parse", tracking_ref)
    if fetched != decision.candidate_commit:
        raise ExperimentalPublicationError("experimental_remote_verification_failed")
    verified = _remote_snapshot(git_executable, repository, remote, decision.ref)
    if verified != decision.candidate_commit:
        raise ExperimentalPublicationError("experimental_remote_verification_failed")
    return replace(decision, outcome="record_existing_exact_branch")


def _remote_snapshot(git_executable: Path, repository: Path, remote: str, ref: str) -> str | None:
    result = _git(git_executable, "-C", str(repository), "ls-remote", "--refs", remote, ref)
    if not result:
        return None
    lines = result.splitlines()
    if len(lines) != 1:
        raise ExperimentalPublicationError("experimental_remote_snapshot_invalid")
    fields = lines[0].split()
    if len(fields) != 2 or fields[1] != ref or not _OBJECT_ID_RE.fullmatch(fields[0]):
        raise ExperimentalPublicationError("experimental_remote_snapshot_invalid")
    return fields[0]


def _git(git_executable: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            (str(git_executable), *args),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ExperimentalPublicationError("experimental_git_unavailable") from error
    if result.returncode != 0:
        raise ExperimentalPublicationError("experimental_git_failed")
    return result.stdout.strip()
