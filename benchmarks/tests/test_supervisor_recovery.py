from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from carl_bench.canonical import canonical_json_bytes
from carl_bench.supervisor_recovery import (
    SupervisorProposal,
    SupervisorRecoveryError,
    SupervisorRecoveryRunner,
    control_plane_diff,
)


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(("git", "-C", str(repository), *arguments), check=True, capture_output=True)


def _repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-q")
    _git(repository, "config", "user.name", "Carl Test")
    _git(repository, "config", "user.email", "carl@example.invalid")
    allowed = repository / "docs/automation-prompts/carl-autonomy-supervisor.md"
    allowed.parent.mkdir(parents=True)
    allowed.write_text("initial\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "-qm", "fixture")
    return repository


def _proposal(action: str = "freeze_stable_boundary") -> SupervisorProposal:
    value = {
        "action": action,
        "expected_revision": 0,
        "reason": "provider_not_commissioned",
        "schema_version": 1,
        "trigger_id": "trigger-1",
    }
    return SupervisorProposal.from_bytes(canonical_json_bytes(value))


def test_proposal_requires_exact_canonical_bounded_action() -> None:
    proposal = _proposal()

    assert proposal.action == "freeze_stable_boundary"
    assert proposal.trigger_id == "trigger-1"

    noncanonical = json.dumps(proposal.to_canonical_dict(), indent=2).encode()
    with pytest.raises(SupervisorRecoveryError, match="supervisor_proposal_invalid"):
        SupervisorProposal.from_bytes(noncanonical)


def test_control_plane_diff_binds_allowed_files_and_rejects_candidate_evidence(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    allowed = repository / "docs/automation-prompts/carl-autonomy-supervisor.md"
    allowed.write_text("changed\n", encoding="utf-8")

    diff = control_plane_diff(repository)

    assert diff.paths == ("docs/automation-prompts/carl-autonomy-supervisor.md",)
    assert len(diff.digest) == 64

    forbidden = repository / "benchmarks/src/carl_bench/candidate_evidence.py"
    forbidden.parent.mkdir(parents=True)
    forbidden.write_text("forged = True\n", encoding="utf-8")
    with pytest.raises(SupervisorRecoveryError, match="repair_diff_scope_forbidden"):
        control_plane_diff(repository)


class _Backend:
    def __init__(self) -> None:
        self.claims: list[dict[str, object]] = []
        self.completions: list[dict[str, object]] = []
        self.receipt: dict[str, object] | None = None

    def select_supervisor_trigger(self) -> dict[str, object]:
        return {
            "claim_id": None,
            "revision": 0,
            "trigger_id": "trigger-1",
            "trigger_json": canonical_json_bytes(
                {
                    "attempt_history": [],
                    "created_at": "2026-08-23T12:00:00Z",
                    "evidence_digest": "a" * 64,
                    "next_safe_node_key": "experiment-1:schedule_soak",
                    "schema_version": 1,
                    "trigger_id": "trigger-1",
                    "unsafe_boundary": "commissioning:provider",
                }
            ).decode(),
        }

    def claim_supervisor_recovery(self, value: dict[str, object]) -> dict[str, object]:
        self.claims.append(value)
        return {**value, "applied": True, "revision": 1}

    def complete_supervisor_recovery(self, value: dict[str, object]) -> dict[str, object]:
        self.completions.append(value)
        receipt = {
            "action_digest": value["action_digest"],
            "outcome": "stable_boundary_frozen",
            "receipt_json": canonical_json_bytes(
                {
                    "action_digest": value["action_digest"],
                    "authoritative_revision": 2,
                    "outcome": "stable_boundary_frozen",
                    "schema_version": 1,
                    "trigger_id": "trigger-1",
                }
            ).decode(),
            "revision": 2,
            "trigger_id": "trigger-1",
        }
        self.receipt = receipt
        return receipt

    def read_supervisor_recovery_receipt(
        self, trigger_id: str, action_digest: str
    ) -> dict[str, object]:
        assert self.receipt is not None
        assert (trigger_id, action_digest) == (
            self.receipt["trigger_id"],
            self.receipt["action_digest"],
        )
        return self.receipt


def test_runner_claims_executes_and_exactly_rebinds_the_durable_receipt(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    backend = _Backend()
    runner = SupervisorRecoveryRunner._for_testing(
        backend=backend,
        coordinator=None,
        repository=repository,
        clock=lambda: datetime(2026, 8, 23, 12, tzinfo=UTC),
    )

    result = runner.recover(_proposal())

    assert result == {
        "action_digest": backend.receipt["action_digest"],
        "outcome": "stable_boundary_frozen",
        "revision": 2,
        "trigger_id": "trigger-1",
    }
    assert len(backend.claims) == 1
    assert len(backend.completions) == 1
    assert backend.claims[0]["action_digest"] == backend.completions[0]["action_digest"]
    assert backend.completions[0]["expected_revision"] == 1


def test_repair_proposal_requires_a_nonempty_allowed_diff_before_claim(
    tmp_path: Path,
) -> None:
    repository = _repository(tmp_path)
    backend = _Backend()
    runner = SupervisorRecoveryRunner._for_testing(
        backend=backend,
        coordinator=None,
        repository=repository,
        clock=lambda: datetime(2026, 8, 23, 12, tzinfo=UTC),
    )

    with pytest.raises(SupervisorRecoveryError, match="repair_diff_required"):
        runner.recover(_proposal("open_repair_pr"))

    assert backend.claims == []
