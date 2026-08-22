from __future__ import annotations

import hashlib
import os
import tomllib
from dataclasses import replace
from datetime import UTC, datetime
from inspect import signature
from pathlib import Path

import pytest
from test_cloud_coordinator import claimed_command_for, lease, node, snapshot

from carl_bench import coordinator_service
from carl_bench.cloud_coordinator import (
    CloudCoordinatorError,
    ProtectedCoordinatorExecutor,
    choose_next_action,
)
from carl_bench.cloud_state import create_command_state
from carl_bench.coordinator_ipc import CoordinatorServiceRequest
from carl_bench.coordinator_service import coordinator_response
from carl_bench.live_evaluation_authority import ProtectedArchiveVersion
from carl_bench.postgres_state import PostgresStateError

NOW_TEXT = "2026-08-22T12:00:00Z"
DIGEST = "1" * 64


def durable_production_receipts(node_kind: str = "create_promotion_pr") -> dict[str, object]:
    receipts: dict[str, object] = {
        "experiment_id": "experiment-1",
        "node_kind": node_kind,
        "request_digest": DIGEST,
        "repository": "StephenBickel/carl-agent",
        "candidate_commit": "2" * 40,
        "candidate_tree": "3" * 40,
        "experimental_ref": "refs/heads/experimental/experiment-1",
        "archive_object_key": f"carl-evidence/v1/sha256/{DIGEST[:2]}/{DIGEST}",
        "archive_version_id": "version-1",
        "archive_digest": DIGEST,
        "archive_receipt_digest": "2" * 64,
        "experimental_receipt_digest": "3" * 64,
        "live_provenance_receipt_digest": "4" * 64,
        "independent_disposition_receipt_digest": "5" * 64,
        "verified_at": NOW_TEXT,
        "archive_retain_until": "2026-09-22T12:00:00Z",
        "pull_request_number": None,
        "pull_request_head": None,
        "pull_request_base": None,
        "required_checks_receipt_digest": None,
        "branch_protection_receipt_digest": None,
        "merge_commit": None,
        "merge_tree": None,
        "merged_at": None,
        "soak_observation_digest": None,
        "soak_observed_at": None,
        "hard_failure_digest": None,
        "revert_candidate_commit": None,
    }
    if node_kind not in {"create_promotion_pr", "create_revert"}:
        receipts.update(
            {
                "pull_request_number": 42,
                "pull_request_head": "2" * 40,
                "pull_request_base": "main",
            }
        )
    if node_kind not in {
        "create_promotion_pr",
        "observe_required_checks",
        "create_revert",
    }:
        receipts.update(
            {
                "required_checks_receipt_digest": "6" * 64,
                "branch_protection_receipt_digest": "7" * 64,
            }
        )
    if node_kind in {
        "schedule_soak",
        "observe_soak",
        "accept_soak",
        "create_revert",
        "observe_revert",
    }:
        receipts.update(
            {
                "merge_commit": "4" * 40,
                "merge_tree": "5" * 40,
                "merged_at": "2026-08-21T12:00:00Z",
            }
        )
    if node_kind in {"accept_soak", "create_revert", "observe_revert"}:
        receipts.update(
            {
                "soak_observation_digest": "8" * 64,
                "soak_observed_at": NOW_TEXT,
            }
        )
    if node_kind in {"create_revert", "observe_revert"}:
        receipts.update(
            {
                "hard_failure_digest": "9" * 64,
                "revert_candidate_commit": "6" * 40,
            }
        )
        if node_kind == "observe_revert":
            receipts["pull_request_head"] = "6" * 40
    return receipts


class DurableState:
    def __init__(self, expected_command: str = "coordinate") -> None:
        self.current = snapshot(node(), current_lease=lease())
        self.applied: list[str] = []
        self.expected_command = expected_command

    def reconstruct(self, command: str, *, observed_at: datetime):
        assert command == self.expected_command
        assert observed_at == datetime(2026, 8, 22, 12, tzinfo=UTC)
        return self.current

    def apply(self, decision, *, observed_at: datetime):
        assert observed_at == datetime(2026, 8, 22, 12, tzinfo=UTC)
        self.applied.append(decision.action)
        selected = node()
        if decision.action == "persist_command":
            self.current = replace(self.current, command=create_command_state(decision.command))
        elif decision.action == "claim_command":
            self.current = replace(self.current, command=claimed_command_for(selected))
        else:  # pragma: no cover - a wrong production branch is the tested defect
            raise AssertionError(decision.action)
        return decision


class NoEffects:
    def execute(self, decision, *, observed_at: datetime):  # pragma: no cover
        del decision, observed_at
        raise AssertionError("no remote effect belongs to these two invocations")


def test_repeated_service_invocation_advances_durable_state() -> None:
    state = DurableState()
    executor = ProtectedCoordinatorExecutor._for_testing(
        state=state,
        effects=NoEffects(),
        clock=lambda: datetime(2026, 8, 22, 12, tzinfo=UTC),
    )
    request = CoordinatorServiceRequest.create("coordinate")

    first = coordinator_response(request, controller=executor)
    second = coordinator_response(request, controller=executor)

    assert first.result is not None and first.result["action"] == "persist_command"
    assert second.result is not None and second.result["action"] == "claim_command"
    assert first.result["identity"] != second.result["identity"]
    assert state.applied == ["persist_command", "claim_command"]


def test_worker_with_no_applicable_node_is_canonical_idle() -> None:
    state = DurableState(expected_command="observe")
    state.current = snapshot(current_lease=lease())
    executor = ProtectedCoordinatorExecutor._for_testing(
        state=state,
        effects=NoEffects(),
        clock=lambda: datetime(2026, 8, 22, 12, tzinfo=UTC),
    )

    response = coordinator_response(
        CoordinatorServiceRequest.create("observe"), controller=executor
    )

    assert response.result is not None
    assert response.result["action"] == "idle"
    assert response.result["reason"] == "no_applicable_node"
    assert response.result["consequential"] is False
    assert state.applied == []


def test_empty_durable_queue_is_canonical_idle_without_a_mutation() -> None:
    class EmptyState:
        def __init__(self) -> None:
            self.applied = False

        def reconstruct(self, command: str, *, observed_at: datetime):
            assert command == "observe"
            assert observed_at == datetime(2026, 8, 22, 12, tzinfo=UTC)
            return None

        def apply(self, decision, *, observed_at: datetime):  # pragma: no cover
            del decision, observed_at
            self.applied = True
            raise AssertionError("idle must not mutate")

    state = EmptyState()
    executor = ProtectedCoordinatorExecutor._for_testing(
        state=state,
        effects=NoEffects(),
        clock=lambda: datetime(2026, 8, 22, 12, tzinfo=UTC),
    )

    response = coordinator_response(
        CoordinatorServiceRequest.create("observe"), controller=executor
    )

    assert response.status == "completed"
    assert response.result is not None
    assert response.result["action"] == "idle"
    assert response.result["reason"] == "no_applicable_node"
    assert response.result["consequential"] is False
    assert state.applied is False


def test_storage_failure_is_a_bounded_rejection_not_a_service_crash() -> None:
    class BrokenState:
        def reconstruct(self, command: str, *, observed_at: datetime):
            del command, observed_at
            raise PostgresStateError("postgres_mutation_failed")

        def apply(self, decision, *, observed_at: datetime):  # pragma: no cover
            del decision, observed_at
            raise AssertionError("unreachable")

    executor = ProtectedCoordinatorExecutor._for_testing(
        state=BrokenState(),
        effects=NoEffects(),
        clock=lambda: datetime(2026, 8, 22, 12, tzinfo=UTC),
    )
    request = CoordinatorServiceRequest.create("coordinate")

    response = coordinator_response(request, controller=executor)

    assert response.status == "rejected"
    assert response.error_code == "coordinator_request_rejected"
    assert response.result is None


def test_protected_coordinator_has_a_zero_argument_packaged_entrypoint() -> None:
    project = tomllib.loads((Path(__file__).parents[1] / "pyproject.toml").read_text())

    assert project["project"]["scripts"]["carl-coordinator-service"] == (
        "carl_bench.coordinator_service:main"
    )
    assert set(signature(coordinator_service.main).parameters) == set()


def test_production_controller_owns_fixed_state_and_effect_clients(monkeypatch) -> None:
    constructed: list[str] = []

    class Backend:
        @classmethod
        def from_protected_environment(cls):
            constructed.append("postgres")
            return object()

    class GitHubClient:
        @classmethod
        def from_protected_environment(cls):
            constructed.append("github")
            return object()

    class ArchiveReader:
        @classmethod
        def from_protected_environment(cls):
            constructed.append("archive")
            return object()

    monkeypatch.setattr(coordinator_service, "PostgresStateBackend", Backend)
    monkeypatch.setattr(coordinator_service, "GitHubEffectSocketClient", GitHubClient)
    monkeypatch.setattr(coordinator_service, "ProtectedArchiveSocketReader", ArchiveReader)

    controller = coordinator_service._build_protected_controller()

    assert isinstance(controller, ProtectedCoordinatorExecutor)
    assert constructed == ["postgres", "github", "archive"]


def test_production_receipts_are_bound_to_an_independent_exact_archive_read() -> None:
    payload = b"protected production evidence"
    archive_digest = hashlib.sha256(payload).hexdigest()
    receipts = durable_production_receipts()
    receipts.update(
        {
            "archive_digest": archive_digest,
            "archive_object_key": (
                f"carl-evidence/v1/sha256/{archive_digest[:2]}/{archive_digest}"
            ),
            "archive_version_id": "version-9",
        }
    )
    durable_snapshot = snapshot(
        node("create_promotion_pr"),
        current_lease=lease(),
    )

    class Backend:
        def reconstruct_coordinator_snapshot(self, command, *, observed_at):
            assert command == "commission-live"
            assert observed_at == datetime(2026, 8, 22, 12, tzinfo=UTC)
            return durable_snapshot, receipts

    class Archive:
        def __init__(self, *, checksum: str = archive_digest) -> None:
            self.checksum = checksum
            self.calls: list[tuple[str, str]] = []

        def read_exact(self, object_key: str, version_id: str):
            self.calls.append((object_key, version_id))
            return ProtectedArchiveVersion(
                object_key=object_key,
                version_id=version_id,
                payload=payload,
                checksum_sha256=self.checksum,
                byte_length=len(payload),
                retention_mode="COMPLIANCE",
                retain_until="2026-09-22T12:00:00Z",
                created_at="2026-08-22T11:00:00Z",
            )

    archive = Archive()
    state = coordinator_service._PostgresCoordinatorState(Backend(), archive)

    rebuilt = state.reconstruct(
        "commission-live", observed_at=datetime(2026, 8, 22, 12, tzinfo=UTC)
    )

    assert rebuilt is not None and rebuilt.production_authorization is not None
    assert rebuilt.production_authorization.archive_digest == archive_digest
    assert archive.calls == [(receipts["archive_object_key"], receipts["archive_version_id"])]

    with pytest.raises(CloudCoordinatorError, match="protected_archive_receipt_mismatch"):
        coordinator_service._PostgresCoordinatorState(
            Backend(), Archive(checksum="f" * 64)
        ).reconstruct("commission-live", observed_at=datetime(2026, 8, 22, 12, tzinfo=UTC))


def test_activation_contract_requires_exact_coordinator_descriptor_name(monkeypatch) -> None:
    captured: list[tuple[dict[str, str], int]] = []

    def validate(*, environment, process_id):
        captured.append((environment, process_id))
        return 3

    monkeypatch.setattr(coordinator_service, "_github_activation_descriptor", validate)
    monkeypatch.setenv("LISTEN_FDNAMES", "coordinator")

    assert coordinator_service._activation_descriptor_from_environment() == 3
    assert captured == [({**os.environ, "LISTEN_FDNAMES": "github-effect"}, os.getpid())]

    monkeypatch.setenv("LISTEN_FDNAMES", "github-effect")
    with pytest.raises(RuntimeError, match="coordinator_service_activation_invalid"):
        coordinator_service._activation_descriptor_from_environment()


def test_production_authorization_is_minted_only_from_exact_current_durable_receipts() -> None:
    observed_at = datetime(2026, 8, 22, 12, tzinfo=UTC)

    authorized = coordinator_service._authorization_from_durable_receipts(
        durable_production_receipts(), observed_at=observed_at
    )

    assert authorized.experiment_id == "experiment-1"
    assert authorized.node_kind == "create_promotion_pr"
    assert authorized.verified_at == NOW_TEXT

    stale = durable_production_receipts()
    stale["verified_at"] = "2026-08-22T11:59:59Z"
    with pytest.raises(CloudCoordinatorError, match="protected_authorization_time_mismatch"):
        coordinator_service._authorization_from_durable_receipts(stale, observed_at=observed_at)

    with pytest.raises(CloudCoordinatorError, match="protected_authorization_receipts_invalid"):
        coordinator_service._authorization_from_durable_receipts(
            {**durable_production_receipts(), "synthetic": False},
            observed_at=observed_at,
        )


def test_only_service_minted_exact_receipts_enable_production_nodes() -> None:
    observed_at = datetime(2026, 8, 22, 12, tzinfo=UTC)
    authorization = coordinator_service._authorization_from_durable_receipts(
        durable_production_receipts(), observed_at=observed_at
    )

    allowed = choose_next_action(
        snapshot(
            node("create_promotion_pr"),
            current_lease=lease(),
            production_authorization=authorization,
        )
    )

    assert allowed.action == "persist_command"
    assert allowed.node == "create_promotion_pr"

    wrong_node = coordinator_service._authorization_from_durable_receipts(
        durable_production_receipts("enable_auto_merge"), observed_at=observed_at
    )
    blocked = choose_next_action(
        snapshot(
            node("create_promotion_pr"),
            current_lease=lease(),
            production_authorization=wrong_node,
        )
    )
    assert blocked.action == "frozen"
    assert blocked.reason == "production_node_identity_mismatch"


def test_service_minted_soak_authorization_requires_exact_merge_bound_observation() -> None:
    receipts = durable_production_receipts("accept_soak")
    for field in (
        "merge_commit",
        "merge_tree",
        "merged_at",
        "soak_observation_digest",
        "soak_observed_at",
    ):
        receipts[field] = None
    with pytest.raises(CloudCoordinatorError, match="protected_authorization_merge_invalid"):
        coordinator_service._authorization_from_durable_receipts(
            receipts,
            observed_at=datetime(2026, 8, 22, 12, tzinfo=UTC),
        )


def test_service_rejects_production_receipts_missing_the_node_specific_chain() -> None:
    receipts = durable_production_receipts("enable_auto_merge")
    receipts["required_checks_receipt_digest"] = None

    with pytest.raises(CloudCoordinatorError, match="protected_authorization_checks_invalid"):
        coordinator_service._authorization_from_durable_receipts(
            receipts,
            observed_at=datetime(2026, 8, 22, 12, tzinfo=UTC),
        )


def test_service_rejects_revert_without_exact_hard_failure_identity() -> None:
    receipts = durable_production_receipts("create_revert")
    receipts["hard_failure_digest"] = None

    with pytest.raises(CloudCoordinatorError, match="protected_authorization_revert_invalid"):
        coordinator_service._authorization_from_durable_receipts(
            receipts,
            observed_at=datetime(2026, 8, 22, 12, tzinfo=UTC),
        )
