"""Deterministic production authority for one bounded supervisor recovery action."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from carl_bench.canonical import CanonicalizationError, canonical_json_bytes
from carl_bench.cloud_coordinator import NODE_ORDER
from carl_bench.coordinator_client import CoordinatorClientError, CoordinatorSocketClient
from carl_bench.coordinator_ipc import CoordinatorServiceRequest
from carl_bench.supervisor_triggers import SupervisorTrigger, SupervisorTriggerError

_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
_ACTIONS = frozenset(
    {
        "freeze_stable_boundary",
        "open_repair_pr",
        "reconcile_state",
        "redispatch_safe_node",
    }
)
_ALLOWED_EXACT_PATHS = frozenset(
    {
        ".github/workflows/autonomy-coordinator.yml",
        ".github/workflows/autonomy-soak-scheduler.yml",
        ".github/workflows/autonomy-supervisor.yml",
        "benchmarks/src/carl_bench/cli.py",
        "benchmarks/src/carl_bench/cloud_coordinator.py",
        "benchmarks/src/carl_bench/coordinator_ipc.py",
        "benchmarks/src/carl_bench/coordinator_service.py",
        "benchmarks/src/carl_bench/postgres_state.py",
        "benchmarks/src/carl_bench/supervisor_recovery.py",
        "benchmarks/src/carl_bench/supervisor_triggers.py",
        "docs/automation-prompts/carl-autonomy-supervisor.md",
    }
)
_ALLOWED_PREFIXES = (
    "infra/autonomy/postgres/",
    "benchmarks/tests/test_automation_prompt_contract.py",
    "benchmarks/tests/test_cli.py",
    "benchmarks/tests/test_cloud_coordinator.py",
    "benchmarks/tests/test_coordinator_ipc.py",
    "benchmarks/tests/test_coordinator_service.py",
    "benchmarks/tests/test_postgres_state.py",
    "benchmarks/tests/test_postgres_state_integration.py",
    "benchmarks/tests/test_supervisor_recovery.py",
    "benchmarks/tests/test_supervisor_triggers.py",
)
_MAX_REPAIR_FILE_BYTES = 1_048_576


class SupervisorRecoveryError(ValueError):
    """Stable supervisor authority failure without private payloads."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class SupervisorProposal:
    schema_version: int
    trigger_id: str
    expected_revision: int
    action: str
    reason: str

    @classmethod
    def from_bytes(cls, payload: bytes) -> SupervisorProposal:
        import json

        code = "supervisor_proposal_invalid"
        try:
            value = json.loads(payload)
            if (
                type(value) is not dict
                or set(value)
                != {"action", "expected_revision", "reason", "schema_version", "trigger_id"}
                or canonical_json_bytes(value) != payload
                or value["schema_version"] != 1
                or isinstance(value["schema_version"], bool)
                or not isinstance(value["trigger_id"], str)
                or _KEY.fullmatch(value["trigger_id"]) is None
                or isinstance(value["expected_revision"], bool)
                or not isinstance(value["expected_revision"], int)
                or not 0 <= value["expected_revision"] <= 2_147_483_646
                or value["action"] not in _ACTIONS
                or not isinstance(value["reason"], str)
                or _REASON.fullmatch(value["reason"]) is None
            ):
                raise ValueError
            return cls(
                schema_version=1,
                trigger_id=value["trigger_id"],
                expected_revision=value["expected_revision"],
                action=value["action"],
                reason=value["reason"],
            )
        except (CanonicalizationError, UnicodeError, ValueError, json.JSONDecodeError) as error:
            raise SupervisorRecoveryError(code) from error

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "expected_revision": self.expected_revision,
            "reason": self.reason,
            "schema_version": 1,
            "trigger_id": self.trigger_id,
        }


@dataclass(frozen=True, slots=True)
class ControlPlaneDiff:
    paths: tuple[str, ...]
    digest: str


def _git(repository: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ("git", "-C", os.fspath(repository), *arguments),
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SupervisorRecoveryError("repair_repository_invalid") from error
    return completed.stdout


def _allowed_control_plane_path(path: str) -> bool:
    if path in _ALLOWED_EXACT_PATHS:
        return True
    return any(path == prefix or path.startswith(prefix) for prefix in _ALLOWED_PREFIXES)


def control_plane_diff(repository: Path) -> ControlPlaneDiff:
    """Bind every changed path and byte while rejecting candidate/evaluation surfaces."""
    root = repository.expanduser().resolve(strict=True)
    discovered = Path(_git(root, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if discovered != root:
        raise SupervisorRecoveryError("repair_repository_invalid")
    tracked = _git(root, "diff", "--name-only", "-z", "HEAD", "--").split(b"\0")
    untracked = _git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0")
    try:
        paths = tuple(
            sorted(
                {item.decode("utf-8") for item in (*tracked, *untracked) if item},
                key=str.encode,
            )
        )
    except UnicodeError as error:
        raise SupervisorRecoveryError("repair_diff_scope_forbidden") from error
    if any(
        path.startswith("/")
        or ".." in Path(path).parts
        or not _allowed_control_plane_path(path)
        for path in paths
    ):
        raise SupervisorRecoveryError("repair_diff_scope_forbidden")
    bindings: list[dict[str, object]] = []
    for path in paths:
        target = root / path
        if not target.exists():
            bindings.append({"digest": None, "path": path})
            continue
        metadata = target.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_size > _MAX_REPAIR_FILE_BYTES
        ):
            raise SupervisorRecoveryError("repair_diff_scope_forbidden")
        bindings.append(
            {"digest": hashlib.sha256(target.read_bytes()).hexdigest(), "path": path}
        )
    return ControlPlaneDiff(
        paths=paths,
        digest=hashlib.sha256(
            canonical_json_bytes({"files": bindings, "schema_version": 1})
        ).hexdigest(),
    )


class SupervisorBackend(Protocol):
    def select_supervisor_trigger(self) -> dict[str, object]: ...

    def claim_supervisor_recovery(self, value: dict[str, object]) -> dict[str, object]: ...

    def complete_supervisor_recovery(self, value: dict[str, object]) -> dict[str, object]: ...

    def complete_supervisor_redispatch(self, value: dict[str, object]) -> dict[str, object]: ...

    def fail_supervisor_recovery(self, value: dict[str, object]) -> dict[str, object]: ...

    def read_supervisor_recovery_receipt(
        self, trigger_id: str, action_digest: str
    ) -> dict[str, object]: ...


class SupervisorRecoveryRunner:
    """Claim, execute, and bind one action to an independently re-read PostgreSQL receipt."""

    __slots__ = ("_backend", "_clock", "_coordinator", "_repository")

    def __init__(
        self,
        *,
        backend: SupervisorBackend,
        coordinator: CoordinatorSocketClient | None,
        repository: Path,
        clock: object,
        _testing: bool,
    ) -> None:
        if not _testing or not callable(clock):
            raise SupervisorRecoveryError("supervisor_runner_configuration_invalid")
        self._backend = backend
        self._coordinator = coordinator
        self._repository = repository
        self._clock = clock

    @classmethod
    def _for_testing(
        cls,
        *,
        backend: SupervisorBackend,
        coordinator: CoordinatorSocketClient | None,
        repository: Path,
        clock: object,
    ) -> SupervisorRecoveryRunner:
        return cls(
            backend=backend,
            coordinator=coordinator,
            repository=repository,
            clock=clock,
            _testing=True,
        )

    @classmethod
    def from_protected_environment(cls, *, repository: Path) -> SupervisorRecoveryRunner:
        from carl_bench.postgres_state import PostgresStateBackend

        return cls(
            backend=PostgresStateBackend.from_protected_environment(),
            coordinator=CoordinatorSocketClient.from_protected_environment(),
            repository=repository,
            clock=lambda: datetime.now(UTC),
            _testing=True,
        )

    def inspect(self) -> dict[str, object]:
        selected = self._backend.select_supervisor_trigger()
        return self._strict_selected(selected)

    @staticmethod
    def _strict_selected(value: object) -> dict[str, object]:
        if (
            type(value) is not dict
            or set(value) != {"claim_id", "revision", "trigger_id", "trigger_json"}
            or not isinstance(value["trigger_json"], str)
            or not isinstance(value["trigger_id"], str)
            or isinstance(value["revision"], bool)
            or not isinstance(value["revision"], int)
            or (value["claim_id"] is not None and not isinstance(value["claim_id"], str))
        ):
            raise SupervisorRecoveryError("supervisor_trigger_state_invalid")
        try:
            trigger = SupervisorTrigger.from_canonical_dict(
                __import__("json").loads(value["trigger_json"])
            )
        except (SupervisorTriggerError, ValueError) as error:
            raise SupervisorRecoveryError("supervisor_trigger_state_invalid") from error
        if trigger.trigger_id != value["trigger_id"]:
            raise SupervisorRecoveryError("supervisor_trigger_state_invalid")
        return value

    def recover(self, proposal: SupervisorProposal) -> dict[str, object]:
        if not isinstance(proposal, SupervisorProposal):
            raise SupervisorRecoveryError("supervisor_proposal_invalid")
        selected = self.inspect()
        if (
            proposal.trigger_id != selected["trigger_id"]
            or proposal.expected_revision != selected["revision"]
        ):
            raise SupervisorRecoveryError("supervisor_trigger_cas_mismatch")
        diff = control_plane_diff(self._repository)
        if proposal.action == "open_repair_pr" and not diff.paths:
            raise SupervisorRecoveryError("repair_diff_required")
        if proposal.action != "open_repair_pr" and diff.paths:
            raise SupervisorRecoveryError("unexpected_repair_diff")

        action_digest = hashlib.sha256(
            canonical_json_bytes(
                {
                    "diff_digest": diff.digest,
                    "proposal": proposal.to_canonical_dict(),
                    "trigger_json": selected["trigger_json"],
                }
            )
        ).hexdigest()
        attempt_id = f"recovery-{action_digest[:32]}"
        claim_id = f"supervisor:{proposal.trigger_id}"
        claim = {
            "action_digest": action_digest,
            "action_kind": proposal.action,
            "attempt_id": attempt_id,
            "claim_id": claim_id,
            "expected_revision": proposal.expected_revision,
            "schema_version": 1,
            "trigger_id": proposal.trigger_id,
        }
        claimed = self._backend.claim_supervisor_recovery(claim)
        claimed_revision = claimed.get("revision")
        if isinstance(claimed_revision, bool) or not isinstance(claimed_revision, int):
            raise SupervisorRecoveryError("supervisor_claim_receipt_invalid")
        trigger = SupervisorTrigger.from_canonical_dict(
            __import__("json").loads(selected["trigger_json"])
        )
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo != UTC:
            raise SupervisorRecoveryError("supervisor_clock_invalid")

        if proposal.action == "redispatch_safe_node":
            completion = self._redispatch(
                trigger=trigger,
                claim=claim,
                claimed_revision=claimed_revision,
                observed_at=now,
            )
            completed = self._backend.complete_supervisor_redispatch(completion)
        else:
            boundary = (
                trigger.unsafe_boundary
                if proposal.action == "freeze_stable_boundary"
                else f"{proposal.action}:{proposal.reason}"
            )
            result_digest = hashlib.sha256(
                canonical_json_bytes(
                    {
                        "action_digest": action_digest,
                        "boundary": boundary,
                        "observed_at": now.isoformat().replace("+00:00", "Z"),
                    }
                )
            ).hexdigest()
            completed = self._backend.complete_supervisor_recovery(
                {
                    "action_digest": action_digest,
                    "attempt_id": attempt_id,
                    "boundary": boundary,
                    "claim_id": claim_id,
                    "evidence_digest": trigger.evidence_digest,
                    "expected_revision": claimed_revision,
                    "outcome": "stable_boundary_frozen",
                    "result_digest": result_digest,
                    "schema_version": 1,
                    "trigger_id": trigger.trigger_id,
                }
            )
        reread = self._backend.read_supervisor_recovery_receipt(
            proposal.trigger_id, action_digest
        )
        if reread != completed:
            raise SupervisorRecoveryError("supervisor_authoritative_receipt_mismatch")
        try:
            result = {
                "action_digest": reread["action_digest"],
                "outcome": reread["outcome"],
                "revision": reread["revision"],
                "trigger_id": reread["trigger_id"],
            }
            canonical_json_bytes(result)
        except (CanonicalizationError, KeyError, TypeError) as error:
            raise SupervisorRecoveryError("supervisor_authoritative_receipt_invalid") from error
        return result

    def _redispatch(
        self,
        *,
        trigger: SupervisorTrigger,
        claim: dict[str, object],
        claimed_revision: int,
        observed_at: datetime,
    ) -> dict[str, object]:
        experiment_id, separator, node = trigger.next_safe_node_key.rpartition(":")
        if not separator or not experiment_id or node not in NODE_ORDER:
            raise SupervisorRecoveryError("supervisor_safe_node_invalid")
        if self._coordinator is None:
            raise SupervisorRecoveryError("coordinator_service_unavailable")
        request = CoordinatorServiceRequest.create("coordinate", allowed_nodes=(node,))
        try:
            response = self._coordinator.execute(request)
        except CoordinatorClientError as error:
            failure_digest = hashlib.sha256(error.args[0].encode("utf-8")).hexdigest()
            self._backend.fail_supervisor_recovery(
                {
                    "action_digest": claim["action_digest"],
                    "attempt_id": claim["attempt_id"],
                    "claim_id": claim["claim_id"],
                    "expected_revision": claimed_revision,
                    "failure_code": "coordinator_service_unavailable",
                    "result_digest": failure_digest,
                    "schema_version": 1,
                    "trigger_id": trigger.trigger_id,
                }
            )
            raise SupervisorRecoveryError("coordinator_service_unavailable") from error
        result = response.result
        if (
            response.status != "completed"
            or type(result) is not dict
            or result.get("experiment_id") != experiment_id
            or result.get("node") != node
            or result.get("consequential") is not True
        ):
            raise SupervisorRecoveryError("supervisor_redispatch_not_material")
        return {
            "action_digest": claim["action_digest"],
            "attempt_id": claim["attempt_id"],
            "claim_id": claim["claim_id"],
            "coordinator_request_digest": request.digest,
            "coordinator_result": result,
            "evidence_digest": trigger.evidence_digest,
            "expected_revision": claimed_revision,
            "outcome": "safe_node_redispatched",
            "result_digest": hashlib.sha256(canonical_json_bytes(result)).hexdigest(),
            "schema_version": 1,
            "trigger_id": trigger.trigger_id,
        }
