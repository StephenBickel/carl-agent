"""Protected one-use authority for bounded live model evaluation capabilities."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from carl_bench.adapters.carl_acp import BoundedModelGatewayCapability
from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_capability import (
    LiveEvaluationIdentity,
    LivePairPolicy,
    LiveTaskIdentity,
)
from carl_bench.live_execution_receipt import (
    ProtectedExecutionReceipt,
    ProtectedLiveExecutionResult,
)
from carl_bench.live_gateway_store import LiveGatewayStateError, SQLiteLiveGatewayStateStore
from carl_bench.openai_gateway import (
    OpenAIGatewayError,
    OpenAIModelGateway,
    OpenAIModelRequest,
    ProtectedOpenAIModelResult,
    ProviderOperationIdentity,
    ProviderReconciliationCapability,
    ProviderReconciliationReceipt,
)

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_ENDPOINT = "http://127.0.0.1:43117/v1/evaluate"
_CLAIM_LEASE_SECONDS = 60
_BOOT_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


class LiveGatewayAuthorityError(ValueError):
    """Stable failure from the protected live gateway authority."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise LiveGatewayAuthorityError(code)
    return value


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise LiveGatewayAuthorityError(code)
    return value


@dataclass(frozen=True, slots=True, init=False)
class ActualLiveExecution:
    """Controller-observed execution context; candidate input cannot populate this value."""

    repository: str
    pair_request_digest: str
    subject: str
    subject_commit: str
    subject_tree: str
    task_id: str
    task_digest: str
    input_digest: str
    input_size: int
    grader_digest: str
    task_role: str
    seed: int
    attempt: int
    environment_digest: str
    model: str
    reasoning_policy: str
    live_policy_digest: str
    execution_context_digest: str
    process_id: int
    worker_uid: int
    worker_gid: int
    executable_digest: str
    checkout_digest: str
    isolation_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise LiveGatewayAuthorityError("live_execution_observation_protected")

    @classmethod
    def _observed(cls, **values: object) -> ActualLiveExecution:
        result = object.__new__(cls)
        for name in cls.__dataclass_fields__:
            object.__setattr__(result, name, values[name])
        result.__post_init__()
        return result

    def __post_init__(self) -> None:
        if (
            not isinstance(self.repository, str)
            or re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", self.repository) is None
            or self.subject not in {"parent", "candidate"}
            or not isinstance(self.subject_commit, str)
            or _OBJECT_RE.fullmatch(self.subject_commit) is None
            or not isinstance(self.subject_tree, str)
            or _OBJECT_RE.fullmatch(self.subject_tree) is None
            or isinstance(self.input_size, bool)
            or not isinstance(self.input_size, int)
            or not 1 <= self.input_size <= 65_536
            or isinstance(self.seed, bool)
            or not isinstance(self.seed, int)
            or not 0 <= self.seed <= 2_147_483_647
            or isinstance(self.attempt, bool)
            or not isinstance(self.attempt, int)
            or not 1 <= self.attempt <= 3
            or self.task_role not in {"affected", "guard", "held_out"}
            or isinstance(self.process_id, bool)
            or not isinstance(self.process_id, int)
            or self.process_id <= 0
            or isinstance(self.worker_uid, bool)
            or not isinstance(self.worker_uid, int)
            or self.worker_uid < 0
            or isinstance(self.worker_gid, bool)
            or not isinstance(self.worker_gid, int)
            or self.worker_gid < 0
        ):
            raise LiveGatewayAuthorityError("live_execution_context_invalid")
        for value in (
            self.pair_request_digest,
            self.task_digest,
            self.input_digest,
            self.grader_digest,
            self.environment_digest,
            self.live_policy_digest,
            self.execution_context_digest,
            self.executable_digest,
            self.checkout_digest,
            self.isolation_digest,
        ):
            _digest(value, "live_execution_context_invalid")
        for value in (self.task_id, self.model, self.reasoning_policy):
            _identifier(value, "live_execution_context_invalid")

    def to_canonical_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


class _PinnedGateway(Protocol):
    def protected_execution_policy(self) -> dict[str, str]: ...

    def evaluate(self, request: OpenAIModelRequest) -> object: ...

    def verify_protected_result(self, result: object) -> bool: ...

    def provider_reconciliation_capability(
        self,
    ) -> ProviderReconciliationCapability | None: ...

    def dispatch_reconciled(
        self, request: OpenAIModelRequest, operation: ProviderOperationIdentity
    ) -> object: ...

    def reconcile_provider_operation(
        self, request: OpenAIModelRequest, operation: ProviderOperationIdentity
    ) -> object: ...

    def verify_provider_reconciliation(
        self, receipt: object, operation: ProviderOperationIdentity
    ) -> bool: ...


class _GatewayState(Protocol):
    def reserve_grant(self, **kwargs: object) -> None: ...

    def load_grant(self, token_digest: str) -> dict[str, Any]: ...

    def load_provider_binding(self, token_digest: str) -> tuple[str | None, str]: ...

    def claim_grant(self, token_digest: str, **kwargs: object) -> dict[str, Any]: ...

    def complete_result(self, token_digest: str, claim_id: str, result: dict[str, Any]) -> None: ...

    def mark_provider_dispatched(
        self, token_digest: str, claim_id: str, **kwargs: object
    ) -> None: ...

    def mark_dispatch_ambiguous(self, token_digest: str, claim_id: str, *, code: str) -> None: ...

    def take_result(self, token_digest: str) -> tuple[dict[str, Any], dict[str, Any]]: ...

    def peek_result(self, token_digest: str) -> tuple[dict[str, Any], dict[str, Any]]: ...

    def load_sealed_bundle(self, runner_request_digest: str) -> dict[str, Any] | None: ...

    def load_resumable_result(
        self, runner_request_digest: str
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None: ...

    def seal_result_bundle(
        self, token_digest: str, *, runner_request_digest: str, bundle: dict[str, Any]
    ) -> dict[str, Any]: ...

    def seal_resumed_result_bundle(
        self, runner_request_digest: str, *, bundle: dict[str, Any]
    ) -> dict[str, Any]: ...

    def record_infrastructure_invalid(self, token_digest: str, code: str) -> None: ...

    def invalidate_execution(self, token_digest: str, code: str) -> None: ...

    def retry_codes(
        self, pair_request_digest: str, task_id: str, attempt: int
    ) -> dict[str, str]: ...

    def reconcile_abandoned_claims(self, **kwargs: object) -> tuple[str, ...]: ...

    def claim_provider_reconciliations(self, **kwargs: object) -> tuple[dict[str, Any], ...]: ...

    def complete_provider_reconciliation(self, *args: object, **kwargs: object) -> None: ...

    def authorize_provider_retry(self, *args: object, **kwargs: object) -> bool: ...

    def defer_provider_reconciliation(self, *args: object, **kwargs: object) -> None: ...

    def freeze_provider_operation(self, *args: object, **kwargs: object) -> None: ...


@dataclass(slots=True)
class _Grant:
    identity: LiveEvaluationIdentity
    policy: LivePairPolicy
    task: LiveTaskIdentity
    actual: ActualLiveExecution
    token_digest: str


def _grant_document(grant: _Grant) -> dict[str, Any]:
    return {
        "actual": grant.actual.to_canonical_dict(),
        "identity": grant.identity.to_canonical_dict(),
        "policy": grant.policy.to_canonical_dict(),
        "schema_version": 1,
        "task": grant.task.to_canonical_dict(),
        "token_digest": grant.token_digest,
    }


def _grant_from_document(value: dict[str, Any]) -> _Grant:
    if set(value) != {"actual", "identity", "policy", "schema_version", "task", "token_digest"}:
        raise LiveGatewayAuthorityError("live_gateway_grant_invalid")
    try:
        raw_identity = dict(value["identity"])
        raw_identity["task_order"] = tuple(raw_identity["task_order"])
        raw_identity["seeds"] = tuple(raw_identity["seeds"])
        identity = LiveEvaluationIdentity.create(**raw_identity)
        policy = LivePairPolicy(**value["policy"])
        task = LiveTaskIdentity(**value["task"])
        actual = ActualLiveExecution._observed(**value["actual"])
    except (KeyError, TypeError, ValueError) as error:
        raise LiveGatewayAuthorityError("live_gateway_grant_invalid") from error
    token_digest = value["token_digest"]
    _digest(token_digest, "live_gateway_grant_invalid")
    if value["schema_version"] != 1:
        raise LiveGatewayAuthorityError("live_gateway_grant_invalid")
    return _Grant(identity, policy, task, actual, token_digest)


def _result_document(result: ProtectedOpenAIModelResult) -> dict[str, Any]:
    return {
        "latency_ms": result.latency_ms,
        "model": result.model,
        "output_digest": result.output_digest,
        "output_text": result.output_text,
        "provenance_tag": result.provenance_tag,
        "request_digest": result.request_digest,
        "response_id": result.response_id,
        "schema_version": 1,
        "status": result.status,
        "usage": {name: getattr(result.usage, name) for name in result.usage.__dataclass_fields__},
    }


def _result_from_document(value: dict[str, Any]) -> ProtectedOpenAIModelResult:
    if (
        set(value)
        != {
            "latency_ms",
            "model",
            "output_digest",
            "output_text",
            "provenance_tag",
            "request_digest",
            "response_id",
            "schema_version",
            "status",
            "usage",
        }
        or value["schema_version"] != 1
    ):
        raise LiveGatewayAuthorityError("live_gateway_result_invalid")
    try:
        from carl_bench.openai_gateway import OpenAIUsage

        return ProtectedOpenAIModelResult(
            response_id=value["response_id"],
            model=value["model"],
            status=value["status"],
            usage=OpenAIUsage(**value["usage"]),
            latency_ms=value["latency_ms"],
            request_digest=value["request_digest"],
            output_digest=value["output_digest"],
            output_text=value["output_text"],
            provenance_tag=value["provenance_tag"],
        )
    except (TypeError, ValueError) as error:
        raise LiveGatewayAuthorityError("live_gateway_result_invalid") from error


@dataclass(frozen=True, slots=True, init=False)
class ProtectedExecutionObservation:
    identity: LiveEvaluationIdentity
    policy: LivePairPolicy
    task: LiveTaskIdentity
    actual: ActualLiveExecution

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise LiveGatewayAuthorityError("live_execution_observation_protected")

    @classmethod
    def _mint(
        cls,
        *,
        identity: LiveEvaluationIdentity,
        policy: LivePairPolicy,
        task: LiveTaskIdentity,
        actual: ActualLiveExecution,
    ) -> ProtectedExecutionObservation:
        value = object.__new__(cls)
        object.__setattr__(value, "identity", identity)
        object.__setattr__(value, "policy", policy)
        object.__setattr__(value, "task", task)
        object.__setattr__(value, "actual", actual)
        return value


class _MemoryGatewayState:
    """Test-only state double; production always uses the durable SQLite authority."""

    def __init__(self) -> None:
        self.rows: dict[str, dict[str, Any]] = {}
        self.issues: set[str] = set()

    def reserve_grant(self, **kwargs: object) -> None:
        token = kwargs["token_digest"]
        issue = kwargs["issue_key"]
        runner_request_digest = kwargs.get("runner_request_digest")
        runner_context = kwargs.get("runner_context")
        if (runner_request_digest is None) != (runner_context is None):
            raise LiveGatewayStateError("live_gateway_runner_binding_invalid")
        if (
            token in self.rows
            or issue in self.issues
            or (
                runner_request_digest is not None
                and any(
                    row["runner_request_digest"] == runner_request_digest
                    for row in self.rows.values()
                )
            )
        ):
            raise LiveGatewayStateError("live_gateway_grant_conflict")
        self.issues.add(issue)
        self.rows[token] = {
            "grant": kwargs["grant"],
            "claim_state": "ready",
            "claim_id": None,
            "claim_boot_id": None,
            "claim_pid": None,
            "claim_process_start": None,
            "claim_expires_at": None,
            "result": None,
            "collected": False,
            "infrastructure_code": None,
            "provider_request_digest": None,
            "provider_operation": None,
            "provider_request": None,
            "provider_reconciliation_receipt": None,
            "provider_retry_count": 0,
            "provider_reconciliation_count": 0,
            "runner_request_digest": kwargs.get("runner_request_digest"),
            "runner_context": kwargs.get("runner_context"),
            "sealed_bundle": None,
        }

    def load_grant(self, token_digest: str) -> dict[str, Any]:
        row = self.rows.get(token_digest)
        if row is None:
            raise LiveGatewayStateError("live_gateway_capability_invalid")
        return row["grant"]

    def load_provider_binding(self, token_digest: str) -> tuple[str | None, str]:
        row = self.rows.get(token_digest)
        if row is None:
            raise LiveGatewayStateError("live_gateway_capability_invalid")
        return (
            row["runner_request_digest"],
            hashlib.sha256(canonical_json_bytes(row["grant"])).hexdigest(),
        )

    def claim_grant(self, token_digest: str, **kwargs: object) -> dict[str, Any]:
        row = self.rows.get(token_digest)
        if row is None:
            raise LiveGatewayStateError("live_gateway_capability_invalid")
        if row["claim_state"] == "dispatch_ambiguous":
            raise LiveGatewayStateError("live_gateway_dispatch_ambiguous")
        if row["claim_state"] in {"pre_dispatch", "dispatched"}:
            raise LiveGatewayStateError("live_gateway_capability_in_progress")
        if row["claim_state"] != "ready":
            raise LiveGatewayStateError("live_gateway_capability_consumed")
        row["claim_state"] = "pre_dispatch"
        for name in (
            "claim_id",
            "boot_id",
            "process_id",
            "process_start",
            "expires_at",
        ):
            target = {
                "boot_id": "claim_boot_id",
                "process_id": "claim_pid",
                "process_start": "claim_process_start",
            }.get(name, name)
            row[target] = kwargs[name]
        return row["grant"]

    def mark_provider_dispatched(self, token_digest: str, claim_id: str, **kwargs: object) -> None:
        row = self.rows[token_digest]
        if row["claim_state"] != "pre_dispatch" or row["claim_id"] != claim_id:
            raise LiveGatewayStateError("live_gateway_capability_invalid")
        row["claim_state"] = "dispatched"
        row["provider_request_digest"] = kwargs["request_digest"]
        row["provider_operation"] = kwargs.get("operation")
        row["provider_request"] = kwargs.get("request")

    def mark_dispatch_ambiguous(self, token_digest: str, claim_id: str, *, code: str) -> None:
        row = self.rows[token_digest]
        if row["claim_state"] != "dispatched" or row["claim_id"] != claim_id:
            raise LiveGatewayStateError("live_gateway_capability_invalid")
        row["claim_state"] = "dispatch_ambiguous"
        row["infrastructure_code"] = code

    def complete_result(self, token_digest: str, claim_id: str, result: dict[str, Any]) -> None:
        row = self.rows[token_digest]
        if row["claim_state"] != "dispatched" or row["claim_id"] != claim_id:
            raise LiveGatewayStateError("live_gateway_capability_invalid")
        if result.get("request_digest") != row["provider_request_digest"]:
            raise LiveGatewayStateError("live_gateway_result_conflict")
        row["result"] = result
        row["claim_state"] = "completed"

    def claim_provider_reconciliations(self, **kwargs: object) -> tuple[dict[str, Any], ...]:
        claimed: list[dict[str, Any]] = []
        observed_at = kwargs["observed_at"]
        current_boot_id = kwargs["current_boot_id"]
        process_identity = kwargs["process_identity"]
        for token_digest, row in sorted(self.rows.items()):
            if (
                row["claim_state"] not in {"dispatched", "dispatch_ambiguous", "reconciling"}
                or row["claim_expires_at"] > observed_at
            ):
                continue
            if row["claim_state"] in {"dispatched", "reconciling"}:
                alive = (
                    process_identity(row["claim_pid"])
                    if row["claim_boot_id"] == current_boot_id
                    else None
                )
                if alive == row["claim_process_start"]:
                    continue
            if row["provider_operation"] is None or row["provider_request"] is None:
                row["claim_state"] = "invalid"
                row["infrastructure_code"] = "gateway_provider_operation_missing"
                continue
            row["claim_state"] = "reconciling"
            row["claim_id"] = kwargs["claim_id"]
            row["claim_boot_id"] = current_boot_id
            row["claim_pid"] = kwargs["process_id"]
            row["claim_process_start"] = kwargs["process_start"]
            row["claim_expires_at"] = kwargs["expires_at"]
            row["provider_reconciliation_count"] += 1
            claimed.append(
                {
                    "claim_id": kwargs["claim_id"],
                    "operation": row["provider_operation"],
                    "request": row["provider_request"],
                    "reconciliation_count": row["provider_reconciliation_count"],
                    "retry_count": row["provider_retry_count"],
                    "token_digest": token_digest,
                }
            )
        return tuple(claimed)

    def complete_provider_reconciliation(
        self,
        token_digest: str,
        claim_id: str,
        *,
        result: dict[str, Any],
        receipt: dict[str, Any],
    ) -> None:
        row = self.rows[token_digest]
        if (
            row["claim_state"] != "reconciling"
            or row["claim_id"] != claim_id
            or result.get("request_digest") != row["provider_request_digest"]
        ):
            raise LiveGatewayStateError("live_gateway_result_conflict")
        row["result"] = result
        row["provider_reconciliation_receipt"] = receipt
        row["claim_state"] = "completed"
        row["infrastructure_code"] = None

    def authorize_provider_retry(self, token_digest: str, claim_id: str, **kwargs: object) -> bool:
        row = self.rows[token_digest]
        if row["claim_state"] != "reconciling" or row["claim_id"] != claim_id:
            raise LiveGatewayStateError("live_gateway_reconciliation_not_authorized")
        row["provider_reconciliation_receipt"] = kwargs["receipt"]
        if row["provider_retry_count"] >= 1:
            row["claim_state"] = "invalid"
            row["infrastructure_code"] = "gateway_provider_retry_exhausted"
            return False
        row["provider_retry_count"] = 1
        row["claim_state"] = "dispatched"
        row["claim_expires_at"] = kwargs["expires_at"]
        row["infrastructure_code"] = None
        return True

    def defer_provider_reconciliation(
        self, token_digest: str, claim_id: str, **kwargs: object
    ) -> None:
        row = self.rows[token_digest]
        if row["claim_state"] != "reconciling" or row["claim_id"] != claim_id:
            raise LiveGatewayStateError("live_gateway_reconciliation_not_authorized")
        row["claim_state"] = "dispatch_ambiguous"
        row["infrastructure_code"] = kwargs["code"]
        row["claim_expires_at"] = kwargs["retry_at"]
        if kwargs["receipt"] is not None:
            row["provider_reconciliation_receipt"] = kwargs["receipt"]

    def freeze_provider_operation(self, token_digest: str, **kwargs: object) -> None:
        row = self.rows[token_digest]
        if row["claim_state"] == "completed" or (
            kwargs.get("claim_id") is not None and row["claim_id"] != kwargs["claim_id"]
        ):
            raise LiveGatewayStateError("live_gateway_reconciliation_not_authorized")
        row["claim_state"] = "invalid"
        row["infrastructure_code"] = kwargs["code"]
        if kwargs.get("receipt") is not None:
            row["provider_reconciliation_receipt"] = kwargs["receipt"]

    def take_result(self, token_digest: str) -> tuple[dict[str, Any], dict[str, Any]]:
        row = self.rows.get(token_digest)
        if row is None:
            raise LiveGatewayStateError("live_gateway_capability_invalid")
        if row["collected"]:
            raise LiveGatewayStateError("live_gateway_result_consumed")
        if row["result"] is None:
            raise LiveGatewayStateError("live_gateway_result_unavailable")
        row["collected"] = True
        return row["grant"], row["result"]

    def peek_result(self, token_digest: str) -> tuple[dict[str, Any], dict[str, Any]]:
        row = self.rows.get(token_digest)
        if row is None:
            raise LiveGatewayStateError("live_gateway_capability_invalid")
        if row["claim_state"] != "completed" or row["result"] is None:
            raise LiveGatewayStateError("live_gateway_result_unavailable")
        return row["grant"], row["result"]

    def load_sealed_bundle(self, runner_request_digest: str) -> dict[str, Any] | None:
        for row in self.rows.values():
            if row["runner_request_digest"] == runner_request_digest:
                if row["sealed_bundle"] is None:
                    return None
                return row["sealed_bundle"]
        return None

    def load_resumable_result(
        self, runner_request_digest: str
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
        for row in self.rows.values():
            if row["runner_request_digest"] != runner_request_digest:
                continue
            if row["sealed_bundle"] is not None:
                return None
            if (
                row["claim_state"] != "completed"
                or row["result"] is None
                or type(row["runner_context"]) is not dict
            ):
                raise LiveGatewayStateError("live_gateway_execution_resume_unavailable")
            return row["grant"], row["result"], row["runner_context"]
        return None

    def seal_result_bundle(
        self,
        token_digest: str,
        *,
        runner_request_digest: str,
        bundle: dict[str, Any],
    ) -> dict[str, Any]:
        row = self.rows.get(token_digest)
        if row is None:
            raise LiveGatewayStateError("live_gateway_capability_invalid")
        if row["sealed_bundle"] is not None:
            if (
                row["runner_request_digest"] != runner_request_digest
                or row["sealed_bundle"] != bundle
            ):
                raise LiveGatewayStateError("live_gateway_bundle_conflict")
            return row["sealed_bundle"]
        if (
            row["collected"]
            or row["claim_state"] != "completed"
            or row["result"] is None
            or row["runner_request_digest"] not in {None, runner_request_digest}
            or bundle.get("model_result") != row["result"]
            or any(
                existing is not row and existing["runner_request_digest"] == runner_request_digest
                for existing in self.rows.values()
            )
        ):
            raise LiveGatewayStateError("live_gateway_bundle_conflict")
        row["runner_request_digest"] = runner_request_digest
        row["sealed_bundle"] = bundle
        row["collected"] = True
        return bundle

    def seal_resumed_result_bundle(
        self,
        runner_request_digest: str,
        *,
        bundle: dict[str, Any],
    ) -> dict[str, Any]:
        for token_digest, row in self.rows.items():
            if row["runner_request_digest"] == runner_request_digest:
                return self.seal_result_bundle(
                    token_digest,
                    runner_request_digest=runner_request_digest,
                    bundle=bundle,
                )
        raise LiveGatewayStateError("live_gateway_execution_resume_unavailable")

    def record_infrastructure_invalid(self, token_digest: str, code: str) -> None:
        row = self.rows.get(token_digest)
        if row is None:
            raise LiveGatewayStateError("live_gateway_capability_invalid")
        if (
            row["claim_state"] in {"dispatched", "dispatch_ambiguous"}
            or row["result"] is not None
            or row["infrastructure_code"] not in {None, code}
        ):
            raise LiveGatewayStateError("live_infrastructure_result_conflict")
        row["claim_state"] = "invalid"
        row["infrastructure_code"] = code

    def invalidate_execution(self, token_digest: str, code: str) -> None:
        row = self.rows.get(token_digest)
        if (
            row is None
            or row["collected"]
            or row["claim_state"] in {"dispatched", "dispatch_ambiguous"}
            or row["infrastructure_code"] not in {None, code}
        ):
            raise LiveGatewayStateError("live_infrastructure_result_conflict")
        row["result"] = None
        row["claim_state"] = "invalid"
        row["infrastructure_code"] = code

    def retry_codes(self, pair_request_digest: str, task_id: str, attempt: int) -> dict[str, str]:
        result: dict[str, str] = {}
        for row in self.rows.values():
            grant = row["grant"]
            actual = grant["actual"]
            if (
                actual["pair_request_digest"] == pair_request_digest
                and actual["task_id"] == task_id
                and actual["attempt"] == attempt
                and row["infrastructure_code"] is not None
                and row["claim_state"] == "invalid"
            ):
                result[actual["subject"]] = row["infrastructure_code"]
        return result

    def reconcile_abandoned_claims(self, **kwargs: object) -> tuple[str, ...]:
        reconciled: list[str] = []
        observed_at = kwargs["observed_at"]
        current_boot_id = kwargs["current_boot_id"]
        process_identity = kwargs["process_identity"]
        for token_digest, row in self.rows.items():
            if (
                row["claim_state"] not in {"pre_dispatch", "dispatched"}
                or row["claim_expires_at"] > observed_at
            ):
                continue
            alive = (
                process_identity(row["claim_pid"])
                if row["claim_boot_id"] == current_boot_id
                else None
            )
            if alive == row["claim_process_start"]:
                continue
            if row["claim_state"] == "pre_dispatch":
                row["claim_state"] = "invalid"
                row["infrastructure_code"] = "gateway_pre_dispatch_abandoned"
            else:
                row["claim_state"] = "dispatch_ambiguous"
                row["infrastructure_code"] = "gateway_dispatch_ambiguous"
            reconciled.append(token_digest)
        return tuple(sorted(reconciled))


def _request_document(request: OpenAIModelRequest) -> dict[str, Any]:
    try:
        value = json.loads(request.to_bytes())
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LiveGatewayAuthorityError("live_gateway_provider_operation_invalid") from error
    if type(value) is not dict:
        raise LiveGatewayAuthorityError("live_gateway_provider_operation_invalid")
    return value


def _receipt_document(receipt: ProviderReconciliationReceipt) -> dict[str, Any]:
    result_digest = (
        None
        if receipt.result is None
        else hashlib.sha256(canonical_json_bytes(_result_document(receipt.result))).hexdigest()
    )
    return {
        "operation_digest": receipt.operation_digest,
        "receipt_digest": receipt.receipt_digest,
        "request_digest": receipt.request_digest,
        "result_digest": result_digest,
        "schema_version": 1,
        "status": receipt.status,
    }


class ProtectedModelGatewayServer:
    """Service-owned registry that turns opaque one-use tokens into fixed model calls."""

    __slots__ = (
        "_claim_holder",
        "_clock",
        "_endpoint",
        "_gateway",
        "_process_identity",
        "_state",
        "_token_source",
    )

    def __new__(cls, *args: object, **kwargs: object) -> ProtectedModelGatewayServer:
        del cls, args, kwargs
        raise LiveGatewayAuthorityError("live_gateway_protected_construction_required")

    @classmethod
    def from_protected_process(cls) -> ProtectedModelGatewayServer:
        """Construct only from protected-process policy and credentials."""
        try:
            gateway = OpenAIModelGateway.from_protected_environment()
        except OpenAIGatewayError as error:
            if error.code in {
                "openai_credentials_missing",
                "openai_provenance_key_missing",
            }:
                raise LiveGatewayAuthorityError("live_acp_credential_missing") from error
            raise LiveGatewayAuthorityError("live_gateway_unavailable") from error
        boot_id, process_id, process_start = cls._protected_claim_holder()
        return cls._construct(
            gateway=gateway,
            endpoint=_ENDPOINT,
            token_source=lambda: secrets.token_urlsafe(32),
            state=SQLiteLiveGatewayStateStore.from_protected_process(),
            clock=lambda: datetime.now(UTC),
            claim_holder=(boot_id, process_id, process_start),
            process_identity=cls._process_start,
        )

    @staticmethod
    def _process_start(process_id: int) -> str | None:
        try:
            payload = Path(f"/proc/{process_id}/stat").read_bytes()
        except OSError:
            return None
        if not 0 < len(payload) <= 16_384:
            return None
        closing = payload.rfind(b")")
        if closing < 0:
            return None
        fields = payload[closing + 1 :].split()
        if len(fields) < 20:
            return None
        start = fields[19]
        try:
            decoded = start.decode("ascii")
        except UnicodeError:
            return None
        return decoded if decoded.isdecimal() else None

    @classmethod
    def _protected_claim_holder(cls) -> tuple[str, int, str]:
        try:
            boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        except OSError as error:
            raise LiveGatewayAuthorityError("live_gateway_claim_observer_unavailable") from error
        process_id = os.getpid()
        process_start = cls._process_start(process_id)
        if _BOOT_ID_RE.fullmatch(boot_id) is None or process_start is None:
            raise LiveGatewayAuthorityError("live_gateway_claim_observer_unavailable")
        return boot_id, process_id, process_start

    @classmethod
    def _for_testing(
        cls,
        *,
        gateway: _PinnedGateway,
        endpoint: str,
        token_source: Callable[[], str],
        state: _GatewayState | None = None,
        clock: Callable[[], datetime] | None = None,
        claim_holder: tuple[str, int, str] | None = None,
        process_identity: Callable[[int], str | None] | None = None,
    ) -> ProtectedModelGatewayServer:
        if (
            not callable(getattr(gateway, "protected_execution_policy", None))
            or not callable(getattr(gateway, "evaluate", None))
            or not callable(getattr(gateway, "verify_protected_result", None))
            or not callable(token_source)
        ):
            raise LiveGatewayAuthorityError("live_gateway_test_configuration_invalid")
        return cls._construct(
            gateway=gateway,
            endpoint=endpoint,
            token_source=token_source,
            state=state if state is not None else _MemoryGatewayState(),
            clock=clock if clock is not None else (lambda: datetime.now(UTC)),
            claim_holder=(
                claim_holder
                if claim_holder is not None
                else ("11111111-1111-4111-8111-111111111111", 1, "test-process-1")
            ),
            process_identity=(
                process_identity
                if process_identity is not None
                else (lambda process_id: "test-process-1" if process_id == 1 else None)
            ),
        )

    @classmethod
    def _construct(
        cls,
        *,
        gateway: _PinnedGateway,
        endpoint: str,
        token_source: Callable[[], str],
        state: _GatewayState,
        clock: Callable[[], datetime],
        claim_holder: tuple[str, int, str],
        process_identity: Callable[[int], str | None],
    ) -> ProtectedModelGatewayServer:
        try:
            BoundedModelGatewayCapability(
                endpoint=endpoint,
                token="validation-token-1234567890",
                pair_request_digest="0" * 64,
                subject="parent",
                task_id="validation",
                attempt=1,
            )
        except ValueError as error:
            raise LiveGatewayAuthorityError("live_gateway_endpoint_invalid") from error
        value = object.__new__(cls)
        value._gateway = gateway
        value._endpoint = endpoint
        value._token_source = token_source
        value._state = state
        if (
            not callable(clock)
            or not callable(process_identity)
            or not isinstance(claim_holder, tuple)
            or len(claim_holder) != 3
            or not isinstance(claim_holder[0], str)
            or _BOOT_ID_RE.fullmatch(claim_holder[0]) is None
            or isinstance(claim_holder[1], bool)
            or not isinstance(claim_holder[1], int)
            or claim_holder[1] <= 0
            or not isinstance(claim_holder[2], str)
            or not claim_holder[2]
        ):
            raise LiveGatewayAuthorityError("live_gateway_claim_observer_invalid")
        value._clock = clock
        value._claim_holder = claim_holder
        value._process_identity = process_identity
        try:
            value._state.reconcile_abandoned_claims(
                observed_at=value._now_epoch(),
                current_boot_id=claim_holder[0],
                process_identity=process_identity,
            )
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error
        value.reconcile_expired_provider_operations()
        return value

    def _now_epoch(self) -> int:
        observed = self._clock()
        if (
            not isinstance(observed, datetime)
            or observed.tzinfo is None
            or observed.utcoffset() is None
            or observed.utcoffset().total_seconds() != 0
        ):
            raise LiveGatewayAuthorityError("live_gateway_clock_invalid")
        return int(observed.timestamp())

    def _provider_capability(self) -> ProviderReconciliationCapability | None:
        operation = getattr(self._gateway, "provider_reconciliation_capability", None)
        if not callable(operation):
            return None
        try:
            capability = operation()
        except Exception:
            return None
        return capability if type(capability) is ProviderReconciliationCapability else None

    @staticmethod
    def _capability_matches_operation(
        capability: ProviderReconciliationCapability,
        operation: ProviderOperationIdentity,
    ) -> bool:
        return (
            capability.provider == operation.provider
            and capability.project_digest == operation.project_digest
            and capability.protocol_revision == operation.protocol_revision
            and capability.receipt_authority_digest == operation.receipt_authority_digest
        )

    def _operation_identity(
        self,
        *,
        grant: _Grant,
        request: OpenAIModelRequest,
        capability: ProviderReconciliationCapability,
    ) -> ProviderOperationIdentity:
        try:
            runner_request_digest, grant_digest = self._state.load_provider_binding(
                grant.token_digest
            )
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error
        runner_binding = runner_request_digest or grant.actual.execution_context_digest
        return ProviderOperationIdentity(
            provider=capability.provider,
            project_digest=capability.project_digest,
            protocol_revision=capability.protocol_revision,
            receipt_authority_digest=capability.receipt_authority_digest,
            grant_digest=grant_digest,
            runner_binding_digest=runner_binding,
            runner_binding_kind=(
                "runner_request" if runner_request_digest is not None else "execution_context"
            ),
            request_digest=request.request_digest,
            model=grant.actual.model,
            attempt=grant.actual.attempt,
            immutable_inputs_digest=hashlib.sha256(request.to_bytes()).hexdigest(),
        )

    def _validate_stored_operation(
        self,
        *,
        token_digest: str,
        operation: ProviderOperationIdentity,
        request: OpenAIModelRequest,
    ) -> None:
        try:
            grant = _grant_from_document(self._state.load_grant(token_digest))
            runner_request_digest, grant_digest = self._state.load_provider_binding(token_digest)
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error
        expected_request = grant.identity.model_request_digest(
            subject=grant.actual.subject,
            task=grant.task,
            policy=grant.policy,
            seed=grant.actual.seed,
            attempt=grant.actual.attempt,
        )
        input_bytes = request.input.encode("utf-8")
        expected_runner_binding = runner_request_digest or grant.actual.execution_context_digest
        if (
            operation.grant_digest != grant_digest
            or operation.runner_binding_digest != expected_runner_binding
            or operation.runner_binding_kind
            != ("runner_request" if runner_request_digest is not None else "execution_context")
            or operation.request_digest != request.request_digest
            or operation.request_digest != expected_request
            or operation.model != grant.actual.model
            or operation.attempt != grant.actual.attempt
            or operation.immutable_inputs_digest != hashlib.sha256(request.to_bytes()).hexdigest()
            or len(input_bytes) != grant.task.input_size
            or hashlib.sha256(input_bytes).hexdigest() != grant.task.input_digest
        ):
            raise LiveGatewayAuthorityError("live_gateway_provider_operation_binding_invalid")

    def _verified_reconciliation_receipt(
        self,
        *,
        receipt: object,
        operation: ProviderOperationIdentity,
        request: OpenAIModelRequest,
    ) -> ProviderReconciliationReceipt:
        verifier = getattr(self._gateway, "verify_provider_reconciliation", None)
        try:
            verified = callable(verifier) and verifier(receipt, operation)
        except Exception:
            verified = False
        if (
            type(receipt) is not ProviderReconciliationReceipt
            or not verified
            or receipt.operation_digest != operation.digest
            or receipt.request_digest != request.request_digest
        ):
            raise LiveGatewayAuthorityError("live_gateway_provider_reconciliation_invalid")
        return receipt

    def reconcile_expired_provider_operations(self) -> tuple[str, ...]:
        """Advance expired ambiguous creates only from authenticated provider receipts."""
        observed_at = self._now_epoch()
        reconciliation_id = hashlib.sha256(
            canonical_json_bytes(
                {
                    "boot_id": self._claim_holder[0],
                    "domain": "carl.live-gateway-provider-reconciliation.v1",
                    "observed_at": observed_at,
                    "process_id": self._claim_holder[1],
                    "process_start": self._claim_holder[2],
                }
            )
        ).hexdigest()
        try:
            claims = self._state.claim_provider_reconciliations(
                observed_at=observed_at,
                claim_id=reconciliation_id,
                current_boot_id=self._claim_holder[0],
                process_id=self._claim_holder[1],
                process_start=self._claim_holder[2],
                expires_at=observed_at + _CLAIM_LEASE_SECONDS,
                process_identity=self._process_identity,
            )
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error
        advanced: list[str] = []
        for claim in claims:
            token_digest = claim["token_digest"]
            claim_id = claim["claim_id"]
            try:
                operation = ProviderOperationIdentity.from_canonical_dict(claim["operation"])
                request = OpenAIModelRequest.from_bytes(canonical_json_bytes(claim["request"]))
                self._validate_stored_operation(
                    token_digest=token_digest,
                    operation=operation,
                    request=request,
                )
                capability = self._provider_capability()
                if capability is None or not self._capability_matches_operation(
                    capability, operation
                ):
                    raise LiveGatewayAuthorityError(
                        "live_gateway_provider_reconciliation_unsupported"
                    )
                reconciler = getattr(self._gateway, "reconcile_provider_operation", None)
                if not callable(reconciler):
                    raise LiveGatewayAuthorityError(
                        "live_gateway_provider_reconciliation_unsupported"
                    )
                receipt = self._verified_reconciliation_receipt(
                    receipt=reconciler(request, operation),
                    operation=operation,
                    request=request,
                )
                receipt_document = _receipt_document(receipt)
                if receipt.status == "completed":
                    result = receipt.result
                    try:
                        protected = type(
                            result
                        ) is ProtectedOpenAIModelResult and self._gateway.verify_protected_result(
                            result
                        )
                    except Exception:
                        protected = False
                    if not protected or result.request_digest != request.request_digest:
                        raise LiveGatewayAuthorityError(
                            "live_gateway_provider_reconciliation_invalid"
                        )
                    self._state.complete_provider_reconciliation(
                        token_digest,
                        claim_id,
                        result=_result_document(result),
                        receipt=receipt_document,
                    )
                elif receipt.status == "not_executed":
                    if not self._state.authorize_provider_retry(
                        token_digest,
                        claim_id,
                        receipt=receipt_document,
                        dispatched_at=observed_at,
                        expires_at=observed_at + _CLAIM_LEASE_SECONDS,
                    ):
                        advanced.append(token_digest)
                        continue
                    dispatcher = getattr(self._gateway, "dispatch_reconciled", None)
                    if not callable(dispatcher):
                        raise LiveGatewayAuthorityError(
                            "live_gateway_provider_reconciliation_unsupported"
                        )
                    try:
                        result = dispatcher(request, operation)
                        verified = self._gateway.verify_protected_result(result)
                    except OpenAIGatewayError:
                        self._mark_dispatch_ambiguous(token_digest, claim_id)
                        advanced.append(token_digest)
                        continue
                    except Exception:
                        self._mark_dispatch_ambiguous(token_digest, claim_id)
                        advanced.append(token_digest)
                        continue
                    if type(result) is not ProtectedOpenAIModelResult or not verified:
                        self._mark_dispatch_ambiguous(token_digest, claim_id)
                        advanced.append(token_digest)
                        continue
                    try:
                        self._state.complete_result(
                            token_digest,
                            claim_id,
                            _result_document(result),
                        )
                    except LiveGatewayStateError:
                        self._mark_dispatch_ambiguous(token_digest, claim_id)
                else:
                    if claim["reconciliation_count"] >= 3:
                        raise LiveGatewayAuthorityError(
                            "live_gateway_provider_reconciliation_exhausted"
                        )
                    self._state.defer_provider_reconciliation(
                        token_digest,
                        claim_id,
                        receipt=receipt_document,
                        code="gateway_provider_reconciliation_pending",
                        retry_at=observed_at + _CLAIM_LEASE_SECONDS,
                    )
                advanced.append(token_digest)
            except LiveGatewayAuthorityError as error:
                try:
                    self._state.freeze_provider_operation(
                        token_digest,
                        claim_id=claim_id,
                        code=error.code.removeprefix("live_"),
                    )
                except LiveGatewayStateError as state_error:
                    raise LiveGatewayAuthorityError(state_error.code) from state_error
                advanced.append(token_digest)
            except Exception as error:
                code = (
                    getattr(error, "code", "live_gateway_provider_reconciliation_invalid")
                    if isinstance(error, OpenAIGatewayError | LiveGatewayStateError)
                    else "live_gateway_provider_reconciliation_unavailable"
                )
                try:
                    if claim["reconciliation_count"] >= 3:
                        self._state.freeze_provider_operation(
                            token_digest,
                            claim_id=claim_id,
                            code="gateway_provider_reconciliation_exhausted",
                        )
                    else:
                        self._state.defer_provider_reconciliation(
                            token_digest,
                            claim_id,
                            receipt=None,
                            code=code.removeprefix("live_"),
                            retry_at=observed_at + _CLAIM_LEASE_SECONDS,
                        )
                except LiveGatewayStateError as state_error:
                    raise LiveGatewayAuthorityError(state_error.code) from state_error
                advanced.append(token_digest)
        return tuple(advanced)

    @staticmethod
    def _expected_actual(
        *,
        identity: LiveEvaluationIdentity,
        policy: LivePairPolicy,
        task: LiveTaskIdentity,
        subject: str,
        attempt: int,
        process_id: int = 1,
        worker_uid: int = 1,
        worker_gid: int = 1,
        executable_digest: str | None = None,
        checkout_digest: str | None = None,
        isolation_digest: str | None = None,
    ) -> ActualLiveExecution:
        if subject not in {"parent", "candidate"}:
            raise LiveGatewayAuthorityError("live_execution_binding_mismatch")
        if (
            isinstance(attempt, bool)
            or not isinstance(attempt, int)
            or not 1 <= attempt <= identity.attempts
        ):
            raise LiveGatewayAuthorityError("live_execution_binding_mismatch")
        seed = identity.seeds[attempt - 1]
        return ActualLiveExecution._observed(
            repository=identity.repository,
            pair_request_digest=identity.request_digest,
            subject=subject,
            subject_commit=(
                identity.parent_commit if subject == "parent" else identity.candidate_commit
            ),
            subject_tree=identity.parent_tree if subject == "parent" else identity.candidate_tree,
            task_id=task.task_id,
            task_digest=task.task_digest,
            input_digest=task.input_digest,
            input_size=task.input_size,
            grader_digest=task.grader_digest,
            task_role=task.role,
            seed=seed,
            attempt=attempt,
            environment_digest=identity.environment_digest,
            model=identity.model,
            reasoning_policy=identity.reasoning_policy,
            live_policy_digest=hashlib.sha256(
                canonical_json_bytes(policy.to_canonical_dict())
            ).hexdigest(),
            execution_context_digest=identity.execution_context_digest(
                subject=subject,
                task=task,
                policy=policy,
                seed=seed,
                attempt=attempt,
            ),
            process_id=process_id,
            worker_uid=worker_uid,
            worker_gid=worker_gid,
            executable_digest=executable_digest or hashlib.sha256(b"test-executable").hexdigest(),
            checkout_digest=checkout_digest or hashlib.sha256(b"test-checkout").hexdigest(),
            isolation_digest=isolation_digest or hashlib.sha256(b"test-isolation").hexdigest(),
        )

    def issue_capability(
        self, observation: ProtectedExecutionObservation
    ) -> BoundedModelGatewayCapability:
        """Issue only from an observation minted by the protected process runner."""
        if not isinstance(observation, ProtectedExecutionObservation):
            raise LiveGatewayAuthorityError("live_execution_observation_protected")
        return self._issue_observed_capability(
            identity=observation.identity,
            policy=observation.policy,
            task=observation.task,
            actual=observation.actual,
        )

    def issue_observed_capability_for_testing(
        self,
        *,
        identity: LiveEvaluationIdentity,
        policy: LivePairPolicy,
        task: LiveTaskIdentity,
        subject: str,
        attempt: int,
        observed_overrides: dict[str, object] | None = None,
    ) -> BoundedModelGatewayCapability:
        """Test seam that exercises the production binding logic without launching a worker."""
        actual = self._expected_actual(
            identity=identity,
            policy=policy,
            task=task,
            subject=subject,
            attempt=attempt,
        )
        if observed_overrides:
            values = actual.to_canonical_dict() | observed_overrides
            actual = ActualLiveExecution._observed(**values)
        return self._issue_observed_capability(
            identity=identity,
            policy=policy,
            task=task,
            actual=actual,
        )

    def _issue_observed_capability(
        self,
        *,
        identity: LiveEvaluationIdentity,
        policy: LivePairPolicy,
        task: LiveTaskIdentity,
        actual: ActualLiveExecution,
        prepared: BoundedModelGatewayCapability | None = None,
        runner_request_digest: str | None = None,
        runner_context: dict[str, Any] | None = None,
    ) -> BoundedModelGatewayCapability:
        if (
            not isinstance(identity, LiveEvaluationIdentity)
            or not isinstance(policy, LivePairPolicy)
            or not isinstance(task, LiveTaskIdentity)
            or not isinstance(actual, ActualLiveExecution)
            or task.task_id not in identity.task_order
            or task.grader_digest != identity.grader_digest
            or identity.attempts > policy.maximum_pair_retries + 1
            or (runner_request_digest is None) != (runner_context is None)
            or (runner_context is not None and type(runner_context) is not dict)
        ):
            raise LiveGatewayAuthorityError("live_execution_binding_mismatch")
        if runner_request_digest is not None:
            _digest(runner_request_digest, "live_gateway_runner_binding_invalid")
        try:
            protected_policy = self._gateway.protected_execution_policy()
        except Exception as error:
            raise LiveGatewayAuthorityError("live_execution_binding_mismatch") from error
        policy_digest = hashlib.sha256(canonical_json_bytes(protected_policy)).hexdigest()
        if (
            protected_policy
            != {
                "model": identity.model,
                "policy_revision": "openai-responses-policy-2026-08-20.1",
                "reasoning_policy": identity.reasoning_policy,
            }
            or identity.model_policy_digest != policy_digest
        ):
            raise LiveGatewayAuthorityError("live_execution_binding_mismatch")
        expected = self._expected_actual(
            identity=identity,
            policy=policy,
            task=task,
            subject=actual.subject,
            attempt=actual.attempt,
            process_id=actual.process_id,
            worker_uid=actual.worker_uid,
            worker_gid=actual.worker_gid,
            executable_digest=actual.executable_digest,
            checkout_digest=actual.checkout_digest,
            isolation_digest=actual.isolation_digest,
        )
        if actual != expected:
            raise LiveGatewayAuthorityError("live_execution_binding_mismatch")
        issue_key = hashlib.sha256(
            canonical_json_bytes(
                {
                    "attempt": actual.attempt,
                    "pair_request_digest": identity.request_digest,
                    "subject": actual.subject,
                    "task_id": task.task_id,
                }
            )
        ).hexdigest()
        if actual.attempt > 1:
            try:
                prior = self._state.retry_codes(
                    identity.request_digest, task.task_id, actual.attempt - 1
                )
            except LiveGatewayStateError as error:
                raise LiveGatewayAuthorityError(error.code) from error
            if set(prior) != {"parent", "candidate"} or len(set(prior.values())) != 1:
                raise LiveGatewayAuthorityError("live_retry_not_authorized")
        capability = prepared or self._prepare_capability(
            identity=identity,
            task=task,
            subject=actual.subject,
            attempt=actual.attempt,
        )
        if (
            capability.pair_request_digest != identity.request_digest
            or capability.subject != actual.subject
            or capability.task_id != task.task_id
            or capability.attempt != actual.attempt
            or capability.endpoint != self._endpoint
        ):
            raise LiveGatewayAuthorityError("live_gateway_token_invalid")
        token = capability.token
        token_digest = hashlib.sha256(token.encode()).hexdigest()
        grant = _Grant(identity, policy, task, actual, token_digest)
        try:
            self._state.reserve_grant(
                token_digest=token_digest,
                issue_key=issue_key,
                pair_request_digest=identity.request_digest,
                task_id=task.task_id,
                attempt=actual.attempt,
                subject=actual.subject,
                grant=_grant_document(grant),
                runner_request_digest=runner_request_digest,
                runner_context=runner_context,
            )
        except LiveGatewayStateError as error:
            code = (
                "live_gateway_capability_duplicate"
                if error.code == "live_gateway_grant_conflict"
                else error.code
            )
            raise LiveGatewayAuthorityError(code) from error
        return capability

    def _prepare_capability(
        self,
        *,
        identity: LiveEvaluationIdentity,
        task: LiveTaskIdentity,
        subject: str,
        attempt: int,
    ) -> BoundedModelGatewayCapability:
        token = self._token_source()
        try:
            return BoundedModelGatewayCapability(
                endpoint=self._endpoint,
                token=token,
                pair_request_digest=identity.request_digest,
                subject=subject,
                task_id=task.task_id,
                attempt=attempt,
            )
        except (TypeError, ValueError) as error:
            raise LiveGatewayAuthorityError("live_gateway_token_invalid") from error

    def _grant(self, token: object) -> _Grant:
        if not isinstance(token, str):
            raise LiveGatewayAuthorityError("live_gateway_capability_invalid")
        try:
            value = self._state.load_grant(hashlib.sha256(token.encode()).hexdigest())
            return _grant_from_document(value)
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error

    def evaluate(self, token: str, input_text: str) -> ProtectedOpenAIModelResult:
        grant = self._grant(token)
        if not isinstance(input_text, str):
            raise LiveGatewayAuthorityError("live_gateway_input_mismatch")
        try:
            payload = input_text.encode("utf-8")
        except UnicodeError:
            raise LiveGatewayAuthorityError("live_gateway_input_mismatch") from None
        if (
            len(payload) != grant.task.input_size
            or hashlib.sha256(payload).hexdigest() != grant.task.input_digest
        ):
            raise LiveGatewayAuthorityError("live_gateway_input_mismatch")
        request = OpenAIModelRequest(
            schema_version=1,
            repository=grant.identity.repository,
            experiment_id=grant.identity.experiment_digest,
            subject="baseline" if grant.actual.subject == "parent" else "candidate",
            task_id=grant.task.task_id,
            seed=grant.actual.seed,
            attempt=grant.actual.attempt,
            input=input_text,
            execution_context_digest=grant.actual.execution_context_digest,
        )
        expected_digest = grant.identity.model_request_digest(
            subject=grant.actual.subject,
            task=grant.task,
            policy=grant.policy,
            seed=grant.actual.seed,
            attempt=grant.actual.attempt,
        )
        if request.request_digest != expected_digest:
            raise LiveGatewayAuthorityError("live_execution_binding_mismatch")
        claim_id = hashlib.sha256(
            canonical_json_bytes(
                {
                    "domain": "carl.live-gateway-provider-claim.v1",
                    "request_digest": request.request_digest,
                    "token_digest": grant.token_digest,
                }
            )
        ).hexdigest()
        started_at = self._now_epoch()
        try:
            claimed = _grant_from_document(
                self._state.claim_grant(
                    grant.token_digest,
                    claim_id=claim_id,
                    boot_id=self._claim_holder[0],
                    process_id=self._claim_holder[1],
                    process_start=self._claim_holder[2],
                    started_at=started_at,
                    expires_at=started_at + _CLAIM_LEASE_SECONDS,
                )
            )
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error
        if claimed != grant:
            raise LiveGatewayAuthorityError("live_gateway_grant_invalid")
        capability = self._provider_capability()
        dispatcher = getattr(self._gateway, "dispatch_reconciled", None)
        reconciler = getattr(self._gateway, "reconcile_provider_operation", None)
        verifier = getattr(self._gateway, "verify_provider_reconciliation", None)
        if (
            capability is None
            or not callable(dispatcher)
            or not callable(reconciler)
            or not callable(verifier)
        ):
            try:
                self._state.freeze_provider_operation(
                    grant.token_digest,
                    claim_id=claim_id,
                    code="gateway_provider_reconciliation_unsupported",
                )
            except LiveGatewayStateError as error:
                raise LiveGatewayAuthorityError(error.code) from error
            raise LiveGatewayAuthorityError("live_gateway_provider_reconciliation_unsupported")
        operation = self._operation_identity(
            grant=grant,
            request=request,
            capability=capability,
        )
        try:
            self._state.mark_provider_dispatched(
                grant.token_digest,
                claim_id,
                request_digest=request.request_digest,
                operation=operation.to_canonical_dict(),
                request=_request_document(request),
                dispatched_at=self._now_epoch(),
            )
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error
        try:
            result = dispatcher(request, operation)
            verified = self._gateway.verify_protected_result(result)
        except OpenAIGatewayError as error:
            self._mark_dispatch_ambiguous(grant.token_digest, claim_id)
            raise LiveGatewayAuthorityError(error.code) from error
        except Exception as error:
            self._mark_dispatch_ambiguous(grant.token_digest, claim_id)
            raise LiveGatewayAuthorityError("live_gateway_unavailable") from error
        if type(result) is not ProtectedOpenAIModelResult or not verified:
            self._mark_dispatch_ambiguous(grant.token_digest, claim_id)
            raise LiveGatewayAuthorityError("live_model_provenance_invalid")
        try:
            self._state.complete_result(
                grant.token_digest,
                claim_id,
                _result_document(result),
            )
        except LiveGatewayStateError as error:
            with suppress(LiveGatewayAuthorityError):
                self._mark_dispatch_ambiguous(grant.token_digest, claim_id)
            raise LiveGatewayAuthorityError(error.code) from error
        return result

    def _mark_dispatch_ambiguous(self, token_digest: str, claim_id: str) -> None:
        try:
            self._state.mark_dispatch_ambiguous(
                token_digest,
                claim_id,
                code="gateway_dispatch_ambiguous",
            )
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error

    def take_completed_result(
        self, capability: BoundedModelGatewayCapability
    ) -> ProtectedOpenAIModelResult:
        """Transfer one authenticated result to the protected evaluator exactly once."""
        if not isinstance(capability, BoundedModelGatewayCapability):
            raise LiveGatewayAuthorityError("live_gateway_capability_invalid")
        token_digest = hashlib.sha256(capability.token.encode()).hexdigest()
        try:
            grant_document, result_document = self._state.take_result(token_digest)
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error
        return self._validated_completed_result(
            capability=capability,
            grant_document=grant_document,
            result_document=result_document,
        )

    def _validated_completed_result(
        self,
        *,
        capability: BoundedModelGatewayCapability,
        grant_document: dict[str, Any],
        result_document: dict[str, Any],
    ) -> ProtectedOpenAIModelResult:
        grant = _grant_from_document(grant_document)
        if (
            capability.pair_request_digest != grant.identity.request_digest
            or capability.subject != grant.actual.subject
            or capability.task_id != grant.task.task_id
            or capability.attempt != grant.actual.attempt
        ):
            raise LiveGatewayAuthorityError("live_gateway_capability_invalid")
        result = _result_from_document(result_document)
        try:
            verified = self._gateway.verify_protected_result(result)
        except Exception as error:
            raise LiveGatewayAuthorityError("live_model_provenance_invalid") from error
        if not verified:
            raise LiveGatewayAuthorityError("live_model_provenance_invalid")
        return result

    def peek_completed_result(
        self, capability: BoundedModelGatewayCapability
    ) -> ProtectedOpenAIModelResult:
        """Read a completed result without consuming it before bundle sealing."""
        if not isinstance(capability, BoundedModelGatewayCapability):
            raise LiveGatewayAuthorityError("live_gateway_capability_invalid")
        token_digest = hashlib.sha256(capability.token.encode()).hexdigest()
        try:
            grant_document, result_document = self._state.peek_result(token_digest)
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error
        return self._validated_completed_result(
            capability=capability,
            grant_document=grant_document,
            result_document=result_document,
        )

    def replay_sealed_execution_bundle(
        self, runner_request_digest: str
    ) -> ProtectedLiveExecutionResult | None:
        _digest(runner_request_digest, "live_gateway_bundle_invalid")
        try:
            document = self._state.load_sealed_bundle(runner_request_digest)
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error
        if document is None:
            return None
        try:
            bundle = ProtectedLiveExecutionResult.from_canonical_dict(document)
            verified = self._gateway.verify_protected_result(bundle.model_result)
        except Exception as error:
            raise LiveGatewayAuthorityError("live_gateway_bundle_invalid") from error
        if not verified:
            raise LiveGatewayAuthorityError("live_gateway_bundle_invalid")
        return bundle

    def resume_completed_execution(
        self, runner_request_digest: str
    ) -> tuple[ProtectedOpenAIModelResult, dict[str, Any]] | None:
        _digest(runner_request_digest, "live_gateway_bundle_invalid")
        try:
            resumed = self._state.load_resumable_result(runner_request_digest)
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error
        if resumed is None:
            return None
        grant_document, result_document, context = resumed
        try:
            grant = _grant_from_document(grant_document)
            result = _result_from_document(result_document)
            verified = self._gateway.verify_protected_result(result)
        except Exception as error:
            raise LiveGatewayAuthorityError("live_gateway_bundle_invalid") from error
        expected_context_fields = set(ProtectedExecutionReceipt.__dataclass_fields__) - {
            "schema_version",
            "model_result_digest",
            "model_request_digest",
            "model_output_digest",
            "response_id",
            "key_id",
            "signature",
        }
        actual = grant.actual
        expected_binding = {
            "attempt": actual.attempt,
            "checkout_digest": actual.checkout_digest,
            "cgroup_observation_digest": actual.isolation_digest,
            "environment_digest": actual.environment_digest,
            "executable_digest": actual.executable_digest,
            "execution_context_digest": actual.execution_context_digest,
            "grader_digest": actual.grader_digest,
            "input_digest": actual.input_digest,
            "input_size": actual.input_size,
            "live_policy_digest": actual.live_policy_digest,
            "model": actual.model,
            "model_policy_digest": grant.identity.model_policy_digest,
            "pair_request_digest": actual.pair_request_digest,
            "process_id": actual.process_id,
            "reasoning_policy": actual.reasoning_policy,
            "repository": actual.repository,
            "seed": actual.seed,
            "subject": actual.subject,
            "subject_commit": actual.subject_commit,
            "subject_tree": actual.subject_tree,
            "task_digest": actual.task_digest,
            "task_id": actual.task_id,
            "task_role": actual.task_role,
            "worker_gid": actual.worker_gid,
            "worker_uid": actual.worker_uid,
        }
        expected_request = grant.identity.model_request_digest(
            subject=actual.subject,
            task=grant.task,
            policy=grant.policy,
            seed=actual.seed,
            attempt=actual.attempt,
        )
        if (
            not verified
            or result.request_digest != expected_request
            or set(context) != expected_context_fields
            or any(context.get(name) != value for name, value in expected_binding.items())
        ):
            raise LiveGatewayAuthorityError("live_gateway_runner_binding_invalid")
        return result, context

    def seal_resumed_execution_bundle(
        self,
        runner_request_digest: str,
        *,
        bundle: ProtectedLiveExecutionResult,
    ) -> ProtectedLiveExecutionResult:
        if not isinstance(bundle, ProtectedLiveExecutionResult):
            raise LiveGatewayAuthorityError("live_gateway_bundle_invalid")
        resumed = self.resume_completed_execution(runner_request_digest)
        if resumed is None:
            replayed = self.replay_sealed_execution_bundle(runner_request_digest)
            if replayed != bundle:
                raise LiveGatewayAuthorityError("live_gateway_bundle_invalid")
            return replayed
        result, _ = resumed
        if bundle.model_result != result:
            raise LiveGatewayAuthorityError("live_gateway_bundle_conflict")
        try:
            sealed = self._state.seal_resumed_result_bundle(
                runner_request_digest,
                bundle=bundle.to_canonical_dict(),
            )
            recovered = ProtectedLiveExecutionResult.from_canonical_dict(sealed)
        except (LiveGatewayStateError, ValueError) as error:
            code = getattr(error, "code", "live_gateway_bundle_invalid")
            raise LiveGatewayAuthorityError(code) from error
        if recovered != bundle:
            raise LiveGatewayAuthorityError("live_gateway_bundle_conflict")
        return recovered

    def seal_execution_bundle(
        self,
        capability: BoundedModelGatewayCapability,
        *,
        runner_request_digest: str,
        bundle: ProtectedLiveExecutionResult,
    ) -> ProtectedLiveExecutionResult:
        if not isinstance(capability, BoundedModelGatewayCapability) or not isinstance(
            bundle, ProtectedLiveExecutionResult
        ):
            raise LiveGatewayAuthorityError("live_gateway_bundle_invalid")
        _digest(runner_request_digest, "live_gateway_bundle_invalid")
        completed = self.peek_completed_result(capability)
        if bundle.model_result != completed:
            raise LiveGatewayAuthorityError("live_gateway_bundle_conflict")
        token_digest = hashlib.sha256(capability.token.encode()).hexdigest()
        try:
            sealed = self._state.seal_result_bundle(
                token_digest,
                runner_request_digest=runner_request_digest,
                bundle=bundle.to_canonical_dict(),
            )
            result = ProtectedLiveExecutionResult.from_canonical_dict(sealed)
        except (LiveGatewayStateError, ValueError) as error:
            code = getattr(error, "code", "live_gateway_bundle_invalid")
            raise LiveGatewayAuthorityError(code) from error
        if result != bundle:
            raise LiveGatewayAuthorityError("live_gateway_bundle_conflict")
        return result

    def reconcile_provider_result(self, token: str, result: ProtectedOpenAIModelResult) -> None:
        """Reject result-only repair; recovery requires a protected durable receipt."""
        del token, result
        raise LiveGatewayAuthorityError("live_gateway_provider_receipt_required")

    def record_infrastructure_invalid(self, token: str, code: str) -> None:
        grant = self._grant(token)
        if not isinstance(code, str) or _ID_RE.fullmatch(code) is None:
            raise LiveGatewayAuthorityError("live_infrastructure_code_invalid")
        try:
            self._state.record_infrastructure_invalid(grant.token_digest, code)
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error

    def invalidate_execution(self, token: str, code: str) -> None:
        grant = self._grant(token)
        if not isinstance(code, str) or _ID_RE.fullmatch(code) is None:
            raise LiveGatewayAuthorityError("live_infrastructure_code_invalid")
        try:
            self._state.invalidate_execution(grant.token_digest, code)
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error
