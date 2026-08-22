"""Exact protected parent/candidate live capability evidence and combination."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from carl_bench.canonical import canonical_json_bytes
from carl_bench.evidence_archive import ArchivedEvidence
from carl_bench.openai_gateway import (
    OpenAIGatewayError,
    OpenAIModelGateway,
    OpenAIUsage,
    ProtectedOpenAIModelResult,
)
from carl_bench.run_attestation import attest_bound_payload, verify_bound_payload_attestation

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_PAIR_ATTESTATION_PURPOSE = "protected-live-pair"
_OPENAI_POLICY_REVISION = "openai-responses-policy-2026-08-20.1"
_TOOL_PROTOCOL_REVISION = "acp-v2/bounded-openai-v1"
_LIVE_GATE_REASON = "live_acp_credential_missing"


class LiveCapabilityError(ValueError):
    """Stable failure for invalid, mismatched, or untrusted live evidence."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise LiveCapabilityError(code)
    return value


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise LiveCapabilityError(code)
    return value


def _bounded_int(value: object, *, minimum: int, maximum: int, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise LiveCapabilityError(code)
    return value


def _utc(value: datetime, code: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo != UTC:
        raise LiveCapabilityError(code)
    return value


def _timestamp(value: datetime) -> str:
    return _utc(value, "live_evidence_time_invalid").isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class LiveEvaluationIdentity:
    repository: str
    parent_commit: str
    parent_tree: str
    candidate_commit: str
    candidate_tree: str
    experiment_digest: str
    workflow_revision: str
    workflow_digest: str
    task_set_digest: str
    metric_pack_digest: str
    policy_digest: str
    model_policy_digest: str
    grader_digest: str
    environment_digest: str
    model: str
    reasoning_policy: str
    tool_protocol_revision: str
    task_order: tuple[str, ...]
    seeds: tuple[int, ...]
    attempts: int
    request_digest: str = ""

    def __post_init__(self) -> None:
        if (
            not isinstance(self.repository, str)
            or _REPOSITORY_RE.fullmatch(self.repository) is None
        ):
            raise LiveCapabilityError("live_repository_invalid")
        for name in ("parent_commit", "parent_tree", "candidate_commit", "candidate_tree"):
            value = getattr(self, name)
            if not isinstance(value, str) or _OBJECT_RE.fullmatch(value) is None:
                raise LiveCapabilityError("live_subject_identity_invalid")
        if self.parent_commit == self.candidate_commit or self.parent_tree == self.candidate_tree:
            raise LiveCapabilityError("live_subject_isolation_invalid")
        for name in (
            "experiment_digest",
            "workflow_digest",
            "task_set_digest",
            "metric_pack_digest",
            "policy_digest",
            "model_policy_digest",
            "grader_digest",
            "environment_digest",
        ):
            _digest(getattr(self, name), "live_identity_invalid")
        if (
            not isinstance(self.workflow_revision, str)
            or _OBJECT_RE.fullmatch(self.workflow_revision) is None
        ):
            raise LiveCapabilityError("live_identity_invalid")
        for value in (self.model, self.reasoning_policy, self.tool_protocol_revision):
            _identifier(value, "live_policy_identity_invalid")
        if (
            not isinstance(self.task_order, tuple)
            or not self.task_order
            or len(set(self.task_order)) != len(self.task_order)
            or any(
                not isinstance(item, str) or _ID_RE.fullmatch(item) is None
                for item in self.task_order
            )
        ):
            raise LiveCapabilityError("live_task_order_invalid")
        if (
            not isinstance(self.seeds, tuple)
            or not self.seeds
            or len(set(self.seeds)) != len(self.seeds)
            or any(
                isinstance(seed, bool)
                or not isinstance(seed, int)
                or not 0 <= seed <= 2_147_483_647
                for seed in self.seeds
            )
        ):
            raise LiveCapabilityError("live_seed_population_invalid")
        if self.attempts != len(self.seeds) or not 1 <= self.attempts <= 3:
            raise LiveCapabilityError("live_attempt_population_invalid")
        expected = hashlib.sha256(
            canonical_json_bytes(self.to_canonical_dict(include_request_digest=False))
        ).hexdigest()
        if self.request_digest and self.request_digest != expected:
            raise LiveCapabilityError("live_request_digest_mismatch")
        object.__setattr__(self, "request_digest", expected)

    @classmethod
    def create(cls, **values: Any) -> LiveEvaluationIdentity:
        return cls(**values)

    def to_canonical_dict(self, *, include_request_digest: bool = True) -> dict[str, Any]:
        value = {
            "attempts": self.attempts,
            "candidate_commit": self.candidate_commit,
            "candidate_tree": self.candidate_tree,
            "environment_digest": self.environment_digest,
            "experiment_digest": self.experiment_digest,
            "grader_digest": self.grader_digest,
            "metric_pack_digest": self.metric_pack_digest,
            "model": self.model,
            "model_policy_digest": self.model_policy_digest,
            "parent_commit": self.parent_commit,
            "parent_tree": self.parent_tree,
            "policy_digest": self.policy_digest,
            "reasoning_policy": self.reasoning_policy,
            "repository": self.repository,
            "seeds": list(self.seeds),
            "task_order": list(self.task_order),
            "task_set_digest": self.task_set_digest,
            "tool_protocol_revision": self.tool_protocol_revision,
            "workflow_digest": self.workflow_digest,
            "workflow_revision": self.workflow_revision,
        }
        if include_request_digest:
            value["request_digest"] = self.request_digest
        return value

    def execution_context_digest(
        self,
        *,
        subject: str,
        task: LiveTaskIdentity,
        policy: LivePairPolicy,
        seed: int,
        attempt: int,
    ) -> str:
        gateway_subject = "baseline" if subject == "parent" else subject
        if gateway_subject not in {"baseline", "candidate"}:
            raise LiveCapabilityError("live_subject_invalid")
        if not isinstance(task, LiveTaskIdentity) or not isinstance(policy, LivePairPolicy):
            raise LiveCapabilityError("live_execution_binding_invalid")
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "attempt": attempt,
                    "domain": "carl.protected-live-execution-context.v1",
                    "evaluation_identity": self.to_canonical_dict(),
                    "live_policy": policy.to_canonical_dict(),
                    "schema_version": 1,
                    "seed": seed,
                    "subject": gateway_subject,
                    "subject_commit": (
                        self.parent_commit if subject == "parent" else self.candidate_commit
                    ),
                    "subject_tree": (
                        self.parent_tree if subject == "parent" else self.candidate_tree
                    ),
                    "task": task.to_canonical_dict(),
                }
            )
        ).hexdigest()

    def model_request_digest(
        self,
        *,
        subject: str,
        task: LiveTaskIdentity,
        policy: LivePairPolicy,
        seed: int,
        attempt: int,
    ) -> str:
        gateway_subject = "baseline" if subject == "parent" else subject
        if gateway_subject not in {"baseline", "candidate"}:
            raise LiveCapabilityError("live_subject_invalid")
        return hashlib.sha256(
            canonical_json_bytes(
                {
                    "attempt": attempt,
                    "domain": "carl.openai.responses.request.v1",
                    "execution_context_digest": self.execution_context_digest(
                        subject=subject,
                        task=task,
                        policy=policy,
                        seed=seed,
                        attempt=attempt,
                    ),
                    "experiment_id": self.experiment_digest,
                    "input_sha256": task.input_digest,
                    "input_size": task.input_size,
                    "policy_revision": _OPENAI_POLICY_REVISION,
                    "repository": self.repository,
                    "schema_version": 1,
                    "seed": seed,
                    "subject": gateway_subject,
                    "task_id": task.task_id,
                }
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class LiveTaskIdentity:
    task_id: str
    task_digest: str
    input_digest: str
    input_size: int
    grader_digest: str
    role: str

    def __post_init__(self) -> None:
        _identifier(self.task_id, "live_task_identity_invalid")
        for value in (self.task_digest, self.input_digest, self.grader_digest):
            _digest(value, "live_task_identity_invalid")
        _bounded_int(self.input_size, minimum=1, maximum=65_536, code="live_task_identity_invalid")
        if self.role not in {"affected", "guard", "held_out"}:
            raise LiveCapabilityError("live_task_role_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "grader_digest": self.grader_digest,
            "input_digest": self.input_digest,
            "input_size": self.input_size,
            "role": self.role,
            "task_digest": self.task_digest,
            "task_id": self.task_id,
        }


@dataclass(frozen=True, slots=True)
class LivePairPolicy:
    maximum_pair_retries: int
    maximum_total_cost_microdollars: int
    maximum_trial_latency_ms: int
    input_cost_microdollars_per_million_tokens: int
    cached_input_cost_microdollars_per_million_tokens: int
    output_cost_microdollars_per_million_tokens: int
    minimum_aggregate_gain_basis_points: int
    minimum_held_out_gain_basis_points: int
    require_affected_improvement: bool
    require_guard_non_regression: bool

    def __post_init__(self) -> None:
        _bounded_int(
            self.maximum_pair_retries,
            minimum=0,
            maximum=2,
            code="live_policy_invalid",
        )
        _bounded_int(
            self.maximum_total_cost_microdollars,
            minimum=0,
            maximum=100_000_000,
            code="live_policy_invalid",
        )
        _bounded_int(
            self.maximum_trial_latency_ms,
            minimum=1,
            maximum=3_600_000,
            code="live_policy_invalid",
        )
        for value in (
            self.input_cost_microdollars_per_million_tokens,
            self.cached_input_cost_microdollars_per_million_tokens,
            self.output_cost_microdollars_per_million_tokens,
        ):
            _bounded_int(
                value,
                minimum=0,
                maximum=1_000_000_000,
                code="live_policy_invalid",
            )
        for value in (
            self.minimum_aggregate_gain_basis_points,
            self.minimum_held_out_gain_basis_points,
        ):
            _bounded_int(value, minimum=0, maximum=10_000, code="live_policy_invalid")
        if (
            type(self.require_affected_improvement) is not bool
            or type(self.require_guard_non_regression) is not bool
        ):
            raise LiveCapabilityError("live_policy_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class LiveTrialEvidence:
    pair_request_digest: str
    subject: str
    subject_commit: str
    task: LiveTaskIdentity
    seed: int
    attempt: int
    attempt_identity: str
    status: str
    score_basis_points: int
    cost_microdollars: int
    latency_ms: int
    model_result: ProtectedOpenAIModelResult | object | None
    infrastructure_code: str | None = None

    def __post_init__(self) -> None:
        _digest(self.pair_request_digest, "live_trial_identity_invalid")
        if self.subject not in {"parent", "candidate"}:
            raise LiveCapabilityError("live_subject_invalid")
        if (
            not isinstance(self.subject_commit, str)
            or _OBJECT_RE.fullmatch(self.subject_commit) is None
        ):
            raise LiveCapabilityError("live_subject_identity_invalid")
        if not isinstance(self.task, LiveTaskIdentity):
            raise LiveCapabilityError("live_task_identity_invalid")
        _bounded_int(self.seed, minimum=0, maximum=2_147_483_647, code="live_trial_invalid")
        _bounded_int(self.attempt, minimum=1, maximum=3, code="live_trial_invalid")
        _digest(self.attempt_identity, "live_attempt_identity_invalid")
        _bounded_int(self.score_basis_points, minimum=0, maximum=10_000, code="live_trial_invalid")
        _bounded_int(
            self.cost_microdollars,
            minimum=0,
            maximum=100_000_000,
            code="live_trial_invalid",
        )
        _bounded_int(self.latency_ms, minimum=0, maximum=3_600_000, code="live_trial_invalid")
        if self.status == "valid":
            if self.infrastructure_code is not None or self.model_result is None:
                raise LiveCapabilityError("live_trial_invalid")
        elif self.status == "infrastructure_invalid":
            if (
                not isinstance(self.infrastructure_code, str)
                or _ID_RE.fullmatch(self.infrastructure_code) is None
                or self.model_result is not None
                or self.score_basis_points != 0
                or self.cost_microdollars != 0
                or self.latency_ms != 0
            ):
                raise LiveCapabilityError("live_trial_invalid")
        else:
            raise LiveCapabilityError("live_trial_status_invalid")

    def to_canonical_dict(self) -> dict[str, Any]:
        result: dict[str, Any] | None = None
        if self.model_result is not None:
            value = self.model_result
            usage = getattr(value, "usage", None)
            result = {
                "latency_ms": getattr(value, "latency_ms", None),
                "model": getattr(value, "model", None),
                "output_digest": getattr(value, "output_digest", None),
                "provenance_tag": getattr(value, "provenance_tag", None),
                "request_digest": getattr(value, "request_digest", None),
                "status": getattr(value, "status", None),
                "usage": (
                    {name: getattr(usage, name) for name in usage.__dataclass_fields__}
                    if usage is not None and hasattr(usage, "__dataclass_fields__")
                    else None
                ),
            }
        return {
            "attempt": self.attempt,
            "attempt_identity": self.attempt_identity,
            "cost_microdollars": self.cost_microdollars,
            "infrastructure_code": self.infrastructure_code,
            "latency_ms": self.latency_ms,
            "model_result": result,
            "pair_request_digest": self.pair_request_digest,
            "score_basis_points": self.score_basis_points,
            "seed": self.seed,
            "status": self.status,
            "subject": self.subject,
            "subject_commit": self.subject_commit,
            "task": self.task.to_canonical_dict(),
        }


def _expected_population(
    identity: LiveEvaluationIdentity, tasks: tuple[LiveTaskIdentity, ...]
) -> tuple[tuple[str, int, int], ...]:
    return tuple(
        (task.task_id, attempt, seed)
        for task in tasks
        for attempt, seed in enumerate(identity.seeds, start=1)
    )


def _task_scores(
    trials: tuple[LiveTrialEvidence, ...], tasks: tuple[LiveTaskIdentity, ...]
) -> dict[str, int]:
    return {
        task.task_id: sum(
            item.score_basis_points for item in trials if item.task.task_id == task.task_id
        )
        // len(tuple(item for item in trials if item.task.task_id == task.task_id))
        for task in tasks
    }


def _authenticated_cost_microdollars(
    result: ProtectedOpenAIModelResult,
    policy: LivePairPolicy,
) -> int:
    usage = result.usage
    if not isinstance(usage, OpenAIUsage):
        raise LiveCapabilityError("live_resource_accounting_invalid")
    values = (
        usage.input_tokens,
        usage.cached_input_tokens,
        usage.output_tokens,
        usage.reasoning_output_tokens,
        usage.total_tokens,
    )
    if (
        any(
            isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1_000_000
            for value in values
        )
        or usage.cached_input_tokens > usage.input_tokens
        or usage.reasoning_output_tokens > usage.output_tokens
        or usage.total_tokens != usage.input_tokens + usage.output_tokens
    ):
        raise LiveCapabilityError("live_resource_accounting_invalid")
    uncached_input_tokens = usage.input_tokens - usage.cached_input_tokens
    numerator = (
        uncached_input_tokens * policy.input_cost_microdollars_per_million_tokens
        + usage.cached_input_tokens * policy.cached_input_cost_microdollars_per_million_tokens
        + usage.output_tokens * policy.output_cost_microdollars_per_million_tokens
    )
    return (numerator + 999_999) // 1_000_000


@dataclass(frozen=True, slots=True)
class ProtectedLivePair:
    identity: LiveEvaluationIdentity
    policy: LivePairPolicy
    tasks: tuple[LiveTaskIdentity, ...]
    parent_trials: tuple[LiveTrialEvidence, ...]
    candidate_trials: tuple[LiveTrialEvidence, ...]
    eligible: bool
    inconclusive: bool
    reasons: tuple[str, ...]
    task_deltas: tuple[tuple[str, int], ...]
    aggregate_gain_basis_points: int
    held_out_gain_basis_points: int
    total_cost_microdollars: int

    @classmethod
    def create(
        cls,
        *,
        identity: LiveEvaluationIdentity,
        policy: LivePairPolicy,
        tasks: tuple[LiveTaskIdentity, ...],
        parent_trials: tuple[LiveTrialEvidence, ...],
        candidate_trials: tuple[LiveTrialEvidence, ...],
        gateway: OpenAIModelGateway,
    ) -> ProtectedLivePair:
        if not isinstance(identity, LiveEvaluationIdentity) or not isinstance(
            policy, LivePairPolicy
        ):
            raise LiveCapabilityError("live_pair_invalid")
        if (
            not isinstance(tasks, tuple)
            or any(not isinstance(task, LiveTaskIdentity) for task in tasks)
            or tuple(task.task_id for task in tasks) != identity.task_order
            or any(task.grader_digest != identity.grader_digest for task in tasks)
            or {task.role for task in tasks} != {"affected", "guard", "held_out"}
        ):
            raise LiveCapabilityError("live_task_identity_mismatch")
        if identity.attempts > policy.maximum_pair_retries + 1:
            raise LiveCapabilityError("live_retry_policy_invalid")
        try:
            protected_policy = gateway.protected_execution_policy()
        except OpenAIGatewayError as error:
            raise LiveCapabilityError("live_execution_binding_mismatch") from error
        protected_policy_digest = hashlib.sha256(canonical_json_bytes(protected_policy)).hexdigest()
        if (
            identity.model != protected_policy["model"]
            or identity.reasoning_policy != protected_policy["reasoning_policy"]
            or identity.model_policy_digest != protected_policy_digest
            or identity.tool_protocol_revision != _TOOL_PROTOCOL_REVISION
        ):
            raise LiveCapabilityError("live_execution_binding_mismatch")
        expected = _expected_population(identity, tasks)
        for subject, values, commit in (
            ("parent", parent_trials, identity.parent_commit),
            ("candidate", candidate_trials, identity.candidate_commit),
        ):
            if (
                not isinstance(values, tuple)
                or tuple(
                    (item.task.task_id, item.attempt, item.seed)
                    for item in values
                    if isinstance(item, LiveTrialEvidence)
                )
                != expected
            ):
                raise LiveCapabilityError("live_trial_population_mismatch")
            if any(
                not isinstance(item, LiveTrialEvidence)
                or item.subject != subject
                or item.subject_commit != commit
                or item.pair_request_digest != identity.request_digest
                or item.task != tasks[index // identity.attempts]
                for index, item in enumerate(values)
            ):
                raise LiveCapabilityError("live_trial_identity_mismatch")
            for item in values:
                if item.status != "valid":
                    continue
                expected_request = identity.model_request_digest(
                    subject=subject,
                    task=item.task,
                    policy=policy,
                    seed=item.seed,
                    attempt=item.attempt,
                )
                if type(item.model_result) is not ProtectedOpenAIModelResult:
                    raise LiveCapabilityError("live_model_provenance_invalid")
                if item.model_result.request_digest != expected_request:
                    raise LiveCapabilityError("live_execution_binding_mismatch")
                try:
                    verified = gateway.verify_protected_result(item.model_result)
                except OpenAIGatewayError:
                    verified = False
                if not verified:
                    raise LiveCapabilityError("live_model_provenance_invalid")
                expected_cost = _authenticated_cost_microdollars(item.model_result, policy)
                if (
                    item.latency_ms != item.model_result.latency_ms
                    or item.cost_microdollars != expected_cost
                ):
                    raise LiveCapabilityError("live_resource_accounting_mismatch")
        for parent, candidate in zip(parent_trials, candidate_trials, strict=True):
            if parent.attempt_identity != candidate.attempt_identity:
                raise LiveCapabilityError("live_attempt_identity_mismatch")
            if (parent.status == "infrastructure_invalid") != (
                candidate.status == "infrastructure_invalid"
            ) or parent.infrastructure_code != candidate.infrastructure_code:
                raise LiveCapabilityError("live_pair_retry_mismatch")

        invalid = any(item.status == "infrastructure_invalid" for item in parent_trials)
        before = _task_scores(parent_trials, tasks)
        after = _task_scores(candidate_trials, tasks)
        task_deltas = tuple(
            (task.task_id, after[task.task_id] - before[task.task_id]) for task in tasks
        )
        aggregate_gain = sum(delta for _, delta in task_deltas) // len(task_deltas)
        held = tuple(
            delta
            for task_id, delta in task_deltas
            if next(task.role for task in tasks if task.task_id == task_id) == "held_out"
        )
        held_gain = sum(held) // len(held)
        valid_trials = tuple(
            item for item in (*parent_trials, *candidate_trials) if item.status == "valid"
        )
        total_cost = sum(
            _authenticated_cost_microdollars(item.model_result, policy)
            for item in valid_trials
            if isinstance(item.model_result, ProtectedOpenAIModelResult)
        )
        reasons: set[str] = set()
        if invalid:
            reasons.add("pair_infrastructure_invalid")
        if any(
            item.model_result.latency_ms > policy.maximum_trial_latency_ms
            for item in valid_trials
            if isinstance(item.model_result, ProtectedOpenAIModelResult)
        ):
            reasons.add("live_latency_limit_exceeded")
        if total_cost > policy.maximum_total_cost_microdollars:
            reasons.add("live_cost_limit_exceeded")
        if aggregate_gain < policy.minimum_aggregate_gain_basis_points:
            reasons.add("minimum_aggregate_gain_not_met")
        if held_gain < policy.minimum_held_out_gain_basis_points:
            reasons.add("held_out_transfer_not_met")
        by_role = {
            role: tuple(
                delta
                for task_id, delta in task_deltas
                if next(task.role for task in tasks if task.task_id == task_id) == role
            )
            for role in ("affected", "guard")
        }
        if policy.require_affected_improvement and any(delta <= 0 for delta in by_role["affected"]):
            reasons.add("affected_task_not_improved")
        if policy.require_guard_non_regression and any(delta < 0 for delta in by_role["guard"]):
            reasons.add("guard_task_regression")
        stable_reasons = tuple(sorted(reasons))
        return cls(
            identity=identity,
            policy=policy,
            tasks=tasks,
            parent_trials=parent_trials,
            candidate_trials=candidate_trials,
            eligible=not stable_reasons,
            inconclusive=invalid,
            reasons=stable_reasons,
            task_deltas=task_deltas,
            aggregate_gain_basis_points=aggregate_gain,
            held_out_gain_basis_points=held_gain,
            total_cost_microdollars=total_cost,
        )

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "aggregate_gain_basis_points": self.aggregate_gain_basis_points,
            "candidate_trials": [item.to_canonical_dict() for item in self.candidate_trials],
            "eligible": self.eligible,
            "held_out_gain_basis_points": self.held_out_gain_basis_points,
            "identity": self.identity.to_canonical_dict(),
            "inconclusive": self.inconclusive,
            "policy": self.policy.to_canonical_dict(),
            "reasons": list(self.reasons),
            "schema_version": 1,
            "parent_trials": [item.to_canonical_dict() for item in self.parent_trials],
            "task_deltas": [
                {"delta_basis_points": delta, "task_id": task_id}
                for task_id, delta in self.task_deltas
            ],
            "tasks": [item.to_canonical_dict() for item in self.tasks],
            "total_cost_microdollars": self.total_cost_microdollars,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class AttestedLivePair:
    payload: ProtectedLivePair
    key_id: str
    signature: str
    archive: ArchivedEvidence | None
    issued_at: str
    expires_at: str

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "archive": self.archive.to_canonical_dict() if self.archive is not None else None,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "key_id": self.key_id,
            "payload": {"digest": self.payload.digest, **self.payload.to_canonical_dict()},
            "schema_version": 1,
            "signature": self.signature,
        }


def _attestation_payload(
    pair: ProtectedLivePair,
    *,
    archive: ArchivedEvidence,
    issued_at: str,
    expires_at: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "archive_record_digest": archive.digest,
            "archived_payload_digest": archive.payload_digest,
            "expires_at": expires_at,
            "issued_at": issued_at,
            "payload_digest": pair.digest,
            "request_digest": pair.identity.request_digest,
            "schema_version": 1,
        }
    )


def _verify_pair_model_results(pair: ProtectedLivePair, gateway: OpenAIModelGateway) -> None:
    for trial in (*pair.parent_trials, *pair.candidate_trials):
        if trial.status == "valid":
            try:
                verified = gateway.verify_protected_result(trial.model_result)
            except OpenAIGatewayError:
                verified = False
            if not verified:
                raise LiveCapabilityError("live_model_provenance_invalid")


def attest_live_pair(
    pair: ProtectedLivePair,
    *,
    gateway: OpenAIModelGateway,
    key: bytes,
    archive: ArchivedEvidence,
    issued_at: datetime,
    expires_at: datetime,
) -> AttestedLivePair:
    if not isinstance(pair, ProtectedLivePair):
        raise LiveCapabilityError("live_evidence_invalid")
    _verify_pair_model_results(pair, gateway)
    if _utc(expires_at, "live_evidence_time_invalid") <= _utc(
        issued_at, "live_evidence_time_invalid"
    ):
        raise LiveCapabilityError("live_evidence_time_invalid")
    _verify_archive(pair, archive, issued_at=issued_at, expires_at=expires_at)
    issued = _timestamp(issued_at)
    expires = _timestamp(expires_at)
    payload = _attestation_payload(
        pair,
        archive=archive,
        issued_at=issued,
        expires_at=expires,
    )
    try:
        key_id, signature = attest_bound_payload(
            payload, purpose=_PAIR_ATTESTATION_PURPOSE, key=key
        )
    except ValueError as error:
        raise LiveCapabilityError("live_evidence_signature_invalid") from error
    return AttestedLivePair(
        payload=pair,
        key_id=key_id,
        signature=signature,
        archive=archive,
        issued_at=issued,
        expires_at=expires,
    )


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise LiveCapabilityError("live_evidence_time_invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise LiveCapabilityError("live_evidence_time_invalid") from error
    if parsed.tzinfo != UTC or _timestamp(parsed) != value:
        raise LiveCapabilityError("live_evidence_time_invalid")
    return parsed


def _verify_archive(
    pair: ProtectedLivePair,
    archive: object,
    *,
    issued_at: datetime,
    expires_at: datetime,
) -> ArchivedEvidence:
    if not isinstance(archive, ArchivedEvidence):
        raise LiveCapabilityError("live_evidence_unarchived")
    expected_key = f"carl-evidence/v1/sha256/{pair.digest[:2]}/{pair.digest}"
    expected_size = len(canonical_json_bytes(pair.to_canonical_dict()))
    identity = archive.identity
    if (
        identity.repository != pair.identity.repository
        or identity.request_digest != pair.identity.request_digest
        or archive.object_key != expected_key
        or archive.payload_digest != pair.digest
        or archive.provider_checksum_sha256 != pair.digest
        or archive.byte_length != expected_size
        or archive.retention_mode != "COMPLIANCE"
        or _parse_time(archive.archived_at) > issued_at
        or _parse_time(archive.retain_until) < expires_at
    ):
        raise LiveCapabilityError("live_evidence_archive_mismatch")
    return archive


def verify_live_pair(
    envelope: AttestedLivePair,
    *,
    key: bytes,
    gateway: OpenAIModelGateway,
    now: datetime,
) -> ProtectedLivePair:
    if not isinstance(envelope, AttestedLivePair):
        raise LiveCapabilityError("live_evidence_unsigned")
    pair = envelope.payload
    if not isinstance(pair, ProtectedLivePair):
        raise LiveCapabilityError("live_evidence_invalid")
    current = _utc(now, "live_evidence_time_invalid")
    issued = _parse_time(envelope.issued_at)
    expires = _parse_time(envelope.expires_at)
    if current < issued or current >= expires:
        raise LiveCapabilityError("live_evidence_expired")
    archive = _verify_archive(pair, envelope.archive, issued_at=issued, expires_at=expires)
    if _parse_time(archive.retain_until) <= current:
        raise LiveCapabilityError("live_evidence_expired")
    payload = _attestation_payload(
        pair,
        archive=archive,
        issued_at=envelope.issued_at,
        expires_at=envelope.expires_at,
    )
    if not verify_bound_payload_attestation(
        payload,
        purpose=_PAIR_ATTESTATION_PURPOSE,
        key=key,
        expected_key_id=envelope.key_id,
        signature=envelope.signature,
    ):
        raise LiveCapabilityError("live_evidence_signature_invalid")
    _verify_pair_model_results(pair, gateway)
    rebuilt = ProtectedLivePair.create(
        identity=pair.identity,
        policy=pair.policy,
        tasks=pair.tasks,
        parent_trials=pair.parent_trials,
        candidate_trials=pair.candidate_trials,
        gateway=gateway,
    )
    if rebuilt != pair:
        raise LiveCapabilityError("live_evidence_mutated")
    return pair


@dataclass(frozen=True, slots=True)
class CombinedCapabilityEvidence:
    identity: LiveEvaluationIdentity
    eligible: bool
    disposition: str
    reasons: tuple[str, ...]
    live_pair_digest: str | None
    task_deltas: tuple[tuple[str, int], ...] = ()

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition,
            "eligible": self.eligible,
            "identity": self.identity.to_canonical_dict(),
            "kind": "combined_deterministic_live_capability",
            "live_pair_digest": self.live_pair_digest,
            "reasons": list(self.reasons),
            "schema_version": 1,
            "task_deltas": [
                {"delta_basis_points": delta, "task_id": task_id}
                for task_id, delta in self.task_deltas
            ],
        }


@dataclass(frozen=True, slots=True, init=False)
class DeterministicPairEvidence:
    identity: LiveEvaluationIdentity
    contract_eligible: bool
    contract_reasons: tuple[str, ...]
    evidence_digest: str
    _source_result: object
    _source_payload: bytes

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise LiveCapabilityError("deterministic_evidence_invalid")

    @staticmethod
    def _derive(result: object) -> tuple[LiveEvaluationIdentity, bool, tuple[str, ...], bytes]:
        from carl_bench.cloud_harness import (
            CloudHarnessResult,
            SubjectResult,
            _is_executed_cloud_harness_result,
        )

        if (
            not _is_executed_cloud_harness_result(result)
            or not isinstance(result, CloudHarnessResult)
            or not isinstance(result.live_evaluation_identity, LiveEvaluationIdentity)
        ):
            raise LiveCapabilityError("deterministic_evidence_unprotected")
        identity = result.live_evaluation_identity
        reasons = tuple(sorted(result.contract_reasons))
        if (
            not isinstance(result.parent, SubjectResult)
            or not isinstance(result.candidate, SubjectResult)
            or not result.parent.observations
            or not result.candidate.observations
            or tuple(item.probe_id for item in result.parent.observations) != identity.task_order
            or tuple(item.probe_id for item in result.candidate.observations) != identity.task_order
            or result.mode != "improvement"
            or result.parent.commit != identity.parent_commit
            or result.candidate.commit != identity.candidate_commit
            or result.gain_basis_points
            != result.candidate.score_basis_points - result.parent.score_basis_points
            or result.immutable_inputs
            != {
                "experiment": identity.experiment_digest,
                "metric_pack": identity.metric_pack_digest,
                "policy": identity.policy_digest,
                "task_set": identity.task_set_digest,
            }
            or type(result.contract_eligible) is not bool
            or not isinstance(result.contract_reasons, tuple)
            or any(
                not isinstance(reason, str) or _ID_RE.fullmatch(reason) is None
                for reason in result.contract_reasons
            )
            or tuple(sorted(set(result.contract_reasons))) != reasons
            or result.contract_eligible == bool(reasons)
            or result.contract_disposition
            != ("improvement" if result.contract_eligible else "rejected")
            or result.eligible is not False
            or result.disposition != "insufficient_evidence"
            or result.reasons != (_LIVE_GATE_REASON,)
        ):
            raise LiveCapabilityError("deterministic_evidence_invalid")
        try:
            payload = canonical_json_bytes(result.to_canonical_dict())
        except (TypeError, ValueError) as error:
            raise LiveCapabilityError("deterministic_evidence_invalid") from error
        if not payload or len(payload) > 1_048_576:
            raise LiveCapabilityError("deterministic_evidence_invalid")
        return identity, result.contract_eligible, reasons, payload

    @classmethod
    def from_cloud_harness(cls, result: object) -> DeterministicPairEvidence:
        identity, eligible, reasons, payload = cls._derive(result)
        value = object.__new__(cls)
        object.__setattr__(value, "identity", identity)
        object.__setattr__(value, "contract_eligible", eligible)
        object.__setattr__(value, "contract_reasons", reasons)
        object.__setattr__(value, "evidence_digest", hashlib.sha256(payload).hexdigest())
        object.__setattr__(value, "_source_result", result)
        object.__setattr__(value, "_source_payload", payload)
        return value

    @classmethod
    def _for_testing(
        cls,
        *,
        identity: LiveEvaluationIdentity,
        contract_eligible: bool,
        contract_reasons: tuple[str, ...],
    ) -> DeterministicPairEvidence:
        """Mint explicitly synthetic evidence for unit tests; it is never production eligible."""
        if (
            not isinstance(identity, LiveEvaluationIdentity)
            or type(contract_eligible) is not bool
            or not isinstance(contract_reasons, tuple)
            or contract_eligible == bool(contract_reasons)
        ):
            raise LiveCapabilityError("deterministic_evidence_invalid")
        payload = canonical_json_bytes(
            {
                "contract_eligible": contract_eligible,
                "contract_reasons": list(contract_reasons),
                "identity": identity.to_canonical_dict(),
                "kind": "synthetic_deterministic_pair_evidence",
                "schema_version": 1,
            }
        )
        value = object.__new__(cls)
        object.__setattr__(value, "identity", identity)
        object.__setattr__(value, "contract_eligible", contract_eligible)
        object.__setattr__(value, "contract_reasons", contract_reasons)
        object.__setattr__(value, "evidence_digest", hashlib.sha256(payload).hexdigest())
        object.__setattr__(value, "_source_result", None)
        object.__setattr__(value, "_source_payload", payload)
        return value

    def verify_source(self) -> None:
        if self._source_result is None:
            payload = canonical_json_bytes(
                {
                    "contract_eligible": self.contract_eligible,
                    "contract_reasons": list(self.contract_reasons),
                    "identity": self.identity.to_canonical_dict(),
                    "kind": "synthetic_deterministic_pair_evidence",
                    "schema_version": 1,
                }
            )
            if (
                payload != self._source_payload
                or hashlib.sha256(payload).hexdigest() != self.evidence_digest
            ):
                raise LiveCapabilityError("deterministic_evidence_invalid")
            return
        identity, eligible, reasons, payload = self._derive(self._source_result)
        if (
            payload != self._source_payload
            or identity != self.identity
            or eligible is not self.contract_eligible
            or reasons != self.contract_reasons
            or hashlib.sha256(payload).hexdigest() != self.evidence_digest
        ):
            raise LiveCapabilityError("deterministic_evidence_invalid")


def combine_paired_evidence(
    *,
    deterministic_evidence: DeterministicPairEvidence,
    live_evidence: AttestedLivePair | None,
    key: bytes,
    gateway: OpenAIModelGateway | None = None,
    now: datetime,
) -> CombinedCapabilityEvidence:
    if not isinstance(deterministic_evidence, DeterministicPairEvidence):
        raise LiveCapabilityError("deterministic_evidence_invalid")
    deterministic_evidence.verify_source()
    identity = deterministic_evidence.identity
    if gateway is None:
        try:
            gateway = OpenAIModelGateway.from_protected_environment()
        except OpenAIGatewayError as error:
            if (
                error.code
                in {
                    "openai_credentials_missing",
                    "openai_provenance_key_missing",
                }
                and live_evidence is None
            ):
                return CombinedCapabilityEvidence(
                    identity=identity,
                    eligible=False,
                    disposition="insufficient_evidence",
                    reasons=(_LIVE_GATE_REASON,),
                    live_pair_digest=None,
                )
            raise LiveCapabilityError("live_gateway_unavailable") from error
    if live_evidence is None:
        return CombinedCapabilityEvidence(
            identity=identity,
            eligible=False,
            disposition="insufficient_evidence",
            reasons=(_LIVE_GATE_REASON,),
            live_pair_digest=None,
        )
    pair = verify_live_pair(live_evidence, key=key, gateway=gateway, now=now)
    if pair.identity != identity:
        raise LiveCapabilityError("deterministic_live_identity_mismatch")
    return CombinedCapabilityEvidence(
        identity=identity,
        eligible=False,
        disposition="insufficient_evidence",
        reasons=("synthetic_evidence_ineligible",),
        live_pair_digest=pair.digest,
        task_deltas=pair.task_deltas,
    )
