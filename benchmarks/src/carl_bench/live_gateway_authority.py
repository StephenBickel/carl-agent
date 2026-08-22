"""Protected one-use authority for bounded live model evaluation capabilities."""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from carl_bench.adapters.carl_acp import BoundedModelGatewayCapability
from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_capability import (
    LiveEvaluationIdentity,
    LivePairPolicy,
    LiveTaskIdentity,
)
from carl_bench.openai_gateway import (
    OpenAIGatewayError,
    OpenAIModelGateway,
    OpenAIModelRequest,
    ProtectedOpenAIModelResult,
)

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_ENDPOINT = "http://127.0.0.1:43117/v1/evaluate"


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


@dataclass(frozen=True, slots=True)
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
        ):
            _digest(value, "live_execution_context_invalid")
        for value in (self.task_id, self.model, self.reasoning_policy):
            _identifier(value, "live_execution_context_invalid")


class _PinnedGateway(Protocol):
    def protected_execution_policy(self) -> dict[str, str]: ...

    def evaluate(self, request: OpenAIModelRequest) -> object: ...

    def verify_protected_result(self, result: object) -> bool: ...


@dataclass(slots=True)
class _Grant:
    identity: LiveEvaluationIdentity
    policy: LivePairPolicy
    task: LiveTaskIdentity
    actual: ActualLiveExecution
    token_digest: str
    consumed: bool = False


class ProtectedModelGatewayServer:
    """Service-owned registry that turns opaque one-use tokens into fixed model calls."""

    __slots__ = (
        "_collected",
        "_completed",
        "_endpoint",
        "_gateway",
        "_grants",
        "_issued",
        "_retryable",
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
        return cls._construct(
            gateway=gateway,
            endpoint=_ENDPOINT,
            token_source=lambda: secrets.token_urlsafe(32),
        )

    @classmethod
    def _for_testing(
        cls,
        *,
        gateway: _PinnedGateway,
        endpoint: str,
        token_source: Callable[[], str],
    ) -> ProtectedModelGatewayServer:
        if (
            not callable(getattr(gateway, "protected_execution_policy", None))
            or not callable(getattr(gateway, "evaluate", None))
            or not callable(getattr(gateway, "verify_protected_result", None))
            or not callable(token_source)
        ):
            raise LiveGatewayAuthorityError("live_gateway_test_configuration_invalid")
        return cls._construct(gateway=gateway, endpoint=endpoint, token_source=token_source)

    @classmethod
    def _construct(
        cls,
        *,
        gateway: _PinnedGateway,
        endpoint: str,
        token_source: Callable[[], str],
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
        value._grants: dict[str, _Grant] = {}
        value._completed: dict[str, ProtectedOpenAIModelResult] = {}
        value._collected: set[str] = set()
        value._issued: set[tuple[str, str, str, int]] = set()
        value._retryable: dict[tuple[str, str, int], dict[str, str]] = {}
        return value

    @staticmethod
    def _expected_actual(
        *,
        identity: LiveEvaluationIdentity,
        policy: LivePairPolicy,
        task: LiveTaskIdentity,
        subject: str,
        attempt: int,
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
        return ActualLiveExecution(
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
        )

    def issue_capability(
        self,
        *,
        identity: LiveEvaluationIdentity,
        policy: LivePairPolicy,
        task: LiveTaskIdentity,
        subject: str,
        attempt: int,
        actual: ActualLiveExecution,
    ) -> BoundedModelGatewayCapability:
        if (
            not isinstance(identity, LiveEvaluationIdentity)
            or not isinstance(policy, LivePairPolicy)
            or not isinstance(task, LiveTaskIdentity)
            or not isinstance(actual, ActualLiveExecution)
            or task.task_id not in identity.task_order
            or task.grader_digest != identity.grader_digest
            or identity.attempts > policy.maximum_pair_retries + 1
        ):
            raise LiveGatewayAuthorityError("live_execution_binding_mismatch")
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
            subject=subject,
            attempt=attempt,
        )
        if actual != expected:
            raise LiveGatewayAuthorityError("live_execution_binding_mismatch")
        issue_key = (identity.request_digest, subject, task.task_id, attempt)
        if issue_key in self._issued:
            raise LiveGatewayAuthorityError("live_gateway_capability_duplicate")
        if attempt > 1:
            prior = self._retryable.get((identity.request_digest, task.task_id, attempt - 1), {})
            if set(prior) != {"parent", "candidate"} or len(set(prior.values())) != 1:
                raise LiveGatewayAuthorityError("live_retry_not_authorized")
        token = self._token_source()
        try:
            capability = BoundedModelGatewayCapability(
                endpoint=self._endpoint,
                token=token,
                pair_request_digest=identity.request_digest,
                subject=subject,
                task_id=task.task_id,
                attempt=attempt,
            )
        except (TypeError, ValueError) as error:
            raise LiveGatewayAuthorityError("live_gateway_token_invalid") from error
        token_digest = hashlib.sha256(token.encode()).hexdigest()
        if token_digest in self._grants:
            raise LiveGatewayAuthorityError("live_gateway_token_duplicate")
        self._grants[token_digest] = _Grant(identity, policy, task, actual, token_digest)
        self._issued.add(issue_key)
        return capability

    def _grant(self, token: object) -> _Grant:
        if not isinstance(token, str):
            raise LiveGatewayAuthorityError("live_gateway_capability_invalid")
        grant = self._grants.get(hashlib.sha256(token.encode()).hexdigest())
        if grant is None:
            raise LiveGatewayAuthorityError("live_gateway_capability_invalid")
        if grant.consumed:
            raise LiveGatewayAuthorityError("live_gateway_capability_consumed")
        return grant

    def evaluate(self, token: str, input_text: str) -> ProtectedOpenAIModelResult:
        grant = self._grant(token)
        grant.consumed = True
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
        try:
            result = self._gateway.evaluate(request)
            verified = self._gateway.verify_protected_result(result)
        except OpenAIGatewayError as error:
            raise LiveGatewayAuthorityError(error.code) from error
        except Exception as error:
            raise LiveGatewayAuthorityError("live_gateway_unavailable") from error
        if type(result) is not ProtectedOpenAIModelResult or not verified:
            raise LiveGatewayAuthorityError("live_model_provenance_invalid")
        self._completed[grant.token_digest] = result
        return result

    def take_completed_result(
        self, capability: BoundedModelGatewayCapability
    ) -> ProtectedOpenAIModelResult:
        """Transfer one authenticated result to the protected evaluator exactly once."""
        if not isinstance(capability, BoundedModelGatewayCapability):
            raise LiveGatewayAuthorityError("live_gateway_capability_invalid")
        token_digest = hashlib.sha256(capability.token.encode()).hexdigest()
        grant = self._grants.get(token_digest)
        if (
            grant is None
            or capability.pair_request_digest != grant.identity.request_digest
            or capability.subject != grant.actual.subject
            or capability.task_id != grant.task.task_id
            or capability.attempt != grant.actual.attempt
        ):
            raise LiveGatewayAuthorityError("live_gateway_capability_invalid")
        if token_digest in self._collected:
            raise LiveGatewayAuthorityError("live_gateway_result_consumed")
        result = self._completed.get(token_digest)
        if result is None:
            raise LiveGatewayAuthorityError("live_gateway_result_unavailable")
        self._collected.add(token_digest)
        return result

    def record_infrastructure_invalid(self, token: str, code: str) -> None:
        grant = self._grant(token)
        if not isinstance(code, str) or _ID_RE.fullmatch(code) is None:
            raise LiveGatewayAuthorityError("live_infrastructure_code_invalid")
        grant.consumed = True
        key = (
            grant.identity.request_digest,
            grant.task.task_id,
            grant.actual.attempt,
        )
        subjects = self._retryable.setdefault(key, {})
        previous = subjects.get(grant.actual.subject)
        if previous is not None and previous != code:
            raise LiveGatewayAuthorityError("live_infrastructure_result_conflict")
        subjects[grant.actual.subject] = code
