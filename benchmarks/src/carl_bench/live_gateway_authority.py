"""Protected one-use authority for bounded live model evaluation capabilities."""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from carl_bench.adapters.carl_acp import BoundedModelGatewayCapability
from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_capability import (
    LiveEvaluationIdentity,
    LivePairPolicy,
    LiveTaskIdentity,
)
from carl_bench.live_gateway_store import LiveGatewayStateError, SQLiteLiveGatewayStateStore
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


class _GatewayState(Protocol):
    def reserve_grant(self, **kwargs: object) -> None: ...

    def load_grant(self, token_digest: str, *, consume: bool = False) -> dict[str, Any]: ...

    def complete_result(self, token_digest: str, result: dict[str, Any]) -> None: ...

    def take_result(self, token_digest: str) -> tuple[dict[str, Any], dict[str, Any]]: ...

    def record_infrastructure_invalid(self, token_digest: str, code: str) -> None: ...

    def retry_codes(
        self, pair_request_digest: str, task_id: str, attempt: int
    ) -> dict[str, str]: ...


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
        if token in self.rows or issue in self.issues:
            raise LiveGatewayStateError("live_gateway_grant_conflict")
        self.issues.add(issue)
        self.rows[token] = {
            "grant": kwargs["grant"],
            "consumed": False,
            "result": None,
            "collected": False,
            "infrastructure_code": None,
        }

    def load_grant(self, token_digest: str, *, consume: bool = False) -> dict[str, Any]:
        row = self.rows.get(token_digest)
        if row is None:
            raise LiveGatewayStateError("live_gateway_capability_invalid")
        if consume:
            if row["consumed"]:
                raise LiveGatewayStateError("live_gateway_capability_consumed")
            row["consumed"] = True
        return row["grant"]

    def complete_result(self, token_digest: str, result: dict[str, Any]) -> None:
        row = self.rows[token_digest]
        row["result"] = result

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

    def record_infrastructure_invalid(self, token_digest: str, code: str) -> None:
        row = self.rows.get(token_digest)
        if row is None:
            raise LiveGatewayStateError("live_gateway_capability_invalid")
        if row["result"] is not None or row["infrastructure_code"] not in {None, code}:
            raise LiveGatewayStateError("live_infrastructure_result_conflict")
        row["consumed"] = True
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
            ):
                result[actual["subject"]] = row["infrastructure_code"]
        return result


class ProtectedModelGatewayServer:
    """Service-owned registry that turns opaque one-use tokens into fixed model calls."""

    __slots__ = (
        "_endpoint",
        "_gateway",
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
        return cls._construct(
            gateway=gateway,
            endpoint=_ENDPOINT,
            token_source=lambda: secrets.token_urlsafe(32),
            state=SQLiteLiveGatewayStateStore.from_protected_process(),
        )

    @classmethod
    def _for_testing(
        cls,
        *,
        gateway: _PinnedGateway,
        endpoint: str,
        token_source: Callable[[], str],
        state: _GatewayState | None = None,
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
        )

    @classmethod
    def _construct(
        cls,
        *,
        gateway: _PinnedGateway,
        endpoint: str,
        token_source: Callable[[], str],
        state: _GatewayState,
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
        return value

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
            subject=actual.subject,
            attempt=actual.attempt,
            process_id=actual.process_id,
            worker_uid=actual.worker_uid,
            worker_gid=actual.worker_gid,
            executable_digest=actual.executable_digest,
            checkout_digest=actual.checkout_digest,
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

    def _grant(self, token: object, *, consume: bool = False) -> _Grant:
        if not isinstance(token, str):
            raise LiveGatewayAuthorityError("live_gateway_capability_invalid")
        try:
            value = self._state.load_grant(
                hashlib.sha256(token.encode()).hexdigest(), consume=consume
            )
            return _grant_from_document(value)
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error

    def evaluate(self, token: str, input_text: str) -> ProtectedOpenAIModelResult:
        grant = self._grant(token, consume=True)
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
        try:
            self._state.complete_result(grant.token_digest, _result_document(result))
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error
        return result

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

    def record_infrastructure_invalid(self, token: str, code: str) -> None:
        grant = self._grant(token)
        if not isinstance(code, str) or _ID_RE.fullmatch(code) is None:
            raise LiveGatewayAuthorityError("live_infrastructure_code_invalid")
        try:
            self._state.record_infrastructure_invalid(grant.token_digest, code)
        except LiveGatewayStateError as error:
            raise LiveGatewayAuthorityError(error.code) from error
