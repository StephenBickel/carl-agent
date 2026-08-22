"""Strict credential-free contracts for non-GitHub coordinator effect families."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_coordinator import (
    CloudCoordinatorDecision,
    EffectFamily,
    effect_family_for_node,
)

REQUEST_DOMAIN = "carl.coordinator-node-effect.request.v1"
RESPONSE_DOMAIN = "carl.coordinator-node-effect.response.v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_EFFECT = re.compile(r"^cloud-effect-[0-9a-f]{64}$")
_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")
_ERROR = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class CoordinatorEffectContractError(ValueError):
    """Stable typed-effect contract failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise CoordinatorEffectContractError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CoordinatorEffectContractError(code) from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise CoordinatorEffectContractError(code)
    return parsed


@dataclass(frozen=True, slots=True)
class CoordinatorNodeEffectRequest:
    schema_version: int
    domain: str
    family: EffectFamily
    node_kind: str
    command_key: str
    effect_key: str
    request_digest: str
    occurred_at: str

    def __post_init__(self) -> None:
        code = "coordinator_node_effect_request_invalid"
        if (
            isinstance(self.schema_version, bool)
            or self.schema_version != 1
            or self.domain != REQUEST_DOMAIN
            or effect_family_for_node(self.node_kind) != self.family
            or self.family in {"github", "state", "supervisor"}
            or not isinstance(self.command_key, str)
            or _KEY.fullmatch(self.command_key) is None
            or not isinstance(self.effect_key, str)
            or _EFFECT.fullmatch(self.effect_key) is None
            or not isinstance(self.request_digest, str)
            or _DIGEST.fullmatch(self.request_digest) is None
        ):
            raise CoordinatorEffectContractError(code)
        _utc(self.occurred_at, code)

    @classmethod
    def from_decision(cls, decision: CloudCoordinatorDecision) -> CoordinatorNodeEffectRequest:
        if (
            not isinstance(decision, CloudCoordinatorDecision)
            or decision.action not in {"execute_effect", "reconcile_effect"}
            or decision.node is None
            or decision.command is None
            or decision.effect_key != decision.command.effect_key
        ):
            raise CoordinatorEffectContractError("coordinator_node_effect_request_invalid")
        return cls(
            schema_version=1,
            domain=REQUEST_DOMAIN,
            family=effect_family_for_node(decision.node),
            node_kind=decision.node,
            command_key=decision.command.command_key,
            effect_key=decision.command.effect_key,
            request_digest=decision.command.request_digest,
            occurred_at=decision.command.occurred_at,
        )

    @classmethod
    def from_canonical_dict(cls, value: object) -> CoordinatorNodeEffectRequest:
        code = "coordinator_node_effect_request_invalid"
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise CoordinatorEffectContractError(code)
        try:
            return cls(**value)
        except (KeyError, TypeError, ValueError) as error:
            raise CoordinatorEffectContractError(code) from error

    def to_canonical_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class CoordinatorNodeEffectResponse:
    schema_version: int
    domain: str
    status: Literal["completed", "rejected", "retry_scheduled", "uncertain"]
    request_digest: str
    observed_at: str
    result_digest: str | None
    retry_not_before: str | None
    error_code: str | None

    def __post_init__(self) -> None:
        code = "coordinator_node_effect_response_invalid"
        if (
            isinstance(self.schema_version, bool)
            or self.schema_version != 1
            or self.domain != RESPONSE_DOMAIN
            or self.status not in {"completed", "rejected", "retry_scheduled", "uncertain"}
            or not isinstance(self.request_digest, str)
            or _DIGEST.fullmatch(self.request_digest) is None
        ):
            raise CoordinatorEffectContractError(code)
        observed_at = _utc(self.observed_at, code)
        if self.status == "completed":
            valid = (
                isinstance(self.result_digest, str)
                and _DIGEST.fullmatch(self.result_digest) is not None
                and self.retry_not_before is None
                and self.error_code is None
            )
        elif self.status == "rejected":
            valid = (
                self.result_digest is None
                and self.retry_not_before is None
                and isinstance(self.error_code, str)
                and _ERROR.fullmatch(self.error_code) is not None
            )
        elif self.status == "retry_scheduled":
            valid = (
                self.result_digest is None
                and self.error_code is None
                and self.retry_not_before is not None
            )
            if valid:
                valid = _utc(self.retry_not_before, code) >= observed_at
        else:
            valid = (
                self.result_digest is None
                and self.retry_not_before is None
                and self.error_code is None
            )
        if not valid:
            raise CoordinatorEffectContractError(code)

    @classmethod
    def completed(
        cls,
        *,
        request: CoordinatorNodeEffectRequest,
        result_digest: str,
        observed_at: str,
    ) -> CoordinatorNodeEffectResponse:
        if not isinstance(request, CoordinatorNodeEffectRequest):
            raise CoordinatorEffectContractError("coordinator_node_effect_response_invalid")
        return cls(
            schema_version=1,
            domain=RESPONSE_DOMAIN,
            status="completed",
            request_digest=request.digest,
            observed_at=observed_at,
            result_digest=result_digest,
            retry_not_before=None,
            error_code=None,
        )

    @classmethod
    def from_canonical_dict(cls, value: object) -> CoordinatorNodeEffectResponse:
        code = "coordinator_node_effect_response_invalid"
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise CoordinatorEffectContractError(code)
        try:
            return cls(**value)
        except (KeyError, TypeError, ValueError) as error:
            raise CoordinatorEffectContractError(code) from error

    def to_canonical_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class PreparedCoordinatorEffect:
    family: EffectFamily
    request: CoordinatorNodeEffectRequest

    def __post_init__(self) -> None:
        if (
            not isinstance(self.request, CoordinatorNodeEffectRequest)
            or self.request.family != self.family
        ):
            raise CoordinatorEffectContractError("coordinator_prepared_effect_invalid")
