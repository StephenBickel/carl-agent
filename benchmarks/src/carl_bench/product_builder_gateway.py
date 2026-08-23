"""Authenticated pricing and protected model accounting for product-builder attempts."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from carl_bench.canonical import canonical_json_bytes
from carl_bench.openai_gateway import (
    OpenAIModelGateway,
    OpenAIModelRequest,
    OpenAIModelResult,
    OpenAIUsage,
)
from carl_bench.product_builder import BuilderError

_PROTECTED_PRICING_POLICY = Path("/etc/carl/product-builder-pricing.json")
_HEX = frozenset("0123456789abcdef")


def _digest(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or not set(value) <= _HEX:
        raise BuilderError("builder_gateway_cost_receipt_invalid")
    return value


@dataclass(frozen=True, slots=True)
class BuilderPricingPolicy:
    schema_version: int
    model: str
    policy_revision: str
    input_cost_microdollars_per_million_tokens: int
    cached_input_cost_microdollars_per_million_tokens: int
    output_cost_microdollars_per_million_tokens: int

    def __post_init__(self) -> None:
        rates = (
            self.input_cost_microdollars_per_million_tokens,
            self.cached_input_cost_microdollars_per_million_tokens,
            self.output_cost_microdollars_per_million_tokens,
        )
        if (
            self.schema_version != 1
            or not isinstance(self.model, str)
            or not self.model
            or not isinstance(self.policy_revision, str)
            or not self.policy_revision
            or any(type(value) is not int or not 0 <= value <= 1_000_000_000 for value in rates)
        ):
            raise BuilderError("builder_gateway_pricing_policy_invalid")

    def to_canonical_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()

    @classmethod
    def from_canonical_dict(cls, value: object) -> BuilderPricingPolicy:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise BuilderError("builder_gateway_pricing_policy_invalid")
        try:
            return cls(**value)
        except TypeError as error:
            raise BuilderError("builder_gateway_pricing_policy_invalid") from error

    def cost(self, usage: OpenAIUsage) -> int:
        if not isinstance(usage, OpenAIUsage):
            raise BuilderError("builder_gateway_usage_invalid")
        uncached = usage.input_tokens - usage.cached_input_tokens
        if uncached < 0 or usage.total_tokens != usage.input_tokens + usage.output_tokens:
            raise BuilderError("builder_gateway_usage_invalid")
        numerator = (
            uncached * self.input_cost_microdollars_per_million_tokens
            + usage.cached_input_tokens * self.cached_input_cost_microdollars_per_million_tokens
            + usage.output_tokens * self.output_cost_microdollars_per_million_tokens
        )
        return (numerator + 999_999) // 1_000_000


@dataclass(frozen=True, slots=True)
class ProtectedGatewayCostReceipt:
    schema_version: int
    model_request_digest: str
    model_output_digest: str
    usage_digest: str
    pricing_policy_digest: str
    cost_microdollars: int
    authentication_tag: str

    def __post_init__(self) -> None:
        if (
            self.schema_version != 1
            or type(self.cost_microdollars) is not int
            or self.cost_microdollars < 0
        ):
            raise BuilderError("builder_gateway_cost_receipt_invalid")
        for value in (
            self.model_request_digest,
            self.model_output_digest,
            self.usage_digest,
            self.pricing_policy_digest,
            self.authentication_tag,
        ):
            _digest(value)

    def unsigned_canonical_dict(self) -> dict[str, object]:
        return {
            "cost_microdollars": self.cost_microdollars,
            "model_output_digest": self.model_output_digest,
            "model_request_digest": self.model_request_digest,
            "pricing_policy_digest": self.pricing_policy_digest,
            "schema_version": self.schema_version,
            "usage_digest": self.usage_digest,
        }

    def to_canonical_dict(self) -> dict[str, object]:
        return {**self.unsigned_canonical_dict(), "authentication_tag": self.authentication_tag}

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()

    @classmethod
    def sign(
        cls,
        *,
        request: OpenAIModelRequest,
        result: OpenAIModelResult,
        policy: BuilderPricingPolicy,
        key: bytes,
    ) -> ProtectedGatewayCostReceipt:
        if (
            type(request) is not OpenAIModelRequest
            or not isinstance(result, OpenAIModelResult)
            or result.request_digest != request.request_digest
            or result.model != policy.model
            or not isinstance(key, bytes)
            or len(key) != 32
        ):
            raise BuilderError("builder_gateway_cost_receipt_invalid")
        usage = {name: getattr(result.usage, name) for name in result.usage.__dataclass_fields__}
        unsigned = {
            "cost_microdollars": policy.cost(result.usage),
            "model_output_digest": result.output_digest,
            "model_request_digest": request.request_digest,
            "pricing_policy_digest": policy.digest,
            "schema_version": 1,
            "usage_digest": hashlib.sha256(canonical_json_bytes(usage)).hexdigest(),
        }
        tag = hmac.new(key, canonical_json_bytes(unsigned), hashlib.sha256).hexdigest()
        return cls(**unsigned, authentication_tag=tag)

    def verify(self, key: bytes) -> ProtectedGatewayCostReceipt:
        if not isinstance(key, bytes) or len(key) != 32:
            raise BuilderError("builder_gateway_cost_receipt_invalid")
        expected = hmac.new(
            key, canonical_json_bytes(self.unsigned_canonical_dict()), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, self.authentication_tag):
            raise BuilderError("builder_gateway_cost_receipt_signature_invalid")
        return self


class ProtectedOpenAIGateway:
    """Require durable preregistration and issue a signed, policy-priced cost receipt."""

    __slots__ = ("_receipts", "_store")

    def __init__(self, store: object) -> None:
        self._store = store
        self._receipts: dict[str, ProtectedGatewayCostReceipt] = {}

    def _policy(self) -> BuilderPricingPolicy:
        path = (
            self._store.root / "pricing-policy.json"
            if self._store.testing
            else _PROTECTED_PRICING_POLICY
        )
        try:
            payload = path.read_bytes()
            value: Any = __import__("json").loads(payload)
        except (OSError, UnicodeError, ValueError) as error:
            raise BuilderError("builder_gateway_pricing_policy_invalid") from error
        if canonical_json_bytes(value) != payload:
            raise BuilderError("builder_gateway_pricing_policy_invalid")
        return BuilderPricingPolicy.from_canonical_dict(value)

    def evaluate(self, request: OpenAIModelRequest) -> OpenAIModelResult:
        if not self._store.has_registration(request.execution_context_digest):
            raise BuilderError("builder_preregistration_not_durable")
        if self._store.testing:
            try:
                payload = (self._store.root / "test-model-result.json").read_bytes()
                value = __import__("json").loads(payload)
            except (OSError, UnicodeError, ValueError) as error:
                raise BuilderError("builder_model_result_invalid") from error
            if type(value) is not dict or canonical_json_bytes(value) != payload:
                raise BuilderError("builder_model_result_invalid")
            usage_value = value.pop("usage", None)
            if type(usage_value) is not dict:
                raise BuilderError("builder_model_result_invalid")
            # Legacy test fixtures may carry an asserted cost; it is deliberately ignored.
            value.pop("trusted_cost_microdollars", None)
            try:
                result = OpenAIModelResult(
                    **value,
                    usage=OpenAIUsage(**usage_value),
                    request_digest=request.request_digest,
                )
            except TypeError as error:
                raise BuilderError("builder_model_result_invalid") from error
        else:
            result = OpenAIModelGateway.from_protected_environment().evaluate(request)
        receipt = ProtectedGatewayCostReceipt.sign(
            request=request,
            result=result,
            policy=self._policy(),
            key=self._store.receipt_key(),
        )
        self._store.persist_gateway_cost_receipt(receipt)
        self._receipts[request.request_digest] = receipt
        return result

    def cost_receipt(self, request_digest: str) -> ProtectedGatewayCostReceipt:
        try:
            return self._receipts[request_digest]
        except KeyError as error:
            raise BuilderError("builder_gateway_cost_missing") from error

    def trusted_cost_microdollars(self, request_digest: str) -> int:
        return self.cost_receipt(request_digest).cost_microdollars
