"""Closed, content-addressed definitions for behavior-oriented benchmark metrics."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from carl_bench.canonical import canonical_json_bytes

_PACK_KEYS = frozenset({"schema_version", "pack_id", "pack_version", "metrics"})
_METRIC_KEYS = frozenset(
    {
        "metric_id",
        "version",
        "mode",
        "observation",
        "threshold_basis_points",
        "reason_codes",
        "disclosure",
        "judge_justification",
    }
)
_METRIC_ID = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
_REASON_CODE = re.compile(r"[a-z][a-z0-9_]*")
_PACK_ID = re.compile(r"[a-z][a-z0-9-]*")


class MetricContractError(ValueError):
    """A stable metric-pack validation failure that does not reveal pack contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class MetricMode(str, Enum):
    DETERMINISTIC = "deterministic"
    JUDGE = "judge"


class ObservationKind(str, Enum):
    FINAL_STATE = "final_state"
    FINAL_RESPONSE = "final_response"
    EFFECT_INVARIANT = "effect_invariant"


class Disclosure(str, Enum):
    PUBLIC = "public"
    PROTECTED_AGGREGATE = "protected_aggregate"


@dataclass(frozen=True, slots=True)
class MetricDefinition:
    metric_id: str
    version: int
    mode: MetricMode
    observation: ObservationKind
    threshold_basis_points: int
    reason_codes: tuple[str, ...]
    disclosure: Disclosure
    judge_justification: str | None

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "metric_id": self.metric_id,
            "version": self.version,
            "mode": self.mode.value,
            "observation": self.observation.value,
            "threshold_basis_points": self.threshold_basis_points,
            "reason_codes": list(self.reason_codes),
            "disclosure": self.disclosure.value,
            "judge_justification": self.judge_justification,
        }


@dataclass(frozen=True, slots=True)
class MetricPack:
    schema_version: int
    pack_id: str
    pack_version: int
    metrics: tuple[MetricDefinition, ...]

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "pack_id": self.pack_id,
            "pack_version": self.pack_version,
            "metrics": [metric.to_canonical_dict() for metric in self.metrics],
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


@dataclass(frozen=True, slots=True)
class MetricVerdict:
    """A metric-level outcome shape, registered here without a judge runner."""

    metric_id: str
    passed: bool
    score_basis_points: int
    reason_code: str
    reason: str
    disclosure: Disclosure


def is_metric_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value.encode("utf-8")) <= 128
        and _METRIC_ID.fullmatch(value) is not None
    )


def _json_object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise MetricContractError("metric_pack_duplicate_key")
        value[key] = item
    return value


def _read_pack(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_size > 1_048_576
        ):
            raise MetricContractError("metric_pack_invalid")
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_json_object_without_duplicates
        )
    except MetricContractError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise MetricContractError("metric_pack_invalid") from error
    if not isinstance(value, dict):
        raise MetricContractError("metric_pack_invalid")
    return value


def _exact_keys(value: dict[str, Any], expected: frozenset[str], *, name: str) -> None:
    if set(value) - expected:
        raise MetricContractError(f"{name}_unknown_key")
    if expected - set(value):
        raise MetricContractError(f"{name}_missing_key")


def _positive_int(value: object, *, maximum: int, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise MetricContractError(code)
    return value


def _enum(enum: type[Enum], value: object, *, code: str) -> Enum:
    try:
        return enum(value)
    except (TypeError, ValueError) as error:
        raise MetricContractError(code) from error


def _reason_codes(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise MetricContractError("metric_reason_codes_invalid")
    if any(
        not isinstance(item, str)
        or not 1 <= len(item.encode("utf-8")) <= 64
        or _REASON_CODE.fullmatch(item) is None
        for item in value
    ):
        raise MetricContractError("metric_reason_codes_invalid")
    result = tuple(value)
    if tuple(sorted(result, key=str.encode)) != result:
        raise MetricContractError("metric_reason_codes_not_sorted")
    if len(set(result)) != len(result):
        raise MetricContractError("metric_reason_codes_duplicate")
    return result


def _metric_definition(value: object) -> MetricDefinition:
    if not isinstance(value, dict):
        raise MetricContractError("metric_definition_invalid")
    _exact_keys(value, _METRIC_KEYS, name="metric_definition")
    metric_id = value["metric_id"]
    if not is_metric_id(metric_id):
        raise MetricContractError("metric_id_invalid")
    version = _positive_int(value["version"], maximum=1_000_000, code="metric_version_invalid")
    mode = _enum(MetricMode, value["mode"], code="metric_mode_unsupported")
    observation = _enum(
        ObservationKind, value["observation"], code="metric_observation_unsupported"
    )
    threshold = value["threshold_basis_points"]
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, int)
        or not 0 <= threshold <= 10_000
    ):
        raise MetricContractError("metric_threshold_invalid")
    disclosure = _enum(Disclosure, value["disclosure"], code="metric_disclosure_unsupported")
    justification = value["judge_justification"]
    if mode is MetricMode.JUDGE:
        if observation is not ObservationKind.FINAL_RESPONSE:
            raise MetricContractError("judge_observation_invalid")
        if (
            not isinstance(justification, str)
            or not 20 <= len(justification.encode("utf-8")) <= 512
        ):
            raise MetricContractError("judge_justification_required")
    elif justification is not None:
        raise MetricContractError("metric_judge_justification_invalid")
    return MetricDefinition(
        metric_id=metric_id,
        version=version,
        mode=mode,
        observation=observation,
        threshold_basis_points=threshold,
        reason_codes=_reason_codes(value["reason_codes"]),
        disclosure=disclosure,
        judge_justification=justification,
    )


def load_metric_pack(path: Path) -> MetricPack:
    """Load one immutable metric pack after its complete contract validates."""
    value = _read_pack(path)
    _exact_keys(value, _PACK_KEYS, name="metric_pack")
    if value["schema_version"] != 1:
        raise MetricContractError("metric_pack_schema_unsupported")
    pack_id = value["pack_id"]
    if (
        not isinstance(pack_id, str)
        or not 1 <= len(pack_id.encode("utf-8")) <= 64
        or _PACK_ID.fullmatch(pack_id) is None
    ):
        raise MetricContractError("metric_pack_id_invalid")
    pack_version = _positive_int(
        value["pack_version"], maximum=1_000_000, code="metric_pack_version_invalid"
    )
    metrics_value = value["metrics"]
    if not isinstance(metrics_value, list) or not metrics_value:
        raise MetricContractError("metric_pack_metrics_invalid")
    metrics = tuple(_metric_definition(item) for item in metrics_value)
    metric_ids = tuple(metric.metric_id for metric in metrics)
    if tuple(sorted(metric_ids, key=str.encode)) != metric_ids:
        raise MetricContractError("metric_ids_not_sorted")
    if len(set(metric_ids)) != len(metric_ids):
        raise MetricContractError("metric_ids_duplicate")
    return MetricPack(
        schema_version=1,
        pack_id=pack_id,
        pack_version=pack_version,
        metrics=metrics,
    )
