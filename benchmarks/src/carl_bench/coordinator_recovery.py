"""Typed supervisor recovery request for one exact frozen coordinator node."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_coordinator import NODE_ORDER

RECOVERY_DOMAIN = "carl.coordinator.recovery.v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}$")


class CoordinatorRecoveryError(ValueError):
    def __init__(self, code: str = "coordinator_recovery_request_invalid") -> None:
        self.code = code
        super().__init__(code)


def _canonical_time(value: object) -> None:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise CoordinatorRecoveryError()
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise CoordinatorRecoveryError() from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise CoordinatorRecoveryError()


@dataclass(frozen=True, slots=True)
class CoordinatorRecoveryRequest:
    schema_version: int
    domain: str
    experiment_id: str
    node_id: str
    node_kind: str
    expected_revision: int
    evidence_digest: str
    repair_fingerprint: str
    requested_at: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or self.schema_version != 1
            or self.domain != RECOVERY_DOMAIN
            or not isinstance(self.experiment_id, str)
            or _IDENTIFIER.fullmatch(self.experiment_id) is None
            or self.node_kind not in NODE_ORDER
            or self.node_id != f"{self.experiment_id}:{self.node_kind}"
            or isinstance(self.expected_revision, bool)
            or not isinstance(self.expected_revision, int)
            or not 0 <= self.expected_revision < 2_147_483_647
            or not isinstance(self.evidence_digest, str)
            or _DIGEST.fullmatch(self.evidence_digest) is None
            or not isinstance(self.repair_fingerprint, str)
            or _DIGEST.fullmatch(self.repair_fingerprint) is None
        ):
            raise CoordinatorRecoveryError()
        _canonical_time(self.requested_at)

    @classmethod
    def from_canonical_dict(cls, value: object) -> CoordinatorRecoveryRequest:
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise CoordinatorRecoveryError()
        try:
            return cls(**value)
        except (KeyError, TypeError, ValueError) as error:
            raise CoordinatorRecoveryError() from error

    def to_canonical_dict(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()
