"""Immutable, content-addressed archive boundary for verified cloud evidence."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from carl_bench.canonical import canonical_json_bytes

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,180}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+=-]{0,255}$")
_ETAG = re.compile(r'^"[A-Za-z0-9._:+/=-]{1,255}"$')
_MEDIA_TYPES = frozenset(
    {
        "application/vnd.carl.improvement-evidence+json;version=1",
        "application/vnd.carl.soak-observation+json;version=1",
    }
)
_MAX_EVIDENCE_BYTES = 8_388_608


class EvidenceArchiveError(ValueError):
    """Stable archive failure without provider details or credentials."""


class ArchiveResponseLost(RuntimeError):
    """The immutable create may have succeeded but its response was lost."""


@dataclass(frozen=True, slots=True)
class ArchiveIdentity:
    repository: str
    request_digest: str
    run_id: int
    artifact_id: int
    artifact_name: str
    media_type: str
    schema_version: int

    def __post_init__(self) -> None:
        if not isinstance(self.repository, str) or not _REPOSITORY.fullmatch(self.repository):
            raise EvidenceArchiveError("evidence_archive_repository_invalid")
        if not isinstance(self.request_digest, str) or not _DIGEST.fullmatch(self.request_digest):
            raise EvidenceArchiveError("evidence_archive_request_digest_invalid")
        for field in ("run_id", "artifact_id"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise EvidenceArchiveError(f"evidence_archive_{field}_invalid")
        if not isinstance(self.artifact_name, str) or not _NAME.fullmatch(self.artifact_name):
            raise EvidenceArchiveError("evidence_archive_artifact_name_invalid")
        if self.media_type not in _MEDIA_TYPES:
            raise EvidenceArchiveError("evidence_archive_media_type_invalid")
        if isinstance(self.schema_version, bool) or self.schema_version != 1:
            raise EvidenceArchiveError("evidence_archive_schema_invalid")


@dataclass(frozen=True, slots=True)
class ImmutableObject:
    object_key: str
    version_id: str
    etag: str
    checksum_sha256: str
    byte_length: int
    retention_mode: str
    retain_until: str
    metadata_digest: str
    created_at: str


@dataclass(frozen=True, slots=True)
class ArchivedEvidence:
    identity: ArchiveIdentity
    object_key: str
    payload_digest: str
    byte_length: int
    provider_version_id: str
    provider_etag: str
    provider_checksum_sha256: str
    retention_mode: str
    retain_until: str
    archived_at: str

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "archive_identity": {
                name: getattr(self.identity, name) for name in self.identity.__dataclass_fields__
            },
            "archived_at": self.archived_at,
            "byte_length": self.byte_length,
            "object_key": self.object_key,
            "payload_digest": self.payload_digest,
            "provider_checksum_sha256": self.provider_checksum_sha256,
            "provider_etag": self.provider_etag,
            "provider_version_id": self.provider_version_id,
            "retain_until": self.retain_until,
            "retention_mode": self.retention_mode,
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()


class ImmutableEvidenceStore(Protocol):
    """Narrow create/head surface; mutation and caller-selected endpoints are absent."""

    def create_immutable(
        self, key: str, payload: bytes, metadata: dict[str, str]
    ) -> ImmutableObject: ...

    def head_immutable(self, key: str) -> ImmutableObject | None: ...


def _utc(value: str, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise EvidenceArchiveError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise EvidenceArchiveError(code) from error
    if parsed.tzinfo != UTC or parsed.isoformat().replace("+00:00", "Z") != value:
        raise EvidenceArchiveError(code)
    return parsed


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo != UTC:
        raise EvidenceArchiveError("evidence_archive_clock_invalid")
    return value.isoformat().replace("+00:00", "Z")


class EvidenceArchive:
    """Archives one exact in-memory buffer before it can become trusted evidence."""

    __slots__ = ("__clock", "__store")

    def __init__(self, *, store: ImmutableEvidenceStore, clock: object, _testing: bool) -> None:
        if not _testing or not callable(clock):
            raise EvidenceArchiveError("evidence_archive_construction_invalid")
        self.__store = store
        self.__clock = clock

    @classmethod
    def _for_testing(cls, *, store: ImmutableEvidenceStore, clock: object) -> EvidenceArchive:
        return cls(store=store, clock=clock, _testing=True)

    def archive(self, identity: ArchiveIdentity, payload: bytes) -> ArchivedEvidence:
        if not isinstance(identity, ArchiveIdentity):
            raise EvidenceArchiveError("evidence_archive_identity_invalid")
        if not isinstance(payload, bytes) or not 0 < len(payload) <= _MAX_EVIDENCE_BYTES:
            raise EvidenceArchiveError("evidence_archive_payload_invalid")
        archived_at_value = self.__clock()
        _timestamp(archived_at_value)
        digest = hashlib.sha256(payload).hexdigest()
        key = f"carl-evidence/v1/sha256/{digest[:2]}/{digest}"
        metadata = {
            "artifact_id": str(identity.artifact_id),
            "artifact_name": identity.artifact_name,
            "media_type": identity.media_type,
            "payload_digest": digest,
            "repository": identity.repository,
            "request_digest": identity.request_digest,
            "run_id": str(identity.run_id),
            "schema_version": str(identity.schema_version),
        }
        metadata_digest = hashlib.sha256(canonical_json_bytes(metadata)).hexdigest()
        try:
            provider = self.__store.create_immutable(key, payload, metadata)
        except ArchiveResponseLost:
            try:
                provider = self.__store.head_immutable(key)
            except Exception:
                raise EvidenceArchiveError("evidence_archive_unavailable") from None
            if provider is None:
                raise EvidenceArchiveError("evidence_archive_response_ambiguous") from None
        except EvidenceArchiveError:
            raise
        except Exception:
            raise EvidenceArchiveError("evidence_archive_unavailable") from None
        return self._validated_record(
            identity=identity,
            key=key,
            digest=digest,
            byte_length=len(payload),
            provider=provider,
            observed_at=archived_at_value,
            metadata_digest=metadata_digest,
        )

    @staticmethod
    def _validated_record(
        *,
        identity: ArchiveIdentity,
        key: str,
        digest: str,
        byte_length: int,
        provider: object,
        observed_at: datetime,
        metadata_digest: str,
    ) -> ArchivedEvidence:
        if not isinstance(provider, ImmutableObject):
            raise EvidenceArchiveError("evidence_archive_provider_result_invalid")
        if provider.object_key != key:
            raise EvidenceArchiveError("evidence_archive_object_key_mismatch")
        if not isinstance(provider.version_id, str) or not _VERSION.fullmatch(provider.version_id):
            raise EvidenceArchiveError("evidence_archive_version_invalid")
        if not isinstance(provider.etag, str) or not _ETAG.fullmatch(provider.etag):
            raise EvidenceArchiveError("evidence_archive_etag_invalid")
        if provider.checksum_sha256 != digest:
            raise EvidenceArchiveError("evidence_archive_checksum_mismatch")
        if provider.byte_length != byte_length:
            raise EvidenceArchiveError("evidence_archive_length_mismatch")
        if provider.retention_mode != "COMPLIANCE":
            raise EvidenceArchiveError("evidence_archive_retention_invalid")
        if _utc(provider.retain_until, "evidence_archive_retention_invalid") <= observed_at:
            raise EvidenceArchiveError("evidence_archive_retention_invalid")
        if provider.metadata_digest != metadata_digest:
            raise EvidenceArchiveError("evidence_archive_metadata_mismatch")
        created_at = _utc(provider.created_at, "evidence_archive_created_at_invalid")
        if created_at > observed_at:
            raise EvidenceArchiveError("evidence_archive_created_at_invalid")
        return ArchivedEvidence(
            identity=identity,
            object_key=key,
            payload_digest=digest,
            byte_length=byte_length,
            provider_version_id=provider.version_id,
            provider_etag=provider.etag,
            provider_checksum_sha256=provider.checksum_sha256,
            retention_mode=provider.retention_mode,
            retain_until=provider.retain_until,
            archived_at=provider.created_at,
        )
