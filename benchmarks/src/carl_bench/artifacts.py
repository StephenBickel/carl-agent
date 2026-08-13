"""Owner-private content-addressed storage for candidate evidence."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_ARTIFACT_BYTES = 16 * 1_048_576
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_KIND_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MEDIA_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,63}/[a-z0-9][a-z0-9.+-]{0,63}$")


class ArtifactIntegrityError(ValueError):
    """A stable artifact failure that does not expose private content or paths."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ArtifactRef:
    schema_version: int
    digest: str
    byte_size: int
    media_type: str
    evidence_kind: str

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ArtifactIntegrityError("invalid_artifact_schema")
        if not isinstance(self.digest, str) or not _DIGEST_RE.fullmatch(self.digest):
            raise ArtifactIntegrityError("invalid_artifact_digest")
        if (
            isinstance(self.byte_size, bool)
            or not isinstance(self.byte_size, int)
            or not 0 <= self.byte_size <= MAX_ARTIFACT_BYTES
        ):
            raise ArtifactIntegrityError("invalid_artifact_size")
        if not isinstance(self.evidence_kind, str) or not _KIND_RE.fullmatch(self.evidence_kind):
            raise ArtifactIntegrityError("invalid_evidence_kind")
        if not isinstance(self.media_type, str) or not _MEDIA_TYPE_RE.fullmatch(self.media_type):
            raise ArtifactIntegrityError("invalid_media_type")

    def to_canonical_dict(self) -> dict[str, Any]:
        return {
            "byte_size": self.byte_size,
            "digest": self.digest,
            "evidence_kind": self.evidence_kind,
            "media_type": self.media_type,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_canonical_dict(cls, value: Any) -> ArtifactRef:
        expected = {
            "byte_size",
            "digest",
            "evidence_kind",
            "media_type",
            "schema_version",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ArtifactIntegrityError("invalid_artifact_keys")
        try:
            return cls(**value)
        except TypeError as error:
            raise ArtifactIntegrityError("invalid_artifact") from error


def _anchored(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    return absolute.parent.resolve(strict=False) / absolute.name


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _owner_private_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return False
    if os.name != "nt":
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            return False
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            return False
    return True


class PrivateArtifactStore:
    def __init__(self, root: Path, repository_root: Path) -> None:
        self.root = _anchored(root)
        repository = _anchored(repository_root)
        if _inside(self.root, repository):
            raise ArtifactIntegrityError("artifact_store_inside_repository")
        if self.root.exists() or self.root.is_symlink():
            if not _owner_private_directory(self.root):
                raise ArtifactIntegrityError("artifact_store_unsafe")
        else:
            try:
                self.root.mkdir(mode=0o700, parents=True)
                if os.name != "nt":
                    self.root.chmod(0o700)
            except OSError as error:
                raise ArtifactIntegrityError("artifact_store_unavailable") from error
            if not _owner_private_directory(self.root):
                raise ArtifactIntegrityError("artifact_store_unsafe")

    def _object_path(self, digest: str) -> Path:
        if not _DIGEST_RE.fullmatch(digest):
            raise ArtifactIntegrityError("invalid_artifact_digest")
        return self.root / digest

    def put(self, *, evidence_kind: str, media_type: str, content: bytes) -> ArtifactRef:
        if not isinstance(content, bytes):
            raise ArtifactIntegrityError("invalid_artifact_content")
        if len(content) > MAX_ARTIFACT_BYTES:
            raise ArtifactIntegrityError("artifact_too_large")
        ref = ArtifactRef(
            schema_version=1,
            digest=hashlib.sha256(content).hexdigest(),
            byte_size=len(content),
            media_type=media_type,
            evidence_kind=evidence_kind,
        )
        destination = self._object_path(ref.digest)
        if destination.exists() or destination.is_symlink():
            if self.read(ref) != content:
                raise ArtifactIntegrityError("artifact_digest_mismatch")
            return ref

        temporary: Path | None = None
        try:
            descriptor, name = tempfile.mkstemp(prefix=".pending-", dir=self.root)
            temporary = Path(name)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            if os.name != "nt":
                temporary.chmod(0o600)
            with suppress(FileExistsError):
                os.link(temporary, destination, follow_symlinks=False)
        except OSError as error:
            raise ArtifactIntegrityError("artifact_write_failed") from error
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        if self.read(ref) != content:
            raise ArtifactIntegrityError("artifact_digest_mismatch")
        return ref

    def read(self, ref: ArtifactRef) -> bytes:
        if not isinstance(ref, ArtifactRef):
            raise ArtifactIntegrityError("invalid_artifact_reference")
        source = self._object_path(ref.digest)
        try:
            metadata = source.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ArtifactIntegrityError("artifact_object_unsafe")
            if metadata.st_size != ref.byte_size or metadata.st_size > MAX_ARTIFACT_BYTES:
                raise ArtifactIntegrityError("artifact_size_mismatch")
            if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ArtifactIntegrityError("artifact_object_unsafe")
            content = source.read_bytes()
        except ArtifactIntegrityError:
            raise
        except OSError as error:
            raise ArtifactIntegrityError("artifact_read_failed") from error
        if len(content) != ref.byte_size:
            raise ArtifactIntegrityError("artifact_size_mismatch")
        if hashlib.sha256(content).hexdigest() != ref.digest:
            raise ArtifactIntegrityError("artifact_digest_mismatch")
        return content
