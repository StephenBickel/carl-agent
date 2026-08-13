from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

import pytest

from carl_bench.artifacts import (
    ArtifactIntegrityError,
    ArtifactRef,
    PrivateArtifactStore,
)


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700)
    if os.name != "nt":
        path.chmod(0o700)
    return path


def test_artifact_store_round_trips_content_and_deduplicates_by_digest(tmp_path: Path) -> None:
    repository = _private(tmp_path / "repository")
    store = PrivateArtifactStore(tmp_path / "private" / "artifacts", repository)

    first = store.put(
        evidence_kind="candidate_diff",
        media_type="text/x-diff",
        content=b"diff --git a/file b/file\n",
    )
    second = store.put(
        evidence_kind="candidate_diff",
        media_type="text/x-diff",
        content=b"diff --git a/file b/file\n",
    )

    assert first == second
    assert first.to_canonical_dict() == {
        "byte_size": 25,
        "digest": "7fee7b7dc8280c5de1e1ad84b990dad3af6ce97e7a5c4999abaed22f285c5aee",
        "evidence_kind": "candidate_diff",
        "media_type": "text/x-diff",
        "schema_version": 1,
    }
    assert ArtifactRef.from_canonical_dict(first.to_canonical_dict()) == first
    assert store.read(first) == b"diff --git a/file b/file\n"
    if os.name != "nt":
        assert stat.S_IMODE(store.root.stat().st_mode) == 0o700
        assert stat.S_IMODE((store.root / first.digest).stat().st_mode) == 0o600


def test_artifact_store_detects_tampering_and_symlink_objects(tmp_path: Path) -> None:
    repository = _private(tmp_path / "repository")
    store = PrivateArtifactStore(tmp_path / "private" / "artifacts", repository)
    ref = store.put(
        evidence_kind="check_output",
        media_type="text/plain",
        content=b"passing\n",
    )
    object_path = store.root / ref.digest
    object_path.write_bytes(b"changed\n")

    with pytest.raises(ArtifactIntegrityError, match="artifact_digest_mismatch"):
        store.read(ref)

    object_path.unlink()
    target = tmp_path / "elsewhere"
    target.write_bytes(b"passing\n")
    object_path.symlink_to(target)
    with pytest.raises(ArtifactIntegrityError, match="artifact_object_unsafe"):
        store.read(ref)


def test_artifact_store_rejects_repository_paths_unsafe_roots_and_oversized_content(
    tmp_path: Path,
) -> None:
    repository = _private(tmp_path / "repository")
    with pytest.raises(ArtifactIntegrityError, match="artifact_store_inside_repository"):
        PrivateArtifactStore(repository / "artifacts", repository)

    external = _private(tmp_path / "external")
    symlink = tmp_path / "artifact-link"
    symlink.symlink_to(external, target_is_directory=True)
    with pytest.raises(ArtifactIntegrityError, match="artifact_store_unsafe"):
        PrivateArtifactStore(symlink, repository)

    unsafe = _private(tmp_path / "unsafe")
    if os.name != "nt":
        unsafe.chmod(0o755)
        with pytest.raises(ArtifactIntegrityError, match="artifact_store_unsafe"):
            PrivateArtifactStore(unsafe, repository)

    store = PrivateArtifactStore(tmp_path / "private" / "artifacts", repository)
    with pytest.raises(ArtifactIntegrityError, match="artifact_too_large"):
        store.put(
            evidence_kind="candidate_diff",
            media_type="application/octet-stream",
            content=b"x" * (16 * 1_048_576 + 1),
        )


@pytest.mark.parametrize(
    ("value", "code"),
    [
        ({}, "invalid_artifact_keys"),
        (
            {
                "byte_size": 1,
                "digest": hashlib.sha256(b"x").hexdigest(),
                "evidence_kind": "UPPERCASE",
                "media_type": "text/plain",
                "schema_version": 1,
            },
            "invalid_evidence_kind",
        ),
        (
            {
                "byte_size": 1,
                "digest": hashlib.sha256(b"x").hexdigest(),
                "evidence_kind": "report",
                "media_type": "bad media",
                "schema_version": 1,
            },
            "invalid_media_type",
        ),
    ],
)
def test_artifact_contract_rejects_noncanonical_or_unbounded_values(
    value: dict[str, object], code: str
) -> None:
    with pytest.raises(ArtifactIntegrityError, match=code):
        ArtifactRef.from_canonical_dict(value)
