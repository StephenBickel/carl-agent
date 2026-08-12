from __future__ import annotations

import math
import os
from pathlib import Path

import pytest

from carl_bench.canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    sha256_file,
    sha256_tree,
)


def test_canonical_json_is_compact_sorted_utf8_without_a_newline() -> None:
    assert canonical_json_bytes({"z": "café", "a": [2, 1]}) == (b'{"a":[2,1],"z":"caf\xc3\xa9"}')


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_canonical_json_rejects_non_finite_numbers(value: float) -> None:
    with pytest.raises(CanonicalizationError, match="canonical_json_invalid"):
        canonical_json_bytes({"value": value})


def test_file_digest_changes_with_literal_bytes(tmp_path: Path) -> None:
    target = tmp_path / "value.txt"
    target.write_bytes(b"first\n")
    first = sha256_file(target)
    target.write_bytes(b"second\n")
    assert first != sha256_file(target)


def test_tree_digest_is_independent_of_creation_order(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "a.txt").write_text("A", encoding="utf-8")
    (first / "b.txt").write_text("B", encoding="utf-8")
    (second / "b.txt").write_text("B", encoding="utf-8")
    (second / "a.txt").write_text("A", encoding="utf-8")

    assert sha256_tree(first) == sha256_tree(second)


def test_tree_digest_binds_path_content_and_executable_mode(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    (left / "run.sh").write_text("exit 0\n", encoding="utf-8")
    (right / "renamed.sh").write_text("exit 0\n", encoding="utf-8")
    assert sha256_tree(left) != sha256_tree(right)

    (right / "renamed.sh").rename(right / "run.sh")
    assert sha256_tree(left) == sha256_tree(right)
    os.chmod(right / "run.sh", 0o755)
    assert sha256_tree(left) != sha256_tree(right)


def test_tree_digest_honors_exact_excluded_names(tmp_path: Path) -> None:
    (tmp_path / "kept.txt").write_text("kept", encoding="utf-8")
    (tmp_path / ".cache").mkdir()
    (tmp_path / ".cache" / "ignored.txt").write_text("one", encoding="utf-8")
    digest = sha256_tree(tmp_path, excluded_names=frozenset({".cache"}))
    (tmp_path / ".cache" / "ignored.txt").write_text("two", encoding="utf-8")
    assert sha256_tree(tmp_path, excluded_names=frozenset({".cache"})) == digest


def test_tree_digest_rejects_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("safe", encoding="utf-8")
    (tmp_path / "alias.txt").symlink_to(target)

    with pytest.raises(CanonicalizationError, match="tree_unsupported_entry"):
        sha256_tree(tmp_path)


def test_tree_digest_rejects_file_and_tree_size_overflow(tmp_path: Path) -> None:
    (tmp_path / "large.bin").write_bytes(b"x" * (1_048_576 + 1))
    with pytest.raises(CanonicalizationError, match="tree_file_too_large"):
        sha256_tree(tmp_path)

    (tmp_path / "large.bin").unlink()
    for index in range(17):
        (tmp_path / f"part-{index:02}.bin").write_bytes(b"x" * 1_048_576)
    with pytest.raises(CanonicalizationError, match="tree_too_large"):
        sha256_tree(tmp_path)


def test_tree_digest_rejects_non_directory_and_missing_roots(tmp_path: Path) -> None:
    file_root = tmp_path / "file.txt"
    file_root.write_text("data", encoding="utf-8")
    with pytest.raises(CanonicalizationError, match="tree_root_invalid"):
        sha256_tree(file_root)
    with pytest.raises(CanonicalizationError, match="tree_root_invalid"):
        sha256_tree(tmp_path / "missing")
