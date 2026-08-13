from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from carl_bench.sanitize import PublicSafetyError, assert_public_safe, write_public_json


@pytest.mark.parametrize(
    "forbidden_key",
    [
        "prompt",
        "instruction",
        "response",
        "output",
        "stdout",
        "stderr",
        "environment",
        "secret",
        "token",
    ],
)
def test_public_safety_rejects_sensitive_keys_at_every_depth(
    tmp_path: Path, forbidden_key: str
) -> None:
    with pytest.raises(PublicSafetyError) as caught:
        assert_public_safe({"outer": [{forbidden_key: "redacted"}]}, tmp_path)

    assert caught.value.code == "public_forbidden_key"
    assert caught.value.pointer == f"/outer/0/{forbidden_key}"
    assert "redacted" not in str(caught.value)


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "-----BEGIN PRIVATE KEY-----",
        "Bearer abcdefghijklmnopqrstuvwxyz",
        "sk-proj-abcdefghijklmnopqrstuvwxyz123456",
        "x" * 513,
    ],
)
def test_public_safety_rejects_secret_shapes_and_long_strings(
    tmp_path: Path, unsafe_value: str
) -> None:
    with pytest.raises(PublicSafetyError) as caught:
        assert_public_safe({"detail": unsafe_value}, tmp_path)

    assert caught.value.code in {"public_secret_pattern", "public_string_too_long"}
    assert unsafe_value not in str(caught.value)


def test_public_safety_rejects_repository_and_home_paths(tmp_path: Path) -> None:
    for value in (str(tmp_path.resolve()), str(Path.home().resolve())):
        with pytest.raises(PublicSafetyError, match="public_absolute_path"):
            assert_public_safe({"path": value}, tmp_path)


def test_public_safety_rejects_deep_and_wide_values(tmp_path: Path) -> None:
    deep: object = True
    for _ in range(13):
        deep = [deep]
    with pytest.raises(PublicSafetyError, match="public_too_deep"):
        assert_public_safe(deep, tmp_path)

    with pytest.raises(PublicSafetyError, match="public_too_wide"):
        assert_public_safe(list(range(257)), tmp_path)


def test_public_safety_accepts_closed_numeric_evidence(tmp_path: Path) -> None:
    assert_public_safe(
        {
            "schema_version": 1,
            "run_id": "run-01",
            "pass_rate": 0.75,
            "counts": [3, 1],
            "valid": True,
            "optional": None,
        },
        tmp_path,
    )


def test_public_writer_is_atomic_private_and_canonical(tmp_path: Path) -> None:
    destination = tmp_path / "results" / "scorecard.json"
    write_public_json(destination, {"z": 1, "a": True}, tmp_path)

    assert destination.read_bytes() == b'{"a":true,"z":1}\n'
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700
    assert list(destination.parent.glob(".scorecard.json.*")) == []


def test_public_writer_validates_before_creating_destination(tmp_path: Path) -> None:
    destination = tmp_path / "results" / "scorecard.json"
    with pytest.raises(PublicSafetyError):
        write_public_json(destination, {"stdout": "sensitive"}, tmp_path)

    assert not destination.exists()
    assert not destination.parent.exists()


def test_public_writer_rejects_symlink_destination(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text("unchanged", encoding="utf-8")
    destination = tmp_path / "scorecard.json"
    destination.symlink_to(real)

    with pytest.raises(PublicSafetyError, match="public_destination_unsafe"):
        write_public_json(destination, {"safe": True}, tmp_path)
    assert real.read_text(encoding="utf-8") == "unchanged"


def test_public_error_contains_only_code_and_pointer(tmp_path: Path) -> None:
    unsafe = "Bearer super-secret-provider-value"
    with pytest.raises(PublicSafetyError) as caught:
        assert_public_safe({"nested": [unsafe]}, tmp_path)

    rendered = str(caught.value)
    assert rendered == "public_secret_pattern at /nested/0"
    assert unsafe not in rendered
    assert os.fspath(tmp_path) not in rendered
