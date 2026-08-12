from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from carl_bench.tasks import TaskContractError, discover_tasks, load_task

FIXTURE = Path(__file__).parent / "fixtures" / "valid-task"


def copy_fixture(tmp_path: Path, name: str = "task") -> Path:
    destination = tmp_path / name
    shutil.copytree(FIXTURE, destination)
    return destination


def rewrite(path: Path, old: str, new: str) -> None:
    source = path.read_text(encoding="utf-8")
    assert old in source
    path.write_text(source.replace(old, new), encoding="utf-8")


def test_valid_task_loads_with_stable_identity_and_closed_contract(tmp_path: Path) -> None:
    first = load_task(copy_fixture(tmp_path, "first"))
    second = load_task(copy_fixture(tmp_path, "second"))

    assert first.identity.task_id == "carl/fixture-task"
    assert first.identity.track == "coding"
    assert first.identity.digest == second.identity.digest
    assert len(first.identity.digest) == 64
    assert first.instruction == "Change hello.txt from broken to fixed.\n"
    assert first.fixture_dir.name == "fixture"
    assert first.workspace_dir == "/workspace"
    assert first.verifier_command == ("python3", "/tests/verify.py")
    assert first.agent_timeout_sec == 180
    assert first.verifier_timeout_sec == 60
    assert first.capabilities == frozenset({"filesystem", "shell"})
    assert first.public is True
    assert len(first.metric_pack_digest) == 64
    assert first.metric_ids == ("coding.config_precedence_correct", "coding.tests_pass")


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda value: value.update({"unknown": True}), "task_manifest_unknown_key"),
        (lambda value: value.update({"schema_version": 2}), "task_schema_unsupported"),
        (lambda value: value.update({"track": "research"}), "task_track_unsupported"),
        (
            lambda value: value.update({"capabilities": ["filesystem", "browser"]}),
            "task_capability_unsupported",
        ),
        (lambda value: value.update({"fixture_dir": "/tmp/fixture"}), "task_path_invalid"),
        (lambda value: value.update({"fixture_dir": "../fixture"}), "task_path_invalid"),
        (
            lambda value: value.update({"verifier_command": "python verify.py"}),
            "task_command_invalid",
        ),
        (lambda value: value.update({"workspace_dir": "workspace"}), "task_workspace_invalid"),
        (lambda value: value.update({"agent_timeout_sec": 181}), "task_timeout_mismatch"),
        (lambda value: value.update({"verifier_timeout_sec": 61}), "task_timeout_mismatch"),
        (lambda value: value.pop("metric_pack_digest"), "task_manifest_missing_key"),
        (
            lambda value: value.update({"metric_pack_digest": "not-a-digest"}),
            "task_metric_pack_digest_invalid",
        ),
        (lambda value: value.update({"metric_ids": []}), "task_metric_ids_invalid"),
        (
            lambda value: value.update(
                {"metric_ids": ["coding.tests_pass", "coding.config_precedence_correct"]}
            ),
            "task_metric_ids_not_sorted",
        ),
        (
            lambda value: value.update(
                {
                    "metric_ids": [
                        "coding.config_precedence_correct",
                        "coding.config_precedence_correct",
                    ]
                }
            ),
            "task_metric_ids_duplicate",
        ),
    ],
)
def test_invalid_manifest_variants_fail_closed(tmp_path: Path, mutation: object, code: str) -> None:
    task = copy_fixture(tmp_path)
    manifest_path = task / "carl-task.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mutation(manifest)  # type: ignore[operator]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(TaskContractError, match=code):
        load_task(task)


@pytest.mark.parametrize(
    ("relative_path", "code"),
    [
        ("task.toml", "task_required_file_missing"),
        ("instruction.md", "task_required_file_missing"),
        ("environment/Dockerfile", "task_required_file_missing"),
        ("tests/test.sh", "task_required_file_missing"),
        ("tests/verify.py", "task_verifier_missing"),
        ("solution/solve.sh", "task_required_file_missing"),
        ("carl-task.json", "task_required_file_missing"),
    ],
)
def test_missing_required_files_are_rejected(tmp_path: Path, relative_path: str, code: str) -> None:
    task = copy_fixture(tmp_path)
    (task / relative_path).unlink()
    with pytest.raises(TaskContractError, match=code):
        load_task(task)


def test_harbor_network_and_schema_are_exact(tmp_path: Path) -> None:
    task = copy_fixture(tmp_path)
    rewrite(task / "task.toml", 'network_mode = "none"', 'network_mode = "public"')
    with pytest.raises(TaskContractError, match="task_network_forbidden"):
        load_task(task)

    task = copy_fixture(tmp_path, "schema")
    rewrite(task / "task.toml", 'schema_version = "1.3"', 'schema_version = "1.2"')
    with pytest.raises(TaskContractError, match="task_harbor_schema_unsupported"):
        load_task(task)


def test_public_task_requires_an_oracle_solution(tmp_path: Path) -> None:
    task = copy_fixture(tmp_path)
    (task / "solution" / "solve.sh").unlink()
    with pytest.raises(TaskContractError, match="task_required_file_missing"):
        load_task(task)


def test_group_writable_and_symlinked_sources_are_rejected(tmp_path: Path) -> None:
    writable = copy_fixture(tmp_path, "writable")
    os.chmod(writable / "instruction.md", 0o666)
    with pytest.raises(TaskContractError, match="task_source_permissions_unsafe"):
        load_task(writable)

    linked = copy_fixture(tmp_path, "linked")
    (linked / "environment" / "fixture" / "alias.txt").symlink_to("hello.txt")
    with pytest.raises(TaskContractError, match="task_source_entry_unsupported"):
        load_task(linked)


def test_verifier_command_must_resolve_inside_tests_directory(tmp_path: Path) -> None:
    task = copy_fixture(tmp_path)
    manifest_path = task / "carl-task.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["verifier_command"] = ["python3", "/tests/missing.py"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(TaskContractError, match="task_verifier_missing"):
        load_task(task)


def test_discovery_is_sorted_and_rejects_duplicate_task_names(tmp_path: Path) -> None:
    second = copy_fixture(tmp_path, "z-task")
    rewrite(second / "task.toml", 'name = "carl/fixture-task"', 'name = "carl/z-task"')
    first = copy_fixture(tmp_path, "a-task")
    rewrite(first / "task.toml", 'name = "carl/fixture-task"', 'name = "carl/a-task"')
    assert [task.identity.task_id for task in discover_tasks(tmp_path)] == [
        "carl/a-task",
        "carl/z-task",
    ]

    duplicate = copy_fixture(tmp_path, "duplicate")
    rewrite(duplicate / "task.toml", 'name = "carl/fixture-task"', 'name = "carl/a-task"')
    with pytest.raises(TaskContractError, match="task_id_duplicate"):
        discover_tasks(tmp_path)


def test_discovery_rejects_a_non_directory_root(tmp_path: Path) -> None:
    with pytest.raises(TaskContractError, match="task_root_invalid"):
        discover_tasks(tmp_path / "missing")
