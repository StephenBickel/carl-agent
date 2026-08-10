"""Strict discovery and validation for portable benchmark tasks."""

from __future__ import annotations

import json
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from carl_bench.canonical import CanonicalizationError, sha256_tree
from carl_bench.models import TaskIdentity

_MANIFEST_KEYS = frozenset(
    {
        "agent_timeout_sec",
        "capabilities",
        "fixture_dir",
        "public",
        "schema_version",
        "track",
        "verifier_command",
        "verifier_timeout_sec",
        "workspace_dir",
    }
)
_CAPABILITIES = frozenset({"filesystem", "shell"})
_TRACKS = frozenset({"coding", "workflow", "safety"})
_REQUIRED_FILES = (
    "carl-task.json",
    "environment/Dockerfile",
    "instruction.md",
    "task.toml",
    "tests/test.sh",
)


class TaskContractError(ValueError):
    """A stable, content-free task validation failure."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class BenchmarkTask:
    source_dir: Path
    identity: TaskIdentity
    instruction: str
    fixture_dir: Path
    workspace_dir: str
    verifier_command: tuple[str, ...]
    verifier_source: Path
    protected_dir: Path | None
    agent_timeout_sec: int
    verifier_timeout_sec: int
    capabilities: frozenset[str]
    public: bool


def _read_required(path: Path, *, maximum: int = 1_048_576) -> bytes:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise TaskContractError("task_required_file_missing")
        if metadata.st_size > maximum:
            raise TaskContractError("task_required_file_too_large")
        return path.read_bytes()
    except TaskContractError:
        raise
    except (OSError, UnicodeError) as error:
        raise TaskContractError("task_required_file_missing") from error


def _json_object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TaskContractError("task_manifest_duplicate_key")
        result[key] = value
    return result


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        decoded = _read_required(path, maximum=65_536).decode("utf-8")
        value = json.loads(decoded, object_pairs_hook=_json_object_without_duplicates)
    except TaskContractError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise TaskContractError("task_manifest_invalid") from error
    if not isinstance(value, dict):
        raise TaskContractError("task_manifest_invalid")
    unknown = set(value) - _MANIFEST_KEYS
    missing = _MANIFEST_KEYS - set(value)
    if unknown:
        raise TaskContractError("task_manifest_unknown_key")
    if missing:
        raise TaskContractError("task_manifest_missing_key")
    return value


def _positive_int(value: Any, *, maximum: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        return None
    return value


def _relative_source_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 256:
        raise TaskContractError("task_path_invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise TaskContractError("task_path_invalid")
    return path


def _validate_source_tree(task_dir: Path) -> None:
    try:
        root_metadata = task_dir.lstat()
    except OSError as error:
        raise TaskContractError("task_root_invalid") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise TaskContractError("task_root_invalid")
    if stat.S_IMODE(root_metadata.st_mode) & 0o022:
        raise TaskContractError("task_source_permissions_unsafe")

    try:
        entries = tuple(task_dir.rglob("*"))
    except OSError as error:
        raise TaskContractError("task_source_unavailable") from error
    if len(entries) > 10_000:
        raise TaskContractError("task_source_too_many_entries")
    for entry in entries:
        try:
            metadata = entry.lstat()
        except OSError as error:
            raise TaskContractError("task_source_unavailable") from error
        if stat.S_ISLNK(metadata.st_mode) or not (
            stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
        ):
            raise TaskContractError("task_source_entry_unsupported")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise TaskContractError("task_source_permissions_unsafe")


def _load_harbor(path: Path) -> dict[str, Any]:
    try:
        value = tomllib.loads(_read_required(path, maximum=65_536).decode("utf-8"))
    except TaskContractError:
        raise
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise TaskContractError("task_harbor_manifest_invalid") from error
    if value.get("schema_version") != "1.3":
        raise TaskContractError("task_harbor_schema_unsupported")
    return value


def _harbor_timeout(harbor: dict[str, Any], section: str) -> int:
    table = harbor.get(section)
    if not isinstance(table, dict):
        raise TaskContractError("task_harbor_manifest_invalid")
    value = table.get("timeout_sec")
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not float(value).is_integer()
    ):
        raise TaskContractError("task_harbor_manifest_invalid")
    integer = int(value)
    if not 1 <= integer <= 3_600:
        raise TaskContractError("task_harbor_manifest_invalid")
    return integer


def _validate_executable(path: Path) -> None:
    _read_required(path)
    try:
        if not path.stat().st_mode & stat.S_IXUSR:
            raise TaskContractError("task_script_not_executable")
    except OSError as error:
        raise TaskContractError("task_required_file_missing") from error


def load_task(path: Path) -> BenchmarkTask:
    """Load one task only after its complete source contract validates."""
    task_dir = path.absolute()
    _validate_source_tree(task_dir)
    for relative in _REQUIRED_FILES:
        _read_required(task_dir / relative)

    manifest = _load_manifest(task_dir / "carl-task.json")
    harbor = _load_harbor(task_dir / "task.toml")

    if manifest["schema_version"] != 1:
        raise TaskContractError("task_schema_unsupported")
    track = manifest["track"]
    if track not in _TRACKS:
        raise TaskContractError("task_track_unsupported")
    capabilities_value = manifest["capabilities"]
    if not isinstance(capabilities_value, list) or any(
        not isinstance(value, str) for value in capabilities_value
    ):
        raise TaskContractError("task_capability_unsupported")
    capabilities = frozenset(capabilities_value)
    if len(capabilities) != len(capabilities_value) or not capabilities <= _CAPABILITIES:
        raise TaskContractError("task_capability_unsupported")

    fixture_relative = _relative_source_path(manifest["fixture_dir"])
    fixture_dir = task_dir.joinpath(*fixture_relative.parts)
    try:
        fixture_metadata = fixture_dir.lstat()
    except OSError as error:
        raise TaskContractError("task_fixture_missing") from error
    if not stat.S_ISDIR(fixture_metadata.st_mode) or stat.S_ISLNK(fixture_metadata.st_mode):
        raise TaskContractError("task_fixture_missing")

    workspace_dir = manifest["workspace_dir"]
    if workspace_dir != "/workspace":
        raise TaskContractError("task_workspace_invalid")

    command = manifest["verifier_command"]
    if (
        not isinstance(command, list)
        or not 2 <= len(command) <= 16
        or any(not isinstance(argument, str) or not argument for argument in command)
        or command[0] != "python3"
        or not command[1].startswith("/tests/")
    ):
        raise TaskContractError("task_command_invalid")
    verifier_relative = PurePosixPath(command[1]).relative_to("/tests")
    if ".." in verifier_relative.parts or len(verifier_relative.parts) != 1:
        raise TaskContractError("task_command_invalid")
    verifier_source = task_dir / "tests" / verifier_relative.name
    try:
        _read_required(verifier_source)
    except TaskContractError as error:
        raise TaskContractError("task_verifier_missing") from error

    agent_timeout = _positive_int(manifest["agent_timeout_sec"], maximum=3_600)
    verifier_timeout = _positive_int(manifest["verifier_timeout_sec"], maximum=3_600)
    if agent_timeout is None or verifier_timeout is None:
        raise TaskContractError("task_timeout_invalid")
    if agent_timeout != _harbor_timeout(harbor, "agent") or verifier_timeout != _harbor_timeout(
        harbor, "verifier"
    ):
        raise TaskContractError("task_timeout_mismatch")

    environment = harbor.get("environment")
    if not isinstance(environment, dict):
        raise TaskContractError("task_harbor_manifest_invalid")
    if environment.get("network_mode") != "none":
        raise TaskContractError("task_network_forbidden")
    task_table = harbor.get("task")
    if not isinstance(task_table, dict) or not isinstance(task_table.get("name"), str):
        raise TaskContractError("task_harbor_manifest_invalid")
    task_id = task_table["name"]

    public = manifest["public"]
    if not isinstance(public, bool):
        raise TaskContractError("task_public_invalid")
    if public:
        _read_required(task_dir / "solution" / "solve.sh")
        _validate_executable(task_dir / "solution" / "solve.sh")
    _validate_executable(task_dir / "tests" / "test.sh")
    _validate_executable(verifier_source)

    protected_dir = task_dir / "environment" / "protected"
    if not protected_dir.exists():
        protected_dir = None
    elif not protected_dir.is_dir() or protected_dir.is_symlink():
        raise TaskContractError("task_source_entry_unsupported")

    try:
        instruction = _read_required(task_dir / "instruction.md", maximum=65_536).decode("utf-8")
    except UnicodeError as error:
        raise TaskContractError("task_instruction_invalid") from error
    if not instruction.strip():
        raise TaskContractError("task_instruction_invalid")
    try:
        digest = sha256_tree(task_dir)
    except CanonicalizationError as error:
        mapped = (
            "task_source_entry_unsupported"
            if error.code == "tree_unsupported_entry"
            else "task_source_invalid"
        )
        raise TaskContractError(mapped) from error

    return BenchmarkTask(
        source_dir=task_dir,
        identity=TaskIdentity(task_id=task_id, digest=digest, track=track),
        instruction=instruction,
        fixture_dir=fixture_dir,
        workspace_dir=workspace_dir,
        verifier_command=tuple(command),
        verifier_source=verifier_source,
        protected_dir=protected_dir,
        agent_timeout_sec=agent_timeout,
        verifier_timeout_sec=verifier_timeout,
        capabilities=capabilities,
        public=public,
    )


def discover_tasks(root: Path) -> tuple[BenchmarkTask, ...]:
    """Discover immediate task directories and return them sorted by task ID."""
    try:
        metadata = root.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise TaskContractError("task_root_invalid")
        children = sorted(
            (
                child
                for child in root.iterdir()
                if child.name not in {".DS_Store"} and not child.name.startswith(".")
            ),
            key=lambda child: child.name.encode("utf-8"),
        )
    except TaskContractError:
        raise
    except (OSError, UnicodeError) as error:
        raise TaskContractError("task_root_invalid") from error

    tasks = [load_task(child) for child in children]
    identifiers = [task.identity.task_id for task in tasks]
    if len(identifiers) != len(set(identifiers)):
        raise TaskContractError("task_id_duplicate")
    return tuple(sorted(tasks, key=lambda task: task.identity.task_id.encode("utf-8")))
