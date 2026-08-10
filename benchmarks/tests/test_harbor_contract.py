from __future__ import annotations

import stat
import tomllib
from pathlib import Path

from carl_bench.tasks import discover_tasks

TASK_ROOT = Path(__file__).parents[1] / "tasks" / "dev"
BASE_IMAGE = (
    "python:3.12.12-slim@sha256:f3fa41d74a768c2fce8016b98c191ae8c1bacd8f1152870a3f9f87d350920b7c"
)


def executable(path: Path) -> bool:
    return stat.S_ISREG(path.lstat().st_mode) and bool(path.stat().st_mode & stat.S_IXUSR)


def test_public_tasks_have_a_closed_pinned_harbor_contract() -> None:
    tasks = discover_tasks(TASK_ROOT)
    assert len(tasks) == 3
    for task in tasks:
        assert task.public
        manifest = tomllib.loads((task.source_dir / "task.toml").read_text(encoding="utf-8"))
        assert manifest["schema_version"] == "1.3"
        assert manifest["artifacts"] == []
        assert manifest["environment"] == {
            "network_mode": "none",
            "build_timeout_sec": 600.0,
            "os": "linux",
            "mcp_servers": [],
            "env": {},
        }
        assert manifest["agent"] == {"timeout_sec": 180.0}
        assert manifest["verifier"] == {
            "timeout_sec": 60.0,
            "collect": [],
            "env": {},
        }
        assert manifest["solution"] == {"env": {}}
        serialized = (task.source_dir / "task.toml").read_text(encoding="utf-8").casefold()
        assert "mount" not in serialized
        assert "secret" not in serialized
        assert "token" not in serialized


def test_dockerfiles_are_immutable_minimal_and_digest_pinned() -> None:
    for task in discover_tasks(TASK_ROOT):
        expected = [f"FROM {BASE_IMAGE}", "", "COPY fixture/ /workspace/"]
        if task.identity.track == "safety":
            expected.append("COPY protected/ /protected/")
        expected.extend(["WORKDIR /workspace", ""])
        dockerfile = task.source_dir / "environment" / "Dockerfile"
        assert dockerfile.read_text(encoding="utf-8").splitlines(keepends=False) == expected[:-1]


def test_harbor_and_local_runner_execute_the_same_verifier_source() -> None:
    for task in discover_tasks(TASK_ROOT):
        test_script = task.source_dir / "tests" / "test.sh"
        solution = task.source_dir / "solution" / "solve.sh"
        assert executable(test_script)
        assert executable(task.verifier_source)
        assert executable(solution)
        script = test_script.read_text(encoding="utf-8")
        assert "python3 /tests/verify.py --workspace /workspace" in script
        assert "/logs/verifier/result.json" in script
        assert "> /logs/verifier/reward.txt" in script
        assert task.verifier_source == task.source_dir / "tests" / "verify.py"
        assert task.verifier_command[:2] == ("python3", "/tests/verify.py")


def test_harbor_validator_is_pinned_closed_and_has_stable_docker_skip() -> None:
    script = (TASK_ROOT.parents[2] / "scripts" / "benchmark-harbor-validate.sh").read_text(
        encoding="utf-8"
    )
    assert "harbor==0.17.1" in script
    assert 'run_harbor "$task" "$oracle_job" oracle 1' in script
    assert 'run_harbor "$task" "$nop_job" nop 0' in script
    assert "--n-concurrent 1" in script
    assert "exit 77" in script
    assert "env -i" in script
    for forbidden in (
        "CARL_DATA_DIR",
        "CARL_CODEX_EXECUTABLE",
        "CODEX_HOME",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    ):
        assert forbidden not in script
