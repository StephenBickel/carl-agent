from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from carl_bench.adapters.scripted import ScriptedAdapter
from carl_bench.models import AgentRequest, OutcomeStatus


def request(workspace: Path, solution: Path, timeout_sec: int = 5) -> AgentRequest:
    return AgentRequest(
        trial_id="trial-01",
        task_id="carl/test",
        instruction="Apply the requested deterministic change.",
        workspace=os.fspath(workspace),
        timeout_sec=timeout_sec,
        seed=7,
        scripted_solution=os.fspath(solution),
    )


def executable_script(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    os.chmod(path, 0o700)
    return path


@pytest.mark.asyncio
async def test_scripted_adapter_executes_a_copied_solution_in_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    solution = executable_script(
        tmp_path / "solve.sh", "#!/bin/sh\nset -eu\nprintf 'fixed\\n' > result.txt\n"
    )

    outcome = await ScriptedAdapter().run(request(workspace, solution))

    assert outcome.status is OutcomeStatus.PASSED
    assert (workspace / "result.txt").read_text(encoding="utf-8") == "fixed\n"
    assert not (workspace / ".carl-bench-solution.sh").exists()


@pytest.mark.asyncio
async def test_scripted_adapter_uses_a_closed_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHOULD_NOT_LEAK", "provider-secret")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    solution = executable_script(
        tmp_path / "solve.sh",
        '#!/bin/sh\nset -eu\nif [ -n "${SHOULD_NOT_LEAK:-}" ] || [ -n "${HOME:-}" ]; '
        "then exit 9; fi\nprintf 'clean\\n' > environment.txt\n",
    )
    outcome = await ScriptedAdapter().run(request(workspace, solution))
    assert outcome.status is OutcomeStatus.PASSED
    assert (workspace / "environment.txt").read_text(encoding="utf-8") == "clean\n"


@pytest.mark.asyncio
async def test_scripted_adapter_classifies_nonzero_timeout_and_output_overflow(
    tmp_path: Path,
) -> None:
    for name, source, expected in (
        ("nonzero", "#!/bin/sh\nexit 7\n", "agent_exit_nonzero"),
        ("timeout", "#!/bin/sh\nsleep 30\n", "agent_timeout"),
        (
            "overflow",
            "#!/bin/sh\npython3 -c 'import sys; sys.stdout.write(\"x\" * 70000)'\n",
            "agent_output_overflow",
        ),
    ):
        workspace = tmp_path / name
        workspace.mkdir()
        solution = executable_script(tmp_path / f"{name}.sh", source)
        timeout = 1 if name == "timeout" else 5
        outcome = await ScriptedAdapter().run(request(workspace, solution, timeout))
        assert outcome.status is OutcomeStatus.FAILED
        assert outcome.failure_code == expected


@pytest.mark.asyncio
async def test_scripted_adapter_rejects_missing_symlinked_and_non_executable_solutions(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    missing = await ScriptedAdapter().run(request(workspace, tmp_path / "missing.sh"))
    assert missing.failure_code == "agent_protocol_error"

    real = executable_script(tmp_path / "real.sh", "#!/bin/sh\nexit 0\n")
    link = tmp_path / "link.sh"
    link.symlink_to(real)
    linked = await ScriptedAdapter().run(request(workspace, link))
    assert linked.failure_code == "agent_protocol_error"

    os.chmod(real, 0o600)
    non_executable = await ScriptedAdapter().run(request(workspace, real))
    assert non_executable.failure_code == "agent_protocol_error"
    assert stat.S_IMODE(real.stat().st_mode) == 0o600
