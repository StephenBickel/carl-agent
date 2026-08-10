from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from carl_bench.adapters.carl_acp import CarlAcpAdapter
from carl_bench.adapters.codex_cli import CodexCliAdapter
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


FAKE_CARL = Path(__file__).parent / "fakes" / "fake-carl-acp.py"
FAKE_CODEX = Path(__file__).parent / "fakes" / "fake-codex.py"


def carl_request(
    tmp_path: Path, mode: str, timeout_sec: int = 3
) -> tuple[CarlAcpAdapter, AgentRequest]:
    workspace = tmp_path / f"acp-{mode}"
    workspace.mkdir(mode=0o700)
    (workspace / "acp-mode.txt").write_text(mode, encoding="utf-8")
    data_dir = tmp_path / f"data-{mode}"
    data_dir.mkdir(mode=0o700)
    adapter = CarlAcpAdapter(
        executable=FAKE_CARL,
        codex_executable=Path(sys.executable).resolve(),
        data_dir=data_dir,
        model="gpt-test",
        effort="low",
    )
    return adapter, AgentRequest(
        trial_id=f"trial-{mode}",
        task_id="carl/test",
        instruction="Complete the fixture task.",
        workspace=os.fspath(workspace),
        timeout_sec=timeout_sec,
        seed=7,
    )


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


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["normal", "partial", "environment"])
async def test_carl_acp_completes_v2_without_retaining_provider_text(
    tmp_path: Path, mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "should-not-leak")
    monkeypatch.setenv("SHOULD_NOT_LEAK", "should-not-leak")
    adapter, agent_request = carl_request(tmp_path, mode)
    outcome = await adapter.run(agent_request)
    assert outcome.status is OutcomeStatus.PASSED
    assert outcome.tool_calls == 1
    argv = json.loads((Path(agent_request.workspace) / "acp-argv.json").read_text(encoding="utf-8"))
    assert argv == [
        "acp",
        "--model",
        "gpt-test",
        "--effort",
        "low",
        "--permission-mode",
        "default",
    ]
    assert "private provider output" not in repr(outcome)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "code"),
    [
        ("malformed", "agent_protocol_error"),
        ("oversized", "agent_output_overflow"),
        ("stderr-flood", "agent_output_overflow"),
        ("unexpected-request", "agent_protocol_error"),
        ("out-of-order", "agent_protocol_error"),
        ("rpc-error", "agent_protocol_error"),
        ("wrong-version", "agent_protocol_error"),
        ("early-exit", "agent_exit_nonzero"),
        ("cancelled-result", "agent_cancelled"),
    ],
)
async def test_carl_acp_classifies_protocol_and_process_failures(
    tmp_path: Path, mode: str, code: str
) -> None:
    adapter, agent_request = carl_request(tmp_path, mode)
    outcome = await adapter.run(agent_request)
    assert outcome.status is OutcomeStatus.FAILED
    assert outcome.failure_code == code


@pytest.mark.asyncio
async def test_carl_acp_timeout_reaps_descendants(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("process-group descendant assertion is Unix-only")
    adapter, agent_request = carl_request(tmp_path, "timeout", timeout_sec=1)
    outcome = await adapter.run(agent_request)
    assert outcome.failure_code == "agent_timeout"
    workspace = Path(agent_request.workspace)
    await assert_pid_gone(int((workspace / "acp-leader.pid").read_text(encoding="utf-8")))
    await assert_pid_gone(int((workspace / "acp-child.pid").read_text(encoding="utf-8")))


@pytest.mark.asyncio
async def test_carl_acp_cancellation_reaps_descendants(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("process-group descendant assertion is Unix-only")
    adapter, agent_request = carl_request(tmp_path, "cancel", timeout_sec=30)
    running = asyncio.create_task(adapter.run(agent_request))
    workspace = Path(agent_request.workspace)
    await wait_for_path(workspace / "acp-child.pid")
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    await assert_pid_gone(int((workspace / "acp-leader.pid").read_text(encoding="utf-8")))
    await assert_pid_gone(int((workspace / "acp-child.pid").read_text(encoding="utf-8")))


async def assert_pid_gone(process_id: int) -> None:
    for _ in range(100):
        try:
            os.kill(process_id, 0)
        except ProcessLookupError:
            return
        await asyncio.sleep(0.02)
    pytest.fail(f"process {process_id} survived adapter cleanup")


async def wait_for_path(path: Path) -> None:
    for _ in range(100):
        if path.exists():
            return
        await asyncio.sleep(0.02)
    pytest.fail(f"timed out waiting for {path.name}")


def codex_request(
    tmp_path: Path, mode: str, timeout_sec: int = 3
) -> tuple[CodexCliAdapter, AgentRequest]:
    workspace = tmp_path / f"codex-{mode}"
    workspace.mkdir(mode=0o700)
    (workspace / "codex-mode.txt").write_text(mode, encoding="utf-8")
    codex_home = tmp_path / f"codex-home-{mode}"
    codex_home.mkdir(mode=0o700)
    adapter = CodexCliAdapter(
        executable=FAKE_CODEX,
        codex_home=codex_home,
        model="gpt-test",
        effort="low",
    )
    return adapter, AgentRequest(
        trial_id=f"trial-{mode}",
        task_id="carl/test",
        instruction="Complete the exact fixture task.",
        workspace=os.fspath(workspace),
        timeout_sec=timeout_sec,
        seed=7,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["normal", "environment"])
async def test_codex_cli_runs_pinned_json_exec_with_closed_environment(
    tmp_path: Path, mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "should-not-leak")
    monkeypatch.setenv("SHOULD_NOT_LEAK", "should-not-leak")
    adapter, agent_request = codex_request(tmp_path, mode)
    outcome = await adapter.run(agent_request)
    assert outcome.status is OutcomeStatus.PASSED
    assert outcome.tool_calls == 1
    workspace = Path(agent_request.workspace)
    argv = json.loads((workspace / "codex-argv.json").read_text(encoding="utf-8"))
    assert argv == [
        "exec",
        "--model",
        "gpt-test",
        "-c",
        'model_reasoning_effort="low"',
        "--sandbox",
        "workspace-write",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--color",
        "never",
        "--json",
        "--skip-git-repo-check",
        "-C",
        os.fspath(workspace),
        "-",
    ]
    assert (workspace / "codex-prompt.txt").read_text(encoding="utf-8") == (
        "Complete the exact fixture task."
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "code"),
    [
        ("malformed", "agent_protocol_error"),
        ("overflow", "agent_output_overflow"),
        ("stderr-flood", "agent_output_overflow"),
        ("nonzero", "agent_exit_nonzero"),
        ("signal", "agent_exit_nonzero"),
        ("wrong-version", "agent_protocol_error"),
    ],
)
async def test_codex_cli_classifies_version_protocol_and_process_failures(
    tmp_path: Path, mode: str, code: str
) -> None:
    adapter, agent_request = codex_request(tmp_path, mode)
    outcome = await adapter.run(agent_request)
    assert outcome.status is OutcomeStatus.FAILED
    assert outcome.failure_code == code


@pytest.mark.asyncio
async def test_codex_cli_timeout_reaps_descendants(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("process-group descendant assertion is Unix-only")
    adapter, agent_request = codex_request(tmp_path, "timeout", timeout_sec=1)
    outcome = await adapter.run(agent_request)
    assert outcome.failure_code == "agent_timeout"
    workspace = Path(agent_request.workspace)
    await assert_pid_gone(int((workspace / "codex-leader.pid").read_text(encoding="utf-8")))
    await assert_pid_gone(int((workspace / "codex-child.pid").read_text(encoding="utf-8")))


@pytest.mark.asyncio
async def test_codex_cli_cancellation_reaps_descendants(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("process-group descendant assertion is Unix-only")
    adapter, agent_request = codex_request(tmp_path, "cancel", timeout_sec=30)
    running = asyncio.create_task(adapter.run(agent_request))
    workspace = Path(agent_request.workspace)
    await wait_for_path(workspace / "codex-child.pid")
    running.cancel()
    with pytest.raises(asyncio.CancelledError):
        await running
    await assert_pid_gone(int((workspace / "codex-leader.pid").read_text(encoding="utf-8")))
    await assert_pid_gone(int((workspace / "codex-child.pid").read_text(encoding="utf-8")))


@pytest.mark.asyncio
async def test_codex_cli_version_timeout_reaps_descendants(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("process-group descendant assertion is Unix-only")
    adapter, agent_request = codex_request(tmp_path, "version-timeout")
    outcome = await adapter.run(agent_request)
    assert outcome.failure_code == "agent_protocol_error"
    workspace = Path(agent_request.workspace)
    await assert_pid_gone(int((workspace / "codex-version-leader.pid").read_text(encoding="utf-8")))
    await assert_pid_gone(int((workspace / "codex-version-child.pid").read_text(encoding="utf-8")))
