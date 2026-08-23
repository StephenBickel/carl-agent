from __future__ import annotations

import hashlib
import importlib
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from test_product_builder import (
    PARENT,
    _attempt,
    _candidate,
    _hypothesis,
    _limits,
    _manifest,
    _register,
    _snapshot,
)

from carl_bench.canonical import canonical_json_bytes

PROMPT = "Implement the preregistered behavior with a failing test first.\n"


def _runtime(name: str):
    return getattr(importlib.import_module("carl_bench.product_builder_runtime"), name)


def _dispatch():
    return _runtime("ValidationDispatchBinding")(
        repository="StephenBickel/carl-agent",
        workflow_file="autonomous-improvement.yml",
        workflow_revision=PARENT,
        workflow_blob_digest="a" * 64,
        experiment_digest="b" * 64,
        task_set_digest="c" * 64,
        metric_pack_digest="d" * 64,
        policy_digest="e" * 64,
    )


def _request():
    hypothesis = _hypothesis("recovery-001")
    return _runtime("BuilderRunRequest")(
        schema_version=1,
        expected_revision=7,
        snapshot=_snapshot(),
        hypotheses=(hypothesis,),
        manifest=_manifest(hypothesis),
        limits=_limits(),
        prompt_digest=hashlib.sha256(PROMPT.encode()).hexdigest(),
        validation_dispatch=_dispatch(),
    )


def _prime_command_files(root: Path) -> tuple[Path, Path, Path]:
    prompt = root / "prompt.md"
    prompt.write_text(PROMPT, encoding="utf-8")
    environment = root / "candidate-environment.json"
    environment.write_bytes(
        canonical_json_bytes(
            {
                "CI": "true",
                "HOME": str(root / "candidate-home"),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "/usr/bin:/bin",
            }
        )
    )
    result = root / "builder-terminal.json"
    sandbox = root / "state" / "sandbox-executor"
    if not sandbox.exists():
        sandbox.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
        sandbox.chmod(0o700)
    return prompt, environment, result


def _run_module(root: Path, request, *, scheduled: bool) -> subprocess.CompletedProcess[str]:
    prompt, environment, result = _prime_command_files(root)
    command = [
        sys.executable,
        "-m",
        "carl_bench.product_builder",
        "run-protected",
        "--runtime-root-for-testing",
        str(root / "state"),
        "--parent-commit",
        PARENT,
        "--candidate-environment",
        str(environment),
        "--prompt",
        str(prompt),
        "--result",
        str(result),
    ]
    if scheduled:
        command.append("--scheduled")
    else:
        command.extend(
            [
                "--request-digest",
                request.digest,
                "--immutable-inputs-digest",
                request.immutable_inputs_digest,
            ]
        )
    environment_variables = dict(os.environ)
    environment_variables.update(
        {
            "OPENAI_API_KEY": "invalid-before-network",
            "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
        }
    )
    return subprocess.run(
        command,
        cwd=Path(__file__).resolve().parents[1],
        env=environment_variables,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_exact_module_command_durably_preregisters_before_gateway_access(tmp_path: Path) -> None:
    request = _request()
    store = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    store.enqueue(request)

    completed = _run_module(tmp_path, request, scheduled=False)

    assert completed.returncode == 2
    reopened = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    registrations = reopened.registration_documents(request.digest)
    assert len(registrations) == 1
    assert registrations[0]["request_digest"] == request.digest
    assert registrations[0]["status"] == "complete"


def test_scheduled_command_claims_exact_request_without_empty_dispatch_inputs(
    tmp_path: Path,
) -> None:
    request = _request()
    store = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    store.enqueue(request)

    completed = _run_module(tmp_path, request, scheduled=True)

    assert completed.returncode == 2
    reopened = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    assert reopened.request_status(request.digest) == "claimed"
    assert len(reopened.registration_documents(request.digest)) == 1


def test_manual_parent_mismatch_stops_before_registration_or_model_access(tmp_path: Path) -> None:
    request = _request()
    store = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    store.enqueue(request)
    prompt, environment, result = _prime_command_files(tmp_path)

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "carl_bench.product_builder",
            "run-protected",
            "--runtime-root-for-testing",
            str(tmp_path / "state"),
            "--request-digest",
            request.digest,
            "--parent-commit",
            "0" * 40,
            "--immutable-inputs-digest",
            request.immutable_inputs_digest,
            "--candidate-environment",
            str(environment),
            "--prompt",
            str(prompt),
            "--result",
            str(result),
        ],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 2
    assert (
        _runtime("ProtectedBuilderStore")
        ._for_testing(tmp_path / "state")
        .registration_documents(request.digest)
        == ()
    )
    assert not result.exists()


def test_request_documents_are_canonical_and_restart_safe(tmp_path: Path) -> None:
    request = _request()
    store = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    store.enqueue(request)

    request_path = tmp_path / "state" / "requests" / f"{request.digest}.json"
    raw = request_path.read_bytes()
    assert canonical_json_bytes(json.loads(raw)) == raw
    assert (
        _runtime("ProtectedBuilderStore")
        ._for_testing(tmp_path / "state")
        .load_request(request.digest)
        == request
    )


def test_exact_module_success_persists_packet_and_writes_canonical_terminal_without_publication(
    tmp_path: Path,
) -> None:
    request = _request()
    state_root = tmp_path / "state"
    store = _runtime("ProtectedBuilderStore")._for_testing(state_root)
    store.enqueue(request)
    registration = _register()
    candidate = replace(_candidate(registration), changed_path_count=1)
    attempt = _attempt()
    attempt_value = {name: getattr(attempt, name) for name in attempt.__dataclass_fields__}
    attempt_value["changed_paths"] = list(attempt.changed_paths)
    attempt_value["tools"] = list(attempt.tools)
    observation = {
        "attempt": attempt_value,
        "candidate": candidate.to_canonical_dict(),
        "candidate_tree": "f" * 40,
        "postpatch_tree": "3" * 40,
        "prepatch_tree": "1" * 40,
        "remote_url": "https://github.com/StephenBickel/carl-agent.git",
        "repository_id": "StephenBickel/carl-agent",
        "requested_at": "2026-08-23T12:10:00Z",
        "test_command": ["cargo", "test", "restart-preserves-progress"],
        "test_output_artifact_digest": "8" * 64,
    }
    model = {
        "latency_ms": 250,
        "model": "gpt-5.2",
        "output_digest": "b" * 64,
        "output_text": '{"patch":"bounded"}',
        "response_id": "resp_builder_001",
        "status": "completed",
        "trusted_cost_microdollars": 250_000,
        "usage": {
            "cached_input_tokens": 0,
            "input_tokens": 100,
            "output_tokens": 50,
            "reasoning_output_tokens": 10,
            "total_tokens": 150,
        },
    }
    (state_root / "test-model-result.json").write_bytes(canonical_json_bytes(model))
    (state_root / "receipt.key").write_bytes(b"k" * 32)
    sandbox = state_root / "sandbox-executor"
    payload = canonical_json_bytes(observation).decode()
    sandbox.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        'test -z "${OPENAI_API_KEY+x}"\n'
        'test -z "${GITHUB_TOKEN+x}"\n'
        'test "$1" = --request\n'
        'test "$3" = --result\n'
        f"printf '%s' '{payload}' > \"$4\"\n",
        encoding="utf-8",
    )
    sandbox.chmod(0o700)

    completed = _run_module(tmp_path, request, scheduled=False)

    assert completed.returncode == 0, completed.stderr
    result_path = tmp_path / "builder-terminal.json"
    raw = result_path.read_bytes()
    assert canonical_json_bytes(json.loads(raw)) == raw
    terminal = importlib.import_module(
        "carl_bench.product_builder_effects"
    ).BuilderTerminalDocument.from_canonical_dict(json.loads(raw))
    reopened = _runtime("ProtectedBuilderStore")._for_testing(state_root)
    assert reopened.load_terminal(request.digest) == terminal
    assert (
        reopened.load_packet(terminal.candidate_packet_digest)["request_digest"] == request.digest
    )
    assert list((state_root / "effects").glob("*.response.json")) == []


def test_sandbox_executor_rejects_group_or_world_writable_binary(tmp_path: Path) -> None:
    store = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    executable = tmp_path / "state" / "sandbox-executor"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o777)

    with pytest.raises(
        importlib.import_module("carl_bench.product_builder").BuilderError,
        match="^builder_sandbox_executor_identity_invalid$",
    ):
        _runtime("ProtectedCandidateSandboxExecutor")(
            store,
            {
                "CI": "true",
                "HOME": str(tmp_path),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
        )


def test_testing_runtime_root_is_unavailable_outside_pytest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    state_root = tmp_path / "untrusted-state"

    result = importlib.import_module("carl_bench.product_builder_runtime").main(
        [
            "run-protected",
            "--runtime-root-for-testing",
            str(state_root),
            "--scheduled",
            "--parent-commit",
            PARENT,
            "--candidate-environment",
            str(tmp_path / "missing-environment.json"),
            "--prompt",
            str(tmp_path / "missing-prompt.md"),
            "--result",
            str(tmp_path / "result.json"),
        ]
    )

    assert result == 2
    assert not state_root.exists()
