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
    receipt_key = root / "state" / "receipt.key"
    if not receipt_key.exists():
        receipt_key.write_bytes(b"k" * 32)
    if not sandbox.exists():
        sandbox.write_text("#!/bin/sh\nexit 2\n", encoding="utf-8")
        sandbox.chmod(0o700)
    return prompt, environment, result


def _create_candidate_repository(state_root: Path) -> tuple[str, str]:
    repository = state_root / "candidate-repository"
    repository.mkdir(exist_ok=True)
    subprocess.run(["git", "init", "-q", os.fspath(repository)], check=True)
    subprocess.run(
        ["git", "-C", os.fspath(repository), "config", "user.name", "Builder Test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", os.fspath(repository), "config", "user.email", "builder@test.invalid"],
        check=True,
    )
    (repository / "product.txt").write_text("candidate\n", encoding="utf-8")
    subprocess.run(["git", "-C", os.fspath(repository), "add", "product.txt"], check=True)
    subprocess.run(
        ["git", "-C", os.fspath(repository), "commit", "-q", "-m", "candidate"],
        check=True,
    )
    values = []
    for revision in ("HEAD", "HEAD^{tree}"):
        values.append(
            subprocess.run(
                ["git", "-C", os.fspath(repository), "rev-parse", revision],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )
    return values[0], values[1]


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


def test_request_claim_is_revision_cas_and_terminal_state_cannot_be_reclaimed(
    tmp_path: Path,
) -> None:
    request = _request()
    store = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    store.enqueue(request)
    claimed = store.claim_manual(
        request.digest,
        parent_commit=PARENT,
        immutable_inputs_digest=request.immutable_inputs_digest,
        claim_id="builder-claim-first",
        expected_revision=0,
        claimed_at="2026-08-23T12:00:00Z",
        expires_at="2026-08-23T12:15:00Z",
    )
    assert claimed.request == request
    assert claimed.revision == 1
    store.complete_request(request.digest, claim_id=claimed.claim_id, expected_revision=1)

    reopened = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    with pytest.raises(
        importlib.import_module("carl_bench.product_builder").BuilderError,
        match="^builder_request_not_claimable$",
    ):
        reopened.claim_manual(
            request.digest,
            parent_commit=PARENT,
            immutable_inputs_digest=request.immutable_inputs_digest,
            claim_id="builder-claim-replay",
            expected_revision=2,
            claimed_at="2026-08-23T12:20:00Z",
            expires_at="2026-08-23T12:35:00Z",
        )


def test_frozen_request_is_terminal_and_cannot_be_reclaimed_after_restart(
    tmp_path: Path,
) -> None:
    request = _request()
    store = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    store.enqueue(request)
    claimed = store.claim_manual(
        request.digest,
        parent_commit=PARENT,
        immutable_inputs_digest=request.immutable_inputs_digest,
        claim_id="builder-claim-to-freeze",
        expected_revision=0,
        claimed_at="2026-08-23T12:00:00Z",
        expires_at="2026-08-23T12:15:00Z",
    )
    store.freeze_request(
        request.digest,
        claim_id=claimed.claim_id,
        expected_revision=claimed.revision,
    )

    reopened = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    with pytest.raises(
        importlib.import_module("carl_bench.product_builder").BuilderError,
        match="^builder_request_not_claimable$",
    ):
        reopened.claim_manual(
            request.digest,
            parent_commit=PARENT,
            immutable_inputs_digest=request.immutable_inputs_digest,
            claim_id="builder-claim-after-freeze",
            expected_revision=claimed.revision + 1,
            claimed_at="2026-08-23T12:20:00Z",
            expires_at="2026-08-23T12:35:00Z",
        )


def test_expired_claim_recovery_is_restart_stable_and_requires_prior_identity(
    tmp_path: Path,
) -> None:
    request = _request()
    store = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    store.enqueue(request)
    first = store.claim_manual(
        request.digest,
        parent_commit=PARENT,
        immutable_inputs_digest=request.immutable_inputs_digest,
        claim_id="builder-claim-abandoned",
        expected_revision=0,
        claimed_at="2026-08-23T12:00:00Z",
        expires_at="2026-08-23T12:05:00Z",
    )
    assert first.revision == 1
    reopened = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")

    with pytest.raises(
        importlib.import_module("carl_bench.product_builder").BuilderError,
        match="^builder_claim_recovery_identity_mismatch$",
    ):
        reopened.claim_manual(
            request.digest,
            parent_commit=PARENT,
            immutable_inputs_digest=request.immutable_inputs_digest,
            claim_id="builder-claim-recovered",
            expected_revision=1,
            abandoned_claim_id="wrong-claim",
            claimed_at="2026-08-23T12:06:00Z",
            expires_at="2026-08-23T12:21:00Z",
        )

    recovered = reopened.claim_manual(
        request.digest,
        parent_commit=PARENT,
        immutable_inputs_digest=request.immutable_inputs_digest,
        claim_id="builder-claim-recovered",
        expected_revision=1,
        abandoned_claim_id="builder-claim-abandoned",
        claimed_at="2026-08-23T12:06:00Z",
        expires_at="2026-08-23T12:21:00Z",
    )
    assert recovered.revision == 2
    assert recovered.claim_id == "builder-claim-recovered"


def test_crashed_kernel_lock_owner_does_not_strand_request_claim(tmp_path: Path) -> None:
    request = _request()
    state_root = tmp_path / "state"
    store = _runtime("ProtectedBuilderStore")._for_testing(state_root)
    store.enqueue(request)
    lock_path = state_root / "claims" / f"{request.digest}.lock"
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import fcntl, os, sys; "
                "handle=open(sys.argv[1], 'a+b'); "
                "os.chmod(sys.argv[1], 0o600); "
                "fcntl.flock(handle.fileno(), fcntl.LOCK_EX); "
                "os._exit(0)"
            ),
            os.fspath(lock_path),
        ],
        check=False,
    )
    assert child.returncode == 0
    assert lock_path.exists()

    claimed = (
        _runtime("ProtectedBuilderStore")
        ._for_testing(state_root)
        .claim_manual(
            request.digest,
            parent_commit=PARENT,
            immutable_inputs_digest=request.immutable_inputs_digest,
            claim_id="builder-after-crash",
            expected_revision=0,
            claimed_at="2026-08-23T12:00:00Z",
            expires_at="2026-08-23T12:15:00Z",
        )
    )

    assert claimed.claim_id == "builder-after-crash"


def test_candidate_commit_tree_is_independently_resolved_from_protected_repository(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "candidate-repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", os.fspath(repository)], check=True)
    subprocess.run(
        ["git", "-C", os.fspath(repository), "config", "user.name", "Builder Test"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", os.fspath(repository), "config", "user.email", "builder@test.invalid"],
        check=True,
    )
    (repository / "product.txt").write_text("candidate\n", encoding="utf-8")
    subprocess.run(["git", "-C", os.fspath(repository), "add", "product.txt"], check=True)
    subprocess.run(
        ["git", "-C", os.fspath(repository), "commit", "-q", "-m", "candidate"],
        check=True,
    )
    commit = subprocess.run(
        ["git", "-C", os.fspath(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ["git", "-C", os.fspath(repository), "rev-parse", "HEAD^{tree}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    blob = subprocess.run(
        ["git", "-C", os.fspath(repository), "rev-parse", "HEAD:product.txt"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", os.fspath(repository), "tag", "-a", "candidate-tag", "-m", "tag"],
        check=True,
    )
    tag = subprocess.run(
        ["git", "-C", os.fspath(repository), "rev-parse", "candidate-tag"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    resolver = _runtime("ProtectedCandidateIdentityResolver")._for_testing(repository)

    assert resolver.resolve_tree(commit) == tree
    for non_commit in (tree, blob, tag):
        with pytest.raises(
            importlib.import_module("carl_bench.product_builder").BuilderError,
            match="^builder_candidate_commit_unresolvable$",
        ):
            resolver.resolve_tree(non_commit)
    with pytest.raises(
        importlib.import_module("carl_bench.product_builder").BuilderError,
        match="^builder_candidate_tree_mismatch$",
    ):
        resolver.verify(commit, "0" * 40)


def test_gateway_cost_uses_authenticated_pricing_receipt_not_total_tokens(
    tmp_path: Path,
) -> None:
    request = _request()
    store = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    store.enqueue(request)
    registration = _register()
    store.register(request.digest, registration)
    (tmp_path / "state" / "receipt.key").write_bytes(b"k" * 32)
    pricing = {
        "cached_input_cost_microdollars_per_million_tokens": 100_000,
        "input_cost_microdollars_per_million_tokens": 1_000_000,
        "model": "gpt-5.2",
        "output_cost_microdollars_per_million_tokens": 2_000_000,
        "policy_revision": "builder-pricing-2026-08-23",
        "schema_version": 1,
    }
    (tmp_path / "state" / "pricing-policy.json").write_bytes(canonical_json_bytes(pricing))
    model = {
        "latency_ms": 250,
        "model": "gpt-5.2",
        "output_digest": "b" * 64,
        "output_text": '{"patch":"bounded"}',
        "response_id": "resp_builder_001",
        "status": "completed",
        "usage": {
            "cached_input_tokens": 0,
            "input_tokens": 100,
            "output_tokens": 50,
            "reasoning_output_tokens": 10,
            "total_tokens": 150,
        },
    }
    (tmp_path / "state" / "test-model-result.json").write_bytes(canonical_json_bytes(model))
    gateway = _runtime("ProtectedOpenAIGateway")(store)
    from carl_bench.openai_gateway import OpenAIModelRequest

    model_request = OpenAIModelRequest(
        schema_version=1,
        repository=request.snapshot.repository,
        experiment_id=request.manifest.experiment_id,
        subject="candidate",
        task_id="product-builder-1",
        seed=7,
        attempt=1,
        input=PROMPT,
        execution_context_digest=registration.digest,
    )
    result = gateway.evaluate(model_request)
    receipt = gateway.cost_receipt(model_request.request_digest)

    assert result.usage.total_tokens == 150
    assert receipt.cost_microdollars == 200
    assert receipt.cost_microdollars != result.usage.total_tokens
    assert receipt.verify(b"k" * 32) == receipt


def test_exact_module_success_persists_packet_and_writes_canonical_terminal_without_publication(
    tmp_path: Path,
) -> None:
    request = _request()
    state_root = tmp_path / "state"
    store = _runtime("ProtectedBuilderStore")._for_testing(state_root)
    store.enqueue(request)
    registration = _register()
    attempt = replace(_attempt(), cost_microdollars=200)
    candidate_commit, candidate_tree = _create_candidate_repository(state_root)
    base_candidate = _candidate(registration)
    candidate = replace(
        base_candidate,
        candidate_commit=candidate_commit,
        changed_path_count=1,
        diff_artifact=replace(base_candidate.diff_artifact, digest=attempt.patch_digest),
    )
    attempt_value = {name: getattr(attempt, name) for name in attempt.__dataclass_fields__}
    attempt_value["changed_paths"] = list(attempt.changed_paths)
    attempt_value["tools"] = list(attempt.tools)
    observation = {
        "attempt": attempt_value,
        "candidate": candidate.to_canonical_dict(),
        "candidate_tree": candidate_tree,
        "diff_artifact_digest": attempt.patch_digest,
        "evidence_digest": None,
        "next_hypothesis": None,
        "outcome": "candidate",
        "postpatch_tree": candidate_tree,
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
    (state_root / "pricing-policy.json").write_bytes(
        canonical_json_bytes(
            {
                "cached_input_cost_microdollars_per_million_tokens": 100_000,
                "input_cost_microdollars_per_million_tokens": 1_000_000,
                "model": "gpt-5.2",
                "output_cost_microdollars_per_million_tokens": 2_000_000,
                "policy_revision": "builder-pricing-2026-08-23",
                "schema_version": 1,
            }
        )
    )
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


def test_subprocess_repair_chain_restarts_through_attempts_one_two_three(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    store = _runtime("ProtectedBuilderStore")._for_testing(state_root)
    current = _hypothesis("recovery-001", priority=20)
    next_hypothesis = _hypothesis(
        "next-product", family="next-family", priority=10, work_marker="7"
    )
    registration = _register(current)
    candidate_commit, candidate_tree = _create_candidate_repository(state_root)
    model = {
        "latency_ms": 250,
        "model": "gpt-5.2",
        "output_digest": "b" * 64,
        "output_text": '{"patch":"bounded"}',
        "response_id": "resp_builder_repair_chain",
        "status": "completed",
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
    (state_root / "pricing-policy.json").write_bytes(
        canonical_json_bytes(
            {
                "cached_input_cost_microdollars_per_million_tokens": 100_000,
                "input_cost_microdollars_per_million_tokens": 1_000_000,
                "model": "gpt-5.2",
                "output_cost_microdollars_per_million_tokens": 2_000_000,
                "policy_revision": "builder-pricing-2026-08-23",
                "schema_version": 1,
            }
        )
    )
    trees = ("1" * 40, "2" * 40, "3" * 40, candidate_tree)
    outcomes = ("repairable", "repairable", "candidate")

    for attempt_number, outcome in enumerate(outcomes, start=1):
        request = replace(
            _request(),
            attempt=attempt_number,
            hypotheses=(current, next_hypothesis),
        )
        store.enqueue(request)
        attempt = replace(
            _attempt(
                attempt=attempt_number,
                action_marker=str(5 + attempt_number),
                patch_marker=str(attempt_number),
            ),
            cost_microdollars=200,
        )
        attempt_value = {name: getattr(attempt, name) for name in attempt.__dataclass_fields__}
        attempt_value["changed_paths"] = list(attempt.changed_paths)
        attempt_value["tools"] = list(attempt.tools)
        candidate = None
        if outcome == "candidate":
            base_candidate = _candidate(registration)
            candidate = replace(
                base_candidate,
                candidate_commit=candidate_commit,
                changed_path_count=1,
                diff_artifact=replace(base_candidate.diff_artifact, digest=attempt.patch_digest),
            )
        observation = {
            "attempt": attempt_value,
            "candidate": None if candidate is None else candidate.to_canonical_dict(),
            "candidate_tree": candidate_tree if candidate is not None else None,
            "diff_artifact_digest": attempt.patch_digest,
            "evidence_digest": None if candidate is not None else str(attempt_number) * 64,
            "next_hypothesis": (
                None if candidate is not None else next_hypothesis.to_canonical_dict()
            ),
            "outcome": outcome,
            "postpatch_tree": trees[attempt_number],
            "prepatch_tree": trees[attempt_number - 1],
            "remote_url": "https://github.com/StephenBickel/carl-agent.git",
            "repository_id": "StephenBickel/carl-agent",
            "requested_at": f"2026-08-23T12:1{attempt_number}:00Z",
            "test_command": ["cargo", "test", "restart-preserves-progress"],
            "test_output_artifact_digest": "8" * 64,
        }
        payload = canonical_json_bytes(observation).decode()
        sandbox = state_root / "sandbox-executor"
        sandbox.write_text(
            f"#!/bin/sh\nset -eu\nprintf '%s' '{payload}' > \"$4\"\n",
            encoding="utf-8",
        )
        sandbox.chmod(0o700)

        completed = _run_module(tmp_path, request, scheduled=False)

        assert completed.returncode == 0, completed.stderr
        terminal = (
            _runtime("ProtectedBuilderStore")._for_testing(state_root).load_terminal(request.digest)
        )
        assert terminal.outcome == ("candidate_packet" if attempt_number == 3 else "repair_request")
        if attempt_number < 3:
            (tmp_path / "builder-terminal.json").unlink()

    packet = store.load_verified_packet(
        terminal.candidate_packet_digest, verification_key=b"k" * 32
    )
    assert tuple(item.receipt.attempt for item in packet.attempt_receipts) == (1, 2, 3)
    assert packet.candidate_tree == candidate_tree


@pytest.mark.parametrize("outcome", ["repairable", "rejected", "inconclusive"])
def test_sandbox_unsuccessful_observation_is_a_typed_production_outcome(
    outcome: str,
) -> None:
    attempt = _attempt()
    attempt_value = {name: getattr(attempt, name) for name in attempt.__dataclass_fields__}
    attempt_value["changed_paths"] = list(attempt.changed_paths)
    attempt_value["tools"] = list(attempt.tools)
    next_hypothesis = _hypothesis("distinct-next")
    next_hypothesis = replace(
        next_hypothesis,
        capability_family="distinct-family",
        work_digest="7" * 64,
    )
    observation = _runtime("SandboxObservation").from_canonical_dict(
        {
            "attempt": attempt_value,
            "candidate": None,
            "candidate_tree": None,
            "diff_artifact_digest": attempt.patch_digest,
            "evidence_digest": "8" * 64,
            "next_hypothesis": next_hypothesis.to_canonical_dict(),
            "outcome": outcome,
            "postpatch_tree": "3" * 40,
            "prepatch_tree": "1" * 40,
            "remote_url": "https://github.com/StephenBickel/carl-agent.git",
            "repository_id": "StephenBickel/carl-agent",
            "requested_at": "2026-08-23T12:10:00Z",
            "test_command": ["cargo", "test", "restart-preserves-progress"],
            "test_output_artifact_digest": "8" * 64,
        }
    )

    assert observation.outcome == outcome
    assert observation.candidate is None
    assert observation.next_hypothesis == next_hypothesis


@pytest.mark.parametrize(
    ("sandbox_outcome", "terminal_outcome"),
    [
        ("repairable", "repair_request"),
        ("rejected", "retained_learning"),
        ("inconclusive", "retained_learning"),
    ],
)
def test_exact_module_persists_every_unsuccessful_outcome_and_distinct_next_node(
    tmp_path: Path,
    sandbox_outcome: str,
    terminal_outcome: str,
) -> None:
    current = _hypothesis("recovery-001", priority=20)
    next_hypothesis = _hypothesis(
        "next-product", family="next-family", priority=10, work_marker="7"
    )
    request = replace(_request(), hypotheses=(current, next_hypothesis))
    state_root = tmp_path / "state"
    store = _runtime("ProtectedBuilderStore")._for_testing(state_root)
    store.enqueue(request)
    attempt = replace(_attempt(), cost_microdollars=200)
    attempt_value = {name: getattr(attempt, name) for name in attempt.__dataclass_fields__}
    attempt_value["changed_paths"] = list(attempt.changed_paths)
    attempt_value["tools"] = list(attempt.tools)
    observation = {
        "attempt": attempt_value,
        "candidate": None,
        "candidate_tree": None,
        "diff_artifact_digest": attempt.patch_digest,
        "evidence_digest": "8" * 64,
        "next_hypothesis": next_hypothesis.to_canonical_dict(),
        "outcome": sandbox_outcome,
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
        "response_id": "resp_builder_unsuccessful",
        "status": "completed",
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
    (state_root / "pricing-policy.json").write_bytes(
        canonical_json_bytes(
            {
                "cached_input_cost_microdollars_per_million_tokens": 100_000,
                "input_cost_microdollars_per_million_tokens": 1_000_000,
                "model": "gpt-5.2",
                "output_cost_microdollars_per_million_tokens": 2_000_000,
                "policy_revision": "builder-pricing-2026-08-23",
                "schema_version": 1,
            }
        )
    )
    sandbox = state_root / "sandbox-executor"
    payload = canonical_json_bytes(observation).decode()
    sandbox.write_text(
        f"#!/bin/sh\nset -eu\nprintf '%s' '{payload}' > \"$4\"\n",
        encoding="utf-8",
    )
    sandbox.chmod(0o700)

    completed = _run_module(tmp_path, request, scheduled=False)

    assert completed.returncode == 0, completed.stderr
    terminal = (
        _runtime("ProtectedBuilderStore")._for_testing(state_root).load_terminal(request.digest)
    )
    assert terminal.outcome == terminal_outcome
    assert terminal.next_safe_node != "report"
    if terminal_outcome == "repair_request":
        assert terminal.next_safe_node.endswith(":2")
    else:
        assert terminal.retained_learning.next_hypothesis_id == "next-product"
        assert terminal.retained_learning.next_capability_family == "next-family"


def test_restart_reloads_only_authenticated_complete_prior_attempt_sequence(
    tmp_path: Path,
) -> None:
    from test_product_builder_evidence import _receipt

    evidence = importlib.import_module("carl_bench.product_builder_evidence")
    store = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    receipt = _receipt()
    envelope = evidence.SignedAttemptReceipt.sign(receipt, b"k" * 32)
    store.persist_attempt_receipt("exp-recovery-001", envelope, verification_key=b"k" * 32)

    reopened = _runtime("ProtectedBuilderStore")._for_testing(tmp_path / "state")
    loaded = reopened.load_attempt_receipts("exp-recovery-001", verification_key=b"k" * 32)
    assert loaded == (envelope,)

    path = tmp_path / "state" / "attempt-receipts" / "exp-recovery-001-attempt-1.json"
    value = json.loads(path.read_bytes())
    value["receipt"]["postpatch_tree"] = "4" * 40
    path.write_bytes(canonical_json_bytes(value))
    with pytest.raises(
        importlib.import_module("carl_bench.product_builder").BuilderError,
        match="^builder_attempt_receipt_invalid$",
    ):
        reopened.load_attempt_receipts("exp-recovery-001", verification_key=b"k" * 32)


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
