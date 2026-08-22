from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

import pytest

import carl_bench.cloud_harness as cloud_harness
from carl_bench.cloud_harness import CloudHarnessError, evaluate_carl_pair
from carl_bench.live_capability import LiveEvaluationIdentity
from carl_bench.live_evaluation_authority import (
    LiveEvaluationAuthorityError,
    ProtectedLiveEvaluationAuthority,
)

PARENT = "1" * 40
CANDIDATE = "2" * 40


def _write_json(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return path


def _subject(path: Path, *, version_ok: bool, flood: bool = False) -> Path:
    version = (
        "printf 'carl 0.1.0\\n'; exit 0" if version_ok else "printf 'unknown option\\n' >&2; exit 2"
    )
    flood_command = "yes x | head -c 2000000; exit 0" if flood else version
    path.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        'case "${1-}" in\n'
        f"  --version) {flood_command} ;;\n"
        "  --help) printf 'Usage: carl [COMMAND]\\n'; exit 0 ;;\n"
        "  memory) test \"${2-}\" = --help; printf 'Usage: carl memory\\n'; exit 0 ;;\n"
        "  *) exit 64 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _flaky_subject(path: Path) -> Path:
    path.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        'case "${1-}" in\n'
        "  --version)\n"
        '    count_file="$0.version-count"\n'
        '    count=0; test ! -f "$count_file" || count="$(cat "$count_file")"\n'
        '    count=$((count + 1)); printf "%s" "$count" > "$count_file"\n'
        '    if test "$count" -eq 1; then printf "transient failure\\n" >&2; exit 2; fi\n'
        "    printf 'carl 0.1.0\\n'; exit 0 ;;\n"
        "  --help) printf 'Usage: carl [COMMAND]\\n'; exit 0 ;;\n"
        "  memory) test \"${2-}\" = --help; printf 'Usage: carl memory\\n'; exit 0 ;;\n"
        "  *) exit 64 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return path


def _objects(root: Path, *, minimum_gain: int = 1) -> dict[str, Path]:
    root.mkdir(parents=True, exist_ok=True)
    return {
        "experiment": _write_json(
            root / "experiment.json",
            {
                "affected_probe_ids": ["version"],
                "experiment_id": "native-version-contract-v1",
                "guard_probe_ids": ["help"],
                "held_out_probe_ids": ["memory-help"],
                "objective": "Expose a stable user-visible Carl version command.",
                "schema_version": 1,
            },
        ),
        "task_set": _write_json(
            root / "task-set.json",
            {
                "adapter": "trusted-carl-cli-v1",
                "attempts": 3,
                "probes": [
                    {
                        "argv": ["--help"],
                        "expected_exit": 0,
                        "id": "help",
                        "stdout_contains": ["Usage: carl"],
                        "timeout_seconds": 5,
                    },
                    {
                        "argv": ["memory", "--help"],
                        "expected_exit": 0,
                        "id": "memory-help",
                        "stdout_contains": ["Usage: carl memory"],
                        "timeout_seconds": 5,
                    },
                    {
                        "argv": ["--version"],
                        "expected_exit": 0,
                        "id": "version",
                        "stdout_regex": "^carl [0-9]+\\.[0-9]+\\.[0-9]+\\n$",
                        "timeout_seconds": 5,
                    },
                ],
                "schema_version": 1,
            },
        ),
        "metric_pack": _write_json(
            root / "metric-pack.json",
            {
                "algorithm": "weighted-binary-probes-v1",
                "probe_weights": {"help": 1, "memory-help": 1, "version": 1},
                "schema_version": 1,
            },
        ),
        "policy": _write_json(
            root / "policy.json",
            {
                "maximum_payload_bytes": 262144,
                "maximum_probe_output_bytes": 4096,
                "minimum_gain_basis_points": minimum_gain,
                "require_affected_improvement": True,
                "require_guard_non_regression": True,
                "require_held_out_non_regression": True,
                "schema_version": 1,
                "soak_minimum_score_basis_points": 10000,
            },
        ),
    }


def _evaluate(tmp_path: Path, *, parent_ok: bool = False, candidate_ok: bool = True):
    objects = _objects(tmp_path)
    return evaluate_carl_pair(
        parent_binary=_subject(tmp_path / "parent-carl", version_ok=parent_ok),
        candidate_binary=_subject(tmp_path / "candidate-carl", version_ok=candidate_ok),
        parent_commit=PARENT,
        candidate_commit=CANDIDATE,
        experiment_path=objects["experiment"],
        task_set_path=objects["task_set"],
        metric_pack_path=objects["metric_pack"],
        policy_path=objects["policy"],
        mode="improvement",
    )


def _git_subject(path: Path, *, version_ok: bool) -> tuple[Path, str, str]:
    path.mkdir()
    binary = _subject(path / "carl", version_ok=version_ok)
    subprocess.run(("git", "init", "-q"), cwd=path, check=True)
    subprocess.run(("git", "config", "user.name", "Carl Test"), cwd=path, check=True)
    subprocess.run(
        ("git", "config", "user.email", "carl-test@example.invalid"),
        cwd=path,
        check=True,
    )
    subprocess.run(("git", "add", "carl"), cwd=path, check=True)
    subprocess.run(("git", "commit", "-q", "-m", "fixture"), cwd=path, check=True)
    commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    tree = subprocess.run(
        ("git", "rev-parse", "HEAD^{tree}"),
        cwd=path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return binary, commit, tree


def _process_exists(process_id: int) -> bool:
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    status = subprocess.run(
        ("ps", "-o", "stat=", "-p", str(process_id)),
        check=False,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return bool(status) and not status.startswith("Z")


def test_contract_hash_and_parser_share_one_held_file_description(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contract = _objects(tmp_path)["experiment"]
    original_payload = contract.read_bytes()
    replacement = tmp_path / "replacement.json"
    replacement_payload = json.dumps(
        json.loads(original_payload) | {"objective": "attacker replacement"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    replacement.write_bytes(replacement_payload)
    original_hash = cloud_harness._hash_regular_file

    def replace_after_hash(path: Path, *, code: str, maximum_bytes: int) -> str:
        digest = original_hash(path, code=code, maximum_bytes=maximum_bytes)
        os.replace(replacement, contract)
        return digest

    monkeypatch.setattr(cloud_harness, "_hash_regular_file", replace_after_hash)

    value, digest = cloud_harness._load_contract(contract, kind="experiment")

    assert value["objective"] == "Expose a stable user-visible Carl version command."
    assert digest == hashlib.sha256(original_payload).hexdigest()


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX hard-link metadata")
def test_contract_reader_rejects_linked_descriptors(tmp_path: Path) -> None:
    original = _objects(tmp_path)["experiment"]
    linked = tmp_path / "linked-experiment.json"
    os.link(original, linked)

    with pytest.raises(CloudHarnessError, match="experiment_contract_invalid"):
        cloud_harness._load_contract(linked, kind="experiment")


def test_trusted_harness_executes_exact_carl_binaries_and_owns_scoring(tmp_path: Path) -> None:
    parent = _subject(tmp_path / "parent-carl", version_ok=False)
    candidate = _subject(tmp_path / "candidate-carl", version_ok=True)
    objects = _objects(tmp_path)

    result = evaluate_carl_pair(
        parent_binary=parent,
        candidate_binary=candidate,
        parent_commit=PARENT,
        candidate_commit=CANDIDATE,
        experiment_path=objects["experiment"],
        task_set_path=objects["task_set"],
        metric_pack_path=objects["metric_pack"],
        policy_path=objects["policy"],
        mode="improvement",
    )
    payload = result.to_canonical_dict()

    assert result.contract_eligible is True
    assert result.contract_disposition == "improvement"
    assert result.eligible is False
    assert result.disposition == "insufficient_evidence"
    assert result.reasons == ("live_acp_credential_missing",)
    assert result.parent.score_basis_points == 6667
    assert result.candidate.score_basis_points == 10000
    assert result.gain_basis_points == 3333
    assert result.parent.binary_digest == hashlib.sha256(parent.read_bytes()).hexdigest()
    assert result.candidate.binary_digest == hashlib.sha256(candidate.read_bytes()).hexdigest()
    version = next(
        item for item in payload["candidate"]["observations"] if item["probe_id"] == "version"
    )
    assert version["stdout"] == "carl 0.1.0\n"
    assert version["passed"] is True
    assert payload["immutable_inputs"] == {
        kind: hashlib.sha256(path.read_bytes()).hexdigest() for kind, path in objects.items()
    }


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX subject process semantics")
def test_subject_binary_cannot_read_protected_evaluator_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Removing the explicit child environment must expose the protected test credential."""
    subject = tmp_path / "credential-probe"
    subject.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "printf '%s\\n' \"${OPENAI_API_KEY-unset}\"\n"
        "printf '%s\\n' \"${CARL_OPENAI_PROVENANCE_KEY_B64-unset}\"\n"
        "env | LC_ALL=C sort\n",
        encoding="utf-8",
    )
    subject.chmod(0o755)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-protected-secret-visible-to-candidate")
    monkeypatch.setenv("CARL_OPENAI_PROVENANCE_KEY_B64", "protected-provenance-secret")

    exit_code, stdout, stderr, timed_out, overflow = cloud_harness._bounded_process(
        subject,
        (),
        timeout_seconds=2,
        output_limit=16_384,
        subject_identity=None,
    )

    assert exit_code == 0
    assert stderr == b""
    assert timed_out is False
    assert overflow is False
    assert b"sk-protected-secret-visible-to-candidate" not in stdout
    assert b"protected-provenance-secret" not in stdout
    assert b"OPENAI_API_KEY=" not in stdout
    assert b"CARL_OPENAI_PROVENANCE_KEY_B64=" not in stdout


def test_deterministic_harness_binds_the_exact_live_pair_identity(tmp_path: Path) -> None:
    objects = _objects(tmp_path)
    immutable = {
        kind: hashlib.sha256(path.read_bytes()).hexdigest() for kind, path in objects.items()
    }
    pair_identity = LiveEvaluationIdentity.create(
        repository="StephenBickel/carl-agent",
        parent_commit=PARENT,
        parent_tree="3" * 40,
        candidate_commit=CANDIDATE,
        candidate_tree="4" * 40,
        experiment_digest=immutable["experiment"],
        workflow_revision="5" * 40,
        workflow_digest="6" * 64,
        task_set_digest=immutable["task_set"],
        metric_pack_digest=immutable["metric_pack"],
        policy_digest=immutable["policy"],
        model_policy_digest="7" * 64,
        grader_digest="8" * 64,
        environment_digest="9" * 64,
        model="gpt-5.2",
        reasoning_policy="medium/no-summary",
        tool_protocol_revision="acp-v2/bounded-openai-v1",
        task_order=("help", "memory-help", "version"),
        seeds=(41000, 41001, 41002),
        attempts=3,
    )

    result = evaluate_carl_pair(
        parent_binary=_subject(tmp_path / "parent-carl", version_ok=False),
        candidate_binary=_subject(tmp_path / "candidate-carl", version_ok=True),
        parent_commit=PARENT,
        candidate_commit=CANDIDATE,
        experiment_path=objects["experiment"],
        task_set_path=objects["task_set"],
        metric_pack_path=objects["metric_pack"],
        policy_path=objects["policy"],
        mode="improvement",
        live_evaluation_identity=pair_identity,
    )

    assert result.live_evaluation_identity == pair_identity
    assert result.to_canonical_dict()["live_evaluation_identity"] == (
        pair_identity.to_canonical_dict()
    )


def test_deterministic_receipt_requires_one_clean_checkout_lease_across_execution(
    tmp_path: Path,
) -> None:
    objects = _objects(tmp_path / "contracts")
    immutable = {
        kind: hashlib.sha256(path.read_bytes()).hexdigest() for kind, path in objects.items()
    }
    parent_binary, parent_commit, parent_tree = _git_subject(tmp_path / "parent", version_ok=False)
    candidate_binary, candidate_commit, candidate_tree = _git_subject(
        tmp_path / "candidate", version_ok=True
    )
    pair_identity = LiveEvaluationIdentity.create(
        repository="StephenBickel/carl-agent",
        parent_commit=parent_commit,
        parent_tree=parent_tree,
        candidate_commit=candidate_commit,
        candidate_tree=candidate_tree,
        experiment_digest=immutable["experiment"],
        workflow_revision="5" * 40,
        workflow_digest="6" * 64,
        task_set_digest=immutable["task_set"],
        metric_pack_digest=immutable["metric_pack"],
        policy_digest=immutable["policy"],
        model_policy_digest="7" * 64,
        grader_digest="8" * 64,
        environment_digest="9" * 64,
        model="gpt-5.2",
        reasoning_policy="medium/no-summary",
        tool_protocol_revision="acp-v2/bounded-openai-v1",
        task_order=("help", "memory-help", "version"),
        seeds=(41000, 41001, 41002),
        attempts=3,
    )

    class Archive:
        def read_exact(self, object_key: str, version_id: str) -> object:
            del object_key, version_id
            raise AssertionError("sealing must not read archive storage")

    class Gateway:
        def protected_execution_policy(self) -> dict[str, str]:
            return {}

        def verify_protected_result(self, value: object) -> bool:
            del value
            return False

    authority = ProtectedLiveEvaluationAuthority._for_testing(
        archive=Archive(),
        gateway=Gateway(),
        clock=lambda: datetime(2026, 8, 22, 12, tzinfo=UTC),
        deterministic_key=b"D" * 32,
        live_key=b"L" * 32,
        result_key=b"R" * 32,
    )
    lease = authority.begin_deterministic_run(
        identity=pair_identity,
        parent_checkout=tmp_path / "parent",
        candidate_checkout=tmp_path / "candidate",
        parent_binary=parent_binary,
        candidate_binary=candidate_binary,
    )
    result = authority.execute_deterministic_run(
        lease=lease,
        experiment_path=objects["experiment"],
        task_set_path=objects["task_set"],
        metric_pack_path=objects["metric_pack"],
        policy_path=objects["policy"],
    )

    sealed = json.loads(authority.seal_deterministic_run(result, lease=lease))

    assert sealed["payload"]["checkout_attestation_digest"] == lease.checkout_digest
    with pytest.raises(LiveEvaluationAuthorityError, match="deterministic_run_lease_consumed"):
        authority.seal_deterministic_run(result, lease=lease)

    unbound_result = evaluate_carl_pair(
        parent_binary=parent_binary,
        candidate_binary=candidate_binary,
        parent_commit=parent_commit,
        candidate_commit=candidate_commit,
        experiment_path=objects["experiment"],
        task_set_path=objects["task_set"],
        metric_pack_path=objects["metric_pack"],
        policy_path=objects["policy"],
        mode="improvement",
        live_evaluation_identity=pair_identity,
    )
    unbound_lease = authority.begin_deterministic_run(
        identity=pair_identity,
        parent_checkout=tmp_path / "parent",
        candidate_checkout=tmp_path / "candidate",
        parent_binary=parent_binary,
        candidate_binary=candidate_binary,
    )
    with pytest.raises(LiveEvaluationAuthorityError, match="deterministic_evidence_unprotected"):
        authority.seal_deterministic_run(unbound_result, lease=unbound_lease)

    replacement_lease = authority.begin_deterministic_run(
        identity=pair_identity,
        parent_checkout=tmp_path / "parent",
        candidate_checkout=tmp_path / "candidate",
        parent_binary=parent_binary,
        candidate_binary=candidate_binary,
    )
    replacement_result = authority.execute_deterministic_run(
        lease=replacement_lease,
        experiment_path=objects["experiment"],
        task_set_path=objects["task_set"],
        metric_pack_path=objects["metric_pack"],
        policy_path=objects["policy"],
    )
    candidate_original = tmp_path / "candidate-original"
    os.replace(tmp_path / "candidate", candidate_original)
    shutil.copytree(candidate_original, tmp_path / "candidate", symlinks=True)

    with pytest.raises(LiveEvaluationAuthorityError, match="deterministic_checkout_changed"):
        authority.seal_deterministic_run(replacement_result, lease=replacement_lease)


def test_protected_deterministic_authority_uses_commissioned_cgroup_for_every_attempt(
    tmp_path: Path,
) -> None:
    objects = _objects(tmp_path / "contracts")
    immutable = {
        kind: hashlib.sha256(path.read_bytes()).hexdigest() for kind, path in objects.items()
    }
    parent_binary, parent_commit, parent_tree = _git_subject(tmp_path / "parent", version_ok=False)
    candidate_binary, candidate_commit, candidate_tree = _git_subject(
        tmp_path / "candidate", version_ok=True
    )
    pair_identity = LiveEvaluationIdentity.create(
        repository="StephenBickel/carl-agent",
        parent_commit=parent_commit,
        parent_tree=parent_tree,
        candidate_commit=candidate_commit,
        candidate_tree=candidate_tree,
        experiment_digest=immutable["experiment"],
        workflow_revision="5" * 40,
        workflow_digest="6" * 64,
        task_set_digest=immutable["task_set"],
        metric_pack_digest=immutable["metric_pack"],
        policy_digest=immutable["policy"],
        model_policy_digest="7" * 64,
        grader_digest="8" * 64,
        environment_digest="9" * 64,
        model="gpt-5.2",
        reasoning_policy="medium/no-summary",
        tool_protocol_revision="acp-v2/bounded-openai-v1",
        task_order=("help", "memory-help", "version"),
        seeds=(41000, 41001, 41002),
        attempts=3,
    )

    class Scope:
        attestation_digest = hashlib.sha256(b"deterministic-scope").hexdigest()

        def attach_and_observe(
            self, process_id: int, *, expected_uid: int, expected_gid: int
        ) -> tuple[int, int]:
            assert process_id > 0
            return expected_uid, expected_gid

        def cleanup_and_verify_empty(self) -> None:
            return None

    class Isolation:
        def __init__(self) -> None:
            self.digests: list[str] = []

        def begin(self, execution_digest: str) -> Scope:
            self.digests.append(execution_digest)
            return Scope()

    class Archive:
        def read_exact(self, object_key: str, version_id: str) -> object:
            del object_key, version_id
            raise AssertionError("not used")

    class Gateway:
        def protected_execution_policy(self) -> dict[str, str]:
            return {}

        def verify_protected_result(self, value: object) -> bool:
            del value
            return False

    isolation = Isolation()
    authority = ProtectedLiveEvaluationAuthority._for_testing(
        archive=Archive(),
        gateway=Gateway(),
        clock=lambda: datetime(2026, 8, 22, 12, tzinfo=UTC),
        deterministic_key=b"D" * 32,
        live_key=b"L" * 32,
        result_key=b"R" * 32,
        worker_isolation=isolation,
    )
    lease = authority.begin_deterministic_run(
        identity=pair_identity,
        parent_checkout=tmp_path / "parent",
        candidate_checkout=tmp_path / "candidate",
        parent_binary=parent_binary,
        candidate_binary=candidate_binary,
    )

    authority.execute_deterministic_run(
        lease=lease,
        experiment_path=objects["experiment"],
        task_set_path=objects["task_set"],
        metric_pack_path=objects["metric_pack"],
        policy_path=objects["policy"],
    )

    assert len(isolation.digests) == 18
    assert len(set(isolation.digests)) == 18


def test_protected_harness_rejects_shared_or_harness_subject_uid(tmp_path: Path) -> None:
    objects = _objects(tmp_path)
    parent = _subject(tmp_path / "parent-carl", version_ok=False)
    candidate = _subject(tmp_path / "candidate-carl", version_ok=True)
    harness_identity = (os.geteuid(), os.getegid())

    with pytest.raises(CloudHarnessError, match="subject_identity_not_isolated"):
        evaluate_carl_pair(
            parent_binary=parent,
            candidate_binary=candidate,
            parent_commit=PARENT,
            candidate_commit=CANDIDATE,
            experiment_path=objects["experiment"],
            task_set_path=objects["task_set"],
            metric_pack_path=objects["metric_pack"],
            policy_path=objects["policy"],
            mode="improvement",
            parent_identity=harness_identity,
            candidate_identity=harness_identity,
        )


def test_protected_harness_rejects_same_uid_with_different_gids(tmp_path: Path) -> None:
    objects = _objects(tmp_path)
    parent = _subject(tmp_path / "parent-carl", version_ok=False)
    candidate = _subject(tmp_path / "candidate-carl", version_ok=True)
    shared_uid = os.geteuid() + 10_000

    with pytest.raises(CloudHarnessError, match="subject_identity_not_isolated"):
        evaluate_carl_pair(
            parent_binary=parent,
            candidate_binary=candidate,
            parent_commit=PARENT,
            candidate_commit=CANDIDATE,
            experiment_path=objects["experiment"],
            task_set_path=objects["task_set"],
            metric_pack_path=objects["metric_pack"],
            policy_path=objects["policy"],
            mode="improvement",
            parent_identity=(shared_uid, os.getegid() + 10_000),
            candidate_identity=(shared_uid, os.getegid() + 10_001),
        )


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX fork and process groups")
def test_bounded_process_reaps_descendants_after_normal_leader_exit(tmp_path: Path) -> None:
    pid_path = tmp_path / "descendant.pid"
    executable = tmp_path / "forking-subject"
    executable.write_text(
        "#!/usr/bin/python3\n"
        "import os, sys, time\n"
        "child = os.fork()\n"
        "if child == 0:\n"
        "    os.close(1)\n"
        "    os.close(2)\n"
        "    open(sys.argv[1], 'w', encoding='utf-8').write(str(os.getpid()))\n"
        "    time.sleep(60)\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    child_pid = -1
    try:
        result = cloud_harness._bounded_process(
            executable,
            (os.fspath(pid_path),),
            timeout_seconds=2,
            output_limit=4_096,
            subject_identity=None,
        )
        deadline = time.monotonic() + 2
        while not pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        child_pid = int(pid_path.read_text(encoding="utf-8"))
        while _process_exists(child_pid) and time.monotonic() < deadline:
            time.sleep(0.01)

        assert result[0] == 0
        assert _process_exists(child_pid) is False
    finally:
        if child_pid > 0 and _process_exists(child_pid):
            os.kill(child_pid, signal.SIGKILL)


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX setsid semantics")
def test_bounded_process_reaps_setsid_descendant_after_normal_leader_exit(
    tmp_path: Path,
) -> None:
    """Removing non-escapable isolation must leave an escaped descendant alive."""
    pid_path = tmp_path / "escaped-descendant.pid"
    executable = tmp_path / "setsid-subject"
    executable.write_text(
        "#!/usr/bin/python3\n"
        "import os, sys, time\n"
        "child = os.fork()\n"
        "if child == 0:\n"
        "    os.setsid()\n"
        "    os.close(1)\n"
        "    os.close(2)\n"
        "    open(sys.argv[1], 'w', encoding='utf-8').write(str(os.getpid()))\n"
        "    time.sleep(60)\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)

    class Scope:
        attestation_digest = hashlib.sha256(b"deterministic-cgroup").hexdigest()

        def attach_and_observe(
            self, process_id: int, *, expected_uid: int, expected_gid: int
        ) -> tuple[int, int]:
            assert process_id > 0
            return expected_uid, expected_gid

        def cleanup_and_verify_empty(self) -> None:
            deadline = time.monotonic() + 2
            while not pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            escaped = int(pid_path.read_text(encoding="utf-8"))
            with suppress(ProcessLookupError):
                os.kill(escaped, signal.SIGKILL)
            while _process_exists(escaped) and time.monotonic() < deadline:
                time.sleep(0.01)
            if _process_exists(escaped):
                raise RuntimeError("non-empty commissioned isolation")

    class Isolation:
        def __init__(self) -> None:
            self.scope = Scope()

        def begin(self, execution_digest: str) -> Scope:
            assert len(execution_digest) == 64
            return self.scope

    isolation = Isolation()
    child_pid = -1
    try:
        result = cloud_harness._bounded_process(
            executable,
            (os.fspath(pid_path),),
            timeout_seconds=2,
            output_limit=4_096,
            subject_identity=None,
            worker_isolation=isolation,
        )
        deadline = time.monotonic() + 2
        while not pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        child_pid = int(pid_path.read_text(encoding="utf-8"))
        while _process_exists(child_pid) and time.monotonic() < deadline:
            time.sleep(0.01)

        assert result[0] == 0
        assert _process_exists(child_pid) is False
    finally:
        if child_pid > 0 and _process_exists(child_pid):
            os.kill(child_pid, signal.SIGKILL)


def test_protected_bounded_process_fails_closed_without_commissioned_isolation(
    tmp_path: Path,
) -> None:
    executable = _subject(tmp_path / "subject", version_ok=True)

    with pytest.raises(CloudHarnessError, match="subject_isolation_not_commissioned"):
        cloud_harness._bounded_process(
            executable,
            ("--version",),
            timeout_seconds=2,
            output_limit=4_096,
            subject_identity=(os.geteuid(), os.getegid()),
            worker_isolation=None,
        )


def test_protected_bounded_process_cleans_scope_when_attach_fails(tmp_path: Path) -> None:
    executable = _subject(tmp_path / "subject", version_ok=True)

    class Scope:
        cleaned = False

        def attach_and_observe(self, *args: object, **kwargs: object) -> tuple[int, int]:
            del args, kwargs
            raise RuntimeError("attach failed")

        def cleanup_and_verify_empty(self) -> None:
            self.cleaned = True

    class Isolation:
        def __init__(self) -> None:
            self.scope = Scope()

        def begin(self, execution_digest: str) -> Scope:
            assert len(execution_digest) == 64
            return self.scope

    isolation = Isolation()
    with pytest.raises(CloudHarnessError, match="subject_isolation_attach_failed"):
        cloud_harness._bounded_process(
            executable,
            ("--version",),
            timeout_seconds=2,
            output_limit=4_096,
            subject_identity=None,
            worker_isolation=isolation,
        )
    assert isolation.scope.cleaned is True


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX process groups")
def test_bounded_process_reaps_subject_when_collection_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid_path = tmp_path / "subject.pid"
    executable = tmp_path / "sleeping-subject"
    executable.write_text(
        "#!/usr/bin/python3\n"
        "import os, sys, time\n"
        "open(sys.argv[1], 'w', encoding='utf-8').write(str(os.getpid()))\n"
        "time.sleep(60)\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)

    class FailingSelector:
        def register(self, *args: object) -> None:
            del args
            deadline = time.monotonic() + 1
            while not pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            raise RuntimeError("selector failed")

    monkeypatch.setattr(cloud_harness.selectors, "DefaultSelector", FailingSelector)
    process_id = -1
    try:
        with pytest.raises(CloudHarnessError, match="subject_process_collection_failed"):
            cloud_harness._bounded_process(
                executable,
                (os.fspath(pid_path),),
                timeout_seconds=2,
                output_limit=4_096,
                subject_identity=None,
            )
        deadline = time.monotonic() + 2
        while not pid_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        process_id = int(pid_path.read_text(encoding="utf-8"))
        while _process_exists(process_id) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert _process_exists(process_id) is False
    finally:
        if process_id < 0 and pid_path.exists():
            process_id = int(pid_path.read_text(encoding="utf-8"))
        if process_id > 0 and _process_exists(process_id):
            os.kill(process_id, signal.SIGKILL)


def test_equal_or_worse_candidate_is_never_eligible(tmp_path: Path) -> None:
    equal = _evaluate(tmp_path / "equal", parent_ok=True, candidate_ok=True)
    worse = _evaluate(tmp_path / "worse", parent_ok=True, candidate_ok=False)

    assert equal.contract_eligible is False
    assert equal.contract_disposition == "rejected"
    assert "minimum_gain_not_met" in equal.contract_reasons
    assert worse.contract_eligible is False
    assert worse.contract_disposition == "rejected"
    assert "affected_probe_not_improved" in worse.contract_reasons
    assert "aggregate_regression" in worse.contract_reasons
    assert equal.eligible is False
    assert worse.eligible is False
    assert equal.reasons == ("live_acp_credential_missing",)


def test_every_immutable_object_controls_the_result(tmp_path: Path) -> None:
    objects = _objects(tmp_path, minimum_gain=4000)
    parent = _subject(tmp_path / "parent-carl", version_ok=False)
    candidate = _subject(tmp_path / "candidate-carl", version_ok=True)

    result = evaluate_carl_pair(
        parent_binary=parent,
        candidate_binary=candidate,
        parent_commit=PARENT,
        candidate_commit=CANDIDATE,
        experiment_path=objects["experiment"],
        task_set_path=objects["task_set"],
        metric_pack_path=objects["metric_pack"],
        policy_path=objects["policy"],
        mode="improvement",
    )

    assert result.contract_eligible is False
    assert result.contract_disposition == "rejected"
    assert result.contract_reasons == ("minimum_gain_not_met",)
    assert result.eligible is False


def test_probe_output_and_final_payload_are_bounded(tmp_path: Path) -> None:
    objects = _objects(tmp_path)
    parent = _subject(tmp_path / "parent-carl", version_ok=False)
    candidate = _subject(tmp_path / "candidate-carl", version_ok=True, flood=True)

    result = evaluate_carl_pair(
        parent_binary=parent,
        candidate_binary=candidate,
        parent_commit=PARENT,
        candidate_commit=CANDIDATE,
        experiment_path=objects["experiment"],
        task_set_path=objects["task_set"],
        metric_pack_path=objects["metric_pack"],
        policy_path=objects["policy"],
        mode="improvement",
    )
    encoded = json.dumps(result.to_canonical_dict(), sort_keys=True, separators=(",", ":")).encode()

    assert result.contract_eligible is False
    assert "probe_output_overflow" in result.contract_reasons
    assert result.eligible is False
    assert len(encoded) <= 262144


def test_each_bounded_attempt_observation_is_retained(tmp_path: Path) -> None:
    objects = _objects(tmp_path)
    result = evaluate_carl_pair(
        parent_binary=_subject(tmp_path / "parent-carl", version_ok=False),
        candidate_binary=_flaky_subject(tmp_path / "candidate-carl"),
        parent_commit=PARENT,
        candidate_commit=CANDIDATE,
        experiment_path=objects["experiment"],
        task_set_path=objects["task_set"],
        metric_pack_path=objects["metric_pack"],
        policy_path=objects["policy"],
        mode="improvement",
    )
    version = next(
        item
        for item in result.to_canonical_dict()["candidate"]["observations"]
        if item["probe_id"] == "version"
    )

    assert version["passed"] is False
    assert version["attempt_observations"] == [
        {
            "attempt": 1,
            "exit_code": 2,
            "output_overflow": False,
            "passed": False,
            "stderr": "transient failure\n",
            "stdout": "",
            "timed_out": False,
        },
        {
            "attempt": 2,
            "exit_code": 0,
            "output_overflow": False,
            "passed": True,
            "stderr": "",
            "stdout": "carl 0.1.0\n",
            "timed_out": False,
        },
        {
            "attempt": 3,
            "exit_code": 0,
            "output_overflow": False,
            "passed": True,
            "stderr": "",
            "stdout": "carl 0.1.0\n",
            "timed_out": False,
        },
    ]


@pytest.mark.parametrize(
    ("group", "gate"),
    (
        ("guard_probe_ids", "require_guard_non_regression"),
        ("held_out_probe_ids", "require_held_out_non_regression"),
    ),
)
def test_enabled_policy_gate_rejects_an_empty_probe_group(
    tmp_path: Path, group: str, gate: str
) -> None:
    objects = _objects(tmp_path)
    experiment = json.loads(objects["experiment"].read_text(encoding="utf-8"))
    policy = json.loads(objects["policy"].read_text(encoding="utf-8"))
    experiment[group] = []
    policy[gate] = True
    _write_json(objects["experiment"], experiment)
    _write_json(objects["policy"], policy)

    with pytest.raises(CloudHarnessError, match="experiment_required_probe_group_empty"):
        evaluate_carl_pair(
            parent_binary=_subject(tmp_path / "parent-carl", version_ok=False),
            candidate_binary=_subject(tmp_path / "candidate-carl", version_ok=True),
            parent_commit=PARENT,
            candidate_commit=CANDIDATE,
            experiment_path=objects["experiment"],
            task_set_path=objects["task_set"],
            metric_pack_path=objects["metric_pack"],
            policy_path=objects["policy"],
            mode="improvement",
        )


def test_harness_rejects_non_regular_or_mutated_input_contracts(tmp_path: Path) -> None:
    objects = _objects(tmp_path)
    metric = json.loads(objects["metric_pack"].read_text(encoding="utf-8"))
    metric["probe_weights"]["not-a-probe"] = 1
    _write_json(objects["metric_pack"], metric)

    with pytest.raises(CloudHarnessError, match="metric_probe_identity_mismatch"):
        evaluate_carl_pair(
            parent_binary=_subject(tmp_path / "parent-carl", version_ok=False),
            candidate_binary=_subject(tmp_path / "candidate-carl", version_ok=True),
            parent_commit=PARENT,
            candidate_commit=CANDIDATE,
            experiment_path=objects["experiment"],
            task_set_path=objects["task_set"],
            metric_pack_path=objects["metric_pack"],
            policy_path=objects["policy"],
            mode="improvement",
        )


@pytest.mark.parametrize("kind", ("experiment", "metric_pack", "policy"))
def test_harness_rejects_smuggled_unused_contract_fields(tmp_path: Path, kind: str) -> None:
    objects = _objects(tmp_path)
    value = json.loads(objects[kind].read_text(encoding="utf-8"))
    value["unused_smuggled_input"] = {"ignored": True}
    _write_json(objects[kind], value)

    with pytest.raises(CloudHarnessError, match=f"{kind}_contract_invalid"):
        evaluate_carl_pair(
            parent_binary=_subject(tmp_path / "parent-carl", version_ok=False),
            candidate_binary=_subject(tmp_path / "candidate-carl", version_ok=True),
            parent_commit=PARENT,
            candidate_commit=CANDIDATE,
            experiment_path=objects["experiment"],
            task_set_path=objects["task_set"],
            metric_pack_path=objects["metric_pack"],
            policy_path=objects["policy"],
            mode="improvement",
        )


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable contract")
def test_harness_rejects_symlinked_subject_binary(tmp_path: Path) -> None:
    objects = _objects(tmp_path)
    parent = _subject(tmp_path / "parent-carl", version_ok=False)
    linked = tmp_path / "candidate-carl"
    linked.symlink_to(parent)

    with pytest.raises(CloudHarnessError, match="subject_binary_invalid"):
        evaluate_carl_pair(
            parent_binary=parent,
            candidate_binary=linked,
            parent_commit=PARENT,
            candidate_commit=CANDIDATE,
            experiment_path=objects["experiment"],
            task_set_path=objects["task_set"],
            metric_pack_path=objects["metric_pack"],
            policy_path=objects["policy"],
            mode="improvement",
        )
