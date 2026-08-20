from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from carl_bench.cloud_harness import CloudHarnessError, evaluate_carl_pair

PARENT = "1" * 40
CANDIDATE = "2" * 40


def _write_json(path: Path, value: object) -> Path:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
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
