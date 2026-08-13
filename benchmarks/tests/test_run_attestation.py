from __future__ import annotations

import hashlib
import hmac
from dataclasses import replace

import pytest
from test_candidate_evidence import _scorecards
from test_experiment import manifest as experiment_manifest
from test_report import manifest as run_manifest
from test_report import trial

from carl_bench.canonical import canonical_json_bytes
from carl_bench.report import summarize_run
from carl_bench.run_attestation import (
    RunAttestationError,
    attest_run,
    verify_attested_scorecard,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))


def _attestation(*, role: str = "baseline", candidate_passes: bool = False):
    trials = tuple(
        trial(run=role, track="coding", attempt=index, passed=candidate_passes)
        for index in range(1, 4)
    )
    subject = experiment_manifest().parent_commit if role == "baseline" else "b" * 40
    manifest = replace(run_manifest(role, trials, subject_commit=subject), seed=101)
    scorecard = summarize_run(manifest, trials)
    return attest_run(
        experiment_id=experiment_manifest().experiment_id,
        role=role,
        checkout_tree_digest="c" * 40,
        manifest=manifest,
        scorecard=scorecard,
        task_identities=(
            {"digest": trials[0].task_digest, "task_id": trials[0].task_id, "track": "coding"},
        ),
        attempts=3,
        key=KEY,
    )


def _resign(value: dict, key: bytes = KEY) -> None:
    value["mac"] = hmac.new(
        key,
        b"carl-bench/run-attestation/v1\x00" + canonical_json_bytes(value["payload"]),
        hashlib.sha256,
    ).hexdigest()


def test_genuine_attested_run_reconstructs_canonical_scorecard() -> None:
    attestation = _attestation()

    verified = verify_attested_scorecard(
        attestation.to_canonical_dict(),
        key=KEY,
        expected_experiment_id=experiment_manifest().experiment_id,
        expected_role="baseline",
        expected_subject_commit=experiment_manifest().parent_commit,
    )

    assert verified.subject_commit == experiment_manifest().parent_commit
    assert verified == summarize_run(
        replace(
            run_manifest(
                "baseline",
                tuple(
                    trial(run="baseline", track="coding", attempt=index, passed=False)
                    for index in range(1, 4)
                ),
                subject_commit=experiment_manifest().parent_commit,
            ),
            seed=101,
        ),
        verified.trials,
    )


@pytest.mark.parametrize(
    "mutation",
    ("relabel_and_recompute", "role_swap", "scorecard_swap", "one_byte", "arbitrary_json"),
)
def test_attested_run_rejects_forgery_and_swaps(mutation: str) -> None:
    value = _attestation().to_canonical_dict()
    if mutation == "relabel_and_recompute":
        value["payload"]["subject_commit"] = "d" * 40
        value["payload"]["run_manifest"]["subject_commit"] = "d" * 40
        value["payload"]["scorecard"]["subject_commit"] = "d" * 40
        value["payload"]["run_manifest_digest"] = hashlib.sha256(
            canonical_json_bytes(value["payload"]["run_manifest"])
        ).hexdigest()
        value["payload"]["scorecard"]["run_digest"] = value["payload"]["run_manifest_digest"]
        value["payload"]["scorecard_digest"] = hashlib.sha256(
            canonical_json_bytes(value["payload"]["scorecard"])
        ).hexdigest()
    elif mutation == "role_swap":
        value["payload"]["role"] = "candidate"
    elif mutation == "scorecard_swap":
        _, candidate = _scorecards(candidate_passes=True)
        value["payload"]["scorecard"] = candidate.to_public_dict()
        value["payload"]["scorecard_digest"] = hashlib.sha256(
            canonical_json_bytes(value["payload"]["scorecard"])
        ).hexdigest()
    elif mutation == "one_byte":
        value["payload"]["benchmark_config"]["seed"] += 1
    else:
        value["payload"] = {"schema_version": 1}

    with pytest.raises(RunAttestationError):
        verify_attested_scorecard(
            value,
            key=KEY,
            expected_experiment_id=experiment_manifest().experiment_id,
            expected_role="baseline",
            expected_subject_commit=experiment_manifest().parent_commit,
        )


def test_attested_run_rejects_unknown_key_and_even_valid_mac_for_inconsistent_evidence() -> None:
    value = _attestation().to_canonical_dict()
    with pytest.raises(RunAttestationError, match="attestation_key_id_mismatch"):
        verify_attested_scorecard(
            value,
            key=OTHER_KEY,
            expected_experiment_id=experiment_manifest().experiment_id,
            expected_role="baseline",
            expected_subject_commit=experiment_manifest().parent_commit,
        )

    value = _attestation().to_canonical_dict()
    value["payload"]["scorecard"]["passed_trials"] = 1
    value["payload"]["scorecard"]["failed_trials"] = 2
    value["payload"]["scorecard"]["pass_rate"] = 1 / 3
    value["payload"]["scorecard_digest"] = hashlib.sha256(
        canonical_json_bytes(value["payload"]["scorecard"])
    ).hexdigest()
    _resign(value)
    with pytest.raises(RunAttestationError, match="attestation_scorecard_not_canonical"):
        verify_attested_scorecard(
            value,
            key=KEY,
            expected_experiment_id=experiment_manifest().experiment_id,
            expected_role="baseline",
            expected_subject_commit=experiment_manifest().parent_commit,
        )
