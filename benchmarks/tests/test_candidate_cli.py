from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from test_candidate_git import _check, _repository
from test_experiment import (
    manifest,
    proposal_state_events,
    role_event,
    transition,
)

from carl_bench import cli
from carl_bench.experiment import (
    EventType,
    ExperimentEvent,
    ExperimentState,
    ReviewRole,
    ReviewVerdict,
)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def _record(ledger: Path, private: Path, event: ExperimentEvent) -> None:
    source = private / f"{event.stage_attempt_id}.json"
    _write_json(source, event.to_canonical_dict())
    assert (
        cli.main(
            [
                "experiment",
                "record",
                "--ledger",
                os.fspath(ledger),
                "--event",
                os.fspath(source),
            ]
        )
        == 0
    )


def _common(
    *, ledger: Path, experiment_id: str, repository: Path, private: Path, remote_url: Path
) -> list[str]:
    return [
        "--ledger",
        os.fspath(ledger),
        "--experiment-id",
        experiment_id,
        "--repository",
        os.fspath(repository),
        "--worktree-root",
        os.fspath(private / "worktrees"),
        "--artifacts",
        os.fspath(private / "artifacts"),
        "--remote",
        "origin",
        "--expected-remote-url",
        os.fspath(remote_url),
        "--lease-owner-id",
        "director-cli",
        "--lease-stage-attempt-id",
        "lease-cli",
    ]


def test_candidate_cli_runs_prepare_seal_evidence_review_and_draft_without_claiming_holdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, origin, parent = _repository(tmp_path)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    if os.name != "nt":
        private.chmod(0o700)
    selected = replace(manifest(), parent_commit=parent, deterministic_checks=("pass",))
    ledger = private / "experiments.sqlite3"
    manifest_path = private / "manifest.json"
    _write_json(manifest_path, selected.to_canonical_dict())
    assert (
        cli.main(
            [
                "experiment",
                "init",
                "--ledger",
                os.fspath(ledger),
                "--manifest",
                os.fspath(manifest_path),
            ]
        )
        == 0
    )
    for event in (
        *proposal_state_events(),
        role_event(
            attempt="review-causal-cli",
            role=ReviewRole.CAUSAL,
            verdict=ReviewVerdict.APPROVE,
            second=4,
        ),
        role_event(
            attempt="review-product-cli",
            role=ReviewRole.PRODUCT,
            verdict=ReviewVerdict.APPROVE,
            second=5,
        ),
        ExperimentEvent.create(
            experiment_id=selected.experiment_id,
            stage_attempt_id="lease-cli",
            event_type=EventType.LEASE_ACQUIRED,
            occurred_at="2026-08-10T12:00:06Z",
            payload={"expires_at": "2026-08-10T18:00:06Z", "owner_id": "director-cli"},
        ),
        transition(
            attempt="stage-build-cli",
            source=ExperimentState.PROPOSAL_REVIEW,
            target=ExperimentState.BUILDING,
            second=7,
            lease_owner_id="director-cli",
            lease_stage_attempt_id="lease-cli",
        ),
    ):
        _record(ledger, private, event)

    common = _common(
        ledger=ledger,
        experiment_id=selected.experiment_id,
        repository=repository,
        private=private,
        remote_url=origin,
    )
    prepared_result = private / "prepared.json"
    assert (
        cli.main(
            [
                "candidate",
                "prepare",
                *common,
                "--stage-attempt-id",
                "prepare-cli",
                "--occurred-at",
                "2026-08-10T12:01:01Z",
                "--private-result",
                os.fspath(prepared_result),
            ]
        )
        == 0
    )
    prepared = json.loads(prepared_result.read_text())
    workspace = Path(prepared["worktree"])
    (workspace / "src" / "runtime" / "task" / "value.txt").write_text(
        "candidate\n", encoding="utf-8"
    )
    registry = private / "checks.json"
    _write_json(
        registry,
        {"checks": [_check("pass", "raise SystemExit(0)")], "schema_version": 1},
    )
    report = private / "report.json"
    report.write_text('{"summary":"candidate CLI fixture"}', encoding="utf-8")
    if os.name != "nt":
        report.chmod(0o600)
    sealed_result = tmp_path / "sealed-public.json"
    assert (
        cli.main(
            [
                "candidate",
                "seal",
                *common,
                "--stage-attempt-id",
                "seal-cli",
                "--occurred-at",
                "2026-08-10T12:01:02Z",
                "--check-registry",
                os.fspath(registry),
                "--report",
                os.fspath(report),
                "--public-result",
                os.fspath(sealed_result),
            ]
        )
        == 0
    )
    sealed = json.loads(sealed_result.read_text())
    assert sealed["all_checks_passed"] is True
    assert "worktree" not in sealed

    for event in (
        transition(
            attempt="stage-deterministic-cli",
            source=ExperimentState.BUILDING,
            target=ExperimentState.DETERMINISTIC_VALIDATION,
            second=10,
            lease_owner_id="director-cli",
            lease_stage_attempt_id="lease-cli",
        ),
        transition(
            attempt="stage-paired-cli",
            source=ExperimentState.DETERMINISTIC_VALIDATION,
            target=ExperimentState.PAIRED_EVALUATION,
            second=11,
            lease_owner_id="director-cli",
            lease_stage_attempt_id="lease-cli",
        ),
    ):
        _record(ledger, private, event)

    paired_result = tmp_path / "paired.json"
    assert (
        cli.main(
            [
                "candidate",
                "bind-comparison",
                *common,
                "--stage-attempt-id",
                "paired-cli",
                "--occurred-at",
                "2026-08-10T12:01:03Z",
                "--baseline-attestation",
                os.fspath(private / "missing-baseline.json"),
                "--candidate-attestation",
                os.fspath(private / "missing-candidate.json"),
                "--attestation-key",
                os.fspath(private / "missing-key"),
                "--comparison-seed",
                "77",
                "--public-result",
                os.fspath(paired_result),
            ]
        )
        == 2
    )
    assert not paired_result.exists()

    packet_result = private / "disabled-packet.json"
    assert (
        cli.main(
            [
                "candidate",
                "review-packet",
                *common,
                "--stage-attempt-id",
                "packet-disabled",
                "--occurred-at",
                "2026-08-10T12:01:04Z",
                "--role",
                "security",
                "--private-result",
                os.fspath(packet_result),
            ]
        )
        == 2
    )
    assert not packet_result.exists()

    review_result = tmp_path / "disabled-review.json"
    assert (
        cli.main(
            [
                "candidate",
                "record-review",
                *common,
                "--stage-attempt-id",
                "review-disabled",
                "--occurred-at",
                "2026-08-10T12:01:05Z",
                "--packet",
                os.fspath(private / "missing-packet.json"),
                "--reviewer-id",
                "reviewer-disabled",
                "--context-id",
                "context-disabled",
                "--verdict",
                "approve",
                "--report",
                os.fspath(private / "missing-report.txt"),
                "--public-result",
                os.fspath(review_result),
            ]
        )
        == 2
    )
    assert not review_result.exists()

    status_path = tmp_path / "candidate-status.json"
    assert (
        cli.main(
            [
                "candidate",
                "status",
                "--ledger",
                os.fspath(ledger),
                "--experiment-id",
                selected.experiment_id,
                "--public-result",
                os.fspath(status_path),
            ]
        )
        == 0
    )
    before_draft = json.loads(status_path.read_text())
    assert before_draft["state"] == "paired_evaluation"
    assert before_draft["next_action"] == "await_isolated_signer"
    assert before_draft["outcome"] == "blocked"
    assert before_draft["reasons"] == ["experimental_publication_disabled"]

    fake_gh = private / "fake-gh"
    shutil.copy2(Path(__file__).parent / "fakes" / "fake-gh.py", fake_gh)
    fake_gh.chmod(0o700)
    monkeypatch.setenv("FAKE_GH_HEAD_OID", sealed["candidate_commit"])
    monkeypatch.setenv("FAKE_GH_LOG", os.fspath(private / "gh-log.jsonl"))
    monkeypatch.setenv("FAKE_GH_STATE", os.fspath(private / "gh-state.json"))
    draft_result = tmp_path / "draft.json"
    open_args = [
        "candidate",
        "open-draft-pr",
        *common,
        "--stage-attempt-id",
        "draft-cli",
        "--occurred-at",
        "2026-08-10T12:04:01Z",
        "--repository-slug",
        "StephenBickel/carl-agent",
        "--base-branch",
        "main",
        "--gh-executable",
        os.fspath(fake_gh),
        "--gateway-private-root",
        os.fspath(private / "gateway"),
        "--gateway-env-name",
        "FAKE_GH_HEAD_OID",
        "--gateway-env-name",
        "FAKE_GH_LOG",
        "--gateway-env-name",
        "FAKE_GH_STATE",
        "--public-result",
        os.fspath(draft_result),
    ]
    assert cli.main(open_args) == 2
    assert not draft_result.exists()
    assert cli.main([*open_args, "--enable-github-draft"]) == 2
    assert not (private / "gh-log.jsonl").exists()
    assert not (private / "gh-state.json").exists()
    assert workspace.is_dir()
    branch_commit = subprocess.run(
        (
            "git",
            "-C",
            os.fspath(repository),
            "rev-parse",
            f"refs/heads/{prepared['branch']}",
        ),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert branch_commit == sealed["candidate_commit"]
    assert (
        subprocess.run(
            (
                "git",
                "-C",
                os.fspath(repository),
                "ls-remote",
                "origin",
                f"refs/heads/{prepared['branch']}",
            ),
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        == ""
    )
    serialized = status_path.read_text().casefold()
    for forbidden in ("worktree", "private", "hypothesis", "stdout", "review report"):
        assert forbidden not in serialized
