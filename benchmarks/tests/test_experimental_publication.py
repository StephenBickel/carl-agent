from __future__ import annotations

import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from test_candidate_git import _repository
from test_experiment import manifest, sealed_candidate

from carl_bench import cli
from carl_bench.capability_validation import CapabilityValidationReport
from carl_bench.experimental_publication import (
    ExperimentalPublicationError,
    ExperimentalPublicationRequest,
    publish_experimental_branch,
    reconcile_experimental_publication,
)
from carl_bench.ledger import ExperimentLedger


def _report(*, eligible: bool = True) -> CapabilityValidationReport:
    return CapabilityValidationReport(
        schema_version=1,
        claim_id="claim-001",
        claim_type="capability",
        eligible=eligible,
        reasons=() if eligible else ("transfer_gain_required",),
        transfer_gain_basis_points=500 if eligible else 0,
        affected_contract_cases_improved=eligible,
        guards_non_inferior=True,
    )


def _request(
    *,
    experiment_id: str = "exp-publication-001",
    candidate_commit: str = "a" * 40,
    candidate_tree: str = "b" * 40,
    report: CapabilityValidationReport | None = None,
) -> ExperimentalPublicationRequest:
    selected = replace(manifest(), experiment_id=experiment_id)
    packet = replace(
        sealed_candidate(),
        experiment_id=experiment_id,
        manifest_digest=selected.digest,
        candidate_commit=candidate_commit,
    )
    return ExperimentalPublicationRequest(
        experiment_id=experiment_id,
        branch=f"experimental/{experiment_id}",
        candidate_packet=packet,
        candidate_tree=candidate_tree,
        capability_report=report or _report(),
    )


def test_reconciliation_pushes_only_the_exact_experimental_ref() -> None:
    request = _request()

    decision = reconcile_experimental_publication(request, remote_snapshot=None)

    assert decision.outcome == "push_branch"
    assert decision.ref == "refs/heads/experimental/exp-publication-001"
    assert decision.candidate_commit == "a" * 40
    assert decision.candidate_tree == "b" * 40
    assert decision.candidate_packet_digest == request.candidate_packet.digest


def test_reconciliation_records_an_existing_exact_experimental_branch() -> None:
    request = _request()

    decision = reconcile_experimental_publication(request, remote_snapshot="a" * 40)

    assert decision.outcome == "record_existing_exact_branch"


def test_reconciliation_blocks_an_existing_branch_with_a_different_commit() -> None:
    decision = reconcile_experimental_publication(_request(), remote_snapshot="c" * 40)

    assert decision.outcome == "blocked_branch_identity_mismatch"


def test_reconciliation_blocks_an_incomplete_candidate_packet() -> None:
    request = _request()
    incomplete = replace(request.candidate_packet, experiment_id="other-experiment")

    decision = reconcile_experimental_publication(
        replace(request, candidate_packet=incomplete), remote_snapshot=None
    )

    assert decision.outcome == "blocked_candidate_packet_incomplete"


def test_reconciliation_blocks_a_candidate_without_local_capability_eligibility() -> None:
    decision = reconcile_experimental_publication(
        _request(report=_report(eligible=False)), remote_snapshot=None
    )

    assert decision.outcome == "blocked_candidate_not_locally_eligible"


def test_publish_cli_records_one_immutable_branch_without_protected_validation(
    tmp_path: Path,
) -> None:
    repository, origin, parent = _repository(tmp_path)
    selected = replace(manifest(), experiment_id="exp-publication-001", parent_commit=parent)
    candidate_file = repository / "src" / "runtime" / "task" / "value.txt"
    candidate_file.write_text("experimental candidate\n", encoding="utf-8")
    subprocess.run(("git", "add", "--all"), cwd=repository, check=True)
    subprocess.run(
        ("git", "commit", "-m", "experimental candidate"),
        cwd=repository,
        check=True,
    )
    candidate_commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    candidate_tree = subprocess.run(
        ("git", "rev-parse", "HEAD^{tree}"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    packet = replace(
        sealed_candidate(),
        experiment_id=selected.experiment_id,
        manifest_digest=selected.digest,
        parent_commit=parent,
        candidate_commit=candidate_commit,
    )
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    ledger_path = private / "experiments.sqlite3"
    ExperimentLedger(ledger_path).register_manifest(selected)
    packet_path = private / "candidate-packet.json"
    packet_path.write_text(json.dumps(packet.to_canonical_dict()), encoding="utf-8")
    report_path = private / "capability-report.json"
    report_path.write_text(json.dumps(_report().to_canonical_dict()), encoding="utf-8")
    git_log = private / "git-log.jsonl"
    fake_git = private / "fake-git.py"
    fake_git.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, subprocess, sys\n"
        "with open(os.environ['CARL_TEST_GIT_LOG'], 'a', encoding='utf-8') as handle:\n"
        "    handle.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "result = subprocess.run([os.environ['CARL_TEST_REAL_GIT'], *sys.argv[1:]])\n"
        "raise SystemExit(result.returncode)\n",
        encoding="utf-8",
    )
    fake_git.chmod(0o700)
    result = tmp_path / "publication.json"
    previous_log = os.environ.get("CARL_TEST_GIT_LOG")
    previous_git = os.environ.get("CARL_TEST_REAL_GIT")
    os.environ["CARL_TEST_GIT_LOG"] = os.fspath(git_log)
    os.environ["CARL_TEST_REAL_GIT"] = "/usr/bin/git"
    try:
        assert (
            cli.main(
                [
                    "candidate",
                    "publish-experimental",
                    "--ledger",
                    os.fspath(ledger_path),
                    "--experiment-id",
                    selected.experiment_id,
                    "--repository",
                    os.fspath(repository),
                    "--remote",
                    "origin",
                    "--branch",
                    f"experimental/{selected.experiment_id}",
                    "--candidate-packet",
                    os.fspath(packet_path),
                    "--capability-report",
                    os.fspath(report_path),
                    "--git-executable",
                    os.fspath(fake_git),
                    "--stage-attempt-id",
                    "publish-experimental-001",
                    "--occurred-at",
                    "2026-08-10T12:02:00Z",
                    "--public-result",
                    os.fspath(result),
                ]
            )
            == 0
        )
    finally:
        if previous_log is None:
            os.environ.pop("CARL_TEST_GIT_LOG", None)
        else:
            os.environ["CARL_TEST_GIT_LOG"] = previous_log
        if previous_git is None:
            os.environ.pop("CARL_TEST_REAL_GIT", None)
        else:
            os.environ["CARL_TEST_REAL_GIT"] = previous_git

    remote_experimental = subprocess.run(
        ("git", "ls-remote", "origin", f"refs/heads/experimental/{selected.experiment_id}"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()[0]
    remote_main = subprocess.run(
        ("git", "ls-remote", "origin", "refs/heads/main"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()[0]
    commands = [json.loads(line) for line in git_log.read_text(encoding="utf-8").splitlines()]

    assert remote_experimental == candidate_commit
    assert remote_main == parent
    assert json.loads(result.read_text(encoding="utf-8"))["tree"] == candidate_tree
    assert any(
        command[-4:]
        == [
            "push",
            f"--force-with-lease=refs/heads/experimental/{selected.experiment_id}:",
            "origin",
            f"{candidate_commit}:refs/heads/experimental/{selected.experiment_id}",
        ]
        for command in commands
    )
    assert all("--force" not in command for command in commands)
    assert all("main" not in command for command in commands)
    assert ExperimentLedger(ledger_path).autonomy_projection(
        selected.experiment_id
    ).protected_validation is None


def test_create_only_push_never_fast_forwards_a_ref_created_after_the_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, origin, parent = _repository(tmp_path)
    selected = replace(manifest(), experiment_id="exp-publication-race-001", parent_commit=parent)
    candidate_file = repository / "src" / "runtime" / "task" / "value.txt"
    candidate_file.write_text("candidate after concurrent ref\n", encoding="utf-8")
    subprocess.run(("git", "add", "--all"), cwd=repository, check=True)
    subprocess.run(
        ("git", "commit", "-m", "candidate after concurrent ref"), cwd=repository, check=True
    )
    candidate_commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    candidate_tree = subprocess.run(
        ("git", "rev-parse", "HEAD^{tree}"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    request = ExperimentalPublicationRequest(
        experiment_id=selected.experiment_id,
        branch=f"experimental/{selected.experiment_id}",
        candidate_packet=replace(
            sealed_candidate(),
            experiment_id=selected.experiment_id,
            manifest_digest=selected.digest,
            parent_commit=parent,
            candidate_commit=candidate_commit,
        ),
        candidate_tree=candidate_tree,
        capability_report=_report(),
    )
    ref = f"refs/heads/experimental/{selected.experiment_id}"
    marker = tmp_path / "racer-ran"
    fake_git = tmp_path / "racing-git.py"
    fake_git.write_text(
        "#!/usr/bin/env python3\n"
        "import os, subprocess, sys\n"
        "if 'push' in sys.argv[1:] and not os.path.exists(os.environ['CARL_RACE_MARKER']):\n"
        "    open(os.environ['CARL_RACE_MARKER'], 'x').close()\n"
        "    subprocess.run([\n"
        "        os.environ['CARL_TEST_REAL_GIT'], '-C', os.environ['CARL_RACE_REPOSITORY'],\n"
        "        'push', 'origin',\n"
        "        os.environ['CARL_RACE_COMMIT'] + ':' + os.environ['CARL_RACE_REF'],\n"
        "    ], check=True)\n"
        "result = subprocess.run([os.environ['CARL_TEST_REAL_GIT'], *sys.argv[1:]])\n"
        "raise SystemExit(result.returncode)\n",
        encoding="utf-8",
    )
    fake_git.chmod(0o700)
    monkeypatch.setenv("CARL_TEST_REAL_GIT", "/usr/bin/git")
    monkeypatch.setenv("CARL_RACE_MARKER", os.fspath(marker))
    monkeypatch.setenv("CARL_RACE_REPOSITORY", os.fspath(repository))
    monkeypatch.setenv("CARL_RACE_COMMIT", parent)
    monkeypatch.setenv("CARL_RACE_REF", ref)

    with pytest.raises(ExperimentalPublicationError, match="experimental_git_failed"):
        publish_experimental_branch(
            request,
            repository=repository,
            remote="origin",
            git_executable=fake_git,
        )

    remote_commit = subprocess.run(
        ("git", "ls-remote", "origin", ref),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()[0]
    assert marker.exists()
    assert remote_commit == parent
