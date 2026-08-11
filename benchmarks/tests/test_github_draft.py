from __future__ import annotations

import json
import os
import shutil
from dataclasses import replace
from pathlib import Path

import pytest
from test_candidate_git import _check, _manager, _registry, _run
from test_experiment import manifest

from carl_bench.candidate import (
    PairedEvidence,
    ReviewAttestation,
    ReviewPacket,
)
from carl_bench.experiment import ExperimentProjection, ExperimentState
from carl_bench.github_draft import DraftPrGateway, DraftPrGatewayError


def _fixture(tmp_path: Path):
    manager, repository, parent = _manager(tmp_path)
    selected = replace(manifest(), parent_commit=parent, deterministic_checks=("pass",))
    prepared = manager.prepare(selected, stage_attempt_id="prepare-draft")
    workspace = manager.worktree_path(prepared)
    (workspace / "src" / "runtime" / "task" / "value.txt").write_text(
        "candidate\n", encoding="utf-8"
    )
    registry = _registry(
        tmp_path / "private" / "draft-checks.json",
        [_check("pass", "raise SystemExit(0)")],
    )
    candidate = manager.seal(selected, prepared, registry, report=b'{"summary":"draft fixture"}')
    comparison_ref = manager.artifact_store.put(
        evidence_kind="paired_comparison",
        media_type="application/json",
        content=b'{"decision":"improvement"}',
    )
    paired = PairedEvidence(
        schema_version=1,
        experiment_id=selected.experiment_id,
        manifest_digest=selected.digest,
        parent_commit=parent,
        candidate_commit=candidate.candidate_commit,
        baseline_scorecard_digest="1" * 64,
        candidate_scorecard_digest="2" * 64,
        comparison_artifact=comparison_ref,
        decision="improvement",
        paired_trials=3,
        pass_rate_delta_basis_points=1000,
        confidence_lower_basis_points=100,
    )
    packets: list[ReviewPacket] = []
    reviews: list[ReviewAttestation] = []
    for index, role in enumerate(
        ("correctness", "security", "maintainability", "benchmark_integrity"), start=3
    ):
        packet = ReviewPacket(
            schema_version=1,
            experiment_id=selected.experiment_id,
            manifest_digest=selected.digest,
            candidate_commit=candidate.candidate_commit,
            role=role,
            diff_digest=candidate.diff_artifact.digest,
            deterministic_evidence_digest=candidate.digest,
            paired_evidence_digest=paired.digest,
            review_contract_version="candidate-review-v1",
        )
        report = manager.artifact_store.put(
            evidence_kind="review_report",
            media_type="text/plain",
            content=f"review {role}".encode(),
        )
        packets.append(packet)
        reviews.append(
            ReviewAttestation(
                schema_version=1,
                experiment_id=selected.experiment_id,
                manifest_digest=selected.digest,
                candidate_commit=candidate.candidate_commit,
                role=role,
                reviewer_id=f"reviewer-{index}",
                context_id=f"context-{index}",
                packet_digest=packet.digest,
                verdict="approve" if index < 6 else "reject",
                report_artifact=report,
            )
        )
    projection = ExperimentProjection(
        experiment_id=selected.experiment_id,
        manifest_digest=selected.digest,
        state=ExperimentState.PAIRED_EVALUATION,
        last_sequence=0,
        applied_attempt_ids=(),
        event_digests=(),
        proposal_reviews=(),
        candidate_reviews=(),
        lease=None,
        live_spend_microdollars=0,
        prepared_candidate=prepared,
        candidate=candidate,
        paired_evidence=paired,
        review_packets=tuple(packets),
        candidate_attestations=tuple(reviews),
        draft_pull_request=None,
        draft_pull_request_request={
            "base_branch": "main",
            "candidate_commit": candidate.candidate_commit,
            "expected_remote_url": os.fspath(tmp_path / "origin.git"),
            "head_branch": candidate.branch,
            "repository": "StephenBickel/carl-agent",
        },
    )
    fake_gh = tmp_path / "private" / "fake-gh"
    shutil.copy2(Path(__file__).parent / "fakes" / "fake-gh.py", fake_gh)
    fake_gh.chmod(0o700)
    state = tmp_path / "private" / "gh-state.json"
    log = tmp_path / "private" / "gh-log.jsonl"
    gateway = DraftPrGateway(
        repository_root=repository,
        repository_slug="StephenBickel/carl-agent",
        remote="origin",
        expected_remote_url=os.fspath(tmp_path / "origin.git"),
        base_branch="main",
        gh_executable=fake_gh,
        private_root=tmp_path / "private" / "gateway",
        command_env={
            "FAKE_GH_HEAD_OID": candidate.candidate_commit,
            "FAKE_GH_LOG": os.fspath(log),
            "FAKE_GH_STATE": os.fspath(state),
        },
    )
    return gateway, selected, projection, state, log, repository


def test_gateway_pushes_exact_commit_creates_one_draft_and_reconciles_retry(
    tmp_path: Path,
) -> None:
    gateway, selected, projection, _, log, repository = _fixture(tmp_path)

    first = gateway.open_or_reconcile(selected, projection)
    second = gateway.open_or_reconcile(selected, projection)

    assert first == second
    assert first.number == 17
    assert first.is_draft is True
    assert first.candidate_commit == projection.candidate.candidate_commit
    remote_head = _run(
        "git",
        "ls-remote",
        "origin",
        f"refs/heads/{projection.candidate.branch}",
        cwd=repository,
    ).split()[0]
    assert remote_head == projection.candidate.candidate_commit
    invocations = [json.loads(line) for line in log.read_text().splitlines()]
    assert sum(arguments[:2] == ["pr", "create"] for arguments in invocations) == 1
    forbidden = {"merge", "--auto", "ready", "release", "delete", "--force", "-f"}
    assert not any(forbidden.intersection(arguments) for arguments in invocations)


@pytest.mark.parametrize(
    ("field", "replacement", "code"),
    [
        ("isDraft", False, "pull_request_not_draft"),
        ("state", "CLOSED", "pull_request_not_open"),
        ("headRefOid", "f" * 40, "pull_request_candidate_mismatch"),
        ("baseRefName", "other", "pull_request_base_mismatch"),
    ],
)
def test_gateway_blocks_conflicting_existing_pull_requests(
    tmp_path: Path, field: str, replacement: object, code: str
) -> None:
    gateway, selected, projection, state, _, _ = _fixture(tmp_path)
    pull_request = {
        "baseRefName": "main",
        "headRefName": projection.candidate.branch,
        "headRefOid": projection.candidate.candidate_commit,
        "isDraft": True,
        "number": 19,
        "state": "OPEN",
        "url": "https://github.com/StephenBickel/carl-agent/pull/19",
    }
    pull_request[field] = replacement
    state.write_text(json.dumps({"pull_request": pull_request}), encoding="utf-8")

    with pytest.raises(DraftPrGatewayError, match=code):
        gateway.open_or_reconcile(selected, projection)


def test_gateway_requires_full_local_review_quorum_and_exact_local_branch(tmp_path: Path) -> None:
    gateway, selected, projection, _, _, repository = _fixture(tmp_path)
    without_review = replace(
        projection, candidate_attestations=projection.candidate_attestations[:2]
    )
    with pytest.raises(DraftPrGatewayError, match="candidate_attestation_quorum_unsatisfied"):
        gateway.open_or_reconcile(selected, without_review)

    _run(
        "git",
        "update-ref",
        f"refs/heads/{projection.candidate.branch}",
        selected.parent_commit,
        cwd=repository,
    )
    with pytest.raises(DraftPrGatewayError, match="candidate_local_ref_mismatch"):
        gateway.open_or_reconcile(selected, projection)


def test_gateway_never_executes_repository_push_hooks(tmp_path: Path) -> None:
    gateway, selected, projection, _, _, repository = _fixture(tmp_path)
    marker = tmp_path / "push-hook-ran"
    hooks = repository / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    hook = hooks / "pre-push"
    hook.write_text(f"#!/bin/sh\nprintf ran > '{marker}'\n", encoding="utf-8")
    hook.chmod(0o700)

    gateway.open_or_reconcile(selected, projection)

    assert not marker.exists()


def test_gateway_revalidates_fetch_and_push_destinations_before_publication(
    tmp_path: Path,
) -> None:
    gateway, selected, projection, state, log, repository = _fixture(tmp_path)
    redirected = tmp_path / "redirected.git"
    _run("git", "init", "--bare", os.fspath(redirected), cwd=tmp_path)
    _run(
        "git",
        "remote",
        "set-url",
        "--push",
        "origin",
        os.fspath(redirected),
        cwd=repository,
    )

    with pytest.raises(DraftPrGatewayError, match="candidate_remote_mismatch"):
        gateway.open_or_reconcile(selected, projection)

    assert not state.exists()
    invocations = [json.loads(line) for line in log.read_text().splitlines()]
    assert not any(arguments[:2] == ["pr", "create"] for arguments in invocations)
    assert (
        _run(
            "git",
            "ls-remote",
            os.fspath(redirected),
            f"refs/heads/{projection.candidate.branch}",
            cwd=repository,
        )
        == ""
    )
