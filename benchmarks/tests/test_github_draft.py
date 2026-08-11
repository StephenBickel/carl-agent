from __future__ import annotations

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
from carl_bench.experiment import ExperimentProjection, ExperimentState, evaluate_phase3
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


def test_gateway_rejects_even_fabricated_eligible_projection_before_git_or_github(
    tmp_path: Path,
) -> None:
    gateway, selected, projection, state, log, repository = _fixture(tmp_path)
    decision = evaluate_phase3(selected, projection)
    assert decision.outcome == "blocked"
    assert decision.next_action == "await_isolated_signer"
    assert decision.reasons == ("experimental_publication_disabled",)
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
    marker = tmp_path / "push-hook-ran"
    hook = repository / ".git" / "hooks" / "pre-push"
    hook.write_text(f"#!/bin/sh\nprintf ran > '{marker}'\n", encoding="utf-8")
    hook.chmod(0o700)

    with pytest.raises(DraftPrGatewayError, match="experimental_publication_disabled"):
        gateway.open_or_reconcile(selected, projection)
    with pytest.raises(DraftPrGatewayError, match="experimental_publication_disabled"):
        gateway.open_or_reconcile(selected, projection)

    assert not state.exists()
    assert not log.exists()
    assert not marker.exists()
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
