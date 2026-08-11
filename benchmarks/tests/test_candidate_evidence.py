from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from test_experiment import (
    candidate_event,
    manifest,
    paired_evidence,
    phase3_build_events,
    prepared_candidate,
    sealed_candidate,
    transition,
)
from test_report import manifest as run_manifest
from test_report import trial

from carl_bench.artifacts import PrivateArtifactStore
from carl_bench.candidate import ReviewAttestation
from carl_bench.candidate_evidence import (
    CandidateEvidenceError,
    bind_paired_evidence,
    issue_review_packet,
    record_review_attestation,
    scorecard_from_public,
)
from carl_bench.experiment import (
    EventType,
    ExperimentState,
    ReviewRole,
    reduce_events,
)
from carl_bench.report import summarize_run
from carl_bench.run_attestation import attest_run

ATTESTATION_KEY = bytes(range(32))


def _store(tmp_path: Path) -> PrivateArtifactStore:
    repository = tmp_path / "repository"
    repository.mkdir()
    return PrivateArtifactStore(tmp_path / "private" / "artifacts", repository)


def _run_evidence(
    *,
    candidate_passes: bool,
    attempts: int = 3,
    baseline_subject: str | None = None,
    candidate_subject: str | None = None,
):
    baseline_trials = tuple(
        trial(run="baseline", track="coding", attempt=index, passed=False)
        for index in range(1, attempts + 1)
    )
    candidate_trials = tuple(
        trial(run="candidate", track="coding", attempt=index, passed=candidate_passes)
        for index in range(1, attempts + 1)
    )
    baseline_manifest = replace(
        run_manifest(
            "baseline",
            baseline_trials,
            subject_commit=baseline_subject or manifest().parent_commit,
        ),
        seed=101,
    )
    candidate_manifest = replace(
        run_manifest(
            "candidate",
            candidate_trials,
            subject_commit=candidate_subject or sealed_candidate().candidate_commit,
        ),
        seed=101,
    )
    return (
        baseline_manifest,
        summarize_run(baseline_manifest, baseline_trials),
        candidate_manifest,
        summarize_run(candidate_manifest, candidate_trials),
    )


def _scorecards(*, candidate_passes: bool, attempts: int = 3):
    _, baseline, _, candidate = _run_evidence(candidate_passes=candidate_passes, attempts=attempts)
    return baseline, candidate


def _attestations(
    *,
    candidate_passes: bool,
    attempts: int = 3,
    baseline_subject: str | None = None,
    candidate_subject: str | None = None,
):
    baseline_manifest, baseline, candidate_manifest, candidate = _run_evidence(
        candidate_passes=candidate_passes,
        attempts=attempts,
        baseline_subject=baseline_subject,
        candidate_subject=candidate_subject,
    )
    identity = (
        {
            "digest": baseline.trials[0].task_digest,
            "task_id": baseline.trials[0].task_id,
            "track": baseline.trials[0].track,
        },
    )
    return (
        attest_run(
            experiment_id=manifest().experiment_id,
            role="baseline",
            checkout_tree_digest="a" * 40,
            manifest=baseline_manifest,
            scorecard=baseline,
            task_identities=identity,
            attempts=attempts,
            key=ATTESTATION_KEY,
        ).to_canonical_dict(),
        attest_run(
            experiment_id=manifest().experiment_id,
            role="candidate",
            checkout_tree_digest="b" * 40,
            manifest=candidate_manifest,
            scorecard=candidate,
            task_identities=identity,
            attempts=attempts,
            key=ATTESTATION_KEY,
        ).to_canonical_dict(),
    )


def _paired_projection():
    prepared_event = candidate_event(
        attempt="prepare-evidence",
        event_type=EventType.WORKSPACE_PREPARED,
        second=1,
        payload=prepared_candidate().to_canonical_dict(),
    )
    sealed_event = candidate_event(
        attempt="seal-evidence",
        event_type=EventType.CANDIDATE_SEALED,
        second=2,
        payload=sealed_candidate().to_canonical_dict(),
    )
    deterministic = transition(
        attempt="deterministic-evidence",
        source=ExperimentState.BUILDING,
        target=ExperimentState.DETERMINISTIC_VALIDATION,
        second=10,
    )
    paired_transition = transition(
        attempt="paired-evidence-state",
        source=ExperimentState.DETERMINISTIC_VALIDATION,
        target=ExperimentState.PAIRED_EVALUATION,
        second=11,
    )
    return reduce_events(
        manifest(),
        (
            *phase3_build_events(),
            prepared_event,
            sealed_event,
            deterministic,
            paired_transition,
        ),
    )


def _projection_with_paired_evidence():
    projection = _paired_projection()
    event = candidate_event(
        attempt="bound-paired-evidence",
        event_type=EventType.PAIRED_EVIDENCE_RECORDED,
        second=3,
        payload=paired_evidence().to_canonical_dict(),
    )
    events = (
        *phase3_build_events(),
        candidate_event(
            attempt="prepare-evidence",
            event_type=EventType.WORKSPACE_PREPARED,
            second=1,
            payload=prepared_candidate().to_canonical_dict(),
        ),
        candidate_event(
            attempt="seal-evidence",
            event_type=EventType.CANDIDATE_SEALED,
            second=2,
            payload=sealed_candidate().to_canonical_dict(),
        ),
        transition(
            attempt="deterministic-evidence",
            source=ExperimentState.BUILDING,
            target=ExperimentState.DETERMINISTIC_VALIDATION,
            second=10,
        ),
        transition(
            attempt="paired-evidence-state",
            source=ExperimentState.DETERMINISTIC_VALIDATION,
            target=ExperimentState.PAIRED_EVALUATION,
            second=11,
        ),
        event,
    )
    assert projection.state is ExperimentState.PAIRED_EVALUATION
    return reduce_events(manifest(), events)


def test_bind_paired_evidence_recomputes_improvement_and_stores_exact_public_inputs(
    tmp_path: Path,
) -> None:
    baseline, candidate = _scorecards(candidate_passes=True)
    baseline_attestation, candidate_attestation = _attestations(candidate_passes=True)
    store = _store(tmp_path)

    evidence = bind_paired_evidence(
        manifest(),
        sealed_candidate(),
        baseline_attestation,
        candidate_attestation,
        attestation_key=ATTESTATION_KEY,
        comparison_seed=77,
        store=store,
    )

    assert evidence.candidate_commit == sealed_candidate().candidate_commit
    assert evidence.decision == "improvement"
    assert evidence.paired_trials == 3
    assert evidence.pass_rate_delta_basis_points == 10_000
    assert evidence.confidence_lower_basis_points == 10_000
    comparison = json.loads(store.read(evidence.comparison_artifact))
    assert comparison["decision"] == "improvement"
    assert comparison["comparison_seed"] == 77
    assert scorecard_from_public(baseline.to_public_dict()) == baseline


@pytest.mark.parametrize(
    ("candidate_passes", "attempts", "code"),
    [
        (False, 3, "paired_improvement_required"),
        (True, 2, "paired_improvement_required"),
    ],
)
def test_bind_paired_evidence_rejects_losers_and_insufficient_pairs(
    tmp_path: Path, candidate_passes: bool, attempts: int, code: str
) -> None:
    baseline, candidate = _attestations(candidate_passes=candidate_passes, attempts=attempts)
    with pytest.raises(CandidateEvidenceError, match=code):
        bind_paired_evidence(
            manifest(),
            sealed_candidate(),
            baseline,
            candidate,
            attestation_key=ATTESTATION_KEY,
            comparison_seed=77,
            store=_store(tmp_path),
        )


@pytest.mark.parametrize(
    ("scorecard", "code"),
    [
        ("baseline", "baseline_attestation_invalid"),
        ("candidate", "candidate_attestation_invalid"),
    ],
)
def test_bind_paired_evidence_rejects_scorecards_from_other_commits(
    tmp_path: Path, scorecard: str, code: str
) -> None:
    baseline_subject = "e" * 40 if scorecard == "baseline" else None
    candidate_subject = "e" * 40 if scorecard == "candidate" else None
    baseline, candidate = _attestations(
        candidate_passes=True,
        baseline_subject=baseline_subject,
        candidate_subject=candidate_subject,
    )

    with pytest.raises(CandidateEvidenceError, match=code):
        bind_paired_evidence(
            manifest(),
            sealed_candidate(),
            baseline,
            candidate,
            attestation_key=ATTESTATION_KEY,
            comparison_seed=77,
            store=_store(tmp_path),
        )


def test_review_packets_are_complete_role_specific_and_bound_to_projection() -> None:
    projection = _projection_with_paired_evidence()
    packets = tuple(
        issue_review_packet(manifest(), projection, role)
        for role in (
            ReviewRole.CORRECTNESS,
            ReviewRole.SECURITY,
            ReviewRole.MAINTAINABILITY,
            ReviewRole.BENCHMARK_INTEGRITY,
        )
    )

    assert len({packet.digest for packet in packets}) == 4
    assert {packet.role for packet in packets} == {
        "correctness",
        "security",
        "maintainability",
        "benchmark_integrity",
    }
    assert all(packet.candidate_commit == sealed_candidate().candidate_commit for packet in packets)
    assert all(packet.paired_evidence_digest == paired_evidence().digest for packet in packets)


def test_review_attestation_stores_private_report_and_rejects_reused_identity(
    tmp_path: Path,
) -> None:
    projection = _projection_with_paired_evidence()
    correctness = issue_review_packet(manifest(), projection, ReviewRole.CORRECTNESS)
    store = _store(tmp_path)
    attestation = record_review_attestation(
        manifest(),
        projection,
        correctness,
        reviewer_id="reviewer-1",
        context_id="context-1",
        verdict="approve",
        report=b"private correctness analysis",
        store=store,
    )

    assert isinstance(attestation, ReviewAttestation)
    assert store.read(attestation.report_artifact) == b"private correctness analysis"
    public = json.dumps(attestation.to_canonical_dict()).casefold()
    assert "private correctness analysis" not in public

    existing_event = candidate_event(
        attempt="attest-existing",
        event_type=EventType.REVIEW_PACKET_RECORDED,
        second=4,
        payload=correctness.to_canonical_dict(),
    )
    review_event = candidate_event(
        attempt="review-existing",
        event_type=EventType.REVIEW_ATTESTED,
        second=5,
        payload=attestation.to_canonical_dict(),
    )
    base_events = (
        *phase3_build_events(),
        candidate_event(
            attempt="prepare-evidence",
            event_type=EventType.WORKSPACE_PREPARED,
            second=1,
            payload=prepared_candidate().to_canonical_dict(),
        ),
        candidate_event(
            attempt="seal-evidence",
            event_type=EventType.CANDIDATE_SEALED,
            second=2,
            payload=sealed_candidate().to_canonical_dict(),
        ),
        transition(
            attempt="deterministic-evidence",
            source=ExperimentState.BUILDING,
            target=ExperimentState.DETERMINISTIC_VALIDATION,
            second=10,
        ),
        transition(
            attempt="paired-evidence-state",
            source=ExperimentState.DETERMINISTIC_VALIDATION,
            target=ExperimentState.PAIRED_EVALUATION,
            second=11,
        ),
        candidate_event(
            attempt="bound-paired-evidence",
            event_type=EventType.PAIRED_EVIDENCE_RECORDED,
            second=3,
            payload=paired_evidence().to_canonical_dict(),
        ),
        existing_event,
        review_event,
    )
    projection_with_review = reduce_events(manifest(), base_events)
    security = issue_review_packet(manifest(), projection_with_review, ReviewRole.SECURITY)
    with pytest.raises(CandidateEvidenceError, match="reviewer_identity_reused"):
        record_review_attestation(
            manifest(),
            projection_with_review,
            security,
            reviewer_id="reviewer-1",
            context_id="context-2",
            verdict="approve",
            report=b"private security analysis",
            store=store,
        )
