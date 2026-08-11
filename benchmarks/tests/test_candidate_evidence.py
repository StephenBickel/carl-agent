from __future__ import annotations

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
from carl_bench.candidate_evidence import (
    CandidateEvidenceError,
    bind_paired_evidence,
    issue_review_packet,
    record_review_attestation,
)
from carl_bench.experiment import (
    EventType,
    ExperimentState,
    GraphContractError,
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


def test_bind_paired_evidence_is_disabled_before_artifact_access(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with pytest.raises(CandidateEvidenceError, match="isolated_signer_required"):
        bind_paired_evidence(
            manifest(),
            sealed_candidate(),
            {"arbitrary": "baseline"},
            {"arbitrary": "candidate"},
            attestation_key=b"not-read",
            comparison_seed=77,
            store=store,
        )

    assert tuple(store.root.iterdir()) == ()


def test_review_apis_are_disabled_before_artifact_access(tmp_path: Path) -> None:
    store = _store(tmp_path)
    selected = manifest()
    projection = reduce_events(selected, phase3_build_events())

    with pytest.raises(CandidateEvidenceError, match="isolated_signer_required"):
        issue_review_packet(selected, projection, ReviewRole.SECURITY)
    with pytest.raises(CandidateEvidenceError, match="isolated_signer_required"):
        record_review_attestation(
            selected,
            projection,
            object(),  # type: ignore[arg-type]
            reviewer_id="reviewer-disabled",
            context_id="context-disabled",
            verdict="approve",
            report=b"must not be written",
            store=store,
        )

    assert tuple(store.root.iterdir()) == ()


@pytest.mark.parametrize(
    "event_type",
    (
        EventType.PAIRED_EVIDENCE_RECORDED,
        EventType.REVIEW_PACKET_RECORDED,
        EventType.REVIEW_ATTESTED,
        EventType.DRAFT_PR_REQUESTED,
        EventType.DRAFT_PR_RECORDED,
        EventType.WORKSPACE_DISPOSED,
    ),
)
def test_isolated_authority_events_fail_before_payload_parsing(event_type: EventType) -> None:
    base = (
        *phase3_build_events(),
        candidate_event(
            attempt="prepare-disabled",
            event_type=EventType.WORKSPACE_PREPARED,
            second=1,
            payload=prepared_candidate().to_canonical_dict(),
        ),
        candidate_event(
            attempt="seal-disabled",
            event_type=EventType.CANDIDATE_SEALED,
            second=2,
            payload=sealed_candidate().to_canonical_dict(),
        ),
        transition(
            attempt="deterministic-disabled",
            source=ExperimentState.BUILDING,
            target=ExperimentState.DETERMINISTIC_VALIDATION,
            second=10,
        ),
        transition(
            attempt="paired-disabled",
            source=ExperimentState.DETERMINISTIC_VALIDATION,
            target=ExperimentState.PAIRED_EVALUATION,
            second=11,
        ),
    )
    event = candidate_event(
        attempt=f"disabled-{event_type.value}",
        event_type=event_type,
        second=12,
        payload={},
    )

    with pytest.raises(GraphContractError, match="isolated_signer_required"):
        reduce_events(manifest(), (*base, event))
