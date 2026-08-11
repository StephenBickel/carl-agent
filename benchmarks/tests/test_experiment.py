from __future__ import annotations

from dataclasses import replace

import pytest

from carl_bench.artifacts import ArtifactRef
from carl_bench.candidate import (
    DeterministicCheckResult,
    DraftPullRequest,
    PairedEvidence,
    PreparedCandidate,
    ReviewAttestation,
    ReviewPacket,
    SealedCandidate,
)
from carl_bench.experiment import (
    BudgetLimits,
    EventType,
    ExperimentEvent,
    ExperimentKind,
    ExperimentManifest,
    ExperimentState,
    GraphContractError,
    ReviewRole,
    ReviewVerdict,
    evaluate_dry_run,
    evaluate_phase3,
    reduce_events,
)


def manifest() -> ExperimentManifest:
    return ExperimentManifest(
        schema_version=1,
        experiment_id="exp-context-recovery-001",
        parent_experiment_id=None,
        parent_commit="0123456789abcdef0123456789abcdef01234567",
        parent_generation=7,
        registered_at="2026-08-10T00:00:00Z",
        kind=ExperimentKind.RELIABILITY,
        failure_cluster="restart-loses-tool-result",
        supporting_run_ids=("run-dev-101", "run-dev-102"),
        hypothesis="Persisting verified tool results prevents duplicate effects after restart.",
        target_surface=("src/runtime/task",),
        forbidden_surface=("benchmarks", ".github", "src/promotion.rs"),
        affected_tasks=("carl/safety-restart-recovery",),
        primary_metric="pass_rate",
        guard_suites=("coding", "workflow"),
        expected_direction="increase",
        minimum_effect_basis_points=300,
        guard_noninferiority_basis_points=-200,
        deterministic_checks=("cargo-test", "restart-replay"),
        model="gpt-5.6",
        provider="openai",
        harness_version="carl-0.1.0",
        tool_version="acp-v1",
        task_version="dev-v1",
        grader_version="grader-v1",
        environment_digest="a" * 64,
        policy_version="promotion-v1",
        minimum_paired_replicas=3,
        maximum_paired_replicas=10,
        budget=BudgetLimits(
            experiment_live_microdollars=20_000_000,
            daily_live_microdollars=25_000_000,
            weekly_live_microdollars=150_000_000,
            elapsed_seconds=86_400,
            live_concurrency=4,
        ),
        known_risks=("migration-compatibility",),
        rollback_trigger="Any replay mismatch or duplicate consequential effect.",
        compatibility_impact="No public protocol change.",
    )


def transition(
    *,
    attempt: str,
    source: ExperimentState,
    target: ExperimentState,
    second: int,
) -> ExperimentEvent:
    return ExperimentEvent.create(
        experiment_id="exp-context-recovery-001",
        stage_attempt_id=attempt,
        event_type=EventType.STATE_TRANSITIONED,
        occurred_at=f"2026-08-10T12:00:{second:02d}Z",
        payload={"from_state": source.value, "to_state": target.value},
    )


def role_event(
    *, attempt: str, role: ReviewRole, verdict: ReviewVerdict, second: int
) -> ExperimentEvent:
    return ExperimentEvent.create(
        experiment_id="exp-context-recovery-001",
        stage_attempt_id=attempt,
        event_type=EventType.ROLE_RECORDED,
        occurred_at=f"2026-08-10T12:00:{second:02d}Z",
        payload={"artifact_digest": "b" * 64, "role": role.value, "verdict": verdict.value},
    )


def proposal_state_events() -> tuple[ExperimentEvent, ...]:
    return (
        transition(
            attempt="stage-baseline-1",
            source=ExperimentState.QUEUED,
            target=ExperimentState.BASELINING,
            second=1,
        ),
        transition(
            attempt="stage-diagnose-1",
            source=ExperimentState.BASELINING,
            target=ExperimentState.DIAGNOSING,
            second=2,
        ),
        transition(
            attempt="stage-proposal-1",
            source=ExperimentState.DIAGNOSING,
            target=ExperimentState.PROPOSAL_REVIEW,
            second=3,
        ),
    )


def candidate_artifact(kind: str, marker: str) -> ArtifactRef:
    return ArtifactRef(
        schema_version=1,
        digest=marker * 64,
        byte_size=7,
        media_type="application/json",
        evidence_kind=kind,
    )


def prepared_candidate() -> PreparedCandidate:
    return PreparedCandidate(
        schema_version=1,
        experiment_id=manifest().experiment_id,
        manifest_digest=manifest().digest,
        parent_commit=manifest().parent_commit,
        branch="codex/experiment-exp-context-recovery-001-0123456789",
        request_artifact=candidate_artifact("builder_request", "c"),
    )


def sealed_candidate() -> SealedCandidate:
    return SealedCandidate(
        schema_version=1,
        experiment_id=manifest().experiment_id,
        manifest_digest=manifest().digest,
        parent_commit=manifest().parent_commit,
        candidate_commit="d" * 40,
        branch=prepared_candidate().branch,
        diff_artifact=candidate_artifact("candidate_diff", "e"),
        report_artifact=candidate_artifact("implementation_report", "f"),
        changed_paths_artifact=candidate_artifact("changed_paths", "1"),
        changed_path_count=1,
        checks=(
            DeterministicCheckResult(
                check_id="cargo-test",
                status="passed",
                exit_code=0,
                elapsed_ms=100,
                output_artifact=candidate_artifact("check_output", "2"),
            ),
            DeterministicCheckResult(
                check_id="restart-replay",
                status="passed",
                exit_code=0,
                elapsed_ms=50,
                output_artifact=candidate_artifact("check_output", "3"),
            ),
        ),
    )


def paired_evidence() -> PairedEvidence:
    return PairedEvidence(
        schema_version=1,
        experiment_id=manifest().experiment_id,
        manifest_digest=manifest().digest,
        parent_commit=manifest().parent_commit,
        candidate_commit=sealed_candidate().candidate_commit,
        baseline_scorecard_digest="4" * 64,
        candidate_scorecard_digest="5" * 64,
        comparison_artifact=candidate_artifact("paired_comparison", "6"),
        decision="improvement",
        paired_trials=12,
        pass_rate_delta_basis_points=500,
        confidence_lower_basis_points=100,
    )


def phase3_build_events() -> tuple[ExperimentEvent, ...]:
    return (
        *proposal_state_events(),
        role_event(
            attempt="review-causal-phase3",
            role=ReviewRole.CAUSAL,
            verdict=ReviewVerdict.APPROVE,
            second=4,
        ),
        role_event(
            attempt="review-product-phase3",
            role=ReviewRole.PRODUCT,
            verdict=ReviewVerdict.APPROVE,
            second=5,
        ),
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="lease-phase3",
            event_type=EventType.LEASE_ACQUIRED,
            occurred_at="2026-08-10T12:00:06Z",
            payload={"expires_at": "2026-08-10T18:00:06Z", "owner_id": "director-phase3"},
        ),
        transition(
            attempt="stage-build-phase3",
            source=ExperimentState.PROPOSAL_REVIEW,
            target=ExperimentState.BUILDING,
            second=7,
        ),
    )


def candidate_event(
    *, attempt: str, event_type: EventType, second: int, payload: dict[str, object]
) -> ExperimentEvent:
    return ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id=attempt,
        event_type=event_type,
        occurred_at=f"2026-08-10T12:01:{second:02d}Z",
        payload=payload,
    )


def test_manifest_is_canonical_immutable_and_change_sensitive() -> None:
    first = manifest()
    second = manifest()

    assert first.digest == second.digest
    assert first.digest == "8a3b6650211f5fb0e619474c169364c81c1bafbc2e4e93435ed9ad5ffc5208e3"
    assert replace(first, hypothesis="A materially different prediction.").digest != first.digest
    with pytest.raises(AttributeError):
        first.hypothesis = "rewrite after observing results"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("affected_tasks", ("duplicate", "duplicate")),
        ("minimum_paired_replicas", 2),
        ("maximum_paired_replicas", 11),
        ("guard_noninferiority_basis_points", 1),
        ("target_surface", ("../outside",)),
        ("target_surface", ("src//runtime",)),
        ("target_surface", ("src/./runtime",)),
        ("target_surface", ("src/runtime/",)),
        ("forbidden_surface", ()),
        ("parent_experiment_id", "exp-context-recovery-001"),
    ],
)
def test_manifest_rejects_ambiguous_or_unbounded_contracts(field: str, value: object) -> None:
    with pytest.raises(GraphContractError):
        replace(manifest(), **{field: value})


def test_target_and_forbidden_surfaces_cannot_overlap_by_ancestry() -> None:
    with pytest.raises(GraphContractError, match="overlapping_source_surface"):
        replace(
            manifest(),
            target_surface=("src/runtime/task",),
            forbidden_surface=("src/runtime",),
        )


def test_reducer_accepts_only_declared_edges_and_replays_deterministically() -> None:
    events = (
        transition(
            attempt="stage-baseline-1",
            source=ExperimentState.QUEUED,
            target=ExperimentState.BASELINING,
            second=1,
        ),
        transition(
            attempt="stage-diagnose-1",
            source=ExperimentState.BASELINING,
            target=ExperimentState.DIAGNOSING,
            second=2,
        ),
    )

    projection = reduce_events(manifest(), events)
    replayed = reduce_events(manifest(), tuple(events))

    assert projection.state is ExperimentState.DIAGNOSING
    assert projection.last_sequence == 2
    assert projection.applied_attempt_ids == ("stage-baseline-1", "stage-diagnose-1")
    assert projection.digest == replayed.digest


def test_reducer_rejects_state_jump_stale_source_and_duplicate_attempt() -> None:
    jump = transition(
        attempt="stage-build-1",
        source=ExperimentState.QUEUED,
        target=ExperimentState.BUILDING,
        second=1,
    )
    with pytest.raises(GraphContractError, match="invalid_transition"):
        reduce_events(manifest(), (jump,))

    first = transition(
        attempt="stage-shared-1",
        source=ExperimentState.QUEUED,
        target=ExperimentState.BASELINING,
        second=1,
    )
    stale = transition(
        attempt="stage-next-1",
        source=ExperimentState.QUEUED,
        target=ExperimentState.BASELINING,
        second=2,
    )
    with pytest.raises(GraphContractError, match="stale_source_state"):
        reduce_events(manifest(), (first, stale))

    duplicate_attempt = transition(
        attempt="stage-shared-1",
        source=ExperimentState.BASELINING,
        target=ExperimentState.DIAGNOSING,
        second=2,
    )
    with pytest.raises(GraphContractError, match="duplicate_stage_attempt"):
        reduce_events(manifest(), (first, duplicate_attempt))


def test_terminal_state_cannot_be_reopened() -> None:
    rejected = transition(
        attempt="stage-reject-1",
        source=ExperimentState.QUEUED,
        target=ExperimentState.REJECTED,
        second=1,
    )
    reopened = transition(
        attempt="stage-reopen-1",
        source=ExperimentState.REJECTED,
        target=ExperimentState.BASELINING,
        second=2,
    )
    with pytest.raises(GraphContractError, match="terminal_state"):
        reduce_events(manifest(), (rejected, reopened))


def test_event_payload_is_canonical_and_cannot_be_mutated_by_the_caller() -> None:
    payload = {"from_state": "queued", "to_state": "baselining"}
    event = ExperimentEvent.create(
        experiment_id="exp-context-recovery-001",
        stage_attempt_id="stage-baseline-1",
        event_type=EventType.STATE_TRANSITIONED,
        occurred_at="2026-08-10T12:00:01Z",
        payload=payload,
    )
    payload["to_state"] = "accepted"

    assert event.payload == {"from_state": "queued", "to_state": "baselining"}
    assert len(event.digest) == 64


def test_proposal_quorum_requires_two_approvals_and_no_hard_objection() -> None:
    events = (
        *proposal_state_events(),
        role_event(
            attempt="review-causal-1",
            role=ReviewRole.CAUSAL,
            verdict=ReviewVerdict.APPROVE,
            second=4,
        ),
    )
    decision = evaluate_dry_run(manifest(), reduce_events(manifest(), events))
    assert decision.outcome == "blocked"
    assert decision.reasons == ("proposal_approvals_below_two",)
    assert decision.next_action == "collect_proposal_reviews"

    approved_events = (
        *events,
        role_event(
            attempt="review-product-1",
            role=ReviewRole.PRODUCT,
            verdict=ReviewVerdict.APPROVE,
            second=5,
        ),
    )
    approved = evaluate_dry_run(manifest(), reduce_events(manifest(), approved_events))
    assert approved.outcome == "advance"
    assert approved.next_action == "acquire_candidate_lease"
    assert approved.reasons == ()

    objected_events = (
        *approved_events,
        role_event(
            attempt="review-evaluation-1",
            role=ReviewRole.EVALUATION,
            verdict=ReviewVerdict.HARD_OBJECTION,
            second=6,
        ),
    )
    objected = evaluate_dry_run(manifest(), reduce_events(manifest(), objected_events))
    assert objected.outcome == "blocked"
    assert objected.reasons == ("proposal_hard_objection",)


def test_build_transition_requires_proposal_quorum_and_an_active_lease() -> None:
    events = proposal_state_events()
    build = transition(
        attempt="stage-build-1",
        source=ExperimentState.PROPOSAL_REVIEW,
        target=ExperimentState.BUILDING,
        second=8,
    )
    with pytest.raises(GraphContractError, match="proposal_quorum_unsatisfied"):
        reduce_events(manifest(), (*events, build))

    reviewed = (
        *events,
        role_event(
            attempt="review-causal-1",
            role=ReviewRole.CAUSAL,
            verdict=ReviewVerdict.APPROVE,
            second=4,
        ),
        role_event(
            attempt="review-product-1",
            role=ReviewRole.PRODUCT,
            verdict=ReviewVerdict.APPROVE,
            second=5,
        ),
    )
    with pytest.raises(GraphContractError, match="mutable_lease_required"):
        reduce_events(manifest(), (*reviewed, build))

    lease = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id="lease-build-1",
        event_type=EventType.LEASE_ACQUIRED,
        occurred_at="2026-08-10T12:00:06Z",
        payload={"expires_at": "2026-08-10T18:00:06Z", "owner_id": "director-1"},
    )
    projection = reduce_events(manifest(), (*reviewed, lease, build))
    assert projection.state is ExperimentState.BUILDING
    assert projection.lease is not None
    assert projection.lease.owner_id == "director-1"


def test_stale_lease_requires_explicit_not_live_reconciliation_before_release() -> None:
    lease = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id="lease-build-1",
        event_type=EventType.LEASE_ACQUIRED,
        occurred_at="2026-08-10T12:00:04Z",
        payload={"expires_at": "2026-08-10T12:00:10Z", "owner_id": "director-1"},
    )
    early_reconcile = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id="reconcile-build-1",
        event_type=EventType.LEASE_RECONCILED,
        occurred_at="2026-08-10T12:00:09Z",
        payload={"lease_stage_attempt_id": "lease-build-1", "worker_not_live": True},
    )
    with pytest.raises(GraphContractError, match="lease_not_expired"):
        reduce_events(manifest(), (*proposal_state_events(), lease, early_reconcile))

    reconciled = replace(early_reconcile, occurred_at="2026-08-10T12:00:11Z")
    release = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id="release-build-1",
        event_type=EventType.LEASE_RELEASED,
        occurred_at="2026-08-10T12:00:12Z",
        payload={"lease_stage_attempt_id": "lease-build-1"},
    )
    projection = reduce_events(manifest(), (*proposal_state_events(), lease, reconciled, release))
    assert projection.lease is None


def test_candidate_review_quorum_requires_three_approvals_and_no_hard_finding() -> None:
    proposal = (
        *proposal_state_events(),
        role_event(
            attempt="review-causal-1",
            role=ReviewRole.CAUSAL,
            verdict=ReviewVerdict.APPROVE,
            second=4,
        ),
        role_event(
            attempt="review-product-1",
            role=ReviewRole.PRODUCT,
            verdict=ReviewVerdict.APPROVE,
            second=5,
        ),
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="lease-build-1",
            event_type=EventType.LEASE_ACQUIRED,
            occurred_at="2026-08-10T12:00:06Z",
            payload={"expires_at": "2026-08-10T18:00:06Z", "owner_id": "director-1"},
        ),
        transition(
            attempt="stage-build-1",
            source=ExperimentState.PROPOSAL_REVIEW,
            target=ExperimentState.BUILDING,
            second=7,
        ),
        transition(
            attempt="stage-deterministic-1",
            source=ExperimentState.BUILDING,
            target=ExperimentState.DETERMINISTIC_VALIDATION,
            second=8,
        ),
        transition(
            attempt="stage-paired-1",
            source=ExperimentState.DETERMINISTIC_VALIDATION,
            target=ExperimentState.PAIRED_EVALUATION,
            second=9,
        ),
        transition(
            attempt="stage-holdout-1",
            source=ExperimentState.PAIRED_EVALUATION,
            target=ExperimentState.HOLDOUT_VALIDATION,
            second=10,
        ),
    )
    reviews = (
        role_event(
            attempt="candidate-correctness-1",
            role=ReviewRole.CORRECTNESS,
            verdict=ReviewVerdict.APPROVE,
            second=11,
        ),
        role_event(
            attempt="candidate-security-1",
            role=ReviewRole.SECURITY,
            verdict=ReviewVerdict.APPROVE,
            second=12,
        ),
        role_event(
            attempt="candidate-maintainability-1",
            role=ReviewRole.MAINTAINABILITY,
            verdict=ReviewVerdict.APPROVE,
            second=13,
        ),
    )
    review_complete = transition(
        attempt="stage-review-complete-1",
        source=ExperimentState.HOLDOUT_VALIDATION,
        target=ExperimentState.REVIEW_COMPLETE,
        second=14,
    )
    projection = reduce_events(manifest(), (*proposal, *reviews, review_complete))
    assert projection.state is ExperimentState.REVIEW_COMPLETE
    assert len(projection.candidate_reviews) == 3

    hard_finding = role_event(
        attempt="candidate-integrity-1",
        role=ReviewRole.BENCHMARK_INTEGRITY,
        verdict=ReviewVerdict.HARD_FINDING,
        second=14,
    )
    with pytest.raises(GraphContractError, match="candidate_quorum_unsatisfied"):
        reduce_events(manifest(), (*proposal, *reviews, hard_finding, review_complete))


def test_integer_budget_accounting_blocks_simulated_dispatch_at_the_exact_limit() -> None:
    spend = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id="spend-run-1",
        event_type=EventType.LIVE_SPEND_RECORDED,
        occurred_at="2026-08-10T12:00:01Z",
        payload={"live_microdollars": 20_000_000, "run_id": "run-live-1"},
    )
    projection = reduce_events(manifest(), (spend,))
    decision = evaluate_dry_run(manifest(), projection)

    assert projection.live_spend_microdollars == 20_000_000
    assert decision.outcome == "budget_exhausted"
    assert decision.reasons == ("experiment_live_budget_exhausted",)


def test_events_before_preregistration_and_expired_mutable_stage_progress_fail_closed() -> None:
    before_registration = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id="spend-before-registration",
        event_type=EventType.LIVE_SPEND_RECORDED,
        occurred_at="2026-08-09T23:59:59Z",
        payload={"live_microdollars": 1, "run_id": "run-too-early"},
    )
    with pytest.raises(GraphContractError, match="event_precedes_registration"):
        reduce_events(manifest(), (before_registration,))

    reviewed = (
        *proposal_state_events(),
        role_event(
            attempt="review-causal-1",
            role=ReviewRole.CAUSAL,
            verdict=ReviewVerdict.APPROVE,
            second=4,
        ),
        role_event(
            attempt="review-product-1",
            role=ReviewRole.PRODUCT,
            verdict=ReviewVerdict.APPROVE,
            second=5,
        ),
    )
    lease = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id="lease-build-1",
        event_type=EventType.LEASE_ACQUIRED,
        occurred_at="2026-08-10T12:00:06Z",
        payload={"expires_at": "2026-08-10T12:00:08Z", "owner_id": "director-1"},
    )
    build = transition(
        attempt="stage-build-1",
        source=ExperimentState.PROPOSAL_REVIEW,
        target=ExperimentState.BUILDING,
        second=7,
    )
    deterministic = transition(
        attempt="stage-deterministic-1",
        source=ExperimentState.BUILDING,
        target=ExperimentState.DETERMINISTIC_VALIDATION,
        second=9,
    )
    with pytest.raises(GraphContractError, match="mutable_lease_required"):
        reduce_events(manifest(), (*reviewed, lease, build, deterministic))

    release = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id="release-build-1",
        event_type=EventType.LEASE_RELEASED,
        occurred_at="2026-08-10T12:00:07Z",
        payload={"lease_stage_attempt_id": "lease-build-1"},
    )
    with pytest.raises(GraphContractError, match="mutable_stage_still_active"):
        reduce_events(manifest(), (*reviewed, lease, build, release))


def test_phase3_candidate_evidence_gates_build_and_cannot_claim_holdout_validation() -> None:
    building_projection = reduce_events(manifest(), phase3_build_events())
    assert evaluate_dry_run(manifest(), building_projection).next_action == "prepare_candidate"
    prepared_event = candidate_event(
        attempt="prepare-phase3",
        event_type=EventType.WORKSPACE_PREPARED,
        second=1,
        payload=prepared_candidate().to_canonical_dict(),
    )
    prepared_projection = reduce_events(manifest(), (*phase3_build_events(), prepared_event))
    assert evaluate_dry_run(manifest(), prepared_projection).next_action == "seal_candidate"
    deterministic = transition(
        attempt="stage-deterministic-phase3",
        source=ExperimentState.BUILDING,
        target=ExperimentState.DETERMINISTIC_VALIDATION,
        second=10,
    )
    with pytest.raises(GraphContractError, match="sealed_candidate_required"):
        reduce_events(manifest(), (*phase3_build_events(), prepared_event, deterministic))

    sealed_event = candidate_event(
        attempt="seal-phase3",
        event_type=EventType.CANDIDATE_SEALED,
        second=2,
        payload=sealed_candidate().to_canonical_dict(),
    )
    paired_transition = transition(
        attempt="stage-paired-phase3",
        source=ExperimentState.DETERMINISTIC_VALIDATION,
        target=ExperimentState.PAIRED_EVALUATION,
        second=11,
    )
    events = (
        *phase3_build_events(),
        prepared_event,
        sealed_event,
        deterministic,
        paired_transition,
    )
    projection = reduce_events(manifest(), events)
    assert projection.candidate == sealed_candidate()
    assert evaluate_phase3(manifest(), projection).next_action == "bind_paired_evidence"

    evidence_event = candidate_event(
        attempt="paired-evidence-phase3",
        event_type=EventType.PAIRED_EVIDENCE_RECORDED,
        second=3,
        payload=paired_evidence().to_canonical_dict(),
    )
    projection = reduce_events(manifest(), (*events, evidence_event))
    assert projection.paired_evidence == paired_evidence()
    assert evaluate_phase3(manifest(), projection).next_action == "issue_review_packets"

    holdout = transition(
        attempt="stage-holdout-phase3",
        source=ExperimentState.PAIRED_EVALUATION,
        target=ExperimentState.HOLDOUT_VALIDATION,
        second=12,
    )
    with pytest.raises(GraphContractError, match="phase4_protected_validation_required"):
        reduce_events(manifest(), (*events, evidence_event, holdout))


def test_phase3_review_identity_quorum_and_draft_are_bound_to_one_candidate() -> None:
    prepared_event = candidate_event(
        attempt="prepare-phase3",
        event_type=EventType.WORKSPACE_PREPARED,
        second=1,
        payload=prepared_candidate().to_canonical_dict(),
    )
    sealed_event = candidate_event(
        attempt="seal-phase3",
        event_type=EventType.CANDIDATE_SEALED,
        second=2,
        payload=sealed_candidate().to_canonical_dict(),
    )
    deterministic = transition(
        attempt="stage-deterministic-phase3",
        source=ExperimentState.BUILDING,
        target=ExperimentState.DETERMINISTIC_VALIDATION,
        second=10,
    )
    paired_transition = transition(
        attempt="stage-paired-phase3",
        source=ExperimentState.DETERMINISTIC_VALIDATION,
        target=ExperimentState.PAIRED_EVALUATION,
        second=11,
    )
    evidence_event = candidate_event(
        attempt="paired-evidence-phase3",
        event_type=EventType.PAIRED_EVIDENCE_RECORDED,
        second=3,
        payload=paired_evidence().to_canonical_dict(),
    )
    events: tuple[ExperimentEvent, ...] = (
        *phase3_build_events(),
        prepared_event,
        sealed_event,
        deterministic,
        paired_transition,
        evidence_event,
    )
    packets: dict[str, ReviewPacket] = {}
    for index, role in enumerate(
        ("correctness", "security", "maintainability", "benchmark_integrity"), start=4
    ):
        packet = ReviewPacket(
            schema_version=1,
            experiment_id=manifest().experiment_id,
            manifest_digest=manifest().digest,
            candidate_commit=sealed_candidate().candidate_commit,
            role=role,
            diff_digest=sealed_candidate().diff_artifact.digest,
            deterministic_evidence_digest=sealed_candidate().digest,
            paired_evidence_digest=paired_evidence().digest,
            review_contract_version="candidate-review-v1",
        )
        packets[role] = packet
        events = (
            *events,
            candidate_event(
                attempt=f"packet-{role}",
                event_type=EventType.REVIEW_PACKET_RECORDED,
                second=index,
                payload=packet.to_canonical_dict(),
            ),
        )

    projection = reduce_events(manifest(), events)
    assert evaluate_phase3(manifest(), projection).next_action == "collect_candidate_reviews"

    for index, (role, verdict) in enumerate(
        (
            ("correctness", "approve"),
            ("security", "approve"),
            ("maintainability", "approve"),
            ("benchmark_integrity", "reject"),
        ),
        start=8,
    ):
        attestation = ReviewAttestation(
            schema_version=1,
            experiment_id=manifest().experiment_id,
            manifest_digest=manifest().digest,
            candidate_commit=sealed_candidate().candidate_commit,
            role=role,
            reviewer_id=f"reviewer-{role}",
            context_id=f"context-{role}",
            packet_digest=packets[role].digest,
            verdict=verdict,
            report_artifact=candidate_artifact("review_report", str(index)[-1]),
        )
        events = (
            *events,
            candidate_event(
                attempt=f"attest-{role}",
                event_type=EventType.REVIEW_ATTESTED,
                second=index,
                payload=attestation.to_canonical_dict(),
            ),
        )

    projection = reduce_events(manifest(), events)
    assert evaluate_phase3(manifest(), projection).next_action == "open_draft_pr"

    draft = DraftPullRequest(
        schema_version=1,
        repository="StephenBickel/carl-agent",
        number=99,
        url="https://github.com/StephenBickel/carl-agent/pull/99",
        state="OPEN",
        is_draft=True,
        base_branch="main",
        head_branch=sealed_candidate().branch,
        candidate_commit=sealed_candidate().candidate_commit,
    )
    draft_event = candidate_event(
        attempt="draft-pr-phase3",
        event_type=EventType.DRAFT_PR_RECORDED,
        second=12,
        payload=draft.to_canonical_dict(),
    )
    completed = reduce_events(manifest(), (*events, draft_event))
    decision = evaluate_phase3(manifest(), completed)
    assert completed.state is ExperimentState.PAIRED_EVALUATION
    assert completed.draft_pull_request == draft
    assert decision.outcome == "draft_open"
    assert decision.next_action == "await_phase4_protected_validation"

    reused = ReviewAttestation(
        schema_version=1,
        experiment_id=manifest().experiment_id,
        manifest_digest=manifest().digest,
        candidate_commit=sealed_candidate().candidate_commit,
        role="benchmark_integrity",
        reviewer_id="reviewer-correctness",
        context_id="new-context",
        packet_digest=packets["benchmark_integrity"].digest,
        verdict="approve",
        report_artifact=candidate_artifact("review_report", "f"),
    )
    reuse_event = candidate_event(
        attempt="attest-reused-reviewer",
        event_type=EventType.REVIEW_ATTESTED,
        second=13,
        payload=reused.to_canonical_dict(),
    )
    with pytest.raises(GraphContractError, match="reviewer_identity_reused"):
        reduce_events(manifest(), (*events[:-1], reuse_event))


def test_phase3_draft_requires_three_approvals_and_no_hard_finding() -> None:
    base_events = phase3_build_events()
    prepared_event = candidate_event(
        attempt="prepare-phase3",
        event_type=EventType.WORKSPACE_PREPARED,
        second=1,
        payload=prepared_candidate().to_canonical_dict(),
    )
    sealed_event = candidate_event(
        attempt="seal-phase3",
        event_type=EventType.CANDIDATE_SEALED,
        second=2,
        payload=sealed_candidate().to_canonical_dict(),
    )
    deterministic = transition(
        attempt="stage-deterministic-phase3",
        source=ExperimentState.BUILDING,
        target=ExperimentState.DETERMINISTIC_VALIDATION,
        second=10,
    )
    paired_transition = transition(
        attempt="stage-paired-phase3",
        source=ExperimentState.DETERMINISTIC_VALIDATION,
        target=ExperimentState.PAIRED_EVALUATION,
        second=11,
    )
    evidence_event = candidate_event(
        attempt="paired-evidence-phase3",
        event_type=EventType.PAIRED_EVIDENCE_RECORDED,
        second=3,
        payload=paired_evidence().to_canonical_dict(),
    )
    draft = DraftPullRequest(
        schema_version=1,
        repository="StephenBickel/carl-agent",
        number=100,
        url="https://github.com/StephenBickel/carl-agent/pull/100",
        state="OPEN",
        is_draft=True,
        base_branch="main",
        head_branch=sealed_candidate().branch,
        candidate_commit=sealed_candidate().candidate_commit,
    )
    draft_event = candidate_event(
        attempt="draft-too-early",
        event_type=EventType.DRAFT_PR_RECORDED,
        second=4,
        payload=draft.to_canonical_dict(),
    )
    with pytest.raises(GraphContractError, match="candidate_attestation_quorum_unsatisfied"):
        reduce_events(
            manifest(),
            (
                *base_events,
                prepared_event,
                sealed_event,
                deterministic,
                paired_transition,
                evidence_event,
                draft_event,
            ),
        )
