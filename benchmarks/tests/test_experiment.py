from __future__ import annotations

from dataclasses import replace

import pytest

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
    assert approved.outcome == "simulated_build_eligible"
    assert approved.reasons == ("phase3_builder_not_enabled",)

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
