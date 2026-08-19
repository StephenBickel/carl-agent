from __future__ import annotations

from dataclasses import replace

import pytest

from carl_bench.artifacts import ArtifactRef
from carl_bench.autonomy import reduce_autonomy_events
from carl_bench.candidate import (
    DeterministicCheckResult,
    PairedEvidence,
    PreparedCandidate,
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
    lease_owner_id: str = "director-phase3",
    lease_stage_attempt_id: str = "lease-phase3",
) -> ExperimentEvent:
    payload: dict[str, object] = {"from_state": source.value, "to_state": target.value}
    if target in {
        ExperimentState.BUILDING,
        ExperimentState.DETERMINISTIC_VALIDATION,
        ExperimentState.PAIRED_EVALUATION,
        ExperimentState.HOLDOUT_VALIDATION,
        ExperimentState.REVIEW_COMPLETE,
        ExperimentState.PR_OPEN,
        ExperimentState.MERGED,
        ExperimentState.SOAKING,
        ExperimentState.ACCEPTED,
    }:
        payload["_lease"] = {
            "owner_id": lease_owner_id,
            "stage_attempt_id": lease_stage_attempt_id,
        }
    return ExperimentEvent.create(
        experiment_id="exp-context-recovery-001",
        stage_attempt_id=attempt,
        event_type=EventType.STATE_TRANSITIONED,
        occurred_at=f"2026-08-10T12:00:{second:02d}Z",
        payload=payload,
    )


def role_event(
    *, attempt: str, role: ReviewRole, verdict: ReviewVerdict, second: int
) -> ExperimentEvent:
    payload: dict[str, object] = {
        "artifact_digest": "b" * 64,
        "role": role.value,
        "verdict": verdict.value,
    }
    if role in {
        ReviewRole.CORRECTNESS,
        ReviewRole.SECURITY,
        ReviewRole.MAINTAINABILITY,
        ReviewRole.BENCHMARK_INTEGRITY,
    }:
        payload["_lease"] = {
            "owner_id": "director-1",
            "stage_attempt_id": "lease-build-1",
        }
    return ExperimentEvent.create(
        experiment_id="exp-context-recovery-001",
        stage_attempt_id=attempt,
        event_type=EventType.ROLE_RECORDED,
        occurred_at=f"2026-08-10T12:00:{second:02d}Z",
        payload=payload,
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
    payload = {
        **payload,
        "_lease": {"owner_id": "director-phase3", "stage_attempt_id": "lease-phase3"},
    }
    return ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id=attempt,
        event_type=event_type,
        occurred_at=f"2026-08-10T12:01:{second:02d}Z",
        payload=payload,
    )


def autonomy_event(
    *,
    attempt: str,
    event_type: EventType,
    occurred_at: str,
    payload: dict[str, object],
) -> ExperimentEvent:
    return ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id=attempt,
        event_type=event_type,
        occurred_at=occurred_at,
        payload=payload,
    )


@pytest.mark.parametrize(
    "authorization",
    [
        None,
        {"owner_id": "director-other", "stage_attempt_id": "lease-phase3"},
        {"owner_id": "director-phase3", "stage_attempt_id": "lease-other"},
    ],
)
def test_mutable_transition_requires_the_active_lease_authorization(
    authorization: dict[str, str] | None,
) -> None:
    payload: dict[str, object] = {
        "from_state": ExperimentState.PROPOSAL_REVIEW.value,
        "to_state": ExperimentState.BUILDING.value,
    }
    if authorization is not None:
        payload["_lease"] = authorization
    build = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id="stage-build-wrong-owner",
        event_type=EventType.STATE_TRANSITIONED,
        occurred_at="2026-08-10T12:00:07Z",
        payload=payload,
    )

    with pytest.raises(GraphContractError, match="lease_capability_invalid"):
        reduce_events(manifest(), (*phase3_build_events()[:-1], build))


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
        lease_owner_id="director-1",
        lease_stage_attempt_id="lease-build-1",
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
            lease_owner_id="director-1",
            lease_stage_attempt_id="lease-build-1",
        ),
        transition(
            attempt="stage-deterministic-1",
            source=ExperimentState.BUILDING,
            target=ExperimentState.DETERMINISTIC_VALIDATION,
            second=8,
            lease_owner_id="director-1",
            lease_stage_attempt_id="lease-build-1",
        ),
        transition(
            attempt="stage-paired-1",
            source=ExperimentState.DETERMINISTIC_VALIDATION,
            target=ExperimentState.PAIRED_EVALUATION,
            second=9,
            lease_owner_id="director-1",
            lease_stage_attempt_id="lease-build-1",
        ),
        transition(
            attempt="stage-holdout-1",
            source=ExperimentState.PAIRED_EVALUATION,
            target=ExperimentState.HOLDOUT_VALIDATION,
            second=10,
            lease_owner_id="director-1",
            lease_stage_attempt_id="lease-build-1",
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
        lease_owner_id="director-1",
        lease_stage_attempt_id="lease-build-1",
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
        lease_owner_id="director-1",
        lease_stage_attempt_id="lease-build-1",
    )
    deterministic = transition(
        attempt="stage-deterministic-1",
        source=ExperimentState.BUILDING,
        target=ExperimentState.DETERMINISTIC_VALIDATION,
        second=9,
        lease_owner_id="director-1",
        lease_stage_attempt_id="lease-build-1",
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

    expired_seal = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id="seal-after-lease-expired",
        event_type=EventType.CANDIDATE_SEALED,
        occurred_at="2026-08-10T18:00:07Z",
        payload=sealed_candidate().to_canonical_dict(),
    )
    with pytest.raises(GraphContractError, match="mutable_lease_required"):
        reduce_events(manifest(), (*phase3_build_events(), prepared_event, expired_seal))

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
    decision = evaluate_phase3(manifest(), projection)
    assert decision.outcome == "blocked"
    assert decision.next_action == "await_isolated_signer"
    assert decision.reasons == ("experimental_publication_disabled",)

    evidence_event = candidate_event(
        attempt="paired-evidence-phase3",
        event_type=EventType.PAIRED_EVIDENCE_RECORDED,
        second=3,
        payload=paired_evidence().to_canonical_dict(),
    )
    with pytest.raises(GraphContractError, match="isolated_signer_required"):
        reduce_events(manifest(), (*events, evidence_event))

    holdout = transition(
        attempt="stage-holdout-phase3",
        source=ExperimentState.PAIRED_EVALUATION,
        target=ExperimentState.HOLDOUT_VALIDATION,
        second=12,
    )
    with pytest.raises(GraphContractError, match="phase4_protected_validation_required"):
        reduce_events(manifest(), (*events, holdout))


def test_autonomy_projection_replays_durable_lifecycle_facts() -> None:
    events = (
        autonomy_event(
            attempt="retry-parser-1",
            event_type=EventType.RETRY_SCHEDULED,
            occurred_at="2026-08-10T12:00:01Z",
            payload={
                "attempt": 1,
                "changed_action": "add parser failure telemetry",
                "failed_stage_attempt_id": "stage-parser-1",
                "failure_class": "infrastructure",
                "scheduled_at": "2026-08-10T12:00:01Z",
            },
        ),
        autonomy_event(
            attempt="retry-parser-2",
            event_type=EventType.RETRY_SCHEDULED,
            occurred_at="2026-08-10T12:01:01Z",
            payload={
                "attempt": 2,
                "changed_action": "replace brittle parser with token scanner",
                "failed_stage_attempt_id": "stage-parser-1",
                "failure_class": "infrastructure",
                "scheduled_at": "2026-08-10T12:01:01Z",
            },
        ),
        autonomy_event(
            attempt="publish-1",
            event_type=EventType.EXPERIMENTAL_PUBLISHED,
            occurred_at="2026-08-10T12:02:01Z",
            payload={
                "branch": "experimental/exp-product-001",
                "candidate_packet_digest": "d" * 64,
                "commit": "a" * 40,
                "tree": "a" * 40,
            },
        ),
        autonomy_event(
            attempt="protected-validation-1",
            event_type=EventType.PROTECTED_VALIDATION_RECORDED,
            occurred_at="2026-08-10T12:03:01Z",
            payload={
                "candidate_commit": "a" * 40,
                "candidate_tree": "a" * 40,
                "receipt_digest": "e" * 64,
            },
        ),
        autonomy_event(
            attempt="promotion-1",
            event_type=EventType.PROMOTION_RECORDED,
            occurred_at="2026-08-10T12:04:01Z",
            payload={"merge_commit": "b" * 40, "merge_tree": "b" * 40},
        ),
        autonomy_event(
            attempt="soak-healthy-1",
            event_type=EventType.SOAK_OBSERVED,
            occurred_at="2026-08-11T12:04:01Z",
            payload={
                "evidence_digest": "f" * 64,
                "healthy": True,
                "merge_commit": "b" * 40,
                "observed_at": "2026-08-11T12:04:01Z",
            },
        ),
    )

    projection = reduce_autonomy_events(manifest(), events)

    assert projection.experimental_publication is not None
    assert projection.experimental_publication.branch == "experimental/exp-product-001"
    assert projection.retry is not None
    assert projection.retry.changed_action == "replace brittle parser with token scanner"
    assert projection.retry.attempt == 2
    assert projection.promotion is not None
    assert projection.promotion.merge_commit == "b" * 40
    assert projection.soak_observations[-1].healthy is True


def test_autonomy_projection_reverts_only_after_a_hard_failure() -> None:
    publication = autonomy_event(
        attempt="publish-1",
        event_type=EventType.EXPERIMENTAL_PUBLISHED,
        occurred_at="2026-08-10T12:02:01Z",
        payload={
            "branch": "experimental/exp-product-001",
            "candidate_packet_digest": "d" * 64,
            "commit": "a" * 40,
            "tree": "a" * 40,
        },
    )
    protected_validation = autonomy_event(
        attempt="protected-validation-1",
        event_type=EventType.PROTECTED_VALIDATION_RECORDED,
        occurred_at="2026-08-10T12:03:01Z",
        payload={
            "candidate_commit": "a" * 40,
            "candidate_tree": "a" * 40,
            "receipt_digest": "e" * 64,
        },
    )
    promotion = autonomy_event(
        attempt="promotion-1",
        event_type=EventType.PROMOTION_RECORDED,
        occurred_at="2026-08-10T12:04:01Z",
        payload={"merge_commit": "b" * 40, "merge_tree": "b" * 40},
    )
    hard_failure = autonomy_event(
        attempt="soak-failure-1",
        event_type=EventType.SOAK_OBSERVED,
        occurred_at="2026-08-10T12:05:01Z",
        payload={
            "evidence_digest": "f" * 64,
            "healthy": False,
            "merge_commit": "b" * 40,
            "observed_at": "2026-08-10T12:05:01Z",
        },
    )
    revert = autonomy_event(
        attempt="revert-1",
        event_type=EventType.REVERT_RECORDED,
        occurred_at="2026-08-10T12:06:01Z",
        payload={
            "hard_failure_digest": "f" * 64,
            "merge_commit": "b" * 40,
            "restored_tree": "c" * 40,
        },
    )

    projection = reduce_autonomy_events(
        manifest(), (publication, protected_validation, promotion, hard_failure, revert)
    )

    assert projection.revert is not None
    assert projection.revert.restored_tree == "c" * 40


def test_autonomy_projection_fails_closed_for_invalid_lifecycle_ordering() -> None:
    publication = autonomy_event(
        attempt="publish-1",
        event_type=EventType.EXPERIMENTAL_PUBLISHED,
        occurred_at="2026-08-10T12:00:01Z",
        payload={
            "branch": "experimental/exp-product-001",
            "candidate_packet_digest": "d" * 64,
            "commit": "a" * 40,
            "tree": "a" * 40,
        },
    )
    duplicate_publication = autonomy_event(
        attempt="publish-2",
        event_type=EventType.EXPERIMENTAL_PUBLISHED,
        occurred_at="2026-08-10T12:01:01Z",
        payload={
            "branch": "experimental/exp-product-002",
            "candidate_packet_digest": "e" * 64,
            "commit": "b" * 40,
            "tree": "b" * 40,
        },
    )
    protected_validation = autonomy_event(
        attempt="protected-validation-1",
        event_type=EventType.PROTECTED_VALIDATION_RECORDED,
        occurred_at="2026-08-10T12:02:01Z",
        payload={
            "candidate_commit": "a" * 40,
            "candidate_tree": "a" * 40,
            "receipt_digest": "e" * 64,
        },
    )
    retry_one = autonomy_event(
        attempt="retry-1",
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at="2026-08-10T12:00:01Z",
        payload={
            "attempt": 1,
            "changed_action": "rebuild the remote cache",
            "failed_stage_attempt_id": "stage-cache-1",
            "failure_class": "infrastructure",
            "scheduled_at": "2026-08-10T12:00:01Z",
        },
    )
    unchanged_retry = autonomy_event(
        attempt="retry-2",
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at="2026-08-10T12:01:01Z",
        payload={
            "attempt": 2,
            "changed_action": "rebuild the remote cache",
            "failed_stage_attempt_id": "stage-cache-1",
            "failure_class": "infrastructure",
            "scheduled_at": "2026-08-10T12:01:01Z",
        },
    )
    fourth_retry = autonomy_event(
        attempt="retry-4",
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at="2026-08-10T12:00:01Z",
        payload={
            "attempt": 4,
            "changed_action": "route to a different runner image",
            "failed_stage_attempt_id": "stage-runner-1",
            "failure_class": "infrastructure",
            "scheduled_at": "2026-08-10T12:00:01Z",
        },
    )
    soak_before_merge = autonomy_event(
        attempt="soak-1",
        event_type=EventType.SOAK_OBSERVED,
        occurred_at="2026-08-10T12:00:01Z",
        payload={
            "evidence_digest": "f" * 64,
            "healthy": True,
            "merge_commit": "b" * 40,
            "observed_at": "2026-08-10T12:00:01Z",
        },
    )
    premature_healthy_soak = autonomy_event(
        attempt="soak-healthy-early-1",
        event_type=EventType.SOAK_OBSERVED,
        occurred_at="2026-08-11T11:59:01Z",
        payload={
            "evidence_digest": "9" * 64,
            "healthy": True,
            "merge_commit": "b" * 40,
            "observed_at": "2026-08-11T11:59:01Z",
        },
    )
    accept_without_24_hour_soak = autonomy_event(
        attempt="accept-1",
        event_type=EventType.STATE_TRANSITIONED,
        occurred_at="2026-08-11T12:00:01Z",
        payload={
            "from_state": ExperimentState.SOAKING.value,
            "to_state": ExperimentState.ACCEPTED.value,
        },
    )
    promotion = autonomy_event(
        attempt="promotion-1",
        event_type=EventType.PROMOTION_RECORDED,
        occurred_at="2026-08-10T12:00:01Z",
        payload={"merge_commit": "b" * 40, "merge_tree": "b" * 40},
    )
    revert_without_failure = autonomy_event(
        attempt="revert-1",
        event_type=EventType.REVERT_RECORDED,
        occurred_at="2026-08-10T12:01:01Z",
        payload={
            "hard_failure_digest": "f" * 64,
            "merge_commit": "b" * 40,
            "restored_tree": "c" * 40,
        },
    )

    with pytest.raises(GraphContractError, match="experimental_publication_already_recorded"):
        reduce_autonomy_events(manifest(), (publication, duplicate_publication))
    with pytest.raises(GraphContractError, match="retry_action_unchanged"):
        reduce_autonomy_events(manifest(), (retry_one, unchanged_retry))
    with pytest.raises(GraphContractError, match="retry_attempt_exhausted"):
        reduce_autonomy_events(manifest(), (fourth_retry,))
    with pytest.raises(GraphContractError, match="soak_promotion_required"):
        reduce_autonomy_events(manifest(), (soak_before_merge,))
    with pytest.raises(GraphContractError, match="soak_healthy_observation_required"):
        reduce_autonomy_events(
            manifest(),
            (
                publication,
                protected_validation,
                promotion,
                premature_healthy_soak,
                accept_without_24_hour_soak,
            ),
        )
    with pytest.raises(GraphContractError, match="hard_failure_required"):
        reduce_autonomy_events(
            manifest(), (publication, protected_validation, promotion, revert_without_failure)
        )


def test_autonomy_events_leave_legacy_experiment_projection_byte_identical() -> None:
    legacy_events = proposal_state_events()
    lifecycle_event = autonomy_event(
        attempt="retry-1",
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at="2026-08-10T12:10:01Z",
        payload={
            "attempt": 1,
            "changed_action": "rebuild the remote cache",
            "failed_stage_attempt_id": "stage-cache-1",
            "failure_class": "infrastructure",
            "scheduled_at": "2026-08-10T12:10:01Z",
        },
    )

    original = reduce_events(manifest(), legacy_events)
    replayed = reduce_events(manifest(), (*legacy_events, lifecycle_event))

    assert replayed == original
    assert replayed.digest == original.digest
