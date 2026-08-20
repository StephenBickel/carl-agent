from __future__ import annotations

import os
import sqlite3
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

from carl_bench.experiment import (
    EventType,
    ExperimentEvent,
    ExperimentState,
    ReviewRole,
    ReviewVerdict,
)
from carl_bench.ledger import ExperimentLedger, LedgerIntegrityError


def test_register_append_reopen_and_replay_are_deterministic(tmp_path: Path) -> None:
    path = tmp_path / "control" / "experiments.sqlite3"
    ledger = ExperimentLedger(path)
    registered = ledger.register_manifest(manifest())
    event = transition(
        attempt="stage-baseline-1",
        source=ExperimentState.QUEUED,
        target=ExperimentState.BASELINING,
        second=1,
    )
    appended = ledger.append(event)

    assert registered is True
    assert appended.appended is True
    assert appended.ordinal == 1
    assert ledger.event_count("exp-context-recovery-001") == 1
    first = ledger.projection("exp-context-recovery-001")

    reopened = ExperimentLedger(path)
    assert reopened.register_manifest(manifest()) is False
    second = reopened.projection("exp-context-recovery-001")
    assert second == first
    assert second.state is ExperimentState.BASELINING
    assert second.digest == first.digest
    assert path.stat().st_mode & 0o077 == 0


def test_exact_stage_redelivery_is_a_noop_but_conflict_fails_closed(tmp_path: Path) -> None:
    ledger = ExperimentLedger(tmp_path / "ledger.sqlite3")
    ledger.register_manifest(manifest())
    event = transition(
        attempt="stage-baseline-1",
        source=ExperimentState.QUEUED,
        target=ExperimentState.BASELINING,
        second=1,
    )

    first = ledger.append(event)
    duplicate = ledger.append(event)

    assert first.appended is True
    assert duplicate.appended is False
    assert duplicate.ordinal == 1
    assert ledger.event_count("exp-context-recovery-001") == 1

    conflict = transition(
        attempt="stage-baseline-1",
        source=ExperimentState.QUEUED,
        target=ExperimentState.REJECTED,
        second=2,
    )
    with pytest.raises(LedgerIntegrityError, match="stage_attempt_conflict"):
        ledger.append(conflict)
    assert ledger.event_count("exp-context-recovery-001") == 1


def test_protected_candidate_reaches_accepted_after_reconciled_lease_rollover(
    tmp_path: Path,
) -> None:
    """Reach durable acceptance through protected evidence and a 24-hour soak."""
    ledger_path = tmp_path / "ledger.sqlite3"
    ledger = ExperimentLedger(ledger_path)
    ledger.register_manifest(manifest())
    for item in phase3_build_events():
        ledger.append(item)
    ledger.append(
        candidate_event(
            attempt="prepare-protected-candidate",
            event_type=EventType.WORKSPACE_PREPARED,
            second=1,
            payload=prepared_candidate().to_canonical_dict(),
        )
    )
    ledger.append(
        candidate_event(
            attempt="seal-protected-candidate",
            event_type=EventType.CANDIDATE_SEALED,
            second=2,
            payload=sealed_candidate().to_canonical_dict(),
        )
    )
    ledger.append(
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="publish-protected-candidate",
            event_type=EventType.EXPERIMENTAL_PUBLISHED,
            occurred_at="2026-08-10T12:01:03Z",
            payload={
                "branch": f"experimental/{manifest().experiment_id}",
                "candidate_packet_digest": sealed_candidate().digest,
                "commit": sealed_candidate().candidate_commit,
                "tree": "7" * 40,
            },
        )
    )
    ledger.append(
        transition(
            attempt="enter-deterministic-validation",
            source=ExperimentState.BUILDING,
            target=ExperimentState.DETERMINISTIC_VALIDATION,
            second=10,
        )
    )
    ledger.append(
        transition(
            attempt="enter-paired-evaluation",
            source=ExperimentState.DETERMINISTIC_VALIDATION,
            target=ExperimentState.PAIRED_EVALUATION,
            second=11,
        )
    )
    ledger.append_trusted_authority(
        candidate_event(
            attempt="record-protected-paired-evidence",
            event_type=EventType.PAIRED_EVIDENCE_RECORDED,
            second=3,
            payload=paired_evidence().to_canonical_dict(),
        )
    )
    ledger.append_trusted_authority(
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="record-protected-validation",
            event_type=EventType.PROTECTED_VALIDATION_RECORDED,
            occurred_at="2026-08-10T12:02:00Z",
            payload={
                "candidate_commit": sealed_candidate().candidate_commit,
                "candidate_tree": "7" * 40,
                "receipt_digest": "8" * 64,
            },
        )
    )
    ledger.append(
        transition(
            attempt="enter-protected-holdout",
            source=ExperimentState.PAIRED_EVALUATION,
            target=ExperimentState.HOLDOUT_VALIDATION,
            second=12,
        )
    )
    for index, role in enumerate(
        (ReviewRole.CORRECTNESS, ReviewRole.SECURITY, ReviewRole.MAINTAINABILITY),
        start=1,
    ):
        ledger.append(
            ExperimentEvent.create(
                experiment_id=manifest().experiment_id,
                stage_attempt_id=f"protected-review-{index}",
                event_type=EventType.ROLE_RECORDED,
                occurred_at=f"2026-08-10T12:03:0{index}Z",
                payload={
                    "_lease": {
                        "owner_id": "director-phase3",
                        "stage_attempt_id": "lease-phase3",
                    },
                    "artifact_digest": str(index) * 64,
                    "role": role.value,
                    "verdict": ReviewVerdict.APPROVE.value,
                },
            )
        )
    for attempt, source, target, second in (
        (
            "finish-protected-review",
            ExperimentState.HOLDOUT_VALIDATION,
            ExperimentState.REVIEW_COMPLETE,
            13,
        ),
        (
            "open-protected-pr",
            ExperimentState.REVIEW_COMPLETE,
            ExperimentState.PR_OPEN,
            14,
        ),
    ):
        ledger.append(transition(attempt=attempt, source=source, target=target, second=second))
    ledger.append_trusted_authority(
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="record-protected-promotion",
            event_type=EventType.PROMOTION_RECORDED,
            occurred_at="2026-08-10T12:00:15Z",
            payload={"merge_commit": "9" * 40, "merge_tree": "a" * 40},
        )
    )
    ledger.append(
        transition(
            attempt="record-protected-merge",
            source=ExperimentState.PR_OPEN,
            target=ExperimentState.MERGED,
            second=15,
        )
    )
    ledger.append(
        transition(
            attempt="start-protected-soak",
            source=ExperimentState.MERGED,
            target=ExperimentState.SOAKING,
            second=16,
        )
    )
    ledger.append_trusted_authority(
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="observe-healthy-protected-soak",
            event_type=EventType.SOAK_OBSERVED,
            occurred_at="2026-08-11T12:00:16Z",
            payload={
                "evidence_digest": "b" * 64,
                "healthy": True,
                "merge_commit": "9" * 40,
                "observed_at": "2026-08-11T12:00:16Z",
            },
        )
    )

    ledger.append(
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="reconcile-expired-soak-lease",
            event_type=EventType.LEASE_RECONCILED,
            occurred_at="2026-08-11T12:00:16Z",
            payload={"lease_stage_attempt_id": "lease-phase3", "worker_not_live": True},
        )
    )
    ledger.append(
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="lease-acceptance",
            event_type=EventType.LEASE_ACQUIRED,
            occurred_at="2026-08-11T12:00:17Z",
            payload={
                "expires_at": "2026-08-11T18:00:17Z",
                "owner_id": "acceptance-controller",
            },
        )
    )
    ledger.append(
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="accept-after-24h-soak",
            event_type=EventType.STATE_TRANSITIONED,
            occurred_at="2026-08-11T12:00:18Z",
            payload={
                "_lease": {
                    "owner_id": "acceptance-controller",
                    "stage_attempt_id": "lease-acceptance",
                },
                "from_state": ExperimentState.SOAKING.value,
                "to_state": ExperimentState.ACCEPTED.value,
            },
        )
    )
    ledger.append(
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="release-acceptance-lease",
            event_type=EventType.LEASE_RELEASED,
            occurred_at="2026-08-11T12:00:19Z",
            payload={"lease_stage_attempt_id": "lease-acceptance"},
        )
    )

    reopened = ExperimentLedger(ledger_path)
    projection = reopened.projection(manifest().experiment_id)
    assert projection.state is ExperimentState.ACCEPTED
    assert projection.lease is None
    assert projection.candidate == sealed_candidate()


def test_trusted_paired_evidence_is_bound_to_the_exact_sealed_candidate(
    tmp_path: Path,
) -> None:
    ledger = ExperimentLedger(tmp_path / "ledger.sqlite3")
    ledger.register_manifest(manifest())
    for item in phase3_build_events():
        ledger.append(item)
    ledger.append(
        candidate_event(
            attempt="prepare-candidate-binding",
            event_type=EventType.WORKSPACE_PREPARED,
            second=1,
            payload=prepared_candidate().to_canonical_dict(),
        )
    )
    ledger.append(
        candidate_event(
            attempt="seal-candidate-binding",
            event_type=EventType.CANDIDATE_SEALED,
            second=2,
            payload=sealed_candidate().to_canonical_dict(),
        )
    )
    ledger.append(
        transition(
            attempt="enter-deterministic-binding",
            source=ExperimentState.BUILDING,
            target=ExperimentState.DETERMINISTIC_VALIDATION,
            second=10,
        )
    )
    ledger.append(
        transition(
            attempt="enter-paired-binding",
            source=ExperimentState.DETERMINISTIC_VALIDATION,
            target=ExperimentState.PAIRED_EVALUATION,
            second=11,
        )
    )

    forged = replace(paired_evidence(), candidate_commit="e" * 40)
    with pytest.raises(LedgerIntegrityError, match="paired_evidence_candidate_mismatch"):
        ledger.append_trusted_authority(
            candidate_event(
                attempt="forged-protected-paired-evidence",
                event_type=EventType.PAIRED_EVIDENCE_RECORDED,
                second=3,
                payload=forged.to_canonical_dict(),
            )
        )


def test_protected_validation_is_bound_to_the_sealed_candidate_packet(
    tmp_path: Path,
) -> None:
    ledger = ExperimentLedger(tmp_path / "ledger.sqlite3")
    ledger.register_manifest(manifest())
    for item in phase3_build_events():
        ledger.append(item)
    ledger.append(
        candidate_event(
            attempt="prepare-validation-binding",
            event_type=EventType.WORKSPACE_PREPARED,
            second=1,
            payload=prepared_candidate().to_canonical_dict(),
        )
    )
    ledger.append(
        candidate_event(
            attempt="seal-validation-binding",
            event_type=EventType.CANDIDATE_SEALED,
            second=2,
            payload=sealed_candidate().to_canonical_dict(),
        )
    )
    ledger.append(
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="publish-wrong-candidate-packet",
            event_type=EventType.EXPERIMENTAL_PUBLISHED,
            occurred_at="2026-08-10T12:01:03Z",
            payload={
                "branch": f"experimental/{manifest().experiment_id}",
                "candidate_packet_digest": "0" * 64,
                "commit": sealed_candidate().candidate_commit,
                "tree": "7" * 40,
            },
        )
    )
    ledger.append(
        transition(
            attempt="enter-deterministic-validation-binding",
            source=ExperimentState.BUILDING,
            target=ExperimentState.DETERMINISTIC_VALIDATION,
            second=10,
        )
    )
    ledger.append(
        transition(
            attempt="enter-paired-validation-binding",
            source=ExperimentState.DETERMINISTIC_VALIDATION,
            target=ExperimentState.PAIRED_EVALUATION,
            second=11,
        )
    )
    ledger.append_trusted_authority(
        candidate_event(
            attempt="record-paired-validation-binding",
            event_type=EventType.PAIRED_EVIDENCE_RECORDED,
            second=3,
            payload=paired_evidence().to_canonical_dict(),
        )
    )

    with pytest.raises(LedgerIntegrityError, match="protected_validation_candidate_mismatch"):
        ledger.append_trusted_authority(
            ExperimentEvent.create(
                experiment_id=manifest().experiment_id,
                stage_attempt_id="record-mismatched-protected-validation",
                event_type=EventType.PROTECTED_VALIDATION_RECORDED,
                occurred_at="2026-08-10T12:02:00Z",
                payload={
                    "candidate_commit": sealed_candidate().candidate_commit,
                    "candidate_tree": "7" * 40,
                    "receipt_digest": "8" * 64,
                },
            )
        )


@pytest.mark.parametrize(
    "event_type",
    (
        EventType.PAIRED_EVIDENCE_RECORDED,
        EventType.REVIEW_PACKET_RECORDED,
        EventType.REVIEW_ATTESTED,
        EventType.DRAFT_PR_REQUESTED,
        EventType.DRAFT_PR_RECORDED,
        EventType.WORKSPACE_DISPOSED,
        EventType.PROTECTED_VALIDATION_RECORDED,
        EventType.PROMOTION_RECORDED,
        EventType.SOAK_OBSERVED,
        EventType.REVERT_RECORDED,
    ),
)
def test_raw_publication_event_injection_is_rejected_without_a_ledger_write(
    tmp_path: Path, event_type: EventType
) -> None:
    ledger = ExperimentLedger(tmp_path / "ledger.sqlite3")
    ledger.register_manifest(manifest())
    forged = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id=f"forged-{event_type.value}",
        event_type=event_type,
        occurred_at="2026-08-10T12:00:01Z",
        payload={},
    )

    with pytest.raises(LedgerIntegrityError, match="isolated_signer_required"):
        ledger.append(forged)

    assert ledger.event_count(manifest().experiment_id) == 0


def test_manifest_is_registered_once_and_conflicting_rewrite_is_rejected(tmp_path: Path) -> None:
    ledger = ExperimentLedger(tmp_path / "ledger.sqlite3")
    ledger.register_manifest(manifest())

    rewritten = replace(manifest(), hypothesis="Rewrite the prediction after seeing evidence.")
    with pytest.raises(LedgerIntegrityError, match="manifest_conflict"):
        ledger.register_manifest(rewritten)

    assert ledger.load_manifest(manifest().experiment_id) == manifest()


def test_child_manifest_requires_registered_ancestry(tmp_path: Path) -> None:
    ledger = ExperimentLedger(tmp_path / "ledger.sqlite3")
    child = replace(
        manifest(),
        experiment_id="exp-child-001",
        parent_experiment_id=manifest().experiment_id,
    )
    with pytest.raises(LedgerIntegrityError, match="parent_experiment_not_found"):
        ledger.register_manifest(child)

    ledger.register_manifest(manifest())
    assert ledger.register_manifest(child) is True

    early_child = replace(
        child,
        experiment_id="exp-child-too-early",
        registered_at="2026-08-09T23:59:59Z",
    )
    with pytest.raises(LedgerIntegrityError, match="child_precedes_parent"):
        ledger.register_manifest(early_child)


def test_hash_chain_tampering_blocks_projection_and_future_append(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    ledger = ExperimentLedger(path)
    ledger.register_manifest(manifest())
    ledger.append(
        transition(
            attempt="stage-baseline-1",
            source=ExperimentState.QUEUED,
            target=ExperimentState.BASELINING,
            second=1,
        )
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE experiment_events SET payload_json = ? WHERE ordinal = 1",
            ('{"from_state":"queued","to_state":"rejected"}',),
        )

    with pytest.raises(LedgerIntegrityError, match="event_digest_mismatch"):
        ledger.projection("exp-context-recovery-001")
    with pytest.raises(LedgerIntegrityError, match="event_digest_mismatch"):
        ledger.append(
            transition(
                attempt="stage-diagnose-1",
                source=ExperimentState.BASELINING,
                target=ExperimentState.DIAGNOSING,
                second=2,
            )
        )


def test_unknown_ledger_event_types_remain_rejected(tmp_path: Path) -> None:
    path = tmp_path / "ledger.sqlite3"
    ledger = ExperimentLedger(path)
    ledger.register_manifest(manifest())
    ledger.append(
        transition(
            attempt="stage-baseline-1",
            source=ExperimentState.QUEUED,
            target=ExperimentState.BASELINING,
            second=1,
        )
    )
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE experiment_events SET event_type = 'unknown_event' WHERE ordinal = 1"
        )

    with pytest.raises(LedgerIntegrityError, match="event_contract_invalid"):
        ledger.projection(manifest().experiment_id)


def test_missing_experiment_and_unsafe_existing_file_fail_closed(tmp_path: Path) -> None:
    ledger = ExperimentLedger(tmp_path / "ledger.sqlite3")
    with pytest.raises(LedgerIntegrityError, match="experiment_not_found"):
        ledger.projection("exp-missing")

    unsafe = tmp_path / "unsafe.sqlite3"
    unsafe.write_text("not a ledger", encoding="utf-8")
    unsafe.chmod(0o644)
    if os.name != "nt":
        with pytest.raises(LedgerIntegrityError, match="unsafe_ledger_permissions"):
            ExperimentLedger(unsafe)

    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_text("not a SQLite database", encoding="utf-8")
    corrupt.chmod(0o600)
    with pytest.raises(LedgerIntegrityError, match="ledger_database_error"):
        ExperimentLedger(corrupt)

    wrong_schema = tmp_path / "wrong-schema.sqlite3"
    with sqlite3.connect(wrong_schema) as connection:
        connection.execute("CREATE TABLE ledger_metadata(key TEXT PRIMARY KEY) STRICT")
    wrong_schema.chmod(0o600)
    with pytest.raises(LedgerIntegrityError, match="ledger_database_error"):
        ExperimentLedger(wrong_schema)


def test_broad_parent_and_hard_linked_ledger_are_rejected(tmp_path: Path) -> None:
    broad_parent = tmp_path / "broad"
    broad_parent.mkdir(mode=0o755)
    if os.name != "nt":
        with pytest.raises(LedgerIntegrityError, match="unsafe_ledger_parent"):
            ExperimentLedger(broad_parent / "ledger.sqlite3")

    ledger_path = tmp_path / "ledger.sqlite3"
    ExperimentLedger(ledger_path)
    alias = tmp_path / "ledger-alias.sqlite3"
    os.link(ledger_path, alias)
    with pytest.raises(LedgerIntegrityError, match="unsafe_ledger_links"):
        ExperimentLedger(ledger_path)


def test_event_for_unregistered_experiment_is_rejected(tmp_path: Path) -> None:
    ledger = ExperimentLedger(tmp_path / "ledger.sqlite3")
    event = transition(
        attempt="stage-baseline-1",
        source=ExperimentState.QUEUED,
        target=ExperimentState.BASELINING,
        second=1,
    )
    with pytest.raises(LedgerIntegrityError, match="experiment_not_found"):
        ledger.append(event)


def test_ledger_replays_autonomy_facts_without_changing_legacy_projection(tmp_path: Path) -> None:
    ledger = ExperimentLedger(tmp_path / "ledger.sqlite3")
    ledger.register_manifest(manifest())
    legacy = transition(
        attempt="stage-baseline-1",
        source=ExperimentState.QUEUED,
        target=ExperimentState.BASELINING,
        second=1,
    )
    retry = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id="retry-cache-1",
        event_type=EventType.RETRY_SCHEDULED,
        occurred_at="2026-08-10T12:01:01Z",
        payload={
            "attempt": 1,
            "changed_action": "rebuild the remote cache",
            "failed_stage_attempt_id": "stage-cache-1",
            "failure_class": "infrastructure",
            "scheduled_at": "2026-08-10T12:01:01Z",
        },
    )

    ledger.append(legacy)
    before = ledger.projection(manifest().experiment_id)
    ledger.append(retry)
    after = ledger.projection(manifest().experiment_id)
    autonomy = ledger.autonomy_projection(manifest().experiment_id)

    assert after == before
    assert autonomy.retry is not None
    assert autonomy.retry.changed_action == "rebuild the remote cache"


def test_trusted_authority_append_replays_a_complete_protected_lifecycle(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger.sqlite3"
    ledger = ExperimentLedger(path)
    ledger.register_manifest(manifest())
    publication = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id="publication-1",
        event_type=EventType.EXPERIMENTAL_PUBLISHED,
        occurred_at="2026-08-10T12:02:01Z",
        payload={
            "branch": "experimental/exp-product-001",
            "candidate_packet_digest": "d" * 64,
            "commit": "a" * 40,
            "tree": "a" * 40,
        },
    )
    protected_events = (
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="protected-validation-1",
            event_type=EventType.PROTECTED_VALIDATION_RECORDED,
            occurred_at="2026-08-10T12:03:01Z",
            payload={
                "candidate_commit": "a" * 40,
                "candidate_tree": "a" * 40,
                "receipt_digest": "e" * 64,
            },
        ),
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="promotion-1",
            event_type=EventType.PROMOTION_RECORDED,
            occurred_at="2026-08-10T12:04:01Z",
            payload={"merge_commit": "b" * 40, "merge_tree": "b" * 40},
        ),
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="soak-failure-1",
            event_type=EventType.SOAK_OBSERVED,
            occurred_at="2026-08-10T12:05:01Z",
            payload={
                "evidence_digest": "f" * 64,
                "healthy": False,
                "merge_commit": "b" * 40,
                "observed_at": "2026-08-10T12:05:01Z",
            },
        ),
        ExperimentEvent.create(
            experiment_id=manifest().experiment_id,
            stage_attempt_id="revert-1",
            event_type=EventType.REVERT_RECORDED,
            occurred_at="2026-08-10T12:06:01Z",
            payload={
                "hard_failure_digest": "f" * 64,
                "merge_commit": "b" * 40,
                "restored_tree": "c" * 40,
                "revert_candidate_commit": "d" * 40,
                "revert_merge_commit": "e" * 40,
                "revert_pull_request_number": 82,
            },
        ),
    )

    with pytest.raises(LedgerIntegrityError, match="trusted_authority_event_required"):
        ledger.append_trusted_authority(publication)
    ledger.append(publication)
    appends = tuple(ledger.append_trusted_authority(event) for event in protected_events)
    with pytest.raises(LedgerIntegrityError, match="isolated_signer_required"):
        ledger.append(protected_events[-1])
    trusted_replay = ledger.append_trusted_authority(protected_events[-1])
    replayed = ExperimentLedger(path).autonomy_projection(manifest().experiment_id)

    assert tuple(result.ordinal for result in appends) == (2, 3, 4, 5)
    assert len({result.chain_digest for result in appends}) == 4
    assert trusted_replay.appended is False
    assert trusted_replay.ordinal == appends[-1].ordinal
    assert trusted_replay.chain_digest == appends[-1].chain_digest
    assert ledger.event_count(manifest().experiment_id) == 5
    assert replayed.protected_validation is not None
    assert replayed.protected_validation.receipt_digest == "e" * 64
    assert replayed.promotion is not None
    assert replayed.promotion.merge_commit == "b" * 40
    assert replayed.soak_observations[-1].healthy is False
    assert replayed.revert is not None
    assert replayed.revert.merge_commit == "b" * 40
    assert replayed.revert.revert_pull_request_number == 82
    assert replayed.revert.revert_candidate_commit == "d" * 40
    assert replayed.revert.revert_merge_commit == "e" * 40
    assert replayed.revert.restored_tree == "c" * 40


def _for_experiment(event: ExperimentEvent, experiment_id: str, attempt: str) -> ExperimentEvent:
    return replace(event, experiment_id=experiment_id, stage_attempt_id=attempt)


def _advance_to_proposal(ledger: ExperimentLedger, experiment_id: str, prefix: str) -> None:
    for index, event in enumerate(
        (
            transition(
                attempt="unused-1",
                source=ExperimentState.QUEUED,
                target=ExperimentState.BASELINING,
                second=1,
            ),
            transition(
                attempt="unused-2",
                source=ExperimentState.BASELINING,
                target=ExperimentState.DIAGNOSING,
                second=2,
            ),
            transition(
                attempt="unused-3",
                source=ExperimentState.DIAGNOSING,
                target=ExperimentState.PROPOSAL_REVIEW,
                second=3,
            ),
        ),
        start=1,
    ):
        ledger.append(_for_experiment(event, experiment_id, f"{prefix}-transition-{index}"))


def test_global_mutable_lease_requires_reconciliation_before_another_experiment(
    tmp_path: Path,
) -> None:
    ledger = ExperimentLedger(tmp_path / "ledger.sqlite3")
    first_manifest = manifest()
    second_manifest = replace(manifest(), experiment_id="exp-second-001")
    ledger.register_manifest(first_manifest)
    ledger.register_manifest(second_manifest)
    _advance_to_proposal(ledger, first_manifest.experiment_id, "first")
    _advance_to_proposal(ledger, second_manifest.experiment_id, "second")

    first_lease = ExperimentEvent.create(
        experiment_id=first_manifest.experiment_id,
        stage_attempt_id="first-lease-1",
        event_type=EventType.LEASE_ACQUIRED,
        occurred_at="2026-08-10T12:00:04Z",
        payload={"expires_at": "2026-08-10T12:00:10Z", "owner_id": "director-1"},
    )
    ledger.append(first_lease)
    second_lease = ExperimentEvent.create(
        experiment_id=second_manifest.experiment_id,
        stage_attempt_id="second-lease-1",
        event_type=EventType.LEASE_ACQUIRED,
        occurred_at="2026-08-10T12:00:11Z",
        payload={"expires_at": "2026-08-10T12:00:20Z", "owner_id": "director-2"},
    )

    with pytest.raises(LedgerIntegrityError, match="mutable_lease_conflict"):
        ledger.append(second_lease)

    ledger.append(
        ExperimentEvent.create(
            experiment_id=first_manifest.experiment_id,
            stage_attempt_id="first-reconcile-1",
            event_type=EventType.LEASE_RECONCILED,
            occurred_at="2026-08-10T12:00:11Z",
            payload={"lease_stage_attempt_id": "first-lease-1", "worker_not_live": True},
        )
    )
    ledger.append(
        ExperimentEvent.create(
            experiment_id=first_manifest.experiment_id,
            stage_attempt_id="first-release-1",
            event_type=EventType.LEASE_RELEASED,
            occurred_at="2026-08-10T12:00:12Z",
            payload={"lease_stage_attempt_id": "first-lease-1"},
        )
    )
    acquired = ledger.append(replace(second_lease, occurred_at="2026-08-10T12:00:13Z"))
    assert acquired.appended is True


def _record_spend(
    ledger: ExperimentLedger,
    *,
    experiment_id: str,
    attempt: str,
    occurred_at: str,
    amount: int,
) -> None:
    ledger.append(
        ExperimentEvent.create(
            experiment_id=experiment_id,
            stage_attempt_id=attempt,
            event_type=EventType.LIVE_SPEND_RECORDED,
            occurred_at=occurred_at,
            payload={"live_microdollars": amount, "run_id": f"run-{attempt}"},
        )
    )


def test_dispatch_budget_checks_experiment_day_week_and_concurrency_exactly(
    tmp_path: Path,
) -> None:
    ledger = ExperimentLedger(tmp_path / "ledger.sqlite3")
    target = replace(manifest(), experiment_id="exp-budget-target")
    ledger.register_manifest(target)
    _record_spend(
        ledger,
        experiment_id=target.experiment_id,
        attempt="target-spend",
        occurred_at="2026-08-10T10:00:00Z",
        amount=5_000_000,
    )

    allowed = ledger.can_dispatch_live_run(
        target.experiment_id,
        requested_microdollars=15_000_000,
        at="2026-08-10T12:00:00Z",
        active_live_workers=3,
    )
    assert allowed.allowed is True
    assert allowed.reasons == ()
    assert allowed.experiment_after_microdollars == 20_000_000

    blocked = ledger.can_dispatch_live_run(
        target.experiment_id,
        requested_microdollars=15_000_001,
        at="2026-08-10T12:00:00Z",
        active_live_workers=4,
    )
    assert blocked.allowed is False
    assert blocked.reasons == (
        "experiment_live_budget_exceeded",
        "live_concurrency_exhausted",
    )

    same_day = replace(manifest(), experiment_id="exp-same-day")
    ledger.register_manifest(same_day)
    _record_spend(
        ledger,
        experiment_id=same_day.experiment_id,
        attempt="same-day-spend",
        occurred_at="2026-08-10T11:00:00Z",
        amount=20_000_000,
    )
    daily = ledger.can_dispatch_live_run(
        target.experiment_id,
        requested_microdollars=1,
        at="2026-08-10T12:00:00Z",
        active_live_workers=0,
    )
    assert daily.reasons == ("daily_live_budget_exceeded",)

    weekly_ledger = ExperimentLedger(tmp_path / "weekly.sqlite3")
    weekly_target = replace(manifest(), experiment_id="exp-weekly-target")
    weekly_ledger.register_manifest(weekly_target)
    for day in range(3, 10):
        item = replace(
            manifest(),
            experiment_id=f"exp-weekly-{day}",
            registered_at=f"2026-08-{day:02d}T12:00:00Z",
        )
        weekly_ledger.register_manifest(item)
        _record_spend(
            weekly_ledger,
            experiment_id=item.experiment_id,
            attempt=f"weekly-spend-{day}",
            occurred_at=f"2026-08-{day:02d}T13:00:00Z",
            amount=20_000_000,
        )
    weekly = weekly_ledger.can_dispatch_live_run(
        weekly_target.experiment_id,
        requested_microdollars=10_000_001,
        at="2026-08-10T12:00:00Z",
        active_live_workers=0,
    )
    assert weekly.reasons == ("weekly_live_budget_exceeded",)


def test_budget_snapshot_cannot_predate_spend_and_enforces_elapsed_limit(tmp_path: Path) -> None:
    ledger = ExperimentLedger(tmp_path / "ledger.sqlite3")
    ledger.register_manifest(manifest())
    _record_spend(
        ledger,
        experiment_id=manifest().experiment_id,
        attempt="known-spend",
        occurred_at="2026-08-10T10:00:00Z",
        amount=1,
    )
    with pytest.raises(LedgerIntegrityError, match="budget_snapshot_precedes_recorded_spend"):
        ledger.can_dispatch_live_run(
            manifest().experiment_id,
            requested_microdollars=1,
            at="2026-08-10T09:59:59Z",
            active_live_workers=0,
        )

    elapsed = ledger.can_dispatch_live_run(
        manifest().experiment_id,
        requested_microdollars=1,
        at="2026-08-11T00:00:01Z",
        active_live_workers=0,
    )
    assert elapsed.reasons == ("experiment_elapsed_budget_exceeded",)
