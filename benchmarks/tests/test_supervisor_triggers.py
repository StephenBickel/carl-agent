from __future__ import annotations

import os
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from carl_bench import supervisor_triggers
from carl_bench.supervisor_triggers import (
    RecoveryAttempt,
    SupervisorTrigger,
    SupervisorTriggerError,
    SupervisorTriggerStore,
)


def _attempt(
    attempt_id: str = "attempt-1",
    action_digest: str = "b" * 64,
    *,
    outcome: str = "retry_queued",
) -> RecoveryAttempt:
    return RecoveryAttempt(
        attempt_id=attempt_id,
        action_digest=action_digest,
        occurred_at="2026-08-19T12:01:00Z",
        outcome=outcome,
    )


def _trigger(
    *,
    trigger_id: str = "trigger-1",
    created_at: str = "2026-08-19T12:00:00Z",
) -> SupervisorTrigger:
    return SupervisorTrigger(
        schema_version=1,
        trigger_id=trigger_id,
        evidence_digest="a" * 64,
        unsafe_boundary="promotion:evidence_acceptance",
        attempt_history=(_attempt(),),
        next_safe_node_key="experiment-17:protected-validation",
        created_at=created_at,
    )


def _resolution(
    action: RecoveryAttempt,
    *,
    status: str = "resolved",
    result_digest: str = "e" * 64,
) -> supervisor_triggers.TriggerResolution:
    return supervisor_triggers.TriggerResolution(
        status=status,
        recovery_action=action,
        evidence_digest="a" * 64,
        result_digest=result_digest,
        resolved_at="2026-08-19T12:30:00Z",
    )


def _store(tmp_path: Path) -> SupervisorTriggerStore:
    return SupervisorTriggerStore(tmp_path / "private" / "supervisor-triggers.sqlite3")


def test_append_is_owner_private_exact_and_idempotent(tmp_path: Path) -> None:
    store = _store(tmp_path)
    trigger = _trigger()

    first = store.append(trigger)
    replay = store.append(trigger)

    assert first.applied is True
    assert first.revision == 0
    assert replay.applied is False
    assert replay.record.trigger == trigger
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600

    with pytest.raises(SupervisorTriggerError, match="trigger_id_conflict"):
        store.append(replace(trigger, evidence_digest="c" * 64))


def test_claim_and_record_action_is_one_atomic_cas_and_replay_is_idempotent(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    store.append(_trigger())
    action = _attempt("supervisor-attempt-1", "c" * 64, outcome="state_reconciled")

    claimed = store.claim_and_record_action(
        trigger_id="trigger-1",
        claim_id="supervisor-run-44",
        expected_revision=0,
        attempt=action,
    )
    replay = store.claim_and_record_action(
        trigger_id="trigger-1",
        claim_id="supervisor-run-44",
        expected_revision=0,
        attempt=action,
    )

    assert claimed.applied is True
    assert claimed.revision == 1
    assert claimed.record.claim_id == "supervisor-run-44"
    assert claimed.record.trigger.attempt_history == (_attempt(), action)
    assert replay.applied is False
    assert replay.revision == 1
    assert replay.record == claimed.record


def test_claim_rejects_stale_or_unchanged_recovery_actions(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.append(_trigger())

    with pytest.raises(SupervisorTriggerError, match="recovery_action_unchanged"):
        store.claim_and_record_action(
            trigger_id="trigger-1",
            claim_id="supervisor-run-44",
            expected_revision=0,
            attempt=_attempt("supervisor-attempt-1", "b" * 64),
        )

    first = store.claim_and_record_action(
        trigger_id="trigger-1",
        claim_id="supervisor-run-44",
        expected_revision=0,
        attempt=_attempt("supervisor-attempt-1", "c" * 64),
    )
    assert first.revision == 1

    with pytest.raises(SupervisorTriggerError, match="trigger_cas_mismatch"):
        store.claim_and_record_action(
            trigger_id="trigger-1",
            claim_id="supervisor-run-44",
            expected_revision=0,
            attempt=_attempt("supervisor-attempt-2", "d" * 64),
        )

    with pytest.raises(SupervisorTriggerError, match="trigger_claim_conflict"):
        store.claim_and_record_action(
            trigger_id="trigger-1",
            claim_id="supervisor-run-45",
            expected_revision=1,
            attempt=_attempt("supervisor-attempt-2", "d" * 64),
        )


def test_concurrent_claimers_cannot_both_own_the_trigger(tmp_path: Path) -> None:
    path = tmp_path / "private" / "supervisor-triggers.sqlite3"
    SupervisorTriggerStore(path).append(_trigger())

    def claim(claim_id: str, digest: str) -> str:
        try:
            result = SupervisorTriggerStore(path).claim_and_record_action(
                trigger_id="trigger-1",
                claim_id=claim_id,
                expected_revision=0,
                attempt=_attempt(f"{claim_id}-attempt", digest),
            )
        except SupervisorTriggerError as error:
            return error.code
        return "applied" if result.applied else "replayed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = sorted(
            executor.map(
                lambda args: claim(*args),
                (("supervisor-run-44", "c" * 64), ("supervisor-run-45", "d" * 64)),
            )
        )

    assert outcomes == ["applied", "trigger_claim_conflict"]


def test_fresh_store_enumerates_pending_oldest_first_with_stable_ties(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private" / "supervisor-triggers.sqlite3"
    writer = SupervisorTriggerStore(path)
    writer.append(_trigger(trigger_id="later", created_at="2026-08-19T12:10:00Z"))
    writer.append(_trigger(trigger_id="same-b", created_at="2026-08-19T12:05:00Z"))
    writer.append(_trigger(trigger_id="oldest", created_at="2026-08-19T12:00:00Z"))
    writer.append(_trigger(trigger_id="same-a", created_at="2026-08-19T12:05:00Z"))

    pending = SupervisorTriggerStore(path).list_pending()

    assert [record.trigger.trigger_id for record in pending] == [
        "oldest",
        "same-a",
        "same-b",
        "later",
    ]
    assert [record.revision for record in pending] == [0, 0, 0, 0]


@pytest.mark.parametrize("status", ["resolved", "rejected"])
def test_terminal_resolution_is_atomic_durable_and_removed_from_pending(
    tmp_path: Path,
    status: str,
) -> None:
    path = tmp_path / "private" / "supervisor-triggers.sqlite3"
    store = SupervisorTriggerStore(path)
    store.append(_trigger())
    action = _attempt("supervisor-attempt-1", "c" * 64, outcome="state_reconciled")
    claimed = store.claim_and_record_action(
        trigger_id="trigger-1",
        claim_id="supervisor-run-44",
        expected_revision=0,
        attempt=action,
    )
    resolution = _resolution(action, status=status)

    completed = store.resolve(
        trigger_id="trigger-1",
        claim_id="supervisor-run-44",
        expected_revision=claimed.revision,
        resolution=resolution,
    )
    reopened = SupervisorTriggerStore(path)

    assert completed.applied is True
    assert completed.revision == 2
    assert completed.record.resolution == resolution
    assert reopened.list_pending() == ()
    assert reopened.get("trigger-1") == completed.record


def test_resolution_replay_is_idempotent_and_stale_claimants_are_rejected(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    store.append(_trigger())
    action = _attempt("supervisor-attempt-1", "c" * 64, outcome="state_reconciled")
    claimed = store.claim_and_record_action(
        trigger_id="trigger-1",
        claim_id="supervisor-run-44",
        expected_revision=0,
        attempt=action,
    )
    resolution = _resolution(action)
    first = store.resolve(
        trigger_id="trigger-1",
        claim_id="supervisor-run-44",
        expected_revision=claimed.revision,
        resolution=resolution,
    )

    replay = store.resolve(
        trigger_id="trigger-1",
        claim_id="supervisor-run-44",
        expected_revision=claimed.revision,
        resolution=resolution,
    )
    assert replay.applied is False
    assert replay.record == first.record

    claim_replay = store.claim_and_record_action(
        trigger_id="trigger-1",
        claim_id="supervisor-run-44",
        expected_revision=0,
        attempt=action,
    )
    assert claim_replay.applied is False
    assert claim_replay.record == first.record

    with pytest.raises(SupervisorTriggerError, match="trigger_claim_conflict"):
        store.resolve(
            trigger_id="trigger-1",
            claim_id="supervisor-run-45",
            expected_revision=first.revision,
            resolution=resolution,
        )
    with pytest.raises(SupervisorTriggerError, match="trigger_cas_mismatch"):
        store.resolve(
            trigger_id="trigger-1",
            claim_id="supervisor-run-44",
            expected_revision=0,
            resolution=replace(resolution, result_digest="f" * 64),
        )


def test_resolution_must_bind_exact_claimed_action_and_trigger_evidence(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    store.append(_trigger())
    action = _attempt("supervisor-attempt-1", "c" * 64, outcome="state_reconciled")
    claimed = store.claim_and_record_action(
        trigger_id="trigger-1",
        claim_id="supervisor-run-44",
        expected_revision=0,
        attempt=action,
    )

    with pytest.raises(SupervisorTriggerError, match="resolution_action_mismatch"):
        store.resolve(
            trigger_id="trigger-1",
            claim_id="supervisor-run-44",
            expected_revision=claimed.revision,
            resolution=_resolution(
                _attempt("other-action", "d" * 64, outcome="state_reconciled")
            ),
        )
    with pytest.raises(SupervisorTriggerError, match="resolution_evidence_mismatch"):
        store.resolve(
            trigger_id="trigger-1",
            claim_id="supervisor-run-44",
            expected_revision=claimed.revision,
            resolution=replace(_resolution(action), evidence_digest="f" * 64),
        )


def test_store_rejects_unsafe_path_and_malformed_trigger(tmp_path: Path) -> None:
    public_parent = tmp_path / "public"
    public_parent.mkdir(mode=0o755)
    os.chmod(public_parent, 0o755)
    with pytest.raises(SupervisorTriggerError, match="unsafe_trigger_store_parent"):
        SupervisorTriggerStore(public_parent / "triggers.sqlite3")

    store = _store(tmp_path)
    with pytest.raises(SupervisorTriggerError, match="invalid_evidence_digest"):
        store.append(replace(_trigger(), evidence_digest="not-a-digest"))
