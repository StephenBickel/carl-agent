from __future__ import annotations

import os
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

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


def _trigger(*, trigger_id: str = "trigger-1") -> SupervisorTrigger:
    return SupervisorTrigger(
        schema_version=1,
        trigger_id=trigger_id,
        evidence_digest="a" * 64,
        unsafe_boundary="promotion:evidence_acceptance",
        attempt_history=(_attempt(),),
        next_safe_node_key="experiment-17:protected-validation",
        created_at="2026-08-19T12:00:00Z",
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


def test_store_rejects_unsafe_path_and_malformed_trigger(tmp_path: Path) -> None:
    public_parent = tmp_path / "public"
    public_parent.mkdir(mode=0o755)
    os.chmod(public_parent, 0o755)
    with pytest.raises(SupervisorTriggerError, match="unsafe_trigger_store_parent"):
        SupervisorTriggerStore(public_parent / "triggers.sqlite3")

    store = _store(tmp_path)
    with pytest.raises(SupervisorTriggerError, match="invalid_evidence_digest"):
        store.append(replace(_trigger(), evidence_digest="not-a-digest"))
