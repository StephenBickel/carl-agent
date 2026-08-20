from __future__ import annotations

from dataclasses import replace

import pytest

from carl_bench.cloud_state import (
    CloudCommand,
    CloudLease,
    CloudStateError,
    CommandClaim,
    CommandState,
    EvidenceObject,
    StateTransition,
    acquire_lease,
    claim_command,
    complete_command,
    create_command_state,
    replay_command,
)

_DIGEST = "a" * 64
_RESULT_DIGEST = "b" * 64
_TIMESTAMP = "2026-08-20T12:00:00Z"
_EXPIRES_AT = "2026-08-20T12:05:00Z"


def _command(*, occurred_at: str = _TIMESTAMP, request_digest: str = _DIGEST) -> CloudCommand:
    return CloudCommand.create(
        command_key="dispatch-improvement-01",
        authority="coordinator",
        operation="dispatch",
        request_digest=request_digest,
        occurred_at=occurred_at,
        expected_revision=7,
        attempt=1,
        max_attempts=3,
    )


def _claim(*, expected_revision: int = 7) -> CommandClaim:
    return CommandClaim(
        command_key="dispatch-improvement-01",
        claim_id="claim-improvement-01",
        authority="coordinator",
        expected_revision=expected_revision,
        claimed_at=_TIMESTAMP,
        expires_at=_EXPIRES_AT,
    )


def test_cloud_command_round_trips_with_deterministic_effect_key() -> None:
    first = _command()
    second = _command()

    assert first.effect_key == second.effect_key
    assert first.effect_key.startswith("cloud-effect-")
    assert CloudCommand.from_canonical_dict(first.to_canonical_dict()) == first


def test_coordinator_allows_existing_cloud_reconciliation_actions() -> None:
    command = CloudCommand.create(
        command_key="record-success-01",
        authority="coordinator",
        operation="record_success",
        request_digest=_DIGEST,
        occurred_at=_TIMESTAMP,
        expected_revision=7,
        attempt=1,
        max_attempts=3,
    )

    assert command.operation == "record_success"
    with pytest.raises(CloudStateError, match="command_authority_denied"):
        CloudCommand.create(
            command_key="invalid-dispatch-01",
            authority="builder",
            operation="dispatch",
            request_digest=_DIGEST,
            occurred_at=_TIMESTAMP,
            expected_revision=7,
            attempt=1,
            max_attempts=3,
        )


def test_command_replay_reuses_the_persisted_occurrence_time() -> None:
    persisted = _command()
    replay = _command(occurred_at="2026-08-20T12:01:00Z")

    assert replay_command(persisted, replay) == persisted


def test_conflicting_command_replay_fails_closed() -> None:
    persisted = _command()
    conflicting = _command(request_digest="c" * 64)

    with pytest.raises(CloudStateError, match="command_replay_conflict"):
        replay_command(persisted, conflicting)


def test_claim_requires_matching_role_and_current_revision() -> None:
    state = create_command_state(_command())

    with pytest.raises(CloudStateError, match="command_authority_denied"):
        claim_command(state, replace(_claim(), authority="builder"))
    with pytest.raises(CloudStateError, match="command_cas_mismatch"):
        claim_command(state, _claim(expected_revision=6))


def test_command_claim_successor_is_idempotent_and_preserves_claim_time() -> None:
    state = create_command_state(_command())
    claimed = claim_command(state, _claim())

    assert claimed.revision == 8
    assert claimed.claim == _claim()
    assert claim_command(claimed, _claim()) == claimed
    assert CommandState.from_canonical_dict(claimed.to_canonical_dict()) == claimed


def test_complete_requires_an_exact_result_identity() -> None:
    claimed = claim_command(create_command_state(_command()), _claim())
    transition = StateTransition(
        command_key="dispatch-improvement-01",
        authority="coordinator",
        claim_id="claim-improvement-01",
        expected_revision=8,
        next_revision=9,
        status="completed",
        occurred_at="2026-08-20T12:02:00Z",
        result_digest=_RESULT_DIGEST,
        failure_code=None,
    )

    completed = complete_command(claimed, transition)

    assert completed.result_digest == _RESULT_DIGEST
    assert complete_command(completed, transition) == completed
    with pytest.raises(CloudStateError, match="command_result_conflict"):
        complete_command(completed, replace(transition, result_digest="d" * 64))


def test_transition_codec_rejects_unhashable_status_values() -> None:
    transition = StateTransition(
        command_key="dispatch-improvement-01",
        authority="coordinator",
        claim_id="claim-improvement-01",
        expected_revision=8,
        next_revision=9,
        status="completed",
        occurred_at="2026-08-20T12:02:00Z",
        result_digest=_RESULT_DIGEST,
        failure_code=None,
    )
    malformed = transition.to_canonical_dict()
    malformed["status"] = []

    assert StateTransition.from_canonical_dict(transition.to_canonical_dict()) == transition
    with pytest.raises(CloudStateError, match="invalid_transition_status"):
        StateTransition.from_canonical_dict(malformed)


def test_expired_lease_can_be_replaced_only_by_a_matching_successor() -> None:
    expired = CloudLease(
        lease_key="coordinator",
        holder_id="worker-a",
        authority="coordinator",
        revision=4,
        acquired_at="2026-08-20T11:00:00Z",
        expires_at="2026-08-20T11:05:00Z",
    )
    successor = CloudLease(
        lease_key="coordinator",
        holder_id="worker-b",
        authority="coordinator",
        revision=4,
        acquired_at=_TIMESTAMP,
        expires_at=_EXPIRES_AT,
    )

    acquired = acquire_lease(expired, successor, observed_at=_TIMESTAMP)

    assert acquired.revision == 5
    assert acquired.holder_id == "worker-b"
    assert CloudLease.from_canonical_dict(acquired.to_canonical_dict()) == acquired


def test_evidence_object_requires_its_content_addressed_key_and_authorized_producer() -> None:
    evidence = EvidenceObject(
        digest=_DIGEST,
        object_key=f"evidence/{_DIGEST}",
        object_version="version-01",
        producer="validator",
        request_digest=_DIGEST,
        media_type="application/json",
        retained_until="2026-09-20T12:00:00Z",
    )

    assert EvidenceObject.from_canonical_dict(evidence.to_canonical_dict()) == evidence
    with pytest.raises(CloudStateError, match="evidence_object_key_mismatch"):
        EvidenceObject(
            digest=_DIGEST,
            object_key="evidence/not-the-digest",
            object_version="version-01",
            producer="validator",
            request_digest=_DIGEST,
            media_type="application/json",
            retained_until="2026-09-20T12:00:00Z",
        )
    with pytest.raises(CloudStateError, match="evidence_authority_denied"):
        replace(evidence, producer="builder")
