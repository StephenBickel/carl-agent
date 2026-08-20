from __future__ import annotations

import base64
from dataclasses import replace
from inspect import signature

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from carl_bench.cloud_state import (
    AuthorityCapability,
    ClaimReconciliation,
    CloudCommand,
    CloudLease,
    CloudStateError,
    CommandClaim,
    CommandState,
    DeadHolderObservation,
    EvidenceObject,
    LeaseReconciliation,
    LeaseRelease,
    StateBackend,
    StateTransition,
    TrustedAuthorityKey,
    acquire_lease,
    authorize_evidence,
    claim_command,
    complete_command,
    create_command_state,
    fail_command,
    reconcile_expired_claim,
    reconcile_lease,
    release_lease,
    replay_command,
    verify_authority_capability,
    verify_dead_holder_observation,
)

_DIGEST = "a" * 64
_RESULT_DIGEST = "b" * 64
_TIMESTAMP = "2026-08-20T12:00:00Z"
_EXPIRES_AT = "2026-08-20T12:05:00Z"
_PRIVATE_KEY = Ed25519PrivateKey.generate()
_TRUSTED_KEY = TrustedAuthorityKey(
    key_id="state-test-key",
    public_key_pem=_PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ),
)


def _authority_capability(
    *,
    authority: str,
    subject_id: str,
    scope_kind: str,
    scope_key: str,
    revision: int,
    observed_at: str = _TIMESTAMP,
):
    unsigned = AuthorityCapability(
        schema_version=1,
        authority=authority,
        subject_id=subject_id,
        scope_kind=scope_kind,
        scope_key=scope_key,
        revision=revision,
        issued_at="2026-08-20T11:00:00Z",
        expires_at="2026-08-20T12:05:00Z",
        key_id="state-test-key",
        signature_base64=base64.b64encode(b"\0" * 64).decode("ascii"),
    )
    signed = replace(
        unsigned,
        signature_base64=base64.b64encode(_PRIVATE_KEY.sign(unsigned.signing_payload())).decode(
            "ascii"
        ),
    )
    return verify_authority_capability(signed, trusted_key=_TRUSTED_KEY, observed_at=observed_at)


def _dead_holder_observation(
    *,
    scope_kind: str,
    scope_key: str,
    holder_id: str,
    authority: str,
    revision: int,
    observed_at: str = _TIMESTAMP,
    live: bool = False,
):
    unsigned = DeadHolderObservation(
        schema_version=1,
        authority=authority,
        subject_id=holder_id,
        scope_kind=scope_kind,
        scope_key=scope_key,
        revision=revision,
        issued_at="2026-08-20T11:59:00Z",
        observed_at=observed_at,
        expires_at="2026-08-20T12:05:00Z",
        live=live,
        key_id="state-test-key",
        signature_base64=base64.b64encode(b"\0" * 64).decode("ascii"),
    )
    signed = replace(
        unsigned,
        signature_base64=base64.b64encode(_PRIVATE_KEY.sign(unsigned.signing_payload())).decode(
            "ascii"
        ),
    )
    return verify_dead_holder_observation(signed, trusted_key=_TRUSTED_KEY, observed_at=observed_at)


def _command_capability(revision: int, claim_id: str = "claim-improvement-01"):
    return _authority_capability(
        authority="coordinator",
        subject_id=claim_id,
        scope_kind="command",
        scope_key="dispatch-improvement-01",
        revision=revision,
    )


def _lease_capability(revision: int, holder_id: str) -> object:
    return _authority_capability(
        authority="coordinator",
        subject_id=holder_id,
        scope_kind="lease",
        scope_key="coordinator",
        revision=revision,
    )


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


def _complete_transition(*, expected_revision: int = 8) -> StateTransition:
    return StateTransition(
        command_key="dispatch-improvement-01",
        authority="coordinator",
        claim_id="claim-improvement-01",
        expected_revision=expected_revision,
        next_revision=expected_revision + 1,
        status="completed",
        occurred_at="2026-08-20T12:02:00Z",
        result_digest=_RESULT_DIGEST,
        failure_code=None,
    )


def _dead_liveness(*, revision: int, observed_at: str = _TIMESTAMP):
    return _dead_holder_observation(
        scope_kind="lease",
        scope_key="coordinator",
        holder_id="worker-a",
        authority="coordinator",
        revision=revision,
        observed_at=observed_at,
    )


def test_cloud_command_round_trips_with_deterministic_effect_key() -> None:
    first = _command()
    second = _command()

    assert first.effect_key == second.effect_key
    assert first.effect_key.startswith("cloud-effect-")
    assert CloudCommand.from_canonical_dict(first.to_canonical_dict()) == first


def test_changed_command_identity_changes_the_effect_key() -> None:
    original = _command()
    changed_commands = (
        CloudCommand.create(
            command_key="dispatch-improvement-02",
            authority="coordinator",
            operation="dispatch",
            request_digest=_DIGEST,
            occurred_at=_TIMESTAMP,
            expected_revision=7,
            attempt=1,
            max_attempts=3,
        ),
        CloudCommand.create(
            command_key="dispatch-improvement-01",
            authority="supervisor",
            operation="dispatch",
            request_digest=_DIGEST,
            occurred_at=_TIMESTAMP,
            expected_revision=7,
            attempt=1,
            max_attempts=3,
        ),
        CloudCommand.create(
            command_key="dispatch-improvement-01",
            authority="coordinator",
            operation="schedule",
            request_digest=_DIGEST,
            occurred_at=_TIMESTAMP,
            expected_revision=7,
            attempt=1,
            max_attempts=3,
        ),
        _command(request_digest="f" * 64),
    )

    assert all(changed.effect_key != original.effect_key for changed in changed_commands)


def test_forged_signed_capability_and_live_observation_are_rejected_before_reconciliation() -> None:
    capability = _command_capability(7).capability

    with pytest.raises(CloudStateError, match="trusted_authority_signature_invalid"):
        verify_authority_capability(
            replace(capability, signature_base64=base64.b64encode(b"\0" * 64).decode("ascii")),
            trusted_key=_TRUSTED_KEY,
            observed_at=_TIMESTAMP,
        )
    with pytest.raises(CloudStateError, match="dead_holder_observation_live"):
        _dead_holder_observation(
            scope_kind="command",
            scope_key="dispatch-improvement-01",
            holder_id="claim-improvement-01",
            authority="coordinator",
            revision=7,
            live=True,
        )


def test_active_lease_conflict_fails_before_recovery() -> None:
    active = CloudLease(
        lease_key="coordinator",
        holder_id="worker-a",
        authority="coordinator",
        revision=4,
        acquired_at="2026-08-20T11:59:00Z",
        expires_at=_EXPIRES_AT,
    )
    desired = CloudLease(
        lease_key="coordinator",
        holder_id="worker-b",
        authority="coordinator",
        revision=4,
        acquired_at=_TIMESTAMP,
        expires_at="2026-08-20T12:10:00Z",
    )

    with pytest.raises(CloudStateError, match="lease_active"):
        acquire_lease(
            active, desired, capability=_lease_capability(4, "worker-b"), observed_at=_TIMESTAMP
        )


def test_retry_metadata_is_strictly_bounded() -> None:
    with pytest.raises(CloudStateError, match="invalid_command_attempt"):
        CloudCommand.create(
            command_key="retry-04",
            authority="coordinator",
            operation="dispatch",
            request_digest=_DIGEST,
            occurred_at=_TIMESTAMP,
            expected_revision=0,
            attempt=4,
            max_attempts=4,
        )
    with pytest.raises(CloudStateError, match="invalid_command_max_attempts"):
        CloudCommand.create(
            command_key="retry-bool",
            authority="coordinator",
            operation="dispatch",
            request_digest=_DIGEST,
            occurred_at=_TIMESTAMP,
            expected_revision=0,
            attempt=1,
            max_attempts=True,
        )


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
        claim_command(
            state,
            replace(_claim(), authority="builder"),
            capability=_command_capability(7),
            observed_at=_TIMESTAMP,
        )
    with pytest.raises(CloudStateError, match="command_cas_mismatch"):
        claim_command(
            state,
            _claim(expected_revision=6),
            capability=_command_capability(7),
            observed_at=_TIMESTAMP,
        )


def test_claim_rejects_an_already_expired_holder_and_untrusted_context() -> None:
    state = create_command_state(_command())
    expired_claim = replace(
        _claim(),
        claimed_at="2026-08-20T11:00:00Z",
        expires_at="2026-08-20T11:05:00Z",
    )
    with pytest.raises(CloudStateError, match="command_claim_expired"):
        claim_command(
            state, expired_claim, capability=_command_capability(7), observed_at=_TIMESTAMP
        )
    with pytest.raises(CloudStateError, match="authority_capability_mismatch"):
        claim_command(
            state,
            _claim(),
            capability=_authority_capability(
                authority="builder",
                subject_id="claim-improvement-01",
                scope_kind="command",
                scope_key="dispatch-improvement-01",
                revision=7,
            ),
            observed_at=_TIMESTAMP,
        )


def test_command_claim_successor_is_idempotent_and_preserves_claim_time() -> None:
    state = create_command_state(_command())
    claimed = claim_command(
        state, _claim(), capability=_command_capability(7), observed_at=_TIMESTAMP
    )

    assert claimed.revision == 8
    assert claimed.claim == _claim()
    assert (
        claim_command(claimed, _claim(), capability=_command_capability(8), observed_at=_TIMESTAMP)
        == claimed
    )
    assert CommandState.from_canonical_dict(claimed.to_canonical_dict()) == claimed


def test_complete_requires_an_exact_result_identity() -> None:
    claimed = claim_command(
        create_command_state(_command()),
        _claim(),
        capability=_command_capability(7),
        observed_at=_TIMESTAMP,
    )
    transition = _complete_transition()

    completed = complete_command(
        claimed, transition, capability=_command_capability(8), observed_at="2026-08-20T12:02:00Z"
    )

    assert completed.result_digest == _RESULT_DIGEST
    assert (
        complete_command(
            completed,
            transition,
            capability=_command_capability(8),
            observed_at="2026-08-20T12:02:00Z",
        )
        == completed
    )
    with pytest.raises(CloudStateError, match="authority_capability_mismatch"):
        complete_command(
            completed,
            transition,
            capability=_authority_capability(
                authority="builder",
                subject_id="claim-improvement-01",
                scope_kind="command",
                scope_key="dispatch-improvement-01",
                revision=8,
            ),
            observed_at="2026-08-20T12:02:00Z",
        )
    with pytest.raises(CloudStateError, match="command_result_conflict"):
        complete_command(
            completed,
            replace(transition, result_digest="d" * 64),
            capability=_command_capability(8),
            observed_at="2026-08-20T12:02:00Z",
        )


def test_terminal_transition_must_chain_from_the_claim_revision() -> None:
    claimed = claim_command(
        create_command_state(_command()),
        _claim(),
        capability=_command_capability(7),
        observed_at=_TIMESTAMP,
    )

    with pytest.raises(CloudStateError, match="transition_claim_revision_mismatch"):
        complete_command(
            claimed,
            _complete_transition(expected_revision=7),
            capability=_command_capability(8),
            observed_at="2026-08-20T12:02:00Z",
        )


def test_fail_command_uses_the_same_fenced_claim_chain() -> None:
    claimed = claim_command(
        create_command_state(_command()),
        _claim(),
        capability=_command_capability(7),
        observed_at=_TIMESTAMP,
    )
    transition = StateTransition(
        command_key="dispatch-improvement-01",
        authority="coordinator",
        claim_id="claim-improvement-01",
        expected_revision=8,
        next_revision=9,
        status="failed",
        occurred_at="2026-08-20T12:02:00Z",
        result_digest=None,
        failure_code="timeout",
    )

    failed = fail_command(
        claimed, transition, capability=_command_capability(8), observed_at="2026-08-20T12:02:00Z"
    )

    assert failed.status == "failed"
    assert failed.failure_code == "timeout"


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


def test_expired_lease_requires_trusted_dead_worker_reconciliation_and_fenced_release() -> None:
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

    with pytest.raises(CloudStateError, match="lease_reconciliation_required"):
        acquire_lease(
            expired, successor, capability=_lease_capability(4, "worker-b"), observed_at=_TIMESTAMP
        )
    with pytest.raises(CloudStateError, match="dead_holder_observation_live"):
        _dead_holder_observation(
            scope_kind="lease",
            scope_key="coordinator",
            holder_id="worker-a",
            authority="coordinator",
            revision=4,
            live=True,
        )
    reconciliation = LeaseReconciliation(
        lease_key="coordinator",
        holder_id="worker-a",
        authority="coordinator",
        expected_revision=4,
        next_revision=5,
        observed_at=_TIMESTAMP,
    )
    dead_holder = _dead_liveness(revision=4)
    reconciled = reconcile_lease(
        expired,
        reconciliation,
        capability=_lease_capability(4, "worker-a"),
        dead_holder=dead_holder,
    )
    successor = replace(successor, revision=5)
    with pytest.raises(CloudStateError, match="lease_release_required"):
        acquire_lease(
            reconciled,
            successor,
            capability=_lease_capability(5, "worker-b"),
            observed_at=_TIMESTAMP,
        )
    released = release_lease(
        reconciled,
        LeaseRelease(
            lease_key="coordinator",
            holder_id="worker-a",
            authority="coordinator",
            expected_revision=5,
            next_revision=6,
            released_at="2026-08-20T12:01:00Z",
            observation_digest=dead_holder.digest,
        ),
        capability=_lease_capability(5, "worker-a"),
    )
    acquired = acquire_lease(
        released,
        replace(successor, revision=6),
        capability=_lease_capability(6, "worker-b"),
        observed_at=_TIMESTAMP,
    )

    assert acquired.revision == 7
    assert acquired.holder_id == "worker-b"
    assert CloudLease.from_canonical_dict(acquired.to_canonical_dict()) == acquired


def test_lease_reconciliation_and_release_are_both_revision_fenced() -> None:
    expired = CloudLease(
        lease_key="coordinator",
        holder_id="worker-a",
        authority="coordinator",
        revision=4,
        acquired_at="2026-08-20T11:00:00Z",
        expires_at="2026-08-20T11:05:00Z",
    )
    with pytest.raises(CloudStateError, match="lease_cas_mismatch"):
        reconcile_lease(
            expired,
            LeaseReconciliation(
                lease_key="coordinator",
                holder_id="worker-a",
                authority="coordinator",
                expected_revision=3,
                next_revision=4,
                observed_at=_TIMESTAMP,
            ),
            capability=_lease_capability(4, "worker-a"),
            dead_holder=_dead_liveness(revision=3),
        )
    dead_holder = _dead_liveness(revision=4)
    reconciled = reconcile_lease(
        expired,
        LeaseReconciliation(
            lease_key="coordinator",
            holder_id="worker-a",
            authority="coordinator",
            expected_revision=4,
            next_revision=5,
            observed_at=_TIMESTAMP,
        ),
        capability=_lease_capability(4, "worker-a"),
        dead_holder=dead_holder,
    )
    with pytest.raises(CloudStateError, match="lease_cas_mismatch"):
        release_lease(
            reconciled,
            LeaseRelease(
                lease_key="coordinator",
                holder_id="worker-a",
                authority="coordinator",
                expected_revision=4,
                next_revision=5,
                released_at="2026-08-20T12:01:00Z",
                observation_digest=dead_holder.digest,
            ),
            capability=_lease_capability(5, "worker-a"),
        )


def test_expired_claim_requires_trusted_reconciliation_before_reclaim() -> None:
    expired_claim = replace(
        _claim(),
        claimed_at="2026-08-20T11:00:00Z",
        expires_at="2026-08-20T11:05:00Z",
    )
    claimed = claim_command(
        create_command_state(_command()),
        expired_claim,
        capability=_command_capability(7),
        observed_at="2026-08-20T11:01:00Z",
    )
    with pytest.raises(CloudStateError, match="command_claim_expired"):
        complete_command(
            claimed,
            _complete_transition(),
            capability=_command_capability(8),
            observed_at=_TIMESTAMP,
        )
    reconciled = reconcile_expired_claim(
        claimed,
        ClaimReconciliation(
            command_key="dispatch-improvement-01",
            claim_id="claim-improvement-01",
            authority="coordinator",
            expected_revision=8,
            next_revision=9,
            observed_at=_TIMESTAMP,
        ),
        capability=_command_capability(8),
        dead_holder=_dead_holder_observation(
            scope_kind="command",
            scope_key="dispatch-improvement-01",
            holder_id="claim-improvement-01",
            authority="coordinator",
            revision=8,
        ),
    )

    assert reconciled.status == "pending"
    assert reconciled.revision == 9
    assert (
        claim_command(
            reconciled,
            replace(_claim(), expected_revision=9, claim_id="claim-improvement-02"),
            capability=_command_capability(9, "claim-improvement-02"),
            observed_at=_TIMESTAMP,
        ).revision
        == 10
    )


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
    with pytest.raises(CloudStateError, match="authority_capability_mismatch"):
        authorize_evidence(
            evidence,
            capability=_authority_capability(
                authority="coordinator",
                subject_id="version-01",
                scope_kind="evidence",
                scope_key=f"evidence/{_DIGEST}",
                revision=0,
            ),
            observed_at=_TIMESTAMP,
        )
    assert (
        authorize_evidence(
            evidence,
            capability=_authority_capability(
                authority="validator",
                subject_id="version-01",
                scope_kind="evidence",
                scope_key=f"evidence/{_DIGEST}",
                revision=0,
            ),
            observed_at=_TIMESTAMP,
        )
        == evidence
    )
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


def test_canonical_codecs_reject_extra_and_missing_fields() -> None:
    records = (
        (_command(), CloudCommand),
        (_claim(), CommandClaim),
        (
            CloudLease(
                lease_key="coordinator",
                holder_id="worker-a",
                authority="coordinator",
                revision=4,
                acquired_at="2026-08-20T11:00:00Z",
                expires_at="2026-08-20T11:05:00Z",
            ),
            CloudLease,
        ),
        (_complete_transition(), StateTransition),
        (_command_capability(7).capability, AuthorityCapability),
        (_dead_liveness(revision=4).observation, DeadHolderObservation),
        (
            ClaimReconciliation(
                command_key="dispatch-improvement-01",
                claim_id="claim-improvement-01",
                authority="coordinator",
                expected_revision=8,
                next_revision=9,
                observed_at=_TIMESTAMP,
            ),
            ClaimReconciliation,
        ),
        (
            LeaseReconciliation(
                lease_key="coordinator",
                holder_id="worker-a",
                authority="coordinator",
                expected_revision=4,
                next_revision=5,
                observed_at=_TIMESTAMP,
            ),
            LeaseReconciliation,
        ),
        (
            LeaseRelease(
                lease_key="coordinator",
                holder_id="worker-a",
                authority="coordinator",
                expected_revision=5,
                next_revision=6,
                released_at="2026-08-20T12:01:00Z",
                observation_digest="e" * 64,
            ),
            LeaseRelease,
        ),
    )
    for record, record_type in records:
        extra = record.to_canonical_dict() | {"unknown": "value"}
        missing = record.to_canonical_dict()
        del missing[next(iter(missing))]
        with pytest.raises(CloudStateError):
            record_type.from_canonical_dict(extra)
        with pytest.raises(CloudStateError):
            record_type.from_canonical_dict(missing)


def test_state_backend_exposes_every_fenced_mutation_boundary() -> None:
    required_methods = {
        "register_manifest",
        "append_event",
        "create_command",
        "claim_command",
        "complete_command",
        "fail_command",
        "reconcile_expired_claim",
        "acquire_lease",
        "reconcile_lease",
        "release_lease",
        "claim_supervisor_trigger",
        "resolve_supervisor_trigger",
        "load_projection",
        "register_evidence",
        "health_snapshot",
    }

    assert required_methods <= set(StateBackend.__dict__)
    for method_name in required_methods - {"load_projection", "health_snapshot"}:
        assert "capability" in signature(getattr(StateBackend, method_name)).parameters
    for method_name in {"reconcile_expired_claim", "reconcile_lease"}:
        assert "dead_holder" in signature(getattr(StateBackend, method_name)).parameters
