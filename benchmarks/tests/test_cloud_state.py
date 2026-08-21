from __future__ import annotations

import base64
import copy
import pickle
from dataclasses import replace
from datetime import UTC, datetime
from inspect import signature
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from carl_bench.cloud_state import (
    AuthorityCapability,
    AuthorityVerifier,
    ClaimReconciliation,
    CloudCommand,
    CloudLease,
    CloudStateError,
    CommandClaim,
    CommandState,
    DeadHolderObservation,
    EvidenceObject,
    HealthSnapshot,
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
)

_DIGEST = "a" * 64
_RESULT_DIGEST = "b" * 64
_TIMESTAMP = "2026-08-20T12:00:00Z"
_EXPIRES_AT = "2026-08-20T12:05:00Z"
_AUTHORITY_PRIVATE_KEY = Ed25519PrivateKey.generate()
_OBSERVATION_PRIVATE_KEY = Ed25519PrivateKey.generate()
_TRUSTED_KEY = TrustedAuthorityKey(
    key_id="state-test-authority-key",
    purpose="authority_capability",
    public_key_pem=_AUTHORITY_PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ),
)
_OBSERVATION_KEY = TrustedAuthorityKey(
    key_id="state-test-observation-key",
    purpose="dead_holder_observation",
    public_key_pem=_OBSERVATION_PRIVATE_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ),
)


def _clock(value: str = _TIMESTAMP):
    return lambda: datetime.fromisoformat(value.removesuffix("Z") + "+00:00").astimezone(UTC)


def _fixed_clock() -> datetime:
    return datetime(2026, 8, 20, 12, tzinfo=UTC)


def _verifier_at(value: str = _TIMESTAMP) -> AuthorityVerifier:
    return AuthorityVerifier(
        authority_key=_TRUSTED_KEY,
        dead_holder_key=_OBSERVATION_KEY,
        clock=_clock(value),
    )


_VERIFIER = _verifier_at()


def _authority_capability(
    *,
    authority: str,
    subject_id: str,
    scope_kind: str,
    scope_key: str,
    revision: int,
    action: str,
):
    unsigned = AuthorityCapability(
        schema_version=1,
        authority=authority,
        action=action,
        subject_id=subject_id,
        scope_kind=scope_kind,
        scope_key=scope_key,
        revision=revision,
        issued_at="2026-08-20T11:00:00Z",
        expires_at="2026-08-20T12:05:00Z",
        key_id="state-test-authority-key",
        signature_base64=base64.b64encode(b"\0" * 64).decode("ascii"),
    )
    signed = replace(
        unsigned,
        signature_base64=base64.b64encode(
            _AUTHORITY_PRIVATE_KEY.sign(unsigned.signing_payload())
        ).decode("ascii"),
    )
    return signed


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
        key_id="state-test-observation-key",
        signature_base64=base64.b64encode(b"\0" * 64).decode("ascii"),
    )
    signed = replace(
        unsigned,
        signature_base64=base64.b64encode(
            _OBSERVATION_PRIVATE_KEY.sign(unsigned.signing_payload())
        ).decode("ascii"),
    )
    return signed


def _command_capability(
    action: str, revision: int, claim_id: str = "claim-improvement-01"
) -> AuthorityCapability:
    return _authority_capability(
        authority="coordinator",
        subject_id=claim_id,
        scope_kind="command",
        scope_key="dispatch-improvement-01",
        revision=revision,
        action=action,
    )


def _lease_capability(action: str, revision: int, holder_id: str) -> AuthorityCapability:
    return _authority_capability(
        authority="coordinator",
        subject_id=holder_id,
        scope_kind="lease",
        scope_key="coordinator",
        revision=revision,
        action=action,
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


def test_verified_handles_are_not_part_of_the_authority_boundary() -> None:
    """Raw signed envelopes must be rechecked at the mutation, not wrapped once."""
    import carl_bench.cloud_state as cloud_state

    assert not hasattr(cloud_state, "VerifiedAuthority")
    assert not hasattr(cloud_state, "VerifiedDeadHolderObservation")


def test_authority_verifier_owns_a_trusted_clock() -> None:
    verifier = _verifier_at()

    assert verifier is not None


def test_authority_verifier_is_immutable_and_nontransferable() -> None:
    verifier = AuthorityVerifier(
        authority_key=_TRUSTED_KEY,
        dead_holder_key=_OBSERVATION_KEY,
        clock=_fixed_clock,
    )

    assert not hasattr(verifier, "__dict__")
    for attribute, replacement in (
        ("_clock", _clock("2026-08-20T12:01:00Z")),
        ("_authority_key", _OBSERVATION_KEY),
        ("_dead_holder_key", _TRUSTED_KEY),
    ):
        with pytest.raises(AttributeError, match="AuthorityVerifier is immutable"):
            setattr(verifier, attribute, replacement)
    for transfer in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match="AuthorityVerifier cannot be copied or serialized"):
            transfer(verifier)


def test_authority_verifier_rejects_reused_key_ids_or_key_bytes() -> None:
    other_private_key = Ed25519PrivateKey.generate()
    other_public_key_pem = other_private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with pytest.raises(CloudStateError, match="trusted_authority_keys_not_separated"):
        AuthorityVerifier(
            authority_key=_TRUSTED_KEY,
            dead_holder_key=replace(
                _TRUSTED_KEY,
                purpose="dead_holder_observation",
                key_id="different-observation-key-id",
            ),
            clock=_fixed_clock,
        )
    with pytest.raises(CloudStateError, match="trusted_authority_keys_not_separated"):
        AuthorityVerifier(
            authority_key=_TRUSTED_KEY,
            dead_holder_key=TrustedAuthorityKey(
                key_id=_TRUSTED_KEY.key_id,
                purpose="dead_holder_observation",
                public_key_pem=other_public_key_pem,
            ),
            clock=_fixed_clock,
        )


def test_capability_validity_is_closed_at_issue_and_open_at_expiry() -> None:
    capability = _command_capability("claim_command", 7)

    _verifier_at("2026-08-20T11:00:00Z").require_authority(
        capability,
        action="claim_command",
        authority="coordinator",
        subject_id="claim-improvement-01",
        scope_kind="command",
        scope_key="dispatch-improvement-01",
        revision=7,
    )
    with pytest.raises(CloudStateError, match="authority_capability_expired"):
        _verifier_at("2026-08-20T12:05:00Z").require_authority(
            capability,
            action="claim_command",
            authority="coordinator",
            subject_id="claim-improvement-01",
            scope_kind="command",
            scope_key="dispatch-improvement-01",
            revision=7,
        )
    with pytest.raises(CloudStateError, match="authority_capability_not_yet_valid"):
        _verifier_at("2026-08-20T10:59:59Z").require_authority(
            capability,
            action="claim_command",
            authority="coordinator",
            subject_id="claim-improvement-01",
            scope_kind="command",
            scope_key="dispatch-improvement-01",
            revision=7,
        )


def test_pure_mutation_captures_the_verifier_clock_once() -> None:
    observed_times: list[datetime] = []
    times = iter(
        (
            datetime(2026, 8, 20, 12, tzinfo=UTC),
            datetime(2026, 8, 20, 12, 6, tzinfo=UTC),
        )
    )

    def advancing_clock() -> datetime:
        observed_times.append(now := next(times))
        return now

    claimed = claim_command(
        create_command_state(_command()),
        _claim(),
        verifier=AuthorityVerifier(
            authority_key=_TRUSTED_KEY,
            dead_holder_key=_OBSERVATION_KEY,
            clock=advancing_clock,
        ),
        capability=_command_capability("claim_command", 7),
    )

    assert claimed.revision == 8
    assert observed_times == [datetime(2026, 8, 20, 12, tzinfo=UTC)]


def test_every_authorized_pure_mutation_reads_the_clock_once() -> None:
    evidence = EvidenceObject(
        digest=_DIGEST,
        object_key=f"evidence/{_DIGEST}",
        object_version="version-01",
        producer="validator",
        request_digest=_DIGEST,
        media_type="application/json",
        retained_until="2026-09-20T12:00:00Z",
    )
    claimed = claim_command(
        create_command_state(_command()),
        _claim(),
        verifier=_VERIFIER,
        capability=_command_capability("claim_command", 7),
    )
    failed_transition = replace(
        _complete_transition(), status="failed", result_digest=None, failure_code="timeout"
    )
    expired_claim = replace(
        _claim(), claimed_at="2026-08-20T11:00:00Z", expires_at="2026-08-20T11:05:00Z"
    )
    expired_claim_state = claim_command(
        create_command_state(_command()),
        expired_claim,
        verifier=_verifier_at("2026-08-20T11:01:00Z"),
        capability=_command_capability("claim_command", 7),
    )
    active_lease = CloudLease(
        lease_key="coordinator",
        holder_id="worker-a",
        authority="coordinator",
        revision=4,
        acquired_at="2026-08-20T11:00:00Z",
        expires_at="2026-08-20T12:05:00Z",
    )
    expired_lease = replace(active_lease, expires_at="2026-08-20T11:05:00Z")
    operations = (
        lambda verifier: authorize_evidence(
            evidence,
            verifier=verifier,
            capability=_authority_capability(
                authority="validator",
                subject_id="version-01",
                scope_kind="evidence",
                scope_key=f"evidence/{_DIGEST}",
                revision=0,
                action="register_evidence",
            ),
        ),
        lambda verifier: claim_command(
            create_command_state(_command()),
            _claim(),
            verifier=verifier,
            capability=_command_capability("claim_command", 7),
        ),
        lambda verifier: complete_command(
            claimed,
            _complete_transition(),
            verifier=verifier,
            capability=_command_capability("complete_command", 8),
        ),
        lambda verifier: fail_command(
            claimed,
            failed_transition,
            verifier=verifier,
            capability=_command_capability("fail_command", 8),
        ),
        lambda verifier: reconcile_expired_claim(
            expired_claim_state,
            ClaimReconciliation(
                command_key="dispatch-improvement-01",
                claim_id="claim-improvement-01",
                authority="coordinator",
                expected_revision=8,
                next_revision=9,
                observed_at=_TIMESTAMP,
            ),
            verifier=verifier,
            capability=_command_capability("reconcile_expired_claim", 8),
            dead_holder=_dead_holder_observation(
                scope_kind="command",
                scope_key="dispatch-improvement-01",
                holder_id="claim-improvement-01",
                authority="coordinator",
                revision=8,
            ),
        ),
        lambda verifier: acquire_lease(
            None,
            replace(
                active_lease,
                revision=0,
                acquired_at=_TIMESTAMP,
                expires_at="2026-08-20T12:05:00Z",
            ),
            verifier=verifier,
            capability=_lease_capability("acquire_lease", 0, "worker-a"),
        ),
        lambda verifier: reconcile_lease(
            expired_lease,
            LeaseReconciliation(
                lease_key="coordinator",
                holder_id="worker-a",
                authority="coordinator",
                expected_revision=4,
                next_revision=5,
                observed_at=_TIMESTAMP,
            ),
            verifier=verifier,
            capability=_lease_capability("reconcile_lease", 4, "worker-a"),
            dead_holder=_dead_liveness(revision=4),
        ),
        lambda verifier: release_lease(
            active_lease,
            LeaseRelease(
                lease_key="coordinator",
                holder_id="worker-a",
                authority="coordinator",
                expected_revision=4,
                next_revision=5,
                released_at="2026-08-20T12:01:00Z",
                observation_digest=None,
            ),
            verifier=verifier,
            capability=_lease_capability("release_lease", 4, "worker-a"),
        ),
    )

    for operation in operations:
        clock_reads = 0

        def counting_clock() -> datetime:
            nonlocal clock_reads
            clock_reads += 1
            return datetime(2026, 8, 20, 12, tzinfo=UTC)

        operation(
            AuthorityVerifier(
                authority_key=_TRUSTED_KEY,
                dead_holder_key=_OBSERVATION_KEY,
                clock=counting_clock,
            )
        )
        assert clock_reads == 1


def test_raw_envelope_mutation_is_reverified_at_the_claim_boundary() -> None:
    capability = _command_capability("claim_command", 7)
    object.__setattr__(capability, "action", "complete_command")

    with pytest.raises(CloudStateError, match="trusted_authority_signature_invalid"):
        claim_command(
            create_command_state(_command()),
            _claim(),
            verifier=_VERIFIER,
            capability=capability,
        )


def test_capability_action_is_exactly_bound_to_the_mutation() -> None:
    with pytest.raises(CloudStateError, match="authority_capability_mismatch"):
        claim_command(
            create_command_state(_command()),
            _claim(),
            verifier=_VERIFIER,
            capability=_command_capability("complete_command", 7),
        )


def test_verifier_clock_rejects_expired_capabilities() -> None:
    with pytest.raises(CloudStateError, match="authority_capability_expired"):
        claim_command(
            create_command_state(_command()),
            _claim(),
            verifier=_verifier_at("2026-08-20T12:06:00Z"),
            capability=_command_capability("claim_command", 7),
        )


def test_verifier_rejects_future_dead_holder_observations() -> None:
    expired = CloudLease(
        lease_key="coordinator",
        holder_id="worker-a",
        authority="coordinator",
        revision=4,
        acquired_at="2026-08-20T11:00:00Z",
        expires_at="2026-08-20T11:05:00Z",
    )
    with pytest.raises(CloudStateError, match="dead_holder_observation_future"):
        reconcile_lease(
            expired,
            LeaseReconciliation(
                lease_key="coordinator",
                holder_id="worker-a",
                authority="coordinator",
                expected_revision=4,
                next_revision=5,
                observed_at="2026-08-20T12:01:00Z",
            ),
            verifier=_VERIFIER,
            capability=_lease_capability("reconcile_lease", 4, "worker-a"),
            dead_holder=_dead_liveness(revision=4, observed_at="2026-08-20T12:01:00Z"),
        )


def test_dead_holder_observation_expires_at_the_exact_boundary() -> None:
    with pytest.raises(CloudStateError, match="dead_holder_observation_expired"):
        _verifier_at("2026-08-20T12:05:00Z").require_dead_holder(
            _dead_liveness(revision=4),
            authority="coordinator",
            subject_id="worker-a",
            scope_kind="lease",
            scope_key="coordinator",
            revision=4,
        )


def test_noncanonical_base64_signature_is_rejected_even_when_bytes_match() -> None:
    capability = _command_capability("claim_command", 7)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last_value = alphabet.index(capability.signature_base64[-3])
    alternate = alphabet[(last_value & 0b110000) | ((last_value + 1) & 0b001111)]
    noncanonical = f"{capability.signature_base64[:-3]}{alternate}=="

    assert base64.b64decode(noncanonical) == base64.b64decode(capability.signature_base64)
    with pytest.raises(CloudStateError, match="invalid_authority_capability_signature"):
        replace(capability, signature_base64=noncanonical)


def test_forged_signed_capability_and_live_observation_are_rejected_before_reconciliation() -> None:
    capability = _command_capability("claim_command", 7)

    with pytest.raises(CloudStateError, match="trusted_authority_signature_invalid"):
        claim_command(
            create_command_state(_command()),
            _claim(),
            verifier=_VERIFIER,
            capability=replace(
                capability, signature_base64=base64.b64encode(b"\0" * 64).decode("ascii")
            ),
        )
    with pytest.raises(CloudStateError, match="dead_holder_observation_live"):
        _VERIFIER.require_dead_holder(
            _dead_holder_observation(
                scope_kind="command",
                scope_key="dispatch-improvement-01",
                holder_id="claim-improvement-01",
                authority="coordinator",
                revision=7,
                live=True,
            ),
            authority="coordinator",
            subject_id="claim-improvement-01",
            scope_kind="command",
            scope_key="dispatch-improvement-01",
            revision=7,
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
            active,
            desired,
            verifier=_VERIFIER,
            capability=_lease_capability("acquire_lease", 4, "worker-b"),
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
            verifier=_VERIFIER,
            capability=_command_capability("claim_command", 7),
        )
    with pytest.raises(CloudStateError, match="command_cas_mismatch"):
        claim_command(
            state,
            _claim(expected_revision=6),
            verifier=_VERIFIER,
            capability=_command_capability("claim_command", 7),
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
            state,
            expired_claim,
            verifier=_VERIFIER,
            capability=_command_capability("claim_command", 7),
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
                action="claim_command",
            ),
            verifier=_VERIFIER,
        )


def test_command_claim_successor_is_idempotent_and_preserves_claim_time() -> None:
    state = create_command_state(_command())
    claimed = claim_command(
        state, _claim(), verifier=_VERIFIER, capability=_command_capability("claim_command", 7)
    )

    assert claimed.revision == 8
    assert claimed.claim == _claim()
    assert (
        claim_command(
            claimed,
            _claim(),
            verifier=_VERIFIER,
            capability=_command_capability("claim_command", 8),
        )
        == claimed
    )
    assert CommandState.from_canonical_dict(claimed.to_canonical_dict()) == claimed


def test_complete_requires_an_exact_result_identity() -> None:
    claimed = claim_command(
        create_command_state(_command()),
        _claim(),
        verifier=_VERIFIER,
        capability=_command_capability("claim_command", 7),
    )
    transition = _complete_transition()

    completed = complete_command(
        claimed,
        transition,
        verifier=_VERIFIER,
        capability=_command_capability("complete_command", 8),
    )

    assert completed.result_digest == _RESULT_DIGEST
    assert (
        complete_command(
            completed,
            transition,
            verifier=_VERIFIER,
            capability=_command_capability("complete_command", 8),
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
                action="complete_command",
            ),
            verifier=_VERIFIER,
        )
    with pytest.raises(CloudStateError, match="command_result_conflict"):
        complete_command(
            completed,
            replace(transition, result_digest="d" * 64),
            verifier=_VERIFIER,
            capability=_command_capability("complete_command", 8),
        )


def test_terminal_transition_must_chain_from_the_claim_revision() -> None:
    claimed = claim_command(
        create_command_state(_command()),
        _claim(),
        verifier=_VERIFIER,
        capability=_command_capability("claim_command", 7),
    )

    with pytest.raises(CloudStateError, match="transition_claim_revision_mismatch"):
        complete_command(
            claimed,
            _complete_transition(expected_revision=7),
            verifier=_VERIFIER,
            capability=_command_capability("complete_command", 8),
        )


def test_fail_command_uses_the_same_fenced_claim_chain() -> None:
    claimed = claim_command(
        create_command_state(_command()),
        _claim(),
        verifier=_VERIFIER,
        capability=_command_capability("claim_command", 7),
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
        claimed,
        transition,
        verifier=_VERIFIER,
        capability=_command_capability("fail_command", 8),
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
            expired,
            successor,
            verifier=_VERIFIER,
            capability=_lease_capability("acquire_lease", 4, "worker-b"),
        )
    with pytest.raises(CloudStateError, match="dead_holder_observation_live"):
        _VERIFIER.require_dead_holder(
            _dead_holder_observation(
                scope_kind="lease",
                scope_key="coordinator",
                holder_id="worker-a",
                authority="coordinator",
                revision=4,
                live=True,
            ),
            authority="coordinator",
            subject_id="worker-a",
            scope_kind="lease",
            scope_key="coordinator",
            revision=4,
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
        verifier=_VERIFIER,
        capability=_lease_capability("reconcile_lease", 4, "worker-a"),
        dead_holder=dead_holder,
    )
    successor = replace(successor, revision=5)
    with pytest.raises(CloudStateError, match="lease_release_required"):
        acquire_lease(
            reconciled,
            successor,
            verifier=_VERIFIER,
            capability=_lease_capability("acquire_lease", 5, "worker-b"),
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
        verifier=_VERIFIER,
        capability=_lease_capability("release_lease", 5, "worker-a"),
    )
    acquired = acquire_lease(
        released,
        replace(successor, revision=6),
        verifier=_VERIFIER,
        capability=_lease_capability("acquire_lease", 6, "worker-b"),
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
            verifier=_VERIFIER,
            capability=_lease_capability("reconcile_lease", 4, "worker-a"),
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
        verifier=_VERIFIER,
        capability=_lease_capability("reconcile_lease", 4, "worker-a"),
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
            verifier=_VERIFIER,
            capability=_lease_capability("release_lease", 5, "worker-a"),
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
        verifier=_verifier_at("2026-08-20T11:01:00Z"),
        capability=_command_capability("claim_command", 7),
    )
    with pytest.raises(CloudStateError, match="command_claim_expired"):
        complete_command(
            claimed,
            _complete_transition(),
            verifier=_VERIFIER,
            capability=_command_capability("complete_command", 8),
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
        verifier=_VERIFIER,
        capability=_command_capability("reconcile_expired_claim", 8),
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
            verifier=_VERIFIER,
            capability=_command_capability("claim_command", 9, "claim-improvement-02"),
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
                action="register_evidence",
            ),
            verifier=_VERIFIER,
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
                action="register_evidence",
            ),
            verifier=_VERIFIER,
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
        (_command_capability("claim_command", 7), AuthorityCapability),
        (_dead_liveness(revision=4), DeadHolderObservation),
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


def test_state_backend_owns_verifier_and_accepts_only_raw_signed_envelopes() -> None:
    mutation_methods = {
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
        "register_evidence",
        "record_health",
    }
    required_methods = mutation_methods | {"health_snapshot", "load_projection"}

    assert required_methods <= set(StateBackend.__dict__)
    constructor_parameters = signature(StateBackend.__init__).parameters
    assert set(constructor_parameters) == {"self", "verifier"}
    verifier_parameter = constructor_parameters["verifier"]
    assert verifier_parameter.kind.name == "KEYWORD_ONLY"
    assert verifier_parameter.annotation in {AuthorityVerifier, "AuthorityVerifier"}
    assert isinstance(StateBackend.__dict__["verifier"], property)
    for method_name in required_methods:
        parameters = signature(getattr(StateBackend, method_name)).parameters
        forbidden = {"authority_key", "clock", "dead_holder_key", "key", "verifier"}
        assert not (forbidden & set(parameters))
        assert "observed_at" not in parameters
    for method_name in mutation_methods:
        annotation = (
            signature(getattr(StateBackend, method_name)).parameters["capability"].annotation
        )
        assert annotation in {AuthorityCapability, "AuthorityCapability"}
    for method_name in {"reconcile_expired_claim", "reconcile_lease"}:
        annotation = (
            signature(getattr(StateBackend, method_name)).parameters["dead_holder"].annotation
        )
        assert annotation in {DeadHolderObservation, "DeadHolderObservation"}


@pytest.mark.parametrize(
    ("method_name", "action", "scope_kind"),
    (
        ("register_manifest", "register_manifest", "manifest"),
        ("append_event", "append_event", "event"),
        ("create_command", "create_command", "command"),
        ("claim_command", "claim_command", "command"),
        ("complete_command", "complete_command", "command"),
        ("fail_command", "fail_command", "command"),
        ("reconcile_expired_claim", "reconcile_expired_claim", "command"),
        ("acquire_lease", "acquire_lease", "lease"),
        ("reconcile_lease", "reconcile_lease", "lease"),
        ("release_lease", "release_lease", "lease"),
        ("claim_supervisor_trigger", "claim_supervisor_trigger", "supervisor_trigger"),
        ("resolve_supervisor_trigger", "resolve_supervisor_trigger", "supervisor_trigger"),
        ("register_evidence", "register_evidence", "evidence"),
        ("record_health", "record_health", "health"),
    ),
)
def test_every_backend_mutation_has_an_exact_action_and_scope_binding(
    method_name: str, action: str, scope_kind: str
) -> None:
    capability = _authority_capability(
        authority="coordinator",
        subject_id="subject-01",
        scope_kind=scope_kind,
        scope_key=f"{scope_kind}-01",
        revision=3,
        action=action,
    )

    assert method_name in StateBackend.__dict__
    _VERIFIER.require_authority(
        capability,
        action=action,
        authority="coordinator",
        subject_id="subject-01",
        scope_kind=scope_kind,
        scope_key=f"{scope_kind}-01",
        revision=3,
    )
    different_action = "append_event" if action != "append_event" else "register_manifest"
    with pytest.raises(CloudStateError, match="authority_capability_mismatch"):
        _VERIFIER.require_authority(
            capability,
            action=different_action,
            authority="coordinator",
            subject_id="subject-01",
            scope_kind=scope_kind,
            scope_key=f"{scope_kind}-01",
            revision=3,
        )


class _FakeStateBackend(StateBackend):
    def __init__(self, *, verifier: AuthorityVerifier) -> None:
        self.hook_calls: list[str] = []
        super().__init__(verifier=verifier)

    def _record(self, name: str) -> str:
        self.hook_calls.append(name)
        return name

    def _register_manifest(self, manifest, *, observed_at):
        return self._record("register_manifest")

    def _append_event(self, event, *, observed_at):
        return self._record("append_event")

    def _create_command(self, command, *, observed_at):
        return self._record("create_command")

    def _claim_command(self, claim, *, observed_at):
        return self._record("claim_command")

    def _complete_command(self, transition, *, observed_at):
        return self._record("complete_command")

    def _fail_command(self, transition, *, observed_at):
        return self._record("fail_command")

    def _reconcile_expired_claim(self, reconciliation, *, dead_holder, observed_at):
        return self._record("reconcile_expired_claim")

    def _acquire_lease(self, desired, *, observed_at):
        return self._record("acquire_lease")

    def _reconcile_lease(self, reconciliation, *, dead_holder, observed_at):
        return self._record("reconcile_lease")

    def _release_lease(self, release, *, observed_at):
        return self._record("release_lease")

    def _claim_supervisor_trigger(self, *, trigger_id, claim_id, expected_revision, observed_at):
        return self._record("claim_supervisor_trigger")

    def _resolve_supervisor_trigger(
        self, *, trigger_id, claim_id, expected_revision, resolution, observed_at
    ):
        return self._record("resolve_supervisor_trigger")

    def _register_evidence(self, evidence, *, observed_at):
        return self._record("register_evidence")

    def _record_health(self, snapshot, *, observed_at):
        return self._record("record_health")

    def load_projection(self, experiment_id):
        raise NotImplementedError

    def health_snapshot(self):
        raise NotImplementedError


def test_state_backend_wrappers_enforce_exact_actions_before_storage_hooks() -> None:
    backend = _FakeStateBackend(verifier=_VERIFIER)
    command = _command()
    claim = _claim()
    transition = _complete_transition()
    reconciliation = ClaimReconciliation(
        command_key=command.command_key,
        claim_id=claim.claim_id,
        authority=claim.authority,
        expected_revision=8,
        next_revision=9,
        observed_at=_TIMESTAMP,
    )
    lease = CloudLease(
        lease_key="coordinator",
        holder_id="worker-a",
        authority="coordinator",
        revision=4,
        acquired_at="2026-08-20T11:00:00Z",
        expires_at="2026-08-20T11:05:00Z",
    )
    lease_reconciliation = LeaseReconciliation(
        lease_key=lease.lease_key,
        holder_id=lease.holder_id,
        authority=lease.authority,
        expected_revision=lease.revision,
        next_revision=lease.revision + 1,
        observed_at=_TIMESTAMP,
    )
    release = LeaseRelease(
        lease_key=lease.lease_key,
        holder_id=lease.holder_id,
        authority=lease.authority,
        expected_revision=lease.revision,
        next_revision=lease.revision + 1,
        released_at=_TIMESTAMP,
        observation_digest=None,
    )
    evidence = EvidenceObject(
        digest=_DIGEST,
        object_key=f"evidence/{_DIGEST}",
        object_version="version-01",
        producer="validator",
        request_digest=_DIGEST,
        media_type="application/json",
        retained_until="2026-09-20T12:00:00Z",
    )
    health = HealthSnapshot(observed_at=_TIMESTAMP, healthy=True, detail_digest=_DIGEST)
    manifest = SimpleNamespace(experiment_id="experiment-01")
    event = SimpleNamespace(experiment_id="experiment-01", stage_attempt_id="attempt-01")
    resolution = SimpleNamespace(status="resolved")
    dead_claim = _dead_holder_observation(
        scope_kind="command",
        scope_key=command.command_key,
        holder_id=claim.claim_id,
        authority=claim.authority,
        revision=reconciliation.expected_revision,
    )
    dead_lease = _dead_liveness(revision=lease.revision)

    operations = (
        (
            "register_manifest",
            dict(
                authority="builder",
                subject_id=manifest.experiment_id,
                scope_kind="manifest",
                scope_key=manifest.experiment_id,
                revision=0,
            ),
            lambda capability: backend.register_manifest(manifest, capability=capability),
        ),
        (
            "append_event",
            dict(
                authority="builder",
                subject_id=event.stage_attempt_id,
                scope_kind="event",
                scope_key=event.experiment_id,
                revision=0,
            ),
            lambda capability: backend.append_event(event, capability=capability),
        ),
        (
            "create_command",
            dict(
                authority=command.authority,
                subject_id=command.effect_key,
                scope_kind="command",
                scope_key=command.command_key,
                revision=command.expected_revision,
            ),
            lambda capability: backend.create_command(command, capability=capability),
        ),
        (
            "claim_command",
            dict(
                authority=claim.authority,
                subject_id=claim.claim_id,
                scope_kind="command",
                scope_key=claim.command_key,
                revision=claim.expected_revision,
            ),
            lambda capability: backend.claim_command(claim, capability=capability),
        ),
        (
            "complete_command",
            dict(
                authority=transition.authority,
                subject_id=transition.claim_id,
                scope_kind="command",
                scope_key=transition.command_key,
                revision=transition.expected_revision,
            ),
            lambda capability: backend.complete_command(transition, capability=capability),
        ),
        (
            "fail_command",
            dict(
                authority=transition.authority,
                subject_id=transition.claim_id,
                scope_kind="command",
                scope_key=transition.command_key,
                revision=transition.expected_revision,
            ),
            lambda capability: backend.fail_command(transition, capability=capability),
        ),
        (
            "reconcile_expired_claim",
            dict(
                authority=reconciliation.authority,
                subject_id=reconciliation.claim_id,
                scope_kind="command",
                scope_key=reconciliation.command_key,
                revision=reconciliation.expected_revision,
            ),
            lambda capability: backend.reconcile_expired_claim(
                reconciliation, capability=capability, dead_holder=dead_claim
            ),
        ),
        (
            "acquire_lease",
            dict(
                authority=lease.authority,
                subject_id=lease.holder_id,
                scope_kind="lease",
                scope_key=lease.lease_key,
                revision=lease.revision,
            ),
            lambda capability: backend.acquire_lease(lease, capability=capability),
        ),
        (
            "reconcile_lease",
            dict(
                authority=lease_reconciliation.authority,
                subject_id=lease_reconciliation.holder_id,
                scope_kind="lease",
                scope_key=lease_reconciliation.lease_key,
                revision=lease_reconciliation.expected_revision,
            ),
            lambda capability: backend.reconcile_lease(
                lease_reconciliation, capability=capability, dead_holder=dead_lease
            ),
        ),
        (
            "release_lease",
            dict(
                authority=release.authority,
                subject_id=release.holder_id,
                scope_kind="lease",
                scope_key=release.lease_key,
                revision=release.expected_revision,
            ),
            lambda capability: backend.release_lease(release, capability=capability),
        ),
        (
            "claim_supervisor_trigger",
            dict(
                authority="supervisor",
                subject_id="trigger-claim-01",
                scope_kind="supervisor_trigger",
                scope_key="trigger-01",
                revision=3,
            ),
            lambda capability: backend.claim_supervisor_trigger(
                trigger_id="trigger-01",
                claim_id="trigger-claim-01",
                expected_revision=3,
                capability=capability,
            ),
        ),
        (
            "resolve_supervisor_trigger",
            dict(
                authority="supervisor",
                subject_id="trigger-claim-01",
                scope_kind="supervisor_trigger",
                scope_key="trigger-01",
                revision=3,
            ),
            lambda capability: backend.resolve_supervisor_trigger(
                trigger_id="trigger-01",
                claim_id="trigger-claim-01",
                expected_revision=3,
                resolution=resolution,
                capability=capability,
            ),
        ),
        (
            "register_evidence",
            dict(
                authority=evidence.producer,
                subject_id=evidence.object_version,
                scope_kind="evidence",
                scope_key=evidence.object_key,
                revision=0,
            ),
            lambda capability: backend.register_evidence(evidence, capability=capability),
        ),
        (
            "record_health",
            dict(
                authority="observer",
                subject_id=health.detail_digest,
                scope_kind="health",
                scope_key=health.detail_digest,
                revision=0,
            ),
            lambda capability: backend.record_health(health, capability=capability),
        ),
    )

    for action, binding, invoke in operations:
        assert invoke(_authority_capability(action=action, **binding)) == action
        before = list(backend.hook_calls)
        wrong_action = "append_event" if action != "append_event" else "register_manifest"
        with pytest.raises(CloudStateError, match="authority_capability_mismatch"):
            invoke(_authority_capability(action=wrong_action, **binding))
        assert backend.hook_calls == before


def test_state_backend_rejects_public_mutation_overrides() -> None:
    with pytest.raises(TypeError, match="cannot override authorized mutation"):

        class UnsafeBackend(_FakeStateBackend):
            def claim_command(self, claim, *, capability):
                return self._claim_command(claim, observed_at=_fixed_clock())
