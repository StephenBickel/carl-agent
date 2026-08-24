from __future__ import annotations

import base64
import copy
import json
import os
import pickle
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_candidate_git import _repository
from test_experiment import manifest, sealed_candidate

import carl_bench.experimental_publication as experimental_publication
from carl_bench import cli
from carl_bench.canonical import canonical_json_bytes
from carl_bench.capability_validation import (
    ExperimentalCheckResult,
    ExperimentalLocalGateResult,
    ExperimentalPublicationEligibility,
    ExperimentalReviewDisposition,
    experimental_evidence_digest,
    experimental_publication_request_digest,
)
from carl_bench.experimental_publication import (
    ExperimentalEligibilityVerifier,
    ExperimentalPublicationError,
    ExperimentalPublicationPolicy,
    ExperimentalPublicationRequest,
    SignedExperimentalPublicationEligibility,
    publish_experimental_branch,
    reconcile_experimental_publication,
)
from carl_bench.ledger import ExperimentLedger
from carl_bench.promotion import PromotionContractError, SignedProtectedValidation

REQUESTED_AT = "2026-08-10T12:02:00Z"
EXPIRES_AT = "2026-08-10T13:02:00Z"
ELIGIBILITY_KEY_ID = "experimental-eligibility-v1"
ELIGIBILITY_ISSUER = "protected-experimental-validator"
ELIGIBILITY_PRIVATE_KEY = Ed25519PrivateKey.generate()
ELIGIBILITY_PUBLIC_KEY = ELIGIBILITY_PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
REPOSITORY_ID = "StephenBickel/carl-agent"
CANONICAL_REMOTE_URL = "https://github.com/StephenBickel/carl-agent.git"


class _RecordingGitTransport:
    def __init__(self, actual_remote: Path) -> None:
        self.actual_remote = actual_remote
        self.network_commands: list[tuple[str, str, tuple[str, ...]]] = []

    def local(self, repository: Path, *args: str) -> str:
        return subprocess.run(
            ("/usr/bin/git", "-C", os.fspath(repository), *args),
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def network(self, repository: Path, operation: str, remote_url: str, *args: str) -> str:
        self.network_commands.append((operation, remote_url, args))
        if operation == "ls-remote":
            command = (operation, "--refs", os.fspath(self.actual_remote), *args)
        else:
            command = (operation, args[0], os.fspath(self.actual_remote), args[1])
        result = subprocess.run(
            ("/usr/bin/git", "-C", os.fspath(repository), *command),
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ExperimentalPublicationError("experimental_git_failed")
        return result.stdout.strip()


def _policy() -> ExperimentalPublicationPolicy:
    return ExperimentalPublicationPolicy(
        schema_version=1,
        key_id=ELIGIBILITY_KEY_ID,
        public_key_pem=ELIGIBILITY_PUBLIC_KEY,
        repository_id=REPOSITORY_ID,
        remote_url=CANONICAL_REMOTE_URL,
    )


def _policy_json() -> dict[str, object]:
    return {
        "key_id": ELIGIBILITY_KEY_ID,
        "public_key_pem": ELIGIBILITY_PUBLIC_KEY.decode("ascii"),
        "remote_url": CANONICAL_REMOTE_URL,
        "repository_id": REPOSITORY_ID,
        "schema_version": 1,
    }


def _write_policy(path: Path) -> None:
    path.parent.mkdir(parents=True, mode=0o700)
    path.parent.chmod(0o700)
    path.write_bytes(canonical_json_bytes(_policy_json()))
    path.chmod(0o600)


def test_experimental_eligibility_verifier_is_immutable_and_production_distinct() -> None:
    verifier = ExperimentalEligibilityVerifier(
        policy=_policy(),
        clock=lambda: datetime(2026, 8, 10, 12, 2, tzinfo=UTC),
    )

    for operation in (
        lambda: setattr(verifier, "_clock", lambda: datetime.now(UTC)),
        lambda: copy.copy(verifier),
        lambda: copy.deepcopy(verifier),
        lambda: pickle.dumps(verifier),
    ):
        with pytest.raises((AttributeError, TypeError)):
            operation()
    with pytest.raises(TypeError, match="cannot be subclassed"):

        class BypassVerifier(ExperimentalEligibilityVerifier):
            def require(self, envelope: object, request: object) -> None:
                return None

    with pytest.raises(TypeError, match="cannot be subclassed"):

        class BypassPolicy(ExperimentalPublicationPolicy):
            pass

    with pytest.raises(TypeError, match="cannot be subclassed"):

        class BypassEnvelope(SignedExperimentalPublicationEligibility):
            pass

    with pytest.raises(TypeError, match="cannot be subclassed"):

        class BypassReceipt(ExperimentalPublicationEligibility):
            pass

    with pytest.raises(PromotionContractError, match="invalid_protected_receipt"):
        SignedProtectedValidation(
            receipt=_signed_eligibility(_request()),  # type: ignore[arg-type]
            key_id="production-key",
            signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
        )


def test_fixed_policy_loader_securely_reads_one_canonical_controller_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "controller" / "experimental-eligibility-policy.json"
    tmp_path.chmod(0o700)
    _write_policy(path)
    monkeypatch.setattr(cli, "_experimental_eligibility_policy_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_experimental_eligibility_policy_path", lambda: path)

    assert cli._experimental_eligibility_policy() == _policy()


@pytest.mark.parametrize(
    "mutation",
    ["missing", "file_symlink", "parent_symlink", "writable_file", "writable_parent"],
)
def test_fixed_policy_loader_rejects_missing_symlinked_or_writable_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    path = tmp_path / "controller" / "experimental-eligibility-policy.json"
    tmp_path.chmod(0o700)
    _write_policy(path)
    if mutation == "missing":
        path.unlink()
    elif mutation == "file_symlink":
        target = tmp_path / "policy-target.json"
        target.write_bytes(canonical_json_bytes(_policy_json()))
        target.chmod(0o600)
        path.unlink()
        path.symlink_to(target)
    elif mutation == "parent_symlink":
        target_parent = tmp_path / "protected-controller"
        target_path = target_parent / path.name
        _write_policy(target_path)
        path.unlink()
        path.parent.rmdir()
        path.parent.symlink_to(target_parent, target_is_directory=True)
    elif mutation == "writable_file":
        path.chmod(0o622)
    else:
        path.parent.chmod(0o722)
    monkeypatch.setattr(cli, "_experimental_eligibility_policy_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_experimental_eligibility_policy_path", lambda: path)

    with pytest.raises(ValueError, match="experimental eligibility protected policy"):
        cli._experimental_eligibility_policy()


@pytest.mark.parametrize("content", [b'{"schema_version":1}', b'{ "schema_version": 1 }'])
def test_fixed_policy_loader_rejects_nonexact_or_noncanonical_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: bytes,
) -> None:
    path = tmp_path / "controller" / "experimental-eligibility-policy.json"
    tmp_path.chmod(0o700)
    _write_policy(path)
    path.write_bytes(content)
    path.chmod(0o600)
    monkeypatch.setattr(cli, "_experimental_eligibility_policy_root", lambda: tmp_path)
    monkeypatch.setattr(cli, "_experimental_eligibility_policy_path", lambda: path)

    with pytest.raises(ValueError, match="experimental eligibility protected policy"):
        cli._experimental_eligibility_policy()


def _eligibility(
    request: ExperimentalPublicationRequest,
    **changes: object,
) -> ExperimentalPublicationEligibility:
    packet = request.candidate_packet
    values: dict[str, object] = {
        "schema_version": 1,
        "receipt_type": "experimental_publication_eligibility",
        "receipt_id": f"eligibility-{request.request_id}",
        "issuer": ELIGIBILITY_ISSUER,
        "key_id": ELIGIBILITY_KEY_ID,
        "request_id": request.request_id,
        "requested_at": request.requested_at,
        "repository_id": request.repository_id,
        "remote_url": request.remote_url,
        "request_digest": "",
        "effect_digest": "",
        "experiment_id": request.experiment_id,
        "branch": request.branch,
        "ref": f"refs/heads/{request.branch}",
        "candidate_packet_digest": packet.digest,
        "candidate_commit": packet.candidate_commit,
        "candidate_tree": request.candidate_tree,
        "required_checks": tuple(
            ExperimentalCheckResult(
                check_id=check.check_id,
                status=check.status,
                exit_code=check.exit_code,
                output_digest=check.output_artifact.digest,
            )
            for check in packet.checks
        ),
        "builder_id": "builder-carl-001",
        "review_dispositions": tuple(
            ExperimentalReviewDisposition(
                role=role,
                reviewer_id=f"reviewer-{role}",
                context_id=f"context-{role}",
                experiment_id=request.experiment_id,
                candidate_packet_digest=packet.digest,
                candidate_commit=packet.candidate_commit,
                candidate_tree=request.candidate_tree,
                packet_digest=character * 64,
                report_digest=report_character * 64,
                verdict="approve",
            )
            for role, character, report_character in (
                ("benchmark_integrity", "a", "e"),
                ("correctness", "b", "f"),
                ("maintainability", "c", "1"),
                ("security", "d", "2"),
            )
        ),
        "security_result": "pass",
        "local_gates": tuple(
            ExperimentalLocalGateResult(
                gate_id=gate_id,
                result="pass",
                candidate_packet_digest=packet.digest,
                candidate_commit=packet.candidate_commit,
                candidate_tree=request.candidate_tree,
                evidence_digest=character * 64,
            )
            for gate_id, character in (
                ("deterministic_checks", "1"),
                ("independent_reviews", "2"),
                ("repository_tests", "3"),
                ("security_review", "4"),
            )
        ),
        "evidence_digest": "",
        "issued_at": "2026-08-10T12:01:00Z",
        "expires_at": EXPIRES_AT,
    }
    values.update(changes)
    if "ref" not in changes:
        values["ref"] = f"refs/heads/{values['branch']}"
    values["request_digest"] = experimental_publication_request_digest(
        request_id=values["request_id"],
        requested_at=values["requested_at"],
        experiment_id=values["experiment_id"],
        branch=values["branch"],
        candidate_packet_digest=values["candidate_packet_digest"],
        candidate_commit=values["candidate_commit"],
        candidate_tree=values["candidate_tree"],
        repository_id=values["repository_id"],
        remote_url=values["remote_url"],
    )
    values["effect_digest"] = values["request_digest"]
    values["evidence_digest"] = experimental_evidence_digest(
        required_checks=values["required_checks"],
        builder_id=values["builder_id"],
        review_dispositions=values["review_dispositions"],
        security_result=values["security_result"],
        local_gates=values["local_gates"],
    )
    return ExperimentalPublicationEligibility(**values)  # type: ignore[arg-type]


def _signed_eligibility(
    request: ExperimentalPublicationRequest,
    *,
    private_key: Ed25519PrivateKey = ELIGIBILITY_PRIVATE_KEY,
    **changes: object,
) -> SignedExperimentalPublicationEligibility:
    receipt = _eligibility(request, **changes)
    unsigned = SignedExperimentalPublicationEligibility(
        receipt=receipt,
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )
    return replace(
        unsigned,
        signature_base64=base64.b64encode(private_key.sign(unsigned.signing_payload())).decode(
            "ascii"
        ),
    )


def _verifier(
    now: datetime = datetime(2026, 8, 10, 12, 2, tzinfo=UTC),
    *,
    clock: object | None = None,
) -> ExperimentalEligibilityVerifier:
    selected_clock = clock if clock is not None else (lambda: now)
    return ExperimentalEligibilityVerifier(
        policy=_policy(),
        clock=selected_clock,  # type: ignore[arg-type]
    )


def _request(
    *,
    experiment_id: str = "exp-publication-001",
    candidate_commit: str = "a" * 40,
    candidate_tree: str = "b" * 40,
    request_id: str = "publish-experimental-001",
    requested_at: str = REQUESTED_AT,
) -> ExperimentalPublicationRequest:
    selected = replace(manifest(), experiment_id=experiment_id)
    packet = replace(
        sealed_candidate(),
        experiment_id=experiment_id,
        manifest_digest=selected.digest,
        candidate_commit=candidate_commit,
    )
    request = ExperimentalPublicationRequest(
        experiment_id=experiment_id,
        branch=f"experimental/{experiment_id}",
        candidate_packet=packet,
        candidate_tree=candidate_tree,
        request_id=request_id,
        requested_at=requested_at,
        repository_id=REPOSITORY_ID,
        remote_url=CANONICAL_REMOTE_URL,
    )
    return request


def _reconcile(
    request: ExperimentalPublicationRequest,
    remote_snapshot: str | None,
    *,
    eligibility: SignedExperimentalPublicationEligibility | None = None,
    verifier: ExperimentalEligibilityVerifier | None = None,
):
    return reconcile_experimental_publication(
        request,
        remote_snapshot,
        verifier=verifier or _verifier(),
        eligibility=eligibility or _signed_eligibility(request),
    )


def test_reconciliation_pushes_only_the_exact_experimental_ref() -> None:
    request = _request()

    decision = _reconcile(request, remote_snapshot=None)

    assert decision.outcome == "push_branch"
    assert decision.ref == "refs/heads/experimental/exp-publication-001"
    assert decision.candidate_commit == "a" * 40
    assert decision.candidate_tree == "b" * 40
    assert decision.candidate_packet_digest == request.candidate_packet.digest


def test_reconciliation_records_an_existing_exact_experimental_branch() -> None:
    request = _request()

    decision = _reconcile(request, remote_snapshot="a" * 40)

    assert decision.outcome == "record_existing_exact_branch"


def test_reconciliation_blocks_an_existing_branch_with_a_different_commit() -> None:
    decision = _reconcile(_request(), remote_snapshot="c" * 40)

    assert decision.outcome == "blocked_branch_identity_mismatch"


def test_reconciliation_blocks_an_incomplete_candidate_packet() -> None:
    request = _request()
    incomplete = replace(request.candidate_packet, experiment_id="other-experiment")

    changed = replace(request, candidate_packet=incomplete)
    decision = _reconcile(changed, remote_snapshot=None, eligibility=_signed_eligibility(request))

    assert decision.outcome == "blocked_candidate_packet_incomplete"


def test_reconciliation_blocks_a_candidate_without_exact_local_eligibility() -> None:
    request = _request()
    receipt = _eligibility(request)
    failed_gates = tuple(
        replace(gate, result="fail") if gate.gate_id == "repository_tests" else gate
        for gate in receipt.local_gates
    )
    decision = _reconcile(
        request,
        remote_snapshot=None,
        eligibility=_signed_eligibility(request, local_gates=failed_gates),
    )

    assert decision.outcome == "blocked_candidate_not_locally_eligible"


def test_eligibility_is_frozen_canonical_request_bound_and_not_a_production_receipt() -> None:
    request = _request()
    eligibility = _eligibility(request)

    assert (
        ExperimentalPublicationEligibility.from_canonical_dict(eligibility.to_canonical_dict())
        == eligibility
    )
    assert len(eligibility.digest) == 64
    assert eligibility.request_digest == experimental_publication_request_digest(
        request_id=request.request_id,
        requested_at=request.requested_at,
        experiment_id=request.experiment_id,
        branch=request.branch,
        candidate_packet_digest=request.candidate_packet.digest,
        candidate_commit=request.candidate_packet.candidate_commit,
        candidate_tree=request.candidate_tree,
        repository_id=request.repository_id,
        remote_url=request.remote_url,
    )
    with pytest.raises(AttributeError):
        eligibility.security_result = "fail"  # type: ignore[misc]
    with pytest.raises(PromotionContractError, match="invalid_protected_receipt"):
        SignedProtectedValidation(
            receipt=eligibility,  # type: ignore[arg-type]
            key_id="carl-protected-validator-2026-01",
            signature_base64="A" * 88,
        )


@pytest.mark.parametrize(
    "change",
    [
        {
            "experiment_id": "exp-publication-other",
            "branch": "experimental/exp-publication-other",
        },
        {"candidate_packet_digest": "9" * 64},
        {"candidate_commit": "9" * 40},
        {"candidate_tree": "9" * 40},
        {"request_id": "publish-experimental-other"},
        {"requested_at": "2026-08-10T12:03:00Z"},
    ],
)
def test_reconciliation_rejects_reused_or_mismatched_receipt(change: dict[str, object]) -> None:
    request = _request()

    decision = _reconcile(
        request,
        remote_snapshot=None,
        eligibility=_signed_eligibility(request, **change),
    )

    assert decision.outcome == "blocked_candidate_not_locally_eligible"


def test_reconciliation_rejects_stale_checks_reviews_security_and_local_gates() -> None:
    request = _request()
    receipt = _eligibility(request)
    mismatched_checks = (replace(receipt.required_checks[0], output_digest="9" * 64),)
    benchmark_only = (receipt.review_dispositions[0],)
    self_authored = tuple(
        replace(review, reviewer_id=receipt.builder_id) if review.role == "correctness" else review
        for review in receipt.review_dispositions
    )
    mismatched_review = (
        replace(receipt.review_dispositions[0], candidate_packet_digest="9" * 64),
        *receipt.review_dispositions[1:],
    )
    mismatched_gate = (
        replace(receipt.local_gates[0], candidate_tree="9" * 40),
        *receipt.local_gates[1:],
    )
    receipts = (
        _signed_eligibility(request, required_checks=mismatched_checks),
        _signed_eligibility(request, review_dispositions=benchmark_only),
        _signed_eligibility(request, review_dispositions=self_authored),
        _signed_eligibility(request, review_dispositions=mismatched_review),
        _signed_eligibility(request, security_result="fail"),
        _signed_eligibility(request, local_gates=mismatched_gate),
        _signed_eligibility(
            request,
            local_gates=tuple(
                replace(gate, result="fail") if gate.gate_id == "security_review" else gate
                for gate in receipt.local_gates
            ),
        ),
    )

    for eligibility in receipts:
        decision = _reconcile(request, remote_snapshot=None, eligibility=eligibility)
        assert decision.outcome == "blocked_candidate_not_locally_eligible"


@pytest.mark.parametrize("mutation", ["missing", "extra", "nested_extra"])
def test_eligibility_parser_rejects_nonexact_fields(mutation: str) -> None:
    eligibility = _eligibility(_request())
    value = eligibility.to_canonical_dict()
    if mutation == "missing":
        value.pop("candidate_tree")
    elif mutation == "extra":
        value["live_capability_validated"] = True
    else:
        value["required_checks"][0]["unexpected"] = True

    with pytest.raises(ValueError, match="experimental_eligibility"):
        ExperimentalPublicationEligibility.from_canonical_dict(value)


def test_trusted_clock_rejects_expired_receipt_even_when_request_is_backdated() -> None:
    request = _request(requested_at="2026-08-10T12:02:00Z")

    decision = _reconcile(
        request,
        None,
        verifier=_verifier(datetime(2026, 8, 10, 13, 2, tzinfo=UTC)),
    )

    assert decision.outcome == "blocked_candidate_not_locally_eligible"


def test_trusted_clock_rejects_receipt_issued_in_the_future() -> None:
    request = _request()
    future = _signed_eligibility(
        request,
        issued_at="2026-08-10T12:03:00Z",
        expires_at="2026-08-10T13:03:00Z",
    )

    decision = _reconcile(request, None, eligibility=future)

    assert decision.outcome == "blocked_candidate_not_locally_eligible"


def test_forged_self_key_unsigned_and_tampered_receipts_fail_closed() -> None:
    request = _request()
    valid = _signed_eligibility(request)
    forged_key = Ed25519PrivateKey.generate()
    forged = _signed_eligibility(request, private_key=forged_key)
    unsigned = replace(valid, signature_base64=base64.b64encode(b"0" * 64).decode("ascii"))
    tampered = replace(valid, receipt=replace(valid.receipt, issuer="attacker"))

    for envelope in (forged, unsigned, tampered):
        assert (
            _reconcile(request, None, eligibility=envelope).outcome
            == "blocked_candidate_not_locally_eligible"
        )
    assert (
        reconcile_experimental_publication(
            request,
            None,
            verifier=_verifier(),
            eligibility=valid.receipt,  # type: ignore[arg-type]
        ).outcome
        == "blocked_candidate_not_locally_eligible"
    )


def test_signed_receipt_replays_only_the_same_immutable_effect() -> None:
    request = _request()
    envelope = _signed_eligibility(request)

    assert _reconcile(request, None, eligibility=envelope).outcome == "push_branch"
    assert (
        _reconcile(request, request.candidate_packet.candidate_commit, eligibility=envelope).outcome
        == "record_existing_exact_branch"
    )
    for changed in (
        replace(request, request_id="publish-experimental-other"),
        replace(request, requested_at="2026-08-10T12:02:01Z"),
    ):
        assert (
            _reconcile(changed, None, eligibility=envelope).outcome
            == "blocked_candidate_not_locally_eligible"
        )
    with pytest.raises(ExperimentalPublicationError, match="experimental_branch_invalid"):
        _reconcile(replace(request, branch="experimental/other"), None, eligibility=envelope)


@pytest.mark.parametrize(
    "repository_id,remote_url",
    [
        ("attacker/carl-agent", "https://github.com/attacker/carl-agent.git"),
        (
            "StephenBickel/carl-agent-fork",
            "https://github.com/StephenBickel/carl-agent-fork.git",
        ),
    ],
)
def test_signed_receipt_cannot_be_replayed_for_another_destination(
    repository_id: str,
    remote_url: str,
) -> None:
    request = _request()
    envelope = _signed_eligibility(request)

    changed = replace(request, repository_id=repository_id, remote_url=remote_url)
    decision = _reconcile(changed, None, eligibility=envelope)

    assert decision.outcome == "blocked_candidate_not_locally_eligible"


def test_publication_effect_identity_changes_with_destination() -> None:
    request = _request()
    changed = replace(
        request,
        repository_id="StephenBickel/carl-agent-fork",
        remote_url="https://github.com/StephenBickel/carl-agent-fork.git",
    )

    assert _eligibility(request).effect_digest != _eligibility(changed).effect_digest


@pytest.mark.parametrize(
    "repository_id,remote_url",
    [
        ("StephenBickel/carl-agent", "ssh://github.com/StephenBickel/carl-agent.git"),
        ("StephenBickel/carl-agent", "https://user@github.com/StephenBickel/carl-agent.git"),
        ("StephenBickel/carl-agent", "https://github.com/StephenBickel/carl-agent.git?q=1"),
        ("StephenBickel/carl-agent", "https://github.com/StephenBickel/carl-agent.git#main"),
        ("StephenBickel/carl-agent", "https://github.com/StephenBickel/carl-agent"),
        ("StephenBickel/carl-agent", "origin"),
    ],
)
def test_policy_rejects_noncanonical_or_alias_remote_destination(
    repository_id: str, remote_url: str
) -> None:
    with pytest.raises(ValueError, match="experimental_(repository|remote)"):
        ExperimentalPublicationPolicy(
            schema_version=1,
            key_id=ELIGIBILITY_KEY_ID,
            public_key_pem=ELIGIBILITY_PUBLIC_KEY,
            repository_id=repository_id,
            remote_url=remote_url,
        )


def test_verifier_reads_trusted_clock_once_per_publication_decision() -> None:
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise AssertionError("clock read more than once")
        return datetime(2026, 8, 10, 12, 2, tzinfo=UTC)

    decision = _reconcile(_request(), None, verifier=_verifier(clock=clock))

    assert decision.outcome == "push_branch"
    assert calls == 1


def test_publish_cli_records_one_immutable_branch_without_protected_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, origin, parent = _repository(tmp_path)
    selected = replace(manifest(), experiment_id="exp-publication-001", parent_commit=parent)
    candidate_file = repository / "src" / "runtime" / "task" / "value.txt"
    candidate_file.write_text("experimental candidate\n", encoding="utf-8")
    subprocess.run(("git", "add", "--all"), cwd=repository, check=True)
    subprocess.run(
        ("git", "commit", "-m", "experimental candidate"),
        cwd=repository,
        check=True,
    )
    candidate_commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    candidate_tree = subprocess.run(
        ("git", "rev-parse", "HEAD^{tree}"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    packet = replace(
        sealed_candidate(),
        experiment_id=selected.experiment_id,
        manifest_digest=selected.digest,
        parent_commit=parent,
        candidate_commit=candidate_commit,
    )
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    ledger_path = private / "experiments.sqlite3"
    ExperimentLedger(ledger_path).register_manifest(selected)
    packet_path = private / "candidate-packet.json"
    packet_path.write_text(json.dumps(packet.to_canonical_dict()), encoding="utf-8")
    eligibility_request = ExperimentalPublicationRequest(
        experiment_id=selected.experiment_id,
        branch=f"experimental/{selected.experiment_id}",
        candidate_packet=packet,
        candidate_tree=candidate_tree,
        request_id="publish-experimental-001",
        requested_at=REQUESTED_AT,
        repository_id=REPOSITORY_ID,
        remote_url=CANONICAL_REMOTE_URL,
    )
    eligibility_path = private / "experimental-eligibility.json"
    signed_eligibility = _signed_eligibility(
        eligibility_request,
        issued_at="2020-01-01T00:00:00Z",
        expires_at="2100-01-01T00:00:00Z",
    )
    eligibility_path.write_text(
        json.dumps(signed_eligibility.to_canonical_dict()), encoding="utf-8"
    )
    attacker_key = Ed25519PrivateKey.generate()
    attacker_public_key_path = private / "attacker-experimental-eligibility-public.pem"
    attacker_public_key_path.write_bytes(
        attacker_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setenv(
        "CARL_EXPERIMENTAL_ELIGIBILITY_PUBLIC_KEY_PATH", os.fspath(attacker_public_key_path)
    )
    monkeypatch.setenv("CARL_EXPERIMENTAL_ELIGIBILITY_KEY_ID", "attacker-selected-key")
    monkeypatch.setattr(cli, "_experimental_eligibility_policy", _policy)
    transport = _RecordingGitTransport(origin)
    monkeypatch.setattr(experimental_publication, "_protected_git_transport", lambda: transport)
    result = tmp_path / "publication.json"
    command = [
        "candidate",
        "publish-experimental",
        "--ledger",
        os.fspath(ledger_path),
        "--experiment-id",
        selected.experiment_id,
        "--repository",
        os.fspath(repository),
        "--branch",
        f"experimental/{selected.experiment_id}",
        "--candidate-packet",
        os.fspath(packet_path),
        "--eligibility-receipt",
        os.fspath(eligibility_path),
        "--stage-attempt-id",
        "publish-experimental-001",
        "--occurred-at",
        REQUESTED_AT,
        "--public-result",
        os.fspath(result),
    ]
    assert cli.main(command) == 0

    remote_experimental = subprocess.run(
        ("git", "ls-remote", "origin", f"refs/heads/experimental/{selected.experiment_id}"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()[0]
    remote_main = subprocess.run(
        ("git", "ls-remote", "origin", "refs/heads/main"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()[0]
    assert remote_experimental == candidate_commit
    assert remote_main == parent
    assert json.loads(result.read_text(encoding="utf-8"))["tree"] == candidate_tree
    assert [item[0] for item in transport.network_commands] == [
        "ls-remote",
        "push",
        "fetch",
        "ls-remote",
    ]
    assert all(item[1] == CANONICAL_REMOTE_URL for item in transport.network_commands)
    assert all("origin" not in item[2] for item in transport.network_commands)
    assert transport.network_commands[1][2] == (
        f"--force-with-lease=refs/heads/experimental/{selected.experiment_id}:",
        f"{candidate_commit}:refs/heads/experimental/{selected.experiment_id}",
    )
    assert (
        ExperimentLedger(ledger_path)
        .autonomy_projection(selected.experiment_id)
        .protected_validation
        is None
    )

    forged_path = private / "forged-experimental-eligibility.json"
    forged_path.write_text(
        json.dumps(
            _signed_eligibility(eligibility_request, private_key=attacker_key).to_canonical_dict()
        ),
        encoding="utf-8",
    )
    forged_command = list(command)
    forged_command[forged_command.index("--eligibility-receipt") + 1] = os.fspath(forged_path)
    assert cli.main(forged_command) == 2

    canonical = eligibility_path.read_text(encoding="utf-8")
    trust_override = signed_eligibility.to_canonical_dict()
    trust_override["receipt"]["public_key_pem"] = "caller-selected"
    malformed_receipts = {
        "duplicate": canonical[:-1] + ', "schema_version": 1}',
        "extra": json.dumps(
            signed_eligibility.to_canonical_dict() | {"live_capability_validated": True}
        ),
        "trust-override": json.dumps(trust_override),
        "oversized": "{" + '"padding":"' + ("x" * 1_048_576) + '"}',
    }
    receipt_index = command.index("--eligibility-receipt") + 1
    for name, content in malformed_receipts.items():
        malformed = private / f"experimental-eligibility-{name}.json"
        malformed.write_text(content, encoding="utf-8")
        invalid_command = list(command)
        invalid_command[receipt_index] = os.fspath(malformed)
        assert cli.main(invalid_command) == 2


def test_local_remote_aliases_cannot_select_the_publication_destination(tmp_path: Path) -> None:
    repository, _, _ = _repository(tmp_path)
    subprocess.run(
        ("git", "remote", "set-url", "--add", "--push", "origin", CANONICAL_REMOTE_URL),
        cwd=repository,
        check=True,
    )
    subprocess.run(
        (
            "git",
            "remote",
            "set-url",
            "--add",
            "--push",
            "origin",
            "https://github.com/attacker/carl-agent.git",
        ),
        cwd=repository,
        check=True,
    )

    parser = cli._parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "candidate",
                "publish-experimental",
                "--remote",
                "origin",
            ]
        )


def test_protected_transport_ignores_equal_length_repository_local_url_rewrite(
    tmp_path: Path,
) -> None:
    repository, intended_remote, parent = _repository(tmp_path)
    attacker_remote = tmp_path / "attacker.git"
    subprocess.run(("git", "init", "--bare", os.fspath(attacker_remote)), check=True)
    marker_ref = "refs/heads/attacker-only"
    subprocess.run(
        ("git", "push", os.fspath(attacker_remote), f"{parent}:{marker_ref}"),
        cwd=repository,
        check=True,
    )
    signed_url = intended_remote.as_uri()
    subprocess.run(
        (
            "git",
            "config",
            "--local",
            f"url.{attacker_remote.as_uri()}.insteadOf",
            signed_url,
        ),
        cwd=repository,
        check=True,
    )

    snapshot = experimental_publication._ProtectedGitTransport().network(
        repository,
        "ls-remote",
        signed_url,
        marker_ref,
    )

    assert snapshot == ""


def test_protected_transport_ignores_worktree_local_url_rewrite(tmp_path: Path) -> None:
    repository, intended_remote, parent = _repository(tmp_path)
    attacker_remote = tmp_path / "attacker.git"
    subprocess.run(("git", "init", "--bare", os.fspath(attacker_remote)), check=True)
    marker_ref = "refs/heads/attacker-only"
    subprocess.run(
        ("git", "push", os.fspath(attacker_remote), f"{parent}:{marker_ref}"),
        cwd=repository,
        check=True,
    )
    signed_url = intended_remote.as_uri()
    subprocess.run(
        ("git", "config", "extensions.worktreeConfig", "true"),
        cwd=repository,
        check=True,
    )
    subprocess.run(
        (
            "git",
            "config",
            "--worktree",
            f"url.{attacker_remote.as_uri()}.insteadOf",
            signed_url,
        ),
        cwd=repository,
        check=True,
    )

    snapshot = experimental_publication._ProtectedGitTransport().network(
        repository,
        "ls-remote",
        signed_url,
        marker_ref,
    )

    assert snapshot == ""


def test_protected_transport_push_ignores_repository_local_url_rewrite(
    tmp_path: Path,
) -> None:
    repository, intended_remote, parent = _repository(tmp_path)
    attacker_remote = tmp_path / "attacker.git"
    subprocess.run(("git", "init", "--bare", os.fspath(attacker_remote)), check=True)
    marker_ref = "refs/heads/intended-only"
    signed_url = intended_remote.as_uri()
    subprocess.run(
        (
            "git",
            "config",
            "--local",
            f"url.{attacker_remote.as_uri()}.insteadOf",
            signed_url,
        ),
        cwd=repository,
        check=True,
    )

    experimental_publication._ProtectedGitTransport().network(
        repository,
        "push",
        signed_url,
        f"--force-with-lease={marker_ref}:",
        f"{parent}:{marker_ref}",
    )

    intended_snapshot = subprocess.run(
        ("git", "ls-remote", os.fspath(intended_remote), marker_ref),
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    attacker_snapshot = subprocess.run(
        ("git", "ls-remote", os.fspath(attacker_remote), marker_ref),
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert intended_snapshot.split()[0] == parent
    assert attacker_snapshot == ""


def test_protected_transport_fetch_ignores_repository_local_url_rewrite(
    tmp_path: Path,
) -> None:
    repository, intended_remote, parent = _repository(tmp_path)
    attacker_remote = tmp_path / "attacker.git"
    subprocess.run(("git", "init", "--bare", os.fspath(attacker_remote)), check=True)
    source_ref = "refs/heads/fetch-source"
    tracking_ref = "refs/carl/fetch-verification"
    subprocess.run(
        ("git", "push", os.fspath(intended_remote), f"{parent}:{source_ref}"),
        cwd=repository,
        check=True,
    )
    candidate_file = repository / "src" / "runtime" / "task" / "value.txt"
    candidate_file.write_text("attacker\n", encoding="utf-8")
    subprocess.run(("git", "add", "--all"), cwd=repository, check=True)
    subprocess.run(("git", "commit", "-m", "attacker object"), cwd=repository, check=True)
    attacker_commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ("git", "push", os.fspath(attacker_remote), f"{attacker_commit}:{source_ref}"),
        cwd=repository,
        check=True,
    )
    signed_url = intended_remote.as_uri()
    subprocess.run(
        (
            "git",
            "config",
            "--local",
            f"url.{attacker_remote.as_uri()}.insteadOf",
            signed_url,
        ),
        cwd=repository,
        check=True,
    )

    experimental_publication._ProtectedGitTransport().network(
        repository,
        "fetch",
        signed_url,
        "--no-tags",
        f"{source_ref}:{tracking_ref}",
    )

    fetched = subprocess.run(
        ("git", "rev-parse", tracking_ref),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert fetched == parent


def test_protected_transport_pins_binary_sanitizes_environment_and_passes_exact_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, _, _ = _repository(tmp_path)
    monkeypatch.setenv("GIT_EXEC_PATH", os.fspath(tmp_path / "caller-helpers"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("HTTPS_PROXY", "http://attacker.invalid:8080")
    object_directory = (repository / ".git" / "objects").resolve()
    invocations: list[tuple[tuple[str, ...], dict[str, str], str]] = []

    class Result:
        returncode = 0

        def __init__(self, stdout: str = "") -> None:
            self.stdout = stdout

    def record(command: tuple[str, ...], **kwargs: object) -> Result:
        invocations.append(  # type: ignore[arg-type]
            (command, kwargs["env"], kwargs["cwd"])
        )
        if "--git-path" in command:
            return Result(os.fspath(object_directory))
        if "--verify" in command:
            return Result("a" * 40)
        return Result()

    transport = experimental_publication._ProtectedGitTransport()
    monkeypatch.setattr(experimental_publication.subprocess, "run", record)
    transport.network(repository, "ls-remote", CANONICAL_REMOTE_URL, "refs/heads/test")
    transport.network(
        repository,
        "push",
        CANONICAL_REMOTE_URL,
        "--force-with-lease=refs/heads/test:",
        "a" * 40 + ":refs/heads/test",
    )
    transport.network(
        repository,
        "fetch",
        CANONICAL_REMOTE_URL,
        "--no-tags",
        "refs/heads/test:refs/carl/test",
    )

    network_invocations = [item for item in invocations if CANONICAL_REMOTE_URL in item[0]]
    assert len(network_invocations) == 3
    for command, environment, cwd in network_invocations:
        assert command[0] == "/usr/bin/git"
        assert command.count(CANONICAL_REMOTE_URL) == 1
        assert "origin" not in command
        assert "core.hooksPath=/dev/null" in command
        assert not any(item.startswith("url.") for item in command)
        assert f"http.{CANONICAL_REMOTE_URL}.proxy=" in command
        assert f"http.{CANONICAL_REMOTE_URL}.curloptResolve=" in command
        assert f"http.{CANONICAL_REMOTE_URL}.sslVerify=true" in command
        assert environment["GIT_DIR"].startswith("/var/tmp/carl-protected-git-")
        assert environment["GIT_OBJECT_DIRECTORY"] == os.fspath(object_directory)
        assert cwd == "/var/empty"
        assert {
            key: value
            for key, value in environment.items()
            if key not in {"GIT_DIR", "GIT_OBJECT_DIRECTORY"}
        } == {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": "/var/empty",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
    assert network_invocations[1][0][-3:] == (
        "--force-with-lease=refs/heads/test:",
        CANONICAL_REMOTE_URL,
        "a" * 40 + ":refs/heads/test",
    )
    assert network_invocations[2][0][-3:] == (
        "--no-tags",
        CANONICAL_REMOTE_URL,
        "refs/heads/test:refs/carl/test",
    )


def test_protected_transport_rejects_symlinked_or_unowned_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    symlink = tmp_path / "git"
    symlink.symlink_to("/usr/bin/git")
    monkeypatch.setattr(experimental_publication, "_PROTECTED_GIT_EXECUTABLE", symlink)
    with pytest.raises(ExperimentalPublicationError, match="experimental_git_unavailable"):
        experimental_publication._ProtectedGitTransport()

    executable = tmp_path / "caller-git"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    monkeypatch.setattr(experimental_publication, "_PROTECTED_GIT_EXECUTABLE", executable)
    with pytest.raises(ExperimentalPublicationError, match="experimental_git_identity_invalid"):
        experimental_publication._ProtectedGitTransport()


def test_protected_transport_rechecks_pinned_binary_identity_before_every_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(experimental_publication, "_PROTECTED_GIT_EXECUTABLE", Path("/usr/bin/git"))
    transport = experimental_publication._ProtectedGitTransport()
    identity = object.__getattribute__(transport, "_identity")
    monkeypatch.setattr(
        experimental_publication._ProtectedGitTransport,
        "_read_identity",
        staticmethod(lambda: (identity, b"changed-binary-digest")),
    )

    with pytest.raises(ExperimentalPublicationError, match="experimental_git_identity_changed"):
        transport.local(tmp_path, "status")


def test_create_only_push_never_fast_forwards_a_ref_created_after_the_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, origin, parent = _repository(tmp_path)
    selected = replace(manifest(), experiment_id="exp-publication-race-001", parent_commit=parent)
    candidate_file = repository / "src" / "runtime" / "task" / "value.txt"
    candidate_file.write_text("candidate after concurrent ref\n", encoding="utf-8")
    subprocess.run(("git", "add", "--all"), cwd=repository, check=True)
    subprocess.run(
        ("git", "commit", "-m", "candidate after concurrent ref"), cwd=repository, check=True
    )
    candidate_commit = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    candidate_tree = subprocess.run(
        ("git", "rev-parse", "HEAD^{tree}"),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    request = ExperimentalPublicationRequest(
        experiment_id=selected.experiment_id,
        branch=f"experimental/{selected.experiment_id}",
        candidate_packet=replace(
            sealed_candidate(),
            experiment_id=selected.experiment_id,
            manifest_digest=selected.digest,
            parent_commit=parent,
            candidate_commit=candidate_commit,
        ),
        candidate_tree=candidate_tree,
        request_id="publish-experimental-race-001",
        requested_at=REQUESTED_AT,
        repository_id=REPOSITORY_ID,
        remote_url=CANONICAL_REMOTE_URL,
    )
    eligibility = _signed_eligibility(request)
    ref = f"refs/heads/experimental/{selected.experiment_id}"
    marker = tmp_path / "racer-ran"
    transport = _RecordingGitTransport(origin)
    original_network = transport.network

    def racing_network(repository_path: Path, operation: str, remote_url: str, *args: str) -> str:
        if operation == "push" and not marker.exists():
            marker.touch(exist_ok=False)
            subprocess.run(
                ("/usr/bin/git", "-C", os.fspath(repository), "push", "origin", f"{parent}:{ref}"),
                check=True,
            )
        return original_network(repository_path, operation, remote_url, *args)

    transport.network = racing_network  # type: ignore[method-assign]
    monkeypatch.setattr(experimental_publication, "_protected_git_transport", lambda: transport)

    with pytest.raises(ExperimentalPublicationError, match="experimental_git_failed"):
        publish_experimental_branch(
            request,
            verifier=_verifier(),
            eligibility=eligibility,
            repository=repository,
        )

    remote_commit = subprocess.run(
        ("git", "ls-remote", "origin", ref),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()[0]
    assert marker.exists()
    assert remote_commit == parent
