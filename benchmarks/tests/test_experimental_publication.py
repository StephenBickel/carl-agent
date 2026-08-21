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

from carl_bench import cli
from carl_bench.capability_validation import (
    ExperimentalCheckResult,
    ExperimentalLocalGateResult,
    ExperimentalPublicationEligibility,
    ExperimentalReviewDisposition,
    experimental_evidence_digest,
    experimental_publication_request_digest,
)
from carl_bench.experimental_publication import (
    ExperimentalEligibilityTrustedKey,
    ExperimentalEligibilityVerifier,
    ExperimentalPublicationError,
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


def test_experimental_eligibility_verifier_is_immutable_and_production_distinct() -> None:
    verifier = ExperimentalEligibilityVerifier(
        trusted_key=ExperimentalEligibilityTrustedKey(
            key_id=ELIGIBILITY_KEY_ID,
            public_key_pem=ELIGIBILITY_PUBLIC_KEY,
        ),
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

        class BypassTrustedKey(ExperimentalEligibilityTrustedKey):
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
        trusted_key=ExperimentalEligibilityTrustedKey(
            key_id=ELIGIBILITY_KEY_ID,
            public_key_pem=ELIGIBILITY_PUBLIC_KEY,
        ),
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
    public_key_path = private / "experimental-eligibility-public.pem"
    public_key_path.write_bytes(ELIGIBILITY_PUBLIC_KEY)
    monkeypatch.setenv("CARL_EXPERIMENTAL_ELIGIBILITY_PUBLIC_KEY_PATH", os.fspath(public_key_path))
    monkeypatch.setenv("CARL_EXPERIMENTAL_ELIGIBILITY_KEY_ID", ELIGIBILITY_KEY_ID)
    git_log = private / "git-log.jsonl"
    fake_git = private / "fake-git.py"
    fake_git.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, subprocess, sys\n"
        "with open(os.environ['CARL_TEST_GIT_LOG'], 'a', encoding='utf-8') as handle:\n"
        "    handle.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "result = subprocess.run([os.environ['CARL_TEST_REAL_GIT'], *sys.argv[1:]])\n"
        "raise SystemExit(result.returncode)\n",
        encoding="utf-8",
    )
    fake_git.chmod(0o700)
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
        "--remote",
        "origin",
        "--branch",
        f"experimental/{selected.experiment_id}",
        "--candidate-packet",
        os.fspath(packet_path),
        "--eligibility-receipt",
        os.fspath(eligibility_path),
        "--git-executable",
        os.fspath(fake_git),
        "--stage-attempt-id",
        "publish-experimental-001",
        "--occurred-at",
        REQUESTED_AT,
        "--public-result",
        os.fspath(result),
    ]
    previous_log = os.environ.get("CARL_TEST_GIT_LOG")
    previous_git = os.environ.get("CARL_TEST_REAL_GIT")
    os.environ["CARL_TEST_GIT_LOG"] = os.fspath(git_log)
    os.environ["CARL_TEST_REAL_GIT"] = "/usr/bin/git"
    try:
        assert cli.main(command) == 0
    finally:
        if previous_log is None:
            os.environ.pop("CARL_TEST_GIT_LOG", None)
        else:
            os.environ["CARL_TEST_GIT_LOG"] = previous_log
        if previous_git is None:
            os.environ.pop("CARL_TEST_REAL_GIT", None)
        else:
            os.environ["CARL_TEST_REAL_GIT"] = previous_git

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
    commands = [json.loads(line) for line in git_log.read_text(encoding="utf-8").splitlines()]

    assert remote_experimental == candidate_commit
    assert remote_main == parent
    assert json.loads(result.read_text(encoding="utf-8"))["tree"] == candidate_tree
    assert any(
        command[-4:]
        == [
            "push",
            f"--force-with-lease=refs/heads/experimental/{selected.experiment_id}:",
            "origin",
            f"{candidate_commit}:refs/heads/experimental/{selected.experiment_id}",
        ]
        for command in commands
    )
    assert all("--force" not in command for command in commands)
    assert all("main" not in command for command in commands)
    assert (
        ExperimentLedger(ledger_path)
        .autonomy_projection(selected.experiment_id)
        .protected_validation
        is None
    )

    monkeypatch.delenv("CARL_EXPERIMENTAL_ELIGIBILITY_PUBLIC_KEY_PATH")
    assert cli.main(command) == 2
    monkeypatch.setenv("CARL_EXPERIMENTAL_ELIGIBILITY_PUBLIC_KEY_PATH", os.fspath(public_key_path))
    monkeypatch.setenv("CARL_EXPERIMENTAL_ELIGIBILITY_KEY_ID", "untrusted-key")
    assert cli.main(command) == 2
    monkeypatch.setenv("CARL_EXPERIMENTAL_ELIGIBILITY_KEY_ID", ELIGIBILITY_KEY_ID)

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
    )
    eligibility = _signed_eligibility(request)
    ref = f"refs/heads/experimental/{selected.experiment_id}"
    marker = tmp_path / "racer-ran"
    fake_git = tmp_path / "racing-git.py"
    fake_git.write_text(
        "#!/usr/bin/env python3\n"
        "import os, subprocess, sys\n"
        "if 'push' in sys.argv[1:] and not os.path.exists(os.environ['CARL_RACE_MARKER']):\n"
        "    open(os.environ['CARL_RACE_MARKER'], 'x').close()\n"
        "    subprocess.run([\n"
        "        os.environ['CARL_TEST_REAL_GIT'], '-C', os.environ['CARL_RACE_REPOSITORY'],\n"
        "        'push', 'origin',\n"
        "        os.environ['CARL_RACE_COMMIT'] + ':' + os.environ['CARL_RACE_REF'],\n"
        "    ], check=True)\n"
        "result = subprocess.run([os.environ['CARL_TEST_REAL_GIT'], *sys.argv[1:]])\n"
        "raise SystemExit(result.returncode)\n",
        encoding="utf-8",
    )
    fake_git.chmod(0o700)
    monkeypatch.setenv("CARL_TEST_REAL_GIT", "/usr/bin/git")
    monkeypatch.setenv("CARL_RACE_MARKER", os.fspath(marker))
    monkeypatch.setenv("CARL_RACE_REPOSITORY", os.fspath(repository))
    monkeypatch.setenv("CARL_RACE_COMMIT", parent)
    monkeypatch.setenv("CARL_RACE_REF", ref)

    with pytest.raises(ExperimentalPublicationError, match="experimental_git_failed"):
        publish_experimental_branch(
            request,
            verifier=_verifier(),
            eligibility=eligibility,
            repository=repository,
            remote="origin",
            git_executable=fake_git,
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
