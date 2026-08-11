from __future__ import annotations

import json

import pytest

from carl_bench.artifacts import ArtifactRef
from carl_bench.candidate import (
    CandidateContractError,
    DeterministicCheckResult,
    DraftPullRequest,
    PairedEvidence,
    PreparedCandidate,
    ReviewAttestation,
    ReviewPacket,
    SealedCandidate,
)

PARENT = "1" * 40
CANDIDATE = "2" * 40
MANIFEST = "3" * 64


def artifact(kind: str, marker: str) -> ArtifactRef:
    return ArtifactRef(
        schema_version=1,
        digest=marker * 64,
        byte_size=7,
        media_type="application/json",
        evidence_kind=kind,
    )


def prepared() -> PreparedCandidate:
    return PreparedCandidate(
        schema_version=1,
        experiment_id="exp-candidate-001",
        manifest_digest=MANIFEST,
        parent_commit=PARENT,
        branch="codex/experiment-exp-candidate-001-0123456789",
        request_artifact=artifact("builder_request", "4"),
    )


def sealed() -> SealedCandidate:
    return SealedCandidate(
        schema_version=1,
        experiment_id="exp-candidate-001",
        manifest_digest=MANIFEST,
        parent_commit=PARENT,
        candidate_commit=CANDIDATE,
        branch=prepared().branch,
        diff_artifact=artifact("candidate_diff", "5"),
        report_artifact=artifact("implementation_report", "6"),
        changed_paths_artifact=artifact("changed_paths", "7"),
        changed_path_count=2,
        checks=(
            DeterministicCheckResult(
                check_id="python-tests",
                status="passed",
                exit_code=0,
                elapsed_ms=125,
                output_artifact=artifact("check_output", "8"),
            ),
        ),
    )


def paired() -> PairedEvidence:
    return PairedEvidence(
        schema_version=1,
        experiment_id="exp-candidate-001",
        manifest_digest=MANIFEST,
        parent_commit=PARENT,
        candidate_commit=CANDIDATE,
        baseline_scorecard_digest="9" * 64,
        candidate_scorecard_digest="a" * 64,
        comparison_artifact=artifact("paired_comparison", "b"),
        decision="improvement",
        paired_trials=12,
        pass_rate_delta_basis_points=833,
        confidence_lower_basis_points=125,
    )


def packet(role: str = "correctness") -> ReviewPacket:
    return ReviewPacket(
        schema_version=1,
        experiment_id="exp-candidate-001",
        manifest_digest=MANIFEST,
        candidate_commit=CANDIDATE,
        role=role,
        diff_digest="5" * 64,
        deterministic_evidence_digest=sealed().digest,
        paired_evidence_digest=paired().digest,
        review_contract_version="candidate-review-v1",
    )


def test_candidate_contracts_round_trip_canonically_and_public_output_omits_private_data() -> None:
    values = (prepared(), sealed(), paired(), packet())
    types = (PreparedCandidate, SealedCandidate, PairedEvidence, ReviewPacket)
    for value, expected_type in zip(values, types, strict=True):
        restored = expected_type.from_canonical_dict(value.to_canonical_dict())
        assert restored == value
        assert len(value.digest) == 64

    public = json.dumps(sealed().to_public_dict()).casefold()
    assert "worktree" not in public
    assert "implementation_report" not in public
    assert "check_output" not in public
    assert sealed().all_checks_passed is True


def test_sealed_candidate_rejects_failed_unsorted_or_duplicate_checks() -> None:
    value = sealed().to_canonical_dict()
    value["checks"][0]["status"] = "failed"
    value["checks"][0]["exit_code"] = 7
    with pytest.raises(CandidateContractError, match="candidate_checks_failed"):
        SealedCandidate.from_canonical_dict(value)

    value = sealed().to_canonical_dict()
    value["checks"].append(dict(value["checks"][0]))
    with pytest.raises(CandidateContractError, match="candidate_checks_not_sorted_unique"):
        SealedCandidate.from_canonical_dict(value)


def test_review_attestation_is_bound_to_packet_candidate_and_unique_identity_fields() -> None:
    review = ReviewAttestation(
        schema_version=1,
        experiment_id="exp-candidate-001",
        manifest_digest=MANIFEST,
        candidate_commit=CANDIDATE,
        role="correctness",
        reviewer_id="reviewer-correctness-1",
        context_id="context-correctness-1",
        packet_digest=packet().digest,
        verdict="approve",
        report_artifact=artifact("review_report", "c"),
    )
    assert ReviewAttestation.from_canonical_dict(review.to_canonical_dict()) == review

    stale = review.to_canonical_dict()
    stale["candidate_commit"] = PARENT
    with pytest.raises(CandidateContractError, match="review_candidate_mismatch"):
        ReviewAttestation.from_packet_dict(stale, packet())

    reused = review.to_canonical_dict()
    reused["context_id"] = reused["reviewer_id"]
    with pytest.raises(CandidateContractError, match="review_identity_context_reused"):
        ReviewAttestation.from_canonical_dict(reused)


@pytest.mark.parametrize(
    "role", ["correctness", "security", "maintainability", "benchmark_integrity"]
)
def test_review_packets_are_role_specific(role: str) -> None:
    value = packet(role)
    assert value.role == role
    assert value.digest != packet("correctness").digest or role == "correctness"


def test_draft_pull_request_requires_reconciled_open_draft_and_exact_head() -> None:
    draft = DraftPullRequest(
        schema_version=1,
        repository="StephenBickel/carl-agent",
        number=17,
        url="https://github.com/StephenBickel/carl-agent/pull/17",
        state="OPEN",
        is_draft=True,
        base_branch="main",
        head_branch=prepared().branch,
        candidate_commit=CANDIDATE,
    )
    assert DraftPullRequest.from_canonical_dict(draft.to_canonical_dict()) == draft

    for field, replacement, code in (
        ("is_draft", False, "pull_request_not_draft"),
        ("state", "CLOSED", "pull_request_not_open"),
        ("candidate_commit", PARENT, "pull_request_candidate_mismatch"),
    ):
        value = draft.to_canonical_dict()
        value[field] = replacement
        with pytest.raises(CandidateContractError, match=code):
            DraftPullRequest.from_candidate_dict(value, sealed())


def test_candidate_contracts_reject_unknown_keys_and_invalid_pairing_decisions() -> None:
    value = prepared().to_canonical_dict()
    value["private_path"] = "/private/worktree"
    with pytest.raises(CandidateContractError, match="invalid_prepared_candidate_keys"):
        PreparedCandidate.from_canonical_dict(value)

    value = paired().to_canonical_dict()
    value["decision"] = "maybe"
    with pytest.raises(CandidateContractError, match="invalid_paired_decision"):
        PairedEvidence.from_canonical_dict(value)
