from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_harness import CloudHarnessResult, SubjectResult
from carl_bench.evidence_archive import ArchivedEvidence, ArchiveIdentity
from carl_bench.live_capability import (
    DeterministicPairEvidence,
    LiveCapabilityError,
    LiveEvaluationIdentity,
    LivePairPolicy,
    LiveTaskIdentity,
    LiveTrialEvidence,
    ProtectedLivePair,
    attest_live_pair,
    combine_paired_evidence,
    verify_live_pair,
)
from carl_bench.openai_gateway import (
    OpenAIModelGateway,
    OpenAIUsage,
    ProtectedOpenAIModelResult,
    SyntheticOpenAIModelResult,
)

NOW = datetime(2026, 8, 22, 12, tzinfo=UTC)
KEY = bytes(range(32))
PROVENANCE_KEY = b"carl-openai-provenance-test-key!"
PARENT = "1" * 40
CANDIDATE = "2" * 40


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def model_policy_digest() -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "model": "gpt-5.2",
                "policy_revision": "openai-responses-policy-2026-08-20.1",
                "reasoning_policy": "medium/no-summary",
            }
        )
    ).hexdigest()


def identity() -> LiveEvaluationIdentity:
    return LiveEvaluationIdentity.create(
        repository="StephenBickel/carl-agent",
        parent_commit=PARENT,
        parent_tree="3" * 40,
        candidate_commit=CANDIDATE,
        candidate_tree="4" * 40,
        experiment_digest=digest("experiment"),
        workflow_revision="5" * 40,
        workflow_digest=digest("workflow"),
        task_set_digest=digest("task-set"),
        metric_pack_digest=digest("metric-pack"),
        policy_digest=digest("policy"),
        model_policy_digest=model_policy_digest(),
        grader_digest=digest("grader"),
        environment_digest=digest("environment"),
        model="gpt-5.2",
        reasoning_policy="medium/no-summary",
        tool_protocol_revision="acp-v2/bounded-openai-v1",
        task_order=("affected", "guard", "held"),
        seeds=(41000, 41001),
        attempts=2,
    )


def policy() -> LivePairPolicy:
    return LivePairPolicy(
        maximum_pair_retries=1,
        maximum_total_cost_microdollars=50_000,
        maximum_trial_latency_ms=30_000,
        input_cost_microdollars_per_million_tokens=5_000_000,
        cached_input_cost_microdollars_per_million_tokens=1_000_000,
        output_cost_microdollars_per_million_tokens=10_000_000,
        minimum_aggregate_gain_basis_points=500,
        minimum_held_out_gain_basis_points=1,
        require_affected_improvement=True,
        require_guard_non_regression=True,
    )


def tasks() -> tuple[LiveTaskIdentity, ...]:
    return (
        LiveTaskIdentity(
            task_id="affected",
            task_digest=digest("affected-task"),
            input_digest=digest("affected-input"),
            input_size=32,
            grader_digest=digest("grader"),
            role="affected",
        ),
        LiveTaskIdentity(
            task_id="guard",
            task_digest=digest("guard-task"),
            input_digest=digest("guard-input"),
            input_size=32,
            grader_digest=digest("grader"),
            role="guard",
        ),
        LiveTaskIdentity(
            task_id="held",
            task_digest=digest("held-task"),
            input_digest=digest("held-input"),
            input_size=32,
            grader_digest=digest("grader"),
            role="held_out",
        ),
    )


def protected_gateway(monkeypatch: pytest.MonkeyPatch) -> OpenAIModelGateway:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-controller-credential-1234567890")
    monkeypatch.setenv(
        "CARL_OPENAI_PROVENANCE_KEY_B64",
        base64.b64encode(PROVENANCE_KEY).decode("ascii"),
    )
    return OpenAIModelGateway.from_protected_environment()


def model_result(
    request_digest: str,
    marker: str,
    *,
    usage: OpenAIUsage | None = None,
    latency_ms: int = 100,
) -> ProtectedOpenAIModelResult:
    fields = {
        "response_id": f"resp-{marker}",
        "model": "gpt-5.2",
        "status": "completed",
        "usage": usage or OpenAIUsage(10, 0, 5, 1, 15),
        "latency_ms": latency_ms,
        "request_digest": request_digest,
        "output_digest": digest(f"output-{marker}"),
        "output_text": "bounded fixture output",
    }
    tag = (
        __import__("hmac")
        .new(
            PROVENANCE_KEY,
            OpenAIModelGateway._result_provenance_payload(fields),
            hashlib.sha256,
        )
        .hexdigest()
    )
    return ProtectedOpenAIModelResult(**fields, provenance_tag=tag)


def trials(
    pair_identity: LiveEvaluationIdentity,
    *,
    subject: str,
    pair_policy: LivePairPolicy | None = None,
    infrastructure_invalid: set[tuple[str, int]] | None = None,
) -> tuple[LiveTrialEvidence, ...]:
    invalid = infrastructure_invalid or set()
    live_policy = pair_policy or policy()
    scores = {
        "parent": {"affected": 4_000, "guard": 10_000, "held": 5_000},
        "candidate": {"affected": 8_000, "guard": 10_000, "held": 7_000},
    }
    values = []
    for task in tasks():
        for attempt, seed in enumerate(pair_identity.seeds, start=1):
            request_digest = pair_identity.model_request_digest(
                subject=subject,
                task=task,
                policy=live_policy,
                seed=seed,
                attempt=attempt,
            )
            status = "infrastructure_invalid" if (task.task_id, attempt) in invalid else "valid"
            values.append(
                LiveTrialEvidence(
                    pair_request_digest=pair_identity.request_digest,
                    subject=subject,
                    subject_commit=PARENT if subject == "parent" else CANDIDATE,
                    task=task,
                    seed=seed,
                    attempt=attempt,
                    attempt_identity=digest(f"{task.task_id}:{attempt}"),
                    status=status,
                    score_basis_points=0 if status != "valid" else scores[subject][task.task_id],
                    cost_microdollars=0 if status != "valid" else 100,
                    latency_ms=0 if status != "valid" else 100,
                    model_result=(
                        None
                        if status != "valid"
                        else model_result(request_digest, f"{subject}-{task.task_id}-{attempt}")
                    ),
                    infrastructure_code=(
                        "runner_internal_error" if status == "infrastructure_invalid" else None
                    ),
                )
            )
    return tuple(values)


def protected_pair(monkeypatch: pytest.MonkeyPatch) -> tuple[ProtectedLivePair, OpenAIModelGateway]:
    pair_identity = identity()
    live_policy = policy()
    gateway = protected_gateway(monkeypatch)
    return (
        ProtectedLivePair.create(
            identity=pair_identity,
            policy=live_policy,
            tasks=tasks(),
            parent_trials=trials(pair_identity, subject="parent", pair_policy=live_policy),
            candidate_trials=trials(pair_identity, subject="candidate", pair_policy=live_policy),
            gateway=gateway,
        ),
        gateway,
    )


def attested(monkeypatch: pytest.MonkeyPatch):
    pair, gateway = protected_pair(monkeypatch)
    archive = ArchivedEvidence(
        identity=ArchiveIdentity(
            repository=pair.identity.repository,
            request_digest=pair.identity.request_digest,
            run_id=42,
            artifact_id=99,
            artifact_name="protected-live-pair",
            media_type="application/vnd.carl.improvement-evidence+json;version=1",
            schema_version=1,
        ),
        object_key=f"carl-evidence/v1/sha256/{pair.digest[:2]}/{pair.digest}",
        payload_digest=pair.digest,
        byte_length=len(canonical_json_bytes(pair.to_canonical_dict())),
        provider_version_id="v1",
        provider_etag='"etag"',
        provider_checksum_sha256=pair.digest,
        retention_mode="COMPLIANCE",
        retain_until="2027-08-22T12:00:00Z",
        archived_at="2026-08-22T12:00:00Z",
    )
    envelope = attest_live_pair(
        pair,
        gateway=gateway,
        key=KEY,
        archive=archive,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    return pair, gateway, envelope


def deterministic_evidence(
    pair_identity: LiveEvaluationIdentity, *, eligible: bool = True
) -> DeterministicPairEvidence:
    source = CloudHarnessResult(
        mode="improvement",
        immutable_inputs={
            "experiment": pair_identity.experiment_digest,
            "metric_pack": pair_identity.metric_pack_digest,
            "policy": pair_identity.policy_digest,
            "task_set": pair_identity.task_set_digest,
        },
        parent=SubjectResult(
            commit=pair_identity.parent_commit,
            binary_digest=digest("parent-binary"),
            score_basis_points=4_000,
            observations=(),
        ),
        candidate=SubjectResult(
            commit=pair_identity.candidate_commit,
            binary_digest=digest("candidate-binary"),
            score_basis_points=8_000 if eligible else 3_000,
            observations=(),
        ),
        gain_basis_points=4_000 if eligible else -1_000,
        contract_eligible=eligible,
        contract_disposition="improvement" if eligible else "rejected",
        contract_reasons=() if eligible else ("deterministic_contract_regression",),
        live_evaluation_identity=pair_identity,
    )
    return DeterministicPairEvidence.from_cloud_harness(source)


def test_pair_identity_is_exact_immutable_and_subject_checkouts_are_isolated() -> None:
    value = identity()

    assert value.parent_commit == PARENT
    assert value.candidate_commit == CANDIDATE
    assert value.parent_tree != value.candidate_tree
    assert (
        value.request_digest
        == hashlib.sha256(
            canonical_json_bytes(value.to_canonical_dict(include_request_digest=False))
        ).hexdigest()
    )
    with pytest.raises((AttributeError, TypeError)):
        value.parent_commit = CANDIDATE  # type: ignore[misc]
    with pytest.raises(LiveCapabilityError, match="live_subject_isolation_invalid"):
        replace(value, parent_tree=value.candidate_tree)


def test_pair_requires_identical_protected_conditions_and_exact_trial_population(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair_identity = identity()
    gateway = protected_gateway(monkeypatch)
    candidate = list(trials(pair_identity, subject="candidate"))
    candidate[0] = replace(candidate[0], seed=99)

    with pytest.raises(LiveCapabilityError, match="live_trial_population_mismatch"):
        ProtectedLivePair.create(
            identity=pair_identity,
            policy=policy(),
            tasks=tasks(),
            parent_trials=trials(pair_identity, subject="parent"),
            candidate_trials=tuple(candidate),
            gateway=gateway,
        )


@pytest.mark.parametrize(
    "commitment",
    (
        "model",
        "reasoning_policy",
        "live_policy",
        "task_role",
        "environment",
        "checkout_tree",
    ),
)
def test_authenticated_execution_rejects_unexecuted_commitment_mutations(
    monkeypatch: pytest.MonkeyPatch, commitment: str
) -> None:
    pair, gateway = protected_pair(monkeypatch)
    mutated_identity = pair.identity
    mutated_policy = pair.policy
    mutated_tasks = pair.tasks
    if commitment == "model":
        mutated_identity = replace(mutated_identity, model="gpt-5.1", request_digest="")
    elif commitment == "reasoning_policy":
        mutated_identity = replace(
            mutated_identity,
            reasoning_policy="high/no-summary",
            request_digest="",
        )
    elif commitment == "live_policy":
        mutated_policy = replace(mutated_policy, maximum_trial_latency_ms=30_001)
    elif commitment == "task_role":
        mutated_tasks = tuple(
            replace(task, role="held_out" if task.role == "guard" else "guard")
            if task.role in {"guard", "held_out"}
            else task
            for task in mutated_tasks
        )
    elif commitment == "environment":
        mutated_identity = replace(
            mutated_identity,
            environment_digest=digest("other-environment"),
            request_digest="",
        )
    else:
        mutated_identity = replace(
            mutated_identity,
            parent_tree="a" * 40,
            request_digest="",
        )

    tasks_by_id = {task.task_id: task for task in mutated_tasks}

    def rebind(trial: LiveTrialEvidence) -> LiveTrialEvidence:
        return replace(
            trial,
            pair_request_digest=mutated_identity.request_digest,
            task=tasks_by_id[trial.task.task_id],
        )

    with pytest.raises(LiveCapabilityError, match="live_execution_binding_mismatch"):
        ProtectedLivePair.create(
            identity=mutated_identity,
            policy=mutated_policy,
            tasks=mutated_tasks,
            parent_trials=tuple(rebind(trial) for trial in pair.parent_trials),
            candidate_trials=tuple(rebind(trial) for trial in pair.candidate_trials),
            gateway=gateway,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (("cost_microdollars", 1), ("latency_ms", 1)),
)
def test_authenticated_model_result_owns_resource_accounting(
    monkeypatch: pytest.MonkeyPatch, field: str, value: int
) -> None:
    pair, gateway = protected_pair(monkeypatch)
    candidate = list(pair.candidate_trials)
    candidate[0] = replace(candidate[0], **{field: value})

    with pytest.raises(LiveCapabilityError, match="live_resource_accounting_mismatch"):
        ProtectedLivePair.create(
            identity=pair.identity,
            policy=pair.policy,
            tasks=pair.tasks,
            parent_trials=pair.parent_trials,
            candidate_trials=tuple(candidate),
            gateway=gateway,
        )


def test_infrastructure_invalidity_is_pair_scoped_with_no_selective_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair_identity = identity()
    gateway = protected_gateway(monkeypatch)
    invalid = {("affected", 1)}
    pair = ProtectedLivePair.create(
        identity=pair_identity,
        policy=policy(),
        tasks=tasks(),
        parent_trials=trials(pair_identity, subject="parent", infrastructure_invalid=invalid),
        candidate_trials=trials(pair_identity, subject="candidate", infrastructure_invalid=invalid),
        gateway=gateway,
    )
    assert pair.inconclusive is True
    assert pair.reasons == ("pair_infrastructure_invalid",)

    with pytest.raises(LiveCapabilityError, match="live_pair_retry_mismatch"):
        ProtectedLivePair.create(
            identity=pair_identity,
            policy=policy(),
            tasks=tasks(),
            parent_trials=trials(pair_identity, subject="parent", infrastructure_invalid=invalid),
            candidate_trials=trials(pair_identity, subject="candidate"),
            gateway=gateway,
        )


def test_task_regressions_transfer_cost_latency_and_aggregate_gain_are_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair, _ = protected_pair(monkeypatch)
    assert pair.eligible is True
    assert pair.aggregate_gain_basis_points > 0
    assert pair.held_out_gain_basis_points > 0
    assert pair.task_deltas == (("affected", 4_000), ("guard", 0), ("held", 2_000))

    candidate = tuple(
        replace(item, score_basis_points=9_000) if item.task.task_id == "guard" else item
        for item in pair.candidate_trials
    )
    regressed = ProtectedLivePair.create(
        identity=pair.identity,
        policy=pair.policy,
        tasks=pair.tasks,
        parent_trials=pair.parent_trials,
        candidate_trials=candidate,
        gateway=protected_gateway(monkeypatch),
    )
    assert regressed.eligible is False
    assert "guard_task_regression" in regressed.reasons

    expensive_usage = OpenAIUsage(0, 0, 1_000, 0, 1_000)
    expensive = tuple(
        replace(
            item,
            cost_microdollars=10_000,
            model_result=model_result(
                item.model_result.request_digest,
                f"expensive-{item.task.task_id}-{item.attempt}",
                usage=expensive_usage,
            ),
        )
        for item in pair.candidate_trials
        if isinstance(item.model_result, ProtectedOpenAIModelResult)
    )
    bounded = ProtectedLivePair.create(
        identity=pair.identity,
        policy=pair.policy,
        tasks=pair.tasks,
        parent_trials=pair.parent_trials,
        candidate_trials=expensive,
        gateway=protected_gateway(monkeypatch),
    )
    assert "live_cost_limit_exceeded" in bounded.reasons


def test_sealed_inputs_and_provider_credentials_never_enter_subject_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from carl_bench.adapters.carl_acp import BoundedModelGatewayCapability

    monkeypatch.setenv("OPENAI_API_KEY", "sk-never-pass-to-subject-123456")
    capability = BoundedModelGatewayCapability(
        endpoint="http://127.0.0.1:43117/v1/evaluate",
        token="pair-task-token-1234567890",
        pair_request_digest=identity().request_digest,
        subject="candidate",
        task_id="held",
        attempt=1,
    )
    environment = capability.subject_environment()

    assert environment == {
        "CARL_MODEL_GATEWAY_ENDPOINT": "http://127.0.0.1:43117/v1/evaluate",
        "CARL_MODEL_GATEWAY_TOKEN": "pair-task-token-1234567890",
    }
    assert "OPENAI_API_KEY" not in environment
    assert not any("grader" in key.lower() or "held" in key.lower() for key in environment)
    with pytest.raises(ValueError, match="gateway capability"):
        replace(capability, subject="other")


def test_synthetic_or_forged_gateway_results_cannot_become_live_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair_identity = identity()
    gateway = protected_gateway(monkeypatch)
    candidate = list(trials(pair_identity, subject="candidate"))
    genuine = candidate[0].model_result
    assert genuine is not None
    candidate[0] = replace(
        candidate[0],
        model_result=SyntheticOpenAIModelResult(
            response_id=genuine.response_id,
            model=genuine.model,
            status=genuine.status,
            usage=genuine.usage,
            latency_ms=genuine.latency_ms,
            request_digest=genuine.request_digest,
            output_digest=genuine.output_digest,
            output_text=genuine.output_text,
        ),
    )
    with pytest.raises(LiveCapabilityError, match="live_model_provenance_invalid"):
        ProtectedLivePair.create(
            identity=pair_identity,
            policy=policy(),
            tasks=tasks(),
            parent_trials=trials(pair_identity, subject="parent"),
            candidate_trials=tuple(candidate),
            gateway=gateway,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "unsigned",
        "unarchived",
        "expired",
        "mutated",
        "wrong_key",
        "cross_run",
        "cross_subject",
    ),
)
def test_combiner_rejects_untrusted_or_identity_mismatched_live_evidence(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    pair, gateway, envelope = attested(monkeypatch)
    deterministic = deterministic_evidence(pair.identity)
    key = KEY
    now = NOW
    if mutation == "unsigned":
        envelope = replace(envelope, signature="")
    elif mutation == "unarchived":
        envelope = replace(envelope, archive=None)
    elif mutation == "expired":
        now = NOW + timedelta(hours=2)
    elif mutation == "mutated":
        envelope = replace(envelope, payload=replace(envelope.payload, eligible=False))
    elif mutation == "wrong_key":
        key = bytes(range(1, 33))
    elif mutation == "cross_run":
        deterministic = deterministic_evidence(
            replace(pair.identity, workflow_digest=digest("other-workflow"), request_digest="")
        )
    else:
        deterministic = deterministic_evidence(
            replace(pair.identity, candidate_commit="9" * 40, request_digest="")
        )

    with pytest.raises(LiveCapabilityError):
        combine_paired_evidence(
            deterministic_evidence=deterministic,
            live_evidence=envelope,
            key=key,
            gateway=gateway,
            now=now,
        )


def test_combiner_rejects_duplicate_reordered_or_missing_trials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair, gateway = protected_pair(monkeypatch)
    defects = (
        pair.parent_trials[:-1],
        (*pair.parent_trials, pair.parent_trials[-1]),
        tuple(reversed(pair.parent_trials)),
    )
    for parent_trials in defects:
        with pytest.raises(LiveCapabilityError):
            ProtectedLivePair.create(
                identity=pair.identity,
                policy=pair.policy,
                tasks=pair.tasks,
                parent_trials=parent_trials,
                candidate_trials=pair.candidate_trials,
                gateway=gateway,
            )


def test_exact_attested_pair_combines_with_deterministic_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair, gateway, envelope = attested(monkeypatch)

    result = combine_paired_evidence(
        deterministic_evidence=deterministic_evidence(pair.identity),
        live_evidence=envelope,
        key=KEY,
        gateway=gateway,
        now=NOW,
    )

    assert verify_live_pair(envelope, key=KEY, gateway=gateway, now=NOW) == pair
    assert result.eligible is True
    assert result.disposition == "improvement"
    assert result.reasons == ()
    encoded = canonical_json_bytes(result.to_canonical_dict())
    assert b"bounded fixture output" not in encoded
    assert b"OPENAI_API_KEY" not in encoded


def test_direct_deterministic_evidence_cannot_claim_an_arbitrary_digest() -> None:
    with pytest.raises(LiveCapabilityError, match="deterministic_evidence_invalid"):
        DeterministicPairEvidence(
            identity=identity(),
            contract_eligible=True,
            contract_reasons=(),
            evidence_digest=digest("attacker-selected-evidence"),
        )


def test_missing_live_evidence_preserves_stable_disposition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CARL_OPENAI_PROVENANCE_KEY_B64", raising=False)
    result = combine_paired_evidence(
        deterministic_evidence=deterministic_evidence(identity()),
        live_evidence=None,
        key=KEY,
        now=NOW,
    )

    assert result.eligible is False
    assert result.disposition == "insufficient_evidence"
    assert result.reasons == ("live_acp_credential_missing",)


def test_live_win_cannot_override_a_deterministic_contract_regression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair, gateway, envelope = attested(monkeypatch)

    result = combine_paired_evidence(
        deterministic_evidence=deterministic_evidence(pair.identity, eligible=False),
        live_evidence=envelope,
        key=KEY,
        gateway=gateway,
        now=NOW,
    )

    assert result.eligible is False
    assert result.disposition == "rejected"
    assert result.reasons == ("deterministic_contract_regression",)


def test_attested_payload_is_canonical_bounded_and_contains_no_raw_provider_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair, _, envelope = attested(monkeypatch)
    encoded = canonical_json_bytes(envelope.to_canonical_dict())
    decoded = json.loads(encoded)

    assert len(encoded) < 1_048_576
    assert decoded["payload"]["digest"] == pair.digest
    assert "bounded fixture output" not in encoded.decode()
