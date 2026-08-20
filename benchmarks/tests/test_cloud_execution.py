from __future__ import annotations

import base64
import json
import re
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import carl_bench.cloud_execution as cloud_execution
from carl_bench.canonical import canonical_json_bytes
from carl_bench.cloud_execution import (
    CloudArtifact,
    CloudExecutionError,
    CloudRetryState,
    CloudRetryStateStore,
    CloudRunDecision,
    CloudRunRequest,
    CloudRunSnapshot,
    CommissioningReceipt,
    CompletedRunObservation,
    SignedCommissioningReceipt,
    SignedCompletedRunObservation,
    TrustedCloudReceiptKey,
    advance_retry_state,
)
from carl_bench.cloud_execution import (
    reconcile_cloud_run as _reconcile_cloud_run,
)

REPOSITORY_ROOT = Path(__file__).parents[2]
WORKFLOW_ROOT = REPOSITORY_ROOT / ".github" / "workflows"
NOW = "2026-08-19T12:00:00Z"
LATER = "2026-08-26T12:00:00Z"
PARENT = "1" * 40
CANDIDATE = "2" * 40
ARTIFACT_DIGEST = "a" * 64
WORKFLOW_REVISION = "7" * 40
WORKFLOW_BLOB_DIGEST = "8" * 64
WORKFLOWS = (
    "autonomous-improvement.yml",
    "autonomous-soak.yml",
)
INPUTS = {
    "experiment_digest",
    "parent_commit",
    "candidate_commit",
    "task_set_digest",
    "metric_pack_digest",
    "policy_digest",
    "request_digest",
    "workflow_revision",
    "workflow_blob_digest",
}
PINNED_ACTIONS = {
    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    "astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990",
}


def request(workflow_file: str = WORKFLOWS[0]) -> CloudRunRequest:
    return CloudRunRequest.create(
        repository="StephenBickel/carl-agent",
        workflow_file=workflow_file,
        experiment_digest="3" * 64,
        parent_commit=PARENT,
        candidate_commit=CANDIDATE,
        task_set_digest="4" * 64,
        metric_pack_digest="5" * 64,
        policy_digest="6" * 64,
        workflow_revision=WORKFLOW_REVISION,
        workflow_blob_digest=WORKFLOW_BLOB_DIGEST,
    )


def artifact(cloud_request: CloudRunRequest, *, downloaded: bool = True) -> CloudArtifact:
    return CloudArtifact(
        artifact_id=99,
        name=cloud_request.expected_artifact_name,
        run_id=42,
        digest=ARTIFACT_DIGEST,
        downloaded_digest=ARTIFACT_DIGEST if downloaded else None,
    )


def commissioning_receipt(cloud_request: CloudRunRequest) -> CommissioningReceipt:
    return CommissioningReceipt(
        schema_version=2,
        repository=cloud_request.repository,
        workflow_file=cloud_request.workflow_file,
        workflow_path=cloud_request.expected_workflow_path,
        workflow_revision=cloud_request.workflow_revision,
        workflow_blob_digest=cloud_request.workflow_blob_digest,
        request_digest=cloud_request.request_digest,
        experiment_digest=cloud_request.experiment_digest,
        task_set_digest=cloud_request.task_set_digest,
        metric_pack_digest=cloud_request.metric_pack_digest,
        policy_digest=cloud_request.policy_digest,
        run_id=42,
        status="completed",
        conclusion="success",
        observed_at=NOW,
        artifact_id=99,
        artifact_name=cloud_request.expected_artifact_name,
        artifact_digest=ARTIFACT_DIGEST,
    )


def trusted_key(
    private_key: Ed25519PrivateKey, *, key_id: str = "cloud-observer-v1"
) -> TrustedCloudReceiptKey:
    return TrustedCloudReceiptKey(
        key_id=key_id,
        public_key_pem=private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def sign_commissioning_receipt(
    receipt: CommissioningReceipt,
    private_key: Ed25519PrivateKey,
    *,
    key_id: str = "cloud-observer-v1",
) -> SignedCommissioningReceipt:
    return SignedCommissioningReceipt(
        receipt=receipt,
        receipt_digest=receipt.digest,
        key_id=key_id,
        signature_base64=base64.b64encode(
            private_key.sign(canonical_json_bytes(receipt.to_canonical_dict()))
        ).decode("ascii"),
    )


def completed_run_observation(
    cloud_request: CloudRunRequest,
    *,
    run_id: int = 42,
    conclusion: str = "timed_out",
    observed_at: str = NOW,
) -> CompletedRunObservation:
    return CompletedRunObservation(
        schema_version=1,
        run_id=run_id,
        repository=cloud_request.repository,
        workflow_revision=cloud_request.workflow_revision,
        workflow_path=cloud_request.expected_workflow_path,
        workflow_blob_digest=cloud_request.workflow_blob_digest,
        request_digest=cloud_request.request_digest,
        status="completed",
        infrastructure_conclusion=conclusion,
        observed_at=observed_at,
    )


def sign_completed_run_observation(
    observation: CompletedRunObservation,
    private_key: Ed25519PrivateKey,
    *,
    key_id: str = "cloud-observer-v1",
) -> SignedCompletedRunObservation:
    return SignedCompletedRunObservation(
        observation=observation,
        observation_digest=observation.digest,
        key_id=key_id,
        signature_base64=base64.b64encode(
            private_key.sign(canonical_json_bytes(observation.to_canonical_dict()))
        ).decode("ascii"),
    )


def signed_observation_for_decision(
    cloud_request: CloudRunRequest,
    decision: CloudRunDecision,
) -> SignedCompletedRunObservation:
    assert decision.run_id is not None
    assert decision.conclusion is not None
    assert decision.observed_at is not None
    return sign_completed_run_observation(
        completed_run_observation(
            cloud_request,
            run_id=decision.run_id,
            conclusion=decision.conclusion,
            observed_at=decision.observed_at,
        ),
        TEST_SIGNER,
    )


TEST_SIGNER = Ed25519PrivateKey.generate()
TEST_TRUSTED_KEY = trusted_key(TEST_SIGNER)


def reconcile_cloud_run(
    cloud_request: CloudRunRequest,
    cloud_snapshot: CloudRunSnapshot,
    **kwargs: object,
):
    kwargs.setdefault("trusted_receipt_key", TEST_TRUSTED_KEY)
    return _reconcile_cloud_run(cloud_request, cloud_snapshot, **kwargs)


def snapshot(
    cloud_request: CloudRunRequest | None = None, **changes: object
) -> CloudRunSnapshot:
    current = cloud_request or request()
    conclusion = changes.get("conclusion", "success")
    run_id = changes.get("run_id", 42)
    observed_at = changes.get("observed_at", NOW)
    signed_observation = None
    if conclusion in {"action_required", "cancelled", "stale", "startup_failure", "timed_out"}:
        signed_observation = sign_completed_run_observation(
            completed_run_observation(
                current,
                run_id=run_id,  # type: ignore[arg-type]
                conclusion=conclusion,  # type: ignore[arg-type]
                observed_at=observed_at,  # type: ignore[arg-type]
            ),
            TEST_SIGNER,
        )
    base = CloudRunSnapshot(
        remote_available=True,
        observed_at=NOW,
        repository=current.repository,
        workflow_file=current.workflow_file,
        workflow_path=current.expected_workflow_path,
        workflow_blob_digest=current.workflow_blob_digest,
        request_digest=current.request_digest,
        dispatch_key=current.dispatch_key,
        run_id=42,
        head_sha=current.workflow_revision,
        status="completed",
        conclusion="success",
        attempt=1,
        max_attempts=3,
        attempt_key=current.attempt_key(1),
        prior_run_ids=(),
        artifacts=(artifact(current),),
        artifacts_expires_at=LATER,
        commissioning_receipt=sign_commissioning_receipt(
            commissioning_receipt(current), TEST_SIGNER
        ),
        completed_run_observation=signed_observation,
    )
    return replace(base, **changes)


def _parse_workflow(name: str) -> dict[str, object]:
    script = (
        'require "yaml"; require "json"; '
        "value = YAML.safe_load(File.read(ARGV.fetch(0)), permitted_classes: [], aliases: false); "
        "STDOUT.write(JSON.generate(value))"
    )
    result = subprocess.run(
        ["ruby", "-e", script, str(WORKFLOW_ROOT / name)],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    value = json.loads(result.stdout)
    assert isinstance(value, dict)
    return value


def _jobs(workflow: dict[str, object]) -> dict[str, dict[str, object]]:
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    assert all(isinstance(job, dict) for job in jobs.values())
    return jobs  # type: ignore[return-value]


def test_request_digest_and_dispatch_key_are_exact_and_idempotent() -> None:
    first = request()
    duplicate = request()
    changed_candidate = CloudRunRequest.create(
        repository=first.repository,
        workflow_file=first.workflow_file,
        experiment_digest=first.experiment_digest,
        parent_commit=first.parent_commit,
        candidate_commit="7" * 40,
        task_set_digest=first.task_set_digest,
        metric_pack_digest=first.metric_pack_digest,
        policy_digest=first.policy_digest,
        workflow_revision=first.workflow_revision,
        workflow_blob_digest=first.workflow_blob_digest,
    )

    assert first.request_digest == duplicate.request_digest
    assert first.dispatch_key == duplicate.dispatch_key
    assert changed_candidate.request_digest != first.request_digest
    assert changed_candidate.dispatch_key != first.dispatch_key
    assert reconcile_cloud_run(first, CloudRunSnapshot(True, NOW)).action == "dispatch"

    accepted_dispatch = CloudRunSnapshot(
        remote_available=True,
        observed_at=NOW,
        repository=first.repository,
        workflow_file=first.workflow_file,
        request_digest=first.request_digest,
        dispatch_key=first.dispatch_key,
        attempt=1,
        max_attempts=3,
        attempt_key=first.attempt_key(1),
    )
    decision = reconcile_cloud_run(first, accepted_dispatch)
    assert decision.action == "await_run"
    assert decision.dispatch_key == first.dispatch_key


def test_accepted_dispatch_without_durable_attempt_key_fails_closed() -> None:
    cloud_request = request()
    decision = reconcile_cloud_run(
        cloud_request,
        CloudRunSnapshot(
            remote_available=True,
            observed_at=NOW,
            repository=cloud_request.repository,
            workflow_file=cloud_request.workflow_file,
            request_digest=cloud_request.request_digest,
            dispatch_key=cloud_request.dispatch_key,
        ),
    )

    assert decision.action == "blocked"
    assert decision.reason == "cloud_attempt_key_missing"


def test_only_the_two_cloud_workflows_can_be_requested() -> None:
    with pytest.raises(CloudExecutionError, match="cloud_workflow_not_allowed"):
        request("ci.yml")


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("repository", "other/project", "cloud_run_repository_mismatch"),
        ("workflow_file", WORKFLOWS[1], "cloud_run_workflow_mismatch"),
        (
            "workflow_path",
            ".github/workflows/autonomous-soak.yml",
            "cloud_run_workflow_path_mismatch",
        ),
        ("workflow_blob_digest", "0" * 64, "cloud_run_workflow_blob_mismatch"),
        ("request_digest", "0" * 64, "cloud_run_request_mismatch"),
        ("dispatch_key", "cloud-run-" + "0" * 64, "cloud_run_dispatch_key_mismatch"),
        ("head_sha", "0" * 40, "cloud_run_head_mismatch"),
    ],
)
def test_run_identity_mismatch_fails_closed(field: str, value: str, reason: str) -> None:
    decision = reconcile_cloud_run(request(), snapshot(**{field: value}))

    assert decision.action == "blocked"
    assert decision.reason == reason
    assert decision.run_id == 42


def test_candidate_ref_cannot_supply_the_workflow_that_evaluates_it() -> None:
    cloud_request = request()

    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, head_sha=cloud_request.candidate_commit),
    )

    assert decision.action == "blocked"
    assert decision.reason == "cloud_run_head_mismatch"


def test_protected_workflow_revision_is_the_run_head_not_the_candidate() -> None:
    cloud_request = request()

    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, head_sha=cloud_request.workflow_revision),
    )

    assert decision.action == "record_success"
    assert decision.head_sha == cloud_request.workflow_revision


def test_run_without_observed_workflow_path_and_blob_fails_closed() -> None:
    cloud_request = request()

    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, workflow_path=None),
    )

    assert decision.action == "blocked"
    assert decision.reason == "cloud_run_workflow_path_missing"


def test_run_without_observed_workflow_blob_fails_closed() -> None:
    cloud_request = request()

    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, workflow_blob_digest=None),
    )

    assert decision.action == "blocked"
    assert decision.reason == "cloud_run_workflow_blob_missing"


def test_running_then_successful_run_downloads_and_records_exact_artifacts() -> None:
    cloud_request = request()
    running = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            status="in_progress",
            conclusion=None,
            artifacts=(),
            artifacts_expires_at=None,
        ),
    )
    download = reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, artifacts=(artifact(cloud_request, downloaded=False),)),
    )
    success = reconcile_cloud_run(cloud_request, snapshot(cloud_request))

    assert running.action == "await_run"
    assert download.action == "download_artifacts"
    assert download.artifact_name == cloud_request.expected_artifact_name
    assert download.artifact_id == 99
    assert success.action == "record_success"
    assert success.repository == cloud_request.repository
    assert success.workflow_file == cloud_request.workflow_file
    assert success.request_digest == cloud_request.request_digest
    assert success.run_id == 42
    assert success.head_sha == WORKFLOW_REVISION
    assert success.conclusion == "success"
    assert success.artifact_name == cloud_request.expected_artifact_name
    assert success.artifact_id == 99
    assert success.artifact_digest == ARTIFACT_DIGEST


def test_downloaded_artifact_digest_mismatch_fails_closed() -> None:
    cloud_request = request()
    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            artifacts=(replace(artifact(cloud_request), downloaded_digest="0" * 64),),
        ),
    )

    assert decision.action == "blocked"
    assert decision.reason == "cloud_artifact_digest_mismatch"


@pytest.mark.parametrize(
    "artifacts",
    (
        (),
        (
            CloudArtifact(99, "wrong-name", 42, ARTIFACT_DIGEST, ARTIFACT_DIGEST),
        ),
        (
            CloudArtifact(99, "placeholder", 41, ARTIFACT_DIGEST, ARTIFACT_DIGEST),
        ),
        (
            CloudArtifact(99, "placeholder", 42, ARTIFACT_DIGEST, ARTIFACT_DIGEST),
            CloudArtifact(100, "other", 42, "b" * 64, "b" * 64),
        ),
    ),
)
def test_exactly_one_request_named_artifact_must_belong_to_the_bound_run(
    artifacts: tuple[CloudArtifact, ...],
) -> None:
    cloud_request = request()
    normalized = tuple(
        replace(value, name=cloud_request.expected_artifact_name)
        if value.name == "placeholder"
        else value
        for value in artifacts
    )

    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, artifacts=normalized),
    )

    assert decision.action == "blocked"
    assert decision.reason in {
        "cloud_artifact_identity_missing",
        "cloud_artifact_count_mismatch",
        "cloud_artifact_name_mismatch",
        "cloud_artifact_run_mismatch",
    }


def test_expired_artifacts_are_never_downloaded_or_recorded() -> None:
    decision = reconcile_cloud_run(
        request(),
        snapshot(artifacts_expires_at="2026-08-19T11:59:59Z"),
    )

    assert decision.action == "blocked"
    assert decision.reason == "cloud_artifact_expired"


@pytest.mark.parametrize(
    "command",
    (
        "cargo test --locked",
        "cargo-nextest run --locked",
        "pytest -q benchmarks/tests",
        "docker compose up",
        "docker-compose up",
        "colima start",
        "./scripts/benchmark-smoke.sh",
        "run production soak probes",
    ),
)
def test_remote_unavailability_rejects_every_heavy_local_fallback(command: str) -> None:
    decision = reconcile_cloud_run(
        request(),
        CloudRunSnapshot(
            remote_available=False,
            observed_at=NOW,
            local_fallback_command=command,
        ),
    )

    assert decision.action == "blocked"
    assert decision.reason == "local_heavy_fallback_forbidden"


def test_remote_unavailability_without_fallback_schedules_bounded_retry() -> None:
    cloud_request = request()
    decision = reconcile_cloud_run(
        cloud_request,
        CloudRunSnapshot(
            remote_available=False,
            observed_at=NOW,
            attempt_key=cloud_request.attempt_key(1),
        ),
    )

    assert decision.action == "schedule_retry"
    assert decision.reason == "cloud_execution_unavailable"
    assert decision.next_attempt == 2
    assert decision.next_attempt_key == request().attempt_key(2)


def test_remote_unavailability_without_current_attempt_key_fails_closed() -> None:
    decision = reconcile_cloud_run(
        request(), CloudRunSnapshot(remote_available=False, observed_at=NOW)
    )

    assert decision.action == "blocked"
    assert decision.reason == "cloud_attempt_key_missing"


def test_retry_budget_is_exactly_three_attempts() -> None:
    cloud_request = request()

    with pytest.raises(CloudExecutionError, match="invalid_cloud_attempt"):
        cloud_request.attempt_key(4)
    with pytest.raises(CloudExecutionError, match="invalid_cloud_retry_state"):
        CloudRunSnapshot(
            remote_available=False,
            observed_at=NOW,
            attempt=1,
            max_attempts=4,
            attempt_key=cloud_request.attempt_key(1),
        )


def test_retry_budget_is_bounded_and_replay_is_idempotent() -> None:
    cloud_request = request()
    failed_attempt = snapshot(
        cloud_request,
        conclusion="timed_out",
        artifacts=(),
        artifacts_expires_at=None,
    )
    first = reconcile_cloud_run(cloud_request, failed_attempt)
    replay = reconcile_cloud_run(cloud_request, failed_attempt)
    exhausted = reconcile_cloud_run(
        cloud_request,
        replace(
            failed_attempt,
            attempt=3,
            attempt_key=cloud_request.attempt_key(3),
            prior_run_ids=(40, 41),
        ),
    )

    assert first == replay
    assert first.next_attempt == 2
    assert first.next_attempt_key == cloud_request.attempt_key(2)
    assert first.retry_not_before == "2026-08-19T12:05:00Z"
    assert exhausted.action == "blocked"
    assert exhausted.reason == "cloud_retry_budget_exhausted"


def test_retry_transition_is_durable_atomic_and_idempotent(tmp_path: Path) -> None:
    cloud_request = request()
    initial = CloudRetryState.initial(cloud_request)
    store = CloudRetryStateStore(tmp_path / "retry-state.json")
    assert store.initialize(initial) == initial
    failed_attempt = snapshot(
        cloud_request,
        conclusion="timed_out",
        artifacts=(),
        artifacts_expires_at=None,
    )
    decision = reconcile_cloud_run(cloud_request, failed_attempt)
    observation = signed_observation_for_decision(cloud_request, decision)
    replacement = advance_retry_state(
        initial,
        request=cloud_request,
        decision=decision,
        prior_run_id=42,
        completed_run_observation=observation,
        trusted_receipt_key=TEST_TRUSTED_KEY,
    )

    persisted = store.compare_and_swap(
        expected=initial,
        replacement=replacement,
        retry_decision=decision,
        completed_run_observation=observation,
        trusted_receipt_key=TEST_TRUSTED_KEY,
    )
    replayed = store.compare_and_swap(
        expected=initial,
        replacement=replacement,
        retry_decision=decision,
        completed_run_observation=observation,
        trusted_receipt_key=TEST_TRUSTED_KEY,
    )

    assert persisted == replayed == replacement
    assert store.load() == replacement
    assert replacement.attempt == 2
    assert replacement.attempt_key == cloud_request.attempt_key(2)
    assert replacement.prior_run_ids == (42,)
    assert replacement.prior_observation_digests == (observation.observation_digest,)
    assert replacement.retry_not_before == "2026-08-19T12:05:00Z"
    assert json.loads((tmp_path / "retry-state.json").read_text(encoding="utf-8")) == {
        "attempt": 2,
        "attempt_key": cloud_request.attempt_key(2),
        "prior_observation_digests": [observation.observation_digest],
        "prior_run_ids": [42],
        "request_digest": cloud_request.request_digest,
        "retry_not_before": "2026-08-19T12:05:00Z",
        "revision": 1,
        "schema_version": 2,
    }


def test_retry_state_cas_rejects_a_different_stale_transition(tmp_path: Path) -> None:
    cloud_request = request()
    initial = CloudRetryState.initial(cloud_request)
    store = CloudRetryStateStore(tmp_path / "retry-state.json")
    store.initialize(initial)
    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            conclusion="timed_out",
            artifacts=(),
            artifacts_expires_at=None,
        ),
    )
    observation = signed_observation_for_decision(cloud_request, decision)
    first = advance_retry_state(
        initial,
        request=cloud_request,
        decision=decision,
        prior_run_id=42,
        completed_run_observation=observation,
        trusted_receipt_key=TEST_TRUSTED_KEY,
    )
    store.compare_and_swap(
        expected=initial,
        replacement=first,
        retry_decision=decision,
        completed_run_observation=observation,
        trusted_receipt_key=TEST_TRUSTED_KEY,
    )
    different = replace(first, prior_run_ids=(41,))

    with pytest.raises(CloudExecutionError, match="cloud_retry_transition_invalid"):
        store.compare_and_swap(
            expected=initial, replacement=different, retry_decision=decision
        )


def test_retry_cas_rejects_skip_reset_missing_deadline_and_history_attacks(
    tmp_path: Path,
) -> None:
    cloud_request = request()
    initial = CloudRetryState.initial(cloud_request)
    store = CloudRetryStateStore(tmp_path / "retry-state.json")
    store.initialize(initial)

    skip = CloudRetryState(
        schema_version=2,
        request_digest=cloud_request.request_digest,
        revision=1,
        attempt=3,
        attempt_key=cloud_request.attempt_key(3),
        prior_run_ids=(40, 41),
        prior_observation_digests=("a" * 64, "b" * 64),
        retry_not_before="2026-08-19T12:05:00Z",
    )
    with pytest.raises(CloudExecutionError, match="cloud_retry_transition_invalid"):
        store.compare_and_swap(
            expected=initial,
            replacement=skip,
            retry_decision=reconcile_cloud_run(
                cloud_request,
                snapshot(
                    cloud_request,
                    conclusion="timed_out",
                    artifacts=(),
                    artifacts_expires_at=None,
                ),
            ),
        )

    with pytest.raises(CloudExecutionError, match="invalid_cloud_retry_state"):
        CloudRetryState(
            schema_version=2,
            request_digest=cloud_request.request_digest,
            revision=1,
            attempt=2,
            attempt_key=cloud_request.attempt_key(2),
            prior_run_ids=(42,),
            prior_observation_digests=("a" * 64,),
            retry_not_before=None,
        )

    first_decision = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            conclusion="timed_out",
            artifacts=(),
            artifacts_expires_at=None,
        ),
    )
    first_observation = signed_observation_for_decision(cloud_request, first_decision)
    first = advance_retry_state(
        initial,
        request=cloud_request,
        decision=first_decision,
        prior_run_id=42,
        completed_run_observation=first_observation,
        trusted_receipt_key=TEST_TRUSTED_KEY,
    )
    store.compare_and_swap(
        expected=initial,
        replacement=first,
        retry_decision=first_decision,
        completed_run_observation=first_observation,
        trusted_receipt_key=TEST_TRUSTED_KEY,
    )
    second_decision = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            run_id=43,
            conclusion="timed_out",
            attempt=2,
            attempt_key=cloud_request.attempt_key(2),
            prior_run_ids=(42,),
            artifacts=(),
            artifacts_expires_at=None,
        ),
    )
    reset = CloudRetryState(
        schema_version=2,
        request_digest=cloud_request.request_digest,
        revision=2,
        attempt=1,
        attempt_key=cloud_request.attempt_key(1),
        prior_run_ids=(),
        prior_observation_digests=(),
        retry_not_before=None,
    )
    with pytest.raises(CloudExecutionError, match="cloud_retry_transition_invalid"):
        store.compare_and_swap(
            expected=first, replacement=reset, retry_decision=second_decision
        )

    second = CloudRetryState(
        schema_version=2,
        request_digest=cloud_request.request_digest,
        revision=2,
        attempt=3,
        attempt_key=cloud_request.attempt_key(3),
        prior_run_ids=(42, 44),
        prior_observation_digests=(first_observation.observation_digest, "b" * 64),
        retry_not_before="2026-08-19T12:15:00Z",
    )
    with pytest.raises(CloudExecutionError, match="cloud_retry_transition_invalid"):
        store.compare_and_swap(
            expected=first, replacement=second, retry_decision=second_decision
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("attempt_key", "cloud-run-" + "0" * 64 + "-attempt-2"),
        ("retry_not_before", None),
        ("prior_run_ids", ()),
        ("prior_run_ids", (42, 43)),
    ),
)
def test_retry_cas_revalidates_even_a_tampered_state_object(
    tmp_path: Path, field: str, value: object
) -> None:
    cloud_request = request()
    initial = CloudRetryState.initial(cloud_request)
    store = CloudRetryStateStore(tmp_path / "retry-state.json")
    store.initialize(initial)
    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            conclusion="timed_out",
            artifacts=(),
            artifacts_expires_at=None,
        ),
    )
    observation = signed_observation_for_decision(cloud_request, decision)
    replacement = advance_retry_state(
        initial,
        request=cloud_request,
        decision=decision,
        prior_run_id=42,
        completed_run_observation=observation,
        trusted_receipt_key=TEST_TRUSTED_KEY,
    )
    object.__setattr__(replacement, field, value)

    with pytest.raises(CloudExecutionError, match="cloud_retry_transition_invalid"):
        store.compare_and_swap(
            expected=initial, replacement=replacement, retry_decision=decision
        )


def test_advance_retry_requires_completed_prior_run_id() -> None:
    cloud_request = request()
    initial = CloudRetryState.initial(cloud_request)
    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            conclusion="timed_out",
            artifacts=(),
            artifacts_expires_at=None,
        ),
    )

    with pytest.raises(TypeError):
        advance_retry_state(initial, request=cloud_request, decision=decision)


def test_retry_decision_without_signed_completed_run_observation_is_rejected() -> None:
    cloud_request = request()
    initial = CloudRetryState.initial(cloud_request)
    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            conclusion="timed_out",
            artifacts=(),
            artifacts_expires_at=None,
        ),
    )

    with pytest.raises(
        CloudExecutionError,
        match="cloud_completed_run_observation_missing",
    ):
        advance_retry_state(
            initial,
            request=cloud_request,
            decision=decision,
            prior_run_id=42,
        )


def test_retry_attempt_rejects_reused_run_and_wrong_attempt_key() -> None:
    cloud_request = request()
    reused = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            attempt=2,
            attempt_key=cloud_request.attempt_key(2),
            prior_run_ids=(42,),
        ),
    )
    wrong_key = reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, attempt_key=cloud_request.attempt_key(2)),
    )

    assert reused.action == "blocked"
    assert reused.reason == "cloud_run_id_reused"
    assert wrong_key.action == "blocked"
    assert wrong_key.reason == "cloud_attempt_key_mismatch"


def test_completed_infrastructure_failure_schedules_retry_but_test_failure_blocks() -> None:
    retry = reconcile_cloud_run(
        request(),
        snapshot(
            conclusion="timed_out",
            artifacts=(),
            artifacts_expires_at=None,
        ),
    )
    failed = reconcile_cloud_run(
        request(),
        snapshot(
            conclusion="failure",
            artifacts=(),
            artifacts_expires_at=None,
        ),
    )

    assert retry.action == "schedule_retry"
    assert retry.reason == "cloud_run_infrastructure_failure"
    assert failed.action == "blocked"
    assert failed.reason == "cloud_run_failed"


def test_completed_infrastructure_failure_without_signed_observation_blocks() -> None:
    cloud_request = request()

    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            conclusion="timed_out",
            artifacts=(),
            artifacts_expires_at=None,
            completed_run_observation=None,
        ),
    )

    assert decision.action == "blocked"
    assert decision.reason == "cloud_completed_run_observation_missing"


def test_signed_completed_run_observation_authorizes_and_binds_atomic_retry(
    tmp_path: Path,
) -> None:
    observation_type = getattr(cloud_execution, "CompletedRunObservation", None)
    signed_type = getattr(cloud_execution, "SignedCompletedRunObservation", None)
    assert observation_type is not None, "canonical completed-run observation is required"
    assert signed_type is not None, "signed completed-run observation is required"

    cloud_request = request()
    observation = observation_type(
        schema_version=1,
        run_id=42,
        repository=cloud_request.repository,
        workflow_revision=cloud_request.workflow_revision,
        workflow_path=cloud_request.expected_workflow_path,
        workflow_blob_digest=cloud_request.workflow_blob_digest,
        request_digest=cloud_request.request_digest,
        status="completed",
        infrastructure_conclusion="timed_out",
        observed_at=NOW,
    )
    signer = Ed25519PrivateKey.generate()
    signed = signed_type(
        observation=observation,
        observation_digest=observation.digest,
        key_id="cloud-observer-v1",
        signature_base64=base64.b64encode(
            signer.sign(canonical_json_bytes(observation.to_canonical_dict()))
        ).decode("ascii"),
    )
    verifier = trusted_key(signer)
    failed_run = snapshot(
        cloud_request,
        conclusion="timed_out",
        artifacts=(),
        artifacts_expires_at=None,
        completed_run_observation=signed,
    )

    decision = cloud_execution.reconcile_cloud_run(
        cloud_request,
        failed_run,
        trusted_receipt_key=verifier,
    )
    initial = CloudRetryState.initial(cloud_request)
    replacement = advance_retry_state(
        initial,
        request=cloud_request,
        decision=decision,
        prior_run_id=42,
        completed_run_observation=signed,
        trusted_receipt_key=verifier,
    )
    store = CloudRetryStateStore(tmp_path / "retry-state.json")
    store.initialize(initial)
    persisted = store.compare_and_swap(
        expected=initial,
        replacement=replacement,
        retry_decision=decision,
        completed_run_observation=signed,
        trusted_receipt_key=verifier,
    )

    assert decision.action == "schedule_retry"
    assert decision.completed_run_observation_digest == observation.digest
    assert replacement.prior_observation_digests == (observation.digest,)
    assert persisted == replacement


def test_completed_run_observation_rejects_unsigned_forged_and_mismatched_facts() -> None:
    cloud_request = request()
    signer = Ed25519PrivateKey.generate()
    raw = completed_run_observation(cloud_request)
    signed = sign_completed_run_observation(raw, signer)
    forged_signature = replace(
        signed,
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )
    mismatched_revision = sign_completed_run_observation(
        replace(raw, workflow_revision="9" * 40),
        signer,
    )

    unsigned = cloud_execution.reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, conclusion="timed_out", artifacts=(), artifacts_expires_at=None,
                 completed_run_observation=raw),
        trusted_receipt_key=trusted_key(signer),
    )
    forged = cloud_execution.reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, conclusion="timed_out", artifacts=(), artifacts_expires_at=None,
                 completed_run_observation=forged_signature),
        trusted_receipt_key=trusted_key(signer),
    )
    mismatched = cloud_execution.reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, conclusion="timed_out", artifacts=(), artifacts_expires_at=None,
                 completed_run_observation=mismatched_revision),
        trusted_receipt_key=trusted_key(signer),
    )

    assert unsigned.reason == "cloud_completed_run_signature_missing"
    assert forged.reason == "cloud_completed_run_signature_invalid"
    assert mismatched.reason == "cloud_completed_run_revision_mismatch"
    assert {unsigned.action, forged.action, mismatched.action} == {"blocked"}


def test_retry_cas_reverifies_signed_observation_and_rejects_manual_decision(
    tmp_path: Path,
) -> None:
    cloud_request = request()
    failed = snapshot(
        cloud_request,
        conclusion="timed_out",
        artifacts=(),
        artifacts_expires_at=None,
    )
    decision = reconcile_cloud_run(cloud_request, failed)
    observation = signed_observation_for_decision(cloud_request, decision)
    initial = CloudRetryState.initial(cloud_request)
    replacement = advance_retry_state(
        initial,
        request=cloud_request,
        decision=decision,
        prior_run_id=42,
        completed_run_observation=observation,
        trusted_receipt_key=TEST_TRUSTED_KEY,
    )
    manual_decision = replace(decision, completed_run_observation_digest=None)
    with pytest.raises(
        CloudExecutionError,
        match="cloud_retry_observation_digest_mismatch",
    ):
        advance_retry_state(
            initial,
            request=cloud_request,
            decision=manual_decision,
            prior_run_id=42,
            completed_run_observation=observation,
            trusted_receipt_key=TEST_TRUSTED_KEY,
        )

    store = CloudRetryStateStore(tmp_path / "retry-state.json")
    store.initialize(initial)
    forged = replace(
        observation,
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )
    with pytest.raises(CloudExecutionError, match="cloud_completed_run_signature_invalid"):
        store.compare_and_swap(
            expected=initial,
            replacement=replacement,
            retry_decision=decision,
            completed_run_observation=forged,
            trusted_receipt_key=TEST_TRUSTED_KEY,
        )
    assert store.load() == initial


def test_success_requires_exact_remote_commissioning_receipt() -> None:
    cloud_request = request()
    absent = reconcile_cloud_run(
        cloud_request, snapshot(cloud_request, commissioning_receipt=None)
    )
    wrong_run = replace(commissioning_receipt(cloud_request), run_id=41)
    mismatched = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            commissioning_receipt=sign_commissioning_receipt(wrong_run, TEST_SIGNER),
        ),
    )

    assert absent.action == "blocked"
    assert absent.reason == "cloud_commissioning_receipt_missing"
    assert mismatched.action == "blocked"
    assert mismatched.reason == "cloud_commissioning_run_mismatch"


def test_manually_constructed_unsigned_commissioning_receipt_fails_closed() -> None:
    cloud_request = request()

    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            commissioning_receipt=commissioning_receipt(cloud_request),
        ),
    )

    assert decision.action == "blocked"
    assert decision.reason == "cloud_commissioning_signature_missing"


def test_valid_canonical_signed_commissioning_receipt_authorizes_exact_run() -> None:
    cloud_request = request()
    receipt = CommissioningReceipt(
        schema_version=2,
        repository=cloud_request.repository,
        workflow_file=cloud_request.workflow_file,
        workflow_path=cloud_request.expected_workflow_path,
        workflow_revision=cloud_request.workflow_revision,
        workflow_blob_digest=cloud_request.workflow_blob_digest,
        request_digest=cloud_request.request_digest,
        experiment_digest=cloud_request.experiment_digest,
        task_set_digest=cloud_request.task_set_digest,
        metric_pack_digest=cloud_request.metric_pack_digest,
        policy_digest=cloud_request.policy_digest,
        run_id=42,
        status="completed",
        conclusion="success",
        observed_at=NOW,
        artifact_id=99,
        artifact_name=cloud_request.expected_artifact_name,
        artifact_digest=ARTIFACT_DIGEST,
    )
    private_key = Ed25519PrivateKey.generate()
    signed = sign_commissioning_receipt(receipt, private_key)

    decision = cloud_execution.reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, commissioning_receipt=signed),
        trusted_receipt_key=trusted_key(private_key),
    )

    assert decision.action == "record_success"
    assert decision.reason == "cloud_run_evidence_verified"


def test_signed_commissioning_requires_the_configured_trusted_public_key() -> None:
    cloud_request = request()
    signer = Ed25519PrivateKey.generate()
    signed = sign_commissioning_receipt(commissioning_receipt(cloud_request), signer)

    missing_key = _reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, commissioning_receipt=signed),
    )
    attacker_key = reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, commissioning_receipt=signed),
        trusted_receipt_key=trusted_key(Ed25519PrivateKey.generate()),
    )

    assert missing_key.action == "blocked"
    assert missing_key.reason == "cloud_commissioning_trusted_key_missing"
    assert attacker_key.action == "blocked"
    assert attacker_key.reason == "cloud_commissioning_signature_invalid"


def test_commissioning_digest_and_signature_tampering_fail_closed() -> None:
    cloud_request = request()
    signer = Ed25519PrivateKey.generate()
    signed = sign_commissioning_receipt(commissioning_receipt(cloud_request), signer)
    wrong_digest = replace(signed, receipt_digest="0" * 64)
    wrong_signature = replace(
        signed,
        signature_base64=base64.b64encode(b"0" * 64).decode("ascii"),
    )

    digest_decision = reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, commissioning_receipt=wrong_digest),
        trusted_receipt_key=trusted_key(signer),
    )
    signature_decision = reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, commissioning_receipt=wrong_signature),
        trusted_receipt_key=trusted_key(signer),
    )

    assert digest_decision.action == "blocked"
    assert digest_decision.reason == "cloud_commissioning_digest_mismatch"
    assert signature_decision.action == "blocked"
    assert signature_decision.reason == "cloud_commissioning_signature_invalid"


def test_malformed_commissioning_signature_cannot_crash_reconciliation() -> None:
    cloud_request = request()
    signer = Ed25519PrivateKey.generate()
    signed = sign_commissioning_receipt(commissioning_receipt(cloud_request), signer)
    object.__setattr__(signed, "signature_base64", "not-base64")

    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, commissioning_receipt=signed),
        trusted_receipt_key=trusted_key(signer),
    )

    assert decision.action == "blocked"
    assert decision.reason == "cloud_commissioning_signature_invalid"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("repository", "other/project", "cloud_commissioning_repository_mismatch"),
        ("workflow_revision", "9" * 40, "cloud_commissioning_revision_mismatch"),
        ("workflow_blob_digest", "9" * 64, "cloud_commissioning_blob_mismatch"),
        ("request_digest", "9" * 64, "cloud_commissioning_request_mismatch"),
        ("task_set_digest", "9" * 64, "cloud_commissioning_task_set_mismatch"),
        ("artifact_id", 100, "cloud_commissioning_artifact_id_mismatch"),
        ("artifact_digest", "9" * 64, "cloud_commissioning_artifact_digest_mismatch"),
    ),
)
def test_commissioning_receipt_is_bound_to_protected_run_and_inputs(
    field: str, value: object, reason: str
) -> None:
    cloud_request = request()
    receipt = replace(commissioning_receipt(cloud_request), **{field: value})

    decision = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            commissioning_receipt=sign_commissioning_receipt(receipt, TEST_SIGNER),
        ),
    )

    assert decision.action == "blocked"
    assert decision.reason == reason


@pytest.mark.parametrize("name", WORKFLOWS)
def test_workflow_dispatch_contract_is_parsed_and_immutable(name: str) -> None:
    workflow = _parse_workflow(name)
    triggers = workflow["on"]
    assert isinstance(triggers, dict)
    assert set(triggers) == {"workflow_dispatch"}
    dispatch = triggers["workflow_dispatch"]
    assert isinstance(dispatch, dict)
    inputs = dispatch["inputs"]
    assert isinstance(inputs, dict)
    assert set(inputs) == INPUTS
    for contract in inputs.values():
        assert isinstance(contract, dict)
        assert contract["required"] is True
        assert contract["type"] == "string"
        assert "default" not in contract

    assert workflow["permissions"] == {"contents": "read"}
    jobs = _jobs(workflow)
    assert set(jobs) >= {"commission", "evaluate", "evidence"}
    assert jobs["evidence"]["needs"] == ["commission", "evaluate"]
    actions = [
        step["uses"]
        for job in jobs.values()
        for step in job["steps"]
        if isinstance(step, dict) and "uses" in step
    ]
    assert set(actions) == PINNED_ACTIONS
    assert all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", action) for action in actions)
    for job in jobs.values():
        assert "permissions" not in job
        assert job["runs-on"] == "ubuntu-latest"
        assert isinstance(job["timeout-minutes"], int)
        assert job["timeout-minutes"] <= 60
        for step in job["steps"]:
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False


@pytest.mark.parametrize("name", WORKFLOWS)
def test_workflow_executes_from_exact_protected_revision_path_and_blob(name: str) -> None:
    jobs = _jobs(_parse_workflow(name))
    expected_path = f".github/workflows/{name}"
    trusted_checkouts = [
        step
        for job in jobs.values()
        for step in job["steps"]
        if str(step.get("uses", "")).startswith("actions/checkout@")
        and step.get("with", {}).get("path") == "trusted-source"
    ]

    assert trusted_checkouts
    assert all(
        step["with"]["ref"] == "${{ inputs.workflow_revision }}"
        for step in trusted_checkouts
    )

    validation = next(
        step
        for step in jobs["commission"]["steps"]
        if "WORKFLOW_BLOB_DIGEST" in step.get("env", {})
    )
    env = validation["env"]
    commands = validation["run"]
    assert env["RUN_HEAD_SHA"] == "${{ github.sha }}"
    assert env["WORKFLOW_REF"] == "${{ github.workflow_ref }}"
    assert env["WORKFLOW_SHA"] == "${{ github.workflow_sha }}"
    assert env["WORKFLOW_PATH"] == expected_path
    assert "RUN_HEAD_SHA" in commands
    assert "WORKFLOW_REF" in commands
    assert "WORKFLOW_SHA" in commands
    assert "WORKFLOW_PATH" in commands
    assert "sha256sum --check --strict" in commands


@pytest.mark.parametrize("name", WORKFLOWS)
def test_candidate_execution_isolated_from_trusted_evidence_and_inputs(name: str) -> None:
    jobs = _jobs(_parse_workflow(name))
    evaluate = jobs["evaluate"]
    evidence = jobs["evidence"]
    evaluate_commands = "\n".join(step["run"] for step in evaluate["steps"] if "run" in step)
    evidence_serialized = json.dumps(evidence, sort_keys=True)

    assert "GITHUB_ENV=" not in evaluate_commands
    assert "PYTHONDONTWRITEBYTECODE=1" in evaluate_commands
    if name == "autonomous-improvement.yml":
        assert "sudo -u carlparent env -i" in evaluate_commands
        assert "sudo -u carlcandidate env -i" in evaluate_commands
        assert "sudo env -i" in evaluate_commands
        assert "--parent-uid carlparent" in evaluate_commands
        assert "--candidate-uid carlcandidate" in evaluate_commands
        assert "python -m carl_bench.cloud_harness" in evaluate_commands
        assert "carl-bench" not in evaluate_commands
        assert "--adapter scripted" not in evaluate_commands
    else:
        assert "sudo -u nobody env -i" in evaluate_commands
        assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1" in evaluate_commands
        assert "-p no:cacheprovider" in evaluate_commands
    assert "sha256sum --check" in evaluate_commands
    assert "immutable-inputs" in evaluate_commands
    assert "actions/upload-artifact" not in json.dumps(evaluate)
    assert "actions/checkout" not in evidence_serialized
    assert evidence_serialized.count("actions/upload-artifact") == 1


@pytest.mark.parametrize("name", WORKFLOWS)
def test_candidate_cannot_guess_runner_file_command_endpoints(name: str) -> None:
    evaluate = _jobs(_parse_workflow(name))["evaluate"]
    commands = "\n".join(step["run"] for step in evaluate["steps"] if "run" in step)

    assert 'chmod 700 "$(dirname "$GITHUB_ENV")"' in commands


def test_improvement_workflow_runs_real_exact_parent_candidate_pair() -> None:
    jobs = _jobs(_parse_workflow(WORKFLOWS[0]))
    evaluate = jobs["evaluate"]
    commands = "\n".join(step["run"] for step in evaluate["steps"] if "run" in step)

    serialized = json.dumps(evaluate)
    assert "subject-parent" in serialized
    assert "subject-candidate" in serialized
    assert "inputs.parent_commit" in serialized
    assert "inputs.candidate_commit" in serialized
    assert "rev-parse HEAD" in commands
    assert "cargo +1.97.0 build --locked --release" in commands
    assert "python -m carl_bench.cloud_harness" in commands
    assert '--parent-binary "$RUNNER_TEMP/build-parent/target/release/carl"' in commands
    assert '--candidate-binary "$RUNNER_TEMP/build-candidate/target/release/carl"' in commands
    assert "carl-bench" not in commands
    assert "--adapter scripted" not in commands
    assert "paired-result" in commands
    assert "useradd --system --no-create-home --shell /usr/sbin/nologin carlparent" in commands
    assert "useradd --system --no-create-home --shell /usr/sbin/nologin carlcandidate" in commands
    assert "sudo -u carlparent env -i" in commands
    assert "sudo -u carlcandidate env -i" in commands
    assert "sudo env -i" in commands
    assert "--parent-uid carlparent" in commands
    assert "--candidate-uid carlcandidate" in commands
    assert "sudo install -d -m 0700 -o root -g root" in commands
    assert 'test "$(id -u)" != "$(id -u carlparent)"' in commands
    assert 'test "$(id -u)" != "$(id -u carlcandidate)"' in commands
    assert 'sudo -u carlparent test ! -r "$results"' in commands
    assert 'sudo -u carlcandidate test ! -r "$results"' in commands
    assert commands.index("sudo -u carlparent env -i") < commands.index(
        'sha256sum "$parent_binary"'
    )
    assert commands.index('sha256sum "$parent_binary"') < commands.index(
        'chmod -R a-w "$parent_root"'
    )
    assert commands.index('chmod -R a-w "$parent_root"') < commands.index(
        "sudo -u carlcandidate env -i"
    )
    assert commands.count('sha256sum --check "$bound/parent.sha256"') >= 2
    assert "parent_binary_digest=" in commands
    assert "candidate_binary_digest=" in commands
    evidence = json.dumps(jobs["evidence"], sort_keys=True)
    evidence_commands = "\n".join(
        step["run"] for step in jobs["evidence"]["steps"] if "run" in step
    )
    assert '"paired_result": result' in evidence_commands
    assert 'result.get("parent", {}).get("binary_digest")' in evidence_commands
    assert 'result.get("candidate", {}).get("binary_digest")' in evidence_commands
    assert "live_acp_credential_missing" in evidence
    assert jobs["evidence"]["needs"] == ["commission", "evaluate"]


def test_improvement_workflow_runs_locked_suites_and_uploads_bounded_evidence() -> None:
    workflow = _parse_workflow(WORKFLOWS[0])
    jobs = _jobs(workflow)
    job = jobs["evaluate"]
    steps = job["steps"]
    commands = "\n".join(step["run"] for step in steps if isinstance(step, dict) and "run" in step)

    assert "rev-parse HEAD" in commands
    assert "build --locked --release" in commands
    assert "uv sync --project trusted-source/benchmarks --python 3.12 --locked" in commands
    assert "python -m carl_bench.cloud_harness" in commands
    assert "paired" in commands.casefold()
    assert "request_digest" in json.dumps(jobs["evidence"])
    _assert_bounded_credential_free_artifact(jobs["evidence"], "autonomous-improvement-evidence")


def test_soak_workflow_runs_merge_bound_health_probes() -> None:
    workflow = _parse_workflow(WORKFLOWS[1])
    jobs = _jobs(workflow)
    job = jobs["evaluate"]
    steps = job["steps"]
    commands = "\n".join(step["run"] for step in steps if isinstance(step, dict) and "run" in step)

    assert "rev-parse HEAD" in commands
    assert "test --locked" in commands
    assert "pytest -q" in commands
    topology = "\n".join(
        step["run"] for step in jobs["commission"]["steps"] if "run" in step
    )
    assert "rev-list --parents -n 1" in topology
    assert "${#MERGE_TOPOLOGY[@]}" in topology
    assert "MERGE_TOPOLOGY[1]" in topology
    assert "merge_commit" in json.dumps(jobs["evidence"])
    assert "request_digest" in json.dumps(jobs["evidence"])
    _assert_bounded_credential_free_artifact(
        jobs["evidence"], "autonomous-soak-observation"
    )


@pytest.mark.parametrize("name", WORKFLOWS)
def test_commissioning_job_runs_actionlint_on_github_hosted_runner(name: str) -> None:
    jobs = _jobs(_parse_workflow(name))
    commission = jobs["commission"]
    commands = "\n".join(
        step["run"] for step in commission["steps"] if "run" in step
    )

    assert commission["runs-on"] == "ubuntu-latest"
    assert "go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7" in commands
    assert ".github/workflows/autonomous-improvement.yml" in commands
    assert ".github/workflows/autonomous-soak.yml" in commands


def _assert_bounded_credential_free_artifact(job: dict[str, object], artifact_name: str) -> None:
    steps = job["steps"]
    assert isinstance(steps, list)
    serialized = json.dumps(job, sort_keys=True)
    assert "${{ secrets" not in serialized
    assert "GITHUB_TOKEN" not in serialized
    assert "git push" not in serialized
    assert "gh pr merge" not in serialized
    assert "production status" not in serialized.casefold()
    assert "production_status" not in serialized.casefold()

    upload = next(
        step for step in steps if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    )
    options = upload["with"]
    assert options["name"] == f"{artifact_name}-${{{{ inputs.request_digest }}}}"
    assert options["retention-days"] <= 7
    assert options["if-no-files-found"] == "error"
    assert options["include-hidden-files"] is False
    assert "*" not in options["path"]
    commands = "\n".join(step["run"] for step in steps if isinstance(step, dict) and "run" in step)
    assert "1_048_576" in commands
