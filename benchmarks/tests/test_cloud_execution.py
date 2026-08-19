from __future__ import annotations

import json
import re
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from carl_bench.cloud_execution import (
    CloudExecutionError,
    CloudRunRequest,
    CloudRunSnapshot,
    reconcile_cloud_run,
)

REPOSITORY_ROOT = Path(__file__).parents[2]
WORKFLOW_ROOT = REPOSITORY_ROOT / ".github" / "workflows"
NOW = "2026-08-19T12:00:00Z"
LATER = "2026-08-26T12:00:00Z"
PARENT = "1" * 40
CANDIDATE = "2" * 40
ARTIFACT_DIGESTS = ("a" * 64, "b" * 64)
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
    )


def snapshot(
    cloud_request: CloudRunRequest | None = None, **changes: object
) -> CloudRunSnapshot:
    current = cloud_request or request()
    base = CloudRunSnapshot(
        remote_available=True,
        observed_at=NOW,
        repository=current.repository,
        workflow_file=current.workflow_file,
        request_digest=current.request_digest,
        dispatch_key=current.dispatch_key,
        run_id=42,
        head_sha=current.candidate_commit,
        status="completed",
        conclusion="success",
        artifact_digests=ARTIFACT_DIGESTS,
        downloaded_artifact_digests=ARTIFACT_DIGESTS,
        artifacts_expires_at=LATER,
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


def _job(workflow: dict[str, object]) -> dict[str, object]:
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    assert len(jobs) == 1
    job = next(iter(jobs.values()))
    assert isinstance(job, dict)
    return job


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
    )
    decision = reconcile_cloud_run(first, accepted_dispatch)
    assert decision.action == "await_run"
    assert decision.dispatch_key == first.dispatch_key


def test_only_the_two_cloud_workflows_can_be_requested() -> None:
    with pytest.raises(CloudExecutionError, match="cloud_workflow_not_allowed"):
        request("ci.yml")


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("repository", "other/project", "cloud_run_repository_mismatch"),
        ("workflow_file", WORKFLOWS[1], "cloud_run_workflow_mismatch"),
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


def test_running_then_successful_run_downloads_and_records_exact_artifacts() -> None:
    cloud_request = request()
    running = reconcile_cloud_run(
        cloud_request,
        snapshot(
            cloud_request,
            status="in_progress",
            conclusion=None,
            artifact_digests=(),
            downloaded_artifact_digests=(),
            artifacts_expires_at=None,
        ),
    )
    download = reconcile_cloud_run(
        cloud_request,
        snapshot(cloud_request, downloaded_artifact_digests=()),
    )
    success = reconcile_cloud_run(cloud_request, snapshot(cloud_request))

    assert running.action == "await_run"
    assert download.action == "download_artifacts"
    assert download.artifact_digests == ARTIFACT_DIGESTS
    assert success.action == "record_success"
    assert success.repository == cloud_request.repository
    assert success.workflow_file == cloud_request.workflow_file
    assert success.request_digest == cloud_request.request_digest
    assert success.run_id == 42
    assert success.head_sha == CANDIDATE
    assert success.conclusion == "success"
    assert success.artifact_digests == ARTIFACT_DIGESTS


def test_downloaded_artifact_digest_mismatch_fails_closed() -> None:
    decision = reconcile_cloud_run(
        request(),
        snapshot(downloaded_artifact_digests=("0" * 64, "b" * 64)),
    )

    assert decision.action == "blocked"
    assert decision.reason == "cloud_artifact_digest_mismatch"


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
    decision = reconcile_cloud_run(
        request(), CloudRunSnapshot(remote_available=False, observed_at=NOW)
    )

    assert decision.action == "schedule_retry"
    assert decision.reason == "cloud_execution_unavailable"


def test_completed_infrastructure_failure_schedules_retry_but_test_failure_blocks() -> None:
    retry = reconcile_cloud_run(
        request(),
        snapshot(
            conclusion="timed_out",
            artifact_digests=(),
            downloaded_artifact_digests=(),
            artifacts_expires_at=None,
        ),
    )
    failed = reconcile_cloud_run(
        request(),
        snapshot(
            conclusion="failure",
            artifact_digests=(),
            downloaded_artifact_digests=(),
            artifacts_expires_at=None,
        ),
    )

    assert retry.action == "schedule_retry"
    assert retry.reason == "cloud_run_infrastructure_failure"
    assert failed.action == "blocked"
    assert failed.reason == "cloud_run_failed"


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
    job = _job(workflow)
    assert "permissions" not in job
    assert job["runs-on"] == "ubuntu-latest"
    assert isinstance(job["timeout-minutes"], int)
    assert job["timeout-minutes"] <= 60
    steps = job["steps"]
    assert isinstance(steps, list)
    actions = [step["uses"] for step in steps if isinstance(step, dict) and "uses" in step]
    assert set(actions) == PINNED_ACTIONS
    assert all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", action) for action in actions)

    checkout = next(
        step
        for step in steps
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert checkout["with"]["ref"] == "${{ inputs.candidate_commit }}"
    assert checkout["with"]["persist-credentials"] is False
    assert checkout["with"]["fetch-depth"] == 0


def test_improvement_workflow_runs_locked_suites_and_uploads_bounded_evidence() -> None:
    workflow = _parse_workflow(WORKFLOWS[0])
    job = _job(workflow)
    steps = job["steps"]
    commands = "\n".join(step["run"] for step in steps if isinstance(step, dict) and "run" in step)

    assert "git rev-parse HEAD" in commands
    assert "cargo test --locked" in commands
    assert "uv sync --project benchmarks --python 3.12 --locked" in commands
    assert "pytest -q" in commands
    assert "paired" in commands.casefold()
    assert "request_digest" in commands
    _assert_bounded_credential_free_artifact(job, "autonomous-improvement-evidence")


def test_soak_workflow_runs_merge_bound_health_probes() -> None:
    workflow = _parse_workflow(WORKFLOWS[1])
    job = _job(workflow)
    steps = job["steps"]
    commands = "\n".join(step["run"] for step in steps if isinstance(step, dict) and "run" in step)

    assert "git rev-parse HEAD" in commands
    assert "cargo test --locked" in commands
    assert "pytest -q" in commands
    assert "merge_commit" in commands
    assert "request_digest" in commands
    _assert_bounded_credential_free_artifact(job, "autonomous-soak-observation")


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
    assert options["name"].startswith(artifact_name)
    assert options["retention-days"] <= 7
    assert options["if-no-files-found"] == "error"
    assert options["include-hidden-files"] is False
    assert "*" not in options["path"]
    commands = "\n".join(step["run"] for step in steps if isinstance(step, dict) and "run" in step)
    assert "1_048_576" in commands
