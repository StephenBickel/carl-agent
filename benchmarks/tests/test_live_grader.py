from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from carl_bench.canonical import canonical_json_bytes
from carl_bench.live_capability import LiveEvaluationIdentity, LiveTaskIdentity
from carl_bench.live_grader import ProtectedGraderBundle, ProtectedLiveGraderError
from carl_bench.openai_gateway import OpenAIUsage, ProtectedOpenAIModelResult


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _fixture(
    root: Path,
) -> tuple[
    ProtectedGraderBundle,
    LiveEvaluationIdentity,
    LiveTaskIdentity,
    ProtectedOpenAIModelResult,
    Path,
]:
    root.mkdir(mode=0o700)
    output_digest = _digest("protected-output")
    task_digest = _digest("task")
    input_digest = _digest("input")
    payload = canonical_json_bytes(
        {
            "algorithm": "exact-output-digest-score-v1",
            "schema_version": 1,
            "tasks": {
                "held": {
                    "input_digest": input_digest,
                    "outputs": {output_digest: 8_750},
                    "task_digest": task_digest,
                }
            },
        }
    )
    grader_digest = hashlib.sha256(payload).hexdigest()
    path = root / f"{grader_digest}.json"
    path.write_bytes(payload)
    path.chmod(0o600)
    task = LiveTaskIdentity("held", task_digest, input_digest, 5, grader_digest, "held_out")
    identity = LiveEvaluationIdentity.create(
        repository="StephenBickel/carl-agent",
        parent_commit="1" * 40,
        parent_tree="2" * 40,
        candidate_commit="3" * 40,
        candidate_tree="4" * 40,
        experiment_digest=_digest("experiment"),
        workflow_revision="5" * 40,
        workflow_digest=_digest("workflow"),
        task_set_digest=_digest("task-set"),
        metric_pack_digest=_digest("metric-pack"),
        policy_digest=_digest("policy"),
        model_policy_digest=_digest("model-policy"),
        grader_digest=grader_digest,
        environment_digest=_digest("environment"),
        model="gpt-5.2",
        reasoning_policy="medium/no-summary",
        tool_protocol_revision="acp-v2/bounded-openai-v1",
        task_order=("held",),
        seeds=(41,),
        attempts=1,
    )
    result = ProtectedOpenAIModelResult(
        "resp-grader",
        "gpt-5.2",
        "completed",
        OpenAIUsage(3, 0, 2, 1, 5),
        9,
        _digest("request"),
        output_digest,
        "private output is not persisted in the receipt",
        _digest("provenance"),
    )
    return (
        ProtectedGraderBundle._for_testing(root=root, expected_uid=os.geteuid()),
        identity,
        task,
        result,
        path,
    )


def test_digest_addressed_protected_grader_owns_exact_output_score(tmp_path: Path) -> None:
    grader, identity, task, result, _ = _fixture(tmp_path / "graders")

    assert grader.grade(identity=identity, task=task, result=result) == 8_750


def test_protected_grader_rejects_unrecognized_output_and_post_read_replacement(
    tmp_path: Path,
) -> None:
    grader, identity, task, result, path = _fixture(tmp_path / "graders")

    with pytest.raises(ProtectedLiveGraderError, match="live_grader_output_unrecognized"):
        grader.grade(
            identity=identity,
            task=task,
            result=ProtectedOpenAIModelResult(
                result.response_id,
                result.model,
                result.status,
                result.usage,
                result.latency_ms,
                result.request_digest,
                _digest("attacker-output"),
                result.output_text,
                result.provenance_tag,
            ),
        )

    path.write_bytes(b'{"schema_version":1}')
    with pytest.raises(ProtectedLiveGraderError, match="live_grader_invalid"):
        grader.grade(identity=identity, task=task, result=result)
