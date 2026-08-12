from __future__ import annotations

import json
from pathlib import Path

import pytest

from carl_bench.metrics import Disclosure, MetricContractError, MetricVerdict, load_metric_pack


def metric(metric_id: str, observation: str, *, mode: str = "deterministic") -> dict[str, object]:
    return {
        "metric_id": metric_id,
        "version": 1,
        "mode": mode,
        "observation": observation,
        "threshold_basis_points": 10_000,
        "reason_codes": ["behavior_failed", "behavior_missing"],
        "disclosure": "public",
        "judge_justification": (
            "A semantic response assessment is necessary for this behavior."
            if mode == "judge"
            else None
        ),
    }


def write_pack(tmp_path: Path, *, metrics: list[dict[str, object]]) -> Path:
    path = tmp_path / "pack.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "pack_id": "development-v1",
                "pack_version": 1,
                "metrics": metrics,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_metric_pack_is_canonical_sorted_and_content_addressed(tmp_path: Path) -> None:
    pack = load_metric_pack(
        write_pack(
            tmp_path,
            metrics=[
                metric("workflow.audit_written", "final_state"),
                metric("workflow.incident_closed", "final_state"),
            ],
        )
    )

    assert [item.metric_id for item in pack.metrics] == [
        "workflow.audit_written",
        "workflow.incident_closed",
    ]
    assert len(pack.digest) == 64


@pytest.mark.parametrize("schema_version", [True, 1.0])
def test_metric_pack_rejects_non_integer_schema_version(
    tmp_path: Path, schema_version: object
) -> None:
    path = write_pack(
        tmp_path, metrics=[metric("workflow.audit_written", "final_state")]
    )
    value = json.loads(path.read_text(encoding="utf-8"))
    value["schema_version"] = schema_version
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(MetricContractError, match="metric_pack_schema_unsupported"):
        load_metric_pack(path)


@pytest.mark.parametrize("observation", ["command_sequence", "exact_trajectory"])
def test_path_scoring_observations_are_rejected(tmp_path: Path, observation: str) -> None:
    with pytest.raises(MetricContractError, match="metric_observation_unsupported"):
        load_metric_pack(write_pack(tmp_path, metrics=[metric("bad.path", observation)]))


def test_judge_metric_requires_semantic_justification(tmp_path: Path) -> None:
    value = metric("reply.tone", "final_response", mode="judge")
    value["judge_justification"] = ""

    with pytest.raises(MetricContractError, match="judge_justification_required"):
        load_metric_pack(write_pack(tmp_path, metrics=[value]))


@pytest.mark.parametrize(
    ("justification", "code"),
    [
        (
            "A semantic review is required.\nIt must stay on one line.",
            "metric_text_not_single_line",
        ),
        (
            "A semantic review is required.\x1fIt must exclude controls.",
            "metric_text_control_character",
        ),
        (
            "A semantic review must not expose Bearer abcdefghijklmnopqrstuvwxyz.",
            "metric_text_secret_pattern",
        ),
    ],
)
def test_judge_justification_rejects_unsafe_text(
    tmp_path: Path, justification: str, code: str
) -> None:
    value = metric("reply.tone", "final_response", mode="judge")
    value["judge_justification"] = justification

    with pytest.raises(MetricContractError, match=code):
        load_metric_pack(write_pack(tmp_path, metrics=[value]))


@pytest.mark.parametrize(
    ("reason", "code"),
    [
        (
            "The final state is incomplete.\nDo not include this line.",
            "metric_text_not_single_line",
        ),
        ("The final state is incomplete.\x1f", "metric_text_control_character"),
        ("The final state leaked api_key=abcdefghijklmnop.", "metric_text_secret_pattern"),
    ],
)
def test_metric_verdict_rejects_unsafe_reason_text(reason: str, code: str) -> None:
    with pytest.raises(MetricContractError, match=code):
        MetricVerdict(
            metric_id="coding.tests_pass",
            passed=False,
            score_basis_points=0,
            reason_code="tests_failed",
            reason=reason,
            disclosure=Disclosure.PUBLIC,
        )


def test_metric_text_accepts_declared_byte_boundaries(tmp_path: Path) -> None:
    minimum = metric("reply.minimum", "final_response", mode="judge")
    minimum["judge_justification"] = "é" * 10
    maximum = metric("reply.maximum", "final_response", mode="judge")
    maximum["judge_justification"] = "é" * 256
    pack = load_metric_pack(write_pack(tmp_path, metrics=[maximum, minimum]))

    empty_passing_reason = MetricVerdict(
        metric_id="reply.minimum",
        passed=True,
        score_basis_points=10_000,
        reason_code="",
        reason="",
        disclosure=Disclosure.PUBLIC,
    )
    maximum_reason = MetricVerdict(
        metric_id="reply.maximum",
        passed=False,
        score_basis_points=0,
        reason_code="behavior_failed",
        reason="é" * 256,
        disclosure=Disclosure.PUBLIC,
    )

    assert len(pack.metrics) == 2
    assert empty_passing_reason.reason == ""
    assert maximum_reason.reason == "é" * 256


def test_metric_text_rejects_values_over_the_declared_byte_bound(tmp_path: Path) -> None:
    value = metric("reply.too_long", "final_response", mode="judge")
    value["judge_justification"] = "j" * 513
    with pytest.raises(MetricContractError, match="metric_text_too_long"):
        load_metric_pack(write_pack(tmp_path, metrics=[value]))

    with pytest.raises(MetricContractError, match="metric_text_too_long"):
        MetricVerdict(
            metric_id="reply.too_long",
            passed=False,
            score_basis_points=0,
            reason_code="behavior_failed",
            reason="r" * 513,
            disclosure=Disclosure.PUBLIC,
        )


def test_failed_metric_verdict_requires_a_nonempty_reason() -> None:
    with pytest.raises(MetricContractError, match="metric_verdict_reason_required"):
        MetricVerdict(
            metric_id="coding.tests_pass",
            passed=False,
            score_basis_points=0,
            reason_code="tests_failed",
            reason="",
            disclosure=Disclosure.PUBLIC,
        )


def test_metric_pack_rejects_unsorted_duplicate_and_incomplete_metric_contracts(
    tmp_path: Path,
) -> None:
    unsorted = [
        metric("workflow.incident_closed", "final_state"),
        metric("workflow.audit_written", "final_state"),
    ]
    with pytest.raises(MetricContractError, match="metric_ids_not_sorted"):
        load_metric_pack(write_pack(tmp_path, metrics=unsorted))

    duplicate = [
        metric("workflow.audit_written", "final_state"),
        metric("workflow.audit_written", "final_state"),
    ]
    with pytest.raises(MetricContractError, match="metric_ids_duplicate"):
        load_metric_pack(write_pack(tmp_path, metrics=duplicate))

    incomplete = metric("workflow.audit_written", "final_state")
    del incomplete["disclosure"]
    with pytest.raises(MetricContractError, match="metric_definition_missing_key"):
        load_metric_pack(write_pack(tmp_path, metrics=[incomplete]))


def test_metric_pack_digest_changes_when_any_metric_field_changes(tmp_path: Path) -> None:
    first = load_metric_pack(
        write_pack(tmp_path, metrics=[metric("workflow.audit_written", "final_state")])
    )
    changed = metric("workflow.audit_written", "final_state")
    changed["threshold_basis_points"] = 9_999
    second = load_metric_pack(write_pack(tmp_path, metrics=[changed]))

    assert first.digest != second.digest
