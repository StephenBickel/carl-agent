from __future__ import annotations

import json
from pathlib import Path

import pytest

from carl_bench.metrics import MetricContractError, load_metric_pack


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


@pytest.mark.parametrize("observation", ["command_sequence", "exact_trajectory"])
def test_path_scoring_observations_are_rejected(tmp_path: Path, observation: str) -> None:
    with pytest.raises(MetricContractError, match="metric_observation_unsupported"):
        load_metric_pack(write_pack(tmp_path, metrics=[metric("bad.path", observation)]))


def test_judge_metric_requires_semantic_justification(tmp_path: Path) -> None:
    value = metric("reply.tone", "final_response", mode="judge")
    value["judge_justification"] = ""

    with pytest.raises(MetricContractError, match="judge_justification_required"):
        load_metric_pack(write_pack(tmp_path, metrics=[value]))


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
