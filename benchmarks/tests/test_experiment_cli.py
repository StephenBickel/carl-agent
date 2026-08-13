from __future__ import annotations

import json
import os
from pathlib import Path

from test_experiment import manifest, transition

from carl_bench import cli
from carl_bench.experiment import EventType, ExperimentEvent, ExperimentState


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _init(ledger: Path, manifest_path: Path) -> int:
    return cli.main(
        [
            "experiment",
            "init",
            "--ledger",
            os.fspath(ledger),
            "--manifest",
            os.fspath(manifest_path),
        ]
    )


def _record(ledger: Path, event_path: Path) -> int:
    return cli.main(
        [
            "experiment",
            "record",
            "--ledger",
            os.fspath(ledger),
            "--event",
            os.fspath(event_path),
        ]
    )


def _event_dict(event: ExperimentEvent) -> dict[str, object]:
    return event.to_canonical_dict()


def test_experiment_cli_initializes_records_replays_and_decides_without_private_prose(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "private-control" / "experiments.sqlite3"
    manifest_path = tmp_path / "manifest.json"
    event_path = tmp_path / "event.json"
    status_path = tmp_path / "status.json"
    decision_path = tmp_path / "decision.json"
    _write_json(manifest_path, manifest().to_canonical_dict())

    assert _init(ledger, manifest_path) == 0
    assert _init(ledger, manifest_path) == 0

    event = transition(
        attempt="stage-baseline-1",
        source=ExperimentState.QUEUED,
        target=ExperimentState.BASELINING,
        second=1,
    )
    _write_json(event_path, _event_dict(event))
    assert _record(ledger, event_path) == 0
    assert _record(ledger, event_path) == 0

    assert (
        cli.main(
            [
                "experiment",
                "status",
                "--ledger",
                os.fspath(ledger),
                "--experiment-id",
                manifest().experiment_id,
                "--public-result",
                os.fspath(status_path),
            ]
        )
        == 0
    )
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert status == {
        "active_lease": False,
        "candidate_review_approvals": 0,
        "event_count": 1,
        "experiment_id": "exp-context-recovery-001",
        "live_spend_microdollars": 0,
        "manifest_digest": manifest().digest,
        "projection_digest": status["projection_digest"],
        "proposal_review_approvals": 0,
        "schema_version": 1,
        "state": "baselining",
    }

    assert (
        cli.main(
            [
                "experiment",
                "decide",
                "--ledger",
                os.fspath(ledger),
                "--experiment-id",
                manifest().experiment_id,
                "--public-result",
                os.fspath(decision_path),
            ]
        )
        == 0
    )
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    assert decision["outcome"] == "advance"
    assert decision["next_action"] == "record_baseline_diagnosis"
    assert decision["reasons"] == []
    serialized = (status_path.read_text() + decision_path.read_text()).casefold()
    for forbidden in ("hypothesis", "rollback", "artifact_digest", "owner_id", "provider"):
        assert forbidden not in serialized


def test_experiment_cli_rejects_unknown_keys_illegal_edges_and_public_repo_ledger(
    tmp_path: Path,
) -> None:
    ledger = tmp_path / "ledger.sqlite3"
    manifest_path = tmp_path / "manifest.json"
    event_path = tmp_path / "event.json"
    _write_json(manifest_path, manifest().to_canonical_dict())
    assert _init(ledger, manifest_path) == 0

    jump = transition(
        attempt="stage-build-1",
        source=ExperimentState.QUEUED,
        target=ExperimentState.BUILDING,
        second=1,
    )
    invalid = _event_dict(jump)
    invalid["unexpected"] = True
    _write_json(event_path, invalid)
    assert _record(ledger, event_path) == 2

    _write_json(event_path, _event_dict(jump))
    assert _record(ledger, event_path) == 2

    repository_ledger = cli.REPOSITORY_ROOT / "benchmarks" / "unsafe-control.sqlite3"
    try:
        assert _init(repository_ledger, manifest_path) == 2
        assert not repository_ledger.exists()
    finally:
        repository_ledger.unlink(missing_ok=True)


def test_experiment_cli_budget_check_is_sanitized_and_non_mutating(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.sqlite3"
    manifest_path = tmp_path / "manifest.json"
    spend_path = tmp_path / "spend.json"
    result_path = tmp_path / "budget.json"
    _write_json(manifest_path, manifest().to_canonical_dict())
    assert _init(ledger, manifest_path) == 0
    spend = ExperimentEvent.create(
        experiment_id=manifest().experiment_id,
        stage_attempt_id="spend-run-1",
        event_type=EventType.LIVE_SPEND_RECORDED,
        occurred_at="2026-08-10T10:00:00Z",
        payload={"live_microdollars": 5_000_000, "run_id": "run-live-1"},
    )
    _write_json(spend_path, _event_dict(spend))
    assert _record(ledger, spend_path) == 0

    assert (
        cli.main(
            [
                "experiment",
                "budget-check",
                "--ledger",
                os.fspath(ledger),
                "--experiment-id",
                manifest().experiment_id,
                "--requested-microdollars",
                "15000000",
                "--at",
                "2026-08-10T12:00:00Z",
                "--active-live-workers",
                "3",
                "--public-result",
                os.fspath(result_path),
            ]
        )
        == 0
    )
    value = json.loads(result_path.read_text(encoding="utf-8"))
    assert value["allowed"] is True
    assert value["experiment_after_microdollars"] == 20_000_000
    assert value["experiment_elapsed_seconds"] == 43_200
    assert value["active_live_workers"] == 3
    assert value["reasons"] == []
