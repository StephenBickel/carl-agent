#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load(workspace: Path, name: str) -> list[dict[str, Any]]:
    try:
        return json.loads((workspace / "data" / f"{name}.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError):
        return []


def verify(workspace: Path) -> tuple[int, int]:
    incidents = load(workspace, "incidents")
    sheet = load(workspace, "sheet")
    audit = load(workspace, "audit")
    checks = [
        {
            "incident_id": "inc-100",
            "service": "checkout",
            "severity": "sev1",
            "status": "acknowledged",
            "owner": "alice",
        }
        in incidents,
        {
            "service": "checkout",
            "status": "incident",
            "incident_id": "inc-100",
            "owner": "alice",
        }
        in sheet,
        audit
        == [
            {
                "event_id": "audit-inc-100",
                "action": "incident_reconciled",
                "incident_id": "inc-100",
                "message_id": "msg-104",
                "owner": "alice",
                "created_at": "2026-08-10T20:05:00Z",
            }
        ],
        {
            "incident_id": "inc-200",
            "service": "search",
            "severity": "sev3",
            "status": "resolved",
            "owner": "bob",
        }
        in incidents
        and {
            "service": "search",
            "status": "healthy",
            "incident_id": None,
            "owner": "bob",
        }
        in sheet,
    ]
    try:
        operations = [
            json.loads(line)
            for line in (workspace / ".workflow-log.jsonl").read_text(encoding="utf-8").splitlines()
        ]
    except (OSError, json.JSONDecodeError, TypeError):
        operations = []
    reads = [entry.get("target") for entry in operations if entry.get("kind") == "read"]
    writes = [entry.get("target") for entry in operations if entry.get("kind") == "write"]
    checks.append(
        {
            "inbox:msg-104",
            "incident:inc-100",
            "calendar:2026-08-10T20:00:00Z",
            "sheet:checkout",
        }.issubset(reads)
        and writes == ["incident:inc-100", "sheet:checkout", "audit:audit-inc-100"]
    )
    return sum(checks), len(checks)


parser = argparse.ArgumentParser()
parser.add_argument("--workspace", required=True, type=Path)
parser.add_argument("--result", required=True, type=Path)
arguments = parser.parse_args()
passed, total = verify(arguments.workspace)
arguments.result.write_text(
    json.dumps({"passed": passed == total, "checks_passed": passed, "checks_total": total}),
    encoding="utf-8",
)
