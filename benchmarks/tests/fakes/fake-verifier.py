#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--workspace", required=True, type=Path)
parser.add_argument("--result", required=True, type=Path)
arguments = parser.parse_args()
mode = (arguments.workspace / "mode.txt").read_text(encoding="utf-8").strip()

if mode == "pass":
    arguments.result.write_text(
        json.dumps({"passed": True, "checks_passed": 3, "checks_total": 3}),
        encoding="utf-8",
    )
elif mode == "fail":
    arguments.result.write_text(
        json.dumps({"passed": False, "checks_passed": 2, "checks_total": 3}),
        encoding="utf-8",
    )
elif mode == "malformed":
    arguments.result.write_text("not-json", encoding="utf-8")
elif mode == "unknown-field":
    arguments.result.write_text(
        json.dumps({"passed": True, "checks_passed": 3, "checks_total": 3, "detail": "forbidden"}),
        encoding="utf-8",
    )
elif mode == "inconsistent":
    arguments.result.write_text(
        json.dumps({"passed": True, "checks_passed": 2, "checks_total": 3}),
        encoding="utf-8",
    )
elif mode == "oversized-result":
    arguments.result.write_text("x" * 5000, encoding="utf-8")
elif mode == "oversized-output":
    sys.stdout.write("x" * 70_000)
    sys.stdout.flush()
    time.sleep(30)
elif mode == "nonzero":
    raise SystemExit(7)
elif mode == "environment":
    safe = "SHOULD_NOT_LEAK" not in os.environ and "PATH" in os.environ and "HOME" not in os.environ
    arguments.result.write_text(
        json.dumps({"passed": safe, "checks_passed": int(safe), "checks_total": 1}),
        encoding="utf-8",
    )
elif mode in {"timeout", "cancel"}:
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    (arguments.workspace / "leader.pid").write_text(str(os.getpid()), encoding="utf-8")
    (arguments.workspace / "child.pid").write_text(str(child.pid), encoding="utf-8")
    time.sleep(60)
else:
    raise SystemExit(9)
