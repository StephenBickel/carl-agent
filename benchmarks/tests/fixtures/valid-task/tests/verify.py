#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--workspace", required=True, type=Path)
parser.add_argument("--result", required=True, type=Path)
arguments = parser.parse_args()
passed = (arguments.workspace / "hello.txt").read_text(encoding="utf-8") == "fixed\n"
arguments.result.write_text(
    json.dumps({"passed": passed, "checks_passed": int(passed), "checks_total": 1}),
    encoding="utf-8",
)
