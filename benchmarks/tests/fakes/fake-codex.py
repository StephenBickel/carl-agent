#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

workspace = Path.cwd()
mode_path = workspace / "codex-mode.txt"
mode = mode_path.read_text(encoding="utf-8").strip() if mode_path.exists() else "normal"

if sys.argv[1:] == ["--version"]:
    if mode == "version-timeout":
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        (workspace / "codex-version-leader.pid").write_text(str(os.getpid()), encoding="utf-8")
        (workspace / "codex-version-child.pid").write_text(str(child.pid), encoding="utf-8")
        time.sleep(60)
    print("codex-cli 0.145.0" if mode == "wrong-version" else "codex-cli 0.146.0")
    raise SystemExit(0)

(workspace / "codex-argv.json").write_text(json.dumps(sys.argv[1:]), encoding="utf-8")
(workspace / "codex-prompt.txt").write_text(sys.stdin.read(), encoding="utf-8")
environment_safe = all(
    key not in os.environ for key in ("OPENAI_API_KEY", "CODEX_API_KEY", "SHOULD_NOT_LEAK", "HOME")
)
if mode == "environment" and not environment_safe:
    raise SystemExit(8)
if mode == "nonzero":
    raise SystemExit(7)
if mode == "nonzero-child":
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    (workspace / "codex-child.pid").write_text(str(child.pid), encoding="utf-8")
    raise SystemExit(7)
if mode == "signal":
    os.kill(os.getpid(), signal.SIGTERM)
if mode == "malformed":
    print("not-json")
    raise SystemExit(0)
if mode == "overflow":
    print("x" * 1_100_000)
    raise SystemExit(0)
if mode == "stderr-flood":
    sys.stderr.write("x" * 300_000)
    sys.stderr.flush()
    time.sleep(30)
if mode in {"timeout", "cancel"}:
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    (workspace / "codex-leader.pid").write_text(str(os.getpid()), encoding="utf-8")
    (workspace / "codex-child.pid").write_text(str(child.pid), encoding="utf-8")
    time.sleep(60)

events = [
    {"type": "thread.started", "thread_id": "thread-01"},
    {"type": "item.completed", "item": {"type": "command_execution"}},
    {"type": "turn.completed", "usage": {"input_tokens": 10, "output_tokens": 5}},
]
for event in events:
    print(json.dumps(event, separators=(",", ":")), flush=True)
