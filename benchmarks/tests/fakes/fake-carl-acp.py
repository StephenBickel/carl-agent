#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

workspace = Path.cwd()
mode = (workspace / "acp-mode.txt").read_text(encoding="utf-8").strip()
(workspace / "acp-argv.json").write_text(json.dumps(sys.argv[1:]), encoding="utf-8")


def emit(value: object, *, partial: bool = False) -> None:
    encoded = json.dumps(value, separators=(",", ":")) + "\n"
    if partial:
        midpoint = len(encoded) // 2
        sys.stdout.write(encoded[:midpoint])
        sys.stdout.flush()
        time.sleep(0.02)
        sys.stdout.write(encoded[midpoint:])
    else:
        sys.stdout.write(encoded)
    sys.stdout.flush()


for raw_line in sys.stdin:
    request = json.loads(raw_line)
    request_id = request["id"]
    method = request["method"]
    if method == "initialize":
        if mode == "malformed":
            sys.stdout.write("not-json\n")
            sys.stdout.flush()
            continue
        if mode == "oversized":
            sys.stdout.write("x" * 1_100_000 + "\n")
            sys.stdout.flush()
            continue
        if mode == "stderr-flood":
            sys.stderr.write("x" * 300_000)
            sys.stderr.flush()
            time.sleep(30)
        if mode == "unexpected-request":
            emit({"jsonrpc": "2.0", "id": 99, "method": "danger", "params": {}})
            continue
        if mode == "out-of-order":
            emit({"jsonrpc": "2.0", "id": request_id + 1, "result": {}})
            continue
        if mode == "rpc-error":
            emit({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32000}})
            continue
        if mode == "early-exit":
            raise SystemExit(7)
        if mode in {"timeout", "cancel"}:
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            (workspace / "acp-leader.pid").write_text(str(os.getpid()), encoding="utf-8")
            (workspace / "acp-child.pid").write_text(str(child.pid), encoding="utf-8")
            time.sleep(60)
        version = 1 if mode == "wrong-version" else 2
        environment_safe = all(
            key not in os.environ
            for key in ("OPENAI_API_KEY", "CODEX_API_KEY", "SHOULD_NOT_LEAK", "HOME")
        )
        if mode == "environment" and not environment_safe:
            emit({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32001}})
            continue
        emit(
            {"jsonrpc": "2.0", "id": request_id, "result": {"protocolVersion": version}},
            partial=mode == "partial",
        )
    elif method == "session/new":
        emit({"jsonrpc": "2.0", "id": request_id, "result": {"sessionId": "session-01"}})
    elif method == "session/prompt":
        emit(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": "session-01",
                    "update": {"sessionUpdate": "tool_call", "content": [{"type": "text"}]},
                },
            }
        )
        emit(
            {
                "jsonrpc": "2.0",
                "method": "session/update",
                "params": {
                    "sessionId": "session-01",
                    "update": {
                        "sessionUpdate": "agent_message_chunk",
                        "content": {"type": "text", "text": "private provider output"},
                    },
                },
            }
        )
        stop_reason = "cancelled" if mode == "cancelled-result" else "end_turn"
        emit(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"stopReason": stop_reason},
            }
        )
