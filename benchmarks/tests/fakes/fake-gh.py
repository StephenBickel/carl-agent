#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _option(arguments: list[str], name: str) -> str:
    try:
        return arguments[arguments.index(name) + 1]
    except (ValueError, IndexError):
        raise SystemExit(2) from None


def main() -> int:
    arguments = sys.argv[1:]
    state_path = Path(os.environ["FAKE_GH_STATE"])
    log_path = Path(os.environ["FAKE_GH_LOG"])
    with log_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(arguments, separators=(",", ":")) + "\n")
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    if arguments[:2] == ["pr", "list"]:
        print(json.dumps([state["pull_request"]] if "pull_request" in state else []))
        return 0
    if arguments[:2] == ["pr", "create"]:
        repository = _option(arguments, "--repo")
        base = _option(arguments, "--base")
        head = _option(arguments, "--head")
        body_path = Path(_option(arguments, "--body-file"))
        if "--draft" not in arguments or not body_path.is_file():
            return 2
        state["pull_request"] = {
            "baseRefName": base,
            "headRefName": head,
            "headRefOid": os.environ["FAKE_GH_HEAD_OID"],
            "isDraft": True,
            "number": 17,
            "state": "OPEN",
            "url": f"https://github.com/{repository}/pull/17",
        }
        state_path.write_text(json.dumps(state), encoding="utf-8")
        print(state["pull_request"]["url"])
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
