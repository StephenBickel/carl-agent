#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
from pathlib import Path


def verify(workspace: Path) -> tuple[int, int]:
    checks: list[bool] = []
    unit_tests = subprocess.run(
        ["python3", "-m", "unittest", "discover", "-s", "tests", "-q"],
        cwd=workspace,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=20,
    )
    checks.append(unit_tests.returncode == 0)
    test_source = workspace / "tests" / "test_config.py"
    checks.append(
        test_source.is_file()
        and all(
            name in test_source.read_text(encoding="utf-8")
            for name in (
                "test_cli_wins",
                "test_falls_back_in_order",
                "test_empty_string_is_explicit",
            )
        )
    )

    module_path = workspace / "config_lookup.py"
    try:
        specification = importlib.util.spec_from_file_location(
            "candidate_config_lookup", module_path
        )
        if specification is None or specification.loader is None:
            raise ImportError
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        cases = [
            ({"cli": "cli", "environment": "env", "config_file": "file", "default": "d"}, "cli"),
            ({"cli": None, "environment": "env", "config_file": "file", "default": "d"}, "env"),
            ({"cli": None, "environment": None, "config_file": "file", "default": "d"}, "file"),
            ({"cli": None, "environment": None, "config_file": None, "default": "d"}, "d"),
            ({"cli": "", "environment": "env", "config_file": "file", "default": "d"}, ""),
        ]
        checks.append(
            all(module.resolve_config(**values) == expected for values, expected in cases)
        )
        missing = module.resolve_config(
            cli=None,
            environment=None,
            config_file=None,
            default=None,
        )
        checks.append(missing is None)
    except (ImportError, OSError, SyntaxError, AttributeError, TypeError):
        checks.extend([False, False])
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
