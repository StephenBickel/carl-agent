from __future__ import annotations

import json
import re
from pathlib import Path

from carl_bench.experiment import ExperimentManifest

REPOSITORY_ROOT = Path(__file__).parents[2]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "benchmark-contracts.yml"
OPERATOR_DOCS = REPOSITORY_ROOT / "docs" / "benchmarks.md"
EXAMPLE_MANIFEST = REPOSITORY_ROOT / "benchmarks" / "examples" / "dry-run-manifest.json"


def test_benchmark_workflow_is_pinned_locked_offline_and_credential_free() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2" in source
    assert "astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990 # v8.3.2" in source
    assert "contents: read" in source
    assert "timeout-minutes:" in source
    assert 'version: "0.10.4"' in source
    assert 'python-version: "3.12"' in source
    assert "enable-cache: true" in source
    assert "cache-dependency-glob: benchmarks/uv.lock" in source
    assert "cache-python: false" in source
    assert "uv sync --project benchmarks --python 3.12 --locked" in source
    assert "uv run --offline --project benchmarks --locked pytest -q benchmarks/tests" in source
    assert "uv run --offline --project benchmarks --locked ruff check benchmarks" in source
    assert "./scripts/benchmark-smoke.sh" in source
    for forbidden in (
        "secrets.",
        "_API_KEY",
        "CODEX_HOME",
        "CARL_DATA_DIR",
        "carl-acp",
        "codex-cli",
        "docker",
        "harbor",
        "protected",
        "upload-artifact",
    ):
        assert forbidden.casefold() not in source.casefold()


def test_operator_documentation_links_resolve_and_describes_manual_only_boundary() -> None:
    source = OPERATOR_DOCS.read_text(encoding="utf-8")
    normalized = " ".join(source.casefold().split())
    links = re.findall(r"\[[^]]+\]\(([^)]+)\)", source)
    local_links = [link.split("#", 1)[0] for link in links if "://" not in link]
    assert local_links
    for link in local_links:
        assert (OPERATOR_DOCS.parent / link).resolve().exists(), link
    assert "advisory" in normalized
    assert "promotion controller is not implemented" in normalized
    assert "dry-run experiment graph" in normalized
    assert "hash-chained sqlite ledger" in normalized
    assert "every two hours" in normalized
    assert "manual and read-only" in normalized
    assert "does not build carl or open, merge, or revert pull requests" in normalized
    assert "USD 25" in source
    assert "USD 150" in source
    assert "three" in normalized and "ten" in normalized


def test_root_readme_links_the_lab_without_claiming_autonomous_promotion() -> None:
    source = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
    assert "[benchmark lab](docs/benchmarks.md)" in source
    assert "[improvement-factory design](" in source
    section = source.split("## Benchmark lab", 1)[1].split("\n## ", 1)[0]
    assert "do not build, autonomously promote, or merge" in section
    assert "append-only dry-run experiment graph" in section


def test_public_dry_run_manifest_example_satisfies_the_strict_contract() -> None:
    value = json.loads(EXAMPLE_MANIFEST.read_text(encoding="utf-8"))
    parsed = ExperimentManifest.from_canonical_dict(value)
    assert parsed.experiment_id == "exp-example-restart-recovery"
    assert len(parsed.digest) == 64
