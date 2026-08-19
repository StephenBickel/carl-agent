# Task 6 report

## Status

Complete. Deterministic reconciliation now dispatches and reconciles only the two allowlisted
GitHub-hosted workflows, binds immutable request/run/artifact identities, and rejects every named
heavy local fallback. The workflows use read-only permissions, exact candidate checkout, pinned
actions and toolchains, locked dependencies, bounded evidence, and no push, merge, signer, or
production-status authority.

## Commit

`feat(factory): offload autonomous verification to cloud runners`

## Tests

- TDD RED: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_cloud_execution.py` failed during
  collection with the expected missing `carl_bench.cloud_execution` module.
- Focused cloud/workflow contracts: 24 passed.
- `benchmarks/.venv/bin/pytest -q benchmarks/tests` — 411 passed.
- `benchmarks/.venv/bin/ruff check benchmarks` — passed.
- `cargo test --locked --test workflow_contract` — 41 passed.
- Ruby/Psych YAML parsing plus `bash -n` validation for every workflow `run` block — passed.
- `git diff --cached --check` — passed; exactly the five Task 6 files are staged.

## Concerns

`actionlint` is not installed, per the task ruling, so it was neither installed nor invoked. The
repository contract tests parse both new workflows, assert their GitHub structure and security
boundaries, and the available YAML and shell validators pass. The workflows themselves were not
dispatched from this local implementation worktree; GitHub-hosted execution remains the deliberate
heavy-work boundary.
