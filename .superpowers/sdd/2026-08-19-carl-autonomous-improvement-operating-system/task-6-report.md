# Task 6 report

## Status

Implementation complete; remote commissioning remains intentionally fail-closed until one real
GitHub-hosted dry run is recorded. The controller cannot accept a successful run without both an
actionlint commissioning fact and a prior GitHub-hosted dry-run ID.

The review's two Critical and four Important findings are fixed:

- candidate/subject execution runs as unprivileged `nobody` with an empty environment, read-only
  source, no checkout credentials, and inaccessible GitHub file-command endpoints;
- final evidence is created and uploaded in a fresh job that never checks out or executes candidate
  code;
- experiment, task-set, metric-pack, and policy content is resolved from the protected parent by
  digest and SHA-256 verified before use;
- the exact parent and candidate each run the same trusted tests and immutable task archive for
  three attempts, then the protected-parent comparator emits the paired result;
- soak accepts only an exact two-parent merge whose supplied parent is the immediate first parent;
- retry state is bounded to at most five attempts and binds attempt keys plus prior run IDs, with a
  deterministic next-at time and fail-closed exhaustion;
- reconciliation accepts exactly one request-named artifact and binds its artifact ID, name, run
  ID, API digest, downloaded digest, and expiration to the exact workflow run.

## Commit

`fix(factory): secure cloud evidence execution`

## Tests

- TDD RED: the first pass failed at import because `CloudArtifact` did not exist; workflow trust
  tests then failed against the original single-job workflows; retry-key, file-command endpoint,
  and real paired-scorecard tests each failed before their implementation was added.
- `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_cloud_execution.py` — 40 passed.
- `benchmarks/.venv/bin/pytest -q benchmarks/tests` — 427 passed before the instruction to stop at
  focused verification; no additional full-suite run was performed afterward.
- `cargo test --locked --test workflow_contract` — 41 passed.
- `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7` for both workflows — passed.
- `benchmarks/.venv/bin/ruff check benchmarks` — passed.
- `git diff --check` — passed.

## Commissioning gate

No GitHub-hosted dry run was claimed from the local worktree. The workflows must first exist on the
remote protected branch with protected immutable inputs at
`benchmarks/immutable-inputs/<kind>/<sha256>`. Until a real workflow run is recorded as the
commissioning run, `reconcile_cloud_run` returns `cloud_github_dry_run_not_commissioned` rather than
accepting evidence. This is a deliberate remote acceptance gate, not a silent local fallback.
