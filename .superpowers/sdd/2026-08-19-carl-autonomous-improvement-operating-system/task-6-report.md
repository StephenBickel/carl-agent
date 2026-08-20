# Task 6 report

## Status

Round 3 implementation is complete locally. Remote acceptance remains explicitly uncommissioned:
no GitHub-hosted commissioning run, artifact, live ACP credential path, or production-grade
capability result is claimed by this report. The protected harness continues to emit
`live_acp_credential_missing` and is wiring evidence only.

## Round 3 controls

- The parent and candidate are built under distinct nonprivileged Unix identities with separate
  homes, temporary directories, Cargo homes, and target roots.
- The parent executable is checked as a regular executable, SHA-256 bound immediately after the
  parent build, and recursively stripped of write permissions before the candidate build begins.
  The workflow proves the candidate identity cannot write the parent root or executable.
- Parent and candidate digests are rechecked before and after protected harness execution, exported
  through protected workflow outputs, and independently matched to the harness result in the fresh
  evidence job.
- Every bounded probe attempt now retains its exit code, stdout, stderr, timeout, overflow, and pass
  disposition, so a failing earlier attempt cannot disappear behind a later success.
- Enabled affected, guard, and held-out policy gates reject empty groups with a stable fail-closed
  error instead of reaching a zero-weight score.
- Cloud retries have a hard budget of exactly three attempts. Remote-unavailable observations must
  carry the current deterministic attempt key.
- `CloudRetryStateStore` persists request digest, revision, attempt, attempt key, prior run IDs, and
  retry-not-before using a locked atomic replace. Compare-and-swap rejects stale divergent writers
  while replaying the same completed transition idempotently.

## Commissioning gate

The local model still must not be treated as proof of remote commissioning. A later commissioning
step must bind an observed GitHub run to the exact repository, protected workflow revision,
immutable request, successful conclusion, and retained artifact before remote evidence can be used
for promotion. No such binding is fabricated here.

## Verification

- TDD RED: retry-state imports were absent; the old model accepted attempt four and remote
  unavailability without an attempt key; retry state had no durable store; flaky first-attempt
  failures were absent from evidence; enabled empty guard/held-out groups raised
  `ZeroDivisionError`; and the workflow used one shared identity. Each failed before its scoped
  implementation.
- Focused command: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_cloud_execution.py
  benchmarks/tests/test_cloud_harness.py`.
- Lint command: `benchmarks/.venv/bin/ruff check benchmarks/src/carl_bench/cloud_execution.py
  benchmarks/src/carl_bench/cloud_harness.py benchmarks/tests/test_cloud_execution.py
  benchmarks/tests/test_cloud_harness.py`.
- Workflow command: `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
  .github/workflows/autonomous-improvement.yml .github/workflows/autonomous-soak.yml`.
- No full test suite was run, per task instruction.

## Commit

`fix(factory): harden cloud isolation and durable retries`
