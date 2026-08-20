# Task 6 report

## Status

Round 5 implementation is complete locally. Remote acceptance remains explicitly uncommissioned:
no GitHub-hosted commissioning run, artifact, live ACP credential path, or production-grade
capability result is claimed by this report. The protected harness continues to emit
`live_acp_credential_missing` and is wiring evidence only.

## Round 5 controls

- GitHub run identity now binds `head_sha` to the protected `workflow_revision`, not the candidate
  commit. The candidate remains an immutable subject input. Reconciliation also requires the exact
  `.github/workflows/...` path and protected workflow blob digest before accepting any run.
- Both workflow files check that `github.sha` and `github.workflow_sha` equal the requested protected
  workflow revision, verify `github.workflow_ref` names the expected workflow path, hash-check that
  workflow blob, and load the trusted harness from that revision.
- `CommissioningReceipt` schema 2 is canonical and digest-bound. Only a
  `SignedCommissioningReceipt` with a valid Ed25519 signature from the configured trusted key can
  authorize success; missing, unsigned, wrong-key, malformed, forged, or mismatched receipts block.
  Workflows and candidate processes receive no signing private key.
- Every retry transition consumes a separately canonical, digest-bound, Ed25519-signed
  `CompletedRunObservation` that binds run ID, repository, workflow revision/path/blob, request
  digest, completed status, infrastructure conclusion, and observation time.
- Retry decisions carry the observation digest, retry-state schema 2 durably appends that digest
  beside the run ID, and `CloudRetryStateStore.compare_and_swap` re-verifies the signature and all
  bindings while holding the file lock. Caller-constructed decisions without signed provenance,
  forged observations, replay, reset, skip, and history substitution fail closed.

## Round 4 controls

- The trusted Python harness and canonical result writer now execute as root while every parent
  probe is dropped to `carlparent` and every candidate probe is dropped to `carlcandidate` with
  supplementary groups cleared. The workflow proves the three UIDs differ.
- The result directory is root-owned mode `0700`; the canonical result is created under `umask
  077` and verified root-owned mode `0600`. Both subject identities are explicitly proven unable
  to read, write, or traverse the result directory, so a detached subject descendant cannot
  mutate the trusted result.
- `CloudRetryStateStore.compare_and_swap` now accepts only the exact successor described by the
  completed infrastructure-failure decision: revision and attempt increment by one, attempt key
  and deadline match, and exactly one non-reused completed run ID is appended. Reset, skip,
  deadline removal, key substitution, history replacement, and multi-ID insertion attacks fail
  before the atomic write. `advance_retry_state` requires and binds the prior run ID.
- Caller booleans and arbitrary dry-run IDs were removed. `CommissioningReceipt` binds repository,
  workflow file, protected workflow revision and blob digest, canonical request and all immutable
  input digests, successful run identity/conclusion, and exact artifact ID/name/digest. Missing or
  mismatched receipts fail closed.
- Both cloud workflow dispatch contracts now carry and verify the exact protected workflow
  revision/blob, include those identities in the canonical request, and retain them in evidence.
  No receipt is installed by default, so reconciliation remains uncommissioned until a real
  GitHub-hosted run and retained artifact are observed.

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

Round 4 focused verification: 66 tests passed across `test_cloud_execution.py` and
`test_cloud_harness.py`; focused Ruff, pinned Actionlint v1.7.7, and `git diff --check` passed.
Attack regressions cover forged commissioning fields, absent receipts, retry reset/skip/key/deadline
and history tampering, and shared harness/subject identities.

Round 5 focused verification: 84 tests passed across `test_cloud_execution.py` and
`test_cloud_harness.py`; focused Ruff, pinned Actionlint v1.7.7, and `git diff --check` passed.
Adversarial regressions cover candidate-ref workflow execution, missing/mismatched workflow
path/blob, unsigned and forged commissioning receipts, unsigned/forged/mismatched completed-run
observations, manually constructed retry decisions, and signature revalidation inside atomic CAS.
No full suite was run, per task instruction.

## Commit

- Round 3: `30b098c` — `fix(factory): harden cloud isolation and durable retries`
- Round 4: `200d741` — `fix(factory): close cloud trust boundary gaps`
- Round 5: this commit — `fix(factory): authenticate cloud run provenance`
