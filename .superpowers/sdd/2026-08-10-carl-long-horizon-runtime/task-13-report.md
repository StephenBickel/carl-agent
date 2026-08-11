# Task 13 report: Deterministic long-horizon evaluation infrastructure

## Implementation

- Added strict, serializable `EvaluationScenario`, `ScheduledSteering`,
  `EvaluationMetrics`, and `EvaluationResult` contracts. Metrics cannot carry
  assistant prose, raw tool output, credentials, or absolute workspace paths.
- Added a real offline evaluation around `TaskEngine<ScriptedPort, RuntimeStore>`.
  It copies the fixture below a fresh owner-private root, performs one planning
  request and exactly 100 tool-bearing work epochs, and derives task-semantic
  metrics from durable `TaskEvent` history plus the final canonical checkpoint.
- The uninterrupted baseline records one planning request and 100 Work requests.
  The restart run records one planning request, 95 Work requests, and five Recovery
  requests because each seventeenth checkpoint is reopened and
  `resume_context` returns `UnavailableContext`; the engine durably emits matching
  `ProviderContextLost` and replacement `ProviderContextBound` events.
- Forced `UsageUpdated` pressure produces exactly 33 completed compactions. Live
  task controls inject steering at work epochs 11 and 61. The identifier
  `needle_7f3a91c2` originates in epoch 1 and remains in the final checkpoint.
- `restart_after_events` is interpreted against durable task-event sequence
  numbers. The standard thresholds 300, 900, and 1500 map to safe checkpoint cuts
  after work epochs 19, 57, and 95. Together with provider-loss cuts and a dedicated
  checkpoint cut at epoch 59, the candidate executes nine real RuntimeStore
  reopen/reconciliation cycles.
- The replay digest normalizes final status, clause states, effect class, semantic
  request digest, semantic applied/failed/cancelled/uncertain outcome, normalized
  evidence shape, required exact identifiers, and the sorted relative fixture
  manifest. It excludes UUIDs, timestamps, provider IDs, absolute paths, prose,
  diffs, and raw output. The uninterrupted and restarted 100-epoch runs produce the
  same digest.
- Added a real unresolved-Started cut after effect dispatch. Runtime startup marks
  it uncertain, reconciliation blocks deterministically, and the effect count stays
  one; it is never forced to complete or replayed.
- Added the bounded ten-case repository matrix with a fresh copied fixture per case.
  Positive cases require completed clauses; cancellation, hostile instruction,
  secret, out-of-scope, and ambiguous-effect cases require their exact expected safe
  outcome instead of synthetic completion.
- Added the exact locked evaluation command to the existing cross-platform CI test
  job and structurally enforced that command in `workflow_contract`.

## RED / GREEN evidence

1. Workflow RED failed with:

   ```text
   jobs.test is missing exact step run command `cargo test --locked --test long_horizon_eval`
   ```

   Adding the exact command and structural owner requirement made the workflow
   contract GREEN.

2. Evaluation API RED failed to compile with:

   ```text
   unresolved import `carl::evals`
   ```

   The strict public contracts and release-gate implementation made the public
   contract GREEN.

3. The first real 100-epoch run reached the engine but returned
   `Error: Invariant`. Phase tracing isolated an invalid in-process SQLite fault:
   returning a storage error at a pre-intent boundary correctly drove the live
   engine's blocking error path, which is not equivalent to process death. The
   success schedule now interrupts only after committed checkpoints; the separate
   unresolved-Started fixture proves the unsafe fail-closed path. All temporary
   diagnostics were removed.

4. The final main scenario is GREEN with exact metrics: 100 work epochs, 101
   semantic provider requests, 100 tool intents, two required clauses, 33
   compactions, nine evaluator restarts, five provider replacements, and zero
   duplicates, lost identifiers, out-of-scope changes, orphans, or secret-policy
   violations.

## Verification

```text
cargo test --locked --test long_horizon_eval
PASS: 4 passed, 0 failed; test body 49.35s (real 49.83s)

cargo test --locked --test workflow_contract
PASS: 38 passed, 0 failed; 0.01s

cargo fmt --all -- --check
PASS: exit 0

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

git diff --check
PASS: exit 0
```

The plan's under-ten-second target is not met on this host. A read-only performance
audit found no evaluator sleeps, subprocesses, network calls, credentials, or
timeouts. The stable cost comes from production's O(n^2) full-journal checkpoint
replay and repeated startup authority scans. Optimizing that shared storage/runtime
path belongs in a separately reviewed production task; this task preserves the
strong uninterrupted-versus-restarted two-run proof. The root agent owns the Task
13 full `cargo test --locked --all-features` milestone gate after independent review.

No Carl service/ACP process remained. `SECURITY.md`, migrations, `Cargo.lock`, and
Task 14 files were not modified.

## Commit

- `5d1b01b test: add deterministic long-horizon evaluations`
