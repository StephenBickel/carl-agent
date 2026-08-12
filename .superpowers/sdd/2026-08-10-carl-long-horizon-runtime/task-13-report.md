# Task 13 report: Deterministic long-horizon evaluation infrastructure

## Implementation

- Strict `EvaluationScenario`, `ScheduledSteering`, `EvaluationMetrics`, and
  `EvaluationResult` contracts deny unknown fields and cannot carry assistant prose,
  raw tool output, credentials, or absolute workspace paths.
- The offline evaluation runs a real `TaskEngine<ScriptedPort, RuntimeStore>` below
  a fresh owner-private root. It performs one planning request and exactly 100
  tool-bearing work epochs. Metrics come from durable `TaskEvent` history, the final
  canonical checkpoint, and sanitized evaluator-owned safety observations.
- The uninterrupted baseline records one planning request and 100 Work requests.
  The restart run records one planning request, 95 Work requests, and five Recovery
  requests because each seventeenth checkpoint is reopened and
  `resume_context` returns `UnavailableContext`; the engine durably emits matching
  `ProviderContextLost` and replacement `ProviderContextBound` events.
- Forced `UsageUpdated` pressure produces exactly 33 completed compactions. Live task
  controls inject steering at work epochs 11 and 61. The provider emits
  `needle_7f3a91c2` only in epoch 1. The engine carries it through every one of the 100
  canonical checkpoints, and each provider replacement reconstructs the continuation
  from the durable `ContextPackage` rather than evaluator-held progress.
- `restart_after_events` now means exact, safely resumable durable envelope sequences.
  The standard targets 25, 72, and 119 are observed in the candidate at the committed
  boundaries after work epochs 1, 4, and 7. An unreachable, repeated, out-of-range, or
  passed sequence fails closed; there is no rounding or fallback. Together with five
  provider-loss cuts and the epoch-59 cut, the candidate executes nine real
  `RuntimeStore` reopen/reconciliation cycles.
- Safe cuts pin the live engine future, observe the exact committed envelope from an
  independent connection, and drop the future and runtime. They do not convert an
  injected storage error into a fake process restart. The unresolved-`Started` test
  likewise drops a live future after one side effect, then proves startup marks it
  uncertain, blocks, and never redispatches it.
- The replay digest normalizes final status, clause states, effect class, semantic
  request digest, semantic applied/failed/cancelled/uncertain outcome, normalized
  evidence shape, required exact identifiers, and the sorted relative fixture
  manifest. It excludes UUIDs, timestamps, provider IDs, absolute paths, prose,
  diffs, and raw output. The uninterrupted and restarted 100-epoch runs produce the
  same digest.
- The exhaustive operation-lifecycle proof remains the existing real-engine
  `every_required_engine_restart_cut_restarts_from_real_engine_state` matrix. It
  covers TaskCreated through provider binding across 12 required cuts. Task 13 pins
  that test and every cut name as an explicit release dependency; the 100-epoch
  digest test owns committed safe-boundary schedules, not a duplicate lifecycle
  simulator.
- The ten repository cases now use a bounded reusable `MatrixPort` around real
  `RuntimeStore`/`TaskEngine` runs (16 scripted work epochs total). Durable events and
  checkpoints drive metrics. The cases exercise command failure and recovery,
  multi-file mutation, actual recovery-strategy selection, provider loss and reopen,
  cancellation/interrupt lifecycle, policy denial, out-of-scope validation, and a
  possibly-applied ambiguous effect that remains blocked after reopen without replay.
- Command-recovery cases now assert the ordered durable lifecycle itself: an exit-one
  command records incomplete/exit-one normalized evidence and transitions to Failed
  before the recovery intent; the final recovery command records complete/exit-zero
  evidence and transitions to Succeeded. A focused unit test rejects any normalization
  that treats exit one as success.
- Fixture admission accepts exactly `README.md`, `Cargo.toml`, `src/lib.rs`, and
  `tests/contract.rs`; extra files and symlinks fail closed. CI structurally requires
  the exact locked command, ungated and exactly once in `jobs.test`. The all-features
  command explicitly skips the named 100-epoch test and the workflow contract rejects
  an unfiltered duplicate, so the expensive proof runs only once per CI execution.
- `Store::read_task_events_after` pages an exclusive task-local tail. Checkpoint
  construction now reads only events after the previous checkpoint while preserving
  canonical merge and authority behavior.

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

3. Exact-sequence RED proved that the former threshold mapper rounded an unreachable
   event to a later checkpoint. The new mapper accepts only an exact
   `Checkpointing -> Active` envelope, and the cooperative candidate observer proves
   that the actual last durable sequence equals the configured target.

4. Single-emission RED cleared volatile progress at every reopen. Recovery initially
   failed with `Error: Invariant`; durable journal reconstruction plus canonical
   `ContextPackage` parsing made all checkpoints and replacements retain the needle.

5. Matrix RED showed the old release matrix fabricated counters without running the
   engine. The real 10-case matrix is GREEN in 1.00s and its out-of-scope and
   ambiguous-effect assertions now depend on actual intent/resolve/reopen events.

6. The final main scenario is GREEN with exact metrics: 100 work epochs, 101
   durable provider requests, 100 tool intents, two required clauses, 33
   compactions, nine evaluator restarts, five provider replacements, and zero
   duplicates, lost identifiers, out-of-scope changes, orphans, or secret-policy
   violations.

## Verification

```text
cargo test --locked --test long_horizon_eval
PASS: 7 passed, 0 failed; test body 28.05s (real 28.27s)

cargo test --locked --lib evals::scenario::tests::ordered_command_recovery_rejects_exit_one_normalized_as_success -- --exact
PASS: 1 passed, 0 failed; 0.00s

cargo test --locked --test long_horizon_eval repository_release_gate_matrix_is_bounded_and_isolated -- --exact
PASS: 1 passed, 0 failed; 0.86s

cargo test --locked --test epoch_engine_contract every_required_engine_restart_cut_restarts_from_real_engine_state -- --exact
PASS: 1 passed, 0 failed; 1.37s

cargo test --locked --test workflow_contract
PASS: 40 passed, 0 failed; 0.01s

cargo test --locked --test task_storage_contract
PASS: 21 passed, 0 failed; 3.51s

cargo fmt --all -- --check
PASS: exit 0

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

git diff --check
PASS: exit 0
```

The bounded repository matrix meets its under-ten-second target at 0.86s. The
dedicated heavy gate meets the reference-host target below 45 seconds at 28.05s and
runs exactly once in CI; it is not duplicated through the all-features step. No
evaluator sleeps, subprocesses, network calls, credentials, or live providers are
involved. Remaining cost includes full authoritative checkpoint validation and
repeated startup reconciliation; this round intentionally did not weaken those
checks.

Before Task 14, the plan requires a separately reviewed incremental
checkpoint-authority/startup performance follow-on. It must optimize from the latest
authenticated canonical checkpoint and task-local durable tail while preserving
journal authority, lineage/digest validation, fail-closed startup, exact restart cuts,
and the two-run normalized replay proof. The root agent owns that follow-on, its
independent review, and the later full `cargo test --locked --all-features` milestone
gate.

No Carl service/ACP process remained. `SECURITY.md`, migrations, `Cargo.lock`, and
Task 14 files were not modified.

## Commit

- `5d1b01b test: add deterministic long-horizon evaluations`
- `3e4293d test: harden deterministic long-horizon evaluations`
- `2be6e65 test: harden recovery and long-horizon CI gates`
