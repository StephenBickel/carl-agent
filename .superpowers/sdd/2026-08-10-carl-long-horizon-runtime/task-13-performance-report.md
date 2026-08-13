# Task 13 checkpoint-authority/startup performance report

## Status

`DONE` after fix round 3/5: the semantic, corruption, rollback, formatting, and lint
gates pass. The final prebuilt warm measurement passed in 24.85 seconds test / 26.20
seconds real, beating the original 27.61 / 27.70 baseline by 2.76 seconds test and
1.50 seconds real. Fix-round 2's slower measurement is retained below as explicitly
superseded evidence.

## Design

- `Store` owns a non-serialized, task-keyed authenticated-checkpoint cache. Each
  entry is a compact authority summary binding checkpoint/task identity, digest,
  source range, generation, operations, usage, replayed task/configuration state,
  and the SQLite `PRAGMA data_version` observed when it was authenticated.
- A checkpoint commit retains the existing immediate transaction and revision CAS.
  When the cached anchor's data version and exact database row match, authority is
  reconstructed from that authenticated checkpoint plus the exclusive, ascending,
  task-local journal tail after its source-sequence end. Paging remains at 512 rows.
- On cache absence, uncertainty, mismatch, or an out-of-band commit, the existing
  full journal-authority routine remains the corruption oracle. The task journal is
  replayed and the complete task-filtered canonical checkpoint/package chain is
  validated before authority can be refreshed.
- Successful full or transitive incremental commits refresh the cache. Failed
  validation, a failed CAS, and uncommitted writes never refresh it.
- Startup keeps the authoritative task records already reconstructed during
  `Store::open` and lets reconciliation and resumable-task listing consume/reuse
  that result when both `data_version` and same-connection `total_changes` match.
  Any uncertainty discards the result and repeats the authoritative scan.
- Test-only counters prove full, incremental, and startup-scan path selection. They
  add no production telemetry or serialized state.

## Preserved invariants

- The append-only Carl journal remains authoritative; `task_operations` and other
  mutable projections are not accepted as source truth.
- Canonical checkpoint/package bytes, digests, task identity, source range,
  previous-digest lineage, event ordering, operation evidence, usage metadata,
  generation, and artifacts remain validated.
- An incremental anchor is trusted only when authenticated by the same `Store` and
  its `data_version` is unchanged. A separate SQLite connection forces fallback.
- Validation and commit remain within the immediate transaction/CAS boundary.
- Corrupt history and unresolved `Started` operations remain fail-closed.
- No durability pragma, epoch/restart/compaction count, canonical validation,
  restart cut, or long-horizon evaluation semantic was weakened.
- `SECURITY.md` was not edited.

## RED evidence

1. `first_checkpoint_uses_full_authority_then_incremental_tail_crosses_page_boundary`
   initially observed two full validations because no authenticated incremental
   authority path existed. It covers a 514-event exclusive tail crossing the
   512-row page boundary.
2. `separate_connection_commit_invalidates_anchor_and_refreshes_full_authority`
   established that an external SQLite commit must turn the next validation into a
   full fallback before later same-store commits can return to the incremental path.
3. `full_fallback_rejects_a_projection_rolled_back_to_a_non_latest_predecessor`
   initially reached a SQLite uniqueness error instead of rejecting the rolled-back
   projection as a validation error. Authenticating the exact latest predecessor
   made the mutation fail closed before append/projection advance.
4. The canonical JSON, digest, source range, previous digest, task identity, and
   relevant usage-event mutations all reject without appending a checkpoint event
   or advancing a projection.
5. The first dedicated gate exposed a parallel-only fixture-copy race. Isolated
   execution passed, a repeated sibling-test permutation reproduced `ENOENT`, and
   `--test-threads=1` passed. The root cause was a temp path keyed only by PID and a
   wall-clock nanosecond value, allowing two parallel copies to share a directory
   whose first drop removed the second test's fixture. The deterministic
   `fixture_copies_with_the_same_clock_read_are_isolated` test failed with equal
   paths before the fix. A process-local atomic serial is now included in the path;
   this changes fixture isolation only, not evaluation semantics.

## GREEN evidence

The initial implementation's focused batch completed successfully:

```text
cargo test --locked --lib checkpoint_authority_tests
  6 passed; 0 failed

cargo test --locked --test context_engine_contract
  20 passed; 0 failed

cargo test --locked --test task_storage_contract
  21 passed; 0 failed

cargo test --locked --test epoch_engine_contract startup
  3 passed; 0 failed; 78 filtered out

cargo test --locked --test long_horizon_eval fixture_copies_with_the_same_clock_read_are_isolated
  1 passed; 0 failed; 7 filtered out

cargo test --locked --test long_horizon_eval repository_fixture_rejects
  2 passed; 0 failed; 6 filtered out

cargo fmt -- --check
  exit 0

cargo clippy --locked --all-targets --all-features -- -D warnings
  exit 0

git diff --check
  exit 0
```

The authorized dedicated gate rerun after the fixture-race fix was also green:

```text
cargo test --locked --test long_horizon_eval
  8 passed; 0 failed; finished in 29.56s (30.01s wall clock)
```

That gate preserved the exact uninterrupted-versus-restarted replay proof: 100 work
epochs, 33 compactions, 9 candidate restarts, no duplicate effects, no lost
identifiers, no out-of-scope changes, no orphan processes, and no secret-policy
violations.

The first dedicated run was not counted as a semantic success: the 100-epoch proof
passed, but the parallel fixture collision caused one repository-fixture test to
fail (6 passed, 1 failed). The root cause was reproduced and corrected before the
single authorized dedicated rerun above.

## Path counts

The focused counters directly observed:

- Initial plus same-store second checkpoint: 1 full, then 1 incremental.
- External-connection invalidation plus later same-store commit: 2 full, then 1
  incremental.
- Open, reconciliation, then resumable listing: 1 authoritative startup task scan
  total.

For the exact long-horizon proof, the Store lifetimes and fixed scenario imply 11
full-path checkpoint validations and 189 incremental validations across its two
100-checkpoint runs: 1 full + 99 incremental in the uninterrupted run, and 10 full
+ 90 incremental across the initial candidate Store plus 9 reopened Stores. These
are structurally derived counts; the counters are test-only and are not exported by
the integration evaluation.

## Superseded pre-fix-round timing history

Same host, debug test profile, locked dependencies, warm exact command:

```text
/usr/bin/time -p cargo test --locked --test long_horizon_eval actual_engine_survives_one_hundred_epochs_and_normalizes_replay -- --exact --nocapture
```

| Measurement | Test | Real | User | Sys |
| --- | ---: | ---: | ---: | ---: |
| Original baseline | 27.61s | 27.70s | 26.72s | 0.54s |
| Superseded initial implementation | 36.73s | 37.38s | 29.10s | 1.27s |

This historical run passed but regressed by 9.12 seconds in test time (33.0%) and 9.68
seconds in wall time (34.9%). An earlier post-change warm sample was also slower at
31.10 seconds test / 31.44 seconds real. The performance objective is therefore
unmet in this superseded pre-fix-round evidence. Later fix-round measurements are
recorded below and govern current status.

## Residual work and risks

- Each new `Store` still replays the full task journal to validate the task
  projection and separately walks all canonical checkpoint/package payloads.
  Startup reuse prevents reconciliation and resumable listing from replaying the
  task journal again, but it does not merge those two open-time validation passes.
- The first checkpoint in every reopened Store intentionally uses the full journal
  authority fallback. The restarted half of the dedicated proof therefore performs
  10 full checkpoint-authority validations, in addition to open-time validation.
- Same-store steady state removes repeated prefix authority work, but the measured
  workload remains dominated by residual reopen/startup and other checkpoint build,
  canonicalization, SQLite, and evaluation costs. No claim of total linear
  complexity is made.
- Timing variance exists on the shared host. The superseded round-2 samples exceeded
  baseline; the final round-3 prebuilt warm exact sample below beat both binding
  thresholds. No claim of total linear complexity is made.

## Self-review

- Reviewed the complete performance-follow-on production/test diff and confirmed the
  changes are limited to `src/storage/repository.rs`,
  `src/runtime/task/checkpoint.rs`, `src/runtime/task/mod.rs`, and
  `tests/long_horizon_eval.rs`. The runtime/task changes are `cfg(test)` observation
  points only; documentation changes are limited to this report and `progress.md`.
- Confirmed cache state is memory-only, exact-task keyed, updated only after a
  successful transaction commit, and invalidated by `data_version`/row mismatch.
- Confirmed incremental paging is exclusive and ascending, checks the exact tail
  end, reconstructs operation/evidence and usage authority, and retains the full
  fallback.
- Confirmed failure-path tests assert no journal, checkpoint-row, or task-revision
  advance.
- Confirmed the fixture fix uses a deterministic process-local uniqueness suffix and
  does not modify the long-horizon scenario, counts, cuts, or assertions.
- Pre-fix-round concern: the original implementation passed its correctness gates
  but did not meet the speedup requirement. Fix round 1/5 evidence follows.

## Fix round 1/5 — authoritative fallback and prefix-free fast path

### Reviewer findings addressed

1. On every cache miss, row mismatch, or `data_version` change, checkpoint commit now
   replays the task journal inside the existing immediate transaction, requires the
   mutable task/configuration projections to agree, and uses the replayed safe
   boundary, contract, provider context, model, and effort for checkpoint authority.
2. The fallback runs task-filtered full canonical checkpoint-chain validation before
   authority can be refreshed. This checks every stored checkpoint/package pair,
   canonical bytes, digests, identities, source bounds, generation/event binding,
   previous-digest lineage, and artifacts, including predecessors older than the
   latest checkpoint.
3. The `MIN/MAX` source-prefix query and mutable latest-checkpoint digest lookup now
   run only on the full fallback. The incremental branch proves source start and
   previous digest from its authenticated anchor, then proves source end, ordering,
   and completeness by reading the exclusive task-local tail to exhaustion.
4. The cache no longer owns or clones a full `CanonicalCheckpoint`. It stores a
   compact authority summary: identity, digest, source bounds, generation, operation
   authority, usage authority, and `Arc`-shared task snapshot. Cache map lookups clone
   only an `Arc`.
5. Incremental validation replays the task snapshot and configuration from the
   authenticated anchor through the exact durable tail, then compares the result to
   current projections before using safe-boundary, contract, or provider facts.
6. Full/incremental test counters now increment only after validation succeeds.
   Failure-path mutations explicitly assert that counts remain unchanged. A separate
   test-only prefix-scan counter proves the full-prefix query is not used by the
   second same-Store checkpoint.

### Systematic debugging and RED evidence

Root-cause tracing found three distinct trust/cost boundaries in
`Store::commit_checkpoint`: fallback facts came from `load_task_record`, fallback
canonical authentication inspected only the latest row, and
`validate_checkpoint_history` ran before the fast/fallback choice. The cache entry
also derived `Clone` over a full `CanonicalCheckpoint`.

The following mutations were written and observed failing before the production fix:

- `full_fallback_rejects_corruption_in_an_older_canonical_checkpoint`: whitespace was
  prepended to the first of two canonical checkpoint payloads through a separate
  SQLite connection. The candidate was incorrectly accepted and committed;
  `assert!(rejected.is_err())` failed.
- `full_fallback_rejects_an_externally_forged_safe_boundary`: the journal retained an
  active epoch while an external connection forged `agent_tasks` and `snapshot_json`
  to clear it. The checkpoint was incorrectly accepted;
  `assert!(rejected.is_err())` failed.
- `incremental_cache_rejects_same_connection_safe_boundary_tampering`: the same
  projection forgery was made through the Store's connection, for which
  `data_version` does not change. The cached fast path incorrectly accepted it;
  `assert!(rejected.is_err())` failed.
- `corrupted_authenticated_anchor_falls_back_and_fails_closed`: a rejected anchor
  mutation changed the counter from `(1, 0)` to `(2, 0)`, proving the counter measured
  attempts rather than successful validations.
- `first_checkpoint_uses_full_authority_then_incremental_tail_crosses_page_boundary`
  gained a literal prefix-scan assertion. Before the test-only observation point was
  implemented it failed to compile because no prefix-scan count existed; its final
  behavioral assertion is one prefix scan after both the full first checkpoint and
  the incremental 514-event tail checkpoint.

Every rejection contract also checks that journal length, task revision, checkpoint
row count, and successful-validation counters do not advance.

### GREEN evidence

Focused commands and results for the round follow. The 9-test authority suite,
formatting, strict Clippy, and diff check were rerun after the last production change;
the unchanged integration contracts were run after the authority implementation was
in place:

```text
cargo test --locked --lib checkpoint_authority_tests
  9 passed; 0 failed; 69 filtered out

cargo test --locked --test context_engine_contract
  20 passed; 0 failed

cargo test --locked --test task_storage_contract
  21 passed; 0 failed

cargo test --locked --test epoch_engine_contract startup
  3 passed; 0 failed; 78 filtered out

cargo test --locked --test long_horizon_eval fixture_copies_with_the_same_clock_read_are_isolated
  1 passed; 0 failed; 7 filtered out

cargo test --locked --test long_horizon_eval repository_fixture_rejects
  2 passed; 0 failed; 6 filtered out

cargo fmt -- --check
  exit 0

cargo clippy --locked --all-targets --all-features -- -D warnings
  exit 0

git diff --check
  exit 0
```

No full all-features test suite was run. The fixture-isolation fix and the dedicated
scenario's epochs, restarts, compactions, cuts, and assertions were unchanged.

### Path-selection evidence

- First checkpoint: 1 successful full validation, 0 incremental validations, 1
  full-prefix scan.
- Same-Store checkpoint with a 514-event exclusive tail: cumulative 1 full, 1
  incremental, still 1 full-prefix scan.
- Separate-connection invalidation followed by a same-Store checkpoint: cumulative
  2 full, 0 incremental; the following unchanged-connection checkpoint reaches 2
  full, 1 incremental.
- Every fallback or incremental corruption mutation leaves successful path counters
  unchanged.

### Superseded fix-round 1 capped exact sample

The one authorized unchanged command was:

```text
/usr/bin/time -p cargo test --locked --test long_horizon_eval actual_engine_survives_one_hundred_epochs_and_normalizes_replay -- --exact --nocapture
```

It passed the 100-epoch uninterrupted-versus-restarted normalized replay proof:

```text
test result: 1 passed; 0 failed; 7 filtered out; finished in 26.61s
real 36.02
user 29.58
sys 2.38
```

This superseded sample's test execution was 1.00 second (3.6%) faster than the
original 27.61-second baseline and 10.12 seconds faster than the pre-fix-round
36.73-second regression.
Cargo reported `Compiling carl-agent` and spent 8.23 seconds rebuilding the
integration target immediately before the test, so the 36.02-second process wall
time could not be compared to the original 27.70-second warm wall time. Fix round 2
therefore prebuilt the target and produced the current comparable evidence below.

### Fix-round self-review and residual concerns

- The production/test change is confined to `src/storage/repository.rs`; the report
  is the only documentation change. `SECURITY.md` is unchanged.
- Fallback authority now originates in durable journal replay and the complete
  task-filtered canonical chain, all inside the immediate transaction/CAS boundary.
- The fast path retains transitive trust only for a same-Store authenticated anchor,
  verifies the exact latest row's stored bytes against the authenticated digest, and
  replays every subsequent task event before trusting current projections.
- The cache remains non-serialized and contains a bounded summary rather than
  multi-MiB checkpoint narrative/work/repository vectors. Operation and task-snapshot
  authority are retained because they are required to reconstruct tail semantics.
- The full fallback remains intentionally expensive after every reopen or external
  commit. No total-linear-complexity claim is made.
- In this superseded round-1 sample, test execution beat baseline by one second but
  process wall time included compilation. Round 2's prebuilt warm measurement below
  replaces it as the current performance evidence.

## Fix round 2/5 — authenticated-session paging and late-failure rollback

### Findings addressed

1. Incremental tail validation no longer calls the public task-to-session discovery
   pager. A private pager accepts the `session_id` from the authenticated cached task
   snapshot and queries `events` by `session_id` and `sequence > cursor`, ordered by
   ascending sequence and capped at 512 rows. The SQL retains the JSON lifecycle type
   and task-ID predicates, and every row still passes through `RawEvent` decoding and
   envelope validation.
2. The existing `events_by_session_sequence ON events(session_id, sequence)` index
   supports this access path. No migration or index change was required.
3. Projection disagreement during checkpoint fallback is again surfaced as typed
   `CarlError::Validation`; unrelated SQLite/storage failures retain their storage
   error type.
4. Full/incremental counters now advance only after the immediate transaction commits,
   rather than after authority validation but before journal/checkpoint/projection
   writes. A late failure therefore changes neither SQL state nor in-memory path
   evidence. Cache refresh remains after commit.

### RED evidence

- The existing 514-event boundary test was extended with test-only discovery-query
  instrumentation. After resetting the counter immediately before incremental
  commit, it observed 3 discovery queries: one for each 512-row page, 2-row page, and
  terminating empty page. The required literal was zero.
- `full_fallback_rejects_a_projection_rolled_back_to_a_non_latest_predecessor` was
  restored from generic `is_err()` to `matches!(..., Err(CarlError::Validation { .. }))`.
  It failed because journal/projection disagreement surfaced as `CarlError::Storage`.
- `late_checkpoint_insert_failure_rolls_back_without_advancing_cache_or_counters`
  installs a trigger that aborts insertion into `task_checkpoints`, after successful
  incremental authority validation and checkpoint-event append. Before the fix, the
  transaction rolled back its SQL changes but the path counters changed from
  `(1, 0)` to `(1, 1)`.

### GREEN contracts

- The 514-event tail crosses the 512-row boundary and remains exclusive, complete,
  ascending, and task-isolated even with another task's events interleaved in the
  same session. Incremental commit records zero task-to-session discovery queries.
- Non-latest projection rollback now returns typed `CarlError::Validation` and does
  not advance journal length, revision, checkpoint rows, or successful path counts.
- The injected late checkpoint-row failure returns typed `CarlError::Storage` and
  leaves journal length, task revision, checkpoint rows, the cached authority `Arc`,
  and path counters unchanged. After removing the trigger, the identical candidate
  commits through the same incremental authority path and advances exactly once.

Final focused evidence:

```text
cargo test --locked --lib checkpoint_authority_tests
  10 passed; 0 failed; 69 filtered out

cargo test --locked --test context_engine_contract
  20 passed; 0 failed

cargo test --locked --test task_storage_contract
  21 passed; 0 failed

cargo test --locked --test epoch_engine_contract startup
  3 passed; 0 failed; 78 filtered out

cargo test --locked --test long_horizon_eval fixture_copies_with_the_same_clock_read_are_isolated
  1 passed; 0 failed; 7 filtered out

cargo test --locked --test long_horizon_eval repository_fixture_rejects
  2 passed; 0 failed; 6 filtered out

cargo fmt -- --check
  exit 0

cargo clippy --locked --all-targets --all-features -- -D warnings
  exit 0

git diff --check
  exit 0
```

No broad all-features test suite or full dedicated test target was run. The fixture
isolation correction and long-horizon scenario semantics were unchanged.

### Superseded fix-round 2 prebuilt warm benchmark

The exact integration target was prebuilt first:

```text
cargo test --locked --test long_horizon_eval --no-run
  Finished test profile in 0.43s
```

Then exactly one warm heavy command was run:

```text
/usr/bin/time -p cargo test --locked --test long_horizon_eval actual_engine_survives_one_hundred_epochs_and_normalizes_replay -- --exact --nocapture
test result: 1 passed; 0 failed; 7 filtered out; finished in 27.78s
real 27.88
user 26.63
sys 0.58
```

| Round-2 comparison | Test | Real |
| --- | ---: | ---: |
| Original baseline | 27.61s | 27.70s |
| Fix round 2 prebuilt warm | 27.78s | 27.88s |
| Difference | +0.17s (+0.6%) | +0.18s (+0.6%) |

The semantic proof passed, but neither test time nor real time demonstrates the
required speedup. Per the timing cap, no second heavy command, tuning, weakened
validation, or evaluation change was attempted.

### Superseded round-2 self-review and residual concern

- Production/test changes are confined to `src/storage/repository.rs`; this report is
  the only documentation change. `SECURITY.md` remains untouched.
- The private known-session pager is used only when the session comes from the
  same-Store authenticated authority. Public discovery APIs and full journal replay
  retain their multi-session ambiguity checks.
- Tail paging uses the existing indexed `(session_id, sequence)` access path while
  retaining JSON task isolation and all decoding checks.
- Failed SQL commit paths cannot advance the cache or successful-validation counters.
- Correctness and rollback evidence was green. At the end of round 2, its comparable
  performance evidence missed the binding speedup requirement by approximately 0.6%,
  so the performance release dependency remained a concern at that superseded point.

## Fix round 3/5 — profile-guided canonical-byte reuse

### Diagnostic profile

No production or report edit preceded profiling. The first sampler setup attached to
the `/usr/bin/time` wrapper and captured only its `sigsuspend`; it provided zero
workload evidence and was discarded. After explicit authorization, the corrected
diagnostic launched the already-built integration binary directly and attached
macOS `/usr/bin/sample` to that exact PID at a 5 ms interval. The unchanged exact
test passed in 28.20 seconds while sampled. The effective profile contained 3,748
samples on the workload thread, representing 18.74 sampled CPU-seconds.

`sample` is statistical rather than a tracing profiler, so it does not report exact
dynamic invocation counts. The call column below records exact counts derivable from
the fixed two-run scenario and existing path counters; for event append it records
the sampled call-graph evidence instead. Inclusive sample buckets attribute child
work to the named enclosing phase and therefore must not be summed as exclusive
wall time.

| Rank | Required phase | Inclusive samples | Approx. sampled CPU | Call evidence |
| ---: | --- | ---: | ---: | --- |
| 1 | Canonical-chain validation | 880 | 4.40s | 22 full-chain calls: open plus first-checkpoint fallback for 11 Stores |
| 2 | Candidate construction/serialization | 531 | 2.66s | 800 `build_checkpoint` calls: four per epoch across two 100-epoch runs; serialization below it is attributed to enclosing paths |
| 3 | SQLite event append/projection | 387 | 1.94s | 136 sampled `append_task_event` call paths; dynamic calls are one per non-checkpoint lifecycle mutation, plus 200 direct checkpoint-event appends |
| 4 | Runtime artifact reconciliation | 99 | 0.50s | 11 RuntimeStore opens |
| 5 | `Store::open` projection replay | 20 | 0.10s | 11 Store opens |
| 6 | Checkpoint full fallback authority | 19 | 0.10s | 11 successful full validations |
| 7 | Checkpoint incremental authority | 7 | 0.04s | 189 successful incremental validations |
| 8 | Abandoned-operation reconciliation | below 5 | below 0.03s | 11 RuntimeStore opens; no standalone frame reached the report threshold |

The canonical-chain phase was the largest required enclosing phase. Stack inspection
showed that each historical checkpoint was normalized, structurally/secret validated,
and serialized once for byte identity, then serialized again by `digest()`, and a
third time by `validate_canonical_source_bounds` when matching the committed journal
event. The same canonical vector was therefore recomputed three times per row even
though the first vector already supplied the exact bytes needed for both hashes.

### Single production optimization

The one permitted optimization keeps the first `canonical_bytes()` result, computes
SHA-256 directly over that exact vector, and passes the resulting digest to source-
bounds/journal-event validation. Each historical checkpoint is now serialized once
per full-chain call instead of three times.

This does not skip a row or a validation boundary. Deserialization, normalization,
structure and secret checks, exact stored-byte comparison, SHA-256 digest comparison,
task/checkpoint/package identity, source bounds, committed-event identity/digest,
previous-digest lineage, context-package canonical bytes, and artifact validation all
remain in the same order and fail closed. The digest is mathematically identical to
`CanonicalCheckpoint::digest()`, which hashes the same canonical byte vector.

### RED/GREEN performance-path contract

A test-only thread-local counter was added at
`CanonicalCheckpoint::canonical_bytes()`. The focused startup contract creates two
canonical checkpoints, resets the counter immediately before reopen, and requires
one serialization for each stored row.

Before the production edit:

```text
cargo test --locked --lib storage::repository::checkpoint_authority_tests::startup_canonical_validation_serializes_each_checkpoint_once -- --exact --nocapture
  FAILED: left 6, right 2
```

After reusing the canonical bytes and digest:

```text
cargo test --locked --lib storage::repository::checkpoint_authority_tests::startup_canonical_validation_serializes_each_checkpoint_once -- --exact --nocapture
  1 passed; 0 failed; 79 filtered out
```

The instrumentation exists only under `cfg(test)` and adds no production state,
telemetry, serialization, or synchronization.

### Focused correctness and quality gates

All focused gates were rerun after the production change:

```text
cargo test --locked --lib checkpoint_authority_tests
  11 passed; 0 failed; 69 filtered out

cargo test --locked --test context_engine_contract
  20 passed; 0 failed

cargo test --locked --test task_storage_contract
  21 passed; 0 failed

cargo test --locked --test epoch_engine_contract startup
  3 passed; 0 failed; 78 filtered out

cargo test --locked --test long_horizon_eval fixture_copies_with_the_same_clock_read_are_isolated
  1 passed; 0 failed; 7 filtered out

cargo test --locked --test long_horizon_eval repository_fixture_rejects
  2 passed; 0 failed; 6 filtered out

cargo fmt -- --check
  exit 0

cargo clippy --locked --all-targets --all-features -- -D warnings
  exit 0

git diff --check
  exit 0
```

No broad all-features test suite or full dedicated integration target was run. The
exact 100-epoch scenario remained unchanged.

### Final prebuilt warm benchmark

The exact integration target was prebuilt first:

```text
cargo test --locked --test long_horizon_eval --no-run
  Finished test profile in 7.72s
```

Then exactly one comparable warm heavy command was run:

```text
/usr/bin/time -p cargo test --locked --test long_horizon_eval actual_engine_survives_one_hundred_epochs_and_normalizes_replay -- --exact --nocapture
test result: 1 passed; 0 failed; 7 filtered out; finished in 24.85s
real 26.20
user 24.02
sys 0.58
```

| Final comparison | Test | Real |
| --- | ---: | ---: |
| Original baseline | 27.61s | 27.70s |
| Fix round 2, superseded | 27.78s | 27.88s |
| Fix round 3 final | 24.85s | 26.20s |
| Final vs. baseline | -2.76s (-10.0%) | -1.50s (-5.4%) |

Both binding dimensions beat baseline. The uninterrupted-versus-restarted normalized
replay proof remained green with its exact 100 epochs, 33 compactions, nine candidate
restarts, exact cuts, and zero-loss/zero-duplicate assertions. No second optimization
or additional timing run was attempted.

### Round-3 self-review and residual cost

- The production change is confined to the canonical full-history validation in
  `src/storage/repository.rs`; `src/runtime/task/checkpoint.rs` and
  `src/runtime/task/mod.rs` contain only the focused `cfg(test)` observation point.
- `SECURITY.md`, the evaluation scenario, durability pragmas, cache trust boundary,
  transaction/CAS placement, journal replay, fallback rules, and corruption behavior
  are unchanged.
- Every new Store still replays task projections and performs full canonical-chain
  validation at open. Its first checkpoint also intentionally performs the complete
  fallback chain validation. This residual repeated scan is security-preserving and
  was not changed because the round allowed exactly one optimization.
- Same-Store steady state still uses the authenticated exclusive tail, and
  out-of-band `data_version` changes still force full journal/canonical fallback.
- The final sample demonstrates the mandatory speedup on this host, but shared-host
  variance remains; no total-linear or universal percentage claim is made.
