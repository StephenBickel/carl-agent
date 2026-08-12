# Task 13 checkpoint-authority/startup performance report

## Status

`DONE_WITH_CONCERNS`: the semantic and corruption gates pass, but the required warm
100-epoch speedup was not demonstrated. The final capped run took 36.73 seconds in
the test (37.38 seconds wall clock), compared with the 27.61-second test baseline
(27.70 seconds wall clock). This follow-on therefore does not satisfy its release
performance objective and should remain a blocker before Task 14.

## Design

- `Store` owns a non-serialized, task-keyed authenticated-checkpoint cache. Each
  entry binds the canonical checkpoint, its digest, source-sequence end, and the
  SQLite `PRAGMA data_version` observed when it was authenticated.
- A checkpoint commit retains the existing immediate transaction and revision CAS.
  When the cached anchor's data version and exact database row match, authority is
  reconstructed from that authenticated checkpoint plus the exclusive, ascending,
  task-local journal tail after its source-sequence end. Paging remains at 512 rows.
- On cache absence, uncertainty, mismatch, or an out-of-band commit, the existing
  full journal-authority routine remains the corruption oracle. Before that full
  scan, the exact latest predecessor is authenticated against its canonical bytes,
  digest, task/checkpoint identity, source range, immediate previous-digest lineage,
  atomic canonical context package, generation, event sequence, and artifact set.
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

The final focused batch completed successfully:

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

## Timing

Same host, debug test profile, locked dependencies, warm exact command:

```text
/usr/bin/time -p cargo test --locked --test long_horizon_eval actual_engine_survives_one_hundred_epochs_and_normalizes_replay -- --exact --nocapture
```

| Measurement | Test | Real | User | Sys |
| --- | ---: | ---: | ---: | ---: |
| Before | 27.61s | 27.70s | 26.72s | 0.54s |
| Final capped after | 36.73s | 37.38s | 29.10s | 1.27s |

The final run passed but regressed by 9.12 seconds in test time (33.0%) and 9.68
seconds in wall time (34.9%). An earlier post-change warm sample was also slower at
31.10 seconds test / 31.44 seconds real. The performance objective is therefore
unmet; no additional tuning or weakening of proof was attempted after the cap.

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
- Timing variance exists on the shared host, but both post-change warm exact samples
  exceeded the baseline; there is no defensible speedup claim.

## Self-review

- Reviewed the complete production/test diff and confirmed the changes are limited
  to `src/storage/repository.rs` and `tests/long_horizon_eval.rs`; the report is the
  only documentation addition.
- Confirmed cache state is memory-only, exact-task keyed, updated only after a
  successful transaction commit, and invalidated by `data_version`/row mismatch.
- Confirmed incremental paging is exclusive and ascending, checks the exact tail
  end, reconstructs operation/evidence and usage authority, and retains the full
  fallback.
- Confirmed failure-path tests assert no journal, checkpoint-row, or task-revision
  advance.
- Confirmed the fixture fix uses a deterministic process-local uniqueness suffix and
  does not modify the long-horizon scenario, counts, cuts, or assertions.
- Concern: correctness is supported by all required gates, but the binding speedup
  requirement is not met. The implementation should not be promoted as completing
  the Task 13 release dependency without a separately authorized performance design.
