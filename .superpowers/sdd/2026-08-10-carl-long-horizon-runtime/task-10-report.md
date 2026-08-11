# Task 10 report: Recover durable tasks without replay

## Implementation

- `RuntimeStore::open` now reconstructs authoritative nonterminal task records and
  changes every abandoned `Started` operation to `Uncertain` in one immediate
  SQLite transaction. Each transition has fresh operation-bound evidence, updates
  the child projection and snapshot atomically, and rolls back globally if any
  projection write fails.
- Startup recovery distinguishes effect classes. Observations reconcile and may
  be issued later under a fresh operation ID. Idempotent file mutations bind a
  typed SHA-256 postcondition before dispatch and invoke the adapter's exact
  postcondition inspector after interruption: an exact match reconciles the same
  operation without redispatch; absence or mismatch remains uncertain and blocks
  with the exact operation ID. Ambiguous consequential effects are never replayed.
- Added `TaskEngine::reconcile_startup` and made kernel startup await it before the
  actor accepts frontend commands. Startup prepares queued and resumable tasks,
  closes abandoned epochs, resumes provider contexts, restores exact background
  processes, and never dispatches a new work epoch.
- Stable unavailable-context failures append `ProviderContextLost`, assemble the
  latest Carl-owned checkpoint/context package, replace rather than mutate the old
  provider context, append the fresh `ProviderContextBound`, and drive the next
  request as `FreshContextDiagnosis` recovery.
- Provider replacement rehydrates correctly at both crash cuts: loss committed
  without a new binding and new binding committed without a recovery epoch.
- Background recovery requires one exact provider process match on process ID,
  item ID, command digest, and cwd digest. Missing, duplicate, invalid, or
  mismatched handles block before new provider work.
- Cancellation terminates each restored process and journals the typed
  `BackgroundProcessTerminationRecorded { process_id, item_id, terminated }`
  result before claiming cleanup. A false result leaves cleanup blocked.
- Added the complete twelve-cut restart matrix, transactional startup fault
  injection, provider loss/replacement, ambiguous and idempotent no-replay,
  background restore/cancel, and typed domain/storage replay contracts.

## RED / GREEN evidence

1. Startup storage tests initially reopened abandoned operations as `Started` and
   did not reach the injected second-operation projection failure. They now pass
   with every operation `Uncertain`, projection equal to authoritative replay,
   and no partial journal/projection mutation after injected rollback.
2. The ambiguous restart regression initially returned a storage error instead of
   a typed exact-ID blocker. It now keeps the external durable counter at one and
   blocks without a second effect resolution.
3. Bound provider restart initially made no `resume_context` attempt. It now
   resumes the exact durable context before any new epoch and does so only once
   when startup preparation is followed by `run`.
4. Unavailable provider recovery initially omitted `ProviderContextLost`; the
   loss-only cut could not rehydrate, and the binding-only cut lost fresh-context
   diagnosis. All three cuts now append/rehydrate the exact loss and fresh binding
   sequence and use recovery-purpose diagnosis.
5. Queued task restart initially failed as invalid. It now starts one context,
   commits activation and binding, and begins no duplicate context on execution.
6. Exact background recovery initially skipped provider enumeration; missing
   handles incorrectly allowed completion. It now restores only a unique exact
   four-field match and blocks a missing/mismatched identity before a new epoch.
7. Background cleanup initially had no typed journal representation. The domain
   RED failed to compile on the missing event; domain and storage reopen tests now
   preserve the exact boolean, and engine tests cover both true and false results.
8. Kernel startup initially had no reconciliation API. The startup contract now
   prepares resumable tasks, resumes their context, starts no work epoch, and lets
   a later `run` continue without a second resume.
9. Idempotent recovery initially implemented only the safe negative path: both an
   exact match and mismatch skipped inspection and blocked. The focused RED showed
   `prepared=[]` for a matching digest and zero mismatch inspections. The GREEN
   cases now inspect the durable binding exactly once: match becomes `Reconciled`,
   while mismatch and the default absent result remain `Uncertain` and blocked;
   all three keep the durable effect counter and provider epoch count unchanged.
10. The twelve required durable interruption cuts reopen to snapshots exactly
    equal to authoritative journal replay.

## Verification

Commands run after the final postcondition implementation:

```text
cargo test --test task_storage_contract --test task_domain_contract \
  --test epoch_engine_contract --test acp_kernel_contract \
  --test agent_port_contract
PASS: 137 passed, 0 failed

cargo clippy --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

cargo fmt --all -- --check
PASS: exit 0

git diff --check
PASS: exit 0

cargo test --all-features
PASS: exit 0; every unit, integration, binary, and doc-test target passed
with 0 failures
```

The all-features milestone suite was run exactly once.

## Self-review

- Every uncertain-operation recovery decision uses Carl-owned journal state and
  fresh adapter evidence; provider prose cannot reconcile an effect.
- Postcondition binding is durable before dispatch, is typed as `Sha256Digest`,
  and the trait-object forwarding path preserves adapter inspection overrides.
- Ambiguous effects and idempotent effects without an exact match are never
  redispatched automatically.
- Provider loss never deletes or edits the old transcript; replacement receives a
  Carl context package and creates a new binding.
- No security policy file was changed.

## Concerns

No known Task 10 correctness or integration gap remains.

## Fix Round 1/5

This round supersedes the earlier postcondition-inspector and label-only restart-matrix
claims above.

### Reviewer findings resolved

1. Background processes now enter and leave `RuntimeTask::running_processes` from
   normal `ItemStarted`/`ItemCompleted` command events. Checkpoint construction
   hashes the current command and cwd from that engine-owned lifecycle state.
   Recovery and cancellation tests consume the resulting engine-built checkpoint;
   none rewrites checkpoint JSON with SQL. Exact recovery requires one match on
   process ID, item ID, command digest, and cwd digest. Tests also prove completed
   metadata replaces started metadata, a completed command without a process removes
   it, every individual identity mismatch blocks before a new epoch, and both true
   and false termination results are durable.
2. The production Codex adapter now recognizes only the stable structured
   `-32600` response whose message is exactly `no rollout found for thread id
   <requested-id>` and whose object shape contains no unrecognized fields. It maps
   that response to definitely-not-applied `UnavailableContext`; an ordinary
   same-code `failed to load rollout` response remains a transport failure. The
   shape was first confirmed against pinned Codex app-server `0.146.0`.
3. Provider-supplied postcondition inspection and the fake digest echo were removed.
   A successful file mutation is bound only after a validated `ItemCompleted`
   mutation event. Carl validates a bounded, sorted, unique set of portable relative
   paths, opens the workspace and every parent through held no-follow handles, and
   records for each path either missing state or the SHA-256 content digest of a
   bounded regular single-link file. The durable typed spec revalidates on decode
   and redacts paths and digests from Debug. Restart compares the current held-
   workspace observation directly. A crash before the durable spec blocks; an exact
   match reconciles without redispatch; a mismatch blocks. Traversal is rejected
   before dispatch, while symlink and hard-link topologies remain uncertain after
   mutation and persist no spec.
4. An `Active` task whose activation committed without any provider binding now
   starts and binds exactly one fresh context when history proves no provider epoch,
   request, or operation could have started. It does not repeat the activation or
   attempt resume. If provider-work evidence is present, recovery durably blocks
   instead of returning an invalid-task kernel failure.
5. The twelve-cut test is now a real table-driven `TaskEngine` fault/restart matrix.
   Every row uses an event-transaction abort or provider pending fault, checks the
   projection against authoritative reducer replay at the cut, drops the engine and
   store, reopens through `RuntimeStore`, verifies the expected completed/blocked
   outcome and exact dispatch/effect/mutation counters, then checks replay again.
   Item-started, operation-intent, effect-authorized, and workspace-mutated are
   independently observable cuts. Provider replacement-started and replacement-
   binding-committed also execute through the real unavailable-context path. The
   old storage-only test remains only as a representative journal-prefix replay
   test and is no longer described as the crash matrix.

### RED / GREEN evidence

- Background RED: `cargo test --test epoch_engine_contract background_process --
  --nocapture` initially failed 3/3 because checkpoints were empty and recovery did
  not enumerate or terminate provider processes. GREEN: 4/4, plus the exact process-
  removal and false-termination tests each pass 1/1.
- Codex RED: the exact pinned missing-rollout response produced `Transport` instead
  of `UnavailableContext`. GREEN: the exact adapter contract passes 1/1, while the
  ordinary same-code failure remains `Transport`.
- Filesystem postcondition RED: 3/3 failed because binding preceded dispatch and a
  provider echo reconciled mismatched real bytes. GREEN: `cargo test --test
  epoch_engine_contract postcondition -- --nocapture` passes 6/6 for absent, exact,
  mismatched, traversal, symlink, and hard-link cases. The typed canonical/redacted
  domain round trip passes 1/1.
- Missing binding RED: the activation-only cut returned `InvalidTask`. GREEN: fresh
  binding and unsafe-history blocking each pass 1/1.
- Matrix RED first exposed a checkpoint-committed expectation that ignored the
  legitimate new verification epoch. The corrected matrix asserts exact total
  dispatches and no second filesystem mutation. GREEN: all twelve rows pass in the
  single table-driven test.

### Verification

Focused compatibility command:

```text
cargo test --test agent_port_contract --test acp_kernel_contract \
  --test epoch_engine_contract --test task_domain_contract \
  --test task_storage_contract --test codex_app_server_contract
PASS: 156 passed, 0 failed
```

Strict lint:

```text
cargo clippy --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings
```

```text
cargo fmt --all -- --check
PASS: exit 0

git diff --check
PASS: exit 0
```

The full `cargo test --all-features` suite was deliberately not run during this fix
round, as required.
