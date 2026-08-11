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
