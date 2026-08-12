# Task 14C report: Recoverable service maintenance

## Implementation

- Bumped the strict owner service protocol from version 3 to version 4 and added
  the required `recoverable_maintenance` capability, `MaintenanceStatus`,
  `PrepareMaintenance`, and `Maintenance(ServiceMaintenanceStatus)` shapes. The
  client requires the capability and retains no older-version fallback.
- Added the fixed maintenance state contract with exact schema-version and
  phase/binding validation. Unknown fields, unsupported schema versions, and
  impossible Running/Draining/Ready combinations fail closed. Serialized status is
  bounded below 1 KiB and contains only typed task/checkpoint identifiers.
- Unified active-task ownership, maintenance phase, and emergency-shutdown
  publication under one asynchronous owner mutex. This linearizes prepare against
  task claims. Draining and Ready reject all new mutations before provider/task
  dispatch, while read commands and the exact durable Prepare replay remain
  available. A fresh Prepare key is rejected after the first maintenance claim.
- Added internal `TaskEngineControl::Quiesce` plus volatile
  `quiesce_after_checkpoint` and safe-boundary-coalescing state. Quiesce never
  interrupts an operation: it requests the existing provider soft boundary, lets
  the normal report/evidence/compaction/checkpoint path finish, and returns the
  exact Active snapshot after `Checkpointing -> Active` instead of starting the
  next epoch. Natural Complete/Blocked/Cancelled/Failed outcomes retain precedence.
- The service actor records Ready from the returned snapshot, preserves the exact
  task/latest-checkpoint binding, clears active ownership, preserves queued work,
  and shuts the provider down once. Idle maintenance becomes Ready without
  dispatching queued work.
- Changed the `carl serve` cancellation/signal path to serialize behind any admitted
  mutation, prepare maintenance, wait for Ready, join the actor, and exit after
  provider shutdown. Explicit protocol `Shutdown` remains the destructive emergency
  path and still uses cancellation/fail-closed task semantics.
- Added `carl maintenance status|prepare`. Prepare uses one outstanding private
  request at a time and a cancellation-aware Tokio interval with 100 ms delayed
  ticks; there is no unbounded yield/request loop. Both commands emit one closed
  JSON object and keep diagnostics on stderr.
- Rejected exact maintenance-shaped Buzz prompt/slash forms before task or provider
  mutation, including group-shaped input. Classification is byte-exact and does not
  trim leading/trailing whitespace into an owner-private command.

## State machine and ownership

```text
Running(active = None) -- prepare/signal --> Ready(None, None)
Running(active = task) -- prepare/signal --> Draining(task, None)
Draining(task, None)
  -- Quiesce accepted
  -- current operation/report/evidence/compaction/checkpoint completes normally
  -- engine returns Active with no active epoch
  --> Ready(task, latest_checkpoint)

Draining | Ready:
  reads                     -> allowed
  exact claimed Prepare key -> durable replay allowed
  fresh mutation/Prepare    -> rejected before dispatch
  emergency Shutdown        -> destructive path remains allowed
```

The owner mutex is shared by `claim_start`, maintenance transition, active clearing,
and emergency publication. The durable mutation gate surrounds receipt admission and
the state transition, so no new task claim can cross a successful prepare boundary.
Shutdown and Prepare exemptions are evaluated before taking maintenance-rejection
state in order to preserve the established durable receipt-before-owner-publication
ordering.

## Crash and restart semantics

- A hard abort after Prepare returned Draining, after one consequential effect was
  dispatched, and before the boundary/checkpoint was released left the operation
  Started in the journal. A fresh service bind used existing startup reconciliation
  to transition it to Uncertain and block the task. The replacement provider
  dispatched zero effects, so the effect count remained exactly one and no new task
  was created.
- A normal signal drain committed the operation and checkpoint, returned an Active
  task with no active epoch, and shut down without an interrupt. A fresh service bind
  resumed that task from the committed checkpoint and completed it with zero
  duplicate effects.
- A pending Prepare receipt is recoverable because a fresh process starts its
  in-memory maintenance phase at Running and re-executes the same receipt-bound
  transition. Status polling creates no durable receipt or task event.

## Emergency distinction

Maintenance is cooperative and recoverable: it never labels an active operation
Cancelled or Blocked merely to stop the service. Explicit `ServiceCommand::Shutdown`
is still the emergency/destructive operation: it publishes emergency ownership,
cancels or fail-closes active work through the established control path, preserves
queued work for restart, completes its durable receipt, and then shuts down the
provider. Tests cover both paths independently so an OS signal cannot silently
regress to emergency cancellation.

## RED evidence

Tests were written and run before the corresponding production changes against base
`75b669f6c18608dfdf887e87f1fdf6d1f9b70c33`.

1. The strict protocol contract failed to compile at the requested v4 boundary:

   ```text
   unresolved imports `MaintenancePhase`, `ServiceMaintenanceStatus`
   no variant `MaintenanceStatus` or `PrepareMaintenance` on `ServiceCommand`
   no variant `Maintenance` on `ServiceResult`
   no field `recoverable_maintenance` on `ServiceCapabilities`
   ```

2. Client negotiation initially accepted an Info response with
   `recoverable_maintenance: false`; the focused regression failed until the new
   capability became mandatory.

3. The engine quiesce regression failed to compile because
   `TaskEngineControl::Quiesce` did not exist. After the control existed, the test
   pinned one effect, two accepted Quiesce acknowledgements, one boundary request,
   one work epoch, a committed checkpoint, and an exact Active return.

4. CLI parsing failed to compile because `MaintenanceCommand` and the
   `Command::Maintenance` variant did not exist.

5. The deterministic emergency ordering regression observed zero pending Shutdown
   receipts while the owner mutex was held:

   ```text
   shutdown receipt must precede owner publication
   left: 0
   right: 1
   ```

   Root-cause tracing showed the maintenance rejection predicate awaited owner state
   before checking the Shutdown exemption. Reordering that predicate restored the
   established durable admission order. The test uses a spawned future with a real
   waker so it does not manufacture a Tokio mutex waiter convoy.

6. A fresh Prepare key after Ready initially returned the existing Ready status.
   The regression failed at `unwrap_err()` until the in-memory owner state bound the
   first Prepare key and admitted only its exact replay.

7. The Buzz classifier test first failed to compile because no private-maintenance
   rejection classifier existed. Exact slash, plain command, CLI-shaped, and group
   attempts now fail before provider work or task creation.

8. The affected service E2E initially timed out in the old signal-cancels contract
   with `interrupts=0, shutdowns=0`. Its pending provider fixture had no safe-boundary
   response. The contract and fixture now model a real Continue report/checkpoint and
   assert Active/no-active-epoch, one checkpoint boundary, zero interrupts, and one
   shutdown.

## GREEN evidence

The complete affected matrix was rerun after the final implementation changes:

```text
cargo test --locked --test service_protocol_contract
PASS: 15 passed, 0 failed

cargo test --locked --lib service::client::tests
PASS: 4 passed, 0 failed

cargo test --locked --lib runtime::task::engine::tests
PASS: 7 passed, 0 failed

cargo test --locked --lib service::server::tests
PASS: 15 passed, 0 failed

cargo test --locked --lib acp::server::tests
PASS: 2 passed, 0 failed

cargo test --locked --lib cli::tests
PASS: 5 passed, 0 failed

cargo test --locked --test cli_contract
PASS: 9 passed, 0 failed

cargo test --locked --test service_end_to_end
PASS: 20 passed, 0 failed

cargo test --locked --test buzz_end_to_end
PASS: 8 passed, 0 failed

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

cargo fmt --all -- --check
PASS: exit 0

git diff --check
PASS: exit 0
```

The full all-features test suite, live provider/OAuth tests, and network tests were
intentionally not run, as required by the Task 14C brief.

## Self-review

- Checked every protocol field and phase combination against the brief, including
  literal v3/v5 rejection, missing capability, bounded JSON, command mutation
  classification, digest replay, and storage receipt-kind validation.
- Checked every engine owner-control match, including planning, work streaming,
  approval wait, acknowledgement extraction, and idle owner control. Quiesce state is
  volatile and rehydrate initializes it false.
- Checked boundary coalescing does not suppress a boundary in a later provider epoch,
  and that the Continue decision performs evidence, compaction, checkpoint creation,
  and `Checkpointing -> Active` before returning.
- Checked actor/provider ordering for active, idle, queued, exact replay, fresh
  mutation denial, signal serialization, emergency receipt ordering, and provider
  shutdown idempotence.
- Checked hard-abort Draining reconciliation and committed-checkpoint reopen with
  exact effect counts, plus the unchanged destructive Shutdown suite.
- Checked CLI cancellation at connect, initial request, interval wait, and each poll;
  polling has one outstanding request and delayed 100 ms cadence.
- Checked Buzz exact raw classification against leading newline, trailing whitespace,
  quoted, embedded, extra-argument, second-block, and group-shaped inputs.
- Confirmed `SECURITY.md` and `Cargo.lock` were not edited, no database migration was
  added, `git diff --check` is clean, and no Cargo/Carl process remains.

## Residual risks and scope boundary

- Maintenance is intentionally process-local state. A crash resets the phase to
  Running and delegates recovery to the authoritative task journal and existing
  startup reconciliation rather than persisting a second lifecycle authority.
- A provider that never produces a valid safe-boundary report can keep recoverable
  maintenance in Draining; the CLI remains cancellation-aware and rate-limited, but
  it does not convert that condition into destructive cancellation. Operators retain
  explicit emergency Shutdown for that separate policy decision.
- Tests are deterministic and offline. No live endurance, provider, OAuth, or network
  run was performed in this slice.

## Commit

- `b49ac7c feat: add recoverable service maintenance`

## Review fix round 1: Durable conflicts and terminal Quiesce race

Two Important review findings were addressed in code commit `8f68dbf`.

### Durable Prepare-key conflicts

Mutation admission now constructs the bounded receipt claim before maintenance-phase
rejection, but only consults durable storage for a rejected mutation when its key is
the synchronized maintenance-owner key. A digest mismatch returns the typed
`idempotency_conflict` service error. Unrelated keys still return `stopped` before
receipt creation, task creation, or provider dispatch, so receipt capacity and the
existing emergency ordering remain unchanged.

The RED used fresh Unix-socket connections after an active Prepare returned
Draining. StartTask and Cancel with the Prepare key both returned `stopped` instead
of the required conflict. The GREEN asserts `idempotency_conflict` for both commands,
one task, one effect, one provider epoch, one boundary request, and exactly the two
legitimate receipts (Start plus Prepare). Existing Ready-phase denial coverage also
remained green. The storage receipt contract now asserts the typed `Conflict` claim
instead of treating digest reuse as an undifferentiated repository error.

### Natural completion before Quiesce acknowledgement

A deterministic test-only gate pauses Prepare after its durable claim and
`Running -> Draining` transition but before Quiesce delivery. The test releases a
valid terminal provider report, observes the actor reach Ready and shut the provider
down once, then releases Quiesce for idle-engine consumption. The RED returned a
rejected Prepare even though the same task was terminal and maintenance was Ready,
which left the Prepare receipt pending.

Prepare now handles a failed Quiesce acknowledgement by re-reading the synchronized
owner status. It returns success only when that status is Ready and retains the exact
same task binding; every other phase/task combination propagates the original actor
error. The GREEN asserts a Completed task, a real final checkpoint, one effect, one
provider shutdown, a completed receipt containing the Ready result, and exact replay
over a fresh connection.

### Fix-round verification

```text
cargo test --locked --lib service::server::tests
PASS: 17 passed, 0 failed

cargo test --locked --test service_protocol_contract
PASS: 15 passed, 0 failed

cargo test --locked --lib service::client::tests
PASS: 4 passed, 0 failed

cargo test --locked --lib runtime::task::engine::tests
PASS: 7 passed, 0 failed

cargo test --locked --test service_end_to_end
PASS: 20 passed, 0 failed

cargo test --locked --test task_storage_contract \
  service_command_receipts_are_global_durable_and_canonical -- --exact
PASS: 1 passed, 0 failed

cargo test --locked --lib acp::server::tests
PASS: 2 passed, 0 failed

cargo test --locked --lib cli::tests
PASS: 5 passed, 0 failed

cargo test --locked --test cli_contract
PASS: 9 passed, 0 failed

cargo test --locked --test buzz_end_to_end
PASS: 8 passed, 0 failed

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

cargo fmt --all -- --check
PASS: exit 0

git diff --check
PASS: exit 0
```

The prohibited broad all-features test suite and live provider/OAuth/network tests
were not run. `SECURITY.md`, `Cargo.lock`, and the database schema were not changed.
