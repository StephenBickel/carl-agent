# Task 12 report: Keep tasks alive behind a persistent owner service

## Implementation

- Added a versioned, strict newline-JSON service protocol with bounded frames, task
  input and event pagination, unknown-field denial, duplicate-request protection,
  and durable idempotency-key binding.
- Added the persistent `TaskService` owner. It alone owns SQLite, the task engine,
  provider lifetime, task actors, control delivery, and cancellation. Client EOF
  drops only the frontend subscriber; active work continues.
- Added owner-private local transport: a canonical-data-root Unix socket with
  symlink/type rejection and mode `0600`, plus a data-root-hashed Windows named-pipe
  implementation restricted to the current owner.
- Added startup reconciliation for every resumable durable task before the service
  accepts frontend commands. A restarted owner resumes from the journal/checkpoint
  rather than duplicating a committed effect.
- Added `carl serve`, authenticated shutdown, OS-signal cancellation, service
  capability/model negotiation, and a reconnecting client with durable event
  cursors.
- Made `carl acp` a thin service client. It no longer opens SQLite or owns a provider;
  ACP disconnects leave the service and task running, and reconnect/load resumes
  strictly after the acknowledged durable sequence.
- Preserved trusted Buzz admission at the sole-writer boundary. Generic Buzz task
  steering fails closed, while the structural trusted route preserves exact
  actor/channel/session and replay checks before provider work.
- Added migration 11 for durable start receipts so the same start idempotency key
  returns the original task after service restart and rejects command-digest
  rebinding.
- Added bounded ACP output and cancellation-aware writes so a non-reading frontend
  cannot stall the owner or interrupt its task.

## RED / GREEN evidence

1. The first cancellation regression hung before provider interruption because an
   active-task mutex guard survived into a nested mutation. Scoping the guard before
   mutation now records one interrupt, one shutdown, and a durable cancelled state.
2. Start replay initially depended on process memory. The receipt migration and
   atomic store API now return the same task across owner restart and deny key reuse
   with a different digest.
3. A three-epoch ACP continuity test disconnects after the first committed effect,
   reconnects from its exact cursor during epoch 2, and completes epoch 3 with one
   effect, one completion report, no interrupt, and strictly increasing replay.
4. Startup initially prepared only the selected task. A two-task restart test now
   proves every resumable task is prepared before the replacement service accepts a
   client.
5. A slow ACP reader initially blocked forever after bounded-queue eviction. The
   writer now selects cancellation against frame writes; the frontend exits while
   the owner stays active with zero provider interrupts.
6. The Buzz end-to-end fixture initially launched an in-process ACP owner. It now
   launches a real `carl serve` process plus thin `carl acp`, proves trusted
   auto-dispatch, terminal-task replacement, structural steering, replay denial,
   generic-route denial, and single cancellation.
7. The ACP CLI contract now proves provider isolation, second-owner rejection, and
   independent clean EOF for two thin frontend processes.

## Verification

Focused implementation suites and broad static gates were used during development:

```text
cargo test --test service_protocol_contract
PASS: 7 passed, 0 failed

cargo test --test service_end_to_end
PASS: 12 passed, 0 failed

cargo test --test acp_server_contract
PASS: 4 passed, 0 failed

cargo test --test acp_protocol_contract
PASS: 8 passed, 0 failed

cargo test --test acp_kernel_contract
PASS: 32 passed, 0 failed

cargo test --test cli_contract
PASS: 5 passed, 0 failed

cargo test --test acp_cli_contract
PASS: 4 passed, 0 failed

cargo test --test buzz_end_to_end Buzz
PASS: 2 passed, 0 failed

cargo clippy --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

cargo fmt --all -- --check
PASS: exit 0

git diff --check
PASS: exit 0
```

The root agent owns the single final `cargo test --all-features` milestone run. This
task used change-focused RED/GREEN tests instead of repeating the full suite after
each Rust edit.

The attempted Windows GNU cross-check reached the bundled SQLite C build and stopped
because `x86_64-w64-mingw32-gcc` is not installed in this environment. Host Rust
compilation and all gates above pass; this is a toolchain limitation, not a reported
Windows Rust diagnostic.

## Self-review

- Slow or disconnected clients cannot own, cancel, pause, or retain an active task.
- Event replay is durable and cursor-based; no completion is synthesized by the ACP
  adapter and no provider effect is replayed merely because a frontend reconnects.
- Start idempotency is committed with task creation rather than acknowledged from an
  in-memory cache.
- The local endpoint derives identity from the canonical data root and is never
  accepted through a symlink alias.
- No service process remains after the focused process tests. `SECURITY.md` was not
  modified.

## Commit

- `1a5fe3a feat: keep tasks alive across frontend reconnects`

## Fix round 1/5

The first review round closed every reported Task 12 issue:

- Replaced process-local mutation replay with globally durable service-command
  receipts (migration 12), including safe pending-receipt reconciliation,
  command/payload rebinding rejection, and replayed owner shutdown.
- Bounded per-connection ledgers and per-task live-update storage. Live updates
  now carry exact task attribution, use cursor-based reconnect, and fall back to a
  snapshot after source or ring overflow instead of retaining unbounded history.
- Bridged approval-mode operations through typed service updates and exact,
  durable, single-use `/approve CODE` and `/deny CODE` commands. A pending
  approval survives frontend reconnect at the acknowledged live cursor and stops
  replaying after resolution.
- Preserved explicit permission modes for trusted starts and added durable,
  taskless trusted-session permission configuration. Owner Full Access remains
  the default ceiling while explicit Plan and Approval choices stay narrower.
- Kept trusted Buzz admission, actor/channel/session binding, and replay defense
  on steering, permission changes, and approval resolution. Plain steering is
  accepted only for an already bound session.
- Added stream generations so a replacement ACP subscriber owns delivery, made
  Buzz publication live-prompt-only, and prevented replay subscribers from
  duplicating pending approval messages.
- Required deterministic completion verification before accepting provider
  completion, retained marker-only cancel recovery, and made failed work-control
  journaling transition durably to `Failed` before acknowledgement.
- Hardened the Windows named-pipe endpoint with current-owner identity, DACL, and
  server-PID checks. The host could not complete the GNU cross-build because the
  MinGW C compiler required by bundled SQLite is not installed.
- Corrected the provider fixtures to emit truthful item completion/report events
  and made Buzz test teardown reap both ACP and service processes after failures.

Verification after the final reconnect fix:

```text
cargo test --locked --lib
PASS: 56 passed, 0 failed

cargo test --locked --test buzz_end_to_end
PASS: 6 passed, 0 failed

cargo test --locked --test service_end_to_end
PASS: 16 passed, 0 failed

cargo test --locked --test service_protocol_contract
PASS: 8 passed, 0 failed

cargo test --locked --test storage_contract
PASS: 21 passed, 0 failed

cargo test --locked --test task_storage_contract
PASS: 21 passed, 0 failed

cargo test --locked --test acp_server_contract
PASS: 4 passed, 0 failed

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

cargo fmt --all -- --check
PASS: exit 0

git diff --check
PASS: exit 0
```

No Task 12 review findings remain open. No service process remained after the
process-level tests, and `SECURITY.md` was not changed.

### Fix commit

- `6cf7453 fix: harden persistent task service`

## Fix round 2/5

The second review round closed all five remaining blockers:

- Buzz steering now requires one fresh, exact structural owner metadata block.
  Missing, malformed, foreign actor/channel, group-shaped, ambiguous, and replayed
  metadata all fail before a task control marker or provider steer is emitted.
- Every service owner instance publishes a UUID live generation. Service and ACP
  cursors are accepted only with their matching generation; reconnecting to a
  replacement owner resets a stale numeric cursor and delivers replacement
  assistant output, diff, and approval exactly once.
- Timed-out live subscribers are removed immediately. A paused-time 10,000-poll
  stress regression leaves zero subscriber senders and still delivers the next
  publication to a real waiter.
- Windows named pipes now use the actual current-user SID, a protected DACL, and
  exactly one non-inherited allow ACE with the exact generic read/write mask. The
  client verifies the server process SID, descriptor owner, DACL protection, ACE
  count/type/flags/mask, and ACE SID. The host security-shape matrix rejects foreign
  owners and SIDs, unprotected or inherited ACLs, extra/deny ACEs, and insufficient
  or excessive masks.
- The runtime peer SQLite connection is read-only from connection creation via
  `SQLITE_OPEN_READ_ONLY`, then additionally uses `query_only`; it performs only
  read validations. Durable mutation receipt claim/completion now runs through the
  owner `TaskEngine` actor, and ordinary and trusted approval mutation receipts are
  asserted canonical, completed, JSON-valid, replay-stable, and never pending.

### RED / GREEN and debugging evidence

- The strict Buzz matrix was RED because missing metadata fell back to generic
  steering; removing that fallback made the full admission matrix GREEN with zero
  mutation delta on every rejection.
- The live-generation protocol, service page, ACP binding, and real owner-restart
  regressions were RED before generation ownership existed. The real restart test
  now crosses a nonzero old cursor and verifies assistant, diff, and approval once
  through both ACP and the service API, then completes truthfully after approval.
- The subscriber stress regression was RED with 10,000 retained senders and GREEN
  with explicit subscriber IDs and unregister-on-return.
- The peer-store regression was RED when a peer could claim a receipt. It is GREEN
  with a read-only SQLite open, and all successful service mutation paths retain
  their durable canonical receipts through the owner writer.
- Systematic debugging of the three-epoch reconnect timeout found a test-ordering
  race: the fixture released its final epoch after writing the prompt but before
  provider steer acknowledgement. The new owner-actor receipt round trip exposed
  that invalid timing assumption, so the task could finish and reject the steer.
  Boundary tracing showed Active status followed by a rejected steer and terminal
  fake-provider state. Holding release until the provider observed the steer made
  the request apply; the final regression uses that condition instead of a sleep.
  All temporary diagnostic logging was removed.

### Verification

```text
cargo test --locked --lib \
  --test service_protocol_contract --test service_end_to_end \
  --test buzz_end_to_end --test acp_server_contract \
  --test buzz_acp_contract --test storage_contract \
  --test task_storage_contract
PASS: 144 passed, 0 failed

cargo fmt --all -- --check
PASS: exit 0

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

git diff --check
PASS: exit 0
```

After the final peer read-only refinement, the peer mutation, ordinary service
mutation receipt, and Buzz approval receipt regressions all passed again, followed
by the strict formatting, clippy, and diff gates.

The installed `x86_64-pc-windows-gnu` target reached `libsqlite3-sys` and stopped
because `x86_64-w64-mingw32-gcc` is not installed. This is the expected external C
toolchain limitation; no Windows Rust diagnostic was reported before it. The host
Windows descriptor/ACE validation matrix passed. No Carl service process remained,
no migration or `Cargo.lock` changed, and `SECURITY.md` was not modified.

### Fix commit

- `1fa6d20 fix: enforce persistent service ownership boundaries`
