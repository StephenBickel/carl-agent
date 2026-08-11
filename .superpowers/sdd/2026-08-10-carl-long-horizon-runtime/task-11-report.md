# Task 11 report: Expose autonomous task controls

## Implementation

- Added canonical `PermissionMode::FullAccess` (`fullAccess`) across ACP configuration,
  Codex adapter requests, CLI startup, and durable storage profiles. The legacy
  `BypassPermissions` wire value remains readable and explicitly gated, while new
  option surfaces advertise only `fullAccess`.
- Added migration 9 without modifying migrations 1–8. It backfills canonical
  permission profiles, records exact trusted Buzz owners and one-time admitted
  events, persists bounded task-control receipts, binds steering rows to receipt
  identities, and projects typed permission-tightening epoch interruptions.
- Added `carl trust buzz --actor <64-lower-hex> --workspace <canonical-path>`.
  Trust is workspace-scoped, idempotent for the same owner, replacement resets the
  channel, the first exact private event fills the channel once, and event replay is
  rejected before provider or task execution.
- Buzz `session/new` remains non-executing. The first admitted private owner prompt
  starts the provider in FullAccess and creates the durable task. Later admitted
  messages preserve explicit permission reductions instead of silently restoring
  FullAccess; an admitted owner may explicitly loosen back to FullAccess.
- Added bounded `_task/status`, `_task/list`, `_task/context`, `_task/resume`,
  `_task/cancel`, and `_task/steer` ACP methods with exact session/task binding.
  Mutations require an idempotency key and use durable pending/completed receipts
  bound to session, task, method, and request digest. Completed replays return the
  stored result; method, task, or payload rebinding fails closed.
- Receipt-scoped steering identities are persisted atomically with steering
  projection rows. The same key is at-most-once across retry/restart, while distinct
  keys carrying identical text remain distinct owner controls.
- Added exact `/status`, `/context`, `/resume`, `/cancel`, and
  `/permissions fullAccess|approval|readOnly` commands. Only an exact whole leading
  block is recognized; extra arguments, quoted text, embedded text, and commands in
  later blocks remain ordinary prompt content.
- Active durable configuration changes are queued. Model, effort, and permission
  loosening do not interrupt and apply immediately before the next provider
  dispatch. Permission tightening performs one controlled interrupt. With no
  active operation, Carl appends typed
  `EpochInterrupted { reason: PermissionTightening }`, closes no provider report,
  checkpoint, progress, verification, or clause evidence, and continues with the
  queued configuration. With a `Started` operation, Carl records evidence,
  transitions the operation to `Uncertain`, appends the typed interruption, blocks
  the task, and starts no next epoch.

## RED / GREEN evidence

1. `fullAccess` protocol and CLI tests initially failed to compile because the
   canonical variant did not exist. They now prove exact wire values, options,
   provider policies, and legacy compatibility.
2. Trust/storage tests initially failed on missing owner, event, permission-profile,
   and receipt APIs. They now cover owner/channel rebinding, replay denial, migration
   upgrade/reopen, and both receipt crash windows.
3. Buzz Kind 9 group-shaped input was initially accepted. Exact structural parsing
   now accepts only Kind 1 private events and rejects untrusted owner, wrong actor,
   wrong channel, group-shaped input, and replay with zero provider work and zero
   durable tasks.
4. Controlled steering initially deduplicated by text, collapsing two distinct
   owner controls. Receipt-derived control identity now makes same-key retry
   at-most-once while two keys with identical text create two steering projections.
5. Queued configuration initially applied before historical checkpoint assembly,
   causing provider-metadata validation to block the next epoch. Application now
   occurs after context assembly and immediately before provider dispatch.
6. Tightening initially interrupted the provider but left the logical epoch waiting,
   and an intermediate implementation incorrectly manufactured a provider report.
   The final implementation uses the distinct Carl-owned `EpochInterrupted` event;
   replay closes `active_epoch` without report or progress evidence.
7. A later Buzz event initially reset `/permissions approval` back to FullAccess.
   Admission now grants FullAccess only on first attachment and preserves later
   explicit reductions.
8. The live method matrix now proves all six routes, including successful queued-task
   resume, terminal resume rejection, exact cross-session denial, steer replay and
   payload/method rebinding denial, cancel completion replay, and bounded status,
   list, and context results.

## Verification

Final focused compatibility suites:

```text
cargo test --locked --test acp_protocol_contract --test acp_server_contract \
  --test acp_cli_contract --test cli_contract --test acp_storage_contract \
  --test storage_contract --test task_storage_contract \
  --test buzz_adapter_contract --test buzz_acp_contract \
  --test buzz_end_to_end --test memory_contract
PASS: 83 passed, 0 failed

cargo test --locked --test epoch_engine_contract
PASS: 79 passed, 0 failed

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

cargo fmt --all -- --check
PASS: exit 0

git diff --check
PASS: exit 0
```

The root agent owns the single final `cargo test --all-features` milestone run, so
this task deliberately did not run it.

## Self-review

- No provider or frontend prose grants authority. FullAccess comes from local ACP
  startup or an exact stored Buzz owner/workspace/event admission.
- No runtime store, mutex guard, or data-root lock is held across provider awaits in
  the Buzz durable loop; one actor owns the runtime store and a short-lived peer
  connection handles admission/status reads.
- Task-control replay never reports a pending crash-window receipt as completed.
  Successful controlled steering is journaled before its receipt completes.
- Permission tightening cannot create verification evidence. Started operations
  become `Uncertain` with explicit evidence and block before any continuation.
- Migrations 1–8 and `SECURITY.md` were not changed.

## Concerns

No known Task 11 correctness or integration gap remains. The branch is intentionally
left for the root agent's clean review and one reserved all-features test run.
