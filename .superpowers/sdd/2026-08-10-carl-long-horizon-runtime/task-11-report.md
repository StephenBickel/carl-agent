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

## Fix Round 1/5

### Findings fixed

- Autonomous task configuration is now journal-owned. `ConfigurationQueued` records
  the exact control identity, model, effort, and permission; its projection keeps
  active, pending, and immediately effective permission state separately.
  `ConfigurationApplied` is appended at the safe epoch boundary before the next
  provider dispatch. Rehydration restores all of that state exactly, so an immediate
  tightening ceiling survives every interruption/restart cut while model, effort,
  and permission loosening remain deferred.
- Every active steering, cancellation, and configuration control now carries its
  exact task identity through the kernel channel into `TaskEngine::apply_control`.
  Both the durable actor and engine reject a request for queued task B while task A
  is executing, before provider interruption or a B control marker can occur.
- Resume and cancel have durable `ControlRequested` markers tied to their receipt
  identities. A pending receipt can be reconstructed after a real engine/store
  restart when the action committed but receipt completion failed, without another
  provider start or interrupt. Deterministic invalid-input outcomes are completed
  durably with the receipt and replay the same rejection instead of leaking a
  permanently pending reservation.
- Interrupted epochs are projected truthfully as `interrupted`, with their exact
  finishing event sequence and no provider report digest. Migration 10 also
  backfills pre-existing v9 interruption rows rather than carrying their obsolete
  `active` epoch status forward.
- The legacy `bypassPermissions` value remains readable for stored/wire
  compatibility but is no longer exposed as a normal `--permission-mode` CLI value.
  Full access remains available only through the canonical explicit route.

### RED / GREEN evidence

1. The first durable-configuration storage regression failed to compile because
   configuration events, their projection, and exact rehydration APIs did not
   exist. It now proves queued model `gpt-5.6-codex`, `ultra` effort, and `plan`
   permission survive reopen, then apply atomically and clear the pending state.
2. The CLI regression initially parsed
   `--permission-mode bypassPermissions`; after removing that Clap variant, the
   exact command is rejected while canonical `fullAccess` still parses.
3. Four configuration interruption cuts now restart from durable state: after the
   configuration append, before provider interrupt confirmation, after confirmation,
   and before the next epoch dispatch. Every row starts the next provider epoch in
   the exact tightened configuration and authorizes no intervening effect.
4. The busy-task Buzz regression proves both `_task/cancel` and `_task/steer` for
   queued task B return `-32602` while A is executing, with zero provider interrupts
   and zero B control markers.
5. SQLite completion-failure triggers first proved same-process action recovery for
   resume and cancel. The final table-driven regression performs the real action,
   forces receipt completion to fail, drops both engine and store, opens fresh
   instances, and proves retry completes the pending receipt with zero duplicate
   starts or interrupts.
6. The literal v9 migration regression initially observed a NULL
   `finished_sequence` for an existing interruption. Migration 10 now produces
   `status = interrupted`, the exact interruption sequence, and a NULL report
   digest.

### Verification

```text
cargo test --locked --test storage_contract --test acp_storage_contract \
  --test task_storage_contract --test acp_server_contract \
  --test acp_protocol_contract --test acp_cli_contract --test cli_contract \
  --test buzz_adapter_contract --test buzz_acp_contract \
  --test buzz_end_to_end --test memory_contract
PASS: 86 passed, 0 failed

cargo test --locked --test epoch_engine_contract
PASS: 81 passed, 0 failed

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

cargo fmt --all -- --check
PASS: exit 0

git diff --check
PASS: exit 0
```

The required full `cargo test --all-features` milestone remains reserved for the
root agent after clean review and was not run in this fix round.

### Fix-round self-review

- Configuration events and projections commit in the same SQLite transaction;
  acknowledgement follows that commit. Tightening changes only the immediate
  authority ceiling until the complete configuration is promoted at a boundary.
- Receipt markers record intent before provider action. Terminal task state plus
  the exact marker distinguishes committed-action recovery from an unrelated
  terminal request, while receipt rebinding checks remain unchanged.
- Foreign keys are enabled and checked immediately after migration 10 rebuilds the
  epoch table. Migrations 1–9 and `SECURITY.md` remain byte-for-byte unchanged.
- No task-control path holds the admission-store mutex across an async provider or
  engine operation. No Important or Critical finding remains open from this round.

## Fix Round 2/5

### Findings fixed

- The frontend no longer supplies a `tightening` claim with autonomous
  configuration controls. `TaskEngine` alone compares each requested permission
  with the runtime's journal-rehydrated effective ceiling before it queues the
  event or interrupts the provider. An active Plan task can therefore queue
  FullAccess and then supersede it with Default: the durable state remains active
  Plan, effective Plan, pending Default until the boundary, where Default—not the
  stale FullAccess request—is promoted and dispatched.
- Configuration delivery acknowledgements now synchronize the session's pending
  configuration from `task_configuration_state`, including failure and channel
  rejection paths. A failed journal append clears the tentative session change;
  an acknowledgement that races with boundary application adopts the exact
  projected active configuration. Pending state is applied to the session only
  after outstanding control acknowledgements have been reconciled.
- `Store::open` now folds `Created`, `ConfigurationQueued`,
  `ConfigurationApplied`, and `ControlRequested` events while it performs the
  existing authoritative task replay. It compares the exact active/effective/
  pending configuration, queue/application sequences, and ordered marker set with
  the child tables. Missing, stale, or extra child state is rejected
  deterministically instead of being trusted by rehydration or receipt recovery.

### RED / GREEN evidence

1. The real Buzz ACP supersession regression began with Plan, accepted queued
   FullAccess, then received `-32602` for Default because the kernel compared
   against its tentative FullAccess while the engine compared against durable
   effective Plan. It now accepts both requests, records `(Plan, Plan, Default)`
   before the boundary, performs zero interrupts, dispatches Default with the
   workspace-write policy, and projects `(Default, Default, none)` afterward.
2. A SQLite trigger rejected the `ConfigurationQueued` event after the session had
   tentatively selected FullAccess. RED persisted `bypassPermissions` in the
   frontend session while the task journal remained Plan. GREEN returns an error,
   finishes the blocked task without promoting the rejected choice, and leaves
   both session and task configuration exactly Plan with no pending value.
3. Two configuration-corruption regressions changed a queued Plan projection to
   stale FullAccess or deleted the row. Both initially reopened successfully; both
   now return typed storage errors naming the missing or disagreeing configuration
   projection.
4. Deleting a durable cancel marker initially allowed `Store::open` to succeed.
   Startup now compares the complete marker table with `ControlRequested` journal
   events and rejects the missing marker, so receipt recovery cannot repeat the
   action from silently corrupted child state.

### Verification

```text
cargo test --locked --test task_storage_contract \
  --test storage_contract --test acp_storage_contract
PASS: 49 passed, 0 failed

cargo test --locked --test buzz_end_to_end --test acp_server_contract
PASS: 9 passed, 0 failed

cargo test --locked --test epoch_engine_contract -- \
  queued_permission_tightening_survives_each_interrupt_restart_cut \
  --exact --nocapture
PASS: 1 passed, 0 failed

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

cargo fmt --all -- --check
PASS: exit 0

git diff --check
PASS: exit 0
```

No `cargo test --all-features` command was run; the final milestone remains
reserved for the root agent after clean review.

### Fix-round self-review

- Supersession can only reduce authority relative to the durable effective ceiling;
  a tentative loosening never becomes the baseline for an unnecessary interrupt.
- Session reconciliation performs no async work while holding the peer-store mutex.
  It accepts the projection as authoritative only after normal `Store::open`
  journal validation has established its integrity.
- Child validation reuses the existing paged journal traversal and configuration
  loader. It adds no migration rewrite or rebuild path, so migration compatibility
  and startup failure semantics remain explicit and deterministic.
- Migrations 1–10, `SECURITY.md`, and the broader task lifecycle reducer were not
  modified. Both review blockers are closed with no deferred finding.

## Fix Round 3/5

### Integration failure fixed

- Buzz session creation now defers provider startup only when the request has no
  pre-bound Buzz context. This preserves the Task 11 rule that production Buzz
  `session/new` is non-executing until trusted-owner admission, while restoring the
  existing bound-session path used by legacy approval and publication flows.
- The failure was unrelated to Round 2 configuration reconciliation. Task 11 had
  widened the non-executing condition from context-free Buzz sessions to every Buzz
  session, so bound Default-mode sessions reached `begin_prompt` without a provider
  context and returned `ApprovalUnavailable` before either delivery or approval.

### RED / GREEN evidence

1. `remote_approval_is_exact_single_use_and_resumes_the_same_turn` initially failed
   on its first prompt with `ApprovalUnavailable`. It now reaches the approval pause,
   resumes the same turn exactly once, and rejects replay.
2. `ambiguous_buzz_delivery_is_durable_and_distinct_from_provider_failure` initially
   returned `ApprovalUnavailable` before publication. It now returns
   `DeliveryUncertain` and records the durable uncertain-delivery transition and turn
   interruption.
3. The complete `acp_kernel_contract` suite passes all 32 tests, including autonomous
   task routing and the legacy ACP/Buzz approval paths.

### Verification

```text
cargo test --locked --test acp_kernel_contract -- \
  remote_approval_is_exact_single_use_and_resumes_the_same_turn --exact --nocapture
PASS: 1 passed, 0 failed

cargo test --locked --test acp_kernel_contract -- \
  ambiguous_buzz_delivery_is_durable_and_distinct_from_provider_failure --exact --nocapture
PASS: 1 passed, 0 failed

cargo test --locked --test acp_kernel_contract
PASS: 32 passed, 0 failed

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

cargo fmt --all
PASS: exit 0

git diff --check
PASS: exit 0
```

No `cargo test --all-features` command was run; the root agent owns the final
milestone rerun after this integration fix.

### Fix-round self-review

- Context-free Buzz sessions remain unable to start provider work before exact
  trusted-owner admission. The production ACP server still creates Buzz sessions
  without a context and attaches one only after the admission check.
- The fix does not alter durable task routing, journal-owned configuration, remote
  code consumption, delivery persistence, migrations, or security documentation.
- No new regression test was needed because the two existing failing contracts are
  exact end-to-end coverage for the affected bound-session behavior.

## Fix Round 4/5

### Integration failure fixed

- The proposal corruption contract now expects `RuntimeStore::open` to reject its
  two deliberately orphaned databases. The fixture disables SQLite foreign-key
  enforcement before deleting an artifact parent and later an inspection parent;
  both states are genuine FK violations and must fail closed at startup.
- No production validation changed. Task 11 Round 1 enabled foreign keys after
  migration and added a global `PRAGMA foreign_key_check`, so the corruption is now
  detected earlier than the proposal-specific getters. The candidate-digest tamper
  does not violate an FK and still opens successfully before the getter rejects its
  recomputed digest mismatch.

### RED / GREEN evidence

1. `proposal_load_rejects_tampered_candidate_digest_and_orphaned_rows` initially
   escaped through `?` when the first intentionally orphaned database was rejected by
   `RuntimeStore::open`. It now explicitly requires startup rejection for both orphan
   variants while retaining the getter-level digest-tamper assertion.
2. The complete `proposal_storage_contract` binary passes all 14 tests.
3. The focused core, ACP, subscription-run, and task-storage suites pass all 67
   tests, including migration upgrades, corrupt-history rejection, and Task 11 child
   projection validation.

### Verification

```text
cargo test --locked --test proposal_storage_contract -- \
  proposal_load_rejects_tampered_candidate_digest_and_orphaned_rows --exact --nocapture
PASS: 1 passed, 0 failed

cargo test --locked --test proposal_storage_contract
PASS: 14 passed, 0 failed

cargo test --locked --test storage_contract --test acp_storage_contract \
  --test task_storage_contract --test subscription_run_storage_contract
PASS: 67 passed, 0 failed

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

cargo fmt --all -- --check
PASS: exit 0

git diff --check
PASS: exit 0
```

No `cargo test --all-features` command was run; the root agent owns the final
milestone rerun after this compatibility correction.

### Fix-round self-review

- The startup FK check remains global and unconditional after migration; the test
  does not whitelist proposal tables or permit orphaned rows to reach runtime code.
- Migrations 1–10, production storage code, `SECURITY.md`, and Task 11 journal/child
  validation are unchanged.
- The updated assertions exercise real startup behavior against the existing
  intentionally corrupt SQLite fixture and do not depend on exact error prose.
