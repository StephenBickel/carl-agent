# Task 9 report: Run autonomous durable coding epochs

## Implementation

- Added `TaskEngine<P, S>` with the stable `start`, `run`, `steer`, and `cancel`
  seam over either `Store` or the kernel-owned `RuntimeStore`.
- Added bounded read-only contract planning with one repair attempt and the fixed
  requested-outcome/explicit-verification fallback contract.
- Added the autonomous work loop: durable epoch start, context assembly, provider
  dispatch, normalized operation evidence, report verification, progress
  assessment, atomic checkpoint commit, continuation, compaction, recovery, and
  terminal completion/blocking.
- Added soft epoch boundaries for elapsed time and completed-tool count. Boundary
  steering is journaled first; unsupported steering falls back to an exact epoch
  interrupt.
- Added deterministic recovery escalation, durable hard-budget blocking,
  conservative ambiguous-failure handling, two-phase provider replacement, and
  safe checkpoint rehydration in a fresh engine.
- Added bounded normalized-evidence and recovery-attempt events plus
  latest-checkpoint projection verification.
- Refactored `KernelActor` to be the sole owner of one `TaskEngine`, one
  `RuntimeStore`, and one `AgentPort`. There is no competing provider reader or
  second mutable store owner during an autonomous prompt.
- Routed autonomous-capable ACP sessions through `TaskEngine`: the initial prompt
  starts the durable task in the session's existing provider context; later input
  is journaled and steers the same live provider epoch; cancellation interrupts
  that exact epoch. Dropping the prompt caller does not cancel the durable task,
  and a prompt after terminal completion starts a new durable task rather than
  writing steering onto the completed lifecycle.
- Added exact approval mediation inside the engine-owned provider loop. Operation
  intent and `Started`, `ToolProposed`, the bound approval, and
  `ApprovalRequested` commit before provider resolution. Exact allow/deny codes
  are actor/session/turn bound and single-use. Denial fails the operation and
  durably blocks the task; full access records automatic dispatch authority before
  resolving the provider effect.
- Added task-oriented frontend updates and ACP rendering for status, epoch
  objective, checkpoint, context usage, compaction, recovery strategy, and
  completion clauses while preserving assistant, diff, and tool updates.
- Kept the legacy direct-turn path for adapters that do not opt into autonomous
  task driving; the Codex app-server adapter opts in.

## RED / GREEN evidence

1. The initial epoch contract failed to compile because `StartTask`, `TaskEngine`,
   and `TaskEngineUpdate` did not exist. After the seam and loop were implemented,
   the three-epoch and one-plan/one-work small-edit scenarios passed.
2. ACP update conversion initially failed on missing `KernelUpdate` task variants.
   The requested variants and JSON renderings now pass while existing update
   shapes remain covered.
3. Recovery persistence initially lacked `RecoveryAttemptRecorded`; recovery
   outcomes now append only after the corresponding recovery epoch finishes.
4. Atomic compaction initially failed with `TaskEngineError::Storage` because the
   context projection attempted a duplicate insert. It now verifies and reuses the
   exact atomically committed canonical package.
5. Fresh-engine restart initially lacked runtime rehydration. A new engine now
   resumes the durable safe checkpoint without another owner prompt.
6. Provider-budget exhaustion and ambiguous provider delivery initially left the
   task `Active`. They now durably transition to `Blocked`, and any started
   ambiguous operation becomes `Uncertain` without replay.
7. The first autonomous ACP routing test proved the legacy path was still used.
   The kernel now performs one planning request plus one work request and projects
   the durable task lifecycle through the frontend.
8. Live autonomous steering/cancellation tests initially could not reach the
   engine-owned provider read. The control pump now accepts commands while that
   one read is pending, journals steering before delivery, and interrupts the
   exact current epoch on cancel.
9. Exact approval initially had no mediation point in the engine loop. The ACP
   prompt now returns `WaitingForApproval`, an exact `/approve CODE` or
   `/deny CODE` resumes the same provider epoch, and replay is rejected.
10. Approval denial initially returned a provider failure while leaving the task
    `Active`. It now records failed evidence, appends `Blocked`, and returns a
    failed prompt outcome with a blocked task update.
11. Caller-disconnect coverage confirms that aborting the waiting frontend future
    leaves the durable task `Active` and resumable with zero provider interrupts;
    a later explicit cancel performs the one interrupt.
12. A second normal prompt after completion initially failed by attempting to steer
    the terminal task. Terminal session tasks are now excluded from resume routing,
    so the next prompt starts its own planning and work epochs.

## Final verification

All commands below were run after the final Rust changes.

```text
cargo fmt --all -- --check
PASS

cargo clippy --all-targets --all-features -- -D warnings
PASS; no warnings

cargo test --test epoch_engine_contract --test acp_kernel_contract \
  --test acp_server_contract --test agent_port_contract \
  --test codex_app_server_contract --test task_domain_contract \
  --test task_storage_contract --test context_engine_contract
PASS; 115 passed, 0 failed

git diff --check
PASS
```

Focused totals:

- Epoch engine/report/progress: 23 passed
- ACP kernel/server: 33 passed
- AgentPort/Codex app-server: 17 passed
- Task domain/storage: 22 passed
- Checkpoint/context: 20 passed

The full all-features test suite was not run because Task 9 is not a milestone;
the requested focused Task 4-8 compatibility gate and strict all-target,
all-feature static gates were run.

## Self-review

- Consequential intent and `Started` are durable before approval or automatic
  dispatch; ambiguous effects are never automatically replayed.
- Required clauses change only after Carl validates report claims against owned
  operation state and normalized terminal evidence.
- Checkpoints/context packages commit before continuation, compaction, recovery,
  or completion decisions. Provider replacement records loss and the returned
  binding before the next provider request.
- Engine controls share the actor-owned provider and store, remain responsive
  during event drain and approval wait, and keep caller lifetime separate from
  durable task lifetime.
- Contract, report, provider, and steering inputs remain bounded; external error
  surfaces use stable codes without provider payloads.
- Existing non-autonomous ACP contracts remain on the compatibility path and pass
  unchanged.
- The worktree contains no SECURITY, plan, or design-spec edits.

## Concerns

No known Task 9 correctness or integration gap remains.

## Fix Round 1/5

### Findings fixed

- Contract planning is now part of the durable task lifecycle. Task/context binding
  precedes the first provider request, planning and work requests are journaled
  with exact purpose/sequence/digest and provider epoch identity, planning usage
  counts toward context pressure, and restart reconstructs the exact accounting.
- Provider provenance now drives fail-closed terminalization. Definitely-not-applied
  reads receive one bounded retry; ambiguous failures after operation binding make
  the operation `Uncertain`; binding and resolution failures become `Failed` or
  `Uncertain` as provenance requires; every such path emits a typed `Blocked`
  update. Unsupported network/external effects are denied before blocking.
- Full-access effect content passes the secret filter before any frontend
  persistence or dispatch authority is recorded.
- Startup checkpoint recovery validates authoritative coverage before acting.
  Missing or invalid coverage blocks without replay, a committed completion
  checkpoint completes without another provider call, and a committed
  continuation starts exactly one new epoch.
- Recovery attempts now have a two-event durable lifecycle:
  `RecoveryAttemptStarted` binds epoch, strategy, and fingerprint before dispatch;
  `RecoveryAttemptRecorded` is appended only after the epoch reaches a terminal
  status. Pending recovery rehydrates with the exact epoch identity and outcome.
- Cancellation is safe-boundary aware. Operation-free planning/work cancellation
  interrupts and durably finishes the epoch before `Cancelled`; cancellation with
  a started operation records uncertain evidence and blocks. The reducer rejects
  forged cancellation across an unsafe boundary, and ACP reports the resulting
  terminal outcome truthfully.
- Provider, tool, and wall-clock budgets are hard dispatch gates. Every provider
  request and effect dispatch is checked immediately before the external action;
  pending reads race the wall deadline; breaches interrupt the exact epoch and
  either close an operation-free epoch safely or uncertainize active operations.
- Per-epoch transcript, diff, provider-event, engine-update count, and aggregate
  engine-update byte caps now apply across individually valid stream items.
  Overflow interrupts and durably blocks rather than leaving an active task.
- Durable ACP/Buzz integration now publishes deferred approval/task updates after
  execution, keeps exact Buzz reply context while approval is pending, accepts
  harmless context-start notifications without cross-context poisoning, and
  normalizes multiline owner requests into a valid bounded contract goal while
  retaining the original request for execution.
- The storage CAS race test now opens both SQLite stores before spawning workers,
  so a pre-barrier open cannot strand the coordinator under default parallel test
  scheduling.

### RED / GREEN evidence

- The new planning/accounting regressions initially showed provider work before a
  durable task/context binding, missing planning request/usage records, and restart
  request-count drift. The focused epoch tests now prove exact ordering, two
  bounded repair requests, conservative missing-usage accounting, and exact
  restart reconstruction.
- Provenance, secret, cancellation, and budget regressions initially left tasks
  active, omitted typed blocked updates, or allowed dispatch after a hard boundary.
  The focused epoch and ACP tests now cover every definitely-not-applied/possibly-
  applied branch, secret rejection before persistence, safe and unsafe cancellation,
  and provider/tool/wall breaches during planning and work.
- Checkpoint/recovery regressions initially repeated completed work or lost pending
  recovery identity. Five checkpoint scenarios and the recovery restart/outcome
  scenarios now pass with zero replay where completion is already committed and
  exactly one continuation epoch otherwise.
- Aggregate streaming regressions initially accepted collections whose individual
  events were valid but whose combined planning text, transcript, diff, event
  count, or frontend update bytes exceeded the epoch cap. All five aggregate-bound
  scenarios now interrupt and block.
- The default-parallel full suite exposed the pre-existing open-before-barrier
  scheduling hazard in `simultaneous_compare_and_transition_has_exactly_one_winner`.
  After opening both stores before spawn, its isolated regression passed: **1
  passed, 0 failed**.

### Aborted diagnostic runs

- An initial `cargo test --all-features` was manually interrupted with exit 130
  after the storage race test remained beyond its 60-second warning; all targets
  displayed before it had passed. The isolated test passed in 0.03 seconds,
  confirming a scheduling-dependent barrier hazard rather than a CAS failure.
- A second quiet default-parallel diagnostic encountered the same hazard and was
  manually stopped before the race-test fix. A briefly started serial diagnostic
  was also stopped on review direction and is not counted as verification.

### Final verification

All final gates below ran after the race-test and Task 9 source changes:

```text
cargo test --all-features --test subscription_run_storage_contract \
  simultaneous_compare_and_transition_has_exactly_one_winner -- --exact
PASS, exit 0: 1 passed, 0 failed

cargo test --all-features
PASS, exit 0: every unit, integration, contract, binary, and doc-test target
passed with 0 failures under default parallel scheduling

cargo fmt --all -- --check
PASS, exit 0

cargo clippy --all-targets --all-features -- -D warnings
PASS, exit 0, no warnings

git diff --check
PASS, exit 0
```

### Fix-round self-review and concerns

- Consequential operation dispatch still follows durable intent, `Started`, and
  authority recording; no ambiguous action is replayed automatically.
- Provider-owned prose never proves completion, checkpoint coverage, recovery
  success, or cancellation safety; each decision uses Carl-owned durable state.
- Bounded/redacted frontend surfaces retain no raw secret-bearing effect content.
- No plan, design specification, or security policy was edited.
- No Critical or Important Task 9 finding remains. Process-startup invocation of
  durable task discovery/resumption remains the explicit Task 10 integration
  boundary; Task 9's discovery and storage behavior is covered independently.

## Fix Round 2/5

### Findings fixed

- Every planning provider read, validation, reported-failure, unexpected-event,
  planning-control, and planning-start failure now interrupts where possible,
  finishes the logical epoch, durably blocks the task, emits `TaskStatus::Blocked`,
  and returns `TaskEngineErrorCode::Blocked` instead of leaking a raw provider
  error.
- Work-event read, validation, sequencing, catch-all, queued-steering, and soft
  boundary steering failures now close every `Started` operation according to
  provenance, finish the active epoch, and take the same typed blocked path.
  `Uncertain` may close a provider epoch but remains unresolved for checkpoint and
  completion safety.
- The hard wall deadline now covers approval-notice delivery, owner approval wait,
  the final pre-Allow checks, and `resolve_effect`. All pending awaits race the
  remaining deadline. A pre-dispatch expiry closes the current operation `Failed`;
  an in-flight Allow resolution closes it `Uncertain`; both interrupt and close the
  work epoch before durable blocking.
- A definitely-not-applied provider start for a pending recovery epoch now finishes
  that exact epoch, appends `RecoveryAttemptRecorded` with `Failed`, clears the
  pending identity, and blocks. Restart therefore cannot reinsert the same
  `task_epochs.id` and observes the truthful terminal attempt outcome.
- Authoritative usage updates no longer discard conservative accounting for later
  assistant or diff bytes. Terminal planning/work flushes merge the accumulated
  post-update estimate into a new durable `UsageObserved` value before compaction.
- Approval-notice failure, approval control-channel closure, invalid approval
  validation, planning approval control, and general work-control closure now close
  operations/epochs and return the typed blocked outcome. Cancellation retains one
  provider interrupt while still closing an uncertain epoch durably.

### RED evidence

1. Provider/safe-closure cluster:

   `cargo test --test epoch_engine_contract faults_close -- --nocapture`

   **FAIL, exit 101: 0 passed, 2 failed.** Planning next-event/validation/
   unexpected failures and work sequencing/catch-all/soft-steer failures returned
   `Provider` instead of `Blocked`.

2. Post-usage accounting:

   `cargo test --test epoch_engine_contract post_usage_assistant_and_diff_bytes_are_merged_before_terminal_compaction -- --exact --nocapture`

   **FAIL, exit 101.** The final durable total remained below the hand-derived
   105,096-token lower bound because terminal flush suppressed 4,096 diff bytes and
   the later assistant report after an authoritative 101,000-token update.

3. Recovery identity:

   `cargo test --test epoch_engine_contract definitely_not_applied_recovery_start_is_recorded_failed_and_restart_safe -- --exact --nocapture`

   **FAIL, exit 101.** The first failed recovery start returned `Provider` rather
   than recording the attempt and returning `Blocked`; a subsequent run could
   reuse the finished epoch identity.

4. Hard wall during effect resolution:

   `cargo test --test epoch_engine_contract hard_wall_budget_covers_pending_allow_resolution_and_closes_the_epoch -- --exact --nocapture`

   **FAIL, exit 101.** The outer two-second diagnostic timed out because the
   one-second task deadline was not polled while `resolve_effect(Allow)` was
   pending.

5. Approval/control harness:

   The first internal-module behavioral run reported **1 passed, 3 failed**: the
   deadline and notice paths left a definitely-not-dispatched operation
   `Uncertain`, and the first control-close fixture could strand its waiter. The
   fixture was then corrected to bind a real frontend session and close controls
   only after receiving the approval notice; the production fix makes all four
   owner-visible behaviors pass.

### GREEN evidence

- Provider/safe-closure cluster: **2 passed, 0 failed**, plus the ambiguous-read
  active-epoch closure regression **1 passed, 0 failed**.
- Post-usage accounting: **1 passed, 0 failed**; the merged durable total crosses
  the compaction threshold and compaction runs once.
- Recovery start/restart identity: **1 passed, 0 failed** with one exact
  `EpochStarted`, one matching failed recovery outcome, and typed Blocked after
  restart.
- Pending Allow resolution deadline: **1 passed, 0 failed** in 1.04 seconds with
  one interrupt, `Uncertain`, and no active epoch.
- Internal approval/control contract:

  `cargo test --lib 'runtime::task::engine::tests::' -- --nocapture`

  **PASS, exit 0: 4 passed, 0 failed, 47 filtered.**
- Focused cross-cutting compatibility:

  `cargo test --test epoch_engine_contract --test acp_kernel_contract --test task_domain_contract`

  **PASS, exit 0: ACP kernel 32 passed; epoch engine 53 passed; task domain 14
  passed; 0 failures.** An earlier focused run exposed a double cancellation
  interrupt in two ACP tests; exact reruns passed after epoch closure was moved
  into the already-interrupted cancellation path.

### Diagnostics and static gates

- An early approval RED fixture left process group 43201 after its waiter became
  stranded. It was manually interrupted, the fixture was made timeout-safe, and a
  process-table check immediately before the full gate confirmed no Cargo/test
  process remained. This diagnostic orphan is not counted as verification.
- The first strict Clippy pass failed with one test-only `enum_variant_names`
  diagnostic. The fixture variants were renamed and the complete static gate was
  rerun.

```text
cargo fmt --all -- --check
PASS, exit 0

cargo clippy --all-targets --all-features -- -D warnings
PASS, exit 0, no warnings

cargo test --all-features
PASS, exit 0: every unit, integration, contract, binary, and doc-test target
passed with 0 failures under default parallel scheduling

git diff --check
PASS, exit 0
```

### Fix-round self-review and concerns

- A logical epoch can close with durable `Uncertain` operations so a provider is
  never represented as still running after interruption, but checkpoints and
  completion continue to reject those unresolved operations.
- Pre-Allow timeout/failure records `Failed` only before provider dispatch;
  ambiguous resolution and post-dispatch failures record `Uncertain`.
- Recovery attempt identity is never reused after an `EpochFinished`, and its
  terminal event agrees with the failed provider start.
- No plan, design specification, or security policy was edited. No Important
  residual from this round remains; process-startup discovery/resumption stays the
  explicit Task 10 boundary.

## Fix Round 3/5

### Findings fixed

- A terminal provider stream with a malformed `<carl-epoch-report>` no longer
  returns raw `Verification` while leaving the logical epoch active. The engine
  reconciles any remaining `Started` operation as `Uncertain`, finishes the exact
  epoch, durably blocks, emits `TaskStatus::Blocked`, and returns typed `Blocked`.
- `Unsupported` soft-boundary steering is now treated as a rejected boundary
  request. The caller performs the single provider interrupt, closes in-flight
  work as `Uncertain`, finishes the epoch, durably blocks, and returns typed
  `Blocked` instead of accepting the interrupt as successful steering.
- A possibly-applied recovery epoch start no longer records the Carl-selected
  strategy as definitely `Failed`. Its durable `RecoveryAttemptStarted` remains
  pending under a blocked task after the uncertain epoch is finished; restart
  performs no provider dispatch and cannot reuse the epoch identity. The
  definitely-not-applied branch still records the terminal `Failed` outcome.
- An invalid or expired remote approval that is normalized into durable task
  blocking now acknowledges the same typed `Blocked` result. The control caller,
  task projection, task update stream, and frontend-bound journal therefore agree
  instead of exposing `InvalidTask` or `Storage` after the task is blocked.

### RED evidence

1. Malformed terminal work report:

   `cargo test --test epoch_engine_contract malformed_terminal_work_report_closes_the_epoch_and_blocks_restart -- --exact --nocapture`

   **FAIL, exit 101:** the engine returned `Verification` instead of `Blocked` and
   had not executed the asserted safe terminal/restart path.

2. Unsupported soft-boundary capability with one started operation:

   `cargo test --test epoch_engine_contract unsupported_soft_boundary_interrupt_closes_started_work_and_returns_blocked -- --exact --nocapture`

   **FAIL, exit 101:** the three-second guard elapsed because the successful
   fallback interrupt was returned as `Ok` and the engine resumed waiting on the
   stranded provider stream.

3. Possibly-applied recovery start provenance:

   `cargo test --test epoch_engine_contract possibly_applied_recovery_start_remains_pending_and_cannot_be_retried_after_restart -- --exact --nocapture`

   **FAIL, exit 101:** the event journal contained a terminal
   `RecoveryAttemptRecorded { outcome: Failed }` for an uncertain dispatch.

4. Approval acknowledgement consistency:

   `cargo test --lib 'runtime::task::engine::tests::invalid_approval_acknowledges_the_same_typed_blocked_outcome_as_the_task' -- --exact --nocapture`

   **FAIL, exit 101:** the acknowledgement exposed `Storage` while the task result
   and durable projection were `Blocked`.

### GREEN evidence

- Each of the four exact commands above passed independently: **1 passed, 0
  failed** for each regression.
- The protected definitely-not-applied recovery behavior passed independently:

  `cargo test --test epoch_engine_contract definitely_not_applied_recovery_start_is_recorded_failed_and_restart_safe -- --exact --nocapture`

  **PASS, exit 0: 1 passed, 0 failed.**
- All internal approval/control engine regressions passed:

  `cargo test --lib 'runtime::task::engine::tests::' -- --nocapture`

  **PASS, exit 0: 5 passed, 0 failed, 47 filtered.**
- Focused cross-cutting compatibility passed:

  `cargo test --test epoch_engine_contract --test acp_kernel_contract --test task_domain_contract`

  **PASS, exit 0: ACP kernel 32 passed; epoch engine 56 passed; task domain 14
  passed; 0 failures.**

### Static gates

- The first format check reported only mechanical wrapping in new test code.
  `cargo fmt --all` applied it, after which the complete static command passed:

```text
cargo fmt --all -- --check
PASS, exit 0

cargo clippy --all-targets --all-features -- -D warnings
PASS, exit 0, no warnings

git diff --check
PASS, exit 0
```

Per round direction, no full-suite command was run. The root task will run the one
final default-parallel all-features gate only after independent review is clean.

### Fix-round self-review and concerns

- A malformed terminal report cannot prove checkpoint or completion claims; the
  durable outcome is therefore blocked with no active epoch and no started work.
- The unsupported-boundary path issues exactly one interrupt and never treats an
  interrupt acknowledgement as acceptance of the requested steering capability.
- Possibly-applied recovery dispatch remains explicitly unresolved rather than
  consuming the strategy as a proven failure. Because the task is durably blocked,
  restart cannot dispatch or reuse that recovery epoch.
- Approval acknowledgement normalization happens only on the same failure path
  that durably closes the pre-dispatch operation and blocks the task. Successful
  approvals retain their existing acknowledgement behavior.
- No plan, design specification, security policy, or Task 10 startup boundary was
  changed.
