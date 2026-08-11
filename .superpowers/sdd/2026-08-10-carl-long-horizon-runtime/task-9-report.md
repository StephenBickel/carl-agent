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
