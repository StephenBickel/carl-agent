# Carl Subscription Run Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:test-driven-development` for every behavior change and
> `superpowers:verification-before-completion` before every commit, push, or merge.

**Goal:** Ship a real `carl run` command that completes one existing-file coding task
through the user's ChatGPT subscription, independently verifies the exact candidate,
requires two bound approvals, promotes only from a sealed, rehashed artifact, persists
the whole lifecycle, and replays the terminal result.

**Architecture:** Keep the official Codex CLI behind Carl's existing supervised
delegate boundary. Persist a run before creating artifacts. Build a sealed,
content-addressed sanitized baseline outside the writable work stage, rehash it before
every use, turn the resulting one-file replacement into a content-addressed proposal,
verify that proposal in a freshly reconstructed workspace, then promote it through a
stale-safe exact-replacement boundary. A durable `SubscriptionRunEngine` coordinates
these capabilities and the CLI only renders its persisted result.

**Tech stack:** Rust 2024, `cap-std`, SHA-256, SQLite WAL, Tokio process supervision,
Clap, deterministic fake Codex fixtures, official `codex-cli 0.136.0`, GitHub Actions
on Linux, macOS, and Windows.

## Global invariants

- Carl never reads or accepts an OAuth access token. Subscription access remains owned
  by the official Codex CLI and its operating-system keyring.
- Codex never receives the live workspace path or a writable live-workspace
  capability.
- No OpenAI API key is required or silently used. The run environment drops
  `OPENAI_API_KEY`, `CODEX_API_KEY`, and all non-allowlisted variables.
- The first slice supports exactly one changed existing regular UTF-8 file. Creation,
  deletion, rename, link, binary, protected-path, secret-bearing, and multi-file
  proposals fail closed.
- The mutable agent stage is never the source of promotion bytes. Baseline and
  proposal bytes live in an owner-only content-addressed object store outside both
  mutable trees, are made read-only where the platform supports it, retain held
  identity, and are reopened and rehashed before every use. Carl does not claim this
  defends against an attacker who already controls the same OS account.
- A Codex claim that tests passed is untrusted evidence. Only Carl's independent
  verifier can authorize a promotion request.
- Delegate approval and promotion approval are separate, exact, expiring, actor/run
  bound, and single-use. The first approval binds both the delegate invocation and the
  exact user-supplied verification specification, so the foreground flow has exactly
  two prompts.
- Promotion revalidates the live workspace and target immediately before replacement.
  A stale result spends the approval and is never retried automatically.
- Every state transition is durable before it is rendered. Restart marks an abandoned
  nonterminal run interrupted and never resumes execution or mutation automatically.
- Each implementation checkpoint below is a separate pull request, runs the full local
  quality gate, passes all required GitHub checks, and merges before its dependent
  checkpoint starts.

## Checkpoint 1: Make stage containment truthful on Windows

**Branch:** `codex/carl-stage-containment`

**Files:**

- Modify: `src/sidecar/mod.rs`
- Modify: `src/staging/builder.rs`
- Modify: `tests/delegate_stage_contract.rs`
- Modify: `docs/security.md`
- Create: `docs/superpowers/plans/2026-07-29-carl-subscription-run-engine.md`

- [ ] Write a Windows-only contract that verifies the stage parent, generated stage
  root, nested directory, and copied file all satisfy Carl's existing private DACL
  policy.
- [ ] Write a Windows-only rejection contract for an unsafe parent DACL and a
  reparse-point source entry.
- [ ] Verify the new test fails because staging currently treats all non-Unix
  permissions as owner-only and performs no Windows DACL validation.
- [ ] Reuse the reviewed `windows_security` implementation in `sidecar` through narrow
  crate-private path/handle APIs; do not duplicate its SID, ACE, or `AccessCheck`
  implementation.
- [ ] Require a verified private parent before preparing a stage and verify every
  generated directory and file after capability-relative creation. On Windows, apply
  a protected current-user descriptor atomically at creation; do not trust inherited
  ACLs. Remove the unconditional non-Unix owner-only success path.
- [ ] Reject Windows reparse points at both roots and open every recursive source
  directory through a no-follow held-capability operation before traversal, closing
  the check/reopen junction race.
- [ ] Keep unsupported platforms fail-closed rather than claiming owner-only
  containment.
- [ ] Run the focused stage contract, the complete local quality gate, and the
  Windows GitHub job before merge.

## Checkpoint 2: Add the durable subscription-run spine

**Branch:** `codex/carl-subscription-run-storage`

**Files:**

- Create: `src/runtime/subscription/mod.rs`
- Create: `src/runtime/subscription/types.rs`
- Modify: `src/runtime/mod.rs`
- Modify: `src/events.rs`
- Create: `migrations/0003_subscription_runs.sql`
- Modify: `src/storage/schema.rs`
- Modify: `src/storage/repository.rs`
- Modify: `src/storage/mod.rs`
- Modify: `tests/domain_contract.rs`
- Modify: `tests/storage_contract.rs`
- Create: `tests/subscription_run_storage_contract.rs`

- [ ] Define validated `RunId`, `ArtifactId`, `VerificationId`, trust labels, resolved
  model/effort values and provenance, typed failure codes, and the closed run states:
  `prepared`, `awaiting_delegate_approval`, `running`, `inspecting`, `verifying`,
  `awaiting_promotion_approval`, `promoted`, `completed_no_changes`, `failed`,
  `cancelled`, and `interrupted`.
- [ ] Persist a run projection, ordered state transitions, resolved per-run and
  session-default delegate settings, and configuration provenance. Per-run overrides
  must not mutate persisted session defaults. Provider-reported resolved values must
  be stored explicitly or as `not_reported`, never inferred.
- [ ] Write transactional contracts first for create, compare-and-transition,
  invalid transitions, append ordering, reopen/replay equivalence, and automatic
  nonterminal-to-interrupted recovery without retry.
- [ ] Add injected-write failures before and during each transition and prove no
  transition is rendered or acted on before its projection and event commit.
- [ ] Preserve backward decoding of existing schema-v1 events. Do not merely bump the
  one accepted event version; add explicit v1 compatibility fixtures and prove an
  existing database reopens while new run events decode.
- [ ] Advance `tests/storage_contract.rs` from two to three migrations and move its
  synthetic future schema from version 3 to version 4. Every later migration must
  advance this fixture again.
- [ ] Keep this checkpoint process-free and mutation-free; the README must continue to
  state that `carl run` is unavailable.
- [ ] Run focused domain/storage contracts, the complete local quality gate, and all
  GitHub jobs.

## Checkpoint 3: Preserve a sealed baseline and inspect one-file proposals

**Branch:** `codex/carl-proposal-artifacts`

**Files:**

- Modify: `src/staging/mod.rs`
- Modify: `src/staging/builder.rs`
- Create: `src/artifacts/mod.rs`
- Create: `src/artifacts/store.rs`
- Create: `src/staging/proposal.rs`
- Create: `migrations/0004_proposal_artifacts.sql`
- Modify: `src/storage/schema.rs`
- Modify: `src/storage/repository.rs`
- Modify: `tests/storage_contract.rs`
- Create: `tests/proposal_contract.rs`
- Modify: `docs/architecture.md`
- Modify: `docs/security.md`

- [ ] Write a failing contract proving one preparation creates two disjoint private
  trees: a sealed baseline object set and a writable work stage with identical initial
  content manifests.
- [ ] Keep deterministic content-manifest fields separate from platform-specific live
  identity preconditions and owner mode. Never hash inode or Windows file IDs into a
  cross-copy/cross-platform content digest.
- [ ] Make only the work-stage capability available to `ExecutionWorkspace`; expose no
  ambient baseline path to delegate code.
- [ ] Write a failing happy-path inspector contract: mutate one staged existing UTF-8
  file, inspect without running code, and produce a literal deterministic artifact ID,
  before hash, after hash, payload hash, and exact payload.
- [ ] Write the rejection matrix first: create, delete, rename, second changed file,
  symlink/reparse point, hard link, binary, protected path, oversize, metadata-only
  change, generated secret, and path race.
- [ ] Persist baseline and proposal bytes outside the mutable stage using owner-only
  create-new/flush/content-addressed semantics. Make objects read-only where
  enforceable, retain their opened identity, and reopen plus rehash before inspection,
  reconstruction, verification, and promotion.
- [ ] Persist proposal metadata and object references under migration 4. Stage cleanup
  and process restart must not delete or invalidate a referenced artifact; terminal
  retention/cleanup must be deterministic and tested.
- [ ] Advance the future-schema fixture to version 5 and prove migrations 1–4 reopen.
- [ ] Expose only an inert `ExactReplacementProposal`; the artifact store has no live
  workspace apply method.
- [ ] Ensure proposal errors contain path and rule identifiers only, never payload or
  secret bytes.
- [ ] Run focused contracts, the full local quality gate, and all GitHub jobs.

## Checkpoint 4: Add an independent bounded verifier

**Branch:** `codex/carl-verification-runner`

**Files:**

- Create: `src/verification.rs`
- Modify: `src/lib.rs`
- Modify: `src/sidecar/mod.rs`
- Create: `src/sidecar/bounded_process.rs`
- Create: `migrations/0005_verifications.sql`
- Modify: `src/storage/schema.rs`
- Modify: `src/storage/repository.rs`
- Modify: `tests/storage_contract.rs`
- Create: `tests/verification_contract.rs`
- Modify: `docs/security.md`

- [ ] Define a bounded exact-argv `VerificationRequest`; never accept shell text.
- [ ] Reconstruct a fresh private candidate workspace from the sealed baseline and
  proposal artifact. Do not reuse the agent-mutated stage.
- [ ] Write failing contracts for exact argv, closed/allowlisted environment, candidate
  cwd, successful result digest, output cap, timeout, cancellation, nonzero exit,
  malformed executable, descendant reaping, and source mutation during verification.
- [ ] A verifier or concurrent actor that mutates the reconstructed candidate
  invalidates the evidence and returns `verification_failed`; it can never yield a
  `VerifiedProposal`.
- [ ] Extract a provider-neutral bounded child-process supervisor from the existing
  Unix process-group/Windows Job Object implementation. The verifier must reuse that
  reviewed reaping boundary rather than the provider-home/JSONL-specific process type
  or a second ad hoc implementation.
- [ ] Treat verification output as bounded diagnostic evidence and run it through the
  secret filter before persistence or rendering.
- [ ] Bind successful evidence to candidate manifest digest, proposal artifact ID,
  executable identity, exact argv, environment profile, exit code, and result digest.
- [ ] Persist verification request/result metadata under migration 5, advance the
  future-schema fixture to version 6, and prove migrations 1–5 reopen.
- [ ] Document that native repository verification executes untrusted code and is not
  an OS sandbox until a reviewed platform sandbox profile is implemented. Bind the
  exact verifier into the first delegate approval and show it in that prompt; do not
  introduce a third foreground approval.
- [ ] Run focused contracts, the full local quality gate, and all GitHub jobs.

## Checkpoint 5: Add exact promotion approval and stale-safe replacement

**Branch:** `codex/carl-safe-promotion`

**Files:**

- Create: `src/promotion.rs`
- Modify: `src/policy/capability.rs`
- Modify: `src/policy/mod.rs`
- Create: `migrations/0006_promotions.sql`
- Modify: `src/storage/schema.rs`
- Modify: `src/storage/repository.rs`
- Modify: `tests/storage_contract.rs`
- Create: `tests/promotion_contract.rs`
- Modify: `tests/subscription_run_storage_contract.rs`

- [ ] Define a normalized promotion request binding run ID, actor, workspace identity,
  baseline and proposal digests, exact path/before/after/payload hashes, verification
  request/result digests, and expiration.
- [ ] Add an idempotent approval action key with a database uniqueness constraint so a
  duplicated callback cannot create two consumable approvals.
- [ ] Persist promotion requests, approval action keys, mutation journal entries, and
  per-path results under migration 6. Reopening must replay the same projection;
  advance the future-schema fixture to version 7.
- [ ] Write the happy-path promotion test first: the live file remains byte-identical
  until approval consumption, then one exact atomic replacement succeeds and read-back
  matches the approved hash.
- [ ] Write stale/race tests first: changed target, changed unrelated eligible file,
  symlink/reparse swap, hard-link swap, concurrent prepared promotions, approval replay,
  crash after approval consumption, crash after `promotion_started`, and crash after
  rename before terminal persistence.
- [ ] Bind successful verification to the complete eligible baseline manifest for the
  one-file slice. A changed unrelated eligible file invalidates that evidence and
  fails `stale_workspace`; it is not silently ignored.
- [ ] Serialize mutations by stable workspace identity, consume before mutation, create
  a same-parent owner-only temporary file through the held directory capability,
  preserve the approved mode, flush, atomically replace, sync where supported, and
  verify read-back.
- [ ] Never automatically retry a consumed or interrupted mutation. Reconcile by hashes
  and persist a review-required outcome.
- [ ] Run focused contracts, migration/reopen tests, the full local quality gate, and
  all GitHub jobs.

## Checkpoint 6: Hold Codex home exclusivity for the complete delegate lifecycle

**Branch:** `codex/carl-codex-run-capability`

**Files:**

- Modify: `src/sidecar/mod.rs`
- Modify: `src/sidecar/exec_jsonl.rs`
- Modify: `src/auth/codex.rs`
- Modify: `src/delegates/codex/mod.rs`
- Modify: `tests/codex_auth_contract.rs`
- Modify: `tests/codex_exec_contract.rs`

- [ ] Write a failing contract showing auth preflight and execution can use the same
  Carl-isolated provider-home identity while execution is bound to the sanitized work
  stage, not the live workspace.
- [ ] Add a consuming `CodexAuth::shutdown_into_home` handoff that returns the same
  provider-home capability only after app-server and descendants are reaped. Add a
  consuming workspace rebind that preserves the same held home/temp identities and
  lock while binding a fresh sanitized `ExecutionWorkspace`.
- [ ] Acquire the provider-home operation lock before writing `config.toml` and retain
  it through spawn, event drain, cancellation, descendant reap, and terminal status.
- [ ] Move exec configuration writes into the async locked start boundary. Transfer
  the operation guard to the child supervisor so dropping an auth/exec wrapper starts
  cleanup but cannot release the lock until detached bounded reaping finishes.
- [ ] Write a barrier-controlled concurrency test proving auth or another run cannot
  overwrite provider configuration while a delegate owns the home.
- [ ] Add failure-release contracts for version mismatch, spawn/stdin failure,
  malformed JSONL, auth initialization failure, and wrapper drop; a later operation
  may acquire the lock only after every spawned child is reaped.
- [ ] Keep version pinning, keyring-only credential storage, `workspace-write`,
  command-network denial, exact model/effort, environment closure, and the already
  corrected global approval-flag ordering in the locked launch regression contract.
- [ ] Add an opt-in installed-binary parser/auth smoke that never sends a task.
- [ ] Run focused contracts, the full local quality gate, and all GitHub jobs.

## Checkpoint 7: Implement the durable `SubscriptionRunEngine`

**Branch:** `codex/carl-subscription-run-engine`

**Files:**

- Create: `src/runtime/subscription/engine.rs`
- Create: `src/runtime/subscription/ports.rs`
- Modify: `src/runtime/subscription/mod.rs`
- Modify: `src/runtime/mod.rs`
- Modify: `src/events.rs`
- Modify: `src/storage/repository.rs`
- Create: `tests/subscription_run_engine_contract.rs`

- [ ] Write a failing process-boundary acceptance contract using a fake Codex binary:
  prepare, delegate approval, execute, inspect, independently verify, promotion
  approval, promote, persist, reopen, and replay.
- [ ] Assert the live workspace remains unchanged through delegate completion and
  verification, and changes only after the exact promotion approval is consumed.
- [ ] Persist every transition before exposing it and label all normalized Codex
  events as untrusted provider evidence.
- [ ] Add one whole-run deadline and one cancellation token owned by the coordinator;
  cancellation must reap the complete child tree and block inspection/promotion.
- [ ] Add aggregate budgets for provider event count, total normalized provider bytes,
  total persisted agent-message bytes, verifier output, and total run artifacts. Test
  an endless stream of individually valid small events.
- [ ] Add crash/reopen coverage for every nonterminal state; reopening marks it
  interrupted without retrying delegate execution, verification, or promotion.
- [ ] Inject storage failure immediately before launch, after delegate terminal,
  before proposal persistence, before verification, before either approval
  consumption, and after promotion read-back. Specify and assert whether the safe
  outcome is cancellation, blocked execution, or hash-only reconciliation.
- [ ] Add a table-driven typed outcome matrix for authentication required (including
  the exact `carl auth login openai` recovery command), subscription unavailable,
  incompatible CLI, invalid model/effort, start/protocol/budget failure,
  cancellation/interruption, stage/proposal/verification rejection, stale workspace,
  and promotion failure. No outcome may fall back to API-key billing.
- [ ] Redact and bound task text, provider output, verifier output, errors, artifacts,
  and terminal summaries before storage.
- [ ] Run focused contracts, all storage replay tests, the full local quality gate, and
  all GitHub jobs.

## Checkpoint 8: Expose and complete `carl run`

**Branch:** `codex/carl-run-cli`

**Files:**

- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Modify: `tests/cli_contract.rs`
- Modify: `tests/auth_cli_contract.rs`
- Create: `tests/run_cli_contract.rs`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/adr/0004-subscription-authentication-through-provider-sidecars.md`
- Modify: `docs/architecture.md`
- Modify: `docs/configuration.md`
- Modify: `docs/security.md`
- Modify: `tests/docs_contract.rs`

- [ ] Add the exact command shape:

  ```text
  carl run [--model MODEL] [--effort LEVEL] \
    --verify-program PROGRAM [--verify-arg ARG]... TASK
  ```

- [ ] Require the canonical current directory as workspace and a verified foreground
  terminal for the two bounded approval prompts. Do not add `--yes`.
- [ ] Keep stdout to one newline-terminated safe JSON result. Send sanitized progress,
  escaped proposal details, prompts, and recovery commands to stderr.
- [ ] Map exit codes: `0` promoted/verified no-change, `1` typed run failure or declined
  approval, `2` usage, `130` cancellation after durable cancellation and child reap.
- [ ] Write the deterministic CLI contract first with a fake Codex executable and real
  verifier process. Assert exact state order, two approvals, one promoted file, replay,
  no secret output, and no live mutation before promotion.
- [ ] Update documentation only after the deterministic acceptance contract passes.
- [ ] Replace the documentation contract's whitespace splitter with quote-aware
  command parsing before adding `carl run "Fix the failing test"` examples.
- [ ] Document that the CLI exposes per-run model/effort overrides and records session
  defaults/provenance, while a general settings-management UI remains outside this
  narrow milestone.
- [ ] Run the complete local quality gate and all required GitHub checks, then merge.

## Checkpoint 9: Complete one real subscription-backed terminal task and publish evidence

**Branch:** `codex/carl-live-acceptance-evidence`

This checkpoint starts with a non-mutating local acceptance run on merged `main`.
Only after it succeeds may a separate documentation-only PR publish a sanitized
transcript. The live smoke remains opt-in and never runs in credential-free CI.

- [ ] Sync merged `main` and create a disposable one-file Rust fixture outside Carl's
  own repository.
- [ ] Confirm `codex --version` is the pinned compatible release and `codex login
  status` reports ChatGPT login.
- [ ] Remove API-key variables from the invocation environment and record only their
  absence, never values.
- [ ] Run `carl run` in the Codex terminal against a narrowly worded failing-test task
  with explicit model and effort.
- [ ] Confirm the live fixture is unchanged before the promotion prompt, approve the
  exact replacement, and confirm the independent verifier and fixture tests pass.
- [ ] Reopen Carl's durable store and confirm the replayed terminal projection matches
  the command result.
- [ ] Run the full quality gate once more on merged `main`:

  ```bash
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo test --workspace --all-targets --all-features --locked
  cargo test --doc --all-features --locked
  cargo deny check
  git diff --check
  ```

- [ ] Verify required GitHub checks are green on the final merged commit.
- [ ] Add a concise acceptance record under `docs/acceptance/` containing commands,
  redacted IDs, hashes, and pass/fail evidence only. Do not persist the personal task
  text, provider output, account data, credentials, or filesystem paths.
- [ ] Run the documentation and full quality gates, open the documentation-only PR,
  wait for all required GitHub checks, and merge it.
