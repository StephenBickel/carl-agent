# Carl Subscription-First Codex Delegate

- Status: Approved for implementation planning
- Date: 2026-07-27
- Decision owner: Stephen Bickel

## Purpose

Carl's first live coding path will use an eligible ChatGPT subscription through the
official Codex CLI. It will not require an OpenAI Platform API key, accept raw
subscription credentials, or reinterpret ChatGPT OAuth as API access.

The first public milestone is intentionally narrow:

```text
carl run "Fix the failing test"
```

Carl creates a durable run, invokes a supervised Codex worker in an isolated staging
workspace, records its streamed activity, independently verifies its proposed changes,
and asks the owner to approve an exact promotion into the live workspace.

This milestone demonstrates harness engineering rather than provider wrapping. Carl
owns execution state, isolation, policy, approvals, cancellation, artifacts,
verification, and replay. Codex owns its model interaction, inner coding loop, and
subscription credentials.

## Relationship to existing decisions

This design preserves the repository's existing principles:

- subscription authentication remains provider-owned;
- Carl never reads, copies, logs, or forwards OAuth bearer or refresh tokens;
- subscription agents are not native `Provider` implementations;
- live workspace mutations require Carl policy, bound approval, stale-state checking,
  and verification;
- CI remains deterministic and credential-free;
- Phase 3 policy, approval, sandbox, secret-filtering, and external-agent capability
  foundations remain prerequisites for live delegate execution.

This design changes two delegate decisions. The top-tier harness design, ADR 0004, and
the existing subscription-delegate implementation plan make delegates tools selected
by a native model loop and select `codex mcp-server` for Codex. Requiring a native
outer model would also require an API key, so the first subscription-only path instead
enters the kernel through a top-level `SubscriptionRunEngine`. It shares Carl's normal
storage, policy, approval, staging, verification, and promotion boundaries but does
not implement the native `Provider` trait.

The Codex implementation will use stable `codex exec --json` because it provides a
documented non-interactive coding-agent surface, a machine-readable JSONL event stream,
explicit sandbox settings, structured outputs, and reuse of saved ChatGPT
authentication.

The implementation must update those documents before claiming the milestone is
complete. Grok remains a later delegate using its provider-supported protocol and the
same outer Carl contracts.

## Goals

- Complete one real repository fix using ChatGPT subscription access and no OpenAI API
  key.
- Keep the model and reasoning-effort choice explicit, configurable, and replayable.
- Prevent Codex from receiving a writable handle or path to the live workspace.
- Preserve enough normalized evidence to explain what happened without treating
  provider claims as Carl verification.
- Make cancellation, crashes, stale state, malformed provider output, and failed
  verification ordinary typed outcomes.
- Prove the complete flow with deterministic fake-sidecar tests on every supported CI
  platform.

## Non-goals

- A raw OpenAI model-sampling adapter backed by ChatGPT OAuth.
- Direct access to Codex credential files or operating-system keyring entries.
- Grok execution in this milestone.
- Telegram, TUI, session branching, compaction, or multi-agent orchestration.
- Automatic model routing.
- Transparent failover to an API key or another model.
- Creating, deleting, or renaming files in the first delegate slice.
- Treating Codex-reported tests as trusted verification.
- Running project hooks, plugins, MCP servers, skills, or user Codex configuration.

## Chosen integration

### Considered approaches

1. `codex exec --json`: selected. It is stable, non-interactive, produces JSONL, allows
   explicit sandbox and approval settings, and reuses saved CLI authentication.
2. `codex mcp-server`: remains viable for later composition but adds an MCP lifecycle
   and tool-schema dependency without improving the first subscription-backed run.
3. `codex app-server`: offers richer thread control but is experimental and creates a
   larger protocol surface than this milestone needs.

### Trust boundary

```text
live workspace
      |
      | capability-safe reads
      v
sanitized staging workspace -----> supervised codex exec
      |                                  |
      | staged diff                      | JSONL events
      v                                  v
proposal artifact <---------- Carl event normalizer
      |
      +--> independent verification
      |
      +--> exact owner approval
      |
      +--> stale-state check --> native patch promotion
```

Earlier discussion used the phrase "staging worktree." The implementation will use a
capability-built staging directory without `.git` metadata instead. A Git worktree
contains metadata that points back into the live repository and would weaken the
claimed isolation boundary. The user-facing concept remains a disposable staging
workspace.

## Components

### Subscription run coordinator

The coordinator owns the outer state machine, budgets, deadlines, cancellation token,
and durable transitions. It depends on interfaces for storage, staging, delegate
execution, verification, policy, approval, and promotion. It does not parse Codex wire
events or manipulate files directly.

The run states are:

```text
prepared -> awaiting_delegate_approval -> running -> inspecting -> verifying
                                                         |
                                                         v
                                               awaiting_promotion_approval
                                                         |
                                                         v
                                                      promoted

Any non-terminal state may end as failed, cancelled, or interrupted where applicable.
```

Every state transition is committed before a frontend exposes it. A process exit and
its final normalized events are persisted atomically where the storage boundary
permits it.

### Sanitized stage builder

The stage builder creates an owner-only temporary directory outside the live
workspace and provider homes. It copies only bounded, regular UTF-8 files through open
directory capabilities and records a deterministic manifest containing relative path,
size, identity preconditions, and SHA-256.

The stage excludes:

- `.git`, `.carl`, `.codex`, `.grok`, `.claude`, `.cursor`, and provider configuration;
- environment files, credentials, keys, cookies, sockets, devices, FIFOs, binaries,
  symlinks, and suspicious hard links;
- hooks, plugins, MCP configuration, skills, commands, and compatibility instruction
  files;
- files rejected by the Phase 3 secret filter;
- files or aggregate stages above configured limits.

Codex receives only the stage path. It never receives an ambient path or handle for the
live workspace.

### Codex exec adapter

The adapter launches a version-compatible Codex executable with:

- the Carl-managed `CODEX_HOME` used by the existing authentication boundary;
- the staging directory as the only working directory;
- JSONL output;
- ephemeral Codex session persistence;
- `workspace-write` sandboxing restricted to the stage;
- no interactive approval escalation;
- the requested model and reasoning effort when set;
- a closed, allowlisted environment;
- bounded stdout and stderr readers;
- process-tree supervision and cancellation.

Codex's provider transport may reach OpenAI as required for the subscription. Commands
spawned by the coding agent do not receive ambient network access. The adapter does not
silently install, update, downgrade, or switch the Codex executable.

The adapter never accepts `OPENAI_API_KEY`, `CODEX_API_KEY`, a bearer token, or a
credential-file path from Carl configuration.

### Subscription run engine

`SubscriptionRunEngine` is a top-level kernel execution strategy, not a native model
provider and not a shortcut around Carl policy. The `carl run` command selects it when
the session provider is `codex`. Frontends still submit versioned commands and consume
the same event stream; they never launch Codex directly.

Later, the same Codex adapter may also be exposed as a specialist tool to a native
provider loop. That composition is outside this milestone and must reuse the same
staging and policy contracts rather than introduce a second execution path.

### Event normalizer

The normalizer converts supported Codex JSONL records into versioned Carl delegate
events. It records:

- provider and executable version;
- requested model and reasoning effort;
- provider-reported resolved model or effort when available;
- thread and turn lifecycle;
- bounded agent messages;
- bounded summaries of command execution and file-change events;
- usage when reported;
- completion, cancellation, and typed failure.

Unknown optional event types are stored only as a bounded, sanitized compatibility
record. Malformed required lifecycle events, invalid framing, duplicate terminal
events, or output beyond hard limits fail closed.

Codex-internal commands, edits, and tests remain labeled untrusted provider evidence.
They never become native Carl tool or verification events.

### Proposal inspector

After Codex exits, Carl compares the stage against its immutable manifest without
executing repository code. It produces a content-addressed artifact of inert,
exact-replacement proposals for existing UTF-8 files.

The first slice rejects:

- file creation, deletion, and rename;
- binary or non-UTF-8 changes;
- protected paths and path escapes;
- oversized changes;
- ambiguous identity;
- changes that require fuzzy matching.

Each proposal includes the live file's expected SHA-256 plus before, after, and payload
hashes. Artifact generation cannot mutate the live workspace.

### Verification runner

Carl runs an explicitly configured, bounded verification command against the staging
workspace after proposal inspection. Verification has its own timeout, output limit,
environment filter, process-tree supervision, and event lifecycle.

A Codex claim that tests passed is informational. Only the verification runner can
produce trusted verification evidence. Failure or interruption blocks promotion while
preserving the proposal artifact for inspection.

### Promotion boundary

Promotion requires approval bound to:

- run and proposal artifact identifiers;
- stage-manifest hash;
- exact changed paths and content hashes;
- live precondition hashes;
- verification command and successful result digest;
- expiration and owner identity.

Carl reopens each live path through workspace capabilities and revalidates its
precondition immediately before applying an atomic exact replacement. Any stale file
fails independently. Carl never implicitly retries or partially replays a failed
promotion.

## Model and reasoning-effort selection

The public command shape is:

```text
carl run [--model <provider-model>] [--effort <level>] <task>
```

Selection precedence, from highest to lowest, is:

1. per-run override;
2. persisted session setting;
3. trusted project configuration;
4. personal Carl configuration;
5. provider default.

Changing a session model or effort persists for subsequent tasks in that session.
Per-run flags are temporary and do not mutate the session defaults.

This milestone introduces only the narrow typed configuration needed for provider,
model, and effort selection. It does not pull the general Phase 8 configuration system
forward. Project and personal values are accepted only from the explicitly documented
Carl configuration keys, with source provenance recorded; unknown keys do not silently
alter delegate behavior.

The Codex adapter passes the selected model through the documented model option and
reasoning effort through a scoped configuration override. Effort is represented by a
typed Carl value, while model identifiers remain provider-owned strings with length
and character bounds.

Carl validates known-invalid values before process launch. Because provider model
availability can vary by account, plan, rollout, and CLI version, final entitlement
validation belongs to Codex. An unavailable model or unsupported effort is a typed
delegate configuration failure. Carl does not silently substitute another model,
effort, provider, or billing path.

The run journal records every configuration source, the requested values, and any
provider-reported resolved values. If Codex does not report a resolved value, Carl
records that fact rather than guessing.

## Data flow

1. Validate the command, trusted workspace, task bounds, session settings, and
   requested model/effort.
2. Confirm that the compatible Codex executable is authenticated through the existing
   provider-owned status handshake.
3. Persist the run and resolved Carl-side configuration.
4. Build and persist the sanitized stage manifest.
5. Evaluate the external-agent policy and obtain approval for the networked delegate
   invocation.
6. Launch `codex exec --json` under the stage-only sandbox and stream normalized
   events.
7. On successful process completion, inspect the stage and persist the proposal
   artifact.
8. Run and persist independent verification.
9. Present the exact proposal, provenance, and verification evidence.
10. Bind owner approval to the exact artifact and current preconditions.
11. Revalidate live state, promote accepted replacements through the native patch
    boundary, and persist the terminal outcome.
12. Clean the stage after terminal state persistence. Interrupted runs retain only
    bounded, non-secret artifacts needed for inspection, not an indefinitely live
    provider process.

## Failure behavior

| Condition | Public outcome | Required behavior |
| --- | --- | --- |
| Missing or expired login | `authentication_required` | Do not start a run; print the exact Carl login recovery command. |
| Logged in but subscription is unavailable | `subscription_unavailable` | Preserve the provider error without falling back to API billing. |
| Unsupported executable version | `delegate_incompatible` | Fail closed before sending a task. |
| Invalid or unavailable model/effort | `delegate_configuration_failed` | Preserve requested values; do not substitute. |
| Sidecar launch failure | `delegate_start_failed` | Persist sanitized diagnostics and clean the stage. |
| Malformed required JSONL | `delegate_protocol_failed` | Terminate the process tree and retain bounded compatibility evidence. |
| Output or time budget exceeded | `delegate_budget_exhausted` | Cancel, reap, and block inspection or promotion unless a complete terminal result exists. |
| User cancellation | `cancelled` | Terminate and reap the process tree; never promote partial work. |
| Carl crash or unknown child completion | `interrupted` | Never automatically repeat the task or promotion. |
| Secret or unsafe stage input | `stage_rejected` | Report paths and rule identifiers without secret bytes. |
| Unsupported staged change | `proposal_rejected` | Preserve a bounded explanation; never coerce or fuzzily apply it. |
| Verification failure | `verification_failed` | Preserve the inert proposal and block promotion. |
| Live source changed | `stale_workspace` | Reject the affected replacement before mutation. |
| Promotion conflict | `promotion_failed` | Stop; do not retry or claim atomicity across multiple files. |

Authentication, policy, model-selection, stale-state, validation, verification, and
mutation failures are never automatically retried. A future retry policy may retry
only demonstrably pre-mutation transport handshakes.

## Redaction and persistence

All provider stdout, stderr, JSONL, errors, and diagnostics pass through size bounds and
redaction before durable storage or frontend rendering. Carl stores no raw OAuth
tokens, refresh tokens, cookies, credential files, authorization headers, personal
provider configuration, or unbounded reasoning text.

The durable record distinguishes:

- trusted Carl state transitions;
- untrusted provider evidence;
- trusted Carl verification;
- owner approvals;
- live workspace mutation results.

This distinction must remain visible in exported traces and future TUI or Telegram
rendering.

## Testing strategy

Normal CI uses a fake Codex executable and no live credentials or network.

### Unit and contract tests

- configuration precedence and session persistence;
- exact model and effort argument construction;
- environment allowlisting and rejection of API-key/token inputs;
- JSONL framing, lifecycle normalization, unknown optional events, malformed required
  events, duplicate terminals, and output bounds;
- typed error mapping and sanitized diagnostics;
- manifest and proposal hashing;
- approval binding and stale-state preconditions.

### Process tests

The fake executable can emit fixtures, hang, crash, exceed output bounds, write staged
files, leak sentinel secrets, and spawn descendants. Tests prove:

- cancellation and timeout reap the entire process tree;
- no child survives a completed test;
- the live workspace and provider homes are not writable through the stage;
- secret sentinels never reach stored events or rendered errors;
- cleanup is bounded and crash-safe.

### Security and filesystem tests

- traversal, symlink, hard-link, ancestor-swap, and protected-path attempts;
- files replaced concurrently during staging and promotion;
- excluded provider/project configuration and executable hooks;
- unsupported creates, deletes, renames, binaries, and oversized diffs;
- stale approval replay;
- environment-variable and command-network leakage.

### Deterministic scenario

A checked-in fixture repository begins with one failing test. The scripted Codex
process emits a realistic JSONL stream and changes one existing source file in the
stage. Carl must:

1. persist the outer lifecycle;
2. produce the expected exact proposal;
3. run the pinned verification successfully;
4. require an exact approval;
5. promote the change;
6. leave the fixture test passing;
7. replay to the same normalized terminal state.

Additional variants cover failed verification, cancellation, malformed JSONL,
secret-bearing source, and a stale live file.

### Live smoke test

An opt-in local test may use a separately installed compatible Codex CLI and an
eligible ChatGPT subscription. It is never required by public CI, never records
credentials or personal prompts, never checks in provider output, and operates only on
a disposable fixture copy.

## Acceptance criteria

The milestone is complete only when:

- a user authenticated with `carl auth login openai` can complete the fixture coding
  task without an OpenAI API key;
- per-session model and effort settings persist, while per-run overrides remain
  temporary;
- requested and provider-reported configuration is durably distinguishable;
- Codex never receives a writable live-workspace path or capability;
- every process terminates or is reaped under success, failure, timeout, and
  cancellation tests;
- every proposed mutation has an inert artifact, trusted verification, exact approval,
  and fresh precondition;
- no test sentinel secret appears in events, errors, artifacts, traces, or child
  environments;
- deterministic CI passes on the repository's supported platforms without live
  credentials;
- README, architecture, security, ADR, changelog, and roadmap statements truthfully
  distinguish authentication, delegate execution, provider evidence, and Carl
  verification.

## References

- [OpenAI Codex authentication](https://learn.chatgpt.com/docs/auth)
- [OpenAI Codex non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode)
- [OpenAI Codex CLI commands](https://learn.chatgpt.com/docs/developer-commands?surface=cli)
- [OpenAI Codex sandboxing](https://learn.chatgpt.com/docs/sandboxing)
- [Carl ADR 0004](../../adr/0004-subscription-authentication-through-provider-sidecars.md)
- [Carl top-tier harness design](2026-07-23-carl-top-tier-harness-design.md)
- [Existing subscription delegate plan](../plans/2026-07-24-carl-subscription-delegates.md)
