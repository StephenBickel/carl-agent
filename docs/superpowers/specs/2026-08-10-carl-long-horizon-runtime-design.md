# Carl Long-Horizon Runtime Design

Status: approved in conversation; written-spec review pending
Date: 2026-08-10
Decision owner: Stephen Bickel

## Purpose

This document defines how Carl becomes a genuinely useful single-owner coding agent
that can continue substantial work for hours, survive provider-context compaction and
process restarts, retain exact task state, recover from failed strategies, and prove
completion with repository evidence.

Carl will remain small and understandable at the product surface. Its distinguishing
capability will be a durable, provider-neutral execution kernel beneath that minimal
interface. The user should be able to give Carl a real coding objective and trust it
to keep making decisions until the work is verified, cancelled, or genuinely blocked.

This design extends the
[top-tier harness design](2026-07-23-carl-top-tier-harness-design.md) and the
[Buzz ACP design](2026-08-10-carl-buzz-acp-design.md). Where those documents describe
approval-first defaults, this document supersedes them: trusted owner surfaces use
`full-access` by default. Permanent identity, credential, durability, and replay
invariants remain in force.

## Product outcome

Carl V1 is a public, open-source, single-owner local coding agent. It is optimized for
one developer working on local repositories, including through an authenticated
owner-only remote frontend. It is not a hosted multi-tenant service.

Its product promise is:

> Give Carl a coding goal, and it will keep working, checking, remembering, adapting,
> and recovering until the goal is demonstrably complete or it can show a real
> blocker.

Hiring signal is a consequence of building this product well, not its objective.
Claims that Carl is more reliable than another harness require reproducible evidence
from the evaluation protocol defined here.

## Current baseline and gap

The implemented ACP kernel already provides valuable foundations:

- append-only versioned events and checksum-verified SQLite migrations;
- durable frontend/session/provider-thread bindings;
- serialized session ownership, steering, cancellation, and exact approvals;
- model, reasoning-effort, and permission-mode persistence;
- provider-owned ChatGPT subscription authentication through the pinned Codex
  app-server;
- deterministic Buzz/ACP end-to-end tests and an opt-in live Codex smoke test;
- owner-private storage, credential isolation, bounded transports, and supervised
  provider processes.

It does not yet provide a Carl-owned completion contract, task state machine, context
ledger, structured compaction record, provider-independent resume path, durable
operation reconciliation, or long-horizon evaluation suite. Token-usage notifications
from Codex are structurally validated but not used to drive context policy. The live
smoke script uses separate short sessions and does not prove repeated-turn continuity,
forced compaction, process restart, or multi-hour execution.

Provider thread state is therefore currently a useful runtime dependency but also an
implicit source of truth. This design removes that dependency.

## Research basis

Current production harnesses converge on several useful patterns:

- Pi stores append-only JSONL sessions and makes compaction a durable summary plus a
  retained recent tail. It preserves complete history and never separates a tool call
  from its result: <https://pi.dev/docs/latest/compaction> and
  <https://pi.dev/docs/latest/session-format>.
- Claude Code combines context compaction with persistent instruction reload,
  checkpoints, rewind, and isolated subagents whose concise results protect the main
  context: <https://code.claude.com/docs/en/context-window>,
  <https://code.claude.com/docs/en/checkpointing>, and
  <https://code.claude.com/docs/en/sub-agents>.
- Codex app-server exposes thread start, resume, fork, compaction, status, and
  persisted-history operations. Carl must feature-detect these against its exact
  pinned Codex version rather than assume the current `main` protocol is available:
  <https://github.com/openai/codex/blob/main/codex-rs/app-server/README.md>.
- OpenCode V2 treats compaction as an idempotent execution barrier at a safe drain
  boundary. Concurrent requests coalesce and overflow recovery is bounded:
  <https://opencode.ai/v2/docs/compaction>.
- OpenClaw separates temporary tool-output pruning from persistent compaction, keeps
  original history, flushes durable memory before compaction, and bounds long-lived
  transcript reads:
  <https://github.com/openclaw/openclaw/blob/main/docs/concepts/compaction.md> and
  <https://github.com/openclaw/openclaw/blob/main/docs/reference/session-management-compaction.md>.
- Hermes uses a pluggable context engine, real provider token observations when
  available, fallback estimation, and configurable compression thresholds:
  <https://github.com/NousResearch/hermes-agent/blob/main/website/docs/developer-guide/context-compression-and-caching.md>.

Carl adopts the durable patterns without copying any harness's provider assumptions or
user experience wholesale.

## Goals

- Own long-horizon task state independently of every model provider.
- Continue autonomously across bounded work epochs without requiring repeated
  `continue` messages.
- Preserve goals, hard constraints, exact identifiers, decisions, unresolved work,
  tool state, and verification evidence across repeated compactions.
- Resume safely after Carl, frontend, or provider failure without duplicating an
  ambiguous side effect.
- Detect stalled strategies and require a materially different recovery approach.
- Treat provider threads as replaceable compute caches rather than durable truth.
- Prove completion clause by clause with recorded repository evidence.
- Default trusted owner surfaces to full access while denying privileged execution
  before model invocation for unauthenticated or shared surfaces.
- Keep small tasks fast: long-horizon machinery must not add visible ceremony to a
  simple edit or question.
- Provide deterministic, accelerated endurance tests and opt-in live subscription
  soak tests.
- Support future OpenAI, Grok, and local-model adapters through one execution and
  context contract.

## Non-goals

- A hosted multi-user or multi-tenant control plane.
- A general workflow-orchestration product or arbitrary distributed DAG scheduler.
- Claiming native commands are contained by a complete operating-system sandbox.
- Making a model-written summary the sole source of recovery state.
- Preserving hidden chain-of-thought. Carl persists decisions, evidence, and concise
  rationale, not private reasoning traces.
- Automatically retrying unknown or irreversible side effects after a crash.
- Treating context rewind as filesystem rollback.
- Shipping subagents before the single-agent kernel passes long-horizon evaluations.
- Requiring an OpenAI Platform API key for the Codex subscription path.

## Selected architecture

Carl will use a durable epoch engine backed by a narrow event-sourced task state
machine. A provider turn may perform many tool calls, but it advances only one bounded
epoch objective. At every safe epoch boundary Carl verifies progress, commits a
checkpoint, assesses completion and context pressure, and either stops or selects the
next objective.

```text
goal + completion contract
          |
          v
select bounded epoch objective
          |
          v
provider reasoning and tool loop
          |
          v
normalize tool results and repository evidence
          |
          v
verify completion clauses and progress
          |
          v
commit checkpoint -----> compact or replace provider context when required
          |
          +-------------> continue, pause, block, cancel, or complete
```

One task actor is the sole writer for a task. Frontends submit idempotent commands to
that actor and consume sequenced events. They do not run providers, tools, compaction,
or verification directly.

### Why not the alternatives

A thin checkpoint wrapper around one provider thread is faster to build but leaves
Carl unable to recover when that thread is lost, corrupt, or too large to resume. A
full persistent workflow DAG provides more scheduling power than a single-owner coding
agent needs and would make the harness harder to understand. The selected state
machine can later add dependency edges without changing checkpoint or operation
semantics.

## Task model

The kernel introduces stable `TaskId`, `EpochId`, `OperationId`, `CheckpointId`, and
`ContextPackageId` identifiers. A session may contain multiple tasks, but only one task
per session can own an active provider turn in V1.

A task contains:

- the owner's original request and subsequent steering;
- a versioned goal and completion contract;
- canonical workspace identity and initial repository evidence;
- provider, model, effort, permission, and budget configuration;
- current state, epoch, checkpoint, provider binding, and progress counters;
- durable operation and verification references;
- terminal outcome and evidence when applicable.

The task state machine is:

```text
queued -> active -> checkpointing -> active
             |             |
             |             +-> paused / blocked / failed
             +-> cancelling -> cancelled
             +-> completing -> completed
```

`active`, `checkpointing`, `cancelling`, and `completing` are durable states, not UI
labels. A process restart replays events, rebuilds projections, and reconciles the
recorded state before accepting a new execution command.

### Goal and completion contract

Carl derives a first contract from the owner's request instead of routinely asking the
owner to restate obvious requirements. The contract contains:

- requested outcome;
- hard constraints and forbidden changes;
- required behavior and artifacts;
- required checks and acceptable substitutes;
- scope boundaries;
- assumptions Carl is authorized to make;
- individual completion clauses and their evidence state.

The contract is visible and versioned. Steering appends a new contract version and
invalidates plans that conflict with it, but it does not erase earlier evidence or
events. Carl asks the owner only when alternatives imply materially different
irreversible outcomes, missing authority, or missing secrets.

## Durable event and storage model

SQLite remains the authoritative local store. The append-only event journal is the
source of truth; query tables are transactional projections and may be rebuilt only
after integrity validation.

The event vocabulary gains typed records for:

- task creation, configuration, state transition, steering, and completion contract;
- epoch planning, start, heartbeat, progress assessment, and finish;
- operation intent, start, output, success, failure, uncertainty, and reconciliation;
- verification request, observation, clause evidence, and final decision;
- checkpoint construction, validation, commit, and rejection;
- compaction request, coalescing, completion, failure, and emergency recovery;
- provider context binding, resume, replacement, loss, and capability observation;
- cancellation, budget exhaustion, stall detection, strategy replacement, blocker,
  and completion.

Every state transition and its projection update commit in one SQLite transaction.
Storage failure stops further consequential work. Events receive monotonically
increasing per-session sequence numbers and schema versions. Context packages and
checkpoints bind the exact source event range and a digest of their canonical form.

Large diffs, command output, provider recordings, and repository snapshots remain in
the owner-private content-addressed artifact store. Journal events contain bounded
metadata and artifact digests rather than unbounded output.

No event, artifact, context package, export, or diagnostic may intentionally retain a
Carl-managed provider token, channel secret, bot token, raw environment value, or
detected secret. Secret detection retains classification and location metadata, not
matched bytes. Full access cannot guarantee that an unrestricted command will never
read some other same-user secret; that residual risk is documented below.

## Epoch execution

An epoch has one concrete objective, such as reproducing a bug, implementing a single
coherent change, or verifying a completed change. Carl gives the provider the full
completion contract but instructs it to advance the current objective and leave an
inspectable result.

An epoch ends at the earliest safe boundary after any of these conditions:

- the objective or another meaningful milestone is reached;
- provider context reaches the configured compaction threshold;
- the soft elapsed-time or completed-tool-call budget is reached;
- owner steering or cancellation arrives;
- the provider ends, disconnects, or reports overflow;
- a required approval is pending in non-full-access mode;
- progress assessment detects a stall.

Initial defaults are a fifteen-minute soft epoch interval, forty completed tool calls,
and an 80 percent context-compaction threshold. These are soft scheduling boundaries,
not permission or correctness limits. An active tool is allowed to finish or is
explicitly cancelled; a checkpoint never fabricates a tool result.

There is no default total task wall-clock cutoff for the authenticated local owner.
Configurable total time, token, tool-call, and provider-request budgets remain
available. A task without a total time limit still cannot spin indefinitely because
the progress and stall policy applies after every epoch.

Model or reasoning-effort changes apply at the next epoch boundary. Permission
tightening may cancel or constrain the active epoch immediately; permission loosening
never changes the interpretation of an already ambiguous operation.

### Operation lifecycle and idempotency

Before dispatch, every operation receives an ID, normalized argument digest, effect
class, relevant preconditions, and retry policy. Its durable lifecycle is:

```text
intent recorded -> started -> succeeded | failed | cancelled | uncertain
                                      uncertain -> reconciled | blocked
```

Operations are classified as:

- **observation**: bounded reads that may be repeated after state reconciliation;
- **idempotent mutation**: operations with exact preconditions and postconditions that
  can be inspected and safely resumed with the same operation ID;
- **ambiguous or irreversible effect**: shell, network, package publication, external
  messaging, or destructive work whose completion cannot be proven after interruption.

Full access authorizes dispatch without an approval prompt; it does not make an
operation idempotent. Carl never blindly repeats an ambiguous or irreversible effect.
It first inspects durable and external state where possible, records reconciliation,
and otherwise reports the exact uncertainty as a blocker.

Tool calls and results are indivisible context units. Compaction, steering, and
checkpoint boundaries cannot retain a call without its corresponding terminal state.

### Pre-dispatch mediation is a release boundary

Carl cannot guarantee intent-before-effect merely by observing provider tool-started
notifications. A provider may already have started the command before Carl durably
receives that notification. Production long-horizon guarantees therefore require
every consequential operation to cross a Carl-controlled pre-dispatch boundary.

A provider adapter may satisfy this contract in one of two ways:

1. expose a real approval hook that pauses every consequential file, shell, network,
   and external operation before effect, allowing Carl to journal intent and then
   auto-allow it in owner `full-access` mode; or
2. disable or constrain the provider's consequential built-in tools and route those
   operations through Carl-owned native or MCP tools.

The second path is the fallback for Codex if its exact pinned app-server protocol
cannot prove complete pre-dispatch mediation. Codex may retain bounded read-only
inspection tools while Carl owns mutation, shell, network, process, and external
effect tools. The product still feels like full access because Carl decides and
dispatches automatically; no user approval prompt is introduced.

Passing Codex's `danger-full-access` directly through while relying only on post-hoc
notifications remains a clearly labeled legacy provider-owned mode. It cannot pass
the zero-duplicate production gate and is not the implementation target of this
design.

### Long-running processes

Commands that outlive an ordinary tool response receive durable process handles,
bounded output artifacts, heartbeats, deadlines, and cancellation tokens. Carl tracks
the executable identity, argv digest, cwd, environment profile, process containment
identity, and last observed state.

After restart Carl reconciles a recorded process instead of assuming it is alive or
dead. If the operating system cannot safely reattach, it terminates a positively
identified test-owned orphan when possible and marks the operation uncertain. A
read-only or reproducible command may then be restarted under a new operation ID;
an ambiguous effect may not.

## Checkpoint format

A checkpoint is a versioned, canonical structure. It contains:

- task goal and completion contract version;
- hard constraints, owner decisions, and accepted assumptions;
- completed work with event and artifact evidence;
- current repository identity, relevant file hashes, diffs, and git metadata;
- decisions, rejected approaches, failure signatures, and retry restrictions;
- exact paths, symbols, commands, ports, issue IDs, process handles, and other
  identifiers required for continuation;
- active epoch outcome, next objective, blockers, and open questions;
- running processes, pending approvals, queued steering, and delivery uncertainty;
- verification clause state and the exact evidence for each satisfied clause;
- provider/model/effort metadata, observed usage, and provider context binding;
- source event range, previous checkpoint digest, schema version, and compaction
  generation.

Canonical fields are derived from durable events and repository observations. A model
may write a concise narrative summary and propose the next objective, but it cannot
replace or contradict canonical state. Validation rejects missing hard constraints,
unresolved operations, invalid event references, unpaired tool lifecycles, unknown
artifact digests, and lost exact identifiers.

Checkpoint commit precedes provider-context deletion, replacement, or acknowledged
compaction. A failed checkpoint leaves the prior context and checkpoint usable.

## Context engine and compaction

Carl owns a provider-neutral `ContextEngine` with three responsibilities:

1. account for every context source and its token or byte estimate;
2. decide when pruning, compaction, retrieval, or provider replacement is required;
3. build and validate the exact context package given to a provider epoch.

Actual provider token observations take precedence. A conservative tokenizer or byte
estimate is used when a provider does not report usage. The context inspector shows
actual versus estimated usage, source budgets, truncation, checkpoint generation, and
the reason for every omission.

### Two-layer reduction

Transient pruning removes old bulky tool output from the next provider request while
retaining its artifact and a short typed result. It does not create a durable
compaction generation.

Persistent compaction creates and commits a new validated checkpoint plus a recent
unsummarized tail. It never deletes the event journal or artifacts.

### Compaction protocol

1. Context pressure or an explicit request appends `CompactionRequested`.
2. Repeated requests coalesce behind one task-scoped barrier.
3. The task actor reaches a safe boundary with no unrecorded tool completion.
4. Carl deterministically assembles canonical checkpoint fields.
5. The provider may create a bounded narrative summary.
6. Carl validates references, required fields, exact identifiers, operation pairing,
   process state, approvals, constraints, and completion evidence.
7. The checkpoint and its context-package digest commit atomically.
8. Carl invokes native provider compaction only when the exact negotiated adapter
   capability is supported and useful.
9. Otherwise Carl starts a replacement provider context from its own package.
10. Execution resumes only after the provider binding is durably recorded.

Automatic compaction begins at 80 percent of the effective model context window and
targets 50–60 percent utilization afterward. The recent tail is selected by semantic
units and budget, never by cutting raw messages or tool pairs. A provider overflow may
trigger one emergency recovery from the latest committed checkpoint. Repeated blind
overflow retries are forbidden.

Each new compaction consumes the previous canonical checkpoint plus post-checkpoint
events; it does not recursively summarize prose summaries. This prevents cumulative
summary drift.

### Provider context package

Every new or replacement provider context contains, in precedence order:

1. stable Carl runtime and security instructions;
2. owner instructions and trusted user configuration;
3. trusted-project instructions with provenance;
4. goal and current completion contract;
5. latest canonical checkpoint and verification state;
6. recent unsummarized event tail;
7. task-relevant historical evidence retrieved by stable reference;
8. current epoch objective, budgets, and available tools;
9. explicitly labeled untrusted repository, memory, and external content.

The exact package manifest and digest are durable. Omitted source ranges and reasons
are visible. Old evidence can be retrieved through bounded artifact and event readers
without loading the full transcript into memory.

## Provider adapter contract

Provider implementations normalize the following capabilities:

- start a context and epoch;
- stream assistant, reasoning-summary, token-usage, tool, diff, and lifecycle events;
- respond to an exact permission request;
- steer or cancel the active epoch;
- list models and supported reasoning efforts;
- optionally resume, fork, compact, page history, and report context limits;
- report a stable provider context ID and terminal reason.

Optional capabilities are negotiated and recorded. Provider-native persistence can
improve efficiency but never changes Carl's checkpoint or recovery semantics.

The first implementation extends the pinned Codex app-server adapter. Its generated
schema and live handshake must prove support before Carl uses native `thread/resume`,
`thread/fork`, or `thread/compact/start`; current upstream documentation alone is not
a compatibility guarantee for Codex `0.146.0`. Unsupported operations fall back to a
new thread assembled from Carl's context package.

The same contract probe must determine whether Codex can pause every consequential
operation before effect. If it cannot, the first production adapter constrains Codex
built-ins and exposes Carl-owned tools through the supported local tool seam. A tool
lifecycle notification without an acknowledgement barrier is observation, not
authorization.

Grok execution can later implement the same adapter using its provider-owned OAuth
home. The long-horizon kernel must not import Codex-specific JSON shapes.

## Autonomous continuation and progress policy

At an epoch boundary Carl records deterministic progress signals:

- new or changed repository artifacts;
- new passing or failing verification evidence;
- resolved completion clauses;
- newly isolated failure causes;
- decisions that eliminate alternatives;
- changed blockers or external state;
- repeated commands, error signatures, and unchanged diffs.

An epoch must produce progress, new information, or an explicit strategy change.
Substantially identical commands, errors, diffs, and plans across epochs increase a
stall score.

Recovery escalates through:

1. reconstructing the current state from evidence;
2. explicitly replacing the failed approach;
3. starting a fresh provider context for an independent diagnosis;
4. reducing the problem to a smaller reproduction or verification target;
5. declaring a blocker only after at least three materially distinct approaches fail
   or required external authority is unavailable.

The stall counter is based on semantic strategy fingerprints rather than raw prompt
text. A new provider thread repeating the same approach is not independent progress.

Carl completes a task only when every required contract clause has valid evidence.
Model confidence is never evidence. Failed required checks prevent success unless the
owner explicitly revises the contract. Final output links the changed files, exact
verification commands, exit status, relevant artifacts, skipped checks, and remaining
workspace state.

## Steering, cancellation, and frontend continuity

Owner steering is accepted while an epoch is active, durably queued, and injected at
the provider's next supported steer point or safe boundary. Steering order is stable
and duplicate frontend messages are ignored by idempotency key.

Cancellation has priority over queued work. Carl records the request, asks the
provider and active tools to stop, escalates process-tree termination after a bounded
deadline, commits the resulting operation states, and only then reports cancellation.

Frontend disconnection does not stop an owner-authorized task. Reconnecting clients
receive a bounded snapshot plus sequenced events after their cursor. A frontend may
observe or steer the one durable task without owning its provider context.

## Permission and security model

Carl exposes three product modes:

- `full-access`: default for trusted owner surfaces; routine approval prompts are
  skipped and coding capabilities use the host account's ambient authority;
- `approval`: exact approval is required for consequential work;
- `read-only`: mutation is denied.

Existing `bypassPermissions` remains a compatibility alias for `full-access`.
Existing finer-grained modes may continue as compatibility profiles, but the product
UI emphasizes these three choices.

`full-access` is a Carl policy decision, not an instruction to blindly pass a
provider's dangerous-bypass flag through. Carl may deliberately run the provider with
stricter built-in permissions while automatically authorizing Carl-mediated tools.
This preserves the no-prompt owner experience and the pre-dispatch journal invariant.

Local CLI and TUI sessions running under the owner-private data root are trusted owner
surfaces. Telegram requires a local, expiring, single-owner pairing ceremony. Buzz
requires a locally confirmed durable actor/channel binding in addition to Buzz's
signed identity and owner-only admission. Pairing warns once that remote full access
controls the current OS account; subsequent authenticated owner requests do not
require repeated confirmation. Re-pairing invalidates the prior owner.

Unknown users, groups, channels, guests, shared webhook identities, malformed context,
and replayed events are rejected before provider or tool invocation.

Full access bypasses approval prompts, not permanent invariants:

- remote identity and pairing cannot be changed by model or repository content;
- provider login remains a verified local-foreground operation;
- Carl-managed provider and channel credentials are excluded from provider prompts,
  general tool environments, checkpoints, events, exports, and diagnostics;
- untrusted content cannot loosen policy, change provenance, or grant capabilities;
- ambiguous side effects are not automatically repeated after interruption;
- storage failure halts consequential execution;
- frontend, actor, channel, session, workspace, and operation bindings remain exact;
- child processes remain bounded, supervised, and cancellable where implemented.

Full access is not a sandbox. Malicious repository content or a compromised model or
provider may execute commands with the owner's ambient OS authority, including outside
the workspace or over the network. Such a command may read or transmit other files and
secrets accessible to that OS account; Carl-managed credential isolation and
best-effort output redaction do not make arbitrary native execution non-exfiltrating.
Carl will document this accepted single-owner risk and recommend source control,
backups, and an isolated development account or machine.

The root `SECURITY.md` is stale: it says the coding runtime is unimplemented and
describes an API-key direction that no longer matches the provider-owned subscription
path. Implementation of this design must separately preview and obtain approval for
an exact policy update before editing that file.

## Observability and user experience

The ordinary interface remains conversational. Long-horizon machinery appears as a
small status surface showing:

- task state and elapsed time;
- current epoch objective and running tool;
- completion clauses and verification status;
- model, effort, permission mode, and provider;
- context utilization, compaction generation, and latest checkpoint;
- changed files, tests, retries, stall recovery, and blockers;
- a clear stop control and steering queue.

Detailed events, context sources, operation digests, provider bindings, artifacts, and
replay diagnostics remain one inspection command away. Carl should explain why it is
continuing, compacting, changing strategy, blocking, or completing without flooding
normal chat with raw traces.

## Evaluation architecture

The evaluation suite has four layers.

### 1. Model-free state-machine and property tests

Tests use fake time, deterministic IDs, bounded fake tools, and generated event
sequences. They prove:

- replay always reconstructs the same task state and projection digest;
- invalid transitions and concurrent task writers fail closed;
- tool calls remain paired with terminal states across every cut point;
- checkpoint source ranges and artifact hashes are valid;
- compaction requests coalesce and cannot pass queued cancellation or steering;
- ambiguous operations are never dispatched twice;
- every consequential fake-provider operation crosses a durable pre-dispatch barrier;
- secret values do not survive events, artifacts, packages, or diagnostics;
- budget arithmetic, token estimation, and emergency recovery are bounded;
- storage failure prevents further consequential execution.

### 2. Deterministic provider scenarios

A scripted provider drives 100 or more epochs while tests force compaction every few
epochs, kill and restart Carl at every operation lifecycle boundary, drop provider
contexts, inject steering and cancellation, fail storage writes, and simulate output
backpressure. The final replay digest and task outcome must be independent of each
permitted interruption schedule.

### 3. Disposable repository evaluations

Small pinned repositories exercise real filesystem and process behavior:

- retain early exact identifiers through at least twelve compactions and use them in
  the final verified change;
- diagnose and fix a bug across multiple files after first adding a regression test;
- perform a repository-wide refactor with formatting, static analysis, tests, and
  documentation;
- recover after termination between operation intent, start, mutation, and result;
- replace a stalled strategy after repeated identical failures;
- preserve or safely restart a long-running verification command;
- apply mid-task owner steering without losing prior valid work;
- reject hostile repository instructions, secret capture, and out-of-scope changes;
- lose the provider thread entirely and continue from a Carl checkpoint;
- encounter an ambiguous fake external side effect without duplicating it.

Each run occurs in a fresh disposable worktree or copied fixture. Endurance tests never
mutate the owner's active repository.

### 4. Live subscription evaluation and soak

An opt-in local suite uses Carl's authenticated Codex subscription path with API-key
environment variables removed. It records only sanitized metrics and artifact hashes.
Public CI remains credential-free.

The live suite includes repeated paired fixture runs against direct Codex using the
same model, effort, repository snapshot, prompt, and resource limits where the
protocol permits. This isolates the value of Carl's long-horizon control plane more
fairly than comparing unrelated models.

The live soak runs for a configurable two to eight hours, defaults to four, and works
through a real multi-clause disposable repository task. It forces multiple Carl
restarts and provider-context replacements, injects owner steering, observes a
long-running command, and requires at least twenty compaction generations before
final verification. Sleeping for four hours is not a passing soak; the task must
continue producing recorded progress and evidence.

## Metrics and release gates

Every evaluation records:

- completion-contract success and required-check success;
- manual interventions and approval prompts;
- hard-constraint and exact-identifier retention;
- duplicate or uncertain side effects;
- out-of-scope file changes and regressions;
- restart and provider-context-loss recovery;
- epochs, strategy changes, tool calls, invalid calls, and orphaned processes;
- actual or estimated tokens, compactions, wall time, and provider requests;
- context-package composition and dropped-source warnings;
- secret, policy, storage, and protocol violations;
- deterministic replay digest after normalization.

The deterministic production gate requires:

- 100 percent scenario completion at every enumerated interruption point;
- zero duplicated consequential effects;
- zero consequential effects outside the Carl-controlled pre-dispatch gateway;
- zero lost hard constraints or required exact identifiers;
- zero successful outcomes with failed required verification;
- zero test-owned orphan processes;
- zero privileged invocation from an untrusted remote identity;
- stable replay and bounded storage/context behavior.

A live reliability claim requires a checked-in fixture version, harness revision,
provider executable version, model, effort, permission mode, date, run count, and raw
sanitized result artifacts. Carl will not claim to be better than another harness from
a single demo or from tests using a stronger model. A comparative claim requires at
least thirty paired task runs and must report completion rate, interventions, safety
failures, time, and token/provider usage, including regressions.

## Failure handling

- Transient provider transport failures use bounded exponential backoff with jitter
  and provider retry hints.
- Authentication, validation, policy, incompatible schema, and stale precondition
  failures are not retried.
- Provider overflow gets one checkpoint-based emergency recovery attempt.
- Storage write or integrity failure stops consequential work and preserves diagnostic
  recovery information without modifying the database destructively.
- Projection mismatch triggers integrity validation and journal rebuild, never silent
  repair from provider state.
- Missing artifacts invalidate dependent checkpoints and block continuation until
  repaired or explicitly abandoned by the owner.
- An unavailable frontend does not fail the task; an uncertain external delivery is
  recorded and never blindly repeated.
- Exhausted budgets pause with current evidence and a resumable checkpoint.
- Genuine blockers include the attempted strategies, failure evidence, missing
  authority, and smallest owner action that can unblock the task.

## Compatibility and migration

Existing sessions remain readable. The next forward-only migration adds task, epoch,
checkpoint, context-package, operation, and verification projections without rewriting
historical event JSON. Historical sessions without a task record may be imported as a
single completed or resumable legacy task only through an explicit, tested adapter.

Permission parsing continues to accept ACP values `plan`, `default`, `acceptEdits`,
`dontAsk`, and `bypassPermissions`. New local sessions and newly paired owner sessions
default to `full-access`; existing persisted sessions keep their current mode until the
owner changes it or creates a new task. This avoids silently escalating authority for
old remote sessions.

Carl continues to pin exact provider and Buzz compatibility versions. New optional
provider lifecycle operations are enabled by generated-schema contract tests and live
handshake capability observation, not version-string assumptions.

## Implementation sequence

1. Prove the Codex pre-dispatch mediation contract; if it is incomplete, add the
   constrained-provider plus Carl-owned local tool gateway required by this design.
2. Add versioned task/epoch/operation/checkpoint types, storage migration, projection
   replay, and property tests.
3. Add the provider-neutral context engine, token ledger, package manifest, checkpoint
   builder, compaction barrier, and deterministic validation.
4. Extend the Codex adapter with feature-detected resume/compact/history operations and
   new-thread fallback.
5. Add the autonomous epoch actor, completion contracts, progress assessment, stall
   recovery, budgets, steering, cancellation, and restart reconciliation.
6. Change new trusted-owner defaults to full access while preserving permanent
   invariants and existing-session authority; add remote pairing/admission tests.
7. Add context and task observability to ACP and the eventual TUI-facing protocol.
8. Build deterministic interruption, compaction, repository, and security evaluations.
9. Add the opt-in live subscription suite, paired baseline runner, and multi-hour soak.
10. Update architecture, configuration, Buzz, security-model, root security-policy, and
   benchmark documentation to match tested behavior.

Each step lands only with its deterministic tests. Live provider success supplements
but never replaces model-free correctness tests.

## Acceptance criteria

This design is complete only when:

- Carl can complete a multi-epoch disposable repository task without manual
  continuation;
- a task survives repeated compaction, Carl restarts, and complete provider-thread
  loss while retaining every hard constraint and required identifier;
- replay reconstructs identical task state from the journal;
- no crash schedule duplicates an ambiguous consequential effect;
- every consequential provider-requested operation is durably mediated before effect;
- checkpoints are canonical, validated, linked to source events and artifacts, and
  inspectable by the owner;
- context packages account for every included or omitted source and stay within the
  negotiated provider budget;
- stalled strategies are detected and materially replaced;
- required checks and clause evidence gate successful completion;
- model and effort changes take effect at safe epoch boundaries;
- trusted owner surfaces default to full access and untrusted remote surfaces cannot
  invoke the provider or tools;
- deterministic CI passes the full interruption and endurance matrix;
- the opt-in live Codex suite passes through provider-owned subscription OAuth with no
  API-key fallback;
- a genuine multi-hour soak completes with no duplicate effects, lost state, leaked
  secrets, false success, or orphaned test processes;
- all documentation and security claims describe only implemented, tested behavior.
