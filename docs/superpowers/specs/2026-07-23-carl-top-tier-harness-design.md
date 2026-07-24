# Carl: Top-Tier Personal Coding Harness Design

Status: approved for implementation
Date: 2026-07-23
Decision owner: Stephen Bickel

## Document purpose

This document defines the product and technical architecture for renaming ArcWren to
Carl and turning the existing pre-alpha Rust foundation into a serious personal coding
agent. It supersedes the product direction and planned runtime in the
[ArcWren v1 design](2026-07-13-arcwren-v1-design.md). Existing event-sourcing,
single-process, and authentication decisions remain valid unless this document changes
them explicitly.

The implementation target is:

> A Pi-sized core with Codex-grade security, Claude Code-grade interaction,
> OpenCode-grade replay, and Hermes/OpenClaw-grade personalization.

Carl is Stephen's personal agent first and an open-source agent harness second. The
public repository should demonstrate disciplined harness engineering: a legible agent
loop, strict capability boundaries, durable execution, reproducible evaluations, and a
polished consumer experience. It should not demonstrate engineering ability through
feature count.

## Product identity

- Product name: **Carl**
- Repository name: **`carl-agent`**
- Rust package name: **`carl-agent`**
- Executable name: **`carl`**
- Rust library import name: **`carl`**
- Public personality and operating contract: **`CARL.md`**

Carl is a name, not an acronym. It is Stephen's middle name and his grandfather's name.
That personal provenance is part of the project's story and is stronger than a forced
technical expansion.

The current repository and Rust identifiers still use ArcWren. The first delivery phase
renames them. Because the project is pre-alpha and has no released compatibility
contract, the rename will not preserve deprecated `arcwren` CLI or library aliases.
Historical design documents and commit history remain intact.

## Research basis and legal boundary

This design synthesizes patterns from six agent products:

- Pi for a small, readable core, explicit compaction, steering queues, tree-structured
  sessions, and a line-oriented RPC mode.
- OpenAI Codex for Rust architecture, tool routing, patch safety, sandbox and approval
  separation, typed app-server protocol, and isolated workers.
- Claude Code for observable interaction design: plan mode, permission transitions,
  checkpoints, context inspection, hooks, subagents, and headless streaming.
- OpenCode for its client/server seam, durable SQLite state, permission grammar,
  snapshots, provider recording, and thin terminal client.
- Hermes Agent for stable prompt assembly, progressive skill loading, curated memory,
  completion contracts, and transport-neutral delivery.
- OpenClaw for a personal-assistant gateway, paired channels, remote approval binding,
  heartbeat/cron concepts, memory files, and gateway security.

Carl may adopt ideas and independently implement public interfaces from projects whose
licenses permit it. It will not copy proprietary code, prompts, branding, or assets.
Claude Code is source-available only in limited packaging surfaces and is not an
open-source codebase; it is an interaction reference, not an implementation source.
Every imported code dependency must pass license and provenance review.

## Goals

### Product goals

- Be useful as Stephen's daily personal coding agent, locally and through Telegram.
- Install as one `carl` executable on macOS and Linux in V1.
- Make the common path exceptionally short: open a repository, run `carl`, describe a
  task, inspect the diff, and receive verified results.
- Support OpenAI's Responses API and OpenAI-compatible local or hosted endpoints without
  coupling the kernel to either.
- Keep personality, instructions, skills, configuration examples, architecture,
  evaluation scenarios, and development process public.
- Keep secrets, raw conversations, runtime memory, provider recordings, and personal
  artifacts local by default.

### Engineering goals

- Keep the turn loop small enough for a reviewer to understand in one sitting.
- Represent every consequential transition as a typed, durable event.
- Make policy, human approval, and operating-system isolation distinct layers.
- Give every mutation an exact preview, precondition, audit record, and recovery path.
- Preserve full execution history while allowing bounded, explicitly lossy model
  context.
- Support deterministic replay and regression evaluation without live provider calls.
- Treat interruption, cancellation, crash recovery, and stale state as normal cases.
- Expose one versioned protocol used by the TUI, automation, and Telegram.
- Make completion claims evidence-based through explicit verification contracts.

### Portfolio goals

A hiring engineer should be able to find and evaluate:

- an explicit state machine rather than a recursive demo loop;
- stable domain events and replay fixtures;
- a centralized tool router and policy engine;
- TOCTOU-resistant approvals and patch preconditions;
- cancellation and child-process cleanup;
- context accounting and structured compaction;
- session branching, checkpoints, and artifact provenance;
- provider contract tests and recorded protocol fixtures;
- repository-level coding evaluations with measurable outcomes;
- architecture decisions explaining rejected complexity.

## Non-goals

- Competing on model count, channel count, or plugin count.
- Implementing LangChain, depending on LangChain, or reproducing its abstraction model.
- A hosted control plane, web application, mobile application, or multi-user service.
- Group-chat operation or accepting commands from unpaired Telegram users.
- General browser or desktop automation in V1.
- An in-process JavaScript/Python plugin runtime or unstable Rust dynamic-library ABI.
- Recursive autonomous agent swarms.
- Silent long-term memory extraction from every conversation.
- An unrestricted shell disguised as a sandbox.
- Transparent failover between models with materially different tool semantics.
- Reading another application's credentials or using undocumented OpenAI OAuth flows.
- Guaranteeing perfect hostile-code isolation on every supported operating system.

## Design principles

### One kernel, many transports

TUI, CLI automation, and Telegram submit commands to the same kernel and consume the
same event stream. No frontend may call a provider, execute a tool, mutate a session, or
grant an approval directly.

### History is durable; context is a projection

The event journal is the authoritative execution record. The prompt sent to a model is
a bounded projection derived from that record, public instructions, selected skills,
and explicit memory. Compaction may remove detail from future prompts but never rewrites
history.

### Models propose; the harness disposes

The model may propose a typed tool invocation. Carl validates its schema, normalizes it,
evaluates policy, obtains any required approval, revalidates preconditions, and only
then executes it. Text emitted by a model never directly changes the machine.

### Approval is not isolation

Policy determines whether an operation is allowed, denied, or requires consent.
Approval records the owner's consent to one exact operation. A sandbox constrains what
the resulting process can actually do. None substitutes for the others.

### Small trusted core

The durable state machine, policy evaluator, approval binding, tool router, patch
application, sandbox launcher, and redaction boundary form the trusted core. Frontend
rendering, provider serialization, skills, and optional integrations remain outside it.

### Explicit degradation

If a provider lacks tool calls, streaming, usage data, or another required capability,
Carl refuses the unsupported mode or surfaces the degradation. It never silently
changes safety or completion semantics.

### Local-first means no surprise network activity

Carl makes no telemetry, update, catalog, memory, or sharing requests by default. A
model request, user-invoked network tool, configured Telegram transport, and explicit
update check are separate, visible capabilities.

## System architecture

```text
                           +----------------------+
                           | CARL.md / AGENTS.md  |
                           | skills / memory      |
                           +----------+-----------+
                                      |
+-------------+    versioned    +-----v------------------------------+
| TUI / CLI   +---------------->+ event-sourced agent kernel         |
+-------------+    protocol     |                                    |
                                | turn state machine                  |
+-------------+                 | context engine   provider adapters |
| Telegram    +---------------->+ tool router      policy engine      |
+-------------+                 | approvals        verification      |
                                +------+----------------------+-------+
                                       |                      |
                               +-------v--------+     +-------v--------+
                               | sandboxed tool |     | SQLite journal |
                               | execution      |     | and projections|
                               +-------+--------+     +-------+--------+
                                       |                      |
                               +-------v--------+     +-------v--------+
                               | workspace and  |     | replay, eval,  |
                               | worktrees      |     | artifacts      |
                               +----------------+     +----------------+
```

Carl remains one distributable executable. During the vertical-slice phases it remains
one Rust package with crate-ready internal modules. A separate `carl-core` crate is
justified only when the headless protocol or a real embedding consumer needs it. Carl
does not commit to a stable public Rust API before 1.0.

Planned module boundaries:

- `runtime`: command handling, turn state machine, queues, budgets, cancellation, and
  completion contracts.
- `events`: schema-versioned commands, events, identifiers, and serialization.
- `context`: instruction precedence, context ledger, token budgets, compaction, memory,
  and skill selection.
- `providers`: capability-aware provider trait, wire adapters, error normalization, and
  cassette support.
- `tools`: schemas, registry, router, built-ins, normalized results, and output bounds.
- `policy`: capability requests, rules, decisions, approval binding, and redaction.
- `sandbox`: platform backends, process containment, environment filtering, and
  cancellation.
- `storage`: migrations, journal appends, projections, artifacts, checkpoints, and
  replay reads.
- `protocol`: versioned request/response/event types shared by all frontends.
- `frontends::tui`: terminal rendering, diff review, approvals, queue control, and
  session navigation.
- `frontends::telegram`: long polling, pairing, deduplication, rendering, and remote
  approvals.
- `evaluation`: scenario runner, fixture repositories, graders, and reports.
- `config`: layered values, source provenance, project trust, credential references,
  and diagnostics.

Dependency direction points inward. `runtime` depends on traits for storage, providers,
tools, policy, and time; implementations depend on those contracts. Frontends depend on
`protocol`, not `runtime` internals. Provider types never cross the provider boundary.

## Commands and events

Commands express requested intent. Events express accepted facts. Commands may be
rejected and do not appear as completed work merely because a frontend sent them.

Core commands include:

- `StartTurn`
- `EnqueueSteering`
- `EnqueueFollowUp`
- `InterruptTurn`
- `ResolveApproval`
- `ResumeSession`
- `ForkSession`
- `RewindSession`
- `CompactSession`

Core events include:

- `TurnStarted`
- `UserInputAccepted`
- `ContextBuilt`
- `ModelRequested`
- `AssistantDelta`
- `AssistantMessageCompleted`
- `ToolProposed`
- `PolicyDecided`
- `ApprovalRequested`
- `ApprovalResolved`
- `ToolStarted`
- `ToolOutputDelta`
- `ToolCompleted`
- `CheckpointCreated`
- `VerificationRecorded`
- `CompactionCompleted`
- `TurnCompleted`
- `TurnInterrupted`
- `TurnFailed`

Each durable event envelope contains:

- event and schema version;
- event, session, branch, turn, and causation identifiers;
- monotonically increasing session sequence;
- timestamp supplied by an injectable clock;
- actor and frontend provenance;
- sanitized payload;
- optional content-addressed artifact references.

The storage transaction appends an event before the kernel exposes the corresponding
durable state. Streaming text and process output may be ephemeral deltas, but their
bounded final form and hashes are persisted. A replay rebuilds projections from durable
events and never re-executes tools.

Schema evolution is additive where practical. Readers reject unknown mandatory
semantics instead of guessing. Migrations are forward-only and checksum-verified.

## Turn state machine

A normal turn follows this state machine:

1. Accept and persist the user input.
2. Snapshot workspace metadata needed for stale-state checks.
3. Assemble a token-budgeted context and persist its ledger.
4. Request a model response through the selected provider.
5. Normalize streaming text, usage, finish reasons, and proposed tool calls.
6. Validate every tool proposal against its typed schema.
7. Convert it to a normalized capability request.
8. Evaluate policy as `allow`, `ask`, or `deny`.
9. If required, persist and surface a bound approval request.
10. Revalidate the approval, workspace state, and file/process preconditions.
11. Execute the tool through the selected sandbox backend.
12. Bound, redact, hash, persist, and return the tool result to the context engine.
13. Continue until a completion contract passes, the user interrupts, or a hard budget
    is reached.
14. Persist `TurnCompleted`, `TurnInterrupted`, or `TurnFailed`.

The loop is iterative, not recursively self-calling. Every iteration observes hard
limits for model requests, tool calls, wall time, provider usage, tool output, and
context size.

Providers may return multiple tool proposals, but V1 executes them in proposal order,
one at a time. This preserves deterministic policy, approval, event, and workspace
semantics. Parallel read-only execution may be added later only when the tool registry
can prove the calls have no shared mutable state.

After a crash, Carl marks an in-progress turn interrupted. It never automatically
repeats a tool whose completion is unknown. Read-only idempotent operations may be
offered for explicit retry. Mutations require a new proposal and policy decision.

## Steering, follow-up, and interruption

Carl maintains three distinct user-control paths:

- **Steering** messages are injected at the next safe model/tool boundary and may alter
  the active turn.
- **Follow-up** messages remain queued until the active turn reaches a terminal state,
  then start in order.
- **Interrupt** cancels provider streaming and child processes, records partial output,
  and ends the active turn without discarding the session.

The queue is durable. Frontend reconnects cannot duplicate or lose accepted messages.
An interrupt has priority over new model work, but cannot erase a tool result already
committed by the operating system.

## Context engine

Every model request produces a context ledger visible through `carl context` and the
TUI. The ledger records each source, precedence, bytes, estimated tokens, truncation,
and inclusion reason.

Instruction precedence, highest to lowest:

1. Carl's compiled security and protocol contract.
2. user-level `CARL.md`;
3. repository `CARL.md` or compatible `AGENTS.md`;
4. directory-scoped instructions from workspace root to active directory;
5. explicitly selected skill instructions;
6. explicit durable memories;
7. compacted session summary and recent events;
8. current user input and tool results.

Lower-precedence content cannot grant capabilities or override policy. Untrusted
repository instructions are labeled as workspace content until the project is trusted.
Carl shows the resolved instruction files and any conflicts.

### Compaction

Compaction is an explicit event that creates a new context projection. Its structured
summary contains:

- current goal and completion contract;
- user constraints and operating decisions;
- work completed and verification evidence;
- next actions;
- relevant facts and unresolved questions;
- files read, modified, or created;
- active approvals, processes, and queued messages;
- failures and retry restrictions.

The summary stores references to source event ranges and artifact hashes. Original
events remain queryable. A deterministic validation step rejects a compaction missing
required fields. Carl can display the exact context before and after compaction.

### Memory and skills

Long-term memory is curated, not ambient. A memory records its text, provenance, scope,
creation event, status, and optional expiration. The agent may propose a memory; V1
persists it only after explicit approval.

Skills are public instruction bundles with small metadata headers. Discovery loads
metadata only; full instructions load progressively when selected. Skills cannot run
setup code, add tools, access credentials, or bypass policy. V1 searches:

- `.carl/skills/` in the trusted project;
- the configured user skill directory;
- built-in read-only skills shipped with Carl.

## Provider boundary

The provider trait accepts normalized messages, tool schemas, model options, deadline,
and cancellation. It emits normalized text deltas, tool-call fragments, completed tool
calls, usage, finish reason, and typed errors.

V1 production adapters:

- OpenAI Responses API using a documented OpenAI Platform API key;
- xAI Responses API using a documented xAI API key;
- a configurable OpenAI-compatible adapter;
- Ollama and LM Studio presets over that compatible adapter.

The native provider interface supports `none` and `api_key` credential modes.
Subscription authentication is a separate delegated-agent boundary because the
supported provider protocols expose coding agents rather than raw model sampling:

- ChatGPT subscription login is owned by a Carl-isolated Codex sidecar. Carl uses the
  documented Codex app-server authentication surface and stable `codex mcp-server`
  delegation without receiving or reading tokens.
- Grok subscription login is owned by a Carl-isolated Grok Build sidecar. Carl uses
  `grok --no-auto-update login` and the documented
  `grok --no-auto-update agent stdio` ACP surface without receiving or reading tokens.

Carl will not read Codex, ChatGPT, or Grok credential stores; copy provider OAuth client
identities; or call private authentication endpoints. A native xAI OAuth adapter may be
enabled after xAI registers or explicitly authorizes a Carl client identity. A native
OpenAI subscription adapter requires a future public third-party sampling flow.

Provider capabilities are explicit: streaming, native tools, parallel proposals,
reasoning items, usage reporting, context window, prompt caching, and structured
output. Carl snapshots the provider and model capability set used by each turn.

Delegates are tools inside Carl's native loop, never alternate top-level engines. Each
invocation passes through Carl policy and bound approval and operates only on a
content-scanned staging copy. V1 returns bounded, inert exact-replacement proposals for
existing text files; it rejects create/delete/rename operations. Each replacement
changes the live workspace only through a separate native patch proposal after
independent policy, approval, stale-state, and verification checks. The event journal
and UI identify Codex and Grok delegate work, and Carl does not attribute a delegate's
inner tool execution or verification to its own trusted core.

Provider contract tests use deterministic scripted streams and redacted HTTP cassettes.
Cassettes contain no bearer tokens, cookies, personal prompts, or identifying request
headers. Live-provider tests are opt-in, cost-capped, and never required for normal
contributor CI.

## Tool runtime

The initial coding tool set is intentionally narrow:

- `fs.list`
- `fs.read`
- `fs.search`
- `fs.apply_patch`
- `shell.exec`
- `process.poll`
- `process.write`
- `process.terminate`

The personalization phase adds `memory.remember` and `memory.forget` through the same
registry and approval path. V1 does not include a general network-fetch or browser tool;
provider and Telegram transport networking are separately declared capabilities.

Every tool has typed inputs, generated JSON Schema, a normalized capability request,
declared side-effect class, cancellation behavior, output limits, and stable result
codes. The registry rejects duplicate names and unsupported schema features at startup.

Tools execute through a central router. The model cannot choose an implementation,
sandbox, approval mode, environment, or artifact retention policy.

### Patch safety

`fs.apply_patch` is Carl's preferred mutation primitive. It:

1. resolves every path relative to an open workspace capability without following
   escaping symlinks;
2. rejects `.git` and configured protected paths;
3. captures the expected hash for the existing target file;
4. parses the patch without changing disk state;
5. produces an exact diff and policy request without fuzzy matching;
6. binds approval to the normalized patch, path, hash, and workspace;
7. serializes Carl-owned mutations and rechecks the hash while holding that lock;
8. atomically replaces one file and rejects multi-file patch requests in V1;
9. stores before/after hashes and a recovery artifact;
10. creates a checkpoint event.

Stale state visible at the locked execution precondition fails closed and requires a
newly generated patch. Fuzzy application, partial single-file writes, hidden writes,
and approval reuse are prohibited. Mainstream portable filesystems do not expose an
atomic conditional replace keyed by both inode identity and content hash, so a
non-cooperating external writer can race the final check-to-rename interval. Carl keeps
that interval minimal and verifies the postcondition, but does not claim a portable
compare-and-swap guarantee against such an external writer.

### Shell and process tools

`shell.exec` receives an argument vector or a deliberately visible shell program,
working directory, timeout, output cap, and environment policy. Its approval display
shows the real executable, normalized arguments, cwd, network mode, and affected
capability class.

Long-running commands return a process handle. Poll, input, and termination operate on
that handle and preserve one ordered output stream. Cancellation first requests
graceful termination, then kills the process tree after a deadline. Provider,
Telegram, and other credentials are stripped from child environments unless a
credential is explicitly granted to that tool invocation.

## Policy, approvals, and sandbox

Policy consumes a normalized capability request containing:

- tool and schema version;
- normalized arguments and cryptographic digest;
- frontend and actor;
- workspace and canonical cwd;
- resolved executable path where relevant;
- file targets and expected hashes;
- network destinations;
- environment grant set;
- side-effect and risk classes.

It returns `allow`, `ask`, or `deny` plus a stable reason code. Rules compose from
compiled safety constraints, user configuration, trusted-project configuration, and
frontend-specific restrictions. A lower-trust source cannot loosen a higher-trust
rule.

An approval is a signed-by-state, single-use database record bound to the exact
capability request digest, actor, session, turn, expiration, and preconditions.
Changing arguments, cwd, executable resolution, environment grants, file hashes, or
network destinations invalidates it. Denial and expiration are terminal.

Default local mode:

- allow bounded workspace reads;
- ask before writes, shell execution, network access, memory mutation, or credential
  access;
- deny writes outside the workspace and direct `.git` mutation;
- deny secret inheritance and undeclared network access.

Default Telegram mode additionally asks for every mutation and shell command, uses
short approval expirations, and denies private-network destinations.

The sandbox backend is selected by platform and reports its effective guarantees.
V1 should use available native mechanisms on macOS and Linux, with a clearly labeled
restricted-process fallback. Carl refuses a configuration that claims stronger
isolation than the active backend provides.

## Sessions, branches, rewind, and checkpoints

SQLite in WAL mode stores the append-only journal and rebuildable projections.
Oversized output, snapshots, diffs, and provider recordings live in a content-addressed
artifact directory.

Carl distinguishes:

- **resume**: continue the same branch at its current head;
- **fork**: create a new branch whose history references an earlier event;
- **rewind context**: start a branch from an earlier conversational state without
  touching files;
- **restore files**: apply an explicit reverse patch from a checkpoint after preview
  and approval.

These operations are never presented as equivalent. A context rewind cannot imply that
filesystem effects were undone.

A checkpoint records event head, relevant file hashes, generated diff artifacts,
workspace identity, and optional git status metadata. It does not silently create git
commits. Restoration rejects stale or conflicting files and never uses destructive git
reset operations.

## Completion contracts and verification

At turn start, the runtime derives or asks for a completion contract: the requested
outcome, required checks, and hard constraints. The contract is visible and can be
edited by the user.

Before claiming success, Carl records:

- files changed;
- exact verification commands;
- exit codes and bounded output;
- skipped checks and explicit reasons;
- remaining workspace changes;
- whether results are deterministic, live-provider, or inferred.

The model may suggest verification, but the harness records what actually ran. A failed
required check prevents a successful terminal status unless the user explicitly
changes the contract. Final answers link to the evidence rather than merely asserting
that tests pass.

## TUI interaction model

The TUI is a thin protocol client. Its primary view shows:

- conversation and streamed output;
- active plan/completion contract;
- running tool and elapsed time;
- steering and follow-up queues;
- pending approvals with exact diffs or command details;
- changed files and verification state;
- context usage, model, workspace, sandbox, and policy profile.

Detailed traces stay one action away but do not flood normal conversation. The user can
inspect context sources, tool inputs/results, policy reasons, provider usage, artifacts,
and event ordering.

Plan mode permits reads and analysis while preventing mutation. Moving from plan mode
to implementation is an explicit user or policy transition, not a phrase inferred from
model text.

## Isolated subagents

Subagents arrive after the single-agent kernel, replay, and evaluations are stable.
Each subagent runs as a separate `carl` process with:

- a fresh bounded context;
- a dedicated git worktree when code mutation is allowed;
- a strict subset of parent capabilities;
- its own budgets and cancellation token;
- a structured task and completion contract;
- no subagent-spawning capability in the first version.

Only the coordinator owns the primary Carl data directory and SQLite database.
Subagents receive an ephemeral worker directory and communicate with the coordinator
through the versioned protocol. The coordinator validates and persists their reported
events and artifacts. This preserves the accepted single-owner storage invariant while
allowing operating-system process isolation.

The parent receives a structured report containing result, evidence, event/artifact
references, commits or diffs, unresolved risks, and cost. It does not receive a hidden
chain of thought. Merging a subagent's worktree is a separate previewable operation.

## Headless protocol and Telegram

Carl exposes a versioned local protocol before Telegram is implemented. V1 may use
JSON Lines over stdin/stdout for one-shot automation and a loopback-only local socket
for reconnecting clients. Both transport the same typed commands, events, snapshots,
and error envelopes.

Protocol rules:

- clients negotiate a version and declared capabilities;
- commands have idempotency keys;
- event sequence numbers support reconnect and catch-up;
- slow clients receive bounded snapshots rather than unbounded replay buffers;
- authorization and transport identity are separate from session identity;
- unknown mandatory fields fail explicitly.

Telegram remains a V1 requirement and is implemented as a client of this protocol.
It uses long polling, a single-owner private-chat pairing flow, durable update
deduplication, and persisted offsets. Groups, channels, and unpaired users are ignored
before model invocation.

Remote approvals display the exact normalized operation, diff or command, risk class,
workspace, expiration, and one-time decision controls. Callback replay is harmless.
Telegram messages never expose secrets, raw environment values, or unrestricted local
artifact paths.

## Configuration, trust, and diagnostics

Configuration layers, highest precedence first:

1. explicit CLI flags;
2. environment variables for automation;
3. trusted project configuration;
4. user configuration;
5. compiled defaults.

`carl config explain KEY` reports the winning value's source without revealing secret
values. Credential configuration stores references; secrets use the operating-system
credential store where available or process environment for automation.

A project is untrusted on first open. Before trust is granted, project instructions,
skills, and configuration cannot loosen policy or request credentials. Trust is bound
to a canonical path and visible repository identity.

`carl doctor` verifies configuration parsing, migrations, database integrity, artifact
permissions, provider credentials and connectivity, sandbox availability, workspace
access, project trust, protocol compatibility, and Telegram state. Its export is
sanitized by construction.

## Error handling and recovery

Errors have stable public codes and sanitized user messages with separate internal
causal detail. Domains include configuration, authentication, provider, protocol,
policy, approval, validation, stale state, tool, sandbox, storage, channel, timeout,
cancellation, budget, and verification.

Carl retries only operations known to be safe:

- transient provider and Telegram transport failures use bounded backoff and jitter;
- server-provided retry delays are honored;
- authentication, validation, policy, and stale-state failures are not retried;
- tool mutations are never implicitly retried;
- storage write failure stops consequential work;
- unknown tool completion after a crash becomes an interruption requiring review.

Database corruption or incompatible schemas fail closed with non-destructive recovery
instructions. Projection corruption may be repaired by replaying the journal after
integrity verification.

## Replay, evaluation, and observability

Replay has three modes:

- **projection replay** rebuilds session state from durable events;
- **provider replay** substitutes redacted recorded model streams while real tools run
  only in disposable fixture workspaces;
- **scenario simulation** uses scripted provider events and deterministic fake time,
  policy, and tools.

The evaluation suite uses small real repositories with pinned commits and tasks such as
bug fixes, refactors, feature additions, interrupted commands, stale patches, malicious
instructions, compaction, and approval replay attempts.

Every scenario records:

- task success and required-check success;
- regressions and files touched outside the expected set;
- model requests, tool calls, invalid calls, and approval count;
- tokens, wall time, and provider-reported cost;
- context compactions and dropped-source warnings;
- policy violations, secret-redaction failures, and orphaned processes;
- event-log determinism after normalization.

CI runs deterministic scenarios. A scheduled or manually triggered job may run
cost-capped live-model evaluations using repository secrets. Results are retained as
versioned artifacts and summarized against a checked-in baseline. Performance claims
must name the model, fixture version, policy, and measurement date.

Structured tracing derives from the same domain events and redacts before export.
OpenTelemetry export can be added later as an opt-in adapter; it is not a second event
system.

## Extension strategy

V1 extensions are skills and external tools only. Built-in Rust tools cover trusted
core operations. Later integrations use one of:

- MCP with explicit tool schemas and the normal Carl policy boundary;
- a versioned subprocess protocol with OS-process isolation;
- a separately reviewed built-in adapter.

Carl will not load native dynamic libraries into the trusted process or execute
arbitrary skill-owned setup code. Extension installation, catalogs, and auto-update are
post-V1 and opt-in.

## Delivery sequence

### Phase 1: Carl identity and public contract

- Rename the package, executable, docs, configuration directories, and public types.
- Add `CARL.md` with Stephen's public personality and operating principles.
- Update repository metadata and GitHub repository name.
- Preserve the current deterministic tests under the Carl identity.

### Phase 2: Vertical coding loop

- Implement context assembly, one live provider, tool routing, read/search/patch,
  verification evidence, and a final response.
- Prove one end-to-end repository fix through a deterministic scenario.
- Establish the native-provider versus subscription-delegate boundary.

### Phase 2B: Subscription delegates

- Add isolated provider homes and authentication status without exposing delegate
  execution.
- Add ChatGPT browser/device login through Codex-owned authentication and expose Codex
  as a delegated specialist through `codex mcp-server` after Phase 3.
- Add Grok browser/device login through Grok Build and expose Grok as a delegated
  specialist through ACP after Phase 3.
- Prove login-state, protocol-compatibility, cancellation, redaction, and fake-sidecar
  scenarios without live credentials in CI.

### Phase 3: Policy, approvals, and sandbox

- Add normalized capabilities, ask/allow/deny policy, bound approvals, secret filtering,
  platform sandbox reporting, and shell/process tools.
- Add stale-state, approval replay, path escape, environment leak, and cancellation
  tests.

### Phase 4: TUI and active control

- Add streaming conversation, diffs, approvals, steering, follow-up, interrupt,
  completion-contract status, and session resume.

### Phase 5: Context and history

- Add context ledger, structured compaction, checkpoints, fork, context rewind, explicit
  file restore, curated memory, and instruction provenance.

### Phase 6: Replay and evaluation

- Add provider cassettes, fixture repositories, scenario metrics, regression baselines,
  and sanitized trace export.

### Phase 7: Isolated subagents

- Add separate-process workers, worktree isolation, capability subsets, structured
  results, cancellation, and merge review.

### Phase 8: Personalization and operations

- Add progressive skills, project trust, configuration provenance, credential-store
  support, and comprehensive `doctor`.

### Phase 9: Headless protocol

- Add version negotiation, idempotent commands, reconnectable event streaming,
  snapshots, and automation documentation.

### Phase 10: Telegram V1

- Add single-owner pairing, long polling, deduplication, session control, streaming
  rendering, cancellation, and bound remote approvals over the headless protocol.

Phases are ordered risk retirement, not independent marketing milestones. A phase is
complete only when its acceptance tests pass.

## V1 acceptance criteria

V1 is complete only when all of the following are true:

- `carl` installs as one documented executable on supported macOS and Linux targets.
- A new user can configure OpenAI, Ollama, or LM Studio and complete a coding task
  through the TUI.
- The deterministic evaluation suite fixes at least one real fixture bug, applies a
  feature patch, survives interruption, and rejects adversarial policy scenarios.
- Every workspace mutation has a durable proposal, policy decision, applicable
  approval, precondition check, result, and checkpoint.
- Single-file patch replacement is atomic; every stale condition visible at Carl's
  locked precondition is rejected, as are traversal, symlink escape, multi-file patch
  requests, and protected paths. The documented external-writer race is not presented
  as a portable compare-and-swap guarantee.
- Shell cancellation terminates child process trees and leaves no test-owned orphan.
- Secrets do not appear in stored events, diagnostics, exported traces, child
  environments, provider cassettes, or Telegram output.
- Sessions can resume, fork, compact, rewind context, and explicitly restore files with
  the distinctions visible to the user.
- The context inspector accounts for every source and reports truncation.
- Required verification failures prevent a successful completion status.
- Projection replay is deterministic from a fresh database.
- The TUI and Telegram use the same versioned protocol and kernel.
- An unpaired Telegram user cannot invoke the provider, tools, approvals, or session
  reads.
- Restarting Telegram processing does not duplicate a handled update or approval.
- CI passes formatting, linting, tests, dependency policy, secret scanning, and
  deterministic evaluation on every pull request.
- The README contains a truthful architecture overview, security limitations, demo,
  benchmark methodology, and contributor path.

## Rejected alternatives

### Broad assistant platform first

Copying OpenClaw or Hermes breadth would bury the engineering signal under provider,
channel, and deployment work. Carl earns breadth only after the coding kernel is
measurably reliable.

### Minimal loop without security

Pi's legibility is the right size target, but its lack of a built-in permission and
sandbox boundary is unacceptable for a personal agent that edits code and runs
commands.

### Multi-crate framework immediately

A crate graph before real consumers would add ceremony and slow interface correction.
Internal boundaries and contract tests provide the useful discipline now; extraction
can follow the headless protocol.

### In-process plugin ecosystem

Arbitrary extension code in the trusted process destroys the value of centralized
policy, redaction, and recovery. Skills, MCP, and subprocesses cover V1 extensibility
with inspectable boundaries.

### Transcript-only storage

A message transcript cannot explain policy decisions, partial tools, approvals,
interruptions, context compaction, or verification. Typed events are required for
replay and trustworthy debugging.

### Git as the session database

Git is valuable workspace evidence, but not all directories are repositories and agent
events do not map cleanly to commits. Carl records git metadata without making git its
runtime state store.

### Telegram-specific agent logic

A second remote loop would drift in policy, context, and replay behavior. Telegram is a
protocol client with stricter policy, not a second harness.

### Undocumented consumer OAuth

Reusing another application's tokens is fragile and creates unclear consent and
credential provenance. Carl waits for an officially documented third-party flow.

## Primary references

- [Pi repository](https://github.com/earendil-works/pi)
- [Pi agent loop](https://github.com/earendil-works/pi/blob/main/packages/agent/src/agent-loop.ts)
- [Pi sessions](https://pi.dev/docs/latest/sessions)
- [Pi compaction](https://pi.dev/docs/latest/compaction)
- [Pi RPC mode](https://pi.dev/docs/latest/rpc)
- [OpenAI Codex repository](https://github.com/openai/codex)
- [Codex Rust architecture](https://github.com/openai/codex/blob/main/codex-rs/README.md)
- [Codex turn loop](https://github.com/openai/codex/blob/main/codex-rs/core/src/session/turn.rs)
- [Codex app-server protocol](https://github.com/openai/codex/blob/main/codex-rs/app-server/README.md)
- [Codex approvals and security](https://developers.openai.com/codex/agent-approvals-security)
- [Claude Code: how it works](https://code.claude.com/docs/en/how-claude-code-works)
- [Claude Code permission modes](https://code.claude.com/docs/en/permission-modes)
- [Claude Code checkpointing](https://code.claude.com/docs/en/checkpointing)
- [Claude Code subagents](https://code.claude.com/docs/en/sub-agents)
- [Claude Code license](https://github.com/anthropics/claude-code/blob/main/LICENSE.md)
- [OpenCode repository](https://github.com/anomalyco/opencode)
- [OpenCode server](https://opencode.ai/docs/server/)
- [OpenCode permissions](https://opencode.ai/docs/permissions)
- [OpenCode HTTP recorder](https://github.com/anomalyco/opencode/tree/dev/packages/http-recorder)
- [Hermes Agent repository](https://github.com/NousResearch/hermes-agent)
- [Hermes architecture](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/developer-guide/architecture.md)
- [Hermes prompt assembly](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/developer-guide/prompt-assembly.md)
- [Hermes memory](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/memory.md)
- [Hermes security](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/security.md)
- [OpenClaw architecture](https://docs.openclaw.ai/concepts/architecture)
- [OpenClaw gateway protocol](https://docs.openclaw.ai/gateway/protocol)
- [OpenClaw agent loop](https://docs.openclaw.ai/agent-loop)
- [OpenClaw execution approvals](https://docs.openclaw.ai/tools/exec-approvals)
- [OpenClaw security](https://docs.openclaw.ai/security)
