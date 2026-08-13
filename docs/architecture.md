# Architecture

Status: pre-alpha with a usable subscription-backed ACP/Buzz path. The
[top-tier design](superpowers/specs/2026-07-23-carl-top-tier-harness-design.md)
defines the broader product target, while the
[Buzz ACP design](superpowers/specs/2026-08-10-carl-buzz-acp-design.md) defines the
implemented integration boundary.

## System shape

```text
Buzz relay
    |
    v
buzz-acp -- ACP/stdio --> carl acp (Buzz ACP frontend)
                               |
Other ACP client -------------+
                               v
                         kernel actor
                     /         |          \
          SQLite journal   exact policy   Codex app-server
                                              |
                                      ChatGPT subscription

kernel -- typed publication --> restricted carl-buzz-mcp --> Buzz CLI --> relay

auth CLI --> provider-owned authentication brokers --> isolated provider homes
```

Frontends parse bounded transport input and translate it to kernel commands. They do
not directly sample a model, execute coding actions, grant approvals, or mutate
durable session state. The kernel serializes session transitions, owns the provider
port, persists accepted state before exposure, and maps normalized results back to
ACP updates and the originating Buzz thread.

## Implemented subscription-backed coding path

`carl acp` canonicalizes and locks one data root, starts the pinned Codex app-server,
discovers its model catalog, starts the kernel actor, and serves bounded newline JSON
RPC on stdin/stdout. ACP v1 and Buzz's v2-shaped contract support initialize,
session creation, prompts, configuration, cancellation, and steering. Assistant
chunks, tool lifecycle, diffs, available commands, and session configuration are
mapped to typed updates.

The kernel retains a provider turn across an exact approval boundary. Approval and
remote-bypass display codes are stored only as digests and bound to the durable
actor, frontend session, Carl session, turn, tool/provider request, workspace, exact
request digest, and expiry. A later valid slash command atomically consumes the code
and resumes the same turn. Cancellation interrupts the exact provider turn. A crash
or ambiguous publication never causes automatic replay of consequential work.

Buzz-specific parsing and publishing remain outside provider modules. The Buzz ACP
frontend extracts current event, channel, author, and reply identity from the exact
pinned context shape. The restricted publisher accepts only the `carl-buzz-mcp`
descriptor and passes its credential allowlist only to a trusted Buzz CLI process.
Provider children receive no Buzz variables.

## Durable model

SQLite WAL is the audit, replay, and local-memory source. Forward migrations are
checksum-verified.
ACP bindings persist external session, client, protocol, canonical cwd, stable
channel, provider thread, and permission mode without storing relay credentials or
raw remote codes. Delivery transitions are monotonic; uncertain delivery is durable
and not silently retried. Stable channel claims invalidate obsolete remote codes on
process replacement.

V1 permits one Carl process to own one canonical data root. Every public auth and ACP
entry point acquires one exclusive OS lock per canonical data root. A single process
may multiplex ACP sessions, but Buzz uses one agent pool (`BUZZ_ACP_AGENTS=1`). This
is intentionally not a multi-daemon coordination protocol.

## Implemented modules

- `events`: versioned provider-neutral events, stable identifiers, frontend binding,
  approval, permission, delivery, and interruption records.
- `storage`: SQLite migrations and projections for sessions, append-only events,
  remote codes, ACP frontends, channel claims, provider turns, and at-most-once
  delivery actions.
- `memory`: local owner/agent and global/workspace/session partitions; curated
  profile, preference, fact, goal, and episode records; bounded lexical ranking;
  proposal approval; expiration, capacity, versioned export, and hard deletion.
  No external memory provider or embedding dependency is required.
- `sidecar`: exact executable identity/version checks, duplex bounded JSONL,
  closed child environments, process-tree supervision, cancellation, deadlines, and
  aggregate output limits.
- `auth`: provider-owned authentication brokers, isolated provider homes, and
  composition for the seven `auth` commands. Authentication status performs only
  provider-owned local handshakes and never samples a model.
- `delegates`: bounded model and reasoning settings, the legacy inert
  `codex exec --json` boundary, and the live Codex app-server port used by ACP.
- `acp::protocol` and `acp::server`: bounded JSON-RPC framing, honest capabilities,
  request dispatch, one serialized stdout writer, session updates, and lifecycle
  cleanup.
- `acp::kernel`: durable session ownership, turn lifecycle, mode enforcement,
  exact approvals, steering, cancellation, diffs, final publication, and recovery.
- `acp::buzz` and `buzz_mcp`: structural Buzz context parsing, closed credential
  descriptors, exact literal-argv publication, and a two-tool MCP surface.
- `policy`: normalized external-agent capability requests and a closed evaluator
  whose exact request digest includes its verification specification.
- `security`: a non-retaining high-confidence secret filter.
- `staging`: bounded, capability-relative construction of disposable work copies,
  a sealed baseline, and process-free exact replacement proposal inspection.
- `artifacts` and `verification`: content-addressed evidence, fresh independent
  verification candidates, approved executable/argv attestation, bounded execution,
  and post-commit verified-proposal capabilities.
- `cli`: safe authentication JSON, local `carl memory` management, the streaming
  `carl acp` entry point, and the argv-zero restricted publisher alias.

## Authentication and execution separation

The auth runner and ACP runner share executable validation, provider homes, and data
root locking but have distinct authority. OAuth ceremonies stay inside provider-owned
authentication brokers. Carl receives sanitized state, never bearer or refresh
tokens. `carl acp` starts inference only after a separate app-server handshake and
model-catalog validation; authentication state alone does not prove entitlement.

Codex app-server receives a closed environment rooted at the isolated Codex home.
Codex uses explicit file credential storage in that owner-private home; Carl validates
`auth.json` metadata before provider launch without reading its contents.
Buzz relay credentials exist only inside the narrow publisher path. This separation
lets the subscription-backed coding path operate without turning provider or relay
credentials into general model context.

## Safety foundations not yet integrated as native tools

The external-agent library boundaries are intentionally stricter than the current
Codex-owned coding tool surface:

- `policy`: normalized external-agent capability requests default safe work to exact
  owner approval and deny live-workspace or credential authority drift;
- `security`: a non-retaining high-confidence secret filter rejects a complete unsafe
  value without retaining the matched bytes;
- `staging`: bounded, capability-relative construction produces an isolated copy and
  sealed baseline;
- a process-free inspector accepts only no change or one exact replacement proposal;
- independent verification reconstructs a fresh candidate from sealed artifacts.

These modules do not yet form a user-reachable native Carl tool loop. Stale-safe
promotion into a live workspace remains unimplemented. The ACP coding path instead
uses the Codex app-server's coding capabilities under Carl's mode and exact approval
boundary.

## Long-horizon task lifecycle

The private task service owns one durable task actor at a time. ACP admission records
the immutable workspace, budget, completion contract, provider/model selection, and
initial context binding before provider work begins. Each consequential tool request
is represented by a durable operation intent and state transition; the journal is the
authority and the task snapshot is a checked projection.

At a safe epoch boundary the engine verifies operation evidence and the structured
epoch report, commits a canonical checkpoint, performs context compaction when needed,
and returns the task to `active`. The checkpoint carries its event-source range,
previous-checkpoint lineage, completion clauses, exact identifiers, operation summaries,
usage, and next objective. Startup validates that lineage and replays the journal tail
instead of trusting checkpoint JSON or a mutable projection by itself.

Recoverable maintenance asks the actor to quiesce at the next committed boundary,
publishes a `ready` task/checkpoint binding, and then stops the provider once. A fresh
service and ACP connection use `session/load` to bind the same task. If the provider
cannot resume its context, provider context replacement records the loss, constructs a
new context from the canonical checkpoint package, and continues without redispatching
successful effects. An unresolved `Started` operation is reconciled as uncertain and
blocks automatic replay.

Metrics are reduced from the task journal in bounded pages and compared with the final
snapshot. They expose counts, status, contract progress, budget usage, and checkpoint
progress without assistant text or command output. See the
[long-horizon task guide](long-horizon-tasks.md) for the frontend methods and the
[benchmark methodology](benchmarks.md) for tested limits.

## Remaining product work

There is no interactive TUI, Telegram gateway, Grok execution port, native HTTP
provider, complete native tool router, stale-safe promotion path, multi-process data
root coordination, or release installer. Stable boundaries are event persistence,
provider isolation, exact permission decisions, frontend translation, and fail-closed
protocol handling; concrete product surfaces remain subject to tested evolution.
