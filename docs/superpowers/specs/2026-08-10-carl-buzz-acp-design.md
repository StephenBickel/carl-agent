# Carl–Buzz ACP Compatibility Design

Status: approved in conversation; written-spec review pending
Date: 2026-08-10
Decision owner: Stephen Bickel

## Purpose

This document defines how Carl will become a first-class agent in Buzz while
remaining a small, transport-neutral coding harness. Buzz will own community
identity, channel membership, message admission, and relay behavior. Carl will own
reasoning, provider access, durable sessions, model and effort selection, coding
tools, permissions, approvals, cancellation, and verification.

The selected integration is an Agent Client Protocol (ACP) server exposed as
`carl acp`. Carl will not add a direct Nostr or Buzz relay client to its trusted
kernel. The same ACP endpoint will be usable by Buzz and other compatible clients.

This design extends, rather than replaces, the approved
[top-tier Carl design](2026-07-23-carl-top-tier-harness-design.md). The event-sourced
runtime, provider-sidecar authentication, single-process ownership, and exact
approval decisions remain in force.

## Research basis

Buzz's current open-source repository establishes the integration contract used by
this design:

- Buzz is a self-hostable workspace in which people and agents share rooms and
  signed events: <https://github.com/block/buzz/blob/main/README.md>.
- `buzz-acp` connects relay events to any ACP agent over newline-delimited JSON-RPC
  on stdio: <https://github.com/block/buzz/blob/main/crates/buzz-acp/README.md>.
- Buzz supports user-defined ACP harnesses without requiring an upstream change:
  <https://github.com/block/buzz/blob/main/crates/buzz-acp/README.md#bring-your-own-harness>.
- Buzz requests ACP protocol v2 today while retaining a v1-shaped base contract;
  its v2 work is explicitly ahead of the upstream protocol process:
  <https://github.com/block/buzz/blob/main/crates/buzz-acp/src/acp.rs>.
- Buzz exposes Claude-compatible permission values through
  `session/set_config_option`, but its current bridge defaults to
  `bypassPermissions`:
  <https://github.com/block/buzz/blob/main/crates/buzz-acp/src/config.rs>.
- Buzz currently auto-selects `allow_once` for every ACP
  `session/request_permission`, so Carl cannot use that request as its human approval
  boundary:
  <https://github.com/block/buzz/blob/main/crates/buzz-acp/src/acp.rs>.
- Buzz passes relay credentials to the configured MCP subprocess. Carl must contain
  those values instead of exposing a credential-bearing general shell:
  <https://github.com/block/buzz/blob/main/crates/buzz-acp/src/lib.rs>.

Claude Code and Codex provide the permission model users already recognize:

- Claude Code offers plan, edit-acceptance, manual, don't-ask, and bypass modes:
  <https://docs.anthropic.com/en/docs/claude-code/cli-usage>.
- Codex's dangerous bypass combines approval policy `never` with
  `danger-full-access`:
  <https://github.com/openai/codex/blob/main/codex-rs/cli/src/main.rs>.

Buzz is new and its extensions may change. Carl will pin a tested Buzz/ACP contract
in fixtures, negotiate capabilities, and fail closed when a required behavior is not
available.

## Product outcome

In the completed experience, Stephen can add Carl to Buzz, mention it in a channel
or DM, choose the model, reasoning effort, and permission mode, ask it to perform a
coding task, steer or cancel it, review an exact approval request, and receive the
verified result in the originating Buzz thread. Carl will use the same subscription
authentication, memory, policy, tools, and durable history that its local interfaces
use.

Buzz controls who may trigger a turn. The recommended and documented default is
`owner-only`; Buzz may later expose allowlists or other admission policies without a
Carl code change.

## Goals

- Make `carl acp` a conforming, reusable ACP agent entry point.
- Make Carl selectable as a custom Buzz harness using the installed `carl` binary.
- Preserve Carl's provider-sidecar subscription authentication, including model and
  reasoning-effort selection.
- Give Buzz sessions the familiar Claude Code/Codex permission modes.
- Support exact, durable, single-use approval from Buzz despite Buzz's current ACP
  auto-approval behavior.
- Keep Buzz identity credentials outside model prompts, provider requests, logs,
  durable events, and general-purpose command environments.
- Stream useful progress and tool status while posting human-facing results to the
  correct Buzz thread.
- Handle cancellation, steering, crashes, timeouts, and uncertain delivery without
  duplicating consequential work.
- Prove compatibility with deterministic subprocess tests and an opt-in live
  subscription smoke test.

## Non-goals

- Reimplementing Buzz channels, identity, Nostr signing, relay subscriptions, or
  author admission inside Carl's kernel.
- Forking Buzz or requiring a Carl-specific Buzz deployment.
- Treating ACP recognition alone as a functional integration.
- Adding Slack, Discord, or other team transports as part of this work.
- Building a general networked MCP gateway.
- Running multiple Carl processes against one `CARL_DATA_DIR` in V1.
- Claiming that dangerous bypass is safe on an untrusted host or repository.
- Making Buzz a dependency of Carl's core runtime or provider modules.

## Alternatives considered

### Selected: Carl-native ACP endpoint

`carl acp` translates ACP requests into Carl commands and Carl events into ACP
updates. It keeps Carl's identity as a real harness, composes with Buzz's intended
bring-your-own-harness seam, and remains useful outside Buzz.

### Rejected: direct Buzz relay transport

A direct WebSocket/Nostr client would expose more Buzz-specific control but duplicate
`buzz-acp`, bind Carl to a rapidly changing relay API, expand the trusted codebase,
and reduce reuse. A narrow, credential-isolated Buzz publishing adapter is permitted
only for sending the already-produced Carl result through the tool boundary; it is
not a second inbound transport.

### Rejected: wrapper around Codex or Claude Code ACP

This would reach a demo quickly but move sessions, policy, tools, and execution out of
Carl. It would make Carl branding around another harness rather than evidence of
harness engineering.

## Architecture

```text
Buzz relay
   |
   | signed events, membership, owner admission
   v
buzz-acp
   |
   | ACP JSON-RPC over stdio
   v
carl acp
   |-- ACP codec and capability negotiation
   |-- ACP session registry
   |-- Buzz context and command adapter
   |-- credential-isolated Buzz publisher
   |
   | Carl commands and provider-neutral events
   v
Carl kernel
   |-- durable sessions and context
   |-- subscription provider adapters
   |-- model and reasoning configuration
   |-- tool router, policy, approvals, sandbox, verification
   `-- SQLite event journal and projections
```

`carl acp` is a frontend. It may validate transport syntax, manage ACP request
lifecycle, and extract typed transport metadata, but it may not call a model, execute
a coding tool, grant an approval, or mutate durable session state outside kernel
commands.

### ACP codec and server

The server reads bounded, newline-delimited JSON-RPC frames from stdin and uses one
serialized writer for stdout. All diagnostics go to stderr. Empty lines may be
ignored; malformed, oversized, or structurally invalid frames receive a bounded
protocol error where the request can be identified. Parser failures must not corrupt
other sessions.

Carl negotiates ACP v1 and the Buzz-requested v2 shape. It advertises only implemented
capabilities. V1 includes:

- `initialize`
- `session/new`
- `session/prompt`
- `session/cancel`
- `session/set_config_option`
- `session/update` notifications for assistant messages and tool lifecycle
- `_session/steering` only when the Carl runtime steering queue is connected

`session/load`, images, audio, delegated filesystem methods, and networked MCP
transports remain unadvertised until implemented and tested.

### Configuration options

The `session/new` result exposes typed options for:

- `model`: only models reported by the active provider adapter;
- `thought_level`: only reasoning efforts supported by the selected model/provider;
- `mode`: the permission values defined below.

`session/set_config_option` validates every value before appending the corresponding
Carl configuration event. Unsupported values return a protocol error and do not
silently fall back.

Local startup also accepts:

```text
carl acp --model <id> --effort <level> --permission-mode <mode>
```

`--dangerously-bypass-permissions` is a visible alias for
`--permission-mode bypassPermissions`; it is never implied by a shorter or
innocent-looking flag.

Session configuration overrides process defaults without mutating global user
configuration.

### Session registry and ownership

One `carl acp` process owns one Carl data root and can multiplex multiple ACP
sessions. Buzz must use `BUZZ_ACP_AGENTS=1` for V1. A second process attempting to
open the same data root fails before serving ACP requests.

Every successful `session/new` creates or binds one durable Carl session to:

- the ACP client identity and negotiated protocol;
- the external ACP session ID;
- the validated canonical working directory;
- the stable Buzz channel ID when the first Buzz context block supplies one.

Buzz's formatted context includes channel, event, author, and reply information.
Carl extracts that data with a bounded transport parser and stores it outside model
conversation text. The parser never treats these fields as a replacement for Buzz's
author gate. If a stable channel cannot be proven, Carl keeps an ACP-process-scoped
mapping and starts a new branch after restart rather than guessing identity.

One turn may run at a time per session. Cross-session concurrency is bounded by Carl's
runtime budget. New input may queue, steer, or cancel according to the runtime's
existing command semantics.

## Permission model

Carl uses wire names already understood by Buzz and Claude-compatible ACP clients.

| Mode | Carl behavior |
|---|---|
| `plan` | Read and reason only. Mutations and side-effecting commands are unavailable. |
| `default` | Read operations proceed. Edits, commands, network access, and external effects follow policy and may require exact approval. |
| `acceptEdits` | In-workspace edits may proceed without a prompt. Risky commands, network access, and external effects still follow policy. |
| `dontAsk` | Carl never waits for approval. Operations allowed by the active sandbox run; operations that would require escalation fail and return evidence to the model. |
| `bypassPermissions` | Carl skips approval prompts and uses unrestricted execution for exposed coding capabilities, equivalent in intent to Claude/Codex dangerous mode. |

Carl's published Buzz setup sets `BUZZ_ACP_PERMISSION_MODE=default`, overriding
Buzz's current bridge default of `bypassPermissions`. Carl also refuses to activate
bypass silently during session setup: an out-of-band request for
`bypassPermissions` leaves the session in its current mode and creates a pending
remote-bypass confirmation. Local startup in bypass remains immediate because the
operator chose the dangerous flag at the host terminal.

Bypass removes approval and sandbox enforcement for coding capabilities. It does not
invent tools, change Buzz membership, disclose control-plane secrets, or make
provider-owned credentials available to the model. Those are capability and process
boundaries rather than permission prompts.

### Changing modes

Modes can be selected locally at launch, through Buzz's out-of-band ACP configuration
control, or through Carl slash commands. Non-bypass out-of-band changes apply
immediately. An out-of-band bypass selection creates the same pending confirmation
as the slash command and does not widen access on its own. Buzz already passes a
leading slash command as a separate first ACP prompt block, so Carl does not infer a
control command from quoted channel history.

- `/permissions` reports the current mode and available values.
- `/permissions <mode>` changes the current session.
- Selecting `bypassPermissions` from chat returns a warning and a one-time
  confirmation code.
- `/confirm-bypass <code>` activates bypass for that session.
- `/permissions default` or another non-bypass mode deactivates bypass immediately.

Remote changes are session-scoped and revert to the configured process default when
the session is replaced. They are accepted only on the explicit slash-command block
delivered by the trusted ACP client. Buzz remains responsible for ensuring that the
triggering event passed its `owner-only` gate.

### Exact approvals in Buzz

Carl does not use ACP `session/request_permission` as the human decision because the
current Buzz client auto-approves that request. Instead:

1. The kernel persists the exact normalized tool proposal and policy decision.
2. The Buzz frontend posts the command, diff, relevant scope, expiry, and a short
   display code in the originating thread.
3. The turn ends in `waiting_for_approval`; no side effect has occurred.
4. `/approve <code>` or `/deny <code>` arrives as a separate slash-command block.
5. Approval resolution binds actor/session/turn/tool/request digest and consumes the
   existing durable approval record once.
6. Before execution, Carl revalidates executable, path, workspace, and proposal
   preconditions.
7. Expiry, replay, mismatched session, changed preconditions, or unknown codes fail
   closed and produce a new visible status.

The display code is an ergonomic lookup key, not the security identity. The durable
request digest and contextual binding remain authoritative.

## Buzz credential and publishing boundary

Buzz currently places `BUZZ_RELAY_URL`, `BUZZ_PRIVATE_KEY`, and optionally
`BUZZ_AUTH_TAG` in the configured MCP server declaration. Carl treats matching values
as secrets at ACP ingress:

- values are held only in a non-serializing secret container;
- values never enter prompts, provider requests, journal payloads, diagnostics, or
  general child environments;
- raw MCP server environment data is not exposed as a model-visible tool argument;
- any diagnostic identifies only the server and stable rule classification.

The Carl installation provides `carl-buzz-mcp` as an argv-zero alias of the same Carl
binary artifact. Buzz is configured with
`BUZZ_ACP_MCP_COMMAND=carl-buzz-mcp`. The alias enters a narrow MCP mode that exposes
typed Buzz messaging operations and no shell, file editor, or environment-reading
tool. Its only job is to use Buzz-owned credentials to publish messages and reactions
through a pinned Buzz CLI boundary. Carl's coding tools remain Carl-owned.

The ACP frontend recognizes this typed server contract and uses it as a delivery
capability. A model cannot turn it into an arbitrary credential-bearing shell, even
in `bypassPermissions`. Unknown credential-bearing MCP servers or a Buzz server that
exposes a general shell are rejected with setup guidance. This is a compatibility
constraint, not an attempt to sandbox arbitrary third-party MCP code.

## Turn and delivery flow

1. Buzz authenticates an event, applies the configured author gate, and selects its
   channel session.
2. `buzz-acp` sends a prompt containing an explicit current-event block and bounded
   context. Slash commands, when present, occupy the first content block.
3. The ACP frontend validates transport framing, records channel and reply metadata,
   and submits a Carl command.
4. Carl persists accepted input, constructs bounded context, invokes the configured
   provider, and streams provider-neutral events.
5. The ACP frontend maps assistant deltas and tool lifecycle events to
   `session/update` notifications for Buzz's observer surfaces.
6. Tool proposals pass through Carl's router, policy, approval, sandbox, and
   verification path according to the active mode.
7. The final human-facing result is sent through the restricted Buzz publisher to
   the originating thread. Approval requests use the same path.
8. The turn reports `end_turn` only after the kernel has completed and the publisher
   has returned an unambiguous success. Cancellation reports `cancelled`.

ACP assistant text is useful for live observation but is not considered proof that a
human-visible Buzz reply was delivered.

## Error handling and recovery

- **Protocol input:** malformed and oversized frames receive bounded errors; a
  broken stdin ends the process after child cleanup.
- **Stdout discipline:** one writer owns stdout. Logging, panics, and provider output
  may not write to it.
- **Authentication:** missing or expired provider authentication produces sanitized
  instructions to authenticate from a local foreground terminal. Carl never relays
  an OAuth ceremony through Buzz.
- **Provider and tools:** failures become typed Carl events and bounded ACP tool
  updates. Secret-bearing raw output is discarded under Carl's redaction policy.
- **Cancellation:** `session/cancel` cancels the provider request, tool work, and
  supervised process tree. Cleanup has a separate bound.
- **Crash:** an in-flight turn becomes interrupted on reconciliation. A potentially
  non-idempotent tool is never resumed automatically.
- **Publisher failure:** a definite pre-send failure is visible as failed delivery.
  An ambiguous failure is persisted as `delivery_uncertain` and is not retried
  automatically.
- **Session replacement:** unused approvals are invalidated. Durable history remains;
  Carl creates a new branch when stable external identity is unavailable.
- **Data-root conflict:** a second Carl owner exits with a stable, actionable error.
- **Unsupported capability:** Carl refuses the mode or method instead of weakening
  policy or silently selecting another model.

Buzz owns relay reconnects, inbound event deduplication, and author admission. Carl
owns command/event deduplication and the at-most-once consumption of approvals and
consequential tool intents after input reaches the kernel.

## Testing strategy

### Protocol and unit tests

- ACP v1/v2 initialization and honest capability advertisement.
- Request ID routing, notifications, unknown methods, malformed JSON, maximum frame
  size, partial reads, and multiple sessions.
- `session/new`, prompt, cancel, configuration changes, and steering.
- Model, reasoning-effort, and permission option validation.
- Exact stdout bytes with all logs confined to stderr.
- Buzz context parsing, slash-command separation, channel mapping, and reply targets.

### Runtime and security tests

- Scripted provider turns that emit text, tools, usage, failures, and cancellation.
- Fake MCP servers that succeed, fail, hang, emit oversized output, and spawn
  descendants.
- Permission behavior for every mode and tool category.
- Approval expiry, replay, wrong session, wrong tool, changed workspace, and stale
  executable tests.
- Fake approval strings in context and tool output cannot resolve an approval.
- Remote bypass requires the explicit command and one-time confirmation.
- Buzz credential values never appear in provider requests, events, logs, diagnostics,
  or general command environments.
- A credential-bearing general-shell MCP declaration is rejected.
- Cancellation races and crash recovery do not repeat consequential work.

### Subprocess and Buzz contract tests

A real `carl acp` child is driven over bounded stdin/stdout while fake provider and
MCP children exercise lifecycle failures. A pinned Buzz contract fixture reproduces
the current:

- initialization request and protocol version;
- `session/new` shape and configuration option flow;
- prompt and slash-command block framing;
- channel, event, author, and reply context headers;
- MCP server declaration and credential environment;
- cancellation and steering behavior.

The fixture prevents accidental drift without requiring network access or a running
Buzz checkout in ordinary CI.

### End-to-end and live verification

An opt-in integration job runs:

```text
Buzz relay -> buzz-acp -> carl acp -> scripted provider -> Carl tools -> Buzz reply
```

The final manual smoke test uses Stephen's locally authenticated Codex subscription.
It is never enabled in public CI and exports no subscription token. The test asks
Carl to edit a fixture repository, run verification, exercise normal approval and
bypass in separate sessions, steer one turn, cancel another, and confirm the final
diff and result appear in the correct Buzz threads.

## Delivery sequence

The work is one integration program delivered in three independently verifiable
increments:

1. **ACP conformance:** codec, server, sessions, config options, event mapping,
   steering, subprocess containment, and contract fixtures use only scripted Carl
   dependencies.
2. **Deterministic Buzz path:** restricted publisher, channel mapping, approvals,
   permission modes, and a local Buzz relay complete an end-to-end run with a
   scripted provider.
3. **Live coding path:** connect the user-reachable Carl runtime and subscription
   delegate, then pass the local Codex subscription smoke test.

Increment one is useful interoperability infrastructure but is not advertised as
functional Buzz support. The public feature claim begins only after increment three.

## Definition of done

Buzz compatibility is complete when all of the following are true on supported macOS
and Linux targets:

1. Buzz discovers the custom Carl harness and successfully initializes `carl acp`.
2. The recommended setup uses Buzz's `owner-only` author gate.
3. A Buzz channel or DM maps to the correct Carl session and working directory.
4. Model, reasoning effort, and permission mode changes reach the active provider.
5. Carl can inspect a repository, edit code, execute tests, and report bounded output.
6. Normal mode posts and consumes an exact, expiring approval in the same thread.
7. Bypass can be selected locally or through the confirmed Buzz command and visibly
   reports its active state.
8. Steering and cancellation change the active turn without corrupting history.
9. Human-facing completion, diff, and verification evidence reach the originating
   Buzz thread.
10. Restart and failure tests show no duplicated consequential work.
11. Buzz and provider credentials are absent from every model-visible and durable
    surface covered by the test suite.
12. The opt-in live Codex subscription smoke test passes without an OpenAI API key.

Documentation will clearly distinguish the tested Buzz version range, the current
single-process/one-pool limitation, dangerous bypass semantics, and any upstream Buzz
behavior Carl cannot control.
