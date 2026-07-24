# Architecture

Status: pre-alpha foundation. The [approved Carl design](superpowers/specs/2026-07-23-carl-top-tier-harness-design.md) defines the target; this document separates current code from that target.

## System shape

Carl is designed as one Rust package with a library and one executable. Frontends create and consume provider-neutral events; they do not call model providers or tools directly.

```text
TUI (planned) --------+
                      +--> runtime (planned) --> provider boundary
Telegram (planned) ---+            |
                                   +--> policy (planned) --> tools (planned)
                                   |
                                   +--> event log (implemented) --> projections

auth CLI (implemented) --> data-root lock --> provider auth broker
                                              |
                                              +--> supervised Codex/Grok sidecar
```

This layout keeps user interfaces replaceable, provider wire formats contained, policy centralized, and scenario tests deterministic.

## Implemented foundation

- `events`: schema-versioned envelopes, provider-neutral event payloads, and stable serialized IDs.
- `error`: stable public error codes with sanitized user messages and separate internal detail.
- `runtime::budget`: hard counters for turn iterations and tool-call limits.
- `storage`: SQLite WAL, forward migrations verified by checksum, transactional append-only events, and durable session, memory, and approval lifecycle records.
- `providers`: a normalized provider request/event trait and a scripted adapter that replays sanitized JSON fixtures with cancellation support.
- `sidecar`: isolated provider homes, executable identity/version checks, closed child
  environments, process-tree supervision, bounded cleanup, and provider-owned
  authentication protocols.
- `auth`: provider-owned authentication brokers for Codex and Grok that expose only
  sanitized state, login, logout, and cancellation boundaries.
- `cli`: composition for the seven `auth` commands, local foreground checks,
  cross-process data-root locking, and deterministic safe JSON output; the other
  top-level commands remain placeholders.

Authentication status performs only provider-owned local handshakes with the pinned
executables. It does not issue prompts, start sessions, invoke inference, or validate
live model entitlement. There is no production HTTP adapter, context assembler, turn
state machine, policy evaluator, tool executor, model runtime, delegate execution,
TUI, general configuration loader, diagnostics command, or Telegram transport yet.

## Authentication composition

The public auth runner owns one crash-released OS lock for the canonical Carl data
root. Inside that boundary, it prepares a fixed provider home, resolves and validates
one canonical executable identity, and constructs a status-only or foreground-capable
provider broker. The broker delegates OAuth ceremonies and token storage to the
provider executable. Carl receives sanitized authentication state, never bearer or
refresh tokens.

The sidecar supervisor owns child-process groups on Unix and Job Objects on Windows so
cancellation and exit can terminate and boundedly reap provider process trees. This
is lifecycle containment, not a sandbox and not proof that a version-matching binary
was published by OpenAI or xAI.

The same sidecar protocols may later support policy-routed subscription delegates, as
described in [ADR 0004](adr/0004-subscription-authentication-through-provider-sidecars.md).
That future composition is deliberately absent: implemented authentication does not
enable model/runtime/delegate execution.

## Planned turn boundary

The v1 runtime will validate and persist user input, assemble bounded context, stream normalized provider events, validate proposed tool calls, evaluate policy, persist approval decisions and tool results, then continue until a final answer, cancellation, or budget exhaustion. Consequential state transitions are to be persisted before a frontend exposes them.

Partially executed tools will not be resumed automatically after a crash: repeating a non-idempotent action is more dangerous than requiring the owner to review an interruption. The append-only log remains the audit and replay source while materialized projections serve normal reads. This decision is recorded in [ADR 0001](adr/0001-event-sourced-runtime.md).

## Ownership and process model

V1 permits one Carl process to own a data directory at a time. Public authentication
entry points enforce that boundary with one exclusive OS lock per canonical data
root; a crashed process releases the lock without a stale logical owner. The
interactive process and future headless `serve` mode are alternate owners, not
concurrent daemons. See [ADR 0002](adr/0002-single-process-v1.md).

## Stable boundaries, unstable details

The event, provider, tool, policy, storage, and frontend boundaries are architectural commitments. Concrete configuration keys, provider request mappings, UI layout, and platform-specific process isolation remain subject to implementation and testing. Documentation must not present a target interface as current behavior.
