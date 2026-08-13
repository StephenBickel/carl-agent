# Carl Native TUI and Provider Runtime Design

Status: Slice 1 implemented and verified; native providers/tools/onboarding remain
Date: 2026-08-13

## Product thesis

Carl should open as a useful coding agent when the user types `carl`, without requiring the user to understand ACP, service sockets, provider processes, or storage internals. The interface should feel as direct as Pi and Codex: one conversation, one input box, a compact status line, visible tool activity, and a small set of slash commands.

The TUI is not a second agent runtime. It is a local frontend for Carl's durable task service. Model requests, native tools, approvals, compaction, cancellation, restart recovery, and session persistence remain authoritative in the existing task engine and event journal.

Version 1 delivers three sequential slices:

1. a minimal interactive TUI using the existing OpenAI subscription-backed Codex adapter;
2. a native provider loop and native coding tools, beginning with OpenAI and OpenRouter-compatible HTTP APIs;
3. secure first-run onboarding for OpenAI subscription login, OpenAI API keys, and OpenRouter API keys.

Each slice must be independently usable and tested before the next slice is added.

## Goals

- Make `carl` with no arguments open an interactive coding session.
- Preserve all existing explicit CLI subcommands and machine-oriented protocols.
- Automatically connect to, or safely launch, the local Carl service.
- Stream assistant text, native tool activity, diffs, context usage, compaction, and completion state.
- Change model, reasoning effort, and permission mode from slash commands.
- create, list, resume, compact, cancel, and inspect durable sessions.
- Default the local TUI to full-access mode while displaying that choice continuously.
- Support OpenAI subscription authentication through the existing supported Codex path.
- Support OpenAI API keys and OpenRouter API keys through a native provider adapter.
- Expose only models that satisfy the capabilities required by Carl's coding loop.
- Keep provider credentials out of configuration, SQLite, logs, event payloads, crash output, and shell environments.
- Make Carl's native coding tools safe, bounded, cancellable, durable, and replay-aware.
- Preserve task context across compaction, service restart, TUI reconnect, and provider context replacement.

## Non-goals for this version

- A multi-pane IDE, file tree, embedded editor, mouse-first UI, or terminal multiplexer.
- Multi-agent orchestration from the TUI.
- A plugin marketplace or public native plugin ABI.
- Direct OAuth implementations for every provider.
- Direct SDK integrations for Anthropic, Google, xAI, DeepSeek, Qwen, or Kimi.
- Silently treating unsupported models as coding-capable.
- Moving provider execution or tool execution into the TUI process.
- Persisting raw provider credentials or copying credentials from unrelated applications.
- Replacing the existing ACP, Buzz, Telegram, service, or maintenance frontends.

Models from DeepSeek, Qwen, Kimi, xAI, Anthropic, Google, and other vendors may be used in this version when OpenRouter exposes a compatible, tool-capable model. Direct vendor adapters can be added later behind the same provider interface.

## User experience

### Startup

`carl` opens the TUI. `carl tui` is an explicit alias useful in scripts and documentation. Existing subcommands such as `carl serve`, `carl acp`, `carl auth`, `carl doctor`, and `carl maintenance` retain their existing meanings.

At startup the TUI:

1. resolves the configured data root and workspace;
2. connects to the local service;
3. if no service is available, launches the same trusted Carl executable in service mode and waits for its bounded readiness probe;
4. negotiates the service protocol and capabilities;
5. loads the most recent resumable local TUI session or creates a new session shell;
6. enters alternate-screen/raw terminal mode only after fallible setup has succeeded.

The service is not owned by the TUI lifetime. Closing the TUI does not kill a running task or stop the service. The existing maintenance and shutdown controls remain responsible for service lifecycle.

Service launch races are resolved by the existing data-root lock and endpoint ownership rules. A second TUI connects to the winning service instead of starting a second writer.

### Layout

The initial interface is deliberately small:

```text
 CARL  gpt-5.6-codex · high · full access · session 7c2a… · 42% context

 You
 Fix the failing parser tests and keep the public API stable.

 Carl
 I found the regression in src/parser.rs.

 ✓ read_file src/parser.rs
 ✓ apply_patch src/parser.rs
 ● run_command cargo test parser

 ❯ _
```

The transcript is scrollable. Tool activity is collapsed to one line by default and can expand to show bounded input, output, diff, duration, and disposition. Approval prompts occupy the input area and require an explicit response. The status bar always shows provider/model, effort, permission mode, session identifier, task state, and context usage.

Enter submits. Shift+Enter inserts a newline. Ctrl+C cancels an active task and, when idle, clears the current input. Ctrl+D or `/exit` closes the TUI without stopping the service. Terminal resize reflows the transcript without mutating durable events.

### Slash commands

The initial command surface is:

- `/model` — list compatible models for the selected provider.
- `/model <id>` — select a model for the next task or, when safe, update the current task through the existing configuration control.
- `/provider` — show the current provider and available configured providers.
- `/provider <id>` — select a provider and start a new session because provider contexts are not interchangeable.
- `/effort low|medium|high|xhigh|max|ultra` — set a supported reasoning effort; unsupported values fail visibly.
- `/permissions plan|default|accept-edits|dont-ask|full-access` — change the permission mode.
- `/compact` — request a safe-boundary compaction through the service.
- `/new` — create a new durable frontend session.
- `/sessions` — list durable local TUI sessions with index, timestamp, workspace, provider/model, and task state.
- `/resume <number-or-id>` — attach to a previous session and replay its recent durable updates.
- `/status` — show task, provider, budget, context, checkpoint, and process status.
- `/cancel` — cancel the current task through the service.
- `/login` — run provider onboarding outside raw terminal mode.
- `/logout` — remove the selected stored credential after confirmation.
- `/help` — show commands and key bindings.
- `/exit` — restore the terminal and exit the TUI.

Normal text starts a new task when the session is idle, or sends steering to the current task when it is active. The transcript clearly labels steering so it is not confused with a new user turn.

## Architecture

```text
 keyboard/terminal
       |
       v
 TUI reducer + renderer
       |
       v
 TUI controller ---- service client ---- durable task service
                                             |
                              +--------------+--------------+
                              |                             |
                        provider driver                task engine
                              |                             |
                 +------------+-----------+       native tool effects
                 |            |           |               |
          subscription   OpenAI HTTP   OpenRouter HTTP     OS/files/processes
```

### TUI boundary

`frontends::tui` contains:

- a pure `TuiState` reducer;
- terminal-independent input and slash-command parsing;
- a `TuiController` that translates user intent to service commands;
- a renderer built with Ratatui;
- a Crossterm terminal owner that enters and restores terminal modes through RAII;
- a bounded event pump that merges keyboard, resize, tick, service update, reconnect, and shutdown events.

The renderer has no storage, provider, process, or filesystem access. The controller cannot call tools or providers directly. All displayed task state is derived from negotiated service results and durable live updates.

The TUI keeps only presentation state: scroll offset, input buffer, selected overlay, transient notices, and the last rendered durable cursor. Session truth stays in the service.

### Service protocol additions

The service protocol gains explicit, versioned commands for:

- listing frontend sessions and their resumable task bindings;
- listing configured providers and their authentication state without exposing secrets;
- listing provider models with normalized capabilities;
- selecting a provider for a newly created frontend session.

Session list results include the stable external session identifier, workspace, provider, model, effort, permission mode, latest task identifier, task state, update cursor, and timestamps. The TUI never reconstructs this mapping by scraping task snapshots.

The protocol remains strict: required fields have no silent defaults, unknown fields fail, capability negotiation is exact, response sizes are bounded, and old clients receive a typed unsupported-version result.

### Provider boundary

Carl introduces a provider-neutral `ProviderDriver` used by the task engine. It accepts:

- canonical context messages and compaction packages;
- normalized native tool schemas;
- model and reasoning configuration;
- cancellation and task budgets;
- an optional provider-context identifier for safe resumption.

It emits normalized events:

- response started;
- assistant text delta;
- tool call started, argument delta, and completed;
- usage and context measurements;
- provider-context binding or loss;
- response completed with a typed finish reason;
- typed, redacted failure with application certainty.

Three drivers are in scope:

1. `CodexSubscriptionDriver`, an adaptation of Carl's current supported Codex app-server integration;
2. `OpenAiDriver`, using the documented OpenAI API and an API key;
3. `OpenRouterDriver`, using OpenRouter's OpenAI-compatible API and an API key.

OpenAI and OpenRouter share a bounded HTTP transport and normalized streaming parser, but remain distinct drivers because authentication, model discovery, headers, usage, and capability semantics differ.

Provider-specific wire types never enter task events or TUI state. Provider configuration is durable; credentials are not.

### Model catalog and capabilities

The normalized model catalog records:

- stable provider and model identifiers;
- display name;
- tool-call support;
- streaming support;
- reasoning-effort support and accepted values;
- context and output limits when known;
- structured-output and parallel-tool support;
- availability and discovery timestamp.

The coding TUI only presents models that support the native tool loop. A user can inspect why another model is excluded. Unsupported reasoning effort is rejected instead of silently dropped.

OpenRouter discovery consumes the provider's model capability metadata and admits only models whose supported parameters satisfy Carl's tool requirements. A conservative built-in cache permits offline startup, while an explicit refresh updates the catalog. Stale metadata is labeled.

Changing a model within one provider may use the existing task configuration boundary when the engine is at a safe state. Changing providers always creates a new session; Carl may seed it with a canonical handoff summary, but never reuses the old provider-context identifier.

### Credential broker and onboarding

The credential broker supports three sources:

- provider-owned OpenAI subscription authentication through the existing supported Codex login path;
- an OpenAI Platform API key;
- an OpenRouter API key.

First run presents these choices after leaving raw terminal mode. API keys are entered through a hidden prompt and stored in the operating-system credential vault. Configuration persists only a credential reference and provider metadata. Environment variables are supported for automation as ephemeral inputs and are never copied into storage.

The broker returns a secret lease only to the provider driver. Secret leases cannot be serialized or formatted through `Debug`. Keys are not inherited by native shell commands. Authentication checks report presence, source, and expiry state without reporting values or token claims.

`cargo install` and package installation do not prompt for credentials. Onboarding occurs on the first interactive `carl` run or through `carl auth`.

## Native coding tools

Carl's minimal native coding tool set is:

- `read_file` — bounded text reads with line/byte ranges and explicit truncation;
- `list_directory` — bounded, sorted directory entries;
- `search_files` — bounded literal or regex search implemented with a trusted `rg` executable when available and a Rust fallback where practical;
- `apply_patch` — structured patch application with preimage/path checks and a returned diff;
- `run_command` — supervised foreground or background process execution with working directory, timeout, output cap, cancellation, and process-tree ownership;
- `process_status` — inspect a background process through its durable identifier;
- `terminate_process` — terminate and reap a supervised process tree.

Tools are engine effects, not callbacks owned by a provider adapter. Every requested tool becomes a durable operation intent before execution. Policy produces allow, deny, or approval-required. The engine records started and terminal evidence before continuing the model loop.

Filesystem paths are workspace-relative at the provider boundary. Before access Carl rejects absolute paths, traversal, NULs, ambiguous encodings, and symlink escapes. Mutations use preconditions so stale or already-modified files fail rather than overwrite silently.

Command execution uses a filtered environment, a canonical workspace, bounded stdin/stdout/stderr, process groups or platform job objects, graceful cancellation, forced termination, and awaited reaping. Provider credentials and Carl control-channel secrets are never present in the child environment.

`full-access` means the local owner has chosen automatic policy approval for operations the engine can safely represent. It does not disable journaling, output bounds, path validation, secret filtering, cancellation, process supervision, or ambiguity handling.

Consequential operations that may have applied but lack authoritative completion evidence transition to `Uncertain` and block automatic replay. Restart reconciliation never repeats them silently.

## Compaction and long-running continuity

Carl's canonical checkpoint remains the compaction source of truth. A compacted context preserves:

- the user objective and ordered completion contract;
- current plan and next objective;
- modified files, stable identifiers, and content digests;
- test commands and observed results;
- unresolved, running, failed, and uncertain operations;
- background process identifiers and ownership state;
- user steering;
- provider, model, effort, permissions, and remaining budget;
- provider-context lineage and loss/replacement evidence;
- the minimum recent dialogue needed for coherent continuation.

Compaction is requested, built, committed, and then installed only at a safe boundary. The provider receives the same canonical package after automatic compaction, `/compact`, provider context loss, or service restart. A TUI disconnect does not affect compaction or task progress.

Carl follows Pi's preference for a small session surface and event streaming, while retaining stronger durable semantics than an in-memory session. It follows Codex's explicit model/provider configuration, approval boundary, process ownership, and credential-store discipline. Carl's differentiator is that recovery and compaction are verifiable products of the authoritative journal rather than opaque chat history replacement.

## Failure handling

- Terminal setup is RAII-owned. Normal exit, typed error, panic hook, Ctrl+C, and dropped render tasks restore raw mode, cursor visibility, mouse mode, and alternate screen exactly once.
- Service loss freezes new mutations, keeps the transcript visible, reconnects with bounded backoff, renegotiates, and replays from the last durable cursor.
- A cursor gap causes a bounded authoritative refresh rather than guessed state.
- Slow terminal rendering cannot block the service reader; bounded queues coalesce replaceable progress events but never discard terminal, approval, tool outcome, compaction, or completion events.
- Provider transport failures are classified by whether a consequential request may have applied. Carl retries only definitely-not-applied requests under the existing budget.
- Tool failures return typed, bounded evidence to the model. Authentication, policy, validation, and uncertain-effect failures are not retried automatically.
- Credential-vault unavailability fails closed with a recovery command. Carl does not fall back to plaintext files.
- Unsupported model capabilities, effort values, or protocol versions fail before starting a task.
- Storage failure stops further consequential work.

## Testing strategy

Development follows test-driven slices and never requires live provider calls in the default suite.

### TUI tests

- table tests for slash parsing, key handling, editing, multiline input, and state transitions;
- pure reducer tests for every service update and reconnect sequence;
- fixed-size render snapshots with sanitized deterministic data;
- pseudo-terminal integration tests for startup, submit, resize, cancel, session list/resume, and exact terminal restoration after normal exit, panic, signal, and service failure;
- binary tests proving `carl` defaults to TUI and every existing subcommand remains stable;
- bounded-queue tests proving load shedding cannot lose authoritative outcomes.

### Service and session tests

- protocol serialization, capability negotiation, size bounds, old-version rejection, and command idempotency;
- durable frontend-session listing and resume across client reconnect and service restart;
- local-TUI full-access default without changing ACP, Buzz, Telegram, or service API defaults;
- auto-launch races with one writer and multiple clients;
- update cursor replay without duplicates or gaps.

### Provider tests

- one provider conformance suite used by subscription, OpenAI, and OpenRouter drivers;
- local fake HTTP/app-server fixtures for streaming chunks, fragmented tool arguments, usage, context loss, retry classification, cancellation, response caps, and malformed data;
- model-catalog capability filtering, stale cache behavior, and unsupported-effort rejection;
- credential source precedence, vault references, redaction, closed child environments, and authentication failures;
- opt-in live smoke tests that are excluded from ordinary CI.

### Tool and endurance tests

- path traversal, symlink escape, stale patch, output cap, timeout, cancellation, process descendant, reaping, and secret-environment tests;
- durable intent/start/outcome ordering and no duplicate effect after restart;
- uncertain-effect blocking;
- multi-step coding scenarios using all native tools;
- repeated compaction, provider context replacement, TUI reconnect, and service restart with normalized final digest equality;
- multi-hour behavior simulated with injected clocks and deterministic provider fixtures rather than wall-clock sleeps.

## Delivery sequence

### Slice 1: subscription-backed TUI

- CLI default and `tui` alias;
- Ratatui/Crossterm shell with terminal restoration;
- service discovery/auto-launch;
- transcript, input, status, tool/update rendering, approval UI;
- slash commands except native-provider login;
- durable session list/resume protocol;
- current subscription-backed provider path;
- focused TUI, protocol, service, and pseudo-terminal tests.

### Slice 2: native provider and coding loop

- provider-neutral driver contract;
- native coding tools and durable effect execution;
- OpenAI and OpenRouter adapters plus model catalogs;
- provider/model selection commands;
- native multi-tool loop, compaction, cancellation, recovery, and conformance tests.

### Slice 3: secure onboarding

- first-run provider chooser;
- supported OpenAI subscription login handoff;
- hidden API-key input and OS vault storage;
- `/login`, `/logout`, credential diagnostics, and model refresh;
- migration and failure-path tests;
- documentation and release packaging updates.

Each slice receives its own focused review and commit series. A broad locked test, strict Clippy, formatting, documentation, and platform matrix run occurs at each slice merge gate rather than after every Rust edit.

## Acceptance criteria

The feature is complete when:

1. a clean install can run `carl`, finish onboarding, and reach a working chat prompt;
2. subscription login, OpenAI API key, and OpenRouter API key paths each produce a usable configured provider without persisting a raw secret;
3. a user can complete a real multi-step coding task with native read, search, patch, command, and process tools;
4. the TUI can change model, effort, and permissions; compact; create; list; resume; cancel; and exit;
5. closing and reopening the TUI resumes the same durable session without stopping the task;
6. service restart and provider-context loss continue from canonical checkpoint evidence without duplicating effects;
7. non-tool-capable models are excluded and unsupported effort values are rejected visibly;
8. full-access remains visible and does not bypass structural safety controls;
9. terminal state is restored on every tested exit and failure path;
10. default CI uses no live credentials or provider network and all focused, strict, security, and platform gates pass.

## Sources and design influences

- Pi coding-agent SDK: small session API, model state, event streaming, tool surfaces, and compaction — <https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/sdk.md>
- OpenAI Codex app-server protocol: explicit session/control and approval semantics — <https://github.com/openai/codex/blob/main/codex-rs/app-server/README.md>
- OpenAI Codex configuration schema: explicit provider, reasoning, credential-store, compaction, sandbox, and tool configuration — <https://github.com/openai/codex/blob/main/codex-rs/core/config.schema.json>
- OpenRouter quickstart and model/tool capability documentation — <https://openrouter.ai/docs/quickstart>, <https://openrouter.ai/docs/guides/overview/models>, <https://openrouter.ai/docs/guides/features/tool-calling>
