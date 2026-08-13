# Carl Native Provider and Coding Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a provider-neutral native coding loop with Carl-owned tools, an OpenAI Responses adapter, and an OpenRouter adapter that exposes only tool-capable text models.

**Architecture:** The existing durable `TaskEngine` remains authoritative. A new `NativeAgentPort` translates Carl checkpoints and epochs into the existing provider-neutral `ModelRequest` stream, dispatches model tool calls through a closed `NativeToolRuntime`, and emits ordinary `AgentEvent`/effect requests back to the engine. Provider HTTP adapters share a bounded transport and strict catalog but keep distinct wire codecs; API-key capture and OS-vault storage are deliberately left to the separate onboarding plan.

**Tech Stack:** Rust 2024, Tokio, reqwest with rustls and streaming only, serde/serde_json, futures-util, existing SQLite task journal, existing `AgentPort`, capability-relative filesystem access, `process_wrap`/Carl sidecar supervision.

## Global Constraints

- Never read a ChatGPT subscription credential or translate it into an API key; subscription execution stays on the Codex adapter.
- Never persist, serialize, clone, or debug-render an OpenAI/OpenRouter key.
- Use `POST https://api.openai.com/v1/responses` for native OpenAI requests and parse documented Responses SSE events.
- Use `POST https://openrouter.ai/api/v1/chat/completions` for OpenRouter requests and parse OpenAI-compatible streaming tool-call deltas.
- Filter OpenRouter's `/api/v1/models?supported_parameters=tools` response again locally for text input/output, `tools`, and a context window of at least 32,768 tokens.
- The native tool set is closed to `read_file`, `list_directory`, `search_text`, `apply_patch`, and `run_command` in this slice.
- Every filesystem name is workspace-relative, normalized, and revalidated against symlink, hard-link, special-file, traversal, aggregate-byte, and entry-count limits at use time.
- Commands use literal argv arrays, a canonical workspace, a closed environment, bounded output/time, cancellation, and process-group teardown; no shell-string execution exists.
- The durable engine owns permission decisions, effect intent/outcome, budgets, checkpointing, compaction, cancellation, and restart behavior.
- No live provider, credential, network, or billing call runs in ordinary tests or public CI.

---

### Task 1: Harden the provider-neutral model and catalog contracts

**Files:**
- Modify: `src/providers/mod.rs`
- Create: `src/providers/catalog.rs`
- Modify: `src/delegates/settings.rs`
- Modify: `src/lib.rs`
- Test: `tests/provider_catalog_contract.rs`

**Interfaces:**
- Consumes: existing `Provider`, `ModelRequest`, `ProviderEvent`, `ModelId`, and `ReasoningEffort`.
- Produces: `ProviderKind`, `ProviderModel`, `ProviderCatalog`, `ProviderSelection`, and strict validation shared by adapters and service bootstrap.

- [ ] **Step 1: Write catalog RED tests**

Test exact snake-case providers (`openai_subscription`, `openai_api`, `openrouter`), bounded model IDs/display names, unique IDs, text/tool capability requirements, context windows `32_768..=4_000_000`, nonempty effort sets, and debug/serde payloads containing no credentials. Include mutation cases for duplicate models, unknown fields, zero context, unsupported tools, and more than 256 models.

- [ ] **Step 2: Observe RED**

Run: `cargo test --locked --test provider_catalog_contract`

Expected: compile failure because `providers::catalog` does not exist.

- [ ] **Step 3: Implement the closed catalog**

Add validated types with these public shapes:

```rust
pub enum ProviderKind { OpenAiSubscription, OpenAiApi, OpenRouter }

pub struct ProviderModel { /* private validated fields with read-only accessors */ }
pub struct ProviderCatalog { /* private validated fields with read-only accessors */ }
```

Construct models/catalogs only through `ProviderModel::new` and `ProviderCatalog::new`, validate all bounds and uniqueness there, and use `#[serde(deny_unknown_fields)]` on wire-safe structs. Extend `ModelId` for slash-separated OpenRouter IDs while rejecting empty, `.` and `..` segments. `ProviderSelection::validate_against(&ProviderCatalog)` must reject an unknown model or effort rather than substituting a default.

- [ ] **Step 4: Run and commit**

Run:

```bash
cargo test --locked --test provider_catalog_contract
cargo test --locked --test provider_contract
cargo clippy --locked --lib -- -D warnings
```

Commit: `feat: add strict native provider catalog`

---

### Task 2: Add a bounded, secret-safe HTTP transport

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `src/providers/http.rs`
- Modify: `src/providers/mod.rs`
- Test: `tests/provider_http_contract.rs`

**Interfaces:**
- Consumes: `CancellationToken`, bounded provider URLs, injected credential bytes, and adapter-specific JSON bodies.
- Produces: `ProviderHttpClient::json`, `ProviderHttpClient::sse`, `ProviderHttpResponse`, and `SecretCredential`.

- [ ] **Step 1: Write transport RED tests**

Use a loopback Tokio HTTP fixture. Assert exact method/path/header/body, a 10 MiB response ceiling, a 256 KiB SSE-line ceiling, a 120-second hard deadline, cancellation, typed 401/403/429/5xx mapping, `Retry-After` bounds, content-type validation, redirect denial, and no proxy/cookie/ambient environment use. Assert `Debug` for every error/request omits URL query, authorization, response bodies, and fixture secret.

- [ ] **Step 2: Observe RED**

Run: `cargo test --locked --test provider_http_contract`

Expected: compile failure because `ProviderHttpClient` is missing.

- [ ] **Step 3: Implement the minimal transport**

Add:

```toml
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "stream"] }
zeroize = "1"
```

`SecretCredential` owns a `Zeroizing<Vec<u8>>`, has no `Clone`, `Serialize`, or value-returning accessor, and exposes only `with_bytes(|bytes| ...)`. Build reqwest with redirects disabled, no proxy, no referer, no cookie store, connect timeout 10 seconds, total timeout 120 seconds, and an exact user agent. The adapters pass an already-validated static origin plus a literal path; arbitrary URLs are not accepted.

- [ ] **Step 4: Run and commit**

Run:

```bash
cargo test --locked --test provider_http_contract
cargo clippy --locked --lib -- -D warnings
```

Commit: `feat: add bounded provider HTTP transport`

---

### Task 3: Implement the OpenAI Responses streaming adapter

**Files:**
- Create: `src/providers/openai.rs`
- Modify: `src/providers/mod.rs`
- Test: `tests/openai_provider_contract.rs`
- Create: `tests/fixtures/openai/responses-tool-stream.sse`
- Create: `tests/fixtures/openai/responses-text-stream.sse`

**Interfaces:**
- Consumes: `ProviderHttpClient`, `SecretCredential`, `ModelRequest`, and an injected `ProviderCatalog`.
- Produces: `OpenAiProvider` implementing `Provider` and `OpenAiProvider::catalog`.

- [ ] **Step 1: Write codec RED tests**

Assert `POST /v1/responses` with `store:false`, `stream:true`, exact `model`, developer/user/assistant/tool messages, strict function tools, optional maximum output tokens, and reasoning effort only when the selected model supports it. Parse `response.output_text.delta`, function-call output item completion, usage in `response.completed`, incomplete/content-filter termination, error events, `[DONE]`, split frames, CRLF, comments, unknown-event rejection, duplicate terminal rejection, duplicate tool IDs, malformed JSON arguments, and aggregate output limits.

- [ ] **Step 2: Observe RED**

Run: `cargo test --locked --test openai_provider_contract`

Expected: compile failure because `OpenAiProvider` is missing.

- [ ] **Step 3: Implement the adapter**

Encode each `ToolDefinition` as a strict custom function. Reassemble a function call only from its bound `item_id`/`call_id` stream, parse arguments as one bounded JSON object, and emit one `ProviderEvent::ToolCall`. Emit usage once and exactly one `Finish`; never emit reasoning text. Treat any unknown output item, bad sequence, missing terminal, or body after terminal as `ProviderError::InvalidResponse`.

- [ ] **Step 4: Run and commit**

Run:

```bash
cargo test --locked --test openai_provider_contract
cargo test --locked --test provider_contract
cargo clippy --locked --lib -- -D warnings
```

Commit: `feat: add native OpenAI Responses adapter`

---

### Task 4: Implement OpenRouter chat streaming and model discovery

**Files:**
- Create: `src/providers/openrouter.rs`
- Modify: `src/providers/mod.rs`
- Test: `tests/openrouter_provider_contract.rs`
- Create: `tests/fixtures/openrouter/models.json`
- Create: `tests/fixtures/openrouter/tool-stream.sse`

**Interfaces:**
- Consumes: `ProviderHttpClient`, `SecretCredential`, `ModelRequest`, and OpenRouter model JSON.
- Produces: `OpenRouterProvider` implementing `Provider` and `OpenRouterProvider::refresh_catalog`.

- [ ] **Step 1: Write discovery and codec RED tests**

Assert discovery uses exact `/api/v1/models?supported_parameters=tools&output_modalities=text`, rejects more than 2 MiB/512 entries, and retains only entries with `tools`, text input/output, a valid context length, and nonexpired identifiers. Include DeepSeek, Qwen, Kimi, Anthropic, Google, and xAI fixture entries to prove vendor-neutral filtering. Assert chat requests use exact message/tool shapes, `stream:true`, `stream_options.include_usage:true`, and optional reasoning effort only when advertised.

For SSE, cover indexed fragmented tool-call arguments, interleaved text, multiple tool calls, usage-only final chunks, finish reasons, provider error metadata redaction, malformed indices/IDs/names/arguments, duplicate finish, and aggregate limits.

- [ ] **Step 2: Observe RED**

Run: `cargo test --locked --test openrouter_provider_contract`

Expected: compile failure because `OpenRouterProvider` is missing.

- [ ] **Step 3: Implement discovery and streaming**

Use `Authorization: Bearer`, `HTTP-Referer: https://github.com/StephenBickel/carl-agent`, and `X-Title: Carl` without ambient headers. Reassemble each tool call by numeric index while binding its first nonempty ID/name; later conflicts fail closed. Map `stop`, `tool_calls`, `length`, and `content_filter` only; unknown finish reasons fail closed.

- [ ] **Step 4: Run and commit**

Run:

```bash
cargo test --locked --test openrouter_provider_contract
cargo test --locked --test provider_catalog_contract
cargo clippy --locked --lib -- -D warnings
```

Commit: `feat: add OpenRouter provider adapter`

---

### Task 5: Add Carl-owned capability-relative coding tools

**Files:**
- Create: `src/tools/mod.rs`
- Create: `src/tools/schema.rs`
- Create: `src/tools/filesystem.rs`
- Create: `src/tools/command.rs`
- Modify: `src/lib.rs`
- Test: `tests/native_tools_contract.rs`

**Interfaces:**
- Consumes: canonical workspace directory, `PermissionMode`, cancellation, tool name, and bounded JSON arguments.
- Produces: `NativeToolRuntime::definitions` and `NativeToolRuntime::prepare`, returning a `PreparedNativeTool` with a stable digest, effect kind, summary, and `execute` future.

- [ ] **Step 1: Write tool RED tests**

Cover exact JSON schemas and these limits:

```text
read_file: 1 MiB, optional line range, UTF-8 only
list_directory: 2,000 entries, depth 1, 512 KiB encoded result
search_text: literal or regex, 2,000 matches, 1 MiB output
apply_patch: 1 MiB patch, 128 files, no binary or mode changes
run_command: 128 argv values, 8 KiB each, 120 seconds, 4 MiB aggregate output
```

Mutation cases must reject absolute/traversal paths, NUL/control bytes, symlinks, hard links, sockets/devices/FIFOs, `.git`, secret-bearing reads/results, file swaps between validation/use, shell strings, ambient environment, output overflow, timeout, cancellation, and descendants surviving completion. Prove `apply_patch` is atomic across all files and returns a bounded diff summary.

- [ ] **Step 2: Observe RED**

Run: `cargo test --locked --test native_tools_contract`

Expected: compile failure because `carl::tools` is missing.

- [ ] **Step 3: Implement tool preparation and execution**

Use cap-std directory handles for reads/list/search and the existing workspace topology/revalidation helpers for mutation. Reuse the existing bounded sidecar supervisor for commands. `prepare` parses one `#[serde(deny_unknown_fields)]` argument type and calculates a canonical digest before any effect; execution revalidates every named object and cannot broaden the prepared capability.

- [ ] **Step 4: Run and commit**

Run:

```bash
cargo test --locked --test native_tools_contract
cargo test --locked --test sidecar_contract
cargo test --locked --test secret_filter_contract
cargo clippy --locked --lib -- -D warnings
```

Commit: `feat: add Carl native coding tools`

---

### Task 6: Implement the native provider AgentPort loop

**Files:**
- Create: `src/runtime/native_port.rs`
- Modify: `src/runtime/mod.rs`
- Modify: `src/runtime/agent_port.rs`
- Test: `tests/native_agent_port_contract.rs`

**Interfaces:**
- Consumes: `Arc<dyn Provider>`, `ProviderCatalog`, `NativeToolRuntime`, `StartAgentContext`, `StartAgentEpoch`, steering/cancellation, and `EffectDecision`.
- Produces: `NativeAgentPort` implementing the existing `AgentPort` without adding a second task engine.

- [ ] **Step 1: Write multi-turn RED tests**

Use `ScriptedProvider` to prove: planning emits a completion contract; work text streams; one and parallel tool calls become bound `EffectRequested` events; denied effects return tool errors without dispatch; allowed reads/edits/commands execute once; tool results return to the next model request; usage maps to context pressure; tool rounds stop at 64; malformed or missing finish blocks safely; steering appends to the next model input; cancellation interrupts provider and tool work; compact replaces message history from Carl's canonical context; restart never replays a started ambiguous effect.

- [ ] **Step 2: Observe RED**

Run: `cargo test --locked --test native_agent_port_contract`

Expected: compile failure because `NativeAgentPort` is missing.

- [ ] **Step 3: Implement the adapter loop**

Keep provider messages inside one bounded native context. `start_epoch` constructs one request and queues normalized events. A tool call queues `AgentItem`, then `EffectRequested`; `resolve_effect(Allow)` executes the previously prepared capability exactly once and queues `ItemCompleted`, while Deny queues a failed tool result. When all calls finish, issue the next provider request with assistant tool-call and tool-result messages. `compact_context` replaces history from the supplied Carl context package rather than summarizing independently.

- [ ] **Step 4: Run and commit**

Run:

```bash
cargo test --locked --test native_agent_port_contract
cargo test --locked --test agent_port_contract
cargo test --locked --test epoch_engine_contract
cargo clippy --locked --lib -- -D warnings
```

Commit: `feat: run native providers through durable task engine`

---

### Task 7: Wire provider selection into the service and TUI

**Files:**
- Modify: `src/service/protocol.rs`
- Modify: `src/service/client.rs`
- Modify: `src/service/server.rs`
- Modify: `src/tui/command.rs`
- Modify: `src/tui/controller.rs`
- Modify: `src/tui/render.rs`
- Modify: `src/tui/state.rs`
- Test: `tests/service_protocol_contract.rs`
- Test: `tests/service_end_to_end.rs`
- Test: `tests/tui_controller_contract.rs`

**Interfaces:**
- Consumes: subscription/native provider factories and their strict catalogs.
- Produces: service protocol v7 `ProviderCatalogs`, provider-bound starts/configuration, and working `/provider [id]` plus provider-scoped `/model`.

- [ ] **Step 1: Write protocol/controller RED tests**

Add required provider identity to new task admission and session summaries; make command digests provider-sensitive. Test v6 rejection, strict v7 capability negotiation, provider list read-only behavior, selection before a task, safe-boundary provider replacement during active work, model reset to the selected provider's default, unsupported model rejection, persistence/reconnect, and subscription/native session isolation. `/provider` with no value must render available configured providers; it must not claim an unconfigured adapter.

- [ ] **Step 2: Observe RED**

Run:

```bash
cargo test --locked --test service_protocol_contract
cargo test --locked --test tui_controller_contract
```

Expected: compile failures for provider-aware protocol fields.

- [ ] **Step 3: Implement service routing**

Create the selected provider/port only inside the single service owner. Existing tasks keep their persisted provider; switching affects the next task unless the active task reaches a checkpoint and provider-context replacement succeeds. The subscription adapter remains default when configured. TUI status always displays provider and never a key/account identifier.

- [ ] **Step 4: Run and commit**

Run:

```bash
cargo test --locked --test service_protocol_contract
cargo test --locked --test service_end_to_end
cargo test --locked --test tui_controller_contract
cargo test --locked --test tui_render_contract
```

Commit: `feat: select native providers in Carl TUI`

---

### Task 8: Prove the offline native coding workflow and document support

**Files:**
- Create: `tests/native_coding_end_to_end.rs`
- Modify: `tests/docs_contract.rs`
- Modify: `README.md`
- Modify: `docs/configuration.md`
- Modify: `docs/security.md`
- Modify: `docs/superpowers/specs/2026-08-13-carl-native-tui-provider-runtime-design.md`

**Interfaces:**
- Consumes: real service, TUI controller, loopback OpenAI/OpenRouter fixtures, native tools, durable store, compaction, cancellation, and reconnect.
- Produces: one credential-free release acceptance target and accurate provider/tool documentation.

- [ ] **Step 1: Write end-to-end and docs RED tests**

Run the same disposable repository task once through loopback OpenAI Responses and once through loopback OpenRouter: read multiple files, search, patch two files, run a failing command, recover, run passing verification, compact, reconnect, and complete. Assert exact final manifest parity, one dispatch per effect digest, no secret persistence/output, bounded transcripts, durable operation replay equivalence, and no process/service leak. Documentation must list the five native tools, explain OpenRouter model filtering, distinguish subscription from API billing, and state that key onboarding is the following slice.

- [ ] **Step 2: Observe RED**

Run:

```bash
cargo test --locked --test native_coding_end_to_end
cargo test --locked --test docs_contract native_provider
```

Expected: failure until the workflow and documentation are complete.

- [ ] **Step 3: Complete docs and acceptance fixture**

Document exact provider endpoints, model capability filtering, tool limits, permission mediation, and the absence of direct vendor adapters beyond OpenAI/OpenRouter. State that DeepSeek/Qwen/Kimi/Anthropic/Google/xAI models work only when OpenRouter advertises text plus tools.

- [ ] **Step 4: Run the merge gate and commit**

Run:

```bash
cargo test --locked --test provider_catalog_contract
cargo test --locked --test provider_http_contract
cargo test --locked --test openai_provider_contract
cargo test --locked --test openrouter_provider_contract
cargo test --locked --test native_tools_contract
cargo test --locked --test native_agent_port_contract
cargo test --locked --test native_coding_end_to_end
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Commit: `docs: ship Carl native provider and tool runtime`

## Completion boundary

This plan ends when configured OpenAI API and OpenRouter credentials can drive the durable Carl task engine through Carl-owned tools. It does not capture or persist credentials. Secure key capture, OS-vault storage, first-run selection, `/login`, `/logout`, and setup recovery belong to `2026-08-13-carl-provider-onboarding.md` and must not be simulated by this implementation.
