# Carl Vertical Coding Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task by task with a fresh implementer and reviewer for each task.

**Goal:** Deliver Carl's first real, deterministic coding loop: assemble inspectable context, stream a provider response, route workspace-confined read/search/patch tools, persist the execution facts, verify mutations, and return a final answer.

**Architecture:** Keep the executable deliberately inert until the Phase 3 policy, approval, and sandbox boundary exists. Phase 2 exposes a library-level `AgentRuntime` whose dependencies are explicit: `Provider`, `ToolRegistry`, `ContextBuilder`, and SQLite `Store`. A scripted provider proves the entire loop offline; a separately tested OpenAI Responses adapter implements the same normalized provider contract without requiring network access in CI. Subscription-backed Codex and Grok integrations remain outside the native provider contract because their supported OAuth boundaries expose full coding agents, not raw model sampling. After Phase 3, Carl may invoke them only as policy-routed, staging-confined delegate tools.

**Tech Stack:** Rust 2024, Tokio, futures, serde/serde_json, rusqlite, sha2, regex, reqwest with rustls, and wiremock for offline HTTP/SSE contract tests.

## Global constraints

- Follow the approved design in `docs/superpowers/specs/2026-07-23-carl-top-tier-harness-design.md`.
- Keep one Rust package and one distributable `carl` binary.
- Do not add LangChain, a framework-style graph abstraction, dynamic plugins, shell execution, network tools, or Telegram behavior in this phase.
- Do not expose autonomous tool execution from the CLI before Phase 3 policy, approval binding, and sandboxing are implemented.
- The journal remains authoritative. Persist every accepted consequential fact before the corresponding state is exposed or a mutation executes.
- Execute tool proposals sequentially in provider order. Set `parallel_tool_calls: false` in the OpenAI adapter.
- Never perform fuzzy or partial patches. Every stale condition observed at the locked
  execution precondition must fail closed.
- Keep all normal tests offline. A developer API key is optional for later manual smoke tests and must never enter fixtures, logs, errors, or version control.
- Use only documented OpenAI authentication: bearer API keys or documented short-lived access tokens. Do not reuse ChatGPT/Codex credentials.
- Do not copy provider OAuth client IDs, read provider credential caches, or forward
  subscription bearer tokens into Carl's native HTTP providers. Subscription login
  follows `2026-07-24-carl-subscription-auth.md`; delegate execution follows the
  post-Phase-3 `2026-07-24-carl-subscription-delegates.md` plan.
- Run `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` after every task that changes Rust code.

---

## Task 1: Add durable Phase 2 lifecycle events

**Files:**

- Modify: `src/events.rs`
- Modify: `tests/domain_contract.rs`
- Modify: `tests/storage_contract.rs`

### Step 1: Write failing serialization and journal tests

Add round-trip assertions for these additive event variants:

```rust
Event::TurnStarted
Event::ContextBuilt {
    sources: vec![ContextSourceRecord {
        name: "CARL.md".into(),
        byte_count: 128,
        sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
    }],
}
Event::ModelRequested {
    iteration: 1,
    provider: "scripted".into(),
    model: "fixture-model".into(),
    message_count: 3,
    tool_count: 4,
    capabilities: ProviderCapabilityRecord {
        streaming: true,
        structured_tool_calls: true,
        parallel_tool_calls: false,
        usage_reporting: true,
        context_window: Some(128_000),
    },
}
Event::ModelUsageRecorded {
    iteration: 1,
    input_tokens: 100,
    output_tokens: 20,
}
Event::AssistantMessageCompleted {
    text: "Done.".into(),
}
Event::ToolStarted {
    tool_call_id,
    preview: json!({"path": "src/lib.rs"}),
}
Event::VerificationRecorded {
    tool_call_id,
    evidence: json!({"kind": "file_sha256", "sha256": "..."}),
}
Event::TurnFailed {
    code: ErrorCode::Tool,
    message: "The tool failed.".into(),
}
```

The tests must assert:

- each JSON payload contains `schema_version: 1`;
- the expected `type` discriminator is stable snake case;
- `Store::append` and `Store::read_events` preserve event order and payloads;
- old Phase 1 events still deserialize unchanged.

Run:

```bash
cargo test --test domain_contract event_round_trip -- --nocapture
cargo test --test storage_contract phase_two_events -- --nocapture
```

Expected: both fail because the variants and `ContextSourceRecord` do not exist.

### Step 2: Implement the event variants

Add this public record beside the ID types in `src/events.rs`:

```rust
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSourceRecord {
    pub name: String,
    pub byte_count: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilityRecord {
    pub streaming: bool,
    pub structured_tool_calls: bool,
    pub parallel_tool_calls: bool,
    pub usage_reporting: bool,
    pub context_window: Option<u64>,
}
```

Add the variants exactly as exercised by the tests to `Event`, `EventRef`, `EventPayload`, and both conversion implementations. Keep `EVENT_SCHEMA_VERSION` at `1` because this is an additive pre-1.0 schema extension and existing payloads remain readable.

### Step 3: Verify and commit

Run the global Rust checks.

Commit:

```bash
git add src/events.rs tests/domain_contract.rs tests/storage_contract.rs
git commit -m "feat: add coding loop lifecycle events"
```

---

## Task 2: Build inspectable context assembly

**Files:**

- Create: `src/context.rs`
- Modify: `src/lib.rs`
- Create: `tests/context_contract.rs`
- Create: `tests/fixtures/context/AGENTS.md`

### Step 1: Write failing precedence, ledger, and bounds tests

Test the public contract:

```rust
pub struct ContextBuilder {
    max_source_bytes: u64,
    max_total_bytes: u64,
}

pub struct ContextInput<'a> {
    pub workspace: &'a Path,
    pub user_text: &'a str,
    pub prior_messages: &'a [Message],
}

pub struct BuiltContext {
    pub messages: Vec<Message>,
    pub sources: Vec<ContextSourceRecord>,
}

impl ContextBuilder {
    pub fn build(&self, input: ContextInput<'_>) -> Result<BuiltContext, CarlError>;
}
```

Assertions:

- the compile-time embedded public `CARL.md` is loaded first, workspace `AGENTS.md` second, prior messages third, and current user text last;
- instruction sources become separate system messages so provenance remains visible;
- each source ledger entry contains its relative display name, byte count, and lowercase SHA-256;
- a missing instruction file is skipped, not treated as empty;
- invalid UTF-8, a source over `max_source_bytes`, aggregate instruction bytes over `max_total_bytes`, or an empty user request returns `CarlError::Validation`;
- `ContextBuilder` never follows a workspace `AGENTS.md` symlink outside the canonical workspace.

Run:

```bash
cargo test --test context_contract -- --nocapture
```

Expected: fail because `carl::context` does not exist.

### Step 2: Implement deterministic assembly

Embed the public contract with `include_str!("../CARL.md")`; record it as
`builtin:CARL.md` in the ledger so a target repository cannot replace Carl's own
operating contract. Open the workspace as a capability root, read `AGENTS.md`
relative to that handle without following symlinks, and use `sha2::Sha256` plus
checked `u64` conversions. Do not perform a check-then-reopen sequence through an
ambient path. Add:

```rust
impl Default for ContextBuilder {
    fn default() -> Self {
        Self {
            max_source_bytes: 128 * 1024,
            max_total_bytes: 256 * 1024,
        }
    }
}
```

The builder must not estimate model tokens in this phase. Its ledger is exact byte accounting; token accounting and compaction are Phase 5.

### Step 3: Verify and commit

Run the global Rust checks.

Commit:

```bash
git add src/context.rs src/lib.rs tests/context_contract.rs tests/fixtures/context
git commit -m "feat: add inspectable context assembly"
```

---

## Task 3: Establish the tool preparation boundary and workspace confinement

**Files:**

- Create: `src/tools/mod.rs`
- Create: `src/tools/workspace.rs`
- Modify: `src/lib.rs`
- Modify: `src/error.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `tests/tool_contract.rs`

### Step 1: Write failing registry and confinement tests

Define the tested public seam:

```rust
pub trait Tool: Send + Sync {
    fn definition(&self) -> ToolDefinition;
    fn prepare(
        &self,
        workspace: &Workspace,
        arguments: Value,
    ) -> Result<Box<dyn PreparedTool>, ToolError>;
}

pub trait PreparedTool: Send {
    fn normalized_arguments(&self) -> &Value;
    fn preview(&self) -> &Value;
    fn execute(self: Box<Self>) -> Result<ToolExecution, ToolError>;
}

pub struct ToolExecution {
    pub output: Value,
    pub verification: Option<Value>,
}

pub struct ToolRegistry { /* private map */ }

impl ToolRegistry {
    pub fn with_builtins(workspace: Workspace) -> Self;
    pub fn definitions(&self) -> Vec<ToolDefinition>;
    pub fn prepare(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<Box<dyn PreparedTool>, ToolError>;
}
```

Test:

- builtin definitions are sorted by tool name for deterministic prompts;
- unknown tools fail with `ToolError::UnknownTool`;
- every definition has an object input schema with `additionalProperties: false`;
- `Workspace::open` stores a canonical display root and one open `cap_std::fs::Dir`
  capability rooted there;
- relative traversal, absolute paths, NUL bytes, and symlinks escaping the root are rejected;
- non-existent write targets are resolved only through an already-open parent directory
  capability beneath the root;
- a concurrent ancestor symlink/directory swap cannot redirect an open, create, or
  rename outside the root;
- `ToolError::code()` maps schema/input failures to `ErrorCode::Validation` and execution failures to `ErrorCode::Tool`;
- `Display` and conversions into `CarlError` expose sanitized messages without leaking file contents.

Run:

```bash
cargo test --test tool_contract registry -- --nocapture
cargo test --test tool_contract workspace_boundary -- --nocapture
```

Expected: fail because the tool module does not exist.

### Step 2: Implement the contracts

Use a private `BTreeMap<String, Arc<dyn Tool>>` to make ordering deterministic.
`Workspace` must provide separate read-existing and write-target capability operations;
no tool may join and reopen an ambient absolute path. Use `cap-std` and
`cap-fs-ext` no-follow options so path traversal and replacement remain relative to an
open directory handle on Unix and Windows. Ambient canonical paths exist only for
display and diagnostics.

Keep previews JSON-serializable and bounded. Define constants in `src/tools/mod.rs`:

```rust
pub const MAX_TOOL_OUTPUT_BYTES: usize = 256 * 1024;
pub const MAX_PATH_BYTES: usize = 4 * 1024;
```

### Step 3: Verify and commit

Run the global Rust checks.

Commit:

```bash
git add Cargo.toml Cargo.lock src/tools src/lib.rs src/error.rs tests/tool_contract.rs
git commit -m "feat: add prepared tool boundary"
```

---

## Task 4: Implement deterministic list, read, and search tools

**Files:**

- Create: `src/tools/list.rs`
- Create: `src/tools/read.rs`
- Create: `src/tools/search.rs`
- Modify: `src/tools/mod.rs`
- Extend: `tests/tool_contract.rs`
- Create: `tests/fixtures/workspace/src/lib.rs`
- Create: `tests/fixtures/workspace/README.md`

### Step 1: Write failing builtin behavior tests

Implement and test these exact tool names and inputs:

```json
{"name":"fs.list","input":{"path":".","max_entries":200}}
{"name":"fs.read","input":{"path":"src/lib.rs","offset":0,"limit":65536}}
{"name":"fs.search","input":{"query":"needle","path":".","max_results":100}}
```

The schemas must require the semantic fields, reject unknown fields, and apply these hard maxima:

- list: 1,000 entries;
- read: 256 KiB;
- search: 1,000 matches and 1 MiB scanned file size per file.

Assertions:

- list output is sorted, relative, uses `/` separators on every OS, labels entry kind, and never follows directory symlinks;
- read returns UTF-8 text, selected byte range, total bytes, truncation flag, and file SHA-256;
- read rejects offsets that split a UTF-8 code point;
- search uses a literal query, deterministic path/line/column ordering, excludes `.git`, skips binary files and symlinks, and reports truncation;
- outputs over `MAX_TOOL_OUTPUT_BYTES` fail closed instead of silently emitting an oversized result;
- all three tools produce a preview during `prepare` and do no I/O mutation during `execute`.

Run:

```bash
cargo test --test tool_contract readonly_tools -- --nocapture
```

Expected: fail because the builtins are not registered.

### Step 2: Implement the read-only tools

Deserialize arguments using private `#[serde(deny_unknown_fields)]` structs. Use a compiled escaped regex only for line/column matching, never model-provided regex syntax. Normalize all display paths with forward slashes.

### Step 3: Verify and commit

Run the global Rust checks.

Commit:

```bash
git add src/tools tests/tool_contract.rs tests/fixtures/workspace
git commit -m "feat: add workspace read and search tools"
```

---

## Task 5: Implement stale-checked atomic patching

**Files:**

- Create: `src/tools/patch.rs`
- Modify: `src/tools/mod.rs`
- Extend: `tests/tool_contract.rs`

### Step 1: Write failing patch safety tests

Use a deliberately strict exact-edit contract:

```json
{
  "path": "src/lib.rs",
  "expected_sha256": "64-lowercase-hex-characters",
  "edits": [
    {"old_text": "fn old() {}", "new_text": "fn new() {}"}
  ]
}
```

Test:

- `prepare` validates the expected digest, non-empty `old_text`, non-empty edit list, bounded arguments, and workspace confinement;
- each `old_text` must occur exactly once in the current file;
- edits are applied sequentially to an in-memory candidate;
- preview contains path, before/after SHA-256, changed byte count, and a bounded unified-style textual diff;
- `prepare` performs no mutation;
- `execute` re-reads and re-hashes the file through the retained workspace capability
  immediately before writing;
- a stale hash, a duplicate match, a missing match, invalid UTF-8, symlink escape, or
  change visible at the locked execution precondition fails without modifying any
  byte;
- two independently prepared Carl patches to the same path execute behind one
  process-local workspace mutation lock; a barrier-controlled test proves the first
  succeeds and the second fails its stale check without a second mutation;
- successful execution creates a random `create_new` temporary file through the open
  parent-directory capability, applies the original permissions, flushes and
  `sync_all`s it, atomically renames it with capability-relative `Dir::rename`, syncs
  the parent directory where supported, leaves no temporary file, and returns
  capability-relative read-back SHA-256 verification evidence;
- a second execution cannot occur because `PreparedTool::execute` consumes the boxed value.

Run:

```bash
cargo test --test tool_contract patch_tool -- --nocapture
```

Expected: fail because `fs.apply_patch` does not exist.

### Step 2: Implement exact patch preparation and execution

Register `fs.apply_patch`. Use `sha2` for hashes and `similar` for preview generation.
Retain the open parent-directory capability from preparation through execution. Create
the temporary file and perform replacement through `cap_std::fs::Dir`; never
revalidate a string path and then reopen it through `std::fs`. Revalidate the current
file identity and digest while holding Carl's process-local workspace mutation lock,
immediately before capability-relative rename. Keep the lock through parent sync and
read-back verification.

Be precise about the concurrency guarantee: the lock serializes every Carl mutation
within the process and the capability root prevents ancestor/path escape. Mainstream
portable filesystems do not expose an atomic "replace only if this path still names
this inode and digest" primitive. A non-cooperating external writer can still race the
final check and rename. Keep that interval minimal, verify the postcondition, emit a
failed verification if it is lost, and document the limitation instead of claiming a
portable compare-and-swap guarantee.

The successful output must be:

```json
{
  "path": "src/lib.rs",
  "before_sha256": "...",
  "after_sha256": "...",
  "changed": true
}
```

The verification payload must be:

```json
{
  "kind": "file_sha256",
  "path": "src/lib.rs",
  "sha256": "...",
  "verified": true
}
```

This evidence proves the patch postcondition only. It must not be labeled as behavioral test evidence.

### Step 3: Verify and commit

Run the global Rust checks.

Commit:

```bash
git add Cargo.toml Cargo.lock src/tools tests/tool_contract.rs
git commit -m "feat: add stale-checked atomic patch tool"
```

---

## Task 6: Implement the iterative event-sourced agent runtime

**Files:**

- Create: `src/runtime/agent.rs`
- Modify: `src/runtime/mod.rs`
- Modify: `src/providers/mod.rs`
- Modify: `src/providers/scripted.rs`
- Modify: `tests/fixtures/provider/tool_then_answer.json`
- Create: `tests/fixtures/provider/direct_answer.json`
- Create: `tests/vertical_loop.rs`

### Step 1: Write failing direct-answer and patch scenarios

Test this public entry point:

```rust
pub struct AgentRuntime<'a, P: Provider> {
    pub provider: &'a P,
    pub tools: &'a ToolRegistry,
    pub context: &'a ContextBuilder,
    pub store: &'a mut Store,
    pub settings: ModelSettings,
    pub budget: TurnBudget,
}

pub struct TurnRequest<'a> {
    pub session_id: SessionId,
    pub workspace: &'a Path,
    pub user_text: &'a str,
    pub prior_messages: &'a [Message],
    pub cancellation: CancellationToken,
}

pub struct TurnOutcome {
    pub turn_id: TurnId,
    pub final_text: String,
    pub usage: UsageTotals,
}

impl<P: Provider> AgentRuntime<'_, P> {
    pub async fn run_turn(
        &mut self,
        request: TurnRequest<'_>,
    ) -> Result<TurnOutcome, CarlError>;
}
```

Direct-answer assertions:

- journal order is `TurnStarted`, `UserInput`, `ContextBuilt`, `ModelRequested`, deltas, `AssistantMessageCompleted`, optional `ModelUsageRecorded`, `TurnCompleted`;
- returned final text equals the concatenated deltas;
- one provider request contains ordered context and all four tool definitions.

Patch-then-answer assertions:

- the scripted provider first proposes `fs.apply_patch`, then returns a final answer;
- journal order contains `ToolProposed` and `ToolStarted` before the fixture file changes, followed by `ToolCompleted` and `VerificationRecorded`;
- the second provider request contains the assistant tool call plus a tool-role `ToolResult` with the same `ToolCallId`;
- the fixture file ends at the expected content and hash;
- exactly two model iterations and one tool call are charged.

Run:

```bash
cargo test --test vertical_loop direct_answer -- --nocapture
cargo test --test vertical_loop patch_then_answer -- --nocapture
```

Expected: fail because `AgentRuntime` does not exist.

### Step 2: Implement the iterative loop

Implementation requirements:

1. Create one `TurnId`, append `TurnStarted`, then append accepted `UserInput`.
2. Build context once and append `ContextBuilt`.
3. For each iteration, charge `BudgetTracker`, append `ModelRequested` with provider
   identity, model, and the exact capability snapshot, then call `Provider::stream`.
4. Append bounded `AssistantTextDelta` events while accumulating the current assistant message.
5. Collect tool proposals in stream order. If a response contains both text and tool calls, persist one `AssistantMessageCompleted` for the bounded text and preserve that text beside the assistant tool calls in the next model-visible message.
6. On a tool-call finish, append `ToolProposed`, prepare it, append `ToolStarted` with the exact preview, execute it, append `ToolCompleted`, append optional `VerificationRecorded`, and add the complete assistant response plus tool result to model-visible messages.
7. When usage arrives, checked-add it to the outcome and append
   `ModelUsageRecorded` for that iteration. Reject duplicate usage events in one
   response.
8. On a stop finish, require non-empty final text, append
   `AssistantMessageCompleted`, then `TurnCompleted`.
9. On cancellation, append `TurnInterrupted` and return `CarlError::Cancelled`.
10. On every other error, append sanitized `TurnFailed` when storage remains
    available, then return the typed error.
11. Never recursively invoke `run_turn`.

Add `Provider::id(&self) -> &str`, implement it for scripted and live adapters, and add
`UsageTotals` with checked token addition. Extend `FinishReason` only if the OpenAI
adapter needs a documented failure mapping; do not silently map unknown terminal
conditions to `Stop`.

### Step 3: Add failure-path tests

Test cancellation before provider start, cancellation during a scripted stream, iteration exhaustion, tool-call exhaustion, malformed finish ordering, unknown tools, invalid arguments, and provider failure. Assert each path has exactly one terminal event.

Run:

```bash
cargo test --test vertical_loop -- --nocapture
```

Expected: pass.

### Step 4: Verify and commit

Run the global Rust checks.

Commit:

```bash
git add src/runtime src/providers tests/vertical_loop.rs tests/fixtures/provider
git commit -m "feat: run deterministic coding turns"
```

---

## Task 7: Implement the OpenAI Responses streaming adapter

**Files:**

- Create: `src/providers/openai.rs`
- Modify: `src/providers/mod.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `tests/openai_provider_contract.rs`

### Step 1: Complete the credential safety gate

Before editing API-backed code, follow `openai-developers:openai-platform-api-key`. If a key is created, write it only to a user-confirmed ignored env file. Do not require the key for any test below.

### Step 2: Write failing offline HTTP and SSE tests

Test this constructor seam:

```rust
pub struct OpenAiResponsesProvider { /* private */ }

impl OpenAiResponsesProvider {
    pub fn new(api_key: SecretString) -> Result<Self, ProviderError>;
    pub fn with_base_url(
        api_key: SecretString,
        base_url: Url,
    ) -> Result<Self, ProviderError>;
}
```

Use `wiremock` on loopback. Assert the request:

- is `POST /v1/responses`;
- sends bearer authorization without exposing it through `Debug`;
- contains `model`, normalized input items, internally tagged function tools, `stream: true`, `store: false`, and `parallel_tool_calls: false`;
- omits absent temperature and max-token settings;
- serializes a `ToolCall` item and matching `function_call_output` with one stable opaque `call_id`;
- sets `strict: true` and supplies object schemas with `additionalProperties: false`.

Feed SSE fixtures containing:

- `response.output_text.delta`;
- `response.output_item.added` with a `function_call` item carrying `id`, `call_id`, and `name`;
- multiple `response.function_call_arguments.delta` chunks;
- `response.function_call_arguments.done` with complete JSON arguments;
- `response.completed` with usage;
- an `error` event.

Assert the normalized stream emits:

```rust
ProviderEvent::TextDelta { .. }
ProviderEvent::ToolCall { tool_call_id, name, arguments }
ProviderEvent::Usage { input_tokens, output_tokens }
ProviderEvent::Finish { reason }
```

The adapter must maintain an internal bijection between Carl `ToolCallId` values and opaque OpenAI `call_id` strings for the duration of one request chain. OpenAI identifiers never become Carl domain identifiers.

Run:

```bash
cargo test --test openai_provider_contract -- --nocapture
```

Expected: fail because `providers::openai` does not exist.

### Step 3: Implement the documented Responses protocol

Use official contracts:

- create endpoint: `POST https://api.openai.com/v1/responses`;
- typed SSE events from the Responses streaming guide;
- function metadata from `response.output_item.added`;
- complete function arguments from `response.function_call_arguments.done`;
- function outputs as `{"type":"function_call_output","call_id":"...","output":"..."}`;
- reasoning items are not supported by the normalized Phase 2 message model, so fail explicitly if a required reasoning item appears in a stateless continuation rather than dropping it.

Implement an incremental SSE decoder that handles:

- arbitrary HTTP chunk boundaries;
- `\n` and `\r\n`;
- multiple `data:` lines;
- comments/keepalives;
- a final event without a trailing blank line;
- unknown future event types by ignoring only events that do not alter text, tool, usage, or terminal semantics.

Use `reqwest` with default features disabled and `rustls-tls`, `json`, and `stream`. Use `secrecy::SecretString` and never include the secret, authorization header, or raw provider response body in an error.

Map status codes:

- `401`/`403` to `ProviderError::Authentication`;
- `429` to `ProviderError::RateLimit` with parsed `Retry-After` when valid;
- other `4xx` to `InvalidRequest`;
- `5xx` and transport failures to `Transport`.

Include a sanitized `x-request-id` in diagnostic detail when present.

### Step 4: Add malformed-protocol and redaction tests

Test invalid JSON, invalid UTF-8, missing function metadata, duplicate call IDs, non-object function arguments, stream EOF before a terminal event, HTTP errors, and cancellation. Assert a sentinel API key never appears in `Debug`, `Display`, or any `ProviderError.detail`.

Run:

```bash
cargo test --test openai_provider_contract -- --nocapture
```

Expected: pass without network access or environment variables.

### Step 5: Verify and commit

Run the global Rust checks.

Commit:

```bash
git add Cargo.toml Cargo.lock src/providers tests/openai_provider_contract.rs
git commit -m "feat: add OpenAI Responses provider"
```

---

## Task 8: Document, evaluate, and publish the vertical slice

**Files:**

- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/security.md`
- Modify: `docs/configuration.md`
- Modify: `CHANGELOG.md`
- Create: `docs/evaluations/vertical-loop.md`
- Modify: `tests/docs_contract.rs`
- Modify: `tests/identity_contract.rs`

### Step 1: Write failing documentation contracts

Require the public docs to state:

- Carl now has a deterministic library-level coding loop;
- implemented tools are exactly `fs.list`, `fs.read`, `fs.search`, and `fs.apply_patch`;
- the live provider is OpenAI Responses with documented API-key authentication;
- all standard tests are offline;
- patch verification proves the file postcondition, not behavioral correctness;
- Carl serializes its own workspace mutations and checks staleness immediately before
  atomic replacement, but cannot provide a portable compare-and-swap guarantee against
  an unsynchronized external writer in the final check-to-rename interval;
- autonomous CLI use remains intentionally disabled until policy, approvals, and sandboxing land in Phase 3;
- native OpenAI Responses authentication remains API-key based because OpenAI does
  not document a third-party subscription-to-Responses OAuth flow; eligible ChatGPT
  and Grok subscriptions use the separately documented provider-owned sidecar login
  boundary and are not native providers.

Run:

```bash
cargo test --test docs_contract -- --nocapture
```

Expected: fail until docs are updated.

### Step 2: Add a reproducible evaluation write-up

`docs/evaluations/vertical-loop.md` must identify:

- fixture repository input;
- scripted provider transcript;
- expected event sequence;
- expected file hash;
- exact command `cargo test --test vertical_loop patch_then_answer -- --nocapture`;
- what the scenario proves and what it does not prove.

Do not claim production readiness or sandboxing.

### Step 3: Run the release gate

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps
cargo deny check
git diff --check
rg -n "TODO|FIXME|todo!|unimplemented!|ArcWren|arcwren|ARCWREN" \
  src tests README.md CARL.md docs Cargo.toml
```

Expected:

- every build/test/lint/doc/license check passes;
- the scan returns no implementation placeholders or stale live identity references;
- historical files may contain old identity references only where their historical status is explicit and contract tests allow them.

### Step 4: Run whole-branch review

Use `superpowers:requesting-code-review` with the final reviewer package from the merge base through branch HEAD. Resolve every high- and medium-confidence correctness, security, durability, or documentation finding. Re-run the entire release gate after fixes.

### Step 5: Commit, push, PR, and merge

Commit documentation:

```bash
git add README.md CHANGELOG.md docs tests/docs_contract.rs tests/identity_contract.rs
git commit -m "docs: document the vertical coding loop"
```

Push `codex/carl-vertical-loop`, open a non-draft PR against `main`, and include:

- architecture summary;
- exact safety boundary;
- deterministic scenario evidence;
- local release-gate results.

Wait for GitHub Quality, Ubuntu, macOS, and Windows checks. Fix failures on the branch. Merge only when every required check is green and the whole-branch reviewer has approved. Pull merged `main` locally and run:

```bash
cargo test --all-features
```

Expected: green on the merged commit.
