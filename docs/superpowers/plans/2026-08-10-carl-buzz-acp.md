# Carl Buzz ACP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Ship a durable `carl acp` coding harness that Buzz can drive over ACP, using the owner's Codex subscription while Carl controls sessions, model and effort selection, permissions, exact remote approvals, cancellation, steering, Buzz delivery, and credential isolation.

**Architecture:** One `carl acp` process owns Carl's data root, a single supervised Codex app-server, and a kernel actor that multiplexes durable ACP sessions while allowing one active provider turn at a time. The ACP frontend parses bounded NDJSON and translates requests into typed kernel commands; Codex app-server is a provider-sidecar execution port, not the ACP server. Buzz context and credentials terminate in a restricted adapter that publishes typed messages through the pinned Buzz CLI and never exposes its environment to the model or coding tools.

**Tech Stack:** Rust 2024, Tokio, serde/serde_json, rusqlite SQLite WAL, SHA-256, Clap, existing process-wrap supervision, ACP JSON-RPC over NDJSON, Codex CLI/app-server `0.146.0`, Buzz ACP contract pinned at `block/buzz@44456e200e3ca6a5d2882b58b447b80474041347`.

## Global Constraints

- Follow `docs/superpowers/specs/2026-08-10-carl-buzz-acp-design.md` and the security boundaries in `docs/superpowers/specs/2026-07-23-carl-top-tier-harness-design.md`.
- Keep one Rust package and one distributable `carl` binary; `carl-buzz-mcp` is an argv-zero symlink/alias of that exact artifact.
- `carl acp` supports ACP protocol versions 1 and 2 and advertises only implemented capabilities.
- Ordinary stdout contains NDJSON protocol frames only; all diagnostics use stderr and must be bounded and redacted.
- `CARL_DATA_DIR` is an absolute, pre-existing, owner-private directory with one live Carl owner.
- Buzz V1 requires `BUZZ_ACP_AGENTS=1` and the documented setup sets `BUZZ_ACP_PERMISSION_MODE=default` and `BUZZ_ACP_RESPOND_TO=owner-only`.
- Permission wire values are exactly `plan`, `default`, `acceptEdits`, `dontAsk`, and `bypassPermissions`.
- Remote bypass never activates from an out-of-band config write alone; it requires `/confirm-bypass <code>` in a later admitted slash-command block.
- Approval display codes are bounded lookup keys. The durable request digest and actor/session/turn/tool binding are authoritative, single-use, and expire within fifteen minutes.
- `BUZZ_PRIVATE_KEY`, `BUZZ_RELAY_URL`, and `BUZZ_AUTH_TAG` never enter model input, provider request parameters, journal event JSON, diagnostics, or general child environments.
- Codex subscription credentials remain owned by the official CLI in Carl's isolated provider home. Carl never reads or accepts OAuth bearer or refresh tokens and never falls back to `OPENAI_API_KEY`.
- All normal tests are deterministic, offline, and credential-free. Live Codex and live Buzz tests are explicit opt-in commands and never run in public CI.
- Every Rust behavior change follows red-green-refactor. Before each commit run the focused tests plus `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --locked`.

---

### Task 1: Add duplex sidecar requests and pin the installed Codex protocol

**Files:**
- Modify: `src/sidecar/mod.rs`
- Modify: `src/auth/codex.rs`
- Modify: `src/delegates/codex/mod.rs`
- Modify: `tests/sidecar_contract.rs`
- Modify: `tests/codex_auth_contract.rs`
- Modify: `tests/codex_exec_contract.rs`

**Interfaces:**
- Consumes: existing `JsonlSidecar`, `SidecarCommand`, `ProviderHome`, `TrustedExecutable`, and `SidecarLimits`.
- Produces: `JsonlSidecar::next_server_request()`, `JsonlSidecar::try_next_server_request()`, and `JsonlSidecar::respond_to_server_request(JsonRpcResponse)`; every Codex adapter accepts exactly `codex-cli 0.146.0`.

- [x] **Step 1: Write failing duplex JSON-RPC contracts**

Add a fake sidecar transcript that emits an id-bearing method after initialization and assert it is queued separately from notifications:

```rust
let request = sidecar.next_server_request().await?;
assert_eq!(request["id"], json!("approval-7"));
assert_eq!(request["method"], "item/commandExecution/requestApproval");
sidecar.respond_to_server_request(json!({
    "id": "approval-7",
    "result": {"decision": "accept"}
}))?;
assert_eq!(child_line(), json!({
    "id": "approval-7",
    "result": {"decision": "accept"}
}));
```

Also assert duplicate server IDs, response objects containing `method`, response objects missing `result`/`error`, a full server-request queue, and an unknown ordinary response ID fail closed and reap the child.

- [x] **Step 2: Run the focused tests and verify RED**

Run: `cargo test --locked --test sidecar_contract server_request -- --nocapture`

Expected: FAIL because `JsonlSidecar` has no server-request channel or response API.

- [x] **Step 3: Implement the minimal duplex supervisor path**

Add a bounded server-request channel to `JsonlSidecar`. Classify incoming objects in this order: id+method is a server request, id without method is a response, method without id is a notification, everything else is a protocol violation. Validate responses with this closed predicate:

```rust
fn is_server_response(value: &Value) -> bool {
    value.as_object().is_some_and(|object| {
        object.contains_key("id")
            && !object.contains_key("method")
            && (object.contains_key("result") ^ object.contains_key("error"))
    })
}
```

Use the existing single writer and process supervisor. No second process or raw stdin handle may escape `JsonlSidecar`.

- [x] **Step 4: Update the exact Codex version fixtures**

Change the production pin and fake version transcripts from `0.136.0` to `0.146.0`. Retain exact version matching, explicit provider-owned file auth, strict config, executable revalidation, and all current negative compatibility tests.

- [x] **Step 5: Verify and commit**

Run the Task 1 focused contracts and the global Rust checks.

Commit: `git commit -m "feat: support duplex provider sidecars"`

---

### Task 2: Define the bounded ACP wire and configuration domain

**Files:**
- Create: `src/acp/mod.rs`
- Create: `src/acp/protocol.rs`
- Create: `src/acp/config.rs`
- Modify: `src/lib.rs`
- Create: `tests/acp_protocol_contract.rs`

**Interfaces:**
- Consumes: `ModelId` and `ReasoningEffort` from `carl::delegates`.
- Produces: `JsonRpcId`, `IncomingFrame`, `OutgoingFrame`, `read_frame`, `write_frame`, `PermissionMode`, `ModeActivation`, `SessionConfiguration`, and `config_options`.

- [x] **Step 1: Write failing framing and message-shape tests**

Exercise the wished-for API with partial reads and exact bytes:

```rust
let mut input = BufReader::new(&b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n"[..]);
let frame = read_frame(&mut input, 1_048_576).await?.unwrap();
assert_eq!(frame.id(), Some(&JsonRpcId::Number(1)));
assert_eq!(frame.method(), Some("initialize"));

let mut output = Vec::new();
write_frame(&mut output, &OutgoingFrame::result(JsonRpcId::Number(1), json!({})), 1_048_576).await?;
assert_eq!(output.last(), Some(&b'\n'));
```

Test empty lines, EOF without a final newline, negative and floating IDs, malformed JSON, duplicate JSON keys, a frame at the exact byte limit, one byte above the limit, NUL-containing methods, missing `jsonrpc: "2.0"`, and stdout serialization of results, errors, and notifications.

- [x] **Step 2: Write failing permission/config option tests**

Assert exact parsing and wire values:

```rust
for (wire, mode) in [
    ("plan", PermissionMode::Plan),
    ("default", PermissionMode::Default),
    ("acceptEdits", PermissionMode::AcceptEdits),
    ("dontAsk", PermissionMode::DontAsk),
    ("bypassPermissions", PermissionMode::BypassPermissions),
] {
    assert_eq!(wire.parse::<PermissionMode>()?, mode);
    assert_eq!(mode.as_wire_str(), wire);
}
assert_eq!(config_options(&catalog)[0]["configId"], "model");
assert_eq!(config_options(&catalog)[1]["configId"], "thought_level");
assert_eq!(config_options(&catalog)[2]["configId"], "mode");
```

Reject empty/oversized model IDs, unsupported efforts for the selected model, unknown modes, and a direct `SessionConfiguration::set_mode(BypassPermissions, RemoteUnconfirmed)`.

- [x] **Step 3: Run focused tests and verify RED**

Run: `cargo test --locked --test acp_protocol_contract -- --nocapture`

Expected: FAIL because `carl::acp` does not exist.

- [x] **Step 4: Implement the protocol and configuration types**

Use a bounded `read_until(b'\n')` loop that clears its buffer after every frame and never allocates above `maximum + 1`. `OutgoingFrame` owns a `serde_json::Value` already validated as one JSON-RPC object. `SessionConfiguration` uses provider-reported model catalogs and exposes this mutation result:

```rust
pub enum ModeActivation {
    LocalExplicit,
    RemoteUnconfirmed,
    RemoteConfirmed,
}

pub enum ConfigChange {
    Applied,
    PendingBypass { display_code: String },
    Rejected(ConfigErrorCode),
}
```

Keep all public errors typed with stable codes and static user messages; internal parse detail is diagnostic-only and bounded.

- [x] **Step 5: Verify and commit**

Run the Task 2 contract and global Rust checks.

Commit: `git commit -m "feat: define the ACP wire contract"`

---

### Task 3: Persist ACP session bindings, remote codes, and delivery state

**Files:**
- Create: `migrations/0006_acp_frontends.sql`
- Modify: `src/storage/schema.rs`
- Modify: `src/storage/repository.rs`
- Modify: `src/storage/mod.rs`
- Modify: `src/events.rs`
- Modify: `src/policy/capability.rs`
- Modify: `tests/domain_contract.rs`
- Modify: `tests/policy_contract.rs`
- Modify: `tests/storage_contract.rs`
- Create: `tests/acp_storage_contract.rs`

**Interfaces:**
- Consumes: existing `SessionId`, `TurnId`, `ToolCallId`, `ApprovalId`, `BoundApprovalBinding`, and `RuntimeStore`.
- Produces: `FrontendSessionRecord`, `RemoteCodeKind`, `RemoteCodeRecord`, `DeliveryRecord`, and transactional `Store` methods for bind/configure/create-code/consume-code/record-delivery.

- [x] **Step 1: Write the migration and replay tests first**

Create tests that open a migration-five fixture, upgrade it, bind one external ACP session, close, reopen, and recover the same record:

```rust
let bound = store.bind_frontend_session(NewFrontendSession {
    frontend: Frontend::Buzz,
    external_session_id: "buzz-session-1".try_into()?,
    session_id: session.id,
    cwd: workspace.clone(),
    protocol_version: 2,
    client_name: "buzz-acp".try_into()?,
    permission_mode: PermissionMode::Default,
    created_at: fixed_time(),
})?;
drop(store);
let store = Store::open(database.path())?;
assert_eq!(store.get_frontend_session("buzz-session-1")?, Some(bound));
```

Assert uniqueness for external session IDs and stable `(frontend, channel_id, cwd)` bindings, strict absolute canonical cwd storage, channel rebinding rejection, and migration-seven future-schema rejection.

- [x] **Step 2: Write exact remote-code and delivery tests**

Assert a random display code is stored only as a SHA-256 digest; consume requires the exact external session, actor, kind, unexpired approval, and provider request digest. Replay and wrong-session attempts fail without changing the provider request record. Delivery transitions accept only `pending -> delivered|failed|uncertain`; uncertain delivery cannot be automatically retried.

- [x] **Step 3: Run focused tests and verify RED**

Run: `cargo test --locked --test acp_storage_contract -- --nocapture`

Expected: FAIL because migration six and the frontend records do not exist.

- [x] **Step 4: Implement migration six and additive event schema three**

Create these tables with bounded CHECK constraints and foreign keys:

```sql
CREATE TABLE frontend_sessions (
    external_session_id TEXT PRIMARY KEY NOT NULL,
    frontend TEXT NOT NULL CHECK (frontend IN ('acp', 'buzz')),
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    client_name TEXT NOT NULL,
    protocol_version INTEGER NOT NULL CHECK (protocol_version IN (1, 2)),
    cwd TEXT NOT NULL,
    channel_id TEXT,
    provider_thread_id TEXT,
    permission_mode TEXT NOT NULL CHECK (permission_mode IN ('plan','default','acceptEdits','dontAsk','bypassPermissions')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE remote_codes (
    code_digest TEXT PRIMARY KEY NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('approval','bypass_confirmation')),
    external_session_id TEXT NOT NULL REFERENCES frontend_sessions(external_session_id) ON DELETE CASCADE,
    approval_id TEXT,
    provider_request_id TEXT,
    request_digest TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT
);
```

Add `frontend_deliveries` with a unique action digest and closed status vocabulary. Extend the existing policy `Frontend` enum with `Acp` and `Buzz` and retain the stable snake-case wire representation for all five values. Add backward decoding for event schemas one and two; schema-three variants record frontend binding, permission change, and delivery status without storing raw credentials or approval codes.

- [x] **Step 5: Verify and commit**

Run migration/reopen contracts, Task 3 contracts, and global Rust checks.

Commit: `git commit -m "feat: persist ACP frontend state"`

---

### Task 4: Build the Buzz context, credential, publisher, and MCP boundary

**Files:**
- Create: `src/acp/buzz.rs`
- Create: `src/buzz_mcp.rs`
- Modify: `src/acp/mod.rs`
- Modify: `src/sidecar/bounded_process.rs`
- Modify: `src/lib.rs`
- Create: `tests/buzz_adapter_contract.rs`
- Create: `tests/buzz_mcp_contract.rs`

**Interfaces:**
- Consumes: Buzz `session/new.mcpServers` values and prompt text blocks; existing trusted executable and bounded process primitives.
- Produces: `BuzzContext::parse`, `BuzzPublisherConfig::from_mcp_servers`, `BuzzPublisher::send_message`, `BuzzPublisher::send_diff`, and `buzz_mcp::run_stdio`.

- [x] **Step 1: Write failing context parser contracts**

Use a literal pinned Buzz event block:

```rust
let context = BuzzContext::parse(&[
    "Event ID: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
     Channel: engineering (#123e4567-e89b-12d3-a456-426614174000)\n\
     Kind: 9\n\
     From: Stephen (npub: npub1example, hex: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)\n\
     Content: @Carl fix the test\n\
     Tags: []"
])?;
assert_eq!(context.channel_id().to_string(), "123e4567-e89b-12d3-a456-426614174000");
assert_eq!(context.reply_to(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
```

Reject duplicate conflicting fields, invalid UUID/hex, more than twelve blocks, blocks over 256 KiB aggregate, missing stable channel, and quoted/history-only lookalikes. Verify the first slash block is parsed separately and never inferred from later context.

- [x] **Step 2: Write failing credential-isolation and publisher tests**

Construct the exact `carl-buzz-mcp` descriptor and assert only `BUZZ_RELAY_URL`, `BUZZ_PRIVATE_KEY`, optional `BUZZ_AUTH_TAG`, and optional `BUZZ_ACP_DISPLAY_NAME` are accepted. A general shell command, unknown credential-bearing server, arguments, duplicate env keys, or extra secret key must be rejected before provider launch.

Drive a fake `buzz 0.1.0` executable and assert literal argv plus stdin:

```text
messages send --channel 123e4567-e89b-12d3-a456-426614174000 --content - --reply-to aaaa... --broadcast
```

Verify the fake child receives the four allowlisted Buzz variables and no Carl, Codex, OpenAI, shell, or parent environment variables. Secret values must be absent from `Debug`, errors, journal events, and captured diagnostics.

- [x] **Step 3: Run focused tests and verify RED**

Run: `cargo test --locked --test buzz_adapter_contract --test buzz_mcp_contract -- --nocapture`

Expected: FAIL because the Buzz adapter and MCP alias do not exist.

- [x] **Step 4: Implement the restricted publisher and MCP server**

Expose only crate-private bounded-process construction needed to run a trusted executable with exact argv, stdin, closed env, 60-second timeout, 256 KiB aggregate output, and process-tree cleanup. The MCP alias supports only JSON-RPC `initialize`, `tools/list`, and `tools/call` for `send_message` and `send_diff`; schemas use `additionalProperties: false`. The `send_message` content enters the Buzz CLI over stdin, never shell interpolation or argv.

- [x] **Step 5: Verify and commit**

Run Task 4 contracts, secret-filter contracts, sidecar contracts, and global Rust checks.

Commit: `git commit -m "feat: add the restricted Buzz publisher"`

---

### Task 5: Implement the Codex app-server execution port

**Files:**
- Create: `src/delegates/codex/app_server.rs`
- Create: `src/delegates/codex/app_events.rs`
- Modify: `src/delegates/codex/mod.rs`
- Create: `tests/codex_app_server_contract.rs`

**Interfaces:**
- Consumes: duplex `JsonlSidecar`, `ProviderHome`, `TrustedExecutable`, `SessionConfiguration`, and Codex app-server `0.146.0` JSON schema.
- Produces: `CodexAppServer`, `CodexModel`, `CodexThreadId`, `CodexTurnId`, `StartThread`, `StartTurn`, `CodexEvent`, `CodexApprovalRequest`, and methods `connect`, `models`, `start_thread`, `start_turn`, `steer`, `interrupt`, `next_event`, and `resolve_approval`.

- [x] **Step 1: Write the handshake/model/thread tests**

Drive a fake app-server and assert exact method order and bounded responses:

```rust
let mut server = CodexAppServer::connect(executable, home, limits).await?;
assert_eq!(server.models().await?[0].id(), "gpt-5.6-codex");
let thread = server.start_thread(StartThread {
    cwd: workspace,
    model: Some(ModelId::parse("gpt-5.6-codex")?),
    mode: PermissionMode::Default,
}).await?;
assert_eq!(thread.as_str(), "thr_123");
```

Assert `initialize` then `initialized`, paginated `model/list`, provider-owned supported effort options, persistent non-ephemeral `thread/start`, strict cwd echo validation, malformed catalog rejection, unknown required fields rejection, and sanitized authentication failure.

- [x] **Step 2: Write event, approval, steering, and cancellation tests**

Normalize `thread/started`, `turn/started`, `item/started`, `item/agentMessage/delta`, `item/completed`, `turn/diff/updated`, `turn/completed`, and `error`. Convert command and file approval server requests into `CodexApprovalRequest` with the exact provider request ID, thread/turn/item IDs, normalized command/reason/scope, and SHA-256 digest. Verify `turn/steer` carries `expectedTurnId`; `turn/interrupt` carries the exact active turn; stale IDs fail closed.

- [x] **Step 3: Run focused tests and verify RED**

Run: `cargo test --locked --test codex_app_server_contract -- --nocapture`

Expected: FAIL because `CodexAppServer` does not exist.

- [x] **Step 4: Implement the version-pinned app-server adapter**

Launch with `app-server --strict-config --listen stdio://` and explicit provider-owned file credential configuration. Map modes exactly:

| Carl mode | Codex approval policy | Codex sandbox | Carl response behavior |
|---|---|---|---|
| `plan` | `never` | `read-only` | deny any unexpected mutation request |
| `default` | `on-request` | `workspace-write` | surface command and file requests |
| `acceptEdits` | `on-request` | `workspace-write` | auto-accept file changes; surface commands |
| `dontAsk` | `never` | `workspace-write` | decline any unexpected request |
| `bypassPermissions` | `never` | `danger-full-access` | no Carl approval prompts |

Do not configure external MCP servers, apps, plugins, hooks, or parent Codex configuration. Preserve model and effort only when the model catalog reports them.

- [x] **Step 5: Verify and commit**

Run Task 5 contracts, Codex auth/exec contracts, sidecar contracts, and global Rust checks.

Commit: `git commit -m "feat: add the Codex app-server runtime"`

---

### Task 6: Implement the Carl kernel actor and exact remote approvals

**Files:**
- Create: `src/acp/kernel.rs`
- Create: `src/acp/session.rs`
- Modify: `src/acp/mod.rs`
- Modify: `src/events.rs`
- Modify: `src/storage/repository.rs`
- Create: `tests/acp_kernel_contract.rs`

**Interfaces:**
- Consumes: `RuntimeStore`, `CodexAppServer`, `BuzzPublisher`, `SessionConfiguration`, and stored remote codes.
- Produces: `KernelHandle`, `KernelCommand::{NewSession, Prompt, SetConfig, Cancel, Steer, Shutdown}`, `KernelUpdate`, and `PromptStopReason`.

- [x] **Step 1: Write the deterministic turn lifecycle contract**

Use a scripted Codex port and fake publisher:

```rust
let session = kernel.new_session(new_session_request()).await?;
let outcome = kernel.prompt(session.id(), prompt("inspect this repo")).await?;
assert_eq!(outcome.stop_reason, PromptStopReason::EndTurn);
assert_eq!(updates, vec![
    KernelUpdate::AgentMessageChunk("Working".into()),
    KernelUpdate::ToolStarted { title: "cargo test".into(), kind: ToolKind::Execute },
    KernelUpdate::ToolCompleted { title: "cargo test".into(), status: ToolStatus::Completed },
    KernelUpdate::AgentMessageChunk("Fixed and verified.".into()),
]);
assert_eq!(publisher.messages()[0].reply_to, event_id());
```

Assert input is persisted before provider start, every normalized event is persisted before emission, final delivery is persisted before `end_turn`, and provider failures, publisher failures, ambiguous delivery, cancellation, and crash reconciliation have distinct durable outcomes.

- [x] **Step 2: Write exact approval and bypass tests**

For `default`, make Codex request a command. Assert Carl persists `ToolProposed`, a bound approval, and one remote code; posts a bounded summary; returns the ACP turn at `waiting_for_approval`; and performs no side effect. Before persistence or publication, high-confidence secret material in a provider request must be rejected by `SecretFilter` rather than copied into the approval summary. Then send `/approve <code>` as the first prompt block and assert Carl atomically resolves/consumes the exact record, revalidates the provider request digest, responds `accept`, and continues the same Codex turn.

Repeat for deny, expiry, replay, wrong actor, wrong session, changed cwd, changed provider request, and a fake approval string in quoted context. Test bypass selection from ACP config and `/permissions bypassPermissions` both create a confirmation code while leaving the current mode unchanged; only `/confirm-bypass <code>` activates it.

- [x] **Step 3: Write mode, steer, and cancel tests**

Test every row of the Task 5 mode table. While a turn is active, send `Steer` and assert a same-turn provider `turn/steer`; send `Cancel` and assert `turn/interrupt`, descendant cleanup, `stopReason: cancelled`, and no final Buzz success reply. Reject concurrent prompts and steering while approval is pending.

- [x] **Step 4: Run focused tests and verify RED**

Run: `cargo test --locked --test acp_kernel_contract -- --nocapture`

Expected: FAIL because the kernel actor does not exist.

- [x] **Step 5: Implement the single-owner kernel actor**

The actor owns `RuntimeStore`, `CodexAppServer`, and an in-memory map of session state. During an active provider turn it uses `tokio::select!` over Codex events and the kernel command channel so cancel and steer remain responsive. At an approval boundary it retains the provider turn and request ID but completes the current ACP prompt; a later exact command resumes it. Generate each display code from ten lowercase hexadecimal characters of a fresh UUID v4, retrying on the database uniqueness constraint, and store only `SHA-256("carl.remote-code.v1\0" || code)`. Run final assistant text through the same bounded secret filter before journal persistence or Buzz publication; a rejected result becomes a typed failed turn rather than a partial delivery.

- [x] **Step 6: Verify and commit**

Run Task 6, storage, bound-approval, and global Rust checks.

Commit: `git commit -m "feat: add the ACP kernel actor"`

---

### Task 7: Serve ACP v1/v2 over stdio

**Files:**
- Create: `src/acp/server.rs`
- Modify: `src/acp/mod.rs`
- Create: `tests/acp_server_contract.rs`

**Interfaces:**
- Consumes: bounded ACP wire functions and `KernelHandle`.
- Produces: `AcpServer::serve<R, W>`, honest initialization metadata, request dispatch, and one serialized outbound writer.

- [x] **Step 1: Write initialize and session contracts**

Drive the server through duplex pipes and assert exact responses:

```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":2,"agentCapabilities":{"loadSession":false,"promptCapabilities":{"image":false,"audio":false,"embeddedContext":false,"mcpCapabilities":{"http":false,"sse":false}},"sessionCapabilities":{}},"agentInfo":{"name":"carl","title":"Carl","version":"0.1.0"},"_meta":{"steering":{"supported":true}}}}
```

Test protocol 1 and 2 negotiation, initialize exactly once, requests before initialize, `session/new` with canonical cwd and MCP descriptors, config options in the new-session result, `session/set_config_option`, and unknown methods returning `-32601` without stopping other sessions.

- [x] **Step 2: Write prompt/update/cancel/steer contracts**

Assert `session/prompt` accepts only bounded text blocks and produces `session/update` notifications with exact `sessionUpdate` discriminators: `agent_message_chunk`, `tool_call`, `tool_call_update`, `available_commands_update`, and `session_info_update`. Verify `session/cancel` is an id-less notification, `_session/steering` returns `{"outcome":"injected"}`, and response IDs can complete out of order without interleaved JSON bytes.

- [x] **Step 3: Write hostile framing and lifecycle contracts**

Feed malformed, oversized, empty, unknown-session, duplicate-prompt, stdout-injection, and shutdown-race inputs. Assert bounded errors, no panic text on stdout, kernel shutdown, Codex/Buzz child reaping, and a clean EOF exit.

- [x] **Step 4: Run focused tests and verify RED**

Run: `cargo test --locked --test acp_server_contract -- --nocapture`

Expected: FAIL because `AcpServer` does not exist.

- [x] **Step 5: Implement the concurrent dispatcher and single writer**

The read loop validates frames and sends typed kernel commands. Long prompt requests complete on spawned response tasks; the main loop continues accepting cancel/steer frames. Every response/update enters one bounded `mpsc` writer queue. If the writer closes or fills, cancel the kernel and exit nonzero rather than dropping protocol state.

- [x] **Step 6: Verify and commit**

Run Task 7, kernel, protocol, and global Rust checks.

Commit: `git commit -m "feat: serve Carl over ACP"`

---

### Task 8: Wire the CLI, argv-zero alias, and secure process setup

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Modify: `tests/cli_contract.rs`
- Create: `tests/acp_cli_contract.rs`

**Interfaces:**
- Consumes: `AcpServerConfig`, `DataRootLock`, provider/publisher executable resolution, and `buzz_mcp::run_stdio`.
- Produces: the public `carl acp` command and `carl-buzz-mcp` argv-zero behavior.

- [x] **Step 1: Write failing Clap and setup contracts**

Assert the exact command parses:

```text
carl acp --model gpt-5.6-codex --effort high --permission-mode default
carl acp --dangerously-bypass-permissions
```

Reject simultaneous dangerous alias plus a conflicting mode, relative `CARL_DATA_DIR`, unsafe data-root permissions, relative explicit executable overrides, a second owner process, `OPENAI_API_KEY` as an authentication substitute, and attempts to pass Buzz secrets as flags.

- [x] **Step 2: Write argv-zero and stdio contracts**

Create a symlink named `carl-buzz-mcp` to the test-built `carl` binary. Assert it starts MCP mode without parsing `carl` subcommands, exposes only the two Buzz tools, and never writes non-JSON diagnostics to stdout. A normal `carl acp` invocation must not inherit or forward Buzz variables to Codex.

- [x] **Step 3: Run focused tests and verify RED**

Run: `cargo test --locked --test cli_contract --test acp_cli_contract -- --nocapture`

Expected: FAIL because `acp` is absent from Clap and `main` has no streaming mode.

- [x] **Step 4: Implement streaming command dispatch**

Parse argv zero before `Cli::parse`. For `carl acp`, create the Tokio runtime, canonicalize and lock `CARL_DATA_DIR`, resolve exact trusted Codex/Buzz executables, open `RuntimeStore`, construct the kernel/server, and stream stdio until EOF or signal. Keep existing buffered auth commands unchanged. Map normal exit, failure, and cancellation to 0, 1, and 130.

- [x] **Step 5: Verify and commit**

Run Task 8, auth CLI contracts, and global Rust checks.

Commit: `git commit -m "feat: expose the Carl ACP command"`

---

### Task 9: Pin Buzz fixtures and prove the deterministic end-to-end path

**Files:**
- Create: `tests/fixtures/buzz/44456e2/initialize.json`
- Create: `tests/fixtures/buzz/44456e2/session_new.json`
- Create: `tests/fixtures/buzz/44456e2/prompt.json`
- Create: `tests/fixtures/buzz/44456e2/slash_prompt.json`
- Create: `tests/fixtures/buzz/44456e2/cancel.json`
- Create: `tests/fixtures/buzz/44456e2/steer.json`
- Create: `tests/buzz_acp_contract.rs`
- Create: `tests/buzz_end_to_end.rs`
- Modify: `Cargo.toml`

**Interfaces:**
- Consumes: the real `carl` subprocess, a fake Codex app-server executable, a fake Buzz CLI executable, and pinned Buzz request fixtures.
- Produces: offline conformance evidence for the entire `buzz-acp -> carl acp -> Codex -> Carl policy -> Buzz publisher` path.

- [x] **Step 1: Add literal pinned Buzz fixtures and provenance**

Copy only the minimal JSON shapes from `block/buzz@44456e200e3ca6a5d2882b58b447b80474041347` into fixtures. Include a `source` field in the test harness metadata, not in protocol messages, and assert fixture hashes so accidental edits are review-visible.

- [x] **Step 2: Write the process-boundary conformance test**

Spawn the real `carl acp`, send initialize/new/config/prompt/cancel/steer frames, and parse stdout with an independent bounded reader. Assert stderr may contain diagnostics but stdout contains only valid JSON-RPC objects. Exercise multiple sessions, model/effort rejection, unknown methods, partial writes, and process EOF cleanup.

- [x] **Step 3: Write the end-to-end coding scenario**

The fake Codex transcript must inspect a fixture repository, request an exact file approval, request an exact command approval, emit a diff, receive a steer, complete verification, and return a final message. The test approves one request, denies another, repeats in bypass, cancels a fourth turn, restarts Carl, and proves:

```rust
assert_eq!(fake_buzz.messages_for(channel).len(), expected_messages);
assert!(fake_buzz.last_message(channel).contains("verification"));
assert_eq!(workspace_file(), "fixed\n");
assert!(!all_captured_bytes().contains(private_key.as_bytes()));
assert_eq!(consequential_action_count("approved-command"), 1);
```

- [x] **Step 4: Run focused tests and verify RED, then GREEN**

Run before implementation wiring: `cargo test --locked --test buzz_acp_contract --test buzz_end_to_end -- --nocapture`

Expected first run: FAIL at the first unimplemented process seam. Implement only the fixture/test wiring needed to exercise Tasks 1–8, then rerun until both pass.

- [x] **Step 5: Verify and commit**

Run Task 9 tests and global Rust checks.

Commit: `git commit -m "test: prove the Buzz ACP path"`

---

### Task 10: Document setup and run local live verification

**Files:**
- Create: `docs/buzz.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/architecture.md`
- Modify: `docs/configuration.md`
- Modify: `docs/security.md`
- Modify: `tests/docs_contract.rs`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the completed CLI and test commands.
- Produces: public installation/configuration guidance, CI enforcement, and opt-in live smoke scripts documented as exact commands.

- [x] **Step 1: Write failing documentation contracts**

Require the README and `docs/buzz.md` to contain these exact operational settings and warnings:

```sh
export BUZZ_ACP_AGENT_COMMAND=carl
export BUZZ_ACP_AGENT_ARGS=acp
export BUZZ_ACP_MCP_COMMAND=carl-buzz-mcp
export BUZZ_ACP_AGENTS=1
export BUZZ_ACP_RESPOND_TO=owner-only
export BUZZ_ACP_PERMISSION_MODE=default
```

Assert docs explain local OAuth via `carl auth login openai`, no API-key fallback, local versus remote bypass, exact approval commands, single-process V1, tested Buzz commit/range, credential isolation, cancellation/steering, and `CARL_BUZZ_EXECUTABLE`.

- [x] **Step 2: Run docs contracts and verify RED**

Run: `cargo test --locked --test docs_contract -- --nocapture`

Expected: FAIL because Buzz documentation is absent and the README still says Carl is not usable.

- [x] **Step 3: Update public docs and CI**

Add the ACP/Buzz integration tests to the existing Linux/macOS/Windows test job without secrets or network. Keep live tests excluded. Update the pre-alpha status truthfully: ACP/Buzz is usable on the tested path; TUI, Telegram, Grok execution, native tools, and broader product milestones remain incomplete unless separately implemented.

- [x] **Step 4: Run the live Codex subscription smoke test**

With `OPENAI_API_KEY`, `CODEX_API_KEY`, and other API-key variables unset, create a disposable fixture repository and drive the real installed `codex-cli 0.146.0` through the real `carl acp`. In `plan` mode ask for a repository assessment; in `default` mode request a one-line edit and test, consume the emitted exact approvals, and verify the diff and final evidence. Run steer and cancel in separate turns. Save only sanitized pass/fail metadata under the test temp directory; do not commit provider output or credentials.

- [x] **Step 5: Run the optional local Buzz relay smoke when prerequisites are present**

Build `buzz`, `buzz-acp`, and the local relay from pinned commit `44456e2`; generate disposable local-only identities, register Carl, run with the six documented env settings, and send an owner mention that edits and tests the fixture repository. Verify the reply appears in the originating thread and the relay/provider secrets do not appear in Carl logs or SQLite. If Docker/relay prerequisites are absent, record the exact missing executable/service and retain the deterministic Task 9 proof without claiming the live-relay criterion.

- [x] **Step 6: Run final verification and commit**

Run:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --locked --release
git diff --check
```

Then re-read every definition-of-done item in the approved design and map it to a test or live transcript. Commit documentation and CI only after all non-optional checks pass.

Commit: `git commit -m "docs: ship Carl Buzz compatibility"`
