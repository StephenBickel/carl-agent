# Carl Subscription-Backed TUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `carl` open a minimal, durable, subscription-backed coding TUI that can start, steer, configure, compact, cancel, list, and resume Carl task sessions.

**Architecture:** The TUI is a thin Ratatui/Crossterm frontend over the existing task service. Pure command parsing and state reduction are separated from terminal ownership and service I/O; every task mutation travels through the versioned service protocol, and every displayed task outcome comes from snapshots or durable live updates.

**Tech Stack:** Rust 1.97, Tokio, Clap, Serde, Ratatui 0.29, Crossterm 0.28, SQLite via Rusqlite, the existing Carl service protocol and Codex subscription adapter.

## Global Constraints

- `carl` with no arguments opens the TUI; `carl tui` is an explicit alias; every existing explicit subcommand retains its contract.
- The TUI never calls providers, storage, filesystem tools, or coding tools directly.
- The local TUI defaults to `PermissionMode::FullAccess`; ACP, Buzz, Telegram, service API, and other frontend defaults do not change.
- The TUI may lose presentation events under load only when they are replaceable; it must not lose approval, tool outcome, compaction, completion, or terminal state.
- Terminal modes are restored exactly once after normal exit, typed error, panic, Ctrl+C, or dropped event/render tasks.
- The local service survives TUI exit and remains the owner of running tasks.
- No provider key, token, authorization metadata, raw credential claim, or secret-bearing environment value may enter TUI state, service frames, logs, snapshots, or fixtures.
- Default tests use scripted/local transports only and perform no live provider network calls.
- Add a failing test and observe the intended failure before each production behavior.
- Run focused tests after each task. Run the locked broad test, strict Clippy, formatting, and diff checks once at the Slice 1 merge gate.

## File structure

- `src/tui/mod.rs` — public TUI entry point and shared error/result types.
- `src/tui/command.rs` — slash-command and submitted-input parsing only.
- `src/tui/state.rs` — pure presentation state and reducer over typed UI events.
- `src/tui/controller.rs` — session/task orchestration through a narrow service backend.
- `src/tui/render.rs` — pure Ratatui widget construction and layout.
- `src/tui/terminal.rs` — Crossterm ownership, event polling, restoration, and panic-hook guard.
- `src/tui/bootstrap.rs` — connect-or-launch service readiness and child detachment.
- `src/service/protocol.rs` — protocol v6 session-list command/result/capability.
- `src/service/server.rs` — read-only durable TUI session-list execution.
- `src/storage/repository.rs` — bounded frontend-session listing.
- `src/cli.rs` and `src/main.rs` — optional subcommand parsing, `tui` alias, and interactive dispatch.
- `tests/tui_command_contract.rs` — slash/input parser tests.
- `tests/tui_state_contract.rs` — reducer, queue, and presentation-state tests.
- `tests/tui_render_contract.rs` — fixed-size render snapshots.
- `tests/tui_terminal_contract.rs` — pseudo-terminal and restoration tests.
- `tests/tui_controller_contract.rs` — fake-service orchestration tests.
- `tests/tui_end_to_end.rs` — real local task-service/TUI binary integration with scripted provider.

---

### Task 1: Add explicit and default TUI CLI dispatch

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/lib.rs`
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Create: `src/tui/mod.rs`
- Modify: `tests/cli_contract.rs`

**Interfaces:**
- Consumes: existing `Cli`, `Command`, `ExitClassification`, and Tokio runtime construction.
- Produces: `TuiArgs`, `Command::Tui(TuiArgs)`, `Cli::selected_command() -> Command`, and `tui::run(args: TuiArgs) -> ExitClassification`.

- [ ] **Step 1: Write the failing CLI contract**

Add tests that parse both an empty argument vector and `tui`, while retaining representative existing commands:

```rust
#[test]
fn no_subcommand_and_tui_alias_select_the_interactive_tui() {
    let implicit = Cli::try_parse_from(["carl"]).expect("default TUI parses");
    let explicit = Cli::try_parse_from(["carl", "tui"]).expect("TUI alias parses");
    assert!(matches!(implicit.selected_command(), Command::Tui(_)));
    assert!(matches!(explicit.selected_command(), Command::Tui(_)));
}

#[test]
fn existing_explicit_commands_do_not_fall_through_to_tui() {
    for args in [["carl", "serve"], ["carl", "doctor"], ["carl", "sessions"]] {
        let parsed = Cli::try_parse_from(args).expect("existing command parses");
        assert!(!matches!(parsed.selected_command(), Command::Tui(_)));
    }
}
```

- [ ] **Step 2: Run the focused test and observe RED**

Run: `cargo test --locked --test cli_contract no_subcommand_and_tui_alias_select_the_interactive_tui`

Expected: compilation fails because `TuiArgs`, `Command::Tui`, and `selected_command` do not exist and the subcommand is required.

- [ ] **Step 3: Add terminal dependencies and minimal dispatch**

Add exact dependencies:

```toml
crossterm = { version = "0.28", features = ["event-stream"] }
ratatui = { version = "0.29", default-features = false, features = ["crossterm"] }
```

Define:

```rust
#[derive(Clone, Debug, Default, Eq, PartialEq, Args)]
pub struct TuiArgs {}

#[derive(Debug, Parser)]
#[command(name = "carl")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

impl Cli {
    #[must_use]
    pub fn selected_command(self) -> Command {
        self.command.unwrap_or_else(|| Command::Tui(TuiArgs::default()))
    }
}
```

Add `Command::Tui(TuiArgs)` and route it specially from `main`, like ACP, to `carl::tui::run`. The temporary `run` returns a typed failure message without entering raw mode so this task changes parsing only.

- [ ] **Step 4: Run the complete CLI contracts**

Run: `cargo test --locked --test cli_contract && cargo test --locked --test acp_cli_contract`

Expected: both targets pass; `carl --help` includes `tui`; all existing ACP parsing remains unchanged.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/cli.rs src/main.rs src/tui/mod.rs tests/cli_contract.rs
git commit -m "feat: add Carl TUI command surface"
```

---

### Task 2: Add durable frontend-session listing to service protocol v6

**Files:**
- Modify: `src/storage/repository.rs`
- Modify: `src/service/protocol.rs`
- Modify: `src/service/client.rs`
- Modify: `src/service/server.rs`
- Modify: `src/runtime/task/engine.rs`
- Modify: `src/acp/server.rs`
- Modify: `tests/acp_storage_contract.rs`
- Modify: `tests/service_protocol_contract.rs`
- Modify: `tests/service_end_to_end.rs`
- Modify: `tests/acp_server_contract.rs`

**Interfaces:**
- Consumes: `FrontendSessionRecord`, `ServiceSessionInfo`, `Store::list_tasks_for_session`, and strict service negotiation.
- Produces: `Store::list_frontend_sessions(frontend: Frontend, limit: u16)`, required `StartTaskCommand::frontend`, `ServiceCommand::Sessions { frontend, limit }`, `ServiceSessionSummary`, `ServiceResult::SessionList(Vec<ServiceSessionSummary>)`, and `ServiceCapabilities::durable_frontend_sessions`.

- [ ] **Step 1: Write failing storage and protocol tests**

Add three TUI sessions and one ACP session, then require bounded TUI-only ordering:

```rust
let sessions = store.list_frontend_sessions(Frontend::Tui, 2)?;
assert_eq!(sessions.len(), 2);
assert!(sessions.iter().all(|record| record.frontend == Frontend::Tui));
assert!(sessions[0].updated_at >= sessions[1].updated_at);
```

Add strict v6 round-trip and negotiation assertions:

```rust
let command = ServiceCommand::Sessions { frontend: Frontend::Tui, limit: 64 };
assert_eq!(serde_json::from_value(serde_json::to_value(&command)?)?, command);
assert_eq!(SERVICE_PROTOCOL_VERSION, 6);
assert!(info.capabilities.durable_frontend_sessions);
```

Require every `StartTaskCommand` to contain a non-optional `frontend`, literal v5 and v7 requests to fail with `UnsupportedVersion`, and a client to reject a v6 `Info` result whose new capability is false. Add engine/service assertions proving an untrusted `Frontend::Tui` start creates a TUI binding while an ACP start still creates an ACP binding.

- [ ] **Step 2: Run focused tests and observe RED**

Run: `cargo test --locked --test acp_storage_contract list_frontend_sessions && cargo test --locked --test service_protocol_contract sessions`

Expected: compilation fails because the repository API, protocol command/result, and capability are absent.

- [ ] **Step 3: Implement the bounded repository query**

Add:

```rust
pub fn list_frontend_sessions(
    &self,
    frontend: Frontend,
    limit: u16,
) -> Result<Vec<FrontendSessionRecord>, CarlError>
```

Validate `1..=64`, query only `frontend = ?`, order by `updated_at DESC, external_session_id ASC`, parse every field with the same validators as `get_frontend_session`, and return no secret or provider-auth metadata.

- [ ] **Step 4: Implement strict protocol v6**

Bump `SERVICE_PROTOCOL_VERSION` from 5 to 6. Add required capability `durable_frontend_sessions: bool`, required `frontend: Frontend` to `StartTaskCommand`, `Sessions { frontend, limit }`, and `SessionList(Vec<ServiceSessionSummary>)`. Update `validate_info`, `empty_info`, server `build_info`, read-command classification, command validation, and all exact negotiation identifiers to v6.

Define the strict summary:

```rust
pub struct ServiceSessionSummary {
    pub external_session_id: String,
    pub session_id: SessionId,
    pub workspace: PathBuf,
    pub permission_mode: PermissionMode,
    pub provider: String,
    pub latest_task_id: Option<TaskId>,
    pub latest_task_status: Option<TaskStatus>,
    pub model: Option<ModelId>,
    pub effort: Option<ReasoningEffort>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

For Slice 1, the exact provider identifier is `openai_subscription`. Model and effort come from `Store::get_task_configuration` for the latest task, never from TUI inference.

Propagate `StartTaskCommand.frontend` into `OwnerStartTask.frontend`; when no trusted admission is present, `enqueue_owner_task` must use that value instead of hard-coding `Frontend::Acp`. Protocol validation admits only `Frontend::Acp` and `Frontend::Tui` for untrusted starts. Update every ACP caller with `Frontend::Acp` and every existing service test fixture explicitly; do not use a serde default.

- [ ] **Step 5: Implement server session projection**

For each listed frontend session, call `list_tasks_for_session(binding.session_id, 64)`, select its latest record, read its active configuration when present, and construct `ServiceSessionSummary` using only authoritative storage records. Reject invalid limits in protocol validation before storage access.

- [ ] **Step 6: Prove read-only reconnect behavior**

Add a real service test that creates TUI and ACP sessions, reconnects a fresh client, requests TUI sessions, and asserts exact external identifiers and task ordering. Compare task-event and service-receipt counts before and after the request to prove listing is read-only.

- [ ] **Step 7: Run affected contracts and commit**

Run:

```bash
cargo test --locked --test acp_storage_contract
cargo test --locked --test service_protocol_contract
cargo test --locked --test service_end_to_end
```

Then commit:

```bash
git add src/storage/repository.rs src/service/protocol.rs src/service/client.rs src/service/server.rs src/runtime/task/engine.rs src/acp/server.rs tests/acp_storage_contract.rs tests/service_protocol_contract.rs tests/service_end_to_end.rs tests/acp_server_contract.rs
git commit -m "feat: list durable TUI sessions"
```

---

### Task 3: Implement slash parsing and the pure TUI reducer

**Files:**
- Create: `src/tui/command.rs`
- Create: `src/tui/state.rs`
- Modify: `src/tui/mod.rs`
- Create: `tests/tui_command_contract.rs`
- Create: `tests/tui_state_contract.rs`

**Interfaces:**
- Consumes: `ModelId`, `ReasoningEffort`, `PermissionMode`, `ServiceSessionSummary`, `TaskSnapshot`, `TaskStatus`, `TaskUpdate`, and `TaskId`.
- Produces: `SubmittedInput`, `SlashCommand`, `TuiEvent`, `TuiState`, `TranscriptItem`, `Overlay`, and `TuiState::apply(TuiEvent)`.

- [ ] **Step 1: Write exhaustive parser tables**

Use a table that includes every accepted form and representative invalid inputs:

```rust
assert_eq!(parse_submission("fix it")?, SubmittedInput::Prompt("fix it".into()));
assert_eq!(parse_submission("/compact")?, SubmittedInput::Command(SlashCommand::Compact));
assert_eq!(parse_submission("/effort xhigh")?, SubmittedInput::Command(SlashCommand::Effort(ReasoningEffort::XHigh)));
assert_eq!(parse_submission("/permissions full-access")?, SubmittedInput::Command(SlashCommand::Permissions(PermissionMode::FullAccess)));
assert!(parse_submission("/model\nunsafe").is_err());
assert!(parse_submission("/resume").is_err());
assert!(parse_submission("/unknown").is_err());
```

Require nonempty prompts up to `MAX_TASK_TEXT_BYTES`, no NUL, and an exact leading slash with no leading whitespace. Multiline non-command prompts remain valid.

- [ ] **Step 2: Run parser target and observe RED**

Run: `cargo test --locked --test tui_command_contract`

Expected: compilation fails because the `tui::command` module and types do not exist.

- [ ] **Step 3: Implement closed command types**

Define:

```rust
pub enum SlashCommand {
    Model(Option<String>),
    Provider(Option<String>),
    Effort(ReasoningEffort),
    Permissions(PermissionMode),
    Compact,
    New,
    Sessions,
    Resume(String),
    Status,
    Cancel,
    Login,
    Logout,
    Help,
    Exit,
}

pub enum SubmittedInput {
    Prompt(String),
    Command(SlashCommand),
}
```

Parse without shell expansion, quoting, globbing, or environment interpolation. Reject extra arguments for closed commands.

- [ ] **Step 4: Write reducer RED tests**

Cover assistant streaming coalescence, tool activity, diff, context usage, compaction, approval, terminal state, session overlay, notices, task replacement, reconnect freeze, and authoritative refresh:

```rust
state.apply(TuiEvent::TaskUpdate(TaskUpdate::AssistantDelta("hel".into())));
state.apply(TuiEvent::TaskUpdate(TaskUpdate::AssistantDelta("lo".into())));
assert_eq!(state.last_assistant_text(), Some("hello"));

state.apply(TuiEvent::Disconnected);
assert!(!state.mutations_enabled());
state.apply(TuiEvent::Reconnected { live_generation, cursor, snapshot });
assert!(state.mutations_enabled());
```

Add a bounded-inbox test proving context/status/tick updates coalesce while approval, tool completion, compaction, and completion remain present and ordered.

- [ ] **Step 5: Implement the pure reducer**

`TuiState` owns only presentation data: input buffer, transcript, tool rows, selected overlay, status bar fields, last cursor/generation, connection state, transient notice, and exit flag. It does not own a client, store, provider, or process handle.

`apply` must reject cursor regression, clear an in-progress assistant accumulator only on a new semantic boundary, and replace state from an authoritative snapshot after overflow.

- [ ] **Step 6: Run reducer tests and commit**

Run: `cargo test --locked --test tui_command_contract && cargo test --locked --test tui_state_contract`

Commit:

```bash
git add src/tui/mod.rs src/tui/command.rs src/tui/state.rs tests/tui_command_contract.rs tests/tui_state_contract.rs
git commit -m "feat: add TUI command and state core"
```

---

### Task 4: Implement the service-only TUI controller

**Files:**
- Create: `src/tui/controller.rs`
- Modify: `src/tui/mod.rs`
- Create: `tests/tui_controller_contract.rs`

**Interfaces:**
- Consumes: `SubmittedInput`, `SlashCommand`, `TuiEvent`, service protocol v6, `TaskBudget::default()`, and `TaskServiceClient`.
- Produces: `TuiBackend`, `ServiceTuiBackend`, `TuiController`, `TuiController::initialize`, `TuiController::submit`, and `TuiController::poll_updates`.

- [ ] **Step 1: Write a fake-backend controller contract**

Define a fake that records exact `ServiceCommand` values. Prove:

- the first prompt creates an external ID beginning `tui-`, sends `Frontend::Tui`, uses canonical current workspace, service default model/effort, `PermissionMode::FullAccess`, and `TaskBudget::default()`;
- normal input during an active task becomes `Steer`;
- `/compact`, `/cancel`, `/status`, `/model`, `/effort`, and `/permissions` map to exact commands;
- `/new` clears the binding without deleting history;
- `/sessions` requests `Frontend::Tui` only;
- `/resume 2` binds the second displayed session and loads its latest task;
- `/provider`, `/login`, and `/logout` return honest Slice 1 notices pointing to subscription auth rather than claiming native provider support;
- `/exit` creates no service command.

Example assertion:

```rust
controller.submit(SubmittedInput::Prompt("fix it".into())).await?;
let ServiceCommand::StartTask(start) = fake.last_command() else { panic!("expected start") };
assert_eq!(start.permission_mode, PermissionMode::FullAccess);
assert_eq!(start.request, "fix it");
```

- [ ] **Step 2: Run the controller target and observe RED**

Run: `cargo test --locked --test tui_controller_contract`

Expected: compilation fails because the controller and backend interfaces do not exist.

- [ ] **Step 3: Define the narrow backend**

Use a boxed-future trait to keep tests dependency-free:

```rust
pub trait TuiBackend {
    fn info(&self) -> &ServiceInfo;
    fn request<'a>(
        &'a mut self,
        command: ServiceCommand,
    ) -> Pin<Box<dyn Future<Output = Result<ServiceResult, TuiError>> + Send + 'a>>;
}
```

`ServiceTuiBackend` owns one `TaskServiceClient`, generates unique request/idempotency identifiers, and verifies the expected result variant for each controller operation.

- [ ] **Step 4: Implement lifecycle and live-update polling**

`initialize` lists TUI sessions and selects the newest without mutating it. `submit` refuses mutations while disconnected. For an attached task, `poll_updates` uses `LiveUpdates { task_id, live_generation, after_cursor, limit: 128 }`, applies any authoritative overflow snapshot first, then emits ordered `TuiEvent::TaskUpdate` values and the new cursor.

When a task is nonterminal after attach, send `Resume` exactly once per controller generation. A repeated reconnect may replay the same idempotency key and must not duplicate provider work.

- [ ] **Step 5: Test reconnect, replay, and approval mapping**

Add fake sequences for unavailable/reconnect, generation change, cursor gap, terminal completion, and `ApprovalRequired`. Approval responses must call `ResolveApproval` with the exact task/session/turn/display code from the update and must not accept modified binding data from the UI.

For local TUI approval, send `frontend: Frontend::Tui`, `actor_id: ActorId::parse("local-owner")`, `channel_id: None`, and `event_id: None`; the server must validate that the TUI binding, workspace, task session, and active task all match before forwarding the decision. Add a negative test for each mismatched binding field and assert zero engine approval controls.

- [ ] **Step 6: Run and commit**

Run: `cargo test --locked --test tui_controller_contract`

Commit:

```bash
git add src/tui/mod.rs src/tui/controller.rs tests/tui_controller_contract.rs
git commit -m "feat: orchestrate TUI sessions through service"
```

---

### Task 5: Build the minimal renderer and terminal owner

**Files:**
- Create: `src/tui/render.rs`
- Create: `src/tui/terminal.rs`
- Modify: `src/tui/mod.rs`
- Create: `tests/tui_render_contract.rs`
- Create: `tests/tui_terminal_contract.rs`

**Interfaces:**
- Consumes: `TuiState`, Crossterm events, Ratatui `Buffer`/`Frame`, and `TuiController` events.
- Produces: `render(frame: &mut Frame, state: &TuiState)`, `TerminalOwner`, `TerminalEvent`, `InputEditor`, and `run_with_terminal`.

- [ ] **Step 1: Write fixed-size render snapshots**

Render deterministic states into `TestBackend` at 80x24 and 120x36. Assert exact normalized lines for:

- empty prompt;
- active assistant stream and three tool rows;
- approval prompt;
- `/sessions` overlay;
- disconnected banner;
- narrow terminal fallback.

Require the first line to contain `CARL`, model, effort, `full access`, shortened session ID, and context percent. Assert the buffer contains no test secret injected into a redacted tool result.

- [ ] **Step 2: Observe render RED**

Run: `cargo test --locked --test tui_render_contract`

Expected: compilation fails because `tui::render` does not exist.

- [ ] **Step 3: Implement the renderer**

Use a vertical layout with one-line status, transcript, optional notice/approval line, and bordered input. Tool rows use stable symbols: `●` running, `✓` succeeded, `×` failed, `?` uncertain. Do not add a file tree, side pane, mouse requirement, Markdown parser, or syntax highlighter in Slice 1.

- [ ] **Step 4: Write input and restoration RED tests**

Test `InputEditor` without a terminal for insertion, cursor movement, deletion, Enter submit, Shift+Enter newline, Ctrl+C active cancellation, Ctrl+C idle clear, Ctrl+D exit, and Unicode boundaries.

Use a pseudo-terminal/helper process contract to assert the exact enter/leave sequences and visible cursor restoration after:

- `/exit`;
- controller error;
- panic caught by the binary boundary;
- Ctrl+C while idle;
- dropped terminal owner.

- [ ] **Step 5: Implement RAII terminal ownership**

`TerminalOwner::enter` enables raw mode and alternate screen only after all fallible controller/bootstrap work succeeds. Its idempotent `restore` disables mouse capture if enabled, leaves alternate screen, shows the cursor, and disables raw mode. `Drop` calls `restore`. Install a scoped panic hook that restores before delegating to the prior hook, then restore the prior hook on exit.

The event loop selects among Crossterm input, a 100ms redraw tick, controller live updates, and cancellation. It drains durable controller events before drawing. It caps redraw rate and never awaits service I/O while holding terminal output locks.

- [ ] **Step 6: Run focused TUI tests and commit**

Run:

```bash
cargo test --locked --test tui_render_contract
cargo test --locked --test tui_terminal_contract
cargo test --locked --test tui_state_contract
```

Commit:

```bash
git add src/tui/mod.rs src/tui/render.rs src/tui/terminal.rs tests/tui_render_contract.rs tests/tui_terminal_contract.rs tests/tui_state_contract.rs
git commit -m "feat: render and own the Carl terminal UI"
```

---

### Task 6: Connect or safely launch the subscription service

**Files:**
- Create: `src/tui/bootstrap.rs`
- Modify: `src/tui/mod.rs`
- Modify: `src/main.rs`
- Create: `tests/tui_bootstrap_contract.rs`

**Interfaces:**
- Consumes: `TaskServiceClient::connect`, `CARL_DATA_DIR`, current canonical workspace, the current Carl executable, and existing `serve` command.
- Produces: `ServiceBootstrap`, `ServiceConnection`, `connect_or_launch`, and bounded readiness behavior.

- [ ] **Step 1: Write bootstrap RED tests with an injected launcher**

Cover:

- existing service connects without launch;
- unavailable endpoint launches once and connects after bounded readiness probes;
- two concurrent launchers result in one service owner and two connected clients;
- invalid endpoint identity never triggers replacement or deletion;
- launch failure and readiness timeout are typed and leave terminal raw mode untouched;
- dropping the TUI-side child handle does not terminate the service;
- launch environment omits `OPENAI_API_KEY`, `CODEX_API_KEY`, `AZURE_OPENAI_API_KEY`, `OPENROUTER_API_KEY`, and unrelated secret-shaped variables.

- [ ] **Step 2: Observe bootstrap RED**

Run: `cargo test --locked --test tui_bootstrap_contract`

Expected: compilation fails because the bootstrap interfaces do not exist.

- [ ] **Step 3: Implement connect-or-launch**

Canonicalize and validate `CARL_DATA_DIR`, current workspace, and `current_exe`. First call `TaskServiceClient::connect`. Launch only on `ServiceClientErrorCode::Unavailable`; return `InvalidEndpoint` unchanged.

Spawn the canonical current executable with `serve`, null stdin/stdout/stderr, no kill-on-drop, and a closed environment rebuilt from the minimum platform variables plus exact `CARL_DATA_DIR` and an optional canonical `CARL_CODEX_EXECUTABLE`. Never forward API-key variables. Probe every 50ms for at most 5 seconds using delayed missed-tick behavior and cancellation.

On timeout, return a typed bootstrap error but do not kill a service process that may have won the data-root race. On a child that exits before readiness, await/reap it and return `LaunchFailed`.

- [ ] **Step 4: Wire the real TUI entry point**

`tui::run` performs configuration, bootstrap, controller initialization, and then terminal entry. It maps normal `/exit` to success, user cancellation to exit 130, and sanitized bootstrap/controller/terminal failures to exit 1 after restoration.

- [ ] **Step 5: Run bootstrap/CLI tests and commit**

Run:

```bash
cargo test --locked --test tui_bootstrap_contract
cargo test --locked --test cli_contract
cargo test --locked --test auth_cli_contract
```

Commit:

```bash
git add src/tui/mod.rs src/tui/bootstrap.rs src/main.rs tests/tui_bootstrap_contract.rs tests/cli_contract.rs
git commit -m "feat: bootstrap the local service for TUI"
```

---

### Task 7: Prove and document the real subscription-backed TUI workflow

**Files:**
- Create: `tests/tui_end_to_end.rs`
- Modify: `tests/docs_contract.rs`
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-08-13-carl-native-tui-provider-runtime-design.md`

**Interfaces:**
- Consumes: the real Carl binary, task service, scripted Codex app-server fixture, pseudo-terminal driver, durable SQLite store, and every Slice 1 TUI command.
- Produces: one end-to-end acceptance target and accurate user documentation.

- [ ] **Step 1: Write the end-to-end scenario and a documentation RED contract**

Drive the actual `carl` binary in a pseudo-terminal against a disposable data root and scripted provider. The scenario must:

1. start with no service and observe automatic service readiness;
2. submit a coding prompt;
3. observe assistant, tool-start, tool-complete, context, and compaction rows;
4. issue `/status`, `/effort high`, `/model <supported>`, and `/permissions full-access`;
5. close the TUI while the service remains alive;
6. reopen `carl`, use `/sessions`, resume the prior external session, and observe no duplicate tool effect;
7. steer the active task, request `/compact`, then `/cancel` or observe completion;
8. `/new`, start a second task, and prove both sessions are listed in durable order;
9. `/exit` and assert terminal restoration and service survival.

Assert the database's task/event/control projections match reducer replay and that no fixture secret appears in terminal capture or persisted JSON.

Add a docs contract that requires the README to contain `carl`, `carl tui`, `CARL_DATA_DIR`, `full access`, `/sessions`, `/compact`, and `OpenAI subscription`, and rejects the old claim that the TUI is unimplemented.

- [ ] **Step 2: Observe the documentation RED**

Run: `cargo test --locked --test docs_contract readme_documents_subscription_tui`

Expected: FAIL because the README still describes the TUI as incomplete and omits the exact launch/session instructions.

- [ ] **Step 3: Replace the obsolete README section**

Add this quick-start shape and expand it with the exact supported slash commands:

```text
CARL_DATA_DIR=/absolute/private/carl-data carl
```

Explain that Slice 1 uses the signed-in Codex subscription provider, the service persists after TUI exit, `carl tui` is an alias, and native OpenAI/OpenRouter onboarding belongs to the next slices. Replace any README claim that the TUI is unimplemented.

- [ ] **Step 4: Run the end-to-end and documentation targets**

Run:

```bash
cargo test --locked --test tui_end_to_end
cargo test --locked --test docs_contract readme_documents_subscription_tui
```

Expected: both targets pass; the real binary scenario completes without duplicate effects, leaked secrets, terminal damage, or stopped background service.

- [ ] **Step 5: Run the Slice 1 merge gate**

Run exactly once after all focused tests are green:

```bash
cargo test --locked --test tui_command_contract
cargo test --locked --test tui_state_contract
cargo test --locked --test tui_controller_contract
cargo test --locked --test tui_render_contract
cargo test --locked --test tui_terminal_contract
cargo test --locked --test tui_bootstrap_contract
cargo test --locked --test tui_end_to_end
cargo test --locked --test service_protocol_contract
cargo test --locked --test service_end_to_end
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Expected: every command exits 0; no Cargo or Carl test/service process remains.

- [ ] **Step 6: Commit Slice 1 documentation and evidence**

```bash
git add README.md tests/docs_contract.rs tests/tui_end_to_end.rs docs/superpowers/specs/2026-08-13-carl-native-tui-provider-runtime-design.md
git commit -m "docs: ship subscription-backed Carl TUI"
```

## Slice 1 completion boundary

After Task 7, Carl must be genuinely usable through the existing OpenAI subscription path. Native OpenAI/OpenRouter HTTP adapters, native coding tools, model-catalog filtering, OS-vault API-key onboarding, `/provider` switching, and direct-provider `/login` are intentionally delivered by the next two plans. Slice 1 must label those commands honestly and must not simulate their success.
