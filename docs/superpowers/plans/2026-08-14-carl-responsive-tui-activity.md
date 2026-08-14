# Carl Responsive TUI Activity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Carl's terminal UI visibly alive and responsive with an authoritative pulse-plus-phase row, asynchronous service polling, adaptive polling, and batched redraws.

**Architecture:** `TuiState` owns deterministic presentation timing and derives an `ActivityView` from durable task state. The terminal task owns input and rendering, while a new controller worker owns `TuiController` and serializes service I/O over bounded channels. Crossterm's existing event stream, an 80 ms activity clock, and a 33 ms render gate drive a `tokio::select!` loop that never awaits service requests.

**Tech Stack:** Rust 1.97, Tokio, Crossterm 0.28 event stream, Ratatui 0.29, existing Carl service protocol and deterministic contract tests.

## Global Constraints

- The activity row is exactly one terminal row immediately above the existing input block.
- The eight pulse frames are `⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧` and advance every 80 ms only for animated phases.
- Show phase elapsed time after 3 seconds and `last update Ns ago` after 10 seconds without an authoritative update.
- Never claim provider progress, percentage completion, or an estimated finish time.
- Keep at most one live-update request in flight.
- Active polling is no more frequent than 50 ms; idle polling is no more frequent than 250 ms.
- Rendering is capped at one draw every 33 ms and occurs only while dirty.
- Authoritative events are never discarded; bounded worker output applies backpressure.
- Existing permission, session, approval, reconnection, cursor, and terminal-restoration semantics remain unchanged.

---

### Task 1: Deterministic activity presentation state

**Files:**
- Create: `src/tui/activity.rs`
- Modify: `src/tui/mod.rs`
- Modify: `src/tui/state.rs`
- Modify: `src/tui/controller.rs`
- Create: `tests/tui_activity_contract.rs`
- Modify: `tests/tui_controller_contract.rs`

**Interfaces:**
- Produces: `ActivityPhase`, `ActivityTone`, and `ActivityView` in `carl::tui::activity`.
- Produces: `TuiState::activity() -> ActivityView`, `TuiState::activity_is_animated() -> bool`, and timestamped `TuiEvent::Tick { elapsed: Duration }`.
- Produces: `TuiEvent::CompactionRequested`, emitted by the existing `/compact` controller branch and cleared by the next authoritative checkpoint or compaction update.
- Consumes: existing `TaskStatus`, `ToolActivity`, approval, connection, and compaction state.

- [ ] **Step 1: Write the failing phase and clock tests**

Add literal behavior tests covering ready, starting, thinking, tool mapping, approval, compaction, disconnection, terminal states, pulse progression, elapsed threshold, stale threshold, and clock regression. The core test shape is:

```rust
#[test]
fn active_activity_pulses_and_reports_authoritative_staleness() {
    let mut state = bound_state();
    state.apply(TuiEvent::TaskUpdate(TaskUpdate::Status(TaskStatus::Active))).unwrap();
    state.apply(TuiEvent::Tick { elapsed: Duration::from_millis(80) }).unwrap();
    assert_eq!(state.activity().symbol, "⠙");
    assert_eq!(state.activity().label, "Thinking…");
    state.apply(TuiEvent::Tick { elapsed: Duration::from_secs(11) }).unwrap();
    assert_eq!(state.activity().stale_seconds, Some(11));
}
```

Before writing the body, name the mutation each test catches: wrong phase priority, animation advancing while idle, a tick incorrectly refreshing authoritative progress, wrong tool verb, or a regressing clock being accepted.

- [ ] **Step 2: Run the new target and observe RED**

Run: `CARGO_INCREMENTAL=0 cargo test --locked --test tui_activity_contract`

Expected: compile failure because `carl::tui::activity`, timestamped ticks, and `TuiState::activity` do not exist.

- [ ] **Step 3: Implement the minimal activity model**

Create these public presentation types without terminal styling dependencies:

```rust
pub enum ActivityTone { Active, Idle, Waiting, Success, Error }

pub struct ActivityView {
    pub symbol: &'static str,
    pub label: String,
    pub elapsed_seconds: Option<u64>,
    pub stale_seconds: Option<u64>,
    pub tone: ActivityTone,
    pub animated: bool,
}
```

Keep timing fields private on `TuiState`: monotonic `now`, `phase_started_at`, `last_authoritative_at`, and `pulse_frame`. Reject a timestamp lower than `now` with `TuiStateError::ClockRegression`. Update `last_authoritative_at` for `TaskUpdate`, `DurableUpdate`, `AuthoritativeSnapshot`, and `Reconnected`, never for `Tick`. Reset `phase_started_at` whenever the derived phase changes.

Map tool prefixes exactly:

```rust
"read_file " => "Reading "
"list_files " => "Listing "
"search_files " => "Searching "
"apply_patch " => "Editing "
"run_command " => "Running "
```

Unknown summaries remain unchanged. Approval, paused, and blocked phases are static. Disconnection is animated only while disconnected. Change the `/compact` success result from the generic notice to `TuiEvent::CompactionRequested`; clear that local presentation flag on the next authoritative compaction or checkpoint update.

- [ ] **Step 4: Run activity and existing state contracts GREEN**

Run:

```sh
CARGO_INCREMENTAL=0 cargo test --locked --test tui_activity_contract
CARGO_INCREMENTAL=0 cargo test --locked --test tui_state_contract
CARGO_INCREMENTAL=0 cargo test --locked --test tui_controller_contract
```

Expected: all tests pass with no warnings.

- [ ] **Step 5: Commit the activity state slice**

```sh
git add src/tui/activity.rs src/tui/mod.rs src/tui/state.rs src/tui/controller.rs tests/tui_activity_contract.rs tests/tui_state_contract.rs tests/tui_controller_contract.rs
git commit -m "feat: model authoritative TUI activity"
```

---

### Task 2: Pulse-plus-phase activity row

**Files:**
- Modify: `src/tui/render.rs`
- Modify: `tests/tui_render_contract.rs`

**Interfaces:**
- Consumes: `TuiState::activity() -> ActivityView` from Task 1.
- Produces: a width-bounded one-row renderer in the existing row above the input block.

- [ ] **Step 1: Write failing rendering tests**

Add TestBackend cases with hand-authored screen expectations for:

```rust
assert!(screen.contains("⠙ Thinking…"));
assert!(screen.contains("⠹ Running cargo test · 12s · last update 11s ago"));
assert!(screen.contains("? Waiting for approval"));
assert!(screen.contains("↻ Reconnecting…"));
assert!(screen.contains("✓ Completed"));
```

Use a 24-column backend to prove the symbol and phase survive truncation and no text appears inside the prompt border. This catches a renderer that uses the old quiet status row, overflows width, or animates a waiting state.

- [ ] **Step 2: Run the render target and observe RED**

Run: `CARGO_INCREMENTAL=0 cargo test --locked --test tui_render_contract`

Expected: assertions fail because the current renderer prints only `active`, `ready`, or `disconnected`.

- [ ] **Step 3: Implement the activity row**

Reuse the existing one-line connection area rather than increasing terminal height. Build spans in this order: symbol, label, optional phase elapsed, optional stale age. Map tones to cyan/yellow/green/red/dark-gray. Truncate the detail to the `Rect` width using Unicode scalar boundaries; never slice a UTF-8 string at an arbitrary byte. Keep the input area at three rows.

- [ ] **Step 4: Run render and narrow-terminal contracts GREEN**

Run:

```sh
CARGO_INCREMENTAL=0 cargo test --locked --test tui_render_contract
CARGO_INCREMENTAL=0 cargo test --locked --test tui_state_contract
```

Expected: all tests pass.

- [ ] **Step 5: Commit the renderer slice**

```sh
git add src/tui/render.rs tests/tui_render_contract.rs
git commit -m "feat: render live TUI activity pulse"
```

---

### Task 3: Serialized asynchronous controller worker

**Files:**
- Create: `src/tui/runtime.rs`
- Modify: `src/tui/mod.rs`
- Create: `tests/tui_runtime_contract.rs`

**Interfaces:**
- Produces: `RuntimeIntent::{Submit, ResolveApproval, Cancel, Shutdown}`.
- Produces: `RuntimeOutput::{Events(Vec<TuiEvent>), Disconnected}`.
- Produces: `run_controller_worker(controller, intent_rx, output_tx)` generic over `TuiBackend`.
- Consumes: `TuiController<B>`, `SubmittedInput`, `ServiceApprovalDecision`, bounded Tokio channels.

- [ ] **Step 1: Write failing worker scheduling tests**

Use a complete fake `TuiBackend` whose `LiveUpdates` branch parks on a `Notify` and whose other branches return complete protocol-shaped results. Test these observable behaviors:

1. only one delayed `LiveUpdates` request is in flight;
2. after it completes, a queued user intent is handled before another poll;
3. active polling never starts twice inside 50 ms under paused Tokio time;
4. idle polling never starts twice inside 250 ms;
5. every authoritative event batch reaches the bounded output channel in order.

The test must assert worker outputs and durable event order, not the existence of the fake itself.

- [ ] **Step 2: Run the runtime target and observe RED**

Run: `CARGO_INCREMENTAL=0 cargo test --locked --test tui_runtime_contract`

Expected: compile failure because `carl::tui::runtime` and its worker interfaces do not exist.

- [ ] **Step 3: Implement the minimal worker**

Create bounded channel capacities of 32 intents and 256 output batches. The worker owns the controller. Its loop is biased toward `intent_rx.recv()` before the poll deadline. It awaits one controller call at a time, sends all returned `TuiEvent` values as one ordered batch, and updates its fast/idle poll mode by inspecting `TaskBound`, `SessionCleared`, and terminal `TaskUpdate::Status` events. A service error sends `Disconnected` and schedules a 250 ms reconnect poll; it never fabricates completion.

On shutdown, stop scheduling polls, drop the controller, and close the output sender. Channel-full behavior must await output capacity so authoritative events are not lost.

- [ ] **Step 4: Run worker and controller contracts GREEN**

Run:

```sh
CARGO_INCREMENTAL=0 cargo test --locked --test tui_runtime_contract
CARGO_INCREMENTAL=0 cargo test --locked --test tui_controller_contract
```

Expected: all tests pass.

- [ ] **Step 5: Commit the worker slice**

```sh
git add src/tui/runtime.rs src/tui/mod.rs tests/tui_runtime_contract.rs
git commit -m "refactor: isolate TUI service polling"
```

---

### Task 4: Non-blocking terminal loop and render batching

**Files:**
- Modify: `src/tui/mod.rs`
- Modify: `tests/tui_end_to_end.rs`
- Modify: `tests/tui_terminal_contract.rs`
- Modify: `README.md`

**Interfaces:**
- Consumes: Task 3 worker channels, `crossterm::event::EventStream`, `TuiEvent::Tick { elapsed }`, and `TuiState::activity_is_animated()`.
- Produces: a `tokio::select!` UI loop with independent input, animation, worker output, render gate, resize, and shutdown handling.

- [ ] **Step 1: Write failing responsiveness and draw-budget tests**

Add an injected terminal-event/render seam used by the process-independent contract test. Under paused Tokio time, park the worker backend's live poll and then inject three character keys plus a tick. Assert the input becomes the literal string within 80 ms and the pulse advances before the poll is released. Feed ten assistant deltas in one 33 ms frame and assert one draw contains their concatenated literal text. Advance one idle second and assert no more than four poll starts and no unnecessary draws.

Add a terminal restoration case that closes the worker output channel while the input source remains open and asserts the UI exits through the typed service-unavailable path with `TerminalOwner` restored once. Add an editor contract proving a submission rejected by a full intent queue restores the exact UTF-8 input and cursor position.

- [ ] **Step 2: Run the end-to-end and terminal targets and observe RED**

Run:

```sh
CARGO_INCREMENTAL=0 cargo test --locked --test tui_end_to_end
CARGO_INCREMENTAL=0 cargo test --locked --test tui_terminal_contract
```

Expected: failing responsiveness/draw assertions because the current loop awaits `poll_updates` and unconditionally draws each iteration.

- [ ] **Step 3: Implement the asynchronous UI loop**

Replace sequential polling in `run_inner` with:

```rust
tokio::select! {
    terminal_event = terminal_events.next() => { /* edit or enqueue intent */ }
    _ = animation.tick() => { /* timestamped Tick; dirty only if visible */ }
    output = output_rx.recv() => { /* apply ordered events; mark dirty */ }
    _ = render_gate.tick(), if dirty => { /* one Ratatui draw; clear dirty */ }
}
```

Set `MissedTickBehavior::Skip` for animation and render intervals. Initialize the render gate at 33 ms and the activity interval at 80 ms. Use `Instant::now().duration_since(runtime_start)` for monotonic tick values. Do not await controller operations in the UI branch: enqueue them with `try_send`; on a full intent queue call a new `InputEditor::restore_submission(String)` method so the exact UTF-8 text and end cursor return to the input bar, then display `controller busy; input not submitted`.

On exit, send `Shutdown`, wait up to 500 ms for the worker, then abort it if necessary. Drop the Ratatui terminal and restore `TerminalOwner` on every path. Update the README TUI section with one sentence describing the activity row and honest stale-update timer.

- [ ] **Step 4: Run all TUI targets GREEN**

Run:

```sh
CARGO_INCREMENTAL=0 cargo test --locked --test tui_activity_contract
CARGO_INCREMENTAL=0 cargo test --locked --test tui_render_contract
CARGO_INCREMENTAL=0 cargo test --locked --test tui_runtime_contract
CARGO_INCREMENTAL=0 cargo test --locked --test tui_state_contract
CARGO_INCREMENTAL=0 cargo test --locked --test tui_controller_contract
CARGO_INCREMENTAL=0 cargo test --locked --test tui_terminal_contract
CARGO_INCREMENTAL=0 cargo test --locked --test tui_end_to_end
```

Expected: all focused tests pass with no warnings.

- [ ] **Step 5: Run strict gates**

Run:

```sh
cargo fmt --all -- --check
CARGO_INCREMENTAL=0 cargo clippy --locked --all-targets --all-features -- -D warnings
git diff --check
```

Expected: all commands exit 0.

- [ ] **Step 6: Commit the integrated responsive loop**

```sh
git add src/tui/mod.rs tests/tui_end_to_end.rs tests/tui_terminal_contract.rs README.md
git commit -m "feat: make TUI streaming responsive"
```

---

### Task 5: Real terminal validation and final evidence

**Files:**
- Modify only if a test-first bug fix is required by the real run.

**Interfaces:**
- Consumes: the completed TUI binary and existing OpenAI subscription configuration.
- Produces: a validated real terminal run showing the pulse, phase changes, streamed assistant text, a native tool call, and a terminal outcome.

- [ ] **Step 1: Build the final binary**

Run: `CARGO_INCREMENTAL=0 cargo build --locked --release`

Expected: release build succeeds.

- [ ] **Step 2: Run one real coding task**

Start Carl in a disposable Rust fixture with the existing owner subscription. Submit a task that requires `read_file`, `apply_patch`, and `run_command`. Observe that input remains responsive, the pulse advances, tool phases change, stale age is honest, and the task completes.

- [ ] **Step 3: Fix any observed defect test-first**

For each defect, add the smallest failing focused contract that reproduces it, observe RED, implement the minimal fix, and rerun the affected TUI target. Do not patch a real-run defect without a regression test.

- [ ] **Step 4: Re-run final focused and strict gates**

Run the seven TUI targets from Task 4, then formatting, strict all-target/all-feature Clippy, and `git diff --check` exactly once after the final source change.

- [ ] **Step 5: Commit any validation fix and hand off for branch completion**

```sh
git add src/tui README.md tests/tui_activity_contract.rs tests/tui_render_contract.rs tests/tui_runtime_contract.rs tests/tui_state_contract.rs tests/tui_controller_contract.rs tests/tui_terminal_contract.rs tests/tui_end_to_end.rs
git commit -m "fix: preserve responsive TUI activity"
```

Then use `superpowers:finishing-a-development-branch` to present and execute the requested GitHub completion option.
