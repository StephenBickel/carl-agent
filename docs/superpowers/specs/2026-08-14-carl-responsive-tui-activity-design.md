# Carl Responsive TUI Activity Design

Date: 2026-08-14
Status: Conversational design approved; written specification awaiting review

## Problem

Carl's TUI currently draws, reads terminal input, polls the task service, and sleeps in one sequential loop. A slow service request can therefore delay typing feedback and redraws. The terminal also exposes task status only as quiet text below the transcript, so a user cannot quickly distinguish active reasoning, tool execution, connection trouble, and a genuine stall. Repeated unconditional redraws and idle polling do work even when nothing visible changed.

## Goals

- Keep typing, cancellation, and the activity animation responsive while service polling is slow.
- Put a compact, animated activity row immediately above the input bar.
- Describe the current authoritative phase or running tool without inventing progress.
- Make elapsed work and time since the last authoritative update visible.
- Batch streamed text into smooth render frames and avoid redraws when the screen is unchanged.
- Preserve durable event ordering, exact session behavior, and fail-closed backpressure.

## Non-goals

- Changing provider protocols or token generation behavior.
- Adding a second transcript, progress percentage, or estimated completion time.
- Replacing the Ratatui frontend or changing slash-command semantics.
- Claiming that a pulse proves provider progress; it proves only that the local UI loop is alive.

## User Experience

The TUI reserves one line directly above the bordered input area. While a task is active, an eight-frame Braille pulse advances every 80 milliseconds:

```text
⠴ Running cargo test · 12s
────────────────────────────────────────────────────────
❯ add another regression test
```

The activity label is derived from state in this priority order:

1. Disconnected: `Reconnecting…`
2. Approval pending: `Waiting for approval`
3. Running tool: the latest unresolved tool summary, normalized as `Reading …`, `Searching …`, `Editing …`, or `Running …`
4. Checkpointing or explicit compaction: `Compacting context`
5. Cancelling: `Cancelling…`
6. Queued: `Queued…`
7. A bound task whose first status has not arrived: `Starting…`
8. Active without a running tool: `Thinking…`
9. Completing: `Finishing…`

After three seconds, the row adds total phase elapsed time. After ten seconds without an authoritative task update, it adds `last update Ns ago`. This is deliberately phrased as local liveness rather than provider progress.

Non-active states use a static symbol and do not animate:

- `● Ready`
- `Ⅱ Paused`
- `! Blocked`
- `✓ Completed`
- `× Failed`
- `■ Cancelled`

The row is width-bounded and truncates the detail before overwriting elapsed or stale-update information. Narrow terminals retain the symbol and phase first.

## Architecture

### Activity state

`TuiState` gains a small presentation model containing the animation frame, phase start time, last authoritative update time, and current activity derivation. Time enters as a monotonic duration on explicit tick events so rendering remains deterministic and testable. Durable updates refresh the last-update clock; animation ticks do not.

The current activity is derived from existing `TaskStatus`, approval state, compaction state, connection state, and unresolved `ToolActivity`. A local explicit-compaction request remains visible only until its authoritative compaction or checkpoint update arrives. Tool summaries remain authoritative strings supplied by the service. Presentation code maps `read_file`, `list_files`, `search_files`, `apply_patch`, and `run_command` to `Reading`, `Listing`, `Searching`, `Editing`, and `Running`; unknown prefixes fall back to the original bounded summary.

`Waiting for approval`, `Paused`, and `Blocked` use static symbols because Carl is waiting rather than working. `Reconnecting…` animates only while the runtime is actively attempting reconnection.

### Runtime loop

The terminal/UI task owns `TuiState`, `InputEditor`, and Ratatui rendering. A controller worker owns `TuiController` and serializes service commands and live-update polling. They communicate through bounded channels:

- UI to worker: submitted prompts, slash commands, approval decisions, cancellation, and shutdown.
- Worker to UI: ordered `TuiEvent` batches or a typed connection failure.

The UI loop selects between an asynchronous terminal event source, an 80-millisecond animation interval, controller events, and shutdown. Production uses Crossterm's event stream; tests inject a deterministic event source. The UI task never awaits a service request. The controller worker allows only one live-update request at a time and services user commands before scheduling the next poll.

Authoritative events are never discarded. Channel saturation applies backpressure to the worker. Replaceable animation ticks stay local to the UI and may coalesce.

### Polling and rendering

Live updates use adaptive polling:

- Active non-terminal task: one request at a time, no more often than every 50 milliseconds.
- Idle or terminal session: no more often than every 250 milliseconds.
- A queued user command preempts the next scheduled poll.

The UI tracks a dirty flag. Input changes, controller events, resize events, and visible animation-frame changes mark it dirty. Rendering is capped at one frame per 33 milliseconds. Multiple assistant deltas received inside that window are reduced into the existing assistant transcript item and rendered together. If nothing visible changed, Ratatui is not asked to draw.

## Failure Handling

- A service failure immediately changes the row to `Reconnecting…`; mutations remain disabled under the existing state rule.
- Reconnection restores the authoritative snapshot and resets stale-update timing without fabricating tool completion.
- If the worker event channel closes unexpectedly, the UI shows a terminal service-unavailable notice and remains safely exit-able.
- Terminal restoration remains owned by `TerminalOwner`; worker shutdown is requested and bounded before leaving the alternate screen.
- Unknown tool summaries remain visible after control characters are rejected or sanitized at their existing boundary.

## Testing

Implementation follows test-driven development.

- State contracts prove pulse frames advance only on ticks and that authoritative updates reset stale timing.
- Render contracts prove active, tool, stale, disconnected, approval, narrow-terminal, and terminal-state rows.
- Runtime contracts use a deliberately delayed backend to prove animation and input continue while polling is pending.
- Runtime contracts prove user commands are serviced before another poll and that only one poll is in flight.
- Streaming contracts prove multiple assistant deltas produce one coalesced visible update within a render frame.
- Existing TUI controller, session, approval, reconnect, terminal restoration, and end-to-end contracts remain green.

## Success Criteria

- The activity pulse continues smoothly during a delayed service poll.
- Typed characters appear within one animation interval even when polling is pending.
- The activity row always reflects the best available authoritative phase and never claims percentage progress or provider activity it cannot prove.
- Active streaming does not exceed 20 service polls or 30 render calls per second; idle sessions do not exceed 4 service polls per second.
- All TUI-focused tests, formatting, strict Clippy, and the relevant process-level TUI test pass.
