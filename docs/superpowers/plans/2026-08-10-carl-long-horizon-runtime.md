# Carl Long-Horizon Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Carl-owned, provider-neutral task engine that autonomously completes verified coding work across repeated tool calls, context compactions, provider-thread replacement, frontend reconnection, and process restart.

**Architecture:** Keep the existing append-only SQLite journal and single-writer kernel, but add a durable task/epoch state machine, canonical checkpoints, a budgeted context engine, and a provider-neutral agent port. Codex `0.146.0` remains the first subscription-backed adapter; owner `full-access` runs Codex behind a read-only pre-dispatch approval barrier that Carl automatically resolves only after journaling the exact operation.

**Tech Stack:** Rust 2024 (`rust-version = 1.97.0`), Tokio, rusqlite/SQLite WAL, serde/serde_json, sha2, uuid, chrono, the pinned Codex CLI `0.146.0`, ACP JSON-RPC, Node.js 22+ for opt-in live subscription tests.

## Global Constraints

- Follow `docs/superpowers/specs/2026-08-10-carl-long-horizon-runtime-design.md`.
- Keep one Rust package and one distributable `carl` binary.
- Keep all normal tests offline and deterministic; live subscription tests remain explicit local opt-ins.
- Do not add LangChain, a graph framework, native dynamic plugins, or undocumented OAuth.
- The append-only Carl journal is authoritative; provider transcripts and threads are replaceable caches.
- Persist every consequential operation intent before authorizing its effect.
- Never split a tool request from its terminal result across a checkpoint or context cut.
- Never automatically repeat an ambiguous consequential operation after interruption.
- New trusted-owner tasks default to Carl `full-access`; existing stored sessions retain their current authority.
- `full-access` skips user prompts but does not bypass identity, credential, journal, replay, or operation-binding invariants.
- Reject unknown, group, guest, unpaired, malformed, and replayed remote inputs before provider invocation.
- Keep provider, Buzz, Telegram, and raw environment credentials out of prompts, general tool environments, events, checkpoints, artifacts, and diagnostics.
- Use actual Codex token observations when present and conservative estimation otherwise.
- Automatic compaction begins at 80 percent of the effective model context window and targets 50–60 percent afterward.
- The default soft epoch boundaries are fifteen minutes or forty completed tool calls; neither value is a task-success condition.
- Carl may declare a stall only after three materially distinct recovery strategies fail.
- A successful terminal task requires evidence for every required completion clause.
- Preserve compatibility with event schema versions 1–3 and migrations 1–7.
- Run `cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` after every Rust task.
- Do not edit `SECURITY.md` until the exact diff has been previewed and approved under the repository security-policy process.

---

## File Structure

New runtime files are deliberately smaller than the existing `acp/kernel.rs` and
`storage/repository.rs` modules:

- `src/runtime/task/mod.rs` — public task runtime exports.
- `src/runtime/task/types.rs` — IDs, contracts, task states, budgets, and evidence.
- `src/runtime/task/reducer.rs` — pure task-event reducer and transition validation.
- `src/runtime/task/checkpoint.rs` — canonical checkpoint construction and validation.
- `src/runtime/task/context.rs` — context ledger, token budget, pruning, and package assembly.
- `src/runtime/task/report.rs` — bounded epoch-report parsing and completion evidence mapping.
- `src/runtime/task/progress.rs` — progress fingerprints, stall scoring, and recovery selection.
- `src/runtime/task/engine.rs` — asynchronous epoch coordinator.
- `src/runtime/agent_port.rs` — provider-neutral coding-agent lifecycle interface.
- `src/service/mod.rs` — persistent single-owner task service exports.
- `src/service/protocol.rs` — versioned local client/service frames and bounds.
- `src/service/server.rs` — owner-private local endpoint and durable task ownership.
- `src/service/client.rs` — reconnecting local frontend client.
- `src/evals/mod.rs` — deterministic evaluation public API.
- `src/evals/scenario.rs` — interruption schedules and scripted long-horizon scenarios.
- `src/evals/metrics.rs` — normalized run metrics and release-gate evaluation.
- `migrations/0008_long_horizon_tasks.sql` — task, epoch, operation, checkpoint, package, and steering projections.
- `migrations/0009_trusted_frontend_owners.sql` — canonical permission profiles and trusted remote-owner bindings.
- `tests/task_domain_contract.rs` — type and reducer contracts.
- `tests/task_storage_contract.rs` — migration, transactional projection, and replay contracts.
- `tests/context_engine_contract.rs` — checkpoint, compaction, and exact-retention contracts.
- `tests/agent_port_contract.rs` — provider-neutral lifecycle and Codex adapter contracts.
- `tests/epoch_engine_contract.rs` — autonomous continuation, completion, steering, and stall recovery.
- `tests/long_horizon_eval.rs` — deterministic 100-epoch interruption matrix.
- `scripts/live-codex-long-horizon.mjs` — sanitized subscription-backed fixture and soak runner.

Existing large files retain transport and persistence integration only. New task
logic must not be embedded directly in `acp/kernel.rs` or `storage/repository.rs`.

---

### Task 1: Make owner full access pre-dispatch and no-prompt

**Files:**
- Modify: `src/acp/config.rs`
- Modify: `src/delegates/codex/app_server.rs`
- Modify: `src/acp/kernel.rs`
- Modify: `src/events.rs`
- Modify: `tests/codex_app_server_contract.rs`
- Modify: `tests/acp_kernel_contract.rs`
- Modify: `tests/buzz_end_to_end.rs`

**Interfaces:**
- Consumes: existing `PermissionMode`, `CodexApprovalRequest`, `Store::append`, and exact approval response handling.
- Produces: `PermissionProfile`, durable `ToolDispatchAuthorized`, and an automatic full-access approval path used by every later epoch.

- [ ] **Step 1: Write failing permission-profile tests**

Add these assertions to `tests/acp_kernel_contract.rs` and
`tests/codex_app_server_contract.rs`:

```rust
assert_eq!(PermissionMode::Plan.profile(), PermissionProfile::ReadOnly);
assert_eq!(PermissionMode::Default.profile(), PermissionProfile::Approval);
assert_eq!(
    PermissionMode::BypassPermissions.profile(),
    PermissionProfile::FullAccess,
);
```

The fake app-server request for `BypassPermissions` must contain exactly:

```rust
assert_eq!(request["params"]["approvalPolicy"], "on-request");
assert_eq!(request["params"]["sandbox"], "read-only");
```

Run:

```bash
cargo test --locked --test codex_app_server_contract --test acp_kernel_contract
```

Expected: FAIL because `PermissionProfile` does not exist and bypass currently uses
`never` plus `danger-full-access`.

- [ ] **Step 2: Add canonical product profiles**

Add to `src/acp/config.rs`:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionProfile {
    ReadOnly,
    Approval,
    FullAccess,
}

impl PermissionMode {
    #[must_use]
    pub const fn profile(self) -> PermissionProfile {
        match self {
            Self::Plan => PermissionProfile::ReadOnly,
            Self::Default | Self::AcceptEdits => PermissionProfile::Approval,
            Self::DontAsk => PermissionProfile::ReadOnly,
            Self::BypassPermissions => PermissionProfile::FullAccess,
        }
    }
}
```

Re-export `PermissionProfile` from `src/acp/mod.rs`.

- [ ] **Step 3: Put full access behind the Codex barrier**

Change both Codex mode translators so `BypassPermissions` uses
`approvalPolicy = "on-request"` and the read-only sandbox. Change
`CodexAppServer::next_event` so a bypass approval request is returned to the kernel
and registered in `outstanding_approvals`; do not auto-allow or deny it inside the
adapter.

The exact mapping becomes:

```rust
PermissionMode::Plan => ("never", read_only()),
PermissionMode::Default | PermissionMode::AcceptEdits => ("on-request", workspace_write()),
PermissionMode::DontAsk => ("never", workspace_write()),
PermissionMode::BypassPermissions => ("on-request", read_only()),
```

- [ ] **Step 4: Journal authorization before resolving it**

Add this event variant to schema version 4 in `src/events.rs`, while retaining the
existing V1–V3 deserializers:

```rust
ToolDispatchAuthorized {
    tool_call_id: ToolCallId,
    request_digest: String,
    automatic: bool,
}
```

In `Kernel::process_provider_event`, route `PermissionProfile::FullAccess` approval
requests to a new method:

```rust
async fn authorize_full_access_effect(
    &mut self,
    session_id: SessionId,
    turn_id: TurnId,
    approval: CodexApprovalRequest,
    updates: &mut Vec<KernelUpdate>,
) -> Result<(), KernelError>;
```

The method must append `ToolProposed` and `ToolDispatchAuthorized`, in that order,
before calling `resolve_approval(&approval, CodexApprovalDecision::Allow)`. It must not
create a remote code or return `WaitingForApproval`.

The approval item ID must already map to the active turn's `ToolCallId`; an unknown,
completed, or cross-turn item is denied and treated as a provider protocol failure.

- [ ] **Step 5: Prove storage failure prevents the effect**

Extend the fake `CodexPort` in `tests/acp_kernel_contract.rs` with a recorded approval
counter. Inject a store failure immediately before `ToolDispatchAuthorized` and assert:

```rust
assert_eq!(port.allowed_effects(), 0);
assert_eq!(outcome.unwrap_err().code(), KernelErrorCode::StorageFailed);
```

Then run the successful case and assert one authorization, no approval message, one
tool completion, and event ordering by sequence.

- [ ] **Step 6: Verify and commit**

Run the global Rust checks, then:

```bash
git add src/acp src/delegates/codex src/events.rs tests/acp_kernel_contract.rs tests/codex_app_server_contract.rs tests/buzz_end_to_end.rs
git commit -m "feat: mediate owner full access before effects"
```

---

### Task 2: Normalize complete Codex tool, usage, and compaction evidence

**Files:**
- Modify: `src/delegates/codex/app_events.rs`
- Modify: `src/delegates/codex/app_server.rs`
- Modify: `src/delegates/codex/mod.rs`
- Modify: `tests/codex_app_server_contract.rs`
- Create: `tests/fixtures/codex/0.146.0/long_horizon_contract.json`

**Interfaces:**
- Consumes: Codex `0.146.0` generated V2 schema.
- Produces: `CodexItem` and `CodexTokenUsage` used by the provider-neutral port and evidence recorder.

- [ ] **Step 1: Check in the bounded protocol contract fixture**

Create a small fixture containing only the methods and required fields Carl uses:

```json
{
  "schema_version": 1,
  "codex_version": "0.146.0",
  "methods": {
    "thread/resume": ["threadId"],
    "thread/compact/start": ["threadId"]
  },
  "notifications": {
    "thread/tokenUsage/updated": ["threadId", "turnId", "tokenUsage"],
    "item/started": ["threadId", "turnId", "item", "startedAtMs"],
    "item/completed": ["threadId", "turnId", "item", "completedAtMs"]
  },
  "item_types": ["commandExecution", "fileChange", "contextCompaction"]
}
```

The test must compare this fixture with the parser's declared contract and reject a
different Codex version.

- [ ] **Step 2: Write failing normalized-event tests**

Test these public records:

```rust
pub struct CodexTokenUsage {
    pub last_total_tokens: u64,
    pub total_tokens: u64,
    pub model_context_window: Option<u64>,
}

pub enum CodexItem {
    Command {
        item_id: String,
        command: String,
        cwd: String,
        status: String,
        exit_code: Option<i32>,
        aggregated_output: Option<String>,
        process_id: Option<String>,
    },
    FileChange {
        item_id: String,
        status: String,
        changes: serde_json::Value,
    },
    ContextCompaction { item_id: String },
    Other { item_id: String, item_type: String },
}
```

Assert signed or overflowing token counts, oversized output, malformed command items,
and unknown required fields fail closed.

- [ ] **Step 3: Parse complete item payloads**

Replace the ID-only `ItemStarted` and `ItemCompleted` events with:

```rust
ItemStarted {
    thread_id: CodexThreadId,
    turn_id: CodexTurnId,
    item: CodexItem,
},
ItemCompleted {
    thread_id: CodexThreadId,
    turn_id: CodexTurnId,
    item: CodexItem,
},
TokenUsageUpdated {
    thread_id: CodexThreadId,
    turn_id: CodexTurnId,
    usage: CodexTokenUsage,
},
```

Bound command text and aggregate output independently. Keep unknown item types as
bounded compatibility evidence; never treat them as successful tools.

- [ ] **Step 4: Preserve exact command and verification evidence**

Update the fake app-server's completed command item to include `command`, `cwd`,
`status`, `exitCode`, `durationMs`, `aggregatedOutput`, `processId`, and
`commandActions`. Assert the normalized event retains command, status, exit code, and
bounded output without retaining ignored fields.

- [ ] **Step 5: Verify and commit**

Run the global Rust checks, then:

```bash
git add src/delegates/codex tests/codex_app_server_contract.rs tests/fixtures/codex
git commit -m "feat: normalize Codex long-horizon evidence"
```

---

### Task 3: Introduce the provider-neutral agent lifecycle port

**Files:**
- Create: `src/runtime/agent_port.rs`
- Modify: `src/runtime/mod.rs`
- Modify: `src/acp/kernel.rs`
- Modify: `src/delegates/codex/app_server.rs`
- Modify: `tests/acp_kernel_contract.rs`
- Create: `tests/agent_port_contract.rs`

**Interfaces:**
- Consumes: normalized Codex events from Task 2.
- Produces: `AgentPort`, `AgentEvent`, `AgentContextId`, and lifecycle request types used by the task engine.

- [ ] **Step 1: Write a failing fake-port contract**

Exercise this exact public seam in `tests/agent_port_contract.rs`:

```rust
pub type AgentFuture<'a, T> = Pin<
    Box<dyn Future<Output = Result<T, AgentPortError>> + Send + 'a>,
>;

pub enum AgentPortErrorCode {
    Unsupported,
    InvalidRequest,
    InvalidResponse,
    UnavailableContext,
    Transport,
    Cancelled,
}

pub struct AgentPortError {
    code: AgentPortErrorCode,
}

pub struct AgentCapabilities {
    pub resume: bool,
    pub compact: bool,
    pub token_usage: bool,
    pub pre_dispatch_effects: bool,
    pub history_paging: bool,
    pub background_processes: bool,
}

pub struct AgentModel {
    pub id: ModelId,
    pub display_name: String,
    pub supported_efforts: Vec<ReasoningEffort>,
    pub default_effort: ReasoningEffort,
}

pub trait AgentPort: Send {
    fn capabilities(&self) -> AgentCapabilities;
    fn models(&mut self) -> AgentFuture<'_, Vec<AgentModel>>;
    fn start_context(&mut self, request: StartAgentContext) -> AgentFuture<'_, AgentContextId>;
    fn resume_context(&mut self, request: ResumeAgentContext) -> AgentFuture<'_, AgentContextId>;
    fn compact_context(&mut self, context_id: &AgentContextId) -> AgentFuture<'_, ()>;
    fn start_epoch(&mut self, request: StartAgentEpoch) -> AgentFuture<'_, AgentEpochId>;
    fn steer(&mut self, context_id: &AgentContextId, epoch_id: &AgentEpochId, text: String) -> AgentFuture<'_, ()>;
    fn interrupt(&mut self, context_id: &AgentContextId, epoch_id: &AgentEpochId) -> AgentFuture<'_, ()>;
    fn next_event(&mut self) -> AgentFuture<'_, AgentEvent>;
    fn resolve_effect(&mut self, request_id: &AgentRequestId, decision: EffectDecision) -> AgentFuture<'_, ()>;
    fn list_background_processes(&mut self, context_id: &AgentContextId) -> AgentFuture<'_, Vec<AgentProcess>>;
    fn terminate_background_process(&mut self, context_id: &AgentContextId, process_id: &str) -> AgentFuture<'_, bool>;
    fn shutdown(&mut self) -> AgentFuture<'_, ()>;
}
```

`AgentModel` contains a validated `ModelId`, display name, supported efforts, and
default effort. `StartAgentContext`, `ResumeAgentContext`, and `StartAgentEpoch`
contain only canonical workspace/model/effort/permission/context text fields. IDs and
process IDs are bounded opaque strings with redacted `Debug` implementations.

Use these request shapes:

```rust
pub struct StartAgentContext {
    pub cwd: PathBuf,
    pub model: ModelId,
    pub permission_mode: PermissionMode,
}

pub struct ResumeAgentContext {
    pub context_id: AgentContextId,
    pub cwd: PathBuf,
    pub model: ModelId,
    pub permission_mode: PermissionMode,
}

pub struct StartAgentEpoch {
    pub context_id: AgentContextId,
    pub input: String,
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub permission_mode: PermissionMode,
}

pub struct AgentProcess {
    pub process_id: String,
    pub item_id: String,
    pub command: String,
    pub cwd: PathBuf,
    pub os_pid: Option<u32>,
}
```

- [ ] **Step 2: Define normalized lifecycle types**

`AgentEvent` must include context start, epoch start, item start/completion, assistant
delta, diff, usage, effect request, compaction start/completion, epoch completion, and
provider failure. `AgentEffectRequest` contains the request ID, item ID, kind, bounded
summary, normalized request digest, and no provider-opaque JSON.

```rust
pub enum AgentEvent {
    ContextStarted { context_id: AgentContextId },
    EpochStarted { context_id: AgentContextId, epoch_id: AgentEpochId },
    ItemStarted { epoch_id: AgentEpochId, item: AgentItem },
    AssistantDelta { epoch_id: AgentEpochId, text: String },
    DiffUpdated { epoch_id: AgentEpochId, diff: String },
    UsageUpdated { epoch_id: AgentEpochId, usage: AgentUsage },
    EffectRequested(AgentEffectRequest),
    ItemCompleted { epoch_id: AgentEpochId, item: AgentItem },
    CompactionStarted { context_id: AgentContextId, item_id: String },
    CompactionCompleted { context_id: AgentContextId, item_id: String },
    EpochCompleted { epoch_id: AgentEpochId, status: String },
    ProviderFailed { context_id: Option<AgentContextId>, epoch_id: Option<AgentEpochId> },
}

pub struct AgentEffectRequest {
    pub request_id: AgentRequestId,
    pub item_id: String,
    pub kind: AgentEffectKind,
    pub summary: String,
    pub request_digest: Sha256Digest,
}

pub enum AgentEffectKind {
    Command,
    FileChange,
    Network,
    External,
}

pub struct AgentUsage {
    pub last_total_tokens: u64,
    pub total_tokens: u64,
    pub model_context_window: Option<u64>,
}
```

Use this provider-neutral item shape:

```rust
pub enum AgentItem {
    Command {
        item_id: String,
        command: String,
        cwd: PathBuf,
        status: String,
        exit_code: Option<i32>,
        aggregated_output: Option<String>,
        process_id: Option<String>,
    },
    FileChange {
        item_id: String,
        status: String,
        changes: serde_json::Value,
    },
    ContextCompaction { item_id: String },
    Other { item_id: String, item_type: String },
}
```

- [ ] **Step 3: Implement `AgentPort` for Codex**

Wrap Codex IDs at the adapter boundary and translate every `CodexEvent`. Keep the
provider's response ID in `CodexAppServer::outstanding_approvals`; resolving through
`AgentRequestId` must look up the stored exact request and digest before replying.

- [ ] **Step 4: Refactor the ACP kernel to depend on `AgentPort`**

Replace `CodexPort`, `CodexModel`, and Codex ID fields in `acp/kernel.rs` with
`AgentPort`, `AgentModel`, and neutral IDs. Do not move Codex JSON types into the task
runtime.

- [ ] **Step 5: Run compatibility tests**

Run:

```bash
cargo test --locked --test agent_port_contract --test acp_kernel_contract --test buzz_end_to_end
```

Expected: PASS with unchanged ACP/Buzz behavior except mediated full access.

- [ ] **Step 6: Verify and commit**

Run the global Rust checks, then:

```bash
git add src/runtime src/acp/kernel.rs src/delegates/codex tests/agent_port_contract.rs tests/acp_kernel_contract.rs
git commit -m "refactor: add provider-neutral agent lifecycle port"
```

---

### Task 4: Add task domain types and a pure replay reducer

**Files:**
- Create: `src/runtime/task/mod.rs`
- Create: `src/runtime/task/types.rs`
- Create: `src/runtime/task/reducer.rs`
- Modify: `src/runtime/mod.rs`
- Modify: `src/events.rs`
- Create: `tests/task_domain_contract.rs`
- Modify: `tests/domain_contract.rs`

**Interfaces:**
- Consumes: `SessionId`, `PermissionMode`, `ModelId`, and `ReasoningEffort`.
- Produces: validated task types, `TaskEvent`, and `reduce_task` for storage and engine tasks.

- [ ] **Step 1: Write failing ID and contract validation tests**

Define and exercise `TaskId`, `EpochId`, `OperationId`, `CheckpointId`, and
`ContextPackageId`. Test round-trip serde, redacted debug output, and UUID display.

Test this contract shape:

```rust
pub struct CompletionContract {
    pub version: u32,
    pub goal: String,
    pub constraints: Vec<String>,
    pub clauses: Vec<CompletionClause>,
}

pub struct CompletionClause {
    pub id: String,
    pub description: String,
    pub required: bool,
    pub status: ClauseStatus,
    pub evidence: Vec<EvidenceRef>,
}

pub struct EvidenceRef {
    pub event_sequence: u64,
    pub artifact_digest: Option<String>,
    pub operation_id: Option<OperationId>,
}
```

Reject empty goals, duplicate clause IDs, control characters, more than 64 clauses,
more than 128 constraints, and any text field over 16 KiB.

- [ ] **Step 2: Define task and operation states**

Add:

```rust
pub enum TaskStatus {
    Queued,
    Active,
    Checkpointing,
    Paused,
    Blocked,
    Cancelling,
    Cancelled,
    Completing,
    Completed,
    Failed,
}

pub enum OperationStatus {
    IntentRecorded,
    Started,
    Succeeded,
    Failed,
    Cancelled,
    Uncertain,
    Reconciled,
}

pub enum EffectClass {
    Observation,
    IdempotentMutation,
    AmbiguousConsequential,
}

pub struct TaskBudget {
    pub max_wall_time_seconds: Option<u64>,
    pub max_provider_requests: Option<u64>,
    pub max_tool_calls: Option<u64>,
    pub soft_epoch_seconds: u64,
    pub soft_epoch_tool_calls: u32,
}

pub struct TaskSnapshot {
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub status: TaskStatus,
    pub contract: CompletionContract,
    pub budget: TaskBudget,
    pub active_epoch: Option<EpochId>,
    pub latest_checkpoint: Option<CheckpointId>,
    pub provider_context: Option<String>,
    pub revision: u64,
}

pub fn classify_effect(request: &AgentEffectRequest, item: &AgentItem) -> EffectClass {
    match (request.kind, item) {
        (AgentEffectKind::FileChange, AgentItem::FileChange { .. }) => {
            EffectClass::IdempotentMutation
        }
        _ => EffectClass::AmbiguousConsequential,
    }
}
```

`TaskBudget` stores optional total seconds/provider requests/tool calls plus the fixed
soft epoch defaults from the global constraints.
Unknown, command, network, external, or mismatched approval requests are never
downgraded. Pure observations run inside the read-only sandbox and do not create
pre-dispatch effect requests.

- [ ] **Step 3: Add schema-version-4 task events**

Add one event wrapper to `Event`:

```rust
TaskLifecycle {
    task_id: TaskId,
    event: TaskEvent,
}
```

`TaskEvent` is internally tagged and contains creation, state transition, contract
revision, epoch start/finish, operation transitions, usage, progress, checkpoint,
compaction, provider binding, steering, cancellation, blocker, and completion
records. Extend only the V4 serializer/deserializer; V1–V3 payload behavior remains
byte-compatible.

```rust
pub enum TaskEvent {
    Created {
        session_id: SessionId,
        workspace: PathBuf,
        contract: CompletionContract,
        budget: TaskBudget,
        model: ModelId,
        effort: ReasoningEffort,
        permission_mode: PermissionMode,
    },
    StateTransitioned { from: TaskStatus, to: TaskStatus, reason: String },
    ContractRevised { contract: CompletionContract },
    EpochStarted { epoch_id: EpochId, objective: String },
    EpochFinished { epoch_id: EpochId, report_digest: String },
    OperationIntentRecorded {
        operation_id: OperationId,
        epoch_id: EpochId,
        item_id: String,
        effect_class: EffectClass,
        request_digest: String,
    },
    OperationTransitioned {
        operation_id: OperationId,
        from: OperationStatus,
        to: OperationStatus,
        evidence_sequences: Vec<u64>,
    },
    UsageObserved { epoch_id: EpochId, total_tokens: u64, context_window: Option<u64> },
    ProgressAssessed { fingerprint: String, stalled: bool },
    CheckpointCommitted { checkpoint_id: CheckpointId, digest: String },
    CompactionRequested { generation: u32, reason: String },
    CompactionCompleted {
        generation: u32,
        checkpoint_id: CheckpointId,
        context_package_id: ContextPackageId,
    },
    ProviderContextBound { context_id: String },
    ProviderContextLost { context_id: String, reason: String },
    SteeringQueued { steering_sequence: u64, text_digest: String },
    CancellationRequested,
    Blocked { reason: String },
    Completed,
}
```

- [ ] **Step 4: Implement the pure reducer**

Expose:

```rust
pub fn reduce_task(
    state: Option<TaskSnapshot>,
    envelope: &EventEnvelope,
) -> Result<TaskSnapshot, TaskReduceError>;
```

Reject illegal status edges, mismatched task IDs, non-monotonic contract versions,
two active epochs, operation completion without intent, compaction without a committed
checkpoint, completion with unsatisfied required clauses, and events after a terminal
state.

- [ ] **Step 5: Add sequence-generated replay tests**

Generate bounded valid and invalid event sequences without adding a property-testing
dependency. For every prefix, reduce from empty and from a cloned intermediate state;
assert identical snapshots or identical stable error codes.

- [ ] **Step 6: Verify and commit**

Run the global Rust checks, then:

```bash
git add src/runtime src/events.rs tests/task_domain_contract.rs tests/domain_contract.rs
git commit -m "feat: add durable task state machine"
```

---

### Task 5: Persist task projections and atomic checkpoints

**Files:**
- Create: `migrations/0008_long_horizon_tasks.sql`
- Modify: `src/storage/schema.rs`
- Modify: `src/storage/repository.rs`
- Modify: `src/storage/mod.rs`
- Create: `tests/task_storage_contract.rs`
- Modify: `tests/storage_contract.rs`

**Interfaces:**
- Consumes: `TaskEvent`, `TaskSnapshot`, and task IDs from Task 4.
- Produces: transactional task event append/read/replay APIs used by checkpointing and `TaskEngine`.

- [ ] **Step 1: Write failing migration tests**

The migration creates these strict projection tables:

```text
agent_tasks
task_epochs
task_operations
task_checkpoints
task_context_packages
task_steering
```

Tests assert foreign keys, uniqueness, status checks, non-negative revisions, bounded
JSON byte lengths, migration checksum rejection, and successful opening of databases
ending at versions 1–7.

- [ ] **Step 2: Write the SQL migration**

`agent_tasks` references `sessions(id)` and stores status, contract JSON, canonical
workspace, model, effort, permission mode, revision, current epoch, latest checkpoint,
provider context, and timestamps. Child tables reference `agent_tasks(id)` with
`ON DELETE CASCADE`. Operation IDs and checkpoint IDs are globally unique.

Add migration 8 to `MIGRATIONS` with name `long-horizon tasks`.

- [ ] **Step 3: Add transactional repository APIs**

Expose:

```rust
pub struct NewTask {
    pub session_id: SessionId,
    pub workspace: PathBuf,
    pub contract: CompletionContract,
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub permission_mode: PermissionMode,
    pub budget: TaskBudget,
    pub created_at: DateTime<Utc>,
}

pub struct TaskRecord {
    pub snapshot: TaskSnapshot,
    pub revision: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub fn create_task(&mut self, input: NewTask) -> Result<TaskRecord, CarlError>;
pub fn append_task_event(
    &mut self,
    task_id: TaskId,
    expected_revision: u64,
    event: TaskEvent,
    at: DateTime<Utc>,
) -> Result<Option<TaskRecord>, CarlError>;
pub fn get_task(&self, task_id: TaskId) -> Result<Option<TaskRecord>, CarlError>;
pub fn list_resumable_tasks(&self) -> Result<Vec<TaskRecord>, CarlError>;
pub fn read_task_events(&self, task_id: TaskId) -> Result<Vec<EventEnvelope>, CarlError>;
pub fn read_task_event_page(
    &self,
    task_id: TaskId,
    after_sequence: Option<u64>,
    limit: u16,
) -> Result<Vec<EventEnvelope>, CarlError>;
```

`append_task_event` inserts the global event and updates every affected projection in
one immediate transaction. Revision mismatch returns `Ok(None)` and writes nothing.
`read_task_event_page` rejects zero or more than 512 rows and is the only history API
used by context assembly; long-running tasks must not load their entire journal.

- [ ] **Step 4: Add bounded event paging and projection checks**

Test page sizes 1 and 512, empty final pages, stable ascending sequence, task/session
isolation, and rejection of limits 0 and 513. Add a startup projection checker that
reduces each resumable task's events through the bounded reader and rejects a projection
whose revision, status, active epoch, or latest checkpoint ID differs.

- [ ] **Step 5: Prove replay and write-failure behavior**

For each transition, reopen the database, read task events, reduce them, and compare
the snapshot to the projection. Install a SQLite trigger that aborts a projection
write and assert neither the event nor partial projection commits.

- [ ] **Step 6: Verify and commit**

Run the global Rust checks, then:

```bash
git add migrations/0008_long_horizon_tasks.sql src/storage tests/task_storage_contract.rs tests/storage_contract.rs
git commit -m "feat: persist long-horizon task state"
```

---

### Task 6: Build canonical checkpoints and the context engine

**Files:**
- Create: `src/runtime/task/checkpoint.rs`
- Create: `src/runtime/task/context.rs`
- Modify: `src/runtime/task/mod.rs`
- Modify: `src/storage/repository.rs`
- Modify: `src/storage/mod.rs`
- Create: `tests/context_engine_contract.rs`
- Create: `tests/fixtures/provider/long_horizon_context.json`

**Interfaces:**
- Consumes: task snapshots/events and content-addressed artifact references.
- Produces: `CanonicalCheckpoint`, `ContextLedger`, `ContextPackage`, and `CompactionDecision`.

- [ ] **Step 1: Write failing canonical-checkpoint tests**

Use this top-level structure:

```rust
pub struct CanonicalCheckpoint {
    pub schema_version: u16,
    pub checkpoint_id: CheckpointId,
    pub task_id: TaskId,
    pub contract: CompletionContract,
    pub completed_work: Vec<WorkEvidence>,
    pub decisions: Vec<DecisionRecord>,
    pub exact_identifiers: Vec<ExactIdentifier>,
    pub operations: Vec<OperationCheckpoint>,
    pub repository: RepositoryCheckpoint,
    pub running_processes: Vec<ProcessCheckpoint>,
    pub pending_approval_digests: Vec<String>,
    pub pending_steering_digests: Vec<String>,
    pub uncertain_delivery_digests: Vec<String>,
    pub verification: Vec<ClauseEvidence>,
    pub next_objective: String,
    pub blockers: Vec<String>,
    pub provider: ProviderCheckpoint,
    pub compaction_generation: u32,
    pub source_sequence_start: u64,
    pub source_sequence_end: u64,
    pub previous_digest: Option<String>,
}
```

Build the same checkpoint from events in two insertion orders and assert identical
canonical bytes and lowercase SHA-256. Reject missing required identifiers, dangling
operation IDs, unpaired operations, invalid evidence ranges, secrets, and non-UTF-8
artifact content.

- [ ] **Step 2: Implement deterministic checkpoint construction**

Use `BTreeMap`/sorted vectors for canonical fields and `serde_json::to_vec` only after
validation. Model-authored narrative is a separate bounded optional string and is not
included in canonical decision or evidence fields.

Define the remaining checkpoint records used above:

```rust
pub struct WorkEvidence {
    pub summary: String,
    pub event_sequences: Vec<u64>,
    pub artifact_digests: Vec<String>,
}

pub struct DecisionRecord {
    pub id: String,
    pub decision: String,
    pub rationale: String,
}

pub struct ExactIdentifier {
    pub kind: String,
    pub value: String,
}

pub struct OperationCheckpoint {
    pub operation_id: OperationId,
    pub status: OperationStatus,
    pub effect_class: EffectClass,
    pub request_digest: String,
}

pub struct RepositoryCheckpoint {
    pub workspace_digest: String,
    pub git_head: Option<String>,
    pub git_status_digest: Option<String>,
    pub diff_artifact_digest: Option<String>,
    pub file_hashes: BTreeMap<String, String>,
}

pub struct ProcessCheckpoint {
    pub process_id: String,
    pub item_id: String,
    pub command_digest: String,
    pub cwd_digest: String,
}

pub struct ProviderCheckpoint {
    pub provider: String,
    pub model: String,
    pub effort: String,
    pub context_id: Option<String>,
    pub observed_total_tokens: Option<u64>,
    pub observed_context_window: Option<u64>,
}

pub struct ClauseEvidence {
    pub clause_id: String,
    pub evidence: Vec<EvidenceRef>,
}
```

- [ ] **Step 3: Write failing context-budget tests**

Define:

```rust
pub struct ContextBudget {
    pub context_window: u64,
    pub trigger_percent: u8,
    pub target_percent: u8,
}

pub enum ContextSourceKind {
    RuntimeInstructions,
    OwnerInstructions,
    ProjectInstructions,
    CompletionContract,
    Checkpoint,
    RecentTail,
    RetrievedEvidence,
    EpochObjective,
    UntrustedContent,
}

pub struct ContextLedgerEntry {
    pub kind: ContextSourceKind,
    pub byte_count: u64,
    pub token_count: u64,
    pub actual_tokens: bool,
    pub digest: String,
    pub included: bool,
    pub omission_reason: Option<String>,
}

pub struct ContextLedger {
    pub entries: Vec<ContextLedgerEntry>,
    pub total_tokens: u64,
    pub context_window: u64,
    pub compaction_generation: u32,
}

pub enum CompactionDecision {
    Continue,
    PruneTransientOutput,
    Compact,
    ReplaceProviderContext,
}

pub struct ContextEngine {
    budget: ContextBudget,
}

pub struct ContextInput {
    pub runtime_instructions: String,
    pub owner_instructions: String,
    pub project_instructions: String,
    pub contract: CompletionContract,
    pub checkpoint: CanonicalCheckpoint,
    pub recent_tail: Vec<ContextUnit>,
    pub retrieved_evidence: Vec<ContextUnit>,
    pub epoch_objective: String,
}

pub enum ContextUnit {
    Text { kind: ContextSourceKind, text: String },
    ToolExchange {
        operation_id: OperationId,
        request: String,
        result: String,
    },
    ArtifactReference { digest: String, summary: String },
}

pub enum ContextError {
    InvalidSource,
    MandatorySourcesExceedBudget,
    ArithmeticOverflow,
    SecretRejected,
}

impl ContextEngine {
    pub fn decide(&self, observed_tokens: u64) -> CompactionDecision;
    pub fn assemble(&self, input: ContextInput) -> Result<ContextPackage, ContextError>;
}
```

Test 80 percent trigger, 60 percent post-compaction maximum, overflow arithmetic,
actual-usage precedence, estimator fallback, stable precedence, and tool-pair atomicity.

- [ ] **Step 4: Implement pruning and package assembly**

`ContextEngine::assemble` emits stable instructions, owner/project instructions,
contract, checkpoint, recent tail, retrieved evidence, objective, then labeled
untrusted content. Old bulky tool output becomes an artifact reference; it is never
deleted. If mandatory sources cannot fit, return a stable budget error rather than
silently omitting them.

The returned package is:

```rust
pub struct ContextPackage {
    pub schema_version: u16,
    pub package_id: ContextPackageId,
    pub checkpoint_id: CheckpointId,
    pub rendered: String,
    pub ledger: Vec<ContextLedgerEntry>,
    pub source_sequence_start: u64,
    pub source_sequence_end: u64,
}
```

- [ ] **Step 5: Persist checkpoints and packages atomically**

Add to `Store`:

```rust
pub struct NewCheckpoint {
    pub task_id: TaskId,
    pub checkpoint: CanonicalCheckpoint,
    pub checkpoint_digest: String,
    pub context_package: ContextPackage,
    pub context_package_digest: String,
    pub created_at: DateTime<Utc>,
}

pub struct CheckpointRecord {
    pub checkpoint: CanonicalCheckpoint,
    pub checkpoint_digest: String,
    pub context_package_digest: String,
    pub created_at: DateTime<Utc>,
}

pub fn commit_checkpoint(
    &mut self,
    input: NewCheckpoint,
    expected_task_revision: u64,
) -> Result<Option<CheckpointRecord>, CarlError>;
```

The transaction verifies sequence bounds,
previous digest, every artifact reference, and both canonical digests before inserting
the records and appending `TaskEvent::CheckpointCommitted`.

- [ ] **Step 6: Prove repeated compaction does not drift**

Force twelve compactions. Each generation must consume the prior canonical checkpoint
plus later raw events, preserve the exact identifier `needle_7f3a91c2`, and never
summarize the prior narrative as source truth.

- [ ] **Step 7: Verify and commit**

Run the global Rust checks, then:

```bash
git add src/runtime/task src/storage tests/context_engine_contract.rs tests/fixtures/provider/long_horizon_context.json
git commit -m "feat: add canonical context compaction"
```

---

### Task 7: Add Codex resume, native compaction, and context replacement

**Files:**
- Modify: `src/delegates/codex/app_server.rs`
- Modify: `src/runtime/agent_port.rs`
- Modify: `tests/codex_app_server_contract.rs`
- Modify: `tests/agent_port_contract.rs`

**Interfaces:**
- Consumes: `AgentPort`, `ContextPackage`, and Codex schema contract.
- Produces: negotiated resume/compact behavior and safe new-context fallback.

- [ ] **Step 1: Write failing exact-request tests**

`resume_context` must send:

```json
{
  "threadId": "thr_123",
  "cwd": "/canonical/workspace",
  "model": "gpt-5.6-codex",
  "approvalPolicy": "on-request",
  "sandbox": "read-only",
  "excludeTurns": true
}
```

`compact_context` sends only `{"threadId":"thr_123"}` to
`thread/compact/start`, requires an empty response object, then observes matching
`contextCompaction` item start/completion notifications.

`list_background_processes` pages `thread/backgroundTerminals/list` with a maximum of
64 entries and 16 pages. `terminate_background_process` sends exactly `threadId` and
`processId` to `thread/backgroundTerminals/terminate` and requires a boolean
`terminated` result.

- [ ] **Step 2: Implement resume with strict response validation**

Validate returned thread ID, cwd, model, approval policy, sandbox, and absence of an
active turn before inserting the context in adapter state. Reject a different rollout,
workspace, or permission response.

- [ ] **Step 3: Implement compaction correlation**

Track one outstanding compaction per context. Coalesce repeat calls, correlate the
item ID from start through completion, and reject epoch start while the compaction
barrier is active.

Parse background process records only when `processId`, `itemId`, `command`, and
canonical `cwd` are present and bounded. Reject duplicate process IDs, repeated page
cursors, a process outside the task workspace, or more than the fixed page/entry caps.

- [ ] **Step 4: Implement new-context fallback**

Expose:

```rust
pub enum ContextRecovery {
    Resumed(AgentContextId),
    Compacted(AgentContextId),
    Replaced(AgentContextId),
}
```

When resume or compact is unsupported or fails before effect, start a new context and
send the rendered Carl context package as the first epoch input. Persisting the new
binding belongs to `TaskEngine`, not the adapter.

- [ ] **Step 5: Verify and commit**

Run the global Rust checks, then:

```bash
git add src/delegates/codex/app_server.rs src/runtime/agent_port.rs tests/codex_app_server_contract.rs tests/agent_port_contract.rs
git commit -m "feat: add Codex context lifecycle controls"
```

---

### Task 8: Parse epoch reports, verify clauses, and detect stalls

**Files:**
- Create: `src/runtime/task/report.rs`
- Create: `src/runtime/task/progress.rs`
- Modify: `src/runtime/task/mod.rs`
- Create: `tests/epoch_engine_contract.rs`

**Interfaces:**
- Consumes: canonical checkpoints and normalized operation evidence.
- Produces: `EpochReport`, `CompletionDecision`, `ProgressAssessment`, and `RecoveryStrategy`.

- [ ] **Step 1: Write failing bounded-report tests**

Parse exactly one final block:

```text
<carl-epoch-report>{"schema_version":1,"disposition":"continue","summary":"Regression reproduced","next_objective":"Implement the fix","clause_evidence":[],"exact_identifiers":["parser::decode"]}</carl-epoch-report>
```

The JSON type is:

```rust
pub enum EpochDisposition {
    Continue,
    Complete,
    Blocked,
}

pub struct ReportedClauseEvidence {
    pub clause_id: String,
    pub operation_ids: Vec<OperationId>,
    pub event_sequences: Vec<u64>,
    pub artifact_digests: Vec<String>,
}

pub struct EpochReport {
    pub schema_version: u16,
    pub disposition: EpochDisposition,
    pub summary: String,
    pub next_objective: Option<String>,
    pub clause_evidence: Vec<ReportedClauseEvidence>,
    pub exact_identifiers: Vec<String>,
}

pub enum CompletionDecision {
    Continue { next_objective: String },
    Complete,
    Blocked { reason: String },
}

pub struct ProgressAssessment {
    pub fingerprint: String,
    pub new_information: bool,
    pub resolved_clause_ids: Vec<String>,
    pub stall_count: u8,
    pub recovery: Option<RecoveryStrategy>,
}
```

Reject multiple blocks, trailing report-like text, unknown fields, output over 64 KiB,
unknown clause IDs, unknown operation IDs, and `complete` without evidence for every
required clause.

- [ ] **Step 2: Implement evidence validation**

Successful command evidence requires a normalized completed command with exit code 0.
File-change evidence requires a completed file-change item plus a matching diff or file
artifact. A model statement alone can satisfy no required clause.

- [ ] **Step 3: Implement deterministic progress fingerprints**

Hash sorted changed-file digests, verification outcomes, failure signatures, resolved
clause IDs, decision IDs, and next objective. Exclude timestamps, token counts, prose
wording, and provider IDs.

- [ ] **Step 4: Implement stall recovery selection**

Expose:

```rust
pub enum RecoveryStrategy {
    ReconstructFromEvidence,
    ReplaceApproach,
    FreshContextDiagnosis,
    MinimizeReproduction,
    DeclareBlocked,
}
```

The fifth result is legal only after three different strategy fingerprints failed or
the state contains a missing-authority blocker.

- [ ] **Step 5: Verify and commit**

Run the global Rust checks, then:

```bash
git add src/runtime/task tests/epoch_engine_contract.rs
git commit -m "feat: verify epoch progress and completion"
```

---

### Task 9: Implement the autonomous durable epoch engine

**Files:**
- Create: `src/runtime/task/engine.rs`
- Modify: `src/runtime/task/mod.rs`
- Modify: `src/acp/kernel.rs`
- Modify: `src/acp/session.rs`
- Modify: `tests/epoch_engine_contract.rs`
- Modify: `tests/acp_kernel_contract.rs`

**Interfaces:**
- Consumes: `AgentPort`, task repository APIs, context engine, report parser, and progress policy.
- Produces: `TaskEngine::run`, durable automatic continuation, and task updates for frontends.

- [ ] **Step 1: Write the failing three-epoch completion scenario**

The fake port must perform:

```text
epoch 1: reproduce failure -> continue
epoch 2: edit and run tests -> continue
epoch 3: run final checks -> complete
```

One owner prompt must return `TaskStatus::Completed` without any intervening user
prompt. Assert three epoch records, three committed checkpoints, one provider context,
and verified evidence for every contract clause.

Add a small-task case that completes a one-file edit with one contract-planning request
and one work request, zero compactions, zero provider replacements, and no visible
permission ceremony in full access.

- [ ] **Step 2: Define the engine seam**

```rust
pub enum TaskEngineErrorCode {
    InvalidTask,
    Storage,
    Provider,
    Context,
    Verification,
    Cancelled,
    Blocked,
}

pub struct TaskEngineError {
    code: TaskEngineErrorCode,
}

pub struct StartTask {
    pub session_id: SessionId,
    pub workspace: PathBuf,
    pub request: String,
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub permission_mode: PermissionMode,
    pub budget: TaskBudget,
}

impl<P: AgentPort> TaskEngine<P> {
    pub async fn start(&mut self, input: StartTask) -> Result<TaskSnapshot, TaskEngineError>;
    pub async fn run(&mut self, task_id: TaskId) -> Result<TaskSnapshot, TaskEngineError>;
    pub async fn steer(&mut self, task_id: TaskId, text: String) -> Result<(), TaskEngineError>;
    pub async fn cancel(&mut self, task_id: TaskId) -> Result<(), TaskEngineError>;
}
```

- [ ] **Step 3: Add autonomous contract planning**

The first read-only epoch asks for a bounded `CompletionContract` JSON block. Validate
it and fall back to an immutable two-clause contract—requested outcome and explicit
verification—when one repair attempt fails. Never ask the owner to restate an obvious
coding request.

- [ ] **Step 4: Implement the work loop**

For each epoch: persist start, assemble context, start provider epoch, drain normalized
events, journal operation evidence, apply queued steering, parse the report, verify
progress, commit checkpoint, then choose complete/continue/compact/recover/block.
Context and provider binding events commit before the next provider request.

- [ ] **Step 5: Add soft-boundary steering**

At fifteen minutes or forty completed tools, inject a steer message requesting a safe
checkpoint. If the provider cannot steer, interrupt only after recording the boundary
request and mark the current operation according to its observed terminal state.

- [ ] **Step 6: Integrate with the ACP kernel**

`session/prompt` starts or steers the session's task. Add `KernelUpdate` variants for
task status, epoch objective, checkpoint committed, context usage, compaction, recovery
strategy, and completion clauses. Preserve existing assistant/diff/tool updates.

- [ ] **Step 7: Verify and commit**

Run the global Rust checks, then:

```bash
git add src/runtime/task src/acp tests/epoch_engine_contract.rs tests/acp_kernel_contract.rs
git commit -m "feat: run autonomous durable coding epochs"
```

---

### Task 10: Recover safely across interruption and provider loss

**Files:**
- Modify: `src/runtime/task/engine.rs`
- Modify: `src/storage/repository.rs`
- Modify: `src/storage/mod.rs`
- Modify: `src/acp/kernel.rs`
- Modify: `tests/task_storage_contract.rs`
- Modify: `tests/epoch_engine_contract.rs`

**Interfaces:**
- Consumes: nonterminal stored tasks and operation effect classes.
- Produces: startup reconciliation, provider replacement, and deterministic resume.

- [ ] **Step 1: Write interruption-boundary tests**

Terminate the engine after each of these durable states:

```text
task created
epoch started
operation intent recorded
effect authorized
item started
workspace mutation observed
item completed
checkpoint candidate built
checkpoint committed
compaction requested
provider replacement started
provider binding committed
```

Reopen SQLite and assert deterministic snapshot reconstruction at every cut.

- [ ] **Step 2: Add startup reconciliation records**

`RuntimeStore::open` must list nonterminal tasks and change abandoned active operations
to `Uncertain` in one transaction. Observation operations may be scheduled again with
a new ID. Idempotent mutations require postcondition inspection. Ambiguous effects
remain uncertain unless an adapter-specific reconciler proves completion.

After a successful provider-context resume, call `list_background_processes` and match
the exact stored process ID, item ID, command digest, and cwd. A complete match restores
the running handle; a missing or mismatched handle becomes uncertain. Cancellation
uses `terminate_background_process` and records its boolean result before reporting
that cleanup succeeded.

- [ ] **Step 3: Replace missing provider contexts**

When `resume_context` fails with a stable unavailable-context code, commit
`ProviderContextLost`, assemble the latest Carl package, start a new context, commit
`ProviderContextBound`, and continue with `FreshContextDiagnosis`. Do not mutate or
delete the old provider transcript.

- [ ] **Step 4: Prove ambiguous effects are never duplicated**

Use a fake external effect that increments a durable counter before the fake provider
disconnects. Across every restart cut, assert the counter equals one and the task is
either reconciled or blocked with the exact uncertain operation ID.

- [ ] **Step 5: Verify and commit**

Run the global Rust checks, then:

```bash
git add src/runtime/task/engine.rs src/storage src/acp/kernel.rs tests/task_storage_contract.rs tests/epoch_engine_contract.rs
git commit -m "feat: recover durable tasks without replay"
```

---

### Task 11: Expose task control and safe owner-default permissions

**Files:**
- Modify: `src/acp/config.rs`
- Modify: `src/acp/protocol.rs`
- Modify: `src/acp/server.rs`
- Modify: `src/acp/session.rs`
- Modify: `src/cli.rs`
- Create: `migrations/0009_trusted_frontend_owners.sql`
- Modify: `src/storage/schema.rs`
- Modify: `src/storage/repository.rs`
- Modify: `src/storage/mod.rs`
- Modify: `tests/acp_protocol_contract.rs`
- Modify: `tests/acp_server_contract.rs`
- Modify: `tests/acp_cli_contract.rs`
- Modify: `tests/buzz_end_to_end.rs`

**Interfaces:**
- Consumes: `TaskEngine` commands and snapshots.
- Produces: owner-visible status/resume/cancel/steer commands and canonical `fullAccess` configuration.

- [ ] **Step 1: Add canonical `fullAccess` parsing tests**

`fullAccess` becomes the preferred wire value. `bypassPermissions` parses to the same
profile and remains serialized only when echoing a legacy client selection. New CLI
aliases are:

Add `PermissionMode::FullAccess` with `as_wire_str() == "fullAccess"`; update
`PermissionMode::ALL`, `FromStr`, serde, configuration options, and
`PermissionMode::profile`. Keep `PermissionMode::BypassPermissions` as a separate
legacy wire variant whose profile is also `FullAccess`.

```text
--permission-mode fullAccess
--dangerously-bypass-permissions
```

Both select `PermissionProfile::FullAccess`.

- [ ] **Step 2: Default only new trusted-owner tasks**

Local CLI/TUI and a newly paired owner frontend default to `fullAccess`. Existing
`frontend_sessions.permission_mode` rows are not rewritten. Unknown or shared
frontends cannot select full access. Migration 9 adds a non-null
`permission_profile` column constrained to `read_only`, `approval`, or `full_access`,
then initializes it from each existing legacy mode. The legacy
`frontend_sessions.permission_mode` column stores `bypassPermissions` when the new
wire value is `fullAccess`; reads use `permission_profile` to return the canonical
product mode. Never modify or rebuild migrations 1–8.

The same migration adds `trusted_frontend_owners(frontend, actor_id, channel_id,
workspace_digest, permission_mode, created_at, updated_at)` with one active owner per
frontend/workspace. Add the local command
`carl trust buzz --actor <stable-actor-id> --workspace <absolute-path>`; the first
matching signed owner message may fill the previously null channel exactly once.
Changing actor, channel, workspace, or frontend requires a new local trust command and
invalidates the prior binding.

- [ ] **Step 3: Add task protocol methods**

Implement bounded ACP-compatible extension methods:

```text
_task/status
_task/list
_task/resume
_task/cancel
_task/steer
_task/context
```

Every mutation accepts an idempotency key and exact session/task binding. Status and
list return bounded snapshots, not full event history.

- [ ] **Step 4: Add slash-command compatibility**

Map `/status`, `/resume`, `/cancel`, `/context`, `/permissions fullAccess`,
`/permissions approval`, and `/permissions readOnly` through the same kernel commands.
Quoted or embedded slash text remains ordinary user input.

Queue model and effort changes while an epoch is active and apply them to the next
`StartAgentEpoch`; a permission tightening may interrupt immediately, while a
permission loosening also waits for a safe boundary. Test all three cases.

- [ ] **Step 5: Prove remote admission precedes execution**

Extend Buzz tests so a mismatched actor/channel, group-shaped context, replayed event,
or unconfirmed binding produces zero provider requests and zero task rows. An accepted
owner task receives full access without an approval message. The existing remote
`/confirm-bypass` ceremony remains only for legacy sessions that lack a locally
trusted owner binding.

- [ ] **Step 6: Verify and commit**

Run the global Rust checks, then:

```bash
git add src/acp src/cli.rs src/storage migrations/0009_trusted_frontend_owners.sql tests/acp_protocol_contract.rs tests/acp_server_contract.rs tests/acp_cli_contract.rs tests/buzz_end_to_end.rs
git commit -m "feat: expose autonomous task controls"
```

---

### Task 12: Keep tasks alive behind a persistent owner service

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `src/service/mod.rs`
- Create: `src/service/protocol.rs`
- Create: `src/service/server.rs`
- Create: `src/service/client.rs`
- Modify: `src/lib.rs`
- Modify: `src/cli.rs`
- Modify: `src/acp/server.rs`
- Create: `tests/service_protocol_contract.rs`
- Create: `tests/service_end_to_end.rs`

**Interfaces:**
- Consumes: task protocol commands from Task 11 and the one-writer `TaskEngine`.
- Produces: a persistent local task owner so frontend disconnects do not cancel active work.

- [ ] **Step 1: Write failing bounded-protocol tests**

Define versioned newline-JSON frames:

```rust
pub struct ServiceRequest {
    pub protocol_version: u16,
    pub request_id: String,
    pub idempotency_key: String,
    pub command: ServiceCommand,
}

pub enum ServiceCommand {
    StartTask(StartTaskCommand),
    Status { task_id: TaskId },
    List,
    Resume { task_id: TaskId },
    Steer { task_id: TaskId, text: String },
    Cancel { task_id: TaskId },
    Events { task_id: TaskId, after_sequence: Option<u64>, limit: u16 },
    Shutdown,
}

pub enum ServiceFrame {
    Response { request_id: String, result: ServiceResult },
    Error { request_id: String, code: String, message: String },
    Event { task_id: TaskId, sequence: u64, update: TaskUpdate },
}

pub struct StartTaskCommand {
    pub external_session_id: String,
    pub workspace: PathBuf,
    pub request: String,
    pub model: ModelId,
    pub effort: ReasoningEffort,
    pub permission_mode: PermissionMode,
}

pub enum ServiceResult {
    Accepted { task_id: TaskId },
    Snapshot(TaskSnapshot),
    TaskList(Vec<TaskSnapshot>),
    Events(Vec<EventEnvelope>),
    Applied,
}

pub enum TaskUpdate {
    Status(TaskStatus),
    EpochObjective(String),
    ToolStarted(String),
    ToolCompleted(String),
    AssistantDelta(String),
    Diff(String),
    Checkpoint(CheckpointId),
    ContextUsage { used: u64, window: u64 },
    Compaction { generation: u32 },
    CompletionClauses(Vec<CompletionClause>),
}
```

Reject frames over 256 KiB, unsupported versions, control characters, duplicate
request IDs, reused idempotency keys with different command digests, event limits 0 or
over 512, and unknown fields.

- [ ] **Step 2: Implement owner-private local endpoints**

Enable Tokio's `net` feature. On Unix, bind `CARL_DATA_DIR/carl.sock` only after
holding the data-root lock; reject a symlink/non-socket entry and set mode 0600. On
Windows, bind a named pipe whose name contains the SHA-256 of the canonical data root
and whose DACL grants only the current user. A second service fails before opening
SQLite.

- [ ] **Step 3: Move task ownership into `TaskService`**

```rust
pub struct TaskService<P: AgentPort> {
    engine: TaskEngine<P>,
    subscribers: HashMap<TaskId, Vec<mpsc::Sender<ServiceFrame>>>,
    completed_idempotency: BTreeMap<String, ServiceResult>,
}
```

The service owns the runtime store, provider process, task actors, and cancellation
tokens. Client EOF removes only that subscriber. It must not cancel, pause, or release
an active task. Slow clients receive a bounded snapshot and cursor instead of an
unbounded in-memory queue.

At startup it reconciles and schedules every resumable task before accepting frontend
commands. Tasks that require a new provider context continue from their latest valid
Carl checkpoint even when no frontend is connected.

- [ ] **Step 4: Add `carl serve` and reconnecting clients**

`carl serve` runs the persistent service in the foreground and exits cleanly on an
authenticated `Shutdown` or OS signal after checkpointing/cancelling active epochs.
`TaskServiceClient::connect` validates endpoint identity, negotiates version 1, and
reconnects with the last durable event cursor.

- [ ] **Step 5: Make ACP a thin service client**

`carl acp` no longer owns SQLite or Codex. It connects to the local service, translates
ACP session/task calls into service commands, and maps service events back to ACP
updates. Losing stdio disconnects the ACP client while the service and task continue.
Reconnecting with the same exact actor/channel/session binding resumes event delivery
from the last acknowledged sequence.

- [ ] **Step 6: Prove disconnect and restart continuity**

Start a three-epoch fake task, disconnect the ACP client during epoch 1, wait for epoch
2, reconnect, and assert the task completes once with all events in sequence. Then
terminate the service after a committed checkpoint, restart it, reconnect the client,
and assert provider replacement resumes the task without duplicating the fake effect.

- [ ] **Step 7: Verify and commit**

Run the global Rust checks, then:

```bash
git add Cargo.toml Cargo.lock src/service src/lib.rs src/cli.rs src/acp/server.rs tests/service_protocol_contract.rs tests/service_end_to_end.rs
git commit -m "feat: keep tasks alive across frontend reconnects"
```

---

### Task 13: Build deterministic long-horizon evaluation infrastructure

**Files:**
- Create: `src/evals/mod.rs`
- Create: `src/evals/scenario.rs`
- Create: `src/evals/metrics.rs`
- Modify: `src/lib.rs`
- Create: `tests/long_horizon_eval.rs`
- Create: `tests/fixtures/long_horizon/needle/README.md`
- Create: `tests/fixtures/long_horizon/needle/src/lib.rs`
- Create: `tests/fixtures/long_horizon/needle/tests/contract.rs`

**Interfaces:**
- Consumes: `TaskEngine` with scripted `AgentPort`, fake clock, and disposable workspace.
- Produces: `EvaluationResult`, sanitized metrics, and deterministic release-gate failures.

- [ ] **Step 1: Define the scenario and metric contracts**

```rust
pub struct EvaluationScenario {
    pub name: String,
    pub epochs: u32,
    pub force_compaction_every: u32,
    pub restart_after_events: Vec<u64>,
    pub steering: Vec<ScheduledSteering>,
    pub expected_identifiers: Vec<String>,
}

pub struct EvaluationMetrics {
    pub completed: bool,
    pub required_clauses_passed: u32,
    pub duplicate_effects: u32,
    pub lost_identifiers: u32,
    pub out_of_scope_changes: u32,
    pub restarts: u32,
    pub compactions: u32,
    pub strategy_changes: u32,
    pub orphan_processes: u32,
    pub replay_digest: String,
}

pub struct EvaluationResult {
    pub scenario: String,
    pub passed: bool,
    pub metrics: EvaluationMetrics,
    pub failure_codes: Vec<String>,
}
```

Serialization denies unknown fields and never includes assistant text, raw tool output,
credentials, or absolute user paths.

- [ ] **Step 2: Implement the 100-epoch scripted scenario**

Force compaction every third epoch, provider loss every seventeenth epoch, steering at
epochs 11 and 61, and storage reopen after every operation lifecycle state. The exact
identifier `needle_7f3a91c2` originates in epoch 1 and is required by the final test.

- [ ] **Step 3: Add repository scenarios**

Cover regression-first bug fix, multi-file refactor, command failure recovery, stalled
strategy replacement, provider loss, long-running command cancellation, hostile
instructions, secret rejection, out-of-scope write, and ambiguous external effect.
Every scenario uses a new copied fixture beneath an owner-private temporary directory.

- [ ] **Step 4: Enforce deterministic release gates**

Fail unless completion and required checks pass, duplicate effects/lost identifiers/
out-of-scope changes/orphans equal zero, and replay digests match across every restart
schedule.

- [ ] **Step 5: Add CI execution**

Add this exact command to the existing test job; do not create a secret-bearing job:

```bash
cargo test --locked --test long_horizon_eval
```

- [ ] **Step 6: Verify and commit**

Run the global Rust checks, then:

```bash
git add src/evals src/lib.rs tests/long_horizon_eval.rs tests/fixtures/long_horizon .github/workflows/ci.yml tests/workflow_contract.rs
git commit -m "test: add deterministic long-horizon evaluations"
```

---

### Task 14: Add the live OAuth endurance and paired baseline runner

**Files:**
- Create: `scripts/live-codex-long-horizon.mjs`
- Modify: `scripts/live-codex-acp-smoke.mjs`
- Modify: `tests/docs_contract.rs`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: release `carl`, Codex `0.146.0`, owner-private `CARL_DATA_DIR`, and ChatGPT subscription OAuth.
- Produces: sanitized live-run metadata and a true two-to-eight-hour soak.

- [ ] **Step 1: Add strict live-run admission**

The script requires absolute `CARL_DATA_DIR`, `CARL_CODEX_EXECUTABLE`, and a release
binary. It removes `OPENAI_API_KEY`, `CODEX_API_KEY`, `AZURE_OPENAI_API_KEY`, every
`BUZZ_*`, and every `XAI_*` variable before spawn. It refuses a duration outside two
to eight hours and defaults to four.

- [ ] **Step 2: Create a disposable multi-clause repository task**

Generate a temporary Rust repository with a failing regression, cross-file refactor,
documentation clause, exact early identifier, formatting check, and test suite. Store
only fixture source beneath the temporary directory; never copy the active Carl
workspace.

- [ ] **Step 3: Exercise long-horizon controls**

The runner must request at least twenty compactions, restart Carl at least five times,
replace the provider context at least twice, inject steering twice, and observe one
long-running command. A timer alone cannot satisfy an epoch; each interval requires a
new checkpoint digest or progress record.

- [ ] **Step 4: Add paired direct-Codex baseline mode**

Run the same prompt, model, effort, fixture snapshot, and wall-time limit once through
Carl and once through direct Codex. Record harness revision, Codex version, model,
effort, completion clauses, interventions, elapsed milliseconds, provider requests,
compactions, and boolean safety outcomes. Do not claim superiority from this one run.

- [ ] **Step 5: Persist only sanitized metadata**

Write a mode-0600 JSON file containing numbers, booleans, version strings, fixture
revision, and digests. Assert it contains no assistant text, diff, command output,
credential, email address, or absolute home path.

- [ ] **Step 6: Run the short live contract**

Build and run:

```bash
cargo build --locked --release
env -u OPENAI_API_KEY -u CODEX_API_KEY -u AZURE_OPENAI_API_KEY \
  CARL_DATA_DIR="$HOME/.carl" \
  CARL_CODEX_EXECUTABLE="$(command -v codex)" \
  CARL_LIVE_MODEL=gpt-5.6-terra \
  CARL_LIVE_EFFORT=low \
  CARL_LIVE_DURATION_HOURS=2 \
  node scripts/live-codex-long-horizon.mjs
```

Expected: completed task, at least twenty compactions, at least five restarts, zero
duplicate effects, zero lost identifiers, zero leaked secrets, and zero orphaned test
processes.

- [ ] **Step 7: Commit without live artifacts**

```bash
git add scripts/live-codex-long-horizon.mjs scripts/live-codex-acp-smoke.mjs tests/docs_contract.rs .gitignore
git commit -m "test: add subscription-backed endurance soak"
```

---

### Task 15: Align security, architecture, configuration, and benchmark claims

**Files:**
- Modify after separate exact-diff approval: `SECURITY.md`
- Modify: `README.md`
- Modify: `docs/security.md`
- Modify: `docs/architecture.md`
- Modify: `docs/configuration.md`
- Modify: `docs/buzz.md`
- Create: `docs/long-horizon-tasks.md`
- Create: `docs/benchmarks.md`
- Modify: `tests/docs_contract.rs`

**Interfaces:**
- Consumes: tested behavior and sanitized evaluation output from Tasks 1–14.
- Produces: truthful user guidance and release claims.

- [ ] **Step 1: Write failing documentation contracts**

Require documentation for full-access accepted risk, pre-dispatch mediation, task
status/resume/cancel/steer, checkpoint inspection, compaction thresholds, provider
replacement, deterministic evals, live soak, and the rule that comparative claims
need at least thirty paired runs.

- [ ] **Step 2: Preview the root security-policy diff**

Prepare but do not apply an exact diff replacing the stale pre-runtime/API-key text
with the implemented subscription-backed coding boundary, owner-default full access,
pre-dispatch invariant, untrusted remote denial, same-user secret risk, and explicit
out-of-scope sandbox claims. Obtain owner approval for that exact diff before editing
`SECURITY.md`.

- [ ] **Step 3: Update product documentation**

Document commands, modes, lifecycle, inspection output, recovery behavior, fixture
methodology, live-run prerequisites, data retained, and limitations. Mark any feature
that did not pass its gate as unavailable rather than planned-as-implemented.

- [ ] **Step 4: Run the complete deterministic release gate**

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --doc
cargo test --all-features
cargo test --locked --test buzz_acp_contract --test buzz_end_to_end --test long_horizon_eval
cargo deny check
```

Expected: every command exits 0.

- [ ] **Step 5: Inspect repository state and commit**

Confirm no live metadata, temporary repository, provider transcript, token, or
credential is tracked. Then:

```bash
git add SECURITY.md README.md docs tests/docs_contract.rs
git commit -m "docs: publish long-horizon runtime guarantees"
```

- [ ] **Step 6: Push only after final review**

Review the complete branch diff against the approved design, rerun the deterministic
gate, and push the reviewed branch. Do not include local OAuth state or live-run
artifacts.
