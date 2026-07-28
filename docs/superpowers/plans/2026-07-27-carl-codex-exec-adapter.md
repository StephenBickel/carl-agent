# Carl Codex Exec Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an inert, subscription-backed Codex execution adapter that resolves model and reasoning-effort settings, supervises `codex exec --json`, and normalizes its event stream without exposing live workspace execution through the CLI.

**Architecture:** A new `delegates` module remains separate from Carl's native `Provider` trait. Pure configuration and event-normalization units feed a one-way JSONL process primitive built on the existing trusted executable, provider-home, process-group, output-bound, and redaction foundations. `CodexExecAdapter` composes those units, writes only Carl-controlled Codex configuration, sends the task over stdin, and exposes normalized events plus a typed terminal outcome.

**Tech Stack:** Rust 2024, Tokio process and channel primitives, Serde JSON, existing `sidecar` capabilities, SHA-256-safe bounded data, custom-harness fake sidecars, and the pinned Codex CLI `0.136.0`.

## Global Constraints

- Do not add, read, accept, or forward `OPENAI_API_KEY`, `CODEX_API_KEY`, OAuth bearer tokens, refresh tokens, or credential-file paths.
- Codex remains a subscription delegate and never implements Carl's native `Provider` trait.
- The tested command is Codex CLI `0.136.0`; incompatible versions fail before task input is sent.
- The task is sent through `codex exec -` on stdin so private prompt text does not appear in the process argument list.
- Use `--json`, `--ephemeral`, `--sandbox workspace-write`, `--ask-for-approval never`, and `--skip-git-repo-check`.
- Generated commands receive no ambient network access; provider transport remains provider-owned.
- Model and effort are never silently substituted.
- All provider JSONL and stderr are bounded before reaching adapters; stderr remains a redacted marker.
- Normal tests use a fake executable and no live provider credentials or network.
- The adapter remains library-only until staging, policy, approval, verification, and promotion plans are implemented.

---

## File structure

- `src/delegates/mod.rs`: public delegate boundary and shared exports.
- `src/delegates/settings.rs`: bounded model IDs, typed effort, layered resolution, and provenance.
- `src/delegates/codex/mod.rs`: Codex adapter request/run API and command composition.
- `src/delegates/codex/events.rs`: stateful Codex JSONL-to-Carl normalization.
- `src/sidecar/exec_jsonl.rs`: provider-neutral one-way JSONL child process with stdin payload, natural-exit draining, cancellation, and bounded diagnostics.
- `src/sidecar/mod.rs`: re-export the new primitive and share existing trusted process helpers.
- `tests/delegate_settings_contract.rs`: setting precedence, validation, and serialization contract.
- `tests/codex_exec_contract.rs`: custom-harness fake Codex executable and end-to-end adapter contract.
- `tests/support/sidecar.rs`: reuse common temporary-layout and process-reaping helpers.
- `Cargo.toml`: register the custom-harness test.

---

### Task 1: Delegate model and reasoning settings

**Files:**

- Create: `src/delegates/mod.rs`
- Create: `src/delegates/settings.rs`
- Modify: `src/lib.rs`
- Create: `tests/delegate_settings_contract.rs`

**Interfaces:**

- Produces: `ModelId::parse`, `BoundedDelegateTask::parse`, `ReasoningEffort`, `SettingSource`, `DelegateSettings`, `DelegateSettingsLayers`, and `ResolvedDelegateSettings`.
- Consumes: no runtime, provider, sidecar, or storage implementation.
- Later tasks consume `ResolvedDelegateSettings::model()` and `ResolvedDelegateSettings::effort()` to construct Codex arguments.

- [ ] **Step 1: Write failing public-contract tests**

```rust
use carl::delegates::{
    DelegateSettings, DelegateSettingsLayers, ModelId, ReasoningEffort, SettingSource,
};

#[test]
fn per_run_values_override_session_without_mutating_it() {
    let session = DelegateSettings::new(
        Some(ModelId::parse("gpt-5.6").unwrap()),
        Some(ReasoningEffort::High),
    );
    let per_run = DelegateSettings::new(
        Some(ModelId::parse("gpt-5.6-terra").unwrap()),
        Some(ReasoningEffort::Low),
    );
    let resolved = DelegateSettingsLayers {
        personal: None,
        project: None,
        session: Some(&session),
        per_run: Some(&per_run),
    }
    .resolve();

    assert_eq!(resolved.model().unwrap().as_str(), "gpt-5.6-terra");
    assert_eq!(resolved.model_source(), SettingSource::PerRun);
    assert_eq!(resolved.effort(), Some(ReasoningEffort::Low));
    assert_eq!(resolved.effort_source(), SettingSource::PerRun);
    assert_eq!(session.model().unwrap().as_str(), "gpt-5.6");
    assert_eq!(session.effort(), Some(ReasoningEffort::High));
}

#[test]
fn settings_resolve_each_field_independently() {
    let personal =
        DelegateSettings::new(Some(ModelId::parse("gpt-5.6").unwrap()), None);
    let session = DelegateSettings::new(None, Some(ReasoningEffort::XHigh));
    let resolved = DelegateSettingsLayers {
        personal: Some(&personal),
        project: None,
        session: Some(&session),
        per_run: None,
    }
    .resolve();

    assert_eq!(resolved.model_source(), SettingSource::Personal);
    assert_eq!(resolved.effort_source(), SettingSource::Session);
}

#[test]
fn model_ids_are_bounded_provider_owned_strings() {
    assert!(ModelId::parse("").is_err());
    assert!(ModelId::parse("gpt 5.6").is_err());
    assert!(ModelId::parse(&"x".repeat(129)).is_err());
    assert_eq!(ModelId::parse("gpt-5.6").unwrap().as_str(), "gpt-5.6");
}

#[test]
fn delegate_tasks_are_nonempty_and_bounded() {
    assert!(BoundedDelegateTask::parse("").is_err());
    assert!(BoundedDelegateTask::parse(&"x".repeat(32_769)).is_err());
    assert_eq!(
        BoundedDelegateTask::parse("Fix the failing test")
            .unwrap()
            .as_str(),
        "Fix the failing test"
    );
}
```

- [ ] **Step 2: Run the contract test and verify failure**

Run:

```bash
cargo test --test delegate_settings_contract
```

Expected: compilation fails because `carl::delegates` does not exist.

- [ ] **Step 3: Implement the bounded setting types**

Implement:

```rust
pub const MAX_MODEL_ID_BYTES: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ModelId(String);

impl ModelId {
    pub fn parse(value: impl Into<String>) -> Result<Self, CarlError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= MAX_MODEL_ID_BYTES
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            });
        valid.then_some(Self(value)).ok_or_else(|| CarlError::Validation {
            detail: "delegate model identifier is invalid".into(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningEffort {
    Low,
    Medium,
    High,
    #[serde(rename = "xhigh")]
    XHigh,
    Max,
    Ultra,
}

impl ReasoningEffort {
    pub const fn as_codex_value(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::XHigh => "xhigh",
            Self::Max => "max",
            Self::Ultra => "ultra",
        }
    }
}
```

Add `BoundedDelegateTask` with the same validating-constructor pattern, a 32 KiB hard
limit, rejection of empty input and NUL bytes, a redacted `Debug` implementation, and
no serialization implementation that can bypass validation.

Resolve model and effort independently using this precedence:

```text
per_run > session > project > personal > provider_default
```

`SettingSource::ProviderDefault` must be returned when a field remains unset.

- [ ] **Step 4: Run focused and domain tests**

Run:

```bash
cargo test --test delegate_settings_contract
cargo test --test domain_contract
```

Expected: both pass.

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs src/delegates tests/delegate_settings_contract.rs
git commit -m "feat: add delegate model settings"
```

---

### Task 2: Stateful Codex JSONL normalization

**Files:**

- Create: `src/delegates/codex/mod.rs`
- Create: `src/delegates/codex/events.rs`
- Modify: `src/delegates/mod.rs`
- Create: `tests/codex_exec_contract.rs`
- Modify: `Cargo.toml`

**Interfaces:**

- Consumes: bounded `serde_json::Value` objects from Task 3's process primitive.
- Produces: `CodexEventNormalizer::new`, `CodexEventNormalizer::ingest`, `DelegateEvent`, `DelegateUsage`, `DelegateTerminal`, and `CodexProtocolError`.
- `ingest` returns `Result<Option<DelegateEvent>, CodexProtocolError>`; `None` is reserved for intentionally suppressed reasoning text.

- [ ] **Step 1: Register a custom-harness test and add failing JSONL fixtures**

Add:

```toml
[[test]]
name = "codex_exec_contract"
path = "tests/codex_exec_contract.rs"
harness = false
```

The test binary's `main` first dispatches fake-sidecar arguments, then runs
`libtest_mimic`. Add focused tests with the documented stream:

```rust
let input = [
    json!({"type":"thread.started","thread_id":"0199a213-81c0-7800-8aa1-bbab2a035a53"}),
    json!({"type":"turn.started"}),
    json!({"type":"item.completed","item":{"id":"item_1","type":"agent_message","text":"Fixed it."}}),
    json!({"type":"turn.completed","usage":{
        "input_tokens":120,
        "cached_input_tokens":100,
        "output_tokens":30
    }}),
];

let mut normalizer = CodexEventNormalizer::new();
let output = input
    .into_iter()
    .map(|value| normalizer.ingest(value))
    .collect::<Result<Vec<_>, _>>()
    .unwrap()
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

assert!(matches!(output.last(), Some(DelegateEvent::Terminal(
    DelegateTerminal::Completed { .. }
))));
```

Also test:

- `turn.started` before `thread.started` fails;
- duplicate terminal events fail;
- malformed required fields fail;
- reasoning items yield a metadata-only activity event with no reasoning text;
- an unknown top-level type becomes a bounded compatibility event;
- text and command fields above their limits fail.

- [ ] **Step 2: Run the contract test and verify failure**

Run:

```bash
cargo test --test codex_exec_contract
```

Expected: compilation fails because Codex delegate event types do not exist.

- [ ] **Step 3: Implement the state machine**

Use closed lifecycle state:

```rust
enum StreamState {
    AwaitingThread,
    AwaitingTurn,
    InTurn,
    Terminal,
}
```

Normalize these top-level types:

```text
thread.started
turn.started
item.started
item.updated
item.completed
turn.completed
turn.failed
error
```

For item types, expose bounded agent messages, command status, file-change status, MCP
status, web-search status, and plan-update status. Represent reasoning as
`DelegateActivityKind::Reasoning` without storing its text. Unknown optional types
produce:

```rust
DelegateEvent::Compatibility {
    event_type: BoundedEventType,
}
```

Do not retain the raw JSON value in a normalized event.

- [ ] **Step 4: Run focused tests**

Run:

```bash
cargo test --test codex_exec_contract normalization
cargo test --test domain_contract
```

Expected: all selected tests pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/delegates tests/codex_exec_contract.rs
git commit -m "feat: normalize Codex exec events"
```

---

### Task 3: One-way supervised JSONL execution

**Files:**

- Create: `src/sidecar/exec_jsonl.rs`
- Modify: `src/sidecar/mod.rs`
- Extend: `tests/codex_exec_contract.rs`
- Extend: `tests/support/sidecar.rs`

**Interfaces:**

- Consumes: `TrustedExecutable`, `ProviderHome`, `SidecarCommand`, `SidecarLimits`, an execution workspace capability, and bounded stdin bytes.
- Produces: `ExecutionWorkspace`, `JsonlEventProcess::spawn_in_home`, `JsonlEventProcess::next_event`, `JsonlEventProcess::wait`, `JsonlEventProcess::cancel`, and `JsonlProcessOutcome`.
- Task 4 consumes the primitive but cannot access raw child handles, unrestricted environment mutation, or unbounded stderr.

- [ ] **Step 1: Write failing fake-process lifecycle tests**

Add fixture modes that:

- print the exact received argv and stdin as bounded JSONL;
- emit two events and exit zero;
- emit malformed JSON;
- emit an oversized line;
- write a fake secret to stderr;
- hang and spawn a descendant.

The success contract:

```rust
let workspace = ExecutionWorkspace::open(&layout.workspace)?;
let mut child = JsonlEventProcess::spawn_in_home(
    specification,
    &trusted_executable,
    &provider_home,
    &workspace,
    b"private task bytes",
    short_limits(),
)
.await?;

assert_eq!(child.next_event().await?, json!({"type":"turn.started"}));
assert_eq!(child.next_event().await?, json!({"type":"turn.completed"}));
assert_eq!(child.wait().await?, JsonlProcessOutcome::Succeeded);
assert_eq!(child.stderr_snapshot(), "<redacted sidecar stderr>");
```

Test natural-exit draining, non-zero exit, cancellation, timeout, descendant cleanup,
workspace replacement before spawn, provider-home/workspace mismatch, malformed JSON,
oversized stdout, closed stdin after the one payload, and absence of parent secret
environment variables.

- [ ] **Step 2: Run lifecycle tests and verify failure**

Run:

```bash
cargo test --test codex_exec_contract process
```

Expected: compilation fails because `ExecutionWorkspace` and `JsonlEventProcess` do not
exist.

- [ ] **Step 3: Implement `ExecutionWorkspace`**

`ExecutionWorkspace::open` must:

- require an absolute existing directory;
- reject a symlink or reparse point;
- canonicalize once;
- retain an open directory handle and platform identity;
- revalidate the named path against the retained identity before spawn;
- expose no public ambient path getter.

Add a crate-private method that configures only `Command::current_dir` after
revalidation. Require it to match the workspace identity used when preparing the
`ProviderHome`.

- [ ] **Step 4: Implement `JsonlEventProcess`**

Reuse the existing:

- trusted executable revalidation;
- version probe;
- closed provider environment;
- Unix process group or Windows Job Object;
- bounded stdout-line reader;
- bounded redacted stderr capture;
- forced termination and reaping deadlines.

Unlike `JsonlSidecar`, the new primitive:

- writes exactly one bounded stdin payload and closes stdin;
- accepts any JSON object, not only JSON-RPC responses or notifications;
- preserves event order;
- drains complete stdout lines after natural leader exit;
- reports a typed zero, non-zero, cancelled, timed-out, or protocol-failed outcome;
- exposes no request-writing method after spawn.

- [ ] **Step 5: Run process and existing sidecar tests**

Run:

```bash
cargo test --test codex_exec_contract process
cargo test --test sidecar_contract
```

Expected: all pass with no orphaned fixture processes.

- [ ] **Step 6: Commit**

```bash
git add src/sidecar tests/codex_exec_contract.rs tests/support/sidecar.rs
git commit -m "feat: supervise one-way JSONL workers"
```

---

### Task 4: Compose the subscription-backed Codex adapter

**Files:**

- Modify: `src/delegates/codex/mod.rs`
- Modify: `src/delegates/codex/events.rs`
- Modify: `src/delegates/mod.rs`
- Extend: `tests/codex_exec_contract.rs`
- Modify: `docs/adr/0004-subscription-authentication-through-provider-sidecars.md`
- Modify: `docs/architecture.md`
- Modify: `CHANGELOG.md`

**Interfaces:**

- Consumes: `ResolvedDelegateSettings`, `ExecutionWorkspace`, `ProviderHome`, `TrustedExecutable`, `SidecarLimits`, and `CodexEventNormalizer`.
- Produces: `CodexExecAdapter::new`, `CodexExecAdapter::start`, `CodexExecRequest`, `CodexExecRun::next_event`, `CodexExecRun::finish`, and `CodexExecRun::cancel`.
- A later orchestration plan will consume this API after staging and policy produce an authorized execution workspace.

- [ ] **Step 1: Write failing exact-composition tests**

Verify the fake executable receives arguments equivalent to:

```text
--strict-config
--model gpt-5.6
-c model_reasoning_effort="high"
exec
--json
--ephemeral
--sandbox workspace-write
--ask-for-approval never
--skip-git-repo-check
-
```

Order may differ only where Codex documents flags as equivalent. Assert:

- the task exists only on stdin and not in argv;
- unset model or effort emits no override;
- per-run values beat session values;
- no API-key or token environment variable reaches the child;
- the isolated home contains only Carl-controlled configuration;
- the adapter rejects a non-Codex provider home;
- version mismatch occurs before stdin is sent;
- completion requires exactly one terminal normalized event;
- non-zero exit, terminal error, malformed stream, cancellation, and output bounds map
  to stable typed errors;
- `Debug` output contains no task, paths, stderr, or provider payloads.

- [ ] **Step 2: Run adapter tests and verify failure**

Run:

```bash
cargo test --test codex_exec_contract adapter
```

Expected: compilation fails because `CodexExecAdapter` does not exist.

- [ ] **Step 3: Implement the adapter**

Write owner-only Codex configuration:

```toml
cli_auth_credentials_store = "keyring"
approval_policy = "never"
sandbox_mode = "workspace-write"

[sandbox_workspace_write]
network_access = false
```

Use `codex exec -` and write the bounded task plus Carl's delegate constraints to stdin.
The adapter must never include task text in `SidecarCommand.arguments`.

Keep the API library-only:

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegateErrorCode {
    Configuration,
    AuthenticationRequired,
    Incompatible,
    StartFailed,
    ProtocolFailed,
    BudgetExhausted,
    Cancelled,
    ProviderFailed,
}

#[derive(Debug, thiserror::Error)]
#[error("The subscription delegate failed.")]
pub struct DelegateError {
    code: DelegateErrorCode,
    detail: String,
}

pub struct CodexExecRequest {
    pub task: BoundedDelegateTask,
    pub settings: ResolvedDelegateSettings,
}

impl CodexExecAdapter {
    pub async fn start(
        &self,
        workspace: &ExecutionWorkspace,
        request: CodexExecRequest,
    ) -> Result<CodexExecRun, DelegateError>;
}
```

Do not add `carl run`, modify the live workspace, or bypass a missing Phase 3 policy
decision in this task.

- [ ] **Step 4: Update truthful architecture documentation**

Change only future-transport claims:

- Codex execution uses `codex exec --json`, not `codex mcp-server`;
- the first subscription-only path enters through `SubscriptionRunEngine`;
- the adapter is implemented but remains inert until staging and Phase 3 safety
  boundaries are present;
- Grok remains planned and unchanged.

Do not claim that a live OAuth ceremony or coding task has succeeded.

- [ ] **Step 5: Run the full quality gate**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --doc
cargo deny check
git diff --check
```

Expected: every command exits zero.

- [ ] **Step 6: Commit**

```bash
git add src/delegates tests/codex_exec_contract.rs docs/adr/0004-subscription-authentication-through-provider-sidecars.md docs/architecture.md CHANGELOG.md
git commit -m "feat: add subscription-backed Codex exec adapter"
```

---

## Follow-on plans

This plan intentionally stops before user-visible execution. The remaining approved
spec is decomposed into:

1. Phase 3 policy, bound approval, secret filtering, and external-agent capability
   classes.
2. Sanitized staging workspace and inert exact-replacement proposal artifacts.
3. Independent verification and stale-safe promotion.
4. Durable `SubscriptionRunEngine`, session model/effort persistence, `carl run`, and
   deterministic repository-fix evaluation.
5. Grok adapter using the same outer contracts.

Each follow-on must remain independently testable and must not expose a writable
live-workspace path to a subscription delegate.
