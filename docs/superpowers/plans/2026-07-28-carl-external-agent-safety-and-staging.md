# Carl External-Agent Safety and Staging Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the policy, single-use approval, secret-filtering, and capability-built staging foundations required before Carl can expose its subscription-backed Codex adapter.

**Architecture:** A pure policy module hashes normalized external-agent capability requests and always requires exact owner approval for safe requests. A separate security module detects high-confidence secrets without retaining matched bytes. Durable bound approvals consume one exact request digest once, while a capability-oriented stage builder copies only bounded safe UTF-8 files into an owner-only directory outside the live workspace.

**Tech Stack:** Rust 2024, Serde, SHA-256, SQLite WAL migrations, `cap-std`, platform metadata checks, and deterministic contract tests.

## Global Constraints

- Work remains library-only; do not add `carl run` or make the Codex adapter CLI-reachable.
- External-agent requests can never receive a writable live-workspace path or capability.
- Safe external-agent requests default to `ask`; unsafe requests fail closed as `deny`.
- Approvals are exact, expiring, actor/session/turn-bound, and single-use.
- Capability requests, approvals, errors, and manifests contain hashes and path-only diagnostics, never raw prompt or secret bytes.
- Stages are owner-only directories outside the live workspace and provider homes.
- Stage traversal uses held directory capabilities; it never follows symlinks.
- V1 staging accepts only bounded regular UTF-8 files with one link and excludes provider configuration, VCS metadata, hooks, plugins, skills, environment files, and compatibility instructions.
- A high-confidence secret finding rejects the stage; it is not silently copied or merely redacted.
- This plan does not implement proposal inspection, verification execution, promotion, or user-visible orchestration. Those consume the contracts produced here.

---

## File Structure

- `src/policy/mod.rs`: policy exports, decisions, and the closed default evaluator.
- `src/policy/capability.rs`: normalized request types, actor identity, SHA-256 value type, and canonical request hashing.
- `src/security/mod.rs`: security exports.
- `src/security/secret_filter.rs`: high-confidence, non-retaining secret classification.
- `src/staging/mod.rs`: stage API and public manifest/error types.
- `src/staging/builder.rs`: capability-relative traversal, copying, hashing, bounds, and cleanup.
- `migrations/0002_bound_approvals.sql`: separate exact approval table; legacy approvals remain readable.
- `src/storage/schema.rs`: ordered checksum-verified migration ledger through version 2.
- `src/storage/repository.rs`: durable bound-approval creation, resolution, expiration, and atomic consumption.
- `tests/policy_contract.rs`: normalization and default policy behavior.
- `tests/secret_filter_contract.rs`: secret classification and redaction behavior.
- `tests/bound_approval_contract.rs`: migration, binding, expiry, replay, and persistence.
- `tests/delegate_stage_contract.rs`: stage isolation, exclusions, bounds, permissions, and manifest determinism.

---

### Task 1: Normalize and evaluate external-agent capability requests

**Files:**

- Create: `src/policy/mod.rs`
- Create: `src/policy/capability.rs`
- Modify: `src/lib.rs`
- Create: `tests/policy_contract.rs`

**Interfaces:**

- Produces: `Sha256Digest`, `ActorId`, `ActorIdentity`, `Frontend`, `ProviderNetwork`, `EnvironmentGrant`, `CapabilityRequest`, `PolicyDisposition`, `PolicyReasonCode`, `PolicyDecision`, and `DefaultPolicy`.
- Later tasks persist `CapabilityRequest::digest()` and `ActorIdentity::id()` in bound approvals.
- The later run engine constructs an external-agent request after staging and before starting Codex.

- [ ] **Step 1: Write failing public-contract tests**

Write literal expectations proving:

```rust
let request = CapabilityRequest::external_agent(
    "delegate.codex",
    ActorIdentity::new(ActorId::parse("local-owner")?, Frontend::Cli),
    SessionId::from_uuid(uuid!("11111111-1111-4111-8111-111111111111")),
    TurnId::from_uuid(uuid!("22222222-2222-4222-8222-222222222222")),
    Sha256Digest::parse("aaaa...64 hex characters")?,
    Sha256Digest::parse("bbbb...64 hex characters")?,
    Some(ModelId::parse("gpt-5.6")?),
    Some(ReasoningEffort::High),
    ProviderNetwork::OpenAiCodex,
    BTreeSet::new(),
    false,
)?;
```

Assert that two identical requests produce one hand-derived 64-character digest; changing model, effort, actor, frontend, turn, prompt hash, stage hash, network, environment grants, or `live_workspace_writable` changes the digest. Assert serialization contains no task text or ambient filesystem path.

Assert the closed default policy returns:

- `Ask / ExternalAgentRequiresApproval` for the safe request;
- `Deny / LiveWorkspaceExposure` when `live_workspace_writable` is true;
- `Deny / EnvironmentGrantForbidden` when any environment grant is present;
- `Deny / ProviderNetworkMismatch` when `delegate.codex` requests `XaiGrok`;
- the same `Ask` result for CLI, TUI, and Telegram safe requests.

Test bounded validation for actor ID, tool name, SHA-256 syntax, and model values. Test `Debug` output does not contain hashes, actor IDs, paths, or prompt text.

- [ ] **Step 2: Run the policy contract and verify RED**

Run:

```bash
cargo test --test policy_contract
```

Expected: compilation fails because `carl::policy` does not exist.

- [ ] **Step 3: Implement normalized hashing and the closed evaluator**

Implement closed enums with stable snake-case serialization. `Sha256Digest` stores `[u8; 32]`, accepts exactly 64 lowercase hexadecimal characters, serializes as lowercase hex, and has a redacted `Debug`.

`CapabilityRequest` stores only normalized typed fields. Its `digest` hashes the compact Serde JSON encoding of the struct; all collections use `BTreeSet`, all strings pass validating constructors, and no `HashMap` participates in encoding.

`DefaultPolicy::evaluate` applies deny rules before the external-agent ask rule:

```rust
if request.live_workspace_writable() {
    return PolicyDecision::deny(PolicyReasonCode::LiveWorkspaceExposure);
}
if !request.environment_grants().is_empty() {
    return PolicyDecision::deny(PolicyReasonCode::EnvironmentGrantForbidden);
}
if !request.provider_matches_tool() {
    return PolicyDecision::deny(PolicyReasonCode::ProviderNetworkMismatch);
}
PolicyDecision::ask(PolicyReasonCode::ExternalAgentRequiresApproval)
```

Do not add an allow branch for external agents.

- [ ] **Step 4: Run focused and domain tests**

Run:

```bash
cargo test --test policy_contract
cargo test --test domain_contract
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: all pass without warnings.

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs src/policy tests/policy_contract.rs
git commit -m "feat: add external-agent policy contracts"
```

---

### Task 2: Detect secrets without retaining secret bytes

**Files:**

- Create: `src/security/mod.rs`
- Create: `src/security/secret_filter.rs`
- Modify: `src/lib.rs`
- Create: `tests/secret_filter_contract.rs`

**Interfaces:**

- Produces: `SecretFilter`, `SecretRule`, and `SecretFinding`.
- `SecretFilter::inspect(&[u8]) -> Result<(), SecretFinding>` never returns matched text, offsets, line contents, or input bytes.
- Task 4 maps a finding to a stage error containing only relative path plus `SecretRule`.

- [ ] **Step 1: Write failing classification and non-retention tests**

Use sentinels in ordinary `.rs`, `.toml`, `.json`, `.yaml`, and `.yml`-style contents. Assert detection of:

- PEM private-key headers;
- OpenAI-style `sk-` tokens, GitHub `ghp_` and `github_pat_` tokens, Slack `xox[baprs]-` tokens, and AWS `AKIA` access-key IDs with required minimum lengths;
- quoted non-placeholder assignments whose normalized key contains `api_key`, `token`, `secret`, `password`, or `cookie`;
- connection strings with non-empty credentials before `@`.

Assert common source text, UUIDs, SHA-256 hashes, environment-variable references, `"example"`, `"placeholder"`, `"changeme"`, and empty assignments are accepted.

For every finding, assert:

```rust
assert_eq!(finding.rule(), SecretRule::ProviderToken);
assert!(!format!("{finding:?}").contains(SECRET_SENTINEL));
assert!(!finding.to_string().contains(SECRET_SENTINEL));
```

The production change these tests catch is returning or formatting matched secret bytes.

- [ ] **Step 2: Run the secret-filter contract and verify RED**

Run:

```bash
cargo test --test secret_filter_contract
```

Expected: compilation fails because `carl::security` does not exist.

- [ ] **Step 3: Implement the bounded classifier**

Reject inputs above 1 MiB before scanning. Decode UTF-8; non-UTF-8 returns `SecretRule::NonUtf8` without retaining bytes. Scan bounded lines with ASCII case normalization and explicit prefix/length checks. For assignment and connection-string rules, classify only non-placeholder quoted values.

`SecretFinding` contains only `SecretRule`; implement redacted `Debug`, a static `Display`, and `std::error::Error`.

- [ ] **Step 4: Run focused tests and lint**

Run:

```bash
cargo test --test secret_filter_contract
cargo test --test domain_contract
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/lib.rs src/security tests/secret_filter_contract.rs
git commit -m "feat: add non-retaining secret filter"
```

---

### Task 3: Persist exact, expiring, single-use approvals

**Files:**

- Create: `migrations/0002_bound_approvals.sql`
- Modify: `src/storage/schema.rs`
- Modify: `src/storage/repository.rs`
- Modify: `src/storage/mod.rs`
- Modify: `tests/storage_contract.rs`
- Create: `tests/bound_approval_contract.rs`

**Interfaces:**

- Consumes: `Sha256Digest`, `ActorId`, `SessionId`, `TurnId`, `ToolCallId`, and `ApprovalId`.
- Produces: `BoundApprovalBinding`, `BoundApprovalRecord`, `ConsumedApproval`, `Store::create_bound_approval`, `Store::resolve_bound_approval`, `Store::get_bound_approval`, and `Store::consume_bound_approval`.
- A later run engine may start an external agent only after `consume_bound_approval` succeeds for the exact current request.

- [ ] **Step 1: Write failing migration and approval tests**

Update storage migration expectations from one migration to two. Change the future-migration fixture from version 2 to version 3 and assert both stored checksums are 64 lowercase hex characters.

Add tests with fixed timestamps:

```rust
let created_at = Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap();
let expires_at = created_at + TimeDelta::minutes(5);
let binding = BoundApprovalBinding::new(
    session.id,
    turn_id,
    tool_call_id,
    ActorId::parse("local-owner")?,
    request.digest(),
    created_at,
    expires_at,
)?;
```

Assert:

- a pending record survives reopen;
- only pending can resolve to allowed, denied, or expired;
- allowed consumes once when digest, actor, session, turn, tool call, and current time match;
- replay fails without modifying `consumed_at`;
- changed digest, actor, session, turn, or tool call fails;
- expired and denied approvals never consume;
- expiry must be after creation and no more than 15 minutes later;
- `Debug` output does not reveal actor IDs or request digests.

- [ ] **Step 2: Run storage contracts and verify RED**

Run:

```bash
cargo test --test bound_approval_contract
cargo test --test storage_contract
```

Expected: the new contract fails to compile and the updated migration assertions fail.

- [ ] **Step 3: Add checksum-verified migration 2**

Create `bound_approvals` without weakening the legacy `approvals` table:

```sql
CREATE TABLE bound_approvals (
    id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    turn_id TEXT NOT NULL,
    tool_call_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    summary TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'allowed', 'denied', 'expired')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    resolved_at TEXT,
    consumed_at TEXT
);

CREATE INDEX bound_approvals_by_session_status
    ON bound_approvals(session_id, status, created_at);
```

Refactor `schema::migrate` around an ordered two-element migration table. Validate every applied name/checksum, reject gaps or extra rows, and apply missing migrations in order inside the existing immediate transaction.

- [ ] **Step 4: Implement atomic approval consumption**

`consume_bound_approval(binding, approval_id, now)` uses an immediate transaction. Read the row, compare every binding field, reject non-allowed, expired, mismatched, or previously consumed records, then execute:

```sql
UPDATE bound_approvals
SET consumed_at = ?2
WHERE id = ?1
  AND status = 'allowed'
  AND consumed_at IS NULL
  AND expires_at > ?2
```

Require exactly one changed row and commit before returning `ConsumedApproval`. A mismatch returns sanitized `CarlError::Policy`; storage failures remain `CarlError::Storage`.

- [ ] **Step 5: Run focused and storage tests**

Run:

```bash
cargo test --test bound_approval_contract
cargo test --test storage_contract
cargo test --test domain_contract
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add migrations src/storage tests/storage_contract.rs tests/bound_approval_contract.rs
git commit -m "feat: bind durable approvals to exact requests"
```

---

### Task 4: Build sanitized capability-safe staging directories

**Files:**

- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `src/staging/mod.rs`
- Create: `src/staging/builder.rs`
- Modify: `src/lib.rs`
- Create: `tests/delegate_stage_contract.rs`

**Interfaces:**

- Consumes: `SecretFilter` and `Sha256Digest`.
- Produces: `StageLimits`, `StageEntry`, `StageExclusionReason`, `ExcludedStageEntry`, `StageManifest`, `StageErrorCode`, `StageError`, `SanitizedStageBuilder`, and `SanitizedStage`.
- `SanitizedStage::execution_workspace()` produces the stage-only `ExecutionWorkspace` capability consumed by `CodexExecAdapter::start`.
- Proposal inspection later consumes the immutable `StageManifest`.

- [ ] **Step 1: Write failing stage-isolation tests**

Create real temporary source and stage-parent sibling directories. Test that `prepare`:

- rejects a relative source/stage parent and a stage parent inside the source;
- creates a unique owner-only directory under the stage parent;
- copies ordinary bounded UTF-8 files with fixed owner-only permissions;
- keeps source permissions unchanged;
- returns manifest entries sorted by normalized slash-separated relative path;
- produces the same manifest digest for the same paths/content created in different orders;
- records byte count and SHA-256 for each copied file;
- exposes an `ExecutionWorkspace` for the stage, never for the live source;
- removes the created stage directory on `SanitizedStage` drop.

The test must compare the manifest digest to a literal digest computed independently from the documented length-prefixed format:

```text
u32(path_bytes.len) || path_bytes || u64(file_bytes) || 32 raw content-hash bytes
```

- [ ] **Step 2: Write failing exclusion, secret, and bound tests**

Plant:

- `.git`, `.carl`, `.codex`, `.grok`, `.claude`, `.cursor`, `.mcp.json`;
- `.env`, `.env.local`, key/certificate names, hooks, plugins, skills, commands;
- `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, and Copilot instructions;
- a symlink, a FIFO on Unix, a hard-linked regular file, binary bytes, and a socket where supported.

Assert these never appear in the stage or manifest and receive stable path-only exclusion reasons. Plant a high-confidence token inside an ordinary `src/config.rs`; assert the entire stage fails with `SecretDetected`, reports only `src/config.rs` plus `SecretRule`, and leaves no stage directory.

Test exact file-count, per-file-byte, and aggregate-byte boundaries, including the first byte/file beyond each limit.

- [ ] **Step 3: Run the stage contract and verify RED**

Run:

```bash
cargo test --test delegate_stage_contract
```

Expected: compilation fails because `carl::staging` does not exist.

- [ ] **Step 4: Add and review the capability dependency**

Add:

```toml
cap-std = "3.4"
```

Use `cap_std::fs::Dir` for traversal and stage writes. Ambient authority is permitted only in `SanitizedStageBuilder::open` to acquire the two initial directory capabilities after absolute-path, canonical-disjointness, directory, symlink/reparse, and owner-safety checks.

- [ ] **Step 5: Implement traversal and deterministic manifests**

Walk through child `Dir` capabilities. For each entry:

1. validate one normal UTF-8 name;
2. evaluate protected path/name rules before opening content;
3. use symlink metadata and reject non-regular types;
4. reject regular files whose link count is not one;
5. open without following symlinks, re-read metadata from the handle, and require identity/type/size consistency;
6. read at most `max_file_bytes + 1`;
7. require UTF-8 and run `SecretFilter`;
8. write with create-new semantics under the held stage capability;
9. set fixed owner-only permissions where supported;
10. append the sorted manifest entry and enforce aggregate limits.

On any hard error, remove the partially created stage through the held stage-parent capability. `StageError` stores only code, optional normalized path, and optional `SecretRule`; its `Debug` and `Display` never contain ambient paths or content.

- [ ] **Step 6: Run focused and cross-domain tests**

Run:

```bash
cargo test --test delegate_stage_contract
cargo test --test secret_filter_contract
cargo test --test policy_contract
cargo test --test sidecar_contract
cargo clippy --all-targets --all-features -- -D warnings
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/staging tests/delegate_stage_contract.rs
git commit -m "feat: add sanitized delegate staging"
```

---

### Task 5: Document and verify the inert safety foundation

**Files:**

- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/security.md`
- Modify: `CHANGELOG.md`
- Modify: `tests/docs_contract.rs`

**Interfaces:**

- Documents that policy, approvals, secret filtering, and staging exist as library boundaries.
- Continues to state that `carl run`, proposal inspection, independent verification, and promotion are unavailable.

- [ ] **Step 1: Update truthful public documentation**

Add the implemented modules and their guarantees. State that:

- external-agent policy defaults to exact approval and denies live-workspace exposure;
- approvals are expiring, actor/session/turn/request-bound, and single-use;
- stage construction is owner-only, bounded, capability-relative, and secret-filtered;
- no subscription coding task is CLI-reachable yet;
- no proposal has been verified or promoted by this slice.

Update documentation contract assertions to enforce those boundaries rather than source wording.

- [ ] **Step 2: Run the full quality gate**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --locked
cargo test --doc --locked
cargo deny check
git diff --check
```

Expected: every command exits zero. `cargo deny` may retain the already-reviewed duplicate `hashbrown` warning but no deny-level finding.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/architecture.md docs/security.md CHANGELOG.md tests/docs_contract.rs
git commit -m "docs: describe external-agent safety foundation"
```

---

## Follow-On Plans

The next independently reviewable plan will add:

1. immutable exact-replacement proposal artifacts for existing UTF-8 files;
2. an independently configured, bounded verification runner against the stage;
3. promotion approvals bound to proposal and verification digests;
4. stale-safe, one-file-at-a-time atomic exact replacement through live workspace capabilities;
5. the durable `SubscriptionRunEngine` and `carl run` orchestration only after all prior boundaries pass.
