# Carl Subscription Delegate Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task by task with a fresh implementer and reviewer for each task.

**Goal:** Make authenticated Codex and Grok agents available as tightly constrained specialist tools inside Carl's native loop.

**Architecture:** `delegate.codex` and `delegate.grok` are networked `external_agent` tools that always pass through Carl policy and bound approval. They receive content-scanned, capability-built staging copies outside the live workspace and may mutate only those copies. Their only durable output is a report plus inert exact-replacement proposals. Applying each proposal is a separate native `fs.apply_patch` lifecycle with its own preview, approval, stale-state check, and verification.

**Prerequisite:** Do not begin this plan until Phase 3 policy, approvals, sandboxing, secret filtering, and external-agent capability classes are merged and green.

**Tech Stack:** Rust 2024, Carl's tool/policy/sandbox contracts, `cap-std`, bounded MCP and ACP clients, Tokio sidecars, SHA-256 artifacts, and deterministic fake provider processes.

## Global constraints

- Follow ADR 0003 and ADR 0004.
- Delegates are tools, never top-level engines or native `Provider` implementations.
- A delegate never receives an ambient path or handle for the live workspace.
- A delegate never loads project provider configuration, hooks, plugins, skills,
  commands, MCP servers, environment files, credentials, or VCS metadata.
- Sidecars run only in Carl's OS sandbox with a Carl-written configuration.
- Sidecar tool-process network is denied; only the sidecar's provider transport may
  reach an allowlisted provider origin.
- The normal event journal records the outer tool lifecycle. Delegate-internal activity
  is labeled untrusted provider evidence and never becomes a native verification event.
- All standard tests use fake sidecars and make no live provider request.

---

## Task 1: Build a sanitized, capability-safe delegate stage

**Files:**

- Create: `src/tools/delegates/mod.rs`
- Create: `src/tools/delegates/staging.rs`
- Modify: `src/tools/mod.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `tests/delegate_stage_contract.rs`

### Step 1: Write failing snapshot tests

`DelegateStage::prepare` creates an owner-only temporary directory outside both the
workspace and provider homes. Through Carl's open workspace capability it copies only
bounded regular UTF-8 source files and records relative path, size, and SHA-256. Raw
platform permission bits are neither copied nor included in the content-addressed
manifest; staged files receive fixed owner-only permissions and live permissions remain
untouched when a replacement is later applied.

Test exclusion of:

- `.git`, `.carl`, `.codex`, `.grok`, `.claude`, `.cursor`, `.mcp.json`, and
  provider-specific instruction/config roots;
- `.env` families, credentials, key material, sockets, devices, FIFOs, binaries,
  symlinks, hard-linked files with unexpected link count, hooks, and plugins;
- files or aggregate snapshots over configured limits.

Run the merged Phase-3 `SecretFilter` on every otherwise eligible file before copying
it. High-confidence credential, private-key, cookie, connection-string, and
token-shaped matches reject the file from the stage with a typed, path-only report;
secret bytes and matched substrings never enter the manifest, journal, preview, or
delegate prompt. Test sentinels embedded in ordinary `.rs`, `.toml`, `.json`, `.yaml`,
and `.yml` files as well as filenames that do not look sensitive.

Test concurrent path replacement, ancestor swapping, staging permission failure,
cleanup, deterministic manifest ordering, and identical path/content manifest hashes
on macOS/Linux/Windows. Every read and write must stay relative to open
`cap_std::fs::Dir` handles.

### Step 2: Write failing artifact tests

After a delegate exits, compare the stage to the immutable manifest without invoking
Git or repository code. Produce a bounded content-addressed artifact containing
independent exact-replacement proposals for existing UTF-8 regular files. Each proposal
must already satisfy the native `fs.apply_patch` schema: relative path, live
`expected_sha256`, and ordered exact old/new text edits. Include before/after and text
payload hashes. V1 rejects creates, deletes, renames, binaries, path escapes, protected
paths, oversized changes, ambiguous file identity, and any edit that cannot be
expressed without fuzzy matching. Prove artifact generation cannot mutate the
workspace.

### Step 3: Implement, verify, and commit

Run full Rust checks, then:

```bash
git add Cargo.toml Cargo.lock src/tools tests/delegate_stage_contract.rs
git commit -m "feat: add sanitized delegate staging"
```

---

## Task 2: Implement the Codex delegate tool

**Files:**

- Create: `src/tools/delegates/codex.rs`
- Modify: `src/tools/delegates/mod.rs`
- Create: `tests/codex_delegate_contract.rs`
- Extend: `tests/support/sidecar.rs`

### Step 1: Write failing tool and MCP tests

Register `delegate.codex` with:

- side-effect class `external_agent`;
- policy default `ask`;
- OpenAI/Codex provider-network capability;
- normalized preview containing prompt hash, model, stage-manifest hash, file/output
  limits, and an explicit `live_workspace_writable: false`.

Spawn version-pinned `codex mcp-server` with the authenticated isolated `CODEX_HOME`.
Test MCP initialize, exact expected `codex`/`codex-reply` schemas, first invocation,
continuation, output bounds, cancellation, malformed messages, child exit, secret
redaction, and unsupported versions.

### Step 2: Enforce sidecar containment

Write only Carl-controlled settings into the isolated Codex home:

```toml
approval_policy = "never"
sandbox_mode = "workspace-write"
cli_auth_credentials_store = "keyring"
```

Launch with cwd set to the stage. Sandbox writes are limited to the stage and
tool-process network is denied. Reject any MCP tool/schema outside the pinned contract.
The tool returns a delegate report and proposed-replacement artifact only.

### Step 3: Verify event and application separation

Assert the native journal contains one normal outer policy/approval/tool lifecycle.
Assert it contains no fabricated native events for Codex-internal shell, edits, tests,
or verification. The artifact itself is never executable. Applying each replacement
requires a later independent `fs.apply_patch` proposal, policy decision, bound
approval, and stale check. Multi-file delegate output therefore produces multiple
native patch lifecycles rather than one falsely atomic operation, and any stale file
fails independently.

Run full checks and commit:

```bash
git add src/tools tests/codex_delegate_contract.rs tests/support/sidecar.rs
git commit -m "feat: add Codex delegate tool"
```

---

## Task 3: Implement the Grok delegate tool

**Files:**

- Create: `src/tools/delegates/grok.rs`
- Modify: `src/tools/delegates/mod.rs`
- Create: `tests/grok_delegate_contract.rs`
- Extend: `tests/support/sidecar.rs`

### Step 1: Write failing tool and ACP tests

Register `delegate.grok` with the same `external_agent`, default-`ask`,
stage-only contract. Spawn:

```text
grok --no-auto-update --cwd <stage> --permission-mode dontAsk \
  --sandbox strict --no-plan --no-subagents --no-memory \
  --disable-web-search --tools Read,Edit,Grep,Glob \
  --allow Read --allow Edit --allow Grep --allow Glob \
  --deny Bash --deny MCPTool --deny WebFetch --deny WebSearch agent stdio
```

Test ACP initialize with no host filesystem/terminal capabilities, `cached_token`
authentication, `session/new` with no MCP servers, `session/prompt`, ordered
agent-message chunks, completion metadata, cancellation, malformed protocol, bounds,
redaction, unsupported versions, and exact allow/deny argv. Prove that merely listing a
tool in `--tools` is not treated as permission.

### Step 2: Prove project configuration cannot load

The stage omits all Grok, Claude, Cursor, AGENTS, MCP, plugin, skill, command, hook, and
environment configuration before Grok starts discovery. The isolated `GROK_HOME`
contains only Carl-written settings disabling compatibility imports, plugins, hooks,
skills, MCP, shell, web search, memory, subagents, and auto-update.

Tests plant executable hooks and sentinel configuration throughout the live workspace
and parent directories. Prove the fake sidecar cannot observe or execute any sentinel.
Before prompting, inspect the effective configuration and fail closed if Grok reports
any user, project, compatibility, managed, or system source outside Carl's isolated
home and staging policy. The Carl-owned OS sandbox denies the sidecar read access to
the live workspace and parent configuration roots. The Grok sandbox writes only to the
stage and denies tool-process network.

### Step 3: Verify and commit

Assert the same event/application separation as Codex, run full checks, then:

```bash
git add src/tools tests/grok_delegate_contract.rs tests/support/sidecar.rs
git commit -m "feat: add Grok delegate tool"
```

---

## Task 4: Evaluate, document, review, PR, and merge

**Files:**

- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/security.md`
- Modify: `CHANGELOG.md`
- Create: `docs/evaluations/subscription-delegates.md`
- Modify: `tests/docs_contract.rs`

### Step 1: Add truthful documentation contracts

Document native-loop ownership, API-key versus subscription billing, sidecar
installation/version requirements, sanitized staging, provider-specific sandboxing,
patch-artifact review, and the difference between delegate-reported and Carl-verified
evidence.

### Step 2: Run release and security gates

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps
cargo deny check
git diff --check
```

Run whole-branch correctness review plus a security review focused on credential
isolation, workspace escape, project-config injection, process-tree cleanup, and
network policy. Fix every material finding and rerun all gates.

### Step 3: PR and merge

Commit docs, push `codex/carl-subscription-delegates`, open a non-draft PR, wait for
Quality/Ubuntu/macOS/Windows CI, merge only when green, pull `main`, and rerun
`cargo test --all-features` on the merge commit.
