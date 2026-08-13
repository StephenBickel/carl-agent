# Carl Provider Onboarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a secure first-run flow that lets a user choose OpenAI subscription, OpenAI API, or OpenRouter, stores API keys only in the OS credential vault, and makes TUI `/login`, `/logout`, and `/provider` fully functional.

**Architecture:** Credential bytes live behind a small `CredentialVault` interface implemented with native OS credential services and an in-memory test double; SQLite stores only provider selection and non-secret status. The foreground CLI/TUI owns key entry and writes the OS vault, then sends the persistent service a credential-free refresh signal; the service independently loads the vault entry into an in-memory provider factory. Subscription login continues to be delegated to the Codex executable and never passes a token through Carl.

**Tech Stack:** Rust 2024, Tokio, `keyring` with platform-native credential stores, `zeroize`, crossterm/Ratatui hidden input, existing provider-owned subscription auth, owner-private service protocol, SQLite migrations.

## Global Constraints

- Provider choices are exactly `openai_subscription`, `openai_api`, and `openrouter`.
- OpenAI subscription login remains the existing provider-owned Codex ceremony; Carl never reads its credential file.
- OpenAI API and OpenRouter keys are written only to the current user's native OS credential vault under service `carl-agent` and accounts `openai_api`/`openrouter`.
- Keys never enter argv, environment variables, SQLite, event JSON, logs, error details, terminal scrollback, debug output, crash reports, or Git.
- Key input is local-foreground-only, echo-disabled, bounded to 512 bytes, UTF-8, one line, and immediately zeroized after the vault operation.
- The service endpoint must already pass its current owner/permission verification before a credential mutation is admitted.
- Provider preference is not credential authority; every native provider construction re-reads the vault and fails closed when the key is absent.
- Logout deletes the exact vault entry, drops in-memory clients at a safe boundary, and preserves historical tasks without making them resumable until reauthentication.
- Ordinary tests use an injected in-memory vault and loopback HTTP fixtures; public CI never touches a real keychain or network.

---

### Task 1: Define and test the credential-vault boundary

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `src/auth/vault.rs`
- Modify: `src/auth/mod.rs`
- Test: `tests/credential_vault_contract.rs`

**Interfaces:**
- Consumes: `ProviderKind`, local foreground authorization, and bounded secret bytes.
- Produces: `CredentialVault`, `NativeCredential`, `OsCredentialVault`, `MemoryCredentialVault`, and typed `CredentialVaultErrorCode`.

- [ ] **Step 1: Write vault RED tests**

Assert fixed service/account names, set/get/delete/status behavior, replacement, deletion idempotency, key bounds, zeroization-on-drop, no `Clone`/serde/value-bearing debug output, provider isolation, concurrent access, unavailable/locked/denied/not-found mappings, and injected backend errors containing no input. Test that the OS implementation refuses redirected input or a non-foreground caller before invoking the keyring backend.

- [ ] **Step 2: Observe RED**

Run: `cargo test --locked --test credential_vault_contract`

Expected: compile failure because `auth::vault` is missing.

- [ ] **Step 3: Implement the vault**

Add:

```toml
keyring = { version = "3", default-features = false, features = ["apple-native", "windows-native", "sync-secret-service"] }
```

Use this trait:

```rust
pub trait CredentialVault: Send + Sync {
    fn status(&self, provider: ProviderKind) -> Result<bool, CredentialVaultError>;
    fn load(&self, provider: ProviderKind) -> Result<NativeCredential, CredentialVaultError>;
    fn store(&self, provider: ProviderKind, value: NativeCredential) -> Result<(), CredentialVaultError>;
    fn delete(&self, provider: ProviderKind) -> Result<(), CredentialVaultError>;
}
```

`NativeCredential` wraps `Zeroizing<Vec<u8>>`; it can be moved into provider construction or borrowed only through a closure. Map keyring errors to closed codes without formatting backend messages.

- [ ] **Step 4: Run and commit**

Run:

```bash
cargo test --locked --test credential_vault_contract
cargo test --locked --test auth_contract
cargo clippy --locked --lib -- -D warnings
```

Commit: `feat: add OS credential vault boundary`

---

### Task 2: Persist non-secret provider preferences

**Files:**
- Create: `migrations/0014_provider_preferences.sql`
- Modify: `src/storage/schema.rs`
- Modify: `src/storage/repository.rs`
- Test: `tests/provider_preference_storage_contract.rs`
- Test: `tests/storage_contract.rs`

**Interfaces:**
- Consumes: `ProviderKind`, optional model and effort preference, timestamps, and compare-and-swap revision.
- Produces: `ProviderPreference`, `Store::provider_preference`, and `Store::set_provider_preference`.

- [ ] **Step 1: Write storage RED tests**

Assert one owner preference row, default `openai_subscription`, strict provider values, optional bounded model, valid effort, monotonic revision, atomic CAS, restart durability, migration from every existing schema version, and rejection of columns/JSON containing a secret sentinel. Prove preference reads do not touch task/event/receipt rows.

- [ ] **Step 2: Observe RED**

Run: `cargo test --locked --test provider_preference_storage_contract`

Expected: failure because migration 14 and repository APIs are absent.

- [ ] **Step 3: Implement the projection**

Store provider/model/effort/revision/updated-at as typed columns, not a free-form settings document. The setter validates a model only when a catalog is supplied and never records credential status, account identity, headers, endpoints, or key metadata.

- [ ] **Step 4: Run and commit**

Run:

```bash
cargo test --locked --test provider_preference_storage_contract
cargo test --locked --test storage_contract
cargo test --locked --test task_storage_contract
```

Commit: `feat: persist non-secret provider preference`

---

### Task 3: Add foreground API-key login and logout commands

**Files:**
- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Modify: `src/auth/mod.rs`
- Test: `tests/auth_cli_contract.rs`
- Test: `tests/credential_cli_contract.rs`

**Interfaces:**
- Consumes: stdin/TTY lease, `CredentialVault`, provider status/catalog probe, cancellation, and exact auth subcommands.
- Produces: `carl auth login openai-api`, `carl auth login openrouter`, corresponding logout/status results, and one sanitized JSON output per command.

- [ ] **Step 1: Write CLI RED tests**

Assert exact clap tree, no `--key` flag, redirected input rejection, echo disable/restore on success/error/cancel/panic guard, 512-byte and newline bounds, no secret in stdout/stderr/process argv/environment, vault store only after a successful loopback provider probe, replacement confirmation, logout deletion, and cancellation exit 130. Extend `auth status` with fixed entries for all four current auth surfaces: OpenAI subscription, Grok subscription, OpenAI API, and OpenRouter.

- [ ] **Step 2: Observe RED**

Run: `cargo test --locked --test credential_cli_contract`

Expected: parse failure for the new provider values.

- [ ] **Step 3: Implement foreground capture**

Acquire the existing local terminal lease, print the prompt to stderr, disable echo, read one bounded line directly into `Zeroizing<Vec<u8>>`, restore before all provider/vault work, probe only the provider's catalog endpoint, then store. Return JSON containing provider/method/status only. Subscription auth commands keep their existing implementation.

- [ ] **Step 4: Run and commit**

Run:

```bash
cargo test --locked --test credential_cli_contract
cargo test --locked --test auth_cli_contract
cargo test --locked --test codex_auth_contract
cargo clippy --locked --all-targets -- -D warnings
```

Commit: `feat: add native provider login commands`

---

### Task 4: Add owner-private service credential refresh

**Files:**
- Modify: `src/service/protocol.rs`
- Modify: `src/service/client.rs`
- Modify: `src/service/server.rs`
- Modify: `src/runtime/native_port.rs`
- Test: `tests/service_protocol_contract.rs`
- Test: `tests/service_end_to_end.rs`

**Interfaces:**
- Consumes: vault-backed provider factory, protocol provider identity, and safe-boundary runtime control.
- Produces: protocol v8 `ProviderStatus`, `RefreshProvider`, and `ForgetProvider` commands without transporting raw credentials.

- [ ] **Step 1: Write protocol/service RED tests**

Assert v7 rejection, strict v8 capability, fixed provider status fields, read-only status, idempotent refresh/forget receipts, safe-boundary replacement, queued-task preservation, active tool cancellation behavior, restart loading from the vault, and no credential field accepted anywhere in request JSON. A changed vault key plus refresh must construct exactly one new provider; a missing key must return typed unauthenticated without dropping the working provider.

- [ ] **Step 2: Observe RED**

Run: `cargo test --locked --test service_protocol_contract`

Expected: compile failure for v8 provider control variants.

- [ ] **Step 3: Implement provider lifecycle controls**

The service owns `Arc<dyn CredentialVault>` and provider factories. Refresh loads the credential inside the service process, authenticates/catalogs it, then swaps only after a safe checkpoint. Forget blocks new starts immediately, quiesces the active native task, drops the in-memory provider/credential, and reports when vault deletion still needs the foreground client.

- [ ] **Step 4: Run and commit**

Run:

```bash
cargo test --locked --test service_protocol_contract
cargo test --locked --test service_end_to_end
cargo test --locked --test native_agent_port_contract
```

Commit: `feat: refresh provider credentials safely`

---

### Task 5: Build the first-run TUI wizard and provider commands

**Files:**
- Create: `src/tui/onboarding.rs`
- Modify: `src/tui/terminal.rs`
- Modify: `src/tui/state.rs`
- Modify: `src/tui/render.rs`
- Modify: `src/tui/controller.rs`
- Modify: `src/tui/mod.rs`
- Test: `tests/tui_onboarding_contract.rs`
- Test: `tests/tui_terminal_contract.rs`
- Test: `tests/tui_controller_contract.rs`

**Interfaces:**
- Consumes: provider status/catalogs, hidden input editor, auth command runner, and provider preference store.
- Produces: first-run provider chooser plus functional `/login [provider]`, `/logout [provider]`, and `/provider [provider]` flows.

- [ ] **Step 1: Write TUI RED tests**

Cover zero-config startup, numbered choices, subscription selection, native-key hidden input, back/cancel, resize, Unicode editing without echo, successful and failed validation, replacement confirmation, logout while active, configured-provider list, model list scoped to provider, restart skipping completed setup, and terminal restoration for every exit. Screen snapshots must contain no key bytes, key length, suffix, account, or authorization failure body.

- [ ] **Step 2: Observe RED**

Run: `cargo test --locked --test tui_onboarding_contract`

Expected: compile failure because `tui::onboarding` is absent.

- [ ] **Step 3: Implement the state machine**

Use closed stages:

```rust
pub enum OnboardingStage {
    ChooseProvider,
    SubscriptionLogin,
    EnterApiKey(ProviderKind),
    Validate(ProviderKind),
    ConfirmReplacement(ProviderKind),
    Complete,
}
```

The hidden editor renders a fixed `API key: ••••••••` placeholder independent of key length and exposes its buffer only by moving it into `NativeCredential`. `/login` invokes the same state machine; `/logout` requires exact provider confirmation, calls the foreground vault deletion, then tells the service to forget the provider.

- [ ] **Step 4: Run and commit**

Run:

```bash
cargo test --locked --test tui_onboarding_contract
cargo test --locked --test tui_terminal_contract
cargo test --locked --test tui_controller_contract
cargo test --locked --test tui_render_contract
```

Commit: `feat: add Carl provider onboarding TUI`

---

### Task 6: Prove setup, restart, logout, and secret non-retention

**Files:**
- Create: `tests/provider_onboarding_end_to_end.rs`
- Modify: `tests/docs_contract.rs`
- Modify: `README.md`
- Modify: `docs/configuration.md`
- Modify: `docs/security.md`
- Modify: `docs/superpowers/specs/2026-08-13-carl-native-tui-provider-runtime-design.md`

**Interfaces:**
- Consumes: real binary pseudo-terminal, memory vault injection, loopback providers, service restart, native coding task, and logout.
- Produces: one deterministic acceptance target and exact installation/first-run documentation.

- [ ] **Step 1: Write E2E and docs RED tests**

In one real-process scenario: start unconfigured, choose OpenRouter, enter a sentinel key with echo disabled, validate against loopback, run a tool task, exit/reopen, resume without re-entry, logout, verify the active service forgets it, and prove the next start is unauthenticated. Repeat the selection path for OpenAI subscription without any key input. Recursively scan terminal capture, data root, SQLite, provider homes, logs, process environment snapshots, and crash output for the sentinel and its substrings; all must be absent.

- [ ] **Step 2: Observe RED**

Run:

```bash
cargo test --locked --test provider_onboarding_end_to_end
cargo test --locked --test docs_contract provider_onboarding
```

Expected: failure until the setup flow and docs exist.

- [ ] **Step 3: Finish user documentation**

Document install prerequisites, `carl` first run, subscription versus API billing, OS vault names, logout semantics, supported providers, OpenRouter access to DeepSeek/Qwen/Kimi/Anthropic/Google/xAI tool-capable models, and recovery from unavailable/locked keychains. Do not document environment-key fallback.

- [ ] **Step 4: Run the release gate and commit**

Run:

```bash
cargo test --locked --test credential_vault_contract
cargo test --locked --test provider_preference_storage_contract
cargo test --locked --test credential_cli_contract
cargo test --locked --test tui_onboarding_contract
cargo test --locked --test provider_onboarding_end_to_end
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Commit: `docs: ship secure Carl provider onboarding`

## Completion boundary

This plan is complete when a new user can install Carl, run `carl`, choose OpenAI subscription/OpenAI API/OpenRouter, authenticate through the correct owner, run and resume native coding tasks, switch configured providers, and log out without credential retention outside the OS vault. Direct API adapters for Grok, Anthropic, Google, DeepSeek, Qwen, and Kimi remain out of scope; those vendors are available through OpenRouter only when its catalog advertises the required coding capabilities.
