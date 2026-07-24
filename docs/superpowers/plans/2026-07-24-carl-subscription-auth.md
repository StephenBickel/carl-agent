# Carl Subscription Authentication Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` to implement this plan task by task with a fresh implementer and reviewer for each task.

**Goal:** Let Carl users securely establish and inspect eligible ChatGPT and Grok subscription sessions without exposing provider credentials.

**Architecture:** Subscription access uses provider-owned local sidecars, not bearer tokens inside Carl. Codex app-server owns ChatGPT login and Grok Build owns xAI login. Carl launches both with isolated provider homes, reports only non-secret auth status, and never receives tokens. Actual Codex/Grok delegate tools follow later, after Phase 3, under `2026-07-24-carl-subscription-delegates.md`.

**Tech Stack:** Rust 2024, Tokio process I/O, `process-wrap` 9.1.0, bounded
JSONL/JSON-RPC, serde, semver, and deterministic custom-harness
current-test-executable sidecar fixtures.

## Global constraints

- Follow ADR 0003 and ADR 0004.
- Never read `~/.codex`, `~/.grok`, or another application's auth cache.
- Never receive, parse, log, serialize, or forward provider access/refresh tokens.
- Never copy Codex, Grok CLI, OpenCode, or Kilo OAuth client identities.
- Set a dedicated `CODEX_HOME` or `GROK_HOME` for every sidecar process.
- Use local child-process stdio for Carl's control protocols. Carl never opens a
  sidecar control listener. A provider-owned browser ceremony may open its own
  short-lived loopback OAuth callback; offer device code when that is unsuitable.
- Do not silently download, install, or update provider executables.
- Pin and test supported provider executable/protocol versions; fail closed outside the supported range.
- Keep every standard test offline by substituting deterministic fake sidecar executables.
- This plan exposes authentication only. It does not run a model, agent, tool, or
  delegate against a workspace.

---

## Task 1: Add subscription authentication domain contracts

**Files:**

- Create: `src/auth/mod.rs`
- Modify: `src/lib.rs`
- Modify: `src/error.rs`
- Create: `tests/auth_contract.rs`

### Step 1: Write failing contracts

Test these provider-neutral, non-secret types:

```rust
pub enum SubscriptionService {
    OpenAiCodex,
    XaiGrok,
}

pub enum AuthMethod {
    BrowserOAuth,
    DeviceCode,
    ProviderManaged,
}

pub enum SubscriptionPlan {
    Free,
    Go,
    Plus,
    Pro,
    ProLite,
    Team,
    Business,
    Enterprise,
    Education,
    SuperGrok,
    XPremium,
    XPremiumPlus,
    Unknown,
}

pub enum AuthUnavailableCode {
    ExecutableMissing,
    UnsupportedVersion,
    KeyringUnavailable,
    ProtocolMismatch,
    ProviderRejected,
    TimedOut,
}

pub enum AuthState {
    SignedOut,
    Pending,
    SignedIn {
        method: AuthMethod,
        plan: Option<SubscriptionPlan>,
    },
    Unavailable {
        code: AuthUnavailableCode,
    },
}

pub struct AuthorizationUrl(/* private Url */);
pub struct UserCode(/* private String */);

pub enum LoginChallenge {
    Browser { authorization_url: AuthorizationUrl },
    Device {
        verification_url: AuthorizationUrl,
        user_code: UserCode,
    },
}

pub trait SubscriptionAuthBroker: Send {
    fn service(&self) -> SubscriptionService;
    fn auth_state(&mut self) -> AuthFuture<'_, AuthState>;
    fn start_login(&mut self, method: AuthMethod) -> AuthFuture<'_, LoginChallenge>;
    fn logout(&mut self) -> AuthFuture<'_, ()>;
    fn cancel_login(&mut self) -> AuthFuture<'_, ()>;
}
```

`AuthorizationUrl` and `UserCode` are deliberately revealable only to the foreground
login command. Give both manual redacted `Debug` implementations, do not implement
`Display` or `Serialize`, and require an explicit consuming method to build the
foreground CLI response. `AuthState` uses closed enums rather than arbitrary provider
strings. Map provider errors to static, typed safe codes before they cross the adapter
boundary.

Assert that `AuthState`, errors, ordinary serialization, and debug output cannot contain
account email, OAuth query parameters, bearer token, refresh token, cookie, user code,
or credential-file path fields. Include hostile provider errors containing those
sentinels. Authentication state is queried from the provider-owned sidecar and is not
appended to Carl's session journal.

### Step 2: Implement and verify

Run:

```bash
cargo test --test auth_contract domain -- --nocapture
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
```

Commit:

```bash
git add src/auth src/lib.rs src/error.rs tests/auth_contract.rs
git commit -m "feat: add subscription auth contracts"
```

---

## Task 2: Build isolated provider homes and sidecar supervision

**Files:**

- Create: `src/sidecar/mod.rs`
- Create: `src/sidecar/jsonl.rs`
- Modify: `src/lib.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `tests/sidecar_contract.rs`
- Create: `tests/support/sidecar.rs`

### Step 1: Write failing lifecycle tests

Define:

```rust
pub enum VersionOutputFormat {
    ExactPrefix(&'static str),
    SingleSemverToken,
}

pub struct SidecarCommand {
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub version_arguments: Vec<OsString>,
    pub version_output: VersionOutputFormat,
    pub home_variable: &'static str,
    pub isolated_home: PathBuf,
    pub supported_versions: VersionReq,
}

pub struct JsonlSidecar { /* private child and pipes */ }
```

Test:

- executable discovery returns a typed unavailable state;
- the configured/discovered executable is canonicalized once to a regular file,
  rejected when platform metadata proves the target is broadly writable, and the same
  canonical path is reused for version and sidecar execution;
- exact provider-specific version argv is honored (Codex uses `--version`; Grok uses
  `--no-auto-update version`), bounded output is parsed with a provider-specific
  closed format, and versions outside the pinned range are rejected;
- the supervisor creates an absolute provider home under Carl's data directory with
  owner-only permissions and rejects symlinks or locations inside the workspace;
- the child receives only an allowlisted environment plus its provider-home variable;
- API keys, Telegram tokens, and parent credential variables are absent;
- stdout accepts bounded JSONL only; malformed/oversized lines fail closed;
- stderr is bounded and redacted;
- request IDs correlate out-of-order responses;
- cancellation closes stdin, sends graceful termination, then kills the process tree
  after a deadline;
- child exit wakes every pending request with one typed error.

### Step 2: Implement and verify

Promote Tokio to a production dependency with `process`, `io-util`, `sync`, `time`, and
`rt` features; add `semver`, `libc` on Unix, `libtest-mimic` as a development
dependency, and pin:

```toml
process-wrap = { version = "=9.1.0", default-features = false, features = [
  "tokio1",
  "process-group",
  "job-object",
] }
```

Use `tokio::process::Command` with piped stdio, call
`tokio::process::Command::kill_on_drop(true)` as a leader-only fallback, then spawn it
through `process_wrap::tokio::CommandWrap`.

Process-group ownership is mandatory:

- Unix: wrap with `ProcessGroup::leader()`; close stdin, signal the group with
  `SIGTERM`, poll `try_wait()` until the deadline, call group-aware `start_kill()`, and
  poll again to reap the leader.
- Windows: wrap with `JobObject`; close stdin, poll until the deadline, call
  group-aware `start_kill()` to terminate the Job Object, and poll again to reap the
  leader.

Keep the `Box<dyn process_wrap::tokio::ChildWrapper>` for the sidecar's entire
lifetime inside a Carl-owned `SidecarProcessGuard`; never unwrap and retain only the
leader `tokio::process::Child`. Explicit cancellation performs the graceful sequence
above. The guard's synchronous `Drop` must call the wrapper's group-aware
`start_kill()` directly. The worker must not hold the guard mutex across `.await`, and
must use bounded `try_wait()` polling rather than cancellation-unsafe
`timeout(child.wait())`. When the leader exits, call `start_kill()` before releasing
the wrapper so an ordinary descendant cannot survive it.

Do not enable `process-wrap`'s `kill-on-drop` or `creation-flags` features in 9.1.0.
The open upstream inter-wrapper lookup bug
[`watchexec/process-wrap#35`](https://github.com/watchexec/process-wrap/issues/35)
prevents `JobObject` from observing those wrappers. Carl's direct Tokio fallback and
its own guard are mandatory. Record this pin, the enabled platform code, and the open
upstream issue in dependency review. Prefer a compile-time ownership invariant around
the private guard's `Box<dyn ChildWrapper>` over a brittle source-text assertion, and
add runtime regressions that drop a live supervisor without calling cancel and observe
both the leader and ordinary grandchild exit.

Document the Unix boundary precisely: a hostile descendant that calls `setsid` or
moves to another process group can escape POSIX process-group cleanup. Authentication
sidecars are version-pinned trusted provider binaries, not arbitrary commands.
Post-Phase-3 delegate execution must add OS containment that accounts for detached
descendants; Carl must not claim the pre-Phase-3 process group is a cgroup or equivalent
process-tree primitive.

Make `sidecar_contract` a custom-harness integration test (`harness = false`) driven by
`libtest-mimic`. Its `main` dispatches private fixture arguments before starting the
test runner, so `current_exe()` can provide clean `--version`, strict JSONL stdio, and a
grandchild mode without libtest writing test chatter into stdout. Pass fixture
scenarios through private arguments rather than environment exceptions. This produces
a real cross-platform executable without adding or shipping a production helper
binary. Record fixture PIDs in an isolated-home file, never in protocol stdout. One
scenario must spawn a grandchild and prove explicit cancellation, leader exit, and
drop cleanup each remove both processes.

On Unix, set provider-home directories to mode `0700` and create files with
owner-only modes. On Windows, inherit only from a trusted Carl-owned data root and
verify the resulting DACL does not grant broad access; ordinary Rust read-only flags
are not an owner-only ACL. Reject symlinks and Windows reparse points, including
junctions. Keep creation capability-relative where the platform APIs allow it and
document the remaining trusted-data-root assumption rather than claiming a portable
race-free path CAS.

Version compatibility is not publisher attestation. Surface the canonical executable
path in the foreground doctor/config UI, require explicit trust for nonstandard paths,
and do not imply that a matching version string proves an executable came from the
provider.

Commit:

```bash
git add Cargo.toml Cargo.lock src/sidecar src/lib.rs tests/sidecar_contract.rs tests/support/sidecar.rs
git commit -m "feat: supervise isolated provider sidecars"
```

---

## Task 3: Add Codex-owned ChatGPT subscription login

**Files:**

- Create: `src/auth/codex.rs`
- Modify: `src/auth/mod.rs`
- Modify: `src/sidecar/mod.rs`
- Create: `tests/codex_auth_contract.rs`
- Modify: `tests/sidecar_contract.rs`
- Extend: `tests/support/sidecar.rs`

### Step 1: Write failing JSON-RPC login tests

The adapter must:

1. accept exactly `codex-cli 0.136.0` from a bounded `codex --version` probe;
2. spawn
   `codex app-server --strict-config -c 'cli_auth_credentials_store="keyring"' --listen stdio://`
   with Carl's `CODEX_HOME` and cwd set to that isolated home;
3. send the headerless JSON-RPC `initialize` request, validate the returned
   `codexHome` equals the isolated home without logging either path, then send
   `initialized` with no parameters;
4. call `account/read` with `refreshToken: false`;
5. start `type: "chatgpt"` browser login or `type: "chatgptDeviceCode"`;
6. retain `loginId` only in a private non-serializable redacted wrapper and surface
   only `authUrl`, or `verificationUrl` plus `userCode`; before surfacing, apply a
   Codex-specific URL contract that pins `auth.openai.com` and the expected
   `/oauth/authorize` or `/codex/device` path, rejects duplicate query keys, and
   validates the browser flow's loopback callback shape;
7. treat only `account/login/completed` with the exact non-null pending `loginId` as
   correlated ceremony completion, then confirm the result with bounded
   `account/read` retries;
8. account for Codex 0.136.0 emitting `account/login/completed` before its
   `AuthManager` reload finishes: treat `account/updated` only as an advisory signal
   to retry `account/read` sooner because it has no `loginId`, and never use it by
   itself to complete a login;
9. report a confirmed ChatGPT session with `AuthMethod::ProviderManaged` plus the
   closed mapped plan type, while immediately discarding email and account
   identifiers; browser/device describes the current ceremony, not durable state;
10. support `account/logout` and `account/login/cancel`, reconciling a cancel
    `notFound` race through buffered completion plus `account/read`.

Map only the exact 0.136.0 plan literals. In addition to the direct names, map
`prolite` to `ProLite`, `edu` to `Education`,
`self_serve_business_usage_based` to the Codex-defined team-like `Team`, and
`enterprise_cbp_usage_based` to the Codex-defined business-like `Business`. Reject
unrecognized literals rather than converting arbitrary strings to `Unknown`.

Test success, rejection, timeout, cancellation, incompatible handshake, malformed
notifications, wrong/mixed response IDs, duplicate terminal notifications, advisory
notification reorderings, stale-then-updated account reads, confirmation deadline
expiry, cancel/completion races, and child exit. Assert fixture
sentinels resembling bearer tokens never appear in Carl events or errors. Pin
headerless JSON-RPC and the exact 0.136.0 plan spellings in fixtures; widen the
supported version only after schema-conformance tests are added for another release.
`SignedIn` means authenticated, not that an eligible/usable entitlement has been
proven.

### Step 2: Implement keyring-only isolated auth

Before login, write provider-owned config beneath Carl's isolated `CODEX_HOME`:

```toml
cli_auth_credentials_store = "keyring"
```

Use owner-only permissions and repeat the setting through the higher-precedence
command-line override shown above. Do not use `auto` or `file`, inspect `auth.json`, or
call a broad config-read endpoint. Codex 0.136.0 exposes no structured
keyring-unavailable error; map opaque provider failures to a static
`ProviderRejected` result rather than matching or exposing provider text.

Write this static configuration through the sidecar module's opaque provider-home
capability using no-follow/create-new-or-verified-replace semantics and platform
owner-only permissions. Do not reopen the home through an unchecked ambient path or
duplicate the Unix/Windows filesystem security logic inside the Codex adapter.
Use the sidecar's bounded outbound-notification and nonblocking
`try_next_notification` APIs for initialization and buffered race reconciliation;
never reach into its private pipes.

`CODEX_HOME` isolates filesystem configuration, but OpenAI does not document OS-keyring
entries as namespaced by that path. Do not claim credential/keyring isolation. Warn
that `carl auth logout openai` can affect another Codex CLI or IDE session for the same
OS user. Never fall back to plaintext auth storage.

### Step 3: Verify and commit

Commit:

```bash
git add src/auth src/sidecar tests/codex_auth_contract.rs tests/sidecar_contract.rs tests/support/sidecar.rs
git commit -m "feat: add isolated ChatGPT subscription login"
```

---

## Task 4: Add Grok-owned subscription login

**Files:**

- Create: `src/auth/grok.rs`
- Modify: `src/auth/mod.rs`
- Modify: `src/sidecar/mod.rs`
- Modify: `tests/auth_contract.rs`
- Create: `tests/grok_auth_contract.rs`
- Modify: `tests/sidecar_contract.rs`
- Extend: `tests/support/sidecar.rs`

### Step 1: Write failing login tests

Accept exactly the tested `grok 0.2.111` release from a bounded
`grok --no-auto-update version` probe. The documented output format is not stable, so
require exactly one semver token, reject prereleases/multiple versions/malformed or
oversized output, and cross-check any ACP `agentInfo.version`. Carl invokes
provider-owned commands using its isolated `GROK_HOME`:

```text
grok --no-auto-update login
grok --no-auto-update login --device-auth
grok --no-auto-update logout
grok --no-auto-update agent stdio
```

The login process owns OAuth and token storage. Official Grok Build documentation
provides no JSON or stable machine-output contract for `login`; it may open a browser
and emits human/ANSI terminal text. Carl must therefore run login only as an explicit
foreground command with the provider process attached directly to the user's terminal.
Carl does not capture, parse, redact, relay, serialize, or persist its login output.
Add a fieldless, non-serializable `LoginChallenge::ProviderManaged` result to represent
this terminal-owned ceremony. Reject login when no foreground terminal can be attached;
Telegram and other remote channels may query status but cannot initiate Grok login in
V1. The `SubscriptionAuthBroker` contract is deliberately sequential: dropping the
in-flight foreground login future is its cancellation boundary. Its cancellation guard
must synchronously start group/job termination while the broker retains the supervised
process handle; callers then invoke `cancel_login` to boundedly reap the leader and
reconcile status. Do not claim that Rust `Future::drop` can asynchronously reap a
process before returning. Test success, decline, timeout, future-drop cancellation,
bounded reconciliation, terminal absence, and process cleanup with a fake binary.

Use `grok --no-auto-update agent stdio` only to perform a local
`initialize`/authenticate handshake against the isolated `GROK_HOME`; ACP has no
status method. Do not send `initialized`, create a session, or send a prompt.
Advertising `cached_token` means only that the method is supported. Carl must call
`authenticate` with:

```json
{"methodId":"cached_token","_meta":{"headless":true}}
```

Report signed in only when that request returns a success object containing no fields
other than an optional bounded `_meta` object. The ACP documentation does not promise
a literally empty authenticate result, while the pinned 0.2.111 artifact exposes an
optional response metadata field. Absence of the method or JSON-RPC
authentication-required error `-32000` means signed out;
malformed/duplicate methods, wrong IDs or protocol versions, mixed result/error,
unsupported requests, and protocol errors fail closed as `ProtocolMismatch`. Other
well-formed provider failures map to `ProviderRejected` without inspecting message
text.

Before any Grok process starts, atomically write this Carl-owned policy to the isolated
`$GROK_HOME/requirements.toml` through the same no-follow, owner-only provider-home
capability used for Codex configuration:

```toml
[cli]
auto_update = false

[grok_com_config]
disable_api_key_auth = true
```

The pinned 0.2.111 implementation can otherwise fall through from a missing or expired
`cached_token` to another configured authentication source. In subscription mode,
require that `xai.api_key` is not advertised and reject the handshake if it appears;
clearing `XAI_API_KEY` alone is insufficient. Root-owned
`/etc/grok/requirements.toml` remains the explicit trusted administrator policy
boundary.

Test:

- newline-delimited JSON-RPC 2.0 `initialize` uses `protocolVersion: 1` and declares
  both filesystem read/write and terminal capabilities as `false`;
- auth-method parsing followed by a successful `cached_token` authenticate request;
- `cached_token` advertised but rejected, expired, or malformed;
- no `session/*`, prompt, filesystem, or terminal request is ever sent;
- cancellation and child cleanup;
- exact `--no-auto-update` argv for version, browser login, device login, logout,
  status, and
  every later delegate process.

Every Grok process runs with `GROK_HOME`, a synthetic generic `HOME`/`USERPROFILE`, and
cwd set to the isolated provider home, not the user's workspace. Set
`GROK_DISABLE_AUTOUPDATER=1` in addition to the argv flag. Clear the parent environment,
do not inherit `BROWSER`, and reject parent provider tokens, OAuth overrides, and
custom inference base URLs in subscription mode. Root-owned `/etc/grok` enterprise
policy is an explicitly trusted administrator boundary and may still be discovered;
Carl does not claim `GROK_HOME` suppresses it or parse `grok inspect --json`.

Grok Build stores provider-managed bearer credentials in `$GROK_HOME/auth.json`, not a
documented OS keychain. Carl must never open or deserialize that file. After successful
login, inspect metadata only: require a regular, non-symlink/non-reparse, single-link
file with owner-only permissions (`0600` on Unix and a non-broad DACL on Windows) under
the owner-only provider home. Perform the same metadata preflight before launching any
auth-bearing Grok process. If the path is a symlink, reparse point, hard link, or has
unsafe ownership/permissions, fail closed without invoking Grok: provider-owned logout
could otherwise follow or mutate an attacker-selected target. Status means
authenticated only; it does not prove subscription
eligibility or model entitlement, so return `AuthMethod::ProviderManaged` and
`plan: None`. Serialize login, logout, and ACP status probes because status may refresh
the provider credential file. After both login and logout, run the ACP probe and trust
that result rather than CLI exit status or human text.

Canonicalize the configured executable and reuse that exact regular file for version,
login, logout, and ACP. Reject writable/untrusted targets where the platform can
establish that fact, but document that version matching alone is compatibility
checking, not publisher attestation. Updating beyond 0.2.111 requires an explicit Carl
compatibility release; Carl never runs Grok's updater.

Commit:

```bash
git add src/auth tests/grok_auth_contract.rs tests/support/sidecar.rs
git commit -m "feat: add isolated Grok subscription login"
```

---

## Task 5: Add authentication commands, document, review, and merge

**Files:**

- Modify: `src/cli.rs`
- Modify: `src/main.rs`
- Create: `tests/auth_cli_contract.rs`
- Modify: `docs/configuration.md`
- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/security.md`
- Modify: `CHANGELOG.md`
- Modify: `tests/docs_contract.rs`

### Step 1: Write failing CLI tests

Add:

```text
carl auth status
carl auth login openai
carl auth login openai --device
carl auth logout openai
carl auth login grok
carl auth login grok --device
carl auth logout grok
```

`status` performs provider-owned local handshakes and does not initiate login or model
inference. Login is the only command allowed to open a browser or show a device code.
JSON output contains service, availability, method, plan label, and safe error code; it
never contains account identity, paths to credential files, or tokens.

### Step 2: Implement and verify

Keep the autonomous chat/run command disabled until Phase 3. Auth commands only manage
provider-owned login state.

Public docs must distinguish API-key billing from subscription access, Codex-owned from
Grok-owned OAuth, installed executable/version requirements, isolated homes, credential
ownership, and authentication from model execution. State that delegate tools remain
unimplemented until the Phase 3 safety foundation exists.

### Step 3: Run the full gate

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo doc --no-deps
cargo deny check
git diff --check
```

Run the whole-branch security and correctness review. Fix every material finding and
re-run the gate.

### Step 4: Commit, PR, and merge

```bash
git add src/cli.rs src/main.rs tests/auth_cli_contract.rs README.md CHANGELOG.md docs tests/docs_contract.rs
git commit -m "feat: add subscription authentication"
```

Push `codex/carl-subscription-auth`, open a non-draft PR, wait for
Quality/Ubuntu/macOS/Windows CI, merge only when green, pull `main`, and rerun
`cargo test --all-features` on the merge commit.
