# Carl

Carl is Stephen Bickel's personal, local-first Rust coding agent and an open-source agent harness built around a deterministic core, replayable events, explicit policy boundaries, and interchangeable model providers.

Carl's personality and operating principles are part of the repository; see the
[public operating contract](CARL.md). The name is personal rather than an acronym:
Carl is Stephen's middle name and his grandfather's name.

## Terminal and Telegram workflow

The intended v1 experience is one continuous session across a local terminal UI and an owner-only Telegram bot: begin a task at the workstation, inspect or approve proposed actions locally, then resume the same persisted session from a paired private chat. This is a **design preview, not captured output or a runnable demo**; neither frontend is implemented yet.

## Status: pre-alpha foundation

> [!WARNING]
> Carl is currently a **pre-alpha foundation** and is not yet a usable end-user agent. The authentication and local memory command surfaces, an inert library-level Codex exec adapter, sealed staging, exact proposal inspection, and independent bounded verification are implemented, but the HTTP/OpenAI adapters, runtime tool loop, user-reachable subscription execution, stale-safe promotion, built-in workspace tools, TUI interaction, and Telegram gateway are not implemented. Only the four placeholder commands `serve`, `pair`, `doctor`, and `sessions` return not-implemented errors; Clap's built-in `help` command displays help.

Authentication and adapter code do not enable a live coding task. The auth and Codex
exec boundaries are tested with offline provider fakes; this repository does not
claim that a live OAuth ceremony or subscription-backed coding task has succeeded.

The repository is being developed in public so the storage, event, provider, and policy boundaries can be reviewed before consequential tool execution exists.

## Features

Implemented and covered by deterministic tests:

- versioned, provider-neutral events plus stable IDs and typed, sanitized errors;
- hard turn-budget accounting primitives;
- SQLite WAL storage with checksum-verified forward migrations;
- append-only session events and durable session and approval lifecycles;
- curated local profile, preference, fact, goal, and expiring episode memory with
  scoped isolation, bounded explainable lexical retrieval, proposal approval,
  secret/injection rejection, versioned export, hard deletion, and no external
  dependency;
- a provider trait and deterministic scripted provider for offline contract tests;
- supervised, isolated provider sidecars for provider-owned authentication;
- a deterministic JSON authentication CLI for status, login, and logout;
- layered Codex model/reasoning settings plus an inert, version-pinned
  `codex exec --json` adapter with bounded normalized events;
- normalized external-agent policy that makes safe external-agent requests default to
  exact owner approval and denies writable live-workspace access, environment grants,
  and provider-network mismatch;
- expiring actor/session/turn/request-bound approvals that are atomically single-use,
  plus non-retaining high-confidence secret detection;
- deterministic, bounded, owner-only, capability-relative, secret-filtered staging
  copies that exclude credentials, provider configuration, VCS metadata, links,
  special files, hooks, plugins, skills, and compatibility instructions;
- private, quota-bounded content-addressed baseline/proposal storage with sealed
  source identity, startup reachability cleanup, plus process-free inspection that
  accepts only no changes or one exact existing UTF-8 file replacement;
- fresh, independently reconstructed verification candidates; approved executable
  and literal-argv attestation; credential-free bounded process-tree supervision;
  sanitized durable results; and post-commit-only verified-proposal capabilities;
- a Clap command/help shell for the remaining planned top-level interface.

The approved v1 design adds a shared runtime loop, OpenAI and OpenAI-compatible HTTP adapters, bounded workspace tools, a TUI, memory-integrated model context, and an owner-only Telegram gateway. These are roadmap items, not current capabilities.

No subscription coding task is CLI-reachable. The implemented safety modules are
library boundaries only; stale-safe promotion and run-engine orchestration remain
unavailable.

## Quick start

The project currently requires the Rust toolchain declared in `rust-toolchain.toml`. Build the foundation, run its tests, and inspect the only supported CLI behavior:

```sh
cargo build --locked
cargo test --all-features --locked
cargo run --locked -- --help
```

If the binary is already on `PATH`, the equivalent help command is:

```sh
carl --help
```

Do not rely on `serve`, `pair`, `doctor`, or `sessions` yet; they are placeholders.

## Local memory

Memory is enabled by default, stored only in Carl's SQLite database, and usable without
an embedding model, network call, account, or paid service. Capture is explicit rather
than ambient: the CLI records direct owner requests, while the library stores agent
suggestions only as short-lived proposals that cannot be retrieved before approval.

```sh
carl memory status
carl memory remember --kind preference --key response-style --content=concise-verified-answers
carl memory search verification
carl memory proposals
carl memory approve 00000000-0000-4000-8000-000000000000
carl memory export
carl memory settings --disable
```

Retrieval is locally ranked, scope-isolated, byte/item bounded, and explains why each
record was selected. `forget` and confirmed `clear` hard-delete live memory content;
exports, backups, snapshots, and already-issued provider requests remain separate
copies. The model turn loop is not implemented, so live model prompts do not yet
consume this memory. See the [memory guide](docs/memory.md) and
[memory ADR](docs/adr/0005-local-curated-memory.md).

## Subscription authentication

Carl can ask separately installed provider executables to authenticate consumer
subscriptions. The exact supported commands are:

```sh
carl auth status
carl auth login openai
carl auth login openai --device
carl auth logout openai
carl auth login grok
carl auth login grok --device
carl auth logout grok
```

These commands require Codex CLI `0.136.0` and Grok Build `0.2.111`. Carl never
installs or updates provider executables. `carl auth status` performs only local
provider-owned authentication handshakes. Login and logout are local,
foreground-only mutations; safe deterministic JSON goes to stdout while challenges,
warnings, and provider terminal output stay on the verified local stderr terminal.

The implemented auth configuration is deliberately narrow:

- `CARL_DATA_DIR` is an absolute, pre-existing trusted data directory;
- `CARL_CODEX_EXECUTABLE` optionally selects an absolute Codex executable instead of
  the default `codex` command;
- `CARL_GROK_EXECUTABLE` optionally selects an absolute Grok executable instead of the
  default `grok` command.

Provider homes are fixed at `$CARL_DATA_DIR/providers/codex` and
`$CARL_DATA_DIR/providers/grok`; there is no arbitrary home override. Codex owns its
credentials in the operating-system keyring, while Grok owns
`$GROK_HOME/auth.json`. Carl supervises the provider processes and inspects only safe
authentication state, never subscription bearer or refresh tokens. See the
[configuration guide](docs/configuration.md) for the complete boundary.

## Architecture

Both planned frontends feed one provider-neutral event stream and are forbidden from calling providers or tools directly:

```text
TUI (planned) --------+
                      +--> runtime --> provider
Telegram (planned) ---+       |
                              +--> policy --> tools
                              |
                              +--> append-only event log --> projections
```

Today, the event model, storage layer, budget primitives, provider boundary, scripted
adapter, provider-owned authentication sidecars, an inert Codex exec adapter,
external-agent policy, exact approvals, secret filtering, sealed staging, and exact
replacement proposal inspection, and independent bounded verification exist. The
subscription run engine, promotion pipeline, native runtime, production adapters,
and frontends remain planned. See the [architecture guide](docs/architecture.md), the
[approved Carl design](docs/superpowers/specs/2026-07-23-carl-top-tier-harness-design.md),
and the decisions on [event-sourced execution](docs/adr/0001-event-sourced-runtime.md),
a [single-process v1](docs/adr/0002-single-process-v1.md),
[local curated memory](docs/adr/0005-local-curated-memory.md), and
[provider-owned subscription authentication](docs/adr/0004-subscription-authentication-through-provider-sidecars.md).

## Security model

Carl treats model output, remote messages, fetched content, and tool arguments as
untrusted. External-agent requests now have a closed policy, exact durable approvals,
non-retaining secret checks, and isolated sanitized staging. These controls are not a
general runtime policy engine or a process sandbox, and they do not make delegate
execution user-reachable. See the [security model](docs/security.md) and
[security policy](SECURITY.md).

**Shell isolation is policy- and process-based in the v1 design; it is not a complete security sandbox.** A future `shell.exec` tool must not be treated as containment for hostile code, even after its workspace, timeout, environment-filtering, and cancellation controls are implemented.

## Provider access and billing

API-key access and consumer subscription access are separate products and billing
paths. Future native OpenAI and xAI model adapters will require an OpenAI Platform API
key or xAI API key respectively. A ChatGPT, SuperGrok, or eligible X subscription
login through the auth CLI does not become an API key, fund API usage, or give Carl a
raw model-sampling interface.

Carl does not read or reuse subscription credentials. It delegates documented login
to the pinned provider executable and does not call undocumented OAuth endpoints.
Authentication reports provider-owned local state only: it neither proves current
subscription/model entitlement nor enables model execution or delegates. See the
[configuration guide](docs/configuration.md), the
[documented-authentication ADR](docs/adr/0003-no-undocumented-oauth.md), and the
[subscription-sidecar ADR](docs/adr/0004-subscription-authentication-through-provider-sidecars.md).

## Telegram pairing

The Telegram gateway is not implemented. The v1 target uses outbound long polling with no public listener and permits exactly one paired owner in one private chat. Pairing will use a short-lived, one-time code; re-pairing invalidates the previous owner. Group, channel, guest, and unpaired updates will be rejected before model invocation. The planned flow and remote approval rules are documented in the [Telegram guide](docs/telegram.md).

## Development

Start with [CONTRIBUTING.md](CONTRIBUTING.md). The local quality gate is:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --doc
```

Public behavior should be developed test-first with deterministic fixtures; normal tests must not require live model or Telegram credentials. Changes follow the [Code of Conduct](CODE_OF_CONDUCT.md), and notable work is recorded in the [changelog](CHANGELOG.md).

## Roadmap

- [x] Provider-neutral domain contracts, budgets, and durable event storage
- [x] Provider interface and deterministic scripted provider
- [x] Provider-owned subscription authentication CLI and sidecar supervision
- [x] External-agent policy, exact approval, secret-filter, and staging foundations
- [x] Local curated-memory storage, retrieval, migration, settings, and CLI controls
- [ ] Production HTTP/OpenAI-compatible adapters
- [ ] Subscription-backed delegate execution
- [ ] Runtime tool/approval loop, policy engine, and bounded built-in tools
- [ ] Interactive TUI and session operations
- [ ] Owner-only Telegram long-polling gateway
- [ ] Cross-platform CI and checksummed releases

The [approved design](docs/superpowers/specs/2026-07-23-carl-top-tier-harness-design.md) is the source of truth for v1 scope; checkboxes here describe repository state, not release promises.

## License

Carl is available under the [MIT License](LICENSE).
