# Carl

Carl is Stephen Bickel's personal, local-first Rust coding agent and an open-source
agent harness. It is built around a deterministic kernel, durable and replayable
events, explicit permission boundaries, and provider-owned subscription login.
Carl's personality and operating principles are public in the
[public operating contract](CARL.md). The name is Stephen's middle name and his
grandfather's name.

## Status: pre-alpha, usable ACP coding path

Carl now has a usable ACP coding path: `carl acp` runs a real, version-pinned Codex
app-server through an existing ChatGPT subscription and can serve Buzz or another
compatible ACP client over stdio. It supports durable sessions, provider-reported
model and reasoning choices, plan/default/edit/don't-ask/bypass permission modes,
exact single-use approvals, steering, cancellation, diffs, and final publication.
The ACP path is CLI-reachable and covered by process-level offline tests.

Carl also includes curated local profile, preference, fact, goal, and expiring
episode memory with scoped isolation, bounded lexical retrieval, proposal approval,
versioned export, hard deletion, and no external service dependency. Memory is
managed through the implemented `carl memory` command tree.

This remains pre-alpha. TUI interaction, the Telegram gateway, Grok execution,
native HTTP/OpenAI adapters, Carl's native tool loop, stale-safe live-workspace
promotion, and broader consumer packaging are incomplete. The four placeholder
commands `serve`, `pair`, `doctor`, and `sessions` return not-implemented errors;
Clap's built-in `help` command displays help.

Only the four placeholder commands remain unavailable as inert CLI shells; `auth`,
`memory`, and `acp` have implemented behavior.

## Try Carl locally

Carl requires the Rust toolchain in `rust-toolchain.toml`, Codex CLI `0.146.0`, an
absolute pre-existing private data directory, and a local ChatGPT subscription login.

```sh
cargo build --locked --release
mkdir -m 700 "$HOME/.carl"
export CARL_DATA_DIR="$HOME/.carl"
carl auth login openai
carl acp --permission-mode default
```

Use `--model <id>` and `--effort low|medium|high|xhigh|max|ultra` to select values
reported by the active provider. A local operator can explicitly launch unrestricted
execution with `carl acp --dangerously-bypass-permissions`; see the
[Buzz guide](docs/buzz.md) before enabling bypass remotely.

## Use Carl from Buzz

Install the same Carl binary as both `carl` and the `carl-buzz-mcp` argv-zero alias,
install the trusted Buzz CLI, authenticate Codex locally, then use Buzz's custom ACP
harness settings:

```sh
export BUZZ_ACP_AGENT_COMMAND=carl
export BUZZ_ACP_AGENT_ARGS=acp
export BUZZ_ACP_MCP_COMMAND=carl-buzz-mcp
export BUZZ_ACP_AGENTS=1
export BUZZ_ACP_RESPOND_TO=owner-only
export BUZZ_ACP_PERMISSION_MODE=default
```

The exact setup, tested Buzz revision, approval commands, restart behavior, and
credential boundary are in [docs/buzz.md](docs/buzz.md).

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

Carl delegates consumer OAuth ceremonies and credential storage to separately
installed provider executables. It never implements undocumented OAuth or receives
subscription bearer or refresh tokens.

```sh
carl auth status
carl auth login openai
carl auth login openai --device
carl auth logout openai
carl auth login grok
carl auth login grok --device
carl auth logout grok
```

These commands require Codex CLI `0.146.0` and Grok Build `0.2.111`. Carl never
installs or updates provider executables. Login and logout are local, foreground-only
mutations. Codex owns `$CODEX_HOME/auth.json` in explicit `file` mode, and Grok owns
`$GROK_HOME/auth.json`. Carl validates each credential file as a bounded, regular,
non-linked, owner-only file but never opens or reads the file. Authentication state
does not itself prove current subscription or model entitlement.

The supported non-secret executable and data settings are `CARL_DATA_DIR`,
`CARL_CODEX_EXECUTABLE`, `CARL_GROK_EXECUTABLE`, and `CARL_BUZZ_EXECUTABLE`.
Provider homes remain fixed at `$CARL_DATA_DIR/providers/codex` and
`$CARL_DATA_DIR/providers/grok`. See the
[configuration guide](docs/configuration.md).

There is no API-key fallback for `carl acp`: if `OPENAI_API_KEY` is present, startup
fails instead of silently changing billing or authentication. API-key access and
consumer subscription access are separate products and billing paths. A future
native OpenAI adapter would use an OpenAI Platform API key and a future native xAI
adapter would use an xAI API key; a ChatGPT, SuperGrok, or eligible X subscription
does not become either API key.

## Architecture and safety

```text
Buzz / ACP client
       |
       v
  Carl ACP  ---> durable Carl kernel ---> Codex app-server ---> subscription
       |                 |
       |                 +--> exact approvals and permission state
       `--> restricted carl-buzz-mcp publisher ---> originating Buzz thread
```

Implemented foundations include provider-neutral events, SQLite WAL persistence,
versioned migrations, curated local memory, bounded sidecars, and
actor/session/turn/request-bound approvals that are atomically single-use.
External-agent requests default to exact owner approval, and the closed evaluator
denies writable live-workspace access. Capability-relative secret-filtered staging,
content-addressed artifacts, and independent bounded verification also exist as
library boundaries. Stale-safe promotion and run-engine orchestration remain
unavailable outside the ACP execution path. See the [memory ADR](docs/adr/0005-local-curated-memory.md).

The ACP runtime isolates Buzz credentials from Codex and rejects unknown
credential-bearing MCP descriptors. Model output, repository content, remote input,
and tool requests remain untrusted. Shell isolation is lifecycle- and policy-based;
it is not a complete security sandbox. Read the [architecture guide](docs/architecture.md)
and [security model](docs/security.md) before enabling consequential execution.

The approved long-term design remains the
[top-tier harness design](docs/superpowers/specs/2026-07-23-carl-top-tier-harness-design.md).
The ACP/Buzz extension is documented in the
[Buzz design](docs/superpowers/specs/2026-08-10-carl-buzz-acp-design.md). The current
single-process decision is recorded in
[ADR 0002](docs/adr/0002-single-process-v1.md), and provider-owned authentication in
[ADR 0004](docs/adr/0004-subscription-authentication-through-provider-sidecars.md).

## Development

Normal tests are deterministic, offline, credential-free, and include the pinned
Buzz ACP fixtures and real-process end-to-end path. The opt-in subscription smoke is
documented in the [Buzz guide](docs/buzz.md) and is excluded from public CI.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --locked
cargo build --locked --release
```

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Security reports follow
[SECURITY.md](SECURITY.md), and notable changes are in [CHANGELOG.md](CHANGELOG.md).

## Benchmark lab

The [benchmark lab](docs/benchmarks.md) now provides reproducible coding,
workflow-automation, and safety tasks, same-model Carl/Codex comparisons, and an owner-private
append-only experiment graph. The phase-three operator can prepare and seal a disposable candidate,
bind paired and independent-review evidence, explicitly open a draft PR, and safely dispose the
clean worktree while retaining the sealed branch. These are the first three layers
of the approved [improvement-factory design](docs/superpowers/specs/2026-08-10-codex-carl-improvement-factory-design.md),
but they do not run protected validation, autonomously promote, or merge changes. The deterministic
promotion controller, protected runner, merge queue, soak, and rollback remain separate gates.

## Roadmap

- [x] Durable provider-neutral domain, storage, and event contracts
- [x] Provider-owned OpenAI and Grok subscription authentication
- [x] Subscription-backed Codex ACP execution
- [x] Buzz-compatible ACP frontend and restricted publication adapter
- [x] Exact remote approvals, model/effort modes, steering, and cancellation
- [x] Local curated-memory storage, retrieval, settings, and CLI controls
- [ ] Interactive local TUI
- [ ] Owner-only Telegram gateway
- [ ] Grok execution adapter
- [ ] Native tools, broader sandboxing, and stale-safe promotion
- [ ] Cross-platform release packaging

## License

Carl is available under the [MIT License](LICENSE).
