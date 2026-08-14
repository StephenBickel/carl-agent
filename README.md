# Carl

Carl is Stephen Bickel's personal, local-first Rust coding agent and an open-source
agent harness. It is built around a deterministic kernel, durable and replayable
events, explicit permission boundaries, and provider-owned subscription login.
Carl's personality and operating principles are public in the
[public operating contract](CARL.md). The name is Stephen's middle name and his
grandfather's name.

## Status: pre-alpha, usable terminal and ACP coding paths

Carl now has a usable ACP coding path: `carl acp` runs a real, version-pinned Codex
app-server through an existing ChatGPT subscription and can serve Buzz or another
compatible ACP client over stdio. It supports durable sessions, provider-reported
model and reasoning choices, plan/default/edit/don't-ask/bypass permission modes,
exact single-use approvals, steering, cancellation, diffs, and final publication.
The ACP path is CLI-reachable and covered by process-level offline tests.

Carl also has a native interactive terminal UI. Running `carl` (or the explicit
`carl tui` alias) connects to the persistent local service, starts it when needed,
and uses the configured provider. OpenAI subscription is the zero-key default;
native OpenAI Responses and OpenRouter are also supported. The TUI defaults to
owner-selected **full access**, streams durable task updates, and keeps sessions
available after the terminal closes.

The coding path now includes a durable long-horizon task engine: immutable admission
budgets, completion contracts, operation evidence, canonical checkpoints, structured
context compaction, recoverable service maintenance, task metrics, and provider-context
replacement. Owner-selected full access is accepted risk; consequential effects still
cross Carl's pre-dispatch mediation boundary, but same-user host processes remain
outside that protection. See the [long-horizon task guide](docs/long-horizon-tasks.md)
and [benchmark methodology](docs/benchmarks.md).

Carl also includes curated local profile, preference, fact, goal, and expiring
episode memory with scoped isolation, bounded lexical retrieval, proposal approval,
versioned export, hard deletion, and no external service dependency. Memory is
managed through the implemented `carl memory` command tree.

This remains pre-alpha. The Telegram gateway, Grok execution,
in-process provider hot-swapping, stale-safe live-workspace
promotion, and broader consumer packaging are incomplete. `serve`, `acp`, `auth`, `memory`, `maintenance`, and the
direct Codex baseline have implemented behavior; `pair`, `doctor`, and `sessions`
remain inert CLI shells.

## Try Carl locally

Carl requires the Rust toolchain in `rust-toolchain.toml` and an absolute
pre-existing private data directory. The default subscription path additionally
requires Codex CLI `0.146.0` and a local ChatGPT subscription login.

```sh
cargo build --locked --release
mkdir -m 700 "$HOME/.carl"
export CARL_DATA_DIR="$HOME/.carl"
carl auth login openai
carl
```

`carl tui` opens the same interface explicitly. Type a prompt and press Enter;
Shift+Enter inserts a newline. Ctrl+C cancels an active task and Ctrl+D exits.
The activity row above the input pulses independently of service polling, names the
current authoritative phase or tool, and reports how long it has been since Carl's
last durable update without pretending to know provider-side progress.
The terminal supports these commands:

- `/model [id]` and `/effort <level>` inspect or change model configuration.
- `/permissions <plan|default|accept-edits|dont-ask|full-access>` changes the
  active policy; **full access** is the local TUI default.
- `/compact`, `/status`, and `/cancel` control the active durable task.
- `/sessions` lists durable TUI sessions and `/resume <number|session-id>` loads one.
- `/new` starts with a clean session, while `/help` and `/exit` are local controls.

OpenAI subscription through Codex is the default. Native keys are captured without
terminal echo and stored in the operating-system credential vault:

```sh
carl auth key openrouter
carl auth use openrouter
carl
```

Use `carl auth key openai` for an OpenAI Platform key, or select
`subscription|openai|openrouter` with `carl auth use`.

OpenRouter exposes only models advertising text input/output, structured tools, and
at least a 32K context window. DeepSeek, Qwen, Kimi, Anthropic, Google, and xAI
models appear when their live metadata qualifies. `carl auth use` safely drains any
running task to a committed checkpoint and stops the old service; the next `carl`
launch starts the selected provider. `/provider` reports the actual running provider,
while `/login` and `/logout` show the exact credential commands.

The background service remains alive when the TUI exits so long-running work and
session state survive terminal restarts. To use ACP instead, run
`carl acp --permission-mode default`.

Use `--model <id>` and `--effort low|medium|high|xhigh|max|ultra` to select values
reported by the active provider. A local operator can explicitly launch unrestricted
execution with `carl acp --dangerously-bypass-permissions`; see the
[Buzz guide](docs/buzz.md) before enabling bypass remotely.

For long tasks, run `carl serve` in one local process and connect with `carl acp`.
Status, sanitized metrics, resume, steering, cancellation, checkpoint inspection, and
recoverable maintenance are documented in the
[long-horizon task guide](docs/long-horizon-tasks.md).

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
The deterministic long-horizon gate and the opt-in paired endurance methodology are
documented in [docs/benchmarks.md](docs/benchmarks.md); one paired run is never treated
as evidence of superiority.

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
- [x] Durable long-horizon tasks, checkpoints, compaction, metrics, and restart recovery
- [x] Local curated-memory storage, retrieval, settings, and CLI controls
- [x] Interactive local TUI backed by durable subscription tasks
- [ ] Owner-only Telegram gateway
- [ ] Grok execution adapter
- [x] Native OpenAI/OpenRouter adapters and Carl-owned coding tools
- [ ] Broader sandboxing and stale-safe promotion
- [ ] Cross-platform release packaging

## License

Carl is available under the [MIT License](LICENSE).
