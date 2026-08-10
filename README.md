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

This remains pre-alpha. TUI interaction, the Telegram gateway, Grok execution,
native HTTP/OpenAI adapters, Carl's native tool loop, stale-safe live-workspace
promotion, and broader consumer packaging are incomplete. The four placeholder
commands `serve`, `pair`, `doctor`, and `sessions` return not-implemented errors;
Clap's built-in `help` command displays help.

Only the four placeholder commands remain unavailable as inert CLI shells; `auth`
and `acp` have implemented behavior.

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
versioned migrations, bounded sidecars, actor/session/turn/request-bound approvals
that are atomically single-use, and external-agent requests default to exact owner
approval. The closed evaluator denies writable live-workspace access. Capability-relative,
secret-filtered staging, content-addressed artifacts, and independent bounded
verification also exist as library boundaries. Stale-safe promotion and run-engine
orchestration remain unavailable outside the ACP execution path.

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

## Roadmap

- [x] Durable provider-neutral domain, storage, and event contracts
- [x] Provider-owned OpenAI and Grok subscription authentication
- [x] Subscription-backed Codex ACP execution
- [x] Buzz-compatible ACP frontend and restricted publication adapter
- [x] Exact remote approvals, model/effort modes, steering, and cancellation
- [ ] Interactive local TUI
- [ ] Owner-only Telegram gateway
- [ ] Grok execution adapter
- [ ] Native tools, broader sandboxing, and stale-safe promotion
- [ ] Cross-platform release packaging

## License

Carl is available under the [MIT License](LICENSE).
