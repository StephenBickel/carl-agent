# Buzz integration

Carl is a custom Agent Client Protocol (ACP) harness for Buzz. Buzz owns relay
identity, membership, inbound deduplication, and author admission. Carl owns the
provider turn, durable session, model and reasoning configuration, permissions,
exact approvals, cancellation, steering, and the restricted outbound publisher.

Status: pre-alpha and usable on the pinned path. The deterministic compatibility
suite is pinned to Buzz commit
`44456e200e3ca6a5d2882b58b447b80474041347`. Carl currently supports that exact
contract rather than claiming an unbounded version range. The publisher additionally
requires Buzz CLI `0.1.0`. Later Buzz revisions must pass the pinned contract and
end-to-end tests before this range is widened.

## Prerequisites

- macOS or Linux with the repository's Rust toolchain;
- Codex CLI `0.146.0` installed from a source you trust;
- a ChatGPT plan supported by Codex CLI;
- Buzz and `buzz-acp` from the tested commit above;
- Buzz CLI `0.1.0` for outbound publication;
- Node.js 22 or later only for the opt-in live subscription smoke script;
- an absolute, pre-existing, owner-private `CARL_DATA_DIR`;
- `carl` and `carl-buzz-mcp` on `PATH`.

`carl-buzz-mcp` is an argv-zero alias of the same Carl binary, not a second program.
On Unix, install `carl` and create a symlink with that exact name beside it. Carl
recognizes the executable name and enters a narrow MCP mode exposing only
`send_message` and `send_diff`.

## Authenticate locally

Authenticate from a trusted local foreground terminal before starting Buzz:

```sh
export CARL_DATA_DIR="$HOME/.carl"
carl auth login openai
carl auth status
```

Run `carl auth login openai` only on that local trusted terminal; never paste a
provider challenge or credential into Buzz.

The directory must already exist and be private; for example, create it with mode
`0700` on Unix. OAuth is performed by Codex CLI and its credentials remain
provider-owned. There is no API-key fallback. `carl acp` refuses to start when
`OPENAI_API_KEY` is present, and Buzz must not relay a login ceremony or credential.

## Configure Buzz

Use these six settings exactly for the supported V1 path:

```sh
export BUZZ_ACP_AGENT_COMMAND=carl
export BUZZ_ACP_AGENT_ARGS=acp
export BUZZ_ACP_MCP_COMMAND=carl-buzz-mcp
export BUZZ_ACP_AGENTS=1
export BUZZ_ACP_RESPOND_TO=owner-only
export BUZZ_ACP_PERMISSION_MODE=default
```

`BUZZ_ACP_RESPOND_TO=owner-only` is enforced by Buzz before Carl receives a turn.
Carl does not reinterpret channel membership or silently broaden that gate.
`BUZZ_ACP_AGENTS=1` is required by the single-process V1 ownership model: one Carl
process exclusively owns one canonical data root while it serves multiple ACP
sessions. A second owner fails closed.

If `buzz` is not discoverable on `PATH`, set the absolute trusted executable path:

```sh
export CARL_BUZZ_EXECUTABLE=/absolute/path/to/buzz
```

`CARL_CODEX_EXECUTABLE` can likewise name an absolute Codex executable. Relative
explicit overrides are rejected. Start Buzz from the repository directory Carl
should treat as the session workspace.

## Models, effort, and permissions

Carl exposes only models and reasoning effort values returned by the active Codex
app-server. Startup defaults may be supplied in `BUZZ_ACP_AGENT_ARGS`, for example
`acp --model <id> --effort high --permission-mode default`. ACP configuration changes
are validated and persisted per session; unsupported model/effort pairs fail instead
of silently falling back.

Permission modes are `plan`, `default`, `acceptEdits`, `dontAsk`, and
`bypassPermissions`:

- `plan` is read-only;
- `default` allows reads and requests exact approval for consequential work;
- `acceptEdits` accepts workspace edits while commands still follow policy;
- `dontAsk` never waits and rejects work that needs escalation;
- `bypassPermissions` removes approval prompts and uses unrestricted execution for
  exposed coding capabilities.

Local bypass is immediate only when the host operator explicitly starts
`carl acp --dangerously-bypass-permissions` (or supplies the exact bypass mode).
Remote bypass never activates from a configuration flip alone. It creates a
single-use warning code and requires `/confirm-bypass <code>` in a later owner
message. Return to a safer mode with `/permissions default`.

Bypass is dangerous. It does not disclose Buzz or provider credentials, but it lets
the active coding capability run with the current OS account's ambient authority.
Use it only in a repository and host you trust.

## Exact approvals

In `default` mode Carl persists a normalized proposal before any effect and posts a
bounded request to the originating Buzz thread. Resolve it with exactly one of:

- `/approve <code>`
- `/deny <code>`

Codes expire, are stored only as hashes, are bound to actor, external session,
Carl session, turn, provider request, tool call, working directory, and request
digest, and are consumed atomically at most once. Replay, a different actor or
session, changed scope, an unknown code, or quoted approval-like text fails closed.
The retained provider turn resumes only after a valid decision.

## Steering, cancellation, and restart

Buzz's `_session/steering` request injects guidance into the currently active Codex
turn using its exact thread and turn IDs. `session/cancel` interrupts that turn and
its supervised process tree. Cancellation does not publish a false successful final
message.

Carl durably binds an ACP session and stable Buzz channel to a workspace. A restart
can claim that stable channel for a new process branch and invalidates obsolete
remote approval codes. In-flight or ambiguous consequential work is never replayed
automatically. An ambiguous outbound delivery is recorded as uncertain rather than
blindly retried.

## Credential isolation

Buzz supplies `BUZZ_RELAY_URL`, `BUZZ_PRIVATE_KEY`, optional `BUZZ_AUTH_TAG`, and
optional `BUZZ_ACP_DISPLAY_NAME` only to the restricted publisher. Carl accepts that
closed descriptor and rejects a credential-bearing general shell or unknown MCP
server. Buzz credentials are never forwarded to Codex, model prompts, Carl's durable
event journal, general command environments, or diagnostics. The publisher sends
message bodies through stdin with literal argv; it does not interpolate shell text.

Subscription credentials remain in Codex-owned `$CODEX_HOME/auth.json` under Carl's
owner-private provider home. Carl uses explicit `file` mode, validates only bounded
owner-only file metadata, and never receives, reads, copies, logs, or stores bearer
or refresh tokens. Version
matching is compatibility evidence, not publisher attestation, so install every
executable from a source you trust.

## Verification

Public CI runs credential-free protocol, hostile framing, permission, approval,
restart, secret-isolation, and real-process end-to-end tests against the pinned Buzz
fixtures:

```sh
cargo test --locked --test buzz_acp_contract
cargo test --locked --test buzz_end_to_end
```

Live subscription and live-relay smoke tests are local opt-in checks and never run in
public CI. The deterministic suite proves the complete Buzz process boundary with
fake Codex and Buzz executables; it does not claim a network relay was present.

After completing the local OAuth login, run the opt-in subscription smoke from the
repository root with API-key variables explicitly removed:

```sh
cargo build --locked --release
env -u OPENAI_API_KEY -u CODEX_API_KEY -u AZURE_OPENAI_API_KEY \
  CARL_DATA_DIR="$HOME/.carl" \
  CARL_CODEX_EXECUTABLE="$(command -v codex)" \
  CARL_LIVE_MODEL=gpt-5.6-terra \
  node scripts/live-codex-acp-smoke.mjs
```

The script uses the real `carl acp` and Codex app-server processes. In separate
sessions it performs a read-only plan assessment, a one-line edit and verification,
an exact-approved loopback-only network-denial probe, steering, and cancellation. It
writes only boolean/count metadata and the pinned Codex version beneath a new
owner-private temporary directory; assistant text, diffs, credentials, and provider
diagnostics are not persisted by the script.

## Troubleshooting

- `API-key authentication is not supported`: unset `OPENAI_API_KEY` and use the
  local Codex subscription login.
- `Codex executable or provider home is invalid`: verify the exact `0.146.0`
  executable and private data-root metadata.
- `Buzz executable is unavailable or untrusted`: install Buzz CLI `0.1.0` or set an
  absolute `CARL_BUZZ_EXECUTABLE`.
- `Carl data directory is unsafe or already in use`: fix ownership/permissions or
  stop the other Carl process using that root.
- approval unavailable: request a fresh proposal; do not reuse or copy a code from
  another thread.

See [architecture.md](architecture.md), [security.md](security.md), and the
[approved integration design](superpowers/specs/2026-08-10-carl-buzz-acp-design.md)
for the complete boundary.
