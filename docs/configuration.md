# Configuration

Carl currently accepts exactly four non-secret Carl process variables plus explicit
`carl acp` flags. It has no general profile loader, endpoint override, arbitrary
provider-home setting, or credential-reference schema.

## Carl process variables

| Variable | Contract |
| --- | --- |
| `CARL_DATA_DIR` | Required absolute path to a pre-existing, trusted Carl data directory. Carl does not create, replace, or weaken this root. |
| `CARL_CODEX_EXECUTABLE` | Optional absolute Codex path. When absent, Carl discovers `codex` on `PATH`. |
| `CARL_GROK_EXECUTABLE` | Optional absolute Grok path. When absent, Carl discovers `grok` on `PATH`. |
| `CARL_BUZZ_EXECUTABLE` | Optional absolute Buzz CLI path for Buzz publication. When absent, Carl discovers `buzz` on `PATH`. |

The fixed provider homes are:

- Codex: `$CARL_DATA_DIR/providers/codex`, passed as `CODEX_HOME`;
- Grok: `$CARL_DATA_DIR/providers/grok`, passed as `GROK_HOME`.

There is no arbitrary provider-home override. Carl creates only provider-home
descendants inside the validated root. Provider processes use those homes rather
than the repository as their home directory.

Carl supports Codex CLI `0.146.0`, Grok Build `0.2.111`, and Buzz CLI `0.1.0`. It
never installs or updates these executables. Discovery canonicalizes and validates
one executable identity and revalidates it at process boundaries. Version matching
is compatibility evidence, not publisher attestation. Explicit overrides must be
absolute paths; install each binary from a source you trust.

## ACP flags

The implemented subscription-backed execution path is `carl acp`:

```text
carl acp --model <id> --effort <level> --permission-mode <mode>
```

`<level>` is one of `low`, `medium`, `high`, `xhigh`, `max`, or `ultra` and must be
supported by the selected provider model. `<mode>` is `plan`, `default`,
`acceptEdits`, `dontAsk`, or `bypassPermissions`. The visible
`--dangerously-bypass-permissions` flag is an alias for local explicit bypass.
Session-level ACP configuration may override these process defaults but cannot
silently select an unknown model, unsupported effort, or remote bypass.

`carl acp` is the implemented subscription-backed execution path. The older
`codex exec --json` adapter remains a separate inert library boundary; the live ACP
path uses Codex app-server `0.146.0`.

## Buzz settings

Buzz owns these integration settings, not Carl's general configuration model:

```sh
export BUZZ_ACP_AGENT_COMMAND=carl
export BUZZ_ACP_AGENT_ARGS=acp
export BUZZ_ACP_MCP_COMMAND=carl-buzz-mcp
export BUZZ_ACP_AGENTS=1
export BUZZ_ACP_RESPOND_TO=owner-only
export BUZZ_ACP_PERMISSION_MODE=default
```

When `BUZZ_ACP_AGENTS=1` selects the Buzz frontend, Carl accepts only the typed
`carl-buzz-mcp` descriptor. That descriptor may contain `BUZZ_RELAY_URL`,
`BUZZ_PRIVATE_KEY`, optional `BUZZ_AUTH_TAG`, and optional
`BUZZ_ACP_DISPLAY_NAME`. These values are credentials or transport metadata, not
general Carl configuration, and are isolated to the restricted publisher. See
[buzz.md](buzz.md).

## Data-root process lock

Every public auth or ACP entry point takes one operating-system-backed exclusive lock
for the canonical `CARL_DATA_DIR` before touching provider state. The lock remains
held through provider startup, turns, foreground ceremonies, cancellation cleanup,
child reaping, reconciliation, and shutdown.

Concurrent commands targeting the same root fail closed. Ownership is tied to a live
handle or descriptor, so a crashed owner does not leave a stale logical lock. The
persistent lock file is not a daemon-discovery record and is not deleted for
recovery. The provider-home mutex still orders brokers inside one process; it is not
a cross-process lock. This is the single-process V1 boundary.

## API keys versus subscriptions

API keys have their own provider access and billing. `carl auth` asks provider-owned
executables to authenticate eligible ChatGPT, SuperGrok, or X subscriptions. Codex
owns `$CODEX_HOME/auth.json` and Grok owns `$GROK_HOME/auth.json`; Carl never accepts
either as adapter credentials. Carl selects Codex's explicit `file` mode rather than
`auto`, so storage behavior cannot silently change with host keyring availability.
Both homes are owner-private, and Carl validates credential-file metadata without
opening or reading the files.

There is no API-key fallback for ACP. If `OPENAI_API_KEY` is set, `carl acp` fails
before provider startup. API-key-like parent variables are not forwarded through the
closed Codex child environment. A future native Responses adapter would use an
OpenAI Platform key, and a future native xAI adapter would use an xAI key; neither
path is implemented here.

Authentication status is a local provider-owned handshake and does not prove current
subscription or model entitlement. Successful authentication enables no model by
itself; `carl acp` still validates the executable, app-server handshake, and provider
model catalog when it starts.

## What is not configurable yet

No general profile configuration is accepted today. There is no configuration file
for native providers, endpoint URLs, native tool budgets, Telegram, TUI layout,
memory policy, or promotion. The current working directory becomes the canonical ACP
workspace, and `CARL_DATA_DIR` must be supplied explicitly. Do not place secrets in
guessed profile files or non-secret Carl variables.
