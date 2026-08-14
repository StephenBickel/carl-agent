# Configuration

Carl currently accepts exactly four non-secret Carl process variables plus explicit
`carl acp` flags. It has no general profile loader, endpoint override, arbitrary
provider-home setting, or credential-reference schema. Memory settings are a narrow,
typed local SQLite projection managed through `carl memory settings`.

## Carl process variables

| Variable | Contract |
| --- | --- |
| `CARL_DATA_DIR` | Optional absolute path to a pre-existing, trusted Carl data directory. When omitted by the TUI, Carl creates and uses an owner-private `$HOME/.carl`; explicit overrides are never created, replaced, or weakened. Other command families still require the explicit variable. |
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

Every newly admitted durable task receives explicit hard and soft budgets. Their ACP
flags and current admission ranges are:

| Flag | Range | Purpose |
| --- | ---: | --- |
| `--max-wall-time-seconds` | 1–86,400 | Hard total wall-time budget. |
| `--max-provider-requests` | 1–10,000 | Hard provider-request budget. |
| `--max-tool-calls` | 1–100,000 | Hard tool-operation budget. |
| `--soft-epoch-seconds` | 30–3,600 | Request a safe checkpoint after a bounded epoch. |
| `--soft-epoch-tool-calls` | 1–1,000 | Request a safe checkpoint after this many tool calls. |

The defaults are printed by `carl acp --help` and are applied once at task admission.
Reconnecting with different flags does not rewrite an existing task's persisted budget;
the new values apply to the next task.

`carl acp` is the implemented subscription-backed execution path. The older
`codex exec --json` adapter is exposed only through the explicit `carl baseline codex`
comparison command; normal ACP work uses Codex app-server `0.146.0`.

`carl maintenance status` is read-only. `carl maintenance prepare` drains an active
task to a canonical checkpoint, reports the bound task/checkpoint, and stops the
provider. Emergency process shutdown remains destructive and is not an alias for
recoverable maintenance.

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

## Implemented memory settings

Memory is enabled by default. `carl memory settings` reads or atomically updates the
local owner/Carl partition:

| Setting | Default | Range |
| --- | ---: | ---: |
| `enabled` | `true` | boolean |
| `max_context_items` | `8` | 1–32 |
| `context_bytes` | `8192` | 256–65536 |
| `max_memories` | `500` | 1–5000 |
| `max_storage_bytes` | `1048576` | 64–67108864 |
| `episode_ttl_days` | `90` | 1–3650 |

These settings contain no credentials and cause no network access. Disabling blocks
capture and retrieval while leaving export and deletion available. See the
[memory guide](memory.md).

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

There is no API-key fallback for subscription ACP. API-key-like parent variables are
not forwarded through the closed Codex child environment. Native service adapters
are configured explicitly with `carl auth key openai|openrouter`; secure input is
stored in macOS Keychain, Windows Credential Manager, or Linux Secret Service.
`carl auth use subscription|openai|openrouter` writes only an owner-private provider
enum. When a service is running, the command uses recoverable maintenance to drain at
a committed checkpoint and shut it down; the next `carl` launch starts the selected
provider. OpenAI and OpenRouter endpoints are pinned and cannot be overridden by
profiles.

Authentication status is a local provider-owned handshake and does not prove current
subscription or model entitlement. Successful authentication enables no model by
itself; `carl acp` still validates the executable, app-server handshake, and provider
model catalog when it starts.

## What is not configurable yet

No general profile configuration is accepted today. Apart from the strict provider
preference above, there is no configuration file for endpoint URLs, native tool budgets,
Telegram, TUI layout, memory policy, or promotion. The current working directory becomes
the canonical ACP workspace. Non-TUI command families require `CARL_DATA_DIR` explicitly;
the TUI alone may prepare the fixed owner-private default. Do not place secrets in guessed
profile files or non-secret Carl variables.
