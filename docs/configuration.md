# Configuration

Carl has no general file-based configuration loader or platform data-directory
resolver. The command surface accepts exactly three non-secret process
variables; profile files, model selection, provider endpoints, policy settings, and
credential references remain unimplemented. Memory settings are a narrow, typed,
local SQLite projection managed through `carl memory settings`.

## Implemented authentication configuration

| Variable | Contract |
| --- | --- |
| `CARL_DATA_DIR` | Required absolute path to a pre-existing, trusted Carl data directory. Carl does not create, repair, replace, or change permissions on this root. |
| `CARL_CODEX_EXECUTABLE` | Optional absolute executable path. When absent, Carl discovers the single command name `codex` on `PATH`. |
| `CARL_GROK_EXECUTABLE` | Optional absolute executable path. When absent, Carl discovers the single command name `grok` on `PATH`. |

The provider homes are fixed:

- Codex: `$CARL_DATA_DIR/providers/codex`, passed as `CODEX_HOME`;
- Grok: `$CARL_DATA_DIR/providers/grok`, passed as `GROK_HOME`.

There is no arbitrary provider-home override. Carl validates the data root and creates
only the provider-home descendants. Every provider process runs from its isolated
provider home rather than the current workspace.

Carl supports exactly Codex CLI `0.136.0` and Grok Build `0.2.111`. It never installs
or updates either executable. Discovery canonicalizes and validates one executable
identity, which Carl reuses for version, status, login, and logout. A matching version
does not attest its publisher: version matching is compatibility evidence, not
publisher attestation. Explicit executable overrides must be absolute paths; ordinary
`PATH` discovery is never granted stronger trust because an install directory has
risky metadata.

These variables are configuration, not credentials, and are not copied into provider
child environments unless independently included in the closed child-environment
allowlist.

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

Every public auth or daemon entry point takes one operating-system-backed exclusive
lock for the canonical `CARL_DATA_DIR` before it touches a provider home or starts a
provider process. The lock is shared across providers and remains held through
foreground ceremonies, cancellation cleanup, child reaping, authentication-state
reconciliation, and provider shutdown.

Concurrent commands targeting the same data root fail closed and promptly. Lock
ownership is tied to a live handle or descriptor. A crashed owner does not leave a
stale logical lock, and an orderly exit releases it too. The persistent lock file is
not a daemon-discovery record and is not deleted for stale-lock recovery. Task 4's
provider-home mutex still orders brokers inside one process; it is not a cross-process
lock.

## API keys versus subscriptions

Native API credentials and consumer subscription login are distinct:

- a future native OpenAI Responses adapter will require an OpenAI Platform API key;
- a future native xAI adapter will require an xAI API key;
- `carl auth` asks provider-owned sidecars to authenticate eligible ChatGPT,
  SuperGrok, or X subscriptions.

API keys have their own provider access and billing. Subscription login does not
produce an API key or authorize Carl's future native adapters. Codex owns its
subscription tokens in the operating-system keyring. Grok owns its subscription
tokens in `$GROK_HOME/auth.json`. Carl never accepts those tokens as adapter
credentials.

Authentication does not enable model execution or subscription-backed delegates.
Those runtime paths remain unavailable.

## Planned general model

V1 will layer explicit command-line choices over a selected profile and local defaults.
A future profile is expected to select a provider, model, endpoint, workspace root,
turn budgets, policy posture, and credential reference. Exact keys and platform paths
will be documented only after a validated schema exists.

The future workspace root will be the default boundary for file and shell tools, not
proof of OS-level containment. Profiles will be able to tighten local and remote
policy. Turn settings will impose hard resource bounds. None of that general
configuration is accepted today.

## Current operation

There is no first-run setup, Carl-owned subscription credential storage, model
provider connectivity check, or configuration file parser today. Do not place real
secrets in the three auth variables or in guessed files. The auth status command
performs only provider-owned local authentication handshakes; it does not contact a
model through a Carl runtime.
