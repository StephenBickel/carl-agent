# Security Model

Status: design plus partial foundation. Carl is not currently a usable agent, and the controls described as planned below are not enforcement claims.

## Trust model

The local owner and host operating system define the trust root. Model output, tool arguments, remote messages, provider responses, fetched content, repository files, and skill instructions are untrusted inputs. The SQLite database, exported traces, and logs may contain sensitive conversation or filesystem metadata even after credential redaction.

Carl does not attempt to defend a host account from an attacker who already controls that account or its operating system. It also does not promise perfect containment of arbitrary native commands.

## Implemented properties

- public error codes and user messages are separated from sanitized internal detail;
- events use stable types and schema versions;
- SQLite migrations are forward-only and checksum-verified, and the store rejects unknown future schemas;
- session events are append-only and lifecycle changes are transactional;
- the scripted provider supports deterministic tests without a network or live credentials.
- provider-owned authentication sidecars run with fixed isolated homes, closed child
  environments, canonical executable identity checks, and supervised process trees;
- the auth CLI emits deterministic safe JSON and keeps provider challenges, warnings,
  and terminal output on verified local stderr.
- safe external-agent requests require approval by default, while writable
  live-workspace access, environment grants, and provider-network mismatch fail
  closed before approval;
- external-agent approvals bind an actor, session, turn, tool call, expiry, and a
  single exact request digest, and an allowed approval is atomically consumed at most
  once;
- secret findings retain only a stable classification, never matched bytes;
- delegate stages are bounded, capability-relative disposable copies whose private
  containment is verified before they are returned. On Unix, the held stage parent
  and every generated entry must be owned by the effective user with no group or
  world access. On Windows, the held parent and generated entries must satisfy Carl's
  current-user-private DACL policy and must not be reparse points. Other target
  families fail closed. Stages accept only permitted single-link UTF-8 regular files,
  exclude known sensitive and executable configuration surfaces, and a
  high-confidence secret finding rejects the entire stage.

These properties improve auditability and failure behavior. They do not implement
model-provider access, a general runtime tool-policy system, redaction of all future
runtime data, live-workspace promotion, or a complete process sandbox. Proposal
inspection, verification, and promotion are not implemented, so no subscription
coding task is user-reachable.

## Planned v1 controls

The approved design requires:

- canonical workspace-relative file access with symlink escape rejection;
- typed `allow`, `ask`, or `deny` policy decisions for every non-delegate tool
  proposal, extending the implemented external-agent boundary;
- exact, expiring approvals for all consequential native tools, extending the
  implemented bound approval store;
- filtered child-process environments, deadlines, output caps, and cancellation;
- bounded HTTP(S) fetches, with private-network destinations denied remotely by default;
- known-credential redaction before events reach storage or frontends;
- a stricter Telegram policy and admission checks before model invocation;
- fail-closed behavior for incompatible storage and storage-write failures.

Every one of these controls requires implementation and adversarial tests before it can be claimed as present.

## Shell boundary

**Shell isolation in v1 is policy- and process-based; it is not a complete security sandbox.** Workspace selection, a filtered environment, timeouts, cancellation, and approvals reduce accidental harm but do not neutralize hostile programs running as the same OS user. Platform sandbox backends may be added later. Until then, never approve a command you would not run directly under the host account.

## Credentials and authentication

Subscription authentication stays inside provider-owned executables. Carl never
receives, reads, copies, logs, persists, or forwards subscription bearer or refresh
tokens.

- Codex owns ChatGPT subscription tokens in the operating-system keyring.
  `CODEX_HOME` isolates filesystem-backed state but does not prove keyring isolation.
  Logging out through Carl can therefore affect another Codex CLI or IDE session for
  the same OS user, and Carl displays a local warning before logout.
- Grok owns `$GROK_HOME/auth.json`. Carl validates only the credential file's metadata
  as a regular, non-linked, owner-only file; it never opens or reads the file.
  Isolating `GROK_HOME` does not suppress trusted root-owned `/etc/grok` policy.

API keys are a separate security and billing boundary. Future native OpenAI and xAI
adapters will use user-supplied OpenAI Platform and xAI API keys, not ChatGPT,
SuperGrok, or X subscription tokens. Carl does not call undocumented OAuth endpoints.
See [ADR 0003](adr/0003-no-undocumented-oauth.md) and
[ADR 0004](adr/0004-subscription-authentication-through-provider-sidecars.md).

Authentication state does not prove current subscription or model entitlement.
Authentication does not enable model execution or subscription-backed delegates.

## Foreground and output boundary

Login requires a verified local foreground terminal. Grok login and logout additionally
require a crate-private foreground capability at the point the provider process is
spawned. A status-only Grok broker cannot upgrade itself or mutate authentication;
`carl auth status` may run without a terminal and can call only the local
provider-owned status handshake.

Stdout is reserved for one deterministic safe JSON value. Validated challenges,
shared-keyring warnings, and provider-owned terminal output go only to the verified
local stderr terminal. Provider terminal text is not captured, parsed, relayed,
serialized, persisted, or logged by Carl.

## Executable and process boundaries

Carl pins Codex CLI `0.136.0` and Grok Build `0.2.111`, validates a canonical
executable identity once, and revalidates that exact identity before use. Version
matching is compatibility evidence, not publisher attestation. Carl neither installs
nor updates provider executables.

On Windows, every existing executable-path component rejects reparse points and
broad deletion or security-descriptor control. The executable's immediate parent
also rejects broad child-creation rights to prevent adjacent DLL, configuration, or
plugin planting. Owners are limited to the current user, SYSTEM, Administrators, or
the exact `NT SERVICE\TrustedInstaller` principal resolved by Windows; arbitrary
service SIDs and unknown owners are rejected. Every non-root ancestor follows that
same strict policy. The only exception is a local disk or verbatim-disk volume root,
where the standard create-subdirectory right may add a sibling but cannot replace the
already-existing first path component. UNC roots do not receive this exception.
Create-file, metadata-write, deletion, and security-descriptor control rights remain
rejected at the volume root because they can mutate the component, participate in
reparse-point creation, or remove an existing child. The residual boundary is limited
to creating an unrelated sibling at the local volume root; the selected first
component and every directory below it are independently checked under the strict
policy.

Every public auth or future daemon entry point holds one cross-process exclusive OS
lock for the canonical `CARL_DATA_DIR`. It retains the lock through provider cleanup,
child reaping, state reconciliation, and shutdown. The lock is released automatically
when the owning process exits or crashes. Task 4's provider-home mutex remains
in-process only and cannot replace this data-root lock.

Provider children are supervised as process groups on Unix and Job Objects on
Windows. These mechanisms support cancellation and bounded cleanup, but they are
lifecycle containment rather than privilege separation: they do not prevent provider
children from exercising the ambient authority that survives the closed environment,
isolated working directory, and OS access controls.

## Remote channel boundary

The planned Telegram gateway uses outbound long polling and one paired owner. Group, channel, guest, and unpaired updates must be discarded before provider or tool invocation. Duplicate updates and approval callbacks must be persisted and deduplicated so retries cannot duplicate consequential work. See the [Telegram design guide](telegram.md).

For vulnerability reporting, follow the private process in the repository [security policy](../SECURITY.md).
