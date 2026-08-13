# Security Model

Status: pre-alpha with an implemented ACP/Buzz coding path plus additional inert
safety foundations. Claims in "Implemented properties" apply to tested code; planned
controls are not enforcement claims.

## Trust model

The local owner and host operating system define the trust root. Model output, tool arguments, remote messages, provider responses, fetched content, repository files, and skill instructions are untrusted inputs. The SQLite database, exported traces, and logs may contain sensitive conversation or filesystem metadata even after credential redaction.

Carl does not attempt to defend a host account from an attacker who already controls that account or its operating system. It also does not promise perfect containment of arbitrary native commands.

## Implemented properties

- public error codes and user messages are separated from sanitized internal detail;
- events use stable types and schema versions;
- SQLite migrations are forward-only and checksum-verified, and the store rejects unknown future schemas;
- session events are append-only and lifecycle changes are transactional;
- memory is partitioned by exact owner, agent, workspace, and session scope; only
  direct owner capture or approved short-lived proposals become retrievable;
- memory capture applies non-retaining secret and high-confidence prompt-injection
  filters before persistence, and retrieved content is labeled as untrusted data that
  cannot override instructions, policy, approvals, or capabilities;
- memory count, content bytes, per-record bytes, pending proposals, context items, and
  context bytes are bounded; episodic memory expires by default;
- memory deletion retains no content-bearing tombstone and requires SQLite secure
  deletion plus a successful truncating WAL checkpoint before success is reported;
- the scripted provider supports deterministic tests without a network or live credentials.
- `carl acp` rejects API-key fallback, validates and locks an owner-private absolute
  data root, starts only the pinned Codex app-server, and keeps JSON protocol output
  separate from bounded stderr diagnostics;
- the ACP kernel serializes each session, persists accepted lifecycle transitions,
  binds exact single-use approvals to actor/session/turn/tool/provider request,
  supports provider steering and cancellation, and does not automatically repeat
  ambiguous consequential work;
- the Buzz frontend accepts only a structurally validated current-event context and
  one typed restricted publisher descriptor. Buzz credentials are never forwarded to
  Codex, provider prompts, durable events, general command environments, or error
  text;
- the `carl-buzz-mcp` alias exposes only typed `send_message` and `send_diff`
  operations. It passes an exact credential allowlist to a trusted Buzz CLI through a
  closed process environment and sends content on stdin rather than shell text;
- remote approval and bypass-confirmation display codes are random, stored only as
  SHA-256 digests, expire, bind exact durable context, and are atomically consumed at
  most once. Remote bypass requires a later explicit confirmation; local bypass is
  available only through an explicit dangerous launch choice;
- provider-owned authentication sidecars run with fixed isolated homes, closed child
  environments, canonical executable identity checks, and supervised process trees;
- the auth CLI emits deterministic safe JSON and keeps provider challenges, warnings,
  and terminal output on verified local stderr.
- safe external-agent requests require approval by default, while writable
  live-workspace access, environment grants, and provider-network mismatch fail
  closed before approval;
- external-agent approvals bind an actor, session, turn, tool call, expiry, and a
  single exact request digest, including the exact verification-specification digest,
  and an allowed approval is atomically consumed at most once;
- secret findings retain only a stable classification, never matched bytes;
- delegate stages are bounded, capability-relative disposable copies whose private
  containment is verified before they are returned. On Unix, the held stage parent
  and every generated entry must be owned by the effective user with no group or
  world access. On Windows, the held parent and generated entries must satisfy Carl's
  current-user-private DACL policy and must not be reparse points. Other target
  families fail closed. Stages accept only permitted single-link UTF-8 regular files,
  exclude known sensitive and executable configuration surfaces, and a
  high-confidence secret finding rejects the entire stage.
- each accepted source file and the deterministic content-manifest preimage are
  sealed in an owner-private content-addressed store outside the mutable stage.
  Published objects are create-new, flushed, single-link, and read-only where the
  platform supports it. Every later read reopens the named object, checks held file
  identity and private metadata, and re-hashes its bytes. A separate sealed
  source-precondition artifact covers source identity and ownership evidence.
  Runtime startup removes canonical objects without durable SQLite roots and prunes
  orphan registry rows while holding both exclusive roots. Aggregate object storage
  is capped at 1 GiB and 200,000 entries, with a separate bounded recovery scan;
- proposal inspection executes no repository code and never reads promotion bytes
  back from the agent-mutated stage after inspection. It either reports no changes
  or persists one inert exact-replacement envelope for an existing UTF-8 file.
  Structural changes, protected paths, redirects, hard links, binary content,
  metadata-only drift, generated secrets, oversized content, and unstable path
  identity fail closed with path-and-rule-only diagnostics. Preparation and
  inspection also cap aggregate relative-path metadata at 8 MiB per snapshot.
- independent verification persists an immutable request that binds the exact
  executable content and platform identity, literal argument vector, credential-free
  environment profile, every execution and shutdown limit, the sealed baseline and
  source-precondition artifacts, the exact proposal and payload artifacts, and both
  file-content and directory-topology digests. A passing result can only be minted
  inside the verifier from a private execution receipt; ordinary crate code has no
  production constructor for a passing result.
- verification reconstructs a new owner-private candidate exclusively from
  re-verified content-addressed artifacts and the inert exact-replacement payload.
  It preserves the sealed directory topology, including empty directories, and
  never executes in the agent-mutated stage or live source tree. The approved
  executable receives the approved arguments as a literal argv vector, a held
  candidate working directory, a closed environment whose home and temporary
  locations point at a separate disposable scratch directory, bounded aggregate
  output, deadlines, and cancellation.
- the verifier revalidates the originally approved executable attestation immediately
  before and after supervised execution. After the process group or Job Object has
  been fully reaped, it performs two stable candidate scans and compares file bytes,
  metadata, identities, and exact directory topology with both the pre-execution
  seal and durable expected digests. It also re-reads the baseline, precondition,
  proposal, payload, and content artifacts. Candidate and scratch cleanup must
  succeed before a passing result is returned.
- verification stdout and stderr share one bounded byte budget. Each complete stream
  must be UTF-8, NUL-free, and pass the high-confidence secret filter. Rejected
  diagnostics are discarded in full; no matching substring is retained in the
  durable result.

These properties improve auditability and failure behavior. The ACP path does
implement model-provider access through provider-owned Codex app-server tools, but it
does not implement a general native Carl tool-policy system, redaction of every
future data shape, live-workspace promotion, or a complete process sandbox.
Independent verification remains a separate inert library boundary and promotion is
not implemented.

The memory store and management CLI are implemented, but the live turn context
assembler is not. Hard deletion covers Carl's live database and WAL, not independent
exports, backups, filesystem snapshots, storage-device remanence, or content already
sent to a model provider. Optional semantic reranking is not configured by default;
provider failure falls back to local lexical ranking without exposing provider detail.

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

**Shell isolation in v1 is policy- and process-based; it is not a complete security
sandbox.** The independent verifier never interprets its approved argv as shell text,
but the selected native executable still runs as the current OS user. Workspace
selection, a closed environment, timeouts, cancellation, output bounds, and approvals
reduce accidental harm; they do not neutralize hostile programs. Platform sandbox
backends may be added later. Until then, never approve a verifier command you would
not run directly under the host account.

## Credentials and authentication

Subscription authentication stays inside provider-owned executables. Carl never
receives, reads, copies, logs, persists, or forwards subscription bearer or refresh
tokens.

- Codex owns ChatGPT subscription tokens in `$CODEX_HOME/auth.json`. Carl selects
  explicit `file` mode instead of `auto`, prepares an owner-private provider home,
  and validates the credential as a bounded, regular, non-linked, owner-only file.
  It never opens or reads the file. Logging out through Carl removes only Carl's
  isolated Codex session, and Carl displays a local notice before logout.
- Grok owns `$GROK_HOME/auth.json`. Carl validates only the credential file's metadata
  as a regular, non-linked, owner-only file; it never opens or reads the file.
  Isolating `GROK_HOME` does not suppress trusted root-owned `/etc/grok` policy.

API keys are a separate security and billing boundary. Future native OpenAI and xAI
adapters will use user-supplied OpenAI Platform and xAI API keys, not ChatGPT,
SuperGrok, or X subscription tokens. Carl does not call undocumented OAuth endpoints.
See [ADR 0003](adr/0003-no-undocumented-oauth.md) and
[ADR 0004](adr/0004-subscription-authentication-through-provider-sidecars.md).

Authentication state does not prove current subscription or model entitlement.
Execution is a separate `carl acp` startup path that must successfully validate the
Codex executable, app-server handshake, and model catalog. API keys cannot substitute
for that provider-owned subscription path.

## Foreground and output boundary

Login requires a verified local foreground terminal. Grok login and logout additionally
require a crate-private foreground capability at the point the provider process is
spawned. A status-only Grok broker cannot upgrade itself or mutate authentication;
`carl auth status` may run without a terminal and can call only the local
provider-owned status handshake.

Stdout is reserved for one deterministic safe JSON value. Validated challenges,
isolated-session notices, and provider-owned terminal output go only to the verified
local stderr terminal. Provider terminal text is not captured, parsed, relayed,
serialized, persisted, or logged by Carl.

## Executable and process boundaries

Carl pins Codex CLI `0.146.0` and Grok Build `0.2.111`, validates a canonical
executable identity once, and revalidates that exact identity before use. Version
matching is compatibility evidence, not publisher attestation. Carl neither installs
nor updates provider executables.

Verification adds a content attestation: canonical path, platform file identity,
metadata-risk decision, byte length, and complete SHA-256 are bound into the approved
specification and durable request. Unix shebang scripts and Windows `.bat`/`.cmd`
files are rejected in v1 because their interpreter identity would otherwise be
unbound. Native loaders and dynamic libraries are not recursively attested.

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

Provider and verification children are supervised as process groups on Unix and Job
Objects on Windows. These mechanisms support cancellation and bounded cleanup, but
they are native lifecycle containment rather than an OS sandbox or privilege
separation: they do not prevent children from exercising the ambient filesystem,
network, keyring, and same-user process authority that survives the closed
environment and isolated working directory.

On Unix, a hostile descendant can escape ordinary process-group cleanup by creating
a new session with `setsid` (or otherwise moving to another process group). On
Windows, Job Objects contain descendants, but selecting a working directory still
has a residual path-based race after Carl verifies its held directory identity.
Executable verification similarly narrows but cannot eliminate the check-to-exec
window between the last content/identity check and the kernel opening the image.

Candidate comparison detects state that differs during a stable post-run scan,
including same-content file replacement through retained file identities. It cannot
prove that a command never made a transient mutation which it completely restored
before inspection. Verification also says nothing about the current live workspace:
future promotion must independently re-check live path identity, ownership, content
preconditions, the committed verification result, and the exact proposal immediately
before applying bytes.

## Long-horizon full-access boundary

Local owner-selected full access is an accepted risk mode. It allows Carl to make
routine effect decisions without pausing for a new interactive prompt, but it does not
remove the pre-dispatch mediation invariant: a consequential provider request must be
normalized, policy-checked, durably recorded, and allowed before Carl dispatches it.
Secret rejection, workspace path validation, operation idempotency, and uncertain-effect
recovery still apply.

Untrusted remote requests do not inherit local full access. Buzz remains owner-bound,
and remote bypass requires an explicit separately configured trusted binding. A denied
request is not dispatched merely because the provider or repository text asks Carl to
ignore policy.

This is not a complete security sandbox. Carl cannot protect credentials from another
same-user process that can inspect files, memory, process arguments, or provider-owned
state. Full access also cannot make arbitrary third-party build scripts safe. Use a
disposable workspace or an operating-system/container boundary for hostile repositories,
and keep high-value credentials out of the agent's user account.

Durable checkpoints improve recovery and auditability, not confinement. After a crash,
an unresolved `Started` operation becomes uncertain and is not automatically replayed.
Provider context replacement reconstructs only from validated canonical task state; it
does not trust an old transcript as authority.

## Remote channel boundary

The implemented Buzz integration relies on Buzz for signed identity, membership,
inbound deduplication, and the `owner-only` author gate. Carl independently binds the
actor and stable channel found in the accepted ACP event to its durable session and
exact approval records; that binding is not a substitute for Buzz's admission gate.
The restricted publisher keeps relay credentials out of the inbound kernel and
provider paths. See the [Buzz guide](buzz.md).

The planned Telegram gateway uses outbound long polling and one paired owner. Group,
channel, guest, and unpaired updates must be discarded before provider or tool
invocation. Duplicate updates and approval callbacks must be persisted and
deduplicated so retries cannot duplicate consequential work. See the
[Telegram design guide](telegram.md).

For vulnerability reporting, follow the private process in the repository [security policy](../SECURITY.md).
