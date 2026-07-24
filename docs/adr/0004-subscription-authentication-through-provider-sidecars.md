# ADR 0004: Subscription authentication through provider-owned sidecars

- Status: Accepted
- Date: 2026-07-24

## Context

Carl must support two distinct ways to pay for model access:

1. provider API credentials used by Carl's native provider loop; and
2. consumer subscriptions authenticated through OpenAI or xAI OAuth.

Those mechanisms are not interchangeable. OpenAI does not document a public flow that
turns a ChatGPT subscription into a bearer token for an arbitrary third-party
Responses API client. OpenAI does document Codex app-server as an embedding interface
for custom products, including managed ChatGPT browser and device-code login, and
documents `codex mcp-server` for using Codex as a specialist inside another agent.

xAI publicly supports SuperGrok and eligible X subscriptions in OpenCode and Kilo
through OAuth. Its OIDC metadata documents authorization-code, refresh-token, and
device-code grants, but it does not advertise dynamic client registration. OpenCode
and Kilo use an xAI client identity that xAI has explicitly endorsed for those
products. A public client identifier is application identity, not permission for Carl
to impersonate that application.

Both OpenAI Codex and Grok Build expose full coding-agent protocols. Neither supported
subscription boundary is a raw model-sampling API in which Carl can supply arbitrary
messages and tools while retaining sole ownership of the inner turn loop.

## Decision

Carl separates native providers from subscription-backed delegates.

### Native providers

Native providers implement Carl's normalized `Provider` trait. Carl owns context
assembly, tool proposals, policy, approvals, execution, persistence, replay, and
continuation.

- OpenAI Responses uses a user-supplied OpenAI Platform API key.
- xAI Responses uses a user-supplied xAI API key.
- OpenAI-compatible local endpoints may use no credential.

API keys are referenced by configuration and loaded from an environment variable or
Carl's credential store. Subscription tokens are never accepted by these adapters.

### OpenAI subscription delegate

Carl uses a dedicated, provider-owned Codex sidecar:

- a version-pinned `codex app-server` process over local stdio owns ChatGPT browser or
  device-code login and reports only login status, plan type, and rate limits;
- stable `codex mcp-server` exposes Codex as a policy-routed delegated tool inside
  Carl's native loop;
- every Codex process receives a Carl-specific `CODEX_HOME`, which isolates
  filesystem-backed configuration and state;
- Codex stores and refreshes its own tokens in the operating-system keyring;
- Carl never reads, receives, copies, logs, or forwards a Codex bearer or refresh token.

OpenAI does not document the OS-keyring entry as namespaced by `CODEX_HOME`; its login
cache may be shared with other Codex surfaces for the same OS user. Carl therefore
does not claim keyring isolation, and its logout UI must warn that logging out can
affect another Codex CLI or IDE session.

The delegated tool runs against a content-scanned staging copy, never the live
workspace, and returns bounded exact-replacement proposals for existing text files.
Each proposal is inert until Carl submits it through the native patch path with its own
policy, approval, stale-state, and verification checks. V1 delegate proposals do not
create, delete, or rename files.

### Grok subscription delegate

Carl uses the official Grok Build process boundary:

- `grok --no-auto-update login` or `grok --no-auto-update login --device-auth` owns
  xAI OAuth;
- `grok --no-auto-update agent stdio` exposes the authenticated Grok coding agent
  through Agent Client Protocol (ACP) as a policy-routed delegated tool inside Carl's
  native loop;
- every Grok process receives a Carl-specific `GROK_HOME`;
- Grok owns token storage and refresh in its provider-managed
  `$GROK_HOME/auth.json`; Carl creates the home owner-only and requires the provider
  credential file to remain a regular, non-linked owner-only file without reading it;
- Carl consumes typed ACP events and never reads or forwards OAuth tokens;
- the Grok delegate runs against the same kind of content-scanned staging copy and can
  only return inert exact-replacement proposals.

A native xAI OAuth provider may be added after xAI registers or explicitly authorizes a
Carl OAuth client identity and redirect URI. Until then Carl will not reuse the Grok
CLI, OpenCode, or Kilo client identity.

### Shared invariants

- Carl's sidecar control protocols run as local child processes over stdio only in V1.
- Carl never exposes provider control protocols on a network listener.
- A provider-owned browser login may create its own short-lived loopback OAuth
  callback listener; device-code login remains available when a callback listener is
  unsuitable.
- Executable discovery, version checks, installation, and upgrades are explicit.
- Carl never silently installs or updates a provider executable.
- Each adapter pins a tested protocol/version range and fails closed on incompatible
  handshakes.
- Sidecar stderr, events, and errors pass through Carl's redaction boundary.
- Cancellation terminates the active request and then the child process tree.
- Subscription delegates cannot be invoked until the policy, bound-approval, sandbox,
  secret-filtering, and staging-copy foundations exist.
- A delegate invocation is a networked external-agent tool that defaults to `ask`.
- Sidecars receive no direct capability to mutate the live workspace, access its
  credential/configuration files, or execute project hooks and plugins.
- Files containing high-confidence secret material are rejected before staging, even
  when their names and extensions would otherwise be eligible.
- Subscription delegates are identified in UI, tool results, and evaluation reports;
  Carl never claims their inner work was executed or verified by the native Carl loop.
- A successful OAuth login and a usable subscription entitlement are separate states.

## Consequences

- Users can use eligible ChatGPT and Grok subscriptions without handing Carl raw
  subscription credentials.
- Carl's native loop remains independently testable, replayable, and provider-neutral.
- Subscription operation depends on separately installed provider executables and
  their supported protocols.
- Some behavior differs between native and delegated modes; capability reporting must
  make that difference visible.
- Direct native Grok OAuth requires coordination with xAI before it can be a stable,
  enabled-by-default feature.
- ADR 0003 remains in force: no undocumented OAuth and no reuse of another
  application's credential cache.

## Primary references

- [OpenAI Codex authentication](https://learn.chatgpt.com/docs/auth)
- [OpenAI Codex app-server protocol](https://learn.chatgpt.com/docs/app-server)
- [Running Codex as an MCP server](https://learn.chatgpt.com/docs/mcp-server)
- [xAI Grok Build CLI reference](https://docs.x.ai/build/cli/reference)
- [xAI Grok Build headless and ACP integration](https://docs.x.ai/build/cli/headless-scripting)
- [xAI Grok Build settings and `GROK_HOME`](https://docs.x.ai/build/settings)
- [xAI Grok Build enterprise authentication and security controls](https://docs.x.ai/build/enterprise)
