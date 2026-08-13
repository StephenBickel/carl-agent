# Security Policy

Carl is pre-alpha software with an implemented subscription-backed Codex coding path,
durable task runtime, tool mediation, and Buzz integration. It can execute consequential
code under the current operating-system account. Review the boundaries below before use.

## Supported versions

No stable release is currently supported. Security fixes are applied to the default development branch. When releases begin, this section will list supported versions explicitly.

## Reporting a vulnerability

Use the repository's private **Report a vulnerability** / private vulnerability reporting flow when it is available. Include the affected revision, impact, prerequisites, a minimal reproduction, and sanitized logs. Do not include real API keys, bot tokens, private conversations, or unrelated local data.

If private vulnerability reporting is unavailable, open a public issue containing only a request for a private maintainer contact. Do not disclose exploit details in that issue. Maintainers will acknowledge reports and coordinate validation, remediation, and disclosure as capacity permits; pre-alpha status means no response-time guarantee is offered.

## Implemented security boundaries

Local ACP uses owner-default full access because Carl is designed to make routine coding
decisions for its owner. This is an accepted-risk mode, not an assertion that generated
commands are safe. Every consequential provider effect must still cross Carl's
pre-dispatch mediation boundary, with durable intent, policy classification, path and
secret checks, and an allow or deny decision before dispatch.

Untrusted remote requests remain denied by default. Buzz admission is owner-bound, and
remote bypass requires a separate explicit trusted configuration. Approval codes are
single-use and bound to the actor, channel, session, turn, request, working directory,
and request digest.

Carl delegates ChatGPT subscription login and credential storage to the pinned Codex
executable. It does not implement undocumented OAuth, accept an OpenAI API-key fallback
for ACP, or read subscription bearer and refresh tokens. Credentials, provider
transcripts, prompts, command output, and live-run workspaces must never be committed.

Durable checkpoints, idempotency, process-tree cleanup, and fail-closed recovery reduce
duplicate effects and improve auditability. An unresolved `Started` operation is not
automatically replayed after a crash.

## Out of scope

Carl is not a complete security sandbox. It cannot defend secrets from other same-user
processes, a compromised provider executable, malicious host tooling, kernel-level
attackers, or code already authorized to run with the owner's ambient authority.
Use a disposable workspace or a stronger operating-system/container boundary for
hostile repositories. Never use Carl to execute code you would not trust under the host
account.

The complete trust model, remote-channel boundary, and current limitations are in
[docs/security.md](docs/security.md).
