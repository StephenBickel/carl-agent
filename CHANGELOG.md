# Changelog

All notable changes to Carl will be recorded here. The project is pre-alpha and has not made a supported release.

## Unreleased

### Changed

- Renamed the pre-alpha ArcWren foundation to Carl, with the package `carl-agent` and executable `carl`.
- Codex subscription authentication now uses the official CLI's explicit `file`
  credential store inside Carl's isolated provider home, with metadata-only safety
  validation and no host-keyring dependency.

### Added

- Public project, contribution, conduct, security, architecture, configuration, and Telegram documentation.
- Architecture decision records for event-sourced execution, the single-process v1 boundary, documented authentication only, and provider-owned subscription authentication.
- A documentation contract covering required public files, local README links, CLI command names, and critical status/security statements.
- A provider-neutral event, identifier, error, and budget foundation.
- SQLite WAL persistence with append-only events and checksum-verified migrations.
- A local curated-memory system with owner/agent and global/workspace/session
  isolation; profile, preference, fact, goal, and expiring episode kinds; bounded
  explainable BM25-style retrieval; conflict replacement; approval-gated proposals;
  secret and prompt-injection rejection; configurable limits; versioned JSON export;
  secure hard deletion; legacy migration; and a complete `carl memory` CLI. The
  default requires no network, embedding model, account, or paid dependency.
- Persistent memory-proposal review, approval, and rejection commands keep agent
  suggestions transparent and controllable across restarts.
- A provider interface and deterministic scripted provider for offline tests.
- Isolated provider sidecar supervision with fixed Codex and Grok homes, pinned
  executable compatibility, and cross-process data-root exclusivity.
- Codex-owned ChatGPT subscription authentication and Grok-owned SuperGrok or eligible
  X subscription authentication; Carl never receives their tokens.
- Seven `carl auth` status/login/logout commands with deterministic safe JSON status
  and foreground-only authentication mutation.
- An inert, library-level subscription-backed Codex exec adapter with layered
  model/reasoning settings, pinned CLI compatibility, private stdin task delivery,
  bounded normalized JSONL events, and supervised process-tree cancellation.
- A normalized external-agent policy that defaults safe requests to owner approval
  and denies live-workspace, environment, and provider-network authority drift.
- Expiring single-use approvals bound to the exact actor, session, turn, tool call,
  request digest, and lifetime.
- Non-retaining secret detection that reports only stable rule classifications.
- Capability-built sanitized staging with deterministic content-addressed manifests,
  strict file/byte/path-metadata bounds, physical root-disjointness checks,
  protected-path exclusions, and automatic cleanup.
- Owner-private, read-only, content-addressed baseline and proposal artifacts with
  verified reopen/rehash, sealed source-identity evidence, startup reachability
  cleanup, aggregate storage limits, plus a process-free one-file exact-replacement
  inspector.
- An inert independent-verification boundary that reconstructs fresh candidates from
  sealed artifacts, binds the approved native executable and literal argv, runs with
  a credential-free environment through a bounded process-tree supervisor, rejects
  candidate mutation and unsafe diagnostics, persists request/result evidence
  atomically, and mints verified-proposal capabilities only after commit.
- Subscription-backed Codex app-server execution through `carl acp`, pinned to Codex
  CLI `0.146.0`, with provider-reported model/reasoning choices and no API-key
  fallback. The ACP path is CLI-reachable and owns durable provider turns.
- A bounded ACP v1/v2 stdio server with honest capability negotiation, multiple
  sessions, configuration updates, assistant/tool/diff updates, steering,
  cancellation, malformed-frame isolation, and JSON-only stdout.
- Durable ACP/Buzz frontend bindings, stable workspace/channel claims, permission
  state, hashed remote codes, and monotonic outbound delivery records.
- Claude/Codex-compatible `plan`, `default`, `acceptEdits`, `dontAsk`, and
  `bypassPermissions` modes. Remote bypass requires a later one-time confirmation;
  local dangerous bypass must be explicit.
- Exact remote command and file approvals bound to actor, frontend session, Carl
  session, turn, tool/provider request, workspace, request digest, and expiry. Codes
  are atomically single-use and provider turns resume without replay.
- Buzz compatibility pinned to commit
  `44456e200e3ca6a5d2882b58b447b80474041347`, including structural context parsing,
  an owner-only recommended setup, restricted `carl-buzz-mcp` message/diff
  publication, credential isolation, restart safety, and deterministic real-process
  end-to-end tests.
- Cross-platform public CI coverage for the pinned Buzz ACP fixtures and end-to-end
  process path without network access or credentials.

### Not yet available

- Native model execution remains unavailable.
- The interactive TUI, Telegram gateway, Grok execution, native Carl tool loop,
  stale-safe live-workspace promotion, and general native HTTP model adapters remain
  unavailable. ACP coding uses Codex app-server capabilities under Carl's kernel and
  exact approval boundary.
