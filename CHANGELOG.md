# Changelog

All notable changes to Carl will be recorded here. The project is pre-alpha and has not made a supported release.

## Unreleased

### Changed

- Renamed the pre-alpha ArcWren foundation to Carl, with the package `carl-agent` and executable `carl`.

### Added

- Public project, contribution, conduct, security, architecture, configuration, and Telegram documentation.
- Architecture decision records for event-sourced execution, the single-process v1 boundary, documented authentication only, and provider-owned subscription authentication.
- A documentation contract covering required public files, local README links, CLI command names, and critical status/security statements.
- A provider-neutral event, identifier, error, and budget foundation.
- SQLite WAL persistence with append-only events and checksum-verified migrations.
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

### Not yet available

- Native model execution remains unavailable.
- Subscription-backed coding is not exposed through the CLI: no subscription coding
  task is CLI-reachable until independent verification, stale-safe promotion, and
  run-engine orchestration are implemented.
