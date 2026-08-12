# Task 14E report: reusable paired live-endurance runner

## Implementation

- Added `scripts/live-codex-long-horizon.mjs`, an opt-in paired runner for one
  disposable Rust fixture through Carl and the trusted direct-Codex baseline. The
  production command admits only canonical release Carl/Codex executables, an
  owner-private data root, an explicit model/effort, and a bounded 2..=8-hour wall
  limit. Task input is byte-identical and protocol/stdin-only for both arms.
- Added the shared `scripts/lib/live-runner-core.mjs` boundary for closed child
  environments, fixture creation/copy/provenance, strict metrics/status/maintenance
  parsing, monotonic evidence, process-group cleanup, signal cancellation, exact
  result validation, and atomic mode-0600 writes. The existing live ACP smoke now
  uses the same closed environment.
- The generated fixture includes a failing whitespace regression, cross-file
  refactor, documentation clause, early identifier, once-only process sentinel, and
  twenty immutable high-context audit chapters. Each chapter is read in bounded
  chunks; its ordered append-only marker must be followed by a changed authoritative
  checkpoint. Batched/skipped markers and mutated audit inputs fail closed.
- Carl orchestration uses service-backed ACP, exact metrics/status schemas, two
  accepted steers, recoverable maintenance, fresh post-load baselines, post-restart
  provider/epoch progress, one-at-a-time context-loss replacement evidence,
  compaction notifications, durable progress, and the independent completed-workspace
  verifier. The direct arm uses `carl baseline codex` and the same verifier.
- Result metadata has an exact bounded schema, contains no prompt/output/diff/path or
  runtime identifiers, uses a unique filename, and is written only after admission,
  parity, evidence, and child-reaping checks succeed. One pair is explicitly not a
  superiority claim; thirty independent pairs are required before comparison claims.
- `.gitignore` excludes local live evidence. No live result, credential, task text,
  provider transcript, or workload artifact is committed.

## Offline TDD and review fixes

The docs contract first failed because the runner did not exist. The offline
`--self-test` then drove strict admission, fixture isolation, identical routing,
evidence derivation, sanitization, atomic output, and cleanup. Independent review
found and the implementation corrected:

1. the ACP metrics wrapper and strict metrics/status/maintenance response schemas;
2. synthetic restart/context proof, mixed Carl/direct elapsed timing, and constant
   parity/duplicate-effect claims;
3. weak fixture topology and mutable public-test verification;
4. PID-only timeout cleanup, deterministic result overwrite, and prompt-in-fixture;
5. provider-defined completion without independent ordered chapter evidence;
6. pre-maintenance restart baselines and multi-loss replacement overclaiming;
7. unbounded post-SIGKILL waits and no never-exits/no-artifact regression; and
8. compaction/checkpoint conflation and delayed-notification ordering.

The final design separates the twenty-compaction endurance gate from the per-chapter
checkpoint oracle. The checkpoint baseline is captured from authoritative task status
only when one new marker is observed, and only a later changed checkpoint completes
that chapter. Final independent review reported no Critical, Important, or Minor
findings.

## Verification

```text
node --check scripts/lib/live-runner-core.mjs
node --check scripts/live-codex-long-horizon.mjs
node --check scripts/live-codex-acp-smoke.mjs
PASS

env -i PATH="$PATH" node scripts/live-codex-long-horizon.mjs --self-test
{"schema_version":1,"passed":true,"checks":7}

cargo test --locked --test docs_contract
PASS: 17 passed, 0 failed

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS

cargo fmt --all -- --check
PASS

git diff --check
PASS
```

Per the task boundary, no live provider/OAuth/network run, two-hour endurance run,
full Rust suite, or `SECURITY.md` edit was performed. Task 14F owns the explicitly
authorized live paired acceptance run.
