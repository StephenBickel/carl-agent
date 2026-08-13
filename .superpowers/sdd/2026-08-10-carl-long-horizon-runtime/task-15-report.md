# Task 15 report: publish long-horizon runtime guarantees

## Documentation

- Updated the root security policy after the owner approved the exact replacement.
  It now describes the implemented subscription-backed coding path, owner-default
  full access as accepted risk, pre-dispatch mediation, remote denial, credential
  ownership, crash behavior, and explicit sandbox limitations.
- Updated the README, architecture, configuration, Buzz, and detailed security guides
  to match the implemented task service, checkpoints, metrics, provider replacement,
  recoverable maintenance, task budgets, and owner controls.
- Added `docs/long-horizon-tasks.md` with admission, control, checkpoint, compaction,
  restart, evidence, and limitation guidance.
- Added `docs/benchmarks.md` with deterministic and subscription-backed methodologies,
  sanitized artifact rules, independent verification, and the minimum thirty-pair
  requirement for comparative claims.
- Added documentation contracts that pin the implemented commands, accepted risks,
  lifecycle controls, evaluation limits, and non-superiority language.

## Deterministic release gate

All required commands ran once at the documentation branch head and exited zero:

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --doc
cargo test --locked --all-features
cargo test --locked --test buzz_acp_contract --test buzz_end_to_end --test long_horizon_eval
cargo deny check
```

The all-features suite and the dedicated gate reported no test failures. The dedicated
long-horizon target passed all 8 tests, including the 100-epoch uninterrupted versus
restarted replay proof. `cargo deny` reported only the repository's existing permitted
duplicate-version warnings for `hashbrown` and `windows-sys`; advisories, bans,
licenses, and sources passed.

## Repository audit

No OAuth state, credential, provider transcript, prompt, live result, disposable
workspace, or test-owned process is included. The public benchmark documentation does
not claim a completed post-fix monolithic paired run or harness superiority.
