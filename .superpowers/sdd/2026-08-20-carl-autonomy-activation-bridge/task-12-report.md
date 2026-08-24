## 2026-08-23 protected soak fix round

- RED: the protected-probe tests failed 2/2 against candidate-owned Cargo targets/config, pytest project/hooks, and benchmark execution; the cadence tests failed 2/2 because no complete signed chain or gap/replay/rebinding checks existed.
- Fix: Rust probes now replace candidate manifests, lockfile, targets, Cargo config, and build hooks with protected-revision inputs; Python tests run from a protected project with isolated config/plugin discovery; benchmark smoke runs the protected harness.
- Fix: soak receipt schema v2 carries a signed five-observation hash chain anchored exactly at merge. Four intervals must each be 6h through 6h30m, yielding a 24h through 26h acceptance window. Prefix splices, duplicate observations, receipt replay, request/outcome/merge rebinding, incomplete chains, and trusted time beyond 26h fail closed.
- Verification: focused Python 39 passed; full locked Python 1,592 passed and 106 skipped; full locked Rust 796 passed; actionlint, YAML parse, all workflow shell and embedded-Python syntax, Ruff, Ruff format, and `git diff --check` passed.
- Live boundary: the protected soak signer/provider must be commissioned to emit `carl.soak-observation.chain-receipt.v2`; no workflow, deployment, release, push, merge, or live provider action was performed.
