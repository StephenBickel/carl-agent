# Carl Dry-Run Experiment Graph Implementation Plan

**Goal:** Add the first safe control-plane slice of the Codex-operated Carl Improvement
Factory: an immutable experiment manifest, append-only/replayable event ledger, exclusive
stage leases, role-output quorum checks, budget accounting, and deterministic simulated
decisions that cannot mutate Carl or GitHub.

**Architecture:** Keep the factory in the Python `benchmarks` project, outside Carl's Rust
runtime. Store normalized facts in SQLite as a hash-chained append-only event stream and
derive all state by replay. Validate immutable manifests and bounded role outputs before
recording them. A dry-run director may identify the next eligible action and calculate a
simulated decision, but it has no builder, protected-holdout, GitHub, merge, or credential
adapter.

**Safety boundary:** This phase is read-only with respect to Carl and GitHub. Protected
holdouts remain outside this repository and are not simulated with public tasks. A future
protected validator will return a signed aggregate scorecard; a future promotion controller
will consume it. No command in this plan opens a PR, merges, reverts, or changes product code.

**Status:** Completed and verified on 2026-08-10.

---

## Task 1: Immutable graph contracts and replay reducer

**Files:**

- Create: `benchmarks/src/carl_bench/experiment.py`
- Create: `benchmarks/tests/test_experiment.py`

1. Write failing tests for manifest validation and ancestry, immutable digests, legal transitions,
   terminal states, UTC preregistration, stage-attempt idempotency, and deterministic replay.
2. Run the focused tests and confirm failures are caused by the missing implementation.
3. Implement closed enums and frozen value objects for manifests, events, role outputs,
   budgets, leases, and projections.
4. Implement the transition reducer with the exact state graph from the approved design.
5. Run the focused tests until green, then refactor without changing behavior.

## Task 2: Append-only SQLite ledger and recovery

**Files:**

- Create: `benchmarks/src/carl_bench/ledger.py`
- Create: `benchmarks/tests/test_ledger.py`

1. Write failing tests for schema creation, append/replay, event hash-chain validation,
   duplicate-attempt idempotency, conflicting duplicate rejection, projection rebuild, and
   corruption detection.
2. Implement an owner-local SQLite ledger with restrictive file permissions, explicit
   transactions, monotonic sequence numbers, and no update/delete API.
3. Persist the canonical manifest once and reject replacement after building begins.
4. Verify a newly opened process reconstructs the identical projection and digest.

## Task 3: Leases, role quorums, and budgets

**Files:**

- Modify: `benchmarks/src/carl_bench/experiment.py`
- Modify: `benchmarks/src/carl_bench/ledger.py`
- Modify: `benchmarks/tests/test_experiment.py`
- Modify: `benchmarks/tests/test_ledger.py`

1. Write failing tests proving only one experiment owns a mutable-stage lease, an active
   lease cannot be stolen, stale recovery requires explicit reconciliation, proposal review
   needs two approvals and no hard objection, independent review needs three approvals and
   no hard finding, and daily/weekly/experiment budgets fail closed.
2. Implement deterministic lease and quorum reducers, exact integer-microdollar budget arithmetic,
   UTC daily/rolling-week accounting, and the 24-hour elapsed gate.
3. Add simulated decision reasons for every missing or failed prerequisite.

## Task 4: Operator CLI and public-safe dry-run report

**Files:**

- Modify: `benchmarks/src/carl_bench/cli.py`
- Create: `benchmarks/tests/test_experiment_cli.py`
- Modify: `docs/benchmarks.md`
- Modify: `benchmarks/README.md`
- Modify: `README.md`

1. Write failing CLI tests for `experiment init`, `experiment record`, `experiment status`,
   and `experiment decide` using a temporary private ledger.
2. Add strict JSON manifest input and bounded sanitized JSON status/decision output.
3. Make every mutation command require a unique stage-attempt ID; repeat delivery is a no-op
   only when the canonical event matches exactly.
4. Document the two-hour director cadence as a future Codex automation and state that the
   current director is manual/dry-run only.

## Task 5: Verification and delivery

1. Run focused graph tests, the full Python suite, Ruff, offline benchmark smoke, full Cargo
   tests, formatting, and clippy.
2. Review the complete diff for control-plane leakage, secret/holdout exposure, mutable
   history, optimistic failure handling, and claims of autonomy that do not exist.
3. Commit and push the feature branch. Keep the existing PR unmerged: phase three must prove
   isolated builders, independent reviews, protected validation, and rollback drills first.

## Exit criteria

- [x] Replaying the same verified event stream always yields the same state and decision digest.
- [x] Invalid transitions, conflicting duplicate attempts, hash-chain corruption, lease theft,
  quorum failures, and exhausted budgets block deterministically.
- [x] The active manifest cannot be rewritten after building begins.
- [x] The public dry-run status contains no role prose, benchmark prompts, holdout content,
  secrets, raw paths, or model output.
- [x] The CLI and CI remain offline and credential-free.
- [x] No Carl source, Git branch, PR, merge queue, protected validator, or external SaaS account is
  mutated by the graph.
