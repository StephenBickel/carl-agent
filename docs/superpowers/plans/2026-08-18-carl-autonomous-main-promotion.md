# Carl Autonomous Main Promotion Implementation Plan

> Execute this plan with `superpowers:executing-plans`; implement behavior with strict
> test-driven development and verify before completion.

**Goal:** Protect `main` and deliver the fail-closed Phase 4 contracts, controller,
rollback path, monitoring, and scheduled operating loop needed for autonomous Carl
improvement without direct pushes or human approval in the routine path.

**Architecture:** Extend the append-only experiment graph with immutable protected
validation, promotion, merge, soak, acceptance, and revert events. A deterministic
controller verifies externally signed receipts and emits intended GitHub operations;
the GitHub gateway performs idempotent PR/auto-merge/revert reconciliation. Repository
rules remain outside candidate authority.

**Tech stack:** Python 3.12, pytest, stdlib subprocess/JSON/hash primitives, Git/GitHub
CLI boundary, GitHub Actions, Codex automations.

---

### Task 1: Lock repository protection and constitutional policy

**Files:**
- Modify: repository settings and `main` branch protection through GitHub API
- Modify: `docs/benchmarks.md`

1. Capture the current repository settings, branch protection, check contexts, and main
   commit.
2. Enable squash-only auto-merge, merged-branch deletion, and protected `main` with the
   five currently reporting strict required checks, admin enforcement, conversation
   resolution, linear history, and no deletion/force-push.
3. Read the remote settings back and compare every field with the intended policy.
4. Document the operating boundary and native merge-queue limitation.

### Task 2: Add protected validation and promotion graph contracts

**Files:**
- Create: `benchmarks/src/carl_bench/promotion.py`
- Modify: `benchmarks/src/carl_bench/experiment.py`
- Create: `benchmarks/tests/test_promotion.py`
- Modify: `benchmarks/tests/test_experiment.py`

1. Write failing tests for canonical protected receipts, signature/expiry/identity
   rejection, constitutional-diff rejection, and stale-production-parent rejection.
2. Run the focused tests and confirm failures name missing Phase 4 behavior.
3. Implement the minimal immutable receipt and verification contracts; rerun to green.
4. Write failing graph-replay tests for protected validation, promotion request/record,
   merge reconciliation, soak observation, acceptance, and exact revert.
5. Implement minimal new events and state invariants; rerun focused and full benchmark
   tests.

### Task 3: Add idempotent GitHub promotion and exact-revert gateway

**Files:**
- Create: `benchmarks/src/carl_bench/github_promotion.py`
- Create: `benchmarks/tests/test_github_promotion.py`
- Modify: `benchmarks/src/carl_bench/cli.py`
- Modify: `benchmarks/tests/test_cli.py`

1. Write failing boundary tests using a complete fake GitHub CLI response set for PR
   discovery/creation, head/base reconciliation, required-check eligibility, auto-merge,
   merge identity, and one exact revert PR.
2. Confirm each test fails for the absent behavior.
3. Implement deterministic command construction and JSON validation without exposing a
   general shell surface; rerun to green.
4. Add narrow reconcile/status CLI commands test-first, then run the full suite.

### Task 4: Add protected workflows, soak, and monitoring contracts

**Files:**
- Create: `.github/workflows/promotion-control.yml`
- Modify: `.github/workflows/security.yml`
- Create: `benchmarks/src/carl_bench/promotion_monitor.py`
- Create: `benchmarks/tests/test_promotion_monitor.py`
- Modify: `benchmarks/tests/test_integration_contract.py`
- Modify: `docs/benchmarks.md`

1. Write failing tests for stale-run, stale-lease, incomplete-evidence, soak-gap, rollback
   SLA, and healthy-state outcomes.
2. Implement the deterministic monitor and machine-readable report.
3. Add workflows that report on PRs but hold no validator signing secret in candidate
   jobs. Keep protected validation non-required until the external signer is provisioned.
4. Replace Phase 3 documentation assertions with verified Phase 4 boundaries and run
   workflow-contract tests.

### Task 5: Configure autonomous operating automations

**Files:**
- Update durable automation definitions through the Codex automation API
- Update: automation memory files outside the repository

1. Update the daily improvement director to start from current production, prioritize
   product value, and yield to live promotion/soak leases.
2. Update the daily independent reviewer to promote only exact eligible commits once the
   protected validator is enabled; otherwise retain and report missing gates.
3. Create a two-hour promotion/rollback watchdog, daily outcome monitor, and Monday
   weekly feature report in the Carl project.
4. Read back every definition, cadence, status, project, and prompt; ensure no duplicate
   automation exists.

### Task 6: Security review, end-to-end verification, and protected PR

**Files:** all changed files

1. Run a fresh security diff scan over `origin/main...HEAD` and resolve every applicable
   finding test-first.
2. Run Ruff, all benchmark tests, all-feature Rust tests, workflow-contract tests, and
   repository-cleanliness checks.
3. Exercise promotion and rollback against controlled fake GitHub responses and verify
   idempotency and fail-closed behavior.
4. Commit the implementation, publish `codex/autonomous-main-promotion`, open a draft PR
   to `main`, and enable auto-merge only if every bootstrap gate is satisfied.
5. Record exact commits, artifact digests, remote protection, automation definitions,
   remaining external-validator gate, and rollback instructions in durable memory.

