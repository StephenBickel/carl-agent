# Carl Autonomous Main Promotion Design

Status: approved for implementation
Date: 2026-08-18
Decision owner: Stephen Bickel

## Outcome

Carl's improvement factory may autonomously promote independently validated Level A
changes into `main`, observe each merge for 24 hours, and autonomously revert the exact
merge when a hard regression is detected. `main` remains protected: automation uses
pull requests and required checks and never pushes directly, rewrites history, weakens
the policy for a candidate, deploys, or publishes a release.

This design is the Phase 4 implementation contract for the approved
[improvement-factory design](2026-08-10-codex-carl-improvement-factory-design.md).

## Repository protection

`main` requires an up-to-date pull request with these existing check contexts:

- `Quality`
- `Benchmark contracts`
- `Test (ubuntu-latest)`
- `Test (macos-latest)`
- `Test (windows-latest)`

The rule applies to administrators, requires resolved conversations and linear history,
and prohibits deletion and force-push. Squash is the only merge method. Automatic merge
and deletion of merged branches are enabled. Required human approval count is zero so
the machine-verifiable gates, not operator availability, govern routine promotion.

GitHub's native merge queue is unavailable to a public repository owned by a personal
account. The equivalent repository-local serialization is a single durable promotion
lease plus strict up-to-date required checks. The controller must reconcile the exact
candidate tree and resulting `main` commit before recording a merge.

## Immutable promotion authority

Candidate-controlled code cannot attest to its own success. The protected validator is
outside the candidate worktree and returns a bounded signed receipt. The repository
contains only its public verification key and immutable policy digest; signing material,
holdouts, graders, and merge credentials are not available to builders.

A valid protected receipt binds all of:

- experiment, manifest, policy, and task-set digests;
- exact production parent commit and exact candidate commit and tree;
- executable, adapter, metric pack, model, effort, environment, and toolchain;
- deterministic checks and complete repository tests;
- paired benchmark point estimate and confidence bound;
- guard-suite non-inferiority, workflow and safety results;
- flake and invalid-run accounting, cost, and latency;
- protected holdout aggregate and leakage audit;
- proposal, build, correctness, security, maintainability, and benchmark-integrity
  review digests;
- creation and expiry times and a unique validation identity.

The controller fails closed on a missing, expired, malformed, incorrectly signed, or
identity-mismatched receipt. A candidate that modifies constitutional surfaces—promotion
policy, protected-validation integration, branch rules, workflows, graders, holdouts,
review prompts, or signing configuration—is ineligible for ordinary autonomous
promotion. This one bootstrap change is explicitly owner-authorized and remains subject
to the existing required checks.

## Promotion transaction

Only one experiment may own the mutable-stage lease from building through acceptance or
revert. For a complete production candidate, the controller:

1. fetches `origin/main` and the immutable `origin/experimental/<experiment-id>` commit;
2. verifies the ledger identity, complete receipts, clean branch, protected receipt,
   independent reviews, security scan, and exact current production parent;
3. creates or reconciles one PR identified by experiment and candidate commit;
4. enables squash auto-merge only while the PR head, base, policy digest, and required
   checks still match the reviewed identities;
5. records the GitHub PR and merge identities in append-only review state;
6. verifies the merged `main` tree equals the reviewed candidate tree applied to the
   bound production parent, then enters a 24-hour soak.

A changed base, candidate head, policy, check suite, or receipt cancels eligibility and
requires fresh evidence. Combining experimental branches is a new experiment; no
candidate may borrow evidence from another branch.

## Soak and exact rollback

No new promotion begins while a merge is soaking. The outcome monitor binds observations
to the merge commit and reruns deterministic, benchmark-contract, workflow, safety, and
repository-health checks. A hard gate failure opens an exact `git revert` PR for that
squash commit, subjects it to the same required checks, and enables auto-merge when green.
The controller never resets or force-pushes `main`.

After successful revert, the experiment becomes `reverted`, the last accepted production
baseline is restored, the failed hypothesis is retained as learning, and a different
improvement may begin. If the revert PR cannot become green, promotion remains frozen and
the watchdog reports an integrity incident.

## Automation portfolio and service objectives

- Improvement director: daily product-first search from fresh `origin/main`; advances
  one causal mechanism and never competes with a live promotion or soak.
- Production reviewer/promoter: daily independent reproduction of at most one oldest
  complete candidate; records exactly one durable disposition and promotes only an
  eligible exact commit.
- Promotion watchdog: every two hours; reconciles leases, PR/check/merge identity, soak,
  and rollback without inventing evidence.
- Outcome monitor: daily; audits main health and automation outcomes rather than merely
  confirming schedules exist.
- Feature report: Mondays; lists merged, experimental, rejected, and reverted features,
  commits, PRs, benchmark deltas, security results, automation health, and blockers.

The watchdog flags a missed daily run after 36 hours, a missed two-hour run after 4
hours, an unreconciled mutable lease after its expiry, a promotion without complete
receipts immediately, a soak observation gap after 26 hours, and an unstarted hard-gate
rollback after 2 hours. Routine recovery is autonomous. Missing credentials, unavailable
infrastructure, invalid signatures, and broken branch protection fail closed.

## Bootstrap sequence

1. Protect `main` with the currently reporting required checks and repository settings.
2. Land the controller contracts, signed-receipt verifier, append-only promotion events,
   exact-revert logic, tests, workflows, and operating documentation through a protected
   PR.
3. Provision the private validator/signing boundary and prove candidate escape and
   forgery tests fail.
4. Make the protected-validation status a required check only after it reports reliably
   on pull requests.
5. Enable ordinary autonomous promotion and rollback automations. Until steps 2–4 are
   verified, reviewer automations may retain candidates but must not auto-merge them.

## Acceptance criteria

- Branch protection is remotely verified and a direct push, force-push, and deletion are
  denied.
- Promotion records are replayable and cryptographically bound to exact identities.
- Duplicate ticks reconcile rather than duplicate PR, merge, or revert actions.
- Stale-base, altered-head, forged/expired receipt, constitutional-diff, and concurrent
  promotion tests fail closed.
- A harmless synthetic candidate passes PR creation, auto-merge, merge reconciliation,
  soak, and acceptance in a non-production fixture.
- Each rollback threshold creates one exact revert and restores the preceding tree.
- Weekly reporting and automation-health monitoring are reproducible from durable state.

