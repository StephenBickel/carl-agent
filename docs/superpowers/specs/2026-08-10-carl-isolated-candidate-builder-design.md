# Carl Isolated Candidate Builder Design

## Status and intent

This document specifies the phase-three design of the Codex-operated Carl Improvement Factory. The
shipped foundation turns an approved dry-run experiment into one isolated candidate commit and
binds deterministic evidence to it. Paired promotion evidence, promotion reviews, workspace
disposal, and draft publication remain planned and are mechanically disabled pending an isolated
signer and executable provenance.

The user approved the phase-three direction after phase two was delivered and explicitly
asked execution to continue without additional approval pauses. This design therefore
resolves implementation details from the factory constitution while keeping publication disabled.

## Goals

- Prepare one disposable Git worktree from the manifest's exact parent commit.
- Let a Codex automation act as the builder without giving the graph a second hidden model
  invocation or putting GitHub credentials in builder context.
- Reject changes outside the manifest's target surface or inside its forbidden surface.
- Run only preregistered deterministic checks resolved through a trusted command registry.
- Seal one immutable candidate commit and content-addressed evidence bundle.
- Define the future contracts for paired comparison, role-specific reviews, and draft publication.
- Fail closed until those contracts are backed by isolated signing, build provenance, and
  authenticated lease ownership.

## Non-goals

- Autonomous merge, auto-merge, release, deployment, rollback, or experiment acceptance.
- Pretending public tasks are protected holdouts.
- Giving the builder raw reviewer prompts, promotion thresholds, merge credentials, or
  protected task material.
- Treating a draft PR as proof that a candidate is promotable.
- Supporting arbitrary shell snippets from manifests or model output.
- Building a generic agent-plugin framework before the Codex-operated path works end to end.

## Selected architecture

The controller uses a prepare/edit/seal workflow.

1. `candidate prepare` verifies the experiment is in `building`, owns a live lease, and has
   proposal quorum. It creates `codex/experiment-<experiment-id>` in a fresh worktree at the
   manifest's exact parent commit. It emits a private builder request containing the worktree
   path, immutable manifest digest, allowed surfaces, and check identifiers.
2. The active Codex task edits that worktree. The builder has no GitHub operation in its
   contract. This preserves the user's desired topology: Codex improves Carl, while Carl does
   not recursively mutate itself in installed copies.
3. `candidate seal` reads the real Git index and filesystem, rejects special files and
   out-of-scope paths, runs trusted argv-based checks without a shell, stores bounded evidence,
   commits the candidate, and appends a candidate event to the ledger.
4. `run-attested` can produce diagnostic HMAC-bound measurements from separate clean checkouts. It
   does not prove that the invoked agent executable was freshly built from the named checkout and
   does not isolate its key from same-UID workers, so it has no promotion authority.
5. The future paired, review, publication, and disposal contracts are present for adversarial
   testing, but their CLI entry points, direct APIs, and reducer events reject unconditionally.
6. `candidate status` reports `await_isolated_signer`; no current state advertises publication.

The graph remains the authority. Chat text, process exit success, a Git branch, and a GitHub PR
are observations until normalized evidence is appended to the hash-chained ledger.

## Component boundaries

### Private artifact store

`artifacts.py` owns an owner-private content-addressed store outside the Carl repository. Objects
are regular files named by lowercase SHA-256, created without following symlinks, written once,
and verified on every read. The ledger records only digest, byte size, media type, and evidence
kind. Absolute owner paths and raw evidence never enter public status.

### Candidate contracts and reducer integration

`candidate.py` defines frozen contracts for prepared workspaces, sealed candidates,
deterministic-check results, paired-evaluation bindings, review packets/attestations, draft PRs,
and public eligibility decisions. Every contract has exact keys, bounded fields, canonical JSON,
and a stable digest.

The experiment reducer defines normalized events for workspace preparation, candidate sealing,
deterministic evidence, and the future promotion path. Mutable foundation events carry the exact
active lease owner and acquisition attempt. State transitions fail closed unless their required
evidence is present:

- leaving `building` requires a sealed candidate at the manifest parent;
- leaving `deterministic_validation` requires all preregistered checks to pass;
- paired evidence, review packets/attestations, draft authorization/publication, and publication
  workspace disposal are rejected with `experimental_publication_disabled`;
- phase three cannot transition from `paired_evaluation` to `holdout_validation`. The protected
  validator introduced in phase four is the only component that may satisfy that edge.

Existing ledgers are replayed through the same rule, so a legacy publication event fails closed.
New foundation events use exact payload contracts and stage-attempt idempotency. Candidate evidence
cannot be replaced; a changed commit requires a child experiment.

### Git workspace manager

`candidate_git.py` is the only component allowed to manipulate candidate worktrees and branches.
It calls Git with argv arrays, never a shell. It verifies:

- repository and worktree roots are absolute, regular directories and not symlinks;
- the repository is a Git worktree with the expected configured remote;
- the parent is an exact full commit and exists locally;
- the experiment branch name is derived, not supplied by model output;
- no existing branch or registered worktree points somewhere ambiguous;
- changed paths are canonical repository-relative paths;
- every change is within a target surface and outside every forbidden surface;
- candidate entries are regular files or directories, never symlinks, devices, sockets, or FIFOs;
- the sealed commit has exactly the declared parent and the worktree is clean afterward.

Cleanup is explicit and idempotent. A stale worktree is never silently deleted; reconciliation
must prove it belongs to the same experiment and sealed commit.

### Deterministic checks

A trusted owner-private registry maps manifest check IDs to an absolute executable, fixed argv,
relative working directory, timeout from 1 to 3600 seconds, and a small environment allowlist.
The manifest selects identifiers only. It cannot inject commands, arguments, environment names,
or paths. Checks execute sequentially with bounded stdout/stderr captured in the private artifact
store. Any timeout, nonzero exit, output overflow, missing check, unsafe executable, or changed
candidate tree blocks sealing.

### Paired evaluation

The existing `compare_runs` implementation remains a diagnostic statistical authority. The HMAC
prototype binds fields in a completed diagnostic, but it cannot establish checkout-to-build-to-
execution provenance or protect the key from same-UID workers. `bind_paired_evidence` and
`candidate bind-comparison` therefore reject before reading keys, attestations, scorecards, or
writing artifacts. Promotion binding requires an isolated asymmetric signer, public-key
verification, an exact fresh build bound to the checkout, and authenticated lease ownership.

### Independent reviews

The contracts define separate role packets and unique reviewer/context identities for the future
review topology. The reducer currently rejects packet and attestation events unconditionally, so
these objects cannot create promotion authority. When enabled, reviewers must remain read-only and
independent and the controller must verify candidate-ref stability around every recording.

### Draft PR gateway

`github_draft.py` retains the narrow reconciliation implementation as defense-in-depth test surface,
but its public `open_or_reconcile` entry point rejects before calling Git, GitHub CLI, or an injected
runner. The candidate CLI independently rejects draft publication before constructing the gateway.
The module contains no merge, auto-merge, ready-for-review, release, or delete operation.

## Public and private data

Private foundation artifacts may contain diffs, check output, implementation reports, and local
paths. They stay in the artifact store. Public output contains only stable identifiers, commit and
artifact digests, changed-path count, and check counts. Diagnostic benchmark output remains subject
to the benchmark lab's public-data contract.

Secrets, environment values, prompts, model responses, absolute paths, raw diffs, raw test output,
and reviewer prose are forbidden from public JSON. Existing public-safety validation remains the
final serializer gate.

## Recovery and idempotency

- Every mutation requires a unique stage-attempt ID.
- Repeating the exact prepare or seal attempt returns the existing result. Reusing an attempt ID for
  different canonical input is a conflict.
- Process failure before ledger append is reconciled from Git and GitHub state on retry.
- A prepared but unsealed worktree remains blocked for inspection; it is not automatically erased.
- Paired, review, publication, and disposal retries fail before artifacts or external mutation.
- Expired mutable leases still require the phase-two explicit worker-not-live reconciliation.

## Test strategy

- Contract tests cover canonicalization, bounds, unknown keys, stale bindings, identity uniqueness,
  and public-safe output.
- Real temporary Git repositories exercise preparation, scope enforcement, special-file rejection,
  exact-parent commits, drift detection, cleanup, and retry reconciliation.
- Real subprocess fixtures exercise check success, timeout, output overflow, nonzero exit, and
  closed environment behavior.
- Real fake `git`/`gh` executables and redirecting remotes prove publication remains unreachable and
  no runner, hook, push, PR, merge, auto-merge, or ready operation is issued.
- Reducer and ledger tests prove evidence-gated transitions, replay stability, corruption detection,
  and exact idempotency.
- CLI, direct-API, raw-ledger, replay, and fabricated-projection tests prove the foundation can
  prepare/edit/seal while every authority and publication path fails closed without artifacts or
  remote mutation.
- Full Python, Ruff, benchmark smoke, Cargo formatting, tests, clippy, and GitHub CI remain required.

## Delivery boundary

This foundation is complete when a fixture experiment can progress from approved proposal to
`paired_evaluation` with a sealed candidate and passing deterministic evidence, then report
`await_isolated_signer` while every authority and publication path fails closed. Publication is
disabled unconditionally, not merely by configuration.

The next delivery must add an isolated Ed25519 signer, exact checkout/build/executable provenance,
authenticated leases, and fresh adversarial review before re-enabling paired or review events. A
later promotion phase must also add protected validation, constrained GitHub identity, branch-rule
verification, merge queue, soak, and automatic revert before autonomous promotion is honest.
