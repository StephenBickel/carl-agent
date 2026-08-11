# Carl Isolated Candidate Builder Design

## Status and intent

This document specifies phase three of the Codex-operated Carl Improvement Factory. It
turns an approved dry-run experiment into one isolated candidate commit, binds deterministic
and paired evidence to that commit, collects independent read-only reviews, and may publish
the candidate as a draft pull request. It does not merge, enable auto-merge, deploy, run a
protected holdout, or accept an experiment.

The user approved the phase-three direction after phase two was delivered and explicitly
asked execution to continue without additional approval pauses. This design therefore
resolves implementation details from the factory constitution and keeps every new external
mutation below the already-approved draft-PR boundary.

## Goals

- Prepare one disposable Git worktree from the manifest's exact parent commit.
- Let a Codex automation act as the builder without giving the graph a second hidden model
  invocation or putting GitHub credentials in builder context.
- Reject changes outside the manifest's target surface or inside its forbidden surface.
- Run only preregistered deterministic checks resolved through a trusted command registry.
- Seal one immutable candidate commit and content-addressed evidence bundle.
- Bind an exact paired comparison and four role-specific review attestations to that commit.
- Require three independent approvals and no hard finding before draft publication.
- Make push and draft-PR creation idempotent, reconciled, and impossible before every local
  phase-three gate passes.

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
4. The trusted controller runs baseline and candidate through `run-attested` from separate clean
   checkouts. It derives each checkout commit and tree itself, reconstructs the scorecard from the
   canonical run manifest, and emits a domain-separated HMAC bound to the experiment, role,
   task/config identity, commit, manifest digest, and scorecard digest. `candidate bind-comparison`
   verifies both attestations, requires baseline to equal the manifest parent and candidate to equal
   the sealed commit, recomputes the comparison, stores the evidence, and appends one paired event.
5. `candidate review-packet` emits one immutable, role-specific packet per reviewer. A reviewer
   works read-only and returns a strict attestation bound to the packet and candidate commit.
   Reviewer identities and context IDs must be unique across the four roles.
6. `candidate record-review` stores the bounded private report and appends a normalized review
   event. Three approvals and no hard finding are required.
7. `candidate open-draft-pr` first appends a durable authorization bound to the active lease,
   repository, effective remote URL, base, branch, and sealed commit. It then replays the ledger,
   revalidates both fetch and push destinations, verifies the local branch still resolves to the
   sealed commit, pushes that exact ref, and invokes a narrow GitHub gateway that can only inspect
   or create a draft PR. It records the PR identity only after reconciliation confirms the head
   commit and draft state. A crash between authorization, publication, and recording resumes by
   reconciling the same immutable request. The experiment remains in `paired_evaluation`; a draft
   is a review surface, not evidence that protected validation happened.

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

The experiment reducer gains normalized events for workspace preparation, candidate sealing,
deterministic evidence, paired evidence, review packets/attestations, draft PR authorization, and
draft PR publication. Mutable events carry the exact active lease owner and acquisition attempt.
State transitions fail closed unless their required evidence is present:

- leaving `building` requires a sealed candidate at the manifest parent;
- leaving `deterministic_validation` requires all preregistered checks to pass;
- recording paired evidence requires the experiment to be in `paired_evaluation` and the
  comparison to be bound to the sealed candidate;
- phase-three review packets, attestations, and draft PR records are allowed only in
  `paired_evaluation` after passing local evidence;
- phase three cannot transition from `paired_evaluation` to `holdout_validation`. The protected
  validator introduced in phase four is the only component that may satisfy that edge.

The existing phase-two event format remains readable. New events use exact payload contracts and
stage-attempt idempotency. Candidate evidence cannot be replaced; a changed commit requires a child
experiment.

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

The existing `compare_runs` implementation remains the statistical authority. A phase-three
binding names the experiment, manifest digest, baseline commit, candidate commit, verified baseline
and candidate scorecard digests, comparison seed, and recomputed comparison digest. Binding accepts
only controller-attested evidence; caller-authored public scorecard labels have no promotion
authority. Only the exact `improvement` decision satisfies the local gate. Infrastructure-invalid
or insufficient evidence does not pass. The binding is local promotion evidence, not a protected
holdout scorecard. The HMAC boundary is limited to the manual, controller-only Phase 3 model; shared
OS identities or cross-machine verification require an isolated signer and public-key verification.

### Independent reviews

Each role receives a different packet digest while sharing the candidate commit, diff digest,
manifest digest, and evidence digests. The packet contains the role and review contract but no
other reviewer's output. An attestation contains a unique bounded reviewer ID and unique context
ID, one of `approve`, `reject`, or `hard_finding`, the packet digest, candidate commit, and a private
report artifact digest. Duplicate identities, duplicate contexts, mismatched packets, stale
commits, missing roles, and hard findings block the local draft-PR quorum. Phase four may require
fresh promotion review after protected validation.

Reviewers never edit the candidate worktree. The controller checks the candidate ref before and
after review recording; drift invalidates the action.

### Draft PR gateway

`github_draft.py` wraps an injected command runner for Git and GitHub CLI. Its public API supports
only:

- inspect an existing PR for the derived head branch;
- push `<candidate-commit>:refs/heads/<derived-branch>` without force;
- create a draft PR with a deterministic, sanitized title/body;
- reconcile URL, number, draft status, state, head branch, and head commit.

The module contains no merge, auto-merge, ready-for-review, release, or delete operation. Existing
PRs are accepted only when every reconciled field matches. A conflict blocks instead of updating
unknown state. The model-facing builder never receives the gateway or its environment.

## Public and private data

Private artifacts may contain diffs, check output, implementation reports, review prose, and local
paths. They stay in the artifact store. Public output contains only stable identifiers, commit and
artifact digests, changed-path count, check counts, aggregate comparison metrics already permitted
by the benchmark lab, reviewer-role verdicts, and the draft PR URL/number after reconciliation.

Secrets, environment values, prompts, model responses, absolute paths, raw diffs, raw test output,
and reviewer prose are forbidden from public JSON. Existing public-safety validation remains the
final serializer gate.

## Recovery and idempotency

- Every mutation requires a unique stage-attempt ID.
- Repeating the exact prepare, seal, evidence, review, push, or PR attempt returns the existing
  result. Reusing an attempt ID for different canonical input is a conflict.
- Process failure before ledger append is reconciled from Git and GitHub state on retry.
- A prepared but unsealed worktree remains blocked for inspection; it is not automatically erased.
- A pushed branch without a PR is safe to retry. A matching draft PR is recorded rather than
  duplicated.
- Cleanup is explicit after draft reconciliation, refuses dirty or mismatched worktrees, preserves
  the sealed branch, and records an idempotent disposal event.
- A PR with a different head, non-draft state, base, or repository is a hard conflict.
- Expired mutable leases still require the phase-two explicit worker-not-live reconciliation.

## Test strategy

- Contract tests cover canonicalization, bounds, unknown keys, stale bindings, identity uniqueness,
  and public-safe output.
- Real temporary Git repositories exercise preparation, scope enforcement, special-file rejection,
  exact-parent commits, drift detection, cleanup, and retry reconciliation.
- Real subprocess fixtures exercise check success, timeout, output overflow, nonzero exit, and
  closed environment behavior.
- Real fake `git`/`gh` executables exercise draft creation and reconciliation without network access;
  their captured argv prove no force-push, merge, auto-merge, or ready operation is issued.
- Reducer and ledger tests prove evidence-gated transitions, replay stability, corruption detection,
  and exact idempotency.
- CLI integration tests run prepare/edit/seal/evidence/review/draft/disposal flows against
  temporary private stores and repositories while asserting public output contains no private
  material.
- Full Python, Ruff, benchmark smoke, Cargo formatting, tests, clippy, and GitHub CI remain required.

## Delivery boundary

Phase three is complete when a fixture experiment can progress from approved proposal to
`paired_evaluation` with a sealed candidate, passing deterministic and paired evidence, independent
local review quorum, and a reconciled draft PR using fake external gateways, while every adversarial
path fails closed. It remains in `paired_evaluation` awaiting phase-four protected validation.

The production GitHub path is shipped disabled by default and requires explicit trusted executable,
repository, remote, base branch, and owner-private artifact/ledger paths. No scheduled task is
created in this phase. Phase four must add a protected validator, constrained GitHub App identity,
branch-rule verification, merge queue, soak, and automatic revert before autonomous promotion is
honest.
