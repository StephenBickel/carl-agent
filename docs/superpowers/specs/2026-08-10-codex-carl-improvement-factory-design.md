# Codex-Run Carl Improvement Factory Design

Status: approved for written-spec review
Date: 2026-08-10
Decision owner: Stephen Bickel

## Purpose

This document defines a private, external development system that uses Codex to
measure, improve, review, and autonomously promote changes to the Carl Agent
repository. The system repeatedly benchmarks Carl and competing agent harnesses,
diagnoses one measurable weakness, proposes and reviews one change, implements the
change in isolation, reruns paired evaluations, and promotes only changes that pass
predeclared correctness, generalization, efficiency, safety, and operational gates.

The improvement factory is not a Carl product feature. It runs in Stephen's Codex
desktop environment against the Carl development repository. An ordinary Carl
installation never receives the scheduler, private holdouts, competitor lab, release
credentials, or an always-running self-modification loop. It receives ordinary source
changes and releases produced by this external process.

This design extends the evaluation architecture in the
[top-tier harness design](2026-07-23-carl-top-tier-harness-design.md) and
[long-horizon runtime design](2026-08-10-carl-long-horizon-runtime-design.md). It does
not move their provider-neutral durability or safety responsibilities out of Carl.

## Decision summary

- Codex owns the recursive improvement graph; Carl remains the target product.
- One recurring Codex scheduled task, the **Carl Improvement Director**, advances a
  durable experiment graph from a private control project.
- Each active experiment changes one causal mechanism and uses independent benchmark,
  analysis, proposal-review, build, code-review, holdout, and promotion roles.
- Harbor is the first external benchmark execution layer. It is replaceable and is
  not the experiment source of truth.
- The benchmark portfolio is coding-first and also includes realistic multi-step
  workflow automation over isolated service doubles.
- Same-model comparisons and native-product comparisons are separate leagues and are
  never pooled into one ranking.
- No candidate promotes from one score or one run. Promotion requires deterministic
  checks, paired repeated trials, builder-inaccessible holdouts, and a repository
  canary/post-merge soak.
- Passing candidates use machine-reviewed pull requests, required checks, automatic
  merge, post-merge monitoring, and automatic revert. Codex never pushes directly to
  `main`.
- Feature discovery runs as a controlled portfolio loop. Approximately one in five
  experiments may add a feature after the evaluation foundation is stable.
- The first autonomous mutation surface covers harness behavior. Integrations and
  constitutional evaluation components unlock only after explicit machine-verifiable
  reliability gates.

## Why this is a program, not one monolithic feature

The factory contains four independently testable subsystems delivered in order:

1. **Benchmark lab**: reproducible tasks, adapters, graders, normalized trajectories,
   baselines, and reports.
2. **Experiment graph**: durable state, hypothesis selection, role orchestration,
   worktree isolation, evidence binding, and learning records.
3. **Promotion system**: protected validation, GitHub checks, auto-merge, post-merge
   soak, rollback, and release audit.
4. **Feature Scout**: evidence-driven capability discovery, prioritization, acceptance
   task creation, and portfolio allocation.

Each subsystem receives its own implementation plan. The benchmark lab ships a useful
manual evaluation workflow before any autonomous code promotion is enabled. The graph
does not become self-modifying until the evaluation and recovery paths have passed
their own deterministic tests.

## Research basis

This design uses the following public systems as inputs rather than as unexamined
dependencies:

- Codex scheduled tasks can run a local Git project in isolated worktrees and can
  invoke reusable skills. Codex subagent workflows can run specialized workers and
  return bounded results to a director:
  <https://learn.chatgpt.com/docs/automations> and
  <https://learn.chatgpt.com/docs/agent-configuration/subagents>.
- Harbor provides a common task/environment/agent abstraction, adapters for popular
  coding agents, custom agent integration, and the Agent Trajectory Interchange Format:
  <https://www.harborframework.com/docs/agents> and
  <https://www.harborframework.com/docs/agents/trajectory-format>.
- SWE-bench supplies containerized real-repository issue-resolution tasks:
  <https://github.com/SWE-bench/SWE-bench>.
- Terminal-Bench 2.0 supplies broader reproducible terminal tasks through Harbor:
  <https://github.com/harbor-framework/terminal-bench>.
- MCPMark supplies practical MCP workflows over services such as GitHub, filesystems,
  Postgres, Notion, and browser environments:
  <https://github.com/eval-sys/mcpmark>.
- Composio's August 2026 comparison demonstrates the motivating experiment shape:
  one model, multiple harnesses, multi-step live-tool tasks, strict fixed checks, and
  separate success, cost, and latency reporting. Carl will independently implement
  reproducible tasks rather than depend on an unpublished task set:
  <https://x.com/composio/status/2086814488162972027>.

## Goals

- Measure how much the harness changes outcomes when the model and task are held
  constant.
- Improve Carl's task completion rate, verification quality, recovery behavior,
  efficiency, and practical feature coverage without hiding regressions.
- Compare Carl reproducibly with Codex, Claude Code, Hermes, Pi, and later harnesses.
- Exercise coding tasks and realistic workflow automation tasks.
- Preserve every experiment's hypothesis, exact inputs, code, results, reviews,
  costs, promotion decision, and later production evidence.
- Make failed and inconclusive experiments useful durable evidence.
- Autonomously open, validate, merge, monitor, and revert pull requests inside a
  bounded machine policy.
- Prevent a builder from grading itself, seeing protected holdouts, changing the
  promotion threshold for its own experiment, or receiving release credentials.
- Keep the system local-first where practical and compatible with Carl's no-hidden-
  telemetry product boundary.

## Non-goals

- Embedding the improvement scheduler or private evaluation lab in the Carl binary.
- Continuously mutating installed Carl copies on user machines.
- Treating one public leaderboard score as product quality.
- Combining unrelated models into a claim about harness superiority.
- Optimizing arbitrary benchmark-specific hacks that do not generalize.
- Letting the same model role propose, implement, grade, and promote its own change.
- Giving model-driven builder processes a token capable of merging to `main`.
- Publishing raw private holdouts, credentials, unredacted trajectories, or personal
  repository content.
- Relying on hidden end-user telemetry to decide whether a release is healthy.
- Running multiple concurrent code candidates whose effects cannot be attributed.
- Replacing normal security review, dependency policy, or repository branch rules.

## System boundary

```text
Codex desktop / private improvement-control project
    |
    +-- recurring Improvement Director scheduled task
    |      |
    |      +-- benchmark and analysis workers
    |      +-- proposal reviewers
    |      +-- isolated builder worktree
    |      +-- independent code and security reviewers
    |      `-- promotion observer
    |
    +-- private append-only experiment ledger and artifact index
    +-- public-task manifests and benchmark configuration
    `-- no merge credential in model-driven worker environments

Harbor / container execution             Protected validation workflow
    |                                        |
    +-- Carl adapter                          +-- private holdout tasks
    +-- competitor adapters                   +-- fixed promotion policy
    +-- public/dev task containers            +-- aggregate signed scorecard
    `-- normalized trajectories               `-- no raw holdout returned

                          GitHub
                            |
                            +-- candidate branch and PR
                            +-- required checks and merge queue
                            +-- deterministic auto-merge controller
                            `-- deterministic auto-revert controller
                                      |
                                      v
                               public Carl repository
                                      |
                                      v
                           ordinary Carl builds/releases
```

The private control project is a separate Codex project from the public Carl
repository. It contains the director skill, experiment ledger, sanitized benchmark
configuration, and artifact digests. It may check out or create worktrees of the Carl
repository, but Carl candidate branches cannot modify the control project.

Protected holdouts and their grader inputs do not exist in the builder workspace or
model context. A separate validation workflow receives a candidate commit digest,
runs the holdouts, and returns only a bounded aggregate scorecard and signature. This
is the only honest way to call the tasks hidden when the builder otherwise has local
filesystem access.

## Codex automation topology

### One scheduled director

One standalone Codex scheduled task named **Carl Improvement Director** runs every two
hours in an isolated worktree of the private control project. A tick is allowed to do
no work. It first acquires the durable lease and reconciles active external jobs; it
does not start a new candidate merely because the schedule fired.

The director uses a checked-in `carl-improvement-director` skill. The skill defines the
state machine, role prompts, evidence schemas, retry rules, budget rules, and terminal
conditions. The scheduled-task prompt stays small: load the skill, reconcile the
ledger, advance the highest-priority ready experiment by the next safe state, record
the result, and stop.

One director is preferred over several loosely coordinated scheduled tasks. Separate
benchmark, builder, reviewer, and release cron jobs would race, duplicate work, and
communicate through implicit chat state. Specialized work happens as bounded
subagents or deterministic external jobs started by the leased director.

### Cadence

- Every two hours: reconcile and advance at most one active experiment stage.
- Every night: refresh the current Carl baseline and run the full builder-visible
  promotion portfolio if no candidate owns the benchmark capacity.
- Every week: run the external harness league, audit grader health, rotate eligible
  holdout variations, and run Feature Scout.
- After a material model, harness, tool, provider, task, or environment version
  change: invalidate affected comparisons and schedule a rebaseline before promotion.
- After every merge: run a repository-local 24-hour soak before the experiment becomes
  accepted evidence for unlocking broader autonomy.

The computer must remain on and Codex desktop must remain running for local scheduled
work. A missed tick is normal. The next tick reconciles durable state and continues;
it never assumes that elapsed wall time means work succeeded.

## Role separation

Every role receives only the information and authority it needs.

### Improvement Director

- Reads the experiment ledger and bounded scorecards.
- Selects the next ready transition according to deterministic priority rules.
- Spawns specialized subagents and external benchmark jobs.
- Cannot modify Carl product code, raw holdouts, promotion thresholds, or branch rules.
- Cannot merge, release, or revert directly.

### Benchmark Operator

- Builds pinned task environments and runs declared agent/model combinations.
- Produces normalized trajectories, run manifests, and unsigned measurements.
- Cannot modify product code, graders, or promotion policy during a candidate run.
- Treats task repositories, prompts, tool output, and model output as untrusted.

### Failure Analyst

- Reads sanitized baseline and competitor trajectories.
- Clusters failures by mechanism: context loss, planning, tool selection, invalid tool
  use, recovery, verification, premature completion, policy friction, or excess work.
- Produces ranked observations; it does not select code changes silently.

### Hypothesis Author

- Selects one failure mechanism or capability gap.
- Pre-registers affected tasks, primary metric, guard metrics, expected mechanism,
  acceptable cost, and likely regressions before implementation.
- May propose a product fix, harness change, efficiency change, or feature acceptance
  contract.

### Proposal Review Quorum

Three independent reviews are required before building:

1. **Causal review**: the proposal isolates one plausible mechanism and has a testable
   prediction.
2. **Product review**: the change fits Carl's mission and is not benchmark-only bloat.
3. **Evaluation review**: the planned tasks and metrics can falsify the proposal and do
   not leak holdouts.

Two approvals and no hard objection are required. A hard objection includes missing
authority, unverifiable success, changing the grader and product together, security
boundary expansion without a contract, or an experiment too broad for attribution.

### Builder

- Works in one fresh Carl worktree and one candidate branch.
- Receives the approved hypothesis, builder-visible tasks, source repository, and
  exact deterministic checks.
- May change only files declared in the proposal or newly discovered files justified
  in the experiment log.
- Cannot access protected holdouts, merge credentials, reviewer prompts, or the
  promotion policy for the active experiment.
- Produces a candidate commit, exact diff, test evidence, and bounded implementation
  report.

### Independent Review Quorum

Four read-only reviewers inspect the candidate commit:

1. correctness and task-completion contract;
2. security, permissions, secrets, and side effects;
3. maintainability, compatibility, and architectural fit;
4. benchmark integrity, causal attribution, and suspicious task-specific behavior.

All hard findings must be resolved by a new candidate commit and a fresh review. Three
of four reviewers must otherwise approve. Reviewers cannot edit the candidate.

### Protected Validator

- Runs builder-inaccessible holdouts through an external workflow.
- Uses the policy version pre-registered before the build.
- Returns a signed aggregate scorecard, run counts, invalid-run reasons, and artifact
  digests, but not raw tasks or secret grader inputs.
- Blocks rather than guesses when the grader or infrastructure cannot produce a valid
  decision.

### Promotion Controller and Watchdog

- Deterministic code, not a free-form model turn, verifies the signed scorecard,
  required checks, candidate commit, branch policy, and budget record.
- Opens or updates the candidate PR, enables GitHub auto-merge, and records the merge.
- Runs the post-merge soak and automatically opens and auto-merges an exact revert if a
  hard regression or predeclared rollback threshold occurs.
- Holds the narrowly scoped GitHub App permissions needed for PR and merge operations.
  Model-driven workers never receive that credential.

## Durable experiment model

The experiment ledger is append-only. Query summaries may be rebuilt from events. A
recorded event is accepted fact; subagent prose is evidence only after normalization
and validation.

### Stable identifiers

- `GenerationId`: monotonically increasing accepted-change generation.
- `ExperimentId`: unique hypothesis attempt.
- `StageAttemptId`: idempotency key for one state transition attempt.
- `RunManifestId`: exact benchmark configuration.
- `CandidateCommit`: immutable Git commit digest.
- `ScorecardId`: signed decision input digest.
- `PromotionId`: PR, merge, or revert action identity.

### Experiment states

```text
queued
  -> baselining
  -> diagnosing
  -> proposal_review
  -> building
  -> deterministic_validation
  -> paired_evaluation
  -> holdout_validation
  -> review_complete
  -> pr_open
  -> merged
  -> soaking
  -> accepted

Any nonterminal state may become:
  rejected | inconclusive | blocked | budget_exhausted | reverted | abandoned
```

Only one experiment may own `building` through `soaking` at a time. Read-only baseline
or competitor jobs may run concurrently when they use pinned snapshots and do not
consume reserved promotion capacity.

### Pre-registered experiment manifest

Every experiment records before implementation:

- parent Carl commit and generation;
- experiment kind: correctness, reliability, efficiency, safety, feature, evaluator,
  or constitutional;
- observed failure cluster and supporting run IDs;
- one causal hypothesis;
- target file/module surface and forbidden surface;
- affected task slice and primary metric;
- unaffected guard suites and non-regression threshold;
- expected direction and minimum meaningful effect;
- deterministic acceptance checks;
- model, provider, harness, tool, task, grader, environment, and policy versions;
- minimum and maximum paired replicas;
- cost, elapsed-time, and concurrency budget;
- known risks, rollback trigger, and expected compatibility impact.

The active manifest is immutable after the first builder action. A material change
creates a child experiment rather than rewriting the prediction after seeing results.

### Evidence and artifacts

Large trajectories, diffs, logs, reports, and container outputs live in a private
content-addressed artifact store. Ledger events contain sanitized metadata, hashes,
sizes, and provenance. Secrets, raw environment values, personal paths, and protected
holdout content are removed before model analysis or public reporting.

Completed experiments publish a bounded sanitized summary containing the hypothesis,
versions, aggregate metrics, decision, PR/commit, cost, and rollback status. Raw
private artifacts are never required to reproduce public task results; public tasks
retain their own complete manifests.

## Benchmark portfolio

### Builder-visible promotion suite

The initial suite contains 48 tasks:

- **24 coding tasks**: regression-first bug fixes, feature additions, refactors,
  documentation, tests, unfamiliar repositories, multi-file changes, and build-system
  work.
- **12 workflow tasks**: isolated email, calendar, files, spreadsheets, GitHub, Slack,
  Notion, CRM, PagerDuty-style incidents, ledgers, audits, batch edits, and cross-app
  synchronization.
- **12 reliability and safety tasks**: context compaction, restart, provider-thread
  loss, steering, cancellation, long-running commands, hostile repository
  instructions, secrets, ambiguous side effects, stale state, and verifier failure.

Workflow tasks use deterministic disposable service doubles by default. Periodic live
connector tests validate adapter realism, but live SaaS state is not promotion truth.

### Protected holdout suite

The initial holdout contains 24 tasks:

- 12 unseen coding repositories or semantic perturbations;
- 6 unseen workflow record sets, tool combinations, policies, and ordering constraints;
- 6 unseen reliability, interruption, secret, and recovery variations.

Holdout families are versioned. Rotation adds new tasks without changing the policy
for an already-active experiment. Retired tasks remain available for historical replay
but no longer decide new promotions.

### External harness league

The weekly league compares Carl, Codex, Claude Code, Hermes, Pi, and later adapters.
It has two separate result tables:

1. **Same-model league**: exact dated model and provider, external task instruction,
   initial task state, functional tool access, limits, reasoning mode, sampling
   parameters, and resource constraints are held equal wherever each harness
   officially or reproducibly supports them. Harness-owned system prompts, context
   policies, and tool encodings remain part of the harness under test and are recorded
   rather than forcibly replaced.
2. **Native-product league**: each harness uses its supported recommended model and
   configuration. This measures the product pair, not pure harness quality.

If an exact same-model configuration is unsupported, that harness is marked
`not_comparable` for the controlled table rather than silently using another model.
The native-product result remains valid in its own table.

Initial external sources are a stratified SWE-bench Verified subset, Terminal-Bench
2.0 through Harbor, MCPMark-compatible tasks, and Carl-owned fixtures. Every report
names the harness commit/version, model, provider, task version, environment digest,
limits, date, and run count.

Every imported benchmark, task, fixture, and adapter records its source, revision,
license, modifications, and redistribution terms. Tasks with incompatible or
noncommercial redistribution terms may run in an owner-private lab when permitted but
are not copied into Carl's public repository. Public benchmark exposure or likely
model-training contamination makes a task diagnostic evidence, not a protected
generalization holdout.

Competitor runs primarily diagnose useful harness behavior. A Carl candidate is
promoted against its pinned Carl baseline, not because it beat a competitor on an
unpaired run.

## Evaluation ladder

Evaluation spends evidence budget progressively.

### Stage 1: deterministic gate

Run formatting, static analysis, unit, integration, replay, migration, security, and
hypothesis-specific acceptance checks. Any required failure rejects the candidate.

### Stage 2: targeted paired smoke

Run the affected task slice and known neighboring regression tasks against baseline
and candidate. Use a minimum of three paired replicas. Reject obvious losers early;
never promote from smoke results.

### Stage 3: full paired confirmation

Run baseline and candidate in randomized paired order on the promotion suite. Start
with three replicas and add paired replicas up to ten until the predeclared decision is
conclusive or the experiment budget is exhausted. Pairing binds task, seed or initial
state, model/provider version, environment, and resource limits.

Task is the resampling cluster. Confidence intervals use a task-clustered paired
bootstrap so repeated attempts on one easy task do not masquerade as independent task
coverage. The analysis code and random seed are pinned in the manifest.

### Stage 4: protected validation

The protected runner evaluates the candidate and pinned baseline against holdouts. It
returns the signed aggregate scorecard. The builder and hypothesis author receive no
raw holdout trace.

### Stage 5: repository canary and soak

Carl has no hidden end-user telemetry, so “canary” does not mean silently monitoring
user installations. The repository canary consists of the merge-queue commit, the
complete deterministic and live-opt-in dogfood suite, repeated clean-checkout runs,
restart/recovery drills, and a 24-hour post-merge soak before acceptance. A hard failure
automatically reverts the merge.

## Metrics and promotion policy

### Hard gates

The following require zero violations:

- required build, test, verification, migration, and compatibility clauses;
- secret disclosure or credential retention;
- unauthorized, duplicated, ambiguous-retried, or out-of-scope consequential effect;
- out-of-scope repository mutation;
- test-owned orphan process;
- replay mismatch or missing evidence artifact;
- protected-task leakage;
- candidate modification of its grader, promotion policy, reviewer instructions,
  branch protection, or rollback controller;
- successful completion recorded while any required check failed.

### Correctness and reliability changes

Promotion requires:

- an estimated primary pass-rate improvement of at least 3 absolute percentage points;
- the one-sided 95 percent paired confidence lower bound above zero; and
- every unaffected suite's one-sided 95 percent paired confidence lower bound at or
  above -2 absolute percentage points.

A deterministic bug fix that affects too few tasks to move aggregate pass rate may
promote when its pre-registered acceptance test changes from fail to pass on every
declared repetition, all guard suites satisfy the 2-point non-inferiority bound, and
the causal review confirms that the test exercises the reported defect rather than a
benchmark-specific shortcut.

### Efficiency changes

Promotion requires at least a 10 percent improvement in predeclared cost per successful
task or wall-clock latency, plus correctness within the 2-point non-inferiority bound.
Token count, provider requests, tool calls, retries, and intervention count remain
reported guard metrics even when they are not primary.

### New features

A feature must begin with a versioned acceptance contract and at least one task that
the baseline cannot complete. Promotion requires the new acceptance suite to pass on
every deterministic run and at least 90 percent of paired live-model attempts, with
all existing suites satisfying their hard gates and non-regression bounds.

Feature code cannot weaken an existing task, remove an existing completion clause, or
modify the active promotion threshold. Evaluation changes required for a feature are
reviewed and activated as a separate parent experiment before the feature build.

### Invalid runs

- Agent timeout, crash, malformed tool call, malformed completion, or failure to
  produce the requested artifact counts as a task failure.
- A classified infrastructure fault may retry at most twice under the predeclared
  retry rule.
- A grader timeout, missing protected artifact, or inconsistent score blocks promotion
  and opens an evaluator-repair experiment. It is never silently excluded.
- Every attempt, retry, timeout, exclusion, and reason appears in the scorecard.
- If the retry budget cannot produce a valid paired decision, the experiment becomes
  `inconclusive`, not successful.

### Multiple experiments and false discovery

Only the pre-registered primary metric decides the claimed win. Secondary metrics are
descriptive unless declared as guard metrics. A failed experiment cannot be rerun with
a new primary metric under the same ID. Monthly reporting includes all experiments,
not only promoted winners, so repeated hypothesis search remains visible.

## Feature Scout

Feature Scout runs weekly after the external harness league and immediately when one
missing capability causes three or more distinct task failures.

It considers:

- repeated Carl capability gaps;
- successful competing-harness traces;
- Carl's approved roadmap and architecture contracts;
- recurring user friction and manual interventions;
- new relevant coding or workflow task categories;
- safety or reliability capabilities that unlock broader autonomy.

It produces at most three ranked feature briefs per run. Each brief contains user
outcome, evidence, task contract, affected architecture, estimated implementation and
evaluation cost, risks, compatibility impact, and the smallest useful vertical slice.

After the benchmark foundation is stable, experiment allocation targets are:

- 60 percent task success and reliability;
- 20 percent new features;
- 10 percent cost and latency efficiency;
- 10 percent benchmark, grader, and safety integrity.

These are rolling 20-experiment targets, not quotas that force a bad feature. If no
feature brief passes product and evaluation review, the slot returns to reliability.
Feature Scout does not bypass the ordinary hypothesis, build, review, holdout, and
promotion states.

## Autonomy levels and unlocks

### Level A: harness behavior

The initial autonomous mutation surface includes prompts, public instructions,
context construction, compaction, planning, tool routing, retry, recovery,
verification, and completion policy. Product code directly required to implement
these behaviors is included.

Level A auto-merge activates only after the benchmark lab can reproduce the same
baseline decision across ten clean repetitions, the rollback drill passes at every
promotion boundary, and the protected validator proves that the builder cannot read a
holdout task.

### Level B: tools, integrations, and product features

Level B unlocks after:

- at least ten accepted Level A promotions across at least 30 days;
- no unreverted hard-gate violation;
- every post-merge regression automatically detected and reverted within the next
  director tick;
- cumulative spend and invalid-run accounting reconcile exactly; and
- the Feature Scout acceptance-contract path passes five synthetic feature drills.

### Level C: evaluator and constitutional components

Benchmark tasks, graders, decision code, reviewer instructions, promotion policy, and
rollback logic never change in the same experiment as Carl product code. A separate
constitutional lane may propose such a change autonomously.

A constitutional change requires three independent model reviews using at least two
model families, replay of the previous 30 completed experiments under old and new
policy, zero change to historical hard-gate outcomes without an explicit corrected-
grader finding, seven days of shadow decisions, and seven days of reversible canary
activation. The old policy and rollback controller remain available until the canary
is accepted.

## Git and promotion flow

1. The builder creates `codex/experiment-<ExperimentId>` from the exact parent commit.
2. The candidate commit and diff are bound into the experiment ledger.
3. Deterministic, paired, review, and protected checks run against that commit.
4. The deterministic controller opens a PR containing the hypothesis, affected task
   IDs, metrics, costs, reviewer decisions, protected scorecard digest, and rollback
   trigger.
5. GitHub rules require all declared machine checks and the exact signed scorecard.
6. GitHub auto-merge uses the merge queue; no model receives direct `main` push access.
7. Post-merge soak binds the merge commit rather than assuming the PR head is identical.
8. A hard regression creates an exact revert PR referencing the experiment and merge
   commit. Required rollback checks run, then auto-merge restores the last accepted
   generation.
9. No new candidate enters build while a merged experiment is soaking.

Changes to workflow files, branch rules, promotion code, holdout integration, or
release credentials use the Level C constitutional lane even when they accompany an
otherwise ordinary feature.

## Budgets and concurrency

Initial autonomous limits are:

- USD 25 live-model spend per calendar day;
- USD 150 live-model spend per rolling seven days;
- four concurrent read-only benchmark workers;
- one active code candidate;
- four concurrent live-model benchmark replicas in total;
- six hours for one director-owned stage lease;
- 24 hours maximum elapsed time for one ordinary experiment before it requires an
  explicit `blocked`, `inconclusive`, or child-experiment decision;
- two infrastructure retries per run;
- three materially distinct hypotheses for one failure cluster before a 14-day
  cooldown.

Local deterministic tests do not consume the live-model dollar budget but do obey CPU,
disk, process, and elapsed-time limits. Reaching a budget stops new dispatch, records
`budget_exhausted`, and waits for the next budget window. It never converts incomplete
evidence into a passing decision.

## Recovery and idempotency

Every stage dispatch uses `StageAttemptId` as an idempotency key. Before retrying after
a crash, the next director tick reconciles the ledger with the filesystem, Harbor job,
Git commit, PR, merge queue, protected scorecard, and workflow state.

- A stale six-hour lease may be reclaimed only after external-state inspection proves
  that no prior worker is still live.
- Read-only observations may repeat after reconciliation.
- Candidate file mutation resumes from the recorded commit or starts a child attempt;
  it never guesses which uncommitted edits survived.
- Push, PR creation, merge, release, and revert are reconciled by experiment ID and
  exact commit before any retry.
- An uncertain consequential action blocks; it is never blindly repeated.
- Storage or ledger-integrity failure stops all new work and preserves the existing
  files for diagnosis.
- Missing artifacts invalidate dependent evidence and block promotion.
- A model/provider outage leaves the experiment ready for a later tick without
  changing its hypothesis or thresholds.

The director pauses when a `PAUSED` control record is active or its Codex automation is
disabled. A pause stops new dispatch but does not kill a running external job unless
the operator explicitly requests cancellation. Emergency rollback remains available
while new experiments are paused.

## Security and privacy

- Candidate repositories, benchmark instructions, model output, competitor traces,
  tool output, and workflow records are untrusted input.
- Builders run in disposable worktrees or containers with the narrowest filesystem and
  network authority required by the task.
- Provider keys, GitHub App keys, SaaS credentials, holdout decryption material, and
  raw environment values never enter model prompts, trajectories, or candidate
  processes.
- Live workflow tests use dedicated disposable test tenants or deterministic service
  doubles. They never operate on Stephen's real inbox, calendar, CRM, or production
  incidents as promotion truth.
- Promotion and rollback credentials belong to deterministic controllers outside the
  model worker environment.
- Public summaries redact personal paths, repository secrets, raw conversations,
  private task content, and user data.
- Carl's no-hidden-telemetry boundary remains unchanged. Repository canary evidence is
  produced by controlled test and dogfood environments, not installed-user monitoring.
- The control project and artifact store are private and owner-only. The public Carl
  repository contains methodology, public tasks, sanitized baselines, and reproducible
  claims only.

## Observability and operator experience

The Codex Scheduled inbox and private control project expose:

- current generation, experiment, state, lease owner, and last transition;
- parent and candidate commits;
- hypothesis, targeted task family, and predicted effect;
- deterministic, paired, holdout, review, canary, and soak status;
- cost, tokens, time, attempts, retries, invalid runs, and remaining budget;
- PR, merge, acceptance, revert, and cooldown status;
- next eligible action and the reason a run is waiting, rejected, blocked, or paused.

Notifications fire only for accepted promotion, automatic revert, blocked integrity or
credential state, budget exhaustion lasting more than one day, or three consecutive
inconclusive experiments. Normal no-op ticks and expected failed hypotheses remain in
the Scheduled run history without interrupting the operator.

## Comparative claims

Carl may claim a harness improvement only when the report includes task and grader
version, harness revisions, exact model/provider, prompt/tool/resource parity, policy,
date, run count, invalid-run accounting, aggregate and per-category results, cost,
latency, and regressions.

A public superiority claim requires at least 30 paired task runs and cannot mix the
same-model and native-product leagues. A single demonstration, excluded failure, or
stronger model does not support a harness-superiority claim.

## Testing the factory

### Model-free tests

- Experiment-event replay produces the same state and decision digest.
- Invalid transitions, expired leases, concurrent builders, and duplicate attempts
  fail closed.
- A candidate cannot change its manifest, primary metric, grader, or threshold after
  build begins.
- Budget arithmetic and concurrency limits are deterministic.
- Promotion cannot occur without every hard gate and exact scorecard signature.
- Revert reconciliation never duplicates a merge or revert.

### Scripted graph tests

- Kill and restart the director at every stage boundary.
- Drop benchmark workers and protected-validation responses.
- Reorder completed read-only jobs and deliver duplicate notifications.
- Inject conflicting PR, branch, and merge-queue state.
- Exhaust daily and weekly budgets.
- Pause and resume with an active external job.
- Corrupt a projection and rebuild it from the append-only ledger.

### Evaluation-integrity tests

- Seed a benchmark-specific shortcut and prove the hidden suite rejects it.
- Attempt to read protected tasks from a builder and prove the boundary denies it.
- Change a grader and candidate together and prove ordinary promotion rejects it.
- Force grader timeouts and prove they block rather than disappear.
- Produce a faster but less correct candidate and prove non-inferiority rejects it.
- Produce a lucky single run and prove repeated paired evaluation rejects it.

### Promotion drills

- Create, check, auto-merge, soak, and accept a harmless synthetic improvement.
- Fail every pre-merge gate independently and prove no merge occurs.
- Trigger every post-merge rollback threshold and prove the exact merge is reverted.
- Lose Codex mid-push, mid-PR, mid-merge, and mid-revert and prove reconciliation is
  idempotent.

## Delivery sequence

### Phase 0: manual calibration

- Create the private control project and versioned configuration.
- Integrate Carl with Harbor and run a small public coding/workflow smoke suite.
- Reproduce baselines manually and validate trajectory normalization.
- No Codex scheduled task, builder, or automatic promotion is enabled.

### Phase 1: benchmark lab

- Build the 48-task builder-visible suite and 24-task protected suite.
- Add same-model and native-product adapters and reports.
- Implement invalid-run accounting, artifact storage, and reproducibility checks.
- Publish the methodology and sanitized baseline.

### Phase 2: dry-run experiment graph

- Add the append-only ledger, reducer, leases, manifests, role outputs, and budget
  accounting.
- Schedule the Improvement Director in read-only proposal mode.
- Produce hypotheses and simulated decisions without changing Carl.

### Phase 3: isolated candidate generation

- Enable Level A builders in disposable worktrees.
- Add isolated signing and exact build/executable provenance for paired evaluation and independent
  reviews. Until those controls land, the foundation must stop at a sealed candidate.
- Open draft PRs but do not auto-merge only after that publication gate is independently reviewed.
- Prove crash recovery, holdout separation, and exact rollback drills.

### Phase 4: autonomous Level A promotion

- Enable deterministic required checks, machine-reviewed PRs, merge queue,
  auto-merge, post-merge soak, and auto-revert.
- Enforce one active candidate and all initial budgets.
- Accumulate the evidence needed for Level B unlock.

### Phase 5: Feature Scout and broader autonomy

- Enable weekly feature discovery and the rolling experiment portfolio.
- Unlock Level B only after its evidence gates pass.
- Add the separate constitutional lane and shadow it before any Level C activation.

## Alternatives rejected

### Put the recursive loop inside Carl

Rejected because the requested system is a private Codex development factory, not a
runtime feature for every Carl user. It would also mix product and evaluator authority.

### Use Harbor as the source of truth

Rejected because Harbor is an excellent replaceable executor but does not own Carl's
experiment hypotheses, Git policy, feature portfolio, or recovery semantics.

### Use several scheduled tasks as independent graph nodes

Rejected because independent schedules race and communicate through implicit state.
One leased director may still spawn parallel read-only workers.

### Let Codex push directly to `main`

Rejected because machine-reviewed PRs, required checks, merge-queue identity, and
exact reverts provide materially better provenance without adding a human gate.

### Use one aggregate leaderboard score

Rejected because correctness, safety, cost, latency, interventions, and reliability
are distinct product dimensions. Same-model and native-product results answer different
questions.

### Keep hidden tasks beside the builder

Rejected because a model with filesystem access could inspect them. Protected tasks
must run across a real workspace and credential boundary.

## Acceptance criteria

The design is implemented when:

- the benchmark lab reproduces pinned Carl baselines and competitor reports with
  complete invalid-run accounting;
- the 48 public/dev and 24 protected tasks cover coding, workflow, and reliability
  categories as specified;
- the director survives restart at every state transition without duplicate mutation,
  PR, merge, or revert;
- a builder cannot read holdouts, promotion secrets, reviewer prompts, or active
  thresholds outside its manifest;
- no candidate promotes from one run, an excluded grader failure, or an unpaired model;
- every promotion satisfies deterministic, paired, protected, review, and repository-
  canary gates;
- passing Level A changes can open a PR, auto-merge, soak, and become accepted without
  a human click;
- a post-merge hard regression automatically reverts the exact merge;
- budget, concurrency, pause, and notification behavior match this document;
- feature proposals begin with failing acceptance tasks and use the ordinary promotion
  path;
- the public Carl binary contains none of the private factory scheduler, credentials,
  holdouts, or self-modification control plane.
