# Carl Autonomous Improvement Operating System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Carl autonomously implement, evaluate, publish, promote, soak, repair, and revert real product improvements without routine human approval.

**Architecture:** Extend the existing append-only experiment graph with explicit experimental publication, retry, protected validation, promotion, soak, and revert events. Separate the product builder from the independent validator/promoter, keep recovery idempotent, and add a high-capability supervisor that repairs the loop itself. Public documentation reports commissioning truth until one real improvement completes the entire lifecycle.

**Tech Stack:** Python 3.12, SQLite, pytest, Rust documentation contracts, Git/GitHub CLI, Codex desktop automations, Mermaid documentation.

**Spec:** `docs/superpowers/specs/2026-08-19-carl-autonomous-improvement-operating-system-design.md`

## Global Constraints

- Routine experimental pushes, protected PR promotion, repair, soak, and exact revert require no human approval.
- Never directly push or rewrite `main`, force-push, weaken required checks or branch protection, edit observed evidence, deploy, or publish releases.
- Experimental publication does not require protected production validation.
- Candidate code cannot modify active evaluators, expected outputs, metrics, thresholds, protected infrastructure, automation policy, or rollback controls.
- Every retry records a changed action; repeating a report or command against unchanged state is not progress.
- README operational claims must remain bound to exact GitHub and durable commissioning evidence.
- Heavy builds, tests, evaluations, protected validation, commissioning, and soak probes run on
  GitHub-hosted runners; local heavy fallback is forbidden.

---

### Task 1: Encode autonomous lifecycle and retry events

**Files:**
- Modify: `benchmarks/src/carl_bench/experiment.py`
- Modify: `benchmarks/src/carl_bench/ledger.py`
- Modify: `benchmarks/tests/test_experiment.py`
- Modify: `benchmarks/tests/test_ledger.py`

**Interfaces:**
- Produces: `EventType.RETRY_SCHEDULED`, `EXPERIMENTAL_PUBLISHED`, `PROTECTED_VALIDATION_RECORDED`, `PROMOTION_RECORDED`, `SOAK_OBSERVED`, and `REVERT_RECORDED`.
- Produces: replayed projection fields `retry`, `experimental_publication`, `protected_validation`, `promotion`, `soak_observations`, and `revert`.
- Preserves: current manifests, hash-chain format, isolated-authority checks, and existing phase-three behavior.

- [ ] **Step 1: Write failing reducer tests**

Add tests that construct normalized events and assert:

```python
assert projection.experimental_publication.branch == "experimental/exp-product-001"
assert projection.retry.changed_action == "replace brittle parser with token scanner"
assert projection.retry.attempt == 2
assert projection.promotion.merge_commit == "b" * 40
assert projection.soak_observations[-1].healthy is True
assert projection.revert.restored_tree == "c" * 40
```

Also assert duplicate publication, unchanged retry actions, retry attempts above three, soak before merge, acceptance without a healthy 24-hour observation, and revert without a hard failure fail closed with stable error codes.

- [ ] **Step 2: Run reducer tests and verify RED**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_experiment.py benchmarks/tests/test_ledger.py`

Expected: failures because the lifecycle event types and projection fields do not exist.

- [ ] **Step 3: Implement immutable lifecycle value objects and reduction**

Add frozen dataclasses with strict canonical serialization:

```python
@dataclass(frozen=True, slots=True)
class RetryRecord:
    failed_stage_attempt_id: str
    attempt: int
    failure_class: str
    changed_action: str
    scheduled_at: str

@dataclass(frozen=True, slots=True)
class ExperimentalPublication:
    branch: str
    commit: str
    tree: str
    candidate_packet_digest: str

@dataclass(frozen=True, slots=True)
class SoakObservation:
    merge_commit: str
    observed_at: str
    healthy: bool
    evidence_digest: str
```

Require exact payload keys, bounded UTF-8 strings, canonical object IDs/digests, monotonic attempts, changed retry actions, and legal state ordering. Add new events to `_ISOLATED_AUTHORITY_REQUIRED_EVENTS` where the event must originate outside candidate authority.

- [ ] **Step 4: Preserve append-only compatibility**

Keep ledger schema version `1`; event rows already carry string event types and canonical payloads. Add replay tests proving old ledgers produce byte-identical projections for all existing fields and reject unknown event types as before.

- [ ] **Step 5: Run focused tests and commit**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_experiment.py benchmarks/tests/test_ledger.py`

Expected: PASS.

Commit: `feat(factory): record autonomous lifecycle recovery`

---

### Task 2: Add capability-validity and benchmark-gaming gates

**Files:**
- Create: `benchmarks/src/carl_bench/capability_validation.py`
- Create: `benchmarks/tests/test_capability_validation.py`
- Modify: `benchmarks/src/carl_bench/candidate_evidence.py`
- Modify: `benchmarks/src/carl_bench/promotion.py`

**Interfaces:**
- Produces: `CapabilityClaim`, `TransferCheck`, `TaskOutcome`, `CapabilityValidationReport`.
- Produces: `evaluate_capability_validation(claim, baseline, candidate, changed_paths) -> CapabilityValidationReport`.
- Consumed by: protected receipt verification and production disposition.

- [ ] **Step 1: Write failing anti-gaming tests**

Cover these exact cases:

```python
assert evaluate_capability_validation(valid_claim, baseline, improved, paths).eligible
assert "active_evaluator_modified" in evaluate_capability_validation(
    valid_claim, baseline, improved, ("benchmarks/tasks/dev/foo/task.toml",)
).reasons
assert "aggregate_hides_task_regression" in report_for_one_regressed_task.reasons
assert "transfer_gain_required" in public_score_only_gain.reasons
assert "selective_retry_detected" in dropped_valid_failure.reasons
assert "hard_coded_fixture_detected" in fixture_probe_failure.reasons
```

Require at least one held-out transfer check, complete valid/invalid trial accounting, unchanged evaluation identities, non-inferior guard tasks, and task-level outcome preservation.

- [ ] **Step 2: Run tests and verify RED**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_capability_validation.py`

Expected: import failure for `carl_bench.capability_validation`.

- [ ] **Step 3: Implement deterministic capability evaluation**

Use frozen dataclasses, exact tuple ordering, basis-point integer metrics, and sorted stable reason codes. Reject candidate changes beneath active benchmark tasks, metric packs, graders, workflow protection, promotion policy, or automation contract paths. Distinguish unit-contract success from held-out behavioral transfer.

- [ ] **Step 4: Bind capability report into protected validation**

Add `capability_report_digest` and `transfer_gain_basis_points` to `ProtectedValidationReceipt` and `PromotionExpectation`. Verification must reject missing, mismatched, or non-positive transfer evidence unless the preregistered claim type is correctness or compatibility and all affected contract cases improve with guards non-inferior.

- [ ] **Step 5: Run promotion and capability tests and commit**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_capability_validation.py benchmarks/tests/test_promotion.py`

Expected: PASS.

Commit: `feat(factory): reject benchmark-gamed candidates`

---

### Task 3: Make experimental publication independent and idempotent

**Files:**
- Create: `benchmarks/src/carl_bench/experimental_publication.py`
- Create: `benchmarks/tests/test_experimental_publication.py`
- Modify: `benchmarks/src/carl_bench/cli.py`
- Modify: `benchmarks/tests/test_cli.py`

**Interfaces:**
- Produces: `ExperimentalPublicationRequest` and `ExperimentalPublicationDecision`.
- Produces: `reconcile_experimental_publication(request, remote_snapshot) -> ExperimentalPublicationDecision`.
- CLI command: `carl-bench candidate publish-experimental` with exact ledger, experiment, repository, remote, branch, candidate packet, and Git executable arguments.

- [ ] **Step 1: Write failing reconciliation tests**

Assert decisions for `push_branch`, `record_existing_exact_branch`, `blocked_branch_identity_mismatch`, `blocked_candidate_packet_incomplete`, and `blocked_candidate_not_locally_eligible`. Assert the function has no `main`, PR, merge, release, or deployment capability.

- [ ] **Step 2: Run tests and verify RED**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_experimental_publication.py benchmarks/tests/test_cli.py`

Expected: missing module and CLI command failures.

- [ ] **Step 3: Implement narrow publication gateway**

Allow only `refs/heads/experimental/<experiment-id>`, reject existing mismatched refs, use argument-vector Git subprocesses, push exact `<candidate_commit>:refs/heads/<branch>` without force, refetch and verify the remote object ID, then append `EXPERIMENTAL_PUBLISHED` with the candidate packet digest.

- [ ] **Step 4: Prove publication does not require protected validation**

Add a process-level fake Git remote test where local deterministic, paired, review, security, and capability gates pass but protected validation is absent. Expect one immutable experimental ref and no PR/main mutation.

- [ ] **Step 5: Run tests and commit**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_experimental_publication.py benchmarks/tests/test_cli.py`

Expected: PASS.

Commit: `feat(factory): publish verified experimental candidates`

---

### Task 4: Integrate protected promotion, soak, and exact revert with the graph

**Files:**
- Create: `benchmarks/src/carl_bench/autonomy_controller.py`
- Create: `benchmarks/tests/test_autonomy_controller.py`
- Modify: `benchmarks/src/carl_bench/github_promotion.py`
- Modify: `benchmarks/src/carl_bench/promotion_monitor.py`

**Interfaces:**
- Produces: `ControllerSnapshot`, `ControllerAction`, and `next_controller_action(snapshot, now) -> ControllerAction`.
- Uses: `verify_protected_validation`, `reconcile_promotion`, `reconcile_revert`, and the experiment ledger.
- Produces only deterministic actions; Git/GitHub mutations remain in narrow gateways.

- [ ] **Step 1: Write the synthetic lifecycle test**

Construct a fixture that advances:

```text
experimental -> validating -> production_candidate -> promoting -> soaking -> accepted
```

Then inject a hard failure in a second fixture and assert:

```text
soaking -> reverting -> reverted
```

Restart the controller after each action and assert no duplicate event, branch, PR, merge, or revert is requested.

- [ ] **Step 2: Run tests and verify RED**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_autonomy_controller.py`

Expected: missing controller module.

- [ ] **Step 3: Implement deterministic orchestration**

Map verified receipts and GitHub snapshots to one action at a time: `record_validation`, `create_pr`, `mark_ready`, `enable_auto_merge`, `record_merge`, `observe_soak`, `accept`, `create_revert_pr`, `record_reverted`, `schedule_retry`, or `idle`. Require the promotion lease from validation through acceptance/revert and bind all actions to exact parent, candidate, PR, merge, and restored-tree identities.

- [ ] **Step 4: Add recovery and SLA tests**

Test three changed infrastructure retry actions, rejection of a fourth, stale lease reconciliation, 26-hour soak observation failure, two-hour hard-failure revert SLA, changed-main cancellation, and tampered receipt rejection.

- [ ] **Step 5: Run controller contracts and commit**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_autonomy_controller.py benchmarks/tests/test_github_promotion.py benchmarks/tests/test_promotion_monitor.py`

Expected: PASS.

Commit: `feat(factory): orchestrate autonomous promotion lifecycle`

---

### Task 5: Publish the public autonomy graph and truthful README framing

**Files:**
- Create: `docs/autonomous-improvement.md`
- Modify: `README.md`
- Modify: `benchmarks/tests/test_integration_contract.py`
- Modify: `tests/docs_contract.rs`

**Interfaces:**
- Public documentation links to the approved design while exposing only sanitized architecture and evidence.
- README status is `commissioning` until the live acceptance receipt exists.

- [ ] **Step 1: Write failing documentation contracts**

Assert README and the public guide contain: `Autonomous improvement: commissioning`, `experimental`, `protected main`, `independent validation`, `24-hour soak`, `exact revert`, `no routine human approval`, `capability transfer`, and a link to `docs/autonomous-improvement.md`. Assert README does not claim all historical commits were autonomous.

- [ ] **Step 2: Run documentation tests and verify RED**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_integration_contract.py && cargo test --locked --test docs_contract`

Expected: missing public guide/status assertions.

- [ ] **Step 3: Write README section and public graph**

Add a top-level section immediately after the project introduction. State that Carl is commissioning a graph-engineered autonomous improvement factory that implements, evaluates, pushes experimental candidates, independently promotes verified gains, soaks production, and reverts regressions without routine human approval. Include the responsibility Mermaid graph, exact safety boundaries, capability-validity rules, and links to GitHub branches/PRs as evidence becomes available.

- [ ] **Step 4: Run documentation tests and commit**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_integration_contract.py && cargo test --locked --test docs_contract && git diff --check`

Expected: PASS.

Commit: `docs: explain autonomous improvement factory`

---

### Task 6: Add cloud execution workflows

**Files:**
- Create: `.github/workflows/autonomous-improvement.yml`
- Create: `.github/workflows/autonomous-soak.yml`
- Create: `benchmarks/src/carl_bench/cloud_execution.py`
- Create: `benchmarks/tests/test_cloud_execution.py`

**Interfaces:**
- Produces: `CloudRunRequest`, `CloudRunSnapshot`, and `reconcile_cloud_run(request, snapshot)`.
- Workflows accept immutable experiment, parent, candidate, task-set, metric-pack, policy, and
  request digests through `workflow_dispatch` inputs.
- Workflows upload bounded artifacts and never expose signing credentials to candidate processes.

- [ ] **Step 1: Write failing cloud-dispatch contract tests**

Assert exact commit binding, allowlisted workflow names, idempotent dispatch keys, artifact digest
verification, expired-artifact rejection, and `local_heavy_fallback_forbidden` when remote execution
is unavailable.

- [ ] **Step 2: Run tests and verify RED**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_cloud_execution.py`

Expected: missing cloud execution module.

- [ ] **Step 3: Implement deterministic cloud reconciliation**

Permit actions `dispatch`, `await_run`, `download_artifacts`, `record_success`, `schedule_retry`, or
`blocked`. Bind repository, workflow file, request digest, GitHub run ID, head SHA, conclusion, and
artifact digests. Reject local Cargo, pytest, Docker, Colima, benchmark, and soak command requests.

- [ ] **Step 4: Add GitHub-hosted workflows**

Use pinned actions and least-privilege permissions. The improvement workflow checks out the exact
SHA, installs locked Rust/Python dependencies, runs deterministic and paired suites, uploads bounded
JSON evidence, and reports no production status. The soak workflow observes an exact merge commit,
runs repository health probes, and uploads a merge-bound observation. Neither workflow pushes code
or merges PRs.

- [ ] **Step 5: Run workflow and cloud tests and commit**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_cloud_execution.py && actionlint .github/workflows/autonomous-improvement.yml .github/workflows/autonomous-soak.yml`

Expected: PASS.

Commit: `feat(factory): offload autonomous verification to cloud runners`

---

### Task 7: Rewrite and align the live automation portfolio

**Files:**
- Update via Codex automation API: `daily-carl-self-improvement-graph`
- Update via Codex automation API: `daily-carl-production-review`
- Update via Codex automation API: `carl-promotion-and-rollback-watchdog`
- Update via Codex automation API: `daily-carl-autonomy-outcome-monitor`
- Update via Codex automation API: `weekly-carl-feature-and-autonomy-report`
- Create via Codex automation API: `carl-autonomy-loop-supervisor`
- Create: `docs/automation-prompts/carl-autonomous-improvement.md`
- Create: `benchmarks/tests/test_automation_prompt_contract.py`

**Interfaces:**
- Builder: daily, `gpt-5.6-sol`, high reasoning, sole candidate mutation owner.
- Validator/promoter: every six hours, `gpt-5.6-sol`, high reasoning, independent disposition and protected PR owner.
- Recovery controller: every two hours, `gpt-5.6-luna`, medium reasoning, compact idle exit and active-state reconciliation only.
- Outcome monitor: daily, `gpt-5.6-luna`, medium reasoning, throughput audit only.
- Loop supervisor: every six hours, `gpt-5.6-sol`, `ultra` reasoning, no-op unless commissioning, critical, stuck, or repeatedly failed.
- Weekly report: weekly, `gpt-5.6-terra`, medium reasoning, outcome synthesis only.
- All automations are thin local control-plane clients until a remote Codex project exists. They
  dispatch heavy work to GitHub-hosted workflows and forbid silent local heavy fallback.

- [ ] **Step 1: Write failing prompt-contract tests**

Load sanitized prompt snapshots from `docs/automation-prompts/carl-autonomous-improvement.md` and assert:

```python
assert builder.allows_experimental_push_without_protected_validation
assert builder.requires_implementation_and_retest
assert promoter.allows_pr_and_auto_merge_without_human_approval
assert watchdog.forbids_idle_narrative
assert supervisor.requires_changed_recovery_action
assert outcome_monitor.critical_after_two_zero_candidate_cycles
```

Also assert exactly one mutation owner, one disposition owner, one promotion owner, and no direct-main/force-push/deploy/release authority.

- [ ] **Step 2: Run prompt tests and verify RED**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_automation_prompt_contract.py`

Expected: missing prompt snapshot and parser.

- [ ] **Step 3: Write canonical prompt portfolio**

Document each full prompt and schedule in `docs/automation-prompts/carl-autonomous-improvement.md`. Include explicit success outputs, retry behavior, state ownership, GitHub authority, anti-gaming gates, idle behavior, and handoff fields.

- [ ] **Step 4: Apply all six automation definitions**

Use the Codex automation update API. Preserve project ID `e02aa208-67fe-4392-912c-d55c3314dafe`, local execution, and `/Users/openclaw/Documents/Carl-agent` cwd. Update existing IDs rather than creating duplicates; create only `carl-autonomy-loop-supervisor`.

- [ ] **Step 5: Re-read definitions and run prompt tests**

Verify active status, schedules, models, reasoning effort, project target, cwd, and exact prompt digest for all six definitions.

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_automation_prompt_contract.py`

Expected: PASS.

- [ ] **Step 6: Commit**

Commit: `docs(factory): align autonomous automation portfolio`

---

### Task 8: Commission with adversarial synthetic verification

**Files:**
- Create: `benchmarks/tests/test_autonomy_commissioning.py`
- Create runtime artifacts outside repository: owner-private commissioning ledger and receipts beneath the automation data root.

**Interfaces:**
- Consumes the lifecycle, capability validator, publication gateway, controller, and prompt portfolio.
- Produces a sanitized commissioning report with exact artifact digests.

- [ ] **Step 1: Build a disposable bare Git fixture and protected-runner fixture**

Create baseline, valid candidate, benchmark-gamed candidate, and hard-regression candidate commits. Keep signer material outside every candidate checkout and expose only signed receipts.

- [ ] **Step 2: Run the healthy synthetic path**

Assert exactly one experimental ref, one promotion PR identity, one merge, at least two restart recoveries, a 24-hour simulated observation sequence bound to the merge commit, and terminal `accepted`.

- [ ] **Step 3: Run adversarial paths**

Tamper candidate evidence, increase only the public score, alter an evaluator, replay a receipt, change `main`, duplicate a tick, kill the controller between effect and receipt, and inject a hard regression. Expect fail-closed rejection, changed retries, or one exact revert restoring the preceding tree.

- [ ] **Step 4: Run the commissioning suite**

Run: `benchmarks/.venv/bin/pytest -q benchmarks/tests/test_autonomy_commissioning.py benchmarks/tests/test_autonomy_controller.py benchmarks/tests/test_capability_validation.py benchmarks/tests/test_automation_prompt_contract.py`

Expected: PASS with no network, credentials, or production mutations.

- [ ] **Step 5: Run full repository verification and commit**

Run:

```bash
benchmarks/.venv/bin/pytest -q benchmarks/tests
benchmarks/.venv/bin/ruff check benchmarks
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
git diff --check
```

Expected: all commands exit zero.

Commit: `test(factory): commission autonomous improvement loop`

---

### Task 9: Execute one live product improvement end to end

**Files:**
- Durable artifacts only under the builder, reviewer, promoter, and supervisor automation roots.
- GitHub effects: one immutable `experimental/*` branch and, if independently eligible, one protected PR to `main`.

**Interfaces:**
- Produces the first live acceptance receipt used to change README status from commissioning to operational after a successful 24-hour soak.

- [ ] **Step 1: Dispatch the builder against exact current `origin/main`**

Require a user-relevant hypothesis, failing test, implementation commit, paired transfer evaluation, guards, security review, and immutable experimental push. A report-only completion fails commissioning.

- [ ] **Step 2: Dispatch independent validation**

Reproduce the exact candidate from a clean checkout. Reject benchmark gaming and record exactly one disposition. For an eligible improvement, open/reconcile the protected PR and enable auto-merge without human approval after checks pass.

- [ ] **Step 3: Follow merge and soak**

Verify exact resulting tree, record periodic health observations for 24 hours, and accept or create one exact revert PR on hard regression.

- [ ] **Step 4: Verify public evidence and automation recovery**

Confirm exact experimental branch, PR, production commit, required checks, durable receipts, no duplicate effects, and concise progress updates. Exercise one interrupted controller tick and verify automatic resumption.

- [ ] **Step 5: Update operational status only after acceptance**

Change README status to `Autonomous improvement: operational` with exact evidence links only if the live candidate reaches terminal `accepted`. Otherwise keep commissioning status, schedule a changed repair or new hypothesis automatically, and continue the loop without user intervention.

- [ ] **Step 6: Commit any evidence-bound documentation update through the normal protected PR path**

Expected: documentation follows the same autonomous experimental and production process; no direct `main` push.
