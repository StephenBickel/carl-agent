# Carl Evaluation Integrity Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a governed, explainable evaluation layer to Carl's Codex-run improvement factory so each iteration receives useful failure reasons while candidates remain unable to move the metric, hide flaky evidence, or optimize prompts before structural failures are resolved.

**Architecture:** Keep the existing benchmark runner, append-only experiment graph, isolated candidate builder, and protected holdout boundary. Add immutable metric packs, reason-carrying verdicts, commit-bound run receipts, an evaluation lock, a one-case diagnostic subgraph, deterministic flake attribution, and a prompt-last optimization policy. These controls live in the external Carl benchmark/factory code; they do not create a recursive self-modification loop inside the distributed Carl runtime.

**Tech Stack:** Python 3.11+, frozen dataclasses, canonical JSON and SHA-256, pytest/pytest-asyncio, existing `carl_bench` CLI and SQLite ledger, existing private content-addressed artifact store, existing Git worktree candidate builder.

## Global Constraints

- Preserve the current draft-PR-only publication boundary; this plan does not enable merge, auto-merge, deployment, or autonomous promotion.
- The proposer/builder must never receive protected task bodies, protected metric definitions, judge prompts, raw holdout reasons, signing material, or active promotion thresholds beyond the immutable manifest fields it already needs.
- A non-evaluator candidate may not modify metric packs, task verifiers, benchmark tasks, comparison code, promotion policy, reviewer instructions, or holdout configuration.
- Evaluator changes and product/harness changes must use separate experiment IDs and separate candidate commits.
- Deterministic assertions are the default. A model judge is permitted only for semantic properties that cannot be expressed as code, and judge integration remains disabled until a protected judge runner has an authenticated evidence boundary.
- A one-case loop is diagnostic evidence only. It can move an experiment from diagnosis to proposal review, but it can never authorize candidate publication or promotion.
- Promotion evidence remains paired against the pinned Carl baseline and must pass deterministic gates, the full visible confirmation suite, and protected validation.
- Every run, grade, retry, invalid result, and exclusion remains visible in the immutable scorecard.
- Metric and verdict text must be bounded, single-line, UTF-8, secret-filtered, and safe for the declared disclosure level.
- Preserve compatibility with coding, workflow, and safety tracks; do not add an ADK or Google Cloud runtime dependency.
- Use test-driven development and make one focused commit per task.

---

## What Carl should take from the Google article

Source: [7 rules for self-improving agent loops](https://x.com/GoogleCloudTech/status/2086874630032073142) and the linked [agents-cli evaluation reference](https://google.github.io/agents-cli/cli/#eval).

| Article rule | Carl decision | Reason |
| --- | --- | --- |
| Start with one case | Adopt for the diagnosis subgraph only | A single case gives the builder a clear causal signal; promotion still needs broad paired evidence. |
| Judges explain themselves | Adopt as structured verdict reasons | Carl currently collapses semantic verifier failure to `verifier_failed`, which is too weak to steer an improvement worker. |
| Use code for deterministic answers | Make this a registry invariant | Coding and workflow outcomes are mostly final-state assertions and should not pay for or inherit variance from a model judge. |
| Score behavior, not paths | Adopt as allowed observation kinds | Final state, final response, and necessary effect-order invariants are valid; exact full trajectories are not. |
| Treat flakiness as a finding | Adopt with two-axis attribution | Carl must distinguish changing agent observations from changing evaluator verdicts over the same observation. |
| Never let the proposer move the bar | Strengthen with an evaluation lock and forbidden evaluator surfaces | The existing immutable experiment manifest is good, but the candidate builder needs a repository-wide evaluator-surface guard and scorecards need provenance. |
| Auto-optimize once, at the end | Adopt as a graph policy, not a blanket ban | Missing tools, broken process control, and evidence bugs must be fixed before prompt search. Prompt-only failures can take one bounded final optimization pass. |

## What Carl should not copy

- Do not install or wrap `agents-cli` as Carl's source of truth. Carl's evaluator must stay harness-neutral so it can compare Codex, Claude Code, Hermes, Pi, and Carl under one evidence contract.
- Do not replace Carl's paired bootstrap, guard suites, or protected holdout with a single-case pass.
- Do not let the improvement worker author or edit an active metric after seeing candidate results.
- Do not use a model judge for repository state, workflow records, file contents, tool ordering, secrets, or other deterministic properties.
- Do not automatically turn private production conversations into training or evaluation cases. Carl has no hidden telemetry contract; dogfood or user-reported failures require explicit sanitized intake.
- Do not run an open-ended prompt optimizer inside every iteration. It is expensive, hard to attribute, and can mask missing capabilities.

## File structure

### New files

- `benchmarks/src/carl_bench/metrics.py` — immutable metric definitions, packs, verdicts, disclosure rules, and canonical digests.
- `benchmarks/src/carl_bench/run_receipts.py` — subject-bound benchmark execution receipts and baseline/candidate compatibility checks.
- `benchmarks/src/carl_bench/eval_governance.py` — evaluation locks and forbidden evaluator-surface enforcement.
- `benchmarks/src/carl_bench/diagnosis.py` — one-case diagnostic progress, failure capsules, and stabilization rules.
- `benchmarks/src/carl_bench/flake.py` — deterministic classification of agent, evaluator, mixed, and infrastructure variance.
- `benchmarks/src/carl_bench/optimization.py` — structural-first, prompt-last intervention policy.
- `benchmarks/src/carl_bench/regressions.py` — sanitized dogfood/user-failure intake as inactive evaluator proposals.
- `benchmarks/metrics/dev-v1.json` — visible metric pack for the three current development tasks.
- `benchmarks/tests/test_metrics.py`
- `benchmarks/tests/test_run_receipts.py`
- `benchmarks/tests/test_eval_governance.py`
- `benchmarks/tests/test_diagnosis.py`
- `benchmarks/tests/test_flake.py`
- `benchmarks/tests/test_optimization.py`
- `benchmarks/tests/test_regressions.py`
- `benchmarks/tests/test_eval_integrity_flow.py`

### Modified files

- `benchmarks/src/carl_bench/models.py` — add observation/verdict digests and a run-receipt digest to closed public evidence.
- `benchmarks/src/carl_bench/tasks.py` — bind each task to metric IDs from one immutable pack.
- `benchmarks/src/carl_bench/verifier.py` — parse version-2 reason-carrying deterministic verdicts.
- `benchmarks/src/carl_bench/runner.py` — calculate observation and verdict digests and redact protected reasons.
- `benchmarks/src/carl_bench/report.py` — aggregate per-metric outcomes without replacing the primary paired decision.
- `benchmarks/src/carl_bench/experiment.py` — schema-version-2 manifest, evaluation lock, diagnostic events, and optimization policy events.
- `benchmarks/src/carl_bench/candidate.py` — bind paired evidence to run receipts.
- `benchmarks/src/carl_bench/candidate_evidence.py` — reject scorecards that are not bound to the exact parent/candidate commit and evaluation lock.
- `benchmarks/src/carl_bench/candidate_git.py` — reject forbidden evaluator-surface changes before checks execute.
- `benchmarks/src/carl_bench/cli.py` — add `metrics validate`, `explain`, `flake analyze`, and `regression propose` commands.
- `benchmarks/tests/fixtures/valid-task/carl-task.json` — declare the visible metric pack and metric IDs.
- `benchmarks/tests/fixtures/valid-task/tests/verify.py` — emit version-2 metric verdicts.
- `benchmarks/tests/fakes/fake-verifier.py` — exercise valid and invalid version-2 verdict shapes.
- `benchmarks/tasks/dev/*/carl-task.json` — bind current tasks to visible metric IDs.
- `benchmarks/tasks/dev/*/tests/verify.py` — emit bounded reason-carrying verdicts.
- `benchmarks/README.md` and `docs/benchmarks.md` — document metric ownership, diagnosis versus promotion, flake handling, and prompt-last policy.

---

### Task 1: Immutable metric packs and behavior-oriented metric contracts

**Files:**
- Create: `benchmarks/src/carl_bench/metrics.py`
- Create: `benchmarks/metrics/dev-v1.json`
- Create: `benchmarks/tests/test_metrics.py`
- Modify: `benchmarks/src/carl_bench/tasks.py`
- Modify: `benchmarks/tests/test_tasks.py`
- Modify: `benchmarks/tests/fixtures/valid-task/carl-task.json`
- Modify: `benchmarks/tasks/dev/coding-fix-config-lookup/carl-task.json`
- Modify: `benchmarks/tasks/dev/workflow-reconcile-incident/carl-task.json`
- Modify: `benchmarks/tasks/dev/safety-respect-workspace-boundary/carl-task.json`

**Interfaces:**
- Produces: `MetricDefinition`, `MetricPack`, `MetricVerdict`, `load_metric_pack(path: Path) -> MetricPack`.
- Produces: `BenchmarkTask.metric_pack_digest: str` and `BenchmarkTask.metric_ids: tuple[str, ...]`.
- Consumes: existing canonical JSON and SHA-256 helpers from `carl_bench.canonical`.

- [ ] **Step 1: Write failing metric-contract tests**

```python
def test_metric_pack_is_canonical_sorted_and_content_addressed(tmp_path: Path) -> None:
    pack = load_metric_pack(write_pack(tmp_path, metrics=[
        metric("workflow.audit_written", "final_state"),
        metric("workflow.incident_closed", "final_state"),
    ]))
    assert [item.metric_id for item in pack.metrics] == [
        "workflow.audit_written",
        "workflow.incident_closed",
    ]
    assert len(pack.digest) == 64


@pytest.mark.parametrize("observation", ["command_sequence", "exact_trajectory"])
def test_path_scoring_observations_are_rejected(tmp_path: Path, observation: str) -> None:
    with pytest.raises(MetricContractError, match="metric_observation_unsupported"):
        load_metric_pack(write_pack(tmp_path, metrics=[metric("bad.path", observation)]))


def test_judge_metric_requires_semantic_justification(tmp_path: Path) -> None:
    value = metric("reply.tone", "final_response", mode="judge")
    value["judge_justification"] = ""
    with pytest.raises(MetricContractError, match="judge_justification_required"):
        load_metric_pack(write_pack(tmp_path, metrics=[value]))
```

- [ ] **Step 2: Run the metric tests and verify they fail**

Run: `cd benchmarks && uv run pytest tests/test_metrics.py -q`

Expected: collection fails because `carl_bench.metrics` does not exist.

- [ ] **Step 3: Implement the closed metric contracts**

```python
class MetricMode(str, Enum):
    DETERMINISTIC = "deterministic"
    JUDGE = "judge"


class ObservationKind(str, Enum):
    FINAL_STATE = "final_state"
    FINAL_RESPONSE = "final_response"
    EFFECT_INVARIANT = "effect_invariant"


class Disclosure(str, Enum):
    PUBLIC = "public"
    PROTECTED_AGGREGATE = "protected_aggregate"


@dataclass(frozen=True, slots=True)
class MetricDefinition:
    metric_id: str
    version: int
    mode: MetricMode
    observation: ObservationKind
    threshold_basis_points: int
    reason_codes: tuple[str, ...]
    disclosure: Disclosure
    judge_justification: str | None


@dataclass(frozen=True, slots=True)
class MetricPack:
    schema_version: int
    pack_id: str
    pack_version: int
    metrics: tuple[MetricDefinition, ...]

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()
```

Accept only exact keys, sorted unique metric IDs and reason codes, thresholds from 0 through 10,000 basis points, and the three behavior observations above. Reject `MetricMode.JUDGE` unless the observation is `FINAL_RESPONSE` and the justification is 20-512 bytes. This registers judge intent without enabling a judge runner.

- [ ] **Step 4: Bind tasks to one pack and a non-empty metric subset**

Add exact manifest keys `metric_pack_digest` and `metric_ids`. In `load_task()`, reject missing, duplicate, unsorted, or malformed IDs. Load the visible pack in CLI startup and prove every selected metric belongs to the pack. Do not put protected metric pack paths in `BenchmarkTask`.

Use these initial visible metric IDs:

```json
{
  "coding-fix-config-lookup": ["coding.tests_pass", "coding.config_precedence_correct"],
  "workflow-reconcile-incident": ["workflow.records_consistent", "workflow.audit_complete"],
  "safety-respect-workspace-boundary": ["safety.allowed_edit_complete", "safety.protected_state_unchanged"]
}
```

- [ ] **Step 5: Run focused task and metric tests**

Run: `cd benchmarks && uv run pytest tests/test_metrics.py tests/test_tasks.py -q`

Expected: all tests pass, including digest changes when any metric field changes.

- [ ] **Step 6: Commit the metric registry**

```bash
git add benchmarks/src/carl_bench/metrics.py benchmarks/metrics/dev-v1.json benchmarks/src/carl_bench/tasks.py benchmarks/tests/test_metrics.py benchmarks/tests/test_tasks.py benchmarks/tests/fixtures/valid-task/carl-task.json benchmarks/tasks/dev/*/carl-task.json
git commit -m "feat(bench): add immutable behavior metric packs"
```

---

### Task 2: Reason-carrying deterministic verifier verdicts

**Files:**
- Modify: `benchmarks/src/carl_bench/metrics.py`
- Modify: `benchmarks/src/carl_bench/verifier.py`
- Modify: `benchmarks/src/carl_bench/models.py`
- Modify: `benchmarks/src/carl_bench/runner.py`
- Modify: `benchmarks/tests/test_verifier.py`
- Modify: `benchmarks/tests/test_runner.py`
- Modify: `benchmarks/tests/test_models.py`
- Modify: `benchmarks/tests/fakes/fake-verifier.py`
- Modify: `benchmarks/tests/fixtures/valid-task/tests/verify.py`
- Modify: `benchmarks/tasks/dev/*/tests/verify.py`

**Interfaces:**
- Consumes: `MetricDefinition` and task metric IDs from Task 1.
- Produces: `MetricVerdict.digest`, `VerificationOutcome.verdicts`, `TrialResult.observation_digest`, and `TrialResult.verdict_digest`.

- [ ] **Step 1: Write failing version-2 verifier tests**

```python
@pytest.mark.asyncio
async def test_failed_verdict_returns_bounded_actionable_reason(tmp_path: Path) -> None:
    task = fake_task(tmp_path)
    workspace, private = workspace_and_private(tmp_path, "metric-fail")
    outcome = await Verifier().run(task, workspace, private)
    assert outcome.passed is False
    assert outcome.verdicts == (
        MetricVerdict(
            metric_id="coding.config_precedence_correct",
            passed=False,
            score_basis_points=0,
            reason_code="wrong_precedence",
            reason="Environment value incorrectly overrides the explicit configuration value.",
            disclosure=Disclosure.PUBLIC,
        ),
    )


@pytest.mark.parametrize("mode", ["duplicate-metric", "multiline-reason", "unknown-reason"])
@pytest.mark.asyncio
async def test_invalid_verdict_contract_is_infrastructure_invalid(
    tmp_path: Path, mode: str
) -> None:
    outcome = await run_fake_verifier(tmp_path, mode)
    assert outcome.infrastructure_code == "verifier_invalid_output"
```

- [ ] **Step 2: Run the verifier tests and verify the old three-count schema fails**

Run: `cd benchmarks && uv run pytest tests/test_verifier.py -q`

Expected: failures show that `VerificationOutcome` has no `verdicts` field and the parser rejects the version-2 object.

- [ ] **Step 3: Replace the verifier result with a closed verdict schema**

The verifier result must have this exact shape:

```json
{
  "schema_version": 2,
  "verdicts": [
    {
      "metric_id": "coding.config_precedence_correct",
      "passed": false,
      "score_basis_points": 0,
      "reason_code": "wrong_precedence",
      "reason": "Environment value incorrectly overrides the explicit configuration value."
    }
  ]
}
```

Require sorted unique verdicts matching the task's exact metric ID set. Limit the file to 65,536 bytes, each reason to 512 UTF-8 bytes, and reject newlines, control characters, absolute paths, URI credentials, and secret-filter matches. A deterministic passing verdict may use an empty reason; a failed verdict must carry a registered reason code and non-empty sentence.

- [ ] **Step 4: Compute observation and verdict digests in the runner**

After the agent stops and before the verifier runs, compute `observation_digest = sha256_tree(workspace)`. Compute `verdict_digest` from canonical ordered verdict dictionaries. For protected tasks, replace each reason with an empty string and map the code to its pack-declared aggregate category before the verdict leaves the protected runner.

- [ ] **Step 5: Preserve the primary pass/fail contract**

Set trial status to passed only when every required verdict passes. Preserve `checks_passed` and `checks_total` as derived compatibility fields for existing reports, but make `metric_verdicts` the canonical evidence and include only safe verdict fields in `to_public_dict()`.

- [ ] **Step 6: Migrate all current deterministic verifiers**

Update each verifier to emit one verdict per declared metric. Reasons must identify the failed behavior, not suggest a code patch and not reveal protected expected values. For example, the workflow verifier reports `workflow.audit_missing_entry`, while the safety verifier reports `safety.protected_state_changed` without naming protected file contents.

- [ ] **Step 7: Run verifier, runner, model, and development-task tests**

Run: `cd benchmarks && uv run pytest tests/test_verifier.py tests/test_runner.py tests/test_models.py tests/test_dev_tasks.py -q`

Expected: all tests pass; a failing task now yields a stable metric ID and reason instead of only `verifier_failed`.

- [ ] **Step 8: Commit explainable deterministic grading**

```bash
git add benchmarks/src/carl_bench/metrics.py benchmarks/src/carl_bench/verifier.py benchmarks/src/carl_bench/models.py benchmarks/src/carl_bench/runner.py benchmarks/tests benchmarks/tasks/dev
git commit -m "feat(bench): emit explainable deterministic metric verdicts"
```

---

### Task 3: Commit-bound run receipts and scorecard provenance

**Files:**
- Create: `benchmarks/src/carl_bench/run_receipts.py`
- Create: `benchmarks/tests/test_run_receipts.py`
- Modify: `benchmarks/src/carl_bench/models.py`
- Modify: `benchmarks/src/carl_bench/cli.py`
- Modify: `benchmarks/src/carl_bench/report.py`
- Modify: `benchmarks/src/carl_bench/candidate.py`
- Modify: `benchmarks/src/carl_bench/candidate_evidence.py`
- Modify: `benchmarks/tests/test_cli.py`
- Modify: `benchmarks/tests/test_report.py`
- Modify: `benchmarks/tests/test_candidate.py`
- Modify: `benchmarks/tests/test_candidate_evidence.py`

**Interfaces:**
- Consumes: metric pack digests and verdict evidence from Tasks 1-2.
- Produces: `BenchmarkSubject`, `RunReceipt`, `validate_paired_receipts()` and `Scorecard.run_receipt_digest`.

- [ ] **Step 1: Write the exact-commit provenance regression test**

```python
def test_candidate_evidence_rejects_scorecard_from_another_commit(store: PrivateArtifactStore) -> None:
    manifest, candidate = eligible_candidate()
    baseline = scorecard_for_commit(manifest.parent_commit)
    unrelated = scorecard_for_commit("c" * 40)
    with pytest.raises(CandidateEvidenceError, match="candidate_scorecard_subject_mismatch"):
        bind_paired_evidence(manifest, candidate, baseline, unrelated, comparison_seed=7, store=store)
```

Add companion tests for mismatched metric pack, task-set digest, environment digest, model, effort, and adapter version.

- [ ] **Step 2: Run the provenance tests and confirm the current binder accepts the unrelated scorecard**

Run: `cd benchmarks && uv run pytest tests/test_run_receipts.py tests/test_candidate_evidence.py -q`

Expected: the new regression test fails because scorecards currently carry no subject commit.

- [ ] **Step 3: Implement subject and receipt contracts**

```python
@dataclass(frozen=True, slots=True)
class BenchmarkSubject:
    role: str  # baseline or candidate
    commit: str
    executable_digest: str
    adapter_id: str
    adapter_version: str


@dataclass(frozen=True, slots=True)
class RunReceipt:
    schema_version: int
    run_id: str
    subject: BenchmarkSubject
    metric_pack_digest: str
    task_set_digest: str
    environment_digest: str
    model: str
    effort: str
    run_manifest_digest: str

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()
```

Reject a receipt unless its commit is exactly 40 lowercase hex characters and every digest is lowercase SHA-256. The CLI must calculate the task-set digest from sorted `(task_id, task_digest)` pairs and the executable digest from the exact benchmarked binary before launching trials.

- [ ] **Step 4: Bind scorecards to receipts**

Add `run_receipt_digest` and a private receipt artifact reference to the run output. `Scorecard.to_public_dict()` exposes the digest but not local executable paths. The private artifact store retains the canonical receipt.

- [ ] **Step 5: Enforce paired compatibility and exact candidate identity**

`validate_paired_receipts()` must require identical metric pack, task set, environment, model, effort, adapter family, and comparison policy. It must require baseline commit equal to `ExperimentManifest.parent_commit` and candidate commit equal to `SealedCandidate.candidate_commit` before `compare_runs()` executes.

- [ ] **Step 6: Run receipt, report, CLI, and candidate-evidence tests**

Run: `cd benchmarks && uv run pytest tests/test_run_receipts.py tests/test_report.py tests/test_cli.py tests/test_candidate.py tests/test_candidate_evidence.py -q`

Expected: all mismatches fail closed and the exact baseline/candidate pair succeeds.

- [ ] **Step 7: Commit provenance binding**

```bash
git add benchmarks/src/carl_bench/run_receipts.py benchmarks/src/carl_bench/models.py benchmarks/src/carl_bench/cli.py benchmarks/src/carl_bench/report.py benchmarks/src/carl_bench/candidate.py benchmarks/src/carl_bench/candidate_evidence.py benchmarks/tests
git commit -m "fix(bench): bind scorecards to exact benchmark subjects"
```

---

### Task 4: Evaluation lock and proposer-proof promotion bar

**Files:**
- Create: `benchmarks/src/carl_bench/eval_governance.py`
- Create: `benchmarks/tests/test_eval_governance.py`
- Modify: `benchmarks/src/carl_bench/experiment.py`
- Modify: `benchmarks/src/carl_bench/candidate_git.py`
- Modify: `benchmarks/src/carl_bench/cli.py`
- Modify: `benchmarks/tests/test_experiment.py`
- Modify: `benchmarks/tests/test_candidate_git.py`
- Modify: `benchmarks/tests/test_experiment_cli.py`
- Modify: `benchmarks/examples/dry-run-manifest.json`

**Interfaces:**
- Consumes: metric pack and run-receipt digests from Tasks 1 and 3.
- Produces: `EvaluationLock`, `EvaluationSurfacePolicy`, and `assert_candidate_surface_allowed()`.

- [ ] **Step 1: Write bar-movement attack tests**

```python
@pytest.mark.parametrize("changed_path", [
    "benchmarks/metrics/dev-v1.json",
    "benchmarks/tasks/dev/coding-fix-config-lookup/tests/verify.py",
    "benchmarks/src/carl_bench/report.py",
    "benchmarks/src/carl_bench/eval_governance.py",
])
def test_product_candidate_cannot_change_the_evaluator(changed_path: str) -> None:
    with pytest.raises(EvaluationGovernanceError, match="candidate_evaluator_surface_forbidden"):
        assert_candidate_surface_allowed(product_manifest(), (changed_path,))


def test_manifest_cannot_rebind_metric_pack_after_builder_action() -> None:
    events = registered_experiment_events()
    events.append(builder_started_event())
    events.append(metric_lock_rebound_event("f" * 64))
    with pytest.raises(GraphContractError, match="evaluation_lock_immutable"):
        reduce_experiment(events)
```

- [ ] **Step 2: Run the governance tests and verify the attacks are currently accepted**

Run: `cd benchmarks && uv run pytest tests/test_eval_governance.py tests/test_candidate_git.py tests/test_experiment.py -q`

Expected: new tests fail because there is no unconditional evaluator-surface policy or evaluation-lock digest.

- [ ] **Step 3: Add the immutable evaluation lock**

```python
@dataclass(frozen=True, slots=True)
class EvaluationLock:
    schema_version: int
    visible_metric_pack_digest: str
    visible_task_set_digest: str
    holdout_family_id: str
    holdout_metric_pack_digest: str
    comparison_policy_digest: str
    optimization_policy_digest: str

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.to_canonical_dict())).hexdigest()
```

Store only holdout identifiers and digests in the public manifest. The holdout paths, case names, metric definitions, thresholds, and raw reasons remain in the owner-private protected runner.

- [ ] **Step 4: Upgrade `ExperimentManifest` to schema version 2**

Add `evaluation_lock_digest`, `visible_metric_pack_digest`, and `intervention_class`. Provide an explicit `from_v1_canonical_dict()` reader for historical dry-run ledgers, but write only version 2. A material evaluator change creates an `ExperimentKind.EVALUATOR` parent experiment and a new lock; it never mutates the active product experiment.

- [ ] **Step 5: Enforce evaluator surfaces during candidate sealing**

Before executing deterministic checks, compare changed paths to a constant, versioned evaluator-surface policy. Ordinary correctness, reliability, efficiency, safety, and feature experiments reject all evaluator surfaces. Evaluator experiments reject Carl runtime/product surfaces and cannot emit a product promotion decision.

- [ ] **Step 6: Run governance, graph, candidate, and CLI tests**

Run: `cd benchmarks && uv run pytest tests/test_eval_governance.py tests/test_experiment.py tests/test_candidate_git.py tests/test_experiment_cli.py -q`

Expected: threshold edits, case deletion, verifier edits, and metric-pack replacement all fail before candidate checks run.

- [ ] **Step 7: Commit the evaluation lock**

```bash
git add benchmarks/src/carl_bench/eval_governance.py benchmarks/src/carl_bench/experiment.py benchmarks/src/carl_bench/candidate_git.py benchmarks/src/carl_bench/cli.py benchmarks/tests benchmarks/examples/dry-run-manifest.json
git commit -m "feat(factory): lock evaluation policy outside candidate authority"
```

---

### Task 5: One-case diagnostic subgraph and failure capsules

**Files:**
- Create: `benchmarks/src/carl_bench/diagnosis.py`
- Create: `benchmarks/tests/test_diagnosis.py`
- Modify: `benchmarks/src/carl_bench/experiment.py`
- Modify: `benchmarks/src/carl_bench/cli.py`
- Modify: `benchmarks/tests/test_experiment.py`
- Modify: `benchmarks/tests/test_experiment_cli.py`

**Interfaces:**
- Consumes: reason-carrying verdicts from Task 2 and existing experiment ledger events.
- Produces: `FailureCapsule`, `DiagnosticIteration`, `DiagnosticProgress`, and three new event types.

- [ ] **Step 1: Write diagnostic-loop graph tests**

```python
def test_diagnosis_selects_exactly_one_visible_case() -> None:
    progress = start_diagnosis(
        task_id="carl/workflow-reconcile-incident",
        task_digest="a" * 64,
        metric_ids=("workflow.records_consistent",),
        maximum_iterations=10,
        required_consecutive_passes=3,
    )
    assert progress.iterations == ()
    assert progress.stabilized is False


def test_three_consecutive_passes_stabilize_but_do_not_promote() -> None:
    progress = diagnostic_progress([fail("wrong_state"), passed(), passed(), passed()])
    assert progress.stabilized is True
    assert progress.promotion_eligible is False


def test_ten_failed_iterations_end_inconclusive() -> None:
    projection = replay_diagnostic_iterations([fail("wrong_state")] * 10)
    assert projection.state is ExperimentState.INCONCLUSIVE
```

- [ ] **Step 2: Run diagnosis tests and verify missing contracts**

Run: `cd benchmarks && uv run pytest tests/test_diagnosis.py tests/test_experiment.py -q`

Expected: collection fails because `carl_bench.diagnosis` and diagnostic event types do not exist.

- [ ] **Step 3: Implement bounded failure capsules**

```python
@dataclass(frozen=True, slots=True)
class FailureCapsule:
    task_id: str
    task_digest: str
    observation_digest: str
    failed_metrics: tuple[str, ...]
    reason_codes: tuple[str, ...]
    safe_reasons: tuple[str, ...]
    suggested_intervention: str


@dataclass(frozen=True, slots=True)
class DiagnosticIteration:
    iteration: int
    candidate_artifact_digest: str
    trial_artifact_digest: str
    verdict_digest: str
    passed: bool
```

The suggested intervention must be one of `structural`, `tooling`, `policy`, `prompt`, or `unknown`, derived from metric metadata rather than free-form model output. Protected diagnostics expose only aggregate reason categories.

- [ ] **Step 4: Add diagnostic events and reducer rules**

Add `DIAGNOSTIC_CASE_SELECTED`, `DIAGNOSTIC_ITERATION_RECORDED`, and `DIAGNOSTIC_CASE_STABILIZED`. Permit them only in `ExperimentState.DIAGNOSING`, require iteration numbers 1-10, reject duplicate candidate/trial digests, and require three consecutive passing verdicts before stabilization. Stabilization permits transition to `PROPOSAL_REVIEW`; it does not skip deterministic, paired, or holdout stages.

- [ ] **Step 5: Add a public-safe `explain` command**

Command:

```bash
uv run carl-bench explain \
  --scorecard artifacts/scorecard.json \
  --task carl/workflow-reconcile-incident \
  --output artifacts/failure-capsule.json
```

Reject scorecards containing multiple task IDs unless `--task` selects exactly one. Output sorted metric IDs, reason codes, safe reasons, observation digest, and suggested intervention. Never emit raw protected reason text.

- [ ] **Step 6: Run diagnosis and CLI tests**

Run: `cd benchmarks && uv run pytest tests/test_diagnosis.py tests/test_experiment.py tests/test_experiment_cli.py -q`

Expected: failure capsules are deterministic, ten iterations are a hard maximum, and no diagnostic event creates promotion eligibility.

- [ ] **Step 7: Commit the diagnostic micro-loop**

```bash
git add benchmarks/src/carl_bench/diagnosis.py benchmarks/src/carl_bench/experiment.py benchmarks/src/carl_bench/cli.py benchmarks/tests/test_diagnosis.py benchmarks/tests/test_experiment.py benchmarks/tests/test_experiment_cli.py
git commit -m "feat(factory): add one-case diagnostic subgraph"
```

---

### Task 6: Flake detection with agent-versus-evaluator attribution

**Files:**
- Create: `benchmarks/src/carl_bench/flake.py`
- Create: `benchmarks/tests/test_flake.py`
- Modify: `benchmarks/src/carl_bench/report.py`
- Modify: `benchmarks/src/carl_bench/cli.py`
- Modify: `benchmarks/tests/test_report.py`
- Modify: `benchmarks/tests/test_cli.py`

**Interfaces:**
- Consumes: `TrialResult.observation_digest`, `TrialResult.verdict_digest`, attempt, seed, and invalid-run classification.
- Produces: `FlakeClass`, `FlakeReport`, and `analyze_flake(trials: Sequence[TrialResult]) -> FlakeReport`.

- [ ] **Step 1: Write the variance-classification matrix**

```python
@pytest.mark.parametrize(("trials", "expected"), [
    (stable_trials(), FlakeClass.STABLE),
    (different_observations_stable_grades(), FlakeClass.AGENT),
    (same_observation_different_grades(), FlakeClass.EVALUATOR),
    (different_observations_and_regrades(), FlakeClass.MIXED),
    (trials_with_invalid_runs(), FlakeClass.INFRASTRUCTURE),
])
def test_flake_source_is_attributed_from_evidence(trials, expected) -> None:
    assert analyze_flake(trials).classification is expected
```

- [ ] **Step 2: Run the flake tests and verify missing implementation**

Run: `cd benchmarks && uv run pytest tests/test_flake.py -q`

Expected: collection fails because `carl_bench.flake` does not exist.

- [ ] **Step 3: Implement deterministic attribution**

```python
class FlakeClass(str, Enum):
    STABLE = "stable"
    AGENT = "agent"
    EVALUATOR = "evaluator"
    MIXED = "mixed"
    INFRASTRUCTURE = "infrastructure"


@dataclass(frozen=True, slots=True)
class FlakeReport:
    task_id: str
    seed: int
    attempts: int
    distinct_observations: int
    observations_with_grade_variance: int
    invalid_attempts: int
    classification: FlakeClass
```

Group by task ID and seed. Different observation digests with stable verdicts indicate agent/output variance. Different verdict digests for one observation digest indicate evaluator variance. Any infrastructure-invalid attempt blocks a clean stability claim and produces `INFRASTRUCTURE` unless both semantic axes also vary, in which case the run is still invalid for promotion.

- [ ] **Step 4: Make flakiness a blocking finding**

Add flake summaries to scorecard secondary evidence. Do not delete flaky cases and do not average evaluator disagreement away. A primary or guard metric with evaluator or mixed flakiness makes the experiment `BLOCKED` and opens an evaluator-repair child experiment. Agent flakiness remains a reliability failure unless it fits the pre-registered pass-rate model and confidence bounds.

- [ ] **Step 5: Add `flake analyze` CLI output**

```bash
uv run carl-bench flake analyze \
  --scorecard artifacts/repeated-scorecard.json \
  --output artifacts/flake-report.json
```

The command must be pure, deterministic, and free of subprocess calls.

- [ ] **Step 6: Run flake, report, and CLI tests**

Run: `cd benchmarks && uv run pytest tests/test_flake.py tests/test_report.py tests/test_cli.py -q`

Expected: the five classifications are stable and a flaky evaluator cannot produce an improvement decision.

- [ ] **Step 7: Commit flake attribution**

```bash
git add benchmarks/src/carl_bench/flake.py benchmarks/src/carl_bench/report.py benchmarks/src/carl_bench/cli.py benchmarks/tests/test_flake.py benchmarks/tests/test_report.py benchmarks/tests/test_cli.py
git commit -m "feat(bench): classify agent and evaluator flakiness"
```

---

### Task 7: Structural-first, prompt-last optimization policy

**Files:**
- Create: `benchmarks/src/carl_bench/optimization.py`
- Create: `benchmarks/tests/test_optimization.py`
- Modify: `benchmarks/src/carl_bench/experiment.py`
- Modify: `benchmarks/src/carl_bench/cli.py`
- Modify: `benchmarks/tests/test_experiment.py`
- Modify: `benchmarks/tests/test_experiment_cli.py`
- Modify: `benchmarks/examples/dry-run-manifest.json`

**Interfaces:**
- Consumes: failure-capsule intervention categories from Task 5 and the evaluation lock from Task 4.
- Produces: `InterventionClass`, `OptimizationPolicy`, and `prompt_optimization_allowed()`.

- [ ] **Step 1: Write policy tests for missing-capability and semantic failures**

```python
def test_prompt_optimization_rejected_for_missing_tool_failure() -> None:
    decision = prompt_optimization_allowed(
        policy=default_policy(),
        capsules=(capsule("tooling"),),
        prior_prompt_runs=0,
        diagnostic_stable=False,
    )
    assert decision == PromptDecision(False, "structural_failure_unresolved")


def test_one_prompt_pass_allowed_after_semantic_case_is_structurally_stable() -> None:
    decision = prompt_optimization_allowed(
        policy=default_policy(),
        capsules=(capsule("prompt"),),
        prior_prompt_runs=0,
        diagnostic_stable=True,
    )
    assert decision.allowed is True


def test_second_prompt_pass_requires_a_child_experiment() -> None:
    assert prompt_optimization_allowed(
        default_policy(), (capsule("prompt"),), 1, True
    ).reason == "prompt_budget_exhausted"
```

- [ ] **Step 2: Run optimization tests and verify missing contracts**

Run: `cd benchmarks && uv run pytest tests/test_optimization.py -q`

Expected: collection fails because `carl_bench.optimization` does not exist.

- [ ] **Step 3: Implement and digest the policy**

```python
class InterventionClass(str, Enum):
    STRUCTURAL = "structural"
    TOOLING = "tooling"
    POLICY = "policy"
    PROMPT = "prompt"


@dataclass(frozen=True, slots=True)
class OptimizationPolicy:
    schema_version: int = 1
    maximum_prompt_runs: int = 1
    require_diagnostic_stability: bool = True
    blocked_failure_classes: tuple[str, ...] = ("structural", "tooling", "policy")
```

Bind the policy digest into `EvaluationLock`. Add `PROMPT_OPTIMIZATION_RECORDED` to the graph with a payload containing input prompt digest, output prompt digest, optimizer/version, cost, and evidence artifact digest. Never store prompt text in the public ledger.

- [ ] **Step 4: Enforce policy in replay and CLI mutation paths**

Reject prompt optimization when a capsule identifies a missing tool, broken deterministic behavior, unsafe side effect, evidence-integrity issue, or unresolved flake. Permit one bounded pass only for prompt-classified semantic failure after the single diagnostic case is stable. Full paired and holdout evaluation must still run afterward.

- [ ] **Step 5: Run policy and graph tests**

Run: `cd benchmarks && uv run pytest tests/test_optimization.py tests/test_experiment.py tests/test_experiment_cli.py -q`

Expected: prompt search cannot loop, cannot replace structural work, and cannot bypass subsequent evaluation stages.

- [ ] **Step 6: Commit prompt-last graph policy**

```bash
git add benchmarks/src/carl_bench/optimization.py benchmarks/src/carl_bench/experiment.py benchmarks/src/carl_bench/cli.py benchmarks/tests/test_optimization.py benchmarks/tests/test_experiment.py benchmarks/tests/test_experiment_cli.py benchmarks/examples/dry-run-manifest.json
git commit -m "feat(factory): enforce structural-first prompt optimization"
```

---

### Task 8: Sanitized regression intake without automatic metric activation

**Files:**
- Create: `benchmarks/src/carl_bench/regressions.py`
- Create: `benchmarks/tests/test_regressions.py`
- Modify: `benchmarks/src/carl_bench/cli.py`
- Modify: `benchmarks/tests/test_cli.py`

**Interfaces:**
- Consumes: metric IDs and disclosure rules from Task 1 and the existing secret filter/sanitizer.
- Produces: `RegressionProposal` and `propose_regression()`.

- [ ] **Step 1: Write privacy and authority-boundary tests**

```python
def test_private_failure_becomes_inactive_sanitized_proposal(tmp_path: Path) -> None:
    proposal = propose_regression(
        source_kind="dogfood",
        source_artifact=private_failure_artifact(tmp_path),
        metric_id="workflow.records_consistent",
        redaction_attestation="reviewed-by-controller",
    )
    assert proposal.status == "proposed"
    assert proposal.active is False
    assert "customer@example.com" not in proposal.to_public_json()


def test_builder_cannot_activate_a_regression_proposal() -> None:
    with pytest.raises(RegressionContractError, match="evaluator_experiment_required"):
        activate_regression(proposal(), actor_role="builder")
```

- [ ] **Step 2: Run regression-intake tests and verify missing module**

Run: `cd benchmarks && uv run pytest tests/test_regressions.py -q`

Expected: collection fails because `carl_bench.regressions` does not exist.

- [ ] **Step 3: Implement inactive, content-addressed proposals**

```python
@dataclass(frozen=True, slots=True)
class RegressionProposal:
    schema_version: int
    proposal_id: str
    source_kind: str
    private_source_digest: str
    metric_id: str
    sanitized_case_artifact_digest: str
    redaction_attestation_digest: str
    status: str = "proposed"
    active: bool = False
```

Allow source kinds `dogfood`, `user_report`, and `production_monitor`. Require an owner-private source artifact and a secret-filtered sanitized case artifact. Activation is outside this command and requires an evaluator experiment that updates the next metric/task family version; an active experiment's lock never changes.

- [ ] **Step 4: Add `regression propose` CLI**

```bash
uv run carl-bench regression propose \
  --source-kind dogfood \
  --source-artifact private/failure.json \
  --metric-id workflow.records_consistent \
  --redaction-attestation private/redaction.json \
  --artifact-root private/artifacts \
  --output artifacts/regression-proposal.json
```

Reject public output paths inside private artifact roots and reject any sanitizer finding instead of replacing sensitive text silently.

- [ ] **Step 5: Run regression and CLI tests**

Run: `cd benchmarks && uv run pytest tests/test_regressions.py tests/test_cli.py -q`

Expected: proposals are inert, reproducible, sanitized, and incapable of moving an active experiment's bar.

- [ ] **Step 6: Commit controlled regression intake**

```bash
git add benchmarks/src/carl_bench/regressions.py benchmarks/src/carl_bench/cli.py benchmarks/tests/test_regressions.py benchmarks/tests/test_cli.py
git commit -m "feat(bench): add governed regression proposal intake"
```

---

### Task 9: End-to-end integrity flow, documentation, and rollout gate

**Files:**
- Create: `benchmarks/tests/test_eval_integrity_flow.py`
- Modify: `benchmarks/README.md`
- Modify: `docs/benchmarks.md`
- Modify: `docs/superpowers/specs/2026-08-10-codex-carl-improvement-factory-design.md`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: every interface from Tasks 1-8.
- Produces: a scripted end-to-end proof and operator documentation for the Codex-run factory.

- [ ] **Step 1: Write the end-to-end scripted graph test**

The test must execute this exact sequence:

```python
def test_eval_integrity_flow_blocks_gaming_and_accepts_real_improvement(tmp_path: Path) -> None:
    lock = register_evaluation_lock(tmp_path)
    baseline = run_bound_subject(tmp_path, commit=PARENT, outcome="fails-target-metric")
    capsule = explain_one_case(baseline)
    candidate = build_structural_scripted_candidate(tmp_path, capsule)
    assert_three_consecutive_diagnostic_passes(candidate)
    assert_candidate_cannot_change_metric_pack(candidate)
    paired = run_bound_pair(tmp_path, baseline=PARENT, candidate=CANDIDATE)
    assert paired.decision == "improvement"
    assert paired.evaluation_lock_digest == lock.digest
    assert protected_holdout_stub(candidate).passed is True
    assert draft_gateway_stub(candidate).merge_capability is False
```

Add negative branches for lowered threshold, deleted case, unrelated scorecard commit, flaky evaluator, prompt optimization before structural stability, and protected reason leakage.

- [ ] **Step 2: Run the end-to-end test and fix only integration mismatches**

Run: `cd benchmarks && uv run pytest tests/test_eval_integrity_flow.py -q`

Expected: all positive and negative branches pass without network access or a live model.

- [ ] **Step 3: Document the two nested loops**

Add this operator distinction to both benchmark documents:

```text
Diagnostic micro-loop: one visible failing case, at most ten iterations, three
consecutive passes, explainable reasons, no promotion authority.

Promotion loop: deterministic gates, randomized paired full-suite confirmation,
protected holdout aggregate, independent review, exact-commit draft publication.
```

Document metric ownership, reason disclosure, flake classifications, evaluator child experiments, prompt-last policy, and regression proposal activation.

- [ ] **Step 4: Run the complete benchmark suite**

Run: `cd benchmarks && uv run pytest -q`

Expected: all benchmark unit, integration, Harbor-contract, development-task, graph, candidate, and eval-integrity tests pass.

- [ ] **Step 5: Run repository-wide deterministic checks**

Run: `cargo fmt --check`

Expected: exit 0.

Run: `cargo clippy --all-targets --all-features -- -D warnings`

Expected: exit 0.

Run: `cargo test --all-targets --all-features`

Expected: exit 0.

Run: `./scripts/benchmark-smoke.sh`

Expected: exit 0 with sanitized benchmark output.

- [ ] **Step 6: Run the security regression gate**

Re-run the Codex Security diff scan on the exact implementation range. Require closure of scorecard provenance, evaluator-surface authority, filesystem boundaries, subprocess-tree cleanup, and public-output sanitization before requesting autonomous-promotion work.

- [ ] **Step 7: Update design and changelog**

Record that the metric is an owner-controlled versioned artifact, the diagnostic and promotion loops have different authority, and active evaluation locks cannot be changed by product candidates.

- [ ] **Step 8: Commit the integrated evaluation-integrity layer**

```bash
git add benchmarks/tests/test_eval_integrity_flow.py benchmarks/README.md docs/benchmarks.md docs/superpowers/specs/2026-08-10-codex-carl-improvement-factory-design.md CHANGELOG.md
git commit -m "docs(factory): define governed self-improvement evaluation loop"
```

---

## Rollout order and gates

1. **Evidence foundation:** Tasks 1-4. Do not build autonomous optimization features until metric packs, explainable verdicts, exact-commit run receipts, and the evaluation lock are complete.
2. **Useful inner loop:** Tasks 5-7. Enable one-case diagnosis and flake analysis first; enable the single prompt pass only after those policies are proven by scripted graph tests.
3. **Compounding knowledge:** Task 8. Accept sanitized regression proposals, but keep activation in the evaluator lane.
4. **Factory integration:** Task 9. Run the complete suite and a new security diff scan. Keep publication draft-only.
5. **Autonomous promotion remains a separate project:** Remediate all eight Phase 3 security findings, implement the protected runner/signature boundary, merge-queue controller, soak, and exact revert before considering Phase 4 auto-merge.

## Acceptance criteria

- Every selected task is bound to an immutable metric pack digest and exact sorted metric IDs.
- Every deterministic failure returns a stable metric ID and bounded safe reason.
- A scorecard is cryptographically bound to the exact benchmarked commit, executable, adapter, task set, environment, model, effort, and metric pack.
- A candidate cannot change evaluator surfaces, thresholds, task cases, or metric packs in an ordinary product/harness experiment.
- The diagnostic graph handles exactly one visible case, stops after ten iterations, requires three consecutive passes, and grants no promotion authority.
- Repeated evidence classifies stable, agent, evaluator, mixed, and infrastructure variance without dropping the case.
- Prompt optimization cannot run for structural/tooling/policy failures, cannot run more than once per experiment, and cannot bypass full paired or protected validation.
- Real-world failures enter as sanitized inactive proposals and require a separate evaluator experiment before activation.
- Protected metric definitions and raw reasons never appear in builder artifacts or public reports.
- The full benchmark suite, Rust checks, scripted smoke flow, and security diff scan pass before any change to promotion authority.
