# Operating the Carl benchmark lab

The benchmark lab, experiment graph, and isolated candidate workflow are the first executable parts of the approved
[improvement-factory design](superpowers/specs/2026-08-10-codex-carl-improvement-factory-design.md).
They give Codex a reproducible way to test Carl and other harnesses on coding,
workflow-automation, and safety tasks, preregister hypotheses, replay normalized decisions, and
account for budgets. An approved experiment can produce a sealed candidate and an explicitly enabled
draft PR. The promotion controller is not implemented: this control plane cannot claim protected
validation, merge, auto-merge, release, deploy, or revert changes.

The command reference and isolation details live in the
[benchmark package guide](../benchmarks/README.md). This page defines the operator loop that Codex
can execute today.

## First-run deterministic gate

From the repository root, install the pinned environment and prove the lab before spending any
model budget:

```bash
uv sync --project benchmarks --python 3.12 --all-groups --locked
uv run --offline --project benchmarks --locked carl-bench tasks validate \
  --root "$(pwd)/benchmarks/tasks/dev"
./scripts/benchmark-smoke.sh
cargo build --locked --release
```

The task identity is the task ID plus a SHA-256 digest of its complete source tree. Every trial
records that digest, the attempt number, and its deterministic seed. A comparison pairs only exact
task-digest/attempt/seed matches, so editing a task or changing seeds cannot silently become evidence
for the same experiment.

## Run the same-model harness diagnostic

Prepare existing owner-authenticated, owner-private Carl and Codex data directories. Do not copy
authentication into the repository or create credentials for CI. Use the same model, effort,
attempts, seed, and task root on both sides:

```bash
TASKS="$(pwd)/benchmarks/tasks/dev"
RESULTS="/absolute/private/path/to/results"
MODEL="gpt-5.2-codex"
EFFORT="high"
SEED="41000"

uv run --project benchmarks --locked carl-bench run \
  --tasks "$TASKS" --adapter codex-cli --attempts 3 --seed "$SEED" \
  --model "$MODEL" --effort "$EFFORT" \
  --codex-bin /absolute/path/to/codex \
  --codex-home /absolute/private/path/to/codex-home \
  --public-result "$RESULTS/codex.json"

uv run --project benchmarks --locked carl-bench run \
  --tasks "$TASKS" --adapter carl-acp --attempts 3 --seed "$SEED" \
  --model "$MODEL" --effort "$EFFORT" \
  --carl-bin "$(pwd)/target/release/carl" \
  --codex-bin /absolute/path/to/codex \
  --carl-data-dir /absolute/private/path/to/carl-data \
  --public-result "$RESULTS/carl.json"

uv run --project benchmarks --locked carl-bench compare \
  --baseline "$RESULTS/codex.json" \
  --candidate "$RESULTS/carl.json" \
  --comparison-seed "$SEED" \
  --public-result "$RESULTS/comparison.json"
```

This competitor comparison diagnoses harness behavior; it is not itself a Carl promotion decision.
For a Carl change, preregister the hypothesis and metrics, check out the baseline and candidate
commits separately, run both with the same Carl adapter configuration, and compare those paired
scorecards. Start with three replicas per task. A full confirmation may add paired replicas up to
ten, but must not change the hypothesis after seeing results.

## Read the evidence correctly

Infrastructure-invalid trials—such as a verifier timeout, unsafe workspace, or changed task
source—are reported separately and excluded from the pass-rate denominator. They never count as
passes and should trigger repair or a bounded rerun. Agent process failures and semantic verifier
failures are valid failures and remain in the denominator.

Public scorecards contain task and run identities, stable failure codes, counts, durations, tool-call
counts when available, and aggregate metrics. They provably exclude prompts, model responses,
stdout, stderr, credentials, absolute owner paths, and repository contents. Provider streams are
bounded and discarded by the adapters; this phase does not persist a private raw trajectory. Keep
the output directory private anyway, because future phases may add separately governed diagnostic
artifacts.

The current correctness gate requires a gain of at least three absolute percentage points, a
positive one-sided 95% task-clustered paired-bootstrap lower bound, at least three valid pairs for
every included task, and no evaluated track worse by more than two points. Those checks are useful guardrails, but
the three public development tasks are too small to establish broad superiority. Protected holdouts
must live outside the builder workspace and return only aggregate evidence before autonomous
promotion can be enabled.

## Harbor boundary

The [Harbor validator](../scripts/benchmark-harbor-validate.sh) runs the identical task verifier
source in a second, containerized path. It uses pinned Harbor `0.17.1`, passes an empty allowlisted
environment, requires oracle reward `1` and nop reward `0`, and never receives provider credentials.
Run it only with a healthy local container daemon:

```bash
./scripts/benchmark-harbor-validate.sh /absolute/private/path/to/harbor-results
```

Exit `77` means Docker was unavailable after static validation; it is not a successful live Harbor
run.

## Dry-run experiment graph

The phase-two graph is an owner-private control plane outside the Carl repository. Its immutable
manifest fixes the hypothesis, allowed and forbidden source surfaces, affected tasks, primary and
guard metrics, versions, paired-replica bounds, budget, risk, and rollback contract before a build.
It also binds its UTC preregistration time and optional parent experiment, so a revised hypothesis
becomes a traceable child rather than a rewrite of prior evidence.
Every normalized fact is appended to a SHA-256 hash-chained SQLite ledger. Reopening the ledger
revalidates the manifest, every event digest, every chain link, every state edge, and every stage
attempt before reconstructing the projection.

Copy the public [dry-run manifest example](../benchmarks/examples/dry-run-manifest.json) to an
owner-private directory and replace every example identity and version with actual pinned values.
The ledger path must also be outside the repository and must remain owner-only:

```bash
CONTROL_ROOT="/absolute/private/path/to/carl-improvement-control"

uv run --offline --project benchmarks --locked carl-bench experiment init \
  --ledger "$CONTROL_ROOT/experiments.sqlite3" \
  --manifest "$CONTROL_ROOT/manifest.json"

uv run --offline --project benchmarks --locked carl-bench experiment record \
  --ledger "$CONTROL_ROOT/experiments.sqlite3" \
  --event "$CONTROL_ROOT/next-event.json"

uv run --offline --project benchmarks --locked carl-bench experiment status \
  --ledger "$CONTROL_ROOT/experiments.sqlite3" \
  --experiment-id exp-real-id \
  --public-result "$CONTROL_ROOT/status.json"

uv run --offline --project benchmarks --locked carl-bench experiment decide \
  --ledger "$CONTROL_ROOT/experiments.sqlite3" \
  --experiment-id exp-real-id \
  --public-result "$CONTROL_ROOT/decision.json"
```

An event is a strict JSON envelope with `schema_version`, `experiment_id`, unique
`stage_attempt_id`, UTC `occurred_at`, `event_type`, and an event-specific `payload`. Supported
facts are state transitions, review results bound to private artifact digests, mutable-stage lease
acquisition/reconciliation/release, and integer-microdollar live spend. Exact duplicate delivery is
a no-op; a conflicting duplicate, illegal transition, stale lease, malformed role verdict, or
corrupt chain blocks.

`experiment budget-check` evaluates a proposed live run against the experiment cap, 24-hour elapsed
limit, USD 25 UTC-calendar-day cap, USD 150 rolling-seven-day cap, and four-worker limit without
reserving or spending money. The supplied UTC instant cannot predate the experiment or any already
recorded spend.
Status and decision files expose only counts, states, stable reasons, and digests—not the hypothesis,
role prose, artifact identities, lease owner, provider settings, or raw benchmark evidence.

The intended Improvement Director cadence is one Codex automation tick every two hours. Scheduling
is not installed by this repository; an operator may run the phase-three commands below manually or
from a separately governed Codex automation. A missed tick is safe because ledger events, Git refs,
and draft PRs reconcile by immutable experiment and candidate identities.

## Isolated candidate workflow

Phase three is a prepare/edit/seal handoff. The controller creates a derived branch and disposable
worktree at the manifest's exact parent. The active Codex task edits only the returned worktree.
Deterministic code then rejects changes outside `target_surface`, inside `forbidden_surface`, or
through symlinks and special files; runs every preregistered check; stores private evidence; and
creates one exact-parent candidate commit.

All control paths below must be absolute, outside the Carl repository, and owner-private. The check
registry is trusted operator input, not model output. It maps manifest IDs to an absolute regular
executable and fixed argv; no shell string is accepted:

```json
{
  "checks": [
    {
      "argv": ["test", "--locked"],
      "check_id": "cargo-test",
      "environment": ["CARGO_HOME", "PATH", "RUSTUP_HOME"],
      "executable": "/absolute/path/to/cargo",
      "timeout_seconds": 1800,
      "working_directory": "."
    }
  ],
  "schema_version": 1
}
```

After proposal quorum, acquire the phase-two lease and transition the experiment to `building`.
Then prepare the candidate:

```bash
COMMON=(
  --ledger "$CONTROL_ROOT/experiments.sqlite3"
  --experiment-id exp-real-id
  --repository /absolute/path/to/carl
  --worktree-root "$CONTROL_ROOT/worktrees"
  --artifacts "$CONTROL_ROOT/artifacts"
  --remote origin
  --expected-remote-url git@github.com:StephenBickel/carl-agent.git
)

uv run --project benchmarks --locked carl-bench candidate prepare \
  "${COMMON[@]}" \
  --stage-attempt-id prepare-exp-real-id-1 \
  --occurred-at 2026-08-10T12:01:01Z \
  --private-result "$CONTROL_ROOT/prepared.json"
```

The private result contains the worktree path and immutable builder request. Run the Codex builder
in that worktree, write a bounded private implementation report, and seal:

```bash
uv run --project benchmarks --locked carl-bench candidate seal \
  "${COMMON[@]}" \
  --stage-attempt-id seal-exp-real-id-1 \
  --occurred-at 2026-08-10T12:20:00Z \
  --check-registry "$CONTROL_ROOT/checks.json" \
  --report "$CONTROL_ROOT/implementation-report.json" \
  --public-result "$CONTROL_ROOT/candidate.json"
```

Record the ordinary transitions to `deterministic_validation` and `paired_evaluation`, run the
exact baseline and candidate scorecards, then bind the recomputed comparison:

```bash
uv run --project benchmarks --locked carl-bench candidate bind-comparison \
  "${COMMON[@]}" \
  --stage-attempt-id paired-exp-real-id-1 \
  --occurred-at 2026-08-10T14:00:00Z \
  --baseline "$CONTROL_ROOT/baseline.json" \
  --candidate-scorecard "$CONTROL_ROOT/candidate-scorecard.json" \
  --comparison-seed 41000 \
  --public-result "$CONTROL_ROOT/paired.json"
```

Issue separate packets for `correctness`, `security`, `maintainability`, and
`benchmark_integrity`. Run each reviewer in a read-only, independent Codex context, then call
`record-review` with a unique reviewer ID, unique context ID, packet, verdict, and private report.
All four roles must report; three approvals and no hard finding are required.

`candidate status` reports only commit/evidence digests, counts, verdict totals, state, and next
action. Once it says `open_draft_pr`, the operator may explicitly enable the narrow gateway:

```bash
uv run --project benchmarks --locked carl-bench candidate open-draft-pr \
  "${COMMON[@]}" \
  --stage-attempt-id draft-exp-real-id-1 \
  --occurred-at 2026-08-10T15:00:00Z \
  --repository-slug StephenBickel/carl-agent \
  --base-branch main \
  --gh-executable /absolute/path/to/gh \
  --gateway-private-root "$CONTROL_ROOT/github" \
  --gateway-env-name GH_TOKEN \
  --gateway-env-name HOME \
  --gateway-env-name SSH_AUTH_SOCK \
  --public-result "$CONTROL_ROOT/draft.json" \
  --enable-github-draft
```

The gateway pushes `<sealed-commit>:refs/heads/<derived-branch>` without force, creates or
reconciles one open draft, and has no merge/auto-merge/ready/release operation. The builder never
receives its environment. The experiment deliberately remains in `paired_evaluation` with next
action `await_phase4_protected_validation`; a draft PR is not promotion evidence.

After the draft is recorded, explicitly remove the candidate worktree while preserving its sealed
branch and private evidence:

```bash
uv run --project benchmarks --locked carl-bench candidate dispose \
  "${COMMON[@]}" \
  --stage-attempt-id dispose-exp-real-id-1 \
  --occurred-at 2026-08-10T15:01:00Z \
  --public-result "$CONTROL_ROOT/disposed.json"
```

Cleanup is ledger-recorded and idempotent. It refuses a dirty worktree, a moved branch, a different
commit, a missing draft record, or an expired lease; it never force-removes or deletes the branch.

## Budget and proposal handoff

The approved factory caps live-model work at USD 25 per calendar day and USD 150 per rolling seven
days. It permits four read-only benchmark workers, one active code candidate, four live-model
replicas total, two infrastructure retries per run, and a maximum of 24 hours for an ordinary
experiment. Deterministic local checks do not consume the dollar budget.

After a paired diagnostic, register an experiment manifest before editing Carl. Record the exact
baseline commit, task digests, model and effort, seed range, observed failure cluster, one causal
hypothesis, files allowed to change, primary metric, non-regression metrics, budget, and a falsifying
prediction. Then record the three independent proposal reviews. Two approvals and no hard objection
allow the phase-three isolated builder to begin under the exclusive lease. A sealed candidate may
reach a draft PR after paired evidence and local review, but protected validation and the
deterministic promotion controller remain separate later gates.
