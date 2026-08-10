# Operating the Carl benchmark lab

The benchmark lab is the first executable part of the approved
[improvement-factory design](superpowers/specs/2026-08-10-codex-carl-improvement-factory-design.md).
It gives Codex a reproducible way to test Carl and other harnesses on coding,
workflow-automation, and safety tasks. The current comparison output is advisory: the promotion
controller is not implemented, and this lab does not open, merge, or revert pull requests.

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

## Budget and proposal handoff

The approved factory caps live-model work at USD 25 per calendar day and USD 150 per rolling seven
days. It permits four read-only benchmark workers, one active code candidate, four live-model
replicas total, two infrastructure retries per run, and a maximum of 24 hours for an ordinary
experiment. Deterministic local checks do not consume the dollar budget.

After a paired diagnostic, write a small experiment proposal before editing Carl. Record the exact
baseline commit, task digests, model and effort, seed range, observed failure cluster, one causal
hypothesis, files allowed to change, primary metric, non-regression metrics, budget, and a falsifying
prediction. Then review the proposal independently before implementation. The next planned layer is
the durable experiment graph and review loop; it will consume these scorecards instead of weakening
or reimplementing them.
