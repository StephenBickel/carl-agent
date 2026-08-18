# Benchmark and evaluation methodology

Carl separates deterministic regression evidence from opt-in subscription-backed
endurance evidence. A passing run supports the exact tested guarantees; it does not
establish that Carl is universally faster or better than another harness.

## Deterministic release evidence

The locked offline gate is:

```sh
cargo test --locked --test long_horizon_eval
```

It contains a deterministic ten-case repository matrix backed by the real task engine.
The cases cover regression-first repair, multi-file refactoring, command recovery,
strategy replacement, provider loss, cancellation, hostile instructions, secret
rejection, path escape, and ambiguous effects. Results are derived from the durable
journal and verified repository topology, not from scenario labels.

The same target includes a 100-epoch uninterrupted-versus-restarted proof with exact
safe cuts, provider replacements, context reconstruction, and normalized replay-digest
equality. It uses no credentials, network, subprocess, or wall-clock sleeps.

## Subscription endurance runner

The live runner uses an owner-private disposable data root and repository. It requires
Codex CLI 0.146.0, an existing ChatGPT subscription login, a release Carl binary, and
an exact Cargo executable:

```sh
cargo build --locked --release
install -d -m 700 "$HOME/.carl-live-eval"
env -u OPENAI_API_KEY -u CODEX_API_KEY -u AZURE_OPENAI_API_KEY \
  CARL_DATA_DIR="$HOME/.carl-live-eval" \
  CARL_CODEX_EXECUTABLE="$(realpath "$(command -v codex)")" \
  CARL_LIVE_CARGO_EXECUTABLE="$(rustup which cargo)" \
  CARL_BIN="$PWD/target/release/carl" \
  CARL_LIVE_MODEL=gpt-5.6-terra \
  CARL_LIVE_EFFORT=low \
  CARL_LIVE_DURATION_HOURS=2 \
  node scripts/live-codex-long-horizon.mjs
```

The same opaque task input, model, effort, wall limit, and immutable fixture snapshot
run once through Carl and once through the direct Codex baseline. The fixture contains
a failing regression, cross-file refactor, documentation clause, exact identifier,
format/test gates, a long command, and twenty immutable high-context audit chapters.
Carl must prove ordered chapter reads with later checkpoints, at least twenty
compactions, five service restarts, two provider context replacements, and two owner
steers.

The runner writes a mode-0600 result only after both workspaces pass an independent
topology, source, regression, documentation, formatting, and test oracle. The artifact
contains sanitized metadata: version strings, counts, booleans, elapsed milliseconds,
and digests. It excludes prompts, assistant text, diffs, command output, credentials,
email addresses, UUID task identifiers, and absolute home paths. A failed or cancelled
run writes no success artifact and must leave no test-owned child process.

## Comparative claims

One paired run is an acceptance test, not a ranking. Any comparative claim needs at
least thirty independent paired runs from fresh fixture copies. Report, at minimum:

- completion rate and completion-clause rate;
- elapsed time and provider-request distribution;
- owner interventions, restarts, and context replacements;
- duplicate effects, orphan processes, leaked secrets, and other safety violations;
- model, effort, harness revision, Codex version, and fixture digest.

Publish failures and censored timeouts alongside successes. Do not claim superiority
from a single run, a deterministic scripted evaluation, or results whose prompts,
models, effort, fixture snapshots, or wall limits differ.

---

# Operating the Carl benchmark lab

The benchmark lab, experiment graph, and isolated candidate workflow are the first executable parts of the approved
[improvement-factory design](superpowers/specs/2026-08-10-codex-carl-improvement-factory-design.md).
They give Codex a reproducible way to test Carl and other harnesses on coding,
workflow-automation, and safety tasks, preregister hypotheses, replay normalized decisions, and
account for budgets. An approved experiment can produce a sealed candidate. The promotion authority
is not implemented: paired/review authority events and every publication operation are mechanically
disabled, so this control plane cannot push a candidate, open a draft PR, claim protected validation,
merge, auto-merge, release, deploy, or revert changes.

## Protected-main and Phase 4 bootstrap

As of 2026-08-18, the remote `main` branch is protected and requires an up-to-date pull request plus
`Quality`, `Benchmark contracts`, and the Ubuntu, macOS, and Windows test jobs. The rule applies to
administrators, requires linear history and resolved conversations, and disables force-push and
deletion. The repository permits squash merges only, enables auto-merge, and deletes merged branches.
Zero human approvals are required because routine promotion is intended to be governed by immutable
machine evidence rather than operator availability.

The repository now contains two Phase 4 building blocks:

- `carl_bench.promotion` verifies externally signed Ed25519 protected-validation receipts and binds
  them to the exact production parent, candidate commit/tree, policy, executable, adapter, task set,
  metric pack, model, effort, environment, reviews, tests, benchmark statistics, holdout aggregate,
  cost, latency, and expiry. It rejects constitutional changes in an ordinary candidate.
- `carl_bench.github_promotion` deterministically reconciles one exact PR, strict required checks,
  squash auto-merge, resulting tree identity, soak entry, and one exact revert. The companion
  outcome monitor detects stale automations, leases, evidence, soak observations, and rollback.

These contracts do not make the current graph a promotion authority by themselves. The private
validator/signing boundary, protected status reporter, append-only Phase 4 event integration, and
credentialed GitHub operation gateway must still be provisioned outside candidate authority and
adversarially verified. Until that happens, experimental publication remains the maximum candidate
authority and production review must fail closed. The full contract and bootstrap order are in the
[autonomous-main promotion design](superpowers/specs/2026-08-18-carl-autonomous-main-promotion-design.md).

GitHub's native merge queue is unavailable for this public personal-account repository. The approved
substitute is a single durable promotion lease, strict up-to-date checks, and exact post-merge tree
reconciliation. Moving the repository to an eligible organization can replace that serialization
layer with the native queue later without weakening evidence requirements.

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
SUBJECT_COMMIT="$(git rev-parse HEAD)"

uv run --project benchmarks --locked carl-bench run \
  --tasks "$TASKS" --adapter codex-cli --attempts 3 --seed "$SEED" \
  --subject-commit "$SUBJECT_COMMIT" \
  --model "$MODEL" --effort "$EFFORT" \
  --codex-bin /absolute/path/to/codex \
  --codex-home /absolute/private/path/to/codex-home \
  --public-result "$RESULTS/codex.json"

uv run --project benchmarks --locked carl-bench run \
  --tasks "$TASKS" --adapter carl-acp --attempts 3 --seed "$SEED" \
  --subject-commit "$SUBJECT_COMMIT" \
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

The separately governed Codex automation may schedule the Improvement Director, but scheduling is
not installed by this repository. A missed tick is safe because the ledger and sealed candidate refs
reconcile by immutable experiment and candidate identities. Publication remains unavailable.

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
  --lease-owner-id director-exp-real-id
  --lease-stage-attempt-id lease-exp-real-id-1
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

Record the ordinary transitions to `deterministic_validation` and `paired_evaluation`. Diagnostic
`run`, `compare`, and `run-attested` executions may still measure the sealed candidate, but none of
their output has promotion authority in this release.

### Publication boundary (disabled)

`candidate status` stops at `await_isolated_signer`. The CLI and direct APIs reject
`bind-comparison`, `open-draft-pr`, and publication-worktree disposal before reading attestations,
keys, artifacts, or invoking Git/GitHub. The reducer independently rejects
`PAIRED_EVIDENCE_RECORDED`, `REVIEW_PACKET_RECORDED`, `REVIEW_ATTESTED`, `DRAFT_PR_REQUESTED`,
`DRAFT_PR_RECORDED`, and `WORKSPACE_DISPOSED`, including during legacy-ledger replay. Fabricated
projections cannot make the draft gateway mutate a remote.

This boundary exists because the current HMAC prototype does not prove that the executed Carl binary
was freshly built from the attested checkout, and a same-UID worker is not isolated from the signing
key or lease identity. Enabling publication requires a separately isolated Ed25519 signer,
public-key verification, an exact checkout-to-build-to-execution provenance chain, and authenticated
lease ownership. Those controls must land with fresh adversarial tests before the disabled events or
commands can be re-enabled.

## Budget and proposal handoff

The approved factory caps live-model work at USD 25 per calendar day and USD 150 per rolling seven
days. It permits four read-only benchmark workers, one active code candidate, four live-model
replicas total, two infrastructure retries per run, and a maximum of 24 hours for an ordinary
experiment. Deterministic local checks do not consume the dollar budget.

After a paired diagnostic, register an experiment manifest before editing Carl. Record the exact
baseline commit, task digests, model and effort, seed range, observed failure cluster, one causal
hypothesis, files allowed to change, primary metric, non-regression metrics, budget, and a falsifying
prediction. Then record the three independent proposal reviews. Two approvals and no hard objection
allow the isolated builder to begin under the exclusive lease. A sealed candidate remains local and
awaits the isolated signer; protected validation and deterministic promotion are later gates.
