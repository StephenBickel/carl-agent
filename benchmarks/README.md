# Carl benchmark lab

This directory contains the first three executable layers of the Carl improvement factory. It runs the
same portable coding, workflow-automation, and safety tasks against disposable workspaces and emits
only bounded, sanitized scorecards, then records private experiment facts in a replayable dry-run
graph. An approved experiment can now prepare and seal an isolated candidate, bind paired and review
evidence, and explicitly open a draft PR. It does **not** run protected validation, merge, enable
auto-merge, release, deploy, or accept changes.

## Offline validation

Install the locked Python 3.12 environment once, then run the credential-free suite:

```bash
uv sync --project benchmarks --python 3.12 --all-groups --locked
./scripts/benchmark-smoke.sh
```

The smoke validates all task contracts, runs each public oracle through the same local runner used
by live agents, and requires a 100% pass rate. The `scripted` adapter is a plumbing oracle, not a
competitive agent result.

## Live Carl run

Carl uses ACP v2 through an explicit trusted executable. All paths must be absolute, executables
must be regular non-symlinked files, and the data directory must be owner-private (`0700`). Existing
owner authentication is used; the runner never copies credentials into a task workspace.

```bash
uv run --project benchmarks --locked carl-bench run \
  --tasks "$(pwd)/benchmarks/tasks/dev" \
  --adapter carl-acp \
  --attempts 3 \
  --seed 41000 \
  --model gpt-5.2-codex \
  --effort high \
  --carl-bin /absolute/path/to/carl \
  --codex-bin /absolute/path/to/codex \
  --carl-data-dir /absolute/private/path/to/carl-data \
  --public-result /absolute/path/to/results/carl.json
```

The existing `scripts/live-codex-acp-smoke.mjs` remains an extended ACP compatibility test for
approval, steering, and cancellation. `carl-bench run --adapter carl-acp` is the canonical benchmark
path and shares its protocol guarantees without task-specific assertions.

## Same-model Codex baseline

The Codex adapter is pinned to `codex-cli 0.146.0` and invokes `codex exec` with an exact frozen argv.
Use the identical task root, attempt count, seed, model, and effort as Carl:

```bash
uv run --project benchmarks --locked carl-bench run \
  --tasks "$(pwd)/benchmarks/tasks/dev" \
  --adapter codex-cli \
  --attempts 3 \
  --seed 41000 \
  --model gpt-5.2-codex \
  --effort high \
  --codex-bin /absolute/path/to/codex \
  --codex-home /absolute/private/path/to/codex-home \
  --public-result /absolute/path/to/results/codex.json
```

Compare the exact paired trials:

```bash
uv run --project benchmarks --locked carl-bench compare \
  --baseline /absolute/path/to/results/codex.json \
  --candidate /absolute/path/to/results/carl.json \
  --comparison-seed 41000 \
  --public-result /absolute/path/to/results/comparison.json
```

A same-model comparison is rejected if model or effort differs. Promotion evidence requires at least
three valid pairs per task, a pass-rate gain of at least three percentage points, a positive paired
bootstrap lower bound, and no track regression beyond two percentage points. Infrastructure-invalid
trials are surfaced but excluded from pass-rate denominators.

## Evidence and isolation limits

- Every attempt gets a new private temporary workspace. Task sources are hashed before and after,
  and source mutation invalidates the trial.
- Verifiers run after the adapter exits, under bounded time and output limits. Safety fixtures may
  include a separate protected directory that is never placed in the agent workspace.
- Public JSON cannot contain prompts, responses, stdout, stderr, credentials, absolute owner paths,
  or repository contents. Live provider streams are consumed only for protocol state and discarded.
- Adapters receive a closed environment containing only their explicitly required paths plus locale
  and `PATH`. Harbor validation deliberately receives neither Carl nor Codex credentials.
- Public tasks are useful for development and regression detection, but serious promotion decisions
  also need protected holdouts to reduce benchmark overfitting.

## Harbor parity

Harbor is pinned to `0.17.1` and provides a second execution path for the public task contracts. The
validator runs both the Harbor `oracle` agent (required reward `1`) and `nop` agent (required reward
`0`) for every task. Harbor receives a closed allowlisted environment and never receives Carl data,
Codex home, or provider API keys.

```bash
./scripts/benchmark-harbor-validate.sh /absolute/private/path/to/harbor-results
```

The validator performs static task validation first. If Docker is missing or unhealthy it exits
`77`; schema, network, verifier, and image-pin checks remain covered by the normal Python suite.

## Dry-run control plane

The `carl-bench experiment` commands register strict manifests, append normalized events, replay
sanitized status, evaluate budget, and emit deterministic simulated decisions. The SQLite ledger
must be outside the public repository and owner-only. Its event stream is hash-chained; exact stage
redelivery is idempotent, while conflicts and corruption block.

Start from [the public example manifest](examples/dry-run-manifest.json), but copy it into the
private control directory and replace every example value. The full operator sequence and event
boundary are in [the benchmark operator guide](../docs/benchmarks.md#dry-run-experiment-graph).

Phase three adds the `carl-bench candidate` prepare/edit/seal protocol, paired-evidence binding,
role-specific independent review packets, sanitized status, a draft-only GitHub gateway, and
explicit conflict-safe candidate-worktree disposal. The Codex task performs the edit inside the
prepared worktree; Carl installations do not mutate themselves. See the operator guide for the
private check registry and command sequence.

This is deliberately not autonomous promotion yet. Protected holdouts, merge credentials,
auto-merge, merge queue, soak, release, and rollback remain absent. A draft candidate stays in
`paired_evaluation` until a later protected validator supplies evidence that the builder cannot see.
