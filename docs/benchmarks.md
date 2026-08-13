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
