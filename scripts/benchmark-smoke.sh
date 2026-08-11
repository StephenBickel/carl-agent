#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
BENCHMARK_ROOT="$REPOSITORY_ROOT/benchmarks"
TASK_ROOT="$BENCHMARK_ROOT/tasks/dev"
SMOKE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/carl-bench-smoke.XXXXXX")"
RESULT_PATH="$SMOKE_ROOT/scorecard.json"
SUBJECT_COMMIT="$(git -C "$REPOSITORY_ROOT" rev-parse HEAD)"

cleanup() {
  if [[ "$SMOKE_ROOT" == "${TMPDIR:-/tmp}/carl-bench-smoke."* ]]; then
    rm -rf -- "$SMOKE_ROOT"
  fi
}
trap cleanup EXIT

uv run --offline --project "$BENCHMARK_ROOT" --locked \
  carl-bench tasks validate --root "$TASK_ROOT"
uv run --offline --project "$BENCHMARK_ROOT" --locked \
  carl-bench run \
  --tasks "$TASK_ROOT" \
  --adapter scripted \
  --attempts 1 \
  --seed 20260810 \
  --subject-commit "$SUBJECT_COMMIT" \
  --public-result "$RESULT_PATH"
uv run --offline --project "$BENCHMARK_ROOT" --locked python -c \
  'import json,sys; value=json.load(open(sys.argv[1], encoding="utf-8")); assert value["subject_commit"] == sys.argv[2]; assert value["passed_trials"] == 3; assert value["valid_trials"] == 3; assert value["invalid_trials"] == 0; assert value["pass_rate"] == 1.0' \
  "$RESULT_PATH" "$SUBJECT_COMMIT"

printf '%s\n' "offline benchmark smoke passed"
