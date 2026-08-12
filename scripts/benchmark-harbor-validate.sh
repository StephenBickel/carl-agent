#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
BENCHMARK_ROOT="$REPOSITORY_ROOT/benchmarks"
TASK_ROOT="$BENCHMARK_ROOT/tasks/dev"
CREATED_OUTPUT=0

if [[ $# -gt 1 ]]; then
  printf '%s\n' "usage: $0 [OUTPUT_ROOT]" >&2
  exit 2
fi
if [[ $# -eq 1 ]]; then
  mkdir -p -- "$1"
  OUTPUT_ROOT="$(cd "$1" && pwd -P)"
else
  OUTPUT_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/carl-harbor.XXXXXX")"
  CREATED_OUTPUT=1
fi
chmod 700 "$OUTPUT_ROOT"

cleanup() {
  if [[ "$CREATED_OUTPUT" -eq 1 && "$OUTPUT_ROOT" == "${TMPDIR:-/tmp}/carl-harbor."* ]]; then
    rm -rf -- "$OUTPUT_ROOT"
  fi
}
trap cleanup EXIT

uv run --offline --project "$BENCHMARK_ROOT" --locked \
  carl-bench tasks validate --root "$TASK_ROOT"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  printf '%s\n' "Harbor validation skipped: Docker is unavailable" >&2
  exit 77
fi

HARBOR_HOME="$OUTPUT_ROOT/harbor-home"
JOBS_ROOT="$OUTPUT_ROOT/jobs"
UV_CACHE_ROOT="$(uv cache dir)"
DOCKER_ENDPOINT="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null)"
mkdir -p "$HARBOR_HOME" "$JOBS_ROOT"
chmod 700 "$HARBOR_HOME" "$JOBS_ROOT"

run_harbor() {
  local task_path="$1"
  local job_name="$2"
  local agent_name="$3"
  local expected_reward="$4"

  env -i \
    "PATH=$PATH" \
    "HOME=$HARBOR_HOME" \
    "LANG=C.UTF-8" \
    "LC_ALL=C.UTF-8" \
    "UV_CACHE_DIR=$UV_CACHE_ROOT" \
    "DOCKER_HOST=$DOCKER_ENDPOINT" \
    uvx --offline --from harbor==0.17.1 harbor run \
    --path "$task_path" \
    --agent "$agent_name" \
    --jobs-dir "$JOBS_ROOT" \
    --job-name "$job_name" \
    --n-attempts 1 \
    --n-concurrent 1 \
    --max-retries 0 \
    --yes \
    --quiet

  local reward_path
  local reward_count
  reward_count="$(find "$JOBS_ROOT/$job_name" -type f -path '*/verifier/reward.txt' | wc -l | tr -d ' ')"
  if [[ "$reward_count" != "1" ]]; then
    printf '%s\n' "Harbor produced an unexpected reward-file count for $job_name" >&2
    return 1
  fi
  reward_path="$(find "$JOBS_ROOT/$job_name" -type f -path '*/verifier/reward.txt' -print -quit)"
  if [[ "$(tr -d '[:space:]' < "$reward_path")" != "$expected_reward" ]]; then
    printf '%s\n' "Harbor reward mismatch for $job_name" >&2
    return 1
  fi
}

for task in "$TASK_ROOT"/*; do
  slug="$(basename "$task")"
  oracle_job="oracle-$slug"
  nop_job="nop-$slug"
  run_harbor "$task" "$oracle_job" oracle 1
  run_harbor "$task" "$nop_job" nop 0
done

printf '%s\n' "Harbor oracle/nop validation passed"
