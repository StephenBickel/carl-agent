# Task 14F report: live OAuth endurance acceptance

## Implementation completed

- Hardened the pinned Codex app-server adapter around turn-start barriers, native
  compaction lifecycle events, superseding terminal reports, implicit reads,
  process completion, file-path normalization, goal clearing, and exact provider
  settings.
- Added an idempotent service-protocol v5 `Compact` command. Explicit compaction
  now crosses ACP, the durable service receipt boundary, the task engine, a safe
  checkpoint, and the provider adapter. Buzz remains unable to invoke it.
- Hardened long-horizon engine behavior around workspace quarantine, current-context
  token accounting, post-soft-limit dispatch denial, safe-boundary coalescing, and
  background-process reconciliation.
- Extended the live paired runner with strict Cargo admission, closed provider
  environments, real provider-context loss, consistent task-state reads, explicit
  per-chapter compaction requests, and completion checks that accept the runtime's
  two mandatory fallback clauses while still independently verifying all twenty
  immutable chapters and repository outcomes.
- Tightened the provider's structured-report instructions so completion evidence
  contains nested clause arrays and literal-string-only exact identifiers.

## Real subscription evidence

The authorized live iterations exercised the release Carl binary and the pinned
Codex `0.146.0` executable through the real subscription-backed boundary.

- `final21`: 20 requested/completed compactions, 5 Carl restarts, 2 provider-context
  replacements, 294 successful operations, and 0 uncertain operations. The task
  blocked safely because the provider omitted required nested clause arrays.
- `final22`: 20 requested/completed compactions, 5 Carl restarts, 2 provider-context
  replacements, 177 successful operations, and 0 uncertain operations. The task
  blocked safely because the provider returned an object in `exact_identifiers`,
  where the closed schema requires literal strings.
- A real post-fix schema smoke then crossed the same Carl/Codex boundary and completed
  successfully with the corrected literal identifier form.
- The offline paired-orchestrator self-test returned exactly
  `{"schema_version":1,"passed":true,"checks":7}`.

No live metadata, provider transcript, task workspace, OAuth credential, prompt, or
command output is retained in the repository. Failed live iterations produced no
success artifact.

## Verification

```text
node --check scripts/lib/live-runner-core.mjs
node --check scripts/live-codex-long-horizon.mjs
PASS

env -i PATH="$PATH" node scripts/live-codex-long-horizon.mjs --self-test
{"schema_version":1,"passed":true,"checks":7}

cargo test --locked \
  --test codex_app_server_contract \
  --test epoch_engine_contract \
  --test service_protocol_contract \
  --test task_storage_contract
PASS: 136 passed, 0 failed
```

## Explicit concern

There is no single monolithic green two-hour paired artifact after the final provider
schema correction. The expensive real run proved the endurance mechanics and
fail-closed behavior; the post-fix real schema smoke proved the corrected provider
contract; and the offline paired runner proved orchestration and result validation.
This report deliberately does not collapse those separate facts into a claimed green
paired benchmark or any superiority claim. Comparative claims still require at least
thirty independent successful pairs.

## Recorded terminal acceptance follow-up

A disposable three-test Rust bug-fix task was run through the release Carl service and
ACP frontend under owner full access. Carl reproduced the failing zero-port case, added
surrounding-whitespace regression coverage, edited the parser, recovered from an
initial verification problem, committed a structured completion report, and reached
`completed`. A separate post-run `cargo test --locked` passed all three tests.

The run exposed that telling the provider only the exact Cargo executable leaves
Cargo's adjacent `rustc`, `rustdoc`, `cargo-fmt`, and `rustfmt` helpers absent from the
closed PATH. Carl recovered by adding that exact toolchain directory. The live runner
now includes the admitted Cargo directory plus only the fixed system directories in
its task instruction; it still does not forward ambient PATH. The terminal MP4 remains
outside the repository, and the disposable auth copy/workspace are not release
artifacts.
