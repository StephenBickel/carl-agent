# Task 14B report: Sanitized durable task metrics

## Implementation

- Added the strict, versioned `TaskMetrics` contract and stable redacted
  `TaskMetricsErrorCode::{Storage, InvalidHistory, ArithmeticOverflow}`. Metrics
  contain only the requested typed task binding, fixed enums/options, checked
  numeric counters, and `TaskBudget`; schema version deserialization accepts exactly
  version 1 and all unknown fields are denied.
- Added a page-fed `TaskMetricsReducer` and `Store::task_metrics`. The store pins one
  SQLite read transaction, loads authoritative task lifecycle envelopes in pages of
  at most 512, replays every envelope through `reduce_task`, and compares the final
  replayed snapshot exactly with the stored task projection before returning data.
- The reducer rejects zero/non-increasing sequences, non-task envelopes, mismatched
  task IDs, duplicate operation intents, transitions without an intent, invalid
  transition history, multiple terminal classifications, projection disagreement,
  and arithmetic/conversion overflow. Its derived unresolved count must agree with
  the replayed snapshot's typed operation authority.
- Counters are derived only from durable event variants: provider requests, epoch
  starts/completions, unique operation intents and classifications, compactions,
  provider context losses, and recovery starts. Latest token/window observations
  come from the highest-sequence `UsageObserved`. Status, revision, contract clause
  counts, and budget come from the final authoritative snapshot.
- Bumped the strict owner service protocol from version 2 to version 3. The service
  advertises and the client requires `sanitized_task_metrics`; versions 1, 2, and 4
  fail typed negotiation. `ServiceCommand::Metrics` is a read-only command and
  returns `ServiceResult::Metrics` without creating a mutation receipt.
- Exposed the identical serialized shape through direct and service-backed
  `_task/metrics` plus exact `/metrics`. Direct ACP checks the session/task binding
  before reading. Service ACP resolves only the task already bound to the session.
  Buzz slash reads additionally require the exact established actor and channel;
  they do not create a new public/group access path.
- Metrics remain poll-only. No raw events or metrics payloads were added to live
  `TaskUpdate` streams, and no database migration or persisted metrics projection
  was introduced.

## Authority and boundedness proof

```text
Store::task_metrics(task_id)
  -> one pinned SQLite read transaction
  -> authoritative stored projection
  -> read_task_event_page(..., limit = 512)
  -> TaskMetricsReducer::push for every lifecycle envelope
  -> reduce_task for domain-valid replay
  -> exact replayed snapshot == stored projection snapshot
  -> operation-derived unresolved count == snapshot authority
  -> fixed TaskMetrics projection
```

The 515-event contract crosses the 512-event page boundary and asserts the complete
count and revision. An absent journal and absent projection returns `None`; either
authority existing alone fails closed. All counters use checked addition, unresolved
subtraction is checked, and platform-size clause/operation counts use checked integer
conversion.

The store wrapper deliberately derives metrics on demand rather than caching them.
Holding the read transaction across projection lookup and every journal page prevents
a concurrent writer from producing a mixed projection/journal view.

## Privacy proof

The adversarial journal fixture contains unique prompt prose, a secret, email,
absolute home path, command text/output, diff, provider context ID, request digest,
and typed operation ID. Neither serialized JSON nor `Debug` contains any fixture
string or operation identifier; the requested typed `TaskId` is retained. The JSON
is asserted below 4 KiB and rejects unknown fields and unsupported schema versions.

No task event, checkpoint prose, request/provider/context identifier, digest,
timestamp, path, model-authored text, or evaluation-only observation is represented
by the public metrics type.

## Protocol decision

- The owner protocol has one exact supported version: 3. There is no v1/v2 fallback
  and no missing-capability default.
- `Metrics { task_id }` is excluded from mutation classification; polling does not
  write service receipts or task events. Its canonical digest is pinned by the
  protocol contract to
  `e276a1292e0d814a5f7414f8918a17845dd28b5c1b98d4321e238be6cb631a6d`.
- Unknown service task IDs use the existing typed rejected/invalid-request path.
  ACP checks the session's task ownership before sending a service metrics request.
- Exact `/metrics` is recognized only as the trimmed first text block. Embedded,
  quoted, and newline-prefixed occurrences remain ordinary prompt input.

## RED evidence

Tests were written and run before production changes against base
`647081e1b0cd94716a74731cdf48953136c1d744`.

1. `cargo test --locked --test task_metrics_contract` failed to compile because the
   wished-for domain/store surface did not exist:

   ```text
   unresolved imports `TaskMetricsErrorCode`, `derive_task_metrics`
   no method named `task_metrics` found for struct `Store`
   ```

2. `cargo test --locked --test service_protocol_contract` failed to compile at the
   required v3 command/result/capability boundary:

   ```text
   no variant named `Metrics` found for enum `ServiceCommand`
   no variant or associated item named `Metrics` found for enum `ServiceResult`
   no field `sanitized_task_metrics` on type `ServiceCapabilities`
   ```

3. The active-task direct ACP regression failed after the first slash implementation:

   ```text
   active metrics slash did not return one sanitized message
   ```

4. Independent review identified that the service-backed Buzz slash fast path had
   parsed fresh metadata without comparing it to the established owner binding. A
   wrong-actor/wrong-channel regression was added first and failed because `/metrics`
   returned success instead of JSON-RPC invalid input. Exact actor/channel matching
   was then added before the metrics lookup.

These REDs covered pure/store derivation, protocol negotiation, service client shape,
durable active-task polling, and the final owner authorization boundary.

## GREEN evidence

The complete affected matrix was rerun after the final implementation changes:

```text
cargo test --locked --lib runtime::task::metrics::tests
PASS: 1 passed, 0 failed

cargo test --locked --test task_metrics_contract
PASS: 5 passed, 0 failed

cargo test --locked --test task_domain_contract
PASS: 21 passed, 0 failed

cargo test --locked --test task_storage_contract
PASS: 21 passed, 0 failed

cargo test --locked --test service_protocol_contract
PASS: 13 passed, 0 failed

cargo test --locked --lib service::client::tests
PASS: 3 passed, 0 failed

cargo test --locked --test service_end_to_end
PASS: 20 passed, 0 failed

cargo test --locked --test acp_kernel_contract
PASS: 35 passed, 0 failed

cargo test --locked --test acp_server_contract
PASS: 5 passed, 0 failed

cargo test --locked --test acp_protocol_contract
PASS: 8 passed, 0 failed

cargo test --locked --test buzz_acp_contract
PASS: 3 passed, 0 failed

cargo test --locked --test buzz_end_to_end
PASS: 7 passed, 0 failed

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

cargo fmt --all -- --check
PASS: exit 0

git diff --check
PASS: exit 0
```

After the review-driven Buzz authorization fix, the complete Buzz E2E, ACP server,
and service E2E targets plus strict Clippy, formatting, and diff checks were rerun and
passed. The full all-features test suite was intentionally not run, as required by
the Task 14B brief.

## Self-review and independent review

- Checked every public field against the exact contract and confirmed version 1 is
  enforced on deserialization rather than merely emitted on serialization.
- Checked every count source against its specific durable event variant and confirmed
  latest usage is sequence-ordered by the reducer input.
- Checked operation identity remains internal to the reducer and that uncertain is a
  non-terminal historical count while only resolved classifications reduce the
  unresolved total.
- Checked Store paging is capped at 512 and runs inside one read snapshot; metrics do
  not create receipts, events, updates, or migrations.
- Checked direct/service extension binding, active/latest slash resolution, embedded
  slash routing, unknown tasks, and service-backed Buzz wrong-actor/wrong-channel
  denial.
- Checked `SECURITY.md` and `Cargo.lock` were not edited.
- Independent read-only review reported no residual Critical, Important, or Minor
  findings after the Buzz owner-binding fix and regression.

## Residual risks and scope boundary

- This view intentionally favors authoritative on-demand replay over caching. Very
  large task journals require multiple bounded database pages and proportional total
  replay work, while peak page memory remains bounded.
- Production metrics intentionally cannot report restart counts, duplicate effects,
  orphan processes, secret-policy violations, out-of-scope changes, or replay
  digests. Those remain acceptance/evaluation observations outside this schema.
- Tests are deterministic and offline. No live provider or OAuth endurance run was
  performed in this slice.

## Commit

- `769ef49 feat: add sanitized durable task metrics`
