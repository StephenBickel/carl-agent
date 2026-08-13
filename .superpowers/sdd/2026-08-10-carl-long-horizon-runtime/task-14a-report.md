# Task 14A report: Explicit bounded task budgets

## Implementation

- `TaskBudget::default()` remains exactly unlimited for the three optional hard
  totals, 900 seconds per soft epoch, and 40 tool calls per soft epoch.
- Structural validation is intentionally distinct from admission validation.
  `TaskBudget::validate` rejects only zero soft epoch seconds/tool calls and accepts
  deterministic engine fixture values including zero optional totals, one-second
  epochs, and values beyond consumer policy. `TaskBudget::validate_for_admission`
  applies the exact inclusive consumer bounds from the brief. Both return the stable
  `TaskValidationErrorCode::InvalidBudget`.
- `TaskBudget` denies unknown serialized fields. `TaskEvent::Created::validate`
  validates the workspace, contract, and structural budget, so journal creation,
  replay, and direct event serialization fail closed on an invalid creation budget.
- `carl acp` exposes all five exact flags. Optional hard totals remain absent by
  default; the soft defaults appear in help. Clap value parsers call the shared
  admission validator rather than maintaining a second bound policy.
- `AcpServerConfig` carries a required budget. Its public `new` convenience chooses
  `TaskBudget::default()`, while CLI construction supplies the explicitly parsed
  budget. Direct ACP validates the policy in `KernelActor::new_session`; service ACP
  validates it in `ServiceAcpServer::new`.
- The local service protocol is strict version 2. `StartTaskCommand.budget` is
  required with no option or serde default. `ServiceCapabilities` requires
  `explicit_task_budgets`; the server advertises true and the client rejects false or
  missing capability data. Version 1 and version 3 requests return the typed
  unsupported-version error.
- Ordinary and trusted Buzz starts use the same nested `StartTaskCommand`. The
  command's canonical serialization naturally includes the budget, so both the
  connection ledger and durable service receipt digest detect an idempotency key
  reused with a changed budget, including after reconnect.
- Loaded or resumed active tasks continue using the budget in the stored task
  snapshot. A different ACP configuration is retained only as the admission policy
  for a future newly created task; steering/resume never rewrites the active task.

## Propagation map

### CLI and service-backed ACP

```text
AcpArgs
  -> AcpArgs::task_budget
  -> AcpServerConfig.budget
  -> ServiceSessionBinding.budget
  -> service_start_command
  -> StartTaskCommand.budget
  -> protocol validate_start / TaskBudget::validate_for_admission
  -> OwnerStartTask.budget
  -> StartTask.budget
  -> TaskEvent::Created / TaskSnapshot / task storage
```

`StartTrustedTaskCommand` contains that identical `StartTaskCommand`; there is no
trusted-start-specific budget or fallback.

### Direct/library ACP

```text
AcpServerConfig.budget
  -> NewSessionRequest.budget
  -> KernelActor admission validation
  -> SessionState.budget (immutable admission policy)
  -> begin_durable_prompt
  -> StartTask.budget
  -> TaskEvent::Created / TaskSnapshot / task storage
```

When the session already has a non-terminal task, `begin_durable_prompt` steers and
runs its task ID without constructing another `StartTask`, preserving the persisted
budget.

## Compatibility decision

- No storage migration was added. Existing task events, snapshots, and projections
  already contain a complete budget and continue to replay under structural
  validation.
- Structural validation deliberately does not retrofit consumer policy onto stored
  tasks or deterministic engine fixtures.
- Service protocol version 1 has no translation path. Version negotiation is exact:
  only `SERVICE_PROTOCOL_VERSION == 2` is accepted, and explicit-budget capability
  support is mandatory.
- ACP's own JSON-RPC protocol version handling remains unchanged and independent of
  the local service protocol bump.

## RED evidence

Tests were written before production edits and run against base
`ac3c5aa4e23209b17cd045ddd57f13c84abccf0f`.

1. `tests/task_domain_contract.rs` failed to compile because the wished-for
   structural contract did not exist:

   ```text
   no method named `validate` found for struct `TaskBudget`
   no variant or associated item named `InvalidBudget` found for enum `TaskValidationErrorCode`
   ```

2. `tests/cli_contract.rs` failed to compile at both explicit and omitted-policy
   assertions:

   ```text
   no method named `task_budget` found for struct `AcpArgs`
   ```

3. `tests/service_protocol_contract.rs` failed at the required v2 start schema:

   ```text
   struct `StartTaskCommand` has no field named `budget`
   ```

4. `tests/acp_kernel_contract.rs` failed at the direct admission boundary:

   ```text
   no field `budget` on type `NewSessionRequest`
   struct `NewSessionRequest` has no field named `budget`
   ```

5. Focused `tests/service_end_to_end.rs` compilation failed at each intended
   service integration boundary:

   ```text
   no field `explicit_task_budgets` on type `ServiceCapabilities`
   struct `StartTaskCommand` has no field named `budget`
   struct `AcpServerConfig` has no field named `budget`
   ```

These REDs covered ordinary service start, trusted Buzz start, reconnect conflict,
service-backed ACP admission, and loaded-session retention before the production
fields were introduced.

## GREEN evidence

The final tree was verified after formatting and all implementation changes:

```text
cargo test --locked --test task_domain_contract
PASS: 21 passed, 0 failed

cargo test --locked --test cli_contract
PASS: 8 passed, 0 failed

cargo test --locked --test service_protocol_contract
PASS: 12 passed, 0 failed

cargo test --locked --test acp_kernel_contract
PASS: 34 passed, 0 failed

cargo test --locked --test acp_server_contract
PASS: 4 passed, 0 failed

cargo test --locked --test service_end_to_end
PASS: 20 passed, 0 failed

cargo test --locked --lib
PASS: 81 passed, 0 failed

cargo fmt --all -- --check
PASS: exit 0

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

git diff --check
PASS: exit 0
```

Additional affected complete targets passed earlier on the implementation tree:
`acp_cli_contract` 4/4, `task_storage_contract` 21/21, and `storage_contract`
21/21. The full all-features test suite was intentionally not run, as required by
the Task 14A brief.

## Self-review

- Checked all five defaults and ten admission endpoints against the binding table.
- Confirmed structural validation accepts zero optional totals, one-second epochs,
  and values beyond consumer policy while rejecting zero soft limits.
- Confirmed all production `StartTaskCommand`, `OwnerStartTask`, `NewSessionRequest`,
  and `AcpServerConfig` paths carry an explicit field; the only production default is
  the documented `AcpServerConfig::new` root convenience.
- Confirmed service protocol tests use `SERVICE_PROTOCOL_VERSION`; literal 1 and 3
  remain only as negative compatibility versions. ACP wire protocol literals and
  unrelated `*.v1` digest domains were not conflated with service negotiation.
- Confirmed the ordinary start snapshot, trusted Buzz list snapshot, direct ACP
  creation event, service ACP task list, and direct resume projection retain exact
  non-default budgets.
- Confirmed changed-budget idempotency conflict is exercised after the first client
  disconnects and a new client reconnects.
- Confirmed `SECURITY.md`, migrations, and `Cargo.lock` were not changed.

## Residual risks and scope boundary

- Task 14A establishes and persists admission policy; it does not add the Task 14
  metrics, maintenance, direct-Codex baseline, Node runner, or live two-hour
  acceptance work.
- Tests are deterministic and offline. No live provider endurance run was performed
  in this slice.
- The local service v2 cut is intentionally incompatible with older clients. A stale
  client fails typed version negotiation rather than receiving a translated default.

## Commit

- `d189215 feat: add explicit task admission budgets`
