# Task 14D report: Trusted direct-Codex baseline

## Implementation

- Added the explicit `carl baseline codex` owner command with required canonical
  workspace, model, and effort arguments. The timeout defaults to 7,200 seconds and
  parses only the inclusive 60..=28,800-second range.
- Added `DirectCodexBaseline`, its request, a monotonic clock/deadline seam, typed
  stable errors, the fixed provider enum, and strict schema-version-1 result. The
  result rejects unknown fields and rejects serialization/deserialization with any
  provider/version/schema outside the fixed contract. Its encoded offline fixture is
  below 4 KiB.
- The CLI reads at most 16 KiB plus one byte from stdin, accepts only UTF-8 nonempty
  bounded task text, preserves its bytes without trimming, and never places task text
  in argv or environment. Success is one JSON object plus newline; failure diagnostics
  are generic stable codes on stderr with empty stdout.
- Reused the existing owner-private Codex provider home, `auth.json` metadata
  validation, static workspace-write/network-disabled/approval-never config, closed
  Codex environment, exact `codex-cli 0.146.0` probe, `TrustedExecutable`, and
  `CodexExecAdapter` argv/stdin contract. API-key variables are explicitly refused by
  the CLI; all provider children still start from `env_clear` and the Codex allowlist.
- Added an attestation-aware JSONL spawn path. The direct adapter captures trusted
  executable identity and content before version probing, rechecks both after the
  version process and immediately before the auth-bearing exec spawn, and checks them
  again after process completion, protocol failure cleanup, and cancellation. Both
  same-path replacement and same-inode byte mutation fail closed.
- The adapter revalidates the credential file and rewrites the static policy at every
  run start. A missing credential file is a typed authentication failure before the
  version probe or task input.
- The runner validates timeout and task size before provider spawn, starts one shared
  deadline before the version/start lifecycle, drains normalized events without
  storing agent text, counts only completed command/file/MCP/web activity, bounds
  compatibility counts, and rejects checked counter or elapsed conversion overflow.
- Successful completion requires the normalizer's one terminal and a successful
  process `finish`. Missing/duplicate terminals, malformed/oversized JSONL, auth,
  nonzero provider exit, version incompatibility, and trust replacement return typed
  sanitized failures with no partial result.
- Cancellation and timeout use the existing process-group/Job Object cancellation and
  await teardown. Start-phase cancellation/timeout awaits the adapter's internally
  bounded constructor through version-process cleanup and, if construction produces a
  run, cancels and reaps that run before returning. Cancellation and timeout retain
  their primary stable code even if construction or post-teardown attestation reports
  another provider error.

## TDD RED evidence

Tests were written and run before their corresponding production changes against
base `cda40e7c91d1712df9f947813646f32fa8d9bf70`.

1. The initial direct-runner/result contract failed to compile with unresolved
   `DirectBaselineErrorCode`, `DirectBaselineProvider`, `DirectCodexBaseline`,
   `DirectCodexBaselineRequest`, and `DirectCodexBaselineResult` imports.
2. The CLI contract failed to compile with unresolved `BaselineCommand` and no
   `Command::Baseline` variant.
3. The monotonic-clock contract failed to compile because `DirectBaselineClock` did
   not exist. The GREEN uses two injected instants and asserts exactly 1,234 elapsed
   milliseconds without sleeping.
4. The post-completion replacement regression initially returned a successful result
   after the fixture atomically replaced the copied executable. It now returns typed
   `Incompatible` after teardown and attestation.
5. The same-inode mutation regression initially wrote an exec record, proving task
   stdin reached an executable modified after the version probe. The attestation-aware
   spawn now rejects the mutation before exec spawn, and no task record exists.
6. CLI success initially failed with typed provider-home/auth errors while the fixture
   was brought under the production private data-root and fixed `providers/codex`
   home. The GREEN covers the production trust/home/auth path rather than bypassing it.
7. The injected deadline timeout regressions exercised both an active exec process
   tree and a version-probe start process tree. Both produce typed `TimedOut`, no
   partial success, exit/reap the leader and grandchild, and finish without a real
   60-second sleep.

## GREEN verification

Fresh verification after the final implementation:

```text
cargo test --locked --lib delegates::codex::direct_baseline::tests
PASS: 2 passed, 0 failed

cargo test --locked --test codex_exec_contract
PASS: 36 passed, 0 failed

cargo test --locked --test cli_contract
PASS: 10 passed, 0 failed

cargo test --locked --test codex_auth_contract
PASS: 21 passed, 0 failed

cargo test --locked --test auth_cli_contract
PASS: 16 passed, 0 failed

cargo test --locked --test sidecar_contract
PASS: 46 passed, 0 failed

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS: exit 0, no warnings

cargo fmt --all -- --check
PASS: exit 0

git diff --check
PASS: exit 0
```

The complete `codex_exec_contract` includes exact argv/model/effort and stdin-only
prompt assertions; closed OpenAI/Azure/Buzz/XAI environment assertions; exact token,
completed-activity, and compatibility counts; strict result serde; invalid timeout,
oversized task, noncanonical workspace, malformed/oversized JSONL, missing/duplicate
terminal, authentication, provider exit, incompatible/replaced/mutated executable;
and cancellation/timeout descendant reaping.

No full suite, live provider/OAuth run, network run, Node endurance runner, or soak was
performed. `SECURITY.md` and `Cargo.lock` were not edited.

## Review fix round 1

Independent review found that the separate two-second start-cleanup deadline could
drop a still-running adapter constructor. Dropping its version-process guard started
group termination but did not synchronously wait/reap, so `DirectCodexBaseline::run`
could resolve before the version leader was reaped.

TDD added timeout and cancellation regressions that sample process existence at the
exact point `run` resolves. Before the production fix, the complete Codex contract
reported 34 passes and both new immediate-reap assertions failed. The implementation
now awaits the adapter constructor instead of racing it against a second deadline,
then cancels any constructed run before returning the original `TimedOut` or
`Cancelled` result.

The awaited start lifecycle remains bounded: version output, status polling, and the
subsequent kill/reap phase each have a five-second bound; exec stdin write uses the
validated graceful-shutdown bound; write failure uses the validated forced-shutdown
reap bound; and a successfully constructed exec run uses the existing bounded
cancel/reap path.
The final regressions prove both primary error codes remain stable, no exec/task record
is produced, descendants exit, and the version leader is already reaped on return.

Fresh review-fix verification passed the direct-baseline unit tests (2), complete
Codex execution contract (36), and complete sidecar contract (46), for 84 focused
tests. Locked all-target/all-feature Clippy with warnings denied, formatting, and
diff checks also passed.

## Self-review and residual boundary

- The production command intentionally prepares and validates the executable,
  provider home, and auth file before reading task stdin, satisfying the requirement
  that missing trust/home/auth fails before task input. After stdin validation, the
  adapter performs the exact version/attestation sequence before sending task bytes.
- The public result still exposes public fields for the later paired runner, so custom
  serialization validates the fixed schema and Codex version even if a caller mutates
  a cloned value before serialization.
- Compatibility events retain only their bounded normalized type long enough to
  increment a counter; agent messages, command text/output, paths, diffs, thread/item
  IDs, and provider prose never enter the result accumulator.
- The provider sandbox remains the existing intentionally restricted comparator:
  ephemeral exec, workspace-write, network disabled, approval never. Task 14E owns
  disposable fixture provenance and the paired orchestration; this slice does not
  claim benchmark superiority.

## Code commit

- `4590a5b feat: add trusted direct Codex baseline`
- `cfe7e49 fix: await Codex start cleanup before return`
