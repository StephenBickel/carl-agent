# Carl Autonomy Activation Bridge Implementation Plan

> **For Codex:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task by task. Use `superpowers:test-driven-development` for every behavior change and `superpowers:verification-before-completion` before claiming a milestone.

**Goal:** Activate Carl's existing autonomous-improvement contracts as a cloud-resident, durable loop that generates product hypotheses, publishes immutable experimental candidates, independently evaluates them, promotes eligible candidates through protected GitHub PRs, soaks production, and automatically reverts hard regressions without routine human approval.

**Architecture:** GitHub-hosted Actions execute all model, build, test, evaluation, promotion, and soak work. Managed PostgreSQL is the transactional command/event/lease authority; versioned object storage retains immutable evidence; KMS signs trusted observations. Pure reconciliation code remains the policy core. A project-scoped OpenAI service account powers a protected Responses API model gateway, while a narrow GitHub App performs experimental, PR, auto-merge, and exact-revert effects. Candidate processes never receive evaluator, database, signing, or promotion credentials.

**Tech Stack:** Python 3.12, PostgreSQL 16+, canonical JSON, Ed25519/KMS signatures, GitHub Actions, GitHub REST API, OpenAI Responses API, AWS RDS/S3 Object Lock/KMS/IAM OIDC reference profile, Rust 1.97.0, pytest, Ruff, actionlint, Terraform.

**Approved design:** `docs/superpowers/specs/2026-08-20-carl-autonomy-activation-bridge-design.md`

**Official OpenAI contracts:** [project service accounts and project controls](https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects), [Responses API](https://developers.openai.com/api/reference/typescript/resources/beta/subresources/responses/methods/create), and [current model/reasoning guidance](https://developers.openai.com/api/docs/guides/latest-model).

## Global implementation rules

- Work only from the isolated `codex/autonomy-activation-bridge` worktree.
- Keep candidate publication independent of live production validation.
- Persist commands before effects and reuse their original timestamps on replay.
- Treat GitHub metadata/artifacts as untrusted until independently observed and signed.
- Never expose OpenAI, database, object-store, KMS, or GitHub App credentials to candidate code.
- Never push `main`, force-push, weaken branch protection/checks, edit evidence, deploy Carl, or publish a release.
- Every task ends with focused tests and a small commit. Run the full benchmark suite at each milestone.
- Production status remains `commissioning` until a real acceptance receipt binds experimental ref, PR, merge, and accepted 24-hour soak.

## Milestone 1: Serializable contracts and durable state semantics

### Task 1: Add strict cloud wire codecs

**Files:**

- Modify: `benchmarks/src/carl_bench/cloud_execution.py`
- Modify: `benchmarks/tests/test_cloud_execution.py`

**Step 1: Write failing codec tests**

Add round-trip tests for `CloudRunRequest`, `CloudArtifact`, `CloudRunSnapshot`, `CloudRunDecision`, `CompletedRunObservation`, `SignedCompletedRunObservation`, `CommissioningReceipt`, and `SignedCommissioningReceipt`. Add rejection tests for missing/extra fields, duplicate JSON keys, invalid enums, booleans-as-integers, identity mismatches, and oversized payloads.

**Step 2: Run the focused test and confirm failure**

Run: `uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_cloud_execution.py`

Expected: FAIL because the types do not yet expose complete strict canonical codecs.

**Step 3: Implement minimal codecs**

Add `to_canonical_dict` and strict `from_canonical_dict` methods. Reuse `canonical_json_bytes`; centralize exact-field validation; preserve stable public error codes. Do not accept coercion or unknown fields.

**Step 4: Run focused verification**

Run: `uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_cloud_execution.py`

Expected: PASS.

**Step 5: Commit**

```bash
git add benchmarks/src/carl_bench/cloud_execution.py benchmarks/tests/test_cloud_execution.py
git commit -m "feat(factory): serialize cloud execution contracts"
```

### Task 2: Define the cloud command and state backend boundary

**Files:**

- Create: `benchmarks/src/carl_bench/cloud_state.py`
- Create: `benchmarks/tests/test_cloud_state.py`
- Modify: `benchmarks/src/carl_bench/__init__.py`

**Step 1: Write failing domain tests**

Cover canonical `CloudCommand`, `CommandClaim`, `CloudLease`, `EvidenceObject`, and `StateTransition` types. Require deterministic effect keys, a fixed persisted `occurred_at`, revision CAS, role/authority validation, bounded retry metadata, and exact result identity. Test identical replay, conflicting replay, stale revision, expired lease, and reused command timestamps.

**Step 2: Run and confirm failure**

Run: `uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_cloud_state.py`

Expected: FAIL because the module does not exist.

**Step 3: Implement the protocol and pure transitions**

Define a `StateBackend` protocol with manifest registration, event append, command create/claim/complete/fail, lease acquire/reconcile/release, supervisor trigger claim/resolve, projection load, evidence registration, and health snapshot methods. Implement pure validation and successor functions without network or database code.

**Step 4: Run focused tests and lint**

Run:

```bash
uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_cloud_state.py
uv run --offline --project benchmarks --locked ruff check benchmarks/src/carl_bench/cloud_state.py benchmarks/tests/test_cloud_state.py
```

Expected: PASS.

**Step 5: Commit**

```bash
git add benchmarks/src/carl_bench/cloud_state.py benchmarks/src/carl_bench/__init__.py benchmarks/tests/test_cloud_state.py
git commit -m "feat(factory): define durable cloud state protocol"
```

### Task 3: Persist acceptance and replay-safe controller timestamps

**Files:**

- Modify: `benchmarks/src/carl_bench/autonomy.py`
- Modify: `benchmarks/src/carl_bench/autonomy_controller.py`
- Modify: `benchmarks/tests/test_autonomy_controller.py`
- Modify: `benchmarks/tests/test_autonomy_commissioning.py`

**Step 1: Write failing regression tests**

Prove that `accept` emits one durable accepted state-transition event and replaying the same persisted command timestamp yields the same attempt/event digest. Prove a different timestamp under the same command key is rejected.

**Step 2: Run and confirm failure**

Run: `uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_autonomy_controller.py benchmarks/tests/test_autonomy_commissioning.py`

Expected: FAIL because acceptance currently returns no event and controller actions generate fresh time values.

**Step 3: Implement the minimal correction**

Thread the command's persisted occurrence time into controller reconciliation. Emit the existing accepted state transition as a trusted durable event. Preserve current soak eligibility and exact merge binding.

**Step 4: Verify**

Run the focused tests above, then:

`uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_experiment.py benchmarks/tests/test_ledger.py`

Expected: PASS.

**Step 5: Commit**

```bash
git add benchmarks/src/carl_bench/autonomy.py benchmarks/src/carl_bench/autonomy_controller.py benchmarks/tests/test_autonomy_controller.py benchmarks/tests/test_autonomy_commissioning.py
git commit -m "fix(factory): persist accepted soak transitions"
```

### Task 4: Add PostgreSQL schema and transactional adapter

**Files:**

- Create: `infra/autonomy/postgres/001_initial.sql`
- Create: `infra/autonomy/postgres/002_role_procedures.sql`
- Create: `benchmarks/src/carl_bench/postgres_state.py`
- Create: `benchmarks/tests/test_postgres_state.py`
- Create: `benchmarks/tests/test_postgres_state_integration.py`
- Modify: `benchmarks/pyproject.toml`
- Modify: `benchmarks/uv.lock`

**Step 1: Write failing schema/adapter tests**

Unit-test parameter binding and response decoding. Integration-test manifest/event chain constraints, unique attempt IDs, command-before-effect, `FOR UPDATE SKIP LOCKED` claim behavior, role-denied event types, lease CAS, duplicate replay, conflicting replay, and atomic command completion plus event append.

**Step 2: Run unit tests and confirm failure**

Run: `uv run --project benchmarks pytest -q benchmarks/tests/test_postgres_state.py`

Expected: FAIL because the adapter and migration do not exist.

**Step 3: Implement schema and adapter**

Add strict tables for manifests, events, commands, leases, triggers, evidence, and monitor snapshots. Put role enforcement and transitions behind procedures. Add the pinned PostgreSQL client dependency and regenerate the lockfile. Do not grant direct table mutation to workflow roles.

**Step 4: Run local unit and container integration tests**

Run:

```bash
uv run --project benchmarks pytest -q benchmarks/tests/test_postgres_state.py
CARL_POSTGRES_TEST_DSN="$CARL_POSTGRES_TEST_DSN" uv run --project benchmarks pytest -q benchmarks/tests/test_postgres_state_integration.py
```

Expected: PASS against an ephemeral PostgreSQL 16 test service. If the DSN is absent locally, the integration test must skip with an explicit reason and run mandatorily in CI.

**Step 5: Commit**

```bash
git add infra/autonomy/postgres benchmarks/src/carl_bench/postgres_state.py benchmarks/tests/test_postgres_state.py benchmarks/tests/test_postgres_state_integration.py benchmarks/pyproject.toml benchmarks/uv.lock
git commit -m "feat(factory): add transactional cloud state backend"
```

## Milestone 2: Inputs, experimental publication, and trusted cloud observation

### Task 5: Build a versioned immutable-input registry

**Files:**

- Create: `benchmarks/src/carl_bench/immutable_inputs.py`
- Create: `benchmarks/tests/test_immutable_inputs.py`
- Create: `benchmarks/immutable-inputs/registry.json`
- Create: `benchmarks/immutable-inputs/public/.gitkeep`
- Modify: `.github/workflows/autonomous-improvement.yml`
- Modify: `.github/workflows/autonomous-soak.yml`

**Step 1: Write failing registry tests**

Cover canonical JSON improvement task sets, normalized soak archives, media-type/version separation, digest-addressed lookup, path traversal/symlink/device rejection, deterministic archive bytes, private commitment resolution, and rejection of unused experiment/metric/policy inputs.

**Step 2: Run and confirm failure**

Run: `uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_immutable_inputs.py`

Expected: FAIL because the registry does not exist.

**Step 3: Implement publisher/verifier**

Implement canonical pack, publish, resolve, and verify operations. Give improvement JSON and soak archive distinct media types. Require all four soak contracts to affect the health decision. Keep only public objects/commitments in Git; private bytes resolve through the object-store interface.

**Step 4: Update workflows and contract tests**

Replace direct `benchmarks/immutable-inputs/<kind>/<digest>` assumptions with the registry verifier. Add actionlint and prompt-contract assertions for the media types and private-object boundary.

**Step 5: Verify**

Run:

```bash
uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_immutable_inputs.py benchmarks/tests/test_cloud_harness.py benchmarks/tests/test_automation_prompt_contract.py
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 .github/workflows/autonomous-improvement.yml .github/workflows/autonomous-soak.yml
```

Expected: PASS.

**Step 6: Commit**

```bash
git add benchmarks/src/carl_bench/immutable_inputs.py benchmarks/tests/test_immutable_inputs.py benchmarks/immutable-inputs .github/workflows/autonomous-improvement.yml .github/workflows/autonomous-soak.yml
git commit -m "feat(factory): version immutable evaluation inputs"
```

### Task 6: Decouple experimental eligibility from production validation

**Files:**

- Modify: `benchmarks/src/carl_bench/experimental_publication.py`
- Modify: `benchmarks/src/carl_bench/capability_validation.py`
- Modify: `benchmarks/src/carl_bench/cli.py`
- Modify: `benchmarks/tests/test_experimental_publication.py`
- Modify: `benchmarks/tests/test_candidate_cli.py`

**Step 1: Write failing policy tests**

Add `ExperimentalPublicationEligibility` cases proving that exact sealed candidate/tree, packet digest, deterministic checks, review/security results, and local gates permit experimental publication without live ACP evidence. Prove this receipt cannot authorize production promotion.

**Step 2: Run and confirm failure**

Run: `uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_experimental_publication.py benchmarks/tests/test_candidate_cli.py`

Expected: FAIL because publication requires promotion-grade capability validation.

**Step 3: Implement the narrow receipt**

Replace publication's `CapabilityValidationReport` dependency with the new exact receipt. Keep immutable create-or-reconcile and remote verification unchanged. Keep live capability validation mandatory in promotion code.

**Step 4: Verify**

Run focused tests plus `benchmarks/tests/test_capability_validation.py` and `benchmarks/tests/test_promotion.py`.

Expected: PASS and no production gate regression.

**Step 5: Commit**

```bash
git add benchmarks/src/carl_bench/experimental_publication.py benchmarks/src/carl_bench/capability_validation.py benchmarks/src/carl_bench/cli.py benchmarks/tests/test_experimental_publication.py benchmarks/tests/test_candidate_cli.py
git commit -m "feat(factory): decouple experimental publication gate"
```

### Task 7: Implement the GitHub dispatch/effect gateway

**Files:**

- Create: `benchmarks/src/carl_bench/github_cloud.py`
- Create: `benchmarks/tests/test_github_cloud.py`
- Modify: `benchmarks/src/carl_bench/cloud_execution.py`

**Step 1: Write failing fake-GitHub tests**

Cover exact-revision workflow dispatch, request/attempt keys, accepted-run discovery, pagination, rate-limit handling, immutable experimental create/reconcile, PR create/update, ready/auto-merge, required checks, exact revert branch/PR, and no direct-main/force/delete methods. Simulate lost responses and prove remote reconciliation prevents duplicate effects.

**Step 2: Run and confirm failure**

Run: `uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_github_cloud.py`

Expected: FAIL because the gateway does not exist.

**Step 3: Implement a closed GitHub REST client**

Use an injectable HTTP transport, explicit endpoint allowlist, bounded response sizes, redacted errors, and exact typed snapshots. Require a pre-persisted command for every consequential effect.

**Step 4: Verify**

Run focused tests plus `test_cloud_execution.py`, `test_github_promotion.py`, and `test_experimental_publication.py`.

**Step 5: Commit**

```bash
git add benchmarks/src/carl_bench/github_cloud.py benchmarks/src/carl_bench/cloud_execution.py benchmarks/tests/test_github_cloud.py
git commit -m "feat(factory): add reconciled GitHub cloud gateway"
```

### Task 8: Add protected observer, evidence archive, and signer interfaces

**Files:**

- Create: `benchmarks/src/carl_bench/cloud_observer.py`
- Create: `benchmarks/src/carl_bench/evidence_archive.py`
- Create: `benchmarks/src/carl_bench/cloud_signer.py`
- Create: `benchmarks/tests/test_cloud_observer.py`
- Create: `benchmarks/tests/test_evidence_archive.py`
- Modify: `benchmarks/src/carl_bench/cloud_execution.py`

**Step 1: Write failing trust-boundary tests**

Test independent run/workflow/head/artifact verification, downloaded-byte hashing, schema validation, immutable object version registration, KMS signer request binding, key-ID pinning, signature verification, replay, expired artifacts, and rejection of workflow-self-signed or synthetic commissioning receipts.

**Step 2: Run and confirm failure**

Run: `uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_cloud_observer.py benchmarks/tests/test_evidence_archive.py`

Expected: FAIL because these modules do not exist.

**Step 3: Implement interfaces and fake backends**

Keep object store and KMS behind injected protocols. The observer must download and verify independently from the evaluated workflow, archive exact bytes before recording success, and return existing signed observation/receipt types.

**Step 4: Verify and commit**

Run focused tests plus `test_cloud_execution.py` and `test_commissioning_sandbox.py`, then commit:

```bash
git add benchmarks/src/carl_bench/cloud_observer.py benchmarks/src/carl_bench/evidence_archive.py benchmarks/src/carl_bench/cloud_signer.py benchmarks/src/carl_bench/cloud_execution.py benchmarks/tests/test_cloud_observer.py benchmarks/tests/test_evidence_archive.py
git commit -m "feat(factory): verify and archive trusted cloud evidence"
```

## Milestone 3: Live capability evaluation and orchestration CLI

### Task 9: Add protected OpenAI model gateway contracts

**Files:**

- Create: `benchmarks/src/carl_bench/openai_gateway.py`
- Create: `benchmarks/tests/test_openai_gateway.py`
- Modify: `benchmarks/pyproject.toml`
- Modify: `benchmarks/uv.lock`

**Step 1: Write failing gateway tests**

Cover project service-account authentication via `OPENAI_API_KEY`, Responses API request shape, explicit protected model and reasoning policy, request idempotency metadata, background response polling, timeout/cancel, usage/cost extraction, bounded output, redacted failures, and refusal to accept candidate-supplied model, effort, instructions, tools, or credentials.

**Step 2: Run and confirm failure**

Run: `uv run --project benchmarks pytest -q benchmarks/tests/test_openai_gateway.py`

Expected: FAIL because the gateway does not exist.

**Step 3: Implement minimal Responses API client**

Use the official OpenAI SDK or an injectable bounded HTTP transport. Read the API key only in the controller process. Bind model, reasoning effort/mode, limits, and prompt template to protected policy. Record response ID, effective model, reasoning context, usage, latency, and request digest without recording secrets.

**Step 4: Verify**

Run focused tests and Ruff. Do not issue a paid live call in unit tests.

**Step 5: Commit**

```bash
git add benchmarks/src/carl_bench/openai_gateway.py benchmarks/tests/test_openai_gateway.py benchmarks/pyproject.toml benchmarks/uv.lock
git commit -m "feat(factory): add protected OpenAI model gateway"
```

### Task 10: Implement paired live capability evidence

**Files:**

- Create: `benchmarks/src/carl_bench/live_capability.py`
- Create: `benchmarks/tests/test_live_capability.py`
- Modify: `benchmarks/src/carl_bench/cloud_harness.py`
- Modify: `benchmarks/src/carl_bench/run_attestation.py`
- Modify: `benchmarks/src/carl_bench/adapters/carl_acp.py`
- Modify: `benchmarks/tests/test_cloud_harness.py`
- Modify: `benchmarks/tests/test_run_attestation.py`
- Modify: `benchmarks/tests/test_adapters.py`

**Step 1: Write failing paired-evidence tests**

Cover exact parent/candidate isolation, identical protected model/effort/tasks/seeds/limits, sealed graders, invalid-trial classification, no selective retry, task-level regressions, held-out transfer, cost/latency limits, aggregate gain, and identity-matched deterministic/live evidence combination. Prove missing live execution retains `live_acp_credential_missing`.

**Step 2: Run and confirm failure**

Run: `uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_live_capability.py benchmarks/tests/test_cloud_harness.py`

Expected: FAIL because live evidence cannot yet be supplied.

**Step 3: Implement the live adapter and combiner**

Reuse `CarlAcpAdapter` and attested clean-checkout execution. Candidate subjects receive a sealed local gateway endpoint/token valid only for their bounded task, never the provider key or grader. Combine one deterministic and one live result only when every request/subject/workflow/input identity matches.

**Step 4: Verify and commit**

Run all listed tests, then commit:

```bash
git add benchmarks/src/carl_bench/live_capability.py benchmarks/src/carl_bench/cloud_harness.py benchmarks/src/carl_bench/run_attestation.py benchmarks/src/carl_bench/adapters/carl_acp.py benchmarks/tests/test_live_capability.py benchmarks/tests/test_cloud_harness.py benchmarks/tests/test_run_attestation.py benchmarks/tests/test_adapters.py
git commit -m "feat(factory): add protected paired live evaluation"
```

### Task 11: Add cloud coordinator and worker CLI commands

**Files:**

- Create: `benchmarks/src/carl_bench/cloud_coordinator.py`
- Create: `benchmarks/tests/test_cloud_coordinator.py`
- Modify: `benchmarks/src/carl_bench/cli.py`
- Modify: `benchmarks/tests/test_cli.py`

**Step 1: Write failing orchestration tests**

Add CLI and pure coordinator cases for reconstruct, select-next-node, persist-command, dispatch, observe, ingest, retry, lease reconciliation, disposition, promotion, soak, revert, and supervisor trigger. Prove one invocation advances at most one consequential state and idle produces no narrative event.

**Step 2: Run and confirm failure**

Run: `uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_cloud_coordinator.py benchmarks/tests/test_cli.py`

Expected: FAIL because commands do not exist.

**Step 3: Implement commands**

Add `cloud request`, `cloud coordinate`, `cloud observe`, `cloud ingest`, `cloud publish-input`, `cloud health`, and `cloud commission-live`. Require explicit environment configuration and fail closed with stable codes. Emit one canonical bounded JSON decision on stdout.

**Step 4: Verify and commit**

Run focused tests and Ruff, then commit:

```bash
git add benchmarks/src/carl_bench/cloud_coordinator.py benchmarks/src/carl_bench/cli.py benchmarks/tests/test_cloud_coordinator.py benchmarks/tests/test_cli.py
git commit -m "feat(factory): add autonomous cloud coordinator CLI"
```

## Milestone 4: Cloud workflows and remote builder

### Task 12: Activate protected improvement and soak workflows

**Files:**

- Modify: `.github/workflows/autonomous-improvement.yml`
- Modify: `.github/workflows/autonomous-soak.yml`
- Modify: `benchmarks/tests/test_automation_prompt_contract.py`
- Modify: `benchmarks/tests/test_autonomy_commissioning.py`

**Step 1: Write failing workflow-contract tests**

Require environment separation, OIDC permissions only where needed, request/attempt keys, private input retrieval, live adapter execution, independent observation handoff, no hard-coded ineligible assertion, six-hour soak cadence input, and exact merge topology.

**Step 2: Run and confirm failure**

Run: `uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_automation_prompt_contract.py benchmarks/tests/test_autonomy_commissioning.py`

Expected: FAIL against dispatch-only wiring workflows.

**Step 3: Update workflows minimally**

Retain protected-parent checkout, action SHA pins, distinct Unix subject identities, bounded outputs, and one request-named artifact. Add OIDC/private input/model gateway stages without passing credentials into subject steps. Make live evidence mandatory for production eligibility and keep missing credentials fail closed.

**Step 4: Verify**

Run focused tests and actionlint for all workflows.

**Step 5: Commit**

```bash
git add .github/workflows/autonomous-improvement.yml .github/workflows/autonomous-soak.yml benchmarks/tests/test_automation_prompt_contract.py benchmarks/tests/test_autonomy_commissioning.py
git commit -m "feat(factory): activate protected cloud evaluation"
```

### Task 13: Add the scheduled coordinator workflow

**Files:**

- Create: `.github/workflows/autonomy-coordinator.yml`
- Modify: `benchmarks/tests/test_automation_prompt_contract.py`
- Modify: `docs/automation-prompts/carl-autonomous-improvement-live-manifest.json`

**Step 1: Write failing workflow assertions**

Require a two-hour cron plus manual dispatch, default-branch-only execution, exact concurrency group, read-only checkout, OIDC state role, no candidate/model credential, one-node coordinator invocation, bounded timeout, and artifact-free durable state.

**Step 2: Implement and verify**

Create the workflow with pinned actions and run:

```bash
uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_automation_prompt_contract.py
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 .github/workflows/autonomy-coordinator.yml
```

Expected: PASS.

**Step 3: Commit**

```bash
git add .github/workflows/autonomy-coordinator.yml benchmarks/tests/test_automation_prompt_contract.py docs/automation-prompts/carl-autonomous-improvement-live-manifest.json
git commit -m "feat(factory): schedule the cloud coordinator"
```

### Task 14: Add the remote product builder

**Files:**

- Create: `benchmarks/src/carl_bench/product_builder.py`
- Create: `benchmarks/tests/test_product_builder.py`
- Create: `.github/workflows/autonomy-builder.yml`
- Create: `docs/automation-prompts/carl-product-builder.md`
- Modify: `benchmarks/tests/test_automation_prompt_contract.py`

**Step 1: Write failing builder policy tests**

Cover hypothesis novelty, product-over-infrastructure selection, capability-family cooldown, preregistration before model call, candidate path limits, failing-test-first evidence, two changed repairs maximum, complete candidate packet, experimental publication without live validation, retained learning, and secret-free candidate environment.

**Step 2: Run and confirm failure**

Run: `uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_product_builder.py benchmarks/tests/test_automation_prompt_contract.py`

Expected: FAIL because builder code/workflow do not exist.

**Step 3: Implement the stateful builder**

Use the protected OpenAI gateway and a sandboxed checkout. Supply product context, constraints, exact parent, and bounded tools. Apply model changes only through validated patches. Run targeted and repository gates in cloud jobs. Produce a terminal packet, repair request, or retained learning; never a report-only result.

**Step 4: Implement the workflow**

Schedule daily and support coordinator dispatch. Use `carl-autonomy-builder`, closed job permissions, pinned actions/toolchains, time/cost limits, and GitHub App publication. Explicitly dispatch downstream work because default `GITHUB_TOKEN` recursion is not relied upon.

**Step 5: Verify and commit**

Run focused tests, Ruff, and actionlint, then commit:

```bash
git add benchmarks/src/carl_bench/product_builder.py benchmarks/tests/test_product_builder.py .github/workflows/autonomy-builder.yml docs/automation-prompts/carl-product-builder.md benchmarks/tests/test_automation_prompt_contract.py
git commit -m "feat(factory): add autonomous cloud product builder"
```

### Task 15: Add supervisor recovery and soak scheduling workflows

**Files:**

- Create: `.github/workflows/autonomy-supervisor.yml`
- Create: `.github/workflows/autonomy-soak-scheduler.yml`
- Create: `docs/automation-prompts/carl-autonomy-supervisor.md`
- Modify: `benchmarks/src/carl_bench/supervisor_triggers.py`
- Modify: `benchmarks/tests/test_supervisor_triggers.py`
- Modify: `benchmarks/tests/test_promotion_monitor.py`
- Modify: `benchmarks/tests/test_automation_prompt_contract.py`

**Step 1: Write failing recovery tests**

Require changed-action fingerprints, three-attempt infrastructure budget, no identical unchanged retry, exact trigger claim CAS, rollback priority over ACP/commissioning outages, six-hour soak observations, 26-hour stale critical, two-hour revert SLA, and supervisor success only on changed state/repair/frozen boundary.

**Step 2: Implement workflows and trigger updates**

Use the strongest protected model policy for supervisor work. Let it open a control-plane repair PR through ordinary protection, reconcile state, or redispatch one safe node. It cannot append validation/promotion evidence or mutate candidate code. Schedule soak only for the exact active merge.

**Step 3: Verify and commit**

Run focused tests and actionlint for both workflows, then commit:

```bash
git add .github/workflows/autonomy-supervisor.yml .github/workflows/autonomy-soak-scheduler.yml docs/automation-prompts/carl-autonomy-supervisor.md benchmarks/src/carl_bench/supervisor_triggers.py benchmarks/tests/test_supervisor_triggers.py benchmarks/tests/test_promotion_monitor.py benchmarks/tests/test_automation_prompt_contract.py
git commit -m "feat(factory): add autonomous recovery and soak scheduling"
```

## Milestone 5: Cloud infrastructure and commissioning

### Task 16: Add the AWS OIDC reference infrastructure profile

**Files:**

- Create: `infra/autonomy/aws/versions.tf`
- Create: `infra/autonomy/aws/variables.tf`
- Create: `infra/autonomy/aws/main.tf`
- Create: `infra/autonomy/aws/iam.tf`
- Create: `infra/autonomy/aws/outputs.tf`
- Create: `infra/autonomy/aws/README.md`
- Create: `infra/autonomy/aws/policies/*.json`
- Create: `infra/autonomy/aws/tests/*.tftest.hcl`
- Modify: `.github/workflows/security.yml`

**Step 1: Write failing Terraform tests**

Assert encrypted PostgreSQL, private networking, versioned S3 with Object Lock/retention, KMS asymmetric signing key, GitHub OIDC trust restricted by repository/ref/environment, separate builder/validator/promoter/soak/observer roles, least privilege, audit logs, deletion protection, backup retention, and no public database/bucket.

**Step 2: Implement the profile**

Provision only control-plane infrastructure: RDS PostgreSQL, S3 evidence/input buckets, KMS signing, IAM OIDC roles/policies, secrets references, logs/alarms, and outputs consumed by GitHub environments. Do not provision a Carl deployment or release path.

**Step 3: Verify**

Run:

```bash
terraform -chdir=infra/autonomy/aws fmt -check -recursive
terraform -chdir=infra/autonomy/aws init -backend=false
terraform -chdir=infra/autonomy/aws validate
terraform -chdir=infra/autonomy/aws test
```

Expected: PASS without creating resources.

**Step 4: Commit**

```bash
git add infra/autonomy/aws .github/workflows/security.yml
git commit -m "feat(factory): provision autonomous cloud control plane"
```

### Task 17: Add true fake-cloud end-to-end commissioning

**Files:**

- Create: `benchmarks/src/carl_bench/live_commissioning.py`
- Create: `benchmarks/tests/test_live_commissioning.py`
- Create: `benchmarks/tests/fixtures/fake_cloud.py`
- Modify: `benchmarks/src/carl_bench/commissioning.py`
- Modify: `benchmarks/src/carl_bench/commissioning_controller.py`
- Modify: `benchmarks/tests/test_autonomy_commissioning.py`
- Modify: `benchmarks/tests/test_commissioning_sandbox.py`

**Step 1: Write the failing end-to-end test**

Simulate persisted command, workflow dispatch, lost response, run reconciliation, artifact download, independent signature, evidence archive, trusted ingestion, experimental publication, independent disposition, PR/check/auto-merge, merge-bound soak, acceptance, hard regression, and exact revert. Prove synthetic commissioning cannot mint `remote_cloud_acceptance`.

**Step 2: Implement live receipt types and runner**

Create a distinct live acceptance receipt bound to real provider/run/object/signature identities. Keep synthetic fixture receipts structurally unable to satisfy it.

**Step 3: Verify milestone**

Run:

```bash
uv run --offline --project benchmarks --locked pytest -q benchmarks/tests/test_live_commissioning.py benchmarks/tests/test_autonomy_commissioning.py benchmarks/tests/test_commissioning_sandbox.py
uv run --offline --project benchmarks --locked pytest -q benchmarks/tests
uv run --offline --project benchmarks --locked ruff check benchmarks/src benchmarks/tests
```

Expected: all tests PASS.

**Step 4: Commit**

```bash
git add benchmarks/src/carl_bench/live_commissioning.py benchmarks/src/carl_bench/commissioning.py benchmarks/src/carl_bench/commissioning_controller.py benchmarks/tests/test_live_commissioning.py benchmarks/tests/fixtures/fake_cloud.py benchmarks/tests/test_autonomy_commissioning.py benchmarks/tests/test_commissioning_sandbox.py
git commit -m "test(factory): commission the complete autonomy bridge"
```

### Task 18: Update public graph, README, and operational prompts

**Files:**

- Modify: `README.md`
- Modify: `docs/autonomous-improvement.md`
- Modify: `docs/automation-prompts/carl-autonomous-improvement.md`
- Modify: `docs/automation-prompts/carl-autonomous-improvement-live-manifest.json`
- Create: `docs/autonomy-operations.md`
- Modify: `benchmarks/tests/test_automation_prompt_contract.py`
- Modify: `tests/docs_contract.rs`

**Step 1: Write failing documentation-contract tests**

Require accurate self-improving-project framing, responsibility graph, cloud execution, autonomous experimental/production authority, anti-gaming controls, update format, and commissioning evidence links. Require status to remain commissioning when no live receipt is supplied.

**Step 2: Update documentation**

Explain the activated responsibilities, durable state, evidence, recovery, and user-facing updates. Preserve historical provenance and do not claim the factory is operational before live commissioning.

**Step 3: Verify and commit**

Run prompt/docs tests, full benchmark tests, and relevant Rust docs contract, then commit:

```bash
git add README.md docs benchmarks/tests/test_automation_prompt_contract.py
git commit -m "docs: explain Carl autonomous improvement operations"
```

### Task 19: Create the protected implementation PR and run commissioning preflight

**Files:**

- No new source files unless verification reveals a defect.

**Step 1: Run complete local verification**

```bash
git diff --check origin/main...HEAD
uv run --offline --project benchmarks --locked pytest -q benchmarks/tests
uv run --offline --project benchmarks --locked ruff check benchmarks/src benchmarks/tests
cargo test --locked
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 .github/workflows/*.yml
terraform -chdir=infra/autonomy/aws fmt -check -recursive
terraform -chdir=infra/autonomy/aws validate
terraform -chdir=infra/autonomy/aws test
```

Expected: PASS.

**Step 2: Run security review**

Inspect workflow permissions, OIDC subjects, secret flow, candidate process environment, GitHub endpoints, SQL roles/procedures, artifact bounds, and Terraform exposure. Fix findings with tests before proceeding.

**Step 3: Push the implementation branch and open a PR**

Push `codex/autonomy-activation-bridge`; open a PR to protected `main`; wait for exact required checks; never merge by direct push. Record PR/head/tree/check identities.

**Step 4: Run cloud preflight after merge**

Verify branch protection, environments, GitHub App installation, OpenAI project service account/model permissions/rate/spend controls, OIDC assumption, database migration, object retention, KMS verification key, and workflow dispatch permissions. A missing external credential freezes only its stage and must not be represented as successful commissioning.

### Task 20: Execute synthetic and real live commissioning

**Files:**

- Modify only evidence/status documentation after receipts exist.

**Step 1: Run synthetic canary**

Dispatch a nonproduction canary through build, immutable experimental publication, protected live validation, PR/check/auto-merge reconciliation in the commissioning fixture, simulated hard failure, and exact revert. Archive and verify every receipt.

**Step 2: Run one real user-visible experiment**

Let the builder choose and preregister a product hypothesis from current `main`. Require a real immutable `experimental/<id>` ref and independent disposition. If eligible, require protected PR/check/merge; if rejected, require retained learning and automatic selection of a different hypothesis on the next cycle.

**Step 3: Observe production for 24 hours**

Require observations at least every six hours. Accept only a healthy observation at or beyond 24 hours. On hard failure, require exact revert start within two hours and complete the revert through protected checks.

**Step 4: Emit live acceptance and update status**

Only after the exact experimental ref, PR, production merge, signed evidence, and accepted soak exist, emit the live acceptance receipt and change README/docs status from `commissioning` to `operational`. Commit through an ordinary protected PR.

**Step 5: Verify ongoing autonomy**

Observe the next coordinator and builder windows. Confirm the owner Mac is not used, state survives runner replacement, user updates report only pushed/dispositioned/promoted/soaked/reverted work, and no watchdog-only loop consumes repeated runs.

## Final completion evidence

Do not mark the activation complete until all of the following are linked in the final handoff:

- implementation PR and protected merge commit;
- green required CI, benchmark-contract, security, workflow, database, and Terraform checks;
- provisioned role-separated cloud resources and successful OIDC preflight;
- exact OpenAI project/model/effort policy without exposing the service-account key;
- signed synthetic commissioning receipt including exact rollback;
- one real immutable experimental branch and independent disposition;
- eligible production PR/merge when the real experiment improves, or retained learning plus a distinct next hypothesis when it does not;
- accepted 24-hour soak or exact protected revert;
- deterministic health evaluator output showing fresh coordinator, builder/review, lease, evidence, soak, rollback, and protection state;
- concise progress update containing exact UTC last-success times and throughput since activation.
