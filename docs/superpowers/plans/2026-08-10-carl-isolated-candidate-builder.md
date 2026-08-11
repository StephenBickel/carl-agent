# Carl Isolated Candidate Builder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a fail-closed prepare/edit/seal pipeline that binds one isolated Carl candidate to
deterministic checks, paired benchmark evidence, independent local reviews, and an idempotent draft
pull request without enabling protected validation or merge.

**Architecture:** Extend the existing replay graph with immutable phase-three evidence while
keeping raw artifacts in an owner-private content-addressed store. A dedicated Git manager prepares
and seals candidate worktrees; evidence services bind comparisons and reviews; a narrow gateway may
push the sealed commit and create a draft PR. The experiment remains in `paired_evaluation` awaiting
phase-four protected validation.

**Tech Stack:** Python 3.12, frozen dataclasses, canonical JSON/SHA-256, SQLite replay ledger,
subprocess argv execution, real temporary Git repositories, pytest, Ruff, GitHub CLI gateway.

## Global Constraints

- No merge, auto-merge, ready-for-review, release, deployment, rollback, or acceptance operation.
- No transition from `paired_evaluation` to `holdout_validation` in phase three.
- No shell evaluation of manifest, model, registry, or artifact content.
- Ledger, artifact store, worktree root, check registry, and private reports stay outside the public
  repository and are owner-private where the platform exposes POSIX ownership/modes.
- Every Git ref, event payload, artifact, packet, attestation, comparison, and PR is bound to the
  manifest digest and exact candidate commit.
- Public JSON contains no absolute paths, diffs, logs, prompts, responses, reviewer prose, secrets,
  or environment values.
- Existing phase-two ledgers and events remain replayable.
- All behavior changes follow red-green-refactor and every external mutation is idempotent.

---

### Task 1: Private content-addressed artifacts

**Files:**

- Create: `benchmarks/src/carl_bench/artifacts.py`
- Create: `benchmarks/tests/test_artifacts.py`

**Interfaces:**

- Produces: `ArtifactRef(schema_version, digest, byte_size, media_type, evidence_kind)`
- Produces: `PrivateArtifactStore(root: Path, repository_root: Path)`
- Produces: `PrivateArtifactStore.put(*, evidence_kind: str, media_type: str, content: bytes) -> ArtifactRef`
- Produces: `PrivateArtifactStore.read(ref: ArtifactRef) -> bytes`

- [ ] **Step 1: Write failing artifact contract and storage tests**

  Cover exact canonical keys, bounded kinds/media types, deterministic digest, same-content
  idempotency, tamper detection, owner-private creation, repository-root rejection, symlink root or
  object rejection, non-regular object rejection, and a 16 MiB object limit.

  ```python
  ref = store.put(evidence_kind="candidate_diff", media_type="text/x-diff", content=b"diff")
  assert store.read(ref) == b"diff"
  assert store.put(
      evidence_kind="candidate_diff", media_type="text/x-diff", content=b"diff"
  ) == ref
  ```

- [ ] **Step 2: Run the tests and verify RED**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_artifacts.py -q`

  Expected: collection fails because `carl_bench.artifacts` does not exist.

- [ ] **Step 3: Implement the minimal immutable store**

  Use `sha256(content).hexdigest()` as the object name, `os.open` with exclusive/no-follow flags
  where available, a temporary file plus atomic hard-link/rename publication, mode `0600`, directory
  mode `0700`, and digest/size verification on every read. Stable failures use
  `ArtifactIntegrityError(code)` and never echo content or owner paths.

- [ ] **Step 4: Run focused tests and Ruff**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_artifacts.py -q`

  Run: `uv run --project benchmarks ruff check benchmarks/src/carl_bench/artifacts.py benchmarks/tests/test_artifacts.py`

- [ ] **Step 5: Commit the artifact store**

  ```bash
  git add benchmarks/src/carl_bench/artifacts.py benchmarks/tests/test_artifacts.py
  git commit -m "feat: add private candidate artifact store"
  ```

### Task 2: Phase-three contracts and evidence-gated replay

**Files:**

- Create: `benchmarks/src/carl_bench/candidate.py`
- Create: `benchmarks/tests/test_candidate.py`
- Modify: `benchmarks/src/carl_bench/experiment.py`
- Modify: `benchmarks/tests/test_experiment.py`
- Modify: `benchmarks/tests/test_ledger.py`

**Interfaces:**

- Produces: `PreparedCandidate`, `DeterministicCheckResult`, `SealedCandidate`,
  `PairedEvidence`, `ReviewPacket`, `ReviewAttestation`, and `DraftPullRequest` frozen contracts
- Produces: `phase3_draft_decision(manifest, projection) -> Phase3Decision`
- Extends: `EventType` with `WORKSPACE_PREPARED`, `CANDIDATE_SEALED`,
  `PAIRED_EVIDENCE_RECORDED`, `REVIEW_PACKET_RECORDED`, `REVIEW_ATTESTED`, and
  `DRAFT_PR_RECORDED`
- Extends: `ExperimentProjection` with optional prepared/candidate/paired/draft records plus
  packet and attestation tuples

- [ ] **Step 1: Write failing canonical-contract tests**

  Instantiate each contract through `from_canonical_dict`, assert exact-key rejection, bounded
  values, full commit/digest validation, sorted unique changed paths/checks, role-specific packet
  digests, exact candidate binding, unique reviewer/context identity, and sanitized public output.

  ```python
  candidate = SealedCandidate.from_canonical_dict(candidate_value)
  assert candidate.parent_commit == manifest.parent_commit
  assert candidate.all_checks_passed is True
  assert "worktree" not in json.dumps(candidate.to_public_dict()).casefold()
  ```

- [ ] **Step 2: Run contract tests and verify RED**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_candidate.py -q`

  Expected: collection fails because `carl_bench.candidate` does not exist.

- [ ] **Step 3: Implement frozen contracts and canonical digests**

  Keep path-free evidence values in `candidate.py`. Each `from_canonical_dict` accepts one exact
  key set. `ReviewAttestation.verdict` accepts only `approve`, `reject`, or `hard_finding`.
  `DraftPullRequest` requires `is_draft is True`, state `OPEN`, a positive number, derived head
  branch, exact candidate commit, and HTTPS GitHub URL.

- [ ] **Step 4: Write failing reducer tests**

  Prove preparation is allowed only in `building` with a live lease; sealing is immutable and
  parent-bound; leaving `building` requires a sealed candidate; leaving deterministic validation
  requires all checks; paired evidence is accepted only in `paired_evaluation`; review packets and
  attestations require passing paired evidence; reviewer/context reuse is rejected; draft recording
  needs three approvals and no hard finding; and the phase-three decision never advances to holdout.

- [ ] **Step 5: Run reducer tests and verify RED**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_experiment.py benchmarks/tests/test_ledger.py -q`

  Expected: new event enum members or projection fields are missing.

- [ ] **Step 6: Extend replay without breaking phase two**

  Parse new event payloads through the contract classes, store immutable evidence in the
  projection, and include it in the projection digest. Preserve legacy `ROLE_RECORDED` behavior for
  phase-two ledgers, but require the richer phase-three attestations whenever a sealed candidate
  exists. At `paired_evaluation`, return one of:

  ```text
  bind_paired_evidence
  issue_review_packets
  collect_candidate_reviews
  open_draft_pr
  await_phase4_protected_validation
  ```

  Never return a phase-three action that transitions to `holdout_validation`.

- [ ] **Step 7: Run focused graph tests and Ruff**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_candidate.py benchmarks/tests/test_experiment.py benchmarks/tests/test_ledger.py -q`

  Run: `uv run --project benchmarks ruff check benchmarks/src/carl_bench/candidate.py benchmarks/src/carl_bench/experiment.py benchmarks/tests/test_candidate.py benchmarks/tests/test_experiment.py benchmarks/tests/test_ledger.py`

- [ ] **Step 8: Commit the contracts and reducer**

  ```bash
  git add benchmarks/src/carl_bench/candidate.py benchmarks/src/carl_bench/experiment.py benchmarks/tests/test_candidate.py benchmarks/tests/test_experiment.py benchmarks/tests/test_ledger.py
  git commit -m "feat: bind candidate evidence into experiment replay"
  ```

### Task 3: Real Git preparation, checks, and sealing

**Files:**

- Create: `benchmarks/src/carl_bench/candidate_git.py`
- Create: `benchmarks/tests/test_candidate_git.py`

**Interfaces:**

- Produces: `candidate_branch(experiment_id: str) -> str`
- Produces: `CheckSpec.from_canonical_dict(value) -> CheckSpec`
- Produces: `TrustedCheckRegistry.load(path: Path, repository_root: Path) -> TrustedCheckRegistry`
- Produces: `CandidateGitManager(repository_root, worktree_root, artifact_store)`
- Produces: `CandidateGitManager.prepare(manifest, *, stage_attempt_id: str) -> PreparedCandidate`
- Produces: `CandidateGitManager.seal(manifest, prepared, registry, report: bytes) -> SealedCandidate`

- [ ] **Step 1: Write failing real-Git preparation tests**

  Create a temporary repository with a bare `origin`, two files, an initial full commit, and local
  identity. Assert derived branch determinism, exact-parent worktree creation, private request
  output, existing branch/worktree conflict, non-commit parent rejection, symlink roots, repository-
  internal worktree root, and dirty/stale preparation failures.

- [ ] **Step 2: Run preparation tests and verify RED**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_candidate_git.py -q -k prepare`

  Expected: collection fails because `carl_bench.candidate_git` does not exist.

- [ ] **Step 3: Implement argv-only Git preparation**

  Use one `_git(*args, cwd, timeout)` wrapper with `shell=False`, a closed locale environment,
  bounded output, and stable `CandidateGitError(code)` failures. Resolve and compare the repository
  top-level, verify `parent_commit^{commit}`, derive `codex/experiment-<slug>-<digest10>`, then call
  `git worktree add -b <branch> <path> <full-parent>`.

- [ ] **Step 4: Write failing scope and check-runner tests**

  Exercise allowed file edits, deletions and additions; target-directory containment; forbidden
  descendants; traversal/invalid UTF-8 paths; symlink/FIFO candidates; zero changes; missing or
  duplicate checks; unsafe executable; nonzero exit; timeout; output overflow; environment closure;
  and a check that dirties tracked files.

- [ ] **Step 5: Run sealing tests and verify RED**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_candidate_git.py -q -k 'scope or check or seal'`

  Expected: failures identify missing scope/check/seal behavior.

- [ ] **Step 6: Implement scope enforcement and trusted checks**

  Collect changed paths from `git diff --name-only -z HEAD` plus
  `git ls-files --others --exclude-standard -z`. Decode UTF-8 strictly, canonicalize separators,
  require every path to equal or descend from a target and no path to equal or descend from a
  forbidden surface, and reject all non-regular existing entries. Resolve manifest check IDs only
  through the private registry. Execute absolute binaries with fixed argv, `shell=False`, bounded
  output, timeout, relative safe cwd, and only registry-allowlisted environment names.

- [ ] **Step 7: Implement evidence capture and exact commit sealing**

  Store check output, report, changed-path manifest, and staged binary diff as artifacts. Run
  `git add --all`, confirm the staged path set still matches, commit with fixed local identity and
  message `experiment(<id>): seal candidate`, resolve the full candidate commit, verify its sole
  parent equals `manifest.parent_commit`, and require a clean status.

- [ ] **Step 8: Run candidate Git tests and Ruff**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_candidate_git.py -q`

  Run: `uv run --project benchmarks ruff check benchmarks/src/carl_bench/candidate_git.py benchmarks/tests/test_candidate_git.py`

- [ ] **Step 9: Commit Git isolation**

  ```bash
  git add benchmarks/src/carl_bench/candidate_git.py benchmarks/tests/test_candidate_git.py
  git commit -m "feat: prepare and seal isolated candidates"
  ```

### Task 4: Paired evidence and independent review services

**Files:**

- Create: `benchmarks/src/carl_bench/candidate_evidence.py`
- Create: `benchmarks/tests/test_candidate_evidence.py`
- Modify: `benchmarks/src/carl_bench/cli.py`
- Modify: `benchmarks/tests/test_cli.py`

**Interfaces:**

- Produces: `bind_paired_evidence(manifest, candidate, baseline, candidate_scorecard, comparison_seed, store) -> PairedEvidence`
- Produces: `issue_review_packet(manifest, projection, role: ReviewRole) -> ReviewPacket`
- Produces: `record_review_attestation(manifest, projection, packet, reviewer_id, context_id, verdict, report, store) -> ReviewAttestation`
- Moves: strict public scorecard parsing from CLI-private helpers to reusable evidence parsing

- [ ] **Step 1: Write failing paired-binding tests**

  Reuse real `Scorecard` fixtures to prove the comparison is recomputed; exact baseline and candidate
  commits/digests are bound; same-model mismatches, insufficient evidence, rejection, invalid
  scorecards, stale candidates, and mismatched manifest digests fail closed; and the full comparison
  JSON is stored privately.

- [ ] **Step 2: Run paired tests and verify RED**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_candidate_evidence.py -q -k paired`

  Expected: import or missing-function failure.

- [ ] **Step 3: Implement paired evidence using `compare_runs`**

  Reuse one strict scorecard parser from production code, call `compare_runs`, require decision
  `improvement`, hash/store canonical baseline, candidate, and comparison payloads, and return one
  `PairedEvidence` bound to the exact candidate and manifest.

- [ ] **Step 4: Write failing packet and attestation tests**

  Assert all four fixed roles produce distinct packet digests; packets omit other verdicts and raw
  evidence; attestations require exact packet/candidate binding; reports are stored privately;
  reviewer and context IDs cannot be reused; hard finding dominates; and three of four approvals are
  required for the local draft gate.

- [ ] **Step 5: Run review tests and verify RED**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_candidate_evidence.py -q -k review`

  Expected: missing packet/attestation behavior.

- [ ] **Step 6: Implement independent review services**

  Generate role-specific canonical packets from ledger evidence only. Store report bytes before
  producing attestations. Enforce uniqueness both in the service and reducer so a forged direct
  event cannot bypass it.

- [ ] **Step 7: Run evidence tests, CLI parser regressions, and Ruff**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_candidate_evidence.py benchmarks/tests/test_cli.py -q`

  Run: `uv run --project benchmarks ruff check benchmarks/src/carl_bench/candidate_evidence.py benchmarks/src/carl_bench/cli.py benchmarks/tests/test_candidate_evidence.py benchmarks/tests/test_cli.py`

- [ ] **Step 8: Commit evidence services**

  ```bash
  git add benchmarks/src/carl_bench/candidate_evidence.py benchmarks/src/carl_bench/cli.py benchmarks/tests/test_candidate_evidence.py benchmarks/tests/test_cli.py
  git commit -m "feat: bind paired and independent review evidence"
  ```

### Task 5: Narrow, idempotent draft-PR gateway

**Files:**

- Create: `benchmarks/src/carl_bench/github_draft.py`
- Create: `benchmarks/tests/fakes/fake-gh.py`
- Create: `benchmarks/tests/test_github_draft.py`

**Interfaces:**

- Produces: `DraftPrGateway(repository_root, repository_slug, remote, base_branch, gh_executable, command_env)`
- Produces: `DraftPrGateway.open_or_reconcile(manifest, projection) -> DraftPullRequest`

- [ ] **Step 1: Write failing process-level gateway tests**

  Use a real temporary Git repository/bare origin plus a fake `gh` executable with a durable JSON
  state file. Cover first push/create, retry reconciliation without duplication, pushed-branch retry,
  candidate drift, wrong head/base/repository, non-draft PR, closed PR, malformed/oversized CLI JSON,
  unsafe `gh` executable, nonzero exits, timeouts, and closed environment.

- [ ] **Step 2: Run gateway tests and verify RED**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_github_draft.py -q`

  Expected: collection fails because `carl_bench.github_draft` does not exist.

- [ ] **Step 3: Implement exact-ref push and draft-only reconciliation**

  Verify local `<branch>^{commit}` equals the sealed candidate, inspect open PRs by derived head,
  and if absent run:

  ```text
  git -C <repo> push --porcelain <remote> <commit>:refs/heads/<branch>
  gh pr create --repo <slug> --draft --base <base> --head <branch> --title <title> --body-file <file>
  ```

  Then query `number,url,isDraft,state,headRefName,headRefOid,baseRefName` and require every field to
  match. Use no force flag. The deterministic body contains experiment ID, manifest/candidate and
  evidence digests, the local-only caveat, and no private prose.

- [ ] **Step 4: Add a source/argv denial test**

  Assert captured invocations contain none of `merge`, `--auto`, `ready`, `release`, `delete`, or
  force-push flags, and assert `github_draft.py` exposes no method with those operations.

- [ ] **Step 5: Run gateway tests and Ruff**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_github_draft.py -q`

  Run: `uv run --project benchmarks ruff check benchmarks/src/carl_bench/github_draft.py benchmarks/tests/test_github_draft.py benchmarks/tests/fakes/fake-gh.py`

- [ ] **Step 6: Commit the draft gateway**

  ```bash
  git add benchmarks/src/carl_bench/github_draft.py benchmarks/tests/fakes/fake-gh.py benchmarks/tests/test_github_draft.py
  git commit -m "feat: add draft-only pull request gateway"
  ```

### Task 6: Operator CLI and end-to-end phase-three flow

**Files:**

- Modify: `benchmarks/src/carl_bench/cli.py`
- Create: `benchmarks/tests/test_candidate_cli.py`
- Modify: `benchmarks/README.md`
- Modify: `docs/benchmarks.md`
- Modify: `README.md`

**Interfaces:**

- Adds: `carl-bench candidate prepare`
- Adds: `carl-bench candidate seal`
- Adds: `carl-bench candidate bind-comparison`
- Adds: `carl-bench candidate review-packet`
- Adds: `carl-bench candidate record-review`
- Adds: `carl-bench candidate status`
- Adds: `carl-bench candidate open-draft-pr --enable-github-draft`

- [ ] **Step 1: Write failing CLI contract tests**

  Assert every command requires ledger, experiment ID, stage-attempt ID where mutating, private
  artifact/worktree paths outside the repository, exact input files, and bounded outputs. Assert
  GitHub mutation is rejected without `--enable-github-draft`, and no command can request merge.

- [ ] **Step 2: Run CLI tests and verify RED**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_candidate_cli.py -q`

  Expected: parser rejects the missing `candidate` command.

- [ ] **Step 3: Implement thin CLI adapters**

  Keep orchestration in the new modules. Parse all control JSON with duplicate-key detection and
  exact contracts. Append prepared, candidate, paired, packet, attestation, and draft events only
  after the corresponding action succeeds/reconciles. Write builder requests and review packets as
  private files; write only sanitized status/eligibility/PR summaries through `write_public_json`.

- [ ] **Step 4: Write failing end-to-end fixture test**

  Initialize a private ledger, advance an approved proposal into building, prepare a real worktree,
  edit one allowed file, seal with a passing trusted check, transition to paired evaluation, bind
  an improvement scorecard pair, issue four packets, record three approvals and one rejection, open
  a fake draft PR, replay in a new process, and assert the final state remains `paired_evaluation`
  with next action `await_phase4_protected_validation`.

- [ ] **Step 5: Run end-to-end test and verify RED**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_candidate_cli.py -q -k end_to_end`

  Expected: the first missing orchestration or evidence append fails.

- [ ] **Step 6: Complete CLI orchestration and public status**

  Add a separate candidate status containing candidate/evidence/review/draft booleans, counts, and
  digests only. Exact redelivery returns the existing artifact/event/PR; conflicting redelivery
  returns exit 2. Preserve exit 3/4 benchmark meanings and the exact phase-two experiment-status
  schema.

- [ ] **Step 7: Update operator documentation**

  Document the private directory layout, trusted check registry schema, Codex prepare/edit/seal
  handoff, paired runs, role separation, draft-only gateway enable flag, recovery steps, and the
  explicit phase-four boundary. Remove statements that phase three is wholly absent, but retain
  the warning that no scheduled task or promotion is enabled.

- [ ] **Step 8: Run CLI/integration tests and Ruff**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_candidate_cli.py benchmarks/tests/test_experiment_cli.py benchmarks/tests/test_integration_contract.py -q`

  Run: `uv run --project benchmarks ruff check benchmarks/src/carl_bench benchmarks/tests`

- [ ] **Step 9: Commit CLI and documentation**

  ```bash
  git add benchmarks/src/carl_bench/cli.py benchmarks/tests/test_candidate_cli.py benchmarks/README.md docs/benchmarks.md README.md
  git commit -m "feat: expose isolated candidate workflow"
  ```

### Task 7: Security review, complete verification, and delivery

**Files:**

- Modify only files implicated by failures found in this task.

**Interfaces:**

- Consumes: every phase-three contract and command from Tasks 1-6
- Produces: a clean, pushed feature branch with all required local and GitHub checks passing

- [ ] **Step 1: Run focused phase-three tests**

  Run: `uv run --project benchmarks pytest benchmarks/tests/test_artifacts.py benchmarks/tests/test_candidate.py benchmarks/tests/test_candidate_git.py benchmarks/tests/test_candidate_evidence.py benchmarks/tests/test_github_draft.py benchmarks/tests/test_candidate_cli.py -q`

- [ ] **Step 2: Run the complete Python and benchmark suite**

  Run: `uv run --project benchmarks pytest benchmarks/tests -q`

  Run: `uv run --project benchmarks ruff check benchmarks/src/carl_bench benchmarks/tests`

  Run: `uv run --project benchmarks ruff format --check benchmarks/src/carl_bench benchmarks/tests`

  Run: `./scripts/benchmark-smoke.sh`

- [ ] **Step 3: Run the complete Rust verification**

  Run: `cargo fmt --all -- --check`

  Run: `cargo test --locked`

  Run: `cargo clippy --all-targets --all-features -- -D warnings`

- [ ] **Step 4: Audit the authority boundary**

  Search production and test argv for `merge`, `--auto`, `pr ready`, force push, shell execution,
  repository-internal private paths, and unbounded process output. Review the complete diff for
  symlink races, path traversal, stale commit use, event replacement, same-context reviews, leaked
  raw artifacts, false holdout claims, and optimistic external-state handling.

- [ ] **Step 5: Run final integrity checks**

  Run: `git diff --check`

  Run: `git status --short --branch`

  Re-read this plan and the design, checking every global constraint and exit criterion against
  code and tests.

- [ ] **Step 6: Commit any verification fixes and push**

  ```bash
  git add <only-files-changed-by-a-verified-fix>
  git commit -m "test: harden isolated candidate workflow"
  git push origin codex/carl-improvement-factory
  ```

- [ ] **Step 7: Confirm GitHub checks**

  Wait for Benchmark contracts, Quality, Ubuntu, macOS, and Windows checks on the pushed head. Retry
  an isolated infrastructure flake once; change code only when the failure is reproducible or tied
  to the phase-three diff. Keep PR #12 open and unmerged because phase four is not implemented.

## Exit criteria

- [ ] One approved experiment creates exactly one derived branch/worktree at its exact parent.
- [ ] Out-of-scope, forbidden, special-file, stale-parent, check-failure, and dirty-check paths block.
- [ ] The sealed candidate, check evidence, comparison, reviews, and draft PR bind the same commit.
- [ ] Three unique approvals and no hard finding are required; reviewers cannot edit the candidate.
- [ ] Draft creation is explicit, idempotent, sanitized, non-force, and reconciliation-driven.
- [ ] The experiment remains in `paired_evaluation`; protected validation and promotion stay absent.
- [ ] Phase-two ledgers, benchmark commands, public schemas, and all existing tests still work.
- [ ] Full Python/Rust verification and all PR checks pass.
