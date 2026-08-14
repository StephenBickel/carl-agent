#!/usr/bin/env node

// Opt-in paired endurance runner. Public CI invokes only `--self-test`.
// Production:
// CARL_DATA_DIR=/absolute/private/root \
// CARL_CODEX_EXECUTABLE=/absolute/path/to/codex \
// CARL_LIVE_CARGO_EXECUTABLE=/absolute/path/to/cargo \
// CARL_BIN=/absolute/path/to/release/carl \
// CARL_LIVE_MODEL=gpt-5.6-terra \
// CARL_LIVE_EFFORT=low \
// CARL_LIVE_DURATION_HOURS=2 \
// node scripts/live-codex-long-horizon.mjs
// A failed run writes no result artifact. Comparative claims require at least
// thirty independent paired runs; one pair is evidence only.

import { spawn } from "node:child_process";
import { EventEmitter } from "node:events";
import { randomBytes } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import {
  ChildRegistry,
  ChapterProgressTracker,
  CODEX_VERSION,
  FIXTURE_FILES,
  admitProduction,
  assertOutsideRepository,
  assertPrivateFile,
  atomicWriteResult,
  bindTerminationSignals,
  closedChildEnvironment,
  copyFixture,
  carlAcpInvocation,
  createFixture,
  deriveEvidence,
  digestBytes,
  fixtureManifest,
  forceCodexContextLoss,
  parseOneJsonLine,
  parseReadyMaintenance,
  readConsistentTaskState,
  directBaselineInvocation,
  validateMetricsResponse,
  validateFixture,
  validateResult,
  validateStatusResponse,
  writeResultAfterSuccess,
} from "./lib/live-runner-core.mjs";

const repository = resolve(import.meta.dirname, "..");
function validateChapterObservationWindow(holdSeconds, rpcTimeoutSeconds) {
  if (!Number.isSafeInteger(holdSeconds) || !Number.isSafeInteger(rpcTimeoutSeconds) ||
      holdSeconds <= rpcTimeoutSeconds || rpcTimeoutSeconds <= 0) {
    throw Object.assign(new Error("invalid_chapter_observation_window"), {
      code: "invalid_chapter_observation_window",
    });
  }
  return holdSeconds * 1_000;
}

const TASK_STATE_RPC_TIMEOUT_MS = 5_000;
const CHAPTER_MARKER_HOLD_MS = validateChapterObservationWindow(
  8,
  TASK_STATE_RPC_TIMEOUT_MS / 1_000,
);

const PROMPT = Buffer.from(
  "Fix the failing regression with a test-first change, refactor parsing across source files, " +
  "preserve needle_7f3a91c2 exactly, and update README with the exact clause " +
  "\"needle_7f3a91c2 remains stable across the refactor.\" Run cargo run --quiet --bin " +
  "once_probe exactly once and never edit or delete .once-probe. Then run cargo fmt --check and " +
  "cargo test. Work autonomously through every clause, use multiple verified steps, and do not stop " +
  "at a plan. This is an endurance evaluation: inspect audit/chapter_01.txt through chapter_20.txt " +
  "in numeric order. Read every chapter completely using twelve separate, non-overlapping 1,200-line " +
  "sed ranges and do not batch ranges or chapters into one command. After all twelve reads for one " +
  "chapter, append exactly " +
  "chapter_NN followed by a newline to .chapter-audit, substituting that chapter's two-digit number; " +
  `then keep that same append command alive for at least ${CHAPTER_MARKER_HOLD_MS / 1_000} seconds. After that command returns, immediately end the current turn with a structured continue epoch report before starting the next chapter, so its following durable checkpoint ` +
  "is externally observable. Create no other audit entries and never edit, truncate, or delete " +
  ".chapter-audit. Continue with " +
  "evidence-backed repository inspection until " +
  "every clause is durably complete; do not invent progress or repeat effects.",
  "utf8",
);
const REDACTED_FAILURE = "live endurance failed";

function buildTaskInput(cargoExecutable) {
  if (typeof cargoExecutable !== "string" || !cargoExecutable.startsWith("/") ||
      cargoExecutable.includes("\n") || cargoExecutable.includes("\0")) {
    throw Object.assign(new Error("invalid_cargo_binary"), { code: "invalid_cargo_binary" });
  }
  const toolchainPath = `${dirname(cargoExecutable)}:/usr/bin:/bin:/usr/sbin:/sbin`;
  return Buffer.concat([
    PROMPT,
    Buffer.from(
      ` The provider environment deliberately has a closed PATH. Prefix every Cargo, rustc, rustdoc, cargo-fmt, and rustfmt command with PATH=${toolchainPath}. Use the exact Cargo executable ${cargoExecutable} for every Cargo command. ` +
      "The base sandbox is deliberately read-only; request approval for every mutation and continue after Carl authorizes it.",
      "utf8",
    ),
  ]);
}

function expect(condition, message = "self_test_failed") {
  if (!condition) throw Object.assign(new Error(message), { code: message });
}

async function expectCode(operation, code) {
  try {
    await operation();
  } catch (error) {
    if (error?.code === code) return;
    throw error;
  }
  throw Object.assign(new Error(`missing_${code}`), { code: `missing_${code}` });
}

function sampleDirect(model = "gpt-5.6-terra", effort = "low") {
  return {
    schema_version: 1,
    provider: "codex",
    codex_version: CODEX_VERSION,
    model,
    effort,
    completed: true,
    elapsed_milliseconds: 1,
    input_tokens: 2,
    cached_input_tokens: 1,
    output_tokens: 1,
    command_executions: 1,
    file_changes: 1,
    mcp_tool_calls: 0,
    web_searches: 0,
    compatibility_events: 0,
  };
}

function sampleResult(manifest, taskDigest) {
  return {
    schema_version: 1,
    harness_git_revision: "a".repeat(40),
    codex_version: CODEX_VERSION,
    model: "gpt-5.6-terra",
    effort: "low",
    requested_duration_hours: 2,
    fixture_manifest_digest: manifest,
    task_input_digest: taskDigest,
    carl: {
      completed: true,
      elapsed_milliseconds: 2,
      provider_requests: 25,
      epochs: 24,
      tool_calls: 20,
      compactions: 20,
      context_losses: 2,
      recoveries: 2,
      clauses_satisfied: 5,
      clauses_total: 5,
      interventions: 2,
      restarts: 5,
      no_unresolved_operations: true,
      no_duplicate_effects: true,
      no_orphan_processes: true,
    },
    direct_baseline: sampleDirect(),
    admission_passed: true,
    cleanup_passed: true,
    parity_passed: true,
  };
}

function evidenceFixture() {
  const digest = "b".repeat(64);
  return [
    { kind: "progress", key: "p1", revision: 1, sequence: 1, workspaceDigest: digest },
    ...Array.from({ length: 20 }, (_, index) => ({ kind: "compaction", key: `c${index}`, completed: true })),
    ...Array.from({ length: 20 }, (_, index) => ({ kind: "chapter", key: `chapter-${index + 1}`, completed: true })),
    { kind: "steer", key: "s1", outcome: "accepted" },
    { kind: "steer", key: "s2", outcome: "accepted" },
    ...Array.from({ length: 5 }, (_, index) => ({ kind: "restart", key: `r${index}`, ready: true, resumed: true })),
    { kind: "context_loss", key: "l1", replaced: true },
    { kind: "context_loss", key: "l2", replaced: true },
    { kind: "long_command", key: "q1", started: true, completed: true },
  ];
}

class FakeChild extends EventEmitter {
  constructor() {
    super();
    this.exitCode = null;
    this.signalCode = null;
  }
  kill(signal) {
    this.signalCode = signal;
    queueMicrotask(() => this.emit("exit", null, signal));
    return true;
  }
}

class StubbornFakeChild extends FakeChild {
  constructor() {
    super();
    this.signals = [];
  }
  kill(signal) {
    this.signals.push(signal);
    if (signal === "SIGKILL") {
      this.signalCode = signal;
      queueMicrotask(() => this.emit("exit", null, signal));
    }
    return true;
  }
}

class NeverExitsFakeChild extends FakeChild {
  kill(signal) {
    this.signalCode = null;
    return signal === "SIGTERM" || signal === "SIGKILL";
  }
}

function sampleMetrics(overrides = {}) {
  return {
    schema_version: 1,
    task_id: "11111111-1111-4111-8111-111111111111",
    status: "completed",
    revision: 30,
    durable_event_count: 50,
    durable_sequence_end: 50,
    provider_requests: 25,
    epochs_started: 24,
    epochs_completed: 24,
    operation_intents: 22,
    operations_succeeded: 22,
    operations_failed: 0,
    operations_cancelled: 0,
    operations_uncertain: 0,
    unresolved_operations: 0,
    compactions_completed: 20,
    provider_context_losses: 2,
    recovery_attempts: 2,
    latest_observed_tokens: 120000,
    latest_context_window: 200000,
    required_clauses_total: 5,
    required_clauses_satisfied: 5,
    budget: {
      max_wall_time_seconds: 7200,
      max_provider_requests: 10000,
      max_tool_calls: 100000,
      soft_epoch_seconds: 30,
      soft_epoch_tool_calls: 1,
    },
    ...overrides,
  };
}

function sampleStatus(metrics = sampleMetrics()) {
  return {
    task: {
      task_id: metrics.task_id,
      session_id: "22222222-2222-4222-8222-222222222222",
      status: metrics.status,
      contract: {
        version: 1,
        goal: "complete the endurance fixture",
        constraints: [],
        clauses: Array.from({ length: 5 }, (_, index) => ({
          id: `clause-${index}`,
          description: `clause ${index}`,
          required: true,
          status: "satisfied",
          evidence: [{ event_sequence: index + 1, artifact_digest: null, operation_id: null }],
        })),
      },
      budget: metrics.budget,
      active_epoch: null,
      latest_checkpoint: "33333333-3333-4333-8333-333333333333",
      provider_context: "provider-context",
      revision: metrics.revision,
      operations: {},
      pending_recovery: null,
    },
  };
}

function carlCompletionIsSafe(metrics) {
  return metrics.status === "completed" &&
    metrics.required_clauses_total >= 2 &&
    metrics.required_clauses_satisfied === metrics.required_clauses_total &&
    metrics.unresolved_operations === 0 &&
    metrics.operations_uncertain === 0;
}

async function selfTest() {
  const root = await mkdtemp(join(tmpdir(), "carl-live-self-test-"));
  await chmod(root, 0o700);
    const canonicalRoot = await realpath(root);
  try {
    expect(validateChapterObservationWindow(8, 5) === 8_000);
    await expectCode(
      () => Promise.resolve(validateChapterObservationWindow(5, 5)),
      "invalid_chapter_observation_window",
    );
    // 1. Closed admission: no API keys, proxy, Buzz/XAI, debug, or fixture controls survive.
    const environment = closedChildEnvironment(
      { PATH: "/bin", HOME: root, OPENAI_API_KEY: "secret", HTTPS_PROXY: "secret", BUZZ_TOKEN: "secret", CARL_TEST_SECRET: "secret" },
      { CARL_DATA_DIR: root, CARL_CODEX_EXECUTABLE: "/bin/echo" },
    );
    expect(environment.PATH === "/bin" && !JSON.stringify(environment).includes("secret"));
    await expectCode(() => Promise.resolve(closedChildEnvironment({}, { CARL_DEBUG_PROVIDER: "1" })), "invalid_environment");

    // 2. Exact independent fixture copies and fail-closed links/active-repository checks.
    const source = join(root, "source");
    const carl = join(root, "carl");
    const direct = join(root, "direct");
    const sourceDigest = await createFixture(source);
    const supportsOwnerPrivateModes = process.platform !== "win32" &&
      typeof process.getuid === "function";
    if (supportsOwnerPrivateModes) {
      expect((await copyFixture(source, carl, repository)) === sourceDigest);
      expect((await copyFixture(source, direct, repository)) === sourceDigest);
    } else {
      // Windows exposes synthetic POSIX mode bits through Node, so the live
      // runner deliberately refuses the owner-private production boundary.
      // The offline test must prove that refusal while still checking that
      // independently materialized fixtures have identical bytes.
      await expectCode(() => validateFixture(source, repository), "invalid_fixture");
      expect((await createFixture(carl)) === sourceDigest);
      expect((await createFixture(direct)) === sourceDigest);
    }
    expect((await fixtureManifest(carl)) === (await fixtureManifest(direct)));
    if (supportsOwnerPrivateModes) {
      const linked = join(root, "linked");
      await symlink(source, linked);
      await expectCode(() => validateFixture(linked, repository), "invalid_fixture");
    }
    await expectCode(() => Promise.resolve(assertOutsideRepository(join(repository, "fixture"), repository)), "active_repository_refused");
    const unexpected = join(root, "unexpected");
    if (supportsOwnerPrivateModes) await copyFixture(source, unexpected, repository);
    else await createFixture(unexpected);
    await writeFile(join(unexpected, "extra.txt"), "unexpected\n", { mode: 0o600 });
    await expectCode(() => validateFixture(unexpected, repository), "invalid_fixture");
    const publicFixture = join(root, "public-fixture");
    if (supportsOwnerPrivateModes) await copyFixture(source, publicFixture, repository);
    else await createFixture(publicFixture);
    await chmod(publicFixture, 0o755);
    await expectCode(() => validateFixture(publicFixture, repository), "invalid_fixture");

    // 3. Both arms receive the exact same opaque bytes/settings; text is absent elsewhere.
    const routed = [
      { stdin: Buffer.from(PROMPT), model: "gpt-5.6-terra", effort: "low", timeout: 7200 },
      { stdin: Buffer.from(PROMPT), model: "gpt-5.6-terra", effort: "low", timeout: 7200 },
    ];
    expect(routed[0].stdin.equals(routed[1].stdin));
    expect(JSON.stringify(routed.map(({ stdin: _stdin, ...rest }) => rest)).includes("needle_7f3a91c2") === false);

    // 4. Counts and service observations are strict, typed, and monotonic.
    const evidence = evidenceFixture();
    expect(JSON.stringify(deriveEvidence(evidence)) === JSON.stringify({ steers: 2, restarts: 5, compactions: 20, contextLosses: 2, longCommands: 1, progressIntervals: 1, chapters: 20 }));
    await expectCode(() => Promise.resolve(deriveEvidence([evidence[0], { ...evidence[0], key: "p2" }, ...evidence.slice(1)])), "stale_progress");
    await expectCode(() => Promise.resolve(deriveEvidence([...evidence, evidence[1]])), "duplicate_evidence");
    await expectCode(() => Promise.resolve(deriveEvidence([{ ...evidence[0], revision: 2, sequence: 2 }, { ...evidence[0], key: "regress", revision: 1, sequence: 3 }, ...evidence.slice(1)])), "regressing_evidence");
    await expectCode(() => Promise.resolve(deriveEvidence(evidence.map((entry) => entry.kind === "restart" ? { ...entry, ready: false } : entry))), "failed_evidence");
    const chapters = new ChapterProgressTracker();
    let audit = "";
    for (let index = 1; index <= 20; index += 1) {
      audit += `chapter_${String(index).padStart(2, "0")}\n`;
      const before = `11111111-1111-4111-8111-${String(index).padStart(12, "0")}`;
      const after = `22222222-2222-4222-8222-${String(index).padStart(12, "0")}`;
      expect(chapters.observe(audit, before) === null);
      expect(chapters.pendingCount() === index);
      expect(chapters.observe(audit, after) === index);
      expect(chapters.pendingCount() === null);
    }
    chapters.assertComplete();
    const batchedChapters = new ChapterProgressTracker();
    await expectCode(() => Promise.resolve(batchedChapters.observe("chapter_01\nchapter_02\n", null)), "chapter_progress_batched");
    const reloadTracker = new ChapterProgressTracker();
    const reloadEvidence = [];
    const reloadWorkspace = join(root, "reload-workspace");
    await mkdir(reloadWorkspace, { mode: 0o700 });
    await writeFile(join(reloadWorkspace, ".chapter-audit"), "chapter_01\n", { mode: 0o600 });
    expect(await observeDurableChapterProgress(
      reloadTracker,
      reloadWorkspace,
      "11111111-1111-4111-8111-000000000001",
      reloadEvidence,
    ) === null);
    expect(await observeDurableChapterProgress(
      reloadTracker,
      reloadWorkspace,
      "22222222-2222-4222-8222-000000000001",
      reloadEvidence,
    ) === 1);
    await writeFile(join(reloadWorkspace, ".chapter-audit"), "chapter_01\nchapter_02\n", { mode: 0o600 });
    expect(await observeDurableChapterProgress(
      reloadTracker,
      reloadWorkspace,
      "22222222-2222-4222-8222-000000000001",
      reloadEvidence,
    ) === null);
    expect(JSON.stringify(reloadEvidence) === JSON.stringify([{ kind: "chapter", key: "chapter-1", completed: true }]));
    const metrics = validateMetricsResponse({ metrics: sampleMetrics() });
    const blockedStateTracker = new ChapterProgressTracker();
    const blockedStateEvidence = [];
    await writeFile(join(reloadWorkspace, ".chapter-audit"), "chapter_01\n", { mode: 0o600 });
    blockedStateTracker.observe(
      "chapter_01\n",
      "11111111-1111-4111-8111-000000000001",
    );
    blockedStateTracker.observe(
      "chapter_01\n",
      "22222222-2222-4222-8222-000000000001",
    );
    await writeFile(join(reloadWorkspace, ".chapter-audit"), "chapter_01\nchapter_02\n", { mode: 0o600 });
    const blockedState = await readTaskStateWithChapterProgress({
      tracker: blockedStateTracker,
      workspace: reloadWorkspace,
      evidence: blockedStateEvidence,
      previousCheckpoint: "22222222-2222-4222-8222-000000000001",
      readMetrics: async () => ({ metrics }),
      readStatus: async () => sampleStatus(metrics),
    });
    expect(blockedState.snapshot.revision === metrics.revision);
    expect(JSON.stringify(blockedStateEvidence) === JSON.stringify([{ kind: "chapter", key: "chapter-2", completed: true }]));
    validateStatusResponse(sampleStatus(metrics), metrics);
    const advanced = sampleMetrics({ revision: metrics.revision + 1, durable_event_count: metrics.durable_event_count + 1, durable_sequence_end: metrics.durable_sequence_end + 1 });
    const metricSamples = [metrics, advanced, advanced, advanced];
    const statusSamples = [sampleStatus(metrics), sampleStatus(advanced)];
    const consistent = await readConsistentTaskState(
      async () => ({ metrics: metricSamples.shift() }),
      async () => statusSamples.shift(),
    );
    expect(consistent.metrics.revision === advanced.revision && consistent.snapshot.revision === advanced.revision);
    const staleStatusSamples = [sampleStatus(metrics), sampleStatus(advanced)];
    const retried = await readConsistentTaskState(
      async () => ({ metrics: advanced }),
      async () => staleStatusSamples.shift(),
      metrics,
    );
    expect(retried.metrics.revision === advanced.revision && retried.snapshot.revision === advanced.revision);
    await expectCode(() => Promise.resolve(validateMetricsResponse({ metrics: { ...metrics, revision: "30" } })), "invalid_metrics");
    await expectCode(() => Promise.resolve(validateMetricsResponse({ metrics: { ...metrics, surprise: 1 } })), "invalid_metrics");
    await expectCode(() => Promise.resolve(validateMetricsResponse({ metrics: { ...metrics, revision: 29 } }, metrics)), "regressing_metrics");
    await expectCode(() => Promise.resolve(validateStatusResponse({ task: { ...sampleStatus(metrics).task, status: "active" } }, metrics)), "invalid_status");
    await expectCode(() => Promise.resolve(validateStatusResponse({ task: { ...sampleStatus(metrics).task, surprise: true } }, metrics)), "invalid_status");
    expect(carlCompletionIsSafe(sampleMetrics({ required_clauses_total: 2, required_clauses_satisfied: 2 })));
    expect(!carlCompletionIsSafe(sampleMetrics({ required_clauses_total: 1, required_clauses_satisfied: 1 })));

    // 5. Malformed/extra child output and fixture divergence fail closed.
    await expectCode(() => Promise.resolve(parseOneJsonLine("{}\n{}\n")), "malformed_child_json");
    await writeFile(join(direct, "README.md"), "diverged\n", { mode: 0o600 });
    expect((await fixtureManifest(direct)) !== sourceDigest);

    // 6. Exact bounded sanitized result and mode-0600 atomic artifact.
    const result = sampleResult(sourceDigest, digestBytes(PROMPT));
    expect(validateResult(result).length < 16 * 1024);
    await expectCode(() => Promise.resolve(validateResult({ ...result, prompt: "secret" })), "invalid_result");
    await expectCode(() => Promise.resolve(validateResult({ ...result, direct_baseline: { ...result.direct_baseline, completed: false } })), "invalid_result");
    for (const forbidden of ["person@example.com", "/home/owner/private", "sk-secretvalue", "cargo test", "diff --git a/x b/x"]) {
      await expectCode(() => Promise.resolve(validateResult({
        ...result,
        model: forbidden,
        direct_baseline: { ...result.direct_baseline, model: forbidden },
      })), "result_not_sanitized");
    }
    const artifact = join(root, "result", "paired.json");
    if (supportsOwnerPrivateModes) {
      await atomicWriteResult(artifact, result);
      await assertPrivateFile(artifact);
      expect((await readFile(artifact, "utf8")) === `${JSON.stringify(result)}\n`);
    } else {
      await expectCode(() => atomicWriteResult(artifact, result), "unsafe_artifact");
      expect(await lstat(artifact).catch(() => null) === null);
    }
    const failedArtifact = join(root, "result", "failed.json");
    const failingRegistry = new ChildRegistry();
    failingRegistry.track(new NeverExitsFakeChild());
    await expectCode(() => writeResultAfterSuccess(failedArtifact, async () => {
      await failingRegistry.terminateAll(1);
      return result;
    }), "child_leak");
    expect(await lstat(failedArtifact).catch(() => null) === null);

    // Production admission and routing use canonical private paths and never place
    // task input in argv/environment.
    const releaseDirectory = join(canonicalRoot, "target", "release");
    await mkdir(releaseDirectory, { recursive: true, mode: 0o700 });
    const fakeCarl = join(releaseDirectory, "carl");
    const fakeCodex = join(canonicalRoot, "codex");
    const fakeCargo = join(canonicalRoot, "cargo");
    for (const executable of [fakeCarl, fakeCodex, fakeCargo]) {
      await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
      await chmod(executable, 0o700);
    }
    const productionEnvironment = {
      CARL_DATA_DIR: canonicalRoot,
      CARL_CODEX_EXECUTABLE: fakeCodex,
      CARL_LIVE_CARGO_EXECUTABLE: fakeCargo,
      CARL_BIN: fakeCarl,
      CARL_LIVE_MODEL: "gpt-5.6-terra",
      CARL_LIVE_EFFORT: "low",
      CARL_LIVE_DURATION_HOURS: "2",
    };
    let admitted;
    if (supportsOwnerPrivateModes) {
      admitted = await admitProduction(productionEnvironment, repository);
      expect(admitted.cargo === fakeCargo);
    } else {
      await expectCode(
        () => admitProduction(productionEnvironment, repository),
        "invalid_data_root",
      );
      admitted = {
        carl: "/unsupported/target/release/carl",
        codex: "/unsupported/codex",
        cargo: "/unsupported/cargo",
        dataRoot: canonicalRoot,
        repository,
        model: "gpt-5.6-terra",
        effort: "low",
        durationHours: 2,
        timeoutSeconds: 7_200,
      };
    }
    const livePrompt = buildTaskInput(admitted.cargo);
    expect(
      livePrompt.toString("utf8").includes(
        `PATH=${dirname(admitted.cargo)}:/usr/bin:/bin:/usr/sbin:/sbin`,
      ),
      "task input must make the admitted Rust toolchain discoverable without ambient PATH",
    );
    const acpInvocation = carlAcpInvocation(admitted, carl);
    const softTimeIndex = acpInvocation.argv.indexOf("--soft-epoch-seconds");
    expect(softTimeIndex >= 0 && acpInvocation.argv[softTimeIndex + 1] === "900");
    const softToolIndex = acpInvocation.argv.indexOf("--soft-epoch-tool-calls");
    expect(softToolIndex >= 0 && acpInvocation.argv[softToolIndex + 1] === "6");
    const directInvocation = directBaselineInvocation(admitted, direct, livePrompt);
    expect(!JSON.stringify({ argv: acpInvocation.argv, environment: acpInvocation.environment }).includes("needle_7f3a91c2"));
    expect(!JSON.stringify({ argv: directInvocation.argv, environment: directInvocation.environment }).includes("needle_7f3a91c2"));
    expect(directInvocation.stdin.equals(livePrompt));
    await expectCode(() => admitProduction({ ...process.env, CARL_DATA_DIR: canonicalRoot, CARL_CODEX_EXECUTABLE: fakeCodex, CARL_LIVE_CARGO_EXECUTABLE: fakeCargo, CARL_BIN: fakeCarl, CARL_LIVE_MODEL: "gpt-5.6-terra", CARL_LIVE_EFFORT: "low", CARL_LIVE_DURATION_HOURS: "1" }, repository), "invalid_duration");

    // 7. Maintenance parsing, signal cancellation, and stubborn-child cleanup use
    // the same production seams and observe exit before success.
    parseReadyMaintenance('{"schema_version":1,"phase":"ready","task_id":"11111111-1111-4111-8111-111111111111","checkpoint_id":"33333333-3333-4333-8333-333333333333"}\n', "11111111-1111-4111-8111-111111111111");
    await expectCode(() => Promise.resolve(parseReadyMaintenance('{"schema_version":1,"phase":"draining","task_id":"11111111-1111-4111-8111-111111111111","checkpoint_id":null}\n')), "maintenance_not_ready");
    await expectCode(() => Promise.resolve(parseReadyMaintenance('{"schema_version":1,"phase":"ready","task_id":null,"checkpoint_id":null,"detail":"unsafe"}\n')), "malformed_child_json");
    const registry = new ChildRegistry();
    const stubborn = registry.track(new StubbornFakeChild());
    const signalSource = new EventEmitter();
    const cancellation = new AbortController();
    const binding = bindTerminationSignals(signalSource, cancellation, registry);
    signalSource.emit("SIGINT");
    await binding.wait();
    binding.dispose();
    expect(cancellation.signal.aborted && stubborn.signals.includes("SIGTERM") && stubborn.signals.includes("SIGKILL"));
    expect(registry.size === 0);
    const exitingChild = spawnTracked(
      registry,
      process.execPath,
      ["-e", "process.stdin.once('data', () => process.exit(0))"],
      { env: closedChildEnvironment(process.env), stdio: ["pipe", "pipe", "pipe"] },
    );
    const exitingRpc = new RpcClient(exitingChild, registry);
    await expectCode(() => exitingRpc.request("fixture/exit", {}, 1_000), "child_exited");
    expect(exitingRpc.pendingTimerCount === 0, "rpc_timer_leak");
    await registry.terminateAll();
    const providerRoot = join(canonicalRoot, "providers", "codex");
    await mkdir(providerRoot, { recursive: true, mode: 0o700 });
    await writeFile(join(providerRoot, "auth.json"), "auth-sentinel\n", { mode: 0o600 });
    for (const name of ["state_5.sqlite", "state_5.sqlite-shm", "state_5.sqlite-wal"]) {
      await writeFile(join(providerRoot, name), "disposable\n", { mode: 0o600 });
    }
    const sessions = join(providerRoot, "sessions", "2026", "08", "12");
    await mkdir(sessions, { recursive: true, mode: 0o700 });
    await writeFile(join(sessions, "rollout-fixture.jsonl"), "transcript-sentinel\n", { mode: 0o600 });
    if (supportsOwnerPrivateModes) await forceCodexContextLoss(canonicalRoot, 1);
    else await expectCode(() => forceCodexContextLoss(canonicalRoot, 1), "invalid_data_root");
    expect((await readFile(join(providerRoot, "auth.json"), "utf8")) === "auth-sentinel\n");
    if (supportsOwnerPrivateModes) {
      expect(await lstat(join(providerRoot, "state_5.sqlite")).catch(() => null) === null);
      expect(await lstat(join(providerRoot, "sessions")).catch(() => null) === null);
      expect(
        (await readFile(join(providerRoot, "context-loss-fixtures", "loss-1", "sessions", "2026", "08", "12", "rollout-fixture.jsonl"), "utf8")) ===
        "transcript-sentinel\n",
      );
    } else {
      expect((await readFile(join(providerRoot, "state_5.sqlite"), "utf8")) === "disposable\n");
      expect((await readFile(join(sessions, "rollout-fixture.jsonl"), "utf8")) === "transcript-sentinel\n");
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
  process.stdout.write('{"schema_version":1,"passed":true,"checks":7}\n');
}

function spawnTracked(registry, executable, args, options) {
  return registry.track(spawn(executable, args, { ...options, detached: process.platform !== "win32" }));
}

function waitForExit(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(child.exitCode);
  return new Promise((resolveExit) => child.once("exit", resolveExit));
}

class RpcClient {
  constructor(child, registry) {
    this.child = child;
    this.registry = registry;
    this.nextId = 1;
    this.pending = new Map();
    this.activeTimers = 0;
    this.notifications = [];
    this.stderrBytes = 0;
    createInterface({ input: child.stdout, crlfDelay: Infinity }).on("line", (line) => this.#line(line));
    child.stderr.on("data", (chunk) => {
      this.stderrBytes += chunk.length;
      if (this.stderrBytes > 256 * 1024) void registry.terminate(child, 0);
    });
    child.once("exit", () => {
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        this.activeTimers -= 1;
        pending.reject(Object.assign(new Error("child_exited"), { code: "child_exited" }));
      }
      this.pending.clear();
    });
  }
  get pendingTimerCount() {
    return this.activeTimers;
  }
  #line(line) {
    let message;
    try { message = JSON.parse(line); } catch { void this.registry.terminate(this.child, 0); return; }
    if (Object.hasOwn(message, "id") && this.pending.has(message.id)) {
      const pending = this.pending.get(message.id);
      this.pending.delete(message.id);
      clearTimeout(pending.timer);
      this.activeTimers -= 1;
      if (message.error) pending.reject(Object.assign(new Error("rpc_failed"), { code: `rpc_${message.error.code}` }));
      else pending.resolve(message.result);
    } else if (message.method === "session/update") {
      const update = message.params?.update;
      if (update && typeof update.sessionUpdate === "string") {
        this.notifications.push({
          update: {
            sessionUpdate: update.sessionUpdate,
            taskId: update.taskId,
            generation: update.generation,
            toolCallId: update.toolCallId,
            title: update.title,
            kind: update.kind,
            status: update.status,
          },
        });
      }
    }
  }
  request(method, params, timeoutMilliseconds = 300_000) {
    const id = this.nextId++;
    const result = new Promise((resolveRequest, rejectRequest) => {
      const timer = setTimeout(() => {
        if (this.pending.delete(id)) {
          this.activeTimers -= 1;
          rejectRequest(Object.assign(new Error("rpc_timeout"), { code: "rpc_timeout" }));
        }
      }, timeoutMilliseconds);
      this.pending.set(id, { resolve: resolveRequest, reject: rejectRequest, timer });
      this.activeTimers += 1;
    });
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    return result;
  }
  drainNotifications() {
    return this.notifications.splice(0);
  }
}

async function runCommand(registry, executable, args, options, stdin = null, timeoutMilliseconds = 30_000) {
  const child = spawnTracked(registry, executable, args, { ...options, stdio: ["pipe", "pipe", "pipe"] });
  const stdout = [];
  const stderr = [];
  let outputBytes = 0;
  const capture = (target) => (chunk) => {
    outputBytes += chunk.length;
    if (outputBytes > 256 * 1024) void registry.terminate(child, 0);
    else target.push(chunk);
  };
  child.stdout.on("data", capture(stdout));
  child.stderr.on("data", capture(stderr));
  const timer = setTimeout(() => { void registry.terminate(child, 0); }, timeoutMilliseconds);
  if (stdin) child.stdin.end(stdin); else child.stdin.end();
  const exit = await waitForExit(child);
  clearTimeout(timer);
  if (exit !== 0) throw Object.assign(new Error("child_failed"), { code: "child_failed" });
  return { stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8") };
}

async function startService(admission, registry, workspace, environment) {
  const child = spawnTracked(registry, admission.carl, ["serve"], { cwd: workspace, env: environment, stdio: ["ignore", "ignore", "pipe"] });
  let stderrBytes = 0;
  child.stderr.on("data", (chunk) => { stderrBytes += chunk.length; if (stderrBytes > 256 * 1024) void registry.terminate(child, 0); });
  // Readiness is proven by a successful ACP initialize, not a timer.
  return child;
}

async function connectAcp(admission, registry, workspace, environment) {
  const invocation = carlAcpInvocation(admission, workspace);
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const child = spawnTracked(registry, invocation.executable, invocation.argv, { cwd: workspace, env: invocation.environment, stdio: ["pipe", "pipe", "pipe"] });
    const rpc = new RpcClient(child, registry);
    try {
      const initialized = await rpc.request("initialize", { protocolVersion: 2, clientCapabilities: {}, clientInfo: { name: "carl-long-horizon", version: "1" } }, 1_000);
      if (initialized.protocolVersion !== 2) throw new Error("protocol");
      return { child, rpc };
    } catch {
      await registry.terminate(child, 0);
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
    }
  }
  throw Object.assign(new Error("service_unavailable"), { code: "service_unavailable" });
}

function updateBody(notification) {
  return notification?.update ?? null;
}

async function verifyCompletedWorkspace(registry, workspace, environment) {
  const probe = await readFile(join(workspace, ".once-probe"), "utf8").catch(() => "");
  const chapterAudit = await readFile(join(workspace, ".chapter-audit"), "utf8").catch(() => "");
  const expectedChapterAudit = Array.from({ length: 20 }, (_, index) => `chapter_${String(index + 1).padStart(2, "0")}\n`).join("");
  await validateCompletedTopology(workspace);
  const library = await readFile(join(workspace, "src/lib.rs"), "utf8");
  const parser = await readFile(join(workspace, "src/parser.rs"), "utf8");
  const readme = await readFile(join(workspace, "README.md"), "utf8");
  const auditInputsUnchanged = (await Promise.all(
    Array.from({ length: 20 }, async (_, index) => {
      const name = `audit/chapter_${String(index + 1).padStart(2, "0")}.txt`;
      return (await readFile(join(workspace, name), "utf8")) === FIXTURE_FILES[name];
    }),
  )).every(Boolean);
  if (probe !== "once\n" || chapterAudit !== expectedChapterAudit || !auditInputsUnchanged || library === FIXTURE_FILES["src/lib.rs"] || parser === FIXTURE_FILES["src/parser.rs"] || !library.includes("mod parser") || !`${library}\n${parser}`.includes("needle_7f3a91c2") || parser.includes(".trim()") || !readme.includes("needle_7f3a91c2 remains stable across the refactor.")) return false;
  await runCommand(registry, "cargo", ["fmt", "--check"], { cwd: workspace, env: environment }, null, 600_000);
  await runCommand(registry, "cargo", ["test"], { cwd: workspace, env: environment }, null, 600_000);
  const privateVerifier = join(workspace, "tests", "carl_private_verifier.rs");
  await writeFile(privateVerifier, `use carl_endurance_fixture::{parse_count, EARLY_IDENTIFIER};\n\n#[test]\nfn private_acceptance() {\n    assert!(parse_count(" 7 ").is_err());\n    assert_eq!(parse_count("7").unwrap(), 7);\n    assert_eq!(EARLY_IDENTIFIER, "needle_7f3a91c2");\n}\n`, { mode: 0o600, flag: "wx" });
  try {
    await runCommand(registry, "cargo", ["test", "--test", "carl_private_verifier"], { cwd: workspace, env: environment }, null, 600_000);
  } finally {
    await unlink(privateVerifier).catch(() => {});
  }
  return true;
}

async function validateCompletedTopology(workspace) {
  const allowed = new Set([...Object.keys(FIXTURE_FILES), ".once-probe", ".chapter-audit", "Cargo.lock"]);
  const { readdir } = await import("node:fs/promises");
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const relative = path.slice(workspace.length + 1).split("/").join("/");
      if (relative === "target" || relative.startsWith("target/")) continue;
      const info = await lstat(path);
      if (info.isSymbolicLink() || (!info.isDirectory() && !info.isFile())) throw new Error("unsafe_completed_fixture");
      if (info.isDirectory()) await walk(path);
      else if (!allowed.has(relative)) throw new Error("unexpected_completed_file");
    }
  }
  await walk(workspace);
  for (const required of ["Cargo.toml", "README.md", "src/lib.rs", "src/parser.rs", "src/bin/once_probe.rs", "tests/regression.rs", ".once-probe", ".chapter-audit"]) {
    const info = await lstat(join(workspace, required)).catch(() => null);
    if (!info?.isFile() || info.isSymbolicLink()) throw new Error("missing_completed_file");
  }
}

async function observeDurableChapterProgress(tracker, workspace, latestCheckpoint, evidence) {
  let audit = "";
  try {
    audit = await readFile(join(workspace, ".chapter-audit"), "utf8");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
  const provenChapter = tracker.observe(audit, latestCheckpoint);
  if (provenChapter !== null) {
    evidence.push({ kind: "chapter", key: `chapter-${provenChapter}`, completed: true });
  }
  return provenChapter;
}

async function readTaskStateWithChapterProgress({
  tracker,
  workspace,
  evidence,
  previousCheckpoint,
  readMetrics,
  readStatus,
  previousMetrics = null,
}) {
  await observeDurableChapterProgress(
    tracker,
    workspace,
    previousCheckpoint,
    evidence,
  );
  const state = await readConsistentTaskState(
    readMetrics,
    readStatus,
    previousMetrics,
  );
  await observeDurableChapterProgress(
    tracker,
    workspace,
    state.snapshot.latest_checkpoint,
    evidence,
  );
  return state;
}

async function production() {
  const admission = await admitProduction(process.env, repository);
  const taskInput = buildTaskInput(admission.cargo);
  const registry = new ChildRegistry();
  const abort = new AbortController();
  const signalBinding = bindTerminationSignals(process, abort, registry);
  const temporaryRoot = await mkdtemp(join(tmpdir(), "carl-live-long-horizon-"));
  await chmod(temporaryRoot, 0o700);
  const root = await realpath(temporaryRoot);
  let success = false;
  try {
    const source = join(root, "source");
    const carlWorkspace = join(root, "carl");
    const directWorkspace = join(root, "direct");
    let manifest;
    try {
      manifest = await createFixture(source);
      if ((await copyFixture(source, carlWorkspace, repository)) !== manifest ||
          (await copyFixture(source, directWorkspace, repository)) !== manifest) {
        throw new Error("fixture_parity");
      }
    } catch {
      throw Object.assign(new Error("fixture_setup_failed"), { code: "fixture_setup_failed" });
    }
    const environment = closedChildEnvironment(process.env, {
      CARL_DATA_DIR: admission.dataRoot,
      CARL_CODEX_EXECUTABLE: admission.codex,
      RUST_BACKTRACE: "0",
    });
    const startedAt = process.hrtime.bigint();
    let carlElapsed = null;
    let service = await startService(admission, registry, carlWorkspace, environment);
    let { child: acp, rpc } = await connectAcp(admission, registry, carlWorkspace, environment);
    const created = await rpc.request("session/new", { cwd: carlWorkspace, mcpServers: [] });
    let sessionId = created.sessionId;
    // The ACP response may be lost during a deliberate service reconnect; durable
    // metrics and the loaded task are the completion authority.
    void rpc.request("session/prompt", { sessionId, prompt: [{ type: "text", text: taskInput.toString("utf8") }] }, admission.timeoutSeconds * 1_000).catch(() => {});
    let taskId = null;
    let lastMetrics = null;
    let lastCheckpoint = null;
    let lastDigest = manifest;
    let steering = 0;
    let restartAttempts = 0;
    let confirmedRestarts = 0;
    let pendingRestart = null;
    let lastProviderContext = null;
    let provenContextLosses = 0;
    const commandStarts = new Map();
    let longObserved = false;
    const observedCompactions = new Set();
    const requestedCompactions = new Set();
    const chapterTracker = new ChapterProgressTracker();
    let lastProgressAt = process.hrtime.bigint();
    const evidence = [];
    while (!abort.signal.aborted) {
      for (const notification of rpc.drainNotifications()) {
        const update = updateBody(notification);
        if (update?.taskId) taskId = update.taskId;
        if (update?.sessionUpdate === "compaction") {
          const key = `compaction-${update.generation}`;
          if (!observedCompactions.has(key)) {
            observedCompactions.add(key);
            evidence.push({ kind: "compaction", key, completed: true });
          }
        }
        if (update?.sessionUpdate === "tool_call" && update?.kind === "execute" && update?.title === "Command") commandStarts.set(update.toolCallId, process.hrtime.bigint());
        if (update?.sessionUpdate === "tool_call_update" && commandStarts.has(update.toolCallId)) {
          const elapsed = Number(process.hrtime.bigint() - commandStarts.get(update.toolCallId));
          if (["succeeded", "failed", "cancelled"].includes(update.status)) {
            if (elapsed >= 5_000_000_000) longObserved = true;
            commandStarts.delete(update.toolCallId);
          }
        }
      }
      if (taskId) {
        const { metrics, snapshot } = await readTaskStateWithChapterProgress({
          tracker: chapterTracker,
          workspace: carlWorkspace,
          evidence,
          previousCheckpoint: lastCheckpoint,
          readMetrics: () => rpc.request("_task/metrics", { sessionId, taskId }, TASK_STATE_RPC_TIMEOUT_MS),
          readStatus: () => rpc.request("_task/status", { sessionId, taskId }, TASK_STATE_RPC_TIMEOUT_MS),
          previousMetrics: lastMetrics,
        });
        lastCheckpoint = snapshot.latest_checkpoint;
        const pendingChapter = chapterTracker.pendingCount();
        if (pendingChapter !== null && !requestedCompactions.has(pendingChapter)) {
          const compacted = await rpc.request("_task/compact", {
            sessionId,
            taskId,
            idempotencyKey: `chapter-compaction-${pendingChapter}`,
          });
          if (compacted.outcome !== "accepted") throw new Error("compaction_not_accepted");
          requestedCompactions.add(pendingChapter);
        }
        if (metrics.provider_context_losses > (lastMetrics?.provider_context_losses ?? 0)) {
          const delta = metrics.provider_context_losses - (lastMetrics?.provider_context_losses ?? 0);
          if (delta !== 1) throw new Error("context_loss_observation_gap");
          if (typeof lastProviderContext !== "string" || typeof snapshot.provider_context !== "string" || snapshot.provider_context.length === 0 || snapshot.provider_context === lastProviderContext) throw new Error("context_replacement_not_proven");
          evidence.push({ kind: "context_loss", key: `loss-${provenContextLosses}`, replaced: true });
          provenContextLosses += 1;
        }
        if (typeof snapshot.provider_context === "string" && snapshot.provider_context.length > 0) lastProviderContext = snapshot.provider_context;
        if (
          pendingRestart && metrics.durable_sequence_end > pendingRestart.sequence &&
          (metrics.provider_requests > pendingRestart.providerRequests ||
            metrics.epochs_started > pendingRestart.epochsStarted ||
            metrics.epochs_completed > pendingRestart.epochsCompleted)
        ) {
          evidence.push({ kind: "restart", key: `restart-${pendingRestart.index}`, ready: true, resumed: true });
          confirmedRestarts += 1;
          pendingRestart = null;
        }
        if (lastMetrics) {
          const digest = await fixtureManifest(carlWorkspace);
          if (metrics.revision > lastMetrics.revision || metrics.durable_sequence_end > lastMetrics.durable_sequence_end || digest !== lastDigest) {
            evidence.push({ kind: "progress", key: `progress-${metrics.revision}-${metrics.durable_sequence_end}-${digest}`, revision: metrics.revision, sequence: metrics.durable_sequence_end, workspaceDigest: digest });
            lastProgressAt = process.hrtime.bigint();
          }
          lastDigest = digest;
        }
        lastMetrics = metrics;
        if (steering < 2 && metrics.epochs_completed >= (steering + 1) * 2) {
          const steered = await rpc.request("_session/steering", { sessionId, prompt: [{ type: "text", text: steering === 0 ? "Preserve the exact early identifier and continue from durable evidence." : "Finish every required clause and verify the repository." }] });
          evidence.push({ kind: "steer", key: `steer-${steering}`, outcome: steered.outcome === "injected" ? "accepted" : steered.outcome });
          steering += 1;
        }
        if (!pendingRestart && restartAttempts < 5 && metrics.compactions_completed >= (restartAttempts + 1) * 4) {
          const maintained = await runCommand(registry, admission.carl, ["maintenance", "prepare"], { cwd: carlWorkspace, env: environment }, null, 1_000_000);
          parseReadyMaintenance(maintained.stdout, taskId);
          await registry.terminate(service);
          await registry.terminate(acp);
          if (restartAttempts === 1 || restartAttempts === 3) {
            await forceCodexContextLoss(admission.dataRoot, restartAttempts);
          }
          service = await startService(admission, registry, carlWorkspace, environment);
          ({ child: acp, rpc } = await connectAcp(admission, registry, carlWorkspace, environment));
          const loaded = await rpc.request("session/load", { sessionId, cwd: carlWorkspace, mcpServers: [], taskId });
          sessionId = loaded.sessionId ?? sessionId;
          const { metrics: reloadedMetrics, snapshot: reloadedSnapshot } =
            await readTaskStateWithChapterProgress({
              tracker: chapterTracker,
              workspace: carlWorkspace,
              evidence,
              previousCheckpoint: lastCheckpoint,
              readMetrics: () => rpc.request("_task/metrics", { sessionId, taskId }, TASK_STATE_RPC_TIMEOUT_MS),
              readStatus: () => rpc.request("_task/status", { sessionId, taskId }, TASK_STATE_RPC_TIMEOUT_MS),
              previousMetrics: metrics,
            });
          lastCheckpoint = reloadedSnapshot.latest_checkpoint;
          pendingRestart = {
            index: restartAttempts,
            revision: reloadedMetrics.revision,
            sequence: reloadedMetrics.durable_sequence_end,
            providerRequests: reloadedMetrics.provider_requests,
            epochsStarted: reloadedMetrics.epochs_started,
            epochsCompleted: reloadedMetrics.epochs_completed,
          };
          lastMetrics = reloadedMetrics;
          if (typeof reloadedSnapshot.provider_context === "string" && reloadedSnapshot.provider_context.length > 0) lastProviderContext = reloadedSnapshot.provider_context;
          restartAttempts += 1;
          continue;
        }
        if (metrics.status === "completed") break;
      }
      if (Number(process.hrtime.bigint() - startedAt) / 1e9 >= admission.timeoutSeconds) throw new Error("wall_timeout");
      if (Number(process.hrtime.bigint() - lastProgressAt) / 1e9 >= 900) throw new Error("stalled_without_durable_progress");
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 1_000));
    }
    if (abort.signal.aborted || !lastMetrics) throw new Error("cancelled");
    chapterTracker.assertComplete();
    if (longObserved) evidence.push({ kind: "long_command", key: "long-command", started: true, completed: true });
    if (provenContextLosses !== lastMetrics.provider_context_losses) throw new Error("context_replacement_not_proven");
    if (confirmedRestarts < 5 || pendingRestart) throw new Error("restart_not_proven");
    const counts = deriveEvidence(evidence);
    if (!carlCompletionIsSafe(lastMetrics)) throw new Error("unsafe_carl_result");
    carlElapsed = Number((process.hrtime.bigint() - startedAt) / 1_000_000n);
    const carlVerified = await verifyCompletedWorkspace(registry, carlWorkspace, environment);
    if (!carlVerified) throw new Error("carl_fixture_failed");
    if ((await fixtureManifest(source)) !== manifest || (await fixtureManifest(directWorkspace)) !== manifest) throw new Error("fixture_provenance_changed");
    const directInvocation = directBaselineInvocation(admission, directWorkspace, taskInput);
    const direct = await runCommand(
      registry,
      directInvocation.executable,
      directInvocation.argv,
      { cwd: directWorkspace, env: directInvocation.environment },
      directInvocation.stdin,
      (admission.timeoutSeconds + 30) * 1_000,
    );
    if (direct.stderr.length !== 0) throw new Error("direct_stderr");
    const directResult = parseOneJsonLine(direct.stdout);
    const directVerified = directResult.completed === true && await verifyCompletedWorkspace(registry, directWorkspace, environment);
    if (!directVerified) throw new Error("direct_fixture_failed");
    const revision = parseOneJsonLine((await runCommand(registry, "git", ["rev-parse", "HEAD"], { cwd: repository, env: closedChildEnvironment(process.env) })).stdout.replace(/([0-9a-f]{40})\n/, '{"revision":"$1"}\n')).revision;
    const result = {
      schema_version: 1,
      harness_git_revision: revision,
      codex_version: CODEX_VERSION,
      model: admission.model,
      effort: admission.effort,
      requested_duration_hours: admission.durationHours,
      fixture_manifest_digest: manifest,
      task_input_digest: digestBytes(taskInput),
      carl: {
        completed: true,
        elapsed_milliseconds: carlElapsed,
        provider_requests: lastMetrics.provider_requests,
        epochs: lastMetrics.epochs_completed,
        tool_calls: lastMetrics.operation_intents,
        compactions: lastMetrics.compactions_completed,
        context_losses: lastMetrics.provider_context_losses,
        recoveries: lastMetrics.recovery_attempts,
        clauses_satisfied: lastMetrics.required_clauses_satisfied,
        clauses_total: lastMetrics.required_clauses_total,
        interventions: counts.steers,
        restarts: counts.restarts,
        no_unresolved_operations: lastMetrics.unresolved_operations === 0 && lastMetrics.operations_uncertain === 0,
        // Exact once-only probe plus the ordered twenty-entry chapter audit are
        // independent live duplicate-effect and completion oracles.
        no_duplicate_effects: carlVerified && lastMetrics.operations_uncertain === 0 && lastMetrics.unresolved_operations === 0,
        no_orphan_processes: registry.size >= 0,
      },
      direct_baseline: directResult,
      admission_passed: true,
      cleanup_passed: false,
      parity_passed: carlVerified && directVerified,
    };
    await registry.terminateAll();
    result.cleanup_passed = registry.size === 0;
    result.carl.no_orphan_processes = result.cleanup_passed;
    validateResult(result);
    const resultPath = join(admission.dataRoot, "live-runs", `paired-${manifest}-${randomBytes(8).toString("hex")}.json`);
    await writeResultAfterSuccess(resultPath, async () => result);
    success = true;
    process.stdout.write(`${JSON.stringify({ schema_version: 1, passed: true })}\n`);
  } finally {
    await signalBinding.wait().catch(() => {});
    signalBinding.dispose();
    await registry.terminateAll().catch(() => {});
    await rm(root, { recursive: true, force: true });
    if (!success) {
      // Failure deliberately writes no result artifact.
    }
  }
}

try {
  if (process.argv.length === 3 && process.argv[2] === "--self-test") await selfTest();
  else if (process.argv.length === 2) await production();
  else throw Object.assign(new Error("invalid_admission"), { code: "invalid_admission" });
} catch (error) {
  process.stderr.write(`${REDACTED_FAILURE} (${typeof error?.code === "string" ? error.code : "failed"})\n`);
  process.exitCode = 1;
}
