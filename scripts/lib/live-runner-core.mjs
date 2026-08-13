import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

export const RESULT_LIMIT_BYTES = 16 * 1024;
export const PROMPT_LIMIT_BYTES = 16 * 1024;
export const CODEX_VERSION = "0.146.0";
export const SUPPORTED_EFFORTS = new Set(["low", "medium", "high", "xhigh", "max", "ultra"]);

const CHILD_ENV_ALLOWLIST = new Set([
  "HOME",
  "LANG",
  "LC_ALL",
  "PATH",
  "SHELL",
  "TERM",
  "TMPDIR",
  "TZ",
  "USER",
]);

const CHILD_OVERRIDE_ALLOWLIST = new Set([
  "CARL_DATA_DIR",
  "CARL_CODEX_EXECUTABLE",
  "RUST_BACKTRACE",
]);

const TASK_STATUSES = new Set([
  "queued", "active", "checkpointing", "paused", "blocked", "cancelling",
  "cancelled", "completing", "completed", "failed",
]);
const METRICS_KEYS = Object.freeze([
  "schema_version", "task_id", "status", "revision", "durable_event_count",
  "durable_sequence_end", "provider_requests", "epochs_started", "epochs_completed",
  "operation_intents", "operations_succeeded", "operations_failed",
  "operations_cancelled", "operations_uncertain", "unresolved_operations",
  "compactions_completed", "provider_context_losses", "recovery_attempts",
  "latest_observed_tokens", "latest_context_window", "required_clauses_total",
  "required_clauses_satisfied", "budget",
]);
const MONOTONIC_METRICS = Object.freeze(METRICS_KEYS.filter((key) => ![
  "schema_version", "task_id", "status", "latest_observed_tokens",
  "latest_context_window", "budget", "unresolved_operations", "required_clauses_total",
].includes(key)));
const BUDGET_KEYS = Object.freeze([
  "max_wall_time_seconds", "max_provider_requests", "max_tool_calls",
  "soft_epoch_seconds", "soft_epoch_tool_calls",
]);
const SNAPSHOT_KEYS = Object.freeze([
  "task_id", "session_id", "status", "contract", "budget", "active_epoch",
  "latest_checkpoint", "provider_context", "revision", "operations", "pending_recovery",
]);
const CONTRACT_KEYS = Object.freeze(["version", "goal", "constraints", "clauses"]);
const CLAUSE_KEYS = Object.freeze(["id", "description", "required", "status", "evidence"]);
const EVIDENCE_KEYS = Object.freeze(["event_sequence", "artifact_digest", "operation_id"]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function closedChildEnvironment(source, overrides = {}) {
  const output = {};
  for (const [name, value] of Object.entries(source)) {
    if (CHILD_ENV_ALLOWLIST.has(name) && typeof value === "string") output[name] = value;
  }
  for (const [name, value] of Object.entries(overrides)) {
    if (typeof value !== "string" || !CHILD_OVERRIDE_ALLOWLIST.has(name)) {
      throw coded("invalid_environment");
    }
    output[name] = value;
  }
  return output;
}

export function assertNoApiKeyMode(source) {
  for (const name of Object.keys(source)) {
    if (name.endsWith("_API_KEY") || name === "OPENAI_API_KEY" || name === "CODEX_API_KEY" || name === "AZURE_OPENAI_API_KEY") {
      throw coded("api_key_mode_refused");
    }
  }
}

async function canonicalRegularExecutable(path, code) {
  if (!isAbsolute(path)) throw coded(code);
  const before = await lstat(path).catch(() => null);
  if (!before?.isFile() || before.isSymbolicLink() || (before.mode & 0o111) === 0) throw coded(code);
  const canonical = await realpath(path).catch(() => null);
  if (canonical !== path) throw coded(code);
  return canonical;
}

async function canonicalPrivateDirectory(path, code) {
  if (!isAbsolute(path)) throw coded(code);
  const before = await lstat(path).catch(() => null);
  if (!before?.isDirectory() || before.isSymbolicLink() || (before.mode & 0o077) !== 0) throw coded(code);
  if (typeof process.getuid === "function" && before.uid !== process.getuid()) throw coded(code);
  const canonical = await realpath(path).catch(() => null);
  if (canonical !== path) throw coded(code);
  return canonical;
}

function ownerPrivate(info) {
  return (info.mode & 0o077) === 0 &&
    (typeof process.getuid !== "function" || info.uid === process.getuid());
}

export async function admitProduction(environment, repository) {
  assertNoApiKeyMode(environment);
  const durationText = environment.CARL_LIVE_DURATION_HOURS ?? "4";
  if (!/^[0-9]+$/.test(durationText)) throw coded("invalid_duration");
  const durationHours = Number(durationText);
  if (!Number.isSafeInteger(durationHours) || durationHours < 2 || durationHours > 8) throw coded("invalid_duration");
  const model = environment.CARL_LIVE_MODEL;
  const effort = environment.CARL_LIVE_EFFORT;
  if (!model || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(model) || !SUPPORTED_EFFORTS.has(effort)) throw coded("invalid_model_selection");
  const dataRoot = await canonicalPrivateDirectory(environment.CARL_DATA_DIR, "invalid_data_root");
  const carl = await canonicalRegularExecutable(environment.CARL_BIN, "invalid_carl_binary");
  const codex = await canonicalRegularExecutable(environment.CARL_CODEX_EXECUTABLE, "invalid_codex_binary");
  const cargo = await canonicalRegularExecutable(
    environment.CARL_LIVE_CARGO_EXECUTABLE,
    "invalid_cargo_binary",
  );
  if (!carl.endsWith(`${sep}target${sep}release${sep}carl`)) throw coded("invalid_carl_binary");
  const canonicalRepository = await realpath(repository);
  return { carl, codex, cargo, dataRoot, repository: canonicalRepository, model, effort, durationHours, timeoutSeconds: durationHours * 3600 };
}

export async function forceCodexContextLoss(dataRoot, lossIndex) {
  if (!Number.isSafeInteger(lossIndex) || lossIndex < 0 || lossIndex > 4) {
    throw coded("invalid_provider_state");
  }
  const root = await canonicalPrivateDirectory(dataRoot, "invalid_data_root");
  const providerRoot = await canonicalPrivateDirectory(
    join(root, "providers", "codex"),
    "invalid_provider_state",
  );
  const names = ["state_5.sqlite", "state_5.sqlite-shm", "state_5.sqlite-wal"];
  const primary = await lstat(join(providerRoot, names[0])).catch(() => null);
  if (!primary?.isFile() || primary.isSymbolicLink() || !ownerPrivate(primary)) {
    throw coded("invalid_provider_state");
  }
  const sessions = await canonicalPrivateDirectory(
    join(providerRoot, "sessions"),
    "invalid_provider_state",
  );
  const stack = [sessions];
  let entries = 0;
  while (stack.length > 0) {
    const directory = stack.pop();
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      entries += 1;
      if (entries > 256) throw coded("invalid_provider_state");
      const path = join(directory, entry.name);
      const info = await lstat(path);
      if (info.isSymbolicLink() || !ownerPrivate(info)) throw coded("invalid_provider_state");
      if (info.isDirectory()) {
        if (!/^\d{2,4}$/.test(entry.name)) throw coded("invalid_provider_state");
        stack.push(path);
      } else if (!info.isFile() || !/^rollout-[A-Za-z0-9._:-]+\.jsonl$/.test(entry.name)) {
        throw coded("invalid_provider_state");
      }
    }
  }
  if (entries === 0) throw coded("invalid_provider_state");
  const quarantine = join(providerRoot, "context-loss-fixtures");
  await mkdir(quarantine, { mode: 0o700 }).catch((error) => {
    if (error?.code !== "EEXIST") throw error;
  });
  await canonicalPrivateDirectory(quarantine, "invalid_provider_state");
  const destination = join(quarantine, `loss-${lossIndex}`);
  await mkdir(destination, { mode: 0o700 });
  await rename(sessions, join(destination, "sessions"));
  for (const name of names) {
    const path = join(providerRoot, name);
    const info = await lstat(path).catch(() => null);
    if (info === null) continue;
    if (!info.isFile() || info.isSymbolicLink() || !ownerPrivate(info)) {
      throw coded("invalid_provider_state");
    }
    await rename(path, join(destination, name));
  }
}

const AUDIT_CHAPTERS = Object.fromEntries(Array.from({ length: 20 }, (_, index) => {
  const number = String(index + 1).padStart(2, "0");
  const line = `audit_${number}: preserve exact parsing semantics and needle_7f3a91c2 evidence.\n`;
  return [`audit/chapter_${number}.txt`, line.repeat(14_400)];
}));

export const FIXTURE_FILES = Object.freeze({
  "Cargo.toml": `[package]\nname = "carl-endurance-fixture"\nversion = "0.1.0"\nedition = "2024"\n\n[lib]\npath = "src/lib.rs"\n`,
  "README.md": `# Endurance fixture\n\nThis crate parses exact non-negative counts.\n`,
  "src/lib.rs": `mod parser;\npub use parser::parse_count;\npub const EARLY_IDENTIFIER: &str = "needle_7f3a91c2";\n`,
  "src/parser.rs": `pub fn parse_count(value: &str) -> Result<u64, std::num::ParseIntError> {\n    value.trim().parse()\n}\n`,
  "src/bin/once_probe.rs": `use std::fs::OpenOptions;\nuse std::io::Write as _;\n\nfn main() {\n    OpenOptions::new().create(true).append(true).open(".once-probe").unwrap().write_all(b"once\\n").unwrap();\n}\n`,
  "tests/regression.rs": `use carl_endurance_fixture::{parse_count, EARLY_IDENTIFIER};\n\n#[test]\nfn rejects_surrounding_whitespace_and_retains_identifier() {\n    std::thread::sleep(std::time::Duration::from_secs(6));\n    assert!(parse_count(" 7 ").is_err());\n    assert_eq!(EARLY_IDENTIFIER, "needle_7f3a91c2");\n}\n`,
  ...AUDIT_CHAPTERS,
});

export async function createFixture(root) {
  await mkdir(root, { recursive: false, mode: 0o700 });
  await chmod(root, 0o700);
  for (const [name, contents] of Object.entries(FIXTURE_FILES)) {
    const path = join(root, name);
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    await writeFile(path, contents, { mode: 0o600, flag: "wx" });
  }
  return fixtureManifest(root);
}

export async function copyFixture(source, destination, repository) {
  assertOutsideRepository(destination, repository);
  await validateFixture(source, repository);
  await mkdir(destination, { recursive: false, mode: 0o700 });
  for (const name of Object.keys(FIXTURE_FILES)) {
    const target = join(destination, name);
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    await writeFile(target, await readFile(join(source, name)), { mode: 0o600, flag: "wx" });
  }
  const digest = await fixtureManifest(destination);
  return digest;
}

export async function validateFixture(root, repository) {
  assertOutsideRepository(root, repository);
  const rootInfo = await lstat(root).catch(() => null);
  if (!rootInfo?.isDirectory() || rootInfo.isSymbolicLink() || !ownerPrivate(rootInfo)) throw coded("invalid_fixture");
  const expected = new Set(Object.keys(FIXTURE_FILES));
  for (const name of expected) {
    const info = await lstat(join(root, name)).catch(() => null);
    if (!info?.isFile() || info.isSymbolicLink() || !ownerPrivate(info)) throw coded("invalid_fixture");
  }
  const { readdir } = await import("node:fs/promises");
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const rel = relative(root, path).split(sep).join("/");
      if (entry.isSymbolicLink() || (!entry.isDirectory() && !entry.isFile())) throw coded("invalid_fixture");
      const info = await lstat(path);
      if (!ownerPrivate(info)) throw coded("invalid_fixture");
      if (entry.isDirectory()) await walk(path);
      else if (!expected.delete(rel)) throw coded("invalid_fixture");
    }
  }
  await walk(root);
  if (expected.size !== 0) throw coded("invalid_fixture");
}

export async function fixtureManifest(root) {
  const hash = createHash("sha256");
  for (const name of Object.keys(FIXTURE_FILES).sort()) {
    const bytes = await readFile(join(root, name));
    hash.update(Buffer.from(name));
    hash.update(Buffer.from([0]));
    hash.update(bytes);
    hash.update(Buffer.from([0]));
  }
  return hash.digest("hex");
}

export function digestBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

export function carlAcpInvocation(admission, workspace) {
  assertOutsideRepository(workspace, admission.repository);
  return {
    executable: admission.carl,
    argv: [
      "acp",
      "--model", admission.model,
      "--effort", admission.effort,
      "--dangerously-bypass-permissions",
      "--max-wall-time-seconds", String(admission.timeoutSeconds),
      "--max-provider-requests", "10000",
      "--max-tool-calls", "100000",
      "--soft-epoch-seconds", "900",
      "--soft-epoch-tool-calls", "6",
    ],
    environment: closedChildEnvironment(process.env, {
      CARL_DATA_DIR: admission.dataRoot,
      CARL_CODEX_EXECUTABLE: admission.codex,
    }),
  };
}

export function directBaselineInvocation(admission, workspace, prompt) {
  assertOutsideRepository(workspace, admission.repository);
  if (!Buffer.isBuffer(prompt) || prompt.length === 0 || prompt.length > PROMPT_LIMIT_BYTES) throw coded("invalid_prompt");
  return {
    executable: admission.carl,
    argv: [
      "baseline", "codex",
      "--workspace", workspace,
      "--model", admission.model,
      "--effort", admission.effort,
      "--timeout-seconds", String(admission.timeoutSeconds),
    ],
    environment: closedChildEnvironment(process.env, {
      CARL_DATA_DIR: admission.dataRoot,
      CARL_CODEX_EXECUTABLE: admission.codex,
    }),
    stdin: prompt,
  };
}

export async function workspaceManifest(root) {
  const rootInfo = await lstat(root).catch(() => null);
  if (!rootInfo?.isDirectory() || rootInfo.isSymbolicLink()) throw coded("invalid_fixture");
  const entries = [];
  const { readdir } = await import("node:fs/promises");
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink() || (!entry.isDirectory() && !entry.isFile())) throw coded("invalid_fixture");
      if (entry.isDirectory()) await walk(path);
      else entries.push(relative(root, path).split(sep).join("/"));
    }
  }
  await walk(root);
  const hash = createHash("sha256");
  for (const name of entries.sort()) {
    hash.update(Buffer.from(name));
    hash.update(Buffer.from([0]));
    hash.update(await readFile(join(root, name)));
    hash.update(Buffer.from([0]));
  }
  return hash.digest("hex");
}

export function assertOutsideRepository(path, repository) {
  const candidate = resolve(path);
  const repo = resolve(repository);
  if (candidate === repo || candidate.startsWith(`${repo}${sep}`)) throw coded("active_repository_refused");
}

export function deriveEvidence(events) {
  let revision = -1;
  let durableSequence = -1;
  let workspaceDigest = null;
  const seen = new Set();
  const counts = { steers: 0, restarts: 0, compactions: 0, contextLosses: 0, longCommands: 0, progressIntervals: 0, chapters: 0 };
  for (const event of events) {
    if (!event || typeof event !== "object" || typeof event.kind !== "string") throw coded("invalid_evidence");
    if (event.key && seen.has(event.key)) throw coded("duplicate_evidence");
    if (event.key) seen.add(event.key);
    if (event.revision != null && (!Number.isSafeInteger(event.revision) || event.revision < revision)) throw coded("regressing_evidence");
    if (event.sequence != null && (!Number.isSafeInteger(event.sequence) || event.sequence < durableSequence)) throw coded("regressing_evidence");
    if (event.kind === "progress") {
      const advanced =
        (event.revision != null && event.revision > revision) ||
        (event.sequence != null && event.sequence > durableSequence) ||
        (typeof event.workspaceDigest === "string" && /^[0-9a-f]{64}$/.test(event.workspaceDigest) && event.workspaceDigest !== workspaceDigest);
      if (!advanced) throw coded("stale_progress");
      workspaceDigest = event.workspaceDigest ?? workspaceDigest;
      counts.progressIntervals += 1;
    } else if (event.kind === "steer" && event.outcome === "accepted") counts.steers += 1;
    else if (event.kind === "restart" && event.ready === true && event.resumed === true) counts.restarts += 1;
    else if (event.kind === "compaction" && event.completed === true) counts.compactions += 1;
    else if (event.kind === "context_loss" && event.replaced === true) counts.contextLosses += 1;
    else if (event.kind === "long_command" && event.started === true && event.completed === true) counts.longCommands += 1;
    else if (event.kind === "chapter" && event.completed === true) counts.chapters += 1;
    else if (["steer", "restart", "compaction", "context_loss", "long_command", "chapter"].includes(event.kind)) throw coded("failed_evidence");
    else if (event.kind !== "progress") throw coded("invalid_evidence");
    if (event.revision != null) revision = event.revision;
    if (event.sequence != null) durableSequence = event.sequence;
  }
  if (counts.steers !== 2 || counts.restarts < 5 || counts.compactions < 20 || counts.contextLosses < 2 || counts.longCommands < 1 || counts.progressIntervals < 1 || counts.chapters !== 20) throw coded("insufficient_evidence");
  return counts;
}

export class ChapterProgressTracker {
  #proven = 0;
  #pending = null;

  observe(audit, latestCheckpoint) {
    if (typeof audit !== "string" || !(latestCheckpoint === null || UUID.test(latestCheckpoint))) throw coded("invalid_chapter_audit");
    const lines = audit === "" ? [] : audit.split("\n").slice(0, -1);
    if (audit !== (lines.length === 0 ? "" : `${lines.join("\n")}\n`) || lines.length > 20) throw coded("invalid_chapter_audit");
    for (let index = 0; index < lines.length; index += 1) {
      if (lines[index] !== `chapter_${String(index + 1).padStart(2, "0")}`) throw coded("invalid_chapter_audit");
    }
    if (lines.length > this.#proven) {
      if (this.#pending === null) {
        if (lines.length !== this.#proven + 1) throw coded("chapter_progress_batched");
        this.#pending = { count: lines.length, checkpoint: latestCheckpoint };
      } else if (lines.length !== this.#pending.count) {
        throw coded("chapter_progress_batched");
      }
    }
    if (this.#pending && latestCheckpoint !== null && latestCheckpoint !== this.#pending.checkpoint) {
      this.#proven = this.#pending.count;
      this.#pending = null;
      return this.#proven;
    }
    return null;
  }

  pendingCount() {
    return this.#pending?.count ?? null;
  }

  assertComplete() {
    if (this.#proven !== 20 || this.#pending !== null) throw coded("chapter_checkpoints_not_proven");
  }
}

function exactObject(value, keys, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw coded(code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw coded(code);
}

function nonnegativeSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function nullablePositiveSafeInteger(value) {
  return value === null || (Number.isSafeInteger(value) && value > 0);
}

function validateBudget(value, code) {
  exactObject(value, BUDGET_KEYS, code);
  if (
    !nullablePositiveSafeInteger(value.max_wall_time_seconds) ||
    !nullablePositiveSafeInteger(value.max_provider_requests) ||
    !nullablePositiveSafeInteger(value.max_tool_calls) ||
    !Number.isSafeInteger(value.soft_epoch_seconds) || value.soft_epoch_seconds <= 0 ||
    !Number.isSafeInteger(value.soft_epoch_tool_calls) || value.soft_epoch_tool_calls <= 0
  ) throw coded(code);
}

export function validateMetricsResponse(response, previous = null) {
  exactObject(response, ["metrics"], "invalid_metrics");
  const metrics = response.metrics;
  exactObject(metrics, METRICS_KEYS, "invalid_metrics");
  if (
    metrics.schema_version !== 1 || !UUID.test(metrics.task_id) ||
    !TASK_STATUSES.has(metrics.status) ||
    !METRICS_KEYS.filter((key) => ![
      "schema_version", "task_id", "status", "latest_observed_tokens",
      "latest_context_window", "budget",
    ].includes(key)).every((key) => nonnegativeSafeInteger(metrics[key])) ||
    ![metrics.latest_observed_tokens, metrics.latest_context_window].every(
      (value) => value === null || nonnegativeSafeInteger(value),
    ) ||
    metrics.required_clauses_satisfied > metrics.required_clauses_total ||
    metrics.epochs_completed > metrics.epochs_started
  ) throw coded("invalid_metrics");
  validateBudget(metrics.budget, "invalid_metrics");
  if (previous !== null) {
    exactObject(previous, METRICS_KEYS, "invalid_metrics");
    if (
      previous.task_id !== metrics.task_id ||
      JSON.stringify(previous.budget) !== JSON.stringify(metrics.budget) ||
      previous.required_clauses_total !== metrics.required_clauses_total ||
      MONOTONIC_METRICS.some((key) => metrics[key] < previous[key])
    ) throw coded("regressing_metrics");
  }
  return metrics;
}

export function validateStatusResponse(response, metrics = null) {
  exactObject(response, ["task"], "invalid_status");
  const snapshot = response.task;
  exactObject(snapshot, SNAPSHOT_KEYS, "invalid_status");
  if (
    !UUID.test(snapshot.task_id) || !UUID.test(snapshot.session_id) ||
    !TASK_STATUSES.has(snapshot.status) || !nonnegativeSafeInteger(snapshot.revision) ||
    ![snapshot.active_epoch, snapshot.latest_checkpoint].every((value) => value === null || UUID.test(value)) ||
    !(snapshot.provider_context === null || (typeof snapshot.provider_context === "string" && snapshot.provider_context.length > 0 && snapshot.provider_context.length <= 4096)) ||
    !snapshot.operations || typeof snapshot.operations !== "object" || Array.isArray(snapshot.operations) ||
    !(snapshot.pending_recovery === null || Array.isArray(snapshot.pending_recovery))
  ) throw coded("invalid_status");
  validateBudget(snapshot.budget, "invalid_status");
  if (metrics !== null && (
    snapshot.task_id !== metrics.task_id || snapshot.status !== metrics.status ||
    snapshot.revision !== metrics.revision ||
    JSON.stringify(snapshot.budget) !== JSON.stringify(metrics.budget)
  )) throw coded("invalid_status");
  exactObject(snapshot.contract, CONTRACT_KEYS, "invalid_status");
  const contract = snapshot.contract;
  if (
    !Number.isSafeInteger(contract.version) || contract.version <= 0 ||
    typeof contract.goal !== "string" || contract.goal.length === 0 ||
    !Array.isArray(contract.constraints) || contract.constraints.some((value) => typeof value !== "string") ||
    !Array.isArray(contract.clauses)
  ) throw coded("invalid_status");
  let required = 0;
  let satisfied = 0;
  const ids = new Set();
  for (const clause of contract.clauses) {
    exactObject(clause, CLAUSE_KEYS, "invalid_status");
    if (
      typeof clause.id !== "string" || clause.id.length === 0 || ids.has(clause.id) ||
      typeof clause.description !== "string" || typeof clause.required !== "boolean" ||
      !["pending", "satisfied", "failed"].includes(clause.status) || !Array.isArray(clause.evidence)
    ) throw coded("invalid_status");
    ids.add(clause.id);
    for (const evidence of clause.evidence) {
      exactObject(evidence, EVIDENCE_KEYS, "invalid_status");
      if (
        !Number.isSafeInteger(evidence.event_sequence) || evidence.event_sequence <= 0 ||
        !(evidence.artifact_digest === null || (typeof evidence.artifact_digest === "string" && evidence.artifact_digest.length > 0)) ||
        !(evidence.operation_id === null || UUID.test(evidence.operation_id))
      ) throw coded("invalid_status");
    }
    if (clause.required) {
      required += 1;
      if (clause.status === "satisfied" && clause.evidence.length > 0) satisfied += 1;
    }
  }
  if (metrics !== null && (
    required !== metrics.required_clauses_total || satisfied !== metrics.required_clauses_satisfied
  )) throw coded("invalid_status");
  return snapshot;
}

export async function readConsistentTaskState(readMetrics, readStatus, previous = null, attempts = 8) {
  if (typeof readMetrics !== "function" || typeof readStatus !== "function" ||
      !Number.isSafeInteger(attempts) || attempts <= 0 || attempts > 32) {
    throw coded("invalid_status_reader");
  }
  let floor = previous;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const before = validateMetricsResponse(await readMetrics(), floor);
    const response = await readStatus();
    const snapshot = validateStatusResponse(response);
    const after = validateMetricsResponse(await readMetrics(), before);
    if (snapshot.task_id !== after.task_id || snapshot.revision > after.revision) {
      throw coded("invalid_status");
    }
    if (snapshot.revision < before.revision) {
      floor = after;
      continue;
    }
    if (snapshot.revision === after.revision) {
      return { metrics: after, snapshot: validateStatusResponse(response, after) };
    }
    floor = after;
  }
  throw coded("unstable_status");
}

export function parseReadyMaintenance(stdout, expectedTaskId = null) {
  const status = parseOneJsonLine(stdout, ["schema_version", "phase", "task_id", "checkpoint_id"]);
  if (
    status.schema_version !== 1 || status.phase !== "ready" ||
    !(status.task_id === null || UUID.test(status.task_id)) ||
    !(status.checkpoint_id === null || UUID.test(status.checkpoint_id)) ||
    (status.task_id === null) !== (status.checkpoint_id === null) ||
    (expectedTaskId !== null && (status.task_id !== expectedTaskId || status.checkpoint_id === null))
  ) throw coded("maintenance_not_ready");
  return status;
}

const DIRECT_KEYS = Object.freeze([
  "schema_version", "provider", "codex_version", "model", "effort", "completed",
  "elapsed_milliseconds", "input_tokens", "cached_input_tokens", "output_tokens",
  "command_executions", "file_changes", "mcp_tool_calls", "web_searches", "compatibility_events",
]);
const RESULT_KEYS = Object.freeze([
  "schema_version", "harness_git_revision", "codex_version", "model", "effort", "requested_duration_hours",
  "fixture_manifest_digest", "task_input_digest", "carl", "direct_baseline", "admission_passed", "cleanup_passed", "parity_passed",
]);
const CARL_KEYS = Object.freeze([
  "completed", "elapsed_milliseconds", "provider_requests", "epochs", "tool_calls", "compactions", "context_losses",
  "recoveries", "clauses_satisfied", "clauses_total", "interventions", "restarts", "no_unresolved_operations",
  "no_duplicate_effects", "no_orphan_processes",
]);

function exactKeys(value, keys, code = "invalid_result") {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw coded(code);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw coded(code);
}

function safeCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

export function validateResult(result) {
  exactKeys(result, RESULT_KEYS);
  exactKeys(result.carl, CARL_KEYS);
  exactKeys(result.direct_baseline, DIRECT_KEYS);
  if (
    result.schema_version !== 1 || result.codex_version !== CODEX_VERSION ||
    !/^[0-9a-f]{40}$/.test(result.harness_git_revision) ||
    !/^[0-9a-f]{64}$/.test(result.fixture_manifest_digest) ||
    !/^[0-9a-f]{64}$/.test(result.task_input_digest) ||
    typeof result.model !== "string" || !SUPPORTED_EFFORTS.has(result.effort) ||
    !Number.isInteger(result.requested_duration_hours) || result.requested_duration_hours < 2 || result.requested_duration_hours > 8 ||
    ![result.admission_passed, result.cleanup_passed, result.parity_passed].every((value) => value === true)
  ) throw coded("invalid_result");
  for (const [key, value] of Object.entries(result.carl)) {
    if (key === "completed" || key.startsWith("no_")) {
      if (typeof value !== "boolean") throw coded("invalid_result");
    } else if (!safeCount(value)) throw coded("invalid_result");
  }
  if (!result.carl.completed || !result.carl.no_unresolved_operations || !result.carl.no_duplicate_effects || !result.carl.no_orphan_processes || result.carl.compactions < 20 || result.carl.context_losses < 2 || result.carl.interventions !== 2 || result.carl.restarts < 5 || result.carl.clauses_total < 5 || result.carl.clauses_satisfied !== result.carl.clauses_total) throw coded("invalid_result");
  if (result.direct_baseline.schema_version !== 1 || result.direct_baseline.provider !== "codex" || result.direct_baseline.codex_version !== CODEX_VERSION || result.direct_baseline.model !== result.model || result.direct_baseline.effort !== result.effort || result.direct_baseline.completed !== true) throw coded("invalid_result");
  for (const [key, value] of Object.entries(result.direct_baseline)) {
    if (!["schema_version", "provider", "codex_version", "model", "effort", "completed"].includes(key) && !safeCount(value)) throw coded("invalid_result");
  }
  const bytes = Buffer.from(`${JSON.stringify(result)}\n`);
  if (bytes.length >= RESULT_LIMIT_BYTES) throw coded("result_too_large");
  const forbidden = [/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i, /(?:^|[" ])\/(?:Users|home|tmp|private)\//, /[A-Z]:\\Users\\/i, /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i, /(?:sk-|Bearer\s)[A-Za-z0-9_-]+/i, /needle_7f3a91c2/, /(?:diff --git|@@ -|cargo (?:test|fmt))/];
  const encoded = bytes.toString("utf8");
  if (forbidden.some((pattern) => pattern.test(encoded))) throw coded("result_not_sanitized");
  return bytes;
}

export async function atomicWriteResult(path, result) {
  const bytes = validateResult(result);
  const parent = dirname(path);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const parentInfo = await lstat(parent);
  if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink() || !ownerPrivate(parentInfo)) throw coded("unsafe_artifact");
  const temporary = `${path}.tmp-${process.pid}`;
  try {
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, path);
    await chmod(path, 0o600);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

export async function writeResultAfterSuccess(path, operation) {
  const result = await operation();
  await atomicWriteResult(path, result);
  return result;
}

export function parseOneJsonLine(stdout, expectedKeys = null) {
  if (typeof stdout !== "string" || !stdout.endsWith("\n") || stdout.slice(0, -1).includes("\n")) throw coded("malformed_child_json");
  let value;
  try { value = JSON.parse(stdout); } catch { throw coded("malformed_child_json"); }
  if (expectedKeys) exactKeys(value, expectedKeys, "malformed_child_json");
  return value;
}

export function coded(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

export async function assertPrivateFile(path) {
  const info = await stat(path);
  if (!info.isFile() || (info.mode & 0o077) !== 0) throw coded("unsafe_artifact");
}

export class ChildRegistry {
  #children = new Set();
  #terminations = new Set();

  track(child) {
    if (!child || typeof child.kill !== "function") throw coded("invalid_child");
    this.#children.add(child);
    child.once("exit", () => this.#children.delete(child));
    return child;
  }

  get size() {
    return this.#children.size;
  }

  terminate(child, graceMilliseconds = 1_000) {
    const termination = (async () => {
      await signalTree(child, "SIGTERM");
      if (child.exitCode === null && child.signalCode === null) {
        await Promise.race([
          new Promise((resolveExit) => child.once("exit", resolveExit)),
          new Promise((resolveDelay) => setTimeout(resolveDelay, graceMilliseconds)),
        ]);
      }
      await signalTree(child, "SIGKILL");
      if (child.exitCode === null && child.signalCode === null) {
        const exited = await Promise.race([
          new Promise((resolveExit) => child.once("exit", () => resolveExit(true))),
          new Promise((resolveDelay) => setTimeout(() => resolveDelay(false), Math.max(1, graceMilliseconds))),
        ]);
        if (!exited) throw coded("child_leak");
      }
    })();
    this.#terminations.add(termination);
    void termination.then(
      () => this.#terminations.delete(termination),
      () => this.#terminations.delete(termination),
    );
    return termination;
  }

  async terminateAll(graceMilliseconds = 1_000) {
    await Promise.all([...this.#terminations]);
    const children = [...this.#children];
    await Promise.all(children.map((child) => this.terminate(child, graceMilliseconds)));
    await Promise.all([...this.#terminations]);
    if (this.#children.size !== 0) throw coded("child_leak");
  }
}

export function bindTerminationSignals(source, abortController, registry) {
  let termination = null;
  const handlers = new Map();
  for (const signal of ["SIGINT", "SIGTERM"]) {
    const handler = () => {
      abortController.abort();
      termination ??= registry.terminateAll();
      void termination.catch(() => {});
    };
    handlers.set(signal, handler);
    source.once(signal, handler);
  }
  return {
    wait: () => termination ?? Promise.resolve(),
    dispose: () => {
      for (const [signal, handler] of handlers) source.removeListener(signal, handler);
    },
  };
}

async function signalTree(child, signal) {
  if (process.platform === "win32" && Number.isSafeInteger(child.pid)) {
    await new Promise((resolveTaskkill) => {
      const killer = spawn("C:\\Windows\\System32\\taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
      });
      killer.once("error", resolveTaskkill);
      killer.once("exit", resolveTaskkill);
    });
    return;
  }
  if (process.platform !== "win32" && Number.isSafeInteger(child.pid)) {
    try {
      process.kill(-child.pid, signal);
      return;
    } catch (error) {
      if (error?.code !== "ESRCH") throw error;
    }
  }
  child.kill(signal);
}
