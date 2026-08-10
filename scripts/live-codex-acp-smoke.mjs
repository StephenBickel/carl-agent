#!/usr/bin/env node

// Opt-in local smoke test. Public CI never runs this file. It stores only boolean
// pass/fail metadata under a disposable directory and never stores provider output.

import { spawn } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, realpath, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { createInterface } from "node:readline";

const repository = resolve(import.meta.dirname, "..");
const executable = resolve(process.env.CARL_BIN ?? join(repository, "target/release/carl"));
const codex = process.env.CARL_CODEX_EXECUTABLE;
const dataRoot = process.env.CARL_DATA_DIR;
const model = process.env.CARL_LIVE_MODEL ?? "gpt-5.6-terra";
const effort = process.env.CARL_LIVE_EFFORT ?? "low";

if (!codex || !dataRoot || !isAbsolute(codex) || !isAbsolute(dataRoot)) {
  throw new Error("CARL_DATA_DIR and CARL_CODEX_EXECUTABLE must be absolute paths");
}

const tempRoot = await mkdtemp(join(tmpdir(), "carl-live-codex-"));
const workspace = join(tempRoot, "workspace");
const metadataPath = join(tempRoot, "live-smoke.json");
await mkdir(workspace, { mode: 0o700 });
const canonicalWorkspace = await realpath(workspace);
await chmod(tempRoot, 0o700);
await writeFile(join(canonicalWorkspace, "target.txt"), "broken\n", { mode: 0o600 });

const environment = { ...process.env };
for (const name of Object.keys(environment)) {
  if (
    name === "OPENAI_API_KEY" ||
    name === "CODEX_API_KEY" ||
    name === "AZURE_OPENAI_API_KEY" ||
    name.startsWith("BUZZ_") ||
    name.startsWith("XAI_")
  ) {
    delete environment[name];
  }
}
environment.CARL_DATA_DIR = dataRoot;
environment.CARL_CODEX_EXECUTABLE = codex;

const child = spawn(
  executable,
  ["acp", "--model", model, "--effort", effort, "--permission-mode", "default"],
  { cwd: canonicalWorkspace, env: environment, stdio: ["pipe", "pipe", "pipe"] },
);
const exited = new Promise((resolveExit) => child.once("exit", resolveExit));

let nextId = 1;
let stderrBytes = 0;
const pending = new Map();
const notifications = [];

child.stderr.on("data", (chunk) => {
  stderrBytes += chunk.length;
  if (stderrBytes > 256 * 1024) child.kill("SIGKILL");
});
child.once("exit", () => {
  for (const entry of pending.values()) entry.reject(new Error("Carl exited early"));
  pending.clear();
});

createInterface({ input: child.stdout, crlfDelay: Infinity }).on("line", (line) => {
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    child.kill("SIGKILL");
    return;
  }
  if (Object.hasOwn(message, "id") && pending.has(message.id)) {
    const entry = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) entry.reject(new Error(`ACP request failed: ${message.error.code}`));
    else entry.resolve(message.result);
  } else if (message.method === "session/update") {
    notifications.push(message.params);
  }
});

function request(method, params, timeoutMs = 240_000) {
  const id = nextId++;
  const promise = new Promise((resolveRequest, rejectRequest) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      rejectRequest(new Error(`ACP request timed out: ${method}`));
    }, timeoutMs);
    pending.set(id, {
      resolve(value) {
        clearTimeout(timer);
        resolveRequest(value);
      },
      reject(error) {
        clearTimeout(timer);
        rejectRequest(error);
      },
    });
  });
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  return promise;
}

function notify(method, params) {
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method, params })}\n`);
}

function prompt(sessionId, text) {
  return request("session/prompt", {
    sessionId,
    prompt: [{ type: "text", text }],
  });
}

function updatesSince(index) {
  return notifications.slice(index).map((entry) => entry.update);
}

function agentText(updates) {
  return updates
    .filter((update) => update?.sessionUpdate === "agent_message_chunk")
    .map((update) => update.content?.text ?? "")
    .join("");
}

function sawDiff(updates) {
  return updates.some(
    (update) =>
      update?.sessionUpdate === "tool_call" &&
      Array.isArray(update.content) &&
      update.content.some((content) => content?.type === "diff"),
  );
}

function newSession() {
  return request("session/new", { cwd: canonicalWorkspace, mcpServers: [] });
}

const metadata = {
  codexVersion: "0.146.0",
  apiKeyVariablesRemoved: true,
  planEndTurn: false,
  editApplied: false,
  exactApprovalsConsumed: 0,
  diffObserved: false,
  finalEvidenceObserved: false,
  steerInjected: false,
  cancellationObserved: false,
  providerOutputPersisted: false,
};

try {
  const initialized = await request("initialize", {
    protocolVersion: 2,
    clientCapabilities: {},
    clientInfo: { name: "carl-live-smoke", version: "1" },
  });
  if (initialized.protocolVersion !== 2) throw new Error("ACP v2 was not negotiated");

  const plan = await newSession();
  await request("session/set_config_option", {
    sessionId: plan.sessionId,
    configId: "mode",
    value: "plan",
  });
  let updateStart = notifications.length;
  const planResult = await prompt(
    plan.sessionId,
    "Inspect target.txt without modifying anything. Give a one-sentence repository assessment and mention the current exact line.",
  );
  metadata.planEndTurn =
    planResult.stopReason === "end_turn" && agentText(updatesSince(updateStart)).length > 0;

  const edit = await newSession();
  updateStart = notifications.length;
  let editResult = await prompt(
    edit.sessionId,
    "Change target.txt from the single line broken to the single line fixed. Verify the file with a minimal read-only command. Then run `curl --max-time 1 http://127.0.0.1:9` as an explicitly approval-gated, loopback-only network denial probe; its connection failure is expected evidence. Do not contact any non-loopback address and do not change any other file.",
  );
  let editUpdates = updatesSince(updateStart);
  for (let attempt = 0; editResult.stopReason === "waiting_for_approval" && attempt < 6; attempt++) {
    const command = agentText(editUpdates).match(/\/approve ([0-9a-f]{10})/);
    if (!command) throw new Error("Exact approval command was not surfaced");
    metadata.exactApprovalsConsumed += 1;
    updateStart = notifications.length;
    editResult = await prompt(edit.sessionId, `/approve ${command[1]}`);
    editUpdates = editUpdates.concat(updatesSince(updateStart));
  }
  if (editResult.stopReason !== "end_turn") throw new Error("Edit turn did not complete");
  metadata.editApplied =
    (await readFile(join(canonicalWorkspace, "target.txt"), "utf8")) === "fixed\n";
  metadata.diffObserved = sawDiff(editUpdates);
  metadata.finalEvidenceObserved = agentText(editUpdates).length > 0;

  const steer = await newSession();
  const steeringTurn = prompt(
    steer.sessionId,
    "Carefully inspect target.txt and explain, step by step, how you would validate its invariant. Do not edit files.",
  );
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 750));
  const steering = await request("_session/steering", {
    sessionId: steer.sessionId,
    prompt: [{ type: "text", text: "Focus the final answer on the exact one-line invariant." }],
  });
  metadata.steerInjected = steering.outcome === "injected";
  await steeringTurn;

  const cancel = await newSession();
  const cancellationTurn = prompt(
    cancel.sessionId,
    "Perform an exhaustive repository analysis before answering. Keep inspecting until every possible concern has been considered.",
  );
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  notify("session/cancel", { sessionId: cancel.sessionId });
  metadata.cancellationObserved = (await cancellationTurn).stopReason === "cancelled";

  const assertionsPassed = Object.entries(metadata)
    .filter(([key]) => !["codexVersion", "providerOutputPersisted"].includes(key))
    .every(([, value]) => (typeof value === "number" ? value > 0 : value === true));
  if (!assertionsPassed || metadata.providerOutputPersisted !== false) {
    throw new Error("One or more live assertions failed");
  }

  await writeFile(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`, { mode: 0o600 });
  child.stdin.end();
  const exitCode = await exited;
  if (exitCode !== 0) throw new Error("Carl did not shut down cleanly");
  process.stdout.write(`${JSON.stringify({ metadataPath, ...metadata })}\n`);
} catch (error) {
  child.kill("SIGKILL");
  await writeFile(
    metadataPath,
    `${JSON.stringify({ ...metadata, failure: String(error.message) }, null, 2)}\n`,
    { mode: 0o600 },
  );
  process.stderr.write(`live smoke failed; sanitized metadata: ${metadataPath}\n`);
  process.exitCode = 1;
}
