# Long-horizon coding tasks

Carl's durable task runtime is the implemented path for coding work that spans many
provider turns, compactions, service restarts, and owner interventions. It is exposed
through ACP and the private local task service; it is not a promise that every model
will finish every repository task.

## Start and admission

Start `carl serve`, then connect with `carl acp`. A new ACP prompt creates one durable
task with an immutable workspace, completion contract, provider/model selection, and
budget. The ACP admission flags are:

- `--max-wall-time-seconds`
- `--max-provider-requests`
- `--max-tool-calls`
- `--soft-epoch-seconds`
- `--soft-epoch-tool-calls`

The two soft limits request a safe epoch boundary; they do not replace the hard wall,
provider-request, or tool-call limits. The model must finish the active operation and
emit a structured epoch report before Carl commits the boundary.

Owner-selected full access is accepted risk. In that mode Carl can authorize local
effects without interrupting for each decision, but every consequential request still
crosses Carl's pre-dispatch policy and durable operation boundary. It does not turn the
provider sandbox or the host operating system into a complete security sandbox.

## Inspect and control a task

ACP clients use the following protocol methods. These names are JSON-RPC methods, not
standalone shell commands:

- `_task/status` returns the durable task snapshot, completion contract, operation
  states, provider context, and `latest_checkpoint`.
- `_task/metrics` returns fixed-schema journal-derived counts and budget usage without
  assistant text, command output, or secrets.
- `_task/resume` resumes a queued or recoverable task with an idempotency key.
- `_session/steering` injects owner guidance into the active provider turn.
- `session/cancel` cancels the bound session; `_task/cancel` addresses a durable task.
- `session/load` rebinds an existing session and task after reconnect or service
  restart.

Buzz provides exact `/status`, `/metrics`, `/resume`, `/steer`, and `/cancel` controls
for the owner-bound conversation. Other ACP clients can invoke the protocol methods
directly.

## Checkpoints and compaction thresholds

At a safe boundary Carl records tool evidence, verifies the epoch report, builds a
canonical checkpoint, optionally compacts context, and transitions back to `active`.
The checkpoint contains the source event range, completion-contract state, exact
identifiers, unresolved operations, usage, and the next bounded objective. The SQLite
journal remains authoritative; a checkpoint is a validated incremental projection,
not a substitute for the journal.

The configured soft epoch limits request a safe checkpoint; they do not themselves
force context compaction. Automatic compaction begins when observed or conservatively
estimated context reaches 80 percent of the effective model window and targets a
50–60 percent continuation package. Explicit owner compaction also waits for a safe
checkpoint. Both paths preserve the completion contract, exact identifiers, durable
operation summaries, and next objective. A provider-native compaction is accepted only
through the pinned protocol lifecycle; malformed or incomplete events fail closed.

## Restart and provider replacement

Recoverable maintenance drains the active task to a committed checkpoint before
stopping the provider. After restart, `session/load` and `_task/resume` continue from
durable state. Carl validates the workspace, canonical checkpoint lineage, projections,
and provider binding before dispatching new work.

If provider state is unavailable, Carl records provider context replacement: the old
context is marked lost, a fresh context is bound, and the checkpoint package is used
to reconstruct the next objective. An unresolved `Started` operation is never blindly
replayed. It becomes uncertain and blocks until authoritative reconciliation or an
owner decision proves what happened.

## Evidence and limitations

Offline release evidence includes the deterministic ten-case repository matrix and
the uninterrupted-versus-restarted 100-epoch replay proof. The opt-in subscription
runner adds real OAuth, process, restart, compaction, steering, context-replacement,
and paired direct-provider coverage. See [benchmark methodology](benchmarks.md).

Carl currently exposes this workflow through ACP/Buzz and the private service. The
interactive TUI, Telegram gateway, Grok execution adapter, and cross-platform release
packaging remain unavailable. Local full access is powerful and cannot protect secrets
from another process already running as the same user.
