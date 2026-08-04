# Memory

Carl's memory is local, curated, scoped, and bounded. It works without an external
memory service, embedding model, network connection, or paid account.

## What is implemented

- explicit global, current-workspace, and session-scoped memories;
- profile, preference, fact, goal, and expiring episode kinds;
- local lexical retrieval with scores and inclusion reasons;
- exact owner/agent/workspace/session isolation;
- agent proposals with persistent CLI review, approval, and rejection controls;
- versioned JSON export, hard deletion, capacity limits, retention, and settings;
- secret and high-confidence prompt-injection rejection before persistence;
- migration of active, currently safe records from the pre-alpha explicit-memory table.

The live model turn loop and context assembler are not implemented yet, so model calls
do not currently consume these records. The memory API and CLI establish that future
integration boundary without claiming a runnable agent experience.

## Commands

`CARL_DATA_DIR` must name the same absolute, pre-existing, owner-private data directory
used by the rest of Carl.

```sh
carl memory status
carl memory remember --kind preference --key response-style --content "Prefer concise answers with verification evidence."
carl memory remember --scope workspace --kind fact --key test-command --content "Use cargo test --all-features for this workspace."
carl memory search "verification evidence"
carl memory list
carl memory export
carl memory purge
carl memory proposals
carl memory approve 00000000-0000-4000-8000-000000000000
carl memory reject 00000000-0000-4000-8000-000000000000
carl memory forget 00000000-0000-4000-8000-000000000000
carl memory clear --confirm delete-all
carl memory settings
carl memory settings --disable
carl memory settings --enable --max-context-items 8 --context-bytes 8192
```

Session scope additionally requires `--session UUID`. Workspace scope binds to the
canonical current directory. Reusing the same scope, kind, and key replaces the old
value in place and increments its revision. Use stable, descriptive keys such as
`response-style`, `test-command`, or `current-goal` so corrections replace conflicts
instead of accumulating.

All successful commands emit one JSON value to stdout. Failures emit one sanitized
JSON error to stderr. `search` reports the retrieval mode, each selected record's score
and reasons, candidates considered, content bytes, truncation, and any stable fallback
warning. `proposals` shows only unexpired suggestions in the local Carl partition;
`approve` commits one suggestion and `reject` hard-deletes it.

## Defaults and settings

Memory is enabled on first use. Defaults are eight items and 8 KiB per context, 500
records and 1 MiB of content per owner/agent partition, and 90-day expiration for
episodes. Other kinds do not expire unless `--expires-in-days` is supplied.

`carl memory settings` accepts:

- `--enable` or `--disable`;
- `--max-context-items` (1–32);
- `--context-bytes` (256–65536);
- `--max-memories` (1–5000);
- `--max-storage-bytes` (64–67108864);
- `--episode-ttl-days` (1–3650).

Disabling memory stops new capture and returns no retrieval results. Existing records
remain available for list, export, forget, or clear. Disabling is not deletion.

## Safety and privacy

Memory content is always rendered to a future model as labeled, escaped, untrusted
data. It cannot grant capabilities or override Carl's instructions, policy, approval,
or sandbox boundaries. Carl rejects high-confidence secrets and prompt-injection forms
before writing a record or proposal. This is defense in depth, not a claim that text
classification can identify every malicious or incorrect statement.

The default store and ranker are entirely local. An optional semantic ranker can be
injected through the Rust interface; if it fails, Carl discards its detail, reports the
stable `semantic_ranker_unavailable` warning, and continues with local lexical ranking.
No semantic provider is configured or required by the CLI.

`forget` and `clear` remove memory and proposal rows without keeping content-bearing
tombstones. Carl enables SQLite secure deletion and requires a truncating WAL
checkpoint before reporting success. This removes the content from Carl's live
database and journal files. It cannot remove copies from exports, backups, filesystem
snapshots, storage-device remanence, or model/provider requests that already received
the content. Protect exports as sensitive local data and delete those copies
separately.

For the architecture, lifecycle, threat model, defaults, migration, and research basis,
see [ADR 0005](adr/0005-local-curated-memory.md).
