# ADR 0005: Local, curated, scoped memory

- Status: Accepted
- Date: 2026-08-04

## Context

Carl needs to remain useful across turns and sessions without treating an ever-growing
transcript as a prompt, silently profiling its owner, or adding a paid service to the
default install. Durable memory also creates a persistence boundary for prompt
injection, secrets, stale facts, and data copied across users, agents, projects, or
sessions.

Research supports separating short-term and long-term stores rather than presenting
one undifferentiated transcript. CoALA distinguishes working memory from semantic,
episodic, and procedural long-term memory and treats retrieval and learning as explicit
internal actions. MemGPT similarly motivates tiered memory under a bounded context
window. Generative Agents demonstrates relevance, recency, importance, and reflection
as useful retrieval and consolidation signals. These are architecture patterns, not a
reason to adopt their ambient capture policies.

User-facing memory products also show the importance of review, correction, disable,
source explanation, and deletion controls. OpenAI's Memory FAQ documents those
controls and calls out stale and contradictory memories. NIST's Privacy Framework
supports data minimization, retention, and user control. Current agent-security
guidance treats durable context as an injection and poisoning surface, so a classifier
alone is not an adequate trust boundary.

SQLite FTS5 offers BM25 ranking, but SQLite documents that FTS shadow tables may retain
forensic traces even with `secure_delete`. An embedding index would also add model,
download, network, portability, and deletion semantics that Carl does not need for a
bounded first version.

## Decision

### Memory layers and data model

Carl uses four distinct layers:

1. **Working context** is a bounded per-model-request projection. It is not durable
   memory.
2. **Session history** remains the append-only event journal. Compaction may change a
   future context projection but never rewrites this history.
3. **Curated semantic memory** stores owner-approved profile, preference, fact, and
   goal records.
4. **Curated episodic memory** stores owner-approved or independently verified episode
   records and expires by default.

Each durable record has an ID, owner and agent partition, global/workspace/session
scope, kind, stable key, content, provenance, importance, revision, creation/update
times, and optional expiration. A versioned export includes the effective settings and
all unexpired records. V1 does not store embeddings, raw source transcripts, hidden
summaries, or a second copy of replaced/deleted content.

### Capture and consolidation

Memory is enabled by default, but capture is curated rather than ambient:

- an owner's explicit `carl memory remember` request is committed directly;
- an agent may create a bounded seven-day proposal only from direct owner input or an
  independently verified episode;
- proposed content is never retrieved before owner approval;
- proposals remain reviewable through `carl memory proposals`, and only explicit
  `approve` commits one; `reject` hard-deletes it;
- tool output, fetched content, repository instructions, remote third-party messages,
  and model-authored claims cannot directly become memory;
- secrets and high-confidence prompt-injection forms are rejected before any write.

Approval commits the proposal and deletes the proposal content atomically. A record
with the same partition, scope, kind, and key is updated in place, incrementing its
revision. This is V1 consolidation: the new approved value replaces the conflicting
value without retaining a stale content copy. The future turn runtime may propose
consolidations, but silent post-conversation extraction remains out of scope.

### Retrieval and context budget

Default retrieval is deterministic, offline lexical BM25-style scoring implemented in
Rust over the bounded local candidate set. Ranking combines lexical relevance, scope
specificity, memory kind, owner-selected importance, and recency. Unmatched facts,
goals, and episodes are excluded; profile and preference records remain eligible. Each
selected item includes its score and stable inclusion reasons.

At most eight records and 8 KiB of rendered memory-source data enter one context
projection by default.
Rendered memory is labeled and JSON-escaped as untrusted data: it cannot override
Carl's compiled contract, instructions, policy, approvals, or capability boundaries.
An optional semantic reranker is an injected trait, not a storage dependency. Invalid
or unavailable rerankers produce a stable warning and fall back to local lexical
ranking without exposing provider details.

### Scoping and isolation

Every query requires an exact owner/agent partition. It may then read only global
records plus the exact current workspace and session scopes. CLI operations use the
fixed V1 partition `local-owner`/`carl`; callers cannot select another partition.
Workspace memory is keyed to the canonical current path. The schema carries explicit
partitions now so later isolated workers cannot accidentally share one unscoped pool.

### Privacy, safety, retention, and capacity

- Memory stays in Carl's local SQLite database; there is no sync, telemetry, network
  call, embedding download, or external memory provider.
- The existing non-retaining secret filter and a stable prompt-injection filter run
  over content and provenance before proposal or record persistence. Errors never
  include rejected content.
- Episodes expire after 90 days by default. Other kinds do not expire unless the owner
  sets an expiration. Expired records are never retrieved or exported and are purged
  on maintenance/capture.
- Defaults cap a partition at 500 records and 1 MiB of content. Each record is at most
  2 KiB; pending proposals are capped at 50 and expire after seven days.
- `forget` and `clear` hard-delete content rather than creating content-bearing
  tombstones. SQLite `secure_delete=ON`, a zero journal-size limit, and a successful
  truncating WAL checkpoint are required. Carl cannot erase copies already present in
  exports, backups, filesystem snapshots, or prior model/provider requests; the user
  documentation states that limit plainly.

### Settings and defaults

| Setting | Default | Supported range |
| --- | ---: | ---: |
| `enabled` | `true` | boolean |
| `max_context_items` | `8` | 1–32 |
| `context_bytes` | `8192` | 256–65536 |
| `max_memories` | `500` | 1–5000 |
| `max_storage_bytes` | `1048576` | 64–67108864 |
| `episode_ttl_days` | `90` | 1–3650 |

Disabling memory blocks capture and retrieval but deliberately leaves list, export,
forget, clear, and settings available. Turning memory off is not represented as
deletion.

### Migration and failure behavior

Migration 0006 rebuilds the pre-alpha explicit-memory table. Active legacy records
that pass current size, secret, and injection filters move into the local Carl
partition as global facts. Unsafe and already-forgotten legacy content is not copied
and is scrubbed during migration. The checksum-verified forward-only migration rules
remain unchanged.

Invalid storage values, incompatible schemas, settings outside bounds, capacity
exhaustion, unsafe capture, secure-delete checkpoint failure, and partition mismatch
fail closed. Memory write failure cannot affect the event journal. Optional semantic
failure degrades only retrieval quality and is surfaced as
`semantic_ranker_unavailable`.

## Consequences

- New users get useful durable memory without installing a model or creating an
  account.
- Memory behavior is bounded, inspectable, exportable, and removable.
- V1 lexical retrieval is intentionally less semantically flexible than embeddings.
- The runtime context assembler is still planned; the storage/retrieval API and CLI are
  production boundaries ready for that integration, not a claim that live model turns
  already consume memory.
- A canonical workspace path in a local export may itself be sensitive and may need
  remapping when moved to another machine.

## Primary and authoritative references

- [Cognitive Architectures for Language Agents (CoALA)](https://arxiv.org/abs/2309.02427)
- [MemGPT: Towards LLMs as Operating Systems](https://arxiv.org/abs/2310.08560)
- [Generative Agents: Interactive Simulacra of Human Behavior](https://arxiv.org/abs/2304.03442)
- [SQLite FTS5 and BM25](https://www.sqlite.org/fts5.html#the_bm25_function)
- [SQLite `secure_delete` and WAL checkpoint pragmas](https://www.sqlite.org/pragma.html#pragma_secure_delete)
- [OpenAI Memory FAQ](https://help.openai.com/en/articles/8590148-memory-faq)
- [OpenAI: Designing AI agents to resist prompt injection](https://openai.com/index/designing-agents-to-resist-prompt-injection/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST Privacy Framework](https://www.nist.gov/privacy-framework/privacy-framework)
