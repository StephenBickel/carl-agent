# Carl autonomy operations

Carl is a self-improving project.

Status: commissioning

This is the operational contract for the autonomous improvement factory. Current zero-human
operation is not proven and is not claimed. Status can become operational only after a genuine
`remote_cloud_acceptance_receipt` proves one user-visible improvement traversed the complete live
graph and completed its production soak.

## Responsibility graph and handoffs

```text
hypothesis
  -> builder
  -> paired evaluation
  -> immutable experimental ref
  -> independent disposition
  -> protected production PR
  -> production soak
  -> exact revert when required
  -> retained learning
  -> next novel hypothesis
```

| Stage | Sole owner | Required durable result | Next owner |
| --- | --- | --- | --- |
| Hypothesis | Product builder | Observable user behavior, exact parent, allowed surface, guards, held-out transfer, budgets | Builder |
| Builder | Product builder | Failing test, bounded implementation, exact candidate commit and tree | Paired evaluator |
| Paired evaluation | Product builder under protected inputs | Parent/candidate task outcomes, invalid attempts, cost, latency, guards | Experimental publisher or repair |
| Immutable experimental | Experimental publisher | New immutable ref plus complete candidate packet and publication receipt | Independent validator |
| Independent disposition | Validator | One production-candidate, repair, reject, or inconclusive receipt | Promoter, builder, retained learning, or independent validator re-evaluation |
| Protected production | Promoter | Protected PR, required checks, auto-merge, exact merge commit and tree | Soak controller |
| Soak | Soak controller | Six-hour observations through 24 hours and accepted or hard-failure result | Accepted baseline or rollback |
| Revert | Rollback controller | Exact revert branch, protected PR, checks, and restored tree | Retained learning |
| Retained learning | Experiment ledger | Terminal reason, transferable finding, and novelty input | Hypothesis selection |

Only the builder mutates candidate code. Only the validator assigns disposition. Only the promoter
changes protected PR promotion state. Recovery may reconcile an interrupted effect but cannot assume
any of those authorities.

An inconclusive disposition preserves the candidate, blocks promotion, and returns ownership to the
independent validator for one materially different evaluation; it never becomes a pass.

## Cloud-heavy execution

Heavy builds, complete test suites, paired behavioral evaluation, protected validation, and soak
probes execute on isolated cloud runners. Local automations are thin clients for bounded source
edits, GitHub dispatch and reconciliation, durable state transitions, signature checks, and concise
receipt handling. They cannot silently fall back to heavy local execution. A cloud outage leaves the
node queued and records a materially changed bounded retry.

## Protected autonomous authority

The commissioned policy grants no-routine-approval authority to autonomously push immutable
experimental refs and autonomously promote eligible candidates through protected production PRs.
Auto-merge is conditional on exact identity reconciliation, independent evidence, required checks,
current branch protection, a serialized promotion lease, and an exact rollback target.

The policy permits experimental branch and revert branch creation, PR creation and updates,
ready-for-review transitions, and auto-merge enablement. It permits no direct `main` push, no
force-push, no required-check or branch-protection weakening, no evidence mutation, no deployment,
and no release. Candidate execution never receives production mutation credentials, protected
holdouts, or signer keys.

## Anti-benchmark-gaming controls

Capability improvement means a transferable user outcome, not a score increase in isolation.

- The hypothesis and success condition are preregistered before implementation.
- A novelty check compares the proposed work with open experiments, recent branches, terminal
  hypotheses, and retained learning so identical work cannot cycle under a new label.
- Parent and candidate run the same model, effort, tasks, seeds, metric pack, and environment.
- At least one held-out or adversarial transfer task is outside candidate mutation authority.
- Immutable provenance binds parent and candidate commits and trees, harness and workflow revision,
  task and metric digests, run and artifact IDs, reviews, signatures, and receipts.
- Task-level regressions, invalid trials, cost, latency, and safety remain visible; aggregate gains
  cannot hide removed coverage or selective reruns.
- The validator probes fixture hard-coding, test detection, narrowed inputs, altered defaults,
  changed graders, threshold manipulation, and repeated metric gains without behavioral transfer.

A gamed or non-transferring candidate receives a terminal disposition and retained learning. It is
not retried unchanged.

## Durable state and evidence

The managed PostgreSQL ledger is the transition authority. Protected object storage holds immutable
packets and receipts. Every consequential request is bound to an idempotency key, actor, attempt,
prior revision, exact target identity, request digest, result digest, and authoritative time.
GitHub remains the authority for refs, PR identities, checks, protection, merges, and reverts.

Advancement requires agreement among durable state, protected artifacts, cryptographic signatures,
and current GitHub identity. A missing or invalid source freezes only the unsafe forward boundary.
It cannot be inferred from a model summary, reconstructed from mutable output, or treated as a pass.

## Recovery and supervisor

The recovery controller resumes the exact next safe node, reconciles stale leases and lost
responses, and verifies whether an idempotent effect already happened before replay. Infrastructure
recovery has at most three attempts, and each attempt must use a materially changed action. A hard
production failure outranks forward commissioning and starts or reconciles one exact revert within
two hours.

The high-capability supervisor watches the loop rather than duplicating it. It reconstructs durable
and GitHub truth, repairs routine reversible control-plane defects, redispatches one exact safe node,
or freezes one precise boundary. It cannot mutate candidate code, assign disposition, operate a
candidate's promotion PR, edit evidence, weaken policy, push `main`, force-push, deploy, or release.
A repeated diagnosis without a changed action is a failed supervisor run.

## Outcome update contract

A user-facing progress update is emitted only for a concrete pushed, disposed, promoted, soaked,
reverted, or frozen outcome. It contains:

- outcome kind and authoritative time;
- experiment ID and prior/next durable state;
- exact parent, candidate, branch, PR, merge, soak, revert, or frozen-boundary identity as relevant;
- evidence and receipt digests;
- paired task-level delta and guard result when relevant;
- independent disposition and reason when relevant; and
- next owner, next safe node, and deadline.

Healthy watchdog ticks, scheduled-run counts, repeated diagnoses, retries without a terminal effect,
and freshly generated reports are not progress updates. The outcome monitor may record them
internally for health and stuck-loop detection.

## Commissioning and live acceptance

The live manifest remains `Status: commissioning` with a null acceptance receipt. The status may
change only after the receipt validator accepts a `remote_cloud_acceptance_receipt` binding all of:

1. a novel user-visible hypothesis and its production parent;
2. an exact immutable experimental ref and candidate commit/tree;
3. paired evaluation and held-out transfer evidence;
4. an independent disposition;
5. a protected PR, required checks, merge commit, and merge tree;
6. signed evidence archived under protected retention; and
7. an accepted 24-hour production soak.

Synthetic commissioning proves wiring and failure handling but cannot mint this receipt. Until real
acceptance, documentation may describe the configured autonomous authority and commissioned design;
it must never claim current zero-human operation or label the factory operational.
