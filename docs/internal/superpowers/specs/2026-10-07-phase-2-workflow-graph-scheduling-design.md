# Phase 2 — Workflow graph and scheduling design — spec

Status: draft. Design-gate input under issue #91: specifies the domain
model and dispatch rules for durable multi-agent orchestration. No
production code is authorized by this document; implementation follows
a reviewed plan and a `docs/implementation/phase-2-slices/` dossier per
the Phase 1 precedent.

## Scope

From `docs/product/phases.md` §Phase 2: workstream 1 (workflow graph
model) and the scheduler-facing parts of workstream 2 (queue model,
leasing surface, concurrency limits, atomic claim, duplicate-dispatch
protection). Worker registration, heartbeat, and loss reconciliation are
the separate *task leasing and worker protocol* spec; event schema
canonical fields, checkpoint format, retry/idempotency detail, artifact
lineage model, and UI each have their own specs.

## Locked inputs — maintainer decisions 2026-10-07

1. **Leader is a harness session.** Child task specifications arrive as
   validated artifacts; Central never parses loop output to make
   orchestration decisions (ADR 0035 §4 holds).
2. **Graph is append-only and may expand dynamically** — a leader may
   emit child specs more than once per run; existing nodes are never
   mutated or deleted by expansion.
3. **Depth cap** — children may spawn children; proposed cap 3 (OQ-3).
4. **Workspace isolation** — code work runs in a dedicated git
   worktree; non-code work in a private directory.
5. **Ambiguous session attempts are operator decisions** at every
   graph level — no automatic re-launch, no auto-rerun (ADR 0035
   restart reconciliation, kept for children).
6. **Sibling data flow via a shared artifact namespace** — children
   read declared artifacts through a Central-provided
   `central artifact read` CLI inside their workspace; no MCP server
   in Phase 2.

## Domain model

### Identities

- `WorkflowNode` — one unit of orchestrated work. Stable identity:
  `(run_id, node_key)`; `node_key` is a leader-chosen slug. The pair is
  the idempotency key: re-emitting an identical spec dedupes to the
  existing node.
- `DependencyEdge` — `(dependent_node → prerequisite, kind)` where
  `kind` is:
  - `ordering` — dependent may dispatch only after the prerequisite
    node reaches `succeeded`;
  - `artifact` — dependent waits for a specific artifact to reach
    `finalized`, and the edge declares a read edge for lineage.
- The root node is the task the operator submitted; a run's graph is
  rooted at that node.

### Node state machine

`declared → ready → dispatched → running → succeeded` with failure
branches `failed_terminal`, `attempt_ambiguous`, and `cancelled`.
`failed` attempts return the node to `ready` only through the retry
policy spec — retry creates a new session attempt; the node, not the
attempt, holds durable progress. Transitions go through the task
domain service (AGENTS.md) and are journaled.

### Validation at emission

Every child-spec artifact is validated before any node exists:

- schema-valid `central.child-spec/v1`;
- `node_key` unique within the run;
- `depends_on` references only existing or co-emitted node keys —
  the batch is checked for cycles and rejected atomically with a
  `child_spec_rejected` event naming the offending keys;
- depth of the deepest proposed node ≤ cap;
- `harness` names an adapter Central can launch;
- `input_artifact_refs` reference finalized artifacts the run may read.

Rejection is a normal journaled event the leader observes, not a
crash — the leader may emit a corrected batch. Every rejection carries
reason code `SPEC_VALIDATION_FAILED` (taxonomy: spec 4) — schema,
cycle, duplicate key, depth, capability, and artifact-ref violations
share the code; the event's detail names the offending keys and the
specific rule.

### Readiness

A node becomes `ready` when every `ordering` in-edge's source is
`succeeded` and every `artifact` in-edge's target is `finalized`.
Readiness is event-driven — recomputed on node/artifact transitions,
never polled.

## Scheduler

- **Queue.** The ready set lives in PostgreSQL; claiming uses
  `SELECT … FOR UPDATE SKIP LOCKED`. Single host, PostgreSQL is the
  source of truth — no external queue.
- **Atomic claim.** A claim is one transaction: `ready → dispatched`,
  allocating a `session_attempt` row with idempotency key
  `(node_id, attempt_seq)` and a lease `(node_id, attempt_id,
  expires_at)`. Duplicate-dispatch protection is structural: only a
  node in `ready` can be claimed, and an attempt row's key prevents
  doubles.
- **Dispatch shape.** Launch uses the ADR 0004 discipline carried by
  the harness workstream: prepare → invoke outside transaction →
  persist outcome. Each dispatch is exactly one harness session
  attempt with the closed launch-argv grammar (ADR 0036); workspace is
  provisioned in prepare, its path recorded on the attempt.
- **Concurrency.** Proposed defaults (OQ-3): `max_parallel_sessions=4`
  global, `max_inflight_nodes` per graph, `max_nodes_per_run=64`,
  `max_depth=3`. Fairness baseline: FIFO by `ready_at`, then
  `node_key`; no priorities in Phase 2.
- **Admission.** Before dispatch, the Slice C capacity-admission
  machinery (RAM/disk floors) gates the claim; session-level wall-clock
  and cost ceilings come from the child spec's budget hints, bounded by
  run-level ceilings.
- **Cancel propagation.** Cancelling a node cascades `cancelled` to
  non-terminal descendants; running descendants receive the harness
  cancel control; `declared`/`ready` descendants transition without a
  session ever existing. Per-edge cancel policy is OQ-4; Phase 2
  default is cascade.

## Workspace isolation

- `workspace_kind: code` → `git worktree add` at the task's recorded
  base ref, under the instance scratch root, path recorded on the
  attempt.
- `workspace_kind: plain` → a fresh directory `workspaces/<run>/<node>/`.
- Merge/conflict handling is **out of scope** for Phase 2 (OQ-2): a
  child's outputs are its artifacts; its worktree remains for the
  operator or leader to inspect.

## Events (this spec's minimum set)

`node_declared`, `node_ready`, `node_dispatched`, `attempt_started`,
`attempt_succeeded`, `attempt_failed`, `attempt_ambiguous`,
`node_succeeded`, `node_failed_terminal`, `node_cancelled`,
`child_spec_rejected` — each carrying `(run_id, node_id, attempt_id?,
recorded_at, reason_code?)`. Canonical field definitions belong to the
event schema spec; this list is the contract it must cover.

## Failure semantics owned here

- **Dispatch failure** (workspace provisioning or launcher refusal
  before `attempt_started`): `attempt_failed` with a reason code; the
  node returns to `ready` only if the retry policy permits, else
  `failed_terminal`.
- **Ambiguous attempt** (launch persisted, outcome unknown):
  `attempt_ambiguous`; the operator chooses harness-native resume or a
  fresh rerun — never automatic.

## Open questions

- **OQ-1 — child-creation approval envelope.** Runs declare
  `max_children` + `delegated_scope` at launch; child creation inside
  the envelope is auto-approved, exceeding it requires operator
  approval. Reviewer decides whether Phase 2 needs per-batch approval.
- **OQ-2 — worktree merge policy.** Deferred; likely late Phase 2 or
  Phase 3.
- **OQ-3 — cap defaults** (`4` parallel, depth `3`, `64` nodes/run).
- **OQ-4 — per-edge cancel policy.** Default cascade; whether
  `isolate` edges are needed in Phase 2.

## Acceptance criteria

- Spec review records a verdict under `docs/internal/superpowers/reviews/`.
- Every maintainer decision above is either encoded as a rule or
  carried as a numbered OQ.
- A slice dossier `docs/implementation/phase-2-slices/slice-*.md` and
  an implementation plan under `docs/internal/superpowers/plans/`
  follow this spec, per the Phase 1 precedent.
