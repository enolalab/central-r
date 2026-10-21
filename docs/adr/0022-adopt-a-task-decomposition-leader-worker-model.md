# ADR 0022: Adopt a task-decomposition (leader/worker) model

- **Number:** 0022
- **Title:** Adopt a task-decomposition (leader/worker) model
- **Status:** Accepted
- **Created:** 2026-08-18
- **Owners:** Central maintainer
- **Decision due:** 2026-09-30
- **Decision due history:** None
- **Implementation blocked at:** Any code that lets one Task spawn child Tasks
  as a first-class decomposition edge, that derives a child's execution
  authority/budget from a parent, or that aggregates child outcomes into a
  parent — and any UI that presents a leader→worker hierarchy as real.
  Acceptance adopts the **direction** and the constraints below, and amends ADR
  0004; it authorizes **no implementation**. This boundary continues to block
  every item above until the dedicated design gate (see Decision) specifies all
  seven invariants. The shipped orchestration surfaces (office, activity feed,
  per-run turn timeline) still visualise only independent tasks and one
  single-lane run each.
- **Decided by:** hieuntg81 (Central maintainer and ADR owner, 2026-08-18)
- **Decision date:** 2026-08-18
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** ADR 0004 (amends its single-agent commitment at the Task level;
  the per-run single-lane guarantee is preserved)
- **Amended by:** None
- **Related:** ADR 0004 (staged **single-agent** runtime — this proposal would
  amend it on acceptance); ADR 0001 (durable Task domain and lifecycle — the
  domain this extends); `docs/runtime/agent-runtime.md` ("Phase 1 has one
  sequential runtime coordinator and at most one active external invocation";
  "no durable Worker registry"); `internal/agent/app/coordinator.go` (the
  single-lane B09 coordinator); the `central.tasks.parent_task_id` rerun-lineage
  column (migration v19, `internal/adapter/postgres/migrate/b11_task_lineage.go`);
  `docs/product/agent-orchestration-view-design.md` (Step 3, the scope this ADR
  opens); ADR 0021 (Step 2, which read turn activity without any decomposition).

## Context

The orchestration mockup imagines a **leader** decomposing work and delegating
to many **workers**, each with its own live activity. The shipped observability
(ADR 0021 and the Step-1 feed) deliberately stops short of that: Central models
no such hierarchy. Two accepted decisions establish today's reality.

- **ADR 0004 commits Phase 1 to a single-agent runtime.** `agent-runtime.md`
  states "Phase 1 has one sequential runtime coordinator and at most one active
  external invocation," and "no durable Worker registry, competing-worker
  fairness, remote heartbeat protocol, or capability advertisement." The B09
  coordinator is "the single-lane B09 provider/tool coordinator."
- **The only task-to-task edge is rerun lineage.** `central.tasks.parent_task_id`
  (migration v19) records "lineage between an original task and the task created
  to retry it" — nothing else. There is no parent→children decomposition edge,
  no leader task, no child spawning.

So "leader/worker with per-worker thoughts" corresponds to nothing Central has,
and building the *view* of it would be fiction. Making it *real* is not a UI
feature; it is a domain-and-runtime direction change that touches the durable
Task lifecycle (ADR 0001), the single-agent runtime (ADR 0004), authority and
budget, cancellation and recovery, and the read model. That direction, and
whether Phase 1 should take it at all, is the decision this ADR opens.

A crucial framing choice constrains the whole space: decomposition can live at
the **Task** level (a leader Task spawns child Tasks, each of which still runs
its own single-lane coordinator) or at the **run** level (multiple provider
lanes inside one run). The run-level option would directly break ADR 0004's
single-lane guarantee and the execution model built on it. Only the task-level
option is compatible with keeping ADR 0004's per-run guarantee intact, so this
proposal is deliberately scoped to it.

## Decision

**Accepted as a direction; implementation is gated.** The leader/worker
task-decomposition direction is adopted, and this ADR **amends ADR 0004** at the
Task level accordingly. Acceptance makes the task-level scoping and the seven
invariants below **binding constraints** on any future design and code — but it
authorizes **no implementation**: every item under "Implementation blocked at"
stays blocked until a dedicated design gate specifies all seven invariants. This
is the ADR 0020 shape — Accepted while its named surface remains deliberately
blocked.

Introduce a first-class **task-decomposition** relation at the Task level. A
**leader** Task may spawn **child** Tasks recorded as a typed
decomposition edge that is **distinct from** the rerun-lineage `parent_task_id`;
the two edges must never be conflated. Each child is an ordinary Task with its
own lifecycle, its own runs, and its own single-lane coordinator — decomposition
adds a Task-level tree, it does **not** add lanes within a run, so ADR 0004's
"one active external invocation per run" guarantee is preserved.

Acceptance requires the following invariants to be designed and enforced, each
a named open question this ADR does not itself resolve:

1. **Domain-service-only transitions.** Spawning a child, and every child and
   leader transition, goes through the task domain service — never a direct
   write (ADR 0001).
2. **Idempotent spawning.** A leader that restarts or retries must not
   double-spawn its children; spawning carries an idempotency key like every
   other command.
3. **Bounded fan-out and depth.** A hard cap on children per leader and on tree
   depth, enforced in the domain, so decomposition cannot run away.
4. **Authority never escalates.** A child's execution authority, scope, and
   budget are *derived from and bounded by* the leader's grant; decomposition
   must not become a privilege- or quota-escalation path. Budget/spend must
   account across the tree, not per isolated task.
5. **Defined roll-up and propagation.** Explicit, tested semantics for how child
   outcomes aggregate into the leader (completion, partial failure, failure
   roll-up) and how leader cancellation propagates to children — including the
   interaction with the recovery/restart barrier across a tree.
6. **Recovery across a tree.** Crash/restart reconciliation must define a
   consistent state for a partially-spawned or partially-completed tree.
7. **Workspace containment.** A leader spawns only within its own workspace; no
   cross-workspace children.

A dedicated design gate must specify all seven before any implementation
begins; acceptance of this ADR authorizes and requires that gate, and nothing
more. Until it completes, the direction is adopted but no decomposition code or
UI ships.

## Consequences

### Benefits

- Makes the leader/worker office and orchestration view *real* rather than a
  visualisation of independent tasks, and unlocks genuine task-level
  parallelism and structured delegation.
- Gives multi-step work a durable, inspectable structure (a tree) instead of a
  flat task list plus ad-hoc correlation.

### Costs and limitations

- **Large and cross-cutting.** It amends ADR 0004, extends ADR 0001, and adds
  schema (a decomposition edge / `task_edges` table), domain lifecycle, an
  authority-derivation path, tree-wide budget accounting, cancellation/failure
  roll-up, recovery semantics, and read/UI surfaces — with a correspondingly
  large test surface.
- **Risk to the durable-task invariants.** Every one of the seven invariants is
  a place the durable-task guarantees could regress; the authority-derivation
  and budget-accounting items are the highest-risk.
- **Beyond Phase 1's accepted scope.** Phase 1 is deliberately single-agent;
  adopting this now would reopen a foundational decision mid-slice.

## Alternatives considered

### Do nothing — keep the single-agent runtime

Keep ADR 0004 as is; the office/orchestration views remain honest
visualisations of independent tasks and single-lane runs. Rejected: with this
ADR accepted, leader/worker is now a committed direction, so "do nothing" no
longer holds — though implementation is still deferred to the design gate.

### UI-only grouping by correlation, no domain change *(lighter middle path)*

Group related tasks in the view by an existing or added **correlation id / tag**
(the event model already carries correlation/causation ids), giving the office
a sense of "related work together" without a decomposition domain model, new
lifecycle, or authority derivation. Rejected *as a substitute* for a real
model, but recommended as a much smaller, separate ADR if some grouping is
wanted before Phase 2.

### Multi-lane within a single run

Let one run drive several provider lanes in parallel. Rejected: it breaks ADR
0004's "at most one active external invocation" guarantee and the execution
model built on it, for no benefit over task-level decomposition.

## Follow-ups

- **Required next step (this ADR authorizes it):** open a **dedicated design
  gate** (brainstorm → spec → ADR chain, as with the lettered slices) that
  resolves the seven invariants above before any implementation; do not
  implement piecemeal.
- Decide the edge representation (a `task_edges` typed-edge table vs. a second
  nullable column) and how it stays distinct from rerun lineage.
- Specify authority/scope/budget derivation for children and tree-wide spend
  accounting.
- Specify cancellation propagation, failure roll-up, and recovery for a partial
  tree, including interaction with the restart/recovery barrier.
- If earlier grouping is desired, draft the much smaller correlation-grouping
  ADR (Alternative 2) instead.

## References

- ADR 0004 — staged single-agent runtime and verified adapter handoffs (would
  be amended on acceptance).
- ADR 0001 — durable Task domain and lifecycle.
- `docs/runtime/agent-runtime.md` — the single-coordinator, no-worker-registry
  Phase 1 runtime contract.
- `internal/agent/app/coordinator.go` — the single-lane B09 coordinator.
- `internal/adapter/postgres/migrate/b11_task_lineage.go` — the rerun-only
  `parent_task_id` edge this proposal must stay distinct from.
- `docs/product/agent-orchestration-view-design.md` — Step 3, opened here.
