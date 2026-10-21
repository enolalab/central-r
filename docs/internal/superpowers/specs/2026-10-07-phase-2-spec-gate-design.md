# Phase 2 — specification gate (ADR 0022 design gate) — spec

Status: draft. Closes issue #91. This spec defines what the Phase 2
design gate must produce: the nine required specifications from
`docs/product/phases.md` §Phase 2 plus per-slice dossiers, their
boundaries, their dependency order, and the shared vocabulary every
downstream spec builds on. It authorizes no implementation.

## Scope (issue #91)

Phase 2 converts Central from a single-agent runner into a durable
orchestration engine. The gate produces implementation-ready specs —
not code — so that slice work proceeds under the same
spec → spec-review → plan → plan-review → implement pipeline Phase 1
used.

## Locked inputs — maintainer decisions 2026-10-07

Recorded on epic #90; all specs must encode them:

1. Leader is a harness session; child specs arrive as validated
   `central.child-spec/v1` artifacts; Central never parses loop output
   (ADR 0035 §4).
2. Graph append-only; dynamic expansion allowed per emission batch.
3. Children may spawn children; depth cap default 3.
4. Workspace isolation: git worktree for code work, private directory
   otherwise.
5. Ambiguous session attempts are operator decisions at every level.
6. Sibling data flow via `central artifact read` CLI in the workspace.
7. Phase 2 starts now; Phase 1 physical-tier/release tracks run in
   parallel and are not prerequisites.
8. Dynamic graph expansion via repeated validated emissions.

## Deliverables and boundaries

Nine specs under `docs/internal/superpowers/specs/`, dated
2026-10-07, each carrying `Status: draft`, a scope section, numbered
design decisions, open questions, and acceptance criteria:

| # | Spec | Owns | Explicitly does not own |
| --- | --- | --- | --- |
| 1 | Workflow graph + scheduling | `2026-10-07-phase-2-workflow-graph-scheduling-design.md` (drafted) — node/edge model, child-spec validation, readiness, atomic claim, concurrency surface, cancel cascade | worker heartbeat detail, checkpoint format, retry policy |
| 2 | Task leasing + worker protocol | lease lifecycle, worker registration/capabilities, heartbeat + renewal, worker-loss detection, abandoned-run reconciliation | scheduling policy itself |
| 3 | Checkpoint + resume format | checkpoint schema/versioning, safe boundaries, resume token + compat validation, GC; harness session id + workspace digest per ADR 0035 | when checkpoints are taken (that's slice dossier policy) |
| 4 | Retry, timeout, error taxonomy | retryable-vs-terminal classification, backoff, attempt limits, timeout hierarchy, compensation hooks | ambiguous-attempt handling (operator decision — locked) |
| 5 | Idempotency + consistency model | idempotency keys for commands/steps, outbox publication, exactly-once vs at-least-once boundaries, artifact dedup | queue claim mechanics (spec 1) |
| 6 | Event schema + reconstruction | canonical event fields, ordering guarantees, task/run/graph reconstruction rules, prompt/model/tool/config versioning record | which events exist (each spec lists its own minimum) |
| 7 | Artifact lineage model | parent/child lineage incl. read edges (`central artifact read`), artifact finalization for graph consumers, lineage queries | artifact payload lifecycle (Phase 1 B10) |
| 8 | Concurrency + resource-limit policy | cap vocabulary (global/session/graph), admission checks, budget aggregation parent→child, fairness baseline | enforcement mechanics (specs 1–2) |
| 9 | Recovery test matrix | injected-failure catalog (process/network/provider/worker), per-scenario expectations, evidence schema for the Phase 2 acceptance suite | the suite's implementation (issue #97) |

Plus: slice dossiers under `docs/implementation/phase-2-slices/`
following the `phase-1-slices/` precedent — one dossier per executable
slice (graph+lineage; scheduler+workers; checkpoint; retry/idempotency;
UI; acceptance), each naming packets, gates, and evidence schema.

## Dependency order

Spec 1 first (vocabulary: node, edge, attempt, lease, readiness) →
specs 2–8 may be drafted in parallel against it → spec 9 last (it
consumes every other spec's failure semantics).

## Cross-cutting invariants every spec must state

- PostgreSQL is the source of truth; artifact bodies stay in object
  storage; metadata in PostgreSQL.
- Task/node transitions through the task domain service; retriable
  operations idempotent.
- ADR 0035 non-intervention: no prompt injection, no fabricated tool
  results, no loop decisions from parsed harness output.
- A node is complete only when its required artifacts + final state are
  durably persisted.
- Failure sections must name the reason code vocabulary they introduce
  (precedent: `MAINTENANCE_TRANSITION_UNLISTED`, `PREPARE_UNAVAILABLE`).

## Acceptance criteria

- All nine specs exist, each spec-reviewed (Focused) with a recorded
  report under `docs/internal/superpowers/reviews/`.
- Every maintainer decision is either encoded as a rule or carried as
  a numbered OQ — none silently dropped.
- No spec contradicts spec 1's vocabulary or ADR 0022/0035.
- Slice dossiers map every spec onto packets, gates, and evidence.
- Issue #91 checkboxes tickable; the gate unblocks #92–#96 specs'
  implementation plans.
