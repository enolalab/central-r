# Slice 2A — Workflow Graph and Lineage

- **Slice ID:** 2A
- **Dossier:** `slice-a-workflow-graph-lineage.md`
- **Issue:** #92 — workflow graph model + event history/artifact lineage
- **Packets:** P2A01–P2A06
- **Dependency:** Phase 1 Slice B runtime (B12); design gate #91
- **Outcome:** Durable append-only workflow graph with validated dynamic child-spec emission, event-driven readiness, a canonical append-only event journal with reconstruction rules, and full artifact lineage including the `central artifact read` sibling-data CLI

## Governing specs

- `docs/internal/superpowers/specs/2026-10-07-phase-2-workflow-graph-scheduling-design.md` — node/edge model, child-spec validation, readiness, cancel cascade
- `docs/internal/superpowers/specs/2026-10-07-phase-2-event-schema-reconstruction.md` — canonical event envelope, ordering, fold rules, event catalog
- `docs/internal/superpowers/specs/2026-10-07-phase-2-artifact-lineage.md` — produce/read lineage edges, finalization contract for graph consumers, `central artifact read` CLI
- `docs/internal/superpowers/specs/2026-10-07-phase-2-concurrency-resource-limits.md` — cited for `max_nodes_per_run`, `max_depth`, `BUDGET_EXCEEDS_PARENT` validation inputs only; admission enforcement is Slice 2B
- Phase 1 artifact lifecycle: `docs/internal/superpowers/specs/2026-07-30-phase-1-b10-artifact-lifecycle-design.md` — extended, never restated

## Slice 2A ownership

P2A01–P2A06 collectively own:

- the `workflow_node`/`dependency_edge` durable model and the append-only guarantee, with `(run_id, node_key)` as the emission idempotency key;
- `central.child-spec/v1` batch validation — schema, uniqueness, acyclicity, depth cap 3, launchable harness, finalized input refs, budget-vs-parent check — with atomic `child_spec_rejected` rejection;
- the node state machine and event-driven readiness recomputation, plus the default cascade cancel policy;
- the canonical event journal: envelope, per-run `seq`, append-only writer API, event catalog, and reconstruction (fold) rules with divergence detection;
- artifact produce/read lineage edges, the `finalized`-only visibility contract, the `central artifact read` CLI, and the `ancestors`/`descendants`/`produced`/`read`/`run_lineage` queries.

Slice 2A must not implement the claim transaction, dispatch, leases, worker protocol, retry policy, checkpoints, or any UI rendering. The leader is a harness session; Central never parses loop output (ADR 0035 §4).

## Packets

- **P2A01** — Durable graph store: `workflow_node` + `dependency_edge` schema, append-only enforcement, `(run_id, node_key)` idempotent identity
- **P2A02** — Child-spec emission and validation: batch-atomic `central.child-spec/v1` intake with dynamic expansion and journaled rejection
- **P2A03** — Node state machine and readiness: transitions through the task domain service, event-driven `ready` recomputation, cancel cascade
- **P2A04** — Event journal: canonical envelope, per-run `seq`, append-only writer surface, event catalog, ingest dedup
- **P2A05** — Reconstruction: fold rules for node state, attempt history, and graph shape; gap and divergence detection
- **P2A06** — Artifact lineage and `central artifact read`: produce/read edges, finalized-only visibility, attempt-scoped read authorization, lineage queries

## P2A01

### Identity and outcome

Implement the durable workflow-graph store: `workflow_node` and `dependency_edge` relations, the append-only guarantee, and `(run_id, node_key)` as the structural idempotency key for emission. P2A01 establishes the substrate every later Phase 2 slice reads and writes.

### Implementation boundary

`workflow_node` carries `(run_id, node_key)` identity, `harness`, `workspace_kind`, `depends_on` resolution, depth, budget ceilings, `max_attempts` bookkeeping, `not_before`, and current state. `dependency_edge` carries `(dependent_node, prerequisite, kind)` with `kind ∈ {ordering, artifact}`; `artifact` edges record the declared read. The root node is the operator-submitted task. Append-only is enforced structurally: no UPDATE or DELETE path mutates graph shape — corrections arrive as new nodes/edges only.

### Durable data and migration

New migration adding `workflow_node` and `dependency_edge` tables with the unique constraints above. PostgreSQL is the source of truth; no in-memory graph is authoritative.

### Security and authority

Node rows carry no secrets; `input_artifact_refs` store `(artifact_id, checksum)` pairs only. Graph writes occur inside task domain service transactions.

### Failure, retry, cancellation, and recovery

Re-emission of an identical `(run_id, node_key)` spec dedupes to the existing node (idempotent success). Constraint violations reject atomically before any node exists — see P2A02.

### Verification and evidence

- `(run_id, node_key)` re-emission dedupes to one node
- No code path can mutate or delete a committed node/edge
- `artifact` edges record declared reads; `ordering` edges record prerequisites
- Depth and per-run node-count bookkeeping present for validation
- Future test suite: `go test ./internal/workflow/...`
- Evidence artifact: `phase-2-slice-a-graph-store.json`

### Scope control

P2A01 owns schema and invariants only. It must not validate child-spec payloads (P2A02), compute readiness (P2A03), or journal events (P2A04).

### Definition of Done

Append-only graph relations exist via migration, enforce their unique identities, and reject mutation of committed shape. Node identity dedupes by construction.

## P2A02

### Identity and outcome

Implement child-spec emission: validate each `central.child-spec/v1` batch atomically, append its nodes/edges, and journal `child_spec_rejected` — naming the offending keys — on any violation. Repeated validated emissions are the dynamic-expansion mechanism.

### Implementation boundary

Validation, in order, before any node exists: schema-valid `central.child-spec/v1`; `node_key` unique within the run; `depends_on` references only existing or co-emitted keys; the batch is cycle-checked and rejected atomically; deepest proposed node depth ≤ `max_depth` (default 3); `harness` names a launchable adapter; `input_artifact_refs` reference `finalized` artifacts the run may read; child `budget.wall_clock`/`budget.cost` ≤ parent remaining budget (`BUDGET_EXCEEDS_PARENT`), `max_nodes_per_run` (`MAX_NODES_PER_RUN_REACHED`) and `max_depth` (`MAX_DEPTH_EXCEEDED`) enforced per the concurrency spec. A child spec omitting ceilings inherits the parent's remaining budget, recorded explicitly.

### Durable data and migration

Validation and append commit in one task-service transaction; rejection is a journaled `child_spec_rejected` event, not a crash. No new tables beyond P2A01.

### Security and authority

Child creation is bounded by the run's declared `max_children`/`delegated_scope` launch envelope (spec 1 OQ-1, default enforced at validation). The leader's emitted spec is data — validated, never executed directly.

### Failure, retry, cancellation, and recovery

Rejection leaves the graph unchanged; the leader may emit a corrected batch. A re-emitted identical spec dedupes on `(run_id, node_key)` per P2A01.

### Verification and evidence

- Valid batch appends all nodes/edges atomically
- Cycle, bad ref, depth-cap, and budget-exceeding batches each reject with `child_spec_rejected` naming offending keys
- Rejected batch leaves zero partial nodes
- Second identical emission dedupes; expansion never mutates existing nodes
- Future test suite: `go test ./internal/workflow/...`
- Evidence artifact: `phase-2-slice-a-child-spec-validation.json`

### Scope control

P2A02 owns emission-time validation and append. It must not dispatch nodes, schedule retries, or interpret loop output — the leader decides what to emit next.

### Definition of Done

Validated child-spec batches expand the graph atomically and append-only; every rejection is journaled, actionable, and leaves no partial state.

## P2A03

### Identity and outcome

Implement the node state machine and event-driven readiness: `declared → ready → dispatched → running → succeeded` with `failed_terminal`, `attempt_ambiguous`, and `cancelled` branches, all transitions through the task domain service.

### Implementation boundary

A node becomes `ready` when every `ordering` in-edge source is `succeeded` and every `artifact` in-edge target is `finalized`; recomputation is triggered by node/artifact transition events, never polled. Retry return-to-`ready` consumes Slice 2D's `not_before` — readiness stays a property of the node, not a timer. Cancel of a node cascades `cancelled` to non-terminal descendants: `declared`/`ready` descendants transition with no session ever existing; running descendants receive the harness cancel control. `attempt_ambiguous` parks the node for operator decision — no auto-rerun, at every depth.

### Durable data and migration

Node state transitions ride the P2A01 tables inside domain-service transactions; each transition emits its P2A04 event in the same commit.

### Security and authority

Cancel and ambiguous-resolution are operator-privileged commands routed through the domain service; Slice 2E renders them, Slice 2D dedupes them.

### Failure, retry, cancellation, and recovery

`failed` attempts return the node to `ready` only via the retry policy (2D). Ambiguous attempts block dependents until the operator resolves them. Cancel cascade is journaled per node.

### Verification and evidence

- Readiness flips `ready` exactly when all in-edge conditions hold — event-driven, no poller
- Dependents of a `failed_terminal` node never dispatch
- Cancel cascades to all non-terminal descendants; running ones get the harness cancel control
- `attempt_ambiguous` node blocks its subtree until operator decision
- Future test suite: `go test ./internal/workflow/...`
- Evidence artifact: `phase-2-slice-a-readiness.json`

### Scope control

P2A03 owns node states and readiness. It must not own the claim transaction, leases, retry classification, or checkpoint boundaries.

### Definition of Done

The state machine is enforced by the domain service, readiness is correct and event-driven, and cancel/ambiguous semantics match the locked decisions.

## P2A04

### Identity and outcome

Implement the canonical event journal: the append-only event table with envelope `{event_id, run_id, seq, node_id?, attempt_id?, kind, recorded_at, actor, reason_code?, payload}`, per-run monotonic `seq`, and the kind catalog.

### Implementation boundary

`seq` is allocated in the same transaction as the transition it journals — total order per run, no cross-node wall-clock claims, gaps tolerated and surfaced as `EVENT_SEQUENCE_GAP`. The writer API is INSERT-only; no update/delete path exists. Payloads are kind-versioned JSON carrying artifact references as `(artifact_id, checksum)` pairs — never bodies, secrets, prompt text, or unsanitized filenames. `actor` values: `scheduler`, `worker:<id>`, `leader:<session>`, `operator:<id>`, `reconciler`, `ingest`. The catalog indexes every declared kind from specs 1–8; undeclared kinds store raw and flag `UNKNOWN_EVENT_KIND`.

### Durable data and migration

New migration adding the append-only event table (or extending the B07/B08 event store to the canonical envelope — one journal, not two). Outbox publication mechanics are Slice 2D; this packet owns the journaled record itself.

### Security and authority

Payloads must not embed secrets or rendered prompt text — `prompt_ref` is an artifact `(id, checksum)`. Ingest dedupes on `event_id`; `DUPLICATE_EVENT_ID` is idempotent, not an error.

### Failure, retry, cancellation, and recovery

A lost commit surfaces as a `seq` gap, never silent interpolation. Invalid payloads store raw, excluded from fold, flagged `INVALID_EVENT_PAYLOAD`; dangling references flag `ORPHAN_EVENT`.

### Verification and evidence

- `seq` is per-run monotonic, allocated in the transition transaction
- Insert-only writer: no update/delete path exists
- Catalog indexes all spec-1 kinds plus T2–T8 declared sets as they land
- `node_dispatched`/`attempt_started` payloads carry the `versions` object (`spec_version`, adapter, model, digests, `prompt_ref`)
- Future test suite: `go test ./internal/eventjournal/...`
- Evidence artifact: `phase-2-slice-a-event-journal.json`

### Scope control

P2A04 owns the envelope, ordering, and catalog. It must not decide which kinds exist beyond indexing the owning specs' declared sets, fold state (P2A05), or publish to consumers (2D outbox).

### Definition of Done

One append-only journal carries every journaled transition with canonical fields, provable per-run ordering, and declared-kind coverage.

## P2A05

### Identity and outcome

Implement reconstruction: fold a run's events in `(run_id, seq)` order into node state, attempt history, graph shape, and artifact references, with divergence reported as `RECONSTRUCTION_DIVERGED` — never silently rewritten.

### Implementation boundary

The fold implements spec 6's table: last applicable kind wins per node; attempt history groups by `attempt_id` ordered by `seq`; graph shape folds `node_declared` payloads' `depends_on` edges (expansion batches append); `child_spec_rejected` folds to no node state; artifact references index the union of payload refs by producing node/attempt. Fold output is a derived projection compared against materialized current state; disagreement blocks trusting the projection until reconciled.

### Durable data and migration

No new state — the fold is a pure function over the P2A04 journal. Projections may be materialized for query performance but the journal stays authoritative.

### Security and authority

Folded evidence is read-only; it never steers a live harness loop (ADR 0035) and never becomes an input to scheduling decisions beyond declared readiness edges.

### Failure, retry, cancellation, and recovery

`EVENT_SEQUENCE_GAP` flags the run and folds on available events. `RECONSTRUCTION_DIVERGED` is evidence of a defect, surfaced to operators — the fix is a new event or a repair packet, never a fold-time rewrite.

### Verification and evidence

- Fold of a recorded run reproduces every node state including retry-return and ambiguous branches
- Graph shape reconstruction follows `node_declared` payloads across expansion batches
- Injected `seq` gap surfaces `EVENT_SEQUENCE_GAP`
- Forced divergence surfaces `RECONSTRUCTION_DIVERGED` and blocks the projection
- Future test suite: `go test ./internal/eventjournal/...`
- Evidence artifact: `phase-2-slice-a-reconstruction.json`

### Scope control

P2A05 owns fold rules and divergence detection. It must not own the journal schema, UI rendering of history (2E), or checkpoint watermarks (2C — though `event_watermark` consumes this fold's ordering).

### Definition of Done

Run state, attempts, and graph shape reconstruct deterministically from the journal alone; every anomaly is a named reason code, never a silent correction.

## P2A06

### Identity and outcome

Implement artifact lineage and sibling data flow: journaled produce/read edges, the `finalized`-only visibility contract, the `central artifact read` CLI for child workspaces, and the lineage query surface that feeds Slice 2E and the Phase 2 exit audit.

### Implementation boundary

Produce edge `(producing node_id, attempt_id) → artifact_id` materializes on `finalized` — exactly one per artifact. Read edge `(reader node_id, attempt_id) → artifact_id` is journaled by `central artifact read` when bytes release, carrying `declared | undeclared` plus the finalized checksum — the edge binds the content generation read. `central artifact read` resolves by artifact id or `--from <producer_node_key> --name <name>`, delivers a verified body to a workspace-local path or `--stdout`, and authorizes via an attempt-scoped credential binding `(run_id, node_id, attempt_id)` whose scope is the node's `artifact` in-edges plus `input_artifact_refs`. Delivered bytes re-verify against the metadata SHA-256. Lineage extends B10's immutable representation — no second lineage store. Queries: `ancestors`, `descendants`, `produced(node)`, `read(node)`, `run_lineage(run_id)`.

### Durable data and migration

Migration extends B10 lineage with node/attempt producer identity and the read-edge relation. `finalized` is the Phase 2 name for B10's terminal `ready` — 1:1, no new transition. Artifact bodies stay in object storage; only metadata and edges live in PostgreSQL.

### Security and authority

Reads outside run scope refuse `ARTIFACT_SCOPE_DENIED`. Undeclared-but-authorized reads are allowed and flagged `LINEAGE_READ_UNDECLARED` — declare-or-flag, never silent. ADR 0035 holds: the CLI transports bytes; Central never inspects content.

### Failure, retry, cancellation, and recovery

`ARTIFACT_NOT_FINALIZED` refuses cleanly (scheduling signal). `ARTIFACT_READ_UNRESOLVED` on ambiguous resolution. `ARTIFACT_BODY_INTEGRITY` fails closed and routes the artifact to B10 reconciliation. `ARTIFACT_READ_AMBIGUOUS` completes the edge once known, deduped per attempt (2D).

### Verification and evidence

- `finalized` artifacts satisfy `artifact` edges; `reserved`/`staging`/`verifying`/`rejected` never visible
- Exactly one produce edge per artifact; read edges carry declared flag + checksum
- Out-of-scope read refuses `ARTIFACT_SCOPE_DENIED`; undeclared read succeeds flagged
- `run_lineage` explains every final artifact of a run end-to-end
- Corrupt body fails the read, never hands over bad bytes
- Future test suite: `go test ./internal/artifact/... ./internal/workflow/...`
- Evidence artifact: `phase-2-slice-a-lineage.json`

### Scope control

P2A06 owns lineage edges, the read CLI, and lineage queries. It must not own artifact payload lifecycle internals (B10), finalization dedup mechanics (2D), or UI rendering (2E).

### Definition of Done

Every produced artifact has exactly one produce edge, every sibling read is journaled and checksum-bound, scope is enforced, and `run_lineage` answers the provenance audit.

## Slice acceptance

**Gate:** `S2A-G1` — **Evidence:** `phase-2-slice-a-acceptance.json`

Slice 2A is complete when:

1. P2A01–P2A06 contracts are verified with passing tests
2. The graph is provably append-only; `(run_id, node_key)` dedupes re-emission (P2A01)
3. A valid `central.child-spec/v1` batch expands the graph atomically; every invalid batch rejects with `child_spec_rejected` and zero partial state (P2A02)
4. Depth cap 3 and `max_nodes_per_run`/parent-budget limits are enforced at validation (P2A02)
5. Readiness is event-driven and correct; cancel cascades; ambiguous attempts park for operator decision (P2A03)
6. The journal is append-only with per-run `seq`, canonical envelope, and cataloged kinds (P2A04)
7. Fold reconstructs node state, attempts, and graph shape; gaps and divergence are named findings (P2A05)
8. Sibling reads flow through `central artifact read` with journaled, checksum-bound lineage; `run_lineage` explains every final artifact (P2A06)
9. The complete Slice 2A acceptance evidence is durably recorded

Slice 2A must not claim scheduler, lease, retry, checkpoint, or UI capabilities — those are Slices 2B–2E.
