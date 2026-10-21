# Phase 2 — artifact lineage model — spec

Status: draft. Design-gate input under issue #91: specifies how
artifact provenance is recorded for a durable multi-agent run — which
attempt produced each artifact, which nodes read it — and the
finalization contract that lets the workflow graph and sibling nodes
consume artifacts safely. No production code is authorized by this
document; implementation follows a reviewed plan and a
`docs/implementation/phase-2-slices/` dossier per the Phase 1
precedent.

## Scope

Owns: parent/child artifact lineage including read edges; the artifact
finalization contract for graph consumers; the lineage query surface
that feeds the Phase 2 graph UI and the exit criterion "task graph and
event history explain how every final artifact was produced".

Does not own: artifact payload lifecycle internals — Phase 1 B10
(`2026-07-30-phase-1-b10-artifact-lifecycle-design.md`) already defines
reserve/stage/verify/promote/finalize; this spec extends, never
rewrites, that lifecycle. Idempotency mechanics belong to the
idempotency and consistency spec (spec 5); canonical event field
definitions belong to the event schema spec (spec 6).

## Locked inputs — maintainer decisions 2026-10-07

1. Sibling data flow runs through the `central artifact read` CLI
   inside the child workspace — no MCP server in Phase 2.
2. Every CLI read records a lineage read edge `(reader_node,
   artifact_id)`; reads are observable, never silent.
3. Only `finalized` artifacts are readable by other nodes.
4. Graph `artifact` dependency edges declare intended reads at
   spec time. A CLI read outside the declared set is recorded as an
   undeclared read — policy is declare-or-flag (flag plus journaled
   event), not refusal.

## Design

1. **Lineage edge model — two journaled kinds.**
   - *Produce edge* — `(producing node_id, attempt_id) → artifact_id`,
     materialized when the artifact reaches `finalized`. Exactly one
     produce edge per artifact; duplicate finalization dedupes on the
     artifact's stable identity (spec 5 owns the mechanics).
   - *Read edge* — `(reader node_id, attempt_id) → artifact_id`,
     journaled by `central artifact read` when bytes are released,
     carrying `declared` | `undeclared` classification and the
     artifact's finalized checksum — the edge binds the content
     generation actually read, not just the artifact id.
   - Both are journaled events carrying at minimum `(run_id,
     artifact_id, node_id, attempt_id, edge_kind, declared, checksum,
     recorded_at)`; spec 6 owns canonical field names. PostgreSQL is
     the queryable store for lineage; bodies stay in object storage.
   - B10 already persists parent-artifact lineage in an immutable
     representation built for derived-artifact queries. Phase 2
     extends that representation with node/attempt producer identity
     and a read-edge relation — no second lineage store.

2. **`central artifact read` CLI surface.**
   - Resolution: `central artifact read <artifact-id>` or
     `central artifact read --from <producer_node_key> --name <name>`;
     the latter resolves inside the run's graph.
   - Delivery: materializes the verified body to a workspace-local
     path under the attempt's artifact cache and prints the path, or
     streams raw bytes with `--stdout` for pipe composition.
   - Authorization: dispatch injects an attempt-scoped credential
     binding `(run_id, node_id, attempt_id)`; the run's artifact scope
     is the set reachable through the node's `artifact` in-edges plus
     `input_artifact_refs` declared in its child spec. Reads outside
     the run's scope are refused (`ARTIFACT_SCOPE_DENIED`).
   - Integrity: delivered bytes are re-verified against the metadata
     SHA-256; a mismatch fails the read rather than handing over
     corrupt content.
   - ADR 0035 holds: the CLI transports bytes; Central never inspects,
     rewrites, or interprets artifact content for the consumer.

3. **Finalization contract for graph consumers.**
   - `finalized` is the terminal lifecycle state — Phase 2 graph
     vocabulary for B10's `ready` state; the mapping is 1:1, no new
     transition is introduced.
   - The contract order is fixed: checksum-verified body in object
     storage → metadata commit in PostgreSQL → `finalized` transition
     plus a journaled `artifact_finalized` event carrying `(run_id,
     artifact_id, node_id, attempt_id, checksum, size)` in one durable
     commit.
   - Only `finalized` artifacts satisfy graph `artifact` edges (the
     readiness recomputation of spec 1) or are readable by any node.
     `reserved`/`staging`/`verifying` artifacts are invisible to graph
     edges and CLI reads; `rejected` artifacts are permanently
     unreadable.

4. **Lineage queries** — PostgreSQL projections over journaled edges:
   - `ancestors(artifact_id)` — transitive walk: producing node → that
     node's read edges → their producers, back to the run root.
   - `descendants(artifact_id)` — nodes that read it, then the
     artifacts those nodes produced, transitively.
   - `produced(node)` / `read(node)` — per-node artifact sets,
     attributed per attempt.
   - `run_lineage(run_id)` — the closure explaining every final
     artifact of the run; this is what the graph UI renders and what
     the Phase 2 exit criterion audits. Undeclared reads render
     flagged, never hidden.

## Failure semantics

Reason codes introduced here, journaled on the read/artifact event:

- `ARTIFACT_NOT_FINALIZED` — read of a non-`finalized` artifact:
  refused and journaled; the reader may retry after finalization — a
  scheduling signal, not corruption.
- `ARTIFACT_SCOPE_DENIED` — artifact outside the run's readable scope:
  refused and journaled; never auto-retried.
- `ARTIFACT_READ_UNRESOLVED` — id or `(producer_node, name)` resolves
  to nothing or to multiple artifacts: refused and journaled.
- `LINEAGE_READ_UNDECLARED` — authorized read outside the declared
  `artifact` in-edge set: allowed; the read edge carries this flag and
  a flag event is journaled for the UI. Default policy is flag, never
  refuse.
- `ARTIFACT_BODY_INTEGRITY` — delivered bytes fail SHA-256
  verification: the read fails closed; the read edge records the
  failure and the artifact is handed to B10 reconciliation.
- `ARTIFACT_READ_AMBIGUOUS` — authorized read outcome unknown
  (CLI/daemon disconnect mid-stream): journaled ambiguous; the edge is
  completed once known and never double-counted (attempt-scoped dedup
  per spec 5).

## Open questions

- **OQ-1 — strict mode.** Whether a run may opt into undeclared-read
  refusal. Default: flag-only in Phase 2; refusal is a run option only
  if the reviewer requires it.
- **OQ-2 — edge granularity.** Default: whole artifact at a pinned
  content generation; no byte-range or partial-stream edges.
- **OQ-3 — cross-run reads.** Whether the CLI may address artifacts
  produced by earlier runs in the same workspace. Default: allowed
  only via `input_artifact_refs`; journaled as declared read edges
  with a `cross_run` marker.
- **OQ-4 — retry attribution.** Default: edges bind `(node, attempt)`;
  a node's read set is the union across attempts, attempt column kept
  for forensics.
- **OQ-5 — operator reads.** Whether the same CLI serves inspection
  outside any node context. Default: same surface, edges attributed to
  a synthetic operator reader, scope = workspace.

## Acceptance criteria

- Spec review records a verdict under
  `docs/internal/superpowers/reviews/`.
- Every locked input is encoded as a rule or carried as a numbered OQ.
- Vocabulary is consistent with the workflow-graph spec (node,
  attempt, `artifact` edge, `finalized`) and extends B10 rather than
  restating it; nothing contradicts ADR 0022/0035.
- Every reason code above maps to a journaled event the event-schema
  spec (spec 6) can carry.
- A slice dossier names the lineage packets, gates, and evidence; the
  `run_lineage` query is the named evidence source for the Phase 2
  exit criterion on final-artifact provenance.
