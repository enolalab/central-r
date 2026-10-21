# Phase 2 — idempotency and consistency model — spec

Status: draft. Design-gate input under issue #91: defines how Phase 2
keeps every durable effect single — idempotency keys for all commands
and steps, the transactional outbox that publishes events, the
explicit boundary between exactly-once and at-least-once effects, and
artifact finalization with duplicate prevention. No production code
is authorized by this document.

## Scope

Owns (`docs/product/phases.md` §Phase 2, workstream 6):

- idempotency keys for every command and step type;
- the transactional outbox event-publication strategy;
- the exactly-once vs at-least-once boundary map;
- artifact finalization and duplicate prevention.

Does not own: queue claim mechanics and lease allocation (spec 1);
retry classification, backoff, and attempt limits (spec 4); canonical
event field definitions (spec 6); lineage queries and read edges
(spec 7); artifact payload lifecycle and GC (Phase 1 B10).

## Locked inputs — maintainer decisions 2026-10-07

1. **Repeated commands with the same idempotency key must not create
   duplicate tasks or artifacts** — the phases.md acceptance scenario
   this spec exists to satisfy.
2. **Sibling artifact reads go through `central artifact read`** in
   the workspace; dedup of finalized artifacts is part of that CLI's
   contract — a read resolves at most one finalized artifact per name.
3. **Ambiguous session attempts are operator decisions** (locked
   decision 5): recording that decision is itself an idempotent
   command — one decision per attempt, replays return the recorded
   choice, never a second decision row.

## Design

### 1. Idempotency key table

Every Phase 2 command/step type carries a key; the backing store is a
unique constraint — the database, not caller discipline, is the
authority.

| Command / step | Idempotency key | Unique on |
| --- | --- | --- |
| submit run | `(workspace_id, run_key)` — client-chosen `run_key` | `run` |
| emit child specs (create node) | `(run_id, node_key)` | `workflow_node` |
| allocate attempt at dispatch | `(node_id, attempt_seq)` | `session_attempt` |
| record attempt outcome | `(attempt_id, outcome_kind)` | attempt journal |
| record operator decision | `(attempt_id)` — one row ever | `attempt_decision` |
| finalize artifact | `(attempt_id, artifact_name)` | `artifact` |
| commit checkpoint | `(attempt_id, checkpoint_seq)` | checkpoint schema (spec 3) |
| cancel node | `(node_id)` — idempotent by terminal state | node state machine |
| publish event | `(aggregate_id, event_seq)` | `event_outbox` PK — in Phase 2 the aggregate is the run, so the key is `(run_id, seq)` and `event_seq` IS spec 6's canonical `seq` |

### 2. Replay semantics

Same key + same payload fingerprint → return the existing record
(idempotent success; no new row). Same key + different fingerprint →
reject with `DUPLICATE_IDEMPOTENCY_KEY`; the existing record stands.
Implementation: insert relies on the unique constraint (`ON CONFLICT`
or `23505` handling), then re-reads and compares the stored
fingerprint — a SHA-256 over the canonical command payload (OQ-2). A
late second outcome report for a terminal attempt dedupes the same
way: no double transition, no second event.

### 3. Transactional outbox

Every state transition writes its event row to `event_outbox` in the
**same** PostgreSQL transaction that commits the state change —
atomicity is structural; a crash between state and event is
impossible by construction. A publisher drains unpublished rows in
per-run `seq` order (`FOR UPDATE SKIP LOCKED` batches) — `seq` is
spec 6's canonical ordering field, allocated in the transition
transaction,
marks them published, and delivers to consumers — readiness
recomputation (spec 1), journal/UI feeds. Delivery is at-least-once;
every consumer dedupes on `event_id`. Backlog depth or
oldest-unpublished age past threshold raises `OUTBOX_PUBLISH_STALLED`.

### 4. Exactly-once vs at-least-once boundary map

| Effect | Guarantee | Dedup point |
| --- | --- | --- |
| State transitions (node, attempt, lease, artifact metadata) | exactly-once | one PostgreSQL transaction + unique keys |
| Event publication to consumers | at-least-once | consumer dedup on `event_id` / `event_seq` |
| Harness session attempt execution | at-least-once | `(node_id, attempt_seq)` key + dedup at artifact finalize |
| Artifact body upload | at-least-once | retried upload rewrites the same object key; finalize is the visibility gate |
| Workspace provisioning | at-least-once | re-prepare reuses the recorded worktree/dir path |

Exactly-once is claimed only inside PostgreSQL. Everything that
crosses a process, network, or harness boundary is at-least-once and
must name its dedup point — the table is that name.

### 5. Artifact finalization — the single visibility boundary

(a) write the body to object storage under
`runs/<run_id>/attempts/<attempt_id>/artifacts/<artifact_name>`;
(b) compute and verify the checksum; (c) in ONE transaction insert
the metadata row — unique `(attempt_id, artifact_name)`, checksum,
size, media type, lineage ids — plus the `artifact_finalized` outbox
event. Readers (`central artifact read`, `artifact`-edge readiness)
see only step (c). Re-finalize with same key + same checksum returns
the existing artifact; different checksum fails with
`ARTIFACT_ALREADY_FINALIZED`. Bodies uploaded but never finalized are
invisible orphans, GC'd by the Phase 1 lifecycle.

## Failure semantics

- `DUPLICATE_IDEMPOTENCY_KEY` — key reused with a different payload
  fingerprint; command rejected, existing record unchanged.
- `ARTIFACT_ALREADY_FINALIZED` — second finalize under an existing
  `(attempt_id, artifact_name)` with a different checksum; nothing
  new becomes visible.
- `ARTIFACT_CHECKSUM_MISMATCH` — computed checksum differs from
  declared at step (b); finalize aborts pre-commit, upload may retry.
- `OUTBOX_PUBLISH_STALLED` — unpublished backlog/age beyond
  threshold; consumers lag but state stays correct — transitions
  never depend on publication.

## Open questions

- **OQ-1 — publisher topology.** In-process drain loop vs dedicated
  publisher role. Default: in-process batch drain in the central
  daemon; single-host, no external broker.
- **OQ-2 — fingerprint definition.** Default: SHA-256 over canonical
  JSON of the command payload, stored on the keyed row.
- **OQ-3 — outbox retention.** Published rows kept for replay/debug.
  Default 7 days, then GC.
- **OQ-4 — dedup journaling.** Default: replays journal a
  `command_deduped` note so operators can observe retries, rather
  than returning silently.

## Acceptance criteria

- The key table covers every Phase 2 command/step type; the phases.md
  scenario "repeated commands with the same idempotency key do not
  create duplicate tasks or artifacts" holds by construction.
- State transition + outbox row are provably one transaction, stated
  as a testable invariant.
- Every at-least-once effect in the boundary map names its dedup
  point; nothing outside PostgreSQL claims exactly-once.
- `central artifact read` resolves at most one finalized artifact per
  name; re-finalization never produces a second visible version.
- The reason-code vocabulary above is what spec 9's failure matrix
  consumes.
- Spec review verdict recorded under
  `docs/internal/superpowers/reviews/`; a slice dossier and
  implementation plan follow per the Phase 1 precedent.
