# Phase 2 — event schema and reconstruction rules — spec

Status: draft. Design-gate input under issue #91 (spec 6 of nine in
`2026-10-07-phase-2-spec-gate-design.md`): defines the canonical event
envelope, ordering guarantees, and the rules that rebuild
task/run/graph state from the event journal. No production code is
authorized; implementation follows a reviewed plan and a
`docs/implementation/phase-2-slices/` dossier per the Phase 1 precedent.

## Scope

From `docs/product/phases.md` §Phase 2 workstream 7 (event history and
lineage): immutable execution events, task and run reconstruction, and
the prompt/model/tool/configuration version record. This spec owns:

- the canonical event field set every emitting spec writes to;
- ordering guarantees and their stated limits;
- reconstruction (fold) rules for node state, attempt history, graph
  shape, and artifact references;
- recording prompt/model/tool/configuration versions as event payload
  fields.

It does **not** own which event names exist — each owning spec declares
its own minimum set (spec 1 already has); this spec collects and indexes
them in the catalog (decision 6). It does not own artifact lineage
modeling (spec 7), artifact payload lifecycle (Phase 1 B10), or UI
rendering of history (the UI slice dossier).

## Locked inputs — maintainer decisions 2026-10-07

1. **Events are read-only evidence.** Harness-produced events are
   ingested as read-only evidence and are never inputs to loop
   decisions (ADR 0035 §4). Central-authored events journal Central's
   own transitions; nothing in this spec may steer a live harness loop.
2. **Append-only, no deletes.** The graph is append-only (spec 1
   locked input 2) and the event journal is append-only —
   reconstruction never applies deletes or updates; corrections arrive
   as new events.

## Design

1. **Canonical envelope.** Every journaled event is one row:
   `{event_id, run_id, seq, node_id?, attempt_id?, kind, recorded_at,
   actor, reason_code?, payload}`.
   - `event_id` — globally unique; the ingest idempotency key.
   - `run_id` — required; every event belongs to exactly one run.
   - `seq` — per-run monotonic sequence (decision 2).
   - `node_id?` — absent only on run-scope kinds (e.g.
     `child_spec_rejected`).
   - `attempt_id?` — present only on attempt-scope kinds.
   - `kind` — a cataloged string (decision 6).
   - `recorded_at` — writer timestamp; diagnostic only, never ordering.
   - `actor` — emitter identity: `scheduler`, `worker:<id>`,
     `leader:<session>`, `operator:<id>`, `reconciler`, `ingest`.
   - `reason_code?` — machine-stable code on failure/rejection kinds.
   - `payload` — kind-versioned JSON object (decision 5, OQ-5).
2. **Ordering guarantees.** `seq` is a per-run monotonically increasing
   integer allocated in the same transaction that applies the
   transition the event journals (spec 1 atomic-claim precedent).
   Guarantees: total order within a run; **no wall-clock ordering
   claims across nodes** — `recorded_at` skew is never evidence of
   causality; cross-node causality flows only through edges and event
   references. Gaps are tolerated: a missing `seq` means a journaled
   write lost its commit or an ingest failed; it surfaces as
   `EVENT_SEQUENCE_GAP`, never silently interpolated.
3. **Storage.** One append-only PostgreSQL table — metadata only
   (AGENTS.md): payloads carry artifact references as
   `(artifact_id, checksum)` pairs; artifact bodies stay in object
   storage and are never inlined. Payloads must not embed secrets,
   rendered prompt text, or unsanitized filenames — those live as
   artifacts referenced by id. Writers INSERT only; no update or
   delete path exists in the writer API.
4. **Reconstruction rules.** Reconstruction folds a run's events in
   `(run_id, seq)` order. Per node, the fold of the last applicable
   kinds is:

   | Folded evidence | Node state |
   | --- | --- |
   | `node_declared` | `declared` |
   | `node_ready` | `ready` |
   | `node_dispatched`, attempt open | `dispatched` |
   | `attempt_started`, attempt open | `running` |
   | `attempt_failed` then retry-path `node_ready` | `ready` |
   | `attempt_ambiguous`, unresolved | `attempt_ambiguous` |
   | `node_succeeded` | `succeeded` |
   | `node_failed_terminal` | `failed_terminal` |
   | `node_cancelled` | `cancelled` |

   Attempt history = events grouped by `attempt_id`, each attempt
   ordered by `seq`. Graph shape = the fold of `node_declared`
   payloads, which carry `depends_on` edges; expansion batches append
   nodes/edges, matching the append-only rule. Artifact references =
   the union of payload `(artifact_id, checksum)` refs, indexed by
   producing node/attempt. `child_spec_rejected` folds to no node
   state — run-scope evidence only. Fold output is a derived
   projection; where it disagrees with materialized current state the
   finding is `RECONSTRUCTION_DIVERGED`, never a silent rewrite.
5. **Versioning record.** `node_dispatched` and `attempt_started`
   payloads carry a `versions` object: `{spec_version, adapter,
   adapter_version, model, model_version, tools_digest, config_digest,
   prompt_ref}` — `spec_version` pins the child-spec schema; digests
   pin the tool manifest and resolved configuration; `prompt_ref` is
   an artifact `(id, checksum)` of the rendered prompt, never prompt
   text. Model or tool changes across retries appear as new attempt
   payloads, so behavior and cost are attributable per attempt
   (vision: observable execution).
6. **Event catalog.** Index of kinds: spec 1's declared set plus
   placeholders for specs still being drafted. `T<n>` names the
   spec-gate deliverable-table row; reviewers cross-check each owning
   spec's minimum set against this index.

   | Entry | Expected kinds | Status |
   | --- | --- | --- |
   | spec 1 — workflow graph + scheduling | `node_declared`, `node_ready`, `node_dispatched`, `attempt_started`, `attempt_succeeded`, `attempt_failed`, `attempt_ambiguous`, `node_succeeded`, `node_failed_terminal`, `node_cancelled`, `child_spec_rejected` | declared |
   | spec 2 — task leasing + worker protocol | `worker_registered`, `worker_deregistered`, `worker_suspect`, `worker_lost`, `lease_expired`, `lease_renewal_rejected` (heartbeats are row updates, not events) | declared |
   | spec 3 — checkpoint + resume | `checkpoint_written`, `checkpoint_refused`, `resume_started`, `resume_completed`, `resume_failed`, `checkpoint_gc_collected` | declared |
   | spec 4 — retry + timeout taxonomy | `attempt_retry_scheduled`, `compensation_requested`; exhaustion/timeouts ride `attempt_failed`/`node_failed_terminal` with reason codes (`RETRY_BUDGET_EXHAUSTED`, `NODE_TIMEOUT`, `WORKFLOW_TIMEOUT` — the latter on the root node) | declared |
   | spec 5 — idempotency + consistency | `command_deduped`, `attempt_decision`; outbox publication is mechanics — dedup on `event_id`/`seq` | declared |
   | spec 6 — event schema (this spec) | none — ingest/fold failures are reason codes, not events (OQ-4) | declared |
   | spec 7 — artifact lineage | `artifact_finalized` plus journaled produce/read lineage-edge events | declared |
   | spec 8 — concurrency + limits | `admission_deferred` (deferral is pre-attempt; budget/cap rejections ride `child_spec_rejected`/`attempt_failed` with spec-8 reason codes) | declared |

   New kinds are added only by their owning spec; the catalog is the
   index ingest uses to detect undeclared kinds (`UNKNOWN_EVENT_KIND`).

## Failure semantics

Reason codes introduced here (precedent: `PREPARE_UNAVAILABLE`):

- `EVENT_SEQUENCE_GAP` — `seq` gap detected at fold/audit; run flagged,
  gap range recorded, fold continues on available events.
- `DUPLICATE_EVENT_ID` — ingest re-delivery deduped by `event_id`;
  idempotent, not an error.
- `UNKNOWN_EVENT_KIND` — kind absent from catalog; stored raw, excluded
  from fold, flagged as spec drift.
- `INVALID_EVENT_PAYLOAD` — payload fails its kind's schema; stored
  raw, excluded from fold.
- `ORPHAN_EVENT` — `node_id`/`attempt_id` references nothing the fold
  has seen; retained and flagged.
- `RECONSTRUCTION_DIVERGED` — fold output disagrees with materialized
  node/run state; blocks trusting the projection until reconciled.

## Open questions

- **OQ-1 — `seq` allocation.** Default: per-run counter advanced in the
  transition transaction (run-row lock serializes writers); a `BIGINT`
  sequence per run is the fallback if contention shows.
- **OQ-2 — run-scope kinds.** Default: the root node's `node_*` kinds
  carry run lifecycle; a `run_*` family is added only if
  reconstruction needs it.
- **OQ-3 — retention/GC.** Default: events live for the run's
  retention window; no Phase 2 event GC (checkpoint GC, spec 3, may
  later name it).
- **OQ-4 — ingest failures as events?** Default no — they are reason
  codes on the ingest/fold path, keeping the evidence stream free of
  self-referential entries; a reviewer may invert this.
- **OQ-5 — payload versioning.** Default: `payload_version` integer
  per kind; readers must fold every declared version and flag
  undeclared ones `INVALID_EVENT_PAYLOAD`.

## Acceptance criteria

- Spec review records a verdict under
  `docs/internal/superpowers/reviews/`.
- Envelope fields, ordering guarantee, and append-only rule are stated
  as testable assertions.
- Catalog indexes every spec-1 kind; T2–T8 placeholders name expected
  kinds for cross-check when specs 2–8 land.
- Fold rules cover every spec-1 node state including retry-return and
  ambiguous branches; graph reconstruction follows `node_declared`
  payloads.
- All six reason codes above are named.
- No contradiction with spec 1 vocabulary, the ADR 0022 gate
  boundaries, or ADR 0035 (events never become loop inputs).
