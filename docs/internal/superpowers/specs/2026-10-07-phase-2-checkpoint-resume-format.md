# Phase 2 — checkpoint and resume format — spec

Status: draft. Design-gate input under issue #91 (spec 3 of the Phase 2
deliverables table): specifies the durable checkpoint record and its
versioning, the boundaries at which writing a checkpoint is legal, the
resume-token and compatibility-validation contract, and checkpoint
garbage collection. No production code is authorized by this document;
implementation follows a reviewed plan and a
`docs/implementation/phase-2-slices/` dossier per the Phase 1 precedent.

## Scope

Owns:

- the checkpoint record schema and format versioning;
- safe checkpoint boundaries — a checkpoint is written only at a
  durable boundary, never mid-side-effect;
- the resume token and its compatibility validation — an incompatible
  checkpoint fails safely with an actionable reason code;
- checkpoint garbage-collection classes and rules.

Does not own: *when* checkpoints are taken (slice-dossier policy per
the spec-gate spec), worker heartbeat and lease mechanics (spec 2),
retry/backoff policy (spec 4), canonical event field definitions
(spec 6), artifact payload lifecycle (Phase 1 B10 / spec 7).

## Locked inputs — maintainer decisions 2026-10-07

1. **A checkpoint records a harness session identifier and a
   workspace-state digest — never serialized loop state** (ADR 0035,
   amended ADR 0004 clause). Central never reconstructs, replays, or
   infers harness-internal loop state.
2. **Ambiguous attempts are operator decisions.** A session attempt
   interrupted after launch is `attempt_ambiguous`; resume offers
   harness-native resume (by recorded harness session id, where the
   harness supports it) or a fresh rerun — chosen by the operator,
   never automatic.
3. **Children may spawn children** — a checkpoint anchored at a node
   captures that node's entire subtree state, not one level.
4. **Sibling data flow via `central artifact read`** — resume restores
   the *readable artifact set* (which finalized artifacts a node may
   read); it never materializes artifact payloads into a workspace.

## Design

### D1 — Checkpoint record

One row per checkpoint, stored in PostgreSQL (the source of truth);
artifact bodies remain in object storage.

| field | meaning |
| --- | --- |
| `checkpoint_id` | unique identifier; embedded in the resume token |
| `run_id` | owning run |
| `node_id` | anchor node; the checkpoint covers this node's subtree (root node ⇒ whole run) |
| `attempt_id` | anchor attempt whose session/workspace the record carries |
| `format_version` | checkpoint record schema, e.g. `central.checkpoint/v1` |
| `graph_schema_version` | child-spec/graph schema the subtree was validated under (`central.child-spec/v1`) |
| `event_watermark` | journal sequence number the snapshot is consistent at |
| `harness_session_id` | anchor attempt's harness session identifier (nullable) |
| `workspace_digest` | digest of the anchor attempt's workspace at the boundary (nullable — see D2) |
| `completed_nodes` | node keys in the subtree that reached `succeeded` at or before the watermark |
| `finalized_artifacts` | artifact ids the subtree's remaining work may read via `central artifact read` |
| `gc_class` | `supersedeable` \| `run_terminal` \| `pinned` |
| `created_at`, `expires_at` | timestamps driving GC |

Per-attempt session ids and workspace paths for all other subtree
nodes are already durable on `session_attempt` rows; the checkpoint
does not duplicate them.

### D2 — Legal checkpoint boundaries

A checkpoint write is legal only inside one transaction pinned to a
journal watermark, and only when the anchor attempt is **quiescent**:
its outcome is journaled (terminal or `attempt_ambiguous`), or the
session is paused/cancelled — i.e. the workspace is not mutating and
`workspace_digest` is computed over a stable tree. `workspace_digest`
is null only when the anchor attempt never opened a workspace.

A checkpoint is **refused** — journaled `checkpoint_refused` with
reason `CHECKPOINT_BOUNDARY_ILLEGAL` — when requested while the anchor
attempt is in its invoke window (mid-side-effect), while its node is
between claim and `attempt_started`, or while a subtree artifact is
mid-finalization. Other in-flight subtree attempts do not block the
write; they are recorded as in-flight and treated as ambiguous at
resume.

### D3 — Resume token and compatibility validation

`resume_token` is an opaque string carrying `checkpoint_id` + the
record's content digest. Resume runs an **all-or-nothing preflight** —
every check below passes before any node is dispatched; any failure
journals `resume_failed` with a reason code and leaves run state
unchanged:

1. token resolves to an existing, unexpired checkpoint — else
   `RESUME_TOKEN_STALE`;
2. `format_version` is readable by this build and
   `graph_schema_version` is compatible with current child-spec
   validation — else `CHECKPOINT_INCOMPATIBLE` (details recorded vs
   current version);
3. `workspace_digest` matches the current digest of the recorded
   workspace path — else `WORKSPACE_DIGEST_MISMATCH`;
4. every artifact in `finalized_artifacts` still exists and is
   `finalized` — else `CHECKPOINT_ARTIFACT_MISSING`.

### D4 — Resume path

validate token → verify compatibility (D3) → rebuild the ready set:
subtree nodes not in `completed_nodes` and not `cancelled` return to
`ready`, recomputed from edges per spec 1 readiness → unfinished nodes
dispatch as **new attempts** (new `attempt_seq`, fresh session; no
harness state is assumed to survive). A node whose last attempt was
recorded in-flight at the watermark, or already `attempt_ambiguous`,
parks at `attempt_ambiguous`: resume halts for that node with reason
`RESUME_REQUIRES_OPERATOR_DECISION` until the operator picks
harness-native resume (requires `harness_session_id` + matching
`workspace_digest`) or fresh rerun. Sibling inputs are re-exposed as
the validated readable artifact set — payloads are fetched lazily by
`central artifact read` inside the new workspace, never restored.

### D5 — Checkpoint GC

- `supersedeable`: eligible for deletion once a newer checkpoint exists
  for the same `(run_id, node_id)` anchor or `expires_at` passes.
- `run_terminal`: written at run completion; retained for the
  run-history window.
- `pinned`: operator-pinned; never garbage-collected.

GC deletes only the checkpoint row — never attempts, events, or
artifacts. Minimum events this spec introduces: `checkpoint_written`,
`checkpoint_refused`, `resume_started`, `resume_completed`,
`resume_failed`, `checkpoint_gc_collected` (field definitions: spec 6).

## Failure semantics

| reason code | meaning | operator action |
| --- | --- | --- |
| `RESUME_TOKEN_STALE` | checkpoint GC'd or expired | resume from a newer checkpoint or rerun the node |
| `CHECKPOINT_INCOMPATIBLE` | format or graph schema version unreadable | upgrade/downgrade Central, or rerun incompatible nodes fresh |
| `WORKSPACE_DIGEST_MISMATCH` | workspace changed since the checkpoint | inspect workspace; fresh rerun (harness-native resume barred) |
| `CHECKPOINT_ARTIFACT_MISSING` | a finalized artifact in the readable set is gone | re-produce the artifact upstream, then resume |
| `RESUME_REQUIRES_OPERATOR_DECISION` | ambiguous attempt blocks auto-dispatch | choose harness-native resume or fresh rerun |
| `CHECKPOINT_BOUNDARY_ILLEGAL` | checkpoint requested mid-side-effect | retry after the attempt reaches a quiescent state |

## Open questions

- **OQ-1 — retention count.** Default: keep latest 3 `supersedeable`
  checkpoints per `(run_id, node_id)` anchor; `run_terminal` kept for
  the run retention window (proposed 30 days).
- **OQ-2 — GC trigger.** Default: scheduled janitor inside
  `central serve`, plus a manual `central checkpoint gc` operator verb.
- **OQ-3 — workspace digest algorithm.** Default: manifest digest over
  (path, size, content hash) for plain workspaces; `HEAD` +
  status-porcelain digest for git worktrees. Detail may be delegated to
  the slice dossier.
- **OQ-4 — partial resume.** Whether preflight failure may resume
  unaffected sibling subtrees. Default: no — all-or-nothing.

## Acceptance criteria

- Spec review records a verdict under `docs/internal/superpowers/reviews/`.
- Every locked input is encoded as a rule or carried as a numbered OQ.
- Every reason code above maps to an operator-actionable remediation;
  an incompatible checkpoint fails safely with that reason
  (`docs/product/phases.md` Phase 2 acceptance scenario).
- A slice dossier and implementation plan follow this spec per the
  Phase 1 precedent.
