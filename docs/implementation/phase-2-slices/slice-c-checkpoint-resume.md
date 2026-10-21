# Slice 2C — Checkpoint and Resume

- **Slice ID:** 2C
- **Dossier:** `slice-c-checkpoint-resume.md`
- **Issue:** #94 — checkpoint + resume
- **Packets:** P2C01–P2C05
- **Dependency:** P2B06 (Slice 2B complete)
- **Outcome:** Durable, versioned checkpoint records written only at quiescent boundaries, an all-or-nothing resume-token preflight, correct resume of unfinished subtrees as new attempts, and garbage collection by retention class

## Governing specs

- `docs/internal/superpowers/specs/2026-10-07-phase-2-checkpoint-resume-format.md` — checkpoint record, legal boundaries, resume token + preflight, resume path, GC classes
- `docs/internal/superpowers/specs/2026-10-07-phase-2-workflow-graph-scheduling-design.md` — readiness recompute, `attempt_ambiguous` parking (consumed, not redefined)
- `docs/internal/superpowers/specs/2026-10-07-phase-2-event-schema-reconstruction.md` — `event_watermark` ordering and journaled resume/checkpoint kinds

## Slice 2C ownership

P2C01–P2C05 collectively own:

- the `central.checkpoint/v1` record: subtree-anchored, watermark-pinned, carrying `harness_session_id` + `workspace_digest` — never serialized loop state (ADR 0035);
- legal-boundary enforcement — checkpoint writes only inside one transaction at a journal watermark while the anchor attempt is quiescent;
- the opaque resume token and all-or-nothing compatibility preflight;
- resume execution: ready-set rebuild, new `attempt_seq` dispatch, ambiguous parking, readable-artifact-set re-exposure (lazy payloads via `central artifact read`);
- GC classes (`supersedeable`/`run_terminal`/`pinned`), the scheduled janitor, and `central checkpoint gc`.

Slice 2C must not implement retry/backoff policy (2D), lease mechanics (2B), lineage edges (2A), or UI rendering (2E). Checkpoint *timing* policy is owned here per the spec gate ("when checkpoints are taken" is slice-dossier policy).

## Packets

- **P2C01** — Checkpoint schema and migration: the `central.checkpoint/v1` record with subtree anchor, watermark, digest, and GC class
- **P2C02** — Boundary enforcement and write path: quiescent-anchor check, single-transaction watermark-pinned write, workspace digest, and the take-checkpoint policy
- **P2C03** — Resume token and preflight: opaque token, all-or-nothing compatibility validation with safe failure codes
- **P2C04** — Resume execution: ready-set rebuild, fresh attempts, `RESUME_REQUIRES_OPERATOR_DECISION` parking, readable-set restoration
- **P2C05** — Checkpoint GC: retention classes, scheduled janitor, `central checkpoint gc` verb, checkpoint rows only

## P2C01

### Identity and outcome

Implement the checkpoint record schema and migration: one row per checkpoint carrying `checkpoint_id`, `run_id`, `node_id` anchor, `attempt_id`, `format_version`, `graph_schema_version`, `event_watermark`, `harness_session_id`, `workspace_digest`, `completed_nodes`, `finalized_artifacts`, `gc_class`, `created_at`, `expires_at`.

### Implementation boundary

The anchor `node_id` scopes the checkpoint to that node's entire subtree (root ⇒ whole run; children spawn children to depth 3). `completed_nodes` lists subtree node keys `succeeded` at or before the watermark; `finalized_artifacts` lists artifact ids the subtree's remaining work may read. Per-attempt session ids/paths for other subtree nodes already live on `session_attempt` rows — never duplicated into the checkpoint.

### Durable data and migration

New migration adding the checkpoint table. PostgreSQL is the source of truth; checkpoint rows reference artifacts by id — bodies stay in object storage.

### Security and authority

The record carries identifiers and digests only — no prompt text, secrets, or unsanitized paths beyond the workspace digest's own manifest rules.

### Failure, retry, cancellation, and recovery

A malformed or unverifiable checkpoint write fails before commit; partial checkpoint rows are impossible (single-transaction writes, P2C02).

### Verification and evidence

- Migration creates the checkpoint table with all spec'd fields
- `format_version`/`graph_schema_version`/`event_watermark`/`gc_class` present and constrained
- Subtree anchor covers descendants to depth cap
- Evidence artifact: `phase-2-slice-c-checkpoint-schema.json`

### Scope control

P2C01 owns the record schema only — not write boundaries, resume, or GC.

### Definition of Done

The checkpoint record exists via migration, anchors a subtree, and carries every field the resume preflight consumes.

## P2C02

### Identity and outcome

Implement the checkpoint write path: legal-boundary enforcement (quiescent anchor, single watermark-pinned transaction), workspace digest computation, and the slice-level policy for when checkpoints are taken.

### Implementation boundary

A write is legal only inside one transaction pinned to an `event_watermark`, and only when the anchor attempt is quiescent — outcome journaled (terminal or `attempt_ambiguous`) or session paused/cancelled — so `workspace_digest` computes over a stable tree (manifest digest of path/size/content-hash for `plain`; `HEAD` + status-porcelain digest for `code`, per spec OQ-3). Requests in the invoke window, between claim and `attempt_started`, or during a subtree artifact mid-finalization refuse with journaled `checkpoint_refused` / `CHECKPOINT_BOUNDARY_ILLEGAL`. Other in-flight subtree attempts don't block — they're recorded and treated as ambiguous at resume. **Take policy (dossier-owned):** automatic `run_terminal` checkpoint at run completion; operator-invoked `central checkpoint create` at any quiescent boundary; pre-GC supersede chain per P2C05. Journals `checkpoint_written`/`checkpoint_refused`.

### Durable data and migration

Writes ride the P2C01 table; `workspace_digest` null only when the anchor never opened a workspace.

### Security and authority

`central checkpoint create` is an operator command through the domain service. Digest manifests follow the A06 path-hygiene rules — no symlink escapes into the digest.

### Failure, retry, cancellation, and recovery

Illegal boundary → refused + journaled; operator retries after quiescence. Digest failure aborts the write pre-commit — no partial checkpoint.

### Verification and evidence

- Mid-invoke request refuses `CHECKPOINT_BOUNDARY_ILLEGAL`
- Quiescent write commits record + `checkpoint_written` in one transaction
- Digest is stable across identical trees and detects any mutation
- In-flight sibling attempts recorded, not blocking
- Future test suite: `go test ./internal/checkpoint/...`
- Evidence artifact: `phase-2-slice-c-checkpoint-write.json`

### Scope control

P2C02 owns boundary legality and the write path plus take policy. It must not validate resume tokens, rebuild ready sets, or collect garbage.

### Definition of Done

Checkpoints commit only at provably quiescent, watermark-pinned boundaries; every refusal is journaled with an actionable code.

## P2C03

### Identity and outcome

Implement the resume token and all-or-nothing preflight: an opaque `resume_token` carrying `checkpoint_id` + content digest; every check passes before any node is dispatched, or `resume_failed` journals a reason code and run state is unchanged.

### Implementation boundary

Preflight order: (1) token resolves to an existing unexpired checkpoint — else `RESUME_TOKEN_STALE`; (2) `format_version` readable by this build and `graph_schema_version` compatible with current child-spec validation — else `CHECKPOINT_INCOMPATIBLE` (details recorded); (3) `workspace_digest` matches the recorded workspace path's current digest — else `WORKSPACE_DIGEST_MISMATCH`; (4) every `finalized_artifacts` entry still exists and is `finalized` — else `CHECKPOINT_ARTIFACT_MISSING`. All-or-nothing: no sibling-subtree partial resume (spec OQ-4 default).

### Durable data and migration

No new state; preflight reads the P2C01 row plus live artifact/workspace state. `resume_started`/`resume_failed` journal per P2A04.

### Security and authority

Resume is an operator command; the token is bearer-scoped to its run and validated by content digest — a forged or mutated token fails check 1–2.

### Failure, retry, cancellation, and recovery

This packet defines safe failure: every preflight violation maps to its reason code and operator remediation (newer checkpoint, version-aligned binary, workspace inspection, upstream re-production).

### Verification and evidence

- GC'd/expired token → `RESUME_TOKEN_STALE`
- Version-incompatible checkpoint → `CHECKPOINT_INCOMPATIBLE` with recorded detail — fails safely per the Phase 2 acceptance scenario
- Mutated workspace → `WORKSPACE_DIGEST_MISMATCH`
- Missing finalized artifact → `CHECKPOINT_ARTIFACT_MISSING`
- Any failure leaves run state untouched
- Future test suite: `go test ./internal/checkpoint/...`
- Evidence artifact: `phase-2-slice-c-resume-preflight.json`

### Scope control

P2C03 owns token resolution and preflight only. It must not dispatch resumed nodes or decide ambiguous outcomes.

### Definition of Done

Resume validates completely before any effect; an incompatible checkpoint fails safely with an actionable reason code.

## P2C04

### Identity and outcome

Implement resume execution: rebuild the subtree's ready set from the checkpoint, dispatch unfinished nodes as new attempts, park ambiguous anchors for operator decision, and re-expose the readable artifact set.

### Implementation boundary

After preflight: subtree nodes not in `completed_nodes` and not `cancelled` return to `ready`, recomputed from edges per spec-1 readiness; unfinished nodes dispatch as **new** attempts (new `attempt_seq`, fresh session — no harness state assumed). A node whose last attempt was in-flight at the watermark or already `attempt_ambiguous` parks with `RESUME_REQUIRES_OPERATOR_DECISION` until the operator picks harness-native resume (requires recorded `harness_session_id` + matching `workspace_digest`) or fresh rerun — one idempotent `attempt_decision` row per attempt (2D05). Sibling inputs re-expose as the validated readable artifact set — payloads fetched lazily by `central artifact read`, never materialized into the workspace. Journals `resume_started`/`resume_completed`.

### Durable data and migration

Resume mutates node states through the domain service and allocates new `session_attempt` rows under the P2B01 claim machinery — no bypass.

### Security and authority

Harness-native resume uses only the recorded session id — Central never reconstructs or replays loop state (ADR 0035). Operator decision commands are idempotent and journaled.

### Failure, retry, cancellation, and recovery

Post-preflight dispatch failures follow 2B dispatch semantics; a newly ambiguous attempt re-parks under the same rule — resume never auto-decides.

### Verification and evidence

- Resumed subtree re-dispatches only unfinished nodes, each a fresh `attempt_seq`
- Completed subtree nodes stay `succeeded`; cancelled stay `cancelled`
- Ambiguous anchor halts that node with `RESUME_REQUIRES_OPERATOR_DECISION`; both resolutions work
- Readable set re-exposed; `central artifact read` fetches lazily in the new workspace
- `resume_completed` journals after the ready set rebuilds
- Future test suite: `go test ./internal/checkpoint/...`
- Evidence artifact: `phase-2-slice-c-resume-execute.json`

### Scope control

P2C04 owns resume execution. It must not alter the retry budget accounting (2D) or make ambiguous decisions automatically.

### Definition of Done

A validated checkpoint resumes its subtree correctly: finished work stays finished, unfinished work re-dispatches fresh, and ambiguity waits on the operator.

## P2C05

### Identity and outcome

Implement checkpoint garbage collection: retention by `gc_class`, the scheduled janitor inside `central serve`, and the manual `central checkpoint gc` verb.

### Implementation boundary

`supersedeable`: deleted once a newer checkpoint exists for the same `(run_id, node_id)` anchor or `expires_at` passes — keep latest 3 per anchor (spec OQ-1 default). `run_terminal`: retained for the run-history window (default 30 days). `pinned`: never collected — operator pin/unpin via the domain service. GC deletes only checkpoint rows — never attempts, events, or artifacts. Each deletion journals `checkpoint_gc_collected`.

### Durable data and migration

GC operates on the P2C01 table; no new schema beyond a `pinned` flag already implied by `gc_class`.

### Security and authority

`central checkpoint gc` and pin/unpin are operator commands; GC can never delete the only checkpoint keeping a resumable run alive without that being the documented class rule.

### Failure, retry, cancellation, and recovery

A deleted checkpoint surfaces later as `RESUME_TOKEN_STALE` — safe, actionable. Janitor failure retries next cycle; partial GC passes are harmless (deletions are independent).

### Verification and evidence

- Fourth supersedeable checkpoint collects the oldest for that anchor
- `run_terminal` survives within the retention window; `pinned` never collected
- GC never touches attempts, events, or artifacts
- `central checkpoint gc` runs a manual pass; deletions journal `checkpoint_gc_collected`
- Future test suite: `go test ./internal/checkpoint/...`
- Evidence artifact: `phase-2-slice-c-checkpoint-gc.json`

### Scope control

P2C05 owns checkpoint retention only. It must not GC artifacts (B10 lifecycle), events (spec 6 default: no Phase 2 event GC), or workspaces.

### Definition of Done

Checkpoints collect predictably by class, the operator can pin and manually collect, and no non-checkpoint state is ever deleted.

## Slice acceptance

**Gate:** `S2C-G1` — **Evidence:** `phase-2-slice-c-acceptance.json`

Slice 2C is complete when:

1. P2C01–P2C05 contracts are verified with passing tests
2. Checkpoints commit only at quiescent watermark-pinned boundaries; mid-effect requests refuse `CHECKPOINT_BOUNDARY_ILLEGAL` (P2C02)
3. Resume preflight is all-or-nothing; every incompatibility fails safely with its named code (P2C03)
4. A resumed subtree re-dispatches only unfinished nodes as new attempts; ambiguous anchors park for operator decision (P2C04)
5. Readable artifact sets re-expose lazily through `central artifact read`; no payload materialization (P2C04, 2A06)
6. GC honors `supersedeable`/`run_terminal`/`pinned` and touches checkpoint rows only (P2C05)
7. No serialized harness loop state exists anywhere — `harness_session_id` + `workspace_digest` only (ADR 0035)
8. The complete Slice 2C acceptance evidence is durably recorded

Slice 2C must not claim retry policy, leasing, lineage, or UI capabilities — those are Slices 2B, 2D, 2E.
