# Slice 2E — Graph UI and Operator Controls

- **Slice ID:** 2E
- **Dossier:** `slice-e-graph-ui.md`
- **Issue:** #96 — graph UI + operator controls
- **Packets:** P2E01–P2E06
- **Dependency:** P2D06 (Slice 2D complete)
- **Outcome:** Server-rendered run-graph UI with per-node attempt history, event timeline, and artifact lineage overlay, plus operator controls for cancel cascade, ambiguous-attempt resolution, resume, and checkpoint management — all through idempotent domain-service commands

## Governing specs

- `docs/internal/superpowers/specs/2026-10-07-phase-2-event-schema-reconstruction.md` — the journal and fold output the UI renders; `versions` record display
- `docs/internal/superpowers/specs/2026-10-07-phase-2-artifact-lineage.md` — `run_lineage`, produced/read sets, undeclared-read flag rendering
- `docs/internal/superpowers/specs/2026-10-07-phase-2-workflow-graph-scheduling-design.md` — node states, cancel cascade, ambiguous parking (rendered, not redefined)
- `docs/internal/superpowers/specs/2026-10-07-phase-2-task-leasing-worker-protocol.md` — worker/lease status surfaces (rendered)
- `docs/internal/superpowers/specs/2026-10-07-phase-2-checkpoint-resume-format.md` — resume-token + checkpoint surfaces (rendered)
- Phase 1 precedent: B11 read-only task projections and operator-flow specs for server-rendered conventions

## Slice 2E ownership

P2E01–P2E06 collectively own:

- read-only projections over the journal, graph, and lineage tables — server-rendered HTML, minimal JavaScript, PostgreSQL-authoritative;
- the run graph DAG view, node/attempt detail with reason codes and `versions` record, and the event timeline;
- the artifact lineage overlay: produced/read sets per node, undeclared reads flagged, `run_lineage` provenance view, `prompt_ref` rendered as an artifact link — never prompt text;
- operator controls: cancel node/run, resolve `attempt_ambiguous` (harness-native resume vs fresh rerun — the locked operator decision), resume by token, checkpoint create/pin/gc;
- observability surfaces for workers/leases, deferred admissions, and outbox health;
- accessibility and security conformance inherited from B06/B11: sanitization, `aria-live`, security headers, and the restart-reconciliation banner extended to run scope.

Slice 2E must not mutate state outside domain-service commands, embed a general JS framework, or render unjournaled data. It reads; it never decides.

## Packets

- **P2E01** — Run and graph read projections: PostgreSQL-backed queries for run list, graph shape, node states, and materialized-vs-folded divergence surfacing
- **P2E02** — Graph DAG view and attempt detail: node states with reason codes, attempt history, `versions` record, event timeline
- **P2E03** — Artifact lineage UI: produce/read edges, undeclared-read flags, `run_lineage` provenance view, artifact download via scope-checked reads
- **P2E04** — Operator controls: cancel cascade, ambiguous resolution, resume-by-token, checkpoint create/pin/gc — all idempotent commands
- **P2E05** — Fleet observability: worker/lease status, suspect/lost banners, deferred admissions, outbox backlog
- **P2E06** — Accessibility and security conformance: sanitization, `aria-live`, security headers, reconciliation banner, evidence

## P2E01

### Identity and outcome

Implement the read projections backing the UI: run listing, per-run graph shape, node states, and attempt summaries — queries over PostgreSQL with the P2A05 fold available for verification; `RECONSTRUCTION_DIVERGED` surfaces as a banner, never silently preferred state.

### Implementation boundary

Server-side queries only (B11 precedent): run list keyset-paginated; graph projection returns nodes, edges, states, and reason codes; attempt history per node ordered by `attempt_seq`. Projections read materialized state plus the journal; where they diverge the UI flags it.

### Durable data and migration

No new state — projections are read-only over P2A/2B tables. No migration.

### Security and authority

Read surface is operator-scoped behind the existing serve auth; no artifact bodies or prompt text ever inline — only `(id, checksum)` references.

### Failure, retry, cancellation, and recovery

A missing/diverged projection renders an explicit empty/error state, never stale data presented as current.

### Verification and evidence

- Run list and graph projections return correct state for multi-level runs
- Divergence between fold and materialized state renders the warning banner
- Keyset pagination holds over large runs
- Future test suite: `go test ./internal/ui/...` (projection tests)
- Evidence artifact: `phase-2-slice-e-projections.json`

### Scope control

P2E01 owns query projections only — no rendering, no commands.

### Definition of Done

Every UI view has a correct, authoritative, divergence-aware projection behind it.

## P2E02

### Identity and outcome

Implement the run graph DAG view and node/attempt detail: the graph renders nodes with state badges and reason codes; drilling into a node shows attempt history, the `versions` record, and its event timeline.

### Implementation boundary

Server-rendered DAG (nested list + minimal JS for layout — no framework). Node states render the full machine: `declared`, `ready` (including `not_before`-deferred), `dispatched`, `running`, `succeeded`, `failed_terminal`, `attempt_ambiguous`, `cancelled`. Attempt detail shows per-attempt `versions` (`spec_version`, adapter, model, digests, `prompt_ref` as artifact link) so behavior and cost attribute per attempt. Timeline renders the node's journaled events in `seq` order; run-scope events (`child_spec_rejected`) attach to the run view naming offending keys.

### Durable data and migration

Renders P2E01 projections; no new state.

### Security and authority

`node_key`, artifact names, and reason strings sanitize through the B11 Markdown/HTML hygiene path; raw harness output is never rendered (ADR 0035 — the journal carries metadata, not loop text).

### Failure, retry, cancellation, and recovery

An `attempt_ambiguous` node renders its parked state and pending-decision affordance (control in P2E04); a `RECONSTRUCTION_DIVERGED` run renders the banner from P2E01.

### Verification and evidence

- DAG renders depth-3 graphs correctly with edge kinds distinguished
- Every state + reason code has a distinct accessible rendering
- Attempt history shows per-attempt versions including `prompt_ref` link
- `child_spec_rejected` renders offending keys on the run view
- Browser acceptance: Firefox ≥115, Chromium ≥115 (B12 baseline)
- Evidence artifact: `phase-2-slice-e-graph-view.json`

### Scope control

P2E02 owns rendering only — no mutations, no polling server state outside the standard refresh mechanism.

### Definition of Done

An operator can read any run's graph, every node's state and history, and each attempt's provenance record without leaving the UI.

## P2E03

### Identity and outcome

Implement the artifact lineage UI: per-node produced/read sets, lineage overlay on the DAG, `run_lineage` provenance view, flagged undeclared reads, and scope-checked artifact download.

### Implementation boundary

Renders the P2A06 query surface: `produced(node)`/`read(node)` per node, `ancestors`/`descendants` on artifact click, and `run_lineage(run_id)` as the run's provenance view answering "how every final artifact was produced". Undeclared reads render flagged, never hidden. Download routes through the same scope enforcement as `central artifact read` (operator reads attribute to a synthetic operator reader per spec-7 OQ-5). `prompt_ref` links resolve to the artifact, never inline text.

### Durable data and migration

Read-only over lineage relations; no new state.

### Security and authority

Downloads re-verify checksums and journal operator read edges; scope denial renders `ARTIFACT_SCOPE_DENIED` as an explicit state.

### Failure, retry, cancellation, and recovery

Unreadable (`rejected`/non-finalized) artifacts render their lifecycle state; integrity failures surface `ARTIFACT_BODY_INTEGRITY` rather than serving corrupt bytes.

### Verification and evidence

- `run_lineage` view traces every final artifact to its producing attempt
- Undeclared reads display the flag prominently
- Artifact download honors scope and checksum verification
- Orphan/invisible-state artifacts never render as readable
- Evidence artifact: `phase-2-slice-e-lineage-ui.json`

### Scope control

P2E03 owns lineage rendering and operator read path. It must not create edges (journaled at production/read time, 2A06) or mutate lifecycle state.

### Definition of Done

The UI answers per-node and per-run provenance completely, flags undeclared reads, and serves artifacts only under verified scope.

## P2E04

### Identity and outcome

Implement operator controls: cancel node/run (cascade), resolve `attempt_ambiguous` (harness-native resume vs fresh rerun), resume via `resume_token`, and checkpoint create/pin/gc — every control an idempotent domain-service command.

### Implementation boundary

Controls POST to server routes that invoke the domain service — cancel rides P2A03 cascade semantics; ambiguous resolution writes the one-row `attempt_decision` (P2D05) and unlocks the parked node; resume invokes the P2C03 preflight + P2C04 execution; checkpoint verbs invoke P2C02/P2C05. Every form replays safely (idempotent commands; double-submit dedupes). Confirmation UX for destructive-ish actions (cancel cascade, gc) follows the Phase 1 operator-flow convention; no PAM ceremony is needed — these are runtime operations, not Slice-D destructive ops.

### Durable data and migration

Commands persist through existing tables; the UI adds no state of its own.

### Security and authority

Controls require the operator session; `attempt_decision` is one-row-ever — a replayed POST returns the recorded decision, never a second row. Cross-scope or stale-lease commands surface their reason codes.

### Failure, retry, cancellation, and recovery

Failed commands render the journaled reason code (`RESUME_TOKEN_STALE`, `CHECKPOINT_BOUNDARY_ILLEGAL`, etc.) inline; nothing fails silently.

### Verification and evidence

- Cancel cascades and the UI reflects per-node transitions
- Ambiguous resolution both ways (resume/rerun) unblocks the node exactly once
- Resume form drives preflight → execution with failure codes visible
- Checkpoint create/pin/gc work and reflect `gc_class`
- Double-submitted forms dedupe to one command
- Evidence artifact: `phase-2-slice-e-operator-controls.json`

### Scope control

P2E04 owns the control surface only — the commands' semantics belong to their owning packets; the UI adds no policy.

### Definition of Done

An operator can cancel, resolve ambiguity, resume, and manage checkpoints entirely through the UI, with every action durable, idempotent, and journaled.

## P2E05

### Identity and outcome

Implement fleet observability: registered workers with capabilities, live leases, suspect/lost banners, deferred admissions, and outbox backlog health.

### Implementation boundary

Server-rendered status views over `worker_registration`, lease rows, `admission_deferred` events, and outbox unpublished-depth/age. `worker_suspect`/`worker_lost` surface as banners; deferred nodes show their `CAPACITY_ADMISSION_DEFERRED` wait; `OUTBOX_PUBLISH_STALLED` renders a health warning. Heartbeats stay row state — the view reads last-beat age, not an event feed.

### Durable data and migration

Read-only; no new state.

### Security and authority

Worker rows carry no credentials; lease display shows ids and timestamps only.

### Failure, retry, cancellation, and recovery

This surface IS failure visibility: every degraded condition (suspect, lost, deferred, stalled) has a distinct rendering tied to its reason code.

### Verification and evidence

- Worker list shows capabilities, `max_concurrent_attempts`, live lease count
- Suspect/lost transitions surface within a refresh of the sweeper
- Deferred nodes list with reason and FIFO position
- Outbox stall renders the warning with backlog metrics
- Evidence artifact: `phase-2-slice-e-observability.json`

### Scope control

P2E05 owns observability rendering only — no sweeper logic, no config mutation.

### Definition of Done

An operator sees worker health, admission pressure, and publication health at a glance, with reason-coded detail.

## P2E06

### Identity and outcome

Prove accessibility and security conformance for the Phase 2 UI: sanitization, focus management, `aria-live` updates, security headers, restart-reconciliation banner at run scope, and the browser-acceptance matrix.

### Implementation boundary

Applies B06/B11 conformance to every 2E surface: emitted strings (node keys, names, reason text) sanitize; live regions announce state changes politely; security headers unchanged; the restart-reconciliation banner extends to runs with in-flight reconciliation (P2B05 startup pass) and unresolved `attempt_ambiguous`; acceptance covers Firefox ≥115 and Chromium ≥115, Safari ≥16 as compatibility target.

### Durable data and migration

None — conformance layer over existing surfaces.

### Security and authority

No raw HTML, `javascript:`/`data:` URLs, or script-capable attributes from journaled/emitted strings; prompts render only as artifact links.

### Failure, retry, cancellation, and recovery

Sanitizer failures fail closed — content omitted, never raw.

### Verification and evidence

- Emitted strings with HTML/URL payloads render inert
- `aria-live` announces node state transitions; focus is managed semantically
- Security headers present on every 2E route
- Reconciliation/ambiguous banners persist correctly across restart
- Browser matrix spot-checks pass
- Evidence artifact: `phase-2-slice-e-conformance.json`

### Scope control

P2E06 owns conformance only — no new views or controls.

### Definition of Done

The Phase 2 UI meets the Phase 1 accessibility and security bar end-to-end, with banners for every degraded state.

## Slice acceptance

**Gate:** `S2E-G1` — **Evidence:** `phase-2-slice-e-acceptance.json`

Slice 2E is complete when:

1. P2E01–P2E06 contracts are verified with passing tests
2. Every run renders its DAG, node states, and attempt history from authoritative projections (P2E01, P2E02)
3. `run_lineage` explains every final artifact in the UI; undeclared reads render flagged (P2E03)
4. Cancel, ambiguous resolution, resume, and checkpoint verbs work through idempotent commands with reason-code feedback (P2E04)
5. Worker/lease/admission/outbox degradation is visible and reason-coded (P2E05)
6. Accessibility, sanitization, security headers, and reconciliation banners conform to the B06/B11 bar (P2E06)
7. No UI path mutates state outside domain-service commands; no prompt text or artifact body renders inline
8. The complete Slice 2E acceptance evidence is durably recorded

Slice 2E must not claim orchestration authority — it observes and issues operator commands only.
