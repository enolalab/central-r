# Slice 2D — Retry, Timeout, and Idempotency

- **Slice ID:** 2D
- **Dossier:** `slice-d-retry-idempotency.md`
- **Issue:** #95 — retry/timeout + idempotency
- **Packets:** P2D01–P2D06
- **Dependency:** P2C05 (Slice 2C complete)
- **Outcome:** Fail-closed error taxonomy with journaled backoff, per-class and total attempt budgets, the three-level timeout hierarchy, at-most-once compensation hooks, database-enforced idempotency keys, and the transactional outbox with single-boundary artifact finalization

## Governing specs

- `docs/internal/superpowers/specs/2026-10-07-phase-2-retry-timeout-error-taxonomy.md` — classes, backoff, attempt limits, timeout hierarchy, compensation, budget exhaustion
- `docs/internal/superpowers/specs/2026-10-07-phase-2-idempotency-consistency.md` — idempotency key table, replay semantics, transactional outbox, exactly-once boundary map, artifact finalization
- `docs/internal/superpowers/specs/2026-10-07-phase-2-concurrency-resource-limits.md` — `SESSION_*_REACHED` breach codes consumed by the taxonomy (cited)
- `docs/internal/superpowers/specs/2026-10-07-phase-2-task-leasing-worker-protocol.md` — lease fencing boundary consumed, not redefined (cited)

## Slice 2D ownership

P2D01–P2D06 collectively own:

- the retryable-vs-terminal taxonomy — every `attempt_failed`/dispatch refusal carries exactly one class and reason code; unknown outcomes fail closed as `terminal`;
- journaled backoff (`base=30s`, `×2`, `cap=10m`, full jitter, `retry_after` honored-but-capped), per-class attempt limits plus the absolute ceiling, and `not_before`-gated return to `ready`;
- the session → node → workflow timeout hierarchy with the `min(...)` dispatch ceiling and kill-confirmation rule;
- at-most-once compensation hooks (`cleanup_workspace`, `retain_artifacts`; anything else journaled `compensation_requested`);
- the idempotency key table enforced by unique constraints with payload-fingerprint replay semantics, including the one-row-ever `attempt_decision` for ambiguous attempts;
- the transactional outbox (state + event in one commit), at-least-once publication with consumer dedup, and artifact finalization as the single visibility boundary.

Slice 2D must not touch ambiguous attempts — they are operator decisions at every level, forever outside the retry path. It must not implement claim mechanics (2B), checkpoint format (2C), lineage (2A), or UI (2E).

## Packets

- **P2D01** — Error taxonomy: six classes, reason-code registry, fail-closed classification of every failure
- **P2D02** — Retry scheduling: journaled exponential backoff, per-class + total attempt limits, `not_before` readiness gate
- **P2D03** — Timeout hierarchy: session/node/workflow bounds, `min(...)` composition, kill-confirmation vs ambiguity
- **P2D04** — Compensation hooks: Central-managed cleanup actions, journaled requests, at-most-once keyed on the node
- **P2D05** — Idempotency keys and replay: unique-constraint-backed key table, fingerprint comparison, `attempt_decision` one-row rule
- **P2D06** — Transactional outbox and artifact finalization: same-transaction event rows, publisher drain, consumer dedup, single visibility boundary

## P2D01

### Identity and outcome

Implement the error taxonomy: classify every `attempt_failed` and dispatch refusal into exactly one class with one reason code; the class — not the code — decides retryability; unclassified outcomes fail closed to `terminal`.

### Implementation boundary

Classes per spec 4: `transient` (`PROCESS_EXIT_NONZERO`, `ADAPTER_ERROR`, `RATE_LIMITED`), `dispatch_infra` (`WORKSPACE_PROVISION_FAILED`, `LAUNCHER_REFUSED`, `ADMISSION_WAIT`), `session_timeout` (`SESSION_TIMEOUT` — plus the spec-8 `SESSION_*_REACHED` breach codes), `terminal` (`SPEC_VALIDATION_FAILED`, `BUDGET_EXHAUSTED`, `WORKSPACE_UNAVAILABLE`, `CAPABILITY_MISSING`), `node_timeout` (`NODE_TIMEOUT`), `workflow_timeout` (`WORKFLOW_TIMEOUT`). Classification is a pure function over the recorded outcome; adding a retryable class requires a spec amendment, not a heuristic. Only definite failures enter — observed exit, kill-confirmed timeout, structured adapter error, dispatch refusal. Nothing ambiguous reaches this path.

### Durable data and migration

Class + reason code persist on the attempt journal row; no new tables.

### Security and authority

Reason codes are machine-stable strings — the vocabulary downstream specs, the UI, and the failure matrix consume; no code is emitted without an owning event.

### Failure, retry, cancellation, and recovery

This packet IS classification. Misclassification risk is controlled by fail-closed default: unknown → `terminal` → `failed_terminal` with the recorded code, never a silent retry.

### Verification and evidence

- Every reachable definite-failure path maps to exactly one class and code
- Unknown outcomes classify `terminal`
- `attempt_ambiguous` never enters the retry path
- Reason codes journal on their owning events verbatim
- Future test suite: `go test ./internal/retry/...`
- Evidence artifact: `phase-2-slice-d-taxonomy.json`

### Scope control

P2D01 owns classification only — not delay computation, limits, or timeout enforcement.

### Definition of Done

The taxonomy is exhaustive and fail-closed; every failure carries its class and code durably.

## P2D02

### Identity and outcome

Implement retry scheduling: compute `delay_n = min(cap, base × 2^(n−1))` with full jitter (defaults `base=30s`, `cap=10m`), journal `attempt_retry_scheduled` with the computed `retry_at`, and return the node to `ready` with `not_before = retry_at` — or `failed_terminal` when budget is spent.

### Implementation boundary

Per-class budgets `transient=3`, `dispatch_infra=5`, `session_timeout=2` plus `max_attempts_total=5`; an attempt counts against its producing class and the total. Counting reads the node's journaled `session_attempt` rows — the node holds durable progress. Provider `retry_after` on `RATE_LIMITED` replaces the computed delay, still capped. The journaled `retry_at` is authoritative — a Central restart never recomputes or loses it; the P2B01 claim requires `not_before ≤ now()`. Budget exhaustion or a terminal-class failure transitions `failed_terminal` in one domain-service transaction with `node_failed_terminal` carrying `RETRY_BUDGET_EXHAUSTED` or the class code plus the failing `attempt_id`; dependents stay blocked and the leader's remedy is emitting replacement nodes — the dead node is never mutated.

### Durable data and migration

`not_before`, `max_attempts` bookkeeping on `workflow_node`; `attempt_retry_scheduled` event per P2A04.

### Security and authority

Budgets derive from the child spec's declared limits bounded by run ceilings — a leader cannot inflate its own retry budget past the parent.

### Failure, retry, cancellation, and recovery

Retry-delay persistence is crash-safe by journaling. A retry-eligible node behind `not_before` simply stays `ready`; nothing times out silently across an unresolved ambiguous attempt.

### Verification and evidence

- Backoff sequence matches `min(cap, 30s×2^(n−1))` with jitter, journaled per retry
- Per-class and total ceilings each force `failed_terminal` at their bound
- `retry_after` honored under cap; restart preserves `retry_at`
- `not_before` gates claims; expired `not_before` restores FIFO eligibility
- Future test suite: `go test ./internal/retry/...`
- Evidence artifact: `phase-2-slice-d-retry.json`

### Scope control

P2D02 owns delay computation, budgets, and the `not_before` gate. It must not classify outcomes (P2D01), enforce timeouts (P2D03), or auto-resolve ambiguity.

### Definition of Done

Retryable failures reschedule with journaled, restart-safe delays inside bounded budgets; exhaustion terminates the node with a named code.

## P2D03

### Identity and outcome

Implement the three-level timeout hierarchy: session ceiling per attempt (adapter-enforced), node timeout across all attempts and waits, workflow timeout on the run's graph — inner bounds fire first.

### Implementation boundary

Session timeout kills the attempt via launcher/adapter; confirmed kill → definite `SESSION_TIMEOUT` (retryable); unconfirmed → `attempt_ambiguous` (locked: operator decision). Node timeout measures elapsed from first dispatch across attempts + backoff; expiry is `failed_terminal` `NODE_TIMEOUT` — a bound, not a retryable class. Workflow timeout cancels running attempts (harness cancel control), cascades `cancelled` to non-terminal nodes per spec 1, and ends the run `failed_terminal` `WORKFLOW_TIMEOUT`. Effective session ceiling at dispatch = `min(spec_hint, node_remaining, workflow_remaining)` — child budgets may tighten, never loosen (spec 8 aggregation consumed here). Timers are computed from journaled timestamps; unresolved ambiguous attempts block parent timers (locked input 3).

### Durable data and migration

Deadline fields on node/run rows; expiry evaluated transactionally with its journal events.

### Security and authority

Only run/child-spec envelopes set bounds — a node cannot extend its own ceiling.

### Failure, retry, cancellation, and recovery

Timeout-expiry handling IS this packet: confirmed kills retry under class rules; unconfirmed kills park ambiguous; node/workflow expiry is terminal and cascades correctly.

### Verification and evidence

- Session ceiling breach kills and confirms → `SESSION_TIMEOUT`; unconfirmed → ambiguous
- Node timeout fires `NODE_TIMEOUT` regardless of remaining retry budget
- Workflow timeout cancels actives, cascades `cancelled`, ends run `WORKFLOW_TIMEOUT`
- Effective ceiling = min of the three inputs at dispatch
- Timers do not fire across unresolved ambiguous descendants
- Future test suite: `go test ./internal/retry/... ./internal/scheduler/...`
- Evidence artifact: `phase-2-slice-d-timeouts.json`

### Scope control

P2D03 owns the timeout hierarchy. It must not decide retry counts (P2D02) or the ambiguous resolution (operator).

### Definition of Done

The three bounds compose with inner-first semantics, correct kill-confirmation splitting, and terminal cascade behavior.

## P2D04

### Identity and outcome

Implement compensation hooks: a child spec may declare `on_terminal_failure`; Central-managed values execute at most once keyed on the node; everything else is journaled `compensation_requested` for the leader/operator.

### Implementation boundary

Central-managed Phase 2 actions: `cleanup_workspace` (remove the worktree/private dir) and `retain_artifacts` (mark declared artifacts kept for inspection). Agent-authored cleanup is never auto-executed. Hook execution journals its outcome; runs once per node — replay dedupes on the node key.

### Durable data and migration

Hook outcome persists on the node row / journal; no new tables.

### Security and authority

Only the two Central-managed actions execute; any other declared value is evidence, not code — ADR 0035 holds (no agent-authored execution).

### Failure, retry, cancellation, and recovery

Hook failure journals but does not reopen the terminal node; `cleanup_workspace` failure leaves the dir for operator cleanup — never blocks the terminal transition.

### Verification and evidence

- `cleanup_workspace` removes the node's workspace; `retain_artifacts` marks declared artifacts kept
- Unknown hook values journal `compensation_requested`, execute nothing
- Double-trigger dedupes — hook runs once per node
- Future test suite: `go test ./internal/retry/...`
- Evidence artifact: `phase-2-slice-d-compensation.json`

### Scope control

P2D04 owns compensation execution. It must not grow new managed actions without spec amendment or perform lineage queries.

### Definition of Done

Terminal-failure compensation is bounded, journaled, at-most-once, and never executes agent-authored code.

## P2D05

### Identity and outcome

Implement idempotency keys and replay semantics: every Phase 2 command/step type carries a key backed by a unique constraint; same key + same fingerprint returns the existing record; same key + different fingerprint rejects `DUPLICATE_IDEMPOTENCY_KEY`.

### Implementation boundary

The spec-5 key table is implemented verbatim: submit run `(workspace_id, run_key)`; emit child specs `(run_id, node_key)`; allocate attempt `(node_id, attempt_seq)`; record outcome `(attempt_id, outcome_kind)`; record operator decision `(attempt_id)` — one row ever, replays return the recorded choice; finalize artifact `(attempt_id, artifact_name)`; commit checkpoint `(attempt_id, checkpoint_seq)`; cancel node idempotent by terminal state; publish event `(aggregate_id, event_seq)` outbox PK. Insert relies on the constraint (`ON CONFLICT`/`23505`), then re-reads and compares the stored fingerprint — SHA-256 over canonical command JSON. Replays journal `command_deduped` so operators observe retries. A late second outcome report for a terminal attempt dedupes — no double transition, no second event.

### Durable data and migration

Migration adds fingerprint columns / unique constraints per the key table and the `attempt_decision` relation. The database — not caller discipline — is the authority.

### Security and authority

`attempt_decision` records the operator's resume-vs-rerun choice once; no replay can rewrite history.

### Failure, retry, cancellation, and recovery

Fingerprint mismatch rejects with `DUPLICATE_IDEMPOTENCY_KEY` and leaves the existing record untouched — the phases.md scenario (repeated commands create no duplicates) holds by construction.

### Verification and evidence

- Every table row: same-key same-payload → existing record; same-key different-payload → rejection
- Double-recorded attempt outcome yields one transition, one event
- Second `attempt_decision` for one attempt is impossible; replay returns the original
- `command_deduped` journals on replays
- Future test suite: `go test ./internal/idempotency/...`
- Evidence artifact: `phase-2-slice-d-idempotency.json`

### Scope control

P2D05 owns command-level keys and replay. It must not own outbox mechanics (P2D06) or lease fencing (2B04 — the complementary layer).

### Definition of Done

Every Phase 2 command is idempotent by construction; replays are safe, observable, and fingerprint-checked.

## P2D06

### Identity and outcome

Implement the transactional outbox and artifact finalization: every state transition writes its `event_outbox` row in the same transaction; a publisher drains in per-aggregate `event_seq` order; artifact finalize is the single visibility boundary.

### Implementation boundary

Outbox: state + event commit atomically — crash-between is impossible by construction. Publisher drains unpublished rows (`FOR UPDATE SKIP LOCKED` batches), marks published, delivers to consumers (readiness recompute, journal/UI feeds); delivery is at-least-once, consumers dedupe on `event_id`; backlog/age past threshold raises `OUTBOX_PUBLISH_STALLED` — transitions never depend on publication. Published rows retain 7 days then GC (OQ-3 default); publisher runs in-process in `central serve` (OQ-1 default). Finalize contract: body to `runs/<run_id>/attempts/<attempt_id>/artifacts/<artifact_name>` → checksum verify (`ARTIFACT_CHECKSUM_MISMATCH` aborts pre-commit) → ONE transaction inserts metadata `unique(attempt_id, artifact_name)` + `artifact_finalized` outbox event. Same key + same checksum returns existing; different checksum → `ARTIFACT_ALREADY_FINALIZED`. Unfinalized bodies are invisible orphans GC'd by B10. Exactly-once claims exist only inside PostgreSQL — every at-least-once effect names its dedup point per the boundary map.

### Durable data and migration

Migration adds `event_outbox` with `(aggregate_id, event_seq)` PK and published-marker columns.

### Security and authority

`central artifact read` resolves at most one finalized artifact per name; re-finalization never produces a second visible version.

### Failure, retry, cancellation, and recovery

Crash between state and event: impossible (one transaction). Stalled publisher: `OUTBOX_PUBLISH_STALLED`, consumers lag, state stays correct. Upload retry rewrites the same object key; finalize gates visibility.

### Verification and evidence

- State transition and outbox row are provably one transaction (test injects crash)
- Publisher delivers each row at-least-once in `event_seq` order; consumers dedupe
- Double-finalize same checksum → existing artifact; different checksum → `ARTIFACT_ALREADY_FINALIZED`
- Checksum mismatch aborts pre-commit; retried upload reuses the object key
- Backlog beyond threshold raises `OUTBOX_PUBLISH_STALLED`
- Future test suite: `go test ./internal/idempotency/... ./internal/artifact/...`
- Evidence artifact: `phase-2-slice-d-outbox.json`

### Scope control

P2D06 owns outbox + finalization mechanics. It must not own lineage edges (2A06) or UI consumption (2E).

### Definition of Done

Durable effects are single by construction: one transaction for state+event, deduped delivery, and exactly one visible version per finalized artifact.

## Slice acceptance

**Gate:** `S2D-G1` — **Evidence:** `phase-2-slice-d-acceptance.json`

Slice 2D is complete when:

1. P2D01–P2D06 contracts are verified with passing tests
2. Every definite failure classifies into exactly one retryable-or-terminal class; unknown fails closed (P2D01)
3. Backoff is journaled and restart-safe; per-class and total budgets each terminate correctly (P2D02)
4. The timeout hierarchy composes inner-first; unconfirmed kills park ambiguous, never retry (P2D03)
5. Compensation hooks run at most once; only Central-managed actions execute (P2D04)
6. Repeated commands create no duplicate tasks or artifacts — verified per key-table row (P2D05)
7. State+event atomicity proven by crash injection; finalize is the single visibility boundary (P2D06)
8. No ambiguous attempt ever enters the retry path — operator decision at every level
9. The complete Slice 2D acceptance evidence is durably recorded

Slice 2D must not claim scheduling, checkpoint, lineage, or UI capabilities — those are Slices 2B, 2C, 2E.
