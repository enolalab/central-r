# Phase R4 — Multi-Agent Workflow Orchestration (Phase 2 Parity: Slices 2A–2F) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the complete Phase R4 vertical slice in `$CENTRAL_RUST_SRC` per [rust-vertical-slice-roadmap.md](../../../implementation/rust-vertical-slice-roadmap.md) §7: implement `central-retry`, `central-workflow`, `central-eventjournal`, `central-scheduler`, `central-runsubmit`, `central-runview`; complete the Phase 2 subtree-checkpoint surface of `central-checkpoint`; add attempt-scoped artifact finalization and `b34` lineage projections to `central-artifact`; implement the matching `central-adapter-postgres` stores over `b33`–`b37`; ship the `/app/runs*` SSR surfaces and the CLI verbs `central run submit`, `central node decide`, `central checkpoint *`, `central artifact read`; compose the scheduler/retry/checkpoint components in `central-kernel`; and pass the 23-scenario Phase 2 recovery test matrix (20 machine-tier scenarios: RTM-01…RTM-18 plus RTM-19 recorded as two scenarios, `RTM-19-session` and `RTM-19-deadlines`, exactly as upstream `TestPhase2RecoveryMatrix` records them; 3 physical rows RTM-P1…P3 recorded `deferred-physical`) plus the §7 fail-fast pipeline.

**Architecture:**
- **Crate DAG ([rust-application-boundaries.md](../../../architecture/rust-application-boundaries.md) §2, lines 80–108):**
  - `central-retry` → `central-foundation` only. Error taxonomy, timeout hierarchy, retry budgets, compensation intents.
  - `central-workflow` → `central-retry` (domain types only, for retry policy in node-spec validation) + `central-foundation`.
  - `central-eventjournal` → `central-foundation` only. Canonical `run_events` envelope, fold/reconstruction (fold is read-only).
  - `central-scheduler` → `central-foundation` only. Ready queue, worker registration, node leases, missed-beat ladder, admission.
  - `central-runview` → `central-eventjournal` (fold types) + `central-foundation`. Read-only projections; no mutation ports.
  - `central-runsubmit` → `central-task` (domain/`app`/`port`), `central-workflow` (domain) + `central-foundation`. Every task transition goes through `central-task`.
  - Lower capabilities never import `central-harness`, `central-execution`, `central-runsubmit`, transport, or `central-kernel`. Scheduler → harness wiring happens **only** in `central-kernel`.
  - All capability crates: no `tokio`, no `uuid`, no `sqlx`; `domain.rs` is pure sync; concurrency goes through capability-owned `Clock`/`Ticker` traits implemented by the kernel (same pattern as R2/R3).
- **Atomicity:** every state change commits as a change set in one PostgreSQL transaction together with its `run_events` append and its `event_outbox` row (b37). Claims use `SELECT … FOR UPDATE SKIP LOCKED`. Lease fencing rejects stale writes with `LEASE_FENCED`.
- **R2 → R4 handoff:** `FinalizeAttemptArtifact` (journals `artifact_finalized` into `run_events`, keyed by `artifact_finalizations`) and `central artifact read` land here, as the R2 plan deferred.

**Tech Stack:** already pinned — `sqlx =0.8.6`, `tokio =1.54.1`, `tokio-util =0.7.20`, `trait-variant =0.1.3`, `serde`/`serde_json`, `sha2 =0.11.1`, `time =0.3.55`, `axum =0.8.9`, `askama =0.16.1`, `tracing`. **No new dependency is planned.** Stop and ask if one turns out to be necessary.

## Global Constraints

- **Source of truth:** `$CENTRAL_SRC` (read-only). No new DDL: `b33`–`b37` already exist under `migrations/`.
- **Prerequisite:** Phase R3 complete — specifically R3 Task 5 (harness `Dispatcher`/`Resolver`), Task 12 (transport router + middleware), Task 13 (kernel serve composition). Tasks 1–9 here do not depend on R3 and may start in parallel (see D1).
- **Zero `unsafe`**; no unwraps in production targets; compile-time-checked SQL only; regenerate `.sqlx/` in every task that adds a statement.
- **Closed vocabularies:** event kinds, reason codes, and error classes are closed enums. An undeclared event kind fails with `UNKNOWN_EVENT_KIND`; the `b33`/`b37` vocabulary check in `migrate/shape_spec.rs` must stay in step with the Rust enums.
- **Wire parity:** `run_events` JSON envelopes, resume-token encoding/digest, `central.local-result/v1` CLI output, and HTML form/redirect behavior match upstream fixtures byte-for-byte.
- **Every task ends green:** `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test -p <touched crates>` (+ `cargo test --workspace` when a `port`/`query` trait or a `central-foundation` type changes), then commit.

---

## Open Decisions

| ID | Question | Gates | Default if no ruling |
| --- | --- | --- | --- |
| D1 | Start R4 before R3 is done? | Tasks 10–13 | Yes for Tasks 1–9; Tasks 10–13 wait for R3 Tasks 5/12/13 |
| D2 | Where does the Phase 2 acceptance driver live? Upstream it is `cmd/central/phase2_acceptance_test.go` (4,389 lines). | Task 13 | `bins/central/tests/phase2_acceptance/` (integration test, one file per RTM group) |
| D3 | Physical rows RTM-P1…P3 (real `kill -9`, real provider partition, clean host). | Task 13 | Recorded as `deferred-physical` in the evidence file, with a pointer to the operator runbook; not automated in R4 |
| D4 | R1 already shipped part of the `b36` surface (`ResumeCheckpointStore`, `ResumePreflight`, adapter `checkpoint.rs`). | Task 8 | Audit the gap first (Step 0), port only what is missing; never duplicate R1 types |

---

## File Structure

```text
central-rust/
├── .sqlx/                                            # + b33–b37 queries
├── crates/
│   ├── capabilities/
│   │   ├── central-retry/src/{lib,domain,port,query}.rs, app/{mod,sweeper}.rs
│   │   ├── central-workflow/src/{lib,domain,validate,readiness,port,query}.rs
│   │   ├── central-eventjournal/src/{lib,domain,fold,port,query}.rs, app/{mod,publisher,consumers}.rs
│   │   ├── central-scheduler/src/{lib,domain,admission,port,query}.rs,
│   │   │                      app/{mod,worker,claim_loop,dispatch,sweeper,reconciler}.rs
│   │   ├── central-runsubmit/src/{lib,domain,app}.rs
│   │   ├── central-runview/src/{lib,domain,port,query}.rs
│   │   ├── central-checkpoint/src/{domain,port,app}.rs + app/janitor.rs   # Phase 2C gap only
│   │   └── central-artifact/src/{app,lineage,port}.rs                     # FinalizeAttemptArtifact + projections
│   ├── adapters/central-adapter-postgres/src/
│   │   ├── workflow/{mod,store}.rs
│   │   ├── eventjournal/{mod,store,outbox}.rs
│   │   ├── scheduler/{mod,store,outcome}.rs                              # also implements central-retry ports
│   │   ├── runview/{mod,store}.rs
│   │   └── checkpoint.rs, artifact/finalization.rs                         # extend
│   ├── transport/central-transport-http/src/web/{run_view,run_controls,run_submit,fleet_view,lineage_view}.rs
│   │                                     + templates/runs/*.html
│   └── central-kernel/src/{scheduler_compose,retry_compose,checkpoint_compose,scheduler_harness}.rs
└── bins/central/
    ├── src/{run_cli,node_cli,checkpoint_cli,artifact_cli}.rs
    └── tests/phase2_acceptance/                      # D2
```

---

## Milestone A — Slice 2A: workflow graph & event journal

### Task 1: `central-retry` pure domain (prerequisite for workflow validation)

**Files:** Create `crates/capabilities/central-retry/src/{domain,port,query}.rs`; modify `lib.rs`, `Cargo.toml`.

**Reference:** `internal/retry/{domain.go,port/port.go}` + tests; spec `2026-10-07-phase-2-retry-timeout-error-taxonomy.md`, `…-idempotency-consistency.md`; dossier `slice-d-retry-idempotency.md`.

- [ ] **Step 1:** Port `domain_test.go` (error-class classification, per-class and `max_attempts_total` budgets, backoff with `retry_after` cap, timeout hierarchy session < node < workflow, compensation intents, fail-closed default for unknown errors) → `cargo test -p central-retry` FAIL.
- [ ] **Step 2:** Implement closed `ErrorClass`, `ReasonCode` (`PROCESS_EXIT_NONZERO`, `RATE_LIMITED`, `ADAPTER_ERROR`, `SESSION_TIMEOUT`, `RETRY_BUDGET_EXHAUSTED`, …), `RetryPolicy`, `RetryDecision`, `TimeoutHierarchy`, `classify(&AttemptFailure, &RetryPolicy, &History) -> RetryDecision`.
- [ ] **Step 3:** Define `port.rs` (atomic conditional eligibility ports, outbox write intent) and `query.rs` (attempt-decision history projection).
- [ ] **Step 4:** `cargo test -p central-retry` PASS → commit `feat(retry): port Phase 2 error taxonomy, budgets, and timeout hierarchy`.

### Task 2: `central-workflow` domain, validation, readiness

**Files:** Create `crates/capabilities/central-workflow/src/{domain,validate,readiness,port,query}.rs`.

**Reference:** `internal/workflow/{domain,validate,readiness}.go`, `port/port.go` + tests; spec `2026-10-07-phase-2-workflow-graph-scheduling-design.md`; dossier `slice-a-workflow-graph-lineage.md`.

- [ ] **Step 1:** Port tests: node state machine (`declared → ready → running → succeeded|failed_terminal|cancelled`), ordering vs `artifact` edges, child-spec batch validation (cycle → atomic `child_spec_rejected` `SPEC_VALIDATION_FAILED` naming keys — RTM-12), dynamic child expansion, readiness rules (dependent not `ready` until `artifact_finalized` — RTM-14), parent cancel cascade (RTM-11) → FAIL.
- [ ] **Step 2:** Implement pure `Node`, `Edge`, `NodeSpec`, `ChildSpecBatch`, `validate_batch`, `evaluate_readiness`, `cancel_cascade` producing graph change sets with expected versions.
- [ ] **Step 3:** Define `port.rs` (`WorkflowStore` with run-row lock anchor) and `query.rs` (graph page by seek cursor).
- [ ] **Step 4:** PASS → commit `feat(workflow): port workflow graph domain, validation, and readiness`.

### Task 3: `central-eventjournal` domain, fold, publisher

**Files:** Create `crates/capabilities/central-eventjournal/src/{domain,fold,port,query}.rs`, `app/{mod,publisher,consumers}.rs`.

**Reference:** `internal/eventjournal/{domain,fold}.go`, `app/{publisher,consumers}.go`, `port/port.go` + tests; spec `2026-10-07-phase-2-event-schema-reconstruction.md`.

- [ ] **Step 1:** Port tests incl. golden envelopes: per-run monotonic `seq`, fold → reconstructed run state, integrity failures `EVENT_SEQUENCE_GAP`, `DUPLICATE_EVENT_ID`, `UNKNOWN_EVENT_KIND` (RTM-18), publisher outbox drain idempotence → FAIL.
- [ ] **Step 2:** Implement closed `EventKind`, `RunEvent` envelope (serde identical to upstream), `fold(events) -> Result<RunState, Failure>`, `Publisher` (outbox drain via port), consumer registry.
- [ ] **Step 3:** PASS → commit `feat(eventjournal): port canonical run_events envelope, fold, and publisher`.

### Task 4: `central-adapter-postgres::{workflow,eventjournal}` (b33 + b37 `event_outbox`)

**Files:** Create `src/workflow/{mod,store}.rs`, `src/eventjournal/{mod,store,outbox}.rs`; modify `lib.rs`, `Cargo.toml`; `.sqlx/`.

**Reference:** `internal/adapter/postgres/workflow/store.go` (1,313 lines), `internal/adapter/postgres/eventjournal/{store,outbox}.go` + tests.

- [ ] **Step 1:** Port store tests as `CENTRAL_TEST_DSN`-gated integration tests → FAIL.
- [ ] **Step 2:** Implement `PgWorkflowStore` (node/edge insert, atomic batch expansion, `ready_at`, run-row `FOR UPDATE` anchor) and `PgEventJournal` (append with `seq` assignment in the same transaction as the change set; `event_outbox` insert; drain with `SKIP LOCKED`).
- [ ] **Step 3:** `cargo sqlx prepare --workspace -- --all-targets`; integration tests PASS; check `central_runtime` grants (record any gap in `docs/internal/tasks/`, never widen silently).
- [ ] **Step 4:** Commit `feat(adapter-postgres): implement b33 workflow and event-journal stores with outbox`.

## Milestone B — Slices 2B–2D: scheduling, artifacts, checkpoints, retry

### Task 5: `central-scheduler` domain, admission, worker protocol

**Files:** Create `crates/capabilities/central-scheduler/src/{domain,admission,port,query}.rs`, `app/{mod,worker,claim_loop,dispatch,sweeper,reconciler}.rs`.

**Reference:** `internal/scheduler/{domain,admission}.go`, `app/*.go`, `port/port.go` + tests; specs `2026-10-07-phase-2-task-leasing-worker-protocol.md`, `…-concurrency-resource-limits.md`; dossier `slice-b-scheduler-workers.md`.

- [ ] **Step 1:** Port tests: worker registration, lease grant/renew/expire, missed-beat ladder (`worker_suspect` at 2, `worker_lost` `WORKER_LOST_GRACE_EXPIRED` at 5 — RTM-05), lease expiry never-started → `LEASE_EXPIRED_NOT_STARTED` + requeue (RTM-06), mid-flight → `attempt_ambiguous` no auto-requeue (RTM-07), admission deferral `CAPACITY_ADMISSION_DEFERRED` with FIFO position kept (RTM-15/17) → FAIL.
- [ ] **Step 2:** Implement pure ladder/lease/admission rules and the `app` loops (`Worker`, `ClaimLoop`, `Dispatch` behind a `NodeLauncher` port, `Sweeper`, `Reconciler`) using capability `Clock`/`Ticker` traits.
- [ ] **Step 3:** PASS → commit `feat(scheduler): port ready queue, worker protocol, leases, and admission`.

### Task 6: `central-adapter-postgres::scheduler` (b35 + b37 attempt decisions/outcomes)

**Files:** Create `src/scheduler/{mod,store,outcome}.rs`; `.sqlx/`.

**Reference:** `internal/adapter/postgres/scheduler/{store,outcome}.go` (3,448 lines) + tests.

- [ ] **Step 1:** Port integration tests incl. concurrent-claim tests (two claimers, one winner via `SKIP LOCKED`), stale-lease write → `LEASE_FENCED`, outcome idempotency (same key + same payload → `command_deduped`; different fingerprint → `DUPLICATE_IDEMPOTENCY_KEY` — RTM-08) → FAIL.
- [ ] **Step 2:** Implement `PgSchedulerStore` (`worker_registrations`, `session_attempts`, `node_leases`, `workflow_nodes.ready_at`) and `PgOutcomeStore` (`attempt_decisions`, `attempt_outcomes`), each change committing with its `run_events` + `event_outbox` rows by reusing Task 4 helpers. These two structs are also the **only** implementers of the `central-retry` ports (eligibility, decision write, sweeper claim). Upstream implements `internal/retry/port` in `internal/adapter/postgres/scheduler/{store,outcome}.go`; there is no separate retry store, and `attempt_decisions` has exactly one writer.
- [ ] **Step 3:** `.sqlx/` regenerate; PASS → commit `feat(adapter-postgres): implement b35 scheduler and b37 outcome stores`.

### Task 7: Attempt-scoped artifact finalization, lineage projections, `central artifact read`

**Files:** Modify `crates/capabilities/central-artifact/src/{app,port,lineage}.rs`; create `crates/adapters/central-adapter-postgres/src/artifact/finalization.rs`; create `bins/central/src/artifact_cli.rs`; `.sqlx/`.

**Reference:** upstream `internal/artifact` attempt-finalization code + `cmd/central/artifact_read_composition.go`; spec `2026-10-07-phase-2-artifact-lineage.md`; R2 plan "Phase R2 vs. Phase R4 Boundary".

- [ ] **Step 1:** Failing tests: `FinalizeAttemptArtifact` writes `artifact_finalizations` + journals `artifact_finalized` atomically and is idempotent; premature read → `ARTIFACT_NOT_FINALIZED` (RTM-14); `ancestors`/`descendants`/`run_lineage` projections over `b34`.
- [ ] **Step 2:** Implement the service method in `central-artifact` producing an artifact-owned `AttemptFinalization` change set (artifact, attempt, run, node, content generation). **`central-artifact` must not import `central-eventjournal`**: the service DAG has no such edge. `central-adapter-postgres::artifact::finalization` maps the change set inside one transaction to the `artifact_finalizations` row, the `artifact_finalized` `run_events` envelope (built from `central-eventjournal` domain types, which adapters may import), and the `event_outbox` row. Then implement `central artifact read` (authorized, bounded stream to stdout, `central.local-result/v1` on failure).
- [ ] **Step 3:** PASS → commit `feat(artifact): add attempt-scoped finalization, lineage projections, and artifact read`.

### Task 8: Phase 2C subtree checkpoints — gap fill (D4)

**Files:** Modify `crates/capabilities/central-checkpoint/src/{domain,port,app}.rs`; create `app/janitor.rs` (or `janitor.rs`); modify `crates/adapters/central-adapter-postgres/src/checkpoint.rs`; create `bins/central/src/checkpoint_cli.rs`.

**Reference:** `internal/checkpoint/{domain.go,app/janitor.go,port/port.go}`, `internal/adapter/postgres/checkpoint/store.go`, `cmd/central/checkpoint_composition.go`; spec `2026-10-07-phase-2-checkpoint-resume-format.md`; dossier `slice-c-checkpoint-resume.md`.

- [ ] **Step 0:** Gap audit: list every upstream exported type/function/test in `internal/checkpoint` and mark which R1 already ports; write the gap list into the task commit body.
- [ ] **Step 1:** Port missing tests: quiescent-boundary write rule, resume-token digest binding, all-or-nothing preflight (`CHECKPOINT_INCOMPATIBLE`, stale token, edited workspace, GC'd artifact — RTM-09), resume dispatches unfinished nodes as new `attempt_seq` and parks ambiguous nodes `RESUME_REQUIRES_OPERATOR_DECISION` (RTM-10), janitor GC → FAIL.
- [ ] **Step 2:** Implement missing domain/app/adapter pieces and `central checkpoint list|show|resume`.
- [ ] **Step 3:** PASS → commit `feat(checkpoint): complete Phase 2C subtree checkpoints, janitor, and CLI`.

### Task 9: `central-retry` app + adapter + `central node decide`

**Files:** Create `crates/capabilities/central-retry/src/app/{mod,sweeper}.rs`, `bins/central/src/node_cli.rs`; extend `crates/adapters/central-adapter-postgres/src/scheduler/{store,outcome}.rs` only if a retry port method is still missing after Task 6; `.sqlx/`.

**Reference:** `internal/retry/app/sweeper.go`, `internal/adapter/postgres/scheduler/{store,outcome}.go` (retry port implementations), `cmd/central/{node_composition,scheduler_retry_composition}.go`.

- [ ] **Step 1:** Failing tests: transient failure → `attempt_retry_scheduled` → node `ready` after backoff (RTM-02/04); budget exhaustion → `node_failed_terminal` (RTM-13); session-ceiling timeout with confirmed vs unconfirmed kill (RTM-19-session) and node/workflow deadline expiry (RTM-19-deadlines); ambiguous attempt waits for operator, timers frozen, decision replay idempotent (RTM-16).
- [ ] **Step 2:** Implement `RetrySweeper` over the retry ports served by `PgSchedulerStore`/`PgOutcomeStore` (transactional outbox via Task 4 helpers), and `central node decide <node> --resume|--rerun|--fail`.
- [ ] **Step 3:** PASS → commit `feat(retry): add retry sweeper and node decide`.

## Milestone C — Slice 2E: submission & run views (needs R3)

### Task 10: `central-runsubmit` + `central run submit` + `POST /app/runs/submit`

**Files:** Create `crates/capabilities/central-runsubmit/src/{domain,app}.rs`, `bins/central/src/run_cli.rs`, `crates/transport/central-transport-http/src/web/run_submit.rs` + template.

**Reference:** `internal/runsubmit/runsubmit.go` + tests, `cmd/central/run_composition.go`, `internal/transport/.../web/run_submit.go` + test; spec `2026-10-09-issue-122-run-submission-entrypoint-design.md`; `docs/operations/phase-2-run-submit.md`.

- [ ] **Step 1:** Failing tests: submit creates task (via `central-task` service) + root workflow nodes in one orchestrated flow; idempotent resubmit; CLI and HTTP map to the same service; HTML uses PRG + CSRF.
- [ ] **Step 2:** Implement; PASS → commit `feat(runsubmit): add run submission service, CLI, and web form`.

### Task 11: `central-runview` + `/app/runs` DAG, controls, fleet, lineage

**Files:** Create `crates/capabilities/central-runview/src/{domain,port,query}.rs`, `crates/adapters/central-adapter-postgres/src/runview/{mod,store}.rs`, `crates/transport/central-transport-http/src/web/{run_view,run_controls,fleet_view,lineage_view}.rs` + `templates/runs/*.html`; `.sqlx/`.

**Reference:** `internal/runview/*`, `internal/adapter/postgres/runview/store.go`, `web/{run_view,run_controls,fleet_view,lineage_view}.go` + `handler_{runs,fleet,lineage}_test.go`, `run_controls_test.go`; `docs/product/agent-orchestration-view-design.md`; dossier `slice-e-graph-ui.md`; boundaries §5 state matrix (normal/loading/empty/pending/terminal/conflict/denied/unavailable/restart/validation).

- [ ] **Step 1:** Port handler + projection tests (each state-matrix row, typed `SeekCursor` polling, no inline script/style, controls are PRG + CSRF) → FAIL.
- [ ] **Step 2:** Implement read-only projections and views; controls call `central-retry`/`central-workflow` services only.
- [ ] **Step 3:** PASS → commit `feat(runview): add run DAG, controls, fleet, and lineage views`.

### Task 12: Kernel composition (scheduler, retry, checkpoint janitor, scheduler → harness)

**Files:** Create `crates/central-kernel/src/{scheduler_compose,retry_compose,checkpoint_compose,scheduler_harness}.rs`; modify `lib.rs`, `serve.rs`, `Cargo.toml`; modify `bins/central/src/main.rs` (lift `exit 5` for `run submit`, `node decide`, `checkpoint *`, `artifact read`).

**Reference:** `cmd/central/{scheduler_composition,scheduler_harness_wiring,scheduler_retry_composition,serve_controls_composition,serve_fleet_composition,serve_lineage_composition}.go`; `internal/adapter/schedulerharness/{launcher,killer,registry,brief}.go` + tests (279 lines: the scheduler `NodeLauncher`/killer over harness sessions).

- [ ] **Step 1:** Failing tests for `central-kernel::scheduler_harness`, ported from `internal/adapter/schedulerharness/schedulerharness_test.go`:
  - `InterimBrief` renders only durable node facts and quotes ids and paths verbatim, never interpreting them.
  - The launcher maps a claimed node lease to a harness `StartSpec` through the R3 adapter registry.
  - The killer cancels the harness session for a node.
  - Unknown adapter → closed failure.
  
  This glue lives in the kernel, because it needs both `central-scheduler` and `central-harness` ports and no adapter crate may import two capabilities. R2's `ArtifactReconcilerComponent` is the precedent.
- [ ] **Step 1b:** Failing kernel tests: serve profile starts worker/claim loop/sweepers/janitor/outbox publisher and settles within `DEFAULT_SETTLEMENT`; R5/R6 verbs stay fail-closed.
- [ ] **Step 2:** Implement; `cargo test -p central-kernel -p central` + `cargo build --workspace` PASS → commit `feat(kernel): compose Phase 2 scheduler, retry, checkpoint, and harness wiring`.

## Milestone D — Slice 2F: acceptance

### Task 13: Phase 2 recovery test matrix (D2, D3)

**Files:** Create `bins/central/tests/phase2_acceptance/{mod,driver,rtm_graph,rtm_leasing,rtm_policy,rtm_checkpoint,evidence}.rs`; evidence output under `docs/internal/evidence/` (path per spec D3).

**Reference:** `cmd/central/phase2_acceptance_test.go` (`TestPhase2RecoveryMatrix`), `internal/phase2accept/*`; specs `2026-10-07-phase-2-recovery-test-matrix.md`, `2026-10-08-phase-2-acceptance-design.md`; dossier `slice-f-phase2-acceptance.md`.

- [ ] **Step 1:** Port the in-process driver: real components + stub harness seams (`clock`, `digester`, `killer`, `launcher`).
- [ ] **Step 2:** Implement the 20 machine scenarios one group at a time, running each group to green before the next:
  - graph: 01/11/12/14
  - leasing: 03/05/06/07/15/17
  - policy: 02/04/08/13/16, `RTM-19-session`, `RTM-19-deadlines`
  - checkpoint/journal: 09/10/18

  Scenario IDs and packet tags (e.g. `RTM-19-session` → `P2F02`, `RTM-19-deadlines` → `P2F03`) must match upstream `recordScenario` calls.
- [ ] **Step 3:** Emit the `phase-2-recovery-matrix/v1` evidence document with exactly 23 scenario records (20 machine `passed` + RTM-P1…P3 `deferred-physical` with runbook pointers); a test asserts the record count and the ID set.
- [ ] **Step 4:** `cargo test -p central --test phase2_acceptance` with `CENTRAL_TEST_DSN` + `CENTRAL_TEST_MINIO_ENDPOINT` → PASS → commit `test(phase2): add recovery test matrix acceptance driver`.

### Task 14: R4 closeout

**Files:** Modify `docs/implementation/current-phase.md`; update `docs/operations/phase-2-run-submit.md` only if behavior differs.

- [ ] **Step 1:** Run the §7 pipeline:
  `cargo sqlx prepare --check --workspace -- --all-targets && cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo deny check && cargo test --workspace`
- [ ] **Step 2:** Mark R4 Complete and R5 Active in `current-phase.md` with a summary of the delivered crates.
- [ ] **Step 3:** Commit `docs(phase-r4): mark Phase R4 complete and advance active slice to Phase R5`.

---

## Self-review notes

- **Roadmap §7 coverage:** 2A → Tasks 2–4 (+ artifact read in 7); 2B → Tasks 5–6, 10; 2C → Task 8; 2D → Tasks 1, 9 (+ outbox in 4/6); 2E → Task 11 (+ lineage in 7); 2F → Task 13.
- **RTM coverage:** every machine row is asserted first at unit/integration level in its owning task (codes named in Tasks 2, 3, 5–9), then end to end in Task 13.
- **Risks:** largest adapter surface of any slice (~7.6k upstream lines across scheduler/workflow/checkpoint/runview stores); concurrent-claim tests need a real PostgreSQL; Task 12 is blocked until R3 is done.
