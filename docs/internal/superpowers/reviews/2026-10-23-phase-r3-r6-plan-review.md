# Plan Review: Phases R3–R6

**Mode:** Focused (one pass per plan; the global architecture/contract check is done once, against `docs/architecture/rust-application-boundaries.md` §2–§3)
**Scope:** crate DAG, adapter boundaries, cross-task contracts, cross-plan dependencies
**Plans:**
- `docs/internal/superpowers/plans/2026-10-23-phase-r3-harness-control-plane-and-serve.md`
- `docs/internal/superpowers/plans/2026-10-23-phase-r4-multi-agent-workflow-orchestration.md`
- `docs/internal/superpowers/plans/2026-10-23-phase-r5-host-authority-broker-compose.md`
- `docs/internal/superpowers/plans/2026-10-23-phase-r6-backup-restore-wipe-maintenance.md`
**Spec:** `docs/implementation/rust-vertical-slice-roadmap.md` §6–§9; `docs/architecture/rust-application-boundaries.md` §2 (service DAG, capability rows, adapter table, line 258 "other adapters" prohibition)
**Base:** `f80d24c` (plans untracked at review time)
**Reviewers:** direct review (no subagents), technical + architecture-boundary focus

## Verdict: Approved with Follow-ups (after fixes applied in this pass)

The review found six blocking boundary and contract issues across the four plans: one Critical and five Important. All six were fixed in one editing pass, and a grep check confirmed that none of the old wording remains. Each plan keeps its Open Decisions (dependency approvals, C→Rust daemon ports, Playwright toolchain). Those decisions gate individual tasks and do not change the architecture, so they are not counted as blockers here.

Strengths:
- Every task names concrete upstream reference files.
- R1/R2 overlaps (checkpoint `b36`, migrate runner, `central-backup` migration domain) are reused rather than re-implemented.
- The R5/R6 scope split for broker and helper ops is explicit.

## Blocking Findings (all resolved in this pass)

1. **F1 Harness crate imports forbidden capability crates.** Critical. Blocking: yes. Plan: R3.
   - Evidence: R3 Architecture let `central-harness` depend on `central-task`, `central-execution`, and `central-artifact`. Boundaries §2 Harness row allows only "Own `domain`/`port`/`query`, `central-foundation`", and the service DAG has no `central-harness → *` edge.
   - Impact: Tasks 1–5 would violate the compile-time DAG contract, and review would require rework.
   - Fix applied: harness depends on foundation only. Collaboration goes through harness-owned consumer-side ports in `app/ports.rs` (upstream `internal/harness/app/ports.go`: `RunLifecycle`, `ArtifactSink`, `WorkspaceProvisioner`, `WorkspaceCapture`, `WorkspaceSealer`, `ResumeSource`, `TaskEventSink`, `ResolveStore`, `Clock`). The kernel adapts the execution, task, and artifact services to these ports (R3 Architecture, Task 13 Step 2).

2. **F2 `central-adapter-harness` imports `central-adapter-linux`.** Important. Blocking: yes. Plans: R3 and R5.
   - Evidence: R3 D2 default ("pull `central-adapter-linux::workspace_seal` forward" for use by gitclone) and R5 Task 14 ("gitclone seal … use `central-adapter-linux::sys`"). Boundaries line 258 prohibits "other adapters", and `rustix` is banned outside `central-adapter-linux`.
   - Impact: R3 Task 9 and R5 Task 14 would introduce a forbidden adapter→adapter edge.
   - Fix applied: a `WorkspaceSealer` harness port, implemented in `central-adapter-linux::workspace_seal` and injected by the kernel. `central-adapter-harness` never imports `central-adapter-linux` (R3 Architecture, D2, Task 9, File Structure; R5 Task 14).

3. **F3 Dev bootstrap authority placed in the PostgreSQL adapter.** Important. Blocking: yes. Plan: R3.
   - Evidence: R3 Task 10 Step 3 put `DevFileProtectedBootstrap` beside `PgSessionStore` in `central-adapter-postgres::session`. That adapter's role is `sqlx` persistence, and the bootstrap token authority belongs to the protected-store owner (`central-adapter-linux`, the R5 broker).
   - Impact: the wrong adapter owns secret custody, and R5 would have to move it across crates.
   - Fix applied: `central-adapter-linux::dev_bootstrap`, constructible only behind the dev gate. R5 Task 14 replaces it with the broker implementation (R3 D1, Task 10; R5 Task 14).

4. **F4 `central-artifact` would journal into `run_events` directly.** Important. Blocking: yes. Plan: R4.
   - Evidence: R4 Task 7 said the artifact service "journals `artifact_finalized`". The DAG has no `central-artifact → central-eventjournal` edge.
   - Impact: Task 7 either cannot compile under the DAG or silently adds an edge.
   - Fix applied: the artifact service emits an artifact-owned `AttemptFinalization` change set. `central-adapter-postgres::artifact::finalization` maps it, in one transaction, to the `artifact_finalizations` row, the `run_events` envelope, and the `event_outbox` row (R4 Task 7 Step 2).

5. **F5 Duplicate retry persistence, and the scheduler→harness launcher had no home.** Important. Blocking: yes. Plan: R4.
   - Evidence, part 1: R4 Task 9 created `central-adapter-postgres/src/retry/` (`PgRetryStore`). Upstream implements `internal/retry/port` in `internal/adapter/postgres/scheduler/{store,outcome}.go`, and a second writer to `attempt_decisions` risks divergence.
   - Evidence, part 2: R4 Task 12 said "`NodeLauncher` is implemented by the R3 harness `Orchestrator` adapter", but upstream has a dedicated `internal/adapter/schedulerharness/` (launcher, killer, registry, brief + tests). It was not referenced, and no adapter crate may import two capabilities.
   - Impact: data-consistency risk in retry decisions, and Task 12 cannot be executed as written.
   - Fix applied: retry ports are implemented only on `PgSchedulerStore`/`PgOutcomeStore` (Task 6 Step 2, Task 9, File Structure). `central-kernel::scheduler_harness` ports `schedulerharness` with named tests, following the R2 `ArtifactReconcilerComponent` kernel precedent (Task 12 Step 1).

6. **F6 Operator binaries would compose adapters directly.** Important. Blocking: yes. Plan: R6.
   - Evidence: R6 Task 1 ("implement on top of the R1 runner" in `bins/central-migrate`) and Task 9 left composition inside the binaries. Boundaries §3 controller row forbids concrete adapters in `bins/*` (except `central-adapter-linux` in launcher and protected-mode bins), and R1 established that `bins/central` depends only on `central-kernel` + `central-foundation`.
   - Impact: the controller boundary is violated in R6 Tasks 1 and 9.
   - Fix applied: a global "Binary dependency rule" constraint, plus `central-kernel::{migrate_compose,backup_compose,restore_compose}` (R6 Global Constraints, Task 1 Step 2, Task 9 Step 2).

## Follow-ups (non-blocking)

- **M1 (resolved, finding corrected):** Roadmap §7 says "23-scenario recovery test matrix", while the spec catalog (`2026-10-07-phase-2-recovery-test-matrix.md` D1) lists 22 rows. Checking upstream `cmd/central/phase2_acceptance_test.go` (`TestPhase2RecoveryMatrix`, lines 804–805) shows RTM-19 recorded as two scenarios (`RTM-19-session`/P2F02 and `RTM-19-deadlines`/P2F03): 18 + 2 + 3 physical = 23. The roadmap is correct. The defect was in the R4 plan, which said "RTM-01…RTM-19", and it is fixed: Goal, Task 9 Step 1, and Task 13 Steps 2–3 now name both RTM-19 scenarios and assert exactly 23 evidence records.
- **M2 (resolved):** Boundaries §2.4 Linux-platform row listed only `central-authorization`/`central-infra`/`central-backup` port traits. After F2/F3, `central-adapter-linux` also implements the `central-harness` `WorkspaceSealer` and the `central-session` `ProtectedBootstrap`. The row in `docs/architecture/rust-application-boundaries.md` §2.4 now lists both (documentation only; no check is weakened, and the allowed/prohibited import columns are unchanged).
- **M3 (resolved, finding refined):** Upstream prune does not go through the R2 two-phase delete service. `internal/destructive/prune.go` uses its own `PruneJournal`, running as `central_migration`, with the ADR 0005 order (metadata → body → tombstone), per-body re-proof, and tombstone-presence resume. R6 Task 11 now specifies exactly that, reusing the R2 `ArtifactTombstone` type and `ObjectStore::remove_ready_for_delete` rather than direct object-store calls.
- Dependency approvals were decided by the maintainer on 2026-10-23 and recorded in the plans:
  - R5 D2: `libc =0.2.191`
  - R5 D3: `rcgen =0.14.10` with `ring` + `pem`
  - R5 D7: `tar =0.4.46` + `flate2 =1.1.10`
  - R6 D1: `aes-gcm =0.11.1`

  All versions were published ≥7 days before the decision, none are yanked, and each is confined to `central-adapter-linux`. Each must pass `cargo deny check` in the task that adds it.

## Coverage and Resolution

- Roadmap §6 (R3) → R3 Tasks 1–15 → covered; F1, F2, F3 resolved
- Roadmap §7 (R4) → R4 Tasks 1–14 → covered; F4, F5 resolved; M1 resolved
- Roadmap §8 (R5) → R5 Tasks 1–16 → covered; F2 (Task 14) resolved; M2 resolved
- Roadmap §9 (R6) → R6 Tasks 1–16 → covered; F6 resolved; M3 resolved
- Cross-plan JCS/archive dependency (R5 D6/D7 ↔ R6 D1) → covered (fixed earlier in this session)
