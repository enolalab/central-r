# Phase 2 — concurrency and resource-limit policy — spec

Status: draft. Design-gate input under issue #91 (spec 8 of the
spec-gate table): defines the cap vocabulary, admission checks, budget
aggregation, and fairness baseline the Phase 2 scheduler enforces. No
production code is authorized by this document.

## Scope

Owns:

- cap vocabulary at four levels — global (host), graph/run, session,
  and node/workspace — with defaults and who may override each;
- admission checks at dispatch, built on the Slice C capacity-admission
  machinery that already exists (`backup.CheckBackupAdmission`,
  `infralifecycle/port.Capacity`, `dependencyprepare/port.CapacityChecker`);
- parent→child budget aggregation: wall-clock and reported-cost ceilings
  at session granularity per ADR 0035 §3;
- the fairness baseline (FIFO) and its documented limits;
- the reason-code vocabulary for capacity and budget failures.

Does NOT own: enforcement mechanics inside claim/dispatch — the
`SELECT … FOR UPDATE SKIP LOCKED` claim transaction, lease allocation,
and node transitions belong to the workflow-graph/scheduling spec,
which owns the transaction boundary this spec's policy is enforced
inside. Worker protocol, retry classification, and event field
definitions remain with their own specs.

## Locked inputs — maintainer decisions 2026-10-07

1. **Ceilings apply at session granularity, using whatever usage the
   harness reports** (ADR 0035 §3). Central never inspects loop output
   to estimate consumption; cost means the harness-reported figure or
   nothing.
2. **Workspace isolation kinds carry different resource footprints** —
   `code` worktrees share a repository and add checkout files; `plain`
   directories are fresh allocations. The policy accounts for both
   rather than applying one flat number.
3. Spec 1's OQ-3 proposed defaults (`max_parallel_sessions=4`,
   `max_depth=3`, `max_nodes_per_run=64`, per-graph
   `max_inflight_nodes`, FIFO by `ready_at` then `node_key`) are inputs
   this spec finalizes or revises with reasoning.

## Design

1. **Cap table.** Every limit is `{scope, limit, default,
   overridable-by}`:

   | scope | limit | default | overridable-by |
   | --- | --- | --- | --- |
   | global | `max_parallel_sessions` | 4 | operator instance config only — never a run, leader, or child spec |
   | graph | `max_inflight_nodes` | = `max_parallel_sessions` (one run may saturate the host; FIFO serializes) | run launch envelope may narrow |
   | graph | `max_nodes_per_run` | 64 | run launch envelope may narrow, never widen |
   | graph | `max_depth` | 3 | run launch envelope may narrow, never widen |
   | session | `wall_clock_ceiling` | declared per attempt; per-harness default lives in the harness-adapter spec (ADR 0035 amended ADR 0004) | child spec budget hint, bounded by run ceiling |
   | session | `reported_cost_ceiling` | same shape as wall-clock | child spec budget hint, bounded by run ceiling |
   | workspace | `disk_budget` | OQ-2; enforced against the device hosting the workspace path | run launch envelope may narrow |

   The table is the `ConcurrencyProfile` analogue of
   `backup.RecoveryProfile` (`internal/backup/recovery.go:50`): an
   installed profile that may narrow but never widen compiled-in
   bounds, validated the way `RecoveryProfile.Validate` refuses a
   weakened profile (`recovery.go:97`).

2. **Admission check reuses the Slice C shape, not the restore gate.**
   Dispatch admission is a pure function
   `CheckDispatchAdmission(profile, snapshot) → nil |
   AdmissionFailure{Reason}` modeled on `backup.CheckBackupAdmission`
   (`internal/backup/recovery.go:260`). The `snapshot` follows
   `CapacitySnapshot`'s rule (`recovery.go:229-240`): measured
   quantities only — inflight session count, per-run inflight and total
   node counts, proposed depth, per-device free bytes for the
   workspace root — never a path, credential, or object key. Where the
   check must consume a filesystem measurement it goes through the
   existing port surfaces — `port.Capacity.Admit` returning a
   `Reservation{ID, Allocated, Bound}`
   (`internal/infralifecycle/port/lifecycle_port.go:48-59`,
   implemented by `FilesystemCapacity.Admit` at
   `internal/adapter/infralifecycle/lifecycle_linux.go:771`) and
   `port.CapacityChecker.HasCapacity`
   (`internal/dependencyprepare/port/prepare_port.go:82`,
   `internal/adapter/dependencyprepare/capacity_linux.go`) — rather
   than a new statfs call. The broker's
   `assertRestoreCapacityReserveGate`
   (`internal/adapter/authority/broker/restore_capacity_gate_linux.go`)
   is the fail-closed precedent (every refusal is one of two reason
   kinds; "cannot ask" lands in the ineligible bucket), not the
   mechanism — its physical reserve is sized for destructive restores.
   An admitted dispatch journals its reservation id on the attempt so
   admission is auditable after the fact.

3. **Budget aggregation parent→child.** A node's *remaining budget* is
   its declared ceiling minus consumption — the sum of reported usage
   across its finished attempts plus live-reported usage of its current
   attempt. At child-spec validation the child's `budget.wall_clock`
   and `budget.cost` must each be ≤ the parent's remaining budget. A
   child spec exceeding the parent is **rejected at validation** with
   `child_spec_rejected` carrying `BUDGET_EXCEEDS_PARENT` — never
   silently clamped, because a clamp would let a leader believe it
   delegated budget it did not have. The child may itself be a parent:
   grandchildren draw against the child's declared budget, not the
   root's, so delegation narrows monotonically down the tree. A child
   spec that omits a ceiling inherits the parent's remaining budget as
   its ceiling — explicit, recorded, and still bounded.

4. **Workspace-kind footprints.** `code` workspaces are measured
   against the device hosting the repository worktree root; `plain`
   workspaces against the instance scratch root device. Both enter the
   admission snapshot as per-device free bytes alongside the
   `disk_budget` reservation; the worktree kind additionally counts
   against `max_nodes_per_run` bookkeeping as one node but carries a
   larger default disk expectation (OQ-2).

5. **Fairness baseline.** FIFO by `ready_at`, then `node_key`, shared
   across all runs on the host — a deferred node keeps its position in
   the queue rather than restarting it. This is a baseline, not a
   promise: no priorities, no preemption, no per-run quota in Phase 2;
   the recovery test matrix owns starvation detection.

6. **Admission deferral, not busy-poll.** When the claim-time
   admission check fails — cap exhaustion or a capacity floor — the
   node stays `ready`; no attempt row is created. An
   `admission_deferred` event is journaled with the failing reason
   code. Re-evaluation is event-driven: on any capacity-freeing event
   (attempt terminal transition, operator config change, workspace
   cleanup) the scheduler re-runs admission for the ready set in FIFO
   order. There is no poll loop and no backoff timer.

7. **Mid-session ceiling breach.** Wall-clock and reported-cost
   ceilings are enforced at session granularity: when harness-reported
   usage crosses the attempt's ceiling, the session receives the
   harness cancel control and the attempt closes with the
   `SESSION_*_REACHED` reason. The node returns to `ready` or
   `failed_terminal` per the retry policy spec — this spec supplies
   only the ceiling and the reason vocabulary.

## Failure semantics

Reason codes introduced here; each names the event that carries it:

- `BUDGET_EXCEEDS_PARENT` — on `child_spec_rejected`: declared child
  ceiling exceeds the parent's remaining budget.
- `MAX_NODES_PER_RUN_REACHED` — on `child_spec_rejected`: the batch
  would push the run past `max_nodes_per_run`.
- `MAX_DEPTH_EXCEEDED` — on `child_spec_rejected`: deepest proposed
  node exceeds `max_depth`.
- `CAPACITY_ADMISSION_DEFERRED` — on `admission_deferred`: host or
  profile cap unavailable at claim time.
- `SESSION_WALL_CLOCK_REACHED` — on `attempt_failed`: attempt exceeded
  its wall-clock ceiling.
- `SESSION_COST_CEILING_REACHED` — on `attempt_failed`: harness-reported
  usage crossed the attempt's cost ceiling.
- `WORKSPACE_DISK_BUDGET_EXCEEDED` — on `attempt_failed`: workspace
  growth crossed `disk_budget`.

## Open questions

- **OQ-1 — session ceiling defaults.** ADR 0035 assigns session-level
  ceiling defaults to the harness-adapter specification. Default here:
  the policy requires the fields, leaves per-harness values there.
- **OQ-2 — `disk_budget` default.** Proposed 8 GiB for `code`
  workspaces, 4 GiB for `plain`, pending a measurement pass on the
  reference host profile.
- **OQ-3 — `max_inflight_nodes` vs global cap.** Proposed: equal to
  `max_parallel_sessions`; alternative is a fraction reserving headroom
  for concurrent runs.
- **OQ-4 — deferral escalation.** Proposed: none in Phase 2 — a
  deferred node may wait indefinitely; whether a max deferral count or
  operator-visible staleness signal is needed is deferred to the
  recovery matrix spec.

## Acceptance criteria

- Spec review records a verdict under `docs/internal/superpowers/reviews/`.
- Every locked input is encoded as a numbered decision or carried as a
  numbered OQ.
- The cap table names `{scope, limit, default, overridable-by}` for
  every limit the scheduler checks; no unnamed knobs.
- The admission design cites the real reuse surfaces
  (`CheckBackupAdmission`, `port.Capacity.Admit`/`Reservation`,
  `port.CapacityChecker.HasCapacity`) — no invented function names.
- Every reason code names the journaled event that carries it; no code
  is emitted without an owning event.
- Nothing here contradicts spec 1's vocabulary (node states, claim
  transaction boundary, event names) or ADR 0035 (ceilings at session
  granularity, non-intervention).
