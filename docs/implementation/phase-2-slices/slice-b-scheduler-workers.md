# Slice 2B — Scheduler and Workers

- **Slice ID:** 2B
- **Dossier:** `slice-b-scheduler-workers.md`
- **Issue:** #93 — scheduler + worker protocol
- **Packets:** P2B01–P2B06
- **Dependency:** P2A06 (Slice 2A complete)
- **Outcome:** PostgreSQL-backed ready queue with atomic claim, dispatch with workspace provisioning, registered capability-matched workers holding fenced leases, loss detection, startup reconciliation, and enforced concurrency/admission limits

## Governing specs

- `docs/internal/superpowers/specs/2026-10-07-phase-2-task-leasing-worker-protocol.md` — registration, lease lifecycle, heartbeat, missed-beat ladder, fencing, reconciliation
- `docs/internal/superpowers/specs/2026-10-07-phase-2-workflow-graph-scheduling-design.md` — queue, atomic claim, dispatch shape, concurrency surface (spec 1 owns the claim-transaction boundary; this slice implements it)
- `docs/internal/superpowers/specs/2026-10-07-phase-2-concurrency-resource-limits.md` — cap table, `CheckDispatchAdmission`, budget aggregation, FIFO fairness, deferral semantics

## Slice 2B ownership

P2B01–P2B06 collectively own:

- the `SELECT … FOR UPDATE SKIP LOCKED` ready queue and the single-transaction `ready → dispatched` claim allocating `session_attempt` + lease;
- dispatch prepare → invoke outside transaction → persist outcome, including `code` git-worktree and `plain` private-directory workspace provisioning;
- worker registration, capability advertisement, and capability-constrained leasing;
- heartbeat renewal, the lease-as-fence durable-write guard, the suspect/lost missed-beat ladder, expiry consequences split by attempt state, deregistration, and startup reconcile-before-reinvoke;
- dispatch admission (`CheckDispatchAdmission`), cap enforcement (`max_parallel_sessions`, `max_inflight_nodes`, `max_nodes_per_run`, `max_depth`, workspace `disk_budget`), `admission_deferred` event-driven re-evaluation, and mid-session ceiling breach.

Slice 2B must not implement retry classification/backoff (2D), checkpoint/resume (2C), lineage (2A), or UI (2E). Heartbeats carry liveness only — never harness output (ADR 0035).

## Packets

- **P2B01** — Ready queue and atomic claim: `ready → dispatched` in one transaction with `session_attempt` idempotency and lease issuance
- **P2B02** — Dispatch and workspace provisioning: prepare → invoke → persist outcome; git worktree vs private directory; launch-argv grammar
- **P2B03** — Worker registration and capabilities: handshake, declared harness/workspace kinds, capability match inside the claim
- **P2B04** — Heartbeat renewal and lease fencing: conditional renewal, `LEASE_RENEWAL_STALE`, durable writes fenced by the live lease
- **P2B05** — Loss detection, expiry, and reconciliation: suspect/lost ladder, expiry split by attempt state, deregistration, startup reconcile-before-reinvoke
- **P2B06** — Concurrency admission and budgets: cap table enforcement, `CheckDispatchAdmission`, event-driven deferral, FIFO, mid-session ceilings

## P2B01

### Identity and outcome

Implement the ready queue and atomic claim: one transaction moves `ready → dispatched`, allocates the `session_attempt` row keyed `(node_id, attempt_seq)`, and issues the lease `(node_id, attempt_id, expires_at)`. Duplicate dispatch is impossible by construction.

### Implementation boundary

The ready set lives in PostgreSQL; claiming uses `SELECT … FOR UPDATE SKIP LOCKED` ordered FIFO by `ready_at` then `node_key`, honoring `not_before` (2D) and `attempt_seq` allocation under the node's lock. Only a node in `ready` can be claimed; the attempt-row unique key prevents doubles. Capability match (P2B03) and admission (P2B06) evaluate inside or immediately before the same claim boundary per spec 8 — the claim transaction is the enforcement point.

### Durable data and migration

Migration adds `session_attempt` (or adapts the B08 attempt table to the `(node_id, attempt_seq)` key and attempt journal) and the lease table `(lease_id, node_id, attempt_id, worker_id, issued_at, last_heartbeat_at, expires_at, heartbeat_interval)`. At most one live lease per `node_id`.

### Security and authority

Claim runs inside the task domain service; the lease row doubles — with `attempt_id` — as the fencing token for all later durable writes (P2B04).

### Failure, retry, cancellation, and recovery

A crashed claim transaction leaves the node `ready` — no attempt, no lease, no partial dispatch. A node that stays `ready` from admission failure carries `admission_deferred`, not a lost claim.

### Verification and evidence

- Concurrent claimants never double-dispatch one node
- Claim is one transaction: node state + attempt row + lease commit or none do
- `not_before` and FIFO order are honored
- Attempt idempotency key `(node_id, attempt_seq)` rejects a second row
- Future test suite: `go test ./internal/scheduler/...`
- Evidence artifact: `phase-2-slice-b-claim.json`

### Scope control

P2B01 owns the claim transaction boundary and queue discipline. It must not launch harnesses, heartbeats, or admission policy internals.

### Definition of Done

Claiming is atomic, structurally duplicate-safe, capability- and admission-gated, and leaves no partial state on crash.

## P2B02

### Identity and outcome

Implement dispatch: prepare (workspace provisioning) → invoke the harness launch outside any transaction → persist outcome. Each dispatch is exactly one harness session attempt under the closed launch-argv grammar (ADR 0036).

### Implementation boundary

Prepare provisions the workspace per locked isolation: `workspace_kind: code` → `git worktree add` at the task's recorded base ref under the instance scratch root; `workspace_kind: plain` → fresh directory `workspaces/<run>/<node>/`; the path is recorded on the attempt and reused by re-prepare (at-least-once provisioning dedupes on the recorded path). Invoke launches the harness adapter outside the transaction; outcome persists as `attempt_started` or `attempt_failed` with a dispatch-class reason code (`WORKSPACE_PROVISION_FAILED`, `LAUNCHER_REFUSED`, `ADMISSION_WAIT`). The attempt-scoped `central artifact read` credential (2A06) is injected at launch.

### Durable data and migration

Workspace path, harness session id (once known), and dispatch outcome ride the `session_attempt` row; events journal per P2A04.

### Security and authority

Workspaces live under the instance scratch root with path hygiene inherited from A06 sandbox bounds; launch argv is the closed grammar — no child-spec string reaches the command line unvalidated.

### Failure, retry, cancellation, and recovery

Provisioning or launcher refusal before `attempt_started` is a definite dispatch failure — `attempt_failed` with reason code; return to `ready` only via the 2D retry policy, else `failed_terminal`. Launch persisted but outcome unknown is `attempt_ambiguous` — operator decision, never auto-rerun.

### Verification and evidence

- `code` nodes get a git worktree at the recorded base ref; `plain` nodes get a fresh private dir
- Workspace path recorded on the attempt; re-prepare reuses it
- Invoke happens outside any open transaction
- Dispatch refusal journals `attempt_failed` with a dispatch-class reason code
- Unknown-outcome launch parks `attempt_ambiguous`, awaiting operator decision
- Future test suite: `go test ./internal/scheduler/... ./internal/execution/...`
- Evidence artifact: `phase-2-slice-b-dispatch.json`

### Scope control

P2B02 owns dispatch and workspace provisioning. It must not classify retryability, renew leases, or merge worktrees (merge policy is out of Phase 2 scope).

### Definition of Done

A claimed node dispatches as exactly one session attempt into an isolated, recorded workspace, with definite and ambiguous failure paths split correctly.

## P2B03

### Identity and outcome

Implement worker registration: a local Central process inserts a `worker_registration` row with a fresh `worker_id`, `protocol_version`, and declared capabilities; only capability-matched workers may hold leases.

### Implementation boundary

Capabilities declare launchable harnesses (e.g. `claude-code`), supported `workspace_kind`s (`code`, `plain`), and `max_concurrent_attempts`. Registration refuses `WORKER_REGISTRATION_REJECTED` on protocol-version mismatch or empty capability intersection with launchable harnesses. The P2B01 claim enforces the match — a worker may hold a lease only on a node whose `harness` and `workspace_kind` it declared. Workers are local processes; PostgreSQL rows are the entire protocol channel — no transport, no remote workers.

### Durable data and migration

`worker_registration` table from the P2B01 migration batch; fresh `worker_id` per process start (spec 2 OQ-7 default — no rejoin protocol).

### Security and authority

Registration is self-asserted capability, not privilege: it widens nothing — it only narrows which nodes a worker may claim.

### Failure, retry, cancellation, and recovery

Rejected registration journals `worker_registered`'s refusal counterpart with `WORKER_REGISTRATION_REJECTED`; the worker exits rather than claiming. Clean shutdown deregisters (`worker_deregistered`, P2B05 release paths).

### Verification and evidence

- Registration persists capabilities and protocol version
- Mismatched protocol version rejects `WORKER_REGISTRATION_REJECTED`
- Claim skips workers lacking the node's harness or `workspace_kind`
- `max_concurrent_attempts` bounds a worker's concurrent leases
- Future test suite: `go test ./internal/scheduler/...`
- Evidence artifact: `phase-2-slice-b-registration.json`

### Scope control

P2B03 owns the handshake and capability match. It must not renew leases, detect loss, or decide dispatch order.

### Definition of Done

Only registered, capability-matched workers hold leases; refusal is journaled with a reason code.

## P2B04

### Identity and outcome

Implement heartbeat renewal and lease-as-fence: workers renew on `heartbeat_interval` (default 15s, `expires_at = now + 3×interval`); every durable write on a node is accepted only under its current lease.

### Implementation boundary

Renewal is a conditional update on `(node_id, attempt_id, worker_id)` matching a live lease — extending `last_heartbeat_at`/`expires_at`. A renewal matching nothing rejects `LEASE_RENEWAL_STALE` and the worker aborts that attempt locally. The fence: artifact finalization, terminal attempt state, and node transitions present `(attempt_id, lease_id)`; writes under expired or superseded leases reject `LEASE_FENCE_STALE`. Same-host single clock — server timestamps authoritative, beats evaluated on arrival, no skew correction. Heartbeats are row updates, not journaled events; rejections journal `lease_renewal_rejected`.

### Durable data and migration

Lease columns from P2B01; no new tables. Fence enforcement lives in the domain-service write paths that also emit P2A04 events.

### Security and authority

The fence is the leasing layer's own exactly-once guarantee for durable effects; finer-grained command keys remain Slice 2D's. Heartbeat payloads carry no harness output (ADR 0035 non-intervention).

### Failure, retry, cancellation, and recovery

A hung worker resuming after its lease lapsed cannot produce durable effects — `LEASE_FENCE_STALE`. Stale-renewal abort is local and immediate.

### Verification and evidence

- Renewal extends `expires_at` only under a matching live lease
- Non-matching renewal rejects `LEASE_RENEWAL_STALE`; worker aborts
- Durable write under expired/superseded lease rejects `LEASE_FENCE_STALE`
- Heartbeat rows are not journaled events; rejections are
- Future test suite: `go test ./internal/scheduler/...`
- Evidence artifact: `phase-2-slice-b-lease-fencing.json`

### Scope control

P2B04 owns renewal and fencing. It must not declare worker loss (P2B05) or schedule retries (2D).

### Definition of Done

Leases renew conditionally, stale writers are fenced from every durable path, and reassignment-after-expiry is provably safe.

## P2B05

### Identity and outcome

Implement worker-loss detection, lease-expiry consequences, deregistration, and startup reconcile-before-reinvoke.

### Implementation boundary

The lease monitor (Central-internal sweeper) applies the missed-beat ladder: 2 missed beats → `worker_suspect` (observable only); 5 → `worker_lost` with `WORKER_LOST_GRACE_EXPIRED`, expiring all its leases in one transaction. Expiry splits by attempt state: never-started attempt → `attempt_failed` `LEASE_EXPIRED_NOT_STARTED`, node back to `ready`; started attempt → `attempt_ambiguous` (`ATTEMPT_AMBIGUOUS_LEASE_EXPIRED` / `ATTEMPT_AMBIGUOUS_WORKER_LOST`), parked for operator decision — never auto-requeued. Clean shutdown deregisters: never-started leases release `WORKER_SHUTDOWN_LEASE_RELEASED` and requeue; started attempts persist outcome first or expire into ambiguous. At startup the reconciler walks every lease before any new dispatch — expired leases follow the same paths, leases with unregistered `worker_id` count as lost.

### Durable data and recovery

All expiry transitions commit in single transactions with their events; reconciliation precedes claims after every restart — the Phase 1 reconcile-before-reinvoke precedent applied to leases.

### Security and authority

The sweeper is internal authority; no worker can veto its own expiry. Operator decision on ambiguous attempts is the 2D idempotent `attempt_decision` command rendered by 2E.

### Failure, retry, cancellation, and recovery

This packet IS the failure surface: `WORKER_REGISTRATION_REJECTED`, `LEASE_RENEWAL_STALE`, `LEASE_EXPIRED_NOT_STARTED`, `ATTEMPT_AMBIGUOUS_LEASE_EXPIRED`, `WORKER_LOST_GRACE_EXPIRED`, `ATTEMPT_AMBIGUOUS_WORKER_LOST`, `LEASE_FENCE_STALE`, `WORKER_SHUTDOWN_LEASE_RELEASED` — each journaled on its owning event. Expiry never produces `failed_terminal` by itself.

### Verification and evidence

- 2 missed beats → suspect event; 5 → lost, all leases expired atomically
- Never-started expiry requeues the node; started expiry parks `attempt_ambiguous`
- Reconciler completes before any post-restart dispatch; orphan-worker leases treated lost
- Clean deregistration requeues never-started work, refuses silently dropping started work
- Injected worker loss during a run yields the documented ambiguous path
- Future test suite: `go test ./internal/scheduler/...`
- Evidence artifact: `phase-2-slice-b-loss-reconcile.json`

### Scope control

P2B05 owns the sweeper, expiry paths, deregistration, and startup reconciliation. It must not resolve ambiguous attempts (operator) or apply retry backoff (2D).

### Definition of Done

Worker loss is detected on the documented ladder, every expiry path lands in its specified state, and no dispatch precedes startup reconciliation.

## P2B06

### Identity and outcome

Implement concurrency and resource-limit enforcement inside claim/dispatch: the cap table, `CheckDispatchAdmission`, event-driven deferral, FIFO fairness, and mid-session ceiling breach.

### Implementation boundary

Caps enforced per the spec-8 table — `max_parallel_sessions=4` global (operator config only), `max_inflight_nodes`/`max_nodes_per_run=64`/`max_depth=3` per run (launch envelope may narrow, never widen), session `wall_clock_ceiling`/`reported_cost_ceiling` bounded by the run, workspace `disk_budget` (default 8 GiB code / 4 GiB plain). `CheckDispatchAdmission(profile, snapshot)` mirrors `backup.CheckBackupAdmission`: measured quantities only — inflight sessions, per-run node counts, depth, per-device free bytes via `port.Capacity.Admit`/`port.CapacityChecker.HasCapacity`; admitted dispatches journal the reservation id on the attempt. Admission failure leaves the node `ready` with journaled `admission_deferred` (`CAPACITY_ADMISSION_DEFERRED`); re-evaluation is event-driven on capacity-freeing events — no poll loop. Mid-session breach of wall-clock/reported-cost ceilings triggers the harness cancel control and `SESSION_WALL_CLOCK_REACHED`/`SESSION_COST_CEILING_REACHED`/`WORKSPACE_DISK_BUDGET_EXCEEDED` on `attempt_failed`; the 2D policy decides what follows.

### Durable data and migration

`ConcurrencyProfile` (the `RecoveryProfile` analogue — validated to only narrow compiled-in bounds) plus reservation ids on attempt rows; migration included.

### Security and authority

Global caps are operator-only; child specs may tighten session ceilings, never loosen. Admission snapshots carry measurements, never paths, credentials, or object keys.

### Failure, retry, cancellation, and recovery

Deferral is a parked `ready` node, not an error; a deferred node keeps FIFO position. Ceiling breach is a definite `attempt_failed` once the cancel is confirmed; unconfirmed kill is `attempt_ambiguous` per the locked rule.

### Verification and evidence

- Fifth concurrent session defers while `max_parallel_sessions=4`; journals `admission_deferred`
- `max_nodes_per_run`/`max_depth`/parent-budget violations reject at validation (with 2A02)
- Freeing a session re-evaluates the deferred ready set in FIFO order — no polling
- Wall-clock and cost breaches cancel and journal the `SESSION_*_REACHED` codes
- Reservation ids on attempts audit admission after the fact
- Future test suite: `go test ./internal/scheduler/... ./internal/concurrency/...`
- Evidence artifact: `phase-2-slice-b-admission.json`

### Scope control

P2B06 owns admission checks, cap enforcement, and ceiling breach signals. It must not define retry budgets (2D), own capacity-port internals (Slice C machinery), or render limits (2E).

### Definition of Done

Every dispatch is admitted or deferred by measured capacity and named caps, ceilings enforce at session granularity, and fairness is FIFO with documented limits.

## Slice acceptance

**Gate:** `S2B-G1` — **Evidence:** `phase-2-slice-b-acceptance.json`

Slice 2B is complete when:

1. P2B01–P2B06 contracts are verified with passing tests
2. Claim is one atomic transaction — no double dispatch under concurrency (P2B01)
3. Dispatch provisions the correct workspace kind and follows prepare → invoke-outside-tx → persist (P2B02)
4. Only capability-matched registered workers hold leases (P2B03)
5. Stale leases fence every durable write (`LEASE_FENCE_STALE`) (P2B04)
6. The suspect/lost ladder, expiry split, and reconcile-before-reinvoke all behave per spec under injection (P2B05)
7. Caps, admission, deferral, and mid-session ceilings enforce with journaled evidence (P2B06)
8. Ambiguous attempts reach operator decision without any automatic rerun
9. The complete Slice 2B acceptance evidence is durably recorded

Slice 2B must not claim retry policy, checkpoint/resume, lineage, or UI capabilities — those are Slices 2C–2E.
