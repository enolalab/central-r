# Phase 2 — task leasing and worker protocol — spec

Status: draft. Design-gate input under issue #91 (deliverable 2 of the
spec-gate table): specifies how workers register, hold, renew, and lose
leases on claimed nodes, and how a lost worker's attempts are
reconciled. No production code is authorized by this document;
implementation follows a reviewed plan and a
`docs/implementation/phase-2-slices/` dossier per the Phase 1
precedent. Vocabulary (node, edge, attempt, lease, readiness, claim) is
spec 1's and is reused unchanged.

## Scope

Owns: worker registration and capability advertisement; the lease
lifecycle (issue inside spec 1's claim transaction, renew on heartbeat,
release, expire); heartbeat interval and missed-beat rules; worker-loss
detection; abandoned-run reconciliation at startup
(reconcile-before-reinvoke, the Phase 1 precedent). Does NOT own:
scheduling policy, readiness computation, the claim transaction itself
(spec 1); retryable-vs-terminal classification and backoff (spec 4);
checkpoint content and resume tokens (spec 3); exactly-once boundaries
beyond the lease fencing rule stated here (spec 5).

## Locked inputs — maintainer decisions 2026-10-07

1. **Ambiguous session attempts are operator decisions.** A started
   attempt whose outcome becomes unknown goes to `attempt_ambiguous`;
   the operator chooses harness-native resume or a fresh rerun. No
   automatic re-launch, no auto-rerun — at every graph level.
2. **Lease expiry never auto-fails a node.** Expiry is not a terminal
   node failure; the node returns to `ready` through the spec 1 claim
   path — directly when nothing ran, or through the operator's rerun
   decision when the attempt is ambiguous.
3. **Workspace isolation is provisioned at dispatch.** `code` work gets
   a dedicated git worktree, other work a private directory —
   provisioned in the dispatch prepare phase (spec 1), never by the
   worker. Workers only *advertise* which `workspace_kind`s they can
   execute in.

## Design

1. **Single-host worker model.** A worker is a local process on the
   Central host. There are no remote workers and no worker network
   transport in Phase 2: PostgreSQL rows (registration, lease) are the
   entire protocol channel, and PostgreSQL is the source of truth.
2. **Registration handshake.** On start a worker inserts a
   `worker_registration` row: fresh `worker_id` per process start,
   `protocol_version`, `registered_at`, and declared capabilities —
   the harness types it can launch (e.g. `claude-code`), the
   `workspace_kind`s it supports (`code`, `plain`), and
   `max_concurrent_attempts`. Registration is refused with
   `WORKER_REGISTRATION_REJECTED` on protocol-version mismatch or an
   empty capability intersection with launchable harnesses. A worker
   may hold a lease only on a node whose `harness` and
   `workspace_kind` are inside its declared capabilities; the spec 1
   claim transaction enforces the match.
3. **Lease record.** One row per attempt, created inside the spec 1
   claim transaction: `(lease_id, node_id, attempt_id, worker_id,
   issued_at, last_heartbeat_at, expires_at, heartbeat_interval)`. At
   most one live lease per `node_id`. The `(attempt_id, lease_id)`
   pair doubles as the fencing token — see decision 7.
4. **Heartbeat and renewal.** The worker renews every
   `heartbeat_interval` (proposed 15s, OQ-5) by updating
   `last_heartbeat_at` and extending `expires_at` to
   `now + lease_ttl` (proposed `lease_ttl = 3 × interval`, OQ-6). The
   update is conditional on `(node_id, attempt_id, worker_id)` matching
   a live lease. A renewal that matches nothing — expired, released,
   or superseded — is rejected with `LEASE_RENEWAL_STALE`, and the
   worker must abort that attempt locally: it no longer owns the node.
   Drift tolerance: same host, single clock; server-side timestamps
   are authoritative and beats are evaluated on arrival time, so no
   clock-skew correction exists or is needed in Phase 2.
5. **Missed-beat ladder.** The lease monitor (a Central-internal
   sweeper, not a worker) evaluates `now − last_heartbeat_at` against
   the interval: 2 missed beats → worker `suspect` (`worker_suspect`
   event); 5 missed beats → `lost` (`worker_lost` with
   `WORKER_LOST_GRACE_EXPIRED`). `suspect` is observable only — it
   neither revokes leases nor blocks new claims. `lost` expires every
   lease the worker holds, in one transaction, each following the
   expiry path of decision 6.
6. **Expiry consequences, split by attempt state.** When a lease
   expires — by sweep or by worker loss:
   - attempt never reached `attempt_started`: the attempt row closes
     `attempt_failed` with `LEASE_EXPIRED_NOT_STARTED` (nothing ran —
     no ambiguity is possible) and the node returns to `ready` via the
     spec 1 claim path;
   - attempt started: the attempt goes to `attempt_ambiguous` with
     `ATTEMPT_AMBIGUOUS_LEASE_EXPIRED` (or
     `ATTEMPT_AMBIGUOUS_WORKER_LOST` when expiry came through worker
     loss). The node does NOT auto-requeue: resume-vs-rerun is the
     operator's decision (locked input 1); a rerun returns the node to
     `ready` as a new `attempt_seq`.
   In no branch does expiry produce `failed_terminal` by itself.
7. **Lease as fence.** A durable write — artifact finalization,
   terminal attempt state, node transition — is accepted only under
   the current lease for that node. A write presented under an expired
   or superseded lease is rejected with `LEASE_FENCE_STALE`. This is
   what makes reassignment safe: a hung worker that resumes after its
   lease lapsed can no longer produce durable effects. Finer-grained
   idempotency keys remain spec 5's; the fence is the leasing layer's
   own guarantee.
8. **Release paths.** Normal release rides the attempt's terminal
   write in the same transaction. Clean worker shutdown deregisters
   (`worker_deregistered`): leases on never-started attempts release
   with `WORKER_SHUTDOWN_LEASE_RELEASED` and their nodes return to
   `ready`; a started attempt may not be cleanly released — the worker
   must either persist its outcome first or leave the lease to expire
   into the ambiguous path.
9. **Startup reconciliation (reconcile-before-reinvoke).** Before
   accepting new claims after a Central restart, the reconciler walks
   every lease: expired leases follow decision 6, and live leases
   whose `worker_id` has no current registration are treated as lost.
   No new dispatch precedes this pass — the Phase 1
   reconcile-before-reinvoke precedent applied to leases.
10. **ADR 0035 non-intervention.** The protocol carries liveness and
    ownership only. Heartbeats contain no harness output; Central never
    parses loop output to make leasing or loss decisions.

## Failure semantics

Reason codes introduced here (carried on the events and attempt/node
records above):

- `WORKER_REGISTRATION_REJECTED` — handshake refused (protocol
  mismatch or no capability intersection).
- `LEASE_RENEWAL_STALE` — renewal rejected: lease expired, released,
  or held under a different `(attempt_id, worker_id)`.
- `LEASE_EXPIRED_NOT_STARTED` — lease lapsed before `attempt_started`;
  attempt closed as failed, node requeued.
- `ATTEMPT_AMBIGUOUS_LEASE_EXPIRED` — started attempt whose lease
  lapsed → `attempt_ambiguous`, operator decision.
- `WORKER_LOST_GRACE_EXPIRED` — worker exceeded the missed-beat grace;
  declared `lost`, all its leases expired.
- `ATTEMPT_AMBIGUOUS_WORKER_LOST` — running attempt of a lost worker →
  `attempt_ambiguous`, operator decision.
- `ATTEMPT_AMBIGUOUS_KILL_UNCONFIRMED` — session kill whose effect is
  unknowable → `attempt_ambiguous`, operator decision (the spec-4
  locked-input-2 path; added 2026-10-08 — Slice 2F acceptance found
  the implementation emitting this code with no vocabulary entry).
- `ATTEMPT_AMBIGUOUS_LAUNCH_UNKNOWN` — launcher invoke of unknowable
  outcome (unconfirmed launch) → `attempt_ambiguous`, operator
  decision, never auto-relaunch (added 2026-10-08 — same Slice 2F
  finding as above, via the P2F04 proof).
- `LEASE_FENCE_STALE` — durable write rejected under a stale or
  superseded lease.
- `WORKER_SHUTDOWN_LEASE_RELEASED` — clean deregistration released a
  never-started attempt's lease; node requeued.

Events this spec adds to the shared schema's coverage list:
`worker_registered`, `worker_deregistered`, `worker_suspect`,
`worker_lost`, `lease_expired`, `lease_renewal_rejected` — each
carrying `worker_id` plus spec 1's `(run_id, node_id, attempt_id?,
recorded_at, reason_code?)` where applicable. Individual heartbeats
are row updates, not journaled events; only state transitions are.

## Open questions

(Numbering continues from spec 1's OQ-1..4.)

- **OQ-5 — heartbeat cadence and loss thresholds.** Recommended
  defaults: interval 15s, `suspect` at 2 missed beats (~30s), `lost`
  at 5 (~75s). Trade-off: shorter detects faster, longer avoids
  declaring loss on a scheduler stall.
- **OQ-6 — lease TTL versus renewal model.** Recommended:
  `expires_at = now + 3 × interval`, renewed every beat, no maximum
  lease lifetime — attempt duration ceilings are spec 4's timeout
  hierarchy, not the lease's job. Alternative: a hard max lease age
  forcing re-claim; rejected unless review wants a bound.
- **OQ-7 — worker identity across restart.** Recommended: fresh
  `worker_id` per process start; the prior incarnation's leases are
  reconciled as lost at startup. Alternative: persisted worker
  identity allowing lease re-attach — adds a rejoin protocol for no
  Phase 2 benefit on one host.

## Acceptance criteria

- Spec review records a verdict under
  `docs/internal/superpowers/reviews/`.
- Vocabulary is consistent with spec 1 — node, attempt, lease,
  readiness, `attempt_ambiguous`, the claim transaction — and no term
  is renamed or contradicted.
- Every locked input is encoded as a rule; no maintainer decision is
  silently dropped.
- Every failure path above names a reason code, and every code in
  `## Failure semantics` is reachable from the design.
- The spec gates a `scheduler+workers` slice dossier and an
  implementation plan, per the Phase 1 precedent.
