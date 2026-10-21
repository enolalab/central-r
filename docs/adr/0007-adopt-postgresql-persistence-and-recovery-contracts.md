# ADR 0007: Adopt PostgreSQL persistence and recovery contracts

- **Number:** 0007
- **Title:** Adopt PostgreSQL persistence and recovery contracts
- **Status:** Accepted
- **Created:** 2026-07-15
- **Owners:** Central maintainer
- **Decision due:** 2026-07-20
- **Decision due history:** None
- **Implementation blocked at:** persistence, migration, repository, and recovery implementation plans
- **Decided by:** Central maintainer
- **Decision date:** 2026-07-15
- **Decision record:** Git status-transition commit
- **Supersedes:** None
- **Superseded by:** None
- **Amends:** None
- **Amended by:** None
- **Related:** [approved Gate 6 PostgreSQL persistence design](../internal/superpowers/specs/2026-07-14-phase-0-postgresql-persistence-design.md), [Phase 0 PostgreSQL persistence plan](../internal/superpowers/plans/2026-07-14-phase-0-postgresql-persistence.md), [ADR 0001](0001-adopt-durable-task-domain-and-lifecycle.md), [ADR 0003](0003-adopt-phase-1-security-policy-and-secret-reference-model.md), [ADR 0004](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md), [ADR 0005](0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md), [ADR 0006](0006-adopt-local-v1-api-and-event-serialization.md), [ADR governance](README.md)

## Context

ADR 0001 established Task, Run, Step, and Artifact as durable Workspace-scoped aggregates with authoritative PostgreSQL current-state records and immutable Event appends. ADR 0003 established the security boundary, SecretReference, CSRF protection, and safe-content rules that every persistence write boundary must enforce. ADR 0004 established staged single-agent runtime and verified adapter-handoff semantics whose results must be queryable and resolvable from durable state. ADR 0005 established Central-mediated Artifact delivery with revalidation of authority, Workspace ownership, ready state, sensitivity, and delete intent before streaming. ADR 0006 established the v1 API and Event serialization contracts with cursor polling, idempotency keys, aggregate-version checks, and outbox delivery records that reference immutable Events.

These decisions require durable PostgreSQL persistence, transaction, concurrency, migration, retention, and recovery contracts that realize the accepted domain, runtime, Artifact, API, and Event meanings without changing them. The approved Gate 6 design defines those persistence contracts. Gate 6 is a design-only specification; this ADR proposes to adopt it.

## Decision

Central adopts the following Phase 1 PostgreSQL persistence and recovery decisions from the approved Gate 6 design:

- PostgreSQL 16 is the authoritative durable store for all Workspace, Task, Run, Step, StepAttempt, ToolCall, ToolCallAttempt, Approval, Checkpoint, Artifact metadata/lineage/tombstones, execution ownership, sessions, Events, and outbox delivery records; Artifact bodies remain in S3-compatible storage and are never stored in PostgreSQL;
- every durable aggregate row carries opaque identity, Workspace ownership where applicable, aggregate `version`, creation/update timestamps, and safe failure/recovery facts; foreign keys, Workspace-scoped uniqueness, check constraints, and immutable-Event protections preserve accepted ownership and lifecycle invariants without adding statuses or transitions;
- normalized current-state rows are authoritative and Events are immutable audit and recovery evidence, never the sole current-state source; no persistence write boundary may expose a plaintext secret, bootstrap/session/CSRF value, backend locator, raw object key/filename/body, or unbounded label in any Event, outbox, dead-letter, migration, or recovery evidence;
- migrations use the version-controlled, checksummed `golang-migrate` format and are forward-only, ordered, checksummed, and recorded durably; each production migration requires preflight checks, a backup/checkpoint or explicit restore precondition, bounded lock/transaction impact, verification, and resumable/idempotent data transformation where data changes; no automatic destructive down migration may rewrite or erase Event, Artifact lineage, tombstone, or audit history, and rollback uses a forward corrective migration or the documented restore runbook;
- commands use optimistic concurrency with expected aggregate version; row locking is used only to linearize Workspace-local `event_sequence` allocation, cross-aggregate completion barriers, Artifact finalization/delete intent, capacity ledger/reservation settlement, execution-ownership lease, and outbox claim; an accepted command atomically updates current state, increments affected versions, appends immutable Events, and creates any required outbox reference;
- a Workspace/Run Artifact capacity ledger with one reservation record per staging generation enforces non-negative counters and quota; reservation settle/release/cleanup/deletion act exactly once, and no concurrent admission may exceed workspace or run quota;
- durable command receipts keyed by Workspace, command scope, and idempotency key carry normalized-input fingerprint, expected version, result correlation, and bounded expiry; a matching key, fingerprint, and scope returns the original durable result, and a changed input or version fails without new state or Event;
- execution-ownership and outbox claims use opaque fencing tokens: renew, complete, fail, release, or heartbeat succeeds only for matching owner, token, and unexpired lease, preventing a stale claimant from settling work after re-claim; outbox delivery records reference one immutable Event and store delivery state separately, and an expired outbox lease is reclaimable without changing Event content;
- Events and Artifact tombstones are retained for the supported Phase 1 local-MVP lifetime; temporary data uses database-derived expiry and bounded cleanup with documented default windows (delivered outbox 7 days, dead-letter 30 days, expired sessions 24 hours, expired staging reservations/cleanup evidence 7 days) as minimum recovery-evidence windows; cleanup is resumable, bounded, idempotent, and never deletes a ready Artifact, required recovery evidence, Event, or tombstone;
- backup/restore uses a protected PostgreSQL-plus-object-store manifest with timestamp, identifiers, and checksums; writes are quiesced or restored to a documented consistent point; restore verifies database metadata, then objects, then startup reconciliation before serving or claiming work, and quarantines inconsistent Artifacts for operator resolution;
- database time is authoritative for lease, expiry, retention, and due-retry comparisons; cursor/list queries use seek pagination, bounded page size, and Workspace ownership predicates; lock timeout, serialization/deadlock, unavailable database, constraint conflict, migration interruption, and ambiguous external effects map to existing structured failure/retry/reconciliation semantics; no in-memory state is a durable recovery source.

The approved Gate 6 design owns the detailed transaction/lock/fencing matrix, query/index matrix, validation scenarios, role separation, retention and cleanup rules, and backup/recovery runbook.

### Decision boundary

This ADR does not select:

- SQL schema, table definitions, indexes, constraints, or DDL;
- Go types, interfaces, package paths, repository implementations, or dependency injection;
- Docker services, MinIO configuration, or local infrastructure topology;
- object-store operations, backup job scheduling, or runtime configuration;
- outbox delivery worker or query implementation;
- HTTP handler implementation, streaming adapters, or middleware.

Those decisions belong to Gates 7–8 and must preserve these persistence and recovery semantics or use a later ADR to change them.

## Consequences

### Benefits

- PostgreSQL 16 with normalized authoritative current-state rows and immutable Event appends durably realizes every accepted domain, runtime, Artifact, API, and Event contract without changing their meanings.
- Optimistic concurrency with expected-version checks prevents blind overwrite and converges with the accepted command idempotency discipline.
- Selective row locking for sequence allocation, completion barriers, quota settlement, Artifact finalization, lease claims, and outbox claims bounds serialization to the minimum required scope while keeping unrelated commands concurrent.
- Opaque fencing tokens on execution-ownership and outbox leases prevent a stale claimant from renewing, completing, or settling work after a new claimant acquires the lease.
- Forward-only checksummed `golang-migrate` with preflight checks, bounded locks, and resumable data transformations provides safe, auditable schema evolution; forward corrective migrations and a documented restore runbook replace automatic destructive down migrations.
- The capacity ledger with atomic reserve/settle/release, non-negative counters, and Workspace/Run quota enforcement prevents over-admission and ensures every reservation settles or releases exactly once.
- Durable command receipts keyed by Workspace, scope, and idempotency key converge with ADR 0006's idempotency semantics and the accepted domain transaction discipline.
- Database-time authority for leases, expiry, retry, and cleanup eliminates clock-skew disputes between processes.
- Immutable Event and tombstone retention for the supported MVP lifetime keeps cursors valid for every existing Workspace while bounded temporary-data cleanup prevents unbounded growth.
- Backup/restore with a protected manifest, consistent-point quiescence, and Artifact quarantine provides operator-controlled recovery without data corruption.
- Safe-content rules at every persistence write boundary enforce ADR 0003's security policy uniformly across Events, outbox records, dead letters, migrations, and recovery evidence.
- Least-privilege runtime, migration, and outbox roles prevent the runtime or cleanup process from mutating or cascade-deleting Events or tombstones.

### Costs and limitations

- Forward-only migrations prohibit automatic rollback to a prior schema version; every rollback requires a forward corrective migration or the documented restore runbook, which adds operator coordination in production.
- Workspace-local `event_sequence` allocation under row locking serializes Event append within a Workspace, bounding per-Workspace concurrency for high-frequency Event producers.
- Durable command receipts, outbox delivery records, capacity reservations, and immutable Events increase per-transaction write volume compared to populating only current-state tables; the trade is accepted durable execution and recovery evidence.
- Fencing-token lease management requires the runtime to periodically renew or heartbeat ownership for long-running executions; a neglected renewal loses the lease and requires a new claim with recovery.
- Event and tombstone retention for the supported MVP lifetime means no material Event removal occurs in Phase 1; a future retention-watermark decision must preserve cursor validity and current-state resync semantics.
- Cleanup defaults are minimum recovery-evidence windows; shortening them requires a later material policy decision, not a configuration change at runtime.

## Alternatives considered

### SQLite instead of PostgreSQL 16

Rejected because SQLite's single-writer concurrency, absence of role-based access control, and lack of native `FOR UPDATE SKIP LOCKED`, advisory locks, and concurrent migration tooling would force a different transaction, concurrency, role-separation, and migration model incompatible with Gate 6's stated semantics. PostgreSQL 16 is already a project constraint and provides the required optimistic concurrency, selective row locking, fencing, role separation, and forward-only migration primitives.

### Auto-generated bidirectional migrations

Rejected because automatic destructive down migrations risk erasing Event history, Artifact lineage, tombstones, or audit evidence. Forward-only migrations with a documented restore runbook let the operator choose corrective migration or restore, and the migration history provides full auditability without a dangerous automatic rollback path.

### Single monolithic database role

Rejected because a single role cannot enforce the accepted constraint that the runtime and cleanup processes must never update or cascade-delete Events or tombstones. Least-privilege roles for runtime, migration, and outbox workers provide a concrete enforcement boundary.

### Event sourcing without normalized current state

Rejected because ADR 0001 established normalized PostgreSQL current-state rows as authoritative with Events as immutable audit and recovery evidence. Replaying Events as the sole current-state source would add latency on every read, remove the enforcement value of declarative constraints and foreign keys, and conflict with the accepted domain model.

### In-process time for leases and expiry

Rejected because process clock skew between the API server, migration runner, and cleanup worker would produce inconsistent lease expiry, premature cleanup, or stale lease recovery. Database time as the single authority eliminates these disputes.

### Unbounded dual-store transactions

Rejected because cross-store two-phase commit between PostgreSQL and S3-compatible storage would add latency, complexity, and failure modes without providing stronger guarantees than the accepted Artifact-finalization atomicity semantics, which require PostgreSQL-finalize-then-object-persist ordering with reconciliation.

## Follow-ups

- Central maintainer explicitly accepts or rejects this ADR after proposal; Gate 6 design approval is not the ADR decision.
- Gate 6 specification owner defines canonical PostgreSQL schema, migration, and recovery contracts by `2026-07-20`.
- Gate 7 specification owner defines Go repository interfaces, handlers, and middleware by `2026-07-20`.
- Gate 8 specification owner defines Docker services, MinIO configuration, and local topology by `2026-07-20`.

## References

- [Phase 0 PostgreSQL Persistence Design](../internal/superpowers/specs/2026-07-14-phase-0-postgresql-persistence-design.md)
- [Phase 0 PostgreSQL Persistence Plan](../internal/superpowers/plans/2026-07-14-phase-0-postgresql-persistence.md)
- [ADR governance and index](README.md)
- [ADR 0001 — Adopt the durable Task domain and lifecycle](0001-adopt-durable-task-domain-and-lifecycle.md)
- [ADR 0003 — Adopt the Phase 1 security policy and SecretReference model](0003-adopt-phase-1-security-policy-and-secret-reference-model.md)
- [ADR 0004 — Adopt staged single-agent runtime and verified adapter handoffs](0004-adopt-staged-single-agent-runtime-and-verified-adapter-handoffs.md)
- [ADR 0005 — Adopt verified Artifact lifecycle and safe content delivery](0005-adopt-verified-artifact-lifecycle-and-safe-content-delivery.md)
- [ADR 0006 — Adopt the local v1 API and Event serialization contracts](0006-adopt-local-v1-api-and-event-serialization.md)
- [Durable execution](../architecture/durable-execution.md)
