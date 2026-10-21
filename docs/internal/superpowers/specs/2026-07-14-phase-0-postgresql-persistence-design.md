# Phase 0 PostgreSQL Persistence Design

- **Status:** Approved
- **Date:** 2026-07-14
- **Phase:** Phase 0 — Architecture and foundations
- **Program gate:** Gate 6 — PostgreSQL persistence
- **Implementation target:** Phase 1 — Local Central MVP

## Objective

Define PostgreSQL representation, transaction, concurrency, migration, retention, and recovery rules that durably realize the accepted domain, runtime, Artifact, API, and Event contracts without changing their meanings.

## Phase boundary

This design defines persistence semantics only. It does not create SQL migrations, Go repositories, connection configuration, Docker services, backup jobs, HTTP handlers, or object-store topology.

## Authority and representation

PostgreSQL normalized current-state rows are authoritative for Workspace, Task, Run, Step, StepAttempt, ToolCall, ToolCallAttempt, Approval, Checkpoint, Artifact metadata/lineage/tombstones, execution ownership, sessions, Events, and outbox delivery records. Events are immutable audit and recovery evidence, never the sole current-state source. Artifact bodies remain in S3-compatible storage.

Every durable aggregate row has opaque identity, Workspace ownership where applicable, aggregate `version`, creation/update timestamps, and safe failure/recovery facts. Foreign keys, Workspace-scoped uniqueness, check constraints, and immutable-event protections preserve accepted ownership and lifecycle invariants. Gate 6 maps the existing states and commands; it never adds a status or transition.

Persistence also includes: a Workspace/Run Artifact capacity ledger and one reservation record per staging generation; durable command receipts keyed by Workspace, command scope, and idempotency key with normalized-input fingerprint, expected version, result correlation, and expiry; server-side session records with only hashed token/CSRF verifiers, authority binding, created/last-seen, idle/absolute expiry, revocation, and bootstrap-rotation evidence; and immutable Event identity plus unique `(workspace_id, event_sequence)`.

Every Workspace-scoped record has non-null `workspace_id`; cross-Workspace references are prevented by composite Workspace-scoped keys/FKs or equivalent constraints. Persistence write boundaries enforce Gate 5 Event allowlists (32 KiB, depth 8) and source redaction: no plaintext secret, bootstrap/session/CSRF value, backend locator, raw filename/key/body, or unbounded label enters Event, outbox, dead-letter, migration, or recovery evidence. Runtime, migration, and outbox roles are least-privileged and separate; runtime/cleanup roles cannot update/delete Events or tombstones or cascade-delete them.

## Transactions and concurrency

Commands use optimistic concurrency: the caller supplies expected aggregate version, and a mismatch fails as a durable conflict without blind retry. An accepted command atomically updates current state, increments affected versions, appends immutable Events, and creates any required outbox reference.

Use row locking only to linearize: Workspace-local `event_sequence` allocation; cross-aggregate completion barriers; Artifact finalization/delete intent; capacity ledger/reservation settlement; execution ownership lease; and outbox claim. Capacity admission/finalization/rejection/cleanup/deletion atomically lock or compare the affected Workspace/Run ledger, reserve/settle/release exactly once, and never permit a negative counter or quota over-admission.

Event sequence is strictly increasing and contiguous per committed Event in a Workspace; allocation, Event append, and command receipt commit atomically, so replay never allocates another sequence. Claims use opaque fencing tokens: renew, complete, fail, release, or heartbeat succeeds only for matching owner, token, and unexpired lease. This applies to outbox and execution ownership, preventing a stale claimant from settling work after re-claim. External provider, tool, object-store, and browser operations never occur inside an open transaction.

## Outbox and recovery

An outbox record references one immutable Event and stores delivery state separately. Workers claim due records with `FOR UPDATE SKIP LOCKED`, durable owner/lease expiry, attempt count, next eligible time, and safe failure reason. An expired claim is recoverable; a retry never changes its Event. Exhausted records enter a retained dead-letter state with sanitized evidence. Delivery/query implementation remains future work, but this persistence contract requires crash-safe claim and release semantics.

## Migration and rollback

Phase 1 uses PostgreSQL 16 and the version-controlled, checksummed `golang-migrate` migration format; Gate 7 selects Go invocation details but may not change migration semantics.

Migrations are forward-only, ordered, checksummed, and recorded durably. Each production migration requires preflight checks, a backup/checkpoint or explicit restore precondition, bounded lock/transaction impact, verification, and resumable/idempotent data transformation where data changes. No automatic destructive down migration may rewrite or erase Event, Artifact lineage, tombstone, or audit history. Rollback uses a forward corrective migration or the documented restore runbook.

Backup/restore uses a protected PostgreSQL-plus-object-store manifest with timestamp, identifiers, and checksums; writes are quiesced or restored to a documented consistent point. Restore order is database metadata, object verification, then startup reconciliation before work is served or claimed. Backup access is restricted to the local operator/service identity, diagnostics are redacted, and restore failure quarantines inconsistent Artifacts for operator resolution.

## Retention and cleanup

Events and Artifact tombstones are retained for the supported Phase 1 local MVP lifetime. Event cursors therefore remain valid while their Workspace exists; a future Event-retention watermark must return `410 cursor_expired` and preserve current-state resync semantics.

Temporary data uses database-derived expiry time and bounded cleanup: delivered outbox records 7 days, dead-letter records 30 days, expired sessions 24 hours, and expired staging reservations/cleanup evidence 7 days. These are Phase 1 defaults and minimum recovery-evidence windows; installed policy may lengthen them but may only shorten them through a later material policy decision. Cleanup is resumable, cursor/batch bounded, idempotent, auditable, and never deletes a ready Artifact, required recovery evidence, Event, or tombstone. It records safe cleanup outcome evidence before releasing temporary capacity.

## Query, index, and failure rules

Cursor/list queries use seek pagination, bounded page size, and Workspace ownership predicates. Gate 6 provides indexes for Workspace-local Event seek, due outbox claims, active lease recovery, Artifact lifecycle/reconciliation, and current Task/Run inspection; exact SQL/index syntax is implementation work. Queries expose only safe bounded summaries.

Database time is authoritative for lease, expiry, retention, and due-retry comparisons. Lock timeout, serialization/deadlock, unavailable database, constraint conflict, migration interruption, and ambiguous external effects map to existing structured failure/retry/reconciliation semantics. No in-memory state is a durable recovery source.

## Validation scenarios

1. Concurrent accepted transitions in one Workspace produce gap-free `event_sequence` and immutable Events.
2. Expected-version conflict changes no state or Event.
3. Required Artifact finalization commits Artifact, completion guard, and Events atomically or none do.
4. Expired outbox lease is reclaimed without changing Event content; exhausted delivery enters retained dead-letter state.
5. Cleanup removes only eligible temporary records and preserves Events, tombstones, ready Artifacts, and recovery evidence.
6. Interrupted forward migration resumes safely or follows the restore/corrective-migration runbook.
7. Cursor seek remains Workspace-scoped, bounded, and deterministic under concurrent Event commits.
8. Database clock—not process time—governs leases, expiry, retry, and cleanup.
9. Concurrent Artifact reservations/finalizations cannot exceed Run or Workspace quota; replay, cleanup, and deletion settle/release one reservation exactly once.
10. Concurrent duplicate HTTP commands return the original receipt/result/Event; changed input or version fails without new state or Event.
11. A stale outbox or execution owner cannot renew or settle after a new fencing-token claimant acquires the lease.
12. Session logout, expiry, bootstrap rotation, and cleanup never restore a revoked or expired session.

## Follow-ups

Gate 6 must propose the material persistence decision in ADR 0007, define canonical schema/migration/repository contracts, validate them, and align summaries before acceptance. Gate 7 owns Go realization; Gate 8 owns Docker/MinIO/local topology. No implementation begins from this Draft.
