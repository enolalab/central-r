# PostgreSQL Persistence Contract

## Authority and status

This is the canonical Gate 6 PostgreSQL persistence contract for the Central project. It defines authoritative records and invariants, transaction and concurrency rules, session persistence, capacity accounting, Event sequence and outbox semantics, migration and retention rules, query and index requirements, role separation, and validation scenarios for Phase 1.

These contracts implement the approved Gate 6 PostgreSQL persistence design and are adopted by Accepted ADR 0007. This document makes no SQL DDL, Go repository, or infrastructure claim. Phase 0 validates it through contract walkthroughs and repository checks. Phase 1 realizes it behind domain-owned interfaces without changing meaning.

This contract consumes ADR 0001 (durable Task domain and lifecycle), ADR 0003 (security policy and SecretReference model), ADR 0004 (staged single-agent runtime and verified adapter handoffs), ADR 0005 (verified Artifact lifecycle and safe content delivery), and ADR 0006 (local v1 API and Event serialization). Gate 7 owns Go realization; Gate 8 owns Docker/MinIO/local topology. Neither gate may change the meanings defined here without a later ADR.

**Accepted ADR 0011.** The local-topology alignment section at the end of this document maps every Gate 6/7 invariant onto the accepted local topology. Those mappings preserve the Gate 6/7 invariants.

PostgreSQL 16 is the authoritative durable store. Artifact bodies remain in S3-compatible storage and are never stored in PostgreSQL. Normalized current-state rows are authoritative; Events are immutable audit and recovery evidence, never the sole current-state source.

## Records and invariants

### Workspace ownership

Every Workspace-scoped record has non-null `workspace_id`. Cross-Workspace references are prevented by composite Workspace-scoped keys and foreign keys or equivalent constraints. No durable record may reference an aggregate, Event, Artifact, session, reservation, command receipt, or outbox entry belonging to another Workspace.

Composite keys incorporate `workspace_id` in every unique constraint and foreign-key relationship scoped to a Workspace. A delete of a Workspace cascades only to non-Events, non-tombstones, and non-recovery evidence through an explicit operator-controlled path; runtime and cleanup roles may not cascade-delete Events or tombstones.

### Aggregate versions

Every durable aggregate row carries:

- opaque aggregate identity;
- `workspace_id` where applicable;
- aggregate `version` (a non-negative, strictly increasing integer);
- creation and update timestamps derived from database time;
- safe failure and recovery facts.

Version is incremented on every accepted command that modifies the aggregate. An accepted command atomically updates current state, increments affected versions, appends immutable Events, and creates any required outbox reference. Optimistic concurrency uses expected aggregate version supplied by the caller; a mismatch fails as a durable conflict without blind retry, state change, or Event append.

### Immutable Events and tombstones

Events are append-only immutable records. No update, delete, or cascade-delete of an Event or tombstone row is permitted by the runtime or cleanup database roles. Events carry:

- opaque Event identity;
- `workspace_id` and Workspace-local `event_sequence`;
- identity of the producing aggregate, command, and Run;
- immutable Event type and safe serialized payload;
- database-derived creation timestamp.

Artifact tombstones are immutable non-body records that preserve safe lineage, delete-intent evidence, and deletion-outcome evidence. A tombstoned Artifact never becomes ready again. Tombstones prevent object-key and content-generation reuse. No runtime or cleanup operation may update or delete a tombstone.

Every persistence write boundary enforces Gate 5 Event allowlists (32 KiB payload, depth 8) and source redaction: no plaintext secret, bootstrap/session/CSRF value, backend locator, raw filename/key/body, or unbounded label enters any Event, outbox, dead-letter, migration, or recovery evidence.

### Command receipts

Every accepted command produces a durable command receipt keyed by `workspace_id`, command scope, and idempotency key. A receipt carries:

- normalized-input fingerprint (hash of the canonical command input);
- expected aggregate version at acceptance;
- result correlation (identity of the resulting Event, state transition, or outcome);
- creation timestamp and bounded expiry derived from database time.

A repeated command with matching `workspace_id`, scope, idempotency key, and fingerprint returns the original durable result, Event, and evidence without new state, Event, or side effect. A repeated command with a changed input or version fails closed with a structured mismatch failure; it performs no transition, no Event append, and no outbox creation. Expired receipts are eligible for bounded cleanup but the idempotency key must not be reused before the receipt is removed.

### Database roles

Three least-privilege database roles are required:

| Role | Permissions |
| --- | --- |
| `central_runtime` | Read/write current-state aggregates, read/write sessions, read/write reservations, read/write outbox records, read/write command receipts, and read every application table required to produce or verify a complete protected backup. Must not update or delete Events, tombstones, or other immutable evidence, and must not cascade-delete Events. Backup/restore verification uses a short-lived read-only transaction and cannot invoke runtime mutation ports. |
| `central_migration` | Full DDL on all schema objects. Read/write all tables including Events and tombstones only for forward corrective migrations or an explicitly confirmed offline `restore apply`. Must not execute destructive down migrations outside that restore contract. |
| `central_outbox` | Read/write outbox records (claim, delivery state, dead-letter). Read Events (referenced by outbox). Must not update or delete Events or tombstones. |

The runtime and outbox roles are separate from the migration role. The runtime role cannot grant permissions, create or alter schema objects, or execute DDL. Runtime, settlement, and cleanup processes use `central_runtime` and are prevented by permission enforcement from mutating or cascade-deleting Events or tombstones. `central_runtime` has exact read-only access to the migration/checksum history required by `MigrationInspector`, never update/delete/truncate authority over it. A short-lived backup or verification pool may authenticate as `central_runtime`, but its adapter exposes only read operations, begins read-only transactions where a transaction is needed, and is never shared with a serving profile. Gate 8 must partition one installation/target-wide PostgreSQL connection budget across all profiles and modes; every pool plus dedicated shared/exclusive advisory-lock, migration-runner, and operator connection counts. No process profile receives an independent copy of the cap.

## Approval and secret-use evidence

Existing Approval records — capability grant, capability revocation, and secret-use/audit evidence — are persisted as Workspace-scoped, safe, bounded, redacted durable records.

Approval records carry:

- opaque approval identity and `workspace_id`;
- granted/revoked capability identity and scope;
- actor, authority, and safe reason evidence;
- creation and expiry timestamps derived from database time;
- aggregate version for optimistic concurrency.

Secret-use audit evidence records:

- opaque evidence identity and `workspace_id`;
- reference to the SecretReference ID (never the secret value);
- actor, operation, and safe authorization outcome;
- creation timestamp derived from database time.

These records preserve the accepted lifecycle and retention semantics from ADR 0003 without creating new authority, statuses, or a new secret representation. No persistence write boundary may expose a plaintext secret, bootstrap/session/CSRF value, or backend locator in any Approval, secret-use, or audit record. Evidence redaction occurs before the write boundary: records contain opaque IDs, safe authorization outcomes, and bounded timestamps only.

## Session persistence

### Bootstrap verifier and exchange records

PostgreSQL is authoritative for bootstrap single-use linearization and stores only safe verifier/evidence facts:

- opaque bootstrap binding identity, Workspace identity, and local-principal authority binding;
- monotonically increasing registered generation, cryptographically random staging candidate identity, and SHA-256 token verifier;
- active or consumed state with database-derived creation/consumption timestamps;
- database-time failed-attempt window, count, next-eligible time, and bounded `Retry-After` outcome;
- pending session identity and safe rotation/recovery correlation where an exchange committed;
- no plaintext bootstrap/session/CSRF value and no protected-store path, locator, or filename.

Each valid exchange stages replacement plaintext create-only under a cryptographically random candidate ID that is distinct from the database generation. One transaction locks and revalidates the active generation, verifier, throttle eligibility, authority binding, and unconsumed state; consumes it; atomically allocates the next monotonic registered generation; binds that generation to the caller's exact candidate ID and verifier; creates a non-authenticating `pending_bootstrap` session with hashed session/CSRF verifiers; and records safe rotation evidence. This is the single-use linearization point. A concurrent or replayed exchange against the consumed generation creates no session and cannot reactivate that generation. A loser deletes only its own candidate ID; it cannot address the winner by proposed generation. Invalid attempts atomically advance database-time throttling without staging or registering replacement material.

Protected-store activation occurs after this transaction and requires the exact registered candidate ID, generation, and digest. A second transaction changes the exact bound `pending_bootstrap` session to non-authenticating `delivery_pending` only after matching replacement activation succeeds. Transport builds the cookie/CSRF response in the bounded non-streaming response buffer. Immediately before buffer commit, a transport-owned precommit hook atomically activates that exact session if the candidate/generation/digest, pending state, authority/security epoch, and buffer request identity still match; activation installs a database-time first-use deadline. Only successful activation permits the buffer to flush. A response-write failure triggers best-effort conditional revocation and safe recovery evidence; crash or uncertain delivery after activation leaves an unreachable session bounded by the first-use predicate. Recovery revokes `pending_bootstrap` or `delivery_pending` sessions whose plaintext response credentials were lost, activates only protected material whose exact registered triple matches, and deletes only individually identified unregistered candidates after rechecking that they are not registered. Recovery never rolls a consumed generation back to active or deletes a registered winner.

### Session records

Server-side session records carry:

- opaque session identity and `workspace_id`;
- hashed session token (SHA-256 of the opaque token; the plaintext token is never stored);
- hashed CSRF verifier (SHA-256 of the opaque verifier; the plaintext verifier is never stored);
- authority binding (reference to the authenticated principal identity);
- `created_at` and `last_seen_at` timestamps derived from database time;
- idle expiry timestamp (database time `last_seen_at` + configured idle timeout);
- absolute expiry timestamp (database time `created_at` + configured absolute timeout);
- revocation flag and revocation timestamp;
- lifecycle state distinguishing non-authenticating `pending_bootstrap` from active and revoked sessions;
- for bootstrap-created sessions, non-authenticating `delivery_pending`, delivery outcome, database-time first-use deadline (default one minute, hard maximum five minutes), and nullable one-way `first_used_at`;
- bootstrap-rotation evidence: previous session identity and rotation timestamp when a session is refreshed.

Session records are Workspace-scoped. A session identity is globally unique but the session belongs to exactly one Workspace.

### Session lifecycle

| Operation | Behavior |
| --- | --- |
| Bootstrap exchange commit | Atomically consumes one bootstrap generation, allocates the next generation, registers the caller's exact random candidate ID plus verifier, creates one `pending_bootstrap` session, and records safe rotation evidence. Concurrent losers and replay create no session and clean only their own candidates. |
| Prepare bootstrap delivery | After exact candidate/generation/digest activation, atomically changes the bound `pending_bootstrap` session to non-authenticating `delivery_pending`. |
| Activate bootstrap session | A transport precommit hook atomically changes the exact `delivery_pending` session to active immediately before flushing the buffered credential response. Activation failure discards the buffer. Response-write failure conditionally revokes best-effort; uncertain/lost delivery is bounded by the first-use predicate. |
| Create session | Atomically inserts session row with hashed token/CSRF, authority binding, created/last-seen, and expiry timestamps. Records bootstrap-rotation evidence if replacing a prior session. |
| Refresh session | Atomically updates `last_seen_at`, recalculates idle expiry, and may rotate token/CSRF hashes. Rotation creates a new session identity and records the prior identity as bootstrap-rotation evidence. The old session is atomically revoked in the same transaction. |
| Validate session | Computes the presented-token hash and atomically requires matching `workspace_id`, current security epoch, active/non-revoked/non-expired state, and—for a bootstrap-created session—`first_used_at IS NOT NULL OR database_time <= first_use_deadline`. The first successful validation writes `first_used_at` and `last_seen_at` in that same statement. |
| Logout/revoke | Atomically sets the revocation flag and revocation timestamp. After revocation is durable, no token refresh, validation, or heartbeat succeeds for that session. |
| Cleanup expired | Removes session rows where absolute expiry or idle expiry is before database time and the session is revoked or expired. Cleanup never revives a revoked or expired session: it only removes rows that satisfy both expired-or-revoked state and elapsed database time beyond the configured cleanup window (default 24 hours after expiry). |

### Session invariants

- Hash-only storage: the plaintext token and CSRF verifier are never stored in PostgreSQL, never appear in any Event, outbox, dead-letter, or log entry.
- Bootstrap single-use: generation consumption, exact candidate/generation/verifier registration, pending-session creation, and rotation evidence commit together. Consumed generations never become active again; `pending_bootstrap` and `delivery_pending` sessions never authenticate.
- First-use fence: validation at or before the database-time deadline linearizes by setting `first_used_at`; deadline revocation succeeds only while `first_used_at IS NULL` and database time is later than the deadline. Concurrent validate/revoke and exact-boundary behavior therefore have one database-authoritative winner.
- Atomic refresh/revoke: token rotation and old-session revocation commit in one transaction. There is no window where both an old and new session are valid for the same authority binding unless explicitly permitted by a configurable overlap window that is bounded and recorded as evidence.
- Cleanup never revives: a cleanup operation only removes rows where the session is already revoked or expired. It must check both the revocation flag and expiry timestamps against database time. A session that is within its validity window is never removed by cleanup regardless of other conditions.
- Authority binding is immutable after creation. Changing the principal associated with a session requires revocation and creation of a new session.
- Bootstrap-rotation evidence records the previous session identity and rotation timestamp. This evidence is durable and survives cleanup of the old session record.

## Capacity ledger and reservations

### Ledger structure

A Workspace/Run Artifact capacity ledger records current usage and enforces quota. One reservation record exists per staging generation.

The capacity ledger carries per-Workspace counters:

- total ready Artifact bytes (non-negative);
- total ready Artifact count (non-negative);
- per-Run ready Artifact bytes (non-negative, one counter per active Run).

The capacity reservation record carries:

- opaque reservation identity and `workspace_id`;
- Run identity and Artifact identity;
- staging-generation identity (immutable, never reused);
- reserved byte count and reserved count (1 per reservation);
- reservation state (`reserved`, `settled`, `released`);
- creation and settlement/release timestamps derived from database time.

### Reservation operations

| Operation | Lock or compare scope | Behavior |
| --- | --- | --- |
| Reserve | Row lock on Workspace capacity ledger and affected Run counter. | Atomically checks Workspace and Run quotas. If the reserved byte count plus current usage would exceed any quota, the reservation fails with a structured limit failure. On success, increments reserved counters and creates the reservation record in `reserved` state. Reservation occurs before any object-store call. |
| Finalize (settle) | Row lock on Workspace capacity ledger, Run counter, and reservation record. | Atomically rechecks quotas against current usage (policy may have tightened). Settles the reservation from reserved bytes to verified bytes, updates the reservation to `settled`, and increments the ledger ready-byte and ready-count counters. If quotas are exceeded at settlement time, the reservation is rejected with a structured limit failure instead. |
| Reject | Row lock on reservation record and Workspace/Run counters. | Atomically releases the reserved bytes back to the counter and sets reservation to `released`. |
| Cleanup (stale) | Row lock on reservation record. | For a `reserved` or `released` reservation whose staging lifetime is expired, releases reserved bytes exactly once and records cleanup evidence. |
| Delete (Artifact) | Row lock on reservation record and Workspace/Run counters. | When a ready Artifact is deleted, decrements the ledger ready-byte and ready-count counters, sets reservation to `released`, and records tombstone evidence. |

### Reservation invariants

- Non-negative counters: no ledger counter may become negative. Any operation that would decrement a counter below zero fails with a structured constraint failure.
- Exactly-once release: each reservation settles or releases exactly once. A reservation already in `settled` or `released` state rejects any further settlement or release attempt (idempotent return of prior result).
- Quota non-overadmission: concurrent reserve or finalize operations linearize through row locking on the Workspace capacity ledger and affected Run counter. The lock scope is the minimum required to prevent over-admission while keeping unrelated Workspace operations concurrent.
- Staging-generation identity is immutable and never reused. A retry creates a new reservation with a new staging generation.

## Event sequence and outbox

### Event sequence

Events are immutable records with identity and ordering.

Every Event carries:

- opaque Event identity;
- `workspace_id`;
- `event_sequence` — a strictly increasing integer per Workspace, allocated atomically with Event append and command receipt commit; normal transactional allocation is contiguous, but restore, import, or governed forward correction may introduce a missing number;
- Event type (string, from the accepted Event type vocabulary);
- safe serialized payload (32 KiB maximum, depth 8 maximum);
- producer aggregate identity, command identity, and Run identity;
- database-derived creation timestamp.

Event sequence allocation, Event row append, and command receipt creation commit in one atomic transaction. Replay of a command never allocates another sequence. A rejected command or a transaction that fails or rolls back before commit consumes no sequence and leaves no gap. Normal transactional allocation is gap-free, but a consumer reading Events by `(workspace_id, event_sequence)` must still tolerate a missing number after restore, import, or a governed forward corrective migration; it uses the sequence only for ordering, not for deduplication or proof of completeness.

### Outbox records

An outbox record references exactly one immutable Event and stores delivery state separately.

Every outbox record carries:

- opaque outbox identity and `workspace_id`;
- reference to the immutable Event (Event identity, never Event body);
- delivery state (`pending`, `claimed`, `delivered`, `dead_letter`);
- due time (`due_at`) — the earliest database time at which delivery may be attempted;
- retry time (`retry_at`) — the next database time at which a failed delivery may be retried;
- owner identity — the executor or worker instance that currently holds the claim;
- opaque fencing token — a unique token generated at claim time and required for any state change;
- lease expiry — database time after which the claim is considered expired and reclaimable;
- attempt count — number of delivery attempts made so far;
- safe failure reason — structured failure classification, bounded and redacted;
- dead-letter evidence — safe, redacted reason for dead-letter entry when attempts are exhausted.

### Outbox operations

| Operation | Required match | Behavior |
| --- | --- | --- |
| Claim | None (claim from `pending` or expired lease) | Uses `FOR UPDATE SKIP LOCKED` with `WHERE (delivery_state = 'pending' OR (delivery_state = 'claimed' AND lease_expiry < database_time)) AND due_at <= database_time`. Atomically sets state to `claimed`, records owner, generates opaque fencing token, sets lease expiry, and increments attempt count. |
| Renew/heartbeat | Owner, token, unexpired lease | Atomically extends lease expiry. |
| Complete | Owner, token, unexpired lease | Atomically sets state to `delivered`, records delivery timestamp, and clears owner/token/lease. |
| Fail (retryable) | Owner, token, unexpired lease | Atomically sets state to `pending`, clears owner/token/lease, sets `retry_at` with backoff, records safe failure reason. Increments attempt count already performed at claim time. |
| Fail (terminal / dead-letter) | Owner, token, unexpired lease | Atomically sets state to `dead_letter`, records dead-letter evidence, clears owner/token/lease. |
| Release | Owner, token, unexpired lease | Atomically sets state to `pending`, clears owner/token/lease. Used for graceful release without failure. |

### Outbox invariants

- Every state-changing outbox operation (renew, complete, fail, release) must match owner, fencing token, and unexpired lease. A mismatch on any of these rejects the operation as stale-owner.
- An expired lease makes a record reclaimable. The next claimant generates a new fencing token; the prior owner can no longer affect the record.
- A retry never changes the referenced Event. The Event reference is immutable for the lifetime of the outbox record.
- Dead-letter records preserve safe, redacted failure evidence. Dead-letter state is retained for the configured dead-letter retention window (default 30 days) before cleanup eligibility.
- Outbox records are Workspace-scoped. The `workspace_id` on the outbox record must match the `workspace_id` of the referenced Event.

### Execution ownership

Execution ownership uses the same fencing-token model as outbox records. An execution-ownership record carries:

- owner identity;
- opaque fencing token;
- lease expiry (database time);
- heartbeat timestamp;
- identity of the claimed Run, Step, or StepAttempt.

Renew, heartbeat, complete, fail, and release operations on execution ownership must match owner, token, and unexpired lease. A stale owner whose lease has expired cannot renew or settle. Startup recovery scans execution-ownership records for expired leases and reclaims them.

## Transaction, lock, and fencing matrix

Each critical operation identifies atomic writes, expected-version behavior, lock predicate, retry/failure mapping, and stale-owner rejection.

| Operation | Atomic writes | Expected-version behavior | Lock predicate | Retry/failure mapping | Stale-owner rejection |
| --- | --- | --- | --- | --- | --- |
| Command replay (idempotent receipt check) | None if receipt matches; state update + Event append + receipt create if new | Fingerprint and version match returns prior result; fingerprint mismatch fails closed | Row lock on receipt by `(workspace_id, scope, idempotency_key)` if new | Mismatch: structured failure, no state change. DB unavailability: existing retry semantics. | N/A (receipt is Workspace-scoped, no lease) |
| Event sequence allocation + Event append + receipt commit | Event row insert, sequence counter increment, receipt insert, aggregate state update, version increment | Aggregate version must match expected; mismatch fails closed with no sequence allocation | Row lock on Workspace sequence counter | Version conflict: no retry, caller must re-read and retry. Constraint violation: structured failure. | N/A |
| Required-Artifact completion barrier | Artifact finalization + aggregate (Task/Run/Step) state update + Event append | All affected aggregate versions must match expected | Row lock on Artifact record and each affected aggregate | Version conflict on any aggregate: no partial commit. Quota conflict: structured failure, no ready state. | N/A |
| Quota admission (reserve) | Reservation record insert, ledger counter increment, limits snapshot | Reservation is new (no prior identity); fingerprint mismatch if retried with changed bytes | Row lock on Workspace capacity ledger and Run counter | Quota exceeded: structured limit failure. Fingerprint mismatch: fail closed. | N/A |
| Quota settlement (finalize) | Reservation state update (settled), ledger ready-byte and count increment, Artifact state → ready | Reservation must be in `reserved` or `staging`/`verifying` state; Artifact version must match | Row lock on reservation, Workspace ledger, Run counter | Reservation already settled: idempotent return. Quota exceeded at settlement: reject with limit failure. | N/A |
| Quota release (reject/cleanup/delete) | Reservation state update (released), ledger counter decrement, optional tombstone insert | Reservation must be in `reserved`, `staging`, `verifying`, or `released` (for cleanup); Artifact version must match for delete | Row lock on reservation, ledger counter (for decrement) | Already released: idempotent return. Counter would go negative: constraint failure. | N/A |
| Artifact finalization (ready) | Artifact state → ready, integrity metadata, lineage, classification. When required: aggregate completion guard update + Event append. | Artifact version must match expected; `delete_pending` blocks finalization | Row lock on Artifact record | Delete-intent conflict: transition to ready rejected. Version conflict: no state change. | N/A |
| Artifact delete intent | Artifact state → `delete_pending`, tombstone insert | Artifact version must match expected | Row lock on Artifact record | Already `delete_pending` or `deleted`: idempotent return. Version conflict: no state change. | N/A |
| Execution-ownership claim | Ownership record insert/update, Run/Step state transition | Run/Step version must match expected | Row lock on execution-ownership record by `(workspace_id, owner_scope)` | Stale-owner: existing owner with unexpired lease blocks claim. Version conflict: no state change. | Yes: claim fails if current owner holds unexpired lease |
| Execution-ownership renew/heartbeat/complete/fail/release | Ownership record update, optional Run/Step state transition | Owner, token, and unexpired lease must match | Row lock on ownership record | Stale token or expired lease: structured stale-fencing rejection. Version conflict: no state change. | Yes: operation rejects if owner, token, or lease does not match |
| Outbox claim | Outbox record state → `claimed`, owner, token, lease, attempt count increment | Record must be in `pending` or expired-lease `claimed` state; due time must be reached | `FOR UPDATE SKIP LOCKED` on eligible rows | No eligible rows: empty result set (not a failure). Constraint violation: structured failure. | Yes: claim generates new token; prior owner with expired lease is locked out |
| Outbox renew/heartbeat/complete/fail/release | Outbox record state update | Owner, token, and unexpired lease must match | Row lock on outbox record | Stale token or expired lease: structured stale-fencing rejection. | Yes: operation rejects if owner, token, or lease does not match |

All operations use database time for lease, expiry, due-time, retry-time, and cleanup comparisons. Local wall-clock skew must not affect any lease, expiry, or cleanup decision.

## Query and index matrix

All list and query paths use Workspace predicates, seek pagination, bounded page sizes, and database time for temporal comparisons. No query may return unbounded results; every list query has a configured maximum page size (default 100, hard maximum 1000).

| Query path | Ordered keys | Predicate and coverage intent | Bounded seek / claim pattern | Failure behavior |
| --- | --- | --- | --- | --- |
| Workspace Event seek | `(workspace_id, event_sequence)` | Retrieve Events for one Workspace in sequence order, optionally after a cursor. Supports cursor-based polling from ADR 0006. | `SELECT ... FROM events WHERE workspace_id = $1 AND event_sequence > $2 ORDER BY event_sequence ASC LIMIT $3` | Empty result set when cursor is at or beyond latest Event. Must tolerate sequence gaps. Page size bounded. |
| Due outbox claim | `(workspace_id, delivery_state, due_at)` or `(delivery_state, lease_expiry, due_at)` | Claim due or reclaimable outbox records across Workspaces. Uses `FOR UPDATE SKIP LOCKED` with `SKIP LOCKED` to avoid contention between workers. | `SELECT ... FROM outbox WHERE (delivery_state = 'pending' OR (delivery_state = 'claimed' AND lease_expiry < now())) AND due_at <= now() ORDER BY due_at ASC LIMIT $1 FOR UPDATE SKIP LOCKED` | Empty result set when no due records exist. Claimed rows are locked; other workers skip them. |
| Active execution-lease recovery | `(lease_expiry)` or `(workspace_id, lease_expiry)` | Find execution-ownership records with expired leases for startup recovery. | `SELECT ... FROM execution_ownership WHERE lease_expiry < now() ORDER BY lease_expiry ASC LIMIT $1` | Empty result set when no expired leases. Recovery must revalidate Run/Step state after scanning. |
| Artifact lifecycle and reconciliation | `(workspace_id, state, staging_expiry)` or `(state, created_at)` | Find staging Artifacts past their staging lifetime; find orphan candidates; find pending deletions. Reconciliation uses cursor/batch/page budgets. | `SELECT ... FROM artifacts WHERE workspace_id = $1 AND state IN ('reserved', 'staging', 'verifying') AND created_at < now() - staging_lifetime ORDER BY created_at ASC LIMIT $2` | Empty result set when no eligible records. Page size bounded. Reconciliation cursor records progress. |
| Current Task/Run inspection | `(workspace_id, state)` or `(workspace_id, id)` | Inspect current Task or Run state for one Workspace. Single-row lookup or bounded state scan. | `SELECT ... FROM tasks WHERE workspace_id = $1 [AND state = $2] ORDER BY created_at DESC LIMIT $3` | Empty result set when no matching records. Single-row lookup by ID returns at most one row. |

All queries use database time (`now()` or equivalent) for temporal predicates. Queries that involve locking (`FOR UPDATE`) must use bounded lock timeouts and must not hold locks across external calls. Lock timeout, serialization failure, deadlock, and unavailable database map to existing structured failure/retry/reconciliation semantics. No in-memory state is a durable recovery source.

## Migration and rollback

Migrations use version-controlled, checksummed `golang-migrate` format. Migrations are forward-only, ordered, checksummed, and recorded durably in a schema-migrations table.

Each production migration requires:

- preflight checks (schema state, connection health, lock availability);
- a backup/checkpoint or explicit restore precondition;
- bounded lock and transaction impact (no long-running DDL without `CONCURRENTLY` where supported by PostgreSQL 16);
- verification of the resulting schema state;
- resumable and idempotent data transformation where data changes.

`migrate verify`, `migrate status`, and serving compatibility preflight use a read-only `MigrationInspector` with a short-lived `central_runtime` pool and an explicitly read-only transaction. It queries only allowlisted PostgreSQL catalogs and existing Central migration/checksum/progress history. It never constructs the golang-migrate driver, loads `central_migration`, creates or ensures a schema/version table, or writes evidence. Missing schema/history returns typed `uninitialized`; dirty, partial, unreadable, unsupported, or checksum-mismatched state returns typed incompatible or exact-recognized-resumable evidence without mutation. Migration status additionally composes a read-only protected-operator-state inspector and cross-checks provisioning target/operation/phase/epoch/candidate binding.

The migration-safety precondition is immutable verified-backup/checkpoint evidence for a new initialized-target migration, a sealed one-use `VerifiedEmptyTarget` capability for version-zero initial provisioning, or exact durable `ResumableMigration` evidence for `migrate resume`. The inspector mints the empty proof only under continuously held common target-exclusive, protected operator-state, and migration-specific ownership after proving the exact database target has no `central` schema, Central relations, migration/checksum history, or restore/security markers. It binds target/empty-state fingerprint, the single lock-owning session, embedded baseline migration/checksum-manifest digest, and provisioning operation identity and cannot be serialized or replayed. Resume evidence binds the original safety input, exact target/operation, version/source/checksum/classification, dirty state, and versioned progress/cursor.

All production migration mutation goes through a context-aware Central `MigrationRunner` used only by `migrate up` or exact-operation `migrate resume`; verify/status/preflight never construct it. Raw golang-migrate CLI and its upstream pgx/v5 database driver are unsupported production paths. The runner opens exactly one non-rebinding `central_migration` session and uses it for common target-exclusive acquisition, protected operator-state ownership when provisioning, migration-specific acquisition, safety-precondition consumption, every migration statement/batch, and every version/checksum/progress-history mutation. Common acquisition defaults to 30 seconds/hard five minutes; migration-specific defaults to 15 seconds/hard 60 seconds; their total defaults to 45 seconds/hard six minutes, with each phase receiving the lesser of its own and total remaining budget. Provisioning's intervening protected-state compare/claim is nonblocking; conflict returns class `4` `operator_state_busy` and closes the session. Other pre-mutation timeout is class `4` with a safe phase-specific reason. The runner owns invocation cancellation by closing the session and joins that hook before return; no context is stored in the context-free driver and no cancellation goroutine or connection can survive/rebind.

Version-zero never constructs golang-migrate. Before PostgreSQL mutation, provisioning persists external `initializing/recorded` bound to target, operation, epoch zero, protocol, and embedded baseline digest with no candidate. It then stages a create-only bootstrap candidate and atomically advances to `candidate_staged` with the exact candidate ID/digest; a candidate created before that replacement is non-authoritative and removable after five minutes by default/one hour hard only under exclusive ownership and repeated external/database no-reference checks. A Central-owned installer then consumes `VerifiedEmptyTarget` and uses one transaction on the lock-owning session to create the version relation, append-only checksum history, entire initial application schema, epoch-zero restore/security markers, exact initial bootstrap registration, and embedded baseline version/checksums. The baseline permits no non-transactional DDL, data backfill, or external effect. After exact verification, only the registered candidate activates and the external record becomes `ready`. `initializing`+empty or `initializing`+exact baseline resumes the same operation; missing/mismatched external binding, partial baseline, changed target/digest/candidate, or unknown phase fails `provisioning_repair_required` without auto-adoption. That class permits only provisioning a newly proved empty target and, when valid backup evidence exists, verified restore to that newly initialized target; it never permits direct external-state/SQL repair. Rollback leaves no Central relation; an indeterminate commit is read-only classified as empty or exact bound baseline. Every new later migration requires verified backup/checkpoint evidence.

Each data-backfill descriptor binds version/source/checksum/classification and a versioned progress schema. Before golang-migrate begins that version, the runner configures the driver with the exact descriptor, fresh operation, and original safety binding. The expected dirty `SetVersion` atomically records that binding and start cursor; `Run` rejects unexpected version/source before any batch, and each batch atomically commits its idempotent transformation and next progress. Because golang-migrate `Up()` rejects dirty state before `Run`, `migrate resume --operation=<id>` reacquires the lock order and invokes only the exact recognized embedded backfill coordinator directly. Completion verification precedes the single authorized dirty-to-clean `SetVersion`; metadata dirty state, generic `Force`, arbitrary clearing, changed/missing progress, or mismatched source/checksum/target remains failed closed for forward correction or restore.

For initialized targets, golang-migrate receives a Central-owned `database.Driver` bound to that same session, not a wrapper around the upstream pgx/v5 driver. Driver `Lock/Unlock` are local ownership checks; `Run`, `SetVersion`, and `Version` use only the bound session; `Open` is unsupported; `Drop` and generic force are denied; driver `Close` marks only library lifecycle completion. `SetVersion` accepts only golang-migrate's normal clean lifecycle or the runner-authorized exact completed-backfill dirty-to-clean transition. The runner alone closes the session after orchestration, which authoritatively releases both locks. Session loss makes further SQL impossible and releases both locks together, so ownership cannot pass while an old mutation channel remains live. Loss after possible mutation is class `6` and read-only inspection resolves rollback, recognized resume evidence, or forward correction. Tests cover phase/total timeouts, every provisioning/backfill crash boundary, initialized dirty classification, loss during initial/later DDL and batch commits, and proof that old-owner SQL cannot run after a new owner acquires.

Automatic destructive down migrations are prohibited. No migration may rewrite or erase Event rows, Artifact lineage, tombstone rows, or audit history. Rollback uses a forward corrective migration or the documented restore runbook.

Backup and restore use a protected PostgreSQL-plus-object-store manifest with timestamp, identifiers, and checksums. Every `central serve` profile acquires a target-scoped session-level shared advisory lock on a dedicated control connection before readiness and holds it for the profile lifetime; loss makes readiness false and cancels the profile. After all serve profiles stop, `backup create` acquires the matching exclusive lock before its accepted point and holds the same connection through snapshot/dump, object inventory, verification, and manifest seal, within a two-hour default/eight-hour hard total. Lock/process loss, cancellation after accepted point, or total expiry makes that operation terminal/non-resumable: partial chunks remain unreferenced and a new operation must establish a new point. Internal bounded slice yields retain the connection; only pre-point acquisition and non-mutating verification are resumable across a process boundary. The manifest records target, lock-protocol, operation, accepted-point, inventory-boundary, and sealing evidence.

The common exclusion matrix is: serve and target-reading verify/status commands take shared ownership; operator-state-only status takes none; `migrate up`, exact-operation `migrate resume`, backup create/accepted-point resume, and restore apply/resume-before-ready take exclusive ownership. Mutating migration acquires common target exclusion, protected operator-state ownership where applicable, then its target/schema migration lock. Read-only modes may coexist within the installation connection budget. No command upgrades in place; the lock order is common target, protected operator state, migration-specific lock, database transaction, object store.

`backup create`, `backup verify`, and the database-reading portion of `restore verify` use short-lived read-only `central_runtime` pools. Only the database/schema replacement portion of an explicitly confirmed offline `restore apply` uses `central_migration`; post-restore verification and quarantine return to typed domain paths under `central_runtime`. No backup or restore operation uses `central_outbox`.

Database and object inventory is canonical-key sorted and chunked. PostgreSQL enumeration uses a composite seek cursor over the canonical object key plus stable Artifact identity; S3-compatible enumeration uses the canonical key as `start-after` and never persists an opaque provider continuation token as durable authority. Each immutable chunk contains at most 1,000 bounded records, has a canonical encoding and checksum, and is written create-only under an operation/ordinal/content-hash identity. The sealed root manifest commits the ordered chunk identities and checksums. Cross-store verification performs a merge comparison with at most one database page and one object page resident, never materializes a complete inventory, and treats duplicate/non-canonical ordering as corruption.

After each verified chunk, the external protected operation state checkpoints phase, ordinal, database seek cursor, object key, cumulative counts/bytes, ordered checksum accumulator, and last committed chunk identity. Resume first revalidates that chunk and checkpoint, then continues idempotently; mismatch quarantines the operation. One work slice has finite page and elapsed budgets and checkpoint-on-cancellation behavior, so a large inventory progresses across slices rather than restarting. Local spool use is bounded to one encoded chunk per worker and incomplete chunks are not referenced by the root manifest. A backup becomes restorable only after every chunk and the root manifest are reverified and sealed; restore cannot reach `ready` until the corresponding complete comparison finishes.

Protected operator state is stored outside both the PostgreSQL target and its Artifact object store. Before initialization its only legal path is `absent -> initializing -> ready`; the `initializing` record carries the provisioning binding and phase required above, and exact baseline without it is not auto-adopted. Every initialized target has matching restore/security epoch markers inside PostgreSQL. The external record is integrity-protected and durably replaced with atomic write, flush, and parent-directory synchronization; it binds opaque target identity, monotonic restore and security epochs, current operation nonce, state, protocol version, and transition timestamp. After initialization its restore path is `ready -> applying -> verifying -> ready`, with `verifying -> quarantined -> verifying`; interrupted states may be resumed only by the same operation nonce after reacquiring exclusive target ownership. `initializing` is never a restore state.

Successful `restore verify` issues one protected, expiring, single-use verification ticket. The ticket binds its random operation nonce and issue/expiry times to the backup identity and manifest checksum; opaque target identity and current external restore epoch; target-state fingerprint; normalized safe configuration digest; database/server, schema/checksum-manifest, dump, object-store, and verification-tool versions; and the verified capacity/authority outcome. The target fingerprint covers the database system/database identity, current restore-epoch marker, schema version/checksum state, and protected object-namespace identity/generation without embedding credentials or locators. Before mutation, `restore apply` must reacquire exclusive target ownership, recompute those exact safe inputs under that ownership, and reject any mismatch, expiry, unknown version, prior consumption, or missing evidence. One atomic durable replacement of the external operator record consumes the ticket and transitions `ready` to `applying` with the same operation nonce and next epoch. The consumed ticket digest and timestamp remain as bounded resume evidence, so a crash cannot replay it as a new operation.

Backup create/verify and restore verify make durable allocation of an opaque operation identity their first protected operator-state write, before target/object work. Restore apply consumes and continues the verified operation identity/ticket rather than allocating an unknowable new ID. Status is non-mutating; apply/resume accepts only the exact operation identity/nonce, revalidates target, authority, evidence, phase, confirmation, and idempotent next action, and cannot restart, adopt, or replay a completed operation. Interactive destructive confirmation requires typing that verified identity; non-interactive apply supplies the same operation identity as both selection and confirmation plus the opaque target identity, and a generic yes flag is insufficient. All eight verbs expose versioned safe JSON with phase, exit class, retryability, resume requirement, and bounded progress but no credentials, paths, locators, object keys, unrestricted checksums, or ticket/nonce material.

After replacement restore advances to `verifying`, enters `quarantined` while any discrepancy remains, and performs a mandatory authority reset before `ready`. The proposed next security epoch is first persisted in the non-ready external operation record. The broker prepares one operation-bound bootstrap draft and retains its one-use plaintext only in protected storage. One idempotent PostgreSQL transaction then installs the matching restore/security epoch markers; revokes all active and pending sessions; consumes/cancels restored bootstrap exchanges and generations; expires claims, leases, and fencing tokens; suspends every effective grant with `restore_review_required`; disables every SecretReference pending reconciliation; allocates exactly one new bootstrap generation; and inserts the exact create-only recovery-bootstrap registration introduced by migration v26. Every session, bootstrap, grant, protected use, claim, lease, and fencing predicate compares the current security epoch.

The migration-only broker channel accepts prepare/activate calls only from the root broker socket under exact helper launch evidence for the protected operation. It activates only the registered candidate/generation/digest, persists an integrity-bound activation receipt, and durably deletes the protected plaintext before its sole presentation. If the protected bootstrap session already contains that exact activated binding but the recovery journal lacks the receipt because of a crash, resume reconstructs only that receipt and never registers a second candidate. Authority reset enumerates and deletes stale recovery-purpose generations by exact identity before preparing the operation-bound draft, including plaintext that was never presented. PostgreSQL then finalizes the aggregate authority-reset receipt; no session is created by reset. Restored bootstrap material is never accepted, and all unrelated/restored candidates are removed only by their exact identities. SecretReference reconciliation compares opaque identity and safe version/fingerprint with the current protected binding authority; re-enabling a reference or suspended grant requires a fresh bootstrap/login and new operator decision under the new epoch. Restore reaches `ready` only after complete inventory/quarantine resolution, successful fresh-bootstrap activation, and exact external/database restore and security epoch matches. A crash at any prepare/register/activate/finalize boundary remains in `verifying`; exact-operation resume reuses the same durable records idempotently. A missing, corrupt, unknown-state, stale, or mismatched external record/marker fails every serve profile closed before readiness or claims. The restore target cannot erase or roll back this external barrier.

Restore order is database metadata, object verification, then startup reconciliation before work is served or claimed. Restore failure quarantines inconsistent Artifacts for operator resolution. Backup access is restricted to the local operator/service identity; diagnostics are redacted.

## Retention and cleanup

Events and Artifact tombstones are retained for the supported Phase 1 local MVP lifetime. Event cursors remain valid while their Workspace exists. A future Event-retention watermark decision must return `410 cursor_expired` and preserve current-state resync semantics.

Temporary data uses database-derived expiry time and bounded cleanup with documented default windows:

| Record type | Default cleanup window | Minimum recovery-evidence window |
| --- | --- | --- |
| Delivered outbox records | 7 days after delivery | 7 days |
| Dead-letter records | 30 days after dead-letter entry | 30 days |
| Expired sessions | 24 hours after expiry or revocation | 24 hours |
| Expired staging reservations | 7 days after release or rejection | 7 days |
| Expired command receipts | 7 days after expiry | 7 days |

These windows are Phase 1 defaults and minimum recovery-evidence windows. Installed policy may lengthen them but may only shorten them through a later material policy decision. Cleanup is resumable, cursor/batch bounded, idempotent, auditable, and never deletes a ready Artifact, required recovery evidence, Event, or tombstone. Cleanup records safe cleanup outcome evidence before releasing temporary capacity.

See [migrations-and-recovery.md](migrations-and-recovery.md) for the full retention table — including cleanup evidence (7 days) and per-record eligibility conditions — and the complete cleanup contract (claim order, concurrency, idempotency, and evidence-before-release rules).

## Validation scenarios

The following validation scenarios are owned by the PostgreSQL persistence contract. They are validated in Phase 0 as contract walkthroughs and repository checks. Phase 1 implements them with a real PostgreSQL 16 instance and controlled concurrency.

### P01 — Concurrent ordinary transactions allocate a gap-free Event range

Two concurrent accepted commands in the same Workspace each allocate a unique, strictly increasing `event_sequence`. Sequence allocation, Event append, and command receipt commit atomically. Within normal transactional allocation from the same accepted recovery baseline, the committed range has no gaps. Rejected commands, version or constraint conflicts, and rolled-back transactions consume no sequence. The global field contract does not promise permanent numerical continuity: consumers tolerate a missing number introduced by restore, import, or a governed forward corrective migration.

### P02 — Expected-version conflict changes no state or Event

A command submitted with a stale aggregate version fails closed. No aggregate state changes, no Event is appended, no outbox record is created, and no receipt is written (or the receipt records the rejection with no state change). The caller receives a structured version-conflict failure.

### P03 — Receipt replay returns original result; fingerprint mismatch fails closed

A repeated command with matching `workspace_id`, scope, idempotency key, and fingerprint returns the original durable result, Event identity, and evidence. No new state, Event, or outbox record is created. A repeated command with a changed input (different fingerprint) or changed expected version fails closed with a structured mismatch failure. No transition, Event, or side effect occurs.

### P04 — Strict Event ordering under concurrent commits

Within a single Workspace, committed Events have strictly increasing `event_sequence` values. No two committed Events share the same sequence number. The sequence number for a committed Event is assigned atomically with the Event append and is never reused. Consumers seeking by `(workspace_id, event_sequence)` see committed Events in order and do not infer completeness from adjacency.

### P05 — Quota non-overadmission and exactly-once settlement

Concurrent reservation requests for the same Workspace linearize through row locking on the capacity ledger. The sum of reserved bytes plus current ready bytes never exceeds the Workspace quota. Each reservation settles or releases exactly once. A reservation already settled or released rejects further settlement or release idempotently. No ledger counter becomes negative. Replay, cleanup, and deletion settle or release one reservation exactly once.

### P06 — Stale fencing rejection

A stale outbox or execution owner attempts to renew, complete, fail, or release after a new claimant has acquired the lease with a new fencing token. The operation fails with a structured stale-fencing rejection. The stale owner's token and/or lease expiry no longer match the durable record. The new claimant is unaffected and may proceed.

### P07 — Outbox recovery and dead-letter

An outbox record with an expired lease is reclaimed by a new claimant. The new claimant generates a new fencing token. The reclaimed Event reference is unchanged. A record that exhausts its maximum attempts enters `dead_letter` state with safe, redacted failure evidence. Dead-letter records are retained for the configured retention window (default 30 days) and are not retried.

### P08 — Bootstrap staging race, activation recovery, and session revocation

Two exchanges of one active bootstrap generation stage different cryptographically random candidate IDs. The winning transaction consumes the old generation, allocates the next monotonic registered generation, binds that exact candidate ID/generation/digest, and creates one non-authenticating pending session. The loser creates no session and deletes only its own candidate. Recovery activates only the exact registered triple, never deletes the winner while cleaning a loser, and revokes delivery-pending sessions whose credential handoff was lost. A bootstrap-created active session that never makes a first authenticated use is revoked at its bounded first-use deadline.

A session logout or revocation atomically sets the revocation flag and revocation timestamp. After revocation is durable, no validate, refresh, or heartbeat operation succeeds for that session. Cleanup of expired sessions only removes rows that are already revoked or expired; it never revives a revoked or expired session. Refresh atomically revokes the old active session while creating its replacement; bootstrap rotation instead uses the staged multi-transaction protocol above.

### P09 — Bounded seek behavior

A Workspace Event seek with a page size of N returns at most N rows. When no Events exist after the cursor, an empty result set is returned. Under concurrent Event commits, the seek cursor is stable: rows committed before the cursor position are never returned again, and rows committed after the seek begins may or may not appear in the result set (snapshot isolation semantics). The consumer must tolerate a missing number introduced by restore, import, or governed forward correction, as well as the possibility of seeing Events from concurrent commits; ordinary rejected or rolled-back commands do not create such a gap.

### P10 — Unavailable, timeout, deadlock, and constraint failure mapping

Database unavailability maps to a structured retryable failure. Query timeout or lock timeout maps to a structured retryable failure with bounded retry. Serialization failure or deadlock maps to a structured retryable failure; the caller must re-read the current aggregate version and retry the full command. Constraint violation (foreign key, unique, check, not-null) maps to a structured non-retryable failure. Migration interruption leaves the migration history in a consistent state that can be resumed or rolled forward with a corrective migration. No in-memory state is used as a durable recovery source for any of these failure modes.

### P11 — Cross-Workspace access rejection

Any operation that references a `workspace_id` different from the owning Workspace of the target aggregate, Artifact, session, reservation, Event, or outbox record fails with a structured authorization denial. Composite keys and foreign keys prevent accidental cross-Workspace references. Queries using Workspace predicates only return results for the specified Workspace.

### P12 — Cleanup preserves Events, tombstones, ready Artifacts, and recovery evidence

A cleanup pass removes only eligible temporary records (delivered outbox beyond 7 days, dead-letter beyond 30 days, expired sessions beyond 24 hours, expired staging reservations beyond 7 days, expired command receipts beyond 7 days). It never deletes a ready Artifact, an Event, a tombstone, or required recovery evidence. Cleanup is resumable, bounded, and records safe outcome evidence before releasing capacity. A cleanup failure leaves the record in place with reconciliation evidence and does not retry indefinitely.

## ADR 0011 local-topology alignment

**Accepted ADR 0011.** This section maps the Gate 6/7 PostgreSQL persistence invariants onto the accepted local topology. It preserves every Gate 6/7 contract; the topology is a realization, not a replacement.

### Fixed local identities

Under ADR 0011 the three database roles (`central_runtime`, `central_outbox`, `central_migration`) receive separate SCRAM-SHA-256 password bindings generated by the root-owned broker. `central_runtime` and `central_outbox` retain their fixed tmpfs delivery rules. `central_migration` is delivered only to the fixed `central-migrate` no-login identity through the broker's authenticated SCM_RIGHTS handoff for one migration or reset invocation; the receiving process never opens a credential path by name. No password appears in Compose YAML, environment variables (except the fixed `_FILE` pointer inside the container), command arguments, or Docker labels.

The PostgreSQL server runs as the Compose `postgres` service on `127.0.0.1:55432` with a single `central` database and a single `central` application schema. The server image is pinned at `postgres:16.14` Debian Bookworm at exact OCI index, platform manifest, and config digests. Host-side `pg_dump` and `pg_restore` are pinned to the matching `16.14` version.

The `central serve` process runs directly on the host under the locked `central-runtime` service UID. It receives only `central_runtime` credentials through the broker handoff. It never loads `central_migration` or `central_outbox` credentials. Migration and restore-apply processes run as `central-migrate`, receive `central_migration` only through the verified SCM_RIGHTS handoff for their invocation lifetime, and close the descriptor immediately after completion, failure, or cancellation.

### Provisioning boundary

Version-zero provisioning remains the exclusive authority of `central_migration` behind the common target-exclusive plus protected operator-state plus migration-specific advisory lock ordering from the canonical migration contract. The external `initializing`/`candidate_staged`/`ready` state is stored in the root-owned protected store at `/var/lib/central-protected/v1/<instance-id>/operator-state/`. The `central-runtime` UID has no direct access to this store. The infrastructure helper mediates the directory creation, candidate placement, and atomic record replacement but never fabricates a `VerifiedEmptyTarget`, a migration-safety precondition, or a resume binding. Only `central migrate up`, running as `central-migrate` under the operator's fresh PAM session with helper-mediated exclusive lock acquisition, may construct and consume the empty-target proof. `central migrate reset` is restricted to the exact failed version-zero operation, requires fresh PAM plus the helper-owned TTY phrase `RESET VERSION-ZERO <full-instance-id> <full-target-id> <operation-id>`, and refuses an initialized/data-bearing target.

### Backup and restore under the local topology

The Gate 7 backup and restore contract (consistent-point capture, chunked inventory, manifest sealing, verify→apply ticket flow, quarantine, authority reset) remains unchanged in semantic. ADR 0009 adds the following topology realizations:

- **Backup manifest storage:** Sealed manifests, inventory chunks, and the root manifest are stored in `/var/lib/central-backup/v1/<instance-id>/` with root-owned directories and operator read access mediated by the infrastructure helper. The `central-runtime` UID has no access to backup repository paths.
- **Backup extensions:** `backup list`, `backup export`, `backup import`, `backup delete`, and `backup prune` operate on the local backup repository through the helper. They never invoke `pg_dump`/`pg_restore`, construct migration credentials, or access the running PostgreSQL target (except `backup list` which reads manifest metadata only).
- **Rescue backup:** `backup create --security-rescue` uses cold copies with conservative admission, never mounts authoritative payload roots writable, and produces exactly one marked current-epoch seal that remains unrestorable until current advisory authority returns. `backup security-rescue cleanup --operation=<id>` provides settlement-only cleanup.
- **Export integrity token:** `backup export` requires fresh PAM and physical-seat TTY and produces a broker-signed Ed25519 `bx1` token on the TTY only. The token is the sole Gate 7 exception to the generic checksum-output rule.
- **Wipe protocol:** `central local maintenance wipe` is a distinct destructive protocol requiring fresh PAM plus the helper-owned TTY confirmation of `WIPE <full-instance-id> <full-target-id> POSTGRES+MINIO`. It runs under an AppArmor-locked `central-local-infra` image with no network, no second mount, and one-root-at-a-time serialization. After wipe, credential reseed produces fresh SCRAM-SHA-256 password bindings for all database roles and fresh S3 credentials for all MinIO identities while preserving CA/trust material, preparation evidence, and signed advisory authority. There is no `--yes`, force, partial-root selector, or caller-supplied confirmation digest.

### No-auto-migrate rule

As prescribed by the migration contract, `central serve` never auto-migrates. The ADR 0011 `central local up` command applies the same rule: it runs `central migrate status` (read-only, `central_runtime`) and, if the target is uninitialized, exits with a safe `migration_required` diagnostic directing the operator to `central local init` (creates instance identity and protected state) followed by `central migrate up` (explicit operator command requiring exclusive target ownership and migration-safety evidence). Only `central migrate up`, `central migrate resume`, and the version-zero-only `central migrate reset` run as `central-migrate` and receive `central_migration` through a verified descriptor handoff. The `central serve` process, the `central local up` composed startup, and every backup/restore verify or status command are physically prohibited from constructing a `central_migration` connection.

### Cross-reference to adapter mapping

The PostgreSQL adapter mapping contract (§14) provides the detailed adapter-level realization: tool parenting, two-permit phases for restore, three-role credential delivery via tmpfs, PGOPTIONS for host-side tools, local operator mode adapter ownership, and no-auto-migrate enforcement at connection construction.
