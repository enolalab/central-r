# Migration and Recovery Contract

## Authority and status

This is the canonical Gate 6 migration and recovery contract for the Central project. It defines the forward-only migration lifecycle, metadata versus data-backfill classification, backup and restore manifest rules, retention windows, and cleanup contract. These contracts implement the approved Gate 6 PostgreSQL persistence design and are adopted by Accepted ADR 0007.

This document defines implementation-independent contracts only. It makes no SQL DDL, Go repository, infrastructure, or tooling claim. Phase 0 validates it through contract walkthroughs and repository checks. Phase 1 realizes it behind domain-owned interfaces without changing meaning. Gate 7 owns Go realization; Gate 8 owns Docker/MinIO/local topology. Neither gate may change the meanings defined here without a later ADR.

**Accepted ADR 0011.** The local-topology alignment section at the end of this document maps every Gate 6/7 invariant onto the accepted topology. Those mappings preserve the Gate 6/7 invariants.

## Forward-only migration lifecycle

### Migration format and authority

Migrations use the version-controlled, checksummed `golang-migrate` format. Every migration file carries an ordered version number, a descriptive label, and an immutable checksum. The migration history is recorded durably in a schema-migrations table that preserves the version, checksum, and application timestamp for every applied migration. Migration history is append-only: once a migration version is recorded as applied its checksum must never change, and no applied migration version may be removed from the history.

### Preflight checks

Before any migration is applied the migration runner must execute compatibility and capacity preflight checks:

| Check | Scope | Failure behavior |
| --- | --- | --- |
| Schema state | Verify that all previously recorded migration checksums match the history table. Any mismatch indicates a corrupted or tampered migration history and must abort with a structured preflight failure. | Abort before any DDL. |
| Connection health | Verify that the target database is reachable, authenticated, and responsive. | Abort with a structured connectivity failure. |
| Lock availability | On one non-rebinding session, acquire common target-exclusive ownership (default 30 seconds, hard five minutes), then the migration-specific lock (default 15 seconds, hard 60 seconds), within a combined default 45-second/hard six-minute deadline. | Abort before mutation with class `4` and safe phase-specific reason; never expose lock keys or connection facts. |
| Disk and backup capacity | Verify that adequate disk space and backup capacity exist for the migration and any required data transformation. The operator configures minimum thresholds; the check compares current usage against those thresholds. | Abort with a structured capacity failure. |

Preflight checks must complete with no failures before any DDL statement is issued. A preflight failure leaves the database unchanged.

Initial provisioning attempts exclusive protected operator-state ownership after common target exclusion and before the migration-specific lock. The compare/claim is nonblocking: a competing owner returns class `4` `operator_state_busy`, closes the PostgreSQL session, and adds no hidden wait beyond the published PostgreSQL acquisition budget.

`migrate verify`, `migrate status`, and serving compatibility preflight use a `central_runtime` read-only inspector over allowlisted catalogs and already-existing migration/checksum/progress history. They never construct the golang-migrate driver or create/ensure any relation; absence returns typed `uninitialized`, while dirty, partial, unreadable, unsupported, or checksum-mismatched state returns typed incompatible or exact-recognized-resumable evidence. Migration status also cross-checks a read-only protected-operator-state inspector for provisioning target/operation/phase/epoch/candidate binding; neither inspector mutates.

Before a new mutation, `migrate up` must consume exactly one typed safety precondition under uninterrupted single-session exclusive ownership: immutable verified-backup/checkpoint evidence, or a sealed non-serializable one-use `VerifiedEmptyTarget` proof for version-zero installation. The empty-target proof binds the exact database identity, empty-state fingerprint, session, embedded baseline checksum-manifest digest, and provisioning operation; it is available only when no `central` schema, Central relation, migration history, or restore/security marker exists. `migrate resume --operation=<id>` instead requires exact durable `ResumableMigration` evidence bound to the original consumed safety input, target, operation, migration version/source/checksum/classification, dirty state, and durable progress; it cannot begin or adopt another operation.

Version-zero uses no golang-migrate database driver. Before PostgreSQL mutation, initial provisioning durably writes an integrity-protected external `initializing` record outside the target and Artifact store under common target-exclusive plus protected operator-state ownership. Its initial `recorded` phase binds target, safe operation ID and hidden nonce, epoch zero, protocol, and embedded baseline digest but no candidate. It then stages one create-only bootstrap candidate in protected storage and atomically replaces the record with `candidate_staged` carrying the exact candidate ID/digest; a crash before that replacement leaves only an unreferenced candidate subject to bounded cleanup. Later phases are `baseline_installed` and `candidate_active`; replacements are atomic, flushed, and directory-synchronized. Only after `candidate_staged` may a Central-owned installer consume `VerifiedEmptyTarget` and create the version relation, append-only checksum history, complete initial schema, epoch-zero restore/security markers, exact initial bootstrap registration, and baseline version/checksums in one transaction on the lock-owning session. After exact read-only baseline verification, the exact protected candidate activates and the external record becomes `ready` only when every binding and epoch matches.

Provisioning recovery is exact-operation and idempotent: `initializing` plus empty resumes the same candidate and obtains a fresh session-bound empty proof; `initializing` plus the exact baseline finishes candidate activation and readiness. Exact baseline without the prior bound external record, `ready` plus empty, partial/mismatched baseline, changed target/digest/candidate, corrupt/unknown phase, or unknown protocol fails as `provisioning_repair_required` and is never auto-adopted or edited. Phase 1 recovers from that class only by provisioning a newly proved empty target and, when valid backup evidence exists, applying the verified-restore protocol to that newly initialized target; direct external-state or SQL repair is prohibited. A create-only candidate with no external or database reference is removable after five minutes by default and no later than one hour, only under exclusive provisioning ownership and after a repeated external/database no-reference check. Rollback before the baseline commit remains empty; an indeterminate commit is read-only classified as empty or exact bound baseline. `migrate status` reports safe operation/phase and resume requirement; only `migrate resume --operation=<id>` continues it. Once any Central schema/history exists, every new later migration requires verified backup/checkpoint evidence.

Only after exact baseline verification may golang-migrate orchestrate later migrations through a Central-owned `database.Driver` whose `Run`, `SetVersion`, and `Version` use the same non-rebinding session. Session loss both prevents further SQL and releases both locks; there is no reconnect or second mutation connection.

### Bounded lock, statement, and transaction limits

Every migration enforces bounded resource limits:

- DDL statements that may acquire long-lived locks (e.g., `ALTER TABLE ... ADD COLUMN` with a default value on a large table) must use `CONCURRENTLY` where PostgreSQL 16 supports it, or must be decomposed into lock-free steps where possible.
- No migration may hold a lock, statement, or transaction open for longer than a configured statement timeout (default 30 seconds for DDL, 5 seconds for data-change statements).
- No migration may hold an external operation — object-store call, tool invocation, network request, or filesystem access — inside an open transaction.
- Every migration uses a single bounded transaction or a documented sequence of bounded transactions. Data-backfill migrations may use multiple bounded transactions with durable cursor/progress (see Data-backfill classification).

### Verification

After a migration is applied the migration runner must verify the resulting schema state:

- Confirm that the migration version and checksum are recorded in the schema-migrations history table.
- Verify that expected schema objects (tables, columns, indexes, constraints) exist with the expected definitions.
- Verify that data invariants (non-negative counters, unique constraints, foreign-key integrity) remain satisfied.

A verification failure must abort the migration run, record the failure in the migration history with structured evidence, and leave the database in a state that can be diagnosed and rolled forward.

### Durable history

The schema-migrations table records every migration application and every forward corrective migration. The history includes:

- migration version and checksum;
- application timestamp derived from database time;
- success or failure outcome with structured failure evidence when a migration fails;
- identity of the migration operator or service that applied the migration.

Migration history is immutable: no migration, cleanup, or runtime operation may update or delete a history row. History rows are retained for the supported Phase 1 local MVP lifetime.

### Forward corrective migration and restore — no destructive down migration

Automatic destructive down migrations are prohibited. No migration tool, operator, or service may execute a migration that rewrites or erases Event rows, Artifact lineage, tombstone rows, or audit history. Rollback to a prior schema version must use one of two approved paths:

1. **Forward corrective migration.** A new, higher-versioned migration that corrects the schema without destroying data. The corrective migration follows the same preflight, bounded-lock, verification, and durable-history rules as any other forward migration.
2. **Documented restore runbook.** Restore from a protected backup manifest using the documented restore procedure (see Backup and restore).

No migration may be reversed by deleting or modifying an applied migration history row. The schema-migrations table records every forward corrective migration as a new version with its own checksum and timestamp.

## Metadata versus data-backfill classification

Every migration is classified as either a metadata migration or a data-backfill migration at authoring time. This classification determines the transaction, locking, and resumability rules.

### Metadata migrations

A metadata migration changes schema structure only — tables, columns, indexes, constraints, types, or functions — without modifying existing row data. Metadata migrations:

- use a single bounded transaction where possible;
- must use `CONCURRENTLY` for DDL that would otherwise acquire an `ACCESS EXCLUSIVE` lock on a busy table;
- must not hold a lock across multiple DDL statements where a decomposition into separate bounded transactions is safe;
- are verified after application (see Verification).

### Data-backfill migrations

A data-backfill migration changes existing row data — populating a new column from existing data, splitting or merging tables, normalizing values, or correcting data without schema changes. Data-backfill migrations:

- use short, resumable, idempotent batches with durable cursor/progress;
- process rows in bounded, configurable page sizes (default 1000, hard maximum 10000);
- commit each batch in a separate bounded transaction;
- record durable cursor/progress after each committed batch to enable safe resume after interruption;
- never hold an external operation or unbounded transaction open across batch boundaries.

#### Batch structure

A data-backfill batch:

1. Opens a new bounded transaction.
2. Selects the next batch of rows using the durable cursor (seek pagination by a stable ordering key).
3. Applies the idempotent transformation to each row.
4. Records the new cursor position as durable progress.
5. Commits the transaction.
6. If the batch fails, retries with the same cursor position (idempotent transformation ensures no double effect).

#### Retry and abort behavior

| Condition | Behavior |
| --- | --- |
| Batch failure (constraint, timeout, deadlock) | Retry the same bounded batch with the same cursor. After a configurable maximum retry count (default 3) the migration aborts with structured failure evidence. |
| Batch failure (non-retryable — disk full, data corruption) | Abort immediately. Record structured failure evidence. Leave cursor/progress in its last durable state so the operator can resume from that point after resolving the cause. |
| Interruption (process crash, network loss) | On restart the migration runner reads the durable cursor/progress and resumes from the last committed batch boundary. Already-processed rows are not re-processed due to idempotent transformations. |

Every data-backfill descriptor binds its migration version, immutable source/checksum, classification, and versioned progress schema. Before golang-migrate starts that version, the Central runner loads the exact descriptor and configures the bound driver with an opaque operation ID and original safety evidence. The expected dirty `SetVersion` atomically records that operation, descriptor binding, start cursor, and dirty state, so interruption immediately after dirty marking is resumable. `Run` rejects an unexpected version/source before delegating to the coordinator. Each batch commits transformation plus cursor/count/checksum-accumulator progress atomically. Final schema/data verification must pass before the version can become clean.

Golang-migrate's ordinary `Up()` stops at a dirty version before calling `Run`; this is an expected safety behavior, not a resume mechanism. A restart therefore uses only `migrate resume --operation=<id>`. Under freshly reacquired common target-exclusive and migration-specific ownership, the Central runner accepts a resume only when read-only evidence exactly matches the Central-authored dirty version, operation, source/checksum/classification, original safety binding, progress schema, and last committed cursor. It invokes that exact embedded data-backfill coordinator directly rather than `Up()`, continues bounded idempotent batches, verifies completion, and only then performs the authorized dirty-to-clean version transition and appends immutable success evidence.

Generic `Force`, arbitrary dirty-bit clearing, changed-source adoption, and resume of a metadata migration are prohibited. Missing/changed progress, an unknown dirty version, checksum/classification mismatch, wrong target/operation, an already-clean version, or a completed/superseded operation remains failed closed and requires forward correction or restore. A repeated interruption preserves the same operation and returns resumable failure; tests inject loss after every committed batch and before/after final verification and clean marking.

#### Idempotent transformation

Every data-backfill transformation must be idempotent: applying it once or many times to the same row produces the same result. Idempotency is achieved through:

- `WHERE` clauses that exclude already-transformed rows (e.g., `WHERE new_column IS NULL`);
- `UPDATE ... SET` statements whose result is stable regardless of repeat application;
- comparison of current value to target value before transformation.

The migration author must document how each data-backfill transformation achieves idempotency.

#### Expand/contract compatibility window

Data-backfill migrations operate within an **expand/contract compatibility window**. The schema must accept both the pre-migration and post-migration data shapes during the migration window:

1. **Expand:** The schema is expanded to accept new columns, types, or constraints without breaking existing reads or writes. New columns have safe defaults or are nullable. New constraints are validated but not yet enforced (using `NOT VALID` where supported).
2. **Contract:** After the data backfill is complete and verified, the schema is contracted — old columns are dropped, new constraints are validated and enforced, and deprecated shapes are removed.

No data-backfill migration may break existing reads or writes during the expand/contract window. The runtime must continue to function correctly with data in either pre-migration or post-migration shape throughout the window. The contract phase may only begin after all data batches are committed, verified, and the cursor/progress indicates completion.

## Backup and restore

### Protected manifest

Backup uses a protected PostgreSQL-plus-object-store manifest. Every backup manifest carries:

- backup timestamp derived from database time;
- opaque backup identifier (UUID or equivalent, never derived from secrets or sensitive data);
- durable backup operation identity, opaque target identity, and lock-protocol version;
- database dump reference with checksum (SHA-256 of the dump file);
- accepted offline consistent-point/snapshot evidence and object-inventory boundary;
- an ordered root over immutable canonical-key inventory chunks, with each chunk identity/checksum and at most 1,000 bounded Artifact records;
- manifest checksum (SHA-256 of the manifest content);
- tool/schema/checksum-manifest versions and verified sealing outcome;
- backup operator or service identity.

The manifest must never include:

- credentials, passwords, tokens, or API keys;
- plaintext secret, session, or CSRF values;
- raw object keys, backend locators, or storage paths;
- raw filenames, Artifact body content, or payload data.

Manifest generation and storage use restricted access: the operator CLI never
opens the repository directly. Only a fresh-PAM helper-launched backup or
recovery worker receives the exact bound repository descriptor for its
invocation; the long-lived serving process receives no repository pathname or
descriptor. The manifest storage location is separate from the object-store
bucket used for Artifact bodies.

The helper launches the fixed backup worker through a native supervisor. The
worker receives invocation evidence at fd 3 and the exact helper-selected
repository descriptor at fd 4; caller input supplies neither descriptor nor a
path. The helper retains an independent repository descriptor. Before the
worker spawns `pg_dump`, it makes its repository descriptor close-on-exec;
`pg_dump` receives only its separate sealed `PGPASSFILE` credential at the
child's fd 3.

The broker protects each launch through the only legal lifecycle
`issued → active → reaped → completed`, bound to the exact runtime UID/GID,
PID, process-start identity, executable, fixed mode, deadline, operation,
backup, and repository binding. The seal request carries the exact canonical
root-manifest bytes. The broker reparses them and recomputes the digest rather
than authenticating a worker-supplied digest alone. The worker may obtain and
write the committed companion and atomically publish its repository-index
proposal, but it cannot perform the dedicated seal-completion transition.

After the worker exits, the native supervisor reaps its complete process tree.
Only then does the root helper mark the launch `reaped` and independently
re-read the repository through its retained descriptor. It recomputes the
canonical root manifest, database dump, ordered inventory, complete file tree,
seal companion, and repository index, and emits a canonical
`central.backup-repository-attestation/v1` binding the launch, operation,
backup, repository, root/companion/file-tree/index digests, index revision, and
post-reap time. Only a root-authorized broker RPC may match that exact
attestation to the committed seal and move the operation from `sealing` to
`sealed` and the launch from `reaped` to `completed`; generic backup CAS and
worker-facing completion are denied. C03 matches all root, companion,
file-tree, root-index digest, and index-revision evidence to this completed
protected attestation.

### Consistent point

Every Phase 1 backup captures one **offline consistent point**. Each serve profile holds the target-scoped shared advisory lock for its lifetime. After the operator stops all profiles, backup create acquires the matching exclusive lock; ownership proves every old writer has drained and prevents a new profile from becoming ready. The same dedicated connection remains held through database snapshot/dump, canonical chunked object inventory, checksum verification, and protected root-manifest seal. The point-in-time-window alternative is not accepted for Phase 1.

The exclusive phase defaults to two hours and has an eight-hour hard maximum. Connection/process loss, cancellation after accepted point, or expiry makes that operation terminal and non-resumable; partial chunks are unreferenced/non-restorable and a new operation must establish a new point. Internal bounded work slices retain the same connection. A backup without exclusive-interval evidence and verified seal is invalid for restore.

### Diagnostics redaction

Backup diagnostics and restore diagnostics must never include:

- credentials, passwords, API keys, or tokens;
- plaintext secret, session, or CSRF values;
- raw object keys, backend locators, storage paths, or filenames;
- Artifact body content or payload data.

Diagnostics may include opaque identifiers, checksums, timestamps, counts, safe status values, and bounded failure reasons. Redaction occurs before diagnostics are written to any log, manifest, recovery evidence, or operator-facing output.

### Restore procedure

Protected operator state exists outside both PostgreSQL and its Artifact object store, with matching restore/security epoch markers inside PostgreSQL once initialized. Before initialization its only legal path is `absent -> initializing -> ready` through the provisioning protocol above. After initialization the external state binds target, operation/ticket nonce, protocol, epochs, timestamps, and `ready`, `applying`, `verifying`, or `quarantined`; the restore path is `ready -> applying -> verifying -> ready`, with bounded `verifying -> quarantined -> verifying`. `initializing` is not a restore state. Missing, corrupt, non-ready, or mismatched state blocks every serve preflight, and an exact PostgreSQL baseline without its bound external provisioning record is not auto-adopted.

`restore verify` is non-mutating with respect to the target database, object bodies, and restore barrier, though it writes bounded protected operator evidence. It issues an expiring single-use ticket bound to the same durable operation ID, backup/manifest checksum, target identity/fingerprint, current epochs, safe configuration/tool versions, capacity/authority result, and hidden nonce. `restore apply` continues that known verified operation ID, reacquires common target-exclusive and operator-state ownership, recomputes all inputs, consumes the ticket, and durably enters `applying` before mutation.

Restore follows a strictly ordered, verifiable sequence:

| Step | Action | Verification |
| --- | --- | --- |
| 1 — Ownership and ticket consumption | Stop serving, acquire common target-exclusive plus operator-state ownership, revalidate target/ticket/confirmation, and atomically consume the ticket while persisting `applying` with the next restore epoch before mutation. | Exact operation/nonce, unexpired ticket, fingerprint, config/tools, capacity/authority, and typed confirmation all match. |
| 2 — Database replacement | Restore the dump under `central_migration`, verify it, then discard that credential. | Schema, migration/checksum history, aggregate rows, and dump checksum match; barrier remains non-ready. |
| 3 — Chunked object verification | Advance to `verifying`; merge-compare canonical database/object seek streams using immutable 1,000-record chunks and durable cursors. | Complete verified root within worker/page/spool caps; resume revalidates the last checkpoint. |
| 4 — Reconciliation and quarantine | Verify ready bodies, tombstones, reservations, and lineage; persist every inconsistency as quarantined through typed runtime paths. | Complete bounded report; no inconsistent Artifact can be served or claimed. |
| 5 — Operator resolution | Resolve every quarantine through standard re-ingest or delete-intent/finalization paths, returning to verification after each mutation. | Complete root comparison passes with no unresolved quarantine. |
| 6 — Authority reset | While `verifying`, prepare one protected bootstrap draft; atomically install restore/security markers, revoke restored sessions/bootstrap, expire claims/leases/fences, suspend grants, disable SecretReferences, retain historical evidence, and register its exact fresh generation; activate that registration and finalize the aggregate receipt. | Exact idempotent draft/registration/activation/reset receipts; fresh bootstrap active; no restored authority effective; fresh login and reevaluation required. |
| 7 — Ready transition | Install final in-database epoch evidence and durably transition external state to `ready`. | External target/restore/security epochs exactly match PostgreSQL and all inventory/quarantine/reset evidence is complete. Only then may serve acquire shared ownership. |

Crash in `applying`, `verifying`, or `quarantined` leaves that durable state and blocks ordinary startup. Resume reacquires exclusive ownership, presents the exact operation ID/nonce, and revalidates its last immutable checkpoint and idempotent next step. There is no force-ready or ordinary-start bypass.

#### Quarantine of inconsistent Artifacts

If the restore procedure detects an inconsistency — a ready Artifact whose object is missing or has a mismatched checksum, or an object that exists but has no corresponding database Artifact record — the inconsistent Artifact must be quarantined:

- The Artifact is marked with a quarantine flag and quarantine timestamp in the database.
- A structured quarantine event is recorded with opaque Artifact identity, detected inconsistency type, and timestamp only (no raw key, path, or body).
- The quarantined Artifact is not served, streamed, delivered, or referenced by any runtime operation.
- The operator is presented with a quarantine report listing each inconsistent Artifact by opaque identity and inconsistency type.

#### Operator resolution

The operator must resolve each quarantined Artifact before the system is `ready`. Resolution options:

| Option | Description |
| --- | --- |
| Re-ingest | If the object body is recoverable from another source, re-ingest the Artifact through the standard Artifact finalization path. |
| Delete | If the Artifact is not needed, delete it through the standard Artifact delete-intent path, which creates a tombstone and releases capacity. |

The system must not serve or claim work while any quarantined Artifact exists without operator resolution. Direct flag clearing or force-ready is prohibited; resolution must pass the accepted Artifact lifecycle so quota, checksum, lineage, Event, and tombstone evidence remain consistent.

After the standard re-ingest or delete-intent/finalization mutation, resume runs a new complete inventory through the same typed recovery adapter. Only an open finding absent from that complete pass is durably resolved (`reingested` for database-backed discrepancies or `delete_finalized` for an unexpected object); a partial pass, a repeated finding, or a direct database flag update cannot resolve it. The operation remains `quarantined` until that durable projection reports zero open findings.

### Backup access control

Backup manifest creation, storage, and retrieval are restricted to the local operator or authorized backup service identity. The runtime role must not have permission to create, read, or delete backup manifests. Backup storage is separate from the Artifact object-store bucket. Diagnostics access follows the same access control: only the operator or authorized service identity may view unredacted diagnostics; runtime-facing diagnostics are fully redacted.

## Retention

### Permanent records

The following records are retained for the supported Phase 1 local MVP lifetime and are never removed by any cleanup operation:

- **Events.** Immutable Event rows with opaque identity, `workspace_id`, `event_sequence`, Event type, safe serialized payload, producer identity, and creation timestamp.
- **Artifact tombstones.** Immutable non-body records with safe lineage, delete-intent evidence, and deletion-outcome evidence. Tombstones prevent object-key and content-generation reuse.
- **Existing Approval records.** Capability grant, capability revocation, and secret-use/audit evidence records as defined in ADR 0003. These carry opaque approval identity, `workspace_id`, granted/revoked capability identity and scope, actor, authority, safe reason evidence, and creation/expiry timestamps.

No cleanup, migration, or runtime operation may delete, truncate, or archive Event rows, tombstone rows, or Approval/capability/secret-use audit evidence rows during the supported Phase 1 local MVP lifetime.

### Temporary data retention windows

Temporary data uses database-derived expiry time and bounded cleanup with documented default windows. These windows are the Phase 1 defaults and minimum recovery-evidence windows. Installed policy may lengthen them but may only shorten them through a later material policy decision. Cleanup cannot erase evidence required by that policy.

| Record type | Default cleanup window | Eligibility condition | Minimum recovery-evidence window |
| --- | --- | --- | --- |
| Delivered outbox records | 7 days after delivery | `delivery_state = 'delivered'` and `delivered_at < database_time - 7 days` | 7 days |
| Dead-letter records | 30 days after dead-letter entry | `delivery_state = 'dead_letter'` and `dead_letter_at < database_time - 30 days` | 30 days |
| Expired sessions | 24 hours after expiry or revocation | `revoked = true` or `expires_at < database_time`, and the later of `expires_at` or `revoked_at` is before `database_time - 24 hours` | 24 hours |
| Expired staging reservations | 7 days after release or rejection | `reservation_state IN ('released')` and `released_at < database_time - 7 days` | 7 days |
| Cleanup evidence | 7 days after cleanup recording | `cleanup_evidence_at < database_time - 7 days` | 7 days |
| Expired command receipts | 7 days after expiry | `expires_at < database_time - 7 days` | 7 days |

All eligibility conditions compare database time against the record's timestamp. The cleanup window is measured from the event that marks the record as eligible (delivery, dead-letter entry, expiry/revocation, release, cleanup recording, or receipt expiry), not from record creation.

### Retention policy governance

These window durations are defaults. Installed policy may lengthen any window — for example, retaining delivered outbox records for 30 days instead of 7 — through a documented policy decision. Lengthening a window requires no code change (the cleanup worker reads the installed policy).

Shortening a window requires a later material policy decision — a documented, reviewed, and accepted policy change that considers the recovery, audit, and compliance implications. A window may not be shortened through a runtime configuration change alone. Cleanup must never erase evidence required by the currently installed policy, regardless of the default values listed above.

## Cleanup contract

### Cleanup claim and order

Cleanup operates in bounded batches ordered by database time. Each cleanup pass:

1. Opens a new bounded transaction.
2. Claims eligible records using `SELECT ... FOR UPDATE SKIP LOCKED` with a configured batch size (default 100, hard maximum 1000).
3. Orders records by the eligibility timestamp (e.g., `delivered_at`, `dead_letter_at`, `expires_at`, `released_at`) to prioritize oldest-eligible records first.
4. Verifies eligibility again within the transaction to prevent race-condition deletion of records that became ineligible between selection and deletion.
5. Records safe cleanup outcome evidence (opaque record identity, record type, cleanup timestamp) before deletion.
6. Deletes the eligible records.
7. Commits the transaction.
8. If the batch had exactly the configured batch size, immediately starts the next batch (backlog pressure). If fewer, waits for the configured cleanup interval before the next pass.

### Concurrency and idempotency

Cleanup is designed for concurrent execution:

- `FOR UPDATE SKIP LOCKED` ensures that multiple cleanup workers never contend for the same rows. Each worker claims a distinct batch.
- A record that is locked by a concurrent operation (e.g., a session heartbeat extending `last_seen_at` between the initial select and the verification select) is skipped; the cleanup worker's re-verification step detects the change and excludes the record.
- A record deleted by a prior cleanup pass is not visible to subsequent passes; the cleanup is naturally idempotent.
- A record that transitions to an ineligible state between passes is excluded by the verification step.

Cleanup does not retry indefinitely. A transient failure (deadlock, serialization failure, timeout) retries the same batch once. After a second failure the batch is skipped and the failure is recorded in cleanup diagnostics. The next cleanup pass picks up the skipped records. A persistent failure (constraint violation, corruption) aborts the cleanup pass and records structured failure evidence for operator action.

### Safe cleanup evidence before capacity release

Before a cleanup pass deletes records that represent consumed capacity (expired staging reservations, delivered outbox records), it must record safe cleanup outcome evidence:

- opaque record identity;
- record type;
- cleanup timestamp derived from database time;
- reason for cleanup (eligibility condition met);
- capacity released (byte count for reservations, count for other records).

This evidence is recorded durably in a cleanup-evidence record that is itself subject to the cleanup evidence retention window (default 7 days). Capacity is not considered released until the evidence is durably recorded and the deletion is committed.

### Object-store and database reconciliation

Cleanup includes periodic reconciliation between the database Artifact metadata and the object store:

1. **Orphan object detection.** Query the object store for objects whose keys do not correspond to any ready Artifact or staging reservation in the database. Orphan objects are reported in cleanup diagnostics with opaque identity only (no raw key or path). The operator may delete orphans through a documented procedure.
2. **Missing object detection.** Query the database for ready Artifacts whose referenced objects are missing from the object store. Missing-object Artifacts are flagged for quarantine (see Restore procedure — Quarantine).
3. **Capacity reconciliation.** Compare the capacity ledger counters against the actual ready Artifact count and total bytes. Any discrepancy is reported in cleanup diagnostics.

Reconciliation runs on a configurable interval (default every 6 hours) and uses bounded batch sizes. Reconciliation never modifies Artifact state or capacity counters; it only reports inconsistencies for operator action.

### Backlog observability and operator action

Cleanup exposes backlog observability through structured diagnostics:

- count of eligible records by type awaiting cleanup;
- age of the oldest eligible record by type;
- last cleanup pass timestamp and duration;
- count of records cleaned in the last pass by type;
- count of skipped or failed records by type and failure reason.

If the eligible backlog exceeds a configurable threshold (default 10,000 records) or the oldest eligible record age exceeds a configurable threshold (default 2x the cleanup window for that record type), cleanup raises a structured diagnostic alert. The operator may:

- increase the cleanup batch size or decrease the cleanup interval;
- run an immediate cleanup pass;
- investigate and resolve persistent failures preventing cleanup.

### Cleanup preservation rules

Cleanup must never remove:

- **Events.** Any Event row, regardless of age or state.
- **Tombstones.** Any Artifact tombstone row, regardless of age or state.
- **Ready Artifacts.** Any Artifact in `ready` state, or its associated object, regardless of age.
- **Required recovery evidence.** Any Approval record, capability grant/revocation record, secret-use audit evidence, migration history row, or cleanup evidence that is within its retention window according to the installed policy.

These preservation rules are enforced by the cleanup worker's query predicates (exclusion of protected record types and states) and by database role permissions (the cleanup role must not have permission to delete from Event, tombstone, or Approval tables). A cleanup operation that attempts to delete a protected record must fail with a structured constraint or permission failure.

### Cleanup role and permissions

Cleanup uses the `central_runtime` database role. This role cannot update or delete Events or tombstones, cannot cascade-delete Events, and cannot truncate protected tables. The migration history, backup manifests, and retention policy are not accessible to the cleanup role for modification. Cleanup evidence is written to a cleanup-evidence table that the runtime role can insert into and the operator can read.

## ADR 0011 local-topology alignment

**Accepted ADR 0011.** This section maps existing Gate 6/7 migration and recovery invariants onto the accepted local topology. It preserves every Gate 6/7 transaction and recovery invariant; the topology is a realization of those rules, not a replacement.

### Provisioning and version-zero ownership

Version-zero provisioning remains the exclusive authority of `central_migration` under common target-exclusive, protected operator-state, and migration-specific advisory locks. The external `initializing`/`candidate_staged`/`ready` protocol from the canonical contract (§Forward-only migration lifecycle) is realized through the ADR 0011 root-owned protected store beneath `/var/lib/central-protected/v1/<instance-id>/operator-state/`. The protected operator-state file is integrity-protected with atomic replacement, data flush, and parent-directory `fsync`. The operator UID, `central-runtime` UID, and `central-migrate` UID cannot directly open or enumerate the protected store. ADR 0011's sole direct-repair exception is `migrate reset --operation=<id>` for an exact failed version-zero operation: it requires fresh PAM plus one-use confirmation, reacquires the full lock order, journals each idempotent reset phase, refuses every ready/data-bearing target, and permits only exact-operation recovery after interruption.

The Gate 8 infrastructure helper mediates every initial directory/structure creation and bootstrap-candidate placement but never fabricates migration authority, a `VerifiedEmptyTarget`, or a resume-binding.

### Three-role topology

The three database roles — `central_runtime`, `central_outbox`, `central_migration` — retain their exact Gate 6/7 privilege matrix. ADR 0011 keeps tmpfs delivery for runtime/outbox and delivers `central_migration` only to the verified `central-migrate` peer through the broker's SCM_RIGHTS handoff for an invocation lifetime. No password appears in Compose YAML, environment variables, command arguments, or Docker labels. The `central serve` process receives only `central_runtime` credentials; migration and restore-apply processes run as `central-migrate` and close the descriptor at completion, failure, or cancellation.

### Pool and permit topology

The installation-wide connection budget (16 default / 24 hard) and pool partitioning from the PostgreSQL adapter mapping contract remain unchanged. ADR 0011 adds: every serving, operator read, operator mutation, runtime-general, runtime-settlement, outbox, and cleanup pool authenticates as its assigned role using its assigned credential delivery mechanism. The `central serve` process never loads `central_migration` or `central_outbox` credentials. The shared-lock control connection for each serve profile is a dedicated `central_runtime` connection that holds the target-scoped session-level advisory lock for the profile lifetime.

### PGOPTIONS and tool parenting

Host-side migration, backup, and restore operations use the pinned PostgreSQL
client tools (`pg_dump` 16.14, `pg_restore` 16.14) only through their installed
fixed Central operator/worker modes. In backup creation, the root helper starts
the fixed `central-backup` worker through the native supervisor; that worker is
the direct tool parent and the supervisor remains responsible for full-tree
termination and reaping. The owning process sets the required `PGOPTIONS`,
connects through its invocation-lifetime sealed `central_migration` or
`central_runtime` descriptor, and never exposes a connection string or
password on the command line. A PostgreSQL tool receives only its child-local
credential fd 3 and never receives worker launch evidence, repository, Docker
socket, or `docker exec` authority.

### Target and host locks

The common target-exclusive advisory lock, protected operator-state lock, and migration-specific lock retain their exact Gate 6/7 semantics and sequencing. ADR 0009 adds: the lock-owning PostgreSQL session is always obtained from the host through the `central` binary, never from inside a container. The Compose `postgres` service binds only to `127.0.0.1:55432`; no external or container-network lock claimant is possible. Lock acquisition uses the host-side `central_runtime` (read-only) or `central_migration` (mutation) credential delivered via tmpfs.

### Backup repository

The Gate 7 backup manifest, inventory chunks, and sealed root manifest are
stored in the local repository at
`/var/lib/central-state/v1/instances/<instance-id>/backups/`. Its
non-operator-searchable parent is root-owned; the bound repository and every
descendant belong to the locked `central-runtime` identity with directories
`0700` and create-only files `0600`. Ownership grants no ambient repository
capability: the long-lived serving process receives no pathname or descriptor,
and the operator cannot traverse or read the repository directly. A fresh-PAM
helper selects and passes fd 4 only to the exact invocation-bound recovery
worker while retaining an independent descriptor for post-reap attestation.
Operator-facing `central backup list`, `backup export`, `backup import`,
`backup delete`, and `backup prune` verbs mediate repository access through the
helper when their owning slice is accepted. Backup export produces a
broker-signed Ed25519 `bx1` integrity token displayed only on the physical-seat
TTY; the token never crosses controller JSON, logs, audit records, HTTP, or any
operator-writable file.

### Export, import, and rescue

- `backup export --operation=<id>` requires fresh PAM and physical-seat TTY. It reads the sealed manifest, verifies all chunks against the root manifest checksum, and emits the `bx1` token on the TTY only.
- `backup import --manifest=<path>` requires fresh PAM and places the manifest in the local repository; it does not verify chunk integrity against the target database — that is the `restore verify` and `restore apply` path.
- `backup create --security-rescue` creates exactly one marked current-epoch seal from cold copies using conservative admission. It never mounts authoritative payload roots writable. The resulting rescue backup is unrestorable until current advisory authority returns.
- `backup security-rescue cleanup --operation=<id>` provides settlement-only cleanup for authenticated rescue operations with bound scratch roots.

### Restore authority reset

The restore authority reset from the canonical contract (§Restore procedure step 6) retains its full semantic: session revocation, bootstrap generation cancellation, claim/lease/fence expiry, grant suspension, SecretReference disablement, fresh bootstrap candidate registration, and security-epoch increment. ADR 0009 adds: the reset transaction runs on the host through the `central` binary under `central_migration` (for the database replacement substep) or `central_runtime` (for post-replacement verification and reset), never inside a container. The fresh bootstrap candidate is created in the root-owned protected store through the broker. Migration v26 records its exact operation/draft/candidate/generation/digest and broker/database receipt hashes create-only in the same authority-reset transaction; the migration-only broker channel then activates that registration, and PostgreSQL finalizes the aggregate receipt without the plaintext verifier crossing any observable boundary. Retry at any boundary must reproduce the same records or fail closed.

### No-auto-migrate rule

`central serve` and `central local up` never auto-migrate. Only `central migrate up` and `central migrate resume` load `central_migration` credentials. The `central local up` command runs: start dependencies → `migrate status` (read-only, `central_runtime`) → if uninitialized, exit with a safe `migration_required` diagnostic directing the operator to `central local init` and `central migrate up` → if compatible, start serve. `central migrate up` is an explicit operator command requiring exclusive target ownership and migration-safety evidence, never an automatic startup side effect.
