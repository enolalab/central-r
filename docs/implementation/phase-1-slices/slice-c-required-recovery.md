# Slice C — Required Recovery

- **Slice ID:** C
- **Dossier:** `slice-c-required-recovery.md`
- **Packets:** C01–C06
- **Dependency:** B12 (Slice B first value)
- **Outcome:** Operator-driven verified local backup and restore with interruption-safe external restore barrier, quarantine, and post-restore authority reset
- **Technical design:** Slice C Required Recovery Design (upstream `central` record: `docs/internal/superpowers/specs/2026-08-09-slice-c-required-recovery-design.md`)
- **Implementation plan:** Slice C Required Recovery Implementation Plan (upstream `central` record: `docs/internal/superpowers/plans/2026-08-09-slice-c-required-recovery.md`)

## Slice C ownership

C01–C06 collectively own:

- `backup create/verify/status/resume` through capability-owned backup ports using broker-held least-privilege backup identities;
- PostgreSQL plus MinIO Artifact-body consistency, signed manifests, immutable operation/checkpoint evidence, and no plaintext credentials;
- capacity/throughput admission and minimum-profile failure evidence;
- `restore verify/apply/status/resume`, one-use restore ticket, fresh PAM, external restore barrier, quarantine, and no partially served restore;
- security-epoch increment, fresh bootstrap, broker TLS re-key, authority re-evaluation, and affected-task reconciliation;
- deterministic interruption/resume at every external boundary without deleting ambiguous evidence.

Slice C does not own export/import, delete/prune, retention policy mutation, wipe/reseed, dependency upgrade, or B12's informal Preview bridge. Export/import, delete/prune, retention policy mutation, and wipe/reseed belong to Slice D; dependency upgrade belongs to Slice E; the B12 informal Preview bridge belongs to Slice B and is not extended or re-implemented here.

## C01

### Identity and outcome

Implement sealed backup creation: take an exclusive-target PostgreSQL backup via pg_dump 16.14, timestamp and sign the backup manifest, store backup artifacts and immutable repository evidence. C01 produces verified backups that C03 verifies and C04 restores.

### Implementation boundary

Backup creation uses `pg_dump` 16.14 with `--clean --if-exists --format=custom --no-owner --no-privileges` flags. A backup manifest records timestamp (ISO 8601), PostgreSQL version, database size, dump file SHA-256, and the creating instance identity. The manifest is signed with the instance Ed25519 key. Backup artifacts (dump file, manifest, signature) are stored in the accepted backup directory as an immutable snapshot. Concurrent backup creation is prohibited: an exclusive lock on the backup directory is acquired before dump begins.

### Durable data and migration

Backup artifacts are stored on the host filesystem. Manifest metadata is recorded as immutable operation/checkpoint evidence for traceability. No new migration beyond B05.

### Security and authority

Backup creation uses broker-held least-privilege backup identities (B04); no plaintext credentials are stored or logged. The backup directory has mode `0700`. Manifest signature proves origin. Backup artifacts are never transmitted outside the local host.

### Failure, retry, cancellation, and recovery

pg_dump failure stops backup creation and preserves partial artifacts as evidence; ambiguous evidence is never deleted. A failed backup produces a `BACKUP_CREATION_FAILED` event with pg_dump stderr. Interrupted backup is detected by the absence of a valid manifest.

### Verification and evidence

- pg_dump produces a restorable custom-format backup file
- Manifest is signed with valid instance Ed25519 key
- Concurrent backup attempt is rejected
- Failed backup preserves partial artifacts as evidence; no ambiguous evidence is deleted
- Backup directory has mode `0700`
- Future test suite: `go test ./internal/backup/...`
- Evidence artifact: `slice-c-backup-creation.json`

### Scope control

C01 owns backup creation. It must not perform restore, verify restore, or manage backup capacity.

### Definition of Done

Sealed backup created with signed manifest, stored as immutable artifacts, concurrent attempt rejected. Partial artifacts never left behind.

## C02

### Identity and outcome

Implement backup throughput and capacity admission: representative probes, reserve/floor formulas, device aggregation, continuous guards, deadlines, permit/session census, and outside-profile results. C02 ensures backup operations never exceed accepted resource bounds.

### Implementation boundary

Throughput admission uses the accepted representative probes: `pg_dump --schema-only` for metadata throughput, `dd`-based write test for filesystem throughput, and `df`-based space check for capacity. Reserve formula: `max_backup_size = min(disk_free * 0.7, 10 * largest_observed_dump_size)`. Floor formula: `min_required = max(accepted_minimum_reserve, current_db_size * 1.5)`. Device aggregation: if backup and database reside on different devices, each is independently probed. Continuous guards: a background goroutine polls disk space every 60 seconds and rejects new backup creation when below floor. Deadline: a backup creation must complete within 3600 seconds. Permit/session census: at most 1 backup permit is active concurrently. Outside-profile results: a device whose probe metrics fall outside the accepted profile range produces a structured warning but does not block backup creation.

### Durable data and migration

Capacity metrics and admission decisions are recorded as immutable operation/checkpoint evidence. No new migration.

### Security and authority

Capacity admission is a safety mechanism, not a security boundary. It prevents resource exhaustion but does not gate on operator identity.

### Failure, retry, cancellation, and recovery

Below-floor rejection produces a structured error with current and required space. Probe timeout (30s per probe) stops admission. Continuous guard activation during a running backup sends a warning but does not cancel; the next backup creation is blocked.

### Verification and evidence

- Probe completes for metadata throughput, filesystem throughput, and capacity
- Reserve and floor formulas produce correct values for accepted fixture sizes
- Below-floor rejection fires when disk is too full
- Deadline (3600s) is enforced
- Permit/session census prevents concurrent backups
- Outside-profile metrics produce warnings but not rejections
- Future test suite: `go test ./internal/backup/...`
- Evidence artifact: `slice-c-capacity-admission.json`

### Scope control

C02 owns backup capacity governance. It must not perform backup creation, restore, or delete backup artifacts.

### Definition of Done

Throughput/capacity admission operational with exact reserve/floor formulas, device aggregation, continuous guards, deadline enforcement, and outside-profile warnings. Accepted minimum-profile capacity/throughput assertions pass.

## C03

### Identity and outcome

Implement restore verification: validate backup manifest signature, verify dump file SHA-256 against manifest, check PostgreSQL version compatibility, issue a one-use restore ticket, and enforce PAM authorization. C03 gates restore admission before C04 applies the restore.

### Implementation boundary

Restore verification reads the backup manifest, verifies the Ed25519 signature, recomputes the dump file SHA-256, and compares against the manifest. PostgreSQL version check ensures the target server is compatible (same major version, minor version >= backup version). A one-use restore ticket is a UUID v7 recorded in PostgreSQL with status `issued`, bound to the verified backup identity, and consumed by C04. PAM authorization verifies the operator's physical-seat presence via the configured PAM agent (A03).

### Durable data and migration

Restore tickets are stored in PostgreSQL `restore_ticket` table. Ticket consumption transitions status from `issued` to `consumed`. No new migration beyond B05.

### Security and authority

Manifest signature verification proves backup authenticity. One-use ticket prevents replay. PAM authorization ensures physical-seat confirmation. Ticket expiration: 600 seconds after issue.

### Failure, retry, cancellation, and recovery

Manifest signature failure, checksum mismatch, or version incompatibility produces a structured rejection. Expired ticket is rejected; a new ticket must be issued. PAM failure (operator not present) rejects admission.

### Verification and evidence

- Valid manifest signature passes verification
- Checksum mismatch rejects admission
- Version incompatibility (different major version) rejects admission
- One-use ticket is consumed and cannot be reused
- Expired ticket (after 600s) is rejected
- PAM authorization gates admission
- Future test suite: `go test ./internal/restore/...`
- Evidence artifact: `slice-c-restore-verification.json`

### Scope control

C03 owns restore verification and admission. It must not apply restore, reset authority, or modify database state.

### Definition of Done

Restore admission gated by manifest verification, checksum validation, version compatibility, one-use ticket, and PAM authorization. Ticket replay is rejected.

## C04

### Identity and outcome

Apply restore via pg_restore 16.14, enforce the quarantine barrier during restore, ensure fresh bootstrap after restore, and prove no partially-served restore. C04 executes the restore that C03 authorized.

### Implementation boundary

Restore apply uses `pg_restore` 16.14 with `--clean --if-exists --no-owner --no-privileges --single-transaction` flags on the verified dump file. Before restore: quarantine barrier sets database to read-only mode and disconnects all non-superuser connections. After restore: fresh bootstrap resets the `event_sequence`, reinitializes the protected-state store with a new `VerifiedEmptyTarget`, and records a `RESTORE_APPLIED` event. No partially-served restore: the quarantine barrier ensures no application connection can read or write during restore; the single-transaction flag ensures atomic application.

### Durable data and migration

Restore replaces all application data. The `restore_log` table records the restore event with the backup identity, ticket identity, starting and ending LSNs. Migration log is reset; the version-zero migration is re-applied from the dump.

### Security and authority

Restore requires the consumed one-use ticket (C03). Quarantine barrier prevents concurrent access. The restore operation runs under broker-held least-privilege backup identities (B04); no plaintext credentials are used. Post-restore the least-privilege session is terminated.

### Failure, retry, cancellation, and recovery

pg_restore failure within the single transaction rolls back and releases the quarantine barrier. A failed restore leaves the original database intact. The failed restore attempt is recorded in `restore_log` with the error.

### Verification and evidence

- Restore applies the verified backup within a single transaction
- Quarantine barrier prevents concurrent connections during restore
- Fresh bootstrap after restore with new event_sequence
- No partially-served restore: either fully applied or fully rolled back
- Failed restore leaves original database intact
- Future test suite: `go test ./internal/restore/...`
- Evidence artifact: `slice-c-restore-apply.json`

### Scope control

C04 owns restore application. It must not verify restore, create backup, or reset authority beyond the fresh bootstrap.

### Definition of Done

Restore applies atomically with quarantine barrier, fresh bootstrap, and rollback-on-failure. No partially-served state.

## C05

### Identity and outcome

Implement post-restore authority reset: increment the security epoch, rebind the helper binary and PAM agent, re-key the broker TLS, and force session re-authentication. C05 ensures no pre-restore authority state survives the restore.

### Implementation boundary

Security epoch increment: current epoch value read from protected state, incremented by 1, written as a signed authority transition (A05). Helper/PAM rebinding: re-derive helper identity and PAM configuration using post-restore instance identity (A03). Broker TLS re-key: generate a new Ed25519 key pair and self-signed certificate (A04). Session invalidation: all existing session tokens are invalidated via epoch check (B06). Bootstrap session forces operator re-authentication.

### Durable data and migration

Security epoch and authority transitions are stored in the protected state directory. Session invalidation is recorded in PostgreSQL. No new migration.

### Security and authority

Authority reset is mandatory after every restore. No pre-restore session survives. The new broker TLS key pair is stored with mode `0600`. Helper rebinding verifies the helper binary signature against the current advisory (B01).

### Failure, retry, cancellation, and recovery

Authority reset failure after a successful restore is a critical inconsistency. Rescue requires manual operator intervention via the rescue path (D06). The failure is recorded in the authority transition log.

### Verification and evidence

- Security epoch is incremented by 1 after restore
- Pre-restore session tokens are invalidated
- New broker TLS key pair is generated with different fingerprint
- Helper rebinding passes advisory signature verification
- Bootstrap session forces operator re-authentication
- Future test suite: `go test ./internal/authority/...`
- Evidence artifact: `slice-c-authority-reset.json`

### Scope control

C05 owns post-restore authority reset. It must not perform restore, create backup, or implement destructive operations.

### Definition of Done

Post-restore authority is fresh: incremented epoch, invalidated sessions, new broker TLS, verified helper, and forced re-authentication.

## C06

### Identity and outcome

Prove full recovery acceptance with minimum-profile capacity/throughput failure assertions and complete end-to-end evidence. C06 validates the complete Slice C recovery chain and owns the minimum-profile capacity/throughput evidence.

### Implementation boundary

C06 is an acceptance verification suite exercising the C01–C05 chain:

1. Create a backup (C01) → manifest signed, dump file verified
2. Simulate a corruption by deleting random rows → application detects inconsistency
3. Verify backup (C03) → admission passes with valid manifest and checksum
4. Issue restore ticket (C03) → one-use ticket recorded
5. Apply restore (C04) → quarantine, restore, fresh bootstrap
6. Reset authority (C05) → epoch incremented, sessions invalidated, TLS re-keyed
7. Verify post-restore state matches pre-corruption state
8. Minimum-profile assertions: backup throughput within profile, restore throughput within profile, disk usage within reserve formula, restore time within deadline
9. Capacity failure: backup creation with below-floor disk space is rejected (C02)
10. Throughput failure: simulated slow device produces outside-profile warning (C02)

### Durable data and migration

All acceptance results reference the same durable state. No new schema.

### Security and authority

Acceptance uses the same authority chain as production flow. No test-only authority bypass.

### Failure, retry, cancellation, and recovery

Acceptance failure is a gate failure. Each scenario produces pass/fail with exact divergence from expectation.

### Verification and evidence

- Full backup → corruption → restore → authority reset chain passes
- Post-restore state matches pre-corruption state
- Minimum-profile capacity/throughput assertions pass
- Capacity failure (below-floor) is correctly rejected
- Throughput failure (slow device) produces outside-profile warning
- Future test suite: `go test ./internal/recovery/...`
- Evidence artifact: `slice-c-recovery-acceptance.json`

### Scope control

C06 is an acceptance suite. It must not implement new runtime components.

### Definition of Done

Full recovery acceptance chain passes. Minimum-profile capacity/throughput assertions verified. Slice C complete.

## Slice C acceptance

Slice C is complete when:

1. C01–C06 contracts are verified
2. Backup creates sealed, signed artifacts (C01)
3. Capacity admission enforces reserve/floor/deadline/aggregation (C02)
4. Restore admission gated by verification, checksum, one-use ticket, and PAM (C03)
5. Restore applies atomically with quarantine barrier and fresh bootstrap (C04)
6. Post-restore authority is reset with new epoch, keys, and sessions (C05)
7. Full recovery acceptance passes with minimum-profile evidence (C06)
8. No partially-served restore state is possible
9. Streaming artifact bodies are restored correctly

Slice C must not claim Slice D or E capabilities.
