# Slice D — Destructive Portable Operations

- **Slice ID:** D
- **Dossier:** `slice-d-destructive-portable-operations.md`
- **Packets:** D01–D07
- **Dependency:** C06 (Slice C complete)
- **Outcome:** Operator-driven destructive and portable operations with physical-seat confirmation, explicit checkpoints, and safe denial

Every destructive packet requires fresh PAM authorization, physical-seat confirmation, descriptor-bound selection, exact checkpoints, retention/reference proof, crash behavior, and prohibited force/manual repair.

## Slice D ownership

D01–D07 collectively own:

- protected wipe/reseed with fresh PAM, physical-seat confirmation, AppArmor isolation, signed denial, and crash-resume evidence;
- backup export/import with independent `bx1` integrity token and fresh-host recovery;
- backup/Artifact delete and prune with retention/reference proof, tombstones, checkpoints, and no resurrection;
- protected-state/audit tombstone maintenance and tamper evidence;
- hard-expired rescue backup/cleanup behavior without bypassing advisory authority.

Delete/Prune UI and commands return `UNSUPPORTED_IN_THIS_SLICE` before D activation. Slice D owns no dependency patch/rollback implementation; that responsibility belongs to Slice E.

## D01

### Identity and outcome

Implement AppArmor wipe and protected-state reseed: destroy all protected state, reinitialize from genesis, verify zero residual state, and honor signed denial. D01 provides the complete protected-state reset capability gated by physical-seat confirmation.

### Implementation boundary

AppArmor wipe: deactivate the current AppArmor profile for the sandbox launcher, remove the profile file, and verify the launcher binary is not confined. Protected-state reseed: delete the protected state directory, re-derive instance identity (A03), rebind helper/PAM (A03), re-key broker TLS (A04), and bootstrap protected-state store (B04). Physical-seat confirmation requires PAM authentication of the operator before any destructive action begins. Descriptor-bound selection: the operator selects the exact protected-state directory by its canonical path. Exact checkpoint: before deletion, a backup is created (C01) and verified. Retention/reference proof: the checkpoint backup identity is recorded in the operator-audit log before deletion begins. Crash behavior: if the process crashes during wipe, on restart the missing protected state is detected and genesis is offered.

### Durable data and migration

Protected state directory is deleted and regenerated. PostgreSQL data is not affected (separate operation in D04). The operator-audit log records the wipe event.

### Security and authority

PAM authorization with physical-seat confirmation is mandatory. AppArmor profile removal requires root-equivalent permissions via the helper binary. Signed denial: when the current advisory is in a deny state, wipe is rejected even with PAM confirmation. Prohibited force/manual repair: no `--force` flag, no manual AppArmor file edit bypass.

### Failure, retry, cancellation, and recovery

PAM failure rejects the operation before any destruction. Checkpoint backup failure rejects the operation. Crash during wipe leaves the audit log record; on restart, genesis detection triggers reinitialization.

### Verification and evidence

- PAM authorization succeeds with valid operator credentials
- PAM failure rejects operation before any state change
- AppArmor profile is removed and launcher is unconfined
- Protected state is regenerated with new identity and TLS keys
- Signed denial rejects wipe even with valid PAM
- Crash during wipe triggers genesis on restart
- Force and manual repair are not available
- Future test suite: `go test ./internal/destructive/...`
- Evidence artifact: `slice-d-wipe-reseed.json`

### Scope control

D01 owns protected-state wipe and reseed. It must not delete PostgreSQL data, MinIO data, or perform export/import.

### Definition of Done

Protected state is completely wiped and regenerated with PAM confirmation, AppArmor profile removal, checkpoint backup, and signed denial enforcement. No force/manual bypass.

## D02

### Identity and outcome

Implement export: produce a portable encrypted bundle containing the complete application state and an independent `bx1` token for trusted fresh-host bootstrap. D02 produces the export artifact that D03 consumes.

### Implementation boundary

Export collects: PostgreSQL dump (C01 format), MinIO bucket objects (all), protected state (configuration, authority transitions, TLS keys, instance identity). Bundle is a tar.gz archive encrypted with an Ed25519-derived symmetric key via AES-256-GCM. The `bx1` token is a signed JSON Web Token containing the export bundle SHA-256, creation timestamp, instance identity, and export purpose tag, signed with the instance Ed25519 key. Token is independent: it validates without access to the original instance. No active credentials or trust material from the original host are included in the export beyond the token signature.

### Durable data and migration

Export bundle and token are written to the operator-specified export directory. No new database schema.

### Security and authority

PAM authorization with physical-seat confirmation is required. Export bundle is encrypted at rest. Token can be independently verified with the accepted Ed25519 public key. No credential, secret, or trust anchor from the original host is embedded in exported data beyond what the operator explicitly exports.

### Failure, retry, cancellation, and recovery

Backup creation failure, MinIO object retrieval failure, or encryption failure stops export. Partial export artifacts are removed. Crash during export produces an incomplete bundle that fails D03's verification.

### Verification and evidence

- Export creates an encrypted tar.gz bundle
- bx1 token is signed with valid Ed25519 key
- Token validates independently without original instance access
- Export contains no active credentials from original host
- Encryption prevents unauthorized bundle inspection
- Partial export on failure is cleaned up
- Future test suite: `go test ./internal/portable/...`
- Evidence artifact: `slice-d-export.json`

### Scope control

D02 owns export. It must not import, delete, or prune. Export does not modify the original instance state.

### Definition of Done

Portable encrypted export bundle created with independent bx1 token. No active credentials or trust material in export. Token verifies independently.

## D03

### Identity and outcome

Implement fresh-host import: verify the bx1 token, decrypt the export bundle, bootstrap the new instance from the exported data, and verify the imported state matches the export. D03 provides fresh-host bootstrap from D02's export.

### Implementation boundary

Import verification: validate bx1 token signature and expiry, verify export bundle SHA-256 against token. Decryption: derive the symmetric key from the token and decrypt the AES-256-GCM bundle. Bootstrap: restore PostgreSQL from the dump (C04), copy MinIO objects to the new instance's buckets, and bootstrap protected state from the exported configuration. Descriptor-bound selection: the operator selects the exact export bundle by its canonical path. Post-import verification: compare the imported PostgreSQL checksum and MinIO object count against the export manifest.

### Durable data and migration

Import replaces all instance state. Fresh PostgreSQL, MinIO, and protected state are provisioned.

### Security and authority

PAM authorization with physical-seat confirmation on the target host is required. Token signature verification proves the export's origin. Import on an already-initialized instance is rejected (must run D01 first).

### Failure, retry, cancellation, and recovery

Token verification failure, SHA-256 mismatch, or decryption failure stops import before any state is modified. Partial import triggers D01 reset. PostgreSQL restore failure rolls back inline (C04 single-transaction guarantee).

### Verification and evidence

- Token signature verifies with accepted public key
- SHA-256 mismatch rejects import
- Imported PostgreSQL checksum matches export manifest
- Imported MinIO object count matches export manifest
- Import on initialized instance is rejected
- Partial import triggers clean reset
- Future test suite: `go test ./internal/portable/...`
- Evidence artifact: `slice-d-import.json`

### Scope control

D03 owns import. It must not export, delete, or prune. Import is a one-way operation: it replaces all instance state.

### Definition of Done

Fresh-host import from export bundle with token verification, decryption, bootstrap, and post-import state verification. Partial import triggers clean reset.

## D04

### Identity and outcome

Implement delete and prune operations: delete tasks with all associated state (events, artifacts, runs) with cascade verification, prune old artifacts beyond retention period, and prove crash safety with checkpoint and retention/reference proof.

### Implementation boundary

Task delete: cascading delete of task, runs, step attempts, events, and artifacts. Before deletion, a retention check ensures no artifact younger than the retention period (30 days default) is deleted. Artifacts held by reference from another task are excluded. Prune: scan artifacts older than retention period, verify no active reference, delete MinIO bodies, and mark metadata as `pruned`. Exact checkpoint: before each batch (100 artifacts), a checkpoint is recorded in the `prune_log`. Crash behavior: on restart, the prune operation resumes from the last checkpoint. Retention/reference proof: each deleted artifact's metadata is recorded in the `prune_log` with its retention age and reference count. Tombstones: every deleted/pruned artifact receives a tombstone record so that no resurrection is possible; tombstones carry the deletion checkpoint, retention age, and reference proof.

### Durable data and migration

Cascading deletes operate within a single PostgreSQL transaction. `prune_log` records every pruned artifact. No new migration.

### Security and authority

PAM authorization with physical-seat confirmation is required. Delete and prune are destructive and irreversible. Prohibited force/manual repair: no bypass of retention check or reference check.

### Failure, retry, cancellation, and recovery

Transaction failure rolls back the entire delete batch. Prune resumes from last checkpoint on restart. Retention check failure (artifact too young) rejects the entire delete.

### Verification and evidence

- Task delete cascades to all associated events, artifacts, and runs
- Artifact younger than 30 days is not deleted
- Artifact referenced by another task is excluded from delete
- Prune removes artifacts older than 30 days with no active references
- Prune resumes from checkpoint after crash
- Prohibited force/manual repair is not available
- Future test suite: `go test ./internal/destructive/...`
- Evidence artifact: `slice-d-delete-prune.json`

### Scope control

D04 owns delete and prune. It must not wipe protected state, export, or import.

### Definition of Done

Task delete cascades correctly with retention and reference checks. Prune removes old artifacts with checkpoint-safe resume. Force/manual bypass prohibited.

## D05

### Identity and outcome

Implement protected-state maintenance and integrity audit: verify the protected-state directory integrity, detect tampering, repair via reseed when authorized, and record signed audit events. D05 maintains state integrity with prohibited force/manual repair.

### Implementation boundary

Integrity audit: hash every file in the protected state directory, compare against the last recorded manifests, and produce a signed audit report. Tampering detection: any file whose hash differs from the manifest is flagged. Authorized repair: reseed via D01 with operator confirmation. Audit events are signed authority transitions recorded in the protected state directory. Audit runs on a schedule (daily) and on operator request.

### Durable data and migration

Audit manifests and reports are stored in the protected state directory. Audit events are authority transitions. No PostgreSQL dependency for audit storage.

### Security and authority

Audit is read-only except for authorized repair. Audit report is signed with the instance Ed25519 key. Tampering detection is evidence-only; it does not automatically trigger repair. Prohibited force/manual repair: no silent file replacement, no manifest overwrite without a signed transition.

### Failure, retry, cancellation, and recovery

Audit failure (unreadable file) produces a partial report with the failing path. The next scheduled audit re-attempts the failing paths.

### Verification and evidence

- Daily audit runs and produces a signed report
- Tampered file is detected and flagged
- Authorized repair triggers D01 reseed
- Manual file replacement without transition is flagged as tampering
- Audit report signature is valid
- Future test suite: `go test ./internal/audit/...`
- Evidence artifact: `slice-d-state-audit.json`

### Scope control

D05 owns state integrity audit. It must not wipe, delete, or prune without operator authorization.

### Definition of Done

Daily integrity audit detects tampering, produces signed reports, and gates authorized repair on operator confirmation. Manual repair is detected as tampering.

## D06

### Identity and outcome

Implement hard-expired advisory rescue with deny-safe cleanup and fresh authority evaluation per B01. D06 provides the escape path when the advisory reaches hard-expired state and the application is denied.

### Implementation boundary

When B01 detects a hard-expired advisory, the application enters deny-safe mode: all operations are blocked except D06 rescue. Deny-safe cleanup: stop all services (B03), terminate all active sandboxes (A06), and disconnect all database connections. Fresh B01 evaluation: load a new advisory from the operator-provided path, verify its signature, and evaluate compatibility. If new advisory passes, resume normal operation with new authority evaluation. If no new advisory is available, the application remains in deny-safe mode. Rescue never bypasses advisory authority: a new advisory must verify and pass compatibility before any operation resumes.

### Durable data and migration

Rescue operations are recorded as authority transitions. State is preserved during rescue; no data is lost.

### Security and authority

D06 depends on B01 for advisory evaluation. PAM authorization is required for rescue initiation. Deny-safe mode prevents any mutation; it is a safety lock, not a security bypass.

### Failure, retry, cancellation, and recovery

If no new advisory is available, the application remains in deny-safe mode. A fresh advisory that fails verification leaves the application in deny-safe mode. Rescue can be retried when a new advisory is available.

### Verification and evidence

- Hard-expired advisory triggers deny-safe mode
- Deny-safe mode blocks all operations except rescue
- Fresh advisory passes verification and resumes normal operation
- No new advisory leaves application in deny-safe mode
- Rescue is retriable with new advisory
- Future test suite: `go test ./internal/advisory/...`
- Evidence artifact: `slice-d-rescue.json`

### Scope control

D06 owns hard-expired rescue. It must not modify the advisory or perform key operations. It is an escape path, not a maintenance routine.

### Definition of Done

Hard-expired advisory triggers deny-safe mode. Rescue with fresh advisory resumes operation. Application remains protected in deny-safe mode when no rescue is possible.

## D07

### Identity and outcome

Prove Slice D acceptance: destructive, portable, and authority evaluation evidence with acceptance of all D01–D06 operations. D07 validates the complete Slice D chain.

### Implementation boundary

D07 is an acceptance verification suite:

1. Protected-state wipe and reseed with PAM and checkpoint (D01)
2. Signed denial rejection (D01)
3. Export → independent token verification → import on fresh instance (D02, D03)
4. Cascade delete with retention and reference checks (D04)
5. Artifact prune with checkpoint resume (D04)
6. Daily audit with tampering detection (D05)
7. Hard-expired rescue cycle (D06)
8. Authority evaluation during rescue (D01, D06)

### Durable data and migration

All acceptance results reference durable state. No new schema.

### Security and authority

Every destructive operation gates on PAM and physical-seat confirmation. Signed denial is enforced. No test-only bypass.

### Failure, retry, cancellation, and recovery

Acceptance failure is a gate failure with structured divergence report.

### Verification and evidence

- Wipe/reseed produces clean state with new identity
- Signed denial blocks wipe
- Export/import round-trip preserves state integrity
- Delete cascade preserves referenced artifacts
- Prune resumes from checkpoint
- Audit detects tampering
- Hard-expired rescue succeeds with new advisory
- Future test suite: `go test ./internal/acceptance/...`
- Evidence artifact: `slice-d-acceptance.json`

### Scope control

D07 is an acceptance suite. It must not implement new runtime components.

### Definition of Done

All destructive and portable operations pass acceptance. Authority evaluation verified. Slice D complete.

## Slice D acceptance

Slice D is complete when:

1. D01–D07 contracts are verified
2. Protected-state wipe/reseed with PAM, checkpoint, and signed denial (D01)
3. Portable export/import round-trip with independent bx1 token (D02, D03)
4. Cascade delete with retention/reference checks (D04)
5. Artifact prune with checkpoint-safe resume (D04)
6. State integrity audit with tampering detection (D05)
7. Hard-expired rescue with deny-safe mode (D06)
8. Complete acceptance evidence (D07)
9. No force/manual repair available for any destructive operation

Slice D must not claim Slice E capabilities.
