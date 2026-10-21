# Slice E — Dependency Maintenance

- **Slice ID:** E
- **Dossier:** `slice-e-dependency-maintenance.md`
- **Packets:** E01–E06
- **Dependency:** D07 (Slice D complete)
- **Outcome:** Operational dependency maintenance with compatibility governance, patch application, verified rollback, advisory lifecycle conformance, and operator runbooks

## Slice E ownership

E01–E06 collectively own:

- the accepted directional compatibility matrix for exact pinned identities;
- ticketed offline patch preparation/application, exact-operation resume, rollback or out-of-place fallback, and post-transition verification;
- advisory consumer conformance using externally produced signed fixtures, excluding compiler/signing/private-key/publication/emergency-response ownership;
- operator runbooks and final E06 compatibility, recovery, security, browser, and minimum-profile evidence.

Unlisted transitions remain unsupported or require out-of-place handling; they are never silently admitted.

## E01

### Identity and outcome

Implement compatibility planning: define the directional transition matrix for every pinned dependency, reject unlisted transitions, and gate any dependency change on matrix approval. E01 establishes the governance framework that all subsequent maintenance operations depend on.

### Implementation boundary

The directional transition matrix enumerates every pinned dependency (Go toolchain, PostgreSQL, MinIO, Docker, Compose, pgx, gin, minio-go, sqlc) with its current version, minimum compatible version, maximum compatible version, supported upgrade path, and required validation gates. A dependency change outside the matrix is rejected. The matrix is stored as a signed authority transition (A05). Compatibility check runs on every `central maintenance plan` invocation and gates E02 and E03 operations.

Matrix example entries:

| Dependency | Current | Min | Max | Upgrade path | Validation gate |
| --- | --- | --- | --- | --- | --- |
| Go toolchain | 1.26.5 | 1.26.5 | 1.26.x | Direct | Full test suite + govulncheck |
| PostgreSQL | 16.14 | 16.14 | 16.x | Direct | Migration replay + pg_dump/restore |
| MinIO | 9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a | 9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a | accepted pinned commit | Direct | Artifact upload/verify round-trip |
| Docker | 29.6.1 | 29.6.1 | 29.x | Direct | Compose up/down cycle |
| Compose | 5.3.1 | 5.3.1 | 5.x | Direct | Compose up/down cycle |

### Durable data and migration

Compatibility matrix is stored as an authority transition in the protected state directory. No PostgreSQL dependency.

### Security and authority

Matrix updates require a signed authority transition. The matrix is the sole authority for permitted dependency changes. No unlisted transition proceeds.

### Failure, retry, cancellation, and recovery

Unlisted transition rejection produces a structured error with the matrix entry for the affected dependency. A rejected transition cannot proceed to E02.

### Verification and evidence

- Matrix covers every pinned dependency from the accepted Gate 7 go.mod
- Listed upgrade path is accepted
- Unlisted transition is rejected with exact dependency name and matrix entry
- Matrix is stored as a signed authority transition
- `central maintenance plan` verifies all current versions against matrix
- Future test suite: `go test ./internal/maintenance/...`
- Evidence artifact: `slice-e-compatibility-matrix.json`

### Scope control

E01 owns the compatibility matrix and planning. It must not apply patches, perform rollbacks, or modify dependencies.

### Definition of Done

Directional transition matrix enumerates every pinned dependency with accepted upgrade paths. Unlisted transitions are rejected. Compatibility planning operational.

## E02

### Identity and outcome

Implement patch application with resume capability and post-patch verification. E02 updates a pinned dependency to a matrix-approved version and verifies the update.

### Implementation boundary

Patch application: verify the target version is in the matrix upgrade path for the current version (E01), download the new version if applicable, update the version pin, and run the matrix-defined validation gate. Resume capability: if a patch fails during validation, the patch log records the failure and the operator can retry or roll back (E03). Post-patch verification: the validation gate must pass before the patch is committed.

### Durable data and migration

Patch log records every patch attempt with dependency, from-version, to-version, validation result, and timestamp. Stored as authority transitions.

### Security and authority

Patch application requires PAM authorization. Version pins are updated via signed authority transitions. No unsigned version change.

### Failure, retry, cancellation, and recovery

Validation failure rejects the patch and leaves the previous version active. The operator can retry the same patch or roll back. Partial application state is not committed.

### Verification and evidence

- Listed upgrade path allows patch from current to target version
- Validation gate runs and passes
- Failed validation leaves previous version active
- Patch log records the attempt
- Resume from failed patch is possible
- Future test suite: `go test ./internal/maintenance/...`
- Evidence artifact: `slice-e-patch-apply.json`

### Scope control

E02 owns patch application. It must not modify the compatibility matrix, perform rollbacks, or manage advisory lifecycle.

### Definition of Done

Dependency updated to matrix-approved version with validation gate, patch log, and resume capability. Failed patches leave previous version intact.

## E03

### Identity and outcome

Implement rollback with out-of-place fallback: restore the previous dependency version, verify rollback integrity, and provide exact evidence of the rollback operation. E03 ensures no dependency change is irreversible.

### Implementation boundary

Rollback restores the previous version from the pre-patch backup (created by E02 automatically before applying a patch). Out-of-place fallback: if the direct rollback fails, an out-of-place copy of the dependency is used as a fallback path while the full suite runs. Rollback verification runs the same validation gate as the patch (E02). Exact evidence: the rollback log records from-version, to-version (restored), validation result, and timestamp.

### Durable data and migration

Rollback log records every rollback with full version trail. Stored as authority transitions.

### Security and authority

Rollback requires PAM authorization. The previous version's signature is verified against the advisory before restoration.

### Failure, retry, cancellation, and recovery

Direct rollback failure triggers out-of-place fallback. Out-of-place fallback failure leaves the system in a maintenance state requiring operator intervention. Both paths are recorded.

### Verification and evidence

- Rollback restores previous dependency version
- Rollback validation gate passes
- Out-of-place fallback activates when direct rollback fails
- Rollback log records the complete version trail
- Previous version signature is verified
- Future test suite: `go test ./internal/maintenance/...`
- Evidence artifact: `slice-e-rollback.json`

### Scope control

E03 owns rollback operations. It must not apply patches, modify the matrix, or manage advisory lifecycle.

### Definition of Done

Rollback restores previous version with verified integrity, out-of-place fallback when needed, and exact rollback evidence.

## E04

### Identity and outcome

Implement advisory lifecycle conformance using externally produced fixtures: verify the current advisory against accepted lifecycle stages, consume fixture-provided test advisories, and maintain conformance evidence. E04 explicitly excludes compiler operations, signing ceremonies, private-key custody/recovery, publication, and emergency response from runtime code.

### Implementation boundary

Advisory lifecycle stages: `current`, `stale` (within grace period), `hard_expired`, and `deny`. E04 reads the advisory from the accepted distribution path (B01) and verifies its stage against the current clock. Fixture-provided test advisories are consumed from a designated directory with verified Ed25519 signatures. Conformance evidence: each lifecycle transition is recorded as a signed authority transition.

Explicit exclusions:
- Compiler: E04 does not compile, cross-compile, or build dependencies
- Signing ceremony: E04 does not perform key generation or signing
- Private-key custody/recovery: E04 does not store, backup, or recover private keys
- Publication: E04 does not publish advisories, updates, or artifacts
- Emergency response: E04 does not execute emergency-response procedures

### Durable data and migration

Advisory lifecycle transitions are stored as authority transitions. Fixture consumption is recorded with fixture identity and verification result.

### Security and authority

Advisory verification uses the compile-time Ed25519 public key. Fixtures are verified before consumption. E04 does not trust unsigned fixtures.

### Failure, retry, cancellation, and recovery

Fixture verification failure rejects the fixture. Advisory stage transition from stale to hard_expired is handled by D06 rescue.

### Verification and evidence

- Current advisory validates within lifecycle stage
- Stale advisory with grace period remaining is accepted
- Hard-expired advisory transitions to deny-safe (D06)
- Fixture-provided test advisories are consumed and verified
- Excluded operations (compiler, signing, key custody, publication, emergency response) are not present in runtime code
- Future test suite: `go test ./internal/advisory/...`
- Evidence artifact: `slice-e-advisory-lifecycle.json`

### Scope control

E04 owns advisory lifecycle conformance. It must not perform compiler operations, signing, key custody, publication, or emergency response.

### Definition of Done

Advisory lifecycle conformance verified with fixture-provided test advisories. All excluded operations confirmed absent from runtime code.

## E05

### Identity and outcome

Write operator runbooks for patch, rollback, and compatibility procedures. E05 produces the canonical operator documentation for all maintenance operations.

### Implementation boundary

Runbooks are Markdown documents in `docs/operations/` covering:

1. **Compatibility planning:** how to run `central maintenance plan`, interpret the matrix, and request a new transition
2. **Patch application:** step-by-step procedure with pre-patch checks, validation, and post-patch verification
3. **Rollback:** when and how to roll back, out-of-place fallback procedure, and recovery from failed rollback
4. **Advisory lifecycle:** how to interpret advisory stages, what to do at each stage, and how to perform rescue
5. **Troubleshooting:** common failure modes, diagnostic commands, and evidence collection

Every procedure includes exact commands, expected output, error handling, and required evidence artifacts.

### Durable data and migration

Runbooks are committed documentation, not application state. No migration.

### Security and authority

Runbooks reference operator-facing commands only. No internal-only operations are exposed.

### Failure, retry, cancellation, and recovery

N/A. Runbooks are documentation, not executable code.

### Verification and evidence

- Runbook for compatibility planning references existing commands and matrix
- Runbook for patch covers pre-check, apply, and post-patch verification
- Runbook for rollback covers direct and out-of-place paths
- Runbook for advisory lifecycle covers all four stages
- Runbook for troubleshooting covers at least five common failure modes
- Future test suite: link checker and command-verification
- Evidence artifact: `slice-e-runbooks-verification.json`

### Scope control

E05 owns operator runbooks. It must not create executable code, modify application state, or perform maintenance operations.

### Definition of Done

Complete runbooks for compatibility, patch, rollback, advisory lifecycle, and troubleshooting. Every procedure includes exact commands and expected output.

## E06

### Identity and outcome

Prove full Phase 1 suite ownership and final acceptance: execute the complete Phase 1 compatibility, recovery, security-sentinel, and minimum-profile performance/resource suite. E06 validates all slices and produces final Phase 1 acceptance evidence.

### Implementation boundary

E06 is the final Phase 1 acceptance suite:

1. Compatibility: every dependency version matches the compatibility matrix (E01)
2. Patch cycle: update one dependency → validate → rollback → verify (E02, E03)
3. Advisory lifecycle: current → stale → hard-expired → rescue (E04, D06)
4. Full backup/restore cycle (C01–C06)
5. Destructive operations with PAM and checkpoint (D01–D07)
6. Security sentinel: run A07 authority verification, B01 advisory checks, B06 security headers, and the complete capability-policy matrix
7. Minimum-profile performance/resource suite: sandbox bounds (A06), capacity admission (C02), throughput probes (C02), backup/restore within deadline (C06)
8. End-to-end: clean host → Slice A → Slice B (first value) → Slice C (recovery) → Slice D (destructive) → Slice E (maintenance)

### Durable data and migration

All acceptance results reference durable state. No new schema.

### Security and authority

Complete acceptance uses production authority chain. No test-only bypass.

### Failure, retry, cancellation, and recovery

Acceptance failure is a gate failure with complete divergence report.

### Verification and evidence

- Compatibility matrix complete and enforced
- Patch-rollback cycle passes
- Advisory lifecycle transitions verified
- Full backup/restore with authority reset passes
- Destructive operations with PAM and checkpoints pass
- Security sentinel passes all authority and policy checks
- Performance suite passes minimum-profile assertions
- End-to-end clean-host acceptance passes
- Future test suite: `go test ./internal/acceptance/...`
- Evidence artifact: `slice-e-full-phase1-acceptance.json`

### Scope control

E06 is the final acceptance suite. It must not implement new runtime components.

### Definition of Done

Complete Phase 1 suite passes: compatibility, recovery, security sentinel, performance, and end-to-end acceptance. Phase 1 full exit achieved. No implementation gaps.

## Phase 1 full exit

Phase 1 is complete when:

1. All five slices (A–E) are accepted with verifiable evidence
2. Compatibility matrix governs all dependency transitions (E01)
3. Patch and rollback cycles are verified (E02, E03)
4. Advisory lifecycle conformance is maintained (E04)
5. Complete operator runbooks are published (E05)
6. Full Phase 1 acceptance suite passes (E06)
7. Every Accepted requirement is mapped to a packet and verifiable evidence
8. The minimum-profile performance/resource suite passes
9. No implementation gap remains
