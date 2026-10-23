# Phase R6 — Backup, Restore, Wipe & Maintenance (Slice C, D, E Parity) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the final vertical slice in `$CENTRAL_RUST_SRC` per [rust-vertical-slice-roadmap.md](../../../implementation/rust-vertical-slice-roadmap.md) §9: the migration-runner CLI surface (`migrate verify|up|status|resume`, exact version-zero `migrate reset`) behind `central-migration-launcherd`; Slice C required recovery (sealed backup, throughput/capacity admission, restore verify/apply, quarantine, post-restore authority reset) through `central-backup`, `central-backup-launcherd`, `bins/central-backup`, `bins/central-restore`; Slice D destructive/portable operations (wipe + reseed, export/`bx1` import, delete/prune, protected-state audit, hard-expired advisory rescue); Slice E dependency maintenance (compatibility matrix, patch, rollback, advisory lifecycle conformance) plus the offline `central-advisory-sign` tool; the `b25`–`b29` evidence stores; the R6 halves of the broker and helper that R5 left as closed denials; and the Phase 1 full-exit suite (E06). R6 closes the `R0`–`R6` sequence.

**Architecture:**
- **Crate roles ([rust-application-boundaries.md](../../../architecture/rust-application-boundaries.md) §2–§3.2, §764):**
  - `central-backup` (capability) owns backup/restore manifests, verified one-use restore tickets, chunked inventory, quarantine, recovery evidence and authority-reset vocabulary. R1 already shipped its migration-domain `domain.rs`/`port.rs`; R6 adds the backup/restore/recovery domain, `query.rs`, and `app.rs`. No `tokio`, `uuid`, `sqlx`.
  - `central-infra` gains `maintenance` (E01–E04) and the destructive/portable command vocabulary (D01–D06) as typed local-operator commands; it still never calls Docker, `pg_*`, or S3 — everything goes through the helper protocol.
  - `central-adapter-postgres` gains `backup/` and `recovery/` stores over `b25`–`b29`.
  - `central-adapter-linux` gains the R6 broker RPCs (backup/restore/migration/recovery authority, restore-capacity reserve, journals) and helper ops (backup, restore, wipe, export, import, delete, prune, rescue, maintenance, security-update) that R5 registered as closed denials — they flip from deny to implemented one by one.
  - Mutating migration/backup/restore verbs run in the dedicated operator binaries (`central-migrate`, `central-backup`, `central-restore`) under their own OS identities via the launcher daemons (§3.2, ADR 0011, ADRs 0015–0018). The `central` binary only dispatches to them.
- **Dependency on earlier slices:** R5 complete (broker, helper, PAM/TTY, `grant`, Compose topology, advisory consumer). R2 `central-adapter-s3` is reused for object-store backup/restore bodies. R1 migration runner (`central-adapter-postgres::migrate`) is reused, not rewritten.

**Tech Stack:** pinned — `sqlx`, `tokio`, `rustix`, `ed25519-dalek`, `hmac`, `rand`, `zeroize`, `sha2`, `serde_json`, `aws-sdk-s3` (via `central-adapter-s3`). **New dependency — approved 2026-10-23 (D1):** `aes-gcm = "=0.11.1"` for the export bundle (upstream `crypto/aes` + `cipher.NewGCM` in `internal/portable/bundle.go`). It is added to `[workspace.dependencies]` in Task 12 and confined to `central-adapter-linux` (helper export/import). `cargo deny check` must pass in the same task; `tar` + gzip for the portable bundle and RFC 8785 JSON canonicalization (upstream `gowebpki/jcs`) are introduced earlier by R5 (R5 D7 archive crates, R5 D6 `central_foundation::jcs`) and only reused here.

## Global Constraints

- **Source of truth:** `$CENTRAL_SRC` (read-only) — `internal/{backup,backuplauncher,migrationlauncher,recovery,maintenance,destructive,portable,advisory}`, `internal/adapter/{backup,objectstore,operatorstate}`, `internal/adapter/postgres/{backup,migrate}`, broker files `{backup_*,restore_*,migration_*,recovery_*,throughput_journal,recovery_journal}.go`, helper files `{backup_*,restore_*,wipe,export,import,delete,prune,rescue,maintenance*,security_update,migration_launch}.go`, `cmd/{central-backup,central-restore,central-migrate,central-advisory-sign,central-backup-launcherd,central-migration-launcherd}`, and the R6 files under `cmd/central/` (`backup_*`, `restore_*`, `import_*`, `export_*`, `wipe_*`, `delete_*`, `prune_*`, `rescue_*`, `maintenance_*`, `security_update_*`, `migration_*`, `verify.go`, `advisory_evaluator_composition.go`, `audit_*`).
- **No new DDL:** `b25`–`b29` exist under `migrations/`. `pg_dump`/`pg_restore` are exactly 16.14, passed via fd-3 by the backup launcher (ADR 0015).
- **No weakened checks:** PAM freshness, TTY ceremony, ADR 0028/0032 `grant` for destructive verbs, one-use restore tickets, quarantine barrier, security-epoch increment, and peer-credential checks are byte-for-byte as strict as upstream. Wire formats (manifests, tickets, `bx1` token, journal records, launcher frames) are unchanged; changing one needs a Proposed ADR.
- **Crash safety:** every long-running operation persists input, current state, retry policy, produced artifacts, failure reason, and resume behavior before acting (AGENTS.md). Restore never serves a partially restored database.
- **Secrets:** credentials travel only as sealed `memfd`s; never in argv/env/logs; export bundle keys exist only in `zeroize`d buffers.
- **`unsafe` discipline:** only in `central-adapter-linux`, launcher daemons, protected-mode bins; every block with `// SAFETY:` and a test.
- **Binary dependency rule (boundaries §3 controller row, R1 `bins/central` precedent):**
  - Operator binaries (`central`, `central-migrate`, `central-backup`, `central-restore`, `central-advisory-sign`) depend only on `central-kernel` and `central-foundation`. All adapter composition (`central-adapter-postgres`, `central-adapter-s3`, `central-adapter-linux` clients) lives in `central-kernel` composition functions those binaries call.
  - Only launcher daemons and protected-mode entrypoints may link `central-adapter-linux` directly.
- **Every task ends green:** `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test -p <touched crates>` (+ `cargo test --workspace` on port/foundation changes), then commit.

---

## Open Decisions

| ID | Question | Gates | Default if no ruling |
| --- | --- | --- | --- |
| D1 | AES-256-GCM for the export bundle; `tar` + gzip and JCS come from R5 (R5 D7, D6). | Tasks 11, 12, 15 | **Decided 2026-10-23:** `aes-gcm =0.11.1`; R6 reuses `central_foundation::jcs`, `tar =0.4.46`, and `flate2 =1.1.10` from R5 |
| D2 | Port the two C daemons (`central-backup-launcherd` 1,552 lines, `central-migration-launcherd` 429 lines) to Rust with identical protocol bytes? | Tasks 2, 6 | Yes, same rule as R3 D3; C test scripts become Rust Tier 3 tests |
| D3 | Which evidence tiers count for R6 acceptance: portable + reference host + the ADR 0033 Docker evidence profile? | Tasks 10, 14, 16 | Same tiers upstream recorded; physical-only rows recorded as deferred with runbook pointers |
| D4 | Slice C02 restore-capacity reserve is ~9k upstream lines in the broker (`restore_capacity_*`). Land it as one task or split per file family? | Task 8 | Split into 8a (receipt/frame/store), 8b (allocation/inspection/sweep), 8c (gate + throughput) |

---

## File Structure

```text
central-rust/
├── crates/
│   ├── capabilities/
│   │   ├── central-backup/src/{domain,port,query,app}.rs       # + backup/, recovery/ submodules
│   │   │   ├── backup/{manifest,ticket,inventory,throughput,capacity}.rs
│   │   │   └── recovery/{evidence,quarantine,authority_reset,operation}.rs
│   │   └── central-infra/src/{maintenance,destructive,portable,rescue}.rs
│   └── adapters/
│       ├── central-adapter-postgres/src/{backup,recovery}/{mod,store}.rs
│       └── central-adapter-linux/src/
│           ├── broker/{backup_authority,backup_launch,backup_worker_credential,restore_launch,
│           │          restore_capacity/*,migration_authority,migration_launch,recovery_authority,
│           │          recovery_journal,throughput_journal}.rs
│           ├── helper/{backup,restore,wipe,export,import,delete,prune,rescue,maintenance,
│           │          security_update,migration_launch}.rs
│           └── backup/{pg_dump,pg_restore,objectstore_backup,operator_state}.rs
└── bins/
    ├── central/src/{migrate_cli,backup_cli,restore_cli,destructive_cli,maintenance_cli}.rs
    ├── central-migrate/src/main.rs
    ├── central-migration-launcherd/src/{main,protocol,policy}.rs
    ├── central-backup/src/main.rs
    ├── central-restore/src/main.rs
    ├── central-backup-launcherd/src/{main,protocol,policy,session}.rs
    └── central-advisory-sign/src/main.rs
```

---

## Milestone A — Migration CLI surface

### Task 1: `bins/central-migrate` + `central migrate *` dispatch

**Files:** Create `bins/central-migrate/src/main.rs`, `bins/central/src/migrate_cli.rs`; modify `bins/central/src/main.rs`.

**Reference:** `cmd/central-migrate/main.go`, `cmd/central/{migration_client,migration_outcome_reader}.go` + tests; `docs/persistence/migrations-and-recovery.md`; R1 `central-adapter-postgres::migrate::{runner,reset_runner,verify_shape}`.

- [ ] **Step 1:** Port CLI tests: `verify` (read-only shape check), `up` (advisory-locked, checksum ledger), `status`, `resume` (dirty data-backfill only, no generic `Force`), `reset` accepted **only** against an exact version-zero target; every outcome as `central.local-result/v1` with stable exit classes → FAIL.
- [ ] **Step 2:** Add `central-kernel::migrate_compose`, which wires the R1 runner (`central-adapter-postgres::migrate`) for the `central_migration` identity. `bins/central-migrate` calls only that kernel function. `central migrate *` dispatches to `central-migrate` through the launcher client (Task 2), never in-process.
- [ ] **Step 3:** PASS (DSN-gated) → commit `feat(migrate): add central-migrate CLI over the native runner`.

### Task 2: `central-migration-launcherd` + broker migration authority (ADR 0011, D2)

**Files:** Create `bins/central-migration-launcherd/src/{main,protocol,policy}.rs`, `central-adapter-linux/src/broker/{migration_authority,migration_launch}.rs`, `helper/migration_launch.rs`.

**Reference:** `cmd/central-migration-launcherd/*.c`, `internal/migrationlauncher/*`, broker `{migration_authority_rpc,migration_authority_client,migration_launch,restore_migration_credential_linux}.go`, helper `migration_launch.go` + tests.

- [ ] **Step 1:** Port tests: socket activation, peer-cred check for the `central_migration` identity, credential delivered as sealed `memfd`, policy denial matrix, outcome frames identical to upstream → FAIL.
- [ ] **Step 2:** Implement; flip the R5 closed denials for these ops.
- [ ] **Step 3:** PASS (root tests skip locally) → commit `feat(migration-launcherd): port migration launcher and broker migration authority`.

## Milestone B — Slice C: required recovery

### Task 3: `central-backup` backup & recovery domain

**Files:** Create `central-backup/src/backup/{manifest,ticket,inventory,throughput,capacity}.rs`, `recovery/{evidence,quarantine,authority_reset,operation}.rs`, `query.rs`, `app.rs`; extend `domain.rs`/`port.rs` without breaking R1 types.

**Reference:** `internal/backup/*` (5.9k), `internal/recovery/*` (5.2k) + tests; dossier `slice-c-required-recovery.md`; ADRs 0015–0018.

- [ ] **Step 1:** Port domain tests: signed manifest (exact signature payload), dump SHA-256 binding, PostgreSQL version compatibility, one-use restore ticket (issue/consume/replay rejection), chunked inventory, quarantine barrier states, authority-reset sequence (epoch++, helper/PAM rebind, broker TLS re-key, session invalidation), throughput reserve/floor formulas → FAIL.
- [ ] **Step 2:** Implement pure domain + ports + `app` services.
- [ ] **Step 3:** PASS; `cargo test --workspace` (port change) → commit `feat(backup): port backup manifest, restore ticket, quarantine, and recovery domain`.

### Task 4: `central-adapter-postgres::{backup,recovery}` (b25–b29)

**Files:** Create `src/backup/{mod,store}.rs`, `src/recovery/{mod,store}.rs`; `.sqlx/`.

**Reference:** `internal/adapter/postgres/backup/*` (1.9k) + tests; `migrations/0025_b25*`–`0029_b29*`.

- [ ] **Step 1:** Port DSN-gated tests for `recovery_operations`, `recovery_quarantines`, `recovery_authority_reset_receipts`, `recovery_bootstrap_registrations`, `prune_log` → FAIL.
- [ ] **Step 2:** Implement with transactions per state change; regenerate `.sqlx/`; check grants (gaps → `docs/internal/tasks/`).
- [ ] **Step 3:** PASS → commit `feat(adapter-postgres): implement b25–b29 recovery evidence stores`.

### Task 5: Backup execution adapter (`pg_dump`/`pg_restore`, object store, operator state)

**Files:** Create `central-adapter-linux/src/backup/{pg_dump,pg_restore,objectstore_backup,operator_state}.rs`.

**Reference:** `internal/adapter/backup/*` (4.6k), `internal/adapter/objectstore/*`, `internal/adapter/operatorstate/*` + tests.

- [ ] **Step 1:** Port tests: `pg_dump`/`pg_restore` 16.14 via fd-3 only, exclusive-target lock, streaming SHA-256, object-store body copy through `central-adapter-s3`, operator-state file handling → FAIL.
- [ ] **Step 2:** Implement; PASS → commit `feat(adapter-linux): add pg_dump/pg_restore and object-store backup execution`.

### Task 6: `central-backup-launcherd` (D2)

**Files:** Create `bins/central-backup-launcherd/src/{main,protocol,policy,session}.rs`.

**Reference:** `cmd/central-backup-launcherd/*.c` (1.5k), `internal/backuplauncher/*` + tests.

- [ ] **Step 1:** Port protocol golden frames + policy/denial tests → FAIL.
- [ ] **Step 2:** Implement (`rustix`, audited `[lints]`); PASS → commit `feat(backup-launcherd): port backup/restore launcher daemon`.

### Task 7: Broker backup/restore/recovery authority + helper ops

**Files:** Create broker `{backup_authority,backup_launch,backup_worker_credential,restore_launch,recovery_authority,recovery_journal,throughput_journal}.rs`; helper `{backup,restore}.rs`.

**Reference:** broker `{backup_authority_rpc,backup_launch,backup_worker_credential_linux,restore_launch,recovery_authority_rpc,recovery_journal,throughput_journal}.go`; helper `{backup_launch,backup_read,backup_read_client_linux,restore_apply,restore_verify,restore_refusal,restore_abandon,restore_operator_client_linux}.go` + tests.

- [ ] **Step 1:** Port tests: each RPC's peer authorization, journal crash recovery, PAM-gated restore, refusal/abandon paths → FAIL.
- [ ] **Step 2:** Implement; flip R5 denials for these ops; PASS → commit `feat(adapter-linux): add broker backup/restore/recovery authority and helper ops`.

### Task 8: C02 throughput & restore-capacity admission (D4)

**Files:** Create `central-adapter-linux/src/broker/restore_capacity/*.rs`; extend `central-backup/src/backup/{throughput,capacity}.rs`.

**Reference:** broker `restore_capacity_*` (≈9k lines: receipt, frame, store, store_path, allocation, inspection, sweep, gate, reserve_helper, reserve_object), `backup_throughput_{launch,launch_rpc,rpc}.go`; `cmd/central/backup_throughput_*`, `restore_capacity_reserve_launch.go` + tests.

- [ ] **Step 1 (8a):** receipt/frame/store: port tests → implement → PASS → commit `feat(adapter-linux): add restore-capacity receipts, frames, and store`.
- [ ] **Step 2 (8b):** allocation/inspection/sweep: port tests → implement → PASS → commit `feat(adapter-linux): add restore-capacity allocation, inspection, and sweep`.
- [ ] **Step 3 (8c):** admission gate + throughput probes, device aggregation, continuous guards, deadlines, permit/session census, outside-profile results → PASS → commit `feat(backup): add throughput and capacity admission`.

### Task 9: `central-backup`/`central-restore` binaries + C01/C03/C04/C05 flows

**Files:** Create `bins/central-backup/src/main.rs`, `bins/central-restore/src/main.rs`, `bins/central/src/{backup_cli,restore_cli}.rs`.

**Reference:** `cmd/central-backup/*`, `cmd/central-restore/*`, `cmd/central/{backup_*,restore_*,verify}.go` + tests.

- [ ] **Step 1:** Failing end-to-end tests (DSN + MinIO gated): create sealed backup (C01) → verify manifest/ticket (C03) → apply restore under quarantine with fresh bootstrap, no partial serving (C04) → authority reset (C05).
- [ ] **Step 2:** Implement `central-kernel::{backup_compose,restore_compose}` (Postgres stores, S3 body copy, `central-adapter-linux` broker/helper clients). Both binaries call only those functions. `central backup *`/`restore *` dispatch to these binaries via the launcher.
- [ ] **Step 3:** PASS → commit `feat(backup): add central-backup and central-restore operator flows`.

### Task 10: C06 recovery acceptance (D3)

**Files:** Create `bins/central-restore/tests/c06_*.rs` (or the upstream-equivalent location).

- [ ] **Step 1:** Port the C06 suite incl. minimum-profile capacity/throughput failure assertions; record evidence path.
- [ ] **Step 2:** Run portable + reference host → commit `test(backup): add Slice C recovery acceptance`.

## Milestone C — Slice D: destructive & portable operations

### Task 11: Wipe + reseed (D01) and delete/prune (D04)

**Files:** Create `central-infra/src/destructive.rs`, helper `{wipe,delete,prune}.rs`, `bins/central/src/destructive_cli.rs`.

**Reference:** `internal/destructive/{wipe,reseed,prune}.go` (+ `prune_test.go`), helper `{wipe,delete,prune}.go`, R2 `crates/capabilities/central-artifact/src/{domain,port}.rs` (tombstone + `remove_ready_for_delete`), `cmd/central/{wipe_*,delete_*,prune_*}.go` + tests; ADR 0032.

- [ ] **Step 1:** Failing tests: AppArmor-confined wipe destroys all protected state, reseed from genesis, zero-residual verification, signed denial honored; delete cascades (events, artifacts, runs) with verification; prune beyond retention with `prune_log`; crash safety via checkpoints; every verb requires the ADR 0032 `grant`.
  - Artifact body removal (ported from `internal/destructive/prune.go` + `prune_test.go`) follows the ADR 0005 order: metadata commit, then body delete, then tombstone.
  - Each body is re-proved (`ReproveBody`: still eligible, same workspace/object key/staging generation) immediately before deletion.
  - On resume, a body that already has a tombstone is skipped (`HasTombstone`), so a re-executed batch never double-deletes.
  - The `PruneJournal` port writes `prune_log` rows, `artifact_tombstones`, and the artifact metadata transition as `central_migration` in one transaction per body.
  - It reuses the R2 `central-artifact` tombstone domain type (`ArtifactTombstone`) and `ObjectStore::remove_ready_for_delete`; it never calls the object store or writes `artifact_tombstones` directly from the helper.
  - Sealed backup trees get no artifact tombstone, as upstream does.
- [ ] **Step 2:** Implement; PASS → commit `feat(infra): add wipe/reseed and delete/prune operations`.

### Task 12: Export / `bx1` fresh-host import (D02/D03, D1)

**Files:** Create `central-infra/src/portable.rs`, helper `{export,import}.rs`.

**Reference:** `internal/portable/bundle.go`, helper `{export,import}.go`, `cmd/central/{export_*,import_*}.go` + tests; ADR 0034.

- [ ] **Step 1:** Failing tests: encrypted bundle (AES-256-GCM, exact layout), independent `bx1` token, import verifies token → decrypts → bootstraps → imported state equals export; tampered bundle/token rejected.
- [ ] **Step 2:** Implement with `aes-gcm =0.11.1` (added to `[workspace.dependencies]` and `central-adapter-linux` only), `tar =0.4.46` + `flate2 =1.1.10` from R5, and `central_foundation::jcs`. Keys and nonces stay in `zeroize`d buffers. Bundle layout, nonce construction, and AAD must match the upstream `bundle.go` fixtures byte-for-byte. Then run `cargo deny check`; PASS → commit `feat(infra): add portable export and bx1 fresh-host import`.

### Task 13: Protected-state audit (D05) + advisory rescue (D06) + security update

**Files:** Create `central-infra/src/rescue.rs`, helper `{maintenance,rescue,security_update}.rs`.

**Reference:** helper `{maintenance,maintenance_apply,rescue,security_update,audit}.go`, `cmd/central/{maintenance_*,rescue_*,security_update_*,audit_*}.go` + tests.

- [ ] **Step 1:** Failing tests: integrity audit detects tampering, authorized repair via reseed, signed audit events; hard-expired advisory rescue with deny-safe cleanup and fresh B01 evaluation.
- [ ] **Step 2:** Implement; flip remaining R5 denials; PASS → commit `feat(infra): add protected-state audit, advisory rescue, and security update`.

### Task 14: D07 acceptance (ADR 0033 Docker evidence profile, D3)

- [ ] **Step 1:** Port the D07 suite covering D01–D06; run under the agreed tiers; record evidence.
- [ ] **Step 2:** Commit `test(infra): add Slice D acceptance`.

## Milestone D — Slice E: dependency maintenance & Phase 1 exit

### Task 15: Maintenance (E01–E04) + `central-advisory-sign`

**Files:** Create `central-infra/src/maintenance.rs`, `bins/central/src/maintenance_cli.rs`, `bins/central-advisory-sign/src/main.rs`.

**Reference:** `internal/maintenance/*`, `internal/advisory/*`, `cmd/central-advisory-sign/main.go`, `cmd/central/advisory_evaluator_composition.go` + tests; `docs/operations/{maintenance-runbook,release-authority-custody}.md`.

- [ ] **Step 1:** Failing tests: directional compatibility matrix rejects unlisted transitions (E01); patch with resume + post-patch verification (E02); rollback with out-of-place fallback and exact evidence (E03); advisory lifecycle conformance against external fixtures (E04); `central-advisory-sign` produces bundles the R5 consumer verifies (offline, no network).
- [ ] **Step 2:** Implement (signature payloads canonicalized with `central_foundation::jcs` from R5); PASS → commit `feat(infra): add dependency maintenance and offline advisory signing`.

### Task 16: E05/E06 Phase 1 full exit + R6/R-sequence closeout

**Files:** Modify `docs/implementation/current-phase.md`, `docs/implementation/rust-vertical-slice-roadmap.md` (status), runbooks only if behavior differs.

- [ ] **Step 1:** Check E05 runbooks (`maintenance-runbook.md`, `local-backup-and-restore.md`, `install-acceptance.md`) match the Rust CLI exactly; fix drift.
- [ ] **Step 2:** Run E06: compatibility, recovery, security-sentinel, minimum-profile performance/resource suites on the agreed tiers.
- [ ] **Step 3:** Full pipeline: `cargo sqlx prepare --check --workspace -- --all-targets && cargo fmt --all -- --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo deny check && cargo test --workspace`
- [ ] **Step 4:** Mark R6 Complete and the `R0`–`R6` sequence complete → commit `docs(phase-r6): mark Phase R6 and the R-slice sequence complete`.

---

## Self-review notes

- **Roadmap §9 coverage:** migrate CLI + reset (T1–T2); Slice C C01–C06 (T3–T10); Slice D D01–D07 (T11–T14); Slice E E01–E06 (T15–T16); `b25`–`b29` (T4); both launcher daemons (T2, T6); `central-advisory-sign` (T15).
- **Scale:** ≈50k upstream lines (backup/recovery domains ~11k, broker R6 RPCs ~20k, backup adapter ~5k, cmd composition ~10k, C daemons ~2k).
- **Cross-plan dependency:** JCS (`central_foundation::jcs`, R5 Task 2 Step 0, R5 D6) and archive crates (R5 D7) must land in R5 before Tasks 11, 12, and 15 here.
