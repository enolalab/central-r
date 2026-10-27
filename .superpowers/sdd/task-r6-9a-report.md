# R6 Task 9a — Sealed-Backup Operator Path (C01 create, C03 verify/status)

## Scope delivered

- `central-kernel::backup_compose` — production worker compositions for
  `central-backup create` (C01) and `central-backup throughput-probe`,
  ported upstream-verbatim with exact refusal vocabulary.
- `bins/central-backup` — the real fixed-descriptor worker binary:
  argv grammar (`create <uuid>` / `throughput-probe <uuid-v7>`), FD 3
  16-byte launch evidence (consumed + closed), FD 4 repository root
  (`FD_CLOEXEC` + directory-shaped), FD 5 CBW1 monitor channel adopted
  before any subprocess; every failure prints only
  `central-backup: BACKUP_WORKER_FAILED` and exits 6.
- `bins/central/src/backup_cli.rs` — `central backup create|verify|status`
  dispatched through the helper socket, upstream-exact envelopes,
  exit classes, safe_next_action, and reason folding
  (`helper::backup::BackupCreateClient` added; `BackupOperatorClient`
  was already landed).
- Supporting adapters: broker worker clients
  (`BackupWorkerJournal`/`Sealer`/`ThroughputWorkerAuthority`),
  Linux target-lock retainer + CBW1 FD5 handoff, PostgreSQL session-port
  target exclusion with retained state (`Arc`-shared lease), sealed
  passfile reader.

## Test counts (this machine)

- `central-backup` bin unit tests: 5 passed.
- `central` bin unit tests: 139 passed (incl. 4 stub-socket e2e in
  `backup_cli` and the updated command census).
- `central-adapter-linux` filtered backup helper tests: 5 passed;
  earlier full filtered run: 260 passed, plus retainer 8, worker
  clients 6.
- `central-kernel` `backup_compose` tests: 3 passed.
- `bins/central/tests/backup_e2e.rs` (C01+C03): 1 ran, **skipped** —
  `CENTRAL_TEST_DSN`/`CENTRAL_TEST_MINIO_*`/`CENTRAL_TEST_HELPER_SOCKET`
  unset on this host; honest skip, not a pass.
- `cargo clippy` on touched crates: clean. `cargo fmt --all`: applied.

## Infrastructure availability

No PostgreSQL DSN, MinIO endpoint, running helper daemon, launcher
socket, or broker on this host — the gated e2e skipped with the
prerequisite list printed.

## T9b must provide (≤8 lines)

1. Helper-daemon composition wiring `BackupCreateHandler` with the real
   throughput gate (upstream `newProductionBackupThroughputGate` has no
   caller — C01 cannot seal until it exists).
2. The CBL1 launcher socket + `central-backup` binary deployment at
   `/usr/lib/central/central-backup`.
3. Broker serving `backup_issue_launch`/`seal_for_launch`/
   `complete_attested_seal`/`verify_seal`/`read_status` verbs.
4. PAM/deny-safe ceremony authorities for the helper peer gate.
5. Restore-side verbs (`restore verify|apply|resume|abandon`) and the
   producer-side backup wiring — explicitly out of T9a scope.
6. `backup export|import|delete|prune`, `maintenance *` remain deferred.
