# Task R6-9 — Broken production links: fix report

Branch `r6-backup-restore-maintenance`, starting from `13c5bd3`. The review in
`.superpowers/sdd/review-task-r6-9.diff` found three production seams that
looked wired but were unreachable behind unconditional fail-closed refusals,
plus one under-specified test and one comment-scope question. This report maps
each finding to the commit that resolves it.

## Commits

| Commit | Finding | Subject |
| ------ | ------- | ------- |
| `c77e7c3` | 1, 4, 5 | resolve restore verbs via broker barrier — transport→protected identity |
| `97bedf4` | 2 | production restore/backup MinIO credential provisioner |
| `b7e412c` | 3 | production C02 throughput gate + backup MinIO wiring |

## Finding 1 (HIGH) — restore apply/resume/abandon always denied — `c77e7c3`

Helper transport UUIDs were passed straight to broker issuers, which require
the protected operation identity; every restore operation verb therefore
denied. Ported `cmd/central/restore_resolvers.go` + the barrier client half of
`main.go`:

- `src/broker/restore_barrier.rs` — `RestoreBarrierClient` over the protected
  broker socket (barrier inspection RPC).
- `src/helper/restore_resolvers.rs` — `ResolvingRestoreOperationHandler`, the
  one decorator backing all three verbs: inspect the barrier, resolve the
  single live protected operation (apply via the issued-ticket path,
  resume/abandon via the live-operation path), run the inner handler against
  that protected identity, and rebind the transport ID onto the response
  envelope. Peer-gate ordering and the protected-identity boundary are
  unchanged.
- `src/helper/daemon.rs` — decorator installed in all three verb slots,
  upstream-fashion; barrier-client construction failure exits 6.

## Finding 2 (HIGH) — restore MinIO preparer `None` pre-spawn refusal — `97bedf4`

- `src/helper/minio_provision.rs` — `ProductionRestoreMinioPreparer` +
  `ProductionBackupMinioPreparer`, the `cmd/central/{restore,backup}
  _minio_composition.go` port: canonical instance ID, dependency root +
  active receipt B03 validation, pinned image identity, exact compose model,
  fixed bucket, policy digest, broker payload-epoch + MinIO handoff issuers,
  operation-derived fence and target descriptors, strict provisioner-receipt
  decode. `PrepareBackupThroughputMinio` carries the same identity for C02
  probes (no `BackupID`).
- `src/broker/daemon.rs` — `ProductionInstanceComposition` gains
  `backup_repository_root`, `compose_path`, `object_store_bucket`, and the
  backup/restore/import policy digests, all populated from validated
  configuration.
- `src/helper/restore_launcher.rs` — `new_production` installs
  `minio: Some(ProductionRestoreMinioPreparer::new_production(composition,
  broker_socket)?)`; composition failure propagates like upstream. Import
  stays uncomposed at the upstream nil-check rung.

## Finding 3 (HIGH) — backup-create forced `BACKUP_CREATE_AUTHORIZATION_REQUIRED` — `b7e412c`

`throughput: None` and missing `minio` left upstream's completeness gate
unreachable-by-design. The complete C02 authority chain is now composed:

- `src/helper/pg_wire.rs` — minimal PostgreSQL wire client: startup,
  cleartext/SASL handling, SCRAM-SHA-256 (RFC 7677 vector test), simple
  query, bounded exchange deadlines, terminate-on-drop — the `pgx` role in
  `postgres_superuser_credential.go`'s syncer.
- `src/helper/pg_credentials.rs` — ADR 0019 root-owned superuser store
  (`rotate_for_operation`: durable active/candidate secrets, live-server
  crash recovery, `ALTER ROLE` then promote, passfile rewrite) and the
  ADR 0014 single-use `postgres_server_admin_v1` passfile manager
  (`postgres:5432:*:central:<pw>`, uid/gid 65532, atomic 0400).
- `src/helper/backup_throughput.rs` — the `backup_throughput_*.go` port:
  broker `BackupThroughputAuthority` (accept/current/complete-pending/
  activate/mark-failed/resolve-cleanup) and `BackupThroughputLaunchIssuer`
  (issue/read-state/mark-fixture-loaded) clients; the disposable-database
  fixture provisioner (byte-parity `create_load_v1`/`verify_v1`/`drop_v1`
  binding digests, unconditional passfile cleanup); the MinIO fixture
  manager (`seed_v1`/`verify_v1`/`delete_v1`, strict receipt decode); the
  cleanup census (nil launch ID = nothing launched; current descriptor
  excluded; tmp-file + open-descriptor sweeps); the static binding builder
  (device-mount set, host profile, dependency provisioning, pinned pg_dump
  tool, transfer envelope, `sha256(PinnedBackupConfiguration)` config
  digest); and `ProductionBackupThroughputGate` implementing
  `BackupThroughputGate` with upstream's full ordering — reconcile stale
  attempt, accept, MinIO-prep, bind, launch, commit, wait target_locked,
  postgres create/verify, minio seed/verify, fixture attestation, reap,
  assert retained lock, staged phase, zero-count census, complete-pending,
  release, activate — with the deferred cleanup/mark-failed semantics on
  every failure path.
- `src/helper/daemon.rs` — `ProductionBackupThroughputGate::
  new_production_for_composition` and `ProductionBackupMinioPreparer`
  installed into `BackupCreateHandler::new` (complete constructor);
  composition failure exits 6 like upstream.
- `src/broker/backup_throughput_launch.rs` — `BackupThroughputLaunchStatus`
  gains `Deserialize` with `omitempty`-faithful defaults for the
  read-state RPC.

## Finding 4 (MEDIUM) — generic restore denial vocabulary in e2e — `c77e7c3`

`bins/central/tests/restore_e2e.rs` now distinguishes resolver-chain
outcomes (`RESTORE_NO_LIVE_OPERATION` etc.) from issuer authorization
denial (`RESTORE_*_AUTHORITY_DENIED`), so a broken resolver can no longer
masquerade as a legitimate authority refusal. Both tests pass.

## Finding 5 (LOW) — `UnavailableRestoreImporter` scope — `c77e7c3`

Verified the importer is intentionally unported under D03/T12; its comment
now names T12 explicitly. Import remains uncomposed at the upstream
nil-check rung.

## Verification (all run)

| Command | Result |
| ------- | ------ |
| `cargo test -p central-adapter-linux` | 758 lib + 91 integration = **849 pass, 0 fail** |
| `cargo test -p central-kernel` | 138 lib + 1 integration = **139 pass, 0 fail** |
| `cargo test -p central` | 139 lib + 1 backup_e2e + 3 phase2_acceptance + 2 restore_e2e = **145 pass, 0 fail** |
| `cargo test -p central-backup-bin` | 5 pass |
| `cargo test -p central-backup-launcherd` | 13 pass |
| `cargo test -p central-harness-launcherd` | 0 tests |
| `cargo test -p central-migration-launcherd` | 6 pass |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy -p central-adapter-linux -p central-kernel -p central --all-targets -- -D warnings` | clean |
| `cargo check --workspace` | clean |
| `cargo deny check` | advisories/bans/licenses/sources ok |

`phase2_recovery_matrix` requires `CENTRAL_TEST_DSN` and fails closed without
it (pre-existing gate, unchanged); it was run with the script-default DSN
`postgresql://postgres:central@localhost:55432/postgres` and passed in 87.6s.
Root-required platform tests skip as non-root/off the pinned reference host —
expected, not failures.

## Known limitations

- `ProductionPostgresSuperuserCredentialStore::ensure_first_boot_materialized`
  is complete but `#[allow(dead_code)]` — its only upstream call site is
  `postgresFirstBootBootstrap.Materialize` inside the helper lifecycle
  composition, which this codebase still serves as
  `LIFECYCLE_SERVICE_UNAVAILABLE` (the B01 evaluator seam is deferred with
  the lifecycle verb). Wiring it is a one-line decorator when that
  composition lands.
- The C02 gate runs the real privileged probe: it executes only against a
  fully provisioned reference host, so its end-to-end behavior is exercised
  by the root-required deployment path, not unit tests. Every non-host seam
  (wire shapes, digests, receipts, ordering) is covered by the tests above.
