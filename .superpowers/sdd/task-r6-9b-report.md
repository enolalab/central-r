# R6 Task 9b — Restore Engine, Composition, Binary, Operator Path (C03–C05)

## Commits (ordered, on `r6-backup-restore-maintenance`, base `1c6f6e7`)

1. `85396aa` — adapter-linux: expose RestoreTicketIssuer and BrokerAuthorityReset on broker Service
2. `2d7a5b6` — adapter-linux: production restore engine launcher and daemon restore verb wiring
3. `a7f3014` — central-kernel: production restore engine composition over fixed descriptors
4. `c281f42` — central-restore: fixed-descriptor engine binary over launch gate and opaque identities
5. `2804ca0` — central: restore verify|apply|resume|abandon operator dispatch
6. `3bc9682` — central-restore, central-kernel, central: gated restore e2e and invocation/engine semantics

## Scope delivered

- Broker `RestoreTicketIssuer` + `BrokerAuthorityReset` served on the
  broker `Service`; journal ticket read/resolve promoted for the root
  engine (`pub(crate)` in `recovery_journal.rs`).
- `helper/restore_launcher.rs` — capacity allocate → PID/executable/
  start-time binding → FD-9 pipe-gate release → reserve sweep release
  on failure/termination; daemon restore-verb wiring + allocator and
  client callers (`helper/daemon.rs`, `helper/restore.rs`,
  `helper/mod.rs`, `broker/restore_capacity`).
- `central-kernel/src/restore_compose.rs` — `new_production_restore_engine`
  over inherited FDs 3–10: protected journal/state, read-only repository
  + seal verifier + ticket issuer, admission inspector, C04 target
  excluder + FK-dropping `pg_restore` runner, audit projection, restored-
  inventory verifier, C05 broker+database authority reset, reserve binder,
  `UnavailableRestoreImporter` (import fails closed). `ComposedRestoreEngine`
  exposes `verify|apply|resume|import`; IDs from argv only select
  protected records — full ticket/authorization values are read in-process
  and must bind the same operation.
- `bins/central-restore` — real engine binary: blocks on the launch gate
  first (release byte `0x01` + 16-byte reserve-set UUID, FD 9), adopts
  fixed descriptors (broker root 3, RO repository 4, capacity roles 5–8,
  staging 10 import-only), exact argv grammar only
  (`verify <uuid>`/`apply|resume <uuid> <uuid>`/`import <uuid>`),
  UUIDv7-canonical, duplicate-identity rejection, stdout = bounded
  `central.restore-engine-receipt/v1` JSON with the closed refusal
  vocabulary only — no HMAC/nonce/paths/DSN/credentials.
- `bins/central/src/restore_cli.rs` + dispatch arm —
  `central restore verify|apply|resume|abandon` over the helper socket
  with upstream envelopes/exit classes.

## Changed files (29, +6387/-53)

New: `bins/central-restore/src/sys.rs`,
`bins/central/src/restore_cli.rs`, `bins/central/tests/restore_e2e.rs`,
`crates/adapters/central-adapter-linux/src/helper/restore_launcher.rs`,
`crates/central-kernel/src/restore_compose.rs`.

Modified: `bins/central-restore/{Cargo.toml,src/main.rs}`,
`bins/central/src/main.rs`, `Cargo.lock`,
`central-adapter-linux`: `backup/{mod,restore_admission}.rs`,
`broker/{recovery_authority,recovery_journal,restore_capacity/mod,restore_credential,server}.rs`,
`helper/{daemon,mod,restore}.rs`, `sys/audited.rs`;
`central-adapter-postgres`: `backup/{restore_admission,target_exclusion}.rs`,
`migrate/{grants,mod}.rs`, `recovery/{restored_inventory,store}.rs`,
`store_support.rs`; `central-backup/src/app.rs`;
`central-kernel/src/lib.rs`.

## Verification (this machine)

- `cargo fmt --all -- --check` — clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean.
- `cargo check --workspace` — clean.
- `cargo deny check` — advisories, bans, licenses, sources all ok.
- `cargo test --workspace` with `CENTRAL_TEST_DSN=postgres://postgres:central@127.0.0.1:55432/postgres`
  (container `central-rust-pg`, PG 16.15): **3024 passed, 0 failed** across
  98 test binaries, incl. `phase2_acceptance` 3/3 (50.8 s).
- `central-restore` bin unit tests: 10/10 — grammar rejection, launch-gate,
  identity forwarding, substitution rejection, refusal classification,
  fail-closed composition.
- `bins/central/tests/restore_e2e.rs`: 2 tests ran → self-skipped
  (helper socket + MinIO gates unset on this host); honest skip, not pass.
- Note: an earlier run without `CENTRAL_TEST_DSN` failed closed at
  `phase2_recovery_matrix` by design; a flaky
  `claudecode::input_with_large_numbers_is_bridged` failed once and
  passed on isolated + full rerun — unrelated to this slice.

## Live vs deferred (≤8 lines)

1. Live: broker ticket issuance + C05 authority reset on the real Service.
2. Live: helper restore verbs → capacity reserve → launch-gated engine.
3. Live: kernel composition over FDs 3–10; C04 exclusion + destructive restore; reserve sweep release.
4. Live: `central-restore` binary (gate-first, opaque UUIDv7 argv, sanitized receipts); `central restore *` dispatch.
5. Deferred: physical C03–C05 e2e — needs helper daemon + MinIO + TTY ceremony (e2e gates self-skip).
6. Deferred: `import` — `UnavailableRestoreImporter` fails closed; C06 restart/quarantine battery not ported.
7. Deferred: deployment of `central-restore` at `/usr/lib/central/` + broker socket provisioning.
8. Deferred: `backup export|import|delete|prune`, `maintenance *` — out of T9b scope.
