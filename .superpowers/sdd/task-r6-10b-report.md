# R6 Task 10 slice B — C06 scenario bodies 2, 3/4, 5 (progress report)

Status: scenarios 2 and 3/4 landed and verified; scenario 5 NOT yet ported
(upstream body is 3097 lines and needs the PAM/physical-TTY ceremony, the
apply-authorization handler, quarantine barriers and no-partial-serving — a
faithful port exceeds the remaining budget of this thread; see handoff).

## Commits

- `f1ad1fc` — test(r6): C06 scenario 2 — corruption injection + detection
- `922bac5` — test(r6): C06 scenarios 3+4 — verify resolver battery + ticket
  one-use lifecycle (task 10b)

## What landed

- `bins/central/tests/c06_acceptance/scenario2.rs` — the six-case corruption
  plan over real PostgreSQL + MinIO through `RestoredInventoryVerifier` /
  `S3BackupObjectSource`, all five quarantine reasons, repair after every
  detection, both fingerprints.
- `bins/central/tests/c06_acceptance/scenario34.rs` — registered as
  `mod scenario34` in `mod.rs`; `c06_s3_restore_verify` and
  `c06_s4_restore_ticket_one_use` dispatched through `slice_c::scenario`
  with `unmet_precondition`/`missing_live_env` gating and per-scenario scope
  disclosures attached to every expectation (`expect3`/`expect4`).
- Portable entry points (upstream `c06WorkstationNarrator` position):
  `c06_s34_portable_verify_resolution_battery`,
  `c06_s34_portable_ticket_battery` — run the same batteries on any host.

## Verification actually run

- `cargo check -p central --test c06_acceptance` — clean.
- `cargo clippy -p central --test c06_acceptance` — clean, no warnings.
- `cargo test -p central --test c06_acceptance` — **53 passed, 0 failed**
  (unarmed; scenario bodies return before the armed gate, portable batteries
  execute). The two portable batteries exercise a real `Service` +
  `RecoveryJournalStore` and pass.
- Armed run: NOT attempted — this host is not the reference host (non-root,
  no pinned toolchain env). Honest gate outcome only.

## Adaptations disclosed in-code (scenario34.rs header)

1. Operator surface = the production handler seam the helper installs
   (`ResolvingRestoreOperationHandler`, `RestoreVerifyHandlerImpl`), called
   in-process; the AF_UNIX transport hop is not exercised.
2. Live sources are test-local impls of the public
   `RestoreLiveOperationSource`/`RestoreLiveTicketSource` traits over the
   real journal, because `BrokerRestoreBarrierOperations` is `pub(crate)`.
3. Protected-state edits identify records by content (PascalCase wire
   members `TicketID`/`OperationID`/`Phase`/`LastCheckpoint`), guarded by
   exactly-one-match + journal read-back checks.
4. Pinned pg_restore version measured off the host for the live entry;
   `16.14` literal only for the portable entry, as upstream.

## Remaining for T10c / next thread

1. Port `c06_scenario5_apply_test.go` (3097 lines) → `scenario5.rs`:
   `RestoreApplyAuthorizationHandler` (pam + issuer + engine ports), the
   PAM/physical-TTY ceremony via `pam_ceremony`/`tty_ceremony`, quarantine
   domain (`central_backup::recovery::quarantine`), no-partial-serving,
   bootstrap/restart boundaries; commit separately.
2. Scenarios 6, 7/8 and the continuous run remain (T10c scope).
3. Shared `RecordSet` still initializes at emission time in `zz_emit_evidence`
   — scenario records must be persisted into emitted evidence.
4. Re-run armed suite on the reference host when available; final report.

## T10c handoff (≤6 lines)

Scenarios 6, 7/8 and the continuous run remain; scenario 5 (apply +
quarantine ceremony) is the immediate gap — 3097 upstream lines, no port
started. `zz_emit_evidence` still emits a fresh `RecordSet`; wire the shared
set before final evidence. Armed run never attempted here.
