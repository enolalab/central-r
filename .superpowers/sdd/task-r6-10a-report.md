# R6 Task 10a — C06 Recovery Acceptance: Ceremony Driver + Slice-C Acceptance Core

## Scope delivered

New integration target `bins/central/tests/c06_acceptance/` — the Rust port
of upstream `cmd/central/c06_ceremony_driver_test.go` +
`c06_slice_c_acceptance_test.go` plus the portable `internal/recovery`
machine they exercise (catalogue, runner, fingerprint, evidence, profile).

- `catalogue.rs` — the installed C06 catalogue (C01–C05 packets, scenario
  and restart-injection kinds, `packet_list`/`by_subject` attribution,
  precondition bits, SC-G3 requirement) with the upstream digest rule
  (SHA-256 over `id\tkind\trequired` lines) and ordering/uniqueness
  validation.
- `runner.rs` — arming (`CENTRAL_C06_REFERENCE_HOST`, armed iff present,
  non-empty, non-`0`), `run`/`skip`/`admit` with exactly-one-outcome
  recording, panic-as-failure via `catch_unwind`, skip census from the
  closed `ReasonClass` vocabulary, and `reconcile` with upstream's
  fail-if-unaccounted message shape (E-1: required skips are gate
  failures). `await_completeness` + `recorded` condvar reproduce
  upstream's `TestMain`-after-`m.Run()` ordering under libtest's parallel
  execution; bound env-overridable via
  `CENTRAL_C06_COMPLETENESS_WAIT_SECS` (default 120s).
- `fingerprint.rs` — state fingerprints (tables/artifacts/schema objects):
  corpus liveness, digest shape, streamed-body floor, schema-coverage
  refusals, divergence comparison with bounded reports, content-only
  exemptions.
- `evidence.rs` — the `central.slice-c-recovery-acceptance/v1` emitter:
  schema/packet constants, all five measurement fields + installed bounds,
  scenario results restricted to pass/fail, skip census emission,
  transcript registration + `verify_transcripts` checksum check,
  dependency-lock digesting, worktree-clean refusal (E-5), and the
  prohibition scan (absolute paths, DSNs, plaintext phrases, blobs).
- `profile.rs` — minimum-profile capacity + throughput differentials:
  `check_backup_admission` driven against real device snapshots from the
  production capacity source; refusal pinned to `CAPACITY_INSUFFICIENT`
  (free space) and the throughput receipt rate (not a generic refusal);
  synthetic receipts only as the differential control, as upstream does.
- `fixture.rs` — env vocabulary (`CENTRAL_C06_*`), evidence directory
  resolution (`target/c06-evidence`, never the worktree), privilege
  census, PAM/AppArmor/build-tag facts, physical-TTY class vocabulary,
  synthetic body/reader, record set.
- `ceremony.rs` — the shared ceremony driver: device predicate pinned to
  `sys::tty::open_physical_tty` (`/dev/tty*` required, `/dev/pts/`
  rejected), descriptor probe via rustix safe wrappers + production
  `lock_tty_exclusive`/`read_ceremony_line` (no `unsafe` — forbidden
  workspace-wide), phrase digests only (governance 3.1), ceremony plan
  validation, child-process driver over the real console file + helper
  socket (`SO_PEERCRED` identity untouched), armed environment fitness
  check.
- `slice_c.rs` — the slice-C core: `require_reference_host` gate, armed
  probe, `c06_s1/s9/s10` live entries (armed: run or skip-recorded; the
  runner then fails the test as E-1 gate failures on a non-reference
  host), `zz_reconcile_the_run`, `zz_emit_the_evidence` (emit goes
  through reconcile; armed emission failure is a test failure).

`bins/central/Cargo.toml`: `[[test]] name = "c06_acceptance"`, dev-deps
`central-backup` (production capacity/admission) and `rustix` features
`pty`/`termios` (probe vocabulary). `Cargo.lock`: only the new path edge.

## Test counts (this machine, uid 1000, no console/PG/MinIO)

- `cargo test -p central --test c06_acceptance` — **46 passed, 0 failed**
  (unarmed; prints the loud "NOT C06 evidence"-class notice on stderr).
- Armed probe run (`CENTRAL_C06_REFERENCE_HOST=1`): **40 passed, 6
  failed** — the honest failure set: `c06.s1/s9/s10` skipped-as-gate-
  failures (E-1, `reason_class=not_root`), `zz_reconcile` naming all 17
  unaccounted catalogue entries with packet/kind attribution,
  `zz_emit_the_evidence` refused (emit goes through reconcile),
  `the_ceremony_environment_is_fit_to_drive_the_ceremony` (fd 0 →
  `/dev/null`, not a physical console). Nothing faked, nothing silent.
- `cargo fmt --all -- --check` — clean. `cargo clippy --workspace
  --all-targets --all-features -- -D warnings` — clean.
  `cargo deny check` — clean. `.sqlx` untouched (no queries added).

## Evidence path

Armed runs emit `slice-c-recovery-acceptance.json` +
`*.transcript.txt` under `CENTRAL_C06_EVIDENCE_DIR` or default
`target/c06-evidence/` — outside the worktree so evidence bytes cannot
trip E-5. This unprivileged run emitted nothing (no evidence claim).

## T10b must provide (≤8 lines)

1. Port `c06_scenario{2,34,5,6,78}_*_test.go` + `c06_continuous_run_test.go`
   bodies against `runner.run`/`skip` + `drive_ceremony` — already shared.
2. `RecordSet`/`EvidenceInputs` assembly per scenario (transcripts must be
   registered + checksummed before emit).
3. Reference-host runbook: raise `CENTRAL_C06_COMPLETENESS_WAIT_SECS` to the
   longest live scenario (default 120s is a slice-A bound).
4. Wire `PG_DSN_ENV`/`S3_ENDPOINT_ENV`/`CEREMONY_DEVICE_ENV`/
   `OPERATOR_SECRET_ENV`/`GRANT_CEREMONY_ENV` consumers (declared, unused).
5. PAM/cgo build-fact mapping: record `pam`/`cgo` facts via
   `fixture::build_tags` — the upstream `//go:build` tags do not exist
   here; the runtime census carries them.
6. `c06CGOEnabled` analogue and the PAM-stack live checks stay armed-only.
