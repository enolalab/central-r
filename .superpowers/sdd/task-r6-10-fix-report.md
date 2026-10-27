# Task R6-10 — C06 acceptance parity: fix report

Branch `r6-backup-restore-maintenance`, continuing from `eaeb915`. The review
in `.superpowers/sdd/review-task-r6-10.diff` (the ported suite itself) plus the
final review pass produced five fix groups against
`bins/central/tests/c06_acceptance/`. Test-only work; no production surfaces
were invented and every measurement the artifact cannot honestly carry is
emitted as an explicit `null` (not measured), never a zeroed placeholder.

## Commits

| Commit | Fix group | Subject |
| ------ | --------- | ------- |
| `78788a3` | 1 | pin the installed catalogue digest to upstream's recorded literal |
| `4cbe655` | 2 + 3 | sequential driver, durable transcripts, audited double emission, honest measurements |
| `a31f9c4` | 4 + 5 | portable restore/ceremony batteries, s2 ready-key pin, build census |

Groups 2 and 3 share hunks inside `evidence.rs`, `fixture.rs` and
`slice_c.rs` (the emit path both writes the artifact and enforces measurement
honesty), so they landed as one commit rather than as two commits with a
non-compiling intermediate state; each group is enumerated below. Groups 4
and 5 are likewise one commit. `4cbe655` was verified to compile standalone
in a detached worktree (`cargo check -p central --test c06_acceptance`).

## Fix 1 — catalogue digest literal pin — `78788a3`

- `catalogue.rs` — `the_installed_catalogue_digest_is_the_recorded_value`
  asserts the literal
  `02fa72ee32a743ab753dcea089995d8c3aa8fa4c615888ef25f7a62a67042738`
  recomputed over the installed catalogue (upstream
  `catalogue_test.go:145,157`). Neighbour pins cover formula stability,
  order sensitivity, per-field distinctness, and restart-boundary naming.

## Fix 2 — evidence emission, transcript durability, run ordering — `4cbe655`

- `scenario2.rs` — `ScenarioLog` gained `armed` + `Drop`: armed transcripts
  are written via `evidence::write_transcript` (mode 0600) before the log is
  dropped, the returned checksum is verified against the digest attached to
  the runner, ordinary-path failure fails the entry, and unwind-path
  failure is recorded in a registry instead of double-panicking.
  `ScenarioLog::portable` keeps portable batteries off the shared runner.
- `fixture.rs` — `record_transcript_failure` / `take_transcript_failures`
  registry consumed by the emitter.
- `continuous_run.rs` — `DRIVER_SEQUENCE` (19 entries, catalogue order) is
  driven by one armed `#[test]`; a positional guard proves the installed
  catalogue and the driver agree id-for-id. `audit_the_emitted_artifact`
  audits the decoded JSON against the actual `RecordSet`, including
  `protected_journal_recorded`, plus a sound-fixture acceptance test and
  per-mutation refusal tests.
- `slice_c.rs` — `zz_emit_the_evidence`: unarmed return, completeness wait,
  instance-usability probe, transcript-failure refusal, `RecordSet`
  snapshot, `validate_evidence_inputs`, required-skip rejection, double
  emit + byte identity, prohibition scan, JSON decode, audit, write to the
  evidence directory only, mode 0600 set and verified, then
  `verify_transcripts` against the bytes a reviewer would be handed.
- Armed `#[test]`s became `pub(crate) fn`s called by the driver
  (`scenario34.rs`, `scenario5.rs`, `scenario6.rs`, `scenario78.rs`,
  `slice_c.rs`, `scenario2.rs`); portable batteries stay `#[test]`s.
- `runner.rs` — `await_completeness` underpins `zz_emit`/`zz_reconcile`
  waiting on the driver under parallel libtest scheduling.

## Fix 3 — no silent zero/empty measurements — `4cbe655` (same commit)

- `evidence.rs` — `EvidenceInputs`/`Evidence` fields 25
  (`quarantine_resolutions`), 7 (`image_digests`) and 9 (`commands`) are
  `Option`-typed; `None` serializes `null`, validated only when `Some`.
- `fixture.rs` — `quarantine_resolutions_recorded`, `commands_recorded`,
  `capacity_reserve_recorded` flags; `record_command` stores the literal
  command line, env names, exit code, result and output digest;
  `record_quarantine_resolutions` refuses a duplicate census.
- `slice_c.rs` — s1 records the real `central backup create` invocation;
  `measure_image_digests` runs the two-step `docker inspect` (container →
  image ref → RepoDigests) and errors when a named image has no repository
  digest; s9's reserve record is an admission record (`released: false`),
  and the fabricated empty-root sweep record was removed.

## Fix 4 — missing portable batteries — `a31f9c4`

- `ceremony.rs` — `restore apply`/`restore abandon` flag-as-confirmation
  refusal through the real operator subprocess (grammar reason, usage exit,
  no phrase echo, neighbour-verb isolation); grant-driver batteries over a
  real child spawn (`/bin/true` no-envelope + envelope-reported exit);
  ceremony plan validation across invalid verbs, console/stdin shapes,
  budgets, secret, grant mode and quarantine tolerance; scope-disclosure
  guard on every ceremony expectation; performed-ceremony read takes only
  consumed authorizations; authorization directories pinned to the broker's
  own `recovery_journal` constants in both directions (the weak
  source-substring test in `slice_c.rs` was removed).
- `scenario2.rs` — the seeded ready key is held to the adapter's own
  `READY_PREFIX`/`STAGING_PREFIX` constants read from its source.

## Fix 5 — final review items — `a31f9c4` (same commit)

- `slice_c.rs` — `the_build_census_is_compile_presence`: profile carries
  `referencehost`+`pam`, `cgo_enabled == true`, and the adapter's
  `build.rs` is read for `cargo:rustc-link-lib=pam`, so the census is a
  claim about a link the build actually performs.
- Artifact file mode `0600` set and verified post-write
  (`EVIDENCE_FILE_MODE`); `write_transcript` modes transcripts 0600.
- Dead code wired or removed: `drive_ceremony` exercised through a real
  spawn; `rfc3339_now` deleted with the fabricated sweep record.

## Verification

- `cargo test -p central --test c06_acceptance` — 78 passed, 0 failed
  (unarmed; the armed path needs the reference-host environment).
- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p central --test c06_acceptance -- -D warnings` — clean.
- `4cbe655` verified to compile standalone in a detached worktree.
- Armed end-to-end run (reference host, Docker containers,
  `CENTRAL_C06_REFERENCE_HOST`) was not executed here; the driver,
  completeness waits and emission ordering are the same code the unarmed
  suite exercises.

## Remaining risks

- `zz_emit_the_evidence` and `zz_reconcile_the_run` remain separate
  `#[test]`s that wait on the driver via `await_completeness` (default
  120 s, `CENTRAL_C06_COMPLETENESS_WAIT` env-overridable); an armed run on a
  very slow host may need the override.
- Upstream batteries that pin broker reserve-record field names and store
  layout on disk have no Rust equivalent — the port reaches reserve facts
  through typed production APIs; noted rather than fabricated.
- Field-7 image digests emit `null` until `CENTRAL_C06_POSTGRES_CONTAINER` /
  `CENTRAL_C06_MINIO_CONTAINER` name running containers on the reference
  host; a named image without a repository digest fails emission rather
  than silently degrading to not-measured.
