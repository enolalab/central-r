# R6 Task 16 — E05 runbook verification + E06 phase-1 acceptance + R6 closeout

Branch: `r6-backup-restore-maintenance`. Commits: `e8404a5` (tests), `e2930c6` (closeout), plus this report.

## E05 — `tests/e05_runbook` (upstream `cmd/central/e05_runbook_test.go`)

- `e05_runbook_commands_parse`: extracts fenced `central …` lines from `docs/operations/maintenance-runbook.md` (byte-identical to upstream — verified by `diff -q`), substitutes `<attempt-id>` → `018f4f3a-…`, and spawns `env!("CARGO_BIN_EXE_central")` with the runbook argv minus argv0. Upstream drove `command.Dispatch` in-process with nil clients (every command answered `MAINTENANCE_SERVICE_UNAVAILABLE`); the Rust binary has no nil-client seam, so `CENTRAL_HELPER_SOCKET` is pinned to a guaranteed-absent path — the deterministic dial refusal (`MAINTENANCE_PLAN_FAILED`/`MAINTENANCE_APPLY_FAILED`, exit 3) is the same "parses, then refuses pre-mutation" shape. `t.Chdir(t.TempDir())` → per-spawn `current_dir` on a cleaned tempdir (a refused apply still writes `slice-e-patch-apply.json`). Root runs skip: upstream's verified surface (`Dispatch`) never carried `main()`'s privilege gate, which refuses root on the Deferred mode — same `non_root` precedent as `main.rs`'s dispatch tests.
- `e05_runbook_reason_tokens_exist`: the `\b(MAINTENANCE_[A-Z_]+|INVALID_MAINTENANCE_GRAMMAR|AUTHORITY_DENIED|DENY_SAFE_ACTIVE)\b` regex re-expressed as a word-split (no regex dep), each documented token asserted as a `"…"` quoted literal across `crates/` + `bins/` — upstream's `internal/{maintenance,command,adapter/authority/helper,cli}` roots.
- One token was genuinely absent: upstream's nil-client `MAINTENANCE_SERVICE_UNAVAILABLE` arm has no Rust equivalent (the client is always constructed; absent helper = dial failure, the lifecycle port's identical `LIFECYCLE_SERVICE_UNAVAILABLE` fold). Documented at both client-construction sites in `maintenance_cli.rs` with the token quoted — the literal now exists and the divergence is on record.
- Evidence: `CENTRAL_E05_EVIDENCE_DIR` → `slice-e-runbooks-verification.json`; `schema_version`/`runbook`/`commands` in Go struct-declaration order (a typed struct — `json!` maps sort keys), command rows keep the Go `map[string]any` alphabetical order.

## E06 — `tests/e06_acceptance` (upstream `cmd/central/e06_acceptance_test.go`)

- The Slice-E authority cycle on real components: `m::new_store` + `MaintenanceApplyHandlerImpl` (store/probes/`images: None`/stub `MaintenanceApplyPamConfirmer`/`CeremonyScope{inst, pg}`) + `broker::journal::Journal`, `PeerIdentity{1000,1000,77}` for `unix.Ucred`.
- All six machine criteria ported verbatim: `postgresql=99` → `MAINTENANCE_TRANSITION_UNLISTED`; patch `16.14→16.15` seq 2; rollback to `16.14` seq 3 (`rollback_applied`); crash-window `patch_pending` (v4 id) abandoned; advisory `current` + `hard_expired` through `Verifier::for_testing` + `AdvisoryTransitionRecorder` over a direct `Journal` writer (the e04 seam); prior-acceptance index.
- Criterion 6 indexes `docs/internal/evidence/phase-2-recovery-matrix.json` — the one acceptance artifact this tree commits; upstream's SD/SC-G3 verdicts stay authoritative in the upstream repo per current-phase.md's baseline note, so the criterion name/tier are verbatim and the detail records what was actually indexed.
- The five `deferred-physical` rows keep upstream names, tiers, and details byte-exact.
- Evidence: `CENTRAL_E06_EVIDENCE_DIR` → `slice-e-full-phase1-acceptance.json`; `candidate_commit` from `GITHUB_SHA`; `matrix_sequence` 3 with the canonical digest.

## Closeout

- `docs/implementation/current-phase.md`: R6 → Completed (13-bullet entry matching the R5 format), intro flipped to "sequence complete", remaining-sequence table updated.

## Checks run

`cargo test -p central --test e05_runbook` (2/2), `--test e06_acceptance` (1/1), `cargo test -p central --bin central` (154/154), `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo deny check` — all clean. `CENTRAL_TEST_DSN`/helper-gated e2e suites (`backup_e2e`, `restore_e2e`, c06/d07 live tiers) skipped as designed — env unset.

## Carried/deferred

- E05 root-run skip (documented): the subprocess path cannot reach upstream's gate-free Dispatch surface under the privilege gate.
- `MAINTENANCE_SERVICE_UNAVAILABLE` unreachable-arm divergence — documented, no behavior gap: upstream's nil client is only reachable when composition is skipped (tests), and the real binary always wires it.
- Physical-tier criteria stay `deferred-physical` — maintainer reference-host runs upgrade them (upstream-identical).
