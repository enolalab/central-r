# R6 Task 14 — Slice-D Acceptance Suite (D07)

## Commit (on `r6-backup-restore-maintenance`, base `387e6c2`)

1. `test(infra): add Slice D acceptance` — this task (see `git log`).

## Scope delivered

- `bins/central/tests/d07_acceptance/` — the Rust port of upstream
  `cmd/central`'s `d07_harness_test.go` + `d07_scenarios_test.go`
  (the `d07_buildtag_{pam,nopam}` split collapses: `PamConfirmer::
  with_grants` needs no build tag, so the real grant ceremony runs in
  every tier).
  - `mod.rs` — suite root: `d07_tier()` (`CENTRAL_D07_RUN=1` AND
    euid 0 → production, else fixture), verdict/bundle records
    (`slice-d-acceptance/v1`, evidence profile `docker`),
    `CENTRAL_D07_EVIDENCE_DIR` copies at `0644`, `run_scenario`
    normalization, and the eight-scenario `d07_acceptance` test.
  - `harness.rs` — `d07Env`/`d07StandUp`: fresh `0700` fixture roots
    (instances, protected, runtime, repository, staging, grants,
    socket, work), a bound config built from the committed
    `complete-config.json` (identity + paths substitution, B09 budget
    fill, re-sign, JCS), the real `GrantStore`, all seven production
    handlers on a real `helper::Server` + `UnixListener`, the sealed-
    backup builder through production repository APIs
    (`initialize_repository_binding` → `bind_backup` → `write_dump` →
    `new_seal_root_manifest` → `write_manifest` →
    `BackupSealCompanion` → `verify_backup`), grant issue/consume
    helpers, `rebind_import` (the fixture's model of per-invocation
    composition resolution), and `run` — the spawned `central` binary
    with `CENTRAL_HELPER_SOCKET` and the work dir as cwd so evidence
    lands where upstream's declaration expects it.
  - `seams.rs` — the `d07_*` test doubles: shared advisory dial,
    installed/candidate evaluators, idempotent-cleanup counter, the
    repository-backed checkpoint verifier, and `d07BackupCreate`
    (upstream fakes the in-process client; the port installs the same
    stand-in *server-side*, keeping socket/matrix/peer/gate real).
  - `scenarios.rs` — S1–S8 assertion bodies.
- `[[test]] d07_acceptance` in `bins/central/Cargo.toml`
  (`path = "tests/d07_acceptance/mod.rs"`, the c06 convention).
- `crates/adapters/central-adapter-linux/src/helper/export.rs` —
  `copy_tree` destination-root fix (see "Carried fix" below).

## Tier model

- **Fixture (default `cargo test`, non-root, no docker):** every root
  a fresh fixture tree; all eight scenarios run green.
- **Production (`CENTRAL_D07_RUN=1` + euid 0):** `stand_up` returns
  `None`, matching upstream's unrehearsed
  `d07InstallProductionInstance` (`d07_harness_test.go:444`) — every
  scenario records an honest `skip` verdict rather than pretending
  production coverage exists.

## Verification (this machine)

- `cargo test -p central --test d07_acceptance` — **1 passed**
  (single `d07_acceptance` test driving all eight scenarios;
  S1–S8 verdicts all `pass` in `slice-d-acceptance.json`).
- `CENTRAL_D07_EVIDENCE_DIR=/tmp/d07-evidence` run — bundle plus the
  five declared artifacts (`slice-d-wipe-reseed.json`,
  `slice-d-export.json`, `slice-d-import.json`,
  `slice-d-state-audit.json`, `slice-d-rescue.json`) copied at 0644.
- `cargo test -p central-adapter-linux` — **806 + 26 + 12 + 7 + 13 +
  14 + 5 + 14 passed, 0 failed** (copy_tree regression coverage).
- `cargo fmt --all -- --check` — clean.
- `cargo clippy -p central -p central-adapter-linux --all-targets` —
  clean.

## Carried fix

- `docs/internal/tasks/r6-t14-copytree-missing-dst-root.md` —
  upstream `copyTree`'s `filepath.WalkDir` creates the destination
  root on the `rel="."` root visit; the port iterated children only,
  so `fs::copy` could hit a missing `dst` root depending on readdir
  order. Restored via `fs::create_dir_all(dst)` up front; S3 fails
  before, passes after; all four ADR 0028 §D3 criteria hold.

## Deliberate adaptations / disclosures (≤8 lines)

1. S1 seals via production repository APIs, then asserts wipe+reseed,
   new identity, checkpoint binding, and the one consumed wipe grant.
2. S2's Denied dial blocks before ceremony: `WIPE_DENIED_SIGNED`, no
   grant spent, tree untouched.
3. S3 verifies the token *without* the helper (ed25519+digest), then
   imports onto a D01-freshened instance; fixture honestly reports
   `data_plane_restored=false` — full round-trip is tier-2 only.
4. S4/S5 assert fail-closed `DELETE_UNAVAILABLE`/`PRUNE_UNAVAILABLE`
   (and no plan file) with the D04 engine seams unplumbed.
5. S6 runs genesis→tamper→repair→clean plus the missing-file repair
   refusal; daily-cadence ticker stays OQ-4-deferred.
6. S7 probes the deny-safe gate with `backup delete` (not `local
   wipe`: this port's CLI `backup-create` hop is itself gate-refused
   first) — `DENY_SAFE_ACTIVE` verbatim, grant unspent; rescue then
   records attempts + idempotent cleanup. Tier-2 exit path disclosed.
7. S8 asserts `already_current` no-op and `RESCUE_NOT_APPLICABLE`
   wrong-remedy refusal with zero side effects.
8. All eight share `slice-d-acceptance.json` + per-scenario evidence
   under `CENTRAL_D07_EVIDENCE_DIR`; nothing else tier-2 remains.

## Remaining risks

- The production tier inherits upstream's unrehearsed root install —
  skip, not failure.
- `d07BackupCreate` sits server-side where upstream fakes the client;
  the transport, matrix, peer policy, and gate are all real, and the
  seam is called out in S1's verdict notes.
