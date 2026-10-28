# R6 Task 15 Slice A — Advisory Signing Tool, E04 Lifecycle Suite, B01 Evaluator Wiring

## Commits (ordered, on `r6-backup-restore-maintenance`, base `844fe6e`)

1. `6daf6d4` — `bins/central-advisory-sign`: offline signing tool (`genkey`/`bundle`/`verify`) + Cargo deps
2. `ac6627d` — `central-adapter-linux`: `config_binding` on `ProductionInstanceComposition`; shared `HelperAdvisoryEvaluator` wired into prepare/wipe/delete/prune slots and the lifecycle evaluator seam
3. `d61d010` — `bins/central/tests/e04_advisory`: E04 advisory lifecycle conformance suite + `[[test]]` registration + dev-dep
4. (this file) — task report

## Upstream mapping

| Upstream | Rust |
|---|---|
| `cmd/central-advisory-sign/main.go` | `bins/central-advisory-sign/src/main.rs` |
| `cmd/central/e04_advisory_lifecycle_test.go` | `bins/central/tests/e04_advisory/mod.rs` |
| `cmd/central/advisory_evaluator_composition.go` + `main.go`'s `newHelperAdvisoryEvaluator` | `crates/adapters/central-adapter-linux/src/helper/daemon.rs` (`helper_advisory_evaluator`, `HelperAdvisoryEvaluator` trait impls) |
| `productionInstanceComposition.configBinding` | `broker/daemon.rs` `ProductionInstanceComposition::config_binding` |

## Scope delivered

### `central-advisory-sign` (offline; no network/db/protected state)

- `genkey` — one Ed25519 keypair; JSON with `key_id`
  `central-release-authority/v2`, `public_key_base64`,
  `private_key_base64`, `release_authority_digest_sha256`.
- `bundle` — required `--out`, `--key` (`-` = stdin), `--issued-at`,
  `--expires-at`, compatibility flags; trims + standard-base64-decodes
  the private key, requires exactly 64 bytes; marshals the
  `signedBundle` shape, canonicalizes via `central_foundation::jcs`
  (the same implementation `Verifier::verify_snapshot` runs), SHA-256
  digests, signs `central.security-advisory/v1|bundle|SHA-256:<hex>`,
  base64-encodes the signature, writes `{bundle, signature}` at mode
  `0600`, prints the stderr summary (path, digest, key id, issued,
  expiry).
- `verify` — `--bundle` envelope → `Verifier::production()` (compiled
  release trust root); refuses every non-`Current` outcome including
  expired and future-issued bundles; prints
  `VALID key_id=... issued=... expires=... digest=...`.
- Go flag grammar replicated (`-flag`/`-flag=v`, `Usage of`/`PrintDefaults`
  output) so operator runbooks transfer verbatim. 5 unit tests
  (grammar, base64, key length, required flags, sign→verify round trip
  under a matching trust).

### Composition wiring (upstream `newHelperAdvisoryEvaluator` parity)

- `ProductionInstanceComposition.config_binding` = `sha256:<hex>` of the
  exact protected `config.json` bytes the authority reads; never accepted
  from a request. Consumed by `PrepareConfirmationSource`. All literal
  construction sites fixed (`helper/minio_provision.rs` test,
  `broker/daemon.rs` tests).
- `HelperAdvisoryEvaluator` — already the shared audit/rescue evaluator —
  now implements all five narrow evaluator traits:
  `infra::lifecycle::AdvisoryEvaluator`, `prepare::EvaluateService`,
  `wipe::WipeAdvisoryEvaluator`, `delete::DeleteAdvisoryEvaluator`,
  `prune::PruneAdvisoryEvaluator`. Every slot takes the same resolution;
  upstream's rule: a second resolution is a second place a deny-only
  default could be swapped for something more permissive.
- Production `EvaluationService` is composed inside
  `helper_advisory_evaluator` (active-bundle source on the authoritative
  state root + instance id, host-facts collector, time-witness store,
  system clock, broker-backed transition recorder, compiled production
  verifier). A composition failure yields the `service: None` arm —
  upstream's `unavailableLifecycleEvaluator{}` — which answers
  `B01 lifecycle admission evaluator is unavailable` verbatim through
  every surface instead of taking unrelated helper verbs down.
- The three per-file `DenyOnlyAdvisoryEvaluator` stubs (wipe/delete/
  prune) were removed — orphaned duplicate fallback sites.
- Lifecycle itself remains uncomposed on purpose: `new_production_service`
  still needs the B02 active-receipt reader, OCI receipt inspector,
  `ComposeRunner`, typed B04 broker authority, MinIO rendezvous, and
  dead-owner verifier; a partial install would fabricate success. The
  evaluator seam it needs is now landed.

## INTENTIONAL BEHAVIOR CHANGE — paths that moved from always-denied to potentially `Current`

All of the following previously answered `unavailable`/`lifecycle_admission`
at advisory evaluation via `DenyOnlyAdvisoryEvaluator` (or an empty slot)
and now run live B01 evaluation **before** any ceremony or destructive
effect:

1. **`helper::wipe`** (D01) — advisory evaluation now precedes the PAM
   confirmation and the destructive tree removal; a `Current` outcome
   with a valid receipt admits, every other outcome still refuses.
2. **`helper::delete`** (D02/D03 path) — live evaluation precedes the
   delete ceremony; the still-unavailable `UnavailableDeleteSource` /
   `UnavailableDeleteRefs` seams continue to fail closed *after*
   admission, so delete cannot yet complete end-to-end.
3. **`helper::prune`** (D04) — live evaluation precedes plan/apply; the
   absent prune engine still fails closed after admission.
4. **`helper::prepare`** evaluator slot — the dependency-prepare
   promotion gate re-runs the same evaluation that admitted the request.
5. **`infra::lifecycle::AdvisoryEvaluator` seam** — implementation
   exists on the shared evaluator for when the lifecycle service is
   fully composed (not yet — see above).

Unchanged: `Admission::new` still admits only `Current` + nonempty
receipt; `Denied`/`Stale`/`HardExpired` and the `None` fallback all
still refuse the verb before effects. Audit and rescue were already on
the shared evaluator — untouched. No operation-matrix `Implemented`
flags changed.

### E04 conformance suite

- Ephemeral suite keypair (`central-release-authority/e04-test`) mints
  9 fixtures over the signing tool's exact wire path; consumed only
  through `verify_snapshot` + `evaluate_verified` +
  `AdvisoryTransitionRecorder` against a **real** `broker::journal::Journal`
  (via a thin `AdvisoryJournalWriter` adapter) — not a fake.
- Scenarios: current, stale-grace, host-mismatch, hard-expired,
  emergency-deny, bad-signature, wrong-key, future-issued,
  witness-rollback. All receipts nonempty; sequences strictly increase.
- `CENTRAL_E04_EVIDENCE_DIR` emits `slice-e-advisory-lifecycle.json`
  (schema version, suite key id/pubkey, per-scenario fixture digests,
  expected vs observed state/code/check, receipt ids/sequences) plus
  fixture copies.
- `e04_exclusion_scan` fails if advisory runtime code
  (`central_infra::advisory`, `infra::advisory_fetch` production regions)
  contains `SigningKey`, `ed25519_dalek::Signer`, or `.sign(` outside
  `#[cfg(test)]` — the runtime verifies, it never signs.

## Changed files

- `bins/central-advisory-sign/{Cargo.toml,src/main.rs}`
- `bins/central/{Cargo.toml,tests/e04_advisory/mod.rs}`
- `Cargo.lock` (dependency entries only)
- `crates/adapters/central-adapter-linux/src/broker/daemon.rs`
- `crates/adapters/central-adapter-linux/src/helper/daemon.rs`
- `crates/adapters/central-adapter-linux/src/helper/{wipe,delete,prune}.rs`
- `crates/adapters/central-adapter-linux/src/helper/minio_provision.rs` (test literal)

## Verification (all commands actually run)

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo check -p central-adapter-linux --all-targets` | clean |
| `cargo clippy -p central-advisory-sign -p central-adapter-linux -p central --all-targets` | clean (6 warnings in the new binary fixed) |
| `cargo test -p central-advisory-sign` | 5/5 pass |
| `cargo test -p central-adapter-linux --lib` | 807/807 pass |
| `cargo test -p central --test e04_advisory` | 2/2 pass (conformance + exclusion scan) |
| `CENTRAL_E04_EVIDENCE_DIR=/tmp/e04-evidence cargo test -p central --test e04_advisory` | 2/2 pass; evidence file + 9 fixtures emitted |

- **Known flake, unrelated**: first full lib run showed one failure —
  `broker::restore_capacity::frame::tests::wire_shape_matches_the_frozen_consumer`
  (`broker: recovery journal unavailable` from the `/proc` identity
  race in the spawned-`sleep` restore-launch fixture). Passed in
  isolation and on the full 807-test rerun. Untouched code.
- Root-required platform tests self-skip as non-root (expected).
- `cargo test -p central` other targets not re-run wholesale; touched
  surface is the new e04 target (all `--all-targets` compile clean
  under check+clippy).
