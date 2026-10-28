# Plan — Prepare promotion / attestation (post-R6 deferral closure)

Closes the `PREPARE_PROMOTION_UNAVAILABLE` boundary recorded in
`docs/implementation/current-phase.md` and
`crates/adapters/central-adapter-linux/src/infra/prepare/service.rs`
(module doc): the operation journal that makes `--resume` lawful, the
attestation signing that makes a built inventory promotable, and the
`CandidateStore` promotion those two gate. Scope decisions (maintainer):
full journal + attest + promote; signing key sourced as upstream does;
worktree `../central-rust-prepare`, branch `prepare-promotion`, no push
until reviewed.

Upstream references (`$CENTRAL_SRC/internal`):

- `dependencyprepare/app/service.go` (state machine, ~1018 lines), `app/progress.go`
- `dependencyprepare/port/prepare_port.go` (port contracts)
- `authority/domain.go:307-350` (`PrepareOperation`, 13-phase enum)
- `adapter/dependencyprepare/factory_linux.go` (`FileJournal`, `PrepareService`, wiring)
- `adapter/dependencyprepare/attestation*.go` (attestor, signer, key)
- `adapter/dependencyprepare/imageload_linux.go`, `release_{verify,import,export}_linux.go`
- `dependencyprepare/release.go`

Already ported (consumed, not redone): `central_infra::prepare` domain
(lock, attestation facts/predicates, `Candidate`, receipt),
`infra/prepare/{buildkit,capacity,fetch,module_cache,oci (comparator),release_stage,store,version_zero}`,
`helper/prepare.rs` handler + `DependencyPrepareService` trait.

## Tasks

### PP-T1 (DONE) — `PrepareOperation` domain + `FileJournal`
- Domain already present: `central_infra::authority::{PrepareOperation,
  PrepareOperationPhase}` and `central_infra::domain::valid_operation_id`.
- Adapter `infra/prepare/journal.rs`: `FileJournal` — dir 0700, `Record`
  (validate id, default `created_at`, tmp 0600 + fsync + rename + dir fsync),
  `Unsettled`, `Exact` (id validated BEFORE join; record id must equal request id).
- Tests: round trip, deadline/phase fidelity, path-traversal ids refused,
  forged-id mismatch refused, unsettled skips terminal, mode bits.

### PP-T2 (FOLDED INTO PP-T5) — comparator wiring, independent-build + attestation-materials checks
- `validate_independent_builds` and `oci::Comparator` already exist; port only
  `attestation_materials` and `SubjectFromInventory` and wire them.

### PP-T3 (DONE) — attestor: key custody, DSSE signer, verify (SBOM / license / SLSA)
- `infra/prepare/attestation.rs`: `AttestationVerifier`, `AttestationSigner`, `AttestationService` (`Attestor`), `load_attestation_signer` (openat2 NO_MAGICLINKS+NOFOLLOW, regular file, owner-only). Key *generation* (upstream operator tool) is not ported.
### PP-T4 (DONE) — image loader (`Supported`, `Load`, post-load digest validation)
### PP-T5 (DONE) — state machine `PrepareState` (run/settle/resume, progress tracker)
- `infra/prepare/state_machine.rs` (+ `CandidateStore::recover`, deferred since R5). Ports as traits with fakes in tests; `attestation_materials`, `prepared_dependency_set`, `persist_op_artifacts` live here. `prepare_one_from_release` is PP-T6.
### PP-T6 (DONE) — release path: verify, import (`PrepareOneFromRelease`), export
- `infra/prepare/release.rs`: `verify_release`, `reverify_manifest_envelopes`, `ReleaseImportService`, `infra_pin_manifests`; `PrepareState::prepare_one_from_release`. Export: `infra/prepare/export.rs` (`ReleaseExportService`, self-checks through `verify_release` before publishing; shared fixtures in `release_fixture.rs`).
### PP-T7 — factory wiring: replace `PREPARE_PROMOTION_UNAVAILABLE`, real
`resume` and `prepare_export_release` in `infra/prepare/service.rs`
### PP-T8 — closeout: task record, `current-phase.md`, README, dashboard

## Wire/fail-closed rules

- Verification precedes side effects; no success is fabricated for a missing stage.
- Operation ids are validated at every trust boundary (resume arrives from the operator).
- Journal records carry the full fine-grained phase and the deadline; a record
  without a deadline is refused by name, never by expiry.
- Image load only after comparison + attestation re-validation; build one's
  export is the loaded object.
- No weakening of existing gates; no unrelated refactors; no new dependency
  without asking.
