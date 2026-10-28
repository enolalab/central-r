# R6 Task 12 — D02 export + D03 import (report)

Status: the portable `bx1` slice is ported end to end — domain
vocabulary + token crypto in `central-infra::portable`, the chunked
AES-256-GCM / Go-parity tar engine in
`central-adapter-linux::helper::portable`, the `backup.export` and
`backup.import` helper handlers with production daemon composition,
whitelisted wire clients, and the `central backup export|import` CLI
with `slice-d-export.json`/`slice-d-import.json` evidence. All new
tests pass; touched suites are green (798 adapter-linux lib, 248
central-infra, 154 central bin); `cargo fmt`, `cargo clippy`, and
`cargo deny check` are clean.

Commits: `0888cd6` (domain), `226ab09` (portable engine),
`77380e3` (handlers + wiring + CLI), and the follow-up commit on
top (production import-MinIO preparer + engine deadline + this
report).

## What landed

### Domain — `crates/capabilities/central-infra/src/portable.rs`

Upstream `internal/portable`'s closed surface:

- Reason tokens for both verbs (upstream `export.go`/`import.go`
  allowlists verbatim), `EXPORT_PURPOSE`, `TOKEN_EXPIRY_SECONDS`
  (30 days), `CHUNK_SIZE` (1 MiB), `BUNDLE_MAGIC` (`BX1GCM01`),
  `RESTORE_PLAN_FILE_NAME`, `IMPORT_MARKER_FILE_NAME`.
- `ManifestFile`/`ExportManifest`/`RestorePlan`/`ExportEvidence`/
  `ImportEvidence` and the `Bx1Token` wire shape.
- `hkdf_sha256` (RFC 5869 case-1 tested), `derive_bundle_key`
  (info `bx1-dek/v1`), `issue_bx1_token`/`verify_bx1_token` over the
  JCS-canonical unsigned projection — the token binds digest,
  instance, purpose, nonce, timestamps, id, and public key.
- `hex_decode`/`hex_encode`, `b64_url_raw_{en,de}code` (no external
  base64/hex crates), RFC 3339 nano format/parse.

### Portable engine — `helper/portable.rs`

- `encrypt_stream`/`decrypt_stream`: `BX1GCM01` magic + 12-byte base
  nonce, per-segment nonce `base[0..4] || BE64(segment_index)`,
  BE32 ciphertext-length framing, AES-256-GCM per segment.
- `build_tar_gz`: deterministic PAX tar — lexicographic entry order,
  zeroed uid/gid, `0600` files / `0700` dirs, mtime pinned to the
  manifest `created_at`, Go-`archive/tar`-identical devmajor/devminor
  NUL fields (verified byte-for-byte against a Go fixture);
  refuses symlinks/hardlinks/specials and traversal.
- `extract_tar_gz`: rejects absolute paths, `..`, links, devices,
  and mode/ownership escapes.
- `verify_extracted_tree`: `manifest.json` first, every other file
  listed once with exact size + SHA-256; unlisted/missing rejected.
- `load_or_mint_export_identity` (O_EXCL `0600`, ownership +
  public-key consistency checks) and `scan_protected_subset` (trust
  material / secret marker rejection).

### Handlers — `helper/{export,import}.rs`

- `ExportHandlerImpl`: out-dir validation before ceremony, the
  `backup-export` PAM ceremony bound to op id + fixed scope,
  explicit-id or single-candidate sealed-backup resolution,
  `VerifyAndStageBackup`, protected-subset collection + secret scan,
  identity load/mint, deterministic archive, encrypt `O_EXCL` under
  the operator dir, token issuance, ownership handoff, and
  `selfVerifyExport` (nonce re-derivation + full stream auth).
  `RepositoryExportSource` opens the descriptor-bound read-only
  repository and refuses symlinks/specials.
- `ImportHandlerImpl`: absolute-clean regular file + 64-hex trust
  key validation before ceremony, `refuseUnlessFreshTarget`
  (reseed marker required; no grants/ceremony/tls-authority/
  lifecycle/data/dependency/backups beyond the wipe-time triple),
  `backup-import` ceremony, token signature/expiry/purpose/nonce/
  trust-key/digest verification, decrypt+extract+manifest verify,
  protected-state bootstrap (`config.json` rebound through
  `rewrite_config_for_instance`, `imported-tls-certs.json`,
  `imported` lifecycle records, `import.json` marker), restore-plan
  staging under `import-<op>/`, and `central-restore import` through
  the shared `RestoreEngineLauncher` (ADR 0034). A nil engine is
  the honest staging-only composition (`data_plane_restored=false`);
  a bad receipt is an error, never success.

### Wiring

- `helper/mod.rs` registers `export`, `import` modules.
- `helper/server.rs`: `Server::{export,import}` fields + dispatch,
  deferred `EXPORT_UNAVAILABLE`/`IMPORT_UNAVAILABLE` for absent
  handlers, `INVALID_*_REQUEST` on parse failure; deadlines —
  export `CEREMONY + 58m`, import `restoreApplyDeadline + 28m`.
- `helper/matrix.rs`: both verbs implemented; import flagged
  destructive.
- `helper/pam_ceremony.rs`: `ExportPamConfirmer`/`ImportPamConfirmer`
  adapters over `PamConfirmer::confirm_backup_{export,import}`.
- `helper/daemon.rs`: production composition resolves the broker
  protected dir via `production_broker_root_at` (fail closed to
  exit 6), installs `ExportHandlerImpl` with
  `RepositoryExportSource`, and `ImportHandlerImpl::with_engine`
  sharing the T9 `ProductionRestoreEngineLauncher`.
- `helper/restore_launcher.rs`:
  `restore_import_engine_deadline` derives the engine share as
  `restoreApplyDeadline + 28m staging − RESTORE_CEREMONY_DEADLINE
  − 28m` (zero → fail closed); production composition now installs
  `ProductionImportMinioPreparer` via `.ok().map(...)`, so a
  preparer-construction failure narrows only the import launch —
  matching upstream `import_minio_composition.go`.
- `helper/minio_provision.rs`: `ProductionImportMinioPreparer` —
  upstream `newProductionImportMinioPreparer`. Validates instance
  identity, dependency root, compose path, fixed
  `central-artifacts-v1` bucket, active dependency receipt, image
  digest, compose model, broker rendezvous; mints `Purpose::
  MinioImport` credentials under import-separated fence/target
  domains (`central.import-minio-fence/v1`,
  `central.import-minio-target/v1`), op-bound handoff receipt and
  absolute expiry from the v7 operation id.

### CLI — `bins/central/src/{backup_cli,destructive_cli,main}.rs`

- `backup.export`/`backup.import` route into `destructive_cli`.
- `backup export [--backup=<uuid>] [--out=<dir>]`: each flag once,
  non-nil UUID, `--out` defaults to the cwd resolved absolute +
  cleaned; validates the helper echo (op id, basenames, explicit-id
  match); writes `slice-d-export.json` (`ExportEvidence`).
- `backup import --bundle=<path> --token=<path>
  --trust-key=<64hex>`: all three required once each, 32-byte key,
  absolute-clean paths; result re-validation; writes
  `slice-d-import.json` (`ImportEvidence`); `safe_next_action`
  is `IMPORT_COMPLETE` only when `data_plane_restored`, else
  `IMPORT_STAGED_RUN_DATA_PLANE_RESTORE`.
- Closed reason→(class, reason, safe-next) tables matching
  upstream `mapHelperExportError`/`mapHelperImportError` including
  `DENY_SAFE_ACTIVE`.

## Tests

- `central-infra::portable`: HKDF RFC 5869 vector, token round trip
  and every upstream rejection ordering (bad signature, wrong trust
  key, expired, wrong purpose, bundle mismatch).
- `helper::portable` (8): chunked round trip across the boundary,
  tamper/truncation/wrong-key/garbage rejection, deterministic tar
  round trip + symlink refusal, extracted-tree contract, protected
  scan, identity mint/load/corrupt, Go-parity archive dump.
- `helper::export` (5): pre-ceremony out-dir refusal (confirmer not
  called), missing confirmer, denied ceremony, candidate
  cardinality, and a full produce→self-verify→decrypt round trip.
- `helper::import` (5): pre-ceremony path/key refusals, initialized
  target refusal, wrong trust key vs. tampered bundle
  (`IMPORT_TOKEN_INVALID` vs `IMPORT_BUNDLE_MISMATCH`), staging-only
  success, and the full bootstrap+engine-launch round trip.
- `helper::minio_provision` (4): import fence/target domain
  separation from backup and restore values, never-zero fences,
  and incomplete-composition refusal — ports of
  `import_minio_composition_test.go`.
- `destructive_cli::portable_cli_tests` (5): both grammars and both
  closed error tables.
- `main.rs` census: `backup export`/`backup import` removed from
  the deferred-verb list; export's absent-socket terminal refusal
  and import's grammar gate asserted.

## Deviations / notes

- `helper::export` and `helper::import` each own the client half of
  `client_linux.go` (same crate, matching upstream file grouping).
- `mkdtemp`/`CleanLexical`/`copy_tree`/`RemoveOnDrop` live in
  `export.rs` as `pub(crate)` and are shared with `import.rs`,
  matching upstream's shared helpers.
- Import config rebind reuses `destructive::rewrite_config_for_instance`
  (upstream `destructive.RewriteConfigForInstance`) — the test
  fixture completes the raw `complete-config.json` exactly like
  `central_infra::config::testutil::complete_config_fixture`.
- `with_now` test hooks were removed (the new tests pin behavior,
  not wall-clock); domain `now` injection remains.
