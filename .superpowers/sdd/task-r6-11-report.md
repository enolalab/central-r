# R6 Task 11 — D01 wipe/reseed + D04 delete/prune (report)

Status: the two destructive slices are ported end to end — domain
vocabulary in `central-infra::destructive`, helper handlers with the
ADR-0032 grant/PAM ceremony preserved per verb, production daemon
composition, and the `central` CLI's grammar + evidence artifacts.
All 39 new tests pass; the full touched suites are green (778
adapter-linux, 241 central-infra, 149 central bin); `cargo fmt` and
`cargo clippy --workspace --all-targets` are clean.

## What landed

### Domain — `crates/capabilities/central-infra/src/destructive.rs` (new)

Upstream `internal/destructive`'s closed surface:

- Wipe reasons (`WIPE_DENIED_SIGNED`, `WIPE_CHECKPOINT_FAILED`,
  `WIPE_APARMOR_REFUSED`, `WIPE_TARGET_INVALID`, `WIPE_TARGET_LIVE`,
  `WIPE_RESEED_FAILED`, `WIPE_CEREMONY_REQUIRED`, `AUTHORITY_DENIED`,
  `WIPE_UNAVAILABLE`, `INVALID_WIPE_REQUEST`), `AppArmorState`
  (`not_confined`/`profile_removed`), the AppArmor path constants,
  `WipeTarget` validation, `WipeIntent`/`WipeResultRecord`, `ReseedInput`,
  `WipeEvidence`, and `is_wipe_intent_file_name` /
  `delete_record_file_name` naming.
- Delete reasons (all nine upstream tokens), `DeleteRecord`,
  `DeleteEvidence` (the shared delete / prune-apply D04 artifact).
- Prune reasons (all seven), `PruneCandidate`/`PrunePlan`/`PruneBatch`,
  `DEFAULT_RETENTION_DAYS = 30`, `PRUNE_BATCH_SIZE = 100`, journal
  states `pending`/`applying`/`done`, and the pure helpers the engine
  seam drives: batching, `ResumeBatches`, `ValidatePruneCandidate`,
  `ApplyPruneBatches`.
- 9 domain tests (naming, batching, resume states, validation order).

### Helper — `central-adapter-linux/src/helper/{wipe,delete,prune}.rs` (new)

Upstream `internal/adapter/authority/helper`'s three handlers, each in
upstream's order: advisory denial before ceremony → strict request
parse (`deny_unknown_fields`) → the verb's own PAM/TTY ceremony →
verification → mutation → durable evidence.

- `wipe.rs`: sealed-checkpoint verification adapted to
  `BackupReader::verify_backup`; AppArmor verify + `apparmor_parser -R`
  removal behind injectable deps; target resolution (absolute, clean,
  direct child of the instances root, strict UUIDv7, correct owner,
  mode `0700`, no live runtime root); durable intent before
  destruction; stale-intent discovery and crash resume; instance +
  broker protected tree removal; reseed (`data`, `backups`,
  `dependencies`, `lifecycle`, canonical rebound `config.json`,
  `reseed.json`, fresh broker protected root, fresh trust state proven
  absent); terminal result written before intent cleanup; bounded
  client with the whitelisted reason surface. 8 tests.
- `delete.rs`: explicit `--backup` or exactly one sealed candidate
  (zero/ambiguous refused), unavailable source/reference seams refuse
  `DELETE_UNAVAILABLE` before any ceremony, post-ceremony age +
  zero-reference re-proof, exclusive `0600`
  `delete-<operation-id>.result.json` journal. 7 tests.
- `prune.rs`: read-only plan minting a frozen plan id; apply bound to
  the plan through the `backup_prune` ceremony (the grant's operation
  id is the plan id, so a grant for one plan cannot spend another);
  per-body stale reproof (`PRUNE_PLAN_STALE` / `DELETE_REFERENCED`);
  100-body batches over `pending`/`applying`/`done` journal states;
  tombstone-checked idempotent resume. 5 tests.

### Transport + composition

- `server.rs`: `wipe`/`delete`/`prune` handler slots, dispatch arms,
  per-verb deadlines (ceremony budget + 13m / +8m / +58m), each verb's
  own `*_UNAVAILABLE` answer when unconfigured; the deny-safe
  allowlist is untouched, so all three verbs refuse `DENY_SAFE_ACTIVE`
  under the gate.
- `matrix.rs`: `WIPE`, `BACKUP_DELETE`, `BACKUP_PRUNE` registered
  implemented + destructive + PAM-required.
- `pam_ceremony.rs`: one trait impl per destructive confirmer face
  (`WipePamConfirmer`/`DeletePamConfirmer`/`PrunePamConfirmer` on
  `PamConfirmer`) — a confirmer for one verb can never satisfy
  another; upstream's failed type assertions are the `Option` returns.
- `daemon.rs`: production composition — wipe wired end to end
  (deny-only evaluator until B01's link lands, the backup-read
  checkpoint verifier, production roots/ownership/AppArmor deps);
  delete behind `UnavailableDeleteSource`/`UnavailableDeleteRefs`;
  prune behind a nil engine — upstream's explicit fail-closed seams,
  never a degraded success.

### CLI — `bins/central/src/destructive_cli.rs` (new)

Upstream `cmd/central`'s `runLocalWipe`/`runBackupDelete`/
`runBackupPrune`:

- `local wipe --target <path>`: seals a C01 checkpoint backup first
  (its own ceremony), binds its id to the wipe call, validates the
  bounded result, writes `slice-d-wipe-reseed.json`.
- `backup delete [--backup=<uuid>] [--retention-days=<n≥30>]`:
  `slice-d-delete-prune.json` with `verb: "delete"`.
- `backup prune plan|apply`: plan writes
  `slice-d-prune-plan-<plan-id>.json`; apply reads exactly that file
  (`deny_unknown_fields`, plan-id binding, complete body identity) and
  writes `slice-d-delete-prune.json` with `verb: "prune-apply"`. The
  helper re-proves every body, so a hand-edited plan cannot smuggle a
  young or referenced body.
- Closed reason→(exit, reason, safe_next_action) tables for all three
  verbs; an empty wire reason collapses to terminal `*_FAILED`
  (upstream's non-`*ClientError` branch).
- 10 tests (grammars, closed error tables, plan-file round-trip and
  tamper rejection); `main.rs` census updated — the three verbs prove
  fail-closed at exit 6 with no helper socket and gate their grammars
  at exit 2.

## Commits

- `9fcec0e` feat(r6): D01/D04 destructive domain vocabulary
- `5dd20e6` feat(r6): D01/D04 helper wipe/delete/prune handlers + dispatch
- `c1d17e0` feat(r6): D01/D04 CLI verbs + evidence

## Verification

- `cargo test -p central-adapter-linux --lib`: **778 passed, 0 failed**
- `cargo test -p central-infra --lib`: **241 passed, 0 failed**
- `cargo test -p central --bin central`: **149 passed, 0 failed**
- `cargo clippy --workspace --all-targets`: clean
- `cargo fmt --all`: clean

## Carried seams (explicit, fail-closed — upstream's own)

- The B01 advisory evaluator is not wired anywhere yet: every
  destructive handler composes the deny-only evaluator, so a signed
  denial is answered `*_DENIED_SIGNED` and nothing proceeds — the same
  `unavailableLifecycleEvaluator` stance upstream holds until the
  evaluator link lands.
- Delete's repository source and PG reference checker are the
  unavailable stand-ins (`DELETE_UNAVAILABLE`); prune's PG/S3 engine
  is absent (`PRUNE_UNAVAILABLE`). Neither verb can delete in this
  composition — intentionally, until the inventory/journal plumbing
  lands.
- Ceremony scope uses `default`/`postgres:central` until
  instance-specific scope wiring exists (unchanged from the migration
  launch composition).
