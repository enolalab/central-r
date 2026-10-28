# R6 Task 13 — D05 audit + D06 rescue + security update + Slice E maintenance (report)

Status: the last closed R5 denials are flipped. `state-audit`,
`security-rescue`, `security-update`, `maintenance-plan`, and
`maintenance-apply` are implemented matrix rows with production
handlers, whitelisted wire clients, deny-safe transport gating,
upstream-verbatim refusal vocabularies, and the full CLI surface
(`central local audit`, `central local security update|rescue`,
`central maintenance plan|apply`) with the `slice-d-state-audit.json`,
`slice-d-rescue.json`, `slice-e-compatibility-matrix.json`, and
`slice-e-patch-apply.json` evidence artifacts. `rescue cleanup` stays
deferred to Slice E inside the shared `("local","security")` router,
exactly as upstream. All tests pass (806 adapter-linux lib, 259
central-infra, 154 central bin, all a07 suites); `cargo fmt`,
`cargo clippy`, `cargo check --workspace`, and `cargo deny check`
are clean.

## What landed

### Domain — `crates/capabilities/central-infra/src/{advisory,maintenance}.rs`

`advisory.rs` (upstream `internal/advisory/denysafe.go` +
`evaluator.go`):

- The closed refusal vocabulary: `DENY_SAFE_ACTIVE`,
  `RESCUE_CEREMONY_REQUIRED`, `AUTHORITY_DENIED`,
  `RESCUE_UNAVAILABLE`, `INVALID_RESCUE_REQUEST`,
  `RESCUE_ADVISORY_INVALID`, `RESCUE_STAYS_DENIED`,
  `RESCUE_NOT_APPLICABLE`, `RESCUE_CLEANUP_FAILED`.
- `RescueEvidence` — op id, `exited`, `already_current`,
  `resumed_after_crash`, `attempts`, `completed_at`; serde shape is
  the Go field-tag verbatim (`attempts` has no `omitempty` upstream).
- `FileDenySafeStore` — atomic deny-safe record persistence
  (enter/mark-attempt/exit); a corrupt record fails closed as
  **active**, upstream's `loadDenySafe` rule.
- `snapshot_from_envelope` — strict candidate parse bounded to
  `MAX_CANDIDATE_ADVISORY_BYTES` (1 MiB), non-empty bundle +
  signature, SHA-256 selector digest; `digest_candidate`,
  `discard_candidate` (zeroize), `evaluate_candidate` (release
  trust + host facts + witness + now — never advances witness or
  journal state), `install_active_bundle` (strict envelope shape +
  atomic generation install).
- `CandidateFacts`/`CandidateWitness` seams — read-only host facts
  and witness loading for the rescue evaluator.

`maintenance.rs` (upstream `internal/maintenance`, pure):

- Matrix schema `central.compatibility-matrix/v1`, baseline matrix,
  strict parse/validate, canonical bytes + digest.
- The closed reason set: `MAINTENANCE_TRANSITION_UNLISTED`,
  `MAINTENANCE_PATCH_PENDING`, `MAINTENANCE_PATCH_UNKNOWN`,
  `MAINTENANCE_PATCH_CLOSED`, `MAINTENANCE_ROLLBACK_STALE`,
  `MAINTENANCE_GATE_UNKNOWN`, `MAINTENANCE_GATE_FAILED`.
- `evaluate`/`evaluate_current` verdicts, `run_gate` gate verbs
  (`version-present`, `digest-present`, `modules-verified`) with
  `GateProbe`/`ImageExistsProbe` seams — `None` refuses loudly.
- `Store` — `load_or_bootstrap`, `commit_update`, `append_attempt`,
  `pending_attempt`, `find_attempt`; tamper detection is
  `MAINTENANCE_MATRIX_TAMPERED` upstream-fashion.
- `Evidence`/`new_evidence`/`write_evidence_file`
  (`slice-e-compatibility-matrix.json`) and
  `ApplyEvidence`/`write_apply_evidence_file`
  (`slice-e-patch-apply.json`, schema/completed-at filled when
  absent).

### Helper — `crates/adapters/central-adapter-linux/src/helper/`

- `audit.rs` — protected-state audit handler (baseline manifest
  mint, tamper classification `modified|missing|unknown|symlink`,
  D01 wipe-ceremony repair) plus `AuditClient`: bounded Unix dial
  (5 s dial + `STATE_AUDIT_BUDGET` read), strict/canonical result
  decode, whitelisted `AuditClientError` (`exit_code()` + retained
  `reason()` only — transport folds to 3, decode to 6).
- `rescue.rs` — strict request parse (`candidate_base64`, bounded
  base64 decode via `broker::wire`), deny-safe rescue handler
  (attempt journal records digest/code/timestamp, never candidate
  bytes), `RescueClient` + closed `RescueClientError`.
- `security_update.rs` — strict request parse (raw `envelope`
  JSON), PAM-confirmed `install_active_bundle`, generation-id
  result, `SecurityUpdateClient` + closed error.
- `maintenance.rs` — plan handler (read-only, deny-safe-admitted,
  no ceremony) and apply handler (PAM ceremony, exactly one of
  set/resume/rollback/abandon, matrix-approved transition
  recording); `MaintenanceClient`/`MaintenanceApplyClient` carry
  the denied partial result on refusals (`plan_result()` /
  `apply_result()`), matching upstream's `ErrResult`.
- `pam_ceremony.rs` — trait impls bridging the audit-repair (D01
  wipe ceremony reuse), security-rescue, security-update, and
  maintenance-apply ceremonies onto `PamConfirmer`
  (physical-TTY and grant modes).
- `server.rs` — the five dispatch arms (handler-`None` →
  upstream's `*_UNAVAILABLE` deferrals, parse errors →
  `INVALID_*_REQUEST` at exit 2), deadline rows
  (`SECURITY_UPDATE_BUDGET` 30 s, `STATE_AUDIT_BUDGET` 120 s + 8 m,
  `RESCUE_BUDGET` 120 s + 13 m, `MAINTENANCE_PLAN_BUDGET` 60 s,
  `MAINTENANCE_APPLY_BUDGET` 120 s + 2 m — upstream's constants
  verbatim), and the deny-safe transport gate
  (`deny_safe_admits_helper`: status, doctor, rescue,
  maintenance-plan, and non-repair audit; an unparseable audit
  payload passes the gate and is denied downstream).
- `matrix.rs` — the five rows flipped to `implemented: true`;
  the census test now asserts 25 implemented of 35.
- `daemon.rs` — production composition: security update via
  `install_active_bundle`; audit over the protected roots with the
  wipe ceremony; rescue with installed-advisory evaluator,
  candidate evaluator, compose-down cleanup, deny-safe store, and
  rescue ceremony; maintenance plan/apply with the matrix store,
  host probes, image probe, and maintenance ceremony.
- `client.rs` — `DIAL_TIMEOUT` promoted to `pub(crate)` for the
  new clients (5 s, upstream `dialTimeout`).

### CLI — `bins/central/src/{security_cli,maintenance_cli}.rs` + wiring

- `security_cli.rs` ports `internal/command/{audit,security_update,
  security_rescue}.go`:
  - `local_audit` — `central local audit [--repair]` (duplicate/
    unknown flags refuse `INVALID_AUDIT_GRAMMAR`);
    `mapHelperAuditError`'s closed table
    (`DENY_SAFE_ACTIVE`→`RUN_CENTRAL_LOCAL_SECURITY_RESCUE`,
    `AUDIT_REPAIR_REFUSED`→`WIPE_AND_RESEED_INSTEAD`, etc.);
    `validAuditResult` echo check; `slice-d-state-audit.json`;
    stdout carries counts + identities only (`tamper_count`,
    `unreadable_count` — paths stay in evidence).
  - `local_security` — `runLocalSecurity` verbatim: `update`,
    `rescue`, and the Slice E `rescue cleanup` deferral
    (`UNSUPPORTED_IN_THIS_SLICE` + `WAIT_FOR_SLICE_E` details)
    route on `tokens[0]` since every `local security *` form
    resolves `local.security-update` (upstream first-match).
    `run_security_update` enforces exactly `update <path>`,
    `SECURITY_UPDATE_ENVELOPE_UNREADABLE`, the exit-class switch
    (3|5→dependency-unavailable, 7→the reason-split denial incl.
    `DENY_SAFE_ACTIVE` folding to terminal `SECURITY_UPDATE_FAILED`
    through `NewSecurityUpdateError`'s default, verbatim),
    generation-id success projection. `run_security_rescue`
    enforces a single non-empty `--advisory=<path>`, bounds it to
    `MAX_CANDIDATE_ADVISORY_BYTES`, zeroizes the candidate after
    the helper call (upstream's `candidate[i] = 0` loop), maps the
    closed rescue reason table, validates `exited XOR
    already_current`, and writes `slice-d-rescue.json`.
- `maintenance_cli.rs` ports `internal/command/maintenance.go`:
  - `run_maintenance_plan` — `--check=name=target` only;
    denied-plan violations echo as `dependency (REASON)` strings
    under `RESOLVE_MATRIX_TRANSITION` (the adapter's
    `ErrResult`-carrying denial); matrix-digest/sequence
    validation; `slice-e-compatibility-matrix.json` via
    `m::new_evidence`; success reason is `""` (omitted, upstream's
    `WriteResult(..., "", ...)`) with `REVIEW_MATRIX`.
  - `run_maintenance_apply` — exactly one of
    `--set name=target`/`--resume`/`--rollback`/`--abandon <uuid>`
    (`uuid.FromString` gate); the emit closure writes
    `slice-e-patch-apply.json` best-effort once an operation id
    exists and never replaces the command's own verdict; refused
    apply evidence carries `refused|failed` per
    `applyVerdictForReason`; success is `applied|abandoned` with
    `REVIEW_MATRIX`.
  - `maintenance.rs` — `maintenance.*` dispatch arm in `main.rs`
    plus the two `local.*` match arms in `local_cli.rs`.
- `helper_socket()` follows the local_cli/migrate_cli rule
  (`CENTRAL_HELPER_SOCKET` then the production path) — deliberately
  not `backup_cli::helper_socket_path()`, whose test override would
  race these handlers against the backup socket fixtures.

## Tests

- `central-infra` (259): deny-safe store enter/attempt/exit +
  corrupt-fails-active, candidate snapshot bounds/strictness,
  evaluator hard-expiry/emergency/deny orderings, witness
  non-advance, matrix parse/validate/tamper, gate verbs, store
  bootstrap/commit/attempt lifecycle, evidence verdict rule.
- `central-adapter-linux` (806 lib + suites): audit walk +
  tamper classification, ceremony-required and deny-safe refusals,
  rescue handler paths, security-update install + PAM denial,
  maintenance plan/apply handlers, client canonical-decode checks,
  server dispatch (`*_UNAVAILABLE` unconfigured answers —
  `a07_authority` + `closed_matrix_denies_later_verbs` updated to
  upstream's `AUDIT_UNAVAILABLE`/`RESCUE_UNAVAILABLE`/
  `MAINTENANCE_UNAVAILABLE`/`SECURITY_UPDATE_UNAVAILABLE` tokens),
  matrix census 25/35.
- `central` bin (154): the registry census now asserts the Task-13
  verbs' grammar gates at exit 2
  (`INVALID_AUDIT_GRAMMAR`/`INVALID_SECURITY_GRAMMAR`/
  `INVALID_SECURITY_UPDATE_GRAMMAR`/`INVALID_RESCUE_GRAMMAR`/
  `INVALID_MAINTENANCE_GRAMMAR`/`SECURITY_UPDATE_ENVELOPE_UNREADABLE`/
  `RESCUE_ADVISORY_UNREADABLE`), helper-dial failures at exit 3
  (`AUDIT_FAILED`, `MAINTENANCE_PLAN_FAILED`), and `rescue
  cleanup`'s Slice E deferral with the `WAIT_FOR_SLICE_E`
  details payload.
- `a07_peers` — the arm-gate probe verb swapped from `wipe`
  (implemented since task 11; answers `WIPE_UNAVAILABLE`) to
  `trust-install`, the remaining plain unimplemented operator verb.

## Deviations / notes

- The plan named `central-infra/src/rescue.rs`; the deny-safe store,
  candidate evaluator, and `RescueEvidence` landed inside the
  existing `advisory.rs` instead — upstream keeps them in
  `internal/advisory/{denysafe,evaluator}.go`, so the file grouping
  matches the source layout.
- `central local security rescue cleanup` still resolves
  `local.security-update` — upstream `Resolve`'s first-match on the
  shared `("local","security")` registry key, where
  `runLocalSecurity` owns the sub-action route.
- `MaintenanceClientError` carries the bounded partial result via
  `plan_result()`/`apply_result()` — the typed equivalent of
  upstream's `ErrResult` on denied plans/applies.
- No production-behavior change to `CENTRAL_HELPER_SOCKET`
  resolution; the new handlers use the same env-then-production rule
  as every existing helper client.
