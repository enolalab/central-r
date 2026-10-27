# R6 Task 10 slice C — C06 scenario bodies 5 and 6 (report)

Status: scenarios 5 (`restore_apply`) and 6 (`authority_reset`) landed and
verified. The shared-record-set emitter fix T10b flagged was already
committed in `f1ad1fc` (verified: `zz_emit_the_evidence` consumes
`fixture::records()`; `RecordSet::default()` survives only inside the
`OnceLock` initializer) — no duplicate emitter patch was needed.

## Commits

- `0fda2ab` — test(c06): port scenario 5 restore_apply quarantine-barrier batteries
- `d2e63f3` — test(c06): port scenario 6 authority_reset batteries and measured reset

## What landed

- `bins/central/tests/c06_acceptance/scenario5.rs` (~800 lines) —
  four portable batteries plus the armed `c06.s5.restore_apply` entry:
  1. quarantine barrier: every non-terminal state reports ACTIVE at the real
     `RecoveryJournalStore` barrier; `serving_allowed()` admits only
     `Ready`/`authority_reset`/`ready_at`; `RESTORE_RESUME_REQUIRED` /
     `RESTORE_BARRIER_UNAVAILABLE` pinned verbatim;
  2. legal-edge walk: real CAS chain applying → verifying →
     inventory_verified → quarantined → resumed → authority_reset → ready;
     skipped/backwards/foreign-expected/from-terminal edges refused at the
     domain and at the journal CAS;
  3. five quarantine classes: per-reason evidence shapes through
     `QuarantineFinding::validate_for`, the `quarantine_source_for`
     bijection, and the persisted wire vocabulary;
  4. capacity reserve release: `ReserveHelperAuthority` refuses a
     caller-labelled `Reconciliation` release, exercises the five
     caller-known triggers, sweeps an empty root intact.
  The apply `CeremonyPlan` is built with the production
  `phrase::restore_apply_phrase` and validated through
  `CeremonyPlan::validate`; the performed PAM/console child ceremony is
  disclosed unperformed (no suite-launched helper socket or operator
  binary exists — recording one would fabricate a destructive
  confirmation).
- `bins/central/tests/c06_acceptance/scenario6.rs` (~1790 lines) —
  receipt battery (12 single-field mutations + four epoch axes at offsets
  -2..=2 through `AuthorityResetReceipt::validate_for`); aggregate-binding
  battery (11 components, digest moves per component, plus the VALUE pin
  against the real `new_authority_reset_receipt` constructor); broker
  battery over a real `Service` (TLS rekey with unmoved control root,
  identical second prepare, single activation, idempotent replay, foreign
  generations denied); recorder-refusal battery (12 refusal rows + double
  record); and the DSN-gated live leg — full census seed plan,
  `AuthorityResetCoordinator::reset_authority` over `RecoveryAuditStore`,
  before/after counts, epoch markers, fence advancement, exactly-one
  generation both directions, foreign-draft refusal, P-4 replay
  idempotence, pre/post-reset session-token leg through `PgSessionStore`,
  governance field 26 written into the shared `RecordSet`.
- `mod.rs` declares `mod scenario5; mod scenario6;`. Shared helpers were
  reused, not rebuilt: `slice_c::scenario`/`unmet_precondition`,
  `ScenarioLog`/`expect*`+divergence attachment, scenario34's
  `begin_a_real_restore`/`admission_facts`/`TempRoot`/`Broker` (marked
  `pub(crate)`), scenario2's `connect_pg`/`missing_live_env`, ceremony's
  `CeremonyPlan`/`drive_ceremony` types and phrase pins.

## Adaptations (each carried in the scope disclosure)

1. Performed apply ceremony (PAM leg, console peer read, typed phrase,
   real helper socket, operator binary): NOT exercisable — no live
   helper-socket/binary env exists in the port. Plan construction +
   validation is exercised; no ceremony outcome is recorded or claimed.
2. `ServeInspection` is crate-private in `central_kernel::serve`, so the
   barrier→inspect ordering is asserted through the composed components
   (journal `RestoreBarrierInspector` + `serving_allowed` + verbatim
   refusal vocabulary) rather than a recording migration inspector.
3. Upstream's AST-walk of the Go producer (census totality, payload tag
   order) has no Rust analogue; totality is pinned to
   `evidence::InvalidatedCounts`' serde names and the reset's statement-text
   constants; the aggregate value pin uses the public producer function.
4. `PINNED_PG_TOOL_VERSION = "16.14"`: `valid_recovery_facts` requires
   `pg_restore-16.14` verbatim; this host carries 16.15, so measuring it
   makes production honestly refuse ticket issuance — the portable
   batteries use the pinned value the reference host would measure.
5. Upstream's fingerprint bracket for scenario 7 is deferred to T10d
   (recorded, not asserted).

## Verification actually run

- `cargo test -p central --test c06_acceptance` — **unarmed**
  (`CENTRAL_C06_REFERENCE_HOST` unset): **64 passed, 0 failed**. New
  portable entry points: 4 scenario-5 batteries, 5 scenario-6
  batteries/recorder/emitter pins; armed scenario entries returned early
  unarmed as designed. **Armed run NOT attempted** — this host is not the
  reference host (non-root, pg_restore 16.15 vs pinned 16.14, no
  PAM/physical-TTY env); on a reference host `unmet_precondition` +
  `missing_live_env` gate or honestly skip per SC-G3.
- `cargo fmt --all -- --check` — clean.
- `cargo check --test c06_acceptance -p central` — clean.
- `cargo clippy --test c06_acceptance -p central` — clean, no warnings.
- Fixes during port: quarantine finding fixtures matched to the real
  `validate_for` per-reason shapes; `quarantine_operation` enters
  `quarantined/inventory_verified` (the state `admits_inventory_verification`
  accepts); protected roots must be created by `Service::new` (mode 0700),
  not `create_dir_all` — journal writes refuse otherwise.

## Remaining for T10d (≤6 lines, per request)

- Scenarios 7/8: state-equivalence fingerprint comparison + restart
  boundary — not yet ported (upstream `c06_scenario78_*` ~2.6k lines).
- `continuous_run`: the `zz_` completeness driver exists; the upstream
  continuous-run scenario body is not yet wired.
- Shared record set: FIXED (emitter consumes `fixture::records()`);
  scenario 6 records `authority_reset`, scenario 5 records
  `capacity_reserve` — scenario 5's quarantine_census and ceremony records
  await the performed-apply leg T10d may supply.
