# R6 Task 10 slice D — C06 scenarios 7/8 and the continuous run (report)

Status: scenarios 7 (`state_equivalence`) and 8 (`minimum_profile`) and the
nine restart injections (`c06.r1`–`c06.r9`) are ported, and the run wiring
upstream puts around them is in place: sequence gates between catalogue
entries, the tool-version recorders, and every `EvidenceInputs` field
sourced. The suite compiles, lints clean, and all 84 unarmed tests pass.

## What landed

- `bins/central/tests/c06_acceptance/scenario78.rs` (new, ~2,545 lines) —
  the armed `c06.s7.state_equivalence` and `c06.s8.minimum_profile` bodies,
  plus seven portable entry points (axis attribution per reported axis,
  restore-audit-table exclusion in both directions, repository walker,
  device floor as minimum-not-sum, recorder vocabulary both directions,
  producer-per-field, measurement field coverage).
  - S7 reads `records.pre_corruption`, `records.corrupted` and
    `records.authority_reset_footprint`, captures the instance's current
    state through the same production fingerprint path, requires it to
    differ from the corrupted capture, requires the moved tables after
    restore-audit exclusion to equal scenario 6's measured footprint, and
    runs the perturbation battery: every declared axis moved exactly one
    way, `UndoOnDrop` guaranteeing the undo on pass, error and panic, and
    the same-length streamed-body case proving size alone would not see it.
  - S8 walks the five minimum-profile fields: declared bounds are the
    installed profile's, the measurement vocabulary equals the emitted
    vocabulary both directions, every field names its producer, and the
    four `profile::minimum_profile_assertions` are verified — never the
    claim that clearing the device reserve bound proves a specific
    admission.
  - `expect78` attaches the scenario-7/8 disclosures rather than scenario
    2's, which the earlier `expect` helper was hard-coded to.
- `bins/central/tests/c06_acceptance/continuous_run.rs` (new, ~1,504
  lines) — the restart scope disclosure verbatim, the five assertion keys
  / three verdicts / `CARRY-FORWARD, NOT CLOSED:` labels, the observation
  composer refusing every malformed shape upstream's refuses, the
  in-process broker recomposition over the same protected root
  (`restart_the_broker` returns the `Service` for ticket reads and the
  `RecoveryJournalStore` for operation CAS — the split the Go `Service`
  hides), the four backup-boundary drivers (admitted/dumping/inventory/
  sealing: planned → accept/advance CAS walk → fresh-broker read-back →
  not-resumable → replay CAS refused → sealed CAS refused → no restore
  barrier), the four restore-checkpoint drivers (ticket-consumed through
  authority-reset: the five-case barrier match, the consumed-ticket
  refusal proven by `read_issued_restore_ticket` absence plus a live
  control, replay skipped where it would pass for the wrong reason), the
  ADR-0016 abandonment driver (abandon/apply phrase discrimination, second
  abandonment refused, barrier released), the sequence gate and instance
  probe, and two portable tests pinning the observation rules and the
  declared-vs-emitted vocabulary.
- `fixture.rs` — `RecordSet` gains `protected_journal_recorded`,
  `authority_reset_footprint` and `tool_version_output`; recorders
  `record_restart_observation`, `record_journal_walk`,
  `record_pre_corruption`, `record_corrupted`,
  `record_server_tool_versions`, `record_pg_tool_versions`,
  `record_authority_reset_footprint`, `record_minimum_profile_measurement`
  with the refusal rules the upstream checkers carry.
- `scenario6.rs` — the live reset now brackets table fingerprints,
  computes `content_divergent_tables`, refuses an empty footprint, and
  records it for scenario 7; `pin_fingerprint_session` /
  `fingerprint_tables` exposed via `scenario2` for reuse.
- `scenario2.rs` — records `before_anything` as `pre_corruption` (see
  adaptations), gate after s1 wired, shared capture helpers marked
  `pub(crate)`.
- `scenario5.rs` — `synthetic_authority_reset_receipt` binds the operation
  id into every receipt digest and takes the caller's clock, matching the
  upstream helper exactly.
- `slice_c.rs` — s1's body records the four tool versions from the tools'
  own output (server via `SELECT version()`, `rustc --version`,
  `pg_dump`/`pg_restore --version`, through the second-capture-refusing
  recorders); `zz_emit_the_evidence` now sources `tool_version_output`
  from the record set, measures `binary_digests` from operator-named
  binaries (`CENTRAL_C06_RESTORE_BIN`, `CENTRAL_C06_LAUNCHERD_BIN` — an
  unset name leaves the field empty and the emitter refuses it), and runs
  upstream's last gate before emitting.
- Sequence gates wired at upstream's positions: each of s2–s10 gates its
  catalogue predecessor at body start, r1 gates s10 at the scenario|
  injection seam, and emission gates after the restart batch.
- `mod.rs` declares `mod scenario78; mod continuous_run;`. Catalogue
  entries were NOT re-registered (s7/s8 and r1–r9 existed).

## Adaptations and honest boundaries

1. `pre_corruption` provenance: upstream records it in scenario 1, which
    seeds and fingerprints before the backup create. This port's scenario
    1 dispatches the operator command only; scenario 2's `before_anything`
    capture — after the idempotent seed and before any injection, by
    construction order inside that body — is recorded instead. The
    baseline names the same state under this port's seed-inside-s2
    ordering, and is the only provenance that cannot interleave with the
    corruption under the unordered armed schedule.
2. Sequence-gate semantics: upstream `t.Fatalf` aborts the whole
    continuous test; a libtest body cannot abort the process, so a failed
    gate fails the entry that runs it and names the predecessor. Parallel
    scheduling also means the predecessor name is catalogue-order, not
    observed execution order — stated in `gate_the_sequence`'s doc.
3. S7's `after` is a live capture: no performed restore exists to compare
    against (no throughput gate — s5's performed-apply leg is disclosed
    absent), so on an armed run s7 honestly fails the "differs from the
    corrupted fingerprint" check unless something restored the instance.
    That is upstream's own red-run posture, not a weakening.
4. The restart is fresh in-process broker composition over the same root
    — `RESTART_PROCESS_BROKER_SERVICE_RECOMPOSED_IN_PROCESS`; no daemon
    restart, fork, exec or systemd semantics are claimed, and the
    disclosure says so verbatim on every divergence.
5. The two carry-forward labels stay distinct: `SYNTHETIC_BACKUP_`
    (journal-only backup state — no sealable backup exists) on r1–r4,
    `RECORDED_AUTHORIZATION_` (recorded apply authorization, not a
    performed ceremony) on r5–r9.
6. Tool-version capture requires the live DSN/tools; an armed host
    without them fails s1's body honestly rather than emitting empty
    versions.
7. Upstream's `beforeAnything`-vs-`PreCorruption` distinction collapses:
    s1's create never completes here, so the two captures describe the
    same state.

## Verification actually run

- `cargo fmt --check -p central` — clean.
- `cargo check --test c06_acceptance -p central` — clean, no warnings.
- `cargo clippy --test c06_acceptance -p central -- -D warnings` — clean.
- `cargo test --test c06_acceptance -p central` — **84 passed, 0 failed**,
  unarmed (`CENTRAL_C06_REFERENCE_HOST` unset). Portable coverage
  includes: all 11 `continuous_run::` tests (9 injection bodies +
  composer/vocabulary pins), all 9 `scenario78::` tests, and the prior
  slices' suites. **Armed run NOT attempted** — not the reference host;
  armed entries gate or honestly skip per SC-G3.

## Fixes during this slice

- `restart_the_broker` returns `(Service, Arc<RecoveryJournalStore>)`:
  `read_issued_restore_ticket` is a `Service` method; the journal carries
  CAS/read — the upstream `*broker.Service` hides the split.
- `synthetic_authority_reset_receipt` bound the digest to the operation
  id and took the walk's clock (previously a fixed `updated_at + 1s` with
  an operation-unbound digest — two operations could have shared receipt
  hashes).
- `zz_emit_the_evidence` now copies `records.tool_version_output` and
  measures `binary_digests`; previously both defaulted and an armed emit
  would have refused at the end with no producer to fix.
- `gate_the_sequence`/`probe_the_instance_is_still_usable` were defined
  but never called — now wired at every seam upstream places one.
- `record_pre_corruption` had no caller — scenario 7's baseline could
  never exist; now recorded from s2's pre-injection capture.
- Clippy: needless lifetimes elided, `&format!` borrows removed, useless
  `format!` → `to_owned`, `AxisMover` type alias, `..Default::default()`
  dropped once every field was sourced.
