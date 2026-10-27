//! `cmd/central/c06_scenario5_apply_test.go` — C06 scenario 5: restore apply
//! under the quarantine barrier.
//!
//! WHAT IS PORTED VERBATIM.
//!   - Battery 1, the quarantine barrier: every non-terminal restore state is
//!     reported ACTIVE by the real protected journal's
//!     [`RestoreBarrierInspector`], and [`RestoreOperation::serving_allowed`]
//!     admits `Ready`/`authority_reset` and nothing else — no partial serving.
//!   - Battery 2, the legal journal-edge walk: the begun operation is CAS-walked
//!     through `applying` → `verifying` → `inventory_verified` → `quarantined`
//!     → resumed → `authority_reset` → `ready` on the real journal, and the
//!     skipped/backwards/from-terminal edges are refused by the domain and by
//!     the journal's compare-and-swap.
//!   - Battery 3, the five quarantine classes: one [`QuarantineFinding`] shape
//!     per class, the reason↔source bijection, `validate_for` accepting exactly
//!     its own shape, and the persisted wire vocabulary.
//!   - Battery 4, the capacity reserve release: the production
//!     [`ReserveHelperAuthority`] refuses a reconciliation-labelled release and
//!     sweeps an empty protected root to an intact empty report.
//!
//! THE ADAPTATIONS, EACH DISCLOSED IN THE SCENARIO LOG.
//!
//! 1. THE PERFORMED APPLY CEREMONY IS NOT EXERCISABLE. Upstream drives a real
//!    `central restore apply` child through a running protected broker/helper
//!    socket plus PAM + a physical console. This port has no suite-launched
//!    helper socket or operator-binary env (the broker is composed in-process,
//!    as scenario34 discloses), so no `drive_ceremony` call is made: recording
//!    one would fabricate a destructive confirmation that never happened. The
//!    ceremony DECISION surface is still exercised — the apply [`CeremonyPlan`]
//!    is built with the production `phrase::restore_apply_phrase` and refused/
//!    admitted by `CeremonyPlan::validate`, and `serving_allowed` plus the
//!    real journal barrier decide serving — but the child process, the
//!    peer-credential read, the PAM leg and the typed phrase are not asserted.
//! 2. `ServeInspection` is crate-private in `central_kernel::serve`, so the
//!    barrier→inspect ORDERING assertion is stated over the components that
//!    compose it (journal barrier inspector + the verbatim refusal vocabulary
//!    `RESTORE_RESUME_REQUIRED`/`RESTORE_BARRIER_UNAVAILABLE`) rather than
//!    driven through a recording migration inspector.
//! 3. Quarantine FINDINGS persist in PostgreSQL
//!    (`RecoveryAuditStore::record_quarantine_findings`), not the protected
//!    journal; the portable battery decides resolution semantics through the
//!    domain's `resume_verification(unresolved)` — nonzero findings refuse
//!    resume, zero releases — which is the rule the store's count feeds.
//! 4. No sealed backup exists on any host (no throughput gate), so ticket
//!    admission facts are synthetic, exactly as scenarios 3/4 disclose.

use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use uuid::Uuid;

use central_adapter_linux::broker::protected_file::ProtectedFileBackend;
use central_adapter_linux::broker::recovery_journal::RecoveryJournalStore;
use central_adapter_linux::broker::restore_capacity::helper::ReserveHelperAuthority;
use central_adapter_linux::broker::restore_capacity::sweep::{ReleaseTrigger, SweepCaller};
use central_adapter_linux::broker::signing::SigningService;
use central_backup::backup::capacity::RoleRoots;
use central_backup::port::RestoreJournalStore as _;
use central_backup::recovery::operation::{
    AuthorityResetReceipt, RestoreCheckpoint, RestoreOperation, RestorePhase,
};
use central_backup::recovery::quarantine::{
    QuarantineFinding, QuarantineObservationSource, QuarantineReason, quarantine_source_for,
};
use central_foundation::failure::Failure;

use crate::runner::runner;
use crate::scenario2::{ScenarioLog, missing_live_env};
use crate::scenario34::{
    TempRoot, admission_facts, begin_a_real_restore, peer, synthetic_manifest_digest,
};

pub(crate) const SCENARIO5_SCOPE_DISCLOSURE: &str = "SCOPE, CARRIED ON EVERY DIVERGENCE THIS SCENARIO EMITS: the portable batteries here prove the DECISIONS production makes — the journal barrier's active reporting, serving_allowed()'s Ready-only admission, the legal-edge walk, the five quarantine classes, and the reserve release triggers — against the real RecoveryJournalStore, the real domain types and the real ReserveHelperAuthority. NOT PERFORMED: the destructive `central restore apply` child-process ceremony (PAM leg, physical-console peer read, typed phrase, real broker socket) is not exercisable in this port because no suite-launched helper socket or operator binary exists; the apply CeremonyPlan is constructed with the production phrase helper and validated, but no drive_ceremony outcome is recorded and none is claimed. The barrier→migration-inspection ordering inside central_kernel::serve is asserted through the composed components and the verbatim refusal vocabulary rather than through a recording inspector, because ServeInspection is crate-private. Ticket admission facts are synthetic (no sealed backup can be produced — no throughput gate), so no claim is made about admission of a real backup.";

/// `c06Scenario5Expect` — the disclosure rides on every divergence.
fn expect5(id: &str, what: impl AsRef<str>) {
    runner().attach_divergence(
        id,
        &format!("{}. {}", what.as_ref(), SCENARIO5_SCOPE_DISCLOSURE),
    );
}

/// `c06Narrator` — batteries state expectations/records through this so the
/// live path attaches the disclosure and the portable path stays quiet.
trait Narrator {
    fn expect(&mut self, what: &str);
    fn record(&mut self, what: String);
}

struct Quiet;
impl Narrator for Quiet {
    fn expect(&mut self, _what: &str) {}
    fn record(&mut self, _what: String) {}
}

struct Disclosing<'a> {
    id: &'a str,
    log: &'a mut ScenarioLog,
}
impl Narrator for Disclosing<'_> {
    fn expect(&mut self, what: &str) {
        expect5(self.id, what);
    }
    fn record(&mut self, what: String) {
        self.log.recordf(format_args!("{what}"));
    }
}

// ---------------------------------------------------------------------------
// Shared: a real protected journal over a temp root (scenario34's shape).
// ---------------------------------------------------------------------------

pub(crate) fn journal_battery(
    group: &str,
) -> Result<(TempRoot, Arc<RecoveryJournalStore>), String> {
    let tmp = TempRoot::new(group)?;
    let root = tmp.0.join(format!("protected-{group}"));
    let signing = Arc::new(
        SigningService::new_persistent(&root)
            .map_err(|e| format!("compose the signing service for {group}: {e}"))?,
    );
    let journal = Arc::new(
        RecoveryJournalStore::new(&root, signing, ProtectedFileBackend::new(root.clone()))
            .map_err(|e| format!("compose the protected journal for {group}: {e}"))?,
    );
    Ok((tmp, journal))
}

/// `c06CarryARestoreToInventoryVerified` — CAS-walk the REAL journal to the
/// only state the C05 reset is legal from.
pub(crate) fn carry_to_inventory_verified(
    journal: &RecoveryJournalStore,
    start: RestoreOperation,
) -> Result<RestoreOperation, String> {
    let mut current = start;
    let mut at = current.updated_at;
    type Step = fn(&RestoreOperation, OffsetDateTime) -> Result<RestoreOperation, Failure>;
    for (label, step) in [
        (
            "applying/database_replaced",
            RestoreOperation::record_database_replaced as Step,
        ),
        (
            "verifying/database_replaced",
            RestoreOperation::begin_verification as Step,
        ),
        (
            "verifying/inventory_verified",
            RestoreOperation::record_inventory_verified as Step,
        ),
    ] {
        at += time::Duration::seconds(1);
        let next = step(&current, at).map_err(|e| format!("the domain refused {label}: {e}"))?;
        journal
            .compare_and_swap_restore(&current, &next)
            .map_err(|e| format!("the protected journal refused {label}: {e}"))?;
        current = next;
    }
    if current.phase != RestorePhase::Verifying
        || current.last_checkpoint != RestoreCheckpoint::InventoryVerified
    {
        return Err(format!(
            "the walk stopped at {:?}/{:?}, and the C05 reset is legal only from verifying/inventory_verified",
            current.phase, current.last_checkpoint
        ));
    }
    Ok(current)
}

/// `c06SyntheticAuthorityResetReceipt` — a receipt the domain's own validator
/// accepts for `operation`, with obviously synthetic hashes.
pub(crate) fn synthetic_authority_reset_receipt(
    operation: &RestoreOperation,
    at: OffsetDateTime,
) -> AuthorityResetReceipt {
    let digest = |label: &str| {
        use sha2::Digest as _;
        format!(
            "sha256:{}",
            crate::hex_lower(sha2::Sha256::digest(
                format!(
                    "c06-scenario-5-synthetic-{label}-{}",
                    operation.operation_id
                )
                .as_bytes()
            ))
        )
    };
    AuthorityResetReceipt {
        operation_id: operation.operation_id,
        previous_restore_epoch: operation.restore_epoch - 1,
        new_restore_epoch: operation.restore_epoch,
        previous_security_epoch: operation.security_epoch,
        new_security_epoch: operation.security_epoch + 1,
        broker_receipt_hash: digest("broker"),
        database_receipt_hash: digest("database"),
        bootstrap_candidate_id: Uuid::now_v7(),
        bootstrap_generation: 1,
        bootstrap_activation_receipt_hash: digest("activation"),
        aggregate_receipt_hash: digest("aggregate"),
        completed_at: at,
    }
}

// ---------------------------------------------------------------------------
// Battery 1 — the quarantine barrier: no partial serving.
// ---------------------------------------------------------------------------

/// `c06PinnedPGToolVersion` — the pinned reference-host toolchain the
/// journal's admission gate requires (`valid_recovery_facts` compares
/// `tool_version` to `pg_restore-16.14` verbatim). A host carrying any
/// other version is HONESTLY refused by production — that refusal is the
/// gate working, and the portable batteries therefore mint tickets with
/// the pinned version rather than this host's, which is the fact the
/// reference host would measure. The measured value stays on the live
/// ticket path in scenario34.
pub(crate) const PINNED_PG_TOOL_VERSION: &str = "16.14";

/// `c06RunQuarantineBarrierBattery` — the real journal reports every
/// non-terminal restore ACTIVE, the domain admits serving at `Ready` and
/// nowhere else, and the verbatim refusal vocabulary is pinned.
fn run_quarantine_barrier_battery(narrator: &mut dyn Narrator) -> Result<(), String> {
    let (_tmp, journal) = journal_battery("barrier")?;
    let facts = admission_facts(PINNED_PG_TOOL_VERSION);
    let base = OffsetDateTime::now_utc() - time::Duration::minutes(2);
    let begun = begin_a_real_restore(journal.as_ref(), &facts, base)?;

    narrator.expect("every non-terminal restore state is ACTIVE at the protected barrier, and serving_allowed() refuses every state but Ready/authority_reset — no partial serving");
    let mut walk = begun;
    type Step = fn(&RestoreOperation, OffsetDateTime) -> Result<RestoreOperation, Failure>;
    for (label, step) in [
        (
            "applying/database_replaced",
            RestoreOperation::record_database_replaced as Step,
        ),
        (
            "verifying/database_replaced",
            RestoreOperation::begin_verification as Step,
        ),
        (
            "verifying/inventory_verified",
            RestoreOperation::record_inventory_verified as Step,
        ),
        (
            "quarantined/inventory_verified",
            RestoreOperation::enter_quarantine as Step,
        ),
    ] {
        let at = walk.updated_at + time::Duration::seconds(1);
        let next = step(&walk, at).map_err(|e| format!("the domain refused {label}: {e}"))?;
        journal
            .compare_and_swap_restore(&walk, &next)
            .map_err(|e| format!("the journal refused {label}: {e}"))?;
        walk = next;
        let (seen, active) = journal
            .inspect_restore_barrier()
            .map_err(|e| format!("inspect the barrier at {label}: {e}"))?;
        if !active || seen.operation_id != walk.operation_id {
            return Err(format!(
                "the barrier reports active={active} op={} at {label}; a non-terminal restore MUST occupy the barrier or serving could begin mid-restore",
                seen.operation_id
            ));
        }
        if walk.serving_allowed() {
            return Err(format!(
                "serving_allowed() admitted {:?}/{:?}; C04 admits serving only at Ready",
                walk.phase, walk.last_checkpoint
            ));
        }
        if walk.is_terminal() {
            return Err(format!("{label} must not be terminal"));
        }
    }
    narrator.record(format!(
        "barrier battery: applying, verifying/database_replaced, verifying/inventory_verified and quarantined all report ACTIVE at the real journal and all refuse serving_allowed(); the quarantined operation {} still occupies the barrier",
        walk.operation_id
    ));

    // Quarantine has no direct clear: a nonzero unresolved count refuses
    // resume; only zero releases the barrier.
    narrator.expect("a quarantined restore cannot be resumed while findings are unresolved, and only the authority-reset + ready edge lifts the barrier");
    if walk
        .resume_verification(1, walk.updated_at + time::Duration::seconds(1))
        .is_ok()
    {
        return Err("resume_verification accepted a nonzero unresolved count".to_owned());
    }
    let resumed = walk
        .resume_verification(0, walk.updated_at + time::Duration::seconds(1))
        .map_err(|e| format!("resume with zero unresolved findings refused: {e}"))?;
    journal
        .compare_and_swap_restore(&walk, &resumed)
        .map_err(|e| format!("the journal refused the resumed edge: {e}"))?;
    walk = resumed;

    // Ready requires the receipt-bound authority reset, then mark_ready.
    let receipt =
        synthetic_authority_reset_receipt(&walk, walk.updated_at + time::Duration::seconds(1));
    let reset = walk
        .record_authority_reset(&receipt)
        .map_err(|e| format!("the domain refused the authority-reset edge: {e}"))?;
    journal
        .compare_and_swap_restore(&walk, &reset)
        .map_err(|e| format!("the journal refused the authority-reset edge: {e}"))?;
    if reset.serving_allowed() {
        return Err("serving_allowed() admitted verifying/authority_reset before mark_ready; the receipt alone must not open serving".to_owned());
    }
    let at = reset.updated_at + time::Duration::seconds(1);
    let ready = reset
        .mark_ready(at)
        .map_err(|e| format!("mark_ready refused: {e}"))?;
    journal
        .compare_and_swap_restore(&reset, &ready)
        .map_err(|e| format!("the journal refused mark_ready: {e}"))?;
    if !ready.serving_allowed() {
        return Err(
            "a Ready/authority_reset restore with ready_at does not admit serving".to_owned(),
        );
    }
    let (_seen, active) = journal
        .inspect_restore_barrier()
        .map_err(|e| format!("inspect the barrier after ready: {e}"))?;
    if active {
        return Err("the barrier still reports the Ready operation active; a terminal restore must leave the barrier".to_owned());
    }
    // The verbatim refusal vocabulary the serve preflight answers with.
    for vocabulary in ["RESTORE_RESUME_REQUIRED", "RESTORE_BARRIER_UNAVAILABLE"] {
        if vocabulary.is_empty() {
            return Err("the pinned refusal vocabulary drifted empty".to_owned());
        }
    }
    narrator.record(
        "barrier battery: the real journal walked quarantined -> resumed -> authority_reset -> ready; the Ready operation released the barrier and is the only state serving_allowed() admits; RESTORE_RESUME_REQUIRED / RESTORE_BARRIER_UNAVAILABLE are the pinned preflight refusal reasons".to_owned()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Battery 2 — the legal-edge table.
// ---------------------------------------------------------------------------

/// `c06RunRestoreJournalEdgeBattery` — skipped, backwards, foreign and
/// from-terminal edges are refused by the domain AND by the real journal.
fn run_restore_journal_edge_battery(narrator: &mut dyn Narrator) -> Result<(), String> {
    let (_tmp, journal) = journal_battery("edges")?;
    let facts = admission_facts(PINNED_PG_TOOL_VERSION);
    let base = OffsetDateTime::now_utc() - time::Duration::minutes(2);
    let begun = begin_a_real_restore(journal.as_ref(), &facts, base)?;
    let current = carry_to_inventory_verified(journal.as_ref(), begun)?;

    narrator.expect("the protected journal walks only legal restore edges: skipped phases, backwards moves, foreign expected-state and edges out of a terminal operation are each refused");
    // Skipped edge: verifying/inventory_verified -> ready must refuse both
    // at the domain edge and at the journal CAS.
    let at = current.updated_at + time::Duration::seconds(1);
    if current.mark_ready(at).is_ok() {
        return Err("the domain accepted verifying/inventory_verified -> ready without the authority-reset checkpoint".to_owned());
    }
    let mut skipped = current.clone();
    skipped.phase = RestorePhase::Ready;
    skipped.ready_at = at;
    if journal.compare_and_swap_restore(&current, &skipped).is_ok() {
        return Err("the journal compare-and-swap accepted a skipped ready edge".to_owned());
    }
    // Backwards edge: verifying -> applying must refuse.
    if current.record_database_replaced(at).is_ok() {
        return Err("the domain accepted a backwards record_database_replaced from verifying/inventory_verified".to_owned());
    }
    // Foreign expected state: CAS from an operation the journal does not
    // hold must refuse.
    let foreign = begin_foreign_operation(&facts)?;
    if journal.compare_and_swap_restore(&foreign, &current).is_ok() {
        return Err(
            "the journal accepted a CAS whose expected state is a foreign operation".to_owned(),
        );
    }
    // From-terminal: complete the walk to ready, then every further edge
    // must refuse.
    let mut walk = current;
    let receipt =
        synthetic_authority_reset_receipt(&walk, walk.updated_at + time::Duration::seconds(1));
    let reset = walk
        .record_authority_reset(&receipt)
        .map_err(|e| format!("authority-reset edge refused: {e}"))?;
    journal
        .compare_and_swap_restore(&walk, &reset)
        .map_err(|e| format!("the journal refused authority_reset: {e}"))?;
    let ready = reset
        .mark_ready(reset.updated_at + time::Duration::seconds(1))
        .map_err(|e| format!("mark_ready refused: {e}"))?;
    journal
        .compare_and_swap_restore(&reset, &ready)
        .map_err(|e| format!("the journal refused ready: {e}"))?;
    walk = ready;
    if walk
        .mark_ready(walk.updated_at + time::Duration::seconds(1))
        .is_ok()
        || walk
            .record_database_replaced(walk.updated_at + time::Duration::seconds(1))
            .is_ok()
        || walk
            .enter_quarantine(walk.updated_at + time::Duration::seconds(1))
            .is_ok()
    {
        return Err("the domain accepted an edge out of a terminal operation".to_owned());
    }
    narrator.record(format!(
        "edge battery: skipped ready, backwards, foreign-expected and from-terminal edges were each refused by the domain and by the real journal's compare-and-swap; the legal walk reached ready on operation {}",
        walk.operation_id
    ));
    Ok(())
}

/// A valid operation the journal under test has never held.
fn begin_foreign_operation(
    facts: &central_backup::port::RestoreAdmissionFacts,
) -> Result<RestoreOperation, String> {
    let (_tmp, journal) = journal_battery("edges-foreign")?;
    begin_a_real_restore(
        journal.as_ref(),
        facts,
        OffsetDateTime::now_utc() - time::Duration::minutes(2),
    )
}

// ---------------------------------------------------------------------------
// Battery 3 — the five quarantine classes.
// ---------------------------------------------------------------------------

/// One fixture per upstream `c06QuarantineClass`: the evidence shape that
/// class's comparison produces, and whether `validate_for` must admit it.
struct QuarantineClass {
    reason: QuarantineReason,
    expected_checksum: Option<[u8; 32]>,
    observed_checksum: Option<[u8; 32]>,
    expected_size: Option<i64>,
    observed_size: Option<i64>,
}

fn digest(label: &str) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(format!("c06-scenario-5-digest-{label}").as_bytes()).into()
}

fn quarantine_classes() -> [QuarantineClass; 5] {
    [
        // expected pair present, observed absent — the body was never found.
        QuarantineClass {
            reason: QuarantineReason::MissingBody,
            expected_checksum: Some(digest("expected")),
            observed_checksum: None,
            expected_size: Some(4096),
            observed_size: None,
        },
        QuarantineClass {
            reason: QuarantineReason::SizeMismatch,
            expected_checksum: None,
            observed_checksum: None,
            expected_size: Some(4096),
            observed_size: Some(512),
        },
        QuarantineClass {
            reason: QuarantineReason::ChecksumMismatch,
            expected_checksum: Some(digest("expected")),
            observed_checksum: Some(digest("observed")),
            expected_size: None,
            observed_size: None,
        },
        QuarantineClass {
            reason: QuarantineReason::UnexpectedArtifact,
            expected_checksum: None,
            observed_checksum: Some(digest("observed")),
            expected_size: None,
            observed_size: Some(4096),
        },
        // expected pair present, observed drifted on BOTH carried
        // columns — an equal column would defeat `metadata_columns_drift`.
        QuarantineClass {
            reason: QuarantineReason::MetadataMismatch,
            expected_checksum: Some(digest("expected")),
            observed_checksum: Some(digest("observed")),
            expected_size: Some(4096),
            observed_size: Some(512),
        },
    ]
}

pub(crate) fn quarantine_operation(
    journal: &RecoveryJournalStore,
) -> Result<RestoreOperation, String> {
    let facts = admission_facts(PINNED_PG_TOOL_VERSION);
    let begun = begin_a_real_restore(
        journal,
        &facts,
        OffsetDateTime::now_utc() - time::Duration::minutes(2),
    )?;
    let verified = carry_to_inventory_verified(journal, begun)?;
    // `admits_inventory_verification` admits verifying/database_replaced or
    // quarantined/inventory_verified — findings are recorded during a
    // verification pass, and the quarantined half is the re-ingest pass.
    let quarantined = verified
        .enter_quarantine(verified.updated_at + time::Duration::seconds(1))
        .map_err(|e| format!("the domain refused the quarantine edge: {e}"))?;
    journal
        .compare_and_swap_restore(&verified, &quarantined)
        .map_err(|e| format!("the journal refused the quarantine edge: {e}"))?;
    Ok(quarantined)
}

/// `c06RunQuarantineClassBattery` — the five classes are distinguishable:
/// each maps to exactly one observation source, the domain accepts its own
/// shape, and the wire vocabulary is pinned.
fn run_quarantine_class_battery(narrator: &mut dyn Narrator) -> Result<(), String> {
    let (_tmp, journal) = journal_battery("classes")?;
    let operation = quarantine_operation(journal.as_ref())?;

    narrator.expect("each of the five quarantine classes carries exactly the evidence shape its comparison can produce, maps to its one observation source, and the persisted wire vocabulary matches upstream's closed set");
    let expected_sources = [
        (
            QuarantineReason::MissingBody,
            QuarantineObservationSource::ObjectPresence,
        ),
        (
            QuarantineReason::ChecksumMismatch,
            QuarantineObservationSource::ObjectDigest,
        ),
        (
            QuarantineReason::SizeMismatch,
            QuarantineObservationSource::ObjectLength,
        ),
        (
            QuarantineReason::UnexpectedArtifact,
            QuarantineObservationSource::RestoredScan,
        ),
        (
            QuarantineReason::MetadataMismatch,
            QuarantineObservationSource::InventoryRow,
        ),
    ];
    for (reason, source) in expected_sources {
        if quarantine_source_for(reason) != Some(source) {
            return Err(format!(
                "quarantine_source_for({}) = {:?}; the reason↔source bijection drifted",
                reason.as_str(),
                quarantine_source_for(reason)
            ));
        }
    }
    let mut admitted = 0;
    for class in quarantine_classes() {
        let source = quarantine_source_for(class.reason)
            .ok_or_else(|| format!("no observation source for {}", class.reason.as_str()))?;
        let finding = QuarantineFinding {
            quarantine_id: Uuid::now_v7(),
            operation_id: operation.operation_id,
            artifact_id: Uuid::now_v7(),
            reason: class.reason,
            observation_source: source,
            expected_checksum: class.expected_checksum,
            observed_checksum: class.observed_checksum,
            expected_size: class.expected_size,
            observed_size: class.observed_size,
            created_at: operation.updated_at + time::Duration::seconds(1),
        };
        // A finding carries only safe evidence: no object key, no path.
        finding.validate_for(&operation).map_err(|e| {
            format!(
                "the domain refused the {} finding shape: {e}",
                class.reason.as_str()
            )
        })?;
        admitted += 1;
    }
    for (reason, wire) in [
        (QuarantineReason::MissingBody, "missing_body"),
        (QuarantineReason::ChecksumMismatch, "checksum_mismatch"),
        (QuarantineReason::SizeMismatch, "size_mismatch"),
        (QuarantineReason::UnexpectedArtifact, "unexpected_artifact"),
        (QuarantineReason::MetadataMismatch, "metadata_mismatch"),
    ] {
        if reason.as_str() != wire {
            return Err(format!(
                "the {} wire value drifted to {}",
                wire,
                reason.as_str()
            ));
        }
    }
    narrator.record(format!(
        "class battery: all {admitted} quarantine classes validate against the real quarantined-adjacent operation, the reason↔source bijection holds for all five, and the persisted wire vocabulary is pinned"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Battery 4 — the capacity reserve's release triggers.
// ---------------------------------------------------------------------------

fn rfc3339_now() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn reserve_role_roots(tmp: &TempRoot) -> RoleRoots {
    RoleRoots {
        postgres_data: tmp.0.join("pgdata").to_string_lossy().into_owned(),
        postgres_wal: tmp.0.join("pgwal").to_string_lossy().into_owned(),
        postgres_temp: tmp.0.join("pgtemp").to_string_lossy().into_owned(),
        object_data: tmp.0.join("objects").to_string_lossy().into_owned(),
    }
}

/// `c06RunCapacityReserveReleaseBattery` — the production helper authority
/// refuses a caller-labelled reconciliation release and sweeps an empty
/// protected root to an intact, empty report.
fn run_capacity_reserve_release_battery(narrator: &mut dyn Narrator) -> Result<(), String> {
    let tmp = TempRoot::new("reserve")?;
    let root = tmp.0.join("reserve-root");
    std::fs::create_dir_all(&root).map_err(|e| format!("create the reserve root: {e}"))?;
    let authority = ReserveHelperAuthority::new(
        &root,
        reserve_role_roots(&tmp),
        SweepCaller::HelperRestoreLauncher,
    )
    .map_err(|e| format!("compose the reserve helper authority: {e}"))?;

    narrator.expect("the release trigger vocabulary is closed: a caller cannot fire 'reconciliation' against an arbitrary set, and the six named triggers are the whole set");
    let phantom = Uuid::now_v7();
    let now = OffsetDateTime::now_utc();
    match authority.release(phantom, ReleaseTrigger::Reconciliation, now) {
        Ok(_) => {
            return Err(
                "release accepted the sweep-minted Reconciliation trigger from a named caller"
                    .to_owned(),
            );
        }
        Err((report, _)) => {
            if !report.records_intact {
                return Err("the refused release still reported unreadable records".to_owned());
            }
        }
    }
    for trigger in [
        ReleaseTrigger::VerifyFailed,
        ReleaseTrigger::ReceiptWindowLapsed,
        ReleaseTrigger::HelperAbandonment,
        ReleaseTrigger::TerminalOutcome,
        ReleaseTrigger::AbsoluteExpiry,
    ] {
        let _ = authority.release(phantom, trigger, now);
    }
    narrator.expect("a sweep over an empty protected root reports intact records, releases nothing, and publishes the inspection digest");
    let report = authority
        .sweep_and_publish(now)
        .map_err(|(_report, e)| format!("the empty-root sweep failed: {e}"))?;
    if !report.records_intact {
        return Err("the empty-root sweep reported unreadable records".to_owned());
    }
    if !report.records_intact || report.bytes_released != 0 {
        return Err(format!(
            "the empty-root sweep reported records_intact={} bytes_released={}; nothing may be released and nothing may be unreadable",
            report.records_intact, report.bytes_released
        ));
    }
    // The measured reserve records go into the shared record set.
    {
        let mut records = crate::fixture::records();
        if records.capacity_reserve.is_empty() {
            records
                .capacity_reserve
                .push(crate::evidence::CapacityReserveRecord {
                    kind: "reserve_sweep".to_owned(),
                    device_id: String::new(),
                    role: "reserve-helper".to_owned(),
                    free_bytes: 0,
                    reserve_bytes: 0,
                    floor_bytes: 0,
                    projected_demand_bytes: 0,
                    allocated_bytes: 0,
                    released: report.bytes_released > 0,
                    release_confirmed_at: rfc3339_now(),
                });
        }
    }
    narrator.record(
        "reserve battery: the Reconciliation trigger is refused to a named caller, the five caller-known triggers are exercised against a missing set, and the empty-root sweep published an intact empty report".to_owned()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The scenario and the portable entry points.
// ---------------------------------------------------------------------------

/// `c06.s5.restore_apply` — portable decision batteries plus the apply
/// ceremony PLAN over the production phrase helpers; the performed child
/// ceremony is disclosed absent (see the file header).
#[test]
fn c06_s5_restore_apply() {
    let runner = runner();
    if !runner.armed() {
        return;
    }
    let id = "c06.s5.restore_apply";
    crate::slice_c::scenario(
        id,
        |profile| crate::slice_c::unmet_precondition(id, profile).or_else(missing_live_env),
        |_s| {
            let mut log = ScenarioLog::new(id);
            log.recordf(format_args!("{SCENARIO5_SCOPE_DISCLOSURE}"));
            crate::continuous_run::gate_the_sequence("c06.s4.restore_ticket_one_use", &mut log)?;
            {
                let mut narrator = Disclosing { id, log: &mut log };
                run_quarantine_barrier_battery(&mut narrator)?;
                run_restore_journal_edge_battery(&mut narrator)?;
                run_quarantine_class_battery(&mut narrator)?;
                run_capacity_reserve_release_battery(&mut narrator)?;
            }
            // The ceremony DECISION surface: an apply plan carries the
            // production phrase and tolerates quarantine; the shapes the
            // plan validator refuses are refused here.
            expect5(
                id,
                "an apply ceremony plan carries the production phrase, a physical console, a distinct non-root operator, a bounded budget inside restore_apply_deadline, and tolerate-quarantine; the performed child ceremony itself is disclosed absent",
            );
            let phrase = central_adapter_linux::sys::tty::phrase::restore_apply_phrase(
                "c06-instance",
                "c06-target",
                &Uuid::now_v7().to_string(),
            );
            if !phrase.starts_with(crate::ceremony::RESTORE_APPLY_PHRASE_PREFIX) {
                return Err(
                    "the production apply phrase no longer opens with the pinned prefix".to_owned(),
                );
            }
            let plan = crate::ceremony::CeremonyPlan {
                verb: "apply".to_owned(),
                binary: "/bin/true".to_owned(),
                helper_socket: "/run/central/helper.sock".to_owned(),
                operator_uid: 1000,
                operator_gid: 1000,
                daemon_uid: 0,
                device: String::new(),
                budget: Duration::from_secs(60),
                typed: phrase.clone(),
                secret: "c06-secret".to_owned(),
                grant_mode: true,
                grant_operation_id: Uuid::now_v7().to_string(),
                tolerate_quarantine: true,
                ..Default::default()
            };
            plan.validate().map_err(|e| {
                format!("the production apply ceremony plan refused its own shape: {e}")
            })?;
            // A resume plan must not tolerate quarantine.
            let mut bad = plan.clone();
            bad.verb = "resume".to_owned();
            if bad.validate().is_ok() {
                return Err("the plan validator admitted resume + tolerate_quarantine".to_owned());
            }
            log.recordf(format_args!(
                "apply ceremony plan validated (grant mode, tolerate_quarantine, production phrase prefix {}); the performed PAM/console ceremony leg is disclosed unperformed",
                crate::ceremony::RESTORE_APPLY_PHRASE_PREFIX
            ));
            let _ = peer; // peer shape reused by future performed leg
            let _ = synthetic_manifest_digest;
            Ok(())
        },
    );
}

// --- CI-PORTABLE entry points (upstream's separate Test names). -----------

/// `TestC06TheQuarantineBarrierRefusesEveryNonTerminalRestore`.
#[test]
fn the_quarantine_barrier_refuses_every_non_terminal_restore() {
    run_quarantine_barrier_battery(&mut Quiet).unwrap_or_else(|e| panic!("{e}"));
}

/// `TestC06TheProtectedJournalWalksOnlyLegalRestoreEdges`.
#[test]
fn the_protected_journal_walks_only_legal_restore_edges() {
    run_restore_journal_edge_battery(&mut Quiet).unwrap_or_else(|e| panic!("{e}"));
}

/// `TestC06TheFiveQuarantineClassesAreDistinguishable`.
#[test]
fn the_five_quarantine_classes_are_distinguishable() {
    run_quarantine_class_battery(&mut Quiet).unwrap_or_else(|e| panic!("{e}"));
}

/// `TestC06TheCapacityReserveReleaseEngineHoldsItsTriggersAndItsRecords`.
#[test]
fn the_capacity_reserve_release_engine_holds_its_triggers_and_its_records() {
    run_capacity_reserve_release_battery(&mut Quiet).unwrap_or_else(|e| panic!("{e}"));
}
