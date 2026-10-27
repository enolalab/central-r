//! `cmd/central/c06_scenario6_authority_reset_test.go` — C06 scenario 6: the
//! post-restore authority reset (C05).
//!
//! WHAT IS PORTED VERBATIM.
//!   - Battery 1: `AuthorityResetReceipt::validate_for` accepts the valid
//!     receipt and refuses every single-field perturbation (all 12 fields)
//!     plus the four epoch axes at offsets -2..=2 (exactly one accepted each).
//!   - Battery 2: the aggregate receipt digest binds all eleven substep
//!     components — restated payload, digest moves per component — and the
//!     production [`new_authority_reset_receipt`] recomputation is the value
//!     pin (the producer is a public domain function here, so the binding is
//!     checked against the real constructor rather than a disk read).
//!   - Battery 3: the broker half over a real [`Service`] and protected root —
//!     prepare re-keys durable TLS (control root unmoved), a second prepare
//!     returns the identical draft without re-keying, one generation activates
//!     exactly once with idempotent replay, and foreign generations deny.
//!   - Battery 5: the recorder refuses a census that cannot be a measurement
//!     (zero before-count, unread side, residue, stalled/skipped epochs, no
//!     rekey, generation delta != 1, malformed digest, double record).
//!   - The live leg (DSN-gated): the census plan seeds every counted category,
//!     the real [`AuthorityResetCoordinator`] resets over the real broker and
//!     real [`RecoveryAuditStore`], epochs/fences/generation-delta/readbacks
//!     are measured from the database on both sides, and governance field 26
//!     is recorded through the recorder.
//!
//! THE ADAPTATIONS, EACH DISCLOSED IN THE SCENARIO LOG.
//!
//! 1. Battery 4's AST-walk of the producer source has no Rust analogue that
//!    is meaningful here: the census plan's TOTALITY is instead asserted
//!    against the migration-declared schema surface, and the seven emitter
//!    fields are pinned to [`crate::evidence::InvalidatedCounts`]' serde
//!    names — the Rust equivalent of pinning `recovery.InvalidatedCounts`.
//!    The live-predicate grounding markers are pinned to the reset's own
//!    statement text constants declared beside the plan.
//! 2. The pre-restore session-token leg uses the production
//!    [`PgSessionStore`] over a `PgPool` built for the leg; the invalidation
//!    census itself reads through `BlockingConn`, exactly as scenario 2 does.
//! 3. Fingerprint-bracket/scenario-7 interplay (upstream's footprint) belongs
//!    to T10d; the unconditional-relations lower bound is carried as the
//!    plan's declared table and recorded, not asserted against a bracket this
//!    slice does not run.
//! 4. No sealed backup exists (no throughput gate): ticket admission facts
//!    are synthetic, as scenarios 3/4/5 disclose.

use std::collections::BTreeMap;
use std::sync::Arc;

use sha2::Digest;
use time::OffsetDateTime;
use uuid::Uuid;

use central_adapter_linux::broker::server::Service;
use central_adapter_postgres::recovery::RecoveryAuditStore;
use central_adapter_postgres::session::PgSessionStore;
use central_adapter_postgres::store_support::BlockingConn;
use central_backup::app::AuthorityResetCoordinator;
use central_backup::port::{
    BrokerAuthorityReset, PostgresAuthorityReset, RestoreJournalStore as _,
};
use central_backup::recovery::operation::{
    AuthorityResetReceipt, RecoveryBootstrapRegistration, RestoreOperation,
    new_authority_reset_receipt,
};
use central_backup::recovery::operation::{RecoveryBootstrapActivation, RecoveryBootstrapDraft};
use central_foundation::failure::Failure;
use central_session::port::SessionStore as _;

use crate::runner::runner;
use crate::scenario2::{ScenarioLog, connect_pg, missing_live_env};
use crate::scenario5::{PINNED_PG_TOOL_VERSION, carry_to_inventory_verified, journal_battery};
use crate::scenario34::{
    TempRoot, admission_facts, begin_a_real_restore, synthetic_manifest_digest,
};

pub(crate) const SCENARIO6_SCOPE_DISCLOSURE: &str = "SCOPE, CARRIED ON EVERY DIVERGENCE THIS SCENARIO EMITS: the batteries prove production DECISIONS — the domain receipt validator, the aggregate-hash binding against the real producer constructor, the real broker's re-key/single-candidate/single-activation behaviour, and the recorder's refusal rules — and the DSN-gated live leg measures the real C05 reset through AuthorityResetCoordinator + RecoveryAuditStore. Adaptations: census totality is pinned to the emitter's serde fields and the reset's own statement-text constants (no AST walk exists for Rust); the session-token leg reads through PgSessionStore on a dedicated pool; the fingerprint bracket upstream opens for scenario 7 is deferred to T10d and recorded, not asserted. Ticket admission facts are synthetic (no sealed backup can be produced).";

fn expect6(id: &str, what: impl AsRef<str>) {
    runner().attach_divergence(
        id,
        &format!("{}. {}", what.as_ref(), SCENARIO6_SCOPE_DISCLOSURE),
    );
}

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
        expect6(self.id, what);
    }
    fn record(&mut self, what: String) {
        self.log.recordf(format_args!("{what}"));
    }
}

// ---------------------------------------------------------------------------
// Shared fixtures.
// ---------------------------------------------------------------------------

fn journal_at(
    root: &std::path::Path,
) -> Result<Arc<central_adapter_linux::broker::recovery_journal::RecoveryJournalStore>, String> {
    let signing = Arc::new(
        central_adapter_linux::broker::signing::SigningService::new_persistent(root)
            .map_err(|e| format!("compose the signing service: {e}"))?,
    );
    Ok(Arc::new(
        central_adapter_linux::broker::recovery_journal::RecoveryJournalStore::new(
            root,
            signing,
            central_adapter_linux::broker::protected_file::ProtectedFileBackend::new(
                root.to_path_buf(),
            ),
        )
        .map_err(|e| format!("compose the journal over the service's root: {e}"))?,
    ))
}

fn s6_digest(label: &str) -> String {
    format!(
        "sha256:{}",
        crate::hex_lower(sha2::Sha256::digest(
            format!("c06-scenario-6-synthetic-{label}").as_bytes()
        ))
    )
}

/// `c06BeginARestoreInThePast` — the -2min base is load-bearing (upstream):
/// `new_broker_reset_record` refuses a `committed_at` before the operation's
/// own `updated_at`, and `committed_at` comes from `now()`.
fn begin_a_restore_in_the_past(
    journal: &central_adapter_linux::broker::recovery_journal::RecoveryJournalStore,
) -> Result<RestoreOperation, String> {
    let facts = admission_facts(PINNED_PG_TOOL_VERSION);
    let base = OffsetDateTime::now_utc() - time::Duration::minutes(2);
    let ticket = journal
        .issue(
            Uuid::now_v7(),
            &synthetic_manifest_digest("authority-reset"),
            &facts,
            Uuid::nil(),
            base,
        )
        .map_err(|e| format!("mint the ticket: {e}"))?;
    let authorization = journal
        .issue_restore_apply_authorization_for_operation(
            ticket.operation_id,
            rustix::process::getuid().as_raw(),
            i32::try_from(std::process::id()).unwrap_or(i32::MAX),
            base + time::Duration::seconds(1),
        )
        .map_err(|e| format!("record the apply authorization: {e}"))?;
    journal
        .begin(&ticket, &authorization, base + time::Duration::seconds(2))
        .map_err(|e| format!("begin the restore: {e}"))
}

/// `c06ResetReceiptFixture` — an operation at verifying/inventory_verified
/// (in-memory walk, no journal needed for the pure-validator batteries) and
/// a receipt the domain's own validator accepts.
fn reset_receipt_fixture() -> Result<(RestoreOperation, AuthorityResetReceipt), String> {
    let (_tmp, journal) = journal_battery("s6-fixture")?;
    let facts = admission_facts(PINNED_PG_TOOL_VERSION);
    let begun = begin_a_real_restore(
        &journal,
        &facts,
        OffsetDateTime::now_utc() - time::Duration::minutes(2),
    )?;
    let operation = carry_to_inventory_verified(&journal, begun)?;
    let receipt = AuthorityResetReceipt {
        operation_id: operation.operation_id,
        previous_restore_epoch: operation.restore_epoch - 1,
        new_restore_epoch: operation.restore_epoch,
        previous_security_epoch: operation.security_epoch,
        new_security_epoch: operation.security_epoch + 1,
        broker_receipt_hash: s6_digest("broker"),
        database_receipt_hash: s6_digest("database"),
        bootstrap_candidate_id: Uuid::now_v7(),
        bootstrap_generation: 1,
        bootstrap_activation_receipt_hash: s6_digest("activation"),
        aggregate_receipt_hash: s6_digest("aggregate"),
        completed_at: operation.updated_at + time::Duration::seconds(1),
    };
    receipt
        .validate_for(&operation)
        .map_err(|e| format!("the fixture receipt is not valid for its operation: {e}"))?;
    Ok((operation, receipt))
}

// ---------------------------------------------------------------------------
// Battery 1 — the receipt binds its operation and its epochs.
// ---------------------------------------------------------------------------

fn run_reset_receipt_battery(narrator: &mut dyn Narrator) -> Result<(), String> {
    let (operation, valid) = reset_receipt_fixture()?;
    narrator.expect("the domain's own receipt validator accepts the valid reset receipt for its operation and refuses every single-field perturbation of it, one field at a time");

    // One row per field of AuthorityResetReceipt — 12 fields.
    type Mutation = (&'static str, Box<dyn Fn(&mut AuthorityResetReceipt)>);
    let mut mutations: Vec<Mutation> = Vec::new();
    mutations.push((
        "operation_id",
        Box::new(|r| r.operation_id = Uuid::now_v7()),
    ));
    mutations.push((
        "previous_restore_epoch",
        Box::new(move |r| {
            r.previous_restore_epoch = operation.restore_epoch - 2;
        }),
    ));
    mutations.push((
        "new_restore_epoch",
        Box::new(move |r| {
            r.new_restore_epoch = operation.restore_epoch + 1;
        }),
    ));
    mutations.push((
        "previous_security_epoch",
        Box::new(move |r| {
            r.previous_security_epoch = operation.security_epoch + 5;
        }),
    ));
    mutations.push((
        "new_security_epoch",
        Box::new(move |r| {
            r.new_security_epoch = operation.security_epoch;
        }),
    ));
    mutations.push((
        "broker_receipt_hash",
        Box::new(|r| r.broker_receipt_hash.clear()),
    ));
    mutations.push((
        "database_receipt_hash",
        Box::new(|r| r.database_receipt_hash.clear()),
    ));
    mutations.push((
        "bootstrap_candidate_id",
        Box::new(|r| r.bootstrap_candidate_id = Uuid::nil()),
    ));
    mutations.push((
        "bootstrap_generation",
        Box::new(|r| r.bootstrap_generation = 0),
    ));
    mutations.push((
        "bootstrap_activation_receipt_hash",
        Box::new(|r| {
            r.bootstrap_activation_receipt_hash.clear();
        }),
    ));
    mutations.push((
        "aggregate_receipt_hash",
        Box::new(|r| r.aggregate_receipt_hash.clear()),
    ));
    mutations.push((
        "completed_at",
        Box::new(move |r| {
            r.completed_at = operation.updated_at - time::Duration::seconds(1);
        }),
    ));
    for (field, apply) in &mutations {
        let mut perturbed = valid.clone();
        apply(&mut perturbed);
        if perturbed.validate_for(&operation).is_ok() {
            return Err(format!(
                "the domain's validator ACCEPTED a reset receipt whose {field} was perturbed"
            ));
        }
    }
    narrator.record(format!(
        "the domain's receipt validator refused all {} single-field perturbations and accepted the unperturbed receipt",
        mutations.len()
    ));

    narrator.expect("each of the four epoch fields is an equality against the operation's own epochs, and the domain refuses every offset from it in both directions");
    let mut accepted = 0usize;
    let mut refused = 0usize;
    for (field, security, want) in [
        ("previous_restore_epoch", false, -1i64),
        ("new_restore_epoch", false, 0),
        ("previous_security_epoch", true, 0),
        ("new_security_epoch", true, 1),
    ] {
        let base = if security {
            operation.security_epoch
        } else {
            operation.restore_epoch
        } as i64;
        for offset in -2i64..=2 {
            let mut candidate = valid.clone();
            let value = (base + offset) as u64;
            match field {
                "previous_restore_epoch" => candidate.previous_restore_epoch = value,
                "new_restore_epoch" => candidate.new_restore_epoch = value,
                "previous_security_epoch" => candidate.previous_security_epoch = value,
                _ => candidate.new_security_epoch = value,
            }
            let result = candidate.validate_for(&operation);
            if offset == want {
                if result.is_err() {
                    return Err(format!(
                        "the domain REFUSED {field} at the operation's epoch {offset:+}: {result:?}"
                    ));
                }
                accepted += 1;
            } else {
                if result.is_ok() {
                    return Err(format!(
                        "the domain ACCEPTED {field} at the operation's epoch {offset:+}; that field is an equality"
                    ));
                }
                refused += 1;
            }
        }
    }
    if accepted == 0 || refused == 0 {
        return Err(format!(
            "the epoch table saw {accepted} accepted and {refused} refused; a table with nothing on one side proves nothing"
        ));
    }
    narrator.record(format!(
        "the four epoch axes were decided by the domain: {accepted} offsets accepted, {refused} refused"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Battery 2 — the aggregate hash binds every substep.
// ---------------------------------------------------------------------------

/// `c06AggregatePayload` — the exact payload the production
/// `new_authority_reset_receipt` encodes, field order included.
#[derive(serde::Serialize)]
struct AggregatePayload {
    operation_id: String,
    previous_restore_epoch: u64,
    new_restore_epoch: u64,
    previous_security_epoch: u64,
    new_security_epoch: u64,
    broker_receipt_hash: String,
    database_receipt_hash: String,
    candidate_id: String,
    generation: u64,
    activation_receipt_hash: String,
    completed_at: String,
}

fn aggregate_digest(payload: &AggregatePayload) -> Result<String, String> {
    let encoded =
        serde_json::to_vec(payload).map_err(|e| format!("encode the aggregate payload: {e}"))?;
    Ok(format!(
        "sha256:{}",
        crate::hex_lower(sha2::Sha256::digest(&encoded))
    ))
}

fn rfc3339_nano(at: OffsetDateTime) -> String {
    at.to_offset(time::UtcOffset::UTC)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn run_aggregate_binding_battery(narrator: &mut dyn Narrator) -> Result<(), String> {
    let (operation, receipt) = reset_receipt_fixture()?;
    let base = AggregatePayload {
        operation_id: operation.operation_id.to_string(),
        previous_restore_epoch: receipt.previous_restore_epoch,
        new_restore_epoch: receipt.new_restore_epoch,
        previous_security_epoch: receipt.previous_security_epoch,
        new_security_epoch: receipt.new_security_epoch,
        broker_receipt_hash: receipt.broker_receipt_hash.clone(),
        database_receipt_hash: receipt.database_receipt_hash.clone(),
        candidate_id: receipt.bootstrap_candidate_id.to_string(),
        generation: receipt.bootstrap_generation,
        activation_receipt_hash: receipt.bootstrap_activation_receipt_hash.clone(),
        completed_at: rfc3339_nano(receipt.completed_at),
    };
    let baseline = aggregate_digest(&base)?;
    narrator.expect("the aggregate receipt digest moves for a change in every one of the eleven substep components the producer encodes, and does not move when nothing changes");
    if aggregate_digest(&base)? != baseline {
        return Err("the aggregate digest of an unchanged payload moved".to_owned());
    }
    type Component = (&'static str, Box<dyn Fn(&mut AggregatePayload)>);
    let components: Vec<Component> = vec![
        (
            "operation_id",
            Box::new(|p| p.operation_id = Uuid::now_v7().to_string()),
        ),
        (
            "previous_restore_epoch",
            Box::new(|p| p.previous_restore_epoch += 1),
        ),
        ("new_restore_epoch", Box::new(|p| p.new_restore_epoch += 1)),
        (
            "previous_security_epoch",
            Box::new(|p| p.previous_security_epoch += 1),
        ),
        (
            "new_security_epoch",
            Box::new(|p| p.new_security_epoch += 1),
        ),
        (
            "broker_receipt_hash",
            Box::new(|p| p.broker_receipt_hash = s6_digest("other-broker")),
        ),
        (
            "database_receipt_hash",
            Box::new(|p| p.database_receipt_hash = s6_digest("other-database")),
        ),
        (
            "candidate_id",
            Box::new(|p| p.candidate_id = Uuid::now_v7().to_string()),
        ),
        ("generation", Box::new(|p| p.generation += 1)),
        (
            "activation_receipt_hash",
            Box::new(|p| p.activation_receipt_hash = s6_digest("other-activation")),
        ),
        (
            "completed_at",
            Box::new(|p| p.completed_at = "1970-01-01T00:00:00Z".to_owned()),
        ),
    ];
    for (tag, apply) in &components {
        let mut perturbed = AggregatePayload {
            operation_id: base.operation_id.clone(),
            previous_restore_epoch: base.previous_restore_epoch,
            new_restore_epoch: base.new_restore_epoch,
            previous_security_epoch: base.previous_security_epoch,
            new_security_epoch: base.new_security_epoch,
            broker_receipt_hash: base.broker_receipt_hash.clone(),
            database_receipt_hash: base.database_receipt_hash.clone(),
            candidate_id: base.candidate_id.clone(),
            generation: base.generation,
            activation_receipt_hash: base.activation_receipt_hash.clone(),
            completed_at: base.completed_at.clone(),
        };
        apply(&mut perturbed);
        if aggregate_digest(&perturbed)? == baseline {
            return Err(format!(
                "the aggregate receipt digest did NOT move when {tag} changed"
            ));
        }
    }
    narrator.record(format!(
        "the aggregate digest moved for all {} substep components and was stable across two encodings of the same payload",
        components.len()
    ));

    // The VALUE pin: the production constructor's aggregate equals this
    // file's recomputation over the same components.
    narrator.expect("the aggregate the production finalization constructor emits is exactly the digest over the eleven substep components");
    let draft = RecoveryBootstrapDraft {
        operation_id: operation.operation_id,
        draft_id: Uuid::now_v7(),
        candidate_id: receipt.bootstrap_candidate_id,
        verifier_hash: sha2::Sha256::digest(b"c06-s6-verifier").into(),
        candidate_digest: sha2::Sha256::digest(b"c06-s6-candidate").into(),
        broker_receipt_hash: s6_digest("producer-broker"),
        created_at: operation.updated_at + time::Duration::seconds(1),
    };
    draft
        .validate_for(&operation)
        .map_err(|e| format!("the producer-pin draft is invalid: {e}"))?;
    let registration = RecoveryBootstrapRegistration {
        operation_id: operation.operation_id,
        draft_id: draft.draft_id,
        candidate_id: draft.candidate_id,
        generation: 1,
        verifier_hash: draft.verifier_hash,
        candidate_digest: draft.candidate_digest,
        broker_receipt_hash: draft.broker_receipt_hash.clone(),
        database_receipt_hash: s6_digest("producer-database"),
        registered_at: draft.created_at + time::Duration::seconds(1),
    };
    let activation = RecoveryBootstrapActivation {
        operation_id: operation.operation_id,
        draft_id: draft.draft_id,
        candidate_id: draft.candidate_id,
        generation: 1,
        database_receipt_hash: registration.database_receipt_hash.clone(),
        activation_receipt_hash: s6_digest("producer-activation"),
        activated_at: registration.registered_at + time::Duration::seconds(1),
    };
    let produced = new_authority_reset_receipt(
        &operation,
        &registration,
        &activation,
        activation.activated_at + time::Duration::seconds(1),
    )
    .map_err(|e| format!("the production receipt constructor refused the fixture: {e}"))?;
    let recomputed = aggregate_digest(&AggregatePayload {
        operation_id: operation.operation_id.to_string(),
        previous_restore_epoch: produced.previous_restore_epoch,
        new_restore_epoch: produced.new_restore_epoch,
        previous_security_epoch: produced.previous_security_epoch,
        new_security_epoch: produced.new_security_epoch,
        broker_receipt_hash: produced.broker_receipt_hash.clone(),
        database_receipt_hash: produced.database_receipt_hash.clone(),
        candidate_id: produced.bootstrap_candidate_id.to_string(),
        generation: produced.bootstrap_generation,
        activation_receipt_hash: produced.bootstrap_activation_receipt_hash.clone(),
        completed_at: rfc3339_nano(produced.completed_at),
    })?;
    if recomputed != produced.aggregate_receipt_hash {
        return Err(format!(
            "the production aggregate {} differs from the recomputation {}; the payload restatement binds something other than what the producer emits",
            produced.aggregate_receipt_hash, recomputed
        ));
    }
    narrator.record("the production constructor's aggregate digest equals the recomputation over all eleven substep components".to_owned());
    Ok(())
}

// ---------------------------------------------------------------------------
// Battery 3 — the broker half: TLS re-key and the single staged candidate.
// ---------------------------------------------------------------------------

fn broker_tls_fingerprints(root: &std::path::Path) -> Result<(String, String), String> {
    let authority = central_adapter_linux::broker::tls::TlsAuthority::new_persistent(root)
        .map_err(|e| format!("load the persistent TLS authority: {e}"))?;
    let ca = authority
        .ca_fingerprint()
        .map_err(|e| format!("read the broker CA fingerprint: {e}"))?;
    let leaf = authority
        .leaf_fingerprint()
        .map_err(|e| format!("read the broker leaf fingerprint: {e}"))?;
    if ca.len() != 64 || leaf.len() != 64 {
        return Err(format!(
            "the TLS authority reported {ca}/{leaf}, which are not sha-256 hex"
        ));
    }
    Ok((ca, leaf))
}

fn registration_for(
    operation: &RestoreOperation,
    draft: &RecoveryBootstrapDraft,
    generation: u64,
) -> RecoveryBootstrapRegistration {
    RecoveryBootstrapRegistration {
        operation_id: operation.operation_id,
        draft_id: draft.draft_id,
        candidate_id: draft.candidate_id,
        generation,
        verifier_hash: draft.verifier_hash,
        candidate_digest: draft.candidate_digest,
        broker_receipt_hash: draft.broker_receipt_hash.clone(),
        database_receipt_hash: s6_digest("registration-database"),
        registered_at: draft.created_at + time::Duration::seconds(1),
    }
}

fn run_broker_authority_reset_battery(narrator: &mut dyn Narrator) -> Result<(), String> {
    let tmp = TempRoot::new("s6-broker")?;
    let root = tmp.0.join("reset-broker-root");
    // Service::new creates the protected root itself at the private mode.
    let service = Service::new(root.clone(), rustix::process::getuid().as_raw())
        .map_err(|e| format!("compose the broker service: {e}"))?;
    let journal = journal_at(&root)?;
    let begun = begin_a_restore_in_the_past(&journal)?;
    // Carry via the service's journal: the domain walk + CAS through the
    // service-composed journal is upstream's c06CarryARestoreToInventoryVerified.
    let mut current = begun;
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
        let at = current.updated_at + time::Duration::seconds(1);
        let next = step(&current, at).map_err(|e| format!("the domain refused {label}: {e}"))?;
        journal
            .compare_and_swap_restore(&current, &next)
            .map_err(|e| format!("the protected journal refused {label}: {e}"))?;
        current = next;
    }
    let operation = current;

    let control_tmp = TempRoot::new("s6-control")?;
    let control_root = control_tmp.0.join("control-broker-root");
    let _control = Service::new(control_root.clone(), rustix::process::getuid().as_raw())
        .map_err(|e| format!("compose the control broker: {e}"))?;

    let before = broker_tls_fingerprints(&root)?;
    let control_before = broker_tls_fingerprints(&control_root)?;

    narrator.expect("the broker half of the reset re-keys the durable TLS authority -- a different CA and a different active leaf -- while a protected root that was never reset reports the same two fingerprints across the same two reads");
    let draft = service
        .prepare_recovery_broker_authority(&operation)
        .map_err(|e| format!("the broker refused to prepare the reset: {e}"))?;
    draft
        .validate_for(&operation)
        .map_err(|e| format!("the broker returned a draft its own validator refuses: {e}"))?;
    let after = broker_tls_fingerprints(&root)?;
    let control_after = broker_tls_fingerprints(&control_root)?;
    if before.0 == after.0 {
        return Err("the broker CA fingerprint did not change across the reset".to_owned());
    }
    if before.1 == after.1 {
        return Err("the broker's active leaf fingerprint did not change".to_owned());
    }
    if control_before != control_after {
        return Err(format!(
            "the control root's fingerprints moved ({control_before:?} then {control_after:?}) without any reset; the reader is manufacturing a difference"
        ));
    }
    narrator.record("the broker re-keyed: CA and leaf both moved on the reset root, and neither moved on the never-reset control root".to_owned());

    narrator.expect("a second prepare for the same operation returns the identical staged candidate and re-keys nothing, so exactly one candidate is ever staged for one operation");
    let second = service
        .prepare_recovery_broker_authority(&operation)
        .map_err(|e| format!("the broker refused an exact replay of the prepare: {e}"))?;
    if second != draft {
        return Err(format!(
            "a second prepare returned a DIFFERENT draft ({}/{} then {}/{}); two staged candidates for one reset fails the gate",
            draft.draft_id, draft.candidate_id, second.draft_id, second.candidate_id
        ));
    }
    if broker_tls_fingerprints(&root)? != after {
        return Err("a second prepare re-keyed the TLS authority again".to_owned());
    }
    narrator.record(format!(
        "the second prepare returned the identical draft {} and left the TLS material untouched",
        draft.draft_id
    ));

    narrator.expect("once one generation is activated the broker admits an exact replay of it and denies any other generation for the same registration");
    let registration = registration_for(&operation, &draft, 1);
    let activation = service
        .activate_recovery_bootstrap(&operation, &registration)
        .map_err(|e| format!("the broker refused to activate the registered generation: {e}"))?;
    activation
        .validate_for(&operation, &registration)
        .map_err(|e| format!("the broker returned an activation its own validator refuses: {e}"))?;
    let replay = service
        .activate_recovery_bootstrap(&operation, &registration)
        .map_err(|e| format!("an exact replay of the activation was not idempotent: {e}"))?;
    if replay != activation {
        return Err("an exact replay of the activation returned different evidence".to_owned());
    }
    for generation in [2u64, 3, 1 << 20] {
        let other = registration_for(&operation, &draft, generation);
        if service
            .activate_recovery_bootstrap(&operation, &other)
            .is_ok()
        {
            return Err(format!(
                "the broker activated generation {generation} for an operation whose activated generation is {}; a second generation fails the gate",
                registration.generation
            ));
        }
    }
    narrator.record(format!(
        "the broker activated generation {} exactly once, replayed it identically, and denied three other generations for the same operation",
        registration.generation
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Battery 4+5 — the census plan and the recorder.
// ---------------------------------------------------------------------------

/// `c06InvalidationField` — governance field 26's seven counts, manifest order.
const INVALIDATION_FIELDS: [&str; 7] = [
    "sessions",
    "grants",
    "claims",
    "leases",
    "fences",
    "provider_bindings",
    "secret_references",
];

/// `c06InvalidationSubject` — one relation the production reset invalidates,
/// its live predicate, the markers tying the predicate to the reset's own
/// statement text, and the seed that puts one live instance in place.
struct InvalidationSubject {
    relation: &'static str,
    live: &'static str,
    markers: &'static [&'static str],
    seed: Vec<String>,
}

const HASH32: &str = "decode(repeat('7e',32),'hex')";
const EPOCH_GENERATION: i64 = 9060100;
const DOMAIN: &str = "c06-scenario-6-domain";
const PRINCIPAL: &str = "c06-scenario-6-synthetic-operator";
const SESSION_TOKEN_SQL: &str = "decode(repeat('a1',32),'hex')";

fn synthetic_id(role: &str) -> String {
    let sum = sha2::Sha256::digest(format!("c06-scenario-6-synthetic-{role}").as_bytes());
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&sum[..16]);
    raw[6] = (raw[6] & 0x0f) | 0x70;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    Uuid::from_bytes(raw).to_string()
}

fn workspace() -> String {
    central_adapter_postgres::migrate::SENTINEL_WORKSPACE_ID.to_owned()
}

/// `c06InvalidationCensusPlan` — each field's subjects, verbatim from upstream.
fn invalidation_census_plan() -> BTreeMap<&'static str, Vec<InvalidationSubject>> {
    let w = workspace();
    let task = synthetic_id("task");
    let run = synthetic_id("run");
    let attempt = synthetic_id("attempt");
    let physical = synthetic_id("physical-attempt");
    let logical = synthetic_id("logical-operation");
    let invocation = synthetic_id("invocation");
    let snapshot = synthetic_id("snapshot");
    let turn = synthetic_id("provider-turn");
    let binding = synthetic_id("provider-binding");
    let artifact = synthetic_id("artifact");
    let event = synthetic_id("event");
    let outbox = synthetic_id("outbox-entry");
    let ownership = synthetic_id("execution-ownership");
    let decision = synthetic_id("authorization-decision");
    let fence = synthetic_id("fence-consumption");

    let mut plan: BTreeMap<&'static str, Vec<InvalidationSubject>> = BTreeMap::new();
    // The seeds are format-built below; the subject table itself is static.
    let s = seeded_subjects();
    plan.insert("sessions", vec![s.0]);
    plan.insert("grants", vec![s.1]);
    plan.insert("claims", s.2);
    plan.insert("leases", s.3);
    plan.insert("provider_bindings", vec![s.4]);
    plan.insert("fences", vec![s.5]);
    plan.insert("secret_references", vec![s.6]);
    let _ = (
        task, run, attempt, physical, logical, invocation, snapshot, turn, binding, artifact,
        event, outbox, ownership, decision, fence, w,
    );
    plan
}

// The subjects with their built seeds — `c06InvalidationCensusPlan`'s body.
#[allow(clippy::type_complexity)]
fn seeded_subjects() -> (
    InvalidationSubject,
    InvalidationSubject,
    Vec<InvalidationSubject>,
    Vec<InvalidationSubject>,
    InvalidationSubject,
    InvalidationSubject,
    InvalidationSubject,
) {
    let w = workspace();
    let task = synthetic_id("task");
    let run = synthetic_id("run");
    let attempt = synthetic_id("attempt");
    let physical = synthetic_id("physical-attempt");
    let logical = synthetic_id("logical-operation");
    let invocation = synthetic_id("invocation");
    let snapshot = synthetic_id("snapshot");
    let turn = synthetic_id("provider-turn");
    let binding = synthetic_id("provider-binding");
    let artifact = synthetic_id("artifact");
    let event = synthetic_id("event");
    let outbox = synthetic_id("outbox-entry");
    let ownership = synthetic_id("execution-ownership");
    let decision = synthetic_id("authorization-decision");
    let fence = synthetic_id("fence-consumption");

    (
        InvalidationSubject {
            relation: "sessions",
            live: "lifecycle_state IN ('pending_bootstrap','delivery_pending','active')",
            markers: &[
                "SET lifecycle_state='revoked'",
                "WHERE lifecycle_state IN ('pending_bootstrap','delivery_pending','active')",
            ],
            seed: vec![format!(
                "INSERT INTO central.sessions (id,workspace_id,token_hash,csrf_hash,principal_identity,lifecycle_state,idle_expiry,absolute_expiry) VALUES \
(gen_random_uuid(),'{w}'::uuid,{SESSION_TOKEN_SQL},decode(repeat('b2',32),'hex'),'{PRINCIPAL}','active',now()+interval '1 hour',now()+interval '2 hour'),\
(gen_random_uuid(),'{w}'::uuid,decode(repeat('a2',32),'hex'),decode(repeat('b3',32),'hex'),'{PRINCIPAL}','pending_bootstrap',now()+interval '1 hour',now()+interval '2 hour'),\
(gen_random_uuid(),'{w}'::uuid,decode(repeat('a3',32),'hex'),decode(repeat('b4',32),'hex'),'{PRINCIPAL}','delivery_pending',now()+interval '1 hour',now()+interval '2 hour')"
            )],
        },
        InvalidationSubject {
            relation: "approvals",
            live: "state='active'",
            markers: &[
                "SET state='suspended'",
                "suspend_reason='restore_review_required'",
                "WHERE state='active'",
            ],
            seed: vec![format!(
                "INSERT INTO central.approvals (id,workspace_id,state,capability_identity,scope,action,actor_identity,authority_identity,reason) \
VALUES (gen_random_uuid(),'{w}'::uuid,'active','c06.scenario6.synthetic.capability','workspace','grant','c06-scenario-6-actor','c06-scenario-6-authority','c06 scenario 6 synthetic grant')"
            )],
        },
        vec![
            InvalidationSubject {
                relation: "outbox",
                live: "delivery_state='claimed' AND claim_expires_at > now()",
                markers: &[
                    "claim_expires_at=$1::timestamptz",
                    "WHERE delivery_state='claimed'",
                ],
                seed: vec![
                    format!(
                        "INSERT INTO central.events (id,workspace_id,event_sequence,event_type,aggregate_id,aggregate_version,payload,kind,producer_id,eligible_after) VALUES ('{event}'::uuid,'{w}'::uuid,{EPOCH_GENERATION},'c06.scenario6.synthetic','{task}'::uuid,1,'{{}}'::jsonb,'task','c06-scenario-6',now())"
                    ),
                    format!(
                        "INSERT INTO central.outbox (id,workspace_id,event_id,delivery_state,catalog_type,deduplication_key,producer_id,payload,visible_at,eligible_after,claim_token_hash,claim_expires_at,owner_identity,lease_expiry) VALUES ('{outbox}'::uuid,'{w}'::uuid,'{event}'::uuid,'claimed','c06.scenario6.synthetic','c06-scenario-6-dedup','c06-scenario-6','{{}}'::jsonb,now(),now(),{HASH32},now()+interval '1 hour','c06-scenario-6-owner',now()+interval '1 hour')"
                    ),
                ],
            },
            InvalidationSubject {
                relation: "outbox_workspace_work",
                live: "claim_expires_at IS NOT NULL AND claim_expires_at > now()",
                markers: &[
                    "SET claim_expires_at=$1",
                    "WHERE claim_expires_at IS NOT NULL",
                ],
                seed: vec![format!(
                    "INSERT INTO central.outbox_workspace_work (workspace_id,next_visible_at,claim_token_hash,claim_expires_at) VALUES ('{w}'::uuid,now(),{HASH32},now()+interval '1 hour') ON CONFLICT (workspace_id) DO UPDATE SET claim_token_hash=EXCLUDED.claim_token_hash, claim_expires_at=EXCLUDED.claim_expires_at"
                )],
            },
            InvalidationSubject {
                relation: "recovery_coordinators",
                live: "state='claimed'",
                markers: &["SET state='expired'", "WHERE state='claimed'"],
                seed: vec![format!(
                    "INSERT INTO central.recovery_coordinators (recovery_domain,instance_id,lease_token_hash,fencing_generation,lease_expires_at,state) VALUES ('{DOMAIN}','c06-scenario-6-instance',{HASH32},1,now()+interval '1 hour','claimed')"
                )],
            },
            InvalidationSubject {
                relation: "recovery_epoch_workspaces",
                live: "delivery_state='claimed' AND claim_expires_at > now()",
                markers: &[
                    "UPDATE central.recovery_epoch_workspaces SET claim_expires_at=$1",
                    "WHERE delivery_state='claimed'",
                ],
                seed: vec![
                    format!(
                        "INSERT INTO central.recovery_epochs (epoch_generation,coordinator_domain,coordinator_fence,state,snapshot_at) VALUES ({EPOCH_GENERATION},'{DOMAIN}',1,'open',now())"
                    ),
                    format!(
                        "INSERT INTO central.recovery_epoch_workspaces (epoch_generation,workspace_id,delivery_state,watermark_created_at,watermark_run_id,claim_token_hash,claim_expires_at) VALUES ({EPOCH_GENERATION},'{w}'::uuid,'claimed',now(),'{run}'::uuid,{HASH32},now()+interval '1 hour')"
                    ),
                ],
            },
        ],
        vec![
            InvalidationSubject {
                relation: "execution_ownership",
                live: "lease_expires_at > now()",
                markers: &[
                    "SET lease_expiry=CASE WHEN lease_expiry IS NULL THEN NULL ELSE $1::timestamptz END",
                    "lease_expires_at=$1::timestamptz",
                    "fencing_generation=fencing_generation+1",
                ],
                seed: vec![format!(
                    "INSERT INTO central.execution_ownership (id,workspace_id,owner_scope,owner_identity,lease_expiry,lease_token_hash,fencing_generation,lease_expires_at) VALUES ('{ownership}'::uuid,'{w}'::uuid,'c06-scenario-6-scope','c06-scenario-6-owner',now()+interval '1 hour',{HASH32},1,now()+interval '1 hour')"
                )],
            },
            InvalidationSubject {
                relation: "artifact_reconciliation_claims",
                live: "lease_expires_at > now()",
                markers: &[
                    "UPDATE central.artifact_reconciliation_claims SET lease_expires_at=$1",
                    "WHERE lease_expires_at>$1",
                ],
                seed: vec![
                    format!(
                        "INSERT INTO central.artifacts (id,workspace_id,task_id,run_id,state,staging_generation,object_key,sensitivity,disposition) VALUES ('{artifact}'::uuid,'{w}'::uuid,'{task}'::uuid,'{run}'::uuid,'reserved',gen_random_uuid(),'c06-scenario-6-synthetic-object','unrestricted','inline')"
                    ),
                    format!(
                        "INSERT INTO central.artifact_reconciliation_claims (artifact_id,workspace_id,claim_kind,coordinator_generation,claim_token_hash,lease_expires_at) VALUES ('{artifact}'::uuid,'{w}'::uuid,'normal',1,{HASH32},now()+interval '1 hour')"
                    ),
                ],
            },
        ],
        InvalidationSubject {
            relation: "provider_bindings",
            live: "revoked_at IS NULL",
            markers: &[
                "UPDATE central.provider_bindings SET revoked_at=COALESCE(revoked_at,$1)",
                "WHERE revoked_at IS NULL",
            ],
            seed: vec![format!(
                "INSERT INTO central.provider_bindings (id,workspace_id,secret_reference,opaque_generation,provider,adapter,model,destination,method,path,binding_verifier,fence_generation,fence_verifier) VALUES ('{binding}'::uuid,'{w}'::uuid,'secret://c06-scenario-6-synthetic',gen_random_uuid(),'c06-scenario-6-provider','c06-scenario-6-adapter','c06-scenario-6-model','https://127.0.0.1','POST','/c06-scenario-6-synthetic-path',{HASH32},1,{HASH32})"
            )],
        },
        InvalidationSubject {
            relation: "provider_fence_consumptions",
            live: "delivery_state='delivery_pending'",
            markers: &[
                "SET delivery_state='reconciliation'",
                "handoff_failure_code='restore_authority_reset'",
                "WHERE delivery_state='delivery_pending'",
            ],
            seed: vec![format!(
                "INSERT INTO central.provider_fence_consumptions (id,provider_binding_id,workspace_id,task_id,run_id,step_attempt_id,logical_operation_id,physical_attempt_id,invocation_id,policy_verifier,context_verifier,sensitivity_verifier,fence_generation,fence_verifier,fence_deadline,result_code,delivery_state,provider_turn_id) VALUES ('{fence}'::uuid,'{binding}'::uuid,'{w}'::uuid,'{task}'::uuid,'{run}'::uuid,'{attempt}'::uuid,'{logical}'::uuid,'{physical}'::uuid,'{invocation}'::uuid,{HASH32},{HASH32},{HASH32},1,{HASH32},now()+interval '1 hour','ok','delivery_pending','{turn}'::uuid)"
            )],
        },
        InvalidationSubject {
            relation: "b09_authorization_decisions",
            live: "revoked_at IS NULL",
            markers: &[
                "UPDATE central.b09_authorization_decisions SET revoked_at=COALESCE(revoked_at,$1)",
                "WHERE revoked_at IS NULL",
            ],
            seed: vec![format!(
                "INSERT INTO central.b09_authorization_decisions (id,workspace_id,task_id,run_id,step_attempt_id,physical_attempt_id,snapshot_id,provider,destination,scope,secret_reference,sensitivity_manifest_hash,policy_revision,security_epoch,grant_id,decision,expires_at,provider_turn_id) VALUES ('{decision}'::uuid,'{w}'::uuid,'{task}'::uuid,'{run}'::uuid,'{attempt}'::uuid,'{physical}'::uuid,'{snapshot}'::uuid,'c06-scenario-6-provider','https://127.0.0.1','model_context.send+secret.use','secret://c06-scenario-6-synthetic',{HASH32},'r1',2,'c06-scenario-6-grant','allow',now()+interval '1 hour','{turn}'::uuid)"
            )],
        },
    )
}

/// `c06InvalidationPrerequisiteSeed` — the task/run/step/attempt chain plus
/// the provider-turn snapshot and turn the subjects hang off.
fn invalidation_prerequisite_seed() -> Vec<String> {
    let w = workspace();
    let task = synthetic_id("task");
    let run = synthetic_id("run");
    let step = synthetic_id("step");
    let attempt = synthetic_id("attempt");
    let physical = synthetic_id("physical-attempt");
    let logical = synthetic_id("logical-operation");
    let invocation = synthetic_id("invocation");
    let snapshot = synthetic_id("snapshot");
    let turn = synthetic_id("provider-turn");
    vec![
        format!(
            "INSERT INTO central.tasks (id,workspace_id,status,title,input_spec) VALUES ('{task}'::uuid,'{w}'::uuid,'queued','c06-scenario-6-synthetic-task','{{}}'::jsonb)"
        ),
        format!(
            "INSERT INTO central.runs (id,workspace_id,task_id,status,run_index) VALUES ('{run}'::uuid,'{w}'::uuid,'{task}'::uuid,'queued',1)"
        ),
        format!(
            "INSERT INTO central.steps (id,workspace_id,run_id,task_id,state,logical_operation_id,sequence) VALUES ('{step}'::uuid,'{w}'::uuid,'{run}'::uuid,'{task}'::uuid,'queued','{logical}'::uuid,1)"
        ),
        format!(
            "INSERT INTO central.step_attempts (id,workspace_id,step_id,task_id,run_id,logical_operation_id,physical_attempt_id,sequence,state,invocation_id,invocation_generation) VALUES ('{attempt}'::uuid,'{w}'::uuid,'{step}'::uuid,'{task}'::uuid,'{run}'::uuid,'{logical}'::uuid,'{physical}'::uuid,1,'prepared','{invocation}'::uuid,1)"
        ),
        format!(
            "INSERT INTO central.b09_run_snapshots (id,workspace_id,task_id,run_id,step_id,provider,model,destination,method,profile_signature,policy_revision,tool_revision,price_revision,selected_budget,task_input_hash,security_epoch,context_hash,sensitivity_manifest_hash,workspace_root_id) VALUES ('{snapshot}'::uuid,'{w}'::uuid,'{task}'::uuid,'{run}'::uuid,'{step}'::uuid,'c06-scenario-6-provider','c06-scenario-6-model','https://127.0.0.1','POST',{HASH32},'r1','r1','r1','{{}}'::jsonb,{HASH32},2,{HASH32},{HASH32},'c06-scenario-6-root')"
        ),
        format!(
            "INSERT INTO central.b09_provider_turns (id,workspace_id,turn_id,task_id,run_id,step_id,step_attempt_id,logical_operation_id,physical_attempt_id,invocation_id,state) VALUES (gen_random_uuid(),'{w}'::uuid,'{turn}'::uuid,'{task}'::uuid,'{run}'::uuid,'{step}'::uuid,'{attempt}'::uuid,'{logical}'::uuid,'{physical}'::uuid,'{invocation}'::uuid,'prepared')"
        ),
    ]
}

/// `c06DeletePriorInvalidationSeeds` — the deterministic seeds die on
/// duplicate keys across runs; delete by the exact fixed keys first.
fn delete_prior_invalidation_seeds() -> Vec<String> {
    let w = workspace();
    vec![
        format!(
            "DELETE FROM central.outbox WHERE id='{}'::uuid",
            synthetic_id("outbox-entry")
        ),
        format!(
            "DELETE FROM central.events WHERE id='{}'::uuid",
            synthetic_id("event")
        ),
        format!(
            "DELETE FROM central.artifact_reconciliation_claims WHERE artifact_id='{}'::uuid",
            synthetic_id("artifact")
        ),
        format!(
            "DELETE FROM central.recovery_epoch_workspaces WHERE epoch_generation={EPOCH_GENERATION} AND workspace_id='{w}'::uuid"
        ),
        format!("DELETE FROM central.recovery_epochs WHERE epoch_generation={EPOCH_GENERATION}"),
        format!(
            "DELETE FROM central.recovery_coordinators WHERE recovery_domain='{DOMAIN}' AND instance_id='c06-scenario-6-instance'"
        ),
        format!(
            "DELETE FROM central.execution_ownership WHERE id='{}'::uuid",
            synthetic_id("execution-ownership")
        ),
        format!(
            "DELETE FROM central.provider_fence_consumptions WHERE id='{}'::uuid",
            synthetic_id("fence-consumption")
        ),
        format!(
            "DELETE FROM central.b09_authorization_decisions WHERE id='{}'::uuid",
            synthetic_id("authorization-decision")
        ),
        format!(
            "DELETE FROM central.provider_bindings WHERE id='{}'::uuid",
            synthetic_id("provider-binding")
        ),
        format!("DELETE FROM central.sessions WHERE principal_identity='{PRINCIPAL}'"),
        "DELETE FROM central.approvals WHERE reason='c06 scenario 6 synthetic grant'".to_owned(),
    ]
}

/// `TestC06TheSevenInvalidationFieldsAreTheOnesTheEmitterCarries` — the
/// plan's names pinned to `InvalidatedCounts`' serde wire names.
#[test]
fn the_seven_invalidation_fields_are_the_ones_the_emitter_carries() {
    let emitted = serde_json::to_value(crate::evidence::InvalidatedCounts::default())
        .expect("serialize the census shape")
        .as_object()
        .expect("the census serializes as an object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let mut sorted_emitted = emitted;
    let mut sorted_declared: Vec<String> = INVALIDATION_FIELDS
        .iter()
        .map(|f| (*f).to_owned())
        .collect();
    sorted_emitted.sort();
    sorted_declared.sort();
    assert_eq!(
        sorted_emitted, sorted_declared,
        "the emitter's invalidation census carries {sorted_emitted:?} and this scenario measures {sorted_declared:?}"
    );
    // Coverage: all seven fields mapped, non-empty predicates and seeds.
    let plan = invalidation_census_plan();
    assert_eq!(plan.len(), INVALIDATION_FIELDS.len());
    let mut claimed = std::collections::HashSet::new();
    for field in INVALIDATION_FIELDS {
        let subjects = plan.get(field).unwrap_or_else(|| {
            panic!("governance field 26 carries {field} and the plan maps it to nothing")
        });
        assert!(!subjects.is_empty());
        for subject in subjects {
            assert!(
                claimed.insert(subject.relation),
                "central.{} is claimed by two fields",
                subject.relation
            );
            assert!(!subject.live.trim().is_empty());
            assert!(!subject.seed.is_empty());
            assert!(!subject.markers.is_empty());
        }
    }
}

// ---------------------------------------------------------------------------
// Battery 5 — the recorder refuses a census that cannot be a measurement.
// ---------------------------------------------------------------------------

/// `c06AuthorityResetMeasurement` — what the live leg measured, before the
/// emitter's shape is derived from it.
#[derive(Clone)]
struct AuthorityResetMeasurement {
    before: BTreeMap<&'static str, i64>,
    after: BTreeMap<&'static str, i64>,
    restore_epoch_before: i64,
    restore_epoch_after: i64,
    security_epoch_before: i64,
    security_epoch_after: i64,
    broker_tls_rekeyed: bool,
    generations_before: i64,
    generations_after: i64,
    aggregate_receipt_hash: String,
}

fn honest_measurement() -> AuthorityResetMeasurement {
    let mut before = BTreeMap::new();
    let mut after = BTreeMap::new();
    for field in INVALIDATION_FIELDS {
        before.insert(field, 1);
        after.insert(field, 0);
    }
    *before.get_mut("sessions").unwrap() = 3;
    *before.get_mut("claims").unwrap() = 4;
    *before.get_mut("leases").unwrap() = 2;
    AuthorityResetMeasurement {
        before,
        after,
        restore_epoch_before: 3,
        restore_epoch_after: 4,
        security_epoch_before: 2,
        security_epoch_after: 3,
        broker_tls_rekeyed: true,
        generations_before: 1,
        generations_after: 2,
        aggregate_receipt_hash: s6_digest("recorder-fixture"),
    }
}

/// `c06RecordSet.checkAuthorityReset` — the recorder's decision, separated
/// from the storing so the refusal rows can exercise it.
fn check_authority_reset(
    measurement: &AuthorityResetMeasurement,
) -> Result<crate::evidence::AuthorityReset, String> {
    let mut counts = crate::evidence::InvalidatedCounts::default();
    for field in INVALIDATION_FIELDS {
        let before = measurement.before.get(field).copied();
        let after = measurement.after.get(field).copied();
        let (Some(before), Some(after)) = (before, after) else {
            return Err(format!(
                "the {field:?} count was not read on both sides of the reset; a count read only afterwards cannot tell an invalidation from an instance where nothing was ever live"
            ));
        };
        if before <= 0 {
            return Err(format!(
                "refusing to record a {field:?} count whose pre-reset reading was {before}: a zero before the reset makes the zero after it indistinguishable from an instance on which nothing of that kind ever existed"
            ));
        }
        if after != 0 {
            return Err(format!(
                "refusing to record a {field:?} count with {after} still live after the reset: a residue is a restored authority the reset did not reach"
            ));
        }
        let delta = before - after;
        match field {
            "sessions" => counts.sessions = delta,
            "grants" => counts.grants = delta,
            "claims" => counts.claims = delta,
            "leases" => counts.leases = delta,
            "fences" => counts.fences = delta,
            "provider_bindings" => counts.provider_bindings = delta,
            _ => counts.secret_references = delta,
        }
    }
    if measurement.restore_epoch_after != measurement.restore_epoch_before + 1 {
        return Err(format!(
            "refusing to record a restore epoch that moved from {} to {}: C05 advances it by exactly one",
            measurement.restore_epoch_before, measurement.restore_epoch_after
        ));
    }
    if measurement.security_epoch_after != measurement.security_epoch_before + 1 {
        return Err(format!(
            "refusing to record a security epoch that moved from {} to {}: the epoch check is what invalidates every restored session",
            measurement.security_epoch_before, measurement.security_epoch_after
        ));
    }
    if !measurement.broker_tls_rekeyed {
        return Err(
            "refusing to record an authority reset that did not re-key the broker's TLS authority"
                .to_owned(),
        );
    }
    let allocated = measurement.generations_after - measurement.generations_before;
    if allocated != 1 {
        return Err(format!(
            "refusing to record a reset that allocated {allocated} bootstrap generations ({} before, {} after): a bootstrap generation count other than one fails the gate",
            measurement.generations_before, measurement.generations_after
        ));
    }
    let digest = measurement
        .aggregate_receipt_hash
        .strip_prefix("sha256:")
        .unwrap_or_default();
    if digest.len() != 64 {
        return Err(format!(
            "refusing to record an authority reset whose aggregate receipt digest is {:?}; the emitter admits a bare sha-256",
            measurement.aggregate_receipt_hash
        ));
    }
    Ok(crate::evidence::AuthorityReset {
        restore_epoch_before: measurement.restore_epoch_before,
        restore_epoch_after: measurement.restore_epoch_after,
        security_epoch_before: measurement.security_epoch_before,
        security_epoch_after: measurement.security_epoch_after,
        invalidated: counts,
        broker_tls_rekeyed: measurement.broker_tls_rekeyed,
        bootstrap_generations_allocated: allocated,
        aggregate_receipt_sha256: digest.to_owned(),
    })
}

/// `TestC06TheAuthorityResetRecorderRefusesACensusThatCannotBeAMeasurement`.
#[test]
fn the_authority_reset_recorder_refuses_a_census_that_cannot_be_a_measurement() {
    let honest = honest_measurement();
    let reset = check_authority_reset(&honest).expect("the honest census is refused");
    assert_eq!(reset.invalidated.sessions, 3);
    assert_eq!(reset.invalidated.claims, 4);
    assert_eq!(reset.invalidated.leases, 2);
    assert_eq!(reset.bootstrap_generations_allocated, 1);
    assert!(!reset.aggregate_receipt_sha256.starts_with("sha256:"));
    assert_eq!(reset.aggregate_receipt_sha256.len(), 64);
    for (name, poison) in [
        (
            "a zero before-count",
            (|m: &mut AuthorityResetMeasurement| *m.before.get_mut("fences").unwrap() = 0)
                as fn(&mut AuthorityResetMeasurement),
        ),
        ("a before-count never read", |m| {
            m.before.remove("grants");
        }),
        ("an after-count never read", |m| {
            m.after.remove("grants");
        }),
        ("a residue after the reset", |m| {
            *m.after.get_mut("claims").unwrap() = 1
        }),
        ("a restore epoch that did not advance", |m| {
            m.restore_epoch_after = m.restore_epoch_before
        }),
        ("a restore epoch that advanced by two", |m| {
            m.restore_epoch_after = m.restore_epoch_before + 2
        }),
        ("a security epoch that did not advance", |m| {
            m.security_epoch_after = m.security_epoch_before
        }),
        ("a reset that did not re-key TLS", |m| {
            m.broker_tls_rekeyed = false
        }),
        ("no fresh bootstrap generation", |m| {
            m.generations_after = m.generations_before
        }),
        ("two fresh bootstrap generations", |m| {
            m.generations_after = m.generations_before + 2
        }),
        ("a table that merely holds one row", |m| {
            m.generations_before = 0;
            m.generations_after = 0;
        }),
        ("a malformed aggregate digest", |m| {
            m.aggregate_receipt_hash = "receipt-of-the-reset".to_owned()
        }),
    ] {
        let mut poisoned = honest_measurement();
        poison(&mut poisoned);
        assert!(
            check_authority_reset(&poisoned).is_err(),
            "the recorder ACCEPTED {name}"
        );
    }
}

// ---------------------------------------------------------------------------
// The live half: the real reset over a real PostgreSQL.
// ---------------------------------------------------------------------------

fn exec_statements(
    conn: &central_adapter_postgres::store_support::BlockingConn,
    statements: &[String],
    what: &str,
) -> Result<(), String> {
    for statement in statements {
        let sql = statement.clone();
        let what = what.to_owned();
        conn.run(|c| {
            let (sql, what) = (sql.clone(), what.clone());
            Box::pin(async move {
                sqlx::query(&sql)
                    .execute(&mut *c)
                    .await
                    .map_err(|e| Failure::internal("c06", format!("{what}: {e}")))
            })
        })
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn count_rows(
    conn: &central_adapter_postgres::store_support::BlockingConn,
    query: &str,
) -> Result<i64, String> {
    let sql = query.to_owned();
    conn.run(|c| {
        let sql = sql.clone();
        Box::pin(async move {
            sqlx::query_scalar::<_, i64>(&sql)
                .fetch_one(&mut *c)
                .await
                .map_err(|e| Failure::internal("c06", format!("read a census value: {e}")))
        })
    })
    .map_err(|e| e.to_string())
}

fn read_invalidation_census(
    conn: &central_adapter_postgres::store_support::BlockingConn,
) -> Result<BTreeMap<&'static str, i64>, String> {
    let plan = invalidation_census_plan();
    let mut census = BTreeMap::new();
    for field in INVALIDATION_FIELDS {
        let mut total = 0i64;
        for subject in &plan[field] {
            total += count_rows(
                conn,
                &format!(
                    "SELECT count(*) FROM central.{} WHERE {}",
                    subject.relation, subject.live
                ),
            )?;
        }
        census.insert(field, total);
    }
    Ok(census)
}

fn format_census(census: &BTreeMap<&'static str, i64>) -> String {
    INVALIDATION_FIELDS
        .iter()
        .map(|f| format!("{f}={}", census.get(f).copied().unwrap_or(-1)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `c06MeasureTheAuthorityReset` — the REAL reset: real broker over a real
/// protected root, the real `RecoveryAuditStore` over the DSN database, joined
/// by the production `AuthorityResetCoordinator`; every number read on both
/// sides out of the state that holds it.
fn measure_the_authority_reset(
    dsn: &str,
    narrator: &mut dyn Narrator,
) -> Result<AuthorityResetMeasurement, String> {
    let conn = Arc::new(connect_pg(dsn)?);
    let store = RecoveryAuditStore::from_blocking_conn(conn.clone());
    let conn_ref: &BlockingConn = &conn;

    let tmp = TempRoot::new("s6-live")?;
    let root = tmp.0.join("authority-reset-root");
    let service = Service::new(root.clone(), rustix::process::getuid().as_raw())
        .map_err(|e| format!("compose the broker service: {e}"))?;
    let journal = journal_at(&root)?;
    let begun = begin_a_restore_in_the_past(&journal)?;
    let mut current = begun;
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
        let at = current.updated_at + time::Duration::seconds(1);
        let next = step(&current, at).map_err(|e| format!("the domain refused {label}: {e}"))?;
        journal
            .compare_and_swap_restore(&current, &next)
            .map_err(|e| format!("the journal refused {label}: {e}"))?;
        store
            .project_restore_operation(&next)
            .map_err(|e| format!("the audit projection refused {label}: {e}"))?;
        current = next;
    }
    let operation = current;

    // --- Seed every counted category; epoch the seeded sessions. --------
    exec_statements(
        conn_ref,
        &delete_prior_invalidation_seeds(),
        "delete a prior run's seeds",
    )?;
    exec_statements(
        conn_ref,
        &invalidation_prerequisite_seed(),
        "seed the prerequisite chain",
    )?;
    let plan = invalidation_census_plan();
    for field in [
        "sessions",
        "grants",
        "claims",
        "leases",
        "provider_bindings",
        "fences",
        "secret_references",
    ] {
        for subject in &plan[field] {
            exec_statements(conn_ref, &subject.seed, "seed a live census subject")?;
        }
    }
    exec_statements(
        conn_ref,
        &[format!(
            "UPDATE central.sessions SET security_epoch={} WHERE principal_identity='{PRINCIPAL}'",
            operation.security_epoch
        )],
        "bind the seeded sessions to the operation's security epoch",
    )?;

    // --- The pre-restore token leg: validate through PgSessionStore. ------
    narrator.expect("a pre-restore session token validates through the production session reader BEFORE the reset, so that its refusal afterwards is a refusal of something that was live");
    let token_hash: [u8; 32] = [0xa1; 32];
    {
        let dsn2 = dsn.to_owned();
        let epoch = operation.security_epoch;
        conn_ref
            .run(|_c| {
                Box::pin(async move {
                    let pool = sqlx::PgPool::connect(&dsn2)
                        .await
                        .map_err(|e| Failure::internal("c06", format!("session pool: {e}")))?;
                    let sessions = PgSessionStore::new(pool);
                    sessions
                        .validate(central_session::domain::ValidationRequest {
                            token_hash,
                            presented_csrf_hash: None,
                            epoch: central_session::domain::SecurityEpoch(epoch),
                        })
                        .await
                        .map(|_| ())
                        .map_err(|e| {
                            Failure::internal(
                                "c06",
                                format!("pre-reset token did NOT validate: {e}"),
                            )
                        })
                })
            })
            .map_err(|e| e.to_string())?;
    }
    narrator.record("the pre-restore session token validated through the production session reader before the reset".to_owned());

    // --- Everything, read before. ---------------------------------------
    let before = read_invalidation_census(conn_ref)?;
    let restore_epoch_before = operation.restore_epoch as i64 - 1;
    let security_epoch_before = operation.security_epoch as i64;
    let generations_before = count_rows(
        conn_ref,
        "SELECT count(*) FROM central.bootstrap_generations",
    )?;
    let registrations_before = count_rows(
        conn_ref,
        &format!(
            "SELECT count(*) FROM central.recovery_bootstrap_registrations WHERE operation_id='{}'::uuid",
            operation.operation_id
        ),
    )?;
    let execution_fence_before = count_rows(
        conn_ref,
        "SELECT COALESCE(max(fencing_generation),0) FROM central.execution_ownership",
    )?;
    let coordinator_fence_before = count_rows(
        conn_ref,
        "SELECT COALESCE(max(fencing_generation),0) FROM central.recovery_coordinators",
    )?;
    let tls_before = broker_tls_fingerprints(&root)?;
    narrator.expect("every one of governance field 26's seven counts has at least one live instance before the reset");
    for field in INVALIDATION_FIELDS {
        if before[field] <= 0 {
            return Err(format!(
                "the {field:?} count read {} live instances BEFORE the reset; a zero here makes the zero afterwards indistinguishable",
                before[field]
            ));
        }
    }
    narrator.record(format!("before the reset: {}", format_census(&before)));

    // --- The real reset. ---------------------------------------------------
    let coordinator = AuthorityResetCoordinator::new(&service, &store);
    narrator.expect("the production authority reset coordinator performs the real C05 reset and returns a receipt the domain's own validator accepts");
    let receipt = coordinator
        .reset_authority(&operation)
        .map_err(|e| format!("the production C05 reset failed: {e:?}"))?;
    receipt
        .validate_for(&operation)
        .map_err(|e| format!("the reset returned a receipt the domain refuses: {e}"))?;
    if receipt.previous_restore_epoch != operation.restore_epoch - 1
        || receipt.new_restore_epoch != operation.restore_epoch
        || receipt.previous_security_epoch != operation.security_epoch
        || receipt.new_security_epoch != operation.security_epoch + 1
    {
        return Err("the receipt names epochs that are not the operation's own".to_owned());
    }
    narrator.record(format!(
        "the real reset settled: restore epoch {}->{}, security epoch {}->{}, generation {}, candidate {}",
        receipt.previous_restore_epoch, receipt.new_restore_epoch,
        receipt.previous_security_epoch, receipt.new_security_epoch,
        receipt.bootstrap_generation, receipt.bootstrap_candidate_id
    ));

    // --- The aggregate value pin over the REAL receipt. -------------------
    let recomputed = aggregate_digest(&AggregatePayload {
        operation_id: operation.operation_id.to_string(),
        previous_restore_epoch: receipt.previous_restore_epoch,
        new_restore_epoch: receipt.new_restore_epoch,
        previous_security_epoch: receipt.previous_security_epoch,
        new_security_epoch: receipt.new_security_epoch,
        broker_receipt_hash: receipt.broker_receipt_hash.clone(),
        database_receipt_hash: receipt.database_receipt_hash.clone(),
        candidate_id: receipt.bootstrap_candidate_id.to_string(),
        generation: receipt.bootstrap_generation,
        activation_receipt_hash: receipt.bootstrap_activation_receipt_hash.clone(),
        completed_at: rfc3339_nano(receipt.completed_at),
    })?;
    if recomputed != receipt.aggregate_receipt_hash {
        return Err(format!(
            "the aggregate digest recomputed over the substeps is {recomputed} and the producer emitted {}",
            receipt.aggregate_receipt_hash
        ));
    }

    // --- Everything, read after. ------------------------------------------
    let after = read_invalidation_census(conn_ref)?;
    narrator.expect("no live instance of any of the seven categories survives the reset");
    for field in INVALIDATION_FIELDS {
        if after[field] != 0 {
            return Err(format!(
                "the {field:?} count read {} live instances AFTER the reset ({} before)",
                after[field], before[field]
            ));
        }
    }
    narrator.record(format!("after the reset: {}", format_census(&after)));

    let restore_epoch_after = count_rows(
        conn_ref,
        "SELECT COALESCE(max(restore_epoch),0) FROM central.epoch_markers",
    )?;
    let security_epoch_after = count_rows(
        conn_ref,
        "SELECT COALESCE(max(security_epoch),0) FROM central.epoch_markers",
    )?;
    if restore_epoch_after != receipt.new_restore_epoch as i64
        || security_epoch_after != receipt.new_security_epoch as i64
    {
        return Err(format!(
            "the epoch markers read {restore_epoch_after}/{security_epoch_after} and the receipt names {}/{}",
            receipt.new_restore_epoch, receipt.new_security_epoch
        ));
    }
    if count_rows(
        conn_ref,
        "SELECT COALESCE(max(fencing_generation),0) FROM central.execution_ownership",
    )? <= execution_fence_before
    {
        return Err("the execution ownership fencing generation did not advance".to_owned());
    }
    if count_rows(
        conn_ref,
        "SELECT COALESCE(max(fencing_generation),0) FROM central.recovery_coordinators",
    )? <= coordinator_fence_before
    {
        return Err("the recovery coordinator fencing generation did not advance".to_owned());
    }

    // --- Exactly one bootstrap generation, both directions. ---------------
    let generations_after = count_rows(
        conn_ref,
        "SELECT count(*) FROM central.bootstrap_generations",
    )?;
    narrator.expect("the reset allocated exactly one fresh bootstrap generation: one more row than before, exactly one registration for this operation, and exactly one generation row carrying the receipt's own candidate");
    if generations_after != generations_before + 1 {
        return Err(format!(
            "central.bootstrap_generations went from {generations_before} rows to {generations_after}; a count other than one fails the gate"
        ));
    }
    if count_rows(
        conn_ref,
        &format!(
            "SELECT count(*) FROM central.recovery_bootstrap_registrations WHERE operation_id='{}'::uuid",
            operation.operation_id
        ),
    )? != registrations_before + 1
    {
        return Err("the operation's registration count did not grow by exactly one".to_owned());
    }
    if count_rows(
        conn_ref,
        &format!(
            "SELECT count(*) FROM central.bootstrap_generations WHERE candidate_id='{}'::uuid AND generation={}",
            receipt.bootstrap_candidate_id, receipt.bootstrap_generation
        ),
    )? != 1
    {
        return Err("the receipt's candidate does not have exactly one generation row".to_owned());
    }

    // --- A foreign draft for the same operation is refused. ---------------
    narrator.expect("a second bootstrap generation cannot be allocated for an operation that already has one: a foreign draft is refused, and the generation table is unchanged by the attempt");
    let foreign = RecoveryBootstrapDraft {
        operation_id: operation.operation_id,
        draft_id: Uuid::now_v7(),
        candidate_id: Uuid::now_v7(),
        verifier_hash: sha2::Sha256::digest(b"c06-scenario-6-foreign-verifier").into(),
        candidate_digest: sha2::Sha256::digest(b"c06-scenario-6-foreign-candidate").into(),
        broker_receipt_hash: s6_digest("foreign-broker"),
        created_at: operation.updated_at + time::Duration::seconds(1),
    };
    foreign
        .validate_for(&operation)
        .map_err(|e| format!("the foreign draft this check offers is itself invalid: {e}"))?;
    if foreign.candidate_id == receipt.bootstrap_candidate_id {
        return Err("the foreign draft carries the candidate the reset registered".to_owned());
    }
    if store.reset_database_authority(&operation, &foreign).is_ok() {
        return Err("the production reset ACCEPTED a foreign draft for an operation that already has a registered bootstrap generation".to_owned());
    }
    if count_rows(
        conn_ref,
        "SELECT count(*) FROM central.bootstrap_generations",
    )? != generations_after
    {
        return Err("the refused attempt still wrote a generation".to_owned());
    }

    // --- The replay, P-4 closed: byte-identical receipt, nothing new. -----
    narrator.expect("an exact replay of the reset repeats all four substeps byte-identically, allocates nothing new, and returns the identical receipt");
    let draft = service
        .prepare_recovery_broker_authority(&operation)
        .map_err(|e| format!("the broker refused an exact replay of the prepare: {e}"))?;
    let registration = store
        .reset_database_authority(&operation, &draft)
        .map_err(|e| format!("the database refused an exact replay of the reset: {e:?}"))?;
    if registration.generation != receipt.bootstrap_generation
        || registration.candidate_id != receipt.bootstrap_candidate_id
    {
        return Err("the replayed reset returned a different generation/candidate".to_owned());
    }
    let activation = service
        .activate_recovery_bootstrap(&operation, &registration)
        .map_err(|e| format!("the broker refused an exact replay of the activation: {e}"))?;
    if activation.generation != receipt.bootstrap_generation
        || activation.activation_receipt_hash != receipt.bootstrap_activation_receipt_hash
    {
        return Err("the replayed activation differs from the receipt's".to_owned());
    }
    if count_rows(
        conn_ref,
        "SELECT count(*) FROM central.bootstrap_generations",
    )? != generations_after
    {
        return Err("the exact replay allocated a bootstrap generation".to_owned());
    }
    let clock_between = OffsetDateTime::now_utc();
    let replayed = store
        .finalize_database_authority_reset(&operation, &registration, &activation)
        .map_err(|e| format!("the finalization replay was refused (P-4 regression): {e:?}"))?;
    if replayed != receipt {
        return Err(
            "the replayed finalization did not return the byte-identical receipt".to_owned(),
        );
    }
    if clock_between <= receipt.completed_at {
        return Err(
            "the wall clock did not pass the original completion; replay idempotence is unproven"
                .to_owned(),
        );
    }
    narrator.record(
        "P-4 closed, reverified: the finalization replay returned the identical receipt".to_owned(),
    );

    // --- The pre-restore token, offered again at both epochs. -------------
    narrator.expect("the pre-restore session token that validated before the reset is refused by the same production reader afterwards, at the old security epoch and at the new one alike");
    for epoch in [operation.security_epoch, operation.security_epoch + 1] {
        let dsn2 = dsn.to_owned();
        let refused = conn_ref.run(|_c| {
            Box::pin(async move {
                let pool = sqlx::PgPool::connect(&dsn2)
                    .await
                    .map_err(|e| Failure::internal("c06", format!("session pool: {e}")))?;
                let sessions = PgSessionStore::new(pool);
                Ok::<bool, Failure>(
                    sessions
                        .validate(central_session::domain::ValidationRequest {
                            token_hash,
                            presented_csrf_hash: None,
                            epoch: central_session::domain::SecurityEpoch(epoch),
                        })
                        .await
                        .is_err(),
                )
            })
        });
        match refused {
            Ok(true) => {}
            _ => {
                return Err(format!(
                    "the pre-restore session token STILL validates at security epoch {epoch} after the reset"
                ));
            }
        }
    }
    narrator.record(format!(
        "the pre-restore session token was refused at the old epoch {} and at the new epoch {}",
        operation.security_epoch,
        operation.security_epoch + 1
    ));

    let tls_after = broker_tls_fingerprints(&root)?;
    Ok(AuthorityResetMeasurement {
        before,
        after,
        restore_epoch_before,
        restore_epoch_after: receipt.new_restore_epoch as i64,
        security_epoch_before,
        security_epoch_after: receipt.new_security_epoch as i64,
        broker_tls_rekeyed: tls_before != tls_after,
        generations_before,
        generations_after,
        aggregate_receipt_hash: receipt.aggregate_receipt_hash.clone(),
    })
}

// ---------------------------------------------------------------------------
// The scenario and the portable entry points.
// ---------------------------------------------------------------------------

/// `c06.s6.authority_reset` — batteries 1/2/3 always (armed); the DSN live
/// leg measures the real reset and records governance field 26.
#[test]
fn c06_s6_authority_reset() {
    let runner = runner();
    if !runner.armed() {
        return;
    }
    let id = "c06.s6.authority_reset";
    crate::slice_c::scenario(
        id,
        |profile| crate::slice_c::unmet_precondition(id, profile).or_else(missing_live_env),
        |_s| {
            let mut log = ScenarioLog::new(id);
            log.recordf(format_args!("{SCENARIO6_SCOPE_DISCLOSURE}"));
            let dsn = std::env::var(crate::fixture::PG_DSN_ENV).map_err(|_| {
                format!(
                    "{} unset; the measured reset leg cannot run",
                    crate::fixture::PG_DSN_ENV
                )
            })?;
            {
                let mut narrator = Disclosing { id, log: &mut log };
                run_reset_receipt_battery(&mut narrator)?;
                run_aggregate_binding_battery(&mut narrator)?;
                run_broker_authority_reset_battery(&mut narrator)?;
                let measurement = measure_the_authority_reset(&dsn, &mut narrator)?;
                let reset = check_authority_reset(&measurement)
                    .map_err(|e| format!("the recorder refused the measured reset: {e}"))?;
                {
                    let mut records = crate::fixture::records();
                    if records.authority_reset.aggregate_receipt_sha256.is_empty() {
                        records.authority_reset = reset.clone();
                    }
                }
                narrator.record(format!(
                    "governance field 26, measured: restore epoch {}->{}, security epoch {}->{}, invalidated {:?}, broker TLS rekeyed {}, {} bootstrap generation allocated",
                    reset.restore_epoch_before, reset.restore_epoch_after,
                    reset.security_epoch_before, reset.security_epoch_after,
                    reset.invalidated, reset.broker_tls_rekeyed,
                    reset.bootstrap_generations_allocated
                ));
            }
            Ok(())
        },
    );
}

// --- CI-PORTABLE entry points. --------------------------------------------

/// `TestC06TheAuthorityResetReceiptBindsItsOperationAndItsEpochs`.
#[test]
fn the_authority_reset_receipt_binds_its_operation_and_its_epochs() {
    run_reset_receipt_battery(&mut Quiet).unwrap_or_else(|e| panic!("{e}"));
}

/// `TestC06TheAggregateReceiptHashBindsEverySubstep`.
#[test]
fn the_aggregate_receipt_hash_binds_every_substep() {
    run_aggregate_binding_battery(&mut Quiet).unwrap_or_else(|e| panic!("{e}"));
}

/// `TestC06TheBrokerAuthorityResetRekeysTLSAndStagesExactlyOneCandidate`.
#[test]
fn the_broker_authority_reset_rekeys_tls_and_stages_exactly_one_candidate() {
    run_broker_authority_reset_battery(&mut Quiet).unwrap_or_else(|e| panic!("{e}"));
}
